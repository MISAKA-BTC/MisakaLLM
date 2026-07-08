//! On-chain provider discovery (design §8.2): resolve dialable provider offers
//! from the `ProviderRegistry` EVM-lane contract over the node's Ethereum
//! JSON-RPC adapter (`--evm-rpc-listen`). This is the Rust twin of the SDK's
//! `mil-sdk-ts` `fetchOffersFromChain`; v0 dialed a provider out-of-band via a
//! hand-passed `host:port`, v1 discovers it from the on-chain registry.
//!
//! Like [`crate::backend_http`], the workspace tokio pin rules out reqwest/hyper,
//! so this is a hand-rolled HTTP/1.1 JSON-RPC client over `TcpStream` (plain
//! HTTP only — front a TLS endpoint with a local proxy). The ABI decoder is a
//! pure function checked against a `cast abi-encode` vector in the tests below.

use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// keccak256("ProviderRegistered(bytes32,address,bytes32,uint8)").
const PROVIDER_REGISTERED_TOPIC0: &str = "0x7e05a0090a0c618a1b410efdf58db1f25151c02909ca4174b76cf431d3b1f75e";
/// Selector of `ProviderRegistry.get(bytes32)`.
const GET_SELECTOR: &str = "8eaa6ac0";
/// eth-rpc response-body cap (a registry read is tiny; larger ⇒ transport fault).
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// A discovered provider offer — the subset of the on-chain `Provider` record
/// needed to match a served model and dial the data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredOffer {
    /// `0x…` bytes32 provider id.
    pub provider_id: String,
    /// `0x…` bytes32 served-model id (registry 32-byte form = low 32 bytes of the Hash64).
    pub model_id: String,
    /// Still registered (not deregistered).
    pub active: bool,
    /// The advertised data-plane `host:port`.
    pub data_plane_addr: String,
}

// --- ABI decode of `get(bytes32)` (a single dynamic tuple) --------------------

fn word_hex_at(raw: &str, byte_off: usize) -> Result<&str, String> {
    raw.get(byte_off * 2..byte_off * 2 + 64).ok_or_else(|| "registry decode: truncated word".to_string())
}

/// A small ABI word (offset/length/bool) at `byte_off`; the high 24 bytes must
/// be zero (a testnet registry never encodes a >2^64 offset).
fn small_at(raw: &str, byte_off: usize) -> Result<usize, String> {
    let w = word_hex_at(raw, byte_off)?;
    if w.as_bytes()[..48].iter().any(|&c| c != b'0') {
        return Err("registry decode: word exceeds usize range".to_string());
    }
    usize::from_str_radix(&w[48..], 16).map_err(|e| format!("registry decode uint: {e}"))
}

/// Decode a `ProviderRegistry.get()` return into the discovery-relevant fields.
/// Field word indices match the Solidity `Provider` struct order; the trailing
/// dynamic `dataPlaneAddr` string is read via its tuple-relative offset.
pub fn decode_provider_record(ret_hex: &str) -> Result<DiscoveredOffer, String> {
    let raw = ret_hex.strip_prefix("0x").unwrap_or(ret_hex);
    // A single dynamic return is [offset][tuple…]; tuple_base is that offset.
    let tuple_base = small_at(raw, 0)?;
    let b32 = |i: usize| -> Result<String, String> { Ok(format!("0x{}", word_hex_at(raw, tuple_base + i * 32)?)) };
    let provider_id = b32(1)?;
    let model_id = b32(3)?;
    let active = small_at(raw, tuple_base + 13 * 32)? != 0;
    // dataPlaneAddr is struct field 18 (word index 17): a tuple-relative offset.
    let off = small_at(raw, tuple_base + 17 * 32)?;
    let start = tuple_base + off;
    let len = small_at(raw, start)?;
    let data_hex = raw.get((start + 32) * 2..(start + 32) * 2 + len * 2).ok_or("registry decode: truncated string")?;
    let mut bytes = vec![0u8; len];
    faster_hex::hex_decode(data_hex.as_bytes(), &mut bytes).map_err(|e| format!("registry decode hex: {e}"))?;
    let data_plane_addr = String::from_utf8(bytes).map_err(|e| format!("dataPlaneAddr utf8: {e}"))?;
    Ok(DiscoveredOffer { provider_id, model_id, active, data_plane_addr })
}

/// The low 32 bytes (64 hex, lowercase) of a hex model id — the registry form.
fn low32(hex: &str) -> String {
    let h = hex.strip_prefix("0x").unwrap_or(hex).to_ascii_lowercase();
    if h.len() > 64 { h[h.len() - 64..].to_string() } else { format!("{:0>64}", h) }
}

// --- minimal HTTP/1.1 JSON-RPC client (plain HTTP) ----------------------------

fn split_url(url: &str) -> Result<(String, String), String> {
    if url.starts_with("https://") {
        return Err("discover: https eth-rpc is unsupported (plain HTTP only; front TLS with a local proxy)".to_string());
    }
    let rest = url.strip_prefix("http://").unwrap_or(url);
    match rest.split_once('/') {
        Some((host, path)) => Ok((host.to_string(), format!("/{path}"))),
        None => Ok((rest.to_string(), "/".to_string())),
    }
}

fn build_request(host: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn split_response(raw: &[u8]) -> Result<&[u8], String> {
    let sep = find_subslice(raw, b"\r\n\r\n").ok_or("eth-rpc response missing header terminator")?;
    let status_line = raw[..sep].split(|&b| b == b'\r' || b == b'\n').next().unwrap_or(b"");
    let status_str = std::str::from_utf8(status_line).map_err(|_| "non-utf8 status line")?;
    let code = status_str.split_whitespace().nth(1).and_then(|c| c.parse::<u16>().ok());
    match code {
        Some(c) if (200..300).contains(&c) => Ok(&raw[sep + 4..]),
        Some(c) => Err(format!("eth-rpc returned HTTP {c}")),
        None => Err(format!("eth-rpc unparseable status line: {status_str}")),
    }
}

async fn exchange(host: &str, request: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect(host).await.map_err(|e| format!("eth-rpc connect {host}: {e}"))?;
    stream.write_all(request).await.map_err(|e| format!("eth-rpc write: {e}"))?;
    stream.flush().await.map_err(|e| format!("eth-rpc flush: {e}"))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| format!("eth-rpc read: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_RESPONSE_BYTES {
            return Err("eth-rpc response exceeded size cap".to_string());
        }
    }
    Ok(buf)
}

async fn eth_rpc(url: &str, method: &str, params: Value) -> Result<Value, String> {
    let (host, path) = split_url(url)?;
    let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .map_err(|e| format!("eth-rpc encode: {e}"))?;
    let request = build_request(&host, &path, &body);
    let raw = tokio::time::timeout(Duration::from_secs(30), exchange(&host, &request))
        .await
        .map_err(|_| format!("eth-rpc {method} timed out"))??;
    let resp_body = split_response(&raw)?;
    let v: Value = serde_json::from_slice(resp_body).map_err(|e| format!("eth-rpc decode: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("eth-rpc {method}: {err}"));
    }
    v.get("result").cloned().ok_or_else(|| "eth-rpc: missing result".to_string())
}

/// Discover active provider offers from the on-chain `ProviderRegistry`:
/// enumerate `ProviderRegistered` logs, `eth_call get()` each, keep the still-active
/// ones, optionally filtered to a served model (compared over the low 32 bytes).
pub async fn resolve_offers(
    eth_rpc_url: &str,
    registry_addr: &str,
    model_id_filter: Option<&str>,
) -> Result<Vec<DiscoveredOffer>, String> {
    let logs = eth_rpc(
        eth_rpc_url,
        "eth_getLogs",
        json!([{ "address": registry_addr, "fromBlock": "earliest", "toBlock": "latest", "topics": [PROVIDER_REGISTERED_TOPIC0] }]),
    )
    .await?;
    let arr = logs.as_array().ok_or("eth_getLogs: result is not an array")?;
    let mut ids: Vec<String> = Vec::new();
    for l in arr {
        if let Some(t) = l.get("topics").and_then(|t| t.get(1)).and_then(|t| t.as_str())
            && !ids.iter().any(|x| x == t)
        {
            ids.push(t.to_string());
        }
    }
    let want = model_id_filter.map(low32);
    let mut offers = Vec::new();
    for id in ids {
        let data = format!("0x{GET_SELECTOR}{}", id.strip_prefix("0x").unwrap_or(&id));
        let ret = eth_rpc(eth_rpc_url, "eth_call", json!([{ "to": registry_addr, "data": data }, "latest"])).await?;
        let ret_hex = ret.as_str().ok_or("eth_call: result is not a string")?;
        let rec = decode_provider_record(ret_hex)?;
        if !rec.active {
            continue;
        }
        if let Some(ref w) = want
            && low32(&rec.model_id) != *w
        {
            continue;
        }
        offers.push(rec);
    }
    Ok(offers)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The REAL `ProviderRegistry.get()` ABI return (same vector as the mil-sdk-ts
    // registry test), from `cast abi-encode`. Provider: id 0x11.., model 0x33..,
    // active, hot, addr "203.0.113.7:37110".
    const V_ACTIVE: &str = "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000aa1111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555555555555555500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000007000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000c800000000000000000000000000000000000000000000000000000000000005dc0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000775732d656173740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000113230332e302e3131332e373a3337313130000000000000000000000000000000";
    // Same provider, active=false.
    const V_INACTIVE: &str = "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000aa1111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555555555555555500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000007000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000c800000000000000000000000000000000000000000000000000000000000005dc0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000775732d656173740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000113230332e302e3131332e373a3337313130000000000000000000000000000000";

    #[test]
    fn decode_matches_cast_vector() {
        let r = decode_provider_record(V_ACTIVE).unwrap();
        assert_eq!(r.provider_id, format!("0x{}", "11".repeat(32)));
        assert_eq!(r.model_id, format!("0x{}", "33".repeat(32)));
        assert!(r.active);
        assert_eq!(r.data_plane_addr, "203.0.113.7:37110");
    }

    #[test]
    fn decode_reads_active_flag() {
        assert!(!decode_provider_record(V_INACTIVE).unwrap().active);
    }

    #[test]
    fn low32_reduces_hash64_to_registry_form() {
        // a 64-byte (128 hex) Hash64 reduces to its low 32 bytes
        assert_eq!(low32(&format!("{}{}", "ab".repeat(32), "33".repeat(32))), "33".repeat(32));
        assert_eq!(low32(&format!("0x{}", "33".repeat(32))), "33".repeat(32));
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(decode_provider_record("0x1234").is_err());
    }
}
