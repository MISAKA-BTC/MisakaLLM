//! `misaka mtp …` — the self-serve half of the Testnet Points Program (ADR-0038 D3).
//!
//! Two operations, both trustless-by-design:
//!
//! * `points <id>` — a thin read-only HTTP client for the MTP service's query API
//!   (`GET /mtp/v1/points/<id>`). The service is a *mirror* of signed ledgers, so
//!   the numbers it returns are only as trustworthy as `verify-epoch` proves.
//! * `verify-epoch <file.jsonl>` — the trustless check: it re-verifies a published,
//!   ML-DSA-87-signed epoch ledger *locally*. With `--facts` it additionally runs
//!   the deterministic recompute and byte-compares, closing the loop the ADR's
//!   self-verification recipe describes (signature → rules-hash → recompute).
//!
//! No new dependencies: the HTTP client is a hand-rolled `TcpStream` GET (the same
//! secp-free, reqwest-free house style as `eth.rs`), and the verification reuses
//! the deterministic core (`misaka-mtp`).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use misaka_mtp::{EpochInput, EpochLedger, Rules, score_epoch};
use serde_json::{Value, json};

use crate::node::Ctx;
use crate::{CliError, CliResult, OutputFormat};

/// ML-DSA-87 verification-key length (2592 bytes = 5184 hex chars).
const MLDSA87_PK_LEN: usize = 2592;

// ---------------------------------------------------------------------------
// minimal HTTP/1.1 GET client (mirrors eth.rs's hand-rolled POST)
// ---------------------------------------------------------------------------

fn http_get(url: &str, timeout: Duration) -> Result<(u16, String), CliError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| CliError::generic(format!("MTP endpoint must be http:// (got {url})")))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| CliError::generic(format!("bad MTP port in {url}")))?),
        None => (hostport, 80u16),
    };
    let sockaddr = (host, port)
        .to_socket_addrs()
        .map_err(|e| CliError::connection(format!("resolve {host}:{port}: {e}")))?
        .next()
        .ok_or_else(|| CliError::connection(format!("no address for {host}:{port}")))?;
    let mut stream = TcpStream::connect_timeout(&sockaddr, timeout)
        .map_err(|e| CliError::connection(format!("MTP connect {host}:{port}: {e} (is misaka-mtp-service serving?)")))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).map_err(|e| CliError::connection(format!("MTP write: {e}")))?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| CliError::connection(format!("MTP read: {e}")))?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or_else(|| CliError::generic("malformed MTP HTTP response (no body)".to_string()))?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| CliError::generic("malformed MTP HTTP status line".to_string()))?;
    Ok((status, body.to_string()))
}

// ---------------------------------------------------------------------------
// `misaka mtp points <id>`
// ---------------------------------------------------------------------------

/// Look up an id's points via the service query API. In JSON mode the service's
/// response is passed through verbatim; in human mode a compact summary is shown
/// with a pointer to `verify-epoch` (the trust anchor).
pub fn points(ctx: &Ctx, id: &str, endpoint: &str) -> CliResult {
    let endpoint = endpoint.trim_end_matches('/');
    let url = format!("{endpoint}/mtp/v1/points/{id}");
    let (status, body) = http_get(&url, Duration::from_secs(ctx.timeout_secs))?;

    if status == 404 {
        return Err(CliError::generic(format!("no points found for id '{id}' (not registered, or no published epoch yet)")));
    }
    if status != 200 {
        return Err(CliError::generic(format!("MTP service returned HTTP {status}: {}", body.trim())));
    }
    let v: Value = serde_json::from_str(&body).map_err(|e| CliError::generic(format!("MTP response was not JSON: {e}")))?;

    match ctx.output {
        OutputFormat::Json => println!("{v}"),
        OutputFormat::Human => {
            let cum = &v["cumulative"];
            println!("id:         {id}");
            println!(
                "cumulative: C1 {}  C2 {}  C3 {}  C4 {}  (total {} mpts)",
                cum["c1"], cum["c2"], cum["c3"], cum["c4"], cum["total"]
            );
            if let Some(epochs) = v["epochs"].as_array() {
                println!("epochs:     {}", epochs.len());
                for e in epochs {
                    let flag = if e["superseded"].as_bool().unwrap_or(false) { " (superseded issues exist)" } else { "" };
                    println!(
                        "  epoch {} [{}] issue {} — C1 {} C2 {} C3 {} C4 {}  ← {}{}",
                        e["epoch"], e["network"].as_str().unwrap_or("?"), e["issue"], e["c1"], e["c2"], e["c3"], e["c4"], e["file"].as_str().unwrap_or("?"), flag
                    );
                }
            }
            if !ctx.quiet {
                println!("\nverify it yourself:  misaka mtp verify-epoch <the epoch-N.issue.jsonl> --pubkey <operator hex>");
                println!("(the signed ledger is the authority — this view is only a mirror of it.)");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `misaka mtp verify-epoch <file.jsonl>`
// ---------------------------------------------------------------------------

fn read_pubkey(pubkey: Option<&str>, pubkey_file: Option<&str>) -> Result<Vec<u8>, CliError> {
    let hex = match (pubkey, pubkey_file) {
        (Some(h), _) => h.trim().to_string(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|e| CliError::generic(format!("cannot read pubkey file '{path}': {e}")))?
            .trim()
            .to_string(),
        (None, None) => {
            return Err(CliError::generic("verify-epoch needs the operator pubkey: pass --pubkey <hex> or --pubkey-file <path>"));
        }
    };
    let mut bytes = vec![0u8; hex.len() / 2];
    faster_hex::hex_decode(hex.as_bytes(), &mut bytes).map_err(|e| CliError::generic(format!("operator pubkey is not valid hex: {e}")))?;
    if bytes.len() != MLDSA87_PK_LEN {
        return Err(CliError::generic(format!("operator pubkey must be {MLDSA87_PK_LEN} bytes ({} hex chars); got {}", MLDSA87_PK_LEN * 2, bytes.len())));
    }
    Ok(bytes)
}

/// Verify a published, signed epoch ledger locally (ADR-0038 D3 self-verification).
///
/// Runs the recipe in order and stops at the first failure:
///  1. **signature** — `EpochLedger::verify(pubkey)` against the operator key;
///  2. **rules-hash** — the ledger's pinned `rules_hash` matches the current
///     [`Rules`] document (so the scores were computed under the published rules);
///  3. **recompute** (only with `--facts`) — feed the published `EpochInput`
///     through `score_epoch` and byte-compare the resulting ledger scores/hashes.
pub fn verify_epoch(output: OutputFormat, file: &str, pubkey: Option<&str>, pubkey_file: Option<&str>, facts: Option<&str>) -> CliResult {
    let text = std::fs::read_to_string(file).map_err(|e| CliError::generic(format!("cannot read ledger '{file}': {e}")))?;
    let ledger: EpochLedger =
        serde_json::from_str(text.trim()).map_err(|e| CliError::generic(format!("'{file}' is not a valid epoch ledger JSONL: {e}")))?;
    let pk = read_pubkey(pubkey, pubkey_file)?;

    // 1) signature.
    let sig_ok = ledger.verify(&pk);
    // 2) rules-hash (the current v1 rules; a future rules-version bump ships its doc).
    let want_rules = faster_hex::hex_string(&Rules::default().rules_hash().as_bytes());
    let rules_ok = ledger.rules_hash == want_rules;

    // 3) optional full recompute from published facts.
    let recompute = match facts {
        Some(path) => {
            let ftext = std::fs::read_to_string(path).map_err(|e| CliError::generic(format!("cannot read facts '{path}': {e}")))?;
            let input: EpochInput =
                serde_json::from_str(ftext.trim()).map_err(|e| CliError::generic(format!("'{path}' is not a valid EpochInput JSON: {e}")))?;
            let mut recomputed = score_epoch(&input, &Rules::default());
            // score_epoch produces an unsigned ledger; compare the signable content.
            recomputed.sig_mldsa87 = None;
            let mut published = ledger.clone();
            published.sig_mldsa87 = None;
            Some(recomputed == published)
        }
        None => None,
    };

    let all_ok = sig_ok && rules_ok && recompute.unwrap_or(true);

    match output {
        OutputFormat::Json => {
            println!(
                "{}",
                json!({
                    "ok": all_ok,
                    "epoch": ledger.epoch,
                    "network": ledger.network,
                    "signature_valid": sig_ok,
                    "rules_hash_matches": rules_ok,
                    "recompute_matches": recompute,
                    "rules_hash": ledger.rules_hash,
                    "inputs_hash": ledger.inputs_hash,
                    "score_rows": ledger.scores.len(),
                })
            );
        }
        OutputFormat::Human => {
            println!("epoch {} [{}] — {} score rows", ledger.epoch, ledger.network, ledger.scores.len());
            println!("  signature (ML-DSA-87):  {}", if sig_ok { "VALID" } else { "INVALID" });
            println!("  rules-hash matches v1:  {}", if rules_ok { "yes" } else { "NO (different rules version?)" });
            match recompute {
                Some(true) => println!("  recompute byte-compare: MATCH"),
                Some(false) => println!("  recompute byte-compare: MISMATCH"),
                None => println!("  recompute byte-compare: skipped (pass --facts <EpochInput.json> to run it)"),
            }
            println!("  rules_hash:  {}", ledger.rules_hash);
            println!("  inputs_hash: {}", ledger.inputs_hash);
            println!("\n{}", if all_ok { "OK — this ledger is authentic." } else { "FAILED — do not trust this ledger." });
        }
    }

    if all_ok { Ok(()) } else { Err(CliError::generic("epoch ledger verification failed")) }
}
