//! MIL faucet client (design §14.3c): solve the faucet proof-of-work and claim
//! the experience-credit drip, so a brand-new user can obtain a little testnet
//! MSK without procuring it out-of-band.
//!
//! The faucet ([`contracts/mil/src/Faucet.sol`]) is Sybil-suppressed by a
//! per-recipient cooldown plus a light PoW: the caller must find a `nonce` such
//! that `keccak256(recipient ‖ epoch ‖ nonce)` has at least `powBits` leading
//! zero bits. This module brute-forces that nonce (a pure, deterministic loop),
//! encodes the `claim(address,uint256)` calldata, and — with a key + node —
//! submits it via the shared [`crate::evm_send`] path. The PoW solver and
//! calldata encoder are pure and unit-tested against `cast`-derived vectors.

use crate::node::Ctx;
use crate::{CliError, CliResult, OutputFormat, exit};
use alloy_primitives::{Address, B256, U256, keccak256};
use serde_json::json;
use std::str::FromStr;

/// Selector of `Faucet.claim(address,uint256)`.
const CLAIM_SELECTOR: [u8; 4] = [0xaa, 0xd3, 0xec, 0x96];
/// No-arg getter selectors (see `cast sig`).
const POW_BITS_SELECTOR: &str = "0xbf8d6799"; // powBits()
const EPOCH_SELECTOR: &str = "0x900cf0cf"; // epoch()
const DRIP_AMOUNT_SELECTOR: &str = "0x35a1529b"; // dripAmount()
const COOLDOWN_SELECTOR: &str = "0x787a08a6"; // cooldown()
const LAST_CLAIM_SELECTOR: &str = "0x5c16e15e"; // lastClaim(address)

// --- pure PoW + calldata (unit-tested) ----------------------------------------

/// The faucet PoW digest: `keccak256(abi.encodePacked(recipient, epoch, nonce))`
/// — a 20-byte address followed by two 32-byte big-endian words.
pub fn pow_digest(recipient: Address, epoch: U256, nonce: U256) -> B256 {
    let mut buf = Vec::with_capacity(20 + 32 + 32);
    buf.extend_from_slice(recipient.as_slice());
    buf.extend_from_slice(&epoch.to_be_bytes::<32>());
    buf.extend_from_slice(&nonce.to_be_bytes::<32>());
    keccak256(&buf)
}

/// The strict PoW threshold `1 << (256 - bits)`, matching Solidity's
/// `_hasLeadingZeroBits` exactly — including the degenerate `bits == 0` case
/// where Solidity's `1 << 256` wraps to `0` (so nothing passes).
fn pow_threshold(bits: u8) -> U256 {
    if bits == 0 { U256::ZERO } else { U256::from(1u8) << (256 - bits as usize) }
}

/// Whether `digest` clears `bits` leading zero bits (`uint256(digest) < 2^(256-bits)`).
pub fn has_leading_zero_bits(digest: B256, bits: u8) -> bool {
    U256::from_be_bytes(digest.0) < pow_threshold(bits)
}

/// Brute-force a PoW nonce for `recipient` at `epoch` clearing `bits` leading
/// zero bits, scanning `nonce = 0..max_iters`. Deterministic (first solution).
pub fn solve_pow(recipient: Address, epoch: U256, bits: u8, max_iters: u64) -> Result<(U256, B256), String> {
    if bits == 0 {
        return Err("powBits must be >= 1 (powBits == 0 is unsatisfiable by the contract)".to_string());
    }
    if bits > 64 {
        return Err(format!("powBits {bits} is far beyond a CPU-solvable range (>64)"));
    }
    for n in 0..max_iters {
        let nonce = U256::from(n);
        let digest = pow_digest(recipient, epoch, nonce);
        if has_leading_zero_bits(digest, bits) {
            return Ok((nonce, digest));
        }
    }
    Err(format!("no PoW solution for powBits={bits} within {max_iters} iterations (raise --max-iters)"))
}

/// ABI-encode `claim(address recipient, uint256 nonce)` calldata.
pub fn claim_calldata(recipient: Address, nonce: U256) -> Vec<u8> {
    let mut cd = Vec::with_capacity(4 + 32 + 32);
    cd.extend_from_slice(&CLAIM_SELECTOR);
    cd.extend_from_slice(&[0u8; 12]); // left-pad the 20-byte address to 32
    cd.extend_from_slice(recipient.as_slice());
    cd.extend_from_slice(&nonce.to_be_bytes::<32>());
    cd
}

// --- eth-rpc reads (faucet params + recipient readiness) ----------------------

fn parse_addr(s: &str) -> Result<Address, CliError> {
    Address::from_str(s).map_err(|e| CliError::generic(format!("invalid address {s}: {e}")))
}

fn eth_call_u256(ctx: &Ctx, to: &str, data_hex: &str) -> Result<U256, CliError> {
    let v = crate::eth::rpc_call(ctx, "eth_call", json!([{ "to": to, "data": data_hex }, "latest"]))?;
    let s = v.as_str().ok_or_else(|| CliError::generic("eth_call: result is not a hex string"))?;
    let raw = s.strip_prefix("0x").unwrap_or(s);
    if raw.is_empty() {
        return Err(CliError::generic(format!("eth_call to {to} returned empty (wrong address / not deployed?)")));
    }
    let mut bytes = vec![0u8; raw.len().div_ceil(2)];
    faster_hex::hex_decode(raw.as_bytes(), &mut bytes).map_err(|e| CliError::generic(format!("eth_call decode: {e}")))?;
    Ok(U256::from_be_slice(&bytes))
}

/// Read `(powBits, epoch)` from the faucet, using CLI overrides when supplied.
fn resolve_pow_params(ctx: &Ctx, faucet: &str, bits: Option<u8>, epoch: Option<u64>) -> Result<(u8, U256), CliError> {
    let bits = match bits {
        Some(b) => b,
        None => eth_call_u256(ctx, faucet, POW_BITS_SELECTOR)?.to::<u64>() as u8,
    };
    let epoch = match epoch {
        Some(e) => U256::from(e),
        None => eth_call_u256(ctx, faucet, EPOCH_SELECTOR)?,
    };
    Ok((bits, epoch))
}

// --- command handlers ---------------------------------------------------------

/// `misaka faucet solve` — brute-force the PoW offline and print the nonce +
/// ready-to-submit `claim` calldata (no node contacted).
pub fn run_solve(output: OutputFormat, recipient: &str, bits: u8, epoch: u64, max_iters: u64) -> CliResult {
    let addr = parse_addr(recipient)?;
    let (nonce, digest) = solve_pow(addr, U256::from(epoch), bits, max_iters).map_err(CliError::generic)?;
    let calldata = format!("0x{}", faster_hex::hex_string(&claim_calldata(addr, nonce)));
    match output {
        OutputFormat::Human => {
            println!("recipient : {addr}");
            println!("epoch     : {epoch}");
            println!("powBits   : {bits}");
            println!("nonce     : {nonce}");
            println!("digest    : {digest}");
            println!("calldata  : {calldata}");
            println!("\nSubmit with: misaka evm call --to <FAUCET> --data {calldata} --key … --yes");
        }
        OutputFormat::Json => println!(
            "{}",
            json!({ "ok": true, "recipient": addr.to_string(), "epoch": epoch, "powBits": bits, "nonce": nonce.to_string(), "digest": digest.to_string(), "calldata": calldata })
        ),
    }
    Ok(())
}

/// `misaka faucet status` — read the faucet parameters and (optionally) a
/// recipient's cooldown readiness.
pub fn run_status(ctx: &Ctx, faucet: &str, recipient: Option<&str>) -> CliResult {
    let _ = parse_addr(faucet)?;
    let pow_bits = eth_call_u256(ctx, faucet, POW_BITS_SELECTOR)?.to::<u64>();
    let epoch = eth_call_u256(ctx, faucet, EPOCH_SELECTOR)?;
    let drip = eth_call_u256(ctx, faucet, DRIP_AMOUNT_SELECTOR)?;
    let cooldown = eth_call_u256(ctx, faucet, COOLDOWN_SELECTOR)?;
    let last_claim = match recipient {
        Some(r) => {
            let a = parse_addr(r)?;
            let data = format!("0x{}{}", LAST_CLAIM_SELECTOR.trim_start_matches("0x"), hex_pad_addr(a));
            Some(eth_call_u256(ctx, faucet, &data)?)
        }
        None => None,
    };
    match ctx.output {
        OutputFormat::Human => {
            println!("faucet    : {faucet}");
            println!("powBits   : {pow_bits}");
            println!("epoch     : {epoch}");
            println!("dripAmount: {drip} wei");
            println!("cooldown  : {cooldown} s");
            if let Some(lc) = last_claim {
                println!("lastClaim : {lc} (ready-at = lastClaim + cooldown; 0 = never claimed)");
            }
        }
        OutputFormat::Json => println!(
            "{}",
            json!({ "ok": true, "faucet": faucet, "powBits": pow_bits, "epoch": epoch.to_string(), "dripAmount": drip.to_string(), "cooldown": cooldown.to_string(), "lastClaim": last_claim.map(|v| v.to_string()) })
        ),
    }
    Ok(())
}

/// `misaka faucet claim` — solve the PoW (reading powBits/epoch from chain when
/// omitted) and submit `claim(recipient, nonce)` via the shared evm-send path.
#[allow(clippy::too_many_arguments)]
pub fn run_claim(
    ctx: &Ctx,
    ks: &crate::evm_send::EvmKeySource,
    faucet: &str,
    recipient: &str,
    bits: Option<u8>,
    epoch: Option<u64>,
    max_iters: u64,
    gas_limit: Option<u64>,
    max_fee: Option<u128>,
    yes: bool,
    wait: bool,
) -> CliResult {
    let addr = parse_addr(recipient)?;
    let _ = parse_addr(faucet)?;
    let (pow_bits, epoch) = resolve_pow_params(ctx, faucet, bits, epoch)?;
    let (nonce, _digest) = solve_pow(addr, epoch, pow_bits, max_iters).map_err(|e| CliError::new(exit::GENERIC, e))?;
    let calldata = claim_calldata(addr, nonce);
    // value = 0 (the faucet pays out); the caller pays only gas.
    crate::evm_send::call(ctx, ks, faucet, calldata, 0, gas_limit, max_fee, None, yes, wait)
}

fn hex_pad_addr(a: Address) -> String {
    // 12 zero bytes ‖ 20-byte address = one 32-byte ABI word.
    format!("{:0>24}{}", "", faster_hex::hex_string(a.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr_aa() -> Address {
        Address::from_str("0x00000000000000000000000000000000000000aa").unwrap()
    }

    #[test]
    fn claim_calldata_matches_cast_vector() {
        // cast calldata "claim(address,uint256)" 0x..aa 5
        let cd = claim_calldata(addr_aa(), U256::from(5));
        let expect = "aad3ec9600000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000005";
        assert_eq!(faster_hex::hex_string(&cd), expect);
    }

    #[test]
    fn pow_digest_matches_cast_keccak() {
        // cast keccak (0x..aa ‖ epoch=1 ‖ nonce=0)
        let d = pow_digest(addr_aa(), U256::from(1), U256::from(0));
        assert_eq!(d.to_string(), "0xa82378c0a5cac76219e8ef10bfb368e01a05bff1f6e31de346116b1fb7022ac2");
    }

    #[test]
    fn solve_then_verify() {
        let (nonce, digest) = solve_pow(addr_aa(), U256::from(7), 8, 1_000_000).unwrap();
        assert!(has_leading_zero_bits(digest, 8), "solved digest must clear 8 bits");
        assert_eq!(digest.0[0], 0, "8 leading zero bits ⇒ top byte is zero");
        // re-deriving the digest from the returned nonce must reproduce it (determinism)
        assert_eq!(pow_digest(addr_aa(), U256::from(7), nonce), digest);
    }

    #[test]
    fn threshold_edges_match_solidity() {
        assert_eq!(pow_threshold(0), U256::ZERO); // Solidity 1<<256 wraps to 0
        assert_eq!(pow_threshold(1), U256::from(1u8) << 255);
        assert_eq!(pow_threshold(256u16 as u8), U256::ZERO); // 256 as u8 == 0
        assert!(solve_pow(addr_aa(), U256::from(0), 0, 10).is_err());
    }
}
