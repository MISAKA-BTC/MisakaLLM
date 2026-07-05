//! F004 `HASH64` — the keyed-BLAKE2b-512 precompile (design MIL §8.3).
//!
//! A PURE hash: it changes no state and moves no value, so — like F003 — it is
//! reachable from any frame including `STATICCALL`. Implemented as the same
//! **call-frame interception** seam (`handler.execution.call` wrap) so the block
//! executor and `eth_call`/`eth_estimateGas` simulation share ONE registration
//! path (parity).
//!
//! Calldata: `key_len(1) ‖ key(key_len) ‖ data`. Output: the 64-byte
//! `keyed_blake2b_512(key, data)` (Hash64). `key_len` must be ≤
//! [`F004_MAX_KEY_LEN`] and `data` ≤ [`F004_MAX_DATA_BYTES`]; a malformed length
//! returns EMPTY output (never panics, never reverts, except a value-bearing
//! call — F004 is non-payable, so a non-zero `msg.value` reverts so value is not
//! stranded). [`F004_HASH64_GAS`] is charged up-front (before dispatch).
//!
//! This is what lets a MIL Solidity contract recompute the protocol commitments
//! (`cm_req`, `receipt_hash`, `model_id`, `profile_id`) that are derived with
//! keyed BLAKE2b-512 elsewhere, without a BLAKE2b implementation in the EVM.
//! Registered ONLY when the shared F003/MIL activation fence is reached; below
//! it the handler is absent and a call to `0x…F004` is byte-identical to a call
//! to an empty account.

use kaspa_consensus_core::evm::{F004_HASH64_GAS, F004_MAX_DATA_BYTES, F004_MAX_KEY_LEN, MISAKA_HASH64_PRECOMPILE};
use kaspa_hashes::blake2b_512_keyed;
use revm::handler::register::EvmHandler;
use revm::interpreter::{CallOutcome, Gas, InstructionResult, InterpreterResult};
use revm::primitives::{Address, Bytes};
use revm::{Database, FrameOrResult, FrameResult};

/// The F004 address as a revm `Address`.
pub fn f004_address() -> Address {
    Address::from(MISAKA_HASH64_PRECOMPILE.as_bytes())
}

/// The pure F004 logic: parse `key_len ‖ key ‖ data` and return the 64-byte
/// keyed BLAKE2b-512, or `None` for ANY malformed input (empty, key too long,
/// truncated key, data too long). This is the consensus-critical decision; the
/// handler only wraps it with gas + output framing.
pub fn run_f004_hash64(input: &[u8]) -> Option<[u8; 64]> {
    let (&key_len, rest) = input.split_first()?;
    let key_len = key_len as usize;
    if key_len > F004_MAX_KEY_LEN || rest.len() < key_len {
        return None;
    }
    let (key, data) = rest.split_at(key_len);
    if data.len() > F004_MAX_DATA_BYTES {
        return None;
    }
    Some(*blake2b_512_keyed(key, data).as_byte_slice())
}

/// Wrap `handler.execution.call` so calls targeting F004 run the keyed hash
/// instead of loading (empty) code. Everything else delegates to the previous
/// handle. Registered ONLY when the shared F003/MIL fence is active (see
/// [`crate::precompiles::register_all_misaka_precompiles`]).
pub fn register_f004_hash64<EXT, DB: Database>(handler: &mut EvmHandler<'_, EXT, DB>) {
    let prev = handler.execution.call.clone();
    handler.execution.call = std::sync::Arc::new(move |ctx, inputs| {
        let f004 = f004_address();
        if inputs.target_address != f004 || inputs.bytecode_address != f004 {
            return prev(ctx, inputs);
        }
        let mut gas = Gas::new(inputs.gas_limit);
        if !gas.record_cost(F004_HASH64_GAS) {
            return Ok(FrameOrResult::Result(FrameResult::Call(CallOutcome::new(
                InterpreterResult { result: InstructionResult::PrecompileOOG, output: Bytes::new(), gas },
                inputs.return_memory_offset.clone(),
            ))));
        }
        // F004 is non-payable: a value-bearing call reverts so value is not stranded.
        if let Some(v) = inputs.value.transfer()
            && !v.is_zero()
        {
            return Ok(FrameOrResult::Result(FrameResult::Call(CallOutcome::new(
                InterpreterResult { result: InstructionResult::Revert, output: Bytes::new(), gas },
                inputs.return_memory_offset.clone(),
            ))));
        }
        let output = match run_f004_hash64(&inputs.input) {
            Some(h) => Bytes::from(h.to_vec()),
            None => Bytes::new(),
        };
        Ok(FrameOrResult::Result(FrameResult::Call(CallOutcome::new(
            InterpreterResult { result: InstructionResult::Return, output, gas },
            inputs.return_memory_offset.clone(),
        ))))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash64_matches_keyed_blake2b_and_rejects_malformed() {
        // key_len=5, key="misak", data="hello"
        let mut input = vec![5u8];
        input.extend_from_slice(b"misak");
        input.extend_from_slice(b"hello");
        let out = run_f004_hash64(&input).expect("valid input");
        assert_eq!(out, *blake2b_512_keyed(b"misak", b"hello").as_byte_slice());

        // empty key is valid (unkeyed BLAKE2b-512)
        let out0 = run_f004_hash64(&[0u8]).expect("empty key + empty data");
        assert_eq!(out0, *blake2b_512_keyed(b"", b"").as_byte_slice());

        // malformed: empty input, key longer than declared, key over the cap
        assert!(run_f004_hash64(&[]).is_none());
        assert!(run_f004_hash64(&[10u8, 1, 2]).is_none(), "declares 10-byte key, only 2 follow");
        assert!(run_f004_hash64(&[(F004_MAX_KEY_LEN as u8) + 1]).is_none());

        // data over the cap
        let mut big = vec![1u8, b'k'];
        big.extend(std::iter::repeat_n(0u8, F004_MAX_DATA_BYTES + 1));
        assert!(run_f004_hash64(&big).is_none());
    }

    #[test]
    fn address_is_f004() {
        assert_eq!(MISAKA_HASH64_PRECOMPILE.as_bytes()[19], 0x04);
        assert_eq!(MISAKA_HASH64_PRECOMPILE.as_bytes()[18], 0xF0);
    }
}
