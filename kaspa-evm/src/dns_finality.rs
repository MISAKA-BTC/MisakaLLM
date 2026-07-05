//! F005 `DNS_FINALITY` — exposes the DNS-finality context to the EVM lane
//! (design MIL §8.4).
//!
//! A PURE read: it returns two block-env scalars captured into the handler
//! closure (the same mechanism as `f003_active`, one level deeper):
//! - `currentDaa`: the executing block's L1 DAA score,
//! - `dnsFinalDaa`: the DAA score of the latest DNS-final (stake-confirmed)
//!   anchor.
//!
//! Output is `abi.encode(uint256 currentDaa, uint256 dnsFinalDaa)` (64 bytes),
//! so a `JobEscrow` can decide "is this escrow's open block DNS-final?" on-chain
//! without a trusted oracle (§8.4). Input calldata is ignored. Non-payable: a
//! value-bearing call reverts. Registered ONLY when the shared F003/MIL fence
//! is active; below it the handler is absent and a call is byte-identical to a
//! call to an empty account.
//!
//! See the activation-prerequisite note on
//! [`kaspa_consensus_core::evm::MISAKA_DNS_FINALITY_PRECOMPILE`]: `dnsFinalDaa`
//! must be an ancestor-derived deterministic value before activation.

use kaspa_consensus_core::evm::{F005_DNS_FINALITY_GAS, MISAKA_DNS_FINALITY_PRECOMPILE};
use revm::handler::register::EvmHandler;
use revm::interpreter::{CallOutcome, Gas, InstructionResult, InterpreterResult};
use revm::primitives::{Address, Bytes};
use revm::{Database, FrameOrResult, FrameResult};

/// The F005 address as a revm `Address`.
pub fn f005_address() -> Address {
    Address::from(MISAKA_DNS_FINALITY_PRECOMPILE.as_bytes())
}

/// The pure F005 output: two big-endian 32-byte words `currentDaa ‖ dnsFinalDaa`.
pub fn encode_dns_finality(current_daa: u64, dns_final_daa: u64) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&current_daa.to_be_bytes());
    out[56..64].copy_from_slice(&dns_final_daa.to_be_bytes());
    out
}

/// Wrap `handler.execution.call` so calls targeting F005 return the captured
/// DNS-finality scalars. Everything else delegates to the previous handle.
/// Registered ONLY when the shared F003/MIL fence is active (see
/// [`crate::precompiles::register_all_misaka_precompiles`]).
pub fn register_f005_dns_finality<EXT, DB: Database>(handler: &mut EvmHandler<'_, EXT, DB>, current_daa: u64, dns_final_daa: u64) {
    let prev = handler.execution.call.clone();
    handler.execution.call = std::sync::Arc::new(move |ctx, inputs| {
        let f005 = f005_address();
        if inputs.target_address != f005 || inputs.bytecode_address != f005 {
            return prev(ctx, inputs);
        }
        let mut gas = Gas::new(inputs.gas_limit);
        if !gas.record_cost(F005_DNS_FINALITY_GAS) {
            return Ok(FrameOrResult::Result(FrameResult::Call(CallOutcome::new(
                InterpreterResult { result: InstructionResult::PrecompileOOG, output: Bytes::new(), gas },
                inputs.return_memory_offset.clone(),
            ))));
        }
        // F005 is non-payable: a value-bearing call reverts so value is not stranded.
        if let Some(v) = inputs.value.transfer()
            && !v.is_zero()
        {
            return Ok(FrameOrResult::Result(FrameResult::Call(CallOutcome::new(
                InterpreterResult { result: InstructionResult::Revert, output: Bytes::new(), gas },
                inputs.return_memory_offset.clone(),
            ))));
        }
        let output = Bytes::from(encode_dns_finality(current_daa, dns_final_daa).to_vec());
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
    fn encodes_two_be_words() {
        let out = encode_dns_finality(0x1122, 0x3344);
        // currentDaa in word 0 (bytes 24..32), dnsFinalDaa in word 1 (bytes 56..64)
        assert_eq!(&out[24..32], &0x1122u64.to_be_bytes());
        assert_eq!(&out[56..64], &0x3344u64.to_be_bytes());
        assert_eq!(&out[0..24], &[0u8; 24]);
        assert_eq!(&out[32..56], &[0u8; 24]);
    }

    #[test]
    fn address_is_f005() {
        assert_eq!(MISAKA_DNS_FINALITY_PRECOMPILE.as_bytes()[19], 0x05);
        assert_eq!(MISAKA_DNS_FINALITY_PRECOMPILE.as_bytes()[18], 0xF0);
    }
}
