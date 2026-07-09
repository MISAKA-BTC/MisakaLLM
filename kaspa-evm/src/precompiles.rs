//! Single registration seam for all MISAKA EVM precompiles / call-frame
//! intercepts (PREA design v1.1 §9.5, §23.1 #4). Both the block executor
//! ([`crate::executor::execute_block_evm`]) and the read-only simulator
//! ([`crate::sim::simulate_call`] / `estimate_gas`) register handlers through
//! THIS function so they can never diverge — an `eth_call` / `eth_estimateGas`
//! result is always computed with the exact handler set consensus uses.
//!
//! - **F002** (`MISAKA_WITHDRAW`) is always registered (live since the EVM lane).
//! - **F003** (`MLDSA87_VERIFY`) is registered ONLY when its activation fence is
//!   reached (`f003_active`). Below the fence it is absent, so a call to
//!   `0x…F003` behaves as a call to an empty account — byte-identical execution,
//!   genesis/state-root unchanged. `f003_active` is derived identically on both
//!   sides (`daa_score >= evm_f003_mldsa_verify_activation_daa_score`), keeping
//!   executor↔simulation parity.
//! - **F004** (`HASH64`, keyed BLAKE2b-512; MIL §8.3) and **F005**
//!   (`DNS_FINALITY`; MIL §8.4) share the F003 fence — all are the MIL/PREA-era
//!   precompile set that activates at one coordinated EVM-HF, so gating them on
//!   `f003_active` avoids extra fences while keeping the same below-the-fence
//!   byte-identical property. F005 additionally captures two block-env DAA
//!   scalars into its handler (the `DnsFinalityView`).

use revm::Database;
use revm::handler::register::EvmHandler;

/// The two block-env DAA scalars F005 exposes (design §8.4): the executing
/// block's L1 DAA score and the latest DNS-final anchor's DAA score.
#[derive(Debug, Clone, Copy, Default)]
pub struct DnsFinalityView {
    pub current_daa: u64,
    pub dns_final_daa: u64,
}

/// Register every MISAKA precompile/intercept on `handler`. F002 unconditionally;
/// F003 + F004 + F005 iff `f003_active`; **F006 iff `f006_active`** (its own,
/// separate fence — ADR-0033 §SP-0 gates the shielded pool independently of the
/// MIL/PREA set). Order: F002, F003, F004, F005, F006 (each wraps
/// `execution.call`, so a call to Fnnn is matched by its own wrapper and any
/// other call falls through to the default).
pub fn register_all_misaka_precompiles<EXT, DB: Database>(
    handler: &mut EvmHandler<'_, EXT, DB>,
    f003_active: bool,
    f006_active: bool,
    dns: DnsFinalityView,
) {
    crate::withdraw::register_f002_withdraw(handler);
    if f003_active {
        crate::mldsa_verify::register_f003_mldsa_verify(handler);
        crate::hash64::register_f004_hash64(handler);
        crate::dns_finality::register_f005_dns_finality(handler, dns.current_daa, dns.dns_final_daa);
    }
    if f006_active {
        crate::shielded::register_f006_shielded_verify(handler);
    }
}
