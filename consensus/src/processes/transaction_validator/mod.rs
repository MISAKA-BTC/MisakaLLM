pub mod errors;
pub mod tx_validation_in_header_context;
pub mod tx_validation_in_isolation;
pub mod tx_validation_in_utxo_context;
use std::sync::Arc;

use kaspa_txscript::{
    SigCacheKey,
    caches::{Cache, TxScriptCacheCounters},
};

use kaspa_consensus_core::{KType, config::params::PqEnforcementMode, mass::MassCalculator};
use kaspa_txscript::ScriptPolicy;

#[derive(Clone)]
pub struct TransactionValidator {
    max_tx_inputs: usize,
    max_tx_outputs: usize,
    max_signature_script_len: usize,
    max_script_public_key_len: usize,
    coinbase_payload_script_public_key_max_len: u8,
    coinbase_maturity: u64,
    ghostdag_k: KType,
    sig_cache: Cache<SigCacheKey, bool>,
    pub(crate) mass_calculator: MassCalculator,
    /// kaspa-pq PQ-only enforcement mode for this network (ADR-0019).
    pq_enforcement: PqEnforcementMode,
    /// DAA score at/after which `PqEnforcementMode::Consensus` takes effect.
    pq_activation_daa_score: u64,
    /// kaspa-pq ADR-0040 **ECON-02** — does this NETWORK have a PALW lane at all, i.e.
    /// `params.palw_activation_daa_score != u64::MAX`. True only on testnet-palw-110 / devnet-palw-111.
    ///
    /// It deliberately does NOT mirror `params.palw_algo4_accept`. That lever is MUTATED AT RUNTIME by
    /// `--palw-enable-algo4` (kaspad/src/args.rs), and the coinbase output cap is a consensus rule that
    /// applies to EVERY coinbase — algo-3 included. Fencing it on an operator flag would make two nodes
    /// on the same network disagree about whether an ordinary algo-3 block is valid, i.e. a
    /// flag-induced consensus split. `palw_activation_daa_score` is assigned only in
    /// `config/params.rs` and never mutated, so it is a safe fence.
    ///
    /// Widening the cap on a PALW preset costs nothing where the lane is closed: no algo-4 block can be
    /// accepted while `palw_algo4_accept` is false, so no coinbase with the wide PALW arm can exist —
    /// the cap is simply not the binding constraint there.
    pub(crate) palw_lane_present: bool,
}

impl TransactionValidator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_tx_inputs: usize,
        max_tx_outputs: usize,
        max_signature_script_len: usize,
        max_script_public_key_len: usize,
        coinbase_payload_script_public_key_max_len: u8,
        coinbase_maturity: u64,
        ghostdag_k: KType,
        counters: Arc<TxScriptCacheCounters>,
        mass_calculator: MassCalculator,
        pq_enforcement: PqEnforcementMode,
        pq_activation_daa_score: u64,
        palw_lane_present: bool,
    ) -> Self {
        Self {
            max_tx_inputs,
            max_tx_outputs,
            max_signature_script_len,
            max_script_public_key_len,
            coinbase_payload_script_public_key_max_len,
            coinbase_maturity,
            ghostdag_k,
            sig_cache: Cache::with_counters(10_000, counters),
            mass_calculator,
            pq_enforcement,
            pq_activation_daa_score,
            palw_lane_present,
        }
    }

    pub fn new_for_tests(
        max_tx_inputs: usize,
        max_tx_outputs: usize,
        max_signature_script_len: usize,
        max_script_public_key_len: usize,
        coinbase_payload_script_public_key_max_len: u8,
        coinbase_maturity: u64,
        ghostdag_k: KType,
        counters: Arc<TxScriptCacheCounters>,
    ) -> Self {
        Self {
            max_tx_inputs,
            max_tx_outputs,
            max_signature_script_len,
            max_script_public_key_len,
            coinbase_payload_script_public_key_max_len,
            coinbase_maturity,
            ghostdag_k,
            sig_cache: Cache::with_counters(10_000, counters),
            mass_calculator: MassCalculator::new(0, 0, 0, 0),
            // Tests run upstream-compatible (no PQ restriction) unless a test
            // explicitly exercises PQ-only via the script engine directly.
            pq_enforcement: PqEnforcementMode::Disabled,
            pq_activation_daa_score: 0,
            // Matches every non-PALW preset. A test that wants the widened PALW cap sets the field
            // directly — it is visible to this module's descendants.
            palw_lane_present: false,
        }
    }

    /// kaspa-pq: resolve the [`ScriptPolicy`] to apply at `pov_daa_score`.
    /// `PQ_ONLY` once PQ-only enforcement is active (legacy secp256k1 opcodes +
    /// P2SH become hard errors), else `LEGACY` (upstream-identical). See ADR-0019.
    pub(crate) fn resolved_script_policy(&self, pov_daa_score: u64) -> ScriptPolicy {
        if matches!(self.pq_enforcement, PqEnforcementMode::Consensus) && pov_daa_score >= self.pq_activation_daa_score {
            ScriptPolicy::PQ_ONLY
        } else {
            ScriptPolicy::LEGACY
        }
    }
}
