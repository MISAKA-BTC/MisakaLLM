//! kaspa-pq ADR-0039 Phase 5: in-process PALW **algo-4 mining** service (`--palw-mine`).
//!
//! The mil/miner producers (real Qwen backend → k=2 leaf → beacon → provider-bond/manifest/leaf-chunk/
//! certificate → eligibility grind) are pure and tested; this service is the missing NODE glue that
//! drives the live algo-4 mint loop. Structurally it mirrors [`crate::validator_service`]: it holds the
//! same [`ConsensusManager`] / [`FlowContext`] / [`TickService`] handles, does eager config validation in
//! [`PalwMineService::new`], and runs a tick-driven [`worker`](PalwMineService::worker) loop that breaks
//! on `TickReason::Shutdown`. Each ready tick it mints one algo-4 block off the sink via the consensus
//! mint (`ConsensusApi::palw_demo_mint_algo4`) and submits it with [`FlowContext::submit_rpc_block`].
//!
//! **Scope + honest boundaries (READ THIS).**
//!  * **Inert-safe / default off.** Registered only when `--palw-mine` is set. On mainnet/testnet-10/
//!    devnet/simnet the lane is fenced (`palw_activation_daa_score = u64::MAX`); the service detects an
//!    inactive lane and becomes a no-op (it still ticks so shutdown is handled). The two PALW re-genesis
//!    presets — testnet-palw-110 and devnet-palw-111 — instead ship `palw_activation_daa_score = 0`, so
//!    the lane IS active there; what fences them is ADR-0040 P0-3's separate `palw_algo4_accept`, which
//!    ships `false` on ALL SIX presets. A mined algo-4 block is therefore rejected
//!    (`RuleError::PalwAlgo4NotAccepted`) unless the operator also passes `--palw-enable-algo4`.
//!  * **devnet-palw ONLY (ADR-0040 P0-1).** The mint this service drives, `palw_demo_mint_algo4`, seeds a
//!    MOCK leaf + empty-vote certificate + `Active` view directly into the real consensus stores. P0-1
//!    narrowed its net gate from {devnet-palw, testnet-palw} to **devnet-palw only**, because
//!    testnet-palw is a SHARED network (`palw_activation_daa_score = 0`) where forged provenance could
//!    reach other participants. On `--testnet --netsuffix=110` this service now logs the mint's refusal
//!    every tick and mints nothing — that is the intended behaviour, not a misconfiguration. Do NOT
//!    re-widen the gate; the supported route to algo-4 on a shared net is the real producer path
//!    (registration → k=2 receipts → auditor certificate → `TicketAuthority::authorize`).
//!  * **The mint it drives is still the reference mint.** `palw_demo_mint_algo4` builds a REAL, valid,
//!    consensus-accepted algo-4 Header-v3 block (it resolves the finality-buried DNS anchor, grinds a
//!    ticket that wins the real clause-9 draw, and restamps the header), but it SEEDS a mock k=2
//!    leaf/certificate/Active-view into the stores rather than standing the batch up from real overlay
//!    transactions. Productionizing the mint to consume a genuinely-Active batch (real
//!    provider-bond/manifest/leaf-chunk/certificate txs run through the multi-epoch lifecycle) is the
//!    next slice and needs the DNS-beacon liveness stack.
//!  * **Time-bounded on a bare node.** With no bonded validators + no beacon quorum the epoch beacon
//!    stays in `DegradedGrace` then `Halted` (grace = 1, epoch = 100 DAA); once the tip crosses PALW
//!    epoch 0 an algo-4 block is disqualified (`PalwLaneHalted`). Sustained mining past epoch 0 requires
//!    the liveness stack (bonded validators for DNS health + the beacon commit/reveal producers reaching
//!    quorum). This service is the loop; that stack is a companion follow-up.
//!  * **Stage A weightlessness.** `palw_compute_work_scale = 0` on the PALW presets, so a mined algo-4
//!    block is accepted + measured but carries no fork-choice weight. Expected (Stage A).

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::coinbase::MinerData;
use kaspa_consensus_core::errors::consensus::ConsensusError;
use kaspa_consensusmanager::ConsensusManager;
use kaspa_core::{
    info,
    task::{
        service::{AsyncService, AsyncServiceFuture},
        tick::{TickReason, TickService},
    },
    trace, warn,
};
use kaspa_p2p_flows::flow_context::FlowContext;
use kaspa_txscript::pay_to_address_script;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PALW_MINE: &str = "palw-mine-service";

/// Attempt cadence. The loop only mints when the sink has advanced, so a short tick just keeps
/// latency low without producing sibling blocks off one sink.
const MINE_TICK_SECS: u64 = 5;

/// Static `--palw-mine` configuration derived from CLI args.
#[derive(Debug, Clone)]
pub struct PalwMineConfig {
    /// The miner coinbase / payout address (`--palw-mine-address`). Must be an ML-DSA-87 P2PKH address
    /// on this network's prefix. `None` disables mining (the service no-ops with a warning).
    pub address: Option<String>,
    /// This network's address prefix (for validating `address`).
    pub address_prefix: Prefix,
    /// Whether the running network's PALW lane is active. `false` ⇒ the service is an inert no-op.
    pub palw_active: bool,
}

/// Why a mint attempt produced no block this tick — used to keep the loop quiet for the expected
/// "not ready yet" cases and WARN only on genuine faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MintOutcome {
    /// Expected on a young chain / non-PALW net: no finality-buried anchor yet, or the mint's own
    /// net gate. Retry next tick without noise.
    NotReady,
    /// A genuine fault worth surfacing.
    Fault,
}

/// Classify the consensus mint error string. The "no finality-buried DNS anchor off the sink yet — mine
/// more algo-3 supporting blocks first" message (and the mint's own devnet/testnet-palw net gate) are
/// EXPECTED preconditions on a young or wrong-net chain; anything else is a real fault.
fn classify_mint_error(msg: &str) -> MintOutcome {
    let m = msg.to_ascii_lowercase();
    if m.contains("finality-buried") || m.contains("mine more algo-3") || m.contains("devnet-palw") || m.contains("testnet-palw") {
        MintOutcome::NotReady
    } else {
        MintOutcome::Fault
    }
}

/// Validate `address` as an ML-DSA-87 P2PKH address on `prefix` and build the coinbase [`MinerData`].
/// Errors (as a message) if the address is malformed, on the wrong network prefix, or not the PQ-only
/// ML-DSA-87 P2PKH class the coinbase-payload rule requires.
fn resolve_miner_data(address: &str, prefix: Prefix) -> Result<MinerData, String> {
    let addr = Address::try_from(address).map_err(|e| format!("invalid --palw-mine-address '{address}': {e}"))?;
    if addr.prefix != prefix {
        return Err(format!("--palw-mine-address prefix {} does not match this network's prefix {prefix}", addr.prefix));
    }
    if addr.version != Version::PubKeyHashMlDsa87 {
        return Err("--palw-mine-address must be an ML-DSA-87 P2PKH (PubKeyHashMlDsa87) address — a non-PQ coinbase script is rejected by the PQ-only rule".to_owned());
    }
    Ok(MinerData::new(pay_to_address_script(&addr), Vec::new()))
}

pub struct PalwMineService {
    consensus_manager: Arc<ConsensusManager>,
    tick_service: Arc<TickService>,
    /// Used to submit the minted algo-4 block to the local DAG + p2p.
    flow_context: Arc<FlowContext>,
    /// The coinbase target the minted blocks pay. `None` ⇒ the service no-ops (address absent/invalid).
    miner_data: Option<MinerData>,
    /// Whether the net's PALW lane is active. `false` ⇒ inert no-op (still ticks for shutdown).
    palw_active: bool,
    /// The last sink a block was successfully minted off, so successive ready ticks don't produce
    /// sibling algo-4 blocks off a single sink.
    last_mined_sink: Mutex<Option<BlockHash>>,
}

impl PalwMineService {
    pub fn new(
        config: PalwMineConfig,
        consensus_manager: Arc<ConsensusManager>,
        tick_service: Arc<TickService>,
        flow_context: Arc<FlowContext>,
    ) -> Self {
        // Validate the payout address eagerly so misconfiguration surfaces at startup.
        let miner_data = match &config.address {
            Some(addr) => match resolve_miner_data(addr, config.address_prefix) {
                Ok(md) => {
                    info!("[{PALW_MINE}] mining to {addr}");
                    Some(md)
                }
                Err(err) => {
                    warn!("[{PALW_MINE}] {err} — mining disabled");
                    None
                }
            },
            None => {
                warn!("[{PALW_MINE}] --palw-mine is set but --palw-mine-address is missing — mining disabled");
                None
            }
        };
        if !config.palw_active {
            warn!(
                "[{PALW_MINE}] the PALW lane is INACTIVE on this network (palw_activation_daa_score = u64::MAX); \
                 --palw-mine is a no-op here. Run --testnet --netsuffix=110 (testnet-palw) or --devnet \
                 --netsuffix=111 (devnet-palw) to mine algo-4 blocks."
            );
        }
        Self {
            consensus_manager,
            tick_service,
            flow_context,
            miner_data,
            palw_active: config.palw_active,
            last_mined_sink: Mutex::new(None),
        }
    }

    pub async fn worker(self: &Arc<PalwMineService>) {
        info!("[{PALW_MINE}] starting (palw_active={}, mining={})", self.palw_active, self.miner_data.is_some());
        loop {
            if let TickReason::Shutdown = self.tick_service.tick(Duration::from_secs(MINE_TICK_SECS)).await {
                break;
            }
            // Inert unless the lane is active AND we have a valid payout address.
            let Some(miner_data) = self.miner_data.clone() else { continue };
            if !self.palw_active {
                continue;
            }
            self.try_mine_once(miner_data).await;
        }
        info!("[{PALW_MINE}] stopped");
    }

    /// One mint+submit attempt. Only mints when the sink has advanced since the last successful block.
    async fn try_mine_once(self: &Arc<PalwMineService>, miner_data: MinerData) {
        let sink = self.consensus_manager.consensus().unguarded_session().async_get_sink().await;
        if *self.last_mined_sink.lock().unwrap() == Some(sink) {
            return; // already mined off this sink; wait for it to advance
        }

        // Build + mint the algo-4 block off the sink. The mint is a synchronous ConsensusApi method with
        // no async wrapper, so it runs on a blocking thread via the owned session.
        let session = self.consensus_manager.consensus().session().await;
        let minted = session.spawn_blocking(move |c| c.palw_demo_mint_algo4(miner_data)).await;
        let block = match minted {
            Ok(block) => block,
            Err(ConsensusError::GeneralOwned(msg)) => {
                match classify_mint_error(&msg) {
                    MintOutcome::NotReady => trace!("[{PALW_MINE}] not ready to mint off sink {sink}: {msg}"),
                    MintOutcome::Fault => warn!("[{PALW_MINE}] mint off sink {sink} failed: {msg}"),
                }
                return;
            }
            Err(err) => {
                warn!("[{PALW_MINE}] mint off sink {sink} failed: {err}");
                return;
            }
        };

        // Submit through the production block path (validate_and_insert_block + gossip).
        let hash = block.hash();
        let submit_session = self.consensus_manager.consensus().unguarded_session();
        match self.flow_context.submit_rpc_block(&submit_session, block).await {
            Ok(()) => {
                info!("[{PALW_MINE}] mined + submitted algo-4 block {hash} off sink {sink}");
                *self.last_mined_sink.lock().unwrap() = Some(sink);
            }
            Err(err) => warn!("[{PALW_MINE}] submit of algo-4 block {hash} failed: {err}"),
        }
    }
}

impl AsyncService for PalwMineService {
    fn ident(self: Arc<Self>) -> &'static str {
        PALW_MINE
    }

    fn start(self: Arc<Self>) -> AsyncServiceFuture {
        Box::pin(async move {
            self.worker().await;
            Ok(())
        })
    }

    fn signal_exit(self: Arc<Self>) {
        trace!("sending an exit signal to {}", PALW_MINE);
    }

    fn stop(self: Arc<Self>) -> AsyncServiceFuture {
        Box::pin(async move {
            trace!("{} stopped", PALW_MINE);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_error_classification_quiets_expected_preconditions() {
        // The two "not ready" preconditions the mint returns on a young / wrong-net chain.
        assert_eq!(
            classify_mint_error("no finality-buried DNS anchor off the sink yet — mine more algo-3 supporting blocks first"),
            MintOutcome::NotReady
        );
        // The CURRENT wrong-net refusal, verbatim from `Consensus::palw_demo_mint_algo4_impl` after
        // ADR-0040 P0-1 narrowed the gate to devnet-palw only. This string is duplicated here rather
        // than imported because the emitter lives in kaspa-consensus and is not re-exported; if that
        // message is ever reworded so it contains neither "devnet-palw" nor "testnet-palw", this test
        // keeps passing while the live service starts warn!-spamming a correctly-configured node every
        // tick. Re-check `palw_demo.rs`'s refusal text whenever `classify_mint_error` changes.
        assert_eq!(classify_mint_error("palw_demo_mint_algo4 is devnet-palw ONLY (net = Testnet)"), MintOutcome::NotReady);
        // The pre-P0-1 wording must stay classified too: an older consensus build paired with this
        // binary should not be reported as a fault.
        assert_eq!(
            classify_mint_error("palw_demo_mint_algo4 is devnet-palw / testnet-palw only (net = Testnet)"),
            MintOutcome::NotReady
        );
        // A genuine fault is surfaced.
        assert_eq!(classify_mint_error("some unexpected internal error"), MintOutcome::Fault);
    }

    #[test]
    fn miner_data_requires_mldsa87_address_on_the_right_prefix() {
        // A malformed address is rejected.
        assert!(resolve_miner_data("not-an-address", Prefix::Testnet).is_err());
        // A well-formed ML-DSA-87 P2PKH testnet address on the WRONG prefix is rejected.
        let addr = Address::new(Prefix::Testnet, Version::PubKeyHashMlDsa87, &[0u8; 64]);
        let s = addr.to_string();
        assert!(resolve_miner_data(&s, Prefix::Testnet).is_ok(), "matching prefix + ML-DSA-87 accepted");
        assert!(resolve_miner_data(&s, Prefix::Mainnet).is_err(), "wrong prefix rejected");
    }
}
