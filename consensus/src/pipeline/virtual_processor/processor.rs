use crate::{
    consensus::{
        services::{
            ConsensusServices, DbBlockDepthManager, DbDagTraversalManager, DbGhostdagManager, DbParentsManager, DbPruningPointManager,
            DbWindowManager,
        },
        storage::ConsensusStorage,
    },
    constants::BLOCK_VERSION,
    errors::RuleError,
    model::{
        services::{
            reachability::{MTReachabilityService, ReachabilityService},
            relations::MTRelationsService,
        },
        stores::{
            DB,
            acceptance_data::{AcceptanceDataStoreReader, DbAcceptanceDataStore},
            block_transactions::{BlockTransactionsStoreReader, DbBlockTransactionsStore},
            block_window_cache::{BlockWindowCacheStore, BlockWindowCacheWriter},
            daa::DbDaaStore,
            depth::{DbDepthStore, DepthStoreReader},
            dns_state::{DbDnsStateStore, DnsStateStoreReader},
            epoch_accumulator::{DbBlockQualityPoolStore, DbEpochAccumulatorStore, DbReserveBalanceStore},
            evm::{
                DbEvmCanonicalHeadsStore, DbEvmHeaderStore, DbEvmPayloadStore, DbEvmStateStore, EvmCanonicalHeadsStoreReader,
                EvmHeaderStore, EvmHeaderStoreReader, EvmStateStore, EvmStateStoreReader,
            },
            ghostdag::{DbGhostdagStore, GhostdagData, GhostdagStoreReader},
            headers::{DbHeadersStore, HeaderStoreReader},
            palw::DbPalwStore,
            palw_provider_bonds::{DbPalwProviderBondsStore, PalwProviderBondsStoreReader},
            past_pruning_points::DbPastPruningPointsStore,
            pruning::{DbPruningStore, PruningStoreReader},
            pruning_meta::PruningMetaStores,
            pruning_overlay_snapshot::{DbPruningPointOverlaySnapshotStore, PruningPointOverlaySnapshotStoreReader},
            pruning_samples::DbPruningSamplesStore,
            reachability::DbReachabilityStore,
            relations::{DbRelationsStore, RelationsStoreReader},
            palw_paid_work::{DbPalwPaidWorkStore, PalwPaidWorkIds, PalwPaidWorkStoreReader},
            rewarded_epochs::{DbRewardedEpochsStore, RewardedEpochKeys, RewardedEpochsStoreReader},
            selected_chain::{DbSelectedChainStore, SelectedChainStore},
            stake_bonds::{DbStakeBondsStore, StakeBondsStoreReader},
            statuses::{DbStatusesStore, StatusesStore, StatusesStoreBatchExtensions, StatusesStoreReader},
            tips::{DbTipsStore, TipsStoreReader},
            utxo_diffs::{DbUtxoDiffsStore, UtxoDiffsStoreReader},
            utxo_multisets::{DbUtxoMultisetsStore, UtxoMultisetsStoreReader},
            virtual_state::{LkgVirtualState, VirtualState, VirtualStateStoreReader, VirtualStores},
        },
    },
    params::Params,
    pipeline::{
        ProcessingCounters, deps_manager::VirtualStateProcessingMessage, pruning_processor::processor::PruningProcessingMessage,
        virtual_processor::utxo_validation::UtxoProcessingContext,
    },
    processes::{
        coinbase::CoinbaseManager,
        ghostdag::ordering::SortableBlock,
        transaction_validator::{
            TransactionValidator,
            errors::{TxResult, TxRuleError},
            tx_validation_in_utxo_context::TxValidationFlags,
        },
        window::WindowManager,
    },
};
use kaspa_consensus_core::{
    BlockHash, BlockHashSet, BlueWorkType, ChainPath,
    acceptance_data::AcceptanceData,
    api::args::{TransactionValidationArgs, TransactionValidationBatchArgs},
    block::{
        BlockTemplate, EvmClaimStaleKind, MutableBlock, TemplateBuildMode, TemplateTransactionSelector,
        TemplateTransactionSelectorFactory,
    },
    blockstatus::BlockStatus::{StatusDisqualifiedFromChain, StatusUTXOValid},
    coinbase::MinerData,
    config::genesis::GenesisBlock,
    dns_finality::{
        ATTESTATION_MLDSA87_CONTEXT, ActiveBondView, AttestationContribution, BlockEpochContribution, BlockOverlayContribution,
        BondMutation, BondStatus, CanonicalLaggedEpochAnchor, DnsParams, DnsReorgMode, DnsRolloutStage,
        MandatoryAttestationContributionKey, MandatoryAttestationDeficit, MandatoryAttestationValidator, OverlaySnapshot,
        PruningPointOverlaySnapshot, StakeBondRecord, StakeScore, advance_dns_confirmation, aggregate_epoch_tallies,
        anchor_cutoff_blue_score, apply_dormancy_round, attestations_from_accepted_txs, bond_mutations_from_accepted_txs,
        canonical_lagged_epoch_anchor, check_dns_reorg_rule, compute_stake_score, derive_dns_health, dns_finality_fresh_for_bridge,
        dormancy_revival_ready, effective_bond_status, epoch_meets_quality_floor, is_bond_active_at, is_dns_confirmed,
        mandatory_attestation_mass_capacity, ready_epoch_from_tip_blue_score, recompute_epoch_tallies,
        reorg_inputs_since_common_ancestor, required_stake_for_quality_floor, stake_attestation_message, total_active_stake_by_epoch,
    },
    header::Header,
    merkle::calc_hash_merkle_root,
    palw::{PalwProviderBondMutation, ProviderBondView, palw_provider_bond_mutations_from_accepted_txs},
    mining_rules::MiningRules,
    pruning::PruningPointsList,
    tx::{MutableTransaction, Transaction, TransactionOutpoint},
    utxo::{
        utxo_diff::UtxoDiff,
        utxo_view::{UtxoView, UtxoViewComposition},
    },
};
use kaspa_consensus_notify::{
    notification::{
        NewBlockTemplateNotification, Notification, SinkBlueScoreChangedNotification, UtxosChangedNotification,
        VirtualChainChangedNotification, VirtualDaaScoreChangedNotification,
    },
    root::ConsensusNotificationRoot,
};
use kaspa_consensusmanager::SessionLock;
use kaspa_core::{debug, info, time::unix_now, trace, warn};
use kaspa_database::prelude::{StoreError, StoreResultExt, StoreResultUnitExt};
use kaspa_hashes::{Hash64, ZERO_HASH64};
use kaspa_muhash::MuHash;
use kaspa_notify::{events::EventType, notifier::Notify};
use once_cell::unsync::Lazy;

use super::errors::{PruningImportError, PruningImportResult};
use crossbeam_channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use itertools::Itertools;
use kaspa_consensus_core::tx::ValidatedTransaction;
use kaspa_txscript::verify_mldsa87_with_context;
use kaspa_utils::binary_heap::BinaryHeapExtensions;
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use rand::{Rng, seq::SliceRandom};
use rayon::{
    ThreadPool,
    prelude::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator},
};
use rocksdb::WriteBatch;
use std::{
    cmp::min,
    collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque},
    iter::once,
    ops::Deref,
    sync::{Arc, atomic::Ordering},
};

/// O9 (optimization design v0.1): rolling EVM-lane throughput counters.
/// Recorded only on the `evm` chain-context step, so it is dead on the default
/// (secp-free, non-`evm`) node — silence the dead-code lint there.
#[cfg_attr(not(feature = "evm"), allow(dead_code))]
#[derive(Default)]
pub(super) struct EvmLaneKpi {
    chain_blocks: std::sync::atomic::AtomicU64,
    mergeset_blocks: std::sync::atomic::AtomicU64,
    accepted_gas: std::sync::atomic::AtomicU64,
    // kaspa-pq EVM bridge observability: cumulative deposit-claims APPLIED in
    // accepted chain blocks. Surfaced in the KPI line because accepted-gas
    // utilization rounds to 0.00% even for several successful claims (one claim
    // ≈ 25k gas of the 30M cap ≈ 0.00065%), so "0.00%" must NOT be read as "zero
    // claims succeeded" — this counter is the direct success signal.
    applied_claims: std::sync::atomic::AtomicU64,
}

#[cfg_attr(not(feature = "evm"), allow(dead_code))]
impl EvmLaneKpi {
    /// Record one validated EVM chain block (and the deposit claims it applied);
    /// periodically logs the rolling averages + cumulative applied claims (every
    /// 256 chain blocks).
    pub(super) fn record(&self, mergeset_size: usize, gas_used: u64, claims_applied: usize) {
        use std::sync::atomic::Ordering;
        let n = self.chain_blocks.fetch_add(1, Ordering::Relaxed) + 1;
        let ms = self.mergeset_blocks.fetch_add(mergeset_size as u64, Ordering::Relaxed) + mergeset_size as u64;
        let gas = self.accepted_gas.fetch_add(gas_used, Ordering::Relaxed) + gas_used;
        let claims = self.applied_claims.fetch_add(claims_applied as u64, Ordering::Relaxed) + claims_applied as u64;
        if n.is_multiple_of(256) {
            let cap = kaspa_consensus_core::evm::MAX_EVM_ACCEPTED_GAS_PER_CHAIN_BLOCK as f64;
            info!(
                "EVM lane KPI (O9): {} chain blocks, avg mergeset {:.2}, avg accepted-gas utilization {:.2}%, {} deposit-claims applied (cumulative)",
                n,
                ms as f64 / n as f64,
                (gas as f64 / n as f64) / cap * 100.0,
                claims
            );
        }
    }
}

pub struct VirtualStateProcessor {
    // Channels
    receiver: CrossbeamReceiver<VirtualStateProcessingMessage>,
    pruning_sender: CrossbeamSender<PruningProcessingMessage>,
    pruning_receiver: CrossbeamReceiver<PruningProcessingMessage>,

    // Thread pool
    pub(super) thread_pool: Arc<ThreadPool>,

    // DB
    db: Arc<DB>,

    // Config
    pub(super) genesis: GenesisBlock,
    pub(super) max_block_parents: u8,
    pub(super) mergeset_size_limit: u64,
    pub(super) max_block_mass: u64,
    /// kaspa-pq Phase 3 PoW (ADR-0007): BLAKE2b-512 ∥ SHA3-512 (`algo_id = 3`) activation — sets the
    /// block template's `pow_algo_id` so miners produce the network-correct Layer-1 algorithm.
    pub(super) pow_blake2b_sha3_activation: kaspa_consensus_core::config::params::ForkActivation,

    // Stores
    pub(super) statuses_store: Arc<RwLock<DbStatusesStore>>,
    pub(super) ghostdag_store: Arc<DbGhostdagStore>,
    pub(super) headers_store: Arc<DbHeadersStore>,
    pub(super) daa_excluded_store: Arc<DbDaaStore>,
    pub(super) block_transactions_store: Arc<DbBlockTransactionsStore>,
    pub(super) pruning_point_store: Arc<RwLock<DbPruningStore>>,
    pub(super) past_pruning_points_store: Arc<DbPastPruningPointsStore>,
    pub(super) body_tips_store: Arc<RwLock<DbTipsStore>>,
    pub(super) depth_store: Arc<DbDepthStore>,
    pub(super) selected_chain_store: Arc<RwLock<DbSelectedChainStore>>,
    pub(super) pruning_samples_store: Arc<DbPruningSamplesStore>,

    // kaspa-pq Phase 10 (ADR-0009): DNS finality overlay. `dns_params` is the
    // dormancy guard — `None` on every current network, so the bond-population
    // pass below is a single `Option` check and a return.
    pub(super) stake_bonds_store: Arc<RwLock<DbStakeBondsStore>>,
    /// kaspa-pq **ADR-0040 ECON-03 (THE WIRE)** — the PALW provider-bond registry (prefix 241).
    /// Written by [`Self::stage_palw_provider_bond_mutations`] at virtual commit and read only to
    /// seed [`Self::initial_palw_provider_bond_view`]; every consensus decision reads the walked
    /// VIEW, never this store, for the same point-of-view reason the DNS bond set does.
    pub(super) palw_provider_bonds_store: Arc<RwLock<DbPalwProviderBondsStore>>,
    pub(super) dns_state_store: Arc<RwLock<DbDnsStateStore>>,
    // kaspa-pq ADR-0022: overlay snapshot as-of the pruning point (serve + below-pp window consult).
    pub(super) pruning_overlay_snapshot_store: Arc<RwLock<DbPruningPointOverlaySnapshotStore>>,
    pub(super) dns_params: Option<DnsParams>,

    // kaspa-pq Selected-Parent EVM Lane (ADR-0020, design v0.4). The lazy
    // chain-context EVM step + canonical head pointers. Inert until
    // `evm_activation_daa_score` is finite (`u64::MAX` on every current net).
    pub(super) evm_header_store: Arc<DbEvmHeaderStore>,
    pub(super) evm_state_store: Arc<DbEvmStateStore>,
    #[cfg_attr(not(feature = "evm"), allow(dead_code))] // read by the cfg(evm) chain-context step only
    pub(super) evm_payload_store: Arc<DbEvmPayloadStore>,
    pub(super) evm_heads_store: Arc<RwLock<DbEvmCanonicalHeadsStore>>,
    pub(super) evm_receipts_store: Arc<crate::model::stores::evm::DbEvmReceiptsStore>,
    pub(super) evm_tx_index_store: Arc<crate::model::stores::evm::DbEvmTxIndexStore>,
    pub(super) evm_block_hash_map_store: Arc<crate::model::stores::evm::DbEvmBlockHashMapStore>,
    pub(super) evm_number_store: Arc<crate::model::stores::evm::DbEvmNumberStore>,
    pub(super) evm_log_index_store: Arc<crate::model::stores::evm::DbEvmLogIndexStore>,
    pub(super) evm_trace_store: Arc<crate::model::stores::evm::DbEvmTraceReplayStore>,
    // §12 archive: forward state diff (220) / full checkpoint (221) / content-addressed
    // code (222) — written alongside the per-block result so an archive/recent node can
    // reconstruct any canonical block's state. RPC/archive data only, never committed.
    pub(super) evm_state_diff_store: Arc<crate::model::stores::evm::DbEvmStateDiffStore>,
    pub(super) evm_state_checkpoint_store: Arc<crate::model::stores::evm::DbEvmStateCheckpointStore>,
    pub(super) evm_code_store: Arc<crate::model::stores::evm::DbEvmCodeStore>,
    // C-01 state-backend (design v0.1, Stage 1, slice S4): the flat latest-canonical
    // state (234) + block→root index (232) + canonical pointer (231). Written ONLY
    // by the shadow dual-write below, gated on `evm_shadow_state_backend` (off by
    // default). Inert otherwise. The pointer is RwLock-wrapped (its `set_batch` is
    // `&mut self`); the lock is taken only while shadow is on.
    pub(super) evm_flat_account_store: Arc<crate::model::stores::evm::DbEvmFlatAccountStore>,
    pub(super) evm_block_state_root_store: Arc<crate::model::stores::evm::DbEvmBlockStateRootStore>,
    pub(super) evm_latest_state_ptr_store: Arc<RwLock<crate::model::stores::evm::DbEvmLatestStatePtrStore>>,
    // C-01 slice S4: node-local shadow dual-write of the flat state backend +
    // per-block live differential vs the committed snapshot. `false` on every
    // current network and by default — purely a pre-cutover validation aid.
    pub(super) evm_shadow_state_backend: bool,
    // C-01 slice S9: when set (together with `evm_shadow_state_backend`), the EVM executor seeds
    // the parent state from the validated flat/reconstruct source instead of the 206 snapshot. The
    // seed is asserted byte-identical to 206 BEFORE use (HALT on divergence), and 206 is still
    // written — consensus-neutral + reversible. `false` on every current network and by default.
    // Only read by the `#[cfg(feature = "evm")]` chain-context path; without that feature the
    // pre-existing dead-code lint fires (allowed here to unblock the clippy gate).
    #[cfg_attr(not(feature = "evm"), allow(dead_code))]
    pub(super) evm_flat_authoritative: bool,
    // C-01 slice S9b: when set (together with `evm_flat_authoritative`), STOP persisting the per-block
    // 206 snapshot. The flat backend — already checked == the executor's in-memory post-state every
    // block by the S4 write-side differential — is the sole persisted post-state; the O12 pipeline is
    // disabled (its gap items 206-seed) and reads fall back to flat-materialize / §12-reconstruct.
    // Node-local, consensus-neutral. `false` on every current network and by default.
    pub(super) evm_retire_206: bool,
    // §12: this node's EVM state-history retention mode (`--evm-history-mode`). In
    // `head` mode the per-block archive diff/checkpoint (220/221) are not written at
    // all; `recent`/`archive` write them (the pruning processor decides how long
    // they survive). Node-local — never affects block validity or any commitment.
    pub(super) evm_history_mode: kaspa_consensus_core::evm::EvmHistoryMode,
    pub(super) evm_activation_daa_score: u64,
    // ADR-0039 PALW: the audited-compute lane's activation fence + overlay-state store. `u64::MAX`
    // on every shipped preset, so `commit_palw_overlay_effects` is a structural no-op there (the
    // batch-state store is never written). Read only at virtual commit to advance the §9.5 batch
    // state machine from accepted PALW overlay txs.
    pub(super) palw_activation_daa_score: u64,
    pub(super) palw_store: Arc<DbPalwStore>,
    pub(super) palw_beacon_store: Arc<crate::model::stores::palw_beacon::DbPalwBeaconStore>,
    pub(super) palw_epoch_length_daa: u64,
    /// kaspa-pq ADR-0040 §5.15.13 (G16): the batch-admission windows that DERIVE the paid-work walk
    /// bound. Held here (not re-read from params) so `palw_paid_work_window` and the body-coordinate
    /// admission check that enforces the windows read the identical values.
    pub(super) palw_batch_admission: kaspa_consensus_core::palw::PalwBatchAdmissionParams,
    pub(super) palw_beacon_grace_epochs: u64,
    pub(super) palw_beacon_quorum_num: u16,
    pub(super) palw_beacon_quorum_den: u16,
    /// ADR-0040 P1-3 (CERT-01): the batch-certificate auditor quorum fraction (§10.2).
    pub(super) palw_audit_quorum_num: u16,
    pub(super) palw_audit_quorum_den: u16,
    /// kaspa-pq ADR-0040 §5.17.4 (AUTHSET-01): the beacon-selected auditor committee size, and §5.17.6
    /// (SAMPLE-01): the leaf sample size — the two config cardinalities the certificate re-derivations at
    /// `verify_certificate_attestation` consume. Held here (like the quorum fraction) because that
    /// re-derivation runs in this processor, which only sees `Params`.
    pub(super) palw_audit_committee_size: u16,
    pub(super) palw_audit_sample_size: u16,
    /// PALW's frozen `u32` network discriminator (the dedicated testnet suffix, e.g. 110).
    /// Only read after the PALW activation fence; non-suffixed, PALW-inert networks use zero.
    pub(super) palw_network_id: u32,
    // These activation-score fields are only read by the `#[cfg(feature = "evm")]` chain-context
    // path; without that feature the pre-existing dead-code lint fires (allowed to unblock the gate).
    #[cfg_attr(not(feature = "evm"), allow(dead_code))]
    pub(super) evm_gas_pool_v2_activation_daa_score: u64,
    #[cfg_attr(not(feature = "evm"), allow(dead_code))]
    pub(super) evm_f002_withdraw_cap_activation_daa_score: u64,
    #[cfg_attr(not(feature = "evm"), allow(dead_code))]
    pub(super) evm_f003_mldsa_verify_activation_daa_score: u64,
    #[cfg_attr(not(feature = "evm"), allow(dead_code))]
    pub(super) evm_typed_receipt_root_activation_daa_score: u64,
    // O9 (optimization design v0.1): node-local EVM-lane KPIs — chain-block
    // count / mergeset-size sum / accepted-gas sum. The gas supply is
    // 30M × chain-block rate (NOT DAG width), and the adversarial degradation
    // mode is a widening mergeset (design §2/B7) — these counters make that
    // observable. Logged every 256 chain blocks; never consensus-relevant.
    #[cfg_attr(not(feature = "evm"), allow(dead_code))] // recorded only on the cfg(evm) chain-context step
    pub(super) evm_lane_kpi: EvmLaneKpi,

    // Utxo-related stores
    pub(super) utxo_diffs_store: Arc<DbUtxoDiffsStore>,
    // kaspa-pq DNS overlay (ADR-0009 Addendum B §B.3(c)): per-block rewarded
    // `(bond, epoch)` keys for cross-block reward uniqueness.
    pub(super) rewarded_epochs_store: Arc<DbRewardedEpochsStore>,
    // kaspa-pq ADR-0040 §5.15.13 (gate G16 / P1-9-RELAND): per-chain-block paid `job_nullifier`s,
    // the delta the bounded reward-coordinate duplicate-work walk reads. Empty on every preset.
    pub(super) palw_paid_work_store: Arc<DbPalwPaidWorkStore>,
    // kaspa-pq ADR-0018 "本格版" (PoS-v2, Phase 1): the per-epoch accumulator and
    // its per-block validator quality sub-pool input. Inert until
    // `pos_v2_activation_daa_score` (`u64::MAX` today).
    pub(super) epoch_accumulator_store: Arc<DbEpochAccumulatorStore>,
    pub(super) block_quality_pool_store: Arc<DbBlockQualityPoolStore>,
    pub(super) reserve_balance_store: Arc<DbReserveBalanceStore>,
    pub(super) utxo_multisets_store: Arc<DbUtxoMultisetsStore>,
    pub(super) acceptance_data_store: Arc<DbAcceptanceDataStore>,
    pub(super) virtual_stores: Arc<RwLock<VirtualStores>>,
    pub(super) pruning_meta_stores: Arc<RwLock<PruningMetaStores>>,

    /// The "last known good" virtual state. To be used by any logic which does not want to wait
    /// for a possible virtual state write to complete but can rather settle with the last known state
    pub lkg_virtual_state: LkgVirtualState,

    // Managers and services
    pub(super) ghostdag_manager: DbGhostdagManager,
    pub(super) reachability_service: MTReachabilityService<DbReachabilityStore>,
    pub(super) relations_service: MTRelationsService<DbRelationsStore>,
    pub(super) dag_traversal_manager: DbDagTraversalManager,
    pub(super) window_manager: DbWindowManager,
    pub(super) coinbase_manager: CoinbaseManager,
    pub(super) transaction_validator: TransactionValidator,
    pub(super) pruning_point_manager: DbPruningPointManager,
    pub(super) parents_manager: DbParentsManager,
    pub(super) depth_manager: DbBlockDepthManager,

    // block window caches
    pub(super) block_window_cache_for_difficulty: Arc<BlockWindowCacheStore>,
    pub(super) block_window_cache_for_past_median_time: Arc<BlockWindowCacheStore>,

    // Pruning lock
    pub(super) pruning_lock: SessionLock,

    // Notifier
    notification_root: Arc<ConsensusNotificationRoot>,

    // Counters
    counters: Arc<ProcessingCounters>,

    // Mining Rule
    _mining_rules: Arc<MiningRules>,
}

impl VirtualStateProcessor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receiver: CrossbeamReceiver<VirtualStateProcessingMessage>,
        pruning_sender: CrossbeamSender<PruningProcessingMessage>,
        pruning_receiver: CrossbeamReceiver<PruningProcessingMessage>,
        thread_pool: Arc<ThreadPool>,
        params: &Params,
        db: Arc<DB>,
        storage: &Arc<ConsensusStorage>,
        services: &Arc<ConsensusServices>,
        pruning_lock: SessionLock,
        notification_root: Arc<ConsensusNotificationRoot>,
        counters: Arc<ProcessingCounters>,
        mining_rules: Arc<MiningRules>,
        evm_history_mode: kaspa_consensus_core::evm::EvmHistoryMode,
        evm_shadow_state_backend: bool,
        evm_flat_authoritative: bool,
        evm_retire_206: bool,
    ) -> Self {
        // C-01 S9: flat-authoritative seeding needs the shadow backend (which maintains + validates
        // the flat store); without it the flag is a silent no-op (the executor keeps seeding from
        // 206). Warn so the prerequisite isn't missed during a cutover rollout. Fail-safe either way.
        if evm_flat_authoritative && !evm_shadow_state_backend {
            warn!(
                "[C-01] --evm-flat-authoritative is set WITHOUT --evm-shadow-state-backend; it is a no-op (the EVM executor keeps seeding from the 206 snapshot). Enable --evm-shadow-state-backend to use the flat-authoritative seed."
            );
        }
        // C-01 S9b: retiring the 206 persist requires the flat-authoritative seed (so the executor no
        // longer reads 206). Without it, dropping 206 would leave the executor's selected-parent read
        // (and the O12 pipeline) with no seed → a stall. Demote to a no-op + warn rather than enable a
        // half-configured retirement: keep writing 206 so the node stays correct.
        let evm_retire_206 = if evm_retire_206 && !(evm_flat_authoritative && evm_shadow_state_backend) {
            warn!(
                "[C-01] --evm-retire-206 is set WITHOUT --evm-flat-authoritative (+ --evm-shadow-state-backend); it is a no-op (the per-block 206 snapshot keeps being written). Enable the flat-authoritative seed first."
            );
            false
        } else {
            evm_retire_206
        };
        // C-01 S9b: `head` history keeps no §12 diff/checkpoint, so a retired-206 node cannot serve the
        // IBD pruning-point snapshot to peers nor answer historical state RPC (both fall back to
        // §12-reconstruct). Block validation is unaffected (it seeds from the flat HEAD), so this is a
        // loud warning, not a demotion — an operator may knowingly run a non-serving retired node.
        if evm_retire_206 && !evm_history_mode.writes_state_history() {
            warn!(
                "[C-01] --evm-retire-206 with --evm-history-mode=head: the IBD pruning-point export and historical state RPC will be UNAVAILABLE on this node (no §12 history to reconstruct 206 from). Use recent/archive history if this node serves IBD or state queries."
            );
        }
        Self {
            receiver,
            pruning_sender,
            pruning_receiver,
            thread_pool,

            genesis: params.genesis.clone(),
            pow_blake2b_sha3_activation: params.pow_blake2b_sha3_activation,
            max_block_parents: params.max_block_parents(),
            mergeset_size_limit: params.mergeset_size_limit(),
            max_block_mass: params.max_block_mass,

            db,
            statuses_store: storage.statuses_store.clone(),
            headers_store: storage.headers_store.clone(),
            ghostdag_store: storage.ghostdag_store.clone(),
            daa_excluded_store: storage.daa_excluded_store.clone(),
            block_transactions_store: storage.block_transactions_store.clone(),
            pruning_point_store: storage.pruning_point_store.clone(),
            past_pruning_points_store: storage.past_pruning_points_store.clone(),
            body_tips_store: storage.body_tips_store.clone(),
            depth_store: storage.depth_store.clone(),
            selected_chain_store: storage.selected_chain_store.clone(),
            pruning_samples_store: storage.pruning_samples_store.clone(),
            stake_bonds_store: storage.stake_bonds_store.clone(),
            palw_provider_bonds_store: storage.palw_provider_bonds_store.clone(),
            dns_state_store: storage.dns_state_store.clone(),
            pruning_overlay_snapshot_store: storage.pruning_overlay_snapshot_store.clone(),
            evm_header_store: storage.evm_header_store.clone(),
            evm_state_store: storage.evm_state_store.clone(),
            evm_payload_store: storage.evm_payload_store.clone(),
            evm_heads_store: storage.evm_heads_store.clone(),
            evm_receipts_store: storage.evm_receipts_store.clone(),
            evm_tx_index_store: storage.evm_tx_index_store.clone(),
            evm_block_hash_map_store: storage.evm_block_hash_map_store.clone(),
            evm_number_store: storage.evm_number_store.clone(),
            evm_log_index_store: storage.evm_log_index_store.clone(),
            evm_trace_store: storage.evm_trace_store.clone(),
            evm_state_diff_store: storage.evm_state_diff_store.clone(),
            evm_state_checkpoint_store: storage.evm_state_checkpoint_store.clone(),
            evm_code_store: storage.evm_code_store.clone(),
            evm_flat_account_store: storage.evm_flat_account_store.clone(),
            evm_block_state_root_store: storage.evm_block_state_root_store.clone(),
            evm_latest_state_ptr_store: storage.evm_latest_state_ptr_store.clone(),
            evm_shadow_state_backend,
            evm_flat_authoritative,
            evm_retire_206,
            evm_history_mode,
            evm_activation_daa_score: params.evm_activation_daa_score,
            palw_activation_daa_score: params.palw_activation_daa_score,
            palw_store: storage.palw_store.clone(),
            palw_beacon_store: storage.palw_beacon_store.clone(),
            palw_epoch_length_daa: params.palw_epoch_length_daa,
            palw_batch_admission: params.palw_batch_admission,
            palw_beacon_grace_epochs: params.palw_beacon_grace_epochs,
            palw_beacon_quorum_num: params.palw_beacon_quorum_num,
            palw_beacon_quorum_den: params.palw_beacon_quorum_den,
            palw_audit_quorum_num: params.palw_audit_quorum_num,
            palw_audit_quorum_den: params.palw_audit_quorum_den,
            palw_audit_committee_size: params.palw_audit_committee_size,
            palw_audit_sample_size: params.palw_audit_sample_size,
            palw_network_id: params.net.suffix().unwrap_or(0),
            evm_gas_pool_v2_activation_daa_score: params.evm_gas_pool_v2_activation_daa_score,
            evm_f002_withdraw_cap_activation_daa_score: params.evm_f002_withdraw_cap_activation_daa_score,
            evm_f003_mldsa_verify_activation_daa_score: params.evm_f003_mldsa_verify_activation_daa_score,
            evm_typed_receipt_root_activation_daa_score: params.evm_typed_receipt_root_activation_daa_score,
            evm_lane_kpi: EvmLaneKpi::default(),
            dns_params: params.dns_params.clone(),
            utxo_diffs_store: storage.utxo_diffs_store.clone(),
            rewarded_epochs_store: storage.rewarded_epochs_store.clone(),
            palw_paid_work_store: storage.palw_paid_work_store.clone(),
            epoch_accumulator_store: storage.epoch_accumulator_store.clone(),
            block_quality_pool_store: storage.block_quality_pool_store.clone(),
            reserve_balance_store: storage.reserve_balance_store.clone(),
            utxo_multisets_store: storage.utxo_multisets_store.clone(),
            acceptance_data_store: storage.acceptance_data_store.clone(),
            virtual_stores: storage.virtual_stores.clone(),
            pruning_meta_stores: storage.pruning_meta_stores.clone(),
            lkg_virtual_state: storage.lkg_virtual_state.clone(),

            block_window_cache_for_difficulty: storage.block_window_cache_for_difficulty.clone(),
            block_window_cache_for_past_median_time: storage.block_window_cache_for_past_median_time.clone(),

            ghostdag_manager: services.ghostdag_manager.clone(),
            reachability_service: services.reachability_service.clone(),
            relations_service: services.relations_service.clone(),
            dag_traversal_manager: services.dag_traversal_manager.clone(),
            window_manager: services.window_manager.clone(),
            coinbase_manager: services.coinbase_manager.clone(),
            transaction_validator: services.transaction_validator.clone(),
            pruning_point_manager: services.pruning_point_manager.clone(),
            parents_manager: services.parents_manager.clone(),
            depth_manager: services.depth_manager.clone(),

            pruning_lock,
            notification_root,
            counters,
            _mining_rules: mining_rules,
        }
    }

    fn bridge_finality_is_fresh(&self, current_daa_score: u64) -> bool {
        let Some(dns_params) = self.dns_params.as_ref() else {
            return false;
        };
        let Ok(state) = self.dns_state_store.read().get() else {
            return false;
        };
        let dns_confirmed =
            is_dns_confirmed(state.work_depth, state.stake_depth, dns_params.required_work_depth, dns_params.required_stake_depth);
        dns_finality_fresh_for_bridge(
            dns_confirmed,
            state.last_dns_confirmed_anchor,
            state.last_dns_confirmed_anchor_daa_score,
            current_daa_score,
            dns_params.bridge_finality_max_staleness_daa_score,
        )
    }

    pub fn worker(self: &Arc<Self>) {
        'outer: while let Ok(msg) = self.receiver.recv() {
            if msg.is_exit_message() {
                break;
            }

            // Once a task arrived, collect all pending tasks from the channel.
            // This is done since virtual processing is not a per-block
            // operation, so it benefits from max available info

            let messages: Vec<VirtualStateProcessingMessage> = std::iter::once(msg).chain(self.receiver.try_iter()).collect();
            trace!("virtual processor received {} tasks", messages.len());

            self.resolve_virtual();

            let statuses_read = self.statuses_store.read();
            for msg in messages {
                match msg {
                    VirtualStateProcessingMessage::Exit => break 'outer,
                    VirtualStateProcessingMessage::Process(task, virtual_state_result_transmitter) => {
                        // We don't care if receivers were dropped
                        let _ = virtual_state_result_transmitter.send(Ok(statuses_read.get(task.block().hash()).unwrap()));
                    }
                };
            }
        }

        // Pass the exit signal on to the following processor
        self.pruning_sender.send(PruningProcessingMessage::Exit).unwrap();
    }

    fn resolve_virtual(self: &Arc<Self>) {
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        let virtual_read = self.virtual_stores.upgradable_read();
        let prev_state = virtual_read.state.get().unwrap();
        let finality_point = self.virtual_finality_point(&prev_state.ghostdag_data, pruning_point);

        // PRUNE SAFETY: in order to avoid locking the prune lock throughout virtual resolving we make sure
        // to only process blocks in the future of the finality point (F) which are never pruned (since finality depth << pruning depth).
        // This is justified since:
        //      1. Tips which are not in the future of F definitely don't have F on their chain
        //         hence cannot become the next sink (due to finality violation).
        //      2. Such tips cannot be merged by virtual since they are violating the merge depth
        //         bound (merge depth <= finality depth).
        // (both claims are true by induction for any block in their past as well)
        let prune_guard = self.pruning_lock.blocking_read();
        let tips = self
            .body_tips_store
            .read()
            .get()
            .unwrap()
            .read()
            .iter()
            .copied()
            // QR reachability hardening: drop a body tip whose reachability is missing (half-pruned);
            // it is below finality and protected by pruning-point finality. Consensus-neutral.
            .filter(|&h| match self.reachability_service.try_is_dag_ancestor_of(finality_point, h) {
                Ok(v) => v,
                Err(_) => {
                    debug!("resolve_virtual: body tip {h} has no reachability vs finality {finality_point} (half-pruned?); dropping tip");
                    false
                }
            })
            .collect_vec();
        drop(prune_guard);
        let prev_sink = prev_state.ghostdag_data.selected_parent;
        let mut accumulated_diff = prev_state.utxo_diff.clone().to_reversed();

        // kaspa-pq Phase 10/11 (ADR-0009 Addendum B): the per-block active-bond
        // view, walked in lockstep with `accumulated_diff` so that at each
        // chain-block UTXO verification it equals the bond set as-of that
        // block's selected parent (the deterministic, as-of-block bond
        // resolution the validator-reward coinbase fan-out needs — PR-10.5′-b3).
        // Seeded from the `StakeBonds` store snapshot (= state at `prev_sink`);
        // empty + untouched on networks without the overlay (`dns_params` None).
        // No consumer yet (b2a): `verify_expected_utxo_state` receives it inert.
        let mut accumulated_bond_view = self.initial_active_bond_view();
        // ADR-0040 ECON-03 (THE WIRE): the PALW provider-bond view, walked in the SAME lockstep so
        // that at each chain-block UTXO verification it equals the registry as-of that block's
        // selected parent — the point of view `palw_work_reward_class` resolves a leaf's
        // `provider_{a,b}_bond` against. Empty + untouched while PALW is fenced.
        let mut accumulated_provider_bond_view = self.initial_palw_provider_bond_view();

        let (new_sink, virtual_parent_candidates) = self.sink_search_algorithm(
            &virtual_read,
            &mut accumulated_diff,
            &mut accumulated_bond_view,
            &mut accumulated_provider_bond_view,
            prev_sink,
            tips,
            finality_point,
            pruning_point,
        );
        let (virtual_parents, virtual_ghostdag_data) = self.pick_virtual_parents(new_sink, virtual_parent_candidates, pruning_point);
        assert_eq!(virtual_ghostdag_data.selected_parent, new_sink);

        let sink_multiset = self.utxo_multisets_store.get(new_sink).unwrap();
        let chain_path = self.dag_traversal_manager.calculate_chain_path(prev_sink, new_sink, None);
        let sink_ghostdag_data = Lazy::new(|| self.ghostdag_store.get_data(new_sink).unwrap());
        // Cache the DAA and Median time windows of the sink for future use, as well as prepare for virtual's window calculations
        self.cache_sink_windows(new_sink, prev_sink, &sink_ghostdag_data);

        let new_virtual_state = self
            .calculate_and_commit_virtual_state(
                virtual_read,
                virtual_parents,
                virtual_ghostdag_data,
                sink_multiset,
                &mut accumulated_diff,
                // After `sink_search_algorithm` the walked view equals the bond
                // set as-of the new sink (= the virtual block's selected parent).
                &accumulated_bond_view,
                // Likewise the provider-bond registry as-of the new sink.
                &accumulated_provider_bond_view,
                &chain_path,
            )
            .expect("all possible rule errors are unexpected here");

        let compact_sink_ghostdag_data = if let Some(sink_ghostdag_data) = Lazy::get(&sink_ghostdag_data) {
            // If we had to retrieve the full data, we convert it to compact
            sink_ghostdag_data.to_compact()
        } else {
            // Else we query the compact data directly.
            self.ghostdag_store.get_compact_data(new_sink).unwrap()
        };

        // Update the pruning processor about the virtual state change
        // Empty the channel before sending the new message. If pruning processor is busy, this step makes sure
        // the internal channel does not grow with no need (since we only care about the most recent message)
        let _consume = self.pruning_receiver.try_iter().count();
        self.pruning_sender.send(PruningProcessingMessage::Process { sink_ghostdag_data: compact_sink_ghostdag_data }).unwrap();

        // Emit notifications
        let accumulated_diff = Arc::new(accumulated_diff);
        let virtual_parents = Arc::new(new_virtual_state.parents.clone());
        self.notification_root
            .notify(Notification::NewBlockTemplate(NewBlockTemplateNotification {}))
            .expect("expecting an open unbounded channel");
        self.notification_root
            .notify(Notification::UtxosChanged(UtxosChangedNotification::new(accumulated_diff, virtual_parents)))
            .expect("expecting an open unbounded channel");
        self.notification_root
            .notify(Notification::SinkBlueScoreChanged(SinkBlueScoreChangedNotification::new(compact_sink_ghostdag_data.blue_score)))
            .expect("expecting an open unbounded channel");
        self.notification_root
            .notify(Notification::VirtualDaaScoreChanged(VirtualDaaScoreChangedNotification::new(new_virtual_state.daa_score)))
            .expect("expecting an open unbounded channel");
        if self.notification_root.has_subscription(EventType::VirtualChainChanged) {
            // check for subscriptions before the heavy lifting
            let added_chain_blocks_acceptance_data =
                chain_path.added.iter().copied().map(|added| self.acceptance_data_store.get(added).unwrap()).collect_vec();
            self.notification_root
                .notify(Notification::VirtualChainChanged(VirtualChainChangedNotification::new(
                    chain_path.added.into(),
                    chain_path.removed.into(),
                    Arc::new(added_chain_blocks_acceptance_data),
                )))
                .expect("expecting an open unbounded channel");
        }
    }

    pub(crate) fn virtual_finality_point(&self, virtual_ghostdag_data: &GhostdagData, pruning_point: BlockHash) -> BlockHash {
        let finality_point = self.depth_manager.calc_finality_point(virtual_ghostdag_data, pruning_point);
        // QR reachability hardening: a half-pruned DB can transiently miss the finality point's
        // reachability until pruning recovery completes; treat a missing row as below-pruning-point
        // and fall back to the pruning point (identical to the IBD-start else branch). Consensus-neutral.
        let fp_reachable = match self.reachability_service.try_is_chain_ancestor_of(pruning_point, finality_point) {
            Ok(v) => v,
            Err(_) => {
                debug!(
                    "virtual_finality_point: finality point {finality_point} has no reachability (half-pruned?); falling back to pruning point {pruning_point}"
                );
                false
            }
        };
        if fp_reachable {
            finality_point
        } else {
            // At the beginning of IBD when virtual finality point might be below the pruning point
            // or disagreeing with the pruning point chain, we take the pruning point itself as the finality point
            pruning_point
        }
    }

    /// Calculates the UTXO state of `to` starting from the state of `from`.
    /// The provided `diff` is assumed to initially hold the UTXO diff of `from` from virtual.
    /// The function returns the top-most UTXO-valid block on `chain(to)` which is ideally
    /// `to` itself (with the exception of returning `from` if `to` is already known to be UTXO disqualified).
    /// When returning it is guaranteed that `diff` holds the diff of the returned block from virtual
    fn calculate_utxo_state_relatively(
        &self,
        stores: &VirtualStores,
        diff: &mut UtxoDiff,
        bond_view: &mut ActiveBondView,
        // ADR-0040 ECON-03 (THE WIRE): walked in lockstep with `bond_view`, on the PALW fence rather
        // than the DNS one. See `initial_palw_provider_bond_view` for why resolution lives here.
        provider_bond_view: &mut ProviderBondView,
        from: BlockHash,
        to: BlockHash,
    ) -> BlockHash {
        // kaspa-pq Phase 10/11 (ADR-0009 Addendum B §B.1): walk the active-bond
        // view in lockstep with `diff` so it always equals the bond set as-of
        // the block whose UTXO state `diff` represents. No-op on networks
        // without the overlay. No consumer yet (b2a) — the view is passed to
        // `verify_expected_utxo_state` inert.
        let track_bonds = self.dns_params.is_some();
        let track_provider_bonds = self.palw_activation_daa_score != u64::MAX;

        // Avoid reorging if disqualified status is already known
        if self.statuses_store.read().get(to).unwrap() == StatusDisqualifiedFromChain {
            return from;
        }

        let mut split_point: Option<BlockHash> = None;

        // Walk down to the reorg split point
        for current in self.reachability_service.default_backward_chain_iterator(from) {
            if self.reachability_service.is_chain_ancestor_of(current, to) {
                split_point = Some(current);
                break;
            }

            let mergeset_diff = self.utxo_diffs_store.get(current).unwrap();
            // Apply the diff in reverse
            diff.with_diff_in_place(&mergeset_diff.as_reversed()).unwrap();
            if track_bonds {
                // Mirror the reverse on the bond view. `current` is leaving the
                // selected chain, so its acceptance data is committed.
                bond_view.revert(&self.dns_bond_mutations_for_chain_block(current));
            }
            if track_provider_bonds {
                provider_bond_view.revert(&self.palw_provider_bond_mutations_for_chain_block(current));
            }
        }

        let split_point = split_point.expect("chain iterator was expected to reach the reorg split point");
        debug!("VIRTUAL PROCESSOR, found split point: {split_point}");

        // O12 (IBD catch-up): when the walk ahead contains a long run of
        // pending chain blocks, pre-execute their EVM acceptance on a pipeline
        // worker overlapped with this thread's serial UTXO validation. Inert
        // when the lane is inactive, on short walks (steady state: 1 block),
        // and on non-evm builds. Commits stay HERE, in canonical order.
        let evm_pipeline = self.maybe_spawn_evm_pipeline(split_point, to);

        // A variable holding the most recent UTXO-valid block on `chain(to)` (note that it's maintained such
        // that 'diff' is always its UTXO diff from virtual)
        let mut diff_point = split_point;

        // Walk back up to the new virtual selected parent candidate
        let mut chain_block_counter = 0;
        let mut chain_disqualified_counter = 0;
        for (selected_parent, current) in self.reachability_service.forward_chain_iterator(split_point, to, true).tuple_windows() {
            if selected_parent != diff_point {
                // This indicates that the selected parent is disqualified, propagate up and continue
                let statuses_guard = self.statuses_store.upgradable_read();
                if statuses_guard.get(current).unwrap() != StatusDisqualifiedFromChain {
                    RwLockUpgradableReadGuard::upgrade(statuses_guard).set(current, StatusDisqualifiedFromChain).unwrap();
                    chain_disqualified_counter += 1;
                }
                continue;
            }

            match self.utxo_diffs_store.get(current) {
                Ok(mergeset_diff) => {
                    diff.with_diff_in_place(mergeset_diff.deref()).unwrap();
                    diff_point = current;
                    if track_bonds {
                        // `current` is an already-validated chain block joining
                        // the diff; its acceptance data is committed.
                        bond_view.apply(&self.dns_bond_mutations_for_chain_block(current));
                    }
                    if track_provider_bonds {
                        provider_bond_view.apply(&self.palw_provider_bond_mutations_for_chain_block(current));
                    }
                }
                Err(StoreError::KeyNotFound(_)) => {
                    if self.statuses_store.read().get(current).unwrap() == StatusDisqualifiedFromChain {
                        // A persisted disqualified status is only a cache of a past validation result. Re-run the
                        // deterministic checks when the block becomes a selected-chain candidate again so nodes can
                        // recover after liveness-first rule changes without wiping their local DAG state. Blocks that
                        // are still invalid will be marked disqualified again below.
                        debug!("Revalidating previously disqualified selected-chain block {}", current);
                    }

                    let header = self.headers_store.get_header(current).unwrap();
                    let mergeset_data = self.ghostdag_store.get_data(current).unwrap();
                    let pov_daa_score = header.daa_score;

                    let selected_parent_multiset_hash = self.utxo_multisets_store.get(selected_parent).unwrap();
                    let selected_parent_utxo_view = (&stores.utxo_set).compose(&*diff);

                    let mut ctx = UtxoProcessingContext::new(mergeset_data.into(), selected_parent_multiset_hash);

                    // `bond_view` currently equals the bond set as-of `selected_parent`
                    // (the verify point's selected-parent view — Addendum B §B.3),
                    // so it is the same view both `calculate_utxo_state` (slashing
                    // side-effect, PR-16.4-b2) and `verify_expected_utxo_state` read.
                    self.calculate_utxo_state(&mut ctx, &selected_parent_utxo_view, &*bond_view, &*provider_bond_view, pov_daa_score);

                    // kaspa-pq EVM Lane v0.4 (§2.3/§9): the lazy chain-context
                    // EVM step — the FIRST time a block becomes a selected-chain
                    // candidate (this KeyNotFound arm), validate its deposit
                    // claims, execute its mergeset acceptance, verify
                    // `evm_commitment_root`, and fold the bridge's UTXO
                    // side-effects (consumed locks + synthetic withdrawal
                    // outputs) into ctx BEFORE `verify_expected_utxo_state`, so
                    // the header's `utxo_commitment` covers them. A fault
                    // disqualifies the block from the chain exactly like a UTXO
                    // fault (no poison; the block stays in the DAG). A single
                    // u64 compare while the lane is inert.
                    let evm_staged = match self.evm_chain_context_step(
                        current,
                        selected_parent,
                        &header,
                        &mut ctx,
                        &selected_parent_utxo_view,
                        evm_pipeline.as_ref(),
                    ) {
                        Ok(staged) => staged,
                        Err(evm_error) => {
                            info!("Block {} is disqualified from virtual chain (EVM): {}", current, evm_error);
                            self.statuses_store.write().set(current, StatusDisqualifiedFromChain).unwrap();
                            chain_disqualified_counter += 1;
                            continue;
                        }
                    };

                    // ADR-0040 ECON-03 leg 5: `provider_bond_view` is no longer forwarded here — the
                    // provider-unbond authorization it once served moved to the acceptance-time filter
                    // inside `calculate_utxo_state`, which already read this same selected-parent view.
                    let res = self.verify_expected_utxo_state(&mut ctx, &selected_parent_utxo_view, &*bond_view, &header);

                    if let Err(rule_error) = res {
                        info!("Block {} is disqualified from virtual chain: {}", current, rule_error);
                        self.statuses_store.write().set(current, StatusDisqualifiedFromChain).unwrap();
                        chain_disqualified_counter += 1;
                    } else {
                        debug!("VIRTUAL PROCESSOR, UTXO validated for {current}");

                        // Accumulate the diff
                        diff.with_diff_in_place(&ctx.mergeset_diff).unwrap();
                        // Update the diff point
                        diff_point = current;
                        // Snapshot THIS block's DNS mutations while the acceptance data is still
                        // in memory, but keep `bond_view` at the selected parent through the commit:
                        // PALW beacon stake/signature checks are deliberately past-relative and may
                        // not see a bond created/slashed/unbonded by the block being committed.
                        let bond_muts =
                            track_bonds.then(|| self.dns_bond_mutations_from_acceptance(&ctx.mergeset_acceptance_data, pov_daa_score));
                        // ADR-0040 ECON-03: same treatment for the provider registry — snapshot now,
                        // advance only after every selected-parent-relative commitment is derived, so
                        // this block's own bonds are never visible to its own reward classification.
                        let provider_bond_muts = track_provider_bonds
                            .then(|| self.palw_provider_bond_mutations_from_acceptance(&ctx.mergeset_acceptance_data, pov_daa_score));
                        // Commit UTXO data for current chain block
                        self.commit_utxo_state(
                            current,
                            ctx.mergeset_diff,
                            ctx.multiset_hash,
                            ctx.mergeset_acceptance_data,
                            ctx.pruning_sample_from_pov.expect("verified"),
                            ctx.validator_rewarded_keys,
                            ctx.palw_paid_work_ids,
                            ctx.validator_quality_subpool,
                            ctx.reserve_balance_after,
                            evm_staged,
                            &*bond_view,
                            // ADR-0040 §5.17: the provider-bond view at THIS block's selected parent —
                            // snapshotted before this block's own provider mutations are applied below.
                            &*provider_bond_view,
                        );
                        if let Some(bond_muts) = bond_muts {
                            // Advance the in-memory selected-chain walk only after every
                            // selected-parent-relative commitment has been derived and persisted.
                            bond_view.apply(&bond_muts);
                        }
                        if let Some(provider_bond_muts) = provider_bond_muts {
                            provider_bond_view.apply(&provider_bond_muts);
                        }
                        // Count the number of UTXO-processed chain blocks
                        chain_block_counter += 1;
                    }
                }
                Err(err) => panic!("unexpected error {err}"),
            }
        }
        // Report counters
        self.counters.chain_block_counts.fetch_add(chain_block_counter, Ordering::Relaxed);
        if chain_disqualified_counter > 0 {
            self.counters.chain_disqualified_counts.fetch_add(chain_disqualified_counter, Ordering::Relaxed);
        }

        diff_point
    }

    /// kaspa-pq EVM Lane v0.4 (§2.3): the lazy chain-context EVM step for one
    /// selected-chain candidate. Gated on `evm_activation_daa_score` (a single
    /// u64 compare on every current network); no-replay and the commitment
    /// check live in `processes::evm::evm_validate`. `Err` = the block is
    /// disqualified from the chain (commitment fault), mirroring a UTXO fault.
    #[cfg(feature = "evm")]
    fn evm_chain_context_step<V: UtxoView>(
        &self,
        current: BlockHash,
        selected_parent: BlockHash,
        header: &Header,
        ctx: &mut UtxoProcessingContext<'_>,
        selected_parent_utxo_view: &V,
        pipeline: Option<&crate::processes::evm::EvmPipeline>,
    ) -> Result<Option<crate::processes::evm::EvmStaged>, String> {
        use crate::model::stores::evm::EvmPayloadStoreReader; // EvmHeaderStoreReader is in module scope
        use crate::processes::evm::{
            EvmValidateError, apply_evm_bridge_effects, evm_validate, evm_validate_chained, validate_evm_deposit_claims,
        };
        if header.daa_score < self.evm_activation_daa_score {
            return Ok(None);
        }
        // The §4.3 version rule admits only v2+ headers at/after activation.
        debug_assert!(header.version >= kaspa_consensus_core::constants::EVM_HEADER_VERSION);
        // B's own payload (system_ops + the accepting coinbase); absent ⇒ empty
        // (only non-empty payloads are persisted at body commit).
        let own_payload = match self.evm_payload_store.get(current) {
            Ok(p) => p,
            Err(kaspa_database::prelude::StoreError::KeyNotFound(_)) => Default::default(),
            Err(e) => return Err(format!("evm payload store: {e}")),
        };
        // §9.2: deposit claims are validated against the CLAIM VIEW = the
        // selected-parent UTXO set composed with the mergeset diff so far (a
        // lock spent by a mergeset tx is not claimable; a same-block lock is
        // not visible). Any violation is an accepting-producer fault.
        let consumed_locks = {
            let claim_view = selected_parent_utxo_view.compose(&ctx.mergeset_diff);
            validate_evm_deposit_claims(&own_payload, &claim_view, header.daa_score)?
        };
        // C-01 S9 cutover: when flat-authoritative (and the shadow backend that maintains the flat
        // store is on), seed the executor from the flat/reconstruct parent state instead of 206 —
        // but ONLY after asserting it byte-identical to 206 (inside `validated_flat_parent_seed`,
        // which HALTs on divergence BEFORE the seed is used, so a backend bug can never falsely
        // disqualify a valid block). A pre-activation / Unavailable parent ⇒ `None` ⇒ the 206 path.
        // 206 is still written, so this is reversible; the result is identical (validated == 206).
        let flat_auth = self.evm_flat_authoritative && self.evm_shadow_state_backend;
        // Whether the inline path pre-validated the flat seed (so the post-execution S6 check below
        // is not run twice). The pipeline path (206-seeded) leaves this false and is checked below.
        let mut seed_prevalidated = false;
        // O12: a pipelined run pre-executed this block's acceptance on the
        // worker (same pure function, same inputs — see EvmPipeline). Consume
        // its result; fall back to inline execution when the pipeline ended.
        let pipelined = pipeline.and_then(|p| p.recv(current));
        let staged = match pipelined {
            Some(Ok(staged)) => Some(staged),
            Some(Err(msg)) => return Err(msg),
            None => {
                // AcceptedEvmTxs(B) source: the consensus-ordered mergeset (selected
                // parent first, then ascending blue work — §3.1 canonical order).
                let sorted_mergeset: Vec<BlockHash> =
                    ctx.ghostdag_data.consensus_ordered_mergeset(self.ghostdag_store.as_ref()).collect();
                let map_err = |e| match e {
                    EvmValidateError::CommitmentMismatch { .. } => {
                        "evm_commitment_root mismatch (mergeset acceptance re-execution)".to_string()
                    }
                    EvmValidateError::Exec(e) => format!("evm execution: {e}"),
                    EvmValidateError::Store(e) => format!("evm store: {e}"),
                };
                // The validated flat/reconstruct seed (S9), or None ⇒ seed from 206 (the default,
                // and the fallback for pre-activation / Unavailable parents).
                match flat_auth.then(|| self.validated_flat_parent_seed(selected_parent)).flatten() {
                    Some(seed) => {
                        seed_prevalidated = true;
                        evm_validate_chained(
                            &self.evm_header_store,
                            &self.evm_state_store,
                            &self.evm_payload_store,
                            current,
                            selected_parent,
                            &sorted_mergeset,
                            header,
                            &own_payload,
                            Some(seed),
                            self.evm_gas_pool_v2_activation_daa_score,
                            self.evm_f002_withdraw_cap_activation_daa_score,
                            self.evm_f003_mldsa_verify_activation_daa_score,
                            self.evm_typed_receipt_root_activation_daa_score,
                        )
                        .map_err(map_err)?
                    }
                    None => {
                        // C-01 S9b: with 206 retired there is NO 206 fallback for an EVM-ACTIVE
                        // parent — the `evm_validate` (206) path below would read an absent snapshot
                        // and disqualify a VALID block (a fork). A flat backend that cannot yield an
                        // EVM-active parent's seed is a NODE fault, not a chain fault: HALT (design §7),
                        // never disqualify. A header-store read error is treated the same way (we cannot
                        // prove the parent is pre-activation, so we must not risk the 206 path) — a
                        // swallowed error here (`unwrap_or(false)`) would let an EVM-active parent fall
                        // through and false-disqualify. A PRE-ACTIVATION parent (no EVM header) needs no
                        // 206 — `evm_validate` seeds the empty genesis parent — so it stays correct.
                        // (The Unavailable-seed case for an EVM-active parent — e.g. a non-head parent
                        // whose §12 history is unreconstructable — also HALTs here; that is the safe
                        // fail-stop, never a fork. It should not arise in recent/archive mode, where
                        // §12 is retained for every unpruned block; if it recurs, retention is
                        // insufficient for the reorg depth — use archive — or the flat backend is faulty.)
                        if self.evm_retire_206 {
                            match self.evm_header_store.has(selected_parent) {
                                Ok(false) => {} // pre-activation: the 206 path seeds the empty parent (no 206 read)
                                Ok(true) => panic!(
                                    "C-01 S9b: --evm-retire-206 is on but no flat/reconstruct seed could be obtained for EVM-active \
                                     selected parent {selected_parent} (the 206 snapshot is retired). HALTING this node — chain integrity \
                                     is intact; restore the flat backend (or use --evm-history-mode=archive), or disable --evm-retire-206."
                                ),
                                Err(e) => panic!(
                                    "C-01 S9b: --evm-retire-206 is on and the EVM header store could not be read for selected parent \
                                     {selected_parent} ({e}); cannot prove it is pre-activation, and there is no 206 fallback. HALTING \
                                     this node (chain integrity intact) rather than risk false-disqualifying a valid block."
                                ),
                            }
                        }
                        evm_validate(
                            &self.evm_header_store,
                            &self.evm_state_store,
                            &self.evm_payload_store,
                            current,
                            selected_parent,
                            &sorted_mergeset,
                            header,
                            &own_payload,
                            self.evm_gas_pool_v2_activation_daa_score,
                            self.evm_f002_withdraw_cap_activation_daa_score,
                            self.evm_f003_mldsa_verify_activation_daa_score,
                            self.evm_typed_receipt_root_activation_daa_score,
                        )
                        .map_err(map_err)?
                    }
                }
            }
        };
        let Some(staged) = staged else {
            // The EVM rows commit in the SAME batch as the UTXO diff, so a
            // present result with an absent diff (this KeyNotFound arm) is
            // store corruption — never a reachable consensus state.
            panic!("EVM result for {current} exists but its UTXO diff does not — corrupt store");
        };
        // §9: fold the bridge's UTXO side-effects into THIS block's diff +
        // multiset (before verify_expected_utxo_state reads them).
        apply_evm_bridge_effects(
            &mut ctx.mergeset_diff,
            &mut ctx.multiset_hash,
            header.daa_score,
            &consumed_locks,
            &staged.result.withdrawals,
        )?;
        // kaspa-pq EVM bridge observability (P0-4): a deposit lock that reaches
        // this point is being APPLIED into this accepted chain block's committed
        // UTXO diff (consumed). Log each so a successful claim is directly visible
        // — the accepted-gas KPI rounds to 0.00% even for several real claims.
        for (outpoint, entry) in &consumed_locks {
            info!(
                "[evm-claim-applied] accepting_block={current} deposit_outpoint={outpoint} amount_sompi={} pov_daa={}",
                entry.amount, header.daa_score
            );
        }
        // O9: chain-rate / mergeset / gas-utilization observability + applied-claim count.
        self.evm_lane_kpi.record(ctx.ghostdag_data.mergeset_size(), staged.result.header.gas_used, consumed_locks.len());
        // C-01 (slice S6/S9) shadow seed validation: confirm the flat/reconstruct PARENT seed source
        // reproduces the committed 206 parent snapshot byte-for-byte (HALT on divergence; never
        // disqualifies — 206 is still written). Skipped when the flat-authoritative inline path
        // already validated the seed BEFORE executing from it (`seed_prevalidated`), so the check
        // runs exactly once: here for 206-seeded blocks (non-flat-auth inline, or the O12 pipeline),
        // pre-execution for flat-authoritative blocks. Node-local, off by default.
        if self.evm_shadow_state_backend && !seed_prevalidated {
            self.shadow_validate_parent_seed(selected_parent);
        }
        Ok(Some(staged))
    }

    /// C-01 (slice S6/S9/S9b) — compute the flat/reconstruct PARENT seed for
    /// `selected_parent` and validate it against the committed state before the
    /// executor uses it. The snapshot is materialized from the flat store when
    /// `selected_parent` is the canonical head, else §12-reconstructed (root-verified).
    ///
    /// Validation has two equivalent modes, chosen by whether the 206 snapshot is
    /// PRESENT (it is until slice S9b's `--evm-retire-206` stops persisting it):
    ///   - **206 present** (S6/S9): assert the flat/reconstruct seed is BYTE-IDENTICAL
    ///     to 206. This is belt-and-suspenders on top of the S4 write-side check.
    ///   - **206 absent** (S9b retired, or a parent committed while retired): there is
    ///     nothing to byte-compare against, so anchor to the consensus-committed root —
    ///     a FlatHead seed's flat pointer `state_root` must equal `parent_header.state_root`;
    ///     a Reconstructed seed is ALREADY keccak-MPT root-verified against it inside
    ///     `flat_or_reconstruct_parent_snapshot`. Either way the flat CONTENTS were
    ///     already proven == the executor's in-memory post-state when the parent was
    ///     committed (the S4 `shadow_dual_write_flat` differential, which never read 206),
    ///     so the per-block oracle is intact — retiring 206 drops only the redundant copy.
    ///
    /// HALTS the node (design §7) on a DEFINITIVE divergence — the seed differs from a
    /// present 206, a flat-head pointer root disagrees with the committed parent root, or
    /// a §12 reconstruction is corrupt — because feeding the executor a wrong parent state
    /// would falsely disqualify valid blocks. It NEVER returns an unvalidated seed and
    /// NEVER disqualifies.
    ///
    /// Returns `Some((parent_header, snapshot))` for a validated EVM-active parent seed.
    /// Returns `None` when the parent is pre-activation (no EVM header ⇒ the executor's
    /// own store path yields the empty genesis parent) OR the seed is Unavailable
    /// (transient store I/O, or a non-head parent's §12 history GC'd past retention).
    /// In retire-206 mode the caller turns a `None` for an EVM-ACTIVE parent into a HALT
    /// (no 206 fallback); otherwise it falls back to the 206 store path. Node-local; only
    /// meaningful when the shadow backend is on.
    #[cfg(feature = "evm")]
    fn validated_flat_parent_seed(
        &self,
        selected_parent: BlockHash,
    ) -> Option<(kaspa_consensus_core::evm::EvmExecutionHeader, kaspa_consensus_core::evm::EvmStateSnapshot)> {
        use crate::model::stores::evm::{EvmHeaderStoreReader, EvmStateStoreReader};
        use crate::processes::evm::{ParentSeedError, ParentSeedSource, flat_or_reconstruct_parent_snapshot};

        // An EVM-active parent always persists its header; a parent with no EVM header is
        // pre-activation (empty genesis state) — nothing to validate, and the executor's
        // store path supplies the empty parent, so return None.
        let parent_header = match self.evm_header_store.get(selected_parent) {
            Ok(h) => h,
            Err(kaspa_database::prelude::StoreError::KeyNotFound(_)) => return None,
            Err(e) => {
                warn!("[evm-shadow-seed] header read failed for {selected_parent}: {e}; falling back to 206");
                return None;
            }
        };
        // The 206 snapshot — the byte-compare oracle WHEN PRESENT. `KeyNotFound` is not an
        // error here: it means 206 was retired (S9b) or this parent was committed while
        // retired. We then validate the seed against the committed root instead (below).
        let snapshot_206 = match self.evm_state_store.get(selected_parent) {
            Ok(s) => Some(s),
            Err(kaspa_database::prelude::StoreError::KeyNotFound(_)) => None,
            Err(e) => {
                warn!("[evm-shadow-seed] 206 read failed for {selected_parent}: {e}; falling back to 206");
                return None;
            }
        };
        // Surface a flat-pointer read failure as a fallback — never silently treat it
        // as "no head" (None), which would misroute the canonical head into the
        // reconstruct path and hide the store error. Carry the pointer's committed
        // `state_root` for the 206-absent FlatHead anchor check.
        let (flat_head, flat_head_root) = match self.evm_latest_state_ptr_store.read().get() {
            Ok(opt) => (opt.map(|p| p.canonical_head), opt.map(|p| p.state_root)),
            Err(e) => {
                warn!("[evm-shadow-seed] flat pointer read failed for {selected_parent}: {e}; falling back to 206");
                return None;
            }
        };

        match flat_or_reconstruct_parent_snapshot(
            selected_parent,
            flat_head,
            &self.evm_flat_account_store,
            &self.evm_code_store,
            &self.evm_header_store,
            &self.evm_state_checkpoint_store,
            &self.evm_state_diff_store,
        ) {
            Ok((snapshot_flat, source)) => {
                match &snapshot_206 {
                    // 206 present (S6/S9): the seed must be byte-identical to it.
                    Some(s206) => {
                        if &snapshot_flat != s206 {
                            panic!(
                                "C-01 shadow seed DIVERGENCE: the {source:?} parent seed for {selected_parent} ({} accounts) does not match \
                                 the committed 206 snapshot ({} accounts). The flat/reconstruct seed source would feed the executor a wrong parent \
                                 state and FALSELY disqualify valid blocks — HALTING this node. 206 stays authoritative (chain integrity intact); \
                                 fix the backend and re-shadow.",
                                snapshot_flat.accounts.len(),
                                s206.accounts.len()
                            );
                        }
                    }
                    // 206 absent (S9b retired): anchor to the consensus-committed root. A
                    // Reconstructed seed is already root-verified inside the helper; a FlatHead
                    // seed's pointer root must equal the committed parent root (guards a stale/
                    // wrong pointer — the flat CONTENTS were already proven == the executor's
                    // post-state at the parent's commit by the S4 write-side differential).
                    None => {
                        if source == ParentSeedSource::FlatHead && flat_head_root != Some(parent_header.state_root) {
                            panic!(
                                "C-01 S9b retired-206 seed DIVERGENCE: the flat head pointer root ({flat_head_root:?}) for {selected_parent} \
                                 does not equal the committed parent state_root ({:?}). The flat pointer is stale/wrong and would seed the \
                                 executor from the wrong head — HALTING this node (chain integrity intact); restore the flat backend.",
                                parent_header.state_root
                            );
                        }
                    }
                }
                Some((parent_header, snapshot_flat))
            }
            // Could not READ the data to validate (transient store I/O, or a non-head
            // parent's §12 history GC'd past retention): NOT a divergence — the caller
            // falls back to 206 (S9) or HALTs for an EVM-active parent (S9b retired).
            Err(ParentSeedError::Unavailable(m)) => {
                debug!("[evm-shadow-seed] seed unavailable for {selected_parent}: {m}; falling back to 206");
                None
            }
            // A broken §12 reconstruction (root mismatch / diff inconsistency / bad
            // checkpoint / absent code) is a real backend fault ⇒ HALT.
            Err(ParentSeedError::Corrupt(m)) => {
                panic!(
                    "C-01 shadow seed CORRUPT for {selected_parent}: {m}. The flat/reconstruct backend is broken — HALTING (206 stays authoritative)."
                );
            }
        }
    }

    /// C-01 (slice S6) post-execution shadow check: validate the flat/reconstruct seed
    /// source against 206 (HALT on divergence), discarding the seed. Used when the
    /// executor was seeded from 206 (every block while the flat-authoritative cutover
    /// is off) — 206 stays authoritative, so this can only HALT on a backend divergence,
    /// never disqualify a valid block.
    #[cfg(feature = "evm")]
    fn shadow_validate_parent_seed(&self, selected_parent: BlockHash) {
        let _ = self.validated_flat_parent_seed(selected_parent);
    }

    /// Non-`evm` builds cannot validate the lane. On every default network the
    /// lane is `u64::MAX`-inert so this is unreachable; on an evm-ACTIVE net a
    /// non-evm binary must refuse to follow a chain it cannot validate rather
    /// than silently fork.
    #[cfg(not(feature = "evm"))]
    fn evm_chain_context_step<V: UtxoView>(
        &self,
        _current: BlockHash,
        _selected_parent: BlockHash,
        header: &Header,
        _ctx: &mut UtxoProcessingContext<'_>,
        _selected_parent_utxo_view: &V,
        _pipeline: Option<&crate::processes::evm::EvmPipeline>,
    ) -> Result<Option<crate::processes::evm::EvmStaged>, String> {
        if header.daa_score >= self.evm_activation_daa_score {
            panic!(
                "the EVM lane is active at DAA {} but this kaspad was built without the `evm` feature — refusing to follow a chain it cannot validate (rebuild with --features evm)",
                header.daa_score
            );
        }
        Ok(None)
    }

    /// O12: spawn the EVM pipeline worker for the upcoming forward walk when it
    /// contains a long run of pending EVM-active chain blocks (IBD catch-up).
    /// Steady-state walks (a handful of blocks) skip the pipeline — the thread
    /// + channel overhead outweighs overlapping a single block.
    #[cfg(feature = "evm")]
    fn maybe_spawn_evm_pipeline(&self, split_point: BlockHash, to: BlockHash) -> Option<crate::processes::evm::EvmPipeline> {
        use crate::processes::evm::{EvmPipeline, EvmPipelineItem};
        const MIN_PIPELINE_RUN: usize = 8;
        if self.evm_activation_daa_score == u64::MAX {
            return None;
        }
        // C-01 S9b: the pipeline worker seeds a run's FIRST/gap item from the 206 store (its other
        // items chain in-memory). With 206 retired there is no such seed, so disable the pipeline
        // and let the inline path (which seeds every block from the validated flat store) handle the
        // run. Pure perf/throughput trade — correctness is identical either way (I-3 invariant).
        if self.evm_retire_206 {
            return None;
        }
        let statuses = self.statuses_store.read();
        let mut pending: Vec<EvmPipelineItem> = Vec::new();
        let mut prev_pending: Option<BlockHash> = None;
        for (selected_parent, current) in self.reachability_service.forward_chain_iterator(split_point, to, true).tuple_windows() {
            // Mirror the walk's KeyNotFound arm: only blocks without a committed
            // UTXO diff and not already disqualified will be validated.
            if self.utxo_diffs_store.get(current).is_ok() {
                continue;
            }
            if statuses.get(current).unwrap() == StatusDisqualifiedFromChain {
                continue;
            }
            if self.headers_store.get_daa_score(current).unwrap() < self.evm_activation_daa_score {
                continue; // pre-activation block: the step is inert for it
            }
            let chain_from_prev = prev_pending == Some(selected_parent);
            pending.push(EvmPipelineItem { block: current, selected_parent, chain_from_prev });
            prev_pending = Some(current);
        }
        drop(statuses);
        if pending.len() < MIN_PIPELINE_RUN {
            return None;
        }
        Some(EvmPipeline::spawn(
            self.evm_header_store.clone(),
            self.evm_state_store.clone(),
            self.evm_payload_store.clone(),
            self.headers_store.clone(),
            self.ghostdag_store.clone(),
            pending,
            self.evm_gas_pool_v2_activation_daa_score,
            self.evm_f002_withdraw_cap_activation_daa_score,
            self.evm_f003_mldsa_verify_activation_daa_score,
            self.evm_typed_receipt_root_activation_daa_score,
        ))
    }

    /// Non-`evm` builds never pipeline (the step itself is a panic-guard there).
    #[cfg(not(feature = "evm"))]
    fn maybe_spawn_evm_pipeline(&self, _split_point: BlockHash, _to: BlockHash) -> Option<crate::processes::evm::EvmPipeline> {
        None
    }

    /// kaspa-pq EVM Lane v0.4 (§10 / invariant I3): a virtual change only moves
    /// the canonical EVM head POINTERS — never executes. Pre-§16 (RPC) policy:
    /// `latest` = the new sink; `safe` tracks `latest`; `finalized` tracks the
    /// pruning point once it carries an EVM result (consensus-final), else the
    /// previous finalized. The blue-work-depth `safe` + DNS-confirmed-anchor
    /// `finalized` selection lands with the RPC phase that first exposes the
    /// tags. Inert (one u64 compare) on every current network.
    fn update_evm_canonical_heads(&self, batch: &mut WriteBatch, sink: BlockHash) {
        use crate::model::stores::evm::{EvmCanonicalHeadsStoreReader, EvmHeaderStoreReader};
        if self.evm_activation_daa_score == u64::MAX {
            return;
        }
        // The sink carries an EVM result iff the lane is live for it (it may
        // predate activation right after the fork).
        if !self.evm_header_store.has(sink).unwrap_or(false) {
            return;
        }
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        let prev_finalized = self.evm_heads_store.read().get().ok().map(|h| h.finalized);
        let finalized =
            if self.evm_header_store.has(pruning_point).unwrap_or(false) { pruning_point } else { prev_finalized.unwrap_or(sink) };
        let heads = kaspa_consensus_core::evm::CanonicalEvmHeads { latest: sink, safe: sink, finalized };
        self.evm_heads_store.write().set_batch(batch, heads).unwrap();
    }

    /// kaspa-pq EVM Lane v0.4 (§16 RPC / canonical-index fix): drive the
    /// `evm_number → L1 hash` map from the CANONICAL selected chain. Detached
    /// chain blocks release their number (only if still theirs); attached chain
    /// blocks claim it. Companion to dropping the per-block write in
    /// `commit_utxo_state`: a sink-search loser (UTXO-validated by
    /// `calculate_utxo_state_relatively` but not selected) never touches the
    /// map, so `get_evm_block_by_number` / `get_evm_logs` can't be shadowed by a
    /// non-canonical row. Detach-before-attach mirrors `stage_dns_bond_mutations`
    /// (a number both removed and re-added in one reorg ends at the attached
    /// block: the batch applies the delete, then the put). Inert (one u64
    /// compare) on every current network.
    fn update_evm_canonical_number_map(&self, batch: &mut WriteBatch, chain_path: &ChainPath) {
        use crate::model::stores::evm::EvmHeaderStoreReader;
        if self.evm_activation_daa_score == u64::MAX {
            return;
        }
        // Detach first (most-recent first): release each removed chain block's
        // number iff the row still points to it.
        for removed in chain_path.removed.iter().rev().copied() {
            if let Some(h) = self.evm_header_store.get(removed).optional().unwrap() {
                self.evm_number_store.delete_if_matches_batch(batch, h.evm_number, removed).unwrap();
            }
        }
        // Attach: each added chain block claims its number (canonical-only write).
        for added in chain_path.added.iter().copied() {
            if let Some(h) = self.evm_header_store.get(added).optional().unwrap() {
                self.evm_number_store.write_batch(batch, h.evm_number, added).unwrap();
            }
        }
    }

    /// kaspa-pq EVM Lane v0.4 (§15): producer-side EVM fields for a template
    /// built from the current virtual state. Runs the SAME acceptance-execution
    /// core the verifier uses, so a block mined from this template reproduces
    /// `evm_commitment_root` byte-for-byte. The own payload is empty until the
    /// EVM mempool lands (§16). NOTE: the commitment derives from the header's
    /// timestamp — a miner must not mutate the template timestamp (refreshing
    /// the template re-derives the commitment).
    #[cfg(feature = "evm")]
    fn evm_template_fields(
        &self,
        header: Header,
        virtual_state: &VirtualState,
        evm_template_data: kaspa_consensus_core::evm::EvmTemplateData,
        // kaspa-pq narrow P0-1: deposit claims already validated + their lock
        // entries materialized against the template's virtual generation (no
        // re-read of a possibly-advanced view here).
        prepared_claims: crate::processes::evm::PreparedDepositClaims,
    ) -> Result<
        (
            Header,
            kaspa_consensus_core::evm::EvmExecutionPayload,
            Vec<(kaspa_consensus_core::tx::TransactionOutpoint, EvmClaimStaleKind)>,
        ),
        RuleError,
    > {
        use crate::processes::evm::{evm_execute_acceptance, evm_execute_acceptance_with_parent}; // EvmHeaderStoreReader in module scope
        if header.daa_score < self.evm_activation_daa_score {
            return Ok((header, Default::default(), vec![]));
        }
        // narrow P0-1: split the deposit-claim snapshot prepared against the
        // template's virtual generation — `accepted` claims go into the payload,
        // their `consumed_locks` fold into the commitment, the `stale` set flows
        // back to the mining manager.
        let crate::processes::evm::PreparedDepositClaims { accepted: accepted_claims, consumed_locks, stale: stale_claims } =
            prepared_claims;
        // §15 step 6: assemble the own payload from the mempool candidates.
        // Defense-in-depth re-admission (the body class-1 rule): an inadmissible
        // tx here would make our OWN block payload-block-invalid, so hard-filter
        // rather than trust the pool; independently re-enforce the byte cap.
        // The candidates execute in a LATER accepting chain block, never here.
        let own_payload = {
            use kaspa_consensus_core::evm::{EvmExecutionPayload, MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK};
            let mut payload = EvmExecutionPayload::default();
            let base = payload.payload_bytes().len();
            let mut budget = MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK.saturating_sub(base);
            for raw in evm_template_data.transactions {
                if 4 + raw.len() > budget {
                    continue;
                }
                match crate::processes::evm::admit_evm_payload_txs(&EvmExecutionPayload {
                    transactions: vec![raw.clone()],
                    ..Default::default()
                }) {
                    Ok(()) => {
                        budget -= 4 + raw.len();
                        payload.transactions.push(raw);
                    }
                    Err((_, reason)) => {
                        warn!("EVM template: dropping inadmissible mempool candidate ({reason})");
                    }
                }
            }
            // §9.2 (narrow P0-1): own-payload deposit claims. These EXECUTE in the
            // accepting chain block, so an invalid claim would make our block invalid.
            // The claims were ALREADY validated, and their consumed lock entries
            // materialized, by `prepare_deposit_claims` against the SAME virtual
            // generation this template's selected parent is taken from — NOT a
            // re-read of a possibly-advanced view here (that second read was the
            // mixed-generation TOCTOU that could self-disqualify the block or wrongly
            // drop a still-valid claim). The claim view for a block B extending the
            // virtual tip is `selected_parent(B)_view ∘ B.mergeset_diff`, which for a
            // fresh template IS the captured virtual UTXO set — exactly what the
            // acceptance path re-checks. Emit the accepted claims; the consumed locks
            // fold into the commitment below; the tagged stale set flows back to the
            // mining manager (`Absent` ⇒ retain + retry, `Invalid` ⇒ evict).
            for claim in accepted_claims {
                payload.system_ops.push(kaspa_consensus_core::evm::EvmSystemOp::DepositClaim(claim));
            }
            // audit #3: the tx loop above budgets ONLY the txs against the byte
            // cap; the deposit-claim system ops are appended afterwards and each
            // is ~105 bytes, so a near-full tx payload + ≥1 claim can exceed
            // MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK — which body validation rejects,
            // making the node's OWN template invalid. Claims must execute (they
            // are this block's bridge credits), so keep every selected claim and
            // drop trailing (lowest-priority) txs until the WHOLE payload fits.
            while !payload.transactions.is_empty() && payload.payload_bytes().len() > MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK {
                payload.transactions.pop();
            }
            // §8.2: the declared coinbase claims this payload's priority fees —
            // meaningful only when the payload actually carries content (and
            // keeping it zero otherwise preserves the empty payload / empty
            // store-row form). A claim-only payload also declares the coinbase
            // (the claim tip routes to it, §9.2).
            if !payload.transactions.is_empty() || !payload.system_ops.is_empty() {
                payload.evm_coinbase = evm_template_data.evm_coinbase;
            }
            payload
        };
        let sorted_mergeset: Vec<BlockHash> =
            virtual_state.ghostdag_data.consensus_ordered_mergeset(self.ghostdag_store.as_ref()).collect();
        let selected_parent = virtual_state.ghostdag_data.selected_parent;
        // C-01 S9/S9b: the producer must seed the SAME parent state the verifier later seeds from
        // (so the mined block reproduces evm_commitment_root). When flat-authoritative, seed from the
        // validated flat/reconstruct parent (HALT on divergence, inside `validated_flat_parent_seed`),
        // exactly like the inline verifier — otherwise the 206 store path. With 206 retired there is no
        // 206 to read for an EVM-active parent, so a missing flat seed fails the template build (a
        // transient producer failure — never a panic / never a wrong commitment), not a 206 read error.
        let parent_override = (self.evm_flat_authoritative && self.evm_shadow_state_backend)
            .then(|| self.validated_flat_parent_seed(selected_parent))
            .flatten();
        let mapper = |e| RuleError::EvmTemplateExecutionFailed(format!("{e:?}"));
        let result = match parent_override {
            Some(seed) => {
                evm_execute_acceptance_with_parent(
                    &self.evm_header_store,
                    &self.evm_state_store,
                    &self.evm_payload_store,
                    selected_parent,
                    &sorted_mergeset,
                    &header,
                    &own_payload,
                    Some(seed),
                    self.evm_gas_pool_v2_activation_daa_score,
                    self.evm_f002_withdraw_cap_activation_daa_score,
                    self.evm_f003_mldsa_verify_activation_daa_score,
                    self.evm_typed_receipt_root_activation_daa_score,
                )
                .map_err(mapper)?
                .0
            }
            None => {
                // C-01 S9b: with 206 retired there is no 206 seed for an EVM-active parent. Unlike the
                // verifier (which HALTs to avoid a fork), a PRODUCER failure must never crash the node —
                // fail THIS template build and let the miner retry. A header-store read error is treated
                // the same (we cannot prove pre-activation, and `unwrap_or(false)` would wrongly let an
                // EVM-active parent fall through to the absent-206 path). Pre-activation (Ok(false)) needs
                // no 206 and proceeds via `evm_execute_acceptance` (empty parent).
                if self.evm_retire_206 {
                    match self.evm_header_store.has(selected_parent) {
                        Ok(false) => {} // pre-activation: empty parent, no 206 read
                        Ok(true) => {
                            return Err(RuleError::EvmTemplateExecutionFailed(format!(
                                "--evm-retire-206: no flat/reconstruct seed for EVM-active selected parent {selected_parent} (206 retired); \
                                 cannot build a template this round — retrying"
                            )));
                        }
                        Err(e) => {
                            return Err(RuleError::EvmTemplateExecutionFailed(format!(
                                "--evm-retire-206: EVM header store read failed for selected parent {selected_parent} ({e}); cannot build a template this round"
                            )));
                        }
                    }
                }
                // audit R2-#4: a producer-side acceptance failure (e.g. a local EVM
                // store-integrity error) is a template-build failure, not a panic.
                evm_execute_acceptance(
                    &self.evm_header_store,
                    &self.evm_state_store,
                    &self.evm_payload_store,
                    selected_parent,
                    &sorted_mergeset,
                    &header,
                    &own_payload,
                    self.evm_gas_pool_v2_activation_daa_score,
                    self.evm_f002_withdraw_cap_activation_daa_score,
                    self.evm_f003_mldsa_verify_activation_daa_score,
                    self.evm_typed_receipt_root_activation_daa_score,
                )
                .map_err(mapper)?
                .0
            }
        };
        let mut header = header.with_evm_payload_hash(own_payload.payload_hash()).with_evm_commitment(result.header.commitment_root());
        // §9: the validator folds the bridge's UTXO side-effects (consumed
        // deposit locks + materialized withdrawals) into THIS block's diff and
        // checks them against `header.utxo_commitment` — so the PRODUCER must
        // fold the identical effects into the template's commitment (the
        // template inherited the virtual multiset, which has none of them).
        // Found live: the first claim-bearing template self-disqualified.
        if !consumed_locks.is_empty() || !result.withdrawals.is_empty() {
            let mut multiset = virtual_state.multiset.clone();
            let mut scratch_diff = kaspa_consensus_core::utxo::utxo_diff::UtxoDiff::default();
            crate::processes::evm::apply_evm_bridge_effects(
                &mut scratch_diff,
                &mut multiset,
                header.daa_score,
                &consumed_locks,
                &result.withdrawals,
            )
            .expect("template bridge effects mirror validation on already-validated inputs");
            header.utxo_commitment = multiset.finalize();
            header.finalize();
        }
        Ok((header, own_payload, stale_claims))
    }

    /// Non-`evm` builds cannot produce evm-active templates (same refusal as
    /// the validation seam); unreachable on every default network.
    #[cfg(not(feature = "evm"))]
    fn evm_template_fields(
        &self,
        header: Header,
        _virtual_state: &VirtualState,
        _evm_template_data: kaspa_consensus_core::evm::EvmTemplateData,
        _prepared_claims: crate::processes::evm::PreparedDepositClaims,
    ) -> Result<
        (
            Header,
            kaspa_consensus_core::evm::EvmExecutionPayload,
            Vec<(kaspa_consensus_core::tx::TransactionOutpoint, EvmClaimStaleKind)>,
        ),
        RuleError,
    > {
        if header.daa_score >= self.evm_activation_daa_score {
            panic!(
                "the EVM lane is active at DAA {} but this kaspad was built without the `evm` feature — cannot build a valid template (rebuild with --features evm)",
                header.daa_score
            );
        }
        Ok((header, Default::default(), vec![]))
    }

    fn commit_utxo_state(
        &self,
        current: BlockHash,
        mergeset_diff: UtxoDiff,
        multiset: MuHash,
        acceptance_data: AcceptanceData,
        pruning_sample_from_pov: BlockHash,
        // kaspa-pq (ADR-0009 Addendum B §B.3(c)): the `(bond, epoch)` keys this
        // block rewarded. Persisted only when non-empty — empty on every block
        // of every current network (the overlay is dormant), so no rows are
        // written there.
        rewarded_keys: RewardedEpochKeys,
        // kaspa-pq ADR-0040 §5.15.13 (G16): the `job_nullifier`s this block's coinbase PAID. Persisted
        // only when non-empty, and it is empty on every block of every shipped preset (no algo-4 source
        // is acceptable anywhere), so no row is ever written there.
        palw_paid_work_ids: PalwPaidWorkIds,
        // kaspa-pq ADR-0018 "本格版" (PoS-v2, Phase 1): this block's validator quality
        // sub-pool, the per-epoch accumulator's recompute input. Non-zero (and
        // therefore persisted) only past `pos_v2_activation_daa_score` (`u64::MAX`
        // today), so no row is written on any current network.
        quality_subpool: u64,
        // kaspa-pq ADR-0018 "本格版" (PoS-v2, Phase 4): this block's cumulative reserve balance.
        // Persisted only when non-zero (the 0 default is never stored), so no row on any current
        // network. Children read it as their `parent_balance` for the reserve drip.
        reserve_balance: u64,
        // kaspa-pq EVM Lane v0.4 (§2.3): the validated EVM rows staged by
        // `evm_chain_context_step` — committed in THIS batch so the EVM result
        // and the block's UTXO diff are atomic. `None` on every current
        // network (lane inert) and on non-evm builds.
        evm_staged: Option<crate::processes::evm::EvmStaged>,
        // ADR-0039 §11.2: DNS bonds exactly as-of this block's selected parent.
        // Beacon commits/reveals must never observe this block's own bond mutations.
        selected_parent_bond_view: &ActiveBondView,
        // kaspa-pq ADR-0040 §5.17: PALW provider bonds exactly as-of this block's selected parent — the
        // auditor candidate pool + vote-key/stake source the certificate re-derivations read. Walked in
        // the same lockstep as the DNS view, so a certificate's committee is resolved against the frozen
        // audit snapshot, not this block's own provider mutations.
        selected_parent_provider_bond_view: &ProviderBondView,
    ) {
        let mut batch = WriteBatch::default();
        if let Some(mut staged) = evm_staged {
            // §12: in a mode that keeps no long-term EVM state history (`head`), drop
            // the archive diff so staging writes no diff/code/checkpoint rows
            // (220/221/222). The hot snapshot (206) + trace body (219) still cover its
            // reorg/trace window.
            if !self.evm_history_mode.writes_state_history() {
                staged.state_diff = None;
            }
            self.evm_header_store.insert_batch(&mut batch, current, staged.result.header.clone()).unwrap();
            // §16: receipts + tx-lookup index rows (store/RPC data only) commit
            // in the SAME batch — atomic with the result and the UTXO diff.
            crate::processes::evm::stage_evm_index_rows(
                &self.evm_receipts_store,
                &self.evm_tx_index_store,
                &self.evm_log_index_store,
                &self.evm_trace_store,
                &self.evm_state_diff_store,
                &self.evm_code_store,
                &self.evm_state_checkpoint_store,
                &mut batch,
                current,
                &staged,
            )
            .unwrap();
            // C-01 (slice S4) shadow dual-write + live differential, node-local,
            // OFF by default. Maintains the flat latest-state store (234/232/231)
            // in THIS batch and HALTS this node if applying the §12 diff to the
            // flat state disagrees with the committed post-state. The 206 snapshot
            // (written just below) stays the source of truth, so the committed
            // bytes are unchanged whether shadow is on or off (consensus-neutral).
            if self.evm_shadow_state_backend {
                use crate::model::stores::evm::{EvmHeaderStoreReader, EvmStateDiffStoreReader};
                // Chain readers for the S5 reorg re-base: a block's §12 diff (220)
                // and its sequential evm_number (from the EVM header, 201).
                let diff_store = &self.evm_state_diff_store;
                let header_store = &self.evm_header_store;
                let get_diff = |b: BlockHash| diff_store.get(b);
                let get_number = |b: BlockHash| match header_store.get(b) {
                    Ok(h) => Ok(Some(h.evm_number)),
                    Err(StoreError::KeyNotFound(_)) => Ok(None),
                    Err(e) => Err(e),
                };
                let mut ptr = self.evm_latest_state_ptr_store.write();
                match crate::processes::evm::shadow_dual_write_flat(
                    &self.evm_flat_account_store,
                    &self.evm_block_state_root_store,
                    &mut ptr,
                    &self.evm_code_store,
                    &mut batch,
                    current,
                    &staged,
                    get_diff,
                    get_number,
                ) {
                    Ok(crate::processes::evm::ShadowOutcome::Reseeded) => {
                        info!("[evm-shadow] flat state backend (re)seeded to block {current}");
                    }
                    Ok(crate::processes::evm::ShadowOutcome::Rebased) => {
                        info!("[evm-shadow] flat state backend re-based across a reorg to block {current}");
                    }
                    Ok(_) => {}
                    // A divergence (or store error) is fatal: never let a node that
                    // would serve a wrong flat-backend root keep running (design §7).
                    Err(e) => panic!("{e}"),
                }
            }
            // C-01 S9b: persist the per-block 206 snapshot UNLESS it is retired. The flat backend
            // (advanced + checked against `staged.snapshot` by the shadow dual-write just above) is
            // then the sole persisted post-state; the executor seeds from it (S9) and reads fall back
            // to flat-materialize / §12-reconstruct. `evm_retire_206` is only ever true together with
            // the shadow backend (the demotion in `new`), so the flat store IS maintained here before
            // the snapshot is dropped — the next block's seed reads a current flat head. Skipping the
            // write changes only what THIS node persists, never a commitment: consensus-neutral.
            if self.evm_retire_206 {
                drop(staged.snapshot);
            } else {
                self.evm_state_store.insert_batch(&mut batch, current, staged.snapshot).unwrap();
            }
            // §16 eth-rpc: map the 32-byte eth block id (first 32 bytes of the
            // 64-byte L1 hash — the truncation `eth_getTransactionReceipt`
            // already exposes as `blockHash`) → this L1 block, so
            // `eth_getBlockByHash` can reverse a client-held 32-byte hash. Upsert
            // (a given L1 block's first-32 is stable). RPC index only.
            let mut rpc_block_id = [0u8; 32];
            rpc_block_id.copy_from_slice(&current.as_bytes()[..32]);
            self.evm_block_hash_map_store.write_batch(&mut batch, kaspa_hashes::EvmH256::from_bytes(rpc_block_id), current).unwrap();
            // NOTE (canonical-index fix): the `evm_number → L1 hash` map is NOT
            // written here. It is the only EVM RPC row keyed by a value shared
            // across DAG side branches, so a UTXO-valid sink-search loser (a
            // candidate `calculate_utxo_state_relatively` validates here but the
            // DNS reorg gate / sink selection then rejects) would overwrite the
            // canonical row and make that number read as absent. It is instead
            // driven by the selected chain in `update_evm_canonical_number_map`
            // at virtual commit. The immutable rows above stay L1-hash-keyed, so
            // detached side branches remain queryable by hash.
        }
        self.utxo_diffs_store.insert_batch(&mut batch, current, Arc::new(mergeset_diff)).unwrap();
        self.utxo_multisets_store.insert_batch(&mut batch, current, multiset).unwrap();
        // ADR-0039 §9.3/§9.5: advance the PALW batch state machine from this chain block's accepted
        // overlay txs, keyed to acceptance (a selected-chain property) exactly like the DNS overlays
        // above. The `palw_activation_daa_score == u64::MAX` guard returns before touching
        // `acceptance_data` — byte-identical — on mainnet / testnet-10 / simnet / devnet ONLY. On
        // testnet-palw-110 / devnet-palw-111 the fence is 0 (config/params.rs:1403, :1454) and this
        // RUNS: PALW overlay txs are ordinary txs (subnets 0x30-0x33), so `palw_algo4_accept = false`
        // does not suppress them.
        self.commit_palw_overlay_effects(current, &acceptance_data, selected_parent_provider_bond_view);
        // ADR-0039 §11.2: derive/carry this block's active beacon seed R_E (block-keyed recurrence,
        // read via selected parent). Written into THIS batch (atomic with the UTXO diff). The fast-path
        // return fires on mainnet / testnet-10 / simnet / devnet only; on testnet-palw-110 /
        // devnet-palw-111 (fence = 0) beacon state + accumulator rows ARE written per chain block.
        self.commit_palw_beacon_state(&mut batch, current, &acceptance_data, selected_parent_bond_view);
        self.acceptance_data_store.insert_batch(&mut batch, current, Arc::new(acceptance_data)).unwrap();
        if !rewarded_keys.is_empty() {
            self.rewarded_epochs_store.insert_batch(&mut batch, current, Arc::new(rewarded_keys)).unwrap();
        }
        // kaspa-pq ADR-0040 §5.15.13 (G16): this chain block's paid-`job_nullifier` delta, written into
        // the SAME atomic batch as the UTXO diff — so a block's payout and the evidence its descendants
        // dedup against can never be persisted apart. Non-empty only when a `ReplicaPalw` class was
        // actually paid, i.e. never on any shipped preset.
        if !palw_paid_work_ids.is_empty() {
            self.palw_paid_work_store.insert_batch(&mut batch, current, Arc::new(palw_paid_work_ids)).unwrap();
        }
        if quality_subpool > 0 {
            self.block_quality_pool_store.insert_batch(&mut batch, current, quality_subpool).unwrap();
        }
        if reserve_balance > 0 {
            self.reserve_balance_store.insert_batch(&mut batch, current, reserve_balance).unwrap();
        }
        // Note we call idempotent since this field can be populated during IBD with headers proof
        self.pruning_samples_store.insert_batch(&mut batch, current, pruning_sample_from_pov).idempotent().unwrap();
        let write_guard = self.statuses_store.set_batch(&mut batch, current, StatusUTXOValid).unwrap();
        self.db.write(batch).unwrap();
        // Calling the drops explicitly after the batch is written in order to avoid possible errors.
        drop(write_guard);
    }

    /// ADR-0039 §9.3/§9.5 — apply the batch-lifecycle transitions carried by this chain block's
    /// accepted PALW overlay txs (subnetwork `0x30`–`0x33`) to the [`PalwStore`]. Runs at virtual
    /// commit, keyed to acceptance (a selected-chain property) so construction and validation see the
    /// same transitions, mirroring the DNS attestation/slashing overlays.
    ///
    /// **Fence status (corrected — the previous "inert on every shipped preset" claim was FALSE).** The
    /// fast-path guard returns before reading `acceptance_data`, leaving the store unwritten, only on
    /// **mainnet / testnet-10 / simnet / devnet**. `testnet-palw-110` and `devnet-palw-111` ship
    /// `palw_activation_daa_score = 0` (`config/params.rs:1403`, `:1454`), so on those two presets this
    /// RUNS from genesis and DOES write the store. `palw_algo4_accept = false` does not prevent it: the
    /// transitions are carried by ordinary transactions on subnetworks `0x30`–`0x33`, and the accept
    /// lever only withholds algo-4 HEADER acceptance (`pre_ghostdag_validation.rs`).
    ///
    /// Two hardening items therefore are NOT moot on those presets, and remain open activation
    /// blockers: (1) fold the store writes into the commit `WriteBatch` for crash-atomicity with the
    /// UTXO diff — today they are direct writes outside the batch; and (2) revert batch-state
    /// transitions when this block is reorged out of the selected chain (batch status is global, not
    /// block-keyed). Neither is reachable in a consensus-critical way while `palw_algo4_accept = false`
    /// keeps tickets from resolving against these rows, which is the actual fence.
    fn commit_palw_overlay_effects(
        &self,
        current: BlockHash,
        acceptance_data: &AcceptanceData,
        selected_parent_provider_bond_view: &ProviderBondView,
    ) {
        if self.palw_activation_daa_score == u64::MAX {
            return; // inert fast path — no header read, no acceptance-data walk.
        }
        let cur_daa = self.headers_store.get_daa_score(current).unwrap();
        if cur_daa < self.palw_activation_daa_score {
            return;
        }
        // kaspa-pq ADR-0040 §5.17.3 — the selected parent anchors the buried-walk audit-epoch seed
        // resolution below; it is strictly in `current`'s past, so every node reaching `current` walks
        // the identical selected-parent chain (order-independent).
        let selected_parent = self.ghostdag_store.get_selected_parent(current).unwrap();
        let epoch_len = self.palw_epoch_length_daa.max(1);
        let inclusion_epoch = cur_daa / epoch_len;
        let inclusion_window_epochs =
            kaspa_consensus_core::palw::palw_audit_epoch_inclusion_window_epochs(&self.palw_batch_admission);
        for merged in acceptance_data.iter() {
            // Load the merged block's bodies once; skip if absent (pruned) — a PALW tx cannot be
            // accepted from a body we no longer hold.
            let Ok(txs) = self.block_transactions_store.get(merged.block_hash) else { continue };
            for entry in merged.accepted_transactions.iter() {
                let Some(tx) = txs.get(entry.index_within_block as usize) else { continue };
                let Some(kind) = tx.subnetwork_id.palw_tx_kind() else { continue };
                // Malformed/unhandled payloads and rejected §9.5 transitions are dropped: a PALW tx
                // that fails payload validity or the batch-state guard has no consensus effect here
                // (body-processing already screened well-formedness; this is the state-application
                // step). `parse`+`apply` are the same units exercised by `processes::palw` tests.
                if let Ok(effect) = crate::processes::palw::parse_palw_overlay(kind, &tx.payload) {
                    // Beacon effects use the fork-local, block-keyed accumulator below. Never
                    // dual-write them into the legacy epoch-global store: a side branch processed
                    // first could otherwise contaminate the selected chain's R_E.
                    if matches!(
                        &effect,
                        crate::processes::palw::PalwOverlayEffect::BeaconCommit(_)
                            | crate::processes::palw::PalwOverlayEffect::BeaconReveal(_)
                    ) {
                        continue;
                    }
                    // kaspa-pq ADR-0040 §5.17 (AUTHSET-01 / SAMPLE-01 / SEL-01): a batch certificate is
                    // checked against the BEACON-SELECTED auditor committee (re-derived by the SEL-01
                    // weighted sampler over the selected-parent PROVIDER-bond view) and the beacon-selected
                    // on-chain leaf sample (re-derived `audit_sample_root`), plus real ML-DSA-87 vote
                    // signatures and stake-weighted quorum, before its blob may be persisted. Votes resolve
                    // against provider bonds, not DNS stake bonds — see the ctx doc for why this refines
                    // §5.17.2's scaffold wording.
                    //
                    // **Evaluated at the AUDIT-BEACON EPOCH's snapshot, not at inclusion time** (§5.17.2 /
                    // §12′). Eligibility freezes at selection: evaluating at this block's DAA would let an
                    // attacker holding a certificate include it just after an honest auditor's bond lapses,
                    // invalidating that vote. The epoch is the certificate's committed field, covered by
                    // every vote's `signing_hash`, so it cannot be re-aimed after the votes are collected.
                    //
                    // **The audit-epoch seed** `R_{audit_beacon_epoch − 1}` is resolved by the buried
                    // selected-parent walk (§5.17.3), a pure function of `(headers, reachability)`;
                    // unresolvable ⇒ the verifier FAILS CLOSED, kept sound by the bounded inclusion window.
                    // Resolved only for a Certificate (the only effect that carries `audit_beacon_epoch`).
                    let (snapshot_daa, prev_seed) = match &effect {
                        crate::processes::palw::PalwOverlayEffect::Certificate(c) => (
                            c.audit_beacon_epoch.saturating_mul(epoch_len),
                            crate::processes::palw::resolve_palw_audit_epoch_seed(
                                &self.headers_store,
                                &self.reachability_service,
                                selected_parent,
                                self.palw_activation_daa_score,
                                self.palw_epoch_length_daa,
                                c.audit_beacon_epoch,
                            ),
                        ),
                        _ => (cur_daa, None),
                    };
                    let attest = crate::processes::palw::PalwCertificateAttestationCtx {
                        network_id: self.palw_network_id,
                        pov_daa_score: snapshot_daa,
                        provider_bond_view: selected_parent_provider_bond_view,
                        prev_seed,
                        inclusion_epoch,
                        inclusion_window_epochs,
                        committee_size: self.palw_audit_committee_size as usize,
                        sample_size: self.palw_audit_sample_size as u32,
                        quorum_num: self.palw_audit_quorum_num,
                        quorum_den: self.palw_audit_quorum_den,
                    };
                    let _ =
                        crate::processes::palw::apply_palw_overlay_effect(effect, &*self.palw_store, &self.palw_beacon_store, Some(&attest));
                }
            }
        }
    }

    /// ADR-0039 §11.2 — derive (or carry) this chain block's active beacon seed `R_E` and persist it
    /// keyed by `current` (block-keyed recurrence, like `reserve_balance`). Every block carries its
    /// selected parent's active state; the FIRST block of a new PALW epoch (its DAA epoch exceeds the
    /// parent's) re-derives the seed from the epoch's accumulated commits/reveals via
    /// [`derive_beacon_epoch_state`]. The write goes into the commit `WriteBatch` (atomic with the UTXO
    /// diff).
    ///
    /// **Inert on every currently activated preset** (`palw_activation_daa_score == u64::MAX`): the
    /// fast-path returns before any store read. On a PALW hard-fork/re-genesis network, commits and
    /// reveals are accumulated in a block-keyed selected-parent view, commit-time DNS stake is frozen,
    /// DNS health is recomputed from the parent's canonical attestation window, and the full resulting
    /// state is committed by Header-v3's `overlay_commitment_root` in descendants.
    /// ADR-0039 C6 SLICE 2 — derive this block's OWN beacon state `R_E`, as a pure, deterministic
    /// function reused by both the commit path (which persists it + advances the accumulator) and the
    /// UTXO-validation path (which authenticates `header.palw_beacon_seed` against it). Returns `None`
    /// when there is no state to derive (inert / pre-activation / the genesis block, whose accumulator
    /// the commit path seeds empty). Identical `(current, selected_parent_bond_view)` ⇒ identical result
    /// on every node — this is what makes the retained `palw_beacon_seed` field trustworthy, so a
    /// descendant may read a buried anchor's `R_E` from its header for the clause-9 draw. Reads the
    /// selected parent's accumulator + carried state, both present here (virtual stage, chain block).
    pub(super) fn derive_palw_beacon_state_value(
        &self,
        current: BlockHash,
        selected_parent_bond_view: &ActiveBondView,
    ) -> Option<kaspa_consensus_core::palw::PalwBeaconStateV1> {
        if self.palw_activation_daa_score == u64::MAX {
            return None; // inert fast path
        }
        let cur_daa = self.headers_store.get_daa_score(current).unwrap();
        // The genesis block seeds only an empty accumulator (no carried state to derive from).
        if cur_daa < self.palw_activation_daa_score || current == self.genesis.hash {
            return None;
        }
        let selected_parent = self.ghostdag_store.get_selected_parent(current).unwrap();
        self.derive_palw_beacon_state_core(cur_daa, selected_parent, current, selected_parent_bond_view)
    }

    /// The pure derivation body of [`Self::derive_palw_beacon_state_value`], with `(cur_daa,
    /// selected_parent)` supplied by the caller instead of resolved from a stored `current` block.
    /// Two callers share it, which is what makes `palw_beacon_seed` construction == validation:
    ///   - the validation/commit path calls `derive_palw_beacon_state_value(current, …)`, which reads
    ///     `cur_daa`/`selected_parent` off the already-stored block, then delegates here;
    ///   - the mining template (`build_block_template`) calls this directly with `virtual_state.daa_score`
    ///     and `virtual_state.ghostdag_data.selected_parent` — both known BEFORE the block (hence its
    ///     hash) exists, so it can stamp the derived seed into the header it is assembling.
    /// A block mined from that template has exactly those `(daa_score, selected_parent)` (GHOSTDAG is
    /// deterministic over the parent set), and the same selected-parent bond view, so the seed the
    /// template stamps equals the seed S2 validation re-derives. `current_label` is used only for panic
    /// messages. The sole entry points are both gated on `palw_activation_daa_score` (the template call
    /// is additionally behind `version >= PALW_HEADER_VERSION`), which makes this INERT on mainnet /
    /// testnet-10 / simnet / devnet — but NOT on `testnet-palw-110` / `devnet-palw-111`, whose fence is
    /// 0 (`config/params.rs:1403`, `:1454`), where it is reached on every chain block.
    pub(super) fn derive_palw_beacon_state_core(
        &self,
        cur_daa: u64,
        selected_parent: BlockHash,
        current_label: BlockHash,
        selected_parent_bond_view: &ActiveBondView,
    ) -> Option<kaspa_consensus_core::palw::PalwBeaconStateV1> {
        use crate::model::stores::palw_beacon::PalwBeaconAccumViewV1;
        use kaspa_consensus_core::palw::derive_beacon_epoch_state;
        let epoch_len = self.palw_epoch_length_daa.max(1);
        let sp_daa = self.headers_store.get_daa_score(selected_parent).unwrap_or(0);
        let epoch_cur = cur_daa / epoch_len;

        let parent_view = match self.palw_beacon_store.accum_view(selected_parent).unwrap() {
            Some(view) => (*view).clone(),
            None if sp_daa < self.palw_activation_daa_score || selected_parent == self.genesis.hash => PalwBeaconAccumViewV1::new(),
            None => panic!("missing fork-local PALW beacon accumulator for active selected parent {selected_parent}"),
        };
        let prev = self.palw_beacon_store.beacon_state(selected_parent).unwrap();
        if prev.as_ref().is_some_and(|s| s.epoch > epoch_cur) {
            panic!("PALW beacon epoch regressed at {current_label}: parent state is ahead of current DAA epoch");
        }

        // Derive on an epoch boundary (or the first PALW block, which has no carried parent state); else
        // carry the parent's active state forward unchanged. Crucially, derivation reads the PARENT
        // view before this block's effects are applied, so an R_E boundary block cannot influence R_E.
        //
        // A wide mergeset can advance DAA by more than one PALW epoch in a single block. The seed is a
        // hash chain (`R_E = f(R_{E-1}, …)`), so every skipped epoch MUST be replayed in ascending order
        // rather than jumping straight to `epoch_cur` — otherwise the intermediate epochs' accumulated
        // commits/reveals are silently dropped by `retain_future_of` below without ever entering the
        // chain, and the recurrence no longer matches §11.2. The replay reads each epoch's own inputs
        // and stake snapshot from the parent view (still intact here — `retain_future_of` runs only
        // after), and threads `seed`/`degraded_epochs` through each step so the grace recurrence is
        // likewise exact. The loop is bounded: a block's DAA increment is bounded by its mergeset, so
        // `epoch_cur - prev.epoch` is small.
        let state = if prev.as_ref().is_none_or(|s| epoch_cur > s.epoch) {
            let (newly_confirmed_anchor, dns_healthy) = self.palw_dns_confirmation(selected_parent, selected_parent_bond_view);
            // DNS confirmation is monotonic along this fork-local selected-parent chain. If the
            // newest lag-ready candidate has not accumulated both depths yet, retain the parent's
            // previously confirmed anchor rather than feeding an unconfirmed candidate into R_E.
            //
            // Carry rule (§12.1 clause-6 freeze, panel F3): the anchor FACTS are recomputed only when
            // the confirmed anchor ADVANCES; while it is unchanged the parent's frozen facts are
            // carried verbatim. The facts are anchor-pure (same anchor ⇒ same facts), so this is a
            // determinism-preserving optimization that also avoids re-reading the anchor header at
            // every boundary of a long-lived anchor.
            let dns_anchor = match (newly_confirmed_anchor, prev.as_ref()) {
                (Some(fresh), prev_state) if prev_state.is_none_or(|s| s.dns_anchor != fresh.hash) => fresh,
                (_, Some(s)) if s.dns_anchor != kaspa_hashes::Hash64::default() => s.anchor(),
                _ => kaspa_consensus_core::palw::BeaconDnsAnchor::UNCONFIRMED,
            };
            let dns_healthy = dns_healthy && dns_anchor.is_confirmed();
            // Every replayed epoch folds in THIS block's selected-parent DNS confirmation. A skipped
            // epoch has no distinct confirmation snapshot to recover (the anchor is only resolvable from
            // a block's own POV), and reusing one deterministic, already-lagged+confirmed anchor keeps
            // the chain identical on every node while granting no extra grinding freedom — the skipped
            // epochs' commit/reveal sets were fixed in the parent view before this block existed.
            let mut seed = prev.as_ref().map(|s| s.seed).unwrap_or_default();
            let mut degraded = prev.as_ref().map(|s| s.degraded_epochs).unwrap_or(0);
            // No carried state ⇒ this is the first PALW block: derive only its own epoch.
            let first_epoch = prev.as_ref().map(|s| s.epoch + 1).unwrap_or(epoch_cur);
            let mut replayed = None;
            for epoch in first_epoch..=epoch_cur {
                let step = derive_beacon_epoch_state(
                    epoch,
                    &seed,
                    &dns_anchor,
                    &parent_view.epoch_inputs(epoch),
                    dns_healthy,
                    degraded,
                    self.palw_beacon_grace_epochs,
                    self.palw_beacon_quorum_num,
                    self.palw_beacon_quorum_den,
                    |bond| parent_view.stake_of(epoch, bond),
                );
                seed = step.seed;
                degraded = step.degraded_epochs;
                replayed = Some(step);
            }
            replayed.expect("epoch range is non-empty: first_epoch <= epoch_cur")
        } else {
            (*prev.unwrap()).clone()
        };
        Some(state)
    }

    fn commit_palw_beacon_state(
        &self,
        batch: &mut WriteBatch,
        current: BlockHash,
        acceptance_data: &AcceptanceData,
        selected_parent_bond_view: &ActiveBondView,
    ) {
        use crate::model::stores::palw_beacon::PalwBeaconAccumViewV1;
        if self.palw_activation_daa_score == u64::MAX {
            return; // inert fast path
        }
        let cur_daa = self.headers_store.get_daa_score(current).unwrap();
        if cur_daa < self.palw_activation_daa_score {
            return;
        }

        // A genesis-active PALW re-genesis has no selected parent. Seed only the fork-local
        // accumulator here; the first child derives the initial epoch state from this empty view.
        if current == self.genesis.hash {
            self.palw_beacon_store.set_accum_view_batch(batch, current, Arc::new(PalwBeaconAccumViewV1::new())).unwrap();
            return;
        }

        let selected_parent = self.ghostdag_store.get_selected_parent(current).unwrap();
        let epoch_len = self.palw_epoch_length_daa.max(1);
        let sp_daa = self.headers_store.get_daa_score(selected_parent).unwrap_or(0);
        let epoch_cur = cur_daa / epoch_len;

        // The block's OWN beacon state (the same derivation UTXO validation authenticates the header
        // `palw_beacon_seed` against — construction == validation).
        let state = self
            .derive_palw_beacon_state_value(current, selected_parent_bond_view)
            .expect("a non-genesis active block has a derivable beacon state");
        self.palw_beacon_store.set_state_batch(batch, current, Arc::new(state)).unwrap();

        // Only after R_E is frozen do this block's accepted E-2/E-1 operations enter the child view.
        let mut next_view = match self.palw_beacon_store.accum_view(selected_parent).unwrap() {
            Some(view) => (*view).clone(),
            None if sp_daa < self.palw_activation_daa_score || selected_parent == self.genesis.hash => PalwBeaconAccumViewV1::new(),
            None => panic!("missing fork-local PALW beacon accumulator for active selected parent {selected_parent}"),
        };
        next_view.retain_future_of(epoch_cur);
        self.apply_palw_beacon_effects(&mut next_view, acceptance_data, selected_parent_bond_view, cur_daa);
        self.palw_beacon_store.set_accum_view_batch(batch, current, Arc::new(next_view)).unwrap();
    }

    /// Apply accepted beacon operations to a selected-parent-carried accumulator. Invalid contextual
    /// operations are fee-paying no-ops: they never enter R_E, but also do not invalidate an otherwise
    /// valid UTXO transaction. Every decision is past-relative to `selected_parent_bond_view`.
    fn apply_palw_beacon_effects(
        &self,
        view: &mut crate::model::stores::palw_beacon::PalwBeaconAccumViewV1,
        acceptance_data: &AcceptanceData,
        selected_parent_bond_view: &ActiveBondView,
        current_daa: u64,
    ) {
        use crate::processes::palw::PalwOverlayEffect;
        use kaspa_consensus_core::palw::PALW_BEACON_MLDSA87_CONTEXT;

        // §11.2 phase coordinate — FROZEN: the commit/reveal lead (`E-2` / `E-1`) is measured against the
        // UTXO **acceptance** epoch (this chain block's own DAA epoch), never the carrier block's.
        // Rationale, and why the alternative is not merely unimplemented but unsafe from here:
        //  * Determinism / c==v: the acceptance epoch is a function of THIS block's DAA score, so the
        //    template and validation paths derive it identically from the one selected-parent POV.
        //  * Carrier-block semantics would require a per-mergeset-source, block-keyed bond view AND
        //    outcome to validate each source's signature/bond at ITS own epoch — not obtainable from a
        //    single POV, so it cannot be made deterministic here.
        //  * Security is unaffected: `is_in_phase` pins `target == accept_epoch + lead` EXACTLY, so a
        //    withheld or early tx is dropped rather than retargeted. A miner choosing when to include a
        //    commit can therefore only censor it (a pre-existing, general property) — never re-aim it at
        //    a different epoch, so no grinding freedom is gained.
        //  * Consistency: identical coordinate to every other `acceptance_data`-driven overlay (DNS
        //    attestations, slashing).
        let current_epoch = current_daa / self.palw_epoch_length_daa.max(1);
        for merged in acceptance_data {
            let txs = self
                .block_transactions_store
                .get(merged.block_hash)
                .unwrap_or_else(|e| panic!("accepted PALW beacon body {} is unavailable: {e}", merged.block_hash));
            for entry in &merged.accepted_transactions {
                let tx = txs.get(entry.index_within_block as usize).unwrap_or_else(|| {
                    panic!("accepted PALW transaction index {} is outside block {}", entry.index_within_block, merged.block_hash)
                });
                let Some(kind) = tx.subnetwork_id.palw_tx_kind() else { continue };
                let effect = crate::processes::palw::parse_palw_overlay(kind, &tx.payload)
                    .unwrap_or_else(|e| panic!("isolation-admitted PALW payload failed contextual decode: {e:?}"));
                match effect {
                    PalwOverlayEffect::BeaconCommit(commit) => {
                        if !commit.is_in_phase(current_epoch) {
                            continue;
                        }
                        let Some(bond) = selected_parent_bond_view.active_bond_at(&commit.bond_outpoint, current_daa) else {
                            continue;
                        };
                        let digest = commit.signing_hash(self.palw_network_id);
                        if !matches!(
                            verify_mldsa87_with_context(
                                &bond.validator_pubkey,
                                &digest.as_bytes(),
                                &commit.signature,
                                PALW_BEACON_MLDSA87_CONTEXT,
                            ),
                            Ok(true)
                        ) {
                            continue;
                        }
                        view.record_commit(commit.epoch, commit.bond_outpoint, commit.commitment, bond.amount);
                    }
                    PalwOverlayEffect::BeaconReveal(reveal) => {
                        if !reveal.is_in_phase(current_epoch) {
                            continue;
                        }
                        let Some(bond) = selected_parent_bond_view.active_bond_at(&reveal.bond_outpoint, current_daa) else {
                            continue;
                        };
                        let Some(commitment) = view.commitment_of(reveal.epoch, &reveal.bond_outpoint) else {
                            continue;
                        };
                        if !reveal.matches_commit(&commitment) {
                            continue;
                        }
                        let digest = reveal.signing_hash(self.palw_network_id);
                        if !matches!(
                            verify_mldsa87_with_context(
                                &bond.validator_pubkey,
                                &digest.as_bytes(),
                                &reveal.signature,
                                PALW_BEACON_MLDSA87_CONTEXT,
                            ),
                            Ok(true)
                        ) {
                            continue;
                        }
                        view.record_valid_reveal(reveal.epoch, reveal.bond_outpoint, reveal.entropy_digest());
                    }
                    _ => {}
                }
            }
        }
    }

    /// Resolve the newest DNS-confirmed anchor and current health from the selected parent's own
    /// chain window and bond view. This deliberately does not read the virtual-tip `DnsState`
    /// singleton: both work depth and stake depth are re-derived at this block POV, and a lag-ready
    /// candidate is returned only after it clears the same two confirmation thresholds.
    fn palw_dns_confirmation(
        &self,
        selected_parent: BlockHash,
        selected_parent_bond_view: &ActiveBondView,
    ) -> (Option<kaspa_consensus_core::palw::BeaconDnsAnchor>, bool) {
        use kaspa_consensus_core::dns_finality::DnsHealth;

        let Some(params) = self.dns_params.as_ref() else { return (None, false) };
        let Some(candidate) = self.palw_lagged_dns_anchor_candidate(selected_parent) else { return (None, false) };
        let dns_anchor = candidate.anchor_hash;
        let sp_daa = self.headers_store.get_daa_score(selected_parent).unwrap();
        let bonds = selected_parent_bond_view.records();
        let active_stakes: Vec<u64> = bonds.iter().filter(|b| is_bond_active_at(b, sp_daa)).map(|b| b.amount).collect();
        let total_active = active_stakes.iter().fold(0u64, |sum, stake| sum.saturating_add(*stake));
        let active_validators = active_stakes.len() as u32;
        let hard_mandatory_active = sp_daa >= params.mandatory_attestation_inclusion_daa_score;
        let capacity = mandatory_attestation_mass_capacity(
            active_stakes.iter().copied(),
            total_active,
            0,
            params.stake_event_quality_floor_bps,
            self.max_block_mass,
            params.max_attestation_shard_mass,
        );
        let overlay_active = sp_daa >= params.dns_activation_daa_score
            && total_active >= params.min_active_stake_sompi
            && active_validators >= params.min_active_validators
            && params.dns_v3_params_consistent()
            && (!hard_mandatory_active || capacity.fits);
        if !overlay_active {
            return (None, false);
        }

        let (contributions, epoch_anchor_daa, _) =
            self.collect_stake_contributions_v2(selected_parent, None, &bonds, self.genesis.hash.as_byte_slice(), params);
        let totals = total_active_stake_by_epoch(&bonds, &epoch_anchor_daa);
        let per_epoch = aggregate_epoch_tallies(&contributions, &totals);
        let stake_depth = compute_stake_score(&per_epoch, params.stake_event_quality_floor_bps);
        // Both hashes are reachable selected-chain blocks. Missing/corrupt work is a consensus DB
        // failure, never zero: defaulting the anchor to zero would inflate work depth and let one
        // node alone classify an unconfirmed candidate as DNS-confirmed inside the v3 commitment.
        let selected_parent_work = self
            .ghostdag_store
            .get_blue_work(selected_parent)
            .unwrap_or_else(|err| panic!("failed reading blue work for PALW selected parent {selected_parent}: {err}"));
        let anchor_work = self
            .ghostdag_store
            .get_blue_work(dns_anchor)
            .unwrap_or_else(|err| panic!("failed reading blue work for PALW DNS anchor {dns_anchor}: {err}"));
        let work_depth = selected_parent_work.saturating_sub(anchor_work);
        let confirmed = is_dns_confirmed(work_depth, stake_depth, params.required_work_depth, params.required_stake_depth);
        let healthy = derive_dns_health(
            &per_epoch,
            params.stake_event_quality_floor_bps,
            params.stake_censorship_floor_bps,
            params.degraded_stake_quality_epochs,
            true,
        ) == DnsHealth::Active;
        // §12.1 clause-6 facts: every field is a frozen property of the ANCHOR BLOCK itself (its own
        // header-committed coordinates + overlay root), never of the boundary-time view — so the
        // certificate digest cannot be ground by boundary producers (panel F1/F2). The anchor header
        // is a confirmed selected-chain ancestor within the lag window, so it is retained.
        let facts = confirmed.then(|| {
            let anchor_header = self
                .headers_store
                .get_header(dns_anchor)
                .unwrap_or_else(|err| panic!("failed reading header for confirmed PALW DNS anchor {dns_anchor}: {err}"));
            kaspa_consensus_core::palw::BeaconDnsAnchor {
                hash: dns_anchor,
                blue_score: candidate.anchor_blue_score,
                daa_score: candidate.anchor_daa_score,
                overlay_root: anchor_header.overlay_commitment_root,
            }
        });
        (facts, healthy)
    }

    /// The newest lag-ready DNS anchor candidate as-of `selected_parent`. This is not itself a
    /// confirmation decision; [`Self::palw_dns_confirmation`] additionally requires both work and
    /// stake depth before the candidate may enter the PALW beacon recurrence.
    fn palw_lagged_dns_anchor_candidate(&self, selected_parent: BlockHash) -> Option<CanonicalLaggedEpochAnchor> {
        let dns_params = self.dns_params.as_ref()?;
        let sp_blue = self.headers_store.get_blue_score(selected_parent).ok()?;
        let epoch_len = dns_params.attestation_epoch_length_blue_score.max(1);
        let lag = dns_params.attestation_lag_blue_score;
        let dns_epoch = kaspa_consensus_core::dns_finality::ready_epoch_from_tip_blue_score(sp_blue, epoch_len, lag)?;
        // Forward the FULL anchor record — clause 6's certificate digest needs the anchor's own
        // coordinates, not just its hash (panel Q3/storage-(ii) resolution).
        self.canonical_anchor_by_blue_score(dns_epoch, selected_parent, dns_params)
    }

    fn calculate_and_commit_virtual_state(
        &self,
        virtual_read: RwLockUpgradableReadGuard<'_, VirtualStores>,
        virtual_parents: Vec<BlockHash>,
        virtual_ghostdag_data: GhostdagData,
        selected_parent_multiset: MuHash,
        accumulated_diff: &mut UtxoDiff,
        // kaspa-pq Phase 10/11 (ADR-0016 §D.4): the bond set as-of the virtual
        // selected parent, walked in lockstep with `accumulated_diff`. Forwarded
        // to `calculate_virtual_state`/`calculate_utxo_state` for the slashing
        // side-effect; inert until PR-16.4-b2 consumes it.
        selected_parent_bond_view: &ActiveBondView,
        // ADR-0040 ECON-03 (THE WIRE): the provider-bond registry as-of the virtual selected parent.
        selected_parent_provider_bond_view: &ProviderBondView,
        chain_path: &ChainPath,
    ) -> Result<Arc<VirtualState>, RuleError> {
        let new_virtual_state = self.calculate_virtual_state(
            &virtual_read,
            virtual_parents,
            virtual_ghostdag_data,
            selected_parent_multiset,
            accumulated_diff,
            selected_parent_bond_view,
            selected_parent_provider_bond_view,
        )?;
        self.commit_virtual_state(virtual_read, new_virtual_state.clone(), accumulated_diff, chain_path);
        Ok(new_virtual_state)
    }

    pub(super) fn calculate_virtual_state(
        &self,
        virtual_stores: &VirtualStores,
        virtual_parents: Vec<BlockHash>,
        virtual_ghostdag_data: GhostdagData,
        selected_parent_multiset: MuHash,
        accumulated_diff: &mut UtxoDiff,
        // kaspa-pq Phase 10/11 (ADR-0016 §D.4): the bond set as-of the virtual
        // selected parent (= the new sink). Forwarded to `calculate_utxo_state`
        // for the slashing side-effect; inert until PR-16.4-b2 consumes it.
        selected_parent_bond_view: &ActiveBondView,
        // ADR-0040 ECON-03 (THE WIRE): forwarded to `calculate_utxo_state` so a virtual-state recompute
        // classifies provider collateral from the identical view a block validation does.
        selected_parent_provider_bond_view: &ProviderBondView,
    ) -> Result<Arc<VirtualState>, RuleError> {
        let selected_parent_utxo_view = (&virtual_stores.utxo_set).compose(&*accumulated_diff);
        let mut ctx = UtxoProcessingContext::new((&virtual_ghostdag_data).into(), selected_parent_multiset);

        // Calc virtual DAA score, difficulty bits and past median time
        let virtual_daa_window = self.window_manager.block_daa_window(&virtual_ghostdag_data)?;
        let virtual_bits = self.window_manager.calculate_difficulty_bits(&virtual_ghostdag_data, &virtual_daa_window);
        let virtual_past_median_time = self.window_manager.calc_past_median_time(&virtual_ghostdag_data)?.0;

        // Calc virtual UTXO state relative to selected parent
        self.calculate_utxo_state(
            &mut ctx,
            &selected_parent_utxo_view,
            selected_parent_bond_view,
            selected_parent_provider_bond_view,
            virtual_daa_window.daa_score,
        );

        // Update the accumulated diff
        accumulated_diff.with_diff_in_place(&ctx.mergeset_diff).unwrap();

        // Build the new virtual state
        Ok(Arc::new(VirtualState::new(
            virtual_parents,
            virtual_daa_window.daa_score,
            virtual_bits,
            virtual_past_median_time,
            ctx.multiset_hash,
            ctx.mergeset_diff,
            ctx.accepted_tx_ids,
            ctx.mergeset_rewards,
            virtual_daa_window.mergeset_non_daa,
            virtual_ghostdag_data,
        )))
    }

    fn commit_virtual_state(
        &self,
        virtual_read: RwLockUpgradableReadGuard<'_, VirtualStores>,
        new_virtual_state: Arc<VirtualState>,
        accumulated_diff: &UtxoDiff,
        chain_path: &ChainPath,
    ) {
        let mut batch = WriteBatch::default();
        let mut virtual_write = RwLockUpgradableReadGuard::upgrade(virtual_read);
        let mut selected_chain_write = self.selected_chain_store.write();

        // Apply the accumulated diff to the virtual UTXO set
        virtual_write.utxo_set.write_diff_batch(&mut batch, accumulated_diff).unwrap();

        // Update virtual state (capture the new sink first — `set_batch` moves the Arc).
        let dns_sink = new_virtual_state.ghostdag_data.selected_parent;
        virtual_write.state.set_batch(&mut batch, new_virtual_state).unwrap();

        // Update the virtual selected chain
        selected_chain_write.apply_changes(&mut batch, chain_path).unwrap();

        // kaspa-pq Phase 10 (ADR-0009 A.4): stage the DNS stake-bond set
        // changes into the same batch so they commit atomically with the
        // virtual state. Inert unless the overlay is configured.
        self.stage_dns_bond_mutations(&mut batch, chain_path);
        // ADR-0040 ECON-03 (THE WIRE): the PALW provider-bond registry moves in the SAME batch and by
        // the same detach-before-attach rule, so the persisted registry and the selected chain can
        // never be committed out of step. Inert while PALW is fenced.
        self.stage_palw_provider_bond_mutations(&mut batch, chain_path);

        // kaspa-pq Phase 10 (ADR-0009 A.5): recompute the DNS StakeScore over
        // the bounded recent epoch window and stage the updated DnsState into
        // the same batch. Inert unless the overlay is configured.
        self.update_dns_state(&mut batch, dns_sink);

        // kaspa-pq EVM Lane v0.4 (§10 / invariant I3): a virtual change only
        // MOVES the canonical EVM head pointers — no execution happens here.
        self.update_evm_canonical_heads(&mut batch, dns_sink);

        // kaspa-pq EVM Lane v0.4 (§16 RPC / canonical-index fix): the canonical
        // `evm_number → L1 hash` map follows the selected chain (detach/attach),
        // not per-block result-commit — so a sink-search loser can't shadow it.
        self.update_evm_canonical_number_map(&mut batch, chain_path);

        // kaspa-pq ADR-0018 "本格版" (PoS-v2, Phase 1): recompute the per-epoch
        // accumulator over the bounded selected-chain window ending at the new
        // sink and stage it into the same batch. Inert below the v2 fence
        // (`pos_v2_activation_daa_score`, `u64::MAX` today) — returns after a
        // single header read on every current network.
        self.update_epoch_accumulator(&mut batch, dns_sink);

        // Flush the batch changes
        self.db.write(batch).unwrap();

        // Calling the drops explicitly after the batch is written in order to avoid possible errors.
        drop(virtual_write);
        drop(selected_chain_write);
    }

    /// kaspa-pq Phase 10 (ADR-0009 Addendum A.4): stage the `StakeBonds`-store
    /// mutations implied by this selected-chain change into `batch`, so they
    /// commit atomically with the virtual state. **Inert** unless the DNS
    /// overlay is configured (`dns_params.is_some()`) — on every current
    /// network this is a single `Option` check and a return.
    ///
    /// Mirrors the UTXO reorg model: blocks leaving the selected chain
    /// (`chain_path.removed`) are reverted, most-recent first, **before**
    /// blocks joining it (`chain_path.added`) are applied. Within a block,
    /// `Insert` reverts by delete and `Slash` by clearing `slashed_at`; a
    /// `Slash` revert whose bond record is already gone (its `Insert` was
    /// reverted in the same range) is skipped gracefully. Acceptance data is
    /// retained on reorg (only pruning deletes it), so removed blocks can be
    /// re-derived deterministically.
    /// kaspa-pq **ADR-0040 ECON-03 (THE WIRE) — the registry WRITER for prefix 241.**
    ///
    /// Stages the `PalwProviderBond`-store mutations implied by this selected-chain change into
    /// `batch`, so they commit atomically with the virtual state. Transposed from
    /// [`Self::stage_dns_bond_mutations`], with the same detach-before-attach order: blocks LEAVING
    /// the selected chain are reverted (most-recent first, and within a block in reverse tx order)
    /// BEFORE blocks joining it are applied.
    ///
    /// **Order independence.** Apply and revert are exact inverses here for the same structural reason
    /// they are in [`ProviderBondView`]: `Insert` reverts by delete, `Unbond`/`Slash` revert by
    /// clearing the single DAA stamp they set, and there is no mutable `status` field to restore to a
    /// guessed value (the DNS precedent's `status = Active` on a slash-revert is exactly the
    /// non-inverse this record type was designed without — see `PalwProviderBondRecord`). Two nodes
    /// reaching the same sink by different reorg paths therefore hold byte-identical rows, which is
    /// what makes it safe for the reward path to read a view seeded from here.
    ///
    /// **Inert** while PALW is fenced (`palw_activation_daa_score == u64::MAX` — mainnet, testnet-10,
    /// simnet, devnet): a single `u64` compare and a return, so no row is written there and the batch
    /// is byte-identical to before this writer existed. On `testnet-palw-110` / `devnet-palw-111` the
    /// fence is 0 and this RUNS: provider-bond (`0x30`) and provider-unbond (`0x37`) transactions are
    /// ordinary txs, so `palw_algo4_accept = false` does not suppress them.
    fn stage_palw_provider_bond_mutations(&self, batch: &mut WriteBatch, chain_path: &ChainPath) {
        if self.palw_activation_daa_score == u64::MAX {
            return;
        }
        let mut store = self.palw_provider_bonds_store.write();

        // Revert blocks that left the selected chain (most-recent first, reverse tx order within).
        for removed in chain_path.removed.iter().rev().copied() {
            for mutation in self.palw_provider_bond_mutations_for_chain_block(removed).into_iter().rev() {
                match mutation {
                    PalwProviderBondMutation::Insert(outpoint, _) => {
                        store.delete_batch(batch, outpoint).unwrap();
                    }
                    PalwProviderBondMutation::Unbond(outpoint, _) => {
                        if let Ok(record) = store.get(&outpoint) {
                            let mut record = (*record).clone();
                            record.unbond_request_daa_score = None;
                            store.insert_batch(batch, outpoint, Arc::new(record)).unwrap();
                        }
                    }
                    PalwProviderBondMutation::Slash(outpoint, _) => {
                        if let Ok(record) = store.get(&outpoint) {
                            let mut record = (*record).clone();
                            record.slashed_at_daa_score = None;
                            store.insert_batch(batch, outpoint, Arc::new(record)).unwrap();
                        }
                    }
                }
            }
        }

        // Apply blocks that joined the selected chain (in chain order, tx order within).
        for added in chain_path.added.iter().copied() {
            for mutation in self.palw_provider_bond_mutations_for_chain_block(added) {
                match mutation {
                    PalwProviderBondMutation::Insert(outpoint, record) => {
                        store.insert_batch(batch, outpoint, Arc::new(record)).unwrap();
                    }
                    PalwProviderBondMutation::Unbond(outpoint, daa) => {
                        if let Ok(record) = store.get(&outpoint) {
                            let mut record = (*record).clone();
                            record.unbond_request_daa_score = Some(daa);
                            store.insert_batch(batch, outpoint, Arc::new(record)).unwrap();
                        }
                    }
                    PalwProviderBondMutation::Slash(outpoint, daa) => {
                        if let Ok(record) = store.get(&outpoint) {
                            let mut record = (*record).clone();
                            record.slashed_at_daa_score = Some(daa);
                            store.insert_batch(batch, outpoint, Arc::new(record)).unwrap();
                        }
                    }
                }
            }
        }
    }

    fn stage_dns_bond_mutations(&self, batch: &mut WriteBatch, chain_path: &ChainPath) {
        if self.dns_params.is_none() {
            return;
        }
        let mut store = self.stake_bonds_store.write();

        // Revert blocks that left the selected chain (most-recent first).
        for removed in chain_path.removed.iter().rev().copied() {
            for mutation in self.dns_bond_mutations_for_chain_block(removed).into_iter().rev() {
                match mutation {
                    BondMutation::Insert(outpoint, _) => {
                        store.delete_batch(batch, outpoint).unwrap();
                    }
                    BondMutation::Slash(outpoint, _) => {
                        if let Ok(record) = store.get(&outpoint) {
                            let mut record = (*record).clone();
                            record.slashed_at_daa_score = None;
                            record.status = BondStatus::Active;
                            store.insert_batch(batch, outpoint, Arc::new(record)).unwrap();
                        }
                    }
                    // kaspa-pq H-05: revert an unbond request (clear the unbond clock).
                    BondMutation::Unbond(outpoint, _) => {
                        if let Ok(record) = store.get(&outpoint) {
                            let mut record = (*record).clone();
                            record.unbond_request_daa_score = None;
                            store.insert_batch(batch, outpoint, Arc::new(record)).unwrap();
                        }
                    }
                }
            }
        }

        // Apply blocks that joined the selected chain (in chain order).
        for added in chain_path.added.iter().copied() {
            for mutation in self.dns_bond_mutations_for_chain_block(added) {
                match mutation {
                    BondMutation::Insert(outpoint, record) => {
                        store.insert_batch(batch, outpoint, Arc::new(record)).unwrap();
                    }
                    BondMutation::Slash(outpoint, daa) => {
                        if let Ok(record) = store.get(&outpoint) {
                            let mut record = (*record).clone();
                            record.slashed_at_daa_score = Some(daa);
                            record.status = BondStatus::Slashed;
                            store.insert_batch(batch, outpoint, Arc::new(record)).unwrap();
                        }
                    }
                    // kaspa-pq H-05: apply an accepted unbond request (start the unbond clock).
                    BondMutation::Unbond(outpoint, daa) => {
                        if let Ok(record) = store.get(&outpoint) {
                            let mut record = (*record).clone();
                            record.unbond_request_daa_score = Some(daa);
                            store.insert_batch(batch, outpoint, Arc::new(record)).unwrap();
                        }
                    }
                }
            }
        }
    }

    /// Seeds the per-block [`ActiveBondView`] walk (ADR-0009 Addendum B §B.1)
    /// from the `StakeBonds` store snapshot — which, at the start of
    /// `resolve_virtual`, reflects the bond set as-of the previous sink (the
    /// same anchor `accumulated_diff` starts from). Returns an empty view on
    /// networks without the overlay (`dns_params` is `None`), so the bond-view
    /// walk is a no-op there.
    pub(crate) fn initial_active_bond_view(&self) -> ActiveBondView {
        if self.dns_params.is_none() {
            return ActiveBondView::new();
        }
        ActiveBondView::from_records(
            self.stake_bonds_store.read().iterator().filter_map(|r| r.ok().map(|(_, rec)| (rec.bond_outpoint, (*rec).clone()))),
        )
    }

    /// kaspa-pq **ADR-0040 ECON-03 (THE WIRE) — where provider-collateral resolution lives, and why.**
    ///
    /// Seeds the per-block [`ProviderBondView`] walk from the `PalwProviderBond` store (prefix 241),
    /// which at the start of `resolve_virtual` reflects the registry as-of the previous sink — the
    /// same anchor `accumulated_diff` and the DNS `ActiveBondView` start from.
    ///
    /// ## The coordinate decision (stated, per the ECON-03 brief)
    ///
    /// Resolution needs a POINT OF VIEW: "is this bond active?" is a question about a DAA score along
    /// a particular chain. There were two candidate coordinates and only one is admissible:
    ///
    /// * **Body / mergeset** (`validate_public_leaf`, where `provider_a_bond != provider_b_bond` is
    ///   checked today) — REJECTED. That validator is context-free by construction; BIND-03 settled
    ///   that the batch view stays at the body coordinate and that body validity must not read
    ///   point-of-view state. Resolving there would also make leaf admission depend on a bond's live
    ///   status, so an unbond timed by a third party could invalidate an already-accepted batch.
    /// * **Reward / virtual** (`palw_work_reward_class`, in `calculate_utxo_state`) — CHOSEN. It
    ///   already reads the leaf, it already has `pov_daa_score`, acceptance data lives here, and it is
    ///   the single seam shared by coinbase construction and validation, so c == v holds structurally
    ///   rather than by two matching copies. It is also the coordinate where the failure mode is
    ///   proportionate: withholding a payout, not bricking a block.
    ///
    /// So `validate_public_leaf` KEEPS its distinctness check — a pure shape rule, and still the only
    /// thing it can honestly assert — and the resolution is layered on top at the reward coordinate.
    /// The distinctness check is no longer load-bearing for the economics; it merely stops a leaf from
    /// naming one bond twice, which would otherwise let a single bond back both halves of a pair.
    ///
    /// Returns an empty view while PALW is fenced (`palw_activation_daa_score == u64::MAX`: mainnet,
    /// testnet-10, simnet, devnet), so the walk is a no-op and every reward is byte-identical there.
    pub(crate) fn initial_palw_provider_bond_view(&self) -> ProviderBondView {
        if self.palw_activation_daa_score == u64::MAX {
            return ProviderBondView::new();
        }
        ProviderBondView::from_records(
            self.palw_provider_bonds_store.read().iterator().filter_map(|r| r.ok().map(|(op, rec)| (op, (*rec).clone()))),
        )
    }

    /// The per-provider-bond acceptance floors — `(min_provider_bond_sompi, provider_unbond_floor_epochs)`
    /// from `palw_batch_admission`. Both are `is_consistent_for_activation`-enforced non-zero on every
    /// activated preset, so neither floor is vacuous where it runs.
    pub(super) fn palw_provider_bond_floors(&self) -> (u64, u64) {
        (self.palw_batch_admission.min_provider_bond_sompi, self.palw_batch_admission.provider_unbond_floor_epochs)
    }

    /// Re-derives the [`PalwProviderBondMutation`]s a chain block contributed, from its retained
    /// acceptance data. Deterministic, so it serves both apply (added) and revert (removed) — the
    /// exact shape of [`Self::dns_bond_mutations_for_chain_block`].
    fn palw_provider_bond_mutations_for_chain_block(&self, chain_block: BlockHash) -> Vec<PalwProviderBondMutation> {
        let accepted_daa_score = self.headers_store.get_header(chain_block).unwrap().daa_score;
        // Per-block fence, matching the leg-5 authorizer's call site EXACTLY. Without it a net with a
        // FINITE, non-zero `palw_activation_daa_score` would write registry rows for blocks below the
        // fence while the authorizer declined to check their `0x37` transactions — i.e. unauthenticated
        // unbonds in the pre-activation window. Unreachable on the six shipped presets (each is either
        // `u64::MAX`, where the caller already returned, or 0, where every block is at/above), which is
        // exactly why it would have gone unnoticed. The writer and the verifier must share one gate.
        if accepted_daa_score < self.palw_activation_daa_score {
            return Vec::new();
        }
        let (min_bond, unbond_floor) = self.palw_provider_bond_floors();
        palw_provider_bond_mutations_from_accepted_txs(
            &self.accepted_txs_of_chain_block(chain_block),
            accepted_daa_score,
            min_bond,
            unbond_floor,
        )
    }

    /// [`PalwProviderBondMutation`]s for a block whose acceptance data is still in memory (the block
    /// currently being UTXO-validated, before its `acceptance_data_store` entry is committed).
    fn palw_provider_bond_mutations_from_acceptance(
        &self,
        acceptance_data: &AcceptanceData,
        accepted_daa_score: u64,
    ) -> Vec<PalwProviderBondMutation> {
        // Same per-block fence as `palw_provider_bond_mutations_for_chain_block`, so the in-memory walk
        // and the persisted registry cannot disagree about which blocks contribute.
        if accepted_daa_score < self.palw_activation_daa_score {
            return Vec::new();
        }
        let (min_bond, unbond_floor) = self.palw_provider_bond_floors();
        palw_provider_bond_mutations_from_accepted_txs(
            &self.accepted_txs_from_acceptance_data(acceptance_data),
            accepted_daa_score,
            min_bond,
            unbond_floor,
        )
    }

    /// Re-derives the [`BondMutation`]s a chain block contributed, from its
    /// retained acceptance data (ADR-0009 Addendum A.4). Deterministic, so it
    /// serves both apply (added) and revert (removed).
    fn dns_bond_mutations_for_chain_block(&self, chain_block: BlockHash) -> Vec<BondMutation> {
        let accepted_daa_score = self.headers_store.get_header(chain_block).unwrap().daa_score;
        let (min_bond, unbonding_floor) = self.dns_bond_floors();
        bond_mutations_from_accepted_txs(&self.accepted_txs_of_chain_block(chain_block), accepted_daa_score, min_bond, unbonding_floor)
    }

    /// The per-bond acceptance floors (min stake amount, min unbonding window) from the network's
    /// `DnsParams`, or `(0, 0)` where the overlay is off — so the bond-acceptance filter is a no-op
    /// on networks without `dns_params`.
    pub(super) fn dns_bond_floors(&self) -> (u64, u64) {
        self.dns_params.as_ref().map(|p| (p.min_bond_amount_sompi, p.unbonding_period_blocks)).unwrap_or((0, 0))
    }

    /// Resolves a chain block's accepted transactions from its acceptance data
    /// (`acceptance_data_store` → `block_transactions_store[index_within_block]`).
    /// Shared by the bond-population (A.4) and StakeScore-aggregation (A.5) passes,
    /// AND (with `--features evm`) the EVM lane.
    ///
    /// Tolerates missing acceptance data → no accepted transactions. A chain block has no committed
    /// acceptance data only when it is the imported pruning point (UTXO-set IBD writes the multiset
    /// but never acceptance data) or a pruned ancestor that a bounded backward overlay walk reaches.
    /// Every overlay reader funnels through here, so guarding the shared helper covers them all (the
    /// per-caller sink guard in `update_dns_state` was not enough: a NORMAL recompute walk legitimately
    /// reaches the pruning point). Returning empty is semantically correct — a block with no
    /// accountable acceptance data contributes no txs; a genuine inconsistency on a non-pruned block
    /// surfaces in the trace log instead of crashing the virtual processor.
    fn accepted_txs_of_chain_block(&self, chain_block: BlockHash) -> Vec<Transaction> {
        match self.acceptance_data_store.get(chain_block) {
            Ok(ad) => self.accepted_txs_from_acceptance_data(&ad),
            Err(StoreError::KeyNotFound(_)) => {
                trace!(
                    "accepted_txs_of_chain_block: no acceptance data for {chain_block} (pruning point / pruned) — treating as no accepted txs"
                );
                Vec::new()
            }
            Err(e) => panic!("accepted_txs_of_chain_block: acceptance_data_store.get({chain_block}) failed: {e}"),
        }
    }

    /// Resolves accepted transactions from already-loaded acceptance data
    /// (`block_transactions_store[index_within_block]`). Split out so the
    /// per-block bond-view walk (ADR-0009 Addendum B) can derive a *not-yet-
    /// committed* block's mutations from the in-memory `ctx.mergeset_acceptance_data`,
    /// whose `acceptance_data_store` entry does not exist until `commit_utxo_state`.
    pub(super) fn accepted_txs_from_acceptance_data(&self, acceptance_data: &AcceptanceData) -> Vec<Transaction> {
        let mut txs = Vec::new();
        for mergeset in acceptance_data.iter() {
            let block_txs = self.block_transactions_store.get(mergeset.block_hash).unwrap();
            for entry in mergeset.accepted_transactions.iter() {
                if let Some(tx) = block_txs.get(entry.index_within_block as usize) {
                    txs.push(tx.clone());
                }
            }
        }
        txs
    }

    /// Resolves the accepted transactions represented by the current virtual state. Unlike a
    /// committed chain block, the virtual state has no persisted `AcceptanceData`; it keeps only the
    /// accepted tx ids. Re-walk the virtual selected-parent + mergeset in consensus order and keep
    /// the ids the virtual UTXO calculation accepted. This lets template-only consensus checks see
    /// the same parent-body attestations that block validation later receives through
    /// `ctx.mergeset_acceptance_data`.
    pub(super) fn accepted_txs_from_virtual_state(&self, virtual_state: &VirtualState) -> Vec<Transaction> {
        if virtual_state.accepted_tx_ids.is_empty() {
            return Vec::new();
        }
        let accepted: HashSet<_> = virtual_state.accepted_tx_ids.iter().copied().collect();
        once(virtual_state.ghostdag_data.selected_parent)
            .chain(virtual_state.ghostdag_data.consensus_ordered_mergeset_without_selected_parent(self.ghostdag_store.deref()))
            .flat_map(|block| (*self.block_transactions_store.get(block).unwrap()).clone())
            .filter(|tx| accepted.contains(&tx.id()))
            .collect()
    }

    /// [`BondMutation`]s for a block whose acceptance data is held in-memory
    /// (the `KeyNotFound` chain block currently being UTXO-validated, before
    /// its `acceptance_data_store` entry is committed). Mirrors
    /// [`Self::dns_bond_mutations_for_chain_block`] but sources the accepted
    /// txs from the provided acceptance data instead of the store.
    fn dns_bond_mutations_from_acceptance(&self, acceptance_data: &AcceptanceData, accepted_daa_score: u64) -> Vec<BondMutation> {
        let (min_bond, unbonding_floor) = self.dns_bond_floors();
        bond_mutations_from_accepted_txs(
            &self.accepted_txs_from_acceptance_data(acceptance_data),
            accepted_daa_score,
            min_bond,
            unbonding_floor,
        )
    }

    /// kaspa-pq DNS Dormancy Fence (design v0.1 §4.3 / §7.3, PR-D2/D3/D4): the
    /// per-epoch dormancy pass, folded into [`Self::update_dns_state`].
    ///
    /// **Fenced inert**: returns immediately unless
    /// `sink_daa >= dormancy_activation_daa_score` (`u64::MAX` on every shipped
    /// preset), so this is byte-identical below the fence.
    ///
    /// ## Reorg-safety (adversarial review + buried-only redesign 2026-07-07)
    /// The persisted dormancy fields (`last_attested_epoch`, `dormant_at_daa_score`,
    /// `dormant_at_epoch`) enter `overlay_commitment_root` and drive the finality
    /// denominator, so they MUST be a pure deterministic function of the canonical
    /// chain or two honest nodes at the same tip fork (`BadOverlayCommitment`).
    /// **FIXED (real-time path):** every transition here keys off `buried_epoch`
    /// (finalized past `max(attestation_lag, max_reorg_horizon)`), the eviction stamp
    /// is the buried round's canonical anchor DAA (never the path-dependent `sink_daa`),
    /// and revival compares in the blue-epoch coordinate (`dormant_at_epoch`, closing
    /// the D4-2 unit bug). Buried data cannot reorg ⇒ the state is reorg-invariant.
    ///
    /// ## Blocker 1 — multi-round catch-up (skip determinism): **CLOSED (PR-D4 checkpoint)**
    /// A `last_evicted_round_epoch` cursor is carried in `DnsState` (recompute-derived, NOT in
    /// the overlay commitment, needs no reorg revert — it is set to the deterministic
    /// `buried_epoch`). The pass replays every eviction round in `(last_evicted_round_epoch,
    /// buried_epoch]` exactly once, ascending, each against its own as-of-`r` buried state via
    /// the pure [`kaspa_consensus_core::dns_finality::apply_dormancy_round`] kernel — so a
    /// virtual commit that JUMPS several epochs lands on the identical dormant set as a node
    /// that advanced one epoch at a time (proven by `dormancy_catch_up_rate_limits_across_rounds`:
    /// jump replay == incremental replay). A fresh `DnsState` (genesis / post-IBD import) seeds
    /// the cursor at the pruning point's buried epoch (the imported bonds already carry the
    /// dormant transitions through `pp`), so the catch-up replays only the `(pp, sink]` rounds.
    ///
    /// ## ⚠️ Blocker 2 — pruned-IBD as-of-pp `last_attested`: **REMAINING (fence stays inert)**
    /// [`Self::bonds_as_of`] nulls dormant stamps `> pp_buried` EXACTLY (a discrete event), but
    /// `last_attested_epoch` is an overwrite-with-latest field, so its as-of-`pp` value is not
    /// recoverable from the current state + post-`pp` data (the `max` is lossy). Because a
    /// bond's committed **Dormant status** is downstream of `last_attested` (via eviction), an
    /// importer that starts from a wrong `last_attested` can evict in a different round → a later
    /// `c != v`. **Exact fix (specified, not yet wired):** unify `last_attested` for *Active*
    /// bonds onto the committed, pruning-survivable **rewarded-epoch overlay window**
    /// (`rewarded_epochs_store`, carried in the snapshot as `BlockOverlayContribution.rewarded_keys
    /// = (outpoint, epoch)`) — reconstructable byte-exactly by a pruned importer — plus a new
    /// consistency invariant I7 (`overlay_window_walk_bound` ≥ the dormancy inactivity horizon,
    /// so every *Active* bond's last attestation is inside the window; fail-safe → dormancy stays
    /// inert if violated). *Dormant* bonds need no exact value (revival requires a post-`pp`
    /// attestation, which the importer replays live). Edge cases to resolve in that change:
    /// rewarded ⊊ credited (pool-cap / zero-reward lag) and the just-revived-bond transition.
    ///
    /// **Release gate (independent of the fence):** the three appended `StakeBondRecord`
    /// fields grow the borsh overlay-commitment preimage, so this binary MUST ship only
    /// on a coordinated **re-genesis** — never rolled onto an existing overlay-active net.
    ///
    /// Effects staged into the atomic `batch` (buried-only, per catch-up round then once at
    /// `buried_epoch`): touch_last_attested (D2), the eviction round `Active -> Dormant` (D3),
    /// then revival `Dormant -> Active` (D4). Returns the new `last_evicted_round_epoch`.
    #[allow(clippy::too_many_arguments)] // buried-only inputs threaded explicitly (all pure)
    fn stage_dormancy_transitions(
        &self,
        batch: &mut WriteBatch,
        sink: BlockHash,
        bonds: &[StakeBondRecord],
        contributions: &[AttestationContribution],
        revival_signals: &[(TransactionOutpoint, u64)],
        epoch_anchor_daa: &BTreeMap<u64, u64>,
        prev_last_evicted: u64,
        sink_daa: u64,
        sink_blue: u64,
        dns_params: &DnsParams,
    ) -> u64 {
        // Master fence: inert until governance activates it under a re-genesis.
        if sink_daa < dns_params.dormancy_activation_daa_score {
            return prev_last_evicted;
        }
        let epoch_len_blue = dns_params.attestation_epoch_length_blue_score.max(1);
        // BURIED-ONLY + CATCH-UP (PR-D4 checkpoint): `buried_epoch` = the latest epoch finalized
        // past BOTH the attestation lag AND the reorg horizon. Every dormancy transition is
        // driven only by buried data, so the persisted state (last_attested_epoch,
        // dormant_at_daa_score, dormant_at_epoch) is a pure function of the canonical chain —
        // reorg-invariant — hence safe in the overlay commitment and the finality denominator.
        // Each eviction ROUND is replayed exactly once against its AS-OF-r buried state via the
        // `(prev_last_evicted, buried_epoch]` catch-up below, so a virtual commit that jumps
        // several epochs cannot skip a round and desync from a node that advanced one at a time.
        let bury_blue = dns_params.attestation_lag_blue_score.max(dns_params.max_reorg_horizon_blocks);
        let Some(buried_epoch) = ready_epoch_from_tip_blue_score(sink_blue, epoch_len_blue, bury_blue) else {
            return prev_last_evicted; // no epoch buried past the horizon yet (early chain)
        };

        // This recompute's BURIED attestation epochs per bond (sorted), so the per-round replay
        // can reconstruct `max attested epoch <= r` — the as-of-r inactivity signal — for any
        // round r. Contributions (Active/credited) + revival signals (Dormant/uncredited) both
        // count for recency. Epochs newer than `buried_epoch` are excluded (not yet finalized).
        let mut att_by_bond: std::collections::HashMap<TransactionOutpoint, Vec<u64>> = std::collections::HashMap::new();
        for c in contributions {
            if c.epoch <= buried_epoch {
                att_by_bond.entry(c.bond_outpoint).or_default().push(c.epoch);
            }
        }
        for &(op, e) in revival_signals {
            if e <= buried_epoch {
                att_by_bond.entry(op).or_default().push(e);
            }
        }
        // (att_by_bond stays unsorted; the kernel takes max<=r directly.)

        // Working copy in the pre-pass snapshot's order, so staging can diff by index (records
        // are never reordered). The catch-up mutates it via the pure kernel; only records that
        // actually changed are staged into the batch.
        let mut work: Vec<StakeBondRecord> = bonds.to_vec();

        let period = dns_params.dormancy_evict_period_epochs.max(1);
        let revival_delay = dns_params.dormancy_revival_delay_epochs.max(1) as u64;

        // CATCH-UP: replay each eviction round r in (prev_last_evicted, buried_epoch] once,
        // ascending, against its own as-of-r buried state (the deterministic kernel).
        let mut last_evicted = prev_last_evicted;
        let mut r = (prev_last_evicted / period + 1) * period;
        while r <= buried_epoch {
            // Deterministic anchor DAA for round r (in-window map, else derive). Unavailable
            // (r far below the window after an extreme catch-up gap) ⇒ stop and retry next
            // recompute rather than skip the round.
            let Some(round_anchor_daa) = epoch_anchor_daa
                .get(&r)
                .copied()
                .or_else(|| self.canonical_anchor_by_blue_score(r, sink, dns_params).map(|a| a.anchor_daa_score))
            else {
                break;
            };
            apply_dormancy_round(&mut work, &att_by_bond, r, round_anchor_daa, sink_daa, epoch_len_blue, dns_params);
            last_evicted = r;
            r += period;
        }

        // Final touch up to buried_epoch (past the last round) so revival + future rounds see it.
        for rec in work.iter_mut() {
            if let Some(m) = att_by_bond.get(&rec.bond_outpoint).and_then(|v| v.iter().copied().filter(|&e| e <= buried_epoch).max())
                && rec.last_attested_epoch.is_none_or(|le| m > le)
            {
                rec.last_attested_epoch = Some(m);
            }
        }

        // REVIVAL at buried_epoch (responsive; not round-gated). Unbonding/Slashed outrank
        // Dormant (skipped). The touch above means a freshly-attested bond is never an eviction
        // candidate, so revival-after-eviction has no conflict.
        for rec in work.iter_mut() {
            if effective_bond_status(rec, sink_daa) != BondStatus::Dormant {
                continue;
            }
            let Some(dormant_epoch) = rec.dormant_at_epoch else {
                continue;
            };
            let last = rec.last_attested_epoch.unwrap_or(0);
            if dormancy_revival_ready(dormant_epoch, last, buried_epoch, revival_delay) {
                rec.dormant_at_daa_score = None;
                rec.dormant_at_epoch = None;
                rec.status = effective_bond_status(rec, sink_daa);
            }
        }

        // Stage only the records that actually changed (diff by index vs the pre-pass snapshot).
        let mut store = self.stake_bonds_store.write();
        for (i, rec) in work.iter().enumerate() {
            if bonds[i] != *rec {
                store.insert_batch(batch, rec.bond_outpoint, Arc::new(rec.clone())).unwrap();
            }
        }
        last_evicted
    }

    /// kaspa-pq Phase 10 (ADR-0009 Addendum A.5): recompute the DNS StakeScore
    /// over the bounded recent epoch window ending at `sink` and stage the
    /// updated [`DnsState`] singleton into `batch`. **Inert** unless the DNS
    /// overlay is configured (`dns_params.is_some()`).
    ///
    /// Bounded-window design (stake_depth is a window quantity, not cumulative):
    /// walk back at most `max_reorg_horizon_blocks` selected-chain blocks from
    /// `sink`, collect on-chain attestation shards, verify each ML-DSA-87
    /// signature against its bond's validator key under
    /// `ATTESTATION_MLDSA87_CONTEXT`, gate by `is_bond_active_at`, then feed the
    /// pure aggregation core. No new store; recompute is reorg-safe.
    fn update_dns_state(&self, batch: &mut WriteBatch, sink: BlockHash) {
        let Some(dns_params) = self.dns_params.as_ref() else {
            return;
        };
        // The StakeScore recompute below walks the selected chain reading each chain block's
        // acceptance data (`collect_stake_contributions_v2` -> `accepted_txs_of_chain_block`). During
        // pruning-point UTXO import (IBD), the sink IS the imported pruning point, whose acceptance
        // data is deliberately never written — `import_pruning_point_utxo_set` writes only the
        // multiset + UTXO status ("acceptance data and utxo-diff are irrelevant"). There is no chain
        // history to aggregate at that moment, so skip the recompute; `DnsState` is recompute-derived
        // and is rebuilt normally from the first fully-processed block after import. Without this
        // guard the walk panics with `KeyNotFound(AcceptanceData/<pruning point>)`, which surfaces as
        // a tokio runtime panic in the `spawn_blocking` import worker and crashes startup.
        match self.acceptance_data_store.get(sink) {
            Ok(_) => {}
            Err(StoreError::KeyNotFound(_)) => {
                // Missing acceptance data for the sink is EXPECTED only during pruning-point import,
                // where the sink IS the imported pruning point. Anywhere else it signals a store
                // inconsistency, so surface it loudly (still skip rather than panic, but never
                // silently): a genuine bug must be visible in the logs, not swallowed.
                let pp = self.pruning_point_store.read().pruning_point().optional().ok().flatten();
                if pp == Some(sink) {
                    trace!("update_dns_state: skipping recompute during pruning-point import (sink == pruning point {sink})");
                } else {
                    warn!(
                        "update_dns_state: acceptance data missing for sink {sink} (pruning point {pp:?}) — skipping DNS recompute; this is UNEXPECTED outside pruning-point import"
                    );
                }
                return;
            }
            Err(e) => panic!("update_dns_state: acceptance_data_store.get({sink}) failed: {e}"),
        }
        let sink_daa = self.headers_store.get_header(sink).unwrap().daa_score;
        // ADR-0009 Addendum A.3 network_id discriminator := the per-network genesis hash.
        let net_id = self.genesis.hash;

        // PR-10.11 throttle: StakeScore is per-epoch, so recompute DnsState only
        // once per epoch — when the sink's epoch differs from the last-written
        // DnsState's epoch. This bounds the window walk to ~once per
        // `epoch_length_blocks` (O(1) amortized per block) instead of walking
        // `max_reorg_horizon_blocks` on every virtual commit. Deterministic and
        // epoch-granular; safe on devnet/testnet where the gate is dormant
        // (Bootstrap). M-01 / audit #3: the recompute no longer depends on which sink first
        // crosses the boundary. The StakeScore is canonical (`collect_stake_contributions_v2`
        // credits only this chain's canonical lagged anchor per ready epoch), AND the
        // DNS-confirmed anchor is that canonical lagged anchor — NOT the sink (see
        // `confirmable_anchor` below). The reorg gate protects ONLY the confirmed anchor, so two
        // nodes that recompute at different boundary sinks still protect the identical anchor;
        // only `selected_chain_anchor` (read solely by this throttle) differs between them.
        let prev_dns_state = self.dns_state_store.read().get().ok();
        // kaspa-pq DNS v3: throttle the recompute to once per BLUE_SCORE epoch (epochs are
        // blue_score-coordinated now), not the DAA epoch. The recompute is canonical
        // regardless of cadence — this only bounds how often the window walk runs, and must
        // fire at least once per blue_score epoch so confirmations don't lag. `prev`'s
        // blue_score is read from its anchor (recent — at most ~1 epoch old, never pruned).
        let sink_blue = self.headers_store.get_blue_score(sink).unwrap();
        let epoch_len_blue = dns_params.attestation_epoch_length_blue_score.max(1);
        if let Some(prev) = prev_dns_state.as_ref() {
            let prev_blue = self.headers_store.get_blue_score(prev.selected_chain_anchor).unwrap_or(0);
            if sink_blue / epoch_len_blue == prev_blue / epoch_len_blue {
                return;
            }
        }

        // Snapshot the bond set (bounded by the active validator count).
        let bonds: Vec<StakeBondRecord> =
            self.stake_bonds_store.read().iterator().filter_map(|r| r.ok().map(|(_, rec)| (*rec).clone())).collect();

        // Current total active stake + validator count at the sink (rollout gating).
        let active_stakes_at_sink: Vec<_> = bonds.iter().filter(|b| is_bond_active_at(b, sink_daa)).map(|b| b.amount).collect();
        let total_active = active_stakes_at_sink.iter().fold(0u64, |acc, amount| acc.saturating_add(*amount));
        let active_validators = active_stakes_at_sink.len() as u32;
        let hard_mandatory_active = sink_daa >= dns_params.mandatory_attestation_inclusion_daa_score;
        let capacity = mandatory_attestation_mass_capacity(
            active_stakes_at_sink.iter().copied(),
            total_active,
            0,
            dns_params.stake_event_quality_floor_bps,
            self.max_block_mass,
            dns_params.max_attestation_shard_mass,
        );
        let rollout_stage = if sink_daa >= dns_params.dns_activation_daa_score
            && total_active >= dns_params.min_active_stake_sompi
            && active_validators >= dns_params.min_active_validators
            // kaspa-pq DNS v3 (PR6): refuse Active unless the blue_score canonical-anchor params
            // are self-consistent. In Active the reorg gate's finality depends entirely on them,
            // so an invalid config fails safe (stay Bootstrap, gate dormant) rather than splitting.
            && dns_params.dns_v3_params_consistent()
            // kaspa-pq optional hard mandatory capacity: only hard-inclusion deployments require
            // proving that the current stake distribution can physically reach φS in one block.
            // Shipped liveness-first presets keep mandatory inclusion at u64::MAX, so capacity
            // cannot demote DNS to Bootstrap or halt finality/reward accounting.
            && (!hard_mandatory_active || capacity.fits)
        {
            DnsRolloutStage::Active
        } else {
            DnsRolloutStage::Bootstrap
        };

        // kaspa-pq DNS v3: canonical, blue_score-coordinated StakeScore. Credit only
        // attestations naming THIS chain's canonical lagged anchor for their (ready,
        // non-duplicate) epoch, with the per-epoch denominator keyed by the canonical anchor
        // DAA and zero-attestation ready epochs included (`collect_stake_contributions_v2`).
        let (contributions, epoch_anchor_daa, revival_signals) =
            self.collect_stake_contributions_v2(sink, None, &bonds, net_id.as_byte_slice(), dns_params);

        // kaspa-pq DNS Dormancy Fence (design v0.1, PR-D2/D3/D4): record each attested
        // bond's latest epoch, revive Dormant bonds that attested (§4.5), then (on a
        // round boundary) evict Active bonds inactive past the window to Dormant so dead
        // stake self-heals out of the finality denominator. Fenced inert
        // (dormancy_activation_daa_score = u64::MAX on every shipped preset) so this
        // returns immediately below the fence.
        // Round cursor for the eviction catch-up. Carried in DnsState (recompute-derived, NOT
        // in the overlay commitment). On a fresh DnsState (genesis or post-IBD import) the
        // imported bonds already carry dormant transitions through the pruning point, so seed
        // the cursor at the pp's buried epoch — the catch-up then replays only the (pp, sink]
        // rounds not yet reflected in the imported set (genesis pp ⇒ blue 0 ⇒ seed 0).
        let prev_last_evicted = match prev_dns_state.as_ref() {
            Some(p) => p.last_evicted_round_epoch,
            None => {
                let bury_blue = dns_params.attestation_lag_blue_score.max(dns_params.max_reorg_horizon_blocks);
                self.pruning_point_store
                    .read()
                    .pruning_point()
                    .optional()
                    .ok()
                    .flatten()
                    .and_then(|pp| self.headers_store.get_blue_score(pp).ok())
                    .and_then(|pp_blue| ready_epoch_from_tip_blue_score(pp_blue, epoch_len_blue, bury_blue))
                    .unwrap_or(0)
            }
        };
        let new_last_evicted = self.stage_dormancy_transitions(
            batch,
            sink,
            &bonds,
            &contributions,
            &revival_signals,
            &epoch_anchor_daa,
            prev_last_evicted,
            sink_daa,
            sink_blue,
            dns_params,
        );

        let totals = total_active_stake_by_epoch(&bonds, &epoch_anchor_daa);
        let per_epoch = aggregate_epoch_tallies(&contributions, &totals);
        let stake_depth = compute_stake_score(&per_epoch, dns_params.stake_event_quality_floor_bps);

        // kaspa-pq Phase 13 (ADR-0018 §C): derive the read-only DnsHealth liveness signal
        // from the same per-epoch tallies that fed the StakeScore. `overlay_active` iff the
        // reorg gate is engaged (`Active`); in Bootstrap there is no DNS finality to judge,
        // so health stays `DisabledBeforeActivation`. Purely a signal — never a
        // block-validity input, so this is inert wherever the gate is dormant.
        let health = derive_dns_health(
            &per_epoch,
            dns_params.stake_event_quality_floor_bps,
            dns_params.stake_censorship_floor_bps,
            dns_params.degraded_stake_quality_epochs,
            rollout_stage == DnsRolloutStage::Active,
        );

        // kaspa-pq DNS-finality (§6.5): structured diagnostics for the StakeScore credit
        // path — how many attestations were credited at this sink, the credited
        // (epoch, bond, stake) tuples, and the resulting stake_depth. Inert when there is
        // no attestation traffic this recompute (empty contributions ⇒ no log).
        if !contributions.is_empty() {
            info!(
                "[stake-score] sink={} sink_blue={} credited {} attestation(s) over {} ready epoch(s) → stake_depth={} (rollout={:?}, health={:?})",
                sink,
                sink_blue,
                contributions.len(),
                epoch_anchor_daa.len(),
                stake_depth.0,
                rollout_stage,
                health,
            );
            for c in contributions.iter() {
                debug!(
                    "[stake-score] credited epoch={} bond={} stake={} validator_id={}",
                    c.epoch, c.bond_outpoint.transaction_id, c.signed_stake_sompi, c.validator_id
                );
            }
        }

        // audit #3: the canonical lagged anchor of the latest ready epoch — a fixed,
        // blue_score-coordinated selected-chain point every node derives identically. THIS (not
        // the POV-dependent `sink`) is what gets DNS-confirmed and protected by the reorg gate, so
        // nodes that recompute at different boundary sinks still protect the same anchor. `None`
        // until an epoch's anchor is buried and lag-ready (early chain / not yet ready).
        let confirmable_anchor = ready_epoch_from_tip_blue_score(sink_blue, epoch_len_blue, dns_params.attestation_lag_blue_score)
            .and_then(|epoch| self.canonical_anchor_by_blue_score(epoch, sink, dns_params))
            .map(|a| (a.anchor_hash, a.anchor_daa_score));

        // true WorkDepth (audit H-02 Option A): WorkDepth(B) is the blue work accumulated SINCE the
        // confirmable anchor B — anchor-relative (`blue_work(sink) − blue_work(anchor)`), NOT the
        // cumulative-from-genesis `blue_work(sink)`. This makes it a real confirmation DEPTH (how much
        // PoW is piled on the confirmed point), so `is_dns_confirmed` genuinely requires BOTH a
        // work-depth AND a stake-depth (two-dimensional confirmation, matching the reorg gate's
        // anchor-relative work∧stake dominance). With `required_work_depth = 0` (devnet/simnet) this is
        // inert (stake-only); on mainnet/testnet (`required_work_depth > 0`) the work term gates too.
        // `ZERO` when no anchor is ready yet (no confirmation happens then anyway).
        let work_depth = confirmable_anchor
            .map(|(anchor_hash, _)| {
                self.ghostdag_store
                    .get_blue_work(sink)
                    .unwrap_or_default()
                    .saturating_sub(self.ghostdag_store.get_blue_work(anchor_hash).unwrap_or_default())
            })
            .unwrap_or_default();
        let new_state = advance_dns_confirmation(
            prev_dns_state.as_ref(),
            sink,
            sink_daa,
            confirmable_anchor,
            work_depth,
            stake_depth,
            rollout_stage,
            // validator_set_commitment: ADR-0017 dropped the sortition committee, so the
            // StakeScore path binds no committee snapshot — this stays zero.
            BlockHash::default(),
            health,
            dns_params.required_work_depth,
            dns_params.required_stake_depth,
            new_last_evicted,
        );
        self.dns_state_store.write().set_batch(batch, new_state).unwrap();
    }

    /// kaspa-pq ADR-0018 "本格版" (PoS-v2, Phase 1): recompute the per-epoch
    /// `EpochTally` accumulator over the bounded selected-chain window ending at
    /// `sink` and stage the live (non-finalized) epochs into `batch`. Gated by the
    /// v2 fence `pos_v2_activation_daa_score`: **inert** (returns after a single
    /// header read) on devnet/simnet (`GENESIS_ACTIVE_DNS_PARAMS`, fence `u64::MAX`);
    /// **active from block 1** on mainnet/testnet (`PRODUCTION_DNS_PARAMS`, fence `0`)
    /// — also requires the DNS overlay to be configured.
    ///
    /// Recompute design (the `update_dns_state` precedent — reorg-safe with no
    /// incremental delta): the accumulator is a pure function of the selected
    /// chain (each block's persisted rewarded `(bond, epoch)` keys + quality
    /// sub-pool, both block-hash-keyed so only the current chain's rows are read)
    /// and the current bond snapshot, so a reorg simply re-derives the live epochs
    /// from the new chain.
    ///
    /// Window: `finalization_depth = reward_uniqueness_window_blocks +
    /// max_reorg_horizon_blocks` — a non-final epoch's included set stays mutable
    /// up to `window` past its anchor and a reorg can rewrite up to
    /// `max_reorg_horizon` blocks, so burying past their sum makes the tally
    /// immutable. The walk covers `finalization_depth + 2·epoch_length` so every
    /// non-final epoch's contributing blocks are seen. An epoch already `finalized`
    /// in the store is never re-derived (its blocks may lie partly outside the
    /// window — an incomplete recompute).
    ///
    /// NOTE (perf): unlike `update_dns_state` this does not throttle to
    /// once-per-epoch — instead the per-block work is **bounded by design** to the
    /// `walk_bound = finalization_depth + 2·epoch_length` window (a few thousand
    /// header/store reads at production params, all block-hash-keyed and cached), so
    /// it is O(window) per virtual commit, not O(chain). This bounded-window walk is
    /// what makes it reorg-safe (a pure function of the current selected chain, no
    /// incremental delta), and it runs from block 1 on mainnet/testnet (fence `0`).
    fn update_epoch_accumulator(&self, batch: &mut WriteBatch, sink: BlockHash) {
        let Some(dns_params) = self.dns_params.as_ref() else {
            return;
        };
        let sink_daa = self.headers_store.get_daa_score(sink).unwrap();
        // The v2 master fence: inert (no walk, no write) on devnet/simnet (`u64::MAX`);
        // the walk runs from block 1 on mainnet/testnet (`PRODUCTION_DNS_PARAMS`, fence `0`).
        if sink_daa < dns_params.pos_v2_activation_daa_score {
            return;
        }

        let epoch_len = dns_params.epoch_length_blocks.max(1);
        let finalization_depth = dns_params.reward_uniqueness_window_blocks.saturating_add(dns_params.max_reorg_horizon_blocks);
        let walk_bound = self.overlay_window_walk_bound(dns_params);

        // Gather this selected chain's per-block contributions within the window, oldest →
        // newest (so the `included` ordering is chain-deterministic). ADR-0022: this goes
        // through `selected_chain_overlay_window`, which merges the persisted below-pruning-
        // point window — so a pruned-IBD node recomputes epochs straddling the pruning point
        // correctly (its walk cannot reach below it). On a from-genesis node the merge is inert.
        let contributions: Vec<BlockEpochContribution> = self
            .selected_chain_overlay_window(sink, sink_daa, walk_bound)
            .into_iter()
            .map(|c| BlockEpochContribution {
                block_daa_score: c.block_daa_score,
                rewarded_keys: c.rewarded_keys,
                quality_subpool: c.quality_subpool,
            })
            .collect();

        // Snapshot the bond set (bounded by the active validator count), as update_dns_state does.
        let bonds: Vec<StakeBondRecord> =
            self.stake_bonds_store.read().iterator().filter_map(|r| r.ok().map(|(_, rec)| (*rec).clone())).collect();

        for (epoch, tally) in recompute_epoch_tallies(sink_daa, epoch_len, finalization_depth, &contributions, &bonds) {
            // Never re-derive a finalized epoch — it is immutable and its blocks may
            // already lie partly outside the walk window (an incomplete recompute).
            if self.epoch_accumulator_store.get(epoch).map(|t| t.finalized).unwrap_or(false) {
                continue;
            }
            self.epoch_accumulator_store.set_batch(batch, epoch, tally).unwrap();
        }
    }

    /// kaspa-pq ADR-0022: build the [`OverlaySnapshot`] **as-of `selected_parent`** —
    /// the exact set of overlay rows a pruned-IBD node needs to validate
    /// `selected_parent`'s descendants. Committed in `Header::overlay_commitment_root`
    /// (template fills it, `verify_expected_utxo_state` re-derives + checks it, c==v).
    ///
    /// Deterministic across the template path (`selected_parent` = sink) and the
    /// validation path (`selected_parent` = the block's selected parent): it reads
    /// only the walked bond view + per-block stores (`reserve_balance_store`,
    /// `rewarded_epochs_store`, `block_quality_pool_store`), never the per-sink
    /// epoch accumulator. Empty (⇒ `OverlaySnapshot::default()`) when the overlay
    /// is dormant; the window walk mirrors `update_epoch_accumulator` (same
    /// `walk_bound`, same pos_v2 fence) but is anchored at `selected_parent` and
    /// keeps only blocks that actually contributed (rewarded keys or quality pool),
    /// so the snapshot stays small on a validator-sparse chain.
    pub(super) fn compute_overlay_snapshot(
        &self,
        selected_parent: BlockHash,
        selected_parent_bond_view: &ActiveBondView,
    ) -> OverlaySnapshot {
        let Some(dns_params) = self.dns_params.as_ref() else {
            return OverlaySnapshot::default();
        };

        let anchor_daa = self.headers_store.get_daa_score(selected_parent).unwrap();

        // Normalize the (non-canonical) stored `status` to the EFFECTIVE status at the
        // anchor. The raw `status` field diverges across reorg paths — `ActiveBondView::revert`
        // restores a reverted-slash bond to `Active` even if it was originally `Pending`, so a
        // never-slashed vs slashed-then-reverted bond can carry different `status` for byte-equal
        // history. `effective_bond_status` is a pure function of the canonical timing fields
        // (`activation_daa_score`/`slashed_at`/`unbond_request`), which the reward path already
        // uses; normalizing here makes the committed bond set deterministic across reorgs without
        // touching consensus-state mutation (the raw field is otherwise vestigial).
        let mut bonds = selected_parent_bond_view.records();
        for b in bonds.iter_mut() {
            b.status = effective_bond_status(b, anchor_daa);
        }
        let reserve_balance = self.reserve_balance_store.get(selected_parent).unwrap_or(0);

        let walk_bound = self.overlay_window_walk_bound(dns_params);
        let window = self.selected_chain_overlay_window(selected_parent, anchor_daa, walk_bound);

        OverlaySnapshot { bonds, reserve_balance, window }
    }

    /// Compute the overlay commitment required by `header_version` from the
    /// already-built legacy DNS snapshot and the selected parent's carried PALW
    /// beacon state.
    ///
    /// Pre-v3 returns the legacy snapshot root without touching the PALW store,
    /// preserving existing-network behavior exactly. Header-v3 reads the
    /// block-keyed state (`Ok(None)` is valid only when the selected parent is
    /// genesis or still pre-activation) and commits the full record through
    /// [`OverlaySnapshot::versioned_commitment_root`]. `beacon_state` already
    /// maps only `StoreError::KeyNotFound` to `Ok(None)`; every other database
    /// error is fatal here rather than being silently reinterpreted as an absent
    /// consensus state.
    pub(super) fn versioned_overlay_commitment_root(
        &self,
        header_version: u16,
        selected_parent: BlockHash,
        snapshot: &OverlaySnapshot,
    ) -> kaspa_hashes::Hash64 {
        let beacon_state = if header_version >= kaspa_consensus_core::constants::PALW_HEADER_VERSION {
            let state = self
                .palw_beacon_store
                .beacon_state(selected_parent)
                .unwrap_or_else(|err| panic!("failed reading PALW beacon state for selected parent {selected_parent}: {err}"));
            if state.is_none()
                && selected_parent != self.genesis.hash
                && self.headers_store.get_daa_score(selected_parent).unwrap() >= self.palw_activation_daa_score
            {
                panic!("missing PALW beacon state for active selected parent {selected_parent}");
            }
            state
        } else {
            None
        };
        snapshot.versioned_commitment_root(header_version, beacon_state.as_deref())
    }

    /// ADR-0022: `reward_uniqueness_window + max_reorg_horizon + 2·epoch_length` — the
    /// selected-chain window that covers BOTH the reward-uniqueness dedup and the
    /// epoch-accumulator recompute. Shared by the overlay snapshot, the epoch
    /// accumulator, and the reward dedup so all three see the same span.
    pub(super) fn overlay_window_walk_bound(&self, dns_params: &DnsParams) -> u64 {
        let epoch_len = dns_params.epoch_length_blocks.max(1);
        let finalization_depth = dns_params.reward_uniqueness_window_blocks.saturating_add(dns_params.max_reorg_horizon_blocks);
        finalization_depth.saturating_add(epoch_len.saturating_mul(2))
    }

    /// kaspa-pq ADR-0022: the per-block overlay contributions on `anchor`'s selected
    /// chain within `walk_bound` (rewarded keys + quality sub-pool), oldest → newest,
    /// MERGING the persisted pruning-point snapshot's below-pruning-point window.
    ///
    /// The selected-chain walk cannot traverse below the pruning point (no reachability
    /// there after a prune or a pruned-IBD import), so it stops at the persisted pruning
    /// point and the persisted snapshot supplies everything at/below it. On a node whose
    /// pruning point is far below `anchor` (normal operation) the walk never reaches it
    /// and every persisted entry is outside `walk_bound`, so the merge is a no-op
    /// (byte-identical to a from-genesis node). Empty-contribution blocks are skipped.
    /// The single seam through which all three below-pp consumers (overlay commitment,
    /// epoch accumulator, reward dedup) read the historical window.
    pub(super) fn selected_chain_overlay_window(
        &self,
        anchor: BlockHash,
        anchor_daa: u64,
        walk_bound: u64,
    ) -> Vec<BlockOverlayContribution> {
        let persisted = self.pruning_overlay_snapshot_store.read().get().ok();
        let stop_at = persisted.as_ref().map(|p| p.pruning_point);

        // Above-pruning-point part, collected newest → oldest by the chain walk.
        let mut above: Vec<BlockOverlayContribution> = Vec::new();
        for ancestor in std::iter::once(anchor).chain(self.reachability_service.default_backward_chain_iterator(anchor)) {
            if Some(ancestor) == stop_at {
                break;
            }
            let ancestor_daa = self.headers_store.get_daa_score(ancestor).unwrap();
            if anchor_daa.saturating_sub(ancestor_daa) > walk_bound {
                break;
            }
            let rewarded_keys = self.rewarded_epochs_store.get(ancestor).map(|k| (*k).clone()).unwrap_or_default();
            let quality_subpool = self.block_quality_pool_store.get(ancestor).unwrap_or(0);
            if rewarded_keys.is_empty() && quality_subpool == 0 {
                continue;
            }
            above.push(BlockOverlayContribution {
                block_hash: ancestor,
                block_daa_score: ancestor_daa,
                rewarded_keys,
                quality_subpool,
            });
        }
        above.reverse(); // → oldest → newest

        // Below-pruning-point part: the persisted window (stored oldest → newest), kept
        // to entries still within `walk_bound` of the anchor. These never overlap `above`
        // (the walk stopped AT the pruning point), so prepending yields a single
        // oldest → newest selected-chain ordering.
        let mut window: Vec<BlockOverlayContribution> = Vec::new();
        if let Some(p) = persisted {
            for c in p.snapshot.window {
                if anchor_daa.saturating_sub(c.block_daa_score) <= walk_bound {
                    window.push(c);
                }
            }
        }
        window.extend(above);
        // kaspa-pq ADR-0022 fix: the persisted below-pruning-point window includes the pruning-point
        // boundary block (it is the newest entry of the captured `compute_overlay_snapshot(pp)` walk),
        // and across pruning advances that boundary block can also be re-captured into a later
        // snapshot's window — so a pruned-IBD node's recomputed window carried ONE EXTRA (duplicate)
        // entry at the pruning-point block vs a from-genesis node's clean live walk. That single extra
        // contribution changed the canonicalized overlay snapshot → the first post-pruning block's
        // `overlay_commitment_root` recompute (and the epoch/reward recompute that share this seam)
        // diverged (c != v) and the pruned-IBD node got stuck at "0 valid chain blocks". Dedup by block
        // hash: a from-genesis live walk visits each selected-chain block exactly once, so this is a
        // no-op there and only removes the spurious merge-path duplicate — restoring construction ==
        // validation for pruned-IBD joiners.
        let mut seen = std::collections::HashSet::new();
        window.retain(|c| seen.insert(c.block_hash));
        window
    }

    /// kaspa-pq **ADR-0040 §5.15.13 — gate G16 (P1-9-RELAND)**: the `job_nullifier`s already PAID on
    /// `anchor`'s selected chain within [`PalwBatchAdmissionParams::paid_work_walk_bound_daa`].
    ///
    /// This is the paid-set the reward coordinate deduplicates against. Three properties, each with a
    /// line below that enforces it:
    ///
    /// * **Chain-relative, hence reorg-clean.** The set is a pure function of `(anchor's selected
    ///   chain, walk_bound)`. A block paid on a branch that loses a reorg is simply not on the new
    ///   chain, so its nullifiers are unpaid there — which is correct, because its payout was undone
    ///   with it. Nothing is carried, so nothing has to be un-carried.
    /// * **Order-independent.** Two nodes evaluating the SAME block walk the same selected chain from
    ///   the same anchor with the same bound and read the same block-keyed rows, so they cannot
    ///   disagree. There is no arrival-order input anywhere in this function.
    /// * **Bounded.** `walk_bound` is derived from the batch-admission windows, which
    ///   `PalwBatchManifestV1::admission_valid` enforces — see that method's doc for the derivation.
    ///
    /// **Inert everywhere today.** The fast path returns an empty set while PALW is gated, and even on
    /// `testnet-palw-110` / `devnet-palw-111` (fence 0) every row is absent because
    /// `palw_algo4_accept = false` means no algo-4 source can be accepted and therefore paid.
    ///
    /// **Recorded residual (pruned-IBD boundary).** Like every selected-chain walk here, this one
    /// cannot traverse below the pruning point. Unlike the DNS overlay window it is deliberately NOT
    /// merged with `pruning_overlay_snapshot_store`: that snapshot's borsh encoding is the preimage of
    /// `Header::overlay_commitment_root` and adding a field to it would move that commitment on every
    /// net, including mainnet. So a pruned joiner validating the first `walk_bound` DAA above its
    /// pruning point sees a short prefix. `palw_paid_work_walk_stays_above_the_pruning_point` pins the
    /// parameter relation that keeps this to the bootstrap band only; closing the band itself is an
    /// activation-blocking item, not something a comment covers.
    pub(super) fn palw_paid_work_window(&self, anchor: BlockHash, anchor_daa: u64) -> std::collections::HashSet<Hash64> {
        let mut paid = std::collections::HashSet::new();
        if self.palw_activation_daa_score == u64::MAX {
            return paid; // inert fast path — no algo-4 source can be accepted, so nothing was ever paid
        }
        let walk_bound = self.palw_batch_admission.paid_work_walk_bound_daa(self.palw_epoch_length_daa);
        let stop_at = self.pruning_overlay_snapshot_store.read().get().ok().map(|p| p.pruning_point);
        for ancestor in std::iter::once(anchor).chain(self.reachability_service.default_backward_chain_iterator(anchor)) {
            if Some(ancestor) == stop_at {
                break;
            }
            let ancestor_daa = self.headers_store.get_daa_score(ancestor).unwrap();
            if anchor_daa.saturating_sub(ancestor_daa) > walk_bound {
                break;
            }
            // FAIL CLOSED on anything that is not a genuine absence. A block that paid no PALW work
            // writes no row, so `KeyNotFound` is the normal case and means "this ancestor paid nothing".
            // Every OTHER StoreError is an IO/corruption fault, and swallowing it would silently drop
            // that ancestor's paid nullifiers from the set — i.e. re-open the duplicate-work hole this
            // walk exists to close, as a transient double-PAYMENT rather than a loud failure. Panicking
            // matches `headers_store.get_daa_score(...).unwrap()` three lines above: inside the reward
            // path, a store we cannot read is not a condition we can safely continue through.
            match self.palw_paid_work_store.get(ancestor) {
                Ok(ids) => paid.extend(ids.iter().copied()),
                Err(kaspa_database::prelude::StoreError::KeyNotFound(_)) => {}
                Err(e) => panic!("PALW paid-work store unreadable for ancestor {ancestor}: {e}"),
            }
        }
        paid
    }

    /// kaspa-pq Phase 13 (ADR-0018 §H) + DNS v3 (PR6): the StakeScore a branch accumulated
    /// **since the common ancestor** — the selected chain from `tip` back to (but excluding)
    /// `ancestor`, scored under `bonds` (that branch's bond set) and this network's `φS`. Uses
    /// the v3 canonical-anchor verifier (`collect_stake_contributions_v2`) with
    /// `stop_at = ancestor`, so the branch is scored only on canonical attestations for the
    /// epochs anchored strictly above the common ancestor (its OWN segment) — byte-identical to
    /// the sink-side StakeScore and immune to a branch inflating its score with non-canonical
    /// (current-sink / fabricated) targets. Inert wherever the overlay is dormant.
    fn stake_score_since_ancestor(
        &self,
        tip: BlockHash,
        ancestor: BlockHash,
        bonds: &[StakeBondRecord],
        dns_params: &DnsParams,
        net_id: &[u8],
    ) -> StakeScore {
        let (contributions, epoch_anchor_daa, _) = self.collect_stake_contributions_v2(tip, Some(ancestor), bonds, net_id, dns_params);
        let totals = total_active_stake_by_epoch(bonds, &epoch_anchor_daa);
        let per_epoch = aggregate_epoch_tallies(&contributions, &totals);
        compute_stake_score(&per_epoch, dns_params.stake_event_quality_floor_bps)
    }

    /// kaspa-pq Phase 13 (ADR-0018 §H): the selected-chain common ancestor of `a` and `b`
    /// — the first block on `a`'s selected chain (from `a` inclusive, walking back) that is
    /// also a chain-ancestor of `b`. `None` if none is found within `max_walk` (a reorg
    /// deeper than the reorg horizon is not gate-eligible — the caller rejects it).
    fn selected_chain_common_ancestor(&self, a: BlockHash, b: BlockHash, max_walk: u64) -> Option<BlockHash> {
        for (walked, block) in (0_u64..).zip(std::iter::once(a).chain(self.reachability_service.default_backward_chain_iterator(a))) {
            if walked > max_walk {
                return None;
            }
            if self.reachability_service.is_chain_ancestor_of(block, b) {
                return Some(block);
            }
        }
        None
    }

    /// kaspa-pq DNS v3 (Canonical Lagged Anchor): the canonical, blue_score-coordinated
    /// epoch anchor for `epoch` as seen from `tip`'s selected chain — the **most-recent
    /// selected-chain ancestor with `blue_score <= anchor_cutoff(epoch)`** (cutoff =
    /// `epoch_end(epoch) - backoff`). Walks the selected-parent chain from `tip`
    /// (inclusive) reading each block's header `blue_score`/`daa_score`, collecting
    /// `(hash, blue_score, daa_score)` tip-first (blue_score strictly decreasing) until it
    /// buries the *previous* epoch's cutoff (so the pure core can decide the
    /// duplicate-anchor flag) or runs past `stake_score_window_blue_score`, then defers to
    /// the pure [`canonical_lagged_epoch_anchor`] core.
    ///
    /// The selected-chain *position* is read from header-committed `blue_score`, NEVER the
    /// store index (which is store-local: archival numbers from genesis, IBD from its
    /// pruning point), so archival and IBD-synced nodes derive the identical anchor. The
    /// signer (PR3), verifier (PR4), reward path (PR5) and reorg gate all call this so they
    /// agree on which block anchors an epoch. Reads only committed header data → reorg-safe.
    ///
    /// Returns `None` when the epoch's anchor cutoff is not yet buried by the tip
    /// (`cutoff > tip.blue_score` — a future / unburied epoch has no canonical anchor on
    /// this chain yet; the degenerate "most-recent-at-or-below == tip" is suppressed) or
    /// when the chain within the window does not reach the cutoff (epoch too old to
    /// credit). The stronger `attestation_lag_blue_score` readiness gate is applied by the
    /// signer / verifier on top of this.
    pub(crate) fn canonical_anchor_by_blue_score(
        &self,
        epoch: u64,
        tip: BlockHash,
        dns_params: &DnsParams,
    ) -> Option<CanonicalLaggedEpochAnchor> {
        let epoch_len = dns_params.attestation_epoch_length_blue_score.max(1);
        let backoff = dns_params.attestation_anchor_backoff_blue_score;
        let window = dns_params.stake_score_window_blue_score;

        let tip_blue_score = self.headers_store.get_blue_score(tip).ok()?;
        // The epoch's anchor cutoff must be buried by the tip; otherwise "most-recent
        // at-or-below" would degenerate to the tip itself (a future / unburied epoch has no
        // canonical anchor on this chain yet).
        let cutoff = anchor_cutoff_blue_score(epoch, epoch_len, backoff);
        if cutoff > tip_blue_score {
            return None;
        }
        // Walk the selected-parent chain tip -> down, collecting (hash, blue, daa) until we
        // have buried the PREVIOUS epoch's cutoff (so the duplicate-anchor check is
        // decidable; for epoch 0 this coincides with this epoch's cutoff) or run past the
        // configured stake-score window. Position is read from blue_score, never the index.
        let needed = anchor_cutoff_blue_score(epoch.saturating_sub(1), epoch_len, backoff);
        let mut ancestors: Vec<(BlockHash, u64, u64)> = Vec::new();
        for hash in std::iter::once(tip).chain(self.reachability_service.default_backward_chain_iterator(tip)) {
            let compact = self.headers_store.get_compact_header_data(hash).ok()?;
            if tip_blue_score.saturating_sub(compact.blue_score) > window {
                break; // out of the stake-score window
            }
            ancestors.push((hash, compact.blue_score, compact.daa_score));
            if compact.blue_score <= needed {
                break; // buried the prev cutoff (and a fortiori this one) -> enough to decide
            }
        }
        canonical_lagged_epoch_anchor(epoch, epoch_len, backoff, &ancestors)
    }

    /// kaspa-pq DNS v3: the canonical anchors for every **creditable** epoch within the
    /// stake-score window ending at `tip`, computed in ONE selected-parent-chain walk.
    /// "Creditable" = ready (buried by `attestation_lag_blue_score`), non-duplicate
    /// (`anchor(E) != anchor(E-1)`; a sparse chain that reused the previous anchor earns no
    /// new credit), and recent enough that both `anchor_cutoff(E)` and `anchor_cutoff(E-1)`
    /// fall inside the collected window (so the duplicate flag is reliable). Older / unready
    /// / duplicate epochs are simply absent. Position comes from header-committed
    /// `blue_score`, never the store index, so archival and IBD-synced nodes agree.
    pub(crate) fn canonical_anchors_in_window(
        &self,
        tip: BlockHash,
        dns_params: &DnsParams,
    ) -> BTreeMap<u64, CanonicalLaggedEpochAnchor> {
        let epoch_len = dns_params.attestation_epoch_length_blue_score.max(1);
        let backoff = dns_params.attestation_anchor_backoff_blue_score;
        let lag = dns_params.attestation_lag_blue_score;
        let window = dns_params.stake_score_window_blue_score;

        let mut anchors: BTreeMap<u64, CanonicalLaggedEpochAnchor> = BTreeMap::new();
        let Ok(tip_blue) = self.headers_store.get_blue_score(tip) else {
            return anchors;
        };
        let Some(latest_ready) = ready_epoch_from_tip_blue_score(tip_blue, epoch_len, lag) else {
            return anchors; // no epoch buried by `lag` yet
        };

        // One walk: collect the selected chain tip-first down to the window bound.
        let mut ancestors: Vec<(BlockHash, u64, u64)> = Vec::new();
        for hash in std::iter::once(tip).chain(self.reachability_service.default_backward_chain_iterator(tip)) {
            let Ok(c) = self.headers_store.get_compact_header_data(hash) else {
                break;
            };
            if tip_blue.saturating_sub(c.blue_score) > window {
                break;
            }
            ancestors.push((hash, c.blue_score, c.daa_score));
        }
        let oldest_blue = ancestors.last().map(|a| a.1).unwrap_or(tip_blue);

        // From the latest ready epoch downward, derive each epoch's anchor over the shared
        // ancestor slice; stop once the PREVIOUS epoch's cutoff falls below the collected
        // window (older epochs aren't reliably decidable, hence not creditable). Skip
        // duplicates (no new credit).
        let mut epoch = latest_ready;
        loop {
            let prev_cutoff = anchor_cutoff_blue_score(epoch.saturating_sub(1), epoch_len, backoff);
            if prev_cutoff < oldest_blue {
                break;
            }
            if let Some(anchor) = canonical_lagged_epoch_anchor(epoch, epoch_len, backoff, &ancestors)
                && !anchor.duplicate_of_previous_anchor
            {
                anchors.insert(epoch, anchor);
            }
            if epoch == 0 {
                break;
            }
            epoch -= 1;
        }
        anchors
    }

    /// kaspa-pq DNS v3 verifier: collect + verify the stake attestations on the selected
    /// chain ending at `tip`, crediting an attestation ONLY if it targets THIS chain's
    /// canonical anchor for its epoch (**GoodAttestation v3**): `att.target_hash` and
    /// `att.target_daa_score` equal the canonical `(anchor_hash, anchor_daa_score)` for
    /// `att.epoch`, the bond is `Active` at the canonical anchor DAA, the self-declared
    /// `validator_id` is bound to the bond (P-1A), and the ML-DSA-87 signature verifies under
    /// `ATTESTATION_MLDSA87_CONTEXT`. The per-epoch denominator (`epoch_anchor_daa`) is keyed
    /// by the CANONICAL anchor DAA (not the v1 first-seen self-reported value) and includes
    /// every creditable (ready, non-duplicate) epoch in the window — **even those with zero
    /// attestations** — so a participation gap is visible to φS / DnsHealth instead of
    /// silently vanishing (the v1 weakness that let honest validators signing divergent
    /// current-sink targets all fall below the φS floor).
    ///
    /// Replaces the v1 self-reported-target `collect_stake_contributions` for the sink-side
    /// StakeScore. For a branch segment (reorg gate, `stop_at = Some(I)`) it credits only
    /// epochs anchored strictly above the common ancestor `I` (the shared prefix belongs to
    /// neither branch's since-`I` delta); the reorg gate itself is migrated to this path in
    /// PR6 (it stays on v1 until then — inert, Active-only). Reads only committed acceptance
    /// + header data, so it is deterministic and reorg-safe; inert wherever the overlay is
    /// dormant.
    pub(crate) fn collect_stake_contributions_v2(
        &self,
        tip: BlockHash,
        stop_at: Option<BlockHash>,
        bonds: &[StakeBondRecord],
        net_id: &[u8],
        dns_params: &DnsParams,
    ) -> (Vec<AttestationContribution>, BTreeMap<u64, u64>, Vec<(TransactionOutpoint, u64)>) {
        // Canonical anchors for the creditable epoch window, computed from THIS chain's tip.
        let anchors = self.canonical_anchors_in_window(tip, dns_params);
        // For a branch segment (`stop_at = Some(I)`), credit only epochs anchored strictly
        // above `I`; the sink-side path (`None`) keeps them all.
        let creditable: BTreeMap<u64, CanonicalLaggedEpochAnchor> = anchors
            .into_iter()
            .filter(|(_, a)| match stop_at {
                Some(i) => a.anchor_hash != i && !self.reachability_service.is_chain_ancestor_of(a.anchor_hash, i),
                None => true,
            })
            .collect();
        let epoch_anchor_daa: BTreeMap<u64, u64> = creditable.iter().map(|(&e, a)| (e, a.anchor_daa_score)).collect();

        let mut contributions: Vec<AttestationContribution> = Vec::new();
        // Dormancy Fence (PR-D4): signature-verified, canonical attestations naming
        // a *Dormant* bond — the accepted-but-uncredited revival signal. Always empty
        // when the fence is inert (no bond is ever Dormant), so credit is unchanged.
        let mut revival_signals: Vec<(TransactionOutpoint, u64)> = Vec::new();
        let Ok(tip_blue) = self.headers_store.get_blue_score(tip) else {
            return (contributions, epoch_anchor_daa, revival_signals);
        };
        for chain_block in self.reachability_service.default_backward_chain_iterator(tip) {
            if Some(chain_block) == stop_at {
                break;
            }
            let Ok(bs) = self.headers_store.get_blue_score(chain_block) else {
                break;
            };
            if tip_blue.saturating_sub(bs) > dns_params.stake_score_window_blue_score {
                break;
            }
            let txs = self.accepted_txs_of_chain_block(chain_block);
            for att in attestations_from_accepted_txs(&txs) {
                // v3 canonical gate: the attestation must name THIS chain's canonical anchor
                // for its epoch, and that epoch must be creditable (ready, non-duplicate,
                // in-window — i.e. present in `creditable`).
                let Some(anchor) = creditable.get(&att.epoch) else {
                    continue;
                };
                if att.target_hash != anchor.anchor_hash || att.target_daa_score != anchor.anchor_daa_score {
                    continue;
                }
                let Some(bond) = bonds.iter().find(|b| b.bond_outpoint == att.bond_outpoint) else {
                    continue;
                };
                // P-1A: the self-declared validator_id (not in the signed digest) must be
                // bound to the bond, else varying it would evade the dedup + inflate stake.
                if att.validator_id != bond.validator_pubkey_hash {
                    continue;
                }
                // The bond must be Active OR Dormant at the CANONICAL anchor DAA (==
                // att.target_daa_score by the gate above), not a self-reported / current
                // value. Active bonds are credited; Dormant bonds (Dormancy Fence, D4)
                // yield only a revival signal — never credit. Pending/Unbonding/Slashed skip.
                let status = effective_bond_status(bond, anchor.anchor_daa_score);
                if !matches!(status, BondStatus::Active | BondStatus::Dormant) {
                    continue;
                }
                let digest = stake_attestation_message(
                    net_id,
                    att.epoch,
                    att.target_hash,
                    att.target_daa_score,
                    att.validator_set_commitment,
                    att.bond_outpoint,
                )
                .as_bytes();
                if matches!(
                    verify_mldsa87_with_context(&bond.validator_pubkey, &digest, &att.signature, ATTESTATION_MLDSA87_CONTEXT),
                    Ok(true)
                ) {
                    if status == BondStatus::Active {
                        contributions.push(AttestationContribution {
                            epoch: att.epoch,
                            validator_id: att.validator_id,
                            bond_outpoint: att.bond_outpoint,
                            signed_stake_sompi: bond.amount,
                        });
                    } else {
                        // Dormant: registry-only revival signal (design §4.5), no credit.
                        revival_signals.push((att.bond_outpoint, att.epoch));
                    }
                }
            }
        }
        (contributions, epoch_anchor_daa, revival_signals)
    }

    /// kaspa-pq Phase 10/13 (ADR-0009 §"Decision" / ADR-0018 §H): the DNS finality reorg
    /// gate. Returns `true` (candidate sink allowed) unless the overlay is configured, in
    /// the `Active` rollout stage, has a confirmed anchor, and `candidate` would abandon
    /// that anchor's selected chain. **Inert** on every current network (`dns_params` is
    /// `None`) and outside the `Active` stage.
    ///
    /// `reorg_mode` (per-network, ADR-0018 §H) selects the rule when a candidate exits the
    /// confirmed prefix:
    /// - `HardCheckpoint` (PoC/testnet/devnet): reject any such exit.
    /// - `TwoDimensionalDominance` (mainnet): accept only if the candidate **strictly
    ///   out-Works AND out-Stakes** canonical since their common ancestor `I`, each by its
    ///   emergency margin (non-substitutability — neither dimension alone suffices).
    ///
    /// Safety: each branch's StakeScore-since-`I` is scored under **its own** bond set —
    /// `candidate_bond_view` (the sink-search view already advanced to `candidate`) for the
    /// candidate, and the persisted `stake_bonds_store` (still at `prev_sink`, because the
    /// bond store is written only at the final virtual commit, never during this sink
    /// search) for canonical. Scoring a branch under the wrong view could over-credit it
    /// and wrongly accept a confirmed-history-abandoning reorg. Both branches' acceptance
    /// data is committed by the time the gate runs (the candidate's by
    /// `calculate_utxo_state_relatively`), so the per-branch walks are deterministic.
    fn dns_reorg_allows(&self, candidate: BlockHash, prev_sink: BlockHash, candidate_bond_view: &ActiveBondView) -> bool {
        let Some(dns_params) = self.dns_params.as_ref() else {
            return true;
        };
        let Ok(state) = self.dns_state_store.read().get() else {
            return true; // no DnsState written yet
        };
        if state.rollout_stage != DnsRolloutStage::Active {
            return true; // gate dormant outside the Active stage
        }
        let confirmed = state.last_dns_confirmed_anchor;
        if confirmed == BlockHash::default() {
            return true; // nothing confirmed yet
        }
        let includes = match self.reachability_service.try_is_chain_ancestor_of(confirmed, candidate) {
            Ok(v) => v,
            Err(_) => {
                debug!(
                    "DNS reorg gate: confirmed anchor {confirmed} has no reachability (behind the pruning point - attestation stalled?); gate is a no-op, subsumed by pruning-point finality"
                );
                true
            }
        };

        // The heavy two-dimensional inputs (common ancestor + per-branch Work/Stake walks)
        // are computed ONLY when the candidate abandons the confirmed prefix AND the
        // network runs the mainnet dominance rule. HardCheckpoint and the includes-anchor
        // case ignore Work/Stake, so they skip the walks entirely.
        let inputs = if dns_params.reorg_mode == DnsReorgMode::TwoDimensionalDominance && !includes {
            // Selected-chain common ancestor I. Beyond the reorg horizon → not gate-eligible;
            // reject (a reorg deeper than the horizon cannot rewrite confirmed history).
            let Some(ancestor) = self.selected_chain_common_ancestor(candidate, prev_sink, dns_params.max_reorg_horizon_blocks) else {
                return false;
            };
            let net_id_hash = self.genesis.hash;
            let net_id = net_id_hash.as_byte_slice();
            // Per-branch bond sets (safety — each branch under its OWN view; see doc comment).
            let candidate_bonds = candidate_bond_view.records();
            let canonical_bonds: Vec<StakeBondRecord> =
                self.stake_bonds_store.read().iterator().filter_map(|r| r.ok().map(|(_, rec)| (*rec).clone())).collect();
            reorg_inputs_since_common_ancestor(
                state.rollout_stage,
                dns_params.reorg_mode,
                includes,
                self.ghostdag_store.get_blue_work(candidate).unwrap_or_default(),
                self.ghostdag_store.get_blue_work(prev_sink).unwrap_or_default(),
                self.ghostdag_store.get_blue_work(ancestor).unwrap_or_default(),
                self.stake_score_since_ancestor(candidate, ancestor, &candidate_bonds, dns_params, net_id),
                self.stake_score_since_ancestor(prev_sink, ancestor, &canonical_bonds, dns_params, net_id),
                dns_params.emergency_work_margin,
                dns_params.emergency_stake_margin,
            )
        } else {
            // HardCheckpoint, or candidate keeps the confirmed anchor: Work/Stake unused.
            reorg_inputs_since_common_ancestor(
                state.rollout_stage,
                dns_params.reorg_mode,
                includes,
                BlueWorkType::from_u64(0),
                BlueWorkType::from_u64(0),
                BlueWorkType::from_u64(0),
                StakeScore(0),
                StakeScore(0),
                dns_params.emergency_work_margin,
                dns_params.emergency_stake_margin,
            )
        };
        check_dns_reorg_rule(&inputs).is_accept()
    }

    /// Caches the DAA and Median time windows of the sink block (if needed). Following, virtual's window calculations will
    /// naturally hit the cache finding the sink's windows and building upon them.
    fn cache_sink_windows(
        &self,
        new_sink: BlockHash,
        prev_sink: BlockHash,
        sink_ghostdag_data: &impl Deref<Target = Arc<GhostdagData>>,
    ) {
        // We expect that the `new_sink` is cached (or some close-enough ancestor thereof) if it is equal to the `prev_sink`,
        // Hence we short-circuit the check of the keys in such cases, thereby reducing the access of the read-lock
        if new_sink != prev_sink {
            // this is only important for ibd performance, as we incur expensive cache misses otherwise.
            // this occurs because we cannot rely on header processing to pre-cache in this scenario.
            if !self.block_window_cache_for_difficulty.contains_key(&new_sink) {
                self.block_window_cache_for_difficulty
                    .insert(new_sink, self.window_manager.block_daa_window(sink_ghostdag_data.deref()).unwrap().window);
            };

            if !self.block_window_cache_for_past_median_time.contains_key(&new_sink) {
                self.block_window_cache_for_past_median_time
                    .insert(new_sink, self.window_manager.calc_past_median_time(sink_ghostdag_data.deref()).unwrap().1);
            };
        }
    }

    /// Returns the max number of tips to consider as virtual parents in a single virtual resolve operation.
    ///
    /// Guaranteed to be `>= self.max_block_parents`
    fn max_virtual_parent_candidates(&self, max_block_parents: usize) -> usize {
        // Limit to max_block_parents x 3 candidates. This way we avoid going over thousands of tips when the network isn't healthy.
        // There's no specific reason for a factor of 3, and its not a consensus rule, just an estimation for reducing the amount
        // of candidates considered.
        max_block_parents * 3
    }

    /// Searches for the next valid sink block (SINK = Virtual selected parent). The search is performed
    /// in the inclusive past of `tips`.
    /// The provided `diff` is assumed to initially hold the UTXO diff of `prev_sink` from virtual.
    /// The function returns with `diff` being the diff of the new sink from previous virtual.
    /// In addition to the found sink the function also returns a queue of additional virtual
    /// parent candidates ordered in descending blue work order.
    pub(super) fn sink_search_algorithm(
        &self,
        stores: &VirtualStores,
        diff: &mut UtxoDiff,
        bond_view: &mut ActiveBondView,
        provider_bond_view: &mut ProviderBondView,
        prev_sink: BlockHash,
        tips: Vec<BlockHash>,
        finality_point: BlockHash,
        pruning_point: BlockHash,
    ) -> (BlockHash, VecDeque<BlockHash>) {
        // TODO (relaxed): additional tests

        let mut heap = tips
            .into_iter()
            .map(|block| SortableBlock { hash: block, blue_work: self.ghostdag_store.get_blue_work(block).unwrap() })
            .collect::<BinaryHeap<_>>();

        // The initial diff point is the previous sink
        let mut diff_point = prev_sink;

        // We maintain the following invariant: `heap` is an antichain.
        // It holds at step 0 since tips are an antichain, and remains through the loop
        // since we check that every pushed block is not in the past of current heap
        // (and it can't be in the future by induction)
        loop {
            let candidate = heap.pop().expect("valid sink must exist").hash;
            // QR reachability hardening: skip a candidate whose reachability is missing (half-pruned)
            // instead of panicking; it is below finality and recovery will complete the prune. Consensus-neutral.
            let candidate_at_or_above_finality = match self.reachability_service.try_is_chain_ancestor_of(finality_point, candidate) {
                Ok(v) => v,
                Err(_) => {
                    debug!(
                        "sink_search: candidate {candidate} has no reachability vs finality {finality_point} (half-pruned?); skipping"
                    );
                    false
                }
            };
            if candidate_at_or_above_finality {
                diff_point = self.calculate_utxo_state_relatively(stores, diff, bond_view, provider_bond_view, diff_point, candidate);
                if diff_point == candidate {
                    // This indicates that candidate has valid UTXO state and that `diff` represents its diff from virtual

                    // kaspa-pq Phase 10 (ADR-0009): the DNS finality reorg gate. Inert
                    // unless the overlay is configured and in the Active stage; it then
                    // rejects a candidate that would abandon a DNS-confirmed anchor. The
                    // rejection is soft — we fall through to push the candidate's parents
                    // and continue, converging on a DNS-valid sink (mirrors the
                    // invalid-UTXO handling below).
                    if self.dns_reorg_allows(candidate, prev_sink, bond_view) {
                        // All blocks with lower blue work than filtering_root are:
                        // 1. not in its future (bcs blue work is monotonic),
                        // 2. will be removed eventually by the bounded merge check.
                        // Hence as an optimization we prefer removing such blocks in advance to allow valid tips to be considered.
                        let filtering_root = self.depth_store.merge_depth_root(candidate).unwrap();
                        let filtering_blue_work = self.ghostdag_store.get_blue_work(filtering_root).unwrap_or_default();
                        return (
                            candidate,
                            heap.into_sorted_iter().take_while(|s| s.blue_work >= filtering_blue_work).map(|s| s.hash).collect(),
                        );
                    }
                    debug!("Block candidate {} rejected by the DNS finality reorg gate; ignored from Virtual chain.", candidate);
                } else {
                    debug!("Block candidate {} has invalid UTXO state and is ignored from Virtual chain.", candidate)
                }
            } else if finality_point != pruning_point {
                // `finality_point == pruning_point` indicates we are at IBD start hence no warning required
                warn!("Finality Violation Detected. Block {} violates finality and is ignored from Virtual chain.", candidate);
            }
            // PRUNE SAFETY: see comment within [`resolve_virtual`]
            let prune_guard = self.pruning_lock.blocking_read();
            for parent in self.relations_service.get_parents(candidate).unwrap().iter().copied() {
                if self.reachability_service.is_dag_ancestor_of(finality_point, parent)
                    && !self.reachability_service.is_dag_ancestor_of_any(parent, &mut heap.iter().map(|sb| sb.hash))
                {
                    heap.push(SortableBlock { hash: parent, blue_work: self.ghostdag_store.get_blue_work(parent).unwrap() });
                }
            }
            drop(prune_guard);
        }
    }

    /// Picks the virtual parents according to virtual parent selection pruning constrains.
    /// Assumes:
    ///     1. `selected_parent` is a UTXO-valid block
    ///     2. `candidates` are an antichain ordered in descending blue work order
    ///     3. `candidates` do not contain `selected_parent` and `selected_parent.blue work > max(candidates.blue_work)`  
    pub(super) fn pick_virtual_parents(
        &self,
        selected_parent: BlockHash,
        mut candidates: VecDeque<BlockHash>,
        pruning_point: BlockHash,
    ) -> (Vec<BlockHash>, GhostdagData) {
        // TODO (relaxed): additional tests

        // Mergeset increasing might traverse DAG areas which are below the finality point and which theoretically
        // can borderline with pruned data, hence we acquire the prune lock to ensure data consistency. Note that
        // the final selected mergeset can never be pruned (this is the essence of the prunality proof), however
        // we might touch such data prior to validating the bounded merge rule. All in all, this function is short
        // enough so we avoid making further optimizations
        let _prune_guard = self.pruning_lock.blocking_read();
        let max_block_parents = self.max_block_parents as usize;
        let mergeset_size_limit = self.mergeset_size_limit;
        let max_candidates = self.max_virtual_parent_candidates(max_block_parents);

        // Prioritize half the blocks with highest blue work and pick the rest randomly to ensure diversity between nodes
        if candidates.len() > max_candidates {
            // make_contiguous should be a no op since the deque was just built
            let slice = candidates.make_contiguous();

            // Keep slice[..max_block_parents / 2] as is, choose max_candidates - max_block_parents / 2 in random
            // from the remainder of the slice while swapping them to slice[max_block_parents / 2..max_candidates].
            //
            // Inspired by rand::partial_shuffle (which lacks the guarantee on chosen elements location).
            for i in max_block_parents / 2..max_candidates {
                let j = rand::thread_rng().gen_range(i..slice.len()); // i < max_candidates < slice.len()
                slice.swap(i, j);
            }

            // Truncate the unchosen elements
            candidates.truncate(max_candidates);
        } else if candidates.len() > max_block_parents / 2 {
            // Fallback to a simpler algo in this case
            candidates.make_contiguous()[max_block_parents / 2..].shuffle(&mut rand::thread_rng());
        }

        let mut virtual_parents = Vec::with_capacity(min(max_block_parents, candidates.len() + 1));
        virtual_parents.push(selected_parent);
        let mut mergeset_size = 1; // Count the selected parent

        // Try adding parents as long as mergeset size and number of parents limits are not reached
        while let Some(candidate) = candidates.pop_front() {
            if mergeset_size >= mergeset_size_limit || virtual_parents.len() >= max_block_parents {
                break;
            }
            match self.mergeset_increase(&virtual_parents, candidate, mergeset_size_limit - mergeset_size) {
                MergesetIncreaseResult::Accepted { increase_size } => {
                    mergeset_size += increase_size;
                    virtual_parents.push(candidate);
                }
                MergesetIncreaseResult::Rejected { new_candidate } => {
                    // If we already have a candidate in the past of new candidate then skip.
                    if self.reachability_service.is_any_dag_ancestor(&mut candidates.iter().copied(), new_candidate) {
                        continue; // TODO (optimization): not sure this check is needed if candidates invariant as antichain is kept
                    }
                    // Remove all candidates which are in the future of the new candidate
                    candidates.retain(|&h| !self.reachability_service.is_dag_ancestor_of(new_candidate, h));
                    candidates.push_back(new_candidate);
                }
            }
        }
        assert!(mergeset_size <= mergeset_size_limit);
        assert!(virtual_parents.len() <= max_block_parents);
        self.remove_bounded_merge_breaking_parents(virtual_parents, pruning_point)
    }

    fn mergeset_increase(&self, selected_parents: &[BlockHash], candidate: BlockHash, budget: u64) -> MergesetIncreaseResult {
        /*
        Algo:
            Traverse past(candidate) \setminus past(selected_parents) and make
            sure the increase in mergeset size is within the available budget
        */

        let candidate_parents = self.relations_service.get_parents(candidate).unwrap();
        let mut queue: VecDeque<_> = candidate_parents.iter().copied().collect();
        let mut visited: BlockHashSet = queue.iter().copied().collect();
        let mut mergeset_increase = 1u64; // Starts with 1 to count for the candidate itself

        while let Some(current) = queue.pop_front() {
            if self.reachability_service.is_dag_ancestor_of_any(current, &mut selected_parents.iter().copied()) {
                continue;
            }
            mergeset_increase += 1;
            if mergeset_increase > budget {
                return MergesetIncreaseResult::Rejected { new_candidate: current };
            }

            let current_parents = self.relations_service.get_parents(current).unwrap();
            for &parent in current_parents.iter() {
                if visited.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }
        MergesetIncreaseResult::Accepted { increase_size: mergeset_increase }
    }

    fn remove_bounded_merge_breaking_parents(
        &self,
        mut virtual_parents: Vec<BlockHash>,
        current_pruning_point: BlockHash,
    ) -> (Vec<BlockHash>, GhostdagData) {
        let mut ghostdag_data = self.ghostdag_manager.ghostdag(&virtual_parents);
        let merge_depth_root = self.depth_manager.calc_merge_depth_root(&ghostdag_data, current_pruning_point);
        let mut kosherizing_blues: Option<Vec<BlockHash>> = None;
        let mut bad_reds = Vec::new();

        //
        // Note that the code below optimizes for the usual case where there are no merge-bound-violating blocks.
        //

        // Find red blocks violating the merge bound and which are not kosherized by any blue
        for red in ghostdag_data.mergeset_reds.iter().copied() {
            if self.reachability_service.is_dag_ancestor_of(merge_depth_root, red) {
                continue;
            }
            // Lazy load the kosherizing blocks since this case is extremely rare
            if kosherizing_blues.is_none() {
                kosherizing_blues = Some(self.depth_manager.kosherizing_blues(&ghostdag_data, merge_depth_root).collect());
            }
            if !self.reachability_service.is_dag_ancestor_of_any(red, &mut kosherizing_blues.as_ref().unwrap().iter().copied()) {
                bad_reds.push(red);
            }
        }

        if !bad_reds.is_empty() {
            // Remove all parents which lead to merging a bad red
            virtual_parents.retain(|&h| !self.reachability_service.is_any_dag_ancestor(&mut bad_reds.iter().copied(), h));
            // Recompute ghostdag data since parents changed
            ghostdag_data = self.ghostdag_manager.ghostdag(&virtual_parents);
        }

        (virtual_parents, ghostdag_data)
    }

    fn validate_mempool_transaction_impl(
        &self,
        mutable_tx: &mut MutableTransaction,
        virtual_utxo_view: &impl UtxoView,
        virtual_daa_score: u64,
        virtual_past_median_time: u64,
        args: &TransactionValidationArgs,
    ) -> TxResult<()> {
        self.transaction_validator.validate_tx_in_isolation(&mutable_tx.tx)?;
        self.validate_palw_overlay_activation(&mutable_tx.tx, virtual_daa_score)?;
        self.transaction_validator.validate_tx_in_header_context_with_args(
            &mutable_tx.tx,
            virtual_daa_score,
            virtual_past_median_time,
        )?;
        self.validate_mempool_transaction_in_utxo_context(mutable_tx, virtual_utxo_view, virtual_daa_score, args)?;
        Ok(())
    }

    pub fn validate_mempool_transaction(&self, mutable_tx: &mut MutableTransaction, args: &TransactionValidationArgs) -> TxResult<()> {
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_utxo_view = &virtual_read.utxo_set;
        let virtual_daa_score = virtual_state.daa_score;
        let virtual_past_median_time = virtual_state.past_median_time;
        // Run within the thread pool since par_iter might be internally applied to inputs
        self.thread_pool.install(|| {
            self.validate_mempool_transaction_impl(mutable_tx, virtual_utxo_view, virtual_daa_score, virtual_past_median_time, args)
        })
    }

    pub fn validate_mempool_transactions_in_parallel(
        &self,
        mutable_txs: &mut [MutableTransaction],
        args: &TransactionValidationBatchArgs,
    ) -> Vec<TxResult<()>> {
        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_utxo_view = &virtual_read.utxo_set;
        let virtual_daa_score = virtual_state.daa_score;
        let virtual_past_median_time = virtual_state.past_median_time;

        self.thread_pool.install(|| {
            mutable_txs
                .par_iter_mut()
                .map(|mtx| {
                    self.validate_mempool_transaction_impl(
                        mtx,
                        &virtual_utxo_view,
                        virtual_daa_score,
                        virtual_past_median_time,
                        args.get(&mtx.id()),
                    )
                })
                .collect::<Vec<TxResult<()>>>()
        })
    }

    fn populate_mempool_transaction_impl(
        &self,
        mutable_tx: &mut MutableTransaction,
        virtual_utxo_view: &impl UtxoView,
    ) -> TxResult<()> {
        self.populate_mempool_transaction_in_utxo_context(mutable_tx, virtual_utxo_view)?;
        Ok(())
    }

    pub fn populate_mempool_transaction(&self, mutable_tx: &mut MutableTransaction) -> TxResult<()> {
        let virtual_read = self.virtual_stores.read();
        let virtual_utxo_view = &virtual_read.utxo_set;
        self.populate_mempool_transaction_impl(mutable_tx, virtual_utxo_view)
    }

    pub fn populate_mempool_transactions_in_parallel(&self, mutable_txs: &mut [MutableTransaction]) -> Vec<TxResult<()>> {
        let virtual_read = self.virtual_stores.read();
        let virtual_utxo_view = &virtual_read.utxo_set;
        self.thread_pool.install(|| {
            mutable_txs
                .par_iter_mut()
                .map(|mtx| self.populate_mempool_transaction_impl(mtx, &virtual_utxo_view))
                .collect::<Vec<TxResult<()>>>()
        })
    }

    fn validate_block_template_transactions_in_parallel<V: UtxoView + Sync>(
        &self,
        txs: &[Transaction],
        virtual_state: &VirtualState,
        utxo_view: &V,
    ) -> Vec<TxResult<u64>> {
        self.thread_pool
            .install(|| txs.par_iter().map(|tx| self.validate_block_template_transaction(tx, virtual_state, &utxo_view)).collect())
    }

    fn validate_block_template_transaction(
        &self,
        tx: &Transaction,
        virtual_state: &VirtualState,
        utxo_view: &impl UtxoView,
    ) -> TxResult<u64> {
        // No need to validate the transaction in isolation since we rely on the mining manager to submit transactions
        // which were previously validated through `validate_mempool_transaction_and_populate`, hence we only perform
        // in-context validations
        self.validate_palw_overlay_activation(tx, virtual_state.daa_score)?;
        self.transaction_validator.validate_tx_in_header_context_with_args(
            tx,
            virtual_state.daa_score,
            virtual_state.past_median_time,
        )?;
        let ValidatedTransaction { calculated_fee, .. } =
            // `None`, `None`, `None`: mempool/template single-tx context, not mergeset acceptance (the
            // bond spend-gate, the provider-unbond authorization filter, and the provider-bond spend
            // gate are all acceptance-time only, inert here).
            self.validate_transaction_in_utxo_context(tx, utxo_view, virtual_state.daa_score, TxValidationFlags::Full, None, None, None)?;
        Ok(calculated_fee)
    }

    /// Isolation can decode the future PALW wire format without a chain POV, but neither the mempool
    /// nor template construction may admit those reserved subnetworks before the hard fork. Keep this
    /// predicate shared by both paths so a locally constructed template cannot fail its own body
    /// contextual validation.
    fn validate_palw_overlay_activation(&self, tx: &Transaction, pov_daa_score: u64) -> TxResult<()> {
        if pov_daa_score < self.palw_activation_daa_score && tx.subnetwork_id.palw_tx_kind().is_some() {
            return Err(TxRuleError::SubnetworksDisabled(tx.subnetwork_id.clone()));
        }
        Ok(())
    }

    fn latest_ready_epoch_for_template_snapshot(&self, virtual_state: &VirtualState) -> Option<u64> {
        let dns_params = self.dns_params.as_ref()?;
        ready_epoch_from_tip_blue_score(
            virtual_state.ghostdag_data.blue_score,
            dns_params.attestation_epoch_length_blue_score,
            dns_params.attestation_lag_blue_score,
        )
    }

    pub(crate) fn mandatory_attestation_deficits_for_template_snapshot(
        &self,
        selected_parent: BlockHash,
        daa_score: u64,
        selected_parent_bond_view: &ActiveBondView,
        candidate_accepted_txs: &[Transaction],
    ) -> Vec<MandatoryAttestationDeficit> {
        let Some(dns_params) = self.dns_params.as_ref() else {
            return Vec::new();
        };
        if daa_score < dns_params.dns_activation_daa_score
            || daa_score < dns_params.mandatory_attestation_inclusion_daa_score
            || !dns_params.dns_v3_params_consistent()
        {
            return Vec::new();
        }

        let anchors = self.canonical_anchors_in_window(selected_parent, dns_params);
        if anchors.is_empty() {
            return Vec::new();
        }

        let bonds = selected_parent_bond_view.records();
        let (parent_contributions, _, _) =
            self.collect_stake_contributions_v2(selected_parent, None, &bonds, self.genesis.hash.as_byte_slice(), dns_params);
        let mut seen_parent: HashSet<(kaspa_consensus_core::tx::TransactionOutpoint, kaspa_consensus_core::Hash64, u64)> =
            HashSet::new();
        let mut seen_candidate: HashSet<(kaspa_consensus_core::tx::TransactionOutpoint, kaspa_consensus_core::Hash64, u64)> =
            HashSet::new();
        let mut signed_by_epoch: HashMap<u64, u64> = HashMap::new();
        let mut contributed_by_epoch: HashMap<u64, Vec<MandatoryAttestationContributionKey>> = HashMap::new();
        for c in parent_contributions {
            let key = (c.bond_outpoint, c.validator_id, c.epoch);
            if !seen_parent.insert(key) {
                continue;
            }
            let entry = signed_by_epoch.entry(c.epoch).or_insert(0);
            *entry = entry.saturating_add(c.signed_stake_sompi);
            contributed_by_epoch.entry(c.epoch).or_default().push(MandatoryAttestationContributionKey {
                bond_outpoint: c.bond_outpoint,
                validator_id: c.validator_id,
                epoch: c.epoch,
            });
        }

        let bond_by_outpoint: HashMap<_, _> = bonds.iter().map(|b| (b.bond_outpoint, b)).collect();
        for att in attestations_from_accepted_txs(candidate_accepted_txs) {
            let Some(anchor) = anchors.get(&att.epoch) else {
                continue;
            };
            if att.target_hash != anchor.anchor_hash || att.target_daa_score != anchor.anchor_daa_score {
                continue;
            }
            let key = (att.bond_outpoint, att.validator_id, att.epoch);
            if seen_parent.contains(&key) || !seen_candidate.insert(key) {
                continue;
            }
            let Some(bond) = bond_by_outpoint.get(&att.bond_outpoint) else {
                continue;
            };
            if att.validator_id != bond.validator_pubkey_hash || !is_bond_active_at(bond, anchor.anchor_daa_score) {
                continue;
            }
            let digest = stake_attestation_message(
                self.genesis.hash.as_byte_slice(),
                att.epoch,
                att.target_hash,
                att.target_daa_score,
                att.validator_set_commitment,
                att.bond_outpoint,
            )
            .as_bytes();
            if !matches!(
                verify_mldsa87_with_context(&bond.validator_pubkey, &digest, &att.signature, ATTESTATION_MLDSA87_CONTEXT),
                Ok(true)
            ) {
                continue;
            }
            let entry = signed_by_epoch.entry(att.epoch).or_insert(0);
            *entry = entry.saturating_add(bond.amount);
            contributed_by_epoch.entry(att.epoch).or_default().push(MandatoryAttestationContributionKey {
                bond_outpoint: att.bond_outpoint,
                validator_id: att.validator_id,
                epoch: att.epoch,
            });
        }

        let mut deficits = Vec::new();
        for (&epoch, anchor) in &anchors {
            let mut active_validators: Vec<_> = bonds
                .iter()
                .filter(|bond| is_bond_active_at(bond, anchor.anchor_daa_score))
                .map(|bond| MandatoryAttestationValidator {
                    bond_outpoint: bond.bond_outpoint,
                    validator_id: bond.validator_pubkey_hash,
                    stake_sompi: bond.amount,
                })
                .collect();
            active_validators.sort_by(|a, b| {
                a.validator_id
                    .cmp(&b.validator_id)
                    .then(a.bond_outpoint.transaction_id.cmp(&b.bond_outpoint.transaction_id))
                    .then(a.bond_outpoint.index.cmp(&b.bond_outpoint.index))
            });

            let expected_stake = active_validators.iter().fold(0u64, |acc, v| acc.saturating_add(v.stake_sompi));
            if expected_stake == 0
                || expected_stake < dns_params.min_active_stake_sompi
                || (active_validators.len() as u32) < dns_params.min_active_validators
            {
                continue;
            }

            let included_stake = signed_by_epoch.get(&epoch).copied().unwrap_or(0);
            if epoch_meets_quality_floor(included_stake as u128, expected_stake as u128, dns_params.stake_event_quality_floor_bps) {
                continue;
            }

            let required_stake = required_stake_for_quality_floor(expected_stake, dns_params.stake_event_quality_floor_bps);
            deficits.push(MandatoryAttestationDeficit {
                epoch,
                target_hash: anchor.anchor_hash,
                target_daa_score: anchor.anchor_daa_score,
                validator_set_commitment: kaspa_consensus_core::Hash64::default(),
                pre_body_included_stake: included_stake,
                expected_stake,
                required_stake,
                required_stake_delta: required_stake.saturating_sub(included_stake),
                quality_floor_bps: dns_params.stake_event_quality_floor_bps,
                already_contributed: contributed_by_epoch.remove(&epoch).unwrap_or_default(),
                active_validators,
            });
        }

        deficits
    }

    pub fn build_block_template(
        &self,
        miner_data: MinerData,
        tx_selector: Box<dyn TemplateTransactionSelector>,
        build_mode: TemplateBuildMode,
        // kaspa-pq EVM Lane v0.4 (§15 step 6 / §16): the node's own payload
        // candidates + declared EVM coinbase. Assembled into the template
        // payload by `evm_template_fields`; ignored pre-activation.
        evm_template_data: kaspa_consensus_core::evm::EvmTemplateData,
    ) -> Result<BlockTemplate, RuleError> {
        self.build_block_template_with_selector_provider(miner_data, build_mode, evm_template_data, move |_, _| tx_selector)
    }

    pub fn build_block_template_with_selector_factory(
        &self,
        miner_data: MinerData,
        tx_selector_factory: &dyn TemplateTransactionSelectorFactory,
        build_mode: TemplateBuildMode,
        evm_template_data: kaspa_consensus_core::evm::EvmTemplateData,
    ) -> Result<BlockTemplate, RuleError> {
        self.build_block_template_with_selector_provider(miner_data, build_mode, evm_template_data, |latest_ready_epoch, deficits| {
            tx_selector_factory.build_selector(latest_ready_epoch, deficits)
        })
    }

    fn build_block_template_with_selector_provider<F>(
        &self,
        miner_data: MinerData,
        build_mode: TemplateBuildMode,
        evm_template_data: kaspa_consensus_core::evm::EvmTemplateData,
        tx_selector_provider: F,
    ) -> Result<BlockTemplate, RuleError>
    where
        F: FnOnce(Option<u64>, &[MandatoryAttestationDeficit]) -> Box<dyn TemplateTransactionSelector>,
    {
        //
        // TODO (relaxed): additional tests
        //

        let virtual_read = self.virtual_stores.read();
        let virtual_state = virtual_read.state.get().unwrap();
        let virtual_utxo_view = &virtual_read.utxo_set;

        // kaspa-pq DNS-finality (E3/§6.2): capture the template's as-of-selected-parent
        // bond view INSIDE the same read lock as `virtual_state`, BEFORE the selection
        // loop, so each selected `StakeAttestationShard` tx can be classified for
        // §B.4 eligibility AT SELECTION TIME (instead of the old late `retain` that ran
        // after selection/validation and could not refill). The template extends the
        // current tip, so the bond set as-of its selected parent is the `StakeBonds`
        // store snapshot (= state at the sink) — `initial_active_bond_view`. Reused
        // below for the reward fan-out + overlay commitment (one coherent generation).
        // Inert (every tx `KeepNonShard`) below the activation gate, so non-overlay nets
        // are byte-identical to before.
        let template_bond_view = self.initial_active_bond_view();
        let candidate_accepted_txs = self.accepted_txs_from_virtual_state(&virtual_state);
        let latest_ready_epoch = self.latest_ready_epoch_for_template_snapshot(&virtual_state);
        let mandatory_deficits = self.mandatory_attestation_deficits_for_template_snapshot(
            virtual_state.ghostdag_data.selected_parent,
            virtual_state.daa_score,
            &template_bond_view,
            &candidate_accepted_txs,
        );
        let mut tx_selector = tx_selector_provider(latest_ready_epoch, &mandatory_deficits);
        let mut txs = tx_selector.select_transactions();
        let mut calculated_fees = Vec::with_capacity(txs.len());
        // kaspa-pq DNS-finality (§6.5): per-reason drop counters for diagnostics.
        let mut shards_seen = 0usize;
        let mut shards_kept = 0usize;
        let mut dropped_bond_inactive = 0usize;
        let mut dropped_id_mismatch = 0usize;
        let mut dropped_bad_sig = 0usize;
        let mut dropped_malformed = 0usize;
        // kaspa-pq DNS-finality (audit v24 H-5): the dropped shards (id + hygiene kind)
        // returned to the mining manager so it can evict terminal drops and quarantine
        // transient ones — otherwise a dropped shard stays in the mempool and is
        // re-selected into every subsequent template forever (the live-testnet stall).
        let mut dropped_attestation_shards: Vec<kaspa_consensus_core::block::AttestationTemplateDrop> = Vec::new();
        // Classify one selected tx for the template. `true` ⇒ keep (push to txs +
        // calculated_fees in lockstep); `false` ⇒ reject back to the selector (it will
        // refill from the next candidate) and DO NOT push, so `txs` and `calculated_fees`
        // stay 1:1. A `Drop` is counted by reason. A `KeepNonShard`/`KeepEligible` is kept.
        let classify_keep = |this: &Self,
                             tx: &Transaction,
                             shards_seen: &mut usize,
                             shards_kept: &mut usize,
                             dropped_bond_inactive: &mut usize,
                             dropped_id_mismatch: &mut usize,
                             dropped_bad_sig: &mut usize,
                             dropped_malformed: &mut usize,
                             dropped_attestation_shards: &mut Vec<kaspa_consensus_core::block::AttestationTemplateDrop>|
         -> bool {
            use crate::pipeline::virtual_processor::utxo_validation::{AttestationDropReason, AttestationShardDecision};
            match this.classify_attestation_shard_for_template(tx, &template_bond_view, virtual_state.daa_score) {
                AttestationShardDecision::KeepNonShard => true,
                AttestationShardDecision::KeepEligible { .. } => {
                    *shards_seen += 1;
                    *shards_kept += 1;
                    true
                }
                AttestationShardDecision::Drop { reason, bond, epoch } => {
                    *shards_seen += 1;
                    match reason {
                        AttestationDropReason::BondNotActiveAtTarget => *dropped_bond_inactive += 1,
                        AttestationDropReason::ValidatorIdMismatch => *dropped_id_mismatch += 1,
                        AttestationDropReason::BadSignature => *dropped_bad_sig += 1,
                        AttestationDropReason::MalformedPayload => *dropped_malformed += 1,
                    }
                    dropped_attestation_shards.push(kaspa_consensus_core::block::AttestationTemplateDrop {
                        tx_id: tx.id(),
                        kind: reason.template_drop_kind(),
                    });
                    debug!(
                        "[attestation-template] dropping ineligible shard tx {} (reason={:?}, bond={}, epoch={})",
                        tx.id(),
                        reason,
                        bond.transaction_id,
                        epoch
                    );
                    false
                }
            }
        };

        let mut invalid_transactions = HashMap::new();
        // kaspa-pq DNS-finality (E3): shards dropped by the classifier (eligible-filter),
        // tracked separately from validation-`invalid_transactions` so the
        // `is_successful`/`InvalidTransactionsInNewBlock` decision is unaffected — a
        // dropped-but-valid shard is a refill, not a template failure.
        let mut dropped_shard_ids: std::collections::HashSet<kaspa_consensus_core::tx::TransactionId> =
            std::collections::HashSet::new();
        let results = self.validate_block_template_transactions_in_parallel(&txs, &virtual_state, &virtual_utxo_view);
        for (tx, res) in txs.iter().zip(results) {
            match res {
                Err(e) => {
                    invalid_transactions.insert(tx.id(), e);
                    tx_selector.reject_selection(tx.id());
                }
                Ok(fee) => {
                    if classify_keep(
                        self,
                        tx,
                        &mut shards_seen,
                        &mut shards_kept,
                        &mut dropped_bond_inactive,
                        &mut dropped_id_mismatch,
                        &mut dropped_bad_sig,
                        &mut dropped_malformed,
                        &mut dropped_attestation_shards,
                    ) {
                        calculated_fees.push(fee);
                    } else {
                        dropped_shard_ids.insert(tx.id());
                        // kaspa-pq audit v26 (H-3): a classifier DROP (valid tx, ineligible
                        // shard) — free its slot for the refill WITHOUT counting it as a
                        // validation rejection that could flip the selector to unsuccessful.
                        tx_selector.reject_selection_for_refill(tx.id());
                    }
                }
            }
        }

        let mut has_rejections = !invalid_transactions.is_empty() || !dropped_shard_ids.is_empty();
        if has_rejections {
            txs.retain(|tx| !invalid_transactions.contains_key(&tx.id()) && !dropped_shard_ids.contains(&tx.id()));
        }

        while has_rejections {
            has_rejections = false;
            let next_batch = tx_selector.select_transactions(); // Note that once next_batch is empty the loop will exit
            let next_batch_results =
                self.validate_block_template_transactions_in_parallel(&next_batch, &virtual_state, &virtual_utxo_view);
            for (tx, res) in next_batch.into_iter().zip(next_batch_results) {
                match res {
                    Err(e) => {
                        invalid_transactions.insert(tx.id(), e);
                        tx_selector.reject_selection(tx.id());
                        has_rejections = true;
                    }
                    Ok(fee) => {
                        if classify_keep(
                            self,
                            &tx,
                            &mut shards_seen,
                            &mut shards_kept,
                            &mut dropped_bond_inactive,
                            &mut dropped_id_mismatch,
                            &mut dropped_bad_sig,
                            &mut dropped_malformed,
                            &mut dropped_attestation_shards,
                        ) {
                            txs.push(tx);
                            calculated_fees.push(fee);
                        } else {
                            // kaspa-pq audit v26 (H-3): classifier DROP during the refill loop —
                            // free the slot but do not count it as a validation rejection.
                            tx_selector.reject_selection_for_refill(tx.id());
                            has_rejections = true;
                        }
                    }
                }
            }
        }

        // kaspa-pq DNS-finality (§6.5): emit the attestation-template diagnostics once
        // per build when any shard was seen (kept or dropped). Inert (no log) on a chain
        // with no attestation traffic / overlay dormant.
        if shards_seen > 0 {
            info!(
                "[attestation-template] shards seen={} kept={} dropped(bond_inactive={}, id_mismatch={}, bad_sig={}, malformed={})",
                shards_seen, shards_kept, dropped_bond_inactive, dropped_id_mismatch, dropped_bad_sig, dropped_malformed
            );
        }

        // Check whether this was an overall successful selection episode. We pass this decision
        // to the selector implementation which has the broadest picture and can use mempool config
        // and context
        match (build_mode, tx_selector.is_successful()) {
            (TemplateBuildMode::Standard, false) => {
                return Err(RuleError::InvalidTransactionsInNewBlock(invalid_transactions)
                    .with_attestation_template_drops(&dropped_attestation_shards));
            }
            (TemplateBuildMode::Standard, true) | (TemplateBuildMode::Infallible, _) => {}
        }

        // kaspa-pq narrow P0-1: `template_bond_view` was captured at the top of this
        // function INSIDE the same read lock as `virtual_state` (the SAME virtual
        // generation = the template's selected parent), so the §6.2 selection-loop
        // classifier, the reward fan-out, the overlay commitment, and the EVM claim
        // payload all reference one coherent generation — never a later re-read of a
        // possibly-advanced view (the mixed-generation TOCTOU). `virtual_state.daa_score`
        // is exactly the template header's daa_score (see `Header::new_finalized` below).
        // Producer policy only: when local DNS finality is stale, this node emits an
        // empty EVM payload for the template (deposit claims, normal EVM txs, and the
        // EVM coinbase all stay out). Base L1 txs and PoW/GHOSTDAG liveness continue.
        // Block validation deliberately does not reject by reading the current
        // dns_state_store; validity must stay determined by the candidate block and
        // its selected-parent state.
        let bridge_finality_fresh = self.bridge_finality_is_fresh(virtual_state.daa_score);
        let evm_template_data = if bridge_finality_fresh {
            evm_template_data
        } else {
            if !evm_template_data.transactions.is_empty() || !evm_template_data.system_ops.is_empty() {
                warn!(
                    "EVM lane producer paused: DNS finality is unconfirmed or stale at DAA {}; emitting an empty EVM payload this template (txs={}, deposit_claims={})",
                    virtual_state.daa_score,
                    evm_template_data.transactions.len(),
                    evm_template_data.system_ops.len()
                );
            }
            kaspa_consensus_core::evm::EvmTemplateData::default()
        };
        let prepared_claims =
            crate::processes::evm::prepare_deposit_claims(&evm_template_data.system_ops, virtual_utxo_view, virtual_state.daa_score);

        // At this point we can safely drop the read lock
        drop(virtual_read);

        // Build the template
        self.build_block_template_from_virtual_state(
            virtual_state,
            template_bond_view,
            prepared_claims,
            miner_data,
            txs,
            calculated_fees,
            evm_template_data,
            dropped_attestation_shards,
        )
    }

    pub(crate) fn validate_block_template_transactions(
        &self,
        txs: &[Transaction],
        virtual_state: &VirtualState,
        utxo_view: &impl UtxoView,
    ) -> Result<(), RuleError> {
        // Search for invalid transactions
        let mut invalid_transactions = HashMap::new();
        for tx in txs.iter() {
            if let Err(e) = self.validate_block_template_transaction(tx, virtual_state, utxo_view) {
                invalid_transactions.insert(tx.id(), e);
            }
        }
        if !invalid_transactions.is_empty() { Err(RuleError::InvalidTransactionsInNewBlock(invalid_transactions)) } else { Ok(()) }
    }

    pub(crate) fn build_block_template_from_virtual_state(
        &self,
        virtual_state: Arc<VirtualState>,
        // kaspa-pq narrow P0-1: the bond view + deposit-claim snapshot, both
        // captured in the SAME virtual generation as `virtual_state` by the caller
        // (under one read lock) — so the reward fan-out, the overlay commitment and
        // the EVM claim payload all reference one coherent generation.
        template_bond_view: ActiveBondView,
        prepared_claims: crate::processes::evm::PreparedDepositClaims,
        miner_data: MinerData,
        mut txs: Vec<Transaction>,
        calculated_fees: Vec<u64>,
        // kaspa-pq EVM Lane v0.4 (§15 step 6 / §16): own-payload inputs.
        evm_template_data: kaspa_consensus_core::evm::EvmTemplateData,
        // kaspa-pq DNS-finality (audit v24 H-5): shards the selection-loop classifier dropped,
        // forwarded into the `BlockTemplate` so the mining manager can reconcile the mempool.
        dropped_attestation_shards: Vec<kaspa_consensus_core::block::AttestationTemplateDrop>,
    ) -> Result<BlockTemplate, RuleError> {
        // [`calc_block_parents`] can use deep blocks below the pruning point for this calculation, so we
        // need to hold the pruning lock.
        let _prune_guard = self.pruning_lock.blocking_read();
        let pruning_point = self.pruning_point_store.read().pruning_point().unwrap();
        let header_pruning_point =
            self.pruning_point_manager.expected_header_pruning_point(virtual_state.ghostdag_data.to_compact()).pruning_point;
        // kaspa-pq Phase 10/11 (ADR-0009 Addendum B §B.4/§B.5): the validator
        // reward fan-out for this template. The template extends the current
        // tip, so the bond set as-of its selected parent is the `StakeBonds`
        // store snapshot (= state at the sink) — `initial_active_bond_view`.
        // Then compute the reward outputs with the SAME
        // `validator_reward_outputs_for_block` the validation path uses, so a
        // block mined from this template reproduces the coinbase byte-for-byte.
        // No-op on every current network (overlay dormant). The bond view is
        // captured by the caller in the template's virtual generation (narrow P0-1)
        // and passed in, not re-read here.
        //
        // kaspa-pq DNS-finality (E3/§6.2): the PRIMARY ineligible-shard drop now
        // happens AT SELECTION TIME in `build_block_template` (with reject/refill +
        // `calculated_fees` lockstep), so by the time this function runs on that path
        // `txs` already carries only eligible shards and the late `retain` finds
        // nothing — `calculated_fees` therefore stays 1:1 with `txs`. The `retain` is
        // retained ONLY for the alternate `test_block_builder` path, which passes a
        // pre-built `txs` (and an empty `calculated_fees`) without going through the
        // selection-loop classifier; there dropping a shard is harmless to fee
        // alignment (no fees are tracked). In debug builds we assert the post-state.
        self.retain_reward_eligible_attestation_shards(&mut txs, &template_bond_view, virtual_state.daa_score);
        // The §6.2 selection loop already aligns the two on the production path; assert
        // that invariant in debug builds (skipped when `calculated_fees` is the test
        // helper's empty sentinel, which legitimately does not track per-tx fees).
        debug_assert!(
            calculated_fees.is_empty() || calculated_fees.len() == txs.len(),
            "calculated_fees ({}) must stay 1:1 with non-coinbase txs ({}) after attestation-shard filtering",
            calculated_fees.len(),
            txs.len()
        );
        // kaspa-pq optional DNS-finality hard inclusion: in shipped liveness-first presets this is
        // inert (`mandatory_attestation_inclusion_daa_score = u64::MAX`), so missing attestations
        // never block template production. Private hard-inclusion forks still use the deterministic
        // selected-parent + candidate-accepted + body view below.
        let candidate_accepted_txs = self.accepted_txs_from_virtual_state(&virtual_state);
        self.check_mandatory_attestation_inclusion(
            &txs,
            &candidate_accepted_txs,
            &template_bond_view,
            virtual_state.ghostdag_data.selected_parent,
            virtual_state.daa_score,
        )
        .map_err(|err| err.with_attestation_template_drops(&dropped_attestation_shards))?;
        // kaspa-pq Phase 13 (ADR-0018 §F+§E): the §F carve + §E validator pool for
        // this template, computed identically to the validation path so a block
        // mined from this template reproduces the coinbase byte-for-byte. `None`/0
        // on every current network (overlay dormant).
        // ADR-0018 §F staged rollout: None (Stage 1) / bootstrap (Stage 2) / full
        // (Stage 3) selected by DAA, identically to the validation path.
        let carve = self.dns_params.as_ref().and_then(|p| p.reward_fee_split(virtual_state.daa_score));
        let validator_pool = carve.map_or(0, |fs| {
            self.coinbase_manager.coinbase_validator_pool(
                &virtual_state.ghostdag_data,
                &virtual_state.mergeset_rewards,
                &virtual_state.mergeset_non_daa,
                fs,
            )
        });
        let (validator_reward_outputs, _rewarded_keys, newly_included_stake, expected_stake) = self
            .validator_reward_outputs_for_block(
                &txs,
                &template_bond_view,
                virtual_state.daa_score,
                virtual_state.ghostdag_data.selected_parent,
                validator_pool,
            );
        // kaspa-pq ADR-0018 "本格版" (PoS-v2, Phase 4): append the reserve-drip outputs so a block
        // mined from this template reproduces the validated coinbase byte-for-byte. Reads the sink's
        // committed reserve balance (= the template's selected parent). Inert below the v2 fence.
        let mut validator_reward_outputs = validator_reward_outputs;
        if let Some(dns_params) = self.dns_params.as_ref() {
            let parent_balance = self.reserve_balance_store.get(virtual_state.ghostdag_data.selected_parent).unwrap_or(0);
            let (drip_outputs, _) = self.reserve_drip_outputs(
                dns_params,
                virtual_state.daa_score,
                virtual_state.ghostdag_data.selected_parent,
                &template_bond_view,
                parent_balance,
            );
            validator_reward_outputs.extend(drip_outputs);
        }
        let coinbase = self
            .coinbase_manager
            .expected_coinbase_transaction(
                virtual_state.daa_score,
                miner_data.clone(),
                &virtual_state.ghostdag_data,
                &virtual_state.mergeset_rewards,
                &virtual_state.mergeset_non_daa,
                &validator_reward_outputs,
                carve,
                (newly_included_stake, expected_stake),
            )
            .unwrap();
        txs.insert(0, coinbase.tx);
        // Declare the highest active header schema, exactly mirroring
        // `HeaderProcessor::check_header_version`: PALW v3 > EVM v2 > base v1.
        let version = if virtual_state.daa_score >= self.palw_activation_daa_score {
            kaspa_consensus_core::constants::PALW_HEADER_VERSION
        } else if virtual_state.daa_score >= self.evm_activation_daa_score {
            kaspa_consensus_core::constants::EVM_HEADER_VERSION
        } else {
            BLOCK_VERSION
        };
        let parents_by_level = self.parents_manager.calc_block_parents(pruning_point, &virtual_state.parents);
        let hash_merkle_root = calc_hash_merkle_root(txs.iter());

        let accepted_id_merkle_root = self
            .calc_accepted_id_merkle_root(virtual_state.accepted_tx_ids.iter().copied(), virtual_state.ghostdag_data.selected_parent);
        let utxo_commitment = virtual_state.multiset.clone().finalize();
        // Past median time is the exclusive lower bound for valid block time, so we increase by 1 to get the valid min
        let min_block_time = virtual_state.past_median_time + 1;
        let header = Header::new_finalized(
            version,
            parents_by_level,
            hash_merkle_root,
            accepted_id_merkle_root,
            utxo_commitment,
            u64::max(min_block_time, unix_now()),
            virtual_state.bits,
            0,
            // kaspa-pq Phase 3 (ADR-0007): the template declares the network-correct Layer-1 algo
            // for this DAA score — BLAKE2b-512 ∥ SHA3-512 (algo_id = 3) once activated, else kHeavyHash (1).
            kaspa_consensus_core::pow_layer0::required_algo_id(self.pow_blake2b_sha3_activation.is_active(virtual_state.daa_score)),
            virtual_state.daa_score,
            virtual_state.ghostdag_data.blue_work,
            virtual_state.ghostdag_data.blue_score,
            header_pruning_point,
        );
        // Header-v3 commits the exact GHOSTDAG-derived component decomposition even for the
        // permanent algo-3 hash lane; ticket fields remain zero on a hash-lane template.
        let header = if version >= kaspa_consensus_core::constants::PALW_HEADER_VERSION {
            // ADR-0039 C6 SLICE 2: stamp this block's OWN beacon state R_E into the header, computed by
            // the SAME derivation the S2 UTXO-validation check (`check_palw_beacon_seed` →
            // `derive_palw_beacon_state_value`) re-runs — so a block mined from this template
            // authenticates (construction == validation). The template knows `(daa_score,
            // selected_parent)` before the block hash exists, so it calls the shared core directly; the
            // selected-parent bond view is the same `template_bond_view` the overlay-commitment root is
            // built from (validation resolves the identical view for the mined block). `unwrap_or_default`
            // covers the never-taken pre-activation branch (this arm is behind `version >= v3`).
            let derived_beacon = self.derive_palw_beacon_state_core(
                virtual_state.daa_score,
                virtual_state.ghostdag_data.selected_parent,
                virtual_state.ghostdag_data.selected_parent,
                &template_bond_view,
            );
            let palw_beacon_seed = derived_beacon.as_ref().map(|s| s.seed).unwrap_or_default();
            // K5 (ADR-0039 §11.3) template contract, c==v twin of the S2 `PalwLaneHalted` rule + the
            // body-stage clause 10: a FUTURE algo-4 candidate constructor MUST suppress emission unless
            // `palw_template_lane_open(derived.mode, buried_carry_run, grace)` — i.e. the block's own
            // mode is not Halted AND the lagged buried seed-carry run does not exceed grace (the second
            // conjunct prevents post-recovery self-bricking). Today the template is ALWAYS algo-3
            // (`required_algo_id` above never returns id 4), so no ticket is emitted and the guard is a
            // documented invariant + debug assert, not a live gate.
            debug_assert!(
                virtual_state.daa_score < self.palw_activation_daa_score
                    || header.pow_algo_id != kaspa_consensus_core::pow_layer0::POW_ALGO_ID_PALW_REPLICA
                    || derived_beacon.as_ref().is_none_or(|d| {
                        kaspa_consensus_core::palw::palw_template_lane_open(d.mode, 0, self.palw_beacon_grace_epochs)
                    }),
                "K5: an algo-4 template must consult palw_template_lane_open (mode not Halted + buried carry <= grace)"
            );
            header.with_palw_fields(kaspa_consensus_core::header::PalwHeaderFields {
                blue_hash_work: virtual_state.ghostdag_data.blue_hash_work,
                blue_compute_work: virtual_state.ghostdag_data.blue_compute_work,
                palw_beacon_seed,
                ..Default::default()
            })
        } else {
            header
        };
        // kaspa-pq EVM Lane v0.4 (§15): on an evm-active template, execute the
        // mergeset acceptance NOW (the producer-side run of the exact verifier
        // code) and commit both EVM header fields. The own payload is empty
        // until the EVM mempool lands (§16 phase) — its (non-zero) hash is
        // still committed. Inert (returns the header unchanged) pre-activation.
        let (header, evm_payload, stale_evm_claims) = self
            .evm_template_fields(header, &virtual_state, evm_template_data, prepared_claims)
            .map_err(|err| err.with_attestation_template_drops(&dropped_attestation_shards))?;
        // kaspa-pq ADR-0022: commit the DNS/PoS-v2 overlay snapshot as-of the template's
        // selected parent (the sink) — the SAME `compute_overlay_snapshot` the validation
        // path re-derives, so a block mined from this template reproduces the
        // `overlay_commitment_root` byte-for-byte (construction == validation). A pre-v3
        // header stays unchanged when DNS is absent; Header-v3 always commits the versioned
        // root because R_E is part of that schema. Appended after the EVM fields;
        // `with_overlay_commitment` re-finalizes over the full preimage.
        let header = if self.dns_params.is_some() || header.version >= kaspa_consensus_core::constants::PALW_HEADER_VERSION {
            let selected_parent = virtual_state.ghostdag_data.selected_parent;
            let overlay_snapshot = self.compute_overlay_snapshot(selected_parent, &template_bond_view);
            let overlay_root = self.versioned_overlay_commitment_root(header.version, selected_parent, &overlay_snapshot);
            header.with_overlay_commitment(overlay_root)
        } else {
            header
        };
        let selected_parent_hash = virtual_state.ghostdag_data.selected_parent;
        let selected_parent_timestamp = self.headers_store.get_timestamp(selected_parent_hash).unwrap();
        let selected_parent_daa_score = self.headers_store.get_daa_score(selected_parent_hash).unwrap();
        let mut template_block = MutableBlock::new(header, txs);
        template_block.evm_payload = evm_payload;
        Ok(BlockTemplate::new(
            template_block,
            miner_data,
            coinbase.has_red_reward,
            coinbase.miner_script_output_indices,
            selected_parent_timestamp,
            selected_parent_daa_score,
            selected_parent_hash,
            calculated_fees,
            stale_evm_claims,
            dropped_attestation_shards,
        ))
    }

    /// Make sure pruning point-related stores are initialized
    pub fn init(self: &Arc<Self>) {
        let pruning_point_read = self.pruning_point_store.upgradable_read();
        if pruning_point_read.pruning_point().optional().unwrap().is_none() {
            let mut pruning_point_write = RwLockUpgradableReadGuard::upgrade(pruning_point_read);
            let mut pruning_meta_write = self.pruning_meta_stores.write();
            let mut batch = WriteBatch::default();
            self.past_pruning_points_store.insert_batch(&mut batch, 0, self.genesis.hash).idempotent().unwrap();
            pruning_point_write.set_batch(&mut batch, self.genesis.hash, 0).unwrap();
            pruning_point_write.set_retention_checkpoint(&mut batch, self.genesis.hash).unwrap();
            pruning_point_write.set_retention_period_root(&mut batch, self.genesis.hash).unwrap();
            pruning_meta_write.set_utxoset_position(&mut batch, self.genesis.hash).unwrap();
            self.db.write(batch).unwrap();
            drop(pruning_point_write);
            drop(pruning_meta_write);
        }
    }

    /// Initializes UTXO state of genesis and points virtual at genesis.
    /// Note that pruning point-related stores are initialized by `init`
    pub fn process_genesis(self: &Arc<Self>) {
        // Write the UTXO state of genesis
        self.commit_utxo_state(
            self.genesis.hash,
            UtxoDiff::default(),
            MuHash::new(),
            AcceptanceData::default(),
            ZERO_HASH64,
            Vec::new(),
            Vec::new(), // kaspa-pq ADR-0040 §5.15.13 (G16): genesis pays no PALW work.
            0,    // kaspa-pq ADR-0018 "本格版": genesis has no validator quality sub-pool.
            0,    // kaspa-pq ADR-0018 "本格版" (Phase 4): genesis reserve balance is 0.
            None, // kaspa-pq ADR-0020 v0.4: genesis is EVM-inert (v0 header).
            &ActiveBondView::new(),
            &ProviderBondView::new(), // kaspa-pq ADR-0040 §5.17: genesis has no provider bonds.
        );

        // Init the virtual selected chain store
        let mut batch = WriteBatch::default();
        let mut selected_chain_write = self.selected_chain_store.write();
        selected_chain_write.init_with_pruning_point(&mut batch, self.genesis.hash).unwrap();
        self.db.write(batch).unwrap();
        drop(selected_chain_write);

        // Init virtual state
        self.commit_virtual_state(
            self.virtual_stores.upgradable_read(),
            Arc::new(VirtualState::from_genesis(&self.genesis, self.ghostdag_manager.ghostdag(&[self.genesis.hash]))),
            &Default::default(),
            &Default::default(),
        );
    }

    /// Finalizes the pruning point utxoset state and imports the pruning point utxoset *to* virtual utxoset
    pub fn import_pruning_point_utxo_set(
        &self,
        new_pruning_point: BlockHash,
        mut imported_utxo_multiset: MuHash,
    ) -> PruningImportResult<()> {
        info!("Importing the UTXO set of the pruning point {}", new_pruning_point);
        let new_pruning_point_header = self.headers_store.get_header(new_pruning_point).unwrap();
        let imported_utxo_multiset_hash = imported_utxo_multiset.finalize();
        if imported_utxo_multiset_hash != new_pruning_point_header.utxo_commitment {
            return Err(PruningImportError::ImportedMultisetHashMismatch(
                new_pruning_point_header.utxo_commitment,
                imported_utxo_multiset_hash,
            ));
        }

        {
            // Set the pruning point utxoset position to the new point we just verified
            let mut batch = WriteBatch::default();
            let mut pruning_meta_write = self.pruning_meta_stores.write();
            pruning_meta_write.set_utxoset_position(&mut batch, new_pruning_point).unwrap();
            self.db.write(batch).unwrap();
            drop(pruning_meta_write);
        }

        {
            // Copy the pruning-point UTXO set into virtual's UTXO set
            let pruning_meta_read = self.pruning_meta_stores.read();
            let mut virtual_write = self.virtual_stores.write();

            virtual_write.utxo_set.clear().unwrap();
            for chunk in &pruning_meta_read.utxo_set.iterator().map(|iter_result| iter_result.unwrap()).chunks(1000) {
                virtual_write.utxo_set.write_from_iterator_without_cache(chunk).unwrap();
            }
        }

        let virtual_read = self.virtual_stores.upgradable_read();

        // Validate transactions of the pruning point itself
        let new_pruning_point_transactions = self.block_transactions_store.get(new_pruning_point).unwrap();
        let validated_transactions = self.validate_transactions_in_parallel(
            &new_pruning_point_transactions,
            &virtual_read.utxo_set,
            new_pruning_point_header.daa_score,
            TxValidationFlags::Full,
        );
        if validated_transactions.len() < new_pruning_point_transactions.len() - 1 {
            // Some non-coinbase transactions are invalid
            return Err(PruningImportError::NewPruningPointTxErrors);
        }

        {
            // Submit partial UTXO state for the pruning point.
            // Note we only have and need the multiset; acceptance data and utxo-diff are irrelevant.
            let mut batch = WriteBatch::default();
            self.utxo_multisets_store.set_batch(&mut batch, new_pruning_point, imported_utxo_multiset.clone()).unwrap();

            let statuses_write = self.statuses_store.set_batch(&mut batch, new_pruning_point, StatusUTXOValid).unwrap();
            self.db.write(batch).unwrap();
            drop(statuses_write);
        }

        // Calculate the virtual state, treating the pruning point as the only virtual parent
        let virtual_parents = vec![new_pruning_point];
        let virtual_ghostdag_data = self.ghostdag_manager.ghostdag(&virtual_parents);

        self.calculate_and_commit_virtual_state(
            virtual_read,
            virtual_parents,
            virtual_ghostdag_data,
            imported_utxo_multiset.clone(),
            &mut UtxoDiff::default(),
            // Pruning-point UTXO import (IBD): the `StakeBonds` store snapshot is
            // the bond set as-of the imported pruning point. Empty on every
            // current network (overlay dormant), so this is inert.
            &self.initial_active_bond_view(),
            // ADR-0040 ECON-03: likewise the provider-bond registry as-of the imported pruning point.
            // Empty on every current network (PALW fenced), so this is inert. NOTE: pruned-IBD
            // transport of the provider registry is NOT solved here — see the ADR-0040 ECON-03 row.
            &self.initial_palw_provider_bond_view(),
            &ChainPath::default(),
        )?;

        Ok(())
    }

    /// kaspa-pq ADR-0022: import the pruning point's EVM execution state during
    /// headers-proof IBD. Without this, the first post-pruning block re-executes the
    /// EVM lane against an empty genesis state (the pruning point has no
    /// `evm_header_store` row on a fresh node), so its recomputed `evm_commitment_root`
    /// mismatches the header and the whole chain is disqualified.
    ///
    /// Verification (trustless): the supplied [`EvmExecutionHeader`] must reproduce
    /// the L1 header's `evm_commitment_root` (a pure, secp-free keyed-BLAKE2b check),
    /// and — on an `evm` build — the supplied [`EvmStateSnapshot`] must reproduce that
    /// EVM header's `state_root` (the keccak-MPT root over the account set). Then the
    /// two rows are persisted and the canonical **finalized** EVM head is set to the
    /// pruning point, so `evm_execute_acceptance_with_parent` finds the real parent
    /// state for `pp`'s children.
    pub fn import_pruning_point_evm_state(
        &self,
        pruning_point: BlockHash,
        evm_header: kaspa_consensus_core::evm::EvmExecutionHeader,
        snapshot: kaspa_consensus_core::evm::EvmStateSnapshot,
    ) -> PruningImportResult<()> {
        info!("Importing the EVM state of the pruning point {}", pruning_point);
        let l1_header = self.headers_store.get_header(pruning_point).unwrap();

        // (1) The EVM header must reproduce the L1 commitment (pure; works on any build).
        let got = evm_header.commitment_root();
        if got != l1_header.evm_commitment_root {
            return Err(PruningImportError::ImportedEvmCommitmentMismatch(pruning_point, got, l1_header.evm_commitment_root));
        }

        // (2) The state snapshot must reproduce the EVM header's keccak-MPT state root.
        // Requires the EVM executor; an `evm`-active network can only be synced by an
        // `--features evm` build (a default build rejects its v2 headers earlier), so
        // skipping this on a non-evm build never weakens a chain it actually follows.
        #[cfg(feature = "evm")]
        {
            let db = kaspa_evm::snapshot::seed_cachedb(&snapshot)
                .map_err(|e| PruningImportError::ImportedEvmSnapshotInvalid(pruning_point, e.to_string()))?;
            let computed = kaspa_hashes::EvmH256::from_bytes(kaspa_evm::state::state_root(&db).0);
            if computed != evm_header.state_root {
                return Err(PruningImportError::ImportedEvmStateRootMismatch(pruning_point, computed, evm_header.state_root));
            }
        }

        // (3) Persist the rows and pin the finalized EVM head to the pruning point.
        let state_root = evm_header.state_root; // captured before `evm_header` is moved below
        let mut batch = WriteBatch::default();
        // C-01 S8 (audit M-01): also seed the flat latest-canonical state from the verified
        // snapshot, so a pruned-IBD node starts with a flat store materialized at the pruning point
        // (the basis the S7 flat fast-path and the S9 cutover read). Gated on the shadow backend,
        // matching the per-block dual-write (S4) — the flat store is a node-local shadow until
        // cutover. Same atomic batch as the 206 write; flat/code/root/pointer are state data only
        // (never a commitment) ⇒ consensus-neutral. Done before `snapshot`/`evm_header` are moved.
        if self.evm_shadow_state_backend {
            let mut ptr = self.evm_latest_state_ptr_store.write();
            crate::processes::evm::seed_flat_from_snapshot(
                &self.evm_flat_account_store,
                &self.evm_code_store,
                &self.evm_block_state_root_store,
                &mut ptr,
                &mut batch,
                pruning_point,
                state_root,
                &snapshot,
            )
            .map_err(|e| PruningImportError::ImportedEvmSnapshotInvalid(pruning_point, format!("flat seed: {e}")))?;
        }
        self.evm_header_store.insert_batch(&mut batch, pruning_point, evm_header).unwrap();
        self.evm_state_store.insert_batch(&mut batch, pruning_point, snapshot).unwrap();
        {
            let mut heads_write = self.evm_heads_store.write();
            let prev = heads_write.get().ok();
            let latest = prev.as_ref().map(|h| h.latest).unwrap_or(pruning_point);
            let safe = prev.as_ref().map(|h| h.safe).unwrap_or(pruning_point);
            let heads = kaspa_consensus_core::evm::CanonicalEvmHeads { latest, safe, finalized: pruning_point };
            heads_write.set_batch(&mut batch, heads).unwrap();
        }
        self.db.write(batch).unwrap();
        Ok(())
    }

    /// kaspa-pq ADR-0022 (serving side): the pruning point's EVM execution header +
    /// state snapshot, for a peer to stream during another node's headers-proof IBD.
    /// `None` if the overlay/EVM rows are absent (pre-activation or not yet computed).
    pub fn pruning_point_evm_state(
        &self,
        pruning_point: BlockHash,
    ) -> Option<(kaspa_consensus_core::evm::EvmExecutionHeader, kaspa_consensus_core::evm::EvmStateSnapshot)> {
        // EvmHeaderStoreReader / EvmStateStoreReader are in module scope.
        let header = self.evm_header_store.get(pruning_point).ok()?;
        // Hot path: the persisted 206[pp] snapshot.
        match self.evm_state_store.get(pruning_point) {
            Ok(snapshot) => return Some((header, snapshot)),
            Err(StoreError::KeyNotFound(_)) => {} // retired (S9b) ⇒ serve from the flat backend below
            Err(e) => {
                warn!("[evm] pruning-point 206 read failed for {pruning_point}: {e}");
                return None;
            }
        }
        // C-01 S9b: 206[pp] retired. Serve the pruning-point state from the flat backend so peers can
        // still IBD from this node — materialize it when the pp IS the flat head (a freshly pruned-IBD
        // -imported node pins the flat pointer to the pp), else §12-reconstruct (a full-sync serving
        // node whose head is far ahead of the buried pp; needs recent/archive history — `head` keeps
        // none, hence the startup warning). `None` if neither yields it (the peer tries another server).
        #[cfg(feature = "evm")]
        {
            use crate::model::stores::evm::{EvmCodeStoreReader, EvmStateCheckpointStoreReader, EvmStateDiffStoreReader};
            if let Ok(Some(ptr)) = self.evm_latest_state_ptr_store.read().get()
                && ptr.canonical_head == pruning_point
            {
                return match crate::processes::evm::materialize_snapshot(&self.evm_flat_account_store, &self.evm_code_store) {
                    Ok(snapshot) => Some((header, snapshot)),
                    Err(e) => {
                        warn!("[evm] pruning-point flat materialize failed for {pruning_point}: {e}");
                        None
                    }
                };
            }
            let (seed, forward_diffs) = match crate::processes::evm::gather_reconstruction_inputs(
                pruning_point,
                |b| self.evm_state_checkpoint_store.get(b),
                |b| self.evm_state_diff_store.get(b),
                |b| self.evm_header_store.get(b).optional().unwrap().is_some(),
            ) {
                Ok(v) => v,
                Err(e) => {
                    warn!("[evm] pruning-point §12 reconstruct gather failed for {pruning_point}: {e}");
                    return None;
                }
            };
            match kaspa_evm::reconstruct::reconstruct_evm_state(
                &seed,
                &forward_diffs,
                |h| self.evm_code_store.get(*h).ok().flatten(),
                header.state_root,
            ) {
                Ok(snapshot) => Some((header, snapshot)),
                Err(e) => {
                    warn!("[evm] pruning-point §12 reconstruct failed for {pruning_point}: {e}");
                    None
                }
            }
        }
        #[cfg(not(feature = "evm"))]
        None
    }

    /// kaspa-pq ADR-0022: import the pruning point's DNS/PoS-v2 overlay snapshot during
    /// headers-proof IBD. Persists the bond set (so `initial_active_bond_view` and the
    /// reward path read it), the pruning point's cumulative reserve balance (read by the
    /// first post-pruning finalizing block's §F drip), and the whole snapshot in the
    /// `pruning_overlay_snapshot_store` — which `selected_chain_overlay_window` consults
    /// for the below-pruning-point window (the selected-chain walk cannot traverse below
    /// the pruning point). Verification is trustless and automatic: the first post-pruning
    /// block's existing coinbase/overlay `c == v` re-derives this state and checks it
    /// against the committed `overlay_commitment_root`; a wrong snapshot disqualifies that
    /// block and the (staging) IBD is discarded.
    pub fn import_pruning_point_overlay_snapshot(
        &self,
        pruning_point: BlockHash,
        snapshot: OverlaySnapshot,
    ) -> PruningImportResult<()> {
        if self.dns_params.is_none() {
            return Ok(()); // overlay dormant — the snapshot is empty and nothing reads it
        }
        info!(
            "Importing the overlay snapshot of the pruning point {} ({} bonds, {} window blocks, reserve {})",
            pruning_point,
            snapshot.bonds.len(),
            snapshot.window.len(),
            snapshot.reserve_balance
        );
        let mut batch = WriteBatch::default();
        {
            let mut bonds_write = self.stake_bonds_store.write();
            for rec in &snapshot.bonds {
                bonds_write.insert_batch(&mut batch, rec.bond_outpoint, std::sync::Arc::new(rec.clone())).unwrap();
            }
        }
        if snapshot.reserve_balance > 0 {
            self.reserve_balance_store.insert_batch(&mut batch, pruning_point, snapshot.reserve_balance).unwrap();
        }
        self.pruning_overlay_snapshot_store
            .write()
            .set_batch(&mut batch, PruningPointOverlaySnapshot { pruning_point, snapshot })
            .unwrap();
        self.db.write(batch).unwrap();
        Ok(())
    }

    /// kaspa-pq ADR-0022 (serving side): the persisted pruning-point overlay snapshot, for
    /// a peer to stream during another node's headers-proof IBD. `None` if the overlay is
    /// dormant or no snapshot has been captured yet (captured at pruning-advance).
    pub fn pruning_point_overlay_snapshot(&self) -> Option<PruningPointOverlaySnapshot> {
        self.pruning_overlay_snapshot_store.read().get().ok()
    }

    /// kaspa-pq ADR-0022: reconstruct the bond set as-of `pp_daa` from the never-pruned
    /// `stake_bonds_store`. A bond belongs to the as-of-pp set iff it was created
    /// (`created_daa_score`) at/below `pp_daa`; mutations stamped after `pp_daa`
    /// (slash / unbond) did not apply yet, so they are nulled. The `status` field is
    /// left as-is — `compute_overlay_snapshot` normalizes it via `effective_bond_status`
    /// at the anchor. Exact (records are never deleted, only revert-of-Insert), O(bondset).
    fn bonds_as_of(&self, pp_daa: u64, pp_blue: u64) -> Vec<StakeBondRecord> {
        // Dormancy Fence (PR-D4): the as-of-pp buried epoch (same bury depth as the live
        // transition), so a discrete dormancy event (an eviction round) stamped AFTER pp is
        // nulled — exactly like slash/unbond. pp is deeply buried (pruning_depth ≫ horizon),
        // so this equals what pp's finalized region implied.
        let pp_buried_epoch = self.dns_params.as_ref().and_then(|p| {
            let epoch_len = p.attestation_epoch_length_blue_score.max(1);
            let bury_blue = p.attestation_lag_blue_score.max(p.max_reorg_horizon_blocks);
            ready_epoch_from_tip_blue_score(pp_blue, epoch_len, bury_blue)
        });
        self.stake_bonds_store
            .read()
            .iterator()
            .filter_map(|r| r.ok().map(|(_, rec)| (*rec).clone()))
            .filter(|rec| rec.created_daa_score <= pp_daa)
            .map(|mut rec| {
                if rec.slashed_at_daa_score.is_some_and(|d| d > pp_daa) {
                    rec.slashed_at_daa_score = None;
                }
                if rec.unbond_request_daa_score.is_some_and(|d| d > pp_daa) {
                    rec.unbond_request_daa_score = None;
                }
                // Dormancy Fence: null a dormancy that was stamped AFTER pp (its buried round
                // epoch is past pp's buried epoch) — as-of pp the bond was not yet Dormant. This
                // is exact (a discrete event). `status` is re-normalized by compute_overlay_snapshot.
                //
                // ⚠️ NOT YET EXACT (Blocker 2, fence-gated): `last_attested_epoch` is an
                // overwrite-with-latest field, so its as-of-pp value is NOT recoverable by a
                // clamp here — `min(e, pp_buried_epoch)` OVER-estimates for a bond whose last
                // pre-pp attestation predates pp_buried_epoch, still diverging a pruned importer's
                // root. Specified fix (see `stage_dormancy_transitions` doc): source Active bonds'
                // `last_attested` from the committed, pruning-survivable rewarded-epoch overlay
                // window (`rewarded_epochs_store`, reconstructable byte-exactly here from the
                // snapshot window) under invariant I7, not a prune-time clamp — left untouched
                // rather than clamped wrongly. Dormant bonds need no exact value (revival replays
                // a post-pp attestation live).
                if let Some(cap) = pp_buried_epoch
                    && rec.dormant_at_epoch.is_some_and(|e| e > cap)
                {
                    rec.dormant_at_daa_score = None;
                    rec.dormant_at_epoch = None;
                    rec.status = BondStatus::Active;
                }
                rec
            })
            .collect()
    }

    /// kaspa-pq ADR-0022: capture the overlay snapshot as-of `pruning_point` into the
    /// persisted store, for serving + the below-pruning-point window consult. MUST be
    /// called BEFORE pruning deletes the below-pruning-point overlay rows (the window walk
    /// reads them). The reconstructed as-of-pp bond view + the still-present per-block
    /// rows reproduce exactly what a node computed when it validated the pruning point's
    /// child (so the first post-pruning block's `c == v` on an importer matches).
    pub fn capture_pruning_point_overlay_snapshot(&self, pruning_point: BlockHash) {
        if self.dns_params.is_none() {
            return;
        }
        let pp_daa = self.headers_store.get_daa_score(pruning_point).unwrap();
        let pp_blue = self.headers_store.get_blue_score(pruning_point).unwrap();
        let view = ActiveBondView::from_records(self.bonds_as_of(pp_daa, pp_blue).into_iter().map(|r| (r.bond_outpoint, r)));
        let snapshot = self.compute_overlay_snapshot(pruning_point, &view);
        let mut batch = WriteBatch::default();
        self.pruning_overlay_snapshot_store
            .write()
            .set_batch(&mut batch, PruningPointOverlaySnapshot { pruning_point, snapshot })
            .unwrap();
        self.db.write(batch).unwrap();
    }

    pub fn are_pruning_points_violating_finality(&self, pp_list: PruningPointsList) -> bool {
        // Ideally we would want to check if the last known pruning point has the finality point
        // in its chain, but in some cases it's impossible: let `lkp` be the last known pruning
        // point from the list, and `fup` be the first unknown pruning point (the one following `lkp`).
        // fup.blue_score - lkp.blue_score ≈ finality_depth (±k), so it's possible for `lkp` not to
        // have the finality point in its past. So we have no choice but to check if `lkp`
        // has `finality_point.finality_point` in its chain (in the worst case `fup` is one block
        // above the current finality point, and in this case `lkp` will be a few blocks above the
        // finality_point.finality_point), meaning this function can only detect finality violations
        // in depth of 2*finality_depth, and can give false negatives for smaller finality violations.
        let current_pp = self.pruning_point_store.read().pruning_point().unwrap();
        let vf = self.virtual_finality_point(&self.lkg_virtual_state.load().ghostdag_data, current_pp);
        let vff = self.depth_manager.calc_finality_point(&self.ghostdag_store.get_data(vf).unwrap(), current_pp);

        let last_known_pp = pp_list.iter().rev().find(|pp| match self.statuses_store.read().get(pp.hash).optional().unwrap() {
            Some(status) => status.is_valid(),
            None => false,
        });

        if let Some(last_known_pp) = last_known_pp {
            !self.reachability_service.is_chain_ancestor_of(vff, last_known_pp.hash)
        } else {
            // If no pruning point is known, there's definitely a finality violation
            // (normally at least genesis should be known).
            true
        }
    }

    /// Executes `op` within the thread pool associated with this processor.
    pub fn install<OP, R>(&self, op: OP) -> R
    where
        OP: FnOnce() -> R + Send,
        R: Send,
    {
        self.thread_pool.install(op)
    }
}

enum MergesetIncreaseResult {
    Accepted { increase_size: u64 },
    Rejected { new_candidate: BlockHash },
}
