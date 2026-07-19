use crate::{
    consensus::{
        services::{ConsensusServices, DbWindowManager},
        storage::ConsensusStorage,
    },
    errors::{BlockProcessResult, RuleError},
    model::{
        services::reachability::MTReachabilityService,
        stores::{
            DB,
            block_transactions::{BlockTransactionsStoreReader, DbBlockTransactionsStore},
            evm::EvmPayloadStore as _,
            ghostdag::{DbGhostdagStore, GhostdagStoreReader},
            headers::{DbHeadersStore, HeaderStoreReader},
            reachability::DbReachabilityStore,
            statuses::{DbStatusesStore, StatusesStore, StatusesStoreBatchExtensions, StatusesStoreReader},
            tips::{DbTipsStore, TipsStore},
        },
    },
    pipeline::{
        ProcessingCounters,
        deps_manager::{BlockProcessingMessage, BlockTaskDependencyManager, TaskId, VirtualStateProcessingMessage},
    },
    processes::{coinbase::CoinbaseManager, transaction_validator::TransactionValidator},
};
use crossbeam_channel::{Receiver, Sender};
use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::{
    KType,
    block::Block,
    blockstatus::BlockStatus::{self, StatusHeaderOnly, StatusInvalid},
    config::{genesis::GenesisBlock, params::Params},
    mass::{Mass, MassCalculator, MassOps},
    tx::Transaction,
};
use kaspa_consensus_notify::{
    notification::{BlockAddedNotification, Notification},
    root::ConsensusNotificationRoot,
};
use kaspa_consensusmanager::SessionLock;
use kaspa_notify::notifier::Notify;
use parking_lot::RwLock;
use rayon::ThreadPool;
use rocksdb::WriteBatch;
use std::sync::{Arc, atomic::Ordering};

pub struct BlockBodyProcessor {
    // Channels
    receiver: Receiver<BlockProcessingMessage>,
    sender: Sender<VirtualStateProcessingMessage>,

    // Thread pool
    pub(super) thread_pool: Arc<ThreadPool>,

    // DB
    db: Arc<DB>,

    // Config
    pub(super) max_block_mass: u64,
    pub(super) genesis: GenesisBlock,
    pub(super) _ghostdag_k: KType,

    // Stores
    pub(super) statuses_store: Arc<RwLock<DbStatusesStore>>,
    pub(super) _ghostdag_store: Arc<DbGhostdagStore>,
    pub(super) headers_store: Arc<DbHeadersStore>,
    pub(super) block_transactions_store: Arc<DbBlockTransactionsStore>,
    /// kaspa-pq EVM Lane v0.4 (§3.1): each block's own payload, persisted at
    /// body commit so the virtual processor can assemble `AcceptedEvmTxs(B)`
    /// from MERGESET blocks' payloads. Only non-empty payloads are written
    /// (possible only on v2+ headers, i.e. post-activation), so this is inert
    /// on every current network.
    pub(super) evm_payload_store: Arc<crate::model::stores::evm::DbEvmPayloadStore>,
    /// §16 (audit R-2): raw EVM tx bytes by hash, written at body commit. Gated
    /// on the evm feature (its only writer needs `kaspa_evm::tx::tx_hash`).
    #[cfg(feature = "evm")]
    pub(super) evm_raw_tx_store: Arc<crate::model::stores::evm::DbEvmRawTxStore>,
    pub(super) body_tips_store: Arc<RwLock<DbTipsStore>>,
    /// ADR-0039 §14.2/§18.1: the PALW overlay store the algo-4 ticket check resolves its leaf/cert
    /// binding against, plus the lane's activation fence + epoch length.
    /// `palw_activation_daa_score` is `u64::MAX` on mainnet / testnet-10 / simnet / devnet, so
    /// `check_palw_ticket` returns before any store read and those nets are byte-identical — but it is
    /// **0** on `testnet-palw-110` / `devnet-palw-111` (`config/params.rs:1403`, `:1454`), where the
    /// read is live. What withholds the lane on those two is `palw_algo4_accept = false` (ADR-0040
    /// P0-3), enforced in `pre_ghostdag_validation.rs`, not this fence.
    pub(super) palw_store: Arc<crate::model::stores::palw::DbPalwStore>,
    pub(super) palw_overlay_view_store: Arc<crate::model::stores::palw_overlay_view::DbPalwOverlayViewStore>,
    pub(super) ghostdag_store: Arc<DbGhostdagStore>,
    pub(super) palw_activation_daa_score: u64,
    pub(super) palw_epoch_length_daa: u64,
    /// ADR-0039 §11.3 (K5): the beacon grace window, consumed by the clause-10 lagged halt indicator and
    /// the `advance_epoch_gated` activation freeze (both keyed off buried seed-carry runs).
    pub(super) palw_beacon_grace_epochs: u64,
    pub(super) palw_batch_admission: kaspa_consensus_core::palw::PalwBatchAdmissionParams,
    /// ADR-0039 §12.1 / C6 clause-6: `network_id` for `chain_commit` + the DNS params for resolving the
    /// finality-buried anchor from the block's past. Read only for algo-4 headers, none exist while gated.
    pub(super) palw_network_id: u32,
    /// ADR-0020 EVM lane activation fence. `check_evm_payload` decides EVM-inactive vs -active by this
    /// score (NOT by `version >= EVM_HEADER_VERSION`), because a PALW v3 header (version 3 ≥ 2) is admitted
    /// while the EVM lane is still inactive — such a block carries an EMPTY payload + zero EVM header
    /// commitments and must take the inactive branch. `u64::MAX` on every EVM-inert preset.
    pub(super) evm_activation_daa_score: u64,
    pub(super) dns_params: Option<kaspa_consensus_core::dns_finality::DnsParams>,

    // Managers and services
    pub(super) reachability_service: MTReachabilityService<DbReachabilityStore>,
    pub(super) coinbase_manager: CoinbaseManager,
    pub(crate) mass_calculator: MassCalculator,
    pub(super) transaction_validator: TransactionValidator,
    pub(super) window_manager: DbWindowManager,

    // Pruning lock
    pruning_lock: SessionLock,

    // Dependency manager
    task_manager: BlockTaskDependencyManager,

    // Notifier
    notification_root: Arc<ConsensusNotificationRoot>,

    // Counters
    counters: Arc<ProcessingCounters>,
}

impl BlockBodyProcessor {
    pub fn new(
        receiver: Receiver<BlockProcessingMessage>,
        sender: Sender<VirtualStateProcessingMessage>,
        thread_pool: Arc<ThreadPool>,

        params: &Params,
        db: Arc<DB>,
        storage: &Arc<ConsensusStorage>,
        services: &Arc<ConsensusServices>,

        pruning_lock: SessionLock,
        notification_root: Arc<ConsensusNotificationRoot>,
        counters: Arc<ProcessingCounters>,
    ) -> Self {
        Self {
            receiver,
            sender,
            thread_pool,
            db,

            max_block_mass: params.max_block_mass,
            genesis: params.genesis.clone(),
            _ghostdag_k: params.ghostdag_k(),

            statuses_store: storage.statuses_store.clone(),
            _ghostdag_store: storage.ghostdag_store.clone(),
            headers_store: storage.headers_store.clone(),
            block_transactions_store: storage.block_transactions_store.clone(),
            evm_payload_store: storage.evm_payload_store.clone(),
            #[cfg(feature = "evm")]
            evm_raw_tx_store: storage.evm_raw_tx_store.clone(),
            body_tips_store: storage.body_tips_store.clone(),
            palw_store: storage.palw_store.clone(),
            palw_overlay_view_store: storage.palw_overlay_view_store.clone(),
            ghostdag_store: storage.ghostdag_store.clone(),
            palw_activation_daa_score: params.palw_activation_daa_score,
            palw_epoch_length_daa: params.palw_epoch_length_daa,
            palw_beacon_grace_epochs: params.palw_beacon_grace_epochs,
            palw_batch_admission: params.palw_batch_admission,
            palw_network_id: params.net.suffix().unwrap_or(0),
            evm_activation_daa_score: params.evm_activation_daa_score,
            dns_params: params.dns_params.clone(),

            reachability_service: services.reachability_service.clone(),
            coinbase_manager: services.coinbase_manager.clone(),
            mass_calculator: services.mass_calculator.clone(),
            transaction_validator: services.transaction_validator.clone(),
            window_manager: services.window_manager.clone(),

            pruning_lock,
            task_manager: BlockTaskDependencyManager::new(),
            notification_root,
            counters,
        }
    }

    pub fn worker(self: &Arc<BlockBodyProcessor>) {
        while let Ok(msg) = self.receiver.recv() {
            match msg {
                BlockProcessingMessage::Exit => break,
                BlockProcessingMessage::Process(task, block_result_transmitter, virtual_result_transmitter) => {
                    if let Some(task_id) = self.task_manager.register(task, block_result_transmitter, virtual_result_transmitter) {
                        let processor = self.clone();
                        self.thread_pool.spawn(move || {
                            processor.queue_block(task_id);
                        });
                    }
                }
            };
        }

        // Wait until all workers are idle before exiting
        self.task_manager.wait_for_idle();

        // Pass the exit signal on to the following processor
        self.sender.send(VirtualStateProcessingMessage::Exit).unwrap();
    }

    fn queue_block(self: &Arc<BlockBodyProcessor>, task_id: TaskId) {
        if let Some(task) = self.task_manager.try_begin(task_id) {
            let res = self.process_body(task.block(), task.is_trusted());

            let dependent_tasks = self.task_manager.end(task, |task, block_result_transmitter, virtual_state_result_transmitter| {
                let _ = block_result_transmitter.send(res.clone());
                if res.is_err() || !task.requires_virtual_processing() {
                    // We don't care if receivers were dropped
                    let _ = virtual_state_result_transmitter.send(res.clone());
                } else {
                    self.sender.send(VirtualStateProcessingMessage::Process(task, virtual_state_result_transmitter)).unwrap();
                }
            });

            for dep in dependent_tasks {
                let processor = self.clone();
                self.thread_pool.spawn(move || processor.queue_block(dep));
            }
        }
    }

    fn process_body(self: &Arc<BlockBodyProcessor>, block: &Block, is_trusted: bool) -> BlockProcessResult<BlockStatus> {
        let _prune_guard = self.pruning_lock.blocking_read();
        let status = self.statuses_store.read().get(block.hash()).unwrap();
        match status {
            StatusInvalid => return Err(RuleError::KnownInvalid),
            StatusHeaderOnly => {} // Proceed to body processing
            _ if status.has_block_body() => return Ok(status),
            _ => panic!("unexpected block status {status:?}"),
        }

        let mass = match self.validate_body(block, is_trusted) {
            Ok(mass) => mass,
            Err(e) => {
                // We mark invalid blocks with status StatusInvalid except in the
                // case of the following errors:
                // MissingParents - If we got MissingParents the block shouldn't be
                // considered as invalid because it could be added later on when its
                // parents are present.
                // BadMerkleRoot - if we get BadMerkleRoot we shouldn't mark the
                // block as invalid because later on we can get the block with
                // transactions that fits the merkle root.
                // PrunedBlock - PrunedBlock is an error that rejects a block body and
                // not the block as a whole, so we shouldn't mark it as invalid.
                if !matches!(e, RuleError::BadMerkleRoot(_, _) | RuleError::MissingParents(_) | RuleError::PrunedBlock) {
                    self.statuses_store.write().set(block.hash(), BlockStatus::StatusInvalid).unwrap();
                }
                return Err(e);
            }
        };

        self.commit_body(block.hash(), block.header.direct_parents(), block.transactions.clone(), &block.evm_payload);

        // Send a BlockAdded notification
        self.notification_root
            .notify(Notification::BlockAdded(BlockAddedNotification::new(block.to_owned())))
            .expect("expecting an open unbounded channel");

        // Report counters
        self.counters.body_counts.fetch_add(1, Ordering::Relaxed);
        self.counters.txs_counts.fetch_add(block.transactions.len() as u64, Ordering::Relaxed);
        self.counters.mass_counts.fetch_add(mass.max(), Ordering::Relaxed);
        Ok(BlockStatus::StatusUTXOPendingVerification)
    }

    fn validate_body(self: &Arc<BlockBodyProcessor>, block: &Block, is_trusted: bool) -> BlockProcessResult<Mass> {
        let mass = self.validate_body_in_isolation(block)?;
        if !is_trusted {
            self.validate_body_in_context(block)?;
        }
        Ok(mass)
    }

    fn commit_body(
        self: &Arc<BlockBodyProcessor>,
        hash: BlockHash,
        parents: &[BlockHash],
        transactions: Arc<Vec<Transaction>>,
        evm_payload: &kaspa_consensus_core::evm::EvmExecutionPayload,
    ) {
        let mut batch = WriteBatch::default();

        // This is an append only store so it requires no lock.
        self.block_transactions_store.insert_batch(&mut batch, hash, transactions).unwrap();

        // kaspa-pq EVM Lane v0.4 (§3.1): persist the block's own payload so the
        // virtual processor can later read it as part of some chain block's
        // mergeset acceptance. Empty payloads are skipped (absent = empty);
        // insert is idempotent under body revalidation.
        if !evm_payload.is_empty() {
            self.evm_payload_store.insert_batch(&mut batch, hash, evm_payload.clone()).unwrap();
            // §16 (audit R-2): index each raw EVM tx by its hash so
            // eth_getTransactionByHash/receipt resolve it directly, surviving the
            // bounded EvmTxLocations.included_in cap (16). RPC index only; tx_hash
            // needs kaspa-evm (the evm feature). Empty payloads (every non-evm
            // build / pre-activation block) never reach here.
            #[cfg(feature = "evm")]
            for raw in &evm_payload.transactions {
                let txh = kaspa_evm::tx::tx_hash(raw);
                self.evm_raw_tx_store.write_batch(&mut batch, txh, raw.clone(), hash).unwrap();
            }
        }

        // ADR-0039 §18.2 (C5 option B): build this block's fork-local batch-lifecycle view
        // `view(B) = view(SP(B)) ⊕ Δ(mergeset(B))` in the same commit batch (block-keyed, past-relative,
        // read at the selected parent by the algo-4 ticket check). Inert fast-path return on every
        // shipped preset. Its bodies-of-the-mergeset reads are sound here: the body-DAG downward closure
        // (`check_parent_bodies_exist`) guarantees every mergeset block already has a committed body.
        self.commit_palw_overlay_view(&mut batch, hash);

        let mut body_tips_write_guard = self.body_tips_store.write();
        body_tips_write_guard.add_tip_batch(&mut batch, hash, parents).unwrap();
        let statuses_write_guard =
            self.statuses_store.set_batch(&mut batch, hash, BlockStatus::StatusUTXOPendingVerification).unwrap();

        self.db.write(batch).unwrap();

        // Calling the drops explicitly after the batch is written in order to avoid possible errors.
        drop(statuses_write_guard);
        drop(body_tips_write_guard);
    }

    /// ADR-0039 §18.2 (C5 option B) — build `hash`'s fork-local batch-lifecycle view as
    /// `view(SP(hash)) ⊕ Δ(mergeset(hash))`: clone the selected parent's view, fold in the accepted
    /// overlay-tx effects of every mergeset-blue block (manifest ⇒ Registering, leaf chunks ⇒ Committed
    /// on completeness, certificate ⇒ Certified), advance the epoch-driven edges, and drop the no-longer-
    /// referenceable batches. Written into the block's commit batch, keyed by `hash`. This is the
    /// past-relative overlay the algo-4 ticket check resolves against (C5), replacing the tip-global
    /// `DbPalwStore` read. Each manifest is admitted at ITS CARRIER block's epoch (`registration_epoch ==
    /// carrier_epoch`), a deterministic, mergeset-consistent coordinate.
    ///
    /// **Fence status (corrected — the previous "inert on every shipped preset" claim was FALSE).**
    /// The fast-path guard tests `palw_activation_daa_score == u64::MAX` and so returns — making this a
    /// byte-identical structural no-op — only on **mainnet / testnet-10 / simnet / devnet**. On
    /// `testnet-palw-110` and `devnet-palw-111` the fence is **0** (`config/params.rs:1403`, `:1454`),
    /// the guard never fires, and this builder RUNS AND WRITES A ROW FOR EVERY BLOCK.
    ///
    /// `palw_algo4_accept = false` does not gate this path — it withholds algo-4 header acceptance in
    /// `pre_ghostdag_validation.rs`, bounding what the view can contain, not whether it is written. The
    /// persisted rows are therefore real on those two presets, which is what forced the
    /// `LATEST_DB_VERSION` 7 → 8 bump (`consensus/src/consensus/factory.rs`).
    ///
    /// The mergeset bodies are guaranteed present by the body-DAG downward closure.
    fn commit_palw_overlay_view(self: &Arc<BlockBodyProcessor>, batch: &mut WriteBatch, hash: BlockHash) {
        use kaspa_consensus_core::palw::{PalwBatchViewV1, PalwBatchAdmissionParams};
        use crate::processes::palw::PalwOverlayEffect;
        if self.palw_activation_daa_score == u64::MAX {
            return; // inert fast path
        }
        let cur_daa = self.headers_store.get_daa_score(hash).unwrap();
        if cur_daa < self.palw_activation_daa_score {
            return;
        }
        let gd = self.ghostdag_store.get_data(hash).unwrap();
        let selected_parent = gd.selected_parent;
        let epoch_len = self.palw_epoch_length_daa.max(1);
        let epoch = cur_daa / epoch_len;
        let a: &PalwBatchAdmissionParams = &self.palw_batch_admission;

        // Seed from the selected parent's carried view (empty at genesis / a pre-activation parent).
        let mut view = self.palw_overlay_view_store.view(selected_parent).unwrap().map(|v| (*v).clone()).unwrap_or_else(PalwBatchViewV1::new);

        // Fold in Δ(mergeset): every mergeset-blue EXCEPT the selected parent (whose effects are already
        // in `view(SP)`; `mergeset_blues[0]` is the selected parent — §GHOSTDAG). Overlay txs are
        // admitted at their carrier block's epoch.
        //
        // **ADR-0040 VIEW-01 — the block's OWN body is deliberately not folded here.**
        //
        // A block is not in its own mergeset, so `B`'s own PALW overlay txs never enter `view(B)`; they
        // enter the views of B's descendants, which merge B. The audit read this as half of C-03 (a
        // missing self-fold), and the code did not say which it was. It is DELIBERATE: a batch
        // registered in B's own body must not be usable by a ticket in B's own header, or a producer
        // could register and spend a batch atomically, defeating the registration lead that the
        // admission window exists to impose. `check_palw_ticket` resolves against `view(SP)` for the
        // same reason.
        //
        // **ADR-0040 P1-5 (DOS-02 / BIND-03) — the coordinate decision, and why the view STAYS here.**
        //
        // The other half of C-03 is that this fold reads RAW mergeset transactions with no acceptance
        // filter, so a never-accepted or double-spending tx still moves the view. The obvious remedy —
        // move the view to the acceptance coordinate — is NOT available, and the reason is decisive:
        //
        //   `check_palw_ticket` resolves against `view(SP)` at BODY validation. Acceptance data exists
        //   only for blocks that have been VIRTUAL-processed, i.e. that became chain blocks. A
        //   side-chain selected parent never is. An acceptance-coordinate view would therefore be
        //   `None` for such an SP, making body validation succeed or fail depending on chain-selection
        //   and arrival order — a permanent, order-dependent `StatusInvalid`. That is a consensus split,
        //   which is strictly worse than the resource issue it would fix.
        //
        // So the view is body/mergeset-coordinate BY NECESSITY, not by oversight, and DOS-02 is closed
        // by BOUNDING what an unaccepted fold can achieve rather than by filtering it out. It is now
        // closed by REMOVAL, which is stronger than a bound:
        //
        //   * the fold writes NO per-leaf state at all. The `job_nullifiers` map this arm used to grow —
        //     up to 64 unpriced, ownership-unbound entries per leaf-chunk tx, retained to an
        //     attacker-chosen expiry, in a struct cloned and re-persisted every block — is DELETED
        //     (ADR-0040 P1-9, withdrawn from this coordinate as a spec change). The persisted view is
        //     therefore `|batches| ≤ max_view_batches` entries and nothing else: an EXACT,
        //     parameter-free bound of ZERO per-leaf bytes on every fork at every height;
        //   * a forged batch cannot become MINEABLE — ADR-0040 CERT-TRUST made this fold monotone and
        //     non-destructive (promotion + write-once `cert_hash` only), and the certificate a ticket
        //     actually uses must resolve out of `palw_store`, which is written only behind the STORE
        //     gate `verify_certificate_attestation` (real ML-DSA quorum over active bonds) at the
        //     virtual coordinate. `apply_certificate` itself verifies nothing — the bound is the store
        //     gate, and the ticket reads that store, never this view's `cert_hash`. View mutation alone
        //     certifies nothing and, crucially, DESTROYS nothing;
        //   * the number of view entries is capped (`max_view_batches`, DOS-03), so slots are finite —
        //     and that cap is now itself enforced, not merely documented: a preset that activates PALW
        //     with `max_view_batches == 0` fails `PalwBatchAdmissionParams::is_consistent_for_activation`;
        //   * leaves are write-once and manifest-bounded (P1-1), so entries cannot be grown or rewritten;
        //   * every fold source is a mergeset BLUE, i.e. a block someone had to mine, so consuming a view
        //     slot costs block production — the network's own rate limit — rather than being free.
        //
        // THE RESIDUAL IS A CENSORSHIP LEVER, not merely bounded slot consumption — state it that way.
        // Refuse-at-cap was chosen over eviction because eviction lets a flood DISPLACE incumbents. It
        // does not stop a flood from PRE-EMPTING them: once the cap is full, every honest manifest is
        // refused until entries expire. And the pre-emption is nearly free, because `min_leaf_bond_sompi
        // = 0` on every shipped preset, so `admission_valid`'s bond requirement (`leaf_count ·
        // min_leaf_bond_sompi`) is vacuous — the only cost is producing the blues that carry the
        // manifests. So the true residual is: an attacker who can mine can lock honest providers out of
        // the view for up to one expiry window, at block-production cost alone.
        //
        // FILED, not fixed here, because pricing it is a calibration decision that belongs to the
        // re-genesis that activates PALW, not to a remediation patch: `min_leaf_bond_sompi` must become
        // non-zero, large enough that filling `max_view_batches` slots costs more than the value of the
        // censorship window. Two things have to be re-checked together whenever either moves —
        // raising `max_view_batches` raises the flood cost but also the per-block clone cost, and
        // raising the bond prices out small honest providers. This is an ACTIVATION-blocking item; see
        // the ADR-0040 §5.12 gate row.
        for &blue in gd.mergeset_blues.iter().filter(|&&b| b != selected_parent) {
            let carrier_epoch = self.headers_store.get_daa_score(blue).unwrap_or(0) / epoch_len;
            let Ok(txs) = self.block_transactions_store.get(blue) else { continue };
            for tx in txs.iter() {
                let Some(kind) = tx.subnetwork_id.palw_tx_kind() else { continue };
                match crate::processes::palw::parse_palw_overlay(kind, &tx.payload) {
                    Ok(PalwOverlayEffect::Manifest(m)) => {
                        view.apply_manifest(
                            &m,
                            carrier_epoch,
                            a.max_batch_leaves,
                            a.max_leaf_chunk_leaves,
                            a.registration_lead_epochs,
                            a.active_window_epochs,
                            a.audit_window_epochs,
                            a.min_leaf_bond_sompi,
                            a.max_view_batches,
                        );
                    }
                    Ok(PalwOverlayEffect::LeafChunk(c)) => {
                        // ADR-0040 P1-9 — the GLOBAL job-nullifier claim is WITHDRAWN from this
                        // coordinate (spec change; see `PalwBatchViewV1`'s doc and ADR-0040). It was
                        // never in force — its bool fed a `continue` that ended a loop body containing
                        // nothing else, and `job_nullifier_spent` had no production reader — and it
                        // cannot be armed here: authorising a claim needs the provider's ML-DSA
                        // signature over `ReplicaExecutionReceiptV1::signing_hash`, which requires an
                        // `ActiveBondView` that exists only at the virtual coordinate. The rule re-lands
                        // there as a REWARD rule; here, a chunk's applicability is fully expressed by
                        // the bitmap, so this is the whole delta. `apply_leaf_chunk`'s bool is
                        // intentionally unused: refusal (unknown batch / non-Registering status /
                        // duplicate or out-of-range `chunk_index`) is a no-op on the view by design.
                        view.apply_leaf_chunk(&c.batch_id, c.chunk_index);
                    }
                    Ok(PalwOverlayEffect::Certificate(cert)) => {
                        // kaspa-pq **ADR-0040 CERT-TRUST** — this fold is MONOTONE and reads NOTHING the
                        // certificate declares beyond its own content hash.
                        //
                        // Accurate statement of which coordinate verifies what (the previous comment
                        // here was false and is replaced):
                        //
                        //   * BODY (here): no `ActiveBondView` exists, and — per the DOS-02 note above —
                        //     the tx need not even be accepted. Nothing a certificate says can be
                        //     checked. So this only promotes `Committed|Auditing → Certified` and sets
                        //     `cert_hash` write-once. It never ranks, never overwrites, never copies a
                        //     window or a stake figure. §12′ supersession is REMOVED from this
                        //     coordinate (spec change): it ranked by a self-declared `approving_stake`,
                        //     so `u128::MAX` won every comparison and evicted honest certificates.
                        //   * VIRTUAL (`apply_palw_overlay_effect` → `verify_certificate_attestation`):
                        //     the bond view exists, the vote tally is RECOMPUTED, and `approving_stake`
                        //     is bound to it. Only then may the blob be persisted into `palw_store`.
                        //   * TICKET (`body_validation_in_context`): the certificate a header actually
                        //     uses is resolved out of that attested store, and its `[activation,
                        //     expiry)` window is taken from the attested blob — never from this view.
                        //
                        // Hence a junk certificate tx can at worst promote a batch to `Certified` with a
                        // `cert_hash` naming no attested blob, which mines nothing.
                        view.apply_certificate(&cert.batch_id, cert.hash(), self.headers_store.get_daa_score(blue).unwrap_or(0));
                    }
                    // Beacon commit/reveal (0x35/0x36) stay on the acceptance/virtual coordinate; provider
                    // bond (0x30) + slashing/unbond are their own slices; malformed payloads are dropped.
                    _ => {}
                }
            }
        }

        // ADR-0039 §11.3 (K5): freeze Certified→Active while the lagged buried beacon-health signal is
        // not Healthy. Computed LAZILY — only when a Certified batch could actually flip this epoch (the
        // gate cannot influence any other transition, so the walk is skipped otherwise) — from THIS
        // block's selected parent, the SAME coordinate `check_palw_ticket` gates its in-memory advance
        // on (the two sites must never diverge on an activation net). Fail-closed: no dns_params / no
        // buried anchor / < 2 samples ⇒ frozen.
        let could_activate = view
            .batches
            .values()
            .any(|e| e.status == kaspa_consensus_core::palw::PalwBatchStatus::Certified && epoch >= e.activation_not_before_epoch);
        let activation_open = could_activate
            && self
                .dns_params
                .as_ref()
                .and_then(|dns| {
                    crate::processes::palw::resolve_palw_lagged_anchor(
                        &self.headers_store,
                        &self.reachability_service,
                        dns,
                        selected_parent,
                    )
                })
                .map(|anchor| {
                    kaspa_consensus_core::palw::palw_lagged_activation_open(&self.palw_buried_epoch_samples(anchor.anchor_hash))
                })
                .unwrap_or(false);
        view.advance_epoch_gated(epoch, a.registration_lead_epochs, a.audit_window_epochs, activation_open);
        view.retain(epoch, cur_daa, a.registration_lead_epochs, a.audit_window_epochs);
        self.palw_overlay_view_store.set_batch(batch, hash, Arc::new(view)).unwrap();
    }

    /// ADR-0039 §11.3 (K5): the lagged buried `(palw_epoch, seed)` samples below a clause-6 anchor —
    /// the shared input of the clause-10 halt indicator, the activation gate, and (future) the algo-4
    /// template's `palw_template_lane_open` check. `grace + 2` distinct epochs suffice to certify a
    /// carry run `> grace` and to answer the two-newest-distinct-epochs activation question.
    pub(super) fn palw_buried_epoch_samples(&self, anchor_hash: BlockHash) -> Vec<(u64, kaspa_hashes::Hash64)> {
        crate::processes::palw::resolve_palw_buried_epoch_seeds(
            &self.headers_store,
            &self.reachability_service,
            anchor_hash,
            self.palw_activation_daa_score,
            self.palw_epoch_length_daa,
            self.palw_beacon_grace_epochs.saturating_add(2),
        )
    }

    pub fn process_genesis(self: &Arc<BlockBodyProcessor>) {
        // Init tips store
        let mut batch = WriteBatch::default();
        let mut body_tips_write_guard = self.body_tips_store.write();
        body_tips_write_guard.init_batch(&mut batch, &[]).unwrap();
        self.db.write(batch).unwrap();
        drop(body_tips_write_guard);

        // Write the genesis body
        self.commit_body(self.genesis.hash, &[], Arc::new(self.genesis.build_genesis_transactions()), &Default::default())
    }
}
