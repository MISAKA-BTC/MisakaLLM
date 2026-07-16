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
    /// binding against, plus the lane's activation fence + epoch length. `palw_activation_daa_score`
    /// is `u64::MAX` on every shipped preset, so `check_palw_ticket` returns before any store read —
    /// byte-identical there.
    pub(super) palw_store: Arc<crate::model::stores::palw::DbPalwStore>,
    pub(super) palw_overlay_view_store: Arc<crate::model::stores::palw_overlay_view::DbPalwOverlayViewStore>,
    pub(super) ghostdag_store: Arc<DbGhostdagStore>,
    pub(super) palw_activation_daa_score: u64,
    pub(super) palw_epoch_length_daa: u64,
    pub(super) palw_batch_admission: kaspa_consensus_core::palw::PalwBatchAdmissionParams,

    // Managers and services
    pub(super) _reachability_service: MTReachabilityService<DbReachabilityStore>,
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
            palw_batch_admission: params.palw_batch_admission,

            _reachability_service: services.reachability_service.clone(),
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
    /// **Inert on every shipped preset** (`palw_activation_daa_score == u64::MAX`): the fast-path guard
    /// returns before any read/write, so this is a structural no-op (byte-identical). The mergeset
    /// bodies are guaranteed present by the body-DAG downward closure.
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
                        );
                    }
                    Ok(PalwOverlayEffect::LeafChunk(c)) => {
                        view.apply_leaf_chunk(&c.batch_id, c.chunk_index);
                    }
                    Ok(PalwOverlayEffect::Certificate(cert)) => {
                        view.apply_certificate(&cert.batch_id, cert.hash(), cert.activation_epoch, cert.expiry_epoch);
                    }
                    // Beacon commit/reveal (0x35/0x36) stay on the acceptance/virtual coordinate; provider
                    // bond (0x30) + slashing/unbond are their own slices; malformed payloads are dropped.
                    _ => {}
                }
            }
        }

        view.advance_epoch(epoch, a.registration_lead_epochs, a.audit_window_epochs);
        view.retain(epoch, a.registration_lead_epochs, a.audit_window_epochs);
        self.palw_overlay_view_store.set_batch(batch, hash, Arc::new(view)).unwrap();
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
