use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use crate::model::{
    services::reachability::{MTReachabilityService, ReachabilityService},
    stores::{
        ghostdag::{CompactGhostdagData, GhostdagStoreReader},
        headers::HeaderStoreReader,
        headers_selected_tip::HeadersSelectedTipStoreReader,
        past_pruning_points::PastPruningPointsStoreReader,
        pruning_samples::PruningSamplesStore,
        reachability::ReachabilityStoreReader,
    },
};
use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::{
    blockhash::BlockHashExtensions,
    errors::pruning::{PruningImportError, PruningImportResult},
};
use kaspa_database::prelude::StoreResultExt;
use parking_lot::RwLock;

pub struct PruningPointReply {
    /// The most recent pruning sample from POV of the queried block (with distance up to ~F)
    pub pruning_sample: BlockHash,

    /// The pruning point of the queried block. I.e., the most recent pruning sample with depth P
    pub pruning_point: BlockHash,
}

/// The read-only result of validating the selected-chain path to a syncer sink.
///
/// `pruning_sample_writes` deliberately remains an in-memory write-set until the caller has
/// completed every other intrusive pruning-point preflight. This prevents a late bad header/path
/// from leaking recursively-derived pruning samples into the live store.
pub(crate) struct PruningPointPathPreflight {
    pub pruning_points: VecDeque<BlockHash>,
    pub pruning_sample_writes: Vec<(BlockHash, BlockHash)>,
}

#[derive(Clone)]
pub struct PruningPointManager<
    S: GhostdagStoreReader,
    T: ReachabilityStoreReader,
    U: HeaderStoreReader,
    V: PastPruningPointsStoreReader,
    W: HeadersSelectedTipStoreReader,
    Y: PruningSamplesStore,
> {
    /// Pruning depth param. Throughout this file we use P to indicate this depth
    pruning_depth: u64,

    /// Finality depth param. Throughout this file we use F to indicate this depth
    /// Note that this quantity represents here the interval between pruning point samples and is not tightly coupled with the
    /// actual concept of finality as used by virtual processor to reject deep reorgs   
    finality_depth: u64,

    genesis_hash: BlockHash,

    reachability_service: MTReachabilityService<T>,
    ghostdag_store: Arc<S>,
    headers_store: Arc<U>,
    past_pruning_points_store: Arc<V>,
    _header_selected_tip_store: Arc<RwLock<W>>,
    pruning_samples_store: Arc<Y>,

    /// The number of hops to go through pruning samples in order to get the pruning point of a sample
    pruning_samples_steps: u64,
}

impl<
    S: GhostdagStoreReader,
    T: ReachabilityStoreReader,
    U: HeaderStoreReader,
    V: PastPruningPointsStoreReader,
    W: HeadersSelectedTipStoreReader,
    Y: PruningSamplesStore,
> PruningPointManager<S, T, U, V, W, Y>
{
    pub fn new(
        pruning_depth: u64,
        finality_depth: u64,
        genesis_hash: BlockHash,
        reachability_service: MTReachabilityService<T>,
        ghostdag_store: Arc<S>,
        headers_store: Arc<U>,
        past_pruning_points_store: Arc<V>,
        header_selected_tip_store: Arc<RwLock<W>>,
        pruning_samples_store: Arc<Y>,
    ) -> Self {
        let pruning_samples_steps = pruning_depth.div_ceil(finality_depth);

        Self {
            pruning_depth,
            finality_depth,
            genesis_hash,
            reachability_service,
            ghostdag_store,
            headers_store,
            past_pruning_points_store,
            _header_selected_tip_store: header_selected_tip_store,
            pruning_samples_steps,
            pruning_samples_store,
        }
    }

    /// The method for calculating the expected pruning point from some POV (header/virtual) using the
    /// pruning samples store.
    ///
    /// Let B denote the current block (represented by `ghostdag_data`)
    /// Assumptions:
    ///     1. This method assumes that the current global pruning point is on B's chain, which
    ///        is why it should be called only for chain candidates / sink / virtual
    ///     2. All chain ancestors of B up to the pruning point are expected to have a
    ///        `pruning_sample_from_pov` store entry    
    pub fn expected_header_pruning_point(&self, ghostdag_data: CompactGhostdagData) -> PruningPointReply {
        self.expected_header_pruning_point_with_overlay(ghostdag_data, &HashMap::new())
    }

    /// Equivalent to [`Self::expected_header_pruning_point`], with an append-only in-memory view of
    /// pruning samples derived earlier on the same selected-chain walk. The overlay is what makes
    /// path validation recursive without publishing intermediate rows to the DB/cache.
    fn expected_header_pruning_point_with_overlay(
        &self,
        ghostdag_data: CompactGhostdagData,
        pruning_samples_overlay: &HashMap<BlockHash, BlockHash>,
    ) -> PruningPointReply {
        //
        // Note that past pruning samples are only assumed to have a header store entry and a pruning sample
        // store entry, se we only use these stores here (and specifically do not use the ghostdag store)
        //

        let pruning_depth = self.pruning_depth;
        let finality_depth = self.finality_depth;

        let selected_parent_blue_score = self.headers_store.get_blue_score(ghostdag_data.selected_parent).unwrap();

        let pruning_sample = if ghostdag_data.selected_parent == self.genesis_hash {
            self.genesis_hash
        } else {
            let selected_parent_pruning_sample = pruning_samples_overlay
                .get(&ghostdag_data.selected_parent)
                .copied()
                .unwrap_or_else(|| self.pruning_samples_store.pruning_sample_from_pov(ghostdag_data.selected_parent).unwrap());
            let selected_parent_pruning_sample_blue_score = self.headers_store.get_blue_score(selected_parent_pruning_sample).unwrap();

            if self.is_pruning_sample(selected_parent_blue_score, selected_parent_pruning_sample_blue_score, finality_depth) {
                // The selected parent is the most recent sample
                ghostdag_data.selected_parent
            } else {
                // ...otherwise take the sample from its pov
                selected_parent_pruning_sample
            }
        };

        let is_self_pruning_sample = self.is_pruning_sample(ghostdag_data.blue_score, selected_parent_blue_score, finality_depth);
        let selected_parent_pruning_point = self.headers_store.get_header(ghostdag_data.selected_parent).unwrap().pruning_point;
        let mut steps = 1;
        let mut current = pruning_sample;
        let pruning_point = loop {
            if current == self.genesis_hash {
                break current;
            }
            let current_blue_score = self.headers_store.get_blue_score(current).unwrap();
            // Find the most recent sample with pruning depth
            if current_blue_score + pruning_depth <= ghostdag_data.blue_score {
                break current;
            }
            // For samples: special clamp for the period right after a blockrate hardfork (where we might reach ceiling(P/F) steps before reaching the new pruning depth)
            if is_self_pruning_sample && steps == self.pruning_samples_steps {
                break current;
            }
            // For non samples: clamp to selected parent pruning point to maintain monotonicity (needed because of the previous condition)
            if current == selected_parent_pruning_point {
                break current;
            }
            current = pruning_samples_overlay
                .get(&current)
                .copied()
                .unwrap_or_else(|| self.pruning_samples_store.pruning_sample_from_pov(current).unwrap());
            steps += 1;
        };

        PruningPointReply { pruning_sample, pruning_point }
    }

    /// A block is a pruning sample *iff* its own finality score is larger than its pruning sample
    /// finality score or its selected parent finality score (or any block in between them).
    ///
    /// To see why we can compare to any such block, observe that by definition all blocks in the range
    /// `[pruning sample, selected parent]` must have the same finality score.
    pub fn is_pruning_sample(&self, self_blue_score: u64, epoch_chain_ancestor_blue_score: u64, finality_depth: u64) -> bool {
        self.finality_score(epoch_chain_ancestor_blue_score, finality_depth) < self.finality_score(self_blue_score, finality_depth)
    }

    pub fn next_pruning_points(&self, sink_ghostdag: CompactGhostdagData, current_pruning_point: BlockHash) -> Vec<BlockHash> {
        if sink_ghostdag.selected_parent.is_origin() {
            // This only happens when sink is genesis
            return vec![];
        }

        let current_pruning_point_blue_score = self.headers_store.get_blue_score(current_pruning_point).unwrap();

        // Sanity check #1: global pruning point depth from sink >= P
        if current_pruning_point_blue_score + self.pruning_depth > sink_ghostdag.blue_score {
            // During initial IBD the sink can be close to the global pruning point.
            return vec![];
        }

        let sink_pruning_point = self.expected_header_pruning_point(sink_ghostdag).pruning_point;
        let sink_pruning_point_blue_score = self.headers_store.get_blue_score(sink_pruning_point).unwrap();

        // Sanity check #2: if the sink pruning point is lower or equal to current, there is no need to search
        if sink_pruning_point_blue_score <= current_pruning_point_blue_score {
            return vec![];
        }

        let mut current = sink_pruning_point;
        let mut deque = VecDeque::with_capacity(self.pruning_samples_steps as usize);
        // At this point we have verified that sink_pruning_point is a chain block above current_pruning_point
        // (by comparing blue score) so we know the loop must eventually exit correctly
        while current != current_pruning_point {
            deque.push_front(current);
            current = self.pruning_samples_store.pruning_sample_from_pov(current).unwrap();
        }

        deque.into()
    }

    /// Returns the floored integer division of blue score by finality depth.
    /// The returned number represent the sampling epoch this blue score point belongs to.   
    fn finality_score(&self, blue_score: u64, finality_depth: u64) -> u64 {
        blue_score / finality_depth
    }

    fn is_pruning_point_in_pruning_depth(&self, pov_blue_score: u64, pruning_point: BlockHash, pruning_depth: u64) -> bool {
        let pp_bs = self.headers_store.get_blue_score(pruning_point).unwrap();
        pov_blue_score >= pp_bs + pruning_depth
    }

    pub fn is_valid_pruning_point(&self, pp_candidate: BlockHash, tip: BlockHash) -> bool {
        if pp_candidate == self.genesis_hash {
            return true;
        }
        if !self.reachability_service.is_chain_ancestor_of(pp_candidate, tip) {
            return false;
        }

        let tip_bs = self.ghostdag_store.get_blue_score(tip).unwrap();
        self.is_pruning_point_in_pruning_depth(tip_bs, pp_candidate, self.pruning_depth)
    }

    // Function returns the pruning points on the path
    // ordered from newest to the oldest
    pub fn pruning_points_on_path_to_syncer_sink(
        &self,
        pruning_point: BlockHash,
        syncer_sink: BlockHash,
    ) -> PruningImportResult<VecDeque<BlockHash>> {
        let preflight = self.preflight_pruning_points_on_path_to_syncer_sink(pruning_point, syncer_sink)?;
        for (hash, pruning_sample) in preflight.pruning_sample_writes {
            self.pruning_samples_store.insert(hash, pruning_sample).unwrap();
        }
        Ok(preflight.pruning_points)
    }

    /// Read-only variant of [`Self::pruning_points_on_path_to_syncer_sink`]. It derives every
    /// recursive pruning-sample row in memory and returns the rows to its caller instead of writing
    /// them. Intrusive pruning-point import uses this method so the rows can join the final atomic
    /// pruning/PALW `WriteBatch` only after all path and anticone checks succeed.
    pub(crate) fn preflight_pruning_points_on_path_to_syncer_sink(
        &self,
        pruning_point: BlockHash,
        syncer_sink: BlockHash,
    ) -> PruningImportResult<PruningPointPathPreflight> {
        let mut pps_on_path = VecDeque::new();
        let mut pruning_samples_overlay = HashMap::new();
        let mut pruning_sample_writes = Vec::new();
        for current in self.reachability_service.forward_chain_iterator(pruning_point, syncer_sink, true).skip(1) {
            let current_header = self.headers_store.get_header(current).unwrap();
            // Post-crescendo: expected header pruning point is no longer part of header validity, but we want to make sure
            // the syncer's virtual chain indeed coincides with the pruning point and past pruning points before downloading
            // the UTXO set and resolving virtual. Hence we perform the check over this chain here.
            let reply = self.expected_header_pruning_point_with_overlay(
                self.ghostdag_store.get_compact_data(current).unwrap(),
                &pruning_samples_overlay,
            );
            if reply.pruning_point != current_header.pruning_point {
                return Err(PruningImportError::WrongHeaderPruningPoint(current_header.pruning_point, current));
            }
            // An append-only row may already exist from an earlier validated path. It must equal the
            // deterministic recomputation: treating a conflicting KeyAlreadyExists as idempotent
            // would validate subsequent headers against this overlay while retaining another value
            // in RocksDB across restart.
            match self.pruning_samples_store.pruning_sample_from_pov(current).optional().unwrap() {
                Some(existing) if existing != reply.pruning_sample => {
                    return Err(PruningImportError::ConflictingPruningSample(current, existing, reply.pruning_sample));
                }
                Some(_) => {}
                None => pruning_sample_writes.push((current, reply.pruning_sample)),
            }
            // Keep the recursively required row private to this preflight. The caller either commits
            // the complete missing-row write-set after every check succeeds or drops it wholesale.
            pruning_samples_overlay.insert(current, reply.pruning_sample);
            // Going up the chain from the pruning point to the sink. The goal is to exit this loop with a queue [P(k),...,P(0), P(-1), P(-2), ..., P(-n)]
            // where P(0) is the new pruning point, P(-1) is the point before it and P(-n) is the pruning point of P(0). That is,
            // ceiling(P/F) = n (where n is usually 3).
            // k is the number of future pruning points on path to virtual beyond the new, currently synced pruning point
            //
            // Let C be the current block's pruning point. Push to the front of the queue if:
            // 1. the queue is empty
            // 2. the front of the queue is different than C
            if pps_on_path.front().is_none_or(|&h| h != current_header.pruning_point) {
                pps_on_path.push_front(current_header.pruning_point);
            }
        }
        Ok(PruningPointPathPreflight { pruning_points: pps_on_path, pruning_sample_writes })
    }

    pub fn are_pruning_points_in_valid_chain(
        &self,
        synced_pruning_point: BlockHash,
        synced_pp_index: u64,
        syncer_sink: BlockHash,
    ) -> PruningImportResult<()> {
        // We want to validate that the past pruning points form a chain to genesis. Since
        // each pruning point's header doesn't point to the previous pruning point, but to
        // the pruning point from its POV, we can't just traverse from one pruning point to
        // the next one by merely relying on the current pruning point header, but instead
        // we rely on the fact that each pruning point is pointed by another known block or
        // pruning point.
        // So in the first stage we go over the selected chain and add to the queue of expected
        // pruning points all the pruning points from the POV of some chain block, and update pruning samples.
        // In the second stage we go over the past pruning points from recent to older, check that it's the head
        // of the queue (by popping the queue), and add its header pruning point to the queue since
        // we expect to see it later on the list.
        // The first stage is important because the most recent pruning point is pointing to a few
        // pruning points before, so the first few pruning points on the list won't be pointed by
        // any other pruning point in the list, so we are compelled to check if it's referenced by
        // the selected chain.
        let mut expected_pps_queue = self.pruning_points_on_path_to_syncer_sink(synced_pruning_point, syncer_sink)?;
        // remove excess pruning points beyond the pruning_point
        while let Some(&future_pp) = expected_pps_queue.front() {
            if future_pp == synced_pruning_point {
                break;
            }
            expected_pps_queue.pop_front();
        }
        if expected_pps_queue.is_empty() {
            return Err(PruningImportError::MissingPointedPruningPoint);
        }

        for idx in (0..=synced_pp_index).rev() {
            let pp = self.past_pruning_points_store.get(idx).unwrap();
            let pp_header = self.headers_store.get_header(pp).unwrap();
            let Some(expected_pp) = expected_pps_queue.pop_front() else {
                // If we have less than expected pruning points.
                return Err(PruningImportError::MissingPointedPruningPoint);
            };

            if expected_pp != pp {
                return Err(PruningImportError::WrongPointedPruningPoint);
            }

            if idx == 0 {
                // The 0th pruning point should always be genesis, and no
                // more pruning points should be expected below it.
                if !expected_pps_queue.is_empty() || pp != self.genesis_hash {
                    return Err(PruningImportError::UnpointedPruningPoint);
                }
                break;
            }

            // Add the pruning point from the POV of the current one if it's
            // not already added.
            match expected_pps_queue.back() {
                Some(last_added_pp) => {
                    if *last_added_pp != pp_header.pruning_point {
                        expected_pps_queue.push_back(pp_header.pruning_point);
                    }
                }
                None => {
                    // expected_pps_queue should always have one block in the queue
                    // until we reach genesis.
                    return Err(PruningImportError::MissingPointedPruningPoint);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::stores::{
            ghostdag::{GhostdagData, GhostdagStore, MemoryGhostdagStore},
            headers::{CompactHeaderData, HeaderWithBlockLevel},
            reachability::MemoryReachabilityStore,
        },
        processes::{ghostdag::ordering::SortableBlock, reachability::interval::Interval, reachability::tests::TreeBuilder},
        test_helpers::header_from_precomputed_hash,
    };
    use kaspa_consensus_core::{BlockLevel, config::params::Params, header::Header, network::NetworkType};
    use kaspa_database::prelude::{DbKey, StoreError, StoreResult};
    use std::{cell::RefCell, collections::HashMap};

    struct TestHeaders(HashMap<BlockHash, Arc<Header>>);

    impl TestHeaders {
        fn header(&self, hash: BlockHash) -> Result<Arc<Header>, StoreError> {
            self.0.get(&hash).cloned().ok_or_else(|| StoreError::KeyNotFound(DbKey::new(b"test-headers", hash)))
        }
    }

    impl HeaderStoreReader for TestHeaders {
        fn get_daa_score(&self, hash: BlockHash) -> Result<u64, StoreError> {
            Ok(self.header(hash)?.daa_score)
        }

        fn get_blue_score(&self, hash: BlockHash) -> Result<u64, StoreError> {
            Ok(self.header(hash)?.blue_score)
        }

        fn get_timestamp(&self, hash: BlockHash) -> Result<u64, StoreError> {
            Ok(self.header(hash)?.timestamp)
        }

        fn get_bits(&self, hash: BlockHash) -> Result<u32, StoreError> {
            Ok(self.header(hash)?.bits)
        }

        fn get_header(&self, hash: BlockHash) -> Result<Arc<Header>, StoreError> {
            self.header(hash)
        }

        fn get_header_with_block_level(&self, hash: BlockHash) -> Result<HeaderWithBlockLevel, StoreError> {
            Ok(HeaderWithBlockLevel { header: self.header(hash)?, block_level: 0 as BlockLevel })
        }

        fn get_compact_header_data(&self, hash: BlockHash) -> Result<CompactHeaderData, StoreError> {
            Ok(CompactHeaderData::from(self.header(hash)?.as_ref()))
        }
    }

    struct UnusedPastPruningPoints;

    impl PastPruningPointsStoreReader for UnusedPastPruningPoints {
        fn get(&self, index: u64) -> StoreResult<BlockHash> {
            Err(StoreError::KeyNotFound(DbKey::new(b"test-past-pruning-points", index.to_be_bytes())))
        }
    }

    struct UnusedHeadersSelectedTip;

    impl HeadersSelectedTipStoreReader for UnusedHeadersSelectedTip {
        fn get(&self) -> StoreResult<SortableBlock> {
            Err(StoreError::KeyNotFound(DbKey::prefix_only(b"test-headers-selected-tip")))
        }
    }

    /// A two-view test store: direct writes publish to both the durable map and cache map. This lets
    /// the late-error test pin the exact regression without depending on RocksDB cache internals.
    #[derive(Default)]
    struct TestPruningSamples {
        db: RefCell<HashMap<BlockHash, BlockHash>>,
        cache: RefCell<HashMap<BlockHash, BlockHash>>,
    }

    impl crate::model::stores::pruning_samples::PruningSamplesStoreReader for TestPruningSamples {
        fn pruning_sample_from_pov(&self, hash: BlockHash) -> Result<BlockHash, StoreError> {
            if let Some(sample) = self.cache.borrow().get(&hash).copied() {
                return Ok(sample);
            }
            let sample = self
                .db
                .borrow()
                .get(&hash)
                .copied()
                .ok_or_else(|| StoreError::KeyNotFound(DbKey::new(b"test-pruning-samples", hash)))?;
            self.cache.borrow_mut().insert(hash, sample);
            Ok(sample)
        }
    }

    impl PruningSamplesStore for TestPruningSamples {
        fn insert(&self, hash: BlockHash, pruning_sample_from_pov: BlockHash) -> Result<(), StoreError> {
            if self.db.borrow().contains_key(&hash) {
                return Err(StoreError::KeyAlreadyExists(hash.to_string()));
            }
            self.db.borrow_mut().insert(hash, pruning_sample_from_pov);
            self.cache.borrow_mut().insert(hash, pruning_sample_from_pov);
            Ok(())
        }

        fn delete(&self, hash: BlockHash) -> Result<(), StoreError> {
            self.db.borrow_mut().remove(&hash);
            self.cache.borrow_mut().remove(&hash);
            Ok(())
        }
    }

    type TestPruningPointManager = PruningPointManager<
        MemoryGhostdagStore,
        MemoryReachabilityStore,
        TestHeaders,
        UnusedPastPruningPoints,
        UnusedHeadersSelectedTip,
        TestPruningSamples,
    >;

    // The production manager owns stores through `Arc`; these single-threaded test doubles use
    // `RefCell`/memory stores intentionally and never cross a thread boundary.
    #[allow(clippy::arc_with_non_send_sync)]
    fn path_manager(wrong_final_pruning_point: bool) -> (TestPruningPointManager, Arc<TestPruningSamples>, [BlockHash; 4]) {
        let hashes = [1u64, 2, 3, 4].map(BlockHash::from);
        let [genesis, block_1, block_2, block_3] = hashes;

        let mut reachability = MemoryReachabilityStore::new();
        TreeBuilder::new(&mut reachability)
            .init_with_params(genesis, Interval::new(1, 100))
            .add_block(block_1, genesis)
            .add_block(block_2, block_1)
            .add_block(block_3, block_2);

        let ghostdag = Arc::new(MemoryGhostdagStore::new());
        let mut headers = HashMap::new();
        for (index, hash) in hashes.into_iter().enumerate() {
            let selected_parent = if index == 0 { kaspa_consensus_core::blockhash::ORIGIN } else { hashes[index - 1] };
            let mut header = header_from_precomputed_hash(hash, (index != 0).then_some(vec![selected_parent]).unwrap_or_default());
            header.blue_score = index as u64 * 10;
            header.daa_score = header.blue_score;
            header.pruning_point = match index {
                0..=2 => genesis,
                3 if wrong_final_pruning_point => genesis,
                3 => block_1,
                _ => unreachable!(),
            };
            headers.insert(hash, Arc::new(header));
            ghostdag
                .insert(hash, Arc::new(GhostdagData { blue_score: index as u64 * 10, selected_parent, ..GhostdagData::default() }))
                .unwrap();
        }

        let samples = Arc::new(TestPruningSamples::default());
        let manager = PruningPointManager::new(
            20,
            10,
            genesis,
            MTReachabilityService::new(Arc::new(RwLock::new(reachability))),
            ghostdag,
            Arc::new(TestHeaders(headers)),
            Arc::new(UnusedPastPruningPoints),
            Arc::new(RwLock::new(UnusedHeadersSelectedTip)),
            samples.clone(),
        );
        (manager, samples, hashes)
    }

    #[test]
    fn assert_pruning_depth_consistency() {
        for net in NetworkType::iter() {
            let params: Params = net.into();

            let pruning_depth = params.pruning_depth();
            let finality_depth = params.finality_depth();
            let ghostdag_k = params.ghostdag_k();

            // Assert P is not a multiple of F +- noise(K)
            let mod_after = pruning_depth % finality_depth;
            assert!((ghostdag_k as u64) < mod_after && mod_after < finality_depth - ghostdag_k as u64);
        }
    }

    #[test]
    fn path_preflight_late_error_leaves_pruning_sample_db_and_cache_unchanged() {
        let (manager, samples, [genesis, _, _, sink]) = path_manager(true);

        let error = manager
            .preflight_pruning_points_on_path_to_syncer_sink(genesis, sink)
            .err()
            .expect("the deliberately wrong final header pruning point must fail after earlier rows were derived");

        assert!(matches!(error, PruningImportError::WrongHeaderPruningPoint(_, hash) if hash == sink));
        assert!(samples.db.borrow().is_empty(), "failed preflight must not publish durable pruning samples");
        assert!(samples.cache.borrow().is_empty(), "failed preflight must not publish cache pruning samples");
    }

    #[test]
    fn path_preflight_is_read_only_and_legacy_api_commits_after_success() {
        let (manager, samples, [genesis, block_1, block_2, sink]) = path_manager(false);

        let preflight = manager.preflight_pruning_points_on_path_to_syncer_sink(genesis, sink).unwrap();
        assert_eq!(preflight.pruning_points, VecDeque::from([block_1, genesis]));
        assert_eq!(preflight.pruning_sample_writes, vec![(block_1, genesis), (block_2, block_1), (sink, block_2)]);
        assert!(samples.db.borrow().is_empty());
        assert!(samples.cache.borrow().is_empty());

        let pruning_points = manager.pruning_points_on_path_to_syncer_sink(genesis, sink).unwrap();
        assert_eq!(pruning_points, VecDeque::from([block_1, genesis]));
        let expected = HashMap::from([(block_1, genesis), (block_2, block_1), (sink, block_2)]);
        assert_eq!(*samples.db.borrow(), expected);
        assert_eq!(*samples.cache.borrow(), expected);
    }

    #[test]
    fn path_preflight_rejects_a_conflicting_append_only_pruning_sample() {
        let (manager, samples, [genesis, block_1, block_2, sink]) = path_manager(false);
        samples.insert(block_1, block_2).unwrap();
        let before_db = samples.db.borrow().clone();
        let before_cache = samples.cache.borrow().clone();

        let error = manager
            .preflight_pruning_points_on_path_to_syncer_sink(genesis, sink)
            .err()
            .expect("a conflicting append-only pruning sample must fail preflight");
        assert!(matches!(
            error,
            PruningImportError::ConflictingPruningSample(hash, existing, recomputed)
                if hash == block_1 && existing == block_2 && recomputed == genesis
        ));
        assert_eq!(*samples.db.borrow(), before_db, "conflicting preflight must not change durable pruning samples");
        assert_eq!(*samples.cache.borrow(), before_cache, "conflicting preflight must not change cached pruning samples");
    }
}
