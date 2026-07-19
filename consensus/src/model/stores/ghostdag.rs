use crate::processes::ghostdag::ordering::SortableBlock;
use kaspa_consensus_core::palw::{COMPUTE_TO_HASH_CAP, capped_compute_work, effective_blue_work};
use kaspa_consensus_core::trusted::ExternalGhostdagData;
use kaspa_consensus_core::{BlockHash, BlockHashMap, BlockHasher, BlockLevel, HashMapCustomHasher};
use kaspa_consensus_core::{BlueWorkType, blockhash::BlockHashes};
use kaspa_database::prelude::DB;
use kaspa_database::prelude::{BatchDbWriter, CachedDbAccess, DbKey};
use kaspa_database::prelude::{CachePolicy, StoreError};
use kaspa_database::registry::{DatabaseStorePrefixes, SEPARATOR};

use itertools::EitherOrBoth::{Both, Left, Right};
use itertools::Itertools;
use kaspa_utils::mem_size::MemSizeEstimator;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::iter::once;
use std::{cell::RefCell, sync::Arc};

/// Re-export for convenience
pub use kaspa_consensus_core::{HashKTypeMap, KType};

// ADR-0039 §15.1 STORE-FORMAT NOTE: appending `blue_hash_work`/`blue_compute_work` changes the
// positional bincode layout of BOTH the full and compact GHOSTDAG records on disk. This is part of the
// single PALW on-disk format change (Header v3 fields landed the same way in slice 4) and is safe ONLY
// because the whole PALW lane ships via re-genesis onto a NEW network-id / genesis hash — the genesis
// guard then forces a fresh DB regardless of `LATEST_DB_VERSION`. The `LATEST_DB_VERSION` bump is the
// belt-and-suspenders cutover action for the whole PALW format (do it ONCE at re-genesis, not per
// slice); resuming this inert binary on a SAME-genesis pre-PALW DB is the unsupported path ADR-0001
// already forbids (old DBs are rejected, not migrated).
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct GhostdagData {
    pub blue_score: u64,
    /// Effective GHOSTDAG work `E = H + min(C, cap·H)` that fork choice consumes (`SortableBlock`).
    /// Equals `blue_hash_work` whenever the PALW compute lane is inert (`blue_compute_work == 0`).
    pub blue_work: BlueWorkType,
    /// ADR-0039 §15.1 (D4): cumulative blue HASH work `H` (algo-3 floor). Carried alongside
    /// `blue_work` but never a fork-choice tie-breaker (§15.6). Pre-v3 blocks migrate as
    /// `blue_hash_work = blue_work` (see [`From<ExternalGhostdagData>`]).
    pub blue_hash_work: BlueWorkType,
    /// ADR-0039 §15.1 (D4): cumulative blue certified COMPUTE work `C`, already capped at `cap·H`
    /// (design §15.5 `min(C, 4H)`). Zero while the PALW lane is inert.
    pub blue_compute_work: BlueWorkType,
    pub selected_parent: BlockHash,
    pub mergeset_blues: BlockHashes,
    pub mergeset_reds: BlockHashes,
    pub blues_anticone_sizes: HashKTypeMap,
}

#[derive(Clone, Serialize, Deserialize, Copy)]
pub struct CompactGhostdagData {
    pub blue_score: u64,
    pub blue_work: BlueWorkType,
    /// ADR-0039 §15.1: component work carried in the compact record too, so the GHOSTDAG
    /// accumulation reads a selected parent's `H`/`C` in a single compact lookup.
    pub blue_hash_work: BlueWorkType,
    pub blue_compute_work: BlueWorkType,
    pub selected_parent: BlockHash,
}

impl MemSizeEstimator for GhostdagData {
    fn estimate_mem_bytes(&self) -> usize {
        let mut bytes = size_of::<Self>();
        bytes += (self.mergeset_blues.len() + self.mergeset_reds.len()) * size_of::<BlockHash>();
        bytes += self.blues_anticone_sizes.len() * size_of::<(BlockHash, KType)>();
        bytes
    }
}

impl MemSizeEstimator for CompactGhostdagData {}

impl From<&GhostdagData> for CompactGhostdagData {
    #[inline(always)]
    fn from(value: &GhostdagData) -> Self {
        Self {
            blue_score: value.blue_score,
            blue_work: value.blue_work,
            blue_hash_work: value.blue_hash_work,
            blue_compute_work: value.blue_compute_work,
            selected_parent: value.selected_parent,
        }
    }
}

impl From<ExternalGhostdagData> for GhostdagData {
    fn from(value: ExternalGhostdagData) -> Self {
        Self {
            blue_score: value.blue_score,
            blue_work: value.blue_work,
            // ADR-0039 §15.1 migration view: externally-provided (trusted / pruning-proof) GHOSTDAG
            // data carries only the effective `blue_work`. A pre-v3 block's effective work IS its
            // hash work, so `blue_hash_work = blue_work`, `blue_compute_work = 0`. Carrying the two
            // components over the trusted wire is deferred to the pruning/IBD-bundle slice (§18.3);
            // while the lane is inert every trusted block is pre-v3, so this view is exact.
            blue_hash_work: value.blue_work,
            blue_compute_work: BlueWorkType::from(0u64),
            selected_parent: value.selected_parent,
            mergeset_blues: Arc::new(value.mergeset_blues),
            mergeset_reds: Arc::new(value.mergeset_reds),
            blues_anticone_sizes: Arc::new(value.blues_anticone_sizes),
        }
    }
}

impl From<&GhostdagData> for ExternalGhostdagData {
    fn from(value: &GhostdagData) -> Self {
        Self {
            blue_score: value.blue_score,
            blue_work: value.blue_work,
            selected_parent: value.selected_parent,
            mergeset_blues: (*value.mergeset_blues).clone(),
            mergeset_reds: (*value.mergeset_reds).clone(),
            blues_anticone_sizes: (*value.blues_anticone_sizes).clone(),
        }
    }
}

impl GhostdagData {
    /// Constructs GHOSTDAG data with the effective `blue_work` migrated into components
    /// (`blue_hash_work = blue_work`, `blue_compute_work = 0`) — the ADR-0039 §15.1 pre-v3 / inert
    /// view. The PALW-active path instead accumulates the two components separately and calls
    /// [`Self::finalize_score_and_component_work`].
    pub fn new(
        blue_score: u64,
        blue_work: BlueWorkType,
        selected_parent: BlockHash,
        mergeset_blues: BlockHashes,
        mergeset_reds: BlockHashes,
        blues_anticone_sizes: HashKTypeMap,
    ) -> Self {
        Self {
            blue_score,
            blue_work,
            blue_hash_work: blue_work,
            blue_compute_work: BlueWorkType::from(0u64),
            selected_parent,
            mergeset_blues,
            mergeset_reds,
            blues_anticone_sizes,
        }
    }

    pub fn new_with_selected_parent(selected_parent: BlockHash, k: KType) -> Self {
        let mut mergeset_blues: Vec<BlockHash> = Vec::with_capacity((k + 1) as usize);
        let mut blues_anticone_sizes: BlockHashMap<KType> = BlockHashMap::with_capacity(k as usize);
        mergeset_blues.push(selected_parent);
        blues_anticone_sizes.insert(selected_parent, 0);

        Self {
            blue_score: Default::default(),
            blue_work: Default::default(),
            blue_hash_work: Default::default(),
            blue_compute_work: Default::default(),
            selected_parent,
            mergeset_blues: BlockHashes::new(mergeset_blues),
            mergeset_reds: Default::default(),
            blues_anticone_sizes: HashKTypeMap::new(blues_anticone_sizes),
        }
    }

    pub fn mergeset_size(&self) -> usize {
        self.mergeset_blues.len() + self.mergeset_reds.len()
    }

    /// Returns an iterator to the mergeset in ascending blue work order (tie-breaking by hash)
    pub fn ascending_mergeset_without_selected_parent<'a>(
        &'a self,
        store: &'a (impl GhostdagStoreReader + ?Sized),
    ) -> impl Iterator<Item = SortableBlock> + 'a {
        self.mergeset_blues
            .iter()
            .skip(1) // Skip the selected parent
            .cloned()
            .map(|h| SortableBlock::new(h, store.get_blue_work(h).unwrap()))
            .merge_join_by(
                self.mergeset_reds
                    .iter()
                    .cloned()
                    .map(|h| SortableBlock::new(h, store.get_blue_work(h).unwrap())),
                |a, b| a.cmp(b),
            )
            .map(|r| match r {
                Left(b) | Right(b) => b,
                Both(_, _) => panic!("distinct blocks are never equal"),
            })
    }

    /// Returns an iterator to the mergeset in descending blue work order (tie-breaking by hash)
    pub fn descending_mergeset_without_selected_parent<'a>(
        &'a self,
        store: &'a (impl GhostdagStoreReader + ?Sized),
    ) -> impl Iterator<Item = SortableBlock> + 'a {
        self.mergeset_blues
                .iter()
                .skip(1) // Skip the selected parent
                .rev()   // Reverse since blues and reds are stored with ascending blue work order
                .cloned()
                .map(|h| SortableBlock::new(h, store.get_blue_work(h).unwrap()))
                .merge_join_by(
                    self.mergeset_reds
                        .iter()
                        .rev() // Reverse
                        .cloned()
                        .map(|h| SortableBlock::new(h, store.get_blue_work(h).unwrap())),
                    |a, b| b.cmp(a), // Reverse
                )
                .map(|r| match r {
                    Left(b) | Right(b) => b,
                    Both(_, _) => panic!("distinct blocks are never equal"),
                })
    }

    /// Returns an iterator to the mergeset with no specified order (excluding the selected parent)
    pub fn unordered_mergeset_without_selected_parent(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.mergeset_blues
            .iter()
            .skip(1) // Skip the selected parent
            .cloned()
            .chain(self.mergeset_reds.iter().cloned())
    }

    /// Returns an iterator to the mergeset in topological consensus order -- starting with the selected parent,
    /// and adding the mergeset in increasing blue work order. Note that this is a topological order even though
    /// the selected parent has highest blue work by def -- since the mergeset is in its anticone.
    pub fn consensus_ordered_mergeset<'a>(
        &'a self,
        store: &'a (impl GhostdagStoreReader + ?Sized),
    ) -> impl Iterator<Item = BlockHash> + 'a {
        once(self.selected_parent).chain(self.ascending_mergeset_without_selected_parent(store).map(|s| s.hash))
    }

    /// Returns an iterator to the mergeset in topological consensus order without the selected parent
    pub fn consensus_ordered_mergeset_without_selected_parent<'a>(
        &'a self,
        store: &'a (impl GhostdagStoreReader + ?Sized),
    ) -> impl Iterator<Item = BlockHash> + 'a {
        self.ascending_mergeset_without_selected_parent(store).map(|s| s.hash)
    }

    /// Returns an iterator to the mergeset with no specified order (including the selected parent)
    pub fn unordered_mergeset(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.mergeset_blues.iter().cloned().chain(self.mergeset_reds.iter().cloned())
    }

    pub fn to_compact(&self) -> CompactGhostdagData {
        self.into()
    }

    pub fn add_blue(&mut self, block: BlockHash, blue_anticone_size: KType, block_blues_anticone_sizes: &BlockHashMap<KType>) {
        // Add the new blue block to mergeset blues
        BlockHashes::make_mut(&mut self.mergeset_blues).push(block);

        // Get a mut ref to internal anticone size map
        let blues_anticone_sizes = HashKTypeMap::make_mut(&mut self.blues_anticone_sizes);

        // Insert the new blue block with its blue anticone size to the map
        blues_anticone_sizes.insert(block, blue_anticone_size);

        // Insert/update map entries for blocks affected by this insertion
        for (blue, size) in block_blues_anticone_sizes {
            blues_anticone_sizes.insert(*blue, size + 1);
        }
    }

    pub fn add_red(&mut self, block: BlockHash) {
        // Add the new red block to mergeset reds
        BlockHashes::make_mut(&mut self.mergeset_reds).push(block);
    }

    /// Legacy single-work finalizer: treats the supplied `blue_work` as pure hash work with zero
    /// compute credit (`blue_hash_work = blue_work`, `blue_compute_work = 0`, effective `blue_work`
    /// unchanged). Kept for callers/tests that never touch the compute lane; delegates to
    /// [`Self::finalize_score_and_component_work`] so the two paths share the same cap arithmetic.
    pub fn finalize_score_and_work(&mut self, blue_score: u64, blue_work: BlueWorkType) {
        // cap ratio is irrelevant when the raw compute term is 0 (`min(0, cap·H) == 0`).
        self.finalize_score_and_component_work(blue_score, blue_work, BlueWorkType::from(0u64), COMPUTE_TO_HASH_CAP);
    }

    /// ADR-0039 §15.5 (D4): finalize blue score and the separated component work, deriving the single
    /// effective `blue_work = E = H + min(C, cap·H)` that fork choice consumes. `blue_compute_work_raw`
    /// is the *uncapped* accumulated compute term; the stored `blue_compute_work` is the capped value
    /// `min(C, cap·H)`, and the cap arithmetic is the shared [`effective_blue_work`] /
    /// [`capped_compute_work`] (checked/saturating big-int, property-tested in `consensus-core`).
    ///
    /// Inert invariant: with `blue_compute_work_raw == 0` this sets `blue_work == blue_hash_work` and
    /// `blue_compute_work == 0`, i.e. byte-identical to the pre-PALW single-work result.
    pub fn finalize_score_and_component_work(
        &mut self,
        blue_score: u64,
        blue_hash_work: BlueWorkType,
        blue_compute_work_raw: BlueWorkType,
        compute_to_hash_cap: u64,
    ) {
        self.blue_score = blue_score;
        self.blue_hash_work = blue_hash_work;
        self.blue_compute_work = capped_compute_work(blue_compute_work_raw, blue_hash_work, compute_to_hash_cap);
        self.blue_work = effective_blue_work(blue_hash_work, blue_compute_work_raw, compute_to_hash_cap);
    }
}
pub trait GhostdagStoreReader {
    fn get_blue_score(&self, hash: BlockHash) -> Result<u64, StoreError>;
    fn get_blue_work(&self, hash: BlockHash) -> Result<BlueWorkType, StoreError>;
    /// ADR-0039 §15: cumulative blue HASH work `H`. Equals [`Self::get_blue_work`] while inert.
    fn get_blue_hash_work(&self, hash: BlockHash) -> Result<BlueWorkType, StoreError>;
    /// ADR-0039 §15: cumulative (capped) blue COMPUTE work `C`. Zero while inert.
    fn get_blue_compute_work(&self, hash: BlockHash) -> Result<BlueWorkType, StoreError>;
    fn get_selected_parent(&self, hash: BlockHash) -> Result<BlockHash, StoreError>;
    fn get_mergeset_blues(&self, hash: BlockHash) -> Result<BlockHashes, StoreError>;
    fn get_mergeset_reds(&self, hash: BlockHash) -> Result<BlockHashes, StoreError>;
    fn get_blues_anticone_sizes(&self, hash: BlockHash) -> Result<HashKTypeMap, StoreError>;

    /// Returns full block data for the requested hash
    fn get_data(&self, hash: BlockHash) -> Result<Arc<GhostdagData>, StoreError>;

    fn get_compact_data(&self, hash: BlockHash) -> Result<CompactGhostdagData, StoreError>;

    /// Check if the store contains data for the requested hash
    fn has(&self, hash: BlockHash) -> Result<bool, StoreError>;
}

pub trait GhostdagStore: GhostdagStoreReader {
    /// Insert GHOSTDAG data for block `hash` into the store. Note that GHOSTDAG data
    /// is added once and never modified, so no need for specific setters for each element.
    /// Additionally, this means writes are semantically "append-only", which is why
    /// we can keep the `insert` method non-mutable on self. See "Parallel Processing.md" for an overview.
    fn insert(&self, hash: BlockHash, data: Arc<GhostdagData>) -> Result<(), StoreError>;
    fn delete(&self, hash: BlockHash) -> Result<(), StoreError>;
}

/// A DB + cache implementation of `GhostdagStore` trait, with concurrency support.
#[derive(Clone)]
pub struct DbGhostdagStore {
    db: Arc<DB>,
    level: BlockLevel,
    access: CachedDbAccess<BlockHash, Arc<GhostdagData>, BlockHasher>,
    compact_access: CachedDbAccess<BlockHash, CompactGhostdagData, BlockHasher>,
}

impl DbGhostdagStore {
    pub fn new(db: Arc<DB>, level: BlockLevel, cache_policy: CachePolicy, compact_cache_policy: CachePolicy) -> Self {
        assert_ne!(SEPARATOR, level, "level {} is reserved for the separator", level);
        let lvl_bytes = level.to_le_bytes();
        let prefix = DatabaseStorePrefixes::Ghostdag.into_iter().chain(lvl_bytes).collect_vec();
        let compact_prefix = DatabaseStorePrefixes::GhostdagCompact.into_iter().chain(lvl_bytes).collect_vec();
        Self {
            db: Arc::clone(&db),
            level,
            access: CachedDbAccess::new(db.clone(), cache_policy, prefix),
            compact_access: CachedDbAccess::new(db, compact_cache_policy, compact_prefix),
        }
    }

    pub fn new_temp(
        db: Arc<DB>,
        level: BlockLevel,
        cache_policy: CachePolicy,
        compact_cache_policy: CachePolicy,
        temp_index: u8,
    ) -> Self {
        assert_ne!(SEPARATOR, level, "level {} is reserved for the separator", level);
        let lvl_bytes = level.to_le_bytes();
        let temp_index_bytes = temp_index.to_le_bytes();
        let prefix = DatabaseStorePrefixes::TempGhostdag.into_iter().chain(lvl_bytes).chain(temp_index_bytes).collect_vec();
        let compact_prefix =
            DatabaseStorePrefixes::TempGhostdagCompact.into_iter().chain(lvl_bytes).chain(temp_index_bytes).collect_vec();
        Self {
            db: Arc::clone(&db),
            level,
            access: CachedDbAccess::new(db.clone(), cache_policy, prefix),
            compact_access: CachedDbAccess::new(db, compact_cache_policy, compact_prefix),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy, compact_cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), self.level, cache_policy, compact_cache_policy)
    }

    pub fn insert_batch(&self, batch: &mut WriteBatch, hash: BlockHash, data: &Arc<GhostdagData>) -> Result<(), StoreError> {
        if self.access.has(hash)? {
            return Err(StoreError::KeyAlreadyExists(hash.to_string()));
        }
        self.access.write(BatchDbWriter::new(batch), hash, data.clone())?;
        self.compact_access.write(BatchDbWriter::new(batch), hash, data.to_compact())?;
        Ok(())
    }

    pub fn update_batch(&self, batch: &mut WriteBatch, hash: BlockHash, data: &Arc<GhostdagData>) -> Result<(), StoreError> {
        self.access.write(BatchDbWriter::new(batch), hash, data.clone())?;
        self.compact_access.write(BatchDbWriter::new(batch), hash, data.to_compact())?;
        Ok(())
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: BlockHash) -> Result<(), StoreError> {
        self.compact_access.delete(BatchDbWriter::new(batch), hash)?;
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}

impl GhostdagStoreReader for DbGhostdagStore {
    fn get_blue_score(&self, hash: BlockHash) -> Result<u64, StoreError> {
        if let Some(ghostdag_data) = self.access.read_from_cache(hash) {
            return Ok(ghostdag_data.blue_score);
        }
        Ok(self.compact_access.read(hash)?.blue_score)
    }

    fn get_blue_work(&self, hash: BlockHash) -> Result<BlueWorkType, StoreError> {
        if let Some(ghostdag_data) = self.access.read_from_cache(hash) {
            return Ok(ghostdag_data.blue_work);
        }
        Ok(self.compact_access.read(hash)?.blue_work)
    }

    fn get_blue_hash_work(&self, hash: BlockHash) -> Result<BlueWorkType, StoreError> {
        if let Some(ghostdag_data) = self.access.read_from_cache(hash) {
            return Ok(ghostdag_data.blue_hash_work);
        }
        Ok(self.compact_access.read(hash)?.blue_hash_work)
    }

    fn get_blue_compute_work(&self, hash: BlockHash) -> Result<BlueWorkType, StoreError> {
        if let Some(ghostdag_data) = self.access.read_from_cache(hash) {
            return Ok(ghostdag_data.blue_compute_work);
        }
        Ok(self.compact_access.read(hash)?.blue_compute_work)
    }

    fn get_selected_parent(&self, hash: BlockHash) -> Result<BlockHash, StoreError> {
        if let Some(ghostdag_data) = self.access.read_from_cache(hash) {
            return Ok(ghostdag_data.selected_parent);
        }
        Ok(self.compact_access.read(hash)?.selected_parent)
    }

    fn get_mergeset_blues(&self, hash: BlockHash) -> Result<BlockHashes, StoreError> {
        Ok(Arc::clone(&self.access.read(hash)?.mergeset_blues))
    }

    fn get_mergeset_reds(&self, hash: BlockHash) -> Result<BlockHashes, StoreError> {
        Ok(Arc::clone(&self.access.read(hash)?.mergeset_reds))
    }

    fn get_blues_anticone_sizes(&self, hash: BlockHash) -> Result<HashKTypeMap, StoreError> {
        Ok(Arc::clone(&self.access.read(hash)?.blues_anticone_sizes))
    }

    fn get_data(&self, hash: BlockHash) -> Result<Arc<GhostdagData>, StoreError> {
        self.access.read(hash)
    }

    fn get_compact_data(&self, hash: BlockHash) -> Result<CompactGhostdagData, StoreError> {
        self.compact_access.read(hash)
    }

    fn has(&self, hash: BlockHash) -> Result<bool, StoreError> {
        self.access.has(hash)
    }
}

impl GhostdagStore for DbGhostdagStore {
    fn insert(&self, hash: BlockHash, data: Arc<GhostdagData>) -> Result<(), StoreError> {
        if self.access.has(hash)? {
            return Err(StoreError::KeyAlreadyExists(hash.to_string()));
        }
        if self.compact_access.has(hash)? {
            return Err(StoreError::DataInconsistency(format!("store has compact data for {} but is missing full data", hash)));
        }
        let mut batch = WriteBatch::default();
        self.access.write(BatchDbWriter::new(&mut batch), hash, data.clone())?;
        self.compact_access.write(BatchDbWriter::new(&mut batch), hash, data.to_compact())?;
        self.db.write(batch)?;
        Ok(())
    }

    fn delete(&self, hash: BlockHash) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        self.compact_access.delete(BatchDbWriter::new(&mut batch), hash)?;
        self.access.delete(BatchDbWriter::new(&mut batch), hash)?;
        self.db.write(batch)?;
        Ok(())
    }
}

/// An in-memory implementation of `GhostdagStore` trait to be used for tests.
/// Uses `RefCell` for interior mutability in order to workaround `insert`
/// being non-mutable.
pub struct MemoryGhostdagStore {
    blue_score_map: RefCell<BlockHashMap<u64>>,
    blue_work_map: RefCell<BlockHashMap<BlueWorkType>>,
    blue_hash_work_map: RefCell<BlockHashMap<BlueWorkType>>,
    blue_compute_work_map: RefCell<BlockHashMap<BlueWorkType>>,
    selected_parent_map: RefCell<BlockHashMap<BlockHash>>,
    mergeset_blues_map: RefCell<BlockHashMap<BlockHashes>>,
    mergeset_reds_map: RefCell<BlockHashMap<BlockHashes>>,
    blues_anticone_sizes_map: RefCell<BlockHashMap<HashKTypeMap>>,
}

impl MemoryGhostdagStore {
    pub fn new() -> Self {
        Self {
            blue_score_map: RefCell::new(BlockHashMap::new()),
            blue_work_map: RefCell::new(BlockHashMap::new()),
            blue_hash_work_map: RefCell::new(BlockHashMap::new()),
            blue_compute_work_map: RefCell::new(BlockHashMap::new()),
            selected_parent_map: RefCell::new(BlockHashMap::new()),
            mergeset_blues_map: RefCell::new(BlockHashMap::new()),
            mergeset_reds_map: RefCell::new(BlockHashMap::new()),
            blues_anticone_sizes_map: RefCell::new(BlockHashMap::new()),
        }
    }

    pub fn key_not_found_error(hash: BlockHash) -> StoreError {
        StoreError::KeyNotFound(DbKey::new(DatabaseStorePrefixes::Ghostdag.as_ref(), hash))
    }
}

impl Default for MemoryGhostdagStore {
    fn default() -> Self {
        Self::new()
    }
}

impl GhostdagStore for MemoryGhostdagStore {
    fn insert(&self, hash: BlockHash, data: Arc<GhostdagData>) -> Result<(), StoreError> {
        if self.has(hash)? {
            return Err(StoreError::KeyAlreadyExists(hash.to_string()));
        }
        self.blue_score_map.borrow_mut().insert(hash, data.blue_score);
        self.blue_work_map.borrow_mut().insert(hash, data.blue_work);
        self.blue_hash_work_map.borrow_mut().insert(hash, data.blue_hash_work);
        self.blue_compute_work_map.borrow_mut().insert(hash, data.blue_compute_work);
        self.selected_parent_map.borrow_mut().insert(hash, data.selected_parent);
        self.mergeset_blues_map.borrow_mut().insert(hash, data.mergeset_blues.clone());
        self.mergeset_reds_map.borrow_mut().insert(hash, data.mergeset_reds.clone());
        self.blues_anticone_sizes_map.borrow_mut().insert(hash, data.blues_anticone_sizes.clone());
        Ok(())
    }

    fn delete(&self, hash: BlockHash) -> Result<(), StoreError> {
        self.blue_score_map.borrow_mut().remove(&hash);
        self.blue_work_map.borrow_mut().remove(&hash);
        self.blue_hash_work_map.borrow_mut().remove(&hash);
        self.blue_compute_work_map.borrow_mut().remove(&hash);
        self.selected_parent_map.borrow_mut().remove(&hash);
        self.mergeset_blues_map.borrow_mut().remove(&hash);
        self.mergeset_reds_map.borrow_mut().remove(&hash);
        self.blues_anticone_sizes_map.borrow_mut().remove(&hash);
        Ok(())
    }
}

impl GhostdagStoreReader for MemoryGhostdagStore {
    fn get_blue_score(&self, hash: BlockHash) -> Result<u64, StoreError> {
        match self.blue_score_map.borrow().get(&hash) {
            Some(blue_score) => Ok(*blue_score),
            None => Err(Self::key_not_found_error(hash)),
        }
    }

    fn get_blue_work(&self, hash: BlockHash) -> Result<BlueWorkType, StoreError> {
        match self.blue_work_map.borrow().get(&hash) {
            Some(blue_work) => Ok(*blue_work),
            None => Err(Self::key_not_found_error(hash)),
        }
    }

    fn get_blue_hash_work(&self, hash: BlockHash) -> Result<BlueWorkType, StoreError> {
        match self.blue_hash_work_map.borrow().get(&hash) {
            Some(blue_hash_work) => Ok(*blue_hash_work),
            None => Err(Self::key_not_found_error(hash)),
        }
    }

    fn get_blue_compute_work(&self, hash: BlockHash) -> Result<BlueWorkType, StoreError> {
        match self.blue_compute_work_map.borrow().get(&hash) {
            Some(blue_compute_work) => Ok(*blue_compute_work),
            None => Err(Self::key_not_found_error(hash)),
        }
    }

    fn get_selected_parent(&self, hash: BlockHash) -> Result<BlockHash, StoreError> {
        match self.selected_parent_map.borrow().get(&hash) {
            Some(selected_parent) => Ok(*selected_parent),
            None => Err(Self::key_not_found_error(hash)),
        }
    }

    fn get_mergeset_blues(&self, hash: BlockHash) -> Result<BlockHashes, StoreError> {
        match self.mergeset_blues_map.borrow().get(&hash) {
            Some(mergeset_blues) => Ok(BlockHashes::clone(mergeset_blues)),
            None => Err(Self::key_not_found_error(hash)),
        }
    }

    fn get_mergeset_reds(&self, hash: BlockHash) -> Result<BlockHashes, StoreError> {
        match self.mergeset_reds_map.borrow().get(&hash) {
            Some(mergeset_reds) => Ok(BlockHashes::clone(mergeset_reds)),
            None => Err(Self::key_not_found_error(hash)),
        }
    }

    fn get_blues_anticone_sizes(&self, hash: BlockHash) -> Result<HashKTypeMap, StoreError> {
        match self.blues_anticone_sizes_map.borrow().get(&hash) {
            Some(sizes) => Ok(HashKTypeMap::clone(sizes)),
            None => Err(Self::key_not_found_error(hash)),
        }
    }

    fn get_data(&self, hash: BlockHash) -> Result<Arc<GhostdagData>, StoreError> {
        if !self.has(hash)? {
            return Err(Self::key_not_found_error(hash));
        }
        // Reconstruct via a struct literal (not `new`, which would collapse the components into the
        // migration view) so the stored `blue_hash_work`/`blue_compute_work` round-trip exactly.
        Ok(Arc::new(GhostdagData {
            blue_score: self.blue_score_map.borrow()[&hash],
            blue_work: self.blue_work_map.borrow()[&hash],
            blue_hash_work: self.blue_hash_work_map.borrow()[&hash],
            blue_compute_work: self.blue_compute_work_map.borrow()[&hash],
            selected_parent: self.selected_parent_map.borrow()[&hash],
            mergeset_blues: self.mergeset_blues_map.borrow()[&hash].clone(),
            mergeset_reds: self.mergeset_reds_map.borrow()[&hash].clone(),
            blues_anticone_sizes: self.blues_anticone_sizes_map.borrow()[&hash].clone(),
        }))
    }

    fn has(&self, hash: BlockHash) -> Result<bool, StoreError> {
        Ok(self.blue_score_map.borrow().contains_key(&hash))
    }

    fn get_compact_data(&self, hash: BlockHash) -> Result<CompactGhostdagData, StoreError> {
        Ok(self.get_data(hash)?.to_compact())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::BlockHashSet;

    #[test]
    fn test_mergeset_iterators() {
        let store = MemoryGhostdagStore::new();

        let factory = |w: u64| {
            Arc::new(GhostdagData {
                blue_score: Default::default(),
                blue_work: w.into(),
                blue_hash_work: w.into(),
                blue_compute_work: Default::default(),
                selected_parent: Default::default(),
                mergeset_blues: Default::default(),
                mergeset_reds: Default::default(),
                blues_anticone_sizes: Default::default(),
            })
        };

        // Blues
        store.insert(1.into(), factory(2)).unwrap();
        store.insert(2.into(), factory(7)).unwrap();
        store.insert(3.into(), factory(11)).unwrap();

        // Reds
        store.insert(4.into(), factory(4)).unwrap();
        store.insert(5.into(), factory(9)).unwrap();
        store.insert(6.into(), factory(11)).unwrap(); // Tie-breaking case

        let mut data = GhostdagData::new_with_selected_parent(1.into(), 5);
        data.add_blue(2.into(), Default::default(), &Default::default());
        data.add_blue(3.into(), Default::default(), &Default::default());

        data.add_red(4.into());
        data.add_red(5.into());
        data.add_red(6.into());

        let mut expected: Vec<BlockHash> = vec![4.into(), 2.into(), 5.into(), 3.into(), 6.into()];
        assert_eq!(expected, data.ascending_mergeset_without_selected_parent(&store).map(|b| b.hash).collect::<Vec<BlockHash>>());

        itertools::assert_equal(once(1.into()).chain(expected.iter().cloned()), data.consensus_ordered_mergeset(&store));

        expected.reverse();
        assert_eq!(expected, data.descending_mergeset_without_selected_parent(&store).map(|b| b.hash).collect::<Vec<BlockHash>>());

        // Use sets since the below functions have no order guarantee
        let expected = BlockHashSet::from_iter([4.into(), 2.into(), 5.into(), 3.into(), 6.into()]);
        assert_eq!(expected, data.unordered_mergeset_without_selected_parent().collect::<BlockHashSet>());

        let expected = BlockHashSet::from_iter([1.into(), 4.into(), 2.into(), 5.into(), 3.into(), 6.into()]);
        assert_eq!(expected, data.unordered_mergeset().collect::<BlockHashSet>());
    }

    /// ADR-0039 §15.5: `finalize_score_and_component_work` sets the four work fields consistently —
    /// `blue_compute_work = min(C, cap·H)` and `blue_work = H + min(C, cap·H)`.
    #[test]
    fn test_finalize_component_work_cap() {
        let w = |v: u64| BlueWorkType::from(v);
        let mut d = GhostdagData::new_with_selected_parent(1.into(), 1);

        // C below the cap (cap·H = 40): credited in full.
        d.finalize_score_and_component_work(7, w(10), w(25), COMPUTE_TO_HASH_CAP);
        assert_eq!(d.blue_score, 7);
        assert_eq!(d.blue_hash_work, w(10));
        assert_eq!(d.blue_compute_work, w(25));
        assert_eq!(d.blue_work, w(35));

        // C exactly at the cap (cap·H = 40): credited in full, effective = 50 (= 5·H, the I-1 bound).
        d.finalize_score_and_component_work(7, w(10), w(40), COMPUTE_TO_HASH_CAP);
        assert_eq!(d.blue_hash_work, w(10));
        assert_eq!(d.blue_compute_work, w(40));
        assert_eq!(d.blue_work, w(50));

        // C above the cap (cap·H = 40): compute clamped to 40, effective still 50 (5·H bound holds).
        d.finalize_score_and_component_work(7, w(10), w(1_000), COMPUTE_TO_HASH_CAP);
        assert_eq!(d.blue_hash_work, w(10));
        assert_eq!(d.blue_compute_work, w(40));
        assert_eq!(d.blue_work, w(50));
    }

    /// Inert invariant: with zero raw compute the component finalizer is byte-identical to the legacy
    /// single-work finalize — `blue_work == blue_hash_work`, `blue_compute_work == 0`. This is what
    /// guarantees fork choice is unchanged while the PALW lane is inert.
    #[test]
    fn test_finalize_inert_equals_legacy() {
        let w = |v: u64| BlueWorkType::from(v);
        let mut component = GhostdagData::new_with_selected_parent(1.into(), 1);
        component.finalize_score_and_component_work(3, w(123), w(0), COMPUTE_TO_HASH_CAP);

        let mut legacy = GhostdagData::new_with_selected_parent(1.into(), 1);
        legacy.finalize_score_and_work(3, w(123));

        assert_eq!(component.blue_work, w(123));
        assert_eq!(component.blue_hash_work, w(123));
        assert_eq!(component.blue_compute_work, w(0));
        // The legacy path routes through the component finalizer and must agree field-for-field.
        assert_eq!(legacy.blue_work, component.blue_work);
        assert_eq!(legacy.blue_hash_work, component.blue_hash_work);
        assert_eq!(legacy.blue_compute_work, component.blue_compute_work);
    }

    /// The stores must round-trip the two new component fields (full data, per-field readers, and the
    /// compact record) rather than collapsing them into the migration view.
    #[test]
    fn test_store_component_work_roundtrip() {
        let w = |v: u64| BlueWorkType::from(v);
        let store = MemoryGhostdagStore::new();
        let mut d = GhostdagData::new_with_selected_parent(1.into(), 1);
        d.finalize_score_and_component_work(9, w(100), w(30), COMPUTE_TO_HASH_CAP);
        assert_eq!(d.blue_work, w(130));
        store.insert(2.into(), Arc::new(d)).unwrap();

        assert_eq!(store.get_blue_hash_work(2.into()).unwrap(), w(100));
        assert_eq!(store.get_blue_compute_work(2.into()).unwrap(), w(30));
        assert_eq!(store.get_blue_work(2.into()).unwrap(), w(130));

        let round = store.get_data(2.into()).unwrap();
        assert_eq!(round.blue_hash_work, w(100));
        assert_eq!(round.blue_compute_work, w(30));
        assert_eq!(round.blue_work, w(130));

        let compact = store.get_compact_data(2.into()).unwrap();
        assert_eq!(compact.blue_hash_work, w(100));
        assert_eq!(compact.blue_compute_work, w(30));
        assert_eq!(compact.blue_work, w(130));
    }

    /// The `ExternalGhostdagData` → `GhostdagData` migration view (§15.1): a trusted block carries only
    /// effective work, so its hash work is that effective work and its compute work is zero.
    #[test]
    fn test_external_ghostdag_migration_view() {
        use kaspa_consensus_core::trusted::ExternalGhostdagData;
        let ext = ExternalGhostdagData {
            blue_score: 5,
            blue_work: BlueWorkType::from(77u64),
            selected_parent: 1.into(),
            mergeset_blues: vec![1.into()],
            mergeset_reds: vec![],
            blues_anticone_sizes: BlockHashMap::new(),
        };
        let gd: GhostdagData = ext.into();
        assert_eq!(gd.blue_work, BlueWorkType::from(77u64));
        assert_eq!(gd.blue_hash_work, BlueWorkType::from(77u64));
        assert_eq!(gd.blue_compute_work, BlueWorkType::from(0u64));
    }
}
