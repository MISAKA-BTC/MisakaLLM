//! DA-01 fork-local state, content-addressed object cache, and pruning snapshot stores.
//!
//! Consensus validity reads `state_by_block(selected_parent)`, never a mutable tip singleton. Raw
//! object bytes are auxiliary/content-addressed and cannot make an invalid object valid; callers still
//! run the receipt/bond/signature verifier. The pruning singleton is tagged by its own snapshot type.

use borsh::BorshDeserialize;
use kaspa_consensus_core::palw::da::{
    PalwDaPruningSnapshotV1, PalwDaStateV1, PalwReceiptDaObjectV1, palw_receipt_da_commitment, palw_receipt_da_object_bytes,
};
use kaspa_consensus_core::{BlockHash, BlockHasher};
use kaspa_database::prelude::{
    BatchDbWriter, CachePolicy, CachedDbAccess, CachedDbItem, DB, DbKey, DirectDbWriter, StoreError, StoreResult,
};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash64;
use rocksdb::{Direction, IteratorMode, ReadOptions, WriteBatch};
use std::sync::Arc;

pub trait PalwDaStoreReader {
    fn state(&self, block: BlockHash) -> StoreResult<Arc<PalwDaStateV1>>;
    fn object(&self, root: Hash64) -> StoreResult<Arc<Vec<u8>>>;
    fn pruning_snapshot(&self) -> StoreResult<PalwDaPruningSnapshotV1>;
}

pub trait PalwDaStore: PalwDaStoreReader {
    fn set_state(&mut self, block: BlockHash, state: Arc<PalwDaStateV1>) -> StoreResult<()>;
    fn set_pruning_snapshot(&mut self, snapshot: PalwDaPruningSnapshotV1) -> StoreResult<()>;
}

#[derive(Clone)]
pub struct DbPalwDaStore {
    db: Arc<DB>,
    states: CachedDbAccess<BlockHash, Arc<PalwDaStateV1>, BlockHasher>,
    objects: CachedDbAccess<Hash64, Arc<Vec<u8>>, BlockHasher>,
    snapshot: CachedDbItem<PalwDaPruningSnapshotV1>,
}

impl DbPalwDaStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            states: CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::PalwDaStateByBlock.into()),
            objects: CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::PalwDaObject.into()),
            snapshot: CachedDbItem::new(db, DatabaseStorePrefixes::PalwDaPruningSnapshot.into()),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_state_batch(&mut self, batch: &mut WriteBatch, block: BlockHash, state: Arc<PalwDaStateV1>) -> StoreResult<()> {
        self.states.write(BatchDbWriter::new(batch), block, state)
    }

    pub fn delete_state_batch(&mut self, batch: &mut WriteBatch, block: BlockHash) -> StoreResult<()> {
        self.states.delete(BatchDbWriter::new(batch), block)
    }

    pub fn set_pruning_snapshot_batch(&mut self, batch: &mut WriteBatch, snapshot: &PalwDaPruningSnapshotV1) -> StoreResult<()> {
        if !snapshot.validate() {
            return Err(StoreError::DataInconsistency("invalid PALW DA pruning snapshot".into()));
        }
        self.snapshot.write(BatchDbWriter::new(batch), snapshot)
    }

    pub(crate) fn validate_object(root: Hash64, bytes: &[u8]) -> StoreResult<()> {
        let version = bytes
            .get(..2)
            .and_then(|prefix| prefix.try_into().ok())
            .map(u16::from_le_bytes)
            .ok_or_else(|| StoreError::DataInconsistency("PALW DA object has no version".into()))?;
        let canonical = match version {
            kaspa_consensus_core::palw::da::PALW_RECEIPT_DA_OBJECT_VERSION_V1 => {
                let object = PalwReceiptDaObjectV1::try_from_slice(bytes)
                    .map_err(|_| StoreError::DataInconsistency("PALW DA v1 object is not canonical borsh".into()))?;
                palw_receipt_da_object_bytes(&object)
                    .map_err(|error| StoreError::DataInconsistency(format!("invalid PALW DA v1 object: {error}")))?
            }
            kaspa_consensus_core::palw::da::PALW_RECEIPT_DA_OBJECT_VERSION_V2 => {
                let object = crate::processes::palw_da::decode_canonical_palw_receipt_da_object_v2(bytes)
                    .map_err(|error| StoreError::DataInconsistency(format!("invalid PALW DA v2 object: {error:?}")))?;
                crate::processes::palw_da::palw_receipt_da_object_v2_bytes(&object)
                    .map_err(|error| StoreError::DataInconsistency(format!("invalid PALW DA v2 object: {error:?}")))?
            }
            other => return Err(StoreError::DataInconsistency(format!("unsupported PALW DA object version {other}"))),
        };
        if canonical != bytes {
            return Err(StoreError::DataInconsistency("PALW DA object round-trip is non-canonical".into()));
        }
        let got = palw_receipt_da_commitment(version, bytes)
            .map_err(|error| StoreError::DataInconsistency(format!("invalid PALW DA commitment: {error}")))?
            .root;
        if got != root {
            return Err(StoreError::DataInconsistency("PALW DA object does not hash to its store key".into()));
        }
        Ok(())
    }

    /// Persist bytes that already passed the complete selected-chain V1/V2 admission verifier. This
    /// remains crate-private so root-only/canonical-only validation cannot be exposed as a public
    /// object admission API; [`crate::consensus::palw_da`] is the production caller. The semantic
    /// verifier is intentionally outside the store because it needs one selected-chain
    /// leaf/provider snapshot.
    pub(crate) fn insert_admitted_object(&mut self, root: Hash64, bytes: Arc<Vec<u8>>) -> StoreResult<()> {
        Self::validate_object(root, &bytes)?;
        self.insert_validated_object_db_first(root, bytes)
    }

    fn insert_validated_object_db_first(&self, root: Hash64, bytes: Arc<Vec<u8>>) -> StoreResult<()> {
        self.insert_validated_object_with_persist(root, bytes, |db, key, encoded| {
            db.put(key, encoded)?;
            Ok(())
        })
    }

    fn insert_validated_object_with_persist(
        &self,
        root: Hash64,
        bytes: Arc<Vec<u8>>,
        persist: impl FnOnce(&DB, &DbKey, &[u8]) -> StoreResult<()>,
    ) -> StoreResult<()> {
        // CachedDbAccess::write populates its cache before invoking the writer. That ordering is safe
        // inside an already-committed fail-stop batch, but not for this fallible auxiliary insert: a
        // RocksDB error followed by a retry could otherwise observe cache-only bytes and return Ok.
        // Read and persist the exact wire format directly; the first later read populates the cache
        // only after the durable row exists.
        let prefix: Vec<u8> = DatabaseStorePrefixes::PalwDaObject.into();
        let key = DbKey::new(&prefix, root);
        if let Some(existing) = self.db.get_pinned(&key)? {
            let existing: Arc<Vec<u8>> = bincode::deserialize(&existing)?;
            return if *existing == *bytes {
                Ok(())
            } else {
                Err(StoreError::KeyAlreadyExists(format!("PALW DA object root collision at {root}")))
            };
        }
        let encoded = bincode::serialize(&bytes)?;
        persist(&self.db, &key, &encoded)
    }

    /// Collect every content key before any GC mutation. Values can be hundreds of KiB and are not
    /// relevant to liveness, so this intentionally uses a raw key-only prefix iterator. A malformed
    /// key or RocksDB iterator error aborts the collection, preserving delete-zero on an incomplete
    /// store view.
    pub(crate) fn object_roots(&self) -> StoreResult<Vec<Hash64>> {
        let prefix: Vec<u8> = DatabaseStorePrefixes::PalwDaObject.into();
        let prefix_key = DbKey::prefix_only(&prefix);
        let mut read_options = ReadOptions::default();
        read_options.set_iterate_range(rocksdb::PrefixRange(prefix_key.as_ref()));
        self.db
            .iterator_opt(IteratorMode::From(prefix_key.as_ref(), Direction::Forward), read_options)
            .map(|row| {
                let (key, _) = row.map_err(|error| StoreError::DataInconsistency(format!("PALW DA object iterator: {error}")))?;
                let bytes: [u8; 64] = key[prefix_key.prefix_len()..]
                    .try_into()
                    .map_err(|_| StoreError::DataInconsistency("PALW DA object key is not 64 bytes".into()))?;
                Ok(Hash64::from_bytes(bytes))
            })
            .collect()
    }

    /// Commit one all-or-nothing removal batch. Cache entries are invalidated while building the
    /// batch; if RocksDB rejects the commit they remain harmless cache misses and subsequent reads
    /// fall back to the still-present durable rows.
    pub(crate) fn delete_objects_atomic(&mut self, roots: &[Hash64]) -> StoreResult<()> {
        if roots.is_empty() {
            return Ok(());
        }
        let mut batch = WriteBatch::default();
        let mut roots = roots.iter().copied();
        self.objects.delete_many(BatchDbWriter::new(&mut batch), &mut roots)?;
        self.db.write(batch)?;
        Ok(())
    }
}

impl PalwDaStoreReader for DbPalwDaStore {
    fn state(&self, block: BlockHash) -> StoreResult<Arc<PalwDaStateV1>> {
        self.states.read(block)
    }

    fn object(&self, root: Hash64) -> StoreResult<Arc<Vec<u8>>> {
        self.objects.read(root)
    }

    fn pruning_snapshot(&self) -> StoreResult<PalwDaPruningSnapshotV1> {
        self.snapshot.read()
    }
}

impl PalwDaStore for DbPalwDaStore {
    fn set_state(&mut self, block: BlockHash, state: Arc<PalwDaStateV1>) -> StoreResult<()> {
        self.states.write(DirectDbWriter::new(&self.db), block, state)
    }

    fn set_pruning_snapshot(&mut self, snapshot: PalwDaPruningSnapshotV1) -> StoreResult<()> {
        if !snapshot.validate() {
            return Err(StoreError::DataInconsistency("invalid PALW DA pruning snapshot".into()));
        }
        self.snapshot.write(DirectDbWriter::new(&self.db), &snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::tx::TransactionOutpoint;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::{ConnBuilder, StoreError};

    fn h(byte: u8) -> Hash64 {
        Hash64::from_bytes([byte; 64])
    }

    #[test]
    fn fork_local_state_and_pruning_snapshot_round_trip() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut store = DbPalwDaStore::new(db.clone(), CachePolicy::Count(32));
        let block_a = h(0x11);
        let block_b = h(0x22);
        let state_a = Arc::new(PalwDaStateV1::default());
        let mut state_b_value = PalwDaStateV1::default();
        state_b_value.record_block_slash(TransactionOutpoint::new(h(0x33), 0)).unwrap();
        let state_b = Arc::new(state_b_value);

        store.set_state(block_a, state_a.clone()).unwrap();
        store.set_state(block_b, state_b.clone()).unwrap();
        assert_eq!(store.state(block_a).unwrap(), state_a);
        assert_eq!(store.state(block_b).unwrap(), state_b);
        assert!(matches!(store.state(h(0xff)), Err(StoreError::KeyNotFound(_))));

        let snapshot = PalwDaPruningSnapshotV1 { version: 1, pruning_point: block_b, state: (*state_b).clone() };
        store.set_pruning_snapshot(snapshot.clone()).unwrap();
        assert_eq!(store.pruning_snapshot().unwrap(), snapshot);

        let mut batch = WriteBatch::default();
        store.delete_state_batch(&mut batch, block_a).unwrap();
        db.write(batch).unwrap();
        assert!(matches!(store.state(block_a), Err(StoreError::KeyNotFound(_))));
        assert_eq!(store.state(block_b).unwrap(), state_b);
    }

    #[test]
    fn invalid_snapshot_is_rejected_before_write() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut store = DbPalwDaStore::new(db, CachePolicy::Count(4));
        let invalid = PalwDaPruningSnapshotV1 { version: 2, pruning_point: h(1), state: PalwDaStateV1::default() };
        assert!(matches!(store.set_pruning_snapshot(invalid), Err(StoreError::DataInconsistency(_))));
    }

    #[test]
    fn object_gc_batch_preserves_live_roots_and_survives_fresh_cache_restart() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut store = DbPalwDaStore::new(db.clone(), CachePolicy::Count(4));
        let live = h(0x31);
        let stale_a = h(0x32);
        let stale_b = h(0x33);
        // GC is content-key agnostic; admission validation is tested separately. Insert tiny rows
        // directly so this test isolates iterator completeness + atomic key removal.
        for root in [live, stale_a, stale_b] {
            store.objects.write(DirectDbWriter::new(&db), root, Arc::new(vec![root.as_bytes()[0]])).unwrap();
        }
        let mut roots = store.object_roots().unwrap();
        roots.sort_unstable();
        assert_eq!(roots, vec![live, stale_a, stale_b]);

        store.delete_objects_atomic(&[stale_a, stale_b]).unwrap();
        assert_eq!(store.object_roots().unwrap(), vec![live]);
        let restarted = store.clone_with_new_cache(CachePolicy::Count(4));
        assert_eq!(*restarted.object(live).unwrap(), vec![0x31]);
        assert!(matches!(restarted.object(stale_a), Err(StoreError::KeyNotFound(_))));
        assert!(matches!(restarted.object(stale_b), Err(StoreError::KeyNotFound(_))));
    }

    #[test]
    fn admitted_object_persist_failure_cannot_turn_retry_into_cache_only_success() {
        let (_lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwDaStore::new(db.clone(), CachePolicy::Count(4));
        let root = h(0x51);
        let bytes = Arc::new(vec![1, 2, 3, 4]);

        let injected = store.insert_validated_object_with_persist(root, bytes.clone(), |_db, _key, _encoded| {
            Err(StoreError::DataInconsistency("injected object write failure".into()))
        });
        assert!(matches!(injected, Err(StoreError::DataInconsistency(_))));
        assert!(matches!(store.object(root), Err(StoreError::KeyNotFound(_))), "failed persistence must not seed the cache");

        store.insert_validated_object_db_first(root, bytes.clone()).unwrap();
        let restarted = store.clone_with_new_cache(CachePolicy::Count(4));
        assert_eq!(restarted.object(root).unwrap(), bytes, "retry success must come from the durable row");
    }
}
