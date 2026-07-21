use std::sync::Arc;

use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::BlockHasher;
use kaspa_consensus_core::palw::PalwLaneBitsV1;
use kaspa_database::prelude::CachePolicy;
use kaspa_database::prelude::DB;
use kaspa_database::prelude::StoreResultExt;
use kaspa_database::prelude::{BatchDbWriter, CachedDbAccess, DirectDbWriter, StoreError};
use kaspa_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;

/// Pure block-state transition shared by the header committer and tests. `parent == None` is valid
/// only at genesis or a finite activation boundary and seeds the network's configured lane pair.
pub fn palw_lane_bits_child(
    parent: Option<PalwLaneBitsV1>,
    genesis_hash_bits: u32,
    genesis_replica_bits: u32,
    pow_algo_id: u8,
    bits: u32,
) -> Result<PalwLaneBitsV1, &'static str> {
    let carried = parent.unwrap_or(PalwLaneBitsV1 { hash_bits: genesis_hash_bits, replica_bits: genesis_replica_bits });
    match pow_algo_id {
        kaspa_consensus_core::pow_layer0::POW_ALGO_ID_BLAKE2B_SHA3 => {
            Ok(carried.with_lane_bits(kaspa_consensus_core::pow_layer0::WorkLane::HashFloor, bits))
        }
        kaspa_consensus_core::pow_layer0::POW_ALGO_ID_PALW_REPLICA => {
            Ok(carried.with_lane_bits(kaspa_consensus_core::pow_layer0::WorkLane::ReplicaPalw, bits))
        }
        _ => Err("active PALW lane state received an unsupported PoW algorithm"),
    }
}

/// kaspa-pq ADR-0039 PALW (§16.3) — the block-keyed per-lane difficulty bits store. Each block carries
/// BOTH lanes' current bits (`hash_bits`, `replica_bits`), read via the selected parent as the retarget
/// HOLD source. Block-keyed because the structural blocker is symmetric: a block's selected parent may
/// be on the OTHER lane, so its `header.bits` is the wrong lane's difficulty. Written for every block
/// at/above the PALW activation fence; the empty-window HOLD falls back to `genesis_{hash,replica}_bits`.
///
/// The header committer is the sole producer. For every active non-genesis block it clones the selected
/// parent's pair (or the configured genesis pair at the boundary), updates only the block's own lane
/// with the already-validated `header.bits`, and stages the row in the same RocksDB batch as the header.
/// Because rows are block-keyed, forks retain independent pairs and a reorg selects the new parent's row
/// without mutating or rolling back a global singleton. Pruning snapshot capture/import preserves the
/// boundary row needed after historical header rows are reclaimed.
#[derive(Clone)]
pub struct DbPalwLaneBitsStore {
    db: Arc<DB>,
    access: CachedDbAccess<BlockHash, PalwLaneBitsV1, BlockHasher>,
}

impl DbPalwLaneBitsStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::PalwLaneBits.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    /// The block's carried lane bits, or `None` if absent (genesis / pre-activation parent → the caller
    /// falls back to the genesis lane bits).
    pub fn lane_bits(&self, block: BlockHash) -> Result<Option<PalwLaneBitsV1>, StoreError> {
        self.access.read(block).optional()
    }

    /// Write `block`'s carried lane bits into the commit `WriteBatch` (atomic with the block commit).
    pub fn set_batch(&self, batch: &mut WriteBatch, block: BlockHash, bits: PalwLaneBitsV1) -> Result<(), StoreError> {
        self.access.write(BatchDbWriter::new(batch), block, bits)
    }

    /// Direct (non-batch) write — diagnostics / tests.
    pub fn set(&self, block: BlockHash, bits: PalwLaneBitsV1) -> Result<(), StoreError> {
        self.access.write(DirectDbWriter::new(&self.db), block, bits)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: BlockHash) -> Result<(), StoreError> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::pow_layer0::WorkLane;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;
    use kaspa_hashes::Hash64;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    /// Absent → None; set → read back both lanes; batch write + delete round-trip.
    #[test]
    fn lane_bits_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwLaneBitsStore::new(db, CachePolicy::Count(16));
        let block = h(0x21);
        assert!(store.lane_bits(block).unwrap().is_none());

        let bits = PalwLaneBitsV1 { hash_bits: 0x1d00ffff, replica_bits: 0x1e00abcd };
        store.set(block, bits).unwrap();
        let got = store.lane_bits(block).unwrap().unwrap();
        assert_eq!(got, bits);
        assert_eq!(got.lane_bits(WorkLane::HashFloor), 0x1d00ffff);
        assert_eq!(got.lane_bits(WorkLane::ReplicaPalw), 0x1e00abcd);

        let mut batch = WriteBatch::default();
        store.delete_batch(&mut batch, block).unwrap();
        store.db.write(batch).unwrap();
        assert!(store.lane_bits(block).unwrap().is_none());
    }

    #[test]
    fn normal_progression_inherits_other_lane_and_updates_current_lane_atomically() {
        use kaspa_consensus_core::pow_layer0::{POW_ALGO_ID_BLAKE2B_SHA3, POW_ALGO_ID_PALW_REPLICA};

        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwLaneBitsStore::new(db.clone(), CachePolicy::Count(16));
        let hash_block = h(0x31);
        let replica_block = h(0x32);
        let hash_state = palw_lane_bits_child(None, 11, 22, POW_ALGO_ID_BLAKE2B_SHA3, 33).unwrap();
        assert_eq!(hash_state, PalwLaneBitsV1 { hash_bits: 33, replica_bits: 22 });

        let mut batch = WriteBatch::default();
        store.set_batch(&mut batch, hash_block, hash_state).unwrap();
        let precommit_observer = DbPalwLaneBitsStore::new(db.clone(), CachePolicy::Count(1));
        assert!(
            precommit_observer.lane_bits(hash_block).unwrap().is_none(),
            "lane bytes must not reach RocksDB before the header batch commits"
        );
        db.write(batch).unwrap();

        let committed = DbPalwLaneBitsStore::new(db.clone(), CachePolicy::Count(1));
        let replica_state =
            palw_lane_bits_child(committed.lane_bits(hash_block).unwrap(), 11, 22, POW_ALGO_ID_PALW_REPLICA, 44).unwrap();
        store.set(replica_block, replica_state).unwrap();
        assert_eq!(store.lane_bits(replica_block).unwrap().unwrap(), PalwLaneBitsV1 { hash_bits: 33, replica_bits: 44 });
    }

    #[test]
    fn fork_reorg_selects_the_block_keyed_parent_lane_state() {
        use kaspa_consensus_core::pow_layer0::{POW_ALGO_ID_BLAKE2B_SHA3, POW_ALGO_ID_PALW_REPLICA};

        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwLaneBitsStore::new(db, CachePolicy::Count(16));
        let common = h(0x40);
        let left = h(0x41);
        let right = h(0x42);
        let common_state = PalwLaneBitsV1 { hash_bits: 100, replica_bits: 200 };
        store.set(common, common_state).unwrap();
        let left_state = palw_lane_bits_child(Some(common_state), 1, 2, POW_ALGO_ID_BLAKE2B_SHA3, 101).unwrap();
        let right_state = palw_lane_bits_child(Some(common_state), 1, 2, POW_ALGO_ID_PALW_REPLICA, 201).unwrap();
        store.set(left, left_state).unwrap();
        store.set(right, right_state).unwrap();

        assert_eq!(store.lane_bits(left).unwrap().unwrap(), PalwLaneBitsV1 { hash_bits: 101, replica_bits: 200 });
        assert_eq!(store.lane_bits(right).unwrap().unwrap(), PalwLaneBitsV1 { hash_bits: 100, replica_bits: 201 });
        assert_eq!(
            palw_lane_bits_child(store.lane_bits(right).unwrap(), 1, 2, POW_ALGO_ID_BLAKE2B_SHA3, 102).unwrap(),
            PalwLaneBitsV1 { hash_bits: 102, replica_bits: 201 },
            "after a reorg, the child must inherit the newly selected branch rather than the old tip"
        );
    }

    #[test]
    fn restart_reopens_the_persisted_block_keyed_lane_state() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let block = h(0x51);
        let expected = PalwLaneBitsV1 { hash_bits: 0x1d00aaaa, replica_bits: 0x1e00bbbb };
        DbPalwLaneBitsStore::new(db.clone(), CachePolicy::Count(1)).set(block, expected).unwrap();

        let reopened = DbPalwLaneBitsStore::new(db, CachePolicy::Count(1));
        assert_eq!(reopened.lane_bits(block).unwrap(), Some(expected));
    }
}
