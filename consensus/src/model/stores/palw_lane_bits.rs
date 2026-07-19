use std::sync::Arc;

use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::BlockHasher;
use kaspa_consensus_core::palw::PalwLaneBitsV1;
use kaspa_database::prelude::CachePolicy;
use kaspa_database::prelude::StoreResultExt;
use kaspa_database::prelude::DB;
use kaspa_database::prelude::{BatchDbWriter, CachedDbAccess, DirectDbWriter, StoreError};
use kaspa_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;

/// kaspa-pq ADR-0039 PALW (§16.3) — the block-keyed per-lane difficulty bits store. Each block carries
/// BOTH lanes' current bits (`hash_bits`, `replica_bits`), read via the selected parent as the retarget
/// HOLD source. Block-keyed because the structural blocker is symmetric: a block's selected parent may
/// be on the OTHER lane, so its `header.bits` is the wrong lane's difficulty. Written for every block
/// at/above the PALW activation fence; the empty-window HOLD falls back to `genesis_{hash,replica}_bits`.
///
/// **Never written — but NOT for the reason previously documented.** The old claim
/// ("`palw_activation_daa_score == u64::MAX` on every shipped preset") is FALSE:
/// `testnet-palw-110` and `devnet-palw-111` ship `palw_activation_daa_score = 0`
/// (`consensus/core/src/config/params.rs:1403`, `:1454`), so a fence-based argument does not hold here.
///
/// The store is empty on every preset for a simpler and stronger reason: **it has no producer at all.**
/// The only write-shaped API is unused — the sole non-test references in the pipeline are a `delete_batch`
/// in the pruning processor and the HOLD read in `processes/palw.rs`. The lane-aware retarget consumes
/// `lane_bits(selected_parent)`, gets `None`, and falls back to `genesis_{hash,replica}_bits`.
///
/// That makes this an OPEN activation blocker, not a closed inert seam: wiring the per-block writer is
/// a prerequisite for clause 7 (lane-aware difficulty), which `body_validation_in_context.rs` already
/// records as deliberately unenforced. Until that writer exists there are no legacy rows to misparse,
/// so this store did not drive the `LATEST_DB_VERSION` 7 → 8 bump — its siblings did.
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
}
