//! kaspa-pq ADR-0039 §18.2 / D3: singleton store for the [`PalwPrunedFrontierV1`] — the PALW frontier
//! taken as-of the current pruning point, tagged with that pruning point.
//!
//! A parallel of [`super::pruning_overlay_snapshot`], captured at the SAME pruning-advance so a pruned
//! joiner can validate the first post-pruning-point v3 block (its `beacon_state(pp)` — else the overlay-
//! root recompute panics — plus the overlay view, lane bits, and active-nullifier window at `pp`).
//!
//! **Why its OWN singleton, not a field on `PruningPointOverlaySnapshot`** (D3 boundary review): the
//! overlay-snapshot wrapper is bincode-persisted, and appending a field to it makes a pre-upgrade
//! singleton unreadable on an in-place binary upgrade (bincode is positional), which on a pruned overlay
//! node degrades serving liveness / risks a capture-time panic until the next pruning advance rewrites
//! it. A FRESH prefix has no legacy bytes to misparse: before the first write `get` returns `KeyNotFound`
//! (→ `None` via `.ok()`), which is exactly the empty / inert case on every shipped preset. Equally
//! non-committed (it never enters `overlay_commitment_root`).

use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::palw::PalwPrunedFrontierV1;
use kaspa_database::prelude::DB;
use kaspa_database::prelude::StoreResult;
use kaspa_database::prelude::{BatchDbWriter, CachedDbItem, DirectDbWriter};
use kaspa_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use std::sync::Arc;

/// The stored value: the frontier plus the pruning point it is taken as-of (so a server only serves it
/// for a matching request, and a joiner binds it to the right pp).
pub type PalwPrunedFrontierEntry = (BlockHash, PalwPrunedFrontierV1);

pub trait PalwPrunedFrontierStoreReader {
    fn get(&self) -> StoreResult<PalwPrunedFrontierEntry>;
}

pub trait PalwPrunedFrontierStore: PalwPrunedFrontierStoreReader {
    fn set(&mut self, entry: PalwPrunedFrontierEntry) -> StoreResult<()>;
}

#[derive(Clone)]
pub struct DbPalwPrunedFrontierStore {
    db: Arc<DB>,
    access: CachedDbItem<PalwPrunedFrontierEntry>,
}

impl DbPalwPrunedFrontierStore {
    pub fn new(db: Arc<DB>) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbItem::new(db, DatabaseStorePrefixes::PalwPrunedFrontier.into()) }
    }

    pub fn clone_with_new_cache(&self) -> Self {
        Self::new(Arc::clone(&self.db))
    }

    pub fn set_batch(&mut self, batch: &mut WriteBatch, entry: PalwPrunedFrontierEntry) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), &entry)
    }
}

impl PalwPrunedFrontierStoreReader for DbPalwPrunedFrontierStore {
    fn get(&self) -> StoreResult<PalwPrunedFrontierEntry> {
        self.access.read()
    }
}

impl PalwPrunedFrontierStore for DbPalwPrunedFrontierStore {
    fn set(&mut self, entry: PalwPrunedFrontierEntry) -> StoreResult<()> {
        self.access.write(DirectDbWriter::new(&self.db), &entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::palw::{PalwBeaconStateV1, PalwLaneBitsV1};
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::{ConnBuilder, StoreError};
    use kaspa_hashes::Hash64;

    /// Before the first write `get` returns `KeyNotFound` (the empty / inert case that maps to `None`
    /// via `.ok()` on every shipped preset — no legacy bytes to misparse, unlike the wrapper). A
    /// populated frontier round-trips, tagged with its pruning point.
    #[test]
    fn pruned_frontier_singleton_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut store = DbPalwPrunedFrontierStore::new(db);
        assert!(matches!(store.get(), Err(StoreError::KeyNotFound(_))), "empty before first write");

        let pp = Hash64::from_bytes([0x42; 64]);
        let frontier = PalwPrunedFrontierV1 {
            beacon_state: Some(PalwBeaconStateV1 {
                version: 1,
                epoch: 9,
                seed: Hash64::from_bytes([7; 64]),
                dns_anchor: Hash64::from_bytes([8; 64]),
                anchor_blue_score: 700,
                anchor_daa_score: 900,
                anchor_overlay_root: Hash64::from_bytes([9; 64]),
                valid_reveals_root: Hash64::default(),
                missing_commitments_root: Hash64::default(),
                mode: 0,
                degraded_epochs: 0,
                valid_reveal_count: 0,
                missing_commit_count: 0,
            }),
            overlay_view: None,
            lane_bits: Some(PalwLaneBitsV1 { hash_bits: 0x1d00ffff, replica_bits: 0x1e00abcd }),
            active_nullifiers: Default::default(),
        };
        assert!(!frontier.is_empty());
        store.set((pp, frontier.clone())).unwrap();
        let (got_pp, got) = store.get().unwrap();
        assert_eq!(got_pp, pp);
        assert_eq!(got, frontier);
    }
}
