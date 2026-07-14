use std::sync::Arc;

use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::BlockHasher;
use kaspa_consensus_core::palw::{BeaconEpochInputs, PalwBeaconEpochAccumV1, PalwBeaconStateV1};
use kaspa_consensus_core::tx::TransactionOutpoint;
use kaspa_database::prelude::CachePolicy;
use kaspa_database::prelude::StoreResultExt;
use kaspa_database::prelude::DB;
use kaspa_database::prelude::{BatchDbWriter, CachedDbAccess, DirectDbWriter, StoreError};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash64;
use rocksdb::WriteBatch;

use super::U64Key;

/// kaspa-pq ADR-0039 PALW (§11.2 / §18.1) — the DNS beacon overlay store. Two access paths:
///
/// * `accum` (prefix 242, keyed by **epoch**): the per-epoch [`PalwBeaconEpochAccumV1`] — the
///   `(bond, commitment)` sets that committed for the epoch and the subset that validly revealed
///   (`matches_commit`). The commit/reveal overlay txs (`0x35`/`0x36`) accumulate here as they are
///   accepted; the epoch-boundary derivation reads it to build the two `beacon_seed` roots. Epoch-keyed
///   (a global overlay fact, like the batch/leaf/cert stores — its past-relative resolution is the same
///   activation-time concern documented on those stores).
/// * `state` (prefix 243, keyed by **block hash**): the block's carried [`PalwBeaconStateV1`] — the
///   active `R_E` recurrence. Block-keyed and read via the selected parent (`reserve_balance` pattern),
///   so it is past-relative + reorg-safe and forward-compatible with the eventual header commitment.
///
/// **Inert (never written)** on every shipped preset: nothing mints a PALW commit/reveal tx or an
/// algo-4 block while the fence is `activation_daa_score = u64::MAX`, so both column families stay empty.
/// This store reserves the format + access path; the writers are exercised only on a PALW-activated
/// re-genesis network.
#[derive(Clone)]
pub struct DbPalwBeaconStore {
    db: Arc<DB>,
    accum: CachedDbAccess<U64Key, Arc<PalwBeaconEpochAccumV1>>,
    state: CachedDbAccess<BlockHash, Arc<PalwBeaconStateV1>, BlockHasher>,
}

impl DbPalwBeaconStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            accum: CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::PalwBeaconAccum.into()),
            state: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::PalwBeaconState.into()),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    // ---- epoch accumulator (commit/reveal facts) ----

    fn read_accum(&self, epoch: u64) -> Result<PalwBeaconEpochAccumV1, StoreError> {
        // Seed an absent epoch with `new()` (version = 1), not `default()` (version = 0), so persisted
        // accumulator records carry the v1 version tag.
        Ok(self.accum.read(epoch.into()).optional()?.map(|a| (*a).clone()).unwrap_or_else(PalwBeaconEpochAccumV1::new))
    }

    /// Record a beacon commit for `bond` in `epoch` (read-modify-write; idempotent per bond outpoint).
    pub fn record_commit(&self, epoch: u64, bond: TransactionOutpoint, commitment: Hash64) -> Result<(), StoreError> {
        let mut accum = self.read_accum(epoch)?;
        accum.record_commit(bond, commitment);
        self.accum.write(DirectDbWriter::new(&self.db), epoch.into(), Arc::new(accum))
    }

    /// The commitment `bond` committed for `epoch`, if any — used to check a reveal's `matches_commit`.
    pub fn commitment_of(&self, epoch: u64, bond: &TransactionOutpoint) -> Result<Option<Hash64>, StoreError> {
        Ok(self.read_accum(epoch)?.commitment_of(bond))
    }

    /// Record that `bond`'s reveal validly opened `commitment` in `epoch` (idempotent per bond outpoint).
    pub fn record_valid_reveal(&self, epoch: u64, bond: TransactionOutpoint, commitment: Hash64) -> Result<(), StoreError> {
        let mut accum = self.read_accum(epoch)?;
        accum.record_valid_reveal(bond, commitment);
        self.accum.write(DirectDbWriter::new(&self.db), epoch.into(), Arc::new(accum))
    }

    /// The pure derivation inputs for `epoch` (empty if nothing accumulated).
    pub fn epoch_inputs(&self, epoch: u64) -> Result<BeaconEpochInputs, StoreError> {
        Ok(self.read_accum(epoch)?.to_inputs())
    }

    pub fn delete_accum_batch(&self, batch: &mut WriteBatch, epoch: u64) -> Result<(), StoreError> {
        self.accum.delete(BatchDbWriter::new(batch), epoch.into())
    }

    // ---- per-block carried state (R_E recurrence) ----

    /// The block's carried beacon state, or `None` if absent (genesis / not yet derived).
    pub fn beacon_state(&self, block: BlockHash) -> Result<Option<Arc<PalwBeaconStateV1>>, StoreError> {
        self.state.read(block).optional()
    }

    /// Write `block`'s carried beacon state into the commit `WriteBatch` (atomic with the UTXO diff).
    pub fn set_state_batch(&self, batch: &mut WriteBatch, block: BlockHash, state: Arc<PalwBeaconStateV1>) -> Result<(), StoreError> {
        self.state.write(BatchDbWriter::new(batch), block, state)
    }

    /// Direct (non-batch) beacon-state write — diagnostics / tests.
    pub fn set_state(&self, block: BlockHash, state: Arc<PalwBeaconStateV1>) -> Result<(), StoreError> {
        self.state.write(DirectDbWriter::new(&self.db), block, state)
    }

    pub fn delete_state_batch(&self, batch: &mut WriteBatch, block: BlockHash) -> Result<(), StoreError> {
        self.state.delete(BatchDbWriter::new(batch), block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;

    fn op(b: u8, i: u32) -> TransactionOutpoint {
        TransactionOutpoint::new(Hash64::from_bytes([b; 64]), i)
    }
    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    /// The epoch accumulator: commits accumulate, a matching reveal is recorded, epoch_inputs reflects
    /// both, and the whole thing round-trips through the DB. Idempotent per bond.
    #[test]
    fn accum_commit_reveal_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwBeaconStore::new(db, CachePolicy::Count(16));

        // empty epoch → empty inputs.
        assert_eq!(store.epoch_inputs(9).unwrap(), BeaconEpochInputs::default());

        // two commits; a duplicate on the same bond is ignored.
        store.record_commit(9, op(0x50, 0), h(11)).unwrap();
        store.record_commit(9, op(0x50, 1), h(12)).unwrap();
        store.record_commit(9, op(0x50, 0), h(99)).unwrap();
        assert_eq!(store.commitment_of(9, &op(0x50, 0)).unwrap(), Some(h(11)));
        let inputs = store.epoch_inputs(9).unwrap();
        assert_eq!(inputs.commits.len(), 2);
        assert_eq!(inputs.valid_reveals.len(), 0);

        // record one valid reveal.
        store.record_valid_reveal(9, op(0x50, 0), h(11)).unwrap();
        let inputs = store.epoch_inputs(9).unwrap();
        assert_eq!(inputs.valid_reveals, vec![(op(0x50, 0), h(11))]);
        // a different epoch is independent.
        assert_eq!(store.epoch_inputs(10).unwrap(), BeaconEpochInputs::default());
    }

    /// The per-block state store: absent → None, set → read back, batch write + delete.
    #[test]
    fn state_block_keyed_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwBeaconStore::new(db, CachePolicy::Count(16));
        let block = h(0x21);
        assert!(store.beacon_state(block).unwrap().is_none());

        let st = Arc::new(PalwBeaconStateV1 {
            version: 1, epoch: 9, seed: h(1), dns_anchor: h(2), valid_reveals_root: h(3),
            missing_commitments_root: h(4), mode: 0, degraded_epochs: 0, valid_reveal_count: 1, missing_commit_count: 0,
        });
        let mut batch = WriteBatch::default();
        store.set_state_batch(&mut batch, block, st.clone()).unwrap();
        db_write(&store, batch);
        assert_eq!(*store.beacon_state(block).unwrap().unwrap(), *st);

        let mut batch = WriteBatch::default();
        store.delete_state_batch(&mut batch, block).unwrap();
        db_write(&store, batch);
        assert!(store.beacon_state(block).unwrap().is_none());
    }

    fn db_write(store: &DbPalwBeaconStore, batch: WriteBatch) {
        store.db.write(batch).unwrap();
    }
}
