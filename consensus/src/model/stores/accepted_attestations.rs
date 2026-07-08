use std::sync::Arc;

use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::{BlockHasher, tx::TransactionOutpoint};
use kaspa_database::prelude::CachePolicy;
use kaspa_database::prelude::DB;
use kaspa_database::prelude::StoreError;
use kaspa_database::prelude::{BatchDbWriter, CachedDbAccess, DirectDbWriter};
use kaspa_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;

/// kaspa-pq DNS Dormancy Fence (SB-2/SB-5, ADR-0031): per-block store of the ACCEPTED
/// `(bond_outpoint, epoch)` attestation set, keyed by the **burial-frontier block** `B(E)`
/// (the first selected-chain block with `blue_score >= epoch_end_blue(E) + bury_blue`, at
/// whose own commit epoch `E` is buried by construction). A row is the union of the accepted
/// sets over every epoch `E` whose frontier lands at that block (usually 0 or 1).
///
/// The exact structural mirror of [`super::rewarded_epochs`], but with two deliberate
/// differences that make dormancy revival deterministic + pruning-reconstructable:
/// - It records the **acceptance superset** (`active_or_dormant_bond_at` — Active OR Dormant,
///   dormancy-INDEPENDENT), NOT the Active-only rewarded subset, so the per-block write is a
///   pure function of `B(E)`'s buried past (no un-accreted dormancy stamp is read). The
///   Active/Dormant classification is done later, per round, inside `apply_dormancy_round`
///   (its `e > dormant_epoch` guard discards the non-revival entries against the kernel's own
///   as-of-`r` state) — so a jumping (IBD/resume) node and an incremental node commit the
///   identical set.
/// - It carries the revival recency the Active-only rewarded store cannot (a Dormant bond
///   earns zero reward, so its attestations never enter `rewarded_epochs`).
///
/// Written at `commit_utxo_state` for each `B(E)`; empty (unwritten) for every block that is
/// not a burial frontier, and for every block while the dormancy fence is inert. Deleted by
/// the pruning processor alongside `rewarded_epochs_store`. Its `accepted_keys` copy rides
/// the committed `BlockOverlayContribution`, so a pruned importer rebuilds it from the
/// captured snapshot window.
pub type AcceptedAttestationKeys = Vec<(TransactionOutpoint, u64)>;

pub trait AcceptedAttestationsStoreReader {
    fn get(&self, hash: BlockHash) -> Result<Arc<AcceptedAttestationKeys>, StoreError>;
}

pub trait AcceptedAttestationsStore: AcceptedAttestationsStoreReader {
    fn insert(&self, hash: BlockHash, keys: Arc<AcceptedAttestationKeys>) -> Result<(), StoreError>;
    fn delete(&self, hash: BlockHash) -> Result<(), StoreError>;
}

/// A DB + cache implementation of the `AcceptedAttestationsStore` trait.
#[derive(Clone)]
pub struct DbAcceptedAttestationsStore {
    db: Arc<DB>,
    access: CachedDbAccess<BlockHash, Arc<AcceptedAttestationKeys>, BlockHasher>,
}

impl DbAcceptedAttestationsStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::AcceptedAttestations.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn insert_batch(&self, batch: &mut WriteBatch, hash: BlockHash, keys: Arc<AcceptedAttestationKeys>) -> Result<(), StoreError> {
        if self.access.has(hash)? {
            return Err(StoreError::KeyAlreadyExists(hash.to_string()));
        }
        self.access.write(BatchDbWriter::new(batch), hash, keys)?;
        Ok(())
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: BlockHash) -> Result<(), StoreError> {
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}

impl AcceptedAttestationsStoreReader for DbAcceptedAttestationsStore {
    fn get(&self, hash: BlockHash) -> Result<Arc<AcceptedAttestationKeys>, StoreError> {
        self.access.read(hash)
    }
}

impl AcceptedAttestationsStore for DbAcceptedAttestationsStore {
    fn insert(&self, hash: BlockHash, keys: Arc<AcceptedAttestationKeys>) -> Result<(), StoreError> {
        if self.access.has(hash)? {
            return Err(StoreError::KeyAlreadyExists(hash.to_string()));
        }
        self.access.write(DirectDbWriter::new(&self.db), hash, keys)?;
        Ok(())
    }

    fn delete(&self, hash: BlockHash) -> Result<(), StoreError> {
        self.access.delete(DirectDbWriter::new(&self.db), hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;
    use kaspa_hashes::Hash64;
    use kaspa_utils::mem_size::MemSizeEstimator;

    fn accepted(n: u32) -> Arc<AcceptedAttestationKeys> {
        Arc::new((0..n).map(|i| (TransactionOutpoint::new(Hash64::from_bytes([i as u8; 64]), i), i as u64)).collect())
    }

    /// Happy path under the PRODUCTION cache mode (untracked `Count`): insert, read back,
    /// delete, and re-insert on the same block hash is rejected (per-block append-only).
    #[test]
    fn insert_get_delete_under_count_policy() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbAcceptedAttestationsStore::new(db, CachePolicy::Count(16));
        let h = Hash64::from_bytes([0x11; 64]);
        let keys = accepted(3);

        assert!(store.get(h).is_err());
        store.insert(h, keys.clone()).unwrap();
        assert_eq!(store.get(h).unwrap().as_slice(), keys.as_slice());
        assert!(store.insert(h, keys.clone()).is_err());
        store.delete(h).unwrap();
        assert!(store.get(h).is_err());
    }

    /// `AcceptedAttestationKeys` is a `Vec`, so it is UNIT-estimable (its length).
    #[test]
    fn value_is_unit_estimable() {
        assert_eq!(accepted(4).estimate_mem_units(), 4);
    }

    /// Regression guard (same as `rewarded_epochs`): the `Vec` value has NO byte estimation,
    /// so this store MUST use an untracked / units cache policy — never `tracked_bytes`, which
    /// would panic on the first non-empty write on-chain. Pinning the missing byte estimation
    /// makes any future switch to a bytes-tracked policy fail loudly in unit tests.
    #[test]
    #[should_panic(expected = "not implemented")]
    fn value_has_no_byte_estimation() {
        let _ = accepted(1).estimate_mem_bytes();
    }
}
