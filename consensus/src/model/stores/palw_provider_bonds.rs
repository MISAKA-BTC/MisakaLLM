//! kaspa-pq **ADR-0040 ECON-03 (THE WIRE) — the provider-bond registry, prefix 241.**
//!
//! Keyed by the [`TransactionOutpoint`] that created the bond (output-0 of its `ProviderBond`
//! transaction — the very output [`kaspa_consensus_core::palw::validate_provider_bond_tx`] pinned).
//! Values are [`PalwProviderBondRecord`]s produced by
//! [`kaspa_consensus_core::palw::palw_provider_bond_mutations_from_accepted_txs`].
//!
//! This is `stake_bonds` (the DNS precedent) transposed with ONE deliberate difference: a
//! [`PalwProviderBondRecord`] carries no mutable `status` field, so the only in-place rewrites this
//! store ever performs are stamping/clearing `unbond_request_daa_score` and `slashed_at_daa_score`.
//! Status is always re-derived by
//! [`kaspa_consensus_core::palw::effective_provider_bond_status`] at a point of view, which is why
//! apply/revert are exact inverses and two nodes reaching the same block by different reorg paths
//! hold byte-identical rows.
//!
//! Prefix 241 was reserved (and documented) long before this slice; nothing has ever written it, so
//! introducing the writer adds rows to a key range that is empty on every existing datadir. No
//! previously-persisted layout moves, hence no `LATEST_DB_VERSION` bump — see the pin test in
//! `consensus/src/consensus/factory.rs`.

use kaspa_consensus_core::{
    palw::PalwProviderBondRecord,
    tx::{TransactionIndexType, TransactionOutpoint},
};
use kaspa_database::prelude::DB;
use kaspa_database::prelude::{BatchDbWriter, CachedDbAccess, DirectDbWriter};
use kaspa_database::prelude::{CachePolicy, StoreError, StoreResult};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::{HASH64_SIZE, Hash64};
use rocksdb::WriteBatch;
use std::{error::Error, sync::Arc};

/// `{ Hash64 txid (64) ‖ u32 index (4) }` = 68 bytes — byte-identical to
/// [`super::stake_bonds::STAKE_BOND_KEY_SIZE`], so the two registries can be diffed key-for-key.
pub const PALW_PROVIDER_BOND_KEY_SIZE: usize = HASH64_SIZE + size_of::<TransactionIndexType>();

#[derive(Eq, Hash, PartialEq, Debug, Copy, Clone)]
struct PalwProviderBondKey([u8; PALW_PROVIDER_BOND_KEY_SIZE]);

impl AsRef<[u8]> for PalwProviderBondKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PalwProviderBondKey {
    type Error = &'static str;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != PALW_PROVIDER_BOND_KEY_SIZE {
            return Err("palw provider-bond key slice has unexpected length");
        }
        let mut bytes = [0u8; PALW_PROVIDER_BOND_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl From<TransactionOutpoint> for PalwProviderBondKey {
    fn from(outpoint: TransactionOutpoint) -> Self {
        let mut bytes = [0u8; PALW_PROVIDER_BOND_KEY_SIZE];
        bytes[..HASH64_SIZE].copy_from_slice(&outpoint.transaction_id.as_bytes());
        bytes[HASH64_SIZE..].copy_from_slice(&outpoint.index.to_le_bytes());
        Self(bytes)
    }
}

impl From<PalwProviderBondKey> for TransactionOutpoint {
    fn from(k: PalwProviderBondKey) -> Self {
        let transaction_id = Hash64::from_slice(&k.0[..HASH64_SIZE]);
        let index = TransactionIndexType::from_le_bytes(
            <[u8; size_of::<TransactionIndexType>()]>::try_from(&k.0[HASH64_SIZE..]).expect("index size is exact"),
        );
        Self::new(transaction_id, index)
    }
}

impl std::fmt::Display for PalwProviderBondKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let outpoint: TransactionOutpoint = (*self).into();
        outpoint.fmt(f)
    }
}

pub trait PalwProviderBondsStoreReader {
    fn get(&self, outpoint: &TransactionOutpoint) -> Result<Arc<PalwProviderBondRecord>, StoreError>;
    fn has(&self, outpoint: &TransactionOutpoint) -> Result<bool, StoreError>;
    /// Iterates every persisted provider-bond record — the seed for the per-block
    /// [`kaspa_consensus_core::palw::ProviderBondView`] walk.
    fn iterator(&self) -> Box<dyn Iterator<Item = Result<(TransactionOutpoint, Arc<PalwProviderBondRecord>), Box<dyn Error>>> + '_>;
}

pub trait PalwProviderBondsStore: PalwProviderBondsStoreReader {
    fn insert(&mut self, outpoint: TransactionOutpoint, record: Arc<PalwProviderBondRecord>) -> Result<(), StoreError>;
    fn delete(&mut self, outpoint: TransactionOutpoint) -> Result<(), StoreError>;
}

/// A DB + cache implementation of [`PalwProviderBondsStore`].
#[derive(Clone)]
pub struct DbPalwProviderBondsStore {
    db: Arc<DB>,
    access: CachedDbAccess<PalwProviderBondKey, Arc<PalwProviderBondRecord>>,
}

impl DbPalwProviderBondsStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::PalwProviderBond.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn insert_batch(
        &mut self,
        batch: &mut WriteBatch,
        outpoint: TransactionOutpoint,
        record: Arc<PalwProviderBondRecord>,
    ) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), outpoint.into(), record)
    }

    pub fn delete_batch(&mut self, batch: &mut WriteBatch, outpoint: TransactionOutpoint) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), outpoint.into())
    }
}

impl PalwProviderBondsStoreReader for DbPalwProviderBondsStore {
    fn get(&self, outpoint: &TransactionOutpoint) -> Result<Arc<PalwProviderBondRecord>, StoreError> {
        self.access.read((*outpoint).into())
    }

    fn has(&self, outpoint: &TransactionOutpoint) -> Result<bool, StoreError> {
        self.access.has((*outpoint).into())
    }

    fn iterator(&self) -> Box<dyn Iterator<Item = Result<(TransactionOutpoint, Arc<PalwProviderBondRecord>), Box<dyn Error>>> + '_> {
        Box::new(self.access.iterator().map(|res| match res {
            Ok((key_bytes, record)) => {
                let key = PalwProviderBondKey::try_from(key_bytes.as_ref())?;
                Ok((key.into(), record))
            }
            Err(e) => Err(e),
        }))
    }
}

impl PalwProviderBondsStore for DbPalwProviderBondsStore {
    fn insert(&mut self, outpoint: TransactionOutpoint, record: Arc<PalwProviderBondRecord>) -> Result<(), StoreError> {
        self.access.write(DirectDbWriter::new(&self.db), outpoint.into(), record)
    }

    fn delete(&mut self, outpoint: TransactionOutpoint) -> Result<(), StoreError> {
        self.access.delete(DirectDbWriter::new(&self.db), outpoint.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;

    fn outpoint(b: u8, idx: u32) -> TransactionOutpoint {
        TransactionOutpoint::new(Hash64::from_bytes([b; 64]), idx)
    }

    fn record(op: TransactionOutpoint, amount: u64) -> Arc<PalwProviderBondRecord> {
        Arc::new(PalwProviderBondRecord {
            version: 1,
            bond_outpoint: op,
            owner_pubkey_hash: Hash64::from_bytes([0xaa; 64]),
            owner_public_key: vec![0xcc; 2592],
            operator_group_id: Hash64::from_bytes([0xbb; 64]),
            runtime_classes: vec![Hash64::from_bytes([0x01; 64])],
            capacity_by_shape: vec![(1, 10)],
            reward_key_root: Hash64::from_bytes([0xdd; 64]),
            amount_sompi: amount,
            activation_daa_score: 100,
            created_daa_score: 100,
            unbond_delay_epochs: 4,
            unbond_request_daa_score: None,
            slashed_at_daa_score: None,
        })
    }

    #[test]
    fn palw_provider_bonds_store_crud_iterator_and_key_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut store = DbPalwProviderBondsStore::new(db.clone(), CachePolicy::Count(16));

        // A high outpoint index exercises the 4-byte LE index half of the key.
        let op1 = outpoint(0x01, 0);
        let op2 = outpoint(0x02, 4_000_000_007);

        assert!(!store.has(&op1).unwrap());
        assert!(store.get(&op1).is_err());

        store.insert(op1, record(op1, 1_000)).unwrap();
        store.insert(op2, record(op2, 2_000)).unwrap();
        assert!(store.has(&op1).unwrap());
        assert_eq!(store.get(&op1).unwrap().amount_sompi, 1_000);
        assert_eq!(store.get(&op2).unwrap().amount_sompi, 2_000);

        // An unbond stamp is an in-place rewrite of the same key.
        let mut unbonding = (*store.get(&op1).unwrap()).clone();
        unbonding.unbond_request_daa_score = Some(700);
        store.insert(op1, Arc::new(unbonding)).unwrap();
        assert_eq!(store.get(&op1).unwrap().unbond_request_daa_score, Some(700));

        // Iterator yields both, round-tripping each outpoint through the key codec.
        let seen: Vec<TransactionOutpoint> = store.iterator().map(|r| r.unwrap().0).collect();
        assert_eq!(seen.len(), 2);
        assert!(seen.contains(&op1) && seen.contains(&op2));

        // Batch delete removes only the targeted key.
        let mut batch = WriteBatch::default();
        store.delete_batch(&mut batch, op1).unwrap();
        db.write(batch).unwrap();
        assert!(!store.has(&op1).unwrap());
        assert!(store.has(&op2).unwrap());
    }
}
