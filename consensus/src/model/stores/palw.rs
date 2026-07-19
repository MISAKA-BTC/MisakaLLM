//! kaspa-pq ADR-0039 §18.1 — the PALW audited-compute overlay stores: the on-chain state a validator
//! resolves an algo-4 ticket against (leaf descriptor, batch manifest, certificate, batch status). A
//! `verify_palw_ticket` binding (§14.2) is built from `leaf(batch_id, leaf_index)` +
//! `certificate(cert_hash)` + `batch_status(batch_id)`.
//!
//! **Inert (never written)** on every shipped preset: nothing mints an algo-4 header while
//! `palw_activation_daa_score = u64::MAX`, so these stores stay empty; they are populated only on a
//! PALW-activated re-genesis network. This module reserves the format + access paths.
//!
//! **ACTIVATION BLOCKERS (C4 design panel, do not activate before these close):**
//! 1. **NOT pruned.** [`DbPalwStore::delete_batch_records`] has ZERO callers — these rows would grow
//!    without bound once written. (An earlier version of this doc claimed "deleted on prune like the
//!    other overlay stores"; that was false.) Deletion must be bound to the PRUNING POINT (not virtual
//!    DAA, or a reorg resurrects a dropped batch).
//! 2. **Keys are NOT content-derived ⇒ not fork-safe.** `batch_id` is an attacker-chosen *field* of
//!    `PalwBatchManifestV1`, not a hash of it, so `(batch_id, leaf_index)` and `batch_id` are NOT
//!    content addresses: two forks can accept different manifests/leaves under the same key and the
//!    last writer wins. The panel-resolved fix is to re-key the content stores by their content
//!    (`manifest_hash -> manifest`, `(leaf_root, leaf_index) -> leaf`; `cert_hash -> cert` is already
//!    correct), so the blob store becomes write-once by collision resistance and fork-relativity is
//!    carried by a separate compact per-block view (presence + status only).
//! 3. **Writes are sink-search-loser-unsafe.** `commit_palw_overlay_effects` writes these
//!    `batch_id`-keyed rows from `commit_utxo_state`, the exact call site whose doc already explains
//!    why the EVM `evm_number -> L1 hash` row is NOT written there: a UTXO-valid candidate that the
//!    sink search later rejects would overwrite the canonical row. Same bug class, consensus-load-
//!    bearing rather than RPC-cosmetic. Writes must be driven by the selected chain instead.

use kaspa_consensus_core::BlockHasher;
use kaspa_consensus_core::palw::{PalwBatchCertificateV1, PalwBatchManifestV1, PalwBatchStatus, PalwPublicLeafV1};
use kaspa_database::prelude::DB;
use kaspa_database::prelude::{BatchDbWriter, CachedDbAccess, DirectDbWriter};
use kaspa_database::prelude::{CachePolicy, StoreError};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::{HASH64_SIZE, Hash64};
use rocksdb::WriteBatch;
use std::sync::Arc;

/// `{ Hash64 batch_id (64) ‖ u32 leaf_index (4) }` = 68 bytes — the composite leaf key (§9.2), same
/// fixed-width scheme as `StakeBondKey`.
pub const PALW_LEAF_KEY_SIZE: usize = HASH64_SIZE + size_of::<u32>();

#[derive(Eq, Hash, PartialEq, Debug, Copy, Clone)]
pub struct PalwLeafKey([u8; PALW_LEAF_KEY_SIZE]);

impl PalwLeafKey {
    pub fn new(batch_id: Hash64, leaf_index: u32) -> Self {
        let mut bytes = [0u8; PALW_LEAF_KEY_SIZE];
        bytes[..HASH64_SIZE].copy_from_slice(&batch_id.as_bytes());
        bytes[HASH64_SIZE..].copy_from_slice(&leaf_index.to_le_bytes());
        Self(bytes)
    }
}

impl AsRef<[u8]> for PalwLeafKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PalwLeafKey {
    type Error = &'static str;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != PALW_LEAF_KEY_SIZE {
            return Err("palw-leaf key slice has unexpected length");
        }
        let mut bytes = [0u8; PALW_LEAF_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for PalwLeafKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "palw-leaf:{}", faster_hex::hex_string(&self.0))
    }
}

/// The §18.1 read surface: resolve the overlay state an algo-4 ticket binds to.
pub trait PalwStoreReader {
    fn leaf(&self, batch_id: Hash64, leaf_index: u32) -> Result<Arc<PalwPublicLeafV1>, StoreError>;
    fn batch_manifest(&self, batch_id: Hash64) -> Result<Arc<PalwBatchManifestV1>, StoreError>;
    fn certificate(&self, cert_hash: Hash64) -> Result<Arc<PalwBatchCertificateV1>, StoreError>;
    fn batch_status(&self, batch_id: Hash64) -> Result<PalwBatchStatus, StoreError>;
    fn has_leaf(&self, batch_id: Hash64, leaf_index: u32) -> Result<bool, StoreError>;
}

pub trait PalwStore: PalwStoreReader {
    fn insert_leaf(&self, batch_id: Hash64, leaf_index: u32, leaf: Arc<PalwPublicLeafV1>) -> Result<(), StoreError>;
    fn insert_manifest(&self, batch_id: Hash64, manifest: Arc<PalwBatchManifestV1>) -> Result<(), StoreError>;
    fn insert_certificate(&self, cert_hash: Hash64, cert: Arc<PalwBatchCertificateV1>) -> Result<(), StoreError>;
    fn set_batch_status(&self, batch_id: Hash64, status: PalwBatchStatus) -> Result<(), StoreError>;
}

/// A DB + cache implementation of the PALW overlay stores.
#[derive(Clone)]
pub struct DbPalwStore {
    db: Arc<DB>,
    leaves: CachedDbAccess<PalwLeafKey, Arc<PalwPublicLeafV1>>,
    manifests: CachedDbAccess<Hash64, Arc<PalwBatchManifestV1>, BlockHasher>,
    certificates: CachedDbAccess<Hash64, Arc<PalwBatchCertificateV1>, BlockHasher>,
    batch_status: CachedDbAccess<Hash64, PalwBatchStatus, BlockHasher>,
}

impl DbPalwStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            leaves: CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::PalwLeaf.into()),
            manifests: CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::PalwBatchManifest.into()),
            certificates: CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::PalwCertificate.into()),
            batch_status: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::PalwBatchStatus.into()),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    /// Batch-delete every overlay record for a batch (used by the pruning processor). The leaf keys are
    /// derived from the manifest's `leaf_count`.
    pub fn delete_batch_records(&self, batch: &mut WriteBatch, batch_id: Hash64, leaf_count: u32, cert_hash: Hash64) -> Result<(), StoreError> {
        for i in 0..leaf_count {
            self.leaves.delete(BatchDbWriter::new(batch), PalwLeafKey::new(batch_id, i))?;
        }
        self.manifests.delete(BatchDbWriter::new(batch), batch_id)?;
        self.certificates.delete(BatchDbWriter::new(batch), cert_hash)?;
        self.batch_status.delete(BatchDbWriter::new(batch), batch_id)?;
        Ok(())
    }
}

impl PalwStoreReader for DbPalwStore {
    fn leaf(&self, batch_id: Hash64, leaf_index: u32) -> Result<Arc<PalwPublicLeafV1>, StoreError> {
        self.leaves.read(PalwLeafKey::new(batch_id, leaf_index))
    }

    fn batch_manifest(&self, batch_id: Hash64) -> Result<Arc<PalwBatchManifestV1>, StoreError> {
        self.manifests.read(batch_id)
    }

    fn certificate(&self, cert_hash: Hash64) -> Result<Arc<PalwBatchCertificateV1>, StoreError> {
        self.certificates.read(cert_hash)
    }

    fn batch_status(&self, batch_id: Hash64) -> Result<PalwBatchStatus, StoreError> {
        self.batch_status.read(batch_id)
    }

    fn has_leaf(&self, batch_id: Hash64, leaf_index: u32) -> Result<bool, StoreError> {
        self.leaves.has(PalwLeafKey::new(batch_id, leaf_index))
    }
}

impl PalwStore for DbPalwStore {
    /// kaspa-pq **ADR-0040 P1-1 (LEAF-01)** — content-addressed, write-once leaf insertion.
    ///
    /// This used to be a plain `write`, i.e. last-writer-wins at `(batch_id, leaf_index)`. That is the
    /// reward-theft path: `palw_work_reward_class` re-reads the CURRENT leaf at coinbase time to pick
    /// `provider_{a,b}_reward_script`, so overwriting an already-accepted leaf with the same key but
    /// different reward scripts re-routes the 77 % worker base to the attacker. Presence of the leaf was
    /// proven at body-validation time; **immutability of its content was not.**
    ///
    /// Semantics: idempotent for identical content, fail-closed for different content. Re-applying the
    /// same overlay effect (reorg replay, chunk re-delivery) must stay legal, so equality is tested on
    /// [`PalwPublicLeafV1::leaf_hash`] rather than rejecting every second write outright.
    ///
    /// Note this is necessary but not sufficient on its own: it pins a leaf once written, while binding
    /// the written set to `manifest.leaf_root` is the separate completeness gate (BIND-01).
    fn insert_leaf(&self, batch_id: Hash64, leaf_index: u32, leaf: Arc<PalwPublicLeafV1>) -> Result<(), StoreError> {
        let key = PalwLeafKey::new(batch_id, leaf_index);
        if let Ok(existing) = self.leaves.read(key) {
            return if existing.leaf_hash() == leaf.leaf_hash() {
                Ok(()) // idempotent re-apply of identical content
            } else {
                Err(StoreError::KeyAlreadyExists(format!(
                    "PALW leaf ({batch_id}, {leaf_index}) is write-once: refusing to replace {} with {}",
                    existing.leaf_hash(),
                    leaf.leaf_hash()
                )))
            };
        }
        self.leaves.write(DirectDbWriter::new(&self.db), key, leaf)
    }

    fn insert_manifest(&self, batch_id: Hash64, manifest: Arc<PalwBatchManifestV1>) -> Result<(), StoreError> {
        self.manifests.write(DirectDbWriter::new(&self.db), batch_id, manifest)
    }

    fn insert_certificate(&self, cert_hash: Hash64, cert: Arc<PalwBatchCertificateV1>) -> Result<(), StoreError> {
        self.certificates.write(DirectDbWriter::new(&self.db), cert_hash, cert)
    }

    fn set_batch_status(&self, batch_id: Hash64, status: PalwBatchStatus) -> Result<(), StoreError> {
        self.batch_status.write(DirectDbWriter::new(&self.db), batch_id, status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec};
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    fn leaf(idx: u32) -> Arc<PalwPublicLeafV1> {
        use kaspa_consensus_core::tx::TransactionOutpoint;
        let spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&[1]));
        Arc::new(PalwPublicLeafV1 {
            version: 1,
            batch_id: h(1),
            leaf_index: idx,
            job_nullifier: h(2),
            ticket_nullifier_commitment: h(3),
            model_profile_id: h(4),
            runtime_class_id: h(5),
            shape_id: 3,
            quantum_count: 2,
            proof_type: 1,
            provider_a_bond: TransactionOutpoint::new(h(6), 0),
            provider_b_bond: TransactionOutpoint::new(h(7), 0),
            provider_a_reward_script: spk.clone(),
            provider_b_reward_script: spk,
            ticket_authority_pk_hash: h(8),
            private_match_commitment: h(9),
            receipt_da_root: h(10),
            registered_epoch: 5,
            activation_epoch: 7,
            expiry_epoch: 13,
            leaf_bond_sompi: 0,
        })
    }

    /// The eligibility-resolution triad (leaf / certificate / batch-status) inserts, reads back, and
    /// (leaf) round-trips under the composite `(batch_id, leaf_index)` key.
    #[test]
    fn overlay_store_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db, CachePolicy::Count(64));

        // leaf keyed by (batch_id, leaf_index) — distinct indices are distinct keys.
        assert!(!store.has_leaf(h(1), 0).unwrap());
        store.insert_leaf(h(1), 0, leaf(0)).unwrap();
        store.insert_leaf(h(1), 1, leaf(1)).unwrap();
        assert!(store.has_leaf(h(1), 0).unwrap());
        assert_eq!(store.leaf(h(1), 0).unwrap().leaf_index, 0);
        assert_eq!(store.leaf(h(1), 1).unwrap().leaf_index, 1);
        assert!(store.leaf(h(1), 2).is_err()); // absent

        // batch status.
        assert!(store.batch_status(h(1)).is_err());
        store.set_batch_status(h(1), PalwBatchStatus::Active).unwrap();
        assert_eq!(store.batch_status(h(1)).unwrap(), PalwBatchStatus::Active);

        // certificate keyed by its hash.
        assert!(store.certificate(h(9)).is_err());
    }

    /// Leaf keys for different batches never collide even at the same leaf index.
    #[test]
    fn leaf_key_is_batch_scoped() {
        let k_a = PalwLeafKey::new(h(1), 5);
        let k_b = PalwLeafKey::new(h(2), 5);
        assert_ne!(k_a.as_ref(), k_b.as_ref());
        assert_eq!(PalwLeafKey::try_from(k_a.as_ref()).unwrap(), k_a);
    }
}
