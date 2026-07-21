//! Bounded in-memory serving cache for DA-01 receipt objects.
//!
//! Consensus owns semantic object validation and durable storage. The flow cache is deliberately a
//! small content-addressed availability seam: it rechecks the committed root, keeps a hard byte and
//! object bound, and derives every response proof from consensus-core.

use indexmap::IndexMap;
use kaspa_consensus_core::palw::da::{
    PALW_RECEIPT_DA_OBJECT_VERSION_V2, PalwDaAdmissionError, PalwDaError, palw_receipt_da_chunk_proof, palw_receipt_da_commitment,
};
use kaspa_hashes::Hash64;
use kaspa_p2p_lib::{palw_da::palw_da_chunk_message, pb::PalwDaChunkMessage};
use std::sync::Arc;
use thiserror::Error;

/// Enough for active production while ensuring an attacker cannot turn the sidecar into an
/// unbounded object store. Durable retention belongs to the consensus DA store/operator tooling.
pub const PALW_DA_FLOW_CACHE_MAX_OBJECTS: usize = 64;
pub const PALW_DA_FLOW_CACHE_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PalwDaObjectCacheError {
    #[error(transparent)]
    InvalidObject(#[from] PalwDaError),
    #[error("PALW DA object bytes do not match the advertised root")]
    RootMismatch,
    #[error("PALW DA object root collision in the serving cache")]
    RootCollision,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PalwDaObjectPublishError {
    #[error(transparent)]
    Admission(#[from] PalwDaAdmissionError),
    #[error(transparent)]
    Cache(#[from] PalwDaObjectCacheError),
}

#[derive(Debug, Default)]
pub(crate) struct PalwDaObjectCache {
    objects: IndexMap<Hash64, PalwDaCachedObject>,
    total_bytes: usize,
}

#[derive(Debug)]
struct PalwDaCachedObject {
    version: u16,
    bytes: Arc<Vec<u8>>,
}

impl PalwDaObjectCache {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    #[cfg(test)]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    fn validated_entry(root: Hash64, bytes: Arc<Vec<u8>>) -> Result<PalwDaCachedObject, PalwDaObjectCacheError> {
        // Every canonical PALW DA object starts with its little-endian object version. Retain that
        // authenticated framing value with the cache entry so V1 and V2 proofs cannot be silently
        // regenerated under a caller-selected or legacy-hardcoded domain.
        let version =
            bytes.get(..2).and_then(|prefix| prefix.try_into().ok()).map(u16::from_le_bytes).ok_or(PalwDaError::NonCanonicalObject)?;
        if version != PALW_RECEIPT_DA_OBJECT_VERSION_V2 {
            return Err(PalwDaError::UnsupportedVersion(version).into());
        }
        let commitment = palw_receipt_da_commitment(version, &bytes)?;
        if commitment.root != root {
            return Err(PalwDaObjectCacheError::RootMismatch);
        }
        Ok(PalwDaCachedObject { version, bytes })
    }

    pub(crate) fn validate_v2(root: Hash64, bytes: Arc<Vec<u8>>) -> Result<(), PalwDaObjectCacheError> {
        Self::validated_entry(root, bytes).map(drop)
    }

    pub(crate) fn insert(&mut self, root: Hash64, bytes: Arc<Vec<u8>>) -> Result<(), PalwDaObjectCacheError> {
        let candidate = Self::validated_entry(root, bytes)?;
        if let Some(existing) = self.objects.get(&root) {
            if existing.version == candidate.version && *existing.bytes == *candidate.bytes {
                return Ok(());
            }
            return Err(PalwDaObjectCacheError::RootCollision);
        }

        while self.objects.len() >= PALW_DA_FLOW_CACHE_MAX_OBJECTS
            || self.total_bytes.saturating_add(candidate.bytes.len()) > PALW_DA_FLOW_CACHE_MAX_BYTES
        {
            let Some((_, evicted)) = self.objects.shift_remove_index(0) else {
                break;
            };
            self.total_bytes -= evicted.bytes.len();
        }
        self.total_bytes += candidate.bytes.len();
        self.objects.insert(root, candidate);
        Ok(())
    }

    /// Rebuild the entire serving set before swapping it into place. This gives restart/reorg refresh
    /// all-or-nothing in-memory semantics: malformed input neither becomes visible nor leaves a
    /// partially refreshed mix of old-fork and new-fork roots.
    pub(crate) fn replace(&mut self, objects: impl IntoIterator<Item = (Hash64, Arc<Vec<u8>>)>) -> Result<(), PalwDaObjectCacheError> {
        let mut replacement = Self::default();
        for (root, bytes) in objects {
            replacement.insert(root, bytes)?;
        }
        *self = replacement;
        Ok(())
    }

    pub(crate) fn chunk(&self, root: &Hash64, chunk_index: u16) -> Result<Option<PalwDaChunkMessage>, PalwDaObjectCacheError> {
        let Some(object) = self.objects.get(root) else {
            return Ok(None);
        };
        let proof = palw_receipt_da_chunk_proof(object.version, &object.bytes, chunk_index)?;
        Ok(Some(palw_da_chunk_message(*root, &proof)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::palw::da::{PALW_RECEIPT_DA_OBJECT_VERSION_V1, PALW_RECEIPT_DA_OBJECT_VERSION_V2};

    fn object(version: u16, byte: u8, len: usize) -> (Hash64, Arc<Vec<u8>>) {
        assert!(len >= 2);
        let bytes = Arc::new(vec![byte; len]);
        let mut bytes = Arc::unwrap_or_clone(bytes);
        bytes[..2].copy_from_slice(&version.to_le_bytes());
        let bytes = Arc::new(bytes);
        let root = palw_receipt_da_commitment(version, &bytes).unwrap().root;
        (root, bytes)
    }

    #[test]
    fn cache_is_content_addressed_bounded_and_v2_proof_serving() {
        let mut cache = PalwDaObjectCache::default();
        let (root, bytes) = object(PALW_RECEIPT_DA_OBJECT_VERSION_V2, 7, 40_000);
        cache.insert(root, bytes.clone()).unwrap();
        cache.insert(root, bytes).unwrap();
        assert_eq!(cache.len(), 1);
        let response = cache.chunk(&root, 1).unwrap().unwrap();
        assert_eq!(response.chunk_index, 1);
        assert_eq!(response.object_version, u32::from(PALW_RECEIPT_DA_OBJECT_VERSION_V2));

        let (wrong_root, _) = object(PALW_RECEIPT_DA_OBJECT_VERSION_V2, 8, 40_000);
        let (_, wrong_bytes) = object(PALW_RECEIPT_DA_OBJECT_VERSION_V2, 9, 40_000);
        assert_eq!(cache.insert(wrong_root, wrong_bytes), Err(PalwDaObjectCacheError::RootMismatch));

        for byte in 0..=PALW_DA_FLOW_CACHE_MAX_OBJECTS as u8 {
            // Keep one payload byte after the two-byte version prefix so each object is distinct.
            let (next_root, next_bytes) = object(PALW_RECEIPT_DA_OBJECT_VERSION_V2, byte, 3);
            cache.insert(next_root, next_bytes).unwrap();
        }
        assert!(cache.len() <= PALW_DA_FLOW_CACHE_MAX_OBJECTS);
        assert!(cache.total_bytes() <= PALW_DA_FLOW_CACHE_MAX_BYTES);
        assert!(cache.chunk(&root, 0).unwrap().is_none(), "oldest object is evicted first");
    }

    #[test]
    fn cache_retains_v2_version_for_root_and_chunk_proof_domains() {
        let mut cache = PalwDaObjectCache::default();
        let (root, bytes) = object(PALW_RECEIPT_DA_OBJECT_VERSION_V2, 0x42, 40_000);
        cache.insert(root, bytes).unwrap();

        let response = cache.chunk(&root, 1).unwrap().expect("cached V2 object");
        assert_eq!(response.object_version, u32::from(PALW_RECEIPT_DA_OBJECT_VERSION_V2));
        assert_eq!(Hash64::from_bytes(response.object_root.unwrap().bytes.as_slice().try_into().unwrap()), root);
    }

    #[test]
    fn cache_rejects_missing_or_unsupported_canonical_version_prefix() {
        let mut cache = PalwDaObjectCache::default();
        assert!(matches!(
            cache.insert(Hash64::default(), Arc::new(vec![0])),
            Err(PalwDaObjectCacheError::InvalidObject(PalwDaError::NonCanonicalObject))
        ));
        assert!(matches!(
            cache.insert(Hash64::default(), Arc::new(vec![0xff, 0xff])),
            Err(PalwDaObjectCacheError::InvalidObject(PalwDaError::UnsupportedVersion(u16::MAX)))
        ));
        let (legacy_root, legacy) = object(PALW_RECEIPT_DA_OBJECT_VERSION_V1, 1, 3);
        assert!(matches!(
            cache.insert(legacy_root, legacy),
            Err(PalwDaObjectCacheError::InvalidObject(PalwDaError::UnsupportedVersion(PALW_RECEIPT_DA_OBJECT_VERSION_V1)))
        ));
    }

    #[test]
    fn atomic_replace_removes_reorged_roots_and_preserves_old_set_on_invalid_input() {
        let mut cache = PalwDaObjectCache::default();
        let (old_root, old_bytes) = object(PALW_RECEIPT_DA_OBJECT_VERSION_V2, 0x11, 3);
        let (new_root, new_bytes) = object(PALW_RECEIPT_DA_OBJECT_VERSION_V2, 0x22, 3);
        cache.insert(old_root, old_bytes).unwrap();

        cache.replace([(new_root, new_bytes)]).unwrap();
        assert!(cache.chunk(&old_root, 0).unwrap().is_none());
        assert!(cache.chunk(&new_root, 0).unwrap().is_some());

        let invalid = Arc::new(vec![0xff, 0xff]);
        assert!(cache.replace([(Hash64::default(), invalid)]).is_err());
        assert!(cache.chunk(&new_root, 0).unwrap().is_some(), "failed refresh is atomic");
    }
}
