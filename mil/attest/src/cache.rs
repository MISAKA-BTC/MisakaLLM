//! Attestation-verification cache (design §13.3).
//!
//! Quote-chain verification happens once per provider × attestation epoch;
//! afterwards the SDK reuses the cached result keyed by quote hash until it
//! expires. Clock is always an explicit parameter — no hidden `SystemTime`
//! reads — so callers (and tests) own time.

use crate::verify::VerifiedAttestation;
use kaspa_hashes::Hash64;
use std::collections::HashMap;

/// Bounded quote-hash → verification cache with expiry.
pub struct AttestationCache {
    entries: HashMap<Hash64, VerifiedAttestation>,
    max_entries: usize,
}

impl AttestationCache {
    pub fn new(max_entries: usize) -> Self {
        Self { entries: HashMap::new(), max_entries: max_entries.max(1) }
    }

    /// Cache a verification result. When full, expired entries are evicted
    /// first; if still full, the soonest-expiring entry makes way (the least
    /// valuable one to keep).
    pub fn insert(&mut self, verified: VerifiedAttestation, now_ms: u64) {
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&verified.quote_hash) {
            self.entries.retain(|_, v| v.expires_at_ms > now_ms);
            if self.entries.len() >= self.max_entries
                && let Some(soonest) = self.entries.values().min_by_key(|v| v.expires_at_ms).map(|v| v.quote_hash)
            {
                self.entries.remove(&soonest);
            }
        }
        self.entries.insert(verified.quote_hash, verified);
    }

    /// A still-valid cached verification for `quote_hash`, if any.
    pub fn get(&self, quote_hash: &Hash64, now_ms: u64) -> Option<&VerifiedAttestation> {
        self.entries.get(quote_hash).filter(|v| v.expires_at_ms > now_ms)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{Measurements, TeePlatform};

    fn verified(tag: u8, expires_at_ms: u64) -> VerifiedAttestation {
        VerifiedAttestation {
            quote_hash: Hash64::from_bytes([tag; 64]),
            platform: TeePlatform::Dev,
            measurements: Measurements {
                runtime_image_hash: Hash64::from_bytes([1u8; 64]),
                model_manifest_hash: Hash64::from_bytes([2u8; 64]),
            },
            verified_at_ms: 0,
            expires_at_ms,
        }
    }

    #[test]
    fn hit_miss_and_expiry() {
        let mut cache = AttestationCache::new(4);
        cache.insert(verified(1, 1000), 0);
        assert!(cache.get(&Hash64::from_bytes([1u8; 64]), 500).is_some());
        assert!(cache.get(&Hash64::from_bytes([1u8; 64]), 1000).is_none(), "expiry is exclusive");
        assert!(cache.get(&Hash64::from_bytes([2u8; 64]), 0).is_none());
    }

    #[test]
    fn eviction_prefers_expired_then_soonest_expiring() {
        let mut cache = AttestationCache::new(2);
        cache.insert(verified(1, 100), 0);
        cache.insert(verified(2, 10_000), 0);
        // entry 1 is expired at now=500 → evicted to make room
        cache.insert(verified(3, 20_000), 500);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&Hash64::from_bytes([2u8; 64]), 500).is_some());
        assert!(cache.get(&Hash64::from_bytes([3u8; 64]), 500).is_some());
        // nothing expired now → soonest-expiring (entry 2) makes way
        cache.insert(verified(4, 30_000), 500);
        assert!(cache.get(&Hash64::from_bytes([2u8; 64]), 500).is_none());
        assert!(cache.get(&Hash64::from_bytes([4u8; 64]), 500).is_some());
    }
}
