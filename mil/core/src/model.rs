//! Model & Agent-Profile identities and the Model Registry entry (design §7.1,
//! §17, §18.2).
//!
//! `model_id` pins the exact weights; `runtime_image_hash` pins the serving
//! stack. Together with the attestation measurement (§3.2) they give the
//! provenance chain "these weights, on this runtime, produced this receipt"
//! (§17.3). MIL-Core is a single canonical model — differentiation happens in
//! the profile layer, never by forking weights (§18.2).

use crate::domains::{MIL_MODEL_DOMAIN, MIL_PROFILE_DOMAIN, MIL_PROTOCOL_VERSION};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{Hash64, blake2b_512_keyed};

/// Tier bitmask values for [`ModelEntry::tier_allowed`].
pub const TIER_ALLOWED_TEE: u8 = 0b01;
pub const TIER_ALLOWED_OPEN: u8 = 0b10;

/// License flags (§7.2): bit 0 = Llama 3.1 Community License lineage
/// ("Built with Llama" attribution + Notice + naming clause on derivative
/// training). Providers fetch weights from the official source themselves;
/// the registry only pins hashes.
pub const LICENSE_FLAG_LLAMA31_COMMUNITY: u32 = 1 << 0;

/// `model_id = Hash64_k("misaka-mil-v1/model" ‖ weights_manifest)` (§7.1).
///
/// The manifest is the canonical serialized list of weight artifacts (path,
/// size, per-artifact hash) as distributed; any re-quantization or silent
/// weight swap changes the id and breaks attestation.
pub fn model_id(weights_manifest: &[u8]) -> Hash64 {
    blake2b_512_keyed(MIL_MODEL_DOMAIN, weights_manifest)
}

/// `profile_id` over the three profile components (§18.2). The components are
/// variable-length, so each is u64-LE length-prefixed — `("a", "bc")` and
/// `("ab", "c")` must never collide.
pub fn profile_id(system_prompt: &[u8], tool_schema: &[u8], rag_index_manifest: &[u8]) -> Hash64 {
    let mut preimage = Vec::with_capacity(24 + system_prompt.len() + tool_schema.len() + rag_index_manifest.len());
    for part in [system_prompt, tool_schema, rag_index_manifest] {
        preimage.extend_from_slice(&(part.len() as u64).to_le_bytes());
        preimage.extend_from_slice(part);
    }
    blake2b_512_keyed(MIL_PROFILE_DOMAIN, &preimage)
}

/// One Model Registry entry (§7.1). v0 keeps the registry as provider/operator
/// configuration + on-chain anchors; v1 moves it into the `ModelRegistry`
/// EVM-lane contract.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ModelEntry {
    pub version: u16,
    /// [`model_id`] of the weights manifest.
    pub model_id: Hash64,
    /// Per-quantization artifact hashes (safetensors / GGUF …), one entry per
    /// artifact, in manifest order.
    pub artifact_hashes: Vec<Hash64>,
    /// Measured inference-server container image (vLLM / llama.cpp pinned
    /// build, logs off, RAM-only) — must equal the attestation measurement.
    pub runtime_image_hash: Hash64,
    /// Context length served under this entry.
    pub ctx_len: u32,
    /// Bitmask of [`TIER_ALLOWED_TEE`] / [`TIER_ALLOWED_OPEN`].
    pub tier_allowed: u8,
    /// Bitmask of `LICENSE_FLAG_*`.
    pub license_flags: u32,
}

impl ModelEntry {
    pub fn new(
        model_id: Hash64,
        artifact_hashes: Vec<Hash64>,
        runtime_image_hash: Hash64,
        ctx_len: u32,
        tier_allowed: u8,
        license_flags: u32,
    ) -> Self {
        Self { version: MIL_PROTOCOL_VERSION, model_id, artifact_hashes, runtime_image_hash, ctx_len, tier_allowed, license_flags }
    }

    pub fn allows_tee(&self) -> bool {
        self.tier_allowed & TIER_ALLOWED_TEE != 0
    }

    pub fn allows_open(&self) -> bool {
        self.tier_allowed & TIER_ALLOWED_OPEN != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_id_pins_manifest_bytes() {
        let a = model_id(b"dolphin-3.0-llama3.1-8b/{f16,q8_0,q4_k_m}");
        assert_eq!(a, model_id(b"dolphin-3.0-llama3.1-8b/{f16,q8_0,q4_k_m}"));
        assert_ne!(a, model_id(b"dolphin-3.0-llama3.1-8b/{f16,q8_0,q4_k_M}"));
    }

    #[test]
    fn profile_id_length_prefixing_prevents_boundary_shifts() {
        // ("a","bc") vs ("ab","c") — identical concatenation, distinct ids
        assert_ne!(profile_id(b"a", b"bc", b""), profile_id(b"ab", b"c", b""));
        assert_ne!(profile_id(b"", b"x", b""), profile_id(b"x", b"", b""));
        assert_eq!(profile_id(b"p", b"t", b"r"), profile_id(b"p", b"t", b"r"));
    }

    #[test]
    fn model_entry_borsh_roundtrip_and_tiers() {
        let entry = ModelEntry::new(
            model_id(b"m"),
            vec![Hash64::from_bytes([1u8; 64])],
            Hash64::from_bytes([2u8; 64]),
            131_072,
            TIER_ALLOWED_TEE | TIER_ALLOWED_OPEN,
            LICENSE_FLAG_LLAMA31_COMMUNITY,
        );
        let bytes = borsh::to_vec(&entry).unwrap();
        let back = ModelEntry::try_from_slice(&bytes).unwrap();
        assert_eq!(entry, back);
        assert!(back.allows_tee() && back.allows_open());
    }
}
