//! ADR-0039 PALW Replica-GEMM — provider-side deterministic-runtime identity (design §6, §7, §21).
//!
//! The **two runtime tiers** that widen the participation base, and the exact-match commitment
//! helpers a provider computes off-chain. Nothing here touches consensus; it pins the identities the
//! k=2 replica match compares (design §7.5): `model_profile_id`, `runtime_class_id`, `shape_id`,
//! `job_set_commitment`, `output_commitment`, `canonical_gemm_trace_root`,
//! `operation_schedule_commitment`. A candidate leaf is minted only when two independent providers
//! agree on all of these — but **exact-match weight is granted only within one `runtime_class_id`**
//! (invariant I-9): a `PALW Standard` (4B) leaf pairs with a Standard leaf, a `PALW Quality` (9B)
//! leaf with a Quality leaf, never cross-tier.
//!
//! Consensus pins the exact **manifest hash**, never the human model name; the tier `project_name`s
//! here (`MISAKA-QW4/QW9-PALW-v1`) are the fixed project forks, turned into a stable id by a keyed
//! hash so an ambiguous common name is never used as a wire identity.

use crate::domains::{
    MIL_PALW_GEMM_TRACE_DOMAIN, MIL_PALW_JOBSET_DOMAIN, MIL_PALW_OP_SCHEDULE_DOMAIN, MIL_PALW_OUTPUT_DOMAIN, MIL_PALW_PROFILE_DOMAIN,
    MIL_PALW_RUNTIME_CLASS_DOMAIN, MIL_PALW_SHAPE_DOMAIN, MIL_PALW_TIER_MODEL_DOMAIN, MIL_PROTOCOL_VERSION,
};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{HASH64_SIZE, Hash64, blake2b_512_keyed};

// =============================================================================================
// The two participation tiers (design §6.1, ADR-0039 D8).
// =============================================================================================

/// The fixed project fork name of the **Standard** tier — Qwen3.5-4B Q4, RAM ≥ 8 GB, VPS / node
/// co-location / broad participation.
pub const PALW_TIER_STANDARD_NAME: &[u8] = b"MISAKA-QW4-PALW-v1";
/// The fixed project fork name of the **Quality** tier — Qwen3.5-9B Q4, RAM ≥ 16 GB, standard useful
/// inference.
pub const PALW_TIER_QUALITY_NAME: &[u8] = b"MISAKA-QW9-PALW-v1";

/// A PALW runtime tier. Two tiers today; the enum is the taxonomy the match/quota logic keys on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum PalwTier {
    /// `MISAKA-QW4-PALW-v1` — Qwen3.5-4B Q4, RAM ≥ 8 GB.
    Standard,
    /// `MISAKA-QW9-PALW-v1` — Qwen3.5-9B Q4, RAM ≥ 16 GB.
    Quality,
}

impl PalwTier {
    /// The fixed project fork name pinned on-chain.
    pub const fn project_name(self) -> &'static [u8] {
        match self {
            PalwTier::Standard => PALW_TIER_STANDARD_NAME,
            PalwTier::Quality => PALW_TIER_QUALITY_NAME,
        }
    }

    /// Minimum provider RAM (GiB) — the participation-widening lever. Advisory (providers self-select
    /// by capacity), not a consensus check.
    pub const fn ram_floor_gib(self) -> u32 {
        match self {
            PalwTier::Standard => 8,
            PalwTier::Quality => 16,
        }
    }

    /// The source model label (documentation / provider tooling).
    pub const fn source_model(self) -> &'static str {
        match self {
            PalwTier::Standard => "Qwen3.5-4B",
            PalwTier::Quality => "Qwen3.5-9B",
        }
    }

    /// `tier_model_id = Hash64_k(tier-model, project_name)` — the stable id for the pinned fork name.
    pub fn model_id(self) -> Hash64 {
        blake2b_512_keyed(MIL_PALW_TIER_MODEL_DOMAIN, self.project_name())
    }
}

// =============================================================================================
// Runtime profile (design §6.2). The pinned deterministic runtime; a change to any field changes
// `runtime_class_id`, so a differently-built runtime can never exact-match.
// =============================================================================================

/// Minimal sampling parameters. v0.2 requires greedy decode (`temperature_milli == 0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwSamplingParams {
    /// True = greedy / argmax (required in v0.2).
    pub greedy: bool,
    /// Temperature × 1000, integer-pinned. 0 for greedy.
    pub temperature_milli: u32,
}

impl PalwSamplingParams {
    pub const fn greedy() -> Self {
        Self { greedy: true, temperature_milli: 0 }
    }
}

/// The pinned deterministic runtime for one tier (design §6.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwRuntimeProfileV1 {
    pub version: u16,
    pub tier: PalwTier,
    /// [`PalwTier::model_id`] of the tier fork, or a manifest-derived id.
    pub model_id: Hash64,
    pub tokenizer_hash: Hash64,
    pub quantization_manifest_hash: Hash64,
    pub runtime_image_hash: Hash64,
    pub kernel_graph_hash: Hash64,
    pub operation_table_hash: Hash64,
    pub shape_table_hash: Hash64,
    pub gpu_arch_class: u32,
    pub tensor_parallel_degree: u16,
    pub pipeline_parallel_degree: u16,
    pub deterministic_reduction: bool,
    pub batch_invariant: bool,
    pub speculative_decode: bool,
    pub sampling: PalwSamplingParams,
}

impl PalwRuntimeProfileV1 {
    /// `model_profile_id` = keyed hash over the *model* identity (model ‖ tokenizer ‖ quant ‖ shape
    /// table). Independent of the serving stack, so the same weights served two ways share a profile
    /// but differ in [`Self::runtime_class_id`].
    pub fn model_profile_id(&self) -> Hash64 {
        let mut p = Vec::with_capacity(4 * HASH64_SIZE + 2);
        p.extend_from_slice(&self.version.to_le_bytes());
        for h in [&self.model_id, &self.tokenizer_hash, &self.quantization_manifest_hash, &self.shape_table_hash] {
            p.extend_from_slice(h.as_byte_slice());
        }
        blake2b_512_keyed(MIL_PALW_PROFILE_DOMAIN, &p)
    }

    /// `runtime_class_id` = keyed hash binding the model profile to the exact serving stack (runtime
    /// image ‖ kernel graph ‖ operation table ‖ GPU-arch class ‖ TP/PP topology ‖ determinism flags).
    /// Exact-match weight is granted **only within one class** (invariant I-9). A CPU vs GPU vs SKU
    /// difference (different `gpu_arch_class`/`kernel_graph_hash`) is a distinct class.
    pub fn runtime_class_id(&self) -> Hash64 {
        let profile = self.model_profile_id();
        let mut p = Vec::with_capacity(5 * HASH64_SIZE + 16);
        p.extend_from_slice(profile.as_byte_slice());
        for h in [&self.runtime_image_hash, &self.kernel_graph_hash, &self.operation_table_hash] {
            p.extend_from_slice(h.as_byte_slice());
        }
        p.extend_from_slice(&self.gpu_arch_class.to_le_bytes());
        p.extend_from_slice(&self.tensor_parallel_degree.to_le_bytes());
        p.extend_from_slice(&self.pipeline_parallel_degree.to_le_bytes());
        p.push(self.deterministic_reduction as u8);
        p.push(self.batch_invariant as u8);
        p.push(self.speculative_decode as u8);
        p.push(self.sampling.greedy as u8);
        p.extend_from_slice(&self.sampling.temperature_milli.to_le_bytes());
        blake2b_512_keyed(MIL_PALW_RUNTIME_CLASS_DOMAIN, &p)
    }

    /// The v0.2 determinism gate (design §6.2 / §30.2): greedy, batch-invariant, deterministic
    /// reduction, and **no** speculative decoding. A profile that fails this must not be registered
    /// as an exact-match Replica class (the runtime should fail startup, §27.1).
    pub fn is_deterministic_admissible(&self) -> bool {
        self.sampling.greedy && self.sampling.temperature_milli == 0 && self.deterministic_reduction && self.batch_invariant && !self.speculative_decode
    }
}

// =============================================================================================
// Exact-match commitment helpers (the fields the k=2 match compares — design §7.4/§7.5).
// =============================================================================================

/// `shape_id`-binding hash of a fixed tensor shape descriptor (design §6.3). The wire `shape_id` is a
/// small index into the pinned shape table; this binds that index to the exact shape bytes.
pub fn shape_commitment(shape_descriptor: &[u8]) -> Hash64 {
    blake2b_512_keyed(MIL_PALW_SHAPE_DOMAIN, shape_descriptor)
}

/// `job_set_commitment` over the packed micro-batch descriptor (design §8/§21.4).
pub fn job_set_commitment(job_set_descriptor: &[u8]) -> Hash64 {
    blake2b_512_keyed(MIL_PALW_JOBSET_DOMAIN, job_set_descriptor)
}

/// `output_commitment = Hash64_k(output, salt ‖ output_token_ids)` (design §7.4). The salt (derived
/// from the job secret) defeats a known-question dictionary attack (§19.3); it is fixed-width so the
/// preimage is unambiguous.
pub fn output_commitment(salt: &[u8; 32], output_token_ids: &[u32]) -> Hash64 {
    let mut p = Vec::with_capacity(32 + output_token_ids.len() * 4);
    p.extend_from_slice(salt);
    for t in output_token_ids {
        p.extend_from_slice(&t.to_le_bytes());
    }
    blake2b_512_keyed(MIL_PALW_OUTPUT_DOMAIN, &p)
}

/// `canonical_gemm_trace_root` — commitment over the primary GPU GEMM trace (design §7.2/§7.3). Here
/// a keyed hash over the already-serialized canonical trace; the real trace is a Merkle root computed
/// by the provider backend (`misaka-mil-provider`). Binding it (not just the output) is what makes a
/// match evidence of the *computation*, not merely of equal answers.
pub fn gemm_trace_root(canonical_trace: &[u8]) -> Hash64 {
    blake2b_512_keyed(MIL_PALW_GEMM_TRACE_DOMAIN, canonical_trace)
}

/// `operation_schedule_commitment` over the deterministic operation schedule (design §7.2).
pub fn operation_schedule_commitment(schedule: &[u8]) -> Hash64 {
    blake2b_512_keyed(MIL_PALW_OP_SCHEDULE_DOMAIN, schedule)
}

/// The eight exact-match fields two providers must agree on to mint a candidate leaf (design §7.5,
/// §8.1). Equality of a full `ReplicaMatchKey` is the leaf-minting predicate; the k=2 backend
/// produces one per provider and mints only if `a == b`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplicaMatchKey {
    pub job_set_commitment: Hash64,
    pub model_profile_id: Hash64,
    pub runtime_class_id: Hash64,
    pub shape_id: u16,
    pub output_commitment: Hash64,
    pub canonical_gemm_trace_root: Hash64,
    pub operation_schedule_commitment: Hash64,
    pub quantum_count: u16,
}

impl ReplicaMatchKey {
    /// True iff the two providers' keys are byte-identical across all eight fields (design §7.5).
    #[inline]
    pub fn exact_match(&self, other: &ReplicaMatchKey) -> bool {
        self == other
    }
}

// =============================================================================================
// Tests.
// =============================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    fn profile(tier: PalwTier, arch: u32) -> PalwRuntimeProfileV1 {
        PalwRuntimeProfileV1 {
            version: MIL_PROTOCOL_VERSION,
            tier,
            model_id: tier.model_id(),
            tokenizer_hash: h(1),
            quantization_manifest_hash: h(2),
            runtime_image_hash: h(3),
            kernel_graph_hash: h(4),
            operation_table_hash: h(5),
            shape_table_hash: h(6),
            gpu_arch_class: arch,
            tensor_parallel_degree: 1,
            pipeline_parallel_degree: 1,
            deterministic_reduction: true,
            batch_invariant: true,
            speculative_decode: false,
            sampling: PalwSamplingParams::greedy(),
        }
    }

    #[test]
    fn tiers_are_distinct_and_pinned() {
        assert_eq!(PalwTier::Standard.project_name(), b"MISAKA-QW4-PALW-v1");
        assert_eq!(PalwTier::Quality.project_name(), b"MISAKA-QW9-PALW-v1");
        assert_eq!(PalwTier::Standard.ram_floor_gib(), 8);
        assert_eq!(PalwTier::Quality.ram_floor_gib(), 16);
        assert_ne!(PalwTier::Standard.model_id(), PalwTier::Quality.model_id());
    }

    #[test]
    fn cross_tier_never_shares_profile_or_class() {
        let std_p = profile(PalwTier::Standard, 100);
        let qual_p = profile(PalwTier::Quality, 100);
        // different tier ⇒ different model_id ⇒ different model_profile_id ⇒ different runtime_class_id.
        assert_ne!(std_p.model_profile_id(), qual_p.model_profile_id());
        assert_ne!(std_p.runtime_class_id(), qual_p.runtime_class_id());
    }

    #[test]
    fn arch_class_separates_runtime_class_but_not_model_profile() {
        let a = profile(PalwTier::Standard, 100); // e.g. a GPU arch
        let b = profile(PalwTier::Standard, 200); // e.g. a different arch / CPU
        // same weights ⇒ same model profile ...
        assert_eq!(a.model_profile_id(), b.model_profile_id());
        // ... but a different arch class is a DISTINCT runtime class (I-9: no cross-class exact match).
        assert_ne!(a.runtime_class_id(), b.runtime_class_id());
    }

    #[test]
    fn determinism_gate() {
        let mut p = profile(PalwTier::Quality, 1);
        assert!(p.is_deterministic_admissible());
        p.speculative_decode = true;
        assert!(!p.is_deterministic_admissible());
        let mut p2 = profile(PalwTier::Quality, 1);
        p2.sampling = PalwSamplingParams { greedy: false, temperature_milli: 700 };
        assert!(!p2.is_deterministic_admissible());
        let mut p3 = profile(PalwTier::Quality, 1);
        p3.batch_invariant = false;
        assert!(!p3.is_deterministic_admissible());
    }

    #[test]
    fn commitment_helpers_are_domain_separated_and_salted() {
        // distinct domains → distinct digests for the same bytes.
        let x = b"same-bytes";
        assert_ne!(shape_commitment(x), job_set_commitment(x));
        assert_ne!(gemm_trace_root(x), operation_schedule_commitment(x));
        assert_ne!(shape_commitment(x), gemm_trace_root(x));

        // output_commitment is salted: same tokens, different salt ⇒ different commitment.
        let toks = [1u32, 2, 3, 4];
        assert_ne!(output_commitment(&[0u8; 32], &toks), output_commitment(&[1u8; 32], &toks));
        assert_eq!(output_commitment(&[7u8; 32], &toks), output_commitment(&[7u8; 32], &toks));
        // sensitive to the token stream.
        assert_ne!(output_commitment(&[7u8; 32], &toks), output_commitment(&[7u8; 32], &[1, 2, 3, 5]));
    }

    #[test]
    fn exact_match_key_is_all_or_nothing() {
        let p = profile(PalwTier::Standard, 100);
        let base = ReplicaMatchKey {
            job_set_commitment: job_set_commitment(b"js"),
            model_profile_id: p.model_profile_id(),
            runtime_class_id: p.runtime_class_id(),
            shape_id: 3,
            output_commitment: output_commitment(&[9u8; 32], &[1, 2, 3]),
            canonical_gemm_trace_root: gemm_trace_root(b"trace"),
            operation_schedule_commitment: operation_schedule_commitment(b"sched"),
            quantum_count: 2,
        };
        let same = base;
        assert!(base.exact_match(&same));
        // any single-field disagreement fails the match.
        let mut diff_trace = base;
        diff_trace.canonical_gemm_trace_root = gemm_trace_root(b"trace2");
        assert!(!base.exact_match(&diff_trace));
        let mut diff_shape = base;
        diff_shape.shape_id = 4;
        assert!(!base.exact_match(&diff_shape));
    }

    #[test]
    fn runtime_profile_borsh_roundtrip() {
        let p = profile(PalwTier::Quality, 42);
        let back = PalwRuntimeProfileV1::try_from_slice(&borsh::to_vec(&p).unwrap()).unwrap();
        assert_eq!(p, back);
    }
}
