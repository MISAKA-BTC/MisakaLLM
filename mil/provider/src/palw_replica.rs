//! ADR-0039 Phase 1 — mock deterministic k=2 backend + exact matcher (design §33 step 2, §7–§8).
//!
//! This is the off-chain, GPU-free prototype the design mandates *before* any consensus/CUDA code:
//! a deterministic runtime that produces the eight exact-match commitment fields
//! ([`ReplicaMatchKey`]) for a job, and a k=2 dispatcher that mints a candidate leaf **only** when
//! two independent providers agree byte-for-byte on all eight (design §7.5). It exercises the two
//! invariants that make replication a substitute for a proof:
//!
//! - two honest providers of the **same** runtime class + same job → identical key → match;
//! - a provider in a **different** runtime class (different tier / GPU-arch class) → different
//!   `runtime_class_id` **and** `canonical_gemm_trace_root` → no match (invariant I-9: exact-match
//!   weight is intra-class only);
//! - a provider that computed the **wrong** output → different `output_commitment` → no match.
//!
//! The "inference" here is a deterministic hash, not a model — the real runtime plugs in behind the
//! same `ReplicaMatchKey` interface (`misaka-mil-provider` backend). Weight 0; nothing on-chain.

use kaspa_hashes::{Hash64, blake2b_512_keyed};
use misaka_mil_core::palw::{
    PalwRuntimeProfileV1, ReplicaMatchKey, gemm_trace_root, job_set_commitment, operation_schedule_commitment, output_commitment,
};

/// Mock-only domain separators (NOT consensus domains — this backend never produces on-chain hashes
/// directly; it feeds `misaka-mil-core::palw` commitment helpers).
const MOCK_OUT_DOMAIN: &[u8] = b"palw-mock/output-tokens";
const MOCK_TRACE_DOMAIN: &[u8] = b"palw-mock/gemm-trace";
const MOCK_SCHED_DOMAIN: &[u8] = b"palw-mock/op-schedule";

/// A deterministic PALW runtime for one provider: a pinned [`PalwRuntimeProfileV1`] plus the fixed
/// shape / quantum it serves. Its output is a pure function of the job inputs — two providers with
/// the same profile compute identical keys.
#[derive(Clone, Debug)]
pub struct MockDeterministicRuntime {
    pub profile: PalwRuntimeProfileV1,
    pub shape_id: u16,
    pub quantum_count: u16,
}

impl MockDeterministicRuntime {
    pub fn new(profile: PalwRuntimeProfileV1, shape_id: u16, quantum_count: u16) -> Self {
        Self { profile, shape_id, quantum_count }
    }

    /// Deterministic mock "inference": the output token stream depends only on inputs both honest
    /// providers share — the prompt and the model weights (`model_profile_id`) — so two providers of
    /// the same model produce identical tokens. `token_fault` flips one token to model a provider
    /// that computed the wrong answer for the same input.
    fn output_tokens(&self, prompt: &[u8], model_profile_id: &Hash64, token_fault: bool) -> Vec<u32> {
        let mut seed_in = Vec::with_capacity(prompt.len() + 64);
        seed_in.extend_from_slice(prompt);
        seed_in.extend_from_slice(model_profile_id.as_byte_slice());
        let seed = blake2b_512_keyed(MOCK_OUT_DOMAIN, &seed_in);
        let mut toks: Vec<u32> = seed.as_byte_slice()[..32].chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        if token_fault {
            toks[0] ^= 1; // a single wrong token → different output_commitment
        }
        toks
    }

    fn run_inner(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32], token_fault: bool) -> ReplicaMatchKey {
        let model_profile_id = self.profile.model_profile_id();
        let runtime_class_id = self.profile.runtime_class_id();
        let tokens = self.output_tokens(prompt, &model_profile_id, token_fault);

        // The GEMM trace depends on the exact kernels (runtime_class_id) AND the prompt: a different
        // class produces a different trace even for the same answer.
        let mut trace_in = Vec::with_capacity(prompt.len() + 64);
        trace_in.extend_from_slice(prompt);
        trace_in.extend_from_slice(runtime_class_id.as_byte_slice());
        let trace = blake2b_512_keyed(MOCK_TRACE_DOMAIN, &trace_in);

        // The operation schedule depends on the class and the shape.
        let mut sched_in = Vec::with_capacity(64 + 2);
        sched_in.extend_from_slice(runtime_class_id.as_byte_slice());
        sched_in.extend_from_slice(&self.shape_id.to_le_bytes());
        let sched = blake2b_512_keyed(MOCK_SCHED_DOMAIN, &sched_in);

        ReplicaMatchKey {
            job_set_commitment: job_set_commitment(job_set_descriptor),
            model_profile_id,
            runtime_class_id,
            shape_id: self.shape_id,
            output_commitment: output_commitment(output_salt, &tokens),
            canonical_gemm_trace_root: gemm_trace_root(trace.as_byte_slice()),
            operation_schedule_commitment: operation_schedule_commitment(sched.as_byte_slice()),
            quantum_count: self.quantum_count,
        }
    }

    /// Run the job honestly, producing the exact-match key.
    pub fn run(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32]) -> ReplicaMatchKey {
        self.run_inner(job_set_descriptor, prompt, output_salt, false)
    }

    /// Run with a single-token output fault (test/adversarial helper — models a wrong computation).
    pub fn run_faulty(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32]) -> ReplicaMatchKey {
        self.run_inner(job_set_descriptor, prompt, output_salt, true)
    }
}

/// The outcome of a k=2 replica dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplicaK2Outcome {
    /// Both providers agreed byte-for-byte on all eight fields — a candidate leaf may be minted with
    /// this shared key.
    Matched(ReplicaMatchKey),
    /// The two keys disagreed on at least one field — no DAG ticket is issued (a response may still
    /// be returned to the requester, design §8.1).
    Mismatch,
}

/// Dispatch one job to two providers and mint a candidate iff they exact-match (design §7.5, §8.1).
/// Both providers receive the **same** job-set descriptor, prompt, and output salt (the salt is
/// derived from the shared job secret, §19.3).
pub fn run_replica_k2(a: &ReplicaMatchKey, b: &ReplicaMatchKey) -> ReplicaK2Outcome {
    if a.exact_match(b) { ReplicaK2Outcome::Matched(*a) } else { ReplicaK2Outcome::Mismatch }
}

/// Convenience: run both mock runtimes on the same job and match. Both honest.
pub fn dispatch_k2(
    provider_a: &MockDeterministicRuntime,
    provider_b: &MockDeterministicRuntime,
    job_set_descriptor: &[u8],
    prompt: &[u8],
    output_salt: &[u8; 32],
) -> ReplicaK2Outcome {
    let ka = provider_a.run(job_set_descriptor, prompt, output_salt);
    let kb = provider_b.run(job_set_descriptor, prompt, output_salt);
    run_replica_k2(&ka, &kb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_hashes::Hash64;
    use misaka_mil_core::palw::{PalwSamplingParams, PalwTier};

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    fn profile(tier: PalwTier, arch: u32) -> PalwRuntimeProfileV1 {
        PalwRuntimeProfileV1 {
            version: 1,
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

    const JS: &[u8] = b"job-set-descriptor";
    const PROMPT: &[u8] = b"what is the capital of the moon?";
    const SALT: [u8; 32] = [0x11; 32];

    #[test]
    fn two_honest_same_class_providers_match() {
        // same tier + same arch class = same runtime_class_id; distinct bonds/operators are a
        // consensus concern, the deterministic output is identical.
        let a = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let b = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        assert_eq!(dispatch_k2(&a, &b, JS, PROMPT, &SALT), ReplicaK2Outcome::Matched(a.run(JS, PROMPT, &SALT)));
    }

    #[test]
    fn cross_tier_never_matches() {
        // Standard (4B) vs Quality (9B): different model_profile_id ⇒ different everything (I-9).
        let a = MockDeterministicRuntime::new(profile(PalwTier::Standard, 100), 3, 2);
        let b = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        assert_eq!(dispatch_k2(&a, &b, JS, PROMPT, &SALT), ReplicaK2Outcome::Mismatch);
    }

    #[test]
    fn cross_arch_class_never_matches() {
        // same weights, different GPU-arch class ⇒ same model_profile_id but different
        // runtime_class_id + trace ⇒ no exact match (I-9: cross-class is audit-only, never main work).
        let a = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let b = MockDeterministicRuntime::new(profile(PalwTier::Quality, 200), 3, 2);
        assert_eq!(dispatch_k2(&a, &b, JS, PROMPT, &SALT), ReplicaK2Outcome::Mismatch);
    }

    #[test]
    fn faulty_output_breaks_the_match() {
        let a = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let b = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        // B computes a wrong answer for the same input ⇒ different output_commitment ⇒ mismatch.
        let ka = a.run(JS, PROMPT, &SALT);
        let kb = b.run_faulty(JS, PROMPT, &SALT);
        assert_eq!(run_replica_k2(&ka, &kb), ReplicaK2Outcome::Mismatch);
        // sanity: an honest re-run of B does match.
        assert!(matches!(run_replica_k2(&ka, &b.run(JS, PROMPT, &SALT)), ReplicaK2Outcome::Matched(_)));
    }

    #[test]
    fn different_shape_or_job_set_breaks_the_match() {
        let a = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let b_shape = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 4, 2); // different shape_id
        assert_eq!(dispatch_k2(&a, &b_shape, JS, PROMPT, &SALT), ReplicaK2Outcome::Mismatch);

        // different job-set descriptor ⇒ different job_set_commitment ⇒ mismatch.
        let b = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let ka = a.run(JS, PROMPT, &SALT);
        let kb = b.run(b"other-job-set", PROMPT, &SALT);
        assert_eq!(run_replica_k2(&ka, &kb), ReplicaK2Outcome::Mismatch);
    }

    #[test]
    fn quantum_count_disagreement_breaks_the_match() {
        let a = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let b = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 3); // different quantum
        assert_eq!(dispatch_k2(&a, &b, JS, PROMPT, &SALT), ReplicaK2Outcome::Mismatch);
    }
}
