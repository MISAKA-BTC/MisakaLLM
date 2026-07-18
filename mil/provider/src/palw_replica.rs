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
    DeterministicInferenceOutputV1, PalwOperationCountersV1, PalwRuntimeProfileV1, ReplicaMatchKey, gemm_trace_root,
    operation_schedule_commitment, output_commitment,
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

    fn infer_inner(&self, prompt: &[u8], output_salt: &[u8; 32], token_fault: bool) -> DeterministicInferenceOutputV1 {
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

        DeterministicInferenceOutputV1 {
            output_token_ids: vec![tokens.clone()],
            output_commitment: output_commitment(output_salt, &tokens),
            canonical_gemm_trace_root: gemm_trace_root(trace.as_byte_slice()),
            operation_schedule_commitment: operation_schedule_commitment(sched.as_byte_slice()),
            operation_counters: PalwOperationCountersV1::default(),
            shape_id: self.shape_id,
            quantum_count: self.quantum_count,
        }
    }

    /// The full deterministic output for a job (answer tokens + compute-path commitments) — the honest run.
    pub fn infer(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32]) -> DeterministicInferenceOutputV1 {
        let _ = job_set_descriptor;
        self.infer_inner(prompt, output_salt, false)
    }

    /// Like [`Self::infer`] but with a single-token output fault (test/adversarial helper — models a
    /// provider, or a whole vendor pool, that computed the wrong answer for the same input).
    pub fn infer_faulty(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32]) -> DeterministicInferenceOutputV1 {
        let _ = job_set_descriptor;
        self.infer_inner(prompt, output_salt, true)
    }

    /// Run the job honestly, producing the exact-match key.
    pub fn run(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32]) -> ReplicaMatchKey {
        self.infer_inner(prompt, output_salt, false).match_key(&self.profile, job_set_descriptor)
    }

    /// Run with a single-token output fault (test/adversarial helper — models a wrong computation).
    pub fn run_faulty(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32]) -> ReplicaMatchKey {
        self.infer_inner(prompt, output_salt, true).match_key(&self.profile, job_set_descriptor)
    }
}

/// ADR-0039 §6.4 / §7 — the contract a PALW compute backend must satisfy to be a work source: a
/// **verifiable, deterministic** runtime that, bound to one [`PalwRuntimeProfileV1`], turns a job into
/// the eight-field [`ReplicaMatchKey`]. Determinism + exact-match (I-9) is what lets replication stand
/// in for a proof: two honest backends of the SAME `runtime_class_id` on the SAME job MUST return
/// byte-identical keys, and any deviation (wrong output, different arch class, different shape/quantum)
/// changes the key so the k=2 dispatch mismatches and no leaf is minted.
///
/// [`MockDeterministicRuntime`] is the GPU-free CPU **reference** implementation (design §33 step 2).
/// The real `MISAKA-QW4-PALW-v1` / `MISAKA-QW9-PALW-v1` Qwen GPU adapter (batch-invariant deterministic
/// CUDA kernels) is the activation implementation of this same trait — it plugs in behind this exact
/// interface, so nothing downstream (the k2 dispatcher, the on-chain leaf, the audit) changes when the
/// real backend replaces the reference. It needs external infrastructure (a GPU + pinned Qwen weights)
/// and is gated on the PALW fence; the contract is frozen here first (design §33: freeze before CUDA).
pub trait VerifiableInferenceBackend {
    /// The runtime profile this backend serves (pins model weights, kernels, and GPU-arch class, hence
    /// the `runtime_class_id`). Two backends match only within one profile's `runtime_class_id` (I-9).
    fn profile(&self) -> &PalwRuntimeProfileV1;

    /// Deterministically execute the job and emit the FULL deterministic output (K3): the answer tokens
    /// plus the compute-path commitments (canonical GEMM trace root, operation schedule, counters). MUST
    /// be a pure function of (`profile`, `job_set_descriptor`, `prompt`, `output_salt`) — no wall-clock,
    /// no nondeterministic reduction order — so a second honest backend of the same class reproduces it
    /// byte-for-byte. The differential-determinism harness compares these full outputs to localize the
    /// first diverging field between providers that should have matched.
    fn infer_with_trace(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32]) -> DeterministicInferenceOutputV1;

    /// The eight-field exact-match key — the projection of [`Self::infer_with_trace`] that the k=2
    /// dispatch compares (design §7.5). Default: derive it from the full output; a backend never needs
    /// to override this.
    fn run_verifiable(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32]) -> ReplicaMatchKey {
        self.infer_with_trace(job_set_descriptor, prompt, output_salt).match_key(self.profile(), job_set_descriptor)
    }
}

impl VerifiableInferenceBackend for MockDeterministicRuntime {
    fn profile(&self) -> &PalwRuntimeProfileV1 {
        &self.profile
    }

    fn infer_with_trace(&self, job_set_descriptor: &[u8], prompt: &[u8], output_salt: &[u8; 32]) -> DeterministicInferenceOutputV1 {
        self.infer(job_set_descriptor, prompt, output_salt)
    }
}

/// Dispatch a job to two [`VerifiableInferenceBackend`]s (dynamic — the reference today, a Qwen GPU
/// adapter after activation) and mint a candidate iff they exact-match (design §7.5). The generic
/// entry point the real backend flows through unchanged.
pub fn dispatch_k2_backends(
    provider_a: &dyn VerifiableInferenceBackend,
    provider_b: &dyn VerifiableInferenceBackend,
    job_set_descriptor: &[u8],
    prompt: &[u8],
    output_salt: &[u8; 32],
) -> ReplicaK2Outcome {
    let ka = provider_a.run_verifiable(job_set_descriptor, prompt, output_salt);
    let kb = provider_b.run_verifiable(job_set_descriptor, prompt, output_salt);
    run_replica_k2(&ka, &kb)
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

/// ADR-0039 §19.8 (Option C) — the outcome of a CROSS-VENDOR diverse-replica dispatch: two same-vendor
/// pools each run a within-class raw k=2, then the two pool leaves are cross-checked at token granularity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiverseK2Outcome {
    /// Both same-vendor pools raw-matched internally AND their leaves agree on the token `output_commitment`
    /// across the two vendors. Carries both pools' keys (they share `output_commitment` but differ in
    /// `runtime_class_id` and the class-dependent raw commitments).
    DiverseMatched { pool_a: ReplicaMatchKey, pool_b: ReplicaMatchKey },
    /// A same-vendor pool failed its OWN within-class raw k=2 (a disagreement inside one vendor).
    PoolMismatch { pool_a_matched: bool, pool_b_matched: bool },
    /// Both pools raw-matched internally but the two vendors disagreed on the token answer — the
    /// cross-vendor check that catches a vendor-specific defect / backdoor / collusion.
    CrossVendorMismatch { pool_a: ReplicaMatchKey, pool_b: ReplicaMatchKey },
}

/// ADR-0039 §19.8 (Option C) — dispatch one job to TWO same-vendor pools (e.g. an Apple-Metal pair and an
/// NVIDIA-CUDA pair). Each pool runs a within-class raw k=2 (`exact_match`, the strong path); a leaf is
/// minted only if **both** pools raw-match internally **and** their leaves agree on the token
/// `output_commitment` across the two vendors (`diverse_replica_match`, which also *requires* the two pools
/// to be different `runtime_class_id`). This keeps within-vendor raw strength and adds cross-vendor hardware
/// diversity: a vendor-specific defect must reproduce the same argmax on the OTHER vendor to survive. All
/// four backends receive the same job/prompt/salt.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_diverse_k2(
    pool_a_1: &dyn VerifiableInferenceBackend,
    pool_a_2: &dyn VerifiableInferenceBackend,
    pool_b_1: &dyn VerifiableInferenceBackend,
    pool_b_2: &dyn VerifiableInferenceBackend,
    job_set_descriptor: &[u8],
    prompt: &[u8],
    output_salt: &[u8; 32],
) -> DiverseK2Outcome {
    let a = dispatch_k2_backends(pool_a_1, pool_a_2, job_set_descriptor, prompt, output_salt);
    let b = dispatch_k2_backends(pool_b_1, pool_b_2, job_set_descriptor, prompt, output_salt);
    match (a, b) {
        (ReplicaK2Outcome::Matched(ka), ReplicaK2Outcome::Matched(kb)) => {
            if ka.diverse_replica_match(&kb) {
                DiverseK2Outcome::DiverseMatched { pool_a: ka, pool_b: kb }
            } else {
                DiverseK2Outcome::CrossVendorMismatch { pool_a: ka, pool_b: kb }
            }
        }
        (a, b) => DiverseK2Outcome::PoolMismatch {
            pool_a_matched: matches!(a, ReplicaK2Outcome::Matched(_)),
            pool_b_matched: matches!(b, ReplicaK2Outcome::Matched(_)),
        },
    }
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

    /// §19.8 (Option C) — the CROSS-VENDOR diverse-replica dispatch: two same-vendor pools (Apple arch 100,
    /// NVIDIA arch 200) each raw-match internally, then their pool leaves are cross-checked at token
    /// granularity. This is the participation model: a pair = one Apple pool + one NVIDIA pool.
    #[test]
    fn dispatch_diverse_k2_cross_vendor_token_check() {
        // A backend that flips a token — models a wrong computation, or (when both providers of a pool use
        // it) a shared vendor-specific defect that a same-vendor k=2 alone cannot catch.
        struct FaultyMock(MockDeterministicRuntime);
        impl VerifiableInferenceBackend for FaultyMock {
            fn profile(&self) -> &PalwRuntimeProfileV1 {
                self.0.profile()
            }
            fn infer_with_trace(&self, j: &[u8], p: &[u8], s: &[u8; 32]) -> DeterministicInferenceOutputV1 {
                self.0.infer_faulty(j, p, s)
            }
        }
        // Apple pool (arch 100) + NVIDIA pool (arch 200): SAME model (Quality) + shape, different vendor.
        let a1 = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let a2 = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let n1 = MockDeterministicRuntime::new(profile(PalwTier::Quality, 200), 3, 2);
        let n2 = MockDeterministicRuntime::new(profile(PalwTier::Quality, 200), 3, 2);

        // (1) Honest: both pools raw-match internally AND agree on the token answer across vendors.
        match dispatch_diverse_k2(&a1, &a2, &n1, &n2, JS, PROMPT, &SALT) {
            DiverseK2Outcome::DiverseMatched { pool_a, pool_b } => {
                assert_eq!(pool_a.output_commitment, pool_b.output_commitment, "the two vendors agree on the token answer");
                assert_ne!(pool_a.runtime_class_id, pool_b.runtime_class_id, "the two pools are different vendors");
                assert_ne!(pool_a.canonical_gemm_trace_root, pool_b.canonical_gemm_trace_root, "raw traces differ cross-vendor");
            }
            other => panic!("expected DiverseMatched, got {other:?}"),
        }

        // (2) Within-pool fault: one Apple provider is faulty ⇒ the Apple pool fails its own raw k=2.
        let a_bad = FaultyMock(MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2));
        assert_eq!(
            dispatch_diverse_k2(&a1, &a_bad, &n1, &n2, JS, PROMPT, &SALT),
            DiverseK2Outcome::PoolMismatch { pool_a_matched: false, pool_b_matched: true }
        );

        // (3) Vendor-specific defect: the WHOLE NVIDIA pool is faulty (both providers share the defect) ⇒ it
        // raw-matches INTERNALLY but disagrees with Apple on the token answer ⇒ the cross-vendor check fires
        // (exactly what a same-vendor-only k=2 would have missed).
        let n_bad1 = FaultyMock(MockDeterministicRuntime::new(profile(PalwTier::Quality, 200), 3, 2));
        let n_bad2 = FaultyMock(MockDeterministicRuntime::new(profile(PalwTier::Quality, 200), 3, 2));
        match dispatch_diverse_k2(&a1, &a2, &n_bad1, &n_bad2, JS, PROMPT, &SALT) {
            DiverseK2Outcome::CrossVendorMismatch { pool_a, pool_b } => {
                assert_ne!(pool_a.output_commitment, pool_b.output_commitment, "the cross-vendor check caught the vendor-specific defect");
            }
            other => panic!("expected CrossVendorMismatch, got {other:?}"),
        }
    }

    /// C6 / §22 — END-TO-END construction==validation from the DETERMINISTIC MOCK BACKEND, in-process
    /// (no network): two honest k=2 mock providers exact-match → the shared `ReplicaMatchKey` mints an
    /// on-chain leaf → a ticket built from that leaf via `palw_template_candidate` wins its draw →
    /// `verify_palw_ticket` (the validator's full nine-clause rule) ACCEPTS it. The same determinism the
    /// real CUDA backend must reproduce flows all the way to a valid algo-4 block.
    #[test]
    fn mock_backend_ticket_construction_equals_validation() {
        use kaspa_consensus_core::palw::{
            palw_select_template_ticket, palw_template_candidate, ticket_nullifier_commitment, verify_palw_ticket,
            PalwPublicLeafV1, PalwTicketBinding,
        };
        use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec, TransactionOutpoint};

        // 1) Deterministic k=2 inference: two honest same-class providers exact-match.
        let a = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let b = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let key = match dispatch_k2(&a, &b, JS, PROMPT, &SALT) {
            ReplicaK2Outcome::Matched(k) => k,
            ReplicaK2Outcome::Mismatch => panic!("two honest same-class providers must match"),
        };

        // 2) Mint an on-chain leaf from the shared match key: the match-derived fields come from `key`;
        //    the provider bonds / reward scripts / authority / windows are registration metadata.
        let spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&[1]));
        let (batch_id, leaf_index, epoch) = (h(0x10), 0u32, 5u64);
        let raw_nf = h(0xC0); // the ticket authority's raw nullifier (disclosed only at the header, I-13)
        let leaf = PalwPublicLeafV1 {
            version: 1,
            batch_id,
            leaf_index,
            job_nullifier: h(0x20),
            ticket_nullifier_commitment: ticket_nullifier_commitment(&raw_nf),
            model_profile_id: key.model_profile_id,
            runtime_class_id: key.runtime_class_id,
            shape_id: key.shape_id,
            quantum_count: key.quantum_count,
            proof_type: 1, // ReplicaExactV1
            provider_a_bond: TransactionOutpoint::new(h(6), 0),
            provider_b_bond: TransactionOutpoint::new(h(7), 0),
            provider_a_reward_script: spk.clone(),
            provider_b_reward_script: spk,
            ticket_authority_pk_hash: h(8),
            private_match_commitment: key.canonical_gemm_trace_root, // binds the leaf to THIS exact k=2 GEMM execution
            receipt_da_root: h(10),
            registered_epoch: 3,
            activation_epoch: 4,
            expiry_epoch: 12,
            leaf_bond_sompi: 0,
        };
        let leaf_hash = leaf.leaf_hash();

        // 3) The template builds a candidate from the leaf + resolver facts (lagged R_E, chain_commit, lane
        //    bits) and the validator re-runs the same pure rule. Easy lane target (see the pure c==v test).
        let (net, eligibility_beacon, chain_commit, interval) = (0x9107u32, h(0x77), h(0x88), 600u64);
        let lane_bits = 0x2100ffff_u32;
        let cand = palw_template_candidate(net, &eligibility_beacon, &chain_commit, interval, &batch_id, leaf_index, &leaf_hash, &raw_nf);
        assert_eq!(palw_select_template_ticket(std::slice::from_ref(&cand), lane_bits), Some(0), "the ticket wins its draw");

        let binding = PalwTicketBinding {
            ticket_nullifier_commitment: leaf.ticket_nullifier_commitment,
            proof_type: leaf.proof_type,
            leaf_activation_epoch: leaf.activation_epoch,
            leaf_expiry_epoch: leaf.expiry_epoch,
            target_daa_interval: interval,
        };
        let cert_active = leaf.activation_epoch <= epoch && epoch < leaf.expiry_epoch;
        assert_eq!(
            verify_palw_ticket(
                &raw_nf, leaf.proof_type, &chain_commit, lane_bits, cand.nonce, interval, &cand.eligibility_digest, &binding,
                cert_active, epoch, &chain_commit, lane_bits, true,
            ),
            Ok(()),
            "the algo-4 header a template builds from a mock-backend match passes all nine validator clauses"
        );
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

    /// ADR-0039 §6.4: the [`VerifiableInferenceBackend`] contract the real Qwen GPU adapter will
    /// implement — via a trait object (as the dispatcher sees it) two honest same-class backends still
    /// exact-match and cross-class still mismatches, and `run_verifiable` is deterministic.
    #[test]
    fn verifiable_backend_trait_object_matches_and_is_deterministic() {
        let a = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let b = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let cross = MockDeterministicRuntime::new(profile(PalwTier::Quality, 200), 3, 2);
        let (da, db, dc): (&dyn VerifiableInferenceBackend, &dyn VerifiableInferenceBackend, &dyn VerifiableInferenceBackend) =
            (&a, &b, &cross);
        // profile() exposes the class binding.
        assert_eq!(da.profile().runtime_class_id(), db.profile().runtime_class_id());
        assert_ne!(da.profile().runtime_class_id(), dc.profile().runtime_class_id());
        // Deterministic: two calls on the same backend/job are byte-identical.
        assert!(da.run_verifiable(JS, PROMPT, &SALT).exact_match(&da.run_verifiable(JS, PROMPT, &SALT)));
        // Same-class honest pair matches; cross-arch-class does not (I-9).
        assert!(matches!(dispatch_k2_backends(da, db, JS, PROMPT, &SALT), ReplicaK2Outcome::Matched(_)));
        assert_eq!(dispatch_k2_backends(da, dc, JS, PROMPT, &SALT), ReplicaK2Outcome::Mismatch);
    }
}
