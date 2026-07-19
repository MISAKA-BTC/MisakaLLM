//! ADR-0039 PALW — K0 differential-determinism harness (scope doc
//! `docs/design/palw-deterministic-kernel-scope-v0.1.md`).
//!
//! The primitive the whole deterministic-kernel effort depends on: run the SAME job through N
//! [`VerifiableInferenceBackend`]s and check they produced BYTE-IDENTICAL
//! [`DeterministicInferenceOutputV1`]s. On a match it mints the shared exact-match key; on a divergence
//! it localizes the FIRST differing field (and, for token divergence, the first differing token index),
//! so a determinism failure points at the op/field to fix rather than "the outputs differ".
//!
//! This is the measurement the class-granularity decision (scope §5) and every later phase (K1/K2/K4)
//! gate on. It is testable NOW without a GPU: the deterministic mock backend exercises the honest
//! (all-match) and faulty (localized-divergence) paths. Against real GPU backends it becomes the
//! cross-machine bit-exactness gate.

use crate::palw::{DeterministicInferenceOutputV1, PalwRuntimeProfileV1, ReplicaMatchKey};
use kaspa_hashes::Hash64;

use crate::palw_replica::VerifiableInferenceBackend;

/// The outcome of a differential-determinism check over N replicas of one job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeterministicReport {
    /// Every replica produced a byte-identical output; the shared exact-match key would mint a leaf.
    AllMatch { key: ReplicaMatchKey, replicas: usize },
    /// Replicas `a` and `b` diverged. `field` names the first differing field, compared in
    /// key-significance order; `note` localizes further (e.g. the first differing output-token index).
    Diverged { backend_a: usize, backend_b: usize, field: &'static str, note: String },
    /// Fewer than two replicas — nothing to cross-check.
    Insufficient,
}

impl DeterministicReport {
    pub fn is_all_match(&self) -> bool {
        matches!(self, DeterministicReport::AllMatch { .. })
    }
}

/// Localize the first differing output token between two token-stream sets, or `None` if equal.
fn first_token_divergence(a: &[Vec<u32>], b: &[Vec<u32>]) -> Option<String> {
    if a.len() != b.len() {
        return Some(format!("sequence count differs ({} vs {})", a.len(), b.len()));
    }
    for (s, (sa, sb)) in a.iter().zip(b.iter()).enumerate() {
        if sa.len() != sb.len() {
            return Some(format!("seq {s} length differs ({} vs {})", sa.len(), sb.len()));
        }
        for (t, (ta, tb)) in sa.iter().zip(sb.iter()).enumerate() {
            if ta != tb {
                return Some(format!("seq {s} token {t} differs ({ta} vs {tb})"));
            }
        }
    }
    None
}

/// The first field on which two full outputs differ, compared most-significant-first. Token streams are
/// checked first because a token divergence is the ROOT cause (it forces `output_commitment` to differ
/// too) and is the most actionable — it names the exact decode step that diverged.
fn first_field_divergence(a: &DeterministicInferenceOutputV1, b: &DeterministicInferenceOutputV1) -> Option<(&'static str, String)> {
    if let Some(note) = first_token_divergence(&a.output_token_ids, &b.output_token_ids) {
        return Some(("output_token_ids", note));
    }
    if a.output_commitment != b.output_commitment {
        return Some(("output_commitment", "same tokens but different output_commitment (salt mismatch?)".to_string()));
    }
    if a.canonical_gemm_trace_root != b.canonical_gemm_trace_root {
        return Some((
            "canonical_gemm_trace_root",
            "same answer, different compute path (kernel/reduction/arch divergence)".to_string(),
        ));
    }
    if a.operation_schedule_commitment != b.operation_schedule_commitment {
        return Some(("operation_schedule_commitment", "different operation schedule".to_string()));
    }
    if a.shape_id != b.shape_id {
        return Some(("shape_id", format!("{} vs {}", a.shape_id, b.shape_id)));
    }
    if a.quantum_count != b.quantum_count {
        return Some(("quantum_count", format!("{} vs {}", a.quantum_count, b.quantum_count)));
    }
    if a.operation_counters != b.operation_counters {
        return Some(("operation_counters", "audit counters differ".to_string()));
    }
    None
}

/// Cross-check N already-computed full outputs. Pure — the caller supplies the outputs (so this is
/// testable with hand-built divergences) and the `profile` + `job_set_descriptor` needed to project the
/// shared key on an all-match. Compares replica 0 against 1..N and reports the first divergence found.
pub fn differential_check(
    profile: &PalwRuntimeProfileV1,
    job_set_descriptor: &[u8],
    outputs: &[DeterministicInferenceOutputV1],
) -> DeterministicReport {
    if outputs.len() < 2 {
        return DeterministicReport::Insufficient;
    }
    for (i, out) in outputs.iter().enumerate().skip(1) {
        if let Some((field, note)) = first_field_divergence(&outputs[0], out) {
            return DeterministicReport::Diverged { backend_a: 0, backend_b: i, field, note };
        }
    }
    DeterministicReport::AllMatch { key: outputs[0].match_key(profile, job_set_descriptor), replicas: outputs.len() }
}

/// Run one job through N backends and cross-check. All backends MUST serve the same runtime class
/// (I-9); a class mismatch is reported before the outputs are even compared, because exact-match across
/// classes is never main-DAG work. This is the harness against real backends: same-class replicas that
/// diverge are a determinism bug (or genuine cross-hardware nondeterminism the class must be narrowed to
/// exclude).
pub fn differential_run(
    backends: &[&dyn VerifiableInferenceBackend],
    job_set_descriptor: &[u8],
    prompt: &[u8],
    output_salt: &[u8; 32],
) -> DeterministicReport {
    if backends.len() < 2 {
        return DeterministicReport::Insufficient;
    }
    let class0 = backends[0].profile().runtime_class_id();
    for (i, b) in backends.iter().enumerate().skip(1) {
        if b.profile().runtime_class_id() != class0 {
            return DeterministicReport::Diverged {
                backend_a: 0,
                backend_b: i,
                field: "runtime_class_id",
                note: "backends are not in the same runtime class (cross-class match is audit-only, I-9)".to_string(),
            };
        }
    }
    let outputs: Vec<DeterministicInferenceOutputV1> =
        backends.iter().map(|b| b.infer_with_trace(job_set_descriptor, prompt, output_salt)).collect();
    differential_check(backends[0].profile(), job_set_descriptor, &outputs)
}

// =============================================================================================
// Canonical Compute v1 (A)-2 — the K0 harness REFRAMED: from "measure divergence between replicas" to
// "assert a candidate stack reproduces a COMMITTED golden vector set V_i byte-exact" (class-as-data, §13).
// This is the registration / self-conformance gate AND the §13 promotion pipeline: a codegen/driver/OS
// drift is fail-closed here (NonConforming) and simultaneously a new-set candidate. Reuses the SAME
// divergence localizer as the differential path, so a failure names the op/field to fix.
// =============================================================================================

/// One committed golden conformance vector (§11): job inputs + the expected output a stack in the class
/// MUST reproduce byte-exact. A `V_i` (§13) is a slice of these; generated once by a reference stack,
/// reviewed, committed by hash (the `set_id`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformanceVector {
    pub job_set_descriptor: Vec<u8>,
    pub prompt: Vec<u8>,
    pub output_salt: [u8; 32],
    pub expected: DeterministicInferenceOutputV1,
}

/// The outcome of running a candidate backend against a committed conformance vector set `V_i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConformanceReport {
    /// Reproduced every vector byte-exact ⇒ the stack is IN the class (the §14 self-conformance /
    /// registration gate passes).
    Conforms { vectors: usize },
    /// Diverged on vector `index`; `field`/`note` localize (same significance order as the differential
    /// check). Registration is REFUSED (fail-closed); this candidate stack is a NEW-SET candidate for the
    /// §13 promotion pipeline.
    NonConforming { index: usize, field: &'static str, note: String },
    /// No vectors — a tier with no committed set is non-live (§13/§15); there is nothing to conform to.
    EmptySet,
}

impl ConformanceReport {
    pub fn conforms(&self) -> bool {
        matches!(self, ConformanceReport::Conforms { .. })
    }
}

/// (A)-2 conformance gate — run `backend` on each committed vector and assert byte-exact reproduction of
/// the expected output. Returns `Conforms` iff every vector matches; otherwise the first divergence,
/// localized. This is the decidable class predicate the §14 gate and the §13 promotion pipeline share.
pub fn check_conformance(backend: &dyn VerifiableInferenceBackend, vectors: &[ConformanceVector]) -> ConformanceReport {
    if vectors.is_empty() {
        return ConformanceReport::EmptySet;
    }
    for (index, v) in vectors.iter().enumerate() {
        let got = backend.infer_with_trace(&v.job_set_descriptor, &v.prompt, &v.output_salt);
        if let Some((field, note)) = first_field_divergence(&v.expected, &got) {
            return ConformanceReport::NonConforming { index, field, note };
        }
    }
    ConformanceReport::Conforms { vectors: vectors.len() }
}

/// A K0 peak-VRAM measurement for one fixed shape (§9 shape table). The participation floor of a class is
/// a function of the shape table + KV quantization, NOT the model alone (§15), so K0 records peak VRAM per
/// fixed shape to decide which SKU VRAM budgets a class admits. On a GPU this is read from the device; the
/// value is `MEASURED-AT-K0` (no local GPU — a stub exercises the plumbing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShapeVramMeasurement {
    pub shape_id: u16,
    pub peak_vram_bytes: u64,
}

/// The VRAM participation floor of a class = the max peak over its admitted fixed shapes (0 for none). A
/// SKU is admissible to the class iff its VRAM budget covers this floor. Pure — the measurements come from
/// K0 on a fleet; this decides, e.g., whether a 12 GB-class SKU can serve the QW9 shape set (§15).
pub fn palw_class_vram_floor_bytes(measurements: &[ShapeVramMeasurement]) -> u64 {
    measurements.iter().map(|m| m.peak_vram_bytes).max().unwrap_or(0)
}

/// A K0 benchmark attestation in `PalwComputeSetRecordV1` shape (Canonical Compute v1 §17.3 / §17.5
/// defense 3): the measured integer `compute_work_scale` + its `evidence_hash`, both `MEASURED-AT-K0` on a
/// fleet. The two fields map 1:1 onto `PalwComputeSetRecordV1.{compute_work_scale,
/// quantum_calibration_evidence}`, so a set-record commit's compute-work value is backed by an attested
/// measurement rather than a bare governance number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenchmarkAttestation {
    pub compute_work_scale: u64,
    pub evidence_hash: Hash64,
}

/// Emit a benchmark attestation from a K0 run — ONLY valid when the conformance gate PASSED: a benchmark
/// for a stack that does not reproduce `V_i` is meaningless (it did not run the pinned compute), so this
/// returns `None` unless `report.conforms()`. Ties `quantum_calibration` to the vector set that backs it.
pub fn attest_benchmark(report: &ConformanceReport, compute_work_scale: u64, evidence_hash: Hash64) -> Option<BenchmarkAttestation> {
    report.conforms().then_some(BenchmarkAttestation { compute_work_scale, evidence_hash })
}

/// Generate a committed conformance vector set `V_i` FROM a reference backend (§11/§13): run each job and
/// capture the expected output. This is how a set's golden vectors are produced — the pinned reference
/// stack runs once, the result is reviewed + committed by hash (the `set_id`). The CPU mock needs no GPU;
/// the real QW9 `V_i` CONTENT is `MEASURED-AT-K0` on the pinned reference (real Qwen weights + GPU).
pub fn generate_conformance_vectors(
    backend: &dyn VerifiableInferenceBackend,
    jobs: &[(Vec<u8>, Vec<u8>, [u8; 32])],
) -> Vec<ConformanceVector> {
    jobs.iter()
        .map(|(js, prompt, salt)| ConformanceVector {
            job_set_descriptor: js.clone(),
            prompt: prompt.clone(),
            output_salt: *salt,
            expected: backend.infer_with_trace(js, prompt, salt),
        })
        .collect()
}

/// §15 (A)-2 — the interface a compute backend implements to report its **peak VRAM per fixed shape** (§9),
/// so K0 can decide which SKU VRAM budgets a class admits (the participation floor is a function of the
/// shape table + KV quant, not the model alone). A CPU / mock backend returns `None` (no device VRAM); a
/// real GPU backend returns the measured peak (`MEASURED-AT-K0`).
pub trait VramProfiled {
    fn peak_vram_bytes(&self, shape_id: u16) -> Option<u64>;
}

/// Collect the peak-VRAM measurements a backend reports over a fixed shape set (§9); shapes it cannot
/// measure (`None`) are omitted. Feed the result to [`palw_class_vram_floor_bytes`] for the SKU-admission
/// decision (§15 participation floor).
pub fn collect_shape_vram(backend: &dyn VramProfiled, shape_ids: &[u16]) -> Vec<ShapeVramMeasurement> {
    shape_ids
        .iter()
        .filter_map(|&shape_id| {
            backend.peak_vram_bytes(shape_id).map(|peak_vram_bytes| ShapeVramMeasurement { shape_id, peak_vram_bytes })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::palw::{PalwRuntimeProfileV1, PalwSamplingParams, PalwTier};
    use crate::palw_replica::MockDeterministicRuntime;
    use kaspa_hashes::Hash64;

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

    /// Two honest same-class replicas → AllMatch, and the minted key equals the direct k=2 run key.
    #[test]
    fn two_honest_replicas_all_match() {
        let a = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let b = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let report = differential_run(&[&a, &b], JS, PROMPT, &SALT);
        match report {
            DeterministicReport::AllMatch { key, replicas } => {
                assert_eq!(replicas, 2);
                assert_eq!(key, a.run(JS, PROMPT, &SALT), "the minted key must equal the honest run key");
            }
            other => panic!("expected AllMatch, got {other:?}"),
        }
    }

    /// A wrong-answer replica → Diverged, localized to the first differing output token.
    #[test]
    fn faulty_replica_diverges_on_output_token() {
        let honest = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let out_ok = honest.infer(JS, PROMPT, &SALT);
        // A single-token fault models a provider that computed the wrong answer.
        let out_bad = {
            let mut o = out_ok.clone();
            o.output_token_ids[0][0] ^= 1;
            o.output_commitment = h(0xEE); // a wrong answer also changes the commitment
            o
        };
        let report = differential_check(honest.profile(), JS, &[out_ok, out_bad]);
        match report {
            DeterministicReport::Diverged { backend_a, backend_b, field, note } => {
                assert_eq!((backend_a, backend_b), (0, 1));
                assert_eq!(field, "output_token_ids");
                assert!(note.contains("token 0"), "should localize the first differing token: {note}");
            }
            other => panic!("expected Diverged, got {other:?}"),
        }
    }

    /// Same answer but a different compute path (trace root) → Diverged on canonical_gemm_trace_root —
    /// this is the shape a genuine cross-hardware reduction divergence takes (right answer, wrong trace).
    #[test]
    fn same_answer_different_trace_diverges_on_trace_root() {
        let honest = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let out_ok = honest.infer(JS, PROMPT, &SALT);
        let out_alt = DeterministicInferenceOutputV1 { canonical_gemm_trace_root: h(0x99), ..out_ok.clone() };
        let report = differential_check(honest.profile(), JS, &[out_ok, out_alt]);
        assert!(matches!(report, DeterministicReport::Diverged { field: "canonical_gemm_trace_root", .. }), "{report:?}");
    }

    /// Cross-class replicas are rejected before output comparison (I-9).
    #[test]
    fn cross_class_replicas_report_class_mismatch() {
        let a = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let cross = MockDeterministicRuntime::new(profile(PalwTier::Quality, 200), 3, 2); // different arch class
        let report = differential_run(&[&a, &cross], JS, PROMPT, &SALT);
        assert!(matches!(report, DeterministicReport::Diverged { field: "runtime_class_id", .. }), "{report:?}");
    }

    #[test]
    fn single_backend_is_insufficient() {
        let a = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        assert_eq!(differential_run(&[&a], JS, PROMPT, &SALT), DeterministicReport::Insufficient);
    }

    // ---- (A)-2: conformance gate (reproduce a committed vector set) ----
    fn committed_vector(backend: &MockDeterministicRuntime, prompt: &[u8], salt: [u8; 32]) -> ConformanceVector {
        ConformanceVector {
            job_set_descriptor: JS.to_vec(),
            prompt: prompt.to_vec(),
            output_salt: salt,
            expected: backend.infer_with_trace(JS, prompt, &salt),
        }
    }

    /// A stack that reproduces the committed vectors byte-exact is IN the class (the §14 gate passes).
    #[test]
    fn conformance_gate_passes_when_backend_reproduces_committed_vectors() {
        let reference = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let v_i = vec![committed_vector(&reference, PROMPT, SALT), committed_vector(&reference, b"second job", [0x22; 32])];
        // Any same-class stack (here the deterministic mock) reproduces the set.
        let candidate = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        assert_eq!(check_conformance(&candidate, &v_i), ConformanceReport::Conforms { vectors: 2 });
    }

    /// Drift is fail-closed AND localized: a candidate that does not reproduce a committed vector is refused
    /// (the §13 promotion pipeline then treats it as a new-set candidate).
    #[test]
    fn conformance_gate_fails_closed_and_localizes_on_drift() {
        let reference = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let mut v_i = vec![committed_vector(&reference, PROMPT, SALT)];
        // Simulate a codegen drift: the committed vector expects a trace root the candidate no longer
        // reproduces (right answer, different compute path).
        v_i[0].expected.canonical_gemm_trace_root = h(0x99);
        let report = check_conformance(&reference, &v_i);
        assert!(matches!(report, ConformanceReport::NonConforming { index: 0, field: "canonical_gemm_trace_root", .. }), "{report:?}");
        assert!(!report.conforms());
    }

    #[test]
    fn conformance_empty_set_is_empty() {
        let reference = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        assert_eq!(check_conformance(&reference, &[]), ConformanceReport::EmptySet);
    }

    /// The V_i generator round-trips: vectors generated FROM a reference backend are reproduced by a
    /// same-class stack (the reference IS in its own class).
    #[test]
    fn generated_vectors_are_reproduced_by_the_reference() {
        let reference = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let jobs = vec![(JS.to_vec(), PROMPT.to_vec(), SALT), (JS.to_vec(), b"second".to_vec(), [0x33; 32])];
        let v_i = generate_conformance_vectors(&reference, &jobs);
        assert_eq!(v_i.len(), 2);
        assert_eq!(check_conformance(&reference, &v_i), ConformanceReport::Conforms { vectors: 2 });
    }

    /// The peak-VRAM interface: a backend's per-shape peaks aggregate to a class floor that decides SKU
    /// admission (§15). A backend that cannot measure a shape (None) is omitted.
    #[test]
    fn peak_vram_interface_drives_the_floor() {
        struct StubGpu; // a GPU-shaped stub; real numbers are MEASURED-AT-K0.
        impl VramProfiled for StubGpu {
            fn peak_vram_bytes(&self, shape_id: u16) -> Option<u64> {
                match shape_id {
                    1 => Some(5_000_000_000),
                    2 => Some(11_500_000_000),
                    _ => None, // an unmeasured / unsupported shape is omitted
                }
            }
        }
        let m = collect_shape_vram(&StubGpu, &[1, 2, 9]);
        assert_eq!(m.len(), 2, "the unmeasured shape 9 is omitted");
        let floor = palw_class_vram_floor_bytes(&m);
        assert_eq!(floor, 11_500_000_000);
        assert!(floor <= 12_000_000_000, "a 12 GB-class SKU is admissible to this class");
        assert!(floor > 8_000_000_000, "an 8 GB SKU is not");
    }

    /// A benchmark attestation is only emitted for a stack that reproduced the vector set (§17.5 defense 3).
    #[test]
    fn benchmark_attestation_requires_conformance() {
        let reference = MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2);
        let v_i = vec![committed_vector(&reference, PROMPT, SALT)];
        let pass = check_conformance(&reference, &v_i);
        assert_eq!(
            attest_benchmark(&pass, 8_000, h(0xEE)),
            Some(BenchmarkAttestation { compute_work_scale: 8_000, evidence_hash: h(0xEE) })
        );
        // A non-conforming stack cannot be attested (no benchmark for a stack that didn't run the compute).
        let fail = ConformanceReport::NonConforming { index: 0, field: "canonical_gemm_trace_root", note: "drift".into() };
        assert_eq!(attest_benchmark(&fail, 8_000, h(0xEE)), None);
        assert_eq!(attest_benchmark(&ConformanceReport::EmptySet, 8_000, h(0xEE)), None);
    }

    /// The class VRAM participation floor is the max peak over its fixed shapes (§15 (A)-2).
    #[test]
    fn vram_floor_is_max_peak_over_shapes() {
        let m = [
            ShapeVramMeasurement { shape_id: 1, peak_vram_bytes: 5_000_000_000 },
            ShapeVramMeasurement { shape_id: 2, peak_vram_bytes: 11_500_000_000 },
        ];
        assert_eq!(palw_class_vram_floor_bytes(&m), 11_500_000_000);
        assert_eq!(palw_class_vram_floor_bytes(&[]), 0);
        // A 12 GB SKU covers the floor; an 8 GB SKU does not (participation-floor decision, §15).
        assert!(palw_class_vram_floor_bytes(&m) <= 12_000_000_000);
        assert!(palw_class_vram_floor_bytes(&m) > 8_000_000_000);
    }
}
