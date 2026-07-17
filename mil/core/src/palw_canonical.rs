//! ADR-0039 Canonical Compute v1 §3–§10 / §15 Level 3 — the platform-independent INTEGER reference
//! (`docs/design/misaka-canonical-compute-v1.md`).
//!
//! This is two things at once:
//!   * **the K1 oracle** — a GPU integer kernel is *conformant* iff it reproduces this reference
//!     bit-for-bit (so conformance vectors for the integer tier are generated FROM this, no GPU needed);
//!   * **the Level-3 arithmetic core** — the integer path's canonical arithmetic.
//!
//! The load-bearing property: **integer addition is associative**, so this reference is
//! REDUCTION-ORDER-INDEPENDENT. That is *exactly* why the integer tier collapses to one determinism class
//! across all hardware (the endgame, §15 Level 3) and is immune to compiler/driver codegen drift (§17.5 /
//! R3): a CPU, an NVIDIA kernel and an Apple kernel that all follow the fixed schedule produce identical
//! bits **regardless of how each orders its reduction**. This module PROVES that with running code — no
//! GPU, no floats. (The float path, by contrast, needs the schedule pinned precisely because fp addition
//! is *not* associative; the tests below demonstrate that contrast.)
//!
//! What still needs the fleet (not here): the real GPU kernels that must MATCH this reference, and real
//! model weights to turn these primitives into a full Qwen forward pass. This module is the canonical
//! answer those are checked against.

use crate::domains::MIL_PALW_GEMM_TRACE_DOMAIN;
use kaspa_hashes::{Hash64, blake2b_512_keyed};

/// §3 — the canonical GEMM schedule: fixed tile dims + split-K factor, a pure function of (op, shape),
/// never of SM count / batch size / runtime dispatch. The reduction tree is DERIVED from these, so every
/// stack reduces in the same order. (Integer arithmetic makes the *order* irrelevant to the result; the
/// schedule is still fixed so the float tier and the trace commitments are reproducible.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalGemmSchedule {
    pub m_tile: u16,
    pub n_tile: u16,
    pub k_tile: u16,
    pub k_split: u16,
}

impl CanonicalGemmSchedule {
    /// A schedule is valid iff every tile dim and the split factor are non-zero (a zero tile has no
    /// canonical reduction). Shape-vs-tile divisibility is the caller's fixed shape-table concern (§9).
    pub fn is_valid(&self) -> bool {
        self.m_tile != 0 && self.n_tile != 0 && self.k_tile != 0 && self.k_split != 0
    }
}

/// The canonical integer GEMM reference (§4): `C[m,n] = Σ_k A[m,k]·B[k,n]`, int8×int8 → **i32** accumulate
/// in the spec-fixed ascending-k order, row-major. For the pinned shapes (`head_dim`/`d_model` ≤ 4096) the
/// worst-case magnitude `K·127²` stays inside i32 (§10 QW9 budget), so a single GEMM needs no split; the
/// `sched` records the canonical tiling the GPU kernel must also follow. Panics only on a shape/length
/// mismatch (a caller bug), never on overflow within the pinned budget.
pub fn canonical_int_gemm(a: &[i8], b: &[i8], m: usize, k: usize, n: usize) -> Vec<i32> {
    assert_eq!(a.len(), m * k, "A must be m×k");
    assert_eq!(b.len(), k * n, "B must be k×n");
    let mut c = vec![0i32; m * n];
    for i in 0..m {
        for j in 0..n {
            // Ascending-k accumulation (the spec-fixed order). Integer ⇒ any order gives the same result;
            // the fixed order pins the trace + keeps the float tier reproducible.
            let mut acc: i32 = 0;
            for p in 0..k {
                acc += a[i * k + p] as i32 * b[p * n + j] as i32;
            }
            c[i * n + j] = acc;
        }
    }
    c
}

/// §10 — the long-context integer reduction discipline (the softmax·V case): sum `vals` in spec-fixed
/// `block`-sized chunks, each chunk accumulated in **i64**, then the chunk partials in i64. The fixed
/// boundary keeps every partial within budget while the i64 total holds the 32k-context worst case
/// (≈1e11 ≪ i64). Order-independent by integer associativity; `overflow` never occurs (i64 headroom),
/// unlike a saturating reduce which would be order-dependent and is FORBIDDEN (§10).
pub fn hierarchical_int_reduce(vals: &[i64], block: usize) -> i64 {
    let block = block.max(1);
    let mut total: i64 = 0;
    for chunk in vals.chunks(block) {
        let mut partial: i64 = 0;
        for &v in chunk {
            partial += v; // within-block, bounded by the §10 budget (block × per-element ≤ i64)
        }
        total += partial;
    }
    total
}

/// A canonical GEMM trace commitment over the fixed schedule + the integer output — the model-opaque
/// `canonical_gemm_trace_root`-shaped digest a leaf/receipt carries. Because the reference is
/// order-independent, this digest is identical on every conformant stack for the same inputs.
pub fn canonical_gemm_trace(sched: &CanonicalGemmSchedule, c: &[i32]) -> Hash64 {
    let mut p = Vec::with_capacity(8 + c.len() * 4);
    p.extend_from_slice(&sched.m_tile.to_le_bytes());
    p.extend_from_slice(&sched.n_tile.to_le_bytes());
    p.extend_from_slice(&sched.k_tile.to_le_bytes());
    p.extend_from_slice(&sched.k_split.to_le_bytes());
    for &x in c {
        p.extend_from_slice(&x.to_le_bytes());
    }
    blake2b_512_keyed(MIL_PALW_GEMM_TRACE_DOMAIN, &p)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small deterministic pseudo-fill (no RNG — const closed form) so tests are reproducible.
    fn fill(n: usize, seed: i32) -> Vec<i8> {
        (0..n).map(|i| (((i as i32 * 31 + seed * 17) % 251) - 125) as i8).collect()
    }

    /// The reference is deterministic: same inputs ⇒ same output + same trace.
    #[test]
    fn canonical_int_gemm_is_deterministic() {
        let (m, k, n) = (4, 8, 5);
        let (a, b) = (fill(m * k, 1), fill(k * n, 2));
        let c1 = canonical_int_gemm(&a, &b, m, k, n);
        let c2 = canonical_int_gemm(&a, &b, m, k, n);
        assert_eq!(c1, c2);
        let sched = CanonicalGemmSchedule { m_tile: 4, n_tile: 5, k_tile: 8, k_split: 1 };
        assert_eq!(canonical_gemm_trace(&sched, &c1), canonical_gemm_trace(&sched, &c2));
    }

    /// THE Level-3 result, in running code: the integer GEMM is REDUCTION-ORDER-INDEPENDENT. Accumulating
    /// k ascending (the reference) and descending (a different-but-valid stack's order) yields BIT-IDENTICAL
    /// output — so a CPU, an NVIDIA kernel and an Apple kernel following the fixed schedule all match,
    /// regardless of how each hardware orders its reduction. This is why the integer tier is one class
    /// across all hardware and immune to codegen drift.
    #[test]
    fn integer_gemm_is_reduction_order_independent() {
        let (m, k, n) = (3, 64, 3);
        let (a, b) = (fill(m * k, 5), fill(k * n, 9));
        let reference = canonical_int_gemm(&a, &b, m, k, n);
        // A "different hardware" reduction: accumulate k in DESCENDING order.
        let mut rev = vec![0i32; m * n];
        for i in 0..m {
            for j in 0..n {
                let mut acc: i32 = 0;
                for p in (0..k).rev() {
                    acc += a[i * k + p] as i32 * b[p * n + j] as i32;
                }
                rev[i * n + j] = acc;
            }
        }
        assert_eq!(reference, rev, "integer reduction MUST be order-independent (Level-3 cross-platform bit-exactness)");
    }

    /// The contrast that motivates the integer endgame: fp32 addition is NOT associative, so the SAME
    /// products summed ascending vs descending can differ by a bit — which is exactly why the float tier
    /// must pin the schedule and still risks cross-vendor drift, and why Level 3 (integers) removes the
    /// problem structurally. (If this ever stops differing on some target it only strengthens the point;
    /// the assert is written to prove the hazard EXISTS on this host.)
    #[test]
    fn float_reduction_is_order_dependent_hazard() {
        // Values chosen so catastrophic cancellation makes the order observable.
        let vals: [f32; 4] = [1.0e8, 1.0, -1.0e8, 1.0];
        let fwd = vals.iter().fold(0.0f32, |s, &v| s + v);
        let rev = vals.iter().rev().fold(0.0f32, |s, &v| s + v);
        assert_ne!(fwd, rev, "fp addition is non-associative — the float tier cannot rely on reduction order");
    }

    /// §10 hierarchical reduce: no overflow at 32k-context scale, order-independent, and equal to the true
    /// sum (the boundary keeps partials in budget while i64 holds the total).
    #[test]
    fn hierarchical_reduce_no_overflow_and_order_independent() {
        // 32_768 elements near the softmax·V per-element magnitude; naive i32 would wrap, i64 does not.
        let n = 32_768usize;
        let vals: Vec<i64> = (0..n).map(|i| 3_000_000 + (i as i64 % 7)).collect();
        let truth: i64 = vals.iter().sum();
        assert_eq!(hierarchical_int_reduce(&vals, 128), truth, "hierarchical (block 128) equals the true sum");
        assert_eq!(hierarchical_int_reduce(&vals, 256), truth, "a different block boundary yields the SAME total");
        assert!(truth > i32::MAX as i64, "the total genuinely exceeds i32 (i64 is required, §10)");
    }

    #[test]
    fn schedule_validity() {
        assert!(CanonicalGemmSchedule { m_tile: 64, n_tile: 64, k_tile: 32, k_split: 2 }.is_valid());
        assert!(!CanonicalGemmSchedule { m_tile: 0, n_tile: 64, k_tile: 32, k_split: 1 }.is_valid());
    }
}
