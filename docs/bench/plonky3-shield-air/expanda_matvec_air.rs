//! C-P6 / B1 integration (ADR-0037), composition-manifest item (iii): **ExpandA REJECTION LOOP +
//! MATRIX-VECTOR WIRING as ONE Plonky3 AIR**. Until now rejection sampling
//! (`rejection_sample_air.rs`), one-hot placement (`sample_in_ball_air.rs`) and the NTT-domain
//! accumulation (`ntt_accumulate_air.rs`) were separately-proven gadgets. Here the ACTUAL
//! ML-DSA-87 verify dataflow for one full output row `i` is wired end-to-end in a single AIR:
//! SHAKE128 output bytes for `Â[i][j]` (witness, bound to PUBLIC VALUES — the SHAKE computation
//! itself is item (ii) = `shake_threaded_air.rs`; binding these publics to that AIR's squeeze
//! output is item (iv)) → 3-byte candidates → rejection sampling (accept iff `t < q`) →
//! counter/one-hot PLACEMENT into the 256-coefficient `Â[i][j]` poly → pointwise mod-q multiply
//! with `ẑ[j]` → accumulation `ŵ_i = Σ_{j<7} Â[i][j]∘ẑ[j] − ĉ∘(t̂1_i·2^d)`, with EVERY
//! stage-to-stage wire bound in-AIR: a sampled-but-tampered coefficient, a mis-placed
//! coefficient, or a substituted accumulate input are each impossible.
//!
//! ## Layout: candidate rows + coefficient rows in ONE trace (preprocessed row-type flags)
//! - **Candidate rows** (7 entries × C=320 rows): one row per 3-byte candidate. The row carries
//!   the PROVEN rejection gadget verbatim (`t = b0 + 256·b1 + 65536·(b2 & 0x7F)`, bytes
//!   bit-decomposed, the `&0x7F` a bit-drop — `t` recomposes only bits 0..22; accept flag via the
//!   sound lt-comparator `t − q + lt·2²⁴ = diff` with `diff` 24-bit range-checked), a running
//!   acceptance counter `cnt` (`cnt' = cnt + place`), the first-256 window `act = [cnt < 256]`
//!   (witnessed `u = 256 − cnt` 9-bit + the exact nonzero test `act = u·u⁻¹`, `u·(1−act) = 0`),
//!   `place = lt·act`, and the `sample_in_ball_air.rs` one-hot placement selector: `sel_k`
//!   boolean, `Σ sel = place`, `Σ k·sel_k = cnt·place` — an accepted in-window candidate MUST be
//!   placed at slot `cnt` (no skip, no duplicate, no reorder); rejected/out-of-window rows place
//!   nothing. Each candidate's 24-bit value is bound to `pi_stream[row]` via a FACTORED
//!   preprocessed one-hot (56 × 40 flags, degree-3 gated equalities), so the whole budget window
//!   of the SHAKE stream is pinned.
//! - **A-banks**: 7 × 256 threaded columns. Bank `j` is written during entry `j`'s candidate rows
//!   by the placement transition `next.A[k] = A[k] + sel_k·(t − A[k])` (gated by the preprocessed
//!   entry flag) and threads IDENTITY on every other transition (gated thread flag) down through
//!   all coefficient rows — for every transition and every bank, EXACTLY ONE of {write, thread}
//!   is active (self-audited), so a placed coefficient cannot be altered after placement.
//! - **Coefficient rows** (256): row `jj` computes output coefficient `jj`: seven `Â[i][j][jj]·
//!   ẑ[j][jj] mod q` gadgets (the `ntt_mul_air.rs` base-2¹² limb-carry multiply, verbatim), the
//!   `2^d`-scale gadget `t1s = 8192·t̂1[jj] mod q` (ζ pinned to the constant 8192), the
//!   subtractive gadget `psub = ĉ[jj]·t1s mod q` (its b-input `==`-bound to the t1s gadget's
//!   output — the c∘t1 wire), materialized accumulate inputs `P[j] == az_j.t` / `PSUB == psub.t`,
//!   and the `ntt_accumulate_air.rs` reduction `Σ_j P[j] − PSUB + q = out + k·q` (exact in-field:
//!   7q < 2²⁶ < p; `k` 3-bit, `out < q` by slack). The mult b-inputs are bound to the banks and
//!   the ζ-inputs / `t̂1` / `ĉ` / `out` to their publics via a FACTORED preprocessed one-hot
//!   (16 × 16 flags) selecting the row's own coefficient index — the "diagonal read" that
//!   replaces a lookup argument (NO LogUp; plain uni-stark).
//! - Rows 2496..4095 are padding: every unconditional gadget is filled with its valid zero
//!   instance (`fill_mult(0,0)`, lt=1/diff=2²⁴−q, kk=1 …); no preprocessed flag is set on row
//!   2495 or beyond, so nothing crosses the padding boundary or the cyclic wrap.
//!
//! ## Bounded candidates (in-circuit ExpandA budget)
//! Acceptance probability per candidate is q/2²³ = 8380417/8388608 ≈ 1 − 2⁻¹⁰ (rejection ≈
//! 8191/2²³ ≈ 9.77·10⁻⁴). The AIR fixes C = 320 candidates per entry and enforces IN-TRACE that
//! all 256 acceptances occur strictly before the last budget row (`cnt == 256` on the entry-last
//! row, `cnt == 0` on the entry-first row). A real SHAKE stream needing more than the budget
//! would require ≥ 64 rejections in 319 candidates: P ≤ C(319,64)·(8191/2²³)⁶⁴ < 2⁻³⁹⁹ per
//! entry (< 2⁻³⁹⁶ for the whole 7-entry row) — the standard in-circuit ExpandA bound; such a
//! stream is unprovable in this shape (re-shape with a larger C), never observed in practice.
//!
//! ## Statement
//! Publics: `pi_stream` (7×320 packed 3-byte candidates), `ẑ[7][256]`, `t̂1_i[256]` (= NTT(t1_i),
//! the 2^d scale is done in-AIR; NTT(t1·2^d) = 2^d·NTT(t1) by linearity — diff-tested), `ĉ[256]`,
//! and `ŵ_i[256]`. z/c/t1 publics are assumed canonical (< q) on the verifier side (host
//! provides canonical residues; in-AIR they are 23-bit-checked by the mult gadgets). SCOPE: one
//! full output row `i` with ALL l=7 ExpandA entries in-AIR, full 256 coefficients each — the
//! per-row unit that repeats k=8 times in item (iv)'s full composition.
//!
//! ## Validation gates (all run in main)
//! (1) host diff-test: the in-AIR placed `Â[i][j]` banks == a from-scratch reference ExpandA
//! (`mldsa_verify_ref.rs` byte order: SHAKE128(ρ‖j‖i)) on REAL libcrux ML-DSA-87 keys, and the
//! final `ŵ_i` == the reference matrix-vector row computed the `mldsa_verify_ref.rs` way
//! (NTT(t1·2^d) path), coefficient-exact; (2) VERIFY ok with prove/verify times, cols/rows/proof
//! bytes, on BOTH a real-ρ instance (rejection count reported) and a synthetic-stream instance
//! with forced rejections (t = 2²³−1 with byte-2 bit 7 set — exercising the bit-drop — and the
//! exact boundary t = q; plus the accept boundary t = q−1); (3) negatives, each a separate flag,
//! all rejected: `--corrupt-accept` (accept-flag forgery on a t ≥ q candidate), `--corrupt-place`
//! (duplicate/skip placement: one-hot moved off slot cnt), `--corrupt-coeff` (a placed bank
//! coefficient tampered AFTER placement, on the row where the mult reads it), `--corrupt-psum`
//! (an accumulate partial-sum input tampered), `--corrupt-ct1` (the ĉ∘t̂1 leg: psub gadget
//! re-filled internally-valid with a substituted b-input — only the t1s→psub wire + PSUB binding
//! break); (4) programmatic constraint-coverage self-audit printed (candidates, acceptances
//! == 256/entry, per-transition bank binding exactly-once, one-hot flag coverage, wire counts);
//! (5) this header's bench-params caveat.
//!
//! NOTE: bench FRI parameters (like the sibling bins) — NOT production soundness settings.
//! Run: `cargo run --release --bin expanda_matvec_air \
//!       [--corrupt-accept|--corrupt-place|--corrupt-coeff|--corrupt-psum|--corrupt-ct1]`

use libcrux_ml_dsa::ml_dsa_87;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

const Q: u64 = 8380417;
const BETA: u64 = 4096; // 2^12 limb base of the mult gadget
const Q1: u64 = 2046; // q = 1 + 2046·β
const TWO24: u64 = 1 << 24;
const N: usize = 256;
const LDIM: usize = 7; // ML-DSA-87 l (columns of A = entries per output row)
const KDIM: usize = 8; // ML-DSA-87 k (rows of A)
const D2: u64 = 8192; // 2^d, d = 13
const CBUD: usize = 320; // per-entry candidate budget (see header for the overflow bound)
const CAND_ROWS: usize = LDIM * CBUD; // 2240
const COEFF0: usize = CAND_ROWS; // first coefficient row
const REAL_ROWS: usize = CAND_ROWS + N; // 2496
const HEIGHT: usize = 4096;
const SHI_N: usize = 56; // 56 × 40 = 2240 factored stream one-hot
const SLO_N: usize = 40;
const CHI_N: usize = 16; // 16 × 16 = 256 factored coefficient one-hot
const CLO_N: usize = 16;

// ---- main columns: candidate block ----
const CIN: usize = 0; // 24 input bits (3 bytes LE)
const CT: usize = 24; // t = low 23 bits (bit 23 dropped = the & 0x7FFFFF)
const CLT: usize = 25; // accept flag [t < q]
const CDIFF: usize = 26; // t − q + lt·2^24
const CDIFFB: usize = 27; // 24 bits of diff
const CCNT: usize = 51; // acceptances before this row (this entry)
const CU: usize = 52; // u = 256 − cnt
const CUB: usize = 53; // 9 bits of u
const CINVU: usize = 62; // u⁻¹ when u ≠ 0 (nonzero-test helper)
const CACT: usize = 63; // act = [cnt < 256]
const CPLACE: usize = 64; // place = lt·act
const CSEL: usize = 65; // 256 one-hot placement selectors
// ---- A-banks (threaded) ----
const BANK: usize = CSEL + N; // 321; bank j at BANK + j·256, 7×256 = 1792 cols
// ---- coefficient block ----
const CB: usize = BANK + LDIM * N; // 2113
const MG_COLS: usize = 296; // one mod-q mult gadget (24 primary + 272 bits)
const MG_AZ0: usize = CB; // az gadgets j = 0..7 at CB + j·296
const MG_T1S: usize = CB + LDIM * MG_COLS; // 2^d scale gadget
const MG_PSUB: usize = CB + (LDIM + 1) * MG_COLS; // ĉ·t1s gadget
const PCOL: usize = CB + (LDIM + 2) * MG_COLS; // P[0..7] accumulate inputs
const PSUBCOL: usize = PCOL + LDIM; // PSUB accumulate input
const O0: usize = PSUBCOL + 1; // out limb 0 (12b)
const O1: usize = O0 + 1; // out limb 1 (11b)
const GO0: usize = O0 + 2; // slack q−1−out limb 0
const GO1: usize = O0 + 3; // slack limb 1
const KKC: usize = O0 + 4; // reduction k ∈ [0,8)
const OBITS: usize = O0 + 5; // bits: O0 12 | O1 11 | GO0 12 | GO1 11 | KK 3 = 49
const NUM_COLS: usize = OBITS + 49; // 4839

// ---- mult gadget relative layout (verbatim ntt_mul_air.rs) ----
const MG_Z0: usize = 0;
const MG_Z1: usize = 1;
const MG_B0: usize = 2;
const MG_B1: usize = 3;
const MG_M0: usize = 4;
const MG_M1: usize = 5;
const MG_T0: usize = 6;
const MG_T1: usize = 7;
const MG_KL0: usize = 8;
const MG_KL1: usize = 9;
const MG_KL2: usize = 10;
const MG_KR0: usize = 11;
const MG_KR1: usize = 12;
const MG_KR2: usize = 13;
const MG_L0: usize = 14;
const MG_L1: usize = 15;
const MG_L2: usize = 16;
const MG_MM0: usize = 17;
const MG_MM1: usize = 18;
const MG_MM2: usize = 19;
const MG_GT0: usize = 20;
const MG_GT1: usize = 21;
const MG_GM0: usize = 22;
const MG_GM1: usize = 23;
const MG_NP: usize = 24;
const MG_WIDTHS: [usize; MG_NP] = [
    12, 11, 12, 11, 12, 11, 12, 11, // z0 z1 b0 b1 m0 m1 t0 t1
    12, 13, 11, 2, 13, 11, // kL0 kL1 kL2 kR0 kR1 kR2
    12, 12, 12, 12, 12, 12, // L0 L1 L2 M0 M1 M2
    12, 11, 12, 11, // gt0 gt1 gm0 gm1
];
fn mg_bit_off(c: usize) -> usize {
    MG_NP + MG_WIDTHS[..c].iter().sum::<usize>()
}

// ---- preprocessed columns ----
const PF_ENTRY: usize = 0; // 7: flag[j] = 1 on entry j's candidate rows (gates bank-j WRITE)
const PF_THREAD: usize = 7; // 7: flag[j] = 1 where bank j threads IDENTITY to the next row
const PF_CAND: usize = 14; // 1 on candidate rows (gates cnt + u == 256)
const PF_STEP: usize = 15; // candidate row, not entry-last (gates cnt' = cnt + place)
const PF_EFIRST: usize = 16; // entry-first rows (gates cnt == 0)
const PF_ELAST: usize = 17; // entry-last rows (gates cnt == 256 — budget completion)
const PF_ROW0: usize = 18; // row 0 (gates all banks == 0)
const PF_COEFF: usize = 19; // coefficient rows (gates t1s ζ == 8192)
const PF_SHI: usize = 20; // 56 stream one-hot (hi)
const PF_SLO: usize = PF_SHI + SHI_N; // 40 stream one-hot (lo)
const PF_CHI: usize = PF_SLO + SLO_N; // 16 coeff one-hot (hi)
const PF_CLO: usize = PF_CHI + CHI_N; // 16 coeff one-hot (lo)
const PREP_W: usize = PF_CLO + CLO_N; // 148

// ---- public values ----
const PI_STREAM: usize = 0; // 2240: entry e candidate rr at e·320 + rr (24-bit LE pack)
const PI_Z: usize = CAND_ROWS; // 1792: ẑ[j][k] at j·256 + k
const PI_T1: usize = PI_Z + LDIM * N; // 256: t̂1_i = NTT(t1_i) (unscaled)
const PI_C: usize = PI_T1 + N; // 256: ĉ
const PI_OUT: usize = PI_C + N; // 256: ŵ_i
const NUM_PIS: usize = PI_OUT + N; // 4800

struct ExpandaMatvecAir {}

impl<F: PrimeField64> BaseAir<F> for ExpandaMatvecAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        NUM_PIS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
    fn preprocessed_width(&self) -> usize {
        PREP_W
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(build_prep::<F>())
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        // Only the CURRENT preprocessed row is read in eval(). INVARIANT: if any constraint ever
        // reads preprocessed().next_slice(), those columns MUST be listed here (the verifier
        // substitutes zeros for unlisted next columns).
        vec![]
    }
}

/// The preprocessed schedule, shared by BaseAir and the self-audit.
fn build_prep<F: PrimeField64>() -> RowMajorMatrix<F> {
    let mut vals = F::zero_vec(HEIGHT * PREP_W);
    for r in 0..HEIGHT {
        let base = r * PREP_W;
        if r < CAND_ROWS {
            let e = r / CBUD;
            let rr = r % CBUD;
            vals[base + PF_ENTRY + e] = F::ONE;
            for j in 0..LDIM {
                if j != e {
                    vals[base + PF_THREAD + j] = F::ONE;
                }
            }
            vals[base + PF_CAND] = F::ONE;
            if rr != CBUD - 1 {
                vals[base + PF_STEP] = F::ONE;
            }
            if rr == 0 {
                vals[base + PF_EFIRST] = F::ONE;
            }
            if rr == CBUD - 1 {
                vals[base + PF_ELAST] = F::ONE;
            }
            if r == 0 {
                vals[base + PF_ROW0] = F::ONE;
            }
            vals[base + PF_SHI + r / SLO_N] = F::ONE;
            vals[base + PF_SLO + r % SLO_N] = F::ONE;
        } else if r < REAL_ROWS {
            let jj = r - COEFF0;
            // banks thread identity through the coefficient region; nothing after row 2495.
            if r < REAL_ROWS - 1 {
                for j in 0..LDIM {
                    vals[base + PF_THREAD + j] = F::ONE;
                }
            }
            vals[base + PF_COEFF] = F::ONE;
            vals[base + PF_CHI + jj / CLO_N] = F::ONE;
            vals[base + PF_CLO + jj % CLO_N] = F::ONE;
        }
        // padding rows: all zero.
    }
    RowMajorMatrix::new(vals, PREP_W)
}

impl<AB: AirBuilder> Air<AB> for ExpandaMatvecAir
where
    AB::F: PrimeField64,
{
    fn eval(&self, builder: &mut AB) {
        let pis: Vec<AB::Expr> = (0..NUM_PIS).map(|k| builder.public_values()[k].into()).collect();
        let prep: Vec<AB::Var> = builder.preprocessed().current_slice().to_vec();
        let main = builder.main();
        let row = main.current_slice();
        let nxt = main.next_slice();
        let one = AB::Expr::ONE;
        let beta = AB::Expr::from_u64(BETA);
        let q = AB::Expr::from_u64(Q);
        let qm1 = AB::Expr::from_u64(Q - 1);
        let e = |i: usize| -> AB::Expr { row[i].into() };

        // ---------------- candidate block (unconditional; padding carries the valid zero fill) --
        for j in 0..24 {
            let b: AB::Expr = row[CIN + j].into();
            builder.assert_zero(b.clone() * (b - one.clone()));
            let d: AB::Expr = row[CDIFFB + j].into();
            builder.assert_zero(d.clone() * (d - one.clone()));
        }
        for j in 0..9 {
            let b: AB::Expr = row[CUB + j].into();
            builder.assert_zero(b.clone() * (b - one.clone()));
        }
        for c in [CLT, CACT, CPLACE] {
            let b: AB::Expr = row[c].into();
            builder.assert_zero(b.clone() * (b - one.clone()));
        }
        for k in 0..N {
            let b: AB::Expr = row[CSEL + k].into();
            builder.assert_zero(b.clone() * (b - one.clone()));
        }
        // t = Σ_{j<23} in_j·2^j  (bit 23 dropped — the & 0x7FFFFF)
        let mut t_acc = AB::Expr::ZERO;
        let mut w = AB::Expr::ONE;
        for j in 0..23 {
            t_acc = t_acc + Into::<AB::Expr>::into(row[CIN + j]) * w.clone();
            w = w.clone() + w.clone();
        }
        builder.assert_eq(e(CT), t_acc);
        // diff recomposition + the sound less-than: t − q + lt·2^24 = diff ∈ [0,2^24)
        let mut d_acc = AB::Expr::ZERO;
        let mut w2 = AB::Expr::ONE;
        for j in 0..24 {
            d_acc = d_acc + Into::<AB::Expr>::into(row[CDIFFB + j]) * w2.clone();
            w2 = w2.clone() + w2.clone();
        }
        builder.assert_eq(e(CDIFF), d_acc);
        builder.assert_eq(e(CT) - q.clone() + e(CLT) * AB::Expr::from_u64(TWO24), e(CDIFF));
        // u recomposition; act = [u ≠ 0] via the exact nonzero test; place = lt·act
        let mut u_acc = AB::Expr::ZERO;
        let mut w3 = AB::Expr::ONE;
        for j in 0..9 {
            u_acc = u_acc + Into::<AB::Expr>::into(row[CUB + j]) * w3.clone();
            w3 = w3.clone() + w3.clone();
        }
        builder.assert_eq(e(CU), u_acc);
        builder.assert_eq(e(CACT), e(CU) * e(CINVU));
        builder.assert_zero(e(CU) * (one.clone() - e(CACT)));
        builder.assert_eq(e(CPLACE), e(CLT) * e(CACT));
        // one-hot placement: Σ sel = place, Σ k·sel = cnt·place  (⇒ slot = cnt exactly)
        let mut sel_sum = AB::Expr::ZERO;
        let mut sel_idx = AB::Expr::ZERO;
        for k in 0..N {
            sel_sum = sel_sum + Into::<AB::Expr>::into(row[CSEL + k]);
            sel_idx = sel_idx + Into::<AB::Expr>::into(row[CSEL + k]) * AB::Expr::from_u64(k as u64);
        }
        builder.assert_eq(sel_sum, e(CPLACE));
        builder.assert_eq(sel_idx, e(CCNT) * e(CPLACE));
        // gated counter bookkeeping
        let f_cand: AB::Expr = prep[PF_CAND].into();
        builder.assert_zero(f_cand * (e(CCNT) + e(CU) - AB::Expr::from_u64(N as u64)));
        let f_step: AB::Expr = prep[PF_STEP].into();
        builder.assert_zero(f_step * (Into::<AB::Expr>::into(nxt[CCNT]) - e(CCNT) - e(CPLACE)));
        let f_first: AB::Expr = prep[PF_EFIRST].into();
        builder.assert_zero(f_first * e(CCNT));
        let f_last: AB::Expr = prep[PF_ELAST].into();
        builder.assert_zero(f_last * (e(CCNT) - AB::Expr::from_u64(N as u64)));
        // stream binding: candidate value (all 24 bits incl. the dropped one) == its public
        let mut in_val = AB::Expr::ZERO;
        let mut w4 = AB::Expr::ONE;
        for j in 0..24 {
            in_val = in_val + Into::<AB::Expr>::into(row[CIN + j]) * w4.clone();
            w4 = w4.clone() + w4.clone();
        }
        for h in 0..SHI_N {
            let fh: AB::Expr = prep[PF_SHI + h].into();
            for o in 0..SLO_N {
                let fo: AB::Expr = prep[PF_SLO + o].into();
                builder.assert_zero(fh.clone() * fo * (in_val.clone() - pis[PI_STREAM + h * SLO_N + o].clone()));
            }
        }

        // ---------------- A-banks: write (placement) xor thread (identity), every transition ----
        let f_row0: AB::Expr = prep[PF_ROW0].into();
        for j in 0..LDIM {
            let wf: AB::Expr = prep[PF_ENTRY + j].into();
            let tf: AB::Expr = prep[PF_THREAD + j].into();
            for k in 0..N {
                let a: AB::Expr = row[BANK + j * N + k].into();
                let an: AB::Expr = nxt[BANK + j * N + k].into();
                let sel: AB::Expr = row[CSEL + k].into();
                // placement transition: next.A = A + sel·(t − A)  (degree 3 with the gate)
                builder.assert_zero(wf.clone() * (an.clone() - a.clone() - sel * (e(CT) - a.clone())));
                // identity thread
                builder.assert_zero(tf.clone() * (an - a.clone()));
                // all banks start at 0
                builder.assert_zero(f_row0.clone() * a);
            }
        }

        // ---------------- mult gadgets (unconditional, valid zero instance elsewhere) ----------
        let mgv = |b: usize, lo: usize, hi: usize| -> AB::Expr {
            Into::<AB::Expr>::into(row[b + lo]) + beta.clone() * Into::<AB::Expr>::into(row[b + hi])
        };
        for g in 0..(LDIM + 2) {
            let base = CB + g * MG_COLS;
            // bind + range-check every primary column via its bits
            for c in 0..MG_NP {
                let bo = base + mg_bit_off(c);
                let mut acc = AB::Expr::ZERO;
                let mut wg = AB::Expr::ONE;
                for j in 0..MG_WIDTHS[c] {
                    let bit: AB::Expr = row[bo + j].into();
                    builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
                    acc = acc + bit * wg.clone();
                    wg = wg.clone() + wg.clone();
                }
                builder.assert_eq(e(base + c), acc);
            }
            let q1 = AB::Expr::from_u64(Q1);
            // LHS = ζ·b limbified with carries (each partial product < 2^24 < p)
            builder.assert_eq(e(base + MG_Z0) * e(base + MG_B0), e(base + MG_L0) + beta.clone() * e(base + MG_KL0));
            builder.assert_eq(
                e(base + MG_Z0) * e(base + MG_B1) + e(base + MG_Z1) * e(base + MG_B0) + e(base + MG_KL0),
                e(base + MG_L1) + beta.clone() * e(base + MG_KL1),
            );
            builder.assert_eq(
                e(base + MG_Z1) * e(base + MG_B1) + e(base + MG_KL1),
                e(base + MG_L2) + beta.clone() * e(base + MG_KL2),
            );
            // RHS = m·q + t limbified (Q0 = 1, Q1 = 2046)
            builder.assert_eq(e(base + MG_M0) + e(base + MG_T0), e(base + MG_MM0) + beta.clone() * e(base + MG_KR0));
            builder.assert_eq(
                e(base + MG_M0) * q1.clone() + e(base + MG_M1) + e(base + MG_T1) + e(base + MG_KR0),
                e(base + MG_MM1) + beta.clone() * e(base + MG_KR1),
            );
            builder.assert_eq(
                e(base + MG_M1) * q1 + e(base + MG_KR1),
                e(base + MG_MM2) + beta.clone() * e(base + MG_KR2),
            );
            builder.assert_eq(e(base + MG_L0), e(base + MG_MM0));
            builder.assert_eq(e(base + MG_L1), e(base + MG_MM1));
            builder.assert_eq(e(base + MG_L2), e(base + MG_MM2));
            builder.assert_eq(e(base + MG_KL2), e(base + MG_KR2));
            // canonical residues: t < q, m < q
            builder.assert_eq(
                e(base + MG_T0) + beta.clone() * e(base + MG_T1) + e(base + MG_GT0) + beta.clone() * e(base + MG_GT1),
                qm1.clone(),
            );
            builder.assert_eq(
                e(base + MG_M0) + beta.clone() * e(base + MG_M1) + e(base + MG_GM0) + beta.clone() * e(base + MG_GM1),
                qm1.clone(),
            );
        }

        // ---------------- stage wiring on coefficient rows -------------------------------------
        // accumulate inputs are MATERIALIZED and ==-bound to the mult outputs (the tamper surface
        // the negatives exercise); the psub b-input is ==-bound to the t1s output (the c∘t1 wire).
        for j in 0..LDIM {
            builder.assert_eq(e(PCOL + j), mgv(MG_AZ0 + j * MG_COLS, MG_T0, MG_T1));
        }
        builder.assert_eq(e(PSUBCOL), mgv(MG_PSUB, MG_T0, MG_T1));
        builder.assert_eq(mgv(MG_PSUB, MG_B0, MG_B1), mgv(MG_T1S, MG_T0, MG_T1));
        let f_coeff: AB::Expr = prep[PF_COEFF].into();
        builder.assert_zero(f_coeff * (mgv(MG_T1S, MG_Z0, MG_Z1) - AB::Expr::from_u64(D2)));
        // out block bits
        let ow = [12usize, 11, 12, 11, 3];
        let ocols = [O0, O1, GO0, GO1, KKC];
        let mut off = OBITS;
        for (ci, &col) in ocols.iter().enumerate() {
            let mut acc = AB::Expr::ZERO;
            let mut wo = AB::Expr::ONE;
            for j in 0..ow[ci] {
                let bit: AB::Expr = row[off + j].into();
                builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
                acc = acc + bit * wo.clone();
                wo = wo.clone() + wo.clone();
            }
            builder.assert_eq(e(col), acc);
            off += ow[ci];
        }
        // accumulation-reduction: Σ P − PSUB + q = out + k·q  (exact: 7q < 2^26 < p), out < q
        let out_val = e(O0) + beta.clone() * e(O1);
        builder.assert_eq(out_val.clone() + e(GO0) + beta.clone() * e(GO1), qm1);
        let mut acc_sum = AB::Expr::ZERO;
        for j in 0..LDIM {
            acc_sum = acc_sum + e(PCOL + j);
        }
        builder.assert_eq(acc_sum - e(PSUBCOL) + q.clone(), out_val.clone() + e(KKC) * q);

        // ---------------- diagonal reads (factored one-hot): banks + publics --------------------
        for a in 0..CHI_N {
            let fa: AB::Expr = prep[PF_CHI + a].into();
            for b in 0..CLO_N {
                let fb: AB::Expr = prep[PF_CLO + b].into();
                let g = fa.clone() * fb;
                let k = a * CLO_N + b;
                for j in 0..LDIM {
                    // mult b-input == the PLACED bank coefficient (the sampling→mult wire)
                    builder.assert_zero(
                        g.clone() * (mgv(MG_AZ0 + j * MG_COLS, MG_B0, MG_B1) - Into::<AB::Expr>::into(row[BANK + j * N + k])),
                    );
                    // mult ζ-input == ẑ[j][k] public
                    builder
                        .assert_zero(g.clone() * (mgv(MG_AZ0 + j * MG_COLS, MG_Z0, MG_Z1) - pis[PI_Z + j * N + k].clone()));
                }
                builder.assert_zero(g.clone() * (mgv(MG_T1S, MG_B0, MG_B1) - pis[PI_T1 + k].clone()));
                builder.assert_zero(g.clone() * (mgv(MG_PSUB, MG_Z0, MG_Z1) - pis[PI_C + k].clone()));
                builder.assert_zero(g * (out_val.clone() - pis[PI_OUT + k].clone()));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// trace generation
// ---------------------------------------------------------------------------------------------

fn split(v: u64) -> (u64, u64) {
    (v % BETA, v / BETA)
}

/// Fill one mod-q mult gadget (verbatim arithmetic from ntt_mul_air.rs). Returns t = ζ·b mod q.
fn fill_mult<F: PrimeField64>(vals: &mut [F], off: usize, zeta: u64, b: u64) -> u64 {
    assert!(zeta < (1 << 23) && b < (1 << 23));
    let (z0, z1) = split(zeta);
    let (b0, b1) = split(b);
    let prod = (zeta as u128) * (b as u128);
    let t = (prod % Q as u128) as u64;
    let m = (prod / Q as u128) as u64;
    let (m0, m1) = split(m);
    let (t0, t1) = split(t);
    let s0 = z0 * b0;
    let (l0, kl0) = (s0 % BETA, s0 / BETA);
    let s1 = z0 * b1 + z1 * b0 + kl0;
    let (l1, kl1) = (s1 % BETA, s1 / BETA);
    let s2 = z1 * b1 + kl1;
    let (l2, kl2) = (s2 % BETA, s2 / BETA);
    let u0 = m0 + t0;
    let (mm0, kr0) = (u0 % BETA, u0 / BETA);
    let u1 = m0 * Q1 + m1 + t1 + kr0;
    let (mm1, kr1) = (u1 % BETA, u1 / BETA);
    let u2 = m1 * Q1 + kr1;
    let (mm2, kr2) = (u2 % BETA, u2 / BETA);
    assert_eq!((l0, l1, l2, kl2), (mm0, mm1, mm2, kr2), "limb mismatch (zeta={zeta}, b={b})");
    let (gt0, gt1) = split((Q - 1) - t);
    let (gm0, gm1) = split((Q - 1) - m);
    let prim = [
        (MG_Z0, z0),
        (MG_Z1, z1),
        (MG_B0, b0),
        (MG_B1, b1),
        (MG_M0, m0),
        (MG_M1, m1),
        (MG_T0, t0),
        (MG_T1, t1),
        (MG_KL0, kl0),
        (MG_KL1, kl1),
        (MG_KL2, kl2),
        (MG_KR0, kr0),
        (MG_KR1, kr1),
        (MG_KR2, kr2),
        (MG_L0, l0),
        (MG_L1, l1),
        (MG_L2, l2),
        (MG_MM0, mm0),
        (MG_MM1, mm1),
        (MG_MM2, mm2),
        (MG_GT0, gt0),
        (MG_GT1, gt1),
        (MG_GM0, gm0),
        (MG_GM1, gm1),
    ];
    for (col, v) in prim {
        vals[off + col] = F::from_u64(v);
        let bo = off + mg_bit_off(col);
        for j in 0..MG_WIDTHS[col] {
            vals[bo + j] = F::from_u64((v >> j) & 1);
        }
    }
    t
}

/// Fill the candidate gadget cells for a 24-bit candidate value with counter state.
/// (cnt = acceptances before this row; place ⇒ slot cnt.) Returns place.
fn fill_cand<F: PrimeField64>(vals: &mut [F], base: usize, v: u64, cnt: usize) -> bool {
    assert!(v < TWO24);
    let t = v & 0x7F_FFFF;
    let lt = if t < Q { 1u64 } else { 0 };
    let diff = t + lt * TWO24 - Q;
    for j in 0..24 {
        vals[base + CIN + j] = F::from_u64((v >> j) & 1);
        vals[base + CDIFFB + j] = F::from_u64((diff >> j) & 1);
    }
    vals[base + CT] = F::from_u64(t);
    vals[base + CLT] = F::from_u64(lt);
    vals[base + CDIFF] = F::from_u64(diff);
    let u = (N - cnt) as u64;
    let act = if u != 0 { 1u64 } else { 0 };
    let place = lt == 1 && act == 1;
    vals[base + CCNT] = F::from_u64(cnt as u64);
    vals[base + CU] = F::from_u64(u);
    for j in 0..9 {
        vals[base + CUB + j] = F::from_u64((u >> j) & 1);
    }
    vals[base + CINVU] = if u != 0 { F::from_u64(u).inverse() } else { F::ZERO };
    vals[base + CACT] = F::from_u64(act);
    vals[base + CPLACE] = F::from_u64(place as u64);
    if place {
        vals[base + CSEL + cnt] = F::ONE;
    }
    place
}

/// Valid zero fill of the candidate gadget (rows outside the candidate region):
/// v = 0 ⇒ t = 0 < q ⇒ lt = 1, diff = 2^24 − q; cnt = u = act = place = 0 (act = [u≠0] holds).
fn fill_cand_zero<F: PrimeField64>(vals: &mut [F], base: usize) {
    let diff = TWO24 - Q;
    for j in 0..24 {
        vals[base + CDIFFB + j] = F::from_u64((diff >> j) & 1);
    }
    vals[base + CLT] = F::ONE;
    vals[base + CDIFF] = F::from_u64(diff);
}

/// Valid zero fill of the out block: Σ0 − 0 + q = 0 + 1·q ⇒ out = 0, kk = 1, slack = q−1.
fn fill_out<F: PrimeField64>(vals: &mut [F], base: usize, psum: u64, psub: u64) -> u64 {
    let s = psum + Q - psub;
    let out = s % Q;
    let kk = s / Q;
    assert!(kk < 8);
    let (o0, o1) = split(out);
    let (g0, g1) = split(Q - 1 - out);
    let prim = [(O0, o0), (O1, o1), (GO0, g0), (GO1, g1), (KKC, kk)];
    let ow = [12usize, 11, 12, 11, 3];
    let mut off = OBITS;
    for (ci, &(col, v)) in prim.iter().enumerate() {
        vals[base + col] = F::from_u64(v);
        for j in 0..ow[ci] {
            vals[base + off + j] = F::from_u64((v >> j) & 1);
        }
        off += ow[ci];
    }
    out
}

/// One instance: the 7 candidate byte streams + the NTT-domain statement inputs.
struct Instance {
    streams: Vec<Vec<u8>>, // 7 × (320·3) bytes
    zhat: Vec<[u64; N]>,   // 7 (canonical < q)
    t1n: [u64; N],         // NTT(t1_i), unscaled (the 2^d multiply is in-AIR)
    chat: [u64; N],
}

/// Reference ExpandA entry over a budgeted stream: returns (poly, rejections seen before the
/// 256th acceptance, candidate index of the 256th acceptance).
fn expand_entry(stream: &[u8]) -> ([u64; N], usize, usize) {
    let mut poly = [0u64; N];
    let mut cnt = 0usize;
    let mut rej = 0usize;
    let mut done_at = 0usize;
    for (ci, ch) in stream.chunks(3).enumerate() {
        if cnt == N {
            break;
        }
        let v = ch[0] as u64 | (ch[1] as u64) << 8 | (ch[2] as u64) << 16;
        let t = v & 0x7F_FFFF;
        if t < Q {
            poly[cnt] = t;
            cnt += 1;
            done_at = ci;
        } else {
            rej += 1;
        }
    }
    assert_eq!(cnt, N, "candidate budget overflow (would need a larger C)");
    assert!(done_at <= CBUD - 2, "256th acceptance must land strictly before the last budget row");
    (poly, rej, done_at)
}

/// Build the full trace + pis. Returns (trace, ahat[7], outref, pis).
#[allow(clippy::type_complexity)]
fn generate<F: PrimeField64>(inst: &Instance) -> (RowMajorMatrix<F>, Vec<[u64; N]>, [u64; N], Vec<F>) {
    let mut vals = F::zero_vec(HEIGHT * NUM_COLS);
    let mut banks = vec![[0u64; N]; LDIM];
    let mut ahat: Vec<[u64; N]> = Vec::with_capacity(LDIM);

    // candidate rows
    for e in 0..LDIM {
        let mut cnt = 0usize;
        for rr in 0..CBUD {
            let r = e * CBUD + rr;
            let base = r * NUM_COLS;
            // banks BEFORE this row's candidate
            for (j, bank) in banks.iter().enumerate() {
                for k in 0..N {
                    vals[base + BANK + j * N + k] = F::from_u64(bank[k]);
                }
            }
            let ch = &inst.streams[e][3 * rr..3 * rr + 3];
            let v = ch[0] as u64 | (ch[1] as u64) << 8 | (ch[2] as u64) << 16;
            let place = fill_cand(&mut vals[base..base + NUM_COLS], 0, v, cnt);
            if place {
                banks[e][cnt] = v & 0x7F_FFFF;
                cnt += 1;
            }
            if rr == CBUD - 1 {
                assert_eq!(cnt, N, "entry {e}: 256th acceptance must precede the last budget row");
                assert!(!place);
            }
            // valid zero fill of the coefficient block
            for g in 0..(LDIM + 2) {
                fill_mult(&mut vals[base..base + NUM_COLS], CB + g * MG_COLS, 0, 0);
            }
            fill_out(&mut vals[base..base + NUM_COLS], 0, 0, 0);
        }
        assert_eq!(cnt, N);
        ahat.push(banks[e]);
    }

    // coefficient rows
    let mut outref = [0u64; N];
    for jj in 0..N {
        let r = COEFF0 + jj;
        let base = r * NUM_COLS;
        for (j, bank) in banks.iter().enumerate() {
            for k in 0..N {
                vals[base + BANK + j * N + k] = F::from_u64(bank[k]);
            }
        }
        fill_cand_zero(&mut vals[base..base + NUM_COLS], 0);
        let mut psum = 0u64;
        for j in 0..LDIM {
            let p = fill_mult(&mut vals[base..base + NUM_COLS], MG_AZ0 + j * MG_COLS, inst.zhat[j][jj], ahat[j][jj]);
            vals[base + PCOL + j] = F::from_u64(p);
            psum += p;
        }
        let t1sv = fill_mult(&mut vals[base..base + NUM_COLS], MG_T1S, D2, inst.t1n[jj]);
        let psv = fill_mult(&mut vals[base..base + NUM_COLS], MG_PSUB, inst.chat[jj], t1sv);
        vals[base + PSUBCOL] = F::from_u64(psv);
        outref[jj] = fill_out(&mut vals[base..base + NUM_COLS], 0, psum, psv);
    }

    // padding rows: valid zero fills everywhere, banks 0
    for r in REAL_ROWS..HEIGHT {
        let base = r * NUM_COLS;
        fill_cand_zero(&mut vals[base..base + NUM_COLS], 0);
        for g in 0..(LDIM + 2) {
            fill_mult(&mut vals[base..base + NUM_COLS], CB + g * MG_COLS, 0, 0);
        }
        fill_out(&mut vals[base..base + NUM_COLS], 0, 0, 0);
    }

    // publics
    let mut pis: Vec<F> = Vec::with_capacity(NUM_PIS);
    for e in 0..LDIM {
        for rr in 0..CBUD {
            let ch = &inst.streams[e][3 * rr..3 * rr + 3];
            let v = ch[0] as u64 | (ch[1] as u64) << 8 | (ch[2] as u64) << 16;
            pis.push(F::from_u64(v));
        }
    }
    for zh in &inst.zhat {
        for k in 0..N {
            pis.push(F::from_u64(zh[k]));
        }
    }
    for k in 0..N {
        pis.push(F::from_u64(inst.t1n[k]));
    }
    for k in 0..N {
        pis.push(F::from_u64(inst.chat[k]));
    }
    for k in 0..N {
        pis.push(F::from_u64(outref[k]));
    }
    assert_eq!(pis.len(), NUM_PIS);

    (RowMajorMatrix::new(vals, NUM_COLS), ahat, outref, pis)
}

// ---------------------------------------------------------------------------------------------
// reference ML-DSA-87 pieces (verbatim from mldsa_verify_ref.rs — the libcrux-pinned ground truth)
// ---------------------------------------------------------------------------------------------

const QI: i64 = Q as i64;
const GAMMA1: i64 = 1 << 19;
const TAU: usize = 60;
const CTILDE: usize = 64;
const ZPB: usize = N * 20 / 8;
const DD: u32 = 13;

type Poly = [i64; N];

fn m(x: i64) -> i64 {
    let r = x % QI;
    if r < 0 { r + QI } else { r }
}
fn mulq(a: i64, b: i64) -> i64 {
    m((a as i128 * b as i128 % QI as i128) as i64)
}
fn powq(mut b: i64, mut e: u64) -> i64 {
    let mut r = 1i64;
    b = m(b);
    while e > 0 {
        if e & 1 == 1 {
            r = mulq(r, b);
        }
        b = mulq(b, b);
        e >>= 1;
    }
    r
}
fn brv8(mut x: usize) -> usize {
    let mut r = 0;
    for _ in 0..8 {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}
fn zetas() -> [i64; N] {
    core::array::from_fn(|k| powq(1753, brv8(k) as u64))
}
fn ntt(a: &mut Poly, z: &[i64; N]) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = z[k];
            for j in start..start + len {
                let t = mulq(zeta, a[j + len]);
                a[j + len] = m(a[j] - t);
                a[j] = m(a[j] + t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}
fn unpack(bytes: &[u8], nbits: usize, count: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(count);
    let (mut acc, mut have, mut bi) = (0u64, 0usize, 0usize);
    for _ in 0..count {
        while have < nbits {
            acc |= (bytes[bi] as u64) << have;
            have += 8;
            bi += 1;
        }
        out.push((acc & ((1 << nbits) - 1)) as u32);
        acc >>= nbits;
        have -= nbits;
    }
    out
}
fn pk_decode(pk: &[u8]) -> ([u8; 32], Vec<Poly>) {
    let rho: [u8; 32] = pk[0..32].try_into().unwrap();
    let mut t1 = Vec::with_capacity(KDIM);
    for i in 0..KDIM {
        let raw = unpack(&pk[32 + i * 320..32 + (i + 1) * 320], 10, N);
        t1.push(core::array::from_fn::<i64, N, _>(|j| raw[j] as i64));
    }
    (rho, t1)
}
fn sig_decode(sig: &[u8]) -> ([u8; 64], Vec<Poly>) {
    let ctilde: [u8; 64] = sig[0..64].try_into().unwrap();
    let mut z = Vec::with_capacity(LDIM);
    for i in 0..LDIM {
        let raw = unpack(&sig[CTILDE + i * ZPB..CTILDE + (i + 1) * ZPB], 20, N);
        z.push(core::array::from_fn::<i64, N, _>(|j| GAMMA1 - raw[j] as i64));
    }
    (ctilde, z)
}
fn sample_in_ball(ctilde: &[u8]) -> Poly {
    let mut c = [0i64; N];
    let mut sh = Shake256::default();
    sh.update(ctilde);
    let mut rd = sh.finalize_xof();
    let mut sbytes = [0u8; 8];
    rd.read(&mut sbytes);
    let mut signs = u64::from_le_bytes(sbytes);
    let mut jb = [0u8; 1];
    for i in (N - TAU)..N {
        let j = loop {
            rd.read(&mut jb);
            if (jb[0] as usize) <= i {
                break jb[0] as usize;
            }
        };
        c[i] = c[j];
        c[j] = 1 - 2 * (signs & 1) as i64;
        signs >>= 1;
    }
    c
}
/// The exact ExpandA byte source: SHAKE128(ρ ‖ s ‖ r) for entry Â[r][s] (s = column FIRST).
fn shake128_stream(rho: &[u8; 32], s: u8, r: u8, outlen: usize) -> Vec<u8> {
    let mut sh = Shake128::default();
    sh.update(rho);
    sh.update(&[s, r]);
    let mut rd = sh.finalize_xof();
    let mut out = vec![0u8; outlen];
    rd.read(&mut out);
    out
}
/// verify_ref-style ExpandA for one (r=i, s=j) entry, reading the XOF incrementally (independent
/// of the budgeted-prefix path — same rejection loop as mldsa_verify_ref.rs / libcrux).
fn expand_a_ref_entry(rho: &[u8; 32], s: u8, r: u8) -> Poly {
    let mut sh = Shake128::default();
    sh.update(rho);
    sh.update(&[s, r]);
    let mut rd = sh.finalize_xof();
    let mut buf = [0u8; 3];
    let mut out = [0i64; N];
    let mut cnt = 0usize;
    while cnt < N {
        rd.read(&mut buf);
        let coef = (buf[0] as i64) | ((buf[1] as i64) << 8) | (((buf[2] & 0x7f) as i64) << 16);
        if coef < QI {
            out[cnt] = coef;
            cnt += 1;
        }
    }
    out
}

/// SplitMix64 for the synthetic stream.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

// ---------------------------------------------------------------------------------------------
// STARK config (verbatim shape from the sibling bins)
// ---------------------------------------------------------------------------------------------

type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

fn make_config() -> MyConfig {
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 8,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    MyConfig::new(pcs, challenger)
}

// ---------------------------------------------------------------------------------------------
// self-audit (gate 4)
// ---------------------------------------------------------------------------------------------

fn self_audit() {
    let prep = build_prep::<Val>();
    let g = |r: usize, c: usize| prep.values[r * PREP_W + c] == Val::ONE;
    // (a) bank binding: for every transition r → r+1 with r < 2495, each bank is bound by
    //     EXACTLY ONE of {write, thread}; no bank constraint is active from row 2495 on.
    let mut bank_bindings = 0usize;
    for r in 0..HEIGHT {
        for j in 0..LDIM {
            let w = g(r, PF_ENTRY + j);
            let t = g(r, PF_THREAD + j);
            if r < REAL_ROWS - 1 {
                assert!(w ^ t, "row {r} bank {j}: expected exactly one of write/thread");
                bank_bindings += 1;
            } else {
                assert!(!w && !t, "row {r} bank {j}: no binding may cross the padding boundary");
            }
        }
    }
    assert_eq!(bank_bindings, (REAL_ROWS - 1) * LDIM);
    // (b) stream one-hot: candidate rows carry exactly one (hi, lo) pair encoding the row index.
    for r in 0..HEIGHT {
        let his: Vec<usize> = (0..SHI_N).filter(|&h| g(r, PF_SHI + h)).collect();
        let los: Vec<usize> = (0..SLO_N).filter(|&o| g(r, PF_SLO + o)).collect();
        if r < CAND_ROWS {
            assert_eq!((his.len(), los.len()), (1, 1), "row {r}: stream one-hot");
            assert_eq!(his[0] * SLO_N + los[0], r, "row {r}: stream index mismatch");
            assert!(g(r, PF_CAND) && g(r, PF_ENTRY + r / CBUD));
            assert_eq!(g(r, PF_STEP), r % CBUD != CBUD - 1);
            assert_eq!(g(r, PF_EFIRST), r % CBUD == 0);
            assert_eq!(g(r, PF_ELAST), r % CBUD == CBUD - 1);
        } else {
            assert!(his.is_empty() && los.is_empty() && !g(r, PF_CAND));
        }
        assert_eq!(g(r, PF_ROW0), r == 0);
    }
    // (c) coefficient one-hot: coefficient rows encode their own coefficient index.
    for r in 0..HEIGHT {
        let his: Vec<usize> = (0..CHI_N).filter(|&a| g(r, PF_CHI + a)).collect();
        let los: Vec<usize> = (0..CLO_N).filter(|&b| g(r, PF_CLO + b)).collect();
        if (COEFF0..REAL_ROWS).contains(&r) {
            assert_eq!((his.len(), los.len()), (1, 1), "row {r}: coeff one-hot");
            assert_eq!(his[0] * CLO_N + los[0], r - COEFF0, "row {r}: coeff index mismatch");
            assert!(g(r, PF_COEFF));
        } else {
            assert!(his.is_empty() && los.is_empty() && !g(r, PF_COEFF));
        }
    }
    // (d) wire-count enumeration (eval emits exactly one constraint per enumerated wire).
    let bank_write_eqs = LDIM * N; // per-transition placement equalities
    let bank_thread_eqs = LDIM * N;
    let diag_bank_reads = LDIM * N; // az b-input == bank[k]
    let diag_z_pins = LDIM * N;
    let diag_t1_c_out = 3 * N;
    let stream_bindings = SHI_N * SLO_N;
    let stage_wires = LDIM + 1 + 1 + 1; // P bindings, PSUB binding, psub.b == t1s.t, t1s ζ pin
    println!(
        "GATE 4 ok — self-audit: {bank_bindings} bank-transition bindings ({} transitions × {LDIM} banks, \
         each EXACTLY ONE of write/thread), stream one-hot {SHI_N}×{SLO_N} covers all {CAND_ROWS} candidate \
         rows, coeff one-hot {CHI_N}×{CLO_N} covers all {N} coefficient rows; constraint families: \
         {bank_write_eqs} placement + {bank_thread_eqs} thread equalities per transition, {diag_bank_reads} \
         bank→mult diagonal reads, {diag_z_pins} ẑ pins, {diag_t1_c_out} t̂1/ĉ/ŵ pins, {stream_bindings} \
         stream bindings, {stage_wires} stage wires (P/PSUB/c∘t1/2^d).",
        REAL_ROWS - 1
    );
}

// ---------------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
fn main() {
    let arg = |s: &str| std::env::args().any(|a| a == s);
    let neg_accept = arg("--corrupt-accept");
    let neg_place = arg("--corrupt-place");
    let neg_coeff = arg("--corrupt-coeff");
    let neg_psum = arg("--corrupt-psum");
    let neg_ct1 = arg("--corrupt-ct1");
    let negative = neg_accept || neg_place || neg_coeff || neg_psum || neg_ct1;

    let z = zetas();
    let ctx = b"mil-receipt-v1";

    // ---- REAL instance: libcrux ML-DSA-87 keys (the mldsa_parse_checks.rs seeds). Scan the
    //      6 keys × 8 output rows for the (key, i) whose 7 entry streams show the most in-budget
    //      rejections, so the real instance exercises the reject path if the real streams do. ----
    let mut best: Option<(u8, usize, usize)> = None; // (key, i, total rejections)
    let mut keys = Vec::new();
    for kseed in 0..6u8 {
        let seed: [u8; 32] = core::array::from_fn(|i| (0x1b_u8).wrapping_mul(i as u8 + 1) ^ kseed);
        let kp = ml_dsa_87::generate_key_pair(seed);
        let (rho, _) = pk_decode(kp.verification_key.as_ref());
        for i in 0..KDIM {
            let mut rej = 0usize;
            for j in 0..LDIM {
                let stream = shake128_stream(&rho, j as u8, i as u8, 3 * CBUD);
                let (_, r, _) = expand_entry(&stream);
                rej += r;
            }
            if best.map(|(_, _, b)| rej > b).unwrap_or(true) {
                best = Some((kseed, i, rej));
            }
        }
        keys.push(kp);
    }
    let (kstar, istar, rejstar) = best.unwrap();
    let kp = &keys[kstar as usize];
    let pk = kp.verification_key.as_ref();
    let (rho, t1all) = pk_decode(pk);
    // a real signature from the same key (mldsa_parse_checks.rs message/rnd shape, m = 0)
    let msg = [b"MISAKA session receipt #".as_slice(), &[0u8]].concat();
    let rnd: [u8; 32] = core::array::from_fn(|i| (0x9e_u8).wrapping_add(i as u8));
    let sig = ml_dsa_87::sign(&kp.signing_key, &msg, ctx, rnd).expect("sign");
    let vk = ml_dsa_87::MLDSA87VerificationKey::new(*kp.verification_key.as_ref());
    let s = ml_dsa_87::MLDSA87Signature::new(*sig.as_ref());
    assert!(ml_dsa_87::portable::verify(&vk, &msg, ctx, &s).is_ok(), "libcrux sanity accept");
    let (ctilde, zpoly) = sig_decode(sig.as_ref());
    let c = sample_in_ball(&ctilde);

    // NTT-domain statement inputs (canonical residues)
    let zhat: Vec<[u64; N]> = zpoly
        .iter()
        .map(|p| {
            let mut q = core::array::from_fn::<i64, N, _>(|j| m(p[j]));
            ntt(&mut q, &z);
            core::array::from_fn(|j| q[j] as u64)
        })
        .collect();
    let chat_p = {
        let mut q = c;
        ntt(&mut q, &z);
        q
    };
    let chat: [u64; N] = core::array::from_fn(|j| chat_p[j] as u64);
    let t1n: [u64; N] = {
        let mut q = t1all[istar];
        ntt(&mut q, &z);
        core::array::from_fn(|j| q[j] as u64)
    };
    let streams_a: Vec<Vec<u8>> = (0..LDIM).map(|j| shake128_stream(&rho, j as u8, istar as u8, 3 * CBUD)).collect();
    let inst_a = Instance { streams: streams_a, zhat: zhat.clone(), t1n, chat };

    // per-entry rejection stats for the report
    let mut rej_detail = Vec::new();
    for j in 0..LDIM {
        let (_, r, d) = expand_entry(&inst_a.streams[j]);
        rej_detail.push((r, d));
    }
    println!(
        "REAL instance — key seed {kstar}, output row i={istar}: {rejstar} in-budget rejections across the 7 \
         entry streams (per entry (rejections, 256th-accept idx): {rej_detail:?}); acceptance p = q/2^23 \
         ≈ 0.999023, budget C={CBUD}, P(real-stream overflow) < 2^-396 (header)."
    );

    // ---- SYNTHETIC instance: forced rejections so the reject path is provably exercised ----
    let mut rng = Rng(0xE0_9A5D_2026_0712);
    let mut streams_b = Vec::with_capacity(LDIM);
    for e in 0..LDIM {
        let mut sbytes = Vec::with_capacity(3 * CBUD);
        for rr in 0..CBUD {
            let v: u64 = if e == 0 && rr == 0 {
                Q - 1 // accept boundary t = q−1
            } else if rr % 16 == 15 {
                // forced rejections: t = 2^23−1 with bit 23 set (exercises the bit-drop), and the
                // exact reject boundary t = q.
                if (rr / 16) % 2 == 0 { 0xFF_FFFF } else { Q }
            } else {
                rng.next() % Q // accept
            };
            sbytes.extend_from_slice(&[(v & 0xff) as u8, ((v >> 8) & 0xff) as u8, ((v >> 16) & 0xff) as u8]);
        }
        streams_b.push(sbytes);
    }
    let inst_b = Instance { streams: streams_b, zhat: zhat.clone(), t1n, chat };
    let mut rej_b = 0usize;
    for j in 0..LDIM {
        let (_, r, _) = expand_entry(&inst_b.streams[j]);
        rej_b += r;
    }
    println!("SYNTHETIC instance — {rej_b} forced in-budget rejections (t=0xFFFFFF bit-drop cases + t=q boundary), accept boundary t=q−1 included.");

    // ---- GATE 4: preprocessed-schedule / constraint-coverage self-audit ----
    self_audit();

    // ---- GATE 1: host ground-truth diff-tests ----
    // (1a) budgeted-stream ExpandA == the incremental verify_ref/libcrux rejection loop.
    for j in 0..LDIM {
        let (poly, _, _) = expand_entry(&inst_a.streams[j]);
        let refp = expand_a_ref_entry(&rho, j as u8, istar as u8);
        for k in 0..N {
            assert_eq!(poly[k] as i64, refp[k], "entry {j} coeff {k}: budgeted != reference ExpandA");
        }
    }
    // (1b) the in-AIR t1 leg equals the verify_ref path: 2^d·NTT(t1) == NTT(t1·2^d).
    let t1hat_ref: Poly = {
        let mut q: Poly = core::array::from_fn(|j| mulq(t1all[istar][j], 1 << DD));
        ntt(&mut q, &z);
        q
    };
    for k in 0..N {
        assert_eq!(mulq(D2 as i64, t1n[k] as i64), t1hat_ref[k], "coeff {k}: 2^d·NTT(t1) != NTT(t1·2^d)");
    }
    // (1c) generate the real trace and check: in-AIR placed banks == reference ExpandA, and the
    //      out column == the verify_ref matrix-vector row ŵ_i = Σ Â∘ẑ − ĉ∘(t̂1·2^d).
    let (trace_a, ahat_a, outref_a, pis_a) = generate::<Val>(&inst_a);
    for j in 0..LDIM {
        let refp = expand_a_ref_entry(&rho, j as u8, istar as u8);
        for k in 0..N {
            assert_eq!(ahat_a[j][k] as i64, refp[k], "placed bank {j} coeff {k} != reference ExpandA");
            // the trace itself: banks on the first coefficient row hold the final placed poly
            assert_eq!(
                trace_a.values[COEFF0 * NUM_COLS + BANK + j * N + k],
                Val::from_u64(refp[k] as u64),
                "trace bank {j} coeff {k} != reference"
            );
        }
    }
    let mut what_ref = [0i64; N];
    for k in 0..N {
        let mut acc = 0i64;
        for j in 0..LDIM {
            acc = m(acc + mulq(ahat_a[j][k] as i64, zhat[j][k] as i64));
        }
        what_ref[k] = m(acc - mulq(chat[k] as i64, t1hat_ref[k]));
    }
    for k in 0..N {
        assert_eq!(outref_a[k] as i64, what_ref[k], "out coeff {k} != reference matrix-vector row");
        assert_eq!(
            trace_a.values[(COEFF0 + k) * NUM_COLS + O0].as_canonical_u64()
                + BETA * trace_a.values[(COEFF0 + k) * NUM_COLS + O1].as_canonical_u64(),
            what_ref[k] as u64,
            "trace out coeff {k} != reference"
        );
    }
    println!(
        "GATE 1 ok — host diff-test: all 7 in-AIR placed Â[{istar}][j] polys == reference ExpandA (SHAKE128(ρ‖j‖i), \
         libcrux-pinned byte order), and ŵ_{istar} == the reference matrix-vector row (Σ Â∘ẑ − ĉ∘(t̂1·2^d)), \
         coefficient-exact (256 coeffs × 7 entries + 256 outputs)."
    );

    // ---- prove/verify ----
    let air = ExpandaMatvecAir {};
    let config = make_config();
    let degree_bits = HEIGHT.ilog2() as usize;
    let (pp_data, pp_vk) = setup_preprocessed::<MyConfig, _>(&config, &air, degree_bits).expect("preprocessed setup");

    let run = |label: &str, trace: RowMajorMatrix<Val>, pis: &[Val], expect_fail: bool| {
        let t0 = std::time::Instant::now();
        let proof = prove_with_preprocessed(&config, &air, trace, &pis.to_vec(), Some(&pp_data));
        let t_prove = t0.elapsed();
        let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
        let t1 = std::time::Instant::now();
        let res = verify_with_preprocessed(&config, &air, &proof, &pis.to_vec(), Some(&pp_vk));
        let t_verify = t1.elapsed();
        let ok = res.is_ok();
        match res {
            Ok(_) if expect_fail => println!("NEGATIVE TEST FAIL — {label}: corrupted trace was ACCEPTED!"),
            Ok(_) => println!(
                "VERIFY ok — {label} [prove {t_prove:.1?}, verify {t_verify:.1?}, {NUM_COLS} cols × {HEIGHT} rows, \
                 prep {PREP_W}, {NUM_PIS} publics, proof {proof_bytes} bytes]"
            ),
            Err(e) if expect_fail => println!("NEGATIVE TEST PASS — {label} rejected: {e:?}"),
            Err(e) => println!("UNEXPECTED reject on a valid trace ({label}): {e:?}"),
        }
        ok == !expect_fail
    };

    if negative {
        if neg_accept {
            // (a) accept-flag forgery on a t ≥ q candidate (synthetic instance): find a rejected
            // row and set lt = 1 — the lt-comparator t − q + lt·2^24 = diff must break.
            let (mut trace_b, _, _, pis_b) = generate::<Val>(&inst_b);
            let mut target = None;
            'outer: for e in 0..LDIM {
                for rr in 0..CBUD {
                    let ch = &inst_b.streams[e][3 * rr..3 * rr + 3];
                    let v = ch[0] as u64 | (ch[1] as u64) << 8 | (ch[2] as u64) << 16;
                    if (v & 0x7F_FFFF) >= Q {
                        target = Some(e * CBUD + rr);
                        break 'outer;
                    }
                }
            }
            let r = target.expect("synthetic stream has rejections");
            trace_b.values[r * NUM_COLS + CLT] = Val::ONE;
            println!("corrupt-accept: row {r} (a t ≥ q candidate) accept flag forged to 1");
            run("accept-flag forgery", trace_b, &pis_b, true);
        }
        if neg_place {
            // (b) placement tamper: on the row placing slot 5 of entry 0, move the one-hot to
            // slot 4 (skip slot 5 / duplicate slot 4) — Σ k·sel = cnt·place must break.
            let (mut trace, _, _, pis) = generate::<Val>(&inst_a);
            let mut cnt = 0usize;
            let mut target = None;
            for rr in 0..CBUD {
                let ch = &inst_a.streams[0][3 * rr..3 * rr + 3];
                let v = ch[0] as u64 | (ch[1] as u64) << 8 | (ch[2] as u64) << 16;
                if (v & 0x7F_FFFF) < Q {
                    if cnt == 5 {
                        target = Some(rr);
                        break;
                    }
                    cnt += 1;
                }
            }
            let r = target.unwrap();
            trace.values[r * NUM_COLS + CSEL + 5] = Val::ZERO;
            trace.values[r * NUM_COLS + CSEL + 4] = Val::ONE;
            println!("corrupt-place: entry-0 row {r} one-hot moved from slot 5 (== cnt) to slot 4");
            run("placement skip/duplicate", trace, &pis, true);
        }
        if neg_coeff {
            // (c) placed-coefficient tamper AFTER placement: flip bank-2 coefficient 123 on the
            // exact coefficient row that routes it into the mult — the identity thread into that
            // row AND the bank→mult diagonal read must break.
            let (mut trace, _, _, pis) = generate::<Val>(&inst_a);
            let r = COEFF0 + 123;
            trace.values[r * NUM_COLS + BANK + 2 * N + 123] += Val::ONE;
            println!("corrupt-coeff: bank 2 coefficient 123 tampered on its mult-read row {r}");
            run("placed-coefficient tamper", trace, &pis, true);
        }
        if neg_psum {
            // (d) accumulate partial-sum tamper: flip P[4] on coefficient row 200 — the
            // P == az.t binding and the accumulation-reduction must break.
            let (mut trace, _, _, pis) = generate::<Val>(&inst_a);
            let r = COEFF0 + 200;
            trace.values[r * NUM_COLS + PCOL + 4] += Val::ONE;
            println!("corrupt-psum: accumulate input P[4] tampered on coefficient row 200");
            run("accumulate-input tamper", trace, &pis, true);
        }
        if neg_ct1 {
            // (e) the ĉ∘t̂1 leg: re-fill the psub gadget on coefficient row 7 with b = t1s+1 —
            // an INTERNALLY-VALID mult of a substituted input; only the t1s → psub wire and the
            // PSUB == psub.t binding are violated.
            let (mut trace, _, _, pis) = generate::<Val>(&inst_a);
            let r = COEFF0 + 7;
            let t1sv = mulq(D2 as i64, inst_a.t1n[7] as i64) as u64;
            let base = r * NUM_COLS;
            fill_mult(&mut trace.values[base..base + NUM_COLS], MG_PSUB, inst_a.chat[7], t1sv + 1);
            println!("corrupt-ct1: psub gadget on coefficient row 7 re-filled internally-valid with b = t1s+1");
            run("c∘t1-leg wire tamper", trace, &pis, true);
        }
        return;
    }

    // positives: the real instance, then the synthetic forced-rejection instance.
    let ok_a = run(
        &format!(
            "ExpandA loop + matrix-vector row i={istar} wired in-AIR on REAL libcrux ML-DSA-87 data (key seed \
             {kstar}): 7 entries × 320 candidates → rejection-sample → one-hot placement (256 acceptances each) \
             → banked routing → 7 pointwise Â∘ẑ mults + ĉ∘(t̂1·2^d) → accumulate-reduce, every stage wire bound"
        ),
        trace_a,
        &pis_a,
        false,
    );
    let (trace_b, _, _, pis_b) = generate::<Val>(&inst_b);
    let ok_b = run("synthetic forced-rejection instance (reject path + boundaries t=q−1 / t=q / bit-drop)", trace_b, &pis_b, false);
    if ok_a && ok_b {
        println!(
            "ALL GATES ok — composition-manifest item (iii) landed: rejection sampling + placement + \
             matrix-vector accumulation are ONE AIR with in-AIR stage wiring (no separately-proven gadgets \
             to splice off-circuit). Negatives: run with --corrupt-accept / --corrupt-place / --corrupt-coeff \
             / --corrupt-psum / --corrupt-ct1."
        );
    }
}
