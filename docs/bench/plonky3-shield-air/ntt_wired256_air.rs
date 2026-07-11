//! C-P6 / B1 integration (ADR-0037): **FULL 256-pt ML-DSA-87 forward NTT with in-AIR cross-layer
//! routing** — all 1024 butterflies across all 8 (=log₂256) layers in ONE AIR, with EVERY
//! inter-layer wire bound by in-AIR constraints, and NO LogUp / cross-row lookup argument.
//!
//! ## Layout: ONE NTT LAYER PER ROW
//! The n=8 demo (`ntt_wired8_air.rs`) put all layers in one row; at 256-pt that is ~470k columns.
//! One-butterfly-per-row needs arbitrary-distance row binding (a permutation/lookup argument
//! uni-stark does not have). The layout here stays inside uni-stark: row r (r = 0..7) holds ALL
//! 128 butterflies of layer r side by side (128 × 460 = 58,880 columns — same demonstrated width
//! budget as `spend.rs`). Every inter-layer wire then connects row r outputs to row r+1 inputs =
//! ADJACENT rows, expressible as plain (current, next) equality constraints.
//!
//! ## Routing soundness (recomposed-value equality)
//! The per-layer wiring differs (stride len = 128 >> layer), so the transition constraint set is
//! the UNION over layers of per-layer routing equalities, each multiplied by a PREPROCESSED
//! one-hot layer flag (the `spend.rs` row-type-flag technique). Flags are committed at setup, not
//! prover-controlled, so the gated equalities are degree ≤ 2 and routing cannot be disabled.
//! Each wire binds RECOMPOSED field values instead of per-bit equality: each side is
//! `lo + β·hi` where lo (12 bits) and hi (11 bits) are boolean-constrained limbs of the proven
//! butterfly gadget, so both sides are < 2²³ < q·2 < p (BabyBear p = 2013265921, q = 8380417) and
//! in fact both sides are range-checked < q by the gadget itself (`value + slack = q−1`).
//! Field equality of two values in [0, 2²³) ⊂ [0, p) implies INTEGER equality, and the base-β
//! decomposition lo + β·hi with lo < β is unique, so the equality pins the destination limbs to
//! the source limbs exactly — 256 constraints per transition instead of ~5888 per-bit ones.
//! 7 transitions × 256 positions = 1792 wire constraints; a programmatic self-audit asserts the
//! routing enumeration covers every input port of rows 1..7 and every output port of rows 0..6
//! exactly once (no silently-unbound wire).
//!
//! ## Twiddles
//! ζ per (layer, butterfly) is a CONSTANT of the Dilithium schedule (`zetas[k] = 1753^brv8(k)`,
//! layer L block b uses k = 2^L + b). Each row's 128 ζ values live in preprocessed columns; the
//! AIR pins each butterfly's in-gadget ζ limbs to them (`z0 + β·z1 == prep_ζ`), so the prover
//! cannot substitute any twiddle anywhere in the network.
//!
//! ## Trace height / padding
//! 8 real rows + 8 padding rows = 16 (FRI in this config family needs height ≥ 16, exactly as
//! `merkle.rs`). Padding rows are all-zero butterflies filled by the SAME `fill_bf(0,0,0)` (t=m=0,
//! outs 0, carries 0, slacks q−1) so they satisfy every unconditional gadget constraint; all
//! preprocessed flags and ζ columns are 0 there, so routing / IO-binding constraints vanish. The
//! row-7 → row-8 transition cannot corrupt row-7 outputs: no layer flag is set on row 7, so no
//! transition constraint reads across that boundary (and none is set on row 15, killing the cyclic
//! wrap to row 0).
//!
//! ## Statement binding
//! The 256 input coefficients and the 256 output coefficients are PUBLIC VALUES (one BabyBear
//! element per coefficient, valid since q < p), bound by preprocessed row-0 / row-7 indicators
//! (the `merkle.rs` SEL pattern, here committed instead of derived): row 0's butterfly a/b inputs
//! == pis[0..256], row 7's out0/out1 == pis[256..512].
//!
//! ## Validation
//! The schedule/twiddles are validated to BE the ML-DSA-87 NTT via the negacyclic convolution
//! theorem `NTT(f) ∘ NTT(g) == NTT(f·g mod x²⁵⁶+1)` against an independent schoolbook multiply
//! (100 random pairs) plus the reference invNTT round-trip. The trace is host-diff-tested against
//! the reference NTT. Negative tests: `--corrupt-mid` re-fills one LAYER-4 butterfly with a
//! perturbed a-input (internally a perfectly valid gadget — ONLY the cross-row routing is
//! violated), `--corrupt-l1out` flips a layer-1 output cell, `--corrupt-twiddle` tampers the
//! t = ζ·b product cell of a butterfly. All must be rejected.
//!
//! NOTE: bench FRI parameters (like the sibling bins) — NOT production soundness settings.
//! Run: `cargo run --release --bin ntt_wired256_air [--corrupt-mid|--corrupt-l1out|--corrupt-twiddle]`

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

const Q: u64 = 8380417;
const BETA: u64 = 4096;
const Q1: u64 = 2046;
const N: usize = 256;
const NSLOT: usize = 128; // butterflies per layer = per row
const LAYERS: usize = 8; // log2(256) real rows
const HEIGHT: usize = 16; // 8 real + 8 padding rows (FRI wants ≥ 16 here)

// one butterfly's 38 primary columns (layout verbatim from ntt_butterfly_air.rs) then its bits.
const Z0: usize = 0;
const Z1: usize = 1;
const B0: usize = 2;
const B1: usize = 3;
const MC0: usize = 4;
const MC1: usize = 5;
const T0: usize = 6;
const T1: usize = 7;
const KL0: usize = 8;
const KL1: usize = 9;
const KL2: usize = 10;
const KR0: usize = 11;
const KR1: usize = 12;
const KR2: usize = 13;
const L0: usize = 14;
const L1: usize = 15;
const L2: usize = 16;
const M0: usize = 17;
const M1: usize = 18;
const M2: usize = 19;
const GT0: usize = 20;
const GT1: usize = 21;
const GM0: usize = 22;
const GM1: usize = 23;
const A0: usize = 24;
const A1: usize = 25;
const O00: usize = 26;
const O01: usize = 27;
const O10: usize = 28;
const O11: usize = 29;
const KO0: usize = 30;
const KO1: usize = 31;
const GA0: usize = 32;
const GA1: usize = 33;
const GO00: usize = 34;
const GO01: usize = 35;
const GO10: usize = 36;
const GO11: usize = 37;
const NP: usize = 38;
const WIDTHS: [usize; NP] = [
    12, 11, 12, 11, 12, 11, 12, 11, 12, 13, 11, 2, 13, 11, 12, 12, 12, 12, 12, 12, 12, 11, 12, 11, 12, 11, 12, 11, 12,
    11, 1, 1, 12, 11, 12, 11, 12, 11,
];
const BF_COLS: usize = 460; // 38 primary + 422 bits
const NUM_COLS: usize = NSLOT * BF_COLS; // 58,880 main columns per row

// ---- preprocessed columns (committed at setup, per row) ----
const PREP_ZETA: usize = 0; // 128 cols: slot j's canonical ζ (0 on padding rows)
const PREP_LFLAG: usize = NSLOT; // 7 cols: flag[L] = 1 iff row == L (gates routing L → L+1)
const PREP_FIN: usize = PREP_LFLAG + (LAYERS - 1); // 1 iff row 0 (gates input binding)
const PREP_FOUT: usize = PREP_FIN + 1; // 1 iff row 7 (gates output binding)
const PREP_W: usize = PREP_FOUT + 1; // 137

// ---- public values ----
const PI_IN: usize = 0; // 256: input polynomial f (canonical residues < q)
const PI_OUT: usize = N; // 256: NTT(f)
const NUM_PIS: usize = 2 * N;

fn bit_off(col: usize) -> usize {
    NP + WIDTHS[..col].iter().sum::<usize>()
}

// ---- schedule topology (shared by eval, trace generation, and the self-audit) ----

/// In-place positions (pos_a, pos_b) of butterfly `slot` in layer `layer` (Dilithium CT order:
/// blocks of 2·len, len = 128 >> layer; slot = block·len + idx).
fn slot_pos(layer: usize, slot: usize) -> (usize, usize) {
    let len = NSLOT >> layer;
    let block = slot / len;
    let idx = slot % len;
    let pa = 2 * len * block + idx;
    (pa, pa + len)
}

/// Which (slot, port) of `layer` touches position p: port=false ⇒ a-input/out0, true ⇒ b-input/out1.
/// (Reader and writer index math coincide because the schedule is in-place.)
fn port_of(layer: usize, p: usize) -> (usize, bool) {
    let len = NSLOT >> layer;
    let block = p / (2 * len);
    let o = p % (2 * len);
    (block * len + (o % len), o >= len)
}

/// 0-based index into the zetas table (zs[i] = 1753^brv8(i+1)) for (layer, slot):
/// layer L block b uses k = 2^L + b, i.e. zs[2^L + b − 1].
fn zeta_idx(layer: usize, slot: usize) -> usize {
    let len = NSLOT >> layer;
    (1usize << layer) + slot / len - 1
}

/// The 256 wires of transition `layer` → `layer`+1: (dst_slot, dst_is_b, src_slot, src_is_out1),
/// one per state position p. eval() emits EXACTLY one gated equality per entry, so the audit of
/// this enumeration is an audit of the emitted constraint set.
fn routing(layer: usize) -> Vec<(usize, bool, usize, bool)> {
    (0..N)
        .map(|p| {
            let (s_slot, s_out1) = port_of(layer, p);
            let (d_slot, d_b) = port_of(layer + 1, p);
            (d_slot, d_b, s_slot, s_out1)
        })
        .collect()
}

/// AIR carrying the 255 canonical twiddles zetas[k] = 1753^brv8(k), k = 1..255 (zs[k−1]).
struct NttWired256Air {
    zetas: [u64; 255],
}

impl<F: PrimeField64> BaseAir<F> for NttWired256Air {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        NUM_PIS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
    fn preprocessed_width(&self) -> usize {
        PREP_W
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut vals = F::zero_vec(HEIGHT * PREP_W);
        for layer in 0..LAYERS {
            let base = layer * PREP_W;
            for slot in 0..NSLOT {
                vals[base + PREP_ZETA + slot] = F::from_u64(self.zetas[zeta_idx(layer, slot)]);
            }
            if layer < LAYERS - 1 {
                vals[base + PREP_LFLAG + layer] = F::ONE;
            }
        }
        vals[PREP_FIN] = F::ONE; // row 0
        vals[(LAYERS - 1) * PREP_W + PREP_FOUT] = F::ONE; // row 7
        // rows 8..15 (padding): all zero — flags off, ζ pinned to 0 (matching fill_bf(0,0,0)).
        Some(RowMajorMatrix::new(vals, PREP_W))
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        // Only the CURRENT preprocessed row is read in eval(). INVARIANT: if any constraint ever
        // reads preprocessed().next_slice(), those column indices MUST be returned here — the
        // verifier substitutes ZEROS for unlisted next columns (a silent prover/verifier
        // divergence a cheater could exploit).
        vec![]
    }
}

impl<AB: AirBuilder> Air<AB> for NttWired256Air
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
        let q1 = AB::Expr::from_u64(Q1);
        let q = AB::Expr::from_u64(Q);
        let qm1 = AB::Expr::from_u64(Q - 1);
        let e = |i: usize| -> AB::Expr { row[i].into() };

        // ---- each butterfly (every row, incl. padding): bit-range every primary col, then the
        //      mod-q multiply + add/sub + range checks — the proven gadget, verbatim ----
        for slot in 0..NSLOT {
            let b = slot * BF_COLS;
            for c in 0..NP {
                let bo = b + bit_off(c);
                let mut acc = AB::Expr::ZERO;
                let mut w = AB::Expr::ONE;
                for j in 0..WIDTHS[c] {
                    let bit: AB::Expr = row[bo + j].into();
                    builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
                    acc = acc + bit * w.clone();
                    w = w.clone() + w.clone();
                }
                builder.assert_eq(e(b + c), acc);
            }
            // mod-q multiply t = ζ·b (limb carry chain)
            builder.assert_eq(e(b + Z0) * e(b + B0), e(b + L0) + beta.clone() * e(b + KL0));
            builder.assert_eq(
                e(b + Z0) * e(b + B1) + e(b + Z1) * e(b + B0) + e(b + KL0),
                e(b + L1) + beta.clone() * e(b + KL1),
            );
            builder.assert_eq(e(b + Z1) * e(b + B1) + e(b + KL1), e(b + L2) + beta.clone() * e(b + KL2));
            builder.assert_eq(e(b + MC0) + e(b + T0), e(b + M0) + beta.clone() * e(b + KR0));
            builder.assert_eq(
                e(b + MC0) * q1.clone() + e(b + MC1) + e(b + T1) + e(b + KR0),
                e(b + M1) + beta.clone() * e(b + KR1),
            );
            builder.assert_eq(e(b + MC1) * q1.clone() + e(b + KR1), e(b + M2) + beta.clone() * e(b + KR2));
            builder.assert_eq(e(b + L0), e(b + M0));
            builder.assert_eq(e(b + L1), e(b + M1));
            builder.assert_eq(e(b + L2), e(b + M2));
            builder.assert_eq(e(b + KL2), e(b + KR2));

            let t_val = e(b + T0) + beta.clone() * e(b + T1);
            let a_val = e(b + A0) + beta.clone() * e(b + A1);
            let out0 = e(b + O00) + beta.clone() * e(b + O01);
            let out1 = e(b + O10) + beta.clone() * e(b + O11);
            let m_val = e(b + MC0) + beta.clone() * e(b + MC1);
            // add/sub
            builder.assert_eq(a_val.clone() + t_val.clone(), out0.clone() + e(b + KO0) * q.clone());
            builder.assert_eq(a_val.clone() + e(b + KO1) * q.clone(), t_val.clone() + out1.clone());
            // ranges
            let slack = |lo: usize, hi: usize| -> AB::Expr { e(b + lo) + beta.clone() * e(b + hi) };
            builder.assert_eq(t_val + slack(GT0, GT1), qm1.clone());
            builder.assert_eq(m_val + slack(GM0, GM1), qm1.clone());
            builder.assert_eq(a_val + slack(GA0, GA1), qm1.clone());
            builder.assert_eq(out0 + slack(GO00, GO01), qm1.clone());
            builder.assert_eq(out1 + slack(GO10, GO11), qm1.clone());

            // ---- pin this butterfly's twiddle to the preprocessed canonical ζ of (row, slot) ----
            builder.assert_eq(e(b + Z0) + beta.clone() * e(b + Z1), Into::<AB::Expr>::into(prep[PREP_ZETA + slot]));
        }

        // ---- CROSS-LAYER ROUTING: row r+1 inputs == row r outputs, gated by preprocessed flags.
        // flag_L is 1 exactly on row L (L = 0..6) and 0 on rows 7..15, so the constraint is only
        // active on real transitions (never across the row-7→8 padding boundary, never on the
        // cyclic last-row wrap). Recomposed-value equality: both sides are bit-constrained
        // lo + β·hi < 2²³ < p (and range-checked < q by the gadget), so field equality implies
        // integer equality and the unique base-β limbs match. One constraint per wire.
        for layer in 0..LAYERS - 1 {
            let fl: AB::Expr = prep[PREP_LFLAG + layer].into();
            for (d_slot, d_b, s_slot, s_out1) in routing(layer) {
                let (dlo, dhi) = if d_b { (B0, B1) } else { (A0, A1) };
                let (slo, shi) = if s_out1 { (O10, O11) } else { (O00, O01) };
                let db = d_slot * BF_COLS;
                let sb = s_slot * BF_COLS;
                let dst = Into::<AB::Expr>::into(nxt[db + dlo]) + beta.clone() * Into::<AB::Expr>::into(nxt[db + dhi]);
                let src = Into::<AB::Expr>::into(row[sb + slo]) + beta.clone() * Into::<AB::Expr>::into(row[sb + shi]);
                builder.assert_zero(fl.clone() * (dst - src));
            }
        }

        // ---- statement binding: row 0 inputs == pis[0..256], row 7 outputs == pis[256..512] ----
        let fin: AB::Expr = prep[PREP_FIN].into();
        for p in 0..N {
            let (slot, is_b) = port_of(0, p);
            let (lo, hi) = if is_b { (B0, B1) } else { (A0, A1) };
            let b = slot * BF_COLS;
            let v = e(b + lo) + beta.clone() * e(b + hi);
            builder.assert_zero(fin.clone() * (v - pis[PI_IN + p].clone()));
        }
        let fout: AB::Expr = prep[PREP_FOUT].into();
        for p in 0..N {
            let (slot, is_out1) = port_of(LAYERS - 1, p);
            let (lo, hi) = if is_out1 { (O10, O11) } else { (O00, O01) };
            let b = slot * BF_COLS;
            let v = e(b + lo) + beta.clone() * e(b + hi);
            builder.assert_zero(fout.clone() * (v - pis[PI_OUT + p].clone()));
        }
    }
}

fn split(v: u64) -> (u64, u64) {
    (v % BETA, v / BETA)
}

/// Fill one butterfly's 460 columns for (a, b, zeta) → (out0=a+ζb, out1=a−ζb) mod q. Returns
/// (out0, out1) so the caller can thread it into the in-place array. Verbatim from
/// ntt_wired8_air.rs (which took it from ntt_butterfly_air.rs).
fn fill_bf<F: PrimeField64>(vals: &mut [F], base: usize, a: u64, b: u64, zeta: u64) -> (u64, u64) {
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
    assert_eq!((l0, l1, l2, kl2), (mm0, mm1, mm2, kr2), "limb mismatch");
    let sum = a + t;
    let ko0 = if sum >= Q { 1u64 } else { 0 };
    let out0 = sum - ko0 * Q;
    let ko1 = if a >= t { 0u64 } else { 1 };
    let out1 = a + ko1 * Q - t;
    assert!(out0 < Q && out1 < Q);
    let (a0, a1) = split(a);
    let (o00, o01) = split(out0);
    let (o10, o11) = split(out1);
    let (gt0, gt1) = split((Q - 1) - t);
    let (gm0, gm1) = split((Q - 1) - m);
    let (ga0, ga1) = split((Q - 1) - a);
    let (go00, go01) = split((Q - 1) - out0);
    let (go10, go11) = split((Q - 1) - out1);
    let prim = [
        (Z0, z0), (Z1, z1), (B0, b0), (B1, b1), (MC0, m0), (MC1, m1), (T0, t0), (T1, t1),
        (KL0, kl0), (KL1, kl1), (KL2, kl2), (KR0, kr0), (KR1, kr1), (KR2, kr2),
        (L0, l0), (L1, l1), (L2, l2), (M0, mm0), (M1, mm1), (M2, mm2),
        (GT0, gt0), (GT1, gt1), (GM0, gm0), (GM1, gm1),
        (A0, a0), (A1, a1), (O00, o00), (O01, o01), (O10, o10), (O11, o11),
        (KO0, ko0), (KO1, ko1),
        (GA0, ga0), (GA1, ga1), (GO00, go00), (GO01, go01), (GO10, go10), (GO11, go11),
    ];
    for (col, v) in prim {
        vals[base + col] = F::from_u64(v);
        let bo = base + bit_off(col);
        for j in 0..WIDTHS[col] {
            vals[bo + j] = F::from_u64((v >> j) & 1);
        }
    }
    (out0, out1)
}

/// Fill the 8 real rows (one layer each, 128 butterflies in schedule order, outputs threaded
/// in-place exactly as the reference NTT) + 8 padding rows of valid all-zero butterflies.
/// Returns the trace and the final state (= NTT(f) if the schedule is right).
fn generate<F: PrimeField64>(f: &[u64; N], zs: &[u64; 255]) -> (RowMajorMatrix<F>, [u64; N]) {
    let mut vals = F::zero_vec(HEIGHT * NUM_COLS);
    let mut state = *f;
    for layer in 0..LAYERS {
        let ro = layer * NUM_COLS;
        let seg = &mut vals[ro..ro + NUM_COLS];
        for slot in 0..NSLOT {
            let (pa, pb) = slot_pos(layer, slot);
            let zeta = zs[zeta_idx(layer, slot)];
            let (o0, o1) = fill_bf(seg, slot * BF_COLS, state[pa], state[pb], zeta);
            state[pa] = o0;
            state[pb] = o1;
        }
    }
    for r in LAYERS..HEIGHT {
        let ro = r * NUM_COLS;
        let seg = &mut vals[ro..ro + NUM_COLS];
        for slot in 0..NSLOT {
            fill_bf(seg, slot * BF_COLS, 0, 0, 0); // a=b=ζ=0 ⇒ satisfies every gadget constraint
        }
    }
    (RowMajorMatrix::new(vals, NUM_COLS), state)
}

fn modpow(base: u64, mut e: u64) -> u64 {
    let mut r = 1u128;
    let mut b = base as u128 % Q as u128;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % Q as u128;
        }
        b = b * b % Q as u128;
        e >>= 1;
    }
    r as u64
}

fn zetas_table() -> [u64; 255] {
    let brv8 = |mut x: u64| -> u64 {
        let mut r = 0;
        for _ in 0..8 {
            r = (r << 1) | (x & 1);
            x >>= 1;
        }
        r
    };
    std::array::from_fn(|i| modpow(1753, brv8((i + 1) as u64)))
}

/// Reference forward NTT — the exact in-place Dilithium CT schedule the AIR wires.
fn ntt256(x: &[u64; N], zs: &[u64; 255]) -> [u64; N] {
    let mut a = *x;
    let mut k = 0usize;
    let mut len = NSLOT;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = zs[k - 1];
            for j in start..start + len {
                let t = ((zeta as u128 * a[j + len] as u128) % Q as u128) as u64;
                a[j + len] = (a[j] + Q - t) % Q;
                a[j] = (a[j] + t) % Q;
            }
            start += 2 * len;
        }
        if len == 1 {
            break;
        }
        len /= 2;
    }
    a
}

/// Reference inverse NTT (Gentleman-Sande + n⁻¹ scaling), for the round-trip gate.
fn intt256(x: &[u64; N], zs: &[u64; 255]) -> [u64; N] {
    let mut a = *x;
    let mut k = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = zs[k - 1];
            for j in start..start + len {
                let aa = a[j];
                let bb = a[j + len];
                a[j] = (aa + bb) % Q;
                let d = (bb + Q - aa) % Q;
                a[j + len] = ((zeta as u128 * d as u128) % Q as u128) as u64;
            }
            start += 2 * len;
        }
        len *= 2;
    }
    let ninv = modpow(N as u64, Q - 2);
    std::array::from_fn(|i| ((a[i] as u128 * ninv as u128) % Q as u128) as u64)
}

/// Independent schoolbook negacyclic product `f · g mod (x²⁵⁶ + 1)` — the ground truth.
fn schoolbook_negacyclic(f: &[u64; N], g: &[u64; N]) -> [u64; N] {
    let mut c = [0u128; N];
    for i in 0..N {
        for j in 0..N {
            let p = (f[i] as u128) * (g[j] as u128);
            let k = i + j;
            if k < N {
                c[k] = (c[k] + p) % Q as u128;
            } else {
                c[k - N] = (c[k - N] + Q as u128 - (p % Q as u128)) % Q as u128; // x^256 = −1
            }
        }
    }
    std::array::from_fn(|i| c[i] as u64)
}

/// SplitMix64 — tiny deterministic PRNG, no deps.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn coeff(&mut self) -> u64 {
        self.next() % Q
    }
}

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

fn main() {
    let arg = |s: &str| std::env::args().any(|a| a == s);
    // --corrupt is an alias for the strongest (routing-only) negative.
    let corrupt_mid = arg("--corrupt-mid") || arg("--corrupt");
    let corrupt_l1out = arg("--corrupt-l1out");
    let corrupt_twiddle = arg("--corrupt-twiddle");
    let negative = corrupt_mid || corrupt_l1out || corrupt_twiddle;
    let zs = zetas_table();

    // ---- GATE 1a: schedule ground truth — convolution theorem vs independent schoolbook,
    //      100 random pairs; GATE 1b: reference invNTT round-trip. ----
    assert_eq!(modpow(N as u64, Q - 2), 8347681, "n_inv sanity");
    let mut rng = Rng(0xC0FFEE_256_0712);
    for c in 0..100 {
        let f: [u64; N] = std::array::from_fn(|_| rng.coeff());
        let g: [u64; N] = std::array::from_fn(|_| rng.coeff());
        let nf = ntt256(&f, &zs);
        let ng = ntt256(&g, &zs);
        let nc = ntt256(&schoolbook_negacyclic(&f, &g), &zs);
        for i in 0..N {
            let prod = ((nf[i] as u128 * ng[i] as u128) % Q as u128) as u64;
            assert_eq!(prod, nc[i], "convolution theorem failed at pair {c} coeff {i}");
        }
        assert_eq!(intt256(&nf, &zs), f, "invNTT round-trip failed at pair {c}");
    }
    println!("GATE 1 ok — convolution theorem NTT(f)∘NTT(g)==NTT(f·g mod x²⁵⁶+1) vs schoolbook + invNTT round-trip, 100 random pairs");

    // ---- GATE 5: routing constraint-coverage self-audit. eval() emits exactly one gated
    //      equality per routing() entry, so auditing the enumeration audits the constraint set:
    //      every input port of rows 1..7 and every output port of rows 0..6 bound exactly once. ----
    let mut total_wires = 0usize;
    for layer in 0..LAYERS - 1 {
        let wires = routing(layer);
        assert_eq!(wires.len(), N, "layer {layer}: expected 256 wires");
        let mut dst = [[false; 2]; NSLOT];
        let mut src = [[false; 2]; NSLOT];
        for &(d, db, s, sb) in &wires {
            assert!(!dst[d][db as usize], "layer {layer}: duplicate dst port ({d},{db})");
            assert!(!src[s][sb as usize], "layer {layer}: duplicate src port ({s},{sb})");
            dst[d][db as usize] = true;
            src[s][sb as usize] = true;
        }
        assert!(dst.iter().all(|r| r[0] && r[1]), "layer {layer}: unbound input port");
        assert!(src.iter().all(|r| r[0] && r[1]), "layer {layer}: unbound output port");
        total_wires += wires.len();
    }
    assert_eq!(total_wires, (LAYERS - 1) * N, "expected 7 × 256 routing equalities");
    println!(
        "GATE 5 ok — routing self-audit: {total_wires} binding equalities (7 transitions × 256 values), \
         every inter-layer input/output port bound exactly once; + {N} input and {N} output public bindings"
    );

    // ---- build the instance ----
    let f: [u64; N] = std::array::from_fn(|_| rng.coeff());
    let air = NttWired256Air { zetas: zs };
    let (mut trace, threaded_out) = generate::<Val>(&f, &zs);

    // ---- GATE 2: host trace diff-test — final-layer outputs == reference NTT(f) ----
    let out = ntt256(&f, &zs);
    assert_eq!(threaded_out, out, "threaded trace output != reference NTT(f)");
    let rd = |trace: &RowMajorMatrix<Val>, r: usize, base: usize, lo: usize, hi: usize| -> u64 {
        trace.values[r * NUM_COLS + base + lo].as_canonical_u64()
            + BETA * trace.values[r * NUM_COLS + base + hi].as_canonical_u64()
    };
    for p in 0..N {
        let (slot, is_out1) = port_of(LAYERS - 1, p);
        let (lo, hi) = if is_out1 { (O10, O11) } else { (O00, O01) };
        assert_eq!(rd(&trace, LAYERS - 1, slot * BF_COLS, lo, hi), out[p], "row-7 trace output {p} != reference");
        let (slot, is_b) = port_of(0, p);
        let (lo, hi) = if is_b { (B0, B1) } else { (A0, A1) };
        assert_eq!(rd(&trace, 0, slot * BF_COLS, lo, hi), f[p], "row-0 trace input {p} != f");
    }
    println!("GATE 2 ok — host diff-test: trace row-7 outputs == reference NTT(f), row-0 inputs == f (rows {HEIGHT}, cols {NUM_COLS}, prep {PREP_W})");

    // ---- negatives (all after trace generation) ----
    if corrupt_mid {
        // Strongest negative: re-fill ONE layer-4 butterfly with a perturbed a-input. The gadget
        // is internally VALID and the twiddle is the canonical one — only the cross-row routing
        // equalities (row 3 outputs → row 4 inputs; row 4 outputs → row 5 inputs) are violated.
        let (layer, slot) = (4usize, 77usize);
        let a = rd(&trace, layer, slot * BF_COLS, A0, A1);
        let b = rd(&trace, layer, slot * BF_COLS, B0, B1);
        let ro = layer * NUM_COLS;
        fill_bf(&mut trace.values[ro..ro + NUM_COLS], slot * BF_COLS, (a + 1) % Q, b, zs[zeta_idx(layer, slot)]);
        println!("corrupt-mid: layer-4 slot-77 re-filled with a+1 (internally-valid gadget, routing-only violation)");
    }
    if corrupt_l1out {
        // flip a layer-1 output cell (breaks its bit recomposition AND the row-1→2 wire).
        trace.values[NUM_COLS + 33 * BF_COLS + O00] += Val::ONE;
        println!("corrupt-l1out: layer-1 slot-33 out0 limb flipped");
    }
    if corrupt_twiddle {
        // tamper the t = ζ·b product of a layer-2 butterfly (the cell that should equal ζ·b mod q).
        trace.values[2 * NUM_COLS + 5 * BF_COLS + T0] += Val::ONE;
        println!("corrupt-twiddle: layer-2 slot-5 t=ζ·b limb tampered");
    }

    // ---- prove + verify (preprocessed ζ schedule + layer flags + IO indicators) ----
    let pis: Vec<Val> = f.iter().chain(out.iter()).map(|&v| Val::from_u64(v)).collect();
    let config = make_config();
    let degree_bits = HEIGHT.ilog2() as usize;
    let (pp_data, pp_vk) = setup_preprocessed::<MyConfig, _>(&config, &air, degree_bits).expect("preprocessed setup");
    let t0 = std::time::Instant::now();
    let proof = prove_with_preprocessed(&config, &air, trace, &pis, Some(&pp_data));
    let t_prove = t0.elapsed();
    let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
    let t1 = std::time::Instant::now();
    let res = verify_with_preprocessed(&config, &air, &proof, &pis, Some(&pp_vk));
    let t_verify = t1.elapsed();
    match res {
        Ok(_) if negative => println!("NEGATIVE TEST FAIL — a corrupted 256-pt wired NTT trace was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — the COMPLETE ML-DSA-87 256-pt forward NTT with FULL in-AIR cross-layer routing \
             proven as ONE Plonky3 AIR (q={Q}): all 1024 butterflies (8 layers × 128, the exact Dilithium \
             CT schedule) laid out ONE LAYER PER ROW, every inter-layer wire bound by a preprocessed-flag-\
             gated adjacent-row equality ({total_wires} wires, recomposed-value binding), every twiddle \
             pinned to preprocessed zetas[k]=1753^brv8(k), input/output coefficients bound to 512 public \
             values. NO LogUp/lookup — plain uni-stark transitions. [prove {t_prove:.1?}, verify \
             {t_verify:.1?}, {NUM_COLS} cols × {HEIGHT} rows, prep {PREP_W}, proof {proof_bytes} bytes]"
        ),
        Err(e) if negative => println!("NEGATIVE TEST PASS — corrupted 256-pt wired NTT rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
