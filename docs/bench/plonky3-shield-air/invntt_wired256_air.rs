//! C-P6 / B1 integration (ADR-0037): **FULL 256-pt inverse (Gentleman-Sande) ML-DSA-87 NTT with
//! in-AIR cross-layer routing** — the inverse partner of `ntt_wired256_air.rs`: all 1024 GS
//! butterflies `(a,b) → (a+b, ζ·(b−a)) mod q` across all 8 layers in ONE AIR, every inter-layer
//! wire bound in-AIR, NO LogUp/lookup. Same ONE-LAYER-PER-ROW layout: row r (r = 0..7) holds the
//! 128 GS butterflies of inverse layer r (len = 2^r), 128 × 480 = 61,440 columns; inter-layer
//! wires are preprocessed-flag-gated adjacent-row equalities on RECOMPOSED limb values (both
//! sides bit-constrained lo + β·hi < 2²³ < p and range-checked < q by the gadget, so field
//! equality ⇒ integer equality ⇒ unique base-β limbs match — see the forward file's soundness
//! note). Twiddles follow the reversed Dilithium schedule (inverse layer L block b uses
//! k = (256 >> L) − 1 − b; the AIR's ζ·(b−a) convention absorbs the reference `−zetas` sign,
//! exactly as `invntt_wired8_air.rs`); each ζ is pinned to a preprocessed constant.
//!
//! Ground truth: fed `ntt256(x)`, the wired network's output (before the uniform n⁻¹ = 8347681
//! scaling) must equal `256·x mod q` — the unscaled inverse exactly undoes the forward up to the
//! scalar n. The reference invNTT (with ×n⁻¹) round-trips over 100 random x (and the forward
//! reference is itself convolution-theorem-validated in the forward bin). The 256 NTT-domain
//! input coefficients and the 256 unscaled outputs are bound to public values on rows 0 / 7.
//! Height 16 = 8 real + 8 all-zero-butterfly padding rows (`fill_gs(0,0,0)` satisfies every
//! gadget constraint; all preprocessed flags/ζ are 0 there so routing/pinning/IO vanish, and no
//! constraint crosses the row-7→8 boundary or the cyclic wrap).
//!
//! Negatives: `--corrupt-mid` re-fills one LAYER-4 GS butterfly with a perturbed a-input
//! (internally a perfectly valid gadget — only the cross-row routing is violated),
//! `--corrupt-l1out` flips a layer-1 out0 cell, `--corrupt-twiddle` tampers a ζ·(b−a) product
//! cell. All must be rejected.
//!
//! NOTE: bench FRI parameters (like the sibling bins) — NOT production soundness settings.
//! Run: `cargo run --release --bin invntt_wired256_air [--corrupt-mid|--corrupt-l1out|--corrupt-twiddle]`

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
const NSLOT: usize = 128; // GS butterflies per layer = per row
const LAYERS: usize = 8;
const HEIGHT: usize = 16; // 8 real + 8 padding rows

// one GS butterfly's 40 primary columns (layout verbatim from invntt_butterfly_air.rs /
// invntt_wired8_air.rs) then its bits.
const Z0: usize = 0;
const Z1: usize = 1;
const D0: usize = 2; // d = (b − a) mod q, the multiply's 2nd operand
const D1: usize = 3;
const MC0: usize = 4;
const MC1: usize = 5;
const T0: usize = 6; // t = ζ·d mod q = out1
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
const A0: usize = 24; // a
const A1: usize = 25;
const BB0: usize = 26; // b
const BB1: usize = 27;
const O00: usize = 28; // out0 = (a+b) mod q
const O01: usize = 29;
const KD: usize = 30; // borrow bit for d = (b−a) mod q
const KO: usize = 31; // carry bit for out0 = (a+b) mod q
const GA0: usize = 32;
const GA1: usize = 33;
const GB0: usize = 34;
const GB1: usize = 35;
const GD0: usize = 36;
const GD1: usize = 37;
const GO0: usize = 38;
const GO1: usize = 39;
const NP: usize = 40;
const WIDTHS: [usize; NP] = [
    12, 11, 12, 11, 12, 11, 12, 11, // z d m t
    12, 13, 11, 2, 13, 11, //          kL0 kL1 kL2 kR0 kR1 kR2
    12, 12, 12, 12, 12, 12, //         L0 L1 L2 M0 M1 M2
    12, 11, 12, 11, //                 gt gm
    12, 11, 12, 11, 12, 11, //         a b out0
    1, 1, //                           kd ko
    12, 11, 12, 11, 12, 11, 12, 11, // ga gb gd go
];
const BF_COLS: usize = 480; // 40 primary + 440 bits
const NUM_COLS: usize = NSLOT * BF_COLS; // 61,440 main columns per row

// ---- preprocessed columns ----
const PREP_ZETA: usize = 0; // 128 cols: slot j's canonical ζ (0 on padding rows)
const PREP_LFLAG: usize = NSLOT; // 7 cols: flag[L] = 1 iff row == L (gates routing L → L+1)
const PREP_FIN: usize = PREP_LFLAG + (LAYERS - 1); // 1 iff row 0
const PREP_FOUT: usize = PREP_FIN + 1; // 1 iff row 7
const PREP_W: usize = PREP_FOUT + 1; // 137

// ---- public values ----
const PI_IN: usize = 0; // 256: the NTT-domain input (= ntt256(x))
const PI_OUT: usize = N; // 256: the UNSCALED inverse output (= 256·x mod q)
const NUM_PIS: usize = 2 * N;

fn bit_off(col: usize) -> usize {
    NP + WIDTHS[..col].iter().sum::<usize>()
}

// ---- schedule topology (shared by eval, trace generation, and the self-audit) ----

/// In-place positions (pos_a, pos_b) of GS butterfly `slot` in inverse layer `layer`
/// (len = 2^layer; blocks of 2·len; slot = block·len + idx).
fn slot_pos(layer: usize, slot: usize) -> (usize, usize) {
    let len = 1usize << layer;
    let block = slot / len;
    let idx = slot % len;
    let pa = 2 * len * block + idx;
    (pa, pa + len)
}

/// Which (slot, port) of inverse `layer` touches position p: port=false ⇒ a-input/out0,
/// true ⇒ b-input/out1(=t). (Reader and writer index math coincide: in-place schedule.)
fn port_of(layer: usize, p: usize) -> (usize, bool) {
    let len = 1usize << layer;
    let block = p / (2 * len);
    let o = p % (2 * len);
    (block * len + (o % len), o >= len)
}

/// 0-based index into the zetas table (zs[i] = 1753^brv8(i+1)) for (layer, slot):
/// inverse layer L block b uses k = (256 >> L) − 1 − b, i.e. zs[k − 1].
fn zeta_idx(layer: usize, slot: usize) -> usize {
    let len = 1usize << layer;
    let block = slot / len;
    (N >> layer) - 1 - block - 1
}

/// The 256 wires of transition `layer` → `layer`+1: (dst_slot, dst_is_b, src_slot, src_is_out1).
/// eval() emits EXACTLY one gated equality per entry.
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
struct InvNttWired256Air {
    zetas: [u64; 255],
}

impl<F: PrimeField64> BaseAir<F> for InvNttWired256Air {
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
        Some(RowMajorMatrix::new(vals, PREP_W))
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        // Only the CURRENT preprocessed row is read in eval(). INVARIANT: if any constraint ever
        // reads preprocessed().next_slice(), those column indices MUST be returned here — the
        // verifier substitutes ZEROS for unlisted next columns.
        vec![]
    }
}

impl<AB: AirBuilder> Air<AB> for InvNttWired256Air
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

        // ---- each GS butterfly (every row, incl. padding): the proven gadget, verbatim ----
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
            // mod-q multiply t = ζ·d (limb carry chain)
            builder.assert_eq(e(b + Z0) * e(b + D0), e(b + L0) + beta.clone() * e(b + KL0));
            builder.assert_eq(
                e(b + Z0) * e(b + D1) + e(b + Z1) * e(b + D0) + e(b + KL0),
                e(b + L1) + beta.clone() * e(b + KL1),
            );
            builder.assert_eq(e(b + Z1) * e(b + D1) + e(b + KL1), e(b + L2) + beta.clone() * e(b + KL2));
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

            let t_val = e(b + T0) + beta.clone() * e(b + T1); // out1 = ζ·d
            let d_val = e(b + D0) + beta.clone() * e(b + D1);
            let a_val = e(b + A0) + beta.clone() * e(b + A1);
            let b_val = e(b + BB0) + beta.clone() * e(b + BB1);
            let out0 = e(b + O00) + beta.clone() * e(b + O01);
            let m_val = e(b + MC0) + beta.clone() * e(b + MC1);
            // GS add/sub: d = (b−a) mod q, out0 = (a+b) mod q
            builder.assert_eq(a_val.clone() + d_val.clone(), b_val.clone() + e(b + KD) * q.clone());
            builder.assert_eq(a_val.clone() + b_val.clone(), out0.clone() + e(b + KO) * q.clone());
            // ranges
            let slack = |lo: usize, hi: usize| -> AB::Expr { e(b + lo) + beta.clone() * e(b + hi) };
            builder.assert_eq(t_val + slack(GT0, GT1), qm1.clone());
            builder.assert_eq(m_val + slack(GM0, GM1), qm1.clone());
            builder.assert_eq(a_val + slack(GA0, GA1), qm1.clone());
            builder.assert_eq(b_val + slack(GB0, GB1), qm1.clone());
            builder.assert_eq(d_val + slack(GD0, GD1), qm1.clone());
            builder.assert_eq(out0 + slack(GO0, GO1), qm1.clone());

            // ---- pin this butterfly's twiddle to the preprocessed canonical ζ of (row, slot) ----
            builder.assert_eq(e(b + Z0) + beta.clone() * e(b + Z1), Into::<AB::Expr>::into(prep[PREP_ZETA + slot]));
        }

        // ---- CROSS-LAYER ROUTING (see forward file for the soundness argument):
        // out0 = (O00,O01), out1 = (T0,T1); inputs a = (A0,A1), b = (BB0,BB1).
        for layer in 0..LAYERS - 1 {
            let fl: AB::Expr = prep[PREP_LFLAG + layer].into();
            for (d_slot, d_b, s_slot, s_out1) in routing(layer) {
                let (dlo, dhi) = if d_b { (BB0, BB1) } else { (A0, A1) };
                let (slo, shi) = if s_out1 { (T0, T1) } else { (O00, O01) };
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
            let (lo, hi) = if is_b { (BB0, BB1) } else { (A0, A1) };
            let b = slot * BF_COLS;
            let v = e(b + lo) + beta.clone() * e(b + hi);
            builder.assert_zero(fin.clone() * (v - pis[PI_IN + p].clone()));
        }
        let fout: AB::Expr = prep[PREP_FOUT].into();
        for p in 0..N {
            let (slot, is_out1) = port_of(LAYERS - 1, p);
            let (lo, hi) = if is_out1 { (T0, T1) } else { (O00, O01) };
            let b = slot * BF_COLS;
            let v = e(b + lo) + beta.clone() * e(b + hi);
            builder.assert_zero(fout.clone() * (v - pis[PI_OUT + p].clone()));
        }
    }
}

fn split(v: u64) -> (u64, u64) {
    (v % BETA, v / BETA)
}

/// Fill one GS butterfly's 480 columns for (a, b, zeta) → (out0=a+b, out1=ζ·(b−a)) mod q.
/// Returns (out0, out1). Verbatim from invntt_wired8_air.rs.
fn fill_gs<F: PrimeField64>(vals: &mut [F], base: usize, a: u64, b: u64, zeta: u64) -> (u64, u64) {
    let d = (b + Q - a) % Q;
    let kd = if b >= a { 0u64 } else { 1 };
    let (z0, z1) = split(zeta);
    let (d0, d1) = split(d);
    let prod = (zeta as u128) * (d as u128);
    let t = (prod % Q as u128) as u64; // out1
    let m = (prod / Q as u128) as u64;
    let (m0, m1) = split(m);
    let (t0, t1) = split(t);
    let s0 = z0 * d0;
    let (l0, kl0) = (s0 % BETA, s0 / BETA);
    let s1 = z0 * d1 + z1 * d0 + kl0;
    let (l1, kl1) = (s1 % BETA, s1 / BETA);
    let s2 = z1 * d1 + kl1;
    let (l2, kl2) = (s2 % BETA, s2 / BETA);
    let u0 = m0 + t0;
    let (mm0, kr0) = (u0 % BETA, u0 / BETA);
    let u1 = m0 * Q1 + m1 + t1 + kr0;
    let (mm1, kr1) = (u1 % BETA, u1 / BETA);
    let u2 = m1 * Q1 + kr1;
    let (mm2, kr2) = (u2 % BETA, u2 / BETA);
    assert_eq!((l0, l1, l2, kl2), (mm0, mm1, mm2, kr2), "limb mismatch");
    let sum = a + b;
    let ko = if sum >= Q { 1u64 } else { 0 };
    let out0 = sum - ko * Q;
    assert!(out0 < Q && t < Q);
    let (a0, a1) = split(a);
    let (bb0, bb1) = split(b);
    let (o00, o01) = split(out0);
    let (gt0, gt1) = split((Q - 1) - t);
    let (gm0, gm1) = split((Q - 1) - m);
    let (ga0, ga1) = split((Q - 1) - a);
    let (gb0, gb1) = split((Q - 1) - b);
    let (gd0, gd1) = split((Q - 1) - d);
    let (go0, go1) = split((Q - 1) - out0);
    let prim = [
        (Z0, z0), (Z1, z1), (D0, d0), (D1, d1), (MC0, m0), (MC1, m1), (T0, t0), (T1, t1),
        (KL0, kl0), (KL1, kl1), (KL2, kl2), (KR0, kr0), (KR1, kr1), (KR2, kr2),
        (L0, l0), (L1, l1), (L2, l2), (M0, mm0), (M1, mm1), (M2, mm2),
        (GT0, gt0), (GT1, gt1), (GM0, gm0), (GM1, gm1),
        (A0, a0), (A1, a1), (BB0, bb0), (BB1, bb1), (O00, o00), (O01, o01),
        (KD, kd), (KO, ko),
        (GA0, ga0), (GA1, ga1), (GB0, gb0), (GB1, gb1), (GD0, gd0), (GD1, gd1), (GO0, go0), (GO1, go1),
    ];
    for (col, v) in prim {
        vals[base + col] = F::from_u64(v);
        let bo = base + bit_off(col);
        for j in 0..WIDTHS[col] {
            vals[bo + j] = F::from_u64((v >> j) & 1);
        }
    }
    (out0, t)
}

/// Fill the 8 real rows (one inverse layer each, outputs threaded in-place exactly as the
/// reference unscaled invNTT) + 8 padding rows of valid all-zero GS butterflies. Returns the
/// trace and the final UNSCALED state (= 256·x mod q when fed ntt256(x)).
fn generate<F: PrimeField64>(input: &[u64; N], zs: &[u64; 255]) -> (RowMajorMatrix<F>, [u64; N]) {
    let mut vals = F::zero_vec(HEIGHT * NUM_COLS);
    let mut state = *input;
    for layer in 0..LAYERS {
        let ro = layer * NUM_COLS;
        let seg = &mut vals[ro..ro + NUM_COLS];
        for slot in 0..NSLOT {
            let (pa, pb) = slot_pos(layer, slot);
            let zeta = zs[zeta_idx(layer, slot)];
            let (o0, o1) = fill_gs(seg, slot * BF_COLS, state[pa], state[pb], zeta);
            state[pa] = o0;
            state[pb] = o1;
        }
    }
    for r in LAYERS..HEIGHT {
        let ro = r * NUM_COLS;
        let seg = &mut vals[ro..ro + NUM_COLS];
        for slot in 0..NSLOT {
            fill_gs(seg, slot * BF_COLS, 0, 0, 0); // a=b=ζ=0 ⇒ satisfies every gadget constraint
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

/// Reference forward NTT (produces the input the inverse consumes).
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

/// Reference UNSCALED GS inverse (no ×n⁻¹) — the exact schedule the AIR wires.
fn invntt256_unscaled(input: &[u64; N], zs: &[u64; 255]) -> [u64; N] {
    let mut a = *input;
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
    a
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
    let corrupt_mid = arg("--corrupt-mid") || arg("--corrupt");
    let corrupt_l1out = arg("--corrupt-l1out");
    let corrupt_twiddle = arg("--corrupt-twiddle");
    let negative = corrupt_mid || corrupt_l1out || corrupt_twiddle;
    let zs = zetas_table();

    // ---- GATE 1: inverse-schedule ground truth — unscaled invNTT(NTT(x)) == 256·x mod q, and
    //      the ×n⁻¹ (n_inv = 8347681) version round-trips, 100 random x. ----
    let ninv = modpow(N as u64, Q - 2);
    assert_eq!(ninv, 8347681, "n_inv sanity");
    let mut rng = Rng(0x1177_C0FFEE_256_1u64);
    for c in 0..100 {
        let x: [u64; N] = std::array::from_fn(|_| rng.coeff());
        let uns = invntt256_unscaled(&ntt256(&x, &zs), &zs);
        for i in 0..N {
            assert_eq!(uns[i], ((N as u128 * x[i] as u128) % Q as u128) as u64, "unscaled inverse != 256·x at {c}/{i}");
            let rt = ((uns[i] as u128 * ninv as u128) % Q as u128) as u64;
            assert_eq!(rt, x[i], "invNTT round-trip failed at {c}/{i}");
        }
    }
    println!("GATE 1 ok — unscaled invNTT(NTT(x)) == 256·x mod q and ×n⁻¹ (8347681) round-trips, 100 random x");

    // ---- GATE 5: routing constraint-coverage self-audit (same enumeration eval() emits). ----
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

    // ---- build the instance: feed the wired inverse the forward NTT of a random x ----
    let x: [u64; N] = std::array::from_fn(|_| rng.coeff());
    let input = ntt256(&x, &zs);
    let air = InvNttWired256Air { zetas: zs };
    let (mut trace, threaded_out) = generate::<Val>(&input, &zs);

    // ---- GATE 2: host trace diff-test — outputs == 256·x mod q (unscaled inverse) ----
    let expect: [u64; N] = std::array::from_fn(|i| ((N as u128 * x[i] as u128) % Q as u128) as u64);
    assert_eq!(threaded_out, expect, "threaded trace output != 256·x");
    assert_eq!(threaded_out, invntt256_unscaled(&input, &zs), "threaded != reference unscaled inverse");
    let rd = |trace: &RowMajorMatrix<Val>, r: usize, base: usize, lo: usize, hi: usize| -> u64 {
        trace.values[r * NUM_COLS + base + lo].as_canonical_u64()
            + BETA * trace.values[r * NUM_COLS + base + hi].as_canonical_u64()
    };
    for p in 0..N {
        let (slot, is_out1) = port_of(LAYERS - 1, p);
        let (lo, hi) = if is_out1 { (T0, T1) } else { (O00, O01) };
        assert_eq!(rd(&trace, LAYERS - 1, slot * BF_COLS, lo, hi), expect[p], "row-7 trace output {p} != 256·x");
        let (slot, is_b) = port_of(0, p);
        let (lo, hi) = if is_b { (BB0, BB1) } else { (A0, A1) };
        assert_eq!(rd(&trace, 0, slot * BF_COLS, lo, hi), input[p], "row-0 trace input {p} != ntt256(x)");
    }
    println!("GATE 2 ok — host diff-test: trace row-7 outputs == 256·x mod q, row-0 inputs == ntt256(x) (rows {HEIGHT}, cols {NUM_COLS}, prep {PREP_W})");

    // ---- negatives (all after trace generation) ----
    if corrupt_mid {
        // Strongest negative: re-fill ONE layer-4 GS butterfly with a perturbed a-input — the
        // gadget is internally VALID, only the cross-row routing is violated.
        let (layer, slot) = (4usize, 77usize);
        let a = rd(&trace, layer, slot * BF_COLS, A0, A1);
        let b = rd(&trace, layer, slot * BF_COLS, BB0, BB1);
        let ro = layer * NUM_COLS;
        fill_gs(&mut trace.values[ro..ro + NUM_COLS], slot * BF_COLS, (a + 1) % Q, b, zs[zeta_idx(layer, slot)]);
        println!("corrupt-mid: layer-4 slot-77 re-filled with a+1 (internally-valid gadget, routing-only violation)");
    }
    if corrupt_l1out {
        trace.values[NUM_COLS + 33 * BF_COLS + O00] += Val::ONE;
        println!("corrupt-l1out: layer-1 slot-33 out0 limb flipped");
    }
    if corrupt_twiddle {
        trace.values[2 * NUM_COLS + 5 * BF_COLS + T0] += Val::ONE;
        println!("corrupt-twiddle: layer-2 slot-5 t=ζ·(b−a) limb tampered");
    }

    // ---- prove + verify ----
    let pis: Vec<Val> = input.iter().chain(expect.iter()).map(|&v| Val::from_u64(v)).collect();
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
        Ok(_) if negative => println!("NEGATIVE TEST FAIL — a corrupted 256-pt wired inverse NTT trace was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — the COMPLETE inverse (Gentleman-Sande) ML-DSA-87 256-pt NTT with FULL in-AIR \
             cross-layer routing proven as ONE Plonky3 AIR (q={Q}): all 1024 GS butterflies (8 layers × \
             128, the exact reversed Dilithium schedule) ONE LAYER PER ROW, every inter-layer wire bound \
             by a preprocessed-flag-gated adjacent-row equality ({total_wires} wires, recomposed-value \
             binding), every twiddle pinned to preprocessed constants, NTT-domain input + unscaled \
             256·x output bound to 512 public values. Fed ntt256(x), output == 256·x mod q (n_inv = \
             8347681 scaling is one further proven mod-q mult per coefficient, as in the n=8 demo). \
             NO LogUp/lookup. [prove {t_prove:.1?}, verify {t_verify:.1?}, {NUM_COLS} cols × {HEIGHT} \
             rows, prep {PREP_W}, proof {proof_bytes} bytes]"
        ),
        Err(e) if negative => println!("NEGATIVE TEST PASS — corrupted 256-pt wired inverse NTT rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
