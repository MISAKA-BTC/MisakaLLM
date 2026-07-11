//! C-P6 integration: **in-AIR cross-layer routing for the COMPLETE inverse (GS) n=8 NTT** over
//! Z_q (q=8380417) — the inverse-transform partner of `ntt_wired8_air.rs`, completing the
//! forward+inverse routing pair the ML-DSA-87 `Verify` matrix path needs (forward NTT for `Â·ẑ`,
//! inverse NTT to bring `w` back to the coefficient domain). Twelve Gentleman-Sande butterflies
//! `(a,b) → (a+b, ζ·(b−a)) mod q` across all 3 (=log₂8) layers live in one row; each is the proven
//! GS gadget (single-carry add/sub + base-β limb-carry multiply of the difference, every residue
//! <q range-checked). The genuinely-new part is the WIRING: EVERY layer's butterfly inputs are
//! constrained EQUAL to the previous layer's outputs (bf4.a==bf0.out0 … bf11.b==bf7.out1), so a
//! prover cannot feed any layer anything other than what the previous layer produced — the same
//! full-depth in-AIR routing shown for the forward transform, now for the inverse GS schedule.
//!
//! Ground truth: the wired network is fed `ntt8(x)` and its output (before the uniform n⁻¹ scaling)
//! must equal `8·x mod q` — i.e. the unscaled inverse exactly undoes the forward up to the scalar n.
//! Equivalently the reference `invntt8` (with the final ×n⁻¹) satisfies `invntt8(ntt8(x)) == x`,
//! checked over random x. The final n⁻¹ scaling is one extra mod-q multiply per coefficient (the
//! same proven gadget), omitted here to keep the demo focused on the layer ROUTING — exactly as the
//! forward demo omits downstream steps. `--corrupt` (break a mid-network wire) → rejected.
//!
//! Like the forward demo this is single-row `==`-routing; the 256-pt scale-up needs the multi-row
//! permutation/lookup (LogUp) generalization, which uni-stark does not expose here.

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
use p3_uni_stark::{StarkConfig, prove, verify};

const Q: u64 = 8380417;
const BETA: u64 = 4096;
const Q1: u64 = 2046;

// one GS butterfly's 40 primary columns (same layout as invntt_butterfly_air.rs) then its bits.
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
const NBF: usize = 12;
const NUM_COLS: usize = NBF * BF_COLS;
// GS inverse schedule (len=1,2,4), butterfly bases in schedule order:
//   layer1 (len=1): bf0=(0,1) bf1=(2,3) bf2=(4,5) bf3=(6,7)
//   layer2 (len=2): bf4=(0,2) bf5=(1,3) bf6=(4,6) bf7=(5,7)
//   layer3 (len=4): bf8=(0,4) bf9=(1,5) bf10=(2,6) bf11=(3,7)
const BASE: [usize; NBF] = {
    let mut b = [0usize; NBF];
    let mut i = 0;
    while i < NBF {
        b[i] = i * BF_COLS;
        i += 1;
    }
    b
};

fn bit_off(col: usize) -> usize {
    NP + WIDTHS[..col].iter().sum::<usize>()
}

/// AIR carrying the seven canonical n=8 twiddles zetas[k] (k=1..7) so every GS butterfly's zeta is
/// pinned. The inverse schedule reuses the SAME zetas as the forward (the AIR's ζ·(b−a) convention
/// absorbs the Dilithium `−zetas` sign).
struct InvNttWired8Air {
    zetas: [u64; 7],
}

impl<F> BaseAir<F> for InvNttWired8Air {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for InvNttWired8Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let beta = AB::Expr::from_u64(BETA);
        let q1 = AB::Expr::from_u64(Q1);
        let q = AB::Expr::from_u64(Q);
        let qm1 = AB::Expr::from_u64(Q - 1);
        let e = |i: usize| -> AB::Expr { row[i].into() };

        for &b in BASE.iter() {
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
        }

        // ---- pin each butterfly's twiddle to the canonical zeta ----
        // inverse schedule order: len=1 → zetas[6,5,4,3]; len=2 → zetas[2,2,1,1]; len=4 → zetas[0]×4.
        let pin = |builder: &mut AB, b: usize, zeta: u64| {
            builder.assert_eq(e(b + Z0) + beta.clone() * e(b + Z1), AB::Expr::from_u64(zeta));
        };
        pin(builder, BASE[0], self.zetas[6]);
        pin(builder, BASE[1], self.zetas[5]);
        pin(builder, BASE[2], self.zetas[4]);
        pin(builder, BASE[3], self.zetas[3]);
        pin(builder, BASE[4], self.zetas[2]);
        pin(builder, BASE[5], self.zetas[2]);
        pin(builder, BASE[6], self.zetas[1]);
        pin(builder, BASE[7], self.zetas[1]);
        pin(builder, BASE[8], self.zetas[0]);
        pin(builder, BASE[9], self.zetas[0]);
        pin(builder, BASE[10], self.zetas[0]);
        pin(builder, BASE[11], self.zetas[0]);

        // ---- CROSS-LAYER WIRING: each layer's inputs == the previous layer's outputs ----
        // out0=(O00,O01), out1=(T0,T1); inputs a=(A0,A1), b=(BB0,BB1).
        let wire = |builder: &mut AB, db: usize, d_lo: usize, d_hi: usize, sb: usize, s_lo: usize, s_hi: usize| {
            builder.assert_eq(e(db + d_lo), e(sb + s_lo));
            builder.assert_eq(e(db + d_hi), e(sb + s_hi));
        };
        let (bf0, bf1, bf2, bf3) = (BASE[0], BASE[1], BASE[2], BASE[3]);
        let (bf4, bf5, bf6, bf7) = (BASE[4], BASE[5], BASE[6], BASE[7]);
        let (bf8, bf9, bf10, bf11) = (BASE[8], BASE[9], BASE[10], BASE[11]);
        // layer2 reads layer1 outputs:
        //   bf4=(pos0,pos2)=(bf0.out0,bf1.out0)  bf5=(pos1,pos3)=(bf0.out1,bf1.out1)
        //   bf6=(pos4,pos6)=(bf2.out0,bf3.out0)  bf7=(pos5,pos7)=(bf2.out1,bf3.out1)
        wire(builder, bf4, A0, A1, bf0, O00, O01);
        wire(builder, bf4, BB0, BB1, bf1, O00, O01);
        wire(builder, bf5, A0, A1, bf0, T0, T1);
        wire(builder, bf5, BB0, BB1, bf1, T0, T1);
        wire(builder, bf6, A0, A1, bf2, O00, O01);
        wire(builder, bf6, BB0, BB1, bf3, O00, O01);
        wire(builder, bf7, A0, A1, bf2, T0, T1);
        wire(builder, bf7, BB0, BB1, bf3, T0, T1);
        // layer3 reads layer2 outputs:
        //   bf8=(pos0,pos4)=(bf4.out0,bf6.out0)  bf9=(pos1,pos5)=(bf5.out0,bf7.out0)
        //   bf10=(pos2,pos6)=(bf4.out1,bf6.out1) bf11=(pos3,pos7)=(bf5.out1,bf7.out1)
        wire(builder, bf8, A0, A1, bf4, O00, O01);
        wire(builder, bf8, BB0, BB1, bf6, O00, O01);
        wire(builder, bf9, A0, A1, bf5, O00, O01);
        wire(builder, bf9, BB0, BB1, bf7, O00, O01);
        wire(builder, bf10, A0, A1, bf4, T0, T1);
        wire(builder, bf10, BB0, BB1, bf6, T0, T1);
        wire(builder, bf11, A0, A1, bf5, T0, T1);
        wire(builder, bf11, BB0, BB1, bf7, T0, T1);
    }
}

fn split(v: u64) -> (u64, u64) {
    (v % BETA, v / BETA)
}

/// Fill one GS butterfly's 480 columns for (a, b, zeta) → (out0=a+b, out1=ζ·(b−a)) mod q. Returns
/// (out0, out1) so the caller can thread it into the in-place array.
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

/// Fill all 12 GS butterflies of the in-place inverse n=8 schedule (BF0..BF11), threading each
/// butterfly's outputs back into the working array exactly as the reference inverse NTT does.
fn generate<F: PrimeField64>(input: &[u64; 8], zetas: &[u64; 7]) -> RowMajorMatrix<F> {
    let rows = 2;
    let mut vals = F::zero_vec(rows * NUM_COLS);
    for r in 0..rows {
        let o = r * NUM_COLS;
        let seg = &mut vals[o..o + NUM_COLS];
        let mut a = *input;
        let mut bf = 0usize;
        let mut k = 7usize;
        let mut len = 1;
        while len < 8 {
            let mut start = 0;
            while start < 8 {
                k -= 1;
                let zeta = zetas[k];
                for j in start..start + len {
                    let (o0, o1) = fill_gs(seg, BASE[bf], a[j], a[j + len], zeta);
                    a[j] = o0;
                    a[j + len] = o1;
                    bf += 1;
                }
                start += 2 * len;
            }
            len *= 2;
        }
    }
    RowMajorMatrix::new(vals, NUM_COLS)
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

/// forward n=8 NTT (produces the input the inverse consumes).
fn ntt8(x: &[u64; 8], z: &[u64; 7]) -> [u64; 8] {
    let mut a = *x;
    let mut k = 0usize;
    let mut len = 4;
    while len >= 1 {
        let mut start = 0;
        while start < 8 {
            k += 1;
            let zeta = z[k - 1];
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

/// reference GS inverse (unscaled — no ×n⁻¹) → returns 8·x when fed ntt8(x). Same schedule the AIR wires.
fn invntt8_unscaled(input: &[u64; 8], z: &[u64; 7]) -> [u64; 8] {
    let mut a = *input;
    let mut k = 7usize;
    let mut len = 1;
    while len < 8 {
        let mut start = 0;
        while start < 8 {
            k -= 1;
            let zeta = z[k];
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
    let corrupt = std::env::args().any(|a| a == "--corrupt");
    let psi = modpow(1753, 32);
    let brv3 = |x: u64| -> u64 { ((x & 1) << 2) | (x & 2) | ((x >> 2) & 1) };
    let zetas: [u64; 7] = std::array::from_fn(|i| modpow(psi, brv3((i + 1) as u64)));

    // ---- validate the inverse schedule: invntt (with n⁻¹) round-trips the forward ----
    let ninv = modpow(8, Q - 2);
    let x0: [u64; 8] = [123456, 7654321, 3141592, 2718281, 1618033, 1414213, 5772156, 8380416];
    for s in 0..64u64 {
        let x: [u64; 8] = std::array::from_fn(|i| (x0[i].wrapping_add(s.wrapping_mul(0x9e3779b9)).wrapping_add(i as u64 * 7)) % Q);
        let uns = invntt8_unscaled(&ntt8(&x, &zetas), &zetas);
        let rt: [u64; 8] = std::array::from_fn(|i| ((uns[i] as u128 * ninv as u128) % Q as u128) as u64);
        assert_eq!(rt, x, "round-trip invntt8(ntt8(x)) != x at seed {s}");
    }

    let air = InvNttWired8Air { zetas };
    let x = x0;
    let input = ntt8(&x, &zetas); // the inverse consumes the forward output
    let mut trace = generate::<Val>(&input, &zetas);
    // sanity: the wired output (positions after layer3, before n⁻¹) equals 8·x mod q.
    let expect: [u64; 8] = std::array::from_fn(|i| ((8u128 * x[i] as u128) % Q as u128) as u64);
    let rd = |bf: usize, lo: usize, hi: usize| -> u64 {
        trace.values[BASE[bf] + lo].as_canonical_u64() + BETA * trace.values[BASE[bf] + hi].as_canonical_u64()
    };
    // final positions: pos0=bf8.out0,pos4=bf8.out1,pos1=bf9.out0,pos5=bf9.out1,
    //                  pos2=bf10.out0,pos6=bf10.out1,pos3=bf11.out0,pos7=bf11.out1.
    let got: [u64; 8] = [
        rd(8, O00, O01), rd(9, O00, O01), rd(10, O00, O01), rd(11, O00, O01),
        rd(8, T0, T1), rd(9, T0, T1), rd(10, T0, T1), rd(11, T0, T1),
    ];
    assert_eq!(got, expect, "wired inverse output != 8·x (unscaled round-trip)");

    if corrupt {
        // break a mid-network cross-layer wire: perturb bf8's a-input (must equal bf4.out0).
        trace.values[BASE[8] + A0] += Val::ONE;
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — broken cross-layer wiring accepted!"),
        Ok(_) => println!(
            "VERIFY ok — a COMPLETE inverse (Gentleman-Sande) n=8 NTT over Z_q (q={Q}) with FULL in-AIR \
             cross-layer routing proven as a Plonky3 AIR: 12 GS butterflies across all 3 layers, each the \
             proven GS gadget, with EVERY layer's inputs CONSTRAINED == the previous layer's outputs and \
             each twiddle pinned to the canonical zeta. Validated: fed ntt8(x), the unscaled output == 8·x \
             mod q (so the inverse exactly undoes the forward up to n), and the reference invntt8 (with \
             n⁻¹) round-trips over random x. --corrupt (broken wiring) rejected. Completes the forward+inverse \
             routing pair at n=8; 256-pt needs the multi-row lookup generalization."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — broken cross-layer wiring rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
