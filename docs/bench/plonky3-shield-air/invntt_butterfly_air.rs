//! C-P6 step: the **inverse-NTT (Gentleman-Sande) butterfly** `(a, b) → (a+b, ζ·(b−a)) mod q` as
//! a sound Plonky3 AIR (q = 8380417). ML-DSA-87 `Verify` runs the FORWARD NTT (ntt_full_air.rs) to
//! do the matrix-vector product `Â·ẑ − ĉ·t̂1`, then the INVERSE NTT to bring `w` back to the
//! coefficient domain before `Decompose`/`UseHint`. The GS butterfly is structurally distinct from
//! the Cooley-Tukey one: it ADDs/SUBs first and MULTIPLIES the difference (CT multiplies first):
//!   out0 = (a + b) mod q              (single carry)
//!   d    = (b − a) mod q              (single borrow)
//!   out1 = (ζ · d) mod q             (base-β limb-carry multiply — the same proven gadget)
//! Every residue `< q` is range-checked (`value + slack = q−1`). `--corrupt` → rejected. (The final
//! `n⁻¹` scaling of the inverse transform is one extra mod-q multiply per coefficient, same gadget.)

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

// mod-q multiply core (ζ · d), d = the difference (b − a) mod q.
const Z0: usize = 0;
const Z1: usize = 1;
const D0: usize = 2; // d limbs (the multiply's 2nd operand)
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
// GS add/sub
const A0: usize = 24; // a
const A1: usize = 25;
const BB0: usize = 26; // b
const BB1: usize = 27;
const O00: usize = 28; // out0 = (a+b) mod q
const O01: usize = 29;
const KD: usize = 30; // borrow bit for d = (b−a) mod q
const KO: usize = 31; // carry bit for out0 = (a+b) mod q
const GA0: usize = 32; // slacks (value < q)
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
const NUM_COLS: usize = 480; // 40 primary + 440 bits

fn bit_off(col: usize) -> usize {
    NP + WIDTHS[..col].iter().sum::<usize>()
}

struct InvNttButterflyAir {}

impl<F> BaseAir<F> for InvNttButterflyAir {
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

impl<AB: AirBuilder> Air<AB> for InvNttButterflyAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        for c in 0..NP {
            let bo = bit_off(c);
            let mut acc = AB::Expr::ZERO;
            let mut w = AB::Expr::ONE;
            for j in 0..WIDTHS[c] {
                let bit: AB::Expr = row[bo + j].into();
                builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
                acc = acc + bit * w.clone();
                w = w.clone() + w.clone();
            }
            builder.assert_eq(row[c].into(), acc);
        }
        let beta = AB::Expr::from_u64(BETA);
        let q1 = AB::Expr::from_u64(Q1);
        let q = AB::Expr::from_u64(Q);
        let qm1 = AB::Expr::from_u64(Q - 1);
        let e = |i: usize| -> AB::Expr { row[i].into() };

        // ---- mod-q multiply  t = ζ·d  (limb carry chain), d = the difference operand ----
        builder.assert_eq(e(Z0) * e(D0), e(L0) + beta.clone() * e(KL0));
        builder.assert_eq(e(Z0) * e(D1) + e(Z1) * e(D0) + e(KL0), e(L1) + beta.clone() * e(KL1));
        builder.assert_eq(e(Z1) * e(D1) + e(KL1), e(L2) + beta.clone() * e(KL2));
        builder.assert_eq(e(MC0) + e(T0), e(M0) + beta.clone() * e(KR0));
        builder.assert_eq(e(MC0) * q1.clone() + e(MC1) + e(T1) + e(KR0), e(M1) + beta.clone() * e(KR1));
        builder.assert_eq(e(MC1) * q1.clone() + e(KR1), e(M2) + beta.clone() * e(KR2));
        builder.assert_eq(e(L0), e(M0));
        builder.assert_eq(e(L1), e(M1));
        builder.assert_eq(e(L2), e(M2));
        builder.assert_eq(e(KL2), e(KR2));

        let t_val = e(T0) + beta.clone() * e(T1); // out1 = ζ·d mod q
        let d_val = e(D0) + beta.clone() * e(D1);
        let a_val = e(A0) + beta.clone() * e(A1);
        let b_val = e(BB0) + beta.clone() * e(BB1);
        let out0 = e(O00) + beta.clone() * e(O01);
        let m_val = e(MC0) + beta.clone() * e(MC1);

        // ---- GS add/sub ----
        //   d = (b − a) mod q :  a + d = b + KD·q
        builder.assert_eq(a_val.clone() + d_val.clone(), b_val.clone() + e(KD) * q.clone());
        //   out0 = (a + b) mod q :  a + b = out0 + KO·q
        builder.assert_eq(a_val.clone() + b_val.clone(), out0.clone() + e(KO) * q.clone());

        // ---- canonical range checks: value + slack = q−1 ----
        let slack = |lo: usize, hi: usize| -> AB::Expr { e(lo) + beta.clone() * e(hi) };
        builder.assert_eq(t_val + slack(GT0, GT1), qm1.clone()); // out1 < q
        builder.assert_eq(m_val + slack(GM0, GM1), qm1.clone());
        builder.assert_eq(a_val + slack(GA0, GA1), qm1.clone());
        builder.assert_eq(b_val + slack(GB0, GB1), qm1.clone());
        builder.assert_eq(d_val + slack(GD0, GD1), qm1.clone());
        builder.assert_eq(out0 + slack(GO0, GO1), qm1);
    }
}

fn split(v: u64) -> (u64, u64) {
    (v % BETA, v / BETA)
}

/// Reference GS butterfly: out0 = (a+b) mod q, out1 = ζ·((b−a) mod q) mod q.
fn gs_ref(a: u64, b: u64, zeta: u64) -> (u64, u64) {
    let d = (b + Q - a) % Q;
    let out0 = (a + b) % Q;
    let out1 = ((zeta as u128 * d as u128) % Q as u128) as u64;
    (out0, out1)
}

fn generate<F: PrimeField64>(data: &[(u64, u64, u64)]) -> RowMajorMatrix<F> {
    let n = data.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, &(a, b, zeta)) in data.iter().enumerate() {
        let base = r * NUM_COLS;
        let d = (b + Q - a) % Q;
        let kd = if b >= a { 0u64 } else { 1 }; // a + d = b + kd·q
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
        assert_eq!((out0, t), gs_ref(a, b, zeta), "gs ref mismatch");

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
            let bo = bit_off(col);
            for j in 0..WIDTHS[col] {
                vals[base + bo + j] = F::from_u64((v >> j) & 1);
            }
        }
    }
    RowMajorMatrix::new(vals, NUM_COLS)
}

fn zetas(n: usize) -> Vec<u64> {
    let modpow = |base: u64, mut e: u64| -> u64 {
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
    };
    let brv8 = |mut x: u64| -> u64 {
        let mut r = 0;
        for _ in 0..8 {
            r = (r << 1) | (x & 1);
            x >>= 1;
        }
        r
    };
    (1..=n as u64).map(|k| modpow(1753, brv8(k))).collect()
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
    let air = InvNttButterflyAir {};
    let zs = zetas(8);
    // 8 GS butterflies with real twiddles + assorted (a,b) incl. b<a (borrow) and b>a.
    let data: Vec<(u64, u64, u64)> = (0..8usize)
        .map(|i| {
            let a = (0x9e3779b9u64.wrapping_mul((i as u64) + 2)) % Q;
            let b = (0x243f6a88u64.wrapping_mul((i as u64) + 1)) % Q;
            (a, b, zs[i])
        })
        .collect();
    let mut trace = generate::<Val>(&data);
    if corrupt {
        trace.values[O00] += Val::ONE; // break out0
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt GS butterfly trace accepted!"),
        Ok(_) => println!(
            "VERIFY ok — 8 inverse-NTT (Gentleman-Sande) butterflies (out0,out1)=(a+b, ζ·(b−a)) mod q \
             proven as a Plonky3 AIR (q={Q}): GS add/sub (out0=a+b, d=b−a, single carry/borrow) + the \
             same base-β limb-carry multiply on the difference (out1=ζ·d), every residue <q \
             range-checked, real Dilithium twiddles. Diff-tested == the reference GS butterfly; \
             --corrupt rejected. This is the inverse-NTT primitive (paired with the forward NTT)."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt GS butterfly trace rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
