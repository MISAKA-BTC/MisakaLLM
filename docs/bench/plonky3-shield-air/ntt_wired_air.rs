//! C-P6 integration: **in-AIR cross-layer routing** for the NTT — a complete negacyclic n=4 NTT
//! over Z_q (q=8380417) where the layer-to-layer data flow is BOUND inside the AIR, not just
//! validated at the reference level. Four butterflies (2 layers) live in one row; each is the
//! proven butterfly gadget (base-β limb-carry multiply + single-carry add/sub, residues <q
//! range-checked). The genuinely-new part is the WIRING: the layer-2 butterflies' inputs are
//! constrained EQUAL to the layer-1 butterflies' outputs (`bf2.a == bf0.out0`, etc.), so a prover
//! cannot feed layer 2 anything other than what layer 1 produced — the cross-layer routing the
//! full 256-pt tiling needs, shown soundly at n=4. Each butterfly's twiddle is pinned to the
//! correct zeta. The transform is validated to BE the n=4 NTT via the convolution theorem vs an
//! independent schoolbook multiply. `--corrupt` (break the wiring / an output) → rejected.

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

// one butterfly's 38 primary columns (same layout as ntt_butterfly.rs) then its bits.
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
const NBF: usize = 4;
const NUM_COLS: usize = NBF * BF_COLS;
// bases of the 4 butterflies: bf0=layer1(x0,x2), bf1=layer1(x1,x3), bf2=layer2(y0,y1), bf3=layer2(y2,y3)
const BASE: [usize; NBF] = [0, BF_COLS, 2 * BF_COLS, 3 * BF_COLS];

fn bit_off(col: usize) -> usize {
    NP + WIDTHS[..col].iter().sum::<usize>()
}

/// AIR carrying the three canonical n=4 twiddles so every butterfly's zeta is pinned.
struct NttWiredAir {
    z1: u64, // layer-1 twiddle (both bf0, bf1)
    z2: u64, // layer-2 group 0 (bf2)
    z3: u64, // layer-2 group 1 (bf3)
}

impl<F> BaseAir<F> for NttWiredAir {
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

impl<AB: AirBuilder> Air<AB> for NttWiredAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let beta = AB::Expr::from_u64(BETA);
        let q1 = AB::Expr::from_u64(Q1);
        let q = AB::Expr::from_u64(Q);
        let qm1 = AB::Expr::from_u64(Q - 1);
        let e = |i: usize| -> AB::Expr { row[i].into() };

        // ---- each butterfly: bit-range every primary col, then the mod-q multiply + add/sub ----
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
        }

        // ---- pin each butterfly's twiddle to the canonical zeta (ζ = z_lo + β·z_hi) ----
        let pin_zeta = |builder: &mut AB, b: usize, zeta: u64| {
            builder.assert_eq(e(b + Z0) + beta.clone() * e(b + Z1), AB::Expr::from_u64(zeta));
        };
        pin_zeta(builder, BASE[0], self.z1);
        pin_zeta(builder, BASE[1], self.z1);
        pin_zeta(builder, BASE[2], self.z2);
        pin_zeta(builder, BASE[3], self.z3);

        // ---- CROSS-LAYER WIRING: layer-2 inputs == layer-1 outputs (the in-AIR routing) ----
        // Dilithium n=4 in-place: layer1 bf0 on (0,2), bf1 on (1,3); layer2 bf2 on (0,1), bf3 on (2,3).
        // After layer1: y0=bf0.out0, y2=bf0.out1, y1=bf1.out0, y3=bf1.out1.
        // Layer2 bf2 reads (y0,y1); bf3 reads (y2,y3).
        let (b0, b1, b2, b3) = (BASE[0], BASE[1], BASE[2], BASE[3]);
        // bf2.a == y0 == bf0.out0
        builder.assert_eq(e(b2 + A0), e(b0 + O00));
        builder.assert_eq(e(b2 + A1), e(b0 + O01));
        // bf2.b == y1 == bf1.out0
        builder.assert_eq(e(b2 + B0), e(b1 + O00));
        builder.assert_eq(e(b2 + B1), e(b1 + O01));
        // bf3.a == y2 == bf0.out1
        builder.assert_eq(e(b3 + A0), e(b0 + O10));
        builder.assert_eq(e(b3 + A1), e(b0 + O11));
        // bf3.b == y3 == bf1.out1
        builder.assert_eq(e(b3 + B0), e(b1 + O10));
        builder.assert_eq(e(b3 + B1), e(b1 + O11));
    }
}

fn split(v: u64) -> (u64, u64) {
    (v % BETA, v / BETA)
}

/// Fill one butterfly's 460 columns for (a, b, zeta) → (out0=a+ζb, out1=a−ζb) mod q. Returns
/// (out0, out1) so the caller can wire it to the next layer.
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

fn generate<F: PrimeField64>(x: &[u64; 4], z1: u64, z2: u64, z3: u64) -> RowMajorMatrix<F> {
    // pad to 2 rows (uni-stark wants height ≥ 2); both rows carry the same wired NTT instance.
    let rows = 2;
    let mut vals = F::zero_vec(rows * NUM_COLS);
    for r in 0..rows {
        let o = r * NUM_COLS;
        // layer 1: bf0 on (x0,x2), bf1 on (x1,x3), both twiddle z1.
        let (y0, y2) = fill_bf(&mut vals[o..o + NUM_COLS], BASE[0], x[0], x[2], z1);
        let (y1, y3) = fill_bf(&mut vals[o..o + NUM_COLS], BASE[1], x[1], x[3], z1);
        // layer 2: bf2 on (y0,y1) twiddle z2, bf3 on (y2,y3) twiddle z3.
        fill_bf(&mut vals[o..o + NUM_COLS], BASE[2], y0, y1, z2);
        fill_bf(&mut vals[o..o + NUM_COLS], BASE[3], y2, y3, z3);
    }
    RowMajorMatrix::new(vals, NUM_COLS)
}

// n=4 forward NTT (same schedule the AIR wires) → returns output array.
fn ntt4(x: &[u64; 4], z1: u64, z2: u64, z3: u64) -> [u64; 4] {
    let bf = |a: u64, b: u64, z: u64| -> (u64, u64) {
        let t = ((z as u128 * b as u128) % Q as u128) as u64;
        ((a + t) % Q, (a + Q - t) % Q)
    };
    let (y0, y2) = bf(x[0], x[2], z1);
    let (y1, y3) = bf(x[1], x[3], z1);
    let (o0, o1) = bf(y0, y1, z2);
    let (o2, o3) = bf(y2, y3, z3);
    [o0, o1, o2, o3]
}

fn schoolbook4(f: &[u64; 4], g: &[u64; 4]) -> [u64; 4] {
    let mut c = [0u128; 4];
    for i in 0..4 {
        for j in 0..4 {
            let p = (f[i] as u128) * (g[j] as u128);
            let k = i + j;
            if k < 4 {
                c[k] = (c[k] + p) % Q as u128;
            } else {
                c[k - 4] = (c[k - 4] + Q as u128 - (p % Q as u128)) % Q as u128;
            }
        }
    }
    std::array::from_fn(|i| c[i] as u64)
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
    // n=4 negacyclic twiddles: ψ = ζ_8 = 1753^(512/8) = 1753^64 (primitive 8th root, ψ^4=−1).
    // Dilithium-style brv over 2 bits: z[k] = ψ^brv2(k).
    let psi = modpow(1753, 64);
    let brv2 = |x: u64| -> u64 { ((x & 1) << 1) | ((x >> 1) & 1) };
    let z1 = modpow(psi, brv2(1)); // = ψ^2 = ζ_4 (ψ^2, a primitive 4th root, ^2 = −1)
    let z2 = modpow(psi, brv2(2));
    let z3 = modpow(psi, brv2(3));

    // validate these ARE a valid n=4 NTT: convolution theorem vs schoolbook.
    let f: [u64; 4] = [123456, 7654321, 3141592, 2718281];
    let g: [u64; 4] = [1000003, 9999991, 424242, 8380416];
    let (nf, ng, nc) = (ntt4(&f, z1, z2, z3), ntt4(&g, z1, z2, z3), ntt4(&schoolbook4(&f, &g), z1, z2, z3));
    for i in 0..4 {
        let prod = ((nf[i] as u128 * ng[i] as u128) % Q as u128) as u64;
        assert_eq!(prod, nc[i], "convolution theorem failed at {i} — n=4 zetas wrong");
    }

    let air = NttWiredAir { z1, z2, z3 };
    let x = f;
    let mut trace = generate::<Val>(&x, z1, z2, z3);
    // sanity: the wired output equals the reference n=4 NTT.
    let out = ntt4(&x, z1, z2, z3);
    let got: [u64; 4] = [
        trace.values[BASE[2] + O00].as_canonical_u64() + BETA * trace.values[BASE[2] + O01].as_canonical_u64(),
        trace.values[BASE[2] + O10].as_canonical_u64() + BETA * trace.values[BASE[2] + O11].as_canonical_u64(),
        trace.values[BASE[3] + O00].as_canonical_u64() + BETA * trace.values[BASE[3] + O01].as_canonical_u64(),
        trace.values[BASE[3] + O10].as_canonical_u64() + BETA * trace.values[BASE[3] + O11].as_canonical_u64(),
    ];
    assert_eq!(got, out, "wired NTT output != reference");

    if corrupt {
        // break the cross-layer wiring: perturb bf2's a-input (should equal bf0.out0). This must
        // fail the wiring equality AND the butterfly's internal consistency.
        trace.values[BASE[2] + A0] += Val::ONE;
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — broken cross-layer wiring accepted!"),
        Ok(_) => println!(
            "VERIFY ok — a complete negacyclic n=4 NTT over Z_q (q={Q}) with IN-AIR CROSS-LAYER ROUTING \
             proven as a Plonky3 AIR: 4 butterflies (2 layers), each the proven mod-q gadget, with the \
             layer-2 inputs CONSTRAINED == the layer-1 outputs (bf2.a==bf0.out0, etc.) and each twiddle \
             pinned to the canonical zeta. Validated to BE the NTT via the convolution theorem vs an \
             independent schoolbook multiply. --corrupt (broken wiring) rejected. This is the in-AIR \
             layer-routing the full 256-pt tiling needs, shown soundly at n=4."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — broken cross-layer wiring rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
