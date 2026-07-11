//! C-P6 integration: **in-AIR cross-layer routing for a COMPLETE small NTT** — a full negacyclic
//! n=8 NTT over Z_q (q=8380417) whose ENTIRE layer-to-layer data flow is bound inside the AIR.
//! Twelve butterflies (all 3 = log₂8 layers) live in one row; each is the proven butterfly gadget
//! (base-β limb-carry multiply + single-carry add/sub, every residue <q range-checked). The
//! genuinely-new part over the n=4 demo (`ntt_wired_air.rs`, 2 layers) is DEPTH: this wires a
//! COMPLETE transform through all three layers — layer-2 butterfly inputs are constrained EQUAL to
//! the layer-1 outputs that produced them, and layer-3 inputs EQUAL to the layer-2 outputs — so a
//! prover cannot feed any layer anything other than what the previous layer produced across the
//! whole NTT, not just one hop. Every twiddle is pinned to the canonical zeta. The transform is
//! validated to BE the n=8 NTT via the convolution theorem `NTT(f)∘NTT(g) == NTT(f·g mod x⁸+1)`
//! vs an independent schoolbook multiply. `--corrupt` (break the wiring / an output) → rejected.
//!
//! This scales the single-row `==`-routing technique from a partial (2-layer) demo to a complete
//! (all-layer) transform. The 256-pt tiling still needs the multi-row generalization (a
//! permutation/lookup argument binding row-i outputs to row-j inputs), which uni-stark does not
//! expose here; this establishes that the routing composes cleanly through a full layer schedule.

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

// one butterfly's 38 primary columns (same layout as ntt_butterfly.rs / ntt_wired_air.rs) then bits.
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
const NBF: usize = 12; // 4 (layer1) + 4 (layer2) + 4 (layer3)
const NUM_COLS: usize = NBF * BF_COLS;
// butterfly bases in schedule order:
//   layer1 (len=4): bf0=(0,4) bf1=(1,5) bf2=(2,6) bf3=(3,7)
//   layer2 (len=2): bf4=(0,2) bf5=(1,3) bf6=(4,6) bf7=(5,7)
//   layer3 (len=1): bf8=(0,1) bf9=(2,3) bf10=(4,5) bf11=(6,7)
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

/// AIR carrying the seven canonical n=8 twiddles (zetas[k], k=1..7) so every butterfly's zeta is
/// pinned to the ML-DSA-style value.
struct NttWired8Air {
    zetas: [u64; 7],
}

impl<F> BaseAir<F> for NttWired8Air {
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

impl<AB: AirBuilder> Air<AB> for NttWired8Air {
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
        // layer1 (k=1): zetas[0]; layer2 (k=2,3): zetas[1],zetas[2]; layer3 (k=4..7): zetas[3..7].
        let pin = |builder: &mut AB, b: usize, zeta: u64| {
            builder.assert_eq(e(b + Z0) + beta.clone() * e(b + Z1), AB::Expr::from_u64(zeta));
        };
        pin(builder, BASE[0], self.zetas[0]);
        pin(builder, BASE[1], self.zetas[0]);
        pin(builder, BASE[2], self.zetas[0]);
        pin(builder, BASE[3], self.zetas[0]);
        pin(builder, BASE[4], self.zetas[1]);
        pin(builder, BASE[5], self.zetas[1]);
        pin(builder, BASE[6], self.zetas[2]);
        pin(builder, BASE[7], self.zetas[2]);
        pin(builder, BASE[8], self.zetas[3]);
        pin(builder, BASE[9], self.zetas[4]);
        pin(builder, BASE[10], self.zetas[5]);
        pin(builder, BASE[11], self.zetas[6]);

        // ---- CROSS-LAYER WIRING: each layer's inputs == the previous layer's outputs ----
        // in-place positions (a[0..8]): layer1 writes pos_j=bf.out0, pos_{j+4}=bf.out1, etc.
        // `wire(dst, a|b, src, out0|out1)` asserts both β-limbs equal.
        let wire = |builder: &mut AB, db: usize, d_lo: usize, d_hi: usize, sb: usize, s_lo: usize, s_hi: usize| {
            builder.assert_eq(e(db + d_lo), e(sb + s_lo));
            builder.assert_eq(e(db + d_hi), e(sb + s_hi));
        };
        let (bf0, bf1, bf2, bf3) = (BASE[0], BASE[1], BASE[2], BASE[3]);
        let (bf4, bf5, bf6, bf7) = (BASE[4], BASE[5], BASE[6], BASE[7]);
        let (bf8, bf9, bf10, bf11) = (BASE[8], BASE[9], BASE[10], BASE[11]);
        // layer2 reads layer1 outputs:
        //   bf4=(pos0,pos2)=(bf0.out0,bf2.out0)  bf5=(pos1,pos3)=(bf1.out0,bf3.out0)
        //   bf6=(pos4,pos6)=(bf0.out1,bf2.out1)  bf7=(pos5,pos7)=(bf1.out1,bf3.out1)
        wire(builder, bf4, A0, A1, bf0, O00, O01);
        wire(builder, bf4, B0, B1, bf2, O00, O01);
        wire(builder, bf5, A0, A1, bf1, O00, O01);
        wire(builder, bf5, B0, B1, bf3, O00, O01);
        wire(builder, bf6, A0, A1, bf0, O10, O11);
        wire(builder, bf6, B0, B1, bf2, O10, O11);
        wire(builder, bf7, A0, A1, bf1, O10, O11);
        wire(builder, bf7, B0, B1, bf3, O10, O11);
        // layer3 reads layer2 outputs:
        //   bf8=(pos0,pos1)=(bf4.out0,bf5.out0)  bf9=(pos2,pos3)=(bf4.out1,bf5.out1)
        //   bf10=(pos4,pos5)=(bf6.out0,bf7.out0) bf11=(pos6,pos7)=(bf6.out1,bf7.out1)
        wire(builder, bf8, A0, A1, bf4, O00, O01);
        wire(builder, bf8, B0, B1, bf5, O00, O01);
        wire(builder, bf9, A0, A1, bf4, O10, O11);
        wire(builder, bf9, B0, B1, bf5, O10, O11);
        wire(builder, bf10, A0, A1, bf6, O00, O01);
        wire(builder, bf10, B0, B1, bf7, O00, O01);
        wire(builder, bf11, A0, A1, bf6, O10, O11);
        wire(builder, bf11, B0, B1, bf7, O10, O11);
    }
}

fn split(v: u64) -> (u64, u64) {
    (v % BETA, v / BETA)
}

/// Fill one butterfly's 460 columns for (a, b, zeta) → (out0=a+ζb, out1=a−ζb) mod q. Returns
/// (out0, out1) so the caller can thread it into the in-place array.
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

/// Fill all 12 butterflies of the in-place n=8 CT schedule in schedule order (BF0..BF11), threading
/// each butterfly's outputs back into the working array exactly as the reference NTT does.
fn generate<F: PrimeField64>(x: &[u64; 8], zetas: &[u64; 7]) -> RowMajorMatrix<F> {
    let rows = 2; // uni-stark wants height ≥ 2; both rows carry the same wired NTT instance.
    let mut vals = F::zero_vec(rows * NUM_COLS);
    for r in 0..rows {
        let o = r * NUM_COLS;
        let seg = &mut vals[o..o + NUM_COLS];
        let mut a = *x;
        let mut bf = 0usize;
        let mut k = 0usize;
        let mut len = 4;
        while len >= 1 {
            let mut start = 0;
            while start < 8 {
                k += 1;
                let zeta = zetas[k - 1];
                for j in start..start + len {
                    let (o0, o1) = fill_bf(seg, BASE[bf], a[j], a[j + len], zeta);
                    a[j] = o0;
                    a[j + len] = o1;
                    bf += 1;
                }
                start += 2 * len;
            }
            if len == 1 {
                break;
            }
            len /= 2;
        }
    }
    RowMajorMatrix::new(vals, NUM_COLS)
}

/// n=8 forward NTT (the exact schedule the AIR wires) → returns the transformed array.
fn ntt8(x: &[u64; 8], zetas: &[u64; 7]) -> [u64; 8] {
    let mut a = *x;
    let mut k = 0usize;
    let mut len = 4;
    while len >= 1 {
        let mut start = 0;
        while start < 8 {
            k += 1;
            let zeta = zetas[k - 1];
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

/// Independent schoolbook negacyclic product `f · g mod (x⁸ + 1)` — the ground truth.
fn schoolbook8(f: &[u64; 8], g: &[u64; 8]) -> [u64; 8] {
    let mut c = [0u128; 8];
    for i in 0..8 {
        for j in 0..8 {
            let p = (f[i] as u128) * (g[j] as u128);
            let k = i + j;
            if k < 8 {
                c[k] = (c[k] + p) % Q as u128;
            } else {
                c[k - 8] = (c[k - 8] + Q as u128 - (p % Q as u128)) % Q as u128; // x^8 = −1
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
    // n=8 negacyclic twiddles: ψ = 1753^(512/16) = 1753^32 (primitive 16th root, ψ^8 = −1).
    // Dilithium-style brv over log₂(n)=3 bits: zetas[k] = ψ^brv3(k), k = 1..7.
    let psi = modpow(1753, 32);
    let brv3 = |x: u64| -> u64 { ((x & 1) << 2) | (x & 2) | ((x >> 2) & 1) };
    let zetas: [u64; 7] = std::array::from_fn(|i| modpow(psi, brv3((i + 1) as u64)));

    // ---- validate these ARE a valid n=8 NTT: convolution theorem vs schoolbook ----
    let f: [u64; 8] = [123456, 7654321, 3141592, 2718281, 1618033, 1414213, 5772156, 8380416];
    let g: [u64; 8] = [1000003, 9999991, 424242, 8380416, 271828, 100000, 999983, 31415];
    let nf = ntt8(&f, &zetas);
    let ng = ntt8(&g, &zetas);
    let nc = ntt8(&schoolbook8(&f, &g), &zetas);
    for i in 0..8 {
        let prod = ((nf[i] as u128 * ng[i] as u128) % Q as u128) as u64;
        assert_eq!(prod, nc[i], "convolution theorem failed at {i} — n=8 zetas/schedule wrong");
    }

    let air = NttWired8Air { zetas };
    let x = f;
    let mut trace = generate::<Val>(&x, &zetas);
    // sanity: the wired output (positions after layer3) equals the reference n=8 NTT.
    let out = ntt8(&x, &zetas);
    // final positions: pos0=bf8.out0,pos1=bf8.out1,pos2=bf9.out0,pos3=bf9.out1,
    //                  pos4=bf10.out0,pos5=bf10.out1,pos6=bf11.out0,pos7=bf11.out1.
    let rd = |bf: usize, lo: usize, hi: usize| -> u64 {
        trace.values[BASE[bf] + lo].as_canonical_u64() + BETA * trace.values[BASE[bf] + hi].as_canonical_u64()
    };
    let got: [u64; 8] = [
        rd(8, O00, O01), rd(8, O10, O11),
        rd(9, O00, O01), rd(9, O10, O11),
        rd(10, O00, O01), rd(10, O10, O11),
        rd(11, O00, O01), rd(11, O10, O11),
    ];
    assert_eq!(got, out, "wired n=8 NTT output != reference");

    if corrupt {
        // break a mid-network cross-layer wire: perturb bf8's a-input (must equal bf4.out0). This
        // fails both the wiring equality AND bf8's internal consistency.
        trace.values[BASE[8] + A0] += Val::ONE;
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — broken cross-layer wiring accepted!"),
        Ok(_) => println!(
            "VERIFY ok — a COMPLETE negacyclic n=8 NTT over Z_q (q={Q}) with FULL in-AIR cross-layer \
             routing proven as a Plonky3 AIR: 12 butterflies across all 3 (=log₂8) layers, each the \
             proven mod-q gadget, with EVERY layer's inputs CONSTRAINED == the previous layer's outputs \
             (bf4.a==bf0.out0 … bf11.b==bf7.out1) and each twiddle pinned to zetas[k]=ψ^brv3(k), \
             ψ=1753^32. Validated to BE the NTT via the convolution theorem NTT(f)∘NTT(g)==NTT(f·g mod \
             x⁸+1) vs an independent schoolbook multiply. --corrupt (broken wiring) rejected. Scales the \
             n=4 2-layer routing to a full-depth transform; 256-pt needs the multi-row lookup generalization."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — broken cross-layer wiring rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
