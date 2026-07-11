//! C-P6 build-order step 2 (AIR): the **mod-q multiply** `t = ζ·b mod q` — the genuinely-new
//! heavy gadget of the in-circuit ML-DSA-87 verify (the NTT butterfly's multiplicative core,
//! cp6 §3 step e) — arithmetized as a real Plonky3 AIR and proven, with a negative test.
//!
//! `q = 8380417 ≈ 2²³`, so `ζ·b` can reach `q² ≈ 2⁴⁶`, which OVERFLOWS the BabyBear field
//! (`p ≈ 2³¹`). A single field equation `ζ·b = m·q + t` is therefore UNSOUND (it holds only
//! mod p, and there are ~8 spurious `(m,t)` that satisfy it plus the range checks via
//! wraparound). The sound construction is base-`β = 2¹²` limbs with an explicit carry chain,
//! so **every intermediate stays `< 2²⁵ < p`** and each field equation is exact over the
//! integers. We verify `ζ·b = m·q + t` by limbifying BOTH sides (`Σ Lᵢβⁱ` and `Σ Mᵢβⁱ`) with
//! carries and asserting the limbs equal, plus a `t < q` slack check so `t` is the canonical
//! residue. `q = 1 + 2046·β` (`Q0=1, Q1=2046`). This is the `Z_q` analogue of build#1's ARX
//! ripple-carry, and it is the arithmetic the diff-tested `ntt_zq.rs` oracle pins.
//!
//! Inputs are range-checked to `[0, 2²³)` via their limbs; input canonicalization (`b<q`,
//! `ζ<q`) is the same slack pattern as `t<q`, omitted here to keep the novel core in focus.
//! `--corrupt` flips a trace cell → the proof must be rejected (soundness).

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
const BETA: u64 = 4096; // 2^12
const Q1: u64 = 2046; // q = 1 + 2046·β  (Q0 = 1)

// primary column indices
const Z0: usize = 0;
const Z1: usize = 1;
const B0: usize = 2;
const B1: usize = 3;
const MC0: usize = 4; // m limb 0
const MC1: usize = 5; // m limb 1
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
const M0: usize = 17; // limb-out (RHS) 0
const M1: usize = 18;
const M2: usize = 19;
const GT0: usize = 20;
const GT1: usize = 21;
const GM0: usize = 22;
const GM1: usize = 23;
const NP: usize = 24;

// bit-widths of each primary column (for the sound range checks)
const WIDTHS: [usize; NP] = [
    12, 11, 12, 11, 12, 11, 12, 11, // z0 z1 b0 b1 m0 m1 t0 t1
    12, 13, 11, 2, 13, 11, //           kL0 kL1 kL2 kR0 kR1 kR2
    12, 12, 12, 12, 12, 12, //          L0 L1 L2 M0 M1 M2
    12, 11, 12, 11, //                  gt0 gt1 gm0 gm1
];
const NUM_COLS: usize = 296; // NP + sum(WIDTHS) = 24 + 272

fn bit_off(col: usize) -> usize {
    NP + WIDTHS[..col].iter().sum::<usize>()
}

struct NttMulAir {}

impl<F> BaseAir<F> for NttMulAir {
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

impl<AB: AirBuilder> Air<AB> for NttMulAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;

        // (1) bind + range-check every primary column via its bit decomposition.
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
            let col: AB::Expr = row[c].into();
            builder.assert_eq(col, acc);
        }

        let beta = AB::Expr::from_u64(BETA);
        let q1 = AB::Expr::from_u64(Q1);
        let qm1 = AB::Expr::from_u64(Q - 1);
        let e = |i: usize| -> AB::Expr { row[i].into() };

        // (2) LHS = ζ·b, limbified with carries: each partial product < 2^24 < p.
        //   s0 = z0·b0                 = L0 + β·kL0
        //   s1 = z0·b1 + z1·b0 + kL0   = L1 + β·kL1
        //   s2 = z1·b1 + kL1           = L2 + β·kL2   (L3 = kL2)
        let p0 = e(Z0) * e(B0);
        builder.assert_eq(p0, e(L0) + beta.clone() * e(KL0));
        let p1 = e(Z0) * e(B1) + e(Z1) * e(B0);
        builder.assert_eq(p1 + e(KL0), e(L1) + beta.clone() * e(KL1));
        let p2 = e(Z1) * e(B1);
        builder.assert_eq(p2 + e(KL1), e(L2) + beta.clone() * e(KL2));

        // (3) RHS = m·q + t, limbified with carries (Q0 = 1, Q1 = 2046):
        //   u0 = m0 + t0               = M0 + β·kR0
        //   u1 = m0·Q1 + m1 + t1 + kR0 = M1 + β·kR1
        //   u2 = m1·Q1 + kR1           = M2 + β·kR2   (M3 = kR2)
        let u0 = e(MC0) + e(T0);
        builder.assert_eq(u0, e(M0) + beta.clone() * e(KR0));
        let u1 = e(MC0) * q1.clone() + e(MC1) + e(T1) + e(KR0);
        builder.assert_eq(u1, e(M1) + beta.clone() * e(KR1));
        let u2 = e(MC1) * q1.clone() + e(KR1);
        builder.assert_eq(u2, e(M2) + beta.clone() * e(KR2));

        // (4) the two limb reps are equal ⇒ ζ·b = m·q + t over the integers.
        builder.assert_eq(e(L0), e(M0));
        builder.assert_eq(e(L1), e(M1));
        builder.assert_eq(e(L2), e(M2));
        builder.assert_eq(e(KL2), e(KR2)); // L3 == M3

        // (5) t < q and m < q (canonical residues): value + slack == q-1, slack range-checked.
        builder.assert_eq(e(T0) + beta.clone() * e(T1) + (e(GT0) + beta.clone() * e(GT1)), qm1.clone());
        builder.assert_eq(e(MC0) + beta.clone() * e(MC1) + (e(GM0) + beta.clone() * e(GM1)), qm1);
    }
}

fn split(v: u64) -> (u64, u64) {
    (v % BETA, v / BETA)
}

fn generate<F: PrimeField64>(data: &[(u64, u64)]) -> RowMajorMatrix<F> {
    let n = data.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, &(b, zeta)) in data.iter().enumerate() {
        let base = r * NUM_COLS;
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

        let u0 = m0 + t0; // Q0 = 1
        let (mm0, kr0) = (u0 % BETA, u0 / BETA);
        let u1 = m0 * Q1 + m1 + t1 + kr0;
        let (mm1, kr1) = (u1 % BETA, u1 / BETA);
        let u2 = m1 * Q1 + kr1;
        let (mm2, kr2) = (u2 % BETA, u2 / BETA);

        // gen-time sanity: the two limb reps of ζ·b must agree.
        assert_eq!((l0, l1, l2, kl2), (mm0, mm1, mm2, kr2), "limb mismatch (b={b}, zeta={zeta})");

        let gt = (Q - 1) - t;
        let (gt0, gt1) = split(gt);
        let gm = (Q - 1) - m;
        let (gm0, gm1) = split(gm);

        let prim = [
            (Z0, z0), (Z1, z1), (B0, b0), (B1, b1), (MC0, m0), (MC1, m1), (T0, t0), (T1, t1),
            (KL0, kl0), (KL1, kl1), (KL2, kl2), (KR0, kr0), (KR1, kr1), (KR2, kr2),
            (L0, l0), (L1, l1), (L2, l2), (M0, mm0), (M1, mm1), (M2, mm2),
            (GT0, gt0), (GT1, gt1), (GM0, gm0), (GM1, gm1),
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

// ---- config (two-adic, verbatim shape from Plonky3 fib_air / atom.rs) ----
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

// the first few Dilithium forward-NTT twiddles ζ^{brv8(k)} mod q, to exercise both limbs.
fn zetas(n: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let modpow = |mut base: u64, mut e: u64| -> u64 {
        let mut r = 1u128;
        let mut b = base as u128 % Q as u128;
        base = 0;
        let _ = base;
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
    for k in 1..=n as u64 {
        out.push(modpow(1753, brv8(k)));
    }
    out
}

fn main() {
    let corrupt = std::env::args().any(|a| a == "--corrupt");
    let air = NttMulAir {};

    // 8 butterfly multiplies over real twiddles × representative coefficients.
    let zs = zetas(8);
    let data: Vec<(u64, u64)> = (0..8usize)
        .map(|i| {
            let b = (0x9e3779b9u64.wrapping_mul((i as u64) + 1)) % Q; // a coefficient < q
            (b, zs[i])
        })
        .collect();

    let mut trace = generate::<Val>(&data);
    if corrupt {
        trace.values[L0] += Val::ONE; // break row 0's LHS limb (and L0==M0)
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt mod-q multiply trace was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — 8 sound mod-q multiplies t = ζ·b mod q proven as a Plonky3 AIR (q={Q}, base-β={BETA} limb carry chain, every intermediate < 2^25 < p; t<q & m<q range-checked). This is the NTT butterfly's multiplicative core = the C-P6 step-e gadget; the diff-tested ntt_zq.rs oracle is now arithmetized."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt mod-q multiply trace rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
