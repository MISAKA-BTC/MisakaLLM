//! C-P6 verify acceptance predicate: the **hint weight `#h ≤ ω`** check as a Plonky3 AIR, for
//! ML-DSA-87 (ω=75, k=8). This is the second FIPS-204 `Verify` accept predicate (the first being
//! the ‖z‖∞ norm bound). In `HintBitUnpack` the last `k` bytes of the hint are the per-polynomial
//! CUMULATIVE set-position counts `b[0..k]`; a hint is valid only if these are **non-decreasing**
//! and every `b[i] ≤ ω`, which makes the total hint weight `#h = b[k−1] ≤ ω`. A forged signature
//! that sets too many hint bits (to force an accept) violates this and is rejected.
//!
//! Each `b[i]` is checked with two 8-bit range slacks: `slo = b[i]−b[i−1] ≥ 0` (monotone, b[−1]=0)
//! and `shi = ω−b[i] ≥ 0` (bounded). One row = one hint's boundary vector; `--corrupt` makes the
//! counts non-monotone → rejected. (The complementary per-position strict-increase / unused-zero
//! canonicity is the other half of HintBitUnpack; this AIR proves the weight-bound accept check.)

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

const OMEGA: i64 = 75; // ML-DSA-87 ω
const K: usize = 8; // ML-DSA-87 k (rows of t1 / polys in the hint)
// columns: b[0..K] | slo[0..K] | shi[0..K] | weight
const B: usize = 0;
const SLO: usize = K;
const SHI: usize = 2 * K;
const W: usize = 3 * K;
const NP: usize = 3 * K + 1;
const BITS: usize = 8; // ω=75, counts and slacks all < 256
const NUM_COLS: usize = NP + 3 * K * BITS;
fn boff(kind: usize, i: usize) -> usize {
    NP + (kind * K + i) * BITS
}

struct HintAir {}

impl<F> BaseAir<F> for HintAir {
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

impl<AB: AirBuilder> Air<AB> for HintAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let e = |i: usize| -> AB::Expr { row[i].into() };
        // range-check + bind every b[i], slo[i], shi[i] to 8 bits.
        for kind in 0..3 {
            let base = [B, SLO, SHI][kind];
            for i in 0..K {
                let bo = boff(kind, i);
                let mut acc = AB::Expr::ZERO;
                let mut wt = AB::Expr::ONE;
                for j in 0..BITS {
                    let b: AB::Expr = row[bo + j].into();
                    builder.assert_zero(b.clone() * (b.clone() - one.clone()));
                    acc = acc + b * wt.clone();
                    wt = wt.clone() + wt.clone();
                }
                builder.assert_eq(e(base + i), acc);
            }
        }
        let omega = AB::Expr::from_u64(OMEGA as u64);
        // monotone: b[0] = slo[0]; b[i] = b[i-1] + slo[i]  (slo ≥ 0 by the 8-bit range).
        builder.assert_eq(e(B), e(SLO));
        for i in 1..K {
            builder.assert_eq(e(B + i), e(B + i - 1) + e(SLO + i));
        }
        // bounded: b[i] + shi[i] = ω  (shi ≥ 0 ⇒ b[i] ≤ ω).
        for i in 0..K {
            builder.assert_eq(e(B + i) + e(SHI + i), omega.clone());
        }
        // weight = b[K-1] (= total set positions, ≤ ω by the last bound).
        builder.assert_eq(e(W), e(B + K - 1));
    }
}

/// Reference acceptance: boundary counts non-decreasing and each ≤ ω (⇒ weight = b[k−1] ≤ ω).
fn accepts(b: &[i64; K]) -> bool {
    let mut prev = 0i64;
    for &x in b {
        if x < prev || x > OMEGA {
            return false;
        }
        prev = x;
    }
    true
}

fn generate<F: PrimeField64>(hints: &[[i64; K]]) -> RowMajorMatrix<F> {
    let n = hints.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    let put_bits = |vals: &mut [F], off: usize, v: i64| {
        for j in 0..BITS {
            vals[off + j] = F::from_u64(((v >> j) & 1) as u64);
        }
    };
    for (r, b) in hints.iter().enumerate() {
        let base = r * NUM_COLS;
        assert!(accepts(b), "test hint must be valid: {b:?}");
        let mut prev = 0i64;
        for i in 0..K {
            let slo = b[i] - prev;
            let shi = OMEGA - b[i];
            vals[base + B + i] = F::from_u64(b[i] as u64);
            vals[base + SLO + i] = F::from_u64(slo as u64);
            vals[base + SHI + i] = F::from_u64(shi as u64);
            put_bits(&mut vals, base + boff(0, i), b[i]);
            put_bits(&mut vals, base + boff(1, i), slo);
            put_bits(&mut vals, base + boff(2, i), shi);
            prev = b[i];
        }
        vals[base + W] = F::from_u64(b[K - 1] as u64);
    }
    RowMajorMatrix::new(vals, NUM_COLS)
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
    let air = HintAir {};
    // representative valid hint boundary vectors incl. the tight case (weight = ω exactly),
    // repeats (some polys contribute no hints), and low weight.
    let hints: Vec<[i64; K]> = vec![
        [10, 20, 30, 40, 50, 60, 70, 75], // weight 75 = ω (tightest)
        [0, 0, 5, 5, 5, 20, 20, 60],       // repeats (empty polys)
        [8, 16, 24, 32, 40, 48, 56, 64],
        [75, 75, 75, 75, 75, 75, 75, 75], // all in poly 0, weight 75 = ω
        [0, 0, 0, 0, 0, 0, 0, 0],          // no hints at all
        [1, 2, 3, 4, 5, 6, 7, 8],
        [9, 18, 27, 36, 45, 54, 63, 72],
        [0, 10, 10, 25, 25, 40, 55, 70],
    ];
    for h in &hints {
        assert!(accepts(h));
    }
    // sanity: a >ω or non-monotone vector is rejected by the reference.
    assert!(!accepts(&[10, 20, 30, 40, 50, 60, 70, 76]), "weight 76 > ω must fail");
    assert!(!accepts(&[10, 5, 30, 40, 50, 60, 70, 75]), "non-monotone must fail");
    let mut trace = generate::<Val>(&hints);
    if corrupt {
        // make row 0 non-monotone: b[1] < b[0] ⇒ slo[1] would be negative ⇒ 8-bit range fails.
        trace.values[B + 1] = Val::from_u64(3); // was 20, now 3 < b[0]=10
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — invalid hint weight accepted!"),
        Ok(_) => println!(
            "VERIFY ok — ML-DSA-87 hint-weight #h ≤ ω acceptance predicate proven as a Plonky3 AIR \
             (ω=75, k=8): the HintBitUnpack cumulative boundary counts are checked non-decreasing \
             (8-bit slo slack) and each ≤ ω (8-bit shi slack), so weight = b[k−1] ≤ ω, over 8 valid \
             boundary vectors incl. the tight weight=ω case and empty polys. --corrupt (non-monotone) \
             rejected. This is the second verify accept predicate (with the ‖z‖∞ norm bound)."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — invalid hint weight rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
