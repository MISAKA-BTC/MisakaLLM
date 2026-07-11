//! C-P6 step-g: the **hint-weight bound** `#{h = 1} ≤ ω` as a Plonky3 AIR — one of the
//! ML-DSA-87 `Verify` acceptance checks (`ω = 75`). The signature's hint vector `h` must have
//! at most ω set bits across all polynomials; a verifier that skips this accepts malformed
//! signatures. The gadget: booleanity of every hint bit, `sum = Σ hᵢ` (a linear popcount),
//! and the sound `≤`: `sum + slack = ω` with `slack ∈ [0, 256)` range-checked (so `sum ≤ ω`;
//! if `sum > ω`, `slack = ω − sum` is negative → out of range → rejected). Every value is
//! `< 2⁹ < p`. Same `value + slack = bound` comparator as the norm bound `‖z‖∞ < γ1−β` and
//! `rejection_sample_air.rs`. `--corrupt` flips a hint bit past the bound → rejected.

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

const OMEGA: u64 = 75; // ML-DSA-87 hint weight bound
const NBITS: usize = 256; // hint bits in this block (one poly's worth)
const SLACK_BITS: usize = 9; // slack < 512 covers [0, ω] and the 256-bit sum

// columns: hint bits (256) | sum | slack | slack bits (9)
const HINT: usize = 0;
const SUM: usize = NBITS;
const SLACK: usize = NBITS + 1;
const SLACK_B: usize = NBITS + 2;
const NUM_COLS: usize = NBITS + 2 + SLACK_BITS; // 267

struct PopcountBoundAir {}

impl<F> BaseAir<F> for PopcountBoundAir {
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

impl<AB: AirBuilder> Air<AB> for PopcountBoundAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;

        // booleanity of hint bits + slack bits.
        let mut sum = AB::Expr::ZERO;
        for i in 0..NBITS {
            let h: AB::Expr = row[HINT + i].into();
            builder.assert_zero(h.clone() * (h.clone() - one.clone()));
            sum = sum + h;
        }
        for j in 0..SLACK_BITS {
            let b: AB::Expr = row[SLACK_B + j].into();
            builder.assert_zero(b.clone() * (b - one.clone()));
        }

        // sum = Σ hint bits (linear popcount).
        builder.assert_eq(row[SUM].into(), sum);

        // slack = Σ slack bits (range-checked to [0, 2^9)).
        let mut sl = AB::Expr::ZERO;
        let mut w = AB::Expr::ONE;
        for j in 0..SLACK_BITS {
            sl = sl + row[SLACK_B + j].into() * w.clone();
            w = w.clone() + w.clone();
        }
        builder.assert_eq(row[SLACK].into(), sl);

        // the sound ≤ : sum + slack = ω  ⇒  sum ≤ ω (slack ≥ 0 range-checked).
        let omega = AB::Expr::from_u64(OMEGA);
        builder.assert_eq(row[SUM].into() + row[SLACK].into(), omega);
    }
}

fn generate<F: PrimeField64>(weights: &[u64]) -> RowMajorMatrix<F> {
    let n = weights.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, &w) in weights.iter().enumerate() {
        assert!(w <= OMEGA, "gen only builds valid (≤ω) rows");
        let base = r * NUM_COLS;
        // set the first `w` hint bits (a canonical weight-w vector).
        for i in 0..(w as usize) {
            vals[base + HINT + i] = F::ONE;
        }
        let slack = OMEGA - w;
        vals[base + SUM] = F::from_u64(w);
        vals[base + SLACK] = F::from_u64(slack);
        for j in 0..SLACK_BITS {
            vals[base + SLACK_B + j] = F::from_u64((slack >> j) & 1);
        }
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
    let air = PopcountBoundAir {};
    // 4 hint vectors with weights straddling ω (all valid ≤ ω): 0, 40, 74, 75.
    let weights = [0u64, 40, 74, OMEGA];
    let mut trace = generate::<Val>(&weights);
    if corrupt {
        // set one more hint bit in the ω-weight row (row 3) → weight 76 > ω, breaks sum+slack=ω.
        trace.values[3 * NUM_COLS + HINT + (OMEGA as usize)] += Val::ONE;
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — a hint of weight > ω was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — hint-weight bound #{{h=1}} ≤ ω proven as a Plonky3 AIR (ω={OMEGA}, 256-bit popcount, weights 0/40/74/75): sum = Σ hᵢ, sum + slack = ω with slack range-checked ⇒ sum ≤ ω. This is an ML-DSA verify acceptance check; the same comparator serves ‖z‖∞ < γ1−β."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — over-weight hint rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
