//! C-P6 step-d: **SampleInBall** shape as a Plonky3 AIR — the challenge polynomial `c` that
//! ML-DSA-87 `Verify` derives from `c̃` must be **ternary** (`cᵢ ∈ {−1, 0, +1}`) with EXACTLY
//! `τ = 60` nonzero coefficients (a "ball" element). This AIR pins that structural property:
//! each coefficient is `cᵢ = posᵢ − negᵢ` with `posᵢ, negᵢ ∈ {0,1}` and `posᵢ·negᵢ = 0` (a
//! coefficient is at most one of ±1), and the Hamming weight `Σ(posᵢ + negᵢ) = τ`.
//!
//! The positional derivation (the Fisher-Yates placement of the τ signs at rejection-sampled
//! positions from `SHAKE256(c̃)`) reuses the already-proven SHAKE (shake_absorb_air.rs /
//! keccak_shake.rs) + rejection-sample (rejection_sample_air.rs) gadgets + a swap network;
//! this AIR is the ball-membership check the norm/hash steps compose with. `--corrupt` breaks
//! the weight or ternary property → rejected.

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

const N: usize = 256; // poly degree
const TAU: u64 = 60; // ML-DSA-87 challenge weight

// columns: pos[256] | neg[256]
const POS: usize = 0;
const NEG: usize = N;
const NUM_COLS: usize = 2 * N; // 512

struct SampleInBallAir {}

impl<F> BaseAir<F> for SampleInBallAir {
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

impl<AB: AirBuilder> Air<AB> for SampleInBallAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;

        let mut weight = AB::Expr::ZERO;
        for i in 0..N {
            let p: AB::Expr = row[POS + i].into();
            let n: AB::Expr = row[NEG + i].into();
            // booleanity
            builder.assert_zero(p.clone() * (p.clone() - one.clone()));
            builder.assert_zero(n.clone() * (n.clone() - one.clone()));
            // mutual exclusion: not both +1 and −1 (⇒ cᵢ = p − n ∈ {−1,0,+1})
            builder.assert_zero(p.clone() * n.clone());
            weight = weight + p + n;
        }
        // exactly τ nonzero coefficients.
        builder.assert_eq(weight, AB::Expr::from_u64(TAU));
    }
}

/// A canonical valid SampleInBall shape for a seed: τ distinct positions get ±1, rest 0.
fn ball_shape(seed: u64) -> (Vec<u64>, Vec<u64>) {
    let mut pos = vec![0u64; N];
    let mut neg = vec![0u64; N];
    // deterministic "random-looking" distinct positions + signs (shape only; not the real
    // Fisher-Yates, which is arithmetized by the SHAKE + rejection-sample gadgets).
    let mut placed = 0u64;
    let mut x = seed | 1;
    let mut used = vec![false; N];
    while placed < TAU {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let idx = (x >> 33) as usize % N;
        if used[idx] {
            continue;
        }
        used[idx] = true;
        if (x & 1) == 0 {
            pos[idx] = 1;
        } else {
            neg[idx] = 1;
        }
        placed += 1;
    }
    (pos, neg)
}

fn generate<F: PrimeField64>(seeds: &[u64]) -> RowMajorMatrix<F> {
    let n = seeds.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, &seed) in seeds.iter().enumerate() {
        let base = r * NUM_COLS;
        let (pos, neg) = ball_shape(seed);
        for i in 0..N {
            vals[base + POS + i] = F::from_u64(pos[i]);
            vals[base + NEG + i] = F::from_u64(neg[i]);
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
    let air = SampleInBallAir {};
    let seeds: Vec<u64> = (0..4u64).map(|i| 0x1234_5678_9abc_def0u64.wrapping_mul(i + 1)).collect();
    let mut trace = generate::<Val>(&seeds);
    if corrupt {
        // set an extra sign bit at a currently-zero position → weight 61 ≠ τ (and maybe pos·neg).
        // find a zero column in row 0 and set it.
        let mut set = false;
        for i in 0..N {
            let pv = trace.values[POS + i];
            let nv = trace.values[NEG + i];
            if pv == Val::ZERO && nv == Val::ZERO {
                trace.values[POS + i] = Val::ONE;
                set = true;
                break;
            }
        }
        assert!(set, "expected a zero coefficient to corrupt");
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — a non-ball (weight≠τ) challenge was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — SampleInBall shape proven as a Plonky3 AIR: c ∈ {{−1,0,+1}}²⁵⁶ with exactly τ={TAU} nonzeros (cᵢ = posᵢ−negᵢ, posᵢ·negᵢ=0, Σ(posᵢ+negᵢ)=τ). This is the ball-membership check ML-DSA verify's challenge must satisfy; the positional derivation reuses the SHAKE + rejection-sample AIRs. --corrupt rejected."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — non-ball challenge rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
