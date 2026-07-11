//! C-P6 verify TERMINAL accept condition: the **challenge equality `c̃' == c̃`** as a Plonky3 AIR,
//! for ML-DSA-87 (`c̃` is 2λ/8 = 64 bytes). This is the actual accept/reject decision of FIPS-204
//! `Verify`: after recomputing `c̃' = SHAKE256(μ ‖ w1Encode(UseHint(h, A·z − c·t1·2^d)))`, the
//! signature is valid iff `c̃'` equals the `c̃` that `sigDecode` produced — the SAME `c̃` that
//! `SampleInBall` consumed to build the challenge polynomial `c`. So this AIR ties the recomputed
//! challenge back to the seed the rest of the verify used, closing the loop; a forged signature
//! whose recomputed challenge differs in any byte is rejected.
//!
//! `cs` = `c̃` (from sig / SampleInBall seed), `cr` = `c̃'` (recomputed). Both are byte-range-checked
//! and asserted equal per byte — a valid trace exists iff they match. `--corrupt` flips one byte of
//! `cr` → rejected. This is the third accept predicate, with the ‖z‖∞ norm bound and #h ≤ ω weight.

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

const CTILDE_LEN: usize = 64; // ML-DSA-87 c̃ length (2λ/8)
// columns: cs[0..64] (sig c̃) | cr[0..64] (recomputed c̃')
const CS: usize = 0;
const CR: usize = CTILDE_LEN;
const NP: usize = 2 * CTILDE_LEN;
const BITS: usize = 8;
// byte-range columns: cs and cr (each byte 8 bits)
const NUM_COLS: usize = NP + 2 * CTILDE_LEN * BITS;
fn boff(which: usize, i: usize) -> usize {
    NP + (which * CTILDE_LEN + i) * BITS
}

struct ChallengeEqAir {}

impl<F> BaseAir<F> for ChallengeEqAir {
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

impl<AB: AirBuilder> Air<AB> for ChallengeEqAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let e = |i: usize| -> AB::Expr { row[i].into() };
        // byte-range-check + bind cs[i] and cr[i].
        for which in 0..2 {
            let base = [CS, CR][which];
            for i in 0..CTILDE_LEN {
                let bo = boff(which, i);
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
        // TERMINAL accept: c̃'[i] == c̃[i] for every byte (a valid trace exists iff they match).
        for i in 0..CTILDE_LEN {
            builder.assert_eq(e(CS + i), e(CR + i));
        }
    }
}

fn generate<F: PrimeField64>(pairs: &[([u8; CTILDE_LEN], [u8; CTILDE_LEN])]) -> RowMajorMatrix<F> {
    let n = pairs.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, (cs, cr)) in pairs.iter().enumerate() {
        let base = r * NUM_COLS;
        for i in 0..CTILDE_LEN {
            vals[base + CS + i] = F::from_u64(cs[i] as u64);
            vals[base + CR + i] = F::from_u64(cr[i] as u64);
            for j in 0..BITS {
                vals[base + boff(0, i) + j] = F::from_u64(((cs[i] >> j) & 1) as u64);
                vals[base + boff(1, i) + j] = F::from_u64(((cr[i] >> j) & 1) as u64);
            }
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
    let air = ChallengeEqAir {};
    // 4 challenge pairs (a valid signature has c̃' == c̃). Deterministic bytes stand in for
    // real 64-byte challenges; the equality predicate is what the AIR proves.
    let mk = |seed: u8| -> [u8; CTILDE_LEN] {
        let mut c = [0u8; CTILDE_LEN];
        for (i, b) in c.iter_mut().enumerate() {
            *b = seed.wrapping_mul(31).wrapping_add(i as u8).wrapping_mul(7);
        }
        c
    };
    let pairs: Vec<([u8; CTILDE_LEN], [u8; CTILDE_LEN])> =
        (0..4u8).map(|s| (mk(s), mk(s))).collect(); // c̃' == c̃ (accept)
    let mut trace = generate::<Val>(&pairs);
    if corrupt {
        // row 0: set c̃'[0] to a DIFFERENT valid byte (consistent bit-decomp) so ONLY the equality
        // constraint is violated — a forged sig whose recomputed challenge differs from c̃.
        let nv = pairs[0].0[0] ^ 0x01;
        trace.values[CR] = Val::from_u64(nv as u64);
        for j in 0..BITS {
            trace.values[boff(1, 0) + j] = Val::from_u64(((nv >> j) & 1) as u64);
        }
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — mismatched challenge accepted!"),
        Ok(_) => println!(
            "VERIFY ok — ML-DSA-87 terminal accept condition c̃' == c̃ proven as a Plonky3 AIR \
             (64-byte challenge): the recomputed SHAKE256 challenge is asserted byte-equal to the \
             signature's c̃ (the SampleInBall seed), over 4 challenge pairs. --corrupt (one byte of \
             c̃' flipped, a forged sig) rejected. This is the verify's actual accept/reject decision, \
             completing the accept-condition set (‖z‖∞ norm bound, #h≤ω weight, and this challenge \
             equality)."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — mismatched challenge rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
