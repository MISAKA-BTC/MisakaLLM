//! Blake2bAtomAir — build-order #1 constraints. The 64-bit ARX atoms of the BLAKE2b
//! G-function, arithmetized as a real Plonky3 AIR and proven against a generated
//! trace, with a negative test (`--corrupt`). p3-blake3-air's `add2/add3` use a
//! 32-bit accumulator trick that does NOT generalize to 64-bit over a 31-bit field
//! (2^64 ≫ char), so the 64-bit path is uniform **bit-level**: XOR is degree-2,
//! rotate is a bit reindex (free), add mod 2^64 is a ripple-carry. Per row we prove:
//!   S = (A + B) mod 2^64      (ripple carry, carry[i] = carry-out of bit i)
//!   DP = rotr(D ^ A, 32)      (the BLAKE2b `v[d] = rotr(v[d]^v[a], 32)` atom)

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
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
use rand::SeedableRng;
use rand::rngs::SmallRng;

const A: usize = 0;
const B: usize = 64;
const S: usize = 128;
const CARRY: usize = 192;
const D: usize = 256;
const DP: usize = 320;
const NUM_COLS: usize = 384;

struct Blake2bAtomAir {}

impl<F> BaseAir<F> for Blake2bAtomAir {
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

impl<AB: AirBuilder> Air<AB> for Blake2bAtomAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let two = AB::Expr::ONE + AB::Expr::ONE;

        // every column is a bit
        for i in 0..NUM_COLS {
            let x: AB::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        // add mod 2^64: a_i + b_i + carry_in_i == s_i + 2*carry_i
        for i in 0..64 {
            let cin: AB::Expr = if i == 0 { AB::Expr::ZERO } else { row[CARRY + i - 1].into() };
            let lhs: AB::Expr = row[A + i].into() + row[B + i].into() + cin;
            let rhs: AB::Expr = row[S + i].into() + row[CARRY + i].into() * two.clone();
            builder.assert_eq(lhs, rhs);
        }
        // dp_i == rotr(d ^ a, 32)_i == (a_j + d_j - 2*a_j*d_j), j = (i+32) mod 64
        for i in 0..64 {
            let j = (i + 32) % 64;
            let aj: AB::Expr = row[A + j].into();
            let dj: AB::Expr = row[D + j].into();
            let xor: AB::Expr = aj.clone() + dj.clone() - aj * dj * two.clone();
            let dp_i: AB::Expr = row[DP + i].into();
            builder.assert_eq(dp_i, xor);
        }
    }
}

fn generate<F: PrimeField64>(data: &[(u64, u64, u64)]) -> RowMajorMatrix<F> {
    let n = data.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, &(a, b, d)) in data.iter().enumerate() {
        let base = r * NUM_COLS;
        let s = a.wrapping_add(b);
        let dp = (d ^ a).rotate_right(32);
        let mut cin = 0u64;
        for i in 0..64 {
            let ai = (a >> i) & 1;
            let bi = (b >> i) & 1;
            let cout = (ai + bi + cin) >> 1;
            vals[base + A + i] = F::from_u64(ai);
            vals[base + B + i] = F::from_u64(bi);
            vals[base + S + i] = F::from_u64((s >> i) & 1);
            vals[base + CARRY + i] = F::from_u64(cout);
            vals[base + D + i] = F::from_u64((d >> i) & 1);
            vals[base + DP + i] = F::from_u64((dp >> i) & 1);
            cin = cout;
        }
    }
    RowMajorMatrix::new(vals, NUM_COLS)
}

// ---- config (two-adic, verbatim shape from Plonky3 fib_air) ----
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
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
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
    let air = Blake2bAtomAir {};
    // 8 rows of BLAKE2b-representative ARX inputs (IV-derived words).
    let data: Vec<(u64, u64, u64)> = (0..8u64)
        .map(|i| {
            (0x6a09e667f3bcc908u64.wrapping_mul(i + 1), 0xbb67ae8584caa73bu64.wrapping_add(i * 7), 0x3c6ef372fe94f82bu64 ^ (i * 0x1111))
        })
        .collect();
    let mut trace = generate::<Val>(&data);
    if corrupt {
        trace.values[S + 5] += Val::ONE; // flip bit 5 of S in row 0 → add constraint must break
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt trace was accepted!"),
        Ok(_) => println!("VERIFY ok — 64-bit ARX atoms proven: S=(A+B) mod 2^64 (ripple carry) + DP=rotr(D^A,32), 8 rows"),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt trace rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on valid trace: {e:?}"),
    }
}
