//! Blake2bGAir — build-order #1 composition: one full BLAKE2b G-function as a real
//! Plonky3 AIR, composing the two ARX atoms (add mod 2^64 ripple-carry, rotr(·^·,k))
//! into the 8-step G with all intermediate 64-bit words, proven against a generated
//! trace with a negative test (`--corrupt`). G is the unit the round (8 G + σ) and
//! the compression (init + 12 rounds + feed-forward) tile — so a correct, sound G
//! reduces those to mechanical wiring driven by the #1 CompressionTrace.
//!
//! G(a,b,c,d,x,y):
//!   a1 = a + b + x ; d1 = rotr(d^a1,32) ; c1 = c + d1 ; b1 = rotr(b^c1,24)
//!   a2 = a1+ b1+ y ; d2 = rotr(d1^a2,16); c2 = c1+ d2 ; b2 = rotr(b1^c2,63)
//! output (a2,b2,c2,d2). The 3-way adds are two ripple add2's (ab=a+b, a1=ab+x).

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

// 16 words × 64 bits, then 6 carry words × 64 bits.
const W: usize = 64;
const A: usize = 0;
const B: usize = W;
const C: usize = 2 * W;
const D: usize = 3 * W;
const X: usize = 4 * W;
const Y: usize = 5 * W;
const AB: usize = 6 * W;
const A1: usize = 7 * W;
const D1: usize = 8 * W;
const C1: usize = 9 * W;
const B1: usize = 10 * W;
const A1B1: usize = 11 * W;
const A2: usize = 12 * W;
const D2: usize = 13 * W;
const C2: usize = 14 * W;
const B2: usize = 15 * W;
const CAB: usize = 16 * W;
const CA1: usize = 17 * W;
const CC1: usize = 18 * W;
const CA1B1: usize = 19 * W;
const CA2: usize = 20 * W;
const CC2: usize = 21 * W;
const NUM_COLS: usize = 22 * W;

fn ripple<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], ao: usize, bo: usize, so: usize, co: usize) {
    let two = AB2::Expr::ONE + AB2::Expr::ONE;
    for i in 0..W {
        let cin: AB2::Expr = if i == 0 { AB2::Expr::ZERO } else { row[co + i - 1].into() };
        let lhs = Into::<AB2::Expr>::into(row[ao + i]) + row[bo + i].into() + cin;
        let rhs = Into::<AB2::Expr>::into(row[so + i]) + Into::<AB2::Expr>::into(row[co + i]) * two.clone();
        b.assert_eq(lhs, rhs);
    }
}
fn xorrot<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], ao: usize, bo: usize, oo: usize, sh: usize) {
    let two = AB2::Expr::ONE + AB2::Expr::ONE;
    for i in 0..W {
        let j = (i + sh) % W;
        let aj: AB2::Expr = row[ao + j].into();
        let bj: AB2::Expr = row[bo + j].into();
        let xor = aj.clone() + bj.clone() - aj * bj * two.clone();
        b.assert_eq(Into::<AB2::Expr>::into(row[oo + i]), xor);
    }
}

struct Blake2bGAir {}
impl<F> BaseAir<F> for Blake2bGAir {
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
impl<AB2: AirBuilder> Air<AB2> for Blake2bGAir {
    fn eval(&self, builder: &mut AB2) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB2::Expr::ONE;
        for i in 0..NUM_COLS {
            let x: AB2::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        ripple(builder, row, A, B, AB, CAB); // ab = a + b
        ripple(builder, row, AB, X, A1, CA1); // a1 = ab + x
        xorrot(builder, row, D, A1, D1, 32); // d1 = rotr(d ^ a1, 32)
        ripple(builder, row, C, D1, C1, CC1); // c1 = c + d1
        xorrot(builder, row, B, C1, B1, 24); // b1 = rotr(b ^ c1, 24)
        ripple(builder, row, A1, B1, A1B1, CA1B1); // a1b1 = a1 + b1
        ripple(builder, row, A1B1, Y, A2, CA2); // a2 = a1b1 + y
        xorrot(builder, row, D1, A2, D2, 16); // d2 = rotr(d1 ^ a2, 16)
        ripple(builder, row, C1, D2, C2, CC2); // c2 = c1 + d2
        xorrot(builder, row, B1, C2, B2, 63); // b2 = rotr(b1 ^ c2, 63)
    }
}

fn carries(p: u64, q: u64) -> [u64; W] {
    let mut c = [0u64; W];
    let mut cin = 0u64;
    for i in 0..W {
        let cout = (((p >> i) & 1) + ((q >> i) & 1) + cin) >> 1;
        c[i] = cout;
        cin = cout;
    }
    c
}

fn generate<F: PrimeField64>(inputs: &[[u64; 6]]) -> RowMajorMatrix<F> {
    let n = inputs.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, &[a, b, c, d, x, y]) in inputs.iter().enumerate() {
        let base = r * NUM_COLS;
        // recompute the G exactly (matches misaka-mil-blake2b-air::g).
        let ab = a.wrapping_add(b);
        let a1 = ab.wrapping_add(x);
        let d1 = (d ^ a1).rotate_right(32);
        let c1 = c.wrapping_add(d1);
        let b1 = (b ^ c1).rotate_right(24);
        let a1b1 = a1.wrapping_add(b1);
        let a2 = a1b1.wrapping_add(y);
        let d2 = (d1 ^ a2).rotate_right(16);
        let c2 = c1.wrapping_add(d2);
        let b2 = (b1 ^ c2).rotate_right(63);
        let words = [
            (A, a),
            (B, b),
            (C, c),
            (D, d),
            (X, x),
            (Y, y),
            (AB, ab),
            (A1, a1),
            (D1, d1),
            (C1, c1),
            (B1, b1),
            (A1B1, a1b1),
            (A2, a2),
            (D2, d2),
            (C2, c2),
            (B2, b2),
        ];
        for (off, w) in words {
            for i in 0..W {
                vals[base + off + i] = F::from_u64((w >> i) & 1);
            }
        }
        let carr = [(CAB, a, b), (CA1, ab, x), (CC1, c, d1), (CA1B1, a1, b1), (CA2, a1b1, y), (CC2, c1, d2)];
        for (off, p, q) in carr {
            let cc = carries(p, q);
            for i in 0..W {
                vals[base + off + i] = F::from_u64(cc[i]);
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
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params =
        FriParameters { log_blowup: 2, log_final_poly_len: 0, max_log_arity: 1, num_queries: 8, commit_proof_of_work_bits: 1, query_proof_of_work_bits: 1, mmcs: challenge_mmcs };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    MyConfig::new(pcs, Challenger::new(perm))
}

fn main() {
    let corrupt = std::env::args().any(|a| a == "--corrupt");
    let air = Blake2bGAir {};
    // 8 rows of BLAKE2b G inputs (IV/word-derived, representative).
    let iv = misaka_iv();
    let inputs: Vec<[u64; 6]> = (0..8u64)
        .map(|i| [iv[0].wrapping_mul(i + 1), iv[4], iv[1], iv[5], 0x0123_4567_89ab_cdefu64.wrapping_add(i), 0xfedc_ba98_7654_3210u64 ^ i])
        .collect();
    let mut trace = generate::<Val>(&inputs);
    if corrupt {
        trace.values[A2 + 7] += Val::ONE; // flip bit 7 of the output a2 in row 0
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt G output accepted!"),
        Ok(_) => println!("VERIFY ok — full BLAKE2b G-function proven (4 adds + 4 xor-rotates, 16 words), 8 rows"),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt G output rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on valid trace: {e:?}"),
    }
}

fn misaka_iv() -> [u64; 8] {
    [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ]
}
