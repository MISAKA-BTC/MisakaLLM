//! Blake2bRoundAir — build-order #1: one full BLAKE2b round = 8 G-functions wired by
//! the (column then diagonal) schedule on the 16-word state, with the message args
//! `m[2k],m[2k+1]` (σ[0]=identity for a standalone round). Composed from the proven
//! G (each G is `g_constraints` reading arbitrary input columns), proven against a
//! generated trace + a negative test. Round is the tile the compression stacks 12×.

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

const W: usize = 64;
// state (16 words) ‖ message (16 words) ‖ 8 G-blocks (16 words each: 10 out + 6 carry).
const V: usize = 0;
const M: usize = 16 * W;
const G0: usize = 32 * W;
const GSTRIDE: usize = 16 * W;
const NUM_COLS: usize = G0 + 8 * GSTRIDE;
// within a G block (word index × W):
const AB: usize = 0;
const A1: usize = 1;
const D1: usize = 2;
const C1: usize = 3;
const B1: usize = 4;
const A1B1: usize = 5;
const A2: usize = 6;
const D2: usize = 7;
const C2: usize = 8;
const B2: usize = 9;
const CAB: usize = 10;
const CA1: usize = 11;
const CC1: usize = 12;
const CA1B1: usize = 13;
const CA2: usize = 14;
const CC2: usize = 15;

fn gbase(k: usize) -> usize {
    G0 + k * GSTRIDE
}
fn vw(i: usize) -> usize {
    V + i * W
}
fn mw(i: usize) -> usize {
    M + i * W
}

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
/// Emit one G's constraints reading inputs a,b,c,d,x,y from arbitrary column offsets,
/// writing its intermediates into the block at `gb`.
#[allow(clippy::too_many_arguments)]
fn g_constraints<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], ia: usize, ib: usize, ic: usize, id: usize, ix: usize, iy: usize, gb: usize) {
    ripple(b, row, ia, ib, gb + AB * W, gb + CAB * W); // ab = a + b
    ripple(b, row, gb + AB * W, ix, gb + A1 * W, gb + CA1 * W); // a1 = ab + x
    xorrot(b, row, id, gb + A1 * W, gb + D1 * W, 32); // d1 = rotr(d^a1,32)
    ripple(b, row, ic, gb + D1 * W, gb + C1 * W, gb + CC1 * W); // c1 = c + d1
    xorrot(b, row, ib, gb + C1 * W, gb + B1 * W, 24); // b1 = rotr(b^c1,24)
    ripple(b, row, gb + A1 * W, gb + B1 * W, gb + A1B1 * W, gb + CA1B1 * W); // a1b1
    ripple(b, row, gb + A1B1 * W, iy, gb + A2 * W, gb + CA2 * W); // a2 = a1b1 + y
    xorrot(b, row, gb + D1 * W, gb + A2 * W, gb + D2 * W, 16); // d2 = rotr(d1^a2,16)
    ripple(b, row, gb + C1 * W, gb + D2 * W, gb + C2 * W, gb + CC2 * W); // c2 = c1 + d2
    xorrot(b, row, gb + B1 * W, gb + C2 * W, gb + B2 * W, 63); // b2 = rotr(b1^c2,63)
}
fn out_a2(k: usize) -> usize {
    gbase(k) + A2 * W
}
fn out_b2(k: usize) -> usize {
    gbase(k) + B2 * W
}
fn out_c2(k: usize) -> usize {
    gbase(k) + C2 * W
}
fn out_d2(k: usize) -> usize {
    gbase(k) + D2 * W
}

struct Blake2bRoundAir {}
impl<F> BaseAir<F> for Blake2bRoundAir {
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
impl<AB2: AirBuilder> Air<AB2> for Blake2bRoundAir {
    fn eval(&self, builder: &mut AB2) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB2::Expr::ONE;
        for i in 0..NUM_COLS {
            let x: AB2::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        // column G's on (0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15), args m[2k],m[2k+1]
        g_constraints(builder, row, vw(0), vw(4), vw(8), vw(12), mw(0), mw(1), gbase(0));
        g_constraints(builder, row, vw(1), vw(5), vw(9), vw(13), mw(2), mw(3), gbase(1));
        g_constraints(builder, row, vw(2), vw(6), vw(10), vw(14), mw(4), mw(5), gbase(2));
        g_constraints(builder, row, vw(3), vw(7), vw(11), vw(15), mw(6), mw(7), gbase(3));
        // diagonal G's on (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)
        g_constraints(builder, row, out_a2(0), out_b2(1), out_c2(2), out_d2(3), mw(8), mw(9), gbase(4));
        g_constraints(builder, row, out_a2(1), out_b2(2), out_c2(3), out_d2(0), mw(10), mw(11), gbase(5));
        g_constraints(builder, row, out_a2(2), out_b2(3), out_c2(0), out_d2(1), mw(12), mw(13), gbase(6));
        g_constraints(builder, row, out_a2(3), out_b2(0), out_c2(1), out_d2(2), mw(14), mw(15), gbase(7));
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
fn g_words(a: u64, b: u64, c: u64, d: u64, x: u64, y: u64) -> [u64; 16] {
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
    // matches the AB..CC2 index order
    [ab, a1, d1, c1, b1, a1b1, a2, d2, c2, b2, 0, 0, 0, 0, 0, 0]
}

fn set_word<F: PrimeField64>(vals: &mut [F], off: usize, w: u64) {
    for i in 0..W {
        vals[off + i] = F::from_u64((w >> i) & 1);
    }
}
fn set_carry<F: PrimeField64>(vals: &mut [F], off: usize, p: u64, q: u64) {
    let cc = carries(p, q);
    for i in 0..W {
        vals[off + i] = F::from_u64(cc[i]);
    }
}

fn fill_g<F: PrimeField64>(vals: &mut [F], base: usize, gb: usize, a: u64, b: u64, c: u64, d: u64, x: u64, y: u64) -> [u64; 4] {
    let w = g_words(a, b, c, d, x, y);
    let (ab, a1, d1, c1, b1, a1b1, a2, d2, c2, b2) = (w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9]);
    for (idx, val) in [(AB, ab), (A1, a1), (D1, d1), (C1, c1), (B1, b1), (A1B1, a1b1), (A2, a2), (D2, d2), (C2, c2), (B2, b2)] {
        set_word(vals, base + gb + idx * W, val);
    }
    set_carry(vals, base + gb + CAB * W, a, b);
    set_carry(vals, base + gb + CA1 * W, ab, x);
    set_carry(vals, base + gb + CC1 * W, c, d1);
    set_carry(vals, base + gb + CA1B1 * W, a1, b1);
    set_carry(vals, base + gb + CA2 * W, a1b1, y);
    set_carry(vals, base + gb + CC2 * W, c1, d2);
    [a2, b2, c2, d2]
}

fn generate<F: PrimeField64>(states: &[([u64; 16], [u64; 16])]) -> RowMajorMatrix<F> {
    let n = states.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, (v, m)) in states.iter().enumerate() {
        let base = r * NUM_COLS;
        for i in 0..16 {
            set_word(&mut vals, base + vw(i), v[i]);
            set_word(&mut vals, base + mw(i), m[i]);
        }
        // column phase
        let o0 = fill_g(&mut vals, base, gbase(0) - G0 + G0, v[0], v[4], v[8], v[12], m[0], m[1]);
        let o1 = fill_g(&mut vals, base, gbase(1) - G0 + G0, v[1], v[5], v[9], v[13], m[2], m[3]);
        let o2 = fill_g(&mut vals, base, gbase(2) - G0 + G0, v[2], v[6], v[10], v[14], m[4], m[5]);
        let o3 = fill_g(&mut vals, base, gbase(3) - G0 + G0, v[3], v[7], v[11], v[15], m[6], m[7]);
        // diagonal phase (a2/b2/c2/d2 of column G's)
        let _ = fill_g(&mut vals, base, gbase(4) - G0 + G0, o0[0], o1[1], o2[2], o3[3], m[8], m[9]);
        let _ = fill_g(&mut vals, base, gbase(5) - G0 + G0, o1[0], o2[1], o3[2], o0[3], m[10], m[11]);
        let _ = fill_g(&mut vals, base, gbase(6) - G0 + G0, o2[0], o3[1], o0[2], o1[3], m[12], m[13]);
        let _ = fill_g(&mut vals, base, gbase(7) - G0 + G0, o3[0], o0[1], o1[2], o2[3], m[14], m[15]);
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
    let val_mmcs = ValMmcs::new(MyHash::new(perm.clone()), MyCompress::new(perm.clone()), 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters { log_blowup: 2, log_final_poly_len: 0, max_log_arity: 1, num_queries: 8, commit_proof_of_work_bits: 1, query_proof_of_work_bits: 1, mmcs: challenge_mmcs };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    MyConfig::new(pcs, Challenger::new(perm))
}

fn main() {
    let corrupt = std::env::args().any(|a| a == "--corrupt");
    let air = Blake2bRoundAir {};
    let iv: [u64; 8] =
        [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];
    // 2 rows: a representative init-like v and a message.
    let states: Vec<([u64; 16], [u64; 16])> = (0..2u64)
        .map(|r| {
            let mut v = [0u64; 16];
            for i in 0..8 {
                v[i] = iv[i].wrapping_add(r);
                v[i + 8] = iv[i];
            }
            let mut m = [0u64; 16];
            for (i, mi) in m.iter_mut().enumerate() {
                *mi = 0x0101_0101_0101_0101u64.wrapping_mul(i as u64 + 1).wrapping_add(r);
            }
            (v, m)
        })
        .collect();
    let mut trace = generate::<Val>(&states);
    if corrupt {
        trace.values[out_b2(7) + 9] += Val::ONE; // flip a bit of the final diagonal G output
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt round accepted!"),
        Ok(_) => println!("VERIFY ok — full BLAKE2b ROUND proven: 8 G's (4 column + 4 diagonal) wired by the schedule"),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt round rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on valid trace: {e:?}"),
    }
}
