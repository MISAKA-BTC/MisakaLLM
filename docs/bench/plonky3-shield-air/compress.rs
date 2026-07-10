//! Blake2bCompressAir — build-order #1 CAPSTONE: the full keyed-BLAKE2b-512
//! compression as a Plonky3 AIR — init (v from h/IV/t/last) + NROUNDS rounds (each 8
//! G's wired by the σ schedule, state threaded round→round) + feed-forward
//! (h_out = v_init ^ v_final ^ v_final[+8]). Unrolled: σ and state-threading are FIXED
//! column references (no lookup). Proven against a generated trace, host-checked that
//! h_out == the reference compress digest (diff-test accept ⇔ the digest), plus a
//! negative test (`--corrupt`). NROUNDS=12 is real BLAKE2b; smaller validates the
//! machinery fast.

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

const NROUNDS: usize = 12;
const W: usize = 64;
const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

// column layout (word units × W). words: HIN 0..8, TLO 8, THI 9, LAST 10,
// VINIT 11..27, M 27..43, FFTMP 43..51, HOUT 51..59, then NROUNDS*8 G-blocks of 16.
const HIN: usize = 0;
const TLO: usize = 8 * W;
const THI: usize = 9 * W;
const LAST: usize = 10 * W;
const VINIT: usize = 11 * W;
const M: usize = 27 * W;
const FFTMP: usize = 43 * W;
const HOUT: usize = 51 * W;
const GBLK: usize = 59 * W;
const GSTRIDE: usize = 16 * W;
const NUM_COLS: usize = GBLK + NROUNDS * 8 * GSTRIDE;
// G-block word indices
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

fn vw(i: usize) -> usize {
    VINIT + i * W
}
fn mw(i: usize) -> usize {
    M + i * W
}
fn gb(block: usize) -> usize {
    GBLK + block * GSTRIDE
}
fn a2(block: usize) -> usize {
    gb(block) + A2 * W
}
fn b2(block: usize) -> usize {
    gb(block) + B2 * W
}
fn c2(block: usize) -> usize {
    gb(block) + C2 * W
}
fn d2(block: usize) -> usize {
    gb(block) + D2 * W
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
#[allow(clippy::too_many_arguments)]
fn g_constraints<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], ia: usize, ib: usize, ic: usize, id: usize, ix: usize, iy: usize, g: usize) {
    ripple(b, row, ia, ib, g + AB * W, g + CAB * W);
    ripple(b, row, g + AB * W, ix, g + A1 * W, g + CA1 * W);
    xorrot(b, row, id, g + A1 * W, g + D1 * W, 32);
    ripple(b, row, ic, g + D1 * W, g + C1 * W, g + CC1 * W);
    xorrot(b, row, ib, g + C1 * W, g + B1 * W, 24);
    ripple(b, row, g + A1 * W, g + B1 * W, g + A1B1 * W, g + CA1B1 * W);
    ripple(b, row, g + A1B1 * W, iy, g + A2 * W, g + CA2 * W);
    xorrot(b, row, g + D1 * W, g + A2 * W, g + D2 * W, 16);
    ripple(b, row, g + C1 * W, g + D2 * W, g + C2 * W, g + CC2 * W);
    xorrot(b, row, g + B1 * W, g + C2 * W, g + B2 * W, 63);
}
fn const_xor<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], kw: u64, col: usize, out: usize) {
    for i in 0..W {
        let x: AB2::Expr = row[col + i].into();
        let rhs = if (kw >> i) & 1 == 1 { AB2::Expr::ONE - x } else { x };
        b.assert_eq(Into::<AB2::Expr>::into(row[out + i]), rhs);
    }
}
fn const_eq<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], kw: u64, out: usize) {
    for i in 0..W {
        let c = if (kw >> i) & 1 == 1 { AB2::Expr::ONE } else { AB2::Expr::ZERO };
        b.assert_eq(Into::<AB2::Expr>::into(row[out + i]), c);
    }
}

struct Blake2bCompressAir {}
impl<F> BaseAir<F> for Blake2bCompressAir {
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
impl<AB2: AirBuilder> Air<AB2> for Blake2bCompressAir {
    fn eval(&self, builder: &mut AB2) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB2::Expr::ONE;
        for i in 0..NUM_COLS {
            let x: AB2::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        // ---- init: v_init from h_in / IV / t / last ----
        for i in 0..8 {
            for k in 0..W {
                builder.assert_eq(Into::<AB2::Expr>::into(row[vw(i) + k]), Into::<AB2::Expr>::into(row[HIN + i * W + k]));
            }
        }
        for j in 0..4 {
            const_eq(builder, row, IV[j], vw(8 + j));
        }
        const_xor(builder, row, IV[4], TLO, vw(12));
        const_xor(builder, row, IV[5], THI, vw(13));
        const_xor(builder, row, IV[6], LAST, vw(14));
        const_eq(builder, row, IV[7], vw(15));

        // ---- rounds: thread the 16-word state, σ per round ----
        let mut sin: [usize; 16] = core::array::from_fn(vw);
        for r in 0..NROUNDS {
            let g: [usize; 8] = core::array::from_fn(|k| gb(r * 8 + k));
            let s = SIGMA[r];
            g_constraints(builder, row, sin[0], sin[4], sin[8], sin[12], mw(s[0]), mw(s[1]), g[0]);
            g_constraints(builder, row, sin[1], sin[5], sin[9], sin[13], mw(s[2]), mw(s[3]), g[1]);
            g_constraints(builder, row, sin[2], sin[6], sin[10], sin[14], mw(s[4]), mw(s[5]), g[2]);
            g_constraints(builder, row, sin[3], sin[7], sin[11], sin[15], mw(s[6]), mw(s[7]), g[3]);
            g_constraints(builder, row, a2(r * 8), b2(r * 8 + 1), c2(r * 8 + 2), d2(r * 8 + 3), mw(s[8]), mw(s[9]), g[4]);
            g_constraints(builder, row, a2(r * 8 + 1), b2(r * 8 + 2), c2(r * 8 + 3), d2(r * 8), mw(s[10]), mw(s[11]), g[5]);
            g_constraints(builder, row, a2(r * 8 + 2), b2(r * 8 + 3), c2(r * 8), d2(r * 8 + 1), mw(s[12]), mw(s[13]), g[6]);
            g_constraints(builder, row, a2(r * 8 + 3), b2(r * 8), c2(r * 8 + 1), d2(r * 8 + 2), mw(s[14]), mw(s[15]), g[7]);
            let base = r * 8;
            sin = [
                a2(base + 4),
                a2(base + 5),
                a2(base + 6),
                a2(base + 7),
                b2(base + 7),
                b2(base + 4),
                b2(base + 5),
                b2(base + 6),
                c2(base + 6),
                c2(base + 7),
                c2(base + 4),
                c2(base + 5),
                d2(base + 5),
                d2(base + 6),
                d2(base + 7),
                d2(base + 4),
            ];
        }
        // ---- feed-forward: h_out[i] = v_init[i] ^ v_final[i] ^ v_final[i+8] ----
        for i in 0..8 {
            xorrot(builder, row, vw(i), sin[i], FFTMP + i * W, 0);
            xorrot(builder, row, FFTMP + i * W, sin[i + 8], HOUT + i * W, 0);
        }
    }
}

// ---- reference compression + trace generation ----
#[inline]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}
fn compress_ref(h_in: &[u64; 8], m: &[u64; 16], t: u128, last: bool) -> [u64; 8] {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h_in);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] ^= 0xffff_ffff_ffff_ffff;
    }
    for s in SIGMA.iter().take(NROUNDS) {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    let mut h = *h_in;
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
    h
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
fn set_word<F: PrimeField64>(vals: &mut [F], off: usize, w: u64) {
    for i in 0..W {
        vals[off + i] = F::from_u64((w >> i) & 1);
    }
}
fn fill_g<F: PrimeField64>(vals: &mut [F], base: usize, g_off: usize, a: u64, b: u64, c: u64, d: u64, x: u64, y: u64) -> [u64; 4] {
    let ab = a.wrapping_add(b);
    let a1 = ab.wrapping_add(x);
    let d1 = (d ^ a1).rotate_right(32);
    let c1 = c.wrapping_add(d1);
    let b1 = (b ^ c1).rotate_right(24);
    let a1b1 = a1.wrapping_add(b1);
    let a2v = a1b1.wrapping_add(y);
    let d2v = (d1 ^ a2v).rotate_right(16);
    let c2v = c1.wrapping_add(d2v);
    let b2v = (b1 ^ c2v).rotate_right(63);
    for (idx, val) in [(AB, ab), (A1, a1), (D1, d1), (C1, c1), (B1, b1), (A1B1, a1b1), (A2, a2v), (D2, d2v), (C2, c2v), (B2, b2v)] {
        set_word(vals, base + g_off + idx * W, val);
    }
    for (idx, p, q) in [(CAB, a, b), (CA1, ab, x), (CC1, c, d1), (CA1B1, a1, b1), (CA2, a1b1, y), (CC2, c1, d2v)] {
        let cc = carries(p, q);
        for i in 0..W {
            vals[base + g_off + idx * W + i] = F::from_u64(cc[i]);
        }
    }
    [a2v, b2v, c2v, d2v]
}

fn generate<F: PrimeField64>(h_in: &[u64; 8], m: &[u64; 16], t: u128, last: bool) -> (RowMajorMatrix<F>, [u64; 8]) {
    let n = 2usize; // pad to a valid height
    let mut vals = F::zero_vec(n * NUM_COLS);
    for base in [0usize, NUM_COLS] {
        for i in 0..8 {
            set_word(&mut vals, base + HIN + i * W, h_in[i]);
        }
        set_word(&mut vals, base + TLO, t as u64);
        set_word(&mut vals, base + THI, (t >> 64) as u64);
        set_word(&mut vals, base + LAST, if last { 0xffff_ffff_ffff_ffff } else { 0 });
        for i in 0..16 {
            set_word(&mut vals, base + M + i * W, m[i]);
        }
        // init state
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(h_in);
        v[8..].copy_from_slice(&IV);
        v[12] ^= t as u64;
        v[13] ^= (t >> 64) as u64;
        if last {
            v[14] ^= 0xffff_ffff_ffff_ffff;
        }
        for i in 0..16 {
            set_word(&mut vals, base + vw(i), v[i]);
        }
        // rounds
        for (r, s) in SIGMA.iter().enumerate().take(NROUNDS) {
            let bk = r * 8;
            let o0 = fill_g(&mut vals, base, gb(bk), v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
            let o1 = fill_g(&mut vals, base, gb(bk + 1), v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
            let o2 = fill_g(&mut vals, base, gb(bk + 2), v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
            let o3 = fill_g(&mut vals, base, gb(bk + 3), v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
            let o4 = fill_g(&mut vals, base, gb(bk + 4), o0[0], o1[1], o2[2], o3[3], m[s[8]], m[s[9]]);
            let o5 = fill_g(&mut vals, base, gb(bk + 5), o1[0], o2[1], o3[2], o0[3], m[s[10]], m[s[11]]);
            let o6 = fill_g(&mut vals, base, gb(bk + 6), o2[0], o3[1], o0[2], o1[3], m[s[12]], m[s[13]]);
            let o7 = fill_g(&mut vals, base, gb(bk + 7), o3[0], o0[1], o1[2], o2[3], m[s[14]], m[s[15]]);
            v = [
                o4[0], o5[0], o6[0], o7[0], o7[1], o4[1], o5[1], o6[1], o6[2], o7[2], o4[2], o5[2], o5[3], o6[3], o7[3], o4[3],
            ];
        }
        // feed-forward
        let mut hout = *h_in;
        for i in 0..8 {
            let ff = h_in[i] ^ v[i];
            set_word(&mut vals, base + FFTMP + i * W, ff);
            hout[i] = ff ^ v[i + 8];
            set_word(&mut vals, base + HOUT + i * W, hout[i]);
        }
    }
    let h = compress_ref(h_in, m, t, last);
    (RowMajorMatrix::new(vals, NUM_COLS), h)
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
    let fri_params = FriParameters { log_blowup: 1, log_final_poly_len: 0, max_log_arity: 1, num_queries: 8, commit_proof_of_work_bits: 1, query_proof_of_work_bits: 1, mmcs: challenge_mmcs };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    MyConfig::new(pcs, Challenger::new(perm))
}

fn main() {
    let corrupt = std::env::args().any(|a| a == "--corrupt");
    let air = Blake2bCompressAir {};
    let h_in: [u64; 8] = IV; // an init-shaped chaining value
    let mut m = [0u64; 16];
    for (i, mi) in m.iter_mut().enumerate() {
        *mi = 0x0123_4567_89ab_cdefu64.wrapping_mul(i as u64 + 1);
    }
    let (t, last) = (204u128, true);
    let (mut trace, digest) = generate::<Val>(&h_in, &m, t, last);
    // host diff-test: the trace's h_out equals the reference digest.
    let hout0: Vec<u64> = (0..8)
        .map(|i| (0..W).fold(0u64, |acc, k| acc | (((trace.values[HOUT + i * W + k].as_canonical_u64()) & 1) << k)))
        .collect();
    let host_ok = (0..8).all(|i| hout0[i] == digest[i]);
    println!("host diff-test: trace h_out == reference {}-round digest: {host_ok} (NROUNDS={NROUNDS}, cols={NUM_COLS})", NROUNDS);
    if corrupt {
        trace.values[HOUT + 3] += Val::ONE;
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt compression accepted!"),
        Ok(_) => println!("VERIFY ok — full BLAKE2b compression proven (init + {NROUNDS} rounds + feed-forward)"),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt compression rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on valid trace: {e:?}"),
    }
}
