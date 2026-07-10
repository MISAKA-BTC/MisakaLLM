//! Blake2bMerklePathAir — build#3: the WHICH-NOTE-HIDING privacy core with the REAL
//! on-chain node hash. Proves depth-20 Merkle membership of a PRIVATE leaf at a
//! PRIVATE index under a PUBLIC root, where each level is the full 12-round
//! keyed-BLAKE2b-512 compression proven in build#1 (`compress.rs`).
//!
//! This is the **multi-row layout** that build#1 could not use (20 unrolled
//! compressions ≈ 2M columns): **one row = one tree level = one full compression**
//! (the build#1 column block per row), with the running digest threaded row→row by a
//! transition constraint. Key structural facts:
//!
//! - `hash_node(l, r) = blake2b_512_keyed("misaka-shield-v1/merkle", l ‖ r)` is keyed,
//!   so on-chain it is TWO compressions — but the key-block compression is the same
//!   for every node. Its output chaining value `h_merkle` is a PUBLIC CONSTANT
//!   (derived from the public domain), so the AIR pins `v_init` to constants
//!   (h_merkle / IV / t=256 / last=true) and proves ONE compression per level. The
//!   host diff-test validates this shortcut against the full two-compression keyed
//!   reference (the same logic differentially tested byte-for-byte vs
//!   `kaspa_hashes::blake2b_512_keyed` in `mil/blake2b-air`).
//! - The PRIVATE index bit per row (`DIR`) MUXes the message block:
//!   `m = dir ? sib ‖ cur : cur ‖ sib` (degree 2) — the which-note hiding.
//! - Chaining: `when_transition: next.CUR == HOUT`. All 32 rows (20 real levels + 12
//!   padding rows that keep chaining garbage) satisfy the SAME constraints — no
//!   activity selector on the compression, so everything stays degree ≤ 2.
//! - Root binding at exactly row DEPTH-1 via a sound indicator: a counter column
//!   (`CNT`: first row 0, +1 per transition), a boolean selector `SEL` with
//!   `SEL·(CNT−(DEPTH−1))=0`, and a running sum `ACC` with `ACC(last)=1` — so SEL is 1
//!   on row DEPTH-1 and nowhere else; then `SEL·(HOUT − root_public)=0`.
//! - Proven under the **hiding / zero-knowledge FRI** (HidingFriPcs), plus the
//!   witness-absence gate: leaf, siblings, and the intermediate path nodes must not
//!   appear in the proof bytes. (Supersedes the depth-8 G-mix toy that first proved
//!   the MUX + hiding mechanics.)
//!
//! Negative tests: `--corrupt` (tampered sibling bit), `--flip-index` (tampered
//! direction bit), `--wrong-root` (valid trace, different public root).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

const DEPTH: usize = 20; // the pool's fixed tree depth (ADR-0033 §4.1)
const HEIGHT: usize = 32; // trace rows: DEPTH real levels + chaining padding, pow2
const NROUNDS: usize = 12;
const W: usize = 64;
const MERKLE_DOMAIN: &[u8] = b"misaka-shield-v1/merkle";
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

// per-row column layout (word units × W). CUR = running digest entering this level
// (row 0: the private leaf), SIB = the private sibling, M = the MUXed message block,
// VINIT = the 16-word initial state (ALL constants: h_merkle/IV/t/last), then the
// build#1 G blocks, then 4 scalar columns.
const CUR: usize = 0;
const SIB: usize = 8 * W;
const M: usize = 16 * W;
const VINIT: usize = 32 * W;
const FFTMP: usize = 48 * W;
const HOUT: usize = 56 * W;
const GBLK: usize = 64 * W;
const GSTRIDE: usize = 16 * W;
const DIR: usize = GBLK + NROUNDS * 8 * GSTRIDE; // private index bit (boolean)
const CNT: usize = DIR + 1; // row counter (NOT boolean)
const SEL: usize = DIR + 2; // 1 exactly on row DEPTH-1 (boolean)
const ACC: usize = DIR + 3; // running Σ SEL (boolean by construction)
const NUM_COLS: usize = DIR + 4;
// G-block word indices (build#1)
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
fn const_eq<AB2: AirBuilder>(b: &mut AB2, row: &[AB2::Var], kw: u64, out: usize) {
    for i in 0..W {
        let c = if (kw >> i) & 1 == 1 { AB2::Expr::ONE } else { AB2::Expr::ZERO };
        b.assert_eq(Into::<AB2::Expr>::into(row[out + i]), c);
    }
}
fn expr_u64<AB2: AirBuilder>(mut k: u64) -> AB2::Expr {
    let two = AB2::Expr::ONE + AB2::Expr::ONE;
    let mut acc = AB2::Expr::ZERO;
    let mut p = AB2::Expr::ONE;
    while k > 0 {
        if k & 1 == 1 {
            acc = acc + p.clone();
        }
        p = p * two.clone();
        k >>= 1;
    }
    acc
}

/// The constant `v_init` words every level shares: `h_merkle` (the chaining value
/// after the keyed hash absorbs the domain key block) + IV + t=256 + last=true.
fn vinit_consts() -> ([u64; 8], [u64; 16]) {
    let hm = h_merkle();
    let mut vi = [0u64; 16];
    vi[..8].copy_from_slice(&hm);
    vi[8..12].copy_from_slice(&IV[0..4]);
    vi[12] = IV[4] ^ 256; // t_lo: key block (128) + data block (128)
    vi[13] = IV[5]; // t_hi = 0
    vi[14] = IV[6] ^ u64::MAX; // last = true
    vi[15] = IV[7];
    (hm, vi)
}

struct Blake2bMerklePathAir {
    vinit: [u64; 16],
}
impl<F> BaseAir<F> for Blake2bMerklePathAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        8 * W // the 512-bit root
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}
impl<AB2: AirBuilder> Air<AB2> for Blake2bMerklePathAir {
    fn eval(&self, builder: &mut AB2) {
        let root: Vec<AB2::Expr> = (0..8 * W).map(|k| builder.public_values()[k].into()).collect();
        let main = builder.main();
        let row = main.current_slice();
        let nxt = main.next_slice();
        let one = AB2::Expr::ONE;
        // booleanity for every column except the counters
        for i in 0..NUM_COLS {
            if i == CNT || i == ACC {
                continue;
            }
            let x: AB2::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }
        // ---- v_init: ALL constants (h_merkle / IV / t=256 / last=true) ----
        for i in 0..16 {
            const_eq(builder, row, self.vinit[i], vw(i));
        }
        // ---- message MUX by the PRIVATE index bit: m = dir ? sib‖cur : cur‖sib ----
        let dir: AB2::Expr = row[DIR].into();
        for i in 0..8 {
            for k in 0..W {
                let cur: AB2::Expr = row[CUR + i * W + k].into();
                let sib: AB2::Expr = row[SIB + i * W + k].into();
                let left = cur.clone() + dir.clone() * (sib.clone() - cur.clone());
                let right = sib.clone() + dir.clone() * (cur - sib);
                builder.assert_eq(Into::<AB2::Expr>::into(row[mw(i) + k]), left);
                builder.assert_eq(Into::<AB2::Expr>::into(row[mw(8 + i) + k]), right);
            }
        }
        // ---- the build#1 compression: 12 rounds, state threaded within the row ----
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
        // ---- row→row chaining: the next level's CUR is this level's digest ----
        {
            let mut wt = builder.when_transition();
            for k in 0..8 * W {
                wt.assert_eq(nxt[CUR + k], row[HOUT + k]);
            }
        }
        // ---- the row-(DEPTH-1) indicator: CNT counts, SEL·(CNT−(DEPTH−1))=0, ΣSEL=1 ----
        builder.when_first_row().assert_zero(row[CNT]);
        builder.when_first_row().assert_eq(row[ACC], row[SEL]);
        {
            let mut wt = builder.when_transition();
            wt.assert_eq(Into::<AB2::Expr>::into(nxt[CNT]), Into::<AB2::Expr>::into(row[CNT]) + one.clone());
            wt.assert_eq(Into::<AB2::Expr>::into(nxt[ACC]), Into::<AB2::Expr>::into(row[ACC]) + nxt[SEL].into());
        }
        builder.when_last_row().assert_eq(Into::<AB2::Expr>::into(row[ACC]), one);
        let sel: AB2::Expr = row[SEL].into();
        builder.assert_zero(sel.clone() * (Into::<AB2::Expr>::into(row[CNT]) - expr_u64::<AB2>((DEPTH - 1) as u64)));
        // ---- root binding: on the SEL row, HOUT == the public root ----
        for k in 0..8 * W {
            let h: AB2::Expr = row[HOUT + k].into();
            builder.assert_zero(sel.clone() * (h - root[k].clone()));
        }
    }
}

// ---- reference keyed BLAKE2b (word-level; diff-tested vs kaspa_hashes in
// mil/blake2b-air) + trace generation ----
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
    for s in SIGMA.iter() {
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
/// The chaining value after the keyed hash's key block: parameter-block-XORed IV
/// compressed over the zero-padded domain, t=128, not last. A PUBLIC constant.
fn h_merkle() -> [u64; 8] {
    let kk = MERKLE_DOMAIN.len() as u64; // 23
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ (kk << 8) ^ 64;
    let mut kb = [0u8; 128];
    kb[..MERKLE_DOMAIN.len()].copy_from_slice(MERKLE_DOMAIN);
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u64::from_le_bytes(kb[i * 8..i * 8 + 8].try_into().unwrap());
    }
    compress_ref(&h, &m, 128, false)
}
/// The FULL on-chain `hash_node` (both compressions, key block included) — the
/// independent reference the AIR's h_merkle shortcut is diff-tested against.
fn hash_node_ref(left: &[u64; 8], right: &[u64; 8]) -> [u64; 8] {
    let h = h_merkle();
    let mut m = [0u64; 16];
    m[..8].copy_from_slice(left);
    m[8..].copy_from_slice(right);
    compress_ref(&h, &m, 256, true)
}
/// `verify_merkle_path` semantics (mil/shield/src/merkle.rs): bit 0 ⇒ cur is left.
fn root_ref(leaf: &[u64; 8], index: u64, sibs: &[[u64; 8]; DEPTH]) -> [u64; 8] {
    let mut cur = *leaf;
    for (r, sib) in sibs.iter().enumerate() {
        let bit = (index >> r) & 1;
        cur = if bit == 0 { hash_node_ref(&cur, sib) } else { hash_node_ref(sib, &cur) };
    }
    cur
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

/// One row per level: rows 0..DEPTH are the real path, rows DEPTH..HEIGHT keep
/// chaining (sib=0, dir=0) so every row satisfies the same constraints.
fn generate<F: PrimeField64>(leaf: &[u64; 8], index: u64, sibs: &[[u64; 8]; DEPTH]) -> (RowMajorMatrix<F>, [u64; 8]) {
    let (hm, vinit) = vinit_consts();
    let mut vals = F::zero_vec(HEIGHT * NUM_COLS);
    let mut cur = *leaf;
    let mut root = [0u64; 8];
    for row in 0..HEIGHT {
        let base = row * NUM_COLS;
        let (dir, sib) = if row < DEPTH { ((index >> row) & 1, sibs[row]) } else { (0u64, [0u64; 8]) };
        let mut m = [0u64; 16];
        for i in 0..8 {
            if dir == 1 {
                m[i] = sib[i];
                m[8 + i] = cur[i];
            } else {
                m[i] = cur[i];
                m[8 + i] = sib[i];
            }
        }
        for i in 0..8 {
            set_word(&mut vals, base + CUR + i * W, cur[i]);
            set_word(&mut vals, base + SIB + i * W, sib[i]);
        }
        for i in 0..16 {
            set_word(&mut vals, base + mw(i), m[i]);
            set_word(&mut vals, base + vw(i), vinit[i]);
        }
        vals[base + DIR] = F::from_u64(dir);
        vals[base + CNT] = F::from_u64(row as u64);
        vals[base + SEL] = F::from_u64((row == DEPTH - 1) as u64);
        vals[base + ACC] = F::from_u64((row >= DEPTH - 1) as u64);
        // rounds
        let mut v = vinit;
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
        // feed-forward from the constant h_merkle
        let mut hout = [0u64; 8];
        for i in 0..8 {
            let ff = hm[i] ^ v[i];
            set_word(&mut vals, base + FFTMP + i * W, ff);
            hout[i] = ff ^ v[i + 8];
            set_word(&mut vals, base + HOUT + i * W, hout[i]);
        }
        if row == DEPTH - 1 {
            root = hout;
        }
        cur = hout;
    }
    (RowMajorMatrix::new(vals, NUM_COLS), root)
}

// ---- hiding / ZK config (verbatim from the harness / fib_air ZK) ----
type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Dft = Radix2DitParallel<Val>;
type ZkByteHash = Keccak256Hash;
type ZkU64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type ZkFieldHash = SerializingHasher<ZkU64Hash>;
type ZkCompress = CompressionFunctionFromHasher<ZkU64Hash, 2, 4>;
type ZkValHidingMmcs = MerkleTreeHidingMmcs<[Val; p3_keccak::VECTOR_LEN], [u64; p3_keccak::VECTOR_LEN], ZkFieldHash, ZkCompress, SmallRng, 2, 4, 4>;
type ZkChallenger = SerializingChallenger32<Val, HashChallenger<u8, ZkByteHash, 32>>;
type ZkChallengeHidingMmcs = ExtensionMmcs<Val, Challenge, ZkValHidingMmcs>;
type ZkHidingPcs = HidingFriPcs<Val, Dft, ZkValHidingMmcs, ZkChallengeHidingMmcs, SmallRng>;
type ZkConfig = StarkConfig<ZkHidingPcs, Challenge, ZkChallenger>;
fn make_zk_config() -> ZkConfig {
    let byte_hash = ZkByteHash {};
    let u64_hash = ZkU64Hash::new(KeccakF {});
    let field_hash = ZkFieldHash::new(u64_hash);
    let compress = ZkCompress::new(u64_hash);
    let val_mmcs = ZkValHidingMmcs::new(field_hash, compress, 0, SmallRng::seed_from_u64(1));
    let challenge_mmcs = ZkChallengeHidingMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_testing(challenge_mmcs, 2);
    let pcs = ZkHidingPcs::new(Dft::default(), val_mmcs, fri_params, 4, SmallRng::seed_from_u64(1));
    ZkConfig::new(pcs, ZkChallenger::from_hasher(vec![], byte_hash))
}

fn main() {
    let arg = |s: &str| std::env::args().any(|a| a == s);
    let (corrupt, flip_index, wrong_root) = (arg("--corrupt"), arg("--flip-index"), arg("--wrong-root"));
    let (_, vinit) = vinit_consts();
    let air = Blake2bMerklePathAir { vinit };
    // PRIVATE witness: the leaf (which note), its 20-bit index (where), the siblings.
    let leaf: [u64; 8] = core::array::from_fn(|i| 0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 1));
    let index: u64 = 0b1010_1101_0110_1001_1011; // 20 bits
    let sibs: [[u64; 8]; DEPTH] =
        core::array::from_fn(|l| core::array::from_fn(|i| 0xa5a5_5a5a_0000_0000u64.wrapping_add((l as u64) << 32).wrapping_mul(2 * i as u64 + 1)));
    let (mut trace, root) = generate::<Val>(&leaf, index, &sibs);
    // host diff-test: the trace's row-(DEPTH-1) digest == the FULL keyed reference
    // root (2 compressions/node, key block included) — validates the h_merkle
    // shortcut against the on-chain hash_node semantics.
    let want = root_ref(&leaf, index, &sibs);
    println!("host diff-test: trace root == full-keyed-reference root: {} (depth {DEPTH}, rows {HEIGHT}, cols {NUM_COLS})", root == want);
    if corrupt {
        trace.values[7 * NUM_COLS + SIB + 5] = Val::ONE - trace.values[7 * NUM_COLS + SIB + 5];
    }
    if flip_index {
        trace.values[5 * NUM_COLS + DIR] = Val::ONE - trace.values[5 * NUM_COLS + DIR];
    }
    let mut pis: Vec<Val> = Vec::with_capacity(8 * W);
    for w in &root {
        for k in 0..W {
            pis.push(Val::from_u64((w >> k) & 1));
        }
    }
    if wrong_root {
        pis[0] = Val::ONE - pis[0];
    }
    let config = make_zk_config();
    let t0 = std::time::Instant::now();
    let proof = prove(&config, &air, trace, &pis);
    let t_prove = t0.elapsed();
    let t1 = std::time::Instant::now();
    let res = verify(&config, &air, &proof, &pis);
    let t_verify = t1.elapsed();
    let negative = corrupt || flip_index || wrong_root;
    match &res {
        Ok(_) if negative => println!("NEGATIVE TEST FAIL — a tampered witness/root was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — depth-{DEPTH} Merkle membership at a PRIVATE index proven with the REAL node hash (full 12-round keyed-BLAKE2b-512 per level), hiding-ZK [prove {:.1?}, verify {:.1?}]",
            t_prove, t_verify
        ),
        Err(e) if negative => println!("NEGATIVE TEST PASS — tampered membership rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on valid membership: {e:?}"),
    }
    if !negative {
        // PRIVACY GATE: no private witness word (leaf, siblings, intermediate path
        // nodes) may appear in the proof bytes. The root is public by design.
        let pb = postcard::to_allocvec(&proof).unwrap();
        let has = |w: u64| {
            let le = w.to_le_bytes();
            pb.windows(8).any(|win| win == le)
        };
        let mut witness: Vec<u64> = leaf.to_vec();
        witness.extend(sibs.iter().flatten().copied());
        // intermediate nodes: re-fold and collect every non-root level digest
        let mut cur = leaf;
        for (r, sib) in sibs.iter().enumerate().take(DEPTH - 1) {
            let bit = (index >> r) & 1;
            cur = if bit == 0 { hash_node_ref(&cur, sib) } else { hash_node_ref(sib, &cur) };
            witness.extend_from_slice(&cur);
        }
        let leaked = witness.iter().filter(|&&w| has(w)).count();
        if leaked == 0 {
            println!("PRIVACY OK — leaf, {DEPTH} siblings and the intermediate path nodes ({} words) do not appear in the proof ({} bytes)", witness.len(), pb.len());
        } else {
            println!("PRIVACY LEAK — {leaked} private witness word(s) present in the proof");
        }
    }
}
