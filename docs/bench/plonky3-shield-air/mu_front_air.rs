//! C-P6 wires 8/9/10/12 — the **decode/μ-derivation FRONT** of ML-DSA-87 `Verify`, the three
//! chained SHAKE256 hashes that produce the FIPS-204 challenge, constrained END-TO-END in ONE
//! AIR with the cross-hash ties PROVEN in-circuit:
//!
//!   tr  = SHAKE256(pk)                                   (wire 9)
//!   μ   = SHAKE256(tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M)       (wire 8)
//!   c̃' = SHAKE256(μ ‖ w1Encode(w1))                      (wire 10)
//!   c̃' == c̃  (the FIPS-204 accept condition)             (wire 12)
//!
//! Until now these were `GADGET_ONLY_NOT_WIRED`: `shake_threaded_air.rs` proves ONE multi-block
//! SHAKE with its message + output bytes bound to public values, but the μ-framing (tr‖…‖M as
//! μ's message) and the tr→μ→c̃' chaining were not bound. This AIR closes that.
//!
//! ## The three hashes are three SEGMENTS of ONE trace
//! Each SHAKE256 is a run of `p3-keccak-air` permutations (24 rows each) laid out in ADJACENT
//! 24-row groups — the exact multi-block threading of `shake_threaded_air.rs` — but here THREE
//! segments sit back-to-back in one trace, each RESET to the all-zero sponge state at its first
//! permutation (a per-segment "first-absorb-into-zero-state" flag). Every cross-block sponge-
//! state wire inside a segment is the same preprocessed-flag-gated adjacent-row equality.
//!
//! ## The cross-hash ties are SHARED PUBLIC VALUES (no new constraint kind, no recursion)
//! `shake_threaded_air.rs` already binds (a) each absorbed message byte to a public value and
//! (b) each squeezed output byte to a public value. Here the GLOBAL public layout makes the
//! intermediate digests appear EXACTLY ONCE and be bound by BOTH the producing segment's output
//! and the consuming segment's message:
//!   - seg0 output bytes[0..64]  and  seg1 message bytes[0..64]  → the SAME `TR` publics
//!   - seg1 output bytes[0..64]  and  seg2 message bytes[0..64]  → the SAME `MU` publics
//!   - seg2 output bytes[0..64]                                   → the `CTILDE` publics (= c̃)
//! So `seg1.msg[0..64] == seg0.out[0..64] == tr` and `seg2.msg[0..64] == seg1.out[0..64] == μ`
//! and `seg2.out[0..64] == c̃` are all forced in-AIR: a prover cannot feed μ a `tr` other than
//! `SHAKE256(pk)`, nor c̃' a `μ` other than `SHAKE256(tr‖…‖M)`, nor accept unless `c̃' == c̃`.
//! (Fusing 3 small hashes into one STARK is measured-cheap here — ≈30 perms ≈ 720 rows — unlike
//! the ExpandA legs, whose fusion ADR-0035 measured too wide, so those route ties through
//! recursion. The shared-public tie is the strictly-stronger in-one-STARK form.)
//!
//! ## Real data
//! Driven by a REAL `libcrux_ml_dsa::ml_dsa_87` key + signature: `pk`, message `M`, ctx
//! `b"mil-receipt-v1"`, and the TRUE `tr/μ/w1/c̃` are computed by a from-scratch FIPS-204
//! reference (the `mldsa_verify_ref.rs` functions, ported) whose accept⇔accept vs libcrux is the
//! pinned oracle; `c̃' == c̃` is checked against the REAL signature's c̃ (the actual accept).
//!
//! ## Gates (host + in-AIR + negatives)
//!  GATE 1 — host sponge oracle == `sha3::Shake256` byte-for-byte on the three real messages.
//!  GATE 2 — proven trace re-read: each segment's squeeze output bytes == sha3, byte-for-byte.
//!  GATE 3 — the reference front == libcrux accept (real signature verifies) and c̃' == c̃.
//!  GATE 4 — coverage self-audit: every boundary (lane,limb), every block byte, every tie index
//!           bound exactly once; the three shared-tie public ranges coincide as designed.
//!  VERIFY — the whole 3-hash chain proves + verifies in ONE AIR.
//!  NEGATIVES (all reject): `--corrupt-thread` (a sponge-state wire between two perms of seg2),
//!           `--corrupt-tie` (feed μ a tr byte ≠ SHAKE256(pk) — the shared-public tie breaks),
//!           `--corrupt-ctilde` (flip a c̃ public — c̃' ≠ c̃), `--corrupt-w1` (flip a w1 message
//!           byte so c̃' changes but c̃ is unchanged).
//!
//! Repro: `cargo run --release --bin mu_front_air
//!   [--corrupt-thread|--corrupt-tie|--corrupt-ctilde|--corrupt-w1]` in `~/Plonky3/shield-air`.

use core::borrow::Borrow;
use libcrux_ml_dsa::ml_dsa_87;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::KeccakF;
use p3_keccak_air::{
    KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, NUM_ROUNDS_MIN_1, RC, U64_LIMBS, generate_trace_rows,
};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

const BPL: usize = 16;
const RATE_LANES: usize = 17; // SHAKE256 rate = 136 bytes = 17 lanes
const RATE_BYTES: usize = RATE_LANES * 8; // 136
const RATE_BITS: usize = RATE_LANES * 64; // 1088
const CTX: &[u8] = b"mil-receipt-v1";

// ===========================================================================================
// Reference ML-DSA-87 front (ported verbatim from mldsa_verify_ref.rs), returning the REAL
// tr / μ / w1Encode / c̃ of a genuine libcrux signature so the AIR proves over real values.
// ===========================================================================================
mod refmldsa {
    use super::*;
    pub const Q: i64 = 8380417;
    pub const N: usize = 256;
    pub const K: usize = 8;
    pub const L: usize = 7;
    pub const D: u32 = 13;
    pub const GAMMA1: i64 = 1 << 19;
    pub const GAMMA2: i64 = (Q - 1) / 32;
    pub const TAU: usize = 60;
    pub const BETA: i64 = 120;
    pub const OMEGA: usize = 75;
    pub const ZETA: i64 = 1753;
    pub const CTILDE: usize = 64;
    pub const ZPB: usize = N * 20 / 8;
    pub type Poly = [i64; N];

    fn m(x: i64) -> i64 {
        let r = x % Q;
        if r < 0 { r + Q } else { r }
    }
    fn mul(a: i64, b: i64) -> i64 {
        m((a as i128 * b as i128 % Q as i128) as i64)
    }
    fn powq(mut b: i64, mut e: u64) -> i64 {
        let mut r = 1i64;
        b = m(b);
        while e > 0 {
            if e & 1 == 1 {
                r = mul(r, b);
            }
            b = mul(b, b);
            e >>= 1;
        }
        r
    }
    fn brv8(mut x: usize) -> usize {
        let mut r = 0;
        for _ in 0..8 {
            r = (r << 1) | (x & 1);
            x >>= 1;
        }
        r
    }
    fn zetas() -> [i64; N] {
        core::array::from_fn(|k| powq(ZETA, brv8(k) as u64))
    }
    fn ntt(a: &mut Poly, z: &[i64; N]) {
        let mut k = 0usize;
        let mut len = 128usize;
        while len >= 1 {
            let mut start = 0;
            while start < N {
                k += 1;
                let zeta = z[k];
                for j in start..start + len {
                    let t = mul(zeta, a[j + len]);
                    a[j + len] = m(a[j] - t);
                    a[j] = m(a[j] + t);
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }
    fn invntt(a: &mut Poly, z: &[i64; N]) {
        let mut k = N;
        let mut len = 1usize;
        while len < N {
            let mut start = 0;
            while start < N {
                k -= 1;
                let zeta = z[k];
                for j in start..start + len {
                    let t = a[j];
                    a[j] = m(t + a[j + len]);
                    a[j + len] = mul(zeta, m(a[j + len] - t));
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        let ninv = powq(N as i64, (Q - 2) as u64);
        for x in a.iter_mut() {
            *x = mul(*x, ninv);
        }
    }
    fn pointwise(a: &Poly, b: &Poly) -> Poly {
        core::array::from_fn(|i| mul(a[i], b[i]))
    }
    fn unpack(bytes: &[u8], nbits: usize, count: usize) -> Vec<u32> {
        let mut out = Vec::with_capacity(count);
        let (mut acc, mut have, mut bi) = (0u64, 0usize, 0usize);
        for _ in 0..count {
            while have < nbits {
                acc |= (bytes[bi] as u64) << have;
                have += 8;
                bi += 1;
            }
            out.push((acc & ((1 << nbits) - 1)) as u32);
            acc >>= nbits;
            have -= nbits;
        }
        out
    }
    fn pk_decode(pk: &[u8]) -> ([u8; 32], Vec<Poly>) {
        let rho: [u8; 32] = pk[0..32].try_into().unwrap();
        let mut t1 = Vec::with_capacity(K);
        for i in 0..K {
            let raw = unpack(&pk[32 + i * 320..32 + (i + 1) * 320], 10, N);
            t1.push(core::array::from_fn::<i64, N, _>(|j| raw[j] as i64));
        }
        (rho, t1)
    }
    fn sig_decode(sig: &[u8]) -> Option<([u8; 64], Vec<Poly>, Vec<[bool; N]>)> {
        let ctilde: [u8; 64] = sig[0..64].try_into().unwrap();
        let mut z = Vec::with_capacity(L);
        for i in 0..L {
            let raw = unpack(&sig[CTILDE + i * ZPB..CTILDE + (i + 1) * ZPB], 20, N);
            z.push(core::array::from_fn::<i64, N, _>(|j| GAMMA1 - raw[j] as i64));
        }
        let y = &sig[CTILDE + L * ZPB..];
        let mut h = vec![[false; N]; K];
        let mut index = 0usize;
        for i in 0..K {
            let end = y[OMEGA + i] as usize;
            if end < index || end > OMEGA {
                return None;
            }
            let mut last: i32 = -1;
            for j in index..end {
                let pos = y[j] as i32;
                if pos <= last {
                    return None;
                }
                last = pos;
                h[i][pos as usize] = true;
            }
            index = end;
        }
        for &b in &y[index..OMEGA] {
            if b != 0 {
                return None;
            }
        }
        Some((ctilde, z, h))
    }
    fn expand_a(rho: &[u8; 32]) -> Vec<Vec<Poly>> {
        let mut a = vec![vec![[0i64; N]; L]; K];
        for r in 0..K {
            for s in 0..L {
                let mut sh = Shake128::default();
                sh.update(rho);
                sh.update(&[s as u8, r as u8]);
                let mut rd = sh.finalize_xof();
                let mut buf = [0u8; 3];
                let mut cnt = 0usize;
                while cnt < N {
                    rd.read(&mut buf);
                    let coef = (buf[0] as i64) | ((buf[1] as i64) << 8) | (((buf[2] & 0x7f) as i64) << 16);
                    if coef < Q {
                        a[r][s][cnt] = coef;
                        cnt += 1;
                    }
                }
            }
        }
        a
    }
    fn sample_in_ball(ctilde: &[u8]) -> Poly {
        let mut c = [0i64; N];
        let mut sh = Shake256::default();
        sh.update(ctilde);
        let mut rd = sh.finalize_xof();
        let mut sbytes = [0u8; 8];
        rd.read(&mut sbytes);
        let mut signs = u64::from_le_bytes(sbytes);
        let mut jb = [0u8; 1];
        for i in (N - TAU)..N {
            let j = loop {
                rd.read(&mut jb);
                if (jb[0] as usize) <= i {
                    break jb[0] as usize;
                }
            };
            c[i] = c[j];
            c[j] = 1 - 2 * (signs & 1) as i64;
            signs >>= 1;
        }
        c
    }
    fn decompose(r: i64) -> (i64, i64) {
        let r = m(r);
        let g2 = 2 * GAMMA2;
        let mut r0 = r % g2;
        if r0 > GAMMA2 {
            r0 -= g2;
        }
        if r - r0 == Q - 1 {
            (0, r0 - 1)
        } else {
            ((r - r0) / g2, r0)
        }
    }
    fn use_hint(hbit: bool, r: i64) -> i64 {
        let mm = (Q - 1) / (2 * GAMMA2);
        let (r1, r0) = decompose(r);
        if hbit {
            if r0 > 0 { (r1 + 1).rem_euclid(mm) } else { (r1 - 1).rem_euclid(mm) }
        } else {
            r1
        }
    }
    fn w1_encode(w1: &[Poly]) -> Vec<u8> {
        let mut bits: Vec<u8> = Vec::new();
        let mut acc = 0u64;
        let mut have = 0;
        for poly in w1 {
            for &c in poly.iter() {
                acc |= (c as u64) << have;
                have += 4;
                while have >= 8 {
                    bits.push((acc & 0xff) as u8);
                    acc >>= 8;
                    have -= 8;
                }
            }
        }
        if have > 0 {
            bits.push((acc & 0xff) as u8);
        }
        bits
    }
    pub fn shake256(parts: &[&[u8]], outlen: usize) -> Vec<u8> {
        let mut sh = Shake256::default();
        for p in parts {
            sh.update(p);
        }
        let mut rd = sh.finalize_xof();
        let mut o = vec![0u8; outlen];
        rd.read(&mut o);
        o
    }

    /// The REAL front values (tr, μ, w1Encode, c̃) of a genuine signature, plus the recomputed
    /// c̃' — computed exactly as FIPS-204 §5.3, so `ctilde_p == ctilde` iff the signature is valid.
    pub struct Front {
        pub tr: Vec<u8>,
        pub mu: Vec<u8>,
        pub w1: Vec<u8>,
        pub ctilde: Vec<u8>,
        pub ctilde_p: Vec<u8>,
    }
    pub fn compute_front(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Front {
        let z = zetas();
        let (rho, t1) = pk_decode(pk);
        let (ctilde, zpoly, hbits) = sig_decode(sig).expect("sig decodes");
        let a = expand_a(&rho);
        let tr = shake256(&[pk], 64);
        let mu = shake256(&[&tr, &[0u8, ctx.len() as u8], ctx, msg], 64);
        let c = sample_in_ball(&ctilde);
        let mut chat = c;
        ntt(&mut chat, &z);
        let mut zhat: Vec<Poly> = zpoly.iter().map(|p| { let mut q = *p; ntt(&mut q, &z); q }).collect();
        let t1hat: Vec<Poly> = t1.iter().map(|p| { let mut q: Poly = core::array::from_fn(|i| mul(p[i], 1 << D)); ntt(&mut q, &z); q }).collect();
        let mut w1: Vec<Poly> = Vec::with_capacity(K);
        for i in 0..K {
            let mut what = [0i64; N];
            for s in 0..L {
                let pw = pointwise(&a[i][s], &mut zhat[s]);
                for j in 0..N {
                    what[j] = m(what[j] + pw[j]);
                }
            }
            let ct = pointwise(&chat, &t1hat[i]);
            for j in 0..N {
                what[j] = m(what[j] - ct[j]);
            }
            invntt(&mut what, &z);
            let w1i: Poly = core::array::from_fn(|j| use_hint(hbits[i][j], what[j]));
            w1.push(w1i);
        }
        let w1b = w1_encode(&w1);
        let ctilde_p = shake256(&[&mu, &w1b], CTILDE);
        Front { tr, mu, w1: w1b, ctilde: ctilde.to_vec(), ctilde_p }
    }
}

// ===========================================================================================
// Host sponge oracle + padded-block helpers (verbatim from shake_threaded_air.rs)
// ===========================================================================================

fn keccakf(mut st: [u64; 25]) -> [u64; 25] {
    KeccakF.permute_mut(&mut st);
    st
}
fn padded_blocks(msg: &[u8], rate: usize) -> Vec<Vec<u8>> {
    let mut p = msg.to_vec();
    p.push(0x1F);
    while p.len() % rate != 0 {
        p.push(0x00);
    }
    let last = p.len() - 1;
    p[last] |= 0x80;
    p.chunks_exact(rate).map(|c| c.to_vec()).collect()
}
fn xor_block_into_state(state: &mut [u64; 25], block: &[u8]) {
    for (i, chunk) in block.chunks(8).enumerate() {
        let mut lane = [0u8; 8];
        lane[..chunk.len()].copy_from_slice(chunk);
        state[i] ^= u64::from_le_bytes(lane);
    }
}
fn state_to_bytes(state: &[u64; 25]) -> [u8; 200] {
    let mut b = [0u8; 200];
    for (i, lane) in state.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
    }
    b
}
fn shake_over_keccakf(msg: &[u8], rate: usize, out_len: usize) -> Vec<u8> {
    let mut state = [0u64; 25];
    for block in padded_blocks(msg, rate) {
        xor_block_into_state(&mut state, &block);
        state = keccakf(state);
    }
    let mut out = Vec::with_capacity(out_len);
    loop {
        let take = core::cmp::min(rate, out_len - out.len());
        out.extend_from_slice(&state_to_bytes(&state)[..take]);
        if out.len() == out_len {
            break;
        }
        state = keccakf(state);
    }
    out
}
fn ref_shake256(msg: &[u8], out_len: usize) -> Vec<u8> {
    let mut o = vec![0u8; out_len];
    let mut h = Shake256::default();
    h.update(msg);
    h.finalize_xof().read(&mut o);
    o
}

// ===========================================================================================
// MuFrontAir — three SHAKE256 segments in one trace with shared-public cross-hash ties
// ===========================================================================================

/// One SHAKE256 hash: its message length (bytes) and, for its single squeeze block, the global
/// public index of each of the 136 output bytes and each of the `msg_len` message bytes.
struct Seg {
    msg_len: usize,
    perm_offset: usize, // first permutation index of this segment in the global chain
    num_absorb: usize,
    msg_pub: Vec<usize>, // len msg_len: global public index of message byte i
    out_pub: Vec<usize>, // len RATE_BYTES: global public index of squeeze-output byte i
}
impl Seg {
    /// Byte dispositions of absorbed block k: `Ok(pi)` = message byte bound to public `pi`,
    /// `Err(c)` = pad byte pinned bit-by-bit to constant `c` (FIPS-202 pad10*1 / 0x1F).
    fn block_bytes(&self, k: usize) -> Vec<(usize, Result<usize, u8>)> {
        let padded_len = self.num_absorb * RATE_BYTES;
        (0..RATE_BYTES)
            .map(|i| {
                let g = k * RATE_BYTES + i;
                if g < self.msg_len {
                    (i, Ok(self.msg_pub[g]))
                } else {
                    let mut b = 0u8;
                    if g == self.msg_len {
                        b |= 0x1F;
                    }
                    if g == padded_len - 1 {
                        b |= 0x80;
                    }
                    (i, Err(b))
                }
            })
            .collect()
    }
}

struct MuFrontAir {
    segs: Vec<Seg>,
    n_pub: usize,
    total_perms: usize,
}

impl MuFrontAir {
    /// Build the 3-segment μ-front with the global public layout that realizes the ties.
    /// Public layout: PK | TR(64) | S0REST(72) | MUTAIL | MU(64) | S1REST(72) | W1 | CTILDE(64)
    /// | S2REST(72). TR is shared by seg0.out[0..64] & seg1.msg[0..64]; MU by seg1.out[0..64] &
    /// seg2.msg[0..64]; CTILDE = seg2.out[0..64] (= c̃).
    fn new(lpk: usize, lmu_tail: usize, lw1: usize) -> Self {
        // ---- allocate public slots ----
        let mut cur = 0usize;
        let alloc = |cur: &mut usize, n: usize| -> Vec<usize> {
            let v = (*cur..*cur + n).collect();
            *cur += n;
            v
        };
        let pk = alloc(&mut cur, lpk);
        let tr = alloc(&mut cur, 64);
        let s0rest = alloc(&mut cur, RATE_BYTES - 64);
        let mutail = alloc(&mut cur, lmu_tail);
        let mu = alloc(&mut cur, 64);
        let s1rest = alloc(&mut cur, RATE_BYTES - 64);
        let w1 = alloc(&mut cur, lw1);
        let ctilde = alloc(&mut cur, 64);
        let s2rest = alloc(&mut cur, RATE_BYTES - 64);
        let n_pub = cur;

        // ---- segment message maps (with the shared prefixes) ----
        // seg0: tr = SHAKE256(pk); msg = pk. out[0..64]=tr, out[64..136]=s0rest.
        let s0_msg: Vec<usize> = pk.clone();
        let s0_out: Vec<usize> = tr.iter().chain(s0rest.iter()).copied().collect();
        // seg1: μ = SHAKE256(tr ‖ tail); msg = tr(64) ‖ tail. out[0..64]=mu, out[64..136]=s1rest.
        let s1_msg: Vec<usize> = tr.iter().chain(mutail.iter()).copied().collect();
        let s1_out: Vec<usize> = mu.iter().chain(s1rest.iter()).copied().collect();
        // seg2: c̃' = SHAKE256(μ ‖ w1); msg = mu(64) ‖ w1. out[0..64]=ctilde(=c̃).
        let s2_msg: Vec<usize> = mu.iter().chain(w1.iter()).copied().collect();
        let s2_out: Vec<usize> = ctilde.iter().chain(s2rest.iter()).copied().collect();

        let lens = [lpk, 64 + lmu_tail, 64 + lw1];
        let msgs = [s0_msg, s1_msg, s2_msg];
        let outs = [s0_out, s1_out, s2_out];
        let mut segs = Vec::new();
        let mut off = 0usize;
        for i in 0..3 {
            let na = (lens[i] + 1).div_ceil(RATE_BYTES); // pad10*1 always adds ≥1 byte
            assert_eq!(msgs[i].len(), lens[i]);
            assert_eq!(outs[i].len(), RATE_BYTES);
            segs.push(Seg {
                msg_len: lens[i],
                perm_offset: off,
                num_absorb: na,
                msg_pub: msgs[i].clone(),
                out_pub: outs[i].clone(),
            });
            off += na; // num_squeeze = 1 ⇒ num_perms = num_absorb
        }
        MuFrontAir { segs, n_pub, total_perms: off }
    }

    fn total_width(&self) -> usize {
        NUM_KECCAK_COLS + 3 * RATE_BITS
    }
    fn x_state(&self) -> usize {
        NUM_KECCAK_COLS
    }
    fn x_block(&self) -> usize {
        NUM_KECCAK_COLS + RATE_BITS
    }
    fn x_out(&self) -> usize {
        NUM_KECCAK_COLS + 2 * RATE_BITS
    }
    fn height(&self) -> usize {
        (self.total_perms * NUM_ROUNDS).next_power_of_two()
    }
    // ---- preprocessed flag columns: per-segment first-absorb, absorb boundaries, output ----
    fn prep_width(&self) -> usize {
        // 3 first-absorb + Σ(na−1) absorb-boundary + 3 output flags
        let inner: usize = self.segs.iter().map(|s| s.num_absorb - 1).sum();
        3 + inner + 3
    }
    fn p_first(&self, s: usize) -> usize {
        s
    }
    fn p_abs(&self, s: usize, k: usize) -> usize {
        // k in 1..num_absorb of seg s
        let before: usize = self.segs[..s].iter().map(|x| x.num_absorb - 1).sum();
        3 + before + (k - 1)
    }
    fn p_out(&self, s: usize) -> usize {
        let inner: usize = self.segs.iter().map(|x| x.num_absorb - 1).sum();
        3 + inner + s
    }
}

impl<F: PrimeField64> BaseAir<F> for MuFrontAir {
    fn width(&self) -> usize {
        self.total_width()
    }
    fn num_public_values(&self) -> usize {
        self.n_pub
    }
    fn preprocessed_width(&self) -> usize {
        self.prep_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let w = self.prep_width();
        let mut vals = F::zero_vec(self.height() * w);
        for (s, seg) in self.segs.iter().enumerate() {
            let base = seg.perm_offset;
            // first-absorb-into-zero-state flag: row 0 of this segment's first perm
            vals[(NUM_ROUNDS * base) * w + self.p_first(s)] = F::ONE;
            // absorb-boundary flags: last row of perm (base+k-1) → first row of perm (base+k)
            for k in 1..seg.num_absorb {
                vals[(NUM_ROUNDS * (base + k) - 1) * w + self.p_abs(s, k)] = F::ONE;
            }
            // output-binding flag: last row of the segment's last perm
            vals[(NUM_ROUNDS * (base + seg.num_absorb) - 1) * w + self.p_out(s)] = F::ONE;
        }
        Some(RowMajorMatrix::new(vals, w))
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

fn rc_bits_table() -> [[u8; 64]; 24] {
    let mut t = [[0u8; 64]; 24];
    for (r, row) in t.iter_mut().enumerate() {
        for (z, bit) in row.iter_mut().enumerate() {
            *bit = ((RC[r] >> z) & 1) as u8;
        }
    }
    t
}

/// The COMPLETE upstream `p3-keccak-air` eval (round flags + all permutation constraints),
/// vendored verbatim from shake_threaded_air.rs (which vendored ~/Plonky3/keccak-air).
fn eval_keccak<AB: AirBuilder>(builder: &mut AB) {
    let rc_bits = rc_bits_table();
    let main = builder.main();
    let row = main.current_slice();
    let nxt = main.next_slice();
    let local: &KeccakCols<AB::Var> = row[..NUM_KECCAK_COLS].borrow();
    let next: &KeccakCols<AB::Var> = nxt[..NUM_KECCAK_COLS].borrow();

    builder.when_first_row().assert_one(local.step_flags[0]);
    builder
        .when_first_row()
        .assert_zeros::<NUM_ROUNDS_MIN_1, _>(local.step_flags[1..].try_into().unwrap());
    builder
        .when_transition()
        .assert_zeros::<NUM_ROUNDS, _>(core::array::from_fn(|i| {
            local.step_flags[i] - next.step_flags[(i + 1) % NUM_ROUNDS]
        }));

    let first_step = local.step_flags[0];
    let final_step = local.step_flags[NUM_ROUNDS - 1];
    let not_final_step = AB::Expr::ONE - final_step;
    let transition_and_not_final = builder.is_transition() * not_final_step.clone();

    for y in 0..5 {
        for x in 0..5 {
            builder
                .when(first_step)
                .assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
                    local.preimage[y][x][limb] - local.a[y][x][limb]
                }));
        }
    }
    for y in 0..5 {
        for x in 0..5 {
            builder
                .when(transition_and_not_final.clone())
                .assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
                    local.preimage[y][x][limb] - next.preimage[y][x][limb]
                }));
        }
    }
    builder.assert_bool(local.export);
    builder.when(not_final_step).assert_zero(local.export);
    for x in 0..5 {
        builder.assert_bools(local.c[x]);
        builder.assert_zeros::<64, _>(core::array::from_fn(|z| {
            let xor = local.c[x][z].into().xor3(
                &local.c[(x + 4) % 5][z].into(),
                &local.c[(x + 1) % 5][(z + 63) % 64].into(),
            );
            local.c_prime[x][z] - xor
        }));
    }
    for x in 0..5 {
        let c_xor_c_prime: [AB::Expr; 64] =
            core::array::from_fn(|z| local.c[x][z].into().xor(&local.c_prime[x][z].into()));
        for y in 0..5 {
            let get_bit = |z: usize| local.a_prime[y][x][z].into().xor(&c_xor_c_prime[z]);
            builder.assert_bools(local.a_prime[y][x]);
            builder.assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
                let computed_limb = (limb * BPL..(limb + 1) * BPL)
                    .rev()
                    .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_bit(z));
                computed_limb - local.a[y][x][limb]
            }));
        }
    }
    for x in 0..5 {
        let four = AB::Expr::TWO.double();
        builder.assert_zeros::<64, _>(core::array::from_fn(|z| {
            let sum: AB::Expr = (0..5).map(|y| local.a_prime[y][x][z].into()).sum();
            let diff = sum - local.c_prime[x][z];
            diff.clone() * (diff.clone() - AB::Expr::TWO) * (diff - four.clone())
        }));
    }
    for y in 0..5 {
        for x in 0..5 {
            let get_bit = |z| {
                let andn = local
                    .b((x + 1) % 5, y, z)
                    .into()
                    .andn(&local.b((x + 2) % 5, y, z).into());
                andn.xor(&local.b(x, y, z).into())
            };
            builder.assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
                let computed_limb = (limb * BPL..(limb + 1) * BPL)
                    .rev()
                    .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_bit(z));
                computed_limb - local.a_prime_prime[y][x][limb]
            }));
        }
    }
    builder.assert_bools(local.a_prime_prime_0_0_bits);
    builder.assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
        let computed = (limb * BPL..(limb + 1) * BPL)
            .rev()
            .fold(AB::Expr::ZERO, |acc, z| acc.double() + local.a_prime_prime_0_0_bits[z]);
        computed - local.a_prime_prime[0][0][limb]
    }));
    let get_xored_bit = |i: usize| {
        let rc_bit_i: AB::Expr = local
            .step_flags
            .iter()
            .zip(rc_bits.iter())
            .filter(|(_, rc_bits_r)| rc_bits_r[i] != 0)
            .map(|(&step_flag, _)| step_flag.into())
            .sum();
        rc_bit_i.xor(&AB::Expr::from(local.a_prime_prime_0_0_bits[i]))
    };
    builder.assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
        let computed = (limb * BPL..(limb + 1) * BPL)
            .rev()
            .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_xored_bit(z));
        computed - local.a_prime_prime_prime_0_0_limbs[limb]
    }));
    for x in 0..5 {
        for y in 0..5 {
            builder
                .when(transition_and_not_final.clone())
                .assert_zeros::<U64_LIMBS, _>(core::array::from_fn(|limb| {
                    local.a_prime_prime_prime(y, x, limb) - next.a[y][x][limb]
                }));
        }
    }
}

fn input_wires() -> Vec<(usize, usize, bool)> {
    (0..25)
        .flat_map(|l| (0..U64_LIMBS).map(move |m| (l, m, l < RATE_LANES)))
        .collect()
}

impl<AB: AirBuilder> Air<AB> for MuFrontAir
where
    AB::F: PrimeField64,
{
    fn eval(&self, builder: &mut AB) {
        eval_keccak::<AB>(builder);

        let pis: Vec<AB::Expr> = (0..self.n_pub).map(|k| builder.public_values()[k].into()).collect();
        let prep: Vec<AB::Var> = builder.preprocessed().current_slice().to_vec();
        let main = builder.main();
        let row = main.current_slice();
        let nxt = main.next_slice();
        let lk: &KeccakCols<AB::Var> = row[..NUM_KECCAK_COLS].borrow();
        let nk: &KeccakCols<AB::Var> = nxt[..NUM_KECCAK_COLS].borrow();
        let one = AB::Expr::ONE;

        // booleanity of every extra bit column (state / block / output bits).
        for i in 0..3 * RATE_BITS {
            let b: AB::Expr = row[NUM_KECCAK_COLS + i].into();
            builder.assert_zero(b.clone() * (b - one.clone()));
        }

        let sbit = |i: usize| -> AB::Expr { row[self.x_state() + i].into() };
        let bbit = |i: usize| -> AB::Expr { row[self.x_block() + i].into() };
        let pow2 = |j: usize| AB::Expr::from_u64(1u64 << j);
        let block_limb = |l: usize, m: usize| -> AB::Expr {
            (0..BPL).fold(AB::Expr::ZERO, |acc, j| acc + bbit(l * 64 + m * BPL + j) * pow2(j))
        };
        let state_limb = |l: usize, m: usize| -> AB::Expr {
            (0..BPL).fold(AB::Expr::ZERO, |acc, j| acc + sbit(l * 64 + m * BPL + j) * pow2(j))
        };
        let xor_limb = |l: usize, m: usize| -> AB::Expr {
            (0..BPL).fold(AB::Expr::ZERO, |acc, j| {
                let i = l * 64 + m * BPL + j;
                acc + sbit(i).xor(&bbit(i)) * pow2(j)
            })
        };
        let out_byte = |i: usize| -> AB::Expr {
            (0..8).fold(AB::Expr::ZERO, |acc, t| acc + row[self.x_out() + i * 8 + t].into() * pow2(t))
        };

        let bind_block = |builder: &mut AB, f: &AB::Expr, seg: &Seg, k: usize| {
            for (i, disp) in seg.block_bytes(k) {
                match disp {
                    Ok(pi) => {
                        let byte = (0..8).fold(AB::Expr::ZERO, |acc, t| acc + bbit(i * 8 + t) * pow2(t));
                        builder.assert_zero(f.clone() * (byte - pis[pi].clone()));
                    }
                    Err(c) => {
                        for t in 0..8 {
                            let cb = AB::Expr::from_u64(((c >> t) & 1) as u64);
                            builder.assert_zero(f.clone() * (bbit(i * 8 + t) - cb));
                        }
                    }
                }
            }
        };

        for (s, seg) in self.segs.iter().enumerate() {
            // (1) first absorb of this segment into the ALL-ZERO state.
            let f0: AB::Expr = prep[self.p_first(s)].into();
            for (l, m, is_rate) in input_wires() {
                let pre: AB::Expr = lk.preimage[l / 5][l % 5][m].into();
                if is_rate {
                    builder.assert_zero(f0.clone() * (pre - block_limb(l, m)));
                } else {
                    builder.assert_zero(f0.clone() * pre);
                }
            }
            bind_block(builder, &f0, seg, 0);

            // (2) absorb boundaries within the segment.
            for k in 1..seg.num_absorb {
                let f: AB::Expr = prep[self.p_abs(s, k)].into();
                for l in 0..RATE_LANES {
                    for mm in 0..U64_LIMBS {
                        let out: AB::Expr = lk.a_prime_prime_prime(l / 5, l % 5, mm).into();
                        builder.assert_zero(f.clone() * (state_limb(l, mm) - out));
                    }
                }
                for (l, m, is_rate) in input_wires() {
                    let pre: AB::Expr = nk.preimage[l / 5][l % 5][m].into();
                    if is_rate {
                        builder.assert_zero(f.clone() * (pre - xor_limb(l, m)));
                    } else {
                        let out: AB::Expr = lk.a_prime_prime_prime(l / 5, l % 5, m).into();
                        builder.assert_zero(f.clone() * (pre - out));
                    }
                }
                bind_block(builder, &f, seg, k);
            }

            // (3) squeeze output: rate lanes of the segment's final state == public bytes,
            //     each output byte canonical (8-bit range check via x_out region).
            let f: AB::Expr = prep[self.p_out(s)].into();
            for l in 0..RATE_LANES {
                for mm in 0..U64_LIMBS {
                    let out: AB::Expr = lk.a_prime_prime_prime(l / 5, l % 5, mm).into();
                    let lo_byte = l * 8 + mm * 2;
                    let base_lo = seg.out_pub[lo_byte];
                    let base_hi = seg.out_pub[lo_byte + 1];
                    builder.assert_zero(f.clone() * (pis[base_lo].clone() - out_byte(lo_byte)));
                    builder.assert_zero(f.clone() * (pis[base_hi].clone() - out_byte(lo_byte + 1)));
                    let expect = pis[base_lo].clone() + AB::Expr::from_u64(256) * pis[base_hi].clone();
                    builder.assert_zero(f.clone() * (out - expect));
                }
            }
        }
    }
}

// ===========================================================================================
// Trace generation
// ===========================================================================================

#[derive(Clone, Copy, PartialEq)]
enum Corrupt {
    None,
    Thread,
    Tie,
    Ctilde,
    W1,
}

/// Build the concatenated permutation-input chain over all segments (each from zero state),
/// returning per-segment output bytes (136 each) and the flat inputs vector for the trace gen.
struct Chains {
    inputs: Vec<[u64; 25]>,
    seg_out: Vec<Vec<u8>>, // per segment: the 136 squeeze-output bytes
    seg_blocks: Vec<Vec<Vec<u8>>>, // per segment: its padded blocks
}
fn build_chains(air: &MuFrontAir, msgs: &[Vec<u8>], corrupt: Corrupt) -> Chains {
    let mut inputs = Vec::new();
    let mut seg_out = Vec::new();
    let mut seg_blocks = Vec::new();
    for (s, seg) in air.segs.iter().enumerate() {
        let blocks = padded_blocks(&msgs[s], RATE_BYTES);
        assert_eq!(blocks.len(), seg.num_absorb, "seg {s} block count");
        let mut st = [0u64; 25];
        let mut outs = [0u64; 25];
        for (k, block) in blocks.iter().enumerate() {
            let mut inp = st;
            xor_block_into_state(&mut inp, block);
            // corrupt-thread: flip a rate-lane bit of the input to the 2nd perm of seg2, keeping
            // that perm internally valid + all downstream consistent (only the absorb-boundary
            // XOR wire is violated).
            if corrupt == Corrupt::Thread && s == 2 && k == 1 {
                inp[3] ^= 1 << 5;
            }
            inputs.push(inp);
            st = keccakf(inp);
            outs = st;
        }
        seg_out.push(state_to_bytes(&outs)[..RATE_BYTES].to_vec());
        seg_blocks.push(blocks);
    }
    assert_eq!(inputs.len(), air.total_perms);
    Chains { inputs, seg_out, seg_blocks }
}

fn generate<F: PrimeField64>(air: &MuFrontAir, chains: &Chains) -> RowMajorMatrix<F> {
    let kc = generate_trace_rows::<F>(chains.inputs.clone(), 0);
    let h = air.height();
    assert_eq!(kc.height(), h, "keccak trace height != instance height");
    let w = air.total_width();
    let mut vals = F::zero_vec(h * w);
    for r in 0..h {
        vals[r * w..r * w + NUM_KECCAK_COLS]
            .copy_from_slice(&kc.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
    }
    fn put_bits<F: PrimeField64>(vals: &mut [F], w: usize, row: usize, base: usize, bytes: &[u8]) {
        for (i, &bv) in bytes.iter().enumerate() {
            for t in 0..8 {
                vals[row * w + base + i * 8 + t] = F::from_u64(((bv >> t) & 1) as u64);
            }
        }
    }
    for (s, seg) in air.segs.iter().enumerate() {
        let base = seg.perm_offset;
        // segment's first block at its first perm's row 0
        put_bits(&mut vals, w, NUM_ROUNDS * base, air.x_block(), &chains.seg_blocks[s][0]);
        // absorb-boundary rows: prior perm output state bytes + next block bytes
        for k in 1..seg.num_absorb {
            let r = NUM_ROUNDS * (base + k) - 1;
            let mut st = [0u64; 25];
            for blk in &chains.seg_blocks[s][..k] {
                xor_block_into_state(&mut st, blk);
                st = keccakf(st);
            }
            put_bits(&mut vals, w, r, air.x_state(), &state_to_bytes(&st)[..RATE_BYTES]);
            put_bits(&mut vals, w, r, air.x_block(), &chains.seg_blocks[s][k]);
        }
        // output-binding row: the segment's squeeze output bytes (8-bit decomposition, M-09)
        let r = NUM_ROUNDS * (base + seg.num_absorb) - 1;
        put_bits(&mut vals, w, r, air.x_out(), &chains.seg_out[s]);
    }
    RowMajorMatrix::new(vals, w)
}

// ===========================================================================================
// STARK config (verbatim from shake_threaded_air.rs — bench FRI params, NOT production)
// ===========================================================================================

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

// ===========================================================================================
// GATE 4 — coverage self-audit
// ===========================================================================================
fn self_audit(air: &MuFrontAir) {
    // every boundary (lane,limb) bound once with the right rate/capacity split
    let wires = input_wires();
    assert_eq!(wires.len(), 25 * U64_LIMBS);
    let mut seen = [[false; U64_LIMBS]; 25];
    for &(l, m, is_rate) in &wires {
        assert!(!seen[l][m], "dup wire");
        seen[l][m] = true;
        assert_eq!(is_rate, l < RATE_LANES);
    }
    assert!(seen.iter().all(|r| r.iter().all(|&x| x)));

    // every message byte + pad byte of every block bound once; the shared-tie public ranges
    // coincide as designed.
    let (mut n_msg, mut n_pad) = (0usize, 0usize);
    for seg in &air.segs {
        for k in 0..seg.num_absorb {
            let bb = seg.block_bytes(k);
            assert_eq!(bb.len(), RATE_BYTES);
            for (_, disp) in bb {
                match disp {
                    Ok(_) => n_msg += 1,
                    Err(_) => n_pad += 1,
                }
            }
        }
        assert_eq!(seg.out_pub.len(), RATE_BYTES);
    }
    let total_msg: usize = air.segs.iter().map(|s| s.msg_len).sum();
    assert_eq!(n_msg, total_msg, "message-byte bindings");
    // ties: seg0.out[0..64] == seg1.msg[0..64]; seg1.out[0..64] == seg2.msg[0..64].
    for i in 0..64 {
        assert_eq!(air.segs[0].out_pub[i], air.segs[1].msg_pub[i], "TR tie byte {i}");
        assert_eq!(air.segs[1].out_pub[i], air.segs[2].msg_pub[i], "MU tie byte {i}");
    }
    println!(
        "GATE 4 ok — coverage self-audit: {} boundary (lane,limb) wires; {n_msg} message-byte + \
         {n_pad} pad-byte block bindings across {} segments; the 64-byte TR tie \
         (seg0.out==seg1.msg) and 64-byte MU tie (seg1.out==seg2.msg) share public indices \
         exactly; c̃'=seg2.out[0..64] bound to the c̃ publics",
        wires.len(),
        air.segs.len()
    );
}

// ===========================================================================================
// Driver
// ===========================================================================================
fn main() {
    let arg = |s: &str| std::env::args().any(|a| a == s);
    let corrupt = if arg("--corrupt-thread") || arg("--corrupt") {
        Corrupt::Thread
    } else if arg("--corrupt-tie") {
        Corrupt::Tie
    } else if arg("--corrupt-ctilde") {
        Corrupt::Ctilde
    } else if arg("--corrupt-w1") {
        Corrupt::W1
    } else {
        Corrupt::None
    };
    let negative = corrupt != Corrupt::None;

    // ---- a REAL libcrux ML-DSA-87 key + signature ----
    let seed: [u8; 32] = core::array::from_fn(|i| (0x1b_u8).wrapping_mul(i as u8 + 1) ^ 5);
    let kp = ml_dsa_87::generate_key_pair(seed);
    let pk = kp.verification_key.as_ref().to_vec();
    let msg = b"session #\x00".to_vec();
    let rnd: [u8; 32] = core::array::from_fn(|i| (0x9e_u8).wrapping_add(i as u8));
    let sig = ml_dsa_87::sign(&kp.signing_key, &msg, CTX, rnd).expect("sign");
    let sig_bytes = sig.as_ref().to_vec();

    // ---- GATE 3: the reference front == libcrux accept, and c̃' == c̃ ----
    let front = refmldsa::compute_front(&pk, &msg, CTX, &sig_bytes);
    assert_eq!(front.tr, refmldsa::shake256(&[&pk], 64));
    let libcrux_ok = {
        let vk = ml_dsa_87::MLDSA87VerificationKey::new(*kp.verification_key.as_ref());
        let sarr: [u8; 4627] = sig_bytes.as_slice().try_into().unwrap();
        ml_dsa_87::portable::verify(&vk, &msg, CTX, &ml_dsa_87::MLDSA87Signature::new(sarr)).is_ok()
    };
    assert!(libcrux_ok, "libcrux must accept the real signature");
    assert_eq!(front.ctilde_p, front.ctilde, "c̃' must equal c̃ (the accept condition)");
    println!(
        "GATE 3 ok — the from-scratch FIPS-204 front (tr=SHAKE256(pk), μ=SHAKE256(tr‖0x00‖len(ctx)‖ctx‖M), \
         c̃'=SHAKE256(μ‖w1Encode)) reproduces the REAL libcrux ML-DSA-87 accept: libcrux verifies the \
         signature AND c̃' == c̃ (|pk|={}, |M|={}, ctx={:?}, |w1Encode|={})",
        pk.len(), msg.len(), core::str::from_utf8(CTX).unwrap(), front.w1.len()
    );

    // ---- messages of the three SHAKE256 segments ----
    let mut mu_tail: Vec<u8> = vec![0u8, CTX.len() as u8];
    mu_tail.extend_from_slice(CTX);
    mu_tail.extend_from_slice(&msg);
    let seg0_msg = pk.clone(); // tr = SHAKE256(pk)
    let mut seg1_msg = front.tr.clone(); // μ = SHAKE256(tr ‖ tail)
    seg1_msg.extend_from_slice(&mu_tail);
    let mut seg2_msg = front.mu.clone(); // c̃' = SHAKE256(μ ‖ w1)
    seg2_msg.extend_from_slice(&front.w1);

    // ---- GATE 1: host sponge oracle == sha3 on the three real messages ----
    for (label, m) in [("tr", &seg0_msg), ("mu", &seg1_msg), ("ctilde", &seg2_msg)] {
        assert_eq!(shake_over_keccakf(m, RATE_BYTES, 64), ref_shake256(m, 64), "host sponge != sha3 for {label}");
    }
    assert_eq!(&shake_over_keccakf(&seg0_msg, RATE_BYTES, 64), &front.tr[..]);
    assert_eq!(&shake_over_keccakf(&seg1_msg, RATE_BYTES, 64), &front.mu[..]);
    assert_eq!(&shake_over_keccakf(&seg2_msg, RATE_BYTES, 64), &front.ctilde_p[..]);
    println!("GATE 1 ok — host sponge oracle == sha3::Shake256 byte-for-byte on all three real segment messages");

    let air = MuFrontAir::new(seg0_msg.len(), mu_tail.len(), front.w1.len());
    self_audit(&air);

    // ---- public values (global layout) ----
    // Build the value for each public index from the three segments' message + output bytes.
    let mut pubs = vec![0u8; air.n_pub];
    let set_msg = |pubs: &mut [u8], seg: &Seg, bytes: &[u8]| {
        for (i, &b) in bytes.iter().enumerate() {
            pubs[seg.msg_pub[i]] = b;
        }
    };
    let set_out = |pubs: &mut [u8], seg: &Seg, out: &[u8]| {
        for (i, &b) in out.iter().enumerate() {
            pubs[seg.out_pub[i]] = b;
        }
    };
    let seg_msgs = [seg0_msg.clone(), seg1_msg.clone(), seg2_msg.clone()];
    let chains = build_chains(&air, &seg_msgs, corrupt);
    for (s, seg) in air.segs.iter().enumerate() {
        set_msg(&mut pubs, seg, &seg_msgs[s]);
        set_out(&mut pubs, seg, &chains.seg_out[s]);
    }
    // the c̃ publics were just set from seg2.out (= c̃' for the honest chain). For a real accept
    // c̃' == c̃, so this equals the signature's c̃. Assert it to make the accept explicit.
    let ctilde_pub: Vec<u8> = air.segs[2].out_pub[..64].iter().map(|&p| pubs[p]).collect();
    if !negative {
        assert_eq!(ctilde_pub, front.ctilde, "c̃ publics == the real signature c̃");
    }

    // ---- GATE 2: trace re-read vs sha3 (positive only) ----
    if !negative {
        for s in 0..air.segs.len() {
            let refout = ref_shake256(&seg_msgs[s], 64);
            assert_eq!(&chains.seg_out[s][..64], &refout[..], "seg {s} squeeze[..64] != sha3");
        }
        println!("GATE 2 ok — each segment's squeeze output re-read from the chain == sha3::Shake256 (64 B), byte-for-byte");
    }

    // ---- inject the public-only corruptions ----
    if corrupt == Corrupt::Tie {
        // Feed μ a tr byte ≠ SHAKE256(pk): flip TR public byte 7. Because TR is SHARED, this is
        // simultaneously seg0.out[7] (≠ real squeeze ⇒ seg0 output binding breaks) and
        // seg1.msg[7]. Trace is the honest one, so the mismatch is caught in-AIR.
        let idx = air.segs[0].out_pub[7];
        pubs[idx] ^= 1;
        println!("corrupt-tie: TR public byte 7 flipped (the tr fed to μ ≠ SHAKE256(pk))");
    }
    if corrupt == Corrupt::Ctilde {
        let idx = air.segs[2].out_pub[3];
        pubs[idx] ^= 1;
        println!("corrupt-ctilde: c̃ public byte 3 flipped (c̃' ≠ c̃)");
    }
    if corrupt == Corrupt::W1 {
        // flip a w1 message byte public of seg2: c̃' would change, but the trace/output are the
        // honest ones, so the seg2 message-binding is violated.
        let idx = air.segs[2].msg_pub[64 + 10];
        pubs[idx] ^= 1;
        println!("corrupt-w1: w1 message public byte 10 flipped (message-binding broken)");
    }

    let pis: Vec<Val> = pubs.iter().map(|&b| Val::from_u64(b as u64)).collect();
    let trace = generate::<Val>(&air, &chains);

    // ---- prove + verify ----
    let config = make_config();
    let (h, w) = (air.height(), air.total_width());
    let degree_bits = h.ilog2() as usize;
    let (pp_data, pp_vk) = setup_preprocessed::<MyConfig, _>(&config, &air, degree_bits).expect("preprocessed setup");
    let t0 = std::time::Instant::now();
    let proof = prove_with_preprocessed(&config, &air, trace, &pis, Some(&pp_data));
    let t_prove = t0.elapsed();
    let proof_bytes = postcard::to_allocvec(&proof).unwrap().len();
    let t1 = std::time::Instant::now();
    let res = verify_with_preprocessed(&config, &air, &proof, &pis, Some(&pp_vk));
    let t_verify = t1.elapsed();
    match res {
        Ok(_) if negative => println!("NEGATIVE TEST FAIL — a corrupted μ-front chain was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — the decode/μ FRONT of ML-DSA-87 Verify constrained END-TO-END in ONE AIR: \
             tr=SHAKE256(pk) → μ=SHAKE256(tr‖0x00‖len(ctx)‖ctx‖M) → c̃'=SHAKE256(μ‖w1Encode) → c̃'==c̃, \
             the three hashes threaded as {} adjacent Keccak-f permutation groups with the tr→μ and \
             μ→c̃' ties bound in-circuit through SHARED public values (no recursion); {} public values. \
             [prove {t_prove:.1?}, verify {t_verify:.1?}, {w} cols × {h} rows, prep {}, proof {proof_bytes} bytes]",
            air.total_perms, air.n_pub, air.prep_width()
        ),
        Err(e) if negative => println!("NEGATIVE TEST PASS — corrupted μ-front rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid μ-front trace: {e:?}"),
    }
}
