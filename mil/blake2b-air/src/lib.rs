//! keyed-BLAKE2b-512 arithmetization, build order #1 (spec:
//! `docs/mil-shield-blake2b-air-spec.md`): the **compression trace generator** and
//! the **differential test** that gates it against the on-chain hash
//! (`kaspa_hashes::blake2b_512_keyed`).
//!
//! The compression `F(h, m, t, last)` here records every intermediate 64-bit working
//! word ([`RoundTrace`]) — that is exactly the AIR's witness. The AIR constraints
//! (bit-columns for XOR/rotate, limb+carry for add mod 2^64, reusing the pattern of
//! Plonky3's `p3-blake3-air`) verify this trace; before writing them, the generator
//! MUST reproduce the reference hash byte-for-byte, which the tests assert. The
//! generator is `no_std`+alloc friendly (pure integer ops), ready to drop into the
//! Plonky3 `generation.rs` slot.

/// BLAKE2b IV (RFC 7693 §2.6).
pub const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Message schedule σ (RFC 7693 §2.7); rounds 10,11 reuse 0,1.
pub const SIGMA: [[usize; 16]; 12] = [
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

/// BLAKE2b G rotation amounts (RFC 7693 §3.1).
pub const R1: u32 = 32;
pub const R2: u32 = 24;
pub const R3: u32 = 16;
pub const R4: u32 = 63;

/// Per-round witness: the 16 working words `v` after this round completes. (The AIR
/// also needs the mid-G intermediates; those are recomputed deterministically from
/// the round inputs, so recording the post-round state pins the trace.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundTrace {
    pub v: [u64; 16],
}

/// The full witness of one compression: the initial working state and the 12
/// post-round states. Everything the AIR constrains is derivable from these.
#[derive(Debug, Clone)]
pub struct CompressionTrace {
    pub v_init: [u64; 16],
    pub rounds: [RoundTrace; 12],
    pub h_out: [u64; 8],
}

#[inline]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(R1);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(R2);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(R3);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(R4);
}

/// The BLAKE2b compression `F` (RFC 7693 §3.2), recording the per-round trace.
/// `h` is the chaining state, `m` the 16-word message block, `t` the byte counter,
/// `last` the finalization flag.
pub fn compress(h: &mut [u64; 8], m: &[u64; 16], t: u128, last: bool) -> CompressionTrace {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= (t & 0xffff_ffff_ffff_ffff) as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] ^= 0xffff_ffff_ffff_ffff;
    }
    let v_init = v;

    let mut rounds = [RoundTrace { v: [0; 16] }; 12];
    for (r, s) in SIGMA.iter().enumerate() {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        rounds[r] = RoundTrace { v };
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
    CompressionTrace { v_init, rounds, h_out: *h }
}

/// Little-endian 128-byte block → 16 u64 words.
fn block_words(block: &[u8; 128]) -> [u64; 16] {
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    m
}

/// keyed BLAKE2b-512 over `context` (the key/domain, ≤ 64 B) and `data`, matching
/// `kaspa_hashes::blake2b_512_keyed` byte-for-byte. Returns the 64-byte digest and
/// the per-compression traces (the AIR witness for every block).
pub fn blake2b_512_keyed_traced(context: &[u8], data: &[u8]) -> ([u8; 64], Vec<CompressionTrace>) {
    let kk = context.len();
    let nn = 64usize;
    assert!(kk <= 64, "key/domain must be ≤ 64 bytes");

    // Parameter block P[0] = nn | (kk<<8) | (fanout=1 <<16) | (depth=1 <<24).
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ ((kk as u64) << 8) ^ (nn as u64);

    // Input stream = (keyed ? key padded to 128 : []) ‖ data.
    let mut stream: Vec<u8> = Vec::with_capacity((if kk > 0 { 128 } else { 0 }) + data.len());
    if kk > 0 {
        stream.extend_from_slice(context);
        stream.resize(128, 0);
    }
    stream.extend_from_slice(data);
    let total = stream.len();

    let mut traces = Vec::new();
    if total == 0 {
        // empty (unkeyed, no data): one zero block, t = 0, last.
        let tr = compress(&mut h, &[0u64; 16], 0, true);
        traces.push(tr);
    } else {
        let num_blocks = total.div_ceil(128);
        for i in 0..num_blocks {
            let start = i * 128;
            let end = (start + 128).min(total);
            let mut block = [0u8; 128];
            block[..end - start].copy_from_slice(&stream[start..end]);
            let t = end as u128; // cumulative bytes absorbed through this block
            let last = i == num_blocks - 1;
            let tr = compress(&mut h, &block_words(&block), t, last);
            traces.push(tr);
        }
    }

    let mut out = [0u8; 64];
    for (i, w) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    (out, traces)
}

/// The digest only (drops the trace) — the value the AIR proves.
pub fn blake2b_512_keyed(context: &[u8], data: &[u8]) -> [u8; 64] {
    blake2b_512_keyed_traced(context, data).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_hashes::blake2b_512_keyed as reference;

    /// The correctness gate: our trace generator's digest MUST equal the on-chain
    /// hash for every shielded gadget's shapes (key/domain + data lengths).
    #[test]
    fn differential_vs_kaspa_hashes() {
        let domains: [&[u8]; 4] =
            [b"misaka-shield-v1/cm", b"misaka-shield-v1/merkle", b"misaka-shield-v1/nf", b"misaka-shield-v1/addr"];
        // shielded data shapes: addr(64), node/nf(128), commit(204), rho(129), multi-block(300), empty, off-boundary.
        let lens = [0usize, 1, 63, 64, 127, 128, 129, 200, 204, 256, 300];
        for d in domains {
            for &n in &lens {
                let data: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect();
                let got = blake2b_512_keyed(d, &data);
                let want = reference(d, &data);
                assert_eq!(got.as_slice(), want.as_byte_slice(), "mismatch domain={d:?} len={n}");
            }
        }
    }

    #[test]
    fn trace_feed_forward_binding_holds() {
        // The digest depends on the whole trace: h_out[i] = h_in[i] ^ v_final[i] ^
        // v_final[i+8], and v_init[0..8] == h_in. This is the constraint the AIR's
        // last row enforces; here we confirm the generator satisfies it.
        let (_d, traces) = blake2b_512_keyed_traced(b"misaka-shield-v1/cm", &[0u8; 204]);
        // keyed: 19-byte domain → 1 key block (128) + 204 data = 332 B ⇒ 3 compressions.
        assert_eq!(traces.len(), 3, "keyed 204-byte data ⇒ 3 compressions");
        // Each block chains: block[i+1].h_in == block[i].h_out.
        for i in 0..traces.len() - 1 {
            assert_eq!(traces[i + 1].v_init[..8], traces[i].h_out, "chaining at block {i}");
        }
        for tr in &traces {
            for i in 0..8 {
                let ff = tr.v_init[i] ^ tr.rounds[11].v[i] ^ tr.rounds[11].v[i + 8];
                assert_eq!(tr.h_out[i], ff, "feed-forward binding, word {i}");
            }
        }
    }
}
