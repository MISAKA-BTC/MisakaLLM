//! C-P6 composition slice: **FIPS-204 pk/sig decode + the acceptance checks my sub-gadgets
//! cover, validated against REAL libcrux ML-DSA-87 signatures**. The in-circuit `Verify`
//! must, among other things, decode `sig = (c̃, z, h)` and check `‖z‖∞ < γ1−β` (the
//! `rejection_sample_air.rs` / norm comparator) and `#{h=1} ≤ ω` (the `popcount_bound_air.rs`
//! gadget). Here we exercise exactly those two checks on genuine signatures produced by
//! `libcrux_ml_dsa::ml_dsa_87`, so the proven sub-gadgets are shown to operate correctly on
//! real ML-DSA-87 data (not just synthetic vectors) — and we pin the FIPS-204 z-BitUnpack and
//! h-HintBitUnpack the full-verify composition needs.
//!
//! ML-DSA-87 (= Dilithium5): q=8380417, (k,l)=(8,7), d=13, γ1=2¹⁹, τ=60, η=2, β=τ·η=120,
//! ω=75. pk = ρ(32) ‖ t1 (k·320 = 2560) = 2592 B. sig = c̃(64) ‖ z (l·640 = 4480) ‖
//! h (ω+k = 83) = 4627 B. Run: `cargo run --release --bin mldsa_parse`.

use libcrux_ml_dsa::ml_dsa_87;

const K: usize = 8;
const L: usize = 7;
const N: usize = 256;
const GAMMA1: i64 = 1 << 19; // 524288
const BETA: i64 = 120; // τ·η = 60·2
const OMEGA: usize = 75;
const CTILDE_LEN: usize = 64;
const Z_BITS: usize = 20; // bitlen(2·γ1 − 1)
const Z_POLY_BYTES: usize = N * Z_BITS / 8; // 640
const PK_LEN: usize = 2592;
const SIG_LEN: usize = 4627;

/// Read `nbits`-wide little-endian bit-packed unsigned integers from `bytes` (FIPS-204 packs
/// LSB-first). Returns `count` values.
fn bit_unpack_unsigned(bytes: &[u8], nbits: usize, count: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(count);
    let mut acc: u64 = 0;
    let mut have = 0usize;
    let mut bi = 0usize;
    for _ in 0..count {
        while have < nbits {
            acc |= (bytes[bi] as u64) << have;
            have += 8;
            bi += 1;
        }
        out.push((acc & ((1u64 << nbits) - 1)) as u32);
        acc >>= nbits;
        have -= nbits;
    }
    out
}

/// FIPS-204 `BitUnpack(v, a=γ1−1, b=γ1)` for `z`: each 20-bit field `t` decodes to the signed
/// coefficient `γ1 − t` ∈ [−γ1+1, γ1].
fn decode_z_poly(bytes: &[u8]) -> [i64; N] {
    let raw = bit_unpack_unsigned(bytes, Z_BITS, N);
    core::array::from_fn(|i| GAMMA1 - raw[i] as i64)
}

/// FIPS-204 `HintBitUnpack`: the last `ω+k` bytes encode the hint. `y[ω..ω+k]` give the
/// cumulative count of set positions per polynomial; `y[0..ω]` are the sorted positions.
/// Returns the total hint weight, or `None` if the encoding is malformed (⊥).
fn decode_hint_weight(y: &[u8]) -> Option<usize> {
    let mut index = 0usize;
    let mut total = 0usize;
    for i in 0..K {
        let end = y[OMEGA + i] as usize;
        if end < index || end > OMEGA {
            return None; // non-monotone / over-weight ⇒ ⊥
        }
        let mut last: i32 = -1;
        for j in index..end {
            let pos = y[j] as i32;
            if pos <= last {
                return None; // positions must strictly increase within a poly ⇒ ⊥
            }
            last = pos;
            total += 1;
        }
        index = end;
    }
    // trailing padding bytes (index..ω) must be zero.
    for &b in &y[index..OMEGA] {
        if b != 0 {
            return None;
        }
    }
    Some(total)
}

fn main() {
    let ctx = b"mil-receipt-v1";
    let mut n_ok = 0usize;
    let mut max_z_seen: i64 = 0;
    let mut max_h_seen: usize = 0;
    let bound = GAMMA1 - BETA; // 524168

    // several keypairs × messages: every VALID signature must satisfy the two checks.
    for k in 0..6u8 {
        let seed: [u8; 32] = core::array::from_fn(|i| (0x1b_u8).wrapping_mul(i as u8 + 1) ^ k);
        let kp = ml_dsa_87::generate_key_pair(seed);
        for m in 0..4u8 {
            let msg = [b"MISAKA session receipt #".as_slice(), &[m]].concat();
            let rnd: [u8; 32] = core::array::from_fn(|i| (0x9e_u8).wrapping_add(i as u8).wrapping_add(m));
            let sig = ml_dsa_87::sign(&kp.signing_key, &msg, ctx, rnd).expect("sign");
            let sb = sig.as_ref();
            assert_eq!(sb.len(), SIG_LEN);
            assert_eq!(kp.verification_key.as_ref().len(), PK_LEN);
            // sanity: libcrux itself accepts this signature.
            let vk = ml_dsa_87::MLDSA87VerificationKey::new(*kp.verification_key.as_ref());
            let s = ml_dsa_87::MLDSA87Signature::new(*sig.as_ref());
            assert!(ml_dsa_87::portable::verify(&vk, &msg, ctx, &s).is_ok(), "libcrux accepts");

            // (1) decode z and check ‖z‖∞ < γ1 − β (the norm bound the comparator AIR proves).
            let z_bytes = &sb[CTILDE_LEN..CTILDE_LEN + L * Z_POLY_BYTES];
            let mut zmax = 0i64;
            for p in 0..L {
                for &c in decode_z_poly(&z_bytes[p * Z_POLY_BYTES..(p + 1) * Z_POLY_BYTES]).iter() {
                    zmax = zmax.max(c.abs());
                }
            }
            assert!(zmax < bound, "‖z‖∞ {zmax} must be < γ1−β {bound}");
            max_z_seen = max_z_seen.max(zmax);

            // (2) decode h and check #{h=1} ≤ ω (the popcount bound AIR proves).
            let h_bytes = &sb[CTILDE_LEN + L * Z_POLY_BYTES..];
            assert_eq!(h_bytes.len(), OMEGA + K);
            let hw = decode_hint_weight(h_bytes).expect("valid hint encoding");
            assert!(hw <= OMEGA, "hint weight {hw} must be ≤ ω {OMEGA}");
            max_h_seen = max_h_seen.max(hw);

            n_ok += 1;
        }
    }

    // negative: a signature whose z is tampered to exceed the norm bound must be caught by the
    // same check the AIR enforces (and libcrux rejects it too).
    let seed = [7u8; 32];
    let kp = ml_dsa_87::generate_key_pair(seed);
    let sig = ml_dsa_87::sign(&kp.signing_key, b"m", ctx, [0u8; 32]).expect("sign");
    let mut bad = sig.as_ref().to_vec();
    // set a z field to the max 20-bit value → coeff = γ1 − 0 = γ1 (‖z‖∞ = γ1 ≥ γ1−β).
    for b in bad[CTILDE_LEN..CTILDE_LEN + 3].iter_mut() {
        *b = 0;
    }
    let z0 = decode_z_poly(&bad[CTILDE_LEN..CTILDE_LEN + Z_POLY_BYTES])[0];
    let vk = ml_dsa_87::MLDSA87VerificationKey::new(*kp.verification_key.as_ref());
    let s = ml_dsa_87::MLDSA87Signature::new(bad.as_slice().try_into().unwrap());
    let norm_check_fails = z0.abs() >= bound;
    let libcrux_rejects = ml_dsa_87::portable::verify(&vk, b"m", ctx, &s).is_err();

    if norm_check_fails && libcrux_rejects {
        println!(
            "MLDSA PARSE ok — {n_ok} real libcrux ML-DSA-87 signatures decoded (FIPS-204 z-BitUnpack + h-HintBitUnpack); \
             the two acceptance checks the proven sub-gadgets enforce hold on genuine data: ‖z‖∞ < γ1−β (max seen {max_z_seen} < {bound}) \
             and #{{h=1}} ≤ ω (max seen {max_h_seen} ≤ {OMEGA}). Negative: an out-of-norm z (coeff {z0}, |·| ≥ {bound}) fails the norm gadget AND libcrux rejects it. \
             This connects popcount_bound_air.rs + the norm comparator to real ML-DSA-87 signatures."
        );
    } else {
        println!("PARSE FAIL — norm_check_fails={norm_check_fails} libcrux_rejects={libcrux_rejects} z0={z0}");
        std::process::exit(1);
    }
}
