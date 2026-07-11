//! C-P6 milestone: a **from-scratch reference ML-DSA-87 `Verify`** (FIPS-204), diff-tested
//! ACCEPT⇔REJECT against `libcrux_ml_dsa::ml_dsa_87` over valid + tampered signatures. This
//! is the "full Verify (libcrux 差分)" step: it composes the SAME sub-operations the proven
//! AIRs constrain — SHAKE (ExpandA/μ/SampleInBall/final hash), the mod-q NTT + pointwise
//! product, Decompose/UseHint, the norm bound, the hint-weight bound — into one verify, and
//! shows the decomposition reconstructs ML-DSA verify. If our reference accepts iff libcrux
//! accepts, the in-circuit composition's TARGET is pinned end-to-end (the AIR wiring then
//! diff-tests against THIS).

use libcrux_ml_dsa::ml_dsa_87;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

const Q: i64 = 8380417;
const N: usize = 256;
const K: usize = 8;
const L: usize = 7;
const D: u32 = 13;
const GAMMA1: i64 = 1 << 19;
const GAMMA2: i64 = (Q - 1) / 32; // 261888
const TAU: usize = 60;
const BETA: i64 = 120;
const OMEGA: usize = 75;
const ZETA: i64 = 1753;
const CTILDE: usize = 64;
const ZPB: usize = N * 20 / 8; // 640

type Poly = [i64; N];

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

/// In-place forward NTT (Dilithium Cooley-Tukey, plain arithmetic — same coefficient order as
/// Dilithium's Montgomery ntt, since Montgomery only scales values not indices).
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
/// In-place inverse NTT with the 1/n normalization (true standard-form inverse).
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

// ---- bit unpacking ----
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

/// pkDecode → (ρ, t1[k]) with t1 coeffs in [0, 2^10).
fn pk_decode(pk: &[u8]) -> ([u8; 32], Vec<Poly>) {
    let rho: [u8; 32] = pk[0..32].try_into().unwrap();
    let mut t1 = Vec::with_capacity(K);
    for i in 0..K {
        let raw = unpack(&pk[32 + i * 320..32 + (i + 1) * 320], 10, N);
        t1.push(core::array::from_fn::<i64, N, _>(|j| raw[j] as i64));
    }
    (rho, t1)
}

/// sigDecode → (c̃, z[l], per-poly hint bit arrays) or None if the hint encoding is ⊥.
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

/// ExpandA(ρ) → Â[k][l], each poly in NTT domain (RejNTTPoly via SHAKE128).
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

/// SampleInBall(c̃) → the τ-sparse ±1 challenge polynomial.
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

/// FIPS-204 Decompose(r) → (r1, r0) with the boundary special case.
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
/// UseHint(hbit, r) → adjusted high part.
fn use_hint(hbit: bool, r: i64) -> i64 {
    let mm = (Q - 1) / (2 * GAMMA2); // 16
    let (r1, r0) = decompose(r);
    if hbit {
        if r0 > 0 { (r1 + 1).rem_euclid(mm) } else { (r1 - 1).rem_euclid(mm) }
    } else {
        r1
    }
}

/// w1Encode: SimpleBitPack of w1 (coeffs in [0, 16), 4 bits each) → k·128 bytes.
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

fn shake256(parts: &[&[u8]], outlen: usize) -> Vec<u8> {
    let mut sh = Shake256::default();
    for p in parts {
        sh.update(p);
    }
    let mut rd = sh.finalize_xof();
    let mut o = vec![0u8; outlen];
    rd.read(&mut o);
    o
}

/// Our from-scratch ML-DSA-87 Verify (FIPS-204 §5.3 external, pure, with context).
fn verify_ref(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let z = zetas();
    let (rho, t1) = pk_decode(pk);
    let (ctilde, zpoly, hbits) = match sig_decode(sig) {
        Some(v) => v,
        None => return false,
    };
    // ‖z‖∞ < γ1 − β
    let zmax = zpoly.iter().flat_map(|p| p.iter()).map(|&c| c.abs()).max().unwrap();
    if zmax >= GAMMA1 - BETA {
        return false;
    }
    // #h ≤ ω (already ≤ ω by decode, but check explicitly)
    let hw: usize = hbits.iter().flat_map(|p| p.iter()).filter(|&&b| b).count();
    if hw > OMEGA {
        return false;
    }
    let a = expand_a(&rho);
    // μ = SHAKE256(SHAKE256(pk,64) ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M, 64)
    let tr = shake256(&[pk], 64);
    let mu = shake256(&[&tr, &[0u8, ctx.len() as u8], ctx, msg], 64);
    let c = sample_in_ball(&ctilde);
    let mut chat = c;
    ntt(&mut chat, &z);
    let mut zhat: Vec<Poly> = zpoly.iter().map(|p| { let mut q = *p; ntt(&mut q, &z); q }).collect();
    // t̂1·2^d
    let t1hat: Vec<Poly> = t1.iter().map(|p| { let mut q: Poly = core::array::from_fn(|i| mul(p[i], 1 << D)); ntt(&mut q, &z); q }).collect();
    // ŵ[i] = Σ_s Â[i][s] ∘ ẑ[s] − ĉ ∘ (t̂1[i]·2^d);  w = invNTT(ŵ)
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
        // UseHint coefficient-wise
        let w1i: Poly = core::array::from_fn(|j| use_hint(hbits[i][j], what[j]));
        w1.push(w1i);
    }
    let ctilde_p = shake256(&[&mu, &w1_encode(&w1)], CTILDE);
    ctilde_p.as_slice() == &ctilde[..]
}

fn main() {
    let ctx = b"mil-receipt-v1";
    let mut agree = 0usize;
    let mut valid_accept = 0usize;
    for k in 0..4u8 {
        let seed: [u8; 32] = core::array::from_fn(|i| (0x1b_u8).wrapping_mul(i as u8 + 1) ^ k);
        let kp = ml_dsa_87::generate_key_pair(seed);
        let pk = kp.verification_key.as_ref();
        for mi in 0..3u8 {
            let msg = [b"session #".as_slice(), &[mi]].concat();
            let rnd: [u8; 32] = core::array::from_fn(|i| (0x9e_u8).wrapping_add(i as u8).wrapping_add(mi));
            let sig = ml_dsa_87::sign(&kp.signing_key, &msg, ctx, rnd).expect("sign");
            let vk = ml_dsa_87::MLDSA87VerificationKey::new(*kp.verification_key.as_ref());
            let s = ml_dsa_87::MLDSA87Signature::new(*sig.as_ref());

            let cases: [(Vec<u8>, Vec<u8>); 4] = [
                (msg.clone(), sig.as_ref().to_vec()),               // valid
                (msg.clone(), { let mut b = sig.as_ref().to_vec(); b[100] ^= 1; b }), // tampered z
                (b"different message".to_vec(), sig.as_ref().to_vec()),               // wrong msg
                (msg.clone(), { let mut b = sig.as_ref().to_vec(); b[0] ^= 1; b }),    // tampered c̃
            ];
            for (mm, ss) in &cases {
                let ours = verify_ref(pk, mm, ctx, ss);
                let theirs = if ss.len() == 4627 {
                    let sarr: [u8; 4627] = ss.as_slice().try_into().unwrap();
                    ml_dsa_87::portable::verify(&vk, mm, ctx, &ml_dsa_87::MLDSA87Signature::new(sarr)).is_ok()
                } else {
                    false
                };
                if ours == theirs {
                    agree += 1;
                    if theirs {
                        valid_accept += 1;
                    }
                } else {
                    println!("DISAGREE — ours={ours} libcrux={theirs} (k={k} m={mi})");
                    std::process::exit(1);
                }
            }
            let _ = (vk, s);
        }
    }
    println!(
        "MLDSA VERIFY-REF ok — a from-scratch FIPS-204 ML-DSA-87 Verify AGREES with libcrux on all {agree} cases \
         ({valid_accept} valid→accept, rest tampered→reject). The reference composition of the proven sub-gadgets \
         (SHAKE ExpandA/μ/SampleInBall + NTT product + Decompose/UseHint + norm/popcount + w1Encode) reconstructs \
         ML-DSA verify accept⇔accept. This is the target the in-circuit AIR composition diff-tests against."
    );
}
