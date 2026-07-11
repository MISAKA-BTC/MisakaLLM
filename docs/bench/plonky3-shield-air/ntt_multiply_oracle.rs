//! C-P6 step-e ORACLE: the **full verify NTT data-flow** — forward NTT → NTT-domain pointwise
//! product → inverse NTT — pinned at real ML-DSA-87 size (n=256, q=8380417). ML-DSA `Verify`
//! computes `w = A·z − c·t1·2^d` by transforming each polynomial with the forward NTT
//! (ntt_full_air.rs), multiplying pointwise in the NTT domain (ntt_accumulate_air.rs), and
//! transforming back with the INVERSE NTT (invntt_butterfly_air.rs). This oracle pins the exact
//! arithmetic of that whole pipeline the way `ntt_zq.rs` pinned the forward transform:
//!
//!   1. round-trip: `invNTT(NTT(x)) == x`  (the inverse schedule + −ζ twiddles + n⁻¹ scaling)
//!   2. multiply:   `invNTT(NTT(f) ∘ NTT(g)) == (f · g) mod (x²⁵⁶+1)`  vs an independent schoolbook
//!
//! So the inverse-NTT SCHEDULE (Gentleman-Sande, reversed layers, `−zetas[k]` twiddles) — the
//! trace the invNTT AIR proves — is validated end-to-end against ground truth. No proving here;
//! this is the reference the composed circuit's NTT pipeline diff-tests against.

const Q: u64 = 8380417;

fn modpow(base: u64, mut e: u64) -> u64 {
    let mut r = 1u128;
    let mut b = base as u128 % Q as u128;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % Q as u128;
        }
        b = b * b % Q as u128;
        e >>= 1;
    }
    r as u64
}

fn brv8(mut x: u64) -> u64 {
    let mut r = 0;
    for _ in 0..8 {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

/// zetas[k] = 1753^brv8(k) mod q, k=0..256 (Dilithium normal-domain twiddle table; index 1-based
/// in the schedule but stored 0-based here as z[k-1]).
fn zetas() -> Vec<u64> {
    (1..=256u64).map(|k| modpow(1753, brv8(k))).collect()
}

/// Forward NTT (in-place Cooley-Tukey, exact Dilithium schedule) — same as ntt_full_air.rs.
fn ntt(a: &mut [u64; 256], zs: &[u64]) {
    let mut k = 0usize;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < 256 {
            k += 1;
            let zeta = zs[k - 1];
            for j in start..start + len {
                let t = ((zeta as u128 * a[j + len] as u128) % Q as u128) as u64;
                a[j + len] = (a[j] + Q - t) % Q;
                a[j] = (a[j] + t) % Q;
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Inverse NTT (in-place Gentleman-Sande, REVERSED layer order, `−zetas[k]` twiddles, then n⁻¹).
fn invntt(a: &mut [u64; 256], zs: &[u64]) {
    let ninv = modpow(256, Q - 2); // 256⁻¹ mod q
    let mut k = 256usize;
    let mut len = 1;
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            k -= 1;
            let zeta = (Q - zs[k - 1]) % Q; // −zetas[k] (mirror the forward's zs[k-1] indexing)
            for j in start..start + len {
                let t = a[j];
                a[j] = (t + a[j + len]) % Q;
                let d = (t + Q - a[j + len]) % Q; // t − a[j+len]  (Dilithium GS sign)
                a[j + len] = ((zeta as u128 * d as u128) % Q as u128) as u64;
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for x in a.iter_mut() {
        *x = ((*x as u128 * ninv as u128) % Q as u128) as u64;
    }
}

fn schoolbook_negacyclic(f: &[u64; 256], g: &[u64; 256]) -> [u64; 256] {
    let mut c = [0u128; 256];
    for i in 0..256 {
        for j in 0..256 {
            let p = (f[i] as u128) * (g[j] as u128);
            let k = i + j;
            if k < 256 {
                c[k] = (c[k] + p) % Q as u128;
            } else {
                c[k - 256] = (c[k - 256] + Q as u128 - (p % Q as u128)) % Q as u128;
            }
        }
    }
    std::array::from_fn(|i| c[i] as u64)
}

fn lcg(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (*seed >> 33) % Q
}

fn main() {
    let zs = zetas();
    let mut seed = 0x0ddc0ffee_u64;
    let trials = 500;

    // (1) round-trip: invNTT(NTT(x)) == x, over random x.
    for _ in 0..trials {
        let x: [u64; 256] = std::array::from_fn(|_| lcg(&mut seed));
        let mut a = x;
        ntt(&mut a, &zs);
        invntt(&mut a, &zs);
        assert_eq!(a, x, "round-trip invNTT∘NTT != identity");
    }

    // (2) multiply: invNTT(NTT(f) ∘ NTT(g)) == schoolbook(f·g mod x²⁵⁶+1), over random f,g.
    for _ in 0..trials {
        let f: [u64; 256] = std::array::from_fn(|_| lcg(&mut seed));
        let g: [u64; 256] = std::array::from_fn(|_| lcg(&mut seed));
        let mut nf = f;
        let mut ng = g;
        ntt(&mut nf, &zs);
        ntt(&mut ng, &zs);
        let mut prod: [u64; 256] = std::array::from_fn(|i| ((nf[i] as u128 * ng[i] as u128) % Q as u128) as u64);
        invntt(&mut prod, &zs);
        let sb = schoolbook_negacyclic(&f, &g);
        assert_eq!(prod, sb, "invNTT(NTT(f)∘NTT(g)) != schoolbook(f·g)");
    }

    println!(
        "NTT-MULTIPLY ORACLE ok — full ML-DSA-87 verify NTT data-flow pinned over {trials}+{trials} random \
         cases (q={Q}, n=256): (1) invNTT∘NTT == identity [inverse Gentleman-Sande schedule, reversed \
         layers, −zetas[k] twiddles, n⁻¹={} scaling]; (2) invNTT(NTT(f)∘NTT(g)) == schoolbook negacyclic \
         (f·g mod x²⁵⁶+1). This pins the inverse-NTT trace the invNTT AIR proves + the whole forward→ \
         pointwise→inverse pipeline the composition reproduces for w = A·z − c·t1·2^d.",
        modpow(256, Q - 2)
    );
}
