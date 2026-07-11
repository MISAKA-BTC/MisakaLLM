//! C-P6 build-order step 2: the **256-point NTT over Z_q** — the one genuinely-new heavy
//! gadget of the in-circuit ML-DSA-87 verify (cp6 design §3 step e / §5 step 2). ML-DSA
//! `Verify` computes `ŵ = A·ẑ − ĉ·t̂1·2ᵈ` in the NTT domain, so the STARK must constrain a
//! negacyclic NTT / pointwise-mult / inverse-NTT over `Z_q` (`q = 8380417`, `n = 256`).
//!
//! This lands the **arithmetic oracle** the AIR constrains, exactly as `shake_sponge.rs`
//! pinned the SHAKE wrapper before its AIR: a **butterfly-trace generator** (the sequence of
//! `(a,b) → (a+ζb, a−ζb) mod q` Cooley-Tukey / Gentleman-Sande steps the AIR proves row by
//! row) **diff-tested against a schoolbook negacyclic convolution** (the definitionally-correct
//! reference). If the transform, the pointwise product, and the inverse all agree with
//! schoolbook over random inputs, the butterfly network + mod-q reductions the AIR must
//! enforce are correct. The trace also reports the butterfly count = the AIR's row budget.
//!
//! Pure integer arithmetic, no deps — `q < 2²³` so every product `< 2⁴⁶` fits in `i128`.
//! Run: `cargo run --release --bin ntt_zq`. Any mismatch aborts (this is the correctness gate).

const Q: i64 = 8380417; // ML-DSA / Dilithium modulus, prime, ≈ 2²³
const N: usize = 256;
const ZETA: i64 = 1753; // a primitive 512th root of unity mod Q (Dilithium's root)

fn addq(a: i64, b: i64) -> i64 {
    let s = (a + b) % Q;
    if s < 0 { s + Q } else { s }
}
fn subq(a: i64, b: i64) -> i64 {
    let s = (a - b) % Q;
    if s < 0 { s + Q } else { s }
}
fn mulq(a: i64, b: i64) -> i64 {
    let m = ((a as i128 * b as i128) % Q as i128) as i64;
    if m < 0 { m + Q } else { m }
}
fn powq(mut base: i64, mut e: u64) -> i64 {
    let mut r = 1i64;
    base %= Q;
    while e > 0 {
        if e & 1 == 1 { r = mulq(r, base); }
        base = mulq(base, base);
        e >>= 1;
    }
    r
}
fn invq(a: i64) -> i64 {
    powq(a, (Q - 2) as u64) // Fermat inverse (Q prime)
}

/// 8-bit bit-reversal — the Dilithium zeta index permutation.
fn brv8(mut x: usize) -> usize {
    let mut r = 0;
    for _ in 0..8 {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

/// zetas[k] = ζ^{brv8(k)} mod Q — the exact Dilithium forward-NTT twiddle table.
fn zeta_table() -> [i64; N] {
    core::array::from_fn(|k| powq(ZETA, brv8(k) as u64))
}

/// One recorded butterfly the AIR proves: `out0 = in0 + ζ·in1`, `out1 = in0 − ζ·in1` (mod Q),
/// all four values range-checked into `[0, Q)`. (Gentleman-Sande for the inverse swaps roles.)
#[derive(Clone, Copy)]
struct Butterfly {
    in0: i64,
    in1: i64,
    zeta: i64,
    out0: i64,
    out1: i64,
}

/// Forward negacyclic NTT (Cooley-Tukey), recording the butterfly trace the AIR generates.
fn ntt_with_trace(a: &mut [i64; N], zetas: &[i64; N], trace: &mut Vec<Butterfly>) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = zetas[k];
            for j in start..start + len {
                let t = mulq(zeta, a[j + len]);
                let (in0, in1) = (a[j], a[j + len]);
                a[j + len] = subq(a[j], t);
                a[j] = addq(a[j], t);
                trace.push(Butterfly { in0, in1, zeta, out0: a[j], out1: a[j + len] });
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT (Gentleman-Sande) + the `n⁻¹` normalization, so `intt(ntt(a)) == a`.
fn intt(a: &mut [i64; N], zetas: &[i64; N]) {
    let mut k = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = zetas[k]; // same table; GS uses the twiddles in reverse
            for j in start..start + len {
                let t = a[j];
                a[j] = addq(t, a[j + len]);
                a[j + len] = mulq(zeta, subq(a[j + len], t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    let ninv = invq(N as i64);
    for x in a.iter_mut() {
        *x = mulq(*x, ninv);
    }
}

/// Definitionally-correct reference: negacyclic convolution in `Z_q[x]/(x²⁵⁶+1)`.
/// `c_k = Σ a_i·b_j` with `x²⁵⁶ = −1`, i.e. wrap `i+j ≥ 256` with a sign flip.
fn schoolbook_negacyclic(a: &[i64; N], b: &[i64; N]) -> [i64; N] {
    let mut c = [0i64; N];
    for i in 0..N {
        for j in 0..N {
            let prod = mulq(a[i], b[j]);
            let k = i + j;
            if k < N {
                c[k] = addq(c[k], prod);
            } else {
                c[k - N] = subq(c[k - N], prod); // x^256 = -1
            }
        }
    }
    c
}

// A tiny deterministic PRNG (no deps): SplitMix64.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn coeff(&mut self) -> i64 {
        (self.next() % Q as u64) as i64
    }
}

fn main() {
    // sanity: ζ is a primitive 512th root ⇒ ζ²⁵⁶ ≡ −1, ζ⁵¹² ≡ 1.
    assert_eq!(powq(ZETA, 256), Q - 1, "ζ^256 must be −1 mod q");
    assert_eq!(powq(ZETA, 512), 1, "ζ^512 must be 1 mod q");
    let zetas = zeta_table();

    let mut rng = Rng(0xC0FFEE_1234_5678);
    let mut cases = 0usize;
    let mut bfly = 0usize;

    for _ in 0..2000 {
        let mut a = [0i64; N];
        let mut b = [0i64; N];
        for i in 0..N {
            a[i] = rng.coeff();
            b[i] = rng.coeff();
        }

        // (1) round-trip: intt(ntt(a)) == a — the transform is invertible as constrained.
        let mut at = a;
        let mut trace = Vec::new();
        ntt_with_trace(&mut at, &zetas, &mut trace);
        bfly = trace.len();
        // the recorded trace is self-consistent with the array it produced.
        let mut ar = at;
        intt(&mut ar, &zetas);
        assert_eq!(ar, a, "intt(ntt(a)) must recover a");

        // (2) convolution theorem: intt(ntt(a) ∘ ntt(b)) == schoolbook negacyclic(a,b).
        let mut bt = b;
        ntt_with_trace(&mut bt, &zetas, &mut Vec::new());
        let mut prod: [i64; N] = core::array::from_fn(|i| mulq(at[i], bt[i]));
        intt(&mut prod, &zetas);
        let reference = schoolbook_negacyclic(&a, &b);
        assert_eq!(prod, reference, "NTT-domain product must equal schoolbook negacyclic conv");

        // (3) every butterfly output is a canonical residue in [0, Q) (the AIR range check).
        for bf in &trace {
            assert!((0..Q).contains(&bf.out0) && (0..Q).contains(&bf.out1), "butterfly outputs range-checked");
            assert_eq!(bf.out0, addq(bf.in0, mulq(bf.zeta, bf.in1)), "out0 = in0 + ζ·in1");
            assert_eq!(bf.out1, subq(bf.in0, mulq(bf.zeta, bf.in1)), "out1 = in0 − ζ·in1");
        }
        cases += 1;
    }

    println!(
        "NTT-Zq ok — {cases} random polynomials: intt∘ntt round-trips, and the NTT-domain \
         product matches schoolbook negacyclic convolution in Z_q[x]/(x^256+1) coefficient-for-\
         coefficient. Forward trace = {bfly} butterflies (= AIR rows/transform), each \
         (a+ζb, a−ζb) mod q with range-checked outputs. This is the C-P6 step-e arithmetic \
         oracle; the AIR proves exactly this butterfly network."
    );
}
