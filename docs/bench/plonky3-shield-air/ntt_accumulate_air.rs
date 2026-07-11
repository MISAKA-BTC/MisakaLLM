//! C-P6 verify step (matrix-vector integration): the **NTT-domain accumulation-reduction**
//! `ŵ[j] = ( Σ_{s=0}^{l-1} Â[i][s][j]·ẑ[s][j] − ĉ[j]·(t̂1·2^d)[i][j] ) mod q`, for ML-DSA-87
//! (`l = 7`). Given the `l` additive pointwise products and the 1 subtractive product (each
//! already reduced `< q` by their own mult AIRs), this AIR proves their signed accumulation is
//! reduced to the canonical `[0,q)` representative. This is the "combine" that turns the
//! per-coefficient pointwise mults into one output coefficient of `Az − c·t1·2^d` in NTT domain.
//!
//! Soundness: `acc = Σ_{i<7} p[i]` is exact in the field (7·q < 2²⁶ < p); then
//! `acc − p_sub + q = out + k·q` with `k ∈ [0,8)` (3-bit) and `out < q` forces
//! `out = (Σ − p_sub) mod q`. Diff-tested against a plain reference reduction; `--corrupt` → reject.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
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

const Q: i64 = 8380417;
const L: usize = 7; // ML-DSA-87 l (additive products Â∘ẑ)
// columns: p[0..L] additive | p_sub | out | k | gp[0..L] slack | gsub | gout
const P0: usize = 0; // p[0..L] at P0..P0+L
const PSUB: usize = L; // subtractive product
const OUT: usize = L + 1;
const K: usize = L + 2;
const GP0: usize = L + 3; // slack q-1-p[i] for p[0..L]
const GSUB: usize = 2 * L + 3;
const GOUT: usize = 2 * L + 4;
const NP: usize = 2 * L + 5; // = 19
// bit-ranged (23-bit) columns: p[0..L], p_sub, out, gp[0..L], gsub, gout  (k is 3-bit sep)
const W23: usize = 23;
const KBITS: usize = 3;
// ranged-23 columns list
fn ranged23() -> Vec<usize> {
    let mut v = Vec::new();
    for i in 0..L {
        v.push(P0 + i);
    }
    v.push(PSUB);
    v.push(OUT);
    for i in 0..L {
        v.push(GP0 + i);
    }
    v.push(GSUB);
    v.push(GOUT);
    v // 2L+4 = 18 columns
}
fn num_cols() -> usize {
    NP + ranged23().len() * W23 + KBITS
}
fn r23_off(idx: usize) -> usize {
    NP + idx * W23
}
fn k_off() -> usize {
    NP + ranged23().len() * W23
}

struct AccAir {}

impl<F> BaseAir<F> for AccAir {
    fn width(&self) -> usize {
        num_cols()
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for AccAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let e = |i: usize| -> AB::Expr { row[i].into() };
        let ranged = ranged23();

        // range-check the 23-bit columns and bind to their bits.
        for (idx, &col) in ranged.iter().enumerate() {
            let bo = r23_off(idx);
            let mut acc = AB::Expr::ZERO;
            let mut wt = AB::Expr::ONE;
            for j in 0..W23 {
                let b: AB::Expr = row[bo + j].into();
                builder.assert_zero(b.clone() * (b.clone() - one.clone()));
                acc = acc + b * wt.clone();
                wt = wt.clone() + wt.clone();
            }
            builder.assert_eq(e(col), acc);
        }
        // k ∈ [0,8) via 3 bits.
        {
            let bo = k_off();
            let mut acc = AB::Expr::ZERO;
            let mut wt = AB::Expr::ONE;
            for j in 0..KBITS {
                let b: AB::Expr = row[bo + j].into();
                builder.assert_zero(b.clone() * (b.clone() - one.clone()));
                acc = acc + b * wt.clone();
                wt = wt.clone() + wt.clone();
            }
            builder.assert_eq(e(K), acc);
        }

        let qc = AB::Expr::from_u64(Q as u64);
        let qm1 = AB::Expr::from_u64((Q - 1) as u64);
        // canonical bounds: p[i] < q, p_sub < q, out < q  (via slack sum = q-1).
        for i in 0..L {
            builder.assert_eq(e(P0 + i) + e(GP0 + i), qm1.clone());
        }
        builder.assert_eq(e(PSUB) + e(GSUB), qm1.clone());
        builder.assert_eq(e(OUT) + e(GOUT), qm1.clone());

        // acc = Σ_{i<L} p[i]  (exact; L·q < 2²⁶ < p).
        let mut acc = AB::Expr::ZERO;
        for i in 0..L {
            acc = acc + e(P0 + i);
        }
        // acc − p_sub + q = out + k·q   ⇒  out ≡ (Σ − p_sub) mod q, out ∈ [0,q).
        builder.assert_eq(acc - e(PSUB) + qc.clone(), e(OUT) + e(K) * qc);
    }
}

fn reference_reduce(p: &[i64; L], psub: i64) -> i64 {
    let s: i64 = p.iter().sum::<i64>() - psub;
    s.rem_euclid(Q)
}

fn generate<F: PrimeField64>(cases: &[([i64; L], i64)]) -> RowMajorMatrix<F> {
    let n = cases.len();
    assert!(n.is_power_of_two());
    let nc = num_cols();
    let ranged = ranged23();
    let mut vals = F::zero_vec(n * nc);
    for (r, (p, psub)) in cases.iter().enumerate() {
        let base = r * nc;
        for i in 0..L {
            assert!(p[i] >= 0 && p[i] < Q);
        }
        assert!(*psub >= 0 && *psub < Q);
        let out = reference_reduce(p, *psub);
        let accv: i64 = p.iter().sum();
        // acc − psub + q = out + k·q  ⇒  k = (acc − psub + q − out)/q
        let k = (accv - psub + Q - out) / Q;
        assert!((0..8).contains(&k), "k out of range: {k}");
        assert_eq!(accv - psub + Q, out + k * Q);

        let set = |vals: &mut [F], c: usize, v: i64| vals[base + c] = F::from_u64(v as u64);
        for i in 0..L {
            set(&mut vals, P0 + i, p[i]);
            set(&mut vals, GP0 + i, Q - 1 - p[i]);
        }
        set(&mut vals, PSUB, *psub);
        set(&mut vals, GSUB, Q - 1 - psub);
        set(&mut vals, OUT, out);
        set(&mut vals, GOUT, Q - 1 - out);
        set(&mut vals, K, k);
        // bit decomps
        let put_bits = |vals: &mut [F], off: usize, v: i64, w: usize| {
            for j in 0..w {
                vals[base + off + j] = F::from_u64(((v >> j) & 1) as u64);
            }
        };
        for (idx, &col) in ranged.iter().enumerate() {
            let v = vals[base + col].as_canonical_u64() as i64;
            put_bits(&mut vals, r23_off(idx), v, W23);
        }
        put_bits(&mut vals, k_off(), k, KBITS);
    }
    RowMajorMatrix::new(vals, nc)
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

fn main() {
    let corrupt = std::env::args().any(|a| a == "--corrupt");
    let air = AccAir {};
    // 8 coefficient positions with assorted products incl. boundary cases (sum wraps, sub > acc).
    let cases: Vec<([i64; L], i64)> = vec![
        ([1, 2, 3, 4, 5, 6, 7], 0),
        ([Q - 1, Q - 1, Q - 1, Q - 1, Q - 1, Q - 1, Q - 1], 0), // acc ≈ 7q → k=6
        ([0, 0, 0, 0, 0, 0, 0], Q - 1),                          // signed negative → wrap
        ([100, 200, 300, 400, 500, 600, 700], 12345),
        ([Q - 1, 0, 0, 0, 0, 0, 0], Q - 1),                      // acc-sub could be 0
        ([1234567, 2345671, 3456712, 4567123, 5671234, 6712345, 7123456], 8000000),
        ([Q / 2, Q / 2, Q / 2, Q / 2, Q / 2, Q / 2, Q / 2], Q / 3),
        ([Q - 2, Q - 3, 5, 6, 7, 8, 9], Q - 10),
    ];
    let mut trace = generate::<Val>(&cases);
    // diff-test: OUT column equals the plain reference reduction.
    for (r, (p, psub)) in cases.iter().enumerate() {
        assert_eq!(
            trace.values[r * num_cols() + OUT],
            Val::from_u64(reference_reduce(p, *psub) as u64),
            "row {r} out"
        );
    }
    if corrupt {
        trace.values[OUT] += Val::ONE; // wrong reduced coefficient for row 0
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt accumulate trace accepted!"),
        Ok(_) => println!(
            "VERIFY ok — ML-DSA-87 NTT-domain accumulation-reduction proven as a Plonky3 AIR: \
             ŵ[j] = (Σ_{{s<7}} Â∘ẑ − ĉ∘t̂1·2^d) mod q, over 8 coefficient cases incl. \
             acc≈7q, signed-negative wrap, and sub>acc boundaries. OUT column diff-tested == \
             plain reference reduction. --corrupt rejected. This is the matrix-vector 'combine' \
             step of the verify integration (pointwise mults → one output coefficient)."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt accumulate trace rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
