//! C-P6 verify step (integration): the **SampleInBall placement** (FIPS-204 Algorithm 29) as a
//! Plonky3 AIR — the Fisher-Yates step that builds the challenge polynomial `c ∈ Rq` with exactly
//! `τ=60` coefficients in `{−1,+1}` and the rest `0`, for ML-DSA-87. Each step does the swap
//! `c[i] ← c[j]; c[j] ← ±1` for a rejection-sampled `j ≤ i`. This AIR proves ONE such placement
//! step over the full `n=256` array via a **data-dependent indexed access**: witnessed selector
//! vectors `sel=[k==j]`, `indi=[k==i]` (each boolean, one-hot, and bound to `j`/`i`), the read
//! `a_j = Σ sel[k]·a[k]`, and the exact next-array formula. `j ≤ i` is enforced by an 8-bit slack.
//!
//! This is the array-threading-with-witnessed-index technique the verify integration needs (also
//! the shape of any indexed permutation). `next` is diff-tested against the reference swap step
//! over 8 consecutive steps of a real SampleInBall run; `--corrupt` → reject.

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

const N: usize = 256;
const A: usize = 0; // a[0..N]
const NEXT: usize = N; // next[0..N]
const SEL: usize = 2 * N; // sel[0..N]  ([k==j])
const INDI: usize = 3 * N; // indi[0..N] ([k==i])
const I: usize = 4 * N;
const J: usize = 4 * N + 1;
const SGN: usize = 4 * N + 2; // sign bit
const AJ: usize = 4 * N + 3; // a[j]
const T: usize = 4 * N + 4; // i - j (>=0)
const NP: usize = 4 * N + 5;
const TBITS: usize = 8; // t < 256
const NUM_COLS: usize = NP + TBITS;

struct SibAir {}

impl<F> BaseAir<F> for SibAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder> Air<AB> for SibAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let e = |i: usize| -> AB::Expr { row[i].into() };
        let boolean = |b: AB::Expr, builder: &mut AB| builder.assert_zero(b.clone() * (b.clone() - one.clone()));

        // a[k] ∈ {−1,0,1}
        for k in 0..N {
            let a = e(A + k);
            builder.assert_zero(a.clone() * (a.clone() - one.clone()) * (a + one.clone()));
        }
        // selector sel = [k==j]: boolean, one-hot, and Σ k·sel[k] = j.
        let mut sum_sel = AB::Expr::ZERO;
        let mut idx_sel = AB::Expr::ZERO;
        let mut sum_indi = AB::Expr::ZERO;
        let mut idx_indi = AB::Expr::ZERO;
        for k in 0..N {
            boolean(e(SEL + k), builder);
            boolean(e(INDI + k), builder);
            sum_sel = sum_sel + e(SEL + k);
            idx_sel = idx_sel + e(SEL + k) * AB::Expr::from_u64(k as u64);
            sum_indi = sum_indi + e(INDI + k);
            idx_indi = idx_indi + e(INDI + k) * AB::Expr::from_u64(k as u64);
        }
        builder.assert_eq(sum_sel, one.clone());
        builder.assert_eq(idx_sel, e(J));
        builder.assert_eq(sum_indi, one.clone());
        builder.assert_eq(idx_indi, e(I));

        // j ≤ i: t = i − j ∈ [0,256) via 8 bits.
        let mut tacc = AB::Expr::ZERO;
        let mut wt = AB::Expr::ONE;
        for b in 0..TBITS {
            let bit: AB::Expr = row[NP + b].into();
            boolean(bit.clone(), builder);
            tacc = tacc + bit * wt.clone();
            wt = wt.clone() + wt.clone();
        }
        builder.assert_eq(e(T), tacc);
        builder.assert_eq(e(I) - e(J), e(T));

        // sign bit → ±1
        boolean(e(SGN), builder);
        let sign = one.clone() - AB::Expr::from_u64(2) * e(SGN);

        // a_j = Σ sel[k]·a[k]  (read c[j] before the step).
        let mut ajv = AB::Expr::ZERO;
        for k in 0..N {
            ajv = ajv + e(SEL + k) * e(A + k);
        }
        builder.assert_eq(e(AJ), ajv);

        // next[k] = a[k]·(1 − sel − indi + sel·indi)  + indi·(1−sel)·a_j  + sel·sign
        //   k∉{i,j}: next=a[k];  k=j≠i: next=sign;  k=i≠j: next=a_j;  k=i=j: next=sign.
        for k in 0..N {
            let s = e(SEL + k);
            let d = e(INDI + k);
            let keep = one.clone() - s.clone() - d.clone() + s.clone() * d.clone();
            let put_i = d.clone() * (one.clone() - s.clone()) * e(AJ);
            let put_j = s.clone() * sign.clone();
            builder.assert_eq(e(NEXT + k), e(A + k) * keep + put_i + put_j);
        }
    }
}

/// Reference SampleInBall placement step: c[i] ← c[j]; c[j] ← sign  (sign ∈ {−1,+1}).
fn ref_step(a: &[i64; N], i: usize, j: usize, sign: i64) -> [i64; N] {
    let mut c = *a;
    let aj = c[j];
    c[i] = aj;
    c[j] = sign;
    c
}

/// A faithful ML-DSA-87 SampleInBall run (rejection j≤i, τ=60 signs) driven by a deterministic
/// byte stream (an LCG stands in for SHAKE256 — the placement gadget is independent of the stream
/// source, which is a separately-proven SHAKE AIR). Returns the sequence of (a_before,i,j,sign).
fn sample_in_ball_steps(seed: u64) -> Vec<([i64; N], usize, usize, i64)> {
    const TAU: usize = 60;
    let mut lcg = seed;
    let mut next_byte = || {
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((lcg >> 33) & 0xff) as usize
    };
    // first 8 bytes → 64 sign bits
    let mut signs: u64 = 0;
    for b in 0..8 {
        signs |= (next_byte() as u64) << (8 * b);
    }
    let mut c = [0i64; N];
    let mut steps = Vec::new();
    for i in (N - TAU)..N {
        let j = loop {
            let b = next_byte();
            if b <= i {
                break b;
            }
        };
        let sign = 1 - 2 * ((signs & 1) as i64);
        signs >>= 1;
        let before = c;
        c[i] = c[j];
        c[j] = sign;
        steps.push((before, i, j, sign));
    }
    // self-check: exactly τ nonzeros, all ±1.
    assert_eq!(c.iter().filter(|&&x| x != 0).count(), TAU);
    assert!(c.iter().all(|&x| x == -1 || x == 0 || x == 1));
    steps
}

fn generate<F: PrimeField64>(rows: &[([i64; N], usize, usize, i64)]) -> RowMajorMatrix<F> {
    let n = rows.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    let fe = |v: i64| -> F {
        // map {−1,0,1,...} to field
        F::from_u64(v.rem_euclid(2013265921) as u64)
    };
    for (r, (a, i, j, sign)) in rows.iter().enumerate() {
        let base = r * NUM_COLS;
        let (i, j, sign) = (*i, *j, *sign);
        assert!(j <= i && i < N);
        let nxt = ref_step(a, i, j, sign);
        for k in 0..N {
            vals[base + A + k] = fe(a[k]);
            vals[base + NEXT + k] = fe(nxt[k]);
            vals[base + SEL + k] = F::from_u64((k == j) as u64);
            vals[base + INDI + k] = F::from_u64((k == i) as u64);
        }
        vals[base + I] = F::from_u64(i as u64);
        vals[base + J] = F::from_u64(j as u64);
        vals[base + SGN] = F::from_u64((sign == -1) as u64); // sign bit: 1 → −1
        vals[base + AJ] = fe(a[j]);
        let t = (i - j) as u64;
        vals[base + T] = F::from_u64(t);
        for b in 0..TBITS {
            vals[base + NP + b] = F::from_u64((t >> b) & 1);
        }
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
    let air = SibAir {};
    let all = sample_in_ball_steps(0x5eed_1234_dead_beef);
    // take 8 consecutive real steps (incl. late steps where several coeffs are already ±1).
    let rows: Vec<_> = all[all.len() - 8..].to_vec();
    let mut trace = generate::<Val>(&rows);
    // diff-test: NEXT column == reference swap step for each row.
    for (r, (a, i, j, sign)) in rows.iter().enumerate() {
        let nxt = ref_step(a, *i, *j, *sign);
        for k in 0..N {
            assert_eq!(trace.values[r * NUM_COLS + NEXT + k], Val::from_u64(nxt[k].rem_euclid(2013265921) as u64));
        }
    }
    if corrupt {
        trace.values[NEXT] += Val::ONE; // wrong placement output for row 0
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt SampleInBall placement accepted!"),
        Ok(_) => println!(
            "VERIFY ok — ML-DSA-87 SampleInBall placement (FIPS-204 Alg.29 Fisher-Yates step) proven \
             as a Plonky3 AIR over n=256: data-dependent indexed swap c[i]←c[j]; c[j]←±1 via one-hot \
             selectors sel=[k==j]/indi=[k==i] (boolean, one-hot, index-bound), read a_j=Σsel·a, j≤i by \
             8-bit slack, over 8 real SampleInBall steps. NEXT column diff-tested == reference swap; \
             --corrupt rejected. This is the array-threading-with-witnessed-index step of the verify \
             integration (challenge polynomial construction)."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt SampleInBall placement rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
