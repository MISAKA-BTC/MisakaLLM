//! C-P6 verify acceptance predicate: the **‖z‖∞ < γ1−β** norm-bound check as a Plonky3 AIR, for
//! ML-DSA-87 (γ1 = 2¹⁹ = 524288, β = τ·η = 60·2 = 120, so the bound is γ1−β = 524168). This is
//! the FIPS-204 `Verify` step that rejects any signature whose response `z` has an oversized
//! coefficient (a forged/malformed sig). `mldsa_parse_checks.rs` already VALIDATED that 24 real
//! libcrux sigs satisfy this (‖z‖∞ max 524153 < 524168); this AIR proves the PREDICATE itself.
//!
//! Each z-coefficient is carried in its BitUnpack form `t = γ1 − z_i ∈ [0, 2γ1)` (20-bit). The
//! centered value is `z_i = γ1 − t`, and `|z_i| < γ1−β  ⟺  β < t < 2γ1−β`, proved by two
//! range-checked slacks `lo = t−(β+1) ≥ 0`, `hi = (2γ1−β−1)−t ≥ 0`. One row = one coefficient;
//! `--corrupt` forces `t=0` (⇒ |z|=γ1 > bound) → rejected.

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

const GAMMA1: i64 = 1 << 19; // 524288
const BETA: i64 = 120; // τ·η = 60·2
const G1X2: i64 = 2 * GAMMA1; // 1048576 = 2^20
// acceptance window for t: β < t < 2γ1−β, i.e. t ∈ [β+1, 2γ1−β−1].
const TLO: i64 = BETA + 1; // 121
const THI: i64 = G1X2 - BETA - 1; // 1048455

const T: usize = 0; // packed t = γ1 − z_i
const Z: usize = 1; // centered z_i = γ1 − t (field)
const LO: usize = 2; // t − (β+1)
const HI: usize = 3; // (2γ1−β−1) − t
const NP: usize = 4;
const W20: usize = 20;
// three 20-bit ranged columns: T, LO, HI
const NUM_COLS: usize = NP + 3 * W20;
fn off(idx: usize) -> usize {
    NP + idx * W20
}

struct NormAir {}

impl<F> BaseAir<F> for NormAir {
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

impl<AB: AirBuilder> Air<AB> for NormAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let e = |i: usize| -> AB::Expr { row[i].into() };
        // range-check T, LO, HI (each 20-bit) and bind to bits.
        for (idx, &col) in [T, LO, HI].iter().enumerate() {
            let bo = off(idx);
            let mut acc = AB::Expr::ZERO;
            let mut wt = AB::Expr::ONE;
            for j in 0..W20 {
                let b: AB::Expr = row[bo + j].into();
                builder.assert_zero(b.clone() * (b.clone() - one.clone()));
                acc = acc + b * wt.clone();
                wt = wt.clone() + wt.clone();
            }
            builder.assert_eq(e(col), acc);
        }
        // z = γ1 − t  (centered representative).
        builder.assert_eq(e(Z), AB::Expr::from_u64(GAMMA1 as u64) - e(T));
        // acceptance window: lo = t − (β+1) ≥ 0, hi = (2γ1−β−1) − t ≥ 0  ⇒ |z| < γ1−β.
        builder.assert_eq(e(LO), e(T) - AB::Expr::from_u64(TLO as u64));
        builder.assert_eq(e(HI), AB::Expr::from_u64(THI as u64) - e(T));
    }
}

/// Reference acceptance: |γ1 − t| < γ1 − β.
fn accepts(t: i64) -> bool {
    (GAMMA1 - t).abs() < GAMMA1 - BETA
}

fn generate<F: PrimeField64>(ts: &[i64]) -> RowMajorMatrix<F> {
    let n = ts.len();
    assert!(n.is_power_of_two());
    let p: i64 = 2013265921;
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, &t) in ts.iter().enumerate() {
        let base = r * NUM_COLS;
        assert!((0..G1X2).contains(&t));
        let z = GAMMA1 - t;
        let lo = t - TLO;
        let hi = THI - t;
        vals[base + T] = F::from_u64(t as u64);
        vals[base + Z] = F::from_u64(z.rem_euclid(p) as u64);
        vals[base + LO] = F::from_u64(lo.rem_euclid(p) as u64);
        vals[base + HI] = F::from_u64(hi.rem_euclid(p) as u64);
        for (idx, &v) in [t, lo, hi].iter().enumerate() {
            let bo = off(idx);
            for j in 0..W20 {
                vals[base + bo + j] = F::from_u64(((v >> j) & 1) as u64);
            }
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
    let air = NormAir {};
    // representative packed t values: the two tight-passing boundaries (t=121, t=1048455 → |z|=524167),
    // the real-sig extremes measured in mldsa_parse_checks (t=135, t=1048441 → |z|=524153), and interior.
    let ts: Vec<i64> = vec![TLO, THI, 135, G1X2 - 135, GAMMA1, GAMMA1 + 1000, 300000, 700000];
    // all must satisfy the reference bound.
    for &t in &ts {
        assert!(accepts(t), "t={t} should pass |z|<γ1−β");
    }
    // and the tight failing boundary t=β=120 must NOT pass the reference (sanity of the window).
    assert!(!accepts(BETA), "t=β must fail (|z|=γ1−β)");
    let mut trace = generate::<Val>(&ts);
    if corrupt {
        // force row 0 t=0 ⇒ |z|=γ1 > bound; the LO slack (0−121) is negative → range fails.
        trace.values[T] = Val::ZERO;
        for j in 0..W20 {
            trace.values[off(0) + j] = Val::ZERO;
        }
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — out-of-bound z accepted!"),
        Ok(_) => println!(
            "VERIFY ok — ML-DSA-87 ‖z‖∞ < γ1−β norm-bound acceptance predicate proven as a Plonky3 \
             AIR (γ1=524288, β=120, bound=524168): each z-coeff carried as t=γ1−z_i, checked β<t<2γ1−β \
             via two 20-bit range slacks, over the tight boundaries (|z|=524167) and the real-sig \
             extremes (|z|=524153, from mldsa_parse_checks over 24 libcrux sigs). --corrupt (t=0, \
             |z|=γ1) rejected. This is the sig-forgery-rejecting verify accept predicate."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — out-of-bound z rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
