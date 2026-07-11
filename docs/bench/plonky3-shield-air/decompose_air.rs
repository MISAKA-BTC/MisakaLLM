//! C-P6 step-f: **Decompose** `r = r1·(2γ2) + r0` as a Plonky3 AIR — the high/low split at
//! the heart of ML-DSA-87 `UseHint` (which reconstructs `w1` in `Verify`). `γ2 = (q−1)/88 =
//! 95232`, `2γ2 = 190464`, `q = 8380417`. The high part `r1 ∈ [0, 44]`, the low part
//! `r0 ∈ [0, 2γ2)`. Key soundness observation: `r1·2γ2 ≤ 44·190464 = q−1 < p ≈ 2³¹`, so the
//! split is an EXACT single field equation — no limb carry needed (unlike the mod-q multiply).
//! Range checks (`r < q`, `r0 < 2γ2`, `r1 ≤ 44`) use the `value + slack = bound` pattern.
//! `UseHint` = this split + a `±1 mod 44` conditional on the hint bit (reuses the comparator).
//! `--corrupt` perturbs the split → rejected.

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

const Q: u64 = 8380417;
const GAMMA2X2: u64 = 190464; // 2·γ2, γ2 = (q-1)/88
const R1MAX: u64 = 44; // (q-1)/(2γ2)

// columns: R R0 R1 GR GR0 GR1  then their bit decompositions
const R: usize = 0;
const R0: usize = 1;
const R1: usize = 2;
const GR: usize = 3; // q-1-r
const GR0: usize = 4; // 2γ2-1-r0
const GR1: usize = 5; // 44-r1
const NP: usize = 6;
const WIDTHS: [usize; NP] = [23, 18, 6, 23, 18, 6];
const NUM_COLS: usize = 100; // 6 + 94

fn bit_off(col: usize) -> usize {
    NP + WIDTHS[..col].iter().sum::<usize>()
}

struct DecomposeAir {}

impl<F> BaseAir<F> for DecomposeAir {
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

impl<AB: AirBuilder> Air<AB> for DecomposeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;

        // bind + range-check every value via its bit decomposition.
        for c in 0..NP {
            let bo = bit_off(c);
            let mut acc = AB::Expr::ZERO;
            let mut w = AB::Expr::ONE;
            for j in 0..WIDTHS[c] {
                let bit: AB::Expr = row[bo + j].into();
                builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
                acc = acc + bit * w.clone();
                w = w.clone() + w.clone();
            }
            builder.assert_eq(row[c].into(), acc);
        }

        let e = |i: usize| -> AB::Expr { row[i].into() };
        let g2x2 = AB::Expr::from_u64(GAMMA2X2);

        // the split: r = r1·2γ2 + r0  (exact — r1·2γ2 ≤ q-1 < p).
        builder.assert_eq(e(R), e(R1) * g2x2 + e(R0));

        // canonical bounds: r < q, r0 < 2γ2, r1 ≤ 44  (value + slack = bound-1 / bound).
        builder.assert_eq(e(R) + e(GR), AB::Expr::from_u64(Q - 1));
        builder.assert_eq(e(R0) + e(GR0), AB::Expr::from_u64(GAMMA2X2 - 1));
        builder.assert_eq(e(R1) + e(GR1), AB::Expr::from_u64(R1MAX));
    }
}

fn generate<F: PrimeField64>(rs: &[u64]) -> RowMajorMatrix<F> {
    let n = rs.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (idx, &r) in rs.iter().enumerate() {
        assert!(r < Q);
        let base = idx * NUM_COLS;
        let r1 = r / GAMMA2X2;
        let r0 = r % GAMMA2X2;
        let put = |vals: &mut [F], col: usize, v: u64| {
            vals[base + col] = F::from_u64(v);
            let bo = bit_off(col);
            for j in 0..WIDTHS[col] {
                vals[base + bo + j] = F::from_u64((v >> j) & 1);
            }
        };
        put(&mut vals, R, r);
        put(&mut vals, R0, r0);
        put(&mut vals, R1, r1);
        put(&mut vals, GR, (Q - 1) - r);
        put(&mut vals, GR0, (GAMMA2X2 - 1) - r0);
        put(&mut vals, GR1, R1MAX - r1);
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
    let air = DecomposeAir {};
    // 8 field elements spanning [0, q): boundaries + interior, exercising r1 ∈ {0..44}.
    let rs: Vec<u64> = [0u64, 1, GAMMA2X2 - 1, GAMMA2X2, GAMMA2X2 + 7, 22 * GAMMA2X2 + 3, Q - 2, Q - 1].to_vec();
    let mut trace = generate::<Val>(&rs);
    if corrupt {
        trace.values[R0] += Val::ONE; // break r = r1·2γ2 + r0 (and R0's bit binding)
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt Decompose trace was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — 8 Decompose splits r = r1·2γ2 + r0 proven as a Plonky3 AIR (2γ2={GAMMA2X2}, r1∈[0,44], r0∈[0,2γ2), r<q). Exact single field equation (r1·2γ2 ≤ q-1 < p, no limb carry). This is the high/low split at the heart of UseHint; the comparator + this split compose the full UseHint. --corrupt rejected."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt Decompose trace rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
