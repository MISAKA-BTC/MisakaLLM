//! C-P6 step-b tail: the **ExpandA rejection-sampling** decision as a Plonky3 AIR — the
//! dominant cost of ML-DSA-87 `Verify` (`ExpandA` rejection-samples `k·l·256 ≈ 14k`
//! coefficients from SHAKE128 output). Per candidate: read 3 SHAKE output bytes, form
//! `t = (b0 | b1<<8 | b2<<16) & 0x7FFFFF` (mask to 23 bits), and **ACCEPT iff `t < q`**
//! (`q = 8380417`); accepted `t` becomes a matrix coefficient, rejected ones are skipped.
//!
//! The novel gadget is the sound **`less-than → boolean`**: witness `lt ∈ {0,1}` and `diff`,
//! constrain `t − q + lt·2²⁴ = diff` with `diff ∈ [0, 2²⁴)` range-checked. If `t < q`, `t−q`
//! is negative and only `lt=1` keeps `diff` in range; if `t ≥ q`, only `lt=0` does — so `lt`
//! is FORCED to `[t < q]`. Every intermediate `< 2²⁵ < p` so the field equation is exact.
//! This is the accept/reject flag the rejection-sampling loop consumes. `--corrupt` → reject.

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
const TWO24: u64 = 1 << 24;

// columns: IN(24 bits) | T value | LT bool | DIFF value | DIFF(24 bits)
const IN_BITS: usize = 0; // 24 input bits (3 bytes, little-endian)
const T: usize = 24; // t = low 23 bits of IN
const LT: usize = 25; // accept flag = [t < q]
const DIFF: usize = 26; // t - q + lt·2^24
const DIFF_BITS: usize = 27; // 24 bits
const NUM_COLS: usize = 27 + 24; // 51

struct RejectionSampleAir {}

impl<F> BaseAir<F> for RejectionSampleAir {
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

impl<AB: AirBuilder> Air<AB> for RejectionSampleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;

        // booleanity: input bits, diff bits, lt.
        for i in 0..24 {
            let x: AB::Expr = row[IN_BITS + i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
            let d: AB::Expr = row[DIFF_BITS + i].into();
            builder.assert_zero(d.clone() * (d - one.clone()));
        }
        let lt: AB::Expr = row[LT].into();
        builder.assert_zero(lt.clone() * (lt.clone() - one.clone()));

        // t = low 23 bits of IN (bit 23 masked off — the ExpandA & 0x7FFFFF).
        let mut t_acc = AB::Expr::ZERO;
        let mut w = AB::Expr::ONE;
        for j in 0..23 {
            t_acc = t_acc + row[IN_BITS + j].into() * w.clone();
            w = w.clone() + w.clone();
        }
        builder.assert_eq(row[T].into(), t_acc);

        // diff = Σ diff_bits.
        let mut d_acc = AB::Expr::ZERO;
        let mut w2 = AB::Expr::ONE;
        for j in 0..24 {
            d_acc = d_acc + row[DIFF_BITS + j].into() * w2.clone();
            w2 = w2.clone() + w2.clone();
        }
        builder.assert_eq(row[DIFF].into(), d_acc);

        // the sound less-than: t - q + lt·2^24 = diff, diff ∈ [0,2^24). Forces lt = [t < q].
        let q = AB::Expr::from_u64(Q);
        let two24 = AB::Expr::from_u64(TWO24);
        let t: AB::Expr = row[T].into();
        let diff: AB::Expr = row[DIFF].into();
        builder.assert_eq(t - q + lt * two24, diff);
    }
}

fn generate<F: PrimeField64>(inputs: &[u32]) -> RowMajorMatrix<F> {
    let n = inputs.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, &input) in inputs.iter().enumerate() {
        let base = r * NUM_COLS;
        let inv = (input & 0x00FF_FFFF) as u64; // 24-bit, 3 bytes
        let t = inv & 0x7F_FFFF; // 23-bit mask
        let lt = if t < Q { 1u64 } else { 0 };
        let diff = t + lt * TWO24 - Q; // = t - q + lt·2^24
        for j in 0..24 {
            vals[base + IN_BITS + j] = F::from_u64((inv >> j) & 1);
            vals[base + DIFF_BITS + j] = F::from_u64((diff >> j) & 1);
        }
        vals[base + T] = F::from_u64(t);
        vals[base + LT] = F::from_u64(lt);
        vals[base + DIFF] = F::from_u64(diff);
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
    let air = RejectionSampleAir {};
    // 8 candidates straddling q: even i land below q (ACCEPT), odd i in [q, 2^23) (REJECT).
    // Bit 23 is set on odd rows too, to exercise the & 0x7FFFFF masking (it must be dropped).
    let inputs: Vec<u32> = (0..8u32)
        .map(|i| {
            let t = if i % 2 == 0 {
                (i as u64) * 1_000_003 % Q // < q → accept
            } else {
                Q + (i as u64) * 777 // in [q, 2^23) → reject
            };
            (t as u32) | ((i & 1) << 23) // bit 23 = arbitrary, masked off
        })
        .collect();
    let n_accept = inputs.iter().filter(|&&v| ((v & 0x7F_FFFF) as u64) < Q).count();

    let mut trace = generate::<Val>(&inputs);
    if corrupt {
        trace.values[LT] += Val::ONE; // flip an accept flag → less-than constraint breaks
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt rejection-sample trace was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — 8 ExpandA rejection-sample decisions proven as a Plonky3 AIR ({n_accept} accept / {} reject): t = 3-byte LE & 0x7FFFFF, accept flag lt = [t < q] FORCED by the sound t−q+lt·2²⁴ = diff ∈ [0,2²⁴) constraint (q={Q}). This is the dominant ML-DSA verify cost; the accept/reject flag the sampling loop consumes is now constrained.",
            8 - n_accept
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt rejection-sample trace rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
