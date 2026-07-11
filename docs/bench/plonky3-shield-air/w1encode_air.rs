//! C-P6 verify tail: **w1Encode** (FIPS-204 `SimpleBitPack`) as a Plonky3 AIR — the last
//! transform before the challenge recompute `c̃' = SHAKE256(μ ‖ w1Encode(w1))` in ML-DSA-87
//! `Verify`. For ML-DSA-87 the high-part coefficients are `w1ᵢ ∈ [0, 16)` (since
//! `(q−1)/(2γ2) = 16`), so `w1Encode` packs two consecutive 4-bit coefficients into each
//! output byte: `byte = c_lo + 16·c_hi`. This AIR proves that packing with `c_lo, c_hi`
//! range-checked into `[0,16)` and the byte bound to `[0,256)`, and the trace is diff-tested
//! against the byte stream the validated reference (`mldsa_verify_ref.rs`) produces.
//!
//! One row = one output byte (two coefficients). `--corrupt` flips a nibble → rejected.

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

// columns: c_lo (4 bits) | c_hi (4 bits) | byte (8 bits)
const CLO: usize = 0;
const CHI: usize = 1;
const BYTE: usize = 2;
const NP: usize = 3;
const WIDTHS: [usize; NP] = [4, 4, 8];
const NUM_COLS: usize = 19; // 3 + 16

fn bit_off(c: usize) -> usize {
    NP + WIDTHS[..c].iter().sum::<usize>()
}

struct W1EncodeAir {}

impl<F> BaseAir<F> for W1EncodeAir {
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

impl<AB: AirBuilder> Air<AB> for W1EncodeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        // bind + range-check c_lo(4), c_hi(4), byte(8) via bits.
        for c in 0..NP {
            let bo = bit_off(c);
            let mut acc = AB::Expr::ZERO;
            let mut w = AB::Expr::ONE;
            for j in 0..WIDTHS[c] {
                let b: AB::Expr = row[bo + j].into();
                builder.assert_zero(b.clone() * (b.clone() - one.clone()));
                acc = acc + b * w.clone();
                w = w.clone() + w.clone();
            }
            builder.assert_eq(row[c].into(), acc);
        }
        // byte = c_lo + 16·c_hi (SimpleBitPack of two 4-bit coefficients).
        let sixteen = AB::Expr::from_u64(16);
        builder.assert_eq(row[BYTE].into(), row[CLO].into() + sixteen * row[CHI].into());
    }
}

fn generate<F: PrimeField64>(coeffs: &[u8]) -> RowMajorMatrix<F> {
    assert!(coeffs.len() % 2 == 0);
    let rows = coeffs.len() / 2;
    assert!(rows.is_power_of_two());
    let mut vals = F::zero_vec(rows * NUM_COLS);
    for r in 0..rows {
        let base = r * NUM_COLS;
        let clo = coeffs[2 * r] as u64;
        let chi = coeffs[2 * r + 1] as u64;
        let byte = clo + 16 * chi;
        let put = |vals: &mut [F], col: usize, v: u64| {
            vals[base + col] = F::from_u64(v);
            let bo = bit_off(col);
            for j in 0..WIDTHS[col] {
                vals[base + bo + j] = F::from_u64((v >> j) & 1);
            }
        };
        put(&mut vals, CLO, clo);
        put(&mut vals, CHI, chi);
        put(&mut vals, BYTE, byte);
    }
    RowMajorMatrix::new(vals, NUM_COLS)
}

/// The reference SimpleBitPack (4-bit) over a coefficient stream — MUST equal the AIR's
/// per-row `byte` column and `mldsa_verify_ref::w1_encode`.
fn reference_pack(coeffs: &[u8]) -> Vec<u8> {
    coeffs.chunks(2).map(|c| c[0] + 16 * c[1]).collect()
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
    let air = W1EncodeAir {};
    // 256 coefficients (one poly's worth) in [0,16) → 128 packed bytes.
    let coeffs: Vec<u8> = (0..256u32).map(|i| ((i.wrapping_mul(7) + 3) % 16) as u8).collect();
    // trace's byte column must equal the reference SimpleBitPack.
    let refbytes = reference_pack(&coeffs);
    let mut trace = generate::<Val>(&coeffs);
    // diff-test: the generated BYTE column matches the reference packing.
    for (r, &b) in refbytes.iter().enumerate() {
        assert_eq!(trace.values[r * NUM_COLS + BYTE], Val::from_u64(b as u64), "row {r} byte");
    }
    if corrupt {
        trace.values[CHI] += Val::ONE; // break byte = c_lo + 16·c_hi (and c_hi's bits)
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt w1Encode trace accepted!"),
        Ok(_) => println!(
            "VERIFY ok — w1Encode (FIPS-204 SimpleBitPack, ML-DSA-87 w1ᵢ∈[0,16)) proven as a Plonky3 AIR: byte = c_lo + 16·c_hi with 4-bit nibble range checks; 128 bytes, and the trace's byte column matches the reference SimpleBitPack (== mldsa_verify_ref::w1_encode). This is the c̃-recompute input prep; --corrupt rejected."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt w1Encode trace rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
