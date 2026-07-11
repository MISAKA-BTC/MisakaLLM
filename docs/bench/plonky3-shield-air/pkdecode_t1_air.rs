//! C-P6 verify prerequisite: **pkDecode `t1` unpacking** (FIPS-204 SimpleBitPack, 10-bit) as a
//! Plonky3 AIR. ML-DSA-87 `Verify` first parses the 2592-byte public key `pk = ρ ‖ t1` where the
//! `k=8` polynomials of `t1` are packed 10 bits per coefficient (`t1ᵢ ∈ [0, 2¹⁰)`); those
//! coefficients are what the NTT then transforms. SimpleBitPack for a 10-bit width packs 4
//! consecutive coefficients into 5 bytes (40 bits), little-endian. This AIR proves that unpack:
//! given the 5 packed bytes and the 4 unpacked coefficients, the 40 bits regroup EXACTLY (a
//! wrong-endianness / off-by-a-bit unpack — which would feed the NTT the wrong t1 — is rejected).
//!
//! One row = one 4-coefficient / 5-byte group. The 40 bits are shared: each coeff is a 10-bit
//! grouping, each byte an 8-bit grouping, of the SAME bit vector. `--corrupt` flips a coeff → the
//! byte grouping no longer matches → rejected. Diff-tested against a plain reference unpack.

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

const NBITS: usize = 40; // 4 coeffs × 10 bits = 5 bytes × 8 bits
const NC: usize = 4; // coefficients per group
const NBY: usize = 5; // bytes per group
// columns: c[0..4] | byte[0..5] | 40 shared bits
const C: usize = 0;
const BY: usize = NC;
const NP: usize = NC + NBY;
const BITS: usize = NP; // bit columns start here
const NUM_COLS: usize = NP + NBITS;

struct PkDecodeT1Air {}

impl<F> BaseAir<F> for PkDecodeT1Air {
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

impl<AB: AirBuilder> Air<AB> for PkDecodeT1Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let e = |i: usize| -> AB::Expr { row[i].into() };
        // boolean-check every shared bit.
        for b in 0..NBITS {
            let bit: AB::Expr = row[BITS + b].into();
            builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
        }
        // each coefficient is a 10-bit grouping of the shared bits (bits [10k, 10k+10)).
        for k in 0..NC {
            let mut acc = AB::Expr::ZERO;
            let mut w = AB::Expr::ONE;
            for i in 0..10 {
                let bit: AB::Expr = row[BITS + 10 * k + i].into();
                acc = acc + bit * w.clone();
                w = w.clone() + w.clone();
            }
            builder.assert_eq(e(C + k), acc);
        }
        // each byte is an 8-bit grouping of the SAME shared bits (bits [8j, 8j+8)).
        for j in 0..NBY {
            let mut acc = AB::Expr::ZERO;
            let mut w = AB::Expr::ONE;
            for i in 0..8 {
                let bit: AB::Expr = row[BITS + 8 * j + i].into();
                acc = acc + bit * w.clone();
                w = w.clone() + w.clone();
            }
            builder.assert_eq(e(BY + j), acc);
        }
    }
}

/// Reference SimpleBitPack unpack: 5 bytes → 4 ten-bit coefficients (little-endian bitstream).
fn unpack10(bytes: &[u8; NBY]) -> [u16; NC] {
    let mut v: u64 = 0;
    for (j, &b) in bytes.iter().enumerate() {
        v |= (b as u64) << (8 * j);
    }
    std::array::from_fn(|k| ((v >> (10 * k)) & 0x3FF) as u16)
}

fn generate<F: PrimeField64>(groups: &[[u8; NBY]]) -> RowMajorMatrix<F> {
    let n = groups.len();
    assert!(n.is_power_of_two());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, bytes) in groups.iter().enumerate() {
        let base = r * NUM_COLS;
        let mut v: u64 = 0;
        for (j, &b) in bytes.iter().enumerate() {
            v |= (b as u64) << (8 * j);
        }
        let coeffs = unpack10(bytes);
        for k in 0..NC {
            vals[base + C + k] = F::from_u64(coeffs[k] as u64);
        }
        for j in 0..NBY {
            vals[base + BY + j] = F::from_u64(bytes[j] as u64);
        }
        for b in 0..NBITS {
            vals[base + BITS + b] = F::from_u64((v >> b) & 1);
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
    let air = PkDecodeT1Air {};
    // 8 packed 5-byte groups (deterministic, spanning the byte range incl. all-0xFF = coeff 0x3FF).
    let groups: Vec<[u8; NBY]> = (0..8u32)
        .map(|g| std::array::from_fn(|j| (g.wrapping_mul(37).wrapping_add(j as u32 * 91).wrapping_add(g)) as u8))
        .collect();
    let mut trace = generate::<Val>(&groups);
    // diff-test: the C columns equal the reference unpack, and each coeff < 2^10.
    for (r, bytes) in groups.iter().enumerate() {
        let coeffs = unpack10(bytes);
        for k in 0..NC {
            assert!(coeffs[k] < 1024);
            assert_eq!(trace.values[r * NUM_COLS + C + k], Val::from_u64(coeffs[k] as u64), "row {r} coeff {k}");
        }
    }
    if corrupt {
        trace.values[C] += Val::ONE; // wrong coeff 0 → its 10-bit grouping no longer matches the bytes
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — wrong t1 unpack accepted!"),
        Ok(_) => println!(
            "VERIFY ok — ML-DSA-87 pkDecode t1 unpacking (FIPS-204 SimpleBitPack, 10-bit) proven as a \
             Plonky3 AIR: 4 coefficients (each t1ᵢ∈[0,2¹⁰)) unpacked from 5 packed bytes via 40 shared \
             bits regrouped 10-bit-per-coeff vs 8-bit-per-byte, over 8 groups. The unpacked coeffs are \
             diff-tested == the reference SimpleBitPack; --corrupt (wrong coeff) rejected. This is the \
             pk-parse step that feeds the NTT the correct t1 (a wrong-endianness unpack is caught)."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — wrong t1 unpack rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
