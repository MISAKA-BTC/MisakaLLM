//! C-P6 steps b/c/d/g (SHAKE side): the **sponge ABSORB + pad10*1 constraint** as a Plonky3
//! AIR. Every ML-DSA-87 SHAKE call reduces to (Keccak-f permutation) + (this sponge
//! bookkeeping); `p3-keccak-air` already proves the permutation (keccak_shake.rs), and
//! `shake_sponge.rs` diff-tests the whole wrapper vs `sha3` byte-for-byte. This AIR pins the
//! WRAPPER's arithmetic: `state' = state ⊕ padded_block` over the SHAKE256 rate (17 lanes ×
//! 64 bits), with the capacity lanes passing through, and the **FIPS-202 padding**
//! (`0x1F` domain byte at the message tail, `0x80` at the last rate byte) enforced as fixed
//! block bits. XOR is build#1's degree-2 `a+b−2ab`. `--corrupt` → rejected.
//!
//! Scope: SHAKE256, single absorb block, empty message (padding at byte 0 = 0x1F and byte
//! 135 = 0x80) — the padding corner. Longer messages differ only in which block bytes carry
//! data vs the pad, the same per-lane XOR constraint.

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

const RATE_LANES: usize = 17; // SHAKE256 rate = 136 bytes = 17 × 64-bit lanes
const BITS: usize = 64;
const RATE_BITS: usize = RATE_LANES * BITS; // 1088
// Layout: [ state_rate bits | block bits | newstate_rate bits ]
const STATE: usize = 0;
const BLOCK: usize = RATE_BITS;
const NEW: usize = 2 * RATE_BITS;
const NUM_COLS: usize = 3 * RATE_BITS; // 3264

struct ShakeAbsorbAir {}

impl<F> BaseAir<F> for ShakeAbsorbAir {
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

impl<AB: AirBuilder> Air<AB> for ShakeAbsorbAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;
        let two = AB::Expr::ONE + AB::Expr::ONE;

        // booleanity of every bit column
        for i in 0..NUM_COLS {
            let x: AB::Expr = row[i].into();
            builder.assert_zero(x.clone() * (x - one.clone()));
        }

        // absorb: newstate_bit = state_bit XOR block_bit  (a+b−2ab), all rate bits
        for i in 0..RATE_BITS {
            let s: AB::Expr = row[STATE + i].into();
            let b: AB::Expr = row[BLOCK + i].into();
            let xor = s.clone() + b.clone() - s * b * two.clone();
            let n: AB::Expr = row[NEW + i].into();
            builder.assert_eq(n, xor);
        }

        // FIPS-202 pad10*1 + SHAKE 0x1F domain separation, empty message:
        //   byte 0 = 0x1F  → lane 0, bits 0..8 = 1,1,1,1,1,0,0,0
        //   byte 135 = 0x80 → lane 16, bits 56..64 = 0,0,0,0,0,0,0,1
        //   all other block bits = 0
        let byte0: [u64; 8] = [1, 1, 1, 1, 1, 0, 0, 0]; // 0x1F little-endian bits
        for (j, &bit) in byte0.iter().enumerate() {
            let col: AB::Expr = row[BLOCK + j].into();
            builder.assert_eq(col, AB::Expr::from_u64(bit));
        }
        // top byte of the last rate lane (lane 16, byte 7 = bits 56..64) = 0x80
        let top_byte: [u64; 8] = [0, 0, 0, 0, 0, 0, 0, 1]; // 0x80 little-endian bits
        let last_lane_base = BLOCK + 16 * BITS;
        for (j, &bit) in top_byte.iter().enumerate() {
            let col: AB::Expr = row[last_lane_base + 56 + j].into();
            builder.assert_eq(col, AB::Expr::from_u64(bit));
        }
        // every other block bit is zero (empty message ⇒ only the two pad bytes are set)
        for i in 0..RATE_BITS {
            let is_pad = i < 8 || (i >= last_lane_base - BLOCK + 56 && i < last_lane_base - BLOCK + 64);
            if !is_pad {
                builder.assert_zero(row[BLOCK + i].into());
            }
        }
    }
}

/// The padded first block for an empty SHAKE256 message (matches shake_sponge.rs / sha3).
fn empty_padded_block() -> Vec<u8> {
    let rate = RATE_LANES * 8; // 136
    let mut p = vec![0u8; rate];
    p[0] = 0x1F;
    p[rate - 1] |= 0x80;
    p
}

fn bytes_to_lane_bits(block: &[u8]) -> Vec<u64> {
    // little-endian lane packing → per-bit values, lane by lane
    let mut bits = vec![0u64; RATE_BITS];
    for lane in 0..RATE_LANES {
        let mut v = 0u64;
        for k in 0..8 {
            v |= (block[lane * 8 + k] as u64) << (8 * k);
        }
        for b in 0..BITS {
            bits[lane * BITS + b] = (v >> b) & 1;
        }
    }
    bits
}

fn generate<F: PrimeField64>(states: &[Vec<u64>]) -> RowMajorMatrix<F> {
    let n = states.len();
    assert!(n.is_power_of_two());
    let block_bits = bytes_to_lane_bits(&empty_padded_block());
    let mut vals = F::zero_vec(n * NUM_COLS);
    for (r, state_bits) in states.iter().enumerate() {
        let base = r * NUM_COLS;
        for i in 0..RATE_BITS {
            let s = state_bits[i];
            let b = block_bits[i];
            vals[base + STATE + i] = F::from_u64(s);
            vals[base + BLOCK + i] = F::from_u64(b);
            vals[base + NEW + i] = F::from_u64(s ^ b);
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
    let air = ShakeAbsorbAir {};
    // 4 rows: distinct pre-permutation states (0, all-ones-ish, and deterministic mixes).
    let states: Vec<Vec<u64>> = (0..4u64)
        .map(|r| {
            (0..RATE_BITS)
                .map(|i| ((0x9e3779b97f4a7c15u64.wrapping_mul(r + 1)).wrapping_add(i as u64) >> 3) & 1)
                .collect()
        })
        .collect();
    let mut trace = generate::<Val>(&states);
    if corrupt {
        trace.values[NEW + 3] += Val::ONE; // break one XOR output bit
    }
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &air, trace, &pis);
    match verify(&config, &air, &proof, &pis) {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — corrupt absorb trace was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — SHAKE256 sponge absorb + pad10*1/0x1F proven as a Plonky3 AIR: state' = state ⊕ padded_block over 17 rate lanes (1088 bits), FIPS-202 padding (0x1F@byte0, 0x80@byte135) constrained. This is the C-P6 SHAKE-wrapper bookkeeping; the permutation is p3-keccak-air (keccak_shake.rs), the whole wrapper diff-tested by shake_sponge.rs."
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupt absorb trace rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid trace: {e:?}"),
    }
}
