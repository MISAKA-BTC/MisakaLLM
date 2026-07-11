//! Blake2bClaim's sibling for C-P6 (ADR-0037 §2.4 / cp6 design step 1): the **Keccak-f
//! [1600] AIR** integrated into the shield-air hiding harness — the hash sub-gadget every
//! ML-DSA-87 SHAKE step (ExpandA / mu / SampleInBall / the final commitment hash) reduces
//! to. We reuse Plonky3's `p3-keccak-air` (a tested, byte-correct Keccak-f AIR — its own
//! diff-tests guarantee correctness) and prove N permutations under the SAME hiding/ZK FRI
//! config as build#1-7, verify, and reject a corrupted trace (soundness). The measured
//! area (rows × cols) is the cost input for the C-P6 estimate: ML-DSA-87 `ExpandA`
//! rejection-samples k·l·256 ≈ 14 k coefficients ⇒ hundreds of Keccak-f permutations.
//!
//! This lands C-P6 build-order step 1 (the SHAKE primitive proves in our harness); the
//! remaining sub-builds are the sponge wrapper + rejection sampling, the 256-pt NTT over
//! Z_q, and the full `Verify` composition diff-tested vs `libcrux_ml_dsa` (cp6 design §5).
//!
//! `--corrupt` flips a trace cell → the proof must be rejected.

use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_field::extension::BinomialExtensionField;
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_keccak_air::{KeccakAir, NUM_ROUNDS, generate_trace_rows};
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Dft = Radix2DitParallel<Val>;
type ZkByteHash = Keccak256Hash;
type ZkU64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type ZkFieldHash = SerializingHasher<ZkU64Hash>;
type ZkCompress = CompressionFunctionFromHasher<ZkU64Hash, 2, 4>;
type ZkValHidingMmcs = MerkleTreeHidingMmcs<[Val; p3_keccak::VECTOR_LEN], [u64; p3_keccak::VECTOR_LEN], ZkFieldHash, ZkCompress, SmallRng, 2, 4, 4>;
type ZkChallenger = SerializingChallenger32<Val, HashChallenger<u8, ZkByteHash, 32>>;
type ZkChallengeHidingMmcs = ExtensionMmcs<Val, Challenge, ZkValHidingMmcs>;
type ZkHidingPcs = p3_fri::HidingFriPcs<Val, Dft, ZkValHidingMmcs, ZkChallengeHidingMmcs, SmallRng>;
type ZkConfig = StarkConfig<ZkHidingPcs, Challenge, ZkChallenger>;
fn make_zk_config() -> ZkConfig {
    let byte_hash = ZkByteHash {};
    let u64_hash = ZkU64Hash::new(KeccakF {});
    let field_hash = ZkFieldHash::new(u64_hash);
    let compress = ZkCompress::new(u64_hash);
    let val_mmcs = ZkValHidingMmcs::new(field_hash, compress, 0, SmallRng::seed_from_u64(1));
    let challenge_mmcs = ZkChallengeHidingMmcs::new(val_mmcs.clone());
    let fri_params = p3_fri::FriParameters::new_testing(challenge_mmcs, 2);
    let pcs = ZkHidingPcs::new(Dft::default(), val_mmcs, fri_params, 4, SmallRng::seed_from_u64(1));
    ZkConfig::new(pcs, ZkChallenger::from_hasher(vec![], byte_hash))
}

fn main() {
    let corrupt = std::env::args().any(|a| a == "--corrupt");
    // N Keccak-f permutations over deterministic input states (the SHAKE building block).
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(8);
    let inputs: Vec<[u64; 25]> = (0..n)
        .map(|i| core::array::from_fn(|j| 0x9e37_79b9_7f4a_7c15u64.wrapping_mul((i * 25 + j) as u64 + 1)))
        .collect();

    let air = KeccakAir {};
    let mut trace = generate_trace_rows::<Val>(inputs.clone(), 2);
    let (rows, cols) = (trace.height(), trace.width());

    // The upstream p3-keccak-air is diff-tested byte-for-byte vs the KeccakF permutation
    // in its own test suite; here we confirm the harness integration by proving + a
    // soundness negative. (A full SHAKE-sponge diff-test lands with the sponge wrapper.)
    let _ref_perm = |st: [u64; 25]| -> [u64; 25] {
        use p3_symmetric::Permutation;
        let mut s = st;
        KeccakF {}.permute_mut(&mut s);
        s
    };

    if corrupt {
        trace.values[cols / 2] += Val::ONE;
    }
    let config = make_zk_config();
    let t0 = std::time::Instant::now();
    let proof = prove(&config, &air, trace, &vec![]);
    let t_prove = t0.elapsed();
    let res = verify(&config, &air, &proof, &vec![]);
    match &res {
        Ok(_) if corrupt => println!("NEGATIVE TEST FAIL — a corrupted Keccak-f trace was accepted!"),
        Ok(_) => println!(
            "VERIFY ok — {n} Keccak-f[1600] permutations proven under the shield hiding-ZK config ({} rows × {} cols = {} cells/round-block, {} rounds/perm), hiding-ZK [prove {:.1?}]. This is the C-P6 SHAKE primitive; ExpandA ≈ hundreds of these.",
            rows, cols, rows * cols, NUM_ROUNDS, t_prove
        ),
        Err(e) if corrupt => println!("NEGATIVE TEST PASS — corrupted Keccak-f trace rejected: {e:?}"),
        Err(e) => println!("UNEXPECTED reject on a valid Keccak-f trace: {e:?}"),
    }
}
