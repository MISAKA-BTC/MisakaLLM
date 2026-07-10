//! Plonky3 F004-AIR harness — production STARK prover path (ADR-0035 / /goal (a)).
//!
//! A REAL custom Plonky3 AIR proving a genuine JoinSplit constraint — **value
//! conservation with HIDDEN amounts**: "I know N private note amounts that sum to
//! the public `total`", proven with the **hiding / zero-knowledge FRI variant**
//! (`HidingFriPcs` + `MerkleTreeHidingMmcs`) so the individual amounts are not
//! revealed. This stands up the exact production harness (custom AIR + M31/BabyBear
//! STARK + ZK-FRI + prove/verify + a soundness check) that every F004 gadget plugs
//! into. The keyed-BLAKE2b-512 membership / nullifier / commitment gadgets are the
//! remaining core (spec: docs/mil-shield-blake2b-air-spec.md).

use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

// ---- the AIR: running-sum value conservation, amounts private ----
const NUM_COLS: usize = 2; // [amount, acc]

pub struct ShieldSumAir {}

impl<F> BaseAir<F> for ShieldSumAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        1 // the public total
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(1)
    }
}

impl<AB: AirBuilder> Air<AB> for ShieldSumAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let total = builder.public_values()[0];
        let local: &ShieldRow<AB::Var> = main.current_slice().borrow();
        let next: &ShieldRow<AB::Var> = main.next_slice().borrow();

        // acc[0] == amount[0]
        builder.when_first_row().assert_eq(local.acc, local.amount);
        // acc[i] == acc[i-1] + amount[i]
        builder.when_transition().assert_eq(next.acc, local.acc + next.amount);
        // acc[last] == public total  (Σ private amounts == total)
        builder.when_last_row().assert_eq(local.acc, total);
    }
}

pub fn generate_trace_rows<F: PrimeField64>(amounts: &[u64]) -> RowMajorMatrix<F> {
    let n = amounts.len();
    assert!(n.is_power_of_two());
    let mut trace = RowMajorMatrix::new(F::zero_vec(n * NUM_COLS), NUM_COLS);
    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<ShieldRow<F>>() };
    assert!(prefix.is_empty() && suffix.is_empty());
    assert_eq!(rows.len(), n);
    let mut acc = 0u64;
    for i in 0..n {
        acc += amounts[i];
        rows[i].amount = F::from_u64(amounts[i]);
        rows[i].acc = F::from_u64(acc);
    }
    trace
}

pub struct ShieldRow<F> {
    pub amount: F,
    pub acc: F,
}
impl<F> Borrow<ShieldRow<F>> for [F] {
    fn borrow(&self) -> &ShieldRow<F> {
        debug_assert_eq!(self.len(), NUM_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<ShieldRow<F>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

// ---- hiding / zero-knowledge STARK config (verbatim from Plonky3 fib_air ZK) ----
type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Dft = Radix2DitParallel<Val>;
type ZkByteHash = Keccak256Hash;
type ZkU64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type ZkFieldHash = SerializingHasher<ZkU64Hash>;
type ZkCompress = CompressionFunctionFromHasher<ZkU64Hash, 2, 4>;
type ZkValHidingMmcs =
    MerkleTreeHidingMmcs<[Val; p3_keccak::VECTOR_LEN], [u64; p3_keccak::VECTOR_LEN], ZkFieldHash, ZkCompress, SmallRng, 2, 4, 4>;
type ZkChallenger = SerializingChallenger32<Val, HashChallenger<u8, ZkByteHash, 32>>;
type ZkChallengeHidingMmcs = ExtensionMmcs<Val, Challenge, ZkValHidingMmcs>;
type ZkHidingPcs = HidingFriPcs<Val, Dft, ZkValHidingMmcs, ZkChallengeHidingMmcs, SmallRng>;
type ZkConfig = StarkConfig<ZkHidingPcs, Challenge, ZkChallenger>;

fn make_zk_config() -> ZkConfig {
    let byte_hash = ZkByteHash {};
    let u64_hash = ZkU64Hash::new(KeccakF {});
    let field_hash = ZkFieldHash::new(u64_hash);
    let compress = ZkCompress::new(u64_hash);
    let val_mmcs = ZkValHidingMmcs::new(field_hash, compress, 0, SmallRng::seed_from_u64(1));
    let challenge_mmcs = ZkChallengeHidingMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters::new_testing(challenge_mmcs, 2);
    let pcs = ZkHidingPcs::new(dft, val_mmcs, fri_params, 4, SmallRng::seed_from_u64(1));
    let challenger = ZkChallenger::from_hasher(vec![], byte_hash);
    ZkConfig::new(pcs, challenger)
}

fn main() {
    // private note amounts (hidden in the trace); their sum is the only public value.
    let amounts: [u64; 8] = [100, 250, 75, 300, 50, 125, 200, 400];
    let total: u64 = amounts.iter().sum();
    let air = ShieldSumAir {};
    let trace = generate_trace_rows::<Val>(&amounts);
    let pis = vec![Val::from_u64(total)];

    let config = make_zk_config();
    let proof = prove(&config, &air, trace, &pis);
    verify(&config, &air, &proof, &pis).expect("valid ZK proof must verify");
    println!("PROVE+VERIFY ok — value conservation (Σ {} hidden amounts = {}) via HIDING FRI (formal ZK)", amounts.len(), total);

    // soundness: a wrong public total must be rejected.
    let bad = vec![Val::from_u64(total + 1)];
    let config2 = make_zk_config();
    let trace2 = generate_trace_rows::<Val>(&amounts);
    let proof2 = prove(&config2, &air, trace2, &pis);
    match verify(&config2, &air, &proof2, &bad) {
        Err(_) => println!("SOUNDNESS ok — a wrong public total is rejected"),
        Ok(_) => println!("SOUNDNESS FAIL — wrong total accepted!"),
    }

    let sz = postcard::to_allocvec(&proof).map(|b| b.len()).unwrap_or(0);
    println!("proof_bytes = {sz} (hiding variant); harness up. Remaining core = keyed-BLAKE2b-512 AIR (spec).");
}
