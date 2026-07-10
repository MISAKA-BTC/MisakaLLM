//! §SP-0 measured cap bench (ADR-0035): a real Circle-STARK (M31) proof of N
//! Keccak-f permutations — the unfriendly-hash proxy for keyed BLAKE2b — with the
//! serialized proof size measured via postcard (Plonky3's own proof serializer).
//!
//! args: NUM_HASHES [num_queries] [log_blowup] [query_pow_bits]
//! prints: CAPBENCH n_hashes=.. rows=.. pad2=.. log_blowup=.. num_queries=..
//!         query_pow=.. sec_bits~=.. proof_bytes=.. proof_kib=..

use core::fmt::Debug;
use core::marker::PhantomData;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::FriParameters;
use p3_keccak_air::{KeccakAir, NUM_ROUNDS, generate_trace_rows};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

fn main() -> Result<(), impl Debug> {
    let mut args = std::env::args().skip(1);
    let num_hashes: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(106);
    let num_queries: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(100);
    let log_blowup: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    let query_pow: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(16);

    type Val = Mersenne31;
    type Challenge = BinomialExtensionField<Val, 3>;

    type ByteHash = Sha256;
    type FieldHash = SerializingHasher<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Sha256);

    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);

    type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 2, 32>;
    let val_mmcs = ValMmcs::new(field_hash, compress, 3);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::from_hasher(vec![], byte_hash);

    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: query_pow,
        mmcs: challenge_mmcs,
    };

    let mut rng = SmallRng::seed_from_u64(1);
    let inputs = (0..num_hashes).map(|_| rng.random()).collect::<Vec<_>>();
    let trace = generate_trace_rows::<Val>(inputs, fri_params.log_blowup);

    type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs { mmcs: val_mmcs, fri_params, _phantom: PhantomData };

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs, challenger);

    let proof = prove(&config, &KeccakAir {}, trace, &[]);
    let bytes = postcard::to_allocvec(&proof).expect("serialize proof");

    let rows = num_hashes * NUM_ROUNDS;
    let pad2 = rows.next_power_of_two();
    let sec = num_queries * log_blowup + query_pow;
    println!(
        "CAPBENCH n_hashes={num_hashes} rows={rows} pad2={pad2} log_blowup={log_blowup} num_queries={num_queries} query_pow={query_pow} sec_bits~={sec} proof_bytes={} proof_kib={:.2}",
        bytes.len(),
        bytes.len() as f64 / 1024.0
    );

    verify(&config, &KeccakAir {}, &proof, &[])
}
