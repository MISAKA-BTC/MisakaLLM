//! Offline DA-01 operator tooling. No RPC or mutable node state is touched here.

use borsh::BorshDeserialize;
use clap::Parser;
use kaspa_consensus_core::Hash64;
use kaspa_consensus_core::palw::da::{
    PALW_DA_MAX_OBJECT_BYTES, palw_receipt_da_chunk_proof, palw_receipt_da_commitment, palw_receipt_da_object_bytes,
};
use kaspa_consensus_core::palw::{da::PalwReceiptDaObjectV1, validate_palw_overlay_payload};
use kaspa_pq_validator_core::{ValidatorKey, load_validator_seed, parse_stake_bond_ref};
use misaka_palw_miner::da::{
    build_da_timeout_evidence, build_signed_da_challenge, build_signed_da_response, encode_da_challenge, encode_da_response,
    encode_da_timeout,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

use super::{parse_hash64, write_new_payload};

#[derive(Parser, Debug)]
pub struct DaInspectArgs {
    /// Canonical Borsh `PalwReceiptDaObjectV1` produced by the LLM/miner receipt path.
    #[arg(long)]
    object_file: PathBuf,
    /// Optional fixed chunk index whose Merkle proof should be exported.
    #[arg(long, requires = "proof_out")]
    chunk_index: Option<u16>,
    /// New file receiving Borsh `PalwReceiptDaChunkProofV1`; requires --chunk-index.
    #[arg(long, requires = "chunk_index")]
    proof_out: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct DaChallengePayloadArgs {
    /// Consensus PALW network-domain u32 (must match the node's configured `palw_network_id`).
    #[arg(long)]
    network_id: u32,
    #[arg(long, value_parser = parse_hash64)]
    obligation_id: Hash64,
    #[arg(long)]
    challenge_epoch: u64,
    #[arg(long)]
    opened_daa_score: u64,
    #[arg(long, default_value_t = 200)]
    response_window_daa: u64,
    /// Active challenger provider bond, `txid:index`.
    #[arg(long)]
    challenger_bond: String,
    /// ML-DSA-87 seed for the challenger bond owner.
    #[arg(long, env = "KASPA_PQ_VALIDATOR_KEY")]
    owner_key: String,
    #[arg(long, value_parser = parse_hash64)]
    challenge_nonce: Hash64,
    /// New file receiving the canonical 0x3a payload.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Parser, Debug)]
pub struct DaResponsePayloadArgs {
    #[arg(long)]
    network_id: u32,
    #[arg(long, value_parser = parse_hash64)]
    challenge_id: Hash64,
    /// Challenged provider bond, `txid:index`.
    #[arg(long)]
    provider_bond: String,
    /// ML-DSA-87 seed for the challenged provider bond owner (not the hot session key).
    #[arg(long, env = "KASPA_PQ_VALIDATOR_KEY")]
    owner_key: String,
    #[arg(long)]
    object_file: PathBuf,
    #[arg(long)]
    chunk_index: u16,
    /// New file receiving the canonical 0x3b payload.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Parser, Debug)]
pub struct DaTimeoutPayloadArgs {
    #[arg(long)]
    network_id: u32,
    #[arg(long, value_parser = parse_hash64)]
    challenge_id: Hash64,
    /// Provider bond named by the expired challenge, `txid:index`.
    #[arg(long)]
    provider_bond: String,
    /// New file receiving the canonical 0x3c payload.
    #[arg(long)]
    out: PathBuf,
}

fn read_bounded_object(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("cannot stat DA object '{}': {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("DA object '{}' is not a regular file", path.display()));
    }
    let len = usize::try_from(metadata.len()).map_err(|_| "DA object length does not fit usize".to_string())?;
    if len == 0 || len > PALW_DA_MAX_OBJECT_BYTES {
        return Err(format!("DA object is {len} bytes; required range is 1..={PALW_DA_MAX_OBJECT_BYTES}"));
    }
    fs::read(path).map_err(|error| format!("cannot read DA object '{}': {error}", path.display()))
}

fn decode_canonical_object(path: &Path) -> Result<(PalwReceiptDaObjectV1, Vec<u8>), String> {
    let bytes = read_bounded_object(path)?;
    let object =
        PalwReceiptDaObjectV1::try_from_slice(&bytes).map_err(|_| "DA object is not canonical Borsh object-v1".to_string())?;
    let canonical = palw_receipt_da_object_bytes(&object).map_err(|error| format!("invalid DA object: {error}"))?;
    if canonical != bytes {
        return Err("DA object has a non-canonical/trailing byte representation".to_string());
    }
    Ok((object, bytes))
}

fn load_key(path: &str) -> Result<ValidatorKey, String> {
    let mut seed = load_validator_seed(path)?;
    let key = ValidatorKey::from_seed(seed);
    seed.fill(0);
    std::hint::black_box(&seed);
    Ok(key)
}

fn write_da_payload(path: &Path, subnetwork_byte: u8, payload: &[u8]) -> Result<(), String> {
    validate_palw_overlay_payload(subnetwork_byte, payload)
        .map_err(|error| format!("built 0x{subnetwork_byte:02x} payload failed consensus stateless validation: {error}"))?;
    write_new_payload(path, payload)
}

pub fn da_inspect(args: DaInspectArgs) -> Result<(), String> {
    let (object, bytes) = decode_canonical_object(&args.object_file)?;
    let commitment =
        palw_receipt_da_commitment(object.version, &bytes).map_err(|error| format!("cannot commit DA object: {error}"))?;
    println!("object_version: {}", object.version);
    println!("object_root: {}", commitment.root);
    println!("object_bytes: {}", commitment.object_len);
    println!("chunk_count: {}", commitment.chunk_count);
    println!("network_id: {}", object.network_id);
    println!("batch_id: {}", object.batch_id);
    println!("leaf_index: {}", object.leaf_index);
    println!("provider_a_bond: {}", object.receipt_a.provider_bond);
    println!("provider_b_bond: {}", object.receipt_b.provider_bond);
    println!(
        "embedded_receipt_roots_zero: {}",
        object.receipt_a.receipt_da_root == Hash64::default() && object.receipt_b.receipt_da_root == Hash64::default()
    );

    if let (Some(chunk_index), Some(proof_out)) = (args.chunk_index, args.proof_out) {
        let proof = palw_receipt_da_chunk_proof(object.version, &bytes, chunk_index)
            .map_err(|error| format!("cannot build chunk proof: {error}"))?;
        let proof_bytes = borsh::to_vec(&proof).map_err(|_| "cannot encode chunk proof".to_string())?;
        write_new_payload(&proof_out, &proof_bytes)?;
        println!("proof_file: {}", proof_out.display());
        println!("proof_chunk_index: {chunk_index}");
    }
    Ok(())
}

pub fn da_challenge_payload(args: DaChallengePayloadArgs) -> Result<(), String> {
    let owner_key = load_key(&args.owner_key)?;
    let challenger_bond = parse_stake_bond_ref(&args.challenger_bond)?;
    let challenge = build_signed_da_challenge(
        args.network_id,
        args.obligation_id,
        args.challenge_epoch,
        args.opened_daa_score,
        args.response_window_daa,
        challenger_bond,
        &owner_key,
        args.challenge_nonce,
    )
    .map_err(|error| format!("cannot build DA challenge: {error}"))?;
    let (subnetwork, payload) = encode_da_challenge(&challenge).map_err(|error| error.to_string())?;
    write_da_payload(&args.out, subnetwork, &payload)?;
    println!("payload_kind: da-challenge");
    println!("subnetwork_byte: 0x{subnetwork:02x}");
    println!("challenge_id: {}", challenge.challenge_id());
    println!("response_deadline_daa_score: {}", challenge.response_deadline_daa_score);
    println!("payload_file: {}", args.out.display());
    Ok(())
}

pub fn da_response_payload(args: DaResponsePayloadArgs) -> Result<(), String> {
    let owner_key = load_key(&args.owner_key)?;
    let provider_bond = parse_stake_bond_ref(&args.provider_bond)?;
    let (_, object_bytes) = decode_canonical_object(&args.object_file)?;
    let response =
        build_signed_da_response(args.network_id, args.challenge_id, provider_bond, &owner_key, &object_bytes, args.chunk_index)
            .map_err(|error| format!("cannot build DA response: {error}"))?;
    let (subnetwork, payload) = encode_da_response(&response).map_err(|error| error.to_string())?;
    write_da_payload(&args.out, subnetwork, &payload)?;
    println!("payload_kind: da-response");
    println!("subnetwork_byte: 0x{subnetwork:02x}");
    println!("response_id: {}", response.response_id());
    println!("chunk_index: {}", response.chunk_proof.chunk_index);
    println!("payload_file: {}", args.out.display());
    Ok(())
}

pub fn da_timeout_payload(args: DaTimeoutPayloadArgs) -> Result<(), String> {
    let provider_bond = parse_stake_bond_ref(&args.provider_bond)?;
    let evidence = build_da_timeout_evidence(args.network_id, args.challenge_id, provider_bond);
    let (subnetwork, payload) = encode_da_timeout(&evidence).map_err(|error| error.to_string())?;
    write_da_payload(&args.out, subnetwork, &payload)?;
    println!("payload_kind: da-timeout");
    println!("subnetwork_byte: 0x{subnetwork:02x}");
    println!("evidence_id: {}", evidence.evidence_id());
    println!("payload_file: {}", args.out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn da_operator_subcommands_have_strict_required_shapes() {
        let hash = "11".repeat(64);
        let bond = format!("{hash}:0");
        assert!(DaInspectArgs::try_parse_from(["da-inspect", "--object-file", "object.borsh"]).is_ok());
        assert!(DaInspectArgs::try_parse_from(["da-inspect", "--object-file", "object.borsh", "--chunk-index", "0"]).is_err());
        assert!(
            DaTimeoutPayloadArgs::try_parse_from([
                "da-timeout",
                "--network-id",
                "111",
                "--challenge-id",
                &hash,
                "--provider-bond",
                &bond,
                "--out",
                "timeout.borsh",
            ])
            .is_ok()
        );
    }
}
