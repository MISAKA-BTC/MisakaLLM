//! PALW on-chain registration payloads (ADR-0039 §9) — the TX payloads a miner submits to put its
//! minted leaves on-chain so an algo-4 ticket can reference them.
//!
//! This phase covers the **leaf-chunk** payload (subnetwork byte `0x32`): the direct bridge from a
//! [`crate::MintedLeaf`] to the on-chain [`PalwPublicLeafV1`] a validator resolves a ticket against.
//! The remaining lifecycle steps are deliberately NOT here:
//!   * the **batch manifest** (`0x31`) commits the leaf merkle root + audit policy;
//!   * the **batch certificate** (`0x33`) requires an AUDITOR QUORUM — several independent auditors
//!     sample the batch, vote, and sign — which is a network role, not something a single node
//!     produces on its own.
//! They are built (with the self-audit / single-operator quorum option) in a later phase.

use kaspa_consensus_core::palw::{PALW_MAX_LEAVES_PER_CHUNK, PalwLeafChunkV1, PalwPublicLeafV1};
use kaspa_hashes::Hash64;

/// The `0x32` subnetwork byte a leaf-chunk PALW TX output carries (mirrors
/// `PalwTxKind::from_subnetwork_byte(0x32) == LeafChunk`).
pub const LEAF_CHUNK_SUBNETWORK_BYTE: u8 = 0x32;

/// Why a chunk could not be assembled.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegistrationError {
    #[error("a leaf chunk must carry 1..={max} leaves, got {got}")]
    ChunkSize { got: usize, max: usize },
    #[error("leaf {0} has a different batch_id than the chunk")]
    BatchIdMismatch(u32),
    #[error("two leaves share leaf_index {0}")]
    DuplicateLeafIndex(u32),
    #[error("two leaves share a ticket-nullifier commitment")]
    DuplicateNullifier,
    #[error("borsh encoding failed")]
    Encode,
}

/// Assemble a leaf-chunk payload registering `leaves` for `batch_id` under `chunk_index`, ready to
/// become a PALW TX output tagged [`LEAF_CHUNK_SUBNETWORK_BYTE`].
///
/// Enforces exactly what `validate_leaf_chunk` requires: 1..=64 leaves, every leaf's `batch_id`
/// equal to the chunk's, strictly-increasing (hence distinct) `leaf_index`, and distinct
/// ticket-nullifier commitments (I-13). The individual leaves must already be valid
/// `PalwPublicLeafV1` (the miner mints them so; the validator re-checks proof_type / bonds / reward
/// scripts / epoch range). Returns `(subnetwork_byte, borsh(chunk))`.
pub fn build_leaf_chunk(
    batch_id: Hash64,
    chunk_index: u16,
    mut leaves: Vec<PalwPublicLeafV1>,
) -> Result<(u8, Vec<u8>), RegistrationError> {
    if leaves.is_empty() || leaves.len() > PALW_MAX_LEAVES_PER_CHUNK {
        return Err(RegistrationError::ChunkSize { got: leaves.len(), max: PALW_MAX_LEAVES_PER_CHUNK });
    }
    for l in &leaves {
        if l.batch_id != batch_id {
            return Err(RegistrationError::BatchIdMismatch(l.leaf_index));
        }
    }
    leaves.sort_by_key(|l| l.leaf_index);
    if let Some(w) = leaves.windows(2).find(|w| w[0].leaf_index == w[1].leaf_index) {
        return Err(RegistrationError::DuplicateLeafIndex(w[0].leaf_index));
    }
    let mut seen = std::collections::HashSet::with_capacity(leaves.len());
    for l in &leaves {
        if !seen.insert(l.ticket_nullifier_commitment) {
            return Err(RegistrationError::DuplicateNullifier);
        }
    }
    let chunk = PalwLeafChunkV1 { version: 1, batch_id, chunk_index, leaves };
    let payload = borsh::to_vec(&chunk).map_err(|_| RegistrationError::Encode)?;
    Ok((LEAF_CHUNK_SUBNETWORK_BYTE, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MiningJob, PalwMiner, ProviderRegistration};
    use kaspa_consensus_core::palw::validate_palw_overlay_payload;
    use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec, TransactionOutpoint};
    use misaka_palw::palw::{PalwRuntimeProfileV1, PalwSamplingParams, PalwTier};
    use misaka_palw::palw_replica::MockDeterministicRuntime;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    fn profile() -> PalwRuntimeProfileV1 {
        PalwRuntimeProfileV1 {
            version: 1,
            tier: PalwTier::Quality,
            model_id: PalwTier::Quality.model_id(),
            tokenizer_hash: h(1),
            quantization_manifest_hash: h(2),
            runtime_image_hash: h(3),
            kernel_graph_hash: h(4),
            operation_table_hash: h(5),
            shape_table_hash: h(6),
            gpu_arch_class: 100,
            tensor_parallel_degree: 1,
            pipeline_parallel_degree: 1,
            deterministic_reduction: true,
            batch_invariant: true,
            speculative_decode: false,
            sampling: PalwSamplingParams::greedy(),
        }
    }

    fn miner() -> PalwMiner<MockDeterministicRuntime, MockDeterministicRuntime> {
        let spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&[1]));
        PalwMiner::new(
            MockDeterministicRuntime::new(profile(), 3, 2),
            MockDeterministicRuntime::new(profile(), 3, 2),
            ProviderRegistration {
                provider_a_bond: TransactionOutpoint::new(h(6), 0),
                provider_b_bond: TransactionOutpoint::new(h(7), 0),
                provider_a_reward_script: spk.clone(),
                provider_b_reward_script: spk,
                ticket_authority_pk_hash: h(8),
                registered_epoch: 3,
                activation_epoch: 4,
                expiry_epoch: 1000,
                leaf_bond_sompi: 0,
            },
        )
    }

    fn mine(m: &PalwMiner<MockDeterministicRuntime, MockDeterministicRuntime>, batch: Hash64, idx: u32, nf: u8) -> PalwPublicLeafV1 {
        m.produce_leaf(&MiningJob {
            batch_id: batch,
            leaf_index: idx,
            job_set_descriptor: vec![idx as u8],
            prompt: format!("prompt {idx}").into_bytes(),
            output_salt: [0x33; 32],
            job_nullifier: h(0x20 + idx as u8),
            raw_ticket_nullifier: h(nf),
        })
        .unwrap()
        .leaf
    }

    #[test]
    fn a_chunk_of_miner_minted_leaves_passes_the_stateless_validator() {
        let m = miner();
        let batch = h(0x10);
        // Two distinct leaves (distinct index + distinct raw nullifier ⇒ distinct commitment). Feed them
        // out of order to prove the producer sorts.
        let leaves = vec![mine(&m, batch, 1, 0xC1), mine(&m, batch, 0, 0xC0)];
        let (byte, payload) = build_leaf_chunk(batch, 0, leaves).expect("chunk assembles");
        assert_eq!(byte, LEAF_CHUNK_SUBNETWORK_BYTE);
        // The exact stateless check the mempool / body validator runs accepts it.
        assert_eq!(validate_palw_overlay_payload(byte, &payload), Ok(()));
    }

    #[test]
    fn wrong_batch_id_and_duplicates_are_rejected() {
        let m = miner();
        let batch = h(0x10);
        // A leaf minted under a DIFFERENT batch id can't go into this chunk.
        let foreign = mine(&m, h(0x99), 0, 0xC0);
        assert_eq!(build_leaf_chunk(batch, 0, vec![foreign]).unwrap_err(), RegistrationError::BatchIdMismatch(0));
        // Two leaves sharing a raw nullifier ⇒ same commitment ⇒ rejected.
        let dup = vec![mine(&m, batch, 0, 0xC0), mine(&m, batch, 1, 0xC0)];
        assert_eq!(build_leaf_chunk(batch, 0, dup).unwrap_err(), RegistrationError::DuplicateNullifier);
        // Empty chunk is rejected.
        assert!(matches!(build_leaf_chunk(batch, 0, vec![]).unwrap_err(), RegistrationError::ChunkSize { got: 0, .. }));
    }
}
