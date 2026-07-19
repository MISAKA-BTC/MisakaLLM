//! PALW on-chain registration payloads (ADR-0039 §9) — the TX payloads a miner submits to put its
//! minted leaves on-chain so an algo-4 ticket can reference them.
//!
//! This module covers the two producer-owned lifecycle payloads:
//!   * the **batch manifest** (`0x31`) — fixes the batch's content identity (`batch_id`), leaf/chunk
//!     counts, leaf-root commitment, and audit policy BEFORE the beacon (design §9.3);
//!   * the **leaf-chunk** payload (`0x32`) — the direct bridge from a [`crate::MintedLeaf`] to the
//!     on-chain [`PalwPublicLeafV1`] a validator resolves a ticket against.
//!
//! The **batch certificate** (`0x33`) is deliberately NOT here: it requires an AUDITOR QUORUM —
//! several independent auditors sample the batch, vote, and sign — which is a network role, built in
//! [`crate::audit`].

use kaspa_consensus_core::dns_finality::STAKE_VALIDATOR_PUBKEY_LEN;
use kaspa_consensus_core::palw::{
    PALW_MAX_LEAVES_PER_CHUNK, PALW_MAX_PROVIDER_CAPACITY_ENTRIES_V1, PALW_MAX_PROVIDER_RUNTIME_CLASSES_V1, PalwBatchManifestV1,
    PalwLeafChunkV1, PalwProviderBondPayloadV1, PalwPublicLeafV1, palw_leaf_root,
};
use kaspa_hashes::Hash64;

/// The `0x30` subnetwork byte a provider-bond PALW TX output carries (mirrors
/// `PalwTxKind::from_subnetwork_byte(0x30) == ProviderBond`).
pub const PROVIDER_BOND_SUBNETWORK_BYTE: u8 = 0x30;

/// The `0x31` subnetwork byte a batch-manifest PALW TX output carries (mirrors
/// `PalwTxKind::from_subnetwork_byte(0x31) == BatchManifest`).
pub const BATCH_MANIFEST_SUBNETWORK_BYTE: u8 = 0x31;

/// The `0x32` subnetwork byte a leaf-chunk PALW TX output carries (mirrors
/// `PalwTxKind::from_subnetwork_byte(0x32) == LeafChunk`).
pub const LEAF_CHUNK_SUBNETWORK_BYTE: u8 = 0x32;

/// Why a chunk or manifest could not be assembled.
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
    #[error("a batch manifest must fix 1..={max} leaves, got {got}")]
    BatchSize { got: usize, max: usize },
    #[error("degenerate batch policy: {0}")]
    Policy(&'static str),
    #[error("provider owner_public_key must be {expected} bytes (ML-DSA-87), got {got}")]
    ProviderPubkeyLen { got: usize, expected: usize },
    #[error("a provider must declare 1..={max} runtime classes, got {got}")]
    RuntimeClassCount { got: usize, max: usize },
    #[error("duplicate runtime class")]
    DuplicateRuntimeClass,
    #[error("a provider must declare 1..={max} shape-capacity entries, got {got}")]
    CapacityCount { got: usize, max: usize },
    #[error("a shape-capacity entry is duplicated or has zero capacity")]
    BadCapacityEntry,
    #[error("provider amount_sompi and unbond_delay_epochs must both be > 0")]
    ProviderAmounts,
    #[error("borsh encoding failed")]
    Encode,
}

/// The chain-params batch windows a manifest must satisfy at registration (ADR-0039 §9.2/§9.3). These
/// mirror the arguments of [`PalwBatchManifestV1::admission_valid`] — the producer computes the tightest
/// admissible epoch layout from them so the manifest passes BOTH the stateless `validate_manifest` and
/// the view-builder admission check.
#[derive(Clone, Debug)]
pub struct BatchPolicy {
    /// The epoch this manifest registers in (== the block's accept epoch; the miner cannot re-aim).
    pub registration_epoch: u64,
    /// Mandatory lead between registration and the earliest activation.
    pub registration_lead_epochs: u64,
    /// Audit budget included in the activation lead.
    pub audit_window_epochs: u64,
    /// Upper bound on the active window (`expiry - activation`).
    pub active_window_epochs: u64,
    /// Per-leaf economic floor; the manifest's `total_leaf_bond_sompi` must cover `leaf_count ×` this.
    pub min_leaf_bond_sompi: u64,
    /// Protocol cap on a batch's leaf count ([`PALW_MAX_BATCH_LEAVES_V1`]).
    pub max_batch_leaves: u32,
}

/// The batch-id-independent leaf commitment the manifest's `leaf_root` holds. Computed over each
/// leaf's `leaf_hash` with `batch_id` ZEROED, in canonical `leaf_index` order.
///
/// Zeroing `batch_id` is what makes the batch's content identity computable: `batch_id ==
/// content_id(manifest)` and `content_id` covers `leaf_root`, while every leaf carries `batch_id`.
/// Committing `leaf_root` to the leaves *including* their `batch_id` would therefore be a hash
/// fixed-point (`batch_id → leaf.batch_id → leaf_hash → leaf_root → content_id → batch_id`), which is
/// not solvable. `batch_id` is redundant inside the leaf commitment anyway — it is DERIVED from that
/// very commitment — so excluding it loses nothing. Consensus never recomputes `leaf_root` from the
/// stored leaves (neither the stateless `validate_manifest` nor `apply_manifest` reads it back), so
/// this is a producer-side content commitment for the audit layer, not a consensus-enforced binding.
pub fn manifest_leaf_root(leaves: &[PalwPublicLeafV1]) -> Hash64 {
    let mut ordered = leaves.to_vec();
    ordered.sort_by_key(|l| l.leaf_index);
    let hashes: Vec<Hash64> = ordered
        .iter()
        .map(|l| {
            let mut projected = l.clone();
            projected.batch_id = Hash64::default();
            projected.leaf_hash()
        })
        .collect();
    palw_leaf_root(&hashes)
}

/// Build a content-addressed [`PalwBatchManifestV1`] fixing `leaves` as a batch under `policy`, ready
/// to become a PALW TX output tagged [`BATCH_MANIFEST_SUBNETWORK_BYTE`]. Returns `(batch_id, (byte,
/// payload))`: the caller re-stamps its leaves with the returned content-derived `batch_id` and chunks
/// them via [`build_leaf_chunk`] (mining is deterministic over the job, so re-stamping only sets
/// `batch_id`; the batch-id-zeroed `leaf_root` is unchanged).
///
/// The result satisfies every check on a manifest: the stateless `validate_manifest` (version, leaf
/// count 1..=max, exact `chunk_count`, `registration < activation < expiry`), the `apply_manifest`
/// content-address guard (`batch_id == content_id`), and `admission_valid` (aggregate bond floor,
/// bounded active window, frozen registration epoch). `descriptor_root` / `audit_policy_id` are the
/// off-protocol batch descriptor + audit-policy commitments the caller supplies.
#[allow(clippy::too_many_arguments)]
pub fn build_batch_manifest(
    leaves: &[PalwPublicLeafV1],
    model_profile_id: Hash64,
    runtime_class_id: Hash64,
    descriptor_root: Hash64,
    audit_policy_id: Hash64,
    total_leaf_bond_sompi: u64,
    policy: &BatchPolicy,
) -> Result<(Hash64, (u8, Vec<u8>)), RegistrationError> {
    let leaf_count = leaves.len();
    if leaf_count == 0 || leaf_count > policy.max_batch_leaves as usize {
        return Err(RegistrationError::BatchSize { got: leaf_count, max: policy.max_batch_leaves as usize });
    }
    // registration < activation requires a non-zero lead; activation < expiry requires a non-zero
    // window. Both are protocol conditions (`validate_manifest` + `admission_valid`); a degenerate
    // policy cannot yield an admissible manifest.
    let lead = policy.registration_lead_epochs.saturating_add(policy.audit_window_epochs);
    if lead == 0 {
        return Err(RegistrationError::Policy("registration_lead_epochs + audit_window_epochs must be >= 1"));
    }
    if policy.active_window_epochs == 0 {
        return Err(RegistrationError::Policy("active_window_epochs must be >= 1"));
    }
    let activation = policy.registration_epoch.saturating_add(lead);
    let expiry = activation.saturating_add(policy.active_window_epochs);
    let leaf_root = manifest_leaf_root(leaves);
    let chunk_count = (leaf_count as u32).div_ceil(PALW_MAX_LEAVES_PER_CHUNK as u32) as u16;
    let mut m = PalwBatchManifestV1 {
        version: 1,
        batch_id: Hash64::default(),
        registration_epoch: policy.registration_epoch,
        model_profile_id,
        runtime_class_id,
        leaf_count: leaf_count as u32,
        chunk_count,
        leaf_root,
        descriptor_root,
        total_leaf_bond_sompi,
        audit_policy_id,
        activation_not_before_epoch: activation,
        expiry_epoch: expiry,
    };
    // Content-address the batch (§9.2): batch_id is the keyed hash of the manifest with batch_id zeroed.
    m.batch_id = m.content_id();
    let payload = borsh::to_vec(&m).map_err(|_| RegistrationError::Encode)?;
    Ok((m.batch_id, (BATCH_MANIFEST_SUBNETWORK_BYTE, payload)))
}

/// Re-stamp `leaves` with `batch_id` (the content-derived id from [`build_batch_manifest`]) so they
/// chunk under the batch's canonical key. Mining is deterministic over the job, so only `batch_id`
/// changes; the manifest's batch-id-zeroed `leaf_root` still commits to them.
pub fn restamp_leaves(batch_id: Hash64, leaves: &[PalwPublicLeafV1]) -> Vec<PalwPublicLeafV1> {
    leaves
        .iter()
        .cloned()
        .map(|mut l| {
            l.batch_id = batch_id;
            l
        })
        .collect()
}

/// Assemble a provider-bond payload (ADR-0039 §24.3) — the lifecycle's FIRST step: a GPU provider
/// registers its ML-DSA-87 identity, the runtime classes it can serve, and its per-shape capacity, so
/// its bond outpoint can later be referenced by a minted leaf's `provider_{a,b}_bond`. Ready to become
/// a PALW TX output tagged [`PROVIDER_BOND_SUBNETWORK_BYTE`].
///
/// Enforces exactly what `validate_provider_bond` requires: an ML-DSA-87 `owner_public_key`
/// ([`STAKE_VALIDATOR_PUBKEY_LEN`] bytes), 1..=64 strictly-ascending (hence distinct) runtime classes,
/// 1..=256 strictly-ascending shape entries each with non-zero capacity, and a non-zero bond amount +
/// unbond delay. `runtime_classes` / `capacity_by_shape` are sorted here, so the caller may pass them
/// in any order.
#[allow(clippy::too_many_arguments)]
pub fn build_provider_bond(
    owner_public_key: Vec<u8>,
    operator_group_id: Hash64,
    mut runtime_classes: Vec<Hash64>,
    mut capacity_by_shape: Vec<(u16, u32)>,
    reward_key_root: Hash64,
    amount_sompi: u64,
    unbond_delay_epochs: u64,
) -> Result<(u8, Vec<u8>), RegistrationError> {
    if owner_public_key.len() != STAKE_VALIDATOR_PUBKEY_LEN {
        return Err(RegistrationError::ProviderPubkeyLen { got: owner_public_key.len(), expected: STAKE_VALIDATOR_PUBKEY_LEN });
    }
    if runtime_classes.is_empty() || runtime_classes.len() > PALW_MAX_PROVIDER_RUNTIME_CLASSES_V1 {
        return Err(RegistrationError::RuntimeClassCount { got: runtime_classes.len(), max: PALW_MAX_PROVIDER_RUNTIME_CLASSES_V1 });
    }
    runtime_classes.sort_by(|a, b| a.as_byte_slice().cmp(b.as_byte_slice()));
    if runtime_classes.windows(2).any(|w| w[0] == w[1]) {
        return Err(RegistrationError::DuplicateRuntimeClass);
    }
    if capacity_by_shape.is_empty() || capacity_by_shape.len() > PALW_MAX_PROVIDER_CAPACITY_ENTRIES_V1 {
        return Err(RegistrationError::CapacityCount { got: capacity_by_shape.len(), max: PALW_MAX_PROVIDER_CAPACITY_ENTRIES_V1 });
    }
    capacity_by_shape.sort_by_key(|(shape, _)| *shape);
    if capacity_by_shape.windows(2).any(|w| w[0].0 == w[1].0) || capacity_by_shape.iter().any(|(_, c)| *c == 0) {
        return Err(RegistrationError::BadCapacityEntry);
    }
    if amount_sompi == 0 || unbond_delay_epochs == 0 {
        return Err(RegistrationError::ProviderAmounts);
    }
    let bond = PalwProviderBondPayloadV1 {
        version: 1,
        owner_public_key,
        operator_group_id,
        runtime_classes,
        capacity_by_shape,
        reward_key_root,
        amount_sompi,
        unbond_delay_epochs,
    };
    let payload = borsh::to_vec(&bond).map_err(|_| RegistrationError::Encode)?;
    Ok((PROVIDER_BOND_SUBNETWORK_BYTE, payload))
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

    fn policy() -> BatchPolicy {
        BatchPolicy {
            registration_epoch: 5,
            registration_lead_epochs: 2,
            audit_window_epochs: 1,
            active_window_epochs: 100,
            min_leaf_bond_sompi: 0,
            max_batch_leaves: kaspa_consensus_core::palw::PALW_MAX_BATCH_LEAVES_V1 as u32,
        }
    }

    #[test]
    fn a_manifest_over_minted_leaves_is_content_addressed_and_admissible() {
        use kaspa_consensus_core::palw::{PALW_MAX_LEAVES_PER_CHUNK, PalwBatchManifestV1};
        let m = miner();
        // Mine two leaves under a PLACEHOLDER batch id — the real content-derived id is not known yet.
        let minted = vec![mine(&m, Hash64::default(), 0, 0xC0), mine(&m, Hash64::default(), 1, 0xC1)];
        let pol = policy();
        let (batch_id, (byte, payload)) = build_batch_manifest(&minted, h(1), h(2), h(3), h(4), 0, &pol).expect("manifest builds");
        assert_eq!(byte, BATCH_MANIFEST_SUBNETWORK_BYTE);

        // The stateless body/mempool validator accepts it.
        assert_eq!(validate_palw_overlay_payload(byte, &payload), Ok(()));

        // It is genuinely content-addressed (the `apply_manifest` store guard) and view-admissible.
        let decoded: PalwBatchManifestV1 = borsh::from_slice(&payload).unwrap();
        assert_eq!(decoded.batch_id, batch_id);
        assert!(decoded.batch_id_is_content_derived(), "batch_id must equal its own content id");
        assert!(
            decoded.admission_valid(
                pol.registration_epoch,
                pol.max_batch_leaves,
                PALW_MAX_LEAVES_PER_CHUNK as u16,
                pol.registration_lead_epochs,
                pol.active_window_epochs,
                pol.audit_window_epochs,
                pol.min_leaf_bond_sompi,
            ),
            "the manifest must satisfy the full view-builder admission predicate"
        );
    }

    #[test]
    fn manifest_then_restamped_leaf_chunk_both_validate_under_one_batch_id() {
        let m = miner();
        let minted = vec![mine(&m, Hash64::default(), 0, 0xC0), mine(&m, Hash64::default(), 1, 0xC1)];
        let (batch_id, (mbyte, mpayload)) =
            build_batch_manifest(&minted, h(1), h(2), h(3), h(4), 0, &policy()).expect("manifest builds");

        // Re-stamp the leaves with the content-derived id and chunk them under it.
        let restamped = restamp_leaves(batch_id, &minted);
        let (cbyte, cpayload) = build_leaf_chunk(batch_id, 0, restamped).expect("chunk assembles");

        // Both the manifest and the leaf chunk pass the stateless validator under ONE batch id — the
        // leaves resolve under the manifest's content-addressed key.
        assert_eq!(validate_palw_overlay_payload(mbyte, &mpayload), Ok(()));
        assert_eq!(validate_palw_overlay_payload(cbyte, &cpayload), Ok(()));
    }

    #[test]
    fn degenerate_policy_and_empty_batch_are_rejected() {
        let m = miner();
        let minted = vec![mine(&m, Hash64::default(), 0, 0xC0)];
        // Empty batch.
        assert!(matches!(
            build_batch_manifest(&[], h(1), h(2), h(3), h(4), 0, &policy()).unwrap_err(),
            RegistrationError::BatchSize { got: 0, .. }
        ));
        // Zero activation lead ⇒ registration == activation ⇒ not admissible.
        let bad_lead = BatchPolicy { registration_lead_epochs: 0, audit_window_epochs: 0, ..policy() };
        assert_eq!(
            build_batch_manifest(&minted, h(1), h(2), h(3), h(4), 0, &bad_lead).unwrap_err(),
            RegistrationError::Policy("registration_lead_epochs + audit_window_epochs must be >= 1")
        );
        // Zero active window ⇒ activation == expiry ⇒ not admissible.
        let bad_window = BatchPolicy { active_window_epochs: 0, ..policy() };
        assert_eq!(
            build_batch_manifest(&minted, h(1), h(2), h(3), h(4), 0, &bad_window).unwrap_err(),
            RegistrationError::Policy("active_window_epochs must be >= 1")
        );
    }

    #[test]
    fn a_provider_bond_over_a_real_mldsa_key_passes_the_stateless_validator() {
        use kaspa_pq_validator_core::ValidatorKey;
        let pubkey = ValidatorKey::from_seed([0x2C; 32]).public_key().to_vec();
        // Runtime classes + shape entries fed OUT of order to prove the producer sorts them.
        let (byte, payload) =
            build_provider_bond(pubkey, h(0xA0), vec![h(3), h(1), h(2)], vec![(7, 4), (2, 1), (5, 2)], h(0xB0), 1_000, 10)
                .expect("provider bond assembles");
        assert_eq!(byte, PROVIDER_BOND_SUBNETWORK_BYTE);
        // The exact stateless check the mempool / body validator runs accepts it.
        assert_eq!(validate_palw_overlay_payload(byte, &payload), Ok(()));
    }

    #[test]
    fn provider_bond_rejects_bad_pubkey_zero_capacity_and_amounts() {
        use kaspa_pq_validator_core::ValidatorKey;
        let pubkey = ValidatorKey::from_seed([0x2C; 32]).public_key().to_vec();
        // Wrong pubkey length.
        assert!(matches!(
            build_provider_bond(vec![0u8; 10], h(0xA0), vec![h(1)], vec![(1, 1)], h(0xB0), 1, 1).unwrap_err(),
            RegistrationError::ProviderPubkeyLen { got: 10, .. }
        ));
        // Zero-capacity shape entry.
        assert_eq!(
            build_provider_bond(pubkey.clone(), h(0xA0), vec![h(1)], vec![(1, 0)], h(0xB0), 1, 1).unwrap_err(),
            RegistrationError::BadCapacityEntry
        );
        // Duplicate runtime class.
        assert_eq!(
            build_provider_bond(pubkey.clone(), h(0xA0), vec![h(1), h(1)], vec![(1, 1)], h(0xB0), 1, 1).unwrap_err(),
            RegistrationError::DuplicateRuntimeClass
        );
        // Zero amount.
        assert_eq!(
            build_provider_bond(pubkey, h(0xA0), vec![h(1)], vec![(1, 1)], h(0xB0), 0, 1).unwrap_err(),
            RegistrationError::ProviderAmounts
        );
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
