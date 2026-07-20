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
    PALW_LEAF_CHUNK_VERSION_V2, PALW_MAX_BATCH_LEAVES_V1, PALW_MAX_LEAVES_PER_CHUNK, PALW_MAX_PROVIDER_CAPACITY_ENTRIES_V1,
    PALW_MAX_PROVIDER_RUNTIME_CLASSES_V1, PalwBatchManifestV1, PalwLeafChunkV1, PalwProviderBondPayloadV1, PalwPublicLeafV1,
    palw_leaf_merkle_proof, palw_leaf_merkle_root,
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
    /// kaspa-pq ADR-0040 §5.15.4 — the Merkle leaf node binds the leaf's POSITION
    /// (`Hash64_k(leaf-merkle-leaf, i_le32 ‖ leaf_hash)`), and the acceptance-coordinate verifier feeds
    /// it `leaf.leaf_index`. So a batch whose `leaf_index` set is not exactly `0..leaf_count` produces a
    /// root the verifier can never reproduce — the silent divergence §5.15.9 exists to prevent. Rejected
    /// HERE, at the only place that fixes a batch's identity, rather than discovered on-chain.
    #[error("batch leaf_index set must be exactly 0..{leaf_count}; index {got} breaks the sequence")]
    NonContiguousLeafIndices { got: u32, leaf_count: u32 },
    /// A batch of `n` leaves has exactly `ceil(n / PALW_MAX_LEAVES_PER_CHUNK)` chunks — the same
    /// `chunk_count` [`build_batch_manifest`] writes into the manifest and `validate_manifest` re-derives.
    #[error("chunk_index {got} is outside the batch's {chunk_count} chunks")]
    ChunkIndexOutOfRange { got: u16, chunk_count: u16 },
    /// kaspa-pq ADR-0040 §5.14.3 item 7 — the acceptance coordinate refuses a leaf whose
    /// `registered_epoch` is not its manifest's `registration_epoch`
    /// (`PalwOverlayError::LeafRegistrationEpochMismatch`). Caught HERE because `build_batch_manifest` is
    /// the point where the two numbers first meet: past this call `registration_epoch` is inside
    /// `content_id()` and `registered_epoch` is inside `leaf_root`, so a mismatched batch is frozen —
    /// its id is final, its leaves cannot be restamped without changing that id, and every chunk it can
    /// ever emit is rejected on-chain. Failing at construction is the difference between a producer bug
    /// and an unusable batch that already paid its registration fee.
    #[error("leaf {leaf_index} is registered at epoch {got}, but the batch registers at epoch {expected}")]
    LeafRegistrationEpochMismatch { leaf_index: u32, got: u64, expected: u64 },
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
///
/// **CORRECTED — kaspa-pq ADR-0040 §5.15 (ACCEPT-BIND/M2).** The last sentence above is now FALSE and is
/// kept only to mark what changed. `leaf_root` is a uniform-depth MERKLE root
/// ([`palw_leaf_merkle_root`]), and the acceptance coordinate verifies a per-leaf membership proof
/// against `manifest.leaf_root` BEFORE storing any leaf. It is a consensus-enforced binding.
///
/// Returns [`RegistrationError::NonContiguousLeafIndices`] unless the batch's `leaf_index` set is
/// exactly `0..leaf_count` — see that variant for why the producer cannot be lenient here.
pub fn manifest_leaf_root(leaves: &[PalwPublicLeafV1]) -> Result<Hash64, RegistrationError> {
    Ok(palw_leaf_merkle_root(&ordered_batch_leaf_hashes(leaves)?))
}

/// The batch's ordered, `batch_id`-zeroed leaf hashes — the exact `&[Hash64]` slice both
/// [`palw_leaf_merkle_root`] and [`palw_leaf_merkle_proof`] consume, so a root and the proofs that open
/// it can never be built over different sequences.
///
/// Enforces that the sorted `leaf_index` sequence is exactly `0..n`, which is what makes array POSITION
/// (used by the Merkle construction) and `leaf.leaf_index` (used by the consensus verifier) the same
/// number. Also rejects an empty or over-cap batch, since `palw_leaf_merkle_depth` is only bounded by
/// [`kaspa_consensus_core::palw::PALW_MAX_LEAF_MEMBERSHIP_PROOF_LEN`] up to
/// [`PALW_MAX_BATCH_LEAVES_V1`].
fn ordered_batch_leaf_hashes(leaves: &[PalwPublicLeafV1]) -> Result<Vec<Hash64>, RegistrationError> {
    if leaves.is_empty() || leaves.len() > PALW_MAX_BATCH_LEAVES_V1 {
        return Err(RegistrationError::BatchSize { got: leaves.len(), max: PALW_MAX_BATCH_LEAVES_V1 });
    }
    let mut ordered = leaves.to_vec();
    ordered.sort_by_key(|l| l.leaf_index);
    let leaf_count = ordered.len() as u32;
    for (position, l) in ordered.iter().enumerate() {
        if l.leaf_index != position as u32 {
            return Err(RegistrationError::NonContiguousLeafIndices { got: l.leaf_index, leaf_count });
        }
    }
    Ok(ordered
        .iter()
        .map(|l| {
            let mut projected = l.clone();
            projected.batch_id = Hash64::default();
            projected.leaf_hash()
        })
        .collect())
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
    // kaspa-pq ADR-0040 §5.14.3 item 7 — mirror of the acceptance-coordinate rule. Checked BEFORE
    // `manifest_leaf_root`, because after that call the mismatch is baked into `batch_id` and the batch is
    // unusable rather than merely wrong.
    for l in leaves.iter() {
        if l.registered_epoch != policy.registration_epoch {
            return Err(RegistrationError::LeafRegistrationEpochMismatch {
                leaf_index: l.leaf_index,
                got: l.registered_epoch,
                expected: policy.registration_epoch,
            });
        }
    }
    let activation = policy.registration_epoch.saturating_add(lead);
    let expiry = activation.saturating_add(policy.active_window_epochs);
    let leaf_root = manifest_leaf_root(leaves)?;
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

/// Assemble the `chunk_index`-th leaf-chunk payload of the batch `batch_leaves` forms under
/// `batch_id`, ready to become a PALW TX output tagged [`LEAF_CHUNK_SUBNETWORK_BYTE`].
///
/// **kaspa-pq ADR-0040 §5.15.9 step (iii) — this now takes the WHOLE batch, not a caller-chosen
/// subset.** A v2 chunk carries one [`kaspa_consensus_core::palw::PalwLeafMembershipProofV1`] per leaf,
/// and a membership proof only exists relative to the complete ordered leaf set the manifest's
/// `leaf_root` was built from. The previous signature — arbitrary `Vec<PalwPublicLeafV1>` plus an
/// arbitrary `chunk_index`, with no tie back to the manifest (§5.15.6 records this as the defect that
/// killed the rival `chunk_digests` design) — cannot produce one. Taking the batch and slicing the
/// chunk out here also makes the emitted `chunk_index`/`chunk_count` agree with
/// [`build_batch_manifest`]'s `leaf_count.div_ceil(PALW_MAX_LEAVES_PER_CHUNK)` by construction rather
/// than by the caller's discipline.
///
/// Note this is a producer convention, not a protocol constraint: because the binding is at LEAF
/// granularity, the acceptance verifier accepts any chunking whatsoever (§5.15.6). Fixing the split
/// here just removes a degree of freedom nobody needs and every caller could get wrong silently.
///
/// Enforces what `validate_leaf_chunk` requires — 1..=64 leaves, every leaf's `batch_id` equal to the
/// chunk's, strictly-increasing `leaf_index`, `proofs.len() == leaves.len()` — plus the two properties
/// the context-free validator cannot see: the batch's `leaf_index` set is exactly `0..leaf_count`
/// (see [`RegistrationError::NonContiguousLeafIndices`]), and ticket-nullifier commitments are distinct
/// across the WHOLE batch. The validator's I-13 distinctness is only per-chunk, so an honest producer
/// holding to the batch-wide property is strictly stronger and costs nothing.
///
/// Returns `(subnetwork_byte, borsh(chunk))`.
pub fn build_leaf_chunk(
    batch_id: Hash64,
    chunk_index: u16,
    batch_leaves: &[PalwPublicLeafV1],
) -> Result<(u8, Vec<u8>), RegistrationError> {
    // The ordered, batch_id-zeroed hashes — the SAME sequence `manifest_leaf_root` reduced to
    // `manifest.leaf_root`, so the proofs below open exactly that root. Also validates size and the
    // position == leaf_index invariant the acceptance verifier depends on.
    let hashes = ordered_batch_leaf_hashes(batch_leaves)?;

    let mut ordered = batch_leaves.to_vec();
    ordered.sort_by_key(|l| l.leaf_index);
    for l in &ordered {
        if l.batch_id != batch_id {
            return Err(RegistrationError::BatchIdMismatch(l.leaf_index));
        }
    }
    // `ordered_batch_leaf_hashes` already proved the indices are exactly 0..n, which implies
    // distinctness; this keeps the original error surface for the duplicate case reachable from a
    // caller's point of view and documents the dependency rather than leaving it implicit.
    if let Some(w) = ordered.windows(2).find(|w| w[0].leaf_index == w[1].leaf_index) {
        return Err(RegistrationError::DuplicateLeafIndex(w[0].leaf_index));
    }
    let mut seen = std::collections::HashSet::with_capacity(ordered.len());
    for l in &ordered {
        if !seen.insert(l.ticket_nullifier_commitment) {
            return Err(RegistrationError::DuplicateNullifier);
        }
    }

    let chunk_count = (ordered.len() as u32).div_ceil(PALW_MAX_LEAVES_PER_CHUNK as u32) as u16;
    if chunk_index >= chunk_count {
        return Err(RegistrationError::ChunkIndexOutOfRange { got: chunk_index, chunk_count });
    }
    let start = chunk_index as usize * PALW_MAX_LEAVES_PER_CHUNK;
    let end = std::cmp::min(ordered.len(), start + PALW_MAX_LEAVES_PER_CHUNK);
    let leaves: Vec<PalwPublicLeafV1> = ordered[start..end].to_vec();
    if leaves.is_empty() || leaves.len() > PALW_MAX_LEAVES_PER_CHUNK {
        return Err(RegistrationError::ChunkSize { got: leaves.len(), max: PALW_MAX_LEAVES_PER_CHUNK });
    }

    // One proof per leaf, opened at the leaf's OWN `leaf_index` — the very index
    // `palw_verify_leaf_membership` will re-derive the direction bits from at the acceptance coordinate.
    // Derived through `palw_leaf_merkle_proof` rather than a local fold so a construction change cannot
    // drift between producer and verifier (the silent-outage mode of §5.15.9).
    let proofs = leaves
        .iter()
        .map(|l| palw_leaf_merkle_proof(&hashes, l.leaf_index).expect("leaf_index < leaf_count was just established"))
        .collect();

    let chunk = PalwLeafChunkV1 { version: PALW_LEAF_CHUNK_VERSION_V2, batch_id, chunk_index, leaves, proofs };
    let payload = borsh::to_vec(&chunk).map_err(|_| RegistrationError::Encode)?;
    Ok((LEAF_CHUNK_SUBNETWORK_BYTE, payload))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{MiningJob, PalwMiner, ProviderRegistration};
    use kaspa_consensus_core::palw::validate_palw_overlay_payload;
    use kaspa_consensus_core::tx::TransactionOutpoint;
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
        // ADR-0040 P0-4 (ECON-01): a leaf's reward scripts are emitted VERBATIM as coinbase outputs, so
        // leaf admission requires the exact 69-byte P2PKH ML-DSA-87 template. An arbitrary script is not
        // coinbase-representable and the leaf chunk is rejected.
        let spk = kaspa_consensus_core::dns_finality::p2pkh_mldsa87_spk(&[0xa0; 64]);
        PalwMiner::new(
            MockDeterministicRuntime::new(profile(), 3, 2),
            MockDeterministicRuntime::new(profile(), 3, 2),
            ProviderRegistration {
                provider_a_bond: TransactionOutpoint::new(h(6), 0),
                provider_b_bond: TransactionOutpoint::new(h(7), 0),
                provider_a_reward_script: spk.clone(),
                provider_b_reward_script: spk,
                ticket_authority_pk_hash: h(8),
                registered_epoch: FIXTURE_REGISTRATION_EPOCH,
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
        let (byte, payload) = build_leaf_chunk(batch, 0, &leaves).expect("chunk assembles");
        assert_eq!(byte, LEAF_CHUNK_SUBNETWORK_BYTE);
        // The exact stateless check the mempool / body validator runs accepts it.
        assert_eq!(validate_palw_overlay_payload(byte, &payload), Ok(()));
    }

    /// kaspa-pq **ADR-0040 §5.14.3 item 7** — the single registration epoch every producer fixture in
    /// this crate is built at.
    ///
    /// A leaf's `registered_epoch` and its batch's `registration_epoch` must now be equal
    /// (`build_batch_manifest`, mirroring `PalwOverlayError::LeafRegistrationEpochMismatch` at the
    /// acceptance coordinate). The fixtures used to carry `3` on the leaf and `5` on the policy — they
    /// modelled exactly the divergence the rule forbids, which is why they all had to move together.
    /// One constant, read by both sides, is what keeps them from drifting apart again.
    pub(crate) const FIXTURE_REGISTRATION_EPOCH: u64 = 3;

    pub(crate) fn policy() -> BatchPolicy {
        BatchPolicy {
            registration_epoch: FIXTURE_REGISTRATION_EPOCH,
            registration_lead_epochs: 2,
            audit_window_epochs: 1,
            active_window_epochs: 100,
            min_leaf_bond_sompi: 0,
            max_batch_leaves: kaspa_consensus_core::palw::PALW_MAX_BATCH_LEAVES_V1 as u32,
        }
    }

    /// kaspa-pq **ADR-0040 §5.14.3 item 7** — the producer refuses to fix a batch whose leaves disagree
    /// with its registration epoch, and the refusal happens BEFORE `batch_id` exists.
    ///
    /// The ordering is the point. `registered_epoch` is inside `leaf_hash` → `leaf_root`, and
    /// `registration_epoch` is inside `content_id()`; once `build_batch_manifest` returns, both are
    /// sealed under one `batch_id` and no restamping can reconcile them (restamping a leaf changes the
    /// root, which changes the id). So a batch built with this mismatch is not merely wrong — it is
    /// permanently unusable, and every chunk it emits is refused on-chain with
    /// `PalwOverlayError::LeafRegistrationEpochMismatch`. Catching it here is the difference between a
    /// caught producer bug and a registration fee spent on a dead batch.
    #[test]
    fn a_batch_cannot_be_fixed_over_leaves_registered_at_another_epoch() {
        let m = miner();
        let minted = vec![mine(&m, Hash64::default(), 0, 0xC0), mine(&m, Hash64::default(), 1, 0xC1)];
        // The miner stamps FIXTURE_REGISTRATION_EPOCH into every leaf it produces; assert that rather
        // than assuming it, so this test cannot pass for the wrong reason.
        assert!(minted.iter().all(|l| l.registered_epoch == FIXTURE_REGISTRATION_EPOCH), "the miner must stamp the fixture epoch");

        let skewed = BatchPolicy { registration_epoch: FIXTURE_REGISTRATION_EPOCH + 1, ..policy() };
        assert_eq!(
            build_batch_manifest(&minted, h(1), h(2), h(3), h(4), 0, &skewed),
            Err(RegistrationError::LeafRegistrationEpochMismatch {
                leaf_index: 0,
                got: FIXTURE_REGISTRATION_EPOCH,
                expected: FIXTURE_REGISTRATION_EPOCH + 1,
            }),
            "a batch whose policy epoch disagrees with its leaves must not be assembled"
        );

        // Control: the SAME leaves under the matching policy still build, so the rule rejects the
        // divergence and nothing else.
        build_batch_manifest(&minted, h(1), h(2), h(3), h(4), 0, &policy()).expect("the epoch-matched batch must still build");
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
        let (cbyte, cpayload) = build_leaf_chunk(batch_id, 0, &restamped).expect("chunk assembles");

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
        assert_eq!(build_leaf_chunk(batch, 0, &[foreign]).unwrap_err(), RegistrationError::BatchIdMismatch(0));
        // Two leaves sharing a raw nullifier ⇒ same commitment ⇒ rejected.
        let dup = vec![mine(&m, batch, 0, 0xC0), mine(&m, batch, 1, 0xC0)];
        assert_eq!(build_leaf_chunk(batch, 0, &dup).unwrap_err(), RegistrationError::DuplicateNullifier);
        // An empty batch is rejected. INTENT CHANGE (kaspa-pq ADR-0040 §5.15.9 step (iii)): this used to
        // assert `ChunkSize { got: 0 }` because the argument WAS the chunk. The argument is now the whole
        // batch — a membership proof does not exist relative to a subset — so emptiness is now a
        // malformed BATCH, and `BatchSize` is the honest error. `ChunkSize` remains reachable only as the
        // slicing post-condition it now is.
        assert!(matches!(build_leaf_chunk(batch, 0, &[]).unwrap_err(), RegistrationError::BatchSize { got: 0, .. }));
        // A chunk_index past the batch's `ceil(n / 64)` chunks has no leaves to carry.
        let two = vec![mine(&m, batch, 0, 0xC0), mine(&m, batch, 1, 0xC1)];
        assert_eq!(
            build_leaf_chunk(batch, 1, &two).unwrap_err(),
            RegistrationError::ChunkIndexOutOfRange { got: 1, chunk_count: 1 }
        );
    }

    /// kaspa-pq ADR-0040 §5.15.4 — the Merkle leaf node binds the leaf's POSITION, and the acceptance
    /// verifier feeds it `leaf.leaf_index`. A batch whose indices are not exactly `0..leaf_count` makes
    /// those two numbers disagree, so the producer would commit to a root no verifier can reproduce and
    /// every chunk would be refused with no error surfaced anywhere (`let _ =` at
    /// virtual_processor/processor.rs:1800-1801). Refused at the producer instead.
    #[test]
    fn a_batch_whose_leaf_indices_are_not_zero_based_and_contiguous_is_refused() {
        let m = miner();
        let batch = h(0x10);
        // Indices {0, 2}: sorted position 1 holds leaf_index 2.
        let gapped = vec![mine(&m, batch, 0, 0xC0), mine(&m, batch, 2, 0xC1)];
        assert_eq!(
            manifest_leaf_root(&gapped).unwrap_err(),
            RegistrationError::NonContiguousLeafIndices { got: 2, leaf_count: 2 }
        );
        assert_eq!(
            build_leaf_chunk(batch, 0, &gapped).unwrap_err(),
            RegistrationError::NonContiguousLeafIndices { got: 2, leaf_count: 2 }
        );
        // Indices {1, 2}: contiguous but not zero-based — the off-by-one a "sorted and distinct" check
        // would wave through.
        let shifted = vec![mine(&m, batch, 1, 0xC0), mine(&m, batch, 2, 0xC1)];
        assert_eq!(
            manifest_leaf_root(&shifted).unwrap_err(),
            RegistrationError::NonContiguousLeafIndices { got: 1, leaf_count: 2 }
        );
    }

    /// **The producer-side half of the ADR-0040 §5.15.12 cross-crate golden.** Every proof
    /// `build_leaf_chunk` emits must open `manifest.leaf_root` under the CONSENSUS verifier
    /// (`palw_verify_leaf_membership`) — not under a re-implementation of the fold. If the miner and
    /// consensus ever disagree about the construction, the on-chain symptom is silence: the acceptance
    /// arm's error is discarded, so honest chunks simply never store. This test is the loud version.
    ///
    /// Covers a MULTI-CHUNK, NON-POWER-OF-TWO batch (65 leaves ⇒ 2 chunks, depth 7, one `H_EMPTY`
    /// padding region), so the second chunk's proofs and the uniform-padding case are both exercised.
    #[test]
    fn every_emitted_proof_opens_the_manifest_leaf_root_under_the_consensus_verifier() {
        use kaspa_consensus_core::palw::palw_verify_leaf_membership;

        let m = miner();
        // 65 distinct raw nullifiers (0..=64 fits a u8 without wrapping into a collision).
        let minted: Vec<PalwPublicLeafV1> = (0..65u32).map(|i| mine(&m, Hash64::default(), i, i as u8)).collect();
        let (batch_id, (_, mpayload)) = build_batch_manifest(&minted, h(1), h(2), h(3), h(4), 0, &policy()).expect("manifest builds");
        let manifest = <PalwBatchManifestV1 as borsh::BorshDeserialize>::try_from_slice(&mpayload).expect("manifest decodes");
        assert_eq!(manifest.chunk_count, 2, "65 leaves is two chunks — the multi-chunk path must be exercised");

        let restamped = restamp_leaves(batch_id, &minted);
        let mut seen = 0usize;
        for chunk_index in 0..manifest.chunk_count {
            let (byte, payload) = build_leaf_chunk(batch_id, chunk_index, &restamped).expect("chunk assembles");
            assert_eq!(validate_palw_overlay_payload(byte, &payload), Ok(()));
            let chunk = <PalwLeafChunkV1 as borsh::BorshDeserialize>::try_from_slice(&payload).expect("chunk decodes");
            assert_eq!(chunk.version, PALW_LEAF_CHUNK_VERSION_V2, "v1 is refused by validate_leaf_chunk");
            assert_eq!(chunk.proofs.len(), chunk.leaves.len());
            for (leaf, proof) in chunk.leaves.iter().zip(&chunk.proofs) {
                // The verifier consumes the batch_id-ZEROED projection — the same one the root was built
                // over. `resolve_palw_binding` deliberately uses the NON-projected `leaf_hash()` for the
                // eligibility draw, so these two hashes of one leaf must not be "deduplicated" later.
                let mut projected = leaf.clone();
                projected.batch_id = Hash64::default();
                assert!(
                    palw_verify_leaf_membership(&projected.leaf_hash(), leaf.leaf_index, manifest.leaf_count, proof, &manifest.leaf_root),
                    "leaf {} of chunk {chunk_index} does not open manifest.leaf_root — producer/verifier drift",
                    leaf.leaf_index
                );
                seen += 1;
            }
        }
        assert_eq!(seen, 65, "the two chunks must together carry every leaf exactly once");
    }

    /// A fully LITERAL leaf — no `PalwMiner`, no `MockDeterministicRuntime`.
    ///
    /// The cross-crate golden below pins hash values, so its fixture must not depend on anything that is
    /// free to change for unrelated reasons. A mock runtime's output is exactly such a thing: if the
    /// golden were built from `mine(...)`, a harmless tweak to the mock would move the pinned constants
    /// and the next person would "fix" the golden by pasting the new values — which is how a pin stops
    /// being evidence. Everything here is a literal or a function of `index`.
    ///
    /// `pub(crate)` because `audit.rs`'s half of the cross-crate golden certifies a manifest built from
    /// THIS fixture: one constant, checked at the miner, at consensus-core, and at the auditor.
    pub(crate) fn golden_leaf(index: u32) -> PalwPublicLeafV1 {
        let spk = kaspa_consensus_core::dns_finality::p2pkh_mldsa87_spk(&[0xa0; 64]);
        PalwPublicLeafV1 {
            version: 1,
            // Zeroed on purpose: the golden pins the PROJECTED hashes, and the projection is what
            // `manifest_leaf_root` applies. Starting from zero means the fixture is already in the
            // projected form, so a regression that dropped the projection would still be visible (the
            // 65-leaf round trip above carries a NON-zero batch_id and covers the other direction).
            batch_id: Hash64::default(),
            leaf_index: index,
            job_nullifier: h(0x30 + index as u8),
            ticket_nullifier_commitment: h(0x40 + index as u8),
            model_profile_id: h(1),
            runtime_class_id: h(2),
            shape_id: 1,
            quantum_count: 1,
            proof_type: 1,
            provider_a_bond: TransactionOutpoint::new(h(6), 0),
            provider_b_bond: TransactionOutpoint::new(h(7), 1),
            provider_a_reward_script: spk.clone(),
            provider_b_reward_script: spk,
            ticket_authority_pk_hash: h(8),
            private_match_commitment: Hash64::default(),
            receipt_da_root: Hash64::default(),
            registered_epoch: 3,
            activation_epoch: 4,
            expiry_epoch: 1000,
            leaf_bond_sompi: 0,
        }
    }

    /// **THE CROSS-CRATE GOLDEN — producer side (ADR-0040 §5.15.9 step (iv), §5.15.12).**
    ///
    /// `kaspa-consensus-core` and `misaka-mil-miner` are separate crates that must agree, byte for byte,
    /// on what `leaf_root` means. Nothing at runtime tells them apart when they don't: the acceptance
    /// arm's result is dropped at `consensus/src/pipeline/virtual_processor/processor.rs:1800-1801`
    /// (`let _ =`), so a miner emitting the old FLAT root produces chunks that are silently never stored
    /// and certificates that are silently always refused. There is no log line, no invalid block, no
    /// symptom short of "the lane does nothing".
    ///
    /// The antidote is a shared CONSTANT rather than a shared function call. This test pins a literal
    /// leaf-hash vector and the literal root it reduces to; `palw_leaf_merkle_root_cross_crate_golden_
    /// vector` in `consensus/core/src/palw.rs` pins the SAME two literals. Neither side can move without
    /// breaking a build, and asserting `f(x) == f(x)` — which proves nothing — is not available here.
    ///
    /// Three independent things are pinned, in the order a change would break them:
    /// 1. the PROJECTION (`batch_id` zeroed, then `leaf_hash()`) → the pinned hash vector;
    /// 2. the miner's own `manifest_leaf_root` over the literal leaves → the pinned root;
    /// 3. an INDEPENDENT straight-line re-derivation of that root, written from the ADR-0040 §5.15.4
    ///    text in this crate, using raw `blake2b_512_keyed` and no helper from consensus-core.
    ///
    /// (3) is what makes (2) a derivation instead of a paste: the literal is anchored by a computation
    /// that does not go through `palw_leaf_merkle_root` at all. If this test ever fails, the fix is
    /// almost never to update the literal — it is a re-genesis, because `leaf_root` sits inside
    /// `content_id()` and therefore inside every `batch_id`.
    #[test]
    fn manifest_leaf_root_is_pinned_to_the_consensus_cross_crate_golden_vector() {
        use kaspa_consensus_core::palw::{
            PALW_LEAF_MERKLE_EMPTY_DOMAIN, PALW_LEAF_MERKLE_LEAF_DOMAIN, PALW_LEAF_MERKLE_NODE_DOMAIN, PALW_LEAF_ROOT_DOMAIN,
            palw_leaf_merkle_root,
        };
        use kaspa_hashes::blake2b_512_keyed;

        // --- (1) the projection, pinned -----------------------------------------------------------
        let leaves: Vec<PalwPublicLeafV1> = (0..3u32).map(golden_leaf).collect();
        let projected: Vec<Hash64> = leaves
            .iter()
            .map(|l| {
                let mut p = l.clone();
                p.batch_id = Hash64::default();
                p.leaf_hash()
            })
            .collect();
        let pinned_hashes: Vec<Hash64> = CROSS_CRATE_GOLDEN_LEAF_HASHES.iter().map(|s| s.parse::<Hash64>().expect("hex")).collect();
        assert_eq!(
            projected, pinned_hashes,
            "the golden leaf fixture no longer hashes to the pinned vector — either PalwPublicLeafV1's \
             layout moved (LEAF_LEN / LEAF_FNV must have moved with it, and ADR-0040 §5.15.10 says they \
             MUST NOT) or manifest_leaf_root's batch_id projection changed"
        );

        // --- (2) the miner's producer, pinned -----------------------------------------------------
        let root = manifest_leaf_root(&leaves).expect("contiguous 0..3");
        assert_eq!(
            root.to_string(),
            CROSS_CRATE_GOLDEN_LEAF_ROOT,
            "manifest_leaf_root no longer produces the pinned ADR-0040 §5.15.4 Merkle root. If this \
             regressed to the retired FLAT palw_leaf_root, every chunk this miner emits will fail the \
             acceptance-coordinate membership check and be dropped WITHOUT an error anywhere"
        );

        // --- (3) independent re-derivation, straight from ADR-0040 §5.15.4 ------------------------
        // Written out here, in the MINER crate, so the pinned literal is anchored by something that
        // never calls palw_leaf_merkle_root.
        let leaf_node = |i: u32, x: &Hash64| {
            let mut p = i.to_le_bytes().to_vec();
            p.extend_from_slice(x.as_byte_slice());
            blake2b_512_keyed(PALW_LEAF_MERKLE_LEAF_DOMAIN, &p)
        };
        let node = |l: &Hash64, r: &Hash64| {
            let mut p = l.as_byte_slice().to_vec();
            p.extend_from_slice(r.as_byte_slice());
            blake2b_512_keyed(PALW_LEAF_MERKLE_NODE_DOMAIN, &p)
        };
        // n = 3 ⇒ d = ceil(log2 3) = 2 ⇒ level 0 is [L0, L1, L2, H_EMPTY] (UNIFORM padding, not a
        // duplicated tail — that distinction is the whole point of the constant).
        let h_empty = blake2b_512_keyed(PALW_LEAF_MERKLE_EMPTY_DOMAIN, &[]);
        let apex = node(
            &node(&leaf_node(0, &pinned_hashes[0]), &leaf_node(1, &pinned_hashes[1])),
            &node(&leaf_node(2, &pinned_hashes[2]), &h_empty),
        );
        let mut pre = 3u64.to_le_bytes().to_vec();
        pre.extend_from_slice(apex.as_byte_slice());
        assert_eq!(
            blake2b_512_keyed(PALW_LEAF_ROOT_DOMAIN, &pre),
            root,
            "the miner's root diverged from a straight-line reading of ADR-0040 §5.15.4"
        );

        // --- (4) and consensus-core reduces the SAME pinned vector to the SAME pinned root ---------
        assert_eq!(
            palw_leaf_merkle_root(&pinned_hashes).to_string(),
            CROSS_CRATE_GOLDEN_LEAF_ROOT,
            "consensus-core and the miner disagree about the golden vector"
        );
    }

    /// The projected (`batch_id`-zeroed) `leaf_hash` of `golden_leaf(0..3)`.
    ///
    /// MIRRORED VERBATIM in `consensus/core/src/palw.rs`'s
    /// `palw_leaf_merkle_root_cross_crate_golden_vector`. Two crates, one constant — that is the point;
    /// do not "de-duplicate" this into a shared helper, because a shared helper is a shared function
    /// call and a shared function call cannot detect the drift this exists to detect.
    const CROSS_CRATE_GOLDEN_LEAF_HASHES: [&str; 3] = [
        "84ff9992ea452424a6f9a7158cc0e8fd896ae81afb10abd466eb8827e1591642\
         64802ffb606cd8fe5f558cdc3d7aaec2006b85fc98309559ec1335ab848e1e14",
        "9e4498cdc836458e77517f154d1a7589968d99ad0d5653175957f21cc992ed09\
         fdfb8b54b35dca923a473e6f1e38a76f1261b2e0a23deec42d8a73f89ec171c1",
        "70fefaa9607758020c94fa96cc56d55d07b98757748235fb2cdbafaa084b58a8\
         c81c703d648e3363da1811af5a27f50d073a6747547a2b087988b2d7fcda3c46",
    ];

    /// The ADR-0040 §5.15.4 Merkle root over [`CROSS_CRATE_GOLDEN_LEAF_HASHES`]. Mirrored in
    /// consensus-core; see that constant's note. `pub(crate)` so `audit.rs` can assert that the
    /// certificate an auditor quorum emits carries THIS value.
    pub(crate) const CROSS_CRATE_GOLDEN_LEAF_ROOT: &str = "19924ac9d60baf3b58f0ce55d9c5b656bc6bf19548d79bd340dc97e5e5b6dcb3\
         5a5ac513972045cbea53cd9a469ac12c250a43f3280f752a626931258a38ed04";
}
