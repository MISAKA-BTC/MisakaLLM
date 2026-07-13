//! ADR-0039 PALW Replica-GEMM audited-compute lane — on-chain wire format.
//!
//! This module freezes the **consensus-facing** PALW types (design v0.2 §9, §10, §11, §12, §24):
//! the public leaf / manifest / chunk / certificate / provider-bond / beacon / authorization /
//! revocation payloads carried on the PALW overlay subnetworks (`0x30-0x37`, see
//! [`crate::subnets`]), plus the security-critical domain-separated hash helpers
//! (`leaf_hash`, `chain_commit`, `slot_digest`, `eligibility_hash`, `beacon_seed`,
//! `private_match_commitment`) and the network [`PalwParams`].
//!
//! Everything here is **inert** until the PALW activation fence — no header is minted on the PALW
//! lane, and no live validator path consumes these types yet. The point of landing them first is
//! design §33: *freeze the wire format and test vectors before any hot-path / GPU code*. The
//! provider-side, off-chain runtime identity (the two `MISAKA-QW4/QW9-PALW-v1` tiers, GEMM-trace and
//! output commitments) lives in `misaka-mil-core`'s `palw` module.
//!
//! All multi-field preimages are unambiguous: fixed-width fields (`Hash64` = 64 B, integers as
//! little-endian) are concatenated directly; variable-length fields are `u64`-LE length-prefixed.
//! Every hash is a keyed BLAKE2b-512 (`blake2b_512_keyed`) under a disjoint `misaka-palw-v1/*`
//! domain so no PALW hash can be replayed as any other hash in the system.

use crate::BlueWorkType;
use crate::tx::{ScriptPublicKey, TransactionOutpoint};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{HASH64_SIZE, Hash64, blake2b_512_keyed};

// =============================================================================================
// Domain separators (keyed BLAKE2b-512 keys, ≤ 64 bytes — pinned in tests).
// =============================================================================================

/// `leaf_hash = Hash64_k(leaf, borsh(PalwPublicLeafV1))` — the on-chain leaf descriptor hash
/// committed before the beacon (design §9.2, invariant I-2).
pub const PALW_LEAF_DOMAIN: &[u8] = b"misaka-palw-v1/leaf";
/// `chain_commit(S)` fork-binding digest (design §12.1, invariant I-4).
pub const PALW_CHAIN_COMMIT_DOMAIN: &[u8] = b"misaka-palw-chain-commit-v1";
/// `slot_digest` → per-leaf target DAA interval assignment (design §12.2, invariant I-3).
pub const PALW_SLOT_DOMAIN: &[u8] = b"misaka-palw-slot-v1";
/// `eligibility_hash` one-shot draw (design §12.3).
pub const PALW_ELIGIBILITY_DOMAIN: &[u8] = b"misaka-palw-eligibility-v1";
/// `R_E` epoch beacon seed (design §11.2).
pub const PALW_BEACON_DOMAIN: &[u8] = b"misaka-palw-beacon-v1";
/// `PalwBeaconCommitV1.commitment = Hash64_k(beacon-commit, epoch ‖ random_64 ‖ bond)` (design §11.2).
pub const PALW_BEACON_COMMIT_DOMAIN: &[u8] = b"misaka-palw-beacon-commit-v1";
/// `private_match_commitment` binding the two provider receipts to the leaf (design §24.2).
pub const PALW_MATCH_DOMAIN: &[u8] = b"misaka-palw-match-v1";
/// `receipt_hash = Hash64_k(replica-receipt, borsh(ReplicaExecutionReceiptV1))` — leaf-committed
/// provider receipt hash (design §24.1).
pub const PALW_RECEIPT_DOMAIN: &[u8] = b"misaka-palw-replica-receipt-v1";
/// Provider-pair selection from the prior-epoch beacon seed (design §8.1).
pub const PALW_PROVIDER_SELECT_DOMAIN: &[u8] = b"misaka-palw-provider-select-v1";
/// Auditor selection weight from the prior-epoch beacon seed (design §10.2).
pub const PALW_AUDITOR_SELECT_DOMAIN: &[u8] = b"misaka-palw-auditor-select-v1";

// =============================================================================================
// Proof type (design §20.2). Header carries `palw_proof_type: u8`; keep the wire byte pinned to the
// design's 1..4 discriminants (borsh's positional enum index would NOT preserve these, so the
// on-wire representation is a plain `u8` and this enum is a typed view over it).
// =============================================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PalwProofType {
    /// k=2 replica-exact — the only full-weight proof type in v0.2.
    ReplicaExactV1 = 1,
    /// Reserved: TEE-assisted, rate-limited, low-weight only (never bypasses the floor; I-7).
    TeeRateLimitedV1 = 2,
    /// Reserved: transparent (STARK-style) argument.
    TransparentArgumentV1 = 3,
    /// Reserved: witness-hiding argument.
    WitnessHidingArgumentV1 = 4,
}

impl PalwProofType {
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::ReplicaExactV1),
            2 => Some(Self::TeeRateLimitedV1),
            3 => Some(Self::TransparentArgumentV1),
            4 => Some(Self::WitnessHidingArgumentV1),
            _ => None,
        }
    }
}

// =============================================================================================
// Preimage helpers.
// =============================================================================================

#[inline]
fn push_hash(buf: &mut Vec<u8>, h: &Hash64) {
    buf.extend_from_slice(h.as_byte_slice());
}

#[inline]
fn push_var(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Interpret the leading 8 bytes of a digest as a little-endian `u64` (used for the modular slot
/// draw). Deterministic across platforms.
#[inline]
fn digest_low_u64(h: &Hash64) -> u64 {
    let b = h.as_byte_slice();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

// =============================================================================================
// Security-critical hash helpers (all keyed, all fixed-width preimages).
// =============================================================================================

/// `chain_commit(S)` (design §12.1). Miner-independent: derived from a DNS-finalized checkpoint fixed
/// *before* the target slot, so a producer cannot re-roll a ticket per fork (invariant I-4).
pub fn chain_commit(dns_finalized_checkpoint: &Hash64, dns_finality_certificate: &Hash64, target_interval: u64, network_id: u32) -> Hash64 {
    let mut p = Vec::with_capacity(2 * HASH64_SIZE + 8 + 4);
    push_hash(&mut p, dns_finalized_checkpoint);
    push_hash(&mut p, dns_finality_certificate);
    p.extend_from_slice(&target_interval.to_le_bytes());
    p.extend_from_slice(&network_id.to_le_bytes());
    blake2b_512_keyed(PALW_CHAIN_COMMIT_DOMAIN, &p)
}

/// `slot_digest` for a leaf (design §12.2).
pub fn slot_digest(eligibility_beacon: &Hash64, batch_id: &Hash64, leaf_index: u32, leaf_hash: &Hash64) -> Hash64 {
    let mut p = Vec::with_capacity(3 * HASH64_SIZE + 4);
    push_hash(&mut p, eligibility_beacon);
    push_hash(&mut p, batch_id);
    p.extend_from_slice(&leaf_index.to_le_bytes());
    push_hash(&mut p, leaf_hash);
    blake2b_512_keyed(PALW_SLOT_DOMAIN, &p)
}

/// `target_daa_interval = active_from + (slot_digest mod active_window_intervals)` (design §12.2).
/// `active_window_intervals` must be non-zero (checked by the caller / params validation).
#[inline]
pub fn target_daa_interval(active_from: u64, active_window_intervals: u64, slot_digest: &Hash64) -> u64 {
    let window = active_window_intervals.max(1);
    active_from + (digest_low_u64(slot_digest) % window)
}

/// `eligibility_hash` — the one-shot draw (design §12.3). Returns a 512-bit digest; acceptance
/// compares `Uint512(eligibility_hash) <= target_512(bits)` in the difficulty slice.
#[allow(clippy::too_many_arguments)]
pub fn eligibility_hash(
    network_id: u32,
    eligibility_beacon: &Hash64,
    chain_commit: &Hash64,
    target_interval: u64,
    batch_id: &Hash64,
    leaf_index: u32,
    leaf_hash: &Hash64,
    ticket_nullifier: &Hash64,
) -> Hash64 {
    let mut p = Vec::with_capacity(4 * HASH64_SIZE + 4 + 8 + 4);
    p.extend_from_slice(&network_id.to_le_bytes());
    push_hash(&mut p, eligibility_beacon);
    push_hash(&mut p, chain_commit);
    p.extend_from_slice(&target_interval.to_le_bytes());
    push_hash(&mut p, batch_id);
    p.extend_from_slice(&leaf_index.to_le_bytes());
    push_hash(&mut p, leaf_hash);
    push_hash(&mut p, ticket_nullifier);
    blake2b_512_keyed(PALW_ELIGIBILITY_DOMAIN, &p)
}

/// `R_E` epoch beacon seed (design §11.2). The reveal / missing-commitment sets are pre-reduced to
/// canonical roots by the caller so the preimage is fixed-width.
pub fn beacon_seed(prev_seed: &Hash64, dns_finalized_anchor: &Hash64, valid_reveals_root: &Hash64, missing_commitments_root: &Hash64, epoch: u64) -> Hash64 {
    let mut p = Vec::with_capacity(4 * HASH64_SIZE + 8);
    push_hash(&mut p, prev_seed);
    push_hash(&mut p, dns_finalized_anchor);
    push_hash(&mut p, valid_reveals_root);
    push_hash(&mut p, missing_commitments_root);
    p.extend_from_slice(&epoch.to_le_bytes());
    blake2b_512_keyed(PALW_BEACON_DOMAIN, &p)
}

/// `PalwBeaconCommitV1.commitment = Hash64_k(beacon-commit, epoch ‖ random_64 ‖ bond_tx ‖ bond_idx)`
/// (design §11.2). Binds the reveal to the epoch and the committing bond.
pub fn beacon_commitment(epoch: u64, random_64: &[u8; 64], bond: &TransactionOutpoint) -> Hash64 {
    let mut p = Vec::with_capacity(8 + 64 + HASH64_SIZE + 4);
    p.extend_from_slice(&epoch.to_le_bytes());
    p.extend_from_slice(random_64);
    push_hash(&mut p, &bond.transaction_id);
    p.extend_from_slice(&bond.index.to_le_bytes());
    blake2b_512_keyed(PALW_BEACON_COMMIT_DOMAIN, &p)
}

/// `private_match_commitment` (design §24.2): the leaf commits this; the body (receipts, trace) stays
/// in receipt DA and a later canary dispute checks equality against it.
pub fn private_match_commitment(
    output_commitment: &Hash64,
    canonical_gemm_trace_root: &Hash64,
    operation_schedule_commitment: &Hash64,
    job_set_commitment: &Hash64,
    receipt_a_hash: &Hash64,
    receipt_b_hash: &Hash64,
) -> Hash64 {
    let mut p = Vec::with_capacity(6 * HASH64_SIZE);
    for h in [output_commitment, canonical_gemm_trace_root, operation_schedule_commitment, job_set_commitment, receipt_a_hash, receipt_b_hash] {
        push_hash(&mut p, h);
    }
    blake2b_512_keyed(PALW_MATCH_DOMAIN, &p)
}

// =============================================================================================
// Provider execution receipt (off-chain artifact, hashed into the leaf) — design §24.1.
// =============================================================================================

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReplicaExecutionReceiptV1 {
    pub version: u16,
    pub provider_bond: TransactionOutpoint,
    pub session_public_key: Vec<u8>,
    pub job_nullifier: Hash64,
    pub job_set_commitment: Hash64,
    pub model_profile_id: Hash64,
    pub runtime_class_id: Hash64,
    pub shape_id: u16,
    pub quantum_count: u16,
    pub output_commitment: Hash64,
    pub canonical_gemm_trace_root: Hash64,
    pub operation_schedule_commitment: Hash64,
    pub receipt_da_root: Hash64,
    pub completed_at_epoch: u64,
    /// ML-DSA-87 signature over [`Self::signing_hash`] under the receipt context. Verification wiring
    /// lands in the audit slice; here it is a wire field only.
    pub signature: Vec<u8>,
}

impl ReplicaExecutionReceiptV1 {
    /// The message a provider signs: every field **except** `signature`, domain-separated and
    /// length-prefixed. Kept separate from [`Self::hash`] so the leaf can commit the full receipt
    /// (incl. signature) while the signature covers only the semantic fields.
    pub fn signing_hash(&self) -> Hash64 {
        let mut p = Vec::with_capacity(256);
        p.extend_from_slice(&self.version.to_le_bytes());
        push_hash(&mut p, &self.provider_bond.transaction_id);
        p.extend_from_slice(&self.provider_bond.index.to_le_bytes());
        push_var(&mut p, &self.session_public_key);
        for h in [&self.job_nullifier, &self.job_set_commitment, &self.model_profile_id, &self.runtime_class_id] {
            push_hash(&mut p, h);
        }
        p.extend_from_slice(&self.shape_id.to_le_bytes());
        p.extend_from_slice(&self.quantum_count.to_le_bytes());
        for h in [&self.output_commitment, &self.canonical_gemm_trace_root, &self.operation_schedule_commitment, &self.receipt_da_root] {
            push_hash(&mut p, h);
        }
        p.extend_from_slice(&self.completed_at_epoch.to_le_bytes());
        blake2b_512_keyed(PALW_RECEIPT_DOMAIN, &p)
    }

    /// Full-receipt hash committed by the leaf (`receipt_a_hash` / `receipt_b_hash`).
    pub fn hash(&self) -> Hash64 {
        blake2b_512_keyed(PALW_RECEIPT_DOMAIN, &borsh::to_vec(self).expect("borsh"))
    }
}

/// Private match record (body in receipt DA; only its commitment is public) — design §24.2.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReplicaMatchRecordV1 {
    pub receipt_a_hash: Hash64,
    pub receipt_b_hash: Hash64,
    pub job_nullifier: Hash64,
    pub output_commitment: Hash64,
    pub canonical_gemm_trace_root: Hash64,
    pub operation_schedule_commitment: Hash64,
    pub matched_at_epoch: u64,
}

// =============================================================================================
// Public leaf, manifest, chunk (design §9.2, §9.3).
// =============================================================================================

/// One public leaf descriptor — everything a validator needs to state-lookup a ticket, with NO
/// prompt/output/receipt body. Published before the beacon (I-2). Design §24 / §9.2.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwPublicLeafV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub leaf_index: u32,
    /// A scheduled work unit cannot mint another leaf.
    pub job_nullifier: Hash64,
    /// A ticket cannot contribute twice to the DAG (also carried first-class in Header v3).
    pub ticket_nullifier: Hash64,
    pub model_profile_id: Hash64,
    pub runtime_class_id: Hash64,
    pub shape_id: u16,
    pub quantum_count: u16,
    /// [`PalwProofType`] discriminant.
    pub proof_type: u8,
    pub provider_a_bond: TransactionOutpoint,
    pub provider_b_bond: TransactionOutpoint,
    pub provider_a_reward_script: ScriptPublicKey,
    pub provider_b_reward_script: ScriptPublicKey,
    pub ticket_authority_pk_hash: Hash64,
    pub private_match_commitment: Hash64,
    pub receipt_da_root: Hash64,
    pub registered_epoch: u64,
    pub activation_epoch: u64,
    pub expiry_epoch: u64,
    pub leaf_bond_sompi: u64,
}

impl PalwPublicLeafV1 {
    /// `leaf_hash` = keyed hash of the full leaf descriptor. Self-contained (the leaf holds no
    /// self-reference), so the borsh encoding is a faithful preimage.
    pub fn leaf_hash(&self) -> Hash64 {
        blake2b_512_keyed(PALW_LEAF_DOMAIN, &borsh::to_vec(self).expect("borsh"))
    }

    pub fn proof_type(&self) -> Option<PalwProofType> {
        PalwProofType::from_u8(self.proof_type)
    }
}

/// Batch manifest — fixes the leaf/chunk counts and roots before the beacon (design §9.3).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwBatchManifestV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub registration_epoch: u64,
    pub model_profile_id: Hash64,
    pub runtime_class_id: Hash64,
    pub leaf_count: u32,
    pub chunk_count: u16,
    pub leaf_root: Hash64,
    pub descriptor_root: Hash64,
    pub total_leaf_bond_sompi: u64,
    pub audit_policy_id: Hash64,
    pub activation_not_before_epoch: u64,
    pub expiry_epoch: u64,
}

/// A chunk of ≤ [`PALW_MAX_LEAVES_PER_CHUNK`] public leaves (design §9.3).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwLeafChunkV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub chunk_index: u16,
    pub leaves: Vec<PalwPublicLeafV1>,
}

/// Chunk-size cap (design §9.3): leaves are chunked in units of 64 rather than crammed into an anchor.
pub const PALW_MAX_LEAVES_PER_CHUNK: usize = 64;

// =============================================================================================
// Certificate + auditor vote (design §10.1, §24.4).
// =============================================================================================

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwAuditorVoteV1 {
    pub bond_outpoint: TransactionOutpoint,
    /// 1 = pass, 0 = reject.
    pub vote: u8,
    pub checked_leaf_bitmap_root: Hash64,
    /// ML-DSA-87 signature (verification in the audit slice).
    pub signature: Vec<u8>,
}

/// Certificate attesting a DNS-selected auditor quorum confirmed the batch facts (design §10.1).
/// It is **not** a proof of inference; it is a set of attested facts (I-10 / design §1.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwBatchCertificateV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub manifest_hash: Hash64,
    pub leaf_root: Hash64,
    pub audit_beacon_epoch: u64,
    pub audit_sample_root: Hash64,
    pub passed_leaf_count: u32,
    pub rejected_leaf_bitmap_root: Hash64,
    pub certificate_epoch: u64,
    pub activation_epoch: u64,
    pub expiry_epoch: u64,
    pub auditor_set_commitment: Hash64,
    pub votes: Vec<PalwAuditorVoteV1>,
}

impl PalwBatchCertificateV1 {
    /// Cached-lookup key: the hash a Header v3 references as `palw_epoch_certificate_hash`.
    pub fn hash(&self) -> Hash64 {
        blake2b_512_keyed(PALW_LEAF_DOMAIN, &borsh::to_vec(self).expect("borsh"))
    }

    /// True iff `activation_epoch <= epoch < expiry_epoch` (design §14.2 `is_active_at`).
    #[inline]
    pub fn is_active_at(&self, epoch: u64) -> bool {
        self.activation_epoch <= epoch && epoch < self.expiry_epoch
    }
}

// =============================================================================================
// Provider bond, block authorization, beacon, revocation (design §24.3, §12.4, §11.2, §9.5).
// =============================================================================================

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwProviderBondPayloadV1 {
    pub version: u16,
    /// ML-DSA-87 public key.
    pub owner_public_key: Vec<u8>,
    pub operator_group_id: Hash64,
    pub runtime_classes: Vec<Hash64>,
    pub capacity_by_shape: Vec<(u16, u32)>,
    pub reward_key_root: Hash64,
    pub amount_sompi: u64,
    pub unbond_delay_epochs: u64,
}

/// Cross-fork double-use authorization (design §12.4). The ticket authority ML-DSA-signs a
/// domain-separated header preimage (with `palw_authorization_hash = 0`); a second signature over a
/// different header commitment is slashing evidence.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwBlockAuthorizationV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub leaf_index: u32,
    pub ticket_nullifier: Hash64,
    pub header_preimage_commitment: Hash64,
    pub authority_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl PalwBlockAuthorizationV1 {
    /// `palw_authorization_hash` = hash of the completed authorization payload (design §12.4).
    pub fn hash(&self) -> Hash64 {
        blake2b_512_keyed(PALW_LEAF_DOMAIN, &borsh::to_vec(self).expect("borsh"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwBeaconCommitV1 {
    pub version: u16,
    pub epoch: u64,
    pub bond_outpoint: TransactionOutpoint,
    pub commitment: Hash64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwBeaconRevealV1 {
    pub version: u16,
    pub epoch: u64,
    pub bond_outpoint: TransactionOutpoint,
    pub random_64: [u8; 64],
    pub signature: Vec<u8>,
}

impl PalwBeaconRevealV1 {
    /// True iff this reveal matches a prior [`PalwBeaconCommitV1::commitment`] (design §11.2).
    pub fn matches_commit(&self, commitment: &Hash64) -> bool {
        beacon_commitment(self.epoch, &self.random_64, &self.bond_outpoint) == *commitment
    }
}

/// Non-retroactive revocation (design §9.5): invalidates only future unused leaves from
/// `effective_daa_score` onward.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwRevocationV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub effective_daa_score: u64,
    pub reason_code: u16,
    pub evidence_hash: Hash64,
}

// =============================================================================================
// Batch state machine (design §9.5). Pure transition function; the caller supplies the events
// (chunk/bond completion, beacon reached, quorum, timeouts, activation/expiry, fraud) from consensus
// state. Terminal states (Slashed / Expired / Revoked) have no outgoing edges. Only `Active` is
// block-eligible, and an `Incomplete` batch (stuck in `Registering` past its lead) expires and is
// never usable (I-2 / §9.5).
// =============================================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum PalwBatchStatus {
    /// No manifest seen yet.
    Missing,
    /// Manifest accepted; awaiting all leaf chunks + bonds.
    Registering,
    /// All chunks + bonds present; awaiting the audit beacon.
    Committed,
    /// Audit beacon reached; canary audit in progress.
    Auditing,
    /// Certificate quorum reached; awaiting the ≥ 1-epoch activation delay.
    Certified,
    /// Live and block-eligible.
    Active,
    /// Failed audit → bonds slashed (terminal).
    Slashed,
    /// Timed out (incomplete / not-activated / expired) (terminal).
    Expired,
    /// Post-activation fraud evidence → revoked (terminal, non-retroactive; §9.5).
    Revoked,
}

/// Events that drive [`PalwBatchStatus`] transitions (design §9.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PalwBatchEvent {
    ManifestAccepted,
    ChunksAndBondsComplete,
    AuditBeaconReached,
    CertificateQuorum,
    AuditFailed,
    /// Registration / audit / certified-not-activated timeout.
    Timeout,
    /// The activation epoch was reached (caller enforces the ≥ 1-epoch delay from `Certified`).
    ActivationReached,
    ExpiryReached,
    FraudEvidence,
}

impl PalwBatchStatus {
    /// The next status for `(self, event)`, or `None` if the transition is invalid (rejected). Pure.
    pub fn next(self, event: PalwBatchEvent) -> Option<PalwBatchStatus> {
        use PalwBatchEvent::*;
        use PalwBatchStatus::*;
        Some(match (self, event) {
            (Missing, ManifestAccepted) => Registering,
            (Registering, ChunksAndBondsComplete) => Committed,
            (Registering, Timeout) => Expired, // incomplete batch → never block-eligible
            (Committed, AuditBeaconReached) => Auditing,
            (Auditing, CertificateQuorum) => Certified,
            (Auditing, AuditFailed) => Slashed,
            (Auditing, Timeout) => Expired,
            (Certified, ActivationReached) => Active,
            (Certified, ExpiryReached) => Expired, // certified but never activated in time
            (Certified, FraudEvidence) => Revoked,
            (Active, ExpiryReached) => Expired,
            (Active, FraudEvidence) => Revoked,
            _ => return None,
        })
    }

    /// Only an `Active` batch can back a block (design §9.5 / §14.2).
    #[inline]
    pub fn is_block_eligible(self) -> bool {
        self == PalwBatchStatus::Active
    }

    /// Terminal states have no outgoing transitions.
    #[inline]
    pub fn is_terminal(self) -> bool {
        matches!(self, PalwBatchStatus::Slashed | PalwBatchStatus::Expired | PalwBatchStatus::Revoked)
    }
}

// =============================================================================================
// Component-work cap — the D4 security bound (design §5.3, §15.5). Pure big-int arithmetic over
// `BlueWorkType`; the GHOSTDAG finalization slice calls these. Even a total forgery of the PALW /
// DNS-certificate stack amplifies an attacker's own hash work by at most `(cap+1)×` (5× at cap 4):
// `E = H + min(C, cap·H)`, so `H ≤ E ≤ (cap+1)·H` (invariant I-1).
// =============================================================================================

/// The canonical compute-to-hash cap ratio (design §5.3, invariant I-1): certified compute work is
/// credited into effective GHOSTDAG work at most `COMPUTE_TO_HASH_CAP ×` the cumulative hash work, so
/// `H ≤ E ≤ (COMPUTE_TO_HASH_CAP + 1)·H`. Single source of truth shared by [`PalwParams`] and the
/// GHOSTDAG finalization path so the two can never drift.
pub const COMPUTE_TO_HASH_CAP: u64 = 4;

/// The capped compute-work term: `min(compute_work, cap · hash_work)` (design §15.5). Saturating on
/// the `cap · hash_work` multiply so a pathological hash work near `BlueWorkType::MAX` cannot wrap.
#[inline]
pub fn capped_compute_work(compute_work: BlueWorkType, hash_work: BlueWorkType, compute_to_hash_cap: u64) -> BlueWorkType {
    let (cap_h, overflow) = hash_work.overflowing_mul_u64(compute_to_hash_cap);
    let cap_h = if overflow { BlueWorkType::MAX } else { cap_h };
    core::cmp::min(compute_work, cap_h)
}

/// Effective blue work `E = H + min(C, cap·H)` (design §5.3). This is the single value that enters
/// fork choice as the legacy `blue_work`; the components `H`/`C` are carried separately in Header v3
/// but are never fork-choice tie-breakers. Saturating add so `E` cannot wrap.
#[inline]
pub fn effective_blue_work(hash_work: BlueWorkType, compute_work: BlueWorkType, compute_to_hash_cap: u64) -> BlueWorkType {
    hash_work.saturating_add(capped_compute_work(compute_work, hash_work, compute_to_hash_cap))
}

// =============================================================================================
// Deterministic selection (provider pair §8.1, auditors §10.2) + coinbase pair split (§17.3).
// All pure and beacon-seeded — the requester cannot choose the pair, and every node derives the
// same auditors / split.
// =============================================================================================

/// Beacon-seeded provider index (design §8.1): `H(seed ‖ job_capability ‖ which ‖ attempt) mod
/// count`. `which` is 0 (provider A) or 1 (provider B); `attempt` salts rejection re-sampling when a
/// derived pair fails the distinctness / operator-group / region constraints. `count` must be > 0.
pub fn provider_index(seed: &Hash64, job_capability: &Hash64, which: u8, attempt: u32, count: u64) -> u64 {
    let mut p = Vec::with_capacity(2 * HASH64_SIZE + 1 + 4);
    push_hash(&mut p, seed);
    push_hash(&mut p, job_capability);
    p.push(which);
    p.extend_from_slice(&attempt.to_le_bytes());
    let d = blake2b_512_keyed(PALW_PROVIDER_SELECT_DOMAIN, &p);
    digest_low_u64(&d) % count.max(1)
}

/// Rejection-sample a distinct, acceptable provider pair (design §8.1). `accept(a, b)` encodes the
/// richer constraints the caller can check (distinct bond outpoint / operator group / region / relay
/// session) against its bond view; distinctness `a != b` is always enforced here. Returns `None` if
/// no acceptable pair is found within `max_attempts` (or `count < 2`).
pub fn select_provider_pair(seed: &Hash64, job_capability: &Hash64, count: u64, max_attempts: u32, accept: impl Fn(u64, u64) -> bool) -> Option<(u64, u64)> {
    if count < 2 {
        return None;
    }
    for attempt in 0..max_attempts {
        let a = provider_index(seed, job_capability, 0, attempt, count);
        let b = provider_index(seed, job_capability, 1, attempt, count);
        if a != b && accept(a, b) {
            return Some((a, b));
        }
    }
    None
}

/// Auditor selection weight (design §10.2): `H(R_{E-1} ‖ batch_id ‖ bond_outpoint)`. Auditors are the
/// bonds with the smallest scores; the registering provider and related bonds are excluded by the
/// caller *before* scoring.
pub fn auditor_score(prev_seed: &Hash64, batch_id: &Hash64, bond: &TransactionOutpoint) -> Hash64 {
    let mut p = Vec::with_capacity(2 * HASH64_SIZE + HASH64_SIZE + 4);
    push_hash(&mut p, prev_seed);
    push_hash(&mut p, batch_id);
    push_hash(&mut p, &bond.transaction_id);
    p.extend_from_slice(&bond.index.to_le_bytes());
    blake2b_512_keyed(PALW_AUDITOR_SELECT_DOMAIN, &p)
}

/// Deterministically pick the top-`count` auditors (smallest [`auditor_score`], ties broken by the
/// bond outpoint) from an already-filtered candidate set (design §10.2). Returns them in canonical
/// (score, outpoint) order so every node agrees.
pub fn select_top_auditors(prev_seed: &Hash64, batch_id: &Hash64, candidates: &[TransactionOutpoint], count: usize) -> Vec<TransactionOutpoint> {
    let mut scored: Vec<(Hash64, TransactionOutpoint)> = candidates.iter().map(|b| (auditor_score(prev_seed, batch_id, b), *b)).collect();
    scored.sort_by(|x, y| x.0.as_byte_slice().cmp(y.0.as_byte_slice()).then_with(|| x.1.transaction_id.as_byte_slice().cmp(y.1.transaction_id.as_byte_slice())).then(x.1.index.cmp(&y.1.index)));
    scored.into_iter().take(count).map(|(_, b)| b).collect()
}

/// PALW **algo-4** lane coinbase split (basis points, sums to 10 000), **asymmetric to the algo-3
/// hash lane** which keeps its 62 / 8 / 30. ADR-0039 §17.1 (amended 2026-07-13): the compute lane
/// routes a larger base to the LLM providers by HALVING the validator share 30 % → 15 %; the freed
/// 15 % goes to the GPU compute source, so the provider base is 62 % + 15 % = **77 %**. This is an
/// intentional trade of DNS-finality validator subsidy for compute incentive (§17, user decision), and
/// only on PALW blocks — hash-lane blocks are unchanged. At the frozen 8 : 32 BPS split the effective
/// validator subsidy across ALL blocks is ≈ 0.2·30 % + 0.8·15 % = **18 %** (down from 30 %).
pub const PALW_PROVIDER_BASE_BPS: u16 = 7700; // 77 % → provider pair (was 62 %; +15 pt taken from validator)
/// PALW algo-4 lane includer/assembler share — 8 %, unchanged from the hash lane.
pub const PALW_INCLUSION_BPS: u16 = 800;
/// PALW algo-4 lane validator share — 15 % (hash lane keeps 30 %). The halved compute-lane validator
/// subsidy is the source of the extra 15 % routed to providers via [`PALW_PROVIDER_BASE_BPS`].
pub const PALW_VALIDATOR_BPS: u16 = 1500;

/// Split the worker-base subsidy between the two providers of a **unique-blue** algo-4 source
/// (design §17.3): `pool = subsidy · base_bps / 10000`, `a = pool / 2`, `b = pool − a` (B gets the odd
/// sompi; A/B are ordered by canonical bond-outpoint order upstream). Pass [`PALW_PROVIDER_BASE_BPS`]
/// (77 %). Red/duplicate sources get 0 (see [`palw_red_or_duplicate_provider_reward`]).
pub fn provider_pair_split(subsidy: u64, base_bps: u16) -> (u64, u64) {
    let pool = (subsidy as u128 * base_bps as u128 / 10_000) as u64;
    let a = pool / 2;
    (a, pool - a)
}

/// A red / duplicate PALW source pays the provider pair **nothing** (design §17.4); the unminted base
/// is NOT redistributed to the current miner (it is unissued / security-reserve). This helper names
/// that rule at the type level.
#[inline]
pub const fn palw_red_or_duplicate_provider_reward() -> (u64, u64) {
    (0, 0)
}

// =============================================================================================
// Consensus parameters (design §24.5, §26). Testnet defaults; hard-fork-only knobs.
// =============================================================================================

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwParams {
    /// DAA score at which the PALW lane activates. `u64::MAX` = **inert** (never active).
    pub activation_daa_score: u64,
    pub total_bps: u64,
    pub hash_lane_bps: u64,
    pub replica_lane_bps: u64,
    /// `E = H + min(C, compute_to_hash_cap · H)` (design §5.3, invariant I-1).
    pub compute_to_hash_cap: u64,
    pub epoch_length_daa: u64,
    pub registration_lead_epochs: u64,
    pub audit_window_epochs: u64,
    pub active_window_epochs: u64,
    pub nullifier_retention_daa: u64,
    pub evidence_window_epochs: u64,
    pub max_batch_leaves: u32,
    pub max_leaf_chunk_leaves: u16,
    pub min_leaf_bond_sompi: u64,
    pub canary_sample_bps: u16,
    pub min_canaries_per_batch: u16,
    pub auditor_count: u16,
    pub auditor_quorum_num: u16,
    pub auditor_quorum_den: u16,
    pub dns_degraded_grace_epochs: u64,
    pub supported_profiles: Vec<Hash64>,
}

impl PalwParams {
    /// The design §26 testnet start values, at the committed 40-BPS split (hash 8 + replica 32,
    /// cap 4 = a permanent 20 % hash floor; epoch 400 DAA ≈ 10 s at 40 BPS; nullifier retention
    /// 4 800 DAA ≈ 120 s). **Inert by construction** (`activation_daa_score = u64::MAX`) — flipping a
    /// real activation score is a re-genesis / hard-fork decision, not a default.
    ///
    /// NOTE (ADR-0039 §"10 vs 40 BPS"): the lane proportion (1 : 4) and the hash-floor fraction
    /// (20 %) are identical at 10 BPS (2 + 8) — only `total_bps`, the two lane rates, and the
    /// wall-clock-preserving `*_daa` windows scale. Switching to a 10-BPS launch is a four-field edit
    /// here (`total/hash/replica_lane_bps`, `epoch_length_daa`, `nullifier_retention_daa`).
    pub fn testnet_inert_default() -> Self {
        Self {
            activation_daa_score: u64::MAX,
            total_bps: 40,
            hash_lane_bps: 8,
            replica_lane_bps: 32,
            compute_to_hash_cap: COMPUTE_TO_HASH_CAP,
            epoch_length_daa: 400,
            registration_lead_epochs: 2,
            audit_window_epochs: 6,
            active_window_epochs: 6,
            nullifier_retention_daa: 4_800,
            evidence_window_epochs: 60,
            max_batch_leaves: 256,
            max_leaf_chunk_leaves: PALW_MAX_LEAVES_PER_CHUNK as u16,
            min_leaf_bond_sompi: 0,
            canary_sample_bps: 100, // 1 %
            min_canaries_per_batch: 1,
            auditor_count: 16,
            auditor_quorum_num: 2,
            auditor_quorum_den: 3,
            dns_degraded_grace_epochs: 1,
            supported_profiles: Vec::new(),
        }
    }

    /// Never true for the inert default (`activation_daa_score = u64::MAX`).
    #[inline]
    pub fn is_active_at(&self, daa_score: u64) -> bool {
        daa_score >= self.activation_daa_score
    }

    /// Structural invariants the params must satisfy (design §5.2/§5.3/§16.3). Cheap; called at
    /// config-build time.
    pub fn is_structurally_valid(&self) -> bool {
        self.total_bps == self.hash_lane_bps + self.replica_lane_bps
            && self.hash_lane_bps > 0
            && self.replica_lane_bps > 0
            && self.compute_to_hash_cap > 0
            && self.epoch_length_daa > 0
            && self.active_window_epochs > 0
            && self.max_leaf_chunk_leaves as usize <= PALW_MAX_LEAVES_PER_CHUNK
            && self.auditor_quorum_den > 0
            && self.auditor_quorum_num <= self.auditor_quorum_den
            // the hash floor must be a positive fraction that the cap actually binds:
            // replica ≤ cap · hash keeps compute work ≤ cap× hash work at steady state.
            && self.replica_lane_bps <= self.compute_to_hash_cap * self.hash_lane_bps
    }
}

// =============================================================================================
// Tests — freeze the wire format + hash test vectors (design §33).
// =============================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_hashes::ZERO_HASH64;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }
    fn op(b: u8, i: u32) -> TransactionOutpoint {
        TransactionOutpoint::new(h(b), i)
    }
    fn spk(b: u8) -> ScriptPublicKey {
        ScriptPublicKey::from_vec(0, vec![b, b, b])
    }

    fn sample_leaf() -> PalwPublicLeafV1 {
        PalwPublicLeafV1 {
            version: 1,
            batch_id: h(1),
            leaf_index: 7,
            job_nullifier: h(2),
            ticket_nullifier: h(3),
            model_profile_id: h(4),
            runtime_class_id: h(5),
            shape_id: 9,
            quantum_count: 3,
            proof_type: PalwProofType::ReplicaExactV1.as_u8(),
            provider_a_bond: op(10, 0),
            provider_b_bond: op(11, 1),
            provider_a_reward_script: spk(0xa0),
            provider_b_reward_script: spk(0xb0),
            ticket_authority_pk_hash: h(6),
            private_match_commitment: h(7),
            receipt_da_root: h(8),
            registered_epoch: 100,
            activation_epoch: 102,
            expiry_epoch: 108,
            leaf_bond_sompi: 1_000,
        }
    }

    #[test]
    fn proof_type_roundtrips_and_pins_wire_bytes() {
        for (v, t) in [
            (1u8, PalwProofType::ReplicaExactV1),
            (2, PalwProofType::TeeRateLimitedV1),
            (3, PalwProofType::TransparentArgumentV1),
            (4, PalwProofType::WitnessHidingArgumentV1),
        ] {
            assert_eq!(t.as_u8(), v);
            assert_eq!(PalwProofType::from_u8(v), Some(t));
        }
        assert_eq!(PalwProofType::from_u8(0), None);
        assert_eq!(PalwProofType::from_u8(5), None);
    }

    #[test]
    fn leaf_borsh_roundtrip_and_hash_is_deterministic_and_sensitive() {
        let leaf = sample_leaf();
        let bytes = borsh::to_vec(&leaf).unwrap();
        let back = PalwPublicLeafV1::try_from_slice(&bytes).unwrap();
        assert_eq!(leaf, back);
        assert_eq!(leaf.proof_type(), Some(PalwProofType::ReplicaExactV1));

        // hash is deterministic ...
        assert_eq!(leaf.leaf_hash(), sample_leaf().leaf_hash());
        // ... and changes on any field mutation.
        let mut m = sample_leaf();
        m.leaf_index = 8;
        assert_ne!(leaf.leaf_hash(), m.leaf_hash());
        let mut m2 = sample_leaf();
        m2.ticket_nullifier = h(0x33);
        assert_ne!(leaf.leaf_hash(), m2.leaf_hash());
    }

    #[test]
    fn hash_helpers_are_domain_separated_and_sensitive() {
        // distinct domains → distinct digests over the same-looking inputs.
        let cc = chain_commit(&h(1), &h(2), 5, 7);
        let sd = slot_digest(&h(1), &h(2), 5, &h(7));
        assert_ne!(cc, sd);
        assert_ne!(cc, ZERO_HASH64);

        // chain_commit is sensitive to the target interval (no per-fork re-roll of the same slot).
        assert_ne!(chain_commit(&h(1), &h(2), 5, 7), chain_commit(&h(1), &h(2), 6, 7));

        // eligibility is sensitive to the nullifier and the interval.
        let e1 = eligibility_hash(7, &h(1), &cc, 5, &h(2), 3, &h(4), &h(9));
        let e2 = eligibility_hash(7, &h(1), &cc, 5, &h(2), 3, &h(4), &h(0xA));
        assert_ne!(e1, e2);

        // slot draw stays inside the window and is deterministic.
        let t = target_daa_interval(1000, 600, &sd);
        assert!((1000..1600).contains(&t));
        assert_eq!(t, target_daa_interval(1000, 600, &sd));
    }

    #[test]
    fn beacon_commit_reveal_binds() {
        let bond = op(0x20, 4);
        let r = [0x5Au8; 64];
        let commitment = beacon_commitment(9, &r, &bond);
        let reveal = PalwBeaconRevealV1 { version: 1, epoch: 9, bond_outpoint: bond, random_64: r, signature: vec![] };
        assert!(reveal.matches_commit(&commitment));
        // wrong epoch / wrong randomness / wrong bond all break the binding.
        assert!(!reveal.matches_commit(&beacon_commitment(10, &r, &bond)));
        assert!(!reveal.matches_commit(&beacon_commitment(9, &[0x5Bu8; 64], &bond)));
        assert!(!reveal.matches_commit(&beacon_commitment(9, &r, &op(0x21, 4))));
    }

    #[test]
    fn receipt_hash_vs_signing_hash_differ_and_match_commitment() {
        let base = ReplicaExecutionReceiptV1 {
            version: 1,
            provider_bond: op(0x30, 0),
            session_public_key: vec![1, 2, 3],
            job_nullifier: h(1),
            job_set_commitment: h(2),
            model_profile_id: h(3),
            runtime_class_id: h(4),
            shape_id: 9,
            quantum_count: 3,
            output_commitment: h(5),
            canonical_gemm_trace_root: h(6),
            operation_schedule_commitment: h(7),
            receipt_da_root: h(8),
            completed_at_epoch: 100,
            signature: vec![0xAA; 16],
        };
        // signing_hash excludes the signature; full hash includes it → they differ.
        assert_ne!(base.signing_hash(), base.hash());
        // signing_hash is stable regardless of the signature bytes; full hash is not.
        let mut resigned = base.clone();
        resigned.signature = vec![0xBB; 16];
        assert_eq!(base.signing_hash(), resigned.signing_hash());
        assert_ne!(base.hash(), resigned.hash());

        // private_match_commitment binds both receipt hashes.
        let a = base.hash();
        let b = resigned.hash();
        let cm = private_match_commitment(&base.output_commitment, &base.canonical_gemm_trace_root, &base.operation_schedule_commitment, &base.job_set_commitment, &a, &b);
        assert_ne!(cm, private_match_commitment(&base.output_commitment, &base.canonical_gemm_trace_root, &base.operation_schedule_commitment, &base.job_set_commitment, &b, &a));
    }

    #[test]
    fn chunk_and_certificate_borsh_roundtrip() {
        let chunk = PalwLeafChunkV1 { version: 1, batch_id: h(1), chunk_index: 0, leaves: vec![sample_leaf(), sample_leaf()] };
        let back = PalwLeafChunkV1::try_from_slice(&borsh::to_vec(&chunk).unwrap()).unwrap();
        assert_eq!(chunk, back);
        assert!(chunk.leaves.len() <= PALW_MAX_LEAVES_PER_CHUNK);

        let cert = PalwBatchCertificateV1 {
            version: 1,
            batch_id: h(1),
            manifest_hash: h(2),
            leaf_root: h(3),
            audit_beacon_epoch: 5,
            audit_sample_root: h(4),
            passed_leaf_count: 2,
            rejected_leaf_bitmap_root: ZERO_HASH64,
            certificate_epoch: 6,
            activation_epoch: 7,
            expiry_epoch: 13,
            auditor_set_commitment: h(5),
            votes: vec![PalwAuditorVoteV1 { bond_outpoint: op(0x40, 0), vote: 1, checked_leaf_bitmap_root: h(6), signature: vec![9; 4] }],
        };
        let cback = PalwBatchCertificateV1::try_from_slice(&borsh::to_vec(&cert).unwrap()).unwrap();
        assert_eq!(cert, cback);
        assert!(cert.is_active_at(7) && cert.is_active_at(12));
        assert!(!cert.is_active_at(6) && !cert.is_active_at(13));
    }

    #[test]
    fn params_default_is_inert_and_structurally_valid() {
        let p = PalwParams::testnet_inert_default();
        assert_eq!(p.activation_daa_score, u64::MAX);
        assert!(!p.is_active_at(0));
        assert!(!p.is_active_at(u64::MAX - 1));
        assert!(p.is_structurally_valid());
        // the committed 40-BPS split: 8 + 32 = 40, 1:4 cap, 20 % hash floor.
        assert_eq!(p.total_bps, 40);
        assert_eq!(p.hash_lane_bps + p.replica_lane_bps, p.total_bps);
        assert_eq!(p.replica_lane_bps, p.compute_to_hash_cap * p.hash_lane_bps);
        assert_eq!(p.hash_lane_bps * 5, p.total_bps); // 8/40 = 20 %

        // borsh roundtrip.
        let back = PalwParams::try_from_slice(&borsh::to_vec(&p).unwrap()).unwrap();
        assert_eq!(p, back);

        // a malformed split is rejected.
        let mut bad = p.clone();
        bad.replica_lane_bps = 33; // 8 + 33 != 40 and 33 > 4·8
        assert!(!bad.is_structurally_valid());
    }

    fn w(n: u64) -> BlueWorkType {
        BlueWorkType::from_u64(n)
    }

    #[test]
    fn compute_cap_bounds_effective_work() {
        // §27.6 property tests, cap = 4:
        // (1) C_eff <= cap·H; (2) E = H + C_eff; (3) H <= E <= (cap+1)·H; (4) monotonic; (5) headroom.
        let cap = 4u64;
        for &hh in &[0u64, 1, 7, 1000, 1_000_000] {
            for &cc in &[0u64, 1, hh, 4 * hh, 4 * hh + 5, 100 * hh + 3] {
                let h = w(hh);
                let c = w(cc);
                let ceff = capped_compute_work(c, h, cap);
                let e = effective_blue_work(h, c, cap);
                // C_eff <= cap·H and C_eff <= C.
                assert!(ceff <= w(cap * hh), "C_eff must be <= 4H (H={hh}, C={cc})");
                assert!(ceff <= c);
                // E = H + C_eff.
                assert_eq!(e, h.saturating_add(ceff));
                // H <= E <= 5H.
                assert!(e >= h, "E >= H (H={hh}, C={cc})");
                assert!(e <= w(5 * hh), "E <= 5H (H={hh}, C={cc})");
            }
        }
    }

    #[test]
    fn compute_cap_monotonic_and_headroom_exhaustion() {
        let cap = 4u64;
        let h = w(100);
        // monotonic in compute up to the cap, then flat (headroom exhausted).
        let mut prev = effective_blue_work(h, w(0), cap);
        for cc in [10u64, 50, 100, 300, 400, 401, 500, 10_000] {
            let e = effective_blue_work(h, w(cc), cap);
            assert!(e >= prev, "E must be monotonic non-decreasing in C");
            prev = e;
        }
        // once C >= cap·H the effective work is pinned at (cap+1)·H — extra compute is worthless
        // (design §5.4: zero-headroom PALW blocks are not accepted, so this pin is never exceeded).
        assert_eq!(effective_blue_work(h, w(400), cap), w(500));
        assert_eq!(effective_blue_work(h, w(400), cap), effective_blue_work(h, w(10_000_000), cap));
    }

    #[test]
    fn compute_cap_saturates_and_zero_hash_zeroes_compute() {
        // zero hash floor ⇒ zero credited compute (a compute-only block earns nothing; §5.4).
        assert_eq!(effective_blue_work(w(0), w(1_000_000), 4), w(0));
        assert_eq!(capped_compute_work(w(1_000_000), w(0), 4), w(0));
        // saturating: cap·H near MAX must not wrap.
        let big = BlueWorkType::MAX;
        let capped = capped_compute_work(big, big, 4);
        assert_eq!(capped, big); // min(MAX, sat(4·MAX)=MAX) = MAX
        assert_eq!(effective_blue_work(big, big, 4), big); // sat(MAX + MAX) = MAX
    }

    #[test]
    fn batch_state_machine_happy_path_and_terminals() {
        use PalwBatchEvent::*;
        use PalwBatchStatus::*;
        // full happy path Missing → ... → Active.
        let mut s = Missing;
        for (ev, expect) in [
            (ManifestAccepted, Registering),
            (ChunksAndBondsComplete, Committed),
            (AuditBeaconReached, Auditing),
            (CertificateQuorum, Certified),
            (ActivationReached, Active),
        ] {
            s = s.next(ev).unwrap();
            assert_eq!(s, expect);
            assert!(!s.is_terminal());
        }
        assert!(s.is_block_eligible());

        // only Active is block-eligible.
        for st in [Missing, Registering, Committed, Auditing, Certified, Slashed, Expired, Revoked] {
            assert!(!st.is_block_eligible());
        }

        // fraud after activation revokes; expiry expires.
        assert_eq!(Active.next(FraudEvidence), Some(Revoked));
        assert_eq!(Active.next(ExpiryReached), Some(Expired));
    }

    #[test]
    fn batch_state_machine_rejects_invalid_and_terminal_transitions() {
        use PalwBatchEvent::*;
        use PalwBatchStatus::*;
        // an incomplete batch (Registering + timeout) expires and can never become Active.
        assert_eq!(Registering.next(Timeout), Some(Expired));
        // a failed audit slashes.
        assert_eq!(Auditing.next(AuditFailed), Some(Slashed));
        // terminal states have no outgoing edges for any event.
        for term in [Slashed, Expired, Revoked] {
            assert!(term.is_terminal());
            for ev in [ManifestAccepted, ChunksAndBondsComplete, AuditBeaconReached, CertificateQuorum, AuditFailed, Timeout, ActivationReached, ExpiryReached, FraudEvidence] {
                assert_eq!(term.next(ev), None, "{term:?} must be terminal for {ev:?}");
            }
        }
        // out-of-order events are rejected (e.g. activate before certified, quorum before auditing).
        assert_eq!(Missing.next(ChunksAndBondsComplete), None);
        assert_eq!(Committed.next(ActivationReached), None);
        assert_eq!(Registering.next(CertificateQuorum), None);
        assert_eq!(Active.next(CertificateQuorum), None);
    }

    #[test]
    fn provider_pair_selection_is_deterministic_distinct_and_gated() {
        let seed = h(0x51);
        let cap = h(0x52); // job capability
        // deterministic + distinct + within range.
        let (a, b) = select_provider_pair(&seed, &cap, 10, 32, |_, _| true).unwrap();
        assert!(a < 10 && b < 10 && a != b);
        assert_eq!(select_provider_pair(&seed, &cap, 10, 32, |_, _| true), Some((a, b)));
        // count < 2 ⇒ no pair.
        assert_eq!(select_provider_pair(&seed, &cap, 1, 32, |_, _| true), None);
        // the accept predicate is honored: reject the found pair ⇒ re-sample to a different pair
        // (or None). Rejecting *everything* yields None.
        assert_eq!(select_provider_pair(&seed, &cap, 10, 32, |_, _| false), None);
        // rejecting the specific first pair forces a different acceptable one.
        let alt = select_provider_pair(&seed, &cap, 10, 32, |x, y| (x, y) != (a, b));
        assert!(alt.is_some() && alt != Some((a, b)));
    }

    #[test]
    fn auditor_selection_is_deterministic_and_score_bounded() {
        let prev = h(0x61);
        let batch = h(0x62);
        let bonds: Vec<TransactionOutpoint> = (0..8).map(|i| op(0x70 + i, i as u32)).collect();
        let top3 = select_top_auditors(&prev, &batch, &bonds, 3);
        assert_eq!(top3.len(), 3);
        // deterministic.
        assert_eq!(top3, select_top_auditors(&prev, &batch, &bonds, 3));
        // the chosen three are exactly the smallest-score bonds.
        let mut all: Vec<(Hash64, TransactionOutpoint)> = bonds.iter().map(|b| (auditor_score(&prev, &batch, b), *b)).collect();
        all.sort_by(|x, y| x.0.as_byte_slice().cmp(y.0.as_byte_slice()));
        let expect: Vec<TransactionOutpoint> = all.into_iter().take(3).map(|(_, b)| b).collect();
        assert_eq!(top3, expect);
        // a different batch id reshuffles the winners (score depends on batch).
        assert_ne!(select_top_auditors(&prev, &h(0x63), &bonds, 3), top3);
    }

    #[test]
    fn coinbase_provider_split_is_77pct_halved_with_odd_to_b() {
        // ADR-0039 §17.1 (amended): the PALW-lane split is 77 / 8 / 15 and sums to 10 000.
        assert_eq!(PALW_PROVIDER_BASE_BPS + PALW_INCLUSION_BPS + PALW_VALIDATOR_BPS, 10_000);
        assert_eq!(PALW_PROVIDER_BASE_BPS, 7700);
        assert_eq!(PALW_VALIDATOR_BPS, 1500);
        // 77 % of 1000 = 770; 770/2 = 385 each.
        assert_eq!(provider_pair_split(1000, PALW_PROVIDER_BASE_BPS), (385, 385));
        // odd pool → B gets the extra sompi, and a+b == pool exactly (no minting/burning).
        let (a, b) = provider_pair_split(999, PALW_PROVIDER_BASE_BPS); // pool = 769
        assert_eq!((a, b), (384, 385));
        assert_eq!(a + b, (999u128 * 7700 / 10_000) as u64);
        // red/duplicate ⇒ nothing to the pair.
        assert_eq!(palw_red_or_duplicate_provider_reward(), (0, 0));
        // no overflow for a large subsidy.
        let (a, b) = provider_pair_split(u64::MAX, PALW_PROVIDER_BASE_BPS);
        assert_eq!(a + b, (u64::MAX as u128 * 7700 / 10_000) as u64);
    }

    #[test]
    fn domain_strings_are_pinned_and_fit_key_limit() {
        assert_eq!(PALW_LEAF_DOMAIN, b"misaka-palw-v1/leaf");
        assert_eq!(PALW_CHAIN_COMMIT_DOMAIN, b"misaka-palw-chain-commit-v1");
        assert_eq!(PALW_SLOT_DOMAIN, b"misaka-palw-slot-v1");
        assert_eq!(PALW_ELIGIBILITY_DOMAIN, b"misaka-palw-eligibility-v1");
        assert_eq!(PALW_BEACON_DOMAIN, b"misaka-palw-beacon-v1");
        assert_eq!(PALW_BEACON_COMMIT_DOMAIN, b"misaka-palw-beacon-commit-v1");
        assert_eq!(PALW_MATCH_DOMAIN, b"misaka-palw-match-v1");
        assert_eq!(PALW_RECEIPT_DOMAIN, b"misaka-palw-replica-receipt-v1");
        assert_eq!(PALW_PROVIDER_SELECT_DOMAIN, b"misaka-palw-provider-select-v1");
        assert_eq!(PALW_AUDITOR_SELECT_DOMAIN, b"misaka-palw-auditor-select-v1");
        for d in [
            PALW_LEAF_DOMAIN,
            PALW_CHAIN_COMMIT_DOMAIN,
            PALW_SLOT_DOMAIN,
            PALW_ELIGIBILITY_DOMAIN,
            PALW_BEACON_DOMAIN,
            PALW_BEACON_COMMIT_DOMAIN,
            PALW_MATCH_DOMAIN,
            PALW_RECEIPT_DOMAIN,
            PALW_PROVIDER_SELECT_DOMAIN,
            PALW_AUDITOR_SELECT_DOMAIN,
        ] {
            assert!(d.len() <= 64, "domain {:?} exceeds BLAKE2b key limit", core::str::from_utf8(d));
        }
    }
}
