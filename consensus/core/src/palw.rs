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
use crate::dns_finality::{STAKE_ATTESTATION_SIG_LEN, STAKE_VALIDATOR_PUBKEY_LEN};
use crate::pow_layer0::{POW_ALGO_ID_BLAKE2B_SHA3, POW_ALGO_ID_PALW_REPLICA, WorkLane};
use crate::tx::{ScriptPublicKey, TransactionOutpoint};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{HASH64_SIZE, Hash64, blake2b_512_keyed};
use kaspa_math::Uint512;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::{self, Display, Formatter};

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
/// `dns_finality_certificate_hash_v1` — clause 6's confirmation-evidence digest over ANCHOR-pure facts
/// (design §12.1; panel-frozen v1 preimage: `anchor_hash ‖ blue ‖ daa ‖ anchor_overlay_root`).
pub const PALW_DNS_CERT_DOMAIN: &[u8] = b"misaka-palw-dns-cert-v1";
/// `PalwAuditorVoteV1` signing message (§10.1, I-14 DA-possession binding) — an auditor's vote
/// signature covers the beacon-selected `audit_sample_root`, so a certificate cannot be signed without
/// first identifying (hence fetching) the beacon-selected receipt chunks.
pub const PALW_AUDITOR_VOTE_DOMAIN: &[u8] = b"misaka-palw-auditor-vote-v1";
/// `ticket_nullifier_commitment = Hash64_k(ticket-nullifier-commit, ticket_nullifier)` (§12.3, I-13) —
/// the leaf publishes only this commitment; the raw `ticket_nullifier` is disclosed at header-use time.
/// A one-way commitment (the 64-byte nullifier is not guessable), so a third party who reads the public
/// leaf CANNOT compute `eligibility_hash` in advance and pre-list the epoch's interval winners.
pub const PALW_TICKET_NULLIFIER_COMMIT_DOMAIN: &[u8] = b"misaka-palw-ticket-nf-commit-v1";
/// `leaf_root = Hash64_k(leaf-root, count ‖ leaf_hash[0] ‖ … ‖ leaf_hash[n-1])` (§9.3) — the manifest's
/// commitment to its ORDERED leaf set. C4 content-addressing: the leaf store is fork-safe (write-once by
/// collision resistance) only because a batch's leaves must reduce to this root.
pub const PALW_LEAF_ROOT_DOMAIN: &[u8] = b"misaka-palw-leaf-root-v1";
/// `batch_id = content_id = Hash64_k(batch-id, borsh(manifest with batch_id zeroed))` (§9.2) — C4
/// content-addressing: `batch_id` must equal the hash of the manifest's OWN content (batch_id excluded,
/// as it is self-referential), so no two forks can register different manifests under one `batch_id`.
pub const PALW_BATCH_ID_DOMAIN: &[u8] = b"misaka-palw-batch-id-v1";
/// ML-DSA signing hash for [`PalwBeaconCommitV1`]. Separate from both the commitment construction
/// and reveal signature domains, so a signature is not reusable across beacon operations.
pub const PALW_BEACON_COMMIT_SIGNING_DOMAIN: &[u8] = b"misaka-palw-beacon-commit-sign-v1";
/// ML-DSA signing hash for [`PalwBeaconRevealV1`].
pub const PALW_BEACON_REVEAL_SIGNING_DOMAIN: &[u8] = b"misaka-palw-beacon-reveal-sign-v1";
/// ML-DSA-87 context used for both beacon operations. Commit/reveal replay separation lives in the
/// distinct signing-hash domains above; this context keeps PALW beacon signatures disjoint from DNS
/// attestations, unbond requests, and transaction-script signatures at the FIPS-204 layer as well.
pub const PALW_BEACON_MLDSA87_CONTEXT: &[u8] = b"PALWBeaconV1";
/// Digest of an opened reveal's secret entropy. This is deliberately distinct from
/// [`PALW_BEACON_COMMIT_DOMAIN`]: the public commitment is known in `E-2` and therefore MUST NOT be
/// reused as the `R_E` entropy input once the reveal arrives in `E-1`.
pub const PALW_BEACON_REVEAL_ENTROPY_DOMAIN: &[u8] = b"misaka-palw-beacon-reveal-entropy-v1";
/// `valid_reveals_root` — canonical-sorted keyed hash of the `(bond, reveal_entropy_digest)` set
/// whose reveal validly opened its commit this epoch (design §11.2, a `beacon_seed` input).
pub const PALW_BEACON_REVEALS_ROOT_DOMAIN: &[u8] = b"misaka-palw-beacon-reveals-root-v1";
/// `missing_commitments_root` — canonical-sorted keyed hash of the `(bond, commitment)` set that
/// committed but did not validly reveal this epoch (design §11.2, a `beacon_seed` input; the missing
/// set is what a later slice slashes).
pub const PALW_BEACON_MISSING_ROOT_DOMAIN: &[u8] = b"misaka-palw-beacon-missing-root-v1";
/// `private_match_commitment` binding the two provider receipts to the leaf (design §24.2).
pub const PALW_MATCH_DOMAIN: &[u8] = b"misaka-palw-match-v1";
/// `receipt_hash = Hash64_k(replica-receipt, borsh(ReplicaExecutionReceiptV1))` — leaf-committed
/// provider receipt hash (design §24.1).
pub const PALW_RECEIPT_DOMAIN: &[u8] = b"misaka-palw-replica-receipt-v1";
/// Provider-pair selection from the prior-epoch beacon seed (design §8.1).
pub const PALW_PROVIDER_SELECT_DOMAIN: &[u8] = b"misaka-palw-provider-select-v1";
/// Auditor selection weight from the prior-epoch beacon seed (design §10.2).
pub const PALW_AUDITOR_SELECT_DOMAIN: &[u8] = b"misaka-palw-auditor-select-v1";
/// R4 anti-griefing (design §24.5) — deterministic per-mismatch escalation draw from the audit beacon.
pub const PALW_MISMATCH_ESCALATE_DOMAIN: &[u8] = b"misaka-palw-mismatch-escalate-v1";

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
pub fn chain_commit(
    dns_finalized_checkpoint: &Hash64,
    dns_finality_certificate: &Hash64,
    target_interval: u64,
    network_id: u32,
) -> Hash64 {
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

/// ADR-0039 §12.3 — the one-shot eligibility DRAW acceptance: `Uint512(eligibility_digest) <=
/// target_512(bits)` AND the canonical algo-4 `nonce == low64(ticket_nullifier)` (the nonce is pinned
/// to the nullifier so it cannot be ground, I-3). Pure; `eligibility_digest` is [`eligibility_hash`].
/// ADR-0039 §12.3 / I-13 — the leaf's public commitment to its `ticket_nullifier`. The raw nullifier is
/// disclosed only when the ticket's header is minted; verification checks
/// `ticket_nullifier_commitment(header.palw_ticket_nullifier) == leaf.ticket_nullifier_commitment`. This
/// makes a ticket's future eligibility computable ONLY by the ticket holder (who knows the raw
/// nullifier), never by a third party reading the on-chain leaf — closing the pre-computable-winner
/// targeted-DoS / censorship / bribery channel.
pub fn ticket_nullifier_commitment(ticket_nullifier: &Hash64) -> Hash64 {
    blake2b_512_keyed(PALW_TICKET_NULLIFIER_COMMIT_DOMAIN, ticket_nullifier.as_byte_slice())
}

pub fn palw_eligibility_win(eligibility_digest: &Hash64, bits: u32, nonce: u64, ticket_nullifier: &Hash64) -> bool {
    let e = Uint512::from_le_bytes(*eligibility_digest.as_byte_slice());
    let target = Uint512::from_compact_target_bits_512(bits);
    e <= target && nonce == digest_low_u64(ticket_nullifier)
}

/// The resolved leaf/certificate facts a Header-v3 must match (design §14.2). The stores
/// (`leaf_store` / `certificate_store` / `beacon_store`) produce this; [`verify_palw_ticket`] is the
/// pure predicate over it, so consensus construction and validation share one acceptance rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PalwTicketBinding {
    /// I-13: the leaf's published commitment. The verify checks
    /// `ticket_nullifier_commitment(header.palw_ticket_nullifier) == this` (not raw equality).
    pub ticket_nullifier_commitment: Hash64,
    pub proof_type: u8,
    /// Leaf active window (epochs): `[leaf_activation_epoch, leaf_expiry_epoch)`.
    pub leaf_activation_epoch: u64,
    pub leaf_expiry_epoch: u64,
    /// The single DAA interval this leaf may draw in (§12.2). Must equal the header's `daa_score`.
    pub target_daa_interval: u64,
}

/// The first §14.2 rule an algo-4 header violates, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PalwTicketReject {
    NullifierMismatch,
    ProofTypeMismatch,
    LeafNotActive,
    CertNotActive,
    IntervalMismatch,
    ChainCommitMismatch,
    LaneBitsMismatch,
    ComputeCapExhausted,
    EligibilityMiss,
}

/// ADR-0039 §14.2 — the pure acceptance predicate for an algo-4 (PALW) header, given its own fields,
/// the resolved leaf/cert `binding`, and the consensus-derived expectations (`cert_active` =
/// `cert.is_active_at(daa_score)`, `epoch` = `ctx.epoch(daa_score)`, `expected_chain_commit` /
/// `expected_bits` from the lagged checkpoint + lane DAA, `compute_headroom_positive` = `E`-cap not
/// exhausted). Deterministic and store-free, so the header-verifier and the mining-template builder
/// apply the identical rule (construction == validation). Returns the first violated rule.
#[allow(clippy::too_many_arguments)]
pub fn verify_palw_ticket(
    h_nullifier: &Hash64,
    h_proof_type: u8,
    h_chain_commit: &Hash64,
    h_bits: u32,
    h_nonce: u64,
    h_daa_score: u64,
    eligibility_digest: &Hash64,
    binding: &PalwTicketBinding,
    cert_active: bool,
    epoch: u64,
    expected_chain_commit: &Hash64,
    expected_bits: u32,
    compute_headroom_positive: bool,
) -> Result<(), PalwTicketReject> {
    // Clauses 1–5 (nullifier / proof-type / leaf-active / cert-active / interval) — the store+epoch
    // resolvable subset, shared with the header pipeline (see `verify_palw_ticket_store_facts`).
    verify_palw_ticket_store_facts(h_nullifier, h_proof_type, h_daa_score, binding, cert_active, epoch)?;
    if h_chain_commit != expected_chain_commit {
        return Err(PalwTicketReject::ChainCommitMismatch);
    }
    if h_bits != expected_bits {
        return Err(PalwTicketReject::LaneBitsMismatch);
    }
    // §5.4: a zero-headroom compute lane produces / accepts no algo-4 block (no free blue score).
    if !compute_headroom_positive {
        return Err(PalwTicketReject::ComputeCapExhausted);
    }
    if !palw_eligibility_win(eligibility_digest, h_bits, h_nonce, h_nullifier) {
        return Err(PalwTicketReject::EligibilityMiss);
    }
    Ok(())
}

/// ADR-0039 §14.2 clauses 1–5 — the subset of the algo-4 acceptance rule that is fully determined by
/// the header, the store-resolved leaf/cert `binding`, and the consensus `epoch`, with no dependency on
/// the beacon (`R_E`), lane-DAA retarget, lagged checkpoint, or compute-cap state. [`verify_palw_ticket`]
/// runs this first; the header pipeline runs *only* this while those later consensus-state slices are
/// still inert, so there is a single, non-divergent source for these five rules. Returns the first
/// violated clause.
pub fn verify_palw_ticket_store_facts(
    h_nullifier: &Hash64,
    h_proof_type: u8,
    h_daa_score: u64,
    binding: &PalwTicketBinding,
    cert_active: bool,
    epoch: u64,
) -> Result<(), PalwTicketReject> {
    // I-13: the header DISCLOSES the raw nullifier; it must open the leaf's published commitment.
    if ticket_nullifier_commitment(h_nullifier) != binding.ticket_nullifier_commitment {
        return Err(PalwTicketReject::NullifierMismatch);
    }
    if h_proof_type != binding.proof_type {
        return Err(PalwTicketReject::ProofTypeMismatch);
    }
    if !(binding.leaf_activation_epoch <= epoch && epoch < binding.leaf_expiry_epoch) {
        return Err(PalwTicketReject::LeafNotActive);
    }
    if !cert_active {
        return Err(PalwTicketReject::CertNotActive);
    }
    if h_daa_score != binding.target_daa_interval {
        return Err(PalwTicketReject::IntervalMismatch);
    }
    Ok(())
}

/// ADR-0039 §9.3 / I-2 — a batch is block-eligible only once **every** leaf chunk is on-chain: a batch
/// missing any of its manifest's `chunk_count` chunks stays `Incomplete` and can never certify (no
/// hidden leaves). Tracks which chunk indices have been seen; deterministic and idempotent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PalwBatchChunkTracker {
    chunk_count: u32,
    received: BTreeSet<u32>,
}

impl PalwBatchChunkTracker {
    pub fn new(chunk_count: u32) -> Self {
        Self { chunk_count, received: BTreeSet::new() }
    }

    /// Record a chunk index; returns `false` if out of range (`>= chunk_count`) or already recorded.
    pub fn record(&mut self, chunk_index: u32) -> bool {
        if chunk_index >= self.chunk_count {
            return false;
        }
        self.received.insert(chunk_index)
    }

    /// True once all `chunk_count` chunks are present (the batch may leave `Incomplete`).
    pub fn is_complete(&self) -> bool {
        self.received.len() as u32 == self.chunk_count
    }

    pub fn missing_count(&self) -> u32 {
        self.chunk_count - self.received.len() as u32
    }
}

/// ADR-0039 §18 (I-6) — the data-availability check that a batch's on-chain / pruning-bundle state is
/// complete enough to verify without out-of-band data: the manifest, all leaf chunks, the certificate,
/// and the beacon state must all be present. Pure boolean over the resolved presence flags.
pub fn palw_da_bundle_complete(
    manifest_present: bool,
    chunks: &PalwBatchChunkTracker,
    certificate_present: bool,
    beacon_present: bool,
) -> bool {
    manifest_present && chunks.is_complete() && certificate_present && beacon_present
}

/// A mining-template algo-4 candidate ticket: the resolved eligibility digest + the canonical nonce +
/// its nullifier, from an Active ticket in the miner's inventory (design §22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PalwTemplateCandidate {
    pub eligibility_digest: Hash64,
    pub nonce: u64,
    pub ticket_nullifier: Hash64,
}

/// ADR-0039 §22 — pick the algo-4 ticket the mining template should use for the current interval: the
/// first candidate (in the caller's canonical inventory order) whose one-shot eligibility draw **wins**
/// at the current lane `bits`, using the EXACT validation predicate [`palw_eligibility_win`] so the
/// template a miner builds and the header a validator accepts agree. Returns the winning index, or
/// `None` if no Active ticket draws this interval (⇒ the miner produces an algo-3 template instead).
pub fn palw_select_template_ticket(candidates: &[PalwTemplateCandidate], bits: u32) -> Option<usize> {
    candidates.iter().position(|c| palw_eligibility_win(&c.eligibility_digest, bits, c.nonce, &c.ticket_nullifier))
}

/// ADR-0039 §22 / C6 — build the mining-template candidate for one Active ticket by computing its
/// eligibility-draw digest and canonical nonce **exactly the way the validator does** (clause 9): the
/// digest is [`eligibility_hash`] over the lagged `R_E` (`eligibility_beacon` = the finality-buried
/// anchor's `palw_beacon_seed`), the consensus-derived `chain_commit`, the target interval, and the leaf
/// identity; the nonce is pinned to `low64(ticket_nullifier)` (I-3). Because the template's selection
/// (`palw_select_template_ticket`) and the validator's acceptance (`verify_palw_ticket`) share these two
/// functions, **construction == validation** is structural — a header built from a winning candidate
/// satisfies clauses 6/9 by construction (proved by `template_ticket_construction_equals_validation`).
#[allow(clippy::too_many_arguments)]
pub fn palw_template_candidate(
    network_id: u32,
    eligibility_beacon: &Hash64,
    chain_commit: &Hash64,
    target_interval: u64,
    batch_id: &Hash64,
    leaf_index: u32,
    leaf_hash: &Hash64,
    ticket_nullifier: &Hash64,
) -> PalwTemplateCandidate {
    PalwTemplateCandidate {
        eligibility_digest: eligibility_hash(
            network_id,
            eligibility_beacon,
            chain_commit,
            target_interval,
            batch_id,
            leaf_index,
            leaf_hash,
            ticket_nullifier,
        ),
        nonce: digest_low_u64(ticket_nullifier),
        ticket_nullifier: *ticket_nullifier,
    }
}

/// `R_E` epoch beacon seed (design §11.2). The reveal / missing-commitment sets are pre-reduced to
/// canonical roots by the caller so the preimage is fixed-width.
pub fn beacon_seed(
    prev_seed: &Hash64,
    dns_finalized_anchor: &Hash64,
    valid_reveals_root: &Hash64,
    missing_commitments_root: &Hash64,
    epoch: u64,
) -> Hash64 {
    let mut p = Vec::with_capacity(4 * HASH64_SIZE + 8);
    push_hash(&mut p, prev_seed);
    push_hash(&mut p, dns_finalized_anchor);
    push_hash(&mut p, valid_reveals_root);
    push_hash(&mut p, missing_commitments_root);
    p.extend_from_slice(&epoch.to_le_bytes());
    blake2b_512_keyed(PALW_BEACON_DOMAIN, &p)
}

/// `R_fallback` degraded-mode seed (design §11.3): used only when the primary commit-reveal quorum is
/// unavailable. Derived from a **lagged wide** selected-chain window (NOT the current tip, to resist
/// tip-grinding) — the caller pre-reduces the window's block hashes to a Merkle root. This is NOT
/// fully unbiasable, so the compute-work multiplier is reduced (or 0) while a fallback seed is active.
pub fn beacon_fallback_seed(prev_seed: &Hash64, finalized_anchor: &Hash64, lagged_window_root: &Hash64, epoch: u64) -> Hash64 {
    let mut p = Vec::with_capacity(3 * HASH64_SIZE + 8);
    push_hash(&mut p, prev_seed);
    push_hash(&mut p, finalized_anchor);
    push_hash(&mut p, lagged_window_root);
    p.extend_from_slice(&epoch.to_le_bytes());
    blake2b_512_keyed(PALW_BEACON_DOMAIN, &p)
}

/// Degraded-mode decision for the DNS PALW beacon (design §11.3). Drives whether new batches may
/// activate and whether algo-4 blocks are accepted this epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PalwBeaconMode {
    /// Primary commit-reveal quorum reached: full seed, new batches may activate, full compute weight.
    Healthy,
    /// DNS quality low / quorum short, still inside the grace window: existing Active tickets keep the
    /// previous seed, NO new batch activates, reduced compute weight.
    DegradedGrace,
    /// Grace exhausted: algo-4 blocks are invalid this epoch; the algo-3 hash lane continues.
    Halted,
}

/// Decide the beacon mode from DNS health + quorum + how many epochs the degradation has lasted
/// (design §11.3). `grace_epochs` is [`PalwParams::dns_degraded_grace_epochs`].
pub fn beacon_mode(dns_healthy: bool, quorum_reached: bool, degraded_epochs: u64, grace_epochs: u64) -> PalwBeaconMode {
    if dns_healthy && quorum_reached {
        PalwBeaconMode::Healthy
    } else if degraded_epochs <= grace_epochs {
        PalwBeaconMode::DegradedGrace
    } else {
        PalwBeaconMode::Halted
    }
}

/// ADR-0039 §11.3 (K5 fallback policy) — the effective per-leaf compute-work multiplier given the
/// beacon mode. Full `base_scale` while `Healthy`; HALVED during the `DegradedGrace` window; ZERO once
/// `Halted`. Monotone: `Healthy >= DegradedGrace >= Halted`.
///
/// **K5 wiring decision (design panel, recorded):** the GHOSTDAG compute credit
/// (`normalize_palw_work` at the header stage) stays FLAT on Header v3 and does NOT consume this
/// policy. Three structural reasons: (1) header-only IBD runs the credit for every header BEFORE any of
/// its history is body/virtual-validated locally, so any beacon-derived input would consume fields not
/// yet S2-authenticated (the unverified-field grinding hazard); (2) proof-level GHOSTDAG managers pin
/// PALW inert (`with_level`), so a mode-aware level-0 credit would diverge from the proof view; (3) the
/// only header-pure lagged signal (buried-anchor seed-carry, below) is BINARY (Healthy vs not) and
/// cannot express this tri-level policy. §11.3's "reduced compute weight" is therefore enforced by the
/// LAYERED gates instead — the S2-site `PalwLaneHalted` chain-block rule, the body-stage clause-10
/// lagged halt indicator, the `WorkRewardClass::ReplicaPalwHalted` zero-pay classification, and the
/// `advance_epoch_gated` activation freeze — with the residual weight exposure bounded by the permanent
/// `E = H + min(C, 4H)` cap (≤ 5× hash). Mode-aware WEIGHT is an explicit activation-time decision
/// (header-committed mode = Header v4 = re-genesis). This fn remains the template/candidate policy and
/// the future weight hook.
pub fn effective_compute_work_scale(base_scale: u64, mode: PalwBeaconMode) -> u64 {
    match mode {
        PalwBeaconMode::Healthy => base_scale,
        PalwBeaconMode::DegradedGrace => base_scale / 2,
        PalwBeaconMode::Halted => 0,
    }
}

/// ADR-0039 §11.3 (K5, the LAGGED BINARY beacon-health signal) — the length of the seed CARRY run
/// ending at the newest sample, over per-PALW-epoch `(epoch, seed)` samples in ascending epoch order
/// (one representative — the newest buried header — per epoch; see the body-stage sampler).
///
/// Soundness: `derive_beacon_epoch_state` carries the seed VERBATIM in `DegradedGrace`/`Halted` and
/// always advances it through the keyed hash chain in `Healthy` (the epoch is folded into the preimage,
/// so even an identical input set yields a fresh seed). Endpoint equality therefore certifies that NO
/// Healthy advance happened in the spanned interval: `seed(E_newest) == seed(e)` ⇒ every epoch in
/// `(e, E_newest]` was non-Healthy, and the run is `E_newest - e` for the OLDEST such equal sample.
/// A run `> grace_epochs` certifies the newest sampled epoch was `Halted`.
///
/// LAGGED + fail-open by construction: with `< 2` samples (short history, activation boundary, pruned
/// walk) the run is `0` — never a false halt. And because the samples are finality-BURIED, the signal
/// trails reality by ~the attestation lag: it misses a just-started halt (the reward gate + weight cap
/// cover that window) and keeps certifying for ~lag epochs after a Healthy recovery (the template MUST
/// consult the same predicate — [`palw_template_lane_open`] — or it would build self-rejecting blocks).
pub fn palw_seed_carry_run(samples: &[(u64, Hash64)]) -> u64 {
    let Some(&(newest_epoch, newest_seed)) = samples.last() else { return 0 };
    let mut oldest_equal = newest_epoch;
    for &(epoch, seed) in samples.iter().rev().skip(1) {
        if seed != newest_seed {
            break;
        }
        oldest_equal = epoch;
    }
    newest_epoch.saturating_sub(oldest_equal)
}

/// ADR-0039 §11.3 (K5) — may a `Certified` batch flip `Active` at this block, judged from the same
/// lagged buried samples? `true` iff the two newest distinct-epoch seeds DIFFER (a buried Healthy
/// advance exists — the beacon was recently healthy enough to admit new batches). `false` fail-closed
/// on `< 2` samples. Binary is exactly sufficient here: §11.3 freezes NEW batch activation during BOTH
/// `DegradedGrace` and `Halted` (existing Active tickets are untouched), and the seed-carry signal is
/// precisely "non-Healthy" — no tri-level resolution needed, unlike the weight policy above.
pub fn palw_lagged_activation_open(samples: &[(u64, Hash64)]) -> bool {
    let mut it = samples.iter().rev();
    let (Some(&(_, newest)), Some(&(_, prev))) = (it.next(), it.next()) else { return false };
    newest != prev
}

/// ADR-0039 §11.3 (K5, template-side c==v twin) — MUST be consulted by the algo-4 template candidate
/// constructor before emitting a ticket: the lane is open iff the block's OWN derived beacon mode is not
/// `Halted` (the S2-site `PalwLaneHalted` rule) AND the buried seed-carry run does not exceed grace (the
/// body-stage clause-10 rule). The second conjunct is what prevents post-recovery self-bricking: for
/// ~the attestation lag after a Healthy recovery the buried run still certifies halted, clause 10 still
/// rejects, and a template consulting only the exact mode would build blocks its own validation refuses.
pub fn palw_template_lane_open(derived_mode: u8, buried_carry_run: u64, grace_epochs: u64) -> bool {
    derived_mode != PalwBeaconMode::Halted.to_u8() && buried_carry_run <= grace_epochs
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

/// Target-epoch lead for a commit included while PALW epoch `P` is current: it commits for `P + 2`.
pub const PALW_BEACON_COMMIT_LEAD_EPOCHS: u64 = 2;
/// Target-epoch lead for a reveal included while PALW epoch `P` is current: it reveals for `P + 1`.
pub const PALW_BEACON_REVEAL_LEAD_EPOCHS: u64 = 1;

/// The only target epoch a commit may name while `current_epoch` is active. `None` at the `u64`
/// boundary rather than wrapping/saturating into an ambiguous epoch.
#[inline]
pub fn beacon_commit_target_epoch(current_epoch: u64) -> Option<u64> {
    current_epoch.checked_add(PALW_BEACON_COMMIT_LEAD_EPOCHS)
}

/// The only target epoch a reveal may name while `current_epoch` is active.
#[inline]
pub fn beacon_reveal_target_epoch(current_epoch: u64) -> Option<u64> {
    current_epoch.checked_add(PALW_BEACON_REVEAL_LEAD_EPOCHS)
}

/// True exactly in the `E-2` commit phase for target epoch `E`.
#[inline]
pub fn beacon_commit_phase_accepts(current_epoch: u64, target_epoch: u64) -> bool {
    beacon_commit_target_epoch(current_epoch) == Some(target_epoch)
}

/// True exactly in the `E-1` reveal phase for target epoch `E`.
#[inline]
pub fn beacon_reveal_phase_accepts(current_epoch: u64, target_epoch: u64) -> bool {
    beacon_reveal_target_epoch(current_epoch) == Some(target_epoch)
}

/// Digest the secret opened by a valid reveal before it enters `valid_reveals_root`. The raw secret
/// is included in this distinct-domain preimage, so two different valid openings produce different
/// epoch seeds even if a caller accidentally supplies their earlier public commitments elsewhere.
pub fn beacon_reveal_entropy_digest(epoch: u64, random_64: &[u8; 64], bond: &TransactionOutpoint) -> Hash64 {
    let mut p = Vec::with_capacity(8 + 64 + HASH64_SIZE + 4);
    p.extend_from_slice(&epoch.to_le_bytes());
    p.extend_from_slice(random_64);
    push_hash(&mut p, &bond.transaction_id);
    p.extend_from_slice(&bond.index.to_le_bytes());
    blake2b_512_keyed(PALW_BEACON_REVEAL_ENTROPY_DOMAIN, &p)
}

/// Canonical-sorted keyed hash of a `(bond, value_digest)` set (design §11.2). Both `beacon_seed`
/// roots use this fixed-width shape, but `value_digest` has different semantics and a different root
/// domain: reveal-entropy digest for valid reveals, public commitment for missing reveals. The set is
/// sorted by `(transaction_id, index)` — the SAME canonical order the `(epoch ‖ bond)` store keys use —
/// then each entry is appended as `transaction_id ‖ index_le ‖ value_digest`, `u64`-LE count-prefixed
/// so the digest is collision-free across cardinalities. Deterministic and caller-order-independent.
fn beacon_bond_digest_set_root(domain: &[u8], entries: &[(TransactionOutpoint, Hash64)]) -> Hash64 {
    let mut sorted: Vec<&(TransactionOutpoint, Hash64)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.transaction_id.as_byte_slice().cmp(b.0.transaction_id.as_byte_slice()).then(a.0.index.cmp(&b.0.index)));
    let mut p = Vec::with_capacity(8 + sorted.len() * (HASH64_SIZE + 4 + HASH64_SIZE));
    p.extend_from_slice(&(sorted.len() as u64).to_le_bytes());
    for (outpoint, value_digest) in sorted {
        push_hash(&mut p, &outpoint.transaction_id);
        p.extend_from_slice(&outpoint.index.to_le_bytes());
        push_hash(&mut p, value_digest);
    }
    blake2b_512_keyed(domain, &p)
}

/// `valid_reveals_root` — the `beacon_seed` input over the epoch's validly-opened reveal entropy
/// digests (§11.2). A public `beacon_commitment` is not a valid entry here.
pub fn beacon_valid_reveals_root(entries: &[(TransactionOutpoint, Hash64)]) -> Hash64 {
    beacon_bond_digest_set_root(PALW_BEACON_REVEALS_ROOT_DOMAIN, entries)
}

/// `missing_commitments_root` — the `beacon_seed` input over the epoch's committed-but-unrevealed
/// bonds (§11.2). The missing set is `commits(E)` minus the bonds that validly revealed.
pub fn beacon_missing_commitments_root(entries: &[(TransactionOutpoint, Hash64)]) -> Hash64 {
    beacon_bond_digest_set_root(PALW_BEACON_MISSING_ROOT_DOMAIN, entries)
}

/// ADR-0039 §11.2 — the beacon commit-reveal quorum: the epoch reached quorum iff the **stake-weighted**
/// revealed tally reaches the `num/den` fraction of the total committed stake. Stake-weighted (not a raw
/// count) so bond-splitting cannot Sybil the quorum — consistent with the certificate quorum
/// ([`PalwBatchCertificateV1::quorum_reached`]). `stake_of` resolves a committing bond to its stake in
/// the epoch's DNS bond view. `den` must be > 0; ties go to reached (`>=`). Feeds `beacon_mode`'s
/// `quorum_reached` bool.
pub fn beacon_quorum_reached(
    committed: &[TransactionOutpoint],
    revealed: &[TransactionOutpoint],
    num: u16,
    den: u16,
    stake_of: impl Fn(&TransactionOutpoint) -> u128,
) -> bool {
    if den == 0 {
        return false;
    }
    let committed_stake: u128 = committed.iter().map(&stake_of).sum();
    // §11.3: an epoch with no committed stake (total participant dropout) is NOT a reached quorum — it
    // is degraded. Without this, the vacuous `0 >= 0` would advance the seed as Healthy over an empty
    // reveal set, masking a dropout as a healthy epoch.
    if committed_stake == 0 {
        return false;
    }
    let revealed_stake: u128 = revealed.iter().map(&stake_of).sum();
    revealed_stake.saturating_mul(den as u128) >= committed_stake.saturating_mul(num as u128)
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
    for h in [
        output_commitment,
        canonical_gemm_trace_root,
        operation_schedule_commitment,
        job_set_commitment,
        receipt_a_hash,
        receipt_b_hash,
    ] {
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
    /// Canonical Compute v1 §17.5 fix 1 — a **model-opaque** commitment: the fold of the off-chain trace
    /// (op-ids, GEMM schedule, integer accumulators — all owned by `compute_spec_version`). Consensus
    /// borsh-serializes/hashes this 64-byte blob and MUST NEVER re-derive or field-parse it; the validity
    /// kernel (`verify_palw_ticket`) never reads it. Keeping it opaque is what makes model/MoE/VLM changes
    /// a spec-version rollout rather than a consensus fork.
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
        for h in [&self.output_commitment, &self.canonical_gemm_trace_root, &self.operation_schedule_commitment, &self.receipt_da_root]
        {
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
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwPublicLeafV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub leaf_index: u32,
    /// A scheduled work unit cannot mint another leaf.
    pub job_nullifier: Hash64,
    /// I-13 winner secrecy: the leaf publishes only the COMMITMENT
    /// `ticket_nullifier_commitment(ticket_nullifier)`, never the raw nullifier. The header discloses the
    /// raw nullifier at mint time (also carried first-class in Header v3); verification binds
    /// `ticket_nullifier_commitment(header.palw_ticket_nullifier) == this`. So only the ticket holder can
    /// pre-compute the ticket's future eligibility — a third party reading the public leaf cannot.
    pub ticket_nullifier_commitment: Hash64,
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
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
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

impl PalwBatchManifestV1 {
    /// ADR-0039 §9.2 — the batch's CONTENT identity: a keyed hash of the manifest with its
    /// (self-referential) `batch_id` field zeroed. A valid manifest must satisfy `batch_id ==
    /// content_id()` (see [`Self::batch_id_is_content_derived`]); this makes `batch_id` a collision-
    /// resistant content address, so `(batch_id, leaf_index)` / `batch_id` store keys are fork-safe
    /// (C4 design panel: without this, `batch_id` is an attacker-chosen FIELD and two forks can register
    /// different manifests under one key, last-writer-wins).
    pub fn content_id(&self) -> Hash64 {
        let mut canonical = self.clone();
        canonical.batch_id = Hash64::default();
        blake2b_512_keyed(PALW_BATCH_ID_DOMAIN, &borsh::to_vec(&canonical).expect("borsh"))
    }

    /// True iff `batch_id` equals the content id (the content-addressing invariant).
    #[inline]
    pub fn batch_id_is_content_derived(&self) -> bool {
        self.batch_id == self.content_id()
    }

    /// ADR-0039 §9.2/§9.3 — the pure admission predicate for a manifest accepted at `accept_epoch`. C4
    /// panel: `apply_palw_overlay_effect`'s Manifest arm currently does ZERO validation, so a manifest
    /// with `expiry_epoch = u64::MAX` (or a forged `batch_id`) is admissible and pins its view entry
    /// forever. This bounds every window and content-addresses the batch. `chunk_span(leaf_count,
    /// max_chunk)` = the exact number of chunks the leaves require.
    #[allow(clippy::too_many_arguments)]
    pub fn admission_valid(
        &self,
        accept_epoch: u64,
        max_batch_leaves: u32,
        max_leaf_chunk_leaves: u16,
        registration_lead_epochs: u64,
        active_window_epochs: u64,
        audit_window_epochs: u64,
        min_leaf_bond_sompi: u64,
    ) -> bool {
        if self.version != 1 || !self.batch_id_is_content_derived() {
            return false;
        }
        if self.leaf_count == 0 || self.leaf_count > max_batch_leaves || max_leaf_chunk_leaves == 0 {
            return false;
        }
        // §7 economic floor (R3 c_saved calibration): the aggregate bond must cover the per-leaf floor for
        // every leaf. Without this, a batch can register `leaf_count` leaves against a token bond, and the
        // forgery-EV inequality — which must dominate `R + c_saved`, not just `R` — never holds. Aggregate
        // (not per-leaf) is checked here because the manifest fixes only the total before the leaf chunks
        // arrive; the per-leaf split is enforced where leaves are admitted.
        if self.total_leaf_bond_sompi < (self.leaf_count as u64).saturating_mul(min_leaf_bond_sompi) {
            return false;
        }
        // chunk_count must be exactly ceil(leaf_count / max_leaf_chunk_leaves) — no hidden/padded chunks.
        let expected_chunks = self.leaf_count.div_ceil(max_leaf_chunk_leaves as u32);
        if self.chunk_count as u32 != expected_chunks {
            return false;
        }
        // §11.2.1-style phase freeze: registration epoch is the acceptance epoch (miner cannot re-aim).
        if self.registration_epoch != accept_epoch {
            return false;
        }
        // Activation is at/after registration + the mandatory lead; the active window is bounded (so no
        // `expiry_epoch = u64::MAX` pins the batch view forever).
        let min_activation = self.registration_epoch.saturating_add(registration_lead_epochs).saturating_add(audit_window_epochs);
        if self.activation_not_before_epoch < min_activation {
            return false;
        }
        self.expiry_epoch > self.activation_not_before_epoch
            && self.expiry_epoch <= self.activation_not_before_epoch.saturating_add(active_window_epochs)
    }
}

/// A chunk of ≤ [`PALW_MAX_LEAVES_PER_CHUNK`] public leaves (design §9.3).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwAuditorVoteV1 {
    pub bond_outpoint: TransactionOutpoint,
    /// 1 = pass, 0 = reject.
    pub vote: u8,
    pub checked_leaf_bitmap_root: Hash64,
    /// ML-DSA-87 signature (verification in the audit slice).
    pub signature: Vec<u8>,
}

impl PalwAuditorVoteV1 {
    /// ADR-0039 §10.1 / I-14 — the message an auditor signs. It binds the vote to the certificate's
    /// batch + audit-beacon epoch + **`audit_sample_root`** (the beacon-selected receipt-chunk
    /// commitment) + the auditor's identity + which leaves it checked. Covering `audit_sample_root`
    /// closes the "certify without fetching" honesty assumption: since consensus independently re-derives
    /// `audit_sample_root` from the audit beacon over the batch's receipt DA, a valid signature cannot be
    /// produced without identifying — hence possessing — the beacon-selected receipt chunks. The
    /// `signature` field itself is excluded (it covers this digest).
    pub fn signing_hash(&self, network_id: u32, batch_id: &Hash64, audit_beacon_epoch: u64, audit_sample_root: &Hash64) -> Hash64 {
        let mut p = Vec::with_capacity(3 * HASH64_SIZE + 8 + HASH64_SIZE + 4 + 4 + 1);
        p.extend_from_slice(&network_id.to_le_bytes());
        push_hash(&mut p, batch_id);
        p.extend_from_slice(&audit_beacon_epoch.to_le_bytes());
        push_hash(&mut p, audit_sample_root);
        push_hash(&mut p, &self.bond_outpoint.transaction_id);
        p.extend_from_slice(&self.bond_outpoint.index.to_le_bytes());
        p.push(self.vote);
        push_hash(&mut p, &self.checked_leaf_bitmap_root);
        blake2b_512_keyed(PALW_AUDITOR_VOTE_DOMAIN, &p)
    }
}

// =============================================================================================
// R4 — mismatch attribution (anti-griefing, design §24.5).
//
// The k=2 replica rule credits a leaf only when both replicas agree. Non-agreement alone is
// therefore a griefing vector: a malicious provider paired with an honest one can deliberately
// emit a wrong output so NEITHER is credited, burning the honest partner's real GPU work at no
// cost to itself. The v0.1 design "just doesn't credit the winner" — which punishes the victim as
// hard as the attacker. R4 makes non-agreement ATTRIBUTABLE: a deterministic fraction of mismatches
// (plus every repeat-offender bond) is escalated to a reference-runtime re-run, and the bond of the
// party whose committed output deviates from the reference result is slashed. The honest partner,
// whose output matches the reference, keeps its bond. This is a pure decision layer — the escalation
// draw, the attribution verdict, and the slash-target set. The re-run itself and the per-provider
// mismatch counter are off-protocol inputs (design §24.5); consensus only checks the verdict.
// =============================================================================================

/// A committed non-agreement between the two replicas of one leaf (design §24.5). `output_a` /
/// `output_b` are the providers' leaf-committed output hashes; a record is only meaningful when they
/// differ (that IS the mismatch).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwMismatchRecordV1 {
    pub batch_id: Hash64,
    pub leaf_index: u32,
    pub provider_a: TransactionOutpoint,
    pub provider_b: TransactionOutpoint,
    pub output_a: Hash64,
    pub output_b: Hash64,
}

/// The attribution verdict after a reference-runtime re-run resolves a mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PalwMismatchVerdict {
    /// `output_a` deviates from the reference result — slash `provider_a`.
    SlashA,
    /// `output_b` deviates — slash `provider_b`.
    SlashB,
    /// Neither committed output matches the reference — both deviated; slash both.
    SlashBoth,
    /// Not actually a mismatch (`output_a == output_b`); nothing to attribute.
    NotAMismatch,
}

/// R4 parameters (design §24.5). Inert placeholder escalates nothing (`0` ppm, threshold `0` disables
/// the repeat-offender path) so activation is byte-neutral; calibrated at re-genesis to the measured
/// collusion cost (see the ADR c_saved / anti-griefing calibration note).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwMismatchParams {
    /// Baseline fraction of mismatches escalated to a reference re-run, in parts-per-million.
    pub escalation_rate_ppm: u32,
    /// A provider bond that has accrued at least this many prior mismatches is escalated
    /// unconditionally (0 disables the repeat-offender path).
    pub repeat_offender_threshold: u32,
}

impl PalwMismatchParams {
    pub const INERT: PalwMismatchParams = PalwMismatchParams { escalation_rate_ppm: 0, repeat_offender_threshold: 0 };
}

impl PalwMismatchRecordV1 {
    /// The deterministic escalation draw for this mismatch under `audit_beacon_seed`. Every node
    /// derives the same value, so escalation cannot be steered by a provider. Returns a value in
    /// `[0, 1_000_000)`; the mismatch is baseline-escalated iff it is `< escalation_rate_ppm`.
    pub fn escalation_draw(&self, audit_beacon_seed: &Hash64) -> u32 {
        let mut p = Vec::with_capacity(HASH64_SIZE + HASH64_SIZE + 4);
        push_hash(&mut p, audit_beacon_seed);
        push_hash(&mut p, &self.batch_id);
        p.extend_from_slice(&self.leaf_index.to_le_bytes());
        let d = blake2b_512_keyed(PALW_MISMATCH_ESCALATE_DOMAIN, &p);
        let b = d.as_byte_slice();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]) % 1_000_000
    }

    /// True iff this mismatch is escalated to a reference-runtime re-run: either the deterministic
    /// baseline draw hits, or one of the two providers is at/over the repeat-offender threshold. The
    /// per-provider mismatch counts are supplied by the off-protocol tracker (design §24.5).
    pub fn is_escalated(&self, audit_beacon_seed: &Hash64, params: &PalwMismatchParams, prior_mismatches_a: u32, prior_mismatches_b: u32) -> bool {
        if self.output_a == self.output_b {
            return false; // not a mismatch — nothing to escalate
        }
        if self.escalation_draw(audit_beacon_seed) < params.escalation_rate_ppm {
            return true;
        }
        let repeat = params.repeat_offender_threshold;
        repeat != 0 && (prior_mismatches_a >= repeat || prior_mismatches_b >= repeat)
    }

    /// Attribute the mismatch given the reference runtime's authoritative output hash. The party whose
    /// committed output differs from the reference is the deviator. Because `output_a != output_b`, at
    /// most one can match the reference — so the honest partner is never slashed.
    pub fn attribute(&self, reference_output: &Hash64) -> PalwMismatchVerdict {
        if self.output_a == self.output_b {
            return PalwMismatchVerdict::NotAMismatch;
        }
        let a_ok = self.output_a == *reference_output;
        let b_ok = self.output_b == *reference_output;
        match (a_ok, b_ok) {
            (true, false) => PalwMismatchVerdict::SlashB,
            (false, true) => PalwMismatchVerdict::SlashA,
            _ => PalwMismatchVerdict::SlashBoth, // neither matches (both cannot, since a != b)
        }
    }

    /// The bond outpoints to slash for a verdict — the deterministic input to the slash slice.
    pub fn slash_targets(&self, verdict: PalwMismatchVerdict) -> Vec<TransactionOutpoint> {
        match verdict {
            PalwMismatchVerdict::SlashA => vec![self.provider_a],
            PalwMismatchVerdict::SlashB => vec![self.provider_b],
            PalwMismatchVerdict::SlashBoth => vec![self.provider_a, self.provider_b],
            PalwMismatchVerdict::NotAMismatch => vec![],
        }
    }
}

/// Certificate attesting a DNS-selected auditor quorum confirmed the batch facts (design §10.1).
/// It is **not** a proof of inference; it is a set of attested facts (I-10 / design §1.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
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

    /// ADR-0039 §10.1/§10.2 — the stake-weighted PASS tally over the certificate's votes. `stake_of`
    /// resolves an auditor bond outpoint to its stake in the audit-epoch DNS bond view (0 if the bond
    /// is not an eligible auditor). Only `vote == 1` (pass) counts. Deterministic: every node computes
    /// the same tally from the same bond view.
    pub fn pass_stake(&self, stake_of: impl Fn(&TransactionOutpoint) -> u128) -> u128 {
        self.votes.iter().filter(|v| v.vote == 1).map(|v| stake_of(&v.bond_outpoint)).sum()
    }

    /// ADR-0039 §10.2 — the certificate is quorum-valid iff the stake-weighted PASS tally reaches the
    /// `num/den` fraction of the total eligible auditor stake (testnet 2/3). `den` must be > 0; ties go
    /// to reached (>=). This is the check every node runs at batch activation before caching the
    /// certificate hash.
    pub fn quorum_reached(
        &self,
        total_auditor_stake: u128,
        num: u16,
        den: u16,
        stake_of: impl Fn(&TransactionOutpoint) -> u128,
    ) -> bool {
        if den == 0 {
            return false;
        }
        // pass_stake * den >= total * num  (cross-multiplied to avoid fractional rounding).
        self.pass_stake(stake_of).saturating_mul(den as u128) >= total_auditor_stake.saturating_mul(num as u128)
    }
}

// =============================================================================================
// Provider bond, block authorization, beacon, revocation (design §24.3, §12.4, §11.2, §9.5).
// =============================================================================================

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
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

impl PalwBeaconCommitV1 {
    /// Domain-separated ML-DSA message digest. Binds the operation to the network and every semantic
    /// field while excluding `signature` itself. `network_id` is the consensus PALW network number
    /// used by the other PALW hash preimages; callers must resolve it from chain params.
    pub fn signing_hash(&self, network_id: u32) -> Hash64 {
        let mut p = Vec::with_capacity(4 + 2 + 8 + HASH64_SIZE + 4 + HASH64_SIZE);
        p.extend_from_slice(&network_id.to_le_bytes());
        p.extend_from_slice(&self.version.to_le_bytes());
        p.extend_from_slice(&self.epoch.to_le_bytes());
        push_hash(&mut p, &self.bond_outpoint.transaction_id);
        p.extend_from_slice(&self.bond_outpoint.index.to_le_bytes());
        push_hash(&mut p, &self.commitment);
        blake2b_512_keyed(PALW_BEACON_COMMIT_SIGNING_DOMAIN, &p)
    }

    /// Contextual phase predicate: a commit carried in epoch `P` may target only `P + 2`.
    #[inline]
    pub fn is_in_phase(&self, current_epoch: u64) -> bool {
        beacon_commit_phase_accepts(current_epoch, self.epoch)
    }
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
    /// Domain-separated ML-DSA message digest. This domain is intentionally distinct from
    /// [`PalwBeaconCommitV1::signing_hash`], so a commit signature cannot authorize a reveal.
    pub fn signing_hash(&self, network_id: u32) -> Hash64 {
        let mut p = Vec::with_capacity(4 + 2 + 8 + HASH64_SIZE + 4 + 64);
        p.extend_from_slice(&network_id.to_le_bytes());
        p.extend_from_slice(&self.version.to_le_bytes());
        p.extend_from_slice(&self.epoch.to_le_bytes());
        push_hash(&mut p, &self.bond_outpoint.transaction_id);
        p.extend_from_slice(&self.bond_outpoint.index.to_le_bytes());
        p.extend_from_slice(&self.random_64);
        blake2b_512_keyed(PALW_BEACON_REVEAL_SIGNING_DOMAIN, &p)
    }

    /// True iff this reveal matches a prior [`PalwBeaconCommitV1::commitment`] (design §11.2).
    pub fn matches_commit(&self, commitment: &Hash64) -> bool {
        beacon_commitment(self.epoch, &self.random_64, &self.bond_outpoint) == *commitment
    }

    /// Distinct-domain digest of the opened secret used by `valid_reveals_root` and hence `R_E`.
    #[inline]
    pub fn entropy_digest(&self) -> Hash64 {
        beacon_reveal_entropy_digest(self.epoch, &self.random_64, &self.bond_outpoint)
    }

    /// Contextual phase predicate: a reveal carried in epoch `P` may target only `P + 1`.
    #[inline]
    pub fn is_in_phase(&self, current_epoch: u64) -> bool {
        beacon_reveal_phase_accepts(current_epoch, self.epoch)
    }
}

/// ADR-0039 §12.1 — the frozen facts of a DNS-confirmed anchor threaded through the beacon recurrence
/// (design-panel resolution for clause 6). Every field is a property of the ANCHOR BLOCK ITSELF
/// (header-committed, lag-buried, confirmation-depth-cleared, strictly before any target interval it
/// certifies), so the certificate digest over them cannot be ground by boundary-block producers: the
/// bond view / attestation set at the deriving boundary never enters the preimage. `overlay_root` is
/// the anchor's own header-committed `overlay_commitment_root` — it binds WHICH bond/stake state
/// confirmed (the materialized `validator_set_commitment` intent) without any churnable input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BeaconDnsAnchor {
    pub hash: Hash64,
    pub blue_score: u64,
    pub daa_score: u64,
    pub overlay_root: Hash64,
}

impl BeaconDnsAnchor {
    /// The pre-confirmation sentinel (all zero). Fail-closed: no certificate is derivable from it.
    pub const UNCONFIRMED: Self = Self {
        hash: Hash64::from_bytes([0u8; HASH64_SIZE]),
        blue_score: 0,
        daa_score: 0,
        overlay_root: Hash64::from_bytes([0u8; HASH64_SIZE]),
    };

    #[inline]
    pub fn is_confirmed(&self) -> bool {
        self.hash != Hash64::default()
    }
}

/// ADR-0039 §12.1 (option (b), panel-frozen v1) — the `dns_finality_certificate_hash` fed to
/// [`chain_commit`]: a domain-separated digest of the confirmed anchor's own frozen facts. Deliberately
/// EXCLUDED (each was a constructed grinding/split channel): any bond-set commitment over a boundary-time
/// view (2^n re-rolls via cheap self-bond inclusion), any `confirmation_epoch` (2-valued at boundaries,
/// undefined for carried anchors), and any raw work/stake depth (grows per block). A future v2 carrying a
/// real certificate object slots in behind a new domain without changing [`chain_commit`]'s signature
/// (its second argument stays an opaque digest).
pub fn dns_finality_certificate_hash_v1(anchor: &BeaconDnsAnchor) -> Hash64 {
    let mut p = Vec::with_capacity(2 * HASH64_SIZE + 16);
    push_hash(&mut p, &anchor.hash);
    p.extend_from_slice(&anchor.blue_score.to_le_bytes());
    p.extend_from_slice(&anchor.daa_score.to_le_bytes());
    push_hash(&mut p, &anchor.overlay_root);
    blake2b_512_keyed(PALW_DNS_CERT_DOMAIN, &p)
}

/// ADR-0039 §12.1 — static params-consistency predicate discharging the §12.1 LOOKBACK inequality
/// ("the checkpoint lag exceeds DNS finality + max shallow reorg") plus non-vacuous confirmation depths.
/// A PALW **re-genesis preflight / C5 activation gate** — deliberately SEPARATE from
/// `dns_v3_params_consistent` (which live nets evaluate on every DNS state update: current testnet DNS
/// presets have `lag + backoff = 120 < max_reorg_horizon = 300` and would be instantly deactivated).
/// The PALW re-genesis must recalibrate `attestation_lag_blue_score`/`backoff` to satisfy this. Both
/// sides of the burial comparison are blue-score-denominated (`max_reorg_horizon_blocks` bounds the
/// abandonable chain suffix, whose blue score is bounded by its block count).
#[allow(clippy::too_many_arguments)]
pub fn palw_checkpoint_params_consistent(
    attestation_lag_blue_score: u64,
    attestation_anchor_backoff_blue_score: u64,
    max_reorg_horizon_blocks: u64,
    finality_depth: u64,
    pruning_depth: u64,
    required_work_depth: BlueWorkType,
    required_stake_depth: u128,
) -> bool {
    let burial = attestation_lag_blue_score.saturating_add(attestation_anchor_backoff_blue_score);
    // C6 SLICE 5 — the re-genesis BAND the finality-buried anchor must sit in:
    //   max(max_reorg_horizon, finality_depth)  <=  burial  <  pruning_depth
    // (i) burial >= max_reorg_horizon: outlast the deepest legal reorg (else a deep reorg re-rolls
    //     chain_commit). (ii) burial >= finality_depth: the anchor's selected-chain identity is
    //     externally SETTLED by DNS finality — this collapses the clause-9 forged-seed residual (a
    //     chain-disqualified block cannot be the canonical settled anchor without a finality violation)
    //     into the standing I-4 trust chain_commit already depends on. (iii) burial < pruning_depth: the
    //     anchor's header + reachability must survive on pruned nodes, or the body-stage clause-6/9 read
    //     becomes unrunnable (a liveness break). (iv) the confirmation predicate must not be vacuous —
    //     with both depths zero, `is_dns_confirmed` passes immediately and a "confirmed" anchor is merely
    //     lag-ready. The band is non-empty only if `pruning_depth > max(max_reorg_horizon, finality_depth)`
    //     (holds by design); a re-genesis must recalibrate lag/backoff to land inside it.
    burial >= max_reorg_horizon_blocks
        && burial >= finality_depth
        && burial < pruning_depth
        && (required_work_depth > BlueWorkType::from(0u64) || required_stake_depth > 0)
}

/// ADR-0039 §11.2 / §18.2 — the per-epoch derived beacon state persisted once per chain block (the
/// block carries its epoch's active `R_E`). Every field is fixed-width so the whole record is a
/// borsh + serde POD (no bare `[u8; 64]` — `random_64` is deliberately NOT here: reveal acceptance
/// reduces it to [`beacon_reveal_entropy_digest`], which is committed by `valid_reveals_root`).
///
/// The `*_root` + `dns_anchor` + `epoch` fields make each entry **self-verifying**: a pruned node with
/// the prior epoch's `seed` can recompute `seed == beacon_seed(prev_seed, dns_anchor, valid_reveals_root,
/// missing_commitments_root, epoch)` from the §18.3 proof bundle without replaying the raw commit/reveal
/// txs. `degraded_epochs` is the per-block-carried grace counter `beacon_mode` consumes (`= parent+1`
/// while degraded, else `0`), so the mode recurrence is reorg-safe without a global counter.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwBeaconStateV1 {
    pub version: u16,
    pub epoch: u64,
    /// `R_E` (or the carried `R_{E-1}` on a non-boundary block / `DegradedGrace`).
    pub seed: Hash64,
    /// The DNS-finalized anchor folded into this epoch's seed (`beacon_seed` arg 2).
    pub dns_anchor: Hash64,
    /// The anchor's own frozen coordinates + header-committed overlay root (§12.1 clause-6 facts;
    /// storage option (ii): the record stays self-verifying — the certificate digest is derivable from
    /// these fields alone, and the carried-anchor path never re-reads the anchor header).
    pub anchor_blue_score: u64,
    pub anchor_daa_score: u64,
    pub anchor_overlay_root: Hash64,
    pub valid_reveals_root: Hash64,
    pub missing_commitments_root: Hash64,
    /// [`PalwBeaconMode`] discriminant (0 = Healthy, 1 = DegradedGrace, 2 = Halted).
    pub mode: u8,
    /// Consecutive degraded epochs feeding `beacon_mode` (`0` when Healthy).
    pub degraded_epochs: u64,
    /// Diagnostics (not seed inputs): counts behind the two roots.
    pub valid_reveal_count: u32,
    pub missing_commit_count: u32,
}

impl PalwBeaconMode {
    /// Wire discriminant for [`PalwBeaconStateV1::mode`].
    pub fn to_u8(self) -> u8 {
        match self {
            PalwBeaconMode::Healthy => 0,
            PalwBeaconMode::DegradedGrace => 1,
            PalwBeaconMode::Halted => 2,
        }
    }

    /// Inverse of [`Self::to_u8`]; `None` for an unknown discriminant (fail-closed at the caller).
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(PalwBeaconMode::Healthy),
            1 => Some(PalwBeaconMode::DegradedGrace),
            2 => Some(PalwBeaconMode::Halted),
            _ => None,
        }
    }
}

impl PalwBeaconStateV1 {
    /// The record's carried anchor facts (the [`dns_finality_certificate_hash_v1`] inputs).
    pub fn anchor(&self) -> BeaconDnsAnchor {
        BeaconDnsAnchor {
            hash: self.dns_anchor,
            blue_score: self.anchor_blue_score,
            daa_score: self.anchor_daa_score,
            overlay_root: self.anchor_overlay_root,
        }
    }

    /// ADR-0039 §11.3 (K5 wiring) — the first PALW epoch of the CURRENT halted run, or `None` if this
    /// state is not `Halted`. Closed-form from the grace recurrence: `degraded_epochs` counts the
    /// consecutive non-Healthy epochs ending at `self.epoch`, and the mode flips to `Halted` exactly when
    /// `degraded_epochs > grace_epochs` — so the first HALTED epoch of the run is
    /// `epoch + grace_epochs + 1 - degraded_epochs`. A source block whose minting epoch is
    /// `>= halted_since(..)` was minted under a halted beacon (within THIS run); epochs before the run
    /// started are outside this state's memory and must be treated conservatively (not halted) by the
    /// caller. Saturating throughout (a `degraded_epochs` inconsistency can under- but never over-reach).
    pub fn halted_since(&self, grace_epochs: u64) -> Option<u64> {
        (self.mode == PalwBeaconMode::Halted.to_u8())
            .then(|| self.epoch.saturating_add(grace_epochs).saturating_add(1).saturating_sub(self.degraded_epochs))
    }

    /// Clause 6's `dns_finality_certificate_hash` derived on demand from the carried anchor facts.
    /// **Fail-closed**: `None` while no DNS-confirmed anchor has entered the recurrence (the zero
    /// bootstrap anchor certifies nothing — `chain_commit` over a degenerate zero-cert would be
    /// reproducible by every private fork, voiding I-4 exactly when the chain is weakest). The C5
    /// atomic flip rejects algo-4 while this is `None`.
    pub fn dns_certificate_hash(&self) -> Option<Hash64> {
        let anchor = self.anchor();
        anchor.is_confirmed().then(|| dns_finality_certificate_hash_v1(&anchor))
    }
}

/// ADR-0039 §18.3 — one epoch's finalized beacon facts in the pruning-proof `beacon_chain`. It carries
/// exactly the inputs a historic verifier needs to (a) re-check the `R_E` hash-chain step
/// (`seed == beacon_seed(prev_seed, dns_anchor, valid_reveals_root, missing_commitments_root, epoch)`)
/// and (b) re-derive that epoch's `chain_commit` from the anchor facts — without the raw commit/reveal
/// set. It is the compact projection of a [`PalwBeaconStateV1`] onto its seed-relevant fields (the two
/// diagnostic counts are dropped; the `version` is fixed at `1`). Frozen wire type (§33 freeze-first);
/// the pruning verifier + P2P flow that consume it are the D3 slice.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwBeaconCheckpointV1 {
    pub epoch: u64,
    /// `R_E` for this epoch (the seed a same-epoch algo-4 ticket's eligibility draws over).
    pub seed: Hash64,
    pub dns_anchor: Hash64,
    pub anchor_blue_score: u64,
    pub anchor_daa_score: u64,
    pub anchor_overlay_root: Hash64,
    pub valid_reveals_root: Hash64,
    pub missing_commitments_root: Hash64,
    /// [`PalwBeaconMode`] discriminant + consecutive degraded epochs — needed so a verifier replays the
    /// exact `DegradedGrace` recurrence, not just the healthy path.
    pub mode: u8,
    pub degraded_epochs: u64,
}

impl PalwBeaconCheckpointV1 {
    /// Project a finalized per-epoch beacon state onto its pruning-proof checkpoint.
    pub fn from_state(s: &PalwBeaconStateV1) -> Self {
        Self {
            epoch: s.epoch,
            seed: s.seed,
            dns_anchor: s.dns_anchor,
            anchor_blue_score: s.anchor_blue_score,
            anchor_daa_score: s.anchor_daa_score,
            anchor_overlay_root: s.anchor_overlay_root,
            valid_reveals_root: s.valid_reveals_root,
            missing_commitments_root: s.missing_commitments_root,
            mode: s.mode,
            degraded_epochs: s.degraded_epochs,
        }
    }

    /// The carried anchor facts (the [`dns_finality_certificate_hash_v1`] inputs).
    pub fn anchor(&self) -> BeaconDnsAnchor {
        BeaconDnsAnchor {
            hash: self.dns_anchor,
            blue_score: self.anchor_blue_score,
            daa_score: self.anchor_daa_score,
            overlay_root: self.anchor_overlay_root,
        }
    }

    /// True iff this checkpoint's `seed` is the correct hash-chain successor of `prev_seed` under the
    /// §11.2 recurrence. The verifier walks `beacon_chain` in ascending epoch order checking this at each
    /// step (the first checkpoint's `prev_seed` is the bundle's `from_epoch − 1` boundary seed).
    pub fn seed_follows(&self, prev_seed: &Hash64) -> bool {
        self.seed
            == beacon_seed(prev_seed, &self.dns_anchor, &self.valid_reveals_root, &self.missing_commitments_root, self.epoch)
    }
}

/// ADR-0039 §18.3 — the PALW slice of the pruning proof: enough on-chain-equivalent data for a pruned
/// node to recompute historic algo-4 ticket validity (batch/leaf existence, certificate quorum,
/// activation/expiry, the beacon chain, target interval, chain_commit, eligibility hash, component work,
/// nullifier dedup) without the full history. Frozen wire type (§33); the builder, the pruning verifier,
/// and the P2P request/response flow (§18.4) are the D3 slice.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwEpochProofBundleV1 {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub beacon_chain: Vec<PalwBeaconCheckpointV1>,
    pub batch_manifests: Vec<PalwBatchManifestV1>,
    pub leaf_chunks: Vec<PalwLeafChunkV1>,
    pub certificates: Vec<PalwBatchCertificateV1>,
    pub revocations: Vec<PalwRevocationV1>,
    /// The frontier commitment of the active-nullifier set at `to_epoch` (§15.2), so the verifier can
    /// continue dedup from a pruned boundary without every historic nullifier.
    pub nullifier_frontier_root: Hash64,
    /// Canonical Compute v1 §17.5 fix 3 (I-12) — the compute-set records active over `[from_epoch,
    /// to_epoch]`. TAIL-appended (never reorder the fields above — borsh is positional). **Carried-but-
    /// unread** until the D3 builder + pruning verifier + re-genesis wire it: a pruned verifier recomputing
    /// historic `E` must apply each epoch's per-set `effective_compute_work_scale()` (via each record's
    /// activation/deprecation window) instead of a single global scale, so class-as-data does not
    /// contradict I-12. Default empty ⇒ the historic recompute falls back to the flat const scale, exactly
    /// as today; no shipped preset produces a bundle, so this is byte-neutral in practice.
    pub active_set_records: Vec<PalwComputeSetRecordV1>,
}

impl PalwEpochProofBundleV1 {
    /// Structural check that the `beacon_chain` is a contiguous ascending run over `[from_epoch,
    /// to_epoch]` whose seeds chain from `boundary_prev_seed` (the seed finalized at `from_epoch − 1`).
    /// Content checks (batch/cert/leaf existence, quorum, windows) are the pruning verifier's job; this
    /// is the beacon-chain linkage the verifier runs first.
    pub fn beacon_chain_links(&self, boundary_prev_seed: &Hash64) -> bool {
        if self.to_epoch < self.from_epoch {
            return false;
        }
        if self.beacon_chain.len() as u64 != self.to_epoch - self.from_epoch + 1 {
            return false;
        }
        let mut prev = *boundary_prev_seed;
        for (i, cp) in self.beacon_chain.iter().enumerate() {
            if cp.epoch != self.from_epoch + i as u64 || !cp.seed_follows(&prev) {
                return false;
            }
            prev = cp.seed;
        }
        true
    }
}

/// ADR-0039 §18.2 / D3 — the PALW frontier a pruned-IBD joiner needs to validate the FIRST post-pruning-
/// point v3 block: the pruning point's own block-keyed PALW state. Without it, `versioned_overlay_
/// commitment_root` (which reads `beacon_state(pruning_point)`) PANICS on the first post-pp v3 block, the
/// algo-4 ticket check has no batch view to gate on, and the cross-ancestor nullifier dedup seeds empty
/// (re-opening reuse of a still-active pre-pp ticket).
///
/// **Commitment boundary (the load-bearing invariant):** this rides its OWN singleton store
/// (`DbPalwPrunedFrontierStore`, a fresh prefix), **not** the committed [`OverlaySnapshot`] and **not** the
/// bincode-persisted `PruningPointOverlaySnapshot` wrapper — so it is byte-neutral to
/// `overlay_commitment_root` AND cannot disturb that wrapper's read on an in-place upgrade (a D3 boundary-
/// review finding: appending a field to the bincode wrapper makes a pre-upgrade singleton unreadable). It
/// is authenticated indirectly: a tampered `beacon_state` here is caught by the forward
/// `overlay_commitment_root` c==v on the first post-pp block, whose own header commits the derived beacon
/// state (C6 SLICE 2). Empty on every shipped preset (PALW inert). Carries only consensus-core types; the
/// beacon accumulator view (consensus crate) is a follow-up (reconstructed at the next epoch boundary or
/// via the epoch-proof bundle).
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwPrunedFrontierV1 {
    /// `beacon_state(pruning_point)` — the R_E seed + DNS anchor; MUST be seeded or the first post-pp v3
    /// block's overlay-root recompute panics.
    pub beacon_state: Option<PalwBeaconStateV1>,
    /// `overlay_view(pruning_point)` — the fork-relative batch lifecycle the ticket check (C5) gates on.
    pub overlay_view: Option<PalwBatchViewV1>,
    /// `lane_bits(pruning_point)` — the carried per-lane difficulty at the boundary (informational; the
    /// enforced clause-7 difficulty is a pure header-window function).
    pub lane_bits: Option<PalwLaneBitsV1>,
    /// `active_nullifiers(pruning_point)` — the retention window, so a joiner still detects reuse of a
    /// pre-pp ticket that is inside the window (else pruning would forget them and re-open double-use).
    pub active_nullifiers: PalwActiveNullifierSet,
}

impl PalwPrunedFrontierV1 {
    /// True iff the frontier carries no PALW state — the shipped-preset / pre-activation case (so a
    /// capture on a non-PALW net produces the byte-neutral empty default).
    pub fn is_empty(&self) -> bool {
        self.beacon_state.is_none() && self.overlay_view.is_none() && self.lane_bits.is_none() && self.active_nullifiers.is_empty()
    }
}

/// The inputs the epoch-boundary derivation gathers from the beacon store (past-relative) before
/// calling [`derive_beacon_epoch_state`]. Kept as an explicit struct so the derivation stays a pure
/// function of already-resolved sets (no store handle), unit-testable in isolation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BeaconEpochInputs {
    /// Every `(bond, commitment)` that committed FOR this epoch (from the commit store).
    pub commits: Vec<(TransactionOutpoint, Hash64)>,
    /// The subset of `commits` whose reveal validly opened it (`matches_commit`), as
    /// `(bond, reveal_entropy_digest)`. The public commitment MUST NOT be placed in this vector.
    pub valid_reveals: Vec<(TransactionOutpoint, Hash64)>,
}

impl BeaconEpochInputs {
    /// `commits` minus the bonds present in `valid_reveals` — the committed-but-unrevealed set whose root
    /// feeds `beacon_seed` (and which a later slice slashes). Deterministic (preserves `commits` order;
    /// the root re-sorts canonically).
    pub fn missing_commitments(&self) -> Vec<(TransactionOutpoint, Hash64)> {
        let revealed: BTreeSet<(Hash64, u32)> = self.valid_reveals.iter().map(|(o, _)| (o.transaction_id, o.index)).collect();
        self.commits.iter().filter(|(o, _)| !revealed.contains(&(o.transaction_id, o.index))).cloned().collect()
    }
}

/// ADR-0039 §11.2 — derive epoch `E`'s beacon state from the resolved commit/reveal sets, the prior
/// epoch's seed, and the DNS-finalized anchor. Pure (store-free): the caller has already gathered
/// [`BeaconEpochInputs`] past-relative to the deriving block. Computes the two roots, decides the mode
/// (`beacon_mode` from DNS health + stake quorum + carried grace counter), and advances the seed —
/// `beacon_seed` on `Healthy`, else the previous seed is carried (design §11.3: `DegradedGrace` reuses
/// `R_{E-1}`; `Halted` also carries it, with algo-4 acceptance gated off elsewhere). `stake_of` resolves
/// a committing bond to its epoch stake. Returns the record persisted for the boundary block.
#[allow(clippy::too_many_arguments)]
pub fn derive_beacon_epoch_state(
    epoch: u64,
    prev_seed: &Hash64,
    anchor: &BeaconDnsAnchor,
    inputs: &BeaconEpochInputs,
    dns_healthy: bool,
    prev_degraded_epochs: u64,
    grace_epochs: u64,
    quorum_num: u16,
    quorum_den: u16,
    stake_of: impl Fn(&TransactionOutpoint) -> u128,
) -> PalwBeaconStateV1 {
    let valid_reveals_root = beacon_valid_reveals_root(&inputs.valid_reveals);
    let missing = inputs.missing_commitments();
    let missing_commitments_root = beacon_missing_commitments_root(&missing);

    let committed: Vec<TransactionOutpoint> = inputs.commits.iter().map(|(o, _)| *o).collect();
    let revealed: Vec<TransactionOutpoint> = inputs.valid_reveals.iter().map(|(o, _)| *o).collect();
    let quorum = beacon_quorum_reached(&committed, &revealed, quorum_num, quorum_den, &stake_of);

    // Grace counter recurrence: reset on Healthy, else +1 (bounded by the mode decision).
    let degraded_epochs = if dns_healthy && quorum { 0 } else { prev_degraded_epochs.saturating_add(1) };
    let mode = beacon_mode(dns_healthy, quorum, degraded_epochs, grace_epochs);

    let seed = match mode {
        // §11.2: full commit-reveal seed advance. The seed preimage folds only the anchor HASH — the
        // clause-6 cert facts ride alongside in the record without altering R_E's semantics.
        PalwBeaconMode::Healthy => beacon_seed(prev_seed, &anchor.hash, &valid_reveals_root, &missing_commitments_root, epoch),
        // §11.3: grace/halt reuse the previous seed (no new unbiasable randomness this epoch).
        PalwBeaconMode::DegradedGrace | PalwBeaconMode::Halted => *prev_seed,
    };

    PalwBeaconStateV1 {
        version: 1,
        epoch,
        seed,
        dns_anchor: anchor.hash,
        anchor_blue_score: anchor.blue_score,
        anchor_daa_score: anchor.daa_score,
        anchor_overlay_root: anchor.overlay_root,
        valid_reveals_root,
        missing_commitments_root,
        mode: mode.to_u8(),
        degraded_epochs,
        valid_reveal_count: inputs.valid_reveals.len() as u32,
        missing_commit_count: missing.len() as u32,
    }
}

/// ADR-0039 §11.2 / §18.1 — the per-epoch on-chain accumulation the beacon store persists (keyed by
/// epoch): every commitment that committed FOR this epoch, plus the subset that validly revealed
/// (`matches_commit` at reveal-accept time). Valid reveals retain the distinct-domain `Hash64`
/// [`beacon_reveal_entropy_digest`] of `random_64`; raw secrets need not remain in the state. At the
/// epoch boundary this maps to
/// [`BeaconEpochInputs`] and feeds [`derive_beacon_epoch_state`].
///
/// **Inert (never written)** on every shipped preset (PALW fence `u64::MAX`) — the store only ever holds
/// the empty default; this type reserves the format + access path.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwBeaconEpochAccumV1 {
    pub version: u16,
    pub commits: Vec<(TransactionOutpoint, Hash64)>,
    /// `(bond, reveal_entropy_digest)` entries; never `(bond, commitment)`.
    pub valid_reveals: Vec<(TransactionOutpoint, Hash64)>,
}

impl PalwBeaconEpochAccumV1 {
    pub fn new() -> Self {
        Self { version: 1, commits: Vec::new(), valid_reveals: Vec::new() }
    }

    /// Record a commit for `bond`. Idempotent on the bond outpoint (a bond commits once per epoch — a
    /// duplicate is ignored, keeping the first-seen commitment).
    pub fn record_commit(&mut self, bond: TransactionOutpoint, commitment: Hash64) {
        if !self.commits.iter().any(|(o, _)| *o == bond) {
            self.commits.push((bond, commitment));
        }
    }

    /// The commitment `bond` committed for this epoch, if any (used to check a reveal's `matches_commit`).
    pub fn commitment_of(&self, bond: &TransactionOutpoint) -> Option<Hash64> {
        self.commits.iter().find(|(o, _)| o == bond).map(|(_, c)| *c)
    }

    /// Record the entropy digest of a reveal that validly opened `bond`'s commitment. Idempotent on
    /// the bond outpoint. The caller computes this with [`PalwBeaconRevealV1::entropy_digest`] only
    /// after `matches_commit` succeeds.
    pub fn record_valid_reveal(&mut self, bond: TransactionOutpoint, reveal_entropy_digest: Hash64) {
        if !self.valid_reveals.iter().any(|(o, _)| *o == bond) {
            self.valid_reveals.push((bond, reveal_entropy_digest));
        }
    }

    /// Map to the pure derivation inputs (design §11.2).
    pub fn to_inputs(&self) -> BeaconEpochInputs {
        BeaconEpochInputs { commits: self.commits.clone(), valid_reveals: self.valid_reveals.clone() }
    }
}

/// Non-retroactive revocation (design §9.5): invalidates only future unused leaves from
/// `effective_daa_score` onward.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwRevocationV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub effective_daa_score: u64,
    pub reason_code: u16,
    pub evidence_hash: Hash64,
}

// =============================================================================================
// PALW overlay stateless payload admission (subnetworks 0x30..0x37).
// =============================================================================================

/// The only PALW payload version accepted by the v1 overlay wire format.
pub const PALW_PAYLOAD_VERSION_V1: u16 = 1;
/// Hard per-transaction PALW payload cap, checked before Borsh decoding. The largest v1 object is a
/// certificate containing ML-DSA-87 votes; 512 KiB leaves room for the frozen hard vote cap while
/// preventing an unbounded payload from reaching nested-vector decoding.
pub const PALW_MAX_OVERLAY_PAYLOAD_BYTES: usize = 512 * 1024;
/// Hard wire cap independent of the smaller per-network `PalwParams::max_batch_leaves` policy.
pub const PALW_MAX_BATCH_LEAVES_V1: usize = 256;
/// Hard wire cap for provider metadata vectors.
pub const PALW_MAX_PROVIDER_RUNTIME_CLASSES_V1: usize = 64;
pub const PALW_MAX_PROVIDER_CAPACITY_ENTRIES_V1: usize = 256;
/// Hard wire cap. A network may select fewer auditors through `PalwParams::auditor_count`.
pub const PALW_MAX_AUDITOR_VOTES_V1: usize = 64;
/// Reward scripts embedded in public leaves are metadata, not transaction outputs. Bound them here
/// so one leaf cannot consume the whole payload cap with an unusable script.
pub const PALW_MAX_REWARD_SCRIPT_BYTES_V1: usize = 1024;

/// Typed view of the reserved PALW subnetwork byte band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PalwTxKind {
    ProviderBond,
    BatchManifest,
    LeafChunk,
    BatchCertificate,
    Revocation,
    BeaconCommit,
    BeaconReveal,
    /// Reserved by ADR-0039, but v1 has not frozen a provider-unbond wire payload yet.
    ProviderUnbond,
}

impl PalwTxKind {
    #[inline]
    pub const fn from_subnetwork_byte(value: u8) -> Option<Self> {
        Some(match value {
            0x30 => Self::ProviderBond,
            0x31 => Self::BatchManifest,
            0x32 => Self::LeafChunk,
            0x33 => Self::BatchCertificate,
            0x34 => Self::Revocation,
            0x35 => Self::BeaconCommit,
            0x36 => Self::BeaconReveal,
            0x37 => Self::ProviderUnbond,
            _ => return None,
        })
    }
}

/// Stateless PALW overlay payload failure. Context-dependent rules (activation fence, beacon phase,
/// past-relative bond ownership/stake, signature verification, and duplicate-on-chain state) are
/// deliberately absent and must run in contextual validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PalwTxError {
    Decode,
    UnsupportedKind(u8),
    PayloadTooLarge { len: usize, max: usize },
    UnsupportedVersion(u16),
    InvalidPublicKeyLen(usize),
    InvalidSignatureLen(usize),
    InvalidCount { field: &'static str, count: usize, min: usize, max: usize },
    InvalidField(&'static str),
    NonCanonical(&'static str),
}

impl Display for PalwTxError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode => write!(f, "PALW overlay payload failed to decode"),
            Self::UnsupportedKind(kind) => write!(f, "PALW overlay subnetwork kind 0x{kind:02x} has no frozen v1 payload"),
            Self::PayloadTooLarge { len, max } => write!(f, "PALW overlay payload length {len} exceeds {max}"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported PALW overlay payload version {version}"),
            Self::InvalidPublicKeyLen(len) => write!(f, "PALW ML-DSA-87 public key length {len} is invalid"),
            Self::InvalidSignatureLen(len) => write!(f, "PALW ML-DSA-87 signature length {len} is invalid"),
            Self::InvalidCount { field, count, min, max } => {
                write!(f, "PALW {field} count {count} is outside {min}..={max}")
            }
            Self::InvalidField(field) => write!(f, "PALW field {field} is invalid"),
            Self::NonCanonical(field) => write!(f, "PALW field {field} is not canonically ordered/unique"),
        }
    }
}

#[inline]
fn decode_palw_payload<T: BorshDeserialize>(payload: &[u8]) -> Result<T, PalwTxError> {
    // `borsh::from_slice` is strict: trailing bytes fail rather than being ignored.
    borsh::from_slice(payload).map_err(|_| PalwTxError::Decode)
}

#[inline]
fn check_palw_version(version: u16) -> Result<(), PalwTxError> {
    if version == PALW_PAYLOAD_VERSION_V1 { Ok(()) } else { Err(PalwTxError::UnsupportedVersion(version)) }
}

#[inline]
fn check_count(field: &'static str, count: usize, min: usize, max: usize) -> Result<(), PalwTxError> {
    if (min..=max).contains(&count) { Ok(()) } else { Err(PalwTxError::InvalidCount { field, count, min, max }) }
}

#[inline]
fn cmp_outpoint(a: &TransactionOutpoint, b: &TransactionOutpoint) -> Ordering {
    a.transaction_id.as_byte_slice().cmp(b.transaction_id.as_byte_slice()).then(a.index.cmp(&b.index))
}

fn validate_provider_bond(payload: &[u8]) -> Result<(), PalwTxError> {
    let bond: PalwProviderBondPayloadV1 = decode_palw_payload(payload)?;
    check_palw_version(bond.version)?;
    if bond.owner_public_key.len() != STAKE_VALIDATOR_PUBKEY_LEN {
        return Err(PalwTxError::InvalidPublicKeyLen(bond.owner_public_key.len()));
    }
    check_count("provider.runtime_classes", bond.runtime_classes.len(), 1, PALW_MAX_PROVIDER_RUNTIME_CLASSES_V1)?;
    if !bond.runtime_classes.windows(2).all(|w| w[0].as_byte_slice() < w[1].as_byte_slice()) {
        return Err(PalwTxError::NonCanonical("provider.runtime_classes"));
    }
    check_count("provider.capacity_by_shape", bond.capacity_by_shape.len(), 1, PALW_MAX_PROVIDER_CAPACITY_ENTRIES_V1)?;
    if !bond.capacity_by_shape.windows(2).all(|w| w[0].0 < w[1].0) {
        return Err(PalwTxError::NonCanonical("provider.capacity_by_shape"));
    }
    if bond.capacity_by_shape.iter().any(|(_, capacity)| *capacity == 0) {
        return Err(PalwTxError::InvalidField("provider.capacity_by_shape.capacity"));
    }
    if bond.amount_sompi == 0 {
        return Err(PalwTxError::InvalidField("provider.amount_sompi"));
    }
    if bond.unbond_delay_epochs == 0 {
        return Err(PalwTxError::InvalidField("provider.unbond_delay_epochs"));
    }
    Ok(())
}

fn validate_manifest(payload: &[u8]) -> Result<(), PalwTxError> {
    let manifest: PalwBatchManifestV1 = decode_palw_payload(payload)?;
    check_palw_version(manifest.version)?;
    check_count("manifest.leaf_count", manifest.leaf_count as usize, 1, PALW_MAX_BATCH_LEAVES_V1)?;
    let expected_chunks = ((manifest.leaf_count as usize + PALW_MAX_LEAVES_PER_CHUNK - 1) / PALW_MAX_LEAVES_PER_CHUNK) as u16;
    if manifest.chunk_count != expected_chunks {
        return Err(PalwTxError::InvalidField("manifest.chunk_count"));
    }
    if !(manifest.registration_epoch < manifest.activation_not_before_epoch
        && manifest.activation_not_before_epoch < manifest.expiry_epoch)
    {
        return Err(PalwTxError::InvalidField("manifest.epoch_range"));
    }
    Ok(())
}

fn validate_public_leaf(leaf: &PalwPublicLeafV1, batch_id: &Hash64) -> Result<(), PalwTxError> {
    check_palw_version(leaf.version)?;
    if leaf.batch_id != *batch_id {
        return Err(PalwTxError::InvalidField("leaf.batch_id"));
    }
    if PalwProofType::from_u8(leaf.proof_type).is_none() {
        return Err(PalwTxError::InvalidField("leaf.proof_type"));
    }
    if leaf.quantum_count == 0 {
        return Err(PalwTxError::InvalidField("leaf.quantum_count"));
    }
    if leaf.provider_a_bond == leaf.provider_b_bond {
        return Err(PalwTxError::InvalidField("leaf.provider_bonds"));
    }
    if leaf.provider_a_reward_script.script().len() > PALW_MAX_REWARD_SCRIPT_BYTES_V1
        || leaf.provider_b_reward_script.script().len() > PALW_MAX_REWARD_SCRIPT_BYTES_V1
    {
        return Err(PalwTxError::InvalidField("leaf.reward_script"));
    }
    if !(leaf.registered_epoch < leaf.activation_epoch && leaf.activation_epoch < leaf.expiry_epoch) {
        return Err(PalwTxError::InvalidField("leaf.epoch_range"));
    }
    Ok(())
}

fn validate_leaf_chunk(payload: &[u8]) -> Result<(), PalwTxError> {
    let chunk: PalwLeafChunkV1 = decode_palw_payload(payload)?;
    check_palw_version(chunk.version)?;
    check_count("leaf_chunk.leaves", chunk.leaves.len(), 1, PALW_MAX_LEAVES_PER_CHUNK)?;
    let mut ticket_nullifiers = HashSet::with_capacity(chunk.leaves.len());
    for leaf in &chunk.leaves {
        validate_public_leaf(leaf, &chunk.batch_id)?;
        // I-13: leaves publish nullifier COMMITMENTS; distinct nullifiers ⇒ distinct commitments, so the
        // per-batch uniqueness check is over the commitments.
        if !ticket_nullifiers.insert(leaf.ticket_nullifier_commitment) {
            return Err(PalwTxError::NonCanonical("leaf_chunk.ticket_nullifiers"));
        }
    }
    if !chunk.leaves.windows(2).all(|w| w[0].leaf_index < w[1].leaf_index) {
        return Err(PalwTxError::NonCanonical("leaf_chunk.leaf_indices"));
    }
    Ok(())
}

fn validate_certificate(payload: &[u8]) -> Result<(), PalwTxError> {
    let cert: PalwBatchCertificateV1 = decode_palw_payload(payload)?;
    check_palw_version(cert.version)?;
    check_count("certificate.votes", cert.votes.len(), 1, PALW_MAX_AUDITOR_VOTES_V1)?;
    if cert.passed_leaf_count == 0 {
        return Err(PalwTxError::InvalidField("certificate.passed_leaf_count"));
    }
    if !(cert.audit_beacon_epoch <= cert.certificate_epoch
        && cert.certificate_epoch < cert.activation_epoch
        && cert.activation_epoch < cert.expiry_epoch)
    {
        return Err(PalwTxError::InvalidField("certificate.epoch_range"));
    }
    for vote in &cert.votes {
        if vote.vote > 1 {
            return Err(PalwTxError::InvalidField("certificate.vote"));
        }
        if vote.signature.len() != STAKE_ATTESTATION_SIG_LEN {
            return Err(PalwTxError::InvalidSignatureLen(vote.signature.len()));
        }
    }
    if !cert.votes.windows(2).all(|w| cmp_outpoint(&w[0].bond_outpoint, &w[1].bond_outpoint) == Ordering::Less) {
        return Err(PalwTxError::NonCanonical("certificate.votes"));
    }
    Ok(())
}

fn validate_revocation(payload: &[u8]) -> Result<(), PalwTxError> {
    let revocation: PalwRevocationV1 = decode_palw_payload(payload)?;
    check_palw_version(revocation.version)?;
    if revocation.evidence_hash == Hash64::default() {
        return Err(PalwTxError::InvalidField("revocation.evidence_hash"));
    }
    Ok(())
}

fn validate_beacon_commit(payload: &[u8]) -> Result<(), PalwTxError> {
    let commit: PalwBeaconCommitV1 = decode_palw_payload(payload)?;
    check_palw_version(commit.version)?;
    if commit.signature.len() != STAKE_ATTESTATION_SIG_LEN {
        return Err(PalwTxError::InvalidSignatureLen(commit.signature.len()));
    }
    Ok(())
}

fn validate_beacon_reveal(payload: &[u8]) -> Result<(), PalwTxError> {
    let reveal: PalwBeaconRevealV1 = decode_palw_payload(payload)?;
    check_palw_version(reveal.version)?;
    if reveal.signature.len() != STAKE_ATTESTATION_SIG_LEN {
        return Err(PalwTxError::InvalidSignatureLen(reveal.signature.len()));
    }
    Ok(())
}

/// Strict context-free PALW payload admission by subnetwork byte. This is safe for transaction
/// isolation because it never reads an activation score or chain state. Contextual validation must
/// subsequently enforce the PALW activation fence, [`PalwBeaconCommitV1::is_in_phase`] /
/// [`PalwBeaconRevealV1::is_in_phase`], active bond/key binding, and ML-DSA verification.
///
/// `0x37` is fail-closed until the provider-unbond payload and its binding to
/// [`PalwProviderBondPayloadV1::owner_public_key`] are frozen; reusing the DNS unbond payload without
/// that contextual binding would allow an unauthenticated provider-state transition.
pub fn validate_palw_overlay_payload(subnetwork_byte: u8, payload: &[u8]) -> Result<(), PalwTxError> {
    let kind = PalwTxKind::from_subnetwork_byte(subnetwork_byte).ok_or(PalwTxError::UnsupportedKind(subnetwork_byte))?;
    if payload.len() > PALW_MAX_OVERLAY_PAYLOAD_BYTES {
        return Err(PalwTxError::PayloadTooLarge { len: payload.len(), max: PALW_MAX_OVERLAY_PAYLOAD_BYTES });
    }
    match kind {
        PalwTxKind::ProviderBond => validate_provider_bond(payload),
        PalwTxKind::BatchManifest => validate_manifest(payload),
        PalwTxKind::LeafChunk => validate_leaf_chunk(payload),
        PalwTxKind::BatchCertificate => validate_certificate(payload),
        PalwTxKind::Revocation => validate_revocation(payload),
        PalwTxKind::BeaconCommit => validate_beacon_commit(payload),
        PalwTxKind::BeaconReveal => validate_beacon_reveal(payload),
        PalwTxKind::ProviderUnbond => Err(PalwTxError::UnsupportedKind(subnetwork_byte)),
    }
}

// =============================================================================================
// Batch state machine (design §9.5). Pure transition function; the caller supplies the events
// (chunk/bond completion, beacon reached, quorum, timeouts, activation/expiry, fraud) from consensus
// state. Terminal states (Slashed / Expired / Revoked) have no outgoing edges. Only `Active` is
// block-eligible, and an `Incomplete` batch (stuck in `Registering` past its lead) expires and is
// never usable (I-2 / §9.5).
// =============================================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
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

/// ADR-0039 §9.3 — the manifest's `leaf_root`: a canonical keyed hash over the ORDERED per-leaf
/// [`PalwPublicLeafV1::leaf_hash`] digests, `u64`-LE count-prefixed. C4 content-addressing (design-panel
/// resolution): once a batch's `batch_id` is content-derived (see [`PalwBatchManifestV1::content_id`])
/// AND its leaves reduce to `leaf_root`, the `(batch_id, leaf_index)`-keyed leaf store is **write-once by
/// collision resistance** — no fork can register a different leaf at the same key. Leaf presence is
/// verified once the batch is chunk-complete (§9.3), not per-leaf-with-a-Merkle-proof.
pub fn palw_leaf_root(ordered_leaf_hashes: &[Hash64]) -> Hash64 {
    let mut p = Vec::with_capacity(8 + ordered_leaf_hashes.len() * HASH64_SIZE);
    p.extend_from_slice(&(ordered_leaf_hashes.len() as u64).to_le_bytes());
    for h in ordered_leaf_hashes {
        push_hash(&mut p, h);
    }
    blake2b_512_keyed(PALW_LEAF_ROOT_DOMAIN, &p)
}

/// ADR-0039 §12.1 clause-6-style referenceability: whether an algo-4 header targeting `epoch` could ever
/// resolve against a batch in `status` with the given windows — i.e. whether a past-relative overlay view
/// must RETAIN the batch. Panel-frozen (see design §18.2):
/// * terminal states (`Slashed`/`Expired`/`Revoked`) or any revoked batch → never referenceable → drop;
/// * `Active`/`Certified` → retain while `epoch < expiry_epoch` (a leaf/cert is block-eligible only
///   inside its active window, §14.2);
/// * pre-certification (`Registering`/`Committed`/`Auditing`) → retain until the registration + lead +
///   audit budget elapses, after which it can no longer certify. Deliberately does NOT key on the
///   evidence window (fraud on an already-expired batch changes no header verdict — that window bounds
///   the provider BOND record, not the batch view). Monotone: a child's epoch ≥ its parent's, so
///   `child_epoch < expiry ⟹ parent_epoch < expiry`, mirroring the beacon `retain_future_of` argument.
pub fn palw_batch_referenceable(
    status: PalwBatchStatus,
    revoked: bool,
    registration_epoch: u64,
    expiry_epoch: u64,
    epoch: u64,
    registration_lead_epochs: u64,
    audit_window_epochs: u64,
) -> bool {
    use PalwBatchStatus::*;
    if revoked || status.is_terminal() {
        return false;
    }
    match status {
        Active | Certified => epoch < expiry_epoch,
        Registering | Committed | Auditing => {
            epoch <= registration_epoch.saturating_add(registration_lead_epochs).saturating_add(audit_window_epochs)
        }
        Missing | Slashed | Expired | Revoked => false,
    }
}

/// ADR-0039 §9.2/§9.3 — the batch-admission bounds the mergeset-delta builder enforces (the subset of
/// `PalwParams` the fork-local batch view needs). A `const` so it lives in the `const Params` presets.
/// Inert placeholder values while PALW is inactive; recalibrated at re-genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwBatchAdmissionParams {
    pub max_batch_leaves: u32,
    pub max_leaf_chunk_leaves: u16,
    pub registration_lead_epochs: u64,
    pub active_window_epochs: u64,
    pub audit_window_epochs: u64,
    /// §7 economic floor per leaf, in sompi. A batch's `total_leaf_bond_sompi` must cover
    /// `leaf_count · min_leaf_bond_sompi`. Calibrated at re-genesis to each tier's measured `c_saved`
    /// (the GPU-execution cost a forger avoids by NOT running the inference) — the missing term in the
    /// forgery-EV inequality: a forger's gain is `R + c_saved`, and `q·slash ≈ R` only offsets the
    /// reward, so `leaf_bond + credential_loss` must cover `c_saved`. Inert placeholder `0`.
    pub min_leaf_bond_sompi: u64,
}

impl PalwBatchAdmissionParams {
    /// §16.3 testnet defaults (mirrors `PalwParams::testnet_inert_default`). Inert.
    pub const INERT: PalwBatchAdmissionParams = PalwBatchAdmissionParams {
        max_batch_leaves: 256,
        max_leaf_chunk_leaves: PALW_MAX_LEAVES_PER_CHUNK as u16,
        registration_lead_epochs: 2,
        active_window_epochs: 6,
        audit_window_epochs: 6,
        min_leaf_bond_sompi: 0,
    };
}

/// ADR-0039 §18.2 — the COMPACT, fork-relative lifecycle facts of one batch carried in a
/// [`PalwBatchViewV1`]. Only the genuinely fork-dependent bits (status + presence + windows +
/// content-address roots); the ~840 B/leaf immutable CONTENT stays in the content-addressed blob store
/// (a full-carry entry is ~292 KB — a per-block clone+persist DoS, C4 panel Q1). `leaf_root` +
/// `cert_hash` bind the blobs a resolver reads back; `chunks_present_count` drives the §9.3 completeness
/// gate (Registering → Committed once it equals `chunk_count`).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwBatchLifecycleV1 {
    pub status: PalwBatchStatus,
    pub registration_epoch: u64,
    pub activation_not_before_epoch: u64,
    pub expiry_epoch: u64,
    pub leaf_count: u32,
    pub chunk_count: u16,
    /// Bitmap of the received chunk indices (idempotent per index; `chunk_count <= 256` for
    /// `max_batch_leaves 256 / max_leaf_chunk_leaves >= 1`, so a 256-bit `[u64; 4]` covers every case).
    /// The §9.3 completeness gate fires when its popcount reaches `chunk_count`.
    pub chunks_present: [u64; 4],
    pub leaf_root: Hash64,
    pub cert_hash: Option<Hash64>,
    pub cert_activation_epoch: u64,
    pub cert_expiry_epoch: u64,
    pub revoked_from_daa: Option<u64>,
}

impl PalwBatchLifecycleV1 {
    /// Whether an algo-4 header targeting `epoch` may resolve against this batch (present, Active, not
    /// revoked, both the leaf-active and cert-active windows open). The per-leaf facts (nullifier /
    /// proof-type / leaf window) come from the content-verified leaf blob; this is the batch-level gate.
    pub fn is_block_eligible_at(&self, epoch: u64) -> bool {
        self.revoked_from_daa.is_none()
            && self.status.is_block_eligible()
            && self.cert_hash.is_some()
            && self.cert_activation_epoch <= epoch
            && epoch < self.cert_expiry_epoch
            && epoch < self.expiry_epoch
    }
}

/// ADR-0039 §18.2 — the fork-relative PALW batch-lifecycle view: a compact `batch_id → lifecycle` map
/// carried per block (clone the selected parent's, apply this block's deltas, `retain` the still-
/// referenceable set). This is the past-relative overlay `check_palw_ticket` must resolve against
/// instead of the global virtual-tip store. **The BUILDER (which stage writes it, and whether deltas
/// key on mergeset vs acceptance) is deliberately NOT here** — the C4 panel proved that choice is a C5
/// prerequisite (a body-stage read of a virtual-commit row is a consensus split; moving the check to
/// virtual loses the work-credit closure). This type + the pure retain/resolve are stage-independent.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwBatchViewV1 {
    pub version: u16,
    pub batches: BTreeMap<Hash64, PalwBatchLifecycleV1>,
}

impl PalwBatchViewV1 {
    pub fn new() -> Self {
        Self { version: 1, batches: BTreeMap::new() }
    }

    /// The batch's lifecycle facts, if present in this fork's past.
    pub fn entry(&self, batch_id: &Hash64) -> Option<&PalwBatchLifecycleV1> {
        self.batches.get(batch_id)
    }

    /// The batch a header may resolve against at `epoch`, or `None` (absent / not block-eligible).
    pub fn resolvable_batch(&self, batch_id: &Hash64, epoch: u64) -> Option<&PalwBatchLifecycleV1> {
        self.batches.get(batch_id).filter(|e| e.is_block_eligible_at(epoch))
    }

    /// Drop batches no longer referenceable by any future algo-4 header (design §18.2), bounding the
    /// carried view independently of chain length. Uses [`palw_batch_referenceable`]; monotone in epoch.
    pub fn retain(&mut self, epoch: u64, registration_lead_epochs: u64, audit_window_epochs: u64) {
        self.batches.retain(|_, e| {
            palw_batch_referenceable(
                e.status,
                e.revoked_from_daa.is_some(),
                e.registration_epoch,
                e.expiry_epoch,
                epoch,
                registration_lead_epochs,
                audit_window_epochs,
            )
        });
    }

    // ---- §9.5 tx-driven deltas (the B-way `Δ(mergeset(B))` applied to `view(SP(B))`). All pure; each
    // returns whether it mutated the view. The immutable leaf/cert CONTENT lives in the content-addressed
    // blob store — the view only tracks the fork-dependent lifecycle. ----

    /// Missing → Registering. Admission-gated ([`PalwBatchManifestV1::admission_valid`], which pins the
    /// content-addressed `batch_id`); idempotent on the content id (a re-registration of the exact same
    /// batch is a no-op — the first mergeset occurrence wins).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_manifest(
        &mut self,
        m: &PalwBatchManifestV1,
        accept_epoch: u64,
        max_batch_leaves: u32,
        max_leaf_chunk_leaves: u16,
        registration_lead_epochs: u64,
        active_window_epochs: u64,
        audit_window_epochs: u64,
        min_leaf_bond_sompi: u64,
    ) -> bool {
        if !m.admission_valid(
            accept_epoch,
            max_batch_leaves,
            max_leaf_chunk_leaves,
            registration_lead_epochs,
            active_window_epochs,
            audit_window_epochs,
            min_leaf_bond_sompi,
        ) {
            return false;
        }
        if self.batches.contains_key(&m.batch_id) {
            return false; // already registered on this fork (idempotent; content-addressed ⇒ same batch)
        }
        self.batches.insert(
            m.batch_id,
            PalwBatchLifecycleV1 {
                status: PalwBatchStatus::Registering,
                registration_epoch: m.registration_epoch,
                activation_not_before_epoch: m.activation_not_before_epoch,
                expiry_epoch: m.expiry_epoch,
                leaf_count: m.leaf_count,
                chunk_count: m.chunk_count,
                chunks_present: [0u64; 4],
                leaf_root: m.leaf_root,
                cert_hash: None,
                cert_activation_epoch: 0,
                cert_expiry_epoch: 0,
                revoked_from_daa: None,
            },
        );
        true
    }

    /// Record leaf chunk `chunk_index` for a Registering batch (idempotent per index via the bitmap; a
    /// re-sent chunk is a no-op, so duplicates cannot spoof completeness). The caller verifies the
    /// chunk's leaves against the batch's `leaf_root` at the §9.3 completeness gate (blob-store layer).
    /// When the bitmap's popcount reaches `chunk_count`, advances Registering → Committed.
    pub fn apply_leaf_chunk(&mut self, batch_id: &Hash64, chunk_index: u16) -> bool {
        let Some(e) = self.batches.get_mut(batch_id) else { return false };
        if e.status != PalwBatchStatus::Registering || chunk_index >= e.chunk_count {
            return false;
        }
        let (word, bit) = ((chunk_index / 64) as usize, chunk_index % 64);
        let mask = 1u64 << bit;
        if e.chunks_present[word] & mask != 0 {
            return false; // already present (idempotent)
        }
        e.chunks_present[word] |= mask;
        let present: u32 = e.chunks_present.iter().map(|w| w.count_ones()).sum();
        if present == e.chunk_count as u32 {
            if let Some(next) = e.status.next(PalwBatchEvent::ChunksAndBondsComplete) {
                e.status = next;
            }
        }
        true
    }

    /// A quorum-valid certificate (§10) advances Committed/Auditing → Certified and records the cert
    /// hash + its active window. The auditor-quorum + beacon checks are the caller's; this records the
    /// accepted outcome. (Committed → Auditing on the audit beacon is driven by [`Self::advance_epoch`].)
    pub fn apply_certificate(&mut self, batch_id: &Hash64, cert_hash: Hash64, cert_activation_epoch: u64, cert_expiry_epoch: u64) -> bool {
        let Some(e) = self.batches.get_mut(batch_id) else { return false };
        let next = match e.status {
            PalwBatchStatus::Auditing => e.status.next(PalwBatchEvent::CertificateQuorum),
            // tolerate a certificate that arrives before the audit-beacon epoch tick has advanced the
            // status to Auditing (mergeset ordering) — Committed also accepts the quorum.
            PalwBatchStatus::Committed => Some(PalwBatchStatus::Certified),
            _ => None,
        };
        let Some(next) = next else { return false };
        e.status = next;
        e.cert_hash = Some(cert_hash);
        e.cert_activation_epoch = cert_activation_epoch;
        e.cert_expiry_epoch = cert_expiry_epoch;
        true
    }

    /// §9.5 non-retroactive revocation from `effective_daa`. Only future unused leaves are invalidated;
    /// the entry is kept (still referenceable for already-drawn intervals below `effective_daa`) but the
    /// resolver treats a revoked batch as non-block-eligible from `effective_daa` on.
    pub fn mark_revoked(&mut self, batch_id: &Hash64, effective_daa: u64) -> bool {
        let Some(e) = self.batches.get_mut(batch_id) else { return false };
        if e.revoked_from_daa.is_some() {
            return false;
        }
        e.revoked_from_daa = Some(effective_daa);
        true
    }

    /// The epoch-driven transitions (design §9.5): Committed → Auditing at the audit-beacon epoch;
    /// Certified → Active at `activation_not_before_epoch`; and the incomplete/expiry timeouts. Applied
    /// once per block at the block's epoch (before [`Self::retain`]). Pure + monotone in epoch.
    /// Delegates to [`Self::advance_epoch_gated`] with the activation gate OPEN (the pre-K5 behavior;
    /// every existing caller/test is byte-identical).
    pub fn advance_epoch(&mut self, epoch: u64, registration_lead_epochs: u64, audit_window_epochs: u64) {
        self.advance_epoch_gated(epoch, registration_lead_epochs, audit_window_epochs, true)
    }

    /// [`Self::advance_epoch`] with the ADR-0039 §11.3 (K5) activation gate: while `activation_open` is
    /// `false` — the lagged buried beacon-health signal certifies a non-Healthy window
    /// ([`palw_lagged_activation_open`]) — the `Certified → Active` transition is FROZEN (no NEW batch
    /// activates during degradation). The gate DELAYS, never cancels: a frozen `Certified` batch flips
    /// `Active` on a later gated call with `true` (if still inside its windows), and its expiry timeout
    /// still fires while frozen (the `Active | Certified` expiry arm below is not gated). All other
    /// transitions (Registering/Committed/expiries) are gate-independent.
    pub fn advance_epoch_gated(&mut self, epoch: u64, registration_lead_epochs: u64, audit_window_epochs: u64, activation_open: bool) {
        use PalwBatchStatus::*;
        for e in self.batches.values_mut() {
            let deadline = e.registration_epoch.saturating_add(registration_lead_epochs).saturating_add(audit_window_epochs);
            match e.status {
                // an incomplete batch that missed its chunk/audit budget expires (I-2).
                Registering if epoch > deadline => e.status = Expired,
                // all chunks present; the audit beacon for this epoch opens the audit window.
                Committed if epoch >= deadline => e.status = Auditing,
                // certified and its activation epoch reached ⇒ live (only while the beacon admits new
                // activations — K5; a frozen batch falls through to the expiry arm below).
                Certified if activation_open && epoch >= e.activation_not_before_epoch => {
                    e.status = if epoch < e.expiry_epoch { Active } else { Expired };
                }
                Active | Certified if epoch >= e.expiry_epoch => e.status = Expired,
                _ => {}
            }
        }
    }
}

impl kaspa_utils::mem_size::MemSizeEstimator for PalwBatchViewV1 {
    fn estimate_mem_units(&self) -> usize {
        self.batches.len().max(1)
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

#[inline]
fn compute_work_cap(hash_work: BlueWorkType, compute_to_hash_cap: u64) -> BlueWorkType {
    let (cap_h, overflow) = hash_work.overflowing_mul_u64(compute_to_hash_cap);
    if overflow { BlueWorkType::MAX } else { cap_h }
}

/// The capped compute-work term: `min(compute_work, cap · hash_work)` (design §15.5). Saturating on
/// the `cap · hash_work` multiply so a pathological hash work near `BlueWorkType::MAX` cannot wrap.
#[inline]
pub fn capped_compute_work(compute_work: BlueWorkType, hash_work: BlueWorkType, compute_to_hash_cap: u64) -> BlueWorkType {
    core::cmp::min(compute_work, compute_work_cap(hash_work, compute_to_hash_cap))
}

/// Remaining compute-credit capacity `max(cap·H − C, 0)` (design §5.4 / clause 8). The multiply
/// saturates consistently with [`capped_compute_work`], and an over-cap `C` produces zero rather
/// than wrapping. An algo-4 block is admissible only while this value is non-zero; Stage-A weight
/// zero still has positive headroom once the permanent hash floor has accumulated work.
#[inline]
pub fn compute_headroom(hash_work: BlueWorkType, compute_work: BlueWorkType, compute_to_hash_cap: u64) -> BlueWorkType {
    compute_work_cap(hash_work, compute_to_hash_cap).saturating_sub(compute_work)
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
pub fn select_provider_pair(
    seed: &Hash64,
    job_capability: &Hash64,
    count: u64,
    max_attempts: u32,
    accept: impl Fn(u64, u64) -> bool,
) -> Option<(u64, u64)> {
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
pub fn select_top_auditors(
    prev_seed: &Hash64,
    batch_id: &Hash64,
    candidates: &[TransactionOutpoint],
    count: usize,
) -> Vec<TransactionOutpoint> {
    let mut scored: Vec<(Hash64, TransactionOutpoint)> =
        candidates.iter().map(|b| (auditor_score(prev_seed, batch_id, b), *b)).collect();
    scored.sort_by(|x, y| {
        x.0.as_byte_slice()
            .cmp(y.0.as_byte_slice())
            .then_with(|| x.1.transaction_id.as_byte_slice().cmp(y.1.transaction_id.as_byte_slice()))
            .then(x.1.index.cmp(&y.1.index))
    });
    scored.into_iter().take(count).map(|(_, b)| b).collect()
}

/// PALW **algo-4** lane coinbase split (basis points, sums to 10 000), **asymmetric to the algo-3
/// hash lane** which keeps its 62 / 8 / 30. ADR-0039 §17.1 (amended 2026-07-13): the compute lane
/// routes a larger base to the LLM providers by HALVING the validator share 30 % → 15 %; the freed
/// 15 % goes to the GPU compute source, so the provider base is 62 % + 15 % = **77 %**. This is an
/// intentional trade of DNS-finality validator subsidy for compute incentive (§17, user decision), and
/// only on PALW blocks — hash-lane blocks are unchanged. At the 1 : 4 lane split (10-BPS PALW genesis:
/// hash 2 + replica 8; proportion-identical to the 40-BPS 8 + 32) the effective validator subsidy
/// across ALL blocks is ≈ 0.2·30 % + 0.8·15 % = **18 %** (down from 30 %) — independent of total BPS.
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

/// ADR-0039 §15.3 / I-5 — the deterministic PALW **duplicate-ticket** rule (the nullifier dedup that
/// makes double-use detectable from the header DAG alone). Given the child's mergeset in **consensus
/// order** (ascending blue-work, hash tie-break) as one `Option<ticket_nullifier>` per block (`None`
/// for a non-PALW / algo-3 block) and `seed_active` = the nullifiers already active in the **selected
/// parent's past** (produced by the §15.2 active-nullifier window store), returns the mergeset
/// positions that are DUPLICATE algo-4 tickets and must be recolored red (`PalwDuplicateTicket`): a
/// nullifier already active before this block, or already first-seen earlier in this very mergeset.
/// First-seen tickets are kept blue-eligible.
///
/// Pure and order-deterministic — every node derives the same set from the header DAG, no Bloom filter
/// or probabilistic structure in the consensus decision (I-5). algo-3 blocks pass `None` and are never
/// duplicates. Inert: with no algo-4 header minted, every entry is `None`, so the result is always
/// empty and GHOSTDAG coloring is unchanged.
///
/// NOTE: this is the frozen dedup **semantics**. Wiring it INTO the GHOSTDAG coloring loop (not as a
/// naive post-pass vector move — forbidden by §15.3) and building the persistent selected-parent-past
/// `seed_active` window store (§15.2) are the activation steps, gated on the PALW fence.
pub fn palw_duplicate_ticket_positions(ordered: &[Option<Hash64>], seed_active: &HashSet<Hash64>) -> Vec<usize> {
    let mut seen: HashSet<Hash64> = seed_active.clone();
    let mut dups = Vec::new();
    for (i, nf) in ordered.iter().enumerate() {
        if let Some(nf) = nf {
            // `insert` returns false when the nullifier was already active (seed) or already first-seen
            // earlier in this mergeset — either way a double-use ⇒ recolor red.
            if !seen.insert(*nf) {
                dups.push(i);
            }
        }
    }
    dups
}

/// ADR-0039 §15.2 — the **active-nullifier window**: the ticket nullifiers still inside the retention
/// window, each keyed by the DAA score it was first seen at so the window prunes forward and stays
/// bounded to `nullifier_retention_daa`. Deterministically reconstructable from the header DAG (no
/// Bloom filter in the consensus decision, I-5). A sorted (`BTreeMap`) structure so a copy-on-write
/// fork view and any canonical active-set commitment are stable across nodes.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwActiveNullifierSet {
    seen: BTreeMap<Hash64, u64>,
}

impl PalwActiveNullifierSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// First-seen insert. Returns `false` (a duplicate — the §15.3 recolor trigger) if the nullifier is
    /// already active; keeps the earliest first-seen DAA otherwise.
    pub fn insert(&mut self, nullifier: Hash64, first_seen_daa: u64) -> bool {
        use std::collections::btree_map::Entry;
        match self.seen.entry(nullifier) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(first_seen_daa);
                true
            }
        }
    }

    pub fn contains(&self, nullifier: &Hash64) -> bool {
        self.seen.contains_key(nullifier)
    }

    /// Prune every nullifier first seen strictly before `retention_floor_daa` (= `current_daa −
    /// nullifier_retention_daa`), bounding the window. Returns the count pruned.
    pub fn prune_below(&mut self, retention_floor_daa: u64) -> usize {
        let before = self.seen.len();
        self.seen.retain(|_, daa| *daa >= retention_floor_daa);
        before - self.seen.len()
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// The active nullifiers in canonical (sorted) order — the seed a child derives its dedup from and
    /// the preimage of any active-set commitment.
    pub fn iter_sorted(&self) -> impl Iterator<Item = (&Hash64, &u64)> {
        self.seen.iter()
    }

    /// Seed this set from another window (first-seen semantics — keeps the earliest DAA per nullifier).
    /// Used to seed a child's GHOSTDAG dedup from its selected parent's persisted window (§15.2), so a
    /// block reusing a buried ANCESTOR's ticket — not just one in the current mergeset — is detected.
    pub fn merge_from(&mut self, other: &PalwActiveNullifierSet) {
        for (nf, daa) in other.iter_sorted() {
            self.insert(*nf, *daa);
        }
    }

    /// ADR-0039 §15.3 integrated with the §15.2 window: apply a child's mergeset (per-block
    /// `Option<(ticket_nullifier, daa_score)>` in consensus order; `None` = non-PALW) to this set
    /// **seeded from the selected parent's past**, returning the mergeset positions that are DUPLICATE
    /// algo-4 tickets to recolor red, and inserting the first-seen ones into the window. Deterministic;
    /// mirrors the pure [`palw_duplicate_ticket_positions`] while advancing the persistent window.
    pub fn apply_mergeset(&mut self, ordered: &[Option<(Hash64, u64)>]) -> Vec<usize> {
        let mut dups = Vec::new();
        for (i, entry) in ordered.iter().enumerate() {
            if let Some((nf, daa)) = entry {
                if !self.insert(*nf, *daa) {
                    dups.push(i);
                }
            }
        }
        dups
    }
}

impl kaspa_utils::mem_size::MemSizeEstimator for PalwActiveNullifierSet {
    /// Unit-estimable by the number of active nullifiers (the store uses a `Count` cache policy, like
    /// the other per-block Vec/map stores — no byte estimation).
    fn estimate_mem_units(&self) -> usize {
        self.seen.len().max(1)
    }
}

/// A red / duplicate PALW source pays the provider pair **nothing** (design §17.4); the unminted base
/// is NOT redistributed to the current miner (it is unissued / security-reserve). This helper names
/// that rule at the type level.
#[inline]
pub const fn palw_red_or_duplicate_provider_reward() -> (u64, u64) {
    (0, 0)
}

// =============================================================================================
// Canonical Compute v1 §13 — determinism class as DATA (docs/design/misaka-canonical-compute-v1.md).
// The class boundary is a *verifiable predicate* ("reproduces a committed golden vector set"), not a
// hardware enumeration; adding/retiring a class is a governed DATA commit, not a hard fork. Pure types +
// predicates only — inert until a set is committed (none on any shipped preset), so byte-identical live.
// =============================================================================================

/// A committed conformance vector set: the DATA that *defines* one determinism class. A provider is in the
/// class iff it reproduces this set's golden vectors byte-exact (checked off-chain by the §14 self-
/// conformance gate); on-chain only the set's lifecycle is carried so a registration referencing it is
/// decidable. **Multi-set by construction** (rolling migration): a codegen / driver / OS cliff, or a
/// model/manifest update, is a NEW set that coexists with the old, and k=2 pairs form only *within* one set
/// (soundness invariant across the migration window).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwConformanceVectorSetV1 {
    pub version: u16,
    /// Content id of the committed golden vector set — the class predicate's subject and the k=2 pairing key.
    pub set_id: Hash64,
    /// The tier this set serves. Tier activation is DERIVED from an active set referencing this id (§15);
    /// there is deliberately NO separate `enabled_tiers` flag (single source of truth).
    pub model_profile_id: Hash64,
    /// The set becomes referenceable for NEW registrations at this DAA score (once the auditor-capacity gate
    /// is met). `u64::MAX` = a candidate set not yet activated.
    pub activation_daa_score: u64,
    /// Non-retroactive deprecation (isomorphic to revocation): `Some(d)` refuses only NEW registrations at
    /// `daa >= d`; already-active providers and already-minted leaves are untouched.
    pub deprecated_from_daa: Option<u64>,
    /// Minimum bit-exact-reproducing auditor capacity before this set may certify (§13 activation gate): an
    /// audit rail that cannot reproduce a set cannot certify it.
    pub auditor_capacity_threshold: u32,
}

impl PalwConformanceVectorSetV1 {
    /// (A)-1 registration predicate (§13/§14) — may a NEW provider registration referencing this set be
    /// admitted at `daa_score`, given the currently measured bit-exact auditor capacity for this set?
    /// Requires: past activation, not deprecated (non-retroactive), and the auditor-capacity gate met. Pure.
    #[inline]
    pub fn registerable(&self, daa_score: u64, measured_auditor_capacity: u32) -> bool {
        daa_score >= self.activation_daa_score
            && self.deprecated_from_daa.is_none_or(|d| daa_score < d)
            && measured_auditor_capacity >= self.auditor_capacity_threshold
    }
}

/// §13 — two providers may form a k=2 pair iff they reference the SAME conformance vector set (same
/// determinism class). Distinct sets NEVER pair, even within one tier during a rolling migration — that is
/// what keeps soundness invariant while a new set coexists with the old.
#[inline]
pub fn palw_providers_can_pair(a_set_id: &Hash64, b_set_id: &Hash64) -> bool {
    a_set_id == b_set_id
}

/// §13/§15 — tier activation is DERIVED, never a flag: a tier (`model_profile_id`) is live at `daa_score`
/// iff at least one committed set referencing it is `registerable` there. `capacity(set_id)` supplies the
/// measured bit-exact auditor capacity per set. QW9 is the only tier with an active set at genesis; QW4
/// with no active set is naturally non-live (re-enable = commit a QW4 set — a data commit, not a fork).
pub fn palw_tier_is_live(
    sets: &[PalwConformanceVectorSetV1],
    model_profile_id: &Hash64,
    daa_score: u64,
    capacity: impl Fn(&Hash64) -> u32,
) -> bool {
    sets.iter().any(|s| &s.model_profile_id == model_profile_id && s.registerable(daa_score, capacity(&s.set_id)))
}

// =============================================================================================
// Canonical Compute v1 §17 — MODEL-as-data. The set record is the SOLE surface through which a model /
// MoE / VLM / trace-restructure change reaches the chain; consensus sees only this record + opaque hashes,
// so a new-model migration is a DATA commit, not a fork (docs/design/misaka-canonical-compute-v1.md §17).
// Pure types + predicates only — a consensus island with zero live callers, no serialized instance on any
// preset/header/store/leaf, so byte-identical live.
// =============================================================================================

/// §17.3 — the integer-only economic VALUES a set record carries; the FORMULAS and FLOORS stay in protocol
/// (§17.5 defense 2). Integer-only by design — a float on any consensus-adjacent path is a determinism
/// hazard.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwSetEconParamsV1 {
    /// Per-leaf minimum provider bond (VALUE; the floor is a protocol check, [`PalwComputeSetRecordV1::registerable`]).
    pub min_leaf_bond_sompi: u64,
    /// Job timeout in DAA (VALUE).
    pub job_timeout_daa: u64,
}

pub const PALW_WEIGHT_FACTOR_BPS_MAX: u16 = 10_000;

/// §17.3 — the model-as-data migration record. Extends the §13 set by *referencing* an immutable `set_id`
/// (the content-id / k=2 pairing key) and binding a compute-spec version, an OPAQUE model manifest, the
/// class predicate (`vector_commitment`), integer econ VALUES, and a governed credit ramp to it. A new
/// model / MoE / VLM is a new record; consensus never parses the model, only these fields + opaque hashes.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwComputeSetRecordV1 {
    pub version: u16,
    /// The determinism class this record governs — the immutable content-id / pairing key (§13), NOT
    /// redefined here.
    pub set_id: Hash64,
    /// The op-catalog version this set's providers/auditors run (§17.4); a bump is a spec release + software
    /// rollout, not a consensus rule change.
    pub compute_spec_version: u32,
    /// OPAQUE — weights / tokenizer / quant / shape live in DA; consensus never parses it.
    pub model_manifest_hash: Hash64,
    /// The committed golden vector set = the class predicate (§11/§13); providers reproduce it byte-exact.
    pub vector_commitment: Hash64,
    /// Attested K0 benchmark commitment backing `compute_work_scale` (§17.5 defense 3). Opaque.
    pub quantum_calibration_evidence: Hash64,
    /// The integer quantum→work scale VALUE (the FORMULA `normalize_palw_work` + the cap `E=H+min(C,4H)`
    /// stay protocol). Credited RAMPED via [`Self::effective_compute_work_scale`].
    pub compute_work_scale: u64,
    /// Integer econ VALUES (formulas + floors are protocol).
    pub econ_params: PalwSetEconParamsV1,
    /// Per-set credit ramp in basis points (0..=10000), governed + rate-limited (§17.5 defense 3). A shadow
    /// set commits at 0 and ramps up.
    pub weight_factor_bps: u16,
    /// Non-retroactive lifecycle (§13, frozen): referenceable for NEW registrations in
    /// `[activation_daa_score, deprecated_from_daa)`.
    pub activation_daa_score: u64,
    pub deprecated_from_daa: Option<u64>,
    /// The per-set auditor-capacity gate (§13): may not certify below this bit-exact-reproducing capacity.
    pub auditor_capacity_threshold: u32,
    /// Off-chain evidence backing the measured auditor capacity (opaque).
    pub auditor_capacity_evidence_hash: Hash64,
}

impl PalwComputeSetRecordV1 {
    /// The compute-work scale actually credited = `compute_work_scale · weight_factor_bps / 10000` (integer
    /// floor division, saturating). A shadow set (bps 0) credits ZERO DAG weight — it serves MIL fee
    /// traffic + accumulates canary stats without weight (§17.4).
    #[inline]
    pub fn effective_compute_work_scale(&self) -> u64 {
        (self.compute_work_scale as u128 * self.weight_factor_bps.min(PALW_WEIGHT_FACTOR_BPS_MAX) as u128
            / PALW_WEIGHT_FACTOR_BPS_MAX as u128) as u64
    }

    /// (A)-1 registration predicate, record form (§17.5 fix 4): past activation, not deprecated
    /// (non-retroactive), the auditor-capacity gate met, `weight_factor_bps` in range, and the econ VALUES
    /// respect the protocol floor. Pure.
    pub fn registerable(&self, daa_score: u64, measured_auditor_capacity: u32, econ_floor: &PalwSetEconParamsV1) -> bool {
        daa_score >= self.activation_daa_score
            && self.deprecated_from_daa.is_none_or(|d| daa_score < d)
            && measured_auditor_capacity >= self.auditor_capacity_threshold
            && self.weight_factor_bps <= PALW_WEIGHT_FACTOR_BPS_MAX
            && self.econ_params.min_leaf_bond_sompi >= econ_floor.min_leaf_bond_sompi
            && self.econ_params.job_timeout_daa >= econ_floor.job_timeout_daa
    }
}

/// §17.5 fix 4 — registration = a valid reference to an ACTIVE set record: resolve `set_id` to a
/// registerable record. The record-based analogue of [`PalwConformanceVectorSetV1::registerable`]. Pure.
pub fn palw_registration_references_active_set(
    records: &[PalwComputeSetRecordV1],
    set_id: &Hash64,
    daa_score: u64,
    measured_auditor_capacity: u32,
    econ_floor: &PalwSetEconParamsV1,
) -> bool {
    records.iter().any(|r| &r.set_id == set_id && r.registerable(daa_score, measured_auditor_capacity, econ_floor))
}

/// §17.5 fix 2 — resolve the compute-work scale a source's set is credited at, keeping the FORMULA
/// (`normalize_palw_work`) + cap in protocol. Returns the matching active record's RAMPED scale, or
/// `fallback` (the protocol default, e.g. the const `palw_compute_work_scale`) when no record governs the
/// source. **Activation seam** (see `ghostdag/protocol.rs`): at activation GHOSTDAG passes the source's
/// `set_id` + the epoch's active records here in place of the flat const scalar. Pure.
pub fn resolve_compute_work_scale(records: &[PalwComputeSetRecordV1], set_id: &Hash64, daa_score: u64, fallback: u64) -> u64 {
    records
        .iter()
        .find(|r| &r.set_id == set_id && daa_score >= r.activation_daa_score && r.deprecated_from_daa.is_none_or(|d| daa_score < d))
        .map(|r| r.effective_compute_work_scale())
        .unwrap_or(fallback)
}

/// §17.5 defense 3 — a governed `weight_factor_bps` change is valid only if it moves by at most
/// `max_step_bps` per commit (rate-limit) and stays in `[0, 10000]`, so a captured governance cannot jump a
/// shadow set straight to full DAG weight. Pure; enforced by protocol.
pub fn palw_weight_ramp_step_valid(prev_bps: u16, next_bps: u16, max_step_bps: u16) -> bool {
    next_bps <= PALW_WEIGHT_FACTOR_BPS_MAX && prev_bps.abs_diff(next_bps) <= max_step_bps
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
    /// The design §26 testnet start values, at the committed **10-BPS PALW genesis** (hash 2 + replica
    /// 8, cap 4 = a permanent 20 % hash floor; 100 ms block interval; epoch 100 DAA ≈ 10 s at 10 BPS;
    /// nullifier retention 1 200 DAA ≈ 120 s). **Inert by construction** (`activation_daa_score =
    /// u64::MAX`) — flipping a real activation score is a re-genesis / hard-fork decision, not a
    /// default.
    ///
    /// RATIONALE (ADR-0039 §"10 vs 40 BPS", decided 2026-07-14): PALW launches on a dedicated 10-BPS
    /// network so the new consensus hot-path (component work, nullifier dedup, lane DAA, overlay
    /// lookups, ML-DSA authorization) has validation-time headroom (100 ms interval vs 25 ms) and
    /// gentler GHOSTDAG pressure (K≈124 / mergeset 248 vs K≈447 / 512) for its first production run.
    /// The lane proportion (1 : 4) and hash-floor fraction (20 %) are IDENTICAL at 10 BPS (2 + 8), so
    /// the coinbase split and all epoch-denominated windows are unchanged — only `total_bps`, the two
    /// lane rates, and the wall-clock-preserving `*_daa` windows scale by 1/4. PALW's LLM throughput is
    /// asynchronous (GPUs fill a ticket inventory; blocks only draw from it), so 10 BPS does NOT
    /// throttle inference. The 40-BPS split (hash 8 + replica 32, epoch 400 / retention 4 800) is
    /// retained as the later `testnet-palw-40` Stage-B stressnet profile, promoted only after the
    /// 10-BPS soak + weight ladder gates.
    pub fn testnet_inert_default() -> Self {
        Self {
            activation_daa_score: u64::MAX,
            total_bps: 10,
            hash_lane_bps: 2,
            replica_lane_bps: 8,
            compute_to_hash_cap: COMPUTE_TO_HASH_CAP,
            epoch_length_daa: 100,
            registration_lead_epochs: 2,
            audit_window_epochs: 6,
            active_window_epochs: 6,
            nullifier_retention_daa: 1_200,
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
// Lane-aware DAA (design §16). The two lanes retarget difficulty INDEPENDENTLY so ticket supply and
// hash rate cannot manipulate each other's difficulty (§16.1); `daa_score` stays the total DAG
// progression. Params + pure per-lane target-time here; the lane-aware `WindowManager` sampling
// (§16.2, only credited-unique-blue sources per lane) and the retarget itself are the activation
// wiring in the `consensus` engine. Inert by construction (no algo-4 header is minted / sampled).
// =============================================================================================

/// Per-second-milliseconds target for one lane: `1000 / lane_bps`, rounded to nearest (min 1). At the
/// frozen 40 BPS split this is 125 ms for the hash lane (8 BPS) and 31 ms for the replica lane (32 BPS,
/// = 31.25 rounded). `lane_bps` must be > 0.
#[inline]
pub fn lane_target_time_ms(lane_bps: u64) -> u64 {
    let bps = lane_bps.max(1);
    ((1000 + bps / 2) / bps).max(1)
}

/// ADR-0039 §16.3 — the per-lane difficulty bits carried by each block (the HOLD sources for the
/// per-lane retarget). Both lanes are carried on EVERY block because the structural blocker is
/// symmetric: a block's selected parent may be on the OTHER lane, so `header.bits` alone cannot supply
/// a lane's "last bits" (that would cross-contaminate). Fixed-width (two `u32`) → borsh + serde +
/// `MemSizeEstimator` storable. **Inert (never written)** on every shipped preset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize)]
pub struct PalwLaneBitsV1 {
    pub hash_bits: u32,
    pub replica_bits: u32,
}

impl PalwLaneBitsV1 {
    pub fn lane_bits(&self, lane: WorkLane) -> u32 {
        match lane {
            WorkLane::HashFloor => self.hash_bits,
            WorkLane::ReplicaPalw => self.replica_bits,
        }
    }

    pub fn with_lane_bits(mut self, lane: WorkLane, bits: u32) -> Self {
        match lane {
            WorkLane::HashFloor => self.hash_bits = bits,
            WorkLane::ReplicaPalw => self.replica_bits = bits,
        }
        self
    }
}

/// ADR-0039 §16.3 lane-difficulty parameters. Each lane keeps its own retarget window and genesis
/// difficulty; a lane with too few samples holds its last bits rather than collapsing to min difficulty
/// (§16.3). All hard-fork / re-genesis knobs.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LaneDifficultyParams {
    pub hash_target_time_ms: u64,
    pub replica_target_time_ms: u64,
    pub hash_window_size: u64,
    pub replica_window_size: u64,
    /// Below this many in-lane samples, hold the last lane bits (no min-difficulty collapse).
    pub min_samples: u64,
    /// Fixed per-leaf compute-work scale (§5.3 `normalize_palw_work`): `ΔC = scale · calc_work(bits)`.
    /// `1` = one leaf is worth exactly its eligibility-target hash-equivalent work (same unit as the
    /// hash lane, never mixed with `calc_work_512`; see `pow_layer0::calc_work_512` audit-L note).
    pub compute_work_scale: u64,
    /// Per-retarget-step clamp: the measured duration ratio is bounded to `[1/f, f]` so a sparse lane
    /// (e.g. a few-GPU launch reaching `min_samples` at ~10× wall-clock) cannot collapse difficulty in
    /// one step (panel FS-6). `lane_retarget_decision`'s `max_adjust_factor`; must be `>= 1`.
    pub max_adjust_factor: u64,
    /// Per-lane sampling rate. The lane window's sample index increments over the LANE-FILTERED
    /// sequence (only in-lane credited blocks), so this is independent of the total-DAG `difficulty_
    /// sample_rate` (panel FS-5). Must be `>= 1`.
    pub hash_sample_rate: u64,
    pub replica_sample_rate: u64,
    /// Genesis difficulty bits per lane (set at re-genesis; inert placeholder `0`).
    pub genesis_hash_bits: u32,
    pub genesis_replica_bits: u32,
}

impl LaneDifficultyParams {
    /// The design §16.3 testnet defaults at the committed **10 BPS** PALW genesis (hash 2 / replica 8)
    /// split, as a `const` so it can live in the `const Params` presets. Windows mirror the single-lane
    /// difficulty window; the genesis bits are re-genesis placeholders (`0` = inert). Inert — nothing
    /// retargets the replica lane until the PALW fence.
    pub const INERT: LaneDifficultyParams = LaneDifficultyParams {
        hash_target_time_ms: 500,    // lane_target_time_ms(2) = 500 ms (2 BPS)
        replica_target_time_ms: 125, // lane_target_time_ms(8) = 125 ms (8 BPS)
        hash_window_size: 2641,
        replica_window_size: 2641,
        min_samples: 60,
        compute_work_scale: 1,
        max_adjust_factor: 2,
        hash_sample_rate: 1,
        replica_sample_rate: 1,
        genesis_hash_bits: 0,
        genesis_replica_bits: 0,
    };

    pub fn testnet_default() -> Self {
        Self::INERT
    }

    /// Structural sanity (positive windows / targets / scale / rates / clamp). Cheap, config-build time.
    pub fn is_structurally_valid(&self) -> bool {
        self.hash_target_time_ms > 0
            && self.replica_target_time_ms > 0
            && self.hash_window_size > 0
            && self.replica_window_size > 0
            && self.compute_work_scale > 0
            && self.max_adjust_factor >= 1
            && self.hash_sample_rate >= 1
            && self.replica_sample_rate >= 1
    }

    /// The genesis bits per lane (the empty-window HOLD source, panel Q6).
    pub fn genesis_bits(&self, lane: WorkLane) -> u32 {
        match lane {
            WorkLane::HashFloor => self.genesis_hash_bits,
            WorkLane::ReplicaPalw => self.genesis_replica_bits,
        }
    }

    /// The lane's window size / min-samples / sample-rate / target-time (per-lane retarget inputs).
    pub fn lane_window_size(&self, lane: WorkLane) -> u64 {
        match lane {
            WorkLane::HashFloor => self.hash_window_size,
            WorkLane::ReplicaPalw => self.replica_window_size,
        }
    }
    pub fn lane_sample_rate(&self, lane: WorkLane) -> u64 {
        match lane {
            WorkLane::HashFloor => self.hash_sample_rate.max(1),
            WorkLane::ReplicaPalw => self.replica_sample_rate.max(1),
        }
    }
    pub fn lane_target_time_ms(&self, lane: WorkLane) -> u64 {
        match lane {
            WorkLane::HashFloor => self.hash_target_time_ms,
            WorkLane::ReplicaPalw => self.replica_target_time_ms,
        }
    }

    /// ADR-0039 §16.3 — the PALW **re-genesis preflight** consistency predicate for the lane-difficulty
    /// params against the genesis header (panel-required). Asserts: structural sanity; the genesis lane
    /// bits are non-zero (`0` is the inert placeholder — an active net MUST set real bits) and the hash
    /// lane's genesis bits EQUAL the genesis header's bits (`genesis_bits`), so the inert single-lane
    /// HOLD (`get_bits(genesis)`) and the active lane-aware HOLD agree at the boundary; `min_samples`
    /// does not exceed either window. NOT evaluated on live nets (inert placeholders would fail it).
    pub fn is_consistent_for_activation(&self, genesis_bits: u32) -> bool {
        self.is_structurally_valid()
            && self.genesis_hash_bits != 0
            && self.genesis_replica_bits != 0
            && self.genesis_hash_bits == genesis_bits
            && self.min_samples <= self.hash_window_size
            && self.min_samples <= self.replica_window_size
    }
}

/// ADR-0039 §16.2 — whether a mergeset source block is sampled into ITS lane's DAA retarget window.
/// Only credited-blue sources count: the hash lane samples algo-3 blues; the compute lane samples
/// **unique, Active, credited** algo-4 blues. Red / duplicate / revoked / zero-headroom PALW blocks
/// carry no lane work and are excluded, and a block never samples the other lane's window (so ticket
/// supply and hash rate cannot manipulate each other's difficulty, §16.1). `daa_score` itself stays
/// total DAG progression, not per-lane. Pure.
pub fn lane_daa_sample_eligible(sample_lane: WorkLane, block_algo_id: u8, credited_blue: bool, unique_active: bool) -> bool {
    if !credited_blue {
        return false;
    }
    match sample_lane {
        WorkLane::HashFloor => block_algo_id == POW_ALGO_ID_BLAKE2B_SHA3,
        WorkLane::ReplicaPalw => block_algo_id == POW_ALGO_ID_PALW_REPLICA && unique_active,
    }
}

/// The per-lane retarget action (design §16.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneRetargetDecision {
    /// Below `min_samples` in-lane samples: keep the current lane bits unchanged — no sudden collapse
    /// to min difficulty on a thin window (§16.3).
    HoldLastBits,
    /// Retarget: the measured mean interval, clamped to `[target/max_factor, target·max_factor]`, that
    /// the difficulty engine multiplies the current target by (`new_target = current · clamped /
    /// target`; faster-than-target ⇒ smaller target ⇒ higher difficulty).
    Adjust { clamped_measured_ms: u64 },
}

/// ADR-0039 §16.3 — decide the lane retarget from the in-lane sample count and the measured mean
/// interval. Holds the last bits below `min_samples`; otherwise clamps the measured interval to
/// `[target/max_adjust_factor, target·max_adjust_factor]` so one burst / stall cannot swing difficulty
/// arbitrarily. Pure; the big-int `current·clamped/target` step is the difficulty engine's, reused
/// per-lane. `target_ms` / `max_adjust_factor` are treated as ≥ 1.
pub fn lane_retarget_decision(
    sample_count: u64,
    min_samples: u64,
    measured_ms: u64,
    target_ms: u64,
    max_adjust_factor: u64,
) -> LaneRetargetDecision {
    if sample_count < min_samples {
        return LaneRetargetDecision::HoldLastBits;
    }
    let f = max_adjust_factor.max(1);
    let target = target_ms.max(1);
    let lo = (target / f).max(1);
    let hi = target.saturating_mul(f);
    LaneRetargetDecision::Adjust { clamped_measured_ms: measured_ms.clamp(lo, hi) }
}

// §18.1 — unit-estimable `MemSizeEstimator` for the PALW overlay-store value types (the store uses a
// `Count` cache policy, no byte estimation), so `DbPalwStore` can cache them like the other per-key
// stores. Inert: never written on a shipped preset.
impl kaspa_utils::mem_size::MemSizeEstimator for PalwPublicLeafV1 {}
impl kaspa_utils::mem_size::MemSizeEstimator for PalwBatchManifestV1 {}
impl kaspa_utils::mem_size::MemSizeEstimator for PalwBatchCertificateV1 {}
impl kaspa_utils::mem_size::MemSizeEstimator for PalwProviderBondPayloadV1 {}
impl kaspa_utils::mem_size::MemSizeEstimator for PalwBatchStatus {}
// Beacon: the per-epoch derived state (block-keyed) + the per-epoch commit/reveal accumulator (the
// stored commitments are `Hash64`; the raw reveal is never persisted). Empty estimators — `Count`-cached
// like the batch overlay values.
impl kaspa_utils::mem_size::MemSizeEstimator for PalwBeaconStateV1 {}
impl kaspa_utils::mem_size::MemSizeEstimator for PalwBeaconEpochAccumV1 {}
impl kaspa_utils::mem_size::MemSizeEstimator for PalwLaneBitsV1 {}

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

    // ---- Canonical Compute v1 §13: determinism class as data ----
    fn cvset(set: u8, tier: u8, activation: u64, deprecated: Option<u64>, cap_threshold: u32) -> PalwConformanceVectorSetV1 {
        PalwConformanceVectorSetV1 {
            version: 1,
            set_id: h(set),
            model_profile_id: h(tier),
            activation_daa_score: activation,
            deprecated_from_daa: deprecated,
            auditor_capacity_threshold: cap_threshold,
        }
    }

    #[test]
    fn conformance_set_registerable_window_and_gates() {
        let s = cvset(0x51, 0x99, 100, Some(500), 3);
        // Before activation: not registerable regardless of capacity.
        assert!(!s.registerable(99, 100));
        // In window + capacity met: registerable.
        assert!(s.registerable(100, 3));
        assert!(s.registerable(499, 3));
        // Capacity gate: below threshold ⇒ refused (canary verifiability is a per-set precondition).
        assert!(!s.registerable(200, 2));
        // Non-retroactive deprecation: at/after `deprecated_from_daa`, only NEW registration is refused.
        assert!(!s.registerable(500, 100));
        assert!(!s.registerable(10_000, 100));
        // A never-deprecated set has no upper bound.
        assert!(cvset(0x51, 0x99, 0, None, 0).registerable(u64::MAX, 0));
    }

    #[test]
    fn palw_pairing_is_same_set_only() {
        // Same set id pairs; distinct sets never pair — even within one tier during a rolling migration.
        assert!(palw_providers_can_pair(&h(0x51), &h(0x51)));
        assert!(!palw_providers_can_pair(&h(0x51), &h(0x52)));
    }

    #[test]
    fn tier_activation_is_derived_from_an_active_set() {
        let qw9 = h(0x99);
        let qw4 = h(0x44);
        // Genesis: one active QW9 set, no QW4 set.
        let sets = vec![cvset(0x51, 0x99, 0, None, 1)];
        let cap = |_id: &Hash64| 4u32; // ample auditor capacity
        // QW9 is live (an active set references it); QW4 is naturally non-live (no set) — no flag needed.
        assert!(palw_tier_is_live(&sets, &qw9, 0, cap));
        assert!(!palw_tier_is_live(&sets, &qw4, 0, cap));

        // Rolling migration: a second QW9 set (new manifest/driver) coexists; the tier stays live and
        // providers pair only within their own set (checked by palw_providers_can_pair).
        let sets = vec![cvset(0x51, 0x99, 0, Some(1_000), 1), cvset(0x52, 0x99, 900, None, 1)];
        assert!(palw_tier_is_live(&sets, &qw9, 950, cap)); // old (in window) + new both referenceable
        assert!(palw_tier_is_live(&sets, &qw9, 2_000, cap)); // old deprecated, new still live ⇒ tier live
        // If the only set's auditor capacity is below threshold, the tier is NOT live (gate bites).
        let starved = vec![cvset(0x53, 0x99, 0, None, 5)];
        assert!(!palw_tier_is_live(&starved, &qw9, 0, |_| 4));
    }

    // ---- Canonical Compute v1 §17: model-as-data record ----
    fn econ(bond: u64, timeout: u64) -> PalwSetEconParamsV1 {
        PalwSetEconParamsV1 { min_leaf_bond_sompi: bond, job_timeout_daa: timeout }
    }
    fn record(set: u8, activation: u64, deprecated: Option<u64>, cap_threshold: u32, scale: u64, weight_bps: u16, bond: u64) -> PalwComputeSetRecordV1 {
        PalwComputeSetRecordV1 {
            version: 1,
            set_id: h(set),
            compute_spec_version: 1,
            model_manifest_hash: h(0xA0),
            vector_commitment: h(0xB0),
            quantum_calibration_evidence: h(0xC0),
            compute_work_scale: scale,
            econ_params: econ(bond, 100),
            weight_factor_bps: weight_bps,
            activation_daa_score: activation,
            deprecated_from_daa: deprecated,
            auditor_capacity_threshold: cap_threshold,
            auditor_capacity_evidence_hash: h(0xD0),
        }
    }

    #[test]
    fn compute_set_record_ramp_and_registerable() {
        let floor = econ(1_000, 50);
        // weight ramp: effective = scale * bps / 10000 (floor division). Shadow (0 bps) credits 0.
        assert_eq!(record(0x51, 0, None, 1, 8_000, 0, 1_000).effective_compute_work_scale(), 0);
        assert_eq!(record(0x51, 0, None, 1, 8_000, 5_000, 1_000).effective_compute_work_scale(), 4_000);
        assert_eq!(record(0x51, 0, None, 1, 8_000, 10_000, 1_000).effective_compute_work_scale(), 8_000);
        // registerable: gates + the protocol econ FLOOR (a commit under the bond floor is refused).
        let r = record(0x51, 100, Some(500), 3, 8_000, 5_000, 1_000);
        assert!(r.registerable(100, 3, &floor));
        assert!(!r.registerable(99, 3, &floor), "before activation");
        assert!(!r.registerable(500, 3, &floor), "non-retroactive deprecation");
        assert!(!r.registerable(200, 2, &floor), "auditor-capacity gate");
        // Bond below the protocol floor ⇒ refused even though every other gate passes (§17.5 defense 2).
        assert!(!record(0x51, 0, None, 0, 8_000, 5_000, 999).registerable(0, 0, &floor));
    }

    #[test]
    fn resolve_compute_work_scale_matches_active_record_else_fallback() {
        let recs = vec![record(0x51, 0, Some(1_000), 1, 8_000, 5_000, 1_000)]; // ramped → 4_000
        // Matching active set ⇒ the record's RAMPED scale; unknown set or no record ⇒ the protocol fallback.
        assert_eq!(resolve_compute_work_scale(&recs, &h(0x51), 500, 42), 4_000);
        assert_eq!(resolve_compute_work_scale(&recs, &h(0x99), 500, 42), 42, "unknown set ⇒ fallback");
        assert_eq!(resolve_compute_work_scale(&recs, &h(0x51), 2_000, 42), 42, "deprecated ⇒ fallback");
        assert_eq!(resolve_compute_work_scale(&[], &h(0x51), 500, 42), 42, "no records ⇒ fallback (today's flat scale)");
    }

    #[test]
    fn registration_references_active_set_and_ramp_step_bounded() {
        let floor = econ(1_000, 50);
        let recs = vec![record(0x51, 100, None, 1, 8_000, 5_000, 1_000)];
        assert!(palw_registration_references_active_set(&recs, &h(0x51), 100, 1, &floor));
        assert!(!palw_registration_references_active_set(&recs, &h(0x52), 100, 1, &floor), "no such set");
        assert!(!palw_registration_references_active_set(&recs, &h(0x51), 99, 1, &floor), "before activation");
        // §17.5 defense 3: a governed weight change is rate-limited and clamped to [0,10000].
        assert!(palw_weight_ramp_step_valid(0, 500, 500));
        assert!(!palw_weight_ramp_step_valid(0, 5_000, 500), "a jump beyond the step is refused (no shadow→full)");
        assert!(!palw_weight_ramp_step_valid(9_800, 10_200, 500), "clamped to 10000");
    }

    #[test]
    fn epoch_proof_bundle_active_set_records_roundtrip() {
        // The I-12 tail field borsh-round-trips (carried-but-unread).
        let bundle = PalwEpochProofBundleV1 {
            from_epoch: 1,
            to_epoch: 1,
            beacon_chain: vec![],
            batch_manifests: vec![],
            leaf_chunks: vec![],
            certificates: vec![],
            revocations: vec![],
            nullifier_frontier_root: h(0x60),
            active_set_records: vec![record(0x51, 0, None, 1, 8_000, 5_000, 1_000)],
        };
        let bytes = borsh::to_vec(&bundle).unwrap();
        assert_eq!(PalwEpochProofBundleV1::try_from_slice(&bytes).unwrap(), bundle);
    }

    fn sample_leaf() -> PalwPublicLeafV1 {
        PalwPublicLeafV1 {
            version: 1,
            batch_id: h(1),
            leaf_index: 7,
            job_nullifier: h(2),
            ticket_nullifier_commitment: h(3),
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
        m2.ticket_nullifier_commitment = h(0x33);
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
    fn beacon_signing_hashes_are_operation_network_and_field_bound() {
        let bond = op(0x22, 7);
        let random = [0xA5; 64];
        let mut commit = PalwBeaconCommitV1 {
            version: 1,
            epoch: 12,
            bond_outpoint: bond,
            commitment: beacon_commitment(12, &random, &bond),
            signature: vec![1, 2, 3],
        };
        let reveal = PalwBeaconRevealV1 { version: 1, epoch: 12, bond_outpoint: bond, random_64: random, signature: vec![4, 5, 6] };

        let network = 0x91_00_00_6e;
        let commit_hash = commit.signing_hash(network);
        let reveal_hash = reveal.signing_hash(network);
        assert_ne!(commit_hash, reveal_hash, "commit/reveal signing domains must be disjoint");
        assert_ne!(commit_hash, commit.signing_hash(network ^ 1), "cross-network replay must fail");
        assert_ne!(reveal_hash, reveal.signing_hash(network ^ 1), "cross-network replay must fail");

        // Signature bytes are excluded from their own message, while every semantic field is bound.
        commit.signature = vec![9; 32];
        assert_eq!(commit_hash, commit.signing_hash(network));
        let mut changed = commit.clone();
        changed.epoch += 1;
        assert_ne!(commit_hash, changed.signing_hash(network));
        changed = commit.clone();
        changed.bond_outpoint.index += 1;
        assert_ne!(commit_hash, changed.signing_hash(network));
        changed = commit.clone();
        changed.commitment = h(0x99);
        assert_ne!(commit_hash, changed.signing_hash(network));

        let mut reveal_changed = reveal.clone();
        reveal_changed.random_64[0] ^= 1;
        assert_ne!(reveal_hash, reveal_changed.signing_hash(network));
    }

    #[test]
    fn beacon_phase_helpers_enforce_e_minus_two_and_e_minus_one() {
        assert_eq!(beacon_commit_target_epoch(10), Some(12));
        assert_eq!(beacon_reveal_target_epoch(10), Some(11));
        assert!(beacon_commit_phase_accepts(10, 12));
        assert!(!beacon_commit_phase_accepts(10, 11));
        assert!(!beacon_commit_phase_accepts(10, 13));
        assert!(beacon_reveal_phase_accepts(10, 11));
        assert!(!beacon_reveal_phase_accepts(10, 10));
        assert!(!beacon_reveal_phase_accepts(10, 12));

        let bond = op(0x23, 0);
        let commit = PalwBeaconCommitV1 { version: 1, epoch: 12, bond_outpoint: bond, commitment: h(1), signature: vec![] };
        let reveal = PalwBeaconRevealV1 { version: 1, epoch: 11, bond_outpoint: bond, random_64: [7; 64], signature: vec![] };
        assert!(commit.is_in_phase(10));
        assert!(reveal.is_in_phase(10));

        // Epoch arithmetic never wraps/saturates into an accepted target.
        assert_eq!(beacon_commit_target_epoch(u64::MAX - 1), None);
        assert_eq!(beacon_reveal_target_epoch(u64::MAX), None);
        assert!(!beacon_commit_phase_accepts(u64::MAX - 1, u64::MAX));
        assert!(!beacon_reveal_phase_accepts(u64::MAX, 0));
    }

    #[test]
    fn beacon_valid_reveal_root_commits_opened_entropy_not_public_commitment() {
        let bond = op(0x24, 3);
        let reveal_a = PalwBeaconRevealV1 { version: 1, epoch: 9, bond_outpoint: bond, random_64: [0x11; 64], signature: vec![] };
        let reveal_b = PalwBeaconRevealV1 { random_64: [0x12; 64], ..reveal_a.clone() };
        let entropy_a = reveal_a.entropy_digest();
        let entropy_b = reveal_b.entropy_digest();
        let public_commitment_a = beacon_commitment(reveal_a.epoch, &reveal_a.random_64, &bond);

        assert_ne!(entropy_a, public_commitment_a, "reveal entropy has a distinct domain from the E-2 commitment");
        assert_ne!(entropy_a, entropy_b, "the opened raw random must influence the digest");
        assert_ne!(
            beacon_valid_reveals_root(&[(bond, entropy_a)]),
            beacon_valid_reveals_root(&[(bond, entropy_b)]),
            "different opened secrets must produce different seed roots"
        );
        assert_ne!(
            beacon_valid_reveals_root(&[(bond, entropy_a)]),
            beacon_valid_reveals_root(&[(bond, public_commitment_a)]),
            "the public commitment is not a substitute reveal entropy input"
        );
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
        let cm = private_match_commitment(
            &base.output_commitment,
            &base.canonical_gemm_trace_root,
            &base.operation_schedule_commitment,
            &base.job_set_commitment,
            &a,
            &b,
        );
        assert_ne!(
            cm,
            private_match_commitment(
                &base.output_commitment,
                &base.canonical_gemm_trace_root,
                &base.operation_schedule_commitment,
                &base.job_set_commitment,
                &b,
                &a
            )
        );
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
            votes: vec![PalwAuditorVoteV1 {
                bond_outpoint: op(0x40, 0),
                vote: 1,
                checked_leaf_bitmap_root: h(6),
                signature: vec![9; 4],
            }],
        };
        let cback = PalwBatchCertificateV1::try_from_slice(&borsh::to_vec(&cert).unwrap()).unwrap();
        assert_eq!(cert, cback);
        assert!(cert.is_active_at(7) && cert.is_active_at(12));
        assert!(!cert.is_active_at(6) && !cert.is_active_at(13));
    }

    fn valid_palw_overlay_payloads() -> Vec<(u8, Vec<u8>)> {
        let provider = PalwProviderBondPayloadV1 {
            version: PALW_PAYLOAD_VERSION_V1,
            owner_public_key: vec![0x41; STAKE_VALIDATOR_PUBKEY_LEN],
            operator_group_id: h(1),
            runtime_classes: vec![h(2), h(3)],
            capacity_by_shape: vec![(1, 10), (2, 20)],
            reward_key_root: h(4),
            amount_sompi: 1_000,
            unbond_delay_epochs: 10,
        };
        let manifest = PalwBatchManifestV1 {
            version: PALW_PAYLOAD_VERSION_V1,
            batch_id: h(5),
            registration_epoch: 7,
            model_profile_id: h(6),
            runtime_class_id: h(7),
            leaf_count: 1,
            chunk_count: 1,
            leaf_root: h(8),
            descriptor_root: h(9),
            total_leaf_bond_sompi: 10,
            audit_policy_id: h(10),
            activation_not_before_epoch: 9,
            expiry_epoch: 15,
        };
        let mut leaf = sample_leaf();
        leaf.batch_id = h(5);
        let chunk = PalwLeafChunkV1 { version: PALW_PAYLOAD_VERSION_V1, batch_id: h(5), chunk_index: 0, leaves: vec![leaf] };
        let certificate = PalwBatchCertificateV1 {
            version: PALW_PAYLOAD_VERSION_V1,
            batch_id: h(5),
            manifest_hash: h(11),
            leaf_root: h(8),
            audit_beacon_epoch: 8,
            audit_sample_root: h(12),
            passed_leaf_count: 1,
            rejected_leaf_bitmap_root: h(13),
            certificate_epoch: 9,
            activation_epoch: 10,
            expiry_epoch: 15,
            auditor_set_commitment: h(14),
            votes: vec![PalwAuditorVoteV1 {
                bond_outpoint: op(0x42, 0),
                vote: 1,
                checked_leaf_bitmap_root: h(15),
                signature: vec![0x55; STAKE_ATTESTATION_SIG_LEN],
            }],
        };
        let revocation = PalwRevocationV1 {
            version: PALW_PAYLOAD_VERSION_V1,
            batch_id: h(5),
            effective_daa_score: 1_000,
            reason_code: 1,
            evidence_hash: h(16),
        };
        let bond = op(0x43, 1);
        let random = [0x66; 64];
        let commit = PalwBeaconCommitV1 {
            version: PALW_PAYLOAD_VERSION_V1,
            epoch: 12,
            bond_outpoint: bond,
            commitment: beacon_commitment(12, &random, &bond),
            signature: vec![0x77; STAKE_ATTESTATION_SIG_LEN],
        };
        let reveal = PalwBeaconRevealV1 {
            version: PALW_PAYLOAD_VERSION_V1,
            epoch: 12,
            bond_outpoint: bond,
            random_64: random,
            signature: vec![0x88; STAKE_ATTESTATION_SIG_LEN],
        };
        vec![
            (0x30, borsh::to_vec(&provider).unwrap()),
            (0x31, borsh::to_vec(&manifest).unwrap()),
            (0x32, borsh::to_vec(&chunk).unwrap()),
            (0x33, borsh::to_vec(&certificate).unwrap()),
            (0x34, borsh::to_vec(&revocation).unwrap()),
            (0x35, borsh::to_vec(&commit).unwrap()),
            (0x36, borsh::to_vec(&reveal).unwrap()),
        ]
    }

    #[test]
    fn palw_stateless_payload_validator_accepts_all_frozen_v1_kinds() {
        for (kind, payload) in valid_palw_overlay_payloads() {
            assert_eq!(validate_palw_overlay_payload(kind, &payload), Ok(()), "kind 0x{kind:02x}");
        }
        // 0x37 is reserved but has no frozen PALW owner-binding wire type yet; fail closed rather
        // than silently treating a DNS unbond authorization as a PALW provider authorization.
        assert_eq!(validate_palw_overlay_payload(0x37, &[]), Err(PalwTxError::UnsupportedKind(0x37)));
    }

    #[test]
    fn palw_stateless_payload_validator_rejects_malformed_noncanonical_and_oversized() {
        let payloads = valid_palw_overlay_payloads();

        // Strict Borsh decoding rejects trailing bytes after a valid object.
        let mut trailing = payloads.iter().find(|(kind, _)| *kind == 0x31).unwrap().1.clone();
        trailing.push(0);
        assert_eq!(validate_palw_overlay_payload(0x31, &trailing), Err(PalwTxError::Decode));

        let mut bad_commit: PalwBeaconCommitV1 =
            borsh::from_slice(&payloads.iter().find(|(kind, _)| *kind == 0x35).unwrap().1).unwrap();
        bad_commit.version = 2;
        assert_eq!(validate_palw_overlay_payload(0x35, &borsh::to_vec(&bad_commit).unwrap()), Err(PalwTxError::UnsupportedVersion(2)));
        bad_commit.version = 1;
        bad_commit.signature.pop();
        assert_eq!(
            validate_palw_overlay_payload(0x35, &borsh::to_vec(&bad_commit).unwrap()),
            Err(PalwTxError::InvalidSignatureLen(STAKE_ATTESTATION_SIG_LEN - 1))
        );

        let mut chunk: PalwLeafChunkV1 = borsh::from_slice(&payloads.iter().find(|(kind, _)| *kind == 0x32).unwrap().1).unwrap();
        chunk.leaves.push(chunk.leaves[0].clone());
        assert_eq!(
            validate_palw_overlay_payload(0x32, &borsh::to_vec(&chunk).unwrap()),
            Err(PalwTxError::NonCanonical("leaf_chunk.ticket_nullifiers"))
        );

        let oversized = vec![0u8; PALW_MAX_OVERLAY_PAYLOAD_BYTES + 1];
        assert_eq!(
            validate_palw_overlay_payload(0x30, &oversized),
            Err(PalwTxError::PayloadTooLarge { len: PALW_MAX_OVERLAY_PAYLOAD_BYTES + 1, max: PALW_MAX_OVERLAY_PAYLOAD_BYTES })
        );
        assert_eq!(validate_palw_overlay_payload(0x2f, &[]), Err(PalwTxError::UnsupportedKind(0x2f)));
    }

    #[test]
    fn params_default_is_inert_and_structurally_valid() {
        let p = PalwParams::testnet_inert_default();
        assert_eq!(p.activation_daa_score, u64::MAX);
        assert!(!p.is_active_at(0));
        assert!(!p.is_active_at(u64::MAX - 1));
        assert!(p.is_structurally_valid());
        // the committed 10-BPS PALW split: 2 + 8 = 10, 1:4 cap, 20 % hash floor.
        assert_eq!(p.total_bps, 10);
        assert_eq!((p.hash_lane_bps, p.replica_lane_bps), (2, 8));
        assert_eq!(p.hash_lane_bps + p.replica_lane_bps, p.total_bps);
        assert_eq!(p.replica_lane_bps, p.compute_to_hash_cap * p.hash_lane_bps);
        assert_eq!(p.hash_lane_bps * 5, p.total_bps); // 2/10 = 20 %
        // wall-clock-preserving DAA windows scaled by 1/4 vs the 40-BPS profile.
        assert_eq!(p.epoch_length_daa, 100); // ≈ 10 s at 10 BPS
        assert_eq!(p.nullifier_retention_daa, 1_200); // ≈ 120 s

        // borsh roundtrip.
        let back = PalwParams::try_from_slice(&borsh::to_vec(&p).unwrap()).unwrap();
        assert_eq!(p, back);

        // a malformed split is rejected.
        let mut bad = p.clone();
        bad.replica_lane_bps = 33; // 2 + 33 != 10 and 33 > 4·2
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
        assert_eq!(compute_headroom(h, w(399), cap), w(1));
        assert_eq!(compute_headroom(h, w(400), cap), w(0));
        assert_eq!(compute_headroom(h, w(401), cap), w(0));
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
        assert_eq!(compute_headroom(big, w(0), 4), big); // sat(4·MAX) - 0 = MAX
        assert_eq!(compute_headroom(big, big, 4), w(0));
        assert_eq!(compute_headroom(w(100), w(0), 0), w(0));
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
            for ev in [
                ManifestAccepted,
                ChunksAndBondsComplete,
                AuditBeaconReached,
                CertificateQuorum,
                AuditFailed,
                Timeout,
                ActivationReached,
                ExpiryReached,
                FraudEvidence,
            ] {
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
    fn palw_batch_completeness_da_and_template_selection() {
        // §9.3: a batch is incomplete until every chunk is on-chain.
        let mut t = PalwBatchChunkTracker::new(3);
        assert!(!t.is_complete() && t.missing_count() == 3);
        assert!(t.record(0) && t.record(2));
        assert!(!t.record(2)); // duplicate
        assert!(!t.record(5)); // out of range
        assert!(!t.is_complete() && t.missing_count() == 1);
        assert!(t.record(1));
        assert!(t.is_complete() && t.missing_count() == 0);

        // §18 (I-6): DA bundle needs manifest + all chunks + cert + beacon.
        assert!(palw_da_bundle_complete(true, &t, true, true));
        assert!(!palw_da_bundle_complete(false, &t, true, true)); // manifest missing
        let incomplete = PalwBatchChunkTracker::new(2); // 0 chunks recorded
        assert!(!palw_da_bundle_complete(true, &incomplete, true, true)); // chunks missing

        // §22: the template picks the first Active ticket that WINS the draw (lenient bits ⇒ zero digest wins).
        let bits = 0x2100ffff_u32;
        let losing = PalwTemplateCandidate { eligibility_digest: Hash64::from_bytes([0xff; 64]), nonce: 0, ticket_nullifier: h(1) };
        let nf = h(2);
        let winner = PalwTemplateCandidate {
            eligibility_digest: Hash64::from_bytes([0u8; 64]),
            nonce: u64::from_le_bytes([2u8; 8]), // low64(h(2))
            ticket_nullifier: nf,
        };
        // At a tight target the "losing" digest (all-ones) misses, and the second candidate wins.
        assert_eq!(palw_select_template_ticket(&[losing.clone(), winner.clone()], 0x1c00ffff), Some(1));
        // No winner ⇒ None (⇒ mine algo-3 instead).
        let only_losers = [PalwTemplateCandidate { nonce: 999, ..losing.clone() }];
        assert_eq!(palw_select_template_ticket(&only_losers, 0x1c00ffff), None);
        // With lenient bits the first candidate (zero digest, matching nonce) wins.
        let first = PalwTemplateCandidate {
            eligibility_digest: Hash64::from_bytes([0u8; 64]),
            nonce: u64::from_le_bytes([1u8; 8]),
            ticket_nullifier: h(1),
        };
        assert_eq!(palw_select_template_ticket(&[first, winner], bits), Some(0));
    }

    #[test]
    fn palw_ticket_verify_predicate() {
        let nf = h(11);
        let nonce = u64::from_le_bytes([11u8; 8]); // low64(nf), since nf == [11; 64]
        let dig = Hash64::from_bytes([0u8; 64]); // Uint512 = 0 ⇒ wins any target
        let bits = 0x2100ffff_u32; // very high target
        let binding = PalwTicketBinding {
            // I-13: the leaf stores the COMMITMENT; verify opens it with the header's raw `nf`.
            ticket_nullifier_commitment: ticket_nullifier_commitment(&nf),
            proof_type: 1,
            leaf_activation_epoch: 7,
            leaf_expiry_epoch: 13,
            target_daa_interval: 100,
        };
        let cc = h(20);
        // Happy path: every rule satisfied.
        assert_eq!(verify_palw_ticket(&nf, 1, &cc, bits, nonce, 100, &dig, &binding, true, 10, &cc, bits, true), Ok(()));
        // Each rule, one violation at a time.
        assert_eq!(
            verify_palw_ticket(&h(99), 1, &cc, bits, nonce, 100, &dig, &binding, true, 10, &cc, bits, true),
            Err(PalwTicketReject::NullifierMismatch)
        );
        assert_eq!(
            verify_palw_ticket(&nf, 2, &cc, bits, nonce, 100, &dig, &binding, true, 10, &cc, bits, true),
            Err(PalwTicketReject::ProofTypeMismatch)
        );
        assert_eq!(
            verify_palw_ticket(&nf, 1, &cc, bits, nonce, 100, &dig, &binding, true, 6, &cc, bits, true),
            Err(PalwTicketReject::LeafNotActive)
        );
        assert_eq!(
            verify_palw_ticket(&nf, 1, &cc, bits, nonce, 100, &dig, &binding, false, 10, &cc, bits, true),
            Err(PalwTicketReject::CertNotActive)
        );
        assert_eq!(
            verify_palw_ticket(&nf, 1, &cc, bits, nonce, 999, &dig, &binding, true, 10, &cc, bits, true),
            Err(PalwTicketReject::IntervalMismatch)
        );
        assert_eq!(
            verify_palw_ticket(&nf, 1, &h(21), bits, nonce, 100, &dig, &binding, true, 10, &cc, bits, true),
            Err(PalwTicketReject::ChainCommitMismatch)
        );
        assert_eq!(
            verify_palw_ticket(&nf, 1, &cc, 0x1d00ffff, nonce, 100, &dig, &binding, true, 10, &cc, bits, true),
            Err(PalwTicketReject::LaneBitsMismatch)
        );
        assert_eq!(
            verify_palw_ticket(&nf, 1, &cc, bits, nonce, 100, &dig, &binding, true, 10, &cc, bits, false),
            Err(PalwTicketReject::ComputeCapExhausted)
        );
        // wrong nonce (not low64(nullifier)) ⇒ draw not won.
        assert_eq!(
            verify_palw_ticket(&nf, 1, &cc, bits, nonce ^ 1, 100, &dig, &binding, true, 10, &cc, bits, true),
            Err(PalwTicketReject::EligibilityMiss)
        );
        // a losing digest (all-ones ⇒ max Uint512) misses even with the right nonce, at a tight target.
        let tight = 0x1c00ffff_u32;
        let losing = Hash64::from_bytes([0xff; 64]);
        assert_eq!(
            verify_palw_ticket(&nf, 1, &cc, tight, nonce, 100, &losing, &binding, true, 10, &cc, tight, true),
            Err(PalwTicketReject::EligibilityMiss)
        );
    }

    #[test]
    fn beacon_fallback_and_degraded_mode() {
        // fallback seed is distinct from the primary seed and depends on the lagged window.
        let f1 = beacon_fallback_seed(&h(1), &h(2), &h(3), 9);
        let f2 = beacon_fallback_seed(&h(1), &h(2), &h(9), 9);
        assert_ne!(f1, f2);
        assert_ne!(f1, beacon_seed(&h(1), &h(2), &h(3), &h(0), 9));
        // mode transitions: healthy → grace (within window) → halted (past window).
        assert_eq!(beacon_mode(true, true, 0, 1), PalwBeaconMode::Healthy);
        assert_eq!(beacon_mode(false, true, 1, 1), PalwBeaconMode::DegradedGrace);
        assert_eq!(beacon_mode(true, false, 1, 1), PalwBeaconMode::DegradedGrace);
        assert_eq!(beacon_mode(false, false, 2, 1), PalwBeaconMode::Halted);

        // K5 fallback policy: full weight healthy, halved in grace, zero when halted; monotone.
        assert_eq!(effective_compute_work_scale(8, PalwBeaconMode::Healthy), 8);
        assert_eq!(effective_compute_work_scale(8, PalwBeaconMode::DegradedGrace), 4);
        assert_eq!(effective_compute_work_scale(8, PalwBeaconMode::Halted), 0);
        for base in [0u64, 1, 2, 3, 40] {
            let (hh, dg, ht) = (
                effective_compute_work_scale(base, PalwBeaconMode::Healthy),
                effective_compute_work_scale(base, PalwBeaconMode::DegradedGrace),
                effective_compute_work_scale(base, PalwBeaconMode::Halted),
            );
            assert!(hh >= dg && dg >= ht, "monotone Healthy>=DegradedGrace>=Halted for base {base}");
        }
    }

    /// K5 (§11.3): halted_since closed form, the lagged buried seed-carry run, and the activation gate.
    #[test]
    fn k5_halt_signal_and_gates() {
        // halted_since = epoch + grace + 1 - degraded_epochs, only when mode == Halted.
        let grace = 3u64;
        let state = |epoch: u64, mode: PalwBeaconMode, degraded: u64| PalwBeaconStateV1 {
            version: 1,
            epoch,
            seed: h(0),
            dns_anchor: h(0),
            anchor_blue_score: 0,
            anchor_daa_score: 0,
            anchor_overlay_root: h(0),
            valid_reveals_root: h(0),
            missing_commitments_root: h(0),
            mode: mode.to_u8(),
            degraded_epochs: degraded,
            valid_reveal_count: 0,
            missing_commit_count: 0,
        };
        // first Halted epoch: degraded == grace+1 at epoch E ⇒ halted_since == E (the run just crossed).
        assert_eq!(state(100, PalwBeaconMode::Halted, grace + 1).halted_since(grace), Some(100));
        // deep halt: degraded == grace+5 at epoch 104 ⇒ run started at 104+3+1-8 = 100.
        assert_eq!(state(104, PalwBeaconMode::Halted, grace + 5).halted_since(grace), Some(100));
        // not Halted ⇒ None (grace-epoch and healthy blocks are never classified halted).
        assert_eq!(state(100, PalwBeaconMode::DegradedGrace, grace).halted_since(grace), None);
        assert_eq!(state(100, PalwBeaconMode::Healthy, 0).halted_since(grace), None);
        // from_u8 round-trips the discriminant.
        for m in [PalwBeaconMode::Healthy, PalwBeaconMode::DegradedGrace, PalwBeaconMode::Halted] {
            assert_eq!(PalwBeaconMode::from_u8(m.to_u8()), Some(m));
        }
        assert_eq!(PalwBeaconMode::from_u8(9), None);

        // seed-carry run: longest equal suffix ending at the newest sample, measured in epochs.
        assert_eq!(palw_seed_carry_run(&[(1, h(1)), (2, h(1)), (3, h(1))]), 2); // 3 - 1
        assert_eq!(palw_seed_carry_run(&[(1, h(1)), (2, h(2)), (3, h(2))]), 1); // 3 - 2 (Healthy advance at 2)
        assert_eq!(palw_seed_carry_run(&[(5, h(9))]), 0); // < 2 samples ⇒ fail-open 0
        assert_eq!(palw_seed_carry_run(&[]), 0);
        // consecutive equal seeds a Healthy advance breaks: a run of 2 needs grace >= 2 to survive clause 10.
        assert!(palw_seed_carry_run(&[(1, h(7)), (2, h(7)), (3, h(7))]) > 2u64.saturating_sub(1));

        // activation gate: the two newest distinct-epoch seeds must DIFFER (a recent Healthy advance).
        assert!(palw_lagged_activation_open(&[(1, h(1)), (2, h(2))])); // advance ⇒ open
        assert!(!palw_lagged_activation_open(&[(1, h(1)), (2, h(1))])); // carry ⇒ frozen
        assert!(!palw_lagged_activation_open(&[(1, h(1))])); // < 2 ⇒ fail-closed
        assert!(!palw_lagged_activation_open(&[]));

        // template lane-open c==v twin: both conjuncts (not Halted AND carry <= grace).
        assert!(palw_template_lane_open(PalwBeaconMode::Healthy.to_u8(), 0, grace));
        assert!(palw_template_lane_open(PalwBeaconMode::DegradedGrace.to_u8(), grace, grace)); // grace-run still open
        assert!(!palw_template_lane_open(PalwBeaconMode::Halted.to_u8(), 0, grace)); // own mode Halted
        assert!(!palw_template_lane_open(PalwBeaconMode::Healthy.to_u8(), grace + 1, grace)); // post-recovery lag
    }

    /// K5 (§9.5/§11.3): advance_epoch_gated freezes Certified→Active while the gate is closed, but never
    /// cancels — a frozen batch activates on a later open call and still expires on time.
    #[test]
    fn k5_advance_epoch_gated_freeze() {
        let mk = || {
            let mut v = PalwBatchViewV1::new();
            v.batches.insert(
                h(0x42),
                PalwBatchLifecycleV1 {
                    status: PalwBatchStatus::Certified,
                    registration_epoch: 0,
                    activation_not_before_epoch: 5,
                    expiry_epoch: 20,
                    leaf_count: 1,
                    chunk_count: 1,
                    chunks_present: [1, 0, 0, 0],
                    leaf_root: h(0),
                    cert_hash: Some(h(1)),
                    cert_activation_epoch: 0,
                    cert_expiry_epoch: 100,
                    revoked_from_daa: None,
                },
            );
            v
        };
        // gate CLOSED at the activation epoch ⇒ stays Certified (frozen, not cancelled).
        let mut frozen = mk();
        frozen.advance_epoch_gated(6, 2, 6, false);
        assert_eq!(frozen.batches[&h(0x42)].status, PalwBatchStatus::Certified);
        // a later OPEN call activates it.
        frozen.advance_epoch_gated(7, 2, 6, true);
        assert_eq!(frozen.batches[&h(0x42)].status, PalwBatchStatus::Active);
        // gate OPEN at the activation epoch ⇒ activates immediately (== the un-gated advance_epoch).
        let mut open = mk();
        open.advance_epoch(6, 2, 6);
        assert_eq!(open.batches[&h(0x42)].status, PalwBatchStatus::Active);
        // frozen past expiry ⇒ Expired even while the gate is closed (the gate delays activation, not expiry).
        let mut expired = mk();
        expired.advance_epoch_gated(20, 2, 6, false);
        assert_eq!(expired.batches[&h(0x42)].status, PalwBatchStatus::Expired);
    }

    /// §11.2 roots: order-independent + collision-free across cardinality, and the two domains disjoint.
    #[test]
    fn beacon_set_roots_canonical() {
        let a = (op(0x50, 0), h(11));
        let b = (op(0x51, 2), h(12));
        // same set in two orders ⇒ identical root (canonical sort inside).
        assert_eq!(beacon_valid_reveals_root(&[a, b]), beacon_valid_reveals_root(&[b, a]));
        // a different member changes the root.
        assert_ne!(beacon_valid_reveals_root(&[a, b]), beacon_valid_reveals_root(&[a]));
        // same entries, different domain (valid vs missing) ⇒ disjoint roots.
        assert_ne!(beacon_valid_reveals_root(&[a, b]), beacon_missing_commitments_root(&[a, b]));
        // empty set is a fixed non-panicking digest.
        assert_eq!(beacon_valid_reveals_root(&[]), beacon_valid_reveals_root(&[]));
    }

    /// §11.2 stake-weighted quorum: revealed stake must reach num/den of committed stake.
    #[test]
    fn beacon_quorum_stake_weighted() {
        let committed = vec![op(0x60, 0), op(0x60, 1), op(0x60, 2)];
        let stake_of = |o: &TransactionOutpoint| -> u128 {
            match o.index {
                0 => 30,
                1 => 30,
                2 => 40,
                _ => 0,
            }
        };
        // reveals 0+1 = 60 of committed 100 at 2/3 (66.67) ⇒ NOT reached.
        assert!(!beacon_quorum_reached(&committed, &[op(0x60, 0), op(0x60, 1)], 2, 3, stake_of));
        // + reveal 2 = 100 ⇒ reached.
        assert!(beacon_quorum_reached(&committed, &committed, 2, 3, stake_of));
        // den==0 ⇒ never reached.
        assert!(!beacon_quorum_reached(&committed, &committed, 1, 0, stake_of));
        // §11.3: empty committed set (total dropout) is NOT reached (degraded, not vacuously Healthy).
        assert!(!beacon_quorum_reached(&[], &[], 2, 3, stake_of));
    }

    /// §11.2/§11.3 derive: Healthy advances the seed via beacon_seed and resets grace; a short quorum
    /// inside the grace window carries the previous seed and increments the grace counter; the missing
    /// set is commits minus valid reveals.
    #[test]
    fn beacon_derive_epoch_state() {
        let unit = |_: &TransactionOutpoint| -> u128 { 1 };
        let commits = vec![(op(0x70, 0), h(21)), (op(0x70, 1), h(22))];
        let reveals = vec![
            (commits[0].0, beacon_reveal_entropy_digest(9, &[0x31; 64], &commits[0].0)),
            (commits[1].0, beacon_reveal_entropy_digest(9, &[0x32; 64], &commits[1].0)),
        ];
        // both revealed ⇒ Healthy (2/2 >= 2/3), seed advances, missing empty.
        let anchor = BeaconDnsAnchor { hash: h(2), blue_score: 77, daa_score: 88, overlay_root: h(9) };
        let inputs = BeaconEpochInputs { commits: commits.clone(), valid_reveals: reveals.clone() };
        assert_eq!(inputs.missing_commitments().len(), 0);
        let st = derive_beacon_epoch_state(9, &h(1), &anchor, &inputs, true, 3, 2, 2, 3, unit);
        assert_eq!(st.mode, PalwBeaconMode::Healthy.to_u8());
        assert_eq!(st.degraded_epochs, 0); // reset on Healthy
        assert_eq!(st.valid_reveal_count, 2);
        assert_eq!(st.missing_commit_count, 0);
        // the seed preimage folds only the anchor HASH; the cert facts ride alongside in the record.
        assert_eq!(st.seed, beacon_seed(&h(1), &h(2), &st.valid_reveals_root, &st.missing_commitments_root, 9));
        assert_eq!(st.anchor(), anchor);
        assert_eq!(st.dns_certificate_hash(), Some(dns_finality_certificate_hash_v1(&anchor)));

        // only 1 of 2 reveals ⇒ quorum short (1/2 < 2/3), still inside grace (prev 0, grace 2) ⇒
        // DegradedGrace carries the previous seed and increments the counter; missing = {bond 1}.
        let inputs2 = BeaconEpochInputs { commits: commits.clone(), valid_reveals: vec![reveals[0]] };
        assert_eq!(inputs2.missing_commitments(), vec![commits[1]]);
        let st2 = derive_beacon_epoch_state(10, &h(5), &anchor, &inputs2, true, 0, 2, 2, 3, unit);
        assert_eq!(st2.mode, PalwBeaconMode::DegradedGrace.to_u8());
        assert_eq!(st2.degraded_epochs, 1);
        assert_eq!(st2.seed, h(5)); // carried, NOT advanced
        assert_eq!(st2.missing_commit_count, 1);

        // grace exhausted (prev 2, grace 2 ⇒ 3 > 2) ⇒ Halted, still carries the seed.
        let st3 = derive_beacon_epoch_state(11, &h(7), &anchor, &inputs2, false, 2, 2, 2, 3, unit);
        assert_eq!(st3.mode, PalwBeaconMode::Halted.to_u8());
        assert_eq!(st3.seed, h(7));

        // bootstrap: an UNCONFIRMED anchor derives a record with NO certificate (fail-closed).
        let st0 = derive_beacon_epoch_state(1, &h(0), &BeaconDnsAnchor::UNCONFIRMED, &inputs, false, 0, 2, 2, 3, unit);
        assert_eq!(st0.dns_certificate_hash(), None);
    }

    /// I-14 DA-possession binding: the auditor vote signing message covers the beacon-selected
    /// `audit_sample_root`, so changing which sample (or which batch/epoch/verdict) changes the digest —
    /// a signature cannot be replayed onto a different sample, and signing requires the sample value.
    #[test]
    fn i14_auditor_vote_binds_audit_sample() {
        let vote = PalwAuditorVoteV1 { bond_outpoint: op(0x40, 0), vote: 1, checked_leaf_bitmap_root: h(5), signature: vec![] };
        let base = vote.signing_hash(0x9107, &h(1), 6, &h(2));
        assert_eq!(base, vote.signing_hash(0x9107, &h(1), 6, &h(2)), "deterministic");
        // the beacon-selected sample root is bound: a different sample ⇒ a different message.
        assert_ne!(base, vote.signing_hash(0x9107, &h(1), 6, &h(0xaa)), "audit_sample_root is covered");
        assert_ne!(base, vote.signing_hash(0x9107, &h(1), 7, &h(2)), "audit_beacon_epoch is covered");
        assert_ne!(base, vote.signing_hash(0x9107, &h(0xbb), 6, &h(2)), "batch_id is covered");
        // the verdict + identity are covered.
        let reject = PalwAuditorVoteV1 { vote: 0, ..vote.clone() };
        assert_ne!(base, reject.signing_hash(0x9107, &h(1), 6, &h(2)), "vote is covered");
        let other = PalwAuditorVoteV1 { bond_outpoint: op(0x40, 1), ..vote.clone() };
        assert_ne!(base, other.signing_hash(0x9107, &h(1), 6, &h(2)), "auditor identity is covered");
    }

    /// I-13 winner secrecy: the leaf's commitment is a deterministic one-way function of the nullifier;
    /// the store-facts verify opens it with the header's DISCLOSED raw nullifier, and a wrong disclosure
    /// (a third party guessing) is rejected. This is what makes a ticket's eligibility uncomputable by
    /// anyone but its holder.
    #[test]
    fn i13_nullifier_commitment_binds_disclosure() {
        let nf = h(0x42);
        let commitment = ticket_nullifier_commitment(&nf);
        assert_eq!(commitment, ticket_nullifier_commitment(&nf), "deterministic");
        assert_ne!(commitment, ticket_nullifier_commitment(&h(0x43)), "distinct nullifiers ⇒ distinct commitments");
        assert_ne!(commitment, nf, "the commitment is not the raw nullifier (one-way)");

        // a binding built from the leaf's commitment: the correct disclosure opens it, a wrong one is a
        // NullifierMismatch (so a third party who only read the public leaf cannot forge the header).
        let binding = PalwTicketBinding {
            ticket_nullifier_commitment: commitment,
            proof_type: 1,
            leaf_activation_epoch: 0,
            leaf_expiry_epoch: 100,
            target_daa_interval: 42,
        };
        assert!(verify_palw_ticket_store_facts(&nf, 1, 42, &binding, true, 10).is_ok());
        assert_eq!(
            verify_palw_ticket_store_facts(&h(0x43), 1, 42, &binding, true, 10),
            Err(PalwTicketReject::NullifierMismatch)
        );
    }

    /// §9.2/§9.3/§18.2 C4 content-addressing + view: batch_id must be content-derived; a manifest with a
    /// forged batch_id or an unbounded expiry is inadmissible; leaf_root reduces the ordered leaves; the
    /// compact view gates referenceability + block-eligibility and retains only the reachable set.
    #[test]
    fn c4_content_address_admission_and_view() {
        // leaf_root reduction is order-sensitive + count-prefixed.
        let (la, lb) = (h(1), h(2));
        assert_ne!(palw_leaf_root(&[la, lb]), palw_leaf_root(&[lb, la]));
        assert_ne!(palw_leaf_root(&[la]), palw_leaf_root(&[la, lb]));

        // build a content-addressed, admissible manifest (registration_epoch = accept_epoch, bounded
        // activation/expiry). max_batch_leaves 256, chunk 64, lead 2, active 6, audit 6.
        let mut m = PalwBatchManifestV1 {
            version: 1, batch_id: h(0), registration_epoch: 5, model_profile_id: h(3), runtime_class_id: h(4),
            leaf_count: 100, chunk_count: 2, leaf_root: palw_leaf_root(&[la, lb]), descriptor_root: h(6),
            total_leaf_bond_sompi: 0, audit_policy_id: h(7), activation_not_before_epoch: 13, expiry_epoch: 19,
        };
        m.batch_id = m.content_id();
        assert!(m.batch_id_is_content_derived());
        assert!(m.admission_valid(5, 256, 64, 2, 6, 6, 0), "well-formed manifest is admissible");

        // forged batch_id ⇒ inadmissible (content-address broken).
        let mut forged = m.clone();
        forged.batch_id = h(0xff);
        assert!(!forged.batch_id_is_content_derived());
        assert!(!forged.admission_valid(5, 256, 64, 2, 6, 6, 0));

        // unbounded expiry ⇒ inadmissible (would pin the view forever). Re-content-address after edit.
        let mut evil = PalwBatchManifestV1 { expiry_epoch: u64::MAX, ..m.clone() };
        evil.batch_id = evil.content_id();
        assert!(!evil.admission_valid(5, 256, 64, 2, 6, 6, 0));
        // wrong registration epoch (miner re-aim) ⇒ inadmissible.
        assert!(!m.admission_valid(6, 256, 64, 2, 6, 6, 0));
        // chunk_count must be exactly ceil(100/64)=2.
        let mut badchunks = PalwBatchManifestV1 { chunk_count: 3, ..m.clone() };
        badchunks.batch_id = badchunks.content_id();
        assert!(!badchunks.admission_valid(5, 256, 64, 2, 6, 6, 0));

        // R3 (§7 c_saved floor): with a nonzero per-leaf floor, a manifest whose aggregate bond does not
        // cover leaf_count·floor is inadmissible; exactly-covering is admissible. m has leaf_count=100.
        let mut bonded = PalwBatchManifestV1 { total_leaf_bond_sompi: 100 * 50, ..m.clone() };
        bonded.batch_id = bonded.content_id();
        assert!(bonded.admission_valid(5, 256, 64, 2, 6, 6, 50), "aggregate bond exactly covers the floor");
        assert!(!bonded.admission_valid(5, 256, 64, 2, 6, 6, 51), "one sompi short per leaf ⇒ inadmissible");
        // the original (bond 0) is inadmissible the moment a floor exists.
        assert!(!m.admission_valid(5, 256, 64, 2, 6, 6, 1));

        // the compact view: an Active batch inside its windows is resolvable; an Expired / revoked /
        // out-of-window one is not; retain drops the unreachable.
        let entry = |status, revoked| PalwBatchLifecycleV1 {
            status, registration_epoch: 5, activation_not_before_epoch: 13, expiry_epoch: 19, leaf_count: 100,
            chunk_count: 2, chunks_present: [0b11, 0, 0, 0], leaf_root: m.leaf_root, cert_hash: Some(h(9)),
            cert_activation_epoch: 13, cert_expiry_epoch: 19, revoked_from_daa: revoked,
        };
        let mut view = PalwBatchViewV1::new();
        view.batches.insert(m.batch_id, entry(PalwBatchStatus::Active, None));
        assert!(view.resolvable_batch(&m.batch_id, 15).is_some(), "Active + in-window ⇒ resolvable");
        assert!(view.resolvable_batch(&m.batch_id, 19).is_none(), "at expiry ⇒ not resolvable");
        assert!(view.resolvable_batch(&h(0xaa), 15).is_none(), "absent batch ⇒ None");
        // a revoked batch is never resolvable and is dropped by retain.
        view.batches.insert(h(0xbb), entry(PalwBatchStatus::Active, Some(900)));
        assert!(view.resolvable_batch(&h(0xbb), 15).is_none());
        view.retain(15, 2, 6);
        assert!(view.entry(&h(0xbb)).is_none(), "revoked batch dropped");
        assert!(view.entry(&m.batch_id).is_some(), "in-window Active kept");
        // past expiry, retain drops the Active batch too.
        view.retain(25, 2, 6);
        assert!(view.entry(&m.batch_id).is_none());
    }

    /// §9.5 B-way delta application: manifest → Registering (admission-gated, idempotent), chunks →
    /// Committed on completeness, audit-beacon epoch → Auditing, certificate → Certified, activation
    /// epoch → Active; revocation + expiry.
    #[test]
    fn c4_view_delta_state_machine() {
        let mut m = PalwBatchManifestV1 {
            version: 1, batch_id: h(0), registration_epoch: 5, model_profile_id: h(3), runtime_class_id: h(4),
            leaf_count: 100, chunk_count: 2, leaf_root: h(8), descriptor_root: h(6), total_leaf_bond_sompi: 0,
            audit_policy_id: h(7), activation_not_before_epoch: 13, expiry_epoch: 19,
        };
        m.batch_id = m.content_id();
        let mut v = PalwBatchViewV1::new();

        // manifest ⇒ Registering; a forged/duplicate is a no-op.
        assert!(v.apply_manifest(&m, 5, 256, 64, 2, 6, 6, 0));
        assert_eq!(v.entry(&m.batch_id).unwrap().status, PalwBatchStatus::Registering);
        assert!(!v.apply_manifest(&m, 5, 256, 64, 2, 6, 6, 0), "idempotent");
        let mut forged = m.clone();
        forged.batch_id = h(0xff);
        assert!(!v.apply_manifest(&forged, 5, 256, 64, 2, 6, 6, 0), "forged batch_id rejected");

        // 2 distinct chunks ⇒ Committed on the last; a duplicate index is a no-op.
        assert!(v.apply_leaf_chunk(&m.batch_id, 0));
        assert!(!v.apply_leaf_chunk(&m.batch_id, 0), "duplicate chunk index is idempotent");
        assert_eq!(v.entry(&m.batch_id).unwrap().status, PalwBatchStatus::Registering);
        assert!(v.apply_leaf_chunk(&m.batch_id, 1));
        assert_eq!(v.entry(&m.batch_id).unwrap().status, PalwBatchStatus::Committed);
        assert!(!v.apply_leaf_chunk(&m.batch_id, 2), "chunk_index out of range");

        // audit-beacon epoch (registration 5 + lead 2 + audit 6 = 13) ⇒ Auditing.
        v.advance_epoch(13, 2, 6);
        assert_eq!(v.entry(&m.batch_id).unwrap().status, PalwBatchStatus::Auditing);

        // certificate ⇒ Certified (records the cert window).
        assert!(v.apply_certificate(&m.batch_id, h(0x99), 13, 19));
        assert_eq!(v.entry(&m.batch_id).unwrap().status, PalwBatchStatus::Certified);
        assert_eq!(v.entry(&m.batch_id).unwrap().cert_hash, Some(h(0x99)));

        // activation epoch (13) ⇒ Active; resolvable in-window.
        v.advance_epoch(13, 2, 6);
        assert_eq!(v.entry(&m.batch_id).unwrap().status, PalwBatchStatus::Active);
        assert!(v.resolvable_batch(&m.batch_id, 15).is_some());

        // revocation ⇒ no longer resolvable.
        assert!(v.mark_revoked(&m.batch_id, 1500));
        assert!(v.resolvable_batch(&m.batch_id, 15).is_none());

        // an incomplete batch expires past its deadline.
        let mut m2 = PalwBatchManifestV1 { registration_epoch: 5, activation_not_before_epoch: 13, expiry_epoch: 19, ..m.clone() };
        m2.model_profile_id = h(0x55); // change content ⇒ distinct batch id
        m2.batch_id = m2.content_id();
        assert!(v.apply_manifest(&m2, 5, 256, 64, 2, 6, 6, 0));
        v.advance_epoch(14, 2, 6); // 14 > deadline 13 while still Registering
        assert_eq!(v.entry(&m2.batch_id).unwrap().status, PalwBatchStatus::Expired);
    }

    /// §16.3 lane params: the inert placeholder is structurally valid but FAILS the activation preflight
    /// (zero genesis bits); a recalibrated set passes only when hash genesis bits == the genesis header
    /// bits and min_samples fits both windows. PalwLaneBitsV1 selects/updates per lane.
    #[test]
    fn lane_difficulty_params_and_bits() {
        use crate::pow_layer0::WorkLane;
        let inert = LaneDifficultyParams::INERT;
        assert!(inert.is_structurally_valid());
        // inert placeholder (genesis bits 0) is NEVER activation-consistent.
        assert!(!inert.is_consistent_for_activation(0x1d00ffff));

        // a recalibrated set: real genesis bits, hash bits == genesis header bits.
        let genesis_bits = 0x1d00ffff_u32;
        let good = LaneDifficultyParams { genesis_hash_bits: genesis_bits, genesis_replica_bits: 0x1e00abcd, ..inert.clone() };
        assert!(good.is_consistent_for_activation(genesis_bits));
        // hash genesis bits must equal the genesis header bits (else inert-vs-active HOLD diverges).
        assert!(!good.is_consistent_for_activation(0x1c00ffff));
        // min_samples must fit the window.
        let bad = LaneDifficultyParams { min_samples: 999_999, ..good.clone() };
        assert!(!bad.is_consistent_for_activation(genesis_bits));
        // a zero adjust factor is structurally invalid.
        assert!(!LaneDifficultyParams { max_adjust_factor: 0, ..inert.clone() }.is_structurally_valid());

        // PalwLaneBitsV1 lane selection + update.
        let bits = PalwLaneBitsV1 { hash_bits: 11, replica_bits: 22 };
        assert_eq!(bits.lane_bits(WorkLane::HashFloor), 11);
        assert_eq!(bits.lane_bits(WorkLane::ReplicaPalw), 22);
        assert_eq!(bits.with_lane_bits(WorkLane::ReplicaPalw, 99).replica_bits, 99);
    }

    /// §12.1 clause-6 cert digest: anchor-pure, field-sensitive, domain-disjoint; and the checkpoint
    /// params predicate rejects the current (unrecalibrated) testnet DNS numbers + vacuous depths.
    #[test]
    fn dns_certificate_hash_and_checkpoint_params() {
        let a = BeaconDnsAnchor { hash: h(2), blue_score: 77, daa_score: 88, overlay_root: h(9) };
        let base = dns_finality_certificate_hash_v1(&a);
        // every fact perturbs the digest.
        assert_ne!(base, dns_finality_certificate_hash_v1(&BeaconDnsAnchor { hash: h(3), ..a }));
        assert_ne!(base, dns_finality_certificate_hash_v1(&BeaconDnsAnchor { blue_score: 78, ..a }));
        assert_ne!(base, dns_finality_certificate_hash_v1(&BeaconDnsAnchor { daa_score: 89, ..a }));
        assert_ne!(base, dns_finality_certificate_hash_v1(&BeaconDnsAnchor { overlay_root: h(10), ..a }));
        // domain-disjoint from the beacon commitment domain over comparable input widths.
        assert_ne!(base, beacon_commitment(77, &[2u8; 64], &op(2, 0)));

        // §12.1 LOOKBACK inequality + C6 SLICE 5 band (finality_depth <= burial < pruning_depth). testnet
        // DNS numbers (lag 100 + backoff 20 < horizon 300) FAIL — the PALW re-genesis must recalibrate.
        // GENESIS-style deeper lag inside the band passes; vacuous depths fail. Args:
        // (lag, backoff, max_reorg, finality_depth, pruning_depth, work_depth, stake_depth).
        let w = |v: u64| BlueWorkType::from(v);
        assert!(!palw_checkpoint_params_consistent(100, 20, 300, 300, 100_000, w(100), 5000)); // burial 120 < reorg 300
        assert!(palw_checkpoint_params_consistent(300, 20, 300, 300, 100_000, w(100), 5000)); // burial 320 in band
        assert!(palw_checkpoint_params_consistent(280, 20, 300, 300, 100_000, w(0), 5000)); // stake depth alone suffices
        assert!(!palw_checkpoint_params_consistent(300, 20, 300, 300, 100_000, w(0), 0)); // both depths zero = vacuous
        // C6 SLICE 5 band edges: burial >= max_reorg but < finality_depth ⇒ FAIL (not externally settled);
        // burial >= pruning_depth ⇒ FAIL (anchor header would be pruned, read unrunnable).
        assert!(!palw_checkpoint_params_consistent(300, 20, 300, 500, 100_000, w(100), 5000)); // burial 320 < finality 500
        assert!(!palw_checkpoint_params_consistent(300, 20, 300, 300, 310, w(100), 5000)); // burial 320 >= pruning 310
    }

    #[test]
    fn certificate_stake_weighted_quorum() {
        // three auditors; A + B vote pass (stake 30 + 30 = 60), C rejects (stake 40). Total 100.
        let vote = |idx: u32, v: u8| PalwAuditorVoteV1 {
            bond_outpoint: op(0x40, idx),
            vote: v,
            checked_leaf_bitmap_root: h(6),
            signature: vec![],
        };
        let mut cert = PalwBatchCertificateV1 {
            version: 1,
            batch_id: h(1),
            manifest_hash: h(2),
            leaf_root: h(3),
            audit_beacon_epoch: 5,
            audit_sample_root: h(4),
            passed_leaf_count: 2,
            rejected_leaf_bitmap_root: h(5),
            certificate_epoch: 6,
            activation_epoch: 7,
            expiry_epoch: 13,
            auditor_set_commitment: h(7),
            votes: vec![vote(0, 1), vote(1, 1), vote(2, 0)],
        };
        let stake_of = |o: &TransactionOutpoint| -> u128 {
            match o.index {
                0 => 30,
                1 => 30,
                2 => 40,
                _ => 0,
            }
        };
        assert_eq!(cert.pass_stake(stake_of), 60);
        // 2/3 of 100 = 66.67 → 60 < 66.67 ⇒ NOT reached.
        assert!(!cert.quorum_reached(100, 2, 3, stake_of));
        // if C also passes: 100 >= 66.67 ⇒ reached.
        cert.votes[2].vote = 1;
        assert!(cert.quorum_reached(100, 2, 3, stake_of));
        // exact boundary: pass 67 of 100 at 2/3 ⇒ 67*3=201 >= 100*2=200 ⇒ reached.
        let stake_bound = |o: &TransactionOutpoint| -> u128 { if o.index < 2 { 33 } else { 34 } };
        cert.votes[2].vote = 0;
        // pass = 33+33 = 66; 66*3=198 < 200 ⇒ not reached at the boundary-1.
        assert!(!cert.quorum_reached(100, 2, 3, stake_bound));
    }

    #[test]
    fn lane_daa_targets_and_params() {
        // 10 BPS PALW split: hash 2 → 500 ms, replica 8 → 125 ms. Total 10 → 100 ms block interval.
        assert_eq!(lane_target_time_ms(2), 500);
        assert_eq!(lane_target_time_ms(8), 125);
        assert_eq!(lane_target_time_ms(10), 100);
        // (the future Stage-B 40-BPS profile: hash 8 → 125, replica 32 → 31 (31.25 rounded), total 25.)
        assert_eq!(lane_target_time_ms(32), 31);
        assert_eq!(lane_target_time_ms(40), 25);
        assert_eq!(lane_target_time_ms(0), 1000); // guarded: bps<1 → treat as 1
        let p = LaneDifficultyParams::testnet_default();
        assert_eq!((p.hash_target_time_ms, p.replica_target_time_ms), (500, 125));
        assert_eq!(p.compute_work_scale, 1);
        assert!(p.is_structurally_valid());
    }

    #[test]
    fn lane_daa_sampling_and_retarget() {
        // §16.2 sampling: hash lane samples algo-3 blues; compute lane samples unique-active algo-4 blues.
        assert!(lane_daa_sample_eligible(WorkLane::HashFloor, POW_ALGO_ID_BLAKE2B_SHA3, true, false));
        assert!(!lane_daa_sample_eligible(WorkLane::HashFloor, POW_ALGO_ID_PALW_REPLICA, true, true)); // algo-4 not in hash window
        assert!(lane_daa_sample_eligible(WorkLane::ReplicaPalw, POW_ALGO_ID_PALW_REPLICA, true, true));
        assert!(!lane_daa_sample_eligible(WorkLane::ReplicaPalw, POW_ALGO_ID_PALW_REPLICA, true, false)); // not unique/active (dup/revoked)
        assert!(!lane_daa_sample_eligible(WorkLane::ReplicaPalw, POW_ALGO_ID_PALW_REPLICA, false, true)); // not credited blue (red)
        assert!(!lane_daa_sample_eligible(WorkLane::HashFloor, POW_ALGO_ID_BLAKE2B_SHA3, false, false)); // red hash source

        // §16.3 retarget: hold below min_samples; else clamp measured to [target/4, target*4].
        assert_eq!(lane_retarget_decision(10, 60, 100, 125, 4), LaneRetargetDecision::HoldLastBits);
        assert_eq!(lane_retarget_decision(60, 60, 125, 125, 4), LaneRetargetDecision::Adjust { clamped_measured_ms: 125 });
        // a stall (measured 10 000 ms) clamps to target*4 = 500.
        assert_eq!(lane_retarget_decision(60, 60, 10_000, 125, 4), LaneRetargetDecision::Adjust { clamped_measured_ms: 500 });
        // a burst (measured 1 ms) clamps to target/4 = 31.
        assert_eq!(lane_retarget_decision(60, 60, 1, 125, 4), LaneRetargetDecision::Adjust { clamped_measured_ms: 31 });
    }

    #[test]
    fn palw_active_nullifier_window() {
        let mut s = PalwActiveNullifierSet::new();
        assert!(s.is_empty());
        // first-seen inserts succeed; a repeat is a duplicate.
        assert!(s.insert(h(1), 100));
        assert!(s.insert(h(2), 110));
        assert!(!s.insert(h(1), 120)); // duplicate ⇒ false, keeps earliest daa
        assert!(s.contains(&h(1)) && s.contains(&h(2)));
        assert_eq!(s.len(), 2);
        // canonical sorted order.
        let order: Vec<Hash64> = s.iter_sorted().map(|(n, _)| *n).collect();
        assert_eq!(order, vec![h(1), h(2)]);
        // prune everything first-seen before the retention floor (105) ⇒ drops nf 1 (seen@100).
        assert_eq!(s.prune_below(105), 1);
        assert!(!s.contains(&h(1)) && s.contains(&h(2)));

        // apply_mergeset seeded from the parent past: within-mergeset + seed duplicates recolor.
        let mut seeded = PalwActiveNullifierSet::new();
        seeded.insert(h(5), 200); // active in the selected parent's past
        let mergeset = [Some((h(5), 210)), None, Some((h(6), 210)), Some((h(6), 210))];
        assert_eq!(seeded.apply_mergeset(&mergeset), vec![0, 3]); // h(5) seed-dup, second h(6) within-mergeset dup
        assert!(seeded.contains(&h(6)));
    }

    #[test]
    fn palw_duplicate_ticket_dedup_is_deterministic() {
        let seed = HashSet::new();
        // Inert / all non-PALW ⇒ no duplicates, coloring unchanged.
        assert_eq!(palw_duplicate_ticket_positions(&[None, None, None], &seed), Vec::<usize>::new());
        // First-seen tickets are all kept.
        assert_eq!(palw_duplicate_ticket_positions(&[Some(h(1)), Some(h(2)), Some(h(3))], &seed), Vec::<usize>::new());
        // Within-mergeset re-use: the SECOND occurrence (position 2) is the duplicate; first is kept.
        assert_eq!(palw_duplicate_ticket_positions(&[Some(h(1)), Some(h(2)), Some(h(1))], &seed), vec![2]);
        // algo-3 (None) interleaved is skipped; the repeat of ticket 1 at position 3 is the duplicate.
        assert_eq!(palw_duplicate_ticket_positions(&[None, Some(h(1)), None, Some(h(1))], &seed), vec![3]);
        // A nullifier already active in the selected parent's past (seed) makes the FIRST mergeset use a
        // duplicate too.
        let seed1: HashSet<Hash64> = [h(1)].into_iter().collect();
        assert_eq!(palw_duplicate_ticket_positions(&[Some(h(1)), Some(h(2))], &seed1), vec![0]);
        assert_eq!(palw_duplicate_ticket_positions(&[Some(h(2)), Some(h(1)), Some(h(2))], &seed1), vec![1, 2]);
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
        assert_eq!(PALW_DNS_CERT_DOMAIN, b"misaka-palw-dns-cert-v1");
        assert_eq!(PALW_LEAF_ROOT_DOMAIN, b"misaka-palw-leaf-root-v1");
        assert_eq!(PALW_BATCH_ID_DOMAIN, b"misaka-palw-batch-id-v1");
        assert_eq!(PALW_TICKET_NULLIFIER_COMMIT_DOMAIN, b"misaka-palw-ticket-nf-commit-v1");
        assert_eq!(PALW_AUDITOR_VOTE_DOMAIN, b"misaka-palw-auditor-vote-v1");
        assert_eq!(PALW_MATCH_DOMAIN, b"misaka-palw-match-v1");
        assert_eq!(PALW_RECEIPT_DOMAIN, b"misaka-palw-replica-receipt-v1");
        assert_eq!(PALW_PROVIDER_SELECT_DOMAIN, b"misaka-palw-provider-select-v1");
        assert_eq!(PALW_AUDITOR_SELECT_DOMAIN, b"misaka-palw-auditor-select-v1");
        assert_eq!(PALW_MISMATCH_ESCALATE_DOMAIN, b"misaka-palw-mismatch-escalate-v1");
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
            PALW_MISMATCH_ESCALATE_DOMAIN,
        ] {
            assert!(d.len() <= 64, "domain {:?} exceeds BLAKE2b key limit", core::str::from_utf8(d));
        }
    }

    /// R4 (§24.5) — mismatch attribution + escalation are deterministic and never slash the honest
    /// partner. The escalation draw is beacon-derived; the inert params escalate nothing.
    #[test]
    fn r4_mismatch_attribution_and_escalation() {
        let op = |n: u8| TransactionOutpoint { transaction_id: h(n), index: n as u32 };
        let (pa, pb) = (op(1), op(2));
        // a genuine mismatch: the two replicas committed different outputs.
        let rec = PalwMismatchRecordV1 {
            batch_id: h(10), leaf_index: 7, provider_a: pa, provider_b: pb, output_a: h(20), output_b: h(21),
        };
        // reference confirms a ⇒ b is the deviator ⇒ slash b only (honest a keeps its bond).
        assert_eq!(rec.attribute(&h(20)), PalwMismatchVerdict::SlashB);
        assert_eq!(rec.slash_targets(PalwMismatchVerdict::SlashB), vec![pb]);
        // reference confirms b ⇒ slash a only.
        assert_eq!(rec.attribute(&h(21)), PalwMismatchVerdict::SlashA);
        // reference matches neither ⇒ both deviated ⇒ slash both.
        assert_eq!(rec.attribute(&h(99)), PalwMismatchVerdict::SlashBoth);
        assert_eq!(rec.slash_targets(PalwMismatchVerdict::SlashBoth), vec![pa, pb]);
        // a non-mismatch (equal outputs) attributes to nothing and slashes nobody.
        let eq = PalwMismatchRecordV1 { output_b: h(20), ..rec.clone() };
        assert_eq!(eq.attribute(&h(20)), PalwMismatchVerdict::NotAMismatch);
        assert!(eq.slash_targets(PalwMismatchVerdict::NotAMismatch).is_empty());
        assert!(!eq.is_escalated(&h(5), &PalwMismatchParams { escalation_rate_ppm: 1_000_000, repeat_offender_threshold: 1 }, 99, 99),
            "an equal-output record is not a mismatch and is never escalated");

        // escalation draw is deterministic in [0, 1_000_000) and beacon-sensitive.
        let d1 = rec.escalation_draw(&h(5));
        assert_eq!(d1, rec.escalation_draw(&h(5)), "deterministic");
        assert!(d1 < 1_000_000);
        assert_ne!(d1, rec.escalation_draw(&h(6)), "different beacon seed ⇒ different draw");
        // inert params escalate nothing regardless of prior counts.
        assert!(!rec.is_escalated(&h(5), &PalwMismatchParams::INERT, 1000, 1000));
        // full-rate escalation always fires; repeat-offender path fires when a count reaches the threshold.
        assert!(rec.is_escalated(&h(5), &PalwMismatchParams { escalation_rate_ppm: 1_000_000, repeat_offender_threshold: 0 }, 0, 0));
        assert!(rec.is_escalated(&h(5), &PalwMismatchParams { escalation_rate_ppm: 0, repeat_offender_threshold: 3 }, 3, 0));
        assert!(!rec.is_escalated(&h(5), &PalwMismatchParams { escalation_rate_ppm: 0, repeat_offender_threshold: 3 }, 2, 2));
    }

    /// D3 (§18.3): a PalwBeaconCheckpointV1 projects a beacon state + verifies the R_E hash-chain step;
    /// the epoch-proof bundle's beacon_chain links iff it is a contiguous ascending run whose seeds chain
    /// from the boundary seed. borsh round-trips.
    #[test]
    fn d3_epoch_proof_bundle_beacon_chain_links() {
        // build a 3-epoch seed chain from a boundary seed, healthy anchor facts fixed across the run.
        let boundary = h(0x40);
        let (anchor, vrr, mcr) = (h(0x50), h(0x51), h(0x52));
        let mut cps = Vec::new();
        let mut prev = boundary;
        for epoch in 10u64..=12 {
            let seed = beacon_seed(&prev, &anchor, &vrr, &mcr, epoch);
            cps.push(PalwBeaconCheckpointV1 {
                epoch, seed, dns_anchor: anchor, anchor_blue_score: 700, anchor_daa_score: 900,
                anchor_overlay_root: h(0x53), valid_reveals_root: vrr, missing_commitments_root: mcr, mode: 0, degraded_epochs: 0,
            });
            assert!(cps.last().unwrap().seed_follows(&prev));
            prev = seed;
        }
        let bundle = PalwEpochProofBundleV1 {
            from_epoch: 10, to_epoch: 12, beacon_chain: cps.clone(), batch_manifests: vec![], leaf_chunks: vec![],
            certificates: vec![], revocations: vec![], nullifier_frontier_root: h(0x60), active_set_records: vec![],
        };
        assert!(bundle.beacon_chain_links(&boundary), "correct contiguous chain from the boundary seed links");
        assert!(!bundle.beacon_chain_links(&h(0xff)), "a wrong boundary seed breaks the first link");

        // a broken middle seed fails linkage.
        let mut tampered = bundle.clone();
        tampered.beacon_chain[1].seed = h(0xaa);
        assert!(!tampered.beacon_chain_links(&boundary));
        // wrong length / non-contiguous epoch fails.
        let mut short = bundle.clone();
        short.beacon_chain.pop();
        assert!(!short.beacon_chain_links(&boundary));

        // borsh round-trips.
        let bytes = borsh::to_vec(&bundle).unwrap();
        assert_eq!(PalwEpochProofBundleV1::try_from_slice(&bytes).unwrap(), bundle);

        // from_state projection matches.
        let st = PalwBeaconStateV1 {
            version: 1, epoch: 12, seed: prev, dns_anchor: anchor, anchor_blue_score: 700, anchor_daa_score: 900,
            anchor_overlay_root: h(0x53), valid_reveals_root: vrr, missing_commitments_root: mcr, mode: 0, degraded_epochs: 0,
            valid_reveal_count: 5, missing_commit_count: 1,
        };
        let cp = PalwBeaconCheckpointV1::from_state(&st);
        assert_eq!(cp.epoch, 12);
        assert_eq!(cp.seed, prev);
        assert_eq!(cp.anchor(), st.anchor());
    }

    /// C6 / §22 — CONSTRUCTION == VALIDATION, proved in-process (no network): a mining template that
    /// (1) builds candidates via `palw_template_candidate` (the validator's own `eligibility_hash` +
    /// canonical nonce), (2) selects a winner with `palw_select_template_ticket`, and (3) fills the
    /// Header-v3 fields from the winner, produces a header that `verify_palw_ticket` ACCEPTS on all nine
    /// clauses — because both sides share the identical pure eligibility / chain_commit / draw functions.
    /// The header's `chain_commit`/`bits` are set to the consensus-derived `expected_chain_commit`/lane
    /// bits, and `daa_score`/nonce are pinned; a validator that re-derives those same values agrees by
    /// construction. This is the in-process c==v proof for the algo-4 mining template.
    #[test]
    fn template_ticket_construction_equals_validation() {
        let net = 0x9107u32;
        let eligibility_beacon = h(0x77); // the lagged R_E = a finality-buried anchor's palw_beacon_seed
        let expected_chain_commit = h(0x88); // consensus-derived (clause 6); the template SETS header.chain_commit = this
        let target_interval = 600u64;
        let batch_id = h(0x10);
        let epoch = 5u64;
        // An EASY lane target: `from_compact_target_bits_512(0x2100ffff)` ≈ 2^512·(1−2^-16), so a real
        // 512-bit eligibility draw wins with probability ≈ 1 − 2^-16 — the first inventory ticket wins in
        // practice (never flakes) while exercising the REAL draw path, not a contrived zero digest.
        let lane_bits = 0x2100ffff_u32;

        let (cert_activation_epoch, cert_expiry_epoch) = (4u64, 12u64);
        let cert_active = cert_activation_epoch <= epoch && epoch < cert_expiry_epoch;

        // The miner's inventory of Active tickets (same batch/cert, distinct leaves ⇒ distinct draws).
        let ticket = |i: u8| {
            let nf = h(0xA0u8.wrapping_add(i));
            let leaf_hash = h(0x40u8.wrapping_add(i));
            let leaf_index = i as u32;
            let cand =
                palw_template_candidate(net, &eligibility_beacon, &expected_chain_commit, target_interval, &batch_id, leaf_index, &leaf_hash, &nf);
            let binding = PalwTicketBinding {
                ticket_nullifier_commitment: ticket_nullifier_commitment(&nf),
                proof_type: 1,
                leaf_activation_epoch: 4,
                leaf_expiry_epoch: 12,
                target_daa_interval: target_interval,
            };
            (nf, cand, binding)
        };
        let inv: Vec<_> = (0..64u8).map(ticket).collect();
        let cands: Vec<PalwTemplateCandidate> = inv.iter().map(|(_, c, _)| c.clone()).collect();

        // Template: pick the first ticket whose draw wins the current lane bits.
        let win_i = palw_select_template_ticket(&cands, lane_bits).expect("a ticket wins the easy target");
        let (nf, cand, binding) = &inv[win_i];

        // Validation over the header the template built (chain_commit/bits set to the consensus values,
        // nonce pinned, daa == the ticket's interval). All nine clauses pass by construction.
        assert_eq!(
            verify_palw_ticket(
                nf,                       // header.palw_ticket_nullifier
                binding.proof_type,       // header.palw_proof_type
                &expected_chain_commit,   // header.palw_chain_commit (template SET = expected)
                lane_bits,                // header.bits (template SET = lane bits)
                cand.nonce,               // header.nonce = low64(nullifier)
                target_interval,          // header.daa_score (== binding.target_daa_interval, clause 5)
                &cand.eligibility_digest, // clause-9 draw digest (template + validator agree)
                binding,
                cert_active,
                epoch,
                &expected_chain_commit,   // validator's re-derived chain_commit (clause 6)
                lane_bits,                // validator's re-derived lane bits (clause 7)
                true,                     // compute headroom (clause 8, header stage)
            ),
            Ok(()),
            "a template-built winning ticket must pass all nine verify_palw_ticket clauses"
        );

        // Non-vacuous: a header claiming a different chain_commit than the validator derives is rejected.
        assert_eq!(
            verify_palw_ticket(
                nf, binding.proof_type, &h(0xEE), lane_bits, cand.nonce, target_interval, &cand.eligibility_digest,
                binding, cert_active, epoch, &expected_chain_commit, lane_bits, true,
            ),
            Err(PalwTicketReject::ChainCommitMismatch),
        );
        // And a losing draw (a huge digest that no easy target admits) is rejected at clause 9.
        let losing = PalwTemplateCandidate { eligibility_digest: h(0xFF), ..cand.clone() };
        assert_eq!(
            verify_palw_ticket(
                &losing.ticket_nullifier, binding.proof_type, &expected_chain_commit, 0x1d00ffff, losing.nonce,
                target_interval, &losing.eligibility_digest, binding, cert_active, epoch, &expected_chain_commit, 0x1d00ffff, true,
            ),
            Err(PalwTicketReject::EligibilityMiss),
        );
    }
}
