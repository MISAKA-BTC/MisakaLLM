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
    pub ticket_nullifier: Hash64,
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
    if *h_nullifier != binding.ticket_nullifier {
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
pub fn palw_checkpoint_params_consistent(
    attestation_lag_blue_score: u64,
    attestation_anchor_backoff_blue_score: u64,
    max_reorg_horizon_blocks: u64,
    required_work_depth: BlueWorkType,
    required_stake_depth: u128,
) -> bool {
    let burial = attestation_lag_blue_score.saturating_add(attestation_anchor_backoff_blue_score);
    // Burial must outlast the deepest legal reorg, AND the confirmation predicate must not be vacuous
    // (with both depths zero, `is_dns_confirmed` passes immediately and the "confirmed" anchor is
    // merely lag-ready — a legal deep reorg could then re-roll chain_commit).
    burial >= max_reorg_horizon_blocks && (required_work_depth > BlueWorkType::from(0u64) || required_stake_depth > 0)
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
        if !ticket_nullifiers.insert(leaf.ticket_nullifier) {
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
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// Genesis difficulty bits per lane (set at re-genesis; inert placeholder `0`).
    pub genesis_hash_bits: u32,
    pub genesis_replica_bits: u32,
}

impl LaneDifficultyParams {
    /// The design §16.3 testnet defaults at the committed **10 BPS** PALW genesis (hash 2 / replica 8)
    /// split. Windows mirror the single-lane difficulty window; the genesis bits are re-genesis
    /// placeholders. Inert — nothing retargets the replica lane until the PALW fence.
    pub fn testnet_default() -> Self {
        Self {
            hash_target_time_ms: lane_target_time_ms(2),    // 500 ms (2 BPS)
            replica_target_time_ms: lane_target_time_ms(8), // 125 ms (8 BPS)
            hash_window_size: 2641,
            replica_window_size: 2641,
            min_samples: 60,
            compute_work_scale: 1,
            genesis_hash_bits: 0,
            genesis_replica_bits: 0,
        }
    }

    /// Structural sanity (positive windows / targets / scale). Cheap, config-build time.
    pub fn is_structurally_valid(&self) -> bool {
        self.hash_target_time_ms > 0
            && self.replica_target_time_ms > 0
            && self.hash_window_size > 0
            && self.replica_window_size > 0
            && self.compute_work_scale > 0
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
            ticket_nullifier: nf,
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

        // §12.1 LOOKBACK inequality: testnet DNS numbers (lag 100 + backoff 20 < horizon 300) FAIL —
        // the PALW re-genesis must recalibrate. GENESIS-style deeper lag passes; vacuous depths fail.
        let w = |v: u64| BlueWorkType::from(v);
        assert!(!palw_checkpoint_params_consistent(100, 20, 300, w(100), 5000));
        assert!(palw_checkpoint_params_consistent(300, 20, 300, w(100), 5000));
        assert!(palw_checkpoint_params_consistent(280, 20, 300, w(0), 5000)); // stake depth alone suffices
        assert!(!palw_checkpoint_params_consistent(300, 20, 300, w(0), 0)); // both depths zero = vacuous
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
