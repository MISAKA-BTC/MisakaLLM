//! kaspa-pq ADR-0039 §9.3/§9.5/§18 — PALW overlay-payload processing: parse a PALW subnetwork
//! (`0x30`–`0x37`) transaction's payload and apply the resulting batch-state transition to the
//! [`PalwStore`]. Pure parse + a store-application step, so the transition logic is unit-testable.
//!
//! **Fence status (corrected — the previous "inert on every shipped preset" claim was FALSE).** The
//! caller gates this on the PALW activation fence, which is `u64::MAX` — hence never invoked — on
//! mainnet / testnet-10 / simnet / devnet only. `testnet-palw-110` and `devnet-palw-111` ship
//! `palw_activation_daa_score = 0` (`consensus/core/src/config/params.rs:1403`, `:1454`), so on those
//! two presets this IS invoked and DOES write [`PalwStore`] rows from genesis onward. The transitions
//! ride on ordinary transactions (subnetworks `0x30`–`0x37`), so `palw_algo4_accept = false` — which
//! withholds algo-4 HEADER acceptance in `pre_ghostdag_validation.rs` — does not suppress them; it
//! only guarantees no ticket ever resolves against what is written.

use std::sync::Arc;

use borsh::BorshDeserialize;
use kaspa_consensus_core::palw::{
    PalwBatchCertificateV1, PalwBatchManifestV1, PalwBeaconCommitV1, PalwBeaconRevealV1, PalwLeafChunkV1, PalwProviderBondPayloadV1,
    PalwTicketBinding, palw_leaf_merkle_depth, palw_verify_leaf_membership,
};
use kaspa_consensus_core::subnets::{
    SUBNETWORK_ID_PALW_BATCH_CERT, SUBNETWORK_ID_PALW_BATCH_MANIFEST, SUBNETWORK_ID_PALW_BEACON_COMMIT,
    SUBNETWORK_ID_PALW_BEACON_REVEAL, SUBNETWORK_ID_PALW_LEAF_CHUNK, SUBNETWORK_ID_PALW_PROVIDER_BOND,
};
/// ADR-0040 P1-6 — re-exported so the isolation validator can name the authorization subnetwork without
/// reaching across crates for it.
pub use kaspa_consensus_core::subnets::SUBNETWORK_ID_PALW_BLOCK_AUTHORIZATION;
use kaspa_hashes::Hash64;

use crate::model::services::reachability::MTReachabilityService;
use crate::model::stores::headers::{DbHeadersStore, HeaderStoreReader};
use kaspa_database::prelude::StoreErrorPredicates;

use crate::model::stores::palw::{PalwStore, PalwStoreReader};
use crate::model::stores::palw_beacon::DbPalwBeaconStore;
use crate::model::stores::reachability::DbReachabilityStore;

/// A parsed PALW overlay transaction. Covers the batch lifecycle (`0x30`–`0x33`) and the DNS beacon
/// commit/reveal (`0x35`/`0x36`); the slashing (`0x34`) and provider-unbond (`0x37`) kinds are their own
/// later slices and still fall through to `UnhandledSubnet`.
#[derive(Clone, Debug)]
pub enum PalwOverlayEffect {
    ProviderBond(PalwProviderBondPayloadV1),
    Manifest(PalwBatchManifestV1),
    LeafChunk(PalwLeafChunkV1),
    Certificate(PalwBatchCertificateV1),
    BeaconCommit(PalwBeaconCommitV1),
    BeaconReveal(PalwBeaconRevealV1),
    /// ADR-0040 P1-6 — per-block ticket authorization. Parsed so the overlay walkers can SKIP it
    /// without treating it as a malformed payload; it has no overlay-state effect, because it is
    /// consumed by body-validation clause 7 on the block that carries it, not by the acceptance walk.
    BlockAuthorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PalwOverlayError {
    /// The subnetwork's first byte is not a batch-lifecycle PALW kind this processor handles.
    UnhandledSubnet(u8),
    /// The payload did not borsh-decode as its declared type.
    MalformedPayload,
    /// ADR-0040 §5.15.4 (ACCEPT-BIND/M2) — a leaf chunk reached the acceptance arm declaring a version
    /// other than `PALW_LEAF_CHUNK_VERSION_V2`. v1 chunks carry no membership proofs, so admitting one
    /// would restore exactly the unbound-leaf hole this gate closes.
    LeafChunkUnsupportedVersion(u16),
    /// The batch-state machine rejects this event from the batch's current status (§9.5).
    InvalidTransition,
    /// A manifest's `batch_id` is not its own content id (§9.2) — an attacker-chosen key that must not
    /// be allowed to pollute the content-addressed blob store.
    NonContentAddressedBatchId,
    /// ADR-0040 P1-1 (BIND-01): a leaf chunk referenced a `batch_id` with no admitted manifest. A leaf
    /// must never be the effect that first materialises a batch key.
    UnknownBatch,
    /// ADR-0040 P1-1 (BIND-01): `leaf_index >= manifest.leaf_count`, so the leaf could never be part of
    /// the batch's `leaf_root`.
    LeafIndexOutOfRange { leaf_index: u32, leaf_count: u32 },
    /// ADR-0040 P1-1 (BIND-01): a leaf inside the chunk claims a different `batch_id` than the chunk.
    LeafBatchIdMismatch,
    /// kaspa-pq ADR-0040 §5.14.3 item 7 (P1-10 prerequisite): the leaf's `registered_epoch` is not the
    /// manifest's `registration_epoch`.
    ///
    /// Before this check the leaf's registration epoch was constrained ONLY relationally
    /// (`registered_epoch < activation_epoch < expiry_epoch`, `validate_public_leaf`), while the
    /// manifest's `registration_epoch` is pinned to the batch's real accept epoch by
    /// `PalwBatchManifestV1::admission_valid` (via `PalwBatchViewV1::apply_manifest`). The two numbers
    /// were never compared, so a batch author could publish an admissible manifest at the true epoch and
    /// still stamp its leaves with an arbitrary earlier `registered_epoch` — which is the value
    /// `palw_work_reward_class` feeds to `palw_premium_at_window` at the REWARD coordinate.
    ///
    /// This check is only sound BECAUSE of §5.15 (ACCEPT-BIND/M2). Both numbers are now committed to the
    /// same `batch_id`: `registered_epoch` sits inside `leaf_hash` → `leaf_root` → `content_id()` ==
    /// `batch_id`, and `registration_epoch` sits directly inside `content_id()`. So the pair is fixed at
    /// batch-construction time and neither side can be swapped afterwards. Pre-M2 the same comparison
    /// would have been decorative — the whole leaf could be replaced at `(batch_id, leaf_index)`.
    LeafRegistrationEpochMismatch { leaf_index: u32, leaf_registered_epoch: u64, manifest_registration_epoch: u64 },
    /// ADR-0040 P1-1 (LEAF-01): an attempt to replace an already-written leaf with different content.
    /// Leaves are write-once because coinbase reward scripts are read from them after acceptance.
    LeafImmutabilityViolation,
    /// kaspa-pq ADR-0040 §5.15 (ACCEPT-BIND/M2, gate G3 clause 1): the chunk carries fewer membership
    /// proofs than leaves, so some leaf has no proof at all.
    ///
    /// `validate_leaf_chunk` already requires `proofs.len() == leaves.len()`, but `parse_palw_overlay`
    /// is a bare Borsh decode and this arm must never depend on a check performed by a different pass —
    /// least of all by indexing a caller-supplied `Vec` and panicking inside consensus.
    LeafProofCountMismatch { leaves: usize, proofs: usize },
    /// kaspa-pq ADR-0040 §5.15 (ACCEPT-BIND/M2, gate G3 clause 1): a proof's length is not exactly
    /// `palw_leaf_merkle_depth(manifest.leaf_count)`.
    ///
    /// This is the CONTEXT-BEARING half of the split the context-free `validate_leaf_chunk`
    /// deliberately leaves open (it can only assert the static `<= 8` bound, having no manifest). The
    /// exact bound is what makes the proof for a given `(leaf, index, root)` UNIQUE; a mere upper bound
    /// leaves the variable-length-path forgeries open. Kept a SEPARATE variant from
    /// [`PalwOverlayError::LeafMembershipProofInvalid`] so a rejection is attributable, and so a test
    /// can state that a mis-length proof is refused BEFORE any hashing happens.
    LeafMembershipProofLengthInvalid { leaf_index: u32, got: usize, expected: u32 },
    /// kaspa-pq ADR-0040 §5.15 (ACCEPT-BIND/M2, gate G3 clause 1): the leaf's membership proof does not
    /// fold to `manifest.leaf_root` at the leaf's own `leaf_index` — i.e. this leaf is not a member of
    /// the batch it is being written into.
    ///
    /// This is the CHUNK-INDEX SQUAT closure. `batch_id` is public, so anyone can copy one; before this
    /// gate existed, a squatter could win the write-once race under an honest `batch_id` with ITS OWN
    /// leaves (own `provider_{a,b}_reward_script`, own `ticket_authority_pk_hash`) and take the 77 %
    /// worker base, because consensus never re-derived `leaf_root` from what it stored. Now those fields
    /// live inside `leaf_hash`, `leaf_hash` must open `manifest.leaf_root`, `leaf_root` is inside
    /// `content_id()`, and `batch_id == content_id()` is enforced on both arms — so writing someone
    /// else's `(batch_id, leaf_index)` costs a BLAKE2b-512 second preimage.
    LeafMembershipProofInvalid { leaf_index: u32 },
    /// ADR-0040 P1-4 (BIND-05): the certificate's `manifest_hash` is not the content id of the manifest
    /// for the batch it names — i.e. it certifies a different manifest than the one on chain.
    CertificateManifestMismatch,
    /// ADR-0040 P1-4 (BIND-05): the certificate's `leaf_root` disagrees with the batch manifest's, so it
    /// attests to a leaf set that is not this batch's.
    CertificateLeafRootMismatch,
    /// ADR-0040 P1-3 (CERT-01): a vote's `bond_outpoint` does not resolve to a bond that is ACTIVE at the
    /// certifying block's DAA score — an unbonded (hence unslashable) "auditor".
    CertificateVoteBondNotActive,
    /// ADR-0040 P1-3 (CERT-01): a vote's ML-DSA-87 signature does not verify under its bond's registered
    /// validator key over the vote's `signing_hash`. Previously only the signature LENGTH was checked.
    CertificateVoteSignatureInvalid,
    /// ADR-0040 P1-3 (CERT-01): the stake-weighted PASS tally did not reach the quorum threshold.
    CertificateQuorumNotReached,
    /// ADR-0040 P1-3 (CERT-01): two votes share a `bond_outpoint`, which would let one bond's stake be
    /// counted more than once toward quorum.
    CertificateDuplicateVoteBond,
    /// ADR-0040 §12′: the certificate's declared `approving_stake` disagrees with the tally recomputed
    /// from the active bond view. Rejected because the supersession comparator reads the declared value.
    CertificateApprovingStakeMismatch,
    /// A backing-store read/write failed.
    StoreError,
}

/// kaspa-pq **ADR-0040 P1-3 (CERT-01)** — everything a node needs to decide whether a batch certificate
/// is genuinely ATTESTED, as opposed to merely well-formed and correctly bound.
///
/// The auditor set is the **active DNS stake-bond set** (design §10.2), which is why this needs no new
/// bond store: `ActiveBondView` already carries each bond's `validator_pubkey` and `amount`, and the PALW
/// beacon path already verifies signatures against exactly that view.
pub struct PalwCertificateAttestationCtx<'a> {
    /// Domain-separates signatures across networks (same value the beacon path uses).
    pub network_id: u32,
    /// The **selection snapshot** DAA score — derived from the certificate's own `audit_beacon_epoch`,
    /// NOT from the certifying block's DAA (ADR-0040 §12′).
    ///
    /// Eligibility must freeze at selection, exactly as B assignment does. Evaluating at inclusion time
    /// would let an attacker holding a certificate choose to include it just after an honest auditor's
    /// bond lapses — invalidating that vote, and thereby either killing the honest certificate or
    /// handing the supersession comparison to a censored one. `audit_beacon_epoch` is committed in the
    /// certificate and covered by every vote's `signing_hash`, so it cannot be re-aimed afterwards.
    pub pov_daa_score: u64,
    /// Selected-parent active bond view: the fork-local auditor set.
    pub bond_view: &'a kaspa_consensus_core::dns_finality::ActiveBondView,
    /// Stake-weighted quorum threshold, `num/den` (testnet 2/3).
    pub quorum_num: u16,
    pub quorum_den: u16,
}

/// kaspa-pq **ADR-0040 P1-3 (CERT-01)** — verify that a certificate is actually attested.
///
/// ## What was wrong
///
/// `validate_certificate` (isolation) checked version, vote count, epoch ordering, `vote <= 1`, outpoint
/// ordering — and the signature **LENGTH**. Nothing else. No ML-DSA verification existed anywhere in PALW
/// consensus, `quorum_reached` had no production caller, and `apply_certificate` flipped a batch to
/// `Certified` on arrival. A certificate carrying correctly-sized *garbage* signatures was therefore
/// accepted, stored content-addressed, and its hash became referenceable by an algo-4 header.
///
/// ## What is enforced now, in order
///
/// 1. **No duplicate bonds.** Isolation already requires strictly ascending outpoints, so this is
///    redundant there — but this function must be sound on its own, since it is what quorum arithmetic
///    depends on. One bond must never contribute its stake twice.
/// 2. **Every voting bond is ACTIVE at the certifying block's DAA score.** An auditor that is not bonded
///    at that point of view is not slashable, and an unslashable auditor is not an auditor.
/// 3. **Every vote's ML-DSA-87 signature verifies** under that bond's registered `validator_pubkey`, over
///    [`PalwAuditorVoteV1::signing_hash`] — which covers `batch_id`, `audit_beacon_epoch`,
///    `audit_sample_root` and the auditor's own checked-leaf bitmap. Signatures are verified for ABSTAIN
///    votes too: a forged abstention still inflates the denominator and so lowers the effective bar.
/// 4. **Stake-weighted quorum** over the participating bonds.
///
/// ## Honest scope limit
///
/// The denominator is the stake of the bonds that actually VOTED, not the stake of the beacon-selected
/// eligible set — selection itself (`sample_auditors_by_score`) is still not stake-weighted and has no
/// production caller (ADR-0040 SEL-01, P2-1). So this proves *"≥ num/den of participating bonded stake
/// signed off"*, not yet *"≥ num/den of the set that was supposed to audit"*. `audit_sample_root` is
/// likewise still not re-derived (SAMPLE-01, P2-7), so I-14's possession property remains unproven.
///
/// That gap is real and is why G4 stays an `Activation`-class gate rather than a `StopShip` one. But the
/// step is not cosmetic: forging a certificate now requires **live ML-DSA-87 signatures from a
/// quorum-weight majority of genuinely bonded, slashable stake**, instead of bytes of the right length.
pub fn verify_certificate_attestation(
    cert: &PalwBatchCertificateV1,
    ctx: &PalwCertificateAttestationCtx<'_>,
) -> Result<(), PalwOverlayError> {
    use kaspa_consensus_core::palw::PALW_AUDITOR_MLDSA87_CONTEXT;
    use kaspa_txscript::verify_mldsa87_with_context;

    let digest = |v: &kaspa_consensus_core::palw::PalwAuditorVoteV1| {
        v.signing_hash(ctx.network_id, &cert.batch_id, cert.audit_beacon_epoch, &cert.audit_sample_root)
    };

    let mut seen: Vec<&kaspa_consensus_core::tx::TransactionOutpoint> = Vec::with_capacity(cert.votes.len());
    let mut total_stake: u128 = 0;
    let mut pass_stake: u128 = 0;

    for vote in &cert.votes {
        // (1) one bond, one vote.
        if seen.contains(&&vote.bond_outpoint) {
            return Err(PalwOverlayError::CertificateDuplicateVoteBond);
        }
        seen.push(&vote.bond_outpoint);

        // (2) the bond must be active at this point of view.
        let bond =
            ctx.bond_view.active_bond_at(&vote.bond_outpoint, ctx.pov_daa_score).ok_or(PalwOverlayError::CertificateVoteBondNotActive)?;

        // (3) real signature, over the vote's own signing hash, under the bond's registered key.
        let d = digest(vote);
        if !matches!(
            verify_mldsa87_with_context(&bond.validator_pubkey, d.as_bytes().as_slice(), &vote.signature, PALW_AUDITOR_MLDSA87_CONTEXT),
            Ok(true)
        ) {
            return Err(PalwOverlayError::CertificateVoteSignatureInvalid);
        }

        total_stake = total_stake.saturating_add(bond.amount as u128);
        if vote.vote == 1 {
            pass_stake = pass_stake.saturating_add(bond.amount as u128);
        }
    }

    // (4) The DECLARED approving stake must equal what we just tallied. This is what turns
    // `approving_stake` from a trusted input into a commitment, bound here — at the only point that has
    // the bond view.
    //
    // NOTE on why this is now belt-and-braces rather than load-bearing. It was written when the §12′
    // supersession comparator ranked certificates by this declared field at the BODY coordinate, where
    // no bond view exists and this check has not yet run — so an inflated value could evict a better
    // certificate. That comparator is withdrawn (§5.6.1a/b): `apply_certificate` now reads no
    // attacker-declarable quantity. The equality is kept because a certificate that lies about its own
    // tally is malformed regardless of who reads the field, and keeping it means a future reader cannot
    // reintroduce the hole by trusting the declaration.
    if cert.approving_stake != pass_stake {
        return Err(PalwOverlayError::CertificateApprovingStakeMismatch);
    }

    // (5) stake-weighted quorum. The guards inside `quorum_reached` (ADR-0040 P0-5) make a zero total or
    // a zero threshold fail closed rather than vacuously pass.
    let stake_of = |o: &kaspa_consensus_core::tx::TransactionOutpoint| -> u128 {
        ctx.bond_view.active_bond_at(o, ctx.pov_daa_score).map(|b| b.amount as u128).unwrap_or(0)
    };
    if !cert.quorum_reached(total_stake, ctx.quorum_num, ctx.quorum_den, stake_of) {
        return Err(PalwOverlayError::CertificateQuorumNotReached);
    }
    Ok(())
}

/// ADR-0039 §9.2/§9.3/§11.2 — parse a PALW overlay tx payload by its subnetwork's first byte. Handles
/// the batch lifecycle (`0x30`–`0x33`) and the beacon commit/reveal (`0x35`/`0x36`); pure (borsh decode),
/// touches no store.
pub fn parse_palw_overlay(subnet_first_byte: u8, payload: &[u8]) -> Result<PalwOverlayEffect, PalwOverlayError> {
    let malformed = |_| PalwOverlayError::MalformedPayload;
    // Resolve each handled subnetwork id to its first byte; the slashing (0x34) / unbond (0x37) kinds
    // fall through to `UnhandledSubnet` here (their own later slices).
    let bond = SUBNETWORK_ID_PALW_PROVIDER_BOND.palw_tx_kind().unwrap();
    let manifest = SUBNETWORK_ID_PALW_BATCH_MANIFEST.palw_tx_kind().unwrap();
    let leaf_chunk = SUBNETWORK_ID_PALW_LEAF_CHUNK.palw_tx_kind().unwrap();
    let cert = SUBNETWORK_ID_PALW_BATCH_CERT.palw_tx_kind().unwrap();
    let beacon_commit = SUBNETWORK_ID_PALW_BEACON_COMMIT.palw_tx_kind().unwrap();
    let beacon_reveal = SUBNETWORK_ID_PALW_BEACON_REVEAL.palw_tx_kind().unwrap();
    match subnet_first_byte {
        b if b == bond => PalwProviderBondPayloadV1::try_from_slice(payload).map(PalwOverlayEffect::ProviderBond).map_err(malformed),
        b if b == manifest => PalwBatchManifestV1::try_from_slice(payload).map(PalwOverlayEffect::Manifest).map_err(malformed),
        b if b == leaf_chunk => PalwLeafChunkV1::try_from_slice(payload).map(PalwOverlayEffect::LeafChunk).map_err(malformed),
        b if b == cert => PalwBatchCertificateV1::try_from_slice(payload).map(PalwOverlayEffect::Certificate).map_err(malformed),
        b if b == beacon_commit => PalwBeaconCommitV1::try_from_slice(payload).map(PalwOverlayEffect::BeaconCommit).map_err(malformed),
        b if b == beacon_reveal => PalwBeaconRevealV1::try_from_slice(payload).map(PalwOverlayEffect::BeaconReveal).map_err(malformed),
        b if b == SUBNETWORK_ID_PALW_BLOCK_AUTHORIZATION.palw_tx_kind().unwrap() => Ok(PalwOverlayEffect::BlockAuthorization),
        other => Err(PalwOverlayError::UnhandledSubnet(other)),
    }
}

/// ADR-0039 §9.5 / §11.2 — apply a parsed overlay effect. **Batch-lifecycle effects persist only the
/// immutable, CONTENT-ADDRESSED blob** (manifest / leaves / certificate) into the [`PalwStore`]; they do
/// **not** write a mutable `batch_status`. The fork-dependent lifecycle (Registering → … → Active /
/// Revoked) lives in the block-keyed overlay VIEW (`commit_palw_overlay_view`), which `check_palw_ticket`
/// resolves against (C5). The old global `set_batch_status` here was the sink-search-loser fork-unsafe
/// write the C4 panel flagged (a UTXO-valid candidate later rejected by sink selection would overwrite the
/// canonical status); with the view as the authoritative lifecycle it is retired. What remains is
/// write-once, content-addressed, fork-safe (same content ⇒ same key), and admission-guarded: a manifest
/// whose `batch_id` is not its own content id is rejected so the store cannot be polluted under an
/// attacker-chosen key. Beacon commit/reveal effects accumulate into the epoch's [`DbPalwBeaconStore`].
/// Deterministic; the caller has already gated on the PALW fence.
pub fn apply_palw_overlay_effect(
    effect: PalwOverlayEffect,
    store: &dyn PalwStore,
    beacon: &DbPalwBeaconStore,
    attest: Option<&PalwCertificateAttestationCtx<'_>>,
) -> Result<(), PalwOverlayError> {
    match effect {
        PalwOverlayEffect::BeaconCommit(c) => {
            // §11.2: record the commitment for its epoch (idempotent per bond). No batch-state effect.
            beacon.record_commit(c.epoch, c.bond_outpoint, c.commitment).map_err(|_| PalwOverlayError::StoreError)
        }
        PalwOverlayEffect::BeaconReveal(r) => {
            // §11.2: a reveal counts only if a prior commit for this (epoch, bond) exists AND the reveal
            // validly opens it. Otherwise it is inert (dropped) — a reveal with no/wrong commit is not a
            // seed input. `commitment_of` reads the same-epoch commit (submitted in an earlier block).
            if let Some(commitment) = beacon.commitment_of(r.epoch, &r.bond_outpoint).map_err(|_| PalwOverlayError::StoreError)? {
                if r.matches_commit(&commitment) {
                    beacon
                        .record_valid_reveal(r.epoch, r.bond_outpoint, r.entropy_digest())
                        .map_err(|_| PalwOverlayError::StoreError)?;
                }
            }
            Ok(())
        }
        // ADR-0040 P1-6: no overlay-state effect — clause 7 already consumed it on its own block.
        PalwOverlayEffect::BlockAuthorization => Ok(()),
        PalwOverlayEffect::ProviderBond(_bond) => {
            // Provider-bond registration feeds the bond view (`PalwProviderBond` prefix) — the bond-store
            // wiring is the audit / economics slice. No batch-state effect.
            Ok(())
        }
        PalwOverlayEffect::Manifest(m) => {
            // Content-address guard (§9.2): the manifest's key must be its own content id, else it is an
            // attacker-chosen key that could pollute the blob store / collide across forks. (The full
            // admission window/bounds check lives in the authoritative view builder, `apply_manifest`.)
            if !m.batch_id_is_content_derived() {
                return Err(PalwOverlayError::NonContentAddressedBatchId);
            }
            store.insert_manifest(m.batch_id, Arc::new(m)).map_err(|_| PalwOverlayError::StoreError)
        }
        PalwOverlayEffect::LeafChunk(c) => {
            // kaspa-pq **ADR-0040 P1-1 (BIND-01)** — contextual admission for leaf blobs.
            //
            // This arm used to be an unconditional insert loop over an attacker-supplied `c.batch_id`,
            // with no manifest lookup, no index bound, and no binding back to the batch. Combined with
            // algo-4's exemption from the Layer-0 hash floor, that made the lane's ENTIRE proof-of-work
            // grindable offline: clause 9 draws on `eligibility_hash(.., leaf_hash, nullifier)`, and both
            // of those are fields of a leaf the attacker authored and injected.
            //
            // The manifest is the batch's only content-addressed anchor (`batch_id == content_id()`,
            // enforced in the Manifest arm), so requiring it here is what ties a leaf to a real batch.
            let manifest = store.batch_manifest(c.batch_id).map_err(|_| PalwOverlayError::UnknownBatch)?;
            // Defence in depth: the Manifest arm cannot admit a non-content-derived id, but a leaf chunk
            // must never be the thing that first materialises a batch key.
            if !manifest.batch_id_is_content_derived() {
                return Err(PalwOverlayError::NonContentAddressedBatchId);
            }
            // ADR-0040 §5.15.4 — the chunk VERSION is re-checked here, not only in the context-free
            // validator. The two checks are not redundant: `validate_leaf_chunk` runs on the
            // transaction-isolation path, while this arm is reachable from the acceptance path, and an
            // adversarial review drove a `version: 1` chunk carrying an otherwise-valid membership proof
            // straight into this function and had the leaf STORED. A v1 chunk has no `proofs` field by
            // construction, so accepting one here is precisely the lenient parse §5.15.4 forbids.
            if c.version != kaspa_consensus_core::palw::PALW_LEAF_CHUNK_VERSION_V2 {
                return Err(PalwOverlayError::LeafChunkUnsupportedVersion(c.version));
            }
            for (position, leaf) in c.leaves.iter().enumerate() {
                // Index bound: the manifest fixes `leaf_count`, so an out-of-range index is a leaf that
                // can never be part of `leaf_root` — i.e. pure blob-store pollution.
                if leaf.leaf_index >= manifest.leaf_count {
                    return Err(PalwOverlayError::LeafIndexOutOfRange { leaf_index: leaf.leaf_index, leaf_count: manifest.leaf_count });
                }
                // Cross-check the leaf's own `batch_id` against the chunk's, so a chunk cannot smuggle a
                // leaf that claims membership in a different batch.
                if leaf.batch_id != c.batch_id {
                    return Err(PalwOverlayError::LeafBatchIdMismatch);
                }

                // ---- kaspa-pq ADR-0040 §5.14.3 item 7 (P1-10 prerequisite) — PIN THE LEAF'S EPOCH ----
                //
                // `validate_public_leaf` constrains `registered_epoch` only RELATIONALLY (it must be less
                // than `activation_epoch`). Nothing tied it to the batch. The manifest side is pinned:
                // `admission_valid` refuses `registration_epoch != accept_epoch`, and a batch must pass
                // through `apply_manifest` into the fork-relative view before `check_palw_ticket`'s
                // `view.resolvable_batch` will let any header mine against it. So the manifest's number is
                // the batch's real acceptance epoch; the leaf's was free.
                //
                // That freedom is not cosmetic — `palw_work_reward_class` reads `leaf.registered_epoch`
                // and feeds it to `palw_premium_at_window`, i.e. it selects which π-controller window
                // prices the leaf. The controller returns the neutral constant today, so nothing is
                // mispriced YET; this closes the degree of freedom BEFORE the sampler lands rather than
                // after, because once the premium varies the leaf is immutable and the choice is already
                // committed.
                //
                // Chained with the manifest-side pin this gives §5.14.3 item 7 in full:
                //   mineable ⇒ resolvable in view(SP) ⇒ admission_valid ⇒ registration_epoch == accept
                //   epoch, and (here) leaf.registered_epoch == registration_epoch.
                // The acceptance arm alone does NOT reach "the real epoch" — it binds leaf to manifest,
                // and the view's admission gate binds manifest to the carrier epoch. A batch that never
                // enters the view may still be stored with any declared epoch; it simply cannot mint.
                if leaf.registered_epoch != manifest.registration_epoch {
                    return Err(PalwOverlayError::LeafRegistrationEpochMismatch {
                        leaf_index: leaf.leaf_index,
                        leaf_registered_epoch: leaf.registered_epoch,
                        manifest_registration_epoch: manifest.registration_epoch,
                    });
                }

                // ---- kaspa-pq ADR-0040 §5.15.4(3) (ACCEPT-BIND/M2) — THE MEMBERSHIP GATE ----
                //
                // Everything above checks what the leaf DECLARES about itself; none of it binds the
                // leaf's CONTENT to the batch. `leaf.batch_id` is a field the submitter wrote, and
                // `batch_id` is public — so before this gate an observer could copy an honest
                // `batch_id`, author leaves naming its own reward scripts and ticket authority, and win
                // the write-once race at `(batch_id, leaf_index)`. The honest auditors' certificate then
                // covered the squatter's leaves, because nothing ever re-derived `leaf_root` from what
                // was stored (`palw_leaf_root` had ZERO consensus callers, and the "§9.3 completeness
                // gate" its doc named did not exist — §5.15.2/§5.15.3).
                //
                // WHY IT MUST BE HERE, BEFORE `insert_leaf`, and not at certificate admission: a gate
                // that re-derived the root from the store at certificate time would close THEFT but
                // leave DENIAL wide open and, worse, permanent — the poisoned leaves are already
                // stored, the honest leaf is then refused as differing content, the batch is
                // permanently uncertifiable, and because `batch_id == content_id()` re-registering the
                // same manifest reuses the very same poisoned keys. Firing before the write is what
                // makes DENIAL fall out of `insert_leaf`'s same-content idempotence instead: a chunk
                // that passes this gate is byte-identical to the honest chunk, so a front-run degrades
                // to the attacker paying the fee to publish the victim's own data, and the honest
                // transaction still succeeds.
                let proof = c
                    .proofs
                    .get(position)
                    .ok_or(PalwOverlayError::LeafProofCountMismatch { leaves: c.leaves.len(), proofs: c.proofs.len() })?;
                // The EXACT length — both too short and too long are rejected — and BEFORE any hashing.
                // `palw_verify_leaf_membership` re-checks this internally; the explicit check here is
                // what gives the failure its own attributable variant and pins the ordering.
                let expected_proof_len = palw_leaf_merkle_depth(manifest.leaf_count);
                if proof.siblings.len() as u32 != expected_proof_len {
                    return Err(PalwOverlayError::LeafMembershipProofLengthInvalid {
                        leaf_index: leaf.leaf_index,
                        got: proof.siblings.len(),
                        expected: expected_proof_len,
                    });
                }
                // The tree is built over the `batch_id`-ZEROED projection of each leaf (`leaf_root` is
                // itself inside `content_id()`, which is the definition of `batch_id` — a leaf hash that
                // included `batch_id` would make the manifest's identity self-referential). Producers
                // project identically in `mil::miner::registration::ordered_batch_leaf_hashes`.
                //
                // NOTE (§5.15.12, FIXED-POINT): this is deliberately NOT the same digest as
                // `resolve_palw_binding`'s, which keeps `batch_id` populated on purpose for the
                // eligibility draw. The tree therefore holds two intentionally different hashes of the
                // same leaf. Do not "de-duplicate" them.
                let mut projected = leaf.clone();
                projected.batch_id = Hash64::default();
                // Direction bits come from `leaf.leaf_index`, never from the payload, and the index is
                // bound INSIDE the level-0 node — so a leaf that is a legitimate member at index i
                // cannot be replayed as a member at any j != i.
                if !palw_verify_leaf_membership(
                    &projected.leaf_hash(),
                    leaf.leaf_index,
                    manifest.leaf_count,
                    proof,
                    &manifest.leaf_root,
                ) {
                    return Err(PalwOverlayError::LeafMembershipProofInvalid { leaf_index: leaf.leaf_index });
                }
                // ADR-0040 P1-9 — the GLOBAL job-nullifier check is DEFERRED ENTIRELY. It is not here,
                // and (as of the P1-5 remediation) it is no longer on the block-keyed view either.
                //
                // It cannot be here: this arm writes the content-addressed blob store, which sits on the
                // ACCEPTANCE coordinate, and enforcing a fork-relative rule here would make the same leaf
                // admissible or not depending on which coordinate observed it first — the BIND-03
                // mismatch, applied to a rule where it would be a consensus split rather than a nuisance.
                //
                // It cannot be on the body/mergeset view either, which is why it was withdrawn from
                // there: that coordinate has no `ActiveBondView` and performs no signature verification,
                // so a first-claim-wins registry there ranks by an attacker-declarable value — unbounded
                // per-block state, and a batch-bricking censorship lever the moment the rejection is
                // armed. It will land at the REWARD/virtual coordinate, authorised by the provider's
                // ML-DSA signature over `ReplicaExecutionReceiptV1::signing_hash` (which commits to
                // `job_nullifier`). See ADR-0040.
                //
                // Blob persistence is therefore permissive, and duplicate-work rejection is an
                // Activation-class gate that blocks mainnet activation — not a body-validity rule.

                // Write-once (see `DbPalwStore::insert_leaf`): identical content is idempotent, different
                // content at an occupied index is rejected rather than silently replacing the leaf whose
                // reward scripts a coinbase may already have been derived from.
                store.insert_leaf(c.batch_id, leaf.leaf_index, Arc::new(leaf.clone())).map_err(|e| {
                    if e.is_already_exists() {
                        PalwOverlayError::LeafImmutabilityViolation
                    } else {
                        PalwOverlayError::StoreError
                    }
                })?;
            }
            Ok(())
        }
        PalwOverlayEffect::Certificate(cert) => {
            // kaspa-pq **ADR-0040 P1-4 (BIND-02 / BIND-05)** — bind the certificate to the batch it claims
            // to certify BEFORE persisting it.
            //
            // Previously this arm persisted the blob unconditionally ("keyed by its own hash, so it is
            // self-content-addressed"). Self-addressing makes the KEY honest; it says nothing about the
            // CONTENTS. Downstream, `is_block_eligible_at` only requires `cert_hash.is_some()`, and
            // `resolve_palw_binding` reads only the certificate's epoch window — so an unbound certificate
            // blob in the store could satisfy an algo-4 header for a batch it never certified.
            //
            // The three fields below are the ones the design says identify the certified batch, and all
            // three were decoded-but-never-read. Checking them here means a certificate that names the
            // wrong batch, the wrong manifest, or the wrong leaf set can never reach the view at all.
            //
            // NOT closed here (needs the provider/auditor bond state, ADR-0040 P2-5/P2-7): ML-DSA
            // verification of each vote, auditor-selection membership, stake-weighted quorum, and
            // `audit_sample_root` re-derivation. A vote carries only a `bond_outpoint`, so resolving it to
            // a signing key requires the bond store that does not exist yet. Until then a certificate is
            // *correctly bound* but *not yet attested* — which is exactly why `palw_algo4_accept` stays
            // false (ADR-0040 §7.1.1: CERT-01 is gate G4, an `Activation`-class gate).
            let manifest = store.batch_manifest(cert.batch_id).map_err(|_| PalwOverlayError::UnknownBatch)?;
            if cert.manifest_hash != manifest.content_id() {
                return Err(PalwOverlayError::CertificateManifestMismatch);
            }
            if cert.leaf_root != manifest.leaf_root {
                return Err(PalwOverlayError::CertificateLeafRootMismatch);
            }
            // ADR-0040 P1-3 (CERT-01) — the ATTESTATION half. See `verify_certificate_attestation`.
            if let Some(ctx) = attest {
                verify_certificate_attestation(&cert, ctx)?;
            }
            store.insert_certificate(cert.hash(), Arc::new(cert)).map_err(|_| PalwOverlayError::StoreError)
        }
    }
}

/// The store-resolved facts an algo-4 (PALW) header binds to (ADR-0039 §14.2 / §18.1): the pure
/// [`PalwTicketBinding`] fed to [`kaspa_consensus_core::palw::verify_palw_ticket_store_facts`], the
/// certificate's active window (so the caller computes `cert_active` at the block's epoch), and the
/// resolved `leaf_hash` (the eligibility-draw preimage input the beacon slice will consume).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PalwResolvedBinding {
    pub binding: PalwTicketBinding,
    pub cert_activation_epoch: u64,
    pub cert_expiry_epoch: u64,
    pub leaf_hash: Hash64,
    /// ADR-0040 P1-6 (AUTH-03): the leaf's declared ticket authority. Projected here because it had
    /// ZERO production readers — the field named an authority nothing checked. Clause 7 checks it.
    pub ticket_authority_pk_hash: Hash64,
}

/// Why an algo-4 header's overlay binding could not be resolved from the stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PalwBindingError {
    /// No leaf at `(palw_batch_id, palw_leaf_index)` — the ticket references a leaf not on-chain.
    LeafAbsent,
    /// No certificate at `palw_epoch_certificate_hash` — the batch has no on-chain certification.
    CertAbsent,
    /// kaspa-pq **ADR-0040 CERT-BATCH** — a certificate WAS found at `palw_epoch_certificate_hash`, but
    /// it certifies a DIFFERENT batch than the header's `palw_batch_id`.
    ///
    /// Distinct from [`Self::CertAbsent`] on purpose: "the blob is missing" and "the blob is present but
    /// belongs to someone else" are different operator-visible failures, and collapsing them would hide
    /// a substitution attempt behind a benign-looking propagation gap.
    CertBatchMismatch,
}

/// ADR-0039 §18.1 — resolve the leaf + certificate an algo-4 header names into the pure verify inputs.
/// This is the concrete `verify_palw_ticket ↔ PalwStore` bridge: a header carries `(batch_id, leaf_index,
/// epoch_certificate_hash, target_daa_interval)`; this reads the corresponding [`PalwPublicLeafV1`] and
/// [`PalwBatchCertificateV1`] and packs them into a [`PalwResolvedBinding`]. Store absence fails closed
/// (`LeafAbsent` / `CertAbsent`). Pure w.r.t. the store snapshot — the caller then applies
/// [`kaspa_consensus_core::palw::verify_palw_ticket_store_facts`] (and, once the beacon / lane-DAA /
/// checkpoint / compute-cap state is live, the full [`kaspa_consensus_core::palw::verify_palw_ticket`]).
pub fn resolve_palw_binding(
    batch_id: Hash64,
    leaf_index: u32,
    epoch_certificate_hash: Hash64,
    target_daa_interval: u64,
    store: &dyn PalwStoreReader,
) -> Result<PalwResolvedBinding, PalwBindingError> {
    let leaf = store.leaf(batch_id, leaf_index).map_err(|_| PalwBindingError::LeafAbsent)?;
    let cert = store.certificate(epoch_certificate_hash).map_err(|_| PalwBindingError::CertAbsent)?;
    // kaspa-pq **ADR-0040 CERT-BATCH** — the certificate is resolved BY HASH ALONE, so without this the
    // resolver would happily project ANY stored certificate's window onto ANY batch. `cert.batch_id` is
    // the certified subject and is covered by `PalwBatchCertificateV1::hash` (hence by the store key), so
    // comparing it here is a total, cheap cross-bind. Kept in the RESOLVER rather than only at the call
    // site so every present and future caller inherits it.
    //
    // Scope note (honest): this closes CROSS-BATCH substitution. It does NOT pin WHICH of a batch's own
    // certificates a header may name — several attested certificates for one batch legitimately coexist
    // in the content-addressed store, and the fork-relative view deliberately no longer records a
    // canonical winner (see `PalwBatchViewV1::apply_certificate`, ADR-0040 CERT-TRUST): making the view's
    // first-arrival `cert_hash` binding would hand any unattested overlay tx a censorship lever, which is
    // the very failure CERT-TRUST removes. Every same-batch alternative is itself quorum-attested and
    // manifest/leaf-root-bound, and the field is not free to an OBSERVER either — the clause-7
    // authorization commits to the whole header preimage, `palw_epoch_certificate_hash` included.
    if cert.batch_id != batch_id {
        return Err(PalwBindingError::CertBatchMismatch);
    }
    Ok(PalwResolvedBinding {
        binding: PalwTicketBinding {
            ticket_nullifier_commitment: leaf.ticket_nullifier_commitment,
            proof_type: leaf.proof_type,
            leaf_activation_epoch: leaf.activation_epoch,
            leaf_expiry_epoch: leaf.expiry_epoch,
            target_daa_interval,
        },
        cert_activation_epoch: cert.activation_epoch,
        cert_expiry_epoch: cert.expiry_epoch,
        // ---- kaspa-pq ADR-0040 §5.15.12 (FIXED-POINT) — READ THIS BEFORE "DE-DUPLICATING" ----
        //
        // This is the `batch_id`-POPULATED `leaf_hash()`, and that is DELIBERATE. It feeds the clause-9
        // eligibility draw (`eligibility_hash`), where binding the draw to the batch the ticket names is
        // the whole point.
        //
        // The ACCEPTANCE arm (`apply_palw_overlay_effect`, LeafChunk) hashes the SAME leaf with
        // `batch_id` ZEROED, because the Merkle `leaf_root` it opens sits inside `content_id()`, which IS
        // `batch_id` — a populated hash there would be an unsolvable fixed point. So the tree carries two
        // intentionally different hashes of one leaf.
        //
        // Collapsing them breaks something in either direction: switching the acceptance arm to this
        // digest makes every honest chunk unopenable (silently — the arm's error is discarded by the
        // production caller), and switching this line to the projected digest unbinds the eligibility
        // draw from the batch. `producer_built_batch_round_trips_through_the_real_acceptance_arm` asserts
        // BOTH directions, so a de-duplication fails loudly rather than shipping.
        leaf_hash: leaf.leaf_hash(),
        ticket_authority_pk_hash: leaf.ticket_authority_pk_hash,
    })
}

/// ADR-0039 §12.3 — the `R_E → eligibility_digest` bridge: resolve the beacon seed active for a block
/// (the seed carried by its `selected_parent`, past-relative + reorg-safe) and compute the header's
/// one-shot draw digest via [`kaspa_consensus_core::palw::eligibility_hash`]. Every other input is on the
/// header, in config (`network_id`), or resolvable from the leaf store (`leaf_hash` via
/// [`resolve_palw_binding`]). Returns `None` when the beacon has not yet produced a seed in this block's
/// history.
///
/// **This is the tested computation seam ONLY — it is deliberately NOT wired into the enforced
/// `check_palw_ticket`.** Enforcing the eligibility DRAW (`palw_eligibility_win` over this digest) while
/// the lane-DAA `expected_bits` (clause 7) and the checkpoint `chain_commit` (clause 6) are still not
/// live would be a *grindable half-gate*: `palw_eligibility_win` compares against the header's own `bits`,
/// so an unchecked-`bits` header trivially satisfies the draw. The activation slice that lands clauses
/// 6+7+8 flips the whole algo-4 acceptance rule atomically (the full
/// [`kaspa_consensus_core::palw::verify_palw_ticket`]); this seam proves R_E makes clause 9 *computable*.
pub fn resolve_palw_eligibility(
    beacon: &DbPalwBeaconStore,
    selected_parent: kaspa_consensus_core::BlockHash,
    network_id: u32,
    header_chain_commit: &Hash64,
    header_target_interval: u64,
    header_batch_id: &Hash64,
    header_leaf_index: u32,
    leaf_hash: &Hash64,
    header_ticket_nullifier: &Hash64,
) -> Result<Option<Hash64>, kaspa_database::prelude::StoreError> {
    let Some(state) = beacon.beacon_state(selected_parent)? else { return Ok(None) };
    Ok(Some(kaspa_consensus_core::palw::eligibility_hash(
        network_id,
        &state.seed,
        header_chain_commit,
        header_target_interval,
        header_batch_id,
        header_leaf_index,
        leaf_hash,
        header_ticket_nullifier,
    )))
}

/// ADR-0039 §12.1 — the clause-6 bridge: resolve a header's `expected_chain_commit` from the beacon
/// record carried at its **selected parent** (design-panel resolution: the exact same single record
/// read clause 9 uses via [`resolve_palw_eligibility`] — cert and seed share one provenance, so
/// clause 6 adds zero fork-degrees-of-freedom over clause 9, c==v is structural, and a boundary-
/// crossing header simply binds the previous epoch's frozen facts). The certificate digest is derived
/// on demand from the record's anchor-pure facts ([`PalwBeaconStateV1::dns_certificate_hash`]).
///
/// **Fail-closed** (`None`): no carried record, or no DNS-confirmed anchor yet (the zero bootstrap
/// anchor certifies nothing — I-4 would be void). The C5 atomic flip rejects algo-4 on `None`.
/// Like [`resolve_palw_eligibility`], this is the tested computation seam ONLY — not spliced into the
/// enforced `check_palw_ticket` until the C5 flip lands all of clauses 6–9 together.
pub fn resolve_palw_chain_commit(
    beacon: &DbPalwBeaconStore,
    selected_parent: kaspa_consensus_core::BlockHash,
    network_id: u32,
    target_interval: u64,
) -> Result<Option<Hash64>, kaspa_database::prelude::StoreError> {
    let Some(state) = beacon.beacon_state(selected_parent)? else { return Ok(None) };
    let Some(certificate) = state.dns_certificate_hash() else { return Ok(None) };
    Ok(Some(kaspa_consensus_core::palw::chain_commit(&state.dns_anchor, &certificate, target_interval, network_id)))
}

/// ADR-0039 §16.3 — the clause-7 HOLD bridge: resolve a lane's carried "last bits" from the block-keyed
/// lane-bits store at a block's **selected parent** (past-relative). A `None` row (genesis / a
/// pre-activation parent) falls back to the lane's `genesis_bits` — so the first PALW blocks HOLD the
/// genesis lane difficulty rather than reading the selected parent's `header.bits` (which, at a
/// mixed-lane boundary, is the OTHER lane's difficulty — the structural blocker). This is the retarget
/// HOLD source; the full lane window build + `lane_retarget_bits` Adjust path is the pipeline wiring.
/// Tested seam — NOT spliced into the enforced difficulty check until the C7 pipeline wiring + C5 flip.
pub fn resolve_palw_lane_hold_bits(
    lane_bits_store: &crate::model::stores::palw_lane_bits::DbPalwLaneBitsStore,
    selected_parent: kaspa_consensus_core::BlockHash,
    lane: kaspa_consensus_core::pow_layer0::WorkLane,
    lane_params: &kaspa_consensus_core::palw::LaneDifficultyParams,
) -> Result<u32, kaspa_database::prelude::StoreError> {
    Ok(match lane_bits_store.lane_bits(selected_parent)? {
        Some(carried) => carried.lane_bits(lane),
        None => lane_params.genesis_bits(lane),
    })
}

/// ADR-0039 §12.1 / C6 SLICE 0 — resolve the **finality-buried DNS anchor** for a block from its
/// selected parent, as a PURE FUNCTION OF THE PAST over `(headers_store, reachability, dns_params)`
/// alone — no virtual/UTXO/bond state. This is the body-stage-callable extraction of the virtual
/// processor's `canonical_anchor_by_blue_score`, using the **window-INDEPENDENT** variant (no
/// `stake_score_window` break) so the resolved anchor is tip-independent for a buried epoch and the
/// miner's template + the validator resolve the identical anchor across a pruning-window advance
/// (construction==validation, C6 panel SLICE 0). The anchor is buried by `attestation_lag_blue_score`;
/// the re-genesis band gate (`palw_checkpoint_params_consistent`, C6 SLICE 5) additionally requires the
/// lag to exceed the reorg horizon (so the anchor's selected-chain identity is settled) and stay below
/// the pruning depth (so its header survives on pruned nodes). Returns `None` before any lag-ready epoch
/// exists in this block's history.
pub fn resolve_palw_lagged_anchor(
    headers: &DbHeadersStore,
    reachability: &MTReachabilityService<DbReachabilityStore>,
    dns_params: &kaspa_consensus_core::dns_finality::DnsParams,
    selected_parent: kaspa_consensus_core::BlockHash,
) -> Option<kaspa_consensus_core::dns_finality::CanonicalLaggedEpochAnchor> {
    use kaspa_consensus_core::dns_finality::{
        anchor_cutoff_blue_score, canonical_lagged_epoch_anchor, ready_epoch_from_tip_blue_score,
    };
    let epoch_len = dns_params.attestation_epoch_length_blue_score.max(1);
    let lag = dns_params.attestation_lag_blue_score;
    let backoff = dns_params.attestation_anchor_backoff_blue_score;
    let sp_blue = headers.get_blue_score(selected_parent).ok()?;
    let dns_epoch = ready_epoch_from_tip_blue_score(sp_blue, epoch_len, lag)?;
    let cutoff = anchor_cutoff_blue_score(dns_epoch, epoch_len, backoff);
    if cutoff > sp_blue {
        return None;
    }
    // Walk the selected-parent chain down until the PREVIOUS epoch's cutoff is buried (decidable
    // duplicate-anchor check), with NO window cap (the acceptance path must resolve the identical
    // canonical anchor even after a pruning-window advance). Position is read from blue_score.
    let needed = anchor_cutoff_blue_score(dns_epoch.saturating_sub(1), epoch_len, backoff);
    let mut ancestors: Vec<(kaspa_consensus_core::BlockHash, u64, u64)> = Vec::new();
    for hash in std::iter::once(selected_parent).chain(reachability.default_backward_chain_iterator(selected_parent)) {
        let compact = headers.get_compact_header_data(hash).ok()?;
        ancestors.push((hash, compact.blue_score, compact.daa_score));
        if compact.blue_score <= needed {
            break;
        }
    }
    canonical_lagged_epoch_anchor(dns_epoch, epoch_len, backoff, &ancestors)
}

/// ADR-0039 §11.3 (K5, clause-10 sampler) — collect one `(palw_epoch, palw_beacon_seed)` sample per
/// PALW DAA epoch (keyed `daa_score / palw_epoch_length_daa` — NOT per DNS anchor: consecutive DNS
/// anchors inside one PALW epoch legitimately share a seed and must not read as a carry), walking the
/// selected-parent chain DOWN from the finality-buried clause-6 anchor (inclusive). Every sampled
/// header sits at or below the anchor, so its `palw_beacon_seed` is trustworthy by the same burial
/// argument as clause 6 (it was S2-authenticated as a chain block, then buried past the reorg horizon).
/// A pure function of the past over `(headers, reachability)` — no virtual/beacon-store read (the C5
/// hazard this K5 wiring exists to avoid).
///
/// FAIL-OPEN stops (return what was collected so far): a pre-v3 / pre-activation / default-zero-seed
/// header (the activation boundary carries no derivable seed — a zero seed must break the run, never
/// extend it), any header-read miss (pruned history), or `max_epochs` distinct epochs collected.
/// Returned ASCENDING by epoch, ready for [`palw_seed_carry_run`] / [`palw_lagged_activation_open`]
/// (both of which are themselves fail-open on `< 2` samples).
pub fn resolve_palw_buried_epoch_seeds(
    headers: &DbHeadersStore,
    reachability: &MTReachabilityService<DbReachabilityStore>,
    anchor_hash: kaspa_consensus_core::BlockHash,
    palw_activation_daa_score: u64,
    palw_epoch_length_daa: u64,
    max_epochs: u64,
) -> Vec<(u64, kaspa_hashes::Hash64)> {
    use kaspa_consensus_core::constants::PALW_HEADER_VERSION;
    let epoch_len = palw_epoch_length_daa.max(1);
    let mut samples: Vec<(u64, kaspa_hashes::Hash64)> = Vec::new();
    for hash in std::iter::once(anchor_hash).chain(reachability.default_backward_chain_iterator(anchor_hash)) {
        let Ok(header) = headers.get_header(hash) else { break }; // pruned history ⇒ fail-open stop
        if header.version < PALW_HEADER_VERSION
            || header.daa_score < palw_activation_daa_score
            || header.palw_beacon_seed == kaspa_hashes::Hash64::default()
        {
            break; // activation boundary / underivable seed ⇒ fail-open stop
        }
        let epoch = header.daa_score / epoch_len;
        // Walking DOWN, the first header seen for an epoch is the NEWEST buried header of that epoch
        // (every header within one epoch carries the same seed — the derivation advances only at epoch
        // boundaries — so any representative is equivalent; we key on first-seen).
        if samples.last().is_none_or(|&(e, _)| e != epoch) {
            if samples.len() as u64 >= max_epochs {
                break;
            }
            samples.push((epoch, header.palw_beacon_seed));
        }
    }
    samples.reverse(); // collected newest→oldest; return ascending
    samples
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::palw::{
        PALW_LEAF_CHUNK_VERSION_V2, PalwAuditorVoteV1, PalwLeafMembershipProofV1, PalwPublicLeafV1, palw_leaf_merkle_proof,
        palw_leaf_merkle_root,
    };
    use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec, TransactionOutpoint};
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::{CachePolicy, ConnBuilder};
    use kaspa_hashes::Hash64;

    use crate::model::stores::palw::{DbPalwStore, PalwStoreReader};

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    /// kaspa-pq **ADR-0040 P1-5/P1-9 — recurrence guard.**
    ///
    /// The withdrawn rule was a first-claim-wins registry keyed on `job_nullifier`, operated by the
    /// body/mergeset fold on a struct cloned and re-persisted every block. It is removed, and removal is
    /// the whole remediation — so the thing to guard is not a value but the RE-APPEARANCE of the
    /// mechanism. `job_nullifier` remains a legitimate FIELD of `PalwPublicLeafV1` and
    /// `ReplicaExecutionReceiptV1` (the reward-coordinate re-land needs it); what must not come back at
    /// this coordinate is the plural registry and its two accessors.
    ///
    /// If you are here because this test failed: re-read ADR-0040 "P1-9 WITHDRAWN FROM THE BODY
    /// COORDINATE" before deleting it. A capped registry is not a fix — the cap bounds the bytes and
    /// leaves the batch-bricking censorship lever.
    #[test]
    fn no_job_nullifier_registry_at_the_body_coordinate() {
        for (name, src) in [
            ("consensus/core/src/palw.rs", include_str!("../../core/src/palw.rs")),
            ("consensus/src/pipeline/body_processor/processor.rs", include_str!("../pipeline/body_processor/processor.rs")),
            ("consensus/src/processes/palw.rs", include_str!("palw.rs")),
        ] {
            for (line_no, line) in src.lines().enumerate() {
                // Doc comments and the ADR-referencing prose are where the withdrawal is EXPLAINED, so
                // they are allowed to name it; code is not.
                let code = line.trim_start();
                if code.starts_with("//") || code.starts_with("///") {
                    continue;
                }
                // Assembled at runtime so this test's own source does not match itself.
                let jn = ["job", "_nullifier"].concat();
                for banned in [format!("{jn}s"), format!("claim_{jn}"), format!("{jn}_spent")] {
                    let banned = banned.as_str();
                    assert!(
                        !code.contains(banned),
                        "{name}:{}: `{banned}` is back. The body/mergeset coordinate cannot authenticate a \
                         job nullifier (no ActiveBondView, no signature verification), so it must not \
                         operate a first-claim-wins registry keyed on one, at any size. See ADR-0040.",
                        line_no + 1
                    );
                }
            }
        }
    }

    /// The fixture batch is two leaves, at indices 0 and 1.
    const FIXTURE_LEAF_COUNT: u32 = 2;

    /// kaspa-pq ADR-0040 §5.14.3 item 7 — the ONE registration epoch the fixture batch is built at.
    /// `leaf_raw`'s `registered_epoch` and `manifest()`'s `registration_epoch` both read it, because the
    /// acceptance arm now requires them to be equal. Two constants here would let the fixture drift back
    /// into the state the rule forbids without any test noticing.
    const FIXTURE_REGISTRATION_EPOCH: u64 = 1;

    /// kaspa-pq ADR-0040 §5.15 — the fixture batch's ORDERED, `batch_id`-ZEROED leaf hashes: exactly the
    /// sequence [`palw_leaf_merkle_root`] reduces to `manifest.leaf_root` and [`palw_leaf_merkle_proof`]
    /// opens.
    ///
    /// The projection is why there is no fixed point to solve here: `leaf_root` feeds `content_id()`
    /// which IS `batch_id`, so the tree must not depend on `batch_id` — and it does not.
    fn fixture_leaf_hashes() -> Vec<Hash64> {
        (0..FIXTURE_LEAF_COUNT)
            .map(|i| {
                let mut projected = leaf_raw(i);
                projected.batch_id = Hash64::default();
                projected.leaf_hash()
            })
            .collect()
    }

    /// A v2 leaf chunk carrying DERIVED membership proofs for `leaves`.
    ///
    /// §5.15.9's audit note: a previous "end-to-end" test passed only because it handed consensus
    /// literals where consensus requires derived values. Fixtures here therefore go through the same
    /// `palw_leaf_merkle_proof` a producer uses — a proof is never pasted.
    fn chunk_with_proofs(batch_id: Hash64, leaves: Vec<PalwPublicLeafV1>) -> PalwLeafChunkV1 {
        let hashes = fixture_leaf_hashes();
        let proofs =
            leaves.iter().map(|l| palw_leaf_merkle_proof(&hashes, l.leaf_index).expect("fixture index is in range")).collect();
        PalwLeafChunkV1 { version: PALW_LEAF_CHUNK_VERSION_V2, batch_id, chunk_index: 0, leaves, proofs }
    }

    fn manifest() -> PalwBatchManifestV1 {
        manifest_at_epoch(FIXTURE_REGISTRATION_EPOCH)
    }

    /// `registration_epoch` is the only knob varied, so a second batch differs in `content_id()` (hence
    /// `batch_id`) while keeping the SAME leaf set — and therefore the same `leaf_root` and the same
    /// membership proofs.
    ///
    /// kaspa-pq ADR-0040 §5.14.3 item 7: `leaf_root` is deliberately still built over
    /// `fixture_leaf_hashes()`, i.e. over leaves stamped `FIXTURE_REGISTRATION_EPOCH`. So any argument
    /// other than `FIXTURE_REGISTRATION_EPOCH` yields a manifest whose membership proofs VERIFY while its
    /// `registration_epoch` disagrees with the leaves — precisely the fixture the epoch-pin test needs,
    /// and the reason that test cannot be satisfied by a broken proof.
    fn manifest_at_epoch(registration_epoch: u64) -> PalwBatchManifestV1 {
        let mut m = PalwBatchManifestV1 {
            version: 1,
            batch_id: h(1),
            registration_epoch,
            model_profile_id: h(2),
            runtime_class_id: h(3),
            leaf_count: FIXTURE_LEAF_COUNT,
            chunk_count: 1,
            // kaspa-pq ADR-0040 §5.15 — DERIVED, not a literal. This used to be `h(4)`, which is exactly
            // the structural blind spot §5.15.10 warns about: a literal root cannot move when the
            // construction moves, so a fixture carrying one silently stops modelling anything the
            // acceptance gate checks.
            leaf_root: palw_leaf_merkle_root(&fixture_leaf_hashes()),
            descriptor_root: h(5),
            total_leaf_bond_sompi: 0,
            audit_policy_id: h(6),
            activation_not_before_epoch: 7,
            expiry_epoch: 13,
        };
        // Content-address it so `apply_palw_overlay_effect`'s manifest arm accepts it (§9.2 guard).
        m.batch_id = m.content_id();
        m
    }

    fn leaf(idx: u32) -> PalwPublicLeafV1 {
        leaf_in(h(1), idx)
    }

    /// ADR-0040 P1-1: a leaf's own `batch_id` must equal the chunk's, so fixtures must build the leaf for
    /// the batch they are inserted under rather than a hardcoded one.
    fn leaf_in(batch_id: Hash64, idx: u32) -> PalwPublicLeafV1 {
        PalwPublicLeafV1 { batch_id, ..leaf_raw(idx) }
    }

    fn leaf_raw(idx: u32) -> PalwPublicLeafV1 {
        let spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&[1]));
        PalwPublicLeafV1 {
            version: 1,
            batch_id: h(1),
            leaf_index: idx,
            job_nullifier: h(2),
            // I-13: the leaf stores the commitment of the raw nullifier `h(3)`.
            ticket_nullifier_commitment: kaspa_consensus_core::palw::ticket_nullifier_commitment(&h(3)),
            model_profile_id: h(4),
            runtime_class_id: h(5),
            shape_id: 3,
            quantum_count: 2,
            proof_type: 1,
            provider_a_bond: TransactionOutpoint::new(h(6), 0),
            provider_b_bond: TransactionOutpoint::new(h(7), 0),
            provider_a_reward_script: spk.clone(),
            provider_b_reward_script: spk,
            ticket_authority_pk_hash: h(8),
            private_match_commitment: h(9),
            receipt_da_root: h(10),
            // kaspa-pq ADR-0040 §5.14.3 item 7 — MUST equal the fixture manifest's `registration_epoch`,
            // which is why both read the same constant. This was `5` against a manifest registered at `1`;
            // the acceptance arm never compared them, so the fixture itself modelled the hole.
            registered_epoch: FIXTURE_REGISTRATION_EPOCH,
            activation_epoch: 7,
            expiry_epoch: 13,
            leaf_bond_sompi: 0,
        }
    }

    /// The payload of each kind round-trips borsh and parses to the right effect; a wrong subnet byte or
    /// garbage payload errors instead of panicking.
    #[test]
    fn parse_palw_overlay_kinds() {
        let m = manifest();
        let bytes = borsh::to_vec(&m).unwrap();
        assert!(matches!(parse_palw_overlay(0x31, &bytes), Ok(PalwOverlayEffect::Manifest(_))));
        let chunk = chunk_with_proofs(h(1), vec![leaf(0), leaf(1)]);
        assert!(matches!(parse_palw_overlay(0x32, &borsh::to_vec(&chunk).unwrap()), Ok(PalwOverlayEffect::LeafChunk(_))));
        // unhandled subnet byte + malformed payload.
        assert_eq!(parse_palw_overlay(0x34, &bytes).unwrap_err(), PalwOverlayError::UnhandledSubnet(0x34));
        assert_eq!(parse_palw_overlay(0x31, &[0xff, 0x00]).unwrap_err(), PalwOverlayError::MalformedPayload);
    }

    /// §9.5 (post-C5): the overlay-effect apply persists only the CONTENT-ADDRESSED blobs (manifest /
    /// leaves / certificate) — NO mutable global batch_status (that lifecycle is the block-keyed view's
    /// job). A manifest whose batch_id is not its own content id is rejected; a well-formed one is
    /// idempotently persisted (write-once content address).
    #[test]
    fn apply_overlay_persists_content_only() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));
        let m = manifest();
        let bid = m.batch_id; // content-derived

        // content-addressed manifest ⇒ persisted; NO batch_status row is written.
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m.clone()), &store, &beacon, None).unwrap();
        assert_eq!(store.batch_manifest(bid).unwrap().leaf_count, 2);
        assert!(store.batch_status(bid).is_err(), "no mutable batch_status is written on the global store");
        // re-applying the same content is idempotent (write-once content address).
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m.clone()), &store, &beacon, None).unwrap();

        // a forged batch_id (not the content id) is rejected — the store cannot be polluted.
        let forged = PalwBatchManifestV1 { batch_id: h(0xff), ..m };
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::Manifest(forged), &store, &beacon, None),
            Err(PalwOverlayError::NonContentAddressedBatchId)
        );

        // leaf chunk ⇒ leaves persisted under (batch_id, leaf_index).
        let chunk = chunk_with_proofs(bid, vec![leaf_in(bid, 0), leaf_in(bid, 1)]);
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(chunk), &store, &beacon, None).unwrap();
        assert!(store.has_leaf(bid, 0).unwrap() && store.has_leaf(bid, 1).unwrap());

        // certificate ⇒ persisted by its own hash (self-content-addressed); no batch_status effect.
        // ADR-0040 P1-4: it must also BIND to the batch it names — `manifest_hash` is the manifest's
        // content id and `leaf_root` is the manifest's, so the fixture carries the real values (it used
        // to carry unrelated hashes, which the binding guard now correctly rejects).
        let cert = PalwBatchCertificateV1 {
            version: 1,
            batch_id: bid,
            manifest_hash: bid, // == manifest.content_id() for a content-addressed manifest
            // ADR-0040 §5.15: DERIVED. The certificate arm cross-binds `cert.leaf_root ==
            // manifest.leaf_root`, so a literal here would have to be re-pasted every time the Merkle
            // construction moves — the "substitution instead of derivation" defect §5.15.9 calls out.
            leaf_root: manifest().leaf_root,
            audit_beacon_epoch: 5,
            audit_sample_root: h(4),
            passed_leaf_count: 2,
            rejected_leaf_bitmap_root: h(5),
            certificate_epoch: 6,
            activation_epoch: 7,
            expiry_epoch: 13,
            auditor_set_commitment: h(7),
            approving_stake: 0,
            votes: vec![PalwAuditorVoteV1 {
                bond_outpoint: TransactionOutpoint::new(h(8), 0),
                vote: 1,
                checked_leaf_bitmap_root: h(6),
                signature: vec![],
            }],
        };
        let cert_hash = cert.hash();
        apply_palw_overlay_effect(PalwOverlayEffect::Certificate(cert), &store, &beacon, None).unwrap();
        assert_eq!(store.certificate(cert_hash).unwrap().passed_leaf_count, 2);
    }

    /// kaspa-pq **ADR-0040 P1-1 / gate G3** — BIND-01 + LEAF-01 closure.
    ///
    /// Two properties, both load-bearing for the lane's proof-of-work:
    ///
    /// * **A leaf cannot be injected into a batch it does not belong to.** algo-4 headers are exempt from
    ///   the Layer-0 hash floor, so the lane's entire PoW is the clause-9 draw over
    ///   `eligibility_hash(.., leaf_hash, nullifier)`. If an attacker could author and inject leaves, both
    ///   miner-variable inputs to that draw would be attacker-chosen — i.e. the draw becomes an offline
    ///   grind. The manifest is the only content-addressed anchor, so membership is checked against it.
    /// * **A written leaf is immutable.** `palw_work_reward_class` re-reads the CURRENT leaf at coinbase
    ///   time for `provider_{a,b}_reward_script`, so a post-acceptance overwrite re-routes the 77 % worker
    ///   base. Identical content stays idempotent so reorg replay is still legal.
    #[test]
    fn leaf_chunk_admission_binds_to_manifest_and_is_write_once() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));
        let m = manifest();
        let bid = m.batch_id; // content-derived
        let leaf_count = m.leaf_count;
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m), &store, &beacon, None).unwrap();

        // NOTE (ADR-0040 §5.15.12): every adversarial fixture below now carries a REAL, derived
        // membership proof, so each still fails for its ORIGINAL reason rather than being caught by the
        // new gate on its way in. That is the whole point of rebuilding them instead of letting the
        // M2 gate quietly absorb the older assertions' coverage.

        // ---- (1) a chunk for a batch with NO admitted manifest is rejected outright ----
        let unknown = h(0xde);
        let orphan = chunk_with_proofs(unknown, vec![leaf_in(unknown, 0)]);
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(orphan), &store, &beacon, None),
            Err(PalwOverlayError::UnknownBatch),
            "a leaf must never be the effect that first materialises a batch key"
        );
        assert!(!store.has_leaf(unknown, 0).unwrap(), "nothing may be persisted for an unknown batch");

        // ---- (2) a leaf claiming a different batch than its chunk is rejected ----
        // The proof is valid (the Merkle projection zeroes `batch_id`, so this leaf's CONTENT is a
        // genuine member), which is what makes this assertion still about the batch-id cross-check.
        let smuggled = chunk_with_proofs(bid, vec![leaf_in(h(0xaa), 0)]);
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(smuggled), &store, &beacon, None),
            Err(PalwOverlayError::LeafBatchIdMismatch)
        );

        // ---- (3) an index outside the manifest's leaf_count can never be part of leaf_root ----
        // No proof can exist for an out-of-range index, so this fixture carries a length-correct
        // placeholder; the index bound fires first, which is the ordering being asserted.
        let oob = PalwLeafChunkV1 {
            version: PALW_LEAF_CHUNK_VERSION_V2,
            batch_id: bid,
            chunk_index: 0,
            leaves: vec![leaf_in(bid, leaf_count)],
            proofs: vec![PalwLeafMembershipProofV1 { siblings: vec![h(0)] }],
        };
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(oob), &store, &beacon, None),
            Err(PalwOverlayError::LeafIndexOutOfRange { leaf_index: leaf_count, leaf_count })
        );

        // ---- (4) the honest chunk lands ----
        let good = chunk_with_proofs(bid, vec![leaf_in(bid, 0), leaf_in(bid, 1)]);
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(good.clone()), &store, &beacon, None).unwrap();
        let sealed = store.leaf(bid, 0).unwrap().leaf_hash();

        // ---- (5) re-applying IDENTICAL content is idempotent (reorg replay must stay legal) ----
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(good), &store, &beacon, None).unwrap();
        assert_eq!(store.leaf(bid, 0).unwrap().leaf_hash(), sealed);

        // ---- (6) a thief's leaf is now refused by the MEMBERSHIP GATE, before the store is touched ----
        //
        // ADR-0040 §5.15: this used to be caught by `insert_leaf`'s write-once check — i.e. only because
        // the honest leaf happened to already occupy the slot, which is precisely the race the squatter
        // wins by going first. The gate now refuses it on CONTENT, so the ordering no longer matters.
        // The write-once assertion has NOT been deleted: it moved to
        // `leaf_write_once_still_fires_after_the_membership_gate`, which reaches `insert_leaf` with a
        // valid proof.
        let mut thief = leaf_in(bid, 0);
        thief.provider_a_reward_script = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0xbe, 0xef]));
        assert_ne!(thief.leaf_hash(), sealed, "the fixture must actually differ, else the test proves nothing");
        let overwrite = chunk_with_proofs(bid, vec![thief]);
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(overwrite), &store, &beacon, None),
            Err(PalwOverlayError::LeafMembershipProofInvalid { leaf_index: 0 })
        );
        assert_eq!(store.leaf(bid, 0).unwrap().leaf_hash(), sealed, "the originally admitted leaf must survive");
    }

    /// kaspa-pq **ADR-0040 §5.15 (ACCEPT-BIND/M2) — the CHUNK-INDEX SQUAT itself, rejected.**
    ///
    /// This is the attack the gate exists for, stated in its own terms and WITHOUT the honest leaf
    /// having been stored first — because the squatter's entire advantage was going first.
    ///
    /// `batch_id` is public. Before M2, an observer could copy one, author leaves paying ITS OWN
    /// `provider_{a,b}_reward_script` and naming its own `ticket_authority_pk_hash`, and write them at
    /// `(batch_id, leaf_index)` before the honest provider's transaction landed. The honest auditors'
    /// certificate then covered the squatter's leaves — consensus never re-derived `leaf_root` from what
    /// it had stored — and `palw_work_reward_class` reads the reward scripts straight off the stored
    /// leaf, so the squatter collected the 77 % worker base.
    ///
    /// The assertion is made on the STORE, not merely on the return value: `apply_palw_overlay_effect`'s
    /// result is discarded by its production caller (`let _ =`, virtual_processor/processor.rs:1800),
    /// so "returned an error" is not by itself evidence that nothing was written.
    #[test]
    fn chunk_index_squat_is_rejected_before_the_leaf_is_stored() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));
        let m = manifest();
        let bid = m.batch_id;
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m), &store, &beacon, None).unwrap();

        // The squatter copies the public batch_id and substitutes its own payout + ticket authority.
        let mut squat = leaf_in(bid, 0);
        let squat_a = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x51, 0x51]));
        let squat_b = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x52, 0x52]));
        squat.provider_a_reward_script = squat_a.clone();
        squat.provider_b_reward_script = squat_b.clone();
        squat.ticket_authority_pk_hash = h(0xaa);
        // It builds a well-formed chunk: right batch, right index, right proof LENGTH. The one thing it
        // cannot produce is a proof that opens the honest `leaf_root` to its own content.
        let chunk = chunk_with_proofs(bid, vec![squat]);
        assert_eq!(
            chunk.proofs[0].len() as u32,
            palw_leaf_merkle_depth(FIXTURE_LEAF_COUNT),
            "the fixture must fail on CONTENT, not length"
        );

        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(chunk), &store, &beacon, None),
            Err(PalwOverlayError::LeafMembershipProofInvalid { leaf_index: 0 })
        );
        assert!(
            !store.has_leaf(bid, 0).unwrap(),
            "the squatter's leaf must not be in the store — the slot stays free for the honest one"
        );

        // And the honest provider, arriving SECOND, still succeeds. Under the old code it would have hit
        // `LeafImmutabilityViolation` against the squatter's leaf and the batch would be dead.
        let honest = chunk_with_proofs(bid, vec![leaf_in(bid, 0), leaf_in(bid, 1)]);
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(honest.clone()), &store, &beacon, None).unwrap();

        // ---- paired with the REWARD PATH (§5.15.12) ----
        //
        // `palw_work_reward_class` (virtual_processor/utxo_validation.rs) builds
        // `WorkRewardClass::ReplicaPalw` by re-reading `palw_store.leaf(header.palw_batch_id,
        // header.palw_leaf_index)` at coinbase time and cloning `provider_{a,b}_reward_script` off it.
        // So the reward-relevant statement of "the squat failed" is exactly this: THAT read, at THAT key,
        // still yields the honest provider pair — all three fields the squatter substituted.
        //
        // Scope, stated rather than implied: this asserts the store half of the chain. The store →
        // coinbase-output half is asserted by the algo-4 reward-rail E2Es in
        // virtual_processor/tests.rs. No single test spans both, because that harness seeds its leaf
        // directly (its `registered_epoch == activation_epoch == 0` leaf cannot pass
        // `validate_public_leaf`, so it can never traverse the acceptance arm).
        let stored = store.leaf(bid, 0).unwrap();
        let honest_leaf = leaf_in(bid, 0);
        assert_eq!(stored.provider_a_reward_script, honest_leaf.provider_a_reward_script, "the 77% worker base must stay with A");
        assert_eq!(stored.provider_b_reward_script, honest_leaf.provider_b_reward_script, "…and with B");
        assert_ne!(stored.provider_a_reward_script, squat_a, "the squatter's payout must not be what the coinbase reads");
        assert_ne!(stored.provider_b_reward_script, squat_b, "the squatter's payout must not be what the coinbase reads");
        assert_eq!(stored.ticket_authority_pk_hash, honest_leaf.ticket_authority_pk_hash, "nor its ticket authority");

        // IDEMPOTENT REPLAY (§5.15.12): the honest chunk re-sent — reorg replay, or an attacker paying
        // to publish the victim's own bytes — still succeeds. This is what makes the DENIAL half of the
        // closure true rather than merely argued.
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(honest), &store, &beacon, None).unwrap();
        assert!(store.has_leaf(bid, 0).unwrap() && store.has_leaf(bid, 1).unwrap());
    }

    /// A leaf whose every field is a function of `index` — no miner, no mock runtime, nothing that is
    /// free to move for unrelated reasons. `batch_id` starts zeroed; `restamp_leaves` sets the real one.
    ///
    /// `provider_{a,b}_reward_script` must be the exact 69-byte P2PKH ML-DSA-87 template, because
    /// `validate_public_leaf` (ADR-0040 P0-4 / ECON-01) requires a coinbase-representable script and the
    /// round trip below runs the REAL `validate_palw_overlay_payload` on the producer's bytes.
    fn e2e_leaf(index: u32) -> PalwPublicLeafV1 {
        // Distinct per index, in a way that cannot collide across a 65-leaf batch (a `[b; 64]`-style
        // fixture wraps at 256 and would silently produce duplicate nullifier commitments).
        let hx = |tag: u8, seed: u32| {
            let mut b = [0u8; 64];
            b[0] = tag;
            b[1..5].copy_from_slice(&seed.to_le_bytes());
            Hash64::from_bytes(b)
        };
        let spk = kaspa_consensus_core::dns_finality::p2pkh_mldsa87_spk(&[0xa0; 64]);
        PalwPublicLeafV1 {
            version: 1,
            batch_id: Hash64::default(),
            leaf_index: index,
            job_nullifier: hx(0x10, index),
            ticket_nullifier_commitment: kaspa_consensus_core::palw::ticket_nullifier_commitment(&hx(0x11, index)),
            model_profile_id: h(2),
            runtime_class_id: h(3),
            shape_id: 1,
            quantum_count: 1,
            proof_type: 1,
            // `validate_public_leaf` rejects `provider_a_bond == provider_b_bond`.
            provider_a_bond: TransactionOutpoint::new(hx(0x12, index), 0),
            provider_b_bond: TransactionOutpoint::new(hx(0x13, index), 1),
            provider_a_reward_script: spk.clone(),
            provider_b_reward_script: spk,
            ticket_authority_pk_hash: h(8),
            private_match_commitment: Hash64::default(),
            receipt_da_root: Hash64::default(),
            registered_epoch: 1,
            activation_epoch: 4,
            expiry_epoch: 1000,
            leaf_bond_sompi: 0,
        }
    }

    /// kaspa-pq **ADR-0040 §5.15.12 — THE E2E ROUND TRIP.** The one named test the ACCEPT-BIND slice
    /// did not land.
    ///
    /// A batch assembled by the REAL miner producers (`misaka_palw_miner::registration::
    /// build_batch_manifest` + `build_leaf_chunk`) is driven through the REAL context-free validator
    /// (`validate_palw_overlay_payload`), the REAL parser (`parse_palw_overlay`) and the REAL acceptance
    /// arm (`apply_palw_overlay_effect`), and every leaf must end up in the store.
    ///
    /// **This is a true cross-crate call, not a pair of pinned goldens.** `misaka-palw-miner` is a
    /// dev-dependency of this crate (acyclic — its closure does not contain `kaspa-consensus`), so both
    /// implementations execute here. The miner-side test
    /// `every_emitted_proof_opens_the_manifest_leaf_root_under_the_consensus_verifier` calls the verify
    /// FUNCTION; this one calls the acceptance ARM, which is where the length bound, the index bound,
    /// the batch-id cross-check, the version check and `insert_leaf` also live. Neither subsumes the
    /// other: a drift that only the arm's ordering exposes would pass over there.
    ///
    /// §5.15.12 requires two properties of the fixture, both asserted below rather than left to a
    /// comment:
    ///  * **multi-chunk** (`leaf_count > PALW_MAX_LEAVES_PER_CHUNK`), so the second chunk's proofs —
    ///    whose sibling paths share no prefix with the first chunk's — are exercised through the arm;
    ///  * **non-power-of-two `leaf_count`**, so the uniform `H_EMPTY` padding is what the honest proofs
    ///    fold through end to end. 65 satisfies both at the cheapest depth (7) that can.
    #[test]
    fn producer_built_batch_round_trips_through_the_real_acceptance_arm() {
        use kaspa_consensus_core::palw::{PALW_MAX_LEAVES_PER_CHUNK, validate_palw_overlay_payload};
        use misaka_palw_miner::registration::{BatchPolicy, build_batch_manifest, build_leaf_chunk, restamp_leaves};

        const LEAF_COUNT: u32 = 65;
        // Stated as assertions on the CONSTANT, so shrinking the fixture to "make the test faster"
        // cannot quietly retire the two cases §5.15.12 names.
        assert!(LEAF_COUNT as usize > PALW_MAX_LEAVES_PER_CHUNK, "the fixture must be multi-chunk");
        assert!(!LEAF_COUNT.is_power_of_two(), "the fixture must exercise the uniform H_EMPTY padding");

        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(256));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));

        let policy = BatchPolicy {
            registration_epoch: 1,
            registration_lead_epochs: 2,
            audit_window_epochs: 1,
            active_window_epochs: 100,
            min_leaf_bond_sompi: 0,
            max_batch_leaves: kaspa_consensus_core::palw::PALW_MAX_BATCH_LEAVES_V1 as u32,
        };
        let minted: Vec<PalwPublicLeafV1> = (0..LEAF_COUNT).map(e2e_leaf).collect();

        // ---- (1) the producer's MANIFEST, through validate → parse → apply ----
        let (batch_id, (mbyte, mpayload)) =
            build_batch_manifest(&minted, h(2), h(3), h(4), h(5), 0, &policy).expect("the fixture is a valid batch");
        assert_eq!(validate_palw_overlay_payload(mbyte, &mpayload), Ok(()), "the producer's manifest must pass isolation");
        let manifest = match parse_palw_overlay(mbyte, &mpayload).expect("manifest parses") {
            PalwOverlayEffect::Manifest(m) => m,
            other => panic!("expected a Manifest effect, got {other:?}"),
        };
        // FIXED-POINT, positive half (§5.15.12): the producer's manifest is content-addressed UNDER the
        // Merkle `leaf_root` — i.e. `leaf_root → content_id() → batch_id` closes, which it only can
        // because the tree is built over the `batch_id`-ZEROED projection.
        assert!(manifest.batch_id_is_content_derived(), "leaf_root sits inside content_id, so batch_id must move with it");
        assert_eq!(manifest.leaf_count, LEAF_COUNT);
        assert_eq!(manifest.chunk_count, 2, "65 leaves is two chunks");
        assert_eq!(palw_leaf_merkle_depth(manifest.leaf_count), 7, "65 leaves pads to 128 — depth 7");
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(manifest.clone()), &store, &beacon, None).unwrap();

        // ---- (2) every CHUNK, through validate → parse → apply ----
        let restamped = restamp_leaves(batch_id, &minted);
        let mut chunk_payloads = Vec::new();
        for chunk_index in 0..manifest.chunk_count {
            let (cbyte, cpayload) = build_leaf_chunk(batch_id, chunk_index, &restamped).expect("chunk assembles");
            assert_eq!(validate_palw_overlay_payload(cbyte, &cpayload), Ok(()), "chunk {chunk_index} must pass isolation");
            let chunk = match parse_palw_overlay(cbyte, &cpayload).expect("chunk parses") {
                PalwOverlayEffect::LeafChunk(c) => c,
                other => panic!("expected a LeafChunk effect, got {other:?}"),
            };
            assert_eq!(
                apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(chunk), &store, &beacon, None),
                Ok(()),
                "chunk {chunk_index} built by the real producer was REJECTED by the real acceptance arm — \
                 miner/consensus drift in the leaf-Merkle construction (on-chain this is silent: the arm's \
                 error is discarded by `let _ =` in virtual_processor)"
            );
            chunk_payloads.push((cbyte, cpayload));
        }

        // ---- (3) EVERY leaf is stored, byte-identical to what the producer minted ----
        for leaf in &restamped {
            assert!(store.has_leaf(batch_id, leaf.leaf_index).unwrap(), "leaf {} was not stored", leaf.leaf_index);
            assert_eq!(
                store.leaf(batch_id, leaf.leaf_index).unwrap().leaf_hash(),
                leaf.leaf_hash(),
                "leaf {} was stored with different content than the producer minted",
                leaf.leaf_index
            );
        }

        // ---- (4) IDEMPOTENT REPLAY over the whole multi-chunk batch (§5.15.12) ----
        // The single-leaf case is covered by `chunk_index_squat_is_rejected_before_the_leaf_is_stored`;
        // this states it for a batch whose chunks were already fully applied, which is the shape a reorg
        // actually replays.
        for (cbyte, cpayload) in &chunk_payloads {
            let chunk = parse_palw_overlay(*cbyte, cpayload).expect("chunk re-parses");
            assert_eq!(
                apply_palw_overlay_effect(chunk, &store, &beacon, None),
                Ok(()),
                "an identical honest chunk must remain admissible — this is what makes the DENIAL half of \
                 the CHUNK-INDEX SQUAT closure true rather than merely argued"
            );
        }
        assert_eq!(store.leaf(batch_id, LEAF_COUNT - 1).unwrap().leaf_hash(), restamped[LEAF_COUNT as usize - 1].leaf_hash());

        // ---- (5) FIXED-POINT, NEGATIVE half (§5.15.12) ----
        //
        // The tree is opened by the `batch_id`-ZEROED projection of a leaf. The NON-projected
        // `leaf_hash()` — the one `resolve_palw_binding` deliberately uses for the eligibility draw — must
        // NOT verify. Asserted so that a future "these two leaf hashes are the same leaf, let's
        // de-duplicate them" cleanup fails LOUDLY here instead of either bricking every honest chunk (if
        // the arm switched to the populated hash) or re-opening the fixed point (if the resolver switched
        // to the projected one).
        let hashes: Vec<Hash64> = restamped
            .iter()
            .map(|l| {
                let mut p = l.clone();
                p.batch_id = Hash64::default();
                p.leaf_hash()
            })
            .collect();
        let subject = &restamped[0];
        let proof = palw_leaf_merkle_proof(&hashes, 0).expect("index 0 is in range");
        assert!(
            palw_verify_leaf_membership(&hashes[0], 0, LEAF_COUNT, &proof, &manifest.leaf_root),
            "the projected hash is the one that opens leaf_root"
        );
        assert_ne!(subject.leaf_hash(), hashes[0], "the projection must actually change the digest");
        assert!(
            !palw_verify_leaf_membership(&subject.leaf_hash(), 0, LEAF_COUNT, &proof, &manifest.leaf_root),
            "the batch_id-POPULATED leaf hash must NOT open leaf_root — see the FIXED-POINT notes on this \
             arm and on `resolve_palw_binding`; the two digests of one leaf are intentional"
        );
    }

    /// kaspa-pq **ADR-0040 §5.15** — the EXACT proof-length bound, rejected in both directions and
    /// BEFORE any hashing.
    ///
    /// The context-free `validate_leaf_chunk` can only assert the static `<= 8` bound, having no
    /// manifest to read `leaf_count` from; the exact bound is what makes the proof for a given
    /// `(leaf, index, root)` unique, so it must live here, where the manifest is already loaded. A
    /// distinct error variant is what lets this test state "rejected on LENGTH" — with a single
    /// catch-all variant, a too-long proof that happened to fold to the right root would be
    /// indistinguishable from one that did not.
    #[test]
    fn membership_proof_length_is_exact_in_both_directions() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));
        let m = manifest();
        let bid = m.batch_id;
        let expected = palw_leaf_merkle_depth(m.leaf_count);
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m), &store, &beacon, None).unwrap();

        let honest = chunk_with_proofs(bid, vec![leaf_in(bid, 0)]);
        for siblings in [Vec::new(), vec![honest.proofs[0].siblings[0], h(7)]] {
            let got = siblings.len();
            let mut bad = honest.clone();
            bad.proofs = vec![PalwLeafMembershipProofV1 { siblings }];
            assert_eq!(
                apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(bad), &store, &beacon, None),
                Err(PalwOverlayError::LeafMembershipProofLengthInvalid { leaf_index: 0, got, expected }),
                "a proof of length {got} (expected {expected}) must be refused on length alone"
            );
            assert!(!store.has_leaf(bid, 0).unwrap());
        }

        // A chunk with FEWER proofs than leaves cannot index-panic in consensus: `parse_palw_overlay` is
        // a bare Borsh decode, so this arm never relies on `validate_leaf_chunk` having run.
        let mut starved = chunk_with_proofs(bid, vec![leaf_in(bid, 0), leaf_in(bid, 1)]);
        starved.proofs.pop();
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(starved), &store, &beacon, None),
            Err(PalwOverlayError::LeafProofCountMismatch { leaves: 2, proofs: 1 })
        );
    }

    /// kaspa-pq **ADR-0040 §5.15** — a member leaf's proof does not open it at ANOTHER index, and a
    /// non-member cannot borrow a member's slot.
    ///
    /// Two independent index bindings have to hold, and this states both:
    ///
    /// * **Cross-index proof reuse.** Leaf 0 is a genuine member, but presented with leaf 1's proof it
    ///   is refused, and vice versa. The direction bits come from the leaf's own `leaf_index`, never
    ///   from the payload, so the attacker has no free bits to grind a fold with.
    /// * **Relabelling.** A leaf whose content is NOT the batch's member at index 1, submitted at index
    ///   1 with index 1's genuine proof, is refused — the level-0 node is
    ///   `Hash64_k(leaf-merkle-leaf, leaf_index_le32 ‖ leaf_hash)`, so the index is bound inside the
    ///   node, on top of `PalwPublicLeafV1::leaf_hash` already committing `leaf_index` itself. The two
    ///   bindings are deliberately redundant; neither may be removed on the grounds that the other
    ///   exists.
    #[test]
    fn a_member_leaf_cannot_be_replayed_at_another_index() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));
        let m = manifest();
        let bid = m.batch_id;
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m), &store, &beacon, None).unwrap();

        let hashes = fixture_leaf_hashes();
        let chunk_with = |leaf: PalwPublicLeafV1, proof_for: u32| PalwLeafChunkV1 {
            version: PALW_LEAF_CHUNK_VERSION_V2,
            batch_id: bid,
            chunk_index: 0,
            leaves: vec![leaf],
            proofs: vec![palw_leaf_merkle_proof(&hashes, proof_for).unwrap()],
        };

        // ---- cross-index proof reuse: genuine member, wrong index's proof ----
        for (leaf_index, proof_for) in [(0u32, 1u32), (1, 0)] {
            assert_eq!(
                apply_palw_overlay_effect(
                    PalwOverlayEffect::LeafChunk(chunk_with(leaf_in(bid, leaf_index), proof_for)),
                    &store,
                    &beacon,
                    None
                ),
                Err(PalwOverlayError::LeafMembershipProofInvalid { leaf_index }),
                "leaf {leaf_index} must not open under leaf {proof_for}'s proof"
            );
        }

        // ---- relabelling: content that is not the member at index 1, submitted at index 1 ----
        let mut relabelled = leaf_in(bid, 1);
        relabelled.job_nullifier = h(0x77);
        assert_ne!(relabelled.leaf_hash(), leaf_in(bid, 1).leaf_hash(), "the fixture must actually differ");
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(chunk_with(relabelled, 1)), &store, &beacon, None),
            Err(PalwOverlayError::LeafMembershipProofInvalid { leaf_index: 1 })
        );

        assert!(!store.has_leaf(bid, 0).unwrap() && !store.has_leaf(bid, 1).unwrap(), "no rejected leaf may have been stored");
    }

    /// kaspa-pq **ADR-0040 §5.14.3 item 7 (P1-10 prerequisite)** — a leaf whose `registered_epoch` is not
    /// its manifest's `registration_epoch` is refused, *even though its membership proof verifies*.
    ///
    /// The fixture is what makes this test mean anything. `manifest_at_epoch` always builds `leaf_root`
    /// over `fixture_leaf_hashes()` — leaves stamped `FIXTURE_REGISTRATION_EPOCH` — so a manifest
    /// registered at `FIXTURE_REGISTRATION_EPOCH + 1` has genuinely-opening proofs for leaves that
    /// disagree with it. Delete the epoch check and this batch is accepted and STORED; that is asserted
    /// positively below by first confirming the same leaves round-trip under the matching manifest.
    ///
    /// Why the leaf cannot dodge this by restamping itself: `registered_epoch` is inside `leaf_hash`,
    /// `leaf_hash` opens `manifest.leaf_root` (§5.15/M2), and `leaf_root` is inside `content_id()` ==
    /// `batch_id`. Changing the leaf's epoch changes the batch it is a member of. So the author's only
    /// remaining move is to build the batch honestly at one epoch — which is the rule.
    ///
    /// What this does NOT claim: the acceptance arm does not know the real acceptance epoch. It binds the
    /// leaf to the manifest; `PalwBatchManifestV1::admission_valid` (reached via
    /// `PalwBatchViewV1::apply_manifest`, which `check_palw_ticket`'s `view.resolvable_batch` requires
    /// before any header may mine the batch) binds the manifest to the carrier epoch.
    #[test]
    fn a_leaf_must_carry_its_manifests_registration_epoch() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));

        // ---- the SAME leaf content, under a manifest whose registration epoch disagrees ----
        let skewed = manifest_at_epoch(FIXTURE_REGISTRATION_EPOCH + 1);
        let skewed_bid = skewed.batch_id;
        assert_eq!(
            skewed.leaf_root,
            manifest().leaf_root,
            "the two fixtures must share a leaf_root, or this test would be proving a membership failure"
        );
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(skewed), &store, &beacon, None).unwrap();

        let leaves = vec![leaf_in(skewed_bid, 0), leaf_in(skewed_bid, 1)];
        // The proofs are DERIVED from the same ordered hash sequence the root was reduced from, so they
        // verify. The rejection below is therefore attributable to the epoch alone.
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(chunk_with_proofs(skewed_bid, leaves)), &store, &beacon, None),
            Err(PalwOverlayError::LeafRegistrationEpochMismatch {
                leaf_index: 0,
                leaf_registered_epoch: FIXTURE_REGISTRATION_EPOCH,
                manifest_registration_epoch: FIXTURE_REGISTRATION_EPOCH + 1,
            }),
            "a leaf registered at a different epoch than its batch must not be stored"
        );
        assert!(!store.has_leaf(skewed_bid, 0).unwrap(), "a rejected leaf must not have been written");

        // ---- the control: identical leaves, matching manifest, accepted ----
        let m = manifest();
        let bid = m.batch_id;
        assert_ne!(bid, skewed_bid, "the two manifests must be distinct batches");
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m), &store, &beacon, None).unwrap();
        let ok = vec![leaf_in(bid, 0), leaf_in(bid, 1)];
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(chunk_with_proofs(bid, ok)), &store, &beacon, None)
            .expect("the epoch-matched batch must still be accepted — the rule must not reject honest chunks");
        assert!(store.has_leaf(bid, 0).unwrap() && store.has_leaf(bid, 1).unwrap());
    }

    /// kaspa-pq **ADR-0040 §5.15.12 (WRITE-ONCE coverage must not be hollowed out)** — `insert_leaf`'s
    /// write-once check is still REACHED and still fires.
    ///
    /// After M2 the membership gate makes `LeafImmutabilityViolation` nearly unreachable through this
    /// arm — that is the intended consequence (§5.15.8), not a regression — because any chunk that
    /// passes the gate is byte-identical to the honest one. So the honest way to keep the write-once
    /// property under test is to occupy the slot from OUTSIDE the arm and then drive a fully valid chunk
    /// through the gate into `insert_leaf`. That is exactly the defence-in-depth ordering being
    /// asserted: gate first, store second, and the store still refuses.
    #[test]
    fn leaf_write_once_still_fires_after_the_membership_gate() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));
        let m = manifest();
        let bid = m.batch_id;
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m), &store, &beacon, None).unwrap();

        // Occupy (bid, 0) with foreign content directly, bypassing the arm.
        let mut foreign = leaf_in(bid, 0);
        foreign.provider_a_reward_script = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0xbe, 0xef]));
        store.insert_leaf(bid, 0, Arc::new(foreign.clone())).unwrap();

        // The HONEST chunk now passes the membership gate and is refused by the store, not by the gate.
        let honest = chunk_with_proofs(bid, vec![leaf_in(bid, 0)]);
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(honest), &store, &beacon, None),
            Err(PalwOverlayError::LeafImmutabilityViolation),
            "the gate must precede insert_leaf, and insert_leaf must still be the thing that refuses here"
        );
        assert_eq!(store.leaf(bid, 0).unwrap().leaf_hash(), foreign.leaf_hash());
    }

    /// kaspa-pq **ADR-0040 P1-2 (LEAF-01)** — the reward basis is immutable after acceptance.
    ///
    /// The audit's remedy was "freeze the leaf hash / reward scripts as an immutable snapshot at
    /// accepted-block time". P1-1's write-once store achieves the same property without copying: the
    /// bytes at `(batch_id, leaf_index)` cannot change once written, so the reward path's re-read
    /// necessarily returns what body validation proved.
    ///
    /// This test states that as the reward-relevant property specifically — the earlier G3 test proves
    /// the store refuses the write, this one proves the REWARD SCRIPTS a coinbase would derive are the
    /// ones that survive.
    #[test]
    fn reward_scripts_are_immutable_after_acceptance() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));
        let m = manifest();
        let bid = m.batch_id;
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m), &store, &beacon, None).unwrap();

        let honest = leaf_in(bid, 0);
        let honest_a = honest.provider_a_reward_script.clone();
        let chunk = chunk_with_proofs(bid, vec![honest]);
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(chunk), &store, &beacon, None).unwrap();

        // The reward path reads the leaf by key at coinbase time. Attempt the theft: same key, different
        // payout. The re-read still yields the accepted scripts.
        //
        // ADR-0040 §5.15 — the REJECTING CHECK moved, the property did not. This used to be refused by
        // `insert_leaf` (write-once), i.e. only because the honest leaf was already there; it is now
        // refused by the M2 membership gate, on content, before the store is consulted at all. The
        // strictly stronger statement: the theft fails whether or not the thief goes first. Write-once
        // is still exercised, at `leaf_write_once_still_fires_after_the_membership_gate`.
        let mut thief = leaf_in(bid, 0);
        thief.provider_a_reward_script = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0xbe, 0xef]));
        let overwrite = chunk_with_proofs(bid, vec![thief.clone()]);
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(overwrite), &store, &beacon, None),
            Err(PalwOverlayError::LeafMembershipProofInvalid { leaf_index: 0 })
        );

        // ...and the ORIGINAL reason this fixture was rejected has NOT been retired, only outranked.
        // Asserted in place, because "the gate happens to fire first" is not the same claim as "the
        // store would still refuse": if a later slice ever loosens the gate, this line is what keeps
        // LEAF-01 from silently becoming unenforced. Driven straight at the store, since no chunk
        // carrying this content can reach `insert_leaf` through the arm any more — which is the point.
        //
        // §5.15.12 negative-fixture audit: `is_err()` was too loose to state the ORIGINAL reason — any
        // store fault would have satisfied it. The write-once property is specifically the ALREADY-EXISTS
        // refusal (`insert_leaf`'s content-address put-if-absent), which is also the exact predicate the
        // arm maps to `LeafImmutabilityViolation`.
        assert!(
            store.insert_leaf(bid, 0, Arc::new(thief)).is_err_and(|e| e.is_already_exists()),
            "write-once must independently refuse the same theft; the M2 gate outranks it, not replaces it"
        );

        assert_eq!(
            store.leaf(bid, 0).unwrap().provider_a_reward_script,
            honest_a,
            "the reward script a coinbase derives must be the one that was accepted"
        );
    }

    /// kaspa-pq **ADR-0040 P1-4 (BIND-02 / BIND-05)** — a certificate must bind to the batch it names.
    ///
    /// Downstream, `is_block_eligible_at` only asks whether `cert_hash.is_some()`, and
    /// `resolve_palw_binding` reads only the certificate's epoch window. So without this check, ANY
    /// certificate blob in the store could satisfy an algo-4 header for ANY batch — the certificate's
    /// `manifest_hash` / `leaf_root` were decoded and never compared to anything.
    ///
    /// Scope note: this closes the *identity* half of CERT-01. The *attestation* half (ML-DSA vote
    /// verification, auditor selection, stake-weighted quorum, `audit_sample_root` re-derivation) needs
    /// the bond state from P2-5/P2-7 and is deliberately still open — hence `palw_algo4_accept = false`.
    #[test]
    fn certificate_must_bind_to_its_batch_manifest_and_leaf_root() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));
        let m = manifest();
        let bid = m.batch_id;
        let real_leaf_root = m.leaf_root;
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m), &store, &beacon, None).unwrap();

        let base = PalwBatchCertificateV1 {
            version: 1,
            batch_id: bid,
            manifest_hash: bid,
            leaf_root: real_leaf_root,
            audit_beacon_epoch: 5,
            audit_sample_root: h(4),
            passed_leaf_count: 2,
            rejected_leaf_bitmap_root: h(5),
            certificate_epoch: 6,
            activation_epoch: 7,
            expiry_epoch: 13,
            auditor_set_commitment: h(7),
            approving_stake: 0,
            votes: vec![PalwAuditorVoteV1 {
                bond_outpoint: TransactionOutpoint::new(h(8), 0),
                vote: 1,
                checked_leaf_bitmap_root: h(6),
                signature: vec![],
            }],
        };

        // (1) a certificate for a batch with no admitted manifest cannot be persisted at all.
        let orphan = PalwBatchCertificateV1 { batch_id: h(0xde), ..base.clone() };
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::Certificate(orphan), &store, &beacon, None),
            Err(PalwOverlayError::UnknownBatch)
        );

        // (2) right batch, wrong manifest — it certifies a manifest that is not the one on chain.
        let wrong_manifest = PalwBatchCertificateV1 { manifest_hash: h(0xbb), ..base.clone() };
        let wrong_manifest_hash = wrong_manifest.hash();
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::Certificate(wrong_manifest), &store, &beacon, None),
            Err(PalwOverlayError::CertificateManifestMismatch)
        );
        assert!(store.certificate(wrong_manifest_hash).is_err(), "a mis-bound certificate must not be persisted");

        // (3) right batch and manifest, wrong leaf set — it attests to leaves that are not this batch's.
        let wrong_leaves = PalwBatchCertificateV1 { leaf_root: h(0xcc), ..base.clone() };
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::Certificate(wrong_leaves), &store, &beacon, None),
            Err(PalwOverlayError::CertificateLeafRootMismatch)
        );

        // (4) the correctly-bound certificate persists.
        let good_hash = base.hash();
        apply_palw_overlay_effect(PalwOverlayEffect::Certificate(base), &store, &beacon, None).unwrap();
        assert_eq!(store.certificate(good_hash).unwrap().leaf_root, real_leaf_root);
    }

    /// kaspa-pq **ADR-0040 P1-3 / gate G4** — CERT-01: a certificate must be genuinely ATTESTED.
    ///
    /// The bug this closes: `validate_certificate` checked the signature **length** and nothing else, no
    /// ML-DSA verification existed anywhere in PALW consensus, and `quorum_reached` had no production
    /// caller. A certificate carrying correctly-sized garbage signatures was accepted, persisted
    /// content-addressed, and its hash became referenceable by an algo-4 header.
    ///
    /// Forging a certificate now requires live ML-DSA-87 signatures from a quorum-weight majority of
    /// genuinely bonded, slashable stake. Every assertion below is a distinct forgery attempt.
    #[test]
    fn certificate_attestation_requires_real_signatures_over_active_bonded_stake() {
        use kaspa_consensus_core::dns_finality::{ActiveBondView, BondStatus, StakeBondRecord, DNS_PAYLOAD_VERSION_V1};
        use kaspa_consensus_core::palw::PALW_AUDITOR_MLDSA87_CONTEXT;
        use libcrux_ml_dsa::ml_dsa_87 as mldsa;

        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));
        let m = manifest();
        let (bid, leaf_root) = (m.batch_id, m.leaf_root);
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(m), &store, &beacon, None).unwrap();

        const NET: u32 = 7;
        let op = |b: u8| TransactionOutpoint::new(h(b), 0);
        let kp = |s: u8| mldsa::generate_key_pair([s; 32]);

        // Three bonded auditors, 40 / 40 / 20 sompi — so any two reach 2/3 and any one alone does not.
        let keys = [kp(0x11), kp(0x22), kp(0x33)];
        let amounts = [40u64, 40, 20];
        let view = ActiveBondView::from_records(keys.iter().enumerate().map(|(i, k)| {
            let outpoint = op(0x40 + i as u8);
            (
                outpoint,
                StakeBondRecord {
                    version: DNS_PAYLOAD_VERSION_V1,
                    bond_outpoint: outpoint,
                    owner_pubkey_hash: h(0x90 + i as u8),
                    validator_pubkey_hash: h(0xa0 + i as u8),
                    validator_pubkey: k.verification_key.as_ref().to_vec(),
                    amount: amounts[i],
                    activation_daa_score: 0,
                    created_daa_score: 0,
                    unbonding_period_blocks: 0,
                    owner_reward_spk_payload: [0u8; 64],
                    unbond_request_daa_score: None,
                    slashed_at_daa_score: None,
                    status: BondStatus::Active,
                    last_attested_epoch: None,
                    dormant_at_daa_score: None,
                    dormant_at_epoch: None,
                },
            )
        }));
        let ctx = PalwCertificateAttestationCtx { network_id: NET, pov_daa_score: 100, bond_view: &view, quorum_num: 2, quorum_den: 3 };

        let base = |votes: Vec<PalwAuditorVoteV1>, approving_stake: u128| PalwBatchCertificateV1 {
            version: 1,
            batch_id: bid,
            manifest_hash: bid,
            leaf_root,
            audit_beacon_epoch: 5,
            audit_sample_root: h(4),
            passed_leaf_count: 2,
            rejected_leaf_bitmap_root: h(5),
            certificate_epoch: 6,
            activation_epoch: 7,
            expiry_epoch: 13,
            auditor_set_commitment: h(7),
            approving_stake,
            votes,
        };
        // Sign a vote correctly for auditor `i`.
        let signed = |i: usize, vote: u8, cert_stub: &PalwBatchCertificateV1| {
            let mut v = PalwAuditorVoteV1 { bond_outpoint: op(0x40 + i as u8), vote, checked_leaf_bitmap_root: h(6), signature: vec![] };
            let d = v.signing_hash(NET, &cert_stub.batch_id, cert_stub.audit_beacon_epoch, &cert_stub.audit_sample_root);
            v.signature = mldsa::sign(&keys[i].signing_key, d.as_bytes().as_slice(), PALW_AUDITOR_MLDSA87_CONTEXT, [0x5au8; 32])
                .expect("sign")
                .as_ref()
                .to_vec();
            v
        };
        let stub = base(vec![], 0);

        // ---- the forgery that used to work: right-length garbage signatures ----
        let garbage = base(vec![
            PalwAuditorVoteV1 {
                bond_outpoint: op(0x40),
                vote: 1,
                checked_leaf_bitmap_root: h(6),
                signature: vec![0u8; keys[0].signing_key.as_ref().len().min(4627)],
            },
            PalwAuditorVoteV1 { bond_outpoint: op(0x41), vote: 1, checked_leaf_bitmap_root: h(6), signature: vec![0u8; 4627] },
        ], 80);
        assert_eq!(
            verify_certificate_attestation(&garbage, &ctx),
            Err(PalwOverlayError::CertificateVoteSignatureInvalid),
            "correctly-sized garbage must no longer pass"
        );

        // ---- an unbonded "auditor" cannot vote (unbonded ⇒ unslashable ⇒ not an auditor) ----
        let mut ghost_vote = signed(0, 1, &stub);
        ghost_vote.bond_outpoint = op(0xee);
        assert_eq!(
            verify_certificate_attestation(&base(vec![ghost_vote], 40), &ctx),
            Err(PalwOverlayError::CertificateVoteBondNotActive)
        );

        // ---- a real signature replayed under a DIFFERENT bond fails (sig binds to its own key) ----
        let mut stolen = signed(0, 1, &stub);
        stolen.bond_outpoint = op(0x41);
        assert_eq!(verify_certificate_attestation(&base(vec![stolen], 40), &ctx), Err(PalwOverlayError::CertificateVoteSignatureInvalid));

        // ---- honest but SHORT of quorum: 40 of 100 passing < 2/3 ----
        let short = base(vec![signed(0, 1, &stub), signed(1, 0, &stub), signed(2, 0, &stub)], 40);
        assert_eq!(verify_certificate_attestation(&short, &ctx), Err(PalwOverlayError::CertificateQuorumNotReached));

        // ---- honest AND at quorum: 80 of 100 ⇒ accepted, and it persists through the apply path ----
        let good = base(vec![signed(0, 1, &stub), signed(1, 1, &stub), signed(2, 0, &stub)], 80);
        assert_eq!(verify_certificate_attestation(&good, &ctx), Ok(()));
        let good_hash = good.hash();
        apply_palw_overlay_effect(PalwOverlayEffect::Certificate(good), &store, &beacon, Some(&ctx)).unwrap();
        assert_eq!(store.certificate(good_hash).unwrap().passed_leaf_count, 2);

        // ---- tampering with a covered field invalidates the signatures it is bound to ----
        let mut tampered = base(vec![signed(0, 1, &stub), signed(1, 1, &stub)], 80);
        tampered.audit_sample_root = h(0xff); // covered by signing_hash
        assert_eq!(verify_certificate_attestation(&tampered, &ctx), Err(PalwOverlayError::CertificateVoteSignatureInvalid));

        // ---- one bond must not be counted twice ----
        let dup = base(vec![signed(0, 1, &stub), signed(0, 1, &stub)], 80);
        assert_eq!(verify_certificate_attestation(&dup, &ctx), Err(PalwOverlayError::CertificateDuplicateVoteBond));

        // ---- ADR-0040 §12′: the DECLARED approving stake must equal the tally ----
        //
        // This is load-bearing, not bookkeeping: the supersession comparator reads the declared field
        // (the body-stage view builder has no bond view), so an inflated declaration would let a weak
        // certificate evict a genuinely better-supported one — the exact censorship the rule exists to
        // make unstable. Both directions must fail: over-declaring buys eviction power, under-declaring
        // would let an attacker park a low value that a later sybil certificate can "beat".
        let inflated = base(vec![signed(0, 1, &stub), signed(1, 1, &stub), signed(2, 0, &stub)], u128::MAX);
        assert_eq!(
            verify_certificate_attestation(&inflated, &ctx),
            Err(PalwOverlayError::CertificateApprovingStakeMismatch),
            "an over-declared approving_stake must be rejected"
        );
        let deflated = base(vec![signed(0, 1, &stub), signed(1, 1, &stub), signed(2, 0, &stub)], 1);
        assert_eq!(
            verify_certificate_attestation(&deflated, &ctx),
            Err(PalwOverlayError::CertificateApprovingStakeMismatch),
            "an under-declared approving_stake must be rejected too"
        );
    }

    /// §11.2: a beacon commit accumulates into the epoch; a matching reveal is recorded as valid; a reveal
    /// with no prior commit (or a wrong random) is inert (dropped, not recorded).
    #[test]
    fn apply_beacon_commit_reveal_accumulates() {
        use kaspa_consensus_core::palw::{PalwBeaconCommitV1, PalwBeaconRevealV1, beacon_commitment};
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db.clone(), CachePolicy::Count(64));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(64));

        let bond = TransactionOutpoint::new(h(0x50), 0);
        let random = [7u8; 64];
        let commitment = beacon_commitment(9, &random, &bond);
        // commit for epoch 9 ⇒ accumulated.
        let commit = PalwBeaconCommitV1 { version: 1, epoch: 9, bond_outpoint: bond, commitment, signature: vec![] };
        apply_palw_overlay_effect(PalwOverlayEffect::BeaconCommit(commit), &store, &beacon, None).unwrap();
        assert_eq!(beacon.commitment_of(9, &bond).unwrap(), Some(commitment));
        assert_eq!(beacon.epoch_inputs(9).unwrap().valid_reveals.len(), 0);

        // a reveal with the WRONG random does not open the commit ⇒ not recorded.
        let bad = PalwBeaconRevealV1 { version: 1, epoch: 9, bond_outpoint: bond, random_64: [0u8; 64], signature: vec![] };
        apply_palw_overlay_effect(PalwOverlayEffect::BeaconReveal(bad), &store, &beacon, None).unwrap();
        assert_eq!(beacon.epoch_inputs(9).unwrap().valid_reveals.len(), 0);

        // the matching reveal ⇒ recorded as a valid reveal.
        let good = PalwBeaconRevealV1 { version: 1, epoch: 9, bond_outpoint: bond, random_64: random, signature: vec![] };
        let entropy = good.entropy_digest();
        apply_palw_overlay_effect(PalwOverlayEffect::BeaconReveal(good), &store, &beacon, None).unwrap();
        assert_eq!(beacon.epoch_inputs(9).unwrap().valid_reveals, vec![(bond, entropy)]);
        assert_ne!(entropy, commitment, "the public E-2 commitment must not be reused as R_E entropy");

        // a reveal for an epoch with no commit is inert.
        let orphan = PalwBeaconRevealV1 { version: 1, epoch: 20, bond_outpoint: bond, random_64: random, signature: vec![] };
        apply_palw_overlay_effect(PalwOverlayEffect::BeaconReveal(orphan), &store, &beacon, None).unwrap();
        assert_eq!(beacon.epoch_inputs(20).unwrap().valid_reveals.len(), 0);
    }

    /// §12.3: the R_E → eligibility_digest bridge. With no beacon seed carried at the selected parent,
    /// resolve returns None; once a state is written, the resolved digest equals the direct
    /// `eligibility_hash` over that seed (proving R_E makes clause 9 computable). NOT enforced anywhere.
    #[test]
    fn resolve_eligibility_from_beacon_seed() {
        use kaspa_consensus_core::palw::{PalwBeaconStateV1, eligibility_hash};
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(16));
        let sp = h(0x30);
        let (net, chain_commit, target, batch_id, leaf_index, leaf_hash, nf) = (0x9107u32, h(1), 42u64, h(2), 3u32, h(4), h(5));

        // no carried seed ⇒ None.
        assert_eq!(
            resolve_palw_eligibility(&beacon, sp, net, &chain_commit, target, &batch_id, leaf_index, &leaf_hash, &nf).unwrap(),
            None
        );

        // write a beacon state at the selected parent, then resolve.
        let seed = h(0x77);
        beacon
            .set_state(
                sp,
                Arc::new(PalwBeaconStateV1 {
                    version: 1,
                    epoch: 9,
                    seed,
                    dns_anchor: h(0),
                    anchor_blue_score: 0,
                    anchor_daa_score: 0,
                    anchor_overlay_root: h(0),
                    valid_reveals_root: h(0),
                    missing_commitments_root: h(0),
                    mode: 0,
                    degraded_epochs: 0,
                    valid_reveal_count: 0,
                    missing_commit_count: 0,
                }),
            )
            .unwrap();

        let got = resolve_palw_eligibility(&beacon, sp, net, &chain_commit, target, &batch_id, leaf_index, &leaf_hash, &nf).unwrap();
        let want = eligibility_hash(net, &seed, &chain_commit, target, &batch_id, leaf_index, &leaf_hash, &nf);
        assert_eq!(got, Some(want));
    }

    /// §12.1: the clause-6 bridge. No carried record ⇒ None; a record whose anchor is the zero
    /// bootstrap ⇒ None (fail-closed — no certificate is derivable); a record with a confirmed anchor
    /// ⇒ chain_commit over the anchor + the on-demand certificate digest, matching the direct pure
    /// computation. NOT enforced anywhere (C5 flips clauses 6–9 atomically).
    #[test]
    fn resolve_chain_commit_from_beacon_record() {
        use kaspa_consensus_core::palw::{BeaconDnsAnchor, PalwBeaconStateV1, chain_commit, dns_finality_certificate_hash_v1};
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let beacon = DbPalwBeaconStore::new(db, CachePolicy::Count(16));
        let (net, target) = (0x9107u32, 42u64);
        let state = |anchor: BeaconDnsAnchor| PalwBeaconStateV1 {
            version: 1,
            epoch: 9,
            seed: h(0x77),
            dns_anchor: anchor.hash,
            anchor_blue_score: anchor.blue_score,
            anchor_daa_score: anchor.daa_score,
            anchor_overlay_root: anchor.overlay_root,
            valid_reveals_root: h(0),
            missing_commitments_root: h(0),
            mode: 0,
            degraded_epochs: 0,
            valid_reveal_count: 0,
            missing_commit_count: 0,
        };

        // no carried record ⇒ None.
        assert_eq!(resolve_palw_chain_commit(&beacon, h(0x40), net, target).unwrap(), None);

        // zero bootstrap anchor ⇒ None (fail-closed).
        let sp_boot = h(0x41);
        beacon.set_state(sp_boot, Arc::new(state(BeaconDnsAnchor::UNCONFIRMED))).unwrap();
        assert_eq!(resolve_palw_chain_commit(&beacon, sp_boot, net, target).unwrap(), None);

        // confirmed anchor ⇒ Some(chain_commit(anchor, cert_v1(facts), S, net)).
        let anchor = BeaconDnsAnchor { hash: h(0x50), blue_score: 700, daa_score: 900, overlay_root: h(0x51) };
        let sp = h(0x42);
        beacon.set_state(sp, Arc::new(state(anchor))).unwrap();
        let want = chain_commit(&anchor.hash, &dns_finality_certificate_hash_v1(&anchor), target, net);
        assert_eq!(resolve_palw_chain_commit(&beacon, sp, net, target).unwrap(), Some(want));
    }

    /// §16.3: the clause-7 lane HOLD bridge. An absent lane-bits row (genesis / pre-activation parent)
    /// falls back to the lane's genesis bits; a carried row supplies the per-lane bits. NOT enforced.
    #[test]
    fn resolve_lane_hold_bits() {
        use crate::model::stores::palw_lane_bits::DbPalwLaneBitsStore;
        use kaspa_consensus_core::palw::{LaneDifficultyParams, PalwLaneBitsV1};
        use kaspa_consensus_core::pow_layer0::WorkLane;
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwLaneBitsStore::new(db, CachePolicy::Count(16));
        let params =
            LaneDifficultyParams { genesis_hash_bits: 0x1d00ffff, genesis_replica_bits: 0x1e00abcd, ..LaneDifficultyParams::INERT };
        let sp = h(0x60);

        // absent row ⇒ genesis lane bits per lane.
        assert_eq!(resolve_palw_lane_hold_bits(&store, sp, WorkLane::HashFloor, &params).unwrap(), 0x1d00ffff);
        assert_eq!(resolve_palw_lane_hold_bits(&store, sp, WorkLane::ReplicaPalw, &params).unwrap(), 0x1e00abcd);

        // carried row ⇒ that block's per-lane bits.
        store.set(sp, PalwLaneBitsV1 { hash_bits: 0x1c00aaaa, replica_bits: 0x1b00bbbb }).unwrap();
        assert_eq!(resolve_palw_lane_hold_bits(&store, sp, WorkLane::HashFloor, &params).unwrap(), 0x1c00aaaa);
        assert_eq!(resolve_palw_lane_hold_bits(&store, sp, WorkLane::ReplicaPalw, &params).unwrap(), 0x1b00bbbb);
    }

    /// §18.1: `resolve_palw_binding` reads the leaf + certificate a header names and packs them into the
    /// pure verify inputs; store absence fails closed. The resolved binding drives
    /// `verify_palw_ticket_store_facts` so a matching header passes clauses 1–5 and a wrong nullifier is
    /// rejected — the concrete verify_palw_ticket ↔ PalwStore bridge.
    #[test]
    fn resolve_binding_and_store_facts() {
        use kaspa_consensus_core::palw::verify_palw_ticket_store_facts;
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db, CachePolicy::Count(64));

        // absent leaf/cert fail closed.
        assert_eq!(resolve_palw_binding(h(1), 0, h(9), 7, &store), Err(PalwBindingError::LeafAbsent));

        // populate a leaf + certificate.
        store.insert_leaf(h(1), 0, Arc::new(leaf(0))).unwrap();
        let cert = PalwBatchCertificateV1 {
            version: 1,
            batch_id: h(1),
            manifest_hash: h(2),
            leaf_root: h(3),
            audit_beacon_epoch: 5,
            audit_sample_root: h(4),
            passed_leaf_count: 2,
            rejected_leaf_bitmap_root: h(5),
            certificate_epoch: 6,
            activation_epoch: 6,
            expiry_epoch: 20,
            auditor_set_commitment: h(7),
            approving_stake: 0,
            votes: vec![],
        };
        let cert_hash = cert.hash();
        store.insert_certificate(cert_hash, Arc::new(cert)).unwrap();
        // leaf present but cert hash unknown ⇒ CertAbsent.
        assert_eq!(resolve_palw_binding(h(1), 0, h(99), 7, &store), Err(PalwBindingError::CertAbsent));

        // kaspa-pq **ADR-0040 CERT-BATCH — REJECT: a certificate belonging to a DIFFERENT batch.**
        //
        // `resolve_palw_binding` looks the certificate up by hash alone, so without the cross-bind a
        // header could name any stored certificate and inherit its window. Here batch h(1)'s leaf is
        // present and batch h(0x21)'s certificate is a perfectly valid, stored, resolvable blob — the
        // ONLY thing wrong is that it certifies someone else's batch. It must be attributably rejected,
        // not silently accepted and not conflated with "absent".
        let foreign = PalwBatchCertificateV1 {
            version: 1,
            batch_id: h(0x21),
            manifest_hash: h(0x22),
            leaf_root: h(0x23),
            audit_beacon_epoch: 5,
            audit_sample_root: h(0x24),
            passed_leaf_count: 2,
            rejected_leaf_bitmap_root: h(0x25),
            certificate_epoch: 6,
            activation_epoch: 0,
            expiry_epoch: u64::MAX,
            auditor_set_commitment: h(0x26),
            approving_stake: 0,
            votes: vec![],
        };
        let foreign_hash = foreign.hash();
        store.insert_certificate(foreign_hash, Arc::new(foreign)).unwrap();
        assert_eq!(
            resolve_palw_binding(h(1), 0, foreign_hash, 7, &store),
            Err(PalwBindingError::CertBatchMismatch),
            "a certificate that certifies another batch must not resolve for this one"
        );
        // ...and the resolver stays honest in the other direction: the batch's OWN certificate resolves.
        assert!(resolve_palw_binding(h(1), 0, cert_hash, 7, &store).is_ok());

        // ADR-0040 CERT-BATCH — certificates are write-once by content, mirroring leaves. Re-inserting
        // identical content is idempotent; a different blob at the same key fails closed.
        store.insert_certificate(foreign_hash, store.certificate(foreign_hash).unwrap()).unwrap();
        let mut collider = (*store.certificate(foreign_hash).unwrap()).clone();
        collider.expiry_epoch = 1;
        assert!(
            store.insert_certificate(foreign_hash, Arc::new(collider)).is_err(),
            "a differing certificate at an existing content key must be refused, not silently overwrite"
        );

        // full resolution: leaf(0) commits raw nullifier h(3), proof_type 1, activation 7, expiry 13.
        let resolved = resolve_palw_binding(h(1), 0, cert_hash, /*target_daa_interval*/ 42, &store).unwrap();
        assert_eq!(resolved.binding.ticket_nullifier_commitment, kaspa_consensus_core::palw::ticket_nullifier_commitment(&h(3)));
        assert_eq!(resolved.binding.proof_type, 1);
        assert_eq!(resolved.binding.leaf_activation_epoch, 7);
        assert_eq!(resolved.binding.leaf_expiry_epoch, 13);
        assert_eq!(resolved.binding.target_daa_interval, 42);
        assert_eq!(resolved.leaf_hash, leaf(0).leaf_hash());

        // clauses 1–5 over the resolved binding: epoch 10 ∈ [7,13) leaf & [6,20) cert, interval matches.
        let cert_active = resolved.cert_activation_epoch <= 10 && 10 < resolved.cert_expiry_epoch;
        assert!(verify_palw_ticket_store_facts(&h(3), 1, 42, &resolved.binding, cert_active, 10).is_ok());
        // a header whose nullifier disagrees with the resolved leaf is rejected.
        assert!(verify_palw_ticket_store_facts(&h(4), 1, 42, &resolved.binding, cert_active, 10).is_err());
        // epoch outside the leaf window is rejected (LeafNotActive at epoch 13).
        assert!(verify_palw_ticket_store_facts(&h(3), 1, 42, &resolved.binding, cert_active, 13).is_err());
    }
}
