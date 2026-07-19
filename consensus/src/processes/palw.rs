//! kaspa-pq ADR-0039 §9.3/§9.5/§18 — PALW overlay-payload processing: parse a PALW subnetwork
//! (`0x30`–`0x37`) transaction's payload and apply the resulting batch-state transition to the
//! [`PalwStore`]. Pure parse + a store-application step, so the transition logic is unit-testable.
//!
//! **Inert (never invoked)** on every shipped preset — the caller gates this on the PALW activation
//! fence, and nothing produces PALW overlay txs while PALW is off.

use std::sync::Arc;

use borsh::BorshDeserialize;
use kaspa_consensus_core::palw::{
    PalwBatchCertificateV1, PalwBatchManifestV1, PalwBeaconCommitV1, PalwBeaconRevealV1, PalwLeafChunkV1,
    PalwProviderBondPayloadV1, PalwTicketBinding,
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
    /// ADR-0040 P1-1 (LEAF-01): an attempt to replace an already-written leaf with different content.
    /// Leaves are write-once because coinbase reward scripts are read from them after acceptance.
    LeafImmutabilityViolation,
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

    // (4) ADR-0040 §12′ — the DECLARED approving stake must equal what we just tallied. This is what
    // turns `approving_stake` from a trusted input into a commitment: the supersession comparator reads
    // the declared field (the body-stage view builder has no bond view), so if a producer could inflate
    // it, it could evict a genuinely better certificate. Bound here, once, at the only point that has
    // the bond view.
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
            for leaf in &c.leaves {
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
                // ADR-0040 P1-9 — the GLOBAL job-nullifier check is NOT here.
                //
                // It cannot be: this arm writes the content-addressed blob store, which sits on the
                // ACCEPTANCE coordinate, while the duplicate-work decision is fork-relative and belongs
                // on the block-keyed view (`PalwBatchViewV1::claim_job_nullifier`, applied in
                // `commit_palw_overlay_view`). Enforcing it here would make the same leaf admissible or
                // not depending on which coordinate observed it first — the BIND-03 mismatch, applied to
                // a rule where it would be a consensus split rather than a nuisance.
                //
                // Blob persistence is therefore permissive; the view is where a duplicate job stops
                // being creditable.

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
    use kaspa_consensus_core::dns_finality::{anchor_cutoff_blue_score, canonical_lagged_epoch_anchor, ready_epoch_from_tip_blue_score};
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
    use kaspa_consensus_core::palw::{PalwAuditorVoteV1, PalwPublicLeafV1};
    use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec, TransactionOutpoint};
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::{CachePolicy, ConnBuilder};
    use kaspa_hashes::Hash64;

    use crate::model::stores::palw::{DbPalwStore, PalwStoreReader};

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    fn manifest() -> PalwBatchManifestV1 {
        let mut m = PalwBatchManifestV1 {
            version: 1,
            batch_id: h(1),
            registration_epoch: 1,
            model_profile_id: h(2),
            runtime_class_id: h(3),
            leaf_count: 2,
            chunk_count: 1,
            leaf_root: h(4),
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
            registered_epoch: 5,
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
        let chunk = PalwLeafChunkV1 { version: 1, batch_id: h(1), chunk_index: 0, leaves: vec![leaf(0), leaf(1)] };
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
        let chunk = PalwLeafChunkV1 { version: 1, batch_id: bid, chunk_index: 0, leaves: vec![leaf_in(bid, 0), leaf_in(bid, 1)] };
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
            leaf_root: h(4),    // == manifest().leaf_root
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

        // ---- (1) a chunk for a batch with NO admitted manifest is rejected outright ----
        let unknown = h(0xde);
        let orphan = PalwLeafChunkV1 { version: 1, batch_id: unknown, chunk_index: 0, leaves: vec![leaf_in(unknown, 0)] };
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(orphan), &store, &beacon, None),
            Err(PalwOverlayError::UnknownBatch),
            "a leaf must never be the effect that first materialises a batch key"
        );
        assert!(!store.has_leaf(unknown, 0).unwrap(), "nothing may be persisted for an unknown batch");

        // ---- (2) a leaf claiming a different batch than its chunk is rejected ----
        let smuggled = PalwLeafChunkV1 { version: 1, batch_id: bid, chunk_index: 0, leaves: vec![leaf_in(h(0xaa), 0)] };
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(smuggled), &store, &beacon, None),
            Err(PalwOverlayError::LeafBatchIdMismatch)
        );

        // ---- (3) an index outside the manifest's leaf_count can never be part of leaf_root ----
        let oob = PalwLeafChunkV1 { version: 1, batch_id: bid, chunk_index: 0, leaves: vec![leaf_in(bid, leaf_count)] };
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(oob), &store, &beacon, None),
            Err(PalwOverlayError::LeafIndexOutOfRange { leaf_index: leaf_count, leaf_count })
        );

        // ---- (4) the honest chunk lands ----
        let good = PalwLeafChunkV1 { version: 1, batch_id: bid, chunk_index: 0, leaves: vec![leaf_in(bid, 0), leaf_in(bid, 1)] };
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(good.clone()), &store, &beacon, None).unwrap();
        let sealed = store.leaf(bid, 0).unwrap().leaf_hash();

        // ---- (5) re-applying IDENTICAL content is idempotent (reorg replay must stay legal) ----
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(good), &store, &beacon, None).unwrap();
        assert_eq!(store.leaf(bid, 0).unwrap().leaf_hash(), sealed);

        // ---- (6) replacing an admitted leaf with DIFFERENT content is refused — the reward-theft path ----
        let mut thief = leaf_in(bid, 0);
        thief.provider_a_reward_script = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0xbe, 0xef]));
        assert_ne!(thief.leaf_hash(), sealed, "the fixture must actually differ, else the test proves nothing");
        let overwrite = PalwLeafChunkV1 { version: 1, batch_id: bid, chunk_index: 0, leaves: vec![thief] };
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(overwrite), &store, &beacon, None),
            Err(PalwOverlayError::LeafImmutabilityViolation)
        );
        assert_eq!(store.leaf(bid, 0).unwrap().leaf_hash(), sealed, "the originally admitted leaf must survive");
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
        let chunk = PalwLeafChunkV1 { version: 1, batch_id: bid, chunk_index: 0, leaves: vec![honest] };
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(chunk), &store, &beacon, None).unwrap();

        // The reward path reads the leaf by key at coinbase time. Attempt the theft: same key, different
        // payout. The store refuses, so the re-read still yields the accepted scripts.
        let mut thief = leaf_in(bid, 0);
        thief.provider_a_reward_script = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0xbe, 0xef]));
        let overwrite = PalwLeafChunkV1 { version: 1, batch_id: bid, chunk_index: 0, leaves: vec![thief] };
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(overwrite), &store, &beacon, None),
            Err(PalwOverlayError::LeafImmutabilityViolation)
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
                    revival_attested_epoch: None,
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
        use kaspa_consensus_core::palw::{chain_commit, dns_finality_certificate_hash_v1, BeaconDnsAnchor, PalwBeaconStateV1};
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
        let params = LaneDifficultyParams { genesis_hash_bits: 0x1d00ffff, genesis_replica_bits: 0x1e00abcd, ..LaneDifficultyParams::INERT };
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
