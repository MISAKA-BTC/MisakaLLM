//! kaspa-pq ADR-0039 §9.3/§9.5/§18 — PALW overlay-payload processing: parse a PALW subnetwork
//! (`0x30`–`0x37`) transaction's payload and apply the resulting batch-state transition to the
//! [`PalwStore`]. Pure parse + a store-application step, so the transition logic is unit-testable.
//!
//! **Inert (never invoked)** on every shipped preset — the caller gates this on the PALW activation
//! fence, and nothing produces PALW overlay txs while PALW is off.

use std::sync::Arc;

use kaspa_consensus_core::palw::{
    PalwBatchCertificateV1, PalwBatchEvent, PalwBatchManifestV1, PalwBatchStatus, PalwLeafChunkV1, PalwProviderBondPayloadV1,
    PalwTicketBinding,
};
use kaspa_consensus_core::subnets::{
    SUBNETWORK_ID_PALW_BATCH_CERT, SUBNETWORK_ID_PALW_BATCH_MANIFEST, SUBNETWORK_ID_PALW_LEAF_CHUNK, SUBNETWORK_ID_PALW_PROVIDER_BOND,
};
use kaspa_hashes::Hash64;
use borsh::BorshDeserialize;

use crate::model::stores::palw::{PalwStore, PalwStoreReader};

/// A parsed PALW overlay transaction (the subset the batch lifecycle needs; slashing / beacon / unbond
/// kinds `0x34`–`0x37` are the audit / beacon slices).
#[derive(Clone, Debug)]
pub enum PalwOverlayEffect {
    ProviderBond(PalwProviderBondPayloadV1),
    Manifest(PalwBatchManifestV1),
    LeafChunk(PalwLeafChunkV1),
    Certificate(PalwBatchCertificateV1),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PalwOverlayError {
    /// The subnetwork's first byte is not a batch-lifecycle PALW kind this processor handles.
    UnhandledSubnet(u8),
    /// The payload did not borsh-decode as its declared type.
    MalformedPayload,
    /// The batch-state machine rejects this event from the batch's current status (§9.5).
    InvalidTransition,
    /// A backing-store read/write failed.
    StoreError,
}

/// ADR-0039 §9.2/§9.3 — parse a PALW overlay tx payload by its subnetwork's first byte (`0x30`–`0x33`).
/// Pure (borsh decode); does not touch any store.
pub fn parse_palw_overlay(subnet_first_byte: u8, payload: &[u8]) -> Result<PalwOverlayEffect, PalwOverlayError> {
    let malformed = |_| PalwOverlayError::MalformedPayload;
    // The four batch-lifecycle PALW subnetwork ids resolve to their first byte (0x30–0x33); the
    // slashing / beacon / unbond kinds (0x34–0x37) fall through to `UnhandledSubnet` here.
    let bond = SUBNETWORK_ID_PALW_PROVIDER_BOND.palw_tx_kind().unwrap();
    let manifest = SUBNETWORK_ID_PALW_BATCH_MANIFEST.palw_tx_kind().unwrap();
    let leaf_chunk = SUBNETWORK_ID_PALW_LEAF_CHUNK.palw_tx_kind().unwrap();
    let cert = SUBNETWORK_ID_PALW_BATCH_CERT.palw_tx_kind().unwrap();
    match subnet_first_byte {
        b if b == bond => PalwProviderBondPayloadV1::try_from_slice(payload).map(PalwOverlayEffect::ProviderBond).map_err(malformed),
        b if b == manifest => PalwBatchManifestV1::try_from_slice(payload).map(PalwOverlayEffect::Manifest).map_err(malformed),
        b if b == leaf_chunk => PalwLeafChunkV1::try_from_slice(payload).map(PalwOverlayEffect::LeafChunk).map_err(malformed),
        b if b == cert => PalwBatchCertificateV1::try_from_slice(payload).map(PalwOverlayEffect::Certificate).map_err(malformed),
        other => Err(PalwOverlayError::UnhandledSubnet(other)),
    }
}

/// ADR-0039 §9.5 — apply a parsed overlay effect to the [`PalwStore`], advancing the batch state
/// machine (`PalwBatchStatus::next`) and persisting the record. Deterministic; the caller has already
/// gated on the PALW activation fence.
pub fn apply_palw_overlay_effect(effect: PalwOverlayEffect, store: &dyn PalwStore) -> Result<(), PalwOverlayError> {
    match effect {
        PalwOverlayEffect::ProviderBond(_bond) => {
            // Provider-bond registration feeds the bond view (`PalwProviderBond` prefix) — the bond-store
            // wiring is the audit / economics slice. No batch-state effect.
            Ok(())
        }
        PalwOverlayEffect::Manifest(m) => {
            let batch_id = m.batch_id;
            let cur = store.batch_status(batch_id).unwrap_or(PalwBatchStatus::Missing);
            let next = cur.next(PalwBatchEvent::ManifestAccepted).ok_or(PalwOverlayError::InvalidTransition)?;
            store.insert_manifest(batch_id, Arc::new(m)).map_err(|_| PalwOverlayError::StoreError)?;
            store.set_batch_status(batch_id, next).map_err(|_| PalwOverlayError::StoreError)?;
            Ok(())
        }
        PalwOverlayEffect::LeafChunk(c) => {
            // Persist every leaf in the chunk under `(batch_id, leaf_index)`. The chunk/bond completeness
            // gate (Registering → Committed) is checked once all `chunk_count` chunks are present (§9.3);
            // that aggregate transition is driven by the caller after applying the block's chunks.
            for leaf in &c.leaves {
                store.insert_leaf(c.batch_id, leaf.leaf_index, Arc::new(leaf.clone())).map_err(|_| PalwOverlayError::StoreError)?;
            }
            Ok(())
        }
        PalwOverlayEffect::Certificate(cert) => {
            let batch_id = cert.batch_id;
            let cur = store.batch_status(batch_id).unwrap_or(PalwBatchStatus::Missing);
            let next = cur.next(PalwBatchEvent::CertificateQuorum).ok_or(PalwOverlayError::InvalidTransition)?;
            store.insert_certificate(cert.hash(), Arc::new(cert)).map_err(|_| PalwOverlayError::StoreError)?;
            store.set_batch_status(batch_id, next).map_err(|_| PalwOverlayError::StoreError)?;
            Ok(())
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
            ticket_nullifier: leaf.ticket_nullifier,
            proof_type: leaf.proof_type,
            leaf_activation_epoch: leaf.activation_epoch,
            leaf_expiry_epoch: leaf.expiry_epoch,
            target_daa_interval,
        },
        cert_activation_epoch: cert.activation_epoch,
        cert_expiry_epoch: cert.expiry_epoch,
        leaf_hash: leaf.leaf_hash(),
    })
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
        PalwBatchManifestV1 {
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
        }
    }

    fn leaf(idx: u32) -> PalwPublicLeafV1 {
        let spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&[1]));
        PalwPublicLeafV1 {
            version: 1,
            batch_id: h(1),
            leaf_index: idx,
            job_nullifier: h(2),
            ticket_nullifier: h(3),
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

    /// §9.5: a manifest advances Missing → Registering + persists the manifest; a chunk persists its
    /// leaves; a certificate on an Auditing batch advances → Certified.
    #[test]
    fn apply_overlay_state_transitions() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbPalwStore::new(db, CachePolicy::Count(64));

        // manifest ⇒ Registering.
        apply_palw_overlay_effect(PalwOverlayEffect::Manifest(manifest()), &store).unwrap();
        assert_eq!(store.batch_status(h(1)).unwrap(), PalwBatchStatus::Registering);
        assert_eq!(store.batch_manifest(h(1)).unwrap().leaf_count, 2);

        // leaf chunk ⇒ leaves persisted under (batch_id, leaf_index).
        let chunk = PalwLeafChunkV1 { version: 1, batch_id: h(1), chunk_index: 0, leaves: vec![leaf(0), leaf(1)] };
        apply_palw_overlay_effect(PalwOverlayEffect::LeafChunk(chunk), &store).unwrap();
        assert!(store.has_leaf(h(1), 0).unwrap() && store.has_leaf(h(1), 1).unwrap());

        // drive the batch to Auditing, then a certificate ⇒ Certified.
        store.set_batch_status(h(1), PalwBatchStatus::Auditing).unwrap();
        let cert = PalwBatchCertificateV1 {
            version: 1, batch_id: h(1), manifest_hash: h(2), leaf_root: h(3), audit_beacon_epoch: 5,
            audit_sample_root: h(4), passed_leaf_count: 2, rejected_leaf_bitmap_root: h(5),
            certificate_epoch: 6, activation_epoch: 7, expiry_epoch: 13, auditor_set_commitment: h(7),
            votes: vec![PalwAuditorVoteV1 { bond_outpoint: TransactionOutpoint::new(h(8), 0), vote: 1, checked_leaf_bitmap_root: h(6), signature: vec![] }],
        };
        let cert_hash = cert.hash();
        apply_palw_overlay_effect(PalwOverlayEffect::Certificate(cert), &store).unwrap();
        assert_eq!(store.batch_status(h(1)).unwrap(), PalwBatchStatus::Certified);
        assert_eq!(store.certificate(cert_hash).unwrap().passed_leaf_count, 2);

        // a manifest for an ALREADY-Registering batch is an invalid transition (rejected, not applied).
        assert_eq!(
            apply_palw_overlay_effect(PalwOverlayEffect::Manifest(manifest()), &store),
            Err(PalwOverlayError::InvalidTransition)
        );
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
            version: 1, batch_id: h(1), manifest_hash: h(2), leaf_root: h(3), audit_beacon_epoch: 5,
            audit_sample_root: h(4), passed_leaf_count: 2, rejected_leaf_bitmap_root: h(5),
            certificate_epoch: 6, activation_epoch: 6, expiry_epoch: 20, auditor_set_commitment: h(7), votes: vec![],
        };
        let cert_hash = cert.hash();
        store.insert_certificate(cert_hash, Arc::new(cert)).unwrap();
        // leaf present but cert hash unknown ⇒ CertAbsent.
        assert_eq!(resolve_palw_binding(h(1), 0, h(99), 7, &store), Err(PalwBindingError::CertAbsent));

        // full resolution: leaf(0) has ticket_nullifier h(3), proof_type 1, activation 7, expiry 13.
        let resolved = resolve_palw_binding(h(1), 0, cert_hash, /*target_daa_interval*/ 42, &store).unwrap();
        assert_eq!(resolved.binding.ticket_nullifier, h(3));
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
