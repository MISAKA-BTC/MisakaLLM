//! Bounded, read-only PALW state exposed to operator tooling.
//!
//! The probe deliberately accepts at most one batch id and one provider-bond outpoint. It reports
//! state at a named sink and never enumerates the provider registry or a batch's leaves.

use kaspa_hashes::Hash64;

use crate::{
    BlockHash,
    palw::{PalwBatchLifecycleV1, PalwBatchManifestV1, PalwProviderBondRecord, PalwProviderBondStatus},
};

/// Fork-relative carried state for one requested batch at `PalwStateProbe::sink`.
///
/// The lifecycle view is built from raw blue-mergeset carriers before acceptance filtering. Manifest,
/// leaf, and certificate bytes live in global content-addressed stores. This is therefore a bounded
/// diagnostic of the exact surfaces ticket resolution reads, not proof that a carrier was accepted on
/// the selected chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PalwBatchProbe {
    pub batch_id: Hash64,
    pub lifecycle: PalwBatchLifecycleV1,
    /// The content-addressed manifest resolved for this fork-local lifecycle entry, if the blob exists.
    pub manifest: Option<PalwBatchManifestV1>,
    /// Number of leaf blobs present, scanned only up to the activated network's bounded batch limit.
    pub leaf_blobs_present: u32,
    /// False only if a corrupt/legacy lifecycle claims more leaves than the bounded scan limit.
    pub leaf_scan_complete: bool,
    /// Whether the fork-local `cert_hash`, when present, resolves to a certificate blob. This is a
    /// presence check, not fork-scoped proof that the certificate was verified at this sink: certificate
    /// blobs remain globally content-addressed until the attestation-provenance blocker is closed.
    pub certificate_blob_present: bool,
}

/// Selected-chain registry state for one requested provider-bond outpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PalwProviderBondProbe {
    pub record: PalwProviderBondRecord,
    pub effective_status: PalwProviderBondStatus,
    pub release_daa_score: Option<u64>,
}

/// One bounded operator probe pinned to a named virtual sink.
///
/// The sink, its immutable carried view, and the selected-chain provider registry are chosen under the
/// virtual-state read lock. Direct global blob writes do not take that lock, so manifest/leaf/certificate
/// availability is diagnostic and is not part of an atomic or fork-scoped acceptance snapshot. A
/// missing requested lifecycle/provider object is represented by `None`; global blobs are never used to
/// invent a lifecycle entry absent from the sink view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PalwStateProbe {
    pub enabled: bool,
    pub sink: BlockHash,
    pub sink_daa_score: u64,
    pub overlay_view_available: bool,
    pub batch: Option<PalwBatchProbe>,
    pub provider_bond: Option<PalwProviderBondProbe>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PalwStateProbeError {
    #[error("PALW state-store read failed: {0}")]
    Store(String),
}
