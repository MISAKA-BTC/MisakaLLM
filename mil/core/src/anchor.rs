//! v0 on-chain anchor payloads (design §8.1).
//!
//! v0 rides **NATIVE transactions with a MIL payload** — this fork places no
//! payload restriction on native txs (`check_transaction_subnetwork` accepts
//! any native tx; standardness has no payload rule), so anchoring needs zero
//! consensus changes. Because the subnetwork id stays NATIVE, the payload is
//! self-identifying: a 4-byte magic, then a version-tagged borsh document.
//!
//! Anchored today:
//! - [`ProviderRegistrationV1`] — provider onboarding: quote hash, key
//!   material, binding, ask, SLA (§2.3 step 2). Trust in v0 is the permissioned
//!   whitelist; the anchor gives tamper-evident public record + discovery.
//! - [`ReceiptAnchorV1`] — the compact hash-anchor of a signed receipt
//!   (settlement evidence; the 7 KiB receipt itself travels off-chain).
//!
//! v1 replaces both with the EVM-lane `ProviderRegistry` / `JobEscrow`
//! contracts (§8.2); the borsh structs here are the v0 field-compatible
//! precursors.

use crate::domains::MIL_PROTOCOL_VERSION;
use crate::job::{SlaParams, Tier};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash64;

/// Magic prefix identifying a MIL anchor inside a native-tx payload.
pub const MIL_ANCHOR_MAGIC: [u8; 4] = *b"MIL1";
/// Hard cap on an encoded anchor payload (registration dominates: two PQ
/// public keys ≈ 4.2 KiB; the cap keeps anchor txs comfortably relayable).
pub const MAX_ANCHOR_PAYLOAD_LEN: usize = 8 * 1024;

/// Provider registration record (§2.3 step 2, v0 shape of `ProviderRegistry`).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProviderRegistrationV1 {
    pub version: u16,
    /// [`crate::ident::provider_id`] of `pk_receipt`.
    pub provider_id: Hash64,
    /// Hash of the attestation bundle pinned at registration (§3.6a) —
    /// lets anyone detect a later quote swap.
    pub quote_hash: Hash64,
    /// The model served ([`crate::model::model_id`]); MIL-Core in v1 (§17).
    pub model_id: Hash64,
    pub tier: Tier,
    /// Attested GPU-class weight `g` (§5.4).
    pub gpu_class_weight: u32,
    /// ML-KEM-1024 encapsulation key (1568 bytes).
    pub pk_kem: Vec<u8>,
    /// ML-DSA-87 receipt verification key (2592 bytes).
    pub pk_receipt: Vec<u8>,
    /// [`crate::ident::key_binding`] — must equal the attested `report_data`.
    pub binding: Hash64,
    /// Ask price, sompi per 1000 input tokens.
    pub ask_in_per_1k_sompi: u64,
    /// Ask price, sompi per 1000 output tokens.
    pub ask_out_per_1k_sompi: u64,
    pub sla: SlaParams,
    /// Region tag for geo routing (§13.6), free-form (e.g. "ap-northeast").
    pub region: String,
    /// Data-plane dial address (`host:port`).
    pub data_plane_addr: String,
    /// Whether the model is hot (VRAM-resident); SDKs prefer hot to dodge
    /// cold-start TTFT (§13.4a).
    pub hot: bool,
    /// Registration wall-clock, unix milliseconds.
    pub timestamp_ms: u64,
}

/// Compact receipt anchor: enough for public settlement accounting without
/// the signature blob. Full receipt available off-chain on demand (disputes
/// present the full [`crate::receipt::SignedReceipt`] whose
/// [`crate::receipt::SignedReceipt::receipt_hash`] must match).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReceiptAnchorV1 {
    pub version: u16,
    pub provider_id: Hash64,
    pub session_id: Hash64,
    pub counter: u64,
    pub cum_tokens_in: u64,
    pub cum_tokens_out: u64,
    pub cm_resp: Hash64,
    /// [`crate::receipt::SignedReceipt::receipt_hash`] of the anchored receipt.
    pub receipt_hash: Hash64,
    pub is_final: bool,
}

/// The MIL anchor document — the borsh enum tag is the payload discriminator.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum MilAnchorPayload {
    ProviderRegistration(ProviderRegistrationV1),
    ReceiptAnchor(ReceiptAnchorV1),
    /// Compute-attestor epoch attestation (ADR-0024 §20.2, Phase A). Recorded as
    /// an ordinary native-tx payload; a keeper reads these to measure
    /// `compute_depth`. No consensus change, no reorg-gate participation.
    ComputeAttestation(crate::compute_attest::ComputeAttestation),
}

impl MilAnchorPayload {
    pub fn version(&self) -> u16 {
        match self {
            MilAnchorPayload::ProviderRegistration(r) => r.version,
            MilAnchorPayload::ReceiptAnchor(r) => r.version,
            MilAnchorPayload::ComputeAttestation(a) => a.body.version,
        }
    }
}

/// Anchor payload encode/decode failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnchorError {
    #[error("encoded anchor payload is {0} bytes, exceeding the {MAX_ANCHOR_PAYLOAD_LEN}-byte cap")]
    PayloadTooLarge(usize),
    #[error("anchor payload version {0} is not supported (expected {MIL_PROTOCOL_VERSION})")]
    UnsupportedVersion(u16),
    #[error("malformed anchor payload: {0}")]
    Malformed(String),
}

/// Encode `magic ‖ borsh(payload)` for a native-tx payload field.
pub fn encode_anchor_payload(payload: &MilAnchorPayload) -> Result<Vec<u8>, AnchorError> {
    let mut out = MIL_ANCHOR_MAGIC.to_vec();
    let body = borsh::to_vec(payload).expect("borsh serialization of an in-memory anchor is infallible");
    out.extend_from_slice(&body);
    if out.len() > MAX_ANCHOR_PAYLOAD_LEN {
        return Err(AnchorError::PayloadTooLarge(out.len()));
    }
    Ok(out)
}

/// Decode a native-tx payload. `Ok(None)` = not a MIL anchor (no magic) —
/// scanners skip it silently; `Err` = carries the magic but is malformed.
pub fn decode_anchor_payload(bytes: &[u8]) -> Result<Option<MilAnchorPayload>, AnchorError> {
    let Some(body) = bytes.strip_prefix(MIL_ANCHOR_MAGIC.as_slice()) else {
        return Ok(None);
    };
    if bytes.len() > MAX_ANCHOR_PAYLOAD_LEN {
        return Err(AnchorError::PayloadTooLarge(bytes.len()));
    }
    let payload = MilAnchorPayload::try_from_slice(body).map_err(|e| AnchorError::Malformed(e.to_string()))?;
    if payload.version() != MIL_PROTOCOL_VERSION {
        return Err(AnchorError::UnsupportedVersion(payload.version()));
    }
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ident::provider_id;

    fn registration() -> ProviderRegistrationV1 {
        ProviderRegistrationV1 {
            version: MIL_PROTOCOL_VERSION,
            provider_id: provider_id(&[0x22u8; 2592]),
            quote_hash: Hash64::from_bytes([1u8; 64]),
            model_id: Hash64::from_bytes([2u8; 64]),
            tier: Tier::Open,
            gpu_class_weight: 1,
            pk_kem: vec![0x11u8; 1568],
            pk_receipt: vec![0x22u8; 2592],
            binding: Hash64::from_bytes([3u8; 64]),
            ask_in_per_1k_sompi: 100_000,
            ask_out_per_1k_sompi: 500_000,
            sla: SlaParams { ttfb_ms: 1500, min_tps: 20 },
            region: "ap-northeast".into(),
            data_plane_addr: "203.0.113.7:37110".into(),
            hot: true,
            timestamp_ms: 1_780_000_000_000,
        }
    }

    #[test]
    fn anchor_roundtrip_registration() {
        let payload = MilAnchorPayload::ProviderRegistration(registration());
        let bytes = encode_anchor_payload(&payload).unwrap();
        assert!(bytes.starts_with(&MIL_ANCHOR_MAGIC));
        assert!(bytes.len() <= MAX_ANCHOR_PAYLOAD_LEN, "registration anchor must fit the cap, got {}", bytes.len());
        assert_eq!(decode_anchor_payload(&bytes).unwrap(), Some(payload));
    }

    #[test]
    fn anchor_roundtrip_receipt() {
        let payload = MilAnchorPayload::ReceiptAnchor(ReceiptAnchorV1 {
            version: MIL_PROTOCOL_VERSION,
            provider_id: Hash64::from_bytes([1u8; 64]),
            session_id: Hash64::from_bytes([2u8; 64]),
            counter: 3,
            cum_tokens_in: 100,
            cum_tokens_out: 1536,
            cm_resp: Hash64::from_bytes([3u8; 64]),
            receipt_hash: Hash64::from_bytes([4u8; 64]),
            is_final: true,
        });
        let bytes = encode_anchor_payload(&payload).unwrap();
        assert_eq!(decode_anchor_payload(&bytes).unwrap(), Some(payload));
    }

    #[test]
    fn non_mil_payloads_are_skipped_not_errors() {
        assert_eq!(decode_anchor_payload(b"").unwrap(), None);
        assert_eq!(decode_anchor_payload(b"EVM-something").unwrap(), None);
        assert_eq!(decode_anchor_payload(&[0u8; 32]).unwrap(), None);
    }

    #[test]
    fn malformed_and_wrong_version_are_errors() {
        let mut bytes = MIL_ANCHOR_MAGIC.to_vec();
        bytes.extend_from_slice(&[0xFFu8; 7]);
        assert!(matches!(decode_anchor_payload(&bytes), Err(AnchorError::Malformed(_))));

        let mut reg = registration();
        reg.version = 999;
        let bytes = encode_anchor_payload(&MilAnchorPayload::ProviderRegistration(reg)).unwrap();
        assert_eq!(decode_anchor_payload(&bytes), Err(AnchorError::UnsupportedVersion(999)));
    }
}
