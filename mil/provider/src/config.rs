//! Provider identity & serving configuration (design §16.1).
//!
//! v0 derives both enclave keypairs deterministically from a single 32-byte
//! provider seed (in Tier 1 they are enclave-generated instead), so a restart
//! reproduces the same `pk_kem` / `pk_receipt` and the registration anchor
//! stays valid. The seed file is loaded with the same fail-closed 0600 guard
//! the validator uses for its signing key.

use kaspa_hashes::{Hash64, blake2b_256_keyed};
use misaka_mil_attest::bundle::{AttestationBundle, Measurements};
use misaka_mil_channel::kem::{KEM_SEED_LEN, ProviderKemKeys};
use misaka_mil_core::ident::{key_binding, provider_id};
use misaka_mil_core::job::{SlaParams, Tier};
use misaka_mil_core::receipt::{RECEIPT_KEY_SEED_LEN, ReceiptSigner};

/// Length of the provider master seed file (hex-encoded on disk).
pub const PROVIDER_SEED_LEN: usize = 32;

/// Domain for deriving the ML-KEM sub-seed from the provider master seed.
const KEM_SUBSEED_DOMAIN: &[u8] = b"misaka-mil-v1/seed/kem";
/// Domain for deriving the ML-DSA receipt sub-seed from the provider master seed.
const RECEIPT_SUBSEED_DOMAIN: &[u8] = b"misaka-mil-v1/seed/receipt";

/// Serving parameters an operator configures (§6.2, §7.1).
#[derive(Debug, Clone)]
pub struct ServingConfig {
    /// Model served ([`misaka_mil_core::model::model_id`]); MIL-Core in v1.
    pub model_id: Hash64,
    /// Measured runtime image (must match attestation + registry, §7.1).
    pub runtime_image_hash: Hash64,
    /// Weights-manifest hash (the `model_id` preimage commitment).
    pub model_manifest_hash: Hash64,
    pub tier: Tier,
    /// Attested GPU-class weight `g` (§5.4).
    pub gpu_class_weight: u32,
    pub ask_in_per_1k_sompi: u64,
    pub ask_out_per_1k_sompi: u64,
    pub sla: SlaParams,
    pub region: String,
    /// The public `host:port` requesters dial for the data plane.
    pub data_plane_addr: String,
    /// Whether the model is hot (VRAM-resident) — SDKs prefer hot providers to
    /// avoid cold-start TTFT (§13.4a). Advertised in the registration.
    pub hot: bool,
    /// Side-channel padding cell size in bytes (§15.3). `None` = no padding
    /// (zero overhead); `Some(cell)` pads every data-plane frame to a `cell`
    /// multiple. The requester must use the same policy.
    pub padding_cell: Option<usize>,
}

impl ServingConfig {
    /// The data-plane padding policy from [`Self::padding_cell`].
    pub fn padding(&self) -> misaka_mil_core::padding::PaddingPolicy {
        match self.padding_cell {
            Some(cell) => misaka_mil_core::padding::PaddingPolicy::Cell(cell),
            None => misaka_mil_core::padding::PaddingPolicy::None,
        }
    }
}

/// The materialized provider: both enclave keypairs + serving config. Holds
/// the long-lived key material for the sidecar's lifetime.
pub struct ProviderContext {
    pub kem: ProviderKemKeys,
    pub receipt_signer: ReceiptSigner,
    pub serving: ServingConfig,
}

impl ProviderContext {
    /// Derive both keypairs from the master seed and attach the serving config.
    pub fn from_seed(master_seed: [u8; PROVIDER_SEED_LEN], serving: ServingConfig) -> Self {
        let mut kem_seed: [u8; KEM_SEED_LEN] = blake2b_256_keyed(KEM_SUBSEED_DOMAIN, &master_seed);
        let mut receipt_seed: [u8; RECEIPT_KEY_SEED_LEN] = blake2b_256_keyed(RECEIPT_SUBSEED_DOMAIN, &master_seed);
        let kem = ProviderKemKeys::from_seed(kem_seed);
        let receipt_signer = ReceiptSigner::from_seed(receipt_seed);
        // sub-seeds are copied into the keypair constructors; scrub our copies
        use zeroize::Zeroize;
        kem_seed.zeroize();
        receipt_seed.zeroize();
        Self { kem, receipt_signer, serving }
    }

    /// `pk_receipt` — the ML-DSA-87 receipt verification key.
    pub fn pk_receipt(&self) -> &[u8] {
        self.receipt_signer.public_key()
    }

    /// `pk_kem` — the ML-KEM-1024 encapsulation key.
    pub fn pk_kem(&self) -> &[u8] {
        self.kem.public_key()
    }

    /// This provider's overlay id.
    pub fn provider_id(&self) -> Hash64 {
        provider_id(self.pk_receipt())
    }

    /// The `report_data` key binding committed by the attestation (§3.2).
    pub fn key_binding(&self) -> Hash64 {
        key_binding(self.pk_kem(), self.pk_receipt())
    }

    /// Build the v0 development attestation bundle (self-declared Dev platform;
    /// real quotes arrive in P2). `report_data` binds the enclave keys exactly,
    /// which the verifier still enforces.
    pub fn dev_attestation_bundle(&self, issued_at_ms: u64) -> AttestationBundle {
        AttestationBundle::dev(
            Measurements {
                runtime_image_hash: self.serving.runtime_image_hash,
                model_manifest_hash: self.serving.model_manifest_hash,
            },
            self.key_binding(),
            issued_at_ms,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serving() -> ServingConfig {
        ServingConfig {
            model_id: Hash64::from_bytes([1u8; 64]),
            runtime_image_hash: Hash64::from_bytes([2u8; 64]),
            model_manifest_hash: Hash64::from_bytes([3u8; 64]),
            tier: Tier::Open,
            gpu_class_weight: 1,
            ask_in_per_1k_sompi: 100_000,
            ask_out_per_1k_sompi: 500_000,
            sla: SlaParams { ttfb_ms: 1500, min_tps: 20 },
            region: "ap-northeast".into(),
            data_plane_addr: "127.0.0.1:37110".into(),
            hot: true,
            padding_cell: None,
        }
    }

    #[test]
    fn seed_derivation_is_deterministic_and_binds() {
        let a = ProviderContext::from_seed([7u8; 32], serving());
        let b = ProviderContext::from_seed([7u8; 32], serving());
        assert_eq!(a.pk_kem(), b.pk_kem());
        assert_eq!(a.pk_receipt(), b.pk_receipt());
        assert_eq!(a.provider_id(), b.provider_id());

        let c = ProviderContext::from_seed([8u8; 32], serving());
        assert_ne!(a.pk_kem(), c.pk_kem());

        // the dev bundle's report_data is exactly the key binding the verifier recomputes
        let bundle = a.dev_attestation_bundle(1_780_000_000_000);
        assert_eq!(bundle.report_data, a.key_binding());
    }
}
