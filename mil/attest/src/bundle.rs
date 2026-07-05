//! The attestation bundle a provider registers and presents in every
//! handshake (design §3.2).

use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{Hash64, blake2b_512_keyed};
use misaka_mil_core::domains::{MIL_PROTOCOL_VERSION, MIL_QUOTE_DOMAIN};

/// CPU TEE platform of the quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum TeePlatform {
    /// Intel TDX guest VM (quote v4 in [`AttestationBundle::cpu_quote`]).
    IntelTdx,
    /// AMD SEV-SNP guest VM (attestation report in `cpu_quote`).
    AmdSevSnp,
    /// No TEE — v0 development / Tier-2 self-declaration. `cpu_quote` empty.
    Dev,
}

/// The two measured artifacts every registry entry pins (§3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Measurements {
    /// Measured inference-server container (vLLM/llama.cpp pinned build,
    /// logs off, tmpfs-only).
    pub runtime_image_hash: Hash64,
    /// Hash64 of the weights manifest — must equal the registry `model_id`
    /// preimage commitment (§7.1).
    pub model_manifest_hash: Hash64,
}

/// The full attestation document. Serialized with borsh; its keyed hash
/// ([`Self::quote_hash`]) is what registration anchors on-chain (§3.6a) and
/// what session ids derive from (§3.2).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AttestationBundle {
    pub version: u16,
    pub platform: TeePlatform,
    /// Raw platform quote: TDX quote v4 or SNP attestation report bytes.
    /// Empty for [`TeePlatform::Dev`].
    pub cpu_quote: Vec<u8>,
    /// Opaque GPU evidence (NVIDIA NRAS token / GPU attestation report).
    /// Hash-pinned in v0, cryptographically verified in P2.
    pub gpu_evidence: Vec<u8>,
    /// Claimed measurements; Tier-1 verifiers cross-check them against the
    /// platform quote fields and the registry pins.
    pub measurements: Measurements,
    /// Must equal `key_binding(pk_kem, pk_receipt)` (§3.2) AND the
    /// `report_data` field inside `cpu_quote` for real platforms.
    pub report_data: Hash64,
    /// Hash of the vendor certificate chain presented out-of-band; compared
    /// against governance-pinned roots (§3.6b).
    pub vendor_chain_hash: Hash64,
    /// Issuance wall-clock, unix milliseconds (freshness window input).
    pub issued_at_ms: u64,
}

impl AttestationBundle {
    /// Canonical quote hash: `Hash64_k("misaka-mil-v1/quote" ‖ borsh(self))`.
    pub fn quote_hash(&self) -> Hash64 {
        blake2b_512_keyed(MIL_QUOTE_DOMAIN, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialization of an in-memory bundle is infallible")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, borsh::io::Error> {
        Self::try_from_slice(bytes)
    }

    /// A development bundle (Tier-2 / loopback): no platform quote, the
    /// report_data key binding is self-declared and still enforced.
    pub fn dev(measurements: Measurements, report_data: Hash64, issued_at_ms: u64) -> Self {
        Self {
            version: MIL_PROTOCOL_VERSION,
            platform: TeePlatform::Dev,
            cpu_quote: Vec::new(),
            gpu_evidence: Vec::new(),
            measurements,
            report_data,
            vendor_chain_hash: Hash64::from_bytes([0u8; 64]),
            issued_at_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_roundtrip_and_quote_hash_stability() {
        let b = AttestationBundle::dev(
            Measurements { runtime_image_hash: Hash64::from_bytes([1u8; 64]), model_manifest_hash: Hash64::from_bytes([2u8; 64]) },
            Hash64::from_bytes([3u8; 64]),
            1_780_000_000_000,
        );
        let decoded = AttestationBundle::decode(&b.encode()).unwrap();
        assert_eq!(b, decoded);
        assert_eq!(b.quote_hash(), decoded.quote_hash());

        // any field change moves the quote hash
        let mut c = b.clone();
        c.issued_at_ms += 1;
        assert_ne!(b.quote_hash(), c.quote_hash());
    }
}
