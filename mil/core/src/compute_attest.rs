//! Compute-attestor epoch attestations (ADR-0024 §20.2, Phase A).
//!
//! A GPU provider that takes on the security-issuance duty signs the same epoch
//! anchor a DNS validator signs, under the disjoint context
//! [`MIL_COMPUTE_ATTEST_MLDSA87_CONTEXT`], and commits a device-certificate hash
//! (§20.5 device binding). In **Phase A** the attestation is recorded on-chain
//! as an ordinary native-tx payload (no consensus change, no reorg-gate
//! participation, zero liveness risk); a keeper/indexer reads the payloads to
//! measure `compute_depth`. The issuance reward (reviving the `FeeSplitParams`
//! service slot, §20.4) and the reorg-gate dimension (Phase C) are separate,
//! HF-gated steps and are NOT in this module.
//!
//! Signing/verification mirror [`crate::receipt`]: ML-DSA-87 over a fixed-width
//! canonical transcript, verified with the **portable** libcrux backend (audit
//! H-2 — accept/reject bit-identical on every node/CPU).

use crate::domains::{MIL_COMPUTE_ATTEST_DOMAIN, MIL_COMPUTE_ATTEST_MLDSA87_CONTEXT, MIL_PROTOCOL_VERSION};
use crate::job::Tier;
use crate::receipt::{MIL_MLDSA87_PK_LEN, MIL_MLDSA87_SIG_LEN};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{HASH64_SIZE, Hash64, blake2b_512_keyed};
use libcrux_ml_dsa::ml_dsa_87;

/// A native UTXO bond reference (txid, output index) — the [ADR-0016] bond form,
/// carried without a consensus-core dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BondOutpoint {
    pub txid: Hash64,
    pub index: u32,
}

/// Compute-attestor overlay identity: `Hash64_k("misaka-mil-v1/compute-attest" ‖
/// pubkey)`. Keyed under the compute-attest domain, so it is disjoint from the
/// DNS `validator_id` and the MIL `provider_id` even under key reuse.
pub fn attestor_id(pubkey: &[u8]) -> Hash64 {
    blake2b_512_keyed(MIL_COMPUTE_ATTEST_DOMAIN, pubkey)
}

/// The signed fields of a compute-attestor epoch attestation.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ComputeAttestationBody {
    pub version: u16,
    /// [`attestor_id`] of the signer.
    pub attestor_id: Hash64,
    /// The native bond backing this attestation (§20.3 weight basis).
    pub bond: BondOutpoint,
    /// Epoch (DNS-mirror, 100 blue score).
    pub epoch: u64,
    /// The chain-block anchor being attested.
    pub target_hash: Hash64,
    pub target_daa_score: u64,
    /// §20.5 device binding: keyed hash of the TEE device certificate (Tier 1)
    /// or the canary-measured profile (Tier 2). Challengeable off-chain.
    pub device_cert_hash: Hash64,
    /// Attestor class (A = TEE/Tier1, B = Tier2).
    pub tier: Tier,
}

impl ComputeAttestationBody {
    /// Canonical fixed-width ML-DSA signing transcript. Domain separation rides
    /// the ML-DSA `ctx` parameter (repo convention); the transcript prepends the
    /// version and the network-id so a signature is bound to one network.
    pub fn signing_message(&self, network_id: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(2 + network_id.len() + 8 + HASH64_SIZE * 4 + 8 + 8 + 4 + 1);
        m.extend_from_slice(&self.version.to_le_bytes());
        m.extend_from_slice(&(network_id.len() as u64).to_le_bytes());
        m.extend_from_slice(network_id);
        m.extend_from_slice(self.attestor_id.as_byte_slice());
        m.extend_from_slice(self.bond.txid.as_byte_slice());
        m.extend_from_slice(&self.bond.index.to_le_bytes());
        m.extend_from_slice(&self.epoch.to_le_bytes());
        m.extend_from_slice(self.target_hash.as_byte_slice());
        m.extend_from_slice(&self.target_daa_score.to_le_bytes());
        m.extend_from_slice(self.device_cert_hash.as_byte_slice());
        m.push(self.tier as u8);
        m
    }
}

/// A compute attestation plus its ML-DSA-87 signature and the signer's key —
/// self-contained: anyone can verify against the pubkey (which
/// [`attestor_id`]-derives to the body's `attestor_id`).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ComputeAttestation {
    pub body: ComputeAttestationBody,
    /// ML-DSA-87 signature (4627 bytes).
    pub signature: Vec<u8>,
    /// ML-DSA-87 verification key (2592 bytes).
    pub attestor_pubkey: Vec<u8>,
}

/// Compute-attestation validation failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ComputeAttestError {
    #[error("unsupported version {0}")]
    UnsupportedVersion(u16),
    #[error("public key must be {MIL_MLDSA87_PK_LEN} bytes, got {0}")]
    BadPublicKeyLength(usize),
    #[error("signature must be {MIL_MLDSA87_SIG_LEN} bytes, got {0}")]
    BadSignatureLength(usize),
    #[error("attestor_id does not derive from the presented public key")]
    AttestorIdMismatch,
    #[error("ML-DSA-87 compute-attestation signature verification failed")]
    BadSignature,
}

impl ComputeAttestation {
    /// Verify: (1) version, (2) `attestor_id == attestor_id(pubkey)` (binds the
    /// id to the key), (3) the ML-DSA-87 signature over the transcript for
    /// `network_id` under the compute-attest context (portable backend).
    pub fn verify(&self, network_id: &[u8]) -> Result<(), ComputeAttestError> {
        if self.body.version != MIL_PROTOCOL_VERSION {
            return Err(ComputeAttestError::UnsupportedVersion(self.body.version));
        }
        let pk: [u8; MIL_MLDSA87_PK_LEN] = self
            .attestor_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| ComputeAttestError::BadPublicKeyLength(self.attestor_pubkey.len()))?;
        let sig: [u8; MIL_MLDSA87_SIG_LEN] =
            self.signature.as_slice().try_into().map_err(|_| ComputeAttestError::BadSignatureLength(self.signature.len()))?;
        if attestor_id(&self.attestor_pubkey) != self.body.attestor_id {
            return Err(ComputeAttestError::AttestorIdMismatch);
        }
        let vk = ml_dsa_87::MLDSA87VerificationKey::new(pk);
        let sig = ml_dsa_87::MLDSA87Signature::new(sig);
        ml_dsa_87::portable::verify(&vk, &self.body.signing_message(network_id), MIL_COMPUTE_ATTEST_MLDSA87_CONTEXT, &sig)
            .map_err(|_| ComputeAttestError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn body(pubkey: &[u8]) -> ComputeAttestationBody {
        ComputeAttestationBody {
            version: MIL_PROTOCOL_VERSION,
            attestor_id: attestor_id(pubkey),
            bond: BondOutpoint { txid: Hash64::from_bytes([1u8; 64]), index: 0 },
            epoch: 42,
            target_hash: Hash64::from_bytes([2u8; 64]),
            target_daa_score: 1_000_000,
            device_cert_hash: Hash64::from_bytes([3u8; 64]),
            tier: Tier::Tee,
        }
    }

    fn sign(seed: u8, network_id: &[u8]) -> ComputeAttestation {
        let kp = ml_dsa_87::generate_key_pair([seed; 32]);
        let pk = kp.verification_key.as_ref().to_vec();
        let b = body(&pk);
        let mut r = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut r);
        let sig = ml_dsa_87::sign(&kp.signing_key, &b.signing_message(network_id), MIL_COMPUTE_ATTEST_MLDSA87_CONTEXT, r).unwrap();
        ComputeAttestation { body: b, signature: sig.as_slice().to_vec(), attestor_pubkey: pk }
    }

    #[test]
    fn sign_verify_roundtrip_and_network_binding() {
        let net = b"testnet-10";
        let att = sign(0x71, net);
        att.verify(net).expect("valid attestation must verify");
        // a signature is bound to its network id
        assert_eq!(att.verify(b"mainnet"), Err(ComputeAttestError::BadSignature));
        // borsh round-trips
        let back = ComputeAttestation::try_from_slice(&borsh::to_vec(&att).unwrap()).unwrap();
        assert_eq!(att, back);
    }

    #[test]
    fn rejects_tamper_and_id_mismatch() {
        let net = b"testnet-10";
        let att = sign(0x71, net);
        // tampered field
        let mut t = att.clone();
        t.body.target_daa_score += 1;
        assert_eq!(t.verify(net), Err(ComputeAttestError::BadSignature));
        // attestor_id not derived from the key
        let mut t = att.clone();
        t.body.attestor_id = Hash64::from_bytes([9u8; 64]);
        assert_eq!(t.verify(net), Err(ComputeAttestError::AttestorIdMismatch));
        // wrong lengths
        let mut t = att.clone();
        t.attestor_pubkey.truncate(10);
        assert!(matches!(t.verify(net), Err(ComputeAttestError::BadPublicKeyLength(_))));
    }

    #[test]
    fn attestor_id_is_domain_separated() {
        let pk = vec![0x22u8; MIL_MLDSA87_PK_LEN];
        // keyed under compute-attest → differs from the unkeyed provider-id-style hash
        assert_ne!(attestor_id(&pk), crate::ident::provider_id(&pk));
    }
}
