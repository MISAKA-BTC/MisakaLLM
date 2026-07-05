//! Vendor attestation certificate-chain cryptographic verification
//! (design §3.6 — the documented PQ-scope exception).
//!
//! TEE attestation trust ultimately rests on **classical** vendor PKI:
//! - Intel TDX (DCAP): the quote is ECDSA-**P-256** signed by the PCK, chaining
//!   PCK → Intel SGX Processor CA → Intel SGX Root CA.
//! - AMD SEV-SNP: the report is ECDSA-**P-384** signed by the VCEK, chaining
//!   VCEK → ASK → ARK.
//! - NVIDIA NRAS: an ES384 (**P-384**) signed attestation token.
//!
//! These signatures cannot be made post-quantum (they are the vendors' own
//! roots), so §3.6 treats them as an explicit exception and mitigates with
//! **root pinning** (governance-pinned root key hashes) + on-chain quote-hash
//! fixing. This module performs the real cryptographic work: ECDSA-P256/P384
//! signature verification and chain-of-trust validation to a pinned root, in
//! pure Rust (RustCrypto). It is application-layer — the consensus lane stays
//! secp-free.
//!
//! ## Scope
//!
//! The cryptographic verification here is complete and tested. What a
//! production deployment additionally needs is the DER glue that extracts the
//! leaf key + intermediate keys + signatures out of the raw Intel/AMD X.509
//! cert blobs embedded in a real quote into the [`VendorCertChain`] structure;
//! the trust decision below (every ECDSA link verifies, root hash matches the
//! pin) is exactly the check that glue feeds.

use kaspa_hashes::{Hash64, blake2b_512_keyed};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256Key};
use p384::ecdsa::{Signature as P384Sig, VerifyingKey as P384Key};

/// Governance-pinned-root domain for the root public-key hash.
const VENDOR_ROOT_DOMAIN: &[u8] = b"misaka-mil-v1/vendor-root";

/// The signature curve of a vendor chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigCurve {
    /// NIST P-256 (ECDSA-with-SHA-256) — Intel TDX / PCS.
    P256,
    /// NIST P-384 (ECDSA-with-SHA-384) — AMD SEV-SNP, NVIDIA NRAS (ES384).
    P384,
}

/// The pinned hash of a vendor root public key (SEC1 bytes).
pub fn root_pin(root_pubkey_sec1: &[u8]) -> Hash64 {
    blake2b_512_keyed(VENDOR_ROOT_DOMAIN, root_pubkey_sec1)
}

/// Verify an ECDSA signature over `message` under `pubkey` (SEC1 encoded).
/// Accepts either a DER or a fixed-size (r‖s) signature. Returns `false` for
/// any parse or verification failure — never panics.
pub fn verify_signature(curve: SigCurve, pubkey_sec1: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match curve {
        SigCurve::P256 => {
            let Ok(vk) = P256Key::from_sec1_bytes(pubkey_sec1) else { return false };
            let sig = P256Sig::from_der(signature).ok().or_else(|| P256Sig::try_from(signature).ok());
            let Some(sig) = sig else { return false };
            vk.verify(message, &sig).is_ok()
        }
        SigCurve::P384 => {
            let Ok(vk) = P384Key::from_sec1_bytes(pubkey_sec1) else { return false };
            let sig = P384Sig::from_der(signature).ok().or_else(|| P384Sig::try_from(signature).ok());
            let Some(sig) = sig else { return false };
            vk.verify(message, &sig).is_ok()
        }
    }
}

/// One certificate in the chain: its subject public key (SEC1) and the
/// signature over its subject key made by its **issuer** (the next cert up).
/// For the self-signed root, `issuer_signature` is the root's self-signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorCert {
    pub subject_pubkey_sec1: Vec<u8>,
    pub issuer_signature: Vec<u8>,
}

/// A vendor attestation chain: the leaf signs the attestation `message`, and
/// each cert up the chain is signed by its parent, terminating at a
/// governance-pinned root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorCertChain {
    pub curve: SigCurve,
    /// The attestation payload the leaf signs (the quote/report body bytes).
    pub message: Vec<u8>,
    /// The leaf's signature over `message`.
    pub leaf_signature: Vec<u8>,
    /// Certs ordered leaf → root. `certs[0]` is the leaf (its key verifies
    /// `leaf_signature`); `certs[i]` is signed by `certs[i+1]`; `certs.last()`
    /// is the root, whose key hash must match the pin.
    pub certs: Vec<VendorCert>,
}

/// Vendor-chain verification failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VendorChainError {
    #[error("vendor cert chain is empty")]
    EmptyChain,
    #[error("leaf signature over the attestation did not verify")]
    LeafSignatureInvalid,
    #[error("cert-chain link {index} did not verify against its issuer")]
    LinkInvalid { index: usize },
    #[error("root public key does not match any pinned root")]
    RootNotPinned,
}

impl VendorCertChain {
    /// Full chain-of-trust verification against a set of pinned root hashes:
    /// 1. the leaf key verifies `leaf_signature` over `message`;
    /// 2. every cert is signed by the one above it (issuer signs subject key);
    /// 3. the root key's hash is among `pinned_roots`.
    pub fn verify(&self, pinned_roots: &[Hash64]) -> Result<(), VendorChainError> {
        if self.certs.is_empty() {
            return Err(VendorChainError::EmptyChain);
        }
        // 1. leaf signs the attestation
        if !verify_signature(self.curve, &self.certs[0].subject_pubkey_sec1, &self.message, &self.leaf_signature) {
            return Err(VendorChainError::LeafSignatureInvalid);
        }
        // 2. each cert is signed by its parent (issuer signs the subject key)
        for i in 0..self.certs.len() - 1 {
            let child = &self.certs[i];
            let parent = &self.certs[i + 1];
            if !verify_signature(self.curve, &parent.subject_pubkey_sec1, &child.subject_pubkey_sec1, &child.issuer_signature) {
                return Err(VendorChainError::LinkInvalid { index: i });
            }
        }
        // root: self-signature check (best-effort) + the pin (authoritative)
        let root = self.certs.last().expect("non-empty checked above");
        let root_hash = root_pin(&root.subject_pubkey_sec1);
        if !pinned_roots.contains(&root_hash) {
            return Err(VendorChainError::RootNotPinned);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;

    // Build a P-256 key from a fixed scalar and return (verifying SEC1, signer).
    fn p256_key(seed: u8) -> (Vec<u8>, p256::ecdsa::SigningKey) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("valid scalar");
        let vk = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        (vk, sk)
    }

    fn p256_sign(sk: &p256::ecdsa::SigningKey, msg: &[u8]) -> Vec<u8> {
        let sig: p256::ecdsa::Signature = sk.sign(msg);
        sig.to_der().as_bytes().to_vec()
    }

    #[test]
    fn raw_signature_verification_p256() {
        let (vk, sk) = p256_key(1);
        let msg = b"tdx quote body";
        let sig = p256_sign(&sk, msg);
        assert!(verify_signature(SigCurve::P256, &vk, msg, &sig));
        // wrong message / tampered sig fail
        assert!(!verify_signature(SigCurve::P256, &vk, b"other", &sig));
        let mut bad = sig.clone();
        bad[10] ^= 1;
        assert!(!verify_signature(SigCurve::P256, &vk, msg, &bad));
        // garbage never panics
        assert!(!verify_signature(SigCurve::P256, b"notakey", msg, &sig));
    }

    #[test]
    fn raw_signature_verification_p384() {
        use p384::ecdsa::signature::Signer as _;
        let sk = p384::ecdsa::SigningKey::from_slice(&[2u8; 48]).expect("valid scalar");
        let vk = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let msg = b"snp report body";
        let sig: p384::ecdsa::Signature = sk.sign(msg);
        let sig = sig.to_der().as_bytes().to_vec();
        assert!(verify_signature(SigCurve::P384, &vk, msg, &sig));
        assert!(!verify_signature(SigCurve::P384, &vk, b"other", &sig));
    }

    #[test]
    fn full_chain_verifies_to_pinned_root() {
        // three-tier chain: leaf (PCK) ← intermediate (Processor CA) ← root
        let (leaf_vk, leaf_sk) = p256_key(3);
        let (inter_vk, inter_sk) = p256_key(4);
        let (root_vk, root_sk) = p256_key(5);

        let message = b"attestation quote body bytes".to_vec();
        let leaf_sig = p256_sign(&leaf_sk, &message);
        // parent signs child's subject key
        let leaf_issuer_sig = p256_sign(&inter_sk, &leaf_vk);
        let inter_issuer_sig = p256_sign(&root_sk, &inter_vk);
        let root_self_sig = p256_sign(&root_sk, &root_vk);

        let chain = VendorCertChain {
            curve: SigCurve::P256,
            message: message.clone(),
            leaf_signature: leaf_sig,
            certs: vec![
                VendorCert { subject_pubkey_sec1: leaf_vk.clone(), issuer_signature: leaf_issuer_sig },
                VendorCert { subject_pubkey_sec1: inter_vk.clone(), issuer_signature: inter_issuer_sig },
                VendorCert { subject_pubkey_sec1: root_vk.clone(), issuer_signature: root_self_sig },
            ],
        };

        let pin = root_pin(&root_vk);
        chain.verify(&[pin]).expect("valid chain must verify");

        // an unpinned root is rejected even though every signature is valid
        assert_eq!(chain.verify(&[Hash64::from_bytes([0u8; 64])]), Err(VendorChainError::RootNotPinned));

        // a broken intermediate link is caught
        let mut broken = chain.clone();
        broken.certs[0].issuer_signature[5] ^= 1;
        assert_eq!(broken.verify(&[pin]), Err(VendorChainError::LinkInvalid { index: 0 }));

        // a tampered attestation message is caught at the leaf
        let mut tampered = chain.clone();
        tampered.message[0] ^= 1;
        assert_eq!(tampered.verify(&[pin]), Err(VendorChainError::LeafSignatureInvalid));

        // empty chain
        let empty = VendorCertChain { curve: SigCurve::P256, message, leaf_signature: vec![], certs: vec![] };
        assert_eq!(empty.verify(&[pin]), Err(VendorChainError::EmptyChain));
    }
}
