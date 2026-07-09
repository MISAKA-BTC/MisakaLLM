//! NVIDIA GPU Confidential Computing attestation (Hopper H100 / H200) — the
//! cryptographic verifier for [`crate::bundle::AttestationBundle::gpu_evidence`]
//! (the "P2 cryptographically verified" upgrade the bundle doc calls out; v0
//! hash-pinned only).
//!
//! For a confidential *inference* provider the load-bearing evidence is the
//! **GPU** attestation: the model weights and activations live on the GPU, so
//! only a GPU-CC quote proves the inference actually ran inside the confidential
//! boundary. This module verifies that quote off-line (no enclave, no network),
//! so it runs on any host — the real enclave that *produces* the quote needs
//! H100/H200-class hardware, but the *verifier* does not.
//!
//! ## The NVIDIA GPU-CC evidence (design §3.6, grounded on `NVIDIA/nvtrust`)
//!
//! An H100 confidential GPU answers an attestation challenge with:
//! - a **DMTF SPDM 1.1 MEASUREMENTS** response: 64 structured measurement
//!   records (firmware / VBIOS / driver / config hashes), signed by the GPU's
//!   per-reset **Attestation Key (AK)**;
//! - a **5-certificate chain** — AK cert → Device-Identity cert (both read from
//!   the GPU) → Provisioner → Model → **Root** — anchored at NVIDIA's GPU
//!   Attestation Root CA. All links are **ECDSA ES384 (NIST P-384 / SHA-384)**;
//! - the verifier's **nonce**, echoed into the signed report for freshness.
//!
//! MISAKA sets that nonce to the session key binding
//! (`key_binding(pk_kem, pk_receipt)` = [`crate::bundle::AttestationBundle::report_data`]),
//! so a valid GPU quote proves *this* GPU, running *these* measured components,
//! holds *this* session's PQ keys — closing the enclave-key-substitution / MITM
//! gap for the GPU exactly as [`crate::verify::common_checks`] does for the CPU.
//!
//! ## Scope (v0 — same honest boundary as [`crate::vendor`] / [`crate::tdx`])
//!
//! This module does the **real crypto trust decision**: every ES384 link on the
//! 5-cert chain verifies, the AK signs the report+nonce, and the root key hash
//! matches a governance pin. What a production collector adds on top is the
//! *extraction glue* that pulls the SPDM body, the DER certs and the raw
//! signatures out of NVIDIA's on-wire evidence into [`NvidiaGpuEvidence`]
//! (base64/DER decode + SPDM field offsets — proprietary, calibrated against a
//! real H100 sample), plus the **online OCSP** revocation check NVIDIA hosts.
//! Neither weakens the trust decision below; they feed it.

use crate::vendor::{SigCurve, VendorCert, VendorCertChain, VendorChainError};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash64;

/// SPDM measurement records in an H100/H200 attestation report (fixed shape so
/// the anonymity/measurement surface is uniform across providers).
pub const NVIDIA_SPDM_MEASUREMENT_RECORDS: usize = 64;

/// Certificates in the NVIDIA GPU attestation chain: AK, Device-Identity,
/// Provisioner, Model, Root (leaf → root).
pub const NVIDIA_CERT_CHAIN_LEN: usize = 5;

/// One link of the GPU cert chain: the cert's subject public key (SEC1) and the
/// signature its **issuer** (the next cert up) made over that subject key. The
/// root link carries its self-signature. Mirrors [`crate::vendor::VendorCert`]
/// but is borsh-encodable for transport inside `gpu_evidence`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NvidiaCertLink {
    pub subject_pubkey_sec1: Vec<u8>,
    pub issuer_signature: Vec<u8>,
}

/// Structured NVIDIA GPU-CC attestation evidence — the canonical decoding of
/// [`crate::bundle::AttestationBundle::gpu_evidence`]. A production collector
/// builds this from the GPU's raw SPDM+DER evidence; this crate verifies it.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NvidiaGpuEvidence {
    pub version: u16,
    /// The SPDM 1.1 MEASUREMENTS response body the AK signed (64 records). Opaque
    /// bytes here; `gpu_measurement` is the collector's digest over it.
    pub spdm_report: Vec<u8>,
    /// Challenge nonce echoed into the signed report; MUST equal the bundle's
    /// `report_data` (= session key binding). This is the anti-replay / anti-MITM
    /// tie between the GPU quote and the PQ session.
    pub nonce: Hash64,
    /// Collector digest over the 64 measurement records, compared against the
    /// registry/RIM golden pin (driver + VBIOS + firmware). Pinning this rejects
    /// a genuine GPU running an unapproved firmware/driver.
    pub gpu_measurement: Hash64,
    /// Leaf → root, exactly [`NVIDIA_CERT_CHAIN_LEN`] links. `cert_chain[0]` is
    /// the AK cert whose key verifies `report_signature`; `cert_chain.last()` is
    /// the NVIDIA GPU Attestation Root, whose key hash must match a pin.
    pub cert_chain: Vec<NvidiaCertLink>,
    /// The AK's ES384 signature over [`Self::signed_body`].
    pub report_signature: Vec<u8>,
}

impl NvidiaGpuEvidence {
    /// The exact bytes the AK signs: `spdm_report ‖ nonce`. Binding the nonce
    /// into the signed body is what makes the quote fresh and session-bound.
    pub fn signed_body(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(self.spdm_report.len() + 64);
        m.extend_from_slice(&self.spdm_report);
        m.extend_from_slice(self.nonce.as_byte_slice());
        m
    }

    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialization of in-memory evidence is infallible")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NvidiaAttestError> {
        Self::try_from_slice(bytes).map_err(|e| NvidiaAttestError::Malformed(e.to_string()))
    }
}

/// NVIDIA GPU-CC verification failures. Every path is fail-closed: a caller that
/// gets `Ok(())` has a cryptographically valid, session-bound, pinned-root,
/// approved-measurement GPU quote.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NvidiaAttestError {
    #[error("malformed NVIDIA GPU evidence: {0}")]
    Malformed(String),
    #[error("GPU cert chain has {got} certs, expected 5 (AK/device/provisioner/model/root)")]
    BadChainLength { got: usize },
    #[error("GPU quote nonce does not equal the session report_data (stale or unbound quote)")]
    NonceMismatch,
    #[error("GPU measurement differs from the pinned RIM golden value")]
    MeasurementMismatch,
    #[error("GPU attestation chain did not verify to a pinned NVIDIA root: {0}")]
    Chain(#[from] VendorChainError),
    #[error("no NVIDIA root is pinned, but GPU-CC is required")]
    NoRootPinned,
}

/// Verify an NVIDIA GPU-CC quote off-line.
///
/// - `expected_nonce` is the session binding (`report_data` =
///   `key_binding(pk_kem, pk_receipt)`); the quote's nonce must equal it.
/// - `nvidia_root_pins` are governance-pinned NVIDIA GPU-Attestation-Root key
///   hashes ([`crate::vendor::root_pin`]).
/// - `expected_gpu_measurement`, when `Some`, is the RIM golden digest the quote
///   must match.
///
/// On `Ok(())` the AK signed `spdm_report ‖ nonce`, the 5-cert ES384 chain
/// verifies AK → … → a pinned NVIDIA root, and the measurement matches the pin.
pub fn verify_nvidia_gpu_cc(
    evidence: &NvidiaGpuEvidence,
    expected_nonce: Hash64,
    nvidia_root_pins: &[Hash64],
    expected_gpu_measurement: Option<Hash64>,
) -> Result<(), NvidiaAttestError> {
    if nvidia_root_pins.is_empty() {
        return Err(NvidiaAttestError::NoRootPinned);
    }
    if evidence.cert_chain.len() != NVIDIA_CERT_CHAIN_LEN {
        return Err(NvidiaAttestError::BadChainLength { got: evidence.cert_chain.len() });
    }
    // Freshness + session binding: the GPU quote is worthless to an attacker who
    // cannot make the GPU echo *this* session's report_data as the nonce.
    if evidence.nonce != expected_nonce {
        return Err(NvidiaAttestError::NonceMismatch);
    }
    // RIM golden-measurement pin (approved firmware/VBIOS/driver).
    if let Some(pin) = expected_gpu_measurement
        && evidence.gpu_measurement != pin
    {
        return Err(NvidiaAttestError::MeasurementMismatch);
    }
    // Real ES384 chain-of-trust: AK signs the report+nonce, every link is signed
    // by its parent, and the root key hash matches a pin.
    let chain = VendorCertChain {
        curve: SigCurve::P384,
        message: evidence.signed_body(),
        leaf_signature: evidence.report_signature.clone(),
        certs: evidence
            .cert_chain
            .iter()
            .map(|l| VendorCert { subject_pubkey_sec1: l.subject_pubkey_sec1.clone(), issuer_signature: l.issuer_signature.clone() })
            .collect(),
    };
    chain.verify(nvidia_root_pins)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::root_pin;
    use p384::ecdsa::signature::Signer as _;
    use p384::ecdsa::{Signature, SigningKey};

    fn key(seed: u8) -> (Vec<u8>, SigningKey) {
        let sk = SigningKey::from_slice(&[seed; 48]).expect("valid P-384 scalar");
        let vk = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        (vk, sk)
    }
    fn sign(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = sk.sign(msg);
        sig.to_der().as_bytes().to_vec()
    }

    /// Build a fully valid GPU-CC quote: a real 5-cert ES384 chain (AK ← Device
    /// ← Provisioner ← Model ← Root) with the AK signing `spdm_report ‖ nonce`.
    /// Returns the evidence and the pinned root hash.
    fn synth(nonce: Hash64, measurement: Hash64) -> (NvidiaGpuEvidence, Hash64) {
        let (ak_vk, ak_sk) = key(1);
        let (dev_vk, dev_sk) = key(2);
        let (prov_vk, prov_sk) = key(3);
        let (model_vk, model_sk) = key(4);
        let (root_vk, root_sk) = key(5);

        let spdm_report = vec![0xA5u8; 64 * 40]; // 64 records, ~40B each (opaque here)
        let mut ev = NvidiaGpuEvidence {
            version: 1,
            spdm_report,
            nonce,
            gpu_measurement: measurement,
            cert_chain: vec![],
            report_signature: vec![],
        };
        // AK signs the report+nonce.
        ev.report_signature = sign(&ak_sk, &ev.signed_body());
        // Each cert's issuer signs the subject key; root self-signs.
        ev.cert_chain = vec![
            NvidiaCertLink { subject_pubkey_sec1: ak_vk.clone(), issuer_signature: sign(&dev_sk, &ak_vk) },
            NvidiaCertLink { subject_pubkey_sec1: dev_vk.clone(), issuer_signature: sign(&prov_sk, &dev_vk) },
            NvidiaCertLink { subject_pubkey_sec1: prov_vk.clone(), issuer_signature: sign(&model_sk, &prov_vk) },
            NvidiaCertLink { subject_pubkey_sec1: model_vk.clone(), issuer_signature: sign(&root_sk, &model_vk) },
            NvidiaCertLink { subject_pubkey_sec1: root_vk.clone(), issuer_signature: sign(&root_sk, &root_vk) },
        ];
        (ev, root_pin(&root_vk))
    }

    fn nonce() -> Hash64 {
        Hash64::from_bytes([0x7Eu8; 64])
    }
    fn meas() -> Hash64 {
        Hash64::from_bytes([0x3Cu8; 64])
    }

    #[test]
    fn valid_gpu_quote_verifies_and_roundtrips() {
        let (ev, pin) = synth(nonce(), meas());
        // borsh roundtrip (transport form)
        assert_eq!(NvidiaGpuEvidence::decode(&ev.encode()).unwrap(), ev);
        verify_nvidia_gpu_cc(&ev, nonce(), &[pin], Some(meas())).expect("valid GPU-CC quote must verify");
        // measurement pin optional
        verify_nvidia_gpu_cc(&ev, nonce(), &[pin], None).expect("no measurement pin is still valid");
    }

    #[test]
    fn wrong_session_nonce_is_rejected() {
        let (ev, pin) = synth(nonce(), meas());
        // A quote bound to a different session (or replayed) must not verify.
        let other = Hash64::from_bytes([0x11u8; 64]);
        assert_eq!(verify_nvidia_gpu_cc(&ev, other, &[pin], None), Err(NvidiaAttestError::NonceMismatch));
    }

    #[test]
    fn unapproved_measurement_is_rejected() {
        let (ev, pin) = synth(nonce(), meas());
        let bad = Hash64::from_bytes([0xFFu8; 64]);
        assert_eq!(verify_nvidia_gpu_cc(&ev, nonce(), &[pin], Some(bad)), Err(NvidiaAttestError::MeasurementMismatch));
    }

    #[test]
    fn unpinned_root_is_rejected() {
        let (ev, _pin) = synth(nonce(), meas());
        let wrong = root_pin(b"not the nvidia root");
        assert_eq!(verify_nvidia_gpu_cc(&ev, nonce(), &[wrong], None), Err(NvidiaAttestError::Chain(VendorChainError::RootNotPinned)));
        // no pin at all is fail-closed
        assert_eq!(verify_nvidia_gpu_cc(&ev, nonce(), &[], None), Err(NvidiaAttestError::NoRootPinned));
    }

    #[test]
    fn tampered_report_breaks_the_ak_signature() {
        let (mut ev, pin) = synth(nonce(), meas());
        ev.spdm_report[0] ^= 1; // AK signature no longer covers this body
        assert_eq!(
            verify_nvidia_gpu_cc(&ev, nonce(), &[pin], None),
            Err(NvidiaAttestError::Chain(VendorChainError::LeafSignatureInvalid))
        );
    }

    #[test]
    fn broken_chain_link_is_caught() {
        let (mut ev, pin) = synth(nonce(), meas());
        ev.cert_chain[1].issuer_signature[7] ^= 1;
        assert_eq!(
            verify_nvidia_gpu_cc(&ev, nonce(), &[pin], None),
            Err(NvidiaAttestError::Chain(VendorChainError::LinkInvalid { index: 1 }))
        );
    }

    #[test]
    fn wrong_chain_length_is_rejected() {
        let (mut ev, pin) = synth(nonce(), meas());
        ev.cert_chain.pop(); // 4 certs, not 5
        assert_eq!(verify_nvidia_gpu_cc(&ev, nonce(), &[pin], None), Err(NvidiaAttestError::BadChainLength { got: 4 }));
    }

    /// End-to-end through the real Tier-1 verifier: a bundle whose GPU evidence
    /// is bound (via the nonce) to the same session keys `common_checks` ties to
    /// `report_data` must pass `require_gpu_cc`, and fail closed when the GPU
    /// root is unpinned, the evidence is missing, or the session differs.
    #[test]
    fn tier1_require_gpu_cc_end_to_end() {
        use crate::bundle::AttestationBundle;
        use crate::verify::{AttestError, ExpectedMeasurements, QuoteVerifier, Tier1QuoteVerifier};
        use misaka_mil_core::ident::key_binding;

        const NOW: u64 = 1_780_000_000_000;
        let (pk_kem, pk_receipt) = (vec![0x11u8; 1568], vec![0x22u8; 2592]);
        let session = key_binding(&pk_kem, &pk_receipt); // = report_data = GPU nonce
        let (ev, root) = synth(session, meas());

        let m = crate::bundle::Measurements {
            runtime_image_hash: Hash64::from_bytes([1u8; 64]),
            model_manifest_hash: Hash64::from_bytes([2u8; 64]),
        };
        let mut bundle = AttestationBundle::dev(m, session, NOW - 1000);
        bundle.gpu_evidence = ev.encode();

        let mut expected = ExpectedMeasurements {
            runtime_image_hash: Hash64::from_bytes([1u8; 64]),
            model_manifest_hash: Hash64::from_bytes([2u8; 64]),
            vendor_root_pins: vec![],
            max_age_ms: 3_600_000,
            expected_mr_td: None,
            expected_snp_measurement: None,
            allow_dev_platform: true, // isolate the GPU path (Dev CPU + real GPU quote)
            require_gpu_cc: true,
            nvidia_root_pins: vec![root],
            expected_gpu_measurement: Some(meas()),
        };

        // valid: real GPU quote, session-bound, pinned root, approved measurement
        Tier1QuoteVerifier.verify(&bundle.encode(), &pk_kem, &pk_receipt, &expected, NOW).expect("GPU-CC bundle must verify");

        // unpinned GPU root fails closed
        expected.nvidia_root_pins = vec![crate::vendor::root_pin(b"wrong root")];
        assert!(matches!(
            Tier1QuoteVerifier.verify(&bundle.encode(), &pk_kem, &pk_receipt, &expected, NOW),
            Err(AttestError::NvidiaGpuCc(NvidiaAttestError::Chain(VendorChainError::RootNotPinned)))
        ));
        expected.nvidia_root_pins = vec![root];

        // missing GPU evidence when required fails closed
        let mut no_gpu = bundle.clone();
        no_gpu.gpu_evidence = vec![];
        assert_eq!(
            Tier1QuoteVerifier.verify(&no_gpu.encode(), &pk_kem, &pk_receipt, &expected, NOW),
            Err(AttestError::GpuEvidenceMissing)
        );

        // a GPU quote minted for a *different* session (its nonce ≠ this
        // report_data) cannot be replayed here
        let (ev_other, root2) = synth(Hash64::from_bytes([0x99u8; 64]), meas());
        let mut replayed = bundle.clone();
        replayed.gpu_evidence = ev_other.encode();
        expected.nvidia_root_pins = vec![root2];
        assert!(matches!(
            Tier1QuoteVerifier.verify(&replayed.encode(), &pk_kem, &pk_receipt, &expected, NOW),
            Err(AttestError::NvidiaGpuCc(NvidiaAttestError::NonceMismatch))
        ));
    }
}
