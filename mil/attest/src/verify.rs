//! Quote verification against registry pins (design §2.3 step 3, §3.6).

use crate::bundle::{AttestationBundle, Measurements, TeePlatform};
use crate::snp::parse_snp_report;
use crate::tdx::parse_tdx_quote;
use kaspa_hashes::Hash64;
use misaka_mil_core::domains::MIL_PROTOCOL_VERSION;
use misaka_mil_core::ident::key_binding;

/// What the verifier demands, sourced from the (v0: configured; v1:
/// on-chain) registry entry for this provider/model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedMeasurements {
    /// Registry-pinned measured runtime image (§7.1).
    pub runtime_image_hash: Hash64,
    /// Registry-pinned weights-manifest hash (§7.1).
    pub model_manifest_hash: Hash64,
    /// Governance-pinned vendor root-chain hashes (§3.6b). Empty = only the
    /// Dev platform is acceptable.
    pub vendor_root_pins: Vec<Hash64>,
    /// Maximum bundle age in milliseconds (attestation epoch, §13.3).
    pub max_age_ms: u64,
    /// TDX: expected `mr_td` (launch measurement), if pinned.
    pub expected_mr_td: Option<[u8; 48]>,
    /// SNP: expected launch `measurement`, if pinned.
    pub expected_snp_measurement: Option<[u8; 48]>,
    /// Whether the self-declared Dev platform is acceptable (v0 Tier-2 /
    /// loopback only; must be `false` for anything Tier-1).
    pub allow_dev_platform: bool,
}

/// Successful verification output — what the SDK caches per §13.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub quote_hash: Hash64,
    pub platform: TeePlatform,
    pub measurements: Measurements,
    /// When this verification was performed (caller clock, unix ms).
    pub verified_at_ms: u64,
    /// When the bundle stops being acceptable (issued_at + max_age).
    pub expires_at_ms: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestError {
    #[error("malformed attestation bundle: {0}")]
    MalformedBundle(String),
    #[error("unsupported bundle version {0}")]
    UnsupportedVersion(u16),
    #[error("platform {0:?} is not acceptable under this policy")]
    PlatformNotAllowed(TeePlatform),
    #[error("TDX quote invalid: {0}")]
    Tdx(#[from] crate::tdx::TdxParseError),
    #[error("SNP report invalid: {0}")]
    Snp(#[from] crate::snp::SnpParseError),
    #[error("quote report_data does not match the bundle's declared report_data")]
    QuoteReportDataMismatch,
    #[error("report_data does not bind the presented keys (enclave key substitution?)")]
    KeyBindingMismatch,
    #[error("runtime image measurement differs from the registry pin")]
    RuntimeImageMismatch,
    #[error("model manifest measurement differs from the registry pin")]
    ModelManifestMismatch,
    #[error("platform launch measurement differs from the pinned value")]
    LaunchMeasurementMismatch,
    #[error("vendor certificate chain hash is not among the pinned roots")]
    VendorChainNotPinned,
    #[error("bundle expired: issued {issued_at_ms}, now {now_ms}, max age {max_age_ms}")]
    Expired { issued_at_ms: u64, now_ms: u64, max_age_ms: u64 },
    #[error("bundle issued in the future: issued {issued_at_ms}, now {now_ms}")]
    FromTheFuture { issued_at_ms: u64, now_ms: u64 },
}

/// A quote verifier: bundle bytes + the peer's presented keys → verified
/// attestation. Implementations differ in how much of the platform evidence
/// they can actually check.
pub trait QuoteVerifier {
    fn verify(
        &self,
        bundle_bytes: &[u8],
        pk_kem: &[u8],
        pk_receipt: &[u8],
        expected: &ExpectedMeasurements,
        now_ms: u64,
    ) -> Result<VerifiedAttestation, AttestError>;
}

fn common_checks(
    bundle: &AttestationBundle,
    pk_kem: &[u8],
    pk_receipt: &[u8],
    expected: &ExpectedMeasurements,
    now_ms: u64,
) -> Result<(), AttestError> {
    if bundle.version != MIL_PROTOCOL_VERSION {
        return Err(AttestError::UnsupportedVersion(bundle.version));
    }
    // freshness window (small forward skew tolerated: 2 minutes)
    const MAX_FORWARD_SKEW_MS: u64 = 2 * 60 * 1000;
    if bundle.issued_at_ms > now_ms + MAX_FORWARD_SKEW_MS {
        return Err(AttestError::FromTheFuture { issued_at_ms: bundle.issued_at_ms, now_ms });
    }
    if now_ms.saturating_sub(bundle.issued_at_ms) > expected.max_age_ms {
        return Err(AttestError::Expired { issued_at_ms: bundle.issued_at_ms, now_ms, max_age_ms: expected.max_age_ms });
    }
    // the anti-MITM core: report_data must bind exactly the keys presented
    if bundle.report_data != key_binding(pk_kem, pk_receipt) {
        return Err(AttestError::KeyBindingMismatch);
    }
    // registry measurement pins
    if bundle.measurements.runtime_image_hash != expected.runtime_image_hash {
        return Err(AttestError::RuntimeImageMismatch);
    }
    if bundle.measurements.model_manifest_hash != expected.model_manifest_hash {
        return Err(AttestError::ModelManifestMismatch);
    }
    Ok(())
}

/// v0 development verifier: accepts only [`TeePlatform::Dev`] bundles, and
/// still enforces everything enforceable without hardware — the key binding,
/// measurement pins, and freshness. Trust here is the permissioned whitelist
/// (§8.1), not the quote.
#[derive(Debug, Default, Clone, Copy)]
pub struct DevQuoteVerifier;

impl QuoteVerifier for DevQuoteVerifier {
    fn verify(
        &self,
        bundle_bytes: &[u8],
        pk_kem: &[u8],
        pk_receipt: &[u8],
        expected: &ExpectedMeasurements,
        now_ms: u64,
    ) -> Result<VerifiedAttestation, AttestError> {
        let bundle = AttestationBundle::decode(bundle_bytes).map_err(|e| AttestError::MalformedBundle(e.to_string()))?;
        if bundle.platform != TeePlatform::Dev || !expected.allow_dev_platform {
            return Err(AttestError::PlatformNotAllowed(bundle.platform));
        }
        common_checks(&bundle, pk_kem, pk_receipt, expected, now_ms)?;
        Ok(VerifiedAttestation {
            quote_hash: bundle.quote_hash(),
            platform: bundle.platform,
            measurements: bundle.measurements,
            verified_at_ms: now_ms,
            expires_at_ms: bundle.issued_at_ms.saturating_add(expected.max_age_ms),
        })
    }
}

/// Tier-1 verifier: structural platform-quote validation + report_data
/// cross-check + launch-measurement and vendor-chain pinning. See the crate
/// docs for the explicit v0 scope (no vendor signature-chain crypto yet).
#[derive(Debug, Default, Clone, Copy)]
pub struct Tier1QuoteVerifier;

impl QuoteVerifier for Tier1QuoteVerifier {
    fn verify(
        &self,
        bundle_bytes: &[u8],
        pk_kem: &[u8],
        pk_receipt: &[u8],
        expected: &ExpectedMeasurements,
        now_ms: u64,
    ) -> Result<VerifiedAttestation, AttestError> {
        let bundle = AttestationBundle::decode(bundle_bytes).map_err(|e| AttestError::MalformedBundle(e.to_string()))?;
        // platform evidence first: the quote's own report_data must equal the
        // bundle's declaration, then the common checks tie that to the keys.
        match bundle.platform {
            TeePlatform::IntelTdx => {
                let quote = parse_tdx_quote(&bundle.cpu_quote)?;
                if quote.report_data != *bundle.report_data.as_byte_slice() {
                    return Err(AttestError::QuoteReportDataMismatch);
                }
                if let Some(pin) = expected.expected_mr_td
                    && quote.mr_td != pin
                {
                    return Err(AttestError::LaunchMeasurementMismatch);
                }
            }
            TeePlatform::AmdSevSnp => {
                let report = parse_snp_report(&bundle.cpu_quote)?;
                if report.report_data != *bundle.report_data.as_byte_slice() {
                    return Err(AttestError::QuoteReportDataMismatch);
                }
                if let Some(pin) = expected.expected_snp_measurement
                    && report.measurement != pin
                {
                    return Err(AttestError::LaunchMeasurementMismatch);
                }
            }
            TeePlatform::Dev => {
                if !expected.allow_dev_platform {
                    return Err(AttestError::PlatformNotAllowed(TeePlatform::Dev));
                }
            }
        }
        if bundle.platform != TeePlatform::Dev && !expected.vendor_root_pins.contains(&bundle.vendor_chain_hash) {
            return Err(AttestError::VendorChainNotPinned);
        }
        common_checks(&bundle, pk_kem, pk_receipt, expected, now_ms)?;
        Ok(VerifiedAttestation {
            quote_hash: bundle.quote_hash(),
            platform: bundle.platform,
            measurements: bundle.measurements,
            verified_at_ms: now_ms,
            expires_at_ms: bundle.issued_at_ms.saturating_add(expected.max_age_ms),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdx::synth_tdx_quote;

    const NOW: u64 = 1_780_000_000_000;

    fn keys() -> (Vec<u8>, Vec<u8>) {
        (vec![0x11u8; 1568], vec![0x22u8; 2592])
    }

    fn measurements() -> Measurements {
        Measurements { runtime_image_hash: Hash64::from_bytes([1u8; 64]), model_manifest_hash: Hash64::from_bytes([2u8; 64]) }
    }

    fn expected(allow_dev: bool) -> ExpectedMeasurements {
        ExpectedMeasurements {
            runtime_image_hash: Hash64::from_bytes([1u8; 64]),
            model_manifest_hash: Hash64::from_bytes([2u8; 64]),
            vendor_root_pins: vec![Hash64::from_bytes([7u8; 64])],
            max_age_ms: 3_600_000,
            expected_mr_td: None,
            expected_snp_measurement: None,
            allow_dev_platform: allow_dev,
        }
    }

    fn dev_bundle(pk_kem: &[u8], pk_receipt: &[u8]) -> AttestationBundle {
        AttestationBundle::dev(measurements(), key_binding(pk_kem, pk_receipt), NOW - 1000)
    }

    #[test]
    fn dev_verifier_accepts_well_formed_bundle() {
        let (pk_kem, pk_receipt) = keys();
        let bundle = dev_bundle(&pk_kem, &pk_receipt);
        let v = DevQuoteVerifier.verify(&bundle.encode(), &pk_kem, &pk_receipt, &expected(true), NOW).unwrap();
        assert_eq!(v.quote_hash, bundle.quote_hash());
        assert_eq!(v.platform, TeePlatform::Dev);
        assert_eq!(v.expires_at_ms, bundle.issued_at_ms + 3_600_000);
    }

    #[test]
    fn dev_verifier_rejects_binding_and_measurement_mismatches() {
        let (pk_kem, pk_receipt) = keys();
        let bundle = dev_bundle(&pk_kem, &pk_receipt);
        let bytes = bundle.encode();

        // substituted KEM key → binding mismatch
        let evil_kem = vec![0x99u8; 1568];
        assert_eq!(
            DevQuoteVerifier.verify(&bytes, &evil_kem, &pk_receipt, &expected(true), NOW),
            Err(AttestError::KeyBindingMismatch)
        );

        // wrong runtime pin
        let mut exp = expected(true);
        exp.runtime_image_hash = Hash64::from_bytes([9u8; 64]);
        assert_eq!(DevQuoteVerifier.verify(&bytes, &pk_kem, &pk_receipt, &exp, NOW), Err(AttestError::RuntimeImageMismatch));

        // expired
        assert!(matches!(
            DevQuoteVerifier.verify(&bytes, &pk_kem, &pk_receipt, &expected(true), NOW + 4_000_000),
            Err(AttestError::Expired { .. })
        ));

        // dev platform disallowed (Tier-1 policy)
        assert_eq!(
            DevQuoteVerifier.verify(&bytes, &pk_kem, &pk_receipt, &expected(false), NOW),
            Err(AttestError::PlatformNotAllowed(TeePlatform::Dev))
        );
    }

    #[test]
    fn tier1_tdx_flow_checks_quote_fields() {
        let (pk_kem, pk_receipt) = keys();
        let binding = key_binding(&pk_kem, &pk_receipt);
        let mr_td = [0xADu8; 48];

        let mut bundle = AttestationBundle {
            version: misaka_mil_core::domains::MIL_PROTOCOL_VERSION,
            platform: TeePlatform::IntelTdx,
            cpu_quote: synth_tdx_quote(mr_td, [0u8; 48], binding.as_bytes()),
            gpu_evidence: b"nras-token".to_vec(),
            measurements: measurements(),
            report_data: binding,
            vendor_chain_hash: Hash64::from_bytes([7u8; 64]),
            issued_at_ms: NOW - 1000,
        };

        let mut exp = expected(false);
        exp.expected_mr_td = Some(mr_td);
        let v = Tier1QuoteVerifier.verify(&bundle.encode(), &pk_kem, &pk_receipt, &exp, NOW).unwrap();
        assert_eq!(v.platform, TeePlatform::IntelTdx);

        // pinned mr_td mismatch
        exp.expected_mr_td = Some([0x00u8; 48]);
        assert_eq!(
            Tier1QuoteVerifier.verify(&bundle.encode(), &pk_kem, &pk_receipt, &exp, NOW),
            Err(AttestError::LaunchMeasurementMismatch)
        );

        // quote report_data disagreeing with the bundle declaration
        exp.expected_mr_td = None;
        bundle.cpu_quote = synth_tdx_quote(mr_td, [0u8; 48], [0xFFu8; 64]);
        assert_eq!(
            Tier1QuoteVerifier.verify(&bundle.encode(), &pk_kem, &pk_receipt, &exp, NOW),
            Err(AttestError::QuoteReportDataMismatch)
        );

        // unpinned vendor chain
        bundle.cpu_quote = synth_tdx_quote(mr_td, [0u8; 48], binding.as_bytes());
        bundle.vendor_chain_hash = Hash64::from_bytes([8u8; 64]);
        assert_eq!(
            Tier1QuoteVerifier.verify(&bundle.encode(), &pk_kem, &pk_receipt, &exp, NOW),
            Err(AttestError::VendorChainNotPinned)
        );
    }

    #[test]
    fn tier1_snp_flow_checks_report_fields() {
        let (pk_kem, pk_receipt) = keys();
        let binding = key_binding(&pk_kem, &pk_receipt);
        let m = [0x5Eu8; 48];
        let bundle = AttestationBundle {
            version: misaka_mil_core::domains::MIL_PROTOCOL_VERSION,
            platform: TeePlatform::AmdSevSnp,
            cpu_quote: crate::snp::synth_snp_report(m, binding.as_bytes(), [0x77u8; 64]),
            gpu_evidence: Vec::new(),
            measurements: measurements(),
            report_data: binding,
            vendor_chain_hash: Hash64::from_bytes([7u8; 64]),
            issued_at_ms: NOW - 1000,
        };
        let mut exp = expected(false);
        exp.expected_snp_measurement = Some(m);
        let v = Tier1QuoteVerifier.verify(&bundle.encode(), &pk_kem, &pk_receipt, &exp, NOW).unwrap();
        assert_eq!(v.platform, TeePlatform::AmdSevSnp);

        exp.expected_snp_measurement = Some([0u8; 48]);
        assert_eq!(
            Tier1QuoteVerifier.verify(&bundle.encode(), &pk_kem, &pk_receipt, &exp, NOW),
            Err(AttestError::LaunchMeasurementMismatch)
        );
    }
}
