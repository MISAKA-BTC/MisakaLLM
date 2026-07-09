//! MIL attestation verification (design §3.2, §3.6).
//!
//! A provider presents an [`bundle::AttestationBundle`]: platform quote (Intel
//! TDX or AMD SEV-SNP), opaque GPU evidence (NVIDIA NRAS token), the claimed
//! measurements, and the `report_data` that must equal the enclave key binding
//! `Hash64_k("misaka-mil-v1/bind" ‖ pk_kem ‖ pk_receipt)`.
//!
//! ## v0 verification scope — read this before trusting anything
//!
//! The verifiers here perform **structural + pinning** verification:
//!
//! - binary structure of the TDX v4 quote / SNP attestation report
//!   ([`tdx`], [`snp`]) with hard offset/length/type checks,
//! - `report_data` ↔ key-binding equality (kills enclave key substitution),
//! - measurement equality against registry-pinned expected values,
//! - vendor certificate-chain **hash pinning** (§3.6b) and bundle freshness.
//!
//! What v0 does **not** do: vendor signature-chain cryptographic validation
//! (Intel PCS / AMD KDS / NVIDIA NRAS JWT). That chain is classical ECDSA
//! P-384 — the explicitly documented PQ-scope exception (§3.6) — and lands in
//! P2 with the real TEE hardware. Until then Tier 1 trust is *pinned*, not
//! *proven*: exactly the permissioned-v0 posture (§8.1). The
//! [`verify::DevQuoteVerifier`] is for Tier-2/loopback development, where the
//! quote is self-declared.

pub mod bundle;
pub mod cache;
pub mod nvidia;
pub mod snp;
pub mod tdx;
pub mod vendor;
pub mod verify;

pub use bundle::{AttestationBundle, Measurements, TeePlatform};
pub use cache::AttestationCache;
pub use vendor::{SigCurve, VendorCert, VendorCertChain, VendorChainError, root_pin, verify_signature};
pub use verify::{AttestError, DevQuoteVerifier, ExpectedMeasurements, QuoteVerifier, Tier1QuoteVerifier, VerifiedAttestation};
