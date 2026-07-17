//! MISAKA Inference Lane (MIL) v0 provider sidecar — library.
//!
//! Mirrors the `kaspa-pq-validator` split: this lib holds the reusable
//! pieces (backend trait + mock, provider identity/config, data-plane session
//! driver, requester client, and the on-chain anchor tx builders); the binary
//! (`src/main.rs`) is a thin clap CLI over them.
//!
//! ## v0 scope (design §2.4, §8.1, §11-P1)
//!
//! Permissioned testnet, no escrow: the data plane, the ML-KEM-1024 +
//! AES-256-GCM PQ channel, attestation verification, and the ML-DSA-87
//! cumulative Proof-of-Inference receipts are all real and exercised
//! end-to-end. Payment is direct-pay + reputation; escrow settlement is the
//! v1 EVM-lane job (§8.2). See [`misaka_mil_attest`] for the (structural,
//! pinned) v0 attestation-verification scope.

pub mod anchor_tx;
pub mod anon;
pub mod backend;
pub mod backend_http;
pub mod client;
pub mod config;
pub mod discover;
pub mod economics;
/// ADR-0039 PALW — K0 differential-determinism harness (run one job through N backends, check
/// byte-identical output, localize the first divergence). See the deterministic-kernel scope doc.
pub mod palw_determinism;
/// ADR-0039 Canonical Compute v1 §14 — the provider-side self-conformance gate: self-run the class's
/// committed vector set at startup, periodically, and on stack-fingerprint change; refuse registration on
/// any drift (fail-closed). Off-consensus. See `docs/design/misaka-canonical-compute-v1.md`.
pub mod palw_conformance_gate;
pub mod palw_replica;
/// ADR-0039 PALW — real local Qwen inference backend (candle GGUF-quantized) implementing the frozen
/// [`palw_replica::VerifiableInferenceBackend`] contract. Feature-gated (`qwen-backend`) so the default
/// build never pulls the candle/tokenizers stack.
#[cfg(feature = "qwen-backend")]
pub mod qwen_backend;
pub mod service;
pub mod store;

pub use backend::{InferenceBackend, InferenceOutput, MockBackend, ResponseChunk};
pub use backend_http::{HttpBackend, ServingStack};
pub use client::{ClientError, PromptResult, RequesterClient, dev_attestation_verifier, pinned_attestation_verifier};
pub use config::{ProviderContext, ServingConfig};
pub use economics::{
    AskFloor, GuardDecision, MicroUsd, ProviderMode, QuoteError, StandbyController, WHOLE_SOMPI_GROSS_STEP, checked_gross_sompi,
    checked_quantize_gross_up, is_whole_sompi_gross, quantize_gross_up, served_gross_sompi,
};
pub use anon::{AnonSessionOutcome, provider_identity_anon, serve_session_anon};
pub use service::{SessionError, SessionOutcome, provider_identity, serve_session, serve_sticky_session};
pub use store::{ProviderStats, SessionRecord, aggregate, append_record, read_records, to_csv};
