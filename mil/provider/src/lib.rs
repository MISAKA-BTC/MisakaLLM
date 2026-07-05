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
pub mod backend;
pub mod backend_http;
pub mod client;
pub mod config;
pub mod service;
pub mod store;

pub use backend::{InferenceBackend, InferenceOutput, MockBackend, ResponseChunk};
pub use backend_http::{HttpBackend, ServingStack};
pub use client::{ClientError, PromptResult, RequesterClient, dev_attestation_verifier, pinned_attestation_verifier};
pub use config::{ProviderContext, ServingConfig};
pub use service::{SessionError, SessionOutcome, provider_identity, serve_session, serve_sticky_session};
pub use store::{ProviderStats, SessionRecord, aggregate, append_record, read_records, to_csv};
