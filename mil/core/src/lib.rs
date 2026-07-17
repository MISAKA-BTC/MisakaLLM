//! MISAKA Inference Lane (MIL) — core protocol primitives.
//!
//! MIL is the decentralized GPU inference layer over misakas (design doc
//! `MIL-design-v0.3.md`): GPU providers run the pinned MIL-Core model (in a TEE
//! for Tier 1) and sell inference for MSK; prompts/responses are end-to-end
//! encrypted with ML-KEM-1024 + AES-256-GCM; the chain only ever sees Hash64
//! commitments and ML-DSA-87-signed cumulative receipts.
//!
//! This crate is the dependency-light shared core, used by both the provider
//! sidecar and requester SDKs:
//!
//! - [`domains`] — every `misaka-mil-v1/...` domain-separation constant
//! - [`ident`]  — enclave key binding, session ids, provider ids (§3.2)
//! - [`commit`] — request commitments `cm_req` and the response transcript
//!   hash `cm_resp` (§3.3)
//! - [`receipt`] — the cumulative Proof-of-Inference receipt: ML-DSA-87
//!   signing, verification, and chain monotonicity (§4.1)
//! - [`model`] — `model_id` / `profile_id` and the model registry entry (§7.1,
//!   §18.2)
//! - [`job`] — the job spec incl. the Tier-2 determinism profile (§7.4)
//! - [`params`] — protocol parameters (§10) and the pure reward math: fee
//!   split 88/5/4/3 and the epoch bootstrap-pool distribution (§5.3–§5.4)
//! - [`anchor`] — v0 on-chain anchor payloads carried in native-tx payloads
//!   (§8.1)
//!
//! No consensus surface: everything here is overlay/application layer. The
//! only chain-visible artifacts are the anchor payloads, which ride ordinary
//! NATIVE transactions.

pub mod anchor;
pub mod canary;
pub mod commit;
pub mod compute_attest;
pub mod domains;
pub mod gov;
pub mod ident;
pub mod job;
pub mod model;
pub mod padding;
pub mod palw;
/// ADR-0039 Canonical Compute v1 §3–§10 / §15 Level 3 — the platform-independent INTEGER reference (the K1
/// oracle + Level-3 arithmetic core). See `docs/design/misaka-canonical-compute-v1.md`.
pub mod palw_canonical;
pub mod params;
pub mod receipt;

pub use kaspa_hashes::Hash64;
