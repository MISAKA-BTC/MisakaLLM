//! misaka-palw — PALW (proof-of-LLM audited-compute PoW lane, ADR-0039) shared kernel
//! **and** the provider-side deterministic compute path.
//!
//! Extracted from `mil/core` (`domains`, `palw`) and `mil/provider` (`palw_replica`,
//! `palw_determinism`, `palw_conformance_gate`, `qwen_backend`) so the consensus crates
//! AND a PALW miner can depend on the algo-4 lane without pulling the MIL job-market
//! runtime (channel / attest) or any EVM / shielded surface. This is the "proof-of-LLM"
//! PoW lane only.
//!
//! * [`palw`] / [`domains`] — the compute-set / commitment types + domain constants
//!   (consumed by consensus-core; carries no heavy deps).
//! * [`palw_replica`] — the k=2 replica dispatch + the `VerifiableInferenceBackend`
//!   contract + the CPU-reference `MockDeterministicRuntime`.
//! * [`palw_determinism`] / [`palw_conformance_gate`] — the determinism + conformance
//!   checks a provider self-runs before it dispatches (no heavy deps).
//! * [`qwen_backend`] — the REAL Qwen inference backend (candle, GGUF-quantized). Behind
//!   the `qwen-backend` feature (+ `qwen-metal` / `qwen-cuda`) with OPTIONAL candle /
//!   tokenizers deps, OFF by default, so the consensus build never pulls the heavy stack.
pub mod domains;
pub mod palw;
pub mod palw_conformance_gate;
pub mod palw_determinism;
pub mod palw_replica;
/// ADR-0039 PALW — the REAL Qwen inference backend (candle, GGUF-quantized, greedy decode)
/// implementing the same [`palw_replica::VerifiableInferenceBackend`] the mock does. Behind
/// the `qwen-backend` feature so a default build (and consensus's dev-dep on this crate)
/// never compiles candle / tokenizers.
#[cfg(feature = "qwen-backend")]
pub mod qwen_backend;
