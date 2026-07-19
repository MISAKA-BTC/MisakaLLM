//! misaka-palw — PALW (proof-of-LLM audited-compute PoW lane, ADR-0039) shared kernel.
//!
//! Extracted from `mil/core` (`domains`, `palw`) and `mil/provider` (`palw_replica`)
//! so the consensus crates can depend ONLY on the PALW compute-set / commitment
//! types and the k=2 replica dispatch, without pulling the MIL job-market runtime
//! (channel / attest), the GPU inference backend (feature-gated in `mil/provider`),
//! or any EVM / shielded surface. This is the algo-4 "proof-of-LLM" PoW lane only.
pub mod domains;
pub mod palw;
pub mod palw_replica;
