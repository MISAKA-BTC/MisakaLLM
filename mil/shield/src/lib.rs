//! MISAKA MIL shielded pool + provider set-membership core (ADR-0033 §4 /
//! ADR-0025 §21 payment shield-ladder rung **L2**).
//!
//! This crate solves **unlinkability**, the Tier-2 privacy goal (ADR-0025 U1):
//! *the provider may see the content, but neither the provider nor any on-chain
//! observer can bind a job/response/payment to **which** provider (GPU) produced
//! it.* Two zero-knowledge statements do this, verified on-chain by the **F006
//! `SHIELDED_VERIFY`** precompile:
//!
//! 1. [`spend`] — a Zcash-Sprout-style value JoinSplit: spend a note by proving
//!    Merkle membership + a nullifier + value conservation **without revealing
//!    which** committed note is spent. This is the L2 payment shield: a provider
//!    is paid into a shielded note, and the fund graph no longer links the job's
//!    payout to a provider address.
//! 2. [`provider`] — an **anonymous provider claim**: prove "I am *one of* the
//!    registered active providers and I hold a valid cumulative receipt for this
//!    session" **without revealing which provider**, deriving a per-session
//!    provider-nullifier so a provider can settle at most once. This is what
//!    makes *which GPU answered* unknown on-chain (blind-open + set-membership).
//!
//! ## Proof systems (the honest boundary — ADR-0033 two-track)
//!
//! Every statement is checked through a versioned [`proof::ShieldProof`]
//! envelope (`proof_system_id` / `circuit_version` / `verifier_key_hash`), so
//! the *contract* and *precompile* are proof-system-agnostic. This crate ships
//! [`proof::PROOF_SYSTEM_REFERENCE`]: a **transparent** verifier that checks the
//! full relation given an explicit witness. It is *sound* (a false statement
//! never verifies) and exercises the pool/escrow mechanics end-to-end, but it is
//! **not zero-knowledge** — the witness is in the clear, so it is for testing and
//! the escrow-capped testnet stepping-stone only. The **zero-knowledge + succinct**
//! system is [`proof::PROOF_SYSTEM_STARK`] (S-two / Circle-STARK, F006), the
//! production rung whose verifier lands under ADR-0033 §SP-0 (single proof under
//! the 32 KiB payload cap). The statements, public inputs, commitments,
//! nullifiers and Merkle structure here are exactly what that STARK circuit
//! proves — so nothing in this core changes when the proof system is swapped.
//!
//! All hashing is MISAKA's keyed BLAKE2b-512 (`Hash64`), hash-based and
//! PQ-aligned: withdrawal/settlement **soundness rests only on hash security**,
//! so a quantum computer cannot forge a spend (ADR-0033 constraint 1).

pub mod domains;
pub mod evm_ctx;
pub mod merkle;
pub mod note;
pub mod proof;
pub mod provider;
pub mod spend;

pub use merkle::{MerklePath, MerkleTree, verify_merkle_path};
pub use note::{Commitment, Note, Nullifier, commit, derive_output_rho, nullifier, shielded_address};
pub use proof::{
    InertStarkVerifier, PROOF_SYSTEM_REFERENCE, PROOF_SYSTEM_STARK, ProofPolicy, ShieldProof, ShieldVerifyError,
    StarkVerifier, VerifiedStatement, verify_shield_proof, verify_shield_proof_with, verify_shield_proof_with_policy,
};
pub use provider::{ProviderClaimStatement, ProviderClaimWitness, provider_leaf, provider_nullifier};
pub use spend::{SpendStatement, SpendWitness};
