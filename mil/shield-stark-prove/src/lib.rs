//! Client-side STARK prover for the MIL shielded pool (ADR-0034 §4 prove side).
//!
//! **What ships now (§SP-0 groundwork).** The real prover — a hash-based STARK
//! over the frozen relations (`misaka-mil-shield::{spend, provider}`) — is the
//! audited ADR-0033 §SP-0 milestone and is *not* implemented here. What this
//! crate delivers is the decision substrate for O-SP-1:
//!
//! - [`cost`] — the exact per-circuit BLAKE2b-512 compression count, derived from
//!   the frozen relations, that decides whether a single proof can meet the
//!   32 KiB payload cap.
//! - [`Backend`] / [`ProofSizeRegime`] / [`cap_feasibility`] — a cap-feasibility
//!   classifier + the `mil-stark-cap-bench` binary that prints the decision table.
//! - [`prove`] — the client-side prover API boundary (returns
//!   [`ProveError::BackendPending`] until the milestone lands), so the wallet /
//!   provider integration can be written against a stable signature now.
//!
//! The prover runs ON THE CLIENT (the provider box for claims, the wallet for
//! spends): the witness never leaves the device, which is what makes the payout
//! unlinkable in practice (complementing the SDK 2-hop relay, ADR-0025 U2).

pub mod cost;

pub use cost::{CircuitCost, provider_claim_cost, spend_cost};
use kaspa_hashes::Hash64;
use misaka_mil_shield::proof::{CIRCUIT_PROVIDER_CLAIM, CIRCUIT_SPEND};

/// The ADR-0033 §SP-0 hard cap: a single proof must fit under the DA payload
/// budget so it can be carried in one shielded-pool transaction (32 KiB).
pub const DA_CAP_BYTES: usize = 32 * 1024;

/// Candidate production backends (O-SP-1). Soundness MUST stay hash-based (SP-05):
/// a pairing-based compression (Groth16/BN254) reintroduces a trusted setup whose
/// toxic waste forges withdrawals = undetectable MSK inflation — disqualifying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// S-two / Circle-STARK over M31. Client-side-proving oriented, hash-based,
    /// native small-proof recursion — the ADR-0035 front-runner.
    CircleStark,
    /// Plonky3 (BabyBear/KoalaBear/M31). A toolkit: you build the AIR + recursion
    /// yourself. Fallback if we need field/AIR control S-two doesn't expose.
    Plonky3,
    /// Risc0 zkVM — proves the exact reference Rust, but its succinct wrap is
    /// Groth16 (pairing). Usable ONLY as an off-chain differential oracle (P4),
    /// NOT as the production verifier (SP-05).
    Risc0,
    /// SP1 zkVM — same posture as Risc0 (Plonky3 core + Groth16 wrap for on-chain).
    Sp1,
}

impl Backend {
    /// Whether the backend has a purely hash-based (no-pairing) path to a
    /// sub-cap proof — the SP-05 gate. zkVMs are `false` for *production* because
    /// their small on-chain proof is a pairing wrap.
    pub const fn pq_only_subcap_path(self) -> bool {
        matches!(self, Backend::CircleStark | Backend::Plonky3)
    }
}

/// Where a circuit of a given AIR area sits relative to a single flat FRI-STARK
/// proof under the 32 KiB cap. Thresholds are literature-grounded regimes (a flat
/// FRI proof for a hash-heavy trace at ~100-bit security runs from a few KB at
/// ~2^12 to tens–hundreds of KB by ~2^18); the measured `.119` bench pins the
/// exact KB. The point is the *regime*, which drives the recursion decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSizeRegime {
    /// Small enough a single flat proof is comfortably under the cap.
    UnderCap,
    /// Borderline: fits only with proof-size-optimized FRI params (fewer queries
    /// + more grinding). Must be confirmed by the measured bench.
    NearCap,
    /// A single flat proof exceeds the cap; a STARK recursion/compression layer
    /// (still hash-based, SP-05-safe) is required to reach it.
    OverCapNeedsRecursion,
}

/// Classify a circuit by its estimated AIR-area exponent (`est_constraints_pow2`).
pub fn cap_feasibility(cost: &CircuitCost) -> ProofSizeRegime {
    match cost.est_constraints_pow2 {
        0..=12 => ProofSizeRegime::UnderCap,
        13..=16 => ProofSizeRegime::NearCap,
        _ => ProofSizeRegime::OverCapNeedsRecursion,
    }
}

/// Client-side prover error surface.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProveError {
    #[error("unknown circuit version {0}")]
    UnknownCircuit(u16),
    #[error("STARK backend not yet implemented — ADR-0033 §SP-0 milestone (audited)")]
    BackendPending,
}

/// The client-side proving entry point (stable API; real prover pending §SP-0).
/// On success this returns the succinct proof bytes to place in
/// `ShieldProof.proof` with `proof_system_id = PROOF_SYSTEM_STARK`. The public
/// inputs and witness are the frozen borsh encodings from `misaka-mil-shield`.
pub fn prove(
    backend: Backend,
    circuit_version: u16,
    _vk: &Hash64,
    _public_inputs: &[u8],
    _witness: &[u8],
) -> Result<Vec<u8>, ProveError> {
    match circuit_version {
        CIRCUIT_SPEND | CIRCUIT_PROVIDER_CLAIM => {
            let _ = backend;
            Err(ProveError::BackendPending)
        }
        other => Err(ProveError::UnknownCircuit(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cost::{DEFAULT_CONSTRAINTS_PER_COMPRESSION, POOL_TREE_DEPTH, blake2b_compressions};

    #[test]
    fn blake2b_compression_model_matches_the_keying_rule() {
        // 1 key block + ⌈len/128⌉ message blocks (min 1).
        assert_eq!(blake2b_compressions(0), 2); // key + one (final) block
        assert_eq!(blake2b_compressions(64), 2); // addr: 1 block
        assert_eq!(blake2b_compressions(128), 2); // node/nf: exactly 1 block
        assert_eq!(blake2b_compressions(129), 3); // rho: spills to a 2nd block
        assert_eq!(blake2b_compressions(204), 3); // commit: 2 message blocks
    }

    #[test]
    fn spend_dominated_by_merkle_membership() {
        let c = spend_cost(POOL_TREE_DEPTH, DEFAULT_CONSTRAINTS_PER_COMPRESSION);
        // 2 inputs × (commit + 20 nodes + addr + nf) + 2 outputs × (rho + commit)
        assert_eq!(c.hash_calls, 2 * (1 + 20 + 1 + 1) + 2 * (1 + 1)); // 50
        // compressions: 2×(3 + 20×2 + 2 + 2) + 2×(3 + 3) = 2×47 + 12 = 106
        assert_eq!(c.blake2b_compressions, 106);
        // membership (40 node-hashes ⇒ 80 comp) is >70% of the cost
        assert!(80 * 100 / c.blake2b_compressions >= 70);
    }

    #[test]
    fn provider_claim_is_cheaper_than_spend() {
        let claim = provider_claim_cost(POOL_TREE_DEPTH, DEFAULT_CONSTRAINTS_PER_COMPRESSION);
        let spend = spend_cost(POOL_TREE_DEPTH, DEFAULT_CONSTRAINTS_PER_COMPRESSION);
        // 20 nodes + leaf + addr + nf + commit + ctx = 25 calls
        assert_eq!(claim.hash_calls, 25);
        // 20×2 + 2 + 2 + 2 + 3 + 3 = 52 compressions
        assert_eq!(claim.blake2b_compressions, 52);
        assert!(claim.blake2b_compressions < spend.blake2b_compressions);
    }

    #[test]
    fn hash_heavy_spend_needs_recursion_for_the_cap() {
        // At the Keccak-class area default, spend lands ~2^18 → over a single
        // flat FRI proof's 32 KiB budget, so recursion is the safe design.
        let c = spend_cost(POOL_TREE_DEPTH, DEFAULT_CONSTRAINTS_PER_COMPRESSION);
        assert!(c.est_constraints_pow2 >= 17);
        assert_eq!(cap_feasibility(&c), ProofSizeRegime::OverCapNeedsRecursion);
    }

    #[test]
    fn only_hash_based_backends_are_production_eligible() {
        assert!(Backend::CircleStark.pq_only_subcap_path());
        assert!(Backend::Plonky3.pq_only_subcap_path());
        // zkVMs compress with a pairing wrap → not production-eligible (SP-05)
        assert!(!Backend::Risc0.pq_only_subcap_path());
        assert!(!Backend::Sp1.pq_only_subcap_path());
    }

    #[test]
    fn prover_is_pending_but_the_api_is_stable() {
        let vk = Hash64::from_bytes([0xB0; 64]);
        assert_eq!(prove(Backend::CircleStark, CIRCUIT_SPEND, &vk, &[], &[]), Err(ProveError::BackendPending));
        assert_eq!(prove(Backend::CircleStark, 999, &vk, &[], &[]), Err(ProveError::UnknownCircuit(999)));
    }
}
