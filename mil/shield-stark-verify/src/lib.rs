//! In-consensus STARK verifier for the MIL shielded pool (ADR-0034 §4/§5).
//!
//! [`StarkBackend`] implements [`misaka_mil_shield::StarkVerifier`], so the whole
//! reference→STARK swap is: the F006 precompile calls
//! `misaka_mil_shield::verify_shield_proof_with(bytes, vk, &StarkBackend)` instead
//! of the default inert verifier. Nothing else in the L2 stack changes.
//!
//! **Consensus determinism (SP-04) is a hard requirement.** This verifier runs in
//! block validation; every node must reach the SAME accept/reject for the SAME
//! `(vk, public_inputs, proof)`, bit-for-bit, on every platform — a divergence is
//! a consensus split, not a bug to patch later (the same bar as the F003 audit
//! finding H-2). The eventual implementation MUST therefore:
//!
//! - use only fixed-width field/integer arithmetic (M31), never floats;
//! - keep the accept/reject decision free of SIMD-/CPU-feature-dependent control
//!   flow (a data path may use SIMD; the decision may not branch on it);
//! - draw every Fiat-Shamir challenge from a fixed, versioned transcript hashed
//!   with keyed BLAKE2b-512 (the chain's canonical, PQ hash);
//! - be panic-free: malformed proof bytes / out-of-range field elements / bad
//!   lengths return `Err`, never unwind (F006 maps `Err → ABI false`).
//!
//! Until the audited §SP-0 milestone, [`verify_stark`] returns
//! [`StarkVerifyError::BackendPending`] and the trait maps it to the same
//! `ProofSystemNotActivated` error the default inert verifier returns — so a node
//! that links this crate behaves byte-identically to one that does not, and the
//! pool cannot be activated "live but non-private".

use kaspa_hashes::Hash64;
use misaka_mil_shield::proof::{CIRCUIT_PROVIDER_CLAIM, CIRCUIT_SPEND, PROOF_SYSTEM_STARK};
use misaka_mil_shield::{ShieldVerifyError, StarkVerifier, VerifiedStatement};

/// The production in-consensus STARK verifier. Zero-sized: it holds no state, so
/// it is trivially `Send + Sync` and cheap to construct per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct StarkBackend;

/// Errors from the (pending) STARK verify. All map to a fail-closed reject.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StarkVerifyError {
    #[error("unknown circuit version {0}")]
    UnknownCircuit(u16),
    #[error("STARK verifier not yet implemented — ADR-0033 §SP-0 milestone (audited)")]
    BackendPending,
}

/// The pure, deterministic verify (pending §SP-0). When implemented it MUST parse
/// `public_inputs` as the frozen borsh statement for `circuit_version`, run the
/// hash-based STARK verify against `vk_hash`, and return the decoded statement.
pub fn verify_stark(
    circuit_version: u16,
    _vk_hash: &Hash64,
    _public_inputs: &[u8],
    _proof: &[u8],
) -> Result<VerifiedStatement, StarkVerifyError> {
    match circuit_version {
        CIRCUIT_SPEND | CIRCUIT_PROVIDER_CLAIM => Err(StarkVerifyError::BackendPending),
        other => Err(StarkVerifyError::UnknownCircuit(other)),
    }
}

impl StarkVerifier for StarkBackend {
    fn verify(
        &self,
        circuit_version: u16,
        vk_hash: &Hash64,
        public_inputs: &[u8],
        proof: &[u8],
    ) -> Result<VerifiedStatement, ShieldVerifyError> {
        match verify_stark(circuit_version, vk_hash, public_inputs, proof) {
            Ok(stmt) => Ok(stmt),
            // Fail-closed and byte-identical to the default inert verifier: any
            // pending/unknown result rejects as "STARK not activated".
            Err(_) => Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_mil_shield::proof::{CIRCUIT_SPEND, PROOF_SYSTEM_REFERENCE, PROOF_SYSTEM_STARK, ShieldProof};
    use misaka_mil_shield::spend::{SpendStatement, SpendWitness};
    use misaka_mil_shield::{MerklePath, Note, commit, derive_output_rho, nullifier, shielded_address, verify_shield_proof_with};

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    // A valid REFERENCE spend proof (still verified in-process; the STARK backend
    // is only consulted for STARK-tagged proofs).
    fn ref_spend(vk: Hash64) -> Vec<u8> {
        let dummy = Note { value: 0, owner_pk: h(0), rho: h(0), r: h(0), token_id: 0 };
        let nf0 = nullifier(&h(1), &dummy.rho);
        let nf1 = nullifier(&h(2), &dummy.rho);
        let out0 = Note { value: 100, owner_pk: shielded_address(&h(0x71)), rho: derive_output_rho(&nf0, &nf1, 0), r: h(0x31), token_id: 0 };
        let out1 = Note { value: 0, owner_pk: h(0), rho: derive_output_rho(&nf0, &nf1, 1), r: h(0), token_id: 0 };
        let stmt = SpendStatement { anchor: h(0), nf_old: [nf0, nf1], cm_new: [commit(&out0), commit(&out1)], v_pub_in: 100, v_pub_out: 0, token_id: 0, ctx: h(0xC7) };
        let wit = SpendWitness {
            notes_in: [dummy, dummy],
            sk_in: [h(1), h(2)],
            paths_in: [MerklePath { siblings: vec![], index: 0 }, MerklePath { siblings: vec![], index: 0 }],
            enable_in: [false, false],
            notes_out: [out0, out1],
        };
        ShieldProof {
            proof_system_id: PROOF_SYSTEM_REFERENCE,
            circuit_version: CIRCUIT_SPEND,
            verifier_key_hash: vk,
            public_inputs: borsh::to_vec(&stmt).unwrap(),
            proof: borsh::to_vec(&wit).unwrap(),
        }
        .encode()
    }

    #[test]
    fn stark_backend_is_fail_closed_until_the_milestone() {
        // A STARK-tagged proof through the real backend is rejected fail-closed.
        assert_eq!(verify_stark(CIRCUIT_SPEND, &h(0xB0), &[], &[]), Err(StarkVerifyError::BackendPending));
        let mut p = ShieldProof::decode(&ref_spend(h(0xB0))).unwrap();
        p.proof_system_id = PROOF_SYSTEM_STARK;
        assert_eq!(
            verify_shield_proof_with(&p.encode(), &h(0xB0), &StarkBackend),
            Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK)),
        );
    }

    #[test]
    fn reference_proofs_still_verify_when_the_backend_is_linked() {
        // Linking the (pending) STARK backend does not disturb the REFERENCE arm —
        // the node stays byte-identical for the currently-live proof system.
        let v = verify_shield_proof_with(&ref_spend(h(0xB0)), &h(0xB0), &StarkBackend).expect("reference spend verifies");
        assert!(matches!(v, VerifiedStatement::Spend(_)));
    }

    #[test]
    fn unknown_circuit_is_rejected() {
        assert_eq!(verify_stark(7, &h(0), &[], &[]), Err(StarkVerifyError::UnknownCircuit(7)));
    }
}
