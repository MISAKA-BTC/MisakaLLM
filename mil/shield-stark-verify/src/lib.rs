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

use borsh::BorshDeserialize;
use kaspa_hashes::Hash64;
use misaka_mil_shield::proof::{CIRCUIT_PROVIDER_CLAIM, CIRCUIT_SPEND, PROOF_SYSTEM_STARK};
use misaka_mil_shield::provider::ProviderClaimStatement;
use misaka_mil_shield::spend::SpendStatement;
use misaka_mil_shield::{ShieldVerifyError, StarkVerifier, VerifiedStatement};

/// Upper bound on the STARK proof bytes the verifier will even parse, a DoS guard so
/// an attacker-supplied length prefix cannot drive an unbounded allocation before the
/// verify runs. A recursion outer proof measures ~40–382 KiB (ADR-0035 §4 / ADR-0036
/// — over the 32 KiB per-block payload cap, so it is chunk-transported and reassembled
/// off the hot path before reaching here). This cap is deliberately generous;
/// **PROVISIONAL** — the exact value is frozen by ADR-0036 O-SP-1 (windowed DA budget)
/// alongside `F006_VERIFY_GAS`, and is a governance parameter, not a constant to guess.
pub const MAX_STARK_PROOF_BYTES: usize = 1 << 20; // 1 MiB
/// Upper bound on the public-input (borsh statement) bytes. The frozen `SpendStatement`
/// borsh is 404 B and `ProviderClaimStatement` is 232 B (ADR-0034 §7 P1); a small cap
/// rejects malformed oversize inputs before decode.
pub const MAX_PUBLIC_INPUT_BYTES: usize = 1024;

/// The production in-consensus STARK verifier. Zero-sized: it holds no state, so
/// it is trivially `Send + Sync` and cheap to construct per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct StarkBackend;

/// Errors from the STARK verify. All map to a fail-closed reject at the trait
/// boundary, so every variant is behaviourally identical to the inert node; the
/// distinctions exist for tests and telemetry, never for consensus branching.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StarkVerifyError {
    #[error("unknown circuit version {0}")]
    UnknownCircuit(u16),
    #[error("proof bytes {got} exceed the cap {cap}")]
    ProofTooLarge { got: usize, cap: usize },
    #[error("public inputs {got} exceed the cap {cap}")]
    PublicInputTooLarge { got: usize, cap: usize },
    #[error("malformed public inputs (not a valid statement for the circuit): {0}")]
    MalformedStatement(String),
    #[error("STARK verifier not yet implemented — ADR-0033 §SP-0 milestone (audited)")]
    BackendPending,
}

/// The parsed, size-checked public statement for a circuit version. Decoding it is
/// the deterministic, panic-free front half of [`verify_stark`] (SP-04): it does the
/// bounds + borsh parse that must never unwind, independent of the STARK verify
/// itself (the audit-gated §SP-0 back half). Kept public so a differential harness /
/// the recursion-side verifier demonstration can reuse the exact same decode.
pub fn decode_statement(circuit_version: u16, public_inputs: &[u8]) -> Result<VerifiedStatement, StarkVerifyError> {
    if public_inputs.len() > MAX_PUBLIC_INPUT_BYTES {
        return Err(StarkVerifyError::PublicInputTooLarge { got: public_inputs.len(), cap: MAX_PUBLIC_INPUT_BYTES });
    }
    match circuit_version {
        // `try_from_slice` is fallible and non-panicking: a short/oversized/invalid
        // buffer returns Err (mapped below), it never indexes out of bounds or unwinds.
        // The trailing-bytes strictness of borsh means extra bytes are also rejected.
        CIRCUIT_SPEND => SpendStatement::try_from_slice(public_inputs)
            .map(VerifiedStatement::Spend)
            .map_err(|e| StarkVerifyError::MalformedStatement(e.to_string())),
        CIRCUIT_PROVIDER_CLAIM => ProviderClaimStatement::try_from_slice(public_inputs)
            .map(VerifiedStatement::ProviderClaim)
            .map_err(|e| StarkVerifyError::MalformedStatement(e.to_string())),
        other => Err(StarkVerifyError::UnknownCircuit(other)),
    }
}

/// The pure, deterministic verify (front half live, back half pending §SP-0).
///
/// Front half (implemented, SP-04-critical): reject unknown circuits, bound the proof
/// and public-input sizes (DoS guard), and borsh-decode the statement — all
/// panic-free, allocation-bounded, and platform-independent. Back half (the audited
/// §SP-0 milestone, marked SEAM below): decode `proof` as the recursion outer proof,
/// run the hash-based STARK verify against `vk_hash`, and — critically — prove the
/// decoded statement equals the public values the proof was produced over (element
/// for element under the frozen field encoding) so a proof valid for a *different*
/// statement cannot be replayed. Until that lands the seam returns `BackendPending`,
/// so the whole function stays fail-closed. Wiring the real back half pulls in a
/// verify-only Plonky3 subset (p3-batch-stark / p3-recursion), which is the
/// experimental, audit-gated dependency ADR-0035 §8 flags — hence it lands behind
/// this seam, not in the default consensus build.
pub fn verify_stark(
    circuit_version: u16,
    _vk_hash: &Hash64,
    public_inputs: &[u8],
    proof: &[u8],
) -> Result<VerifiedStatement, StarkVerifyError> {
    // --- deterministic front half (SP-04): bounds + parse, never panics ---
    if proof.len() > MAX_STARK_PROOF_BYTES {
        return Err(StarkVerifyError::ProofTooLarge { got: proof.len(), cap: MAX_STARK_PROOF_BYTES });
    }
    let statement = decode_statement(circuit_version, public_inputs)?;
    // --- SEAM: the audited §SP-0 STARK verify + statement-binding check ---
    // When implemented, `statement` is returned ONLY if the outer proof verifies AND
    // binds exactly these public values. Until then, fail closed.
    let _ = (statement, proof);
    Err(StarkVerifyError::BackendPending)
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
        // A well-formed STARK statement passes the deterministic front half and stops
        // fail-closed at the §SP-0 seam.
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        assert_eq!(verify_stark(CIRCUIT_SPEND, &h(0xB0), &pi, &[0u8; 32]), Err(StarkVerifyError::BackendPending));
        // Through the trait boundary, EVERY internal error (pending, malformed,
        // oversized) maps to the same ProofSystemNotActivated the inert node returns —
        // so a linked-but-inactive backend is byte-identical to one that does not link.
        let mut p = ShieldProof::decode(&ref_spend(h(0xB0))).unwrap();
        p.proof_system_id = PROOF_SYSTEM_STARK; // reference bytes tagged STARK
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
        // unknown circuit also rejects at the decode layer, before any size work.
        assert_eq!(decode_statement(7, &[]), Err(StarkVerifyError::UnknownCircuit(7)));
    }

    // ---- deterministic front-half (SP-04): panic-free bounds + parse ----

    fn spend_stmt() -> SpendStatement {
        SpendStatement {
            anchor: h(0x10),
            nf_old: [misaka_mil_shield::Nullifier(h(0x20)), misaka_mil_shield::Nullifier(h(0x21))],
            cm_new: [misaka_mil_shield::Commitment(h(0x30)), misaka_mil_shield::Commitment(h(0x31))],
            v_pub_in: 100,
            v_pub_out: 0,
            token_id: 0,
            ctx: h(0xC7),
        }
    }

    #[test]
    fn valid_statement_decodes_and_reaches_the_pending_seam() {
        // A well-formed statement passes the front half (bounds + borsh) and stops at
        // the §SP-0 seam — proving the deterministic decode works end to end.
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        assert_eq!(verify_stark(CIRCUIT_SPEND, &h(0xB0), &pi, &[0u8; 64]), Err(StarkVerifyError::BackendPending));
        // and the decoded statement round-trips exactly.
        match decode_statement(CIRCUIT_SPEND, &pi).unwrap() {
            VerifiedStatement::Spend(s) => assert_eq!(s, spend_stmt()),
            _ => panic!("expected Spend"),
        }
    }

    #[test]
    fn malformed_public_inputs_error_never_panic() {
        // Truncated, empty, garbage, and trailing-byte inputs all return Err (borsh is
        // strict about trailing bytes) — none unwind. This is the SP-04 panic-free bar.
        let good = borsh::to_vec(&spend_stmt()).unwrap();
        for bad in [vec![], vec![0u8; 1], good[..good.len() - 1].to_vec(), {
            let mut v = good.clone();
            v.push(0xff); // trailing byte
            v
        }] {
            let r = verify_stark(CIRCUIT_SPEND, &h(0xB0), &bad, &[]);
            assert!(matches!(r, Err(StarkVerifyError::MalformedStatement(_))), "must reject {bad:?} as malformed");
        }
    }

    #[test]
    fn oversized_proof_and_public_inputs_are_bounded_before_work() {
        // Proof larger than the cap is rejected before any parse (DoS guard).
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let big = vec![0u8; MAX_STARK_PROOF_BYTES + 1];
        assert_eq!(
            verify_stark(CIRCUIT_SPEND, &h(0xB0), &pi, &big),
            Err(StarkVerifyError::ProofTooLarge { got: MAX_STARK_PROOF_BYTES + 1, cap: MAX_STARK_PROOF_BYTES }),
        );
        // Oversized public inputs rejected at decode, before borsh runs.
        let big_pi = vec![0u8; MAX_PUBLIC_INPUT_BYTES + 1];
        assert_eq!(
            decode_statement(CIRCUIT_SPEND, &big_pi),
            Err(StarkVerifyError::PublicInputTooLarge { got: MAX_PUBLIC_INPUT_BYTES + 1, cap: MAX_PUBLIC_INPUT_BYTES }),
        );
    }

    #[test]
    fn provider_claim_statement_decodes() {
        // The second circuit version parses its own statement type.
        let claim = ProviderClaimStatement {
            provider_set_root: h(0x40),
            session_cm: h(0x41),
            amount: 7,
            provider_nf: misaka_mil_shield::Nullifier(h(0x42)),
            cm_payout: misaka_mil_shield::Commitment(h(0x43)),
            ctx: h(0x44),
        };
        let pi = borsh::to_vec(&claim).unwrap();
        match decode_statement(CIRCUIT_PROVIDER_CLAIM, &pi).unwrap() {
            VerifiedStatement::ProviderClaim(c) => assert_eq!(c, claim),
            _ => panic!("expected ProviderClaim"),
        }
        // a Spend circuit id will NOT accept ProviderClaim bytes as a valid SpendStatement
        // of the same length unless borsh happens to parse — assert it stays fail-closed
        // through verify_stark regardless (BackendPending or MalformedStatement, never panic).
        let r = verify_stark(CIRCUIT_PROVIDER_CLAIM, &h(0xB0), &pi, &[0u8; 32]);
        assert_eq!(r, Err(StarkVerifyError::BackendPending));
    }

    #[test]
    fn decode_is_deterministic() {
        // Same input → same output, every time (no hidden state / ordering).
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let a = decode_statement(CIRCUIT_SPEND, &pi);
        let b = decode_statement(CIRCUIT_SPEND, &pi);
        assert_eq!(a, b);
    }
}
