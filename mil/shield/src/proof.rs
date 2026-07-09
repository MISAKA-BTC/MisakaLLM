//! The versioned proof envelope the **F006 `SHIELDED_VERIFY`** precompile
//! verifies. Keeping the contract/precompile proof-system-agnostic (ADR-0033
//! §5.1 `proof_system_id` / `circuit_version` / `verifier_key_hash`) is what lets
//! the zero-knowledge STARK drop in later without touching the pool, the escrow,
//! or the statements.

use crate::provider::{self, ProviderClaimStatement, ProviderClaimWitness};
use crate::spend::{self, SpendStatement, SpendWitness};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash64;

/// Transparent reference system: `proof` carries the witness in the clear. Sound
/// but **not** zero-knowledge — testing + escrow-capped testnet stepping-stone.
pub const PROOF_SYSTEM_REFERENCE: u8 = 0x01;
/// Production system: hash-based STARK (S-two / Circle-STARK). Zero-knowledge +
/// succinct; verifier lands under ADR-0033 §SP-0 (single proof under the 32 KiB
/// payload cap). Statements/public-inputs are unchanged from the reference.
pub const PROOF_SYSTEM_STARK: u8 = 0x02;

/// Value-pool JoinSplit (L2 payment shield).
pub const CIRCUIT_SPEND: u16 = 1;
/// Anonymous provider claim (which-GPU unlinkability).
pub const CIRCUIT_PROVIDER_CLAIM: u16 = 2;

/// The F006 calldata payload (after the `input[0]` version/kind discriminator the
/// precompile strips): a self-describing proof over one shielded statement.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShieldProof {
    pub proof_system_id: u8,
    pub circuit_version: u16,
    /// Governance-pinned verifier key hash for `(proof_system_id, circuit_version)`.
    pub verifier_key_hash: Hash64,
    /// The statement's public inputs (borsh of `SpendStatement` /
    /// `ProviderClaimStatement`). The contract reconstructs these from its own
    /// state and calldata, so a valid proof binds to values it already trusts.
    pub public_inputs: Vec<u8>,
    /// The proof (reference: borsh witness; STARK: the succinct proof bytes).
    pub proof: Vec<u8>,
}

impl ShieldProof {
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh of an in-memory proof is infallible")
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ShieldVerifyError> {
        Self::try_from_slice(bytes).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))
    }
}

/// The verified public statement returned to the precompile/contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedStatement {
    Spend(SpendStatement),
    ProviderClaim(ProviderClaimStatement),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShieldVerifyError {
    #[error("malformed shield proof: {0}")]
    Malformed(String),
    #[error("unknown proof system id {0:#04x}")]
    UnknownProofSystem(u8),
    #[error("unknown circuit version {0}")]
    UnknownCircuit(u16),
    #[error("verifier key hash does not match the pinned key for this circuit")]
    VerifierKeyMismatch,
    #[error("proof system {0:#04x} is not activated (STARK verifier is the ADR-0033 §SP-0 milestone)")]
    ProofSystemNotActivated(u8),
    #[error("spend statement invalid: {0}")]
    Spend(#[from] spend::SpendError),
    #[error("provider claim invalid: {0}")]
    ProviderClaim(#[from] provider::ProviderClaimError),
}

/// A pluggable verifier for [`PROOF_SYSTEM_STARK`] — the one seam of the
/// reference→STARK swap (ADR-0034 §5). The zero-knowledge backend
/// (`misaka-mil-shield-stark-verify`) implements this and returns the decoded
/// public statement on success; until the ADR-0033 §SP-0 milestone the node links
/// [`InertStarkVerifier`], so a STARK proof is rejected fail-closed and F006 stays
/// byte-identical. Swapping in the real backend is the *entire* code change.
pub trait StarkVerifier {
    /// Verify `proof` over `public_inputs` for `circuit_version` under `vk_hash`,
    /// returning the decoded [`VerifiedStatement`] on success. Fail-closed: any
    /// invalid/malformed/inactive input is an `Err` (mapped to ABI false), never a
    /// panic (a consensus-critical determinism requirement — ADR-0034 §3).
    fn verify(
        &self,
        circuit_version: u16,
        vk_hash: &Hash64,
        public_inputs: &[u8],
        proof: &[u8],
    ) -> Result<VerifiedStatement, ShieldVerifyError>;
}

/// The STARK verifier linked until the ADR-0033 §SP-0 milestone: it rejects every
/// STARK proof, so the pool cannot be activated "live but non-private". Behavior is
/// byte-identical to the pre-seam `verify_shield_proof` (the F006 fence is
/// `u64::MAX` anyway), so all existing tests and on-chain execution are unchanged.
pub struct InertStarkVerifier;

impl StarkVerifier for InertStarkVerifier {
    fn verify(
        &self,
        _circuit_version: u16,
        _vk_hash: &Hash64,
        _public_inputs: &[u8],
        _proof: &[u8],
    ) -> Result<VerifiedStatement, ShieldVerifyError> {
        Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK))
    }
}

/// Verify a shielded proof against the pinned verifier key using the node's STARK
/// verifier (inert until §SP-0). On `Ok` the returned [`VerifiedStatement`] carries
/// the public inputs the caller enforces against pool/escrow state (nullifier
/// freshness, anchor-in-ring, commitment insertion).
///
/// Fail-closed: any malformed/unknown/mismatched/false input is an `Err`, never a
/// panic (the precompile maps `Ok → 0x…01`, `Err → 0x…00`).
pub fn verify_shield_proof(bytes: &[u8], pinned_vk_hash: &Hash64) -> Result<VerifiedStatement, ShieldVerifyError> {
    verify_shield_proof_with(bytes, pinned_vk_hash, &InertStarkVerifier)
}

/// The extensible form (ADR-0034 §5): the REFERENCE arm is verified in-process; the
/// STARK arm delegates to the injected `stark` backend. This is the single
/// code-diff surface of the reference→STARK swap — construct with the real backend
/// instead of [`InertStarkVerifier`] and nothing else in the L2 stack changes.
pub fn verify_shield_proof_with<V: StarkVerifier>(
    bytes: &[u8],
    pinned_vk_hash: &Hash64,
    stark: &V,
) -> Result<VerifiedStatement, ShieldVerifyError> {
    let p = ShieldProof::decode(bytes)?;
    if &p.verifier_key_hash != pinned_vk_hash {
        return Err(ShieldVerifyError::VerifierKeyMismatch);
    }
    match p.proof_system_id {
        PROOF_SYSTEM_REFERENCE => match p.circuit_version {
            CIRCUIT_SPEND => {
                let stmt =
                    SpendStatement::try_from_slice(&p.public_inputs).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                let wit = SpendWitness::try_from_slice(&p.proof).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                spend::verify_reference(&stmt, &wit)?;
                Ok(VerifiedStatement::Spend(stmt))
            }
            CIRCUIT_PROVIDER_CLAIM => {
                let stmt = ProviderClaimStatement::try_from_slice(&p.public_inputs)
                    .map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                let wit = ProviderClaimWitness::try_from_slice(&p.proof).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                provider::verify_reference(&stmt, &wit)?;
                Ok(VerifiedStatement::ProviderClaim(stmt))
            }
            other => Err(ShieldVerifyError::UnknownCircuit(other)),
        },
        // The STARK verifier is the production/ZK milestone; the injected backend
        // is `InertStarkVerifier` until §SP-0, so a STARK proof is rejected rather
        // than silently accepted (the F006 fence is u64::MAX anyway).
        PROOF_SYSTEM_STARK => stark.verify(p.circuit_version, &p.verifier_key_hash, &p.public_inputs, &p.proof),
        other => Err(ShieldVerifyError::UnknownProofSystem(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{MerklePath, MerkleTree};
    use crate::note::{Commitment, Note, commit, derive_output_rho, nullifier, shielded_address};

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }
    fn vk() -> Hash64 {
        h(0xB0)
    }

    // A reference spend proof (shield 100 → one 100-note).
    fn spend_proof(vk_hash: Hash64) -> Vec<u8> {
        let dummy = Note { value: 0, owner_pk: h(0), rho: h(0), r: h(0), token_id: 0 };
        let nf0 = nullifier(&h(1), &dummy.rho);
        let nf1 = nullifier(&h(2), &dummy.rho);
        let out0 =
            Note { value: 100, owner_pk: shielded_address(&h(0x71)), rho: derive_output_rho(&nf0, &nf1, 0), r: h(0x31), token_id: 0 };
        let out1 = Note { value: 0, owner_pk: h(0), rho: derive_output_rho(&nf0, &nf1, 1), r: h(0), token_id: 0 };
        let stmt = SpendStatement {
            anchor: h(0),
            nf_old: [nf0, nf1],
            cm_new: [commit(&out0), commit(&out1)],
            v_pub_in: 100,
            v_pub_out: 0,
            token_id: 0,
            ctx: h(0xC7),
        };
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
            verifier_key_hash: vk_hash,
            public_inputs: borsh::to_vec(&stmt).unwrap(),
            proof: borsh::to_vec(&wit).unwrap(),
        }
        .encode()
    }

    #[test]
    fn reference_spend_proof_verifies_via_envelope() {
        let bytes = spend_proof(vk());
        let v = verify_shield_proof(&bytes, &vk()).expect("valid reference spend must verify");
        assert!(matches!(v, VerifiedStatement::Spend(_)));
    }

    #[test]
    fn wrong_verifier_key_is_rejected() {
        let bytes = spend_proof(vk());
        assert_eq!(verify_shield_proof(&bytes, &h(0x00)), Err(ShieldVerifyError::VerifierKeyMismatch));
    }

    #[test]
    fn stark_system_is_inert_not_accepted() {
        // A STARK-tagged proof is rejected (fail-closed) until the milestone.
        let mut p = ShieldProof::decode(&spend_proof(vk())).unwrap();
        p.proof_system_id = PROOF_SYSTEM_STARK;
        assert_eq!(verify_shield_proof(&p.encode(), &vk()), Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK)));
    }

    #[test]
    fn stark_arm_routes_to_injected_backend() {
        // The reference→STARK swap (ADR-0034 §5) is exactly "inject a real backend
        // instead of InertStarkVerifier". A mock backend that accepts a STARK-tagged
        // proof and returns the decoded statement proves the seam is wired and that
        // swapping it in is the whole change — while the production entry point
        // (inert verifier) still rejects the identical bytes.
        struct Accepting;
        impl StarkVerifier for Accepting {
            fn verify(
                &self,
                circuit_version: u16,
                _vk: &Hash64,
                public_inputs: &[u8],
                _proof: &[u8],
            ) -> Result<VerifiedStatement, ShieldVerifyError> {
                assert_eq!(circuit_version, CIRCUIT_SPEND);
                let stmt =
                    SpendStatement::try_from_slice(public_inputs).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                Ok(VerifiedStatement::Spend(stmt))
            }
        }
        let mut p = ShieldProof::decode(&spend_proof(vk())).unwrap();
        p.proof_system_id = PROOF_SYSTEM_STARK;
        let bytes = p.encode();
        // injected backend accepts → decoded statement flows back to the caller
        let v = verify_shield_proof_with(&bytes, &vk(), &Accepting).expect("injected backend accepts");
        assert!(matches!(v, VerifiedStatement::Spend(_)));
        // wrong pinned vk is still rejected before the backend is ever consulted
        assert_eq!(verify_shield_proof_with(&bytes, &h(0x00), &Accepting), Err(ShieldVerifyError::VerifierKeyMismatch));
        // the production entry (inert backend) rejects the very same bytes
        assert_eq!(verify_shield_proof(&bytes, &vk()), Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK)));
    }

    #[test]
    fn provider_claim_proof_verifies_via_envelope() {
        // build a minimal registry + claim
        let (pkh, sec) = (h(0x41), h(0x81));
        let mut tree = MerkleTree::new(16);
        let idx = tree.append(Commitment(provider::provider_leaf(&pkh, &shielded_address(&sec))));
        let session_cm = h(0x5E);
        let amount = 500u64;
        let payout = Note { value: amount, owner_pk: shielded_address(&h(0x71)), rho: h(1), r: h(2), token_id: 0 };
        let cm_payout = commit(&payout);
        let provider_nf = provider::provider_nullifier(&sec, &session_cm);
        let stmt = ProviderClaimStatement {
            provider_set_root: tree.root(),
            session_cm,
            amount,
            provider_nf,
            cm_payout,
            ctx: provider::claim_ctx(&session_cm, amount, &cm_payout, &provider_nf),
        };
        let wit = ProviderClaimWitness {
            pk_receipt_hash: pkh,
            claim_secret: sec,
            leaf_index: idx,
            path: tree.path(idx).unwrap(),
            payout_note: payout,
        };
        let bytes = ShieldProof {
            proof_system_id: PROOF_SYSTEM_REFERENCE,
            circuit_version: CIRCUIT_PROVIDER_CLAIM,
            verifier_key_hash: vk(),
            public_inputs: borsh::to_vec(&stmt).unwrap(),
            proof: borsh::to_vec(&wit).unwrap(),
        }
        .encode();
        let v = verify_shield_proof(&bytes, &vk()).expect("valid provider claim must verify");
        assert!(matches!(v, VerifiedStatement::ProviderClaim(_)));
    }
}
