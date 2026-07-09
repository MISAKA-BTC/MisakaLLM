//! Anonymous provider claim — the **which-GPU-unlinkability** statement
//! (ADR-0025 §21 / the "set-membership claim"). A provider settles a session by
//! proving:
//!
//! - it is **one of** the registered active providers (Merkle membership in the
//!   provider-set root), **without revealing which**;
//! - it derives a per-session provider **nullifier**, so a provider can settle a
//!   given session at most once (double-claim prevention, the anonymous analogue
//!   of `JobEscrow`'s cumulative-receipt monotonicity);
//! - the payout goes into a **shielded note** (`cm_payout`) it alone can spend,
//!   so the fund graph never names the provider either.
//!
//! Together with a blind `open` (an escrow that does not name a `providerId`)
//! this removes every on-chain artifact that says *which* GPU produced a
//! response, replacing the v1 `claim(providerId, pubkey, signature)` path.
//!
//! ## Reference vs STARK boundary
//!
//! The transparent reference relation below proves membership, the
//! session-nullifier, and the shielded-payout binding. The one piece it binds
//! rather than re-derives is **receipt validity**: in v1 the ML-DSA-87 receipt is
//! checked on-chain by F003 against a *named* key — which is exactly the leak.
//! In the anonymous flow that check moves **inside** the proof ("I know a valid
//! ML-DSA-87 receipt under the key whose hash sits in my registry leaf, for this
//! session"), an ML-DSA-verify-in-circuit that is the `PROOF_SYSTEM_STARK`
//! milestone (ADR-0033 §SP-0 / O-SP-1). The reference system ties `pk_receipt_hash`
//! into the leaf and the session into the nullifier, so the mechanism — an
//! unidentified registered provider, at most once per session, paid privately —
//! is complete and testable now.

use crate::domains::{CLAIM_CTX_DOMAIN, PROVIDER_LEAF_DOMAIN, PROVIDER_NF_DOMAIN};
use crate::merkle::{MerklePath, verify_merkle_path};
use crate::note::{Commitment, Note, Nullifier, commit, shielded_address};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{Hash64, blake2b_512_keyed};

/// A provider-registry Merkle leaf: `H_k("provider-leaf", pk_receipt_hash ‖ claim_pk)`.
/// `claim_pk = H(claim_secret)` binds the anonymous spend/nullifier authority to
/// the registry entry without exposing which entry on claim.
pub fn provider_leaf(pk_receipt_hash: &Hash64, claim_pk: &Hash64) -> Hash64 {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(pk_receipt_hash.as_byte_slice());
    b.extend_from_slice(claim_pk.as_byte_slice());
    blake2b_512_keyed(PROVIDER_LEAF_DOMAIN, &b)
}

/// Per-session provider nullifier `H_k("provider-nf", claim_secret ‖ session_cm)`.
/// Deterministic in the provider secret and the session, so a provider yields one
/// nullifier per session — at-most-once settlement, unlinkable across sessions.
pub fn provider_nullifier(claim_secret: &Hash64, session_cm: &Hash64) -> Nullifier {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(claim_secret.as_byte_slice());
    b.extend_from_slice(session_cm.as_byte_slice());
    Nullifier(blake2b_512_keyed(PROVIDER_NF_DOMAIN, &b))
}

/// Context binding for an anonymous claim, recomputed by the contract from its
/// call parameters and checked equal to the statement's `ctx` (§4.2 analogue):
/// `H_k("claim-ctx", session_cm ‖ amount ‖ cm_payout ‖ provider_nf)`.
pub fn claim_ctx(session_cm: &Hash64, amount: u64, cm_payout: &Commitment, provider_nf: &Nullifier) -> Hash64 {
    let mut b = Vec::with_capacity(200);
    b.extend_from_slice(session_cm.as_byte_slice());
    b.extend_from_slice(&amount.to_le_bytes());
    b.extend_from_slice(cm_payout.0.as_byte_slice());
    b.extend_from_slice(provider_nf.0.as_byte_slice());
    blake2b_512_keyed(CLAIM_CTX_DOMAIN, &b)
}

/// Public inputs the escrow enforces: the anonymity set root, the session, the
/// amount, the double-claim nullifier, the shielded payout, and the ctx.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProviderClaimStatement {
    /// Merkle root over `provider_leaf(pk_receipt_hash, claim_pk)` of every
    /// registered active provider (the anonymity set).
    pub provider_set_root: Hash64,
    /// The session commitment (`cmReq`) the escrow was opened against.
    pub session_cm: Hash64,
    /// The cumulative amount claimed (public; only the *identity* is hidden).
    pub amount: u64,
    /// At-most-once-per-session provider nullifier.
    pub provider_nf: Nullifier,
    /// The shielded payout note commitment (paid into the value pool).
    pub cm_payout: Commitment,
    /// Context binding (recomputed by the contract).
    pub ctx: Hash64,
}

/// Private witness (clear in the reference system, inside the STARK otherwise).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProviderClaimWitness {
    /// The registry key hash of the claiming provider.
    pub pk_receipt_hash: Hash64,
    /// The provider's anonymous claim secret (`claim_pk = H(claim_secret)`).
    pub claim_secret: Hash64,
    pub leaf_index: u64,
    pub path: MerklePath,
    /// The payout note that opens `cm_payout` (value must equal `amount`).
    pub payout_note: Note,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProviderClaimError {
    #[error("provider leaf is not a member of the provider-set root")]
    NotRegistered,
    #[error("declared provider nullifier != H(claim_secret ‖ session_cm)")]
    NullifierMismatch,
    #[error("payout commitment does not open to the declared note")]
    PayoutCommitment,
    #[error("payout note value ({got}) does not equal the claimed amount ({want})")]
    PayoutAmount { got: u64, want: u64 },
    #[error("ctx binding mismatch (tampered session/amount/payout/nullifier)")]
    CtxMismatch,
}

/// Verify the anonymous-claim relation transparently (reference system). Sound:
/// only a genuinely-registered provider, settling this session at most once and
/// paying itself exactly `amount` into a shielded note, passes — and *which*
/// provider is not revealed by any public input.
pub fn verify_reference(stmt: &ProviderClaimStatement, wit: &ProviderClaimWitness) -> Result<(), ProviderClaimError> {
    // 1. set membership: the claimer's leaf is under the provider-set root
    let claim_pk = shielded_address(&wit.claim_secret);
    let leaf = provider_leaf(&wit.pk_receipt_hash, &claim_pk);
    if !verify_merkle_path(&stmt.provider_set_root, &leaf, &wit.path) {
        return Err(ProviderClaimError::NotRegistered);
    }
    // 2. per-session nullifier is the correct one for this secret + session
    if stmt.provider_nf != provider_nullifier(&wit.claim_secret, &stmt.session_cm) {
        return Err(ProviderClaimError::NullifierMismatch);
    }
    // 3. shielded payout opens to a note worth exactly the claimed amount
    if stmt.cm_payout != commit(&wit.payout_note) {
        return Err(ProviderClaimError::PayoutCommitment);
    }
    if wit.payout_note.value != stmt.amount {
        return Err(ProviderClaimError::PayoutAmount { got: wit.payout_note.value, want: stmt.amount });
    }
    // 4. ctx binds session/amount/payout/nullifier so none can be swapped
    if stmt.ctx != claim_ctx(&stmt.session_cm, stmt.amount, &stmt.cm_payout, &stmt.provider_nf) {
        return Err(ProviderClaimError::CtxMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    /// Register N providers; return the set tree + the (index, pk_receipt_hash,
    /// claim_secret) of one honest claimant.
    fn registry(n: u8, claimant: u8) -> (MerkleTree, u64, Hash64, Hash64) {
        let mut tree = MerkleTree::new(16);
        let mut chosen = None;
        for i in 0..n {
            let pk_receipt_hash = h(0x40 + i);
            let claim_secret = h(0x80 + i);
            let leaf = provider_leaf(&pk_receipt_hash, &shielded_address(&claim_secret));
            let idx = tree.append(Commitment(leaf));
            if i == claimant {
                chosen = Some((idx, pk_receipt_hash, claim_secret));
            }
        }
        let (idx, pkh, sec) = chosen.unwrap();
        (tree, idx, pkh, sec)
    }

    fn valid() -> (ProviderClaimStatement, ProviderClaimWitness) {
        let (tree, idx, pkh, sec) = registry(8, 3);
        let session_cm = h(0x5E);
        let amount = 1_636_000u64;
        let payout_note = Note { value: amount, owner_pk: shielded_address(&h(0x71)), rho: h(0x11), r: h(0x22), token_id: 0 };
        let cm_payout = commit(&payout_note);
        let provider_nf = provider_nullifier(&sec, &session_cm);
        let ctx = claim_ctx(&session_cm, amount, &cm_payout, &provider_nf);
        let stmt = ProviderClaimStatement { provider_set_root: tree.root(), session_cm, amount, provider_nf, cm_payout, ctx };
        let wit = ProviderClaimWitness {
            pk_receipt_hash: pkh,
            claim_secret: sec,
            leaf_index: idx,
            path: tree.path(idx).unwrap(),
            payout_note,
        };
        (stmt, wit)
    }

    #[test]
    fn registered_provider_claims_anonymously() {
        let (stmt, wit) = valid();
        verify_reference(&stmt, &wit).expect("a registered provider must be able to claim");
        // the public statement names no provider: only a set root + a nullifier
        // that is unlinkable to the leaf without the secret.
        assert_ne!(stmt.provider_nf.0, wit.pk_receipt_hash);
    }

    #[test]
    fn unregistered_provider_is_rejected() {
        let (mut stmt, wit) = valid();
        stmt.provider_set_root = h(0xFF); // claimant not under this root
        assert_eq!(verify_reference(&stmt, &wit), Err(ProviderClaimError::NotRegistered));
    }

    #[test]
    fn double_claim_same_session_reuses_the_nullifier() {
        // Two claims by the same provider for the same session derive the SAME
        // nullifier, so the escrow's nullifier set rejects the second.
        let (_, wit) = valid();
        let session_cm = h(0x5E);
        let nf_a = provider_nullifier(&wit.claim_secret, &session_cm);
        let nf_b = provider_nullifier(&wit.claim_secret, &session_cm);
        assert_eq!(nf_a, nf_b);
        // a different session gives a different (unlinkable) nullifier
        assert_ne!(nf_a, provider_nullifier(&wit.claim_secret, &h(0x5F)));
    }

    #[test]
    fn payout_amount_and_ctx_are_bound() {
        // inflate the private payout note without touching cm_payout → the
        // published commitment no longer opens to it
        let (stmt, mut wit) = valid();
        wit.payout_note.value = stmt.amount + 1;
        assert!(matches!(verify_reference(&stmt, &wit), Err(ProviderClaimError::PayoutCommitment)));

        // a payout amount that disagrees with the note value (cm re-derived so
        // only the amount binding is wrong)
        let (mut s2, mut w2) = valid();
        w2.payout_note.value = s2.amount + 5;
        s2.cm_payout = commit(&w2.payout_note);
        s2.ctx = claim_ctx(&s2.session_cm, s2.amount, &s2.cm_payout, &s2.provider_nf);
        assert_eq!(verify_reference(&s2, &w2), Err(ProviderClaimError::PayoutAmount { got: s2.amount + 5, want: s2.amount }));

        // a directly-corrupted ctx (all other fields consistent) is caught
        let (mut s3, w3) = valid();
        s3.ctx = h(0xFF);
        assert_eq!(verify_reference(&s3, &w3), Err(ProviderClaimError::CtxMismatch));
    }
}
