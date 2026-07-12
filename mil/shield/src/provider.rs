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

use crate::domains::{
    CLAIM_CTX_DOMAIN, MIL_PROVIDER_ID_DOMAIN, PROVIDER_LEAF_DOMAIN, PROVIDER_NF_DOMAIN, PROVIDER_SESSION_RK_DOMAIN, VALUE_DOMAIN,
};
use crate::merkle::{MerklePath, TREE_DEPTH, verify_merkle_path_exact};
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

/// Canonical provider-identity hash `pk_receipt_hash = H_k("misaka-mil-v1/provider-id", pk)`
/// over a real 2592-byte ML-DSA-87 verification key. This is the **derivation the pk_receipt
/// bridge AIR proves** (`docs/bench/plonky3-shield-air/pk_receipt_bind_air.rs`, commit 8208ee0)
/// and is **byte-identical to `misaka_mil_core::ident::provider_id`** (pinned by the differential
/// test `pk_receipt_hash_of_matches_mil_core_provider_id`). Replicated locally here — rather than
/// pulling `misaka-mil-core` (and its ML-DSA / rand tree) into the shield crate's PRODUCTION graph
/// — following the `evm_ctx.rs` local-derivation-plus-differential-test pattern.
///
/// Its role: a provider registry leaf's `pk_receipt_hash` is meant to be this DERIVED value, not
/// a free hash. [`ProviderLeaf::from_pk`] and [`verify_reference_with_pk`] are the Rust boundaries
/// that REQUIRE it (the AIR proves the same hash in-circuit).
pub fn pk_receipt_hash_of(pk: &[u8]) -> Hash64 {
    blake2b_512_keyed(MIL_PROVIDER_ID_DOMAIN, pk)
}

/// A **checked** provider-registry leaf. The only constructors ([`ProviderLeaf::from_pk`] /
/// [`ProviderLeaf::from_pk_and_secret`]) DERIVE `pk_receipt_hash` from a real ML-DSA-87
/// verification key via [`pk_receipt_hash_of`], so the embedded `pk_receipt_hash` is guaranteed
/// to equal `provider_id(pk)` — it can never be an opaque/free hash. This is the leaf-construction
/// half of the pk_receipt wiring: a provider can only enter the anonymity set with a leaf bound to
/// a real key. (The bare [`provider_leaf`] function still exists for the AIR reference corpus,
/// which supplies `pk_receipt_hash` as a private input; use `ProviderLeaf` wherever a leaf is
/// FORMED from an actual key.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderLeaf {
    /// The DERIVED provider-identity hash `pk_receipt_hash_of(pk)`.
    pub pk_receipt_hash: Hash64,
    /// The anonymous claim public key (`shielded_address(claim_secret)`).
    pub claim_pk: Hash64,
    /// The registry Merkle leaf `provider_leaf(pk_receipt_hash, claim_pk)`.
    pub leaf: Hash64,
}

impl ProviderLeaf {
    /// Form a registry leaf from a real 2592-byte ML-DSA-87 verification key and the provider's
    /// anonymous claim public key. `pk_receipt_hash` is DERIVED (never accepted), so a caller
    /// cannot register a leaf whose identity hash is unbound to a real key.
    pub fn from_pk(pk: &[u8], claim_pk: &Hash64) -> Self {
        let pk_receipt_hash = pk_receipt_hash_of(pk);
        let leaf = provider_leaf(&pk_receipt_hash, claim_pk);
        Self { pk_receipt_hash, claim_pk: *claim_pk, leaf }
    }

    /// As [`ProviderLeaf::from_pk`], deriving the claim public key from the claim SECRET
    /// (`claim_pk = shielded_address(claim_secret)`).
    pub fn from_pk_and_secret(pk: &[u8], claim_secret: &Hash64) -> Self {
        Self::from_pk(pk, &shielded_address(claim_secret))
    }
}

/// Enforce that a claim witness's `pk_receipt_hash` is the canonical [`pk_receipt_hash_of`] of a
/// real ML-DSA-87 verification key `pk` (`pk_receipt_hash == provider_id(pk)`). This is the Rust
/// half of the pk_receipt bridge — it turns the otherwise-opaque `pk_receipt_hash` into a value a
/// caller must justify with an actual key. The in-circuit half is the AIR at commit 8208ee0.
pub fn enforce_pk_receipt_binding(pk_receipt_hash: &Hash64, pk: &[u8]) -> Result<(), ProviderClaimError> {
    if *pk_receipt_hash != pk_receipt_hash_of(pk) {
        return Err(ProviderClaimError::PkReceiptHashUnbound);
    }
    Ok(())
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

/// Per-session RECEIPT-SIGNING key `H_k("provider-session-rk", claim_secret ‖ session_cm)`
/// (ADR-0037 §3 #3, the off-circuit half — receipt WITHOUT provider naming). A `SignedReceipt`
/// on the anonymous path is signed under THIS key, not the registered `pk_receipt`, so the
/// receipt names a SESSION rather than a provider. Like the nullifier it is deterministic in
/// `(claim_secret, session_cm)` and unlinkable across sessions (distinct `session_cm` ⇒ distinct
/// key, sharing no provider-visible material), yet it is bound to the SAME `claim_secret` whose
/// `claim_pk = shielded_address(claim_secret)` sits in the provider's registry leaf — so the
/// claim proof (C-P6, B1) can prove "this session key was derived from the secret behind my
/// registered leaf" without revealing the leaf. The in-circuit binding is the pending B1 half;
/// this is the derivation the prover and the honest provider both compute.
pub fn session_receipt_key(claim_secret: &Hash64, session_cm: &Hash64) -> Hash64 {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(claim_secret.as_byte_slice());
    b.extend_from_slice(session_cm.as_byte_slice());
    blake2b_512_keyed(PROVIDER_SESSION_RK_DOMAIN, &b)
}

/// The DEFAULT context binding for an anonymous claim over the statement fields:
/// `H_k("claim-ctx", session_cm ‖ amount ‖ cm_payout ‖ provider_nf)`. Like
/// [`crate::spend::SpendStatement::ctx`], `ctx` is a binding VALUE the settling contract
/// RECOMPUTES (audit H-05: the on-chain `_computeClaimCtx` binds `chainId`, `address(this)`,
/// and `escrowId` on top, so a claim proof is valid for exactly one (chain, contract,
/// escrow) and cannot be replayed across deployments). The relation therefore does not
/// re-derive `ctx` — the proof binds whatever `ctx` the contract puts in the public inputs.
/// This helper is what a prover / test uses to build a plausible statement.
pub fn claim_ctx(session_cm: &Hash64, amount: u64, cm_payout: &Commitment, provider_nf: &Nullifier) -> Hash64 {
    let mut b = Vec::with_capacity(200);
    b.extend_from_slice(session_cm.as_byte_slice());
    b.extend_from_slice(&amount.to_le_bytes());
    b.extend_from_slice(cm_payout.0.as_byte_slice());
    b.extend_from_slice(provider_nf.0.as_byte_slice());
    blake2b_512_keyed(CLAIM_CTX_DOMAIN, &b)
}

/// The claim-v2 hiding VALUE COMMITMENT `v_claim_cm = H_k("value", amount_le8 ‖ blind)`
/// (ADR-0037 §2.2 / circuit_version=4). Byte-identical to the claim-v2 AIR's
/// `value_commit_ref` (72-byte preimage: the 8-byte LE amount then the 64-byte blind).
pub fn value_commit(amount: u64, blind: &Hash64) -> Hash64 {
    let mut b = Vec::with_capacity(72);
    b.extend_from_slice(&amount.to_le_bytes());
    b.extend_from_slice(blind.as_byte_slice());
    blake2b_512_keyed(VALUE_DOMAIN, &b)
}

// (audit H-01) There is deliberately NO `claim_ctx_v2` helper. A claim-v2 statement's
// `ctx` has a SINGLE authority — the contract's `_computeClaimCtx`, mirrored byte-for-byte
// by [`crate::evm_ctx::claim_ctx_onchain`] over the 404-byte deployment preimage
// (chainId‖contract‖escrowId‖setRoot‖sessionCm‖grossSompi‖providerNf‖cmPayout‖keccak(encNote)).
// The former 256-byte 4-field helper would never match a real contract, so provers/tests
// now source the reference `ctx` from `claim_ctx_onchain` directly; the relation binds
// whatever `ctx` the public inputs carry and never re-derives it (audit H-05).

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

/// Public inputs of the HIDDEN-AMOUNT claim (circuit_version = 4, ADR-0037 §2.2 /
/// audit C-01). The public `amount` of v1 is replaced by the hiding value commitment
/// `v_claim_cm`, and — the C-06.2 value-conservation binding — the CONTRACT-COMPUTED
/// whole-sompi 88%-of-gross share is carried as the explicit `provider_share_sompi`
/// public input the relation/circuit binds the private payout amount to.
///
/// Field NAME/ORDER/WIDTH are frozen by
/// [`crate::statement_schema::PROVIDER_CLAIM_V2_STATEMENT_SCHEMA`] (392 bytes),
/// byte-identical to the Solidity builder `MilShieldedEscrow._borshClaimStatementV2`.
///
/// (audit M-08, honest privacy claim) under uniform pricing `gross` — and hence the
/// 88% share — is publicly DERIVABLE from the public `tokIn/tokOut` + snapshot price,
/// so surfacing `provider_share_sompi` publicly costs no privacy: v2 provides
/// *provider unlinkability*, not amount hiding. `v_claim_cm` stays for the
/// committed-ask V3 follow-up where the magnitude itself goes private.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProviderClaimStatementV2 {
    /// Merkle root over the registered active providers (the anonymity set).
    pub provider_set_root: Hash64,
    /// The session commitment (`cmReq`) the escrow was opened against.
    pub session_cm: Hash64,
    /// Hiding commitment `H_k("value", amount ‖ blind)` to the payout amount.
    pub v_claim_cm: Hash64,
    /// At-most-once-per-session provider nullifier.
    pub provider_nf: Nullifier,
    /// The shielded payout note commitment (paid into the value pool).
    pub cm_payout: Commitment,
    /// (C-06.2 / C-01) The CONTRACT-COMPUTED whole-sompi provider share
    /// (88%-of-gross; see [`crate::economics::claim_v2_split`]). The relation
    /// enforces `witness.amount == provider_share_sompi`, so the payout note can
    /// be neither larger (undercollateralized) nor smaller (underpaid) than the
    /// value the contract actually deposits.
    pub provider_share_sompi: u64,
    /// Context binding (recomputed by the contract — `_computeClaimCtx`).
    pub ctx: Hash64,
}

/// Private witness for the v2 claim: v1's membership material plus the payout
/// amount and the value-commitment blind (clear in the reference system, inside
/// the STARK otherwise).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProviderClaimWitnessV2 {
    /// The registry key hash of the claiming provider.
    pub pk_receipt_hash: Hash64,
    /// The provider's anonymous claim secret (`claim_pk = H(claim_secret)`).
    pub claim_secret: Hash64,
    pub leaf_index: u64,
    pub path: MerklePath,
    /// The payout note that opens `cm_payout` (value must equal `amount`).
    pub payout_note: Note,
    /// The payout amount committed in `v_claim_cm` (must equal the statement's
    /// `provider_share_sompi` — the C-06.2 equality).
    pub amount: u64,
    /// Fresh per-claim value-commitment blind.
    pub blind: Hash64,
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
    #[error("v_claim_cm does not open to the declared (amount, blind)")]
    ValueCommitment,
    #[error("witness amount ({got}) does not equal the contract-computed provider share ({want})")]
    ShareMismatch { got: u64, want: u64 },
    #[error("claim-v2 payout note must be the native token (token_id = 0)")]
    TokenNotNative,
    #[error("witness pk_receipt_hash != provider_id(pk): the registry identity is not bound to the supplied ML-DSA-87 key")]
    PkReceiptHashUnbound,
}

/// Verify the anonymous-claim relation transparently (reference system). Sound:
/// only a genuinely-registered provider, settling this session at most once and
/// paying itself exactly `amount` into a shielded note, passes — and *which*
/// provider is not revealed by any public input.
pub fn verify_reference(stmt: &ProviderClaimStatement, wit: &ProviderClaimWitness) -> Result<(), ProviderClaimError> {
    // 1. set membership: the claimer's leaf is under the provider-set root.
    //    (audit M-03) the witness's declared leaf_index must equal the path's index, so the
    //    two cannot disagree and `leaf_index` is a bound, canonical value (not ignored).
    if wit.leaf_index != wit.path.index {
        return Err(ProviderClaimError::NotRegistered);
    }
    let claim_pk = shielded_address(&wit.claim_secret);
    let leaf = provider_leaf(&wit.pk_receipt_hash, &claim_pk);
    // Membership at EXACTLY the circuit-fixed provider-set depth (audit M-03): a short/long
    // path or non-canonical index is rejected, matching the fixed-depth AIR.
    if !verify_merkle_path_exact(&stmt.provider_set_root, &leaf, &wit.path, TREE_DEPTH) {
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
    // NOTE: `ctx` is a binding VALUE the settling contract recomputes (`_computeClaimCtx`,
    // binding chain/contract/escrowId — audit H-05), exactly like `SpendStatement.ctx`. The
    // relation binds it via the public inputs but does not re-derive it, so the contract is
    // free to bind deployment-scoped fields the statement alone does not carry.
    Ok(())
}

/// Verify the HIDDEN-AMOUNT claim relation (circuit_version = 4) transparently —
/// the reference oracle the claim-v2 AIR (`docs/bench/plonky3-shield-air/claim_v2.rs`)
/// proves. Everything [`verify_reference`] enforces, with the public amount replaced
/// by the value-commitment opening PLUS the C-06.2 payout binding (audit C-01):
///
/// 1. membership of the claimer's leaf under `provider_set_root` (exact depth);
/// 2. `provider_nf == H(claim_secret ‖ session_cm)` (at-most-once per session);
/// 3. `v_claim_cm == H_k("value", amount ‖ blind)` — the commitment opens to the
///    witness amount (the AIR's `F_VCM` row);
/// 4. `cm_payout == commit(payout_note)` and `payout_note.value == amount` — the
///    payout note is worth exactly the committed amount (the AIR sources the note's
///    value word from the SAME private `AMT` global, `F_CM_B1`);
/// 5. **`amount == provider_share_sompi`** — the private amount equals the
///    CONTRACT-COMPUTED public share (the AIR's `PI_SHARE` binding), closing the
///    undercollateralized-note / mismatched-payout gap;
/// 6. `payout_note.token_id == 0` — native token only, matching the AIR's
///    hard-zeroed token word (strictly more restrictive than v1, a scope choice).
///
/// `ctx` is bound via the public inputs, not re-derived (the contract recomputes it —
/// H-05), exactly as in v1.
pub fn verify_reference_v2(stmt: &ProviderClaimStatementV2, wit: &ProviderClaimWitnessV2) -> Result<(), ProviderClaimError> {
    // 1. set membership (leaf_index canonical + exact circuit depth, audit M-03).
    if wit.leaf_index != wit.path.index {
        return Err(ProviderClaimError::NotRegistered);
    }
    let claim_pk = shielded_address(&wit.claim_secret);
    let leaf = provider_leaf(&wit.pk_receipt_hash, &claim_pk);
    if !verify_merkle_path_exact(&stmt.provider_set_root, &leaf, &wit.path, TREE_DEPTH) {
        return Err(ProviderClaimError::NotRegistered);
    }
    // 2. per-session nullifier.
    if stmt.provider_nf != provider_nullifier(&wit.claim_secret, &stmt.session_cm) {
        return Err(ProviderClaimError::NullifierMismatch);
    }
    // 3. the value commitment opens to (amount, blind).
    if stmt.v_claim_cm != value_commit(wit.amount, &wit.blind) {
        return Err(ProviderClaimError::ValueCommitment);
    }
    // 4. the shielded payout opens to a note worth exactly the committed amount.
    if stmt.cm_payout != commit(&wit.payout_note) {
        return Err(ProviderClaimError::PayoutCommitment);
    }
    if wit.payout_note.value != wit.amount {
        return Err(ProviderClaimError::PayoutAmount { got: wit.payout_note.value, want: wit.amount });
    }
    // 5. (C-06.2 / C-01) the committed amount IS the contract-computed share.
    if wit.amount != stmt.provider_share_sompi {
        return Err(ProviderClaimError::ShareMismatch { got: wit.amount, want: stmt.provider_share_sompi });
    }
    // 6. native token only (matches the AIR's hard-zeroed token word).
    if wit.payout_note.token_id != 0 {
        return Err(ProviderClaimError::TokenNotNative);
    }
    Ok(())
}

/// [`verify_reference`] PLUS the **pk_receipt binding**: the witness's `pk_receipt_hash` must be
/// the canonical `provider_id(pk)` of the supplied real ML-DSA-87 verification key. Use this at
/// the boundary where a provider forms a claim from its OWN key — it rejects a witness whose
/// `pk_receipt_hash` is unbound to a real key, which the bare [`verify_reference`] cannot detect
/// (it treats `pk_receipt_hash` as an opaque private input, deferring the hash to the AIR at
/// commit 8208ee0). The binding is checked FIRST so a mismatch is diagnosed even if the leaf
/// itself is (spuriously) present in the anonymity-set root.
pub fn verify_reference_with_pk(
    stmt: &ProviderClaimStatement,
    wit: &ProviderClaimWitness,
    pk: &[u8],
) -> Result<(), ProviderClaimError> {
    enforce_pk_receipt_binding(&wit.pk_receipt_hash, pk)?;
    verify_reference(stmt, wit)
}

/// [`verify_reference_v2`] PLUS the pk_receipt binding (see [`verify_reference_with_pk`]).
pub fn verify_reference_v2_with_pk(
    stmt: &ProviderClaimStatementV2,
    wit: &ProviderClaimWitnessV2,
    pk: &[u8],
) -> Result<(), ProviderClaimError> {
    enforce_pk_receipt_binding(&wit.pk_receipt_hash, pk)?;
    verify_reference_v2(stmt, wit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    // A CONTRACT-CONSISTENT claim-v2 `ctx` for fixtures. There is NO separate claim-v2 ctx
    // algorithm: the sole authority is the contract's `_computeClaimCtx`, mirrored byte-for-byte
    // by `evm_ctx::claim_ctx_onchain` over the 404-byte deployment preimage (audit H-01). The
    // deployment-scoped fields are fixed to the representative placeholders the `evm_ctx`
    // differential test uses (chainId=1, contract=0xaa.., escrowId=0x07.., grossSompi=88,
    // keccak(encNote)=0x08..). The reference relation binds whatever `ctx` the public inputs
    // carry and never re-derives it, so these placeholders only shape an opaque tag.
    fn claim_ctx_fixture(set_root: &Hash64, session_cm: &Hash64, provider_nf: &Nullifier, cm_payout: &Commitment) -> Hash64 {
        let mut chain_id = [0u8; 32];
        chain_id[31] = 1;
        let mut gross = [0u8; 32];
        gross[31] = 88;
        crate::evm_ctx::claim_ctx_onchain(&chain_id, &[0xaa; 20], &[0x07; 32], set_root, session_cm, &gross, provider_nf, cm_payout, &[0x08; 32])
    }

    /// A REPRESENTATIVE 2592-byte ML-DSA-87 verification key (the real `pk_receipt` width). The
    /// registry corpus derives every `pk_receipt_hash` from one of these via the checked
    /// [`ProviderLeaf`] path, so the fixtures reflect the ENFORCED invariant
    /// `pk_receipt_hash == provider_id(pk)` — not a placeholder `h(0x40+i)`.
    fn rep_pk(seed: u8) -> Vec<u8> {
        vec![seed; 2592]
    }

    /// The representative verification key of the i-th registered provider.
    fn provider_pk(i: u8) -> Vec<u8> {
        rep_pk(0x40 + i)
    }

    /// Register N providers — each leaf formed via the CHECKED [`ProviderLeaf::from_pk_and_secret`],
    /// so `pk_receipt_hash` is DERIVED from a real key — and return the set tree + the
    /// (index, pk_receipt_hash, claim_secret) of one honest claimant.
    fn registry(n: u8, claimant: u8) -> (MerkleTree, u64, Hash64, Hash64) {
        let mut tree = MerkleTree::new(TREE_DEPTH);
        let mut chosen = None;
        for i in 0..n {
            let claim_secret = h(0x80 + i);
            let reg = ProviderLeaf::from_pk_and_secret(&provider_pk(i), &claim_secret);
            let idx = tree.append(Commitment(reg.leaf));
            if i == claimant {
                chosen = Some((idx, reg.pk_receipt_hash, claim_secret));
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

        // `ctx` is a binding VALUE the contract recomputes (audit H-05), not a relation
        // check — the proof binds whatever ctx the public inputs carry, so the relation
        // accepts any ctx (the on-chain `_computeClaimCtx` is the authority).
        let (mut s3, w3) = valid();
        s3.ctx = h(0xFF);
        verify_reference(&s3, &w3).expect("relation binds but does not re-derive ctx");
    }

    // ---- claim v2 (hidden-amount, circuit_version = 4 — audit C-01/C-06.2) ----

    fn valid_v2(share: u64) -> (ProviderClaimStatementV2, ProviderClaimWitnessV2) {
        let (tree, idx, pkh, sec) = registry(8, 3);
        let session_cm = h(0x5E);
        let blind = h(0xB1);
        let v_claim_cm = value_commit(share, &blind);
        let payout_note = Note { value: share, owner_pk: shielded_address(&h(0x71)), rho: h(0x11), r: h(0x22), token_id: 0 };
        let cm_payout = commit(&payout_note);
        let provider_nf = provider_nullifier(&sec, &session_cm);
        let ctx = claim_ctx_fixture(&tree.root(), &session_cm, &provider_nf, &cm_payout);
        let stmt = ProviderClaimStatementV2 {
            provider_set_root: tree.root(),
            session_cm,
            v_claim_cm,
            provider_nf,
            cm_payout,
            provider_share_sompi: share,
            ctx,
        };
        let wit = ProviderClaimWitnessV2 {
            pk_receipt_hash: pkh,
            claim_secret: sec,
            leaf_index: idx,
            path: tree.path(idx).unwrap(),
            payout_note,
            amount: share,
            blind,
        };
        (stmt, wit)
    }

    #[test]
    fn v2_registered_provider_claims_with_bound_share() {
        let (stmt, wit) = valid_v2(88);
        verify_reference_v2(&stmt, &wit).expect("a registered provider with a share-bound payout must pass");
        // boundary shares: zero and u64::MAX both verify when consistently bound.
        for share in [0u64, u64::MAX] {
            let (s, w) = valid_v2(share);
            verify_reference_v2(&s, &w).unwrap_or_else(|e| panic!("share {share} must verify when bound: {e}"));
        }
    }

    #[test]
    fn v2_share_mutations_are_rejected() {
        // (audit C-01 acceptance) payout ±1 in the PUBLIC share (contract-computed) vs
        // the committed private amount — every mismatch direction must be rejected.
        for delta in [1i128, -1i128] {
            let (mut stmt, wit) = valid_v2(88);
            stmt.provider_share_sompi = (88i128 + delta) as u64;
            assert_eq!(
                verify_reference_v2(&stmt, &wit),
                Err(ProviderClaimError::ShareMismatch { got: 88, want: (88i128 + delta) as u64 }),
                "public share {delta:+} must be rejected"
            );
        }
        // zero / max public share against an 88-committed witness.
        for bogus in [0u64, u64::MAX] {
            let (mut stmt, wit) = valid_v2(88);
            stmt.provider_share_sompi = bogus;
            assert_eq!(verify_reference_v2(&stmt, &wit), Err(ProviderClaimError::ShareMismatch { got: 88, want: bogus }));
        }
        // witness amount ±1 against the honest statement: the value commitment no
        // longer opens (checked BEFORE the share equality — both bindings hold).
        for wa in [87u64, 89u64] {
            let (stmt, mut wit) = valid_v2(88);
            wit.amount = wa;
            assert_eq!(verify_reference_v2(&stmt, &wit), Err(ProviderClaimError::ValueCommitment));
        }
        // a FULLY re-derived over-claim (attacker recomputes v_claim_cm, cm_payout and ctx
        // for amount+1 but cannot change the contract-computed share): ShareMismatch.
        let (mut stmt, mut wit) = valid_v2(88);
        wit.amount = 89;
        wit.payout_note.value = 89;
        stmt.v_claim_cm = value_commit(89, &wit.blind);
        stmt.cm_payout = commit(&wit.payout_note);
        stmt.ctx = claim_ctx_fixture(&stmt.provider_set_root, &stmt.session_cm, &stmt.provider_nf, &stmt.cm_payout);
        assert_eq!(
            verify_reference_v2(&stmt, &wit),
            Err(ProviderClaimError::ShareMismatch { got: 89, want: 88 }),
            "an over-claimed note larger than the contract share must be rejected (C-06.2)"
        );
    }

    #[test]
    fn v2_note_and_commitment_bindings_hold() {
        // note value != committed amount (cm re-derived so only the note binding fails).
        let (mut stmt, mut wit) = valid_v2(88);
        wit.payout_note.value = 90;
        stmt.cm_payout = commit(&wit.payout_note);
        assert_eq!(verify_reference_v2(&stmt, &wit), Err(ProviderClaimError::PayoutAmount { got: 90, want: 88 }));
        // wrong blind → the value commitment does not open.
        let (stmt, mut wit) = valid_v2(88);
        wit.blind = h(0xEE);
        assert_eq!(verify_reference_v2(&stmt, &wit), Err(ProviderClaimError::ValueCommitment));
        // inflating the note without re-deriving cm_payout.
        let (stmt, mut wit) = valid_v2(88);
        wit.payout_note.value = 89;
        assert_eq!(verify_reference_v2(&stmt, &wit), Err(ProviderClaimError::PayoutCommitment));
        // non-native token (AIR hard-zeroes the token word) — cm re-derived so ONLY the
        // token check fails.
        let (mut stmt, mut wit) = valid_v2(88);
        wit.payout_note.token_id = 1;
        stmt.cm_payout = commit(&wit.payout_note);
        assert_eq!(verify_reference_v2(&stmt, &wit), Err(ProviderClaimError::TokenNotNative));
        // unregistered claimer.
        let (mut stmt, wit) = valid_v2(88);
        stmt.provider_set_root = h(0xFF);
        assert_eq!(verify_reference_v2(&stmt, &wit), Err(ProviderClaimError::NotRegistered));
        // wrong session → nullifier mismatch.
        let (mut stmt, wit) = valid_v2(88);
        stmt.session_cm = h(0x5F);
        assert_eq!(verify_reference_v2(&stmt, &wit), Err(ProviderClaimError::NullifierMismatch));
    }

    #[test]
    fn v2_value_commit_is_hiding_material_and_field_sensitive() {
        let blind = h(0xB1);
        assert_eq!(value_commit(88, &blind), value_commit(88, &blind), "deterministic");
        assert_ne!(value_commit(88, &blind), value_commit(89, &blind), "amount moves the commitment");
        assert_ne!(value_commit(88, &blind), value_commit(88, &h(0xB2)), "blind moves the commitment");
        // domain-separated from the note commitment and the nullifier domains.
        let n = Note { value: 88, owner_pk: h(1), rho: h(2), r: h(3), token_id: 0 };
        assert_ne!(value_commit(88, &blind).as_byte_slice(), commit(&n).0.as_byte_slice());
    }

    // ---- pk_receipt system wiring: pk_receipt_hash == provider_id(pk) ----

    #[test]
    fn pk_receipt_hash_of_matches_mil_core_provider_id() {
        // (differential — the `evm_ctx.rs` pattern) the shield's local derivation MUST be
        // byte-identical to mil-core's canonical `provider_id` and, therefore, to the pk_receipt
        // bridge AIR it proves (`pk_receipt_bind_air.rs`, commit 8208ee0).
        let pk = rep_pk(0x5A);
        assert_eq!(
            pk_receipt_hash_of(&pk),
            misaka_mil_core::ident::provider_id(&pk),
            "shield pk_receipt_hash_of must equal mil-core provider_id byte-for-byte"
        );
        // the domain string is pinned to the mil-core constant (no silent drift).
        assert_eq!(MIL_PROVIDER_ID_DOMAIN, misaka_mil_core::domains::MIL_PROVIDER_ID_DOMAIN);
        // input sensitivity: a one-bit flip in the key moves the hash.
        let mut pk2 = pk.clone();
        pk2[0] ^= 1;
        assert_ne!(pk_receipt_hash_of(&pk), pk_receipt_hash_of(&pk2));
    }

    #[test]
    fn provider_leaf_from_pk_derives_pk_receipt_hash() {
        // the checked constructor DERIVES pk_receipt_hash and forms the SAME leaf the opaque API
        // would over that derived hash — so the registry leaf is provably bound to a real key.
        let pk = rep_pk(0x40);
        let claim_secret = h(0x80);
        let claim_pk = shielded_address(&claim_secret);
        let reg = ProviderLeaf::from_pk(&pk, &claim_pk);
        assert_eq!(reg.pk_receipt_hash, pk_receipt_hash_of(&pk));
        assert_eq!(reg.claim_pk, claim_pk);
        assert_eq!(reg.leaf, provider_leaf(&pk_receipt_hash_of(&pk), &claim_pk));
        // the two constructors agree.
        assert_eq!(ProviderLeaf::from_pk_and_secret(&pk, &claim_secret), reg);
        // a different key yields a different identity (and leaf).
        assert_ne!(ProviderLeaf::from_pk(&rep_pk(0x41), &claim_pk).leaf, reg.leaf);
    }

    #[test]
    fn unbound_pk_receipt_hash_is_rejected_by_the_relation() {
        // The honest witness's pk_receipt_hash IS the derived identity of the claimant's key ...
        let (stmt, wit) = valid();
        let pk = provider_pk(3); // claimant index in `valid()` / `registry(8, 3)`
        assert_eq!(wit.pk_receipt_hash, pk_receipt_hash_of(&pk));
        verify_reference_with_pk(&stmt, &wit, &pk).expect("a pk-bound witness must pass");

        // ... supplying the WRONG key is rejected, though membership/nullifier/payout are untouched
        // — exactly the free-`pk_receipt_hash` gap the wiring closes.
        assert_eq!(verify_reference_with_pk(&stmt, &wit, &rep_pk(0x99)), Err(ProviderClaimError::PkReceiptHashUnbound));

        // A leaf whose pk_receipt_hash was NEVER a `provider_id(pk)` (a forged opaque hash) is
        // accepted by the OPAQUE relation but cannot be justified by ANY real key.
        let forged = h(0xEF);
        let claim_secret = h(0x83);
        let claim_pk = shielded_address(&claim_secret);
        let mut tree = MerkleTree::new(TREE_DEPTH);
        let idx = tree.append(Commitment(provider_leaf(&forged, &claim_pk)));
        let session_cm = h(0x5E);
        let payout_note = Note { value: 1, owner_pk: shielded_address(&h(0x71)), rho: h(0x11), r: h(0x22), token_id: 0 };
        let cm_payout = commit(&payout_note);
        let provider_nf = provider_nullifier(&claim_secret, &session_cm);
        let forged_stmt =
            ProviderClaimStatement { provider_set_root: tree.root(), session_cm, amount: 1, provider_nf, cm_payout, ctx: h(0) };
        let forged_wit = ProviderClaimWitness {
            pk_receipt_hash: forged,
            claim_secret,
            leaf_index: idx,
            path: tree.path(idx).unwrap(),
            payout_note,
        };
        verify_reference(&forged_stmt, &forged_wit).expect("opaque relation accepts a free pk_receipt_hash (the gap)");
        assert_eq!(
            verify_reference_with_pk(&forged_stmt, &forged_wit, &rep_pk(0x40)),
            Err(ProviderClaimError::PkReceiptHashUnbound),
            "no real key can justify a forged opaque pk_receipt_hash"
        );
    }

    #[test]
    fn v2_unbound_pk_receipt_hash_is_rejected_by_the_relation() {
        let (stmt, wit) = valid_v2(88);
        let pk = provider_pk(3);
        assert_eq!(wit.pk_receipt_hash, pk_receipt_hash_of(&pk));
        verify_reference_v2_with_pk(&stmt, &wit, &pk).expect("a pk-bound v2 witness must pass");
        assert_eq!(
            verify_reference_v2_with_pk(&stmt, &wit, &rep_pk(0x99)),
            Err(ProviderClaimError::PkReceiptHashUnbound)
        );
    }
}
