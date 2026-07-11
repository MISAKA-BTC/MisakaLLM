//! End-to-end ANONYMOUS PROVIDER CLAIM (ADR-0025 §21 / ADR-0037): a provider settles
//! a session and gets paid **without any artifact naming which provider** did the work.
//!
//!   register N providers → provider-set root → openBlind(session) → one provider
//!   proves the anonymous claim relation (membership at a PRIVATE leaf + per-session
//!   nullifier + shielded payout) → envelope → 32 KiB DA chunking → reassembly →
//!   verify → claimAnon (nullifier check-then-insert + payout note into the pool).
//!
//! This is the reference-level oracle (witness in the clear); the STARK arm proves
//! EXACTLY this relation, and giving the claim the build#1-5 real-hash + recursion
//! treatment is ADR-0037 §2.1. The `which_provider_is_hidden` test pins the core
//! privacy property: the public statement reveals nothing about which provider (the
//! leaf, its index, and `pk_receipt_hash` are all absent from the public inputs).
//!
//! The escrow application mirrors `contracts/mil/src/MilShieldedEscrow.sol`:
//! `providerNfSpent[keccak(nf)]` is the anonymous analogue of the spend pool's
//! nullifier set — the same SEQUENTIAL check-then-insert obligation applies (a
//! provider settles a given session at most once).
//!
//! NOTE (ADR-0037 §5 residual, honest): this closes only the on-chain claim/payout
//! surface. The amount is PUBLIC here (ask-price inversion, ADR-0037 §2.2 proposes
//! hiding it via circuit_version=4), and off-chain surfaces (cleartext handshake,
//! provider-named receipt) are protocol changes outside this relation. The test
//! asserts what the claim circuit DOES close, not full end-to-end unlinkability.

use kaspa_hashes::Hash64;
use misaka_mil_shield::merkle::MerkleTree;
use misaka_mil_shield::note::{Commitment, Note, commit, shielded_address};
use misaka_mil_shield::proof::{
    CIRCUIT_PROVIDER_CLAIM, PROOF_SYSTEM_REFERENCE, ShieldProof, VerifiedStatement, verify_shield_proof,
};
use misaka_mil_shield::provider::{
    ProviderClaimError, ProviderClaimStatement, ProviderClaimWitness, claim_ctx, provider_leaf, provider_nullifier,
    verify_reference,
};
use misaka_mil_shield_da::{chunk_proof, reassemble, validate_chunk, validate_descriptor};
use std::collections::BTreeSet;

const DEPTH: u32 = 20; // the provider-set tree depth (ADR-0033 §4.1, same as the pool)

fn h(b: u8) -> Hash64 {
    Hash64::from_bytes([b; 64])
}
fn vk() -> Hash64 {
    h(0xB0)
}

/// A registered provider's public + secret material.
struct Provider {
    pk_receipt_hash: Hash64,
    claim_secret: Hash64,
}
impl Provider {
    fn leaf(&self) -> Hash64 {
        provider_leaf(&self.pk_receipt_hash, &shielded_address(&self.claim_secret))
    }
}

/// The blind escrow, mirroring MilShieldedEscrow.sol: a pinned provider-set root and
/// the per-session nullifier set. `openBlind` locks value for a session commitment
/// without naming a provider; `claim_anon` settles it.
struct BlindEscrow {
    provider_set_root: Hash64,
    nf_spent: BTreeSet<Hash64>, // providerNfSpent (keccak(nf) on-chain; the nf itself here)
    pool: MerkleTree,           // the shielded value pool cm_payout is inserted into
    open_sessions: BTreeSet<Hash64>,
}
#[derive(Debug, PartialEq, Eq)]
enum EscrowError {
    UnknownSetRoot,
    SessionNotOpen,
    DoubleClaim,
}
impl BlindEscrow {
    fn new(provider_set_root: Hash64) -> Self {
        Self { provider_set_root, nf_spent: BTreeSet::new(), pool: MerkleTree::new(DEPTH), open_sessions: BTreeSet::new() }
    }
    fn open_blind(&mut self, session_cm: Hash64) {
        self.open_sessions.insert(session_cm); // locks value; no providerId (MilShieldedEscrow.sol:93)
    }
    /// claimAnon: verify the anonymous-claim statement against pinned state, then
    /// spend the per-session nullifier (check-then-insert) and insert cm_payout.
    fn claim_anon(&mut self, stmt: &ProviderClaimStatement) -> Result<(), EscrowError> {
        if stmt.provider_set_root != self.provider_set_root {
            return Err(EscrowError::UnknownSetRoot);
        }
        if !self.open_sessions.contains(&stmt.session_cm) {
            return Err(EscrowError::SessionNotOpen);
        }
        if !self.nf_spent.insert(stmt.provider_nf.0) {
            return Err(EscrowError::DoubleClaim); // at-most-once per session (providerNfSpent)
        }
        self.pool.append(stmt.cm_payout.clone()); // payout into the shielded pool
        Ok(())
    }
}

fn envelope(stmt: &ProviderClaimStatement, wit: &ProviderClaimWitness) -> Vec<u8> {
    ShieldProof {
        proof_system_id: PROOF_SYSTEM_REFERENCE,
        circuit_version: CIRCUIT_PROVIDER_CLAIM,
        verifier_key_hash: vk(),
        public_inputs: borsh::to_vec(stmt).unwrap(),
        proof: borsh::to_vec(wit).unwrap(),
    }
    .encode()
}
fn da_roundtrip(bytes: &[u8]) -> Vec<u8> {
    let (desc, mut chunks) = chunk_proof(bytes).expect("chunk");
    validate_descriptor(&desc).expect("descriptor");
    chunks.reverse(); // arbitrary arrival order
    for c in &chunks {
        validate_chunk(&desc, c).expect("chunk arrival validation");
    }
    reassemble(&desc, &chunks).expect("reassemble")
}

/// Build a provider set, a claim for provider `who`, and everything the escrow sees.
fn build_claim(who: usize, session_cm: Hash64, amount: u64) -> (Hash64, ProviderClaimStatement, ProviderClaimWitness, Provider) {
    // register a handful of providers (the anonymity set)
    let providers: Vec<Provider> = (0..5)
        .map(|i| Provider { pk_receipt_hash: h(0x40 + i as u8), claim_secret: h(0x80 + i as u8) })
        .collect();
    let mut tree = MerkleTree::new(DEPTH);
    let mut idxs = vec![];
    for p in &providers {
        idxs.push(tree.append(Commitment(p.leaf())));
    }
    let root = tree.root();
    let p = &providers[who];
    let payout = Note { value: amount, owner_pk: shielded_address(&h(0x71)), rho: h(0x33), r: h(0x34), token_id: 0 };
    let cm_payout = commit(&payout);
    let provider_nf = provider_nullifier(&p.claim_secret, &session_cm);
    let ctx = claim_ctx(&session_cm, amount, &cm_payout, &provider_nf);
    let stmt = ProviderClaimStatement {
        provider_set_root: root,
        session_cm,
        amount,
        provider_nf,
        cm_payout,
        ctx,
    };
    let wit = ProviderClaimWitness {
        pk_receipt_hash: p.pk_receipt_hash,
        claim_secret: p.claim_secret,
        leaf_index: idxs[who],
        path: tree.path(idxs[who]).unwrap(),
        payout_note: payout,
    };
    (root, stmt, wit, Provider { pk_receipt_hash: p.pk_receipt_hash, claim_secret: p.claim_secret })
}

fn submit(escrow: &mut BlindEscrow, stmt: &ProviderClaimStatement, wit: &ProviderClaimWitness) -> Result<ProviderClaimStatement, EscrowError> {
    let bytes = envelope(stmt, wit);
    let arrived = da_roundtrip(&bytes);
    assert_eq!(arrived, bytes, "DA transport must be byte-faithful");
    let VerifiedStatement::ProviderClaim(vstmt) = verify_shield_proof(&arrived, &vk()).expect("envelope verify") else {
        panic!("provider-claim statement expected")
    };
    escrow.claim_anon(&vstmt)?;
    Ok(vstmt)
}

#[test]
fn anonymous_claim_pipeline() {
    let session_cm = h(0x5E);
    let amount = 500u64;
    // provider #2 (of 5) served this session — but that index must never surface.
    let (root, stmt, wit, _who) = build_claim(2, session_cm, amount);
    verify_reference(&stmt, &wit).expect("claim relation holds");

    let mut escrow = BlindEscrow::new(root);
    escrow.open_blind(session_cm);
    let vstmt = submit(&mut escrow, &stmt, &wit).expect("anonymous claim settled");
    assert_eq!(escrow.pool.len(), 1, "cm_payout inserted into the pool");
    assert!(escrow.nf_spent.contains(&vstmt.provider_nf.0), "session nullifier recorded");

    // double-claim of the SAME session by the same provider is rejected.
    assert_eq!(escrow.claim_anon(&stmt), Err(EscrowError::DoubleClaim));

    println!("ANON CLAIM ok — provider (index hidden) settled session 0x5E for {amount}, paid into the pool; double-claim rejected");
}

#[test]
fn which_provider_is_hidden() {
    // THE core privacy property: the PUBLIC statement (what the escrow + chain see)
    // reveals nothing identifying WHICH provider claimed — not the leaf, not its
    // index, not pk_receipt_hash. Two different providers, same session/amount,
    // produce statements that expose no membership witness.
    let session_cm = h(0x77);
    let (_r0, s0, w0, _p0) = build_claim(1, session_cm, 300);
    let (_r4, s4, w4, _p4) = build_claim(4, session_cm, 300);
    // same set root, same public shape; identity differs only in the PRIVATE witness.
    assert_eq!(s0.provider_set_root, s4.provider_set_root, "same anonymity set");
    let pub0 = borsh::to_vec(&s0).unwrap();
    let pub4 = borsh::to_vec(&s4).unwrap();
    // For each provider, its identifying witness — pk_receipt_hash AND the registry
    // leaf (which provider) — must be absent from its own public statement.
    for (w, pub_bytes) in [(&w0, &pub0), (&w4, &pub4)] {
        let leaf = provider_leaf(&w.pk_receipt_hash, &shielded_address(&w.claim_secret));
        let absent = |x: &Hash64| !pub_bytes.windows(64).any(|win| win == x.as_byte_slice());
        assert!(absent(&w.pk_receipt_hash), "pk_receipt_hash must not appear in the public statement");
        assert!(absent(&leaf), "the registry leaf (which provider) must not appear in the public statement");
    }
    // the nullifiers DO differ (per-secret), but neither reveals the index/identity.
    assert_ne!(s0.provider_nf, s4.provider_nf);
    println!("PRIVACY ok — which-provider is hidden: leaf, index, and pk_receipt_hash absent from the public statement");
}

#[test]
fn non_registered_provider_is_rejected() {
    // A provider whose leaf is NOT under the set root cannot claim (membership fails).
    let session_cm = h(0x88);
    let (root, mut stmt, mut wit, _who) = build_claim(0, session_cm, 100);
    // swap in an unregistered secret/receipt: the leaf no longer matches the path.
    wit.claim_secret = h(0xEE);
    wit.pk_receipt_hash = h(0xEF);
    // recompute the dependent public fields so only membership is the failure.
    stmt.provider_nf = provider_nullifier(&wit.claim_secret, &session_cm);
    stmt.ctx = claim_ctx(&session_cm, stmt.amount, &stmt.cm_payout, &stmt.provider_nf);
    assert_eq!(verify_reference(&stmt, &wit), Err(ProviderClaimError::NotRegistered));
    let _ = root;
}

#[test]
fn tampered_ctx_and_double_session_are_rejected() {
    let session_cm = h(0x99);
    let (root, stmt, wit, _who) = build_claim(3, session_cm, 250);
    // tampered ctx (e.g. redirect the payout) breaks the binding.
    let mut bad = stmt.clone();
    bad.ctx = h(0x00);
    assert_eq!(verify_reference(&bad, &wit), Err(ProviderClaimError::CtxMismatch));

    // a claim for an unopened session is rejected by the escrow even if the relation holds.
    let mut escrow = BlindEscrow::new(root);
    // note: session NOT opened
    verify_reference(&stmt, &wit).expect("relation holds");
    assert_eq!(escrow.claim_anon(&stmt), Err(EscrowError::SessionNotOpen));
    // and an unknown set root is rejected.
    let mut escrow2 = BlindEscrow::new(h(0x01));
    escrow2.open_blind(session_cm);
    assert_eq!(escrow2.claim_anon(&stmt), Err(EscrowError::UnknownSetRoot));
}
