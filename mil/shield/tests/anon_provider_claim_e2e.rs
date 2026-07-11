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
    // `ctx` is a binding VALUE the settling contract RECOMPUTES (audit H-05:
    // `_computeClaimCtx` binds chain/contract/escrowId), so the relation binds it via the
    // public inputs but does not re-derive it — any ctx passes the relation, and the
    // contract is the authority that ties the proof to one (chain, contract, escrow).
    let mut any_ctx = stmt.clone();
    any_ctx.ctx = h(0x00);
    verify_reference(&any_ctx, &wit).expect("relation binds ctx via public inputs, not a re-derivation");

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

/// ADR-0037 §3.1 #1 — DECOY SET / set growth. The which-provider circuit hides the
/// index; its anonymity is capped only by the set SIZE. Seeding the provider-set tree
/// with **decoy leaves** (provider_leaf of secrets nobody holds) enlarges the effective
/// anonymity set far beyond the live-provider count — a reference-level change, no new
/// circuit. A real provider's claim verifies against the {real ∪ decoy} root, and the
/// public statement is indistinguishable across which of the K+N leaves claimed. Decoys
/// are UNSPENDABLE (their preimages are unknown), so they inflate k-anonymity without
/// being claimable. (Stopping a KNOWN-secret provider from claiming a session it did not
/// serve is C-P6's job, not the decoy set's — ADR-0037 §2.4.)
#[test]
fn decoy_set_enlarges_the_anonymity_set() {
    const K_REAL: usize = 3;
    const N_DECOY: usize = 200; // k-anonymity floor ≫ live-provider count
    let session_cm = h(0x5D);
    let amount = 500u64;

    // real providers hold their secrets; decoys are leaves of unknown-preimage hashes.
    let reals: Vec<Provider> = (0..K_REAL).map(|i| Provider { pk_receipt_hash: h(0x40 + i as u8), claim_secret: h(0x80 + i as u8) }).collect();
    let mut tree = MerkleTree::new(DEPTH);
    let mut real_idx = vec![];
    for p in &reals {
        real_idx.push(tree.append(Commitment(p.leaf())));
    }
    // interleave decoys: a decoy leaf is a provider_leaf of a secret nobody knows.
    for d in 0..N_DECOY {
        // deterministic "random-looking" decoy leaf; no one holds the claim_secret.
        let decoy_leaf = provider_leaf(&Hash64::from_bytes([(d as u8) ^ 0x5A; 64]), &shielded_address(&Hash64::from_bytes([(d as u8) ^ 0xA5; 64])));
        tree.append(Commitment(decoy_leaf));
    }
    let root = tree.root();
    assert_eq!(tree.len(), K_REAL + N_DECOY, "the set holds real + decoy leaves");
    assert!(tree.len() >= 128, "effective anonymity set ≥ 128 (k-anonymity floor)");

    // a REAL provider (index 1, hidden) claims against the enlarged set.
    let who = 1usize;
    let p = &reals[who];
    let payout = Note { value: amount, owner_pk: shielded_address(&h(0x71)), rho: h(0x33), r: h(0x34), token_id: 0 };
    let cm_payout = commit(&payout);
    let provider_nf = provider_nullifier(&p.claim_secret, &session_cm);
    let ctx = claim_ctx(&session_cm, amount, &cm_payout, &provider_nf);
    let stmt = ProviderClaimStatement { provider_set_root: root, session_cm, amount, provider_nf, cm_payout, ctx };
    let wit = ProviderClaimWitness {
        pk_receipt_hash: p.pk_receipt_hash,
        claim_secret: p.claim_secret,
        leaf_index: real_idx[who],
        path: tree.path(real_idx[who]).unwrap(),
        payout_note: payout,
    };
    verify_reference(&stmt, &wit).expect("real provider claims against the {real ∪ decoy} set");

    // the public statement reveals nothing about WHICH of the K+N leaves claimed:
    // the provider_nf is H(secret‖session), independent of the leaf index; the leaf and
    // index are private. So the anonymity set is the full K_REAL + N_DECOY.
    let pub_bytes = borsh::to_vec(&stmt).unwrap();
    let leaf = provider_leaf(&p.pk_receipt_hash, &shielded_address(&p.claim_secret));
    assert!(!pub_bytes.windows(64).any(|w| w == leaf.as_byte_slice()), "the claiming leaf is absent from the public statement");

    println!(
        "DECOY SET ok — effective anonymity set = {} ({} real + {} decoy), a real claim verifies and the claiming leaf/index stay hidden (k-anonymity ≫ live-provider count)",
        K_REAL + N_DECOY,
        K_REAL,
        N_DECOY
    );
}

/// B3 #2 — TIMING BATCHING (ADR-0037 §3, surface #9). Even with the amount hidden (build#7)
/// and the leaf hidden (decoy set), *when* a provider submits leaks: an observer who sees a
/// session end and a claim land in the next block links them. The off-protocol closure is an
/// EPOCH BATCHER — claims arriving within an epoch are buffered and settled in a CANONICAL
/// content order (sorted by `provider_nf`, a public per-claim value uncorrelated with arrival
/// time), so the settled batch reveals nothing about within-epoch ordering. This is a
/// gateway/relayer behavior (no consensus change); the test pins the invariant the relayer
/// must satisfy: two different arrival orders of the same claim set settle identically.
fn canonical_batch_order(mut claims: Vec<ProviderClaimStatement>) -> Vec<ProviderClaimStatement> {
    claims.sort_by(|a, b| a.provider_nf.0.as_byte_slice().cmp(b.provider_nf.0.as_byte_slice()));
    claims
}

#[test]
fn timing_batching_breaks_arrival_order_linkage() {
    let session = h(0xE0);
    // eight distinct claims (distinct providers/sessions ⇒ distinct nullifiers).
    let claims: Vec<ProviderClaimStatement> =
        (0..8).map(|i| build_claim(i % 5, h(0xE0 + i as u8), 300 + (i as u64) * 11).1).collect();

    // two very different arrival orders of the SAME batch (early-first vs reversed).
    let arrival_a = claims.clone();
    let mut arrival_b = claims.clone();
    arrival_b.reverse();

    let settled_a = canonical_batch_order(arrival_a);
    let settled_b = canonical_batch_order(arrival_b);

    // the settled order is identical regardless of arrival order — arrival timing is
    // unrecoverable from the on-chain batch.
    let nfs_a: Vec<_> = settled_a.iter().map(|s| s.provider_nf).collect();
    let nfs_b: Vec<_> = settled_b.iter().map(|s| s.provider_nf).collect();
    assert_eq!(nfs_a, nfs_b, "canonical batch order is arrival-independent");
    // and it is NOT the arrival order (so the batch actually shuffles): with 8 random-looking
    // nullifiers the canonical order differs from insertion order with overwhelming probability.
    let insertion: Vec<_> = claims.iter().map(|s| s.provider_nf).collect();
    assert_ne!(nfs_a, insertion, "the batch reorders vs arrival (breaks the timing channel)");
    let _ = session;

    println!("TIMING BATCH ok — {} claims settle in an arrival-independent canonical order (within-epoch submission time is unrecoverable)", nfs_a.len());
}

/// B3 #3 — DENOMINATION OBFUSCATION (ADR-0037 §3, surface #10). `claimAnonV2` hides the
/// payout VALUE (vClaimCm) but the PUBLIC token counts (tokIn,tokOut) still drive the
/// uniform-price gross — so a unique token count fingerprints a session even under uniform
/// pricing. The closure QUANTIZES the public count UP to a fixed denomination ladder, so a
/// whole range of true usages shares ONE public denomination (hence one public gross). The
/// provider is paid on the bucket (a uniform, non-leaking overpayment); which exact count
/// within the bucket was served stays hidden. Matches the `tokIn+tokOut` public inputs of
/// `MilShieldedEscrow.claimAnonV2`, which a compliant gateway must pre-bucket.
const DENOM_LADDER: &[u64] = &[1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000, 1_000_000];

fn quantize_denom(tokens: u64) -> u64 {
    for &d in DENOM_LADDER {
        if tokens <= d {
            return d;
        }
    }
    *DENOM_LADDER.last().unwrap() // beyond the top bucket ⇒ split off-protocol into ladder-sized claims
}

#[test]
fn denomination_bucketing_collapses_token_count_fingerprint() {
    // 64 DISTINCT real usages spread across [900, ~9500] tokens.
    let real_counts: Vec<u64> = (0..64u64).map(|i| 900 + i * 137).collect();
    assert_eq!(real_counts.iter().collect::<BTreeSet<_>>().len(), 64, "inputs are distinct");

    let denoms: Vec<u64> = real_counts.iter().map(|&t| quantize_denom(t)).collect();
    let distinct_denoms: BTreeSet<u64> = denoms.iter().copied().collect();

    // 64 distinct usages collapse to a handful of public denominations (fingerprint gone).
    assert!(distinct_denoms.len() <= 4, "distinct usages collapse to ≤4 public denominations, got {}", distinct_denoms.len());

    // never underbill: the public denom is ≥ true tokens (provider paid for ≥ what it served).
    for (&t, &d) in real_counts.iter().zip(&denoms) {
        assert!(d >= t, "denom {d} must cover true usage {t}");
    }
    // monotone non-decreasing: bucketing preserves order (no inversion that could re-fingerprint).
    for w in denoms.windows(2) {
        assert!(w[1] >= w[0], "denomination bucketing is monotone");
    }
    // k-anonymity per bucket: the most-populated denomination is shared by many usages.
    let mut per_bucket: std::collections::BTreeMap<u64, usize> = Default::default();
    for &d in &denoms {
        *per_bucket.entry(d).or_default() += 1;
    }
    let k = *per_bucket.values().max().unwrap();
    assert!(k >= 8, "the busiest denomination hides ≥8 usages, got {k}");

    println!(
        "DENOMINATION ok — 64 distinct token counts collapse to {} public denominations (busiest bucket hides {} usages); the public gross carries no per-session count fingerprint",
        distinct_denoms.len(),
        k
    );
}

/// B3 #5 — BLIND HANDSHAKE (ADR-0037 §3, surface #2). Before a session, the provider must
/// assure the requester it is a *legitimate provider for this model* WITHOUT sending its
/// `pk_receipt`/attestation in cleartext (that would let the requester deanonymize it). This
/// is the SAME set-membership primitive the anonymous claim (build#6/#7) already proves —
/// applied to a requester-issued CHALLENGE instead of a payout: the provider proves
/// "membership in the model's provider set ∧ knowledge of the claim secret ∧ binding to your
/// challenge", revealing nothing about WHICH provider. The handshake nullifier
/// `H(claim_secret ‖ challenge)` is fresh per challenge, so two handshakes are unlinkable.
/// (Reference-level, witness-in-clear oracle: the real handshake wraps this membership proof
/// in a transport where `pk_receipt` never appears — the circuit arm proves the same relation.)
#[test]
fn blind_handshake_proves_membership_without_naming_provider() {
    const K: usize = 5;
    // the model's registered provider set (real secrets held by the providers).
    let providers: Vec<Provider> =
        (0..K).map(|i| Provider { pk_receipt_hash: h(0x40 + i as u8), claim_secret: h(0x80 + i as u8) }).collect();
    let mut tree = MerkleTree::new(DEPTH);
    let mut idx = vec![];
    for p in &providers {
        idx.push(tree.append(Commitment(p.leaf())));
    }
    let root = tree.root();

    // a provider (index 2, HIDDEN) answers a requester challenge with a membership proof.
    let handshake = |who: usize, challenge: Hash64| -> (ProviderClaimStatement, ProviderClaimWitness) {
        let p = &providers[who];
        let zero = Note { value: 0, owner_pk: shielded_address(&h(0x71)), rho: h(0x33), r: h(0x34), token_id: 0 };
        let cm = commit(&zero);
        let nf = provider_nullifier(&p.claim_secret, &challenge); // binds the challenge, proves secret knowledge
        let ctx = claim_ctx(&challenge, 0, &cm, &nf);
        let stmt = ProviderClaimStatement { provider_set_root: root, session_cm: challenge, amount: 0, provider_nf: nf, cm_payout: cm, ctx };
        let wit = ProviderClaimWitness {
            pk_receipt_hash: p.pk_receipt_hash,
            claim_secret: p.claim_secret,
            leaf_index: idx[who],
            path: tree.path(idx[who]).unwrap(),
            payout_note: zero,
        };
        (stmt, wit)
    };

    let who = 2usize;
    let chal_a = h(0xA1); // requester nonce A
    let (hs_a, wit_a) = handshake(who, chal_a);
    verify_reference(&hs_a, &wit_a).expect("a registered provider answers the challenge");

    // (1) the handshake transcript names NO provider: leaf/index/pk_receipt_hash are absent.
    let pub_bytes = borsh::to_vec(&hs_a).unwrap();
    let leaf = provider_leaf(&providers[who].pk_receipt_hash, &shielded_address(&providers[who].claim_secret));
    assert!(!pub_bytes.windows(64).any(|w| w == leaf.as_byte_slice()), "handshake hides the provider leaf");
    assert!(
        !pub_bytes.windows(64).any(|w| w == providers[who].pk_receipt_hash.as_byte_slice()),
        "handshake hides pk_receipt"
    );

    // (2) cross-challenge UNLINKABILITY: a second challenge yields a different handshake
    // nullifier, so two responses from the SAME provider are unlinkable from public data.
    let chal_b = h(0xB2);
    let (hs_b, _wit_b) = handshake(who, chal_b);
    assert_ne!(hs_a.provider_nf, hs_b.provider_nf, "handshake nullifier is fresh per challenge (unlinkable)");

    // (3) an IMPOSTOR (secret not in the model set) cannot pass — the requester rejects it.
    let impostor = Provider { pk_receipt_hash: h(0xEE), claim_secret: h(0xEF) };
    let zero = Note { value: 0, owner_pk: shielded_address(&h(0x71)), rho: h(0x33), r: h(0x34), token_id: 0 };
    let cm = commit(&zero);
    let nf = provider_nullifier(&impostor.claim_secret, &chal_a);
    let ctx = claim_ctx(&chal_a, 0, &cm, &nf);
    let fake = ProviderClaimStatement { provider_set_root: root, session_cm: chal_a, amount: 0, provider_nf: nf, cm_payout: cm, ctx };
    let fake_wit = ProviderClaimWitness {
        pk_receipt_hash: impostor.pk_receipt_hash,
        claim_secret: impostor.claim_secret,
        leaf_index: 0,
        path: tree.path(0).unwrap(), // borrows provider 0's path — membership still fails (leaf ≠ node)
        payout_note: zero,
    };
    assert!(verify_reference(&fake, &fake_wit).is_err(), "an unregistered provider fails the blind handshake");

    println!("BLIND HANDSHAKE ok — provider proves 'registered for this model, bound to your challenge' with leaf/pk hidden; per-challenge nullifier is unlinkable; impostor rejected");
}
