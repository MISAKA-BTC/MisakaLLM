//! End-to-end PRIVATE TRANSFER over the full pipeline (ADR-0033 / ADR-0036):
//!
//!   shield (public → pool) → private transfer Alice→Bob (which-note hidden) →
//!   proof envelope → DA CHUNKING (32 KiB consensus payloads) → gossip-order
//!   reassembly → envelope verification → pool-state application (root ring +
//!   SEQUENTIAL nullifier check-then-insert + commitment insertion) → Bob recovers
//!   his note and RE-SPENDS it against the new anchor (Bob→Carol).
//!
//! The proof arm here is the transparent REFERENCE system (witness in the clear —
//! the mechanics oracle); the zero-knowledge STARK arm proves EXACTLY the same
//! relation (`docs/bench/plonky3-shield-air/spend.rs`, build#4) and its recursive
//! compression to DA-carriable size is measured by
//! `recursive_spend.rs` (build#5). `outer_proof_da_roundtrip` below runs the REAL
//! recursion output bytes through the same DA path when `MIL_OUTER_PROOF` points at
//! the dumped artifact.
//!
//! The pool application deliberately mirrors `contracts/mil/src/ShieldedPool.sol`
//! (`_spend`): anchor must be in a 128-deep root ring, nullifiers are applied
//! check-then-insert SEQUENTIALLY (the documented caller obligation in
//! `mil/shield/src/proof.rs` — neither the relation nor the circuit enforces
//! `nf_old[0] != nf_old[1]`, so batch application would double-count; the
//! `same_note_in_both_slots_is_stopped_by_sequential_application` test pins this).

use kaspa_hashes::Hash64;
use misaka_mil_shield::merkle::{MerklePath, MerkleTree};
use misaka_mil_shield::note::{Note, Nullifier, commit, derive_output_rho, nullifier, shielded_address};
use misaka_mil_shield::proof::{
    CIRCUIT_SPEND, PROOF_SYSTEM_REFERENCE, PROOF_SYSTEM_STARK, ShieldProof, ShieldVerifyError, VerifiedStatement, verify_shield_proof,
};
use misaka_mil_shield::spend::{SpendStatement, SpendWitness, verify_reference};
use misaka_mil_shield_da::{chunk_proof, reassemble, validate_chunk, validate_descriptor};
use std::collections::BTreeSet;

const DEPTH: u32 = 20; // production pool depth (ADR-0033 §4.1)
const ROOT_RING: usize = 128; // ShieldedPool.sol:25

fn h(b: u8) -> Hash64 {
    Hash64::from_bytes([b; 64])
}
fn vk() -> Hash64 {
    h(0xB0) // the governance-pinned reference vk hash used across proof.rs tests
}

/// The on-chain pool state machine, mirroring ShieldedPool.sol `_spend`.
struct Pool {
    tree: MerkleTree,
    roots: Vec<Hash64>, // ring, newest last
    spent: BTreeSet<Hash64>,
}
#[derive(Debug, PartialEq, Eq)]
enum PoolError {
    UnknownAnchor,
    DoubleSpend(usize),
}
impl Pool {
    fn new() -> Self {
        let tree = MerkleTree::new(DEPTH);
        let root0 = tree.root();
        Self { tree, roots: vec![root0], spent: BTreeSet::new() }
    }
    fn root_known(&self, anchor: &Hash64) -> bool {
        self.roots.iter().rev().take(ROOT_RING).any(|r| r == anchor)
    }
    /// ShieldedPool.sol:156-168 — anchor ring check, then SEQUENTIAL
    /// check-then-insert per nullifier (this order is the documented caller
    /// obligation: it is what rejects nf_old[0] == nf_old[1]).
    fn apply(&mut self, stmt: &SpendStatement) -> Result<(), PoolError> {
        if !self.root_known(&stmt.anchor) {
            return Err(PoolError::UnknownAnchor);
        }
        for (i, nf) in stmt.nf_old.iter().enumerate() {
            if !self.spent.insert(nf.0) {
                return Err(PoolError::DoubleSpend(i));
            }
        }
        self.tree.append(stmt.cm_new[0]);
        self.tree.append(stmt.cm_new[1]);
        self.roots.push(self.tree.root());
        Ok(())
    }
}

/// Encode a reference-arm proof envelope for (stmt, wit).
fn envelope(stmt: &SpendStatement, wit: &SpendWitness) -> Vec<u8> {
    ShieldProof {
        proof_system_id: PROOF_SYSTEM_REFERENCE,
        circuit_version: CIRCUIT_SPEND,
        verifier_key_hash: vk(),
        public_inputs: borsh::to_vec(stmt).unwrap(),
        proof: borsh::to_vec(wit).unwrap(),
    }
    .encode()
}

/// Transport bytes through the DA layer exactly as consensus would see them:
/// chunk to ≤32 KiB payloads, validate each on arrival, reassemble out of order.
fn da_roundtrip(bytes: &[u8]) -> Vec<u8> {
    let (desc, mut chunks) = chunk_proof(bytes).expect("chunk");
    validate_descriptor(&desc).expect("descriptor");
    chunks.reverse(); // gossip arrival order is arbitrary
    for c in &chunks {
        validate_chunk(&desc, c).expect("chunk arrival validation");
    }
    reassemble(&desc, &chunks).expect("reassemble")
}

/// A dummy (disabled) input slot: value 0, arbitrary fields, random-looking nf.
fn dummy_input(nf_seed: u8) -> (Note, Hash64, MerklePath, Nullifier) {
    let dummy = Note { value: 0, owner_pk: h(0), rho: h(0), r: h(0), token_id: 0 };
    let sk = h(nf_seed);
    let nf = nullifier(&sk, &dummy.rho);
    (dummy, sk, MerklePath { siblings: vec![], index: 0 }, nf)
}

/// Full private transfer: verify the envelope after DA transport, then apply.
fn submit(pool: &mut Pool, stmt: &SpendStatement, wit: &SpendWitness) -> Result<SpendStatement, PoolError> {
    let bytes = envelope(stmt, wit);
    let arrived = da_roundtrip(&bytes);
    assert_eq!(arrived, bytes, "DA transport must be byte-faithful");
    let verified = verify_shield_proof(&arrived, &vk()).expect("envelope verify");
    let VerifiedStatement::Spend(vstmt) = verified else { panic!("spend statement expected") };
    pool.apply(&vstmt)?;
    Ok(vstmt)
}

#[test]
fn full_private_transfer_pipeline() {
    let mut pool = Pool::new();

    // ---- keys: three wallets ----
    let (sk_alice, sk_bob, sk_carol) = (h(0x51), h(0x52), h(0x53));

    // ---- 1. SHIELD: Alice moves 100 public MSK into the pool ----
    let (d0, dsk0, dp0, dnf0) = dummy_input(0xD1);
    let (d1, dsk1, dp1, dnf1) = dummy_input(0xD2);
    let note_a =
        Note { value: 100, owner_pk: shielded_address(&sk_alice), rho: derive_output_rho(&dnf0, &dnf1, 0), r: h(0x21), token_id: 0 };
    let zero_out = Note { value: 0, owner_pk: h(0x0F), rho: derive_output_rho(&dnf0, &dnf1, 1), r: h(0x22), token_id: 0 };
    let shield_stmt = SpendStatement {
        anchor: pool.tree.root(),
        nf_old: [dnf0, dnf1],
        cm_new: [commit(&note_a), commit(&zero_out)],
        v_pub_in: 100,
        v_pub_out: 0,
        token_id: 0,
        ctx: h(0xC1),
    };
    let shield_wit = SpendWitness {
        notes_in: [d0, d1],
        sk_in: [dsk0, dsk1],
        paths_in: [dp0.clone(), dp1.clone()],
        enable_in: [false, false],
        notes_out: [note_a, zero_out],
    };
    verify_reference(&shield_stmt, &shield_wit).expect("shield relation");
    submit(&mut pool, &shield_stmt, &shield_wit).expect("shield applied");
    let idx_a = 0u64; // note_a is leaf 0

    // ---- 2. PRIVATE TRANSFER: Alice → Bob 60, change 40 (v_pub 0/0) ----
    let (dummy, _dsk, dpath, _) = dummy_input(0xD3);
    let nf_a = nullifier(&sk_alice, &note_a.rho);
    let dummy_nf = nullifier(&h(0xD3), &dummy.rho);
    let anchor = pool.tree.root();
    let note_bob =
        Note { value: 60, owner_pk: shielded_address(&sk_bob), rho: derive_output_rho(&nf_a, &dummy_nf, 0), r: h(0x31), token_id: 0 };
    let note_change = Note {
        value: 40,
        owner_pk: shielded_address(&sk_alice),
        rho: derive_output_rho(&nf_a, &dummy_nf, 1),
        r: h(0x32),
        token_id: 0,
    };
    let transfer_stmt = SpendStatement {
        anchor,
        nf_old: [nf_a, dummy_nf],
        cm_new: [commit(&note_bob), commit(&note_change)],
        v_pub_in: 0,
        v_pub_out: 0,
        token_id: 0,
        ctx: h(0xC2),
    };
    let transfer_wit = SpendWitness {
        notes_in: [note_a, dummy],
        sk_in: [sk_alice, h(0xD3)],
        paths_in: [pool.tree.path(idx_a).unwrap(), dpath.clone()],
        enable_in: [true, false],
        notes_out: [note_bob, note_change],
    };
    verify_reference(&transfer_stmt, &transfer_wit).expect("transfer relation");
    let vstmt = submit(&mut pool, &transfer_stmt, &transfer_wit).expect("transfer applied");
    // the statement reveals NOTHING about which note was consumed:
    assert!(!borsh::to_vec(&vstmt).unwrap().windows(64).any(|w| w == commit(&note_a).0.as_byte_slice()));

    // ---- 3. DOUBLE-SPEND of note_a is rejected (nullifier set) ----
    let pool2_err = pool.apply(&transfer_stmt);
    assert_eq!(pool2_err, Err(PoolError::DoubleSpend(0)), "same nullifier again must fail");

    // ---- 4. Bob RECOVERS his note and RE-SPENDS it: Bob → Carol 35, change 25 ----
    assert_eq!(note_bob.owner_pk, shielded_address(&sk_bob), "Bob recognises his note");
    let idx_bob = 2u64; // leaves: 0 note_a, 1 zero_out, 2 note_bob, 3 note_change
    assert_eq!(pool.tree.path(idx_bob).map(|p| p.index), Some(2));
    let (dummy2, _, dpath2, _) = dummy_input(0xD4);
    let nf_bob = nullifier(&sk_bob, &note_bob.rho);
    let dummy_nf2 = nullifier(&h(0xD4), &dummy2.rho);
    let anchor2 = pool.tree.root(); // the NEW anchor after the transfer
    let note_carol = Note {
        value: 35,
        owner_pk: shielded_address(&sk_carol),
        rho: derive_output_rho(&nf_bob, &dummy_nf2, 0),
        r: h(0x41),
        token_id: 0,
    };
    let note_change2 = Note {
        value: 25,
        owner_pk: shielded_address(&sk_bob),
        rho: derive_output_rho(&nf_bob, &dummy_nf2, 1),
        r: h(0x42),
        token_id: 0,
    };
    let respend_stmt = SpendStatement {
        anchor: anchor2,
        nf_old: [nf_bob, dummy_nf2],
        cm_new: [commit(&note_carol), commit(&note_change2)],
        v_pub_in: 0,
        v_pub_out: 0,
        token_id: 0,
        ctx: h(0xC3),
    };
    let respend_wit = SpendWitness {
        notes_in: [note_bob, dummy2],
        sk_in: [sk_bob, h(0xD4)],
        paths_in: [pool.tree.path(idx_bob).unwrap(), dpath2],
        enable_in: [true, false],
        notes_out: [note_carol, note_change2],
    };
    verify_reference(&respend_stmt, &respend_wit).expect("re-spend relation");
    submit(&mut pool, &respend_stmt, &respend_wit).expect("Bob's re-spend applied");

    // ---- 5. UNKNOWN ANCHOR is rejected ----
    let mut bad = respend_stmt.clone();
    bad.anchor = h(0xEE);
    assert_eq!(pool.apply(&bad), Err(PoolError::UnknownAnchor));

    println!(
        "E2E ok — shield 100 → Alice→Bob 60 (+40 change) → Bob→Carol 35 (+25 change), all via envelope + 32 KiB DA chunks, double-spend + unknown-anchor rejected"
    );
}

/// The adversarial-panel HIGH finding pinned as a regression test: the RELATION
/// accepts the same note in BOTH input slots (nf_old[0] == nf_old[1] — value counted
/// twice), and only the SEQUENTIAL pool application stops it. If this test ever
/// fails on the `verify_reference` line, the relation started enforcing
/// distinctness (fine — update the docs); if it fails on the `apply` line, the pool
/// lost its protection (CRITICAL).
#[test]
fn same_note_in_both_slots_is_stopped_by_sequential_application() {
    let mut pool = Pool::new();
    let sk = h(0x61);
    let note = Note { value: 100, owner_pk: shielded_address(&sk), rho: h(0x11), r: h(0x12), token_id: 0 };
    let idx = pool.tree.append(commit(&note));
    pool.roots.push(pool.tree.root());
    let nf = nullifier(&sk, &note.rho);
    let out0 = Note { value: 150, owner_pk: h(0x0A), rho: derive_output_rho(&nf, &nf, 0), r: h(0x13), token_id: 0 };
    let out1 = Note { value: 50, owner_pk: h(0x0B), rho: derive_output_rho(&nf, &nf, 1), r: h(0x14), token_id: 0 };
    let stmt = SpendStatement {
        anchor: pool.tree.root(),
        nf_old: [nf, nf],
        cm_new: [commit(&out0), commit(&out1)],
        v_pub_in: 0,
        v_pub_out: 0,
        token_id: 0,
        ctx: h(0xC9),
    };
    let path = pool.tree.path(idx).unwrap();
    let wit = SpendWitness {
        notes_in: [note, note],
        sk_in: [sk, sk],
        paths_in: [path.clone(), path],
        enable_in: [true, true],
        notes_out: [out0, out1],
    };
    // (audit C-03) the relation now REJECTS two enabled inputs sharing a nullifier
    // (defense in depth), so the same-note double-count is caught at the relation itself…
    assert_eq!(
        verify_reference(&stmt, &wit),
        Err(misaka_mil_shield::spend::SpendError::DuplicateNullifier),
        "the relation forbids the same real note in both lanes"
    );
    // …and the pool's sequential application is the second layer that also stops it.
    assert_eq!(pool.apply(&stmt), Err(PoolError::DoubleSpend(1)));
}

/// DA-layer negatives on a real envelope: tampered and missing chunks must fail.
#[test]
fn da_transport_rejects_tampered_and_missing_chunks() {
    // a >32 KiB envelope so it actually splits: pad the witness notes' entropy by
    // using a full-size proof — the reference witness is small, so chunk a synthetic
    // blob of the measured build#5 outer-proof size instead (475,009 bytes).
    let blob: Vec<u8> = (0..475_009u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let (desc, mut chunks) = chunk_proof(&blob).unwrap();
    assert_eq!(chunks.len(), 15, "475 KB → 15 chunks at the 32 KiB Stage-B cap");
    // tampered chunk
    let mut evil = chunks[3].clone();
    evil.bytes[0] ^= 1;
    assert!(validate_chunk(&desc, &evil).is_err(), "tampered chunk must fail arrival validation");
    // missing chunk
    chunks.remove(7);
    assert!(reassemble(&desc, &chunks).is_err(), "missing chunk must fail reassembly");
}

/// When `MIL_OUTER_PROOF` points at the build#5 recursion artifact (the REAL outer
/// STARK proof bytes of the REAL spend), run the actual bytes through the DA path
/// and the STARK-arm envelope (fail-closed inert verification until F006/§SP-0).
#[test]
fn outer_proof_da_roundtrip() {
    let Ok(path) = std::env::var("MIL_OUTER_PROOF") else {
        eprintln!("MIL_OUTER_PROOF not set — skipping the real-artifact DA roundtrip");
        return;
    };
    let bytes = std::fs::read(&path).expect("read outer proof artifact");
    let (desc, mut chunks) = chunk_proof(&bytes).expect("chunk outer proof");
    validate_descriptor(&desc).expect("descriptor");
    chunks.reverse();
    for c in &chunks {
        validate_chunk(&desc, c).expect("arrival validation");
    }
    let back = reassemble(&desc, &chunks).expect("reassemble");
    assert_eq!(back, bytes, "outer proof survives DA transport byte-for-byte");

    // STARK-arm envelope round-trip: the outer proof rides `ShieldProof.proof`.
    let stmt_placeholder: Vec<u8> = vec![0u8; 4]; // the real statement bytes are pinned by the circuit publics
    let env = ShieldProof {
        proof_system_id: PROOF_SYSTEM_STARK,
        circuit_version: CIRCUIT_SPEND,
        verifier_key_hash: vk(),
        public_inputs: stmt_placeholder,
        proof: back,
    }
    .encode();
    let dec = ShieldProof::decode(&env).expect("decode");
    assert_eq!(dec.proof.len(), bytes.len());
    // fail-closed: the node rejects STARK proofs until §SP-0 activates the backend.
    assert_eq!(
        verify_shield_proof(&env, &vk()),
        Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK)),
        "STARK arm must stay fail-closed until F006 activation"
    );
    println!(
        "REAL outer proof: {} bytes → {} x 32 KiB chunks, DA roundtrip byte-faithful, envelope round-trips, inert arm fail-closed",
        bytes.len(),
        desc.total_chunks
    );
}
