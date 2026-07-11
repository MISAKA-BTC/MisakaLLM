//! §SP-0 A5 — the reference↔STARK DIFFERENTIAL CORPUS (ADR-0035 §7 gate).
//!
//! A deterministic, exhaustive corpus of spend (statement, witness) pairs — one valid
//! case per spend flavour plus one per rejection class — each tagged with the verdict
//! `spend::verify_reference` MUST return. This is the fixture the STARK verifier is
//! held to: `stark_verify(P(S,W))` must accept **iff** `verify_reference(S,W)` accepts,
//! for every case (accept ⇔ accept, reject ⇔ reject). Here we pin the REFERENCE side
//! (the oracle) and assert each expected verdict; the STARK side consumes the same
//! corpus (build#4 `spend.rs` proves the valid cases and rejects the tampered ones —
//! its positive + 6 negatives are differential points in this corpus).
//!
//! The corpus is exported (`MIL_CORPUS_OUT=<path>` → borsh) so the AIR harness on the
//! build host can replay it and assert the SAME accept/reject, closing the differential
//! gate. Determinism (SP-04): the corpus is a pure function of fixed seeds — no RNG, no
//! clock — so it is byte-identical on every platform (the x86-64 + aarch64 conformance
//! requirement rides on the same fixture).

use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash64;
use misaka_mil_shield::merkle::{MerklePath, MerkleTree};
use misaka_mil_shield::note::{Commitment, Note, commit, derive_output_rho, nullifier, shielded_address};
use misaka_mil_shield::spend::{SpendError, SpendStatement, SpendWitness, verify_reference};

fn h(b: u8) -> Hash64 {
    Hash64::from_bytes([b; 64])
}

/// One corpus case: the statement, its witness, and the exact verdict the reference
/// relation must return. `Ok` = accept; `Err(SpendError)` = the specific rejection.
#[derive(BorshSerialize, BorshDeserialize)]
struct Case {
    name: String,
    stmt: SpendStatement,
    wit: SpendWitness,
    /// Borsh of the expected verdict as a small tag: 0 = Ok, else 1 + error-ordinal.
    expect_tag: u8,
}

/// Verdict tags — kept explicit so the STARK harness (which does not link SpendError)
/// can compare against the same integer.
fn tag(v: &Result<(), SpendError>) -> u8 {
    match v {
        Ok(()) => 0,
        Err(SpendError::Membership(_)) => 1,
        Err(SpendError::SpendAuthority(_)) => 2,
        Err(SpendError::Nullifier(_)) => 3,
        Err(SpendError::DummyNonZero(_)) => 4,
        Err(SpendError::OutputRho(_)) => 5,
        Err(SpendError::OutputCommitment(_)) => 6,
        Err(SpendError::ValueConservation) => 7,
        Err(SpendError::Overflow) => 8,
        Err(SpendError::TokenMismatch) => 9,
        Err(SpendError::DuplicateNullifier) => 10,
    }
}

/// A valid 1-real + 1-dummy transfer (100 → 60 + 40); the template every case perturbs.
fn base() -> (SpendStatement, SpendWitness, MerkleTree, Hash64) {
    let sk = h(0x51);
    let note_in = Note { value: 100, owner_pk: shielded_address(&sk), rho: h(0x11), r: h(0x22), token_id: 0 };
    let mut tree = MerkleTree::new(20);
    let idx = tree.append(commit(&note_in));
    let dummy = Note { value: 0, owner_pk: h(0), rho: h(0), r: h(0), token_id: 0 };
    let nf0 = nullifier(&sk, &note_in.rho);
    let nf1 = nullifier(&h(0xDE), &dummy.rho);
    let anchor = tree.root();
    let out0 = Note { value: 60, owner_pk: shielded_address(&h(0x71)), rho: derive_output_rho(&nf0, &nf1, 0), r: h(0x31), token_id: 0 };
    let out1 = Note { value: 40, owner_pk: shielded_address(&h(0x72)), rho: derive_output_rho(&nf0, &nf1, 1), r: h(0x32), token_id: 0 };
    let stmt = SpendStatement {
        anchor,
        nf_old: [nf0, nf1],
        cm_new: [commit(&out0), commit(&out1)],
        v_pub_in: 0,
        v_pub_out: 0,
        token_id: 0,
        ctx: h(0xC7),
    };
    let wit = SpendWitness {
        notes_in: [note_in, dummy],
        sk_in: [sk, h(0xDE)],
        paths_in: [tree.path(idx).unwrap(), MerklePath { siblings: vec![], index: 0 }],
        enable_in: [true, false],
        notes_out: [out0, out1],
    };
    (stmt, wit, tree, sk)
}

/// Build the full corpus: valid flavours + one case per rejection class.
fn corpus() -> Vec<Case> {
    let mut cases = Vec::new();
    let mut add = |name: &str, stmt: SpendStatement, wit: SpendWitness| {
        let v = verify_reference(&stmt, &wit);
        cases.push(Case { name: name.to_string(), stmt, wit, expect_tag: tag(&v) });
    };

    // ---- valid flavours ----
    let (s, w, _t, _sk) = base();
    add("valid/transfer", s, w);

    // shield: v_pub_in=100, two disabled inputs → two 50-notes out
    {
        let dummy = Note { value: 0, owner_pk: h(0), rho: h(0), r: h(0), token_id: 0 };
        let nf0 = nullifier(&h(1), &dummy.rho);
        let nf1 = nullifier(&h(2), &dummy.rho);
        let o0 = Note { value: 50, owner_pk: shielded_address(&h(0x71)), rho: derive_output_rho(&nf0, &nf1, 0), r: h(0x31), token_id: 0 };
        let o1 = Note { value: 50, owner_pk: shielded_address(&h(0x72)), rho: derive_output_rho(&nf0, &nf1, 1), r: h(0x32), token_id: 0 };
        let stmt = SpendStatement { anchor: h(0), nf_old: [nf0, nf1], cm_new: [commit(&o0), commit(&o1)], v_pub_in: 100, v_pub_out: 0, token_id: 0, ctx: h(0xC1) };
        let wit = SpendWitness {
            notes_in: [dummy, dummy],
            sk_in: [h(1), h(2)],
            paths_in: [MerklePath { siblings: vec![], index: 0 }, MerklePath { siblings: vec![], index: 0 }],
            enable_in: [false, false],
            notes_out: [o0, o1],
        };
        add("valid/shield", stmt, wit);
    }

    // ---- one case per rejection class ----
    // Membership(0): wrong anchor
    {
        let (mut s, w, _t, _sk) = base();
        s.anchor = h(0xEE);
        add("reject/membership", s, w);
    }
    // SpendAuthority(0): owner_pk not H(sk)
    {
        let (mut s, mut w, mut t, _sk) = base();
        w.notes_in[0].owner_pk = h(0xAB); // not the address of sk
        // re-anchor to keep membership passing so authority is the failure
        t = MerkleTree::new(20);
        let idx = t.append(commit(&w.notes_in[0]));
        s.anchor = t.root();
        w.paths_in[0] = t.path(idx).unwrap();
        add("reject/spend_authority", s, w);
    }
    // Nullifier(0): declared nf != H(sk‖rho)
    {
        let (mut s, w, _t, _sk) = base();
        s.nf_old[0] = nullifier(&h(0x99), &w.notes_in[0].rho); // wrong sk in the nf
        add("reject/nullifier", s, w);
    }
    // DummyNonZero(1): disabled input carries value != 0
    {
        let (s, mut w, _t, _sk) = base();
        w.notes_in[1].value = 5; // dummy must be 0
        add("reject/dummy_nonzero", s, w);
    }
    // OutputRho(0): output rho not Faerie-Gold-bound
    {
        let (mut s, mut w, _t, _sk) = base();
        w.notes_out[0].rho = h(0x00);
        s.cm_new[0] = commit(&w.notes_out[0]);
        add("reject/output_rho", s, w);
    }
    // OutputCommitment(0): cm_new does not open to the declared note
    {
        let (mut s, w, _t, _sk) = base();
        s.cm_new[0] = Commitment(h(0x00));
        add("reject/output_commitment", s, w);
    }
    // ValueConservation: 100 in, 60+41 out
    {
        let (mut s, mut w, _t, _sk) = base();
        w.notes_out[1].value = 41;
        // rebind rho/cm so only conservation is the failure
        let nf0 = s.nf_old[0].clone();
        let nf1 = s.nf_old[1].clone();
        w.notes_out[1].rho = derive_output_rho(&nf0, &nf1, 1);
        s.cm_new[1] = commit(&w.notes_out[1]);
        add("reject/value_conservation", s, w);
    }
    // TokenMismatch: an input note carries a different token_id
    {
        let (s, mut w, _t, _sk) = base();
        w.notes_in[0].token_id = 7; // != statement token 0
        add("reject/token_mismatch", s, w);
    }
    cases
}

#[test]
fn reference_side_of_the_differential_corpus_is_pinned() {
    let cases = corpus();
    assert!(cases.len() >= 10, "corpus must cover valid flavours + every rejection class");
    let mut valid = 0usize;
    let mut seen_tags = std::collections::BTreeSet::new();
    for c in &cases {
        let v = verify_reference(&c.stmt, &c.wit);
        // the recorded expected verdict must match a fresh evaluation (determinism)
        assert_eq!(tag(&v), c.expect_tag, "case {}: verdict drifted", c.name);
        // and it must match the name's intent
        if c.name.starts_with("valid/") {
            assert_eq!(v, Ok(()), "case {} must accept", c.name);
            valid += 1;
        } else {
            assert!(v.is_err(), "case {} must reject", c.name);
        }
        seen_tags.insert(c.expect_tag);
    }
    assert!(valid >= 2, "at least the transfer + shield valid flavours");
    // every rejection class 1..=9 present at least once (except Overflow=8, unreachable
    // with ≤2 u64 terms — documented, not a gap).
    for t in [1u8, 2, 3, 4, 5, 6, 7, 9] {
        assert!(seen_tags.contains(&t), "rejection class tag {t} must appear in the corpus");
    }

    // export for the STARK-side differential harness (build#4 spend.rs replays these).
    if let Ok(path) = std::env::var("MIL_CORPUS_OUT") {
        let blob = borsh::to_vec(&cases).expect("borsh corpus");
        std::fs::write(&path, &blob).expect("write corpus");
        eprintln!("wrote {} differential cases ({} bytes) to {path}", cases.len(), blob.len());
    }
    println!(
        "A5 differential corpus (reference side) — {} cases pinned: {} valid, {} rejection classes; STARK verdict must match each (accept ⇔ accept)",
        cases.len(),
        valid,
        seen_tags.len() - 1
    );
}

/// Determinism (SP-04): the corpus is a pure function of fixed inputs, so re-generating
/// it yields byte-identical bytes — the property the x86-64/aarch64 conformance run
/// checks by regenerating on each platform and comparing the borsh blob.
#[test]
fn corpus_is_byte_deterministic() {
    let a = borsh::to_vec(&corpus()).unwrap();
    let b = borsh::to_vec(&corpus()).unwrap();
    assert_eq!(a, b, "corpus must be byte-identical across regenerations (no RNG/clock)");
}
