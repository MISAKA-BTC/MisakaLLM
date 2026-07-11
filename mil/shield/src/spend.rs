//! The value-pool JoinSplit statement (ADR-0033 §4.1, 2-in/2-out) — the L2
//! payment shield. A spend consumes up to two notes and creates two, proving
//! Merkle membership + nullifier correctness + value conservation **without
//! revealing which** notes are consumed. `shield` (`v_pub_in>0`), `transfer`
//! (both 0) and `unshield` (`v_pub_out>0`) are one parameterised statement so
//! the anonymity set is never split.

use crate::merkle::{MerklePath, verify_merkle_path};
use crate::note::{Commitment, Note, Nullifier, commit, derive_output_rho, nullifier, shielded_address};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash64;

/// Public inputs (what the contract/precompile sees and enforces against pool
/// state). Reveals nothing about which notes are consumed.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SpendStatement {
    /// A historical pool root the membership is proven against.
    pub anchor: Hash64,
    /// Nullifiers of the consumed notes (dummy inputs carry random-looking nf).
    pub nf_old: [Nullifier; 2],
    /// New note commitments inserted into the pool.
    pub cm_new: [Commitment; 2],
    /// Public in / out amounts (shield / unshield; both 0 for a private transfer).
    pub v_pub_in: u64,
    pub v_pub_out: u64,
    /// Token id of the whole statement (all notes must match).
    pub token_id: u32,
    /// Context binding (chain/pool/to/fee/…) recomputed by the contract (§4.2).
    pub ctx: Hash64,
}

/// Private witness (in the clear for the reference system; inside the STARK for
/// the zero-knowledge system).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SpendWitness {
    pub notes_in: [Note; 2],
    pub sk_in: [Hash64; 2],
    pub paths_in: [MerklePath; 2],
    /// `false` = a dummy input (value must be 0, membership skipped).
    pub enable_in: [bool; 2],
    pub notes_out: [Note; 2],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpendError {
    #[error("input {0}: Merkle membership under the anchor failed")]
    Membership(usize),
    #[error("input {0}: owner_pk is not H(sk) (spend authority)")]
    SpendAuthority(usize),
    #[error("input {0}: declared nullifier != H(sk ‖ rho)")]
    Nullifier(usize),
    #[error("input {0}: dummy input must have value 0")]
    DummyNonZero(usize),
    #[error("output {0}: rho is not Faerie-Gold-bound to the input nullifiers")]
    OutputRho(usize),
    #[error("output {0}: commitment does not open to the declared note")]
    OutputCommitment(usize),
    #[error("value is not conserved (Σ in + v_pub_in != Σ out + v_pub_out)")]
    ValueConservation,
    #[error("value overflow")]
    Overflow,
    #[error("token id mismatch (all notes must share the statement token id)")]
    TokenMismatch,
    #[error("both real inputs carry the same nullifier (same note double-counted)")]
    DuplicateNullifier,
}

/// Verify the JoinSplit relation transparently (reference proof system). Sound:
/// no false statement passes. The zero-knowledge system proves *exactly* this.
pub fn verify_reference(stmt: &SpendStatement, wit: &SpendWitness) -> Result<(), SpendError> {
    let mut sum_in: u128 = 0;
    for i in 0..2 {
        let n = &wit.notes_in[i];
        if n.token_id != stmt.token_id {
            return Err(SpendError::TokenMismatch);
        }
        if wit.enable_in[i] {
            // 1. membership of the consumed commitment under the anchor
            if !verify_merkle_path(&stmt.anchor, &commit(n).0, &wit.paths_in[i]) {
                return Err(SpendError::Membership(i));
            }
            // 2. spend authority: owner_pk == H(sk)
            if n.owner_pk != shielded_address(&wit.sk_in[i]) {
                return Err(SpendError::SpendAuthority(i));
            }
            // 3. declared nullifier is the correct one for (sk, rho)
            if stmt.nf_old[i] != nullifier(&wit.sk_in[i], &n.rho) {
                return Err(SpendError::Nullifier(i));
            }
            sum_in = sum_in.checked_add(n.value as u128).ok_or(SpendError::Overflow)?;
        } else {
            // dummy input: no membership, value must be 0
            if n.value != 0 {
                return Err(SpendError::DummyNonZero(i));
            }
        }
    }

    // (audit C-03, defense in depth) The same real note in BOTH input lanes shares one
    // nullifier and would be counted twice in `sum_in`. The contract also rejects
    // `nf0 == nf1`, but the relation must forbid it too so soundness does not rest on a
    // caller obligation. (Dummy lanes carry value 0, so a dummy nf colliding with a real
    // one cannot inflate; only two ENABLED lanes double-count.)
    if wit.enable_in[0] && wit.enable_in[1] && stmt.nf_old[0] == stmt.nf_old[1] {
        return Err(SpendError::DuplicateNullifier);
    }

    let mut sum_out: u128 = 0;
    for j in 0..2usize {
        let o = &wit.notes_out[j];
        if o.token_id != stmt.token_id {
            return Err(SpendError::TokenMismatch);
        }
        // 4. Faerie-Gold: output rho bound to the consumed nullifiers
        if o.rho != derive_output_rho(&stmt.nf_old[0], &stmt.nf_old[1], j as u8) {
            return Err(SpendError::OutputRho(j));
        }
        // 5. the published commitment opens to this output note
        if stmt.cm_new[j] != commit(o) {
            return Err(SpendError::OutputCommitment(j));
        }
        sum_out = sum_out.checked_add(o.value as u128).ok_or(SpendError::Overflow)?;
    }

    // 6. value conservation
    let lhs = sum_in.checked_add(stmt.v_pub_in as u128).ok_or(SpendError::Overflow)?;
    let rhs = sum_out.checked_add(stmt.v_pub_out as u128).ok_or(SpendError::Overflow)?;
    if lhs != rhs {
        return Err(SpendError::ValueConservation);
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

    // Build a valid transfer: one real 100-note in, two out (60 + 40).
    fn valid() -> (SpendStatement, SpendWitness, MerkleTree) {
        let sk = h(0x51);
        let a_pk = shielded_address(&sk);
        let note_in = Note { value: 100, owner_pk: a_pk, rho: h(0x11), r: h(0x22), token_id: 0 };
        let mut tree = MerkleTree::new(16);
        let idx = tree.append(commit(&note_in));
        // second input is a dummy (value 0)
        let dummy = Note { value: 0, owner_pk: h(0), rho: h(0), r: h(0), token_id: 0 };
        let nf0 = nullifier(&sk, &note_in.rho);
        let nf1 = nullifier(&h(0xDE), &dummy.rho); // dummy nf (any value; not checked for membership)
        let anchor = tree.root();

        let rho_out0 = derive_output_rho(&nf0, &nf1, 0);
        let rho_out1 = derive_output_rho(&nf0, &nf1, 1);
        let out0 = Note { value: 60, owner_pk: shielded_address(&h(0x71)), rho: rho_out0, r: h(0x31), token_id: 0 };
        let out1 = Note { value: 40, owner_pk: shielded_address(&h(0x72)), rho: rho_out1, r: h(0x32), token_id: 0 };

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
        (stmt, wit, tree)
    }

    #[test]
    fn valid_transfer_verifies() {
        let (stmt, wit, _t) = valid();
        verify_reference(&stmt, &wit).expect("valid JoinSplit must verify");
    }

    #[test]
    fn value_inflation_is_rejected() {
        let (stmt, mut wit, _t) = valid();
        wit.notes_out[0].value = 61; // 61+40 > 100
        // recompute the affected commitment so only conservation is wrong
        let mut s = stmt.clone();
        s.cm_new[0] = commit(&wit.notes_out[0]);
        assert_eq!(verify_reference(&s, &wit), Err(SpendError::ValueConservation));
    }

    #[test]
    fn forged_membership_is_rejected() {
        let (mut stmt, wit, _t) = valid();
        stmt.anchor = h(0xFF); // note is not under this anchor
        assert_eq!(verify_reference(&stmt, &wit), Err(SpendError::Membership(0)));
    }

    #[test]
    fn wrong_nullifier_is_rejected() {
        let (mut stmt, wit, _t) = valid();
        stmt.nf_old[0] = Nullifier(h(0xAB));
        // output rhos depend on nf_old, so fix them too — isolate the nf check
        let mut w = wit.clone();
        let r0 = derive_output_rho(&stmt.nf_old[0], &stmt.nf_old[1], 0);
        let r1 = derive_output_rho(&stmt.nf_old[0], &stmt.nf_old[1], 1);
        w.notes_out[0].rho = r0;
        w.notes_out[1].rho = r1;
        let mut s = stmt.clone();
        s.cm_new = [commit(&w.notes_out[0]), commit(&w.notes_out[1])];
        assert_eq!(verify_reference(&s, &w), Err(SpendError::Nullifier(0)));
    }

    #[test]
    fn faerie_gold_output_rho_is_enforced() {
        let (stmt, mut wit, _t) = valid();
        wit.notes_out[0].rho = h(0x99); // not the bound rho
        let mut s = stmt.clone();
        s.cm_new[0] = commit(&wit.notes_out[0]);
        assert_eq!(verify_reference(&s, &wit), Err(SpendError::OutputRho(0)));
    }

    #[test]
    fn shield_and_unshield_balance() {
        // shield: v_pub_in = 100, one output of 100, no real inputs
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
        verify_reference(&stmt, &wit).expect("shield must balance");
    }
}
