//! Notes, commitments and nullifiers (ADR-0033 §3). Hash-based (keyed
//! BLAKE2b-512), so soundness rests only on hash security — PQ from genesis.

use crate::domains::{ADDR_DOMAIN, CM_DOMAIN, NF_DOMAIN, RHO_DOMAIN};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{Hash64, blake2b_512_keyed};

/// A note commitment `cm` (the public leaf inserted into the pool tree).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct Commitment(pub Hash64);

/// A spend nullifier `nf` (published on spend; the double-spend tag). Reveals
/// nothing about *which* commitment it spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct Nullifier(pub Hash64);

/// A shielded note (ADR-0033 §3.1). `value` is sompi (the UTXO-lane unit) so the
/// pool conserves supply exactly across the shield/unshield boundary (I-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Note {
    pub value: u64,
    /// Recipient shielded address `a_pk = H("addr", sk)`.
    pub owner_pk: Hash64,
    /// Nullifier seed (bound to the consuming nullifiers on output, §3.3).
    pub rho: Hash64,
    /// Commitment trapdoor (randomness).
    pub r: Hash64,
    /// Token id; `0` = MSK.
    pub token_id: u32,
}

impl Note {
    pub fn commitment(&self) -> Commitment {
        commit(self)
    }
}

/// `cm = H_k("cm", value ‖ a_pk ‖ rho ‖ r ‖ token_id)`.
pub fn commit(n: &Note) -> Commitment {
    let mut b = Vec::with_capacity(8 + 64 + 64 + 64 + 4);
    b.extend_from_slice(&n.value.to_le_bytes());
    b.extend_from_slice(n.owner_pk.as_byte_slice());
    b.extend_from_slice(n.rho.as_byte_slice());
    b.extend_from_slice(n.r.as_byte_slice());
    b.extend_from_slice(&n.token_id.to_le_bytes());
    Commitment(blake2b_512_keyed(CM_DOMAIN, &b))
}

/// `a_pk = H_k("addr", sk)` — the shielded address / spend authority commitment.
pub fn shielded_address(owner_sk: &Hash64) -> Hash64 {
    blake2b_512_keyed(ADDR_DOMAIN, owner_sk.as_byte_slice())
}

/// `nf = H_k("nf", sk ‖ rho)`. Deterministic in `(sk, rho)` so a note spends to
/// exactly one nullifier (double-spend prevention).
pub fn nullifier(owner_sk: &Hash64, rho: &Hash64) -> Nullifier {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(owner_sk.as_byte_slice());
    b.extend_from_slice(rho.as_byte_slice());
    Nullifier(blake2b_512_keyed(NF_DOMAIN, &b))
}

/// Output-note `rho'_j = H_k("rho", nf_old_1 ‖ nf_old_2 ‖ j)` (§3.3). Binding the
/// output rho to the *input* nullifiers gives global rho uniqueness from
/// nullifier uniqueness — the Faerie-Gold defence.
pub fn derive_output_rho(nf_old_1: &Nullifier, nf_old_2: &Nullifier, j: u8) -> Hash64 {
    let mut b = Vec::with_capacity(129);
    b.extend_from_slice(nf_old_1.0.as_byte_slice());
    b.extend_from_slice(nf_old_2.0.as_byte_slice());
    b.push(j);
    blake2b_512_keyed(RHO_DOMAIN, &b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    #[test]
    fn commitment_is_deterministic_and_field_sensitive() {
        let n = Note { value: 100, owner_pk: h(1), rho: h(2), r: h(3), token_id: 0 };
        assert_eq!(commit(&n), n.commitment());
        assert_eq!(commit(&n), commit(&n));
        // every field moves the commitment
        for m in [
            Note { value: 101, ..n },
            Note { owner_pk: h(9), ..n },
            Note { rho: h(9), ..n },
            Note { r: h(9), ..n },
            Note { token_id: 1, ..n },
        ] {
            assert_ne!(commit(&n), commit(&m));
        }
    }

    #[test]
    fn nullifier_binds_sk_and_rho() {
        let (sk, rho) = (h(7), h(8));
        assert_eq!(nullifier(&sk, &rho), nullifier(&sk, &rho));
        assert_ne!(nullifier(&sk, &rho), nullifier(&h(70), &rho));
        assert_ne!(nullifier(&sk, &rho), nullifier(&sk, &h(80)));
    }

    #[test]
    fn output_rho_is_faerie_gold_bound() {
        let (nf1, nf2) = (Nullifier(h(1)), Nullifier(h(2)));
        // distinct output indices give distinct rho
        assert_ne!(derive_output_rho(&nf1, &nf2, 0), derive_output_rho(&nf1, &nf2, 1));
        // distinct consumed nullifiers give distinct rho (uniqueness inheritance)
        assert_ne!(derive_output_rho(&nf1, &nf2, 0), derive_output_rho(&Nullifier(h(3)), &nf2, 0));
    }
}
