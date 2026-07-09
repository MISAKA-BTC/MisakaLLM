//! Fixed-depth append-only Merkle tree over `Hash64` (ADR-0033 §4.1 membership).
//! The pool's anchor is [`MerkleTree::root`]; a spend proves a note commitment is
//! under a historical anchor via a [`MerklePath`] — in the clear here (reference
//! system), inside the STARK for the zero-knowledge system.

use crate::domains::{MERKLE_DOMAIN, MERKLE_EMPTY_DOMAIN};
use crate::note::Commitment;
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{Hash64, blake2b_512_keyed};

/// `H_k("merkle", left ‖ right)`.
pub fn hash_node(left: &Hash64, right: &Hash64) -> Hash64 {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(left.as_byte_slice());
    b.extend_from_slice(right.as_byte_slice());
    blake2b_512_keyed(MERKLE_DOMAIN, &b)
}

fn empty_leaf() -> Hash64 {
    blake2b_512_keyed(MERKLE_EMPTY_DOMAIN, b"leaf")
}

/// The empty-subtree root at each level `0..=depth` (level 0 = empty leaf).
fn empty_roots(depth: u32) -> Vec<Hash64> {
    let mut v = Vec::with_capacity(depth as usize + 1);
    v.push(empty_leaf());
    for level in 0..depth as usize {
        let e = v[level];
        v.push(hash_node(&e, &e));
    }
    v
}

/// A Merkle authentication path: the sibling at each level (leaf → root) and the
/// leaf's index (its bits select left/right at each level).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MerklePath {
    pub siblings: Vec<Hash64>,
    pub index: u64,
}

/// Recompute the root from a leaf + path and compare — the membership check the
/// on-chain pool (and the STARK circuit) performs.
pub fn verify_merkle_path(root: &Hash64, leaf: &Hash64, path: &MerklePath) -> bool {
    let mut cur = *leaf;
    let mut idx = path.index;
    for sib in &path.siblings {
        cur = if idx & 1 == 0 { hash_node(&cur, sib) } else { hash_node(sib, &cur) };
        idx >>= 1;
    }
    &cur == root
}

/// A fixed-depth append-only commitment tree. Holds up to `2^depth` leaves.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    depth: u32,
    empties: Vec<Hash64>,
    leaves: Vec<Hash64>,
}

impl MerkleTree {
    pub fn new(depth: u32) -> Self {
        assert!((1..=40).contains(&depth), "merkle depth out of range");
        Self { depth, empties: empty_roots(depth), leaves: Vec::new() }
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }
    pub fn len(&self) -> usize {
        self.leaves.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
    pub fn capacity(&self) -> u64 {
        1u64 << self.depth
    }

    /// Append a commitment; returns its leaf index. Panics if the tree is full.
    pub fn append(&mut self, cm: Commitment) -> u64 {
        assert!((self.leaves.len() as u64) < self.capacity(), "merkle tree full");
        let idx = self.leaves.len() as u64;
        self.leaves.push(cm.0);
        idx
    }

    /// The current anchor (root over the inserted leaves, empty-padded).
    pub fn root(&self) -> Hash64 {
        if self.leaves.is_empty() {
            return self.empties[self.depth as usize];
        }
        let mut cur = self.leaves.clone();
        for level in 0..self.depth as usize {
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut i = 0;
            while i < cur.len() {
                let left = cur[i];
                let right = if i + 1 < cur.len() { cur[i + 1] } else { self.empties[level] };
                next.push(hash_node(&left, &right));
                i += 2;
            }
            cur = next;
        }
        cur[0]
    }

    /// The authentication path for the leaf at `index`, or `None` if unset.
    pub fn path(&self, index: u64) -> Option<MerklePath> {
        if index >= self.leaves.len() as u64 {
            return None;
        }
        let mut cur = self.leaves.clone();
        let mut idx = index as usize;
        let mut siblings = Vec::with_capacity(self.depth as usize);
        for level in 0..self.depth as usize {
            let sib_idx = idx ^ 1;
            let sib = if sib_idx < cur.len() { cur[sib_idx] } else { self.empties[level] };
            siblings.push(sib);
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut i = 0;
            while i < cur.len() {
                let left = cur[i];
                let right = if i + 1 < cur.len() { cur[i + 1] } else { self.empties[level] };
                next.push(hash_node(&left, &right));
                i += 2;
            }
            cur = next;
            idx >>= 1;
        }
        Some(MerklePath { siblings, index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cm(b: u8) -> Commitment {
        Commitment(Hash64::from_bytes([b; 64]))
    }

    #[test]
    fn append_root_and_paths_verify() {
        let mut t = MerkleTree::new(8);
        let mut idxs = vec![];
        for i in 1..=13u8 {
            idxs.push((cm(i), t.append(cm(i))));
        }
        let root = t.root();
        // every inserted leaf has a path that recomputes the root
        for (c, i) in &idxs {
            let path = t.path(*i).expect("path exists");
            assert!(verify_merkle_path(&root, &c.0, &path), "leaf {i} must verify");
        }
    }

    #[test]
    fn wrong_leaf_or_root_fails() {
        let mut t = MerkleTree::new(6);
        let c = cm(1);
        let i = t.append(c);
        t.append(cm(2));
        let root = t.root();
        let path = t.path(i).unwrap();
        assert!(verify_merkle_path(&root, &c.0, &path));
        // a non-member leaf does not verify against the same path
        assert!(!verify_merkle_path(&root, &cm(99).0, &path));
        // the path does not verify against a different root
        assert!(!verify_merkle_path(&Hash64::from_bytes([0u8; 64]), &c.0, &path));
    }

    #[test]
    fn root_moves_with_every_insert() {
        let mut t = MerkleTree::new(10);
        let r0 = t.root();
        t.append(cm(1));
        let r1 = t.root();
        t.append(cm(2));
        let r2 = t.root();
        assert_ne!(r0, r1);
        assert_ne!(r1, r2);
    }
}
