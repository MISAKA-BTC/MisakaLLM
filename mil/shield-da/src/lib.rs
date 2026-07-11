//! Shielded-proof DA **chunk transport** — the data layer of ADR-0036 §3.A.
//!
//! The measured outer STARK proof is 170–382 KiB (ADR-0035 §4), but a DAG block's
//! EVM payload cap is 32 KiB (`MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK`). A proof cannot
//! ride a block, and — because the cap is a `1.25 MB/s envelope ÷ BPS` slice, not an
//! arbitrary number — the answer is to **split the proof into ≤ 32 KiB inert chunks**
//! so every block stays its current size (propagation profile untouched; ADR-0036
//! §5 measured `reds = 0`), and reassemble the proof off the critical block path.
//!
//! This crate is the **pure, deterministic, panic-free data layer**:
//!
//! - [`chunk_proof`] splits an outer proof into ordered [`ProofChunk`]s and a
//!   [`ChunkSetDescriptor`] that commits (keyed BLAKE2b-512, matching the F004 lane)
//!   to the ordered chunk hashes. The settling tx references `descriptor.set_id`.
//! - [`validate_chunk`] checks one chunk against the descriptor **on arrival**
//!   (index in range, hash matches, ≤ cap) — the "inert chunk object, class-1
//!   syntactic validation only" of ADR-0036 §3.A.
//! - [`reassemble`] rebuilds the proof from a full chunk set, **fail-closed**: a
//!   missing / duplicate / tampered / mis-sized / mis-committed chunk is an `Err`,
//!   never a panic (an incomplete set is a class-2-style skip, not a halt).
//!
//! The consensus wiring — assembly at the accepting block (riding mergeset delayed
//! acceptance), per-byte DA charge, unreferenced-chunk TTL prune — is a fenced
//! follow-up that consumes this layer; nothing here touches consensus state.

use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{Hash64, blake2b_512_keyed};

/// Per-block DA cap = `MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK` (consensus). Each chunk
/// must fit a block, so this is the maximum chunk payload.
pub const MAX_CHUNK_BYTES: usize = 32 * 1024;

/// Abuse cap on the chunk count (a 512 KiB proof is 16 chunks; 4096 admits ~128 MiB
/// — far above any real proof, a backstop against a malicious descriptor).
pub const MAX_CHUNKS: usize = 4096;

/// Hard cap on the reassembled proof length a descriptor may commit to (audit H-02). A
/// real outer proof is 170–382 KiB; 8 MiB is a generous ceiling that still bounds the
/// `reassemble` allocation so a malicious descriptor cannot request gigabytes.
pub const MAX_REASSEMBLED_PROOF_BYTES: usize = 8 * 1024 * 1024;

/// keyed-BLAKE2b domain for a single chunk hash.
const CHUNK_DOMAIN: &[u8] = b"misaka-shield-v1/da-chunk";
/// keyed-BLAKE2b domain for the chunk-set commitment (`set_id`).
const SET_DOMAIN: &[u8] = b"misaka-shield-v1/da-set";

/// The commitment the settling tx references. `set_id` binds the proof length and
/// the ordered list of chunk hashes, so a reassembled proof is exactly the one the
/// tx committed to (no substitution, no reorder, no truncation).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChunkSetDescriptor {
    /// `H_k("da-set", proof_len_le ‖ total_le ‖ H(c_0) ‖ … ‖ H(c_{n-1}))`.
    pub set_id: Hash64,
    /// Exact length of the reassembled proof (guards truncation/padding).
    pub proof_len: u32,
    /// Number of chunks (`ceil(proof_len / MAX_CHUNK_BYTES)`, ≥ 1).
    pub total_chunks: u16,
    /// Per-chunk hashes in order (so an arriving chunk is validated immediately).
    pub chunk_hashes: Vec<Hash64>,
}

/// An inert chunk object as gossiped. Carries its `set_id` + position so a node can
/// validate it against a known descriptor without any other context.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProofChunk {
    pub set_id: Hash64,
    pub index: u16,
    pub total: u16,
    pub bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DaError {
    #[error("empty proof cannot be chunked")]
    Empty,
    #[error("proof too large: {0} bytes exceeds MAX_CHUNKS×MAX_CHUNK_BYTES")]
    ProofTooLarge(usize),
    #[error("chunk index {index} out of range (total {total})")]
    IndexOutOfRange { index: u16, total: u16 },
    #[error("chunk {0} exceeds the {MAX_CHUNK_BYTES}-byte cap")]
    ChunkTooLarge(u16),
    #[error("chunk {0} hash does not match the descriptor")]
    BadChunkHash(u16),
    #[error("chunk {index} declares set_id/total inconsistent with the descriptor")]
    SetMismatch { index: u16 },
    #[error("incomplete set: chunk {0} missing")]
    MissingChunk(u16),
    #[error("duplicate chunk {0}")]
    DuplicateChunk(u16),
    #[error("reassembled length {got} != committed {want}")]
    LenMismatch { got: usize, want: u32 },
    #[error("descriptor set_id does not match its own contents (forged descriptor)")]
    DescriptorForged,
    #[error("descriptor total_chunks {0} out of range")]
    BadTotal(u16),
    #[error("descriptor proof_len {0} exceeds the reassembly cap")]
    ProofLenTooLarge(u32),
    #[error("descriptor proof_len {proof_len} is not consistent with total_chunks {total}")]
    NonCanonicalLength { proof_len: u32, total: u16 },
    #[error("allocation of {0} bytes failed")]
    AllocFailed(usize),
}

/// `H_k("da-chunk", index_le ‖ bytes)` — binds a chunk's position into its hash so
/// chunks cannot be reordered.
fn chunk_hash(index: u16, bytes: &[u8]) -> Hash64 {
    let mut b = Vec::with_capacity(2 + bytes.len());
    b.extend_from_slice(&index.to_le_bytes());
    b.extend_from_slice(bytes);
    blake2b_512_keyed(CHUNK_DOMAIN, &b)
}

/// `set_id` over the ordered chunk hashes + length (the tx's commitment reference).
fn compute_set_id(proof_len: u32, chunk_hashes: &[Hash64]) -> Hash64 {
    let total = chunk_hashes.len() as u16;
    let mut b = Vec::with_capacity(4 + 2 + chunk_hashes.len() * 64);
    b.extend_from_slice(&proof_len.to_le_bytes());
    b.extend_from_slice(&total.to_le_bytes());
    for h in chunk_hashes {
        b.extend_from_slice(h.as_byte_slice());
    }
    blake2b_512_keyed(SET_DOMAIN, &b)
}

/// Split an outer proof into ≤ `MAX_CHUNK_BYTES` chunks + a committing descriptor.
pub fn chunk_proof(proof: &[u8]) -> Result<(ChunkSetDescriptor, Vec<ProofChunk>), DaError> {
    if proof.is_empty() {
        return Err(DaError::Empty);
    }
    if proof.len() > MAX_CHUNKS * MAX_CHUNK_BYTES {
        return Err(DaError::ProofTooLarge(proof.len()));
    }
    let total = proof.len().div_ceil(MAX_CHUNK_BYTES);
    debug_assert!((1..=MAX_CHUNKS).contains(&total));
    let total_u16 = total as u16;

    let mut chunk_hashes = Vec::with_capacity(total);
    let mut chunks = Vec::with_capacity(total);
    for (i, piece) in proof.chunks(MAX_CHUNK_BYTES).enumerate() {
        let index = i as u16;
        let h = chunk_hash(index, piece);
        chunk_hashes.push(h);
        chunks.push(ProofChunk { set_id: Hash64::default(), index, total: total_u16, bytes: piece.to_vec() });
    }
    let set_id = compute_set_id(proof.len() as u32, &chunk_hashes);
    for c in &mut chunks {
        c.set_id = set_id;
    }
    let descriptor = ChunkSetDescriptor { set_id, proof_len: proof.len() as u32, total_chunks: total_u16, chunk_hashes };
    Ok((descriptor, chunks))
}

/// Validate the descriptor is self-consistent (its `set_id` commits to its own
/// contents). Cheap; run once before trusting a descriptor from the wire.
pub fn validate_descriptor(desc: &ChunkSetDescriptor) -> Result<(), DaError> {
    let total = desc.chunk_hashes.len();
    if total == 0 || total > MAX_CHUNKS || total as u16 != desc.total_chunks {
        return Err(DaError::BadTotal(desc.total_chunks));
    }
    // (audit H-02) bound the committed proof length BEFORE any `with_capacity`, and require
    // it to be the canonical length for `total_chunks` (`ceil(proof_len/MAX_CHUNK_BYTES) ==
    // total`, and the length lands in the last chunk's range) so a self-consistent descriptor
    // cannot commit a `proof_len` that would drive a huge allocation or truncated reassembly.
    let plen = desc.proof_len as usize;
    if plen == 0 || plen > MAX_REASSEMBLED_PROOF_BYTES {
        return Err(DaError::ProofLenTooLarge(desc.proof_len));
    }
    if plen.div_ceil(MAX_CHUNK_BYTES) != total {
        return Err(DaError::NonCanonicalLength { proof_len: desc.proof_len, total: desc.total_chunks });
    }
    if compute_set_id(desc.proof_len, &desc.chunk_hashes) != desc.set_id {
        return Err(DaError::DescriptorForged);
    }
    Ok(())
}

/// Validate one chunk against a (already `validate_descriptor`-checked) descriptor,
/// as it arrives — the inert-chunk syntactic check of ADR-0036 §3.A.
pub fn validate_chunk(desc: &ChunkSetDescriptor, chunk: &ProofChunk) -> Result<(), DaError> {
    if chunk.set_id != desc.set_id || chunk.total != desc.total_chunks {
        return Err(DaError::SetMismatch { index: chunk.index });
    }
    if chunk.index >= desc.total_chunks {
        return Err(DaError::IndexOutOfRange { index: chunk.index, total: desc.total_chunks });
    }
    if chunk.bytes.len() > MAX_CHUNK_BYTES {
        return Err(DaError::ChunkTooLarge(chunk.index));
    }
    // (audit M-06) `.get()` — never index directly. If a caller passes an un-`validate_
    // descriptor`-checked descriptor whose `chunk_hashes` is shorter than `total_chunks`,
    // a direct `[index]` would panic (the crate's panic-free contract). Fail closed instead.
    let expected = desc.chunk_hashes.get(chunk.index as usize).ok_or(DaError::BadTotal(desc.total_chunks))?;
    if chunk_hash(chunk.index, &chunk.bytes) != *expected {
        return Err(DaError::BadChunkHash(chunk.index));
    }
    Ok(())
}

/// Reassemble the proof from a full chunk set. **Fail-closed**: the descriptor must
/// be self-consistent, every index present exactly once, every chunk valid, and the
/// concatenated length must equal the committed `proof_len`.
pub fn reassemble(desc: &ChunkSetDescriptor, chunks: &[ProofChunk]) -> Result<Vec<u8>, DaError> {
    validate_descriptor(desc)?;
    let total = desc.total_chunks as usize;

    // Place each chunk at its index; reject duplicates and out-of-range up front.
    let mut slots: Vec<Option<&ProofChunk>> = vec![None; total];
    for c in chunks {
        validate_chunk(desc, c)?;
        let slot = &mut slots[c.index as usize];
        if slot.is_some() {
            return Err(DaError::DuplicateChunk(c.index));
        }
        *slot = Some(c);
    }

    // `validate_descriptor` above already bounded `proof_len` ≤ MAX_REASSEMBLED_PROOF_BYTES
    // and made it canonical; `try_reserve` is belt-and-braces so even a bug upstream degrades
    // to an `Err`, never an abort (audit H-02).
    let mut out = Vec::new();
    out.try_reserve_exact(desc.proof_len as usize).map_err(|_| DaError::AllocFailed(desc.proof_len as usize))?;
    for (i, slot) in slots.iter().enumerate() {
        let c = slot.ok_or(DaError::MissingChunk(i as u16))?;
        out.extend_from_slice(&c.bytes);
    }
    if out.len() != desc.proof_len as usize {
        return Err(DaError::LenMismatch { got: out.len(), want: desc.proof_len });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic pseudo-proof of `n` bytes (no rng in tests).
    fn proof(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 131 + 7) as u8).collect()
    }

    #[test]
    fn roundtrip_across_sizes() {
        for &n in &[1usize, 32, MAX_CHUNK_BYTES - 1, MAX_CHUNK_BYTES, MAX_CHUNK_BYTES + 1, 170 * 1024, 382 * 1024] {
            let p = proof(n);
            let (desc, chunks) = chunk_proof(&p).unwrap();
            assert_eq!(desc.total_chunks as usize, n.div_ceil(MAX_CHUNK_BYTES));
            assert!(chunks.iter().all(|c| c.bytes.len() <= MAX_CHUNK_BYTES));
            validate_descriptor(&desc).unwrap();
            assert_eq!(reassemble(&desc, &chunks).unwrap(), p, "n={n}");
        }
    }

    #[test]
    fn measured_outer_proof_splits_into_expected_chunk_count() {
        // ADR-0035 §4: the outer proof is 170–382 KiB.
        assert_eq!(chunk_proof(&proof(170 * 1024)).unwrap().0.total_chunks, 6); // 170/32 → 6
        assert_eq!(chunk_proof(&proof(382 * 1024)).unwrap().0.total_chunks, 12); // 382/32 → 12
    }

    #[test]
    fn tampered_chunk_is_rejected() {
        let p = proof(200 * 1024);
        let (desc, mut chunks) = chunk_proof(&p).unwrap();
        chunks[3].bytes[10] ^= 0xff; // flip a byte
        assert_eq!(reassemble(&desc, &chunks), Err(DaError::BadChunkHash(3)));
    }

    #[test]
    fn missing_chunk_is_incomplete() {
        let p = proof(200 * 1024);
        let (desc, mut chunks) = chunk_proof(&p).unwrap();
        chunks.remove(2); // drop chunk 2
        assert_eq!(reassemble(&desc, &chunks), Err(DaError::MissingChunk(2)));
    }

    #[test]
    fn duplicate_chunk_is_rejected() {
        let p = proof(100 * 1024);
        let (desc, chunks) = chunk_proof(&p).unwrap();
        let mut dup = chunks.clone();
        dup.push(chunks[1].clone());
        assert_eq!(reassemble(&desc, &dup), Err(DaError::DuplicateChunk(1)));
    }

    #[test]
    fn reordered_chunks_still_reassemble_correctly() {
        // chunks carry their index, so wire-order does not matter.
        let p = proof(150 * 1024);
        let (desc, mut chunks) = chunk_proof(&p).unwrap();
        chunks.reverse();
        assert_eq!(reassemble(&desc, &chunks).unwrap(), p);
    }

    #[test]
    fn forged_descriptor_is_rejected() {
        let (mut desc, chunks) = chunk_proof(&proof(100 * 1024)).unwrap();
        desc.proof_len += 1; // len no longer matches the committed set_id
        assert_eq!(validate_descriptor(&desc), Err(DaError::DescriptorForged));
        assert_eq!(reassemble(&desc, &chunks), Err(DaError::DescriptorForged));
    }

    #[test]
    fn substituted_chunk_from_another_set_is_rejected() {
        let (desc_a, _) = chunk_proof(&proof(100 * 1024)).unwrap();
        let (_, chunks_b) = chunk_proof(&proof(100 * 1024).iter().map(|b| b ^ 0x5a).collect::<Vec<_>>()).unwrap();
        // a chunk from set B carries B's set_id → SetMismatch against desc_a
        assert!(matches!(validate_chunk(&desc_a, &chunks_b[0]), Err(DaError::SetMismatch { .. })));
    }

    #[test]
    fn empty_proof_is_rejected() {
        assert_eq!(chunk_proof(&[]), Err(DaError::Empty));
    }

    // ---- audit 2026-07-11 regressions ----

    /// H-02: a self-consistent descriptor claiming a giant `proof_len` is rejected BEFORE
    /// any allocation, so it cannot drive an OOM.
    #[test]
    fn h02_giant_proof_len_rejected_before_alloc() {
        // total_chunks=1, one chunk hash, but proof_len = u32::MAX. Make set_id self-consistent.
        let bytes = vec![0u8; 100];
        let ch = chunk_hash(0, &bytes);
        let set_id = compute_set_id(u32::MAX, &[ch]);
        let desc = ChunkSetDescriptor { set_id, proof_len: u32::MAX, total_chunks: 1, chunk_hashes: vec![ch] };
        // rejected at validate_descriptor (cap), never reaching with_capacity/try_reserve.
        assert_eq!(validate_descriptor(&desc), Err(DaError::ProofLenTooLarge(u32::MAX)));
        let chunk = ProofChunk { set_id, index: 0, total: 1, bytes };
        assert_eq!(reassemble(&desc, &[chunk]), Err(DaError::ProofLenTooLarge(u32::MAX)));
    }

    /// H-02: a `proof_len` that is not the canonical length for `total_chunks` is rejected.
    #[test]
    fn h02_noncanonical_length_rejected() {
        // total_chunks=1 but proof_len says it needs 2 chunks.
        let ch = chunk_hash(0, &[0u8; 10]);
        let plen = (MAX_CHUNK_BYTES + 1) as u32;
        let set_id = compute_set_id(plen, &[ch]);
        let desc = ChunkSetDescriptor { set_id, proof_len: plen, total_chunks: 1, chunk_hashes: vec![ch] };
        assert_eq!(validate_descriptor(&desc), Err(DaError::NonCanonicalLength { proof_len: plen, total: 1 }));
    }

    /// M-06: `validate_chunk` on a malformed descriptor (total_chunks > chunk_hashes.len)
    /// returns `Err`, never panics — even without a prior `validate_descriptor`.
    #[test]
    fn m06_validate_chunk_is_panic_free_on_malformed_descriptor() {
        let bytes = vec![1u8, 2, 3];
        let ch = chunk_hash(1, &bytes); // index 1
        // descriptor claims 2 chunks but only carries ONE hash → index 1 is out of the vec.
        let set_id = compute_set_id(3, &[ch]);
        let desc = ChunkSetDescriptor { set_id, proof_len: 3, total_chunks: 2, chunk_hashes: vec![ch] };
        let chunk = ProofChunk { set_id, index: 1, total: 2, bytes };
        // index 1 < total_chunks 2 passes the range check, then .get(1) on a len-1 vec is None.
        assert_eq!(validate_chunk(&desc, &chunk), Err(DaError::BadTotal(2)));
    }
}
