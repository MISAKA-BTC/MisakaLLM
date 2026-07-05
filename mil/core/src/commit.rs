//! On-chain content commitments (design §3.3).
//!
//! The chain never carries prompt or response bytes — only:
//!
//! - `cm_req  = Hash64_k("misaka-mil-v1/commit" ‖ salt ‖ H(prompt_ct))` — the
//!   salted request commitment submitted at escrow/anchor time. The salt
//!   defeats dictionary attacks on known prompts; the inner hash is over the
//!   *ciphertext*, so even the commitment preimage never touches plaintext.
//! - `cm_resp_k` — the running transcript hash of the plaintext response
//!   stream, recomputed independently by the enclave (signer) and the
//!   requester (verifier), and signed into every cumulative receipt (§4.1).

use crate::domains::{MIL_COMMIT_DOMAIN, MIL_PROMPT_CT_DOMAIN, MIL_TRANSCRIPT_DOMAIN};
use blake2b_simd::Params as Blake2bParams;
use kaspa_hashes::{HASH64_SIZE, Hash64, blake2b_512_keyed};

/// Length of the request-commitment salt (§3.3).
pub const REQUEST_SALT_LEN: usize = 32;

/// Inner hash `H(prompt_ct)` over the prompt *ciphertext*.
pub fn prompt_ct_hash(prompt_ct: &[u8]) -> Hash64 {
    blake2b_512_keyed(MIL_PROMPT_CT_DOMAIN, prompt_ct)
}

/// The salted request commitment `cm_req` (§3.3). Both fields are
/// fixed-width (32 ‖ 64 bytes), so concatenation is unambiguous.
pub fn request_commitment(salt: &[u8; REQUEST_SALT_LEN], prompt_ct_hash: &Hash64) -> Hash64 {
    let mut preimage = [0u8; REQUEST_SALT_LEN + HASH64_SIZE];
    preimage[..REQUEST_SALT_LEN].copy_from_slice(salt);
    preimage[REQUEST_SALT_LEN..].copy_from_slice(prompt_ct_hash.as_byte_slice());
    blake2b_512_keyed(MIL_COMMIT_DOMAIN, &preimage)
}

/// Convenience: `cm_req` straight from the prompt ciphertext.
pub fn request_commitment_for_ct(salt: &[u8; REQUEST_SALT_LEN], prompt_ct: &[u8]) -> Hash64 {
    request_commitment(salt, &prompt_ct_hash(prompt_ct))
}

/// Incremental response-transcript hasher producing `cm_resp_k` (§3.3/§4.1).
///
/// A single keyed BLAKE2b-512 state, seeded with the session id, absorbing
/// each plaintext response chunk in stream order. [`Self::commitment`]
/// finalizes a *clone*, so intermediate commitments at every receipt boundary
/// and the final commitment all come from one pass — provider and requester
/// converge as long as they saw the same byte stream.
#[derive(Clone)]
pub struct TranscriptHasher {
    state: blake2b_simd::State,
    absorbed: u64,
}

impl TranscriptHasher {
    /// Start a transcript for `session_id` (binding transcripts to sessions,
    /// so identical responses in different sessions commit differently).
    pub fn new(session_id: &Hash64) -> Self {
        let mut state = Blake2bParams::new().hash_length(HASH64_SIZE).key(MIL_TRANSCRIPT_DOMAIN).to_state();
        state.update(session_id.as_byte_slice());
        Self { state, absorbed: 0 }
    }

    /// Absorb the next plaintext response chunk.
    pub fn absorb(&mut self, chunk: &[u8]) {
        self.state.update(chunk);
        self.absorbed += chunk.len() as u64;
    }

    /// Total plaintext bytes absorbed so far.
    pub fn absorbed_bytes(&self) -> u64 {
        self.absorbed
    }

    /// The transcript commitment `cm_resp` at the current position
    /// (non-destructive — the stream can keep absorbing).
    pub fn commitment(&self) -> Hash64 {
        let mut out = [0u8; HASH64_SIZE];
        out.copy_from_slice(self.state.clone().finalize().as_bytes());
        Hash64::from_bytes(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_commitment_is_salted() {
        let ct = b"opaque prompt ciphertext";
        let cm1 = request_commitment_for_ct(&[1u8; REQUEST_SALT_LEN], ct);
        let cm2 = request_commitment_for_ct(&[2u8; REQUEST_SALT_LEN], ct);
        assert_ne!(cm1, cm2, "same ciphertext under different salts must not match (dictionary defense)");
        assert_eq!(cm1, request_commitment_for_ct(&[1u8; REQUEST_SALT_LEN], ct));
    }

    #[test]
    fn transcript_is_incremental_and_chunking_invariant() {
        let sid = Hash64::from_bytes([9u8; 64]);
        let mut a = TranscriptHasher::new(&sid);
        a.absorb(b"hello ");
        let mid = a.commitment();
        a.absorb(b"world");
        let fin = a.commitment();
        assert_ne!(mid, fin);

        // one absorb of the concatenation converges to the same final commitment
        let mut b = TranscriptHasher::new(&sid);
        b.absorb(b"hello world");
        assert_eq!(fin, b.commitment());
        assert_eq!(a.absorbed_bytes(), 11);

        // a different session diverges even on identical bytes
        let mut c = TranscriptHasher::new(&Hash64::from_bytes([10u8; 64]));
        c.absorb(b"hello world");
        assert_ne!(fin, c.commitment());
    }
}
