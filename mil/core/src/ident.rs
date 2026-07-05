//! MIL identity derivations (design §3.2): enclave key binding, session ids,
//! provider ids. All are keyed-BLAKE2b-512 (`Hash64_k`) with the domain string
//! as the BLAKE2b key — same construction as the rest of the fork.

use crate::domains::{MIL_BIND_DOMAIN, MIL_PROVIDER_ID_DOMAIN, MIL_SESSION_DOMAIN};
use kaspa_hashes::{Hash64, blake2b_512_keyed};

/// Length of the requester handshake nonce feeding [`session_id`].
pub const SESSION_NONCE_LEN: usize = 32;

/// Enclave key binding committed into the attestation `report_data` (§3.2):
///
/// ```text
/// report_data = Hash64_k("misaka-mil-v1/bind" ‖ pk_kem ‖ pk_receipt)
/// ```
///
/// Binding both enclave-generated public keys into the measured quote is what
/// stops a MITM substituting another enclave's keys. Both inputs are
/// fixed-width (ML-KEM-1024 ek = 1568 bytes, ML-DSA-87 vk = 2592 bytes), so
/// plain concatenation is unambiguous.
pub fn key_binding(pk_kem: &[u8], pk_receipt: &[u8]) -> Hash64 {
    let mut preimage = Vec::with_capacity(pk_kem.len() + pk_receipt.len());
    preimage.extend_from_slice(pk_kem);
    preimage.extend_from_slice(pk_receipt);
    blake2b_512_keyed(MIL_BIND_DOMAIN, &preimage)
}

/// Session identity (§3.2):
///
/// ```text
/// session_id = Hash64_k("misaka-mil-v1/session" ‖ quote_hash ‖ kem_ct ‖ nonce_req)
/// ```
///
/// `quote_hash` pins the provider identity/attestation epoch, `kem_ct` is the
/// requester's ML-KEM-1024 encapsulation (fresh per session — this is what
/// makes sessions unlinkable, §15.2), and `nonce_req` is the requester's
/// handshake nonce. All three are fixed-width (64 ‖ 1568 ‖ 32 bytes).
pub fn session_id(quote_hash: &Hash64, kem_ct: &[u8], nonce_req: &[u8; SESSION_NONCE_LEN]) -> Hash64 {
    let mut preimage = Vec::with_capacity(64 + kem_ct.len() + SESSION_NONCE_LEN);
    preimage.extend_from_slice(quote_hash.as_byte_slice());
    preimage.extend_from_slice(kem_ct);
    preimage.extend_from_slice(nonce_req);
    blake2b_512_keyed(MIL_SESSION_DOMAIN, &preimage)
}

/// Provider overlay identity: `Hash64_k("misaka-mil-v1/provider-id" ‖ pk_receipt)`.
///
/// Keyed under a MIL-specific domain so it is disjoint from both the DNS
/// validator id (unkeyed BLAKE2b-512) and the wallet address payload
/// (`kaspa-pq-v2/address/mldsa87`), even when the same ML-DSA-87 key were
/// (unwisely) reused across roles.
pub fn provider_id(pk_receipt: &[u8]) -> Hash64 {
    blake2b_512_keyed(MIL_PROVIDER_ID_DOMAIN, pk_receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindings_are_deterministic_and_input_sensitive() {
        let pk_kem = vec![0x11u8; 1568];
        let pk_receipt = vec![0x22u8; 2592];
        let b1 = key_binding(&pk_kem, &pk_receipt);
        let b2 = key_binding(&pk_kem, &pk_receipt);
        assert_eq!(b1, b2);
        let mut other = pk_kem.clone();
        other[0] ^= 1;
        assert_ne!(b1, key_binding(&other, &pk_receipt));
        // domain separation: a provider id over the same bytes must differ
        assert_ne!(provider_id(&pk_receipt).as_bytes(), key_binding(&[], &pk_receipt).as_bytes());
    }

    #[test]
    fn session_id_binds_all_three_inputs() {
        let quote = Hash64::from_bytes([7u8; 64]);
        let ct = vec![0x33u8; 1568];
        let nonce = [0x44u8; SESSION_NONCE_LEN];
        let sid = session_id(&quote, &ct, &nonce);
        assert_eq!(sid, session_id(&quote, &ct, &nonce));
        assert_ne!(sid, session_id(&Hash64::from_bytes([8u8; 64]), &ct, &nonce));
        let mut ct2 = ct.clone();
        ct2[100] ^= 1;
        assert_ne!(sid, session_id(&quote, &ct2, &nonce));
        let mut nonce2 = nonce;
        nonce2[0] ^= 1;
        assert_ne!(sid, session_id(&quote, &ct, &nonce2));
    }
}
