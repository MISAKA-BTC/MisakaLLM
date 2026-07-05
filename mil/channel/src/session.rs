//! Session key schedule (design §3.2).
//!
//! ```text
//! k_c2p ‖ k_p2c = HKDF-SHA3-512(ss, info = "misaka-mil-v1/kdf" ‖ session_id, L = 64)
//! ```
//!
//! The first 32 bytes key the client→provider direction, the last 32 the
//! provider→client direction. Binding the session id into `info` ties the
//! keys to the exact (quote, ciphertext, nonce) triple that named the session.

use kaspa_hashes::Hash64;
use misaka_mil_core::domains::MIL_KDF_INFO;
use sha3::Sha3_512;
use zeroize::Zeroize;

/// The two direction keys of an established session. Zeroized on drop.
pub struct SessionKeys {
    /// Client → provider (requester sends under this).
    pub k_c2p: [u8; 32],
    /// Provider → client (response stream).
    pub k_p2c: [u8; 32],
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.k_c2p.zeroize();
        self.k_p2c.zeroize();
    }
}

/// Derive both direction keys from the KEM shared secret and session id.
/// The shared secret is consumed and scrubbed.
pub fn derive_session_keys(mut shared_secret: [u8; 32], session_id: &Hash64) -> SessionKeys {
    let mut info = Vec::with_capacity(MIL_KDF_INFO.len() + 64);
    info.extend_from_slice(MIL_KDF_INFO);
    info.extend_from_slice(session_id.as_byte_slice());

    let hk = hkdf::Hkdf::<Sha3_512>::new(None, &shared_secret);
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm).expect("64-byte HKDF-SHA3-512 output is far below the 255*64 limit");
    shared_secret.zeroize();

    let mut k_c2p = [0u8; 32];
    let mut k_p2c = [0u8; 32];
    k_c2p.copy_from_slice(&okm[..32]);
    k_p2c.copy_from_slice(&okm[32..]);
    okm.zeroize();
    SessionKeys { k_c2p, k_p2c }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_schedule_is_deterministic_and_direction_separated() {
        let sid = Hash64::from_bytes([5u8; 64]);
        let a = derive_session_keys([1u8; 32], &sid);
        let b = derive_session_keys([1u8; 32], &sid);
        assert_eq!(a.k_c2p, b.k_c2p);
        assert_eq!(a.k_p2c, b.k_p2c);
        assert_ne!(a.k_c2p, a.k_p2c, "direction keys must differ");

        // different session id or secret → different keys
        let c = derive_session_keys([1u8; 32], &Hash64::from_bytes([6u8; 64]));
        assert_ne!(a.k_c2p, c.k_c2p);
        let d = derive_session_keys([2u8; 32], &sid);
        assert_ne!(a.k_c2p, d.k_c2p);
    }
}
