//! Direction-keyed AEAD record layer (design §3.2).
//!
//! Every record is AES-256-GCM under the direction key with:
//!
//! - nonce (96-bit): `direction byte ‖ 0x000000 ‖ seq (u64 LE)` — unique per
//!   (key, direction, seq); the u64 counter cannot wrap in practice and we
//!   hard-error long before.
//! - AAD: `session_id ‖ direction ‖ frame_type ‖ seq (u64 LE)` — replay,
//!   reorder, cross-direction reflection, and frame-type confusion all break
//!   authentication instead of surfacing as protocol bugs.
//!
//! Receivers enforce **strict in-order delivery** (`seq == expected`): the
//! v0 transport is a reliable ordered byte stream, so any gap is an attack or
//! a broken peer, never something to tolerate.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use kaspa_hashes::Hash64;
use zeroize::Zeroize;

/// AES-256-GCM authentication-tag length.
pub const AEAD_TAG_LEN: usize = 16;

/// Channel direction, encoded into nonce and AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    ClientToProvider = 0x01,
    ProviderToClient = 0x02,
}

/// Record-layer failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChannelError {
    #[error("AEAD open failed (tampered, replayed, or cross-direction record)")]
    Aead,
    #[error("record sequence out of order: expected {expected}, got {got}")]
    OutOfOrder { expected: u64, got: u64 },
    #[error("sequence space exhausted")]
    SequenceExhausted,
}

fn nonce_for(direction: Direction, seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = direction as u8;
    nonce[4..].copy_from_slice(&seq.to_le_bytes());
    nonce
}

fn aad_for(session_id: &Hash64, direction: Direction, frame_type: u8, seq: u64) -> [u8; 64 + 1 + 1 + 8] {
    let mut aad = [0u8; 74];
    aad[..64].copy_from_slice(session_id.as_byte_slice());
    aad[64] = direction as u8;
    aad[65] = frame_type;
    aad[66..].copy_from_slice(&seq.to_le_bytes());
    aad
}

/// Sealing half: owns the direction key and the send counter.
pub struct SendCipher {
    cipher: Aes256Gcm,
    session_id: Hash64,
    direction: Direction,
    next_seq: u64,
}

impl SendCipher {
    pub fn new(mut key: [u8; 32], session_id: Hash64, direction: Direction) -> Self {
        let cipher = Aes256Gcm::new((&key).into());
        key.zeroize();
        Self { cipher, session_id, direction, next_seq: 0 }
    }

    /// Seal a frame; returns `(seq, ciphertext)`. The sequence is consumed
    /// even if the caller drops the record — never reused.
    pub fn seal(&mut self, frame_type: u8, plaintext: &[u8]) -> Result<(u64, Vec<u8>), ChannelError> {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.checked_add(1).ok_or(ChannelError::SequenceExhausted)?;
        let aad = aad_for(&self.session_id, self.direction, frame_type, seq);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce_for(self.direction, seq)), Payload { msg: plaintext, aad: &aad })
            .expect("AES-GCM encryption is infallible for in-memory buffers");
        Ok((seq, ct))
    }
}

/// Opening half: enforces strict in-order sequence numbers.
pub struct RecvCipher {
    cipher: Aes256Gcm,
    session_id: Hash64,
    direction: Direction,
    expected_seq: u64,
}

impl RecvCipher {
    pub fn new(mut key: [u8; 32], session_id: Hash64, direction: Direction) -> Self {
        let cipher = Aes256Gcm::new((&key).into());
        key.zeroize();
        Self { cipher, session_id, direction, expected_seq: 0 }
    }

    /// Open the next record. The counter advances only on success, so a
    /// tampered record does not desynchronize an honest retransmit.
    pub fn open(&mut self, frame_type: u8, seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if seq != self.expected_seq {
            return Err(ChannelError::OutOfOrder { expected: self.expected_seq, got: seq });
        }
        let aad = aad_for(&self.session_id, self.direction, frame_type, seq);
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce_for(self.direction, seq)), Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| ChannelError::Aead)?;
        self.expected_seq += 1;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (SendCipher, RecvCipher) {
        let sid = Hash64::from_bytes([9u8; 64]);
        (SendCipher::new([1u8; 32], sid, Direction::ClientToProvider), RecvCipher::new([1u8; 32], sid, Direction::ClientToProvider))
    }

    #[test]
    fn seal_open_roundtrip_in_order() {
        let (mut tx, mut rx) = pair();
        for i in 0..5u8 {
            let (seq, ct) = tx.seal(7, &[i; 100]).unwrap();
            assert_eq!(seq, i as u64);
            assert_eq!(rx.open(7, seq, &ct).unwrap(), vec![i; 100]);
        }
    }

    #[test]
    fn replay_reorder_tamper_and_type_confusion_fail() {
        let (mut tx, mut rx) = pair();
        let (s0, c0) = tx.seal(7, b"zero").unwrap();
        let (s1, c1) = tx.seal(7, b"one").unwrap();

        // reorder: record 1 before record 0
        assert_eq!(rx.open(7, s1, &c1).unwrap_err(), ChannelError::OutOfOrder { expected: 0, got: 1 });
        // correct order works
        rx.open(7, s0, &c0).unwrap();
        // replay of record 0
        assert_eq!(rx.open(7, s0, &c0).unwrap_err(), ChannelError::OutOfOrder { expected: 1, got: 0 });
        // tamper
        let mut bad = c1.clone();
        bad[0] ^= 1;
        assert_eq!(rx.open(7, s1, &bad).unwrap_err(), ChannelError::Aead);
        // failed open must not advance the counter — honest record still lands
        // frame-type confusion
        assert_eq!(rx.open(8, s1, &c1).unwrap_err(), ChannelError::Aead);
        rx.open(7, s1, &c1).unwrap();
    }

    #[test]
    fn directions_and_sessions_are_isolated() {
        let sid = Hash64::from_bytes([9u8; 64]);
        let mut tx = SendCipher::new([1u8; 32], sid, Direction::ClientToProvider);
        let (seq, ct) = tx.seal(7, b"hello").unwrap();

        // same key, opposite direction: reflection must fail
        let mut rx_wrong_dir = RecvCipher::new([1u8; 32], sid, Direction::ProviderToClient);
        assert_eq!(rx_wrong_dir.open(7, seq, &ct).unwrap_err(), ChannelError::Aead);

        // same key+direction, different session id
        let mut rx_wrong_sid = RecvCipher::new([1u8; 32], Hash64::from_bytes([10u8; 64]), Direction::ClientToProvider);
        assert_eq!(rx_wrong_sid.open(7, seq, &ct).unwrap_err(), ChannelError::Aead);
    }
}
