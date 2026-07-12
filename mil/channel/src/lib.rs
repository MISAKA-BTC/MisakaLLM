//! MIL data-plane PQ channel (design §3.2).
//!
//! An application-layer HPKE-like construction, PQ throughout:
//!
//! ```text
//! (ct, ss)     = ML-KEM-1024.Encaps(pk_kem)
//! session_id   = Hash64_k("misaka-mil-v1/session" ‖ quote_hash ‖ ct ‖ nonce_req)
//! k_c2p ‖ k_p2c = HKDF-SHA3-512(ss, info = "misaka-mil-v1/kdf" ‖ session_id, L = 64)
//! ```
//!
//! Direction-separated AES-256-GCM with a strictly increasing per-direction
//! sequence number bound into both the nonce and the AAD (together with the
//! session id and frame type) — reordering, replay, cross-direction
//! reflection, and type confusion all fail authentication.
//!
//! The channel is transport-agnostic: [`wire`] speaks over any
//! `AsyncRead + AsyncWrite` byte stream (TCP for v0; QUIC later without
//! touching the cryptography — the PQ layer sits above the transport by
//! design, §3.6).

pub mod kem;
pub mod secure;
pub mod session;
pub mod wire;

pub use kem::{KEM_CT_LEN, KEM_EK_LEN, ProviderKemKeys, decapsulate, encapsulate};
pub use secure::{ChannelError, Direction, RecvCipher, SendCipher};
pub use session::{SessionKeys, derive_session_keys};
pub use wire::{
    AnonServerHello, AnonServerMsg, ClientHello, ClientMsg, EncryptedFrame, EstablishedChannel, HandshakeError, MAX_FRAME_LEN,
    ProviderIdentity, ProviderIdentityAnon, ServerHello, ServerMsg, accept_channel, accept_channel_anon, establish_channel,
    establish_channel_anon,
};
