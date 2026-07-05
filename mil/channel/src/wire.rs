//! Wire protocol: handshake + encrypted framing over any ordered byte stream
//! (design §2.3 steps 3–8, §7.4).
//!
//! ```text
//! C → P  ClientHello   { version, nonce_req }
//! P → C  ServerHello   { version, attestation, pk_kem, pk_receipt }
//!        client verifies the attestation bundle + report_data key binding
//! C → P  ClientKem     { kem_ct }                       (ML-KEM-1024 encaps)
//!        both derive session_id and the direction keys
//! C → P  EncryptedFrame(ClientMsg::Prompt), EncryptedFrame(ClientMsg::Job)
//! P → C  EncryptedFrame(ServerMsg::Chunk)* / Receipt / Done
//! ```
//!
//! The prompt frame is sealed **before** the job frame so `cm_req` can commit
//! to the actual prompt ciphertext (§3.3) while wire order still matches the
//! strict record sequence; the provider simply buffers the prompt until the
//! job arrives. The attestation check is a callback, so this crate stays
//! independent of the verifier implementation (`misaka-mil-attest` plugs in).
//!
//! All messages are `u32`-length-prefixed borsh; frames are capped at
//! [`MAX_FRAME_LEN`].

use crate::kem::{ProviderKemKeys, encapsulate};
use crate::secure::{ChannelError, Direction, RecvCipher, SendCipher};
use crate::session::derive_session_keys;
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash64;
use misaka_mil_core::domains::MIL_PROTOCOL_VERSION;
use misaka_mil_core::ident::{SESSION_NONCE_LEN, session_id};
use misaka_mil_core::job::JobSpec;
use misaka_mil_core::padding::PaddingPolicy;
use misaka_mil_core::receipt::SignedReceipt;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

/// Hard cap on any single wire message (handshake or encrypted frame).
pub const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

// --- handshake messages ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ClientHello {
    pub version: u16,
    pub nonce_req: [u8; SESSION_NONCE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ServerHello {
    pub version: u16,
    /// Opaque attestation bundle (borsh `misaka-mil-attest` document). The
    /// client MUST verify it (measurements + `report_data` key binding)
    /// before encapsulating to `pk_kem`.
    pub attestation: Vec<u8>,
    /// ML-KEM-1024 encapsulation key (1568 bytes).
    pub pk_kem: Vec<u8>,
    /// ML-DSA-87 receipt verification key (2592 bytes).
    pub pk_receipt: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ClientKem {
    pub kem_ct: Vec<u8>,
}

/// One encrypted record on the wire. `frame_type` is constant per direction
/// in v1 (the message enum tag rides inside the sealed plaintext); it is
/// bound into the AAD regardless.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EncryptedFrame {
    pub frame_type: u8,
    pub seq: u64,
    pub ciphertext: Vec<u8>,
}

/// Frame type for all client→provider records.
pub const FT_CLIENT: u8 = 0x01;
/// Frame type for all provider→client records.
pub const FT_SERVER: u8 = 0x02;

// --- application messages (sealed plaintext) -----------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ClientMsg {
    /// The prompt bytes (chat-completion request body, client-composed §18.2).
    Prompt(Vec<u8>),
    /// The job spec; `cm_req` commits to the *ciphertext* of the preceding
    /// Prompt frame.
    Job(JobSpec),
    /// First-class cancel (§14.4): provider stops decoding and emits the
    /// final receipt at the exact cumulative counters.
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ServerMsg {
    /// One streamed response chunk.
    Chunk { text: Vec<u8>, token_count: u32 },
    /// A cumulative receipt (every 512 output tokens, and once at the end).
    Receipt(SignedReceipt),
    /// End of stream. Billing settles on the final receipt, not on this.
    Done { total_tokens_out: u64 },
    /// Terminal provider-side failure.
    Error(String),
}

// --- provider identity handed to `accept_channel` -------------------------------------------

/// What the provider presents during the handshake.
pub struct ProviderIdentity {
    /// Serialized attestation bundle (opaque to this crate).
    pub attestation: Vec<u8>,
    /// `Hash64_k("misaka-mil-v1/quote" ‖ bundle)` — must match what the
    /// verifier derives on the client side.
    pub quote_hash: Hash64,
    /// ML-DSA-87 receipt verification key.
    pub pk_receipt: Vec<u8>,
}

// --- errors -----------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("wire message of {0} bytes exceeds the {MAX_FRAME_LEN}-byte cap")]
    FrameTooLarge(usize),
    #[error("malformed wire message: {0}")]
    Malformed(String),
    #[error("peer speaks MIL protocol version {0}, this build requires {MIL_PROTOCOL_VERSION}")]
    VersionMismatch(u16),
    #[error("attestation rejected: {0}")]
    AttestationRejected(String),
    #[error("KEM failure: {0}")]
    Kem(#[from] crate::kem::KemError),
    #[error("record layer failure: {0}")]
    Channel(#[from] ChannelError),
    #[error("peer closed the stream mid-handshake")]
    UnexpectedEof,
}

// --- length-prefixed borsh IO ----------------------------------------------------------------

pub(crate) async fn write_msg<W: AsyncWrite + Unpin, T: BorshSerialize>(w: &mut W, msg: &T) -> Result<(), HandshakeError> {
    let bytes = borsh::to_vec(msg).expect("borsh serialization of an in-memory message is infallible");
    if bytes.len() > MAX_FRAME_LEN {
        return Err(HandshakeError::FrameTooLarge(bytes.len()));
    }
    w.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

pub(crate) async fn read_msg<R: AsyncRead + Unpin, T: BorshDeserialize>(r: &mut R) -> Result<T, HandshakeError> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof { HandshakeError::UnexpectedEof } else { HandshakeError::Io(e) }
    })?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FRAME_LEN {
        return Err(HandshakeError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof { HandshakeError::UnexpectedEof } else { HandshakeError::Io(e) }
    })?;
    T::try_from_slice(&buf).map_err(|e| HandshakeError::Malformed(e.to_string()))
}

// --- the established channel -------------------------------------------------------------------

/// A fully established PQ channel over `S`. Sequential turn-based use; call
/// [`Self::into_parts`] to drive reads and writes concurrently (the ciphers
/// are transport-independent).
pub struct EstablishedChannel<S> {
    pub session_id: Hash64,
    /// The provider's receipt verification key (client side; on the provider
    /// side this is its own key).
    pub peer_pk_receipt: Vec<u8>,
    stream: S,
    send: SendCipher,
    recv: RecvCipher,
    send_frame_type: u8,
    recv_frame_type: u8,
    /// Side-channel padding applied to the plaintext before sealing (§15.3).
    /// Both peers MUST agree; default [`PaddingPolicy::None`] (zero overhead).
    padding: PaddingPolicy,
}

impl<S: AsyncRead + AsyncWrite + Unpin> EstablishedChannel<S> {
    /// Enable side-channel padding (§15.3). Must match the peer's policy.
    pub fn with_padding(mut self, padding: PaddingPolicy) -> Self {
        self.padding = padding;
        self
    }

    /// Seal and transmit one message. Returns the record ciphertext (the
    /// client's Prompt frame ciphertext feeds `cm_req`, §3.3).
    pub async fn send<T: BorshSerialize>(&mut self, msg: &T) -> Result<Vec<u8>, HandshakeError> {
        let plaintext = self.padding.pad(&borsh::to_vec(msg).expect("borsh serialization of an in-memory message is infallible"));
        let (seq, ciphertext) = self.send.seal(self.send_frame_type, &plaintext)?;
        let frame = EncryptedFrame { frame_type: self.send_frame_type, seq, ciphertext: ciphertext.clone() };
        write_msg(&mut self.stream, &frame).await?;
        Ok(ciphertext)
    }

    /// Receive and open the next message.
    pub async fn recv<T: BorshDeserialize>(&mut self) -> Result<T, HandshakeError> {
        let frame: EncryptedFrame = read_msg(&mut self.stream).await?;
        if frame.frame_type != self.recv_frame_type {
            return Err(HandshakeError::Malformed(format!(
                "unexpected frame type {:#04x} (expected {:#04x})",
                frame.frame_type, self.recv_frame_type
            )));
        }
        let opened = self.recv.open(frame.frame_type, frame.seq, &frame.ciphertext)?;
        let plaintext = if self.padding.is_framed() {
            PaddingPolicy::unpad(&opened).map_err(|e| HandshakeError::Malformed(e.to_string()))?
        } else {
            opened
        };
        T::try_from_slice(&plaintext).map_err(|e| HandshakeError::Malformed(e.to_string()))
    }

    /// Decompose into transport + ciphers for concurrent read/write drivers.
    pub fn into_parts(self) -> (S, SendCipher, RecvCipher, Hash64) {
        (self.stream, self.send, self.recv, self.session_id)
    }

    /// Split into independent reader/writer halves so a peer can stream
    /// responses while concurrently watching for an inbound frame (e.g. a live
    /// `Cancel`, §14.4). Padding + frame types are carried onto each half.
    pub fn into_split(self) -> (ChannelReader<ReadHalf<S>>, ChannelWriter<WriteHalf<S>>) {
        let (rh, wh) = tokio::io::split(self.stream);
        (
            ChannelReader { rh, recv: self.recv, recv_frame_type: self.recv_frame_type, padding: self.padding },
            ChannelWriter { wh, send: self.send, send_frame_type: self.send_frame_type, padding: self.padding },
        )
    }
}

/// The read half of a split channel (see [`EstablishedChannel::into_split`]).
pub struct ChannelReader<R> {
    rh: R,
    recv: RecvCipher,
    recv_frame_type: u8,
    padding: PaddingPolicy,
}

impl<R: AsyncRead + Unpin> ChannelReader<R> {
    /// Receive and open the next inbound message.
    pub async fn recv<T: BorshDeserialize>(&mut self) -> Result<T, HandshakeError> {
        let frame: EncryptedFrame = read_msg(&mut self.rh).await?;
        if frame.frame_type != self.recv_frame_type {
            return Err(HandshakeError::Malformed(format!("unexpected frame type {:#04x}", frame.frame_type)));
        }
        let opened = self.recv.open(frame.frame_type, frame.seq, &frame.ciphertext)?;
        let plaintext = if self.padding.is_framed() {
            PaddingPolicy::unpad(&opened).map_err(|e| HandshakeError::Malformed(e.to_string()))?
        } else {
            opened
        };
        T::try_from_slice(&plaintext).map_err(|e| HandshakeError::Malformed(e.to_string()))
    }
}

/// The write half of a split channel (see [`EstablishedChannel::into_split`]).
pub struct ChannelWriter<W> {
    wh: W,
    send: SendCipher,
    send_frame_type: u8,
    padding: PaddingPolicy,
}

impl<W: AsyncWrite + Unpin> ChannelWriter<W> {
    /// Seal and transmit one message; returns the record ciphertext.
    pub async fn send<T: BorshSerialize>(&mut self, msg: &T) -> Result<Vec<u8>, HandshakeError> {
        let plaintext = self.padding.pad(&borsh::to_vec(msg).expect("borsh serialization of an in-memory message is infallible"));
        let (seq, ciphertext) = self.send.seal(self.send_frame_type, &plaintext)?;
        write_msg(&mut self.wh, &EncryptedFrame { frame_type: self.send_frame_type, seq, ciphertext: ciphertext.clone() }).await?;
        Ok(ciphertext)
    }
}

// --- establishment ---------------------------------------------------------------------------

/// Requester side (§2.3 steps 3–5). `verify_attestation` receives the raw
/// [`ServerHello`] and must return the canonical quote hash after verifying
/// the bundle — including that its `report_data` equals
/// `key_binding(pk_kem, pk_receipt)` — or reject with a reason.
pub async fn establish_channel<S, F>(mut stream: S, verify_attestation: F) -> Result<EstablishedChannel<S>, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&ServerHello) -> Result<Hash64, String>,
{
    let mut nonce_req = [0u8; SESSION_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_req);
    write_msg(&mut stream, &ClientHello { version: MIL_PROTOCOL_VERSION, nonce_req }).await?;

    let hello: ServerHello = read_msg(&mut stream).await?;
    if hello.version != MIL_PROTOCOL_VERSION {
        return Err(HandshakeError::VersionMismatch(hello.version));
    }
    let quote_hash = verify_attestation(&hello).map_err(HandshakeError::AttestationRejected)?;

    let (kem_ct, shared_secret) = encapsulate(&hello.pk_kem)?;
    write_msg(&mut stream, &ClientKem { kem_ct: kem_ct.to_vec() }).await?;

    let sid = session_id(&quote_hash, &kem_ct, &nonce_req);
    let keys = derive_session_keys(shared_secret, &sid);
    Ok(EstablishedChannel {
        session_id: sid,
        peer_pk_receipt: hello.pk_receipt,
        stream,
        send: SendCipher::new(keys.k_c2p, sid, Direction::ClientToProvider),
        recv: RecvCipher::new(keys.k_p2c, sid, Direction::ProviderToClient),
        send_frame_type: FT_CLIENT,
        recv_frame_type: FT_SERVER,
        padding: PaddingPolicy::None,
    })
}

/// Provider side (§2.3 steps 1–2 counterpart).
pub async fn accept_channel<S>(
    mut stream: S,
    identity: &ProviderIdentity,
    kem: &ProviderKemKeys,
) -> Result<EstablishedChannel<S>, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello: ClientHello = read_msg(&mut stream).await?;
    if hello.version != MIL_PROTOCOL_VERSION {
        return Err(HandshakeError::VersionMismatch(hello.version));
    }
    write_msg(
        &mut stream,
        &ServerHello {
            version: MIL_PROTOCOL_VERSION,
            attestation: identity.attestation.clone(),
            pk_kem: kem.public_key().to_vec(),
            pk_receipt: identity.pk_receipt.clone(),
        },
    )
    .await?;

    let client_kem: ClientKem = read_msg(&mut stream).await?;
    let shared_secret = kem.decapsulate(&client_kem.kem_ct)?;

    let sid = session_id(&identity.quote_hash, &client_kem.kem_ct, &hello.nonce_req);
    let keys = derive_session_keys(shared_secret, &sid);
    Ok(EstablishedChannel {
        session_id: sid,
        peer_pk_receipt: identity.pk_receipt.clone(),
        stream,
        send: SendCipher::new(keys.k_p2c, sid, Direction::ProviderToClient),
        recv: RecvCipher::new(keys.k_c2p, sid, Direction::ClientToProvider),
        send_frame_type: FT_SERVER,
        recv_frame_type: FT_CLIENT,
        padding: PaddingPolicy::None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_mil_core::commit::{TranscriptHasher, request_commitment_for_ct};
    use misaka_mil_core::domains::MIL_PROTOCOL_VERSION as RECEIPT_VERSION;
    use misaka_mil_core::ident::key_binding;
    use misaka_mil_core::job::{SamplingParams, SlaParams, Tier};
    use misaka_mil_core::receipt::{ReceiptBody, ReceiptSigner};

    fn provider_setup() -> (ProviderKemKeys, ReceiptSigner, ProviderIdentity) {
        let kem = ProviderKemKeys::from_seed([1u8; 32]);
        let signer = ReceiptSigner::from_seed([2u8; 32]);
        let attestation = b"dev-bundle".to_vec();
        let quote_hash = kaspa_hashes::blake2b_512_keyed(misaka_mil_core::domains::MIL_QUOTE_DOMAIN, &attestation);
        let identity = ProviderIdentity { attestation, quote_hash, pk_receipt: signer.public_key().to_vec() };
        (kem, signer, identity)
    }

    #[tokio::test]
    async fn full_duplex_session_end_to_end() {
        let (kem, signer, identity) = provider_setup();
        let (client_io, server_io) = tokio::io::duplex(1 << 20);

        let server = tokio::spawn(async move {
            let mut ch = accept_channel(server_io, &identity, &kem).await.expect("accept");
            // strict order: prompt first (sealed first for cm_req), then job
            let ClientMsg::Prompt(prompt) = ch.recv().await.expect("prompt") else { panic!("expected prompt first") };
            let ClientMsg::Job(job) = ch.recv().await.expect("job") else { panic!("expected job second") };
            assert_eq!(job.tier, Tier::Open);

            // echo the prompt back in two chunks with a receipt in between
            let mut transcript = TranscriptHasher::new(&ch.session_id);
            let half = prompt.len() / 2;
            for (k, part) in [&prompt[..half], &prompt[half..]].into_iter().enumerate() {
                transcript.absorb(part);
                ch.send(&ServerMsg::Chunk { text: part.to_vec(), token_count: part.len() as u32 }).await.expect("chunk");
                let receipt = signer.sign(ReceiptBody {
                    version: RECEIPT_VERSION,
                    session_id: ch.session_id,
                    counter: (k + 1) as u64,
                    cum_tokens_in: 10,
                    cum_tokens_out: (half * (k + 1)) as u64,
                    timestamp_ms: 1 + k as u64,
                    cm_resp: transcript.commitment(),
                    is_final: k == 1,
                });
                ch.send(&ServerMsg::Receipt(receipt)).await.expect("receipt");
            }
            ch.send(&ServerMsg::Done { total_tokens_out: prompt.len() as u64 }).await.expect("done");
        });

        let mut ch = establish_channel(client_io, |hello: &ServerHello| {
            // v0 dev verification: recompute the quote hash; a real verifier also
            // checks report_data == key_binding(pk_kem, pk_receipt)
            let _ = key_binding(&hello.pk_kem, &hello.pk_receipt);
            Ok(kaspa_hashes::blake2b_512_keyed(misaka_mil_core::domains::MIL_QUOTE_DOMAIN, &hello.attestation))
        })
        .await
        .expect("establish");

        // prompt sealed first so cm_req commits to its ciphertext
        let prompt = b"MIL says hello over the PQ channel".to_vec();
        let prompt_ct = ch.send(&ClientMsg::Prompt(prompt.clone())).await.expect("send prompt");
        let salt = [7u8; 32];
        let cm_req = request_commitment_for_ct(&salt, &prompt_ct);
        let job = JobSpec::new(
            Hash64::from_bytes([1u8; 64]),
            Tier::Open,
            256,
            SamplingParams::greedy(),
            SlaParams { ttfb_ms: 1500, min_tps: 1 },
            1_000_000,
            cm_req,
        );
        ch.send(&ClientMsg::Job(job)).await.expect("send job");

        // consume the stream, verifying transcript + receipts
        let mut transcript = TranscriptHasher::new(&ch.session_id);
        let mut chain = misaka_mil_core::receipt::ReceiptChainVerifier::new(ch.session_id, ch.peer_pk_receipt.clone());
        let mut collected = Vec::new();
        loop {
            match ch.recv().await.expect("server msg") {
                ServerMsg::Chunk { text, .. } => {
                    transcript.absorb(&text);
                    collected.extend_from_slice(&text);
                }
                ServerMsg::Receipt(r) => {
                    assert_eq!(r.body.cm_resp, transcript.commitment(), "receipt transcript must match what we received");
                    chain.ingest(&r).expect("receipt chain");
                }
                ServerMsg::Done { total_tokens_out } => {
                    assert_eq!(total_tokens_out, prompt.len() as u64);
                    break;
                }
                ServerMsg::Error(e) => panic!("server error: {e}"),
            }
        }
        assert_eq!(collected, prompt, "echo backend must return the prompt");
        assert!(chain.is_finalized());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cell_padding_round_trips_over_the_channel() {
        use misaka_mil_core::padding::PaddingPolicy;
        let (kem, _signer, identity) = provider_setup();
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let mut ch = accept_channel(server_io, &identity, &kem).await.unwrap().with_padding(PaddingPolicy::Cell(256));
            // echo whatever prompt arrives, padded
            let ClientMsg::Prompt(p) = ch.recv().await.unwrap() else { panic!("prompt") };
            ch.send(&ServerMsg::Chunk { text: p, token_count: 1 }).await.unwrap();
            ch.send(&ServerMsg::Done { total_tokens_out: 1 }).await.unwrap();
        });
        let mut ch = establish_channel(client_io, |hello: &ServerHello| {
            Ok(kaspa_hashes::blake2b_512_keyed(misaka_mil_core::domains::MIL_QUOTE_DOMAIN, &hello.attestation))
        })
        .await
        .unwrap()
        .with_padding(PaddingPolicy::Cell(256));
        // a short and a long message both work through the padded channel
        ch.send(&ClientMsg::Prompt(b"padded prompt of some length".to_vec())).await.unwrap();
        let ServerMsg::Chunk { text, .. } = ch.recv().await.unwrap() else { panic!("chunk") };
        assert_eq!(text, b"padded prompt of some length");
        let ServerMsg::Done { .. } = ch.recv().await.unwrap() else { panic!("done") };
        server.await.unwrap();
    }

    #[tokio::test]
    async fn attestation_rejection_aborts_before_any_key_material_flows() {
        let (kem, _signer, identity) = provider_setup();
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let server = tokio::spawn(async move {
            // provider side will fail once the client hangs up
            let _ = accept_channel(server_io, &identity, &kem).await;
        });
        let err = establish_channel(client_io, |_hello: &ServerHello| Err("measurement mismatch".to_string())).await;
        match err {
            Err(HandshakeError::AttestationRejected(reason)) => assert_eq!(reason, "measurement mismatch"),
            Err(other) => panic!("expected AttestationRejected, got {other:?}"),
            Ok(_) => panic!("expected AttestationRejected, got an established channel"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn version_mismatch_is_rejected() {
        let (mut a, b) = tokio::io::duplex(1 << 16);
        let (kem, _signer, identity) = provider_setup();
        let server = tokio::spawn(async move { accept_channel(b, &identity, &kem).await });
        write_msg(&mut a, &ClientHello { version: 999, nonce_req: [0u8; SESSION_NONCE_LEN] }).await.unwrap();
        match server.await.unwrap() {
            Err(HandshakeError::VersionMismatch(999)) => {}
            other => panic!("expected VersionMismatch, got {:?}", other.err()),
        }
    }
}
