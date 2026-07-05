//! Requester-side client (design §2.3 steps 3–8, §14.2).
//!
//! A thin reference SDK: establish the PQ channel (verifying attestation),
//! send the prompt then the job (so `cm_req` commits to the actual prompt
//! ciphertext), collect the streamed response, and validate every receipt
//! against the running transcript and the monotonic receipt chain. This is
//! the trust terminus — the plaintext lives here and nowhere else on the
//! provider side (§15.1).

use kaspa_hashes::Hash64;
use misaka_mil_attest::bundle::AttestationBundle;
use misaka_mil_attest::verify::{ExpectedMeasurements, QuoteVerifier};
use misaka_mil_channel::HandshakeError;
use misaka_mil_channel::wire::{ClientMsg, EstablishedChannel, ServerHello, ServerMsg, establish_channel};
use misaka_mil_core::commit::{REQUEST_SALT_LEN, TranscriptHasher, request_commitment_for_ct};
use misaka_mil_core::ident::key_binding;
use misaka_mil_core::job::JobSpec;
use misaka_mil_core::receipt::{ReceiptChainVerifier, ReceiptError, SignedReceipt};
use tokio::io::{AsyncRead, AsyncWrite};

/// The result of one prompt turn.
#[derive(Debug, Clone)]
pub struct PromptResult {
    pub session_id: Hash64,
    /// Decoded plaintext response (lossy UTF-8).
    pub response_text: String,
    /// All receipts received, in order (already chain-verified).
    pub receipts: Vec<SignedReceipt>,
    /// The final settlement receipt.
    pub final_receipt: SignedReceipt,
}

/// Client-side failures.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("handshake failed: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("provider reported an error: {0}")]
    ProviderError(String),
    #[error("receipt validation failed: {0}")]
    Receipt(#[from] ReceiptError),
    #[error("a receipt's transcript commitment does not match the response bytes received")]
    TranscriptMismatch,
    #[error("stream ended without a final receipt")]
    NoFinalReceipt,
}

/// An established requester session.
pub struct RequesterClient<S> {
    channel: EstablishedChannel<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> RequesterClient<S> {
    /// Establish a session, verifying the provider attestation via `verify`.
    /// `verify` returns the canonical quote hash on success (see
    /// [`dev_attestation_verifier`] / [`pinned_attestation_verifier`]).
    pub async fn connect<F>(stream: S, verify: F) -> Result<Self, ClientError>
    where
        F: FnOnce(&ServerHello) -> Result<Hash64, String>,
    {
        let channel = establish_channel(stream, verify).await?;
        Ok(Self { channel })
    }

    /// The negotiated session id.
    pub fn session_id(&self) -> Hash64 {
        self.channel.session_id
    }

    /// Send one prompt and drive the response to completion.
    ///
    /// `make_job` receives the `cm_req` computed from the salted prompt
    /// ciphertext and returns the [`JobSpec`] to submit; `salt` is the
    /// per-request commitment salt (fresh random in production, §3.3).
    pub async fn run_prompt<F>(
        &mut self,
        prompt: &[u8],
        make_job: F,
        salt: [u8; REQUEST_SALT_LEN],
    ) -> Result<PromptResult, ClientError>
    where
        F: FnOnce(Hash64) -> JobSpec,
    {
        // prompt first: its record ciphertext is what cm_req commits to
        let prompt_ct = self.channel.send(&ClientMsg::Prompt(prompt.to_vec())).await?;
        let cm_req = request_commitment_for_ct(&salt, &prompt_ct);
        let job = make_job(cm_req).enforce_tier_policy();
        self.channel.send(&ClientMsg::Job(job)).await?;

        let session_id = self.channel.session_id;
        let peer_pk = self.channel.peer_pk_receipt.clone();
        let mut transcript = TranscriptHasher::new(&session_id);
        let mut chain = ReceiptChainVerifier::new(session_id, peer_pk);
        let mut response = Vec::new();
        let mut receipts = Vec::new();

        loop {
            match self.channel.recv::<ServerMsg>().await? {
                ServerMsg::Chunk { text, .. } => {
                    transcript.absorb(&text);
                    response.extend_from_slice(&text);
                }
                ServerMsg::Receipt(receipt) => {
                    if receipt.body.cm_resp != transcript.commitment() {
                        return Err(ClientError::TranscriptMismatch);
                    }
                    chain.ingest(&receipt)?;
                    receipts.push(receipt);
                }
                ServerMsg::Done { .. } => break,
                ServerMsg::Error(e) => return Err(ClientError::ProviderError(e)),
            }
        }

        let final_receipt = receipts.iter().rev().find(|r| r.body.is_final).cloned().ok_or(ClientError::NoFinalReceipt)?;

        Ok(PromptResult { session_id, response_text: String::from_utf8_lossy(&response).into_owned(), receipts, final_receipt })
    }
}

/// Development attestation verifier (loopback / Tier-2): decodes the bundle,
/// enforces that its `report_data` binds exactly the presented enclave keys
/// (the anti-MITM check that holds even without hardware), and returns the
/// canonical quote hash. Trust otherwise rests on the permissioned whitelist
/// (§8.1) — do NOT use this for Tier-1 production.
pub fn dev_attestation_verifier() -> impl FnOnce(&ServerHello) -> Result<Hash64, String> {
    |hello: &ServerHello| {
        let bundle = AttestationBundle::decode(&hello.attestation).map_err(|e| format!("malformed attestation bundle: {e}"))?;
        if bundle.report_data != key_binding(&hello.pk_kem, &hello.pk_receipt) {
            return Err("attestation report_data does not bind the presented keys".to_string());
        }
        Ok(bundle.quote_hash())
    }
}

/// Production attestation verifier: runs a full [`QuoteVerifier`] against
/// registry-pinned [`ExpectedMeasurements`], then returns the verified quote
/// hash. `now_ms` is the caller's clock (freshness window).
pub fn pinned_attestation_verifier<V: QuoteVerifier>(
    verifier: V,
    expected: ExpectedMeasurements,
    now_ms: u64,
) -> impl FnOnce(&ServerHello) -> Result<Hash64, String> {
    move |hello: &ServerHello| {
        verifier
            .verify(&hello.attestation, &hello.pk_kem, &hello.pk_receipt, &expected, now_ms)
            .map(|v| v.quote_hash)
            .map_err(|e| e.to_string())
    }
}
