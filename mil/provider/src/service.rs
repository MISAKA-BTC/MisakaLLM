//! The data-plane inference service (design §2.3 steps 6–8, §5.6, §13.5, §14.4).
//!
//! One TCP connection = one MIL session. After the PQ handshake the channel is
//! split into independent read/write halves so the provider can stream the
//! response **while concurrently watching for an inbound `Cancel`** (§14.4):
//! a cancel stops decoding and settles on the exact cumulative counts, with no
//! over-charge from the 512-token interval.
//!
//! [`serve_session`] serves a single prompt turn (with live cancel).
//! [`serve_sticky_session`] keeps the same session/enclave across multiple
//! turns (§13.5): the cumulative receipt counters and transcript carry across
//! turns, so a real KV-cache-retaining backend only re-prefills the new turn;
//! only the last receipt of the session is `is_final`.
//!
//! The backend is injected, so the same driver serves the mock, a Tier-1 vLLM
//! enclave, or a Tier-2 llama.cpp process.

use crate::backend::InferenceBackend;
use crate::config::ProviderContext;
use kaspa_hashes::Hash64;
use misaka_mil_channel::HandshakeError;
use misaka_mil_channel::wire::{ChannelReader, ChannelWriter, ClientMsg, ProviderIdentity, ServerMsg, accept_channel};
use misaka_mil_core::commit::TranscriptHasher;
use misaka_mil_core::domains::MIL_PROTOCOL_VERSION;
use misaka_mil_core::params::RECEIPT_INTERVAL_OUTPUT_TOKENS;
use misaka_mil_core::receipt::{ReceiptBody, SignedReceipt};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// Current unix time in milliseconds (wall clock; receipts only need per-session
/// monotonicity, which sequential sends preserve).
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// What one served session produced — enough to anchor and bill (§8.1).
#[derive(Debug, Clone)]
pub struct SessionOutcome {
    pub session_id: Hash64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    /// Number of prompt turns served in this session (≥ 1).
    pub turns: u32,
    /// Whether the session ended on a client `Cancel`.
    pub cancelled: bool,
    /// The final cumulative receipt (the single settlement receipt, §4.1).
    pub final_receipt: SignedReceipt,
}

/// Session-level failures.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("handshake failed: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("backend error: {0}")]
    Backend(String),
    #[error("job requested model {requested} but this provider serves {served}")]
    WrongModel { requested: Hash64, served: Hash64 },
    #[error("client closed the session before sending a prompt")]
    NoPrompt,
}

/// Build the provider identity presented in the handshake, with a fresh dev
/// attestation bundle (issued now, so its freshness window is open).
pub fn provider_identity(ctx: &ProviderContext) -> ProviderIdentity {
    let bundle = ctx.dev_attestation_bundle(now_ms());
    ProviderIdentity { attestation: bundle.encode(), quote_hash: bundle.quote_hash(), pk_receipt: ctx.pk_receipt().to_vec() }
}

/// Running cumulative state of a session (carries across sticky turns).
struct SessionState {
    session_id: Hash64,
    transcript: TranscriptHasher,
    cum_in: u64,
    cum_out: u64,
    last_receipt_out: u64,
    counter: u64,
    turns: u32,
    last_receipt: Option<SignedReceipt>,
}

impl SessionState {
    fn new(session_id: Hash64) -> Self {
        Self {
            session_id,
            transcript: TranscriptHasher::new(&session_id),
            cum_in: 0,
            cum_out: 0,
            last_receipt_out: 0,
            counter: 0,
            turns: 0,
            last_receipt: None,
        }
    }

    fn sign(&mut self, ctx: &ProviderContext, is_final: bool) -> SignedReceipt {
        self.counter += 1;
        let r = ctx.receipt_signer.sign(ReceiptBody {
            version: MIL_PROTOCOL_VERSION,
            session_id: self.session_id,
            counter: self.counter,
            cum_tokens_in: self.cum_in,
            cum_tokens_out: self.cum_out,
            timestamp_ms: now_ms(),
            cm_resp: self.transcript.commitment(),
            is_final,
        });
        self.last_receipt = Some(r.clone());
        r
    }
}

/// Spawn a reader task forwarding decoded `ClientMsg`s over an mpsc channel.
/// Whole-frame reads make it cancel-safe (a partial read is never dropped), so
/// the main loop can watch for a `Cancel` without desyncing the record stream.
fn spawn_reader<R>(mut reader: ChannelReader<R>) -> mpsc::Receiver<ClientMsg>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<ClientMsg>(8);
    tokio::spawn(async move {
        while let Ok(msg) = reader.recv::<ClientMsg>().await {
            if tx.send(msg).await.is_err() {
                break;
            }
        }
    });
    rx
}

/// Stream one turn's response, updating cumulative `state`, emitting a receipt
/// every interval, and stopping early if a `Cancel` arrives on `rx` (§14.4).
/// Returns `true` if the turn was cancelled.
async fn stream_turn<W>(
    writer: &mut ChannelWriter<W>,
    rx: &mut mpsc::Receiver<ClientMsg>,
    ctx: &ProviderContext,
    output: crate::backend::InferenceOutput,
    state: &mut SessionState,
) -> Result<bool, SessionError>
where
    W: AsyncWrite + Unpin,
{
    state.cum_in += output.tokens_in;
    let mut cancelled = false;
    for chunk in &output.chunks {
        // Yield so the concurrent reader task can surface an inbound Cancel, then
        // check it. A cancel takes effect at the next chunk boundary — never
        // mid-frame (dropping a write would corrupt the stream).
        tokio::task::yield_now().await;
        if let Ok(ClientMsg::Cancel) = rx.try_recv() {
            cancelled = true;
            break;
        }
        writer.send(&ServerMsg::Chunk { text: chunk.text.clone(), token_count: chunk.token_count }).await?;
        state.transcript.absorb(&chunk.text);
        state.cum_out += chunk.token_count as u64;
        if state.cum_out - state.last_receipt_out >= RECEIPT_INTERVAL_OUTPUT_TOKENS {
            let receipt = state.sign(ctx, false);
            writer.send(&ServerMsg::Receipt(receipt)).await?;
            state.last_receipt_out = state.cum_out;
        }
    }
    Ok(cancelled)
}

/// Receive the prompt then the job for a turn from the reader channel, applying
/// the tier policy and checking the served model.
async fn recv_prompt_and_job(
    rx: &mut mpsc::Receiver<ClientMsg>,
    ctx: &ProviderContext,
) -> Result<Option<(Vec<u8>, misaka_mil_core::job::JobSpec)>, SessionError> {
    let prompt = match rx.recv().await {
        Some(ClientMsg::Prompt(p)) => p,
        Some(ClientMsg::Cancel) | None => return Ok(None), // clean end of session
        Some(ClientMsg::Job(_)) => return Err(SessionError::Protocol("received job before prompt".into())),
    };
    let job = match rx.recv().await {
        Some(ClientMsg::Job(j)) => j.enforce_tier_policy(),
        Some(ClientMsg::Cancel) | None => return Err(SessionError::Protocol("session ended before the job".into())),
        Some(ClientMsg::Prompt(_)) => return Err(SessionError::Protocol("received a second prompt, expected the job".into())),
    };
    if job.model_id != ctx.serving.model_id {
        return Err(SessionError::WrongModel { requested: job.model_id, served: ctx.serving.model_id });
    }
    Ok(Some((prompt, job)))
}

/// Serve a single prompt turn with live cancel (§14.4). Consumes the stream.
pub async fn serve_session<S, B>(stream: S, ctx: Arc<ProviderContext>, backend: Arc<B>) -> Result<SessionOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: InferenceBackend + ?Sized,
{
    serve_inner(stream, ctx, backend, 1, Duration::from_secs(0)).await
}

/// Serve a sticky multi-turn session (§13.5): the same session/enclave across up
/// to `max_turns` prompts, each within `turn_ttl` of the previous. Cumulative
/// counters + transcript carry across turns; only the final receipt is
/// `is_final`.
pub async fn serve_sticky_session<S, B>(
    stream: S,
    ctx: Arc<ProviderContext>,
    backend: Arc<B>,
    max_turns: u32,
    turn_ttl: Duration,
) -> Result<SessionOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: InferenceBackend + ?Sized,
{
    serve_inner(stream, ctx, backend, max_turns.max(1), turn_ttl).await
}

async fn serve_inner<S, B>(
    stream: S,
    ctx: Arc<ProviderContext>,
    backend: Arc<B>,
    max_turns: u32,
    turn_ttl: Duration,
) -> Result<SessionOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: InferenceBackend + ?Sized,
{
    let identity = provider_identity(&ctx);
    let ch = accept_channel(stream, &identity, &ctx.kem).await?.with_padding(ctx.serving.padding());
    let session_id = ch.session_id;
    let (reader, mut writer) = ch.into_split();
    let mut rx = spawn_reader(reader);
    let mut state = SessionState::new(session_id);
    let mut cancelled = false;
    let mut final_receipt: Option<SignedReceipt> = None;

    while state.turns < max_turns {
        // Await the next prompt. On the first turn we block; on later turns the
        // sticky TTL (§10 sticky_session_ttl) bounds how long we hold the enclave.
        let next = if state.turns == 0 || turn_ttl.is_zero() {
            recv_prompt_and_job(&mut rx, &ctx).await?
        } else {
            match tokio::time::timeout(turn_ttl, recv_prompt_and_job(&mut rx, &ctx)).await {
                Ok(res) => res?,
                Err(_) => None, // sticky TTL elapsed with no new turn → drain the session
            }
        };
        let Some((prompt, job)) = next else { break };

        let output = backend.infer(&prompt, &job).await.map_err(SessionError::Backend)?;
        cancelled = stream_turn(&mut writer, &mut rx, &ctx, output, &mut state).await?;
        state.turns += 1;

        // Settle each turn with a receipt + Done so the client can bill/continue.
        // The receipt is `is_final` iff this is the session's last turn (turn cap
        // reached or a cancel) — that final receipt is sent BEFORE its Done so a
        // single-turn client (which breaks on Done) still receives it (§14.4).
        let is_final = cancelled || state.turns == max_turns;
        let receipt = state.sign(&ctx, is_final);
        writer.send(&ServerMsg::Receipt(receipt.clone())).await?;
        writer.send(&ServerMsg::Done { total_tokens_out: state.cum_out }).await?;
        state.last_receipt_out = state.cum_out;
        if is_final {
            final_receipt = Some(receipt);
            break;
        }
    }

    if state.turns == 0 {
        return Err(SessionError::NoPrompt);
    }

    // If the client closed early (drained sticky session without hitting the cap),
    // sign the settlement receipt on the exact cumulative counts. Best-effort
    // transmit — the provider keeps it for the on-chain claim regardless.
    let final_receipt = match final_receipt {
        Some(r) => r,
        None => {
            let r = state.sign(&ctx, true);
            let _ = writer.send(&ServerMsg::Receipt(r.clone())).await;
            r
        }
    };

    Ok(SessionOutcome { session_id, tokens_in: state.cum_in, tokens_out: state.cum_out, turns: state.turns, cancelled, final_receipt })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{InferenceBackend, InferenceOutput, MockBackend, ResponseChunk};
    use crate::config::{ProviderContext, ServingConfig};
    use async_trait::async_trait;
    use misaka_mil_channel::wire::{ClientMsg, establish_channel};
    use misaka_mil_core::job::{JobSpec, SamplingParams, SlaParams, Tier};

    fn ctx() -> Arc<ProviderContext> {
        let serving = ServingConfig {
            model_id: Hash64::from_bytes([1u8; 64]),
            runtime_image_hash: Hash64::from_bytes([2u8; 64]),
            model_manifest_hash: Hash64::from_bytes([3u8; 64]),
            tier: Tier::Open,
            gpu_class_weight: 1,
            ask_in_per_1k_sompi: 100_000,
            ask_out_per_1k_sompi: 500_000,
            sla: SlaParams { ttfb_ms: 1500, min_tps: 1 },
            region: "test".into(),
            data_plane_addr: "127.0.0.1:0".into(),
            hot: true,
            padding_cell: None,
        };
        Arc::new(ProviderContext::from_seed([42u8; 32], serving))
    }

    fn job(cm_req: Hash64) -> JobSpec {
        JobSpec::new(
            Hash64::from_bytes([1u8; 64]),
            Tier::Open,
            4096,
            SamplingParams::greedy(),
            SlaParams { ttfb_ms: 1500, min_tps: 1 },
            10_000_000,
            cm_req,
        )
    }

    /// A backend that emits many small chunks so a cancel lands mid-stream.
    struct SlowManyChunks;
    #[async_trait]
    impl InferenceBackend for SlowManyChunks {
        fn name(&self) -> &str {
            "slow"
        }
        async fn infer(&self, _prompt: &[u8], _job: &JobSpec) -> Result<InferenceOutput, String> {
            let chunks = (0..200).map(|i| ResponseChunk { text: format!("tok{i} ").into_bytes(), token_count: 1 }).collect();
            Ok(InferenceOutput { chunks, tokens_in: 5 })
        }
    }

    #[tokio::test]
    async fn single_turn_still_works() {
        let ctx = ctx();
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn({
            let ctx = ctx.clone();
            async move { serve_session(server_io, ctx, Arc::new(MockBackend::new(4))).await }
        });
        let mut client = crate::client::RequesterClient::connect(client_io, crate::client::dev_attestation_verifier()).await.unwrap();
        let result = client.run_prompt(b"hello sticky world over many chunks", job, [7u8; 32]).await.unwrap();
        assert!(result.final_receipt.body.is_final);
        let outcome = server.await.unwrap().unwrap();
        assert_eq!(outcome.turns, 1);
        assert!(!outcome.cancelled);
    }

    #[tokio::test]
    async fn live_cancel_settles_partial() {
        let ctx = ctx();
        // Small buffer → the provider blocks on backpressure, so the client's
        // mid-stream Cancel lands before all chunks are written.
        let (client_io, server_io) = tokio::io::duplex(1024);
        let server = tokio::spawn({
            let ctx = ctx.clone();
            async move { serve_session(server_io, ctx, Arc::new(SlowManyChunks)).await }
        });

        // Drive the raw channel so we can send a Cancel mid-stream.
        let mut ch = establish_channel(client_io, crate::client::dev_attestation_verifier()).await.unwrap();
        let prompt_ct = ch.send(&ClientMsg::Prompt(b"cancel me".to_vec())).await.unwrap();
        let cm_req = misaka_mil_core::commit::request_commitment_for_ct(&[7u8; 32], &prompt_ct);
        ch.send(&ClientMsg::Job(job(cm_req))).await.unwrap();

        // read a few chunks, then cancel
        let mut chunks_seen = 0;
        loop {
            match ch.recv::<ServerMsg>().await.unwrap() {
                ServerMsg::Chunk { .. } => {
                    chunks_seen += 1;
                    if chunks_seen == 5 {
                        ch.send(&ClientMsg::Cancel).await.unwrap();
                    }
                }
                ServerMsg::Receipt(_) => {}
                ServerMsg::Done { .. } => break,
                ServerMsg::Error(e) => panic!("{e}"),
            }
        }
        let outcome = server.await.unwrap().unwrap();
        assert!(outcome.cancelled, "session must record the cancel");
        assert!(outcome.tokens_out < 200, "cancel settled fewer than all tokens: {}", outcome.tokens_out);
        assert!(outcome.final_receipt.body.is_final);
        assert_eq!(outcome.final_receipt.body.cum_tokens_out, outcome.tokens_out, "final receipt bills exact partial count");
    }

    #[tokio::test]
    async fn sticky_multi_turn_accumulates() {
        let ctx = ctx();
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn({
            let ctx = ctx.clone();
            async move { serve_sticky_session(server_io, ctx, Arc::new(MockBackend::new(8)), 3, Duration::from_secs(5)).await }
        });

        let mut ch = establish_channel(client_io, crate::client::dev_attestation_verifier()).await.unwrap();
        let model = Hash64::from_bytes([1u8; 64]);
        let mut prev_cum = 0u64;
        for turn in 0..3 {
            let pct = ch.send(&ClientMsg::Prompt(format!("turn {turn} prompt text here").into_bytes())).await.unwrap();
            let cm = misaka_mil_core::commit::request_commitment_for_ct(&[turn as u8; 32], &pct);
            ch.send(&ClientMsg::Job(job_for(model, cm))).await.unwrap();
            // drain until this turn's Done
            loop {
                match ch.recv::<ServerMsg>().await.unwrap() {
                    ServerMsg::Chunk { .. } | ServerMsg::Receipt(_) => {}
                    ServerMsg::Done { total_tokens_out } => {
                        assert!(total_tokens_out >= prev_cum, "cumulative across turns");
                        prev_cum = total_tokens_out;
                        break;
                    }
                    ServerMsg::Error(e) => panic!("{e}"),
                }
            }
        }
        drop(ch); // close → server drains and emits the final receipt
        let outcome = server.await.unwrap().unwrap();
        assert_eq!(outcome.turns, 3);
        assert!(outcome.final_receipt.body.is_final);
        assert!(outcome.tokens_out > 0);
        assert!(outcome.tokens_in >= 3, "each turn added its input tokens");
    }

    fn job_for(model: Hash64, cm_req: Hash64) -> JobSpec {
        JobSpec::new(model, Tier::Open, 4096, SamplingParams::greedy(), SlaParams { ttfb_ms: 1500, min_tps: 1 }, 10_000_000, cm_req)
    }

    #[tokio::test]
    async fn wrong_model_is_rejected() {
        let ctx = ctx();
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let server = tokio::spawn(async move { serve_session(server_io, ctx, Arc::new(MockBackend::default())).await });
        let mut ch = establish_channel(client_io, crate::client::dev_attestation_verifier()).await.unwrap();
        let pct = ch.send(&ClientMsg::Prompt(b"hi".to_vec())).await.unwrap();
        let cm = misaka_mil_core::commit::request_commitment_for_ct(&[1u8; 32], &pct);
        ch.send(&ClientMsg::Job(job_for(Hash64::from_bytes([0xAAu8; 64]), cm))).await.unwrap();
        match server.await.unwrap() {
            Err(SessionError::WrongModel { .. }) => {}
            other => panic!("expected WrongModel, got {other:?}"),
        }
    }
}
