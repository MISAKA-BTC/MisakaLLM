//! ANONYMOUS (which-provider-unlinkable) serving path — the H-04 remediation of
//! ADR-0037 §3 (#2 blind handshake, #3 receipt without provider naming).
//!
//! The live v0 [`crate::service`] lane is deliberately **named**: it presents the
//! provider's long-term `pk_receipt` in the handshake, signs every session with
//! one long-term [`ReceiptSigner`], and ships `provider_pk` inside each
//! [`misaka_mil_core::receipt::SignedReceipt`]. Those three artifacts let a
//! requester/relay/receipt-log link many sessions to one provider (audit H-04).
//!
//! This module is the **separate, INERT** anonymous lane that removes all three:
//!
//! - **No long-term key in the handshake.** [`serve_session_anon`] uses
//!   [`accept_channel_anon`] with an [`AnonServerHello`](misaka_mil_channel::wire::AnonServerHello):
//!   no `pk_receipt`, and an *ephemeral* per-session ML-KEM key, so nothing
//!   provider-stable transits. The session id is `session_id_anon` (no `quote_hash`).
//! - **Per-session signing key.** Each session is signed with
//!   [`ReceiptSigner::from_session_key`], derived from `session_rk =
//!   session_receipt_key(claim_secret, session_cm)` — a fresh key per session.
//! - **Provider-non-naming receipt.** It emits
//!   [`AnonSignedReceipt`](misaka_mil_core::receipt::AnonSignedReceipt): body +
//!   signature only, no `provider_pk`. The requester verifies against the
//!   handshake `session_pk`.
//!
//! ## What this enforces now vs. what still needs building
//!
//! Enforced now (off-circuit): a requester/relay/receipt-log observing this lane
//! sees no long-term provider key at any of the three points — receipts and the
//! handshake name a session, not a provider, and two sessions of one provider are
//! cryptographically unlinkable by key material.
//!
//! Still required for the FULL anonymous-credential flow (out of session):
//! 1. **In-circuit binding (C-P6 / B1).** A ZK proof that the per-session key was
//!    derived from the `claim_secret` behind the provider's *registered leaf*, so
//!    the receipt binds to the anonymity set. Until then the requester has no
//!    proof the session key belongs to a real provider.
//! 2. **Blind attestation (§3 #2).** A membership-proof attestation replacing the
//!    named quote, so the requester gets provider assurance without a name. Here
//!    the attestation is left empty; the reference membership primitive lives in
//!    `mil-shield` (`blind_handshake_proves_membership_without_naming_provider`).
//! 3. **`claim_secret` plumbing.** The provider must reach `claim_secret` (config/
//!    keyfile) to derive the real `session_rk`; today this API takes `session_rk`
//!    as an argument (the caller supplies it).
//!
//! Nothing here is wired into `main.rs`; it changes no live behavior and is
//! fail-closed. It exists so the anonymous receipt/handshake contract is real,
//! composable, and tested ahead of C-P6/B1 activation.

use crate::backend::InferenceBackend;
use crate::config::ProviderContext;
use crate::service::{SessionError, now_ms};
use kaspa_hashes::Hash64;
use misaka_mil_channel::kem::ProviderKemKeys;
use misaka_mil_channel::wire::{AnonServerMsg, ClientMsg, ProviderIdentityAnon, accept_channel_anon};
use misaka_mil_core::commit::TranscriptHasher;
use misaka_mil_core::domains::MIL_PROTOCOL_VERSION;
use misaka_mil_core::params::RECEIPT_INTERVAL_OUTPUT_TOKENS;
use misaka_mil_core::receipt::{AnonSignedReceipt, ReceiptBody, ReceiptSigner};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// What one anonymously-served session produced. Mirrors
/// [`crate::service::SessionOutcome`] but the settlement receipt is an
/// [`AnonSignedReceipt`] and the verification key is the per-session `session_pk`.
#[derive(Debug, Clone)]
pub struct AnonSessionOutcome {
    pub session_id: Hash64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    /// The single final cumulative anonymous receipt (§4.1).
    pub final_receipt: AnonSignedReceipt,
    /// The per-session ML-DSA-87 verification key the receipts are signed under
    /// (fresh per session, provider-non-naming). Equals the handshake `session_pk`.
    pub session_pk: Vec<u8>,
}

/// Build the provider identity presented in the ANONYMOUS handshake for a session
/// whose per-session signing key has verification key `session_pk`. The
/// attestation is left empty: a blind membership-proof attestation (ADR-0037 §3
/// #2) is the pending piece — see the module doc.
pub fn provider_identity_anon(session_pk: Vec<u8>) -> ProviderIdentityAnon {
    ProviderIdentityAnon { attestation: Vec::new(), session_pk }
}

/// Serve a single prompt turn on the ANONYMOUS lane (ADR-0037 §3). `session_rk`
/// is the per-session receipt key `session_receipt_key(claim_secret, session_cm)`
/// (an opaque 64-byte value the caller derives — see the module doc's plumbing
/// note); the session is signed under `ReceiptSigner::from_session_key(session_rk)`
/// and settled with [`AnonSignedReceipt`]s that carry no `provider_pk`.
///
/// Only `ctx.serving` (model id + padding policy) is used from `ctx`; the KEM
/// keypair is minted **ephemerally** per session, so neither the long-term
/// `pk_receipt` nor the registered `pk_kem` transits. INERT: not called by the
/// live sidecar.
pub async fn serve_session_anon<S, B>(
    stream: S,
    ctx: Arc<ProviderContext>,
    backend: Arc<B>,
    session_rk: Hash64,
) -> Result<AnonSessionOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: InferenceBackend + ?Sized,
{
    // Per-session signer + its verification key (the only ML-DSA-87 key that
    // exists on this lane — fresh per session, never the long-term one).
    let signer = ReceiptSigner::from_session_key(session_rk);
    let session_pk = signer.public_key().to_vec();

    // Ephemeral per-session KEM keypair: nothing provider-stable on the wire.
    let kem = ProviderKemKeys::generate();
    let identity = provider_identity_anon(session_pk.clone());
    let mut ch = accept_channel_anon(stream, &identity, &kem).await?.with_padding(ctx.serving.padding());
    let session_id = ch.session_id;

    // Strict record order: the prompt frame is sealed first (so `cm_req` commits
    // to its ciphertext), then the job.
    let prompt = match ch.recv::<ClientMsg>().await? {
        ClientMsg::Prompt(p) => p,
        ClientMsg::Cancel => return Err(SessionError::NoPrompt),
        ClientMsg::Job(_) => return Err(SessionError::Protocol("received job before prompt".into())),
    };
    let job = match ch.recv::<ClientMsg>().await? {
        ClientMsg::Job(j) => j.enforce_tier_policy(),
        ClientMsg::Cancel | ClientMsg::Prompt(_) => {
            return Err(SessionError::Protocol("expected the job after the prompt".into()));
        }
    };
    if job.model_id != ctx.serving.model_id {
        return Err(SessionError::WrongModel { requested: job.model_id, served: ctx.serving.model_id });
    }

    let output = backend.infer(&prompt, &job).await.map_err(SessionError::Backend)?;

    let mut transcript = TranscriptHasher::new(&session_id);
    let mut cum_out: u64 = 0;
    let mut last_receipt_out: u64 = 0;
    let mut counter: u64 = 0;
    for chunk in &output.chunks {
        ch.send(&AnonServerMsg::Chunk { text: chunk.text.clone(), token_count: chunk.token_count }).await?;
        transcript.absorb(&chunk.text);
        cum_out += chunk.token_count as u64;
        if cum_out - last_receipt_out >= RECEIPT_INTERVAL_OUTPUT_TOKENS {
            counter += 1;
            let r = sign_anon_receipt(&signer, session_id, counter, output.tokens_in, cum_out, transcript.commitment(), false);
            ch.send(&AnonServerMsg::Receipt(r)).await?;
            last_receipt_out = cum_out;
        }
    }

    // Final settlement receipt on the exact cumulative counts, sent before Done so
    // a single-turn requester (which breaks on Done) still receives it (§14.4).
    counter += 1;
    let final_receipt = sign_anon_receipt(&signer, session_id, counter, output.tokens_in, cum_out, transcript.commitment(), true);
    ch.send(&AnonServerMsg::Receipt(final_receipt.clone())).await?;
    ch.send(&AnonServerMsg::Done { total_tokens_out: cum_out }).await?;

    Ok(AnonSessionOutcome { session_id, tokens_in: output.tokens_in, tokens_out: cum_out, final_receipt, session_pk })
}

/// Build + sign one anonymous cumulative receipt under the per-session signer.
fn sign_anon_receipt(
    signer: &ReceiptSigner,
    session_id: Hash64,
    counter: u64,
    cum_in: u64,
    cum_out: u64,
    cm_resp: Hash64,
    is_final: bool,
) -> AnonSignedReceipt {
    signer.sign_anon(ReceiptBody {
        version: MIL_PROTOCOL_VERSION,
        session_id,
        counter,
        cum_tokens_in: cum_in,
        cum_tokens_out: cum_out,
        timestamp_ms: now_ms(),
        cm_resp,
        is_final,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use crate::config::{ProviderContext, ServingConfig};
    use misaka_mil_channel::wire::{AnonServerHello, ClientMsg, establish_channel_anon};
    use misaka_mil_core::commit::request_commitment_for_ct;
    use misaka_mil_core::job::{JobSpec, SamplingParams, SlaParams, Tier};
    use misaka_mil_core::receipt::AnonReceiptChainVerifier;

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

    fn job(model: Hash64, cm_req: Hash64) -> JobSpec {
        JobSpec::new(model, Tier::Open, 4096, SamplingParams::greedy(), SlaParams { ttfb_ms: 1500, min_tps: 1 }, 10_000_000, cm_req)
    }

    #[tokio::test]
    async fn anon_session_never_reveals_the_long_term_key() {
        let ctx = ctx();
        let long_term_pk = ctx.pk_receipt().to_vec();
        // an opaque, claim_secret-keyed session receipt key (the caller derives it
        // via mil-shield's session_receipt_key; here a fixed value stands in).
        let session_rk = Hash64::from_bytes([0x5Au8; 64]);

        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn({
            let ctx = ctx.clone();
            async move { serve_session_anon(server_io, ctx, Arc::new(MockBackend::new(4)), session_rk).await }
        });

        // Requester drives the anonymous handshake. The closure only ever sees an
        // AnonServerHello — which has no pk_receipt field — and captures session_pk.
        let mut hello_session_pk = Vec::new();
        let mut hello_attestation_len = usize::MAX;
        let mut ch = establish_channel_anon(client_io, |hello: &AnonServerHello| {
            hello_session_pk = hello.session_pk.clone();
            hello_attestation_len = hello.attestation.len();
            Ok(())
        })
        .await
        .expect("anon establish");

        // The handshake carried the per-session key, NOT the long-term one, and no
        // (named) attestation.
        assert_ne!(hello_session_pk, long_term_pk, "handshake must not surface the long-term key");
        assert_eq!(hello_attestation_len, 0, "no named attestation on the anon path yet");
        assert_eq!(ch.peer_pk_receipt, hello_session_pk);

        let model = ctx.serving.model_id;
        let prompt_ct = ch.send(&ClientMsg::Prompt(b"anonymous inference please".to_vec())).await.unwrap();
        let cm_req = request_commitment_for_ct(&[7u8; 32], &prompt_ct);
        ch.send(&ClientMsg::Job(job(model, cm_req))).await.unwrap();

        // Verify every receipt against the OUT-OF-BAND per-session key; none carries
        // provider_pk (AnonSignedReceipt has no such field).
        let mut chain = AnonReceiptChainVerifier::new(ch.session_id, ch.peer_pk_receipt.clone());
        let total = loop {
            match ch.recv::<AnonServerMsg>().await.unwrap() {
                AnonServerMsg::Chunk { .. } => {}
                AnonServerMsg::Receipt(r) => chain.ingest(&r).expect("anon receipt chain"),
                AnonServerMsg::Done { total_tokens_out } => break total_tokens_out,
                AnonServerMsg::Error(e) => panic!("server error: {e}"),
            }
        };
        assert!(chain.is_finalized());

        let outcome = server.await.unwrap().unwrap();
        assert_eq!(outcome.tokens_out, total);
        assert!(outcome.final_receipt.body.is_final);
        assert_eq!(outcome.session_pk, hello_session_pk);
        // the settlement receipt verifies under the per-session key but NOT under the
        // long-term one — no key links this session to the provider's registration.
        outcome.final_receipt.verify_with_key(&outcome.session_pk).expect("verifies under session key");
        assert!(outcome.final_receipt.verify_with_key(&long_term_pk).is_err(), "must not verify under the long-term key");
    }

    #[tokio::test]
    async fn anon_session_rejects_wrong_model() {
        let ctx = ctx();
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let server =
            tokio::spawn(async move { serve_session_anon(server_io, ctx, Arc::new(MockBackend::default()), Hash64::from_bytes([9u8; 64])).await });
        let mut ch = establish_channel_anon(client_io, |_h: &AnonServerHello| Ok(())).await.unwrap();
        let prompt_ct = ch.send(&ClientMsg::Prompt(b"hi".to_vec())).await.unwrap();
        let cm_req = request_commitment_for_ct(&[1u8; 32], &prompt_ct);
        ch.send(&ClientMsg::Job(job(Hash64::from_bytes([0xAAu8; 64]), cm_req))).await.unwrap();
        match server.await.unwrap() {
            Err(SessionError::WrongModel { .. }) => {}
            other => panic!("expected WrongModel, got {other:?}"),
        }
    }
}
