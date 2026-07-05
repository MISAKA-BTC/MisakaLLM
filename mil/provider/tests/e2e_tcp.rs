//! End-to-end MIL session over a real TCP socket (design §2.3 full flow).
//!
//! Binds the provider data-plane server on an ephemeral port, connects a
//! requester over `TcpStream`, runs a multi-receipt prompt, and asserts the
//! response and the receipt chain verify — the same path the `run` + `client`
//! subcommands take, minus the CLI.

use kaspa_hashes::Hash64;
use misaka_mil_core::job::{JobSpec, SamplingParams, SlaParams, Tier};
use misaka_mil_provider::backend::MockBackend;
use misaka_mil_provider::client::{RequesterClient, dev_attestation_verifier};
use misaka_mil_provider::config::{ProviderContext, ServingConfig};
use misaka_mil_provider::service::serve_session;
use std::sync::Arc;

fn provider_ctx() -> Arc<ProviderContext> {
    let serving = ServingConfig {
        model_id: Hash64::from_bytes([0x11u8; 64]),
        runtime_image_hash: Hash64::from_bytes([0x22u8; 64]),
        model_manifest_hash: Hash64::from_bytes([0x33u8; 64]),
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
    Arc::new(ProviderContext::from_seed([0xEEu8; 32], serving))
}

#[tokio::test]
async fn tcp_session_streams_and_settles() {
    let ctx = provider_ctx();
    let model_id = ctx.serving.model_id;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // one-shot server: accept a single connection and serve it
    let server_ctx = ctx.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        // 3-word chunks over a long prompt guarantee several intermediate receipts
        serve_session(stream, server_ctx, Arc::new(MockBackend::new(3))).await
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut client = RequesterClient::connect(stream, dev_attestation_verifier()).await.unwrap();

    let long_prompt =
        "verify the decentralized post quantum inference lane streams tokens and settles on a cumulative receipt exactly once "
            .repeat(40);
    let make_job = |cm_req| {
        JobSpec::new(
            model_id,
            Tier::Open,
            4096,
            SamplingParams::greedy(),
            SlaParams { ttfb_ms: 1500, min_tps: 1 },
            100_000_000,
            cm_req,
        )
    };
    let result = client.run_prompt(long_prompt.as_bytes(), make_job, [0x5Au8; 32]).await.unwrap();

    // response is the mock echo, receipts chain-verified inside run_prompt
    assert!(result.response_text.contains("You said"));
    assert!(result.final_receipt.body.is_final);
    assert!(result.final_receipt.verify().is_ok(), "final receipt signature must verify");

    // receipt counters are strictly increasing and the last is final
    for pair in result.receipts.windows(2) {
        assert!(pair[1].body.counter > pair[0].body.counter);
    }
    assert_eq!(*result.receipts.last().unwrap(), result.final_receipt);

    let outcome = server.await.unwrap().unwrap();
    assert_eq!(outcome.session_id, result.session_id);
    assert_eq!(outcome.tokens_out, result.final_receipt.body.cum_tokens_out);
    assert!(outcome.tokens_out > 0);
}
