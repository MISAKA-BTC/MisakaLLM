//! misaka-mil-provider — the MISAKA Inference Lane (MIL) v0 provider sidecar.
//!
//! A standalone process that sells LLM inference over a post-quantum
//! (ML-KEM-1024 + AES-256-GCM) data plane and issues ML-DSA-87 cumulative
//! Proof-of-Inference receipts (design §2.4-v0, §4.1). It mirrors the
//! `kaspa-pq-validator` deployment shape: run beside a co-located `kaspad`,
//! optionally anchoring registration/receipts as native-payload txs over
//! wRPC.
//!
//! Subcommands:
//! - `keygen`  — generate the 32-byte provider seed and print the identity.
//! - `run`     — start the data-plane inference server (mock backend in v0).
//! - `client`  — one-shot requester: connect, prompt, print the verified reply.
//! - `register`— build (dry-run) or `--submit` a provider registration anchor.

use clap::{Parser, Subcommand};
use kaspa_addresses::{Address, Prefix};
use kaspa_consensus_core::config::params::Params;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::network::{EndpointKind, NetworkId, NetworkType};
use kaspa_consensus_core::tx::{TransactionOutpoint, UtxoEntry};
use kaspa_core::{info, warn};
use kaspa_pq_validator_core::{VALIDATOR_SEED_LEN, ValidatorKey, is_spendable, load_validator_seed, select_funding};
use kaspa_rpc_core::{RpcTransaction, api::rpc::RpcApi};
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
};
use misaka_mil_core::anchor::ProviderRegistrationV1;
use misaka_mil_core::domains::MIL_PROTOCOL_VERSION;
use misaka_mil_core::job::{JobSpec, SamplingParams, SlaParams, Tier};
use misaka_mil_provider::anchor_tx::{build_anchor_tx, estimate_anchor_fee, registration_payload};
use misaka_mil_provider::backend::{InferenceBackend, MockBackend};
use misaka_mil_provider::backend_http::{HttpBackend, ServingStack};
use misaka_mil_provider::client::{RequesterClient, dev_attestation_verifier};
use misaka_mil_provider::config::{PROVIDER_SEED_LEN, ProviderContext, ServingConfig};
use misaka_mil_provider::service::now_ms;
use rand::RngCore;
use std::collections::HashSet;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const MIL: &str = "misaka-mil-provider";

/// MISAKA Inference Lane provider sidecar (design v0).
#[derive(Parser, Debug)]
#[command(name = "misaka-mil-provider", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a 32-byte provider seed and print the derived identity.
    Keygen(KeygenArgs),
    /// Start the data-plane inference server (mock backend in v0).
    Run(RunArgs),
    /// One-shot requester: connect, send a prompt, print the verified reply.
    Client(ClientArgs),
    /// Build (dry-run) or --submit a provider registration anchor.
    Register(RegisterArgs),
    /// Print aggregate operator stats from the receipt store (§16.5).
    Stats(StoreArgs),
    /// Export the receipt store as CSV for accounting (§16.5).
    ExportReceipts(ExportArgs),
}

#[derive(clap::Args, Debug)]
struct StoreArgs {
    /// JSONL receipt store path (the one passed to `run --receipt-store`).
    #[arg(long)]
    receipt_store: String,
}

#[derive(clap::Args, Debug)]
struct ExportArgs {
    /// JSONL receipt store path.
    #[arg(long)]
    receipt_store: String,
    /// Output CSV path; prints to stdout when omitted.
    #[arg(long)]
    out: Option<String>,
}

#[derive(clap::Args, Debug)]
struct KeygenArgs {
    /// Output file for the 32-byte provider seed (hex, 0600, refuses to clobber).
    #[arg(long)]
    out: String,
}

/// Serving parameters shared by `run` and `register`.
#[derive(clap::Args, Debug, Clone)]
struct ServingArgs {
    /// Provider seed file (32-byte hex; derives pk_kem + pk_receipt).
    #[arg(long, env = "MIL_PROVIDER_SEED")]
    provider_seed: String,
    /// Model id (128-char hex Hash64). Default: MIL-Core placeholder.
    #[arg(long)]
    model_id: Option<String>,
    /// Measured runtime image hash (128-char hex Hash64).
    #[arg(long)]
    runtime_image_hash: Option<String>,
    /// Weights-manifest hash (128-char hex Hash64).
    #[arg(long)]
    model_manifest_hash: Option<String>,
    /// Tier: `tee` (Tier 1) or `open` (Tier 2).
    #[arg(long, default_value = "open")]
    tier: String,
    /// Attested GPU-class weight g (§5.4).
    #[arg(long, default_value_t = 1)]
    gpu_class_weight: u32,
    /// Ask, sompi per 1000 input tokens.
    #[arg(long, default_value_t = 100_000)]
    ask_in_per_1k: u64,
    /// Ask, sompi per 1000 output tokens.
    #[arg(long, default_value_t = 500_000)]
    ask_out_per_1k: u64,
    /// SLA: max time-to-first-byte, ms.
    #[arg(long, default_value_t = 1500)]
    ttfb_ms: u32,
    /// SLA: minimum decode speed, tokens/s.
    #[arg(long, default_value_t = 20)]
    min_tps: u32,
    /// Region tag for geo routing.
    #[arg(long, default_value = "local")]
    region: String,
    /// Advertised data-plane dial address (`host:port`).
    #[arg(long, default_value = "127.0.0.1:37110")]
    data_plane_addr: String,
    /// Advertise the model as hot (VRAM-resident) so SDKs prefer it (§13.4a).
    #[arg(long, default_value_t = true)]
    hot: bool,
    /// Data-plane padding cell in bytes (§15.3); 0 = no padding. The requester
    /// must use the same value.
    #[arg(long, default_value_t = 0)]
    padding_cell: usize,
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    #[command(flatten)]
    serving: ServingArgs,
    /// TCP address to bind the data-plane server.
    #[arg(long, default_value = "127.0.0.1:37110")]
    listen: String,
    /// Backend: `mock` (deterministic echo, v0 default) or an OpenAI-compatible
    /// server tag `vllm` / `llamacpp`.
    #[arg(long, default_value = "mock")]
    backend: String,
    /// OpenAI-compatible inference server `host:port` (required for
    /// `--backend vllm|llamacpp`), e.g. `127.0.0.1:8000`.
    #[arg(long)]
    backend_addr: Option<String>,
    /// Model name the backend server expects (defaults to the model_id hex).
    #[arg(long)]
    backend_model: Option<String>,
    /// Words per streamed chunk.
    #[arg(long, default_value_t = 32)]
    chunk_words: usize,
    /// Max prompt turns per sticky session (§13.5). 1 = single-turn.
    #[arg(long, default_value_t = 1)]
    max_turns: u32,
    /// Sticky session TTL seconds — how long to hold the enclave awaiting the
    /// next turn (§10 sticky_session_ttl). 0 = no wait.
    #[arg(long, default_value_t = 1800)]
    sticky_ttl_secs: u64,
    /// Append each settled session to this JSONL receipt store (§16.5). Enables
    /// `stats` / `export-receipts`.
    #[arg(long)]
    receipt_store: Option<String>,
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(clap::Args, Debug)]
struct ClientArgs {
    /// Provider data-plane address (`host:port`). Omit to discover a provider
    /// on-chain via `--discover-from` + `--registry-addr`.
    #[arg(long)]
    provider_addr: Option<String>,
    /// Discover the provider on-chain: the node Ethereum JSON-RPC URL
    /// (e.g. `http://127.0.0.1:8545`). Requires `--registry-addr`. Picks the
    /// cheapest-listed active provider serving `--model-id`.
    #[arg(long, requires = "registry_addr")]
    discover_from: Option<String>,
    /// `ProviderRegistry` contract address (`0x…`) for `--discover-from`.
    #[arg(long)]
    registry_addr: Option<String>,
    /// Prompt text.
    #[arg(long)]
    prompt: String,
    /// Model id to request (128-char hex Hash64). Default: MIL-Core placeholder.
    #[arg(long)]
    model_id: Option<String>,
    /// Tier: `tee` or `open`.
    #[arg(long, default_value = "open")]
    tier: String,
    /// Price cap, sompi.
    #[arg(long, default_value_t = 10_000_000)]
    price_cap: u64,
    /// Max output tokens.
    #[arg(long, default_value_t = 512)]
    max_tokens: u32,
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(clap::Args, Debug)]
struct RegisterArgs {
    #[command(flatten)]
    serving: ServingArgs,
    /// Funding key file (32-byte hex ML-DSA-87 seed) that pays the anchor fee.
    #[arg(long, env = "MIL_FUNDING_KEY")]
    funding_key: String,
    /// Node wRPC (borsh) endpoint `host:port`. Auto-discovered from the
    /// endpoint registry when omitted.
    #[arg(long = "node-wrpc-borsh", visible_alias = "node-rpc", env = "MIL_NODE_RPC")]
    node_rpc: Option<String>,
    /// Network id (e.g. `testnet-10`). Used for endpoint discovery + the guard.
    #[arg(long, visible_alias = "network-id", env = "MIL_NETWORK")]
    network: Option<String>,
    /// Actually submit the anchor tx (default: dry-run, print txid + hex only).
    #[arg(long)]
    submit: bool,
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Keygen(args) => keygen(args),
        Command::Run(args) => {
            kaspa_core::log::init_logger(None, &args.log_level);
            run(args).await
        }
        Command::Client(args) => {
            kaspa_core::log::init_logger(None, &args.log_level);
            client(args).await
        }
        Command::Register(args) => {
            kaspa_core::log::init_logger(None, &args.log_level);
            register(args).await
        }
        Command::Stats(args) => stats(args),
        Command::ExportReceipts(args) => export_receipts(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[{MIL}] error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Generate a provider seed, write it 0600 (O_EXCL), print the derived identity.
fn keygen(args: KeygenArgs) -> Result<(), String> {
    let mut seed = [0u8; PROVIDER_SEED_LEN];
    rand::thread_rng().fill_bytes(&mut seed);

    let mut hex_buf = [0u8; PROVIDER_SEED_LEN * 2];
    faster_hex::hex_encode(&seed, &mut hex_buf).map_err(|e| format!("hex encode failed: {e}"))?;
    let hex = std::str::from_utf8(&hex_buf).expect("hex is valid utf-8");

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&args.out)
            .map_err(|e| format!("cannot create provider seed file '{}': {e}", args.out))?;
        f.write_all(hex.as_bytes()).map_err(|e| format!("cannot write provider seed: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&args.out, hex.as_bytes()).map_err(|e| format!("cannot write provider seed file '{}': {e}", args.out))?;
    }

    // Print the derived identity (placeholder serving config — identity only).
    let ctx = ProviderContext::from_seed(seed, placeholder_serving());
    use zeroize::Zeroize;
    seed.zeroize();
    println!("provider seed written to {}", args.out);
    println!("provider_id       = {}", ctx.provider_id());
    println!("pk_kem  ({} B)   = {}...", ctx.pk_kem().len(), hex_prefix(ctx.pk_kem(), 8));
    println!("pk_receipt ({} B) = {}...", ctx.pk_receipt().len(), hex_prefix(ctx.pk_receipt(), 8));
    println!("key_binding       = {}", ctx.key_binding());
    Ok(())
}

/// Start the data-plane inference server.
async fn run(args: RunArgs) -> Result<(), String> {
    let ctx = Arc::new(load_provider(&args.serving)?);
    let backend: Arc<dyn InferenceBackend> = build_backend(&args, &ctx)?;
    let listener =
        tokio::net::TcpListener::bind(&args.listen).await.map_err(|e| format!("cannot bind data plane to {}: {e}", args.listen))?;

    info!(
        "[{MIL}] serving provider_id={} on {} (tier={:?}, model={})",
        ctx.provider_id(),
        args.listen,
        ctx.serving.tier,
        ctx.serving.model_id
    );
    info!("[{MIL}] data plane: ML-KEM-1024 + AES-256-GCM; receipts: ML-DSA-87 cumulative every 512 tokens");

    // Startup self-check: confirm the real backend actually serves the configured
    // model (a name-level liveness check — catches a misconfigured/empty backend
    // before we advertise it). Non-fatal: a probe failure must not down the
    // provider. Weights-hash binding is receipt-level (§17.3, P3).
    let backend_model = args.backend_model.clone().unwrap_or_else(|| ctx.serving.model_id.to_string());
    match backend.probe_served_models().await {
        Ok(models) if models.is_empty() => {
            info!("[{MIL}] backend reports no model list (mock/opaque); skipping serve check");
        }
        Ok(models) if models.iter().any(|m| m == &backend_model) => {
            info!("[{MIL}] backend serves the configured model '{backend_model}'");
        }
        Ok(models) => {
            warn!("[{MIL}] backend does NOT list configured model '{backend_model}' (serves {models:?}); serving anyway");
        }
        Err(e) => warn!("[{MIL}] backend model probe failed: {e} (serving anyway)"),
    }

    let max_turns = args.max_turns.max(1);
    let sticky_ttl = std::time::Duration::from_secs(args.sticky_ttl_secs);
    let receipt_store = args.receipt_store.clone().map(std::path::PathBuf::from);

    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => accepted.map_err(|e| format!("accept failed: {e}"))?,
            _ = tokio::signal::ctrl_c() => {
                info!("[{MIL}] shutdown signal received");
                return Ok(());
            }
        };
        let ctx = ctx.clone();
        let backend = backend.clone();
        let store = receipt_store.clone();
        tokio::spawn(async move {
            let result = misaka_mil_provider::service::serve_sticky_session(stream, ctx.clone(), backend, max_turns, sticky_ttl).await;
            match result {
                Ok(outcome) => {
                    info!(
                        "[{MIL}] session {} done: turns={} in={} out={} cancelled={} final#{}",
                        outcome.session_id,
                        outcome.turns,
                        outcome.tokens_in,
                        outcome.tokens_out,
                        outcome.cancelled,
                        outcome.final_receipt.body.counter
                    );
                    if let Some(path) = &store {
                        let record = misaka_mil_provider::store::SessionRecord::from_outcome(
                            &outcome,
                            ctx.serving.ask_in_per_1k_sompi,
                            ctx.serving.ask_out_per_1k_sompi,
                            misaka_mil_provider::service::now_ms(),
                        );
                        if let Err(e) = misaka_mil_provider::store::append_record(path, &record) {
                            info!("[{MIL}] could not write receipt store: {e}");
                        }
                    }
                }
                Err(e) => info!("[{MIL}] session from {peer} ended: {e}"),
            }
        });
    }
}

/// Print aggregate operator stats from the receipt store (§16.5).
fn stats(args: StoreArgs) -> Result<(), String> {
    let records = misaka_mil_provider::store::read_records(std::path::Path::new(&args.receipt_store))
        .map_err(|e| format!("cannot read receipt store '{}': {e}", args.receipt_store))?;
    let s = misaka_mil_provider::store::aggregate(&records);
    println!("sessions       = {}", s.sessions);
    println!("turns          = {}", s.turns);
    println!("cancelled      = {}", s.cancelled);
    println!("tokens_in      = {}", s.tokens_in);
    println!("tokens_out     = {}", s.tokens_out);
    println!("gross_sompi    = {}", s.gross_sompi);
    println!("provider_sompi = {} (88% share)", s.provider_sompi);
    Ok(())
}

/// Export the receipt store as CSV (§16.5).
fn export_receipts(args: ExportArgs) -> Result<(), String> {
    let records = misaka_mil_provider::store::read_records(std::path::Path::new(&args.receipt_store))
        .map_err(|e| format!("cannot read receipt store '{}': {e}", args.receipt_store))?;
    let csv = misaka_mil_provider::store::to_csv(&records);
    match &args.out {
        Some(path) => {
            std::fs::write(path, csv).map_err(|e| format!("cannot write CSV '{path}': {e}"))?;
            println!("wrote {} records to {path}", records.len());
        }
        None => print!("{csv}"),
    }
    Ok(())
}

/// One-shot requester: connect, send a prompt, print the verified response.
async fn client(args: ClientArgs) -> Result<(), String> {
    let model_id = parse_hash64_opt(&args.model_id, placeholder_model_id())?;
    let tier = parse_tier(&args.tier)?;

    // Resolve the data-plane address: explicit `--provider-addr`, or on-chain
    // discovery from the ProviderRegistry (the v1 replacement for the v0
    // out-of-band address).
    let provider_addr = match (&args.provider_addr, &args.discover_from) {
        (Some(addr), _) => addr.clone(),
        (None, Some(eth_rpc_url)) => {
            let registry = args.registry_addr.as_deref().ok_or("--registry-addr is required with --discover-from")?;
            let model_hex = model_id.to_string();
            let offers = misaka_mil_provider::discover::resolve_offers(eth_rpc_url, registry, Some(&model_hex)).await?;
            let picked = offers.into_iter().next().ok_or("no active provider found on-chain serving the requested model")?;
            info!("[{MIL}] discovered provider {} at {}", picked.provider_id, picked.data_plane_addr);
            picked.data_plane_addr
        }
        (None, None) => return Err("either --provider-addr or --discover-from is required".to_string()),
    };

    let stream = tokio::net::TcpStream::connect(&provider_addr)
        .await
        .map_err(|e| format!("cannot connect to provider {provider_addr}: {e}"))?;

    let mut client =
        RequesterClient::connect(stream, dev_attestation_verifier()).await.map_err(|e| format!("handshake failed: {e}"))?;
    info!("[{MIL}] established session {}", client.session_id());

    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let price_cap = args.price_cap;
    let max_tokens = args.max_tokens;
    let make_job = |cm_req| {
        JobSpec::new(model_id, tier, max_tokens, SamplingParams::greedy(), SlaParams { ttfb_ms: 1500, min_tps: 1 }, price_cap, cm_req)
    };
    let result = client.run_prompt(args.prompt.as_bytes(), make_job, salt).await.map_err(|e| format!("inference failed: {e}"))?;

    println!("--- response ---");
    println!("{}", result.response_text);
    println!("--- receipts ---");
    for r in &result.receipts {
        println!(
            "  #{} out={} in={} final={} cm_resp={}",
            r.body.counter, r.body.cum_tokens_out, r.body.cum_tokens_in, r.body.is_final, r.body.cm_resp
        );
    }
    println!(
        "final settlement: {} output tokens, receipt_hash={}",
        result.final_receipt.body.cum_tokens_out,
        result.final_receipt.receipt_hash()
    );
    Ok(())
}

/// Build (and optionally submit) a provider registration anchor.
async fn register(args: RegisterArgs) -> Result<(), String> {
    let ctx = load_provider(&args.serving)?;
    let funding_seed = load_validator_seed(&args.funding_key)?;
    let funding_key = ValidatorKey::from_seed(funding_seed);

    let node_rpc = resolve_node_rpc(&args.network, &args.node_rpc);
    info!("[{MIL}] connecting to node ws://{node_rpc} (submit={})", args.submit);
    let rpc = connect(&node_rpc).await?;
    let server = rpc.get_server_info().await.map_err(|e| format!("getServerInfo failed: {e}"))?;
    let node_network = server.network_id.to_string();
    if let Some(expected) = args.network.as_deref()
        && node_network != expected
    {
        return Err(format!("network mismatch: node is '{node_network}' but --network is '{expected}'"));
    }
    let prefix = prefix_for(server.network_id.network_type);
    let params = Params::from(server.network_id);
    let mass_calc = MassCalculator::new(
        params.mass_per_tx_byte,
        params.mass_per_script_pub_key_byte,
        params.mass_per_sig_op,
        params.storage_mass_parameter,
    );
    let coinbase_maturity = params.coinbase_maturity();
    let virtual_daa = server.virtual_daa_score;

    let reg = ProviderRegistrationV1 {
        version: MIL_PROTOCOL_VERSION,
        provider_id: ctx.provider_id(),
        quote_hash: ctx.dev_attestation_bundle(now_ms()).quote_hash(),
        model_id: ctx.serving.model_id,
        tier: ctx.serving.tier,
        gpu_class_weight: ctx.serving.gpu_class_weight,
        pk_kem: ctx.pk_kem().to_vec(),
        pk_receipt: ctx.pk_receipt().to_vec(),
        binding: ctx.key_binding(),
        ask_in_per_1k_sompi: ctx.serving.ask_in_per_1k_sompi,
        ask_out_per_1k_sompi: ctx.serving.ask_out_per_1k_sompi,
        sla: ctx.serving.sla,
        region: ctx.serving.region.clone(),
        data_plane_addr: ctx.serving.data_plane_addr.clone(),
        hot: ctx.serving.hot,
        timestamp_ms: now_ms(),
    };
    let payload = registration_payload(reg);

    let fee = estimate_anchor_fee(&funding_key, &mass_calc, prefix, &payload, 1);
    let funding_addr = funding_key.funding_address(prefix);
    let funding = select_funding_paged(&rpc, &funding_addr, fee, virtual_daa, coinbase_maturity).await?;
    let tx = build_anchor_tx(&funding_key, &payload, &[funding], fee, params.storage_mass_parameter)?;
    let txid = tx.id();

    println!("registration anchor tx:");
    println!("  provider_id = {}", ctx.provider_id());
    println!("  funding     = {funding_addr}");
    println!("  fee         = {fee} sompi");
    println!("  txid        = {txid}");

    if args.submit {
        let submitted =
            rpc.submit_transaction(RpcTransaction::from(&tx), false).await.map_err(|e| format!("submitTransaction failed: {e}"))?;
        println!("  submitted   = {submitted}");
    } else {
        println!("  (dry-run: re-run with --submit to broadcast)");
    }
    let _ = rpc.disconnect().await;
    Ok(())
}

// --- helpers -----------------------------------------------------------------------------

/// Select the serving backend from `--backend`. `mock` needs no server;
/// `vllm`/`llamacpp` require `--backend-addr` and speak OpenAI HTTP.
fn build_backend(args: &RunArgs, ctx: &ProviderContext) -> Result<Arc<dyn InferenceBackend>, String> {
    match args.backend.to_ascii_lowercase().as_str() {
        "mock" => Ok(Arc::new(MockBackend::new(args.chunk_words))),
        stack @ ("vllm" | "llamacpp" | "llama.cpp") => {
            let addr = args.backend_addr.clone().ok_or("--backend-addr is required for a real backend (e.g. 127.0.0.1:8000)")?;
            let model = args.backend_model.clone().unwrap_or_else(|| ctx.serving.model_id.to_string());
            let serving_stack = if stack == "vllm" { ServingStack::Vllm } else { ServingStack::LlamaCpp };
            Ok(Arc::new(HttpBackend::new(addr, model, serving_stack).with_chunk_words(args.chunk_words)))
        }
        other => Err(format!("unknown backend '{other}' (expected mock, vllm, or llamacpp)")),
    }
}

fn load_provider(args: &ServingArgs) -> Result<ProviderContext, String> {
    // Same 32-byte 0600 hex-file format + fail-closed guard as the validator key.
    let mut seed: [u8; PROVIDER_SEED_LEN] = load_validator_seed(&args.provider_seed)?;
    let serving = ServingConfig {
        model_id: parse_hash64_opt(&args.model_id, placeholder_model_id())?,
        runtime_image_hash: parse_hash64_opt(&args.runtime_image_hash, placeholder_runtime())?,
        model_manifest_hash: parse_hash64_opt(&args.model_manifest_hash, placeholder_manifest())?,
        tier: parse_tier(&args.tier)?,
        gpu_class_weight: args.gpu_class_weight,
        ask_in_per_1k_sompi: args.ask_in_per_1k,
        ask_out_per_1k_sompi: args.ask_out_per_1k,
        sla: SlaParams { ttfb_ms: args.ttfb_ms, min_tps: args.min_tps },
        region: args.region.clone(),
        data_plane_addr: args.data_plane_addr.clone(),
        hot: args.hot,
        padding_cell: (args.padding_cell != 0).then_some(args.padding_cell),
    };
    let ctx = ProviderContext::from_seed(seed, serving);
    use zeroize::Zeroize;
    seed.zeroize();
    Ok(ctx)
}

/// Scan the funding address (paged, bounded) and pick the best mature UTXO.
async fn select_funding_paged(
    rpc: &KaspaRpcClient,
    funding_addr: &Address,
    fee: u64,
    virtual_daa: u64,
    coinbase_maturity: u64,
) -> Result<(TransactionOutpoint, UtxoEntry), String> {
    const PAGE_LIMIT: u64 = 1000;
    const MAX_PAGES: usize = 16;
    const GOOD_ENOUGH_FEE_MULT: u64 = 64;
    let good_enough = fee.saturating_mul(GOOD_ENOUGH_FEE_MULT);

    let mut gathered: Vec<(TransactionOutpoint, UtxoEntry)> = Vec::new();
    let mut cursor = String::new();
    for _ in 0..MAX_PAGES {
        let page = rpc
            .get_utxos_by_address_page(funding_addr.clone(), cursor, PAGE_LIMIT)
            .await
            .map_err(|e| format!("getUtxosByAddressPage failed (does the node run --utxoindex?): {e}"))?;
        let next_cursor = page.next_cursor;
        let mut seen_good = false;
        for e in page.entries {
            let op = TransactionOutpoint::from(e.outpoint);
            let en = UtxoEntry::from(e.utxo_entry);
            if en.amount > good_enough && is_spendable(en.is_coinbase, en.block_daa_score, virtual_daa, coinbase_maturity) {
                seen_good = true;
            }
            gathered.push((op, en));
        }
        if seen_good || next_cursor.is_empty() {
            break;
        }
        cursor = next_cursor;
    }
    select_funding(&None, &HashSet::new(), gathered, fee, virtual_daa, coinbase_maturity)
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    let take = n.min(bytes.len());
    let mut buf = vec![0u8; take * 2];
    faster_hex::hex_encode(&bytes[..take], &mut buf).ok();
    String::from_utf8(buf).unwrap_or_default()
}

fn parse_tier(s: &str) -> Result<Tier, String> {
    match s.to_ascii_lowercase().as_str() {
        "tee" | "tier1" | "1" => Ok(Tier::Tee),
        "open" | "tier2" | "2" => Ok(Tier::Open),
        _ => Err(format!("unknown tier '{s}' (expected 'tee' or 'open')")),
    }
}

fn parse_hash64_opt(s: &Option<String>, default: kaspa_hashes::Hash64) -> Result<kaspa_hashes::Hash64, String> {
    match s {
        None => Ok(default),
        Some(hex) => kaspa_hashes::Hash64::from_str(hex.trim()).map_err(|e| format!("bad Hash64 hex '{hex}': {e}")),
    }
}

/// Deterministic placeholder identities until MIL-Core is pinned (§7.2). The
/// keyed inputs encode which artifact they stand for, so they are never
/// mistaken for a registered model.
fn placeholder_runtime() -> kaspa_hashes::Hash64 {
    kaspa_hashes::blake2b_512_keyed(b"misaka-mil-v1/placeholder", b"runtime-image")
}
fn placeholder_manifest() -> kaspa_hashes::Hash64 {
    kaspa_hashes::blake2b_512_keyed(b"misaka-mil-v1/placeholder", b"model-manifest")
}
fn placeholder_model_id() -> kaspa_hashes::Hash64 {
    misaka_mil_core::model::model_id(b"MIL-Core-v1/dolphin-3.0-llama3.1-8b/PLACEHOLDER")
}
fn placeholder_serving() -> ServingConfig {
    ServingConfig {
        model_id: placeholder_model_id(),
        runtime_image_hash: placeholder_runtime(),
        model_manifest_hash: placeholder_manifest(),
        tier: Tier::Open,
        gpu_class_weight: 1,
        ask_in_per_1k_sompi: 100_000,
        ask_out_per_1k_sompi: 500_000,
        sla: SlaParams { ttfb_ms: 1500, min_tps: 20 },
        region: "local".into(),
        data_plane_addr: "127.0.0.1:37110".into(),
        hot: true,
        padding_cell: None,
    }
}

fn prefix_for(network_type: NetworkType) -> Prefix {
    match network_type {
        NetworkType::Mainnet => Prefix::Mainnet,
        NetworkType::Testnet => Prefix::Testnet,
        NetworkType::Devnet => Prefix::Devnet,
        NetworkType::Simnet => Prefix::Simnet,
    }
}

fn resolve_node_rpc(network: &Option<String>, explicit: &Option<String>) -> String {
    if let Some(e) = explicit {
        return e.clone();
    }
    if let Some(net) = network
        && let Ok(nid) = NetworkId::from_str(net)
    {
        return misaka_endpoints::resolve(
            &nid,
            EndpointKind::NodeWrpcBorsh,
            None,
            misaka_endpoints::EndpointRegistry::load(net).as_ref(),
        );
    }
    "127.0.0.1:27210".to_string()
}

async fn connect(node_rpc: &str) -> Result<KaspaRpcClient, String> {
    let url = format!("ws://{node_rpc}");
    let client = KaspaRpcClient::new(WrpcEncoding::Borsh, Some(&url), None, None, None)
        .map_err(|e| format!("failed to build wRPC client: {e}"))?;
    let options = ConnectOptions {
        block_async_connect: true,
        connect_timeout: Some(Duration::from_millis(5_000)),
        strategy: ConnectStrategy::Retry,
        ..Default::default()
    };
    client.connect(Some(options)).await.map_err(|e| format!("cannot connect to node at {node_rpc}: {e}"))?;
    Ok(client)
}

// The provider seed reuses the validator's 32-byte 0600 hex-file loader, so the
// two lengths must stay identical.
const _: () = assert!(PROVIDER_SEED_LEN == VALIDATOR_SEED_LEN);
