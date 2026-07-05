//! misaka-compute-attestor — the MIL compute-attestor sidecar (ADR-0024 §20, Phase A).
//!
//! Mirrors `kaspa-pq-validator`: it connects to a co-located node over wRPC and,
//! once configured with a bond + device-certificate hash, signs the ready-to-
//! attest epoch anchor with its ML-DSA-87 key under the compute-attest context
//! and records the attestation as a NATIVE-tx payload anchor. **Phase A =
//! record only: no subnetwork, no coinbase change, no reorg-gate participation
//! (zero liveness risk).** The issuance reward + Phase-C reorg dimension are
//! separate HF-gated steps (ADR-0024).
//!
//! Subcommands: `run` (the attestor daemon), `keygen`, `status`.

use clap::{Parser, Subcommand};
use kaspa_addresses::{Address, Prefix};
use kaspa_consensus_core::config::params::Params;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::network::{EndpointKind, NetworkId, NetworkType};
use kaspa_consensus_core::tx::{TransactionOutpoint, UtxoEntry};
use kaspa_core::info;
use kaspa_hashes::Hash64;
use kaspa_pq_validator_core::{VALIDATOR_SEED_LEN, is_spendable, load_validator_seed, select_funding};
use kaspa_rpc_core::{GetValidatorAttestationTargetRequest, RpcTransaction, api::rpc::RpcApi};
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
};
use misaka_compute_attestor::{ComputeAttestorKey, estimate_attestation_anchor_fee};
use misaka_mil_core::compute_attest::BondOutpoint;
use misaka_mil_core::job::Tier;
use rand::RngCore;
use std::collections::HashSet;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

const ATT: &str = "misaka-compute-attestor";

#[derive(Parser, Debug)]
#[command(name = "misaka-compute-attestor", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a 32-byte attestor seed and print the derived identity.
    Keygen(KeygenArgs),
    /// Run the compute-attestor daemon (Phase A: record-only anchoring).
    Run(RunArgs),
    /// One-shot: print the attestor identity + funding address.
    Status(StatusArgs),
}

#[derive(clap::Args, Debug)]
struct KeygenArgs {
    #[arg(long)]
    out: String,
    #[arg(long, visible_alias = "network-id", default_value = "testnet-10")]
    network: String,
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// Attestor seed file (32-byte hex, 0600).
    #[arg(long, env = "MIL_ATTESTOR_SEED")]
    attestor_seed: String,
    /// Native bond reference `txid:index` backing this attestor (§20.3).
    #[arg(long, env = "MIL_COMPUTE_BOND")]
    bond: String,
    /// Device-certificate hash (128-char hex Hash64): TEE cert (Tier1) or
    /// canary-measured profile (Tier2). §20.5 device binding.
    #[arg(long, env = "MIL_DEVICE_CERT_HASH")]
    device_cert_hash: String,
    /// Attestor class: `tee` (Tier1) or `open` (Tier2).
    #[arg(long, default_value = "tee")]
    tier: String,
    /// Node wRPC (borsh) endpoint `host:port` (auto-discovered if omitted).
    #[arg(long = "node-wrpc-borsh", visible_alias = "node-rpc", env = "MIL_NODE_RPC")]
    node_rpc: Option<String>,
    #[arg(long, visible_alias = "network-id", env = "MIL_NETWORK")]
    network: Option<String>,
    /// Poll interval seconds.
    #[arg(long, default_value_t = 10)]
    poll_secs: u64,
    /// Actually submit anchor txs (default: dry-run, log the txid only).
    #[arg(long)]
    submit: bool,
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(clap::Args, Debug)]
struct StatusArgs {
    #[arg(long, env = "MIL_ATTESTOR_SEED")]
    attestor_seed: String,
    #[arg(long, visible_alias = "network-id", default_value = "testnet-10")]
    network: String,
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
        Command::Status(args) => status(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[{ATT}] error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(args: KeygenArgs) -> Result<(), String> {
    let prefix = parse_prefix(&args.network)?;
    let mut seed = [0u8; VALIDATOR_SEED_LEN];
    rand::thread_rng().fill_bytes(&mut seed);
    let mut hex = [0u8; VALIDATOR_SEED_LEN * 2];
    faster_hex::hex_encode(&seed, &mut hex).map_err(|e| format!("hex encode failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&args.out)
            .map_err(|e| format!("cannot create attestor seed file '{}': {e}", args.out))?;
        f.write_all(&hex).map_err(|e| format!("cannot write attestor seed: {e}"))?;
    }
    #[cfg(not(unix))]
    std::fs::write(&args.out, hex).map_err(|e| format!("cannot write attestor seed file '{}': {e}", args.out))?;

    let key = ComputeAttestorKey::from_seed(seed);
    use zeroize::Zeroize;
    seed.zeroize();
    println!("attestor seed written to {}", args.out);
    println!("attestor_id     = {}", key.attestor_id);
    println!("funding address = {}", key.funding_address(prefix));
    Ok(())
}

fn status(args: StatusArgs) -> Result<(), String> {
    let prefix = parse_prefix(&args.network)?;
    let seed = load_validator_seed(&args.attestor_seed)?;
    let key = ComputeAttestorKey::from_seed(seed);
    println!("attestor_id     = {}", key.attestor_id);
    println!("funding address = {}", key.funding_address(prefix));
    println!("(fund the address above, then run `run --bond <txid:index> --device-cert-hash <hex>`)");
    Ok(())
}

async fn run(args: RunArgs) -> Result<(), String> {
    let seed = load_validator_seed(&args.attestor_seed)?;
    let key = ComputeAttestorKey::from_seed(seed);
    let bond = parse_bond(&args.bond)?;
    let device_cert_hash = parse_hash64(&args.device_cert_hash)?;
    let tier = parse_tier(&args.tier)?;

    let node_rpc = resolve_node_rpc(&args.network, &args.node_rpc);
    info!("[{ATT}] attestor_id={} connecting to ws://{node_rpc} (submit={})", key.attestor_id, args.submit);
    let client = connect(&node_rpc).await?;
    let server = client.get_server_info().await.map_err(|e| format!("getServerInfo failed: {e}"))?;
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
    let network_id_bytes = params.genesis.hash.as_byte_slice().to_vec();
    let funding_addr = key.funding_address(prefix);
    info!("[{ATT}] connected: network={node_network} funding={funding_addr}");

    let cfg = LoopCfg {
        bond,
        device_cert_hash,
        tier,
        prefix,
        network_id: network_id_bytes,
        coinbase_maturity,
        storage_mass_parameter: params.storage_mass_parameter,
        poll_secs: args.poll_secs,
        submit: args.submit,
    };
    let result = tokio::select! {
        r = run_loop(&client, &key, &mass_calc, &cfg) => r,
        _ = tokio::signal::ctrl_c() => { info!("[{ATT}] shutdown signal received"); Ok(()) }
    };
    let _ = client.disconnect().await;
    result
}

/// Per-run configuration for the attestor loop.
struct LoopCfg {
    bond: BondOutpoint,
    device_cert_hash: Hash64,
    tier: Tier,
    prefix: Prefix,
    network_id: Vec<u8>,
    coinbase_maturity: u64,
    storage_mass_parameter: u64,
    poll_secs: u64,
    submit: bool,
}

async fn run_loop(client: &KaspaRpcClient, key: &ComputeAttestorKey, mass_calc: &MassCalculator, cfg: &LoopCfg) -> Result<(), String> {
    let funding_addr = key.funding_address(cfg.prefix);
    let bond_string = format!("{}:{}", cfg.bond.txid, cfg.bond.index);
    let mut last_epoch: Option<u64> = None;
    loop {
        let server = match client.get_server_info().await {
            Ok(s) => s,
            Err(e) => {
                info!("[{ATT}] getServerInfo failed, retrying: {e}");
                sleep_secs(5).await;
                continue;
            }
        };
        if !server.is_synced {
            sleep_secs(5).await;
            continue;
        }
        // Phase A uses the DNS-validator epoch anchor as the compute-attestation
        // target: `target_hash`/`epoch`/`target_daa_score` are network-global per
        // epoch; the per-validator `message` field is ignored (the attestor signs
        // its own compute-attest transcript).
        let req = GetValidatorAttestationTargetRequest { bond_outpoint: bond_string.clone() };
        let target = match client.get_validator_attestation_target(req).await {
            Ok(t) if t.available => t,
            _ => {
                sleep_secs(cfg.poll_secs).await;
                continue;
            }
        };
        if last_epoch == Some(target.epoch) {
            sleep_secs(cfg.poll_secs).await;
            continue;
        }
        let target_hash = parse_hash64(&target.target_hash)?;

        let body = key.attestation_body(cfg.bond, target.epoch, target_hash, target.target_daa_score, cfg.device_cert_hash, cfg.tier);
        let attestation = key.sign_attestation(body, &cfg.network_id);

        let fee = estimate_attestation_anchor_fee(key, mass_calc, cfg.prefix, &cfg.network_id, 1);
        match select_funding_paged(client, &funding_addr, fee, server.virtual_daa_score, cfg.coinbase_maturity).await {
            Ok(funding) => match key.build_attestation_anchor_tx(attestation, &[funding], fee, cfg.storage_mass_parameter) {
                Ok(tx) => {
                    let txid = tx.id();
                    if cfg.submit {
                        match client.submit_transaction(RpcTransaction::from(&tx), false).await {
                            Ok(_) => info!("[{ATT}] epoch {} attested: submitted {txid}", target.epoch),
                            Err(e) => {
                                info!("[{ATT}] submit failed: {e}");
                                sleep_secs(cfg.poll_secs).await;
                                continue;
                            }
                        }
                    } else {
                        info!("[{ATT}] epoch {} attested (dry-run): txid {txid} — add --submit to broadcast", target.epoch);
                    }
                    last_epoch = Some(target.epoch);
                }
                Err(e) => info!("[{ATT}] anchor tx build failed: {e}"),
            },
            Err(e) => info!("[{ATT}] no funding (fund {funding_addr}?): {e}"),
        }
        sleep_secs(cfg.poll_secs).await;
    }
}

async fn select_funding_paged(
    client: &KaspaRpcClient,
    funding_addr: &Address,
    fee: u64,
    virtual_daa: u64,
    coinbase_maturity: u64,
) -> Result<(TransactionOutpoint, UtxoEntry), String> {
    const PAGE_LIMIT: u64 = 1000;
    const MAX_PAGES: usize = 16;
    let good_enough = fee.saturating_mul(64);
    let mut gathered: Vec<(TransactionOutpoint, UtxoEntry)> = Vec::new();
    let mut cursor = String::new();
    for _ in 0..MAX_PAGES {
        let page = client
            .get_utxos_by_address_page(funding_addr.clone(), cursor, PAGE_LIMIT)
            .await
            .map_err(|e| format!("getUtxosByAddressPage failed (does the node run --utxoindex?): {e}"))?;
        let next = page.next_cursor;
        let mut seen_good = false;
        for e in page.entries {
            let op = TransactionOutpoint::from(e.outpoint);
            let en = UtxoEntry::from(e.utxo_entry);
            if en.amount > good_enough && is_spendable(en.is_coinbase, en.block_daa_score, virtual_daa, coinbase_maturity) {
                seen_good = true;
            }
            gathered.push((op, en));
        }
        if seen_good || next.is_empty() {
            break;
        }
        cursor = next;
    }
    select_funding(&None, &HashSet::new(), gathered, fee, virtual_daa, coinbase_maturity)
}

async fn sleep_secs(s: u64) {
    tokio::time::sleep(Duration::from_secs(s)).await;
}

fn parse_bond(s: &str) -> Result<BondOutpoint, String> {
    let (txid, idx) = s.rsplit_once(':').ok_or("bond must be 'txid:index'")?;
    Ok(BondOutpoint { txid: parse_hash64(txid)?, index: idx.parse().map_err(|_| "bond index must be a u32")? })
}

fn parse_hash64(hex: &str) -> Result<Hash64, String> {
    Hash64::from_str(hex.trim()).map_err(|e| format!("bad Hash64 hex '{hex}': {e}"))
}

fn parse_tier(s: &str) -> Result<Tier, String> {
    match s.to_ascii_lowercase().as_str() {
        "tee" | "tier1" | "1" => Ok(Tier::Tee),
        "open" | "tier2" | "2" => Ok(Tier::Open),
        _ => Err(format!("unknown tier '{s}' (expected 'tee' or 'open')")),
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

fn parse_prefix(s: &str) -> Result<Prefix, String> {
    let base = s.split('-').next().unwrap_or(s);
    match base.to_ascii_lowercase().as_str() {
        "mainnet" => Ok(Prefix::Mainnet),
        "testnet" => Ok(Prefix::Testnet),
        "devnet" => Ok(Prefix::Devnet),
        "simnet" => Ok(Prefix::Simnet),
        _ => Err(format!("unknown network '{s}'")),
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

const _: () = assert!(VALIDATOR_SEED_LEN == misaka_compute_attestor::ATTESTOR_SEED_LEN);
