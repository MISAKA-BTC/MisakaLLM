//! `misaka-mtp-service` — the MTP service-layer binary (ADR-0038 D2).
//!
//! Off-chain, consensus-neutral, **testnet-only**. Two subcommands cover the
//! trust-critical deterministic pipeline and the read-only self-serve surface;
//! the live collector I/O (p2p-crawler / wRPC chain-indexer / github-sync /
//! campaign-forms) is the injected non-deterministic edge (ADR-0038 §3 step 3)
//! and is wired per-deployment on top of the fact store this binary manages.
//!
//! ```text
//! misaka-mtp-service serve      --data-dir DIR --operator-key FILE --listen ADDR [--network testnet-10]
//! misaka-mtp-service run-epoch  --data-dir DIR --operator-key FILE \
//!                               --epoch N --start RFC3339 --end RFC3339 [--network testnet-10]
//! ```
//!
//! `serve` opens the signed-ledger archive read-only and serves the D3 query API.
//! `run-epoch` builds a fresh single-epoch fact store (G3), resolves attribution
//! (G1), scores + signs (core), and publishes the signed ledger (D6).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use kaspa_pq_validator_core::{ValidatorKey, load_validator_seed};
use misaka_mtp::{Rules, Stage};
use misaka_mtp_collectors::EpochWindow;
use misaka_mtp_service::{Attributor, HttpState, LedgerArchive, PersistentStore, RegistrationRecord, config, epoch};

const USAGE: &str = "\
misaka-mtp-service — MISAKA Testnet Points Program service (ADR-0038, testnet-only)

USAGE:
  misaka-mtp-service serve     --data-dir DIR --operator-key FILE --listen ADDR [--network NET] [--pin STR]...
  misaka-mtp-service run-epoch --data-dir DIR --operator-key FILE --epoch N --start RFC3339 --end RFC3339 [--network NET]

COMMON:
  --data-dir DIR        root data dir: <DIR>/facts (fact store), <DIR>/points (signed ledger archive),
                        <DIR>/registrations.jsonl (attribution registry)
  --operator-key FILE   dedicated MTP operator ML-DSA-87 seed file (0600, D7)
  --network NET         scored testnet network name (default: testnet-10)

serve:
  --listen ADDR         query-http bind address, e.g. 127.0.0.1:8790
  --pin STR             an out-of-band operator-key pin surfaced by /mtp/v1/operator (repeatable)

run-epoch:
  --epoch N             epoch number
  --start / --end       RFC-3339 UTC window bounds [start, end)
";

fn main() {
    std::process::exit(match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("misaka-mtp-service: error: {e}");
            1
        }
    });
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => cmd_serve(&args[1..]),
        Some("run-epoch") => cmd_run_epoch(&args[1..]),
        Some("-h") | Some("--help") | Some("help") | None => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown subcommand '{other}'\n\n{USAGE}")),
    }
}

/// A tiny `--flag value` parser (no clap dep — mirrors the eth-rpc house style of
/// keeping the service dependency-light).
struct Flags {
    map: std::collections::HashMap<String, String>,
    multi: std::collections::HashMap<String, Vec<String>>,
}

impl Flags {
    fn parse(args: &[String], repeatable: &[&str]) -> Result<Self, String> {
        let mut map = std::collections::HashMap::new();
        let mut multi: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        let mut i = 0;
        while i < args.len() {
            let k = &args[i];
            let key = k.strip_prefix("--").ok_or_else(|| format!("expected a --flag, got '{k}'"))?;
            let v = args.get(i + 1).ok_or_else(|| format!("flag --{key} needs a value"))?.clone();
            if repeatable.contains(&key) {
                multi.entry(key.to_string()).or_default().push(v);
            } else {
                map.insert(key.to_string(), v);
            }
            i += 2;
        }
        Ok(Self { map, multi })
    }
    fn get(&self, k: &str) -> Result<&str, String> {
        self.map.get(k).map(String::as_str).ok_or_else(|| format!("missing required flag --{k}"))
    }
    fn opt(&self, k: &str) -> Option<&str> {
        self.map.get(k).map(String::as_str)
    }
    fn list(&self, k: &str) -> Vec<String> {
        self.multi.get(k).cloned().unwrap_or_default()
    }
}

fn network_or_default(flags: &Flags) -> Result<String, String> {
    let net = flags.opt("network").unwrap_or("testnet-10").to_string();
    if config::stage_for(&net).is_none() {
        return Err(format!("network '{net}' is not in the testnet scope {:?} (D1)", config::NETWORKS.iter().map(|(n, _)| *n).collect::<Vec<_>>()));
    }
    Ok(net)
}

fn load_operator_key(path: &str) -> Result<ValidatorKey, String> {
    let seed = load_validator_seed(path)?;
    Ok(ValidatorKey::from_seed(seed))
}

/// Load the persisted registrations (JSONL, one [`RegistrationRecord`] per line).
/// A missing file is an empty registry (fresh deployment).
fn load_registrations(path: &PathBuf) -> Result<Vec<RegistrationRecord>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line).map_err(|e| format!("{}:{}: malformed registration: {e}", path.display(), i + 1))?);
    }
    Ok(out)
}

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args, &["pin"])?;
    let data_dir = PathBuf::from(flags.get("data-dir")?);
    let listen: SocketAddr = flags.get("listen")?.parse().map_err(|e| format!("bad --listen address: {e}"))?;
    let _network = network_or_default(&flags)?;
    let key = load_operator_key(flags.get("operator-key")?)?;

    let archive_dir = data_dir.join("points");
    // Ensure the archive dir exists so the query API can open it immediately.
    LedgerArchive::open(&archive_dir).map_err(|e| e.to_string())?;

    let state = Arc::new(HttpState {
        archive_dir,
        operator_pubkey_hex: faster_hex::hex_string(key.public_key()),
        rules: Rules::default(),
        operator_pins: flags.list("pin"),
    });

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        // Stop cleanly on Ctrl-C so the process doesn't wedge (eth-rpc lesson).
        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        misaka_mtp_service::serve_http_with_shutdown(listen, state, shutdown).await.map_err(|e| format!("http server: {e}"))
    })
}

fn cmd_run_epoch(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args, &[])?;
    let data_dir = PathBuf::from(flags.get("data-dir")?);
    let network = network_or_default(&flags)?;
    let stage: Stage = config::stage_for(&network).expect("checked in network_or_default");
    let epoch_n: u64 = flags.get("epoch")?.parse().map_err(|e| format!("bad --epoch: {e}"))?;
    let start = flags.get("start")?.to_string();
    let end = flags.get("end")?.to_string();
    let key = load_operator_key(flags.get("operator-key")?)?;

    let store = PersistentStore::load(data_dir.join("facts")).map_err(|e| e.to_string())?;
    let attr = Attributor::from_records(load_registrations(&data_dir.join("registrations.jsonl"))?);
    let mut archive = LedgerArchive::open(data_dir.join("points")).map_err(|e| e.to_string())?;

    let window = EpochWindow { epoch: epoch_n, range: [start, end], network, stage };
    let ledger = epoch::run_epoch(&store, &attr, &Rules::default(), &key, &window, &mut archive).map_err(|e| e.to_string())?;

    let entry = archive.latest(epoch_n).expect("just published");
    println!(
        "published epoch {} issue {} — {} score rows, digest {} → {}",
        ledger.epoch,
        entry.issue,
        ledger.scores.len(),
        &entry.digest[..16.min(entry.digest.len())],
        entry.file
    );
    Ok(())
}
