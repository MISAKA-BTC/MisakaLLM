//! Read-only validator views implemented directly in `misaka`.
//!
//! Mutating validator operations still shell out to `kaspa-pq-validator`; this
//! module handles `misaka validator status` so operators can inspect node,
//! bond, and DNS-finality health without needing the sidecar binary on PATH.

use std::str::FromStr;
use std::time::Duration;

use kaspa_consensus_core::network::NetworkId;
use kaspa_rpc_core::{GetStakeBondRequest, api::rpc::RpcApi};
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
};
use serde_json::json;

use crate::node::Ctx;
use crate::{CliError, CliResult, OutputFormat, exit};

#[derive(Debug, Default, PartialEq, Eq)]
struct StatusArgs {
    node_rpc: Option<String>,
    network: Option<String>,
    stake_bond: Option<String>,
}

fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, CliError> {
    *i += 1;
    args.get(*i).cloned().ok_or_else(|| CliError::new(2, format!("{flag} requires a value")))
}

fn parse_status_args(args: &[String]) -> Result<Option<StatusArgs>, CliError> {
    let Some(cmd) = args.first() else {
        return Ok(None);
    };
    if cmd != "status" {
        return Ok(None);
    }

    let mut out = StatusArgs::default();
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-h" || arg == "--help" {
            print_status_help();
            return Err(CliError::new(exit::SUCCESS, ""));
        } else if let Some(v) =
            arg.strip_prefix("--node-rpc=").or_else(|| arg.strip_prefix("--node-wrpc-borsh=")).or_else(|| arg.strip_prefix("--rpc="))
        {
            out.node_rpc = Some(v.to_string());
        } else if arg == "--node-rpc" || arg == "--node-wrpc-borsh" || arg == "--rpc" {
            out.node_rpc = Some(take_value(args, &mut i, arg)?);
        } else if let Some(v) = arg.strip_prefix("--network=").or_else(|| arg.strip_prefix("--network-id=")) {
            out.network = Some(v.to_string());
        } else if arg == "--network" || arg == "--network-id" {
            out.network = Some(take_value(args, &mut i, arg)?);
        } else if let Some(v) = arg.strip_prefix("--stake-bond=") {
            out.stake_bond = Some(v.to_string());
        } else if arg == "--stake-bond" {
            out.stake_bond = Some(take_value(args, &mut i, arg)?);
        } else {
            return Err(CliError::new(2, format!("unknown `misaka validator status` argument: {arg}")));
        }
        i += 1;
    }
    Ok(Some(out))
}

fn print_status_help() {
    println!(
        "Read validator/node status over node wRPC (no sidecar binary required)\n\n\
Usage: misaka validator status [OPTIONS]\n\n\
Options:\n  \
    --node-rpc <HOST:PORT>         Node wRPC Borsh endpoint (alias: --node-wrpc-borsh, --rpc)\n  \
    --network <NETWORK_ID>         Network id for default endpoint resolution (alias: --network-id)\n  \
    --stake-bond <TXID:INDEX>      Stake-bond outpoint to report\n  \
    -h, --help                     Print help\n\n\
Global options such as --output json may be passed before `validator`."
    );
}

async fn connect(network: &str, node_rpc: &Option<String>, timeout_secs: u64) -> Result<KaspaRpcClient, CliError> {
    let net = NetworkId::from_str(network).map_err(|e| CliError::new(exit::GENERIC, format!("bad --network '{network}': {e}")))?;
    let hostport = node_rpc.clone().unwrap_or_else(|| format!("127.0.0.1:{}", net.network_type().default_borsh_rpc_port()));
    let url = format!("ws://{hostport}");
    let client = KaspaRpcClient::new(WrpcEncoding::Borsh, Some(&url), None, None, None)
        .map_err(|e| CliError::new(exit::CONNECTION, format!("build wRPC client: {e}")))?;
    let options = ConnectOptions {
        block_async_connect: true,
        connect_timeout: Some(Duration::from_secs(timeout_secs.clamp(2, 15))),
        strategy: ConnectStrategy::Fallback,
        ..Default::default()
    };
    client
        .connect(Some(options))
        .await
        .map_err(|e| CliError::new(exit::CONNECTION, format!("connect {url}: {e} (node up with --rpclisten-borsh?)")))?;
    Ok(client)
}

fn dns_health_name(health: u32) -> &'static str {
    match health {
        0 => "DisabledBeforeActivation",
        1 => "Active",
        2 => "DegradedStakeQualityLow",
        3 => "DegradedCertificateCensored",
        _ => "Unknown",
    }
}

async fn status(ctx: &Ctx, args: StatusArgs) -> CliResult {
    let network = args.network.as_deref().unwrap_or(&ctx.network);
    let node_rpc = args.node_rpc.or_else(|| ctx.rpc.clone());
    let client = connect(network, &node_rpc, ctx.timeout_secs).await?;
    let server = client.get_server_info().await.map_err(|e| CliError::new(exit::CONNECTION, format!("getServerInfo failed: {e}")))?;

    if ctx.output == OutputFormat::Human {
        println!("node_network: {}", server.network_id);
        println!("node_synced:  {}", server.is_synced);
        println!("node_version: {}", server.server_version);
    }

    let bond_json = if let Some(bond) = &args.stake_bond {
        match client.get_stake_bond(GetStakeBondRequest { bond_outpoint: bond.clone() }).await {
            Ok(b) if b.available => {
                if ctx.output == OutputFormat::Human {
                    println!("bond:         {bond}");
                    println!("bond_status:  {}", b.effective_status);
                    println!("bond_amount:  {}", b.amount);
                    println!("validator_id: {}", b.validator_id);
                }
                json!({
                    "outpoint": bond,
                    "available": true,
                    "status": b.effective_status,
                    "amount": b.amount,
                    "activationDaaScore": b.activation_daa_score,
                    "validatorId": b.validator_id,
                })
            }
            Ok(_) => {
                if ctx.output == OutputFormat::Human {
                    println!("bond:         {bond} (not found in the registry)");
                }
                json!({ "outpoint": bond, "available": false })
            }
            Err(e) => {
                if ctx.output == OutputFormat::Human {
                    println!("bond:         query failed: {e} (does the node configure the overlay?)");
                }
                json!({ "outpoint": bond, "available": false, "error": e.to_string() })
            }
        }
    } else {
        json!(null)
    };

    let dns_resp = client.get_dns_confirmation().await;
    let dns_json = match dns_resp {
        Ok(d) if d.available => {
            let health = dns_health_name(d.health);
            if ctx.output == OutputFormat::Human {
                println!("dns_confirmed: {}", d.dns_confirmed);
                println!("pow_confirmed: {}", d.pow_confirmed);
                println!("work_depth:    {}/{}", d.work_depth, d.required_work_depth);
                println!("stake_depth:   {}/{}", d.stake_depth, d.required_stake_depth);
                println!("dns_health:    {health}");
                println!("dns_anchor:    {} (daa {})", d.last_dns_confirmed_anchor, d.last_dns_confirmed_anchor_daa_score);
            }
            json!({
                "available": true,
                "dnsConfirmed": d.dns_confirmed,
                "powConfirmed": d.pow_confirmed,
                "workDepth": d.work_depth,
                "requiredWorkDepth": d.required_work_depth,
                "stakeDepth": d.stake_depth,
                "requiredStakeDepth": d.required_stake_depth,
                "health": health,
                "healthCode": d.health,
                "anchor": d.last_dns_confirmed_anchor,
                "anchorDaaScore": d.last_dns_confirmed_anchor_daa_score,
            })
        }
        Ok(_) => {
            if ctx.output == OutputFormat::Human {
                println!("dns:          overlay not active on this node");
            }
            json!({ "available": false })
        }
        Err(e) => {
            if ctx.output == OutputFormat::Human {
                println!("dns:          query failed: {e}");
            }
            json!({ "available": false, "error": e.to_string() })
        }
    };

    if ctx.output == OutputFormat::Json {
        println!(
            "{}",
            json!({
                "ok": true,
                "expectedNetwork": network,
                "node": {
                    "network": server.network_id.to_string(),
                    "synced": server.is_synced,
                    "version": server.server_version,
                    "virtualDaaScore": server.virtual_daa_score,
                    "utxoIndex": server.has_utxo_index,
                },
                "bond": bond_json,
                "dns": dns_json,
            })
        );
    }

    let _ = client.disconnect().await;
    Ok(())
}

pub async fn maybe_handle(ctx: &Ctx, args: &[String]) -> Option<CliResult> {
    match parse_status_args(args) {
        Ok(Some(args)) => Some(status(ctx, args).await),
        Ok(None) => None,
        Err(e) if e.code == exit::SUCCESS && e.msg.is_empty() => Some(Ok(())),
        Err(e) => Some(Err(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn ignores_non_status_validator_commands() {
        assert_eq!(parse_status_args(&s(&["bond", "--amount", "1"])).unwrap(), None);
    }

    #[test]
    fn parses_status_aliases() {
        let parsed =
            parse_status_args(&s(&["status", "--node-rpc", "127.0.0.1:27610", "--network-id=testnet-10", "--stake-bond", "abc:0"]))
                .unwrap()
                .unwrap();
        assert_eq!(
            parsed,
            StatusArgs {
                node_rpc: Some("127.0.0.1:27610".to_string()),
                network: Some("testnet-10".to_string()),
                stake_bond: Some("abc:0".to_string()),
            }
        );
    }
}
