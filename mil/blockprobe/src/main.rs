//! `misaka-mil-blockprobe` — first-seen block probe (ADR-0036 §5 filler-block A/B).
//!
//! Run one instance per geo node (JP: .119/.213, DE: .186/207.180.230.3) pointed at
//! that node's wRPC endpoint, each with a distinct `--label`. On every `BlockAdded`
//! it prints one CSV row:
//!
//! ```text
//! label,recv_unix_ms,hash,blue_score,blues,reds,is_chain,evm_payload_len,txs
//! ```
//!
//! Collect the per-node CSVs and join by `hash`: `prop_delay = max(recv_ms) −
//! min(recv_ms)` across nodes is the diameter propagation delay (NTP-sync the boxes,
//! or the delay is only as good as the clock skew); `blues+reds` is the mergeset
//! width and `reds/(blues+reds)` the red rate — the same metrics simpa produced, now
//! on real DE↔JP latency + bandwidth. This tool only *reads* notifications; it never
//! submits or mutates anything.

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use kaspa_consensus_core::network::NetworkId;
use kaspa_notify::scope::{BlockAddedScope, Scope};
use kaspa_rpc_core::Notification;
use kaspa_wrpc_client::prelude::*;
use kaspa_wrpc_client::result::Result;
use workflow_core::channel::{Channel, DuplexChannel, oneshot};
use workflow_core::task::spawn;

pub use futures::FutureExt;

#[derive(Parser, Debug)]
#[command(about = "First-seen block probe for the ADR-0036 §5 testnet filler-block A/B")]
struct Args {
    /// wRPC endpoint of the node to probe, e.g. `ws://127.0.0.1:17610`.
    #[arg(short, long)]
    url: String,
    /// Network id, e.g. `testnet-10`.
    #[arg(short, long, default_value = "testnet-10")]
    network: String,
    /// Short label for this node/geo, e.g. `jp-119` or `de-186`.
    #[arg(short, long)]
    label: String,
}

struct Inner {
    task_ctl: DuplexChannel<()>,
    client: Arc<KaspaRpcClient>,
    is_connected: AtomicBool,
    notification_channel: Channel<Notification>,
    listener_id: Mutex<Option<ListenerId>>,
    label: String,
}

#[derive(Clone)]
struct Probe {
    inner: Arc<Inner>,
}

impl Probe {
    fn try_new(network_id: NetworkId, url: String, label: String) -> Result<Self> {
        let client = Arc::new(KaspaRpcClient::new_with_args(WrpcEncoding::Borsh, Some(url.as_str()), None, Some(network_id), None)?);
        Ok(Self {
            inner: Arc::new(Inner {
                task_ctl: DuplexChannel::oneshot(),
                client,
                is_connected: AtomicBool::new(false),
                notification_channel: Channel::unbounded(),
                listener_id: Mutex::new(None),
                label,
            }),
        })
    }

    fn client(&self) -> &Arc<KaspaRpcClient> {
        &self.inner.client
    }

    fn is_connected(&self) -> bool {
        self.inner.is_connected.load(Ordering::SeqCst)
    }

    async fn start(&self) -> Result<()> {
        self.start_event_task().await?;
        self.client().connect(Some(ConnectOptions { block_async_connect: false, ..Default::default() })).await?;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.client().disconnect().await?;
        self.inner.task_ctl.signal(()).await.expect("stop_event_task signal error");
        Ok(())
    }

    async fn handle_connect(&self) -> Result<()> {
        eprintln!("# connected {} -> {:?}", self.inner.label, self.client().url());
        let listener_id = self.client().rpc_api().register_new_listener(ChannelConnection::new(
            "mil-blockprobe",
            self.inner.notification_channel.sender.clone(),
            ChannelType::Persistent,
        ));
        *self.inner.listener_id.lock().unwrap() = Some(listener_id);
        self.client().rpc_api().start_notify(listener_id, Scope::BlockAdded(BlockAddedScope {})).await?;
        // CSV header (once per node; strip duplicates when merging).
        println!("label,recv_unix_ms,hash,blue_score,blues,reds,is_chain,evm_payload_len,txs");
        self.inner.is_connected.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn handle_disconnect(&self) -> Result<()> {
        eprintln!("# disconnected {}", self.inner.label);
        // Extract the id and DROP the mutex guard before the await (guard is !Send).
        let listener_id = self.inner.listener_id.lock().unwrap().take();
        if let Some(id) = listener_id {
            self.client().rpc_api().unregister_listener(id).await?;
        }
        self.inner.is_connected.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn handle_notification(&self, notification: Notification) {
        // Timestamp FIRST — before any parsing — so the recv time is the earliest.
        let recv_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        if let Notification::BlockAdded(n) = notification {
            let b = &n.block;
            let txs = b.transactions.len();
            let evm_len = b.evm_payload.len();
            match &b.verbose_data {
                Some(v) => println!(
                    "{},{recv_ms},{},{},{},{},{},{evm_len},{txs}",
                    self.inner.label,
                    v.hash,
                    v.blue_score,
                    v.merge_set_blues_hashes.len(),
                    v.merge_set_reds_hashes.len(),
                    v.is_chain_block as u8,
                ),
                // No verbose data on this notification: still record the arrival so the
                // per-node first-seen count is complete (hash/mergeset blank).
                None => println!("{},{recv_ms},,,,,,{evm_len},{txs}", self.inner.label),
            }
        }
    }

    async fn start_event_task(&self) -> Result<()> {
        let probe = self.clone();
        let rpc_ctl_channel = self.client().rpc_ctl().multiplexer().channel();
        let task_ctl_receiver = self.inner.task_ctl.request.receiver.clone();
        let task_ctl_sender = self.inner.task_ctl.response.sender.clone();
        let notification_receiver = self.inner.notification_channel.receiver.clone();

        spawn(async move {
            loop {
                futures::select_biased! {
                    msg = rpc_ctl_channel.receiver.recv().fuse() => {
                        match msg {
                            Ok(RpcState::Connected) => { let _ = probe.handle_connect().await.map_err(|e| eprintln!("# connect err: {e}")); }
                            Ok(RpcState::Disconnected) => { let _ = probe.handle_disconnect().await.map_err(|e| eprintln!("# disconnect err: {e}")); }
                            Err(e) => { eprintln!("# rpc ctl channel closed: {e}"); break; }
                        }
                    }
                    notification = notification_receiver.recv().fuse() => {
                        match notification {
                            Ok(notification) => probe.handle_notification(notification),
                            Err(e) => { eprintln!("# notification channel error: {e}"); break; }
                        }
                    }
                    _ = task_ctl_receiver.recv().fuse() => { break; }
                }
            }
            if probe.is_connected() {
                let _ = probe.handle_disconnect().await;
            }
            let _ = task_ctl_sender.send(()).await;
        });
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let network_id = NetworkId::from_str(&args.network).unwrap_or_else(|e| panic!("bad --network '{}': {e}", args.network));
    let probe = Probe::try_new(network_id, args.url, args.label)?;

    let (shutdown_sender, shutdown_receiver) = oneshot::<()>();
    ctrlc::set_handler(move || {
        let _ = shutdown_sender.try_send(());
    })
    .expect("Ctrl+C handler");

    probe.start().await?;
    shutdown_receiver.recv().await.expect("shutdown signal");
    probe.stop().await?;
    Ok(())
}
