//! kaspa-pq ADR-0040: in-process PALW **algo-4 mining** service (`--palw-mine`).
//!
//! The node glue for the real mint path. Each ready tick it asks consensus for the frozen draw inputs,
//! evaluates the leaves this node owns on chain, and — if one wins the interval — builds, authorizes and
//! submits the algo-4 block through the production block path.
//!
//! # The construction order, and why it is not negotiable
//!
//! ADR-0040 (AUTH-02) makes the ticket authorization bind the block's ENTIRE canonical header preimage,
//! with exactly two substitutions: `palw_authorization_hash := 0` and `hash_merkle_root := authed_root`
//! (the root over every transaction EXCEPT the authorization itself). Everything else — parents,
//! coinbase, the transaction set and its order, timestamp, bits, nonce, DAA score, and every PALW header
//! field — is inside the signature. So the block must be COMPLETE before it is signed, and after signing
//! only those two fields may move:
//!
//! ```text
//!  1. pick a winning ticket among the leaves we own       (mining::select_eligible_ticket)
//!  2-5. parents / coinbase / txs+order / timestamp / bits / nonce / DAA / PALW fields
//!                                                          (ConsensusApi::palw_build_algo4_template)
//!  6. authed_root = merkle over the txs EXCLUDING the authorization
//!  7. authorize                                            (TicketAuthority::authorize_for_leaf)
//!  8-9. append the canonical 0x38 tx as the LAST transaction
//! 10. recompute hash_merkle_root over ALL txs
//! 11. stamp header.palw_authorization_hash
//! 12. finalize — and touch nothing else
//! 13. submit
//! ```
//!
//! Steps 8-12 are the dangerous part: appending, sorting, re-selecting transactions, retargeting the
//! coinbase, or recomputing any virtual-derived commitment after step 7 silently invalidates the
//! signature. The compiler cannot see it and the block simply gets rejected. `debug_assert`s at the end
//! of [`PalwMineService::try_mine_once`] re-check the binding before submission so a mistake here fails
//! loudly in tests rather than quietly in production.
//!
//! # Why a lost interval is not a retry
//!
//! A PALW ticket is one leaf, one nullifier, one draw per DAA interval. The nullifier is fixed by the
//! commitment the leaf published at registration and cannot be re-rolled (clause 1). So every
//! precondition that could make a win unmintable is checked BEFORE the draw: the ticket authority key is
//! required at startup, leaves whose authority we cannot sign for are filtered out, and the lane-closed
//! (clause 10) case aborts before drawing.
//!
//! # Scope
//!
//! * **Default off**, registered only with `--palw-mine`, and requires `--palw-ticket-authority-key-file`
//!   plus `--palw-ticket-secret-file` (both enforced at startup).
//! * **Inert on shipped presets.** `palw_algo4_accept` is `false` on all six, so a mined algo-4 block is
//!   rejected with `RuleError::PalwAlgo4NotAccepted` unless the operator also passes
//!   `--palw-enable-algo4`. That flag is a per-node runtime override of a consensus rule; two nodes on
//!   one network passing different values will diverge. Do not use it on a shared network.
//! * **No seeded provenance.** The leaf comes from `palw_store` and the batch's eligibility from the
//!   overlay view. This service cannot mint a leaf nobody registered.
//! * **Weightless.** `palw_compute_work_scale = 0` on the PALW presets: accepted and measured, no
//!   fork-choice weight.

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::coinbase::MinerData;
use kaspa_consensus_core::merkle::calc_hash_merkle_root;
use kaspa_consensus_core::palw_mint::{PalwAlgo4Stamp, PalwMintError};
use kaspa_consensusmanager::ConsensusManager;
use kaspa_core::{
    info,
    task::{
        service::{AsyncService, AsyncServiceFuture},
        tick::{TickReason, TickService},
    },
    trace, warn,
};
use kaspa_hashes::Hash64;
use kaspa_p2p_flows::flow_context::FlowContext;
use kaspa_pq_validator_core::{TicketSecretStore, ValidatorKey, load_validator_seed};
use kaspa_txscript::pay_to_address_script;
use misaka_palw_miner::PROOF_TYPE_REPLICA_EXACT_V1;
use misaka_palw_miner::authorization::TicketAuthority;
use misaka_palw_miner::mining::{EligibilityContext, OwnedTicket, evaluate_ticket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PALW_MINE: &str = "palw-mine-service";

/// Attempt cadence. The loop only mints when the sink has advanced, so a short tick just keeps latency
/// low without producing sibling blocks off one sink.
const MINE_TICK_SECS: u64 = 5;

/// Static `--palw-mine` configuration derived from CLI args.
#[derive(Debug, Clone)]
pub struct PalwMineConfig {
    /// `--palw-mine-address`: the coinbase / payout target. A DIFFERENT role from the ticket authority.
    pub address: Option<String>,
    pub address_prefix: Prefix,
    /// Whether the running network's PALW lane is active. `false` ⇒ inert no-op.
    pub palw_active: bool,
    /// `--palw-ticket-authority-key-file`: the ML-DSA-87 seed clause 7 requires signatures from.
    pub ticket_authority_key_path: Option<String>,
    /// `--palw-ticket-secret-file`: where registration-time raw nullifiers live.
    pub ticket_secret_path: Option<PathBuf>,
    /// `--palw-leaf`: the on-chain leaves this node claims, as `(batch_id, leaf_index)`.
    pub owned_leaves: Vec<(Hash64, u32)>,
}

/// Parse a `--palw-leaf` value of the form `<batch_id_hex>:<leaf_index>`.
pub fn parse_leaf_ref(s: &str) -> Result<(Hash64, u32), String> {
    let (batch_hex, index) = s.rsplit_once(':').ok_or_else(|| format!("--palw-leaf '{s}' must be <batch_id_hex>:<leaf_index>"))?;
    let mut bytes = [0u8; 64];
    faster_hex::hex_decode(batch_hex.as_bytes(), &mut bytes)
        .map_err(|e| format!("--palw-leaf '{s}': batch_id must be 128 hex chars (64 bytes): {e}"))?;
    let leaf_index = index.parse::<u32>().map_err(|e| format!("--palw-leaf '{s}': bad leaf index: {e}"))?;
    Ok((Hash64::from_bytes(bytes), leaf_index))
}

/// Validate `address` as an ML-DSA-87 P2PKH address on `prefix` and build the coinbase [`MinerData`].
fn resolve_miner_data(address: &str, prefix: Prefix) -> Result<MinerData, String> {
    let addr = Address::try_from(address).map_err(|e| format!("invalid --palw-mine-address '{address}': {e}"))?;
    if addr.prefix != prefix {
        return Err(format!("--palw-mine-address prefix {} does not match this network's prefix {prefix}", addr.prefix));
    }
    if addr.version != Version::PubKeyHashMlDsa87 {
        return Err("--palw-mine-address must be an ML-DSA-87 P2PKH (PubKeyHashMlDsa87) address — a non-PQ coinbase script is rejected by the PQ-only rule".to_owned());
    }
    Ok(MinerData::new(pay_to_address_script(&addr), Vec::new()))
}

/// Load the ticket authority from its seed file.
///
/// The seed is zeroed as soon as the key is materialised: it stays in this frame only long enough to
/// derive the ML-DSA-87 keypair. Nothing about the key — not the seed, not the public key, not the
/// path's contents — is ever logged; only the path itself and a short pk-hash prefix, so an operator can
/// tell WHICH authority is loaded without the log disclosing it.
fn load_ticket_authority(path: &str) -> Result<TicketAuthority, String> {
    let mut seed = load_validator_seed(path)?;
    let authority = TicketAuthority::new(ValidatorKey::from_seed(seed));
    seed.fill(0);
    Ok(authority)
}

pub struct PalwMineService {
    consensus_manager: Arc<ConsensusManager>,
    tick_service: Arc<TickService>,
    flow_context: Arc<FlowContext>,
    miner_data: Option<MinerData>,
    palw_active: bool,
    /// The clause-7 signing key. `None` ⇒ inert (the daemon refuses to start in this state when
    /// `--palw-mine` is set, so this is only `None` on a load failure worth surfacing).
    authority: Option<Arc<TicketAuthority>>,
    /// Registration-time nullifiers, keyed by `(batch_id, leaf_index)`.
    secrets: Option<Mutex<TicketSecretStore>>,
    owned_leaves: Vec<(Hash64, u32)>,
    /// The last sink a block was successfully minted off, so successive ready ticks do not produce
    /// sibling algo-4 blocks off a single sink.
    last_mined_sink: Mutex<Option<BlockHash>>,
}

impl PalwMineService {
    pub fn new(
        config: PalwMineConfig,
        consensus_manager: Arc<ConsensusManager>,
        tick_service: Arc<TickService>,
        flow_context: Arc<FlowContext>,
    ) -> Self {
        let miner_data = match &config.address {
            Some(addr) => match resolve_miner_data(addr, config.address_prefix) {
                Ok(md) => {
                    info!("[{PALW_MINE}] paying coinbase to {addr}");
                    Some(md)
                }
                Err(err) => {
                    warn!("[{PALW_MINE}] {err} — mining disabled");
                    None
                }
            },
            None => {
                warn!("[{PALW_MINE}] --palw-mine is set but --palw-mine-address is missing — mining disabled");
                None
            }
        };

        // AUTH-03: the clause-7 signing key. Without it every won interval is wasted, so a load failure
        // disables mining rather than letting the loop draw tickets it cannot authorize.
        let authority = match &config.ticket_authority_key_path {
            Some(path) => match load_ticket_authority(path) {
                Ok(a) => {
                    let pk = a.pk_hash();
                    info!(
                        "[{PALW_MINE}] ticket authority loaded from {path} (pk_hash {})",
                        &format!("{pk:?}")[..18.min(format!("{pk:?}").len())]
                    );
                    Some(Arc::new(a))
                }
                Err(err) => {
                    warn!("[{PALW_MINE}] cannot load the ticket authority key: {err} — mining disabled");
                    None
                }
            },
            None => {
                warn!("[{PALW_MINE}] --palw-ticket-authority-key-file is missing — mining disabled");
                None
            }
        };

        // C-1: the raw nullifiers. Bound to the authority so a foreign file is refused.
        let secrets = match (&config.ticket_secret_path, &authority) {
            (Some(path), Some(a)) => match TicketSecretStore::load_or_empty(path.clone(), a.pk_hash()) {
                Ok(s) => {
                    info!("[{PALW_MINE}] ticket-secret store {} holds {} secret(s)", path.display(), s.len());
                    Some(Mutex::new(s))
                }
                Err(err) => {
                    warn!("[{PALW_MINE}] cannot open the ticket-secret store: {err} — mining disabled");
                    None
                }
            },
            _ => None,
        };

        if !config.palw_active {
            warn!(
                "[{PALW_MINE}] the PALW lane is INACTIVE on this network (palw_activation_daa_score = u64::MAX); \
                 --palw-mine is a no-op here. Run --testnet --netsuffix=110 (testnet-palw) or --devnet \
                 --netsuffix=111 (devnet-palw) to mine algo-4 blocks."
            );
        }
        if config.owned_leaves.is_empty() {
            warn!("[{PALW_MINE}] no --palw-leaf given — this node owns no tickets and will mint nothing");
        }

        Self {
            consensus_manager,
            tick_service,
            flow_context,
            miner_data,
            palw_active: config.palw_active,
            authority,
            secrets,
            owned_leaves: config.owned_leaves,
            last_mined_sink: Mutex::new(None),
        }
    }

    pub async fn worker(self: &Arc<PalwMineService>) {
        info!(
            "[{PALW_MINE}] starting (palw_active={}, payout={}, authority={}, tickets={})",
            self.palw_active,
            self.miner_data.is_some(),
            self.authority.is_some(),
            self.owned_leaves.len()
        );
        loop {
            if let TickReason::Shutdown = self.tick_service.tick(Duration::from_secs(MINE_TICK_SECS)).await {
                break;
            }
            let Some(miner_data) = self.miner_data.clone() else { continue };
            let Some(authority) = self.authority.clone() else { continue };
            if !self.palw_active || self.secrets.is_none() || self.owned_leaves.is_empty() {
                continue;
            }
            if let Err(err) = self.try_mine_once(miner_data, authority).await {
                match err {
                    PalwMintError::NotReady(m) => trace!("[{PALW_MINE}] not ready: {m}"),
                    PalwMintError::Fault(m) => warn!("[{PALW_MINE}] mint fault: {m}"),
                }
            }
        }
        info!("[{PALW_MINE}] stopped");
    }

    /// One attempt at the 13-step construction order. See the module docs.
    async fn try_mine_once(
        self: &Arc<PalwMineService>,
        miner_data: MinerData,
        authority: Arc<TicketAuthority>,
    ) -> Result<(), PalwMintError> {
        let sink = self.consensus_manager.consensus().unguarded_session().async_get_sink().await;
        if *self.last_mined_sink.lock().unwrap() == Some(sink) {
            return Ok(()); // already mined off this sink; wait for it to advance
        }

        // ---- Step 1: find a ticket that wins THIS interval ----
        //
        // One facts call per owned leaf. The draw inputs (beacon seed, chain commit, interval, bits) do
        // not depend on the leaf, but the batch's block-eligibility and certificate hash do, so the leaf
        // has to be named. With a handful of leaves this is fine; a miner holding many should get a
        // batched facts call rather than N template builds per tick.
        let mut winner: Option<(PalwAlgo4Stamp, Hash64)> = None; // (stamp, leaf authority pk_hash)
        for (batch_id, leaf_index) in self.owned_leaves.iter().copied() {
            let Some(raw_nullifier) = self.secrets.as_ref().and_then(|s| s.lock().unwrap().secret_for(&batch_id, leaf_index)) else {
                trace!("[{PALW_MINE}] no stored nullifier for {batch_id:?}:{leaf_index} — cannot open its commitment");
                continue;
            };

            let session = self.consensus_manager.consensus().session().await;
            let md = miner_data.clone();
            let facts = match session.spawn_blocking(move |c| c.palw_algo4_mint_facts(batch_id, leaf_index, md)).await {
                Ok(f) => f,
                Err(PalwMintError::NotReady(m)) => {
                    trace!("[{PALW_MINE}] {batch_id:?}:{leaf_index} not ready: {m}");
                    continue;
                }
                Err(e) => return Err(e),
            };

            // Clause 10: refuse to draw at all while the lane is closed. Winning here would consume the
            // ticket's single draw on a block the node's own body check rejects.
            if !facts.lane_open {
                return Err(PalwMintError::not_ready("lane closed (clause 10) — not drawing"));
            }

            let ctx = EligibilityContext {
                network_id: facts.network_id,
                beacon_seed: facts.beacon_seed,
                chain_commit: facts.chain_commit,
                target_daa_interval: facts.target_daa_interval,
                replica_bits: facts.replica_bits,
            };
            // AUTH-03 filter BEFORE the draw: a leaf naming an authority we do not hold can never be
            // authorized, so drawing it would spend the interval for nothing.
            if facts.leaf.ticket_authority_pk_hash != authority.pk_hash() {
                trace!("[{PALW_MINE}] {batch_id:?}:{leaf_index} names another ticket authority — skipping");
                continue;
            }
            let ticket = OwnedTicket { leaf: facts.leaf.clone(), raw_nullifier };
            if evaluate_ticket(&ctx, &ticket).is_some() {
                winner = Some((
                    PalwAlgo4Stamp {
                        sink: facts.sink,
                        batch_id,
                        leaf_index,
                        ticket_nullifier: raw_nullifier,
                        epoch_certificate_hash: facts.epoch_certificate_hash,
                        chain_commit: facts.chain_commit,
                        target_daa_interval: facts.target_daa_interval,
                        proof_type: PROOF_TYPE_REPLICA_EXACT_V1,
                        replica_bits: facts.replica_bits,
                    },
                    facts.leaf.ticket_authority_pk_hash,
                ));
                break;
            }
        }
        let Some((stamp, leaf_authority)) = winner else {
            return Ok(()); // no ticket won this interval — the common case
        };

        // ---- Steps 2-5: the complete, unsigned block ----
        let session = self.consensus_manager.consensus().session().await;
        let md = miner_data.clone();
        let stamp_for_build = stamp.clone();
        let mut mb =
            session.spawn_blocking(move |c| c.palw_build_algo4_template(md, Box::new(EmptySelector), stamp_for_build)).await?;

        // ---- Step 6: the root over every tx EXCEPT the authorization ----
        let authed_root = calc_hash_merkle_root(mb.transactions.iter());

        // ---- Step 7: authorize. Every header field is final at this point. ----
        let binding = misaka_palw_miner::authorization::BlockAuthorizationBinding {
            network_id: self.network_id(),
            header: mb.header.clone(),
            authed_hash_merkle_root: authed_root,
        };
        let authorized = authority
            .authorize_for_leaf(&binding, &leaf_authority)
            .map_err(|e| PalwMintError::fault(format!("authorization refused: {e}")))?;

        // ---- Steps 8-9: the canonical 0x38 tx, appended LAST. Nothing may follow. ----
        mb.transactions.push(authorized.carrying_transaction());

        // ---- Steps 10-12: the two fields the commitment substitutes, then finalize. ----
        mb.header.hash_merkle_root = calc_hash_merkle_root(mb.transactions.iter());
        mb.header.palw_authorization_hash = authorized.authorization_hash;
        mb.header.finalize();

        // The signature is over a CLONE of the header taken at step 7. Nothing above may have touched
        // any other field, and the compiler cannot check that — so check it here, before submission.
        debug_assert!(
            authorized.auth.binds_header(binding.network_id, &mb.header, &authed_root),
            "AUTH-02: a header field changed after signing — the block would be rejected by clause 7"
        );

        // ---- Step 13: submit through the production path (validate_and_insert_block + gossip). ----
        let block = mb.to_immutable();
        let hash = block.hash();
        let submit_session = self.consensus_manager.consensus().unguarded_session();
        match self.flow_context.submit_rpc_block(&submit_session, block).await {
            Ok(()) => {
                info!("[{PALW_MINE}] mined + submitted algo-4 block {hash} off sink {sink}");
                *self.last_mined_sink.lock().unwrap() = Some(sink);
                Ok(())
            }
            Err(err) => Err(PalwMintError::fault(format!("submit of algo-4 block {hash} failed: {err}"))),
        }
    }

    /// The PALW network number every preimage binds.
    fn network_id(&self) -> u32 {
        self.flow_context.config.params.net.suffix().unwrap_or(0)
    }
}

/// Yields nothing — a coinbase-only algo-4 block.
///
/// A real transaction selector must RESERVE block mass for the authorization transaction: its ML-DSA-87
/// public key (2592 B) and signature (4627 B) make it roughly 7.3 KB, and `check_block_mass` recomputes
/// compute/transient mass from the transaction bytes (the declared `mass = 0` only suppresses the
/// storage-mass term). A selector that fills the block to `max_block_mass` and then has this appended
/// produces `ExceedsComputeMassLimit`. Coinbase-only sidesteps that entirely, which is why this is what
/// ships until the mempool path is wired.
struct EmptySelector;
impl kaspa_consensus_core::block::TemplateTransactionSelector for EmptySelector {
    fn select_transactions(&mut self) -> Vec<kaspa_consensus_core::tx::Transaction> {
        vec![]
    }
    fn reject_selection(&mut self, _tx_id: kaspa_consensus_core::tx::TransactionId) {}
    fn is_successful(&self) -> bool {
        true
    }
}

impl AsyncService for PalwMineService {
    fn ident(self: Arc<Self>) -> &'static str {
        PALW_MINE
    }

    fn start(self: Arc<Self>) -> AsyncServiceFuture {
        Box::pin(async move {
            self.worker().await;
            Ok(())
        })
    }

    fn signal_exit(self: Arc<Self>) {
        trace!("sending an exit signal to {}", PALW_MINE);
    }

    fn stop(self: Arc<Self>) -> AsyncServiceFuture {
        Box::pin(async move {
            trace!("{} stopped", PALW_MINE);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miner_data_requires_mldsa87_address_on_the_right_prefix() {
        assert!(resolve_miner_data("not-an-address", Prefix::Testnet).is_err());
        let addr = Address::new(Prefix::Testnet, Version::PubKeyHashMlDsa87, &[0u8; 64]);
        let s = addr.to_string();
        assert!(resolve_miner_data(&s, Prefix::Testnet).is_ok(), "matching prefix + ML-DSA-87 accepted");
        assert!(resolve_miner_data(&s, Prefix::Mainnet).is_err(), "wrong prefix rejected");
    }

    /// `--palw-leaf` names an on-chain coordinate; a malformed one must not silently become leaf 0 of
    /// some other batch.
    #[test]
    fn leaf_refs_parse_exactly_or_not_at_all() {
        let hex = "ab".repeat(64);
        let (batch, idx) = parse_leaf_ref(&format!("{hex}:7")).expect("well-formed");
        assert_eq!(batch, Hash64::from_bytes([0xab; 64]));
        assert_eq!(idx, 7);

        assert!(parse_leaf_ref(&hex).is_err(), "missing index");
        assert!(parse_leaf_ref(&format!("{hex}:")).is_err(), "empty index");
        assert!(parse_leaf_ref(&format!("{hex}:x")).is_err(), "non-numeric index");
        assert!(parse_leaf_ref("dead:0").is_err(), "short batch id");
        assert!(parse_leaf_ref(&format!("{}:0", "zz".repeat(64))).is_err(), "non-hex batch id");
    }
}
