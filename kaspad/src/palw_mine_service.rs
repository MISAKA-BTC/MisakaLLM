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
//! required at startup, a configured leaf naming another authority faults explicitly, and the
//! lane-closed (clause 10) case aborts before drawing.
//!
//! # Scope
//!
//! * **Default off**, registered only with `--palw-mine`, and requires a network-correct ML-DSA-87
//!   payout address, the ticket-authority seed, an existing authority-bound ticket-secret store, at
//!   least one owned leaf, and `--palw-enable-algo4`. All are enforced before daemon startup.
//! * **PALW presets only.** Inactive networks are refused rather than starting an inert service. The
//!   acceptance flag is a per-node runtime override of a consensus rule; two nodes on one network
//!   passing different values will diverge. Do not use it on a public or value-bearing network.
//! * **No seeded provenance.** The leaf comes from `palw_store` and the batch's eligibility from the
//!   overlay view. This service cannot mint a leaf nobody registered.
//! * **Weightless.** `palw_compute_work_scale = 0` on the PALW presets: accepted and measured, no
//!   fork-choice weight.

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::coinbase::MinerData;
use kaspa_consensus_core::merkle::calc_hash_merkle_root;
use kaspa_consensus_core::palw::ticket_nullifier_commitment;
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

/// Logging severity is part of the miner's operational contract: an ordinary not-yet-eligible tick
/// must not flood operator warnings, while infrastructure/authorization faults must remain loud.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MintErrorLogClass {
    QuietTrace,
    FaultWarning,
}

fn mint_error_log_class(error: &PalwMintError) -> MintErrorLogClass {
    match error {
        PalwMintError::NotReady(_) => MintErrorLogClass::QuietTrace,
        PalwMintError::Fault(_) => MintErrorLogClass::FaultWarning,
    }
}

fn log_mint_error(error: PalwMintError) {
    match (mint_error_log_class(&error), error) {
        (MintErrorLogClass::QuietTrace, PalwMintError::NotReady(message)) => {
            trace!("[{PALW_MINE}] not ready: {message}")
        }
        (MintErrorLogClass::FaultWarning, PalwMintError::Fault(message)) => {
            warn!("[{PALW_MINE}] mint fault: {message}")
        }
        _ => unreachable!("PALW mint-error classifier and logger match must stay exhaustive and aligned"),
    }
}

/// Attempt cadence. The loop only mints when the sink has advanced, so a short tick just keeps latency
/// low without producing sibling blocks off one sink.
const MINE_TICK_SECS: u64 = 5;

/// Static `--palw-mine` configuration derived from CLI args.
#[derive(Debug, Clone)]
pub struct PalwMineConfig {
    /// `--palw-mine-address`: the coinbase / payout target. A DIFFERENT role from the ticket authority.
    pub address: Option<String>,
    pub address_prefix: Prefix,
    /// Whether the running network's PALW lane is active. `false` is rejected by startup preflight.
    pub palw_active: bool,
    /// `--palw-ticket-authority-key-file`: the ML-DSA-87 seed clause 7 requires signatures from.
    pub ticket_authority_key_path: Option<String>,
    /// `--palw-ticket-secret-file`: where registration-time raw nullifiers live.
    pub ticket_secret_path: Option<PathBuf>,
    /// `--palw-leaf`: the on-chain leaves this node claims, as `(batch_id, leaf_index)`.
    pub owned_leaves: Vec<(Hash64, u32)>,
}

/// A [`PalwMineConfig`] after the daemon's fail-closed startup preflight.
///
/// Keeping the service's required inputs non-optional makes an apparently-running but permanently
/// inert miner unrepresentable. In particular, `TicketSecretStore::load_or_empty` deliberately creates
/// an empty in-memory store for registration workflows, so the mining preflight must first prove that
/// the configured file already exists and then prove every configured leaf has a key in it.
pub struct PreparedPalwMineConfig {
    payout_address: String,
    miner_data: MinerData,
    authority_key_path: String,
    authority: Arc<TicketAuthority>,
    ticket_secret_path: PathBuf,
    secrets: TicketSecretStore,
    owned_leaves: Vec<(Hash64, u32)>,
}

impl PalwMineConfig {
    /// Materialise and validate every input the mining worker needs before the daemon starts.
    ///
    /// The on-chain leaf is not available until consensus starts, so startup can prove store-key
    /// presence but cannot compare the raw nullifier with the leaf commitment yet. The worker performs
    /// that comparison explicitly as soon as mint facts expose the leaf.
    pub fn prepare(self) -> Result<PreparedPalwMineConfig, String> {
        if !self.palw_active {
            return Err(
                "--palw-mine requires an active PALW preset (testnet --netsuffix=110 or devnet --netsuffix=111)"
                    .to_owned(),
            );
        }

        let payout_address = self.address.ok_or_else(|| "--palw-mine-address is missing".to_owned())?;
        let miner_data = resolve_miner_data(&payout_address, self.address_prefix)?;

        let authority_key_path = self
            .ticket_authority_key_path
            .ok_or_else(|| "--palw-ticket-authority-key-file is missing".to_owned())?;
        let authority = Arc::new(load_ticket_authority(&authority_key_path)?);

        let ticket_secret_path = self.ticket_secret_path.ok_or_else(|| "--palw-ticket-secret-file is missing".to_owned())?;
        let secret_metadata = std::fs::symlink_metadata(&ticket_secret_path).map_err(|err| {
            format!(
                "ticket-secret store {} must already exist before --palw-mine starts: {err}",
                ticket_secret_path.display()
            )
        })?;
        if !secret_metadata.file_type().is_file() {
            return Err(format!(
                "ticket-secret store {} is not a regular file (symlink/device/fifo refused)",
                ticket_secret_path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = secret_metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "ticket-secret store {} is group/world-accessible (mode {mode:o}); restrict it to 0600 (chmod 600)",
                    ticket_secret_path.display()
                ));
            }
        }

        let secrets = TicketSecretStore::load_or_empty(ticket_secret_path.clone(), authority.pk_hash())?;
        if self.owned_leaves.is_empty() {
            return Err("at least one --palw-leaf=<batch_id>:<leaf_index> is required".to_owned());
        }
        for (batch_id, leaf_index) in self.owned_leaves.iter().copied() {
            if secrets.secret_for(&batch_id, leaf_index).is_none() {
                return Err(format!(
                    "ticket-secret store {} has no secret for configured --palw-leaf {batch_id:?}:{leaf_index}",
                    ticket_secret_path.display()
                ));
            }
        }

        Ok(PreparedPalwMineConfig {
            payout_address,
            miner_data,
            authority_key_path,
            authority,
            ticket_secret_path,
            secrets,
            owned_leaves: self.owned_leaves,
        })
    }
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
    miner_data: MinerData,
    /// The clause-7 signing key, materialised during startup preflight.
    authority: Arc<TicketAuthority>,
    /// Registration-time nullifiers, keyed by `(batch_id, leaf_index)`.
    secrets: Mutex<TicketSecretStore>,
    owned_leaves: Vec<(Hash64, u32)>,
    /// The last sink a block was successfully minted off, so successive ready ticks do not produce
    /// sibling algo-4 blocks off a single sink.
    last_mined_sink: Mutex<Option<BlockHash>>,
}

impl PalwMineService {
    pub fn new(
        config: PreparedPalwMineConfig,
        consensus_manager: Arc<ConsensusManager>,
        tick_service: Arc<TickService>,
        flow_context: Arc<FlowContext>,
    ) -> Self {
        info!("[{PALW_MINE}] paying coinbase to {}", config.payout_address);
        let pk = config.authority.pk_hash();
        let formatted_pk = format!("{pk:?}");
        info!(
            "[{PALW_MINE}] ticket authority loaded from {} (pk_hash {})",
            config.authority_key_path,
            &formatted_pk[..18.min(formatted_pk.len())]
        );
        info!(
            "[{PALW_MINE}] ticket-secret store {} holds {} secret(s)",
            config.ticket_secret_path.display(),
            config.secrets.len()
        );

        Self {
            consensus_manager,
            tick_service,
            flow_context,
            miner_data: config.miner_data,
            authority: config.authority,
            secrets: Mutex::new(config.secrets),
            owned_leaves: config.owned_leaves,
            last_mined_sink: Mutex::new(None),
        }
    }

    pub async fn worker(self: &Arc<PalwMineService>) {
        info!("[{PALW_MINE}] starting (tickets={})", self.owned_leaves.len());
        loop {
            if let TickReason::Shutdown = self.tick_service.tick(Duration::from_secs(MINE_TICK_SECS)).await {
                break;
            }
            let miner_data = self.miner_data.clone();
            let authority = self.authority.clone();
            if let Err(err) = self.try_mine_once(miner_data, authority).await {
                log_mint_error(err);
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
            let raw_nullifier = self
                .secrets
                .lock()
                .unwrap()
                .secret_for(&batch_id, leaf_index)
                .expect("startup preflight requires a secret for every owned PALW leaf");

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
            // AUTH-03 check BEFORE the draw: a leaf naming an authority we do not hold can never be
            // authorized, so drawing it would spend the interval for nothing.
            if facts.leaf.ticket_authority_pk_hash != authority.pk_hash() {
                return Err(PalwMintError::fault(format!(
                    "configured leaf {batch_id:?}:{leaf_index} names another ticket authority"
                )));
            }
            if ticket_nullifier_commitment(&raw_nullifier) != facts.leaf.ticket_nullifier_commitment {
                return Err(PalwMintError::fault(format!(
                    "stored nullifier for {batch_id:?}:{leaf_index} does not open the on-chain leaf commitment"
                )));
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

    fn write_seed(path: &std::path::Path, seed: [u8; 32]) {
        std::fs::write(path, faster_hex::hex_string(&seed)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn mine_config(
        payout_address: &str,
        seed_path: &std::path::Path,
        secret_path: &std::path::Path,
        owned_leaves: Vec<(Hash64, u32)>,
    ) -> PalwMineConfig {
        PalwMineConfig {
            address: Some(payout_address.to_owned()),
            address_prefix: Prefix::Testnet,
            palw_active: true,
            ticket_authority_key_path: Some(seed_path.display().to_string()),
            ticket_secret_path: Some(secret_path.to_path_buf()),
            owned_leaves,
        }
    }

    fn prepare_error(config: PalwMineConfig) -> String {
        match config.prepare() {
            Ok(_) => panic!("PALW mining preflight unexpectedly accepted invalid configuration"),
            Err(err) => err,
        }
    }

    #[test]
    fn mint_error_classification_quiets_expected_preconditions() {
        assert_eq!(
            mint_error_log_class(&PalwMintError::not_ready("batch is not active yet")),
            MintErrorLogClass::QuietTrace
        );
        assert_eq!(
            mint_error_log_class(&PalwMintError::fault("ticket authority mismatch")),
            MintErrorLogClass::FaultWarning
        );
    }

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

    #[test]
    fn mining_preflight_requires_existing_authority_bound_secrets_for_every_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let seed = [0x11; 32];
        let seed_path = dir.path().join("authority.seed");
        write_seed(&seed_path, seed);
        let payout_address = ValidatorKey::from_seed([0x22; 32]).funding_address(Prefix::Testnet).to_string();
        let batch = Hash64::from_bytes([0x33; 64]);
        let nullifier = Hash64::from_bytes([0x44; 64]);

        let absent_path = dir.path().join("absent-ticket-secrets.json");
        let err = prepare_error(mine_config(&payout_address, &seed_path, &absent_path, vec![(batch, 0)]));
        assert!(err.contains("must already exist"), "{err}");

        let foreign_path = dir.path().join("foreign-ticket-secrets.json");
        let foreign_authority = TicketAuthority::from_seed([0x55; 32]);
        let mut foreign_store = TicketSecretStore::load_or_empty(foreign_path.clone(), foreign_authority.pk_hash()).unwrap();
        foreign_store.record_and_flush(batch, 0, nullifier).unwrap();
        let err = prepare_error(mine_config(&payout_address, &seed_path, &foreign_path, vec![(batch, 0)]));
        assert!(err.contains("different ticket authority"), "{err}");

        let authority = TicketAuthority::from_seed(seed);
        let store_path = dir.path().join("ticket-secrets.json");
        let mut store = TicketSecretStore::load_or_empty(store_path.clone(), authority.pk_hash()).unwrap();
        store.record_and_flush(batch, 0, nullifier).unwrap();
        let err = prepare_error(mine_config(&payout_address, &seed_path, &store_path, vec![(batch, 0), (batch, 1)]));
        assert!(err.contains("has no secret"), "{err}");
        assert!(err.contains(":1"), "{err}");

        let prepared = mine_config(&payout_address, &seed_path, &store_path, vec![(batch, 0)])
            .prepare()
            .unwrap_or_else(|err| panic!("valid PALW mining preflight failed: {err}"));
        assert_eq!(prepared.authority.pk_hash(), authority.pk_hash());
        assert_eq!(prepared.secrets.secret_for(&batch, 0), Some(nullifier));
        assert_eq!(prepared.owned_leaves, vec![(batch, 0)]);
    }
}
