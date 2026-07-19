use crate::{consensus::test_consensus::TestConsensus, constants::TX_VERSION, model::services::reachability::ReachabilityService};
use kaspa_consensus_core::BlockHash;
use kaspa_consensus_core::{
    BlockHashSet,
    api::ConsensusApi,
    block::{Block, BlockTemplate, MutableBlock, TemplateBuildMode, TemplateTransactionSelector},
    blockhash,
    blockstatus::BlockStatus,
    coinbase::MinerData,
    config::{
        ConfigBuilder,
        params::{DEVNET_PARAMS, MAINNET_PARAMS},
    },
    dns_finality::p2pkh_mldsa87_spk,
    subnets::SUBNETWORK_ID_PALW_BEACON_COMMIT,
    tx::{Transaction, TransactionOutpoint},
};
use std::{collections::VecDeque, thread::JoinHandle};

struct OnetimeTxSelector {
    txs: Option<Vec<Transaction>>,
    rejected: bool,
}

impl OnetimeTxSelector {
    fn new(txs: Vec<Transaction>) -> Self {
        Self { txs: Some(txs), rejected: false }
    }
}

impl TemplateTransactionSelector for OnetimeTxSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        // First call returns the fixed set; subsequent calls (the builder's
        // rejection re-selection loop) return empty so the loop terminates
        // instead of unwrapping `None`.
        self.txs.take().unwrap_or_default()
    }

    fn reject_selection(&mut self, _tx_id: kaspa_consensus_core::tx::TransactionId) {
        // Record the rejection so `is_successful` reports failure and
        // `build_block_template` surfaces the per-tx `RuleError` (instead of
        // panicking or silently dropping the tx).
        self.rejected = true;
    }

    fn is_successful(&self) -> bool {
        !self.rejected
    }
}

struct TestContext {
    consensus: TestConsensus,
    join_handles: Vec<JoinHandle<()>>,
    miner_data: MinerData,
    simulated_time: u64,
    current_templates: VecDeque<BlockTemplate>,
    current_tips: BlockHashSet,
}

impl Drop for TestContext {
    fn drop(&mut self) {
        self.consensus.shutdown(std::mem::take(&mut self.join_handles));
    }
}

impl TestContext {
    fn new(consensus: TestConsensus) -> Self {
        let join_handles = consensus.init();
        let genesis_hash = consensus.params().genesis.hash;
        let simulated_time = consensus.params().genesis.timestamp;
        Self {
            consensus,
            join_handles,
            miner_data: new_miner_data(),
            simulated_time,
            current_templates: Default::default(),
            current_tips: BlockHashSet::from_iter([genesis_hash]),
        }
    }

    pub fn build_block_template_row(&mut self, nonces: impl Iterator<Item = usize>) -> &mut Self {
        for nonce in nonces {
            self.simulated_time += self.consensus.params().target_time_per_block();
            self.current_templates.push_back(self.build_block_template(nonce as u64, self.simulated_time));
        }
        self
    }

    pub fn assert_row_parents(&mut self) -> &mut Self {
        for t in self.current_templates.iter() {
            assert_eq!(self.current_tips, BlockHashSet::from_iter(t.block.header.direct_parents().iter().copied()));
        }
        self
    }

    pub async fn validate_and_insert_row(&mut self) -> &mut Self {
        self.current_tips.clear();
        while let Some(t) = self.current_templates.pop_front() {
            self.current_tips.insert(t.block.header.hash);
            self.validate_and_insert_block(t.block.to_immutable()).await;
        }
        self
    }

    pub async fn build_and_insert_disqualified_chain(&mut self, mut parents: Vec<BlockHash>, len: usize) -> BlockHash {
        // The chain will be disqualified since build_block_with_parents builds utxo-invalid blocks
        for _ in 0..len {
            self.simulated_time += self.consensus.params().target_time_per_block();
            let b = self.build_block_with_parents(parents, 0, self.simulated_time);
            parents = vec![b.header.hash];
            self.validate_and_insert_block(b.to_immutable()).await;
        }
        parents[0]
    }

    pub fn build_block_template(&self, nonce: u64, timestamp: u64) -> BlockTemplate {
        let mut t = self
            .consensus
            .build_block_template(
                self.miner_data.clone(),
                Box::new(OnetimeTxSelector::new(Default::default())),
                TemplateBuildMode::Standard,
            )
            .unwrap();
        t.block.header.timestamp = timestamp;
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t
    }

    pub fn build_block_with_parents(&self, parents: Vec<BlockHash>, nonce: u64, timestamp: u64) -> MutableBlock {
        let mut b = self.consensus.build_block_with_parents_and_transactions(blockhash::NONE, parents, Default::default());
        b.header.timestamp = timestamp;
        b.header.nonce = nonce;
        b.header.finalize(); // This overrides the NONE hash we passed earlier with the actual hash
        b
    }

    pub async fn validate_and_insert_block(&mut self, block: Block) -> &mut Self {
        let status = self.consensus.validate_and_insert_block(block).virtual_state_task.await.unwrap();
        assert!(status.has_block_body());
        self
    }

    /// kaspa-pq ADR-0018 §G (DAG-2 harness): build ONE block from a template with a
    /// custom `miner_data` (so the coinbase can pay a known, spendable key) and a
    /// custom tx set fed through `OnetimeTxSelector` (so the coinbase is computed
    /// correctly and the block can reach a valid UTXO tip — unlike
    /// `build_block_with_parents_and_transactions`, which builds a utxo-invalid
    /// coinbase). Parents are auto-selected from the current virtual tips, so the
    /// caller just mines a linear chain. Returns the inserted (immutable) block so
    /// the caller can read its coinbase outputs / daa score. NOTE: an invalid tx in
    /// `txs` makes the template builder call `OnetimeTxSelector::reject_selection`,
    /// which panics — i.e. an invalid funded spend fails loudly here.
    pub async fn mine_block(&mut self, miner_data: MinerData, txs: Vec<Transaction>) -> Block {
        self.simulated_time += self.consensus.params().target_time_per_block();
        let mut t = self
            .consensus
            .build_block_template(miner_data, Box::new(OnetimeTxSelector::new(txs)), TemplateBuildMode::Standard)
            .unwrap();
        t.block.header.timestamp = self.simulated_time;
        t.block.header.nonce = self.simulated_time;
        t.block.header.finalize();
        let block = t.block.to_immutable();
        self.validate_and_insert_block(block.clone()).await;
        block
    }

    pub fn assert_tips(&mut self) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()), self.current_tips);
        self
    }

    pub fn assert_tips_num(&mut self, expected_num: usize) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()).len(), expected_num);
        self
    }

    pub fn assert_virtual_parents_subset(&mut self) -> &mut Self {
        assert!(self.consensus.get_virtual_parents().is_subset(&self.current_tips));
        self
    }

    pub fn assert_valid_utxo_tip(&mut self) -> &mut Self {
        // Assert that at least one body tip was resolved with valid UTXO
        assert!(self.consensus.body_tips().iter().copied().any(|h| self.consensus.block_status(h) == BlockStatus::StatusUTXOValid));
        self
    }
}

#[tokio::test]
async fn template_mining_sanity_test() {
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let rounds = 10;
    let width = 3;
    for _ in 0..rounds {
        ctx.build_block_template_row(0..width)
            .assert_row_parents()
            .validate_and_insert_row()
            .await
            .assert_tips()
            .assert_virtual_parents_subset()
            .assert_valid_utxo_tip();
    }
}

#[tokio::test]
async fn preactivation_palw_transaction_is_rejected_from_template() {
    use kaspa_consensus_core::errors::{block::RuleError, tx::TxRuleError};

    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().build();
    let ctx = TestContext::new(TestConsensus::new(&config));
    let tx = Transaction::new(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_PALW_BEACON_COMMIT, 0, vec![]);
    let tx_id = tx.id();
    let result =
        ctx.consensus.build_block_template(new_miner_data(), Box::new(OnetimeTxSelector::new(vec![tx])), TemplateBuildMode::Standard);

    assert!(matches!(
        result,
        Err(RuleError::InvalidTransactionsInNewBlock(ref failures))
            if matches!(failures.get(&tx_id), Some(TxRuleError::SubnetworksDisabled(id)) if *id == SUBNETWORK_ID_PALW_BEACON_COMMIT)
    ));
}

#[tokio::test]
async fn antichain_merge_test() {
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Build a large 32-wide antichain
    ctx.build_block_template_row(0..32)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mine a long enough chain s.t. the antichain is fully merged
    for _ in 0..32 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

/// kaspa-pq Phase 10/11 (ADR-0009/0013): first overlay-ACTIVE integration
/// test. With `dns_params = Some` and `dns_activation_daa_score = 0`, the
/// validator-reward code paths that are dormant on every shipping network —
/// the per-block `ActiveBondView` walk, the §B.4 eligibility check, the
/// coinbase reward fan-out (construction + validation), the cross-block
/// uniqueness walk over the rewarded-keys store, and the template
/// ineligible-shard pre-filter — all RUN here (with empty data, since this
/// chain carries no bonds or attestations). The chain must still mine and
/// validate to a valid UTXO tip, proving that activating the overlay does not
/// break block production or validation and that the empty-reward coinbase is
/// reproduced byte-for-byte by the validation path.
///
/// (A full reward-bearing e2e — a real bond tx, an ML-DSA-signed attestation,
/// and a non-empty reward coinbase — needs funded UTXO-valid overlay txs and
/// is a separate harness effort; the reward/eligibility/uniqueness logic is
/// already unit-tested.)
#[tokio::test]
async fn dns_overlay_active_chain_validates() {
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            // Activate the DNS overlay from genesis (reuse the self-consistent
            // devnet DNS parameters, with activation pulled down to 0).
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            p.dns_params = Some(dns);
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine + validate a chain with the overlay active end-to-end.
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

/// kaspa-pq ADR-0018 "本格版" (PoS-v2, Phase 2): overlay **and** v2-economics ACTIVE integration
/// test. With `dns_activation_daa_score = 0` AND `pos_v2_activation_daa_score = 0` (plus shrunk
/// windows so epochs actually bury within a short chain), the full v2 machinery RUNS on every
/// block: the fence-gated 70/30 participation/quality split, the per-block quality-pool
/// persistence (`block_quality_pool_store`, written non-empty here since the §F carve funds a
/// validator pool even with no attestations), the per-epoch accumulator recompute + finalization
/// (`update_epoch_accumulator`), and the deferred quality-bonus payout
/// (`deferred_quality_bonus_outputs` — incl. the finalization-crossing detection and the φS gate).
///
/// This chain carries no bonds/attestations, so every *reward* set is empty — but the code paths
/// execute, write the stores, and the chain must still mine and validate to a valid UTXO tip.
/// Because the validation path rebuilds the coinbase and rejects any mismatch, reaching a valid
/// UTXO tip proves the v2 economics neither break block production nor desynchronise coinbase
/// construction vs validation. (A reward-bearing e2e — real bonds + attestations paid a non-empty
/// bonus — needs the funded-bond DAG harness, DAG-2.)
#[tokio::test]
async fn pos_v2_active_empty_chain_validates() {
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            // Activate the v2 economics from genesis and shrink the finalization window
            // (= reward_uniqueness_window + max_reorg_horizon = 4) so epochs bury and the
            // deferred-bonus crossing fires within a short chain.
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 2;
            dns.max_reorg_horizon_blocks = 2;
            p.dns_params = Some(dns);
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // threshold(E) = (E+1)·2 + 4, so by ~daa 12 several epochs have finalized and the deferred
    // quality-bonus path has fired (with empty included sets — exercised, not paid).
    for _ in 0..12 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

/// kaspa-pq ADR-0018 §G DAG-2 (funded-bond milestone — retires the "fund a bond
/// from a coinbase UTXO" wall). With the overlay + v2 economics ACTIVE, a real
/// ML-DSA-87 keypair mines a coinbase; after maturity its output is SPENT into a
/// funded stake-bond tx (output-0 = locked stake, input-0 signed over the v2 tx
/// sighash under `MLDSA87_TX_CONTEXT`). The block carrying the bond must reach a
/// valid UTXO tip — proving the script engine (`OpCheckSigMlDsa87`) accepts the
/// real ML-DSA-87 P2PKH spend through full consensus validation, the precondition
/// for the reward-bearing / slashing DAG e2e (DAG-2..6).
#[tokio::test]
async fn pos_v2_funded_bond_chain_validates() {
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            // Shrink coinbase maturity so the funding coinbase is spendable within a short chain.
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 2;
            dns.max_reorg_horizon_blocks = 2;
            p.dns_params = Some(dns);
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // A known validator/funding key; its coinbase P2PKH spk.
    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);

    // 1) Mine a run of blocks whose coinbase pays K. In Kaspa a block's coinbase
    //    rewards the blocks it MERGES (each merged block's reported miner script),
    //    not its own miner — so K's reward for the funding block b1 (which merges
    //    only genesis → 0 reward) appears in the coinbase of the block that merges
    //    b1 (the harvest block b2).
    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let harvest = ctx.mine_block(k_miner.clone(), vec![]).await;
    let coinbase = &harvest.transactions[0];
    let coinbase_id = coinbase.id();
    let coinbase_daa = harvest.header.daa_score;
    let (idx, out) = coinbase
        .outputs
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_public_key == k_spk)
        .expect("the harvest coinbase must pay the known key");
    let coinbase_outpoint = TransactionOutpoint::new(coinbase_id, idx as u32);
    let coinbase_value = out.value;
    assert!(coinbase_value > 200_000, "coinbase value must cover the bond + fee");

    // 2) Mine filler blocks so the harvested coinbase matures (coinbase_maturity = 2).
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    // 3) Spend the matured coinbase into a funded, ML-DSA-87-signed stake-bond tx.
    let amount = coinbase_value - 100_000; // small fee; bond almost the whole coinbase
    let storage_mass_parameter = ctx.consensus.params().storage_mass_parameter;
    let (bond_tx, _validator_id, _reward_payload) =
        dns_harness::funded_signed_bond_tx(seed, coinbase_outpoint, coinbase_value, coinbase_daa, amount, 0, storage_mass_parameter);
    let bond_tx_id = bond_tx.id();

    // 4) Mine the block carrying the bond tx; it must reach a valid UTXO tip.
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert!(bond_block.transactions.iter().any(|t| t.id() == bond_tx_id), "the funded stake-bond tx must be included in the block");
    assert_eq!(
        ctx.consensus.block_status(bond_block.header.hash),
        BlockStatus::StatusUTXOValid,
        "the block carrying the funded ML-DSA-87 stake-bond spend must be UTXO-valid (construction == validation)"
    );
    ctx.assert_valid_utxo_tip();
}

/// ADR-0018 §F bridge wiring — one scenario of the finality-fee e2e: fund a key,
/// spend its matured coinbase into a deposit-lock tx (fee 100_000), mine it, then
/// harvest the next block's coinbase. Returns `(worker_output_value,
/// lock_block_subsidy)` — the worker payout for the block that carried the bridge tx,
/// and that block's subsidy (parsed from its coinbase payload: blue_score u64 LE ‖
/// subsidy u64 LE ‖ …).
///
/// `evm_active` toggles `evm_activation_daa_score` (0 vs u64::MAX). evm-active
/// templates COMMIT to the header timestamp (the EVM execution env derives from it),
/// so in that mode blocks are inserted exactly as templated — no
/// `TestContext::mine_block` timestamp/nonce mutation (the same insertion pattern the
/// EVM lane e2e tests use); the inert mode exercises the ordinary v1 mine path.
async fn finality_fee_bridge_scenario(finality_fence: u64, evm_active: bool) -> (u64, u64) {
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            // Shrink coinbase maturity so the funding coinbase is spendable quickly.
            p.coinbase_maturity = 2;
            // The classification is doubly gated: the §F fence AND EVM-lane activation
            // (the bridge only exists on an EVM-active net). MAINNET_PARAMS is EVM-inert
            // (u64::MAX) by default.
            p.evm_activation_daa_score = if evm_active { 0 } else { u64::MAX };
            let mut dns = p.dns_params.clone().unwrap();
            dns.finality_fee_activation_daa_score = finality_fence;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Insert one block: template-as-is when evm-active (timestamp is commitment-bound),
    // else the ordinary simulated-time mine path.
    async fn mine(ctx: &mut TestContext, evm_active: bool, miner: MinerData, txs: Vec<Transaction>) -> Block {
        if evm_active {
            let t =
                ctx.consensus.build_block_template(miner, Box::new(OnetimeTxSelector::new(txs)), TemplateBuildMode::Standard).unwrap();
            let block = t.block.to_immutable();
            ctx.validate_and_insert_block(block.clone()).await;
            block
        } else {
            ctx.mine_block(miner, txs).await
        }
    }

    // Fund: harvest a coinbase paying the known key K (a block's coinbase rewards
    // the blocks it MERGES, so K's reward for b1 appears in the harvest block).
    let seed = [0x5Au8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);
    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = mine(&mut ctx, evm_active, k_miner.clone(), vec![]).await;
    let harvest = mine(&mut ctx, evm_active, k_miner.clone(), vec![]).await;
    let coinbase = &harvest.transactions[0];
    let (idx, out) = coinbase
        .outputs
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_public_key == k_spk)
        .expect("the harvest coinbase must pay the known key");
    let coinbase_outpoint = TransactionOutpoint::new(coinbase.id(), idx as u32);
    let (coinbase_value, coinbase_daa) = (out.value, harvest.header.daa_score);
    assert!(coinbase_value > 200_000, "coinbase must cover the lock + fee");

    // Mature the coinbase (coinbase_maturity = 2).
    for _ in 0..5 {
        mine(&mut ctx, evm_active, new_miner_data(), vec![]).await;
    }

    // The bridge tx: matured coinbase → one EVM_DEPOSIT_LOCK output, fee 100_000.
    let lock_tx = dns_harness::funded_signed_deposit_lock_tx(
        seed,
        coinbase_outpoint,
        coinbase_value,
        coinbase_daa,
        ctx.consensus.params().storage_mass_parameter,
    );
    let lock_tx_id = lock_tx.id();

    // Mine it under a distinct miner spk so its worker payout is findable.
    let lock_miner_spk = p2pkh_mldsa87_spk(&[0x33u8; 64]);
    let lock_block = mine(&mut ctx, evm_active, MinerData::new(lock_miner_spk.clone(), vec![]), vec![lock_tx]).await;
    assert!(lock_block.transactions.iter().any(|t| t.id() == lock_tx_id), "the bridge tx must be included");
    assert_eq!(
        ctx.consensus.block_status(lock_block.header.hash),
        BlockStatus::StatusUTXOValid,
        "the block carrying the deposit-lock tx must be UTXO-valid (construction == validation)"
    );
    // The lock block's subsidy, from its coinbase payload (blue_score ‖ subsidy ‖ …).
    let payload = &lock_block.transactions[0].payload;
    let subsidy = u64::from_le_bytes(payload[8..16].try_into().unwrap());

    // Harvest: the next block's coinbase pays the lock block's worker share.
    let harvest2 = mine(&mut ctx, evm_active, new_miner_data(), vec![]).await;
    ctx.assert_valid_utxo_tip();
    let worker_out = harvest2.transactions[0]
        .outputs
        .iter()
        .find(|o| o.script_public_key == lock_miner_spk)
        .expect("the next coinbase must pay the lock block's miner")
        .value;
    (worker_out, subsidy)
}

/// kaspa-pq ADR-0018 §F bridge wiring e2e (EVM-active net): an accepted L1 tx that
/// CREATES an `EVM_DEPOSIT_LOCK` output (ADR-0020 §9.2 bridge deposit) is
/// **finality-class** — its fee is split at the validator-primary finality ratios
/// (Worker 25%) instead of the normal-tx ratios (Worker 90%) — through the REAL
/// template→validate coinbase path over a chain (classification at
/// `calculate_utxo_state`, payout via `expected_coinbase_transaction`; every mined
/// block reaching `StatusUTXOValid` proves construction == validation). The fenced
/// twin (`finality_fee_activation_daa_score = u64::MAX`) runs the identical chain
/// shape and pays the Worker the normal 90% — the exact pre-wiring math — proving the
/// §F fence isolates the change. evm-feature-gated: an evm-active template requires
/// the executor (a non-evm build refuses evm-active blocks by design).
#[tokio::test]
#[cfg(feature = "evm")]
async fn finality_fee_bridge_tx_pays_validator_primary_split() {
    use kaspa_consensus_core::dns_finality::{split_block_subsidy, split_finality_fees, split_normal_tx_fees};
    kaspa_core::log::try_init_logger("info");

    // Active fence (0, the PRODUCTION preset value): the 100_000 bridge fee splits at
    // the finality ratios — the Worker gets 25%, the Validator share (75%) funds the
    // §E pool (don't-mint burned here: no bonded validators).
    let (worker_active, subsidy_a) = finality_fee_bridge_scenario(0, true).await;
    // Inert §F fence: the same chain shape pays the normal-tx 90% — the pre-wiring math.
    let (worker_inert, subsidy_b) = finality_fee_bridge_scenario(u64::MAX, true).await;
    assert_eq!(subsidy_a, subsidy_b, "identical chain shape ⇒ identical lock-block subsidy");

    let dns = MAINNET_PARAMS.dns_params.clone().unwrap();
    let fs = &dns.reward_params.fee_split;
    let worker_base = split_block_subsidy(subsidy_a, fs).worker_base_sompi;
    assert_eq!(
        worker_active,
        worker_base + split_finality_fees(100_000, fs).worker_sompi,
        "bridge-tx fee pays the Worker the FINALITY share (25%)"
    );
    assert_eq!(
        worker_inert,
        worker_base + split_normal_tx_fees(100_000, fs).worker_sompi,
        "below the §F fence the same fee pays the Worker the NORMAL share (90%) — byte-identical to pre-wiring"
    );
    assert_eq!(
        worker_inert - worker_active,
        split_normal_tx_fees(100_000, fs).worker_sompi - split_finality_fees(100_000, fs).worker_sompi,
        "the Worker delta is exactly the normal→finality reclassification (the Validator gains it)"
    );
}

/// kaspa-pq ADR-0018 §F bridge wiring — the EVM-activation gate: deposit-lock OUTPUTS
/// are consensus-legal on every net (the output-class exemption is unconditional),
/// but on an EVM-INERT net (`evm_activation_daa_score = u64::MAX` — mainnet today)
/// the classification must NOT fire even with the §F fence at 0: the lock-bearing
/// tx's fee stays normal-class (Worker 90%), byte-identical to the pre-wiring math.
/// Without this gate a miner on an EVM-inert net could self-include a never-claimable
/// lock tx and reroute fees into the §E pool. Runs on the default (non-evm) build —
/// inert nets produce ordinary v1 blocks.
#[tokio::test]
async fn finality_fee_inert_on_evm_inert_net() {
    use kaspa_consensus_core::dns_finality::{split_block_subsidy, split_normal_tx_fees};
    kaspa_core::log::try_init_logger("info");

    // §F fence ACTIVE (0, the production value) but the EVM lane INERT.
    let (worker_out, subsidy) = finality_fee_bridge_scenario(0, false).await;
    let dns = MAINNET_PARAMS.dns_params.clone().unwrap();
    let fs = &dns.reward_params.fee_split;
    assert_eq!(
        worker_out,
        split_block_subsidy(subsidy, fs).worker_base_sompi + split_normal_tx_fees(100_000, fs).worker_sompi,
        "on an EVM-inert net a lock-bearing tx's fee stays NORMAL-class (Worker 90%) — the EVM gate holds"
    );
}

/// kaspa-pq ADR-0018 §G DAG-2 (reward-bearing e2e): the full overlay + v2 reward
/// path over a real BlockDAG. A funded ML-DSA-87 bond is created (as in the funding
/// milestone), then the validator ML-DSA-signs a recent attestation; the block that
/// includes the attestation shard must pay the validator a non-empty §E
/// participation reward in its coinbase AND validate to a UTXO-valid tip — proving
/// the reward fan-out (eligibility → distribution → coinbase) is
/// construction == validation with real bonds + attestations, not just by unit test.
#[tokio::test]
async fn pos_v2_reward_bearing_attestation_validates() {
    use crate::model::stores::headers::HeaderStoreReader;
    use kaspa_consensus_core::{Hash64, dns_finality::ready_epoch_from_tip_blue_score};
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            // Reward recency must comfortably cover the canonical anchor, which is buried by
            // attestation_lag + backoff below the tip (blue_score ~ DAA on this linear chain).
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            // DNS v3 blue_score epochs: small so an epoch buries within this short chain.
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // A known validator/funding key.
    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);

    // Fund: b1 funds, then two harvest blocks — h_a pays K for b1, h_b pays K for h_a.
    // coinbase_a funds the bond; coinbase_b funds the attestation shard tx (a 0-input
    // shard tx is rejected by the isolation `NoTxInputs` check, so production funds it).
    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_b = ctx.mine_block(k_miner.clone(), vec![]).await;
    let cb_a = &h_a.transactions[0];
    let (ia, oa) = cb_a.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_a pays K");
    let (coinbase_a, value_a, daa_a) = (TransactionOutpoint::new(cb_a.id(), ia as u32), oa.value, h_a.header.daa_score);
    let cb_b = &h_b.transactions[0];
    let (ib, ob) = cb_b.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_b pays K");
    let (coinbase_b, value_b, daa_b) = (TransactionOutpoint::new(cb_b.id(), ib as u32), ob.value, h_b.header.daa_score);
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let storage_mass_parameter = ctx.consensus.params().storage_mass_parameter;
    let (bond_tx, _vid, reward_payload) =
        dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, value_a - 100_000, 0, storage_mass_parameter);
    let bond_tx_id = bond_tx.id();
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert_eq!(ctx.consensus.block_status(bond_block.header.hash), BlockStatus::StatusUTXOValid, "the bond block must be UTXO-valid");
    assert_eq!(reward_payload, k_payload, "rewards pay back to K");

    // Bury several blue_score epochs past the bond so a ready, bond-active canonical anchor
    // exists — DNS v3 pays the §E reward only to an attestation naming the canonical anchor.
    for _ in 0..8 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let genesis_hash = ctx.consensus.params().genesis.hash;
    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let bond_outpoint = TransactionOutpoint::new(bond_tx_id, 0);
    let sink = ctx.consensus.get_sink();
    let anchor = {
        let vp = ctx.consensus.virtual_processor();
        let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
        let lr = ready_epoch_from_tip_blue_score(sink_blue, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
            .expect("an epoch is ready");
        vp.canonical_anchor_by_blue_score(lr, sink, &dns).expect("canonical anchor for the ready epoch")
    };

    // The validator ML-DSA-signs the CANONICAL anchor for a ready epoch (DNS v3). net_id =
    // genesis hash (Addendum A.3); VSC is a domain-separation field only (P-1D zero).
    let att = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        anchor.epoch,
        anchor.anchor_hash,
        anchor.anchor_daa_score,
        Hash64::default(),
    );
    let shard_tx = dns_harness::funded_signed_shard_tx(seed, coinbase_b, value_b, daa_b, att, storage_mass_parameter);

    // The block that includes the attestation shard pays the validator the §E
    // participation reward (to owner_reward_spk_payload == k_spk) and must validate.
    let reward_block = ctx.mine_block(new_miner_data(), vec![shard_tx]).await;
    assert_eq!(
        ctx.consensus.block_status(reward_block.header.hash),
        BlockStatus::StatusUTXOValid,
        "the attestation-including block must be UTXO-valid with a non-empty reward coinbase"
    );
    let reward_value = reward_block.transactions[0].outputs.iter().find(|o| o.script_public_key == k_spk).map(|o| o.value);
    assert!(
        reward_value.unwrap_or(0) > 0,
        "the coinbase must pay the validator a non-empty §E participation reward (got {reward_value:?})"
    );
}

/// kaspa-pq ADR-0018 §G (DAG-6): full-consensus equivocation-slashing e2e. A funded,
/// ML-DSA-87-signed bond goes active; the validator then EQUIVOCATES — two signed
/// attestations for the same `(bond, validator, epoch)` but DIFFERENT anchors — and a
/// `SlashingEvidence` tx carries both. The block including it must validate
/// (construction == validation), and as a consensus side-effect must REMOVE the locked
/// stake UTXO (the bond's output-0 leaves the supply) and MINT the reporter reward
/// (`slashing_reporter_reward_bps` = 10%) at `(slashing_tx, 0)`. This proves the slashing
/// economics end-to-end through `mine_block`/validate-and-insert, not just at the
/// `UtxoDiff` unit level (closes the audit's DAG-6 test gap).
#[tokio::test]
async fn pos_v2_slashing_evidence_removes_bond_and_pays_reporter() {
    use kaspa_consensus_core::{
        Hash64,
        dns_finality::{DNS_PAYLOAD_VERSION_V1, SlashingEvidencePayload},
    };
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // One validator/funding/reporter key suffices to exercise the slashing mechanism.
    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);

    // Fund: h_a pays K (funds the bond), h_b pays K (funds the evidence tx).
    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_b = ctx.mine_block(k_miner.clone(), vec![]).await;
    let cb_a = &h_a.transactions[0];
    let (ia, oa) = cb_a.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_a pays K");
    let (coinbase_a, value_a, daa_a) = (TransactionOutpoint::new(cb_a.id(), ia as u32), oa.value, h_a.header.daa_score);
    let cb_b = &h_b.transactions[0];
    let (ib, ob) = cb_b.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_b pays K");
    let (coinbase_b, value_b, daa_b) = (TransactionOutpoint::new(cb_b.id(), ib as u32), ob.value, h_b.header.daa_score);
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    // Fund + mine the bond — active from activation_daa_score = 0.
    let storage_mass_parameter = ctx.consensus.params().storage_mass_parameter;
    let bond_amount = value_a - 100_000;
    let (bond_tx, _vid, _reward_payload) =
        dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, bond_amount, 0, storage_mass_parameter);
    let bond_tx_id = bond_tx.id();
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert_eq!(ctx.consensus.block_status(bond_block.header.hash), BlockStatus::StatusUTXOValid, "the bond block must be UTXO-valid");
    let bond_outpoint = TransactionOutpoint::new(bond_tx_id, 0);
    assert!(
        ctx.consensus.get_virtual_utxos(None, 100_000, false).iter().any(|(o, _)| *o == bond_outpoint),
        "the bond's locked-stake UTXO must exist before slashing"
    );
    // Bury the bond so its record is committed into the active bond view the slashing
    // verifier reads (mirrors the burial the reward-bearing e2e does before attesting).
    let mut buried = Vec::new();
    for _ in 0..5 {
        buried.push(ctx.mine_block(new_miner_data(), vec![]).await);
    }

    // Equivocation: two ML-DSA-87-signed attestations, same (bond, validator, epoch),
    // DIFFERENT target_hash (approving two conflicting anchors) — the punishable act.
    let net_id = ctx.consensus.params().genesis.hash;
    let epoch = 1u64;
    // A buried block's DAA: past the bond's (inclusion-set) activation so the bond is
    // Active at the target, and well within `evidence_window_blocks` of the including block.
    let target_daa = buried[1].header.daa_score;
    let att_a = dns_harness::build_signed_attestation(
        &v,
        net_id.as_byte_slice(),
        bond_outpoint,
        epoch,
        Hash64::from_bytes([0xa1u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let att_b = dns_harness::build_signed_attestation(
        &v,
        net_id.as_byte_slice(),
        bond_outpoint,
        epoch,
        Hash64::from_bytes([0xb2u8; 64]),
        target_daa,
        Hash64::default(),
    );
    // Sanity (localizes a signature/net_id mismatch vs a freshness/status rejection): both
    // attestations must verify under the net_id (genesis hash) the consensus slashing
    // verifier reconstructs the digest with.
    for att in [&att_a, &att_b] {
        let msg = kaspa_consensus_core::dns_finality::stake_attestation_message(
            net_id.as_byte_slice(),
            att.epoch,
            att.target_hash,
            att.target_daa_score,
            att.validator_set_commitment,
            att.bond_outpoint,
        );
        assert!(
            kaspa_txscript::verify_mldsa87_with_context(
                &v.pubkey,
                &msg.as_bytes()[..],
                &att.signature,
                kaspa_consensus_core::dns_finality::ATTESTATION_MLDSA87_CONTEXT
            )
            .unwrap(),
            "attestation must self-verify under the consensus net_id"
        );
    }
    let evidence = SlashingEvidencePayload {
        version: DNS_PAYLOAD_VERSION_V1,
        bond_outpoint,
        attestation_a: att_a,
        attestation_b: att_b,
        reporter_reward_spk_payload: k_payload,
    };
    let slash_tx = dns_harness::funded_signed_slashing_evidence_tx(seed, coinbase_b, value_b, daa_b, evidence, storage_mass_parameter);
    let slash_tx_id = slash_tx.id();

    // The block including the slashing evidence must validate AND apply the side-effects.
    let slash_block = ctx.mine_block(new_miner_data(), vec![slash_tx]).await;
    assert_eq!(
        ctx.consensus.block_status(slash_block.header.hash),
        BlockStatus::StatusUTXOValid,
        "the slashing-evidence block must be UTXO-valid (construction == validation of the slashing side-effects)"
    );

    // Consensus side-effects: the locked stake is REMOVED and the reporter reward is minted.
    let utxos: std::collections::HashMap<_, _> = ctx.consensus.get_virtual_utxos(None, 100_000, false).into_iter().collect();
    assert!(!utxos.contains_key(&bond_outpoint), "the slashed bond's locked stake must be removed from the UTXO set");
    let reporter_mint = TransactionOutpoint::new(slash_tx_id, 0);
    let reporter_bps = ctx.consensus.params().dns_params.clone().unwrap().reward_params.slashing_reporter_reward_bps as u128;
    let expected_reporter = (bond_amount as u128 * reporter_bps / 10_000) as u64;
    let r = utxos.get(&reporter_mint).expect("the reporter reward must be minted at (slashing_tx, 0)");
    assert_eq!(r.amount, expected_reporter, "reporter reward = bond_amount * reporter_bps / 10000");
    assert_eq!(r.script_public_key, k_spk, "the reporter reward pays the declared reporter P2PKH");

    // ── Supply invariant (audit M-01) ──────────────────────────────────────────────────────
    // The 4-way slashing split is value-conserving: reporter + reserve + victim + burn equals the
    // slashed amount EXACTLY (no coins are created or destroyed by slashing), and only the reporter
    // is re-minted into the UTXO set. With a single (self-)validator there is no honest epoch peer,
    // so no victim-compensation output is emitted at (slash_tx, 2); the reserve share is pool-accrued
    // (not a UTXO) and the victim/burn shares leave the supply with the removed locked stake. Hence
    // minted (reporter) ≤ slashed ⇒ slashing cannot inflate supply.
    let rp = ctx.consensus.params().dns_params.clone().unwrap().reward_params;
    let dist = kaspa_consensus_core::dns_finality::compute_slashing_distribution(
        bond_amount,
        rp.slashing_reporter_reward_bps,
        rp.security_reserve_bps,
        rp.victim_epoch_pool_bps,
    );
    assert_eq!(
        dist.reporter_reward_sompi + dist.security_reserve_sompi + dist.victim_epoch_pool_sompi + dist.burned_sompi,
        bond_amount,
        "slashing split conserves value: reporter + reserve + victim + burn == slashed amount"
    );
    assert_eq!(dist.reporter_reward_sompi, expected_reporter, "minted reporter reward == the split's reporter share");
    assert!(dist.reporter_reward_sompi <= bond_amount, "the minted reporter reward never exceeds the slashed amount (no inflation)");
    assert!(
        !utxos.contains_key(&TransactionOutpoint::new(slash_tx_id, 2)),
        "no victim-compensation output is minted with a single (self-)validator"
    );
}

/// kaspa-pq ADR-0018 "本格版" (PoS-v2) — victim compensation (audit M-01). TWO validators: A
/// (equivocator) and B (honest). B attests the canonical anchor for a ready epoch E and is rewarded
/// (so it joins epoch E's accumulator `included` set); A then EQUIVOCATES the SAME epoch E (two
/// conflicting attestations) and is slashed. The slashing routes the victim-epoch share of A's
/// slashed stake to epoch E's honest peers = {B} (A is dropped by its `owner_reward_spk_payload`),
/// minting a victim-compensation output to B's reward P2PKH at `(slash_tx, 2)`. Proves the
/// multi-validator victim-compensation economics end-to-end through `mine_block`.
#[tokio::test]
async fn pos_v2_slashing_victim_compensates_honest_peer() {
    use crate::model::stores::headers::HeaderStoreReader;
    use kaspa_consensus_core::{
        Hash64,
        dns_finality::{
            DNS_PAYLOAD_VERSION_V1, SlashingEvidencePayload, compute_slashing_distribution, ready_epoch_from_tip_blue_score,
        },
    };
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            // Ensure a non-zero victim pool (the 4-way split): reporter 10% / reserve 40% /
            // victim 40% / burn 10%.
            dns.reward_params.slashing_reporter_reward_bps = 1000;
            dns.reward_params.security_reserve_bps = 4000;
            dns.reward_params.victim_epoch_pool_bps = 4000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let (va, vb) = (dns_harness::harness_validator([0x42u8; 32]), dns_harness::harness_validator([0x43u8; 32]));
    let payload_a: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&va.pubkey).as_bytes();
    let payload_b: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&vb.pubkey).as_bytes();
    let (spk_a, spk_b) = (p2pkh_mldsa87_spk(&payload_a), p2pkh_mldsa87_spk(&payload_b));

    // Fund: A needs two coinbases (bond + slashing-evidence tx), B two (bond + attestation shard).
    // A block's coinbase pays its MERGESET (the previous block's miner), not its own, so mine a
    // batch per miner and SCAN all coinbases for ones paying each validator.
    let (miner_a, miner_b) = (MinerData::new(spk_a.clone(), vec![]), MinerData::new(spk_b.clone(), vec![]));
    let mut blocks = Vec::new();
    for _ in 0..4 {
        blocks.push(ctx.mine_block(miner_a.clone(), vec![]).await);
    }
    for _ in 0..4 {
        blocks.push(ctx.mine_block(miner_b.clone(), vec![]).await);
    }
    for _ in 0..5 {
        blocks.push(ctx.mine_block(new_miner_data(), vec![]).await); // mature the coinbases
    }
    let (mut a_funds, mut b_funds) = (Vec::new(), Vec::new());
    for blk in &blocks {
        let cb = &blk.transactions[0];
        for (i, o) in cb.outputs.iter().enumerate() {
            let f = (TransactionOutpoint::new(cb.id(), i as u32), o.value, blk.header.daa_score);
            if o.script_public_key == spk_a {
                a_funds.push(f);
            } else if o.script_public_key == spk_b {
                b_funds.push(f);
            }
        }
    }
    assert!(a_funds.len() >= 2 && b_funds.len() >= 2, "need ≥2 funding coinbases each (a={}, b={})", a_funds.len(), b_funds.len());
    let ((cb_a1, va1, da1), (cb_a2, va2, da2)) = (a_funds[0], a_funds[1]);
    let ((cb_b1, vb1, db1), (cb_b2, vb2, db2)) = (b_funds[0], b_funds[1]);

    // Bond A and B (active from activation_daa_score = 0).
    let storage = ctx.consensus.params().storage_mass_parameter;
    let bond_a_amount = va1 - 100_000;
    let (bond_a_tx, _, _) = dns_harness::funded_signed_bond_tx([0x42u8; 32], cb_a1, va1, da1, bond_a_amount, 0, storage);
    let (bond_b_tx, _, _) = dns_harness::funded_signed_bond_tx([0x43u8; 32], cb_b1, vb1, db1, vb1 - 100_000, 0, storage);
    let (bond_a_id, bond_b_id) = (bond_a_tx.id(), bond_b_tx.id());
    ctx.mine_block(new_miner_data(), vec![bond_a_tx]).await;
    ctx.mine_block(new_miner_data(), vec![bond_b_tx]).await;
    let (bond_a_outpoint, bond_b_outpoint) = (TransactionOutpoint::new(bond_a_id, 0), TransactionOutpoint::new(bond_b_id, 0));

    // Bury so a ready, bond-active canonical anchor exists for a real epoch E.
    for _ in 0..8 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let genesis_hash = ctx.consensus.params().genesis.hash;
    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let sink = ctx.consensus.get_sink();
    let anchor = {
        let vp = ctx.consensus.virtual_processor();
        let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
        let lr = ready_epoch_from_tip_blue_score(sink_blue, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
            .expect("an epoch is ready");
        vp.canonical_anchor_by_blue_score(lr, sink, &dns).expect("canonical anchor for the ready epoch")
    };
    let epoch_e = anchor.epoch;

    // B HONESTLY attests the canonical anchor for epoch E → B is rewarded ⇒ joins epoch E's
    // accumulator `included` set (keyed by the attestation epoch).
    let att_b = dns_harness::build_signed_attestation(
        &vb,
        genesis_hash.as_byte_slice(),
        bond_b_outpoint,
        epoch_e,
        anchor.anchor_hash,
        anchor.anchor_daa_score,
        Hash64::default(),
    );
    let shard_b = dns_harness::funded_signed_shard_tx([0x43u8; 32], cb_b2, vb2, db2, att_b, storage);
    let reward_block = ctx.mine_block(new_miner_data(), vec![shard_b]).await;
    assert!(
        reward_block.transactions[0].outputs.iter().any(|o| o.script_public_key == spk_b),
        "B must be rewarded for attesting epoch E (so it joins the epoch's included set)"
    );

    // Bury so A's bond is committed into the active bond view the slashing verifier reads.
    let mut buried = Vec::new();
    for _ in 0..5 {
        buried.push(ctx.mine_block(new_miner_data(), vec![]).await);
    }

    // A EQUIVOCATES the SAME epoch E: two conflicting attestations (different anchors).
    let target_daa = buried[1].header.daa_score;
    let att_a1 = dns_harness::build_signed_attestation(
        &va,
        genesis_hash.as_byte_slice(),
        bond_a_outpoint,
        epoch_e,
        Hash64::from_bytes([0xa1u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let att_a2 = dns_harness::build_signed_attestation(
        &va,
        genesis_hash.as_byte_slice(),
        bond_a_outpoint,
        epoch_e,
        Hash64::from_bytes([0xb2u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let evidence = SlashingEvidencePayload {
        version: DNS_PAYLOAD_VERSION_V1,
        bond_outpoint: bond_a_outpoint,
        attestation_a: att_a1,
        attestation_b: att_a2,
        reporter_reward_spk_payload: payload_a, // reporter paid to A's address (payout is independent of who is slashed)
    };
    let slash_tx = dns_harness::funded_signed_slashing_evidence_tx([0x42u8; 32], cb_a2, va2, da2, evidence, storage);
    let slash_tx_id = slash_tx.id();
    let slash_block = ctx.mine_block(new_miner_data(), vec![slash_tx]).await;
    assert_eq!(
        ctx.consensus.block_status(slash_block.header.hash),
        BlockStatus::StatusUTXOValid,
        "the slashing block must validate AND mint the victim-compensation outputs (construction == validation)"
    );

    let utxos: std::collections::HashMap<_, _> = ctx.consensus.get_virtual_utxos(None, 100_000, false).into_iter().collect();
    assert!(!utxos.contains_key(&bond_a_outpoint), "A's slashed locked stake is removed");
    let dist = compute_slashing_distribution(
        bond_a_amount,
        dns.reward_params.slashing_reporter_reward_bps,
        dns.reward_params.security_reserve_bps,
        dns.reward_params.victim_epoch_pool_bps,
    );
    let reporter = utxos.get(&TransactionOutpoint::new(slash_tx_id, 0)).expect("reporter reward minted at (slash_tx, 0)");
    assert_eq!(reporter.amount, dist.reporter_reward_sompi, "reporter = reporter_bps share");
    // VICTIM COMPENSATION: the single honest peer B receives the whole victim pool at (slash_tx, 2).
    let victim = utxos.get(&TransactionOutpoint::new(slash_tx_id, 2)).expect("victim-compensation output minted at (slash_tx, 2)");
    assert_eq!(victim.script_public_key, spk_b, "victim compensation pays the honest peer B");
    assert_eq!(victim.amount, dist.victim_epoch_pool_sompi, "the lone honest peer receives the entire victim pool");
}

/// kaspa-pq ADR-0018 "本格版" (PoS-v2) — multiple slashings in ONE block (audit M-01). TWO
/// independently-bonded validators A and B BOTH equivocate and are slashed by SEPARATE evidence
/// transactions carried in the SAME block. Proves the slashing pipeline applies N>1 side-effects
/// atomically and independently: both locked stakes are removed, each reporter reward is minted at
/// its own `(slash_tx, 0)`, each bond's 4-way split conserves value, and — the multi-slash-specific
/// invariant — the block's committed security-reserve accrual is the SUM of both bonds' reserve
/// shares (`apply_slashing_side_effects`'s fold over the resolved effects, persisted by the
/// `parent_balance + reserve_accrual − drip` recurrence). With no honest epoch peer, no
/// victim-compensation output is minted for either.
#[tokio::test]
async fn pos_v2_multi_slashing_in_one_block() {
    use kaspa_consensus_core::{
        Hash64,
        dns_finality::{DNS_PAYLOAD_VERSION_V1, SlashingEvidencePayload, compute_slashing_distribution},
    };
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            // 4-way split with non-zero reserve + victim shares (so the summed reserve accrual is observable).
            dns.reward_params.slashing_reporter_reward_bps = 1000;
            dns.reward_params.security_reserve_bps = 4000;
            dns.reward_params.victim_epoch_pool_bps = 4000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let (va, vb) = (dns_harness::harness_validator([0x42u8; 32]), dns_harness::harness_validator([0x43u8; 32]));
    let payload_a: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&va.pubkey).as_bytes();
    let payload_b: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&vb.pubkey).as_bytes();
    let (spk_a, spk_b) = (p2pkh_mldsa87_spk(&payload_a), p2pkh_mldsa87_spk(&payload_b));

    // Fund: each validator needs two coinbases (bond + slashing-evidence tx). A block's coinbase pays
    // its MERGESET (the previous block's) miner, so mine a batch per miner and SCAN all coinbases.
    let (miner_a, miner_b) = (MinerData::new(spk_a.clone(), vec![]), MinerData::new(spk_b.clone(), vec![]));
    let mut blocks = Vec::new();
    for _ in 0..4 {
        blocks.push(ctx.mine_block(miner_a.clone(), vec![]).await);
    }
    for _ in 0..4 {
        blocks.push(ctx.mine_block(miner_b.clone(), vec![]).await);
    }
    for _ in 0..5 {
        blocks.push(ctx.mine_block(new_miner_data(), vec![]).await); // mature the coinbases
    }
    let (mut a_funds, mut b_funds) = (Vec::new(), Vec::new());
    for blk in &blocks {
        let cb = &blk.transactions[0];
        for (i, o) in cb.outputs.iter().enumerate() {
            let f = (TransactionOutpoint::new(cb.id(), i as u32), o.value, blk.header.daa_score);
            if o.script_public_key == spk_a {
                a_funds.push(f);
            } else if o.script_public_key == spk_b {
                b_funds.push(f);
            }
        }
    }
    assert!(a_funds.len() >= 2 && b_funds.len() >= 2, "need ≥2 funding coinbases each (a={}, b={})", a_funds.len(), b_funds.len());
    let ((cb_a1, va1, da1), (cb_a2, va2, da2)) = (a_funds[0], a_funds[1]);
    let ((cb_b1, vb1, db1), (cb_b2, vb2, db2)) = (b_funds[0], b_funds[1]);

    // Bond A and B (active from activation_daa_score = 0).
    let storage = ctx.consensus.params().storage_mass_parameter;
    let (bond_a_amount, bond_b_amount) = (va1 - 100_000, vb1 - 100_000);
    let (bond_a_tx, _, _) = dns_harness::funded_signed_bond_tx([0x42u8; 32], cb_a1, va1, da1, bond_a_amount, 0, storage);
    let (bond_b_tx, _, _) = dns_harness::funded_signed_bond_tx([0x43u8; 32], cb_b1, vb1, db1, bond_b_amount, 0, storage);
    let (bond_a_id, bond_b_id) = (bond_a_tx.id(), bond_b_tx.id());
    ctx.mine_block(new_miner_data(), vec![bond_a_tx]).await;
    ctx.mine_block(new_miner_data(), vec![bond_b_tx]).await;
    let (bond_a_outpoint, bond_b_outpoint) = (TransactionOutpoint::new(bond_a_id, 0), TransactionOutpoint::new(bond_b_id, 0));

    // Bury so BOTH bonds are committed into the active bond view the slashing verifier reads.
    let mut buried = Vec::new();
    for _ in 0..6 {
        buried.push(ctx.mine_block(new_miner_data(), vec![]).await);
    }

    // Both A and B equivocate: each emits two conflicting attestations for the same epoch (different
    // anchors). With no honest peer the epoch only has to be shared by each validator's own pair.
    let genesis_hash = ctx.consensus.params().genesis.hash;
    let epoch = 1u64;
    let target_daa = buried[1].header.daa_score; // past each bond's activation, within evidence_window of the slash block
    let att_a1 = dns_harness::build_signed_attestation(
        &va,
        genesis_hash.as_byte_slice(),
        bond_a_outpoint,
        epoch,
        Hash64::from_bytes([0xa1u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let att_a2 = dns_harness::build_signed_attestation(
        &va,
        genesis_hash.as_byte_slice(),
        bond_a_outpoint,
        epoch,
        Hash64::from_bytes([0xb2u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let att_b1 = dns_harness::build_signed_attestation(
        &vb,
        genesis_hash.as_byte_slice(),
        bond_b_outpoint,
        epoch,
        Hash64::from_bytes([0xc3u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let att_b2 = dns_harness::build_signed_attestation(
        &vb,
        genesis_hash.as_byte_slice(),
        bond_b_outpoint,
        epoch,
        Hash64::from_bytes([0xd4u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let ev_a = SlashingEvidencePayload {
        version: DNS_PAYLOAD_VERSION_V1,
        bond_outpoint: bond_a_outpoint,
        attestation_a: att_a1,
        attestation_b: att_a2,
        reporter_reward_spk_payload: payload_a,
    };
    let ev_b = SlashingEvidencePayload {
        version: DNS_PAYLOAD_VERSION_V1,
        bond_outpoint: bond_b_outpoint,
        attestation_a: att_b1,
        attestation_b: att_b2,
        reporter_reward_spk_payload: payload_b,
    };
    let slash_a = dns_harness::funded_signed_slashing_evidence_tx([0x42u8; 32], cb_a2, va2, da2, ev_a, storage);
    let slash_b = dns_harness::funded_signed_slashing_evidence_tx([0x43u8; 32], cb_b2, vb2, db2, ev_b, storage);
    let (slash_a_id, slash_b_id) = (slash_a.id(), slash_b.id());

    // BOTH slashing-evidence txs in ONE block.
    let slash_block = ctx.mine_block(new_miner_data(), vec![slash_a, slash_b]).await;
    assert_eq!(
        ctx.consensus.block_status(slash_block.header.hash),
        BlockStatus::StatusUTXOValid,
        "the block carrying TWO slashing-evidence txs must validate (both side-effects apply atomically)"
    );
    // A block's own transactions (and thus their slashing side-effects + the reserve accrual they
    // commit) are applied to the persisted UTXO state only once the block becomes a SELECTED PARENT.
    // Mine one empty block on top so `slash_block`'s effects settle into a committed chain block
    // (`settle`), whose `reserve_balance_store` row we read below.
    let settle = ctx.mine_block(new_miner_data(), vec![]).await;

    let utxos: std::collections::HashMap<_, _> = ctx.consensus.get_virtual_utxos(None, 100_000, false).into_iter().collect();
    // Both locked stakes removed.
    assert!(!utxos.contains_key(&bond_a_outpoint), "A's slashed locked stake is removed");
    assert!(!utxos.contains_key(&bond_b_outpoint), "B's slashed locked stake is removed");

    let rp = ctx.consensus.params().dns_params.clone().unwrap().reward_params;
    let dist_a = compute_slashing_distribution(
        bond_a_amount,
        rp.slashing_reporter_reward_bps,
        rp.security_reserve_bps,
        rp.victim_epoch_pool_bps,
    );
    let dist_b = compute_slashing_distribution(
        bond_b_amount,
        rp.slashing_reporter_reward_bps,
        rp.security_reserve_bps,
        rp.victim_epoch_pool_bps,
    );
    // Each reporter reward minted independently at its own (slash_tx, 0).
    let ra = utxos.get(&TransactionOutpoint::new(slash_a_id, 0)).expect("A's reporter reward minted at (slash_a, 0)");
    let rb = utxos.get(&TransactionOutpoint::new(slash_b_id, 0)).expect("B's reporter reward minted at (slash_b, 0)");
    assert_eq!((ra.amount, &ra.script_public_key), (dist_a.reporter_reward_sompi, &spk_a), "A's reporter share pays A");
    assert_eq!((rb.amount, &rb.script_public_key), (dist_b.reporter_reward_sompi, &spk_b), "B's reporter share pays B");
    // No honest epoch peer ⇒ no victim-compensation output for either bond.
    assert!(!utxos.contains_key(&TransactionOutpoint::new(slash_a_id, 2)), "no victim output without an honest peer (A)");
    assert!(!utxos.contains_key(&TransactionOutpoint::new(slash_b_id, 2)), "no victim output without an honest peer (B)");

    // Per-bond value conservation: each 4-way split sums back to the slashed amount.
    assert_eq!(
        dist_a.reporter_reward_sompi + dist_a.security_reserve_sompi + dist_a.victim_epoch_pool_sompi + dist_a.burned_sompi,
        bond_a_amount,
        "A's slash split conserves value"
    );
    assert_eq!(
        dist_b.reporter_reward_sompi + dist_b.security_reserve_sompi + dist_b.victim_epoch_pool_sompi + dist_b.burned_sompi,
        bond_b_amount,
        "B's slash split conserves value"
    );

    // MULTI-SLASH INVARIANT: the committed security-reserve accrual is the SUM of both bonds' reserve
    // shares (the fold in `apply_slashing_side_effects`). It commits under `settle` (the block whose
    // selected parent is `slash_block`, so its mergeset carries the two slash txs). `settle`'s parent
    // (`slash_block`) accrued no reserve (balance 0 ⇒ no drip), so the recurrence reduces to
    // `0 + (reserve_a + reserve_b) − 0`.
    let committed_reserve = ctx.consensus.virtual_processor().reserve_balance_store.get(settle.header.hash).unwrap_or(0);
    assert_eq!(
        committed_reserve,
        dist_a.security_reserve_sompi + dist_b.security_reserve_sompi,
        "the block's reserve accrual is the SUM of both slashed bonds' reserve shares"
    );
}

/// kaspa-pq ADR-0018 "本格版" (PoS-v2, Phase 4) — security-reserve DRIP (audit M-01). Closes the
/// reserve loop end-to-end: a slashing accrues its reserve share to the pool, and when an epoch the
/// pool can pay finalizes, the reserve DRIPS back out into that block's coinbase, stake-proportionally
/// to the epoch's honest included validators. TWO validators: A is slashed for equivocation (its
/// `security_reserve_bps` share accrues to the reserve pool); B honestly attests the canonical anchor
/// for a ready epoch E and joins `included[E]`. Once epoch E finalizes (its `(E+1)·L + finalization_depth`
/// DAA threshold is crossed), the finalizing block's coinbase pays B the whole reserve (cap set high,
/// B the sole included validator). Proves accrued-in == dripped-out (value conservation).
///
/// NOTE the config sets `epoch_length_blocks == attestation_epoch_length_blue_score`: the drip pays
/// the FINALIZING epoch's `included` set, which `recompute_epoch_tallies` keys by the ATTESTATION
/// epoch, while `epochs_finalized_at` selects epochs by the DAA epoch (`daa_score / epoch_length_blocks`).
/// The two numberings coincide (on a linear chain blue_score ≈ daa_score) only when those two lengths
/// are equal — which is exactly the production reality (both = 100 in GENESIS_ACTIVE/PRODUCTION_DNS_PARAMS).
#[tokio::test]
async fn pos_v2_reserve_drip_pays_finalized_epoch() {
    use crate::model::stores::headers::HeaderStoreReader;
    use kaspa_consensus_core::{
        Hash64,
        dns_finality::{
            DNS_PAYLOAD_VERSION_V1, SlashingEvidencePayload, compute_slashing_distribution, ready_epoch_from_tip_blue_score,
        },
    };
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            // epoch_length_blocks == attestation_epoch_length_blue_score (production reality) so the
            // attestation epoch B signs and the DAA epoch the drip finalizes are the same number.
            dns.epoch_length_blocks = 3;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            // Reward recency must comfortably cover the canonical anchor (buried by lag + backoff
            // below the tip); finalization_depth = window + max_reorg_horizon = 52.
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            dns.stake_score_window_blue_score = 10_000;
            // Isolate the drip: participation takes the full validator pool (quality-bonus pool = 0), so
            // the only post-attestation coinbase output to B is the reserve drip.
            dns.reward_params.validator_participation_bps = 10_000;
            dns.reward_params.slashing_reporter_reward_bps = 1000;
            dns.reward_params.security_reserve_bps = 4000; // 40% of the slashed bond accrues to the reserve
            dns.reward_params.victim_epoch_pool_bps = 4000;
            dns.reward_params.reserve_drip_per_epoch_cap_sompi = u64::MAX; // the whole reserve drips in one epoch
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let (va, vb) = (dns_harness::harness_validator([0x42u8; 32]), dns_harness::harness_validator([0x43u8; 32]));
    let payload_a: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&va.pubkey).as_bytes();
    let payload_b: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&vb.pubkey).as_bytes();
    let (spk_a, spk_b) = (p2pkh_mldsa87_spk(&payload_a), p2pkh_mldsa87_spk(&payload_b));

    // Fund: A needs two coinbases (bond + slashing-evidence tx), B two (bond + attestation shard).
    // A block's coinbase pays its MERGESET miner, so mine a batch per miner and SCAN all coinbases.
    let (miner_a, miner_b) = (MinerData::new(spk_a.clone(), vec![]), MinerData::new(spk_b.clone(), vec![]));
    let mut blocks = Vec::new();
    for _ in 0..4 {
        blocks.push(ctx.mine_block(miner_a.clone(), vec![]).await);
    }
    for _ in 0..4 {
        blocks.push(ctx.mine_block(miner_b.clone(), vec![]).await);
    }
    for _ in 0..5 {
        blocks.push(ctx.mine_block(new_miner_data(), vec![]).await);
    }
    let (mut a_funds, mut b_funds) = (Vec::new(), Vec::new());
    for blk in &blocks {
        let cb = &blk.transactions[0];
        for (i, o) in cb.outputs.iter().enumerate() {
            let f = (TransactionOutpoint::new(cb.id(), i as u32), o.value, blk.header.daa_score);
            if o.script_public_key == spk_a {
                a_funds.push(f);
            } else if o.script_public_key == spk_b {
                b_funds.push(f);
            }
        }
    }
    assert!(a_funds.len() >= 2 && b_funds.len() >= 2, "need ≥2 funding coinbases each (a={}, b={})", a_funds.len(), b_funds.len());
    let ((cb_a1, va1, da1), (cb_a2, va2, da2)) = (a_funds[0], a_funds[1]);
    let ((cb_b1, vb1, db1), (cb_b2, vb2, db2)) = (b_funds[0], b_funds[1]);

    let storage = ctx.consensus.params().storage_mass_parameter;
    let genesis_hash = ctx.consensus.params().genesis.hash;

    // ── B bonds and HONESTLY attests the ready canonical epoch E ────────────────────────────────
    // B bonds and attests FIRST: A is bonded only later (below), strictly after E's anchor, so A is
    // not part of E's expected-stake denominator — leaving B the sole included validator at E, which
    // makes the drip pay B the WHOLE reserve (a crisp value-conservation assertion). The stake-
    // proportional split when a slashed peer co-existed at the anchor is exercised separately.
    let (bond_b_tx, _, _) = dns_harness::funded_signed_bond_tx([0x43u8; 32], cb_b1, vb1, db1, vb1 - 100_000, 0, storage);
    let bond_b_id = bond_b_tx.id();
    ctx.mine_block(new_miner_data(), vec![bond_b_tx]).await;
    let bond_b_outpoint = TransactionOutpoint::new(bond_b_id, 0);
    // Bury so a ready, bond-active canonical anchor exists for B's epoch E.
    for _ in 0..8 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let sink = ctx.consensus.get_sink();
    let anchor = {
        let vp = ctx.consensus.virtual_processor();
        let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
        let lr = ready_epoch_from_tip_blue_score(sink_blue, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
            .expect("an epoch is ready");
        vp.canonical_anchor_by_blue_score(lr, sink, &dns).expect("canonical anchor for the ready epoch")
    };
    let epoch_e = anchor.epoch;
    let att_b = dns_harness::build_signed_attestation(
        &vb,
        genesis_hash.as_byte_slice(),
        bond_b_outpoint,
        epoch_e,
        anchor.anchor_hash,
        anchor.anchor_daa_score,
        Hash64::default(),
    );
    let shard_b = dns_harness::funded_signed_shard_tx([0x43u8; 32], cb_b2, vb2, db2, att_b, storage);
    let reward_block = ctx.mine_block(new_miner_data(), vec![shard_b]).await;
    assert!(
        reward_block.transactions[0].outputs.iter().any(|o| o.script_public_key == spk_b),
        "B must be rewarded for attesting epoch E (so it joins included[E])"
    );

    // ── Accrue the reserve: bond A (AFTER E's anchor) and slash it for equivocation ─────────────
    let bond_a_amount = va1 - 100_000;
    let (bond_a_tx, _, _) = dns_harness::funded_signed_bond_tx([0x42u8; 32], cb_a1, va1, da1, bond_a_amount, 0, storage);
    let bond_a_id = bond_a_tx.id();
    ctx.mine_block(new_miner_data(), vec![bond_a_tx]).await;
    let bond_a_outpoint = TransactionOutpoint::new(bond_a_id, 0);
    // Bury so A's bond is committed into the active bond view the slashing verifier reads.
    let mut buried = Vec::new();
    for _ in 0..6 {
        buried.push(ctx.mine_block(new_miner_data(), vec![]).await);
    }
    // A equivocates an arbitrary epoch (1) DISJOINT from B's epoch E, so A's slash mints no victim
    // output (epoch 1 has no honest included peer) — only the reserve accrues.
    let target_daa = buried[1].header.daa_score;
    let att_a1 = dns_harness::build_signed_attestation(
        &va,
        genesis_hash.as_byte_slice(),
        bond_a_outpoint,
        1,
        Hash64::from_bytes([0xa1u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let att_a2 = dns_harness::build_signed_attestation(
        &va,
        genesis_hash.as_byte_slice(),
        bond_a_outpoint,
        1,
        Hash64::from_bytes([0xb2u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let evidence = SlashingEvidencePayload {
        version: DNS_PAYLOAD_VERSION_V1,
        bond_outpoint: bond_a_outpoint,
        attestation_a: att_a1,
        attestation_b: att_a2,
        reporter_reward_spk_payload: payload_a,
    };
    let slash_tx = dns_harness::funded_signed_slashing_evidence_tx([0x42u8; 32], cb_a2, va2, da2, evidence, storage);
    let slash_block = ctx.mine_block(new_miner_data(), vec![slash_tx]).await;
    assert_eq!(ctx.consensus.block_status(slash_block.header.hash), BlockStatus::StatusUTXOValid, "the slashing block must validate");
    // Settle so the reserve accrual commits (a block's own txs apply once it becomes a selected parent).
    let reserve_settle = ctx.mine_block(new_miner_data(), vec![]).await;
    let dist = compute_slashing_distribution(
        bond_a_amount,
        dns.reward_params.slashing_reporter_reward_bps,
        dns.reward_params.security_reserve_bps,
        dns.reward_params.victim_epoch_pool_bps,
    );
    let reserve_accrued = ctx.consensus.virtual_processor().reserve_balance_store.get(reserve_settle.header.hash).unwrap_or(0);
    assert_eq!(reserve_accrued, dist.security_reserve_sompi, "A's slash accrues its reserve share to the pool");
    assert!(reserve_accrued > 0, "the reserve must be non-zero to drip");

    // ── Mine until epoch E's DAA-finalization; the drip pays B in that block's coinbase ─────────
    let target_final_daa =
        (epoch_e + 1) * dns.epoch_length_blocks + dns.reward_uniqueness_window_blocks + dns.max_reorg_horizon_blocks;
    let mut drip_block = None;
    for _ in 0..80 {
        let blk = ctx.mine_block(new_miner_data(), vec![]).await;
        // The reserve drip is appended to the coinbase of the block that finalizes epoch E. B got its
        // one-time participation reward at `reward_block` (cross-block dedup blocks re-payment), and the
        // §D worker bounty pays the includer — so the only later coinbase output to B is the drip.
        if blk.transactions[0].outputs.iter().any(|o| o.script_public_key == spk_b) {
            drip_block = Some(blk);
            break;
        }
        if blk.header.daa_score > target_final_daa + 5 {
            break;
        }
    }
    let drip_block = drip_block.expect("a block after the reward must drip the reserve to B at epoch E's finalization");
    let drip_out = drip_block.transactions[0].outputs.iter().find(|o| o.script_public_key == spk_b).expect("drip pays B");
    // The sole included validator B receives the WHOLE reserve (cap is u64::MAX): accrued-in == dripped-out.
    assert_eq!(drip_out.value, reserve_accrued, "the entire accrued reserve drips to the lone included validator B");
}

/// kaspa-pq ADR-0016 §D.2 — the bond-UTXO spend-gate races the slashing side-effect (audit M-01). A
/// validator's locked stake (the bond's output-0) is NOT releasable while the bond is Active, so a
/// block that SPENDS it must be rejected — even when the SAME block also carries a slashing-evidence
/// tx for that bond (which would otherwise remove output-0). The spend-gate wins the race: the block
/// is disqualified (`NonReleasableBondSpendInBlock`), so NEITHER the spend NOR the slash takes effect
/// — the locked stake survives intact and no reporter reward is minted. Proves a validator cannot
/// reclaim locked capital by smuggling a self-spend into a block, and that the spend-gate takes
/// precedence over the slashing side-effect.
#[tokio::test]
async fn pos_v2_spend_gate_rejects_locked_bond_racing_slash() {
    use kaspa_consensus_core::{
        Hash64,
        dns_finality::{DNS_PAYLOAD_VERSION_V1, SlashingEvidencePayload},
    };
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // One validator/funding/reporter key.
    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);

    // Fund: h_a pays K (funds the bond), h_b pays K (funds the slashing-evidence tx).
    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_b = ctx.mine_block(k_miner.clone(), vec![]).await;
    let cb_a = &h_a.transactions[0];
    let (ia, oa) = cb_a.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_a pays K");
    let (coinbase_a, value_a, daa_a) = (TransactionOutpoint::new(cb_a.id(), ia as u32), oa.value, h_a.header.daa_score);
    let cb_b = &h_b.transactions[0];
    let (ib, ob) = cb_b.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_b pays K");
    let (coinbase_b, value_b, daa_b) = (TransactionOutpoint::new(cb_b.id(), ib as u32), ob.value, h_b.header.daa_score);
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    // Bond: output-0 is the locked stake (a P2PKH to K), Active from activation 0.
    let storage = ctx.consensus.params().storage_mass_parameter;
    let bond_amount = value_a - 100_000;
    let (bond_tx, _vid, _payload) = dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, bond_amount, 0, storage);
    let bond_tx_id = bond_tx.id();
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert_eq!(ctx.consensus.block_status(bond_block.header.hash), BlockStatus::StatusUTXOValid, "the bond block must be UTXO-valid");
    let bond_outpoint = TransactionOutpoint::new(bond_tx_id, 0);
    let bond_daa = bond_block.header.daa_score;

    // Bury so the bond is committed into the active bond view the slashing verifier reads.
    let mut buried = Vec::new();
    for _ in 0..6 {
        buried.push(ctx.mine_block(new_miner_data(), vec![]).await);
    }

    // Equivocation evidence (two conflicting attestations for the same (bond, epoch)).
    let genesis_hash = ctx.consensus.params().genesis.hash;
    let target_daa = buried[1].header.daa_score;
    let att_a = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        1,
        Hash64::from_bytes([0xa1u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let att_b = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        1,
        Hash64::from_bytes([0xb2u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let evidence = SlashingEvidencePayload {
        version: DNS_PAYLOAD_VERSION_V1,
        bond_outpoint,
        attestation_a: att_a,
        attestation_b: att_b,
        reporter_reward_spk_payload: k_payload,
    };
    let slash_tx = dns_harness::funded_signed_slashing_evidence_tx(seed, coinbase_b, value_b, daa_b, evidence, storage);
    let slash_tx_id = slash_tx.id();
    // A self-spend of the still-locked bond output-0 (the spend-gate violation).
    let spend_tx = dns_harness::funded_signed_p2pkh_spend(seed, bond_outpoint, bond_amount, bond_daa, storage);

    // ONE block carries BOTH: the slash (which would remove output-0) AND the self-spend of output-0.
    // The Active bond is not releasable ⇒ the spend-gate disqualifies the whole block.
    let race_block = ctx.mine_block(new_miner_data(), vec![slash_tx, spend_tx]).await;
    assert_ne!(
        ctx.consensus.block_status(race_block.header.hash),
        BlockStatus::StatusUTXOValid,
        "spending the locked bond output-0 must disqualify the block (the spend-gate wins over the slash)"
    );

    // The block had NO effect: the locked stake survives (neither spent nor slashed-away) and no
    // reporter reward was minted.
    let utxos: std::collections::HashMap<_, _> = ctx.consensus.get_virtual_utxos(None, 100_000, false).into_iter().collect();
    assert!(utxos.contains_key(&bond_outpoint), "the locked stake survives — the spend-gate rejected the racing block");
    assert!(
        !utxos.contains_key(&TransactionOutpoint::new(slash_tx_id, 0)),
        "no reporter reward — the slash never applied (block disqualified)"
    );
}

/// kaspa-pq ADR-0018 "本格版" (PoS-v2) — slashing is REORG-RESISTANT and reorg-SAFE (audit M-01). An
/// equivocator cannot escape its slash by getting the network to reorg onto a heavier branch that
/// omits the evidence. A bond X is buried in a shared prefix; one branch (A) slashes X — committing
/// the side-effect (output-0 removed, reporter minted at `(slash_tx, 0)`) — while a HEAVIER competing
/// branch (B), built by a second consensus instance over the SAME prefix, omits the slash. When B's
/// blocks arrive the node reorgs onto B (the reorg gate is held dormant — Bootstrap stage, since
/// `min_active_validators` is raised so a lone bond never activates it — so selection is pure
/// blue_work). The slash block leaves the SELECTED chain, but branch A is still a DAG tip and is
/// MERGED into the virtual, so the slash side-effect is RECOMPUTED and re-applies deterministically:
/// X stays slashed and the reporter stays minted, exactly once (no double-removal, no panic, supply
/// conserved). This is the economically correct, reorg-safe outcome — the equivocation evidence is
/// permanent in the DAG, so the punishment survives the reorg rather than being stranded or replayed.
#[tokio::test]
async fn pos_v2_slashing_survives_reorg_via_evidence_merge() {
    use kaspa_consensus_core::{
        Hash64,
        dns_finality::{DNS_PAYLOAD_VERSION_V1, SlashingEvidencePayload},
    };
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 50;
            // A large reorg horizon so the fork is within range (the gate is dormant anyway).
            dns.max_reorg_horizon_blocks = 1000;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            // Keep the rollout stage in Bootstrap (one bond can never reach Active), so the reorg gate
            // stays GateInactive and selection is pure blue_work — the heaviest branch wins.
            dns.min_active_validators = 100;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);

    // ── Shared prefix on the honest node: fund + bond X + bury (collected for delivery to the 2nd
    //    instance, so both branches share an identical bond-creation history) ────────────────────
    let mut prefix = Vec::new();
    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    prefix.push(ctx.mine_block(k_miner.clone(), vec![]).await);
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    prefix.push(h_a.clone());
    let h_b = ctx.mine_block(k_miner.clone(), vec![]).await;
    prefix.push(h_b.clone());
    let cb_a = &h_a.transactions[0];
    let (ia, oa) = cb_a.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_a pays K");
    let (coinbase_a, value_a, daa_a) = (TransactionOutpoint::new(cb_a.id(), ia as u32), oa.value, h_a.header.daa_score);
    let cb_b = &h_b.transactions[0];
    let (ib, ob) = cb_b.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_b pays K");
    let (coinbase_b, value_b, daa_b) = (TransactionOutpoint::new(cb_b.id(), ib as u32), ob.value, h_b.header.daa_score);
    for _ in 0..5 {
        prefix.push(ctx.mine_block(new_miner_data(), vec![]).await);
    }
    let storage = ctx.consensus.params().storage_mass_parameter;
    let bond_amount = value_a - 100_000;
    let (bond_tx, _vid, _rp) = dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, bond_amount, 0, storage);
    let bond_tx_id = bond_tx.id();
    prefix.push(ctx.mine_block(new_miner_data(), vec![bond_tx]).await);
    let bond_outpoint = TransactionOutpoint::new(bond_tx_id, 0);
    let mut buried = Vec::new();
    for _ in 0..6 {
        let b = ctx.mine_block(new_miner_data(), vec![]).await;
        buried.push(b.clone());
        prefix.push(b);
    }

    // ── Second instance: replay the SAME prefix, then build a HEAVIER no-slash branch B ─────────
    let mut atk = TestContext::new(TestConsensus::new(&config));
    for b in &prefix {
        atk.validate_and_insert_block(b.clone()).await;
    }
    atk.simulated_time = ctx.simulated_time; // so branch B's timestamps stay ahead of the prefix
    let mut branch_b = Vec::new();
    for _ in 0..12 {
        branch_b.push(atk.mine_block(new_miner_data(), vec![]).await);
    }
    let branch_b_tip = branch_b.last().unwrap().header.hash;

    // ── Honest branch A: slash X (equivocation) and settle so the side-effect is COMMITTED ──────
    let genesis_hash = ctx.consensus.params().genesis.hash;
    let target_daa = buried[1].header.daa_score;
    let att_a = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        1,
        Hash64::from_bytes([0xa1u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let att_b = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        1,
        Hash64::from_bytes([0xb2u8; 64]),
        target_daa,
        Hash64::default(),
    );
    let evidence = SlashingEvidencePayload {
        version: DNS_PAYLOAD_VERSION_V1,
        bond_outpoint,
        attestation_a: att_a,
        attestation_b: att_b,
        reporter_reward_spk_payload: k_payload,
    };
    let slash_tx = dns_harness::funded_signed_slashing_evidence_tx(seed, coinbase_b, value_b, daa_b, evidence, storage);
    let slash_tx_id = slash_tx.id();
    let slash_block = ctx.mine_block(new_miner_data(), vec![slash_tx]).await;
    assert_eq!(ctx.consensus.block_status(slash_block.header.hash), BlockStatus::StatusUTXOValid, "branch A's slash block validates");
    ctx.mine_block(new_miner_data(), vec![]).await; // settle so the slash side-effect commits

    // Slash applied on branch A: X's locked stake is gone and the reporter reward is minted.
    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let expected_reporter = kaspa_consensus_core::dns_finality::compute_slashing_distribution(
        bond_amount,
        dns.reward_params.slashing_reporter_reward_bps,
        dns.reward_params.security_reserve_bps,
        dns.reward_params.victim_epoch_pool_bps,
    )
    .reporter_reward_sompi;
    let reporter_outpoint = TransactionOutpoint::new(slash_tx_id, 0);
    let pre: std::collections::HashMap<_, _> = ctx.consensus.get_virtual_utxos(None, 100_000, false).into_iter().collect();
    assert!(!pre.contains_key(&bond_outpoint), "branch A: the slashed bond's locked stake is removed");
    assert_eq!(pre.get(&reporter_outpoint).map(|u| u.amount), Some(expected_reporter), "branch A: the reporter reward is minted");

    // ── Deliver branch B → the node reorgs onto the heavier no-slash branch ─────────────────────
    for b in &branch_b {
        ctx.validate_and_insert_block(b.clone()).await;
    }
    assert_eq!(ctx.consensus.get_sink(), branch_b_tip, "the node reorged onto the heavier branch B (gate dormant ⇒ pure blue_work)");

    // ── The slash SURVIVES the reorg: branch A leaves the selected chain but is merged back into the
    //    virtual, so the side-effect re-applies deterministically — X stays slashed, reporter stays
    //    minted EXACTLY ONCE (no double-removal, no double-mint, no panic). ──────────────────────
    let post: std::collections::HashMap<_, _> = ctx.consensus.get_virtual_utxos(None, 100_000, false).into_iter().collect();
    assert!(
        !post.contains_key(&bond_outpoint),
        "after reorg: the equivocator is STILL slashed — its locked stake stays removed (evidence merged back)"
    );
    assert_eq!(
        post.get(&reporter_outpoint).map(|u| u.amount),
        Some(expected_reporter),
        "after reorg: the reporter reward is still minted, exactly once (recomputed over the new selected chain + merge set)"
    );
}

/// kaspa-pq ADR-0018 §F (DAG-3) — STAGED reward-split rollout across the `full_reward_split_daa_score`
/// boundary. The §F carve selects the fee/subsidy split deterministically from the block's DAA score:
/// below `full_reward_split_daa_score` the BOOTSTRAP split (smaller validator carve — worker base
/// 8200bps), at/above it the FULL split (worker base 6200bps; validator 30% — re-genesis raised it
/// from 25%). This mines a constant-miner chain straight across the boundary and asserts (a) EVERY
/// block stays UTXO-valid — the coinbase carve the template builds equals the one validation
/// recomputes, on BOTH sides AND at the crossing block (construction == validation across a staged
/// consensus parameter), and (b) the miner's per-block subsidy share visibly DROPS at the boundary
/// (bootstrap 82% → full 62% of subsidy), proving the split actually changed rather than the stage
/// being inert.
#[tokio::test]
async fn pos_v2_staged_full_reward_split_across_boundary() {
    kaspa_core::log::try_init_logger("info");
    const H: u64 = 20; // full_reward_split_daa_score
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0; // overlay active ⇒ the §F carve applies (Some(split))
            dns.full_reward_split_daa_score = H; // Stage 2 (bootstrap) below H, Stage 3 (full) at/above
            // pos_v2 stays fenced (preset u64::MAX) — §F fee-split staging is independent of the v2 economics.
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // A single, constant miner so every coinbase pays the same spk (the reward is the prev block's
    // carved subsidy — the coinbase pays its mergeset miner).
    let v = dns_harness::harness_validator([0x42u8; 32]);
    let k_spk = p2pkh_mldsa87_spk(&kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes());
    let miner = MinerData::new(k_spk.clone(), vec![]);

    let mut rewards: Vec<(u64, u64)> = Vec::new(); // (block daa_score, miner's coinbase reward)
    for _ in 0..(H + 15) {
        let b = ctx.mine_block(miner.clone(), vec![]).await;
        assert_eq!(
            ctx.consensus.block_status(b.header.hash),
            BlockStatus::StatusUTXOValid,
            "every block stays UTXO-valid across the staged-split boundary (construction == validation)"
        );
        let r: u64 = b.transactions[0].outputs.iter().filter(|o| o.script_public_key == k_spk).map(|o| o.value).sum();
        rewards.push((b.header.daa_score, r));
    }

    // The coinbase of a block at DAA d carves the mergeset (prev block's) subsidy by the split
    // SELECTED FROM d. Sample a block clearly in Stage 2 (bootstrap) and one clearly in Stage 3
    // (full); both adjacent enough that subsidy decay is negligible, so the ratio isolates the carve.
    let stage2 = rewards.iter().rev().find(|(d, r)| *d < H && *r > 0).map(|(_, r)| *r).expect("a Stage-2 reward");
    let stage3 = rewards.iter().find(|(d, r)| *d >= H && *r > 0).map(|(_, r)| *r).expect("a Stage-3 reward");
    // Worker base share drops 8200bps → 6200bps ⇒ ratio ≈ 0.7561. Tolerance absorbs the tiny per-block decay.
    let ratio = stage3 as f64 / stage2 as f64;
    assert!(
        (0.74..=0.77).contains(&ratio),
        "the miner's subsidy share drops at the boundary by the bootstrap→full worker-base carve (8200→6200bps ≈ 0.756); got stage2={stage2} stage3={stage3} ratio={ratio:.4}"
    );
}

/// kaspa-pq ADR-0018 §G (DAG-7) — MULTI-NODE mesh convergence with the DNS overlay ACTIVE. Three
/// independent consensus instances (same overlay-active config) each mine a DIVERGENT chain from
/// genesis; then every block is gossiped to every node. All three must converge on the SAME sink —
/// i.e. the overlay's per-block machinery (epoch accumulator / reserve / rewarded-keys stores) and
/// the reorg gate (dormant here: no attestations ⇒ no confirmed anchor) do NOT break GHOSTDAG's
/// deterministic multi-node convergence. Complements the single-instance wide-DAG anchor-agreement
/// test (which proves divergent VIEWS pick one anchor) with real cross-instance block exchange.
#[tokio::test]
async fn dag7_multi_node_mesh_converges_with_overlay_active() {
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 8; // enough to merge the divergent tips
            p.mergeset_size_limit = 16;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0; // overlay ACTIVE on every node
            p.dns_params = Some(dns);
        })
        .build();

    // Three nodes, each mining a chain of a DIFFERENT length from genesis (genuinely divergent tips).
    let mut nodes: Vec<TestContext> = (0..3).map(|_| TestContext::new(TestConsensus::new(&config))).collect();
    let lengths = [5usize, 8, 6];
    let mut chains: Vec<Vec<Block>> = Vec::new();
    for i in 0..nodes.len() {
        let mut blocks = Vec::new();
        for _ in 0..lengths[i] {
            blocks.push(nodes[i].mine_block(new_miner_data(), vec![]).await);
        }
        chains.push(blocks);
    }

    // Before gossip the nodes disagree (each sees only its own chain's tip).
    let pre: Vec<_> = nodes.iter().map(|n| n.consensus.get_sink()).collect();
    assert!(pre[0] != pre[1] || pre[1] != pre[2], "pre-gossip the nodes' sinks diverge");

    // Gossip: deliver every OTHER node's chain (parents-first) to each node.
    // Index-based: the inner `i == j` skip needs both indices, and `nodes[i]` is
    // borrowed mutably while `chains[j]` is borrowed immutably in the same body.
    #[allow(clippy::needless_range_loop)]
    for i in 0..nodes.len() {
        for j in 0..chains.len() {
            if i == j {
                continue;
            }
            for b in &chains[j] {
                nodes[i].validate_and_insert_block(b.clone()).await;
            }
        }
    }

    // After gossip every node holds the identical union DAG ⇒ all converge on ONE sink.
    let sinks: Vec<_> = nodes.iter().map(|n| n.consensus.get_sink()).collect();
    assert_eq!(sinks[0], sinks[1], "node 0 and node 1 converge on the same sink ({} vs {})", sinks[0], sinks[1]);
    assert_eq!(sinks[1], sinks[2], "node 1 and node 2 converge on the same sink ({} vs {})", sinks[1], sinks[2]);
    // The converged sink is the heaviest divergent chain's tip (node 1's 8-block chain), and every
    // node's chosen sink is one of the gossiped tips (a real block, not genesis).
    let tips: std::collections::HashSet<_> = chains.iter().map(|c| c.last().unwrap().header.hash).collect();
    assert!(tips.contains(&sinks[0]), "the converged sink is one of the mined chain tips");
}

/// kaspa-pq DNS-finality optional hard inclusion — SELECTIVE attestation CENSORSHIP below φS is invalid when enabled.
///
/// Two equal-stake validators A and B are both bonded. With φS = 60%, a block/template that includes
/// only A's attestation reaches 50% included stake and must be rejected by consensus. Including both
/// reaches 100%, clears the mandatory gate, and the block validates.
#[tokio::test]
async fn dag5_selective_censorship_below_quality_floor_is_rejected() {
    use kaspa_consensus_core::{Hash64, errors::block::RuleError};
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            dns.mandatory_attestation_inclusion_daa_score = 0;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let (va, vb) = (dns_harness::harness_validator([0x42u8; 32]), dns_harness::harness_validator([0x43u8; 32]));
    let payload_a: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&va.pubkey).as_bytes();
    let payload_b: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&vb.pubkey).as_bytes();
    let (spk_a, spk_b) = (p2pkh_mldsa87_spk(&payload_a), p2pkh_mldsa87_spk(&payload_b));

    // Fund: each validator needs one coinbase for the bond and one for the mandatory shard.
    let (miner_a, miner_b) = (MinerData::new(spk_a.clone(), vec![]), MinerData::new(spk_b.clone(), vec![]));
    let mut blocks = Vec::new();
    for _ in 0..4 {
        blocks.push(ctx.mine_block(miner_a.clone(), vec![]).await);
    }
    for _ in 0..4 {
        blocks.push(ctx.mine_block(miner_b.clone(), vec![]).await);
    }
    for _ in 0..5 {
        blocks.push(ctx.mine_block(new_miner_data(), vec![]).await);
    }
    let (mut a_funds, mut b_funds) = (Vec::new(), Vec::new());
    for blk in &blocks {
        let cb = &blk.transactions[0];
        for (i, o) in cb.outputs.iter().enumerate() {
            let f = (TransactionOutpoint::new(cb.id(), i as u32), o.value, blk.header.daa_score);
            if o.script_public_key == spk_a {
                a_funds.push(f);
            } else if o.script_public_key == spk_b {
                b_funds.push(f);
            }
        }
    }
    assert!(a_funds.len() >= 2 && b_funds.len() >= 2, "need ≥2 A / ≥2 B funding coinbases (a={}, b={})", a_funds.len(), b_funds.len());
    let ((cb_a_bond, va1, da_bond), (cb_a_att, va_att, da_a_att)) = (a_funds[0], a_funds[1]);
    let ((cb_b_bond, vb1, db_bond), (cb_b_e1, vb_e1, db_b_e1)) = (b_funds[0], b_funds[1]);

    // Bond A and B with EXACTLY equal stake. One validator alone is 50% < φS(60%).
    let storage = ctx.consensus.params().storage_mass_parameter;
    let bond_amount = va1.min(vb1) - 100_000;
    let (bond_a_tx, _, _) = dns_harness::funded_signed_bond_tx([0x42u8; 32], cb_a_bond, va1, da_bond, bond_amount, 0, storage);
    let (bond_b_tx, _, _) = dns_harness::funded_signed_bond_tx([0x43u8; 32], cb_b_bond, vb1, db_bond, bond_amount, 0, storage);
    let (bond_a_id, bond_b_id) = (bond_a_tx.id(), bond_b_tx.id());
    ctx.mine_block(new_miner_data(), vec![bond_a_tx]).await;
    ctx.mine_block(new_miner_data(), vec![bond_b_tx]).await;
    let (bond_a_outpoint, bond_b_outpoint) = (TransactionOutpoint::new(bond_a_id, 0), TransactionOutpoint::new(bond_b_id, 0));

    // Advance until the first ready epoch whose selected-parent chain is under-certified. Empty
    // templates are valid before that point and rejected exactly once the hard inclusion gate opens.
    let missing_epoch = {
        let mut guard = 0;
        loop {
            let res = ctx.consensus.build_block_template(
                new_miner_data(),
                Box::new(OnetimeTxSelector::new(Vec::new())),
                TemplateBuildMode::Standard,
            );
            match res {
                Ok(mut t) => {
                    guard += 1;
                    assert!(guard < 64, "expected the mandatory attestation gate to open");
                    ctx.simulated_time += ctx.consensus.params().target_time_per_block();
                    t.block.header.timestamp = ctx.simulated_time;
                    t.block.header.nonce = ctx.simulated_time;
                    t.block.header.finalize();
                    ctx.validate_and_insert_block(t.block.to_immutable()).await;
                }
                Err(RuleError::MissingMandatoryAttestationInBlock(epoch, included, expected, floor)) => {
                    assert_eq!(included, 0, "the first deficient epoch has no parent-chain attestation yet");
                    assert_eq!(expected, bond_amount.saturating_mul(2));
                    assert_eq!(floor, 6000);
                    break epoch;
                }
                Err(e) => panic!("unexpected template error before mandatory gate: {e:?}"),
            }
        }
    };

    let genesis_hash = ctx.consensus.params().genesis.hash;
    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let quality_deficit = ctx
        .consensus
        .get_attestation_quality_deficits()
        .into_iter()
        .find(|deficit| deficit.epoch == missing_epoch)
        .expect("quality-monitoring API reports the under-certified ready epoch");
    assert_eq!(quality_deficit.included_stake, 0);
    assert_eq!(quality_deficit.expected_stake, bond_amount.saturating_mul(2));
    assert_eq!(quality_deficit.required_stake_delta, quality_deficit.required_stake);

    let anchor_at = |ctx: &TestContext, epoch: u64| {
        let vp = ctx.consensus.virtual_processor();
        vp.canonical_anchor_by_blue_score(epoch, ctx.consensus.get_sink(), &dns).expect("canonical anchor")
    };

    let anchor_e1 = anchor_at(&ctx, missing_epoch);
    let att_a1 = dns_harness::build_signed_attestation(
        &va,
        genesis_hash.as_byte_slice(),
        bond_a_outpoint,
        missing_epoch,
        anchor_e1.anchor_hash,
        anchor_e1.anchor_daa_score,
        Hash64::default(),
    );
    let att_b1 = dns_harness::build_signed_attestation(
        &vb,
        genesis_hash.as_byte_slice(),
        bond_b_outpoint,
        missing_epoch,
        anchor_e1.anchor_hash,
        anchor_e1.anchor_daa_score,
        Hash64::default(),
    );
    let shard_a1 = dns_harness::funded_signed_shard_tx([0x42u8; 32], cb_a_att, va_att, da_a_att, att_a1, storage);
    let shard_b1 = dns_harness::funded_signed_shard_tx([0x43u8; 32], cb_b_e1, vb_e1, db_b_e1, att_b1, storage);

    // Selector snapshot regression: the deficits handed to the mining selector must be derived
    // from the same template snapshot as validation, including candidate-accepted txs. If A is
    // already accepted by the virtual candidate set, the selector should see only the remaining
    // stake delta, not the full floor from the selected-parent chain.
    let selector_snapshot_deficit = {
        let vp = ctx.consensus.virtual_processor();
        let bond_view = vp.initial_active_bond_view();
        let deficits = vp.mandatory_attestation_deficits_for_template_snapshot(
            ctx.consensus.get_sink(),
            ctx.consensus.get_virtual_daa_score(),
            &bond_view,
            std::slice::from_ref(&shard_a1),
        );
        deficits.into_iter().find(|deficit| deficit.epoch == missing_epoch).expect("candidate-accepted A leaves a reduced deficit")
    };
    assert_eq!(selector_snapshot_deficit.pre_body_included_stake, bond_amount);
    assert_eq!(
        selector_snapshot_deficit.required_stake_delta,
        selector_snapshot_deficit.required_stake.saturating_sub(bond_amount),
        "selector deficit must be reduced by candidate-accepted stake before body selection"
    );

    // A-only is selective censorship: 50% included stake is below the 60% quality floor, so the
    // template is not produced.
    let only_a = ctx.consensus.build_block_template(
        new_miner_data(),
        Box::new(OnetimeTxSelector::new(vec![shard_a1.clone()])),
        TemplateBuildMode::Standard,
    );
    match only_a {
        Err(RuleError::MissingMandatoryAttestationInBlock(epoch, included, expected, floor)) => {
            assert_eq!(epoch, missing_epoch);
            assert_eq!(included, bond_amount);
            assert_eq!(expected, bond_amount.saturating_mul(2));
            assert_eq!(floor, 6000);
        }
        other => panic!("A-only censorship template must be rejected, got {other:?}"),
    }

    // A+B reaches 100% included stake and validates.
    let block_full = ctx.mine_block(new_miner_data(), vec![shard_a1, shard_b1]).await;
    let reward = |blk: &Block, spk: &kaspa_consensus_core::tx::ScriptPublicKey| -> u64 {
        blk.transactions[0].outputs.iter().filter(|o| o.script_public_key == *spk).map(|o| o.value).sum()
    };
    let (a_reward_e1, b_reward_e1) = (reward(&block_full, &spk_a), reward(&block_full, &spk_b));
    assert!(a_reward_e1 > 0 && b_reward_e1 > 0, "both included validators are rewarded");
    assert_eq!(a_reward_e1, b_reward_e1, "equal stake gives equal participation reward");

    // Hard mandatory child-after-certification regression: a child of the certifying block must
    // not re-demand the epoch that the selected-parent chain already brought above the floor. It
    // may still stop on a later deficient ready epoch if the test chain has already advanced far
    // enough for another backlog item.
    let child_after_cert = ctx.consensus.build_block_template(
        new_miner_data(),
        Box::new(OnetimeTxSelector::new(Vec::new())),
        TemplateBuildMode::Standard,
    );
    match child_after_cert {
        Ok(_) => {}
        Err(RuleError::MissingMandatoryAttestationInBlock(epoch, ..)) => {
            assert_ne!(
                epoch, missing_epoch,
                "child-after-certification must not re-demand the epoch certified by its selected parent"
            );
        }
        other => panic!("child-after-certification must not fail with an unrelated error, got {other:?}"),
    }
}

/// kaspa-pq H-06 (unbond lifecycle): full-consensus unbond-REQUEST e2e + the client-side
/// funded builder (`funded_signed_unbond_tx`). A funded, ML-DSA-87-signed bond goes
/// Active; the owner then submits a funded, signed `StakeUnbondRequest` — the shape an
/// operator's exit tool produces. The including block must validate, exercising the live
/// unbond-authorization rule (`unbond_request_authorized`: bond present, Pending/Active,
/// owner-key binding `validator_id_from_pubkey(owner) == bond.owner_pubkey_hash`, and the
/// ML-DSA-87 signature over the bond-bound `unbond_request_message` under
/// `UNBOND_REQUEST_CONTEXT`). The release-after-`unbonding_period_blocks` spend is covered
/// by the apply-path unit tests (`allows_spend_of_releasable_bond`).
#[tokio::test]
async fn pos_v2_funded_unbond_request_validates() {
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            dns.stake_score_window_blue_score = 10_000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);

    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_b = ctx.mine_block(k_miner.clone(), vec![]).await;
    let cb_a = &h_a.transactions[0];
    let (ia, oa) = cb_a.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_a pays K");
    let (coinbase_a, value_a, daa_a) = (TransactionOutpoint::new(cb_a.id(), ia as u32), oa.value, h_a.header.daa_score);
    let cb_b = &h_b.transactions[0];
    let (ib, ob) = cb_b.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_b pays K");
    let (coinbase_b, value_b, daa_b) = (TransactionOutpoint::new(cb_b.id(), ib as u32), ob.value, h_b.header.daa_score);
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    let storage_mass_parameter = ctx.consensus.params().storage_mass_parameter;
    let bond_amount = value_a - 100_000;
    let (bond_tx, _vid, _rp) =
        dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, bond_amount, 0, storage_mass_parameter);
    let bond_tx_id = bond_tx.id();
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert_eq!(ctx.consensus.block_status(bond_block.header.hash), BlockStatus::StatusUTXOValid, "the bond block must be UTXO-valid");
    let bond_outpoint = TransactionOutpoint::new(bond_tx_id, 0);
    // Bury the bond so its record is committed into the active bond view the unbond rule reads.
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    // The owner submits a funded, ML-DSA-87-signed unbond request; the block must validate.
    // audit M-04: the authorization binds the network id (genesis hash), as the consensus rule reconstructs it.
    let net_id = ctx.consensus.params().genesis.hash;
    let unbond_tx = dns_harness::funded_signed_unbond_tx(
        seed,
        net_id.as_byte_slice(),
        coinbase_b,
        value_b,
        daa_b,
        bond_outpoint,
        storage_mass_parameter,
    );
    let unbond_block = ctx.mine_block(new_miner_data(), vec![unbond_tx]).await;
    assert_eq!(
        ctx.consensus.block_status(unbond_block.header.hash),
        BlockStatus::StatusUTXOValid,
        "the owner-authorized funded unbond request must validate through full consensus"
    );
}

/// kaspa-pq DNS v3 (PR2b): the processor's blue_score canonical-anchor walk
/// (`canonical_anchor_by_blue_score`) feeds the pure core the *real* selected-chain
/// `(hash, blue_score, daa_score)` ancestors, so the anchor it returns is a genuine
/// selected-chain block, most-recent-at-or-below the epoch cutoff, and stable as the tip
/// advances (the v3 position-invariance property). The hot path does not call it yet (PR4
/// wires it into the verifier), so this white-box test is the only thing exercising the
/// store walk until then. A future / unburied epoch must return `None`, never the tip.
#[tokio::test]
async fn dns_v3_canonical_anchor_walk_matches_chain() {
    use std::collections::HashMap;
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            // Tiny blue_score epochs so several bury within a short linear chain.
            // L=3, backoff=1 -> cutoff(E) = (E+1)*3 - 1 - 1 = 3E+1; lag=2.
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            p.dns_params = Some(dns);
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    // A linear chain (one block per row); each block's only parent is the prior tip, so
    // mergeset_blues = {selected_parent} and blue_score increments by exactly 1 (genesis = 0).
    let miner = new_miner_data();
    let mut by_blue: HashMap<u64, BlockHash> = HashMap::new();
    for _ in 0..20 {
        let b = ctx.mine_block(miner.clone(), vec![]).await;
        by_blue.insert(b.header.blue_score, b.header.hash);
    }

    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let tip = ctx.consensus.get_sink();
    let vp = ctx.consensus.virtual_processor();

    // cutoff(E) = 3E+1 on this dense chain, and every integer blue_score 0..=20 is present
    // exactly once, so the most-recent-at-or-below is the block whose blue_score == cutoff(E).
    let a0 = vp.canonical_anchor_by_blue_score(0, tip, &dns).expect("epoch 0 buried");
    assert_eq!(a0.epoch, 0);
    assert_eq!(a0.cutoff_blue_score, 1);
    assert_eq!(a0.anchor_blue_score, 1);
    assert_eq!(a0.anchor_hash, by_blue[&1], "epoch 0 anchors the real bs=1 block");
    assert!(!a0.duplicate_of_previous_anchor);

    let a1 = vp.canonical_anchor_by_blue_score(1, tip, &dns).expect("epoch 1 buried");
    assert_eq!(a1.cutoff_blue_score, 4);
    assert_eq!(a1.anchor_blue_score, 4);
    assert_eq!(a1.anchor_hash, by_blue[&4], "epoch 1 anchors the real bs=4 block");
    assert!(!a1.duplicate_of_previous_anchor); // distinct anchors on a dense chain

    // Position-invariance: anchor(0) is the SAME block no matter how far the tip advanced
    // (the walk reads blue_score, not the store index) — the core v3 property.
    let mid = by_blue[&10];
    let a0_mid = vp.canonical_anchor_by_blue_score(0, mid, &dns).expect("epoch 0 buried at mid-chain tip");
    assert_eq!(a0_mid.anchor_hash, a0.anchor_hash, "the anchor is independent of the observing tip");

    // A future / unburied epoch has no canonical anchor on this chain (cutoff > tip.blue_score)
    // and must NOT degenerate to returning the tip.
    assert!(vp.canonical_anchor_by_blue_score(1_000_000, tip, &dns).is_none());
}

/// kaspa-pq DNS v3 (PR4) — POSITIVE: an attestation that names THIS chain's canonical
/// lagged anchor for a ready blue_score epoch IS credited by the v3 verifier
/// (`collect_stake_contributions_v2`) with the bond's full stake, the per-epoch
/// denominator is keyed by the CANONICAL anchor DAA, and a ready epoch the validator did
/// NOT attest still appears in the denominator (so a participation gap is visible to φS
/// instead of vanishing — the v1 weakness). Reuses the funded-bond + funded-shard DAG-2
/// harness; the attestation is signed over the canonical `(epoch, anchor_hash,
/// anchor_daa_score)` rather than a free-floating self-reported target.
#[tokio::test]
async fn dns_v3_canonical_attestation_credited() {
    use crate::model::stores::{headers::HeaderStoreReader, stake_bonds::StakeBondsStoreReader};
    use kaspa_consensus_core::{Hash64, dns_finality::ready_epoch_from_tip_blue_score};
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 2;
            dns.max_reorg_horizon_blocks = 2;
            // Small blue_score epochs so several bury within this chain: L=3, backoff=1 ->
            // cutoff(E)=3E+1; lag=2 -> epoch E ready once tip_blue >= 3E+4.
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);

    // Fund a bond (coinbase_a) + a shard-funding coinbase (coinbase_b), same as the e2e.
    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_b = ctx.mine_block(k_miner.clone(), vec![]).await;
    let cb_a = &h_a.transactions[0];
    let (ia, oa) = cb_a.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_a pays K");
    let (coinbase_a, value_a, daa_a) = (TransactionOutpoint::new(cb_a.id(), ia as u32), oa.value, h_a.header.daa_score);
    let cb_b = &h_b.transactions[0];
    let (ib, ob) = cb_b.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_b pays K");
    let (coinbase_b, value_b, daa_b) = (TransactionOutpoint::new(cb_b.id(), ib as u32), ob.value, h_b.header.daa_score);
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let storage_mass_parameter = ctx.consensus.params().storage_mass_parameter;
    let (bond_tx, _vid, _reward_payload) =
        dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, value_a - 100_000, 0, storage_mass_parameter);
    let bond_tx_id = bond_tx.id();
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert_eq!(ctx.consensus.block_status(bond_block.header.hash), BlockStatus::StatusUTXOValid, "the bond block is UTXO-valid");
    let bond_outpoint = TransactionOutpoint::new(bond_tx_id, 0);

    // Bury several blue_score epochs past the bond so a ready, bond-active anchor exists.
    for _ in 0..8 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    // THIS chain's canonical anchor for the latest ready epoch at the current sink.
    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let genesis_hash = ctx.consensus.params().genesis.hash;
    let sink = ctx.consensus.get_sink();
    let anchor = {
        let vp = ctx.consensus.virtual_processor();
        let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
        let latest_ready =
            ready_epoch_from_tip_blue_score(sink_blue, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
                .expect("an epoch is ready");
        vp.canonical_anchor_by_blue_score(latest_ready, sink, &dns).expect("canonical anchor for the ready epoch")
    };

    // Sign an attestation that names the canonical anchor exactly, fund + include it.
    let att = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        anchor.epoch,
        anchor.anchor_hash,
        anchor.anchor_daa_score,
        Hash64::default(),
    );
    let shard_tx = dns_harness::funded_signed_shard_tx(seed, coinbase_b, value_b, daa_b, att, storage_mass_parameter);
    let reward_block = ctx.mine_block(new_miner_data(), vec![shard_tx]).await;
    assert_eq!(
        ctx.consensus.block_status(reward_block.header.hash),
        BlockStatus::StatusUTXOValid,
        "the canonical-attestation block validates"
    );
    // Mine 2 fillers so the shard is MERGED -> accepted by a chain block in past(sink), the
    // view the StakeScore verifier walks (accepted txs, not a block's own body).
    ctx.mine_block(new_miner_data(), vec![]).await;
    ctx.mine_block(new_miner_data(), vec![]).await;

    let new_sink = ctx.consensus.get_sink();
    let (contributions, denom, bond_amount) = {
        let vp = ctx.consensus.virtual_processor();
        let bonds: Vec<_> = vp.stake_bonds_store.read().iterator().filter_map(|r| r.ok().map(|(_, rec)| (*rec).clone())).collect();
        let bond_amount = bonds.iter().find(|b| b.bond_outpoint == bond_outpoint).expect("the funded bond is persisted").amount;
        let (c, d, _) = vp.collect_stake_contributions_v2(new_sink, None, &bonds, genesis_hash.as_byte_slice(), &dns);
        (c, d, bond_amount)
    };

    // The canonical attestation is credited with the bond's full stake at its epoch.
    let credited = contributions.iter().find(|c| c.bond_outpoint == bond_outpoint).expect("the canonical attestation is credited");
    assert_eq!(credited.epoch, anchor.epoch, "credited at the canonical epoch");
    assert_eq!(credited.signed_stake_sompi, bond_amount, "credited with the bond's full stake");
    // The denominator is keyed by the CANONICAL anchor DAA for that epoch.
    assert_eq!(denom.get(&anchor.epoch).copied(), Some(anchor.anchor_daa_score), "denominator keyed by the canonical anchor DAA");
    // A ready epoch with no attestation still appears in the denominator (visible gap).
    assert!(
        denom.keys().any(|&e| !contributions.iter().any(|c| c.epoch == e)),
        "a ready, un-attested epoch is still in the denominator (got epochs {:?})",
        denom.keys().collect::<Vec<_>>()
    );
}

/// kaspa-pq DNS v3 (PR4) — NEGATIVE: a validly-signed, bonded, reward-eligible attestation
/// for a ready epoch whose `target_hash` is NOT this chain's canonical anchor is NOT
/// credited by the v3 verifier. The including block still validates (the reward path is
/// migrated to the canonical rule in PR5; until then a non-canonical attestation can still
/// earn the v1 reward), which is exactly the divergence PR5 closes — here we prove the
/// StakeScore verifier already refuses the non-canonical target.
#[tokio::test]
async fn dns_v3_noncanonical_attestation_rejected() {
    use crate::model::stores::{headers::HeaderStoreReader, stake_bonds::StakeBondsStoreReader};
    use kaspa_consensus_core::{Hash64, dns_finality::ready_epoch_from_tip_blue_score};
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            // Wide reward recency so the canonical anchor is comfortably in-window: the only
            // reason the bogus-target attestation earns nothing is the v3 canonical gate.
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);

    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_b = ctx.mine_block(k_miner.clone(), vec![]).await;
    let cb_a = &h_a.transactions[0];
    let (ia, oa) = cb_a.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_a pays K");
    let (coinbase_a, value_a, daa_a) = (TransactionOutpoint::new(cb_a.id(), ia as u32), oa.value, h_a.header.daa_score);
    let cb_b = &h_b.transactions[0];
    let (ib, ob) = cb_b.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_b pays K");
    let (coinbase_b, value_b, daa_b) = (TransactionOutpoint::new(cb_b.id(), ib as u32), ob.value, h_b.header.daa_score);
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let storage_mass_parameter = ctx.consensus.params().storage_mass_parameter;
    let (bond_tx, _vid, _reward_payload) =
        dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, value_a - 100_000, 0, storage_mass_parameter);
    let bond_tx_id = bond_tx.id();
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert_eq!(ctx.consensus.block_status(bond_block.header.hash), BlockStatus::StatusUTXOValid);
    let bond_outpoint = TransactionOutpoint::new(bond_tx_id, 0);
    for _ in 0..8 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let genesis_hash = ctx.consensus.params().genesis.hash;
    let sink = ctx.consensus.get_sink();
    let anchor = {
        let vp = ctx.consensus.virtual_processor();
        let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
        let latest_ready =
            ready_epoch_from_tip_blue_score(sink_blue, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
                .expect("an epoch is ready");
        vp.canonical_anchor_by_blue_score(latest_ready, sink, &dns).expect("canonical anchor for the ready epoch")
    };

    // Same ready epoch + canonical DAA, but a BOGUS target_hash (not this chain's anchor).
    let bogus_target = Hash64::from_bytes([0xdeu8; 64]);
    assert_ne!(bogus_target, anchor.anchor_hash);
    let att = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        anchor.epoch,
        bogus_target,
        anchor.anchor_daa_score,
        Hash64::default(),
    );
    let shard_tx = dns_harness::funded_signed_shard_tx(seed, coinbase_b, value_b, daa_b, att, storage_mass_parameter);
    let reward_block = ctx.mine_block(new_miner_data(), vec![shard_tx]).await;
    assert_eq!(
        ctx.consensus.block_status(reward_block.header.hash),
        BlockStatus::StatusUTXOValid,
        "the block still validates — the canonical-gated reward fan-out simply pays nothing for the non-canonical attestation (same in construction + validation)"
    );
    // PR5: the §E reward fan-out is canonical-gated, so the non-canonical attestation earns
    // NO coinbase reward (only output to K would be the §E reward; the miner is a different spk).
    let reward_to_validator = reward_block.transactions[0].outputs.iter().find(|o| o.script_public_key == k_spk).map(|o| o.value);
    assert_eq!(reward_to_validator, None, "a non-canonical attestation earns no §E reward (PR5)");

    ctx.mine_block(new_miner_data(), vec![]).await;
    ctx.mine_block(new_miner_data(), vec![]).await;

    let new_sink = ctx.consensus.get_sink();
    let (contributions, denom, _) = {
        let vp = ctx.consensus.virtual_processor();
        let bonds: Vec<_> = vp.stake_bonds_store.read().iterator().filter_map(|r| r.ok().map(|(_, rec)| (*rec).clone())).collect();
        vp.collect_stake_contributions_v2(new_sink, None, &bonds, genesis_hash.as_byte_slice(), &dns)
    };

    // The non-canonical attestation also earns NO StakeScore credit (PR4)...
    assert!(contributions.iter().all(|c| c.bond_outpoint != bond_outpoint), "a non-canonical-target attestation must not be credited");
    // ...even though its epoch IS a ready, creditable epoch (present in the denominator).
    assert!(denom.contains_key(&anchor.epoch), "the epoch is ready/creditable; only the non-canonical target is rejected");
}

/// kaspa-pq DNS v3 (PR3) — the signer hands the validator the canonical lagged anchor, NOT
/// the live sink. The singular `get_validator_attestation_target` returns the oldest READY
/// canonical anchor for which the requested bond is Active (matching the hard-inclusion gate's
/// oldest-first backlog order), and the batch `get_validator_attestation_targets` returns every
/// ready, non-duplicate, bond-active epoch ascending up to the latest — so a fallen-behind
/// validator can catch up. Both feed the exact target the PR4 verifier credits.
#[tokio::test]
async fn dns_v3_signer_produces_canonical_ready_targets() {
    use crate::model::stores::headers::HeaderStoreReader;
    use kaspa_consensus_core::{Hash64, dns_finality::ready_epoch_from_tip_blue_score};
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);
    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    let cb_a = &h_a.transactions[0];
    let (ia, oa) = cb_a.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_a pays K");
    let (coinbase_a, value_a, daa_a) = (TransactionOutpoint::new(cb_a.id(), ia as u32), oa.value, h_a.header.daa_score);
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let storage = ctx.consensus.params().storage_mass_parameter;
    let (bond_tx, _, _) = dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, value_a - 100_000, 0, storage);
    let bond_tx_id = bond_tx.id();
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert_eq!(ctx.consensus.block_status(bond_block.header.hash), BlockStatus::StatusUTXOValid);
    let outpoint = TransactionOutpoint::new(bond_tx_id, 0);

    let miner = new_miner_data();
    for _ in 0..20 {
        ctx.mine_block(miner.clone(), vec![]).await;
    }

    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let sink = ctx.consensus.get_sink();

    // The singular target == the first batch target: the oldest ready epoch for which this bond is
    // active at the canonical anchor.
    let target = ctx.consensus.get_validator_attestation_target(outpoint).expect("a ready canonical target");
    let (latest_ready, anchor) = {
        let vp = ctx.consensus.virtual_processor();
        let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
        let lr = ready_epoch_from_tip_blue_score(sink_blue, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
            .expect("an epoch is ready");
        (lr, vp.canonical_anchor_by_blue_score(target.epoch, sink, &dns).expect("canonical anchor for the singular target"))
    };
    assert!(target.epoch <= latest_ready, "the singular target is no later than the latest ready epoch");
    assert_eq!(target.target_hash, anchor.anchor_hash, "target is the canonical anchor hash");
    assert_eq!(target.target_daa_score, anchor.anchor_daa_score, "target daa is the canonical anchor daa");
    assert_eq!(target.validator_set_commitment, Hash64::default(), "VSC is a fixed zero (P-1D)");

    // The batch returns every ready, non-duplicate, bond-active epoch ascending up to the latest.
    let targets = ctx.consensus.get_validator_attestation_targets(outpoint, 0, 100);
    assert!(!targets.is_empty());
    assert!(targets.windows(2).all(|w| w[0].epoch < w[1].epoch), "ascending, unique epochs");
    assert_eq!(target.epoch, targets[0].epoch, "singular target follows oldest-first backlog order");
    assert_eq!(targets.last().unwrap().epoch, latest_ready, "the batch reaches the latest ready epoch");
    {
        let vp = ctx.consensus.virtual_processor();
        for t in &targets {
            let a = vp.canonical_anchor_by_blue_score(t.epoch, sink, &dns).expect("each batched epoch has a canonical anchor");
            assert!(!a.duplicate_of_previous_anchor, "duplicate epochs are excluded from the batch");
            assert_eq!(t.target_hash, a.anchor_hash);
            assert_eq!(t.target_daa_score, a.anchor_daa_score);
        }
    }

    // A `from_epoch` past the latest ready epoch yields nothing (no future epochs to sign).
    assert!(ctx.consensus.get_validator_attestation_targets(outpoint, latest_ready + 1, 100).is_empty());
}

/// kaspa-pq DNS v3 (PR6) — high-parallel no-hole: on a WIDE DAG the selected chain's
/// blue_score jumps by the merged-set size, skipping whole epoch [start, end] ranges. Every
/// buried epoch must still resolve to a canonical anchor (the most-recent selected-chain block
/// at-or-below its cutoff — which, for a skipped epoch, is a block below the jump → a
/// correctly-flagged duplicate), NEVER a hole (None / panic). This is the DAG-level analogue of
/// PR2a's pure `no-hole-on-jump` test, exercising the real store walk over a jumpy chain.
#[tokio::test]
async fn dns_v3_high_parallel_blue_score_jump_no_hole() {
    use crate::model::stores::headers::HeaderStoreReader;
    use kaspa_consensus_core::dns_finality::ready_epoch_from_tip_blue_score;
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 16;
            p.mergeset_size_limit = 16;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            // Small epochs vs. wide merges (up to 16) so a single merge jumps past whole epochs.
            dns.attestation_epoch_length_blue_score = 5;
            dns.attestation_lag_blue_score = 3;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 100_000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Warm up, then alternate WIDE antichains + single merge blocks so the selected chain's
    // blue_score jumps by the merged set size (skipping whole epoch ranges), then settle.
    for _ in 0..3 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    for _ in 0..4 {
        ctx.build_block_template_row(0..14).validate_and_insert_row().await; // wide antichain
        ctx.build_block_template_row(0..1).validate_and_insert_row().await; // merge -> blue_score jump
    }
    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    ctx.assert_tips_num(1);

    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let sink = ctx.consensus.get_sink();
    let vp = ctx.consensus.virtual_processor();
    let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
    let latest_ready =
        ready_epoch_from_tip_blue_score(sink_blue, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
            .expect("epochs are ready on a chain this long");
    assert!(latest_ready >= 2, "the chain spans several epochs (latest_ready = {latest_ready})");

    // NO HOLE + monotonic: every buried epoch resolves to a canonical anchor whose blue_score is
    // non-decreasing across epochs, even across the blue_score jumps.
    let mut prev_blue = 0u64;
    let mut distinct = std::collections::HashSet::new();
    for e in 0..=latest_ready {
        let a = vp.canonical_anchor_by_blue_score(e, sink, &dns).unwrap_or_else(|| panic!("epoch {e} has no canonical anchor (hole)"));
        assert!(a.anchor_blue_score >= prev_blue, "anchor blue_score is monotonic across epochs");
        prev_blue = a.anchor_blue_score;
        distinct.insert(a.anchor_hash);
    }
    // The wide merges actually skipped >=1 epoch range: fewer distinct anchors than epochs (some
    // epochs share an anchor) — proving the test exercised real blue_score jumps, not a dense chain.
    assert!(
        distinct.len() <= latest_ready as usize,
        "a blue_score jump made >=1 epoch reuse a prior anchor ({} distinct anchors over {} epochs)",
        distinct.len(),
        latest_ready + 1
    );
}

/// kaspa-pq DNS v3 — the validator FUNCTIONS end-to-end: a bonded validator's canonical
/// attestation drives the StakeScore over `required_stake_depth`, so `update_dns_state`
/// promotes the overlay to the `Active` stage AND records a DNS-confirmed anchor — the
/// precondition the §H reorg gate needs to protect finality. Shrunk params: a single
/// validator is the whole active stake, so one fully-attested ready epoch earns exactly
/// `1·SCALE`, clearing `required_stake_depth = SCALE/2`. (Foundation for the 51%-attack test.)
#[tokio::test]
async fn dns_v3_validator_drives_confirmed_anchor() {
    use crate::model::stores::{dns_state::DnsStateStoreReader, headers::HeaderStoreReader};
    use kaspa_consensus_core::{
        Hash64,
        dns_finality::{DnsRolloutStage, STAKE_SCORE_SCALE, StakeScore, ready_epoch_from_tip_blue_score},
    };
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap(); // GENESIS_ACTIVE: TwoDimensionalDominance
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            // Confirm on a short chain: work threshold trivial, one fully-attested epoch suffices.
            dns.required_work_depth = kaspa_consensus_core::BlueWorkType::ZERO;
            dns.required_stake_depth = StakeScore(STAKE_SCORE_SCALE / 2);
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);

    // Fund a bond + a shard-funding coinbase.
    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_b = ctx.mine_block(k_miner.clone(), vec![]).await;
    let cb_a = &h_a.transactions[0];
    let (ia, oa) = cb_a.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_a pays K");
    let (coinbase_a, value_a, daa_a) = (TransactionOutpoint::new(cb_a.id(), ia as u32), oa.value, h_a.header.daa_score);
    let cb_b = &h_b.transactions[0];
    let (ib, ob) = cb_b.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_b pays K");
    let (coinbase_b, value_b, daa_b) = (TransactionOutpoint::new(cb_b.id(), ib as u32), ob.value, h_b.header.daa_score);
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let storage_mass_parameter = ctx.consensus.params().storage_mass_parameter;
    let (bond_tx, _vid, _reward_payload) =
        dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, value_a - 100_000, 0, storage_mass_parameter);
    let bond_tx_id = bond_tx.id();
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert_eq!(ctx.consensus.block_status(bond_block.header.hash), BlockStatus::StatusUTXOValid);
    let bond_outpoint = TransactionOutpoint::new(bond_tx_id, 0);

    for _ in 0..8 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let genesis_hash = ctx.consensus.params().genesis.hash;
    let sink = ctx.consensus.get_sink();
    let anchor = {
        let vp = ctx.consensus.virtual_processor();
        let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
        let lr = ready_epoch_from_tip_blue_score(sink_blue, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
            .expect("an epoch is ready");
        vp.canonical_anchor_by_blue_score(lr, sink, &dns).expect("canonical anchor")
    };
    let att = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        anchor.epoch,
        anchor.anchor_hash,
        anchor.anchor_daa_score,
        Hash64::default(),
    );
    let shard_tx = dns_harness::funded_signed_shard_tx(seed, coinbase_b, value_b, daa_b, att, storage_mass_parameter);
    let reward_block = ctx.mine_block(new_miner_data(), vec![shard_tx]).await;
    assert_eq!(ctx.consensus.block_status(reward_block.header.hash), BlockStatus::StatusUTXOValid);

    // Mine generously so the shard merges (accepted on the selected chain), the attested epoch
    // buries, and update_dns_state recomputes (it throttles to once per blue_score epoch) with
    // the attestation credited -> stake_depth >= required -> the anchor confirms.
    for _ in 0..15 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    let state = {
        let vp = ctx.consensus.virtual_processor();
        vp.dns_state_store.read().get().expect("DnsState is written once the overlay is active")
    };
    assert_eq!(state.rollout_stage, DnsRolloutStage::Active, "one active validator -> Active stage");
    assert!(
        state.stake_depth >= StakeScore(STAKE_SCORE_SCALE / 2),
        "the validator's canonical attestation drove StakeScore over the threshold (got {:?})",
        state.stake_depth
    );
    assert_ne!(
        state.last_dns_confirmed_anchor,
        Hash64::default(),
        "a DNS-confirmed anchor is recorded (the reorg gate now protects it)"
    );
}

/// kaspa-pq DNS-finality (E3/§6.2 template integration) — a refill-capable selector for the
/// template-adoption tests: returns its candidate batches in order (one per
/// `select_transactions` call) and never reports failure on rejection, so a classifier-driven
/// `reject_selection` (an ineligible-shard drop) triggers the builder's refill loop pulling the
/// next batch — exactly the production frontier-selector refill semantics, without a mempool.
struct RefillTxSelector {
    batches: VecDeque<Vec<Transaction>>,
    rejected: Vec<kaspa_consensus_core::tx::TransactionId>,
}

impl RefillTxSelector {
    fn new(batches: Vec<Vec<Transaction>>) -> Self {
        Self { batches: batches.into(), rejected: vec![] }
    }
}

impl TemplateTransactionSelector for RefillTxSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        self.batches.pop_front().unwrap_or_default()
    }
    fn reject_selection(&mut self, tx_id: kaspa_consensus_core::tx::TransactionId) {
        self.rejected.push(tx_id);
    }
    // Infallible from the selector's POV: rejections are refills, not failures. The
    // tests build with `TemplateBuildMode::Infallible` so the rejection never aborts.
    fn is_successful(&self) -> bool {
        true
    }
}

/// Shared setup for the template-adoption tests (E3/§6.2): bond one validator, bury several
/// blue_score epochs so a ready bond-active anchor exists, and return the context plus the
/// validator, the canonical anchor, and TWO matured shard-funding coinbase outpoints (so two
/// distinct funded shards can be built in one test). Mirrors the `dns_v3_*` preamble.
#[cfg(test)]
async fn template_adoption_setup() -> (
    TestContext,
    dns_harness::HarnessValidator,
    TransactionOutpoint,                                            // bond outpoint
    kaspa_consensus_core::dns_finality::CanonicalLaggedEpochAnchor, // canonical anchor for latest ready epoch
    (TransactionOutpoint, u64, u64),                                // shard-funding coinbase #1 (outpoint, value, daa)
    (TransactionOutpoint, u64, u64),                                // shard-funding coinbase #2 (outpoint, value, daa)
    kaspa_consensus_core::dns_finality::DnsParams,
    BlockHash, // genesis hash (net id)
    u64,       // storage_mass_parameter
) {
    use crate::model::stores::headers::HeaderStoreReader;
    use kaspa_consensus_core::dns_finality::ready_epoch_from_tip_blue_score;
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 50;
            dns.max_reorg_horizon_blocks = 2;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);
    let k_miner = MinerData::new(k_spk.clone(), vec![]);

    // coinbase_a funds the bond; coinbase_b + coinbase_c fund two shards.
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_b = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_c = ctx.mine_block(k_miner.clone(), vec![]).await;
    let pick = |h: &Block| {
        let cb = &h.transactions[0];
        let (i, o) = cb.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("pays K");
        (TransactionOutpoint::new(cb.id(), i as u32), o.value, h.header.daa_score)
    };
    let (coinbase_a, value_a, daa_a) = pick(&h_a);
    let cb_b = pick(&h_b);
    let cb_c = pick(&h_c);
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let storage_mass_parameter = ctx.consensus.params().storage_mass_parameter;
    let (bond_tx, _vid, _rp) =
        dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, value_a - 100_000, 0, storage_mass_parameter);
    let bond_tx_id = bond_tx.id();
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert_eq!(ctx.consensus.block_status(bond_block.header.hash), BlockStatus::StatusUTXOValid);
    let bond_outpoint = TransactionOutpoint::new(bond_tx_id, 0);
    for _ in 0..8 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let genesis_hash = ctx.consensus.params().genesis.hash;
    let sink = ctx.consensus.get_sink();
    let anchor = {
        let vp = ctx.consensus.virtual_processor();
        let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
        let lr = ready_epoch_from_tip_blue_score(sink_blue, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
            .expect("an epoch is ready");
        vp.canonical_anchor_by_blue_score(lr, sink, &dns).expect("canonical anchor")
    };
    (ctx, v, bond_outpoint, anchor, cb_b, cb_c, dns, genesis_hash, storage_mass_parameter)
}

/// kaspa-pq DNS-finality (E3/§6.2, test T3): a mempool-submitted ELIGIBLE attestation shard
/// appears as a non-coinbase tx in `build_block_template` output (the construction path now
/// classifies + keeps eligible shards at selection time instead of dropping them late).
#[tokio::test]
async fn t3_eligible_shard_in_block_template() {
    use kaspa_consensus_core::Hash64;
    let (ctx, v, bond_outpoint, anchor, cb_b, _cb_c, dns, genesis_hash, smp) = template_adoption_setup().await;
    let att = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        anchor.epoch,
        anchor.anchor_hash,
        anchor.anchor_daa_score,
        Hash64::default(),
    );
    let shard_tx = dns_harness::funded_signed_shard_tx(v.seed, cb_b.0, cb_b.1, cb_b.2, att, smp);
    let shard_id = shard_tx.id();

    let template = ctx
        .consensus
        .build_block_template(new_miner_data(), Box::new(OnetimeTxSelector::new(vec![shard_tx])), TemplateBuildMode::Standard)
        .expect("template builds with the eligible shard");
    // The eligible shard is included as a non-coinbase tx.
    assert!(
        template.block.transactions.iter().skip(1).any(|t| t.id() == shard_id),
        "the eligible attestation shard must appear in the template"
    );
    // T5 (fee alignment): calculated_fees stays 1:1 with the non-coinbase txs.
    assert_eq!(
        template.calculated_fees.len(),
        template.block.transactions.len() - 1,
        "calculated_fees must be 1:1 with the non-coinbase txs"
    );
    let _ = dns; // params used by setup; silence unused on some builds
}

/// kaspa-pq DNS-finality (E3/§6.2, test T4): an INELIGIBLE shard selected first is rejected
/// (refilled) and an ELIGIBLE shard from the next batch is included instead. Uses the
/// refill-capable selector + `Infallible` build so the classifier drop triggers a refill, not
/// a build failure.
#[tokio::test]
async fn t4_ineligible_shard_refilled_with_eligible() {
    use kaspa_consensus_core::Hash64;
    let (ctx, v, bond_outpoint, anchor, cb_b, cb_c, _dns, genesis_hash, smp) = template_adoption_setup().await;

    // Ineligible: correct bond + signature but a WRONG self-declared validator_id (P-1A
    // mismatch) ⇒ classifier `Drop(ValidatorIdMismatch)`. Still a structurally valid funded tx
    // (so it passes block-template tx validation and reaches the classifier).
    let mut bad_att = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        anchor.epoch,
        anchor.anchor_hash,
        anchor.anchor_daa_score,
        Hash64::default(),
    );
    bad_att.validator_id = Hash64::from_bytes([0xff; 64]); // ≠ bond.validator_pubkey_hash
    let bad_shard = dns_harness::funded_signed_shard_tx(v.seed, cb_b.0, cb_b.1, cb_b.2, bad_att, smp);
    let bad_id = bad_shard.id();

    // Eligible: correct id + signature + canonical anchor.
    let good_att = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        anchor.epoch,
        anchor.anchor_hash,
        anchor.anchor_daa_score,
        Hash64::default(),
    );
    let good_shard = dns_harness::funded_signed_shard_tx(v.seed, cb_c.0, cb_c.1, cb_c.2, good_att, smp);
    let good_id = good_shard.id();

    // Batch 1 = the ineligible shard (dropped+refilled); batch 2 = the eligible shard (kept).
    let selector = RefillTxSelector::new(vec![vec![bad_shard], vec![good_shard]]);
    let template = ctx
        .consensus
        .build_block_template(new_miner_data(), Box::new(selector), TemplateBuildMode::Infallible)
        .expect("template builds (infallible)");

    let ids: Vec<_> = template.block.transactions.iter().skip(1).map(|t| t.id()).collect();
    assert!(!ids.contains(&bad_id), "the ineligible shard must be dropped from the template");
    assert!(ids.contains(&good_id), "the eligible refill shard must be included instead");
    // T5 (fee alignment) after a drop+refill: still 1:1.
    assert_eq!(
        template.calculated_fees.len(),
        template.block.transactions.len() - 1,
        "calculated_fees must stay 1:1 with the non-coinbase txs after a drop+refill"
    );
}

/// kaspa-pq DNS-finality (P1, duplicate-epoch credit regression): the SAME (bond, epoch)
/// attestation accepted TWICE on the selected chain is credited to StakeScore only ONCE
/// (`collect_stake_contributions_v2` dedups by the canonical-anchor gate + the
/// `aggregate_epoch_tallies` per-(bond,epoch) collapse). This pins the existing — and, as the
/// investigation found, already-correct — behavior so a future change cannot start double-crediting.
#[tokio::test]
async fn duplicate_epoch_attestation_credited_once() {
    use crate::model::stores::stake_bonds::StakeBondsStoreReader;
    use kaspa_consensus_core::{
        Hash64,
        dns_finality::{aggregate_epoch_tallies, total_active_stake_by_epoch},
    };
    let (mut ctx, v, bond_outpoint, anchor, cb_b, cb_c, dns, genesis_hash, smp) = template_adoption_setup().await;

    // Two shards naming the SAME canonical (epoch, anchor) for the SAME bond, funded from two
    // distinct coinbases so both are structurally valid + can both be mined/accepted.
    let mk = |cb: (TransactionOutpoint, u64, u64)| {
        let att = dns_harness::build_signed_attestation(
            &v,
            genesis_hash.as_byte_slice(),
            bond_outpoint,
            anchor.epoch,
            anchor.anchor_hash,
            anchor.anchor_daa_score,
            Hash64::default(),
        );
        dns_harness::funded_signed_shard_tx(v.seed, cb.0, cb.1, cb.2, att, smp)
    };
    let shard1 = mk(cb_b);
    let shard2 = mk(cb_c);
    let b1 = ctx.mine_block(new_miner_data(), vec![shard1]).await;
    assert_eq!(ctx.consensus.block_status(b1.header.hash), BlockStatus::StatusUTXOValid);
    let b2 = ctx.mine_block(new_miner_data(), vec![shard2]).await;
    assert_eq!(ctx.consensus.block_status(b2.header.hash), BlockStatus::StatusUTXOValid);
    // Bury so both merge onto the selected chain.
    for _ in 0..4 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    let new_sink = ctx.consensus.get_sink();
    let vp = ctx.consensus.virtual_processor();
    let bonds: Vec<_> = vp.stake_bonds_store.read().iterator().filter_map(|r| r.ok().map(|(_, rec)| (*rec).clone())).collect();
    let (contributions, denom, _) = vp.collect_stake_contributions_v2(new_sink, None, &bonds, genesis_hash.as_byte_slice(), &dns);

    // The (bond, epoch) pair is credited at most once even though two shards carry it.
    let credited_for_epoch = contributions.iter().filter(|c| c.bond_outpoint == bond_outpoint && c.epoch == anchor.epoch).count();
    assert!(credited_for_epoch >= 1, "the canonical attestation is credited at least once");
    // After the per-(bond,epoch) aggregation, the signed stake for this epoch equals the bond's
    // stake exactly ONCE (no double-count from the duplicate shard).
    let totals = total_active_stake_by_epoch(&bonds, &denom);
    let per_epoch = aggregate_epoch_tallies(&contributions, &totals);
    let bond_amount = bonds.iter().find(|b| b.bond_outpoint == bond_outpoint).expect("bond persisted").amount;
    let tally = per_epoch.iter().find(|t| t.epoch == anchor.epoch).expect("the epoch is tallied");
    assert_eq!(
        tally.signed_stake_sompi, bond_amount,
        "the duplicate (bond, epoch) is credited exactly once (signed stake == one bond's stake, got {})",
        tally.signed_stake_sompi
    );
}

/// kaspa-pq DNS v3 (§H finality) — **51%-PoW attack is stopped**: a stake-less attacker that
/// out-mines the honest chain (strictly higher blue_work — a PoW majority) CANNOT rewrite a
/// DNS-confirmed anchor. The honest node bonds a validator and reaches a confirmed anchor;
/// a second consensus instance (the attacker, same genesis) mines a longer STAKE-LESS chain;
/// its heavier blocks are delivered to the honest node, whose sink-search runs the
/// `TwoDimensionalDominance` gate (`dns_reorg_allows`): the candidate exits the confirmed
/// prefix and out-Works but does NOT out-Stake (zero attestations) → `DominanceViolation` →
/// soft-reject. The honest sink therefore STILL contains the confirmed anchor, never the
/// heavier attacker tip — PoW surplus does not substitute for a PoS deficit (the
/// non-substitutability finality property). Completes the PR6-deferred 51%-finality-stop sim.
#[tokio::test]
async fn dns_v3_pow_majority_cannot_rewrite_confirmed_anchor() {
    use crate::model::stores::{dns_state::DnsStateStoreReader, ghostdag::GhostdagStoreReader, headers::HeaderStoreReader};
    use kaspa_consensus_core::{
        Hash64,
        dns_finality::{DnsRolloutStage, STAKE_SCORE_SCALE, StakeScore, ready_epoch_from_tip_blue_score},
    };
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.coinbase_maturity = 2;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap(); // GENESIS_ACTIVE: TwoDimensionalDominance
            dns.dns_activation_daa_score = 0;
            dns.pos_v2_activation_daa_score = 0;
            dns.epoch_length_blocks = 2;
            dns.reward_uniqueness_window_blocks = 50;
            // Large reorg horizon so a from-genesis fork is GATE-ELIGIBLE (the dominance test
            // runs) instead of being auto-rejected as deeper than the horizon.
            dns.max_reorg_horizon_blocks = 1000;
            dns.attestation_epoch_length_blue_score = 3;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.stake_score_window_blue_score = 10_000;
            dns.required_work_depth = kaspa_consensus_core::BlueWorkType::ZERO;
            dns.required_stake_depth = StakeScore(STAKE_SCORE_SCALE / 2);
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // ---- Honest node: bond a validator, attest, reach a DNS-confirmed anchor. ----
    let seed = [0x42u8; 32];
    let v = dns_harness::harness_validator(seed);
    let k_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&v.pubkey).as_bytes();
    let k_spk = p2pkh_mldsa87_spk(&k_payload);
    let k_miner = MinerData::new(k_spk.clone(), vec![]);
    let _b1 = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_a = ctx.mine_block(k_miner.clone(), vec![]).await;
    let h_b = ctx.mine_block(k_miner.clone(), vec![]).await;
    let cb_a = &h_a.transactions[0];
    let (ia, oa) = cb_a.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_a pays K");
    let (coinbase_a, value_a, daa_a) = (TransactionOutpoint::new(cb_a.id(), ia as u32), oa.value, h_a.header.daa_score);
    let cb_b = &h_b.transactions[0];
    let (ib, ob) = cb_b.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == k_spk).expect("h_b pays K");
    let (coinbase_b, value_b, daa_b) = (TransactionOutpoint::new(cb_b.id(), ib as u32), ob.value, h_b.header.daa_score);
    for _ in 0..5 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let storage_mass_parameter = ctx.consensus.params().storage_mass_parameter;
    let (bond_tx, _vid, _rp) =
        dns_harness::funded_signed_bond_tx(seed, coinbase_a, value_a, daa_a, value_a - 100_000, 0, storage_mass_parameter);
    let bond_tx_id = bond_tx.id();
    let bond_block = ctx.mine_block(new_miner_data(), vec![bond_tx]).await;
    assert_eq!(ctx.consensus.block_status(bond_block.header.hash), BlockStatus::StatusUTXOValid);
    let bond_outpoint = TransactionOutpoint::new(bond_tx_id, 0);
    for _ in 0..8 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }
    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let genesis_hash = ctx.consensus.params().genesis.hash;
    let sink = ctx.consensus.get_sink();
    let anchor = {
        let vp = ctx.consensus.virtual_processor();
        let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
        let lr = ready_epoch_from_tip_blue_score(sink_blue, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
            .expect("an epoch is ready");
        vp.canonical_anchor_by_blue_score(lr, sink, &dns).expect("canonical anchor")
    };
    let att = dns_harness::build_signed_attestation(
        &v,
        genesis_hash.as_byte_slice(),
        bond_outpoint,
        anchor.epoch,
        anchor.anchor_hash,
        anchor.anchor_daa_score,
        Hash64::default(),
    );
    let shard_tx = dns_harness::funded_signed_shard_tx(seed, coinbase_b, value_b, daa_b, att, storage_mass_parameter);
    ctx.mine_block(new_miner_data(), vec![shard_tx]).await;
    for _ in 0..15 {
        ctx.mine_block(new_miner_data(), vec![]).await;
    }

    let honest_sink = ctx.consensus.get_sink();
    let (confirmed_anchor, honest_work) = {
        let vp = ctx.consensus.virtual_processor();
        let st = vp.dns_state_store.read().get().expect("DnsState");
        assert_eq!(st.rollout_stage, DnsRolloutStage::Active, "honest node is Active");
        assert_ne!(st.last_dns_confirmed_anchor, Hash64::default(), "honest node has a confirmed anchor");
        (st.last_dns_confirmed_anchor, vp.ghostdag_store.get_blue_work(honest_sink).unwrap())
    };

    // ---- Attacker: a SEPARATE instance (same genesis) mines a longer STAKE-LESS chain. ----
    let mut atk = TestContext::new(TestConsensus::new(&config));
    let mut attacker_blocks = Vec::new();
    for _ in 0..60 {
        attacker_blocks.push(atk.mine_block(new_miner_data(), vec![]).await);
    }
    let attacker_tip = attacker_blocks.last().unwrap().header.hash;
    let attacker_work = { atk.consensus.virtual_processor().ghostdag_store.get_blue_work(attacker_tip).unwrap() };
    assert!(
        attacker_work > honest_work,
        "the attacker is a genuine PoW majority (heavier blue_work): attacker {attacker_work} vs honest {honest_work}"
    );

    // ---- Deliver the attacker's heavier branch to the honest node. ----
    for b in &attacker_blocks {
        ctx.validate_and_insert_block(b.clone()).await;
    }

    // ---- Finality held: the honest sink STILL contains the confirmed anchor, NOT the heavier
    //      attacker tip. PoW surplus could not substitute for the attacker's zero stake. ----
    let new_sink = ctx.consensus.get_sink();
    assert_ne!(new_sink, attacker_tip, "the honest node did NOT reorg onto the heavier stake-less attacker chain");
    {
        let vp = ctx.consensus.virtual_processor();
        assert!(
            vp.reachability_service.is_chain_ancestor_of(confirmed_anchor, new_sink),
            "the DNS-confirmed anchor is still on the selected chain (the reorg gate stopped the 51% attack)"
        );
        // The confirmed anchor is unchanged — finality was not rewritten.
        let st = vp.dns_state_store.read().get().expect("DnsState");
        assert_eq!(st.last_dns_confirmed_anchor, confirmed_anchor, "the confirmed anchor was not rewritten by the attack");
    }
}

/// kaspa-pq DNS v3 — **many validators converge on ONE anchor at the epoch boundary**, the
/// core reason v3 replaces v1 current-sink signing. Under fast mining / a wide DAG, validators
/// transiently observe DIFFERENT sinks (the multi-tip frontier + propagation lag) — v1 had each
/// sign its own differing sink, splitting honest stake below φS. Here we build a wide DAG, take
/// many divergent validator VIEWS (the multiple frontier tips a fast network produces + lagging
/// ancestors at different heights), and show that although their views differ (≥2 distinct
/// blocks → ≥2 distinct v1 sink-targets), every one of them computes the SAME v3 canonical
/// lagged anchor for a buried epoch (exactly 1) — unanimous, so honest stake never splits.
#[tokio::test]
async fn dns_v3_many_validators_agree_on_anchor_under_fast_wide_dag() {
    use crate::model::stores::headers::HeaderStoreReader;
    use kaspa_consensus_core::dns_finality::ready_epoch_from_tip_blue_score;
    use std::collections::HashSet;
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 16;
            p.mergeset_size_limit = 16;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            // Moderate epoch + a generous lag so the latest ready epoch's anchor is buried well
            // below the churning multi-tip frontier (where the views diverge) into shared history.
            dns.attestation_epoch_length_blue_score = 5;
            dns.attestation_lag_blue_score = 20;
            dns.attestation_anchor_backoff_blue_score = 2;
            dns.stake_score_window_blue_score = 100_000;
            p.dns_params = Some(dns);
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Fast mining / wide DAG: wide antichains merged repeatedly, ENDING on a wide antichain so the
    // frontier is genuinely multi-tip (the different sinks a fast network's validators observe).
    for _ in 0..3 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    for _ in 0..6 {
        ctx.build_block_template_row(0..12).validate_and_insert_row().await; // wide antichain
        ctx.build_block_template_row(0..1).validate_and_insert_row().await; // merge -> blue_score jump
    }
    ctx.build_block_template_row(0..12).validate_and_insert_row().await; // leave a multi-tip frontier

    let dns = ctx.consensus.params().dns_params.clone().unwrap();
    let sink = ctx.consensus.get_sink();

    // Collect many divergent VALIDATOR VIEWS: every frontier tip (a fast network's competing
    // sinks) + several RECENT lagging ancestors at different heights (validators a little behind
    // on propagation — but still past the readiness threshold, like real honest nodes).
    let mut views: Vec<BlockHash> = ctx.consensus.get_tips().into_iter().collect();
    {
        let vp = ctx.consensus.virtual_processor();
        let sink_blue = vp.headers_store.get_blue_score(sink).unwrap();
        for anc in vp.reachability_service.default_backward_chain_iterator(sink) {
            let b = vp.headers_store.get_blue_score(anc).unwrap();
            // Only "slightly behind" validators (recent ancestors); stop once we'd reach nodes too
            // far back to have a ready epoch (a genesis-deep view is not a realistic poll state).
            if sink_blue.saturating_sub(b) > 40
                || ready_epoch_from_tip_blue_score(b, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
                    .is_none()
            {
                break;
            }
            views.push(anc);
            if views.len() >= 24 {
                break;
            }
        }
    }
    views.sort();
    views.dedup();

    let (anchors, blue_scores, buried_epoch) = {
        let vp = ctx.consensus.virtual_processor();
        // A buried epoch every view agrees is ready: the min over views of each view's latest
        // ready epoch (so canonical_anchor_by_blue_score returns Some for every view).
        let buried_epoch = views
            .iter()
            .map(|t| {
                let b = vp.headers_store.get_blue_score(*t).unwrap();
                ready_epoch_from_tip_blue_score(b, dns.attestation_epoch_length_blue_score, dns.attestation_lag_blue_score)
                    .expect("each view has at least one ready epoch")
            })
            .min()
            .unwrap();
        let anchors: HashSet<BlockHash> = views
            .iter()
            .map(|t| {
                vp.canonical_anchor_by_blue_score(buried_epoch, *t, &dns).expect("every view resolves the buried epoch").anchor_hash
            })
            .collect();
        let blue_scores: HashSet<u64> = views.iter().map(|t| vp.headers_store.get_blue_score(*t).unwrap()).collect();
        (anchors, blue_scores, buried_epoch)
    };

    // The views are genuinely divergent (a fast network: many distinct tips at several heights) —
    // under v1 these would be ≥2 different current-sink targets, splitting honest stake.
    assert!(views.len() >= 5, "many validator views ({})", views.len());
    assert!(blue_scores.len() >= 2, "the views sit at genuinely different positions (would be different v1 sinks)");
    // ...yet under v3 every view computes the SAME canonical anchor for the buried epoch.
    assert_eq!(
        anchors.len(),
        1,
        "all {} validator views must agree on ONE canonical anchor for epoch {} (got {} distinct)",
        views.len(),
        buried_epoch,
        anchors.len()
    );
}

/// kaspa-pq Layer-0 (audit M-3, updated for ADR-0007 Phase 3): a header whose
/// `pow_algo_id` is not the algo the network mandates at its DAA score is
/// rejected by header-in-isolation validation. On the BLAKE2b-SHA3-active mainnet
/// params the mandated id is `3`, so both the wrong-but-known Phase-1 id (`1` —
/// a miner trying the cheap kHeavyHash on a BLAKE2b-SHA3 network) and a garbage id
/// (`99`) must be rejected, before the PoW seed — which consumes algo_id — is
/// even derived.
#[tokio::test]
async fn header_with_unknown_pow_algo_id_is_rejected() {
    use kaspa_consensus_core::errors::block::RuleError;
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    // Establish a virtual chain with one valid (template-built ⇒ correct algo id) block.
    ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();

    // Corrupt the algo id to the wrong-but-known Phase-1 id and re-finalize.
    let mut t = ctx.build_block_template(0, ctx.simulated_time + 1_000);
    t.block.header.pow_algo_id = kaspa_consensus_core::pow_layer0::POW_ALGO_ID_KHEAVYHASH;
    t.block.header.finalize();
    let res = ctx.consensus.validate_and_insert_block(t.block.to_immutable()).block_task.await;
    assert!(matches!(res, Err(RuleError::UnknownPowAlgoId(1))), "expected UnknownPowAlgoId(1), got {res:?}");

    // A garbage id is rejected the same way.
    let mut t = ctx.build_block_template(0, ctx.simulated_time + 2_000);
    t.block.header.pow_algo_id = 99;
    t.block.header.finalize();
    let res = ctx.consensus.validate_and_insert_block(t.block.to_immutable()).block_task.await;
    assert!(matches!(res, Err(RuleError::UnknownPowAlgoId(99))), "expected UnknownPowAlgoId(99), got {res:?}");
}

// ============================================================================
// kaspa-pq ADR-0018 §G — DNS-overlay DAG integration harness (foundation).
//
// Retires the "ML-DSA-87 signing unavailable in the consensus test crate"
// blocker for the reward-bearing / reorg / slashing DAG tests (DAG-2..7): these
// helpers let a consensus test build stake-bond + attestation-shard txs and
// produce an attestation signature the §B.4 verifier
// (`kaspa_txscript::verify_mldsa87_with_context` under
// `ATTESTATION_MLDSA87_CONTEXT`) accepts. Funding a bond tx from a coinbase UTXO
// (so a full reward-bearing chain validates) is the next harness step (DAG-2).
// ============================================================================
#[cfg(test)]
mod dns_harness {
    use kaspa_consensus_core::{
        Hash64,
        dns_finality::{
            ATTESTATION_MLDSA87_CONTEXT, DNS_PAYLOAD_VERSION_V1, SlashingEvidencePayload, StakeAttestation, StakeBondPayload,
            StakeUnbondRequestPayload, UNBOND_REQUEST_CONTEXT, attestations_from_accepted_txs, p2pkh_mldsa87_spk,
            single_attestation_shard, stake_attestation_message, stake_attestation_shard_tx, unbond_request_message,
            validator_id_from_pubkey,
        },
        hashing::sighash::{Mldsa87SigHashReusedValuesUnsync, calc_mldsa87_signature_hash},
        hashing::sighash_type::SIG_HASH_ALL,
        mass::MassCalculator,
        subnets::{
            SUBNETWORK_ID_NATIVE, SUBNETWORK_ID_SLASHING_EVIDENCE, SUBNETWORK_ID_STAKE_ATTESTATION_SHARD, SUBNETWORK_ID_STAKE_BOND,
            SUBNETWORK_ID_STAKE_UNBOND,
        },
        tx::{PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
    };
    use kaspa_txscript::{MLDSA87_TX_CONTEXT, script_builder::ScriptBuilder};
    use libcrux_ml_dsa::ml_dsa_87 as mldsa;

    /// A test validator: an ML-DSA-87 key (re-derived deterministically from
    /// `seed`) plus its 2592-byte pubkey and overlay `validator_id`.
    pub(super) struct HarnessValidator {
        pub seed: [u8; 32],
        pub pubkey: Vec<u8>,
        pub validator_id: Hash64,
    }

    pub(super) fn harness_validator(seed: [u8; 32]) -> HarnessValidator {
        let kp = mldsa::generate_key_pair(seed);
        let pubkey = kp.verification_key.as_ref().to_vec();
        let validator_id = validator_id_from_pubkey(&pubkey);
        HarnessValidator { seed, pubkey, validator_id }
    }

    /// Build a stake-bond tx (subnetwork `SUBNETWORK_ID_STAKE_BOND`, payload =
    /// borsh `StakeBondPayload`). The funded variant (output-0 = `amount` locked
    /// stake spent from a coinbase UTXO) is the next step; here the tx is
    /// payload-first for shape / borsh checks.
    pub(super) fn build_stake_bond_tx(
        v: &HarnessValidator,
        amount: u64,
        activation_daa_score: u64,
        reward_payload: [u8; 64],
    ) -> Transaction {
        let payload = StakeBondPayload {
            version: DNS_PAYLOAD_VERSION_V1,
            owner_pubkey_hash: v.validator_id,
            validator_pubkey_hash: v.validator_id,
            validator_pubkey: v.pubkey.clone(),
            amount,
            activation_daa_score,
            unbonding_period_blocks: 700,
            owner_reward_spk_payload: reward_payload,
        };
        Transaction::new(
            crate::constants::TX_VERSION,
            vec![],
            vec![],
            0,
            SUBNETWORK_ID_STAKE_BOND,
            0,
            borsh::to_vec(&payload).unwrap(),
        )
    }

    /// kaspa-pq ADR-0018 §G (DAG-2): build a FUNDED, ML-DSA-87-signed stake-bond tx.
    /// Spends the matured coinbase UTXO `coinbase_outpoint` (value `coinbase_value`,
    /// paid to this validator's own P2PKH) into output-0 = `amount` locked stake
    /// (P2PKH to the same key), carrying the `StakeBondPayload`. Input-0 is signed
    /// over `calc_mldsa87_signature_hash(.., SIG_HASH_ALL)` under `MLDSA87_TX_CONTEXT`
    /// — the exact 64-byte digest `OpCheckSigMlDsa87` recomputes — so the block
    /// validates through the full script engine (construction == validation).
    /// Returns `(signed tx, validator_id, owner_reward_spk_payload)`.
    pub(super) fn funded_signed_bond_tx(
        seed: [u8; 32],
        coinbase_outpoint: TransactionOutpoint,
        coinbase_value: u64,
        coinbase_daa_score: u64,
        amount: u64,
        activation_daa_score: u64,
        storage_mass_parameter: u64,
    ) -> (Transaction, Hash64, [u8; 64]) {
        let kp = mldsa::generate_key_pair(seed);
        let pubkey = kp.verification_key.as_ref().to_vec();
        let validator_id = validator_id_from_pubkey(&pubkey);
        // Keyed BLAKE2b-512 address payload (the same digest the spk's OP_BLAKE2B_512
        // recomputes); rewards + the locked-stake output both pay this P2PKH.
        let reward_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&pubkey).as_bytes();
        let spk = p2pkh_mldsa87_spk(&reward_payload);

        let payload = StakeBondPayload {
            version: DNS_PAYLOAD_VERSION_V1,
            owner_pubkey_hash: validator_id,
            validator_pubkey_hash: validator_id,
            validator_pubkey: pubkey.clone(),
            amount,
            activation_daa_score,
            unbonding_period_blocks: 700,
            owner_reward_spk_payload: reward_payload,
        };
        // input-0 spends the coinbase; output-0 = the locked stake; fee = coinbase_value - amount.
        let mut tx = Transaction::new(
            crate::constants::TX_VERSION,
            vec![TransactionInput::new(coinbase_outpoint, vec![], 0, 1)],
            vec![TransactionOutput::new(amount, spk.clone())],
            0,
            SUBNETWORK_ID_STAKE_BOND,
            0,
            borsh::to_vec(&payload).unwrap(),
        );

        // KIP-9 storage-mass commitment: value-based, so independent of the (still
        // empty) signature_script — committing it now matches the validator's
        // `calc_contextual_masses(..).storage_mass` recheck (else WrongMass).
        let utxo = UtxoEntry::new(coinbase_value, spk, coinbase_daa_score, true);
        let storage_mass = MassCalculator::new(0, 0, 0, storage_mass_parameter)
            .calc_contextual_masses(&PopulatedTransaction::new(&tx, vec![utxo.clone()]))
            .expect("contextual mass is computable for the funded bond tx")
            .storage_mass;
        tx.set_mass(storage_mass);

        // Sign input-0 over the SIG_HASH_ALL digest of the (mass-committed) tx.
        let reused = Mldsa87SigHashReusedValuesUnsync::new();
        let sig_hash = {
            let populated = PopulatedTransaction::new(&tx, vec![utxo]);
            calc_mldsa87_signature_hash(&populated, 0, SIG_HASH_ALL, &reused)
        };
        let sig = mldsa::sign(&kp.signing_key, sig_hash.as_bytes().as_slice(), MLDSA87_TX_CONTEXT, [0x77u8; 32])
            .expect("ML-DSA-87 sign on the 64-byte sighash");
        let mut sig_item = sig.as_ref().to_vec();
        sig_item.push(SIG_HASH_ALL.to_u8());
        let sig_script = ScriptBuilder::new()
            .add_data(&sig_item)
            .expect("ML-DSA-87 signature push fits MAX_SCRIPT_ELEMENT_SIZE")
            .add_data(&pubkey)
            .expect("ML-DSA-87 public-key push fits MAX_SCRIPT_ELEMENT_SIZE")
            .drain();
        tx.inputs[0].signature_script = sig_script;
        (tx, validator_id, reward_payload)
    }

    /// kaspa-pq ADR-0018 §G (DAG-2): build a FUNDED, ML-DSA-87-signed attestation
    /// shard tx — the production shape (`build_funded_shard_tx`). A canonical 0-input
    /// shard tx is rejected by the isolation `NoTxInputs` check, so the shard must
    /// spend a (matured) coinbase like any other tx: one P2PKH change output back to
    /// the same key, with the attestation carried verbatim in the payload on
    /// `SUBNETWORK_ID_STAKE_ATTESTATION_SHARD`. Input-0 is ML-DSA-signed over the v2
    /// tx sighash; the storage mass is committed.
    pub(super) fn funded_signed_shard_tx(
        seed: [u8; 32],
        coinbase_outpoint: TransactionOutpoint,
        coinbase_value: u64,
        coinbase_daa_score: u64,
        attestation: StakeAttestation,
        storage_mass_parameter: u64,
    ) -> Transaction {
        let kp = mldsa::generate_key_pair(seed);
        let pubkey = kp.verification_key.as_ref().to_vec();
        let reward_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&pubkey).as_bytes();
        let spk = p2pkh_mldsa87_spk(&reward_payload);
        // The payload is exactly what the canonical zero-input shard builder emits.
        let payload = stake_attestation_shard_tx(&single_attestation_shard(attestation)).payload;
        let mut tx = Transaction::new(
            crate::constants::TX_VERSION,
            vec![TransactionInput::new(coinbase_outpoint, vec![], 0, 1)],
            vec![TransactionOutput::new(coinbase_value - 100_000, spk.clone())],
            0,
            SUBNETWORK_ID_STAKE_ATTESTATION_SHARD,
            0,
            payload,
        );
        let utxo = UtxoEntry::new(coinbase_value, spk, coinbase_daa_score, true);
        let storage_mass = MassCalculator::new(0, 0, 0, storage_mass_parameter)
            .calc_contextual_masses(&PopulatedTransaction::new(&tx, vec![utxo.clone()]))
            .expect("contextual mass is computable for the funded shard tx")
            .storage_mass;
        tx.set_mass(storage_mass);
        let reused = Mldsa87SigHashReusedValuesUnsync::new();
        let sig_hash = {
            let populated = PopulatedTransaction::new(&tx, vec![utxo]);
            calc_mldsa87_signature_hash(&populated, 0, SIG_HASH_ALL, &reused)
        };
        let sig = mldsa::sign(&kp.signing_key, sig_hash.as_bytes().as_slice(), MLDSA87_TX_CONTEXT, [0x88u8; 32])
            .expect("ML-DSA-87 sign on the 64-byte sighash");
        let mut sig_item = sig.as_ref().to_vec();
        sig_item.push(SIG_HASH_ALL.to_u8());
        let sig_script = ScriptBuilder::new()
            .add_data(&sig_item)
            .expect("ML-DSA-87 signature push fits MAX_SCRIPT_ELEMENT_SIZE")
            .add_data(&pubkey)
            .expect("ML-DSA-87 public-key push fits MAX_SCRIPT_ELEMENT_SIZE")
            .drain();
        tx.inputs[0].signature_script = sig_script;
        tx
    }

    /// kaspa-pq ADR-0018 §G (DAG-6): build a FUNDED, ML-DSA-87-signed slashing-evidence
    /// tx. Spends the matured coinbase `coinbase_outpoint` (paid to this key's P2PKH) with
    /// **no outputs** — the reporter reward is minted by consensus as a side-effect at
    /// `(tx, 0)` (ADR-0013 Addendum C.2), so any declared output would collide with the
    /// mint — carrying the `SlashingEvidencePayload` on `SUBNETWORK_ID_SLASHING_EVIDENCE`.
    /// Input-0 is ML-DSA-87-signed over the v2 sighash and the storage mass is committed,
    /// so the block validates through the full script engine (construction == validation).
    pub(super) fn funded_signed_slashing_evidence_tx(
        seed: [u8; 32],
        coinbase_outpoint: TransactionOutpoint,
        coinbase_value: u64,
        coinbase_daa_score: u64,
        evidence: SlashingEvidencePayload,
        storage_mass_parameter: u64,
    ) -> Transaction {
        let kp = mldsa::generate_key_pair(seed);
        let pubkey = kp.verification_key.as_ref().to_vec();
        let reward_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&pubkey).as_bytes();
        let spk = p2pkh_mldsa87_spk(&reward_payload);
        // Evidence tx: input-0 funds it (the entire value becomes fee), NO outputs.
        let mut tx = Transaction::new(
            crate::constants::TX_VERSION,
            vec![TransactionInput::new(coinbase_outpoint, vec![], 0, 1)],
            vec![],
            0,
            SUBNETWORK_ID_SLASHING_EVIDENCE,
            0,
            borsh::to_vec(&evidence).unwrap(),
        );
        let utxo = UtxoEntry::new(coinbase_value, spk, coinbase_daa_score, true);
        let storage_mass = MassCalculator::new(0, 0, 0, storage_mass_parameter)
            .calc_contextual_masses(&PopulatedTransaction::new(&tx, vec![utxo.clone()]))
            .expect("contextual mass is computable for the funded slashing-evidence tx")
            .storage_mass;
        tx.set_mass(storage_mass);
        let reused = Mldsa87SigHashReusedValuesUnsync::new();
        let sig_hash = {
            let populated = PopulatedTransaction::new(&tx, vec![utxo]);
            calc_mldsa87_signature_hash(&populated, 0, SIG_HASH_ALL, &reused)
        };
        let sig = mldsa::sign(&kp.signing_key, sig_hash.as_bytes().as_slice(), MLDSA87_TX_CONTEXT, [0x99u8; 32])
            .expect("ML-DSA-87 sign on the 64-byte sighash");
        let mut sig_item = sig.as_ref().to_vec();
        sig_item.push(SIG_HASH_ALL.to_u8());
        let sig_script = ScriptBuilder::new()
            .add_data(&sig_item)
            .expect("ML-DSA-87 signature push fits MAX_SCRIPT_ELEMENT_SIZE")
            .add_data(&pubkey)
            .expect("ML-DSA-87 public-key push fits MAX_SCRIPT_ELEMENT_SIZE")
            .drain();
        tx.inputs[0].signature_script = sig_script;
        tx
    }

    /// kaspa-pq H-06 (unbond lifecycle): build a FUNDED, ML-DSA-87-signed stake-unbond
    /// request tx — the client-side shape an operator submits to exit a bond. Spends the
    /// matured coinbase into one P2PKH change output (subnet `SUBNETWORK_ID_STAKE_UNBOND`),
    /// carrying a `StakeUnbondRequestPayload` whose `signature` is the owner's ML-DSA-87
    /// signature over `unbond_request_message(bond)` under `UNBOND_REQUEST_CONTEXT`
    /// (the digest the stateful `unbond_request_authorized` rule reconstructs). Input-0 is
    /// signed over the v2 tx sighash so the block validates through the script engine.
    pub(super) fn funded_signed_unbond_tx(
        seed: [u8; 32],
        net_id: &[u8],
        coinbase_outpoint: TransactionOutpoint,
        coinbase_value: u64,
        coinbase_daa_score: u64,
        bond_outpoint: TransactionOutpoint,
        storage_mass_parameter: u64,
    ) -> Transaction {
        let kp = mldsa::generate_key_pair(seed);
        let pubkey = kp.verification_key.as_ref().to_vec();
        let reward_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&pubkey).as_bytes();
        let spk = p2pkh_mldsa87_spk(&reward_payload);
        // Owner authorization: ML-DSA-87 signature over the network- and bond-bound unbond message (M-04).
        let auth_digest = unbond_request_message(net_id, bond_outpoint);
        let auth_sig = mldsa::sign(&kp.signing_key, &auth_digest.as_bytes()[..], UNBOND_REQUEST_CONTEXT, [0xaau8; 32])
            .expect("ML-DSA-87 unbond authorization sign");
        let payload = borsh::to_vec(&StakeUnbondRequestPayload {
            version: DNS_PAYLOAD_VERSION_V1,
            bond_outpoint,
            owner_pubkey: pubkey.clone(),
            signature: auth_sig.as_ref().to_vec(),
        })
        .unwrap();
        let mut tx = Transaction::new(
            crate::constants::TX_VERSION,
            vec![TransactionInput::new(coinbase_outpoint, vec![], 0, 1)],
            vec![TransactionOutput::new(coinbase_value - 100_000, spk.clone())],
            0,
            SUBNETWORK_ID_STAKE_UNBOND,
            0,
            payload,
        );
        let utxo = UtxoEntry::new(coinbase_value, spk, coinbase_daa_score, true);
        let storage_mass = MassCalculator::new(0, 0, 0, storage_mass_parameter)
            .calc_contextual_masses(&PopulatedTransaction::new(&tx, vec![utxo.clone()]))
            .expect("contextual mass is computable for the funded unbond tx")
            .storage_mass;
        tx.set_mass(storage_mass);
        let reused = Mldsa87SigHashReusedValuesUnsync::new();
        let sig_hash = {
            let populated = PopulatedTransaction::new(&tx, vec![utxo]);
            calc_mldsa87_signature_hash(&populated, 0, SIG_HASH_ALL, &reused)
        };
        let sig = mldsa::sign(&kp.signing_key, sig_hash.as_bytes().as_slice(), MLDSA87_TX_CONTEXT, [0xabu8; 32])
            .expect("ML-DSA-87 sign on the 64-byte sighash");
        let mut sig_item = sig.as_ref().to_vec();
        sig_item.push(SIG_HASH_ALL.to_u8());
        let sig_script = ScriptBuilder::new()
            .add_data(&sig_item)
            .expect("ML-DSA-87 signature push fits MAX_SCRIPT_ELEMENT_SIZE")
            .add_data(&pubkey)
            .expect("ML-DSA-87 public-key push fits MAX_SCRIPT_ELEMENT_SIZE")
            .drain();
        tx.inputs[0].signature_script = sig_script;
        tx
    }

    /// Build a FUNDED, ML-DSA-87-signed NATIVE spend of a P2PKH UTXO (e.g. a bond's locked
    /// output-0) back to the same key. Exercises the ADR-0016 §D.2 bond-UTXO spend-gate: consensus
    /// must reject a block that spends a still-locked (non-releasable) bond output. The spent output
    /// is a regular (non-coinbase) tx output; the sighash commits its value + spk (both supplied),
    /// so the signature verifies through the full script engine.
    pub(super) fn funded_signed_p2pkh_spend(
        seed: [u8; 32],
        outpoint: TransactionOutpoint,
        value: u64,
        daa_score: u64,
        storage_mass_parameter: u64,
    ) -> Transaction {
        let kp = mldsa::generate_key_pair(seed);
        let pubkey = kp.verification_key.as_ref().to_vec();
        let reward_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&pubkey).as_bytes();
        let spk = p2pkh_mldsa87_spk(&reward_payload);
        let mut tx = Transaction::new(
            crate::constants::TX_VERSION,
            vec![TransactionInput::new(outpoint, vec![], 0, 1)],
            vec![TransactionOutput::new(value - 100_000, spk.clone())],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );
        let utxo = UtxoEntry::new(value, spk, daa_score, false);
        let storage_mass = MassCalculator::new(0, 0, 0, storage_mass_parameter)
            .calc_contextual_masses(&PopulatedTransaction::new(&tx, vec![utxo.clone()]))
            .expect("contextual mass is computable for the bond-output spend")
            .storage_mass;
        tx.set_mass(storage_mass);
        let reused = Mldsa87SigHashReusedValuesUnsync::new();
        let sig_hash = {
            let populated = PopulatedTransaction::new(&tx, vec![utxo]);
            calc_mldsa87_signature_hash(&populated, 0, SIG_HASH_ALL, &reused)
        };
        let sig = mldsa::sign(&kp.signing_key, sig_hash.as_bytes().as_slice(), MLDSA87_TX_CONTEXT, [0xacu8; 32])
            .expect("ML-DSA-87 sign on the 64-byte sighash");
        let mut sig_item = sig.as_ref().to_vec();
        sig_item.push(SIG_HASH_ALL.to_u8());
        let sig_script = ScriptBuilder::new()
            .add_data(&sig_item)
            .expect("ML-DSA-87 signature push fits MAX_SCRIPT_ELEMENT_SIZE")
            .add_data(&pubkey)
            .expect("ML-DSA-87 public-key push fits MAX_SCRIPT_ELEMENT_SIZE")
            .drain();
        tx.inputs[0].signature_script = sig_script;
        tx
    }

    /// ADR-0018 §F bridge wiring: a fully ML-DSA-87-signed BRIDGE tx — spends `seed`'s
    /// P2PKH `outpoint` into a single `EVM_DEPOSIT_LOCK` output (`value − 100_000`; fee
    /// 100_000), whose refund path is the same key's P2PKH. Mirrors
    /// [`funded_signed_p2pkh_spend`]; the lock output makes the tx **finality-class**
    /// past `finality_fee_activation_daa_score`.
    pub(super) fn funded_signed_deposit_lock_tx(
        seed: [u8; 32],
        outpoint: TransactionOutpoint,
        value: u64,
        daa_score: u64,
        storage_mass_parameter: u64,
    ) -> Transaction {
        use kaspa_txscript::script_class::evm_deposit_lock_script;
        let kp = mldsa::generate_key_pair(seed);
        let pubkey = kp.verification_key.as_ref().to_vec();
        let reward_payload: [u8; 64] = kaspa_hashes::blake2b_512_address_payload(&pubkey).as_bytes();
        let spk = p2pkh_mldsa87_spk(&reward_payload);
        // The deposit lock: 20-byte EVM address, far-future timeout (refund path never taken
        // here), small claim tip; refund = the spender's own ML-DSA P2PKH.
        let lock_spk = evm_deposit_lock_script([0xABu8; 20], 100_000_000, 7, spk.script());
        let mut tx = Transaction::new(
            crate::constants::TX_VERSION,
            vec![TransactionInput::new(outpoint, vec![], 0, 1)],
            vec![TransactionOutput::new(value - 100_000, lock_spk)],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );
        let utxo = UtxoEntry::new(value, spk, daa_score, false);
        let storage_mass = MassCalculator::new(0, 0, 0, storage_mass_parameter)
            .calc_contextual_masses(&PopulatedTransaction::new(&tx, vec![utxo.clone()]))
            .expect("contextual mass is computable for the deposit-lock spend")
            .storage_mass;
        tx.set_mass(storage_mass);
        let reused = Mldsa87SigHashReusedValuesUnsync::new();
        let sig_hash = {
            let populated = PopulatedTransaction::new(&tx, vec![utxo]);
            calc_mldsa87_signature_hash(&populated, 0, SIG_HASH_ALL, &reused)
        };
        let sig = mldsa::sign(&kp.signing_key, sig_hash.as_bytes().as_slice(), MLDSA87_TX_CONTEXT, [0xadu8; 32])
            .expect("ML-DSA-87 sign on the 64-byte sighash");
        let mut sig_item = sig.as_ref().to_vec();
        sig_item.push(SIG_HASH_ALL.to_u8());
        let sig_script = ScriptBuilder::new()
            .add_data(&sig_item)
            .expect("ML-DSA-87 signature push fits MAX_SCRIPT_ELEMENT_SIZE")
            .add_data(&pubkey)
            .expect("ML-DSA-87 public-key push fits MAX_SCRIPT_ELEMENT_SIZE")
            .drain();
        tx.inputs[0].signature_script = sig_script;
        tx
    }

    /// Build a fully ML-DSA-87-signed attestation for `bond_outpoint`, signing
    /// exactly the digest the §B.4 verifier reconstructs.
    pub(super) fn build_signed_attestation(
        v: &HarnessValidator,
        network_id: &[u8],
        bond_outpoint: TransactionOutpoint,
        epoch: u64,
        target_hash: Hash64,
        target_daa_score: u64,
        validator_set_commitment: Hash64,
    ) -> StakeAttestation {
        let msg = stake_attestation_message(network_id, epoch, target_hash, target_daa_score, validator_set_commitment, bond_outpoint);
        let mb = msg.as_bytes();
        let kp = mldsa::generate_key_pair(v.seed);
        let sig = mldsa::sign(&kp.signing_key, &mb[..], ATTESTATION_MLDSA87_CONTEXT, [0x55u8; 32]).expect("ml-dsa-87 sign");
        StakeAttestation {
            version: DNS_PAYLOAD_VERSION_V1,
            validator_id: v.validator_id,
            bond_outpoint,
            epoch,
            target_hash,
            target_daa_score,
            validator_set_commitment,
            signature: sig.as_ref().to_vec(),
        }
    }

    /// DAG-harness foundation (ADR-0018 §G): a consensus test can build overlay
    /// txs and produce an attestation signature the §B.4 verifier accepts.
    #[test]
    fn dns_harness_signs_attestations_the_verifier_accepts() {
        let v = harness_validator([0x11u8; 32]);
        assert_eq!(v.pubkey.len(), 2592);
        assert_eq!(v.validator_id, validator_id_from_pubkey(&v.pubkey));

        // Stake-bond tx shape + payload round-trip; validator_pubkey_hash binds the pubkey.
        let bond_tx = build_stake_bond_tx(&v, 10_000_000_000, 0, [0x33u8; 64]);
        assert_eq!(bond_tx.subnetwork_id, SUBNETWORK_ID_STAKE_BOND);
        let bond_outpoint = TransactionOutpoint::new(bond_tx.id(), 0);
        let decoded: StakeBondPayload = borsh::from_slice(&bond_tx.payload).unwrap();
        assert_eq!(decoded.amount, 10_000_000_000);
        assert_eq!(decoded.validator_pubkey_hash, validator_id_from_pubkey(&decoded.validator_pubkey));

        // Signed attestation: the §B.4 verifier (txscript) must accept it.
        let net_id = [0xabu8; 32];
        let target_hash = Hash64::from_bytes([0x44u8; 64]);
        let vsc = Hash64::from_bytes([0x22u8; 64]);
        let att = build_signed_attestation(&v, &net_id, bond_outpoint, 7, target_hash, 700, vsc);
        let msg = stake_attestation_message(
            &net_id,
            att.epoch,
            att.target_hash,
            att.target_daa_score,
            att.validator_set_commitment,
            att.bond_outpoint,
        );
        let mb = msg.as_bytes();
        assert!(
            kaspa_txscript::verify_mldsa87_with_context(&v.pubkey, &mb[..], &att.signature, ATTESTATION_MLDSA87_CONTEXT).unwrap(),
            "the §B.4 verifier must accept the harness-signed attestation"
        );
        // A different key must NOT verify (sanity).
        let v2 = harness_validator([0x99u8; 32]);
        assert!(
            !kaspa_txscript::verify_mldsa87_with_context(&v2.pubkey, &mb[..], &att.signature, ATTESTATION_MLDSA87_CONTEXT).unwrap()
        );

        // Shard tx wraps exactly one extractable attestation.
        let shard_tx = stake_attestation_shard_tx(&single_attestation_shard(att));
        assert_eq!(shard_tx.subnetwork_id, SUBNETWORK_ID_STAKE_ATTESTATION_SHARD);
        assert_eq!(attestations_from_accepted_txs(std::slice::from_ref(&shard_tx)).len(), 1);
    }
}

#[tokio::test]
async fn basic_utxo_disqualified_test() {
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    // Mine a longer disqualified chain
    let disqualified_tip = ctx.build_and_insert_disqualified_chain(vec![config.genesis.hash], 20).await;

    assert_ne!(sink, disqualified_tip);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(BlockHashSet::from_iter([sink, disqualified_tip]), BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter()));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip));
}

#[tokio::test]
async fn double_search_disqualified_test() {
    // TODO: add non-coinbase transactions and concurrency in order to complicate the test

    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.min_difficulty_window_size = p.difficulty_window_size;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine 3 valid blocks over genesis
    ctx.build_block_template_row(0..3)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mark the one expected to remain on virtual chain
    let original_sink = ctx.consensus.get_sink();

    // Find the roots to be used for the disqualified chains
    let mut virtual_parents = ctx.consensus.get_virtual_parents();
    assert!(virtual_parents.remove(&original_sink));
    let mut iter = virtual_parents.into_iter();
    let root_1 = iter.next().unwrap();
    let root_2 = iter.next().unwrap();
    assert_eq!(iter.next(), None);

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    assert!(ctx.consensus.reachability_service().is_chain_ancestor_of(original_sink, sink));

    // Mine a long disqualified chain
    let disqualified_tip_1 = ctx.build_and_insert_disqualified_chain(vec![root_1], 30).await;

    // And another shorter disqualified chain
    let disqualified_tip_2 = ctx.build_and_insert_disqualified_chain(vec![root_2], 20).await;

    assert_eq!(ctx.consensus.get_block_status(root_1), Some(BlockStatus::StatusUTXOValid));
    assert_eq!(ctx.consensus.get_block_status(root_2), Some(BlockStatus::StatusUTXOValid));

    assert_ne!(sink, disqualified_tip_1);
    assert_ne!(sink, disqualified_tip_2);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(
        BlockHashSet::from_iter([sink, disqualified_tip_1, disqualified_tip_2]),
        BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter())
    );
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_1));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_2));

    // Mine a long enough valid chain s.t. both disqualified chains are fully merged
    for _ in 0..30 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

fn new_miner_data() -> MinerData {
    // kaspa-pq PQ-only: coinbase outputs must be the standard ML-DSA-87 P2PKH class
    // (enforced with no exemption — see `check_transaction_pq_output_classes`). Use a
    // random 64-byte hash payload: the script is class-valid but unspendable (no
    // preimage), which is all this helper needs, and stays distinct per call.
    let mut payload = [0u8; 64];
    for b in payload.iter_mut() {
        *b = rand::random();
    }
    MinerData::new(p2pkh_mldsa87_spk(&payload), vec![])
}

#[cfg(feature = "evm")]
fn set_fresh_dns_finality(consensus: &TestConsensus) {
    use crate::model::stores::dns_state::DnsStateStore;
    use kaspa_consensus_core::BlueWorkType;
    use kaspa_consensus_core::dns_finality::{DnsHealth, DnsRolloutStage, DnsState, STAKE_SCORE_SCALE, StakeScore};

    consensus
        .virtual_processor()
        .dns_state_store
        .write()
        .set(DnsState {
            selected_chain_anchor: BlockHash::from(77u64),
            anchor_daa_score: 0,
            work_depth: BlueWorkType::from_u64(2_000_000),
            stake_depth: StakeScore(20 * STAKE_SCORE_SCALE),
            last_dns_confirmed_anchor: BlockHash::from(77u64),
            last_dns_confirmed_anchor_daa_score: 0,
            rollout_stage: DnsRolloutStage::Active,
            validator_set_commitment: BlockHash::from(88u64),
            health: DnsHealth::Active,
        })
        .unwrap();
}

/// kaspa-pq EVM Lane v0.4 (ADR-0020) — first EVM-ACTIVE pipeline integration
/// test: with `evm_activation_daa_score = 0`, real blocks inserted through the
/// full pipeline (header → body → virtual) drive the lazy chain-context step:
/// each chain block's mergeset acceptance executes ONCE, its result + state
/// snapshot persist atomically with its UTXO diff, the canonical EVM heads
/// move with the sink, a commitment fault disqualifies the block from the
/// chain (the block stays in the DAG — no poison), and the chain recovers
/// past the disqualified block without re-executing prior EVM results.
#[tokio::test]
#[cfg(feature = "evm")]
async fn evm_active_chain_executes_persists_and_moves_heads() {
    use crate::model::stores::evm::{EvmCanonicalHeadsStoreReader, EvmHeaderStoreReader, EvmPayloadStoreReader, EvmRawTxStoreReader};
    use kaspa_consensus_core::constants::EVM_HEADER_VERSION;
    use kaspa_consensus_core::evm::{EvmAddress, EvmExecutionPayload, EvmStateSnapshot};
    use kaspa_evm::EvmBlockInput;
    use kaspa_hashes::Hash64;

    kaspa_core::log::try_init_logger("info");
    let config =
        ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().edit_consensus_params(|p| p.evm_activation_daa_score = 0).build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let storage = consensus.consensus_clone().storage.clone();
    set_fresh_dns_finality(&consensus);

    let genesis = consensus.params().genesis.hash;
    let miner_data = MinerData::new(p2pkh_mldsa87_spk(&[0u8; 64]), vec![]);

    // ---- b1: empty payload. The §4.3 version rule demands v2 post-activation;
    // the producer (this test) computes the mergeset-acceptance commitment the
    // same way the verifier will (mergeset = [genesis], no payloads ⇒ no
    // accepted txs; EVM parent = none ⇒ genesis state).
    let payload1 = EvmExecutionPayload::default();
    let mut b1 = consensus.build_utxo_valid_block_with_parents(1.into(), vec![genesis], miner_data.clone(), vec![]);
    b1.header.version = EVM_HEADER_VERSION;
    b1.header.evm_payload_hash = payload1.payload_hash();
    let input1 = EvmBlockInput {
        parent: None,
        header_timestamp_ms: b1.header.timestamp,
        selected_parent_hash: genesis.as_bytes(),
        blue_work_be: b1.header.blue_work.to_be_bytes().to_vec(),
        daa_score: b1.header.daa_score,
        payload: &payload1,
        accepted_txs: &[],
        gas_pool_v2_activation_daa_score: u64::MAX,
        f002_withdraw_cap_activation_daa_score: u64::MAX,
        f003_mldsa_verify_activation_daa_score: u64::MAX,
        f006_shielded_verify_activation_daa_score: u64::MAX,
        typed_receipt_root_activation_daa_score: u64::MAX,
    };
    let (exp1, snap1) = kaspa_evm::snapshot::execute_block_from_snapshot(&EvmStateSnapshot::default(), &input1).unwrap();
    b1.header.evm_commitment_root = exp1.header.commitment_root();
    b1.evm_payload = payload1;
    consensus.validate_and_insert_block(b1.to_immutable()).virtual_state_task.await.unwrap();

    assert_eq!(storage.evm_header_store.get(1.into()).unwrap(), exp1.header, "b1's EVM result persisted by the pipeline");
    assert_eq!(exp1.header.evm_number, 1);
    assert_eq!(storage.evm_heads_store.read().get().unwrap().latest, BlockHash::from(1u64), "heads moved to the sink");

    // ---- b2: carries its OWN non-empty payload (a declared coinbase + extra
    // data) — proving payload persistence at body commit and EVM state chaining
    // b1 → b2 through the real pipeline. (A real DepositClaim needs a funded
    // EVM_DEPOSIT_LOCK UTXO — P4 claim validation rejects a dangling one; the
    // claim/bridge paths are unit-tested in processes::evm.)
    let payload2 = EvmExecutionPayload {
        evm_coinbase: EvmAddress::from_bytes([0xFE; 20]),
        extra_data: vec![0x4D, 0x53, 0x4B],
        ..Default::default()
    };
    let mut b2 = consensus.build_utxo_valid_block_with_parents(2.into(), vec![1.into()], miner_data.clone(), vec![]);
    b2.header.version = EVM_HEADER_VERSION;
    b2.header.evm_payload_hash = payload2.payload_hash();
    let input2 = EvmBlockInput {
        parent: Some(&exp1.header),
        header_timestamp_ms: b2.header.timestamp,
        selected_parent_hash: BlockHash::from(1u64).as_bytes(),
        blue_work_be: b2.header.blue_work.to_be_bytes().to_vec(),
        daa_score: b2.header.daa_score,
        payload: &payload2,
        accepted_txs: &[], // b1's payload was empty ⇒ nothing to accept
        gas_pool_v2_activation_daa_score: u64::MAX,
        f002_withdraw_cap_activation_daa_score: u64::MAX,
        f003_mldsa_verify_activation_daa_score: u64::MAX,
        f006_shielded_verify_activation_daa_score: u64::MAX,
        typed_receipt_root_activation_daa_score: u64::MAX,
    };
    let (exp2, _snap2) = kaspa_evm::snapshot::execute_block_from_snapshot(&snap1, &input2).unwrap();
    b2.header.evm_commitment_root = exp2.header.commitment_root();
    b2.evm_payload = payload2.clone();
    consensus.validate_and_insert_block(b2.to_immutable()).virtual_state_task.await.unwrap();

    let stored2 = storage.evm_header_store.get(2.into()).unwrap();
    assert_eq!(stored2, exp2.header);
    assert_eq!(stored2.evm_number, 2);
    assert_eq!(stored2.parent_state_root, exp1.header.state_root, "EVM state chains selected-parent-wise");
    assert_eq!(storage.evm_payload_store.get(2.into()).unwrap(), payload2, "own payload persisted at body commit");
    assert_eq!(storage.evm_heads_store.read().get().unwrap().latest, BlockHash::from(2u64));

    // ---- b3: a commitment FAULT (producer lied about the acceptance result).
    // The block enters the DAG but is disqualified from the chain — exactly the
    // UTXO-fault shape — and no EVM rows are written for it.
    let payload3 = EvmExecutionPayload::default();
    let mut b3 = consensus.build_utxo_valid_block_with_parents(3.into(), vec![2.into()], miner_data.clone(), vec![]);
    b3.header.version = EVM_HEADER_VERSION;
    b3.header.evm_payload_hash = payload3.payload_hash();
    b3.header.evm_commitment_root = Hash64::from_bytes([0xEE; 64]);
    b3.evm_payload = payload3.clone();
    let _ = consensus.validate_and_insert_block(b3.to_immutable()).virtual_state_task.await;
    assert_eq!(consensus.block_status(3.into()), BlockStatus::StatusDisqualifiedFromChain, "commitment mismatch ⇒ chain-disqualified");
    assert!(!storage.evm_header_store.has(3.into()).unwrap(), "no EVM rows for a disqualified block");
    assert_eq!(storage.evm_heads_store.read().get().unwrap().latest, BlockHash::from(2u64), "heads did NOT follow the faulty block");

    // ---- b4: a valid sibling continuation on b2 — the chain recovers past the
    // disqualified b3 (b3 ∉ past(b4), so b3's payload is NOT accepted by b4)
    // and the heads advance. b1/b2 results are reused (their diffs exist ⇒ the
    // KeyNotFound execution arm is never re-entered: no re-execution on reorg).
    let payload4 = EvmExecutionPayload::default();
    let mut b4 = consensus.build_utxo_valid_block_with_parents(4.into(), vec![2.into()], miner_data, vec![]);
    b4.header.version = EVM_HEADER_VERSION;
    b4.header.evm_payload_hash = payload4.payload_hash();
    let input4 = EvmBlockInput {
        parent: Some(&exp2.header),
        header_timestamp_ms: b4.header.timestamp,
        selected_parent_hash: BlockHash::from(2u64).as_bytes(),
        blue_work_be: b4.header.blue_work.to_be_bytes().to_vec(),
        daa_score: b4.header.daa_score,
        payload: &payload4,
        accepted_txs: &[], // b2's payload txs are empty (system ops are not delayed-accepted)
        gas_pool_v2_activation_daa_score: u64::MAX,
        f002_withdraw_cap_activation_daa_score: u64::MAX,
        f003_mldsa_verify_activation_daa_score: u64::MAX,
        f006_shielded_verify_activation_daa_score: u64::MAX,
        typed_receipt_root_activation_daa_score: u64::MAX,
    };
    let snap2 = {
        // Recompute b2's child snapshot the same way the node stored it.
        let (_, s) = kaspa_evm::snapshot::execute_block_from_snapshot(&snap1, &input2).unwrap();
        s
    };
    let (exp4, _) = kaspa_evm::snapshot::execute_block_from_snapshot(&snap2, &input4).unwrap();
    b4.header.evm_commitment_root = exp4.header.commitment_root();
    b4.evm_payload = payload4;
    consensus.validate_and_insert_block(b4.to_immutable()).virtual_state_task.await.unwrap();

    assert_eq!(storage.evm_header_store.get(4.into()).unwrap().evm_number, 3, "b4 is EVM block 3 on the selected chain");
    assert_eq!(
        storage.evm_heads_store.read().get().unwrap().latest,
        BlockHash::from(4u64),
        "heads recovered past the disqualified block"
    );

    // ---- b5: the node's OWN template (§15 producer path) — the builder must
    // declare v2, commit the (empty) payload hash and the REAL acceptance
    // commitment, and the resulting block must validate through the full
    // pipeline. (Template used as-is: on an evm-active net a miner must not
    // mutate the template timestamp — the commitment derives from it.)
    let template = consensus
        .build_block_template(
            MinerData::new(p2pkh_mldsa87_spk(&[0u8; 64]), vec![]),
            Box::new(OnetimeTxSelector::new(Default::default())),
            TemplateBuildMode::Standard,
        )
        .unwrap();
    assert_eq!(template.block.header.version, EVM_HEADER_VERSION, "evm-active template declares v2");
    assert_eq!(template.block.header.evm_payload_hash, EvmExecutionPayload::default().payload_hash());
    assert_ne!(template.block.header.evm_commitment_root, Hash64::default(), "the template committed a real acceptance result");
    let mut b5 = template.block;
    b5.header.hash = 5u64.into(); // test identity (PoW skipped)
    consensus.validate_and_insert_block(b5.to_immutable()).virtual_state_task.await.unwrap();
    assert!(storage.evm_header_store.has(5.into()).unwrap(), "the self-mined block executed + persisted");
    assert_eq!(storage.evm_heads_store.read().get().unwrap().latest, BlockHash::from(5u64));

    // ---- b6 (§16-1): a template with an EVM-mempool candidate — the §15
    // step-6 own-payload path. The fixture is a signed EIP-1559 transfer on
    // EVM_CHAIN_ID (regenerate: `cargo test -p kaspa-evm fixture_generator --
    // --ignored --nocapture`); its sender is UNFUNDED, which is irrelevant for
    // inclusion (data-only) and makes acceptance a deterministic class-2 skip.
    const FIXTURE_TX_NONCE0: &str = "02f86b834d534b8080843b9aca008252089400000000000000000000000000000000000000228201f480c001a03244f5d74a96a52bd1c42fa1b9c336f4d3ae5509190ed9a526f17971c7fd743ca07f58e09399b50636b84f0ae4a7634c60a11c6f32427b613ebf6f4a638d6c68c1";
    let mut raw_n0 = vec![0u8; FIXTURE_TX_NONCE0.len() / 2];
    faster_hex::hex_decode(FIXTURE_TX_NONCE0.as_bytes(), &mut raw_n0).unwrap();

    let template = consensus
        .build_block_template_with_evm(
            MinerData::new(p2pkh_mldsa87_spk(&[0u8; 64]), vec![]),
            Box::new(OnetimeTxSelector::new(Default::default())),
            TemplateBuildMode::Standard,
            kaspa_consensus_core::evm::EvmTemplateData {
                evm_coinbase: kaspa_consensus_core::evm::EvmAddress::from_bytes([0xCB; 20]),
                transactions: vec![raw_n0.clone()],
                system_ops: vec![],
            },
        )
        .unwrap();
    assert_eq!(template.block.evm_payload.transactions, vec![raw_n0.clone()], "the candidate landed in the own payload");
    assert_eq!(
        template.block.evm_payload.evm_coinbase,
        kaspa_consensus_core::evm::EvmAddress::from_bytes([0xCB; 20]),
        "the declared fee recipient landed as the payload coinbase (§8.2)"
    );
    assert_eq!(
        template.block.header.evm_payload_hash,
        template.block.evm_payload.payload_hash(),
        "the header commits the NON-empty payload"
    );
    let mut b6 = template.block;
    b6.header.hash = 6u64.into();
    consensus.validate_and_insert_block(b6.to_immutable()).virtual_state_task.await.unwrap();
    assert!(storage.evm_payload_store.has(6.into()).unwrap(), "the non-empty own payload persisted at commit_body");

    // ---- b7: the NEXT template accepts b6's payload (mergeset delayed
    // acceptance): the unfunded sender makes the tx a deterministic class-2
    // skip — counted, no receipt, block valid. This closes the full §16-1
    // loop: pool candidate → template inclusion → wire/body validation →
    // acceptance processing by the selected child.
    let template = consensus
        .build_block_template(
            MinerData::new(p2pkh_mldsa87_spk(&[0u8; 64]), vec![]),
            Box::new(OnetimeTxSelector::new(Default::default())),
            TemplateBuildMode::Standard,
        )
        .unwrap();
    let mut b7 = template.block;
    b7.header.hash = 7u64.into();
    consensus.validate_and_insert_block(b7.to_immutable()).virtual_state_task.await.unwrap();
    let h7 = storage.evm_header_store.get(7.into()).unwrap();
    assert_eq!(h7.skipped_tx_count, 1, "b6's unfunded payload tx was class-2 skipped at acceptance");
    assert_eq!(h7.accepted_tx_count, 0);
    assert_eq!(storage.evm_heads_store.read().get().unwrap().latest, BlockHash::from(7u64));

    // §16-3: the tx-lookup index recorded the journey — included in b6 (DA
    // visibility), never accepted, last skip = class 2 (unfunded sender). The
    // exact data misaka_getTxInclusionStatus serves.
    let fixture_hash = kaspa_evm::tx::tx_hash(&{
        let mut raw = vec![0u8; FIXTURE_TX_NONCE0.len() / 2];
        faster_hex::hex_decode(FIXTURE_TX_NONCE0.as_bytes(), &mut raw).unwrap();
        raw
    });
    let row = storage.evm_tx_index_store.get_or_default(fixture_hash).unwrap();
    assert_eq!(row.included_in, vec![BlockHash::from(6u64)], "DA visibility: the payload block carrying the tx");
    assert!(row.accepted_in.is_empty(), "never executed (unfunded)");
    assert_eq!(row.last_skip_class, Some(2));

    // audit R-2: the raw tx is resolvable DIRECTLY by hash (no included_in scan),
    // recorded at body commit of its carrying payload block (b6) — the path the
    // eth_getTransactionByHash/receipt adapter now uses.
    let stored = storage.evm_raw_tx_store.get(fixture_hash).unwrap().expect("raw tx indexed by hash");
    assert_eq!(stored.raw, raw_n0, "raw EIP-2718 bytes round-trip by hash");
    assert_eq!(stored.payload_block, BlockHash::from(6u64), "carrying payload block recorded");
    assert_eq!(
        consensus.consensus_clone().get_evm_raw_tx(fixture_hash).unwrap(),
        Some(raw_n0.clone()),
        "get_evm_raw_tx resolves the tx without the bounded included_in scan"
    );

    consensus.shutdown(wait_handles);
}

/// kaspa-pq EVM Lane v0.4 (§16 RPC / canonical-index fix, R-1): the
/// `evm_number → L1 hash` map is driven by the SELECTED chain at virtual commit,
/// NOT per-block result-commit. A reorg must detach the old canonical block's
/// number and attach the new chain's block at that number; the detached block
/// stays queryable by L1 hash (immutable rows are kept). This exercises
/// `update_evm_canonical_number_map` end-to-end. The conditional-release branch
/// is unit-tested in `model::stores::evm` (`evm_number_store_canonical_*`). The
/// precise sink-search-loser shadow that motivated the fix needs the DNS
/// reorg-gate (overlay-Active); the structural fix prevents it by construction —
/// a non-selected block never writes the map.
#[tokio::test]
#[cfg(feature = "evm")]
async fn evm_active_canonical_number_map_follows_reorg() {
    use crate::model::stores::evm::{EvmCanonicalHeadsStoreReader, EvmHeaderStoreReader, EvmNumberStoreReader};
    use kaspa_consensus_core::constants::EVM_HEADER_VERSION;
    use kaspa_consensus_core::evm::{EvmExecutionPayload, EvmStateSnapshot};
    use kaspa_evm::EvmBlockInput;

    kaspa_core::log::try_init_logger("info");
    let config =
        ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().edit_consensus_params(|p| p.evm_activation_daa_score = 0).build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let storage = consensus.consensus_clone().storage.clone();

    let genesis = consensus.params().genesis.hash;
    let miner_data = MinerData::new(p2pkh_mldsa87_spk(&[0u8; 64]), vec![]);
    let inert = u64::MAX;

    // ---- b1 (#1): empty payload on genesis (mirrors the EVM-active test).
    let payload1 = EvmExecutionPayload::default();
    let mut b1 = consensus.build_utxo_valid_block_with_parents(1.into(), vec![genesis], miner_data.clone(), vec![]);
    b1.header.version = EVM_HEADER_VERSION;
    b1.header.evm_payload_hash = payload1.payload_hash();
    let input1 = EvmBlockInput {
        parent: None,
        header_timestamp_ms: b1.header.timestamp,
        selected_parent_hash: genesis.as_bytes(),
        blue_work_be: b1.header.blue_work.to_be_bytes().to_vec(),
        daa_score: b1.header.daa_score,
        payload: &payload1,
        accepted_txs: &[],
        gas_pool_v2_activation_daa_score: inert,
        f002_withdraw_cap_activation_daa_score: inert,
        f003_mldsa_verify_activation_daa_score: inert,
        typed_receipt_root_activation_daa_score: inert,
    };
    let (exp1, snap1) = kaspa_evm::snapshot::execute_block_from_snapshot(&EvmStateSnapshot::default(), &input1).unwrap();
    b1.header.evm_commitment_root = exp1.header.commitment_root();
    b1.evm_payload = payload1;
    consensus.validate_and_insert_block(b1.to_immutable()).virtual_state_task.await.unwrap();

    // ---- b2 (#2): on b1.
    let payload2 = EvmExecutionPayload::default();
    let mut b2 = consensus.build_utxo_valid_block_with_parents(2.into(), vec![1.into()], miner_data.clone(), vec![]);
    b2.header.version = EVM_HEADER_VERSION;
    b2.header.evm_payload_hash = payload2.payload_hash();
    let input2 = EvmBlockInput {
        parent: Some(&exp1.header),
        header_timestamp_ms: b2.header.timestamp,
        selected_parent_hash: BlockHash::from(1u64).as_bytes(),
        blue_work_be: b2.header.blue_work.to_be_bytes().to_vec(),
        daa_score: b2.header.daa_score,
        payload: &payload2,
        accepted_txs: &[],
        gas_pool_v2_activation_daa_score: inert,
        f002_withdraw_cap_activation_daa_score: inert,
        f003_mldsa_verify_activation_daa_score: inert,
        typed_receipt_root_activation_daa_score: inert,
    };
    let (exp2, snap2) = kaspa_evm::snapshot::execute_block_from_snapshot(&snap1, &input2).unwrap();
    b2.header.evm_commitment_root = exp2.header.commitment_root();
    b2.evm_payload = payload2;
    consensus.validate_and_insert_block(b2.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(storage.evm_number_store.get(2).unwrap(), Some(BlockHash::from(2u64)), "b2 claims #2");

    // ---- x3 (#3) on b2 — the initial sink. Hash 9 wins the equal-blue-work
    // tiebreak vs y3 (hash 5), so x3 stays canonical at #3 until y4 reorgs.
    let payloadx = EvmExecutionPayload::default();
    let mut x3 = consensus.build_utxo_valid_block_with_parents(9.into(), vec![2.into()], miner_data.clone(), vec![]);
    x3.header.version = EVM_HEADER_VERSION;
    x3.header.evm_payload_hash = payloadx.payload_hash();
    let inputx = EvmBlockInput {
        parent: Some(&exp2.header),
        header_timestamp_ms: x3.header.timestamp,
        selected_parent_hash: BlockHash::from(2u64).as_bytes(),
        blue_work_be: x3.header.blue_work.to_be_bytes().to_vec(),
        daa_score: x3.header.daa_score,
        payload: &payloadx,
        accepted_txs: &[],
        gas_pool_v2_activation_daa_score: inert,
        f002_withdraw_cap_activation_daa_score: inert,
        f003_mldsa_verify_activation_daa_score: inert,
        typed_receipt_root_activation_daa_score: inert,
    };
    let (expx, _snapx) = kaspa_evm::snapshot::execute_block_from_snapshot(&snap2, &inputx).unwrap();
    assert_eq!(expx.header.evm_number, 3);
    x3.header.evm_commitment_root = expx.header.commitment_root();
    x3.evm_payload = payloadx;
    consensus.validate_and_insert_block(x3.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(storage.evm_heads_store.read().get().unwrap().latest, BlockHash::from(9u64), "x3 is the sink");
    assert_eq!(storage.evm_number_store.get(3).unwrap(), Some(BlockHash::from(9u64)), "x3 canonical at #3 before the reorg");

    // ---- y3 (#3) on b2 — a sibling of x3. Equal blue work, lower hash (5 < 9)
    // ⇒ x3 keeps the sink; y3 is inserted but not yet selected/validated.
    let payloady3 = EvmExecutionPayload::default();
    let mut y3 = consensus.build_utxo_valid_block_with_parents(5.into(), vec![2.into()], miner_data.clone(), vec![]);
    y3.header.version = EVM_HEADER_VERSION;
    y3.header.evm_payload_hash = payloady3.payload_hash();
    let inputy3 = EvmBlockInput {
        parent: Some(&exp2.header),
        header_timestamp_ms: y3.header.timestamp,
        selected_parent_hash: BlockHash::from(2u64).as_bytes(),
        blue_work_be: y3.header.blue_work.to_be_bytes().to_vec(),
        daa_score: y3.header.daa_score,
        payload: &payloady3,
        accepted_txs: &[],
        gas_pool_v2_activation_daa_score: inert,
        f002_withdraw_cap_activation_daa_score: inert,
        f003_mldsa_verify_activation_daa_score: inert,
        typed_receipt_root_activation_daa_score: inert,
    };
    let (expy3, snapy3) = kaspa_evm::snapshot::execute_block_from_snapshot(&snap2, &inputy3).unwrap();
    y3.header.evm_commitment_root = expy3.header.commitment_root();
    y3.evm_payload = payloady3;
    consensus.validate_and_insert_block(y3.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(storage.evm_number_store.get(3).unwrap(), Some(BlockHash::from(9u64)), "x3 still canonical at #3 (y3 not selected)");

    // ---- y4 (#4) on y3 — the heavier branch (2 blocks past b2) reorgs the sink
    // from x3 to y4. The selected chain is now ...b2, y3(#3), y4(#4).
    let payloady4 = EvmExecutionPayload::default();
    let mut y4 = consensus.build_utxo_valid_block_with_parents(6.into(), vec![5.into()], miner_data, vec![]);
    y4.header.version = EVM_HEADER_VERSION;
    y4.header.evm_payload_hash = payloady4.payload_hash();
    let inputy4 = EvmBlockInput {
        parent: Some(&expy3.header),
        header_timestamp_ms: y4.header.timestamp,
        selected_parent_hash: BlockHash::from(5u64).as_bytes(),
        blue_work_be: y4.header.blue_work.to_be_bytes().to_vec(),
        daa_score: y4.header.daa_score,
        payload: &payloady4,
        accepted_txs: &[],
        gas_pool_v2_activation_daa_score: inert,
        f002_withdraw_cap_activation_daa_score: inert,
        f003_mldsa_verify_activation_daa_score: inert,
        typed_receipt_root_activation_daa_score: inert,
    };
    let (expy4, _snapy4) = kaspa_evm::snapshot::execute_block_from_snapshot(&snapy3, &inputy4).unwrap();
    assert_eq!(expy4.header.evm_number, 4);
    y4.header.evm_commitment_root = expy4.header.commitment_root();
    y4.evm_payload = payloady4;
    consensus.validate_and_insert_block(y4.to_immutable()).virtual_state_task.await.unwrap();

    // The reorg detached x3 and attached y3(#3) + y4(#4):
    assert_eq!(storage.evm_heads_store.read().get().unwrap().latest, BlockHash::from(6u64), "sink reorged to y4");
    assert_eq!(
        storage.evm_number_store.get(3).unwrap(),
        Some(BlockHash::from(5u64)),
        "#3 now resolves to y3 (canonical), not the detached x3"
    );
    assert_eq!(storage.evm_number_store.get(4).unwrap(), Some(BlockHash::from(6u64)), "y4 claimed #4");
    assert_eq!(storage.evm_number_store.get(2).unwrap(), Some(BlockHash::from(2u64)), "#2 (below the fork) is unchanged");
    assert_ne!(storage.evm_number_store.get(3).unwrap(), Some(BlockHash::from(9u64)), "the detached x3 no longer owns #3");
    // The detached x3 stays queryable by L1 hash (immutable rows survive).
    assert!(storage.evm_header_store.has(9.into()).unwrap(), "x3's immutable EVM rows survive the reorg (hash-queryable)");

    consensus.shutdown(wait_handles);
}

/// kaspa-pq EVM Lane v0.4 §9.2 — producer-side deposit-claim path: a queued
/// `DepositClaim` (resolved from a real EVM_DEPOSIT_LOCK UTXO, the work the
/// `submitEvmDepositClaim` RPC does) lands in the node's OWN template
/// `system_ops` after the template path re-validates it against the live claim
/// view; a claim for a non-existent/stale lock is dropped — so a queued claim
/// can never make the producer's own block invalid. This closes the production
/// half of the bridge: deposits are now both validatable (P4) AND producible.
#[tokio::test]
#[cfg(feature = "evm")]
async fn evm_producer_deposit_claim_fills_and_filters_template_system_ops() {
    use kaspa_consensus_core::evm::{DepositClaim, EvmAddress, EvmSystemOp, EvmTemplateData};
    use kaspa_consensus_core::header::Header;
    use kaspa_consensus_core::muhash::MuHashExtensions;
    use kaspa_consensus_core::tx::UtxoEntry;
    use kaspa_muhash::MuHash;
    use kaspa_txscript::script_class::evm_deposit_lock_script;

    kaspa_core::log::try_init_logger("info");

    // A real EVM_DEPOSIT_LOCK output: 1000 sompi locked to an EVM address, claim
    // tip 7, timeout far in the future; refund = a standard ML-DSA P2PKH.
    let evm_addr = [0xAB; 20];
    let refund_spk = p2pkh_mldsa87_spk(&[0x42; 64]);
    let lock_spk = evm_deposit_lock_script(evm_addr, 1_000_000, 7, refund_spk.script());
    let lock_outpoint = TransactionOutpoint::new(99u64.into(), 0);
    let initial_utxos =
        [(lock_outpoint, UtxoEntry { amount: 1000, script_public_key: lock_spk, block_daa_score: 0, is_coinbase: false })];

    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| p.evm_activation_daa_score = 0)
        .apply_args(|cfg| {
            let mut ms = MuHash::new();
            initial_utxos.iter().for_each(|(op, u)| ms.add_utxo(op, u));
            cfg.params.genesis.utxo_commitment = ms.finalize();
            let genesis_header: Header = (&cfg.params.genesis).into();
            cfg.params.genesis.hash = genesis_header.hash;
        })
        .build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let mut genesis_ms = MuHash::new();
    consensus.append_imported_pruning_point_utxos(&initial_utxos, &mut genesis_ms);
    consensus.import_pruning_point_utxo_set(config.genesis.hash, genesis_ms).unwrap();

    // (1) the valid claim for the real lock; (2) a claim for a non-existent
    // outpoint that re-validation must drop.
    let good_claim = DepositClaim {
        deposit_outpoint: lock_outpoint,
        evm_address: EvmAddress::from_bytes(evm_addr),
        amount_sompi: 1000,
        claim_tip_sompi: 7,
    };
    let bogus_claim = DepositClaim {
        deposit_outpoint: TransactionOutpoint::new(123u64.into(), 0),
        evm_address: EvmAddress::from_bytes([0xCD; 20]),
        amount_sompi: 500,
        claim_tip_sompi: 0,
    };

    let stale_template = consensus
        .build_block_template_with_evm(
            MinerData::new(p2pkh_mldsa87_spk(&[0u8; 64]), vec![]),
            Box::new(OnetimeTxSelector::new(Default::default())),
            TemplateBuildMode::Standard,
            EvmTemplateData {
                evm_coinbase: EvmAddress::from_bytes([0xCB; 20]),
                transactions: vec![],
                system_ops: vec![good_claim.clone(), bogus_claim.clone()],
            },
        )
        .unwrap();
    assert!(
        stale_template.block.evm_payload.is_empty(),
        "without a fresh DNS-confirmed anchor, bridge deposit claims stay out of the template"
    );

    set_fresh_dns_finality(&consensus);

    let template = consensus
        .build_block_template_with_evm(
            MinerData::new(p2pkh_mldsa87_spk(&[0u8; 64]), vec![]),
            Box::new(OnetimeTxSelector::new(Default::default())),
            TemplateBuildMode::Standard,
            EvmTemplateData {
                evm_coinbase: EvmAddress::from_bytes([0xCB; 20]),
                transactions: vec![],
                system_ops: vec![good_claim.clone(), bogus_claim],
            },
        )
        .unwrap();

    assert_eq!(template.block.evm_payload.system_ops.len(), 1, "only the valid claim survives template re-validation");
    assert_eq!(
        template.block.evm_payload.system_ops[0],
        EvmSystemOp::DepositClaim(good_claim),
        "the resolved lock's claim is in the own payload"
    );
    assert_eq!(
        template.block.evm_payload.evm_coinbase,
        EvmAddress::from_bytes([0xCB; 20]),
        "a claim-bearing payload declares the coinbase (the tip routes to it)"
    );
    assert_eq!(template.block.header.evm_payload_hash, template.block.evm_payload.payload_hash(), "header commits the claim payload");

    consensus.shutdown(wait_handles);
}

/// kaspa-pq EVM Lane v0.4 §14.1/§14.3 — Y9 budget independence, pipeline e2e:
/// a template assembled from an OVERSUPPLIED candidate list fills the payload
/// to the byte cap (and no further), the resulting full-cap block keeps its
/// normal UTXO content and passes the complete pipeline (mass rules included),
/// and the next chain block processes the entire payload at acceptance without
/// invalidating or stalling the UTXO lane. Complements the in-isolation mass
/// equality test (`evm_y9_payload_byte_budget_independent_of_utxo_mass_budget`);
/// the λ·D propagation re-validation with measured payload-laden D is Y10 —
/// testnet work and an activation precondition (§14.3), not a unit concern.
#[tokio::test]
#[cfg(feature = "evm")]
async fn evm_y9_full_cap_payload_block_validates_and_executes() {
    use crate::model::stores::evm::{EvmCanonicalHeadsStoreReader, EvmHeaderStoreReader, EvmPayloadStoreReader};
    use kaspa_consensus_core::evm::{EvmAddress, EvmExecutionPayload, EvmTemplateData, MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK};

    kaspa_core::log::try_init_logger("info");
    let config =
        ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().edit_consensus_params(|p| p.evm_activation_daa_score = 0).build();
    let consensus = TestConsensus::new(&config);
    let wait_handles = consensus.init();
    let storage = consensus.consensus_clone().storage.clone();
    set_fresh_dns_finality(&consensus);

    // The class-1-valid §16 fixture, oversupplied: duplication is legal at the
    // body (admission is per-tx) and a deterministic skip at acceptance.
    const FIXTURE_TX_NONCE0: &str = "02f86b834d534b8080843b9aca008252089400000000000000000000000000000000000000228201f480c001a03244f5d74a96a52bd1c42fa1b9c336f4d3ae5509190ed9a526f17971c7fd743ca07f58e09399b50636b84f0ae4a7634c60a11c6f32427b613ebf6f4a638d6c68c1";
    let mut raw = vec![0u8; FIXTURE_TX_NONCE0.len() / 2];
    faster_hex::hex_decode(FIXTURE_TX_NONCE0.as_bytes(), &mut raw).unwrap();
    let base = EvmExecutionPayload::default().payload_bytes().len();
    let per_tx = 4 + raw.len();
    let n = (MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK - base) / per_tx;

    let template = consensus
        .build_block_template_with_evm(
            MinerData::new(p2pkh_mldsa87_spk(&[0u8; 64]), vec![]),
            Box::new(OnetimeTxSelector::new(Default::default())),
            TemplateBuildMode::Standard,
            EvmTemplateData {
                evm_coinbase: EvmAddress::from_bytes([0xCB; 20]),
                transactions: vec![raw.clone(); n + 32], // 32 candidates beyond the cap
                system_ops: vec![],
            },
        )
        .unwrap();
    assert_eq!(template.block.evm_payload.transactions.len(), n, "template fills to the byte cap and not one tx further");
    let assembled = template.block.evm_payload.payload_bytes().len();
    assert!(assembled <= MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK, "assembled payload within the cap");
    assert!(assembled > MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK - per_tx, "assembled payload NEAR the cap");

    let mut b1 = template.block;
    b1.header.hash = 1u64.into();
    consensus.validate_and_insert_block(b1.to_immutable()).virtual_state_task.await.unwrap();
    assert!(storage.evm_payload_store.has(1.into()).unwrap(), "full-cap payload persisted at commit_body");

    // The next chain block accepts b1's payload: every copy is a deterministic
    // skip (unfunded sender), the block stays valid, the heads advance — a
    // payload-maxed DAG block never blocks the UTXO lane (§14.2).
    let template = consensus
        .build_block_template(
            MinerData::new(p2pkh_mldsa87_spk(&[0u8; 64]), vec![]),
            Box::new(OnetimeTxSelector::new(Default::default())),
            TemplateBuildMode::Standard,
        )
        .unwrap();
    let mut b2 = template.block;
    b2.header.hash = 2u64.into();
    consensus.validate_and_insert_block(b2.to_immutable()).virtual_state_task.await.unwrap();
    let h2 = storage.evm_header_store.get(2.into()).unwrap();
    assert_eq!(h2.skipped_tx_count, n as u32, "the full-cap payload was processed: every copy skipped, none accepted");
    assert_eq!(h2.accepted_tx_count, 0);
    assert_eq!(storage.evm_heads_store.read().get().unwrap().latest, BlockHash::from(2u64));

    consensus.shutdown(wait_handles);
}

/// kaspa-pq DNS Dormancy Fence — **WI-1, the activation gate**: a processor-level *integration*
/// test on a REAL mined chain (real headers ⇒ real reachability + blue/DAA scores), exercising the
/// three reconstruction surfaces the pure-kernel unit tests can't reach:
///   1. the LIVE per-round eviction (`stage_dormancy_transitions`, run incrementally per block, its
///      accepted set sourced from `accepted_by_bond_in_blue_window` over the real chain, its round
///      anchors derived from the real canonical-lagged-anchor walk), and
///   2. the pruned-node **jump replay** (`bonds_as_of`) which re-derives the whole dormancy history
///      from genesis in one shot (its band anchors via the unbounded `canonical_anchor_daa_deep`), and
///   3. the pruning-point snapshot **capture** (`capture_pruning_point_overlay_snapshot`).
///
/// It asserts the **jump-vs-incremental byte-equality** that is the heart of the fence's
/// commitment determinism: a never-attested bond that buries + evicts round-by-round on the live
/// chain is reconstructed into a byte-identical `StakeBondRecord` by the one-shot as-of-pp replay
/// (the c==v property, in miniature), and the replay is deterministic (same run twice ⇒ identical).
///
/// The fence is INERT in every shipped preset (`dormancy_activation_daa_score = u64::MAX`); this
/// test pulls it to 0 and shrinks the dormancy windows to their smallest still-v4-consistent values
/// so the bond buries + evicts inside a short chain. No bond/attestation *txs* are mined (that needs
/// the funded-DAG harness, DAG-2); the bond is seeded directly into the store and the real
/// reconstruction code then runs over the real chain.
#[tokio::test]
async fn dormancy_wi1_jump_vs_incremental_bonds_as_of_byte_equal() {
    use crate::model::stores::stake_bonds::{StakeBondsStore, StakeBondsStoreReader};
    use kaspa_consensus_core::api::ConsensusApi;
    use kaspa_consensus_core::dns_finality::{BondStatus, StakeBondRecord};
    use kaspa_consensus_core::tx::TransactionOutpoint;
    use kaspa_hashes::Hash64;
    use rocksdb::WriteBatch;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.dormancy_activation_daa_score = 0; // fence ACTIVE (test-only; u64::MAX in every preset)
            // Small, still-v4-consistent windows so the bond buries + evicts within a short chain.
            // `stake_score_window` must still cover required_stake_depth (10 epochs) · epoch_len +
            // lag + grace for the *base* DNS finality invariant, so keep it comfortably wide.
            dns.attestation_epoch_length_blue_score = 2;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1; // must be < epoch_len (dns_v3 I: backoff < L)
            dns.max_reorg_horizon_blocks = 2;
            dns.unbonding_period_blocks = 2;
            dns.stake_score_window_blue_score = 100;
            dns.dormancy_window_epochs = 3;
            dns.dormancy_evict_period_epochs = 1;
            dns.dormancy_revival_delay_epochs = 1;
            dns.dormancy_evict_limit_bps = 10_000;
            dns.degraded_stake_quality_epochs = 1;
            assert!(dns.dns_v4_params_consistent(), "WI-1 tiny dormancy params must be v4-consistent");
            p.dns_params = Some(dns);
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let dns = config.params.dns_params.clone().unwrap();

    // Seed an Active, never-attested bond created at genesis. Never-attested ⇒ its inactivity
    // counts from its activation epoch, so it goes Dormant a full `dormancy_window` after genesis.
    let op = TransactionOutpoint::new(Hash64::from_u64_word(0xB0AD_1111), 0);
    let seed = StakeBondRecord {
        version: 2,
        bond_outpoint: op,
        owner_pubkey_hash: Hash64::from_u64_word(1),
        validator_pubkey_hash: Hash64::from_u64_word(2),
        validator_pubkey: vec![7u8; 2592],
        amount: 1_000,
        activation_daa_score: 0,
        created_daa_score: 0,
        unbonding_period_blocks: 2,
        owner_reward_spk_payload: [0u8; 64],
        unbond_request_daa_score: None,
        slashed_at_daa_score: None,
        status: BondStatus::Active,
        last_attested_epoch: None,
        dormant_at_daa_score: None,
        dormant_at_epoch: None,
        revival_attested_epoch: None,
    };
    ctx.consensus.virtual_processor().stake_bonds_store.write().insert(op, Arc::new(seed)).unwrap();

    // Mine a linear chain, running the LIVE eviction round after each block exactly as the virtual
    // processor would — threading `prev_last_evicted` so the catch-up is INCREMENTAL (one round per
    // buried epoch), sourcing the accepted set + round anchors from the real chain internally.
    let mut prev_last_evicted = 0u64;
    for _ in 0..26 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
        let vp = ctx.consensus.virtual_processor();
        let sink = ctx.consensus.get_sink();
        let sink_blue = ctx.consensus.get_sink_blue_score();
        let sink_daa = ctx.consensus.get_virtual_daa_score();
        let current = (*vp.stake_bonds_store.read().get(&op).unwrap()).clone();
        let mut batch = WriteBatch::default();
        // Empty `epoch_anchor_daa` ⇒ every round anchor is derived from the real canonical-lagged
        // anchor walk (the same derivation the production `collect_stake_contributions_v2` feeds in).
        prev_last_evicted = vp.stage_dormancy_transitions(
            &mut batch,
            sink,
            std::slice::from_ref(&current),
            &BTreeMap::new(),
            prev_last_evicted,
            sink_daa,
            sink_blue,
            &dns,
        );
        // insert_batch already updated the CachedDbAccess in-memory map, so the next read sees the
        // eviction without committing `batch` — mirroring the batched write inside a virtual commit.
    }

    let vp = ctx.consensus.virtual_processor();
    let sink = ctx.consensus.get_sink();
    let sink_blue = ctx.consensus.get_sink_blue_score();
    let sink_daa = ctx.consensus.get_virtual_daa_score();

    // (1) LIVE integration: the incremental rounds drove the bond Dormant with a BURIED
    // (reorg-invariant) DAA + epoch stamp — proving fence + real chain + eviction round wire up e2e.
    let incremental = (*vp.stake_bonds_store.read().get(&op).unwrap()).clone();
    assert_eq!(incremental.status, BondStatus::Dormant, "never-attested bond must bury + evict on the live chain");
    assert!(incremental.dormant_at_epoch.is_some(), "eviction must stamp a buried epoch");
    assert!(incremental.dormant_at_daa_score.is_some(), "eviction must stamp a buried canonical anchor DAA");

    // (2) JUMP replay: reconstruct the as-of-sink bond set from genesis in one shot (first prune ⇒
    // clean seed ⇒ full replay over (0, pp_buried], band anchors via `canonical_anchor_daa_deep`).
    let reconstructed = vp.bonds_as_of(sink, sink_daa, sink_blue);
    let jump = reconstructed.iter().find(|r| r.bond_outpoint == op).expect("bond present in as-of-pp set").clone();

    // The jump replay must be BYTE-IDENTICAL to the incrementally-evicted live record (c==v).
    assert_eq!(jump, incremental, "jump replay must byte-match the incremental live eviction (c==v)");

    // (3) Determinism: the replay is a pure function of the committed chain — same run twice.
    let reconstructed_again = vp.bonds_as_of(sink, sink_daa, sink_blue);
    assert_eq!(reconstructed, reconstructed_again, "bonds_as_of must be deterministic (jump-invariant)");

    // (4) Capture path executes over the real chain without panicking (exercises the snapshot +
    // boundary_accepted gather that feeds a pruned joiner).
    vp.capture_pruning_point_overlay_snapshot(sink);

    // (5) prune→reimport ROOT-EQUALITY at the wire boundary: the captured snapshot is what a syncer
    // serializes (borsh) and a joiner deserializes + commits. Round-trip it through the exact wire
    // codec (snapshot + boundary_accepted, as in request_pruning_point_snapshots / ibd::flow) and
    // assert the committed overlay root is byte-identical — the importer's c==v acceptance check.
    {
        use crate::model::stores::pruning_overlay_snapshot::PruningPointOverlaySnapshotStoreReader;
        let stored = vp.pruning_overlay_snapshot_store.read().get().expect("snapshot captured at sink");
        let root_before = stored.snapshot.commitment_root();
        let snapshot_bytes = borsh::to_vec(&stored.snapshot).unwrap();
        let boundary_bytes = borsh::to_vec(&stored.boundary_accepted).unwrap();
        let snapshot_wire: kaspa_consensus_core::dns_finality::OverlaySnapshot = borsh::from_slice(&snapshot_bytes).unwrap();
        let boundary_wire: Vec<(kaspa_consensus_core::tx::TransactionOutpoint, u64)> = borsh::from_slice(&boundary_bytes).unwrap();
        assert_eq!(snapshot_wire.commitment_root(), root_before, "overlay commitment root must survive the wire round-trip (c==v)");
        assert_eq!(boundary_wire, stored.boundary_accepted, "boundary_accepted must survive the wire round-trip byte-identically");
    }
}

/// kaspa-pq DNS Dormancy Fence — **WI-1, revive-across-pruning-point**: the SB-5 replay gate.
/// A bond evicts to Dormant, a pruning-point snapshot is captured **while it is Dormant**, then a
/// post-dormancy re-attestation revives it *after* that pruning point. Because revival CLEARS the
/// dormancy stamps, a pruned joiner cannot null-forward the bond — the as-of-pp replay
/// (`bonds_as_of`) must instead **seed** the dormant stamps from the previous snapshot and **replay**
/// the eviction+revival rounds over the `(old_pp_buried, pp_buried]` band (reading the same accepted
/// attestation the live node saw). This test drives that whole path on a REAL mined chain and asserts
/// the jump replay across the pruning point reconstructs a byte-identical `StakeBondRecord` to the
/// incrementally-revived live one — the property that makes revival safe under pruning.
#[tokio::test]
async fn dormancy_wi1_revive_across_pruning_point_byte_equal() {
    use crate::model::stores::accepted_attestations::AcceptedAttestationsStore;
    use crate::model::stores::stake_bonds::{StakeBondsStore, StakeBondsStoreReader};
    use kaspa_consensus_core::api::ConsensusApi;
    use kaspa_consensus_core::dns_finality::{BondStatus, StakeBondRecord};
    use kaspa_consensus_core::tx::TransactionOutpoint;
    use kaspa_hashes::Hash64;
    use rocksdb::WriteBatch;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            let mut dns = DEVNET_PARAMS.dns_params.clone().unwrap();
            dns.dns_activation_daa_score = 0;
            dns.dormancy_activation_daa_score = 0;
            dns.attestation_epoch_length_blue_score = 2;
            dns.attestation_lag_blue_score = 2;
            dns.attestation_anchor_backoff_blue_score = 1;
            dns.max_reorg_horizon_blocks = 2;
            dns.unbonding_period_blocks = 2;
            dns.stake_score_window_blue_score = 100;
            dns.dormancy_window_epochs = 3;
            dns.dormancy_evict_period_epochs = 1;
            dns.dormancy_revival_delay_epochs = 1;
            dns.dormancy_evict_limit_bps = 10_000;
            dns.degraded_stake_quality_epochs = 1;
            assert!(dns.dns_v4_params_consistent());
            p.dns_params = Some(dns);
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let dns = config.params.dns_params.clone().unwrap();

    let op = TransactionOutpoint::new(Hash64::from_u64_word(0xB0AD_2222), 0);
    let seed = StakeBondRecord {
        version: 2,
        bond_outpoint: op,
        owner_pubkey_hash: Hash64::from_u64_word(1),
        validator_pubkey_hash: Hash64::from_u64_word(2),
        validator_pubkey: vec![7u8; 2592],
        amount: 1_000,
        activation_daa_score: 0,
        created_daa_score: 0,
        unbonding_period_blocks: 2,
        owner_reward_spk_payload: [0u8; 64],
        unbond_request_daa_score: None,
        slashed_at_daa_score: None,
        status: BondStatus::Active,
        last_attested_epoch: None,
        dormant_at_daa_score: None,
        dormant_at_epoch: None,
        revival_attested_epoch: None,
    };
    ctx.consensus.virtual_processor().stake_bonds_store.write().insert(op, Arc::new(seed)).unwrap();

    // Small closure to run one incremental live eviction round at the current sink.
    let step = |ctx: &TestContext, prev: u64| -> (u64, StakeBondRecord) {
        let vp = ctx.consensus.virtual_processor();
        let sink = ctx.consensus.get_sink();
        let sink_blue = ctx.consensus.get_sink_blue_score();
        let sink_daa = ctx.consensus.get_virtual_daa_score();
        let current = (*vp.stake_bonds_store.read().get(&op).unwrap()).clone();
        let mut batch = WriteBatch::default();
        let last = vp.stage_dormancy_transitions(
            &mut batch,
            sink,
            std::slice::from_ref(&current),
            &BTreeMap::new(),
            prev,
            sink_daa,
            sink_blue,
            &dns,
        );
        (last, (*vp.stake_bonds_store.read().get(&op).unwrap()).clone())
    };

    // Phase 1 — mine until the bond evicts to Dormant.
    let mut prev = 0u64;
    let mut dormant_epoch = None;
    for _ in 0..60 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
        let (last, b) = step(&ctx, prev);
        prev = last;
        if b.status == BondStatus::Dormant {
            dormant_epoch = b.dormant_at_epoch;
            break;
        }
    }
    let e_d = dormant_epoch.expect("bond must evict to Dormant within the mining budget");

    // Phase 2 — capture a pruning-point snapshot WHILE the bond is Dormant. This is the "previous
    // snapshot" the later replay seeds the dormant stamps from (revival will erase the live ones).
    let pp1 = ctx.consensus.get_sink();
    ctx.consensus.virtual_processor().capture_pruning_point_overlay_snapshot(pp1);

    // Phase 3 — a post-dormancy re-attestation (epoch strictly after eviction). Mine one block first
    // so the attestation lands strictly ABOVE pp1 (the live blue-window walk stops AT pp1, so a row
    // seeded at pp1 itself would be missed), then seed it and mine until the live path revives.
    let e_revive = e_d + 1;
    ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    let (last, _) = step(&ctx, prev);
    prev = last;
    let attest_block = ctx.consensus.get_sink();
    assert_ne!(attest_block, pp1, "re-attestation must sit strictly above the captured pruning point");
    ctx.consensus.virtual_processor().accepted_attestations_store.insert(attest_block, Arc::new(vec![(op, e_revive)])).unwrap();

    let mut revived = false;
    for _ in 0..60 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
        let (last, b) = step(&ctx, prev);
        prev = last;
        if b.status == BondStatus::Active {
            revived = true;
            break;
        }
    }
    assert!(revived, "post-dormancy re-attestation must revive the bond on the live chain");

    let vp = ctx.consensus.virtual_processor();
    let sink = ctx.consensus.get_sink();
    let sink_blue = ctx.consensus.get_sink_blue_score();
    let sink_daa = ctx.consensus.get_virtual_daa_score();
    let incremental = (*vp.stake_bonds_store.read().get(&op).unwrap()).clone();
    assert_eq!(incremental.status, BondStatus::Active, "revived bond is Active");
    assert!(
        incremental.dormant_at_epoch.is_none()
            && incremental.dormant_at_daa_score.is_none()
            && incremental.revival_attested_epoch.is_none(),
        "revival must clear all three dormancy stamps"
    );

    // Phase 4 — the jump replay ACROSS pp1: seed dormant from the pp1 snapshot, replay the band that
    // carries the revival attestation, and reconstruct. Must byte-match the live revived record.
    let reconstructed = vp.bonds_as_of(sink, sink_daa, sink_blue);
    let jump = reconstructed.iter().find(|r| r.bond_outpoint == op).expect("bond present in as-of-pp set").clone();
    assert_eq!(jump, incremental, "revive-across-pp jump replay must byte-match the live revived bond (SB-5 c==v)");

    // Determinism across the pruning point.
    assert_eq!(reconstructed, vp.bonds_as_of(sink, sink_daa, sink_blue), "bonds_as_of must be deterministic across pp");
}

/// The seeded, past-relative facts a PALW-active reward-rail E2E needs to MINT algo-4 (replica-lane)
/// blocks against one selected parent: the ground winning ticket (nullifier + pinned nonce), the leaf /
/// certificate seeded into the stores, the finality-buried anchor's lagged beacon + the derived
/// chain_commit, and the two provider reward scripts. Produced once by [`palw_algo4_env`]; consumed by
/// [`mint_algo4`], which builds as many distinct algo-4 blocks (siblings, reuses, single-field mutants)
/// off `sp` as a test needs.
struct PalwAlgo4Facts {
    sp: BlockHash,
    replica_bits: u32,
    batch_id: kaspa_hashes::Hash64,
    leaf_index: u32,
    proof_type: u8,
    nullifier: kaspa_hashes::Hash64,
    nonce: u64,
    cert_hash: kaspa_hashes::Hash64,
    target_interval: u64,
    expected_chain_commit: kaspa_hashes::Hash64,
    prov_a: kaspa_consensus_core::tx::ScriptPublicKey,
    prov_b: kaspa_consensus_core::tx::ScriptPublicKey,
    miner: MinerData,
    /// ADR-0040 P1-6: the ticket authority whose ML-DSA-87 signature authorizes each algo-4 block.
    /// The leaf's `ticket_authority_pk_hash` binds to this key, so only its holder can mint.
    authority_seed: [u8; 32],
}

/// Mint (but do NOT insert) a distinct algo-4 (replica-lane) block off `f.sp`, carrying the ground
/// winning ticket from `f`. `ts_delta` perturbs the template timestamp so callers can build several
/// blocks that share ALL ticket-relevant fields (same nullifier/leaf/anchor/chain_commit/eligibility,
/// hence both win clause 9) yet have DISTINCT block ids — the exact shape a duplicate-nullifier
/// double-pay test needs. `mutate` runs AFTER the PALW fields are stamped, for single-field rejection
/// tests (flip chain_commit / break the nonce pin), and the header is re-finalized so the mutation binds
/// into the block id. All GHOSTDAG-derived fields (component work, beacon seed) are kept from the v3
/// template, so S2 re-derives and authenticates them exactly (construction == validation).
/// ADR-0040 P1-6 — the test ticket authority. A single fixed seed so every algo-4 fixture in this file
/// shares one authority; the leaf binds to its key hash and `mint_algo4` signs with it.
const PALW_TEST_AUTHORITY_SEED: [u8; 32] = [0x9a; 32];

/// ADR-0040 P1-7: the leaf's published activation window, which fixes its own slot range. Must match
/// `make_leaf`'s `activation_epoch` / `expiry_epoch` — the derived target interval depends on it.
const PALW_TEST_LEAF_ACTIVATION_EPOCH: u64 = 0;
const PALW_TEST_LEAF_EXPIRY_EPOCH: u64 = 1000;

fn palw_authority_keypair(seed: [u8; 32]) -> libcrux_ml_dsa::ml_dsa_87::MLDSA87KeyPair {
    libcrux_ml_dsa::ml_dsa_87::generate_key_pair(seed)
}

fn palw_authority_pk_hash(seed: [u8; 32]) -> kaspa_hashes::Hash64 {
    let kp = palw_authority_keypair(seed);
    kaspa_hashes::blake2b_512_keyed(kaspa_consensus_core::palw::PALW_AUTHORIZATION_DOMAIN, kp.verification_key.as_ref())
}

fn mint_algo4(
    tc: &TestConsensus,
    f: &PalwAlgo4Facts,
    seed: u8,
    ts_delta: u64,
    mutate: impl FnOnce(&mut kaspa_consensus_core::header::Header),
) -> MutableBlock {
    use kaspa_consensus_core::header::PalwHeaderFields;
    use kaspa_consensus_core::pow_layer0::POW_ALGO_ID_PALW_REPLICA;
    use kaspa_hashes::Hash64;
    let mut mb = tc.build_utxo_valid_block_with_parents(Hash64::from_bytes([seed; 64]), vec![f.sp], f.miner.clone(), vec![]);
    let keep_hash_work = mb.header.blue_hash_work;
    let keep_compute_work = mb.header.blue_compute_work;
    let keep_beacon_seed = mb.header.palw_beacon_seed;
    mb.header.pow_algo_id = POW_ALGO_ID_PALW_REPLICA;
    mb.header.bits = f.replica_bits;
    mb.header.nonce = f.nonce;
    mb.header.timestamp = mb.header.timestamp.saturating_add(ts_delta);
    mb.header = mb.header.with_palw_fields(PalwHeaderFields {
        blue_hash_work: keep_hash_work,       // KEEP — GHOSTDAG-derived, independent of this block's own algo
        blue_compute_work: keep_compute_work, // KEEP
        palw_beacon_seed: keep_beacon_seed,   // KEEP — S2 re-derives & authenticates it
        palw_batch_id: f.batch_id,
        palw_leaf_index: f.leaf_index,
        palw_ticket_nullifier: f.nullifier,
        palw_epoch_certificate_hash: f.cert_hash,
        palw_chain_commit: f.expected_chain_commit,
        palw_target_daa_interval: f.target_interval,
        palw_authorization_hash: Hash64::default(),
        palw_proof_type: f.proof_type,
    }); // with_palw_fields re-finalizes header.hash over the full v3 preimage
    // ADR-0040 P1-6 (AUTH-01/02/03) — attach the per-block ticket authorization.
    //
    // Construction == validation: clause 7 requires every algo-4 block to carry an ML-DSA-87
    // authorization signed by the leaf's declared ticket authority, binding this block's parents and
    // transaction set. Without it a winning nullifier (disclosed at mint) would let any observer restamp
    // the same draw onto unlimited competing blocks.
    {
        use kaspa_consensus_core::palw::{palw_header_preimage_commitment, palw_parents_commitment, PalwBlockAuthorizationV1, PALW_AUTHORIZATION_MLDSA87_CONTEXT};
        use kaspa_consensus_core::subnets::SUBNETWORK_ID_PALW_BLOCK_AUTHORIZATION;
        use kaspa_consensus_core::tx::Transaction;
        use libcrux_ml_dsa::ml_dsa_87 as mldsa;

        let net_id = tc.params().net.suffix().unwrap_or(0);
        // The merkle root the authorization binds EXCLUDES the authorization tx itself (non-circular).
        let authed_root = kaspa_consensus_core::merkle::calc_hash_merkle_root(mb.transactions.iter());
        let parents_hash = palw_parents_commitment(mb.header.direct_parents());
        let commitment = palw_header_preimage_commitment(
            net_id,
            &parents_hash,
            &authed_root,
            &f.batch_id,
            f.leaf_index,
            &f.nullifier,
            &f.expected_chain_commit,
            f.target_interval,
            mb.header.timestamp,
        );
        let kp = palw_authority_keypair(f.authority_seed);
        let mut auth = PalwBlockAuthorizationV1 {
            version: 1,
            batch_id: f.batch_id,
            leaf_index: f.leaf_index,
            ticket_nullifier: f.nullifier,
            header_preimage_commitment: commitment,
            authority_public_key: kp.verification_key.as_ref().to_vec(),
            signature: vec![],
        };
        let digest = auth.signing_hash(net_id);
        auth.signature = mldsa::sign(&kp.signing_key, digest.as_bytes().as_slice(), PALW_AUTHORIZATION_MLDSA87_CONTEXT, [0x3cu8; 32])
            .expect("sign authorization")
            .as_ref()
            .to_vec();
        mb.header.palw_authorization_hash = auth.hash();
        let payload = borsh::to_vec(&auth).expect("borsh");
        mb.transactions.push(Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_PALW_BLOCK_AUTHORIZATION, 0, payload));
        // The header's own merkle root DOES include the authorization tx (it is a real transaction).
        mb.header.hash_merkle_root = kaspa_consensus_core::merkle::calc_hash_merkle_root(mb.transactions.iter());
    }

    mutate(&mut mb.header);
    mb.header.finalize(); // re-finalize so any per-test mutation is bound into the block id
    mb
}

/// kaspa-pq ADR-0039 PALW — the FIRST end-to-end reward-rail integration test: a hand-built algo-4
/// (replica-lane, `pow_algo_id = 4`) block is pushed through the ENTIRE real pipeline
/// (header → GHOSTDAG → body 9-clause ticket check → virtual/UTXO → coinbase) on a single-node
/// PALW-ACTIVE `TestConsensus`, reaches `StatusUTXOValid`, and the CHILD that merges it pays the two
/// providers' one-time reward scripts (§17.2 `WorkRewardClass::ReplicaPalw`, base 77 % split A/B).
///
/// This is the in-process proof that the three activation seams that just landed compose end-to-end:
///   1. the algo-4 Layer-0 PoW arm (`consensus/pow` — no panic, floor tag reused),
///   2. the template's `palw_beacon_seed` stamping (so the algo-3 v3 supporting chain authenticates),
///   3. the `ReplicaPalw` reward-class derivation (`calculate_utxo_state` → provider-pair coinbase).
///
/// It is NOT a claim that PALW can be mined for real value today — the config is a throwaway
/// PALW-active net (`palw_activation_daa_score = 0`), the inference is not run (the leaf/cert/view are
/// seeded directly), and PoW is skipped. Real activation still needs a re-genesis + real CUDA backend +
/// a live DNS beacon network + external audit. What this proves is that the REWARD RAIL is wired
/// correctly: an accepted algo-4 block mints a provider-pair UTXO through the exact production code.
///
/// Shared construction for the algo-4 reward-rail E2E tests (K5 §11.3): builds a PALW-active SIMNET
/// TestConsensus with the given beacon `grace_epochs`, an algo-3 v3 supporting chain, resolves the
/// finality-buried anchor, seeds a leaf/cert/view, and grinds a winning ticket nullifier — returning the
/// harness plus the [`PalwAlgo4Facts`] needed to MINT algo-4 blocks off `sp`. Does NOT itself mint or
/// insert an algo-4 block (that is [`mint_algo4`] + `validate_and_insert_block`). Because DNS is inactive
/// the epoch-0 beacon is degraded: `grace_epochs >= 1` ⇒ DegradedGrace (algo-4 accepted); `grace_epochs
/// == 0` ⇒ Halted (algo-4 disqualified at the S2 `PalwLaneHalted` rule).
/// Real-inference leaf commitments (from a k=2 Qwen match) injected into the seeded leaf, so an accepted
/// algo-4 block carries a leaf whose model fingerprint came from an ACTUAL LLM forward pass, not hand-set
/// constants. Supplied by `palw_algo4_real_inference_e2e` from a fixture that `palw-qwen-demo` produces.
#[derive(Clone)]
struct LeafInferParams {
    model_profile_id: kaspa_hashes::Hash64,
    runtime_class_id: kaspa_hashes::Hash64,
    shape_id: u16,
    quantum_count: u16,
    private_match_commitment: kaspa_hashes::Hash64,
}

async fn palw_algo4_env(grace_epochs: u64) -> (TestConsensus, Vec<std::thread::JoinHandle<()>>, PalwAlgo4Facts) {
    palw_algo4_env_infer(grace_epochs, None, None).await
}

async fn palw_algo4_env_infer(
    grace_epochs: u64,
    infer: Option<LeafInferParams>,
    config_override: Option<kaspa_consensus_core::config::Config>,
) -> (TestConsensus, Vec<std::thread::JoinHandle<()>>, PalwAlgo4Facts) {
    palw_algo4_env_full(grace_epochs, infer, config_override, None).await
}

/// ADR-0040 P1-1: leaves are now write-once (`DbPalwStore::insert_leaf` refuses to replace admitted
/// content), so a test can no longer mutate a seeded leaf after the fact. `leaf_edit` lets a test shape
/// the leaf BEFORE it is first written — which is also the only correct order, since the clause-9
/// eligibility grind hashes the leaf: editing after the grind would invalidate the very draw the block
/// depends on.
async fn palw_algo4_env_full(
    grace_epochs: u64,
    infer: Option<LeafInferParams>,
    config_override: Option<kaspa_consensus_core::config::Config>,
    leaf_edit: Option<&(dyn Fn(&mut kaspa_consensus_core::palw::PalwPublicLeafV1) + Sync)>,
) -> (TestConsensus, Vec<std::thread::JoinHandle<()>>, PalwAlgo4Facts) {
    use crate::model::stores::headers::HeaderStoreReader;
    use crate::model::stores::palw::PalwStore;
    use crate::processes::palw::resolve_palw_lagged_anchor;
    use kaspa_consensus_core::config::params::{ForkActivation, SIMNET_PARAMS};
    use kaspa_consensus_core::palw::{
        BeaconDnsAnchor, LaneDifficultyParams, PalwBatchCertificateV1, PalwBatchLifecycleV1, PalwBatchStatus, PalwBatchViewV1,
        PalwPublicLeafV1, chain_commit, dns_finality_certificate_hash_v1, eligibility_hash, palw_eligibility_win,
        ticket_nullifier_commitment,
    };
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint};
    use kaspa_hashes::Hash64;
    use std::sync::Arc;

    fn hh(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }
    // The seeded leaf, parameterised only by the nullifier commitment (grinding varies just that field).
    #[allow(clippy::too_many_arguments)]
    fn make_leaf(
        batch_id: Hash64,
        leaf_index: u32,
        proof_type: u8,
        a: &ScriptPublicKey,
        b: &ScriptPublicKey,
        commit: Hash64,
        infer: &Option<LeafInferParams>,
    ) -> PalwPublicLeafV1 {
        // model-opaque leaf fingerprint: real k=2 inference values when injected, else deterministic defaults
        let (mpi, rci, sid, qc, pmc) = match infer {
            Some(p) => (p.model_profile_id, p.runtime_class_id, p.shape_id, p.quantum_count, p.private_match_commitment),
            None => (hh(1), hh(2), 1u16, 1u16, Hash64::default()),
        };
        PalwPublicLeafV1 {
            version: 1,
            batch_id,
            leaf_index,
            job_nullifier: hh(9),
            ticket_nullifier_commitment: commit,
            model_profile_id: mpi,
            runtime_class_id: rci,
            shape_id: sid,
            quantum_count: qc,
            proof_type,
            provider_a_bond: TransactionOutpoint::new(hh(6), 0),
            provider_b_bond: TransactionOutpoint::new(hh(7), 0),
            provider_a_reward_script: a.clone(),
            provider_b_reward_script: b.clone(),
            // ADR-0040 P1-6 (AUTH-03): the leaf names the authority that may authorize its blocks.
            ticket_authority_pk_hash: palw_authority_pk_hash(PALW_TEST_AUTHORITY_SEED),
            private_match_commitment: pmc,
            receipt_da_root: Hash64::default(),
            registered_epoch: 0,
            activation_epoch: 0,
            expiry_epoch: 1000,
            leaf_bond_sompi: 0,
        }
    }

    // Apply the test's pre-write edit, then return. Wrapped so every construction site (the grind loop
    // AND the final seed) sees the identical leaf.
    fn make_leaf_edited(
        batch_id: Hash64,
        leaf_index: u32,
        proof_type: u8,
        a: &ScriptPublicKey,
        b: &ScriptPublicKey,
        commit: Hash64,
        infer: &Option<LeafInferParams>,
        leaf_edit: Option<&(dyn Fn(&mut kaspa_consensus_core::palw::PalwPublicLeafV1) + Sync)>,
    ) -> PalwPublicLeafV1 {
        let mut l = make_leaf(batch_id, leaf_index, proof_type, a, b, commit, infer);
        if let Some(f) = leaf_edit {
            f(&mut l);
        }
        l
    }

    // ---- Config: caller-supplied (e.g. the shipped DEVNET_PALW_PARAMS preset), else SIMNET base
    // (skip_proof_of_work, genesis bits = max target), PALW active from genesis ----
    let config = config_override.unwrap_or_else(|| ConfigBuilder::new(SIMNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.palw_activation_daa_score = 0;
            // ADR-0040 P0-3: every shipped preset withholds algo-4 ACCEPTANCE (`palw_algo4_accept =
            // false`) until the §7.1.1 gates are released. These tests exercise algo-4 *behaviour*, so
            // they presuppose acceptance and open the lever here — once, in the shared env, rather than
            // in each test. The shipped default is pinned separately by
            // `palw_algo4_rejected_while_accept_lever_closed`, which passes its own config and is
            // therefore untouched by this override.
            p.palw_algo4_accept = true;
            p.palw_epoch_length_daa = 100; // epoch(B) == 0 on this short chain
            // K5 (§11.3): the beacon grace window. DNS is inactive here, so at epoch 0 degraded_epochs == 1;
            // grace >= 1 keeps the mode DegradedGrace (block accepted), grace == 0 forces Halted.
            p.palw_beacon_grace_epochs = grace_epochs;
            // SIMNET defaults kHeavyHash (algo-1); once PALW is active check_live_algo_id accepts only
            // algo 3|4, so make the standard builder emit algo-3 v3 supporting blocks.
            p.pow_blake2b_sha3_activation = ForkActivation::always();
            // Non-inert lane difficulty: HashFloor HOLD must equal the genesis bits (== the single-lane
            // HOLD the builder emits), Replica HOLD easy so the clause-9 draw is winnable by grinding
            // only a couple of nullifiers. min_samples huge so both lanes HOLD across the whole chain.
            p.palw_lane_difficulty = LaneDifficultyParams {
                genesis_hash_bits: 0x207fffff,
                genesis_replica_bits: 0x207fffff,
                min_samples: 100_000,
                ..LaneDifficultyParams::INERT
            };
            // Never let the single-lane difficulty engine retarget away from the max-easy genesis bits.
            p.min_difficulty_window_size = p.difficulty_window_size;
            // Small DNS anchor windows so a finality-buried v3 anchor exists after a short chain; keep
            // dns_activation = 0 so the coinbase fee-split carve is present (the ReplicaPalw arm needs it).
            let d = p.dns_params.as_mut().unwrap();
            d.dns_activation_daa_score = 0;
            d.attestation_epoch_length_blue_score = 4;
            d.attestation_lag_blue_score = 2;
            d.attestation_anchor_backoff_blue_score = 1;
        })
        .build());
    let net_id = config.params.net.suffix().unwrap_or(0);
    let replica_bits = config.params.palw_lane_difficulty.genesis_replica_bits;

    let tc = TestConsensus::new(&config);
    let handles = tc.init();
    let miner = MinerData::new(p2pkh_mldsa87_spk(&[0x07; 64]), vec![]);

    // ---- Build a short algo-3 v3 supporting chain via the REAL template builder ----
    let mut parent = config.params.genesis.hash;
    for i in 1u8..=8 {
        let blk = tc.build_utxo_valid_block_with_parents(hh(i), vec![parent], miner.clone(), vec![]);
        let h = blk.header.hash;
        let status = tc.validate_and_insert_block(blk.to_immutable()).virtual_state_task.await.unwrap();
        assert_eq!(status, BlockStatus::StatusUTXOValid, "supporting algo-3 v3 block {i} must validate");
        parent = h;
    }
    let sp = parent; // selected parent of the algo-4 block

    // ---- Resolve the SAME finality-buried anchor the body check will, read its frozen facts ----
    let dns_params = config.params.dns_params.clone().unwrap();
    let anchor = resolve_palw_lagged_anchor(&tc.storage.headers_store, tc.reachability_service(), &dns_params, sp)
        .expect("a finality-buried DNS anchor must exist after the supporting chain");
    let anchor_header = tc.storage.headers_store.get_header(anchor.anchor_hash).unwrap();
    let anchor_facts = BeaconDnsAnchor {
        hash: anchor.anchor_hash,
        blue_score: anchor.anchor_blue_score,
        daa_score: anchor.anchor_daa_score,
        overlay_root: anchor_header.overlay_commitment_root,
    };
    let eligibility_beacon = anchor_header.palw_beacon_seed; // clause-9 lagged R_E (template-stamped)

    // ---- Build a throwaway algo-3 template on `sp` to read its GHOSTDAG-fixed daa_score (the target
    // interval every algo-4 block minted off `sp` will share); the algo-4 blocks themselves are minted
    // later by `mint_algo4`. ----
    let mb = tc.build_utxo_valid_block_with_parents(hh(0xf0), vec![sp], miner.clone(), vec![]);
    let target_interval = mb.header.daa_score; // clause 5: target_daa_interval == daa_score

    // ---- Grind the ticket nullifier so the clause-9 eligibility draw wins (bits easy ⇒ ~50 % per try) ----
    let batch_id = hh(0x42);
    let leaf_index = 0u32;
    let proof_type = 1u8; // must match leaf.proof_type (clause 2)
    let prov_a = p2pkh_mldsa87_spk(&[0xa0; 64]);
    let prov_b = p2pkh_mldsa87_spk(&[0xb0; 64]);
    let expected_chain_commit =
        chain_commit(&anchor_facts.hash, &dns_finality_certificate_hash_v1(&anchor_facts), target_interval, net_id);
    let (nullifier, nonce) = {
        let mut cand_byte: u16 = 1;
        loop {
            let cand = hh(cand_byte as u8);
            let leaf = make_leaf_edited(batch_id, leaf_index, proof_type, &prov_a, &prov_b, ticket_nullifier_commitment(&cand), &infer, leaf_edit);
            let leaf_hash = leaf.leaf_hash();
            let digest =
                eligibility_hash(net_id, &eligibility_beacon, &expected_chain_commit, target_interval, &batch_id, leaf_index, &leaf_hash, &cand);
            let cb = cand.as_byte_slice();
            let nonce = u64::from_le_bytes([cb[0], cb[1], cb[2], cb[3], cb[4], cb[5], cb[6], cb[7]]);
            if palw_eligibility_win(&digest, replica_bits, nonce, &cand) {
                break (cand, nonce);
            }
            cand_byte += 1;
            assert!(cand_byte < 256, "eligibility grind exhausted (target unexpectedly hard)");
        }
    };

    // ---- Seed the leaf + certificate CONTENT into the content-addressed blob store ----
    let leaf = make_leaf_edited(batch_id, leaf_index, proof_type, &prov_a, &prov_b, ticket_nullifier_commitment(&nullifier), &infer, leaf_edit);
    tc.storage.palw_store.insert_leaf(batch_id, leaf_index, Arc::new(leaf)).unwrap();
    let cert = PalwBatchCertificateV1 {
        version: 1,
        batch_id,
        manifest_hash: Hash64::default(),
        leaf_root: Hash64::default(),
        audit_beacon_epoch: 0,
        audit_sample_root: Hash64::default(),
        passed_leaf_count: 1,
        rejected_leaf_bitmap_root: Hash64::default(),
        certificate_epoch: 0,
        activation_epoch: 0,
        expiry_epoch: 1000,
        auditor_set_commitment: Hash64::default(),
        approving_stake: 0,
        votes: vec![],
    };
    let cert_hash = cert.hash();
    tc.storage.palw_store.insert_certificate(cert_hash, Arc::new(cert)).unwrap();

    // ---- Seed the batch VIEW (directly Active) at the algo-4 block's selected parent ----
    let mut view = PalwBatchViewV1::new();
    view.batches.insert(
        batch_id,
        PalwBatchLifecycleV1 {
            status: PalwBatchStatus::Active,
            registration_epoch: 0,
            activation_not_before_epoch: 0,
            expiry_epoch: 1000,
            leaf_count: 1,
            chunk_count: 1,
            chunks_present: [1, 0, 0, 0],
            leaf_root: Hash64::default(),
            cert_hash: Some(cert_hash),
            cert_activation_epoch: 0,
            cert_expiry_epoch: 1000,
            cert_approving_stake: 0,
            first_cert_daa: None,
            revoked_from_daa: None,
        },
    );
    tc.storage.palw_overlay_view_store.set(sp, Arc::new(view)).unwrap();

    // Assemble the facts a test needs to MINT algo-4 blocks off `sp`. The throwaway template above was
    // built only to read the GHOSTDAG-fixed target interval + derive chain_commit; minting is deferred to
    // `mint_algo4`, so one env can produce many distinct algo-4 blocks (siblings / reuses / mutants).
    // `leaf` is the exact PalwPublicLeafV1 seeded into the content store above.
    let facts = PalwAlgo4Facts {
        sp,
        replica_bits,
        batch_id,
        leaf_index,
        proof_type,
        nullifier,
        nonce,
        cert_hash,
        target_interval,
        expected_chain_commit,
        prov_a,
        prov_b,
        miner,
        authority_seed: PALW_TEST_AUTHORITY_SEED,
    };
    (tc, handles, facts)
}

/// The single-algo-4-block reward-rail E2E driver used by the two original tests: build the env, mint ONE
/// honest algo-4 block off `sp` (no mutation), insert it through the REAL pipeline, and return the
/// harness + the algo-4 block hash / its selected parent / the provider scripts / the miner + the status
/// the insert reported.
#[allow(clippy::type_complexity)]
async fn palw_algo4_e2e_build(
    grace_epochs: u64,
) -> (
    TestConsensus,
    Vec<std::thread::JoinHandle<()>>,
    BlockHash,
    BlockHash,
    kaspa_consensus_core::tx::ScriptPublicKey,
    kaspa_consensus_core::tx::ScriptPublicKey,
    MinerData,
    BlockStatus,
) {
    let (tc, handles, f) = palw_algo4_env(grace_epochs).await;
    let mb = mint_algo4(&tc, &f, 0xf0, 0, |_| {});
    let algo4_hash = mb.header.hash;
    let insert_status = tc.validate_and_insert_block(mb.to_immutable()).virtual_state_task.await.unwrap();
    (tc, handles, algo4_hash, f.sp, f.prov_a, f.prov_b, f.miner, insert_status)
}

/// K5 §17: an algo-4 block minted under a DEGRADED-GRACE beacon is accepted through the full pipeline
/// and its merging child pays the provider pair (§17.1 base split A/B). The honest degraded path — now
/// also pinning the double-pay guards (exactly one output per provider, no base leak to the merging
/// miner) and the §15.2 window fold that every later dedup depends on.
#[tokio::test]
async fn palw_algo4_block_accepted_and_pays_provider_pair_e2e() {
    use crate::model::stores::palw_nullifier::PalwNullifierStoreReader;
    use kaspa_consensus_core::tx::ScriptPublicKey;
    let (tc, handles, f) = palw_algo4_env(1).await;
    let algo4 = mint_algo4(&tc, &f, 0xf0, 0, |_| {});
    let algo4_hash = algo4.header.hash;
    let insert_status = tc.validate_and_insert_block(algo4.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(
        insert_status,
        BlockStatus::StatusUTXOValid,
        "the algo-4 replica block must be accepted through the full pipeline (DegradedGrace)"
    );

    // ---- The merging child pays the provider pair (ReplicaPalw 77 % base split A/B) ----
    let child_hash = kaspa_hashes::Hash64::from_bytes([0xf1; 64]);
    let child = tc.build_utxo_valid_block_with_parents(child_hash, vec![algo4_hash], f.miner.clone(), vec![]);
    let child_coinbase = child.transactions[0].clone();
    let status = tc.validate_and_insert_block(child.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(status, BlockStatus::StatusUTXOValid, "the block merging the algo-4 source must be accepted");

    let outputs_to = |s: &ScriptPublicKey| child_coinbase.outputs.iter().filter(|o| &o.script_public_key == s).count();
    let credited = |s: &ScriptPublicKey| child_coinbase.outputs.iter().filter(|o| &o.script_public_key == s).map(|o| o.value).sum::<u64>();
    // The reward UTXO the whole rail exists to produce: the child coinbase pays BOTH provider scripts,
    // each by EXACTLY ONE output — even in the honest path this is the double-credit structural guard (a
    // regression paying a source twice would push two outputs to a provider). Because the §17.1 base
    // (77 %) splits A 38.5 % / B 38.5 %, the two are non-zero and equal to within the odd sompi.
    assert_eq!(outputs_to(&f.prov_a), 1, "provider A is paid by exactly one output");
    assert_eq!(outputs_to(&f.prov_b), 1, "provider B is paid by exactly one output");
    let (out_a, out_b) = (credited(&f.prov_a), credited(&f.prov_b));
    assert!(out_a > 0 && out_b > 0, "both provider rewards must be non-zero (got A={out_a} B={out_b})");
    assert!(out_a.abs_diff(out_b) <= 1, "the §17.1 base must split evenly A/B (got A={out_a} B={out_b})");
    // No PALW base leaks to the merging miner / source assembler (both are `f.miner` here, and with zero
    // fees its whole legitimate share is 0) — closing the double-pay hole the bare >0/even check left open.
    assert_eq!(credited(&f.miner.script_public_key), 0, "no PALW base leaks to the merging miner / source assembler");

    // §15.2: the child folds the accepted source's ticket nullifier into its persisted active-nullifier
    // window, so any descendant reusing it is recolored red. The SOURCE's own window is empty — a block's
    // ticket enters its DESCENDANTS' windows (it is in their mergeset_blues), never its own.
    assert!(
        tc.storage.palw_nullifier_store.get(child_hash).unwrap().contains(&f.nullifier),
        "the merging child folds the algo-4 source's nullifier into its active-nullifier window"
    );
    assert!(
        tc.storage.palw_nullifier_store.get(algo4_hash).unwrap().is_empty(),
        "the source's own window carries no ticket (only descendants that merge it record it)"
    );

    tc.shutdown(handles);
}

/// kaspa-pq ADR-0039 P0 — the SHIPPED `DEVNET_PALW_PARAMS` preset (`--devnet --netsuffix=111`, committed
/// d02d1dd) accepts a mock-k2 algo-4 proof-of-LLM block through the ENTIRE real pipeline and pays the
/// provider pair: the in-process proof that the LIVE devnet preset (not just a SIMNET-edited config) is
/// algo-4-ready. Only the DNS anchor windows are tuned small here — the shipped preset inherits the large
/// `GENESIS_ACTIVE_DNS_PARAMS` windows, so a running daemon needs either these small windows baked in or a
/// long supporting chain before a finality-buried anchor resolves (the Stage-5 daemon-packaging follow-up
/// in docs/design/palw-devnet-activation-runbook.md). Everything else — PALW active, max-easy
/// genesis/replica bits, skip_proof_of_work, algo-3 v3 supporting blocks, EVM off — is the preset verbatim.
#[tokio::test]
async fn palw_algo4_devnet_palw_preset_e2e() {
    use kaspa_consensus_core::config::params::DEVNET_PALW_PARAMS;
    use kaspa_consensus_core::network::{NetworkId, NetworkType};
    use kaspa_consensus_core::tx::ScriptPublicKey;
    // No edits to the anchor windows: the shipped DEVNET_PALW_PARAMS bakes the small ones
    // (DEVNET_PALW_DNS_PARAMS), so a finality-buried anchor resolves on the short supporting chain.
    let mut config = ConfigBuilder::new(DEVNET_PALW_PARAMS).build();
    // This is the real shipped preset (PALW-active devnet-111), not a SIMNET stand-in.
    assert_eq!(config.params.net, NetworkId::with_suffix(NetworkType::Devnet, 111));
    assert!(config.params.is_palw_active(0));
    assert!(config.params.skip_proof_of_work);

    // ADR-0040 P0-3 — the ONE deliberate override. The shipped preset now ships `palw_algo4_accept =
    // false`, so algo-4 headers are rejected at `check_pow_algo_id` before any store write. This test
    // asserts what the preset can do ONCE THE GATES ARE RELEASED, so it opens the lever explicitly.
    // The companion test `palw_algo4_rejected_while_accept_lever_closed` pins the shipped default.
    assert!(!config.params.palw_algo4_accept, "the shipped preset must ship with the accept lever CLOSED");
    config.params.palw_algo4_accept = true;

    let (tc, handles, f) = palw_algo4_env_infer(1, None, Some(config)).await;
    let algo4 = mint_algo4(&tc, &f, 0xf0, 0, |_| {});
    let algo4_hash = algo4.header.hash;
    let insert_status = tc.validate_and_insert_block(algo4.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(
        insert_status,
        BlockStatus::StatusUTXOValid,
        "the shipped DEVNET_PALW_PARAMS preset must accept a mock-k2 algo-4 proof-of-LLM block"
    );

    // The merging child pays the provider pair (§17.1 ReplicaPalw 77% base split A/B).
    let child_hash = kaspa_hashes::Hash64::from_bytes([0xf1; 64]);
    let child = tc.build_utxo_valid_block_with_parents(child_hash, vec![algo4_hash], f.miner.clone(), vec![]);
    let child_coinbase = child.transactions[0].clone();
    let status = tc.validate_and_insert_block(child.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(status, BlockStatus::StatusUTXOValid, "the block merging the algo-4 source must be accepted");
    let outputs_to = |s: &ScriptPublicKey| child_coinbase.outputs.iter().filter(|o| &o.script_public_key == s).count();
    let credited = |s: &ScriptPublicKey| child_coinbase.outputs.iter().filter(|o| &o.script_public_key == s).map(|o| o.value).sum::<u64>();
    assert_eq!(outputs_to(&f.prov_a), 1, "provider A paid by exactly one output");
    assert_eq!(outputs_to(&f.prov_b), 1, "provider B paid by exactly one output");
    let (out_a, out_b) = (credited(&f.prov_a), credited(&f.prov_b));
    assert!(out_a > 0 && out_b > 0, "both provider rewards non-zero (A={out_a} B={out_b})");
    assert!(out_a.abs_diff(out_b) <= 1, "§17.1 base splits evenly A/B (A={out_a} B={out_b})");

    tc.shutdown(handles);
}

/// kaspa-pq **ADR-0040 P1-6 / AUTH-02 — the re-mint attack, reproduced and then closed.**
///
/// # The attack
///
/// A winning algo-4 header DISCLOSES its raw `ticket_nullifier` (I-13 secrecy ends at mint), and
/// `eligibility_hash` binds no block content. So an OBSERVER of a winning block could previously
/// restamp the same winning draw onto unlimited competing blocks of their own choosing — a
/// consensus-level DoS surface aimed at other people's nodes. That is why this gates T-shared (a
/// network with third parties) and not merely activation.
///
/// # What closes it
///
/// Every algo-4 block must carry an ML-DSA-87 authorization by the leaf's declared ticket authority,
/// binding this block's parents and transaction set. The observer has the nullifier but not the key.
///
/// # Why the attack is reproduced rather than just the fix asserted
///
/// A fix that carries its own attack does not regress: if someone later relaxes clause 7, this test
/// fails as an *attack succeeding*, which reads very differently from a coverage gap.
#[tokio::test]
async fn palw_algo4_reminted_ticket_is_rejected_auth02() {
    use kaspa_consensus_core::errors::block::RuleError;
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_PALW_BLOCK_AUTHORIZATION;

    let (tc, handles, f) = palw_algo4_env(1).await;

    // The legitimate holder mints and the block is accepted.
    let honest = mint_algo4(&tc, &f, 0xf0, 0, |_| {});
    let honest_auth = honest
        .transactions
        .iter()
        .find(|tx| tx.subnetwork_id == SUBNETWORK_ID_PALW_BLOCK_AUTHORIZATION)
        .expect("the honest block carries an authorization")
        .clone();
    assert_eq!(
        tc.validate_and_insert_block(honest.to_immutable()).virtual_state_task.await.unwrap(),
        BlockStatus::StatusUTXOValid,
        "the authorized block is accepted"
    );

    // The attacker now knows everything public: the raw nullifier, the leaf, the chain commit. They
    // build a DIFFERENT block on the same winning draw — a different timestamp, hence a different block.
    // The one thing they cannot do is produce the authority's signature over THEIR block.
    let mut stolen = mint_algo4(&tc, &f, 0xf1, 7, |_| {});
    // Strip the authorization: an observer who never had the key simply has none to attach.
    stolen.transactions.retain(|tx| tx.subnetwork_id != SUBNETWORK_ID_PALW_BLOCK_AUTHORIZATION);
    stolen.header.hash_merkle_root = kaspa_consensus_core::merkle::calc_hash_merkle_root(stolen.transactions.iter());
    stolen.header.finalize();
    match tc.validate_and_insert_block(stolen.to_immutable()).block_task.await {
        Err(RuleError::PalwTicketInvalid(m)) if m.contains("clause 7") => {}
        other => panic!("an unauthorized re-mint must be rejected by clause 7, got {other:?}"),
    }

    // Nor can they REPLAY the honest block's authorization onto their own block: it commits to the
    // honest block's parents and transaction set, so it does not bind theirs.
    let mut replayed = mint_algo4(&tc, &f, 0xf2, 9, |_| {});
    replayed.transactions.retain(|tx| tx.subnetwork_id != SUBNETWORK_ID_PALW_BLOCK_AUTHORIZATION);
    replayed.transactions.push(honest_auth);
    replayed.header.hash_merkle_root = kaspa_consensus_core::merkle::calc_hash_merkle_root(replayed.transactions.iter());
    replayed.header.finalize();
    match tc.validate_and_insert_block(replayed.to_immutable()).block_task.await {
        Err(RuleError::PalwTicketInvalid(m)) if m.contains("clause 7") => {}
        other => panic!("a replayed authorization must not bind a different block, got {other:?}"),
    }

    tc.shutdown(handles);
}

/// kaspa-pq **ADR-0040 P0-3 / gate G1** — the algo-4 ACCEPTANCE lever, pinned two ways.
///
/// 1. Every shipped preset ships `palw_algo4_accept = false`, including the two PALW presets that run
///    `palw_activation_daa_score = 0`. Activation says the lane EXISTS; this says its blocks may ENTER.
/// 2. While the lever is closed, an otherwise-VALID algo-4 block is rejected — the same block that
///    `palw_algo4_devnet_palw_preset_e2e` accepts with the lever open. So the rejection is attributable
///    to the lever alone, not to some other defect in the block.
///
/// Why this matters beyond bookkeeping: algo-4 headers are exempt from the Layer-0 hash floor, and
/// `palw_compute_work_scale = 0` prevents the compute cap from ever firing, so on a PALW preset there is
/// no work-based bound on algo-4 header volume (ADR-0040 DOS-01). This lever is that bound until the
/// gates in ADR-0040 §7.1.1 are released.
#[tokio::test]
async fn palw_algo4_rejected_while_accept_lever_closed() {
    use kaspa_consensus_core::config::params::{
        DEVNET_PALW_PARAMS, DEVNET_PARAMS, MAINNET_PARAMS, SIMNET_PARAMS, TESTNET_PALW_PARAMS, TESTNET_PARAMS,
    };

    // (1) The shipped default is CLOSED on every preset — the PALW ones especially.
    for (name, p) in [
        ("mainnet", MAINNET_PARAMS),
        ("testnet", TESTNET_PARAMS),
        ("simnet", SIMNET_PARAMS),
        ("devnet", DEVNET_PARAMS),
        ("testnet-palw", TESTNET_PALW_PARAMS),
        ("devnet-palw", DEVNET_PALW_PARAMS),
    ] {
        assert!(!p.palw_algo4_accept, "{name} must ship with the ADR-0040 algo-4 accept lever CLOSED");
    }

    // (2) With the lever closed, the very block the sibling e2e accepts is rejected instead.
    let config = ConfigBuilder::new(DEVNET_PALW_PARAMS).build();
    assert!(config.params.is_palw_active(0), "the lane is ACTIVE — only acceptance is withheld");
    assert!(!config.params.palw_algo4_accept);

    let (tc, handles, f) = palw_algo4_env_infer(1, None, Some(config)).await;
    let algo4 = mint_algo4(&tc, &f, 0xf0, 0, |_| {});
    let res = tc.validate_and_insert_block(algo4.to_immutable()).virtual_state_task.await;
    match res {
        Err(kaspa_consensus_core::errors::block::RuleError::PalwAlgo4NotAccepted) => {}
        other => panic!("expected PalwAlgo4NotAccepted while the lever is closed, got {other:?}"),
    }

    tc.shutdown(handles);
}

/// kaspa-pq ADR-0039 P0 — the RUNNING-DAEMON in-node mint mechanism. `Consensus::palw_demo_mint_algo4`
/// (what kaspad's `--palw-demo-mint` invokes) mints an algo-4 block off the sink using the REAL
/// `build_block_template` + real store seeding — NOT the test's `mint_algo4` / `build_utxo_valid_block…`
/// helpers — and the block is accepted through the full pipeline. This exercises the exact code path a live
/// daemon takes, on the shipped `DEVNET_PALW_PARAMS` preset.
#[tokio::test]
async fn palw_demo_mint_algo4_in_node_e2e() {
    use kaspa_consensus_core::config::params::DEVNET_PALW_PARAMS;
    use kaspa_hashes::Hash64;
    let mut config = ConfigBuilder::new(DEVNET_PALW_PARAMS).build();
    // ADR-0040 P0-3: the shipped preset withholds algo-4 acceptance. This test asserts the daemon's mint
    // path works once the gates are released, so it opens the lever explicitly (see
    // `palw_algo4_rejected_while_accept_lever_closed` for the shipped-default pin).
    config.params.palw_algo4_accept = true;
    let tc = TestConsensus::new(&config);
    let handles = tc.init();
    let miner = MinerData::new(p2pkh_mldsa87_spk(&[0x07; 64]), vec![]);
    // Mine an algo-3 v3 supporting chain so a finality-buried anchor exists off the sink.
    let mut parent = config.params.genesis.hash;
    for i in 1u8..=8 {
        let blk = tc.build_utxo_valid_block_with_parents(Hash64::from_bytes([i; 64]), vec![parent], miner.clone(), vec![]);
        let h = blk.header.hash;
        let status = tc.validate_and_insert_block(blk.to_immutable()).virtual_state_task.await.unwrap();
        assert_eq!(status, BlockStatus::StatusUTXOValid, "supporting algo-3 v3 block {i} must validate");
        parent = h;
    }
    // The in-node method seeds the leaf/cert/Active-view and mints the algo-4 block off the sink, all via
    // the real Consensus API — the daemon's exact path.
    let block = tc.palw_demo_mint_algo4(miner.clone()).expect("in-node algo-4 mint");
    assert_eq!(block.header.pow_algo_id, kaspa_consensus_core::pow_layer0::POW_ALGO_ID_PALW_REPLICA, "minted block is algo-4");
    let status = tc.validate_and_insert_block(block).virtual_state_task.await.unwrap();
    assert_eq!(status, BlockStatus::StatusUTXOValid, "the in-node minted algo-4 block must be accepted through the full pipeline");
    tc.shutdown(handles);
}

/// The proof-of-LLM end-to-end on a REAL model: an algo-4 block whose leaf carries the commitments of an
/// ACTUAL Qwen k=2 inference match (not hand-set constants) is accepted by the unmodified pipeline and pays
/// the provider pair. Opt-in — runs only when `PALW_LEAF_FIXTURE` points at a fixture produced by a real
/// k=2 run (so `cargo test` on a machine without a GPU/model just skips it):
///   QWEN_GGUF_PATH=... QWEN_TOKENIZER_PATH=... PALW_LEAF_FIXTURE=/tmp/palw_leaf_fixture.json \
///     cargo run -p misaka-mil-provider --features qwen-metal --bin palw-qwen-demo
///   PALW_LEAF_FIXTURE=/tmp/palw_leaf_fixture.json \
///     cargo test -p kaspa-consensus palw_algo4_real_inference_e2e -- --nocapture
#[tokio::test]
async fn palw_algo4_real_inference_e2e() {
    use kaspa_consensus_core::tx::ScriptPublicKey;
    use kaspa_hashes::Hash64;

    let Ok(fixture_path) = std::env::var("PALW_LEAF_FIXTURE") else {
        eprintln!("[palw_algo4_real_inference_e2e] SKIP — set PALW_LEAF_FIXTURE to a fixture from palw-qwen-demo");
        return;
    };
    let raw = std::fs::read_to_string(&fixture_path).expect("read PALW_LEAF_FIXTURE");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse leaf fixture JSON");
    let hx = |key: &str| -> Hash64 {
        let s = v[key].as_str().unwrap_or_else(|| panic!("fixture missing string field {key}"));
        assert_eq!(s.len(), 128, "field {key} must be 64-byte hex");
        let mut b = [0u8; 64];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
        }
        Hash64::from_bytes(b)
    };
    let infer = LeafInferParams {
        model_profile_id: hx("model_profile_id"),
        runtime_class_id: hx("runtime_class_id"),
        shape_id: v["shape_id"].as_u64().expect("shape_id") as u16,
        quantum_count: v["quantum_count"].as_u64().expect("quantum_count") as u16,
        private_match_commitment: hx("canonical_gemm_trace_root"),
    };
    eprintln!(
        "[palw_algo4_real_inference_e2e] REAL k=2 leaf: model_profile_id={}… runtime_class_id={}… trace_root={}…",
        &v["model_profile_id"].as_str().unwrap()[..16],
        &v["runtime_class_id"].as_str().unwrap()[..16],
        &v["canonical_gemm_trace_root"].as_str().unwrap()[..16],
    );

    let (tc, handles, f) = palw_algo4_env_infer(1, Some(infer), None).await;
    let algo4 = mint_algo4(&tc, &f, 0xf0, 0, |_| {});
    let algo4_hash = algo4.header.hash;
    let insert_status = tc.validate_and_insert_block(algo4.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(
        insert_status,
        BlockStatus::StatusUTXOValid,
        "an algo-4 block whose leaf came from a REAL Qwen k=2 match must be accepted by the full pipeline"
    );

    // The merging child pays the provider pair (ReplicaPalw 77 % base, split A/B).
    let child_hash = Hash64::from_bytes([0xf1; 64]);
    let child = tc.build_utxo_valid_block_with_parents(child_hash, vec![algo4_hash], f.miner.clone(), vec![]);
    let child_coinbase = child.transactions[0].clone();
    let status = tc.validate_and_insert_block(child.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(status, BlockStatus::StatusUTXOValid, "the block merging the real-inference algo-4 source must be accepted");

    let outputs_to = |s: &ScriptPublicKey| child_coinbase.outputs.iter().filter(|o| &o.script_public_key == s).count();
    let credited = |s: &ScriptPublicKey| child_coinbase.outputs.iter().filter(|o| &o.script_public_key == s).map(|o| o.value).sum::<u64>();
    assert_eq!(outputs_to(&f.prov_a), 1, "provider A paid by exactly one output");
    assert_eq!(outputs_to(&f.prov_b), 1, "provider B paid by exactly one output");
    let (out_a, out_b) = (credited(&f.prov_a), credited(&f.prov_b));
    assert!(out_a > 0 && out_b > 0, "both provider rewards non-zero (A={out_a} B={out_b})");
    assert!(out_a.abs_diff(out_b) <= 1, "§17.1 base splits evenly A/B (A={out_a} B={out_b})");
    assert_eq!(credited(&f.miner.script_public_key), 0, "no PALW base leaks to the merging miner");

    eprintln!(
        "[palw_algo4_real_inference_e2e] ✅ algo-4 block {algo4_hash} accepted (StatusUTXOValid); provider pair paid A={out_a} B={out_b} sompi from a REAL 9B-class k=2 inference leaf"
    );
    tc.shutdown(handles);
}

/// K5 §15.3 / §17.4 — the reward rail's anti-double-pay teeth, end to end: a SECOND algo-4 block that
/// reuses an already-live ticket nullifier is colored RED by the REAL GHOSTDAG dedup, and the child that
/// merges both pays the provider pair EXACTLY ONCE — the red duplicate's base is burned by don't-mint,
/// neither paid to the (same) providers a second time nor rerouted to the merging miner. Without this,
/// resubmitting one k=2 leaf's ticket in two blocks would pay its providers twice.
#[tokio::test]
async fn palw_algo4_duplicate_nullifier_red_pays_nothing_e2e() {
    use crate::model::stores::ghostdag::GhostdagStoreReader;
    use kaspa_consensus_core::tx::ScriptPublicKey;
    let (tc, handles, f) = palw_algo4_env(1).await;

    // Two sibling algo-4 blocks off the SAME selected parent, carrying the SAME ticket (identical
    // nullifier/leaf/anchor/chain_commit/eligibility ⇒ both independently win clause 9). They differ ONLY
    // in the template timestamp, hence in block id. Each is individually body-valid and reaches a valid
    // UTXO tip — the dedup fires only where a block MERGES both into one mergeset.
    let x = mint_algo4(&tc, &f, 0xf0, 0, |_| {});
    let y = mint_algo4(&tc, &f, 0xf1, 1, |_| {});
    let (x_hash, y_hash) = (x.header.hash, y.header.hash);
    assert_ne!(x_hash, y_hash, "the two reuses must be distinct blocks");
    assert_eq!(
        tc.validate_and_insert_block(x.to_immutable()).virtual_state_task.await.unwrap(),
        BlockStatus::StatusUTXOValid,
        "the first algo-4 ticket is accepted (it extends the chain, so it is the sink)"
    );
    // Y is a competing NON-sink tip, so its own UTXO state is deferred — the point is it is accepted into
    // the DAG (body-valid, NOT disqualified/invalid); the dedup fires only where a block MERGES both.
    let y_status = tc.validate_and_insert_block(y.to_immutable()).virtual_state_task.await.unwrap();
    assert!(
        matches!(y_status, BlockStatus::StatusUTXOValid | BlockStatus::StatusUTXOPendingVerification),
        "the sibling reuse is body-valid / accepted into the DAG (not disqualified) — got {y_status:?}"
    );

    // A child merging BOTH: GHOSTDAG seeds the active-nullifier set from its selected parent's OWN ticket
    // (whichever sibling wins the blue-work/hash tiebreak) and colors the OTHER sibling RED for reuse.
    let child_hash = kaspa_hashes::Hash64::from_bytes([0xf2; 64]);
    let child = tc.build_utxo_valid_block_with_parents(child_hash, vec![x_hash, y_hash], f.miner.clone(), vec![]);
    let child_coinbase = child.transactions[0].clone();
    assert_eq!(
        tc.validate_and_insert_block(child.to_immutable()).virtual_state_task.await.unwrap(),
        BlockStatus::StatusUTXOValid,
        "the merging child is accepted (construction == validation over the deduped mergeset)"
    );

    // Exactly one sibling is red (the duplicate); the other is the blue selected parent.
    let reds = tc.ghostdag_store().get_mergeset_reds(child_hash).unwrap();
    let blue_sp = tc.ghostdag_store().get_selected_parent(child_hash).unwrap();
    assert_eq!(reds.len(), 1, "exactly one duplicate-ticket sibling is colored red");
    assert!(reds.contains(&x_hash) ^ reds.contains(&y_hash), "the red is exactly one of the two reuses");
    assert!((blue_sp == x_hash || blue_sp == y_hash) && !reds.contains(&blue_sp), "the other reuse is the blue selected parent");

    // The reward: the provider pair is paid EXACTLY ONCE (from the blue), never twice; nothing is
    // rerouted to the merging miner. Same leaf ⇒ same provider scripts, so a double-pay would surface as
    // TWO outputs per provider — `count == 1` is the crisp guard.
    let outputs_to = |s: &ScriptPublicKey| child_coinbase.outputs.iter().filter(|o| &o.script_public_key == s).count();
    let credited = |s: &ScriptPublicKey| child_coinbase.outputs.iter().filter(|o| &o.script_public_key == s).map(|o| o.value).sum::<u64>();
    assert_eq!(outputs_to(&f.prov_a), 1, "provider A is paid by exactly ONE output (the blue), never the red duplicate");
    assert_eq!(outputs_to(&f.prov_b), 1, "provider B is paid by exactly ONE output");
    let (pa, pb) = (credited(&f.prov_a), credited(&f.prov_b));
    assert!(pa > 0 && pb > 0 && pa.abs_diff(pb) <= 1, "the single (blue) payment is the even §17.1 base split (A={pa} B={pb})");
    assert_eq!(credited(&f.miner.script_public_key), 0, "the red duplicate's base is burned, NOT rerouted to the merging miner");

    tc.shutdown(handles);
}

/// K5 §14/§22 — the acceptance-side integrity of the reward rail: an algo-4 ticket that fails a body
/// clause is REJECTED before it can mint a provider payment. Two single-field mutants of the honest
/// ticket, each driven through the REAL `check_palw_ticket` and expected to fail closed:
///   • clause 6 (chain_commit) — the header's chain_commit is flipped off the finality-buried DNS anchor
///     (the I-4 fork-binding that stops a miner grinding chain_commit as a re-roll nonce to steer the
///     draw off the canonical anchor);
///   • clause 9 (eligibility draw) — the nonce is unpinned from `low64(nullifier)`. Clause 9 IS the PALW
///     proof-of-work, so a silent-accept here would mint an unbounded provider reward with no work.
/// The honest twin of both (same construction, no mutation) is the accepted-path test above, so these
/// prove the REJECTION is caused by the mutated field, not an unrelated setup defect.
#[tokio::test]
async fn palw_algo4_invalid_ticket_rejected_e2e() {
    use kaspa_consensus_core::errors::block::RuleError;
    let (tc, handles, f) = palw_algo4_env(1).await;

    // Clause 6: a chain_commit that does not match the value derived from the finality-buried DNS anchor.
    let bad_commit = mint_algo4(&tc, &f, 0xe6, 0, |h| h.palw_chain_commit = kaspa_hashes::Hash64::from_bytes([0xEE; 64]));
    let r6 = tc.validate_and_insert_block(bad_commit.to_immutable()).block_task.await;
    assert!(
        matches!(&r6, Err(RuleError::PalwTicketInvalid(m)) if m.contains("clause 6")),
        "a chain_commit off the finality-buried anchor must be rejected at clause 6, got {r6:?}"
    );

    // Clause 9: break the nonce == low64(nullifier) pin so the one-shot eligibility draw no longer wins.
    let bad_draw = mint_algo4(&tc, &f, 0xe9, 0, |h| h.nonce ^= 1);
    let r9 = tc.validate_and_insert_block(bad_draw.to_immutable()).block_task.await;
    assert!(
        matches!(&r9, Err(RuleError::PalwTicketInvalid(m)) if m.contains("clause 9")),
        "an eligibility draw that does not satisfy the PALW proof-of-work must be rejected at clause 9, got {r9:?}"
    );

    // Clause 5: the header's target interval no longer equals its DAA position (`daa_score !=
    // target_daa_interval`) — the bind that pins the draw + chain_commit to the block's real DAA slot.
    let bad_interval = mint_algo4(&tc, &f, 0xe5, 0, |h| h.palw_target_daa_interval = h.palw_target_daa_interval.wrapping_add(1));
    let r5 = tc.validate_and_insert_block(bad_interval.to_immutable()).block_task.await;
    assert!(
        matches!(&r5, Err(RuleError::PalwTicketInvalid(m)) if m.contains("IntervalMismatch")),
        "a target interval != daa_score must be rejected at clause 5 (IntervalMismatch), got {r5:?}"
    );

    tc.shutdown(handles);
}

/// Build a PALW-active env, apply a batch-lifecycle / leaf / cert seeding override (read-modify-write on
/// the honest seed), mint an OTHERWISE HONEST algo-4 block, and assert `check_palw_ticket` rejects it with
/// a `PalwTicketInvalid` message containing `expect_substr`. The no-override run of the same construction
/// is the accepted-path test, so the rejection is attributable to the seeded override, not a setup defect.
async fn palw_algo4_expect_ticket_reject(apply: impl FnOnce(&TestConsensus, &PalwAlgo4Facts), expect_substr: &str) {
    palw_algo4_expect_ticket_reject_full(apply, None, expect_substr).await
}

/// ADR-0040 P1-1 variant: shape the leaf BEFORE it is sealed into the write-once store (see
/// `palw_algo4_env_full`). Used by clauses whose rejection depends on leaf CONTENT rather than on
/// fork-relative view state.
async fn palw_algo4_expect_ticket_reject_full(
    apply: impl FnOnce(&TestConsensus, &PalwAlgo4Facts),
    leaf_edit: Option<&(dyn Fn(&mut kaspa_consensus_core::palw::PalwPublicLeafV1) + Sync)>,
    expect_substr: &str,
) {
    use kaspa_consensus_core::errors::block::RuleError;
    let (tc, handles, f) = palw_algo4_env_full(1, None, None, leaf_edit).await;
    apply(&tc, &f);
    let mb = mint_algo4(&tc, &f, 0xf0, 0, |_| {});
    let res = tc.validate_and_insert_block(mb.to_immutable()).block_task.await;
    assert!(
        matches!(&res, Err(RuleError::PalwTicketInvalid(m)) if m.contains(expect_substr)),
        "expected PalwTicketInvalid containing {expect_substr:?}, got {res:?}"
    );
    tc.shutdown(handles);
}

/// K5 §18.2 (rank 6) — a REVOKED batch pays nothing: the fork-relative view gate (`resolvable_batch` →
/// `is_block_eligible_at`) rejects an algo-4 ticket whose batch was revoked, before any leaf/cert clause.
/// This is the batch-lifecycle double-pay guard: a batch the audit rail pulled must never mint a payment.
#[tokio::test]
async fn palw_algo4_revoked_batch_rejected_e2e() {
    palw_algo4_expect_ticket_reject(
        |tc, f| {
            let mut v = (*tc.storage.palw_overlay_view_store.view(f.sp).unwrap().expect("seeded view")).clone();
            v.batches.get_mut(&f.batch_id).unwrap().revoked_from_daa = Some(1);
            tc.storage.palw_overlay_view_store.set(f.sp, std::sync::Arc::new(v)).unwrap();
        },
        "not block-eligible",
    )
    .await;
}

/// K5 §18.2 (rank 6) — an EXPIRED batch pays nothing: with `expiry_epoch <= epoch(B)` the view's
/// `advance_epoch_gated` flips the batch to `Expired`, so `resolvable_batch` returns `None` and the
/// ticket is rejected at the view gate.
#[tokio::test]
async fn palw_algo4_expired_batch_rejected_e2e() {
    palw_algo4_expect_ticket_reject(
        |tc, f| {
            let mut v = (*tc.storage.palw_overlay_view_store.view(f.sp).unwrap().expect("seeded view")).clone();
            v.batches.get_mut(&f.batch_id).unwrap().expiry_epoch = 0;
            tc.storage.palw_overlay_view_store.set(f.sp, std::sync::Arc::new(v)).unwrap();
        },
        "not block-eligible",
    )
    .await;
}

/// K5 §14.2 (rank 9, clause 3) — a leaf whose active window is closed at epoch(B) is rejected
/// (`LeafNotActive`): `verify_palw_ticket_store_facts` requires `leaf.activation_epoch <= epoch <
/// leaf.expiry_epoch`. Guards against paying for a leaf outside its published validity window.
#[tokio::test]
async fn palw_algo4_leaf_not_active_rejected_e2e() {
    // ADR-0040 P1-1: leaves are write-once, so the closed window is seeded BEFORE the first write rather
    // than patched in afterwards. The nullifier commitment is untouched, so clause 1 still passes and the
    // FIRST failing clause is 3 — the property this test is actually about.
    palw_algo4_expect_ticket_reject_full(|_tc, _f| {}, Some(&|l: &mut kaspa_consensus_core::palw::PalwPublicLeafV1| l.expiry_epoch = 0), "LeafNotActive").await;
}

/// K5 §14.2 (rank 9, clause 4) — a certificate whose active window has not opened at epoch(B) is rejected
/// (`CertNotActive`): the cert blob the header's `epoch_certificate_hash` resolves to must satisfy
/// `cert.activation_epoch <= epoch < cert.expiry_epoch`. Guards against paying for a batch whose
/// certificate had not yet activated (or had expired).
#[tokio::test]
async fn palw_algo4_cert_not_active_rejected_e2e() {
    use crate::model::stores::palw::{PalwStore, PalwStoreReader};
    palw_algo4_expect_ticket_reject(
        |tc, f| {
            // Push the cert blob's activation past epoch(B)=0. The header/view still reference the same
            // cert_hash (the store is keyed by the given hash), and the view's own cert window stays open,
            // so the view gate passes and clause 4 is the failing clause.
            let mut c = (*tc.storage.palw_store.certificate(f.cert_hash).unwrap()).clone();
            c.activation_epoch = 999;
            tc.storage.palw_store.insert_certificate(f.cert_hash, std::sync::Arc::new(c)).unwrap();
        },
        "CertNotActive",
    )
    .await;
}

/// K5 §15.2 — the anti-replay-ACROSS-THE-DAG guarantee that the PERSISTENT active-nullifier window
/// exists to provide: a ticket nullifier BURIED in the selected-parent past (NOT in the current
/// mergeset) is still recolored red when reused. This is a distinct code path from the within-mergeset
/// dedup: here the reusing block's merger has an algo-3 selected parent with NO ticket of its own, so the
/// nullifier is active ONLY via the window carried down the chain (protocol.rs `store.get(sp).merge_from`,
/// not the SP-own-ticket seed). The leaf's providers are paid ONCE by the honest chain and the buried
/// reuse earns nothing.
#[tokio::test]
async fn palw_algo4_buried_nullifier_window_recolors_reuse_e2e() {
    use crate::model::stores::ghostdag::GhostdagStoreReader;
    use crate::model::stores::palw_nullifier::PalwNullifierStoreReader;
    use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction};
    let (tc, handles, f) = palw_algo4_env(1).await;

    // A: the first algo-4 block mints nullifier N (accepted, the sink). A1: an algo-3 v3 block on top of A
    // — folding N into the PERSISTED window so it is buried in A1's selected-parent past. A1 is also the
    // CONTROL: its coinbase pays the leaf's providers exactly once (A is its blue selected parent).
    let a = mint_algo4(&tc, &f, 0xa0, 0, |_| {});
    let a_hash = a.header.hash;
    assert_eq!(
        tc.validate_and_insert_block(a.to_immutable()).virtual_state_task.await.unwrap(),
        BlockStatus::StatusUTXOValid,
        "A (mints N) is accepted"
    );
    // On this max-easy SIMNET config every block's blue_work is a flat floor (work does not accumulate
    // with depth), so a merger's selected parent is decided purely by the SortableBlock hash tiebreak
    // (`max` by blue_work THEN hash). Give A1 the maximum possible hash so it DETERMINISTICALLY wins that
    // tiebreak over B's content-derived hash — making A1 (an algo-3 block with NO own ticket) P's selected
    // parent, so the reuse can only be caught by the persisted window seed (the path under test).
    let a1_hash = kaspa_hashes::Hash64::from_bytes([0xff; 64]);
    let a1 = tc.build_utxo_valid_block_with_parents(a1_hash, vec![a_hash], f.miner.clone(), vec![]);
    let a1_coinbase = a1.transactions[0].clone();
    assert_eq!(
        tc.validate_and_insert_block(a1.to_immutable()).virtual_state_task.await.unwrap(),
        BlockStatus::StatusUTXOValid,
        "A1 (buries N into the persisted window) is accepted"
    );
    assert!(tc.storage.palw_nullifier_store.get(a1_hash).unwrap().contains(&f.nullifier), "A1's window carries the buried nullifier N");
    assert!(tc.storage.palw_nullifier_store.get(a_hash).unwrap().is_empty(), "A's own window is empty (N enters descendants' windows)");

    // B: a sibling algo-4 block off `sp` that REUSES N. Individually body-valid (empty own mergeset).
    let b = mint_algo4(&tc, &f, 0xb0, 1, |_| {});
    let b_hash = b.header.hash;
    let b_status = tc.validate_and_insert_block(b.to_immutable()).virtual_state_task.await.unwrap();
    assert!(
        matches!(b_status, BlockStatus::StatusUTXOValid | BlockStatus::StatusUTXOPendingVerification),
        "B (buried-N reuse) is body-valid / accepted into the DAG — got {b_status:?}"
    );

    // P merges {A1, B}: selected parent A1 (algo-3, NO own ticket), B in the mergeset. N is active ONLY via
    // window(A1) ⇒ B is recolored RED purely by the persisted window. A DISTINCT miner for P isolates the
    // no-reroute check from A1's legitimate hash-lane reward (which flows to the harness miner script).
    let p_miner = MinerData::new(p2pkh_mldsa87_spk(&[0x0e; 64]), vec![]);
    let p_hash = kaspa_hashes::Hash64::from_bytes([0xcc; 64]);
    let p = tc.build_utxo_valid_block_with_parents(p_hash, vec![a1_hash, b_hash], p_miner.clone(), vec![]);
    let p_coinbase = p.transactions[0].clone();
    assert_eq!(
        tc.validate_and_insert_block(p.to_immutable()).virtual_state_task.await.unwrap(),
        BlockStatus::StatusUTXOValid,
        "P (merges the buried reuse) is accepted"
    );

    let p_reds = tc.ghostdag_store().get_mergeset_reds(p_hash).unwrap();
    assert!(p_reds.contains(&b_hash), "the buried-nullifier reuse B is recolored red via the persisted window");
    assert_eq!(
        tc.ghostdag_store().get_selected_parent(p_hash).unwrap(),
        a1_hash,
        "P's selected parent is the algo-3 chain tip (it has NO own ticket — the seed is the window alone)"
    );

    // Anti-replay: the leaf's providers are paid ONCE (by the control A1); the buried reuse pays nothing,
    // and its base is not rerouted to P's (distinct) miner.
    let credited = |cb: &Transaction, s: &ScriptPublicKey| cb.outputs.iter().filter(|o| &o.script_public_key == s).map(|o| o.value).sum::<u64>();
    assert!(
        credited(&a1_coinbase, &f.prov_a) > 0 && credited(&a1_coinbase, &f.prov_b) > 0,
        "control: A1 pays the leaf's providers once (A is its blue selected parent)"
    );
    assert_eq!(credited(&p_coinbase, &f.prov_a), 0, "the buried-ticket reuse pays provider A nothing");
    assert_eq!(credited(&p_coinbase, &f.prov_b), 0, "the buried-ticket reuse pays provider B nothing");
    assert_eq!(credited(&p_coinbase, &p_miner.script_public_key), 0, "the red reuse's base is not rerouted to the merging miner");

    tc.shutdown(handles);
}

/// K5 §11.3 (active-path halt teeth): the SAME algo-4 block, but with `grace_epochs == 0` so its
/// epoch-0 beacon is HALTED, is DISQUALIFIED from the chain by the S2 `PalwLaneHalted` rule — while the
/// permanent algo-3 hash lane keeps validating (a sibling on the same tip reaches a valid UTXO tip).
/// This proves the compute lane actually closes under a halted beacon; the DegradedGrace acceptance +
/// payment path is the sibling test above.
#[tokio::test]
async fn palw_algo4_halted_epoch_disqualified_e2e() {
    let (tc, handles, algo4_hash, sp, _prov_a, _prov_b, miner, _insert_status) = palw_algo4_e2e_build(0).await;

    // The algo-4 block cleared header/ghostdag/body (clauses 1-9; clause 10's buried samples are empty
    // because degraded seeds are the zero bootstrap, so it does not fire), then S2 rejected it for a
    // Halted own-epoch mode ⇒ StatusDisqualifiedFromChain (body-valid, chain-invalid, stays in the DAG).
    assert_eq!(
        tc.block_status(algo4_hash),
        BlockStatus::StatusDisqualifiedFromChain,
        "a Halted-epoch algo-4 block must be disqualified from the chain (S2 PalwLaneHalted)"
    );

    // §11.3: the hash lane continues. An algo-3 v3 sibling on the same tip is still UTXO-valid.
    let sibling = tc.build_utxo_valid_block_with_parents(kaspa_hashes::Hash64::from_bytes([0xf2; 64]), vec![sp], miner.clone(), vec![]);
    let sib_status = tc.validate_and_insert_block(sibling.to_immutable()).virtual_state_task.await.unwrap();
    assert_eq!(sib_status, BlockStatus::StatusUTXOValid, "the algo-3 hash lane continues while the compute lane is halted");

    tc.shutdown(handles);
}

/// K5 §11.3/§17.4 — the ReplicaPalwHalted zero-pay reward gate through the FULL pipeline: an algo-4 block
/// minted under a Halted beacon is S2-disqualified (but stays body-valid in the DAG), and a child that
/// MERGES it reaches a valid UTXO tip while paying the halted source's providers NOTHING — compute minted
/// under an untrusted beacon earns no reward (`WorkRewardClass::ReplicaPalwHalted`, keyed on the source's
/// own halted epoch). The halted-disqualification test above stops at S2 and never builds a merger, so
/// this is the only place the ReplicaPalwHalted coinbase arm is reached through the real classify→coinbase
/// path (its amounts are unit-tested in processes/coinbase.rs).
#[tokio::test]
async fn palw_algo4_halted_source_merged_pays_nothing_e2e() {
    use crate::model::stores::ghostdag::GhostdagStoreReader;
    use kaspa_consensus_core::tx::ScriptPublicKey;
    let (tc, handles, f) = palw_algo4_env(0).await;

    // The halted algo-4 block: body-valid, S2-disqualified (Halted own epoch).
    let halted = mint_algo4(&tc, &f, 0xf0, 0, |_| {});
    let halted_hash = halted.header.hash;
    assert_eq!(
        tc.validate_and_insert_block(halted.to_immutable()).virtual_state_task.await.unwrap(),
        BlockStatus::StatusDisqualifiedFromChain,
        "the Halted-epoch algo-4 block is disqualified from the chain (S2 PalwLaneHalted)"
    );

    // A valid algo-3 hash-lane block on `sp`, given the maximum hash so it DETERMINISTICALLY wins the
    // SortableBlock tiebreak (blue_work is a flat floor here) ⇒ the merger's selected parent is this valid
    // block, never the disqualified one (which could otherwise become the SP and disqualify the merger).
    let good_hash = kaspa_hashes::Hash64::from_bytes([0xff; 64]);
    let good = tc.build_utxo_valid_block_with_parents(good_hash, vec![f.sp], f.miner.clone(), vec![]);
    assert_eq!(
        tc.validate_and_insert_block(good.to_immutable()).virtual_state_task.await.unwrap(),
        BlockStatus::StatusUTXOValid,
        "the algo-3 hash lane continues under a halted compute lane"
    );

    // The merger: selected parent = the valid hash-lane block, halted algo-4 in the mergeset. It reaches a
    // valid UTXO tip (merging a disqualified-but-body-valid block is fine) and its coinbase classifies the
    // halted source ReplicaPalwHalted ⇒ the providers are paid nothing.
    let merger_hash = kaspa_hashes::Hash64::from_bytes([0xcc; 64]);
    let merger = tc.build_utxo_valid_block_with_parents(merger_hash, vec![good_hash, halted_hash], f.miner.clone(), vec![]);
    let merger_coinbase = merger.transactions[0].clone();
    assert_eq!(
        tc.validate_and_insert_block(merger.to_immutable()).virtual_state_task.await.unwrap(),
        BlockStatus::StatusUTXOValid,
        "the child merging the halted source is accepted"
    );

    // The halted source is genuinely in the merger's mergeset (so the zero payment is the reward gate
    // firing, not the block being absent), and the merger's selected parent is the valid hash-lane block.
    let merger_gd = tc.ghostdag_store().get_data(merger_hash).unwrap();
    assert_eq!(merger_gd.selected_parent, good_hash, "the merger's selected parent is the valid hash-lane block, not the disqualified source");
    assert!(
        merger_gd.mergeset_blues.contains(&halted_hash) || merger_gd.mergeset_reds.contains(&halted_hash),
        "the halted algo-4 source is in the merger's mergeset (merged, then classified ReplicaPalwHalted)"
    );

    let credited = |s: &ScriptPublicKey| merger_coinbase.outputs.iter().filter(|o| &o.script_public_key == s).map(|o| o.value).sum::<u64>();
    assert_eq!(credited(&f.prov_a), 0, "the halted source pays provider A nothing (ReplicaPalwHalted reward gate)");
    assert_eq!(credited(&f.prov_b), 0, "the halted source pays provider B nothing (ReplicaPalwHalted reward gate)");

    tc.shutdown(handles);
}
