//! ADR-0039 P0 — **devnet-palw ONLY** in-node "mint one algo-4 proof-of-LLM block" path for a LIVE
//! running kaspad. This is the running-daemon twin of the in-process E2E
//! (`palw_algo4_devnet_palw_preset_e2e`): it seeds a **mock-k=2** leaf / certificate / Active-view into the
//! real consensus stores off the current sink, then mints an algo-4 (replica-lane) block off the sink via
//! the real template builder and returns it ready to submit through the normal pipeline. Consensus treats
//! the inference leaf as **opaque** (never re-runs the model), so a mock leaf is indistinguishable to the
//! validator; the `DegradedGrace` beacon path accepts the block with no live DNS quorum. NOT real value
//! (throwaway devnet, seeded stores, mock inference). The caller submits the returned block and awaits its
//! `validate_and_insert_block` future.

use std::sync::Arc;

use kaspa_consensus_core::{
    api::ConsensusApi,
    block::{Block, TemplateBuildMode, TemplateTransactionSelector},
    coinbase::MinerData,
    config::params::{DEVNET_PALW_PARAMS, TESTNET_PALW_PARAMS},
    dns_finality::p2pkh_mldsa87_spk,
    header::PalwHeaderFields,
    palw::{
        BeaconDnsAnchor, PalwBatchCertificateV1, PalwBatchLifecycleV1, PalwBatchStatus, PalwBatchViewV1, PalwPublicLeafV1,
        chain_commit, dns_finality_certificate_hash_v1, eligibility_hash, palw_eligibility_win, ticket_nullifier_commitment,
    },
    pow_layer0::POW_ALGO_ID_PALW_REPLICA,
    tx::{Transaction, TransactionId, TransactionOutpoint},
};
use kaspa_hashes::Hash64;

use super::Consensus;
use crate::{
    model::stores::{headers::HeaderStoreReader, palw::PalwStore},
    processes::palw::resolve_palw_lagged_anchor,
};

/// Yields the fixed tx set once (here always empty ⇒ coinbase-only), then drains so the builder's
/// re-selection loop terminates.
struct OnceSelector(Option<Vec<Transaction>>);
impl TemplateTransactionSelector for OnceSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        self.0.take().unwrap_or_default()
    }
    fn reject_selection(&mut self, _tx_id: TransactionId) {}
    fn is_successful(&self) -> bool {
        true
    }
}

impl Consensus {
    /// See module docs. Errors (as a String) if not the devnet-palw preset, or if no finality-buried DNS
    /// anchor exists off the sink yet (mine more supporting blocks first).
    pub(crate) fn palw_demo_mint_algo4_impl(&self, miner_data: MinerData) -> Result<Block, String> {
        // Gate: PALW-active demo nets only (devnet-palw or testnet-palw).
        let net = self.config.params.net;
        if net != DEVNET_PALW_PARAMS.net && net != TESTNET_PALW_PARAMS.net {
            return Err(format!("palw_demo_mint_algo4 is devnet-palw / testnet-palw only (net = {net:?})"));
        }
        let net_id = self.config.params.net.suffix().unwrap_or(0);
        let replica_bits = self.config.params.palw_lane_difficulty.genesis_replica_bits;
        let dns_params = self.config.params.dns_params.clone().ok_or("devnet-palw preset has no dns_params")?;

        let sink = self.get_sink();
        // Resolve the SAME finality-buried anchor the body check will (burial-only: headers + reachability).
        let anchor = resolve_palw_lagged_anchor(&self.storage.headers_store, &self.services.reachability_service, &dns_params, sink)
            .ok_or("no finality-buried DNS anchor off the sink yet — mine more algo-3 supporting blocks first")?;
        let anchor_header = self.storage.headers_store.get_header(anchor.anchor_hash).map_err(|e| format!("anchor header: {e:?}"))?;
        let anchor_facts = BeaconDnsAnchor {
            hash: anchor.anchor_hash,
            blue_score: anchor.anchor_blue_score,
            daa_score: anchor.anchor_daa_score,
            overlay_root: anchor_header.overlay_commitment_root,
        };
        let eligibility_beacon = anchor_header.palw_beacon_seed; // clause-9 lagged R_E

        // Fixed devnet provider reward scripts (standard P2PKH ML-DSA class so the coinbase can pay them).
        let prov_a = p2pkh_mldsa87_spk(&[0xa0; 64]);
        let prov_b = p2pkh_mldsa87_spk(&[0xb0; 64]);
        let batch_id = Hash64::from_bytes([0x42; 64]);
        let leaf_index = 0u32;
        let proof_type = 1u8;
        let make_leaf = |commit: Hash64| PalwPublicLeafV1 {
            version: 1,
            batch_id,
            leaf_index,
            job_nullifier: Hash64::from_bytes([9; 64]),
            ticket_nullifier_commitment: commit,
            model_profile_id: Hash64::from_bytes([1; 64]),
            runtime_class_id: Hash64::from_bytes([2; 64]),
            shape_id: 1,
            quantum_count: 1,
            proof_type,
            provider_a_bond: TransactionOutpoint::new(Hash64::from_bytes([6; 64]), 0),
            provider_b_bond: TransactionOutpoint::new(Hash64::from_bytes([7; 64]), 0),
            provider_a_reward_script: prov_a.clone(),
            provider_b_reward_script: prov_b.clone(),
            ticket_authority_pk_hash: Hash64::from_bytes([8; 64]),
            private_match_commitment: Hash64::default(),
            receipt_da_root: Hash64::default(),
            registered_epoch: 0,
            activation_epoch: 0,
            expiry_epoch: 1000,
            leaf_bond_sompi: 0,
        };

        // Throwaway template off the sink to read the GHOSTDAG-fixed target interval (== daa_score).
        let tmpl0 = self
            .build_block_template(miner_data.clone(), Box::new(OnceSelector(Some(vec![]))), TemplateBuildMode::Infallible)
            .map_err(|e| format!("target-interval template: {e:?}"))?;
        let target_interval = tmpl0.block.header.daa_score;
        let expected_chain_commit =
            chain_commit(&anchor_facts.hash, &dns_finality_certificate_hash_v1(&anchor_facts), target_interval, net_id);

        // Grind the ticket nullifier so the clause-9 eligibility draw wins (max-easy bits ⇒ a few tries).
        let (nullifier, nonce) = {
            let mut b: u16 = 1;
            loop {
                let cand = Hash64::from_bytes([b as u8; 64]);
                let leaf = make_leaf(ticket_nullifier_commitment(&cand));
                let leaf_hash = leaf.leaf_hash();
                let digest = eligibility_hash(
                    net_id,
                    &eligibility_beacon,
                    &expected_chain_commit,
                    target_interval,
                    &batch_id,
                    leaf_index,
                    &leaf_hash,
                    &cand,
                );
                let cb = cand.as_byte_slice();
                let nonce = u64::from_le_bytes([cb[0], cb[1], cb[2], cb[3], cb[4], cb[5], cb[6], cb[7]]);
                if palw_eligibility_win(&digest, replica_bits, nonce, &cand) {
                    break (cand, nonce);
                }
                b += 1;
                if b >= 256 {
                    return Err("eligibility grind exhausted (target unexpectedly hard)".into());
                }
            }
        };

        // Seed the leaf + certificate content + a directly-Active batch view at the sink (== the algo-4
        // block's selected parent, which the body-stage ticket check reads).
        let leaf = make_leaf(ticket_nullifier_commitment(&nullifier));
        self.storage.palw_store.insert_leaf(batch_id, leaf_index, Arc::new(leaf)).map_err(|e| format!("insert_leaf: {e:?}"))?;
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
            votes: vec![],
        };
        let cert_hash = cert.hash();
        self.storage.palw_store.insert_certificate(cert_hash, Arc::new(cert)).map_err(|e| format!("insert_certificate: {e:?}"))?;
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
                revoked_from_daa: None,
            },
        );
        self.storage.palw_overlay_view_store.set(sink, Arc::new(view)).map_err(|e| format!("set overlay view: {e:?}"))?;

        // Mint: fresh template off the sink, restamp as algo-4 + ticket fields, keeping the GHOSTDAG-derived
        // component work + the template-stamped beacon seed (S2 re-derives & authenticates both).
        let mut mb = self
            .build_block_template(miner_data, Box::new(OnceSelector(Some(vec![]))), TemplateBuildMode::Infallible)
            .map_err(|e| format!("algo-4 template: {e:?}"))?
            .block;
        let keep_hash_work = mb.header.blue_hash_work;
        let keep_compute_work = mb.header.blue_compute_work;
        let keep_beacon_seed = mb.header.palw_beacon_seed;
        mb.header.pow_algo_id = POW_ALGO_ID_PALW_REPLICA;
        mb.header.bits = replica_bits;
        mb.header.nonce = nonce;
        mb.header = mb.header.with_palw_fields(PalwHeaderFields {
            blue_hash_work: keep_hash_work,
            blue_compute_work: keep_compute_work,
            palw_beacon_seed: keep_beacon_seed,
            palw_batch_id: batch_id,
            palw_leaf_index: leaf_index,
            palw_ticket_nullifier: nullifier,
            palw_epoch_certificate_hash: cert_hash,
            palw_chain_commit: expected_chain_commit,
            palw_target_daa_interval: target_interval,
            palw_authorization_hash: Hash64::default(),
            palw_proof_type: proof_type,
        }); // with_palw_fields re-finalizes header.hash over the full v3 preimage
        Ok(mb.to_immutable())
    }

    /// Devnet-palw only: fixed placeholder provider scripts are used, so the caller supplies only a miner
    /// address. Convenience for the kaspad demo task.
    pub(crate) fn palw_demo_miner_data() -> MinerData {
        MinerData::new(p2pkh_mldsa87_spk(&[0x07; 64]), vec![])
    }
}
