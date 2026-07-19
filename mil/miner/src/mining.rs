//! PALW continuous-mining core (ADR-0039 §12) — the deterministic BODY of the algo-4 loop.
//!
//! An algo-4 block is won by a TICKET, not by hashing: a leaf is block-eligible for exactly one DAA
//! interval iff its one-shot draw `eligibility_hash(...)` clears the lane target, and the header nonce
//! is PINNED to the ticket nullifier (`nonce == low64(nullifier)`, I-3) so it is not a separate knob.
//! The only mining freedom is therefore the raw ticket nullifier itself — which the ticket authority
//! (for self-mining, the node's own key) grinds. This module is that grind plus the batch orchestration
//! that ties the Phase-4b producers (provider-bond → manifest → leaf-chunk → certificate) into one
//! self-contained "stand up a batch and win its first ticket" round.
//!
//! Everything here is pure and deterministic. The LIVE loop bindings — read the finality-buried DNS
//! anchor for the beacon seed + `chain_commit`, take the GHOSTDAG-fixed `target_daa_interval` off a
//! block template, submit the payloads as PALW TXs, and submit the minted algo-4 block — are the node's
//! job (Phase 5). This module gives that loop its brain and proves the whole round in-process against
//! the real consensus validators + the real `palw_eligibility_win` draw.

use kaspa_consensus_core::palw::{PalwPublicLeafV1, eligibility_hash, palw_eligibility_win, ticket_nullifier_commitment};
use kaspa_hashes::{Hash64, blake2b_512_keyed};

/// Miner-local domain for deriving a ticket authority's candidate nullifier sequence. NOT a consensus
/// input — the nullifier is just a `Hash64` the ticket holder picks; consensus only checks the draw
/// and the leaf's `ticket_nullifier_commitment`. Keyed so a holder's stream is reproducible by the
/// holder yet unpredictable to a third party reading the on-chain leaf (I-13 winner secrecy).
const TICKET_NULLIFIER_DOMAIN: &[u8] = b"misaka-palw-miner-ticket-v1";

/// The frozen per-block draw inputs a Header v3 binds (design §12.3), resolved from the finality-buried
/// DNS anchor (`beacon_seed`, the lagged `R_E`), the checkpoint (`chain_commit`), and the
/// GHOSTDAG-fixed target interval. In the live loop these come from the anchor header + a throwaway
/// template (see `palw_demo_mint_algo4_impl`); here they are the caller-supplied context.
#[derive(Clone, Debug)]
pub struct EligibilityContext {
    pub network_id: u32,
    /// The anchor's `palw_beacon_seed` (clause-9 lagged `R_E`).
    pub beacon_seed: Hash64,
    /// `chain_commit(anchor, dns_cert, target_interval, net)` — the checkpoint the header commits to.
    pub chain_commit: Hash64,
    /// The GHOSTDAG-fixed DAA interval this draw targets (must equal the minted header's `daa_score`).
    pub target_daa_interval: u64,
    /// The lane difficulty (`bits`) the draw clears (`genesis_replica_bits` at genesis).
    pub replica_bits: u32,
}

/// A ticket whose raw nullifier makes the clause-9 draw win for a specific leaf.
#[derive(Clone, Debug)]
pub struct WinningTicket {
    /// Disclosed in the winning header (`palw_ticket_nullifier`); the leaf published only its commitment.
    pub raw_nullifier: Hash64,
    /// The header nonce, pinned to `low64(raw_nullifier)` (I-3).
    pub nonce: u64,
    /// The leaf carrying `ticket_nullifier_commitment(raw_nullifier)` — the on-chain ticket.
    pub leaf: PalwPublicLeafV1,
    pub leaf_hash: Hash64,
    /// 1-based number of candidates tried before this win (for logging / difficulty telemetry).
    pub tries: u64,
}

/// `low64(nullifier)` — the canonical algo-4 nonce the draw pins to the nullifier (I-3, non-grindable).
/// Mirrors the consensus `digest_low_u64` so a minted header's nonce matches `palw_eligibility_win`.
#[inline]
pub fn pinned_nonce(nullifier: &Hash64) -> u64 {
    let b = nullifier.as_byte_slice();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// A ticket authority's deterministic candidate-nullifier stream for one leaf: `candidate_i =
/// H_k(ticket-domain, secret ‖ i)`. Reproducible by the holder (same `secret`), unpredictable to a
/// third party (I-13). Feed to [`grind_eligibility`].
pub fn nullifier_sequence(secret: &[u8], count: u64) -> impl Iterator<Item = Hash64> + '_ {
    (0..count).map(move |i| {
        let mut p = Vec::with_capacity(secret.len() + 8);
        p.extend_from_slice(secret);
        p.extend_from_slice(&i.to_le_bytes());
        blake2b_512_keyed(TICKET_NULLIFIER_DOMAIN, &p)
    })
}

/// Grind the ticket nullifier until the clause-9 eligibility DRAW wins for `base_leaf`.
///
/// Only the nullifier varies: for each candidate its commitment is swapped into a clone of `base_leaf`
/// (so the expensive k=2 inference that minted `base_leaf` runs ONCE, not per candidate), the leaf hash
/// + `eligibility_hash` are recomputed, and the pinned nonce `low64(nullifier)` is checked against the
/// lane target via [`palw_eligibility_win`]. Returns the first winner, or `None` if `candidates` is
/// exhausted (the caller widens the search or waits for the next interval). Pure + deterministic — a
/// validator re-running the draw over the returned `(leaf, nullifier)` gets the identical verdict.
pub fn grind_eligibility(
    ctx: &EligibilityContext,
    base_leaf: &PalwPublicLeafV1,
    candidates: impl IntoIterator<Item = Hash64>,
) -> Option<WinningTicket> {
    for (i, raw) in candidates.into_iter().enumerate() {
        let mut leaf = base_leaf.clone();
        leaf.ticket_nullifier_commitment = ticket_nullifier_commitment(&raw);
        let leaf_hash = leaf.leaf_hash();
        let digest = eligibility_hash(
            ctx.network_id,
            &ctx.beacon_seed,
            &ctx.chain_commit,
            ctx.target_daa_interval,
            &leaf.batch_id,
            leaf.leaf_index,
            &leaf_hash,
            &raw,
        );
        let nonce = pinned_nonce(&raw);
        if palw_eligibility_win(&digest, ctx.replica_bits, nonce, &raw) {
            return Some(WinningTicket { raw_nullifier: raw, nonce, leaf, leaf_hash, tries: i as u64 + 1 });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::{BatchPolicy, build_batch_manifest, build_leaf_chunk, build_provider_bond, restamp_leaves};
    use crate::{MiningJob, PalwMiner, ProviderRegistration};
    use kaspa_consensus_core::palw::{PALW_MAX_BATCH_LEAVES_V1, validate_palw_overlay_payload};
    use kaspa_consensus_core::tx::TransactionOutpoint;
    use kaspa_pq_validator_core::ValidatorKey;
    use misaka_palw::palw::{PalwRuntimeProfileV1, PalwSamplingParams, PalwTier};
    use misaka_palw::palw_replica::MockDeterministicRuntime;

    const NET: u32 = 0x9107;
    /// The max-easy genesis lane bits (`DEVNET_PALW`/`TESTNET_PALW`): `target_512 = target_256 << 256`
    /// with `target_256 ≈ 2^255`, i.e. ≈ 50 % win per candidate — a handful of tries suffices.
    const EASY_BITS: u32 = 0x207fffff;
    /// A tiny target (`target_256 = 1 ⇒ target_512 = 2^256`, win prob ≈ 2^-256): no candidate wins.
    const HARD_BITS: u32 = 0x03000001;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    fn profile() -> PalwRuntimeProfileV1 {
        PalwRuntimeProfileV1 {
            version: 1,
            tier: PalwTier::Quality,
            model_id: PalwTier::Quality.model_id(),
            tokenizer_hash: h(1),
            quantization_manifest_hash: h(2),
            runtime_image_hash: h(3),
            kernel_graph_hash: h(4),
            operation_table_hash: h(5),
            shape_table_hash: h(6),
            gpu_arch_class: 100,
            tensor_parallel_degree: 1,
            pipeline_parallel_degree: 1,
            deterministic_reduction: true,
            batch_invariant: true,
            speculative_decode: false,
            sampling: PalwSamplingParams::greedy(),
        }
    }

    fn miner() -> PalwMiner<MockDeterministicRuntime, MockDeterministicRuntime> {
        // ADR-0040 P0-4 (ECON-01): a leaf's reward scripts are emitted VERBATIM as coinbase outputs, so
        // leaf admission requires the exact 69-byte P2PKH ML-DSA-87 template. An arbitrary script is not
        // coinbase-representable and the leaf chunk is rejected.
        let spk = kaspa_consensus_core::dns_finality::p2pkh_mldsa87_spk(&[0xa0; 64]);
        PalwMiner::new(
            MockDeterministicRuntime::new(profile(), 3, 2),
            MockDeterministicRuntime::new(profile(), 3, 2),
            ProviderRegistration {
                provider_a_bond: TransactionOutpoint::new(h(6), 0),
                provider_b_bond: TransactionOutpoint::new(h(7), 0),
                provider_a_reward_script: spk.clone(),
                provider_b_reward_script: spk,
                ticket_authority_pk_hash: h(8),
                registered_epoch: 3,
                activation_epoch: 4,
                expiry_epoch: 1000,
                leaf_bond_sompi: 0,
            },
        )
    }

    fn base_leaf(batch_id: Hash64) -> PalwPublicLeafV1 {
        miner()
            .produce_leaf(&MiningJob {
                batch_id,
                leaf_index: 0,
                job_set_descriptor: b"job".to_vec(),
                prompt: b"prompt".to_vec(),
                output_salt: [0x33; 32],
                job_nullifier: h(0x20),
                // The base nullifier is irrelevant — grind_eligibility swaps in each candidate's commitment.
                raw_ticket_nullifier: h(0),
            })
            .unwrap()
            .leaf
    }

    fn ctx(bits: u32) -> EligibilityContext {
        EligibilityContext {
            network_id: NET,
            beacon_seed: h(0xBE),
            chain_commit: h(0xCC),
            target_daa_interval: 42,
            replica_bits: bits,
        }
    }

    /// The mining core: grinding the nullifier over the max-easy genesis target finds a winner, and the
    /// winning ticket independently satisfies the exact `palw_eligibility_win` draw a validator runs —
    /// with the nonce pinned to `low64(nullifier)` and the leaf carrying the candidate's commitment.
    #[test]
    fn grind_finds_a_ticket_that_wins_the_real_draw() {
        let batch = h(0x10);
        let leaf = base_leaf(batch);
        let c = ctx(EASY_BITS);
        let ticket = grind_eligibility(&c, &leaf, nullifier_sequence(b"authority-secret", 128)).expect("easy target wins");

        // The nonce is pinned to the nullifier (I-3), and the leaf commits to the winning nullifier.
        assert_eq!(ticket.nonce, pinned_nonce(&ticket.raw_nullifier));
        assert_eq!(ticket.leaf.ticket_nullifier_commitment, ticket_nullifier_commitment(&ticket.raw_nullifier));

        // Re-run the EXACT consensus draw over the returned ticket — it must win.
        let digest = eligibility_hash(
            NET,
            &c.beacon_seed,
            &c.chain_commit,
            c.target_daa_interval,
            &batch,
            0,
            &ticket.leaf_hash,
            &ticket.raw_nullifier,
        );
        assert!(palw_eligibility_win(&digest, EASY_BITS, ticket.nonce, &ticket.raw_nullifier));
        assert!(ticket.tries >= 1);
    }

    /// Determinism: the same secret + context grinds to the identical winning ticket.
    #[test]
    fn grind_is_deterministic() {
        let leaf = base_leaf(h(0x10));
        let c = ctx(EASY_BITS);
        let a = grind_eligibility(&c, &leaf, nullifier_sequence(b"secret", 128)).unwrap();
        let b = grind_eligibility(&c, &leaf, nullifier_sequence(b"secret", 128)).unwrap();
        assert_eq!(a.raw_nullifier, b.raw_nullifier);
        assert_eq!(a.tries, b.tries);
    }

    /// An effectively-impossible target exhausts the candidate budget → no ticket (the caller waits or
    /// widens the search); it never fabricates a win.
    #[test]
    fn impossible_target_yields_no_ticket() {
        let leaf = base_leaf(h(0x10));
        assert!(grind_eligibility(&ctx(HARD_BITS), &leaf, nullifier_sequence(b"secret", 256)).is_none());
    }

    /// The whole self-contained round, end to end, validated against the REAL consensus gates: stand up
    /// a batch (provider-bond → manifest → leaf-chunk → auditor certificate), then grind the winning
    /// ticket for its first leaf. Every payload the loop would submit is accepted by the stateless
    /// validator under ONE content-derived batch id, and the ticket wins the real draw.
    #[test]
    fn full_self_contained_mining_round_end_to_end() {
        use crate::audit::{AuditRound, Auditor, QuorumPolicy, run_audit_round};
        use std::collections::HashMap;

        // (1) Provider bond — the lifecycle's first payload.
        let prov_pubkey = ValidatorKey::from_seed([0x2C; 32]).public_key().to_vec();
        let (bond_byte, bond_payload) =
            build_provider_bond(prov_pubkey, h(0xA0), vec![h(1)], vec![(1, 4)], h(0xB0), 1_000, 10).unwrap();
        assert_eq!(validate_palw_overlay_payload(bond_byte, &bond_payload), Ok(()));

        // (2) Mine two leaves under a placeholder id, then fix them as a content-addressed batch.
        let m = miner();
        let mine = |idx: u32, nf: u8| {
            m.produce_leaf(&MiningJob {
                batch_id: Hash64::default(),
                leaf_index: idx,
                job_set_descriptor: vec![idx as u8],
                prompt: format!("p{idx}").into_bytes(),
                output_salt: [0x33; 32],
                job_nullifier: h(0x20 + idx as u8),
                raw_ticket_nullifier: h(0xC0 + nf),
            })
            .unwrap()
            .leaf
        };
        let leaves = vec![mine(0, 0), mine(1, 1)];
        let policy = BatchPolicy {
            registration_epoch: 5,
            registration_lead_epochs: 2,
            audit_window_epochs: 1,
            active_window_epochs: 100,
            min_leaf_bond_sompi: 0,
            max_batch_leaves: PALW_MAX_BATCH_LEAVES_V1 as u32,
        };
        let (batch_id, (man_byte, man_payload)) = build_batch_manifest(&leaves, h(1), h(2), h(3), h(4), 0, &policy).unwrap();
        assert_eq!(validate_palw_overlay_payload(man_byte, &man_payload), Ok(()));
        // The certificate below MUST carry values DERIVED from this manifest, not placeholders:
        // `verify_certificate_attestation` cross-binds `cert.manifest_hash == manifest.content_id()`
        // and `cert.leaf_root == manifest.leaf_root` (consensus/src/processes/palw.rs:384-389). An
        // earlier revision of this "end-to-end" test used literals here, so it passed while the same
        // producer path would have been rejected on-chain with CertificateManifestMismatch /
        // CertificateLeafRootMismatch. Decode the manifest back and use its real fields, so the test
        // fails if the producer and the verifier ever disagree again.
        let manifest = <kaspa_consensus_core::palw::PalwBatchManifestV1 as borsh::BorshDeserialize>::try_from_slice(&man_payload)
            .expect("the manifest we just built must decode");
        assert_eq!(manifest.content_id(), batch_id, "batch_id is the manifest content id");

        // (3) Re-stamp under the content id + chunk on-chain.
        let restamped = restamp_leaves(batch_id, &leaves);
        let (chunk_byte, chunk_payload) = build_leaf_chunk(batch_id, 0, restamped.clone()).unwrap();
        assert_eq!(validate_palw_overlay_payload(chunk_byte, &chunk_payload), Ok(()));

        // (4) Auditor quorum certifies the batch.
        let auditors = [
            Auditor {
                key: ValidatorKey::from_seed([0x11; 32]),
                bond: TransactionOutpoint::new(h(0x11), 1),
                pass: true,
                checked_leaf_bitmap_root: h(0x51),
            },
            Auditor {
                key: ValidatorKey::from_seed([0x22; 32]),
                bond: TransactionOutpoint::new(h(0x22), 2),
                pass: true,
                checked_leaf_bitmap_root: h(0x52),
            },
            Auditor {
                key: ValidatorKey::from_seed([0x33; 32]),
                bond: TransactionOutpoint::new(h(0x33), 3),
                pass: true,
                checked_leaf_bitmap_root: h(0x53),
            },
        ];
        let stakes: HashMap<_, _> = auditors.iter().map(|a| (a.bond, 100u128)).collect();
        let set_commit = kaspa_consensus_core::palw::auditor_set_commitment(&auditors.iter().map(|a| a.bond).collect::<Vec<_>>());
        let round = AuditRound {
            network_id: NET,
            batch_id,
            manifest_hash: manifest.content_id(),
            leaf_root: manifest.leaf_root,
            audit_beacon_epoch: 5,
            audit_sample_root: h(0x33),
            passed_leaf_count: 2,
            rejected_leaf_bitmap_root: h(0x44),
            certificate_epoch: 6,
            activation_epoch: 7,
            expiry_epoch: 13,
            auditor_set_commitment: set_commit,
        };
        let cert = run_audit_round(&round, &auditors, &stakes, QuorumPolicy { num: 2, den: 3 }).unwrap();
        assert_eq!(validate_palw_overlay_payload(cert.subnetwork_byte, &cert.payload), Ok(()));

        // (5) Grind the winning ticket for the batch's first (restamped) leaf.
        let c = ctx(EASY_BITS);
        let ticket = grind_eligibility(&c, &restamped[0], nullifier_sequence(b"authority-secret", 128)).expect("ticket");
        let digest = eligibility_hash(
            NET,
            &c.beacon_seed,
            &c.chain_commit,
            c.target_daa_interval,
            &batch_id,
            0,
            &ticket.leaf_hash,
            &ticket.raw_nullifier,
        );
        assert!(palw_eligibility_win(&digest, EASY_BITS, ticket.nonce, &ticket.raw_nullifier), "the minted ticket wins the real draw");
        // The winning leaf resolves under the batch's content id (matches the chunk key the node stored).
        assert_eq!(ticket.leaf.batch_id, batch_id);
    }
}
