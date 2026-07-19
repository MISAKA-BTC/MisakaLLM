//! PALW **per-block ticket authorization** producer (ADR-0040 P1-6, AUTH-01/02/03) — the signing half
//! of body clause 7.
//!
//! # Why the miner needs this at all
//!
//! A winning algo-4 header DISCLOSES its raw `ticket_nullifier` (I-13 secrecy ends at mint) and
//! `eligibility_hash` binds no block content. Before ADR-0040 any OBSERVER of a winning block could
//! restamp that same winning draw onto unlimited competing blocks of their own choosing. Clause 7
//! closes it by REQUIRING every algo-4 block to carry an ML-DSA-87 authorization, signed by the
//! authority the leaf named in `ticket_authority_pk_hash`, that binds this block's parents,
//! transaction set, timestamp and ticket coordinates.
//!
//! That is a *requirement*, not an option: without a matching producer this crate's mining path
//! ([`crate::mining::grind_eligibility`]) mints blocks that this repository's own consensus rejects.
//! This module is that producer.
//!
//! # Construction == validation
//!
//! Every value here is fed to a live check, and the module deliberately owns none of the binding
//! logic — it calls the SAME consensus functions the verifier calls:
//!
//! | produced here | checked by clause 7 |
//! |---|---|
//! | [`TicketAuthority::pk_hash`] | `PalwBlockAuthorizationV1::binds_leaf_authority` (AUTH-03) |
//! | `header_preimage_commitment` via `palw_header_preimage_commitment` | `PalwBlockAuthorizationV1::binds_header` (AUTH-02) |
//! | `signature` under [`PALW_AUTHORIZATION_MLDSA87_CONTEXT`] over `signing_hash` | `verify_mldsa87_with_context` (AUTH-01) |
//! | [`BlockAuthorization::authorization_hash`] | `auth.hash() == header.palw_authorization_hash` |
//! | [`BlockAuthorization::payload`] on subnetwork `0x38` | the body's authorization-tx lookup + `validate_palw_overlay_payload` |
//!
//! The `ctx` matters as much as the digest: FIPS-204 binds the context into the signature, so signing
//! under anything but [`PALW_AUTHORIZATION_MLDSA87_CONTEXT`] yields an authorization consensus cannot
//! verify (and, by construction, one that can never be replayed as a beacon or an audit vote).
//!
//! # The one input this module cannot compute for itself
//!
//! [`BlockAuthorizationBinding::authed_hash_merkle_root`] is the merkle root over the block's
//! transactions **EXCLUDING the authorization transaction itself** — the authorization cannot commit
//! to a root that contains the authorization, that is circular. The node assembling the block owns
//! the transaction set, so it computes that root (`calc_hash_merkle_root` over the non-`0x38` txs)
//! and passes it in; after appending the returned payload it recomputes the header's own
//! `hash_merkle_root` over ALL transactions, which does include it.

use kaspa_consensus_core::palw::{
    PALW_AUTHORIZATION_DOMAIN, PALW_AUTHORIZATION_MLDSA87_CONTEXT, PalwBlockAuthorizationV1, palw_header_preimage_commitment,
    palw_parents_commitment,
};
use kaspa_hashes::{Hash64, blake2b_512_keyed};
use kaspa_pq_validator_core::ValidatorKey;

/// The `0x38` subnetwork byte a ticket-authorization PALW TX carries (mirrors
/// `PalwTxKind::from_subnetwork_byte(0x38) == BlockAuthorization` and
/// `SUBNETWORK_ID_PALW_BLOCK_AUTHORIZATION`).
pub const BLOCK_AUTHORIZATION_SUBNETWORK_BYTE: u8 = 0x38;

/// The `ticket_authority_pk_hash` a leaf must publish for `public_key` to be able to authorize its
/// blocks — the exact preimage `PalwBlockAuthorizationV1::binds_leaf_authority` recomputes (AUTH-03).
///
/// A leaf whose `ticket_authority_pk_hash` is anything else (a placeholder, or the hash of a key the
/// miner does not hold) can never win a block: it may be admitted on-chain, but every algo-4 block
/// referencing it fails clause 7.
pub fn ticket_authority_pk_hash(public_key: &[u8]) -> Hash64 {
    blake2b_512_keyed(PALW_AUTHORIZATION_DOMAIN, public_key)
}

/// Everything the authorization binds, resolved by the node from the block it is about to mint.
///
/// This is exactly the clause-7 binding set — the miner-chosen quantities that distinguish one
/// competing block from another. `palw_authorization_hash` is necessarily absent (it is the
/// commitment to the object being built), and the remaining header fields are GHOSTDAG/UTXO-derived
/// rather than freely chosen, so this set pins the authorization to one block.
#[derive(Clone, Debug)]
pub struct BlockAuthorizationBinding {
    /// The consensus PALW network number (`params.net.suffix()`), as used by every PALW preimage.
    pub network_id: u32,
    /// The block's DIRECT PARENTS in consensus order. Order-sensitive on purpose: two blocks
    /// differing only in parent order are different blocks and need different authorizations.
    pub parents: Vec<Hash64>,
    /// Merkle root over the block's transactions **excluding** the authorization tx (see module docs).
    pub authed_hash_merkle_root: Hash64,
    /// `header.palw_batch_id`.
    pub batch_id: Hash64,
    /// `header.palw_leaf_index`.
    pub leaf_index: u32,
    /// `header.palw_ticket_nullifier` — the RAW winning nullifier (`WinningTicket::raw_nullifier`).
    pub ticket_nullifier: Hash64,
    /// `header.palw_chain_commit`, as re-derived by clause 6 from the finality-buried DNS anchor.
    pub chain_commit: Hash64,
    /// `header.palw_target_daa_interval`.
    pub target_daa_interval: u64,
    /// `header.timestamp`. Miner-chosen, therefore bound: omitting it leaves two blocks differing only
    /// in timestamp sharing a preimage, i.e. a live replay hole (the AUTH-02 attack test found exactly
    /// this in the first cut of the fix).
    pub timestamp: u64,
}

/// A signed authorization ready to ride in the block it authorizes.
#[derive(Clone, Debug)]
pub struct BlockAuthorization {
    /// [`BLOCK_AUTHORIZATION_SUBNETWORK_BYTE`] — the subnetwork the carrying transaction declares.
    pub subnetwork_byte: u8,
    /// `borsh(auth)` — the bytes the `0x38` transaction carries as its payload.
    pub payload: Vec<u8>,
    /// The value the minted header must stamp into `palw_authorization_hash`, so the header cannot
    /// name one authorization while the body carries another.
    pub authorization_hash: Hash64,
    pub auth: PalwBlockAuthorizationV1,
}

/// A ticket authority: the ML-DSA-87 key whose public-key hash a leaf publishes as
/// `ticket_authority_pk_hash`, and which alone can authorize blocks spending that leaf's ticket.
///
/// The key is the whole point of clause 7 — the observer of a winning block has the nullifier, the
/// leaf and the chain commit, but not this. Keep it where the mining loop runs.
pub struct TicketAuthority {
    key: ValidatorKey,
}

impl TicketAuthority {
    pub fn new(key: ValidatorKey) -> Self {
        Self { key }
    }

    /// Derive an authority from a 32-byte seed (same derivation as every other ML-DSA-87 role key).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::new(ValidatorKey::from_seed(seed))
    }

    /// The raw ML-DSA-87 verification key carried verbatim in the authorization.
    pub fn public_key(&self) -> &[u8] {
        self.key.public_key()
    }

    /// The value to put in [`crate::ProviderRegistration::ticket_authority_pk_hash`] (and therefore in
    /// every minted leaf) so that this authority can authorize the leaf's blocks — AUTH-03.
    pub fn pk_hash(&self) -> Hash64 {
        ticket_authority_pk_hash(self.public_key())
    }

    /// Sign the per-block authorization for `binding`.
    ///
    /// Pure over `(key, binding)` apart from ML-DSA's hedged signing randomness: the DIGEST is
    /// deterministic, so a verifier re-deriving it from the block gets the identical value.
    pub fn authorize(&self, binding: &BlockAuthorizationBinding) -> BlockAuthorization {
        let parents_hash = palw_parents_commitment(&binding.parents);
        let header_preimage_commitment = palw_header_preimage_commitment(
            binding.network_id,
            &parents_hash,
            &binding.authed_hash_merkle_root,
            &binding.batch_id,
            binding.leaf_index,
            &binding.ticket_nullifier,
            &binding.chain_commit,
            binding.target_daa_interval,
            binding.timestamp,
        );
        let mut auth = PalwBlockAuthorizationV1 {
            version: 1,
            batch_id: binding.batch_id,
            leaf_index: binding.leaf_index,
            ticket_nullifier: binding.ticket_nullifier,
            header_preimage_commitment,
            // INCLUDED in the signing preimage by `signing_hash`, so a signature cannot be
            // re-presented under a substituted key.
            authority_public_key: self.public_key().to_vec(),
            signature: Vec::new(),
        };
        let digest = auth.signing_hash(binding.network_id);
        auth.signature = self.key.sign_with_context(digest.as_bytes().as_slice(), PALW_AUTHORIZATION_MLDSA87_CONTEXT).to_vec();
        let authorization_hash = auth.hash();
        let payload = borsh::to_vec(&auth).expect("borsh encoding of a fixed-shape authorization is infallible");
        BlockAuthorization { subnetwork_byte: BLOCK_AUTHORIZATION_SUBNETWORK_BYTE, payload, authorization_hash, auth }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mining::{EligibilityContext, grind_eligibility, nullifier_sequence};
    use crate::registration::restamp_leaves;
    use crate::{MiningJob, PalwMiner, ProviderRegistration};
    use kaspa_consensus_core::palw::{PalwPublicLeafV1, validate_palw_overlay_payload};
    use kaspa_consensus_core::tx::TransactionOutpoint;
    use kaspa_txscript::verify_mldsa87_with_context;
    use misaka_palw::palw::{PalwRuntimeProfileV1, PalwSamplingParams, PalwTier};
    use misaka_palw::palw_replica::MockDeterministicRuntime;

    const NET: u32 = 0x9107;
    /// Max-easy genesis lane bits (`DEVNET_PALW`/`TESTNET_PALW`) — a handful of candidates wins.
    const EASY_BITS: u32 = 0x207fffff;
    const AUTHORITY_SEED: [u8; 32] = [0x9a; 32];

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

    /// A miner whose registration names `authority` — the AUTH-03 link between the key held by the
    /// mining loop and the `ticket_authority_pk_hash` published in every leaf it mints.
    fn miner(authority: &TicketAuthority) -> PalwMiner<MockDeterministicRuntime, MockDeterministicRuntime> {
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
                ticket_authority_pk_hash: authority.pk_hash(),
                registered_epoch: 3,
                activation_epoch: 4,
                expiry_epoch: 1000,
                leaf_bond_sompi: 0,
            },
        )
    }

    fn base_leaf(authority: &TicketAuthority, batch_id: Hash64) -> PalwPublicLeafV1 {
        miner(authority)
            .produce_leaf(&MiningJob {
                batch_id,
                leaf_index: 0,
                job_set_descriptor: b"job".to_vec(),
                prompt: b"prompt".to_vec(),
                output_salt: [0x33; 32],
                job_nullifier: h(0x20),
                raw_ticket_nullifier: h(0),
            })
            .unwrap()
            .leaf
    }

    fn ctx() -> EligibilityContext {
        EligibilityContext {
            network_id: NET,
            beacon_seed: h(0xBE),
            chain_commit: h(0xCC),
            target_daa_interval: 42,
            replica_bits: EASY_BITS,
        }
    }

    /// The full producer path, exactly as the node drives it: mint a leaf under the authority, grind a
    /// winning ticket, then authorize the block that would carry it.
    fn produce() -> (TicketAuthority, PalwPublicLeafV1, BlockAuthorizationBinding, BlockAuthorization) {
        let authority = TicketAuthority::from_seed(AUTHORITY_SEED);
        let batch_id = h(0x10);
        let leaf = restamp_leaves(batch_id, &[base_leaf(&authority, batch_id)]).remove(0);
        let c = ctx();
        let ticket = grind_eligibility(&c, &leaf, nullifier_sequence(b"authority-secret", 128)).expect("easy target wins");
        let binding = BlockAuthorizationBinding {
            network_id: NET,
            parents: vec![h(0x71), h(0x72)],
            authed_hash_merkle_root: h(0x80),
            batch_id,
            leaf_index: 0,
            ticket_nullifier: ticket.raw_nullifier,
            chain_commit: c.chain_commit,
            target_daa_interval: c.target_daa_interval,
            timestamp: 1_700_000_000_000,
        };
        let authorized = authority.authorize(&binding);
        (authority, ticket.leaf, binding, authorized)
    }

    /// **Construction == validation, ACCEPT half.** Everything body clause 7 checks, checked here
    /// against the produced authorization — using the consensus functions themselves, not a
    /// re-implementation: the payload is isolation-valid on `0x38`, the header hash matches, the
    /// binding matches, the key is the leaf's declared authority, and the ML-DSA-87 signature verifies
    /// under the verifier's own context.
    #[test]
    fn miner_authorization_satisfies_every_clause_7_check() {
        let (authority, leaf, binding, authorized) = produce();

        // Isolation validity of the carrying 0x38 transaction payload.
        assert_eq!(authorized.subnetwork_byte, BLOCK_AUTHORIZATION_SUBNETWORK_BYTE);
        assert_eq!(validate_palw_overlay_payload(authorized.subnetwork_byte, &authorized.payload), Ok(()));
        // The payload really decodes back to the object we signed (the body decodes it, not us).
        let decoded = <PalwBlockAuthorizationV1 as borsh::BorshDeserialize>::try_from_slice(&authorized.payload).expect("decode");
        assert_eq!(decoded, authorized.auth);

        // `auth.hash() == header.palw_authorization_hash`.
        assert_eq!(decoded.hash(), authorized.authorization_hash);

        // AUTH-02: the authorization is ABOUT this block.
        let parents_hash = palw_parents_commitment(&binding.parents);
        assert!(decoded.binds_header(
            binding.network_id,
            &parents_hash,
            &binding.authed_hash_merkle_root,
            &binding.batch_id,
            binding.leaf_index,
            &binding.ticket_nullifier,
            &binding.chain_commit,
            binding.target_daa_interval,
            binding.timestamp,
        ));

        // AUTH-03: the signing key is the authority the LEAF declared — the link that makes
        // `ticket_authority_pk_hash` mean something.
        assert_eq!(leaf.ticket_authority_pk_hash, authority.pk_hash());
        assert!(decoded.binds_leaf_authority(&leaf.ticket_authority_pk_hash));

        // AUTH-01: the exact verification the body performs, same digest, same ctx.
        assert_eq!(
            verify_mldsa87_with_context(
                &decoded.authority_public_key,
                decoded.signing_hash(binding.network_id).as_bytes().as_slice(),
                &decoded.signature,
                PALW_AUTHORIZATION_MLDSA87_CONTEXT,
            ),
            Ok(true)
        );
    }

    /// **Construction == validation, REJECT half.** Mutating ANY bound field breaks the binding — this
    /// is the anti-re-mint property (AUTH-02): an observer who knows the disclosed nullifier still
    /// cannot lift the authorization onto a block of their own, because a block of their own differs in
    /// at least one of these. The `timestamp` case is called out on purpose: the first cut of the fix
    /// left it unbound and the replay SUCCEEDED.
    #[test]
    fn every_bound_field_is_load_bearing() {
        let (_authority, _leaf, binding, authorized) = produce();
        let auth = authorized.auth;

        // Each mutation is a block the authority did NOT authorize.
        let cases: Vec<(&str, BlockAuthorizationBinding)> = vec![
            ("parents", BlockAuthorizationBinding { parents: vec![h(0x71), h(0x73)], ..binding.clone() }),
            // Order-sensitivity: the same parent SET in a different order is a different block.
            ("parent order", BlockAuthorizationBinding { parents: vec![h(0x72), h(0x71)], ..binding.clone() }),
            ("tx set", BlockAuthorizationBinding { authed_hash_merkle_root: h(0x81), ..binding.clone() }),
            ("timestamp", BlockAuthorizationBinding { timestamp: binding.timestamp + 1, ..binding.clone() }),
            ("chain commit", BlockAuthorizationBinding { chain_commit: h(0xCD), ..binding.clone() }),
            ("target interval", BlockAuthorizationBinding { target_daa_interval: 43, ..binding.clone() }),
            ("batch id", BlockAuthorizationBinding { batch_id: h(0x11), ..binding.clone() }),
            ("leaf index", BlockAuthorizationBinding { leaf_index: 1, ..binding.clone() }),
            ("nullifier", BlockAuthorizationBinding { ticket_nullifier: h(0xEE), ..binding.clone() }),
            ("network id", BlockAuthorizationBinding { network_id: NET + 1, ..binding.clone() }),
        ];
        for (what, mutated) in cases {
            let parents_hash = palw_parents_commitment(&mutated.parents);
            assert!(
                !auth.binds_header(
                    mutated.network_id,
                    &parents_hash,
                    &mutated.authed_hash_merkle_root,
                    &mutated.batch_id,
                    mutated.leaf_index,
                    &mutated.ticket_nullifier,
                    &mutated.chain_commit,
                    mutated.target_daa_interval,
                    mutated.timestamp,
                ),
                "mutating {what} must break the authorization binding"
            );
        }

        // A DIFFERENT authority's key does not satisfy the leaf's AUTH-03 declaration...
        let impostor = TicketAuthority::from_seed([0x5b; 32]);
        assert!(!auth.binds_leaf_authority(&impostor.pk_hash()));
        // ...and swapping the public key into the payload does not rescue the signature either, because
        // `signing_hash` covers the key.
        let mut swapped = auth.clone();
        swapped.authority_public_key = impostor.public_key().to_vec();
        assert_ne!(
            verify_mldsa87_with_context(
                &swapped.authority_public_key,
                swapped.signing_hash(binding.network_id).as_bytes().as_slice(),
                &swapped.signature,
                PALW_AUTHORIZATION_MLDSA87_CONTEXT,
            ),
            Ok(true)
        );
    }

    /// The signature is bound to the authorization's OWN context. Signing the same digest under a
    /// different PALW context (here the auditor-vote one) does not verify as an authorization — so an
    /// authorization can never be replayed as a vote or a beacon, and a producer that picks the wrong
    /// constant fails loudly rather than emitting silently-unverifiable blocks.
    #[test]
    fn authorization_signature_is_context_bound() {
        let (_authority, _leaf, binding, authorized) = produce();
        let digest = authorized.auth.signing_hash(binding.network_id);
        assert_ne!(
            verify_mldsa87_with_context(
                &authorized.auth.authority_public_key,
                digest.as_bytes().as_slice(),
                &authorized.auth.signature,
                kaspa_consensus_core::palw::PALW_AUDITOR_MLDSA87_CONTEXT,
            ),
            Ok(true),
            "an authorization signature must not verify under another PALW context"
        );
    }

    /// AUTH-03 is only meaningful if the leaf actually carries the authority's hash — the registration
    /// field is the producer's single point of failure, so pin the derivation to the consensus one.
    #[test]
    fn pk_hash_matches_the_consensus_authority_derivation() {
        let authority = TicketAuthority::from_seed(AUTHORITY_SEED);
        assert_eq!(authority.pk_hash(), blake2b_512_keyed(PALW_AUTHORIZATION_DOMAIN, authority.public_key()));
        // And a leaf minted under it declares exactly that.
        assert_eq!(base_leaf(&authority, h(0x10)).ticket_authority_pk_hash, authority.pk_hash());
    }
}
