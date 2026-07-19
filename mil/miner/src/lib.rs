//! misaka-palw-miner — the PALW-only mining driver (ADR-0039): compute → k=2 → leaf.
//!
//! Ties a [`VerifiableInferenceBackend`] (the real Qwen backend or the CPU reference
//! runtime) to the on-chain leaf: run one job through TWO providers of the same runtime
//! class (k=2), and iff they exact-match, mint the candidate [`PalwPublicLeafV1`] from the
//! shared match key plus the miner's provider registration. This is the self-contained
//! compute half a node needs to mine algo-4 blocks; block-template construction, block
//! submission, and the beacon commit/reveal cycle live in the node (later phases). Carries
//! NO MIL job-market runtime (channel / attest).

pub mod audit;
pub mod beacon;
pub mod mining;
pub mod registration;

use kaspa_consensus_core::palw::{PalwPublicLeafV1, ticket_nullifier_commitment};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint};
use kaspa_hashes::Hash64;
use misaka_palw::palw::ReplicaMatchKey;
use misaka_palw::palw_replica::{ReplicaK2Outcome, VerifiableInferenceBackend, dispatch_k2_backends};

/// ReplicaExactV1 — the only proof type this driver mints (design §20.2).
pub const PROOF_TYPE_REPLICA_EXACT_V1: u8 = 1;

/// The miner's on-chain provider identity: the fixed metadata a minted leaf carries beyond
/// the match-derived fields — the two provider bonds + one-time reward scripts, the ticket
/// authority, and the registration windows (all resolved from the provider registration TX).
#[derive(Clone, Debug)]
pub struct ProviderRegistration {
    pub provider_a_bond: TransactionOutpoint,
    pub provider_b_bond: TransactionOutpoint,
    pub provider_a_reward_script: ScriptPublicKey,
    pub provider_b_reward_script: ScriptPublicKey,
    pub ticket_authority_pk_hash: Hash64,
    pub registered_epoch: u64,
    pub activation_epoch: u64,
    pub expiry_epoch: u64,
    pub leaf_bond_sompi: u64,
}

/// One inference job to mine: the batch slot + the actual work (job-set descriptor / prompt /
/// output salt) + the ticket authority's raw nullifier (disclosed only at the header, I-13).
#[derive(Clone, Debug)]
pub struct MiningJob {
    pub batch_id: Hash64,
    pub leaf_index: u32,
    pub job_set_descriptor: Vec<u8>,
    pub prompt: Vec<u8>,
    pub output_salt: [u8; 32],
    pub job_nullifier: Hash64,
    /// The raw ticket nullifier; the leaf commits to `ticket_nullifier_commitment(raw)`, and the
    /// winning header later reveals the raw value (I-13 winner-secrecy).
    pub raw_ticket_nullifier: Hash64,
}

/// A minted candidate: the on-chain leaf, its hash, and the shared k=2 match key (kept for the
/// receipt / data-availability step).
#[derive(Clone, Debug)]
pub struct MintedLeaf {
    pub leaf: PalwPublicLeafV1,
    pub leaf_hash: Hash64,
    pub match_key: ReplicaMatchKey,
}

/// Why a job produced no leaf.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MineError {
    /// The two providers disagreed on at least one of the eight match fields — the audited-compute
    /// check that stops a faulty / dishonest provider from minting. No leaf, no ticket.
    #[error("k=2 replica mismatch — the two providers disagreed; no leaf minted")]
    ReplicaMismatch,
}

/// The PALW mining driver over two providers of the SAME runtime class (I-9). For a single
/// operator both are local backend instances; across the network they are two independent
/// providers whose byte-exact agreement IS the audited-compute guarantee.
pub struct PalwMiner<A: VerifiableInferenceBackend, B: VerifiableInferenceBackend> {
    provider_a: A,
    provider_b: B,
    reg: ProviderRegistration,
}

impl<A: VerifiableInferenceBackend, B: VerifiableInferenceBackend> PalwMiner<A, B> {
    pub fn new(provider_a: A, provider_b: B, reg: ProviderRegistration) -> Self {
        Self { provider_a, provider_b, reg }
    }

    /// The provider registration this miner mints under.
    pub fn registration(&self) -> &ProviderRegistration {
        &self.reg
    }

    /// Run `job` through both providers (k=2). On exact-match, mint the candidate leaf from the
    /// shared key + the provider registration; on disagreement, no leaf ([`MineError::ReplicaMismatch`]).
    /// Pure over `(providers, job, registration)` — deterministic, no wall-clock — so a validator
    /// re-deriving the leaf fields from the same inputs gets the identical `leaf_hash`.
    pub fn produce_leaf(&self, job: &MiningJob) -> Result<MintedLeaf, MineError> {
        let key =
            match dispatch_k2_backends(&self.provider_a, &self.provider_b, &job.job_set_descriptor, &job.prompt, &job.output_salt) {
                ReplicaK2Outcome::Matched(k) => k,
                ReplicaK2Outcome::Mismatch => return Err(MineError::ReplicaMismatch),
            };
        let leaf = PalwPublicLeafV1 {
            version: 1,
            batch_id: job.batch_id,
            leaf_index: job.leaf_index,
            job_nullifier: job.job_nullifier,
            ticket_nullifier_commitment: ticket_nullifier_commitment(&job.raw_ticket_nullifier),
            model_profile_id: key.model_profile_id,
            runtime_class_id: key.runtime_class_id,
            shape_id: key.shape_id,
            quantum_count: key.quantum_count,
            proof_type: PROOF_TYPE_REPLICA_EXACT_V1,
            provider_a_bond: self.reg.provider_a_bond,
            provider_b_bond: self.reg.provider_b_bond,
            provider_a_reward_script: self.reg.provider_a_reward_script.clone(),
            provider_b_reward_script: self.reg.provider_b_reward_script.clone(),
            ticket_authority_pk_hash: self.reg.ticket_authority_pk_hash,
            // Bind the leaf to THIS exact k=2 GEMM execution (the private match commitment).
            private_match_commitment: key.canonical_gemm_trace_root,
            receipt_da_root: Hash64::default(),
            registered_epoch: self.reg.registered_epoch,
            activation_epoch: self.reg.activation_epoch,
            expiry_epoch: self.reg.expiry_epoch,
            leaf_bond_sompi: self.reg.leaf_bond_sompi,
        };
        let leaf_hash = leaf.leaf_hash();
        Ok(MintedLeaf { leaf, leaf_hash, match_key: key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec};
    use misaka_palw::palw::{PalwRuntimeProfileV1, PalwSamplingParams, PalwTier};
    use misaka_palw::palw_replica::MockDeterministicRuntime;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    fn profile(tier: PalwTier, arch: u32) -> PalwRuntimeProfileV1 {
        PalwRuntimeProfileV1 {
            version: 1,
            tier,
            model_id: tier.model_id(),
            tokenizer_hash: h(1),
            quantization_manifest_hash: h(2),
            runtime_image_hash: h(3),
            kernel_graph_hash: h(4),
            operation_table_hash: h(5),
            shape_table_hash: h(6),
            gpu_arch_class: arch,
            tensor_parallel_degree: 1,
            pipeline_parallel_degree: 1,
            deterministic_reduction: true,
            batch_invariant: true,
            speculative_decode: false,
            sampling: PalwSamplingParams::greedy(),
        }
    }

    fn reg() -> ProviderRegistration {
        let spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&[1]));
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
        }
    }

    fn job() -> MiningJob {
        MiningJob {
            batch_id: h(0x10),
            leaf_index: 0,
            job_set_descriptor: b"job-set-1".to_vec(),
            prompt: b"the prompt".to_vec(),
            output_salt: [0x33; 32],
            job_nullifier: h(0x20),
            raw_ticket_nullifier: h(0xC0),
        }
    }

    #[test]
    fn two_honest_same_class_providers_mint_a_leaf() {
        let miner = PalwMiner::new(
            MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2),
            MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2),
            reg(),
        );
        let minted = miner.produce_leaf(&job()).expect("two honest same-class providers must match");
        assert_eq!(minted.leaf.proof_type, PROOF_TYPE_REPLICA_EXACT_V1);
        assert_eq!(minted.leaf.batch_id, h(0x10));
        // The leaf binds to the shared match execution and commits the ticket nullifier.
        assert_eq!(minted.leaf.private_match_commitment, minted.match_key.canonical_gemm_trace_root);
        assert_eq!(minted.leaf.ticket_nullifier_commitment, ticket_nullifier_commitment(&h(0xC0)));
        assert_eq!(minted.leaf_hash, minted.leaf.leaf_hash());
        // Deterministic: mining the same job again yields the identical leaf hash.
        let again = miner.produce_leaf(&job()).unwrap();
        assert_eq!(again.leaf_hash, minted.leaf_hash);
    }

    #[test]
    fn cross_class_providers_do_not_match_no_leaf() {
        // Two DIFFERENT runtime classes (different gpu_arch_class) never exact-match → no leaf.
        let miner = PalwMiner::new(
            MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2),
            MockDeterministicRuntime::new(profile(PalwTier::Quality, 200), 3, 2),
            reg(),
        );
        assert_eq!(miner.produce_leaf(&job()).unwrap_err(), MineError::ReplicaMismatch);
    }

    #[test]
    fn a_faulty_provider_breaks_the_match() {
        // Provider B computes a wrong answer for the same job ⇒ mismatch ⇒ no leaf.
        struct Faulty(MockDeterministicRuntime);
        impl VerifiableInferenceBackend for Faulty {
            fn profile(&self) -> &PalwRuntimeProfileV1 {
                self.0.profile()
            }
            fn infer_with_trace(
                &self,
                js: &[u8],
                prompt: &[u8],
                salt: &[u8; 32],
            ) -> misaka_palw::palw::DeterministicInferenceOutputV1 {
                // Perturb the prompt so the deterministic output (and thus the match key) differs.
                let mut p = prompt.to_vec();
                p.push(0xFF);
                self.0.infer_with_trace(js, &p, salt)
            }
        }
        let miner = PalwMiner::new(
            MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2),
            Faulty(MockDeterministicRuntime::new(profile(PalwTier::Quality, 100), 3, 2)),
            reg(),
        );
        assert_eq!(miner.produce_leaf(&job()).unwrap_err(), MineError::ReplicaMismatch);
    }
}
