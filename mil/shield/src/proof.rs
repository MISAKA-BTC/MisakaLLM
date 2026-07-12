//! The versioned proof envelope the **F006 `SHIELDED_VERIFY`** precompile
//! verifies. Keeping the contract/precompile proof-system-agnostic (ADR-0033
//! §5.1 `proof_system_id` / `circuit_version` / `verifier_key_hash`) is what lets
//! the zero-knowledge STARK drop in later without touching the pool, the escrow,
//! or the statements.

use crate::provider::{self, ProviderClaimStatement, ProviderClaimStatementV2, ProviderClaimWitness, ProviderClaimWitnessV2};
use crate::spend::{self, SpendStatement, SpendWitness};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash64;

/// Transparent reference system: `proof` carries the witness in the clear. Sound
/// but **not** zero-knowledge — testing + escrow-capped testnet stepping-stone.
pub const PROOF_SYSTEM_REFERENCE: u8 = 0x01;
/// Production system: hash-based STARK (S-two / Circle-STARK). Zero-knowledge +
/// succinct; verifier lands under ADR-0033 §SP-0 (single proof under the 32 KiB
/// payload cap). Statements/public-inputs are unchanged from the reference.
pub const PROOF_SYSTEM_STARK: u8 = 0x02;

/// Value-pool JoinSplit (L2 payment shield).
pub const CIRCUIT_SPEND: u16 = 1;
/// Anonymous provider claim (which-GPU unlinkability).
pub const CIRCUIT_PROVIDER_CLAIM: u16 = 2;
/// Anonymous provider claim v2 (ADR-0037 §2.2 hidden-amount statement + the audit
/// C-06.2/C-01 contract-computed `provider_share_sompi` payout binding). Statement
/// layout frozen by [`crate::statement_schema::PROVIDER_CLAIM_V2_STATEMENT_SCHEMA`]
/// (392 B), byte-identical to `MilShieldedEscrow._borshClaimStatementV2`.
/// (`3` is reserved for the C-P6 receipt-validity circuit.)
pub const CIRCUIT_PROVIDER_CLAIM_V2: u16 = 4;

/// The F006 calldata payload (after the `input[0]` version/kind discriminator the
/// precompile strips): a self-describing proof over one shielded statement.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShieldProof {
    pub proof_system_id: u8,
    pub circuit_version: u16,
    /// Governance-pinned verifier key hash for `(proof_system_id, circuit_version)`.
    pub verifier_key_hash: Hash64,
    /// The statement's public inputs (borsh of `SpendStatement` /
    /// `ProviderClaimStatement`). The contract reconstructs these from its own
    /// state and calldata, so a valid proof binds to values it already trusts.
    pub public_inputs: Vec<u8>,
    /// The proof (reference: borsh witness; STARK: the succinct proof bytes).
    pub proof: Vec<u8>,
}

impl ShieldProof {
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh of an in-memory proof is infallible")
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ShieldVerifyError> {
        Self::try_from_slice(bytes).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))
    }
}

/// The verified public statement returned to the precompile/contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedStatement {
    Spend(SpendStatement),
    ProviderClaim(ProviderClaimStatement),
    ProviderClaimV2(ProviderClaimStatementV2),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShieldVerifyError {
    #[error("malformed shield proof: {0}")]
    Malformed(String),
    #[error("unknown proof system id {0:#04x}")]
    UnknownProofSystem(u8),
    #[error("unknown circuit version {0}")]
    UnknownCircuit(u16),
    #[error("circuit version {0} is not in the verifier-key registry (unregistered/inactive on this network)")]
    CircuitNotRegistered(u16),
    #[error("verifier key hash does not match the pinned key for this circuit")]
    VerifierKeyMismatch,
    #[error("proof system {0:#04x} is not activated (STARK verifier is the ADR-0033 §SP-0 milestone)")]
    ProofSystemNotActivated(u8),
    #[error("spend statement invalid: {0}")]
    Spend(#[from] spend::SpendError),
    #[error("provider claim invalid: {0}")]
    ProviderClaim(#[from] provider::ProviderClaimError),
}

/// A pluggable verifier for [`PROOF_SYSTEM_STARK`] — the one seam of the
/// reference→STARK swap (ADR-0034 §5). The zero-knowledge backend
/// (`misaka-mil-shield-stark-verify`) implements this and returns the decoded
/// public statement on success; until the ADR-0033 §SP-0 milestone the node links
/// [`InertStarkVerifier`], so a STARK proof is rejected fail-closed and F006 stays
/// byte-identical. Swapping in the real backend is the *entire* code change.
pub trait StarkVerifier {
    /// Verify `proof` over `public_inputs` for `circuit_version` under `vk_hash`,
    /// returning the decoded [`VerifiedStatement`] on success. Fail-closed: any
    /// invalid/malformed/inactive input is an `Err` (mapped to ABI false), never a
    /// panic (a consensus-critical determinism requirement — ADR-0034 §3).
    fn verify(
        &self,
        circuit_version: u16,
        vk_hash: &Hash64,
        public_inputs: &[u8],
        proof: &[u8],
    ) -> Result<VerifiedStatement, ShieldVerifyError>;
}

/// The STARK verifier linked until the ADR-0033 §SP-0 milestone: it rejects every
/// STARK proof, so the pool cannot be activated "live but non-private". Behavior is
/// byte-identical to the pre-seam `verify_shield_proof` (the F006 fence is
/// `u64::MAX` anyway), so all existing tests and on-chain execution are unchanged.
pub struct InertStarkVerifier;

impl StarkVerifier for InertStarkVerifier {
    fn verify(
        &self,
        _circuit_version: u16,
        _vk_hash: &Hash64,
        _public_inputs: &[u8],
        _proof: &[u8],
    ) -> Result<VerifiedStatement, ShieldVerifyError> {
        Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK))
    }
}

/// The proof-system acceptance policy (audit H-03). A CONSENSUS parameter: production
/// must be [`ProofPolicy::StarkOnly`] so a transparent (non-zero-knowledge) reference
/// witness is rejected even if a caller or a second contract tags it — otherwise the
/// privacy + provider-receipt semantics can be bypassed by submitting a reference proof.
/// The reference arm exists ONLY as a testnet stepping-stone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofPolicy {
    /// Testnet: transparent reference proofs are accepted (escrow-capped stepping-stone).
    ReferenceAndStark,
    /// Production: only the zero-knowledge STARK proof system is accepted.
    StarkOnly,
}

/// Verify a shielded proof against the pinned verifier key using the node's STARK
/// verifier (inert until §SP-0). On `Ok` the returned [`VerifiedStatement`] carries
/// the public inputs the caller enforces against pool/escrow state (nullifier
/// freshness, anchor-in-ring, commitment insertion).
///
/// CALLER OBLIGATION — nullifier application MUST be sequential check-then-insert
/// per nullifier within one statement: check `nf_old[0]` unspent → insert it →
/// check `nf_old[1]` → insert it. Neither the relation (`verify_reference`) nor the
/// circuit enforces `nf_old[0] != nf_old[1]`; a batch check that tests both against
/// the pre-state and then inserts both would accept a spend using the SAME note in
/// both input slots (value double-count). Sequential check-insert rejects it for
/// free. (Dummy-lane nullifiers are indistinguishable from real ones — the enable
/// bit is private — so both are always inserted; wallets randomize dummy nfs.)
///
/// Fail-closed: any malformed/unknown/mismatched/false input is an `Err`, never a
/// panic (the precompile maps `Ok → 0x…01`, `Err → 0x…00`).
pub fn verify_shield_proof(bytes: &[u8], pinned_vk_hash: &Hash64) -> Result<VerifiedStatement, ShieldVerifyError> {
    verify_shield_proof_with(bytes, pinned_vk_hash, &InertStarkVerifier)
}

/// The extensible form (ADR-0034 §5): the REFERENCE arm is verified in-process; the
/// STARK arm delegates to the injected `stark` backend. This is the single
/// code-diff surface of the reference→STARK swap — construct with the real backend
/// instead of [`InertStarkVerifier`] and nothing else in the L2 stack changes.
pub fn verify_shield_proof_with<V: StarkVerifier>(
    bytes: &[u8],
    pinned_vk_hash: &Hash64,
    stark: &V,
) -> Result<VerifiedStatement, ShieldVerifyError> {
    // Default policy is the testnet stepping-stone; production callers use the explicit
    // `_with_policy` form with `StarkOnly` (audit H-03).
    verify_shield_proof_with_policy(bytes, pinned_vk_hash, stark, ProofPolicy::ReferenceAndStark)
}

/// Policy-aware verify (audit H-03): under [`ProofPolicy::StarkOnly`] a `PROOF_SYSTEM_REFERENCE`
/// proof is rejected before it is ever evaluated, so production cannot be tricked into
/// accepting a transparent witness. This is the acceptance-policy consensus parameter the
/// F006 wiring must pass (production preset ⇒ `StarkOnly`).
pub fn verify_shield_proof_with_policy<V: StarkVerifier>(
    bytes: &[u8],
    pinned_vk_hash: &Hash64,
    stark: &V,
    policy: ProofPolicy,
) -> Result<VerifiedStatement, ShieldVerifyError> {
    let p = ShieldProof::decode(bytes)?;
    if &p.verifier_key_hash != pinned_vk_hash {
        return Err(ShieldVerifyError::VerifierKeyMismatch);
    }
    if policy == ProofPolicy::StarkOnly && p.proof_system_id == PROOF_SYSTEM_REFERENCE {
        return Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_REFERENCE));
    }
    match p.proof_system_id {
        PROOF_SYSTEM_REFERENCE => match p.circuit_version {
            CIRCUIT_SPEND => {
                let stmt =
                    SpendStatement::try_from_slice(&p.public_inputs).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                let wit = SpendWitness::try_from_slice(&p.proof).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                spend::verify_reference(&stmt, &wit)?;
                Ok(VerifiedStatement::Spend(stmt))
            }
            CIRCUIT_PROVIDER_CLAIM => {
                let stmt = ProviderClaimStatement::try_from_slice(&p.public_inputs)
                    .map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                let wit = ProviderClaimWitness::try_from_slice(&p.proof).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                provider::verify_reference(&stmt, &wit)?;
                Ok(VerifiedStatement::ProviderClaim(stmt))
            }
            // (audit C-01) the hidden-amount claim with the C-06.2 payout binding:
            // `verify_reference_v2` enforces amount == provider_share_sompi on top of
            // membership/nullifier/commitment openings.
            CIRCUIT_PROVIDER_CLAIM_V2 => {
                let stmt = ProviderClaimStatementV2::try_from_slice(&p.public_inputs)
                    .map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                let wit = ProviderClaimWitnessV2::try_from_slice(&p.proof).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                provider::verify_reference_v2(&stmt, &wit)?;
                Ok(VerifiedStatement::ProviderClaimV2(stmt))
            }
            other => Err(ShieldVerifyError::UnknownCircuit(other)),
        },
        // The STARK verifier is the production/ZK milestone; the injected backend
        // is `InertStarkVerifier` until §SP-0, so a STARK proof is rejected rather
        // than silently accepted (the F006 fence is u64::MAX anyway).
        PROOF_SYSTEM_STARK => stark.verify(p.circuit_version, &p.verifier_key_hash, &p.public_inputs, &p.proof),
        other => Err(ShieldVerifyError::UnknownProofSystem(other)),
    }
}

/// (audit K-01.3) The per-circuit verifier-key registry. Each ACTIVATED `circuit_version` maps to
/// its governance-pinned `vk_hash` AND its acceptance [`ProofPolicy`] (`StarkOnly` in production,
/// `ReferenceAndStark` for the testnet stepping-stone). The node verifies against THIS registry so
/// a proof for an UNREGISTERED circuit — an unknown/typo'd version, or a circuit not yet activated
/// on this network — is rejected fail-closed BEFORE any crypto. `verify_shield_proof` pins a single
/// key at a time; the registry is what lets a network safely run circuits 1/2 (live), 3 (C-P6), and
/// 4 (claim-v2) each under its own key + policy. Adding a circuit is a governance action (register
/// its ceremony VK); a circuit is un-activatable simply by leaving it out.
#[derive(Debug, Clone, Default)]
pub struct ShieldVkRegistry {
    entries: Vec<(u16, Hash64, ProofPolicy)>,
}

impl ShieldVkRegistry {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Register (or replace) a circuit's pinned VK hash + acceptance policy.
    pub fn with_circuit(mut self, circuit_version: u16, vk_hash: Hash64, policy: ProofPolicy) -> Self {
        self.entries.retain(|(c, _, _)| *c != circuit_version);
        self.entries.push((circuit_version, vk_hash, policy));
        self
    }

    /// The pinned VK + policy for `circuit_version`, or `None` if not registered.
    pub fn lookup(&self, circuit_version: u16) -> Option<(&Hash64, ProofPolicy)> {
        self.entries.iter().find(|(c, _, _)| *c == circuit_version).map(|(_, vk, p)| (vk, *p))
    }
}

/// (audit K-01.3) Verify a shield proof against the per-circuit registry: look up the pinned VK +
/// policy for the proof's `circuit_version`, rejecting an unregistered circuit fail-closed, then
/// verify under exactly that key + policy. This is the node's production entry point once multiple
/// circuits are activated (it subsumes `verify_shield_proof_with_policy`, which pins one key).
pub fn verify_shield_proof_with_registry<V: StarkVerifier>(
    bytes: &[u8],
    registry: &ShieldVkRegistry,
    stark: &V,
) -> Result<VerifiedStatement, ShieldVerifyError> {
    let p = ShieldProof::decode(bytes)?;
    let (vk_hash, policy) = registry.lookup(p.circuit_version).ok_or(ShieldVerifyError::CircuitNotRegistered(p.circuit_version))?;
    verify_shield_proof_with_policy(bytes, vk_hash, stark, policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{MerklePath, MerkleTree, TREE_DEPTH};
    use crate::note::{Commitment, Note, Nullifier, commit, derive_output_rho, nullifier, shielded_address};

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }
    fn vk() -> Hash64 {
        h(0xB0)
    }

    // A CONTRACT-CONSISTENT claim-v2 `ctx` for fixtures — the sole authority is the
    // contract's `_computeClaimCtx`, mirrored by `evm_ctx::claim_ctx_onchain` over the
    // 404-byte deployment preimage (audit H-01). Deployment-scoped fields are fixed to the
    // representative placeholders the `evm_ctx` differential test uses; the reference
    // relation binds whatever `ctx` the public inputs carry and never re-derives it.
    fn claim_ctx_fixture(set_root: &Hash64, session_cm: &Hash64, provider_nf: &Nullifier, cm_payout: &Commitment) -> Hash64 {
        let mut chain_id = [0u8; 32];
        chain_id[31] = 1;
        let mut gross = [0u8; 32];
        gross[31] = 88;
        crate::evm_ctx::claim_ctx_onchain(&chain_id, &[0xaa; 20], &[0x07; 32], set_root, session_cm, &gross, provider_nf, cm_payout, &[0x08; 32])
    }

    // A reference spend proof (shield 100 → one 100-note).
    fn spend_proof(vk_hash: Hash64) -> Vec<u8> {
        let dummy = Note { value: 0, owner_pk: h(0), rho: h(0), r: h(0), token_id: 0 };
        let nf0 = nullifier(&h(1), &dummy.rho);
        let nf1 = nullifier(&h(2), &dummy.rho);
        let out0 =
            Note { value: 100, owner_pk: shielded_address(&h(0x71)), rho: derive_output_rho(&nf0, &nf1, 0), r: h(0x31), token_id: 0 };
        let out1 = Note { value: 0, owner_pk: h(0), rho: derive_output_rho(&nf0, &nf1, 1), r: h(0), token_id: 0 };
        let stmt = SpendStatement {
            anchor: h(0),
            nf_old: [nf0, nf1],
            cm_new: [commit(&out0), commit(&out1)],
            v_pub_in: 100,
            v_pub_out: 0,
            token_id: 0,
            ctx: h(0xC7),
        };
        let wit = SpendWitness {
            notes_in: [dummy, dummy],
            sk_in: [h(1), h(2)],
            paths_in: [MerklePath { siblings: vec![], index: 0 }, MerklePath { siblings: vec![], index: 0 }],
            enable_in: [false, false],
            notes_out: [out0, out1],
        };
        ShieldProof {
            proof_system_id: PROOF_SYSTEM_REFERENCE,
            circuit_version: CIRCUIT_SPEND,
            verifier_key_hash: vk_hash,
            public_inputs: borsh::to_vec(&stmt).unwrap(),
            proof: borsh::to_vec(&wit).unwrap(),
        }
        .encode()
    }

    // A reference provider-claim proof (circuit 2 — public amount), fuzz-seed quality:
    // a real 8-leaf registry, real Merkle path, real nullifier/commitment openings.
    fn claim_proof(vk_hash: Hash64) -> Vec<u8> {
        let (pkh, sec) = (h(0x41), h(0x81));
        let mut tree = MerkleTree::new(TREE_DEPTH);
        let idx = tree.append(Commitment(provider::provider_leaf(&pkh, &shielded_address(&sec))));
        let session_cm = h(0x5E);
        let amount = 500u64;
        let payout = Note { value: amount, owner_pk: shielded_address(&h(0x71)), rho: h(1), r: h(2), token_id: 0 };
        let cm_payout = commit(&payout);
        let provider_nf = provider::provider_nullifier(&sec, &session_cm);
        let stmt = ProviderClaimStatement {
            provider_set_root: tree.root(),
            session_cm,
            amount,
            provider_nf,
            cm_payout,
            ctx: provider::claim_ctx(&session_cm, amount, &cm_payout, &provider_nf),
        };
        let wit = ProviderClaimWitness {
            pk_receipt_hash: pkh,
            claim_secret: sec,
            leaf_index: idx,
            path: tree.path(idx).unwrap(),
            payout_note: payout,
        };
        ShieldProof {
            proof_system_id: PROOF_SYSTEM_REFERENCE,
            circuit_version: CIRCUIT_PROVIDER_CLAIM,
            verifier_key_hash: vk_hash,
            public_inputs: borsh::to_vec(&stmt).unwrap(),
            proof: borsh::to_vec(&wit).unwrap(),
        }
        .encode()
    }

    // A reference provider-claim V2 proof (circuit 4 — hidden amount + C-06.2 share binding).
    fn claim_v2_proof(vk_hash: Hash64) -> Vec<u8> {
        let (pkh, sec) = (h(0x42), h(0x82));
        let mut tree = MerkleTree::new(TREE_DEPTH);
        let idx = tree.append(Commitment(provider::provider_leaf(&pkh, &shielded_address(&sec))));
        let session_cm = h(0x5D);
        let share = 1_636_000u64;
        let blind = h(0xB1);
        let v_claim_cm = provider::value_commit(share, &blind);
        let payout = Note { value: share, owner_pk: shielded_address(&h(0x72)), rho: h(3), r: h(4), token_id: 0 };
        let cm_payout = commit(&payout);
        let provider_nf = provider::provider_nullifier(&sec, &session_cm);
        let stmt = ProviderClaimStatementV2 {
            provider_set_root: tree.root(),
            session_cm,
            v_claim_cm,
            provider_nf,
            cm_payout,
            provider_share_sompi: share,
            ctx: claim_ctx_fixture(&tree.root(), &session_cm, &provider_nf, &cm_payout),
        };
        let wit = ProviderClaimWitnessV2 {
            pk_receipt_hash: pkh,
            claim_secret: sec,
            leaf_index: idx,
            path: tree.path(idx).unwrap(),
            payout_note: payout,
            amount: share,
            blind,
        };
        ShieldProof {
            proof_system_id: PROOF_SYSTEM_REFERENCE,
            circuit_version: CIRCUIT_PROVIDER_CLAIM_V2,
            verifier_key_hash: vk_hash,
            public_inputs: borsh::to_vec(&stmt).unwrap(),
            proof: borsh::to_vec(&wit).unwrap(),
        }
        .encode()
    }

    #[test]
    fn reference_spend_proof_verifies_via_envelope() {
        let bytes = spend_proof(vk());
        let v = verify_shield_proof(&bytes, &vk()).expect("valid reference spend must verify");
        assert!(matches!(v, VerifiedStatement::Spend(_)));
    }

    #[test]
    fn wrong_verifier_key_is_rejected() {
        let bytes = spend_proof(vk());
        assert_eq!(verify_shield_proof(&bytes, &h(0x00)), Err(ShieldVerifyError::VerifierKeyMismatch));
    }

    #[test]
    fn registry_looks_up_per_circuit_vk_and_rejects_unregistered() {
        let bytes = spend_proof(vk()); // circuit 1 (CIRCUIT_SPEND), pinned vk = vk()

        // (1) registered circuit with the matching VK + testnet policy → verifies.
        let reg = ShieldVkRegistry::new().with_circuit(CIRCUIT_SPEND, vk(), ProofPolicy::ReferenceAndStark);
        assert!(matches!(verify_shield_proof_with_registry(&bytes, &reg, &InertStarkVerifier), Ok(VerifiedStatement::Spend(_))));

        // (2) circuit NOT in the registry (only circuit 2 registered) → CircuitNotRegistered(1),
        //     fail-closed BEFORE any crypto: a not-yet-activated circuit cannot be used.
        let reg_other = ShieldVkRegistry::new().with_circuit(CIRCUIT_PROVIDER_CLAIM, vk(), ProofPolicy::ReferenceAndStark);
        assert_eq!(
            verify_shield_proof_with_registry(&bytes, &reg_other, &InertStarkVerifier),
            Err(ShieldVerifyError::CircuitNotRegistered(CIRCUIT_SPEND))
        );

        // (3) registered but with the WRONG pinned VK → VerifierKeyMismatch (the registry key wins).
        let reg_wrongvk = ShieldVkRegistry::new().with_circuit(CIRCUIT_SPEND, h(0xEE), ProofPolicy::ReferenceAndStark);
        assert_eq!(
            verify_shield_proof_with_registry(&bytes, &reg_wrongvk, &InertStarkVerifier),
            Err(ShieldVerifyError::VerifierKeyMismatch)
        );

        // (4) a StarkOnly (production) circuit rejects the transparent reference proof.
        let reg_starkonly = ShieldVkRegistry::new().with_circuit(CIRCUIT_SPEND, vk(), ProofPolicy::StarkOnly);
        assert_eq!(
            verify_shield_proof_with_registry(&bytes, &reg_starkonly, &InertStarkVerifier),
            Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_REFERENCE))
        );

        // (5) with_circuit REPLACES (no duplicate entries): re-registering circuit 1 updates its VK.
        let reg_replaced = ShieldVkRegistry::new().with_circuit(CIRCUIT_SPEND, h(0xEE), ProofPolicy::ReferenceAndStark).with_circuit(
            CIRCUIT_SPEND,
            vk(),
            ProofPolicy::ReferenceAndStark,
        );
        assert!(verify_shield_proof_with_registry(&bytes, &reg_replaced, &InertStarkVerifier).is_ok());
    }

    #[test]
    fn malformed_shield_proofs_never_panic() {
        // (audit M-07 malformed-proof fuzz / M-05R panic-free): the envelope decode + reference
        // verify path must return `Err` on ANY adversarial byte string and NEVER panic — a
        // consensus-determinism requirement (a panic in F006 is a chain split). Over 20k structured
        // adversarial inputs (random, truncated, bit-flipped, garbage-suffixed), every call must
        // return without unwinding; a panic anywhere fails this test.
        //
        // (audit 2026-07-11 M-05, seed coverage) mutation SEEDS cover every registered circuit —
        // spend (1), provider-claim v1 (2), provider-claim v2 (4) — not only the spend proof, so
        // the claim-side reference relations (`provider::verify_reference{,_v2}`: Merkle membership,
        // nullifier, value-commitment and share-binding arms) see the same corpus the spend
        // relation does. The earlier revision seeded only the spend proof.
        // splitmix64 (audit M-05): the previous LCG's low bits have tiny periods
        // (low-2 period 4), which can lock the `% 4` class selector into a cycle that
        // starves whole mutation classes; splitmix64 avalanches the low bits.
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut rng = || {
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let seeds = [spend_proof(vk()), claim_proof(vk()), claim_v2_proof(vk())];
        let reg = ShieldVkRegistry::new()
            .with_circuit(CIRCUIT_SPEND, vk(), ProofPolicy::ReferenceAndStark)
            .with_circuit(CIRCUIT_PROVIDER_CLAIM, vk(), ProofPolicy::ReferenceAndStark)
            .with_circuit(CIRCUIT_PROVIDER_CLAIM_V2, vk(), ProofPolicy::ReferenceAndStark);
        // sanity: every seed verifies before mutation (the corpus mutates VALID proofs).
        for s in &seeds {
            assert!(verify_shield_proof_with_registry(s, &reg, &InertStarkVerifier).is_ok(), "seed proof must verify");
        }
        // corpus-quality counter: mutants whose ENVELOPE still decodes reach the inner
        // statement/witness decode + reference relations; asserted below so a weak
        // generator that starves the decodable classes fails loudly instead of proving
        // nothing (the original LCG's low-bit periods starved `% 4` class selection).
        let mut n_decodable = 0u32;
        for i in 0..21_000 {
            let valid = &seeds[i % seeds.len()];
            let bytes: Vec<u8> = match rng() % 4 {
                0 => {
                    // pure random bytes, random length.
                    let len = (rng() % 512) as usize;
                    (0..len).map(|_| (rng() & 0xff) as u8).collect()
                }
                1 => {
                    // a truncation of a valid proof (exercises short-read decode paths).
                    let n = (rng() as usize) % (valid.len() + 1);
                    valid[..n].to_vec()
                }
                2 => {
                    // a valid proof with a few random bytes flipped (corrupted lengths/fields).
                    let mut v = valid.clone();
                    for _ in 0..(rng() % 16) {
                        let i = (rng() as usize) % v.len();
                        v[i] ^= (rng() & 0xff) as u8;
                    }
                    v
                }
                _ => {
                    // a valid proof with random trailing garbage.
                    let mut v = valid.clone();
                    v.extend((0..(rng() % 64)).map(|_| (rng() & 0xff) as u8));
                    v
                }
            };
            n_decodable += ShieldProof::decode(&bytes).is_ok() as u32;
            // Both entry points must return (Ok/Err) without panicking; a panic fails the test.
            let _ = verify_shield_proof(&bytes, &vk());
            let _ = verify_shield_proof_with_registry(&bytes, &reg, &InertStarkVerifier);
        }
        // corpus reach: the bit-flip class decodes most of the time (only the two Vec
        // length prefixes are structurally fragile), measured ~4.6k of 21k with splitmix64;
        // ≥ 500 is a loose floor that fails loudly on generator regression.
        assert!(n_decodable >= 500, "corpus starved: only {n_decodable} decodable envelope mutants");
    }

    #[test]
    fn stark_system_is_inert_not_accepted() {
        // A STARK-tagged proof is rejected (fail-closed) until the milestone.
        let mut p = ShieldProof::decode(&spend_proof(vk())).unwrap();
        p.proof_system_id = PROOF_SYSTEM_STARK;
        assert_eq!(verify_shield_proof(&p.encode(), &vk()), Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK)));
    }

    #[test]
    fn stark_arm_routes_to_injected_backend() {
        // The reference→STARK swap (ADR-0034 §5) is exactly "inject a real backend
        // instead of InertStarkVerifier". A mock backend that accepts a STARK-tagged
        // proof and returns the decoded statement proves the seam is wired and that
        // swapping it in is the whole change — while the production entry point
        // (inert verifier) still rejects the identical bytes.
        struct Accepting;
        impl StarkVerifier for Accepting {
            fn verify(
                &self,
                circuit_version: u16,
                _vk: &Hash64,
                public_inputs: &[u8],
                _proof: &[u8],
            ) -> Result<VerifiedStatement, ShieldVerifyError> {
                assert_eq!(circuit_version, CIRCUIT_SPEND);
                let stmt = SpendStatement::try_from_slice(public_inputs).map_err(|e| ShieldVerifyError::Malformed(e.to_string()))?;
                Ok(VerifiedStatement::Spend(stmt))
            }
        }
        let mut p = ShieldProof::decode(&spend_proof(vk())).unwrap();
        p.proof_system_id = PROOF_SYSTEM_STARK;
        let bytes = p.encode();
        // injected backend accepts → decoded statement flows back to the caller
        let v = verify_shield_proof_with(&bytes, &vk(), &Accepting).expect("injected backend accepts");
        assert!(matches!(v, VerifiedStatement::Spend(_)));
        // wrong pinned vk is still rejected before the backend is ever consulted
        assert_eq!(verify_shield_proof_with(&bytes, &h(0x00), &Accepting), Err(ShieldVerifyError::VerifierKeyMismatch));
        // the production entry (inert backend) rejects the very same bytes
        assert_eq!(verify_shield_proof(&bytes, &vk()), Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK)));
    }

    #[test]
    fn h03_stark_only_policy_rejects_reference_proof() {
        // A valid reference proof verifies under the testnet policy…
        let bytes = spend_proof(vk());
        assert!(verify_shield_proof_with_policy(&bytes, &vk(), &InertStarkVerifier, ProofPolicy::ReferenceAndStark).is_ok());
        // …but is REJECTED under the production StarkOnly policy, before evaluation.
        assert_eq!(
            verify_shield_proof_with_policy(&bytes, &vk(), &InertStarkVerifier, ProofPolicy::StarkOnly),
            Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_REFERENCE))
        );
    }

    #[test]
    fn provider_claim_proof_verifies_via_envelope() {
        let v = verify_shield_proof(&claim_proof(vk()), &vk()).expect("valid provider claim must verify");
        assert!(matches!(v, VerifiedStatement::ProviderClaim(_)));
        // and the v2 (hidden-amount) envelope verifies through the same entry point.
        let v2 = verify_shield_proof(&claim_v2_proof(vk()), &vk()).expect("valid provider claim v2 must verify");
        assert!(matches!(v2, VerifiedStatement::ProviderClaimV2(_)));
    }
}
