//! In-consensus STARK verifier for the MIL shielded pool (ADR-0034 §4/§5).
//!
//! [`StarkBackend`] implements [`misaka_mil_shield::StarkVerifier`], so the whole
//! reference→STARK swap is: the F006 precompile calls
//! `misaka_mil_shield::verify_shield_proof_with(bytes, vk, &StarkBackend)` instead
//! of the default inert verifier. Nothing else in the L2 stack changes.
//!
//! **Consensus determinism (SP-04) is a hard requirement.** This verifier runs in
//! block validation; every node must reach the SAME accept/reject for the SAME
//! `(vk, public_inputs, proof)`, bit-for-bit, on every platform — a divergence is
//! a consensus split, not a bug to patch later (the same bar as the F003 audit
//! finding H-2). The eventual implementation MUST therefore:
//!
//! - use only fixed-width field/integer arithmetic (M31), never floats;
//! - keep the accept/reject decision free of SIMD-/CPU-feature-dependent control
//!   flow (a data path may use SIMD; the decision may not branch on it);
//! - draw every Fiat-Shamir challenge from a fixed, versioned transcript hashed
//!   with keyed BLAKE2b-512 (the chain's canonical, PQ hash);
//! - be panic-free: malformed proof bytes / out-of-range field elements / bad
//!   lengths return `Err`, never unwind (F006 maps `Err → ABI false`).
//!
//! Until the audited §SP-0 milestone, [`verify_stark`] returns
//! [`StarkVerifyError::BackendPending`] and the trait maps it to the same
//! `ProofSystemNotActivated` error the default inert verifier returns — so a node
//! that links this crate behaves byte-identically to one that does not, and the
//! pool cannot be activated "live but non-private".

use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{Hash64, blake2b_512_keyed};
use misaka_mil_shield::proof::{CIRCUIT_PROVIDER_CLAIM, CIRCUIT_SPEND, PROOF_SYSTEM_STARK};
use misaka_mil_shield::provider::ProviderClaimStatement;
use misaka_mil_shield::spend::SpendStatement;
use misaka_mil_shield::{ShieldVerifyError, StarkVerifier, VerifiedStatement};

// ============================================================================
// A3 — vk_hash + the consensus-boundary keyed-BLAKE2b binding (SP-04)
// ============================================================================
//
// The STARK's own Fiat-Shamir transcript is Poseidon2 (fixed by the recursion stack,
// ADR-0035 §5.3) and MUST stay Poseidon2 — it is arithmetized in-circuit and cannot be
// swapped to BLAKE2b without re-proving every layer. So the chain's canonical keyed
// BLAKE2b-512 is applied as the OUTER, consensus-controlled binding, NOT the internal
// challenger:
//   1. `vk_hash` — a keyed-BLAKE2b digest over the FULL canonical verifier context
//      (field, extension degree, Poseidon2 constants id, the FRI parameters that live
//      in the verifier config, the security level, the table packing / row shape, the
//      non-primitive op set, and the preprocessed-commitment fingerprint). The
//      governance vk-pinning ceremony computes this once and pins it on-chain
//      (`ShieldedPool.spendVkHash`); a proof whose reconstructed context hashes
//      differently is rejected before the STARK verify runs. Because the FRI params
//      live in the config (not the proof), pinning them here is load-bearing for
//      soundness (wrong num_queries ⇒ the FRI verify itself would reject, but pinning
//      makes the intent explicit and catches a mis-provisioned verifier).
//   2. `bind_artifact` — a keyed-BLAKE2b digest over (vk_hash ‖ statement ‖ proof) that
//      the consensus layer records/derives, tying the exact proof bytes to the exact
//      statement at the chain boundary (defence-in-depth alongside the in-proof
//      statement binding, §SP-0 CRITICAL-2).
//
// Both are keyed BLAKE2b-512, deterministic (fixed-width, no float/SIMD-branch),
// and computed OUTSIDE the FRI soundness transcript, so they do not conflict with the
// Poseidon2 challenger. Versioned by a domain string so the framing can evolve.

/// Domain for the verifier-key fingerprint.
pub const VK_DOMAIN: &[u8] = b"misaka-shield-v1/stark-vk";
/// Domain for the consensus-boundary proof↔statement binding digest.
pub const BIND_DOMAIN: &[u8] = b"misaka-shield-v1/stark-bind";

/// The canonical verifier context that `vk_hash` commits to. Every field that affects
/// the accept/reject decision but is NOT carried inside the proof (or must be pinned so
/// a mis-provisioned verifier cannot silently lower soundness) lives here. Borsh gives a
/// fixed, deterministic, cross-platform encoding.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VerifierContext {
    /// Circuit this vk verifies (`CIRCUIT_SPEND` / `CIRCUIT_PROVIDER_CLAIM`).
    pub circuit_version: u16,
    /// Field tag (0 = BabyBear, 1 = M31/Circle, …) and extension degree D.
    pub field_tag: u8,
    pub ext_degree: u8,
    /// Poseidon2 constants identifier (e.g. a tag for BABY_BEAR_D4_W16).
    pub poseidon2_id: u16,
    /// The FRI parameters that live in the verifier config, not the proof.
    pub log_blowup: u8,
    pub num_queries: u16,
    pub commit_pow_bits: u8,
    pub query_pow_bits: u8,
    pub max_log_arity: u8,
    pub log_final_poly_len: u8,
    pub cap_height: u8,
    /// Conjectured security level (bits) the params target.
    pub security_level: u16,
    /// Canonical table packing + per-table row counts (opaque, canonicalized upstream).
    pub table_packing: Vec<u8>,
    pub rows: Vec<u8>,
    /// Sorted non-primitive op-type ids (dedup + sorted for canonicity).
    pub non_primitive_ops: Vec<u16>,
    /// The preprocessed-commitment fingerprint — the circuit-stable Merkle-cap that
    /// commits every AIR's preprocessed (constant/selector) columns.
    pub preprocessed_commitment: Vec<u8>,
}

impl VerifierContext {
    /// Canonicalize (sort/dedup the non-primitive ops) so equal circuits hash equal.
    pub fn canonical(mut self) -> Self {
        self.non_primitive_ops.sort_unstable();
        self.non_primitive_ops.dedup();
        self
    }
}

/// `vk_hash = H_k(VK_DOMAIN, borsh(canonical context))`. Deterministic and versioned;
/// the value the governance ceremony pins on-chain and the node checks against.
pub fn compute_vk_hash(ctx: &VerifierContext) -> Hash64 {
    let bytes = borsh::to_vec(&ctx.clone().canonical()).expect("borsh of an in-memory context is infallible");
    blake2b_512_keyed(VK_DOMAIN, &bytes)
}

/// `bind = H_k(BIND_DOMAIN, vk_hash ‖ statement ‖ proof)` — the consensus-boundary tie
/// between exactly these proof bytes and exactly this statement.
pub fn bind_artifact(vk_hash: &Hash64, statement: &[u8], proof: &[u8]) -> Hash64 {
    let mut data = Vec::with_capacity(64 + statement.len() + proof.len());
    data.extend_from_slice(vk_hash.as_byte_slice());
    data.extend_from_slice(statement);
    data.extend_from_slice(proof);
    blake2b_512_keyed(BIND_DOMAIN, &data)
}

/// Upper bound on the STARK proof-field bytes the verifier back half will process, a
/// DoS guard for the (pending) verify loop. A recursion outer proof measures ~40–382 KiB
/// (ADR-0035 §4 / ADR-0036 — over the 32 KiB per-block payload cap, so it is
/// chunk-transported and reassembled off the hot path before reaching here). This cap is
/// deliberately generous; **PROVISIONAL** — the exact value is frozen by ADR-0036 O-SP-1
/// (windowed DA budget) alongside `F006_VERIFY_GAS`, a governance parameter.
///
/// NOTE on allocation: this constant bounds the INNER `proof` field *after* the outer
/// `ShieldProof` borsh decode; it does not front that decode. The pre-decode allocation
/// is already bounded — borsh's `cautious`/chunked `Vec<u8>` reads never allocate from a
/// length prefix beyond the finite calldata, and the calldata is itself capped by the EVM
/// payload / `F006_VERIFY_GAS` ceiling — so a giant length prefix yields `UnexpectedEof`,
/// not an unbounded allocation. This cap's job is to bound the verify loop's work, not the
/// decode's memory.
pub const MAX_STARK_PROOF_BYTES: usize = 1 << 20; // 1 MiB
/// Upper bound on the public-input (borsh statement) bytes. The frozen statements have a
/// FIXED encoding (all fields fixed-width, no `Vec`): `SpendStatement` = 404 B,
/// `ProviderClaimStatement` = 328 B (ADR-0034 §7 P1). A valid statement's length is thus
/// exact and always ≤ this cap, so the cap never false-rejects a valid statement; it only
/// rejects malformed oversize inputs before decode.
pub const MAX_PUBLIC_INPUT_BYTES: usize = 1024;

/// The production in-consensus STARK verifier. Zero-sized: it holds no state, so
/// it is trivially `Send + Sync` and cheap to construct per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct StarkBackend;

/// Errors from the STARK verify. All map to a fail-closed reject at the trait
/// boundary, so every variant is behaviourally identical to the inert node; the
/// distinctions exist for tests and telemetry, never for consensus branching.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StarkVerifyError {
    #[error("unknown circuit version {0}")]
    UnknownCircuit(u16),
    #[error("proof bytes {got} exceed the cap {cap}")]
    ProofTooLarge { got: usize, cap: usize },
    #[error("public inputs {got} exceed the cap {cap}")]
    PublicInputTooLarge { got: usize, cap: usize },
    #[error("malformed public inputs (not a valid statement for the circuit): {0}")]
    MalformedStatement(String),
    #[error("STARK verifier not yet implemented — ADR-0033 §SP-0 milestone (audited)")]
    BackendPending,
    /// (A2) The proof cryptographically verified, but it does NOT surface the on-chain
    /// statement in any non-primitive public-value table, so the node cannot bind it — a
    /// crypto-valid proof could otherwise be replayed onto a different statement. Fail-closed.
    #[error("proof does not surface the on-chain statement (A2 binding: prover-side surfacing pending)")]
    StatementNotSurfaced,
}

/// (A2) The FROZEN encoding of a statement (its borsh public-input bytes) into the field
/// public-values a proof surfaces: **one byte per BabyBear element**, in order. BabyBear's
/// order (`2^31 − 2^27 + 1 ≈ 2.0e9`) far exceeds 255, so every byte is a canonical element
/// and the map is injective. The node re-encodes its on-chain statement with this exact
/// function and requires the proof to carry the identical vector in a public-output table
/// (`proof.non_primitives[k].public_values`), which `verify_all_tables` binds — so a proof
/// valid for a *different* statement cannot be replayed. Kept outside the `stark-backend`
/// feature so the encoding is testable (and identical) in the default build.
pub fn statement_to_pvs(bytes: &[u8]) -> Vec<u64> {
    bytes.iter().map(|&b| b as u64).collect()
}

/// (A2) Node-side statement binding, fail-closed: is the on-chain statement surfaced in one
/// of the proof's public-output tables? `surfaced` is the per-non-primitive-table public
/// values (canonical `u64`) the crypto verify bound; the statement is bound iff one table
/// carries exactly `statement_to_pvs(public_inputs)`. Absence ⇒ `false` (a crypto-valid but
/// unbound proof must NOT be accepted — it would be replayable onto another statement).
pub fn statement_is_bound(surfaced: &[Vec<u64>], public_inputs: &[u8]) -> bool {
    let expected = statement_to_pvs(public_inputs);
    surfaced.iter().any(|pv| *pv == expected)
}

/// The parsed, size-checked public statement for a circuit version. Decoding it is
/// the deterministic, panic-free front half of [`verify_stark`] (SP-04): it does the
/// bounds + borsh parse that must never unwind, independent of the STARK verify
/// itself (the audit-gated §SP-0 back half). Kept public so a differential harness /
/// the recursion-side verifier demonstration can reuse the exact same decode.
pub fn decode_statement(circuit_version: u16, public_inputs: &[u8]) -> Result<VerifiedStatement, StarkVerifyError> {
    if public_inputs.len() > MAX_PUBLIC_INPUT_BYTES {
        return Err(StarkVerifyError::PublicInputTooLarge { got: public_inputs.len(), cap: MAX_PUBLIC_INPUT_BYTES });
    }
    match circuit_version {
        // `try_from_slice` is fallible and non-panicking: a short/oversized/invalid
        // buffer returns Err (mapped below), it never indexes out of bounds or unwinds.
        // The trailing-bytes strictness of borsh means extra bytes are also rejected.
        CIRCUIT_SPEND => SpendStatement::try_from_slice(public_inputs)
            .map(VerifiedStatement::Spend)
            .map_err(|e| StarkVerifyError::MalformedStatement(e.to_string())),
        CIRCUIT_PROVIDER_CLAIM => ProviderClaimStatement::try_from_slice(public_inputs)
            .map(VerifiedStatement::ProviderClaim)
            .map_err(|e| StarkVerifyError::MalformedStatement(e.to_string())),
        other => Err(StarkVerifyError::UnknownCircuit(other)),
    }
}

/// The pure, deterministic verify (front half live, back half pending §SP-0).
///
/// Front half (implemented, SP-04-critical): reject unknown circuits, bound the proof
/// and public-input sizes (DoS guard), and borsh-decode the statement — all
/// panic-free, allocation-bounded, and platform-independent. Back half (the audited
/// §SP-0 milestone, marked SEAM below): decode `proof` as the recursion outer proof,
/// run the hash-based STARK verify against `vk_hash`, and — critically — prove the
/// decoded statement equals the public values the proof was produced over (element
/// for element under the frozen field encoding) so a proof valid for a *different*
/// statement cannot be replayed. Until that lands the seam returns `BackendPending`,
/// so the whole function stays fail-closed. Wiring the real back half pulls in a
/// verify-only Plonky3 subset (p3-batch-stark / p3-recursion), which is the
/// experimental, audit-gated dependency ADR-0035 §8 flags — hence it lands behind
/// this seam, not in the default consensus build.
pub fn verify_stark(
    circuit_version: u16,
    vk_hash: &Hash64,
    public_inputs: &[u8],
    proof: &[u8],
) -> Result<VerifiedStatement, StarkVerifyError> {
    // --- deterministic front half (SP-04): bounds + parse, never panics ---
    if proof.len() > MAX_STARK_PROOF_BYTES {
        return Err(StarkVerifyError::ProofTooLarge { got: proof.len(), cap: MAX_STARK_PROOF_BYTES });
    }
    let statement = decode_statement(circuit_version, public_inputs)?;
    // --- back half: the real STARK verify, behind the `stark-backend` feature ---
    #[cfg(feature = "stark-backend")]
    {
        // (A1) crypto verify the outer proof; returns every non-primitive table's surfaced
        // public values (the field vectors `verify_all_tables` bound).
        let surfaced = backend::verify_outer_proof(vk_hash, proof)?;
        // (A2) NODE-SIDE statement binding, fail-closed: the proof must surface EXACTLY the
        // on-chain statement in one of its public-output tables, under the frozen encoding.
        // A crypto-valid proof whose surfaced statement differs (or is absent) is rejected,
        // so it cannot be replayed onto a different statement at the consensus boundary.
        if statement_is_bound(&surfaced, public_inputs) {
            return Ok(statement);
        }
        return Err(StarkVerifyError::StatementNotSurfaced);
    }
    #[cfg(not(feature = "stark-backend"))]
    {
        // Default node: fail-closed, byte-identical to the inert verifier.
        let _ = (statement, proof, vk_hash);
        Err(StarkVerifyError::BackendPending)
    }
}

/// Added error variants when the real backend is linked (still fail-closed at the trait).
#[cfg(feature = "stark-backend")]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StarkBackendError {
    #[error("outer proof failed to deserialize")]
    Malformed,
    #[error("outer proof metadata invalid")]
    BadMetadata,
    #[error("STARK verify rejected the proof")]
    VerifyRejected,
}

/// The real verify path — a fixed, deterministic (rayon OFF), panic-free verify of the
/// recursion OUTER proof under the pinned production config. Kept in its own module so
/// the p3 types are only referenced under the feature.
#[cfg(feature = "stark-backend")]
mod backend {
    use super::{Hash64, StarkVerifyError};
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_challenger::DuplexChallenger;
    use p3_circuit::ops::poseidon2_perm::Poseidon2Config;
    use p3_circuit_prover::BatchStarkProver;
    use p3_circuit_prover::batch_stark_prover::BatchStarkProof;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriParameters, TwoAdicFriPcs};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_uni_stark::StarkConfig;

    const D: usize = 4;
    const WIDTH: usize = 16;
    const RATE: usize = 8;
    const DIGEST: usize = 8;
    type F = BabyBear;
    type Challenge = BinomialExtensionField<F, D>;
    type Dft = Radix2DitParallel<F>;
    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST>;
    type MyCompress = TruncatedPermutation<Perm, 2, DIGEST, WIDTH>;
    type MyMmcs = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 2, DIGEST>;
    type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
    type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
    type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
    type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

    /// The PINNED production FRI parameters of the final recursion layer (these live in
    /// the verifier config, not the proof — they are committed by `vk_hash`, A3). A
    /// proof produced under different params fails the verify. **PROVISIONAL** — frozen
    /// by the vk-pinning ceremony; here matched to the measured ~100-bit run
    /// (`--security-level 100 --query-pow-bits 28 --final-log-blowup 4
    /// --log-final-poly-len 5`, `num_queries = (100-28)/4 = 18`).
    fn pinned_config() -> MyConfig {
        let perm = default_babybear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let val_mmcs = MyMmcs::new(hash, compress, 0); // cap_height = 0
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri = FriParameters {
            max_log_arity: 2,
            log_blowup: 4,
            log_final_poly_len: 5,
            num_queries: 18,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 28,
            mmcs: challenge_mmcs,
        };
        let pcs = MyPcs::new(Dft::default(), val_mmcs, fri);
        MyConfig::new(pcs, Challenger::new(perm))
    }

    /// Decode + verify the outer proof, returning every non-primitive table's surfaced
    /// public values (as canonical `u64` vectors) so the caller can bind the statement
    /// (A2). Fail-closed and (per the verify-path analysis) panic-free on adversarial
    /// bytes: `postcard::from_bytes` and `validate` guard the structure before any crypto,
    /// and `verify_all_tables` returns `Err` on mismatch.
    pub fn verify_outer_proof(_vk_hash: &Hash64, proof: &[u8]) -> Result<Vec<Vec<u64>>, StarkVerifyError> {
        use p3_field::PrimeField64;
        let proof: BatchStarkProof<MyConfig> =
            postcard::from_bytes(proof).map_err(|_| StarkVerifyError::MalformedStatement("outer proof".into()))?;
        proof.validate().map_err(|_| StarkVerifyError::MalformedStatement("outer proof metadata".into()))?;
        let mut prover = BatchStarkProver::new(pinned_config()).with_table_packing(proof.table_packing.clone());
        prover.register_poseidon2_table::<D>(Poseidon2Config::BABY_BEAR_D4_W16);
        prover.register_recompose_table::<D>(false);
        // TODO(A3): recompute the VerifierContext from the proof's shape + pinned params
        // and require compute_vk_hash(ctx) == *_vk_hash before returning Ok.
        prover
            .verify_all_tables::<Challenge>(&proof)
            .map_err(|_| StarkVerifyError::MalformedStatement("STARK verify rejected".into()))?;
        // (A2) surface the field public values the proof was bound over, canonicalized to
        // u64 so the caller compares them against `statement_to_pvs(on_chain_statement)`.
        Ok(proof
            .non_primitives
            .iter()
            .map(|e| e.public_values.iter().map(|v| v.as_canonical_u64()).collect())
            .collect())
    }
}

impl StarkVerifier for StarkBackend {
    fn verify(
        &self,
        circuit_version: u16,
        vk_hash: &Hash64,
        public_inputs: &[u8],
        proof: &[u8],
    ) -> Result<VerifiedStatement, ShieldVerifyError> {
        match verify_stark(circuit_version, vk_hash, public_inputs, proof) {
            Ok(stmt) => Ok(stmt),
            // Fail-closed and byte-identical to the default inert verifier: any
            // pending/unknown result rejects as "STARK not activated".
            Err(_) => Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_mil_shield::proof::{CIRCUIT_SPEND, PROOF_SYSTEM_REFERENCE, PROOF_SYSTEM_STARK, ShieldProof};
    use misaka_mil_shield::spend::{SpendStatement, SpendWitness};
    use misaka_mil_shield::{MerklePath, Note, commit, derive_output_rho, nullifier, shielded_address, verify_shield_proof_with};

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    // A valid REFERENCE spend proof (still verified in-process; the STARK backend
    // is only consulted for STARK-tagged proofs).
    fn ref_spend(vk: Hash64) -> Vec<u8> {
        let dummy = Note { value: 0, owner_pk: h(0), rho: h(0), r: h(0), token_id: 0 };
        let nf0 = nullifier(&h(1), &dummy.rho);
        let nf1 = nullifier(&h(2), &dummy.rho);
        let out0 = Note { value: 100, owner_pk: shielded_address(&h(0x71)), rho: derive_output_rho(&nf0, &nf1, 0), r: h(0x31), token_id: 0 };
        let out1 = Note { value: 0, owner_pk: h(0), rho: derive_output_rho(&nf0, &nf1, 1), r: h(0), token_id: 0 };
        let stmt = SpendStatement { anchor: h(0), nf_old: [nf0, nf1], cm_new: [commit(&out0), commit(&out1)], v_pub_in: 100, v_pub_out: 0, token_id: 0, ctx: h(0xC7) };
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
            verifier_key_hash: vk,
            public_inputs: borsh::to_vec(&stmt).unwrap(),
            proof: borsh::to_vec(&wit).unwrap(),
        }
        .encode()
    }

    #[test]
    fn stark_backend_is_fail_closed_until_the_milestone() {
        // A well-formed STARK statement passes the deterministic front half; a garbage
        // proof is then rejected fail-closed — as BackendPending when the real backend
        // is not linked, or as a real verify-rejection when it is. Either way `Err`.
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let r = verify_stark(CIRCUIT_SPEND, &h(0xB0), &pi, &[0u8; 32]);
        #[cfg(not(feature = "stark-backend"))]
        assert_eq!(r, Err(StarkVerifyError::BackendPending));
        #[cfg(feature = "stark-backend")]
        assert!(r.is_err(), "the real backend must reject a garbage proof");
        // Through the trait boundary, EVERY internal error (pending, malformed,
        // oversized) maps to the same ProofSystemNotActivated the inert node returns —
        // so a linked-but-inactive backend is byte-identical to one that does not link.
        let mut p = ShieldProof::decode(&ref_spend(h(0xB0))).unwrap();
        p.proof_system_id = PROOF_SYSTEM_STARK; // reference bytes tagged STARK
        assert_eq!(
            verify_shield_proof_with(&p.encode(), &h(0xB0), &StarkBackend),
            Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK)),
        );
    }

    #[test]
    fn reference_proofs_still_verify_when_the_backend_is_linked() {
        // Linking the (pending) STARK backend does not disturb the REFERENCE arm —
        // the node stays byte-identical for the currently-live proof system.
        let v = verify_shield_proof_with(&ref_spend(h(0xB0)), &h(0xB0), &StarkBackend).expect("reference spend verifies");
        assert!(matches!(v, VerifiedStatement::Spend(_)));
    }

    #[test]
    fn unknown_circuit_is_rejected() {
        assert_eq!(verify_stark(7, &h(0), &[], &[]), Err(StarkVerifyError::UnknownCircuit(7)));
        // unknown circuit also rejects at the decode layer, before any size work.
        assert_eq!(decode_statement(7, &[]), Err(StarkVerifyError::UnknownCircuit(7)));
    }

    // ---- deterministic front-half (SP-04): panic-free bounds + parse ----

    fn spend_stmt() -> SpendStatement {
        SpendStatement {
            anchor: h(0x10),
            nf_old: [misaka_mil_shield::Nullifier(h(0x20)), misaka_mil_shield::Nullifier(h(0x21))],
            cm_new: [misaka_mil_shield::Commitment(h(0x30)), misaka_mil_shield::Commitment(h(0x31))],
            v_pub_in: 100,
            v_pub_out: 0,
            token_id: 0,
            ctx: h(0xC7),
        }
    }

    #[test]
    fn valid_statement_decodes_and_reaches_the_pending_seam() {
        // A well-formed statement passes the front half (bounds + borsh); with the real
        // backend unlinked it stops at the §SP-0 seam (BackendPending), and with it
        // linked a garbage proof is rejected by the real verify — either way `Err`.
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let r = verify_stark(CIRCUIT_SPEND, &h(0xB0), &pi, &[0u8; 64]);
        #[cfg(not(feature = "stark-backend"))]
        assert_eq!(r, Err(StarkVerifyError::BackendPending));
        #[cfg(feature = "stark-backend")]
        assert!(r.is_err());
        // and the decoded statement round-trips exactly.
        match decode_statement(CIRCUIT_SPEND, &pi).unwrap() {
            VerifiedStatement::Spend(s) => assert_eq!(s, spend_stmt()),
            _ => panic!("expected Spend"),
        }
    }

    #[test]
    fn malformed_public_inputs_error_never_panic() {
        // Truncated, empty, garbage, and trailing-byte inputs all return Err (borsh is
        // strict about trailing bytes) — none unwind. This is the SP-04 panic-free bar.
        let good = borsh::to_vec(&spend_stmt()).unwrap();
        for bad in [vec![], vec![0u8; 1], good[..good.len() - 1].to_vec(), {
            let mut v = good.clone();
            v.push(0xff); // trailing byte
            v
        }] {
            let r = verify_stark(CIRCUIT_SPEND, &h(0xB0), &bad, &[]);
            assert!(matches!(r, Err(StarkVerifyError::MalformedStatement(_))), "must reject {bad:?} as malformed");
        }
    }

    #[test]
    fn oversized_proof_and_public_inputs_are_bounded_before_work() {
        // Proof larger than the cap is rejected before any parse (DoS guard).
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let big = vec![0u8; MAX_STARK_PROOF_BYTES + 1];
        assert_eq!(
            verify_stark(CIRCUIT_SPEND, &h(0xB0), &pi, &big),
            Err(StarkVerifyError::ProofTooLarge { got: MAX_STARK_PROOF_BYTES + 1, cap: MAX_STARK_PROOF_BYTES }),
        );
        // Oversized public inputs rejected at decode, before borsh runs.
        let big_pi = vec![0u8; MAX_PUBLIC_INPUT_BYTES + 1];
        assert_eq!(
            decode_statement(CIRCUIT_SPEND, &big_pi),
            Err(StarkVerifyError::PublicInputTooLarge { got: MAX_PUBLIC_INPUT_BYTES + 1, cap: MAX_PUBLIC_INPUT_BYTES }),
        );
    }

    #[test]
    fn provider_claim_statement_decodes() {
        // The second circuit version parses its own statement type.
        let claim = ProviderClaimStatement {
            provider_set_root: h(0x40),
            session_cm: h(0x41),
            amount: 7,
            provider_nf: misaka_mil_shield::Nullifier(h(0x42)),
            cm_payout: misaka_mil_shield::Commitment(h(0x43)),
            ctx: h(0x44),
        };
        let pi = borsh::to_vec(&claim).unwrap();
        match decode_statement(CIRCUIT_PROVIDER_CLAIM, &pi).unwrap() {
            VerifiedStatement::ProviderClaim(c) => assert_eq!(c, claim),
            _ => panic!("expected ProviderClaim"),
        }
        // a Spend circuit id will NOT accept ProviderClaim bytes as a valid SpendStatement
        // of the same length unless borsh happens to parse — assert it stays fail-closed
        // through verify_stark regardless (BackendPending or MalformedStatement, never panic).
        let r = verify_stark(CIRCUIT_PROVIDER_CLAIM, &h(0xB0), &pi, &[0u8; 32]);
        #[cfg(not(feature = "stark-backend"))]
        assert_eq!(r, Err(StarkVerifyError::BackendPending));
        #[cfg(feature = "stark-backend")]
        assert!(r.is_err()); // real backend rejects the garbage proof
    }

    #[test]
    fn decode_is_deterministic() {
        // Same input → same output, every time (no hidden state / ordering).
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let a = decode_statement(CIRCUIT_SPEND, &pi);
        let b = decode_statement(CIRCUIT_SPEND, &pi);
        assert_eq!(a, b);
    }

    // ---- A3: vk_hash + binding ----

    fn ctx() -> VerifierContext {
        VerifierContext {
            circuit_version: CIRCUIT_SPEND,
            field_tag: 0,
            ext_degree: 4,
            poseidon2_id: 1,
            log_blowup: 1,
            num_queries: 100,
            commit_pow_bits: 16,
            query_pow_bits: 16,
            max_log_arity: 2,
            log_final_poly_len: 0,
            cap_height: 0,
            security_level: 100,
            table_packing: vec![1, 2, 3],
            rows: vec![4, 5, 6],
            non_primitive_ops: vec![7, 2, 7, 5],
            preprocessed_commitment: vec![0xAB; 32],
        }
    }

    #[test]
    fn vk_hash_is_deterministic_and_canonical() {
        let a = compute_vk_hash(&ctx());
        let b = compute_vk_hash(&ctx());
        assert_eq!(a, b, "vk_hash must be deterministic");
        // canonicalization: the same context with the non-primitive ops in a different
        // order / with duplicates hashes IDENTICALLY.
        let mut c = ctx();
        c.non_primitive_ops = vec![5, 7, 2]; // sorted+dedup of {7,2,7,5}
        assert_eq!(compute_vk_hash(&c), a, "op order/dups must not change vk_hash");
    }

    #[test]
    fn vk_hash_is_sensitive_to_every_field() {
        let base = compute_vk_hash(&ctx());
        // Flip each field in turn; the vk_hash MUST change — a mis-provisioned verifier
        // (wrong params/circuit/commitment) can never collide with the pinned hash.
        let mutators: Vec<fn(&mut VerifierContext)> = vec![
            |c| c.circuit_version ^= 1,
            |c| c.field_tag ^= 1,
            |c| c.ext_degree ^= 1,
            |c| c.poseidon2_id ^= 1,
            |c| c.log_blowup ^= 1,
            |c| c.num_queries ^= 1,
            |c| c.commit_pow_bits ^= 1,
            |c| c.query_pow_bits ^= 1,
            |c| c.max_log_arity ^= 1,
            |c| c.log_final_poly_len ^= 1,
            |c| c.cap_height ^= 1,
            |c| c.security_level ^= 1,
            |c| c.table_packing.push(9),
            |c| c.rows.push(9),
            |c| c.non_primitive_ops.push(999),
            |c| c.preprocessed_commitment[0] ^= 1,
        ];
        for (i, m) in mutators.iter().enumerate() {
            let mut c = ctx();
            m(&mut c);
            assert_ne!(compute_vk_hash(&c), base, "field {i} must affect vk_hash");
        }
    }

    // ---- A1: the REAL verify back-half (only under the stark-backend feature) ----
    #[cfg(feature = "stark-backend")]
    #[test]
    fn real_backend_verifies_the_production_proof_and_rejects_tampering() {
        // Point MIL_OUTER_PROOF at a dumped recursion outer proof produced with the
        // pinned params (e.g. the ~100-bit spend_outer_sec100.bin). The real verify
        // back-half must ACCEPT it and REJECT a one-bit-flipped copy — fail-closed,
        // panic-free. Without the artifact the test is a no-op (CI without the file).
        let Ok(path) = std::env::var("MIL_OUTER_PROOF") else {
            eprintln!("MIL_OUTER_PROOF not set — skipping the real-backend verify");
            return;
        };
        let proof = std::fs::read(&path).expect("read outer proof");

        // (A1) CRYPTO verify: the real proof passes `verify_all_tables` under the pinned
        // config, and returns the surfaced per-table public values.
        let surfaced = backend::verify_outer_proof(&h(0xB0), &proof).expect("production proof crypto-verifies");

        // (A2) NODE binding is enforced by verify_stark on top of the crypto verify:
        if let Some(surfaced_stmt) = surfaced.iter().find(|pv| !pv.is_empty()) {
            // The prover surfaces a statement ⇒ end-to-end binding is exercisable: feeding
            // the SURFACED statement accepts, and any DIFFERENT statement fails-closed.
            let bound_pi: Vec<u8> = surfaced_stmt.iter().map(|&v| v as u8).collect();
            assert!(
                statement_is_bound(&surfaced, &bound_pi),
                "the surfaced statement binds"
            );
            let mut other = bound_pi.clone();
            other[0] ^= 1;
            assert!(!statement_is_bound(&surfaced, &other), "a different statement is not bound (A2 fail-closed)");
            eprintln!("A2 real backend: crypto-verify + surfaced-statement binding both hold (accept-on-match, reject-on-mismatch)");
        } else {
            // Prover-side surfacing pending (current artifacts carry empty batch-level public
            // values): the crypto verify passes, but verify_stark correctly FAILS CLOSED
            // because it cannot bind the statement — an unbound proof must not be accepted.
            let stmt = borsh::to_vec(&spend_stmt()).unwrap();
            assert_eq!(
                verify_stark(CIRCUIT_SPEND, &h(0xB0), &stmt, &proof),
                Err(StarkVerifyError::StatementNotSurfaced),
                "crypto-valid but unbound ⇒ fail-closed (A2), never silently accepted"
            );
            eprintln!("A1 real backend: production proof crypto-verifies; A2 node-binding fail-closed (prover surfacing pending)");
        }

        // (A1 negative) a one-bit flip in the proof is rejected by the crypto verify itself
        // (fail-closed, no panic) — before A2 binding is even reached.
        let mut bad = proof.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        assert!(
            backend::verify_outer_proof(&h(0xB0), &bad).is_err(),
            "a tampered proof must be rejected by the crypto verify"
        );
    }

    // ---- A2: node-side statement binding (artifact-free, default build) ----
    #[test]
    fn statement_pvs_encoding_is_injective_and_byte_exact() {
        let a = borsh::to_vec(&spend_stmt()).unwrap();
        let pvs = statement_to_pvs(&a);
        assert_eq!(pvs.len(), a.len(), "one field element per statement byte");
        assert!(pvs.iter().all(|&v| v < 256), "every element is a canonical byte");
        // injective: a different statement yields a different vector.
        let mut b = a.clone();
        b[0] ^= 0x01;
        assert_ne!(statement_to_pvs(&b), pvs);
    }

    #[test]
    fn statement_binding_accepts_on_match_rejects_otherwise() {
        let stmt = borsh::to_vec(&spend_stmt()).unwrap();
        let good = statement_to_pvs(&stmt);
        // a proof surfacing exactly this statement (in some non-primitive table) binds.
        let surfaced = vec![vec![], good.clone(), vec![1, 2, 3]];
        assert!(statement_is_bound(&surfaced, &stmt), "exact surfaced statement binds");
        // a proof surfacing a DIFFERENT statement does not bind (replay defense).
        let mut other = stmt.clone();
        other[3] ^= 0x80;
        assert!(!statement_is_bound(&surfaced, &other), "a different statement is not bound");
        // a proof surfacing NOTHING (all tables empty) fails closed — the critical case.
        assert!(!statement_is_bound(&[vec![], vec![]], &stmt), "absent surfacing ⇒ fail-closed");
        assert!(!statement_is_bound(&[], &stmt), "no tables ⇒ fail-closed");
    }

    #[test]
    fn bind_artifact_ties_proof_to_statement() {
        let vk = compute_vk_hash(&ctx());
        let stmt = borsh::to_vec(&spend_stmt()).unwrap();
        let proof = vec![0xEE; 128];
        let base = bind_artifact(&vk, &stmt, &proof);
        assert_eq!(bind_artifact(&vk, &stmt, &proof), base, "deterministic");
        // any change to vk / statement / proof changes the binding.
        assert_ne!(bind_artifact(&h(0x00), &stmt, &proof), base);
        let mut stmt2 = stmt.clone();
        stmt2[0] ^= 1;
        assert_ne!(bind_artifact(&vk, &stmt2, &proof), base);
        let mut proof2 = proof.clone();
        proof2[0] ^= 1;
        assert_ne!(bind_artifact(&vk, &stmt, &proof2), base);
        // domain separation: vk_hash and bind never collide on the same bytes.
        assert_ne!(base, compute_vk_hash(&ctx()));
    }
}
