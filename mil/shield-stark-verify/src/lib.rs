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
use misaka_mil_shield::proof::{
    CIRCUIT_PROVIDER_CLAIM, CIRCUIT_PROVIDER_CLAIM_V2, CIRCUIT_PROVIDER_CLAIM_V3, CIRCUIT_SPEND, PROOF_SYSTEM_STARK,
};
use misaka_mil_shield::provider::{ProviderClaimStatement, ProviderClaimStatementV2, ProviderClaimStatementV3};
use misaka_mil_shield::spend::SpendStatement;
use misaka_mil_shield::{ShieldVerifyError, StarkVerifier, VerifiedStatement};

pub mod manifest;
/// The vk-pinning CEREMONY tools (never verify-time trust sources — see their docs).
#[cfg(feature = "stark-backend")]
pub use backend::{ceremony_preprocessed_commitment, ceremony_vk_hash};
pub use manifest::{CircuitManifest, manifest_for_circuit};

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
    /// Per-non-primitive-table LOSSLESS fingerprints (audit K-01.1): each is the full 64-byte
    /// keyed-BLAKE2b digest of `(op_type, rows, lanes, air_variant)` — NOT a u16 truncation, so
    /// two tables that differ in row/lane count or AIR variant no longer collide. ORDER-BINDING
    /// (2026-07-11 re-audit K-01 `table_order`): the sequence is hashed exactly as the proof
    /// declares it — the verifier reconstructs AIRs positionally from `proof.non_primitives`,
    /// so the vk pins that exact order; a same-multiset reorder is a DIFFERENT vk_hash. (An
    /// earlier revision sorted here, making the hash order-independent — closed, see
    /// `vk_hash_binds_table_order_and_multiplicity`.) Multiplicity preserved (`{A,A}` ≠ `{A}`).
    pub non_primitive_ops: Vec<Vec<u8>>,
    /// The REAL preprocessed-commitment binding (audit K-01.1): postcard of the proof's
    /// `stark_common.preprocessed` — the PCS commitment (Merkle cap) over every AIR's
    /// preprocessed (constant/selector) columns, plus the per-instance metas and the
    /// matrix→instance map. A distinct circuit with a different preprocessed commitment now
    /// yields a different vk_hash. A fixed sentinel is used when there are no preprocessed columns.
    pub preprocessed_commitment: Vec<u8>,
    /// The ALU-shape scalars (`alu_variant`, `ext_degree`, `w_binomial`, quintic flag) that used
    /// to (incorrectly) occupy `preprocessed_commitment`; kept as a distinct binding field.
    pub alu_shape: Vec<u8>,
}

/// `vk_hash = H_k(VK_DOMAIN, borsh(context))`. Deterministic and versioned; the value
/// the governance ceremony pins on-chain and the node checks against. The context is
/// hashed EXACTLY as constructed — there is deliberately NO canonicalization step any
/// more: the former `canonical()` sorted `non_primitive_ops`, making the vk_hash
/// order-independent over the table multiset, which the 2026-07-11 re-audit (K-01
/// `table_order: False`) flagged as the one unbound circuit dimension. The pinned
/// production circuit emits its tables in one deterministic order, so binding the
/// order costs nothing for genuine proofs and closes the reordered-table surface.
pub fn compute_vk_hash(ctx: &VerifierContext) -> Result<Hash64, StarkVerifyError> {
    // (L-01) borsh of an in-memory context is infallible for the current fixed types (a `Vec`
    // writer never fails); this is a typed, fail-closed error rather than the former
    // `expect(..)` so a future type change can never panic the ceremony/verify path.
    let bytes = borsh::to_vec(ctx).map_err(|_| StarkVerifyError::ContextSerialization("vk_hash borsh(context)"))?;
    Ok(blake2b_512_keyed(VK_DOMAIN, &bytes))
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
/// `ProviderClaimStatement` = 328 B, `ProviderClaimStatementV2` = 392 B — the single
/// source of truth for these layouts is `misaka_mil_shield::statement_schema` (audit
/// C-01), cross-asserted in the tests below. A valid statement's length is thus exact
/// and always ≤ this cap, so the cap never false-rejects a valid statement; it only
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
    /// (A3) The proof's pinned circuit shape / params do not hash to the governance-pinned
    /// vk_hash for this circuit — a mis-provisioned or downgraded verifier is rejected.
    #[error("proof vk_hash does not match the pinned circuit (A3)")]
    VkHashMismatch,
    /// (K-01) The pinned per-circuit release manifest disagrees with the call in the named
    /// dimension (circuit version, statement schema id/length, type-level field/extension/
    /// Poseidon2 pins, transcript KAT constant) — fail-closed before any crypto.
    #[error("verifier manifest mismatch: {0}")]
    ManifestMismatch(&'static str),
    /// (K-01 placeholder policy) The circuit is known but its verifier key has NOT been
    /// frozen by a vk-pinning ceremony yet (`vk_hash: None` in [`manifest`]): every STARK
    /// proof for it is rejected fail-closed. Freezing is a deliberate governance release —
    /// see the [`manifest`] module docs.
    #[error("circuit {0} verifier key is not frozen in the pinned manifest (K-01)")]
    CircuitVkNotFrozen(u16),
    /// (K-01) The live Fiat-Shamir known-answer computed by THIS binary's challenger does
    /// not equal the manifest's frozen transcript KAT — a drifted or locally patched
    /// proving stack; fail-closed before any crypto.
    #[error("Fiat-Shamir transcript drifted from the pinned manifest KAT (K-01/A3)")]
    TranscriptDrift,
    /// (K-01) The proof's ACTUAL preprocessed PCS commitment does not byte-equal the
    /// manifest's independently pinned raw commitment — checked directly, in addition to
    /// the `vk_hash` fold-in, so the pinned program is auditable without any proof.
    #[error("preprocessed commitment does not match the pinned manifest (K-01)")]
    PreprocessedCommitmentMismatch,
    /// (L-01) A trust-anchor serialization step failed while constructing the
    /// [`VerifierContext`] or its `vk_hash` (the borsh/postcard encodings that pin the
    /// circuit). This is infallible for the current fixed types — a `Vec` writer never fails —
    /// so it is a typed, fail-closed error rather than an `expect`/`unwrap_or_default`: a future
    /// type change can then never (a) PANIC in the ceremony/verify path, nor (b) SILENTLY
    /// collapse two distinct contexts to the same empty encoding (and thus the same `vk_hash`).
    /// The `&'static str` names the failing field for telemetry only; it is never
    /// consensus-branched (every variant maps to a reject).
    #[error("trust-anchor context serialization failed (L-01): {0}")]
    ContextSerialization(&'static str),
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

/// (A2) Node-side statement binding, fail-closed: the on-chain statement must be surfaced in
/// EXACTLY ONE of the proof's non-primitive public-value tables. `surfaced` is the
/// per-non-primitive-table public values (canonical `u64`) the crypto verify bound; the
/// statement is bound iff exactly one table carries `statement_to_pvs(public_inputs)`.
///
/// This is the fail-closed **unique-surface** rule (audit m2): it rejects a proof with ZERO
/// surfacing tables (a crypto-valid but unbound proof is replayable onto another statement —
/// the critical case) OR with MORE THAN ONE table carrying the statement (an ambiguous /
/// duplicate surfacing), replacing the earlier `contains` (accept-on-ANY) scan that bound as
/// soon as *some* table matched.
///
/// (audit M-02, in-session tightening) A degenerate EMPTY statement fails closed BEFORE the
/// count: a null `public_inputs` carries no on-chain binding, so a proof surfacing an empty
/// table must never be read as "the statement is bound" (without this guard, `expected` is the
/// empty vector and a single empty surfaced table would satisfy `count() == 1`, binding a proof
/// to *nothing*). Production statements are length-pinned (>= 328 B) by `manifest_precheck`, so
/// this only hardens the pure function against a degenerate/decoy caller — but that makes the
/// fail-closed property total rather than incidental on the upstream length gate.
///
/// RESIDUAL — the TYPE-selection half is genuinely patch-gated, NOT reachable in-session
/// (audit M-02, recorded external): the fully sound rule selects the ONE surface table by its
/// manifest-pinned `public_surface` NpoTypeId (op type), so a DECOY table of a *different* op
/// type whose `public_values` happen to equal the statement is excluded by TYPE, not merely by
/// count. That discriminator is unavailable to this code today for two independent reasons:
///   1. [`backend::verify_outer_proof`] returns only each table's `public_values`
///      (`Vec<Vec<u64>>`) — never an op-type tag — so `statement_is_bound` has no type field to
///      switch on even in a `stark-backend` build; and
///   2. the typed `public_surface` op (`register_public_surface_table` / the `PublicSurfaceAir`
///      first-row constraint) exists ONLY in the audit-gated A2-patched recursion tree
///      (`docs/bench/plonky3-recursion-a2-surfacing.diff` on `b363397`, pinned by
///      [`manifest::A2_PATCH_SHA256_ONDISK`]); without the `stark-backend-a2-surface` feature +
///      that `[patch]` the op is UNREGISTERED and any proof carrying it is rejected as an
///      unknown non-primitive op — so no genuine typed surface table can even appear in the
///      pinned build to select by type.
/// The residual content-decoy gap is not reachable in production before that lands, because the
/// STARK arm is fail-closed end-to-end today (every [`CircuitManifest::vk_hash`] is `None` ⇒
/// [`StarkVerifyError::CircuitVkNotFrozen`]); the type-selection half is frozen at the SAME
/// vk-pinning ceremony that applies the A2 patch. Until then, unique-content surfacing (`count
/// == 1`) plus the empty-statement guard is the tightest node-side check the surfaced vectors
/// admit. See [`verify_stark`].
pub fn statement_is_bound(surfaced: &[Vec<u64>], public_inputs: &[u8]) -> bool {
    // (M-02) fail-closed on the empty statement — see the doc comment.
    if public_inputs.is_empty() {
        return false;
    }
    let expected = statement_to_pvs(public_inputs);
    surfaced.iter().filter(|t| *t == &expected).count() == 1
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
        // (audit C-01) the hidden-amount claim (392 B, schema-frozen): decodes the
        // explicit `provider_share_sompi` public input alongside `v_claim_cm`, so the
        // node binds the SAME payout value the contract computed and the circuit proved.
        CIRCUIT_PROVIDER_CLAIM_V2 => ProviderClaimStatementV2::try_from_slice(public_inputs)
            .map(VerifiedStatement::ProviderClaimV2)
            .map_err(|e| StarkVerifyError::MalformedStatement(e.to_string())),
        // (C-P6 / ADR-0037 §2.4) the receipt-authorized claim (456 B, schema-frozen): the
        // claim-v2 layout plus the `receipt_cm` receipt-verify binding. Size-checked by the
        // decode cap above and by strict borsh (exactly 456 B). INERT — the manifest's `vk_hash`
        // is `None`, so `verify_stark` fails closed at the K-01 anchor before any crypto.
        CIRCUIT_PROVIDER_CLAIM_V3 => ProviderClaimStatementV3::try_from_slice(public_inputs)
            .map(VerifiedStatement::ProviderClaimV3)
            .map_err(|e| StarkVerifyError::MalformedStatement(e.to_string())),
        other => Err(StarkVerifyError::UnknownCircuit(other)),
    }
}

/// (K-01) The manifest precheck — the release-pinned gate every STARK verify passes
/// BEFORE any cryptography. Enforces, against the compiled-in [`CircuitManifest`]:
///
/// 1. the envelope's `circuit_version` is the manifest's;
/// 2. the statement schema cross-lock: the C-01 schema manifest
///    (`misaka_mil_shield::statement_schema`) must agree with THIS manifest on the
///    schema id and exact statement length, and the presented public inputs must have
///    exactly that length (borsh strictness re-enforces this at decode; the explicit
///    check makes the manifest authoritative, not incidental);
/// 3. the transcript KAT constant matches the frozen A3 value (a mutated manifest can
///    never pass — the backend additionally recomputes the KAT live);
/// 4. **the trust anchor**: the expected `vk_hash` the caller presents must EQUAL the
///    manifest's ceremony-frozen key. The manifest is the ONLY source of expected-key
///    truth — never the proof, never statement bytes. While the circuit is unfrozen
///    (`vk_hash: None`) the verify fails closed ([`StarkVerifyError::CircuitVkNotFrozen`]).
///
/// Deterministic, allocation-free, panic-free.
pub fn manifest_precheck(
    m: &CircuitManifest,
    circuit_version: u16,
    vk_hash: &Hash64,
    public_inputs: &[u8],
) -> Result<(), StarkVerifyError> {
    if m.circuit_version != circuit_version {
        return Err(StarkVerifyError::ManifestMismatch("circuit_version"));
    }
    let Some(schema) = misaka_mil_shield::statement_schema::schema_for_circuit(circuit_version) else {
        return Err(StarkVerifyError::ManifestMismatch("statement schema not frozen"));
    };
    if schema.name != m.statement_schema_id {
        return Err(StarkVerifyError::ManifestMismatch("statement_schema_id"));
    }
    if schema.size != m.statement_len || public_inputs.len() != m.statement_len {
        return Err(StarkVerifyError::ManifestMismatch("statement length"));
    }
    if m.transcript_kat != manifest::FIAT_SHAMIR_KAT_FROZEN {
        return Err(StarkVerifyError::ManifestMismatch("transcript_kat"));
    }
    match m.vk_hash {
        Some(pinned) => {
            if *vk_hash != pinned {
                return Err(StarkVerifyError::VkHashMismatch);
            }
        }
        None => return Err(StarkVerifyError::CircuitVkNotFrozen(circuit_version)),
    }
    Ok(())
}

/// The pure, deterministic verify (front half live, back half pending §SP-0), under
/// the RELEASE-PINNED manifest for the circuit (K-01): unknown circuit ⇒ reject.
///
/// Front half (implemented, SP-04-critical): reject unknown circuits, bound the proof
/// and public-input sizes (DoS guard), borsh-decode the statement, and run the
/// [`manifest_precheck`] trust anchor — all panic-free, allocation-bounded, and
/// platform-independent. Back half (the audited §SP-0 milestone, marked SEAM below):
/// decode `proof` as the recursion outer proof, run the hash-based STARK verify
/// against `vk_hash`, and — critically — prove the decoded statement equals the
/// public values the proof was produced over (element for element under the frozen
/// field encoding) so a proof valid for a *different* statement cannot be replayed.
/// Until that lands the seam returns `BackendPending`, so the whole function stays
/// fail-closed. Wiring the real back half pulls in a verify-only Plonky3 subset
/// (p3-batch-stark / p3-recursion), which is the experimental, audit-gated dependency
/// ADR-0035 §8 flags — hence it lands behind this seam, not in the default consensus
/// build.
pub fn verify_stark(
    circuit_version: u16,
    vk_hash: &Hash64,
    public_inputs: &[u8],
    proof: &[u8],
) -> Result<VerifiedStatement, StarkVerifyError> {
    // (K-01) resolve the release-pinned manifest FIRST: a circuit without one is
    // unverifiable, full stop (same fail-closed class as an unknown statement type).
    let m = manifest_for_circuit(circuit_version).ok_or(StarkVerifyError::UnknownCircuit(circuit_version))?;
    verify_stark_with_manifest(m, circuit_version, vk_hash, public_inputs, proof)
}

/// [`verify_stark`] parameterized over an explicit manifest. Public for the vk-pinning
/// ceremony and the acceptance/mutation test corpus (which must exercise a FROZEN
/// manifest before production freezes one, and mutate every field of a frozen one);
/// production consensus callers go through [`verify_stark`], which only ever resolves
/// the compiled-in pinned set.
pub fn verify_stark_with_manifest(
    m: &CircuitManifest,
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
    // (K-01) the manifest trust anchor: the expected vk_hash is valid ONLY if it equals
    // the release-pinned key for this circuit; unfrozen circuits fail closed here.
    manifest_precheck(m, circuit_version, vk_hash, public_inputs)?;
    // --- back half: the real STARK verify, behind the `stark-backend` feature ---
    #[cfg(feature = "stark-backend")]
    {
        // (A1) crypto verify the outer proof + (A3/K-01) require the recomputed vk_hash of
        // the proof's pinned circuit shape to equal the manifest-pinned `vk_hash`, the
        // manifest params, the live transcript KAT, and (once frozen) the raw preprocessed
        // commitment; returns every non-primitive table's surfaced public values.
        let surfaced = backend::verify_outer_proof(m, vk_hash, circuit_version, proof)?;
        // (A2) NODE-SIDE statement binding, fail-closed: the proof must surface EXACTLY the
        // on-chain statement in one of its public-output tables, under the frozen encoding.
        // A crypto-valid proof whose surfaced statement differs (or is absent) is rejected,
        // so it cannot be replayed onto a different statement at the consensus boundary.
        if statement_is_bound(&surfaced, public_inputs) {
            return Ok(statement);
        }
        Err(StarkVerifyError::StatementNotSurfaced)
    }
    #[cfg(not(feature = "stark-backend"))]
    {
        // Default node: fail-closed, byte-identical to the inert verifier.
        let _ = (statement, proof);
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
    use p3_challenger::{CanObserve, CanSample, DuplexChallenger};
    use p3_circuit::ops::poseidon2_perm::Poseidon2Config;
    use p3_circuit_prover::BatchStarkProver;
    use p3_circuit_prover::batch_stark_prover::BatchStarkProof;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
    use p3_fri::{FriParameters, TwoAdicFriPcs};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_uni_stark::StarkConfig;

    const D: usize = 4;
    const WIDTH: usize = 16;
    const RATE: usize = 8;
    const DIGEST: usize = 8;

    // (audit M-05R → K-01) The DoS bounds on attacker-controlled proof metadata magnitudes
    // moved INTO the per-circuit release manifest (`CircuitManifest::max_*`) so the ceremony
    // tightens them alongside every other pinned parameter; `verify_outer_proof` enforces
    // them from the manifest before the vendored verifier reconstructs any trace.
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

    /// Build the verifier `StarkConfig` FROM the release-pinned manifest (K-01). The
    /// FRI/PCS parameters live in the verifier config, not the proof — they are committed
    /// by `vk_hash` AND enumerated in the manifest, and this constructor is the ONLY place
    /// they enter the config, so the previously hand-duplicated constants (the old
    /// `pinned_config()` vs the context builder — an audit-noted drift risk) cannot drift:
    /// both now read the same `CircuitManifest` fields. A proof produced under different
    /// params fails the verify. **PROVISIONAL** values until the vk-pinning ceremony; the
    /// current pins match the measured ~100-bit run (`--security-level 100
    /// --query-pow-bits 28 --final-log-blowup 4 --log-final-poly-len 5`,
    /// `num_queries = (100-28)/4 = 18`).
    pub(crate) fn config_from_manifest(m: &super::CircuitManifest) -> MyConfig {
        let perm = default_babybear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let val_mmcs = MyMmcs::new(hash, compress, m.cap_height as usize);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri = FriParameters {
            max_log_arity: m.max_log_arity as usize,
            log_blowup: m.log_blowup as usize,
            log_final_poly_len: m.log_final_poly_len as usize,
            num_queries: m.num_queries as usize,
            commit_proof_of_work_bits: m.commit_pow_bits as usize,
            query_proof_of_work_bits: m.query_pow_bits as usize,
            mmcs: challenge_mmcs,
        };
        let pcs = MyPcs::new(Dft::default(), val_mmcs, fri);
        MyConfig::new(pcs, Challenger::new(perm))
    }

    /// (A3) Fiat-Shamir transcript FREEZE — a known-answer over the pinned Fiat-Shamir challenger
    /// (`DuplexChallenger` over Poseidon2-BabyBear-D4-W16, WIDTH=16/RATE=8). Absorb a fixed
    /// transcript (a full rate's worth of field elements, an interleaved observe, more squeezes)
    /// and return the squeezed challenges. Any change to the permutation constants, the width/rate,
    /// the duplex sampling, or the field changes these outputs — so the freeze test fails and forces
    /// a DELIBERATE re-freeze + re-ceremony. This pins the challenge-derivation PRIMITIVE; the full
    /// FRI transcript is additionally pinned by `config_from_manifest` (log_blowup=4,
    /// num_queries=18, query_pow_bits=28, …) bound into `vk_hash`, and real-artifact-verified
    /// (only a proof under the exact transcript verifies — cf. `spend_outer_sec100.bin`).
    /// (K-01) `verify_outer_proof` recomputes this per verify and compares it against the
    /// manifest's frozen `transcript_kat`, failing closed on drift before any crypto.
    pub fn fiat_shamir_kat() -> [u64; 3] {
        let mut ch = Challenger::new(default_babybear_poseidon2_16());
        for i in 0..16u32 {
            ch.observe(BabyBear::from_u32(i.wrapping_mul(2654435761)));
        }
        let a: BabyBear = ch.sample();
        ch.observe(BabyBear::from_u32(0x00C0_FFEE));
        let b: BabyBear = ch.sample();
        let c: BabyBear = ch.sample();
        [a.as_canonical_u64(), b.as_canonical_u64(), c.as_canonical_u64()]
    }

    /// (K-01) The FROZEN encoding of the proof's ACTUAL preprocessed-commitment surface:
    /// postcard of the PCS commitment (Merkle cap) over every AIR's preprocessed
    /// (constant/selector) columns, plus the per-instance metas and the matrix→instance
    /// map (`PreprocessedInstanceMeta` is not `Serialize`, so its public scalars are
    /// lifted into a serializable tuple). When there is no preprocessed data a fixed
    /// sentinel is returned (so `None` and any real commitment can never compare equal).
    /// This is BOTH what the ceremony transcribes into
    /// `CircuitManifest::preprocessed_commitment` AND what `verify_outer_proof` compares
    /// the manifest against — byte-for-byte, independent of any hash.
    pub fn encode_preprocessed(proof: &BatchStarkProof<MyConfig>) -> Result<Vec<u8>, StarkVerifyError> {
        match proof.stark_common.preprocessed.as_ref() {
            Some(gp) => {
                // (L-01) NO `unwrap_or_default()`: a serialization failure must surface as a typed
                // error, never as empty bytes — otherwise two distinct commitments that both failed
                // to encode would alias to the same (empty) context field and thus the same vk_hash.
                let commitment = postcard::to_allocvec(&gp.commitment)
                    .map_err(|_| StarkVerifyError::ContextSerialization("preprocessed commitment"))?;
                let instances: Vec<Option<(u64, u64, u64)>> = gp
                    .instances
                    .iter()
                    .map(|o| o.as_ref().map(|m| (m.matrix_index as u64, m.width as u64, m.degree_bits as u64)))
                    .collect();
                let matrix_to_instance: Vec<u64> = gp.matrix_to_instance.iter().map(|&x| x as u64).collect();
                postcard::to_allocvec(&(commitment, instances, matrix_to_instance))
                    .map_err(|_| StarkVerifyError::ContextSerialization("preprocessed tuple"))
            }
            None => Ok(b"MISAKA-SHIELD-NO-PREPROCESSED-v1".to_vec()),
        }
    }

    /// (A3/K-01) Recompute the pinned [`VerifierContext`] from the outer proof's circuit
    /// SHAPE (only PUBLIC, `Serialize` proof fields) + the MANIFEST's pinned config params,
    /// so a proof whose shape or params differ from the governance-pinned
    /// `(circuit_version, vk_hash)` is rejected before its statement is trusted. The
    /// preprocessed/table shape + FRI params are exactly the "exact structural-param
    /// equality" audit §6 requires. Config-side fields come from the SAME manifest the
    /// verify config is built from (`config_from_manifest`), so they cannot drift apart.
    pub fn context_from_proof(
        m: &super::CircuitManifest,
        circuit_version: u16,
        proof: &BatchStarkProof<MyConfig>,
    ) -> Result<super::VerifierContext, StarkVerifyError> {
        // LOSSLESS per-table fingerprint (audit K-01.1): hash the FULL circuit-stable shape of
        // each non-primitive table — op_type AND its row count, lane count, and AIR variant —
        // into the complete 64-byte digest (no u16 truncation). ORDER-BINDING (K-01
        // table_order): the fingerprints are bound in exactly the proof's table order — the
        // verifier reconstructs AIRs positionally, so the vk pins that order; multiplicity
        // is preserved too. (L-01) A postcard failure on any fingerprint is a typed error, not
        // an empty-byte fallback that would let two distinct tables share a fingerprint.
        let non_primitive_ops: Vec<Vec<u8>> = proof
            .non_primitives
            .iter()
            .map(|e| {
                let b = postcard::to_allocvec(&(&e.op_type, e.rows as u64, e.lanes as u64, &e.air_variant))
                    .map_err(|_| StarkVerifyError::ContextSerialization("non-primitive op fingerprint"))?;
                Ok(kaspa_hashes::blake2b_512_keyed(super::VK_DOMAIN, &b).as_byte_slice().to_vec())
            })
            .collect::<Result<Vec<Vec<u8>>, StarkVerifyError>>()?;
        // The REAL preprocessed-commitment binding (audit K-01.1), frozen-encoded.
        let preprocessed_commitment = encode_preprocessed(proof)?;
        // The ALU-shape scalars (previously mis-stored in `preprocessed_commitment`).
        let alu_shape =
            postcard::to_allocvec(&(&proof.alu_variant, proof.ext_degree as u64, &proof.w_binomial, proof.alu_quintic_trinomial))
                .map_err(|_| StarkVerifyError::ContextSerialization("alu shape"))?;
        Ok(super::VerifierContext {
            circuit_version,
            field_tag: m.field_tag,
            ext_degree: m.ext_degree,
            poseidon2_id: m.poseidon2_id,
            log_blowup: m.log_blowup,
            num_queries: m.num_queries,
            commit_pow_bits: m.commit_pow_bits,
            query_pow_bits: m.query_pow_bits,
            max_log_arity: m.max_log_arity,
            log_final_poly_len: m.log_final_poly_len,
            cap_height: m.cap_height,
            security_level: m.security_level,
            table_packing: postcard::to_allocvec(&proof.table_packing)
                .map_err(|_| StarkVerifyError::ContextSerialization("table packing"))?,
            rows: postcard::to_allocvec(&proof.rows).map_err(|_| StarkVerifyError::ContextSerialization("rows"))?,
            non_primitive_ops,
            preprocessed_commitment,
            alu_shape,
        })
    }

    /// CEREMONY-ONLY: compute the vk_hash a valid proof of `circuit_version` carries under
    /// manifest `m` — i.e. the value the vk-pinning ceremony transcribes into
    /// `CircuitManifest::vk_hash` from the audited reference artifact. Deliberately named
    /// so no verify path is tempted to call it: deriving the EXPECTED key from the proof
    /// under verification is the circular trust anchor the K-01 re-audit prohibits. At
    /// verify time the expected key comes only from the compiled-in manifest
    /// ([`super::manifest_precheck`]); this function exists so the ceremony (and the test
    /// corpus standing in for it) can produce the value to freeze.
    pub fn ceremony_vk_hash(m: &super::CircuitManifest, circuit_version: u16, proof: &[u8]) -> Result<Hash64, StarkVerifyError> {
        let proof: BatchStarkProof<MyConfig> =
            postcard::from_bytes(proof).map_err(|_| StarkVerifyError::MalformedStatement("outer proof".into()))?;
        super::compute_vk_hash(&context_from_proof(m, circuit_version, &proof)?)
    }

    /// CEREMONY-ONLY: the raw preprocessed-commitment bytes to transcribe into
    /// `CircuitManifest::preprocessed_commitment` at the circuit freeze (same caveat as
    /// [`ceremony_vk_hash`] — never a verify-time source of expectations).
    pub fn ceremony_preprocessed_commitment(proof: &[u8]) -> Result<Vec<u8>, StarkVerifyError> {
        let proof: BatchStarkProof<MyConfig> =
            postcard::from_bytes(proof).map_err(|_| StarkVerifyError::MalformedStatement("outer proof".into()))?;
        encode_preprocessed(&proof)
    }

    /// Decode + verify the outer proof under the release-pinned manifest `m`, enforcing
    /// (K-01, in order): the type-level field/extension/Poseidon2 pins, the live
    /// Fiat-Shamir transcript KAT, the manifest metadata bounds, the raw preprocessed
    /// commitment (once frozen), and the (A3) vk_hash — then the crypto verify — and
    /// returning every non-primitive table's surfaced public values (as canonical `u64`
    /// vectors) so the caller can bind the statement (A2). Fail-closed and (per the
    /// verify-path analysis) panic-free on adversarial bytes: `postcard::from_bytes` and
    /// `validate` guard the structure before any crypto, and `verify_all_tables` returns
    /// `Err` on mismatch.
    pub fn verify_outer_proof(
        m: &super::CircuitManifest,
        vk_hash: &Hash64,
        circuit_version: u16,
        proof: &[u8],
    ) -> Result<Vec<Vec<u64>>, StarkVerifyError> {
        use p3_field::PrimeField64;
        // (K-01) the field, extension degree and Poseidon2 constants are TYPE-LEVEL in this
        // binary (BabyBear, D=4, BABY_BEAR_D4_W16): a manifest naming anything else cannot
        // be honoured by this code and must fail closed rather than verify under a
        // mislabeled context.
        if m.field_tag != 0 || m.ext_degree != D as u8 || m.poseidon2_id != 0x0416 {
            return Err(StarkVerifyError::ManifestMismatch("field/ext_degree/poseidon2 type-level pin"));
        }
        // (K-01) live transcript pin: the Fiat-Shamir primitive THIS binary computes must
        // equal the manifest's frozen KAT — a drifted/patched challenger fails closed here.
        if fiat_shamir_kat() != m.transcript_kat {
            return Err(StarkVerifyError::TranscriptDrift);
        }
        let proof: BatchStarkProof<MyConfig> =
            postcard::from_bytes(proof).map_err(|_| StarkVerifyError::MalformedStatement("outer proof".into()))?;
        proof.validate().map_err(|_| StarkVerifyError::MalformedStatement("outer proof metadata".into()))?;
        // (audit M-05R) upstream `validate()` only checks non-zero-ness + ext_degree; it does NOT
        // bound the MAGNITUDE of attacker-controlled metadata. Cap the table count and every
        // per-table row/lane/public-value count BEFORE the vendored verifier reconstructs traces,
        // so a small metadata field cannot amplify into unbounded allocation / work (consensus
        // DoS). The bounds come from the release manifest (generous relative to the frozen
        // circuit; tightened to the exact measured shape at the K-01 ceremony).
        if proof.non_primitives.len() > m.max_tables {
            return Err(StarkVerifyError::MalformedStatement("too many non-primitive tables".into()));
        }
        for e in &proof.non_primitives {
            if e.rows > m.max_rows_per_table
                || e.lanes > m.max_lanes_per_table
                || e.public_values.len() > m.max_public_values_per_table
            {
                return Err(StarkVerifyError::MalformedStatement("non-primitive table metadata out of bounds".into()));
            }
        }
        // (K-01) the INDEPENDENT preprocessed anchor: once the ceremony froze the raw
        // commitment bytes, the proof's actual preprocessed PCS commitment must byte-equal
        // them — checked directly, not only through the vk_hash fold-in, so the pinned
        // program is auditable against the release without recomputing any hash.
        if let Some(expected) = m.preprocessed_commitment
            && encode_preprocessed(&proof)? != expected
        {
            return Err(StarkVerifyError::PreprocessedCommitmentMismatch);
        }
        // (A3) the proof's pinned circuit shape must hash to the governance-pinned vk_hash.
        if super::compute_vk_hash(&context_from_proof(m, circuit_version, &proof)?)? != *vk_hash {
            return Err(StarkVerifyError::VkHashMismatch);
        }
        let mut prover = BatchStarkProver::new(config_from_manifest(m)).with_table_packing(proof.table_packing.clone());
        prover.register_poseidon2_table::<D>(Poseidon2Config::BABY_BEAR_D4_W16);
        prover.register_recompose_table::<D>(false);
        // (A2, AUDIT-GATED) the `public_surface` statement-surfacing table: its AIR binds the
        // proof's claimed `public_values` to the committed trace (first-row constraint) and the
        // trace to the layer circuit's verified statement targets (WitnessChecks bus), so the
        // surfaced values below are sound to compare against the on-chain statement. The
        // registration API exists only in the A2-patched recursion tree
        // (docs/bench/plonky3-recursion-a2-surfacing.diff on b363397); without this feature a
        // proof containing the surface table is REJECTED (unknown non-primitive op) — fail-closed.
        #[cfg(feature = "stark-backend-a2-surface")]
        prover.register_public_surface_table::<D>();
        prover
            .verify_all_tables::<Challenge>(&proof)
            .map_err(|_| StarkVerifyError::MalformedStatement("STARK verify rejected".into()))?;
        // (A2) surface the field public values the proof was bound over, canonicalized to
        // u64 so the caller compares them against `statement_to_pvs(on_chain_statement)`.
        Ok(proof.non_primitives.iter().map(|e| e.public_values.iter().map(|v| v.as_canonical_u64()).collect()).collect())
    }

    /// TEST-ONLY (K-01 acceptance): build + prove a genuine ALTERNATE circuit (a short
    /// additive chain — same field, same pinned config, entirely different program) so the
    /// corpus can demonstrate that a VALID proof of the wrong AIR is rejected under the
    /// pinned spend manifest by the trust anchor, not merely by crypto failure. `chain_len`
    /// varies the trace height so two alternates get distinct shapes.
    #[cfg(test)]
    pub fn prove_easy_alternate_circuit(m: &super::CircuitManifest, chain_len: usize) -> Vec<u8> {
        use p3_batch_stark::ProverData;
        use p3_circuit::CircuitBuilder;
        use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
        use p3_circuit_prover::{CircuitProverData, ConstraintProfile, TablePacking};

        let mut builder = CircuitBuilder::<Challenge>::new();
        let expected = builder.alloc_public_input("expected");
        let mut a = builder.alloc_const(Challenge::ZERO, "f0");
        let mut b = builder.alloc_const(Challenge::ONE, "f1");
        for _ in 2..=chain_len {
            let next = builder.add(a, b);
            a = b;
            b = next;
        }
        builder.connect(b, expected);
        let circuit = builder.build().expect("easy circuit builds");
        // FRI needs log_min_height > log_final_poly_len + log_blowup for every committed
        // matrix, so derive the minimum trace height from the SAME manifest params.
        let table_packing = TablePacking::new(4, 4).with_fri_params(m.log_final_poly_len as usize, m.log_blowup as usize);
        let (airs_degrees, primitive_columns, non_primitive_columns) =
            get_airs_and_degrees_with_prep::<MyConfig, Challenge, D>(&circuit, &table_packing, &[], &[], ConstraintProfile::Standard)
                .expect("airs/degrees");
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let mut runner = circuit.runner();
        // classical Fibonacci over the extension field
        let (mut x, mut y) = (Challenge::ZERO, Challenge::ONE);
        for _ in 2..=chain_len {
            let next = x + y;
            x = y;
            y = next;
        }
        runner.set_public_inputs(&[y]).expect("public input");
        let traces = runner.run().expect("witness generation");
        let prover_data = ProverData::from_airs_and_degrees(&config_from_manifest(m), &airs, &degrees);
        let circuit_prover_data = CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
        let prover = BatchStarkProver::new(config_from_manifest(m)).with_table_packing(table_packing);
        let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove easy circuit");
        postcard::to_allocvec(&proof).expect("serialize easy proof")
    }

    /// TEST-ONLY (M-05 fuzz): the canonical re-encoding of decodable outer-proof bytes —
    /// `postcard(decode(bytes))`. postcard is deterministic, so two byte strings with equal
    /// canonical re-encodings decode to the SAME proof; the fuzz uses this to assert that
    /// only a semantic no-op mutation (e.g. trailing garbage, which `postcard::from_bytes`
    /// ignores) may still verify. `None` when the bytes do not decode.
    #[cfg(test)]
    pub fn canonical_reencode(bytes: &[u8]) -> Option<Vec<u8>> {
        let proof: BatchStarkProof<MyConfig> = postcard::from_bytes(bytes).ok()?;
        postcard::to_allocvec(&proof).ok()
    }

    /// TEST-ONLY (M-05 fuzz): the `(rows, lanes, public_values.len())` shape of every
    /// non-primitive table, so the fuzz can build typed mutants without the p3 types.
    #[cfg(test)]
    pub fn table_shapes(bytes: &[u8]) -> Option<Vec<(usize, usize, usize)>> {
        let proof: BatchStarkProof<MyConfig> = postcard::from_bytes(bytes).ok()?;
        Some(proof.non_primitives.iter().map(|e| (e.rows, e.lanes, e.public_values.len())).collect())
    }

    /// TEST-ONLY (M-05 fuzz): typed structural mutations over the DECODED proof — the
    /// "shape-valid / content-corrupt" and metadata-magnitude corpus classes random byte
    /// flips rarely hit (a flip usually breaks the postcard stream long before it lands in
    /// one specific field). `None` when the mutation is inapplicable (e.g. no tables).
    #[cfg(test)]
    #[derive(Debug, Clone, Copy)]
    pub enum TypedMutation {
        /// Shape-preserving CONTENT corruption: +1 (in-field) on one surfaced public value.
        /// `vk_hash` does NOT cover `public_values` (the crypto verify binds them), so this
        /// mutant passes every pre-crypto gate and exercises `verify_all_tables` itself.
        BumpPublicValue { table: usize, idx: usize },
        /// Shape-preserving: extend one table's `public_values` with `extra` fresh elements
        /// (M-05R cap-boundary probing; still passes the vk gate — pvs are not in the context).
        ExtendPublicValues { table: usize, extra: usize },
        /// Metadata magnitude: overwrite a table's row count (bound by the M-05R manifest
        /// cap when huge; bound by the vk_hash shape fold-in when merely wrong).
        SetRows { table: usize, rows: usize },
        /// Same for the lane count.
        SetLanes { table: usize, lanes: usize },
        /// Append `times` more copies of the whole table list (max_tables cap probing).
        DuplicateTables { times: usize },
    }

    #[cfg(test)]
    pub fn mutate_typed(bytes: &[u8], m: TypedMutation) -> Option<Vec<u8>> {
        let mut proof: BatchStarkProof<MyConfig> = postcard::from_bytes(bytes).ok()?;
        match m {
            TypedMutation::BumpPublicValue { table, idx } => {
                let v = proof.non_primitives.get_mut(table)?.public_values.get_mut(idx)?;
                *v += BabyBear::ONE;
            }
            TypedMutation::ExtendPublicValues { table, extra } => {
                let e = proof.non_primitives.get_mut(table)?;
                for i in 0..extra {
                    e.public_values.push(BabyBear::from_u32(0x00A5_0000 ^ (i as u32 & 0xffff)));
                }
            }
            TypedMutation::SetRows { table, rows } => proof.non_primitives.get_mut(table)?.rows = rows,
            TypedMutation::SetLanes { table, lanes } => proof.non_primitives.get_mut(table)?.lanes = lanes,
            TypedMutation::DuplicateTables { times } => {
                if proof.non_primitives.is_empty() {
                    return None;
                }
                for _ in 0..times {
                    let again: BatchStarkProof<MyConfig> = postcard::from_bytes(bytes).ok()?;
                    proof.non_primitives.extend(again.non_primitives);
                }
            }
        }
        postcard::to_allocvec(&proof).ok()
    }

    /// TEST-ONLY (K-01 table-order acceptance): re-serialize `proof_bytes` with two
    /// non-primitive tables swapped. Returns `None` when the proof has no two tables whose
    /// shape fingerprints differ (then a swap is a semantic no-op and cannot be a test
    /// vector). The swap keeps every byte of both tables intact — only their ORDER changes
    /// — so a rejection can only come from the order binding.
    #[cfg(test)]
    pub fn reserialize_with_swapped_tables(proof_bytes: &[u8]) -> Option<Vec<u8>> {
        let mut proof: BatchStarkProof<MyConfig> = postcard::from_bytes(proof_bytes).ok()?;
        let fp = |e: &p3_circuit_prover::batch_stark_prover::NonPrimitiveTableEntry<MyConfig>| {
            postcard::to_allocvec(&(&e.op_type, e.rows as u64, e.lanes as u64, &e.air_variant)).unwrap_or_default()
        };
        let n = proof.non_primitives.len();
        for i in 0..n {
            for j in (i + 1)..n {
                if fp(&proof.non_primitives[i]) != fp(&proof.non_primitives[j]) {
                    proof.non_primitives.swap(i, j);
                    return postcard::to_allocvec(&proof).ok();
                }
            }
        }
        None
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
            verifier_key_hash: vk,
            public_inputs: borsh::to_vec(&stmt).unwrap(),
            proof: borsh::to_vec(&wit).unwrap(),
        }
        .encode()
    }

    #[test]
    fn stark_backend_is_fail_closed_until_the_milestone() {
        // A well-formed STARK statement passes the deterministic front half; the verify is
        // then rejected fail-closed at the K-01 trust anchor — no production circuit has a
        // ceremony-frozen vk yet, so EVERY STARK proof is rejected regardless of whether
        // the real backend is linked (and the backend seam behind it stays fail-closed too,
        // see `frozen_manifest_reaches_the_backend_seam`).
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let r = verify_stark(CIRCUIT_SPEND, &h(0xB0), &pi, &[0u8; 32]);
        assert_eq!(r, Err(StarkVerifyError::CircuitVkNotFrozen(CIRCUIT_SPEND)));
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
        // A well-formed statement passes the front half (bounds + borsh) and stops at the
        // K-01 trust anchor (unfrozen production circuit) — fail-closed in every build.
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let r = verify_stark(CIRCUIT_SPEND, &h(0xB0), &pi, &[0u8; 64]);
        assert_eq!(r, Err(StarkVerifyError::CircuitVkNotFrozen(CIRCUIT_SPEND)));
        // and the decoded statement round-trips exactly.
        match decode_statement(CIRCUIT_SPEND, &pi).unwrap() {
            VerifiedStatement::Spend(s) => assert_eq!(s, spend_stmt()),
            _ => panic!("expected Spend"),
        }
    }

    /// The §SP-0 seam is still exercisable UNDER a frozen manifest: pin a test vk (the
    /// ceremony mechanism), present the matching expected key, and the verify proceeds past
    /// the K-01 anchor to the backend — `BackendPending` without the feature, a real
    /// verify-rejection of the garbage proof with it. Either way fail-closed.
    #[test]
    fn frozen_manifest_reaches_the_backend_seam() {
        let m = CircuitManifest { vk_hash: Some(h(0xB0)), ..manifest::SPEND_V1_MANIFEST.clone() };
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let r = verify_stark_with_manifest(&m, CIRCUIT_SPEND, &h(0xB0), &pi, &[0u8; 64]);
        #[cfg(not(feature = "stark-backend"))]
        assert_eq!(r, Err(StarkVerifyError::BackendPending));
        #[cfg(feature = "stark-backend")]
        assert!(matches!(r, Err(StarkVerifyError::MalformedStatement(_))), "real backend rejects garbage proof bytes: {r:?}");
        // …and a caller presenting a DIFFERENT expected key than the frozen pin is rejected
        // at the anchor itself (the manifest, not the caller, is the source of truth).
        assert_eq!(verify_stark_with_manifest(&m, CIRCUIT_SPEND, &h(0xB1), &pi, &[0u8; 64]), Err(StarkVerifyError::VkHashMismatch));
    }

    /// (K-01 placeholder policy) EVERY production circuit is fail-closed until its
    /// vk-pinning ceremony: valid statements, any expected key, any proof — rejected with
    /// `CircuitVkNotFrozen`, and the pinned manifests all carry `vk_hash: None`.
    #[test]
    fn production_circuits_fail_closed_until_vk_freeze() {
        let spend_pi = borsh::to_vec(&spend_stmt()).unwrap();
        let claim_pi = borsh::to_vec(&ProviderClaimStatement {
            provider_set_root: h(0x40),
            session_cm: h(0x41),
            amount: 7,
            provider_nf: misaka_mil_shield::Nullifier(h(0x42)),
            cm_payout: misaka_mil_shield::Commitment(h(0x43)),
            ctx: h(0x44),
        })
        .unwrap();
        let claim_v2_pi = borsh::to_vec(&claim_v2_stmt()).unwrap();
        let claim_v3_pi = borsh::to_vec(&claim_v3_stmt()).unwrap();
        for (cv, pi) in [
            (CIRCUIT_SPEND, &spend_pi),
            (CIRCUIT_PROVIDER_CLAIM, &claim_pi),
            (CIRCUIT_PROVIDER_CLAIM_V2, &claim_v2_pi),
            // circuit 3 (C-P6 receipt-authorized claim) is now PRESENT but unfrozen — it resolves
            // and fails closed at the vk anchor, exactly like the other production circuits.
            (CIRCUIT_PROVIDER_CLAIM_V3, &claim_v3_pi),
        ] {
            let m = manifest_for_circuit(cv).expect("pinned manifest exists");
            assert!(m.vk_hash.is_none() && m.preprocessed_commitment.is_none(), "circuit {cv} must be unfrozen (pre-ceremony)");
            assert_eq!(verify_stark(cv, &h(0xB0), pi, &[0u8; 32]), Err(StarkVerifyError::CircuitVkNotFrozen(cv)));
        }
    }

    /// (K-01) The pinned manifests are internally consistent and cross-locked to the C-01
    /// statement-schema manifest, the A3 transcript freeze, and the workspace's pinned
    /// recursion revision — the release cannot drift in any of these dimensions without
    /// this test failing.
    #[test]
    fn pinned_manifests_are_self_consistent_and_schema_locked() {
        use misaka_mil_shield::statement_schema::schema_for_circuit;
        for m in manifest::PINNED_CIRCUIT_MANIFESTS {
            let schema = schema_for_circuit(m.circuit_version).expect("every pinned circuit has a frozen statement schema");
            assert_eq!(schema.name, m.statement_schema_id, "schema id cross-lock");
            assert_eq!(schema.size, m.statement_len, "schema length cross-lock");
            assert!(m.statement_len <= MAX_PUBLIC_INPUT_BYTES, "statement must fit the decode cap");
            assert_eq!(m.transcript_kat, manifest::FIAT_SHAMIR_KAT_FROZEN, "A3 transcript pin");
            // type-level pins this binary can honour
            assert_eq!((m.field_tag, m.ext_degree, m.poseidon2_id), (0, 4, 0x0416));
            // the pinned FRI params satisfy the targeted security relation
            assert_eq!(
                m.num_queries as u32 * m.log_blowup as u32 + m.query_pow_bits as u32,
                m.security_level as u32,
                "num_queries*log_blowup + query_pow == security_level"
            );
            assert_eq!(m.recursion_rev, manifest::PINNED_RECURSION_REV);
            assert!(m.a2_patch_sha256.is_none(), "no patched-tree artifact is frozen yet");
            // the manifest lookup resolves back to the same pin
            assert_eq!(manifest_for_circuit(m.circuit_version), Some(*m));
        }
        // the manifest's recursion rev and the workspace dependency pin cannot drift apart.
        assert!(
            include_str!("../../../Cargo.toml").contains(manifest::PINNED_RECURSION_REV),
            "workspace Cargo.toml no longer pins the manifest's recursion rev — re-ceremony required"
        );
        assert!(manifest_for_circuit(999).is_none());
    }

    /// (audit m3 — A2 patch-hash pin) The on-disk audit-gated A2 statement-surfacing patch
    /// and the manifest's pinned SHA-256 cannot silently drift: hash the diff embedded from
    /// the tree and require it to equal `manifest::A2_PATCH_SHA256_ONDISK`. A change to the
    /// diff without re-pinning fails here. Additionally, any circuit that ever freezes a
    /// per-circuit `a2_patch_sha256` must reference this SAME on-disk pin (currently all
    /// `None` — the ceremony that fills them with the AUDITED tree's value stays external).
    #[test]
    fn a2_patch_diff_hash_matches_the_pinned_manifest_value() {
        use sha2::{Digest, Sha256};
        // `include_bytes!` embeds the diff at compile time (path relative to this src file),
        // so the hash is over the exact tree bytes with no runtime file-IO/CWD dependence.
        const DIFF: &[u8] = include_bytes!("../../../docs/bench/plonky3-recursion-a2-surfacing.diff");
        let digest = Sha256::digest(DIFF);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            manifest::A2_PATCH_SHA256_ONDISK,
            "on-disk A2 patch diff drifted from the pinned manifest SHA-256 — re-pin + re-ceremony"
        );
        // any circuit that has frozen a per-circuit patch hash must reference the on-disk pin.
        for m in manifest::PINNED_CIRCUIT_MANIFESTS {
            if let Some(pinned) = m.a2_patch_sha256 {
                assert_eq!(pinned, manifest::A2_PATCH_SHA256_ONDISK, "frozen a2_patch_sha256 must equal the on-disk pin");
            }
        }
    }

    /// (K-01 mutation corpus, manifest-precheck dimensions — runs in the DEFAULT build)
    /// Every field the precheck consults is mutated one at a time against a frozen test
    /// manifest; each mutation must be rejected with its typed error while the unmutated
    /// manifest passes.
    #[test]
    fn manifest_precheck_mutations_all_reject() {
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let vk = h(0xB0);
        let frozen = CircuitManifest { vk_hash: Some(vk), ..manifest::SPEND_V1_MANIFEST.clone() };
        assert_eq!(manifest_precheck(&frozen, CIRCUIT_SPEND, &vk, &pi), Ok(()), "unmutated manifest passes");

        // circuit_version
        let m = CircuitManifest { circuit_version: CIRCUIT_SPEND + 1, ..frozen.clone() };
        assert_eq!(manifest_precheck(&m, CIRCUIT_SPEND, &vk, &pi), Err(StarkVerifyError::ManifestMismatch("circuit_version")));
        // …and the same manifest presented for its OWN circuit fails the schema-id lock
        // (an attacker cannot re-badge the spend manifest as another circuit's).
        assert!(manifest_precheck(&m, CIRCUIT_SPEND + 1, &vk, &pi).is_err());

        // statement_schema_id
        let m = CircuitManifest { statement_schema_id: "ProviderClaimStatement", ..frozen.clone() };
        assert_eq!(manifest_precheck(&m, CIRCUIT_SPEND, &vk, &pi), Err(StarkVerifyError::ManifestMismatch("statement_schema_id")));

        // statement_len (manifest side and presented-bytes side)
        let m = CircuitManifest { statement_len: frozen.statement_len + 1, ..frozen.clone() };
        assert_eq!(manifest_precheck(&m, CIRCUIT_SPEND, &vk, &pi), Err(StarkVerifyError::ManifestMismatch("statement length")));
        assert_eq!(
            manifest_precheck(&frozen, CIRCUIT_SPEND, &vk, &pi[..pi.len() - 1]),
            Err(StarkVerifyError::ManifestMismatch("statement length"))
        );

        // transcript_kat
        let mut kat = frozen.transcript_kat;
        kat[0] ^= 1;
        let m = CircuitManifest { transcript_kat: kat, ..frozen.clone() };
        assert_eq!(manifest_precheck(&m, CIRCUIT_SPEND, &vk, &pi), Err(StarkVerifyError::ManifestMismatch("transcript_kat")));

        // vk_hash: mutated pin ⇒ mismatch; unfrozen ⇒ fail-closed
        let m = CircuitManifest { vk_hash: Some(h(0xB1)), ..frozen.clone() };
        assert_eq!(manifest_precheck(&m, CIRCUIT_SPEND, &vk, &pi), Err(StarkVerifyError::VkHashMismatch));
        let m = CircuitManifest { vk_hash: None, ..frozen.clone() };
        assert_eq!(manifest_precheck(&m, CIRCUIT_SPEND, &vk, &pi), Err(StarkVerifyError::CircuitVkNotFrozen(CIRCUIT_SPEND)));

        // caller-side: a different expected key than the pin is rejected (trust anchor)
        assert_eq!(manifest_precheck(&frozen, CIRCUIT_SPEND, &h(0x77), &pi), Err(StarkVerifyError::VkHashMismatch));
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
        // through verify_stark regardless (the K-01 anchor rejects the unfrozen circuit).
        let r = verify_stark(CIRCUIT_PROVIDER_CLAIM, &h(0xB0), &pi, &[0u8; 32]);
        assert_eq!(r, Err(StarkVerifyError::CircuitVkNotFrozen(CIRCUIT_PROVIDER_CLAIM)));
    }

    #[test]
    fn decode_is_deterministic() {
        // Same input → same output, every time (no hidden state / ordering).
        let pi = borsh::to_vec(&spend_stmt()).unwrap();
        let a = decode_statement(CIRCUIT_SPEND, &pi);
        let b = decode_statement(CIRCUIT_SPEND, &pi);
        assert_eq!(a, b);
    }

    // ---- C-01: the claim-v2 statement at the node boundary ----

    fn claim_v2_stmt() -> ProviderClaimStatementV2 {
        ProviderClaimStatementV2 {
            provider_set_root: h(0x50),
            session_cm: h(0x51),
            v_claim_cm: h(0x52),
            provider_nf: misaka_mil_shield::Nullifier(h(0x53)),
            cm_payout: misaka_mil_shield::Commitment(h(0x54)),
            provider_share_sompi: 88,
            ctx: h(0x55),
        }
    }

    fn claim_v3_stmt() -> ProviderClaimStatementV3 {
        ProviderClaimStatementV3 {
            provider_set_root: h(0x60),
            session_cm: h(0x61),
            v_claim_cm: h(0x62),
            provider_nf: misaka_mil_shield::Nullifier(h(0x63)),
            cm_payout: misaka_mil_shield::Commitment(h(0x64)),
            receipt_cm: h(0x65),
            provider_share_sompi: 88,
            ctx: h(0x66),
        }
    }

    /// Circuit 4 decodes its schema-frozen 392-byte statement; every size in this
    /// verifier derives from the C-01 statement-schema manifest.
    #[test]
    fn provider_claim_v2_statement_decodes_and_matches_the_schema_manifest() {
        use misaka_mil_shield::statement_schema::{ALL_STATEMENT_SCHEMAS, schema_for_circuit};
        let claim = claim_v2_stmt();
        let pi = borsh::to_vec(&claim).unwrap();
        // the manifest is the single source of truth for the encoded size.
        let schema = schema_for_circuit(CIRCUIT_PROVIDER_CLAIM_V2).expect("v2 schema frozen");
        assert_eq!(pi.len(), schema.size, "borsh(v2 statement) must equal the manifest size (392)");
        match decode_statement(CIRCUIT_PROVIDER_CLAIM_V2, &pi).unwrap() {
            VerifiedStatement::ProviderClaimV2(c) => assert_eq!(c, claim),
            _ => panic!("expected ProviderClaimV2"),
        }
        // the surfaced-pvs encoding covers exactly the manifest bytes.
        assert_eq!(statement_to_pvs(&pi).len(), schema.size);
        // every frozen statement fits the decode cap (the cap can never false-reject).
        for s in ALL_STATEMENT_SCHEMAS {
            assert!(s.size <= MAX_PUBLIC_INPUT_BYTES, "{} ({} B) must fit the cap", s.name, s.size);
        }
        // the share field sits at the manifest offset in the pvs vector too.
        let f = schema.field("provider_share_sompi").unwrap();
        let pvs = statement_to_pvs(&pi);
        assert_eq!(&pvs[f.range()], &claim.provider_share_sompi.to_le_bytes().map(|b| b as u64)[..]);
    }

    /// (C-P6 / ADR-0037 §2.4) Circuit 3 resolves its release-pinned manifest and FAILS CLOSED
    /// (`CircuitVkNotFrozen`) — the inert production surface — while its 456-byte statement
    /// decodes and round-trips through the schema-frozen decoder. This is the exact shape the
    /// task requires: verify_stark resolves circuit 3, fails closed on the vk anchor, and the
    /// statement decodes size-checked against the schema.
    #[test]
    fn provider_claim_v3_resolves_and_fails_closed_but_statement_round_trips() {
        use misaka_mil_shield::statement_schema::schema_for_circuit;
        let claim = claim_v3_stmt();
        let pi = borsh::to_vec(&claim).unwrap();
        // the schema is the single source of truth for the size (456).
        let schema = schema_for_circuit(CIRCUIT_PROVIDER_CLAIM_V3).expect("v3 schema frozen");
        assert_eq!(pi.len(), schema.size, "borsh(v3 statement) must equal the manifest size (456)");
        assert_eq!(schema.name, "ProviderClaimStatementV3");
        // verify_stark RESOLVES circuit 3 (manifest present) and fails closed at the K-01 anchor
        // (vk unfrozen) — NOT UnknownCircuit. The manifest cross-locks to the schema.
        let m = manifest_for_circuit(CIRCUIT_PROVIDER_CLAIM_V3).expect("circuit 3 manifest present");
        assert!(m.vk_hash.is_none(), "circuit 3 vk is unfrozen (inert)");
        assert_eq!(m.statement_len, schema.size);
        assert_eq!(
            verify_stark(CIRCUIT_PROVIDER_CLAIM_V3, &h(0xB0), &pi, &[0u8; 64]),
            Err(StarkVerifyError::CircuitVkNotFrozen(CIRCUIT_PROVIDER_CLAIM_V3))
        );
        // the statement decodes and round-trips exactly.
        match decode_statement(CIRCUIT_PROVIDER_CLAIM_V3, &pi).unwrap() {
            VerifiedStatement::ProviderClaimV3(c) => assert_eq!(c, claim),
            other => panic!("expected ProviderClaimV3, got {other:?}"),
        }
        // the surfaced-pvs encoding covers exactly the manifest bytes, and receipt_cm sits at [320,384).
        assert_eq!(statement_to_pvs(&pi).len(), schema.size);
        let f = schema.field("receipt_cm").unwrap();
        assert_eq!(f.range(), 320..384);
        // strict borsh rejects malformed sizes at decode (never panics).
        for bad in [&pi[..pi.len() - 1], &pi[..0], &[pi.clone(), vec![0u8]].concat()[..]] {
            assert!(
                matches!(decode_statement(CIRCUIT_PROVIDER_CLAIM_V3, bad), Err(StarkVerifyError::MalformedStatement(_))),
                "malformed v3 statement must be rejected at decode ({} bytes)",
                bad.len()
            );
        }
        // cross-circuit confusion: v2 (392 B) and v3 (456 B) can never decode as each other.
        assert!(decode_statement(CIRCUIT_PROVIDER_CLAIM_V3, &borsh::to_vec(&claim_v2_stmt()).unwrap()).is_err());
        assert!(decode_statement(CIRCUIT_PROVIDER_CLAIM_V2, &pi).is_err());
    }

    /// (audit C-01 acceptance — statement mutations at the NODE layer) payout ±1,
    /// field-order swap, trailing append, truncation, zero, max: every mutation
    /// either fails the strict borsh decode or yields DIFFERENT pvs, so
    /// `statement_is_bound` rejects it against a proof surfacing the true statement.
    #[test]
    fn claim_v2_statement_mutations_fail_decode_or_binding() {
        let base = claim_v2_stmt();
        let pi = borsh::to_vec(&base).unwrap();
        // the "proof" surfaces exactly the true statement.
        let surfaced = vec![statement_to_pvs(&pi)];
        assert!(statement_is_bound(&surfaced, &pi), "true statement binds");

        // (a) decode-level rejections: truncation / trailing append / empty.
        for bad in [&pi[..pi.len() - 1], &pi[..0], &[pi.clone(), vec![0u8]].concat()[..]] {
            assert!(
                matches!(decode_statement(CIRCUIT_PROVIDER_CLAIM_V2, bad), Err(StarkVerifyError::MalformedStatement(_))),
                "malformed v2 statement must be rejected at decode ({} bytes)",
                bad.len()
            );
        }

        // (b) binding-level rejections: well-formed but DIFFERENT statements.
        let mut mutants: Vec<ProviderClaimStatementV2> = vec![];
        for share in [89u64, 87, 0, u64::MAX] {
            mutants.push(ProviderClaimStatementV2 { provider_share_sompi: share, ..base.clone() });
        }
        // field-order swap (same-width fields exchanged).
        mutants.push(ProviderClaimStatementV2 { session_cm: base.v_claim_cm, v_claim_cm: base.session_cm, ..base.clone() });
        mutants.push(ProviderClaimStatementV2 { provider_set_root: base.ctx, ctx: base.provider_set_root, ..base.clone() });
        for (i, m) in mutants.iter().enumerate() {
            let mpi = borsh::to_vec(m).unwrap();
            // still decodes (well-formed) …
            assert!(decode_statement(CIRCUIT_PROVIDER_CLAIM_V2, &mpi).is_ok(), "mutant {i} is well-formed");
            // … but does NOT bind against a proof surfacing the true statement.
            assert!(!statement_is_bound(&surfaced, &mpi), "mutant {i} must not bind (replay defense)");
        }

        // (c) cross-circuit confusion: v1 (328 B) and v2 (392 B) statements can never
        // decode as each other (schema sizes differ; borsh is strict).
        assert!(decode_statement(CIRCUIT_PROVIDER_CLAIM, &pi).is_err(), "v2 bytes must not decode as v1");
        let v1 = ProviderClaimStatement {
            provider_set_root: h(0x50),
            session_cm: h(0x51),
            amount: 88,
            provider_nf: misaka_mil_shield::Nullifier(h(0x53)),
            cm_payout: misaka_mil_shield::Commitment(h(0x54)),
            ctx: h(0x55),
        };
        let v1pi = borsh::to_vec(&v1).unwrap();
        assert!(decode_statement(CIRCUIT_PROVIDER_CLAIM_V2, &v1pi).is_err(), "v1 bytes must not decode as v2");
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
            non_primitive_ops: vec![vec![7], vec![2], vec![7], vec![5]],
            preprocessed_commitment: vec![0xAB; 32],
            alu_shape: vec![0xCD; 8],
        }
    }

    #[test]
    fn vk_hash_binds_table_order_and_multiplicity() {
        let a = compute_vk_hash(&ctx()).unwrap();
        let b = compute_vk_hash(&ctx()).unwrap();
        assert_eq!(a, b, "vk_hash must be deterministic");
        // (2026-07-11 re-audit K-01 `table_order`) REGRESSION: the same context with the
        // non-primitive tables in a different ORDER (same multiset) must hash DIFFERENTLY —
        // the verifier reconstructs AIRs positionally, so the vk pins the exact order. An
        // earlier revision sorted the fingerprints and this very case hashed identically.
        let mut c = ctx();
        c.non_primitive_ops = vec![vec![5], vec![7], vec![2], vec![7]]; // a permutation of [7,2,7,5]
        assert_ne!(compute_vk_hash(&c).unwrap(), a, "table order must change vk_hash (K-01 table_order)");
        // a two-entry swap alone is enough to change the hash…
        let mut s = ctx();
        s.non_primitive_ops.swap(0, 1);
        assert_ne!(compute_vk_hash(&s).unwrap(), a, "a single table swap must change vk_hash");
        // …and DROPPING a duplicate (losing multiplicity) also changes it (K-01.1).
        let mut d = ctx();
        d.non_primitive_ops = vec![vec![5], vec![7], vec![2]]; // one 7 removed
        assert_ne!(compute_vk_hash(&d).unwrap(), a, "op multiplicity must affect vk_hash (K-01.1)");
    }

    #[test]
    fn vk_hash_is_sensitive_to_every_field() {
        let base = compute_vk_hash(&ctx()).unwrap();
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
            |c| c.non_primitive_ops.push(vec![255]),
            |c| c.preprocessed_commitment[0] ^= 1,
            |c| c.alu_shape.push(9),
        ];
        for (i, m) in mutators.iter().enumerate() {
            let mut c = ctx();
            m(&mut c);
            assert_ne!(compute_vk_hash(&c).unwrap(), base, "field {i} must affect vk_hash");
        }
    }

    // (L-01) `compute_vk_hash` is a typed `Result`, never a panic and never a silent
    // empty-byte fallback. The normal context hashes as `Ok`; and two contexts that differ ONLY
    // in a field that the former `unwrap_or_default()` could have collapsed to `b""` (here
    // `preprocessed_commitment`) still produce DIFFERENT hashes — proving the removed
    // empty-fallback cannot alias two distinct trust anchors to one `vk_hash`.
    #[test]
    fn vk_hash_is_a_typed_result_without_empty_fallback_aliasing() {
        assert!(compute_vk_hash(&ctx()).is_ok(), "a well-formed context serializes to Ok, not a panic");
        let mut empty_pp = ctx();
        empty_pp.preprocessed_commitment = Vec::new(); // what a silent unwrap_or_default() would have produced
        let mut real_pp = ctx();
        real_pp.preprocessed_commitment = vec![0x11; 48];
        assert_ne!(
            compute_vk_hash(&empty_pp).unwrap(),
            compute_vk_hash(&real_pp).unwrap(),
            "an empty vs a real preprocessed commitment must never share a vk_hash (no empty-fallback aliasing)"
        );
    }

    // ---- A1: the REAL verify back-half (only under the stark-backend feature) ----
    // (A3) The pinned Fiat-Shamir transcript is FROZEN: the challenger's known-answer must not
    // drift. Any change to the Poseidon2 permutation, the challenger width/rate/sampling, or the
    // field flips these values — forcing a deliberate re-freeze + re-ceremony. The frozen value
    // lives in the release manifest (`manifest::FIAT_SHAMIR_KAT_FROZEN`, captured 2026-07-11
    // from the pinned Poseidon2-BabyBear-D4-W16 DuplexChallenger); `verify_outer_proof` also
    // recomputes it live per verify. Re-capture ONLY with a deliberate transcript change
    // (which requires a new vk-pinning ceremony).
    #[cfg(feature = "stark-backend")]
    #[test]
    fn fiat_shamir_transcript_is_frozen() {
        // Uncomment to (re-)capture after a DELIBERATE change:
        // println!("KAT = {:?}", backend::fiat_shamir_kat());
        assert_eq!(
            backend::fiat_shamir_kat(),
            manifest::FIAT_SHAMIR_KAT_FROZEN,
            "Fiat-Shamir transcript drifted — A3 re-freeze + re-ceremony required"
        );
    }

    /// Run the CEREMONY MECHANISM against a designated artifact: derive the vk_hash and
    /// the raw preprocessed-commitment bytes exactly as the vk-pinning ceremony would,
    /// and freeze them into a manifest. In production this transcription happens once,
    /// against the audited circuit artifact, into `manifest.rs` — here it stands in so
    /// the acceptance corpus can exercise a FROZEN manifest end to end.
    #[cfg(feature = "stark-backend")]
    fn ceremony_freeze(m: &CircuitManifest, circuit_version: u16, proof: &[u8]) -> (CircuitManifest, Hash64) {
        let vk = backend::ceremony_vk_hash(m, circuit_version, proof).expect("ceremony vk_hash");
        let pp: &'static [u8] =
            Box::leak(backend::ceremony_preprocessed_commitment(proof).expect("ceremony preprocessed").into_boxed_slice());
        (CircuitManifest { vk_hash: Some(vk), preprocessed_commitment: Some(pp), ..m.clone() }, vk)
    }

    #[cfg(feature = "stark-backend")]
    #[test]
    fn real_backend_verifies_the_production_proof_and_rejects_tampering() {
        // Point MIL_OUTER_PROOF at a dumped recursion outer proof produced with the
        // pinned params (e.g. the ~100-bit spend_outer_sec100.bin). The real verify
        // back-half must ACCEPT it and REJECT a one-bit-flipped copy — fail-closed,
        // panic-free. Without the artifact the test is a no-op (CI without the file).
        // NOTE the artifact must match the BUILD: a pre-surfacing artifact works under
        // plain `stark-backend`; an A2 SURFACED artifact (produced by the patched
        // recursion tree, docs/bench/plonky3-recursion-a2-surfacing.diff) additionally
        // requires `--features stark-backend-a2-surface` + the local [patch] — under the
        // plain pinned build its surface table is (correctly, fail-closed) rejected as an
        // unknown non-primitive op, which this test would surface as a crypto-verify panic.
        let Ok(path) = std::env::var("MIL_OUTER_PROOF") else {
            eprintln!("MIL_OUTER_PROOF not set — skipping the real-backend verify");
            return;
        };
        let proof = std::fs::read(&path).expect("read outer proof");

        // (K-01) freeze a manifest around the artifact (the ceremony mechanism); at verify
        // time the expected values come only from that frozen manifest.
        let (frozen, vk) = ceremony_freeze(&manifest::SPEND_V1_MANIFEST, CIRCUIT_SPEND, &proof);

        // (A3) a wrong expected vk_hash is rejected; the pinned one passes the A3 gate.
        assert_eq!(
            backend::verify_outer_proof(&frozen, &h(0xB0), CIRCUIT_SPEND, &proof),
            Err(StarkVerifyError::VkHashMismatch),
            "a proof whose shape does not hash to the pinned vk_hash is rejected (A3)"
        );

        // (A1) CRYPTO verify under the CORRECT vk_hash: the real proof passes
        // `verify_all_tables` under the pinned config, and returns the surfaced public values.
        let surfaced = backend::verify_outer_proof(&frozen, &vk, CIRCUIT_SPEND, &proof).expect("production proof crypto-verifies");

        // (A2) NODE binding is enforced by verify_stark on top of the crypto verify:
        if let Some(surfaced_stmt) = surfaced.iter().find(|pv| !pv.is_empty()) {
            // The prover surfaces a statement ⇒ end-to-end binding is exercisable: feeding
            // the SURFACED statement accepts, and any DIFFERENT statement fails-closed.
            assert!(surfaced_stmt.iter().all(|&v| v < 256), "surfaced values are canonical statement bytes");
            let bound_pi: Vec<u8> = surfaced_stmt.iter().map(|&v| v as u8).collect();
            assert!(statement_is_bound(&surfaced, &bound_pi), "the surfaced statement binds");
            let mut other = bound_pi.clone();
            other[0] ^= 1;
            assert!(!statement_is_bound(&surfaced, &other), "a different statement is not bound (A2 fail-closed)");
            eprintln!("A2 real backend: crypto-verify + surfaced-statement binding both hold (accept-on-match, reject-on-mismatch)");

            // FULL node path (A1+A3+A2 in one call): when the surfaced bytes decode as the
            // frozen 404-byte SpendStatement (the recursive_spend pipeline surfaces exactly
            // the borsh statement, 1 byte = 1 BabyBear element), `verify_stark` must ACCEPT
            // the true statement and REJECT a tampered-but-well-formed one (flipping one
            // anchor byte still borsh-decodes, so the reject is A2 binding, not a parse error).
            match decode_statement(CIRCUIT_SPEND, &bound_pi) {
                Ok(VerifiedStatement::Spend(s)) => {
                    assert_eq!(
                        verify_stark_with_manifest(&frozen, CIRCUIT_SPEND, &vk, &bound_pi, &proof),
                        Ok(VerifiedStatement::Spend(s)),
                        "full verify accepts the surfaced statement (K-01 anchor + A1 crypto + A3 vk + A2 binding)"
                    );
                    let mut tampered_pi = bound_pi.clone();
                    tampered_pi[0] ^= 1; // a DIFFERENT (still decodable) statement
                    assert_eq!(
                        verify_stark_with_manifest(&frozen, CIRCUIT_SPEND, &vk, &tampered_pi, &proof),
                        Err(StarkVerifyError::StatementNotSurfaced),
                        "full verify rejects a tampered statement (A2 fail-closed)"
                    );
                    eprintln!("A2 E2E: full verify ACCEPTS the surfaced 404-byte SpendStatement and REJECTS a tampered one");
                }
                _ => eprintln!(
                    "surfaced statement ({} bytes) is not a SpendStatement — binding demonstrated on raw bytes only",
                    bound_pi.len()
                ),
            }
        } else {
            // Prover-side surfacing pending (current artifacts carry empty batch-level public
            // values): the crypto verify passes, but the full verify correctly FAILS CLOSED
            // because it cannot bind the statement — an unbound proof must not be accepted.
            let stmt = borsh::to_vec(&spend_stmt()).unwrap();
            assert_eq!(
                verify_stark_with_manifest(&frozen, CIRCUIT_SPEND, &vk, &stmt, &proof), // past K-01+A3, reaches A2
                Err(StarkVerifyError::StatementNotSurfaced),
                "crypto-valid but unbound ⇒ fail-closed (A2), never silently accepted"
            );
            eprintln!(
                "A1/A3 real backend: proof crypto-verifies + vk_hash matches; A2 node-binding fail-closed (prover surfacing pending)"
            );
        }

        // (K-01) the PRODUCTION path stays fail-closed for the very same artifact + key:
        // the compiled-in manifest is unfrozen, so `verify_stark` (which resolves only the
        // pinned set) rejects even this crypto-valid proof until the real ceremony lands.
        let stmt404 = borsh::to_vec(&spend_stmt()).unwrap();
        assert_eq!(
            verify_stark(CIRCUIT_SPEND, &vk, &stmt404, &proof),
            Err(StarkVerifyError::CircuitVkNotFrozen(CIRCUIT_SPEND)),
            "production manifest unfrozen ⇒ the artifact cannot verify through verify_stark yet"
        );

        // (A1 negative) a one-bit flip in the proof is rejected by the crypto verify itself
        // (fail-closed, no panic) — before A2 binding is even reached.
        let mut bad = proof.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        assert!(
            backend::verify_outer_proof(&frozen, &vk, CIRCUIT_SPEND, &bad).is_err(),
            "a tampered proof must be rejected (vk_hash mismatch or crypto reject)"
        );
    }

    /// (K-01 acceptance — FULL manifest-field mutation corpus against the REAL artifact)
    /// Every decision-bearing manifest field is mutated one at a time; the unmutated
    /// frozen manifest ACCEPTS the artifact (crypto verify) and every mutation REJECTS it
    /// with its typed error. Provenance strings (`recursion_rev`, `a2_patch_sha256`) are
    /// not runtime inputs; their drift is caught by
    /// `pinned_manifests_are_self_consistent_and_schema_locked`. Skips without the artifact.
    #[cfg(feature = "stark-backend")]
    #[test]
    fn manifest_field_mutations_reject_the_real_artifact() {
        let Ok(path) = std::env::var("MIL_OUTER_PROOF") else {
            eprintln!("MIL_OUTER_PROOF not set — skipping the manifest mutation corpus");
            return;
        };
        let proof = std::fs::read(&path).expect("read outer proof");
        let (frozen, vk) = ceremony_freeze(&manifest::SPEND_V1_MANIFEST, CIRCUIT_SPEND, &proof);
        // baseline: the frozen manifest accepts (crypto verify + preprocessed anchor).
        assert!(backend::verify_outer_proof(&frozen, &vk, CIRCUIT_SPEND, &proof).is_ok(), "frozen manifest accepts the artifact");

        // every FRI/PCS param folds into the recomputed context ⇒ VkHashMismatch.
        type ManifestMutator = fn(&mut CircuitManifest);
        let param_mutations: Vec<(&str, ManifestMutator)> = vec![
            ("log_blowup", |m| m.log_blowup += 1),
            ("num_queries", |m| m.num_queries += 1),
            ("commit_pow_bits", |m| m.commit_pow_bits += 1),
            ("query_pow_bits", |m| m.query_pow_bits ^= 1),
            ("max_log_arity", |m| m.max_log_arity += 1),
            ("log_final_poly_len", |m| m.log_final_poly_len += 1),
            ("cap_height", |m| m.cap_height += 1),
            ("security_level", |m| m.security_level ^= 1),
        ];
        for (name, mutate) in param_mutations {
            let mut m = frozen.clone();
            mutate(&mut m);
            assert_eq!(
                backend::verify_outer_proof(&m, &vk, CIRCUIT_SPEND, &proof),
                Err(StarkVerifyError::VkHashMismatch),
                "mutated {name} must be rejected"
            );
        }

        // type-level pins this binary cannot honour ⇒ ManifestMismatch (fail-closed, never
        // a verify under a mislabeled field/extension/transcript).
        for (name, mutate) in [
            ("field_tag", (|m| m.field_tag = 1) as fn(&mut CircuitManifest)),
            ("ext_degree", |m| m.ext_degree = 5),
            ("poseidon2_id", |m| m.poseidon2_id ^= 1),
        ] {
            let mut m = frozen.clone();
            mutate(&mut m);
            assert_eq!(
                backend::verify_outer_proof(&m, &vk, CIRCUIT_SPEND, &proof),
                Err(StarkVerifyError::ManifestMismatch("field/ext_degree/poseidon2 type-level pin")),
                "mutated {name} must be rejected"
            );
        }

        // the live transcript KAT ⇒ TranscriptDrift.
        let mut m = frozen.clone();
        m.transcript_kat[0] ^= 1;
        assert_eq!(
            backend::verify_outer_proof(&m, &vk, CIRCUIT_SPEND, &proof),
            Err(StarkVerifyError::TranscriptDrift),
            "mutated transcript_kat must be rejected by the live KAT recompute"
        );

        // the independent preprocessed anchor ⇒ PreprocessedCommitmentMismatch.
        let mut m = frozen.clone();
        m.preprocessed_commitment = Some(b"MISAKA-SHIELD-NO-PREPROCESSED-v1");
        assert_eq!(
            backend::verify_outer_proof(&m, &vk, CIRCUIT_SPEND, &proof),
            Err(StarkVerifyError::PreprocessedCommitmentMismatch),
            "a different pinned preprocessed commitment must be rejected byte-for-byte"
        );
        // …which also proves the REAL artifact carries an actual preprocessed commitment
        // (not the no-preprocessed sentinel) — the sentinel pin above did not match it.
        assert_ne!(
            backend::ceremony_preprocessed_commitment(&proof).unwrap(),
            b"MISAKA-SHIELD-NO-PREPROCESSED-v1".to_vec(),
            "production artifact must commit real preprocessed columns"
        );

        // metadata bounds (M-05R, manifest-pinned) ⇒ bounded before trace reconstruction.
        for (name, mutate) in [
            ("max_tables", (|m: &mut CircuitManifest| m.max_tables = 0) as fn(&mut CircuitManifest)),
            ("max_rows_per_table", |m| m.max_rows_per_table = 0),
            ("max_lanes_per_table", |m| m.max_lanes_per_table = 0),
        ] {
            let mut m = frozen.clone();
            mutate(&mut m);
            assert!(
                matches!(backend::verify_outer_proof(&m, &vk, CIRCUIT_SPEND, &proof), Err(StarkVerifyError::MalformedStatement(_))),
                "zeroed {name} bound must reject the artifact's metadata"
            );
        }
        // (max_public_values_per_table = 0 is only violated by a table that HAS public
        // values; pre-A2 artifacts may carry none, so it is not asserted here.)

        // vk_hash / statement-side mutations reject at the precheck (full-path form).
        let stmt404 = borsh::to_vec(&spend_stmt()).unwrap();
        let mut m = frozen.clone();
        m.vk_hash = Some(h(0xEE));
        assert_eq!(
            verify_stark_with_manifest(&m, CIRCUIT_SPEND, &vk, &stmt404, &proof),
            Err(StarkVerifyError::VkHashMismatch),
            "a mutated frozen vk pin must reject the true key"
        );
        let mut m = frozen.clone();
        m.circuit_version = CIRCUIT_PROVIDER_CLAIM;
        assert_eq!(
            verify_stark_with_manifest(&m, CIRCUIT_SPEND, &vk, &stmt404, &proof),
            Err(StarkVerifyError::ManifestMismatch("circuit_version")),
            "a re-badged circuit_version must be rejected"
        );

        // cross-circuit (alternate-AIR-adjacent): the SAME proof + key presented as a
        // DIFFERENT circuit version recomputes a different context ⇒ VkHashMismatch.
        assert_eq!(
            backend::verify_outer_proof(&frozen, &vk, CIRCUIT_PROVIDER_CLAIM, &proof),
            Err(StarkVerifyError::VkHashMismatch),
            "the spend artifact must not verify as the provider-claim circuit"
        );
    }

    /// (K-01 acceptance — table-order binding against the REAL artifact) Re-serialize the
    /// artifact with two non-primitive tables swapped (bytes intact, order changed): the
    /// recomputed context hashes differently ⇒ VkHashMismatch. Skips without the artifact
    /// (and when the artifact has no two distinguishable tables, in which case a swap is a
    /// semantic no-op).
    #[cfg(feature = "stark-backend")]
    #[test]
    fn reordered_tables_are_rejected_on_the_real_artifact() {
        let Ok(path) = std::env::var("MIL_OUTER_PROOF") else {
            eprintln!("MIL_OUTER_PROOF not set — skipping the table-reorder corpus");
            return;
        };
        let proof = std::fs::read(&path).expect("read outer proof");
        let (frozen, vk) = ceremony_freeze(&manifest::SPEND_V1_MANIFEST, CIRCUIT_SPEND, &proof);
        let Some(swapped) = backend::reserialize_with_swapped_tables(&proof) else {
            eprintln!("artifact has no two distinguishable non-primitive tables — reorder is a no-op, skipping");
            return;
        };
        assert_eq!(
            backend::verify_outer_proof(&frozen, &vk, CIRCUIT_SPEND, &swapped),
            Err(StarkVerifyError::VkHashMismatch),
            "a same-multiset table reorder must change the vk_hash (K-01 table_order)"
        );
    }

    /// (audit 2026-07-11 M-05 MUST-FIX — malformed OUTER-PROOF corpus through the REAL
    /// backend) The one panic-freeness gap the M-05 reachability triage identified: the
    /// reference-path fuzz (edfdc92, `misaka_mil_shield::proof` tests) never exercises the
    /// `stark-backend` verify loop, so the vendored p3 `verify_all_tables` path was only
    /// ARGUED panic-free, not demonstrated. This corpus demonstrates it — WITHOUT
    /// `catch_unwind`: a panic anywhere unwinds through the test and fails it (in
    /// production that unwind is an F006 consensus halt, the M-05 node-DoS).
    ///
    /// Seeds:
    ///  1. HERMETIC — a genuine proof of the alternate easy circuit under the exact pinned
    ///     config, proved in-test (runs in every `--features stark-backend` job, no file);
    ///  2. the REAL production artifact when `MIL_OUTER_PROOF` is set (e.g.
    ///     `spend_outer_sec100.bin`, whose Poseidon2/recompose tables give the typed
    ///     corpus real non-primitive metadata to mutate).
    ///
    /// Classes: random bytes / truncations / bit-flips / trailing garbage (byte level,
    /// most decode-reject, many bit-flips land in opening data ⇒ shape-valid
    /// content-corrupt mutants that pass every pre-crypto gate and are rejected inside the
    /// crypto verify itself), plus TYPED mutants (`backend::mutate_typed`) probing the
    /// M-05R manifest caps at their exact boundaries and the vk_hash shape binding.
    ///
    /// Soundness invariant on top of no-unwind: an accepted input must be a semantic
    /// no-op — its canonical re-encoding must equal the seed's (postcard ignores trailing
    /// garbage, so byte-identity is deliberately NOT the bar; proof-bytes malleability is
    /// bounded at the consensus layer by the strict borsh envelope + `bind_artifact`).
    #[cfg(feature = "stark-backend")]
    #[test]
    fn malformed_outer_proofs_never_panic() {
        // splitmix64 (audit M-05): an LCG's low bits have tiny periods, which starves
        // `% 4` class selection (observed on the DA corpus); splitmix64 avalanches them.
        let mut seed_state = 0x0057_0911_ace5_u64;
        let mut rng = move || {
            seed_state = seed_state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed_state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let stmt404 = borsh::to_vec(&spend_stmt()).unwrap();

        // seed 1: hermetic (every CI run); seed 2: the real artifact (when provided). The
        // real artifact gets a smaller byte-level count (its verify is ~10× costlier) but
        // the FULL typed corpus (it actually has non-primitive tables to mutate).
        let mut corpus: Vec<(Vec<u8>, usize)> =
            vec![(backend::prove_easy_alternate_circuit(&manifest::SPEND_V1_MANIFEST, 64), 20_000)];
        match std::env::var("MIL_OUTER_PROOF") {
            Ok(path) => corpus.push((std::fs::read(&path).expect("read outer proof"), 2_000)),
            Err(_) => eprintln!("MIL_OUTER_PROOF not set — running the hermetic corpus only"),
        }

        for (proof, iters) in corpus {
            let (frozen, vk) = ceremony_freeze(&manifest::SPEND_V1_MANIFEST, CIRCUIT_SPEND, &proof);
            assert!(backend::verify_outer_proof(&frozen, &vk, CIRCUIT_SPEND, &proof).is_ok(), "seed proof accepts before mutation");
            let canonical = backend::canonical_reencode(&proof).expect("seed re-encodes");

            // ---- byte-level corpus ----
            // corpus-quality counter: bit-flip mutants that still POSTCARD-DECODE are the
            // ones that reach past the decode into the metadata caps / vk gate / crypto
            // verify; asserted below so a starved generator fails loudly (the LCG low-bit
            // pathology found and fixed on the DA corpus).
            let mut n_flip_decodable = 0u32;
            for i in 0..iters {
                let class = rng() % 4;
                let bytes: Vec<u8> = match class {
                    0 => {
                        // pure random bytes, random length (postcard varint headers, etc.).
                        let len = (rng() % 2048) as usize;
                        (0..len).map(|_| (rng() & 0xff) as u8).collect()
                    }
                    1 => {
                        // truncation (short-read decode paths).
                        let n = (rng() as usize) % (proof.len() + 1);
                        proof[..n].to_vec()
                    }
                    2 => {
                        // 1–16 random bit/byte flips. Flips confined to opening/FRI data
                        // decode fine AND keep the vk-bound shape ⇒ they reach and must be
                        // rejected INSIDE `verify_all_tables` (the previously unfuzzed path).
                        let mut v = proof.clone();
                        for _ in 0..1 + (rng() % 16) {
                            let i = (rng() as usize) % v.len();
                            v[i] ^= (rng() & 0xff) as u8;
                        }
                        v
                    }
                    _ => {
                        // trailing garbage (postcard ignores it ⇒ may legitimately verify;
                        // the canonical-re-encoding invariant is what's asserted).
                        let mut v = proof.clone();
                        v.extend((0..(rng() % 64)).map(|_| (rng() & 0xff) as u8));
                        v
                    }
                };
                if class == 2 && backend::table_shapes(&bytes).is_some() {
                    n_flip_decodable += 1;
                }
                let r = backend::verify_outer_proof(&frozen, &vk, CIRCUIT_SPEND, &bytes);
                if r.is_ok() {
                    assert_eq!(
                        backend::canonical_reencode(&bytes).as_ref(),
                        Some(&canonical),
                        "an accepted mutant must be a semantic no-op (iter {i})"
                    );
                }
                // the FULL node path (statement decode + K-01 anchor + backend + A2 binding)
                // on a subset — must return, never unwind.
                if i % 16 == 0 {
                    let _ = verify_stark_with_manifest(&frozen, CIRCUIT_SPEND, &vk, &stmt404, &bytes);
                }
            }
            eprintln!("byte corpus done: {iters} mutants, {n_flip_decodable} decodable bit-flip mutants reached past decode");
            // corpus reach floor: fails loudly if the generator regresses into starved
            // classes (calibrated well below the measured decodable-flip rate).
            assert!(n_flip_decodable >= (iters / 400) as u32, "corpus starved: {n_flip_decodable} decodable flip mutants");

            // ---- typed structural corpus (M-05R cap boundaries + shape binding) ----
            let shapes = backend::table_shapes(&proof).expect("seed decodes");
            let mut typed: Vec<backend::TypedMutation> = Vec::new();
            for (t, &(rows, lanes, n_pv)) in shapes.iter().enumerate() {
                // exact wrong-shape (vk-bound): ±1 on rows/lanes, still under the caps.
                typed.push(backend::TypedMutation::SetRows { table: t, rows: rows + 1 });
                typed.push(backend::TypedMutation::SetRows { table: t, rows: rows.saturating_sub(1) });
                typed.push(backend::TypedMutation::SetLanes { table: t, lanes: lanes + 1 });
                // M-05R magnitude bounds, at the boundary and just past it.
                typed.push(backend::TypedMutation::SetRows { table: t, rows: frozen.max_rows_per_table + 1 });
                typed.push(backend::TypedMutation::SetRows { table: t, rows: usize::MAX });
                typed.push(backend::TypedMutation::SetLanes { table: t, lanes: frozen.max_lanes_per_table + 1 });
                typed.push(backend::TypedMutation::SetLanes { table: t, lanes: usize::MAX });
                // shape-valid content corruption: the surfaced public values (pass EVERY
                // pre-crypto gate — pvs are not in the vk context — and hit the crypto).
                for k in 0..n_pv.min(4) {
                    typed.push(backend::TypedMutation::BumpPublicValue { table: t, idx: k });
                }
                typed.push(backend::TypedMutation::ExtendPublicValues { table: t, extra: 1 });
                typed.push(backend::TypedMutation::ExtendPublicValues {
                    table: t,
                    extra: frozen.max_public_values_per_table.saturating_sub(n_pv),
                });
                typed.push(backend::TypedMutation::ExtendPublicValues {
                    table: t,
                    extra: frozen.max_public_values_per_table.saturating_sub(n_pv) + 1,
                });
            }
            if !shapes.is_empty() {
                // duplicate the table list past the max_tables cap.
                let times = frozen.max_tables / shapes.len() + 1;
                typed.push(backend::TypedMutation::DuplicateTables { times });
                typed.push(backend::TypedMutation::DuplicateTables { times: 1 });
            } else {
                eprintln!("seed has no non-primitive tables — typed table corpus skipped (hermetic easy circuit)");
            }
            for m in typed {
                let Some(bytes) = backend::mutate_typed(&proof, m) else { continue };
                let r = backend::verify_outer_proof(&frozen, &vk, CIRCUIT_SPEND, &bytes);
                match m {
                    // magnitude bounds past the manifest cap ⇒ the typed M-05R reject,
                    // BEFORE any trace reconstruction.
                    backend::TypedMutation::SetRows { rows, .. } if rows > frozen.max_rows_per_table => {
                        assert!(matches!(r, Err(StarkVerifyError::MalformedStatement(_))), "{m:?} must hit the M-05R cap, got {r:?}")
                    }
                    backend::TypedMutation::SetLanes { lanes, .. } if lanes > frozen.max_lanes_per_table => {
                        assert!(matches!(r, Err(StarkVerifyError::MalformedStatement(_))), "{m:?} must hit the M-05R cap, got {r:?}")
                    }
                    backend::TypedMutation::ExtendPublicValues { .. }
                        if backend::table_shapes(&bytes)
                            .is_some_and(|s| s.iter().any(|&(_, _, n)| n > frozen.max_public_values_per_table)) =>
                    {
                        assert!(matches!(r, Err(StarkVerifyError::MalformedStatement(_))), "{m:?} must hit the M-05R cap, got {r:?}")
                    }
                    backend::TypedMutation::DuplicateTables { .. }
                        if backend::table_shapes(&bytes).unwrap().len() > frozen.max_tables =>
                    {
                        assert!(matches!(r, Err(StarkVerifyError::MalformedStatement(_))), "{m:?} must hit the M-05R cap, got {r:?}")
                    }
                    // within-cap wrong shape ⇒ the vk_hash fold-in (or the raw preprocessed
                    // anchor / crypto) — some pre-crypto or crypto gate MUST reject it.
                    backend::TypedMutation::SetRows { .. }
                    | backend::TypedMutation::SetLanes { .. }
                    | backend::TypedMutation::DuplicateTables { .. } => {
                        assert!(r.is_err(), "{m:?} (wrong shape, within caps) must be rejected, got Ok")
                    }
                    // content corruption of a surfaced public value: the pv vector is the
                    // A2 statement-binding surface — the crypto verify must reject it.
                    backend::TypedMutation::BumpPublicValue { .. } => {
                        assert!(r.is_err(), "{m:?} (corrupted surfaced public value) must be rejected, got Ok")
                    }
                    // pv EXTENSION within the cap: semantics belong to the table's AIR; the
                    // no-unwind bar plus the fail-closed FULL path are what M-05 requires.
                    backend::TypedMutation::ExtendPublicValues { .. } => {}
                }
                // the FULL node path must stay fail-closed (none of these mutants surfaces
                // the true statement) and, above all, must return — never unwind.
                assert!(
                    verify_stark_with_manifest(&frozen, CIRCUIT_SPEND, &vk, &stmt404, &bytes).is_err(),
                    "{m:?} must stay fail-closed through the full verify path"
                );
            }
        }
    }

    /// (K-01 acceptance — alternate-AIR reject, HERMETIC: prove in-test, no artifact) Two
    /// genuine proofs of two DIFFERENT easy circuits under the exact pinned config:
    /// each crypto-verifies under its own self-derived key (this is precisely the circular
    /// anchor the re-audit prohibits — a valid proof can always vouch for itself), and the
    /// release-pinned manifest is what rejects the substitution in every direction.
    #[cfg(feature = "stark-backend")]
    #[test]
    fn alternate_air_proof_cannot_impersonate_a_pinned_circuit() {
        let base = &manifest::SPEND_V1_MANIFEST;
        // 64 vs 16384 adds: with 4 ALU lanes and the FRI minimum height (2^10) the two
        // programs land on DIFFERENT padded trace heights (2^10 vs 2^12), so their shapes
        // differ no matter whether `rows` records natural or padded counts.
        let alt_a = backend::prove_easy_alternate_circuit(base, 64);
        let alt_b = backend::prove_easy_alternate_circuit(base, 16384);

        // (a) both are GENUINE proofs: each crypto-verifies under its own derived key.
        let vk_a = backend::ceremony_vk_hash(base, CIRCUIT_SPEND, &alt_a).unwrap();
        let vk_b = backend::ceremony_vk_hash(base, CIRCUIT_SPEND, &alt_b).unwrap();
        assert!(backend::verify_outer_proof(base, &vk_a, CIRCUIT_SPEND, &alt_a).is_ok(), "alt circuit A proof is genuinely valid");
        assert!(backend::verify_outer_proof(base, &vk_b, CIRCUIT_SPEND, &alt_b).is_ok(), "alt circuit B proof is genuinely valid");
        // (b) different programs ⇒ different vk (the shape binding separates them).
        assert_ne!(vk_a, vk_b, "distinct circuits must derive distinct vk hashes");

        // (c) pin circuit B as "the" spend circuit (a stand-in ceremony). A valid
        // alternate-AIR proof (A) is rejected in BOTH substitution directions:
        let (frozen_b, _) = ceremony_freeze(base, CIRCUIT_SPEND, &alt_b);
        //   – attacker presents the PINNED key with their alternate proof ⇒ rejected before
        //     any crypto: by the raw preprocessed anchor when the programs' preprocessed
        //     commitments differ, else by the recomputed shape hash (VkHashMismatch);
        let r = backend::verify_outer_proof(&frozen_b, &vk_b, CIRCUIT_SPEND, &alt_a);
        assert!(
            matches!(r, Err(StarkVerifyError::PreprocessedCommitmentMismatch) | Err(StarkVerifyError::VkHashMismatch)),
            "alternate-AIR proof under the pinned key must be rejected pre-crypto, got {r:?}"
        );
        //   – attacker presents their SELF-DERIVED key (the circular anchor) ⇒ the manifest
        //     precheck rejects it against the frozen pin before anything else runs.
        let stmt404 = borsh::to_vec(&spend_stmt()).unwrap();
        assert_eq!(
            verify_stark_with_manifest(&frozen_b, CIRCUIT_SPEND, &vk_a, &stmt404, &alt_a),
            Err(StarkVerifyError::VkHashMismatch),
            "a self-derived expected key is rejected by the manifest trust anchor"
        );
        // (d) and under the PRODUCTION (unfrozen) manifest the self-consistent pair fails
        // closed outright — there is no key an attacker can present for an unfrozen circuit.
        assert_eq!(
            verify_stark(CIRCUIT_SPEND, &vk_a, &stmt404, &alt_a),
            Err(StarkVerifyError::CircuitVkNotFrozen(CIRCUIT_SPEND)),
            "unfrozen production circuit rejects every (key, proof) pair"
        );
        // (e) cross-circuit re-badging of a genuine proof also fails (context binds the
        // circuit_version).
        assert_eq!(
            backend::verify_outer_proof(base, &vk_a, CIRCUIT_PROVIDER_CLAIM, &alt_a),
            Err(StarkVerifyError::VkHashMismatch),
            "circuit_version is bound into the recomputed context"
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

    /// (audit m2) UNIQUE-surface binding: the statement must be surfaced by EXACTLY ONE
    /// table. Zero tables (unbound/replayable) AND more-than-one table carrying the statement
    /// (ambiguous/duplicate surfacing) both fail closed — the tightening over the old
    /// `contains` (accept-on-any) scan.
    #[test]
    fn statement_binding_requires_exactly_one_surface_table() {
        let stmt = borsh::to_vec(&spend_stmt()).unwrap();
        let good = statement_to_pvs(&stmt);
        // exactly one surfacing table (amidst decoys) ⇒ bound.
        assert!(statement_is_bound(&[vec![], good.clone(), vec![1, 2, 3]], &stmt), "exactly one ⇒ bound");
        // TWO tables carrying the statement ⇒ rejected (ambiguous/duplicate surfacing).
        assert!(
            !statement_is_bound(&[good.clone(), vec![9], good.clone()], &stmt),
            "duplicate surfacing ⇒ fail-closed (m2 unique-surface)"
        );
        // zero surfacing tables ⇒ rejected (the replay-defense critical case).
        assert!(!statement_is_bound(&[vec![7], vec![1, 2, 3]], &stmt), "no surfacing table ⇒ fail-closed");
    }

    /// (audit M-02) the empty-statement fail-closed guard: a null `public_inputs` must NOT bind,
    /// even against a lone empty surfaced table (which would otherwise satisfy `count() == 1`).
    /// A bound proof must surface a NON-empty statement; binding to nothing is rejected.
    #[test]
    fn statement_binding_rejects_empty_statement() {
        // a lone empty surfaced table would content-match an empty `expected` (count == 1) —
        // the guard rejects it so a proof can never "bind" the null statement.
        assert!(!statement_is_bound(&[vec![]], &[]), "empty statement ⇒ fail-closed (M-02)");
        assert!(!statement_is_bound(&[vec![], vec![]], &[]), "empty statement, multiple empty tables ⇒ fail-closed");
        assert!(!statement_is_bound(&[], &[]), "empty statement, no tables ⇒ fail-closed");
        // and a non-empty surface never binds an empty statement either.
        assert!(!statement_is_bound(&[vec![1, 2, 3]], &[]), "empty statement never binds a populated table");
    }

    #[test]
    fn bind_artifact_ties_proof_to_statement() {
        let vk = compute_vk_hash(&ctx()).unwrap();
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
        assert_ne!(base, compute_vk_hash(&ctx()).unwrap());
    }
}
