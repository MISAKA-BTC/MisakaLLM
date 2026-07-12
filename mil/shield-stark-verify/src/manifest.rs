//! (audit 2026-07-11 K-01) THE pinned per-circuit VERIFIER RELEASE MANIFEST.
//!
//! The re-audit's K-01 core requirement: *"actual commitment と全 verifier
//! parameter を署名済み release manifest に固定し、proof 由来値を trust anchor
//! にしない"* — the expected verifier key and every parameter that decides
//! accept/reject must come from an INDEPENDENT, release-pinned enumeration, never
//! from the proof under verification and never from attacker-controllable
//! statement bytes.
//!
//! This module is that enumeration: one `const` [`CircuitManifest`] per
//! `circuit_version`, compiled into the node binary (the release-signing of the
//! binary is what signs the manifest — the values below are source, reviewed and
//! hash-pinned by the release process, not runtime inputs). The verify path
//! ([`crate::verify_stark`]) consults **only** this table for the expected
//! `vk_hash`, the statement schema, the FRI/PCS parameters, the transcript pin,
//! and the metadata bounds — checking the FULL manifest, not a subset:
//!
//! - **Trust anchor** — [`CircuitManifest::vk_hash`] is the ONLY source of the
//!   expected verifier key. The caller/contract-supplied 64-byte key must EQUAL
//!   it; the proof's self-declared key was already only ever compared, never
//!   trusted. While a circuit's key is unfrozen (`None`) every STARK proof for
//!   it is rejected fail-closed ([`crate::StarkVerifyError::CircuitVkNotFrozen`]).
//! - **Statement schema** — `statement_schema_id`/`statement_len` cross-lock this
//!   manifest to the C-01 statement-schema manifest
//!   (`misaka_mil_shield::statement_schema`), so the public-input layout the
//!   verifier binds is version-pinned in BOTH manifests.
//! - **PCS/FRI parameters** — the single source for the pinned verifier config;
//!   `backend::config_from_manifest` and `backend::context_from_proof` both read
//!   THESE fields (the previous hand-written duplication between `pinned_config()`
//!   and the context builder — an audit-noted drift risk — is gone).
//! - **Transcript pin** — `transcript_kat` freezes the Fiat-Shamir challenger
//!   known-answer (A3 freeze, commit 4cc7d63); the backend recomputes it live and
//!   fails closed on drift before any crypto.
//! - **Preprocessed commitment** — once a circuit is frozen,
//!   `preprocessed_commitment` carries the raw expected bytes of the proof's
//!   preprocessed PCS commitment (cap + instance metas + matrix→instance map), so
//!   an auditor can check the actual commitment against the release WITHOUT
//!   recomputing `vk_hash` from a proof (the audit's independence requirement),
//!   and the node compares it directly in addition to the `vk_hash` fold-in.
//!
//! ## Freeze / placeholder policy (K-01)
//!
//! The production spend/claim circuits are NOT frozen yet (the C-P6 full-receipt
//! build is pending), so `vk_hash`/`preprocessed_commitment` are `None` for every
//! circuit below and the STARK arm is fail-closed end to end — the MECHANISM is
//! live now, the VALUES land at the vk-pinning ceremony. Freezing a circuit is a
//! deliberate governance action: run the ceremony against the audited artifact
//! (`backend::ceremony_vk_hash` / `backend::ceremony_preprocessed_commitment`),
//! transcribe the outputs into the `const` below, flip the
//! `production_circuits_fail_closed_until_vk_freeze` test, and cut a release
//! whose diff is exactly that transcription. Changing ANY other field of a frozen manifest
//! (params, schema, transcript) REQUIRES a new `circuit_version` — never an
//! in-place edit.

use kaspa_hashes::Hash64;
use misaka_mil_shield::proof::{CIRCUIT_PROVIDER_CLAIM, CIRCUIT_PROVIDER_CLAIM_V2, CIRCUIT_PROVIDER_CLAIM_V3, CIRCUIT_SPEND};

/// The pinned Plonky3-recursion source revision the verifier back-half is built
/// from (the workspace `[workspace.dependencies]` git rev — cross-asserted against
/// the root `Cargo.toml` in tests so the two pins cannot drift).
pub const PINNED_RECURSION_REV: &str = "b36339709a7a67ee9760fb578b3d4339fd983709";

/// (audit m3 — A2 patch-hash pin) The SHA-256 of the audit-gated A2 statement-surfacing
/// patch (`docs/bench/plonky3-recursion-a2-surfacing.diff`) EXACTLY as it sits in this
/// tree. This is the value the vk-pinning ceremony transcribes into a frozen circuit's
/// [`CircuitManifest::a2_patch_sha256`] once it proves that circuit on the PATCHED tree.
/// Pinning it here — and cross-checking the on-disk diff against it in a test
/// (`a2_patch_diff_hash_matches_the_pinned_manifest_value`) — means the patch file and the
/// manifest cannot silently drift: a change to the diff without re-pinning fails the test,
/// and any per-circuit `a2_patch_sha256` that is ever frozen must equal this on-disk pin.
/// The ceremony that fills a per-circuit `a2_patch_sha256` with the AUDITED tree's value
/// (and freezes the corresponding `vk_hash`) stays EXTERNAL to this source.
pub const A2_PATCH_SHA256_ONDISK: &str = "28e6d560bb1e56ec64c9598d49f921ece6f82e54a3d32746d9bb3da04a3d53d6";

/// (A3 transcript freeze, commit 4cc7d63) The frozen Fiat-Shamir challenger
/// known-answer: the outputs of `backend::fiat_shamir_kat()` over the pinned
/// Poseidon2-BabyBear-D4-W16 `DuplexChallenger` (WIDTH=16/RATE=8). Any change to
/// the permutation constants, width/rate, duplex sampling, or field changes these
/// values; the backend recomputes them live per verify and fails closed on drift.
/// Re-capture ONLY with a deliberate transcript change (⇒ new ceremony + version).
pub const FIAT_SHAMIR_KAT_FROZEN: [u64; 3] = [129923706, 957612192, 690001879];

/// One circuit's complete, release-pinned verifier manifest. Every field either
/// decides accept/reject directly or pins provenance; the verify path checks all
/// of the decision-bearing fields (see the module docs for the map).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitManifest {
    /// The `ShieldProof.circuit_version` this manifest freezes.
    pub circuit_version: u16,
    /// Cross-lock into the C-01 statement-schema manifest: must equal
    /// `statement_schema::schema_for_circuit(circuit_version).name`…
    pub statement_schema_id: &'static str,
    /// …and `.size` (the exact borsh length of a valid statement).
    pub statement_len: usize,
    /// Field tag (0 = BabyBear). TYPE-LEVEL in the backend — a manifest naming a
    /// different field cannot be honoured and fails closed.
    pub field_tag: u8,
    /// Extension degree D (4). Type-level in the backend, same rule.
    pub ext_degree: u8,
    /// Poseidon2 constants id (0x0416 = BABY_BEAR_D4_W16). Type-level, same rule.
    pub poseidon2_id: u16,
    /// The frozen Fiat-Shamir challenger known-answer (== [`FIAT_SHAMIR_KAT_FROZEN`]).
    pub transcript_kat: [u64; 3],
    // --- the pinned FRI/PCS parameters (they live in the verifier config, not the
    // --- proof; matched to the measured ~100-bit run: `--security-level 100
    // --- --query-pow-bits 28 --final-log-blowup 4 --log-final-poly-len 5`,
    // --- num_queries = (100-28)/4 = 18). PROVISIONAL until the ceremony.
    pub log_blowup: u8,
    pub num_queries: u16,
    pub commit_pow_bits: u8,
    pub query_pow_bits: u8,
    pub max_log_arity: u8,
    pub log_final_poly_len: u8,
    pub cap_height: u8,
    /// Conjectured security level (bits) the params target.
    pub security_level: u16,
    // --- (audit M-05R) DoS bounds on attacker-controlled proof metadata, enforced
    // --- BEFORE the vendored verifier reconstructs any trace. Generous relative to
    // --- the frozen circuit; tightened to the exact measured shape at the ceremony.
    pub max_tables: usize,
    pub max_rows_per_table: usize,
    pub max_lanes_per_table: usize,
    pub max_public_values_per_table: usize,
    /// (K-01 trust anchor) The ceremony-frozen expected `vk_hash` — the keyed-BLAKE2b
    /// digest of the full canonical [`crate::VerifierContext`] of the ONE genuine
    /// circuit. `None` until the vk-pinning ceremony ⇒ the STARK arm fails closed.
    pub vk_hash: Option<Hash64>,
    /// (K-01 independence) The ceremony-frozen RAW expected preprocessed-commitment
    /// bytes (postcard of PCS cap + instance metas + matrix→instance map — the exact
    /// encoding `backend::ceremony_preprocessed_commitment` emits). Compared directly
    /// against the proof's actual commitment, in addition to the `vk_hash` fold-in,
    /// so the pinned program is auditable without recomputing any hash from a proof.
    /// `None` until the ceremony.
    pub preprocessed_commitment: Option<&'static [u8]>,
    /// Provenance: the pinned Plonky3-recursion rev this verifier is built from.
    pub recursion_rev: &'static str,
    /// Provenance: the SHA-256 of the audit-gated A2 statement-surfacing patch when
    /// the frozen circuit was proved on the patched tree
    /// (`docs/bench/plonky3-recursion-a2-surfacing.diff`), `None` until the freeze
    /// pins a patched-tree artifact.
    pub a2_patch_sha256: Option<&'static str>,
}

/// The shared unfrozen parameter block (every current circuit verifies under the
/// same pinned ~100-bit recursion-outer config; per-circuit divergence would be a
/// per-circuit ceremony choice).
macro_rules! pinned_manifest {
    ($cv:expr, $schema:expr, $len:expr) => {
        CircuitManifest {
            circuit_version: $cv,
            statement_schema_id: $schema,
            statement_len: $len,
            field_tag: 0,         // BabyBear
            ext_degree: 4,        // D = 4
            poseidon2_id: 0x0416, // BABY_BEAR_D4_W16
            transcript_kat: FIAT_SHAMIR_KAT_FROZEN,
            log_blowup: 4,
            num_queries: 18,
            commit_pow_bits: 0,
            query_pow_bits: 28,
            max_log_arity: 2,
            log_final_poly_len: 5,
            cap_height: 0,
            security_level: 100,
            max_tables: 64,
            max_rows_per_table: 1 << 24,
            max_lanes_per_table: 1 << 12,
            max_public_values_per_table: 1 << 16,
            vk_hash: None,                 // UNFROZEN — fail-closed (K-01 placeholder policy)
            preprocessed_commitment: None, // UNFROZEN — pinned at the same ceremony
            recursion_rev: PINNED_RECURSION_REV,
            a2_patch_sha256: None,
        }
    };
}

/// Circuit 1 — the shielded-pool spend (JoinSplit).
pub const SPEND_V1_MANIFEST: CircuitManifest = pinned_manifest!(CIRCUIT_SPEND, "SpendStatement", 404);
/// Circuit 2 — the anonymous provider claim (public amount).
pub const PROVIDER_CLAIM_V1_MANIFEST: CircuitManifest = pinned_manifest!(CIRCUIT_PROVIDER_CLAIM, "ProviderClaimStatement", 328);
/// Circuit 4 — the hidden-amount provider claim (ADR-0037 §2.2 / C-06.2 payout binding).
pub const PROVIDER_CLAIM_V2_MANIFEST: CircuitManifest = pinned_manifest!(CIRCUIT_PROVIDER_CLAIM_V2, "ProviderClaimStatementV2", 392);
/// Circuit 3 — the RECEIPT-AUTHORIZED provider claim (C-P6 / ADR-0037 §2.4). The inert
/// production surface: the statement layout (456 B) is frozen and cross-locked to the C-01
/// schema manifest, the FRI/PCS/transcript params are pinned, but `vk_hash` is `None` — so a
/// STARK proof for circuit 3 is rejected fail-closed ([`crate::StarkVerifyError::CircuitVkNotFrozen`])
/// until the C-P6 vk-pinning ceremony (which is gated on the external multi-week ML-DSA-verify
/// prover). Present here — not absent like before — so `verify_stark` RESOLVES circuit 3 and
/// fails closed on the vk anchor, mirroring how circuit 4 was wired; the F006 fence stays
/// `u64::MAX` regardless.
pub const PROVIDER_CLAIM_V3_MANIFEST: CircuitManifest = pinned_manifest!(CIRCUIT_PROVIDER_CLAIM_V3, "ProviderClaimStatementV3", 456);

/// Every release-pinned circuit manifest. Circuit 3 (the C-P6 receipt-authorized claim) is now
/// PRESENT as an inert surface (`vk_hash: None` ⇒ fail-closed), so the verifier resolves it and
/// rejects at the K-01 trust anchor rather than as an unknown circuit — the freeze is the only
/// remaining step. All manifests carry `vk_hash: None` until their vk-pinning ceremony.
pub const PINNED_CIRCUIT_MANIFESTS: &[&CircuitManifest] =
    &[&SPEND_V1_MANIFEST, &PROVIDER_CLAIM_V1_MANIFEST, &PROVIDER_CLAIM_V3_MANIFEST, &PROVIDER_CLAIM_V2_MANIFEST];

/// The pinned manifest for `circuit_version`, or `None` (⇒ the verifier rejects
/// the circuit outright).
pub fn manifest_for_circuit(circuit_version: u16) -> Option<&'static CircuitManifest> {
    PINNED_CIRCUIT_MANIFESTS.iter().copied().find(|m| m.circuit_version == circuit_version)
}
