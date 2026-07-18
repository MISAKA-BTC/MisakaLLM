//! MIL domain-separation constants (design §3.2).
//!
//! Naming follows the repo-wide convention (see `consensus/core/src/dns_finality.rs`):
//! `*_DOMAIN` constants are **keyed-BLAKE2b `Params::key` values** (≤ 64 bytes),
//! `*_CONTEXT` constants ending in `/mldsa87` are **ML-DSA-87 `ctx` parameters**
//! (≤ 255 bytes), and [`MIL_KDF_INFO`] is an **HKDF `info` prefix**. The three
//! kinds live in disjoint mechanisms, so no value can be replayed across them.

/// MIL wire/protocol version carried in every versioned struct.
pub const MIL_PROTOCOL_VERSION: u16 = 1;

// --- keyed BLAKE2b-512 domains (Hash64_k keys) --------------------------------------

/// Enclave key binding: `report_data = Hash64_k(bind, pk_kem ‖ pk_receipt)` (§3.2).
pub const MIL_BIND_DOMAIN: &[u8] = b"misaka-mil-v1/bind";
/// Session id: `Hash64_k(session, quote_hash ‖ kem_ct ‖ nonce_req)` (§3.2).
pub const MIL_SESSION_DOMAIN: &[u8] = b"misaka-mil-v1/session";
/// ANONYMOUS-path session id: `Hash64_k(session-anon, kem_ct ‖ nonce_req)`
/// (ADR-0037 §3 #2 blind handshake). Unlike [`MIL_SESSION_DOMAIN`] it binds NO
/// `quote_hash`, so the session id carries no provider-identifying attestation
/// epoch — a requester/relay cannot use it to link the session to a named
/// provider. Disjoint domain so an anon session id can never equal a named one.
pub const MIL_SESSION_ANON_DOMAIN: &[u8] = b"misaka-mil-v1/session-anon";
/// Seed-compression domain for the anonymous per-session receipt signer
/// (ADR-0037 §3 #3): `seed32 = Hash64_k(session-rk-seed, session_rk)[..32]` — the
/// 64-byte `session_receipt_key(claim_secret, session_cm)` compressed to the
/// 32-byte ML-DSA-87 keygen seed used by [`crate::receipt::ReceiptSigner::from_session_key`].
/// Disjoint from every other domain so the seed is not derivable from, nor
/// re-usable as, any other keyed value.
pub const MIL_SESSION_RK_SEED_DOMAIN: &[u8] = b"misaka-mil-v1/session-rk-seed";
/// Request commitment: `cm_req = Hash64_k(commit, salt ‖ H(prompt_ct))` (§3.3).
pub const MIL_COMMIT_DOMAIN: &[u8] = b"misaka-mil-v1/commit";
/// Inner prompt-ciphertext hash `H(prompt_ct)` feeding [`MIL_COMMIT_DOMAIN`].
/// A distinct key so the fixed-width outer preimage (32-byte salt ‖ 64-byte
/// hash) can never collide with a 96-byte ciphertext.
pub const MIL_PROMPT_CT_DOMAIN: &[u8] = b"misaka-mil-v1/commit/prompt-ct";
/// Running response-transcript hash `cm_resp_k` signed by every receipt (§3.3/§4.1).
pub const MIL_TRANSCRIPT_DOMAIN: &[u8] = b"misaka-mil-v1/transcript";
/// Model identity: `model_id = Hash64_k(model, weights_manifest)` (§7.1).
pub const MIL_MODEL_DOMAIN: &[u8] = b"misaka-mil-v1/model";
/// Agent-profile identity (§18.2), over length-prefixed
/// `system_prompt / tool_schema / rag_index_manifest`.
pub const MIL_PROFILE_DOMAIN: &[u8] = b"misaka-mil-v1/profile";
/// Attestation quote hash pinned on-chain at registration (§3.6a).
pub const MIL_QUOTE_DOMAIN: &[u8] = b"misaka-mil-v1/quote";
/// Provider overlay identity: `Hash64_k(provider-id, pk_receipt)`.
pub const MIL_PROVIDER_ID_DOMAIN: &[u8] = b"misaka-mil-v1/provider-id";
/// Hash of a full borsh-encoded [`crate::receipt::SignedReceipt`], anchored
/// on-chain in place of the 7 KiB signature blob (v0, §8.1).
pub const MIL_RECEIPT_HASH_DOMAIN: &[u8] = b"misaka-mil-v1/receipt-hash";
/// G1 reproducible-bench VRF-seeded question-subset selection (§19.3-G1).
pub const MIL_BENCH_SELECT_DOMAIN: &[u8] = b"misaka-mil-v1/bench/select";
/// G1 per-question result hash over the output token-id sequence (§19.3-G1).
pub const MIL_BENCH_RESULT_DOMAIN: &[u8] = b"misaka-mil-v1/bench/result";
/// G1 whole-run commitment anchored on-chain by `MilGovernance.recordGate` (§19.3-G1).
pub const MIL_BENCH_RUN_DOMAIN: &[u8] = b"misaka-mil-v1/bench/run";
/// Canary job selection: which provider gets probed this epoch (§4.3).
pub const MIL_CANARY_SELECT_DOMAIN: &[u8] = b"misaka-mil-v1/canary/select";
/// Canary prompt generation from the epoch VRF seed (§4.3).
pub const MIL_CANARY_PROMPT_DOMAIN: &[u8] = b"misaka-mil-v1/canary/prompt";
/// Compute-attestor overlay identity: `Hash64_k(compute-attest, pubkey)` (ADR-0024 §20.2).
pub const MIL_COMPUTE_ATTEST_DOMAIN: &[u8] = b"misaka-mil-v1/compute-attest";

// --- ADR-0039 PALW two-tier deterministic runtime identity (design §6, §7) ----------
// These key the PROVIDER-side exact-match fields. Disjoint `misaka-palw-v1/*` prefixes so a PALW
// runtime/commitment hash can never be replayed as a MIL receipt/session/model hash and vice versa.

/// Per-tier model identity from the fixed project fork name: `Hash64_k(tier-model, project_name)`
/// (e.g. `MISAKA-QW4-PALW-v1` / `MISAKA-QW35A-PALW-v1`). Consensus pins the manifest hash, never the
/// human name — this domain turns the pinned name into a stable id.
pub const MIL_PALW_TIER_MODEL_DOMAIN: &[u8] = b"misaka-palw-v1/tier-model";
/// `model_profile_id = Hash64_k(model-profile, model_id ‖ tokenizer ‖ quant ‖ shape_table)` (§6/§21.1).
pub const MIL_PALW_PROFILE_DOMAIN: &[u8] = b"misaka-palw-v1/model-profile";
/// `runtime_class_id = Hash64_k(runtime-class, profile ‖ runtime_image ‖ kernel_graph ‖ op_table ‖
/// arch ‖ topology ‖ determinism-flags)` — exact-match is only granted within one class (I-9, §6.2).
pub const MIL_PALW_RUNTIME_CLASS_DOMAIN: &[u8] = b"misaka-palw-v1/runtime-class";
/// `shape_id` binding of the fixed tensor shape (§6.3).
pub const MIL_PALW_SHAPE_DOMAIN: &[u8] = b"misaka-palw-v1/shape";
/// `job_set_commitment` over the packed micro-batch (§8/§21.4).
pub const MIL_PALW_JOBSET_DOMAIN: &[u8] = b"misaka-palw-v1/job-set";
/// `output_commitment = Hash64_k(output, salt ‖ output_token_ids)` — salted so a known-question
/// dictionary cannot be brute-forced (§7.4/§19.3).
pub const MIL_PALW_OUTPUT_DOMAIN: &[u8] = b"misaka-palw-v1/output";
/// `canonical_gemm_trace_root` — commitment over the primary GPU GEMM trace (§7.2/§7.3).
pub const MIL_PALW_GEMM_TRACE_DOMAIN: &[u8] = b"misaka-palw-v1/gemm-trace";
/// `operation_schedule_commitment` over the deterministic operation schedule (§7.2).
pub const MIL_PALW_OP_SCHEDULE_DOMAIN: &[u8] = b"misaka-palw-v1/op-schedule";
/// `PalwExecutionChallengeV1` derivation from the prior DNS beacon + job capability + profile (§7.3).
pub const MIL_PALW_EXEC_CHALLENGE_DOMAIN: &[u8] = b"misaka-palw-v1/exec-challenge";
/// The GEMM trace-chain step hash `t_(i+1) = H(domain ‖ t_i ‖ op_id ‖ …)` (§7.3).
pub const MIL_PALW_TRACE_STEP_DOMAIN: &[u8] = b"misaka-palw-v1/trace-step";
/// The canonical `PalwOperationIdV1` serialization hash (§7.2).
pub const MIL_PALW_OP_ID_DOMAIN: &[u8] = b"misaka-palw-v1/op-id";
/// The blinded job-capability commitment handed to providers (§8.3), unlinkable to the requester.
pub const MIL_PALW_JOB_CAPABILITY_DOMAIN: &[u8] = b"misaka-palw-v1/job-capability";

// --- HKDF ---------------------------------------------------------------------------

/// HKDF-SHA3-512 `info` prefix: `info = MIL_KDF_INFO ‖ session_id` (§3.2).
pub const MIL_KDF_INFO: &[u8] = b"misaka-mil-v1/kdf";

// --- ML-DSA-87 signing contexts -------------------------------------------------------

/// ML-DSA-87 `ctx` for inference receipts (§4.1). Disjoint from every
/// `kaspa-pq-*` signing context, so a receipt signature can never be replayed
/// as a tx-input / attestation / unbond signature and vice versa.
pub const MIL_RECEIPT_MLDSA87_CONTEXT: &[u8] = b"misaka-mil-v1/receipt/mldsa87";

/// ML-DSA-87 `ctx` for compute-attestor epoch attestations (ADR-0024 §20.2).
/// Disjoint from the DNS validator's `kaspa-pq-v1/att/mldsa87` and every other
/// context, so a compute attestation can never be replayed as a stake
/// attestation, tx-input, or receipt signature and vice versa.
pub const MIL_COMPUTE_ATTEST_MLDSA87_CONTEXT: &[u8] = b"misaka-mil-v1/compute-attest/mldsa87";

#[cfg(test)]
mod tests {
    use super::*;

    /// Domain strings are consensus-grade constants for the overlay: pin them
    /// byte-for-byte so an accidental edit is caught (same pattern as the
    /// `dns_finality.rs` domain pin test).
    #[test]
    fn mil_domain_strings_are_pinned() {
        assert_eq!(MIL_BIND_DOMAIN, b"misaka-mil-v1/bind");
        assert_eq!(MIL_SESSION_DOMAIN, b"misaka-mil-v1/session");
        assert_eq!(MIL_SESSION_ANON_DOMAIN, b"misaka-mil-v1/session-anon");
        assert_eq!(MIL_SESSION_RK_SEED_DOMAIN, b"misaka-mil-v1/session-rk-seed");
        // the anon session domain is disjoint from the named one (no cross-linkage).
        assert_ne!(MIL_SESSION_ANON_DOMAIN, MIL_SESSION_DOMAIN);
        assert_eq!(MIL_COMMIT_DOMAIN, b"misaka-mil-v1/commit");
        assert_eq!(MIL_PROMPT_CT_DOMAIN, b"misaka-mil-v1/commit/prompt-ct");
        assert_eq!(MIL_TRANSCRIPT_DOMAIN, b"misaka-mil-v1/transcript");
        assert_eq!(MIL_MODEL_DOMAIN, b"misaka-mil-v1/model");
        assert_eq!(MIL_PROFILE_DOMAIN, b"misaka-mil-v1/profile");
        assert_eq!(MIL_QUOTE_DOMAIN, b"misaka-mil-v1/quote");
        assert_eq!(MIL_PROVIDER_ID_DOMAIN, b"misaka-mil-v1/provider-id");
        assert_eq!(MIL_RECEIPT_HASH_DOMAIN, b"misaka-mil-v1/receipt-hash");
        assert_eq!(MIL_KDF_INFO, b"misaka-mil-v1/kdf");
        assert_eq!(MIL_RECEIPT_MLDSA87_CONTEXT, b"misaka-mil-v1/receipt/mldsa87");
        assert_eq!(MIL_COMPUTE_ATTEST_DOMAIN, b"misaka-mil-v1/compute-attest");
        assert_eq!(MIL_COMPUTE_ATTEST_MLDSA87_CONTEXT, b"misaka-mil-v1/compute-attest/mldsa87");
        // the compute-attest ML-DSA context is disjoint from the DNS validator's
        assert_ne!(MIL_COMPUTE_ATTEST_MLDSA87_CONTEXT, &b"kaspa-pq-v1/att/mldsa87"[..]);
        assert_ne!(MIL_COMPUTE_ATTEST_MLDSA87_CONTEXT, MIL_RECEIPT_MLDSA87_CONTEXT);
    }

    /// Every keyed-BLAKE2b domain must fit the BLAKE2b key limit (64 bytes)
    /// and the ML-DSA context must fit its 255-byte limit.
    #[test]
    fn mil_domain_strings_fit_limits() {
        for d in [
            MIL_BIND_DOMAIN,
            MIL_SESSION_DOMAIN,
            MIL_SESSION_ANON_DOMAIN,
            MIL_SESSION_RK_SEED_DOMAIN,
            MIL_COMMIT_DOMAIN,
            MIL_PROMPT_CT_DOMAIN,
            MIL_TRANSCRIPT_DOMAIN,
            MIL_MODEL_DOMAIN,
            MIL_PROFILE_DOMAIN,
            MIL_QUOTE_DOMAIN,
            MIL_PROVIDER_ID_DOMAIN,
            MIL_RECEIPT_HASH_DOMAIN,
            // ADR-0039 PALW runtime-identity domains.
            MIL_PALW_TIER_MODEL_DOMAIN,
            MIL_PALW_PROFILE_DOMAIN,
            MIL_PALW_RUNTIME_CLASS_DOMAIN,
            MIL_PALW_SHAPE_DOMAIN,
            MIL_PALW_JOBSET_DOMAIN,
            MIL_PALW_OUTPUT_DOMAIN,
            MIL_PALW_GEMM_TRACE_DOMAIN,
            MIL_PALW_OP_SCHEDULE_DOMAIN,
        ] {
            assert!(d.len() <= 64, "BLAKE2b key {:?} exceeds 64 bytes", core::str::from_utf8(d));
        }
        // the PALW domains are pinned and mutually distinct.
        assert_eq!(MIL_PALW_PROFILE_DOMAIN, b"misaka-palw-v1/model-profile");
        assert_eq!(MIL_PALW_RUNTIME_CLASS_DOMAIN, b"misaka-palw-v1/runtime-class");
        assert_ne!(MIL_PALW_PROFILE_DOMAIN, MIL_PALW_RUNTIME_CLASS_DOMAIN);
        assert!(MIL_RECEIPT_MLDSA87_CONTEXT.len() <= 255);
    }
}
