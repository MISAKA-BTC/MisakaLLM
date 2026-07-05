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
            MIL_COMMIT_DOMAIN,
            MIL_PROMPT_CT_DOMAIN,
            MIL_TRANSCRIPT_DOMAIN,
            MIL_MODEL_DOMAIN,
            MIL_PROFILE_DOMAIN,
            MIL_QUOTE_DOMAIN,
            MIL_PROVIDER_ID_DOMAIN,
            MIL_RECEIPT_HASH_DOMAIN,
        ] {
            assert!(d.len() <= 64, "BLAKE2b key {:?} exceeds 64 bytes", core::str::from_utf8(d));
        }
        assert!(MIL_RECEIPT_MLDSA87_CONTEXT.len() <= 255);
    }
}
