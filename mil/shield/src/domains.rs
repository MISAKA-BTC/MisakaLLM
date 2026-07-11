//! Keyed-BLAKE2b domain separators (the hash *key*), frozen at F006 activation.
//! Every hash in this crate is `blake2b_512_keyed(DOMAIN, data)`; distinct
//! domains make the commitment, nullifier, Merkle-node and context hashes
//! non-interchangeable.

/// Note commitment `cm`.
pub const CM_DOMAIN: &[u8] = b"misaka-shield-v1/cm";
/// Spend nullifier `nf` (value pool).
pub const NF_DOMAIN: &[u8] = b"misaka-shield-v1/nf";
/// Shielded address `a_pk = H(sk)`.
pub const ADDR_DOMAIN: &[u8] = b"misaka-shield-v1/addr";
/// Output-note `rho` derivation (Faerie-Gold binding).
pub const RHO_DOMAIN: &[u8] = b"misaka-shield-v1/rho";
/// Merkle inner node.
pub const MERKLE_DOMAIN: &[u8] = b"misaka-shield-v1/merkle";
/// Merkle empty leaf.
pub const MERKLE_EMPTY_DOMAIN: &[u8] = b"misaka-shield-v1/merkle-empty";
/// Transaction context binding (`ctx`).
pub const CTX_DOMAIN: &[u8] = b"misaka-shield-v1/ctx";
/// Provider-registry Merkle leaf (`= H(pk_receipt_hash ‖ operator_commit)`).
pub const PROVIDER_LEAF_DOMAIN: &[u8] = b"misaka-shield-v1/provider-leaf";
/// Per-session provider nullifier (at-most-once anonymous claim).
pub const PROVIDER_NF_DOMAIN: &[u8] = b"misaka-shield-v1/provider-nf";
/// Per-session receipt-signing key (ADR-0037 §3 #3: the receipt names a SESSION, not a
/// provider — receipts are signed under a key derived per session from `claim_secret`).
pub const PROVIDER_SESSION_RK_DOMAIN: &[u8] = b"misaka-shield-v1/provider-session-rk";
/// Anonymous-claim payout-note binding (ties the shielded payout into `ctx`).
pub const CLAIM_CTX_DOMAIN: &[u8] = b"misaka-shield-v1/claim-ctx";
/// Hiding value commitment `v_claim_cm = H_k("value", amount_le8 ‖ blind)` — the
/// claim-v2 (circuit_version=4) payout-value binding (ADR-0037 §2.2 / audit C-01).
/// MUST equal the `VALUE_DOMAIN` of the claim-v2 AIR
/// (`docs/bench/plonky3-shield-air/claim_v2.rs`).
pub const VALUE_DOMAIN: &[u8] = b"misaka-shield-v1/value";
