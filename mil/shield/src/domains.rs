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
/// Receipt-verify commitment `receipt_cm = H_k("receipt-verify",
/// pk_receipt_hash ‖ session_rk ‖ session_cm ‖ receipt_digest)` — the circuit-3
/// (C-P6, `circuit_version=3`, ADR-0037 §2.4) RECEIPT-AUTHORIZED claim binding: it
/// commits that a valid ML-DSA-87 service receipt was verified under the per-session
/// receipt key (derived from the same `claim_secret` behind the provider's registry
/// leaf) for THIS session. The heavy in-circuit ML-DSA verify is the recursion
/// sub-tree (`docs/mil-shield-cp6-mldsa-in-circuit-design.md`); this domain pins the
/// public commitment the C-P6 circuit surfaces and the reference relation
/// ([`crate::provider::verify_reference_v3`]) checks. Inert until the C-P6 prover +
/// vk-freeze + activation land.
pub const RECEIPT_VERIFY_DOMAIN: &[u8] = b"misaka-shield-v1/receipt-verify";
/// Provider overlay identity: `pk_receipt_hash = H_k("misaka-mil-v1/provider-id", pk)`
/// over the 2592-byte ML-DSA-87 verification key. This is the MIL-core domain (NOT a
/// `misaka-shield-v1/*` one): it MUST equal `misaka_mil_core::domains::MIL_PROVIDER_ID_DOMAIN`
/// so that [`crate::provider::pk_receipt_hash_of`] is byte-identical to
/// `misaka_mil_core::ident::provider_id` and to the pk_receipt bridge AIR
/// (`docs/bench/plonky3-shield-air/pk_receipt_bind_air.rs`, commit 8208ee0). Making the
/// provider leaf's `pk_receipt_hash` a value DERIVED under this domain from a real key —
/// rather than a free input — is what closes the pk_receipt system-wiring gap.
pub const MIL_PROVIDER_ID_DOMAIN: &[u8] = b"misaka-mil-v1/provider-id";
