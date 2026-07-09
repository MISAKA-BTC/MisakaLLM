//! Exact per-circuit cost model (ADR-0033 §SP-0 / O-SP-1 input). The number that
//! decides the STARK backend is **how much keyed-BLAKE2b-512 the circuit proves**,
//! because BLAKE2b is the only non-trivial gadget (everything else is field
//! addition / comparison). This module derives that count *from the frozen
//! relations* (`misaka-mil-shield::{note, merkle, spend, provider}`), so the
//! cap-feasibility verdict rests on real structure, not a guess.
//!
//! ## keyed BLAKE2b-512 compression model
//!
//! `blake2b_512_keyed(context, data)` (crypto/hashes) uses `context` as the
//! BLAKE2b **key**: a nonzero key is padded to one 128-byte block processed
//! *before* the message. So the compression-function count for a message of
//! `data_len` bytes is `1 (key block) + max(1, ceil(data_len / 128))`.

/// Compressions for one keyed BLAKE2b-512 over `data_len` message bytes
/// (1 key block + ⌈data_len/128⌉ message blocks, min 1 message block).
pub const fn blake2b_compressions(data_len: usize) -> u32 {
    let msg_blocks = if data_len == 0 { 1 } else { data_len.div_ceil(128) };
    1 + msg_blocks as u32
}

// --- exact hashed-message lengths of every gadget (bytes), from the sources ---

/// `commit`: value(8) ‖ owner_pk(64) ‖ rho(64) ‖ r(64) ‖ token_id(4) — note.rs.
pub const COMMIT_LEN: usize = 8 + 64 + 64 + 64 + 4; // 204
/// `hash_node`: left(64) ‖ right(64) — merkle.rs.
pub const NODE_LEN: usize = 64 + 64; // 128
/// `shielded_address`: sk(64) — note.rs.
pub const ADDR_LEN: usize = 64;
/// `nullifier`: sk(64) ‖ rho(64) — note.rs.
pub const NF_LEN: usize = 64 + 64; // 128
/// `derive_output_rho`: nf1(64) ‖ nf2(64) ‖ j(1) — note.rs.
pub const RHO_LEN: usize = 64 + 64 + 1; // 129
/// `provider_leaf`: pk_receipt_hash(64) ‖ claim_pk(64) — provider.rs.
pub const PROVIDER_LEAF_LEN: usize = 64 + 64; // 128
/// `provider_nullifier`: claim_secret(64) ‖ session_cm(64) — provider.rs.
pub const PROVIDER_NF_LEN: usize = 64 + 64; // 128
/// `claim_ctx`: session_cm(64) ‖ amount(8) ‖ cm_payout(64) ‖ provider_nf(64).
pub const CLAIM_CTX_LEN: usize = 64 + 8 + 64 + 64; // 200

/// The tree depth the on-chain pool commits to (`ShieldedPool.TREE_DEPTH`).
pub const POOL_TREE_DEPTH: u32 = 20;

/// AIR cells (area = rows × columns) one BLAKE2b-512 compression costs in a
/// modern STARK. Keccak-f-class unfriendly permutations land at roughly this
/// order in Plonky3/stwo AIRs; it is the ONE input the measured `.119` bench
/// refines (see `docs/mil-shield-stark-bench-runbook.md`). Using area (not
/// "rows") avoids the layout-dependent rows-vs-columns ambiguity: proof size
/// tracks the committed domain, which tracks total area.
pub const DEFAULT_CONSTRAINTS_PER_COMPRESSION: u32 = 3_000;

/// A circuit's proving cost, in hash gadgets and BLAKE2b-512 compressions, plus a
/// constraint-area estimate given a per-compression area cost (the measured input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitCost {
    pub circuit: &'static str,
    /// Number of keyed-BLAKE2b-512 invocations proven.
    pub hash_calls: u32,
    /// Total BLAKE2b-512 compression-function calls (the dominant AIR cost).
    pub blake2b_compressions: u32,
    /// AIR cells (area) charged per compression (measured; the one uncertain knob).
    pub constraints_per_compression: u32,
    /// Estimated total AIR area ≈ compressions × constraints_per_compression.
    pub est_constraints: u64,
    /// Smallest power-of-two exponent ≥ `est_constraints` (STARK domains are 2^k).
    pub est_constraints_pow2: u32,
}

impl CircuitCost {
    fn finish(circuit: &'static str, hash_calls: u32, compressions: u32, constraints_per_compression: u32) -> Self {
        let est_constraints = compressions as u64 * constraints_per_compression as u64;
        let mut k = 0u32;
        while (1u64 << k) < est_constraints.max(1) {
            k += 1;
        }
        CircuitCost {
            circuit,
            hash_calls,
            blake2b_compressions: compressions,
            constraints_per_compression,
            est_constraints,
            est_constraints_pow2: k,
        }
    }
}

/// `CIRCUIT_SPEND` (2-in / 2-out JoinSplit) worst case = both inputs enabled.
/// Constraints C-S1..8 (ADR-0034 §2.1); the hashed gadgets are:
/// per input: `commit(note_in)` + `tree_depth × hash_node` + `shielded_address`
/// + `nullifier`; per output: `derive_output_rho` + `commit(note_out)`.
pub fn spend_cost(tree_depth: u32, constraints_per_compression: u32) -> CircuitCost {
    let per_input_calls = 1 /*commit*/ + tree_depth /*membership nodes*/ + 1 /*addr*/ + 1 /*nf*/;
    let per_output_calls = 1 /*rho*/ + 1 /*commit*/;
    let hash_calls = 2 * per_input_calls + 2 * per_output_calls;

    let per_input_comp = blake2b_compressions(COMMIT_LEN)
        + tree_depth * blake2b_compressions(NODE_LEN)
        + blake2b_compressions(ADDR_LEN)
        + blake2b_compressions(NF_LEN);
    let per_output_comp = blake2b_compressions(RHO_LEN) + blake2b_compressions(COMMIT_LEN);
    let compressions = 2 * per_input_comp + 2 * per_output_comp;

    CircuitCost::finish("spend (2-in/2-out)", hash_calls, compressions, constraints_per_compression)
}

/// `CIRCUIT_PROVIDER_CLAIM` v2 (membership-only) — constraints C-P1..5. Gadgets:
/// `set_depth × hash_node` + `provider_leaf` + `shielded_address` +
/// `provider_nullifier` + `commit(cm_payout)` + `claim_ctx`. (v3 adds C-P6, an
/// in-circuit ML-DSA-87 verify — see `mldsa_verify_cost_note`.)
pub fn provider_claim_cost(set_depth: u32, constraints_per_compression: u32) -> CircuitCost {
    let hash_calls = set_depth + 1 /*leaf*/ + 1 /*addr*/ + 1 /*provider_nf*/ + 1 /*commit*/ + 1 /*ctx*/;
    let compressions = set_depth * blake2b_compressions(NODE_LEN)
        + blake2b_compressions(PROVIDER_LEAF_LEN)
        + blake2b_compressions(ADDR_LEN)
        + blake2b_compressions(PROVIDER_NF_LEN)
        + blake2b_compressions(COMMIT_LEN)
        + blake2b_compressions(CLAIM_CTX_LEN);
    CircuitCost::finish("provider-claim v2", hash_calls, compressions, constraints_per_compression)
}

/// Honest note on C-P6 (v3): an in-circuit ML-DSA-87 (FIPS-204) verify is
/// SHAKE256 (Keccak) expansion + NTTs over Z_q (q≈2^23, degree 256) + an 8×7
/// matrix-vector product + norm/hint checks — on the order of **10^2–10^3× the
/// spend circuit**. It is the clear driver toward a zkVM or a recursion layer
/// rather than a hand-written flat AIR, and is why ADR-0034 fences C-P6 as its
/// own `circuit_version = 3` with the receipt checked off-circuit until then.
pub const fn mldsa_verify_cost_note() -> &'static str {
    "C-P6 in-circuit ML-DSA-87 ≈ 10^2–10^3× spend; recursion/zkVM territory (ADR-0034 §2.2)"
}
