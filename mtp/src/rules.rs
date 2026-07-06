//! Frozen scoring rules (ADR-0027 §3, §6.2, §11-A). Every value here is part of
//! the per-epoch `rules_hash` so a ledger is reproducible from published rules.
//!
//! All arithmetic in the crate is **integer** (points are carried in
//! milli-points = points × 1000, multipliers as exact `(num, den)` rationals)
//! so scoring is bit-reproducible on every platform — no floating point.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Points are carried internally as milli-points (1 point = 1000 milli-points).
pub type MilliPoints = u64;
/// 1 point in milli-points.
pub const POINT: MilliPoints = 1000;

/// Rules schema version — bump on any change to the values below.
pub const RULES_VERSION: u16 = 1;

/// BPS stage coefficient (ADR-0027 §3): A ×1.0, B ×1.25, C ×1.5. As an exact rational.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Stage {
    /// testnet-25.
    A,
    /// testnet-40.
    B,
    /// testnet-50.
    C,
}

impl Stage {
    /// The stage multiplier as `(num, den)`: A=1/1, B=5/4, C=3/2.
    pub const fn factor(self) -> (u64, u64) {
        match self {
            Stage::A => (1, 1),
            Stage::B => (5, 4),
            Stage::C => (3, 2),
        }
    }
}

/// Bug severity → base points (ADR-0027 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Severity {
    /// consensus split, fund loss, PQ soundness, remote crash.
    S0,
    /// node crash/DoS, EVM state divergence, overlay finality break.
    S1,
    /// sync edge case, RPC inconsistency, resource leak.
    S2,
    /// minor bug, docs, UX.
    S3,
}

impl Severity {
    /// Base points for a first, accepted report.
    pub const fn base_points(self) -> u64 {
        match self {
            Severity::S0 => 5_000,
            Severity::S1 => 2_000,
            Severity::S2 => 500,
            Severity::S3 => 100,
        }
    }
}

/// The four scoring categories (ADR-0027 §3, §6.2). Order is canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Category {
    /// C1 node operation.
    Node,
    /// C2 bug reports.
    Bug,
    /// C3 verification / feedback.
    Verify,
    /// C4 infrastructure.
    Infra,
}

impl Category {
    /// All categories in canonical order (C1..C4).
    pub const ALL: [Category; 4] = [Category::Node, Category::Bug, Category::Verify, Category::Infra];
    /// Canonical index 0..4 (C1..C4).
    pub const fn index(self) -> usize {
        match self {
            Category::Node => 0,
            Category::Bug => 1,
            Category::Verify => 2,
            Category::Infra => 3,
        }
    }
}

/// The frozen rule parameters that define a score. Hashed into every ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Rules {
    pub version: u16,
    // --- C1 base points ---
    pub node_uptime_base: u64, // 100 · u · m_geo · m_ver · d_n
    pub validator_base: u64,   // 200 · a
    pub ibd_bench_points: u64, // 50 / submission
    pub drill_points: u64,     // 100 / event
    // --- C1 multipliers as (num, den) ---
    pub m_geo_num: u64,
    pub m_geo_den: u64,
    pub m_ver_num: u64,
    pub m_ver_den: u64,
    /// Per-ID node decrement d_n by rank (1st, 2nd, 3rd, 4th+), each as (num, den).
    pub d_n: [(u64, u64); 4],
    // --- C2 duplicate factor (num, den) ---
    pub bug_dup_num: u64,
    pub bug_dup_den: u64,
    // --- category weights, basis points (sum 10000) ---
    pub weight_bps: [u16; 4],
    // --- settlement ---
    pub per_id_cap_bps: u16, // 500 = 5%
    /// Vesting threshold as bps of the pool (10 = 0.1%); above it, cliff+linear.
    pub vesting_threshold_bps: u16,
    pub vesting_cliff_bps: u16, // 2500 = 25% at TGE
}

impl Default for Rules {
    /// The ADR-0027 v1 defaults (§3, §6.2, §6.3).
    fn default() -> Self {
        Rules {
            version: RULES_VERSION,
            node_uptime_base: 100,
            validator_base: 200,
            ibd_bench_points: 50,
            drill_points: 100,
            m_geo_num: 3,
            m_geo_den: 2, // 1.5
            m_ver_num: 6,
            m_ver_den: 5, // 1.2
            d_n: [(1, 1), (1, 2), (1, 4), (0, 1)],
            bug_dup_num: 1,
            bug_dup_den: 10, // duplicates score 10%
            weight_bps: [4000, 3000, 1500, 1500],
            per_id_cap_bps: 500,       // 5%
            vesting_threshold_bps: 10, // 0.1%
            vesting_cliff_bps: 2500,   // 25% TGE, 75% linear/6mo
        }
    }
}

impl Rules {
    /// `Hash64_k("misaka-mtp-v1/rules", borsh(self))` — the value pinned in each
    /// epoch ledger. Anyone with the same `Rules` recomputes the same hash.
    pub fn rules_hash(&self) -> kaspa_hashes::Hash64 {
        let bytes = borsh::to_vec(self).expect("borsh of in-memory Rules is infallible");
        kaspa_hashes::blake2b_512_keyed(crate::MTP_RULES_CONTEXT, &bytes)
    }

    /// Canonical `weight_bps` must sum to 10000 (guards a malformed rule set).
    pub fn weights_sum_to_full(&self) -> bool {
        self.weight_bps.iter().map(|&w| w as u32).sum::<u32>() == 10_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_are_well_formed() {
        let r = Rules::default();
        assert!(r.weights_sum_to_full(), "category weights must sum to 100%");
        assert_eq!(r.per_id_cap_bps, 500);
        // rules_hash is deterministic + non-trivial.
        assert_eq!(r.rules_hash(), Rules::default().rules_hash());
        assert_ne!(r.rules_hash().as_bytes(), [0u8; 64]);
    }

    #[test]
    fn a_rule_change_changes_the_hash() {
        let mut r = Rules::default();
        let h0 = r.rules_hash();
        r.node_uptime_base = 101;
        assert_ne!(h0, r.rules_hash(), "any rule edit must change rules_hash");
    }
}
