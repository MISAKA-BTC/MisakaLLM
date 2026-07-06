//! TGE settlement (ADR-0027 §6.3–6.4). Deterministic, integer-only. Turns
//! per-identity category points into an MSK (sompi) allocation from a fixed pool.
//!
//! Algorithm (§6.3), literally: (1) provisional per-category share
//! `cat_pool_c · pts_{i,c} / Σ_j pts_{j,c}`; (2) clip each ID's TOTAL to the
//! per-ID cap (`per_id_cap_bps` of the pool); (3) redistribute each capped ID's
//! excess to the *uncapped* participants of the SAME category by point ratio,
//! **once** (a recipient may thereby exceed the cap — this is the "1 回のみ"
//! rule); (4) floor; the un-allocated remainder (weight/floor rounding + excess
//! with no uncapped recipient) goes to the ecosystem fund.

use crate::rules::{MilliPoints, Rules};

/// Per-identity category points, C1..C4 in canonical order.
pub type CategoryPoints = [MilliPoints; 4];

/// The outcome of a settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    /// `(identity, reward_sompi)`, sorted by identity. Lossless w.r.t. the pool
    /// together with `ecosystem_remainder`.
    pub rewards: Vec<(String, u64)>,
    /// Un-allocated remainder returned to the ecosystem fund.
    pub ecosystem_remainder: u64,
}

/// Settle `pool` sompi over `ids_points` under `rules`. Input order is
/// irrelevant — the result is sorted by identity and fully deterministic.
pub fn settle(pool: u64, rules: &Rules, ids_points: &[(String, CategoryPoints)]) -> Settlement {
    let mut items: Vec<(String, CategoryPoints)> = ids_points.to_vec();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let n = items.len();
    let pool = pool as u128;

    // (0) category pools + total points per category.
    let mut cat_pool = [0u128; 4];
    for (c, cp) in cat_pool.iter_mut().enumerate() {
        *cp = pool * rules.weight_bps[c] as u128 / 10_000;
    }
    let mut total_pts = [0u128; 4];
    for (_, p) in &items {
        for c in 0..4 {
            total_pts[c] += p[c] as u128;
        }
    }

    // (1) provisional per-category reward.
    let mut base = vec![[0u128; 4]; n];
    for (i, (_, p)) in items.iter().enumerate() {
        for c in 0..4 {
            if total_pts[c] > 0 {
                base[i][c] = cat_pool[c] * p[c] as u128 / total_pts[c];
            }
        }
    }

    // (2) clip each ID's total to the per-ID cap; collect the removed excess per category.
    let cap = pool * rules.per_id_cap_bps as u128 / 10_000;
    let mut kept = vec![[0u128; 4]; n];
    let mut capped = vec![false; n];
    let mut excess = [0u128; 4];
    for i in 0..n {
        let tot: u128 = base[i].iter().sum();
        if tot > cap && tot > 0 {
            capped[i] = true;
            for c in 0..4 {
                let k = base[i][c] * cap / tot;
                kept[i][c] = k;
                excess[c] += base[i][c] - k;
            }
        } else {
            kept[i] = base[i];
        }
    }

    // (3) redistribute excess within each category to the uncapped, by point ratio (once).
    let mut uncapped_pts = [0u128; 4];
    for i in 0..n {
        if !capped[i] {
            for (c, up) in uncapped_pts.iter_mut().enumerate() {
                *up += items[i].1[c] as u128;
            }
        }
    }
    for i in 0..n {
        if capped[i] {
            continue;
        }
        for c in 0..4 {
            if excess[c] > 0 && uncapped_pts[c] > 0 {
                kept[i][c] += excess[c] * items[i].1[c] as u128 / uncapped_pts[c];
            }
        }
    }

    // (4) finalize; remainder → ecosystem.
    let mut distributed = 0u128;
    let rewards: Vec<(String, u64)> = items
        .iter()
        .enumerate()
        .map(|(i, (id, _))| {
            let r: u128 = kept[i].iter().sum();
            distributed += r;
            (id.clone(), r as u64)
        })
        .collect();
    Settlement { rewards, ecosystem_remainder: (pool - distributed) as u64 }
}

/// Vesting split (§6.4): rewards above `vesting_threshold_bps` of the pool vest
/// `vesting_cliff_bps` at TGE and the rest linearly over 6 months; smaller ones
/// are a TGE lump. Returns `(tge_amount, linear_amount)`.
pub fn vesting_split(reward: u64, pool: u64, rules: &Rules) -> (u64, u64) {
    let threshold = (pool as u128 * rules.vesting_threshold_bps as u128 / 10_000) as u64;
    if reward <= threshold {
        return (reward, 0);
    }
    let tge = (reward as u128 * rules.vesting_cliff_bps as u128 / 10_000) as u64;
    (tge, reward - tge)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[(&str, [MilliPoints; 4])]) -> Vec<(String, CategoryPoints)> {
        v.iter().map(|(a, p)| (a.to_string(), *p)).collect()
    }

    #[test]
    fn equal_participants_split_their_category_pool() {
        // Disable the per-ID cap to isolate the proportional split (each would take
        // 20% of the pool here, far above the 5% cap — see the cap test below).
        let r = Rules { per_id_cap_bps: 10_000, ..Rules::default() };
        // Two IDs, equal Node points only. Node pool = 40% of 1000 = 400 → 200 each.
        let s = settle(1000, &r, &ids(&[("a", [10, 0, 0, 0]), ("b", [10, 0, 0, 0])]));
        assert_eq!(s.rewards, vec![("a".into(), 200), ("b".into(), 200)]);
        // Bug/Verify/Infra pools (300+150+150) had no points → all to ecosystem.
        assert_eq!(s.ecosystem_remainder, 600);
        // lossless.
        assert_eq!(s.rewards.iter().map(|(_, r)| r).sum::<u64>() + s.ecosystem_remainder, 1000);
    }

    #[test]
    fn per_id_cap_clips_and_redistributes_once() {
        let r = Rules::default(); // cap 5% of 1000 = 50
        // A holds 90% of Node points, B 10%. Node pool 400 → base A=360, B=40.
        // A total 360 > cap 50 → clipped to 50, excess 310 → to uncapped B (only one).
        // B: 40 + 310 = 350 (exceeds cap — the "once" rule does not re-cap).
        let s = settle(1000, &r, &ids(&[("a", [90, 0, 0, 0]), ("b", [10, 0, 0, 0])]));
        assert_eq!(s.rewards, vec![("a".into(), 50), ("b".into(), 350)]);
        assert_eq!(s.rewards.iter().map(|(_, r)| r).sum::<u64>() + s.ecosystem_remainder, 1000);
    }

    #[test]
    fn deterministic_regardless_of_input_order() {
        let r = Rules::default();
        let s1 = settle(1_000_000, &r, &ids(&[("z", [5, 2, 0, 1]), ("a", [3, 0, 4, 0])]));
        let s2 = settle(1_000_000, &r, &ids(&[("a", [3, 0, 4, 0]), ("z", [5, 2, 0, 1])]));
        assert_eq!(s1, s2);
        assert_eq!(s1.rewards[0].0, "a", "output is sorted by identity");
    }

    #[test]
    fn vesting_only_above_threshold() {
        let r = Rules::default(); // threshold 0.1% of pool
        let pool = 100_000_000u64; // threshold = 100_000
        assert_eq!(vesting_split(50_000, pool, &r), (50_000, 0), "below threshold = TGE lump");
        // above: 25% TGE, 75% linear.
        assert_eq!(vesting_split(200_000, pool, &r), (50_000, 150_000));
    }
}
