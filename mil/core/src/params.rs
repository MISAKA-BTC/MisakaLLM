//! MIL protocol parameters (design §10) and the pure reward math (§5.3–§5.5).
//!
//! Everything here is exact integer arithmetic — no floats — so provider,
//! requester, and any future contract/precompile implementation agree
//! bit-for-bit.

/// Sompi per whole MSK (same base unit as KAS).
pub const SOMPI_PER_MSK: u64 = 100_000_000;

// --- §5.3 fee split ------------------------------------------------------------------

pub const FEE_SPLIT_PROVIDER_PCT: u64 = 88;
pub const FEE_SPLIT_BURN_PCT: u64 = 5;
pub const FEE_SPLIT_VALIDATOR_POOL_PCT: u64 = 4;
pub const FEE_SPLIT_TREASURY_PCT: u64 = 3;

// --- §10 parameter table ---------------------------------------------------------------

/// Cumulative receipt cadence (fixed in v1).
pub const RECEIPT_INTERVAL_OUTPUT_TOKENS: u64 = 512;
/// Compute epoch, blue score (≈ 6 h @ 10 BPS; 2160 × the DNS attestation epoch).
pub const COMPUTE_EPOCH_BLUE_SCORE: u64 = 216_000;
/// Per-entity share cap of the epoch subsidy pool, parts-per-million (5%).
pub const SHARE_CAP_PPM: u64 = 50_000;
/// Minimum stake, class A (H100+ CC, Tier 1).
pub const MIN_STAKE_CLASS_A_SOMPI: u64 = 500_000 * SOMPI_PER_MSK;
/// Minimum stake, class B (24 GB+ VRAM, Tier 2).
pub const MIN_STAKE_CLASS_B_SOMPI: u64 = 100_000 * SOMPI_PER_MSK;
/// Unbond delay (dispute window + DNS-finality margin).
pub const UNBOND_DELAY_SECS: u64 = 7 * 24 * 3600;
/// Claims/refunds above this must reference a DNS-final escrow open (§8.4).
pub const DNS_FINAL_CLAIM_THRESHOLD_SOMPI: u64 = 10_000 * SOMPI_PER_MSK;
/// Sticky-session TTL: in-enclave KV cache retention (§13.5).
pub const STICKY_SESSION_TTL_SECS: u64 = 30 * 60;

/// Reference GPU-class weights `g` for the epoch pool (§5.4). Attested class →
/// weight; governance-tunable, these are the design's initial values.
pub const GPU_CLASS_WEIGHT_H200_CC: u32 = 10;
pub const GPU_CLASS_WEIGHT_H100_CC: u32 = 8;
pub const GPU_CLASS_WEIGHT_CONSUMER_24G: u32 = 1;

// --- §5.3 fee split math ---------------------------------------------------------------

/// One fee split into the four §5.3 destinations. Invariant: the four parts
/// always sum to the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSplit {
    pub provider: u64,
    pub burn: u64,
    pub validator_pool: u64,
    pub treasury: u64,
}

/// Split a fee 88/5/4/3. The three minority shares round down; every
/// remainder sompi goes to the provider (the party that did the work), so the
/// sum is exactly `total` and no sompi is minted or lost.
pub fn split_fee(total_sompi: u64) -> FeeSplit {
    // u128 per-share math: no intermediate overflow for any u64 input.
    let share = |pct: u64| -> u64 { (total_sompi as u128 * pct as u128 / 100) as u64 };
    let burn = share(FEE_SPLIT_BURN_PCT);
    let validator_pool = share(FEE_SPLIT_VALIDATOR_POOL_PCT);
    let treasury = share(FEE_SPLIT_TREASURY_PCT);
    let provider = total_sompi - burn - validator_pool - treasury;
    FeeSplit { provider, burn, validator_pool, treasury }
}

// --- §6.2 pricing ------------------------------------------------------------------------

/// Job cost under an ask of `ask_in`/`ask_out` sompi per 1000 tokens,
/// rounding **up** per side (a provider is never underpaid by rounding;
/// the requester's exposure is bounded by `price_cap_sompi`).
pub fn job_cost_sompi(ask_in_per_1k: u64, ask_out_per_1k: u64, tokens_in: u64, tokens_out: u64) -> u64 {
    let side = |ask: u64, tokens: u64| -> u64 { ((ask as u128 * tokens as u128).div_ceil(1000)) as u64 };
    side(ask_in_per_1k, tokens_in).saturating_add(side(ask_out_per_1k, tokens_out))
}

// --- §5.4 epoch subsidy pool -------------------------------------------------------------

/// A provider's measured standing for one compute epoch (§5.4 inputs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderEpochStanding {
    /// Attested GPU-class weight `g` (e.g. [`GPU_CLASS_WEIGHT_H100_CC`]).
    pub gpu_class_weight: u32,
    /// Canary response rate `u`, parts-per-million of canaries answered in SLA.
    pub canary_uptime_ppm: u32,
    /// Reputation `q` (completion rate / latency p95 / dispute rate
    /// composite), parts-per-million.
    pub reputation_ppm: u32,
    /// Bonded stake `s`, sompi.
    pub stake_sompi: u64,
}

/// `w_i = g_i · u_i · q_i · sqrt(min(s_i, s_cap))` in exact integer math.
/// ppm factors keep full precision; the result fits u128 comfortably
/// (g ≤ 2³², u·q ≤ 10¹², √s ≤ 2³²).
pub fn provider_weight(standing: &ProviderEpochStanding, stake_cap_sompi: u64) -> u128 {
    let g = standing.gpu_class_weight as u128;
    let u = standing.canary_uptime_ppm.min(1_000_000) as u128;
    let q = standing.reputation_ppm.min(1_000_000) as u128;
    let s = standing.stake_sompi.min(stake_cap_sompi) as u128;
    g * u * q * s.isqrt()
}

/// Distribute one epoch's subsidy pool (§5.4):
/// `payout_i = pool · min(w_i / Σw, 5%)`. The cap binds per entity; capped
/// surplus stays in the pool (rolls forward), so `Σ payout ≤ pool` always.
/// Returns per-provider payouts aligned with `standings`.
pub fn epoch_payouts(pool_sompi: u64, standings: &[ProviderEpochStanding], stake_cap_sompi: u64) -> Vec<u64> {
    let weights: Vec<u128> = standings.iter().map(|s| provider_weight(s, stake_cap_sompi)).collect();
    let total: u128 = weights.iter().sum();
    if total == 0 {
        return vec![0; standings.len()];
    }
    let cap = (pool_sompi as u128) * (SHARE_CAP_PPM as u128) / 1_000_000;
    weights.iter().map(|w| ((pool_sompi as u128 * w / total).min(cap)) as u64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_split_is_exact_and_lossless() {
        for total in [0u64, 1, 99, 100, 101, 12_345, SOMPI_PER_MSK, u64::MAX / 2] {
            let s = split_fee(total);
            assert_eq!(s.provider + s.burn + s.validator_pool + s.treasury, total, "split must be lossless for {total}");
            assert!(s.provider >= s.burn + s.validator_pool + s.treasury || total < 100);
        }
        // exact percentages on a round number
        let s = split_fee(100 * SOMPI_PER_MSK);
        assert_eq!(s.provider, 88 * SOMPI_PER_MSK);
        assert_eq!(s.burn, 5 * SOMPI_PER_MSK);
        assert_eq!(s.validator_pool, 4 * SOMPI_PER_MSK);
        assert_eq!(s.treasury, 3 * SOMPI_PER_MSK);
    }

    #[test]
    fn job_cost_rounds_up_per_side() {
        // 1 token at 1 sompi/1k must still cost 1 sompi
        assert_eq!(job_cost_sompi(1, 1, 1, 0), 1);
        assert_eq!(job_cost_sompi(0, 500, 0, 3), 2); // ceil(1500/1000) = 2
        assert_eq!(job_cost_sompi(1000, 2000, 1000, 500), 1000 + 1000);
        assert_eq!(job_cost_sompi(0, 0, 100, 100), 0);
    }

    fn standing(g: u32, stake_msk: u64) -> ProviderEpochStanding {
        ProviderEpochStanding {
            gpu_class_weight: g,
            canary_uptime_ppm: 1_000_000,
            reputation_ppm: 1_000_000,
            stake_sompi: stake_msk * SOMPI_PER_MSK,
        }
    }

    #[test]
    fn epoch_payouts_cap_and_sqrt_dampening() {
        let cap = 1_000_000 * SOMPI_PER_MSK;
        let pool = 1_000 * SOMPI_PER_MSK;

        // 25 identical providers → 4% each, below the 5% cap, near-full pool
        let many: Vec<_> = (0..25).map(|_| standing(GPU_CLASS_WEIGHT_H100_CC, 500_000)).collect();
        let payouts = epoch_payouts(pool, &many, cap);
        let sum: u64 = payouts.iter().sum();
        assert!(sum <= pool);
        assert!(payouts.iter().all(|&p| p == payouts[0]));

        // 2 providers → the cap binds both at 5%, surplus rolls forward
        let two = vec![standing(8, 500_000), standing(8, 500_000)];
        let payouts = epoch_payouts(pool, &two, cap);
        let cap_amount = pool / 20;
        assert_eq!(payouts, vec![cap_amount, cap_amount]);

        // sqrt dampening: 4× the stake buys only 2× the weight
        let a = provider_weight(&standing(1, 100_000), cap);
        let b = provider_weight(&standing(1, 400_000), cap);
        assert!(b > a && b <= 2 * a + a / 100, "4x stake must yield ~2x weight, got {a} vs {b}");

        // stake above the cap adds nothing
        let capped = provider_weight(&standing(1, 2_000_000), cap);
        let at_cap = provider_weight(&standing(1, 1_000_000), cap);
        assert_eq!(capped, at_cap);

        // zero weights → zero payouts, no division panic
        assert_eq!(epoch_payouts(pool, &[standing(0, 0)], cap), vec![0]);
    }
}
