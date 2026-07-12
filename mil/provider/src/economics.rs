//! Provider economic guard + standby controller (ADR-0029 §24, D4–D8).
//!
//! This is **off-protocol SDK policy** — it never touches consensus, contracts,
//! issuance, or the coinbase split. It gives an operator two levers so that
//! "unprofitable" always means "no jobs", never "below-cost jobs" or "forced
//! exit":
//!
//!  1. [`AskFloor`] — the **economic guard** (§24.3, D4/D5). A provider prices
//!     its supply cost (power, and optionally CAPEX amortization + stake
//!     opportunity cost) in USD, applies a margin, and the SDK **rejects any
//!     job below that floor**. The floor is USD-indexed and repriced to MSK
//!     per session via the FSL rate (D5), so power-cost coverage is decoupled
//!     from MSK volatility. Non-MSK is never paid out — only the *price* is
//!     indexed (precondition 3).
//!
//!  2. [`StandbyController`] — the **standby layer** (§24.4, D6). In
//!     thin-demand / cheap-MSK periods a provider hibernates instead of
//!     exiting: stop the GPU (~0 power), **keep attestation signing** (no GPU
//!     needed), drop out of matching. Hardware-existence proof relaxes to one
//!     wake-up canary/day; issuance stays full (issuance = presence, D7). Supply
//!     hibernates and returns instantly on recovery.
//!
//! Everything is **exact integer arithmetic** (µUSD / mWh / bps), matching
//! `misaka_mil_core::params`, so the guard is deterministic and float-free.

use misaka_mil_core::params::SOMPI_PER_MSK;

/// Micro-USD: 1e-6 USD. The integer money unit for the USD-indexed guard (D5).
pub type MicroUsd = u64;

/// Basis-points denominator (100% = 10_000).
const BPS: u128 = 10_000;
/// Milli-watt-hours per kWh (1 kWh = 1_000 Wh = 1_000_000 mWh).
const MWH_PER_KWH: u128 = 1_000_000;

// --- §24.3 economic guard (D4/D5) --------------------------------------------------------

/// A provider's measured supply-cost profile (§24.3). All money is µUSD; energy
/// is mWh/1k tokens so a hobbyist can express fractional kWh without floats.
///
/// The two CAPEX/capital terms are **optional** (0 = a hobbyist prices power
/// only; a commercial/cloud-rental operator prices full cost — D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AskFloor {
    /// Energy per 1000 tokens, in milli-watt-hours (mWh). Measured under the
    /// batch-invariant serving profile (D1). E.g. 50 Wh/1k = 50_000 mWh.
    pub mwh_per_1k_tokens: u64,
    /// Electricity tariff in µUSD per kWh. (An operator sets ¥/kWh locally; the
    /// SDK converts to USD, since D5 indexes the *price* — the floor is USD-native.)
    pub tariff_uusd_per_kwh: MicroUsd,
    /// Optional CAPEX amortization per 1k tokens (purchase price / lifetime /
    /// assumed utilization). 0 for a power-only hobbyist.
    pub capex_uusd_per_1k: MicroUsd,
    /// Optional stake opportunity cost per 1k tokens. 0 for a hobbyist.
    pub stake_opp_cost_uusd_per_1k: MicroUsd,
    /// Provider margin over cost, in basis points (2000 = 20%).
    pub margin_bps: u32,
}

impl AskFloor {
    /// A power-only profile (both optional cost terms zero, D4 hobbyist case).
    pub fn power_only(mwh_per_1k_tokens: u64, tariff_uusd_per_kwh: MicroUsd, margin_bps: u32) -> Self {
        Self { mwh_per_1k_tokens, tariff_uusd_per_kwh, capex_uusd_per_1k: 0, stake_opp_cost_uusd_per_1k: 0, margin_bps }
    }

    /// Energy cost per 1k tokens (µUSD): `mWh/1k · tariff / 1e6`.
    ///
    /// The narrowing u128→u64 **saturates** to `u64::MAX`: an operator who
    /// misconfigures a floor beyond `u64` yields the maximum floor, so every
    /// offer is rejected (fail-closed) — never a silently wrapped, low floor.
    pub fn energy_uusd_per_1k(&self) -> MicroUsd {
        let raw = self.mwh_per_1k_tokens as u128 * self.tariff_uusd_per_kwh as u128 / MWH_PER_KWH;
        u64::try_from(raw).unwrap_or(u64::MAX)
    }

    /// `ask_floor = (energy + capex + stake_opp) × (1 + margin)` in µUSD/1k (§24.3).
    /// Pure supply cost times the margin — the USD-native floor before FSL repricing.
    /// Narrowing saturates to `u64::MAX` (fail-closed, see [`Self::energy_uusd_per_1k`]).
    pub fn floor_uusd_per_1k(&self) -> MicroUsd {
        let base = self.energy_uusd_per_1k() as u128 + self.capex_uusd_per_1k as u128 + self.stake_opp_cost_uusd_per_1k as u128;
        u64::try_from(base * (BPS + self.margin_bps as u128) / BPS).unwrap_or(u64::MAX)
    }

    /// Reprice the µUSD/1k floor to **sompi per 1k tokens** via the FSL rate
    /// (D5). `fsl_uusd_per_msk` is the µUSD price of 1 whole MSK.
    ///
    /// `floor_sompi = floor_uusd · SOMPI_PER_MSK / fsl_uusd_per_msk`, rounded
    /// **up** so repricing never drops the ask below cost. A zero/absent FSL
    /// rate yields 0 (the caller must treat an unavailable feed as "cannot
    /// price" — never as "free").
    pub fn floor_sompi_per_1k(&self, fsl_uusd_per_msk: MicroUsd) -> u64 {
        if fsl_uusd_per_msk == 0 {
            return 0;
        }
        let floor_uusd = self.floor_uusd_per_1k() as u128;
        // Narrowing saturates to u64::MAX (fail-closed): an unpriceably-high floor
        // rejects every offer rather than wrapping to a low sompi value.
        u64::try_from((floor_uusd * SOMPI_PER_MSK as u128).div_ceil(fsl_uusd_per_msk as u128)).unwrap_or(u64::MAX)
    }

    /// The economic guard (§24.3, D4): accept a job only if its offered price
    /// per 1k tokens covers the repriced floor. `offered_sompi_per_1k` is the
    /// weaker of the two ask sides the operator would honor for this job.
    pub fn guard(&self, offered_sompi_per_1k: u64, fsl_uusd_per_msk: MicroUsd) -> GuardDecision {
        let floor = self.floor_sompi_per_1k(fsl_uusd_per_msk);
        // Fail-closed: no FSL rate ⇒ cannot prove cost coverage ⇒ reject.
        if fsl_uusd_per_msk == 0 {
            return GuardDecision::RejectNoRate;
        }
        if offered_sompi_per_1k < floor {
            GuardDecision::RejectBelowFloor { floor_sompi_per_1k: floor, offered_sompi_per_1k }
        } else {
            GuardDecision::Accept { floor_sompi_per_1k: floor }
        }
    }
}

/// The economic guard's verdict for one job (§24.3, D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardDecision {
    /// The offer covers the repriced floor.
    Accept { floor_sompi_per_1k: u64 },
    /// The offer is below the repriced supply-cost floor — rejected.
    RejectBelowFloor { floor_sompi_per_1k: u64, offered_sompi_per_1k: u64 },
    /// The FSL price feed is unavailable — cost coverage cannot be proven, so
    /// the guard fails closed rather than pricing at zero.
    RejectNoRate,
}

impl GuardDecision {
    /// Whether the job clears the guard.
    pub fn is_accept(&self) -> bool {
        matches!(self, GuardDecision::Accept { .. })
    }
}

// --- (audit m7) whole-sompi pricing guard at the quote SOURCE ----------------------------

/// The provider-share whole-sompi granularity. `MilShieldedEscrow.claimAnonV2` pays the
/// provider `gross · 88/100` sompi as a shielded note and reverts `SplitMismatch` unless
/// that share is a WHOLE sompi — which holds **iff `gross ≡ 0 (mod 25)`** (88/100 = 22/25
/// and `gcd(22, 25) = 1`, so a whole-sompi share requires 25 | gross). This mirrors the
/// contract gate exactly (`misaka_mil_shield::economics::claim_v2_split` /
/// `whole_sompi_gate_iff_gross_mod_25`).
///
/// A quote whose *served gross* is not a multiple of 25 is a **permanent liveness trap**:
/// the escrow can never be claimed and its funds sit locked until the requester refunds.
/// The helpers below close that at the SOURCE — where the provider turns a uniform price +
/// token counts into a gross — instead of discovering it as a stuck escrow at claim time.
pub const WHOLE_SOMPI_GROSS_STEP: u64 = 25;

/// The largest multiple of [`WHOLE_SOMPI_GROSS_STEP`] representable in a `u64`
/// (`u64::MAX - (u64::MAX % 25) = u64::MAX - 15`). A gross in the top 25-wide band
/// `(MAX_WHOLE_SOMPI_GROSS, u64::MAX]` cannot be rounded UP to the next multiple of 25
/// without exceeding `u64::MAX`; [`quantize_gross_up`] clamps such a gross DOWN to this
/// value so its result is **always** a whole-sompi-claimable multiple — never `u64::MAX`
/// itself (which is `≡ 15 (mod 25)` and would re-open the SplitMismatch liveness trap).
pub const MAX_WHOLE_SOMPI_GROSS: u64 = u64::MAX - (u64::MAX % WHOLE_SOMPI_GROSS_STEP);

/// Why a quote cannot be served as-is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QuoteError {
    /// The served gross is not a multiple of [`WHOLE_SOMPI_GROSS_STEP`], so
    /// `claimAnonV2` would revert `SplitMismatch` and the escrow would be unclaimable.
    #[error("served gross {gross} sompi is not a multiple of {step} — claimAnonV2 would revert SplitMismatch (permanent liveness trap)")]
    GrossNotWholeSompi { gross: u64, step: u64 },
    /// `price · (tok_in + tok_out)` overflowed before the `/1000`, or the gross exceeds
    /// `u64` — a misconfigured quote, rejected rather than silently wrapped.
    #[error("overflow computing served gross from price/token counts")]
    Overflow,
}

/// The gross `MilShieldedEscrow.claimAnonV2` will compute for `(uniform_price_per_1k,
/// tok_in, tok_out)`: `gross = price · (tok_in + tok_out) / 1000` (floor) — operation-
/// identical to the Solidity. Fail-closed on overflow rather than wrapping.
pub fn served_gross_sompi(uniform_price_per_1k: u64, tok_in: u64, tok_out: u64) -> Result<u64, QuoteError> {
    let sum = tok_in as u128 + tok_out as u128;
    let prod = (uniform_price_per_1k as u128).checked_mul(sum).ok_or(QuoteError::Overflow)?;
    u64::try_from(prod / 1000).map_err(|_| QuoteError::Overflow)
}

/// REJECT-mode guard (audit m7): return the served gross only if it is *claimable* (a
/// whole-sompi provider share), else `Err(GrossNotWholeSompi)`. Call this at quote time so
/// an unclaimable price/token combination is refused BEFORE a requester locks funds against
/// it — never discovered at claim time as a permanently stuck escrow.
pub fn checked_gross_sompi(uniform_price_per_1k: u64, tok_in: u64, tok_out: u64) -> Result<u64, QuoteError> {
    let gross = served_gross_sompi(uniform_price_per_1k, tok_in, tok_out)?;
    if !gross.is_multiple_of(WHOLE_SOMPI_GROSS_STEP) {
        return Err(QuoteError::GrossNotWholeSompi { gross, step: WHOLE_SOMPI_GROSS_STEP });
    }
    Ok(gross)
}

/// Whether a gross is claimable (a whole-sompi provider share): `gross ≡ 0 (mod 25)`.
pub fn is_whole_sompi_gross(gross: u64) -> bool {
    gross.is_multiple_of(WHOLE_SOMPI_GROSS_STEP)
}

/// CLAMP-to-claimable helper (audit m7 / L-04): the nearest CLAIMABLE gross — a multiple of
/// [`WHOLE_SOMPI_GROSS_STEP`] — for `gross`. In the entire economically-reachable range this is a
/// round-**up** (ceil to the next multiple of 25), snapping the served gross onto the ADR-0037 §3
/// denomination ladder; on the physically-unreachable top 25-wide band `(MAX_WHOLE_SOMPI_GROSS,
/// u64::MAX]` (see below) it clamps **down** instead, because there no multiple of 25 that is
/// `≥ gross` is representable in a `u64`. It is therefore NOT an unconditional `≥ input` round-up —
/// the strict `≥`-or-reject contract is [`checked_quantize_gross_up`]; this total variant never
/// fails, so the post-serving **settlement record** always yields a claimable value. A provider
/// that prefers to snap its reported denomination onto the ladder (rather than reject) uses this;
/// the *reject* counterpart at the pre-funding **quote** gate is [`checked_gross_sompi`].
///
/// The result is **always** a multiple of [`WHOLE_SOMPI_GROSS_STEP`] — this is the whole point
/// of the guard, and the invariant M-07 protects. The previous version used
/// `saturating_add`, which for a gross in the top 25-wide band (e.g. `u64::MAX`, where
/// `u64::MAX % 25 == 15`) saturated to `u64::MAX` — itself **not** a multiple of 25, silently
/// re-opening the permanent `claimAnonV2` SplitMismatch trap the guard exists to close. This
/// version uses `checked_add` and, on the overflow band `(MAX_WHOLE_SOMPI_GROSS, u64::MAX]`,
/// clamps **down** to [`MAX_WHOLE_SOMPI_GROSS`] — the largest representable claimable gross.
///
/// Clamping (rather than returning a `QuoteError`) is the safer choice on this **settlement-
/// record** path, deliberately splitting responsibilities with the quote gate:
///  * The **quote** path ([`checked_gross_sompi`], `config.rs`) runs *before* a requester locks
///    escrow funds, so it **rejects** overflow/non-multiples — the fundable amount is refused.
///  * This **record** path runs *after* a session is already served, so it must always emit a
///    *claimable* gross and never fail/panic — keeping the provider sidecar live and the record
///    settleable. The overflow band is `> u64::MAX - 15 ≈ 6× the entire 30 B MSK supply`, i.e.
///    physically unreachable from legitimate economics (only from a misconfigured ask or an
///    adversarial/overflow-saturated `job_cost_sompi`). Clamping down there under-states an
///    already-impossible cost, which is economically fail-safe: the provider claims *less*,
///    never over-claims, and the escrow is always settleable — the exact liveness property
///    M-07 guarantees. Returning `Err` instead would force `SessionRecord::from_outcome` to a
///    fallible signature, rippling to the out-of-scope `main.rs` caller and risking a
///    panic/drop that would harm provider liveness for a guaranteed-garbage value.
pub fn quantize_gross_up(gross: u64) -> u64 {
    let r = gross % WHOLE_SOMPI_GROSS_STEP;
    if r == 0 {
        return gross;
    }
    match gross.checked_add(WHOLE_SOMPI_GROSS_STEP - r) {
        // Normal case: the next multiple of 25 fits in u64.
        Some(up) => up,
        // Top 25-wide band: rounding up would exceed u64::MAX. Clamp DOWN to the largest
        // representable multiple of 25 so the result stays claimable — NEVER u64::MAX, which
        // is not a multiple of 25 and would re-open the SplitMismatch trap.
        None => MAX_WHOLE_SOMPI_GROSS,
    }
}

/// STRICT round-up (audit L-04): the honest `≥ gross` contract — the smallest CLAIMABLE gross
/// (multiple of [`WHOLE_SOMPI_GROSS_STEP`]) that is `≥ gross`, or [`QuoteError::Overflow`] when no
/// such value fits in a `u64` (the top 25-wide band `(MAX_WHOLE_SOMPI_GROSS, u64::MAX]`, where the
/// next multiple of 25 exceeds `u64::MAX`). Unlike the total [`quantize_gross_up`] — which clamps
/// that band DOWN so the settlement-record path stays non-panicking — this variant *rejects* rather
/// than under-report, so it honors the strict round-up contract exactly. Use it wherever a caller
/// needs a value provably `≥ gross` (e.g. a reject-mode quote path): the two agree everywhere in the
/// reachable range and differ only on the physically-unreachable overflow band (`> 6×` the entire
/// 30 B MSK supply), where this one refuses instead of silently clamping.
pub fn checked_quantize_gross_up(gross: u64) -> Result<u64, QuoteError> {
    let r = gross % WHOLE_SOMPI_GROSS_STEP;
    if r == 0 {
        return Ok(gross);
    }
    gross.checked_add(WHOLE_SOMPI_GROSS_STEP - r).ok_or(QuoteError::Overflow)
}

// --- §24.4 standby layer (D6) ------------------------------------------------------------

/// One wake-up canary per day (§24.4) — the relaxed hardware-existence proof a
/// standby device must still answer.
pub const WAKE_CANARY_INTERVAL_MS: u64 = 24 * 60 * 60 * 1000;

/// Consecutive missed wake-up canaries before the controller flags the §20.5
/// device-existence challenge (precondition 4: spoofed hardware must not farm
/// issuance through standby).
pub const CANARY_FAILURE_ESCALATION: u32 = 3;

/// Serving posture of the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderMode {
    /// Taking jobs, GPU powered, normal matching.
    Active,
    /// Hibernating: GPU stopped (~0 power), out of matching, attestation signing
    /// continues, hardware proof relaxed to the daily wake-up canary.
    Standby,
}

/// The standby state machine (§24.4, D6). Enforces the invariants that make
/// standby safe: it drops out of matching but keeps signing and full issuance,
/// and it still answers a daily canary (so spoofed hardware can't hide behind
/// standby to farm the presence reward).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandbyController {
    mode: ProviderMode,
    /// Timestamp (ms) of the last answered wake-up canary — the staleness clock.
    last_wake_canary_ms: u64,
    /// Consecutive missed wake-up canaries.
    consecutive_canary_failures: u32,
}

impl StandbyController {
    /// A freshly-started active provider. `now_ms` seeds the canary clock so an
    /// immediate standby has a full day before its first wake-up canary is due.
    pub fn new_active(now_ms: u64) -> Self {
        Self { mode: ProviderMode::Active, last_wake_canary_ms: now_ms, consecutive_canary_failures: 0 }
    }

    pub fn mode(&self) -> ProviderMode {
        self.mode
    }

    pub fn is_standby(&self) -> bool {
        self.mode == ProviderMode::Standby
    }

    /// Declare standby: stop the GPU, drop out of matching. The canary clock is
    /// seeded from `now_ms` **only on the Active→Standby transition** (the first
    /// wake-up canary is due one day later); re-declaring while already in standby
    /// is a no-op on the clock. This is precondition-4 hardening: a device cannot
    /// dodge a due wake-up canary by toggling standby off and on to reset its
    /// clock, and the missed-canary streak is carried (never reset by a toggle).
    pub fn declare_standby(&mut self, now_ms: u64) {
        if self.mode == ProviderMode::Active {
            self.last_wake_canary_ms = now_ms;
        }
        self.mode = ProviderMode::Standby;
    }

    /// Resume active serving (supply returns instantly on demand recovery, D6).
    /// The missed-canary streak is **not** cleared here — only an actually answered
    /// canary ([`Self::record_wake_canary_success`]) clears it, so a spoofed device
    /// can't launder missed canaries by toggling modes (precondition-4 hardening).
    pub fn resume(&mut self) {
        self.mode = ProviderMode::Active;
    }

    /// Whether the provider is in the matching set / A1 substitution scope.
    /// Standby takes no real jobs, so it is excluded (§24.4).
    pub fn accepts_jobs(&self) -> bool {
        self.mode == ProviderMode::Active
    }

    /// Attestation signing needs no GPU, so it continues in **both** modes
    /// (§24.4) — this is what lets a standby device keep proving key custody.
    pub fn signs_attestations(&self) -> bool {
        true
    }

    /// Issuance (the presence reward) stays **full** in both modes (D7: issuance
    /// = presence, never scaled to fiat/power). Standby does not reduce it.
    pub fn issuance_active(&self) -> bool {
        true
    }

    /// Whether the GPU is drawing power. Standby stops it (~0 power).
    pub fn gpu_powered(&self) -> bool {
        self.mode == ProviderMode::Active
    }

    /// Whether this device counts toward the burn router's `I` denominator and
    /// PSP distribution (§24.7): non-standby, attested, active devices only.
    pub fn counts_toward_active_devices(&self) -> bool {
        self.mode == ProviderMode::Active
    }

    /// Whether a wake-up canary is currently due (standby only, once per day).
    /// An active provider proves existence through real jobs, so this is false.
    pub fn wake_canary_due(&self, now_ms: u64) -> bool {
        self.mode == ProviderMode::Standby && now_ms.saturating_sub(self.last_wake_canary_ms) >= WAKE_CANARY_INTERVAL_MS
    }

    /// Record an answered wake-up canary: reset the clock and the failure count.
    pub fn record_wake_canary_success(&mut self, now_ms: u64) {
        self.last_wake_canary_ms = now_ms;
        self.consecutive_canary_failures = 0;
    }

    /// Record a missed wake-up canary. Returns whether the miss streak has hit
    /// [`CANARY_FAILURE_ESCALATION`] — i.e. the §20.5 device-existence challenge
    /// should now fire (repeated failure ⇒ likely spoofed hardware).
    pub fn record_wake_canary_failure(&mut self) -> bool {
        self.consecutive_canary_failures = self.consecutive_canary_failures.saturating_add(1);
        self.needs_device_existence_challenge()
    }

    /// Consecutive missed wake-up canaries so far.
    pub fn consecutive_canary_failures(&self) -> u32 {
        self.consecutive_canary_failures
    }

    /// Whether the miss streak has reached the escalation threshold (§20.5).
    pub fn needs_device_existence_challenge(&self) -> bool {
        self.consecutive_canary_failures >= CANARY_FAILURE_ESCALATION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- economic guard (D4/D5) ---

    #[test]
    fn energy_and_floor_are_exact_integers() {
        // 50 Wh/1k @ $0.20/kWh = 50_000 mWh × 200_000 µUSD/kWh / 1e6 = 10_000 µUSD/1k = $0.01.
        let f = AskFloor::power_only(50_000, 200_000, 2_000); // 20% margin
        assert_eq!(f.energy_uusd_per_1k(), 10_000);
        // floor = 10_000 × 1.2 = 12_000 µUSD/1k.
        assert_eq!(f.floor_uusd_per_1k(), 12_000);
    }

    #[test]
    fn optional_capex_and_stake_terms_lift_the_floor() {
        let hobbyist = AskFloor::power_only(50_000, 200_000, 0);
        let commercial = AskFloor { capex_uusd_per_1k: 5_000, stake_opp_cost_uusd_per_1k: 3_000, ..hobbyist };
        assert_eq!(hobbyist.floor_uusd_per_1k(), 10_000);
        // (10_000 + 5_000 + 3_000) × 1.0 = 18_000.
        assert_eq!(commercial.floor_uusd_per_1k(), 18_000);
    }

    #[test]
    fn fsl_repricing_to_sompi_rounds_up() {
        // floor 12_000 µUSD/1k; FSL says 1 MSK = 60_000 µUSD ($0.06).
        // sompi = 12_000 × 1e8 / 60_000 = 20_000_000 sompi/1k = 0.2 MSK/1k.
        let f = AskFloor::power_only(50_000, 200_000, 2_000);
        assert_eq!(f.floor_sompi_per_1k(60_000), 20_000_000);
        // A cheaper MSK ($0.03) doubles the sompi floor — cost coverage preserved.
        assert_eq!(f.floor_sompi_per_1k(30_000), 40_000_000);
    }

    #[test]
    fn guard_accepts_at_or_above_floor_rejects_below() {
        let f = AskFloor::power_only(50_000, 200_000, 2_000);
        let floor = f.floor_sompi_per_1k(60_000); // 20_000_000
        assert!(matches!(f.guard(floor, 60_000), GuardDecision::Accept { .. }));
        assert!(matches!(f.guard(floor + 1, 60_000), GuardDecision::Accept { .. }));
        match f.guard(floor - 1, 60_000) {
            GuardDecision::RejectBelowFloor { floor_sompi_per_1k, offered_sompi_per_1k } => {
                assert_eq!(floor_sompi_per_1k, floor);
                assert_eq!(offered_sompi_per_1k, floor - 1);
            }
            other => panic!("expected below-floor reject, got {other:?}"),
        }
    }

    #[test]
    fn guard_fails_closed_when_fsl_rate_absent() {
        let f = AskFloor::power_only(50_000, 200_000, 2_000);
        // Even a huge offer is rejected: no rate ⇒ cost coverage unprovable.
        assert_eq!(f.guard(u64::MAX, 0), GuardDecision::RejectNoRate);
        assert_eq!(f.floor_sompi_per_1k(0), 0);
    }

    // --- (audit m7) whole-sompi pricing guard ---

    #[test]
    fn served_gross_matches_the_contract_formula() {
        // 2 sompi/1k · (30_000 + 20_000)/1000 = 2 · 50 = 100 — the ADR-0037 §2.3 example.
        assert_eq!(served_gross_sompi(2, 30_000, 20_000).unwrap(), 100);
        assert_eq!(checked_gross_sompi(2, 30_000, 20_000).unwrap(), 100); // 100 % 25 == 0
        // overflow is rejected, never wrapped.
        assert_eq!(served_gross_sompi(u64::MAX, u64::MAX, u64::MAX), Err(QuoteError::Overflow));
    }

    #[test]
    fn checked_gross_rejects_non_multiple_of_25_at_the_source() {
        // 2 sompi/1k · 51_000/1000 = 102 ⇒ 102 % 25 = 2 ⇒ permanent SplitMismatch trap.
        assert_eq!(
            checked_gross_sompi(2, 51_000, 0),
            Err(QuoteError::GrossNotWholeSompi { gross: 102, step: 25 })
        );
        assert!(!is_whole_sompi_gross(102));
    }

    #[test]
    fn quantize_snaps_up_to_the_next_whole_sompi_gross() {
        assert_eq!(quantize_gross_up(0), 0);
        assert_eq!(quantize_gross_up(1), 25);
        assert_eq!(quantize_gross_up(100), 100);
        assert_eq!(quantize_gross_up(102), 125);
        // every quantized gross is claimable.
        for g in [0u64, 1, 2, 24, 25, 26, 49, 99, 100, 101, 1_000_003] {
            assert!(is_whole_sompi_gross(quantize_gross_up(g)), "quantized {g} must be claimable");
        }
    }

    #[test]
    fn quantize_gross_up_never_emits_a_non_multiple_on_the_overflow_band() {
        // audit m7 (M-07 fix): the auditor's exact bug — quantize_gross_up(u64::MAX) MUST NOT
        // return u64::MAX (u64::MAX % 25 == 15, a non-multiple that re-opens the permanent
        // claimAnonV2 SplitMismatch trap). On the top 25-wide band it clamps DOWN to the
        // largest representable multiple of 25, never a non-multiple, never a panic.
        assert_eq!(u64::MAX % WHOLE_SOMPI_GROSS_STEP, 15, "the boundary the bug hid in");
        assert_eq!(MAX_WHOLE_SOMPI_GROSS, u64::MAX - 15);
        assert_eq!(MAX_WHOLE_SOMPI_GROSS % WHOLE_SOMPI_GROSS_STEP, 0);

        // (1) u64::MAX — the auditor's reported input — clamps to the largest multiple, not u64::MAX.
        assert_eq!(quantize_gross_up(u64::MAX), MAX_WHOLE_SOMPI_GROSS);
        assert_ne!(quantize_gross_up(u64::MAX), u64::MAX, "must NOT return the non-multiple u64::MAX");
        // (2) u64::MAX - 1 — also in the overflow band — clamps down too.
        assert_eq!(quantize_gross_up(u64::MAX - 1), MAX_WHOLE_SOMPI_GROSS);
        // (3) the exact largest multiple of 25 is returned unchanged (r == 0, no round-up needed).
        assert_eq!(quantize_gross_up(MAX_WHOLE_SOMPI_GROSS), MAX_WHOLE_SOMPI_GROSS);
        // (4) a normal value rounds up to the next multiple as before.
        assert_eq!(quantize_gross_up(102), 125);

        // The core invariant: across the whole top band (and normal values) the result is
        // ALWAYS ≡ 0 (mod 25) — never a non-multiple, never a panic. In the overflow band it
        // is clamped to MAX_WHOLE_SOMPI_GROSS; below it, it is the ceil-to-25 of the input.
        for g in (u64::MAX - 60..=u64::MAX).chain([0u64, 1, 24, 25, 26, 99, 100, 102]) {
            let q = quantize_gross_up(g);
            assert_eq!(q % WHOLE_SOMPI_GROSS_STEP, 0, "quantize_gross_up({g}) = {q} is not a multiple of 25");
            assert!(is_whole_sompi_gross(q));
            if g > MAX_WHOLE_SOMPI_GROSS {
                assert_eq!(q, MAX_WHOLE_SOMPI_GROSS, "overflow-band gross clamps to the largest multiple");
            } else {
                assert!(q >= g && q - g < WHOLE_SOMPI_GROSS_STEP, "below the band, q is ceil_25(g)");
            }
        }
    }

    #[test]
    fn checked_quantize_honors_the_strict_round_up_contract() {
        // audit L-04: the STRICT variant returns the smallest claimable gross ≥ input (the honest
        // `≥` contract quantize_gross_up's name implied) and REJECTS the top overflow band rather
        // than clamping DOWN (which the total quantize_gross_up does to stay non-panicking).
        assert_eq!(checked_quantize_gross_up(0), Ok(0));
        assert_eq!(checked_quantize_gross_up(1), Ok(25));
        assert_eq!(checked_quantize_gross_up(100), Ok(100));
        assert_eq!(checked_quantize_gross_up(102), Ok(125));
        assert_eq!(checked_quantize_gross_up(MAX_WHOLE_SOMPI_GROSS), Ok(MAX_WHOLE_SOMPI_GROSS));
        // the boundary: MAX-1 rounds UP to exactly MAX (still representable).
        assert_eq!(checked_quantize_gross_up(MAX_WHOLE_SOMPI_GROSS - 1), Ok(MAX_WHOLE_SOMPI_GROSS));
        // the overflow band: no multiple of 25 that is ≥ input fits u64 ⇒ Err (NOT the clamp-DOWN
        // that quantize_gross_up returns), so the strict `≥` contract is never violated.
        assert_eq!(checked_quantize_gross_up(MAX_WHOLE_SOMPI_GROSS + 1), Err(QuoteError::Overflow));
        assert_eq!(quantize_gross_up(MAX_WHOLE_SOMPI_GROSS + 1), MAX_WHOLE_SOMPI_GROSS); // total clamps down
        assert_eq!(checked_quantize_gross_up(u64::MAX), Err(QuoteError::Overflow));

        // reachable-range agreement + the honest ≥ contract: strict == total, and result ≥ input.
        for g in [0u64, 1, 2, 24, 25, 26, 99, 100, 101, 1_000_003, MAX_WHOLE_SOMPI_GROSS - 25, MAX_WHOLE_SOMPI_GROSS - 1] {
            let strict = checked_quantize_gross_up(g).expect("reachable range never overflows");
            assert_eq!(strict, quantize_gross_up(g), "strict == total in the reachable range (g={g})");
            assert!(strict >= g && is_whole_sompi_gross(strict), "strict ≥ input and claimable (g={g})");
        }
    }

    #[test]
    fn checked_gross_gate_iff_gross_mod_25_matches_contract_boundary() {
        // cross-check the mod-25 boundary the contract enforces (mirrors shield's
        // whole_sompi_gate_iff_gross_mod_25 / claim_v2_split): accept iff gross % 25 == 0.
        for gross in 0u64..=200 {
            // price = gross, tok_in = 1000, tok_out = 0 ⇒ served gross == gross.
            assert_eq!(served_gross_sompi(gross, 1000, 0).unwrap(), gross);
            assert_eq!(checked_gross_sompi(gross, 1000, 0).is_ok(), gross % 25 == 0, "gross {gross}");
        }
    }

    // --- standby layer (D6) ---

    #[test]
    fn standby_stops_gpu_and_matching_but_keeps_signing_and_issuance() {
        let mut c = StandbyController::new_active(1_000);
        assert!(c.accepts_jobs());
        assert!(c.gpu_powered());
        assert!(c.counts_toward_active_devices());

        c.declare_standby(1_000);
        assert!(c.is_standby());
        assert!(!c.accepts_jobs(), "standby is out of matching / A1 scope");
        assert!(!c.gpu_powered(), "standby stops the GPU (~0 power)");
        assert!(!c.counts_toward_active_devices(), "excluded from I denominator + PSP");
        // The invariants that keep standby safe & non-death-spiral:
        assert!(c.signs_attestations(), "attestation signing continues (no GPU)");
        assert!(c.issuance_active(), "issuance = presence stays full in standby");
    }

    #[test]
    fn wake_canary_is_due_once_per_day_only_in_standby() {
        let mut c = StandbyController::new_active(0);
        // Active providers prove existence via real jobs — never a canary.
        assert!(!c.wake_canary_due(WAKE_CANARY_INTERVAL_MS * 10));

        c.declare_standby(0);
        assert!(!c.wake_canary_due(WAKE_CANARY_INTERVAL_MS - 1), "not yet a day");
        assert!(c.wake_canary_due(WAKE_CANARY_INTERVAL_MS), "one day elapsed");

        c.record_wake_canary_success(WAKE_CANARY_INTERVAL_MS);
        assert!(!c.wake_canary_due(WAKE_CANARY_INTERVAL_MS), "clock reset");
        assert!(c.wake_canary_due(2 * WAKE_CANARY_INTERVAL_MS), "next day due");
    }

    #[test]
    fn repeated_canary_failure_triggers_device_existence_challenge() {
        let mut c = StandbyController::new_active(0);
        c.declare_standby(0);
        assert!(!c.record_wake_canary_failure()); // 1
        assert!(!c.record_wake_canary_failure()); // 2
        assert!(!c.needs_device_existence_challenge());
        assert!(c.record_wake_canary_failure()); // 3 == escalation
        assert!(c.needs_device_existence_challenge());
        assert_eq!(c.consecutive_canary_failures(), CANARY_FAILURE_ESCALATION);

        // A subsequent success clears the streak (the device answered).
        c.record_wake_canary_success(WAKE_CANARY_INTERVAL_MS);
        assert!(!c.needs_device_existence_challenge());
        assert_eq!(c.consecutive_canary_failures(), 0);
    }

    #[test]
    fn resume_returns_to_active_but_carries_the_missed_canary_streak() {
        let mut c = StandbyController::new_active(0);
        c.declare_standby(0);
        c.record_wake_canary_failure();
        c.resume();
        assert_eq!(c.mode(), ProviderMode::Active);
        assert!(c.accepts_jobs());
        // The streak is NOT laundered by the mode toggle (precondition-4): only a
        // real answered canary clears it.
        assert_eq!(c.consecutive_canary_failures(), 1);
        c.record_wake_canary_success(0);
        assert_eq!(c.consecutive_canary_failures(), 0);
    }

    #[test]
    fn re_declaring_standby_cannot_reset_a_due_wake_canary() {
        let mut c = StandbyController::new_active(0);
        c.declare_standby(0);
        // A day passes → a canary is due.
        assert!(c.wake_canary_due(WAKE_CANARY_INTERVAL_MS));
        // Attempt to dodge it by re-declaring standby (while already standby) at the
        // due time — the clock must NOT reseed, so the canary stays due.
        c.declare_standby(WAKE_CANARY_INTERVAL_MS);
        assert!(c.wake_canary_due(WAKE_CANARY_INTERVAL_MS), "re-declare must not reset a due canary");
    }
}
