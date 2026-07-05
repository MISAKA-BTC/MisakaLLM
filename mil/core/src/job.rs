//! Job specification (design §7.4) and the tier policy.
//!
//! Wire encoding is borsh; sampling knobs are fixed-point integers (milli
//! units) — never floats — so the Tier-2 deterministic replication check
//! (§4.2) compares bit-identical job inputs across verifiers.

use crate::domains::MIL_PROTOCOL_VERSION;
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash64;

/// Provider tier (§3.2 / §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Tier {
    /// Tier 1: TEE-confidential — plaintext exists only in the requester
    /// client and the enclave; receipts carry attestation-backed integrity.
    Tee,
    /// Tier 2: provider-visible — same PQ channel on the wire, but the
    /// provider sees plaintext (UI must disclose), verified by optimistic
    /// replication under the deterministic profile.
    Open,
}

/// Sampling parameters, fixed-point (`milli` = value × 1000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SamplingParams {
    /// Temperature × 1000 (0 = greedy).
    pub temperature_milli: u16,
    /// top-p × 1000 (1000 = disabled).
    pub top_p_milli: u16,
    /// Optional sampling seed (ignored under greedy).
    pub seed: Option<u64>,
}

impl SamplingParams {
    /// The Tier-2 deterministic profile: greedy decode (§4.2).
    pub const fn greedy() -> Self {
        Self { temperature_milli: 0, top_p_milli: 1000, seed: None }
    }

    pub fn is_greedy(&self) -> bool {
        self.temperature_milli == 0
    }
}

/// SLA floor advertised by the provider and demanded by the job (§6.2, §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SlaParams {
    /// Max time-to-first-byte in milliseconds.
    pub ttfb_ms: u32,
    /// Minimum decode speed, tokens/second.
    pub min_tps: u32,
}

/// One inference job (§7.4). `cm_req` is the salted commitment to the prompt
/// ciphertext — the only content-derived value that ever leaves the channel.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct JobSpec {
    pub version: u16,
    pub model_id: Hash64,
    /// Optional Agent Profile (§18.2); composed client-side, informational to
    /// the provider.
    pub profile_id: Option<Hash64>,
    pub tier: Tier,
    pub max_tokens: u32,
    pub sampling: SamplingParams,
    pub sla: SlaParams,
    /// Requester's price ceiling for the whole job, sompi.
    pub price_cap_sompi: u64,
    /// Request commitment (§3.3).
    pub cm_req: Hash64,
}

impl JobSpec {
    pub fn new(
        model_id: Hash64,
        tier: Tier,
        max_tokens: u32,
        sampling: SamplingParams,
        sla: SlaParams,
        price_cap_sompi: u64,
        cm_req: Hash64,
    ) -> Self {
        Self { version: MIL_PROTOCOL_VERSION, model_id, profile_id: None, tier, max_tokens, sampling, sla, price_cap_sompi, cm_req }
            .enforce_tier_policy()
    }

    /// Apply the tier policy (§7.4): Tier 2 force-overrides sampling to the
    /// deterministic greedy profile, no matter what the requester asked for —
    /// replication verification is only sound over deterministic decode.
    pub fn enforce_tier_policy(mut self) -> Self {
        if self.tier == Tier::Open {
            self.sampling = SamplingParams::greedy();
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier2_sampling_is_force_overridden() {
        let spicy = SamplingParams { temperature_milli: 900, top_p_milli: 950, seed: Some(42) };
        let sla = SlaParams { ttfb_ms: 1500, min_tps: 40 };
        let open = JobSpec::new(Hash64::from_bytes([1u8; 64]), Tier::Open, 1024, spicy, sla, 10_000, Hash64::from_bytes([2u8; 64]));
        assert_eq!(open.sampling, SamplingParams::greedy(), "Tier2 must decode greedily (§4.2)");

        let tee = JobSpec::new(Hash64::from_bytes([1u8; 64]), Tier::Tee, 1024, spicy, sla, 10_000, Hash64::from_bytes([2u8; 64]));
        assert_eq!(tee.sampling, spicy, "Tier1 keeps requested sampling (TEE integrity needs no determinism)");
    }

    #[test]
    fn jobspec_borsh_roundtrip() {
        let job = JobSpec::new(
            Hash64::from_bytes([1u8; 64]),
            Tier::Open,
            2048,
            SamplingParams::greedy(),
            SlaParams { ttfb_ms: 800, min_tps: 40 },
            123_456,
            Hash64::from_bytes([2u8; 64]),
        );
        let back = JobSpec::try_from_slice(&borsh::to_vec(&job).unwrap()).unwrap();
        assert_eq!(job, back);
    }
}
