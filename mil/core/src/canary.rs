//! Canary jobs (design §4.3).
//!
//! Each compute epoch, the protocol derives — from that epoch's VRF seed —
//! prompts to send to pseudo-randomly chosen providers, **indistinguishable
//! from a normal job** (same channel, same job shape). Because the seed is
//! unpredictable before the epoch, a provider cannot tell a canary from a paid
//! job, so "answer only canaries" farming does not work. The observed result
//! feeds the epoch weight inputs (`u` = response rate, `q` = quality) in
//! [`crate::params`].
//!
//! Tier 1 canaries measure attestation validity + latency; Tier 2 canaries
//! additionally replicate the output against a reference (token-id equality,
//! §4.2) — the same grading [`crate::gov::grade`] uses.
//!
//! This module is the deterministic protocol (which provider, which prompt,
//! how to score); dispatching over the data plane is the prober's job (the
//! sidecar / a keeper), and it is byte-identical to a normal request.

use crate::domains::{MIL_CANARY_PROMPT_DOMAIN, MIL_CANARY_SELECT_DOMAIN};
use kaspa_hashes::{Hash64, blake2b_512_keyed};

/// A deterministic hash-stream over a VRF seed (same construction as
/// [`crate::gov`]). Reproducible + pre-image-unpredictable selection.
struct SeedStream {
    state: Hash64,
    counter: u64,
}

impl SeedStream {
    fn new(seed: &[u8]) -> Self {
        Self { state: blake2b_512_keyed(MIL_CANARY_SELECT_DOMAIN, seed), counter: 0 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut preimage = Vec::with_capacity(72);
        preimage.extend_from_slice(self.state.as_byte_slice());
        preimage.extend_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        blake2b_512_keyed(MIL_CANARY_SELECT_DOMAIN, &preimage).to_le_u64()[0]
    }
}

/// Deterministically choose which of `n_providers` receive a canary this epoch,
/// approximately `probe_rate_ppm` fraction of them, from the VRF `seed`. Same
/// (n, rate, seed) → same set. A provider cannot predict its own selection
/// before the seed is revealed.
pub fn select_probed_providers(n_providers: usize, probe_rate_ppm: u32, seed: &[u8]) -> Vec<usize> {
    if n_providers == 0 {
        return Vec::new();
    }
    let mut stream = SeedStream::new(seed);
    (0..n_providers).filter(|_| (stream.next_u64() % 1_000_000) < probe_rate_ppm as u64).collect()
}

/// A single canary job derived from the epoch seed + a per-provider index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryJob {
    /// The canary prompt bytes (looks like any other prompt on the wire).
    pub prompt: Vec<u8>,
    /// The provider index this canary targets.
    pub provider_index: usize,
    /// For Tier-2 canaries: the expected greedy output token-id sequence to
    /// replicate against (`None` for Tier-1, which only checks attestation +
    /// latency). The reference is computed off-line from the pinned model at
    /// canary-set publication time.
    pub reference_token_ids: Option<Vec<u32>>,
}

/// A bank of fixed canary prompt templates. The concrete prompt is one of these
/// selected by the seed, so the on-wire distribution matches real traffic
/// shape while the selection stays unpredictable. Operators can extend the bank
/// (governance) without changing the protocol.
pub const DEFAULT_CANARY_TEMPLATES: &[&str] = &[
    "Summarize the following in one sentence: the quick brown fox jumps over the lazy dog.",
    "What is 17 multiplied by 23? Answer with the number only.",
    "Translate to formal English: おはようございます。",
    "List three prime numbers greater than 50.",
    "Complete the function signature: fn add(a: i32, b: i32) -> ",
    "Explain what a hash function is in two sentences.",
];

/// Derive the canary job for `provider_index` from the epoch `seed`.
/// `reference_token_ids` is supplied by the caller for Tier-2 (from the pinned
/// model); pass `None` for Tier-1.
pub fn derive_canary(seed: &[u8], provider_index: usize, reference_token_ids: Option<Vec<u32>>) -> CanaryJob {
    let mut preimage = Vec::with_capacity(seed.len() + 8);
    preimage.extend_from_slice(seed);
    preimage.extend_from_slice(&(provider_index as u64).to_le_bytes());
    let pick = blake2b_512_keyed(MIL_CANARY_PROMPT_DOMAIN, &preimage).to_le_u64()[0];
    let template = DEFAULT_CANARY_TEMPLATES[(pick as usize) % DEFAULT_CANARY_TEMPLATES.len()];
    CanaryJob { prompt: template.as_bytes().to_vec(), provider_index, reference_token_ids }
}

/// The outcome the prober records for one canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryOutcome {
    /// The provider answered within the SLA.
    pub answered_in_sla: bool,
    /// Tier-1: attestation verified; Tier-2: output matched the reference.
    pub verified: bool,
    /// Observed latency to first token, milliseconds.
    pub ttft_ms: u32,
}

/// Rolling per-provider canary tally over an epoch, reduced to the `u` (uptime)
/// and `q` (quality) weight inputs (§5.4), both parts-per-million.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CanaryTally {
    pub sent: u32,
    pub answered: u32,
    pub verified: u32,
}

impl CanaryTally {
    pub fn record(&mut self, outcome: CanaryOutcome) {
        self.sent += 1;
        if outcome.answered_in_sla {
            self.answered += 1;
        }
        if outcome.verified {
            self.verified += 1;
        }
    }

    /// `u` — canary response rate, ppm.
    pub fn uptime_ppm(&self) -> u32 {
        if self.sent == 0 { 0 } else { ((self.answered as u64) * 1_000_000 / self.sent as u64) as u32 }
    }

    /// `q` — verified-answer rate, ppm (quality proxy from canaries).
    pub fn quality_ppm(&self) -> u32 {
        if self.sent == 0 { 0 } else { ((self.verified as u64) * 1_000_000 / self.sent as u64) as u32 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_is_deterministic_unpredictable_and_rate_bounded() {
        let a = select_probed_providers(1000, 100_000, b"epoch-seed-7"); // ~10%
        let b = select_probed_providers(1000, 100_000, b"epoch-seed-7");
        assert_eq!(a, b, "same seed reproduces the probe set");
        let c = select_probed_providers(1000, 100_000, b"epoch-seed-8");
        assert_ne!(a, c, "a different seed probes differently (unpredictable)");
        // roughly the requested rate (10% of 1000 ≈ 100, allow wide band)
        assert!((30..300).contains(&a.len()), "probe count {} near 10%", a.len());
        assert!(a.iter().all(|&i| i < 1000));
        assert!(select_probed_providers(0, 100_000, b"x").is_empty());
    }

    #[test]
    fn canary_is_deterministic_and_from_the_template_bank() {
        let j1 = derive_canary(b"seed", 3, None);
        let j2 = derive_canary(b"seed", 3, None);
        assert_eq!(j1, j2);
        assert!(DEFAULT_CANARY_TEMPLATES.iter().any(|t| t.as_bytes() == j1.prompt.as_slice()));
        // different provider index → (usually) different prompt selection
        let j3 = derive_canary(b"seed", 4, None);
        assert_eq!(j3.provider_index, 4);
        // tier-2 carries a reference
        let j4 = derive_canary(b"seed", 3, Some(vec![1, 2, 3]));
        assert_eq!(j4.reference_token_ids, Some(vec![1, 2, 3]));
    }

    #[test]
    fn tally_reduces_to_uptime_and_quality() {
        let mut t = CanaryTally::default();
        t.record(CanaryOutcome { answered_in_sla: true, verified: true, ttft_ms: 500 });
        t.record(CanaryOutcome { answered_in_sla: true, verified: false, ttft_ms: 600 });
        t.record(CanaryOutcome { answered_in_sla: false, verified: false, ttft_ms: 0 });
        assert_eq!(t.sent, 3);
        assert_eq!(t.uptime_ppm(), 666_666); // 2/3
        assert_eq!(t.quality_ppm(), 333_333); // 1/3
        assert_eq!(CanaryTally::default().uptime_ppm(), 0);
    }
}
