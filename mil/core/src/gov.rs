//! G1 reproducible-bench harness (design §19.3-G1).
//!
//! The first DAO gate: a public benchmark suite (general / math / code /
//! Japanese + Fin/Code domain sets) run as **verifiable jobs** under the Tier-2
//! deterministic profile (§4.2). Two properties make it a governance primitive:
//!
//! - **Reproducible**: from an epoch VRF seed, [`select_subset`] picks a
//!   question subset and [`perturb_seed`] derives per-question presentation
//!   perturbations deterministically, so anyone re-running the gate gets the
//!   exact same questions — defeating public-benchmark overfit while staying
//!   checkable.
//! - **Anchorable**: a candidate's answers reduce to a single
//!   [`bench_run_commitment`] (a `Hash64` over exact output token-id sequences,
//!   token-ID equality per §4.2, not logits), which `MilGovernance.recordGate`
//!   pins on-chain as the G1 verdict evidence.
//!
//! This crate defines the deterministic protocol and grading; the actual model
//! inference is run by the provider backend and fed back in.

use crate::domains::{MIL_BENCH_RESULT_DOMAIN, MIL_BENCH_RUN_DOMAIN, MIL_BENCH_SELECT_DOMAIN};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{Hash64, blake2b_512_keyed};

/// The evaluation axes a G1 suite spans (§19.3-G1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum BenchAxis {
    General,
    Math,
    Code,
    Japanese,
    Fin,
    CodeDomain,
}

/// One benchmark item.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BenchQuestion {
    /// Stable id used in the result hash (so selection order never matters).
    pub id: u64,
    pub axis: BenchAxis,
    pub prompt: String,
    /// The reference greedy output token-id sequence (§4.2 token-ID equality).
    pub reference_token_ids: Vec<u32>,
}

/// A fixed, public G1 suite.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BenchSuite {
    pub questions: Vec<BenchQuestion>,
}

/// A deterministic hash-stream PRNG seeded from a VRF beacon. Not
/// cryptographically strong on its own — its only job is a *reproducible*,
/// pre-image-unpredictable selection order derived from the on-chain VRF seed.
struct SeedStream {
    state: Hash64,
    counter: u64,
}

impl SeedStream {
    fn new(domain: &[u8], seed: &[u8]) -> Self {
        Self { state: blake2b_512_keyed(domain, seed), counter: 0 }
    }

    /// Next 64-bit draw.
    fn next_u64(&mut self) -> u64 {
        let mut preimage = Vec::with_capacity(72);
        preimage.extend_from_slice(self.state.as_byte_slice());
        preimage.extend_from_slice(&self.counter.to_le_bytes());
        let block = blake2b_512_keyed(MIL_BENCH_SELECT_DOMAIN, &preimage);
        self.counter += 1;
        let words = block.to_le_u64();
        words[0]
    }
}

/// Deterministically select `k` distinct question indices from `[0, n_total)`
/// using a partial Fisher–Yates driven by the VRF `seed`. Same (n, k, seed)
/// always yields the same set + order — the reproducibility core. `k` is
/// clamped to `n_total`.
pub fn select_subset(n_total: usize, k: usize, seed: &[u8]) -> Vec<usize> {
    let k = k.min(n_total);
    let mut pool: Vec<usize> = (0..n_total).collect();
    let mut stream = SeedStream::new(MIL_BENCH_SELECT_DOMAIN, seed);
    let mut out = Vec::with_capacity(k);
    for i in 0..k {
        let remaining = n_total - i;
        let j = i + (stream.next_u64() as usize) % remaining;
        pool.swap(i, j);
        out.push(pool[i]);
    }
    out
}

/// A deterministic per-question presentation-perturbation seed (§19.3-G1: guard
/// against overfit by varying phrasing). The harness that renders a prompt uses
/// this to pick a fixed, reproducible surface variation; here we expose the
/// seed so rendering stays outside the consensus-relevant core.
pub fn perturb_seed(vrf_seed: &[u8], question_id: u64) -> Hash64 {
    let mut preimage = Vec::with_capacity(vrf_seed.len() + 8);
    preimage.extend_from_slice(vrf_seed);
    preimage.extend_from_slice(&question_id.to_le_bytes());
    blake2b_512_keyed(MIL_BENCH_SELECT_DOMAIN, &preimage)
}

/// One graded answer: the candidate's greedy output token ids for a question.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BenchAnswer {
    pub question_id: u64,
    pub output_token_ids: Vec<u32>,
}

impl BenchAnswer {
    /// `Hash64_k("misaka-mil-v1/bench/result" ‖ question_id ‖ token_ids)`.
    pub fn result_hash(&self) -> Hash64 {
        let mut preimage = Vec::with_capacity(8 + self.output_token_ids.len() * 4);
        preimage.extend_from_slice(&self.question_id.to_le_bytes());
        for t in &self.output_token_ids {
            preimage.extend_from_slice(&t.to_le_bytes());
        }
        blake2b_512_keyed(MIL_BENCH_RESULT_DOMAIN, &preimage)
    }
}

/// The outcome of grading a candidate on a selected subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchScore {
    /// Per-axis (passed, total) counts. Passed = exact token-id match (§4.2).
    pub per_axis: Vec<(BenchAxis, u32, u32)>,
    pub passed: u32,
    pub total: u32,
    /// The reproducible run commitment anchored on-chain (§19.3-G1).
    pub run_commitment: Hash64,
}

impl BenchScore {
    /// Pass rate in parts-per-million (0 if no questions were graded).
    pub fn pass_ppm(&self) -> u32 {
        if self.total == 0 { 0 } else { ((self.passed as u64) * 1_000_000 / self.total as u64) as u32 }
    }
}

/// The single on-chain-anchorable G1 commitment over an ordered result set:
/// `Hash64_k("misaka-mil-v1/bench/run" ‖ Σ result_hash)`. Order-independent
/// content but order-sensitive transcript: the caller passes results in the
/// selection order, so re-running with the same seed reproduces it exactly.
pub fn bench_run_commitment(answers: &[BenchAnswer]) -> Hash64 {
    let mut preimage = Vec::with_capacity(answers.len() * 64);
    for a in answers {
        preimage.extend_from_slice(a.result_hash().as_byte_slice());
    }
    blake2b_512_keyed(MIL_BENCH_RUN_DOMAIN, &preimage)
}

/// Grade `answers` against `suite` on the VRF-selected `subset` (indices into
/// `suite.questions`). A question passes iff the candidate's token ids exactly
/// match the reference (§4.2). Answers must be provided for every selected
/// question, keyed by id; a missing/mismatched answer counts as a fail.
pub fn grade(suite: &BenchSuite, subset: &[usize], answers: &[BenchAnswer]) -> BenchScore {
    use std::collections::HashMap;
    let answer_by_id: HashMap<u64, &BenchAnswer> = answers.iter().map(|a| (a.question_id, a)).collect();
    let mut axis_counts: Vec<(BenchAxis, u32, u32)> = Vec::new();
    let mut ordered_answers: Vec<BenchAnswer> = Vec::with_capacity(subset.len());
    let mut passed = 0u32;

    for &idx in subset {
        let q = &suite.questions[idx];
        let ok = answer_by_id.get(&q.id).is_some_and(|a| a.output_token_ids == q.reference_token_ids);
        if ok {
            passed += 1;
        }
        // record the answer (or an empty one) into the ordered transcript
        let ans =
            answer_by_id.get(&q.id).map(|a| (*a).clone()).unwrap_or(BenchAnswer { question_id: q.id, output_token_ids: Vec::new() });
        ordered_answers.push(ans);

        match axis_counts.iter_mut().find(|(ax, _, _)| *ax == q.axis) {
            Some(entry) => {
                entry.2 += 1;
                if ok {
                    entry.1 += 1;
                }
            }
            None => axis_counts.push((q.axis, ok as u32, 1)),
        }
    }

    BenchScore { per_axis: axis_counts, passed, total: subset.len() as u32, run_commitment: bench_run_commitment(&ordered_answers) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suite(n: usize) -> BenchSuite {
        let axes = [BenchAxis::General, BenchAxis::Math, BenchAxis::Code, BenchAxis::Japanese, BenchAxis::Fin];
        BenchSuite {
            questions: (0..n)
                .map(|i| BenchQuestion {
                    id: i as u64,
                    axis: axes[i % axes.len()],
                    prompt: format!("question {i}"),
                    reference_token_ids: vec![i as u32, (i as u32) + 1, (i as u32) + 2],
                })
                .collect(),
        }
    }

    #[test]
    fn subset_selection_is_deterministic_and_distinct() {
        let a = select_subset(100, 10, b"vrf-seed-epoch-42");
        let b = select_subset(100, 10, b"vrf-seed-epoch-42");
        assert_eq!(a, b, "same seed reproduces the subset");
        let c = select_subset(100, 10, b"vrf-seed-epoch-43");
        assert_ne!(a, c, "a different seed selects differently");
        // distinct indices, all in range
        let mut sorted = a.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 10, "selected indices are distinct");
        assert!(a.iter().all(|&i| i < 100));
        // k clamps to n
        assert_eq!(select_subset(5, 10, b"x").len(), 5);
    }

    #[test]
    fn grading_matches_reference_and_commitment_is_reproducible() {
        let s = suite(50);
        let seed = b"vrf-seed-1";
        let subset = select_subset(s.questions.len(), 12, seed);

        // a perfect candidate: exact reference token ids for every selected question
        let perfect: Vec<BenchAnswer> = subset
            .iter()
            .map(|&idx| BenchAnswer {
                question_id: s.questions[idx].id,
                output_token_ids: s.questions[idx].reference_token_ids.clone(),
            })
            .collect();
        let score = grade(&s, &subset, &perfect);
        assert_eq!(score.passed, score.total);
        assert_eq!(score.pass_ppm(), 1_000_000);

        // re-grading the same answers reproduces the commitment
        let score2 = grade(&s, &subset, &perfect);
        assert_eq!(score.run_commitment, score2.run_commitment);

        // one wrong answer drops the pass count and changes the commitment
        let mut flawed = perfect.clone();
        flawed[0].output_token_ids[0] ^= 1;
        let score3 = grade(&s, &subset, &flawed);
        assert_eq!(score3.passed, score.total - 1);
        assert_ne!(score3.run_commitment, score.run_commitment);

        // a missing answer counts as a fail (empty transcript entry)
        let missing: Vec<BenchAnswer> = perfect[1..].to_vec();
        let score4 = grade(&s, &subset, &missing);
        assert_eq!(score4.passed, score.total - 1);
    }

    #[test]
    fn perturb_seed_is_deterministic_per_question() {
        assert_eq!(perturb_seed(b"seed", 7), perturb_seed(b"seed", 7));
        assert_ne!(perturb_seed(b"seed", 7), perturb_seed(b"seed", 8));
        assert_ne!(perturb_seed(b"seed", 7), perturb_seed(b"other", 7));
    }
}
