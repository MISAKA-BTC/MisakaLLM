# PALW Deterministic-Kernel Scope (v0.1)

Scope for the hardest, still-open piece of ADR-0039 PALW: making two independent providers'
inference **byte-identical** so the k=2 exact-match can stand in for a proof. This document draws the
boundary between what is achievable now, what is genuinely out of reach, and how the design's existing
decisions (I-9, integer accumulation, fallback) already contain the problem. It is a *scope*, not an
implementation — most of the hard phases need a real GPU fleet we do not have locally.

Status: **planning**. Nothing here is implemented. Reference: `docs/adr/0039-*.md`,
`docs/design/misaka-palw-replica-gemm-v0.2.md` (§6.4, §7, §27, §33), and the k=2 rail already landed
(`mil/provider/src/palw_replica.rs` mock + `mil/provider/src/qwen_backend.rs` real, feature-gated).

---

## 1. The requirement, stated exactly

PALW replaces a compute *proof* with **replication**: a leaf is minted only when two providers of the
same runtime class return a byte-identical `ReplicaMatchKey` (design §7.5). The eight-field key folds in
`output_commitment` (the answer tokens) and `canonical_gemm_trace_root` (the compute path). So the
determinism requirement is precise and two-sided:

- **No false mismatch** among honest same-class providers. If two honest providers ever disagree by one
  bit, no leaf is minted, the provider pair is unpaid, and — at scale — the compute lane stalls. Target:
  false-mismatch rate ≈ 0.
- **No false match** for wrong compute. If a forger can cheaply produce a matching key without running
  the model, replication buys nothing. Target: any deviation in weights / model / output / kernels
  changes the key.

Exact-match (not a tolerance band) is deliberate: a tolerance band is exactly the crack a forger cheaply
squeezes a "close enough" output through. That choice is what makes determinism *load-bearing* — it is
not a nice-to-have, it is the precondition for the honest rail to function at all.

## 2. What the design already decided (this shrinks the problem a lot)

The design does **not** ask for universal cross-vendor bit-exactness. It scopes determinism down three
ways, and the scope below inherits all three:

- **I-9 — intra-class only.** Exact-match weight is credited **only within one `runtime_class_id`**
  (= tier + `gpu_arch_class` + pinned `runtime_image_hash`/`kernel_graph_hash`). Cross-arch-class
  comparison is audit-only and never enters main DAG work (design §183–185, §27.1). So we need
  determinism *within a pinned class*, not across all hardware.
- **Integer accumulation.** The GEMM trace chain absorbs an `integer_accumulator_checksum` per op
  (§7.3), and the runtime requires "fixed integer/fixed-point quantization profile" (§ line 350).
  Integer reduction is associative and hardware-portable in a way fp is not — it is the design's lever
  for widening a class.
- **Graceful fallback.** If a class cannot achieve determinism, or during beacon degradation, the
  **compute-work multiplier drops toward 0** and the block degrades to the permanent hash floor (§ line
  919, `E = H + min(C, 4H)` with C→0). PALW is *safe* under total determinism failure — it just stops
  delivering compute credit. That bounds the downside but is also the existential risk (see §7).

## 3. State of the art (grounded)

- **Batch-invariance is the root cause and it is solved for same-hardware.** Thinking Machines Lab's
  *Defeating Nondeterminism in LLM Inference* (Horace He et al.) shows temperature-0 nondeterminism comes
  from kernels whose reduction order depends on batch size / sequence chunking, and ships batch-invariant
  RMSNorm / matmul / attention that produce **bit-identical output across 1,000 runs on Qwen3-8B** (~61.5%
  throughput cost; SGLang's CUDA-graph integration cut it to ~34%). Library:
  `thinking-machines-lab/batch-invariant-ops`; a vLLM "deterministic" mode and SGLang deterministic
  inference exist. **Qwen3-8B is exactly the Quality tier (MISAKA-QW9)** — the tooling targets our model.
- **Cross-GPU bit-exact is NOT guaranteed.** Independent work (*Understanding and Mitigating Numerical
  Sources of Nondeterminism in LLM Inference*, arXiv 2506.09501) finds bitwise reproducibility across
  different GPUs (A100 / H100 / L40S / 4090) is not guaranteed: different SKUs use different reduction
  schedules for a given shape, and precision format matters (FP32 ≈ 1.11% vs BF16 ≈ 5.02% accuracy
  variance). Divergence is rare per-token but compounds through autoregressive decoding after the first
  differing token.
- **Net:** *same SKU + batch-invariant kernels + deterministic mode + greedy* → bit-exact, achievable
  today. *Different SKU* → not bit-exact in fp. This maps cleanly onto I-9.

Sources: [Thinking Machines — Defeating Nondeterminism](https://thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/),
[SGLang deterministic inference (LMSYS)](https://www.lmsys.org/blog/2025-09-22-sglang-deterministic/),
[Numerical Sources of Nondeterminism (arXiv 2506.09501)](https://arxiv.org/abs/2506.09501).

## 4. Tractable vs intractable (the boundary)

| Target | Status | How |
|---|---|---|
| Same machine, run-to-run, batch-varying → bit-exact | **Achievable now** | batch-invariant kernels + greedy + deterministic mode |
| Two machines of the **same SKU** + same driver/kernel binary → bit-exact | **Achievable, needs empirical confirmation** | pin the full stack into `runtime_image_hash`/`kernel_graph_hash`; verify with the differential harness (K0) |
| Across **different SKUs** (same vendor) → bit-exact in fp | **Not achievable in general** | out of scope; handled by narrow arch-class + fallback |
| Across **different SKUs** via **integer-only** inference → bit-exact | **Open research** | K6; high-risk, potentially widens a class |
| Across **vendors** (NVIDIA/Apple/AMD) → bit-exact | **Not achievable** | never one class; cross-vendor is audit-only (I-9) |

## 5. The central tension: class granularity vs provider pool

The one decision that dominates everything: **how narrow is a `runtime_class_id`?**

- Narrow (exact SKU + driver + kernel-binary hash): determinism is achievable, but each class's provider
  pool is small — only holders of that exact GPU can k=2-match, and a driver bump forks the class.
- Broad (e.g., "any Ampere"): a large pool, but fp reduction differences break exact-match → false
  mismatches → honest rail stalls.

This is not a code decision; it is an economics/decentralization decision made **empirically** from the
differential harness (K0/K4): register a class only across the SKU set the harness proves bit-exact, and
size the tier/quantum economics (§21.2) to the resulting pool. The scope's job is to build the harness
that turns this into a measurement, not a guess.

## 6. Phased plan

Ordered by dependency; each phase's infra need is flagged. "codeable now" = no GPU required (we can do
it on the current stack); "needs GPU(s)" = requires a real (ideally multi-node, same-SKU) GPU fleet we
do not have locally.

- **K0 — Differential determinism harness.** *Codeable now (fleet to run).* A rig that runs the SAME
  job (job-set, prompt, salt, challenge) on N provider instances and asserts byte-identical
  `DeterministicInferenceOutputV1`; reports first-divergence op + token; sweeps (batch size, sequence
  chunking, SKU, driver, kernel version). This is the measurement primitive the class-granularity
  decision (§5) depends on, and the CI gate for every later phase. Build against the existing
  `VerifiableInferenceBackend` contract; extend the current sync `run_verifiable`→`ReplicaMatchKey` to
  the design's async `infer_with_trace`→`DeterministicInferenceOutputV1`.
- **K1 — Single-node batch-invariant backend.** *Needs GPU.* Wrap a batch-invariant deterministic
  runtime (Thinking Machines / SGLang deterministic mode, or the candle path with batch-invariant ops)
  behind the trait so ONE machine is bit-identical across runs and batch sizes. Verify with K0 (single
  node). Pin the exact runtime image + kernel graph into the profile hashes.
- **K2 — Intra-SKU cross-machine determinism.** *Needs ≥2 GPUs of the same SKU.* Prove two *different*
  physical machines of the same SKU + pinned stack produce byte-identical output. This is the
  make-or-break empirical result: it establishes whether an achievable class exists at all, and at what
  granularity. Output: the verified SKU set per class.
- **K3 — Real GEMM trace chain + integer accumulator checksums.** *Codeable now (types) / needs GPU
  (instrumentation).* Replace the current output-hash placeholder `canonical_gemm_trace_root` with the
  §7.2/§7.3 canonical-op-ID trace: `t_{i+1} = H(t_i || op_id || input_commit || integer_accumulator_checksum
  || output_commit || selected_expert_ids || overflow_flags)`. Bind "the same compute path ran," not just
  "same answer." The `PalwOperationIdV1` / trace types are pure and codeable now; the kernel
  instrumentation that emits the integer checksums needs the GPU runtime.
- **K4 — Arch-class calibration + registration.** *Needs GPU fleet.* From K0/K2, register one
  `runtime_class_id` per bit-exact-verified SKU set; measure the per-class compute quantum (§21.2 tier
  benchmark) and feed the `min_leaf_bond_sompi` c_saved calibration (already scoped, R3). Decide the MoE
  tie-break + prefill/decode schedule pinning (§ line 2478).
- **K5 — Fallback / degraded wiring.** *Codeable now (consensus).* Make the compute-work multiplier
  provably drop to 0 when a class fails determinism or the beacon degrades (§ line 919). Most of the
  degraded-beacon path exists; this adds the class-level determinism-failure → C→0 path so a bad class
  can never mint compute credit. Consensus-side, gated, testable in-process.
- **K6 — (Research) integer-only inference for wider classes.** *Needs GPU + research.* Full integer
  GEMM/attention with a defined canonical accumulation so a class can span *different* SKUs (even
  vendors). This is the ambitious lever that would fix §5's pool-fragmentation, but it is open research
  with real accuracy/perf risk. Explicitly optional; do not gate activation on it.

**Codeable now, without any GPU:** K0's harness + trait extension, K3's pure trace types, K5's fallback
wiring. Everything that establishes *whether* determinism holds (K1/K2/K4) needs the fleet.

## 7. Risks & honest assessment

- **Existential risk.** Exact-match is load-bearing (§1): if reliable intra-class determinism cannot be
  achieved even at the narrowest granularity, the compute lane's honest rail does not function — it falls
  to the fallback (C→0) and PALW degrades to a hash-floor chain that delivers no compute credit. That is
  *safe* (the design guarantees it) but means the whole audited-compute thesis under-delivers. This risk
  must be resolved by K2 (empirical intra-SKU cross-machine result) **before** any activation
  commitment. Do not re-genesis a PALW net on the assumption that K2 will succeed.
- **Q4 makes it harder.** The tiers ship Q4-quantized (design §317): quantized kernel numerics differ
  across hardware *more* than fp16, so batch-invariance alone may not suffice — this is precisely why the
  design leans on integer accumulation. K1/K2 must test the actual quantized path, not an fp16 proxy.
- **MoE + non-batch-invariant ops.** Qwen MoE routing / expert selection and any remaining
  non-batch-invariant op (some attention variants, flash-attention autotuning) are the likely
  first-divergence sources; K0 must localize them.
- **Fragile pinning.** A driver/library/firmware update can silently break a class's bit-exactness; the
  class hash must pin the full stack, and K0 must run as a continuous gate, not a one-shot.
- **Infra dependency we cannot satisfy locally.** K1–K4 need a real GPU fleet (ideally ≥2 identical-SKU
  nodes). The current build host (.119) is CPU-only Linux; the local Mac is single-node Metal. So the
  determinism *result* cannot be produced here — only the harness, types, and fallback can.

## 8. Recommended first step

Build **K0 (the differential harness) + the trait extension to `infer_with_trace`/
`DeterministicInferenceOutputV1` + K3's pure trace types** now (all codeable without a GPU), so the
moment a same-SKU pair of GPUs is available, K1/K2 become a measurement rather than a build. Treat K2's
intra-SKU cross-machine result as the **go/no-go gate** for the entire audited-compute lane: everything
downstream (class registration, quantum calibration, activation) is contingent on it, and the fallback
(K5) is what keeps the chain safe if it comes back no.
