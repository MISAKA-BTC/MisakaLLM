# MISAKA Canonical Compute v1 — a decision freeze

Status: **FROZEN (decision record).** This is not a description; it is the set of binding choices that
turn ADR-0039 PALW's determinism class from a *hardware enumeration* into a *verifiable predicate*. Where
a numeric value needs a GPU fleet to bind, the **policy** is frozen here and the value is tagged
`MEASURED-AT-K0` (bound by the first calibration run, not re-litigated). Normative words: **MUST**,
**MUST NOT**, **FROZEN**.

References: `docs/adr/0039-palw-replica-gemm-audited-compute-lane.md`,
`docs/design/misaka-palw-replica-gemm-v0.2.md` (§6.4, §7.2/§7.3, §21.2, §27.1, I-8, I-9),
`docs/design/palw-deterministic-kernel-scope-v0.1.md` (K0–K4). Existing committed carriers this spec
canonicalizes: `PalwOperationIdV1.tile_schedule_id`, the trace step's `integer_accumulator_checksum` and
`overflow_flags`, `operation_schedule_commitment`, and the `batch_invariant`/`deterministic_reduction`
profile flags (`mil/core/src/palw.rs`). **This spec is an increment on those fields, not a new tax.**

## 0. Thesis this freezes

Cross-hardware bit-divergence has exactly two root causes: (1) fp addition is non-associative and the
**reduction order** is machine-chosen (SM count / warp / tile size reshape the reduction tree); (2)
**vendor intrinsics** (transcendentals, fast-math, FMA contraction, FTZ defaults) differ by vendor.
Neither is a law of physics: integer addition is associative (order-independent), and IEEE-754 fp32
basic ops (add/mul/fma, div, sqrt) are correctly-rounded on NVIDIA sm_20+, AMD, and Apple GPUs. Class
explosion is therefore an artifact of **vendor BLAS SKU-specific tile heuristics + driver JIT**, not of
arithmetic. Owning the kernels and **fixing the schedule in the spec** moves the class boundary from
"which hardware" to "which stacks reproduce a committed test vector." That reframing — **class-as-data,
not class-as-code** — is the load-bearing decision of this document.

---

## 1. Scope and the definition of bit-exact

**FROZEN.** Two providers of the same class on the same job mint a leaf iff their eight-field
`ReplicaMatchKey` is byte-identical (design §7.5): `job_set_commitment`, `model_profile_id`,
`runtime_class_id`, `shape_id`, `output_commitment`, `canonical_gemm_trace_root`,
`operation_schedule_commitment`, `quantum_count`. "Bit-exact" in this spec means **all eight match**; it
is never a tolerance band (a band is the crack a forger squeezes a "close-enough" output through — I-9,
scope v0.1 §1). This spec's job is to make the two compute-path fields (`canonical_gemm_trace_root`,
`operation_schedule_commitment`) reproducible across every stack registered to the same class.

## 2. Numeric environment

**FROZEN.**
- **Basis:** fp32 correctly-rounded add/mul/fma/div/sqrt only. No fp16/bf16 accumulation on the trace
  path (storage may be lower precision; **accumulation MUST be fp32** for the fp profiles, integer for
  the integer profile of §15/Level 3).
- **Contraction:** every `a*b+c` MUST be emitted as an explicit `fma()` intrinsic **where the schedule
  specifies fusion**, and as separate `mul` then `add` **where it specifies non-fusion**. Implicit
  compiler contraction is **FORBIDDEN**; `--fmad`, Metal fast-math, and ROCm `-ffast-math` MUST be off.
  Contraction is never left to codegen — this is the single largest cross-vendor leak and it is closed by
  making every fusion site explicit in the kernel source.
- **Environment flags:** round-to-nearest-even; FTZ/denormal handling fixed to **flush-to-zero OFF**
  (denormals preserved) uniformly; no fast-reciprocal / fast-rsqrt intrinsics (see §5/§6 for the software
  replacements).
- **Transcendentals:** vendor `exp`/`rsqrt`/`sin`/`cos` intrinsics are **FORBIDDEN on the trace path**.
  Replaced by fixed software polynomials / manifest tables (§5–§7). *This is pulled forward into Level 1*
  because it also removes intra-backend driver-version drift, not only cross-vendor drift.

## 3. GEMM canonical schedule

**FROZEN policy; tile constants `MEASURED-AT-K0`.**
- The schedule is a **pure function of (op-type, shape_id)**, never of SM count, batch size, or runtime
  dispatch. `tile_schedule_id` (already in `PalwOperationIdV1`) selects one entry of a **spec-side tile
  table** (M/N/K tile dims + split-K factor) that MUST NOT depend on the device.
- **Reduction tree:** intra-tile reduction order and inter-tile / split-K combination order are fixed by
  the spec (a fixed binary reduction tree keyed on the fixed split-K factor). SM-count independence of the
  reduction order is the property that lets a single source collapse Ampere…Blackwell into one class.
- Kernels are compiled from one source per backend, arch-specialized to SASS/ISA **without** changing the
  schedule (arch specialization is layout/occupancy only, never reduction order).
- **Calibration:** K0 sweeps (batch size, sequence chunking, SKU, driver, kernel version) MUST show
  byte-identical `canonical_gemm_trace_root` across the SKU set claimed for a class before that class's
  vector set is committed (§13). The tile constants are whatever K0 proves collapse the widest SKU set.

## 4. Q4 dequantization and integer dot

**FROZEN.**
- Per block: int8 (or int4-packed→int8) dot products accumulate into **int32**; the block scale is applied
  as an fp32 multiply **after** the int32 dot (position fixed: `fp32(int32_dot) * fp32(scale)`), never
  interleaved.
- **Cross-block accumulation order is fixed** (ascending block index, fixed binary tree). This is the last
  place llama.cpp-family kernels retain order dependence; the spec fixes it so the free variable is gone.
- Block layout / group size is pinned by `model_profile_id` (quantization manifest hash); this spec fixes
  only the *arithmetic order*, not the quantization.

## 5. Attention

**FROZEN.**
- **Scores:** `QK^T` scaled by a spec-fixed `1/sqrt(head_dim)` constant (precomputed fp32, not a runtime
  `rsqrt`); mask applied as an additive spec-fixed sentinel before softmax.
- **Softmax:** max-subtraction MUST use the per-row max computed in a fixed reduction order; `exp` = a
  fixed minimax polynomial (fp profile) **or** a manifest-supplied LUT with fixed interpolation (both
  profiles); normalization divides by the sum accumulated in a fixed order.
- **`·V` accumulation:** fp profile — fixed reduction order over the sequence. Integer profile — see §10:
  either an **int64 accumulator** or spec-fixed **hierarchical requantization boundaries** (the sequence
  is partitioned at fixed positions so no int32 sum exceeds budget). The boundary lives in the spec, so
  determinism is preserved regardless of context length.

## 6. RMSNorm, SwiGLU

**FROZEN.**
- **RMSNorm:** sum-of-squares in a fixed reduction order; `rsqrt` via a **fixed number of Newton–Raphson
  iterations** from a spec-fixed seed (no vendor `rsqrt`); `ε` added at a spec-fixed position
  (`sqrt(mean + ε)` vs `sqrt(mean) + ε` is FROZEN to the former, `1/sqrt(mean_sq + ε)`).
- **SwiGLU:** the gate activation uses the same §2 basic ops + §5 `exp`/sigmoid policy; elementwise, so
  order-trivial, but the intermediate precision (fp32) is FROZEN.

## 7. RoPE

**FROZEN.** Rotary sin/cos are **never** computed with vendor `sin`/`cos` on the trace path. The manifest
carries a **precomputed table** (per position × dimension pair, fp32) whose generation procedure is
spec-fixed (a reference table generator run once, committed by hash into the quantization/runtime
manifest). Providers read the table; they do not regenerate it. This removes transcendental divergence
from position encoding entirely.

## 8. Sampling

**FROZEN.** Greedy only (matches the profile `sampling.greedy` flag; temperature path out of scope for
v1). Argmax over logits; **tie-break = smallest token id** (deterministic, spec-fixed — closes the
logits-tie nondeterminism). Logits are read out as fp32 in a spec-fixed memory order before argmax.

## 9. Scheduler and batch-invariance

**FROZEN.** This section makes the `batch_invariant` flag *mean* something concrete — without it Level 1
does not hold.
- **Shape table:** a fixed table of admissible `(seq_len, batch, chunk)` shapes keyed by `shape_id`;
  requests are bucketed to a table entry, never run at an ad-hoc shape.
- **Prefill chunk boundary:** chunked-prefill boundaries are **spec-fixed** (not chosen by a runtime
  memory heuristic) so the reduction structure of a long prefill is identical regardless of how the
  runtime would have batched it.
- **Batch-invariance:** a token's output MUST NOT depend on which other requests share its batch. Kernels
  MUST use batch-invariant reductions (per-request reduction trees independent of batch size); continuous
  batching MUST NOT alter any committed reduction.
- **KV-cache:** layout and (if any) KV quantization granularity are **spec-fixed**; a KV read MUST return
  bit-identical values regardless of cache occupancy or eviction history within the fixed shape.

## 10. Overflow budget (R4 freeze — proof obligation moved into the spec)

**FROZEN.** The integer profile's determinism depends on no int32 accumulator silently wrapping in an
order-dependent way. The spec carries an **op-type × max-shape overflow budget table**; `overflow_flags`
(already in the trace step) is the **fail-closed backstop** (any budget breach diverges the trace, it is
never a silent wrap). Representative frozen entries (worst-case magnitudes; int32 headroom = 2³¹ ≈ 2.1e9):

| Op | Worst-case accumulator | Fits int32? | Rule |
|----|------------------------|-------------|------|
| `QK^T` (head_dim ≤ 128) | 128·127² ≈ 2.1e6 | yes | int32, no split |
| RMSNorm Σx² (d_model ≤ 4096) | 4096·127² ≈ 6.6e7 | yes | int32, fixed order |
| softmax·V (seq up to 32k) | ≈ 1e11 | **NO** | **int64 accumulator OR hierarchical requant at spec-fixed 128-position boundaries** |

The rule for any op not listed: if worst-case at its max admissible shape (§9 shape table) exceeds int32
headroom, it MUST use an int64 accumulator or spec-fixed hierarchical-requant boundaries; **saturation is
FORBIDDEN** (order-dependent). Overflow budgets are part of the frozen spec, not a runtime decision.

## 11. Conformance vectors

**FROZEN format; content `MEASURED-AT-K0`.** A conformance vector set `V_i` is the committed golden
input/output set that *defines* a class (§13). Requirements:
- **Coverage:** every op-type × boundary value (min/max shape from §9, block boundaries from §4, chunk
  boundaries from §9, overflow-budget edges from §10, and at least the trace-committing ops of §3–§8).
- **Form:** each vector is `(execution_challenge inputs, expected DeterministicInferenceOutputV1)` with
  all eight match fields, reproducible by `mil/provider` K0 (§16). Generated once by a reference stack,
  reviewed, then committed by hash.
- A stack "is in class `V_i`" iff it reproduces `V_i` **byte-exact**. This is a decidable predicate, not a
  hardware label.

## 12. (Non-normative) intrinsic correspondence

Guidance, not a freeze: the CUDA / Metal / ROCm intrinsic map for the §2 explicit-`fma`, §5–§7 software
transcendental, and §4/§10 integer-dot primitives. Maintained per backend; each entry is validated by the
§11 vectors, so an incorrect mapping fails registration rather than silently diverging.

---

## 13. Class-as-data: multi-set concurrency (R3 freeze — kills the OS-JIT cliff)

**FROZEN.** `conformance_vector_set_id` is designed **multi-set from day one** (it is the successor to
`gpu_arch_class` equality as the pairing key).
- **Class predicate:** a provider is in class `V_i` iff it reproduces committed vector set `V_i` (§11).
  **Pairing condition = same set id.** (`runtime_class_id` remains, but its arch-class component is
  subsumed by / cross-checked against the reproduced set id.)
- **Drift = fail-closed AND a candidate signal.** An OS/driver/toolchain update that changes codegen
  produces a **mismatch against the provider's current set → registration refused** (existing policy,
  unchanged). Simultaneously it is a **candidate for a new set**: K0 is reused as a *promotion pipeline* —
  run the updated stack, generate a candidate set, commit it, resume registration under the new set.
- **Rolling migration:** old and new sets **coexist** during a migration window; a codegen cliff becomes a
  rolling migration instead of a mass de-registration. Providers on the old set keep pairing until the old
  set is deprecated.
- **Deprecation is non-retroactive** (isomorphic to revocation): a set is retired by an
  `effective_daa_score` after which only *new* registrations under it are refused; already-active
  providers and already-minted leaves are untouched.
- **Class addition is a data commit, not a hard fork.** Adding/retiring a class is a governed commit of a
  vector-set record; no consensus binary change. *This — class-as-data — is the real payoff of the whole
  design.*
- **Activation gate — auditor capacity per set.** A set `V_i` MUST NOT advance to `Certified`/active
  unless the bit-exact-reproducing **auditor capacity ≥ threshold** for that set (canary verifiability
  becomes a per-class precondition — an audit rail that cannot reproduce a set cannot certify it). The
  liveness-shock SLA is defined by **candidate-set qualification time**, minimized by automating the K0
  promotion pipeline.

## 14. Registration and the conformance gate ((A) amendments)

**FROZEN.**
- **Startup self-conformance:** a provider MUST self-run its class's `V_i` at startup and **refuse to
  register on any mismatch** (an extension of the existing speculative-decode / determinism check).
- **Periodic re-conformance:** the gate MUST **also re-run on driver/OS fingerprint change and on a fixed
  period** — an in-flight driver update otherwise slips past a startup-only gate and silently breaks
  fail-closed. This closes that hole.
- **Fingerprint telemetry:** a driver/OS/toolchain fingerprint is attached to the registration record as
  **off-consensus telemetry** (never a consensus input) purely to diagnose set-split events and drive the
  §13 promotion pipeline.

## 15. Level roadmap (recalibrated to the review)

- **Level 1 — policy + schedule constraint. Fleet-gated, months, not research.** Own kernels already
  exist (llama.cpp-family MMQ). The work is *constraining* arch/batch-dependent tile heuristics to the
  §3 fixed schedule and **killing runtime dispatch** — reducing schedule freedom, not writing GEMMs from
  scratch. Plus §2 transcendental software-ization (helps intra-backend too). Result target:
  `{CUDA-unified, Metal-unified} × {QW4, QW9} ≈ 4 classes`. K0 is reframed from "measure how many classes"
  to "verify this unification holds."
- **Level 2 — cross-vendor fp = CONDITIONAL STANDBY (not R&D, not a milestone).** Trigger requires **both**:
  (a) the integer tier (Level 3) fails its quality gate, **and** (b) even the Level-1 backend-unified
  classes leave a pool below the I-8 independent-operator threshold. Rationale: Level 2 and Level 3 are
  substitutes for the "universal class" goal; if Level 3 lands, Level 2's marginal value is only
  collapsing an fp tier from 2–3 → 1 class, which does not justify the permanent tax of
  contraction-explicit kernels × N backends re-conformed on every toolchain bump.
- **Level 3 — integer-only third tier = the endgame; QW9 stays fp.** A new W4A8 integer profile (int GEMM
  + int32/int64 accumulation per §10 + fixed-point requant + integer/LUT nonlinearities). Integer
  associativity makes determinism a property of arithmetic, immune to codegen drift → one class across all
  arch **including CPU**. Gated by a perplexity/eval gate; **QW9 "Quality" remains fp** (integer quality
  risk is real). Apple stacks are structurally steered toward the integer tier because it is JIT-drift
  immune (R3 argument).

## 16. What lands inert now vs GPU-gated

**Inert, GPU-free, landable now (the (A) protocol foundation; MUST stay `activation == u64::MAX`
byte-identical, existing suites green):**
- This spec doc (§1–§15) — the freeze itself.
- `conformance_vector_set_id` as the class predicate, **multi-set + auditor-capacity** per §13 — additive
  to the profile / a new registration record in `consensus-core`/`mil-core`, inert.
- K0 harness (`mil/provider/src/palw_determinism.rs`) reframed from "measure divergence" to "**assert a
  configured backend set reproduces the committed `V_i`**" — a CI gate; runs on the mock now, on a fleet
  later; doubles as the §13 promotion pipeline.
- Provider startup + periodic self-conformance gate (§14) — `mil/provider`, testable against the mock.

**GPU-fleet-gated (the long pole):** the §3–§10 fixed-schedule kernels (K1/K2), Level-2 cross-vendor
conformance (only if §15 triggers), the Level-3 integer profile + eval gate.

---

## Appendix — this is an increment, not a new tax

The carriers this spec canonicalizes already exist and are already committed into the trace / leaf:
`tile_schedule_id` (schedule selector, §3), `integer_accumulator_checksum` + `overflow_flags` (integer
path + §10 backstop), `operation_schedule_commitment` (§9 schedule), `batch_invariant` /
`deterministic_reduction` (§9 semantics). The design already pays the batch-invariance / fixed-shape /
deterministic-reduction tax; canonicalizing the schedule and moving class from code to data is the
increment on top — and it buys, in order of importance: (1) I-8 anonymity-set / collusion resistance
(bigger pairing sets), (2) fork-free class operation during testnet (data commits, not hard forks), (3)
the pool size that makes k=2 liveness viable at all.
