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
never a silent wrap). The table is scoped to the **QW9 (9B) shape table only** (genesis single live tier,
§15); QW4/4B rows are deferred to Appendix B and re-derived on QW4 activation. Representative frozen QW9
entries (worst-case magnitudes; int32 headroom = 2³¹ ≈ 2.1e9):

| Op (QW9) | Worst-case accumulator | Fits int32? | Rule |
|----------|------------------------|-------------|------|
| `QK^T` (head_dim ≤ 128) | 128·127² ≈ 2.1e6 | yes | int32, no split |
| RMSNorm Σx² (d_model ≤ 4096) | 4096·127² ≈ 6.6e7 | yes | int32, fixed order |
| softmax·V (seq up to 32k) | ≈ 1e11 | **NO** | **int64 accumulator OR hierarchical requant at spec-fixed 128-position boundaries** |

The rule for any op not listed: if worst-case at its max admissible QW9 shape (§9 shape table) exceeds
int32 headroom, it MUST use an int64 accumulator or spec-fixed hierarchical-requant boundaries;
**saturation is FORBIDDEN** (order-dependent). Overflow budgets are part of the frozen spec, not a runtime
decision. (Appendix B holds the deferred QW4 budget rows.)

## 11. Conformance vectors

**FROZEN format; content `MEASURED-AT-K0`.** A conformance vector set `V_i` is the committed golden
input/output set that *defines* a class (§13). Requirements:
- **Coverage:** every op-type × boundary value **over the QW9 shape table only** (min/max shape from §9,
  block boundaries from §4, chunk boundaries from §9, overflow-budget edges from §10, and at least the
  trace-committing ops of §3–§8). QW4 coverage is deferred to Appendix B, generated on QW4 activation.
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
- **Tier activation is DERIVED, never a separate flag.** A tier is live iff there exists a committed
  **active** vector set referencing that tier's `model_profile_id`. There MUST NOT be an `enabled_tiers`
  parameter — that would duplicate the source of truth. QW4 with no committed set is naturally
  non-registerable; re-enabling it is exactly a set commit. The registration predicate ((A)-1) collapses
  to a single check: *"the referenced vector set is active."*
- **Tier mechanism is retained.** `model_profile_id` and I-9 intra-tier pairing are NOT removed — the
  integer tier arrives as a second tier, and a **model/manifest update reuses §13 rolling migration**: the
  new manifest is a new set that coexists with the old; pairs form only within one set, so soundness is
  invariant across the migration window. Single-model-event risk (a model defect becoming a whole-net
  event) is mitigated by this exact mechanism — multiple sets under one tier is why it was designed
  multi-set even though the live tier count is 1.
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

**Genesis is QW9-only (single live tier).** QW9 (9B Q4, fp) is the sole tier with a committed active
conformance vector set at genesis, so it is the only registerable/paying tier. QW4 (4B) is **defined but
not activated at genesis** — its profile constants and tests are kept **reserved** (as a fixture: a live
tier count of 1 would leave the I-9 cross-tier separation path untested, so QW4 stays as the second tier
*in tests*), and 4B survives off-consensus as a **MIL service class** (ticket-less inference, fee income).
Re-enabling QW4 later is a governed **data commit** of its vector set (§13), not a fork, not special-case
code. Excluded-by-VRAM hardware retains two roles: permanent hash-floor mining + MIL 4B serving — so
D8 "broad participation" moves from the consensus face to the service face, it is not abandoned.

- **Level 1 — policy + schedule constraint. Fleet-gated, months, not research.** Own kernels already
  exist (llama.cpp-family MMQ). The work is *constraining* arch/batch-dependent tile heuristics to the
  §3 fixed schedule and **killing runtime dispatch** — reducing schedule freedom, not writing GEMMs from
  scratch. Plus §2 transcendental software-ization (helps intra-backend too). Result target (QW9-only):
  `{CUDA-unified, Metal-unified} × {QW9} = 2 classes` (immediately halved vs a two-tier world). K0 is
  reframed from "measure how many classes" to "verify this unification holds." **Optional minimal genesis
  (§13, judgment call):** start with the **CUDA set only** (class count = 1) and add the Metal set as a
  second data commit once Mac provider depth warrants it — "start minimal, grow monotonically" avoids
  creating a strand.
- **Level 2 — cross-vendor fp = CONDITIONAL STANDBY (not R&D, not a milestone).** Trigger requires **both**:
  (a) the integer tier (Level 3) fails its quality gate, **and** (b) even the Level-1 backend-unified
  classes leave a pool below the I-8 independent-operator threshold. Rationale: Level 2 and Level 3 are
  substitutes for the "universal class" goal; if Level 3 lands, Level 2's marginal value is only
  collapsing an fp tier from 2 → 1 class, which does not justify the permanent tax of
  contraction-explicit kernels × N backends re-conformed on every toolchain bump.
- **Level 3 — integer-only SECOND tier = the endgame; QW9 stays fp.** A new W4A8 integer profile (int GEMM
  + int32/int64 accumulation per §10 + fixed-point requant + integer/LUT nonlinearities) is the intended
  **second live tier** (QW9-fp being the first). Integer associativity makes determinism a property of
  arithmetic, immune to codegen drift → one class across all arch **including CPU**. Gated by a
  perplexity/eval gate; **QW9 "Quality" remains fp** (integer quality risk is real). Apple stacks are
  structurally steered toward the integer tier because it is JIT-drift immune (R3 argument).
- **Bond calibration** at genesis references a **single `c_saved(9B)`** (one live tier ⇒ one saved-compute
  reference); the `min_leaf_bond_sompi` calibration (scope v0.1 R3) is single-valued until a second tier's
  set is committed.

## 16. What lands inert now vs GPU-gated

**Inert, GPU-free, landable now (the (A) protocol foundation; MUST stay `activation == u64::MAX`
byte-identical, existing suites green):**
- This spec doc (§1–§15) — the freeze itself.
- **(A)-1** `conformance_vector_set_id` as the class predicate, **multi-set + per-set auditor-capacity**
  per §13 — additive to the profile / a new registration record in `consensus-core`/`mil-core`, inert.
  The registration predicate collapses to a single check — *"the referenced vector set is active"* — from
  which **tier activation is DERIVED** (no `enabled_tiers` flag; §13). QW9 is the only referenceable set at
  genesis; QW4 stays as a reserved test fixture (I-9 cross-tier path).
- **(A)-2** K0 harness (`mil/provider/src/palw_determinism.rs`) reframed from "measure divergence" to
  "**assert a configured backend set reproduces the committed `V_i`**" — a CI gate; runs on the mock now,
  on a fleet later; doubles as the §13 promotion pipeline. Adds a **peak-VRAM-per-fixed-shape** measurement
  (the participation floor is a function of the §9 shape table + §9 KV quantization, not the model alone).
- **(A)-3** Provider startup **+ periodic / driver-OS-fingerprint-change** self-conformance gate (§14) —
  `mil/provider`, testable against the mock; fingerprint attached as off-consensus telemetry.

**GPU-fleet-gated (the long pole):** the §3–§10 fixed-schedule kernels (K1/K2), Level-2 cross-vendor
conformance (only if §15 triggers), the Level-3 integer profile + eval gate, and the QW9 `V_i` content +
per-fixed-shape peak-VRAM numbers that decide the 12 GB-class SKU inclusion (§15 participation floor).

---

## 17. Fork surface — model-as-data (the deepest freeze)

**FROZEN.** What forks the chain is decided not by "semantics vs data" but by **what the validator's
validity predicate reads**. By D3 a PALW validator **never executes the model** — block acceptance reads
only certificate / nullifier / beacon / structural checks and treats every model output as an **opaque
hash** (`canonical_gemm_trace_root`, `output_commitment`, `model_profile_id`, `model_manifest_hash`). So
model semantics are expelled from consensus entirely. Design goal, one sentence:

> Consensus knows only "a valid certificate and valid structure." The subject that knows *what the model
> is* is limited to the provider and the auditor, and its satisfaction is measured by the §13
> auditor-capacity gate.

### 17.1 The invariant kernel (the ONLY fork surface)

Protocol retains exactly these; everything else is data or a spec-version rollout:

- Header v3 wire (the 10 fields + preimage order) and the leaf's **8 opaque slots** (each slot an
  un-parsed hash/int — consensus never interprets the contents).
- `E = H + min(C, 4H)` and the cap; the coinbase formula (values are params).
- the `eligibility` / `chain_commit` / `R_E` / `nullifier` formulas and their domain tags; the 9-clause
  acceptance **structure**.
- the DNS certificate quorum rule; the subnet `0x30–0x37` wire schema and the batch state machine.
- the **set-record schema** (§17.3 — cut general ONCE).

**Verification condition:** the words *Qwen / GEMM / tokenizer* (and RMSNorm / RoPE / softmax / expert /
MoE / VLM) MUST NOT appear anywhere in this list or in a consensus validity rule. A hit is a semantics
leak = a future-fork reservation, and must be opaque-ized (§17.5 step 1).

### 17.2 The set record is the unit of migration (class-as-data → model-as-data)

The §13 conformance-set record is extended to the **sole surface of model migration**:

```
PalwComputeSetRecordV1 {
  set_id
  compute_spec_version          // the op-catalog version (§17.4)
  model_manifest_hash           // OPAQUE (weights / tokenizer / quant / shape … contents live in DA)
  vector_commitment             // the golden vector set = the class predicate (§11/§13)
  quantum_calibration           // work_per_quantum + attested K0 benchmark hash
  econ_params                   // the VALUES of bond / timeout … (formulas are protocol, with floors)
  weight_factor                 // per-set credit ramp 0→1 (governed, change rate-limited)
  activation_daa / deprecation_daa   // non-retroactive (already frozen, §13)
  auditor_capacity_evidence_hash
}
```

A new-model migration = a commit of a new record. Because consensus sees only this record and opaque
hashes, a change of tokenizer / modality / architecture leaves it **structurally indifferent** — a VLM is
the same (prompt/output commitments are already opaque ⇒ consensus is modality-free from day one). The
doc-6 fork table is revised:

| Change | doc-6 | this design |
|--------|-------|-------------|
| add MoE | fork | spec chapter + rollout + commit (`expert_index` / `selected_expert_ids` are ALREADY in the trace = half pre-taken) |
| VLM | often a fork | encoder spec chapter + kernels + shape table; consensus unchanged |
| trace-internal restructure | fork | if the leaf's 8 slots are unchanged, a spec-version delta (derivation rules live in the audit layer) |
| quantum / bond VALUES | data | data (the formula + floor stay protocol) |

### 17.3 Op catalog is a *version*, not a fork

Canonical Compute (this document) is a **normative document for providers/auditors + a version number a
set record references**, not consensus code. Adding a new operation = publishing a spec-vN chapter +
implementing its kernel + generating its conformance vectors; **no consensus rule changes**. doc-6's "new
operation semantics → protocol upgrade" is downgraded to "**spec release + software rollout**", and rollout
satisfaction (can auditors bit-reproduce vN?) is exactly what the §13 capacity gate already measures — the
"how to treat un-upgraded nodes" problem never reaches the validator (it does not execute), it only shows
up as adoption rate at the capacity gate.

### 17.4 Migration playbook (the fork-free standard path)

```
publish spec-vN chapter (only if needed)
→ provider/auditor release (advertise the capable version)
→ K0/K4 generate the vector set + benchmark
→ DAO commits the set record (weight_factor = 0, shadow)
→ shadow period: serve real MIL fee traffic + accumulate canary/mismatch stats
→ weight ramp (rate-limited)
→ non-retroactive deprecation of the old set
```

No validator upgrade at any stage. This is the **per-set version of the global activation ladder (Stage
A–D)**, not a new rule; rollback = deprecation (already-frozen mechanism).

### 17.5 The price of expelling semantics = a larger governance surface (honest accounting)

Letting a DAO data-commit decide "what counts as compute work" is real. The defense is four layers, one of
which is pre-existing structure:

1. **`E ≤ 5H` cap bounds the worst case structurally** — even a fully bought governance committing a fake
   set + fake quantum amplifies attacker hash work by at most 5×. The permanent hash floor earns its keep
   here again.
2. **econ formulas + floors are protocol** (only values are data) — a commit lowering bond below the
   fraud-EV threshold is rejected by protocol.
3. **rate-limit `weight_factor` / `quantum_calibration` changes** in protocol, and require an attested K0
   benchmark hash on `quantum_calibration`.
4. **shadow period + capacity gate + canary stats** are ramp preconditions (reused from the §13 freeze).

**Consensus-side genericity fixes (added to (A), all inert)** — without these the above is vapor:
1. **opaque-ize `operation_id`** — `PalwOperationIdV1`'s fields become fixed-width opaque bytes on the
   wire; the internal schema is demoted to `compute_spec_version`. The current struct persists as "the
   spec-v1 encoding." An SSM without `expert_index` leaves the wire unchanged.
2. **quantum_calibration as a record read** — move the quantum→work conversion from hardcoded params to a
   set-record read; protocol keeps only the floor formula (`bond ≥ f(quantum, c_saved ref)` …).
3. **fix I-12** — add "the set records active in this epoch" to `PalwEpochProofBundleV1`; historic-`E`
   recompute becomes per-set `quantum` / `weight_factor` dependent, so without this class-as-data
   contradicts I-12.
4. **load-swap the (A)-1 predicate** — registration = "a valid reference to an active set record" (same
   shape as the QW9-only impl, the referent is now a record).

### 17.6 What still forks (short, honest)

The `E` formula / cap value, the Header v3 wire, the leaf 8-slot composition itself, k=2 → k=3 (acceptance
+ slashing predicates change), the certificate quorum rule, the eligibility / nullifier / beacon formulas,
a breaking change to the set-record schema, exact → fuzzy (a permanent non-goal). **No change that touches
the model is on this list** — that is this design's success condition.

### 17.7 Pre-writing budget

Worth pre-writing: **the MoE chapter (a spec-v2 candidate) only** — future large Qwen is MoE-dominant and
the trace already carries expert fields; freeze only the router determinism (top-k tie-break = smallest
expert id, capacity-dropping forbidden or made deterministic, expert-parallel reduction order). Doc work
only, no kernel, inert. SSM / sliding-window wait for demand. **Backlog-registered, not written now.**

---

## Appendix B — deferred QW4 (4B) rows

QW4 is defined but not activated at genesis (§15). Its overflow-budget rows (§10) and conformance-vector
coverage (§11) are **deferred here, empty until QW4 activation**, which is a governed data commit of a QW4
vector set (§13) — not a fork. Until then QW4 lives only as (a) a reserved profile/test fixture keeping the
I-9 cross-tier separation path under test, and (b) an off-consensus MIL 4B service class. When activated,
this appendix is populated by re-running §10's derivation and §11's coverage over the QW4 shape table.

## Appendix A — this is an increment, not a new tax

The carriers this spec canonicalizes already exist and are already committed into the trace / leaf:
`tile_schedule_id` (schedule selector, §3), `integer_accumulator_checksum` + `overflow_flags` (integer
path + §10 backstop), `operation_schedule_commitment` (§9 schedule), `batch_invariant` /
`deterministic_reduction` (§9 semantics). The design already pays the batch-invariance / fixed-shape /
deterministic-reduction tax; canonicalizing the schedule and moving class from code to data is the
increment on top — and it buys, in order of importance: (1) I-8 anonymity-set / collusion resistance
(bigger pairing sets), (2) fork-free class operation during testnet (data commits, not hard forks), (3)
the pool size that makes k=2 liveness viable at all.
