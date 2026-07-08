# ADR-0031 — DNS Dormancy Fence: revival-path reconstructability (SB-1/2/3/4 unified fix)

- Status: **Design frozen (§7 RESOLVED); ready to implement in the revised order (§3 + §7 + §9).**
- Fence: `dormancy_activation_daa_score = u64::MAX` on every shipped preset — everything
  here is **INERT** and re-genesis-gated. No live/re-genesis config in-tree is affected.
- Supersedes the "CLOSED" claim of the Blocker-2 scaffolding commit `7c45532`.
- Inputs: three multi-agent workflows (understand: 9 agents; unified-design: 10 agents;
  §7-validation: 8 agents) + a prior 50-agent adversarial review of the scaffolding.
- **§7 update:** the original canonical-lagged-anchor keying is **rejected** (phase-ordering
  split, confirmed both lenses); the fix is **burial-frontier-block `B(E)` keying** (§7). A
  fifth gate **SB-5** (revive-across-pp un-reconstructable) was found → `bonds_as_of` must
  **replay**, not patch (§9). Gate count is now FIVE (SB-1..SB-5).

## 1. Context

The DNS Dormancy Fence (design v0.1, PR-D1..D4) evicts long-inactive stake bonds to
`Dormant` (excluded from the finality denominator) and revives them when they re-attest.
Its persisted fields (`last_attested_epoch`, `dormant_at_daa_score`, `dormant_at_epoch`,
`revival_attested_epoch`) enter `overlay_commitment_root`, so they MUST be a pure
deterministic function of the canonical chain, and a pruned-IBD importer MUST reconstruct
them byte-exactly (first post-pruning `c == v`).

**Blocker 1 (multi-round eviction catch-up) is CLOSED** (`8939b6c`): `DnsState.last_evicted_round_epoch`
+ per-round replay via `apply_dormancy_round`. **Blocker 2** (pruned-IBD as-of-pp reconstruction)
landed *scaffolding* (`7c45532`) — `revival_attested_epoch` field, rewarded-sourced
`last_attested`, `bonds_as_of` M1/M2/M3 chaining, I7 — but a 50-agent adversarial review then
proved **four latent consensus-splits remain** (all inert; activation gates):

- **SB-1** revival runs POST the catch-up loop, not per-round → a single sink-jump
  (IBD/resume: one `resolve_virtual` → one `update_dns_state` → one `stage_dormancy_transitions`
  with `prev_last_evicted ≪ buried_epoch`) collapses a dormant→revive→re-dormant cycle → a
  jumping node's dormant state diverges from an incremental node's → different root.
- **SB-2** `revival_attested_epoch` is stamped from `revival_signals` produced by
  `collect_stake_contributions_v2` (classified off the live store, walk truncated at
  `stake_score_window`) → **not pruning-reconstructable and not jump-invariant.**
- **SB-3** the eviction catch-up reads a `walk_bound`-truncated `att_by_bond` → deep replayed
  rounds starve on a jumping node.
- **SB-4** I7 (`walk_bound ≥ bury_blue`) compares a **DAA-block** count to a **blue-score**
  quantity → on a red-heavy DAG the M2 window coverage proof is unsound.

## 2. Decision

Adopt **Hybrid C+A′**: keep the existing `revival_signals` mechanism (it already runs in the
`update_dns_state` recompute phase, off the same `bonds` snapshot as staging → **phase-consistent**),
make it **per-round** and **durable in the recompute phase**, and reconstruct (not delete)
`revival_attested_epoch`. **Reject** a per-block Dormant-attestation write.

### Why NOT the two highest-scored variants (per-block write / Approach A / B′)

The reward/classification write phase and the dormancy-staging phase are **different pipeline
phases**. `validator_reward_outputs_for_block` runs per-block during body validation against
`bond_view = initial_active_bond_view` (seeded from the *persisted* store, mutated only by
`dns_bond_mutations_for_chain_block`, which re-derives bond/unbond/slash and **never replays
dormancy**). `stage_dormancy_transitions` runs later, once, in `update_dns_state`, *after* every
per-block commit. So **any per-block write that classifies "is this bond Dormant at block B?"
reads a dormant-stamp state that lags by up to a full recompute cadence** — an intra-resolve
ordering gap that fixing SB-1 (a staging-phase fix) cannot remove. A jumping node classifies its
whole batch against one frozen previous-sink view; an incremental node against an accreted view →
the committed `BlockOverlayContribution(B)` itself diverges. **This kills Approach A's separate
per-block store and B′'s `revival_keys` write in the reward path.**

### Why NOT literal Approach B (reward Dormant bonds)

Crediting a Dormant bond's attestation (Active-only → Active-or-Dormant at
`utxo_validation.rs:904`) double-mints: it feeds both the §E participation pool (numerator with
a denominator that *excludes* dormant stake → over-distribution) **and** the §D worker inclusion
bounty (`newly_included_stake`), creating a griefing incentive to spam dead-stake attestations.
**The reward path stays Active-only.**

## 3. Implementation plan (single atomic, re-genesis-gated change)

1. **SB-1 (self-contained, do first).** Fold revival into `apply_dormancy_round`
   (`dns_finality.rs`): add `revival_by_bond` + `revival_delay` params; after per-round eviction,
   stamp `revival_attested_epoch = min{e ∈ revival_by_bond : e > dormant_epoch, e ≤ r}` (first-wins,
   set-only-when-None) and revive via `dormancy_revival_ready(dormant_epoch, revival_attested, r, …)`
   with `r` (not `buried_epoch`) as the ready epoch. In `stage_dormancy_transitions` delete the
   post-loop revival block; keep a tail revival at `buried_epoch` (idempotent under first-wins).
   Reference coordinate: revival reads `dormant_at_epoch` (epoch) and compares epoch-vs-`r` — no
   DAA/blue mix inside the kernel.
2. **SB-2 durability.** Append `revival_keys: Vec<(TransactionOutpoint, u64)>` to
   `BlockOverlayContribution` (after `rewarded_keys`; add to `OverlaySnapshot::canonicalize`; do
   NOT feed `epoch_contributions`/economics). New store `revival_epochs.rs` — verbatim sibling of
   `rewarded_epochs.rs` (block-hash-keyed `Vec<(outpoint,u64)>`, **untracked/Count cache policy** —
   the byte-estimation `should_panic` guard test is mandatory), prefix `RevivalEpochs = 214`,
   registered in `mod.rs`/`storage.rs`/VSP/`pruning_processor` (delete_batch beside rewarded).
   **Write in the PER-BLOCK path at the burial-frontier block `B(E)`** (§7 RESOLVED — NOT the
   recompute phase, NOT the canonical anchor), filtered `e ≤ buried_epoch` + deduped.
   `selected_chain_overlay_window` reads it into `revival_keys`.
3. **SB-2 + SB-5 reconstruction — REPLAY, not patch (§9).** `bonds_as_of` must **replay** the
   eviction/revival kernel (`apply_dormancy_round`) over the bounded band `(old_pp_buried, pp_buried]`
   from committed `rewarded_keys` (eviction recency) + `revival_keys` (first-wins revival), seeded
   from the previous captured snapshot — so ALL FOUR stamps (`dormant_at_daa_score`,
   `dormant_at_epoch`, `last_attested_epoch`, `revival_attested_epoch`) come out of the replay and
   the committed dormancy of pp's child is a pure function of pp's buried past (like the StakeScore
   recompute). **Delete** the current null-forward patches and the standalone `last_attested` MAX
   reconstruction. (The original §3.3 "patch a MIN-reconstructed stamp onto the current record"
   CANNOT close SB-5 — a revived record has `dormant_at_epoch = None`, so a null-forward patch never
   re-derives the as-of-pp Dormant status; only a replay does.)
4. **SB-3.** Source `revival_by_bond` from the SAME `selected_chain_overlay_window` as
   `att_by_bond` (read `c.revival_keys` beside `c.rewarded_keys`), so eviction and revival
   recency ride the identical pruning-survivable window (neither starves relative to the other).
   Keep the defer-on-unavailable-anchor `break`.

## 4. New invariants (single coordinate: **blue-score epochs**) — fixes SB-4 — **DONE (params)**

**Root cause (validated):** the dormancy recency signals are BLUE-coordinated (epochs), but the
overlay window is **DAA-bounded** (`selected_chain_overlay_window` truncates by
`anchor_daa − ancestor_daa > walk_bound`). The old I7 compared DAA-block `walk_bound` to blue-score
`bury_blue` — dimensionally incoherent. A correct DAA form needs `walk_bound ≥ (bury_blue+L)·ρ_max`
with `ρ_max = Δdaa/Δblue ≤ mergeset_size_limit = ghostdag_k·2 ∈ [180,512]` (248 at 10 BPS, 512 at
testnet-40) → `walk_bound ~10^4–10^5` blocks, an **inert lockout**. So a DAA params comparison
cannot fix it.

**Resolution:** the reconstruction must ride the **BLUE-bounded StakeScore window**
(`stake_score_window_blue_score`), NOT the DAA overlay window. Then:
- **I7 removed** (the DAA `walk_bound ≥ bury_blue` was the wrong coordinate).
- **I6** (`stake_score_window_blue_score ≥ bury_blue + L`, already present) IS the eviction-band
  coverage invariant.
- **I8 (new, DONE)** `revival_delay_epochs · L ≤ stake_score_window_blue_score` — the revival
  straddle band (`revival_delay` epochs wide) must fit the same blue window. PRODUCTION
  `revival_delay=1` satisfies it trivially; both fail safe (violation → dormancy inert).

The params half is landed (`dns_v4_params_consistent` now uses I6 + I8, both pure blue-score; I8
fail-safe test). The **reconstruction-code half** — switching `bonds_as_of`'s M1/M2/M3 (and the
catch-up `att_by_bond`) from the DAA overlay window to the blue StakeScore window — is folded into
**SB-2/SB-5** (§3.2–3.3 / §9), since that code is being rewritten there anyway. `bonds_as_of` today
still reads the DAA window (fence-inert), flagged in-code.

## 5. Mandatory tests (activation gate)

- **WI-1 (the gate).** Virtual-processor harness: two nodes, one advancing one epoch/commit, one
  single-sink-jumping across a full dormant→revive→re-dormant band that **straddles a pruning
  point** (`E ∈ (pp_buried − revival_delay, pp_buried]`). Assert **identical `overlay_commitment_root`
  at the shared tip** + identical post-import `revival_attested_epoch`/`status`, across DAA/blue skew.
  **`dormancy_activation_daa_score` MUST NOT be set finite until WI-1 is green.**
- SB-1 unit: one call replaying an evict→revive→re-evict cycle == N single-round calls.
- SB-2: window with a Dormant `(op,E)` in `revival_keys`, live acceptance dropped → `bonds_as_of`
  re-derives `E` (min-in-band); post-pp stamp `> cap` with no support → `None`.
- Economics regression: a re-attesting Dormant bond leaves every Active reward output + `Σ minted`
  byte-identical (the test literal-B fails).
- I8 fail-safe; canonicalize determinism (shuffled `revival_keys` → stable root); store crud +
  `should_panic` byte-estimation guard.

## 6. Residuals (fence-gated, documented)

1. Whole change is re-genesis-gated; the `revival_keys` field changes the frozen commitment
   preimage → activation and the field addition ship together in one re-genesis.
2. `revival_keys` is a superset recency hint — consumable ONLY under the
   `e > dormant_epoch && e ≤ r/pp_buried` first-wins-min guard; `stage_dormancy_transitions` /
   `bonds_as_of` are the sole consumers (assert it).
3. Reward path stays Active-only (deliberate rejection of literal-B).
4. I7 (blue) is a shared prerequisite of BOTH `last_attested` and revival reconstruction.

## 7. RESOLVED — deterministic block-assignment via the burial-frontier block `B(E)`

The unified-design synthesis proposed keying `revival_keys` by the **recompute sink** (pov-dependent
→ split) or the **canonical lagged epoch anchor `A(E)`**. The §7-validation workflow (8 agents,
refute-by-default) **CONFIRMED both fail** and found the correct escape.

**Rejected — `A(E)` (canonical lagged anchor):** `A(E)` sits at `blue ≈ epoch_end(E) − backoff`
(`backoff < L`), but a revival signal for E is only decidable once E is **buried**
(`blue ≥ epoch_end(E) + bury_blue`, `bury_blue = max(attestation_lag, max_reorg_horizon)`). So at
`A(E)`'s own commit E is NOT yet buried → unlike `rewarded_keys` (written at the block's own commit
from its own past), `revival_keys(A(E))` would be **back-written** at the later recompute. A single
`resolve_virtual` sink-jump commits a descendant `D` (reading `A(E).revival_keys = {}` in its
per-block window) BEFORE the recompute back-writes `A(E).revival_keys = {(bond,E)}` that an
incremental node already has → same `D`, two `commit_root`s → `BadOverlayCommitment`.

**RESOLVED — key by `B(E)` = the FIRST (lowest-blue) selected-chain block with
`blue_score ≥ epoch_end_blue_score(E) + bury_blue`** (the identical burial threshold
`stage_dormancy_transitions` / `bonds_as_of` already use). At `B(E)`'s **own** per-block commit E is
buried **by construction**, so the set `{(op,E): op attested-while-Dormant for E}` is a pure function
of `B(E)`'s selected-parent past → produce it in the **per-block path** (`revival_signal_keys_for_block`
in `utxo_validation.rs`, threaded via `ctx`) and write it at `commit_utxo_state` beside
`rewarded_epochs_store.insert_batch`, restoring the write-at-own-commit invariant. Any descendant
reads a value frozen at `B(E)`'s commit — identical on jumping and incremental nodes. `B(E)` is a
canonical selected-chain block (reorg-stable once buried) and in-window under I7-blue. Add
`burial_frontier_block(epoch, tip, dns_params)` — a header-only sibling of `canonical_anchor_by_blue_score`.

Invariants: **I-R1** `revival_keys(B)` is a pure function of `B`'s past; **I-R2** every
`(op,E) ∈ revival_keys(B) ⇒ B == burial_frontier_block(E)`; **I-R3** consume-only under
`e > dormant_epoch ∧ e ≤ r/pp_buried` first-wins-MIN; **I-R4** pp-purity of committed dormancy;
**I-R5** bounded ≤ one-pruning-delta replay under I7-blue + I8. Per-block `ActiveBondView` dormancy
accretion (Approach C3) is NOT needed and rejected on cost (`derive_dormancy_evictions` is a
whole-bondset stake-budgeted sort → O(epochs·bonds·log bonds) on the serial UTXO hot path).

## 8. Status of the FIVE blockers

| | State |
|---|---|
| SB-1 | **DONE** (`8a8e782`) — revival folded into `apply_dormancy_round`, round-gated, jump-invariant |
| SB-2 | design frozen; write at `B(E)` per-block (§7 RESOLVED) — remaining |
| SB-3 | design frozen (§3.4); rides SB-2's blue window — remaining |
| SB-4 | **params DONE** — I7(DAA) removed, I6 + new I8 (both blue); reconstruction-code switch to the blue window folded into SB-2/SB-5 |
| SB-5 | design frozen (§9); `bonds_as_of` replay-not-patch — remaining |

**Do not flip `dormancy_activation_daa_score` off `u64::MAX` until SB-1..SB-5 are implemented and
WI-1 (extended, §9) is green.**

## 9. SB-5 (new gate) — revive-across-pp reconstructability requires a REPLAY

**Confirmed real (both lenses).** A bond Dormant as-of pp that **revives strictly post-pp** is
unreconstructable by the current `bonds_as_of` (which only null-forwards): revival CLEARS all four
stamps, so at capture the record shows `status = Active, dormant_at_epoch = None`; `bonds_as_of`'s
sole dormant branch is `dormant_at_epoch.is_some_and(|e| e > cap) → None` — it **never SETS** a
dormant stamp — so the bond reconstructs Active, while the from-genesis node committed it Dormant
as-of pp → different `commit_root` + different finality denominator → hard split. This is on the
binary eviction-status axis, orthogonal to `revival_keys` recency, so §7 alone does not close it.

**Fix:** `bonds_as_of` must **REPLAY** `apply_dormancy_round` over the bounded band
`(old_pp_buried, pp_buried]` from committed `rewarded_keys` + `revival_keys` (seeded from the
previous captured snapshot), yielding all four stamps as-of-pp — the committed dormancy of pp's
child becomes a pure function of pp's buried past, exactly like the live per-round path. Delete the
null-forward patches (`bonds_as_of` dormant/last_attested/revival) — they are replaced wholesale.

**Highest-risk item + its test:** the importer replay must produce **byte-identical** stamps to the
live per-round `stage_dormancy_transitions` for a bond that evicts at `D ≤ pp_buried` and revives at
`V > pp_buried`, across DAA↔blue skew. **WI-1 (extended, the activation gate):** two-node harness —
one incremental, one single-sink-jumping across a `dormant→revive` band straddling a pruning point
with such a bond X; assert (i) identical `overlay_commitment_root` at the shared tip, and (ii) the
importer's `bonds_as_of(pp)` yields `X.status = Dormant` with A's exact stamps (X must NOT
reconstruct Active). Run under a red-heavy DAG to exercise I7-blue/I8. Green gates activation.

## 10. SB-2/SB-5 implementation-validated final design (accepted-set / classify-in-kernel)

A pre-implementation validation (8-agent workflow, 2026-07-08) **confirmed a second flaw** in the
frozen §7 wording and fixed it. §7 keying (B(E)) is right, but §7's set definition
`{(op,E): op attested-while-Dormant for E}` classifies **Dormant at the write** — and the only
Dormant source is the per-block `ActiveBondView`, which (F1) never accretes dormancy (apply/revert
handle only Insert/Slash/Unbond), so it reads a `dormant_at_daa_score` **frozen at prev_sink** for
the whole resolve span; a single sink-jump then classifies B(E) against a stale view while an
incremental node classifies against an accreted one → divergent `revival_keys(B(E))` → split. This
is the ADR §2 phase-lag, at the write instead of the recompute.

**Adopted fix — record the ACCEPTED SET, classify in the kernel:**
- At B(E) record the **full accepted attestation set** for E — every `(bond_outpoint, E)` passing
  the *acceptance* gate (`active_or_dormant_bond_at` + validator-id + ML-DSA-87 + v3 canonical
  anchor + readiness), with **NO Active/Dormant branch**. `active_or_dormant_bond_at` returns `Some`
  for BOTH Active and Dormant (it flips only on Slashed/Unbonding/Pending, all per-block-accreted),
  so the set is a **pure function of B(E)'s buried past** — no phase-lag.
- The Active/Dormant classification moves entirely into `apply_dormancy_round`: feed the accepted
  set as BOTH `att_by_bond` (touch `last_attested` for all) AND `revival_by_bond`; the kernel's
  `e > dormant_epoch && e ≤ r` guard discards the non-revival entries against its own as-of-`r`
  state — jump-invariant on both node types (SB-1 already makes the kernel per-round deterministic).

**Consequences vs the earlier §3:**
- Store `DbAcceptedAttestationsStore` (`accepted_attestations_store`), value `Vec<(outpoint,epoch)>`,
  keyed by B(E), untracked cache, **registry prefix `AcceptedAttestations = 235`** (NOT 214 — 214-216
  are reserved for RPC canonical-v2). Committed field `BlockOverlayContribution.accepted_keys`.
- `last_attested` is now sourced from the **accepted** set (superset of rewarded) — removes the
  pool-cap-tail eviction churn; a **net correctness gain**, economically neutral (the reward path
  stays Active-only and untouched — rewarded_keys / §D / §E / `Σ minted` byte-identical).
- `OverlaySnapshot` gains `last_evicted_round_epoch: u64` so the `bonds_as_of` replay starts its
  round loop at the exact as-of-pp cursor.
- **SB-4 blue-window switch must land in ALL THREE readers** (the per-block gather, `stage_dormancy_transitions`,
  and `bonds_as_of`) — any one left on the DAA overlay window reintroduces the red-heavy truncation split.
- `collect_stake_contributions_v2`'s Active/Dormant branch + the `revival_signals` plumbing are deleted.

**Implementation status (this session):** store scaffolding landed (new store + registry 235 +
storage/VSP/pruning wiring, builds, INERT). Remaining: committed fields + `canonicalize`;
`burial_frontier_block` + per-block `accepted_attestation_keys_for_block` gather + `commit_utxo_state`
write; kernel input rewire + shared `replay_dormancy_rounds` helper; `bonds_as_of` replay; IBD
reseed; WI-1. **Highest residual risk (from validation):** the B(E) gather + all three readers must
ride `stake_score_window_blue_score` (blue), and the importer replay's per-round `round_anchor_daa`
must be reproducible in-window under I6-blue (else persist the band anchors in the snapshot).
