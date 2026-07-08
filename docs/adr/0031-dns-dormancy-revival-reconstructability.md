# ADR-0031 — DNS Dormancy Fence: revival-path reconstructability (SB-1/2/3/4 unified fix)

- Status: **Design frozen; implementation NOT started (one open sub-problem, see §7).**
- Fence: `dormancy_activation_daa_score = u64::MAX` on every shipped preset — everything
  here is **INERT** and re-genesis-gated. No live/re-genesis config in-tree is affected.
- Supersedes the "CLOSED" claim of the Blocker-2 scaffolding commit `7c45532`.
- Inputs: two multi-agent workflows (understand: 9 agents; unified-design: 10 agents +
  a prior 50-agent adversarial review of the scaffolding).

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
   **Write in the recompute phase** (see §7 for the open keying question), filtered `e ≤ buried_epoch`
   + deduped. `selected_chain_overlay_window` reads it into `revival_keys`.
3. **SB-2 reconstruction.** In `bonds_as_of`, build a SECOND reconstructed map using **MIN
   (first-wins)** — structurally different from `last_attested`'s MAX — over the same M1/M2/M3 chain
   reading `revival_keys`, restricted to the straddle band `pp_buried − revival_delay < e ≤ pp_buried`
   and `e > the bond's as-of-pp dormant_at_epoch`. For a still-Dormant bond whose
   `revival_attested_epoch` is None/`> cap`, set it from the min-in-band reconstruction.
4. **SB-3.** Source `revival_by_bond` from the SAME `selected_chain_overlay_window` as
   `att_by_bond` (read `c.revival_keys` beside `c.rewarded_keys`), so eviction and revival
   recency ride the identical pruning-survivable window (neither starves relative to the other).
   Keep the defer-on-unavailable-anchor `break`.

## 4. New invariants (single coordinate: **blue-score epochs**) — fixes SB-4

- **I7 (restated).** Express `walk_bound` in blue-score (blue-denominated window params, or the
  DAA bound × min blue-density) and require `walk_bound_blue ≥ bury_blue + L`, so the captured
  window's *blue* reach provably covers the reconstruction band. (The current L1124-1128 compares
  DAA-block `walk_bound` to blue-score `bury_blue` — dimensionally incoherent; a red-heavy DAG can
  make a DAA bound blue-shallower than one bury depth.)
- **I8 (new).** `revival_delay_epochs · L ≤ walk_bound_blue` — the straddle band (`revival_delay`
  epochs wide) must fit the captured window. PRODUCTION `revival_delay=1` satisfies it trivially;
  a future re-genesis raising it must keep the invariant. Both fail safe (violation → dormancy inert).

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

## 7. ⚠️ OPEN SUB-PROBLEM — deterministic block-assignment of committed `revival_keys`

The design synthesis proposed writing `revival_keys` **keyed by the recompute sink**. This is
**non-deterministic**: the recompute fires at whichever sink first crosses the epoch boundary
(pov-dependent, the M-01 concern), so different nodes would attach the same revival signals to
different blocks → different committed windows → split. Meanwhile a **per-block** write has the
§2 phase-lag. So neither the synthesis's keying nor a naïve per-block keying is correct.

**Candidate resolution (needs its own adversarial validation before coding):** key each revival
signal by the **canonical lagged epoch anchor** of its epoch (deterministic, a selected-chain
block, already computed as `epoch_anchor_daa`), written **once when that epoch is buried** (stable,
never reorgs). All nodes then attach identical `revival_keys` to identical canonical-anchor blocks,
and the window walk reads them consistently for every block at which the epoch is buried. This must
be validated against: (a) commitment-timing consistency (a descendant committed before vs after the
buried write sees the same window), (b) the canonical-anchor being in-window under I7, (c) reorg
stability. **Until this is resolved, implementation must not begin — a wrong keying is a latent split.**

## 8. Status of the four blockers

| | State |
|---|---|
| SB-1 | design frozen (§3.1); clean, self-contained; implementable once §7 chosen (shares the test) |
| SB-2 | design frozen **except §7 open sub-problem** (block-assignment) |
| SB-3 | design frozen (§3.4); rides SB-2's window |
| SB-4 | design frozen (§4, I7 blue-restatement + I8) |

**Do not flip `dormancy_activation_daa_score` off `u64::MAX` until SB-1..SB-4 are implemented,
§7 is resolved+validated, and WI-1 is green.**
