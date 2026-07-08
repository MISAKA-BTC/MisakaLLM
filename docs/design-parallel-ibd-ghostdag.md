# Parallel Per-Header GHOSTDAG + Reachability for IBD — Final Design

**Project:** kaspa-pq (rusty-kaspa fork) · **Branch:** `pr-19-s5f-generator-mldsa-recalibration`
**Audience:** maintainer of this fork · **Status:** design-final, implementation-ready
**Scope:** header-sync stage only (`HeaderProcessor`). Body/virtual/pruning processors unchanged except where the commit handshake touches them.

---

## 1. Problem statement and the measured bottleneck

During IBD header-sync only the **first** pipeline stage runs (`HeaderProcessor`), and the measured wall-clock bottleneck is **not** PoW hashing. It is the per-header GHOSTDAG coloring plus the reachability interval-tree staging/commit, gated by two things: (a) a serial `commit_header` critical section (`processor.rs:359-433`) in which every header funnels through the single global reachability lock — `StagingReachabilityStore::new(self.reachability_store.upgradable_read())` at `:389`, held across `add_block` (`:392`), `staging.commit` upgrade-to-write (`:422` → `reachability.rs:411`), and a synchronous `db.write` (`:425`) — and (b) the rocksdb random point-reads inside GHOSTDAG (`get_data`/`get_blues_anticone_sizes` chain-walks at `protocol.rs:242,280`) and reachability (`is_dag_ancestor_of` interval gets). GHOSTDAG **compute** already fans out across a rayon pool sized to logical cores, but during linear selected-chain sync the dependency chain collapses width to ≈1 in-flight, so each header serially pays a full lock-upgrade + fsync. The code's own comment (`processor.rs:385-388`) flags this region as deliberately serialized "on the assumption reachability time << header time … this should be benchmarked."

---

## 2. Consensus invariants that constrain the design

Each invariant below is load-bearing; the design preserves all of them. "Why it must hold" is stated because the rollout's shadow-validation (§7) asserts each one.

| # | Invariant | Site | Why it must hold |
|---|-----------|------|------------------|
| **I1** | **Cross-node determinism.** `GhostdagData{selected_parent, mergeset_blues (ordered), mergeset_reds, blues_anticone_sizes, blue_score, blue_work}` is a *pure deterministic* function of {parents, K, committed ancestors' GhostdagData + header bits}. Tie-breaks total: `selected_parent = argmax SortableBlock(blue_work, hash)`; mergeset sorted by the same order before coloring; integer-only sums. | `protocol.rs:99-166`, `ordering.rs:38-42`, `mergeset.rs:43-50` | A single flipped blue/red bit or a non-deterministic mergeset order changes `blue_work` → this node computes a different selected chain/virtual sink than the network → it soft-rejects the honest chain and **forks**. |
| **I2** | **Topological processing order.** A header is not processed until **all** its direct parents have *fully committed* (left the `pending` map). | `deps_manager.rs:225-230`, requeue `processor.rs:262-265` | GHOSTDAG `.unwrap()`s every parent store read (`protocol.rs:102,153,159,161,242-243`; `mergeset.rs:20`). Running early → `KeyNotFound` panic, or a torn read of stale `blue_work` → silent I1 break. |
| **I3** | **Reachability tree monotonicity + atomicity.** Each block's interval strictly contains its tree-children's; siblings disjoint and interval-ordered; FCS lists interval-sorted; the whole tree+FCS+reindex_root update for one block applied atomically. | `extensions.rs:14-18`, `inquirer.rs:233-266`, `tree.rs:11-38`, `reachability.rs:410-438` | Two concurrent allocations against one parent both `split_half` its remaining range → overlapping intervals → `is_chain_ancestor_of` returns **wrong booleans** for the whole subtree → corrupt mergeset pruning, incest checks, virtual chain walk. A half-applied reindex makes a true ancestor momentarily test non-ancestor → transient consensus-wrong results. |
| **I4** | **Cross-store atomic commit.** ghostdag(full+compact), daa, headers(full+compact), depth, relations, reachability_relations, reachability staging, conditional HST, and status all land in **one** `WriteBatch` flushed by exactly one `db.write`; guards dropped only **after** the flush. status-present ⇒ all derived data present. | `processor.rs:363-432` | If status is published before ghostdag/reachability (e.g. split across transactions), a child admitted by `check_parents_exist` (status store) then panics in `ghostdag` (parent rows missing). |
| **I5** | **Selected-tip monotonicity + reindex-root/pruning interaction.** HST advances only if `SortableBlock(hash, blue_work) > prev` **and** `is_chain_ancestor_of(pruning_point, hash)`; reindex_root follows the consensus selected chain; reindex and pruning are global tree rewrites that must be exclusive vs per-header interval allocation. | `processor.rs:398-404`, `tree.rs:109-146`, `pruning_processor/processor.rs:444-520` | A reindex_root advanced off a half-committed/non-canonical tip, or pruning interleaved with header interval allocation, corrupts intervals globally; a missing `reachability_relations` entry breaks header pruning. |
| **I6** | **Restart/crash recovery.** On-disk state is always a **prefix-consistent committed set**; every committed header has all stores present (single batch); restart is idempotent via the status short-circuit and write-once/idempotent inserts; startup asserts `past_pruning_points[0] == config genesis`. | `processor.rs:272-278,425`, `ghostdag.rs:298-305`, `consensus/mod.rs:304-306` | A torn block (status set but ghostdag/reachability missing) is permanently skipped by the idempotency short-circuit and later panics in every descendant's GHOSTDAG/reachability query. |

---

## 3. The chosen approach

**Chosen: a hybrid — *Compute-parallel / commit-serial via a dedicated single-thread `ReachabilityProcessor` lane* (Proposal 2), with Proposal 3's prefetch + group-commit folded in as bounded, optional sub-layers of the same committer.** This is exactly the "separate ReachabilityProcessor" the code comment at `processor.rs:387-388` anticipates.

### Why this one

All three proposals share the same honest ceiling — **reachability mutation stays serial** — because interval allocation is a genuine read-after-write along the DAG (a second child of parent P must observe the first child's just-assigned interval via `interval_remaining_after`, `extensions.rs:35-44`). The differences are in *structure and risk*:

- **Proposal 1 (Topological-level / anti-chain batching).** Highest theoretical compute parallelism but it changes the **crash-consistency unit from one header to a whole level**, and the `ordering-pruning-restart` verifier found that the proposal's own "split a level at a reindex boundary" mitigation **re-introduces a torn-reindex corruption path** that escapes the per-header idempotency model (reindex rewrites *already-committed* rows whose status was set levels ago, so the status short-circuit does not protect them). That is a fixable-but-real footgun on the recovery path, and the win over Proposal 2 is marginal during the *linear* sync that is our actual bottleneck (level width ≈ 1 on the selected chain). **Rejected as the primary structure** — but its group-commit-per-level idea survives as the bounded group-commit sub-layer below.
- **Proposal 3 (Prefetch + group-commit only).** Lowest risk and lowest ceiling: pure I/O amortization, no added CPU parallelism, and at the steady tip it is a no-op. **Not rejected — absorbed.** Its two layers (look-ahead prefetch; group-commit with reindex/HST-advance barriers) are precisely the parts of the committer that are safe and high-value, so we adopt them *inside* Proposal 2's committer.
- **Proposal 2 (dedicated committer lane).** Keeps **per-header (or bounded per-group) single-`WriteBatch` atomicity** — i.e. I4/I6 are preserved by construction, the crash unit does not silently grow to a whole DAG frontier — while still lifting *all* CPU + random-read work (validation, PoW, GHOSTDAG, prefetch) off the lock-held path so N−1 cores run ahead of one committer. Four independent verifier lenses (determinism ×1 **sound**, reachability-integrity ×1 fixable, ordering-pruning-restart ×1 fixable) converged on the **same single fix**, which means the risk surface is small and well-understood.

### The verdict-driving decision: when `end()` fires

Every "fixable/fatal-but-fixable" verdict against Proposal 2 and Proposal 3 reduces to one thing: **`task_manager.end()` must fire only *after* the header's batch is durably written, never on enqueue into the committer.** The determinism verifier (Proposal 3 lens) states it bluntly: releasing dependents on enqueue lets a child run GHOSTDAG against a parent whose rows are not yet in the committed store → `KeyNotFound` panic at best, a timing-dependent **divergent-`GhostdagData` fork** at worst. We adopt this as a **hard, asserted invariant**, not a comment. This single rule is what makes the design `sound` rather than `fixable`. Everything else (prefetch discipline, group-commit barriers, pruning-lock span) follows from it.

**What we reject outright:** any scheme that (a) makes the GHOSTDAG read path consult an in-flight staging store, or (b) parallelizes the reachability mutation itself, or (c) releases dependents before durable commit. All three break I2/I3.

---

## 4. Concrete mechanism

### 4.1 The compute-parallel / commit-serial boundary

Today `queue_block` (`processor.rs:241-267`) runs `try_begin → process_header (validate + commit) → end` on one rayon task. We split it at the `validate | commit` seam:

```
                       block_processors_pool (rayon, = #cores)
  receiver ──► worker ──► [Phase A: validate + ghostdag + prefetch]  (N workers, no write locks)
   (serial)   (serial)            │  produces a fully-populated HeaderProcessingContext
                                  ▼
                       bounded crossbeam channel  (back-pressure)
                                  ▼
                  [Phase B: ReachabilityProcessor]  (exactly ONE thread)
                    per ctx (or per bounded group), in arrival order:
                      add_block → HST RMW/hint → relations/statuses → staging.commit → db.write
                      then, AFTER db.write: task_manager.end(ctx)   ◄── the load-bearing rule
```

- **Phase A (parallel, unchanged math).** A byte-for-byte move of the existing `validate_header` body (`processor.rs:300-311`): `validate_header_in_isolation` + PoW, `validate_parent_relations`, `build_processing_context`, `ghostdag()`, `pre_pow_validation`, `post_pow_validation`. It writes nothing to shared stores; output is a `HeaderProcessingContext` carrying `ghostdag_data`. **New, additive:** it also (1) materializes `ghostdag_data.unordered_mergeset_without_selected_parent()` (the reachability mergeset, already cheap) and (2) issues read-only **prefetch** (§4.3). Phase A runs concurrently for any antichain of parent-committed headers — exactly today's parallelism, now never interleaved with a held write lock.
- **Phase B (serial, single thread = the committer).** Consumes contexts in channel-arrival order, which under the `end()`-after-commit rule is a **total topological order** (a child cannot finish Phase A before its parents are even enqueued, and parents commit before the child is admitted). It runs the *verbatim* `commit_header` body, now never contended on `upgradable_read` because there is exactly one writer. After `db.write` returns, it calls `end()` for the just-committed header(s), which (a) releases dependent tasks and (b) forwards full blocks to `body_sender`.

### 4.2 Why the read path is correct (no in-flight staging visibility)

Critically, GHOSTDAG and incest checks read the **global committed** stores via `MTReachabilityService` (`reachability.rs:106-108`, fresh `self.store.read()` per query) and the bare `ghostdag_store`/`relations_store` — they have **no access** to the committer's private `StagingReachabilityStore`. Therefore a header is only safe to admit to Phase A once its parents are in the *committed* `DbReachabilityStore`/`DbGhostdagStore`. The `end()`-after-`db.write` rule guarantees exactly that: by the time `try_begin` admits a child (I2), every parent's batch has flushed and its write-through caches (`access.rs:140`) are populated. This is why we must **not** consult staging on the read path and must **not** release on enqueue.

### 4.3 Look-ahead / prefetch window

For a header whose parents are known (at `register` time, before fan-out), every key GHOSTDAG/reachability will read is statically derivable: parents' compact `get_blue_work`; parents' `ReachabilityData` (interval/parent/height); parents' `relations`; and a **bounded depth-D walk** (default D=64) of the selected-parent chain's full `GhostdagData` (the `get_data` walk at `protocol.rs:280`, the dominant random-read source). Prefetch issues one batched `multi_get` per key set, then calls each store's existing `read()` once so values land in the per-store write-through cache (`access.rs:62`). The mergeset-blues `get_bits` reads are *not* statically known (blue set is only known post-coloring) and are left cold — stated honestly.

**Prefetch discipline (hard rules, asserted/documented):**
1. **Cache-warming only.** Prefetched values are never fed into any value-producing computation; GHOSTDAG re-reads under the live lock. A stale/missing prefetch is therefore harmless (the real read recomputes).
2. **Misses are no-ops.** `prefetch_many` must swallow `KeyNotFound`/deserialize errors (collect hits only) — it must **not** `.unwrap()`, or racing ahead of the committer panics the node.
3. **Never prefetch a mutable-in-flight row.** Restrict to immutable committed-ancestor rows (interval/height/FCS/ghostdag). **Never** prefetch the *children-set* of a block that can still be an in-flight `selected_parent` (Phase B `append_child` mutates it, `tree.rs:21`).
4. **Fire-and-forget on the pool**, never inline in `worker()`, never holding `reachability.upgradable_read()`.

### 4.4 Group-commit (optional sub-layer of Phase B)

Because each header's writes are already one `WriteBatch`, Phase B may accumulate up to **K** topo-adjacent headers (default K=64) into one `WriteBatch` + one `db.write`, holding **one** `StagingReachabilityStore` across the group's `add_block` calls (so intra-group reads hit the staging map's `Occupied` branch). This amortizes the fsync and the lock-upgrade K-fold. Atomicity is **upgraded to per-group**, all-or-nothing.

**Mandatory group barriers (flush-before, so each persisted batch is prefix- and index-consistent):**
- **Drain-flush:** when the channel is empty, flush immediately → steady tip-follow degrades to per-header commit (no latency or crash-window regression at the tip).
- **Reindex barrier:** if `add_tree_block` is about to hit `remaining.is_empty()` (`tree.rs:23`), flush the current group *first*, then run the reindex as its own isolated batch. **Never** flush partway through a single `add_block`'s reindex — a reindex rewrites *already-committed* rows (`reindex.rs` `propagate_interval`), so a torn reindex corrupts durable state outside the status short-circuit (I3/I6). The legal split granularity is a **fully-committed member boundary**, never inside one member's `add_block`.
- **HST-advance / reindex-root barrier:** any header that advances HST or triggers `hint_virtual_selected_parent → concentrate_interval` (`processor.rs:402`) must carry its `staging_reindex_root` write (`reachability.rs:434-436`) in the *same* batch as the member that produced it, applied in ascending `(blue_work, hash)` order. Simplest safe rule: treat reindex-root advancement as a group barrier too.

### 4.5 Pruning-lock span

`process_header` holds `pruning_lock.blocking_read()` across validate+commit today (`processor.rs:270`). Phase B must hold a single `pruning_lock.blocking_read()` guard across its **entire** group commit (mirroring today's span at group granularity), so a pruning epoch (`pruning_processor` takes `blocking_write`, mutates reachability via `delete_block`) can never interleave between two members of a group. Pruning already yields cooperatively, and K is capped, so starvation stays bounded. The `staging.commit` upgrade (`reachability.rs:411`) already serializes Phase B against any other reachability writer; the only remaining obligation is that pruning takes that same write lock — which it does.

---

## 5. Exact code-change sites

| File:line | Change |
|-----------|--------|
| `consensus/src/pipeline/header_processor/processor.rs:216-239` (`worker`) | Reception stays single-threaded. After `register` returns `Some(task_id)`, optionally spawn `prefetch_for(header)` fire-and-forget on the pool. Rework the `Exit` path: on `Exit`, `wait_for_idle` must now mean "Phase A drained **and** the committer channel drained **and** every queued ctx committed," then forward `Exit` to `body_sender`. (Verifier-flagged: an unspecified drain loses uncommitted headers on clean shutdown.) |
| `consensus/src/pipeline/header_processor/processor.rs:241-267` (`queue_block`) | Split: run `try_begin` + Phase-A compute (`process_header`'s validate half + ghostdag + mergeset materialization + prefetch); **do not** call `commit_header` inline (remove the `:284` Ordinary commit). Send the populated ctx to the committer channel. **Do not** call `end()` here — `end()` moves to Phase B. |
| `consensus/src/pipeline/header_processor/processor.rs:269-311` (`process_header`/`validate_header`) | Return a fully-populated ctx for the Ordinary path without committing; keep the status short-circuit (`:272-278`) and `StatusInvalid` set-on-failure (`:307`) unchanged. Trusted path (`:286-289`) is **not** routed through the committer lane (see below). |
| `consensus/src/pipeline/header_processor/processor.rs:359-433` (`commit_header`) | Move this body **verbatim** into `ReachabilityProcessor::commit` (single thread). The `upgradable_read` (`:389`), `add_block` (`:392`), HST RMW/hint (`:396-404`), relations/reachability_relations/statuses (`:410-417`), `staging.commit` (`:422`), `db.write` (`:425`), guard drops (`:428-432`) are unchanged. Add the optional group loop with the §4.4 barriers and one shared `StagingReachabilityStore` per group. Hold `pruning_lock.blocking_read()` across the whole group. |
| `consensus/src/pipeline/header_processor/processor.rs` (struct + `new`, ~`:96-214`) | Add committer channel handle + group threshold K, prefetch depth D. New `prefetch_for` and `group_commit_run(Vec<ctx>)`. |
| `consensus/src/pipeline/header_processor/mod.rs` (+ new `reachability_processor.rs`) | New `ReachabilityProcessor` module owning the single Phase-B thread + its **bounded** input channel; wired between the header pool and `body_sender`. |
| `consensus/src/pipeline/deps_manager.rs:239-265` (`end`) | **The load-bearing change.** `end()` (which removes the header from `pending` `:252`, releases `dependent_tasks`, and forwards full blocks to `body_sender` via the callback `:255-256`) must be invoked **by Phase B after `db.write`**, not by Phase A. The body-forward + result-send + dependent-release + commit become inseparable on the committer thread. Re-plumb `wait_for_idle` (`:268-273`) so "idle" = "committed," and the same-hash FIFO requeue (`:252`, returns `task_id`) is also Phase-B-driven (else two same-hash tasks race in Phase A; `reachability.rs:460` insert would collide). |
| `consensus/src/consensus/mod.rs:204-282` | Add the Phase-A→Phase-B **bounded** crossbeam channel and spawn the single committer thread (mirroring the `worker()` spawn). `block_processors_pool` keeps running Phase A; the committer is **one dedicated thread, not a rayon pool** (single-consumer keeps `upgradable_read` uncontended and the order topological). No new pool sizing needed. |
| `consensus/src/processes/ghostdag/protocol.rs:126-166` | **No change** to the algorithm — it is moved (not edited) into Phase A. Listed so the reviewer confirms byte-identical math (the shadow-validation in §7 asserts this). |
| `consensus/src/processes/reachability/inquirer.rs:24-50` (`add_block`) | **No algorithm change.** Still called once per header in topological order inside the committer; only the call site moves to the per-group loop. |
| `consensus/src/model/stores/reachability.rs:389-438` (`StagingReachabilityStore`) | **No algorithm change.** Lifetime now spans a group; confirm `staging_writes/children/fcs` already serve intra-group reads-of-just-staged nodes (they do — `set_interval`/`append_child`/`insert_future_covering_item` read staging-first). Add a debug `validate_intervals(reindex_root)` at each group boundary (the test path at `inquirer.rs:465` already exists). |
| `consensus/src/model/services/reachability.rs:100-131` | Add a batch-prefetch helper (one `.read()` guard warming a header's SP interval/children/height + mergeset FCS) for Phase A. Reads only — query semantics unchanged. |
| `database/src/access.rs:134-143` | Add `prefetch_many(keys)` on `CachedDbAccess`: one rocksdb `multi_get` over `self.prefix`, insert hits into `self.cache`. **Ignore per-key misses.** Pure cache-warming. |
| `consensus/src/consensus/storage.rs:47-49` (+ cache budgets) | Optionally raise reachability_data / reachability_sets / ghostdag_compact / ghostdag_full cache budgets so the active IBD frontier + selected-parent prefix survives eviction long enough for the committer to consume prefetched rows. Under-sizing only loses the win — never corrupts. |
| `consensus/core/src/config/constants.rs:107` (`DEFAULT_REINDEX_SLACK`) + `perf.rs` | Optional consensus-neutral perf knobs: `group_commit_max_headers` (K=64), `prefetch_chain_depth` (D=64); optionally widen reindex slack during IBD to make reindexes rarer on the now-bottleneck committer. **Intervals are store-local, not in any block hash** — these do not touch genesis or I1. |

---

## 6. Invariant-preservation argument (addressing every verifier verdict)

**I1 — Determinism.** GHOSTDAG is a verbatim move of `protocol.rs:126-166`. Output is integer-only with total tie-breaks (`SortableBlock(blue_work, hash)`), and the mergeset is collected as an unordered set then **re-sorted** by `(blue_work, hash)` before coloring (`ordering.rs:45-50`) — erasing all HashMap/BFS iteration-order non-determinism. The determinism verifier returned **sound** for this proposal and confirmed no float enters the consensus path (the only floats, in `interval.rs` allocation, produce node-local interval *numbers* that are **not** consensus state; only the boolean relations they encode matter, and those are deterministic because tree edges = `selected_parent` and FCS membership = mergeset, both unchanged). The two `fixable_concerns` it raised are addressed here: (a) `end()` fires after commit (§4.1, §5), guaranteeing every GHOSTDAG input is committed and final — this is the single happens-before edge the whole no-fork argument rests on; (b) prefetch is cache-warming only and never feeds a value-producing path (§4.3 rule 1).

**I2 — Topological order.** `try_begin` (`deps_manager.rs:225-230`) is preserved exactly. The reachability-integrity and ordering verifiers both flagged that the *meaning* of "parent left `pending`" must stay "parent durably committed." We pin it: `end()` (the sole `pending`-remover) is called by Phase B *after* `db.write`. A debug assertion at the top of Phase A checks every `direct_parent` has a committed ghostdag entry + `has_reachability_data`. The same-hash FIFO requeue is also Phase-B-driven so two same-hash tasks never co-run in Phase A.

**I3 — Reachability integrity.** The mutation stays **single-threaded and in topological order** — exactly today's guarantee, now never contended. The sibling read-after-write (`interval_remaining_after` reads the last appended child, `extensions.rs:35-44`) is honored because the committer applies siblings serially. Intra-group reads hit the one shared `StagingReachabilityStore`. Reindex stays an isolated exclusive epoch; the **torn-reindex** path the verifiers warned about is forbidden by the §4.4 rule "never flush partway through one `add_block`'s reindex; split only on a fully-committed member boundary." `validate_intervals` runs at each group boundary in debug.

**I4 — Cross-store atomicity.** One `WriteBatch` + one `db.write` per header (or per group), guards dropped only after the flush — moved verbatim. status is written in the same batch as ghostdag/reachability/relations, so status-present ⇒ all-present. Prefetch never writes; it only fills read-caches with immutable, write-once-keyed values, so it can never shadow a newer value (committed keys have none).

**I5 — Selected-tip / reindex-root / pruning.** HST RMW + `hint_virtual_selected_parent` run per-header in ascending `(blue_work, hash)` order on the single committer, with the reindex-root write bundled into the same member's batch (§4.4). Pruning holds the reachability write lock and Phase B holds `pruning_lock.blocking_read()` across the whole group (§4.5), so pruning's interval redistribution never interleaves with header allocation.

**I6 — Restart/crash recovery.** Crash between Phase A and Phase B loses zero writes (Phase A is read-only) → the lost header re-syncs and the status short-circuit (`processor.rs:272-278`) re-processes it cleanly. Crash mid-group loses the **whole** group atomically (one `WriteBatch`) → prefix-consistent, never torn, idempotently replayable. The drain-flush rule bounds the crash window to ≤K headers and makes the steady tip per-header-atomic. The reindex/HST barriers keep `reindex_root` always pointing at a block whose interval is present in the same flush. The genesis guard (`consensus/mod.rs:304-306`) is untouched (`past_pruning_points[0]` is genesis-only). **Shutdown:** the `Exit` handshake (§5) drains the committer before forwarding `Exit`, so a clean shutdown loses no uncommitted header — the one *fatal-but-fixable* gap the ordering verifier raised against Proposal 2 is closed here.

---

## 7. Rollout plan

**Feature flag.** `parallel_header_commit` (config/perf flag, default **off**). Off ⇒ today's inline `queue_block → process_header → commit_header → end` path, byte-for-byte. On ⇒ the Phase-A/Phase-B lane. Group-commit (K>1) and prefetch (D>0) are independent sub-flags so they can be enabled incrementally.

**Shadow-validation mode** (`shadow_validate_reachability`, the trust-building gate before we rely on the new path):
- Run **both** paths. The new lane computes and commits; in parallel, a shadow committer (or an in-process replay) recomputes `GhostdagData` and the reachability mutation for the same header via the **old serial code** against the same committed snapshot.
- **Assert byte-identical** `GhostdagData` (`selected_parent`, ordered `mergeset_blues`, `mergeset_reds`, `blues_anticone_sizes`, `blue_score`, `blue_work`) — this is the I1 gate.
- **Assert identical boolean reachability:** for a sampled set of ancestor pairs, `is_dag_ancestor_of` / `is_chain_ancestor_of` agree between the two paths. (Interval *numbers* may legitimately differ if allocation order ever diverges — assert the *relations*, not the raw intervals, per the determinism verifier's note that the `(blue_work,hash)` commit order is efficiency/recovery-relevant, not determinism-relevant.)
- **Assert per-(group) atomicity** with a fault-injection harness: `kill -9` mid-group and on restart verify (1) no header has a committed status without a committed reachability interval, (2) `reindex_root` resolves to a block whose interval is present, (3) clean idempotent re-sync.
- Any mismatch ⇒ hard `panic!` with the offending hash; ship with shadow on for the first soak, then flip off once a full mainnet/testnet header-sync passes mismatch-free.

**Regression gate (must be green before merge):** existing `consensus-core` `test_genesis_hashes` (genesis **UNCHANGED** — this design touches no block-hash input), `pos_v2_*`, `dns_overlay_*` suites; a new test replaying a long parent→child header chain with K=1 vs K=64 asserting byte-identical reachability + `GhostdagData` + final HST; a pruning-interleave test; a kill-mid-group restart test.

**Benchmark/measurement plan** (this is the measurement `processor.rs:387` asks for):
1. **Instrument first, before any code change:** add timers for (a) time-in-`commit_header` held-lock, (b) `add_block` excl. reindex, (c) reindex bursts, (d) `db.write` fsync, (e) Phase-A compute, per header. This tells us the **actual** serial fraction *f* = reachability-mutation-time / total.
2. Measure on the real kaspa-pq Hash64 chain (testnet, the live mesh) and a synthetic wide-DAG fixture (to exercise antichain width).
3. Report: headers/sec for {baseline, prefetch-only, prefetch+group-commit, full lane} at 1/2/4/8/#cores; held-write-lock p50/p99; cache hit-rate on the SP-chain `get_data` walk; reindex frequency.
4. Accept the lane only if it beats baseline **and** shadow-validation is mismatch-free **and** RPC/virtual-processor `is_dag_ancestor_of` p99 latency does not regress (the held-lock window now amortizes K headers — confirm K is capped low enough).

---

## 8. What we deliberately keep serial — the honest Amdahl ceiling

**Kept serial (mandatory, not incidental):**
- The entire reachability mutation: `add_tree_block` interval allocation (sibling read-after-write via `interval_remaining_after`), `add_dag_block` FCS insertion (sorted binary-search per mergeset member), `reindex_intervals`, `concentrate_interval`/reindex-root advance — all on **one** committer thread in topological order.
- The HST RMW and the single-`WriteBatch` atomic multi-store commit.
- The topological happens-before edge along every DAG edge (I2) — this is what makes Phase A's parallel reads valid; it cannot be relaxed.
- Trusted/pruning-proof headers (`commit_trusted_header`, `processor.rs:435-455`) route through their existing idempotent, reachability-free path — **never** into the committer lane.

**Residual ceiling (Amdahl).** Speedup is bounded by *f*, the serial reachability-mutation fraction. Honest expectations:
- **Linear selected-chain sync (our measured bottleneck, antichain width ≈ 1):** the win is almost entirely **group-commit + prefetch** — N per-header lock-upgrades + N fsyncs collapse to one per group, and the SP-chain `get_data` random-read walk becomes cache hits. Realistic **~1.5–3×** on the commit/IO path. There is essentially **no** added CPU parallelism here because width is 1.
- **Wide-DAG frontier sync (antichain width W):** Phase-A GHOSTDAG/PoW/validation scales toward `min(W, #cores)`, and the serial reachability tail (assumed << header time, *to be confirmed by §7's instrumentation*) becomes the residual.
- **If instrumentation shows reachability mutation is *not* << header time** (e.g. reindex bursts dominate on the Hash64 chain), Phase B is the hard ceiling and the lane collapses toward the Phase-A fraction. That is the honest failure mode, and it is exactly why §7 measures *f* **before** we commit to the full lane. We do **not** promise core-count scaling; the realistic, defensible win is the I/O-amortization + prefetch path, which is real, low-risk, and a no-op at the tip.

The bottleneck deliberately **shifts** from per-header lock+fsync serialization to the genuinely-serial reachability mutation — which is the correct place for it to land.

---

## 9. kaspa-pq specifics: the Hash64 2× I/O amplification

This fork uses 64-byte `Hash64` (e.g. `utxo_commitment → Hash64`, `mass txid 32→64`), so every reachability/ghostdag **key** is 64 bytes instead of 32. The consequences and how the design interacts:

- **Larger keys ⇒ heavier rocksdb random point-reads** — the exact bottleneck half the prompt names. The `get_data`/`get_blues_anticone_sizes` SP-chain walk (`protocol.rs:242,280`) and `is_dag_ancestor_of` interval gets each move ~2× the key bytes through rocksdb's block cache and comparator. **Prefetch (§4.3) is therefore higher-value on this fork than on upstream:** converting the O(mergeset × chain-depth) random point-reads into a few batched `multi_get`s amortizes the doubled per-key cost. This is the single biggest concrete win for kaspa-pq specifically.
- **Larger keys ⇒ bigger per-store caches needed for the same hit-rate.** The `storage.rs` cache-budget bump (§5) should account for ~2× bytes-per-entry so the active IBD frontier + SP prefix still fit; otherwise prefetched rows evict before the committer consumes them (correctness-neutral, but the win evaporates). Size budgets in **bytes**, not item counts.
- **Larger `WriteBatch` payloads ⇒ group-commit is more valuable.** Each `db.write` already carries 2× key bytes across ghostdag(full+compact) + reachability(interval/children/FCS) + relations + status; amortizing the fsync over K headers (§4.4) is a larger absolute saving here than upstream.
- **Interval values are unaffected by Hash64.** Reachability intervals are `u64` numbers independent of hash width and remain node-local non-consensus state — so the Hash64 change does not interact with I1/I3 correctness at all, only with the I/O cost the design targets. The `(blue_work, hash)` tie-break now compares 64-byte hashes, but it is still a total order (the determinism verifier's argument is hash-width-agnostic), so I1 holds unchanged.

**Net for kaspa-pq:** the Hash64 amplification makes the **read-side prefetch + group-commit** the dominant lever and the **parallel-compute** lever secondary — reinforcing the §8 conclusion that the realistic, honest win on this fork is I/O amortization, with core-scaling only on genuinely wide DAG frontiers.

---

**Files referenced (all absolute):** `/Users/wata/Downloads/rusty-kaspa-master 2/consensus/src/pipeline/header_processor/processor.rs`, `…/consensus/src/pipeline/deps_manager.rs`, `…/consensus/src/processes/ghostdag/protocol.rs`, `…/consensus/src/processes/ghostdag/{mergeset,ordering}.rs`, `…/consensus/src/processes/reachability/{inquirer,tree,reindex,extensions}.rs`, `…/consensus/src/model/stores/reachability.rs`, `…/consensus/src/model/services/reachability.rs`, `…/consensus/src/consensus/{mod,storage}.rs`, `…/consensus/core/src/config/{constants,perf}.rs`, `…/database/src/access.rs`.

---

## 10. Measured results (§7-1 instrumentation, 2026-06-14)

The §7-1 instrumentation was implemented (consensus-neutral timers in `counters.rs` / `header_processor/processor.rs` / `monitor.rs`, logging `[ibd-perf]` every 10 s) and run on a **fast node** (`.213`, local NVMe, ~9 ms RTT to the sync source, **~1000 headers/s** — i.e. the CPU/commit-bound regime, the regime relevant to this decision) on the canonical SHA3 testnet (`512e7424`), `--rocksdb-preset hdd`, fresh IBD up to DAA ≈ 110 k (10 %). Per-header averages:

| depth | validate(A) | commit(serial) | add_block | db.write | held-lock | **f_serial** | **f_reach** | parallelize-ceiling |
|------|------|------|------|------|------|------|------|------|
| DAA ~50k  | 368 µs | 458 µs | 44 µs  | 186 µs | 373 µs | 0.554 | 0.053 | 1.80× |
| DAA ~80k  | 377 µs | 551 µs | 64 µs  | 209 µs | 449 µs | 0.594 | 0.069 | 1.68× |
| DAA ~110k | 397 µs | 779 µs | 126 µs | 253 µs | 622 µs | 0.663 | 0.107 | 1.51× |

(`f_serial = commit / (validate + commit)`; `f_reach = add_block / (validate + commit)`; ceiling `= 1/f_serial` = the Amdahl bound on parallelizing Phase-A only. Per-header total ≈ validate + commit ≈ 0.97 ms → ~1030 headers/s, matching observed throughput, confirming antichain width ≈ 1 on linear sync.)

### What the data says — and how it revises §3 and §8

1. **The full compute-parallel LANE (Proposal 2) is NOT worth its complexity.** `f_serial` is **0.55→0.66 and rising with depth**, so the Amdahl ceiling from parallelizing Phase-A is only **1.5–1.8× and falling**. Parallelizing the validate phase buys little.

2. **The serial cost is NOT the reachability mutation.** `f_reach` (the genuinely-unavoidable `add_block`) is only **5–11 %**. The §2/§8 worry that the *reachability mutation* is the hard ceiling is **not** what the numbers show at this depth. The serial committer is dominated instead by:
   - **`db.write` (~190–250 µs)** — the single largest serial component, and
   - the **lock-held bookkeeping** (HST + relations + reachability_relations + statuses + `staging.commit`), ≈ `held-lock − add_block − db.write` ≈ 150–240 µs.

3. **Therefore the high-value, low-risk lever is GROUP-COMMIT (§4.4), not the lane.** Batching K topo-adjacent headers into one `WriteBatch` + one `db.write` under one held `StagingReachabilityStore` directly amortizes the dominant serial cost (`db.write` + the per-header lock-acquire/`staging.commit`/WAL boundary) K-fold, with **no change to the GHOSTDAG or reachability algorithms**. Prefetch (§4.3) additionally targets the stable ~370 µs `validate` phase (the GHOSTDAG SP-chain `get_data` reads). This is exactly the I/O-amortization path §8 predicted would be the realistic win — the data confirms it and **demotes the parallel-compute lane to optional**.

### Revised recommendation

- **Implement group-commit + prefetch** (the §4.4 / §4.3 sub-layers) behind the feature flag, **skip the parallel Phase-A fan-out** initially (low ceiling here). The committer is still a single dedicated lane — but its justification is **fsync/lock amortization**, not compute parallelism.
- **Caveat — re-measure deeper.** `f_reach` is **rising** (0.053 → 0.107 as DAA went 50k→110k; `add_block` 44→126 µs as reindex bursts grow on the Hash64 DAG). The 10 %-depth snapshot may understate the reachability-mutation fraction at full chain depth. Before committing to a final K and to confirm group-commit doesn't just shift the ceiling onto `add_block`, re-run the instrumentation at DAA ≳ 1 M (the §8 "reindex dominates" failure mode). The instrumentation is permanent and consensus-neutral, so this is a free ongoing measurement.
- **Cold-cache / slow-disk nodes (e.g. `.186`, EU, throttled volume):** there `db.write` + the GHOSTDAG reads are even heavier, so group-commit + prefetch help *more* — but those are I/O-bound, not the regime this `.213` run measured.

### 10.1 Group-commit was implemented and live-validated — and it does NOT help (decisive)

The group-commit lane was implemented behind `header_group_commit_size` (`--header-group-commit-size`, default 1 = legacy inline path), and **validated live on `.213` with K=64**, fresh IBD of the canonical SHA3 chain (`512e7424`):

| metric | K=1 (legacy) | **K=64 (lane)** | verdict |
|------|------|------|------|
| `db.write` / header | ~200 µs | **~200–306 µs (unchanged)** | **NOT amortized** |
| `commit(serial)` / header | ~600 µs | ~576–766 µs (unchanged) | unchanged |
| `f_serial` | 0.55–0.66 | **0.55–0.63 (unchanged)** | unchanged |
| genesis / chain | `512e7424` | **`512e7424` — converged on canonical** | ✅ consensus-equivalent |
| errors | — | **0 panics / 0 wrong-version / 0 invalid-pow** | ✅ correct |

**The lane is consensus-correct (synced the canonical chain to 8 % with zero errors, antichain invariant held) but delivers ZERO speedup**, because of a fundamental property:

- A group is always an **antichain** (the end-after-commit rule means a child is not released for Phase-A validation until its parent has committed — that is what makes the lane safe).
- **During linear selected-chain sync the antichain width is 1.** Each header's Phase-A validation reads its parent's **committed** GHOSTDAG (`ghostdag_store.get_data(parent).unwrap()`); it cannot run until the parent is committed. So the committer's channel never holds more than ~1 ready header → **the group size is effectively 1** → one `db.write` per header → no fsync/lock amortization.

The very antichain constraint that guarantees safety also guarantees width-1 (hence un-batchable) on the linear sync that *is* the bottleneck. Batching only fills on a genuinely wide DAG frontier (the bounded headers-proof/anticone phase), a negligible fraction of IBD.

### 10.2 Final conclusion — the per-header commit chain is irreducibly serial

Neither lever helps the dominant workload:
- **Compute-parallel lane:** Amdahl ceiling 1.5–1.8× (§10), and even that is unreachable on linear sync (width 1 ⇒ validate is also serial).
- **Group-commit:** zero amortization on linear sync (groups stay size 1, §10.1).

`validate (~450 µs) + commit (~600 µs) ≈ 1 ms/header`, **all serial** because each header's validation depends on its parent being committed. The measured **~1000 headers/s is a hard ceiling for linear IBD on this node that batching/parallelism cannot break.**

**Recommendation:** do **not** deploy the group-commit lane (keep the flag default-off, or revert the lane; the change is contained). **Keep the §7-1 instrumentation** (consensus-neutral, permanently measures `f`). Real IBD speedups must attack the *per-header* cost or the *header count*, not parallelism:
1. **Cheaper `db.write`** — investigate why ~200 µs for ~10 small KV writes (BlobDB/hdd-preset overhead? try the default preset; consider `disableWAL` during IBD since headers are peer-replayable; fewer/cheaper store writes per header).
2. **Cheaper `validate`** — prefetch/cache the GHOSTDAG SP-chain `get_data` reads (the §4.3 prefetch sub-layer is still worthwhile, independent of the lane).
3. **Fewer headers** — as the chain ages past the pruning depth, IBD starts from a recent pruning point instead of genesis (self-resolving; the current full-1.4 M-header sync is the young-chain worst case).
4. **Operational** (highest leverage, already done): keep ≥1 fully-synced canonical node externally reachable so joiners IBD only the recent gap, not the whole chain.

**Process note:** this negative result is the *value* of the instrument→measure→implement→validate loop — it prevented shipping a complex consensus-critical optimization that the measurements prove does not work for the real workload.

### 10.3 Final code state

Per the negative result, the group-commit lane was **reverted** (2026-06-14):
- **Kept:** the §7-1 instrumentation — `ProcessingCounters` `hdr_*_ns` timing fields (`consensus/core/src/api/counters.rs`), the per-span timers in `header_processor/processor.rs` (`process_header` ordinary branch + `commit_header`), and the `[ibd-perf]` per-header serial-fraction log in `consensus/src/pipeline/monitor.rs`. Consensus-neutral; lets any node print `f_serial` / `f_reach` / parallelize-ceiling every 10 s indefinitely.
- **Reverted:** the committer-thread lane in `processor.rs`, the `header_group_commit_size` `PerfParams` field + `PERF_PARAMS` default, the `HeaderProcessor::new` wiring in `consensus/src/consensus/mod.rs`, and the `--header-group-commit-size` CLI flag in `kaspad/src/args.rs`. `cargo check -p kaspa-consensus` clean post-revert.
- **Kept:** this document, as the record of the design + the decisive measurement.