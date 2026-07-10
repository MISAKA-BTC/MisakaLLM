# Testnet filler-block A/B — the live-topology half of ADR-0036 §5

> **Reference tree:** `feat/mil-v0` @ `d6e8297`. Design doc; execution is a gated,
> mesh-coordinated testnet operation (requires user go — it deliberately stresses
> propagation and needs every mesh node on the cap-raised build).

## 0. Why this exists — what simpa could not measure

simpa's `--delay` is a **fixed, size-independent** synthetic latency, so it proved
the DAG-topology half: `reds = 0` until concurrency ≈ `k = 447` (delay ≈ 11 s @ 40
BPS), i.e. **oversized blocks do not orphan** (ADR-0036 §5). What it *cannot* model
is the physical link: on the live net a block's propagation delay is
`latency + size / bandwidth`, so a 256–512 KiB block is genuinely slower to
propagate than a 32 KiB one — and that size→delay→mergeset chain is what this A/B
measures on the **real DE↔JP topology**, where bandwidth (not synthetic delay) bites.

**Hypothesis to falsify:** raising per-block size does *not* raise reds (simpa),
but it *does* raise propagation delay super-linearly past some `S*` (bandwidth
saturation), spiking mergeset width and confirmation depth on the slow leg. `S*`
sets the safe per-block ceiling ⇒ validates chunk transport (≤32 KiB, far below
`S*`) over the oversized-section fallback, and pins `β` (ADR-0036 §3.C).

## 1. Topology (the real DE↔JP mesh — this is the point)

| node | geo | role in the A/B |
|---|---|---|
| `160.16.131.119` (Sakura) | **JP** | filler-miner + observer probe |
| `133.167.126.213` (Sakura) | **JP** | observer probe (build/ops box) |
| `95.111.236.186` (Contabo) | **DE** | observer probe (seed) |
| `207.180.230.3` (Contabo) | **DE** | observer probe |

The JP↔DE leg (~230–250 ms RTT) is the network diameter that dominates
propagation; the A/B is meaningless on a single host. All nodes: `kaspad --testnet
--features evm` (the lane is active at DAA 867197 — an evm-less build dies), and on
the 7.8 GB boxes use `--ram-scale=0.3`.

## 2. Injection mechanism

Two knobs; both are **testnet param overrides (reversible, non-genesis** — params
are not genesis inputs, per the Stage A/B precedent), rolled mesh-wide:

- **Size cap.** `max_block_mass` is the per-block ceiling (Stage B testnet =
  `125_000`). To inject oversized blocks it is raised mesh-wide to admit
  `S ∈ {64, 128, 256, 384, 512} KiB`. **Every mesh node must run the raised build**
  — a non-updated peer *rejects* the oversized block, which is itself the exhibit
  for "oversized needs a consensus change," whereas chunk transport does not.
- **Filler traffic.** `rothschild --payload-size <bytes>` (native-tx payload
  padding — the same lever simpa's `long_payload` used) fills each block to the
  target `S`. Point it at the JP filler-miner's RPC; size `payload-size × txs/block`
  to hit `S`.

Two arms:

- **A (chunk-spread, the chosen design):** cap at Stage B; run rothschild at a DA
  *rate* equal to the shielded lane's amortized `β·E` but spread across normal
  ≤32 KiB blocks (no single block oversized). Establishes the baseline.
- **B (oversized-section fallback):** cap raised; inject size-`S` blocks at a
  matched DA rate, for each `S`. Measures the per-block-size penalty.

## 3. Metrics (RPC + a first-seen probe — no DB access)

Per block, from `getBlock(includeTransactions, verbose)` → `verboseData`:

- **mergeset width** = `len(mergeSetBluesHashes) + len(mergeSetRedsHashes)`.
- **red rate** = `len(mergeSetRedsHashes) / mergeset` (the simpa metric, now on real
  latency), plus `isChainBlock` churn (selected-parent reorg proxy).

Propagation delay needs a **first-seen probe** (small tool to build, §6): a wRPC
client subscribing to `blockAdded` on **each geo node**, logging
`(block_hash, local_monotonic_recv_time)`. Then per block:
`prop_delay = max_over_nodes(recv_time) − min_over_nodes(recv_time)` (the
diameter-spanning delay). Also record: block bytes, blocks/s, DAA-score rate
(are blocks keeping up), and node-log reject/orphan counts.

## 4. Protocol

1. **Warm-up:** mesh synced at 40 BPS Stage B; confirm baseline `reds ≈ 0` matches
   simpa. Probes running on all 4 nodes, clocks NTP-synced (or use relative
   first-seen deltas to avoid clock skew).
2. **Arm A (baseline), 30 min:** rothschild at DA rate `β·E`, normal blocks. Record
   the distribution of prop_delay, mergeset width, reds, blocks/s.
3. **Arm B sweep, 15 min per `S` ∈ {64,128,256,384,512} KiB:** cap raised, inject
   size-`S` blocks at the matched rate. Record the same.
4. Repeat at the highest live BPS (40 = Stage B). 50 BPS is Stage C (not yet live);
   model it from the 40-BPS curve + the `1/interval` scaling, or defer to Stage C.

## 5. Acceptance — what an envelope breach looks like

- **Confirming simpa:** if reds stay ≈ 0 across all `S` (prop_delay stays below the
  `k`-margin), the DAG is robust to size — the bind is bandwidth, not orphans (as
  ADR-0036 §5 concluded). Expected.
- **The breach signature (the number we want):** `prop_delay(S)` is ~flat then turns
  **super-linear** past `S*` (the point where `S / bandwidth` dominates latency);
  at/after `S*`, blocks/s drops below BPS (DAA lag), mergeset width spikes, and reds
  begin appearing on the DE↔JP leg. `S*` (in bytes, and as `S*·BPS` vs `E`) is the
  deliverable: it is the largest block the mesh absorbs without envelope breach.
- **Decision:** chunk size ≤ 32 KiB sits far below `S*` ⇒ A passes with baseline
  metrics; B at `S ∈ {256,384} KiB` shows a materially worse prop_delay/DAA-lag on
  the JP↔DE leg ⇒ the quantitative case for chunk transport, and `β·E < S*·BPS`
  freezes the windowed budget (ADR-0036 O-DA-2).

## 6. Tooling to build (small, before execution)

- **`first-seen probe`** — a thin wRPC subscriber (reuse the SDK / `misaka` CLI wRPC
  client) that prints `block_hash, recv_monotonic_ns` on `blockAdded`; run one per
  geo node, then a join step computes per-block diameter delay. ~1 evening.
- **`mergeset collector`** — poll `getBlocksByDaaScore` / `getBlock` verbose over the
  window, emit CSV `(daa, size, blues, reds, isChain)`.
- rothschild is already in-tree (`--payload-size`, `--tps`); only config, no code.

## 7. Safety / reversibility

- **Testnet only.** The `max_block_mass` raise is a rolling param override, reverted
  after the run; no genesis change; never mainnet.
- **Mesh coordination is mandatory for Arm B** (all nodes on the raised build) — the
  same roll discipline as a BPS stage; a partial roll turns the A/B into a
  reject-rate test (informative, but not the intended measurement).
- Filler txs spend throwaway testnet coins; the filler-miner is a single JP node so
  the injection point is controlled.
- **Gate:** this deliberately stresses propagation and can degrade the testnet during
  Arm B — run it in a maintenance window with user go, watch the DAA-lag metric, and
  abort (revert cap) if blocks/s falls below a floor.

## 8. Output → back into the ADRs

`S*` and the `prop_delay(S)` curve pin: (a) ADR-0036 `β`/`W` (O-DA-2) against the
*measured* bandwidth headroom, not the derived constant; (b) confirm the chunk-size
choice (≤32 KiB) is comfortably sub-`S*`; (c) the confirmation-depth budget from the
mergeset-width curve. Record them with the reference-commit header, and — per the
process note — **only after ADR-0030+ is pushed to main** so the cap constants the
run assumes are not tree-divergent.
