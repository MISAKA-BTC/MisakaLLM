# ADR-0030: BPS Stage B — testnet-40 Activation

## Status

**Proposed — Stage B activation, 2026-07-07.** Concrete decision to execute the
**second** step of the staged BPS raise frozen in
[ADR-0026](0026-bps-acceleration-ibd-fast-sync.md): **testnet 25 → 40 BPS**
(`k = 288 → 447`, block time `40 ms → 25 ms`), holding the per-second throughput
envelope invariant. This ADR does **not** re-open the design; it selects and
freezes the *Stage B parameter set* and its rollout gates. All "Dn" refer to
ADR-0026's decisions and all "§N / O-n / R-n" to
[`docs/misaka-bps-acceleration-design-v0.1.md`](../misaka-bps-acceleration-design-v0.1.md).

**Builds on:** ADR-0026 (the 10→25→40→50 freeze) and its **Stage A already
implemented** (testnet-25, commit `2949354`): `TESTNET_PARAMS` at
`BlockrateParams::new::<25>()`, `max_block_mass = 200_000`,
`pre_crescendo_target_time_per_block = 40`, `TESTNET_DNS_PARAMS` epoch lengths
`250`, and the global EVM caps at `EVM_GAS_LIMIT = 12M` /
`MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK = 48 KiB`.

**Gate (non-negotiable):** Stage B MUST NOT ship until Stage A has cleared its
ADR-0026 D9 exit gates over a soak ≥ 7 days (mergeset p99/p999 bounded, tips
stable, orphan < 1%, virtual-processing p99 < 40 ms, DAA in band, 60 s-partition
drill auto-recovers, attestation-miss < 0.1%, IBD baseline `B_A` recorded).
Stage B is the **dress rehearsal for Stage C** (the first BPS value beyond the
`ghostdag_k` table, and the first with `k > mergeset_size_limit/2`).

Inherits ADR-0026's three hard preconditions verbatim: (1) envelope invariance is
the safety contract — caps shrink in lockstep; (2) each stage is a barrier
re-genesis on testnet and the caps ride it (no mid-chain cap change, no mainnet
re-genesis); (3) I-2 (`--ibd-trust-dns-finality`) never weakens state validation.
Changes **only** cap/period numbers + the k-table (design NG3): no PoW
(ADR-0007), PQ-signature (ADR-0019), or EVM-semantics (ADR-0020/0023) change.

---

## Context

Stage A (testnet-25) is live and const-derives its DAG params from
`Bps<25>`; `25 => 288` was **already present** in the `ghostdag_k()` match table
(`consensus/core/src/config/bps.rs:42`), so Stage A needed no table change. Stage
B is different in one structural way:

- **`ghostdag_k()` currently ends at `32 => 362`** with `_ => panic!` (`bps.rs:43`).
  `40` is **not** in the table, so `BlockrateParams::new::<40>()` would panic at
  const-eval. **Stage B is the first stage that requires extending the k-table.**
  The frozen value is `40 => 447` (D=5, δ=0.01, x = 2·D·λ = 2·5·40 = 400), from
  the design's appendix A (`calculate_ghostdag_k` ported and validated against the
  existing rows 1→18 / 10→124 / 25→288 / 32→362 before deriving the new ones).
  `KType = u16` and `1000 % 40 == 0` both hold; the f64 `e^-x` limit (BPS ≤ 74)
  is far off.
- The block-built caps do **not** auto-follow BPS and must shrink again (D3); the
  DNS overlay epoch lengths are block-denominated and must scale again (D4); the
  perf/p2p follow-through constants (D5) become materially more relevant at 25 ms
  block time and are set to their program (Stage-C-sized) values now so Stage C
  needs no further perf change.
- Everything else (`merge_depth` / `finality_depth` / `pruning_depth` /
  `coinbase_maturity` / PMT+DAA sample rates / per-block subsidy) is **auto-derived**
  from `Bps<40>` + `bps_history` and needs no manual edit (verified: these are
  const-derived, not literals).

At 40 BPS the block time is 25 ms while worst-case per-node bandwidth stays
~6.4 MB/s and the single-block worst case *shrinks* to ~156 KiB — the same trade
ADR-0026 makes for the whole ladder.

---

## Decision

**B1 — Raise `TESTNET_PARAMS` to `BlockrateParams::new::<40>()` via a barrier
re-genesis** to `NetworkId::with_suffix(Testnet, 40)` → **`testnet-40`** (D1, O7),
structurally isolating the new mesh from `testnet-25`. Full re-genesis checklist
(§4.1): param commit → genesis recompute → seeds/nodes/miners/attestors/faucet/
premine refresh → attestor reboot (epoch-constant reload) → explorer/indexer
window reset → gate measurement start.

**B2 — Extend the `ghostdag_k` table to cover 40** (D2). Minimum diff: add
`33..=40` rows through `40 => 447` to the `bps.rs:40` match (equivalently, widen
`gen_ghostdag_table`'s range and regenerate — same values). Recommended: land the
full `33..=64` drop-in from ADR-0026 appendix A in one edit so **Stage C (50→553)
needs no further k-table change**. The derived DAG params then follow:

| Param | Stage A (25, current) | **Stage B (40)** | Source |
| --- | --- | --- | --- |
| `blockrate` | `new::<25>()` | **`new::<40>()`** | const generic |
| `ghostdag_k` | 288 (in table) | **447** | **table extension (new)** |
| `target_time_per_block` | 40 ms | **25 ms** | `1000/BPS`, `1000 % 40 == 0` |
| `pre_crescendo_target_time_per_block` | 40 | **25** | `= 1000/BPS` (emission held, B6) |
| `max_block_parents` | 16 | 16 | clamp (k/2 = 223 ≫ 16, R1) |
| `mergeset_size_limit` | 512 | 512 | clamp (2k = 894, O2/R2) |
| `merge_depth` | 90,000 | **144,000** | auto (1 h) |
| `finality_depth` | 1,080,000 | **1,728,000** | auto (12 h) |
| `pruning_depth` | 2,700,000 | **4,320,000** | auto (30 h) |
| `coinbase_maturity` | 2,500 | **4,000** | auto (100 s) |
| PMT / DAA sample rate | 250 / 100 | **400 / 160** | auto (window size BPS-invariant) |
| year-1 subsidy / block (sompi) | 148,187,338 | **92,617,087** | `TABLE[0].div_ceil(40)`; per-sec/month unchanged |

**B3 — Envelope-invariant caps shrink 25 → 40** (D3, precondition 1), riding the
re-genesis. These are the block-built caps that would otherwise 1.6× the
per-second envelope:

| Cap | Stage A (25) | **Stage B (40)** | Per-second envelope |
| --- | --- | --- | --- |
| `max_block_mass` | 200,000 | **125,000** | 5.0 M grams/s (invariant) |
| `MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK` | 48 KiB | **32 KiB** | ~1.2 MB/s |
| `MAX_EVM_ACCEPTED_GAS_PER_CHAIN_BLOCK` (`EVM_GAS_LIMIT`) | 12 M | **7.5 M** | 300 M gas/s |

Worst-case bandwidth ~6.4 MB/s, worst block ~156 KiB, L1 ≈ 240 tx/s (§3.2;
ML-DSA 1-in/2-out ≈ 18k grams). **Consensus note:** the EVM caps are
global consts and testnet is EVM-genesis-active (`evm_activation_daa_score = 0`),
so this cap change is consensus-relevant to the running mesh — which is exactly
why it ships *inside* the re-genesis (B1), not mid-chain. mainnet EVM stays inert
(u64::MAX), so the const change is non-HF there (ADR-0020 O13).

**B4 — DNS/PoS-v2 overlay: `required_work_depth` UNCHANGED; epoch lengths scale to
×BPS/10 = ×4** (D4). `TESTNET_DNS_PARAMS`: `epoch_length_blocks` 250 → **400**,
`attestation_epoch_length_blue_score` 250 → **400**, holding the real-time epoch at
10 s (block-denominated: leaving it at Stage A's 250 would shrink the real-time
epoch to 250 × 25 ms = 6.25 s and over-poll attestors — the
`DegradedStakeQualityLow` condition, R5). Blue-work
finality (`required_work_depth`, Uint576) is BPS-invariant by construction and is
**not** touched. Attestor SLO: per-epoch attestation-miss < 0.1%. ADR-0022
overlay-snapshot cadence is now 4× the 10-BPS rate and is an IBD metric (§5.6).

**B5 — perf/p2p follow-through set to program (Stage-C) values now** (D5): so
Stage C needs no further perf edit. `header_data_cache_size` → 65_536,
`block_window_cache_size` → 8_192, `block_data_cache_size` bps-clamp 10 → 50,
`MAX_ORPHANS_UPPER_BOUND` 1024 → 4096. relay flows (`bps/2` = 20) auto-follow;
reachability reindex frequency (4× insert rate) stays but is monitored (R3).

**B6 — Emission invariant** (D8, §4.2): with
`pre_crescendo_target_time_per_block = 1000/40 = 25`, `bps_history` is constant so
per-block subsidy = `SUBSIDY_BY_MONTH_TABLE[i].div_ceil(40)` and per-second /
per-month emission is unchanged from 10 BPS (div_ceil remainder ≤ 39 sompi/block,
within the existing emission-test tolerance). Total supply invariant.

**B7 — IBD program carries forward** (D6): I-0 (ops, zero-code) and I-1
(`IBD_BATCH_SIZE` 99→256, header read-ahead 1→3, pruning-UTXO chunk 1000→4096 +
pipelining) apply as at Stage A. I-2 (`--ibd-trust-dns-finality`, default off /
testnet-on per O5) is available and consensus-neutral. Record Stage B IBD time
against the Stage A baseline `B_A`: with the 4.32 M-block window, Stage B's
headers ≈ 8.6 GB wire (§ appendix B).

**B8 — Stage B exit gates** (D9, §6): soak ≥ 7 days → 24 h load test (L1 tx spam +
EVM gas saturation) → 60 s-partition drill → exit judgement.

| Exit gate | Stage B (40) target |
| --- | --- |
| mergeset size p99 / p999 | < 223 / < 447 |
| tips mean (steady) | < 2·λ·d̂, non-divergent |
| orphan rate | < 1% |
| virtual processing p99 | < 25 ms |
| DAA | target interval ±10%, 24 h convergence, no oscillation |
| partition drill (60 s) | auto-recover < 5 min, DAA-band return < 30 min |
| attestation-miss | < 0.1% |
| IBD | §5.1 SLO; time ≤ `B_A × (4.32M / 2.7M)` = 1.6·`B_A` |

Recovery-capacity check for the drill: `mergeset cap 512 × 40 blk/s = 20,480 blk/s`
≫ generation rate.

---

## Consequences

**Positive.**
- 25 ms L1 blocks at an **unchanged per-second node cost** (B3 holds the envelope);
  single-block worst-case shrinks 245 → 156 KiB vs Stage A. The full advance is one
  const-generic swap + the k-table extension + the enumerated cap/overlay/perf edits
  (appendix C of the design gives exact touchpoints).
- Landing the full `33..=64` k-table now (B2) means **Stage C (50) is a pure
  const/cap change** — the last untrodden piece is de-risked here.
- `required_work_depth` unchanged — DNS-finality wall-clock security stays
  BPS-invariant (B4), a design advantage preserved.

**Negative / limits (frozen honestly).**
- **k = 447 is the first value beyond the original table** and the first where
  `k > mergeset_size_limit/2` (447 > 256): if mergeset p99 approaches k under the
  DE↔JP merge dynamics, that is the early warning ADR-0026 O1 watches — Stage B is
  where we first see it, before committing to Stage C. Settling at 40 BPS (rather
  than 50) is a legitimate ADR-0026 O1 outcome.
- **16-parent clamp ≪ expected tips** at 25 ms (R1) — effective D may creep via
  log-round merges; gated by B8 + the D=6/k=658 reserve (O1).
- **mergeset cap 512 < 2k = 894** (R2) — a departure from the PHANTOM 2k
  assumption; justified by 20,480 blk/s recovery capacity but flagged.
- **Full re-genesis** (seeds/nodes/miners/attestors/faucet/explorer) — operationally
  heavy; rolling DB grows to ~17–30 GB at 40 BPS (empty-block, R4) → NVMe + WAL
  separation. The ForkedParam live-fork for mainnet remains design-only (§4.3).

**Carried-forward open decisions** (not resolved here): O1 (D=5/k=447 vs a D=6
reserve — Stage B is the first read on it), O2 (mergeset cap 512), O3 (final EVM
per-chain-block gas, unified with ADR-0020 O13), O5 (I-2 default), O6 (log-space k
for future >64), O7 (suffix/port map for `testnet-40`).

**Interaction with MIL P2 (F003 activation).** A re-genesis resets every activation
fence (ADR-0026's closing note): if MIL F003
(`evm_f003_mldsa_verify_activation_daa_score`) is to be active on `testnet-40`, set
it in the new genesis (cleanest: active-from-genesis) together with the shrunk EVM
caps (B3) — do not assume a prior `testnet-25` flip carries across the re-genesis.
