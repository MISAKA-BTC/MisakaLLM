# ADR-0026: BPS Acceleration (10→50) & IBD Fast-Sync — Parameter Freeze

## Status

**Proposed — parameter freeze, 2026-07-06. Staged rollout, NOT implemented.**
Code-grounded freeze of [`docs/misaka-bps-acceleration-design-v0.1.md`](../misaka-bps-acceleration-design-v0.1.md)
— raising testnet block rate **10 → 25 → 40 → 50 BPS** while holding the per-second
throughput envelope invariant, plus the IBD fast-sync program (I-0…I-3). Every
"§N" / "O-n" below points to that design. This ADR records the *settled*
decisions and the hard rollout gates; the design's open decisions (O1–O7) are
carried forward, not resolved here. Target commit `3b5e986`.

This ADR **relates to but does not supersede**: [ADR-0005](0005-mass-policy.md)
(mass), [ADR-0007](0007-layered-pow.md) (PoW — **unchanged**),
[ADR-0019](0019-mldsa87-migration.md) (ML-DSA — **unchanged**),
[ADR-0020](0020-selected-parent-evm-lane.md) (EVM lane / O13 gas cap),
[ADR-0022](0022-pruned-ibd-evm-overlay-snapshot.md) (pruned-IBD EVM/overlay
snapshot — its cadence ×5), and the DNS-finality / PoS-v2 attestation ADRs
([0009](0009-dns-probabilistic-finality.md)/[0013](0013-validator-reward-distribution.md)/[0017](0017-all-active-staker-attestation.md)/[0018](0018-quality-gated-stakescore-inclusion-economics.md))
whose epoch lengths follow BPS. It changes **only cap/period numbers + IBD**
(design NG3): no PoW, PQ-signature, or EVM-semantics change.

> **Hard preconditions (non-negotiable).**
> 1. **Envelope invariance is the safety contract, not a nice-to-have.** The k
>    values are derived for `D = 5 s, δ = 0.01`. That bound only holds if the
>    per-second bandwidth/gas/mass envelope stays constant as BPS rises — so the
>    block-built caps (§3.2) MUST shrink in lockstep with each BPS raise. Raising
>    BPS without shrinking the caps invalidates the k derivation.
> 2. **Each stage is a barrier re-genesis on testnet; the caps ride it.** The EVM
>    payload/gas caps are consensus-coupled on an EVM-active net (testnet
>    `evm_activation_daa_score = 0`), so changing them mid-chain would be a fork.
>    This design changes them **only inside a re-genesis** (new genesis hash +
>    suffix). **No mid-chain cap change, no mainnet re-genesis** from this doc —
>    mainnet BPS change needs the ForkedParam live-fork path (§4.3, design-only).
> 3. **I-2 (trusted-DNS-finality IBD) MUST NOT weaken state validation.** It skips
>    **only** script/ML-DSA-87 verify for bodies at `blue_score ≤ finalized`, and
>    **only** when the node-local `--ibd-trust-dns-finality` flag is on (default
>    off). PoW, header-chain, merkle, EVM-commitment, and the pruning-point
>    `utxo_commitment` verification are **always** performed. It is
>    consensus-neutral (mesh may mix flagged/unflagged nodes) and adds **no new
>    trust assumption** beyond the attestor set the reorg gate already trusts.
> 4. **50 is the hard ceiling of this design (NG1).** Three limits coincide at
>    50→100: the ms-divisor ladder (`1000 % BPS == 0` skips 51…99), the f64
>    `calculate_ghostdag_k` limit (BPS ≤ 74), and k(100)=1074 exceeding 2× the
>    mergeset cap (breaking the O(#headers×L) storage assumption). BPS > 50
>    requires a µs period + log-space k + mergeset/parent redesign — out of scope.

---

## Context

Current mainnet **and** testnet run `blockrate: BlockrateParams::new::<10>()`
(k = 124, 100 ms) — verified at `consensus/core/src/config/params.rs:1034/1115`.
The whole DAG parameter set is const-derived from `Bps<BPS>` in
`consensus/core/src/config/bps.rs`, so a BPS change is *almost* a one-line const
swap — **except** for the block-built caps that do not auto-follow, and the
overlay/perf/IBD constants. The design verified the structural ladder in code:

- `bps.rs:38` `ghostdag_k()` is a `const fn` match table currently ending at
  `32 => 362`; `bps.rs:50` panics on `1000 % BPS != 0`; `bps.rs:9`
  `calculate_ghostdag_k` uses f64 `e^-x` (dies for BPS > 74 at D=5).
- `mergeset_size_limit` caps at 512, `max_block_parents` at 16 (both intentional
  upstream storage/reachability clamps); `KType = u16` covers k=553.
- `TxValidationFlags::{Full, SkipScriptChecks, SkipMassCheck}` exist
  (`tx_validation_in_utxo_context.rs:21`), and
  `utxo_validation.rs:267` already branches
  `if is_selected_parent { SkipScriptChecks } else { Full }` — the exact seam I-2
  extends.
- Current caps: `MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK = 128*1024`
  (`evm/mod.rs:210`), `MAX_EVM_ACCEPTED_GAS_PER_CHAIN_BLOCK = EVM_GAS_LIMIT` (30M,
  `evm/mod.rs:213`); `IBD_BATCH_SIZE = 99` (`streams.rs:24`);
  `MAX_ORPHANS_UPPER_BOUND = 1024` (`flow_context.rs:95`).

The prize: at 50 BPS the block-time is 20 ms (GPT/Claude-grade "instant" L1
finality feel) while the per-second cost of running a node is unchanged, and IBD
(the thing that gets 5× more headers) stays at or below today's wall-clock.

---

## Decision

**D1 — Staged BPS raise 10 → 25 → 40 → 50 on testnet, each a barrier re-genesis**
(§4.1), with a soak ≥ 7 days + load test + partition drill + exit gates (§6)
between stages. Suffix per stage `NetworkId::with_suffix(Testnet, BPS)` →
`testnet-25 / -40 / -50` to structurally prevent cross-mesh misconnection (O7).

**D2 — Derived DAG params come from `BlockrateParams::new::<BPS>()`; the only code
change is extending the `ghostdag_k` table to 64.** Frozen k: 25→288, 40→447,
**50→553** (D=5, δ=0.01). The design ports `calculate_ghostdag_k` and reproduces
the existing table (1→18/10→124/25→288/32→362) before deriving the new rows
(appendix A). `merge_depth`/`finality_depth`/`pruning_depth`/`coinbase_maturity`
scale by BPS (1h/12h/30h/100s held constant); `max_block_parents` stays 16 and
`mergeset_size_limit` stays 512 (clamped — O2).

**D3 — Envelope-invariant caps SHRINK with each raise** (§3.2, precondition 1),
riding the re-genesis: `max_block_mass` 500k→200k→125k→**100k** (5.0M grams/s);
`MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK` 128K→48K→32K→**24K** (~1.2 MB/s);
`MAX_EVM_ACCEPTED_GAS_PER_CHAIN_BLOCK` 30M→12M→7.5M→**6M** (300M gas/s). Worst-case
bandwidth stays ~6.3 MB/s; L1 ≈ 250 tx/s; single-block worst-case *improves*
(618 KiB → ~124 KiB).

**D4 — DNS/PoS-v2 overlay: `required_work_depth` UNCHANGED; epoch lengths scale
×BPS/10** (§3.3). Blue-work is BPS-independent (difficulty just drops 5×), so the
same work-depth threshold has BPS-invariant wall-clock finality and attack cost —
kept as a design advantage. But block-denominated
`epoch_length_blocks` / `attestation_epoch_length_blue_score` (100 → 250/400/**500**)
must scale or the real-time epoch shrinks 10s→2s and 5×-loads attestor polling
(the `DegradedStakeQualityLow` recurrence condition). Attestor SLO: per-epoch
attestation-miss < 0.1%. ADR-0022 overlay-snapshot cadence/size becomes an IBD
metric (pruning point moves 5× faster).

**D5 — perf/p2p follow** (§3.4): `header_data_cache_size` 10k→65_536,
`block_window_cache_size` 2k→8_192, `block_data_cache_size` bps-clamp 10→50,
`MAX_ORPHANS_UPPER_BOUND` 1024→4096. relay flows (`bps/2`) auto-follow;
reachability reindex stays but is monitored (R3).

**D6 — IBD fast-sync program:**
- **I-0 (ops, zero-code, day-1):** BBR + enlarged TCP buffers; same-region
  dedicated seed per site (DE/JP) — the single biggest lever for the high-RTT
  single-stream IBD; `--ram-scale`/rocksdb cache + WAL on a separate NVMe;
  `target-cpu=native` (libcrux SIMD 63.9µs vs portable 76.5µs; keep blake2b/keccak
  asm paths).
- **I-1 (protocol/cache):** `IBD_BATCH_SIZE` 99→256; header read-ahead depth 1→3
  (VecDeque of validation futures); pruning-UTXO chunk 1000→4096 + receive/apply
  pipelining; explicit thread pinning.
- **I-2 (fork-specific centerpiece):** `--ibd-trust-dns-finality` (default off) —
  extend `utxo_validation.rs:267` with
  `|| (trust_flag && blue_score ≤ dns_finalized_blue_score)` on the
  `SkipScriptChecks` branch. Skips **only** script/ML-DSA verify below the
  attestor-quorum-finalized blue_score (precondition 3). Honest effect model:
  ~0 on empty blocks; under load (~27M tx over the 30h window) ≈ 2 min + removes
  the serial virtual-path wait.
- **I-3 (future, design-only):** multi-peer parallel body download (NG2).

**D7 — I-2 trust equivalence** (precondition 3): the reorg gate already assumes
the same attestor set's signatures; referencing that set's finalized signature in
IBD adds no new assumption. Even on attestor-key compromise, state transition is
still bound by the pruning-point `utxo_commitment`, and the flag is node-local +
default-off. O5: testnet default-on / mainnet default-off.

**D8 — Migration = barrier re-genesis per stage; the ForkedParam live-fork path is
preserved (design-only) for post-launch mainnet BPS change** (§4.3). Emission is
held invariant via `pre_crescendo_target_time_per_block = 1000/BPS` so
`bps_history` is constant and per-block subsidy = `SUBSIDY_BY_MONTH_TABLE[i] /
BPS` (div_ceil; per-second/per-month emission unchanged, §4.2).

**D9 — Exit gates per stage** (§6): mergeset p99/p999 < k/2 · {…}; tips bounded;
orphan < 1%; virtual-processing p99 < block-time; DAA in ±10% band, no
oscillation; 60s-partition drill auto-recovers < 5 min; attestation-miss < 0.1%;
IBD SLO met (the primary gate at Stage C). **O1 decision point at C:** if mergeset
p99 > k/2 persists, re-genesis at D=6 (k=658) or settle at 40 BPS.

---

## Consequences

**Positive.**
- 20 ms L1 blocks at 50 BPS with an **unchanged per-second node cost** — the
  envelope-invariant caps mean bandwidth/gas/mass/sec are held constant; only
  latency improves. Single-block worst-case actually shrinks.
- BPS is one const-generic + a k-table extension; the heavy lifting is caps +
  overlay + IBD, all enumerated with exact touchpoints (appendix C).
- `required_work_depth` needs no change — DNS finality's wall-clock security is
  BPS-invariant by construction.
- I-2 turns the fork's own DNS-finality overlay into an IBD accelerant with no new
  trust assumption, gated behind a default-off node-local flag.

**Negative / limits (frozen honestly).**
- **50 is the ceiling** (precondition 4); going further is a different design
  (µs period, log-space k, DAGKnight-class mergeset/parent rework).
- **16-parent clamp ≪ expected tips at 50 BPS** (R1): effective D may creep via
  log-round merges; mitigated by gates + the D=6/k=658 reserve (O1).
- **mergeset cap 512 < 2k** at 40/50 (R2) — a departure from the PHANTOM 2k
  assumption; justified by 25,600 blk/s recovery capacity but flagged.
- **Each stage is a full re-genesis** (seeds, nodes, miners, attestors, faucet,
  explorer) — operationally heavy; the ForkedParam live-fork for mainnet is
  designed but **not implemented**.
- **I-2 gives ~0 on empty blocks** (stated), and DB grows to 22–38 GB at 50 BPS
  (R4) → NVMe + WAL separation mandatory.

**Interaction with the MIL v1 payment HF (P2).** A BPS re-genesis produces a fresh
genesis where every activation fence resets — so if MIL F003
(`evm_f003_mldsa_verify_activation_daa_score`) is to be active on the new net, its
value is set in the new genesis (cleanest: active-from-genesis). Sequencing note:
if the MIL P2 F003-activation ships on `testnet-10` first, a later BPS re-genesis
to `testnet-25` re-establishes it in the new params — do not assume the flip
carries across a re-genesis. Conversely, a BPS re-genesis is a natural moment to
also land F003-active + the shrunk EVM caps (D3) together.

**Open decisions carried forward:** O1 (D=5 vs D=6 @50), O2 (mergeset cap),
O3 (final EVM gas cap, with ADR-0020 O13), O4 (epoch real-time fix), O5 (I-2
default), O6 (log-space k), O7 (suffix/port scheme). Resolved at the stage/soak
milestones in §8.
