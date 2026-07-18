# ADR-0024: MIL GPU Attestation Layer — ComputeDepth & Issuance Distribution (Triple Nakamoto Security)

## Status

**WITHDRAWN — 2026-07-19. Security-issuance plane (ComputeDepth / this ADR's plane-2) removed from code.**
The `mil/compute-attestor` sidecar crate, `mil/core::compute_attest` (ComputeAttestation), the
`MilAnchorPayload::ComputeAttestation` anchor variant, and the `MIL_COMPUTE_ATTEST_*` domains were deleted
(commit follows). ADR-0039 PALW (replica-exact-match, **attestation-free**, I-7) makes the TEE-rooted
"prove you have a real GPU" ComputeDepth dimension unnecessary, and the project is TEE-free / all-open. The
**inference-market plane** below (plane-1: EVM lane, `mil/attest` TEE identity + `mil/channel` ML-KEM,
`mil/provider`, receipts, SDKs) is a **separate live system and is NOT withdrawn** — only the
security-issuance ComputeDepth plane is removed. The text below is retained for historical context.

**Proposed — design freeze, 2026-07-05. Consensus overlay NOT implemented.** This ADR is the
code-grounded freeze of **§20 (+ the §5 revision)** of
[`docs/misaka-mil-design-v0.4.md`](../misaka-mil-design-v0.4.md) — the MISAKA Inference Lane (MIL)
GPU compute market. Every "§N" below points to a section of that document.

> **Amended by [ADR-0028](0028-mil-payment-gateway-buyback.md) D10 (MIL v0.11 §20.4):** the subsidy split is
> confirmed at **70/25/5** (`subsidy_validator_bps 2500 / subsidy_service_bps 500`), superseding the provisional
> 70/24/6 below — the validator floor stays at its live 25% and the revived service slot takes 5%. The 10%
> compute-pool ceiling is **conditional on Phase-C (TNS) activation**, and reward-follow moves to the fee side
> (finality fee `25/75/0 → 25/65/10` at Phase B) rather than more subsidy. The preconditions and D1–D6 below are
> unchanged; only these numbers refine.

**Scope boundary — two planes, only one is this ADR.** MIL has two orthogonal planes:

- **Inference-market plane (EVM lane + off-chain data plane)** — `ProviderRegistry` / `JobEscrow` /
  `StakeManager` / `RewardPool` / `DisputeGame` / `MilGovernance` contracts, the `mldsa87_verify`
  (F003 v0x03) / `hash64` (F004) / `dns_finality` (F005) precompiles, the `misaka-mil-provider`
  sidecar, the PQ data-plane (ML-KEM-1024 + AES-256-GCM), the ML-DSA-87 receipts, and the TS/Swift
  SDKs. **This plane is implemented** (branch `feat/mil-v0`) and does **not** touch coinbase, base
  consensus, or DNS finality — the precompiles are activation-fenced INERT (`u64::MAX` on every
  network) and consensus-neutral until a coordinated EVM-HF.
- **Security-issuance plane (this ADR)** — **ComputeDepth**: a third confirmation dimension and a
  block-subsidy share paid to GPU providers for a **validator-mirror epoch-attestation duty**, NOT for
  inference. This plane changes base consensus (fee split, reorg gate) and is **NOT implemented**; it
  is a forward-looking, HF-gated program frozen here.

This ADR **relates to but does not supersede** the reward/finality ADRs it builds on
([ADR-0013](0013-validator-reward-distribution.md), [ADR-0018](0018-quality-gated-stakescore-inclusion-economics.md),
[ADR-0009](0009-dns-probabilistic-finality.md), [ADR-0017](0017-all-active-staker-attestation.md),
[ADR-0016](0016-stake-locked-bond-utxos.md)): it **adds a third participation dimension** by the same
patterns, reusing their proportional-share, anti-capture, and equivocation machinery verbatim.

> **Hard preconditions (non-negotiable gates).**
> 1. **No activation before mainnet economics are frozen.** Reviving the subsidy split touches
>    coinbase construction + verification. If activated **before mainnet launch**, it rides a
>    re-genesis (the minimal-diff path used for the 25%→30% validator raise). **After launch it MUST
>    be an activation fence** (the pos_v2 / EVM-lane pattern), with byte-identical coinbase
>    build/verify below the fence.
> 2. **No reorg-gate participation (Phase C) without an auto-suspend.** A third liveness dimension MUST
>    ship with a quorum-hysteresis auto-suspend (§20.6), the same low-participation risk class as
>    `min_active_validators = 1`.
> 3. **Independence is a measured property, not an assumption.** The AND-composition safety gain is
>    proportional to the independence of the stake set and the compute set (§20.6); this is the same
>    separation-theorem gap flagged in the DNS-finality review and remains an open research item
>    (§12-18/19).

---

## Context

### The problem: why paying issuance for "useful compute" fails

The obvious design — pay block subsidy directly for inference (the "useful compute" a GPU does) — is
**not verifiable on-chain**: in a demand-free window there is no auditable basis for the payment, and
"answer canaries only" farming becomes profitable. This is the exact failure that already caused the
**Node reward to be removed from this codebase** as *Sybil-prone*. The `FeeSplitParams` struct records
that decision in its own doc comment (`consensus/core/src/dns_finality.rs:2190`):

```rust
/// `service` is **0** — the Node reward was dropped (Sybil-prone; node duty is
/// enforced via the validator role instead). The field is retained at 0 for
/// borsh stability / future re-activation.
pub subsidy_service_bps: u16,   // = 0 in the live preset (params.rs:725)
```

So the dormant `service` slot is **already the intended home for a re-activated third role** — this
ADR fills it, but only under a design that does not repeat the Sybil mistake.

### The existing economics (ADR-0018 §D/§E/§F, verified against misakas-main)

`reward_fee_split(daa_score)` (`dns_finality.rs:951`) selects the active `FeeSplitParams`. The live
Stage-3 (DNS-Active) preset (`config/params.rs:717`) is, in bps:

| stream | worker (miner) | validator (§E pool) | service (dormant) |
|---|---|---|---|
| subsidy | **7000** (`base 6200` + `inclusion 800` — the §D `worker_inclusion_pool`) | **3000** (25→30 raised, re-genesis-同便) | **0** |
| normal tx fee | 9000 | 1000 | 0 |
| DNS finality fee (`EVM_DEPOSIT_LOCK`, ADR-0018 §F) | 2500 | 7500 | 0 |

The §E validator pool is distributed per epoch to the **first-included** attesting validator by
`validator_participation_outputs` (`dns_finality.rs:2341`) using the anti-capture proportional share
`proportional_share(pool, stake, expected_stake)` = `pool × min(stake, expected_stake) / expected_stake`
(`:2097`); undistributed residue is **don't-mint** (anti-capture). `worker_inclusion_bounty` (`:2118`)
pays miners for including the certificate. The DNS reorg gate already composes two dimensions
(`dns_finality.rs:604-665`):

```text
work_depth  ≥ required_work_depth      (PoW — existing)
stake_depth ≥ required_stake_depth      (DNS validator — existing)
```

### The gap

GPU providers are a **new third role** with no consensus-side security duty and no issuance basis. The
inference-market plane (fees, EVM contracts) does not answer *"why does the chain mint MSK to GPUs?"*.
An answer that is auditable on-chain is required, or the compute pool repeats the Node-reward Sybil
failure.

---

## Decision

### D1 — Issuance is security, fees are inference (the separation principle)

Block subsidy to GPU providers is paid **only** for a validator-category, on-chain-verifiable duty:
signing an epoch anchor. Inference is paid **only** by market fees (§5.3, 88/5/4/3). The audit answer
to "why mint to GPUs" becomes the auditable fact *"they participate in chain-reorg defense by
signing"*, never the unverifiable *"they did useful compute"*.

### D2 — Compute attestor = validator mirror = a third confirmation dimension

A `misaka-compute-attestor` is a fork of `kaspa-pq-validator-core` that signs the **same epoch (100
blue score), same anchor form** as a DNS validator, under a **distinct domain**
`misaka-mil-v1/compute-attest`. It contributes a third reorg dimension:

```text
compute_depth ≥ required_compute_depth   (this ADR; live only in Phase C)
```

Bonds are native UTXO bonds (ML-DSA-87 P2PKH, bond txid:index — the [ADR-0016](0016-stake-locked-bond-utxos.md)
form). The **attestor role is a native overlay; the inference market is the EVM lane** — the two planes
stay separate so coinbase construction/verification never depends on EVM state.

### D3 — Weight is bond, not FLOPS

Consensus weight (`compute_depth` contribution and issuance share) is `min(bond_i, compute_bond_cap)`,
**not** measured compute. FLOPS-weighting is fatal: compute is time-rentable (cloud GPUs), so a
FLOPS-weighted attack costs only a few hours of rental. A slashable, unbond-delayed bond sets the
cost-of-attack floor. GPU physical existence (device certificate / canary) gates **eligibility**, not
weight (D5).

### D4 — Issuance plumbing: revive the dormant `service` slot, slide the residue (zero new fields)

Re-purpose `subsidy_service_bps` (currently 0, borsh-retained) as the **compute pool**. **Recommended
split (proposal A):**

| stream | worker | validator | **compute (revived service)** |
|---|---|---|---|
| subsidy (post HF-MIL) | 7000 (unchanged) | nominal **2400** (effective 2400–3000, sliding) | **600** (future cap 1000) |

- Distribution mirrors §E exactly: a new `compute_participation_outputs` (the §E analogue of
  `validator_participation_outputs`) pays first-included attestors `pool × min(bond, cap) /
  expected_compute_bond`.
- **Residue slides back to the validator pool** — until the compute set's total bond reaches
  `expected_compute_bond`, the validator's *effective* share decays from 30% toward 24% by exactly the
  compute-paid amount, so there is **no discontinuous 30→24 cut** (misakastake staker protection). The
  residue never reaches miners, preserving the §E anti-capture property.
- `worker_inclusion_bounty`'s eligible-certificate set gains the compute-attestation tx, buying the
  third set's inclusion with miner reward (censorship resistance, ADR-0018 §D).

Alternatives **B** (carve from worker 7000→6400) and **C** (3 from each side) are rejected: B touches
the PoW budget and the "miner stays majority" invariant (a coded comment); C muddies the principle. A
buys an independent second attestor set *inside the same finality-budget category* the 25→30 raise
already established.

### D5 — Sybil resistance: bond + device binding + equivocation slash

The three conditions the Node reward lacked:

1. **Bond** (D3) — participation itself is bonded capital; a Sybil split only evades `bond_cap`, which
   the cap design bounds.
2. **Device binding** — the registration tx payload commits a TEE device-certificate hash (Tier-1) or
   a canary-measured profile (Tier-2). False/duplicate claims are **permissionlessly challengeable**;
   on proof, the PoS-v2 four-way slash path (reporter 10 / reserve 40 / victim 40 / burn 10) is reused
   for forfeiture. **Canary (§4.3) is NOT a consensus input** — it is a challenge basis and a
   reputation input only, so coinbase verification determinism never depends on EVM/off-chain state.
3. **Equivocation** — double-signing conflicting anchors in one epoch is detected by the existing
   `kaspa-pq-signer` anti-equivocation machinery ([ADR-0011](0011-validator-deployment-and-equivocation-safety.md)),
   heavily slashed.

### D6 — Phased rollout with an auto-suspend

- **Phase A (record + reward only)** — measure and record `compute_depth`, pay issuance, but do NOT
  enter the reorg gate. Zero liveness risk; accumulates set participation history.
- **Phase B (MIL-internal gate)** — add `compute_depth ≥ θ` to the large-escrow-claim DNS-final
  condition (§8.4). GPU-economy settlement is guarded by GPU attestation; base finality is untouched.
- **Phase C (Triple Nakamoto Security)** — add the third dimension to the reorg-gate AND. An attacker
  needs simultaneous majorities in work AND stake AND compute; cost-of-attack is ~additive. HF-gated,
  and **must** ship with a quorum-hysteresis auto-suspend so a low-participation compute set cannot
  stall liveness.

---

## Consequences

**Positive.** GPU issuance has an auditable justification (signing duty, not "useful compute"); the
farming failure that killed the Node reward is structurally excluded; the dormant `service` slot is
used as its own doc comment intended, adding zero borsh fields; the validator-share transition is a
smooth slide, not a cut; and a genuine third security dimension (TNS) becomes available at Phase C.

**Negative / risks.** More consensus surface (a third participation set, a third depth). The AND
safety gain is **conditional on stake↔compute independence** — if the same operators dominate both,
the third dimension's marginal safety approaches zero (§20.6). Device certificates give partial, not
proven, independence. Phase C adds a liveness dimension (mitigated by auto-suspend). Calibrating
`expected_compute_bond` / `compute_bond_cap` is unresolved (§12-17).

**Neutral.** 30B supply cap unchanged — this redistributes existing subsidy, it does not inflate. The
inference-market plane (already implemented) is unaffected; it can ship and run (permissioned v0 /
EVM-lane v1) with the compute pool at 0, and Phase A/B/C activate independently later.

---

## Implementation touchpoints (code-grounded, misakas-main)

| Site | Change |
|---|---|
| `consensus/core/src/dns_finality.rs:2190` (`FeeSplitParams`) | Set `subsidy_service_bps` as the compute pool (e.g. `subsidy_validator_bps: 2400`, `subsidy_service_bps: 600`). **No field added.** |
| `consensus/core/src/dns_finality.rs:2341` (`validator_participation_outputs`) | Mirror as `compute_participation_outputs`: denominator `expected_compute_bond`, residue → validator pool (reuse `proportional_share`, `:2097`). |
| `consensus/core/src/dns_finality.rs:604-665` (`work_depth`/`stake_depth`/`required_*`/`is_dns_confirmed`) | Add `compute_depth` / `required_compute_depth` (gate participation deferred to Phase C). |
| `consensus/core/src/dns_finality.rs:2118` (`worker_inclusion_bounty`) | Add the compute-attestation tx to the eligible-certificate set. |
| `consensus/core/src/config/params.rs:717` (fee-split preset) | New bps. **Pre-mainnet: re-genesis-同便 (minimal diff, the 25→30 手筋). Post-launch: activation fence (pos_v2/EVM pattern).** |
| `kaspa-pq-validator-core` | Fork → `misaka-compute-attestor` (delta = domain separation + bond class). |
| PoS-v2 slashing path / `kaspa-pq-signer` | Reuse for device-certificate challenge + equivocation slash. |

---

## Open questions (from §12)

- **§12-17** — calibrate `expected_compute_bond` / `compute_bond_cap` (target device count × average
  bond; full-share convergence simulation).
- **§12-18** — measure and enforce stake-set ↔ compute-set independence (high overlap → AND safety →
  0); how to treat dual-role operators; the metric.
- **§12-19** — formalize the ComputeDepth-inclusive AND-composition cost-of-attack lower bound (the
  DNS separation-theorem follow-up; candidate FC 2027 addendum).
- **§12-20** — introduction mechanism: pre-launch re-genesis vs. post-launch activation fence; verify
  byte-identical coinbase build/verify for the §5.4 residual-reflow on both paths.

---

## Relationship to existing ADRs

- **[ADR-0013](0013-validator-reward-distribution.md)** — the §E per-epoch first-included proportional
  payout this ADR mirrors for the compute pool.
- **[ADR-0018](0018-quality-gated-stakescore-inclusion-economics.md)** — §D worker-inclusion bounty
  (extended to compute certs), §E validator pool (compute residue reflows here), §F finality-fee
  wiring. The `FeeSplitParams` streams live here.
- **[ADR-0009](0009-dns-probabilistic-finality.md)** — the two-dimension (work + stake) reorg gate
  this ADR extends to three (Phase C). The separation-theorem independence caveat is inherited.
- **[ADR-0017](0017-all-active-staker-attestation.md)** — the all-active epoch-attestation model the
  compute attestor copies.
- **[ADR-0016](0016-stake-locked-bond-utxos.md)** / **[ADR-0011](0011-validator-deployment-and-equivocation-safety.md)**
  — native bond-UTXO form and the anti-equivocation guard, reused for compute bonds.
- **[ADR-0019](0019-mldsa87-migration.md)** — attestor signatures are ML-DSA-87; the native overlay
  plane stays secp-free (the EVM inference plane's classical ECC is out of scope here).
