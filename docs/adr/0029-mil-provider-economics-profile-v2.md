# ADR-0029: MIL Provider Unit Economics & Tier-2 Profile-v2 (batch-invariant determinism)

## Status

**Proposed — design freeze, 2026-07-05 (extended through MIL v0.13). NOT implemented.**
Code-grounded freeze of **§24 (+ the §4.2/§7.3 Tier-2 profile-v2 revision)** of
[`docs/misaka-mil-design-v0.12-provider-economics.md`](../misaka-mil-design-v0.12-provider-economics.md), extended
with **§24.7 (the counter-cyclical burn router + Provider Stabilization Pool) and the §24.1/24.3 refinements** of
[`docs/misaka-mil-design-v0.13-burn-router.md`](../misaka-mil-design-v0.13-burn-router.md) — making the Tier-2 GPU
provider's unit economics structurally sound. Every "§N" below points to those documents.

**Mostly off-protocol; §24.7 adds ONE EVM-lane contract.** The v0.12 levers are (a) the Tier-2 **serving kernel**
(a provider runtime config: batch-invariant continuous batching instead of batch=1) and (b) **SDK / provider
policy** (an economic guard, USD-indexed ask, a standby mode) — no consensus code, no contract. **v0.13 adds an
on-chain component (D9):** a burn-router / Provider-Stabilization-Pool **EVM-lane contract** through which the B1
(JobEscrow 5% burn) and B2 (gateway margin) flows pass, splitting each between the eater and the pool by a revenue
indicator. It reuses the existing issuance plane (ADR-0024) and the Tier-2 verification model (ADR-0025) unchanged
in substance, and — critically — the router touches **only already-earned fee/gateway flow**, never issuance, the
cap, or the coinbase split.

This ADR **relates to**: [ADR-0025](0025-mil-tier2-unlinkability-adversarial-provider.md) (whose Tier-2
deterministic profile it revises from batch=1 to batch-invariant — see the amendment note there; the byte-exact
token-ID verification is unchanged), [ADR-0024](0024-mil-gpu-attestation-computedepth.md) (whose "issuance is
security, never inference/fiat" principle §24.5 reaffirms, and whose compute-attestor the standby mode extends),
and the §6.1 single-token principle + §23.1 gateway freeze clause (which forbid paying providers in non-MSK — so
the FX mismatch is solved by pricing, not by payout currency).

> **Hard preconditions (non-negotiable).**
> 1. **Batch-invariant cross-GPU reproducibility is MEASURED, not assumed** (§12-35). The whole Tier-2 verification
>    model (ADR-0025 B4b) rests on byte-exact token-ID equality across independent runs. If a device class fails
>    exact-match reproducibility on batch-invariant kernels, that class **auto-downgrades to the batch=1 fallback**
>    (honest but throughput-penalized, a low-price class) — it does not silently ship a non-reproducible profile.
> 2. **Issuance NEVER links to fiat/power cost** (§24.5, the anti-death-spiral clause). Scaling issuance to power
>    or MSK price is the DePIN death-spiral entry (price↓ → issue↑ → dilute → ↓). The 70/25/5 coinbase split
>    (ADR-0024) scales only to participation (`expected_compute_bond`), never to a fiat metric; the Bootstrap Fund
>    never subsidizes supply-side power (§5.2). The network promises a **no-loss structure**, not universal profit.
> 3. **No non-MSK is ever paid to a provider** (§23.1 freeze). The provider's real pain — costs in ¥/$, income in
>    MSK — is solved by **USD-indexing the price** (SDK reprices via FSL per session), NOT by paying USDC to
>    providers, which would spread regulatory party-hood to every provider (§24.3).
> 4. **Standby must not let spoofed hardware farm issuance** (§12-37). The wake-up canary (1/day, exact-match
>    verified) is the device-existence check; repeated failures feed the §20.5 device-existence challenge. Whether
>    a higher standby bond is needed is a calibration item, not settled here.
> 5. **The burn router redistributes only already-earned flow — never issuance** (§24.7, D9). It routes B1
>    (JobEscrow 5% burn) + B2 (gateway margin); **the buy/collect is unconditional, only the destination (eater ⇔
>    pool) is revenue-linked**, so zero revenue ⇒ zero pool (no death-spiral path, precondition-2 preserved). Pool
>    payout is by **verified served-tokens, not bond** (keeping "fee = utilization", not "issuance = presence").
>    Standby devices are excluded from BOTH the pool and the indicator's denominator. A continuous ramp (not a
>    binary threshold) avoids boundary flapping/cliff-gaming; on FSL-rate-read failure the router **fails to s=1
>    (all-burn)**, never to the pool.

---

## Context

A Tier-2 provider (RTX-4090 class, 8B Q8) diagnosed at batch=1 runs at ~50 tok/s → ~2.5 kWh/1M tok → ~¥75–90/1M
tok, which is **300–1000% of the ¥7–22/1M market price — a structural loss** (§24.1). The root cause is neither
electricity nor an issuance shortfall: it is **batch=1 determinism suppressing throughput**. The MIL v1 Tier-2
verification model (ADR-0025) required a fully deterministic profile for its byte-exact token-ID dispute/canary
checks, and the v1 design used greedy + batch=1 to get it — at the cost of ~16× lower throughput than continuous
batching.

v0.12's fix is **profile-v2**: batch-invariant kernels give deterministic output *independent of batch composition*,
so a provider can run production continuous batching (~800 tok/s → ~0.16 kWh/1M → ~¥5–6/1M, a healthy 3–8% of
market) **and** still produce the exact token-ID sequence the dispute/canary layer verifies. With the structural
loss removed, §24 then handles the residual variance (MSK volatility, thin demand) with edge mechanisms rather than
by bending issuance.

---

## Decision

**D1 — Diagnosis: the Tier-2 break-even problem was batch=1 throughput suppression** (§24.1), not power or
issuance. batch=1 = 300–1000% of market; batch-invariant v2 = 3–8% (healthy); idle = ~¥75/day (floored by the
presence issuance). This reframes everything below: the fix is a serving-kernel change, and the economic mechanisms
handle only the residual variance. **Explicit ROI disclaimer (v0.13 §24.1):** this break-even is the *electricity-
OPEX* minimum-defense line — it does NOT guarantee full ROI (GPU depreciation, cloud rental, stake capital cost,
cooling/maintenance, tax are out of scope). Providers who need those covered raise their ask floor via D4's
optional terms.

**D2 — Tier-2 profile-v2 = batch-invariant continuous batching** (§4.2/§7.3): greedy + seed-fixed + fixed
quantization artifacts + pinned runtime as before, but on **batch-invariant kernels** so output is independent of
batch composition. This reconciles production throughput (100s–1000s tok/s) with the byte-exact token-ID match
verification (unchanged). **Fallback:** device classes without batch-invariant support drop to llama.cpp batch=1,
explicitly marked as a low-price class. Cross-GPU consistency + the throughput penalty (~10–20% vs the standard
kernel) are measured before trusting a class (§12-35, precondition 1).

**D3 — Three-layer principle: issuance = presence, fee = utilization, price never below cost** (§24.2). (i) Issuance
(compute pool 5%) is the attestation/presence reward and floors idle power (~¥75/day); it does NOT backfill
utilization loss. (ii) Utilization is paid by fees, demand-proportional. (iii) Below-cost jobs never occur, by the
guard (D4).

**D4 — SDK economic guard** (§24.3): a provider sets its power tariff (¥/kWh) locally; the SDK computes an
`ask_floor` from the measured power profile and **rejects sub-floor jobs**, making the ask board an honest
reflection of supply cost. **(v0.13 §24.3)** the floor gains two **optional** cost terms:
`ask_floor = (kWh/1k · tariff + capex_amortization_per_1k + stake_opportunity_cost_per_1k) × (1 + margin)` — a
hobbyist prices power only; a commercial/cloud-rental operator prices full cost. (Still USD-set + FSL-repriced to
MSK per session, D5.)

**D5 — USD-indexed ask** (§24.3): the provider's real pain is the ¥/$-cost vs MSK-income mismatch. Set the ask
floor in USD; the SDK **reprices to MSK per session via the FSL rate** (promoting §6.2's v2 plan to v1). Power-cost
coverage is decoupled from MSK volatility; the vol exposure shrinks to each provider's own MSK-hold-duration choice.
**Not done:** distributing non-MSK to providers — the mismatch is solved by indexing the *price*, not the payout
currency (precondition 3).

**D6 — Standby layer: hibernate, don't exit** (§24.4): in thin-demand / cheap-MSK periods a provider declares
**standby** — stop the GPU (~0 power), **keep attestation signing** (no GPU needed), and drop out of matching.
Hardware-existence proof relaxes to **one wake-up canary/day** (TTFT grace 5 min, response still exact-match
verified); issuance stays full. Supply hibernates instead of exiting and returns instantly on recovery. Standby is
out of A1 (substitution) scope (it takes no real jobs); repeated wake-up-canary failure feeds the §20.5
device-existence challenge (precondition 4).

**D7 — No fiat-linked issuance (anti-death-spiral)** (§24.5): issuance is never scaled to power/fiat cost. The
70/25/5 split scales only to participation (`expected_compute_bond`) — never a fiat metric; the Bootstrap Fund never
subsidizes supply-side power (it buys *demand*: arena, faucet, RFP — the only sustainable source that pays power via
fees). This is the operational restatement of ADR-0024's "issuance is security, not inference".

**D8 — Equilibrium when jobs are absent** (§24.6): the guard prevents below-cost jobs, so "unprofitable" means "no
jobs". The path is standby → (if no recovery) unbond (7d) exit. Exit is healthy consolidation — over-supply relative
to demand converging onto a high-utilization few, whose rising utilization amortizes idle and lowers unit price. The
network promises a **no-loss structure (guard / hibernate / presence-floor)**, explicitly NOT everyone's
profitability. This line is drawn in the document on purpose.

**D9 (v0.13) — Counter-cyclical burn router + Provider Stabilization Pool (PSP)** (§24.7). One line: **buy pressure
unconditional, burn pro-cyclical, provider support counter-cyclical.** A single EVM-lane router contract carries
B1 (JobEscrow's 5% burn leg) + B2 (the gateway's burn-margin buy); the buy/collect is unconditional (MSK
buy-pressure is revenue-independent) and only the *destination* switches. A revenue indicator
`I = 7-day fee revenue (FSL-USD) / non-standby attested active devices` drives a **continuous ramp**
`s = clamp((I − I_low)/(I_high − I_low), 0, 1)`: `s·(B1+B2)` is burned (to the native eater), `(1−s)·(B1+B2)` funds
the PSP. **PSP payout is per-epoch by verified served-tokens** (`min(served_i/Σserved, 5%)`), **not by bond** — so
the support is a fee-side top-up to those who actually served, keeping the D3 axis (fee = utilization) intact;
standby devices are excluded from both the payout and `I`'s denominator. **Consistency with D7 (precondition 5):**
the router never touches issuance, the cap, or the 70/25/5 split — it only re-routes flow the network *actually
earned*, so zero revenue ⇒ zero PSP (no dilution path) and it is still not a profitability guarantee (D8 holds).
Gaming: under-report = self-defeating (reject jobs); wash-trade over-report loses the real burn/split cost and only
strengthens burn (no attacker gain); standby-inflation is blocked by the denominator; FSL-rate manipulation is
damped by the 7-day average and, on read failure, fails to all-burn (s=1). Proof-of-Buyback references the router
txs (§23.8). This is the one on-chain component of this ADR (a `contracts/mil` addition + JobEscrow's burn leg
pointed at the router); calibration of `[I_low, I_high]` and the attack cost are open (§12-38/39).

---

## Consequences

**Positive.**
- Turns Tier-2 from a structural loss into a healthy 3–8%-of-market unit cost with a **serving-kernel change**, no
  consensus/contract change — the single highest-leverage fix in the provider economics.
- The economic guard makes the ask board honest (no hidden below-cost supply); USD-indexing removes MSK-volatility
  from the power-coverage calculation while keeping the single-token payout.
- Standby lets supply hibernate rather than exit, so capacity survives demand troughs and returns instantly —
  compounding the compute-attestor presence role (ADR-0024) rather than adding a new mechanism.
- The anti-death-spiral clause hard-codes the discipline that killed many DePINs into the issuance design.

**Negative / limits (frozen honestly).**
- **Profile-v2 rests on batch-invariant cross-GPU reproducibility** (precondition 1) — unproven per device class;
  failing classes fall back to batch=1 (throughput-penalized), so the economics improve only where reproducibility
  holds. This is measured, not assumed (§12-35).
- **The network does not promise profitability** (D8) — only a no-loss structure. Providers can still end up with
  no jobs and choose to exit; that is by design, not a bug.
- **Standby is a new small abuse surface** (precondition 4): a spoofed device could try to farm issuance on a
  1/day wake-up canary; the device-existence challenge coupling (and a possible higher standby bond) is a
  calibration item (§12-37).
- **USD-indexing depends on the FSL price feed** for per-session repricing — an off-chain oracle dependency on the
  provider path (the gateway already uses it, §23.3).

**Open decisions carried forward:** O35 (batch-invariant cross-GPU consistency + throughput penalty + supported
quantizations — the profile-v2 gating condition), O36 (per-device×quant power table, merged with the §12-27
physical-throughput-cap measurement campaign), O37 (standby abuse — wake-up-canary sufficiency + standby bond),
**O38 (router calibration + attack cost — `[I_low, I_high]` from an idle+partial-CAPEX-cover level, wash-trade /
FSL-manipulation mode-flip cost, 7-day window validity), O39 (router contract — unifying B1's fee-split-contract
leg and B2's gateway destination switch into one contract, with the FSL-read-failure → s=1 all-burn fallback).**
