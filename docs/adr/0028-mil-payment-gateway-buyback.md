# ADR-0028: MIL Multi-Asset Payment Gateway & MSK Buyback

## Status

**Proposed — design freeze, 2026-07-05. Off-protocol; NOT implemented; publication gated on a legal review.**
Code-grounded freeze of **§23 (+ the §20.4 subsidy-split refinement)** of
[`docs/misaka-mil-design-v0.11-payment-gateway.md`](../misaka-mil-design-v0.11-payment-gateway.md) — accepting
USDT/USDC/SOL/ETH for MIL inference by converting them, at the *edge*, into MSK demand and burn, while the protocol
itself stays MSK-only. Every "§N" / "O-n" below points to that document.

**This is an OFF-PROTOCOL operations + economics decision.** It changes **no consensus code, no EVM contract, and no
escrow/receipt/burn/fee-split**. The gateway is the founder-operated formalization of the §14.3 paymaster; from the
network's view it is just "a large MSK-paying user" of `JobEscrow` (the MIL v1 payment plane). There is nothing in
the `misakas` tree to build for it — it is an external service + a published policy, frozen here.

This ADR **relates to**: [ADR-0024](0024-mil-gpu-attestation-computedepth.md) (the issuance/burn economics it
complements — and whose subsidy split it refines to 25/5, see the amendment note there),
[ADR-0027](0027-testnet-points-program.md) (the same "single MSK token, edge accounting, legal-review-gated"
pattern), and the MIL v1 payment plane (JobEscrow — the gateway's spend path). The MSK direct-pay price it protects
is the §6.1 single-token principle.

> **Hard preconditions (non-negotiable).**
> 1. **Legal review (§23.5, §12-29) is a HARD precondition of LAUNCH, not a follow-up.** Before operating the
>    gateway, a review MUST settle: crypto-exchange-business non-applicability of the "user buys a service credit,
>    not MSK" structure, the prepaid-payment-instrument (資金決済法) registration/deposit question, AML/sanctions
>    screening of deposit addresses, and tax (crypto-receipt income + period-end valuation). This ADR is scheme
>    design only, not legal advice.
> 2. **No reverse conversion.** The operator MUST NOT offer MSK → USD/USDC/SOL/ETH/fiat cashout (§23.1 freeze
>    clause (ii)). Forward-only (sell service credit + self-account treasury buys) is the legal structure's
>    lifeline; reverse conversion drops it squarely into exchange-business scope. MSK holders cash out on the open
>    market themselves.
> 3. **The native⇔Hyperliquid bridge/custody is the single biggest new attack surface** (§23.10, §12-32). It MUST
>    ship with per-tx caps, withdrawal delay, threshold-signer distribution, and staged TVL release from day one —
>    the same discipline as the §9 launch-guard TVL cap. Do not list on HIP-1 without it.
> 4. **Providers never touch a non-MSK asset via the protocol** (§23.1 (i)). FX / key-management / tax / regulatory
>    party-hood is isolated to the gateway, outside the PQ environment. Providers are always paid MSK.
> 5. **Burn comes only from the price margin; COGS is unburnable** (§23.8 identity `P = COGS + Burn + Ops`). "Buy
>    90% and burn it" is false — the 90% buy is executed literally, but the burn applies only to the margin
>    `b·COGS`. The accounting identity is exposed in the price formula itself.
> 6. **Never sell unbacked credit.** When MSK inventory falls below threshold, new credit sales pause (§23.7). The
>    90/10 books stay separated and Proof-of-Buyback stays checkable: **no buying MSK from the 10% ops cut** (§23.9
>    prohibition).

---

## Context

MIL prices inference in MSK and burns 5% of every fee (the 88/5/4/3 split). But most paying demand arrives in
USDT/USDC/SOL/ETH, and the §6.1 single-token principle + the burn machinery must not be diluted by multi-asset
escrows, and bridge risk must not enter the settlement layer. The v0.11 design resolves this by keeping the
protocol MSK-only and pushing multi-asset acceptance to the *edge*: a founder-operated **payment gateway** that
sells MSK-denominated service credit, buys MSK on the open market to back it, and burns the price margin — turning
external-asset revenue into MSK buy-pressure + provable native burn (a Hyperliquid-style flywheel that stacks on
the native 5% fee burn).

The gateway is deliberately a *swappable off-protocol part*: paymasters can be run by anyone (§14.3), the 90/10
split is the official gateway's policy not a consensus rule (§23.6), and an on-chain `PaymentRouter` that enforces
90/10 in a contract is deferred to v2 until the bridge is audited (bridges being the industry's largest hack
surface, compounded here by bringing classical assets onto a PQ chain).

---

## Decision

**D1 — Protocol knows only MSK; multi-asset is edge accounting** (§23.1). Non-MSK acceptance enters neither escrow,
receipt, burn, nor the 88/5/4/3 split. The gateway is the formalized §14.3 paymaster; the network sees a large
MSK-paying user. **Freeze clauses:** providers never touch a non-MSK asset via the protocol; the operator offers
**no reverse conversion** (precondition 2).

**D2 — Inventory model, not atomic swap** (§23.2): deposit (per-user address, MPC threshold custody, per-chain
finality-confirmed) → **MSK-denominated, account-bound, non-transferable, generally non-refundable credit** →
consume from the operator's own MSK inventory to open the session escrow → replenish by buying MSK with 90% of the
net deposit via TWAP batches (≤2% slippage/batch, overflow deferred), 10% to a separate ops wallet (distinct from
the protocol Treasury's 3%). Decoupling UX (instant credit) from thin-book execution is the point.

**D3 — Price formula exposes the burn identity** (§23.3): `P = ask_MSK × R_oracle × (1 + b) / 0.9`, where `R` is an
FSL price-fact MSK/USD rate (locked per session/top-up) and `b` is the published **burn-margin rate**. Of `P`,
`0.9P` all goes to MSK buy (split COGS→inventory + `b·COGS`→**immediate burn**), `0.1P` is ops. `b=0` degenerates
to no burn — burn is generated *only* from margin. Consequence: **MSK direct-pay is always cheapest** (zero spread,
no `b`), a standing hold-MSK incentive. Credit is MSK-denominated so the operator carries no FX risk (liability and
inventory match units).

**D4 — Buyback flywheel + Proof-of-Buyback** (§23.4): `$X/mo` of non-MSK demand becomes `$0.9X/mo` of MSK
buy-pressure (stacking on the 5% fee burn). A **monthly Proof-of-Buyback** — deposit txids, fills, 90/10 breakdown,
inventory balance — is anchored as an FSL fact so anyone can audit it. The project's own verification layer proves
its own books.

**D5 — Regulatory structure** (§23.5, precondition 1): **users buy service credit, not MSK**; the 90% buy is the
issuer's self-account treasury policy. Credit is non-transferable + generally non-refundable; the prepaid-payment-
instrument registration/deposit obligation is checked; deposit-address sanctions screening is an operating
requirement; tax is bundled into the same review. Legal review is a launch gate.

**D6 — Hyperliquid auto-execution rail** (§23.7): venue fixed to Hyperliquid (HIP-1 USDC/MSK spot), which requires
a **native⇔HL bridge/custody** (threshold-signed) as a prerequisite project. Pipeline: (1) **ingest** — SOL/ETH via
**Hyperliquid Unit direct deposit** (Guardian lock-and-mint → uSOL/uETH on the spot book, sold to USDC; native-
chain DEX swaps eliminated), USDC aggregated on Arbitrum (Solana→CCTP, Ethereum→bridge), USDT normalized to USDC
once; Unit minimum deposit (e.g. 0.12 SOL) surfaced as the user minimum top-up. (2) **TWAP buy** — ≤2% slippage,
overflow deferred, every fill ID recorded. (3) **burn** — the burn allotment is **withdrawn from HL and sent to a
native eater address** (`P2PKH(Hash64("MISAKA-BURN-V1"))`, preimage-unknown by construction) so native supply
provably drops (not a wMSK burn on HL). (4) remainder replenishes inventory. **On failure** (HL/bridge down),
execution halts and queues — the inventory buffer absorbs UX, and credit sales pause below the inventory threshold
(never sell unbacked credit).

**D7 — Three-layer burn** (§23.8): B1 native fee burn (existing 5%, no HL dependency), B2 margin burn (`b·COGS` via
the eater send), B3 misc (expired credit / forfeited residue, quarterly). Recommended initial **`b = 0.1–0.2`** —
the burn premium directly erodes the price competitiveness that is §18's lifeline, so it is tuned against the
demand curve on a public dashboard. The cheapest max-deflation lever is raising the **native fee-burn rate** (no HL
needed); the HL rail is the dedicated "external-asset revenue → MSK demand + burn" converter.

**D8 — Receipt routing + treasury policy** (§23.9): **SOL/ETH/USDT are pass-through, not held.** Waterfall: AML
screen (fail → quarantine, do not convert) → deduct only operating gas float (SOL/ETH spot, weeks-bounded, capped)
→ ingest/normalize → 90% buy/burn → 10% ops held in **USDC**, spent in order: (1) HIP-1 auction fee + USDC-side
MSK/USDC liquidity seed (book depth = the 90% rail's own execution quality), (2) audit/legal, (3) Tier-1 seed nodes
(H100 CC — promoting the §22.3c TEE-anchor supply from a precondition to an operator duty), (4) JPY conversion only
against real expenses. **Prohibited:** SOL/ETH speculation, float yield-farming, **buying MSK from the 10%**,
reverse conversion. Monthly attestation includes float + liquidity positions.

**D9 — Decentralization compatibility** (§23.6): the gateway is a swappable off-protocol component; §21 visibility
holds (it knows the payer, not the content). A v2 on-chain `PaymentRouter` that enforces 90/10 in a contract is
deferred until the bridge is audited.

**D10 (amends ADR-0024) — subsidy split confirmed at 25/5** (§20.4): the compute pool is `subsidy_validator_bps
2500 / subsidy_service_bps 500` (70/25/5), superseding ADR-0024's provisional 70/24/6. The validator floor stays at
its live 25% (`dns_finality.rs` currently `subsidy_validator_bps: 2500`), and the revived service slot takes 5%; the
10% compute-pool ceiling becomes **conditional on Phase-C (TNS) activation**, and reward-follow moves to the fee
side (finality fee `25/75/0 → 25/65/10` at Phase B), not further subsidy. This is a numeric refinement to ADR-0024's
issuance plane; the ADR-0024 preconditions (no activation before mainnet economics freeze; auto-suspend for Phase C;
independence is measured) are unchanged.

---

## Consequences

**Positive.**
- Turns the majority (non-MSK) demand into `0.9×` MSK buy-pressure + provable native burn, stacking on the 5% fee
  burn — a real deflation flywheel — **without** touching consensus, contracts, or the single-token principle.
- The price formula makes MSK direct-pay strictly cheapest, a standing hold-MSK incentive, and exposes the burn
  identity so "buy 90% and burn" cannot be mis-sold.
- Proof-of-Buyback uses MIL's own FSL verification layer to make the operator's books publicly checkable —
  simultaneously a trust device and a market-manipulation-suspicion defense (TWAP + pre-published rules + auditable
  fills).
- Everything is a swappable off-protocol part; a future contract-enforced PaymentRouter is a clean v2 upgrade.

**Negative / limits (frozen honestly).**
- **Centralized + legally loaded.** The gateway is operator-run and cannot launch before the legal review
  (precondition 1); the whole structure depends on the no-reverse-conversion lifeline (precondition 2).
- **The native⇔HL bridge is the biggest new attack surface** in the entire MIL design (precondition 3) — a
  classical-asset bridge onto a PQ chain, gated on custody hardening + audit.
- **Single venue.** HL/bridge downtime halts buys; tolerated by the queue + inventory buffer + sales pause, at the
  cost of a hard operational dependency.
- **Burn premium trades against price competitiveness** (§18) — `b` is a live tuning knob, not a set-and-forget.
- **Bootstrap liquidity is unsolved at scale** (§12-34): TWAP execution quality is bounded by MSK/USDC book depth,
  which the 10%-seeded liquidity must build up.

**Open decisions carried forward:** O29 (legal — launch precondition), O31 (v2 on-chain PaymentRouter),
O32 (bridge/custody design — the largest new surface), O33 (`b` demand-elasticity measurement), O34 (MSK/USDC
bootstrap-liquidity sizing). O30 (venue) is resolved = Hyperliquid, with HIP-1 auction cost/timing and
liquidity-supply plan as residual tasks.
