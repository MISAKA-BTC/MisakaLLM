# ADR-0025: MIL Tier-2 Trust Model — Unlinkability & Adversarial-Provider Economics

## Status

**Proposed — design freeze, 2026-07-05. Not implemented (some primitives exist; see the matrix).**
This ADR is the code-grounded freeze of **§21 (unlinkability)** and **§22 (adversarial-provider design)** of
[`docs/misaka-mil-design-v0.6.md`](../misaka-mil-design-v0.6.md) — the two sections that define how the MISAKA
Inference Lane (MIL) **Tier-2 lane** (non-TEE consumer GPUs: RTX 4090 / 3090) stays private and honest **without**
the hardware confidentiality/integrity a Tier-1 TEE would provide. Every "§N" below points to a section of that
document; §21/§22 are reproduced there, and §0–§20 live in
[`misaka-mil-design-v0.4.md`](../misaka-mil-design-v0.4.md).

**Why one ADR for two sections.** §21 and §22 are the two halves of a single question — *"a Tier-2 provider has no
TEE, so how is the lane both private and correct?"* — and they are load-bearing on each other, not independent:

- §22.3(a) makes the **anonymity infrastructure a precondition of the audit**: canary jobs can only be
  unidentifiable (and therefore un-farmable, attack A6) if they arrive over the same relay/payment-unlinkable path
  as real traffic. The privacy machinery of §21 **doubles as** the audit substrate of §22.
- §22.3(c)'s TEE-anchored dispute oracle keeps disputes **content-private** (evidence is disclosed only to an
  enclave), which is itself a §21 unlinkability property applied to the dispute path.
- The §10 parameter coupling `ρ > g/(S+V)` (§22.6) and the relay/shield ladder (§21) are frozen together as a
  **joint** parameter block whose members may not move independently.

Splitting them would scatter one decision across two records. This ADR captures the Tier-2 trust model as a whole;
it can be split later if either half grows an independent implementation track.

**Scope boundary.** This ADR is about the **Tier-2 lane's trust model** — the economic and architectural
substitutes for a missing TEE. It does **not** restate Tier-1 (TEE + PQ E2EE, ADR-covered in the v0.4 design),
does **not** change base consensus, and does **not** touch the ComputeDepth security-issuance plane
([ADR-0024](0024-mil-gpu-attestation-computedepth.md)). The MIL EVM-lane precompiles it leans on
(`mldsa87_verify` F003, `dns_finality` F005) remain activation-fenced **INERT** (`u64::MAX` on every network);
nothing here is consensus-affecting until a coordinated EVM-HF.

This ADR **relates to but does not supersede** [ADR-0024](0024-mil-gpu-attestation-computedepth.md) (it reuses
that plane's device-cert binding and PoS-v2 slash path), [ADR-0018](0018-quality-gated-stakescore-inclusion-economics.md)
(fee/slash economics), and [ADR-0009](0009-dns-probabilistic-finality.md) (DNS finality for large-claim gating).

> **Hard preconditions (non-negotiable gates).**
> 1. **The TEE-anchored dispute oracle (§22.3c) requires real Tier-1 supply.** Until at least one attesting Tier-1
>    enclave exists (design roadmap P2), the *primary* dispute oracle **must** fall back to the VRF committee
>    (§4.2) — which reintroduces the collusion surface (A9) the enclave path removes. **Tier-2 MUST NOT be run
>    single-handedly in a Tier-1-zero region without acknowledging degraded audit power** (§22.7).
> 2. **The S·ρ·W parameters are one coupled block, not three knobs.** The safety invariant `ρ > g/(S + V)`
>    (§22.6) MUST hold at all times. Any pressure to lower the minimum stake `S` (e.g. delegated staking, §16.2)
>    MUST be met by raising the canary-mix rate `ρ` and/or the challenge window `W`. Independent changes are
>    forbidden and this coupling is frozen into the §10 parameter table.
> 3. **Subjective signals never slash.** Reputation `q` and user ratings feed matching priority **only**. Every
>    slashing trigger MUST be objective (byte-exact output mismatch, a signed equivocation fraud-proof, or a
>    physical-throughput violation). A single canary miss is **probation, not slashing** — negligence and attack
>    are separated by degree (§22.4).
> 4. **Unlinkability is a target, not a claim of content secrecy.** Tier-2 providers **see plaintext by design**
>    (disclosed in the UI, §3.5). The guarantee is that no observer — the provider included — can bind that
>    plaintext to a *who*. The residual risks in §22.7 (A7 sub-contracting, A11 data exfil) are unprovable and are
>    mitigated **only** by that unlinkability, not by detection.

---

## Context

MIL has two service tiers (v0.4 design §3.2, §3.5):

- **Tier-1** — Confidential-Computing GPUs (H100/H200/Blackwell) inside a CPU-TEE guest VM. The TEE gives both
  **confidentiality** (host/operator cannot read plaintext) and **integrity** (an attested, pinned runtime → the
  enclave-signed receipt *is* the proof of correct execution, §4.1). Nothing in this ADR is needed for Tier-1.
- **Tier-2** — Consumer GPUs (24 GB-class, RTX 4090/3090; 12 GB-class for Q4 entries) with **no** Confidential
  Computing. The two properties the TEE would have provided are now open problems:
  1. **Confidentiality is impossible** on a non-TEE GPU without FHE (10³–10⁶× slowdown, §3.7) or MPC (broken by
     embedding inversion, §21.5). The provider process necessarily sees plaintext.
  2. **Integrity is unattested** — there is no hardware measurement proving *which* model ran, so a provider can
     silently swap in a 1B/Q2 model (attack A1), pad token counts (A2), or claim physically impossible throughput
     (A4).

The naive reading ("Tier-2 has no privacy and no correctness, so it's worthless") is wrong, but only if both gaps
are answered by *other* mechanisms. This ADR freezes those answers:

- **For confidentiality → unlinkability (§21).** Invert the goal. The provider may see *what* was asked; the design
  guarantees no one (provider included) can learn *whose* it was. Sever the three links that bind content to
  identity: network (IP), payment (fund graph), and content self-disclosure.
- **For integrity → objective fidelity + EV-negative fraud (§22).** Reduce "quality" to **fidelity** (did it run
  the registered MIL-Core under the registered profile?). Judge only by objective signals (byte-exact token-ID
  match, signatures, physical limits). Make fraud **lose money in expectation** via `ρ > g/(S+V)`, rather than
  relying on detecting every instance.

The current `feat/mil-v0` branch already ships some of the primitives (canary generation, an untrusted single-hop
gateway, a DisputeGame with a 50% slash, cumulative-claim escrow). This ADR records the **target** design and
marks precisely which v0.6 mechanisms are new relative to that code, so a later implementation pass has an exact
delta to build.

---

## Decision — Part A: Unlinkability (§21)

**U1 — Goal inversion is the Tier-2 contract.** Tier-2 does not promise content secrecy; it promises
**unlinkability**: *the provider sees the content, but neither the provider nor anyone else can bind it to a who.*
This is stated in the UI (Tier-2 is "Provider-visible", §3.5) and is the frozen definition of the Tier-2
guarantee. Harm (profiling, extortion, censorship, subpoena) comes from the *join* of content and identity;
severing the join collapses the value of orphaned content.

**U2 — Network link: 2-hop relay is the Tier-2 *standard* path** (Tier-1: optional). `Requester → R1 → R2 →
Provider`. R1 learns the requester IP but not the destination provider or content; R2 learns the provider but not
the requester IP. A single relay would itself hold the IP↔provider map, so two hops is the minimum. 4 KB fixed
cells + send-timing jitter. Relays are stake-registered; the SDK picks two stake-weighted at random; reward is a
small per-MB charge from the session budget. Latency cost ≈ +50–150 ms, inside the 800 ms TTFT target (§13.1).

**U3 — Payment link: a four-rung shield ladder** (weak→strong), frozen with an explicit PQ-consistency rationale:

| Rung | Mechanism | Unlinkability | Status |
|---|---|---|---|
| L0 | Per-session fresh address (§15.2) | Weak (fund-graph analysis follows it) | v1 default |
| L1 | Paymaster / gateway aggregation (§14.3) | Medium–strong (k-anonymity = the app's user count; gateway knows *who* but not *what* — the two never sit in one party) | v1 |
| L2 | **STARK shielded prepaid pool** — deposit fixed-denomination (100/1k/10k MSK) note commitments to an EVM-lane contract; spend by proving Merkle inclusion + a nullifier in a **STARK** without revealing which deposit, opening the session escrow directly | Strong (anonymity set = all same-denomination deposits) | v2 |
| L3 | PQ blind-signature ecash (lattice blind signatures) | Strong + off-chain immediacy | Research (§12-22) |

**PQ-consistency is a hard constraint on the shield choice.** Tornado-style Groth16/BN254 pairings are non-PQ →
rejected. STARKs are hash-based, PQ-aligned, and the only practical shield MISAKA can adopt. Classical blind
signatures (Cashu/DLOG) are rejected because a future CRQC could break the blinding and **retroactively link**
purchase to spend (harvest-now-link-later) — the same compromise the PQ chain body refuses.

**U4 — Content link: SDK-side hygiene.** (a) A **local PII scrubber** flags names/addresses/account/key-like
strings before send, doing the detection locally so it never leaves the client. (b) **Private mode** — disable
sticky sessions and rotate providers per conversation (per-utterance at the strongest setting), trading TTFT
(§13.5) for dispersion, surfaced in the UI as an explicit choice. (c) **Conversation dispersion by default** —
sticky *within* a conversation, a different provider *across* conversations, so no single provider accumulates a
long-lived profile of one person.

**U5 — Rejected alternatives (recorded so they are not re-litigated).** Layer-split MPC (the first-layer holder
sees raw tokens and **embedding inversion** reconstructs the prompt from intermediate activations; non-collusion
and bandwidth also fail) → rejected. Prompt-splitting (LLM inference needs full context; semantically
ill-defined) → rejected. FHE (§3.7, non-practical) → rejected. **The Tier-2 answer is "cut," not "hide."**

**U6 — Visibility-matrix invariant.** The frozen correctness property of §21 is that **no observer row ever holds
both `content = ✓` and `identity = ✓`**. The Tier-2-provider row is `content ✓ / identity ✗`; the gateway row is
`identity ✓ / content ✗`. Any future change that would put both in one row breaks the model and is disallowed.

---

## Decision — Part B: Adversarial-Provider Economics (§22)

**B1 — "Quality" reduces to fidelity, judged only objectively.** Whether the *canonical model* is good is §19's
job (the DAO 3-gate). §22 guarantees only **fidelity**: the provider ran the registered MIL-Core under the
registered profile. If fidelity holds, Tier-2 answer quality equals MIL-Core's quality by definition. All verdicts
fall to objective signals (exact token-ID match, signature, physical quantity); subjective signals (user ratings)
feed **matching priority only and never slash**.

**B2 — Kill fraud by expected value, not by detectability.** The design target is *expected fraud gain < total
loss on discovery*, held for every parameter set (B8). Detection need not be certain; it needs to be *frequent
enough* relative to stake at risk.

**B3 — Attack catalog A1–A11 is the frozen threat set** (§22.2): model/quantization swap (A1), token-count
inflation (A2), fake/revoked attestation (A3, Tier-1), physically-impossible throughput (A4), receipt equivocation
(A5), canary-selection (A6), sub-contracting (A7), selective refusal (A8), committee collusion (A9), scorched-Sybil
re-registration (A10), data exfiltration (A11). Each row carries a detection mechanism and a consequence; A7 and
A11 are explicitly **undetectable** and handled by §21 unlinkability + ToS only (B9).

**B4 — Detection stack** (§22.3):
- **(a) Canary unidentifiability — the audit's precondition.** The moment canaries are distinguishable, every
  Tier-2 audit dies (A6). Canaries therefore arrive over the normal relay/gateway path, are paid via an
  unlinkable L1/L2 rung (fund source indistinguishable), and their prompts are **generated by MIL-Core itself**
  from a VRF seed (so the style distribution matches real traffic and any verifier can reproduce them), with
  Poisson arrival and multi-turn mixing. *The anonymity infra is promoted to a design-required audit device.*
- **(b) Deterministic exact-match.** Tier-2 profiles are fully deterministic (seed-fixed); canary and dispute
  verdicts are byte-exact token-ID equality — **no threshold discretion**. Cross-GPU reproducibility risk
  (§12-3) falls back to (c).
  > **Amended by [ADR-0029](0029-mil-provider-economics-profile-v2.md) (MIL v0.12 §4.2/§7.3):** the deterministic
  > profile is now **batch-invariant continuous batching** (profile-v2), not batch=1 — production throughput is
  > restored while the byte-exact token-ID verification here is unchanged. Device classes without batch-invariant
  > support **auto-downgrade to batch=1** (the low-price fallback). The §12-3 cross-GPU reproducibility risk is now
  > tested on batch-invariant kernels (§12-35); a class that fails falls back to batch=1, then to (c).
- **(c) TEE-anchored dispute oracle — Tier-1 judges Tier-2.** The primary dispute/canary oracle is "any Tier-1
  enclave re-runs the Tier-2 deterministic profile and returns an attested reference output." This (1) removes the
  human-committee collusion surface (A9), (2) makes disputes **content-neutral** (evidence goes only to the
  enclave; only a verdict + hashes leave it), and (3) sidesteps heterogeneous-GPU reproducibility by pinning the
  reference to one measured config. VRF committee (§4.2) is the fallback **only** while no Tier-1 exists.
- **(d) Physical-throughput cap.** Claim verification enforces `claimed_tokens/epoch ≤ device-class cap × units`
  (A4), the cap rooted in the attested device type (Tier-1) or the canary-measured profile (Tier-2).
- **(e) Statistical monitoring + adaptive audit.** Per-provider canary match-rate (anything ≠ 100 % is anomalous),
  refusal/short-response z-scores, latency-vs-hardware coherence, output-length drift — a rising suspicion score
  auto-raises that provider's canary-mix rate `ρ` (concentrate audit on the suspect without raising global cost).

**B5 — Payment mechanism: optimistic claim + challenge window** (§22.4):
- **Tier-1: immediate claim** (`W = 0`) — the enclave receipt is the proof.
- **Tier-2: optimistic claim, `W = 24 h`.** A claim finalizes after `W`; a dispute opened inside `W` **freezes**
  it until the TEE-anchored verdict. Provider capital tied up is only "the last 24 h of revenue."

  | Trigger | Slash | Extra |
  |---|---|---|
  | A5 equivocation / proven fake attestation | **100 %** | Permanent ban (per-device for Tier-1) |
  | A1 output mismatch (dispute lost) | **50 %** | All session claims forfeited; victim requester refunded |
  | A4 throughput over-cap | over-claim forfeit + 20 % | Audit escalation |
  | Single canary miss | 0 (no slash) | Probation, ρ↑, matching demotion — negligence ≠ attack, separated by degree |
  | Timeout / disappearance | Minor (§5.5) | Full escrow refund |

**B6 — Slash distribution reuses the PoS-v2 4-way** (`reporter 10 / victim 40 / reserve 40 / burn 10`), with the
**victim requester's refund funded from the forfeited stake** (§22.4). This extends the §5.5 slash table; it reuses
the existing 4-way path verbatim rather than inventing a new split.

**B7 — Reputation + probation price new entry** (§22.5). `q` = objective composite (canary record, dispute
history, measured SLA); no subjective input. New identities enter **probation**: 14 days of capped escrow exposure
(e.g. 1k MSK concurrent), lowest matching priority, elevated ρ. This makes scorched-Sybil (A10) re-entry cost =
lost stake + probation opportunity-cost + (Tier-1) buying a fresh, non-blacklisted device.

**B8 — Economic calibration is a frozen invariant** (§22.6): with per-job replacement gain `g`, canary-mix `ρ`,
and exact-match detection ≈ 1, expected fraud gain is `g/ρ` and the safety condition is
```
g / ρ  <  S + V        ⇔        ρ  >  g / (S + V)
```
Worked example: `g = 0.5`, `S = 100k`, `V ≈ 50k` MSK → required `ρ ≈ 0.0003 %`; the baseline `ρ = 1 %` carries a
~3,000× safety factor. The challenge window `W` is the second brake (caps pre-discovery extractable fraud to the
last `W` hours). `S`, `ρ`, `W` are frozen as a coupled §10 block (precondition 2).

**B9 — Residual-risk honesty** (§22.7): A7 (sub-contracting to the same profile) is output-identical and thus
**undetectable** — harmless to quality, but it widens Tier-2's visibility; mitigated only by §21 unlinkability +
ToS. A11 (data exfil) is likewise unprovable; same mitigation. Determinism collapse (§12-3 fails) shifts all
verdicts onto the TEE anchor (B4c), making Tier-2 disputes depend on Tier-1 supply. TEE-vendor compromise reduces
to the existing §3.6/§9 limits.

---

## Implemented vs. frozen (delta for a later implementation pass)

The `feat/mil-v0` branch already contains primitives that partially realize this ADR. What v0.6 **adds** is the
delta below.

| Mechanism | Already on `feat/mil-v0` | v0.6 adds (this ADR freezes) |
|---|---|---|
| Canary jobs | `mil/core/src/canary.rs` — VRF-seeded probe selection, template bank, `CanaryTally` → u/q | **Unidentifiability routing** (arrive over relay + unlinkable payment; MIL-Core-generated natural prompts, §22.3a); **adaptive ρ** per suspicion score (§22.3e) |
| Untrusted relay | `mil/sdk-ts/src/gateway.ts` — single-hop byte-splice, holds no plaintext/keys | **2-hop standardization** for Tier-2 (R1/R2 split, §21.2); stake-registered relay set + stake-weighted selection; 4 KB cells + jitter |
| Response side-channels | `mil/core/src/padding.rs` — cell/bucket padding (None = identity) | Wire padding into the **standard** Tier-2 path (currently opt-in) |
| Dispute | `contracts/mil/src/DisputeGame.sol` — challenger bond, **50 %** slash via `StakeManager` (challenger/burn split) | **TEE-anchored oracle** as primary (§22.3c); **4-way victim-refund** split (§22.4, B6) replacing challenger/burn-only; VRF committee demoted to fallback |
| Claim | `contracts/mil/src/JobEscrow.sol` — immediate cumulative claim (`settledCost`, `finalized`) | **Optimistic claim + 24 h window `W`** for Tier-2 (freeze-on-dispute, §22.4); **physical-throughput cap** in claim verification (§22.3d) |
| Payment unlinkability | L0 fresh addr (§15.2); L1 paymaster (`Paymaster.sol`) | **L2 STARK shielded pool** (fixed denominations, nullifier STARK, §21.3) — needs a PQ STARK verifier + gas/mass measurement (§12-21); **L3** PQ blind ecash (research) |
| Content hygiene | — | **Local PII scrubber**, **private mode** provider rotation, conversation dispersion (§21.4) — SDK-side |
| Calibration | Fee/slash constants exist | **`ρ > g/(S+V)` invariant** + S·ρ·W coupling frozen into the §10 parameter table (§22.6, precondition 2) |

None of the "v0.6 adds" column is implemented by this ADR — it is a design freeze. The largest new dependencies are
a **PQ STARK verifier** (L2) and **real Tier-1 supply** (the TEE-anchored oracle), both gated by hardware/research
roadmap items (design P2, §12-3/21/22).

---

## Consequences

**Positive.**
- Gives the non-TEE consumer-GPU lane (the RTX-4090 on-ramp, §16.3) a coherent, honestly-bounded trust model
  instead of an implicit "no guarantees" gap.
- The privacy machinery pays for itself twice: unlinkability *is* the audit substrate (canary unidentifiability),
  so §21 and §22 share cost.
- Correctness rests on objective checks and EV math, not on trusted human committees — the dispute path can be run
  by an enclave with no discretion, and slashing has no subjective trigger.
- Nothing here is consensus-affecting; the MIL EVM-lane precompiles stay INERT until a coordinated HF, so the
  freeze can mature without touching the running chain.

**Negative / limits (frozen honestly).**
- **Tier-2 content is provider-visible.** This is stated, not hidden; the guarantee is unlinkability, not secrecy.
- **A7/A11 are undetectable** and rely entirely on unlinkability + ToS (B9).
- **The TEE-anchored oracle depends on Tier-1 existing.** Before P2 hardware, Tier-2 disputes fall back to the VRF
  committee with its collusion surface (precondition 1).
- **L2/L3 payment shielding is unbuilt** and gated on a PQ STARK verifier and blind-signature maturity — until
  then, Tier-2 payment unlinkability is L0/L1 only (fund-graph-analyzable at L0).
- **The S·ρ·W coupling constrains future economics** — delegated staking (lower S) cannot ship without raising ρ
  and/or W; this is a deliberate handcuff (precondition 2).

**Follow-ups (tracked in the v0.6 §12 open list):** STARK verifier gas/mass + proving time (§12-21); PQ blind
ecash maturity (§12-22); relay-set Sybil/timing-correlation calibration (§12-23); embedding-inversion retest as
MPC-rejection is periodically re-validated (§12-24); canary natural-prompt distribution-match adversarial test
(§12-25); TEE-anchor verifier reward/availability + Tier-1-zero degradation policy (§12-26); per-device-class
throughput tables (§12-27); `g` (replacement-saving) measurement to fix the ρ floor (§12-28).
