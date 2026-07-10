# ADR-0036 — Shielded-proof DA envelope (carrying a hundreds-of-KiB outer proof)

- **Status:** Proposed (design; the numbers it needs are the ADR-0035 recursion
  bench, which landed T3, plus a simpa propagation run — both scoped below).
- **Date:** 2026-07-10
- **Extends:** ADR-0035 (STARK backend / O-SP-1 — the measurement that forces this),
  ADR-0030 / ADR-0026 (BPS staging + the DA *envelope invariant*), ADR-0033/0034
  (the shielded pool + F006). Distinct from ADR-0032 (Cancun opcodes).
- **Problem in one line:** the shielded pool's outer proof is measured at **170–382
  KiB** (ADR-0035 §4), but a DAG block's EVM payload cap is **32 KiB**
  (`MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK`). A proof cannot ride a block. This ADR
  makes it fit **without breaking the DA envelope or fighting BPS acceleration.**

---

## 1. The constraint is the envelope, not the per-block number

`consensus/core/src/evm/mod.rs`:

```rust
/// Stage B (ADR-0030 §3.2): ~1.2 MB/s envelope ÷ 40 BPS ≈ 32 KiB/block (global const).
pub const MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK: usize = 32 * 1024;
```

The 32 KiB is **derived**: a ~1.2 MB/s DA bandwidth envelope, sliced by 40 BPS. So
the real invariant is the **1.2 MB/s average**, and the design question is *not*
"raise the per-block cap by 5–12×" but "**let a rare, large outer proof through
while keeping the average inside 1.2 MB/s.**" Because aggregation is width-bound and
witness-free (ADR-0035 §5.5 / §8), one outer proof settles `k` shielded txs, so its
amortized DA is `outer / k` blocks — small even at k in the tens. The lever is
amortization + propagation decoupling, not brute cap size.

## 2. Decision

### D1 — A separate "shielded section," not a bigger EVM payload

Normal EVM payload stays capped at 32 KiB/block. A shielded outer proof rides an
**optional additional section**, **≤ 1 proof per block**, capped at `S` (design
point `S ≈ 256 KiB`, covering the ~213 KiB lb-4 outer with margin; NOT the 382 KiB
lb-2 or the pathological 170 KiB lb-5 — the prover-sane design point is lb 3–4).
Ordinary blocks are unchanged; only a block that actually carries an aggregated
proof is larger, and those are rare (1 per `k` shielded txs). **Average block size
barely moves; only the worst case is `32 + S`.** This keeps the §21 privacy lane
physically separate from the throughput lane.

### D2 — Compact-relay the proof (decouple proof DA from block propagation)

The proof is **gossiped into the mempool at tx-announce time**; the block carries
only a **hash reference** to it (the BIP-152 compact-block argument). A node that
already holds the proof reconstructs the block with no extra propagation bytes; only
a node missing it does a round-trip. This **decouples the proof's DA cost from the
critical block-propagation path** — the single mechanism that lets a hundreds-of-KiB
artifact coexist with fast BPS without inflating orphan risk. D2 is a **precondition**
for D1 at high BPS (see D3), not an optimization.

### D3 — Honest BPS × size propagation table (why D2 is mandatory)

Naive per-block propagation of a worst-case section, ignoring D2:

| BPS | block interval | worst-case section `S` | naive bytes/s added | vs 1.2 MB/s envelope |
|---|---|---|---|---|
| 10 | 100 ms | 256 KiB | if every block: 2.6 MB/s | **breaks** (2×) |
| 25 | 40 ms | 256 KiB | if every block: 6.4 MB/s | breaks (5×) |
| 40 | 25 ms | 256 KiB | if every block: 10 MB/s | breaks (8×) |

The table is only catastrophic under the false assumption that *every* block carries
the section. With D1 (≤1 proof/block AND proofs are rare, 1-per-k-tx) the **average**
added rate is `proof_rate × S`, which the aggregation batch `k` tunes below the
envelope headroom; and with D2 the worst-case block does not add propagation bytes at
all for nodes that pre-hold the proof. D3's job is to state the naive failure openly
so D1+D2 are shown to be **necessary**, not nice-to-have.

### D4 — Quantify orphan/red-rate with simpa (the review crux)

The repo ships a DAG simulator (`simpa/`). Before any activation, run it with
256/384/512 KiB proof-carrying blocks injected at the target proof rate, at 10/25/40
BPS, and report **red/orphan rate** against the ghostdag `λ·D_max ≲ k` regime. This
project has a real DE↔JP network-split history, so propagation headroom is the
audit crux, not a footnote. Acceptance: red-rate delta from injecting the shielded
section is within the ADR-0030 envelope-invariance budget.

### D5 — Pair the DA change with a pool batch entrypoint (the v0.3 payoff)

`ShieldedPool`/`MilShieldedEscrow` gain a **batch entrypoint** that consumes one
outer proof settling `k` `(nf, cm)` sets. This is what makes D1's "1 proof per k tx"
real on-chain and turns the SP-0-forced recursion into the v0.3 aggregation throughput
win: per-tx DA = `outer/k + encNote_floor`; at `S=256 KiB`, lb-4 outer 213 KiB, k=64
→ `213/64 + 3.4 ≈ 6.7 KiB/tx`, approaching the encNote floor (~385 TPS @ 10 BPS). A
testnet **filler-block A/B** validates the propagation model before mainnet.

## 3. Consequences

- **Positive.** A hundreds-of-KiB PQ proof — the measured world-floor, unavoidable
  without a pairing wrap — becomes carriable **without touching the 1.2 MB/s envelope
  or slowing BPS**, via amortization (D1/D5) + propagation decoupling (D2). Privacy is
  intact: aggregation is witness-free, so the aggregator never sees tx content
  (ADR-0035 §8).
- **Cost / risk.** D2 (compact-relay for the shielded section) is real consensus/
  networking work and must land before high-BPS activation. If the D4 simpa run shows
  even the amortized rate dents the envelope, the fallbacks are a smaller `S` (design
  at lb-5 170 KiB, accepting worse prover cost), a lower proof rate (bigger `k`), a
  narrower proof (stwo/M31 or STIR/WHIR, ADR-0035 §4), or — last — a modest envelope
  increase re-derived through ADR-0030's invariant.
- **Honest boundary.** This ADR is blocked on two numbers: the ADR-0035 recursion
  outer size at the chosen field/impl (have: 170–382 KiB on KoalaBear/Plonky3), and
  the D4 simpa red-rate. It does not change consensus yet; it is the plan that turns
  the T3 verdict into a shippable DA design. Nothing here is inert code — it is a
  design freeze pending those measurements and an audit.

## 4. Open items

- **O-DA-1:** compact-relay wire format for the shielded section (reuse the tx-gossip
  path vs a new inv type).
- **O-DA-2:** `S` and the proof-rate/`k` coupling frozen against the ADR-0030 envelope
  invariant (the analogue of the `ρ > g/(S+V)` freeze in ADR-0025).
- **O-DA-3:** STIR/WHIR Rust-impl maturity scout (external) — if a mature one exists,
  a ~1.5–3× smaller outer could pull the design point toward T2 (envelope-light).
