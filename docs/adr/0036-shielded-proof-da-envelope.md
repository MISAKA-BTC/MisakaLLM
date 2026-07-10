# ADR-0036 — Shielded-proof DA envelope: chunk transport + windowed budget

> **Reference tree:** `feat/mil-v0` @ `d6e8297` (134 commits ahead of public main
> `9314c70`). Consensus constants cited here are working-tree values; **public main
> still carries the pre-Stage-B `MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK = 128 KiB`,
> this tree carries `32 KiB`** — the *same* DA budget expressed at a different BPS
> (see §1). All `file:line` citations are against this commit.

- **Status:** Proposed (design; unblocked on the "does it fit one block" question —
  the answer is *no, unconditionally*, §2 — and blocked only on the β/W numbers a
  simpa run + verifier-time measurement will fix).
- **Date:** 2026-07-10
- **Extends:** ADR-0035 (the measurement that forces this), ADR-0030 / ADR-0026 (the
  DA **envelope invariant** + BPS staging), ADR-0022 (`--ibd-trust-dns-finality` /
  snapshot-IBD prune precedent), ADR-0033/0034 (pool + F006). Distinct from ADR-0032
  (Cancun opcodes).

---

## 1. The load-bearing constant is the envelope E, not the per-block cap

The per-block EVM payload cap is a *derived, BPS-dependent* slice of one physical
budget. This is provable from the tree divergence itself:

```
128 KiB × 10 BPS  =  32 KiB × 40 BPS  =  1,280 KiB/s  ≈  E ≈ 1.25 MiB/s
```

Public main's `128 KiB` (@10 BPS) and this tree's `32 KiB` (@40 BPS, Stage B) are the
**same envelope** `E`. The per-block number is ephemera; **only `E` is load-bearing.**
Therefore every threshold in this ADR and in ADR-0035 is frozen in **units of `E`
(a share `β`)**, never in per-block KiB — a per-block figure silently moves 4× across
the BPS roadmap (at 50 BPS the cap is ~25.6 KiB, below even ADR-0035's old "T1 comfort"
of 32 KiB — a self-contradiction that E-units remove). *Process note:* this whole
correction traces to a 4× consensus-constant divergence between the public tree and
the working tree that no doc pinned — hence the reference-commit header above, now
mandatory on any ADR citing a consensus constant.

## 2. Indivisibility lemma — a single block cannot carry the proof, on any path

Measured outer floor (ADR-0035 §4): **170 KiB** (extreme blowup) to **382 KiB**
(sane prover). Per-block cap: 32 KiB (@40 BPS) / 25.6 KiB (@50 BPS). Gap = **5.3–12×**.
Best-case future compression (STIR/WHIR, ~1.5–3× smaller at equal security; WHIR's
verifier is also faster → helps O-SP-2 `F006_VERIFY_GAS`) yields **57–113 KiB** — still
1.8–4.4× over a single block. **Conclusion: no proof system, present or near-future,
fits the outer proof in one block.** A transport mechanism is therefore an
**unconditional necessity**, not contingent on the stwo cross-check or STIR/WHIR — those
only tune the *chunk count* and the *share*, never the need. (At the old 128 KiB there
was a thin "lb-5 single ~ barely fits" gap; at 32 KiB it is gone — the correction
*strengthened* the conclusion.)

## 3. Decision — chunk transport (primary) × windowed budget (accounting)

The master/slave from the 128-KiB era inverts. A "section carve-out" that puts a
213–382 KiB block on a 25 ms mesh is a **7–12× oversized block** on a network with a
real DE↔JP split history — expensive to justify in simpa *and* the live net. Instead:

### A — Chunk transport (primary)

Split the outer proof into **≤ 32 KiB chunks (7–9 of them)**. **Every block stays its
current size, so the propagation profile is untouched and the ghostdag `λ·D_max ≲ k`
argument is trivially preserved.** All chunks land in ~175–225 ms @ 40 BPS (~200 ms @
50 BPS) — latency buried in the DNS-finality wait, invisible to UX. Consensus surface,
each piece reusing an existing mechanism:

- an **inert chunk object**: syntactic (class-1) validation only — no state touch;
- **assembly at the accepting block**, riding the existing mergeset delayed-acceptance
  path (no new ordering rule);
- a **commitment reference** from the settling tx to the chunk-set root;
- **per-byte DA charge** on chunks so spam is self-funded;
- **unreferenced-chunk TTL prune**; an **incomplete set → skip** (class-2-style,
  matching the EVM lane's existing skip-class taxonomy), nonce untouched, re-includable.

### C — Windowed budget (the accounting rule on top of A)

```
Σ shielded-DA bytes over any W consecutive blocks  ≤  β · E · W
```

`β = SHIELDED_DA_SHARE`, a **BPS-denominated consensus parameter of `E`** — so it does
**not** re-freeze across BPS stages (the formal encoding of "ask in rate, not in
per-block bytes"). `W` is the smoothing window. This bounds the shielded lane's
*average* DA to a share of the envelope while A keeps any *instantaneous* block normal.

### B — Section carve-out (conditional reject / fallback)

Kept on record only as a fallback if chunk assembly proves heavier than A's estimate;
rejected as the primary because it perturbs the propagation profile the network's split
history makes precious.

## 4. Retention is asymmetric (essential, and not optional)

- **Proof chunks are verify-once ⇒ prunable after DNS finality.** Once the settling tx
  is DNS-final, the proof has done its job; chunks may be pruned, consistent with the
  ADR-0022 snapshot-IBD + `--ibd-trust-dns-finality` precedent.
- **encNote is NOT prunable.** A seed-restored wallet must trial-decrypt the full note
  history to find its notes, so encNote retention is a **wallet-liveness requirement**.
  It becomes prunable only once O-SP-4 (a discovery / note-tagging redesign) provides
  an alternative — until then, encNote is permanent while proofs are ephemeral. This
  asymmetry must be wired into the pruning rules, not assumed away.

## 5. Propagation verification (measured — and it moves the argument)

`simpa/` (the in-workspace DAG simulator, PQ-patched: coinbase → PubKeyHashMlDsa87,
`--tpb 0`) was run at 40 / 50 BPS across a delay sweep. **Measured result:**

| bps | delay (≈ propagation) | mergeset blues | reds |
|---|---|---|---|
| 40 | 0.1 s | 4.7 | **0** |
| 40 | 0.5 s | 21.0 | **0** |
| 40 | 1.0 s | 41.7 | **0** |
| 40 | 2.0 s | 67.5 | **0** |

**Ghostdag red-rate is 0 across every realistic delay.** Mergeset width scales linearly
`blues ≈ bps × delay`, and reds appear only when concurrency approaches `k = 447`, i.e.
delay ≈ **11 s @ 40 BPS** — 30–100× beyond any real propagation. Mapping to the A/B: a
≤32 KiB chunk block adds ~0.05–0.15 s (blues ≈ 5); a 213–382 KiB oversized block adds
~0.1–0.3 s (blues ≈ 10–15) — **both reds = 0. Oversized blocks do NOT cause orphans; the
k-margin absorbs them.**

This *sharpens* the ADR rather than contradicting it. The binding constraint was never
ghostdag reds — it is **(a) the DA bandwidth envelope** (1.25 MB/s, ADR-0030) and **(b)
mergeset-width / confirmation-depth growth** (linear in delay). So the case for chunk
transport (§3.A) is **envelope-conformance + latency smoothing** (keeping per-block delay
small ⇒ mergeset width ~constant), *not* orphan avoidance. And **β's floor is set by the
bandwidth share, not a red-rate cliff** — the DAG tolerates the concurrency, so `β` is
bounded only by the envelope it shares with the EVM + tx lanes and by a confirmation-depth
budget, which is a far weaker constraint than an orphan limit would have been.

A testnet **filler-block A/B** still confirms the bandwidth/mergeset model on the live
topology (with its DE↔JP-split latency) before mainnet — that is where an *envelope*
breach, not a red, would show. Design + protocol:
`docs/mil-shield-filler-block-ab-runbook.md` — it sweeps per-block size `S` over the
real JP↔DE mesh (`rothschild --payload-size` filler, `max_block_mass` raised mesh-wide,
a first-seen wRPC probe for diameter propagation delay) to find `S*`, the largest block
the mesh absorbs without envelope breach; chunk size ≤32 KiB must sit well below `S*`.

## 6. Budget table (Stage B, E ≈ 1.25 MiB/s; per-tx = outer/k + encNote 3.4 KiB, lb-4 outer 213 KiB)

| β (share of E) | k=64 (6.7 KiB/tx) | k=128 (5.1 KiB/tx) | encNote floor only |
|---|---|---|---|
| 25% | ~48 TPS | ~63 TPS | ~94 TPS |
| 50% | ~96 | ~125 | ~188 |
| 100% | ~191 | ~250 | ~376 |

`k` is bounded **not by proof size** (width-bound ⇒ aggregation ≈ free, ADR-0035 §5.5)
but by **batch-fill latency**: at 48 TPS, k=64 fills in ~1.3 s; low-traffic worst case
is a timeout-close at 2–5 s. So β and the k-policy are the two knobs; the proof size is
a constant the window absorbs.

## 7. Interface

- **Pool batch entrypoint**: `ShieldedPool`/`MilShieldedEscrow` consume one outer proof
  settling `k` `(nf, cm)` sets (the on-chain form of A+C; the v0.3 aggregation payoff).
- **F006 gas** from the *measured* recursive-verifier wall-clock (O-SP-2), not guessed.
- **Chunk gossip** rides mempool pre-distribution so the block carries only the
  commitment (BIP-152-style: no proof bytes on the critical block-propagation path).

## 8. Consequences & open items

- **Positive.** A hundreds-of-KiB PQ proof — the world floor, unavoidable without a
  pairing wrap — is carried with **zero change to block size or propagation** (A) and a
  **BPS-invariant average bound** (C). Privacy is intact: aggregation is witness-free
  (ADR-0035 §8). The design is independent of which prover wins (§2).
- **Honest boundary.** Design freeze, no consensus code yet; blocked on the §5 simpa
  red-rate and the §7 verifier-time number. The chunk object, assembly, and pruning
  asymmetry are real protocol surface requiring an audit.
- **Open:** **O-DA-1** chunk gossip wire format (reuse tx-gossip inv vs new type);
  **O-DA-2** `β` and `W` frozen against the ADR-0030 **bandwidth** invariant (§5 showed
  the DAG absorbs the concurrency with no reds, so `β` is envelope-bounded, not
  orphan-bounded — a weaker constraint; analogue of ADR-0025's `ρ > g/(S+V)` freeze); **O-DA-3** k-policy (batch-fill latency vs UX timeout);
  **O-DA-4** STIR/WHIR adoption lands as a `circuit_version` bump (ADR-0034), tightening
  chunk count, never a precondition.
