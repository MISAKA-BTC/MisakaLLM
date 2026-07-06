# ADR-0027: MISAKA Testnet Points Program (MTP) — Scheme Freeze

## Status

**Proposed — scheme freeze, 2026-07-06. NOT implemented; publication gated on a legal
review.** Code-grounded freeze of
[`docs/misaka-testnet-points-program-design-v0.1.md`](../misaka-testnet-points-program-design-v0.1.md)
— a testnet-only contribution points program whose points convert to MSK at TGE
(mainnet launch). Every "§N" / "O-n" below points to that design.

This ADR **relates to but does not supersede**: [ADR-0026](0026-bps-acceleration-ibd-fast-sync.md)
(the BPS stages/gates the point weights are designed to feed),
[ADR-0017](0017-all-active-staker-attestation.md) (on-chain attestation records =
the C1 validator-scoring source), [ADR-0018](0018-quality-gated-stakescore-inclusion-economics.md)
(the quality-gate philosophy it inherits), and
`consensus/core/src/config/premine.rs` (the pool source). It is an **off-chain
program** and changes **no consensus code**.

> **Hard preconditions (non-negotiable).**
> 1. **Legal review (O4) is a HARD precondition of PUBLICATION, not a follow-up.**
>    Before announcing the program, a legal review MUST settle: (a) regional
>    eligibility (sanctions / excluded jurisdictions), (b) KYC need + thresholds,
>    (c) terms wording (points worthless / discretionary / amendable), (d)
>    distribution method (self-claim vs push). This ADR is *scheme design only*,
>    not legal advice (§9). Nothing publishes until (a)–(d) are signed off.
> 2. **Points are non-transferable accounting units with no value and no claim
>    right; final allocation is discretionary** (§6.5). The testnet coin stays
>    worthless (NG1). This is the legal safety valve and MUST be in the terms.
> 3. **The pool earmarks an EXISTING genesis vault — it does NOT change genesis.**
>    `premine.rs` already fixes 40 vault UTXOs of `VAULT_PREMINE_SOMPI =
>    100_000_000` KAS/MSK each (+ a 9B main), total 13B premine; the vault
>    addresses are **mainnet custody with the ceremony COMPLETE + locked** (audit
>    H-01). Earmarking ONE vault (100M MSK ≈ 0.36% of the 28B supply) as the MTP
>    pool is a **custody/allocation decision recorded off-chain** — it does not
>    edit `premine.rs`, the genesis hash, or `utxo_commitment`. Only if the pool
>    ever needed a *new dedicated* vault would that be a re-genesis (out of scope).
> 4. **Vulnerabilities MUST use the private `SECURITY.md` path.** Public-issue
>    disclosure of a security bug forfeits the points (§3.2). `SECURITY.md`
>    exists; O6 extends it with the S0–S3 rubric.
> 5. **Determinism + verifiability are load-bearing, not cosmetic.** Every epoch
>    ledger pins `rules_hash` + `inputs_hash` (BLAKE2b-512) and is ML-DSA-87-signed;
>    anyone can recompute the same ledger from the same facts (§2). Scores that
>    cannot be reproduced from published facts + published rules are invalid.

---

## Context

The BPS-acceleration program (ADR-0026) needs *real behavior* to measure its gates:
geo-distributed always-synced nodes (mergeset/tips under real propagation), per-stage
IBD benchmarks (the §5.1 SLO), partition-drill / load-test participation, and
consensus/EVM/overlay bug discovery. Rather than run that measurement infrastructure
separately, MTP **is** that infrastructure: it pays points for exactly the actions
the gates consume (appendix E maps each gate to its supplying activity), and settles
those points to MSK at TGE.

The design is deliberately single-operator-operable: a weekly deterministic batch
(pure function of collected facts × public rules) + a signed public ledger +
GitHub-based appeals, reusing `kaspa-pq-validator-core` for the registration-challenge
signature verification (~1–2 week single-service build, §4.5). The pool rides an
existing premine vault, so it needs no genesis change.

---

## Decision

**D1 — Scope: testnet only, points → MSK at TGE.** Covers testnet-10/25/40/50;
mainnet activity is out of scope (§0). Faucet testnet MSK stays worthless and is
unrelated to points (NG1). Settlement is a single TGE event (NG2), never
mid-program cash-out or transfer.

**D2 — Four activity categories, weights 40/30/15/15** (§3, §6.2): **C1 node
operation 40%** (full-node uptime with *sync required*, validator/attestor
participation, IBD-bench submission, drill participation), **C2 bug reports 30%**
(S0 5000 / S1 2000 / S2 500 / S3 100; first-report only, dup 10%, repro required,
private disclosure mandatory), **C3 verification/feedback 15%** (campaigns,
accepted feedback, load-window tx), **C4 infra 15%** (seeders, same-region IBD
seeds, explorer/faucet/monitoring, docs/tooling PRs). A **stage coefficient
`m_stage`** (A×1.0 / B×1.25 / C×1.5) multiplies every category — higher BPS stages
cost more to participate in and yield more valuable data.

**D3 — Deterministic, verifiable scoring** (§2, §4.3): weekly epochs (UTC Monday);
`inputs_hash` (BLAKE2b-512 of all facts) + `rules_hash` (pinned rules yaml) per
epoch; scoring engine = pure function → `epoch_scores`; ML-DSA-87-signed JSONL
ledger published to misakascan + repo `points/`, each score linking evidence
(crawler sample / on-chain attestation / GitHub issue / tx id); **7-day appeal
window**; corrections re-issue the epoch with `supersedes` (old versions retained).

**D4 — Sybil resistance by real cost** (§5, §8): uptime samples require the
advertised sink timestamp within **300 s** (real sync, not a heartbeat forgery);
per-ID node decrement `d_n` (1st ×1.0 / 2nd ×0.5 / 3rd ×0.25 / 4th+ 0); same /24 or
ASN capped at 2 nodes; **per-ID cap = 5% of the total pool** with in-category
redistribution; and the standing cost of a 40–50 BPS full node at Stage B/C.

**D5 — Pool = one existing premine vault** (O1, precondition 3): earmark
`VAULT_PREMINE_SOMPI` = 100M MSK (≈0.36% of 28B) as the MTP allocation — a custody
decision on the already-existing genesis vaults, no genesis change. Pool size
adjusts in vault-count units (0.5 vault = 50M needs tooling).

**D6 — TGE settlement** (§6.3–6.4): `reward_i = Σ_c Pool·w_c·pts_{i,c}/Σ_j pts_{j,c}`
→ clip at the 5% per-ID cap → redistribute the excess within the same category by
point ratio (once) → floor, remainder to the ecosystem fund. Recipients above 0.1%
of the pool (>100k MSK) vest **25% at TGE + 75% linear over 6 months**; smaller ones
are TGE-lump. **Claim via PQ-key continuity:** the registered testnet ML-DSA-87 key
signs the mainnet receiving address — testnet identity *is* the mainnet-claim auth.
Unclaimed after 6 months returns to the ecosystem fund.

**D7 — Re-genesis resilience** (§4.4): the ledger + cumulative points are
**off-chain** and persist across the testnet-25/40/50 barrier re-geneses (ADR-0026
D1); on-chain evidence is referenced with the network suffix
(`testnet-40:txid…`), valid only in that stage's ledger.

**D8 — Single-operator operation** (§4, §7): a single Rust service + cron (registry
/ p2p-crawler ×2 vantage / chain-indexer / github-sync / campaign-forms / scoring
engine / signed ledger / dashboard), reusing `kaspa-pq-validator-core` for the
registration-challenge verify; crawlers co-located on the existing DE/JP seeder
hosts. Triage SLA = time-to-first-triage (S0 24h / S1 72h). Event calendar (drills,
load windows, IBD-bench windows) shares ADR-0026 §6's schedule; drill/load points
only count for calendared events.

---

## Consequences

**Positive.**
- The incentive program doubles as the BPS measurement infrastructure — every paid
  action feeds an ADR-0026 gate (appendix E), so participation directly buys the
  data the staged rollout needs.
- Fully off-chain, zero consensus change; the only on-chain touchpoint is optionally
  earmarking one *already-existing* premine vault at TGE (a custody decision).
- Determinism + signed ledgers + hash-pinned rules make the whole allocation
  auditable and reproducible, which is both a fairness property and a legal-defense
  posture (discretion + verifiable basis).
- Sybil resistance leans on the same "real cost" the network itself imposes at high
  BPS, rather than on KYC-heavy gating.

**Negative / limits (frozen honestly).**
- **Cannot publish before the legal review** (precondition 1) — region eligibility,
  KYC, terms, and distribution method are unresolved (O4) and gate announcement.
- **Points confer no right** (precondition 2) — deliberately, as the legal valve;
  participants must accept discretionary final allocation.
- **Single-operator triage is a centralization/arbitrariness risk** (R4), mitigated
  only by public rationale + appeal window + hash-pinned rules, not by decentralized
  judgment.
- **The pool earmark touches mainnet custody records** (precondition 3): re-assigning
  a completed-ceremony vault to MTP must be reflected in custody/ceremony
  bookkeeping; getting a *new* dedicated vault instead would force a re-genesis.
- **Open calibration** (O5/O7): the ASN/decrement coefficients and the
  heartbeat-vs-crawler-only choice are Stage-A-tunable, not final.

**Open decisions carried forward:** O1 (pool size), O2 (category split), O3
(cap/vesting), **O4 (legal — publication precondition)**, O5 (ASN/decrement
coefficients), O6 (severity points + SECURITY.md rubric), O7 (heartbeat), O8
(intermediate perks). O2/O3/O6 settle pre-publication; O5/O7 after Stage A
measurement.
