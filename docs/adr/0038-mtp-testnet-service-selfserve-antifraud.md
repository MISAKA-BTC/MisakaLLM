# ADR-0038 — MTP Testnet Service Layer: self-serve points lookup, registration, and anti-fraud enforcement

> **Reference tree:** `feat/mil-v0` @ `2096c78`. Code claims below are grounded in
> `mtp/src/` (crate `misaka-mtp`, landed `5dd6850`) and `mtp/collectors/src/`
> (crate `misaka-mtp-collectors`, landed `3f85b34`).

- **Status:** Proposed (implementation design; buildable now, **announcement still
  gated on ADR-0027 precondition 1 = legal review O4**). Off-chain, consensus-neutral,
  **testnet-only** — no fence needed because nothing here touches consensus code;
  the only mainnet touchpoint is the TGE claim (D8), which is a custody action.
- **Date:** 2026-07-12
- **Extends:** [ADR-0027](0027-testnet-points-program.md) (scheme freeze — categories,
  weights, determinism, settlement; unchanged here). Consumes
  [ADR-0017](0017-all-active-staker-attestation.md) (attestation store = C1 validator
  facts) and [ADR-0026](0026-bps-acceleration-ibd-fast-sync.md) (stage calendar).
- **Scope rule:** this ADR designs the **service layer only** — the I/O ring that
  ADR-0027's deterministic core deliberately excludes. It changes **no scoring rule,
  no weight, no cap**; where it needs a number, it cites ADR-0027 / design v0.1
  and the `Rules` defaults already frozen in code.

---

## 1. Context

ADR-0027 froze the scheme: four activity categories — **bug reports on testnet,
verification/feedback submissions, node operation, network-stabilization / infra
contributions** (C2/C3/C1/C4, weights 30/15/40/15) — scored weekly into an
ML-DSA-87-signed, bit-reproducible ledger, settled to MSK at TGE. Two crates
already implement the trust-critical half:

| layer | crate | state |
|---|---|---|
| deterministic core (score / settle / ledger sign+verify / registration+claim verify) | `misaka-mtp` | **DONE** (`5dd6850`), integer-only, 18+ tests (`verify_claim` itself untested — D8) |
| Sybil aggregation (per-owner rank `d_n`, /24-or-ASN cap = 2, fail-closed keyless bucket, uptime folding) + `FactStore` + `Collector` trait | `misaka-mtp-collectors` | **DONE** (`3f85b34`), but the four collectors are **pure data-holder structs — no real I/O exists** |

What does **not** exist is everything a participant actually touches:

1. **No way for a participant to check their own points.** The signed JSONL ledger
   is designed for publication (design §4.1: misakascan + repo `points/`), but no
   query surface, no dashboard wiring, no CLI exists.
2. **No running service.** Registration challenge issuance, the weekly epoch cron,
   crawler I/O, GitHub sync, ledger publication — all unimplemented (the collectors
   crate's own docs enumerate this).
3. **Service-layer fraud gaps that the core cannot close by construction** (found
   by code audit of the two crates, D4 below): identity-namespace splitting
   defeats `d_n` and the 5 % cap; `geo_diverse`/`fast_follow` are trusted booleans;
   `build_epoch_input` double-counts if the store isn't epoch-fresh; challenge
   nonces, duplicate adjudication, and C3/C4 point resolution have no defined
   lifecycle (nor do ledger corrections — D6).

This ADR fixes the requirements the program owner set for the implementation:
**(R-a) points exist on testnet only; (R-b) every participant can look up — and
independently verify — their own points; (R-c) inflating points fraudulently must
be expensive and detectable.**

---

## 2. Decision

### D1 — Testnet-only is enforced cryptographically, not by deployment convention

- Registration accepts **only `misakatest:` v2 ML-DSA-87 P2PKH addresses**:
  `verify_registration(.., expected_prefix = Prefix::Testnet)` already rejects
  mainnet addresses (`WrongPrefix`), non-ML-DSA versions (`WrongVersion`), and
  keys that don't hash to the address payload (`KeyAddressMismatch`)
  (`mtp/src/registry.rs`). The service passes the testnet prefix as a **compile-time
  constant of the service binary**, not config — there is no mainnet mode to
  misconfigure into existence.
- Every ledger's `network` field (`"testnet-10"` / `"testnet-25"` / `"testnet-40"`
  / `"testnet-50"` — the full ADR-0027 D1 set; testnet-10 is the live network today
  and is in scope from service go-live) is inside both `inputs_hash` and the signed
  digest (`mtp/src/lib.rs`, `mtp/src/ledger.rs`) — a testnet ledger cannot be
  replayed as anything else.
- On-chain evidence is recorded **network-suffixed** (`testnet-40:txid…`, design
  §4.4) and is valid only in that stage's ledgers; the cumulative point totals are
  off-chain and survive the ADR-0026 re-geneses.
- The single mainnet touchpoint remains the TGE claim (D8): the registered testnet
  key signs the mainnet receiving address under `MTP_CLAIM_CONTEXT`. Nothing else
  in this service ever sees a mainnet address.

### D2 — One service binary: `misaka-mtp-service` (new crate `mtp/service`)

Single Rust binary + cron, per design §4.5 (1–2 week build). Components:

```
misaka-mtp-service
├── registry     — challenge issuance + verify_registration + identities table
├── collectors   — real I/O impls of the misaka-mtp-collectors Collector trait:
│    ├── p2p-crawler ×2 vantages (DE + JP, co-hosted on the existing seeder hosts)
│    ├── chain-indexer (wRPC to a local testnet node; attestations from the
│    │    ADR-0017 rewarded-epochs store, load-window tx counts, slashing events)
│    ├── github-sync (issues/PRs + triage labels, Appendix-D label set)
│    └── campaign-forms (submission ingestion, evidence URI required)
├── epoch-cron   — Monday 00:00 UTC cutoff → fresh FactStore → build_epoch_input
│                  → score_epoch → EpochLedger::sign → publish (D5)
├── query-http   — read-only self-serve lookup (D3)
└── store        — SQLite (design §4.2 schema) + append-only ledger archive
```

- **HTTP stack:** hand-written HTTP/1.1 over raw tokio, copying the house pattern
  of `rpc/eth/src/lib.rs` (`kaspa-eth-rpc`): `TcpListener` + connection semaphore +
  per-phase timeouts + body cap + `Connection: close` + CORS. This is deliberate —
  the workspace pins tokio 1.42.1, which rules out axum/hyper/jsonrpsee (stated in
  `rpc/eth/Cargo.toml`), and the eth-rpc crate is the proven template.
- **Store:** SQLite per design §4.2 (`identities`, `nodes`, `uptime_samples`,
  `attestations`, `gh_events`, `submissions`, `epoch_scores`) **plus
  `chain_fixed(author_id, kind, evidence, ts)`** — the seventh fact table the
  crate's `FactStore` already carries for IBD-bench/drill facts
  (`mtp/collectors/src/store.rs`; design §4.2 omits it). Ingestion route:
  IBD-bench submissions arrive via campaign-forms, drill participation is
  confirmed by chain-indexer — the `Collector` trait allows either to write
  `chain_fixed` rows. Plus an append-only directory of published ledger JSONL
  files (one per epoch **per issue**, D6).
- **Transport note:** design §4.1 specifies the chain-indexer as "gRPC / store
  read"; this ADR uses **wRPC** (the house RPC of every other in-repo client) —
  an implementation-transport refinement, not a data-source change: the facts
  still come from the service's own node (I-MTP-8).
- **Hosting:** crawler vantages co-located on the existing DE/JP seeder hosts;
  the service itself on `.119` next to misakascan's REST stack.

### D3 — Self-serve points lookup (R-b): convenience view + verifiable authority

The **authoritative artifact is the published, ML-DSA-87-signed epoch ledger** —
not any HTTP response. The lookup surface is a read-only mirror of exactly those
signed files, in three forms:

1. **HTTP query API** (`query-http`, unauthenticated, read-only):
   - `GET /mtp/v1/points/<id>` → `{ id, cumulative: {c1..c4, total}, epochs: [ {epoch, network, c1..c4, evidence[], rules_hash, inputs_hash, superseded: bool} ], operator_pubkey_hash, latest_epoch }` — every number is copied verbatim from signed ledgers; the response also carries, per epoch, the URL of the signed JSONL it was read from.
   - `GET /mtp/v1/epoch/<n>` → the signed ledger JSONL for epoch *n*, byte-exact
     (all issues if superseded, latest first).
   - `GET /mtp/v1/rules/<rules_hash>` → the borsh-serializable `Rules` document
     whose `Rules::rules_hash()` equals `<rules_hash>`, plus the yaml source.
   - `GET /mtp/v1/operator` → the operator ML-DSA-87 pubkey (2592 B, hex) and its
     out-of-band pins (repo file + misakascan page + release notes).
   - IDs are the ledger's registered-handle keys (`gh:<handle>`); the API serves
     nothing that is not already in the published signed ledger — no unpublished
     partial scores, no registration internals. **Published-linkage honesty:** the
     program *does* publish, by design, the linkage GitHub handle ↔ registered
     `misakatest:` address (and, at TGE, ↔ the mainnet claim address), over a
     trivially enumerable ID space — this is a **consented disclosure recorded in
     the registration terms**, not an accident, and most privacy regimes treat it
     as personal data (feeds the O4 legal review). Design §4.1's "displays
     registered handles only" governs the *dashboard rendering*, not the ledger
     content.
2. **misakascan dashboard**: leaderboard + per-ID page rendering the same API,
   with a "verify this yourself" box showing the three-step recompute recipe below.
3. **CLI**: `misaka mtp points <id>` — new `Command::Mtp` subcommand in
   `misaka-cli` following the `eth.rs` raw-HTTP client pattern, honoring the global
   `--output human|json`; and `misaka mtp verify-epoch <file.jsonl>` which runs the
   full verification locally.

**Self-verification recipe (what makes the mirror trustless).** Anyone — in
particular a participant checking that *their own* row is correct and that the
operator can't silently change it later — can:

1. **Signature**: fetch the ledger JSONL and the operator pubkey; check
   `EpochLedger::verify(pubkey)` (`mtp/src/ledger.rs` — the digest is recomputed
   from the ledger contents under `MTP_LEDGER_CONTEXT`, so a single milli-point of
   tamper flips it, tested).
2. **Rules**: recompute `Rules::rules_hash()` from the published rules document and
   compare to the ledger's pinned `rules_hash`.
3. **Recompute**: feed the published facts (each `ScoreRow.evidence` links them)
   through `score_epoch` — a pure, integer-only, order-independent function — and
   byte-compare the resulting ledger. `misaka mtp verify-epoch` automates 1–3.

Because the ledger is append-only and corrections are supersede-reissues (D6),
"my points changed and nobody can prove it" is not an expressible state: both the
old and new signed files exist, and the appeal record (D6) explains the delta.

### D4 — Anti-fraud enforcement (R-c): five layers, and the four service-layer gaps this ADR closes

The core and collectors crates already enforce, per layer:

- **L3 scoring (in `misaka-mtp`, DONE):** per-owner node-rank decrement
  `d_n = [×1.0, ×0.5, ×0.25, ×0]`; slashed validator forfeits the whole week
  (`pts_validator → 0`); duplicate bug reports ×0.1 (first report only at 100 %);
  zero-denominator → 0 points, never a panic; `scale()` saturates.
- **L3 aggregation (in `misaka-mtp-collectors`, DONE):** same /24 **or** same ASN
  → max 2 nodes counted; nodes with *neither* /24 nor ASN attribution share one
  capped bucket (**fail-closed**, tested); rank order is deterministic
  (`first_seen_ms`, then `node_key`).
- **L4 settlement (in `misaka-mtp`, DONE):** per-ID cap = 5 % of pool, pro-rata
  clip, single-pass in-category redistribution, lossless
  (`Σ rewards + ecosystem_remainder == pool`, tested).
- **L5 transparency-as-deterrence (DONE in format, D5/D6 operationalize):**
  signed ledger + `inputs_hash` + `rules_hash` + per-row evidence links + 7-day
  appeal + supersede-reissue. Fraud that survives L1–L4 is still *visible*: every
  point is publicly attributable to a concrete artifact anyone can dispute.

The service layer (this ADR) adds **L1 identity** and **L2 fact authenticity**,
and closes four gaps that code audit of the existing crates surfaced:

**G1 — Identity-namespace splitting (the one real scoring-layer hole).**
In the collectors crate, the ledger id is whatever string the fact carried
(`gh:carol`, `addr:bob`, `op:alice`) — the `identities` table is **write-only**;
nothing joins namespaces. One human with a GitHub handle, an on-chain address, and
a node key is *three* ledger IDs, which defeats both `d_n` (register each node
under a fresh `op:` id) and the 5 % settlement cap (split winnings across ids).
**Fix (I-MTP-1):** the registry is the **single attribution authority**. Every
scoreable fact MUST resolve, through the registration record
(`identities(id, github, address, registered_at)` + bound node claim-tokens,
I-MTP-11), to the **one canonical ledger id `gh:<handle>`** before it enters the
`FactStore`. Facts whose author cannot be resolved to a registration are
**dropped, not bucketed** (fail-closed): unregistered contributions score zero.
Consequences: node facts attribute via the registration's claim-token (no
self-declared `owner_id`); chain facts attribute via the registered address;
campaign submissions via the registered handle.

**Honest scope of I-MTP-1:** this binds `d_n`, the colocation cap, and the 5 %
cap at the level of the *registration*, not the human. It closes namespace
splitting (one registration can no longer appear as three ledger ids), but a
human holding N GitHub accounts holds N registrations, and `d_n` rank restarts
per registration (`aggregate.rs` ranks per owner). What still binds *across*
registrations is the colocation cap — it keys on the /24-or-ASN bucket globally,
regardless of owner — so multi-registration Sybil additionally requires real IP-
and AS-diversity per extra node. Beyond that, 1-person-1-ID remains self-declared
with full forfeiture on discovery (design §5, frozen by ADR-0027); discovery is
supported by **advisory clustering signals the operator monitors** (registration
timing correlation, shared /24 reuse across registrations over time, common
funding source of registered testnet addresses, shared campaign-form metadata) —
advisory means they trigger human review and possible forfeiture, never automated
scoring changes (else they'd break ledger reproducibility).

**G2 — Self-reported multipliers.** `NodeRecord.geo_diverse` / `fast_follow`
(×1.5 / ×1.2) are passed through verbatim today. **Fix (I-MTP-2):** both booleans
are **derived by the service, never ingested**: `geo_diverse` from crawler-observed
IP geolocation at both vantages (non-DE/JP region per design §3.1), `fast_follow`
from the crawler-observed protocol/version string crossing the release version
within 72 h of publication. Any field a participant can set in their own node
config is treated as a claim, not a fact.

**G3 — Epoch scoping.** `build_epoch_input` does **not** filter by the epoch
window — the caller contract (documented in the crate) is a fresh `FactStore` per
run, or prior epochs double-count. **Fix (I-MTP-3):** the epoch-cron constructs a
fresh in-memory `FactStore` per epoch from SQLite rows `WHERE ts ∈ [monday, monday+7d)`;
a service-level test regression-pins that running the same cron twice yields
byte-identical ledgers and never double-counts.

**G4 — Undefined lifecycles: nonces, dedup adjudication, C3/C4 point resolution.**
The core verifies signatures over opaque challenge bytes; it does not generate,
expire, or single-use them, and it trusts the collector to hand pre-resolved
`base_points`. **Fix (I-MTP-4..6):**
- *Nonces (I-MTP-4):* server-issued 32-byte random nonce, bound to the requested
  `(github, address)` pair, **TTL 15 minutes, single-use, deleted on success or
  expiry**; the challenge message is the Appendix-B registration message verbatim
  (network, github, address, nonce, issued_at). Registration issuance is
  rate-limited (per IP and per GitHub handle) — cheap, since registration is rare.
- *Bug/dup adjudication (I-MTP-5):* `first_report`, `severity`, `fix_pr_accepted`,
  and duplicate status enter the `FactStore` **only** from the Appendix-D triage
  labels (`sev/S0..S3`, `points/accepted`, `points/duplicate-of-#N`,
  `points/rejected` + reason, `points/needs-repro`) — and github-sync MUST verify
  **via the issue timeline/events API that each scoring label was applied by an
  actor on a maintainer allowlist pinned in-repo** (like the operator key);
  label *presence* alone is spoofable by anyone with triage permission or a bot.
  Labels applied by non-allowlisted actors yield no fact; GitHub events without a
  terminal triage label yield no fact. Vulnerability reports of **any severity
  (S0–S3)** MUST arrive via the private `SECURITY.md` path; public-issue
  disclosure of a security-classified bug produces an explicit `points/rejected`
  fact — an affirmative recorded rejection of that report's points (ADR-0027
  precondition 4).
- *C3/C4 resolution (I-MTP-6):* `Fixed { base_points }` values are computed by the
  service from the design-§3.3/§3.4 tables **with the caps applied at ingestion**:
  load-window tx = 1 pt / 100 accepted tx, **cap 100 pt/event AND aggregate cap
  100 pt × (calendared events that epoch) per identity per epoch** — the per-event
  cap alone would not bound per-epoch take; only ADR-0026-calendared windows
  count; infra tiers 100–300 maintainer-assessed; docs/tooling PRs 50–500 per
  accepted item. No free-form point values exist in the ingestion path. **Honest
  note on wash-tx:** testnet fees are ~free, so self-directed transactions cost
  nothing — but generating load *inside a calendared window* is the paid activity
  by design; the defense is not cost but **saturation** (the caps above) plus
  windows being operator-scheduled and short.

**L2 fact-authenticity rules (crawler/chain), restated as invariants:**

- *Node ↔ registration binding (I-MTP-11).* The design's implicit "registered
  node" needs an actual possession proof — otherwise anyone can register a rival's
  (or any healthy public) node key and harvest its C1 uptime, and nothing binds a
  crawled IP to a registration. v1 binding: at registration the service issues a
  per-registration **claim-token** (short hash derived from the registration
  record); the participant configures their node to carry `mtp:<token>` in its
  P2P **user-agent comment** (kaspad already supports user-agent comments — no
  protocol change). The crawler attributes a sample to a registration **only** if
  it observes the token in the handshake. Security direction is what matters:
  putting *your* token into a node requires config access to that node, so you
  cannot claim a node you don't operate; conversely, a stranger advertising your
  token only donates uptime *to you* (and counts against *your* `d_n`/colocation
  buckets — griefing via token duplication is damped by keying node identity as
  (token, observed endpoint) and by the caps). This is **possession-of-config
  binding, not cryptographic proof-of-possession**; a signed in-handshake
  challenge needs a P2P protocol change and is deferred (O-SV-4). Nodes observed
  with no (or an unknown) token are dropped, not bucketed (I-MTP-1 fail-closed).
- *Uptime = proven sync, not advertised sync (I-MTP-7).* The advertised sink
  timestamp is **participant-settable** — by this ADR's own I-MTP-2 principle it
  is a claim, not a fact, and alone it would let a chainless stub node farm C1
  (40 % of the pool) by advertising fresh timestamps. A sample therefore counts
  as up **only if all three** hold at crawl time: (a) handshake succeeds (with
  the I-MTP-11 token); (b) advertised sink timestamp within **300 s** (design
  §3.1 — kept as the cheap first filter); (c) the peer **passes a sync probe**:
  the crawler requests a block the *crawler's own synced node* knows to be recent
  (e.g. a selected-chain block a few minutes old, chosen fresh per sample) and
  the peer serves it within timeout — serving the correct bytes at a
  crawler-chosen recent hash proves possession of recent chain data and cannot be
  forged by timestamp games. Reachable-but-probe-failing counts as down (this is
  the `in_sync` bit the aggregation folds). Samples from **two independent
  vantages (DE, JP)** at ~10-minute cadence; evidence ids name the vantage.
  Heartbeats do not exist in v1 (O7: crawler-only start).
- *Network attribution is derived and reconciled (I-MTP-12).* The /24-or-ASN
  colocation cap is only as real as its inputs: (a) the crawler derives /24 (v4)
  or /48 (v6) prefixes from the **observed TCP source address at each vantage**,
  and a node counts against **every** bucket any vantage observed for it (union —
  a node showing DE one /24 and JP another lands in both, so per-vantage IP
  games make the cap tighter, not looser); (b) the crawler **always performs ASN
  attribution**, v4 and v6, from an ASN snapshot **pinned per epoch by hash in
  the inputs** (determinism) — without this the "or ASN" half of the cap is inert
  (`asn: None`) and IPv6-only nodes would all collapse into the single keyless
  bucket; with it, v6 nodes are properly ASN- and /48-capped.
- *Chain facts (I-MTP-8):* attestation/slash facts come from the service's own
  testnet node (ADR-0017 rewarded-epochs store), never from participant
  submission; load-window tx counts come from the service's own indexer over
  accepted-set transactions of registered addresses.

### D5 — Publication pipeline (determinism made operational)

Weekly, per design §4.3 (all times UTC):

1. **Monday 00:00** — collection cutoff. Epoch-cron builds the fresh `FactStore`
   (G3), runs the four collectors' window queries, resolves attribution (G1),
   freezes `inputs_hash`.
2. **Score + sign** — `score_epoch(input, rules)`; `EpochLedger::sign(operator_key)`.
3. **By Wednesday** — publish the signed JSONL to **both** the repo `points/`
   directory (append-only, one file per epoch-issue) and misakascan; the query
   API (D3) serves from the same files.
4. **7-day appeal window** — GitHub issue template, evidence links mandatory;
   appeals are deduplicated per (epoch, id) and rate-limited per identity —
   appeal floods cost the operator supersede churn, so the intake is bounded.
5. **Finalize** — or supersede-reissue (D6). Monthly cumulative snapshots are
   published alongside (design §7).

The rules yaml (mirroring the `Rules` struct, `RULES_VERSION` bumped on any edit)
lives in the repo next to `points/`; its `rules_hash` is what ledgers pin. O5's
Stage-A retuning of ASN/decrement coefficients is a rules-version bump + new hash —
old epochs stay verifiable against their pinned hash (I-MTP-9: **rules changes are
never retroactive**).

### D6 — Corrections: supersede-reissue envelope (service-layer, core untouched)

The core `EpochLedger` has no supersedes field — correctly, since the signed digest
must stay minimal. Corrections are a **service-layer envelope**: a reissued epoch
is a new fully-signed ledger file `points/epoch-<n>.<issue>.jsonl` (issue starts at
0), plus an unsigned index entry `{epoch, issue, supersedes: issue-1, reason,
appeal_url}` in `points/index.json`. Old issues are **never deleted**; `verify-epoch`
verifies any issue independently; the query API marks superseded rows (D3). An
epoch is *final* when its appeal window closes with no open appeal, and becomes
**immutable once the next monthly cumulative snapshot that includes it is
published (I-MTP-13)** — a finality horizon, so a late supersede cannot quietly
rewrite old history; after the horizon, an error is corrected by a *forward*
adjustment fact in a current epoch, visibly evidenced, never by reopening the
past ledger.

### D7 — Operator key hygiene

The ledger-signing key is a **dedicated MTP operator key** — not a validator
attestation key, not the premine custody key. Seed loaded via
`kaspa_pq_validator_core::load_validator_seed` (fail-closed on permissions/symlink);
pubkey pinned in-repo, on misakascan, and in release notes (D3). The five
`misaka-mtp-v1/*` domain-separation contexts are disjoint from every consensus and
MIL context (`mtp/src/lib.rs`); cross-context signature reuse is
**rejected-by-test for the register/claim pair** (`mtp/src/registry.rs` — a
claim-context signature fails registration verification), and the remaining
pairs (ledger ↔ register/claim/attestation) follow from ML-DSA context domain
separation — the announcement-gate tests (§5 test 6) extend the tested matrix.

### D8 — TGE claim (unchanged from ADR-0027 D6, restated as the only mainnet edge)

At TGE the registered testnet key signs the Appendix-B claim message (identity,
mainnet address, `total_points_ack`, server nonce) under `MTP_CLAIM_CONTEXT`.
`settle` + `vesting_split` (5 % cap, 0.1 %-of-pool vesting threshold, 25 % cliff
+ 75 % / 6 months linear) are implemented **and tested**; `verify_claim` is
implemented but currently **untested** — the announcement gate adds its
round-trip + tamper test (§5 test 6). Claim handling is a TGE-time custody procedure,
out of this service's runtime scope; unclaimed allocations return to the
ecosystem fund after 6 months.

---

## 3. Implementation plan

1. **`mtp/service` crate** — binary skeleton: config (vantage role / full role),
   SQLite store behind the design-§4.2 schema (+ `chain_fixed`, D2),
   `load_validator_seed` key loading.
2. **Registry** — nonce issuance + TTL store (I-MTP-4), `verify_registration`
   wiring, `identities` table + claim-token issuance (I-MTP-11), the G1
   attribution resolver (fact → canonical `gh:<handle>` or drop).
3. **Collectors, real I/O** — implement the `Collector` trait for: p2p-crawler
   (reuse the dnsseeder's handshake path; claim-token attribution I-MTP-11;
   sink-freshness + sync-probe I-MTP-7; union /24·/48 + epoch-pinned ASN
   attribution I-MTP-12; vantage-tagged evidence), chain-indexer (wRPC; ADR-0017
   store reads; I-MTP-8), github-sync (label-actor-verified facts, I-MTP-5),
   campaign-forms (cap-at-ingestion, I-MTP-6). `geo_diverse`/`fast_follow`
   derivation (I-MTP-2).
4. **Epoch-cron** — fresh-store window build (I-MTP-3), score, sign, publish to
   `points/` + misakascan; `index.json` + supersede flow + finality horizon (D6).
5. **Query surface** — `query-http` (eth-rpc HTTP pattern), 4 endpoints (D3);
   `misaka mtp points` / `misaka mtp verify-epoch` CLI; misakascan page.
6. **Tests (announcement gate, §5)** — then dark-launch on `.119` + DE/JP
   vantages against the live testnet-10 (carrying into testnet-25 at Stage A).
   Announcement waits for legal (O4).

## 4. New invariants

- **I-MTP-1** Every scored fact resolves through the registry to exactly one
  canonical ledger id; unresolvable facts are dropped (fail-closed). `d_n`,
  colocation cap, and the 5 % cap bind per registered identity.
- **I-MTP-2** Score multipliers derive from service-observed data only; no
  participant-supplied boolean reaches the scorer.
- **I-MTP-3** One epoch = one fresh fact-store build; re-running the cron is
  byte-idempotent.
- **I-MTP-4** Registration nonces: 32 B server random, pair-bound, 15-min TTL,
  single-use.
- **I-MTP-5** C2 facts exist only via terminal triage labels whose applying actor
  is timeline-verified against a pinned maintainer allowlist; public disclosure
  of any security-classified bug (S0–S3) → recorded rejection fact.
- **I-MTP-6** C3/C4 `base_points` are table-resolved and capped at ingestion —
  per event AND per identity per epoch; calendared-window events only.
- **I-MTP-7** Uptime = handshake ∧ sink-freshness ≤ 300 s ∧ **sync probe passed**
  (peer serves a crawler-chosen recent block verified against the crawler's own
  node), dual-vantage, ~10-min cadence.
- **I-MTP-8** Chain facts originate from the service's own node/indexer only.
- **I-MTP-9** Rules changes bump `version`, produce a new `rules_hash`, and are
  never applied retroactively; every published ledger stays verifiable forever
  against its pinned hash.
- **I-MTP-10** Ledger publication is append-only; corrections supersede, never
  replace; the query API is a verbatim mirror of signed files.
- **I-MTP-11** Node uptime attributes only through the registration claim-token
  observed in the peer's user-agent; token-less or unknown-token nodes are
  dropped (fail-closed).
- **I-MTP-12** Colocation buckets are derived from vantage-observed addresses
  (union across vantages, /24 v4 · /48 v6) plus mandatory ASN attribution from an
  epoch-hash-pinned snapshot; no participant-supplied network metadata.
- **I-MTP-13** A published epoch becomes immutable at the next monthly cumulative
  snapshot; later corrections are forward adjustment facts in a current epoch,
  never rewrites of the past.

## 5. Mandatory tests (announcement gate)

Announcement MUST NOT happen until all are green:

1. **Attribution round-trip** — one registration with a claim-token + address +
   handle; facts arriving via all four collectors land under the single `gh:` id;
   the same facts with no registration score zero (I-MTP-1, I-MTP-11).
2. **Sybil E2E** — 4 nodes / one registration across two /24s → `d_n` + colocation
   caps produce the exact expected mpts (extends the existing collectors tests to
   the service ingestion path); plus per-vantage divergence (different /24 shown
   to DE vs JP → node counts in both buckets) and an IPv6-only node landing in
   its ASN bucket, not the keyless bucket (I-MTP-12).
3. **Multiplier derivation** — a node self-reporting `geo_diverse=true` from a DE
   IP scores ×1.0, not ×1.5 (I-MTP-2).
4. **Sync-probe forgery** — a stub peer advertising a fresh sink timestamp but
   unable to serve the crawler-chosen recent block scores **zero** uptime; a node
   advertising an unknown claim-token, or none, yields no attributable sample
   (I-MTP-7, I-MTP-11).
5. **Idempotent epoch** — cron run twice → byte-identical ledger; facts from epoch
   N−1 never appear in N (I-MTP-3).
6. **Nonce + signature lifecycle** — replayed, expired, and cross-pair nonces all
   reject (I-MTP-4); registration signature under the claim context rejects
   (in-core test re-asserted at the service boundary); **`verify_claim`
   round-trip + tamper test added to `misaka-mtp`** (closing its current zero
   coverage); ledger-context signatures cross-verified against register/claim
   contexts (extending the tested matrix, D7).
7. **Label-actor gate** — a scoring label applied by a non-allowlisted actor
   yields no C2 fact (I-MTP-5).
8. **Wash-tx saturation** — a self-tx flood inside one load window yields exactly
   the per-event cap, and across an epoch never exceeds the per-identity
   aggregate cap (I-MTP-6).
9. **Supersede flow** — reissue epoch N: both issues verify independently;
   `verify-epoch` and `GET /mtp/v1/points/<id>` reflect the latest and flag the
   old; a supersede attempted past the finality horizon is rejected (D6,
   I-MTP-10, I-MTP-13).
10. **Self-verification** — `misaka mtp verify-epoch` on a published file:
    signature + rules-hash + full recompute byte-compare pass; then flip one
    milli-point and confirm it fails.
11. **Query-surface honesty** — fuzz the API against the ledger archive: every
    number served is byte-traceable to a signed file (I-MTP-10).

## 6. Consequences & open items

**Positive.**
- Participants get a lookup they don't have to trust: the HTTP/dashboard/CLI views
  are conveniences over ML-DSA-87-signed, hash-pinned, recomputable artifacts, and
  `misaka mtp verify-epoch` makes "check my points" a one-command cryptographic
  operation (R-b).
- Fraud has to beat five independent layers. C1 — the biggest slice — now
  requires *proven* possession of recent chain data (sync probe) on a node the
  registrant *configured* (claim-token), from IP/AS-diverse infrastructure
  (colocation cap), which is exactly the real cost the network imposes at 25–50
  BPS. What the layers can't prevent is publicly attributable and disputable:
  every point links evidence anyone can challenge in the appeal window (R-c).
- Testnet-only is structural: prefix-checked registration, network-bound signed
  digests, network-suffixed evidence (R-a).
- Zero consensus change; the deterministic core stays frozen — this ADR only adds
  the I/O ring around it.

**Honest boundary.**
- **Fact collection is single-operator-trusted.** Signed ledgers prove the *scoring*
  is honest given the facts; they cannot prove the operator didn't omit or shade
  facts. Mitigations are transparency (evidence links, dual vantages, appeals),
  not decentralization. Posture is analogous to design-§8 R4 (solo triage) / R5
  (ledger tampering), but fact-*omission* is a residual those two rows don't
  enumerate — recorded here as new.
- **The 5 % cap binds per-id, pre-redistribution — and is exceedable by design.**
  ADR-0027 D6's "redistribute once" rule sends a capped id's excess to uncapped
  ids of the same category, who may end above the cap (`mtp/src/settle.rs`'s own
  test lands a recipient at 35 % of a small pool). On a thin category, a whale
  can engineer a sacrificial capped id plus uncapped ids and recapture its own
  excess — i.e. the cap bounds *identities*, not *humans*, and large earners are
  economically nudged toward Sybil. This is frozen scheme behavior this ADR may
  not change; O-SV-5 routes a post-redistribution clip into the ADR-0027 O3
  (cap/vesting) pre-publication calibration.
- **1-person-1-ID remains self-declared** (design §5, frozen by ADR-0027).
  I-MTP-1/11 stop *namespace* splitting and *node-claim* theft, the /24-ASN cap
  plus the sync-probe cost damp *hardware* splitting, but a determined human with
  distinct GitHub accounts, keys, IPs, and machines is caught only by the G1
  advisory clustering signals + forfeiture-on-discovery, not prevention. This is
  the accepted design point (no KYC on testnet).
- **Node binding is possession-of-config, not cryptography** (I-MTP-11): the
  claim-token proves the registrant can edit the node's config, which is the
  right direction against claim-theft, but a signed in-handshake challenge
  (O-SV-4) would be strictly stronger.
- **GitHub is a trusted dependency** for C2 identity, label timelines, and
  maintainer-allowlist enforcement.
- Announcement is still hard-gated on the ADR-0027 legal review (O4) — the
  published handle↔address linkage (D3) is an explicit input to it; O5/O7
  (coefficient retuning, heartbeat) stay open for Stage-A data as planned.

**Open (carried, service-scoped):**
- **O-SV-1** vantage count: 2 (DE/JP) at launch; a third (US) if Stage-B geo data
  shows blind spots.
- **O-SV-2** registered-infrastructure exemption slots for the /24-ASN cap
  (design §5 allows them): manual allowlist in v1; criteria to be published before
  first use.
- **O-SV-3** whether `points/` lives in the public misakas repo or a dedicated
  `misaka-points` repo (affects appeal-issue routing only).
- **O-SV-4** cryptographic node proof-of-possession (signed challenge in the P2P
  handshake) — requires a protocol change; claim-token binding (I-MTP-11) is the
  v1 stand-in.
- **O-SV-5** post-redistribution cap clip — a one-line settle change, but it
  edits frozen ADR-0027 D6 semantics; decide inside O3 before publication.
