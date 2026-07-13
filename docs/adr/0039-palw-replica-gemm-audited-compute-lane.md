# ADR-0039 — PALW Replica-GEMM Lane: k=2 audited-compute PoW as a second block lane over a permanent hash floor

> **Reference tree:** `feat/mil-v0`. This ADR is the **decision record**; the buildable
> specification — every wire struct, frozen hash order, domain string, and exact parameter —
> lives in [`docs/design/misaka-palw-replica-gemm-v0.2.md`](../design/misaka-palw-replica-gemm-v0.2.md)
> (design v0.2, 35 sections). Code claims about the *current* tree below are grounded in
> `consensus/core/src/{pow_layer0.rs, header.rs, hashing/header.rs, subnets.rs, coinbase.rs,
> config/{bps.rs,params.rs}}`, `consensus/src/{model/stores/ghostdag.rs, processes/ghostdag/protocol.rs}`,
> and `consensus/core/src/dns_finality.rs`.

- **Status:** Proposed (design + this ADR only — **nothing here is implemented**). Testnet-only,
  **hard-fork / re-genesis** onto a *new* network ID and genesis; the live 40-BPS testnet
  (ADR-0030) is not touched. At activation the compute lane runs at **DAG weight 0**; raising it
  follows an activation ladder (§3, Phase 8) gated on the stop conditions in §6. No mainnet path
  until every §6 stop condition holds.
- **Date:** 2026-07-13
- **Consensus classification:** *MISAKA Double Nakamoto Security — Proof of Audited Compute over a
  Permanent Hash-Work Floor.*
- **Extends:** [ADR-0007](0007-layered-pow.md) (layered PoW — the `algo_id=3` BLAKE2b-512∥SHA3-512 path,
  `POW_ALGO_ID_BLAKE2B_SHA3=3`, is kept **unchanged** as the permanent 8-BPS floor; PALW adds
  `algo_id=4` *above* it, it does not supersede). [ADR-0018](0018-quality-gated-stakescore-inclusion-economics.md)
  + [ADR-0013](0013-validator-reward-distribution.md) (coinbase / validator reward — PALW adds a
  provider-pair reward class to `BlockRewardData`; the worker/inclusion/validator shares and the
  validator fan-out are unchanged).
- **Consumes:** [ADR-0022](0022-pruned-ibd-evm-overlay-snapshot.md) (`overlay_commitment_root` +
  pruned-IBD — PALW's DA and historic-reproducibility invariants ride the same mechanism) and
  [ADR-0031](0031-dns-dormancy-revival-reconstructability.md) (`OverlaySnapshot` append-only
  reconstructability discipline — PALW appends its active-ticket/beacon/certificate frontier to the
  same snapshot).
- **Relates / departs from:** [ADR-0024](0024-mil-gpu-attestation-computedepth.md) — **same goal**
  (make real GPU compute a consensus work source) but a **different mechanism**. ADR-0024's
  consensus overlay was `Proposed`/unimplemented and rooted compute credit in GPU **TEE
  attestation**; PALW's invariant **I-7 (TEE non-authority)** deliberately demotes TEE out of the
  validity root and replaces it with *k=2 replica-exact GEMM + PQ DNS certificate + bonds + a
  hash-floor-capped compute-work term*. Where ADR-0024 and this ADR disagree on the TEE trust
  posture, **this ADR governs the PALW lane.** [ADR-0026](0026-bps-acceleration-ibd-fast-sync.md) /
  [ADR-0030](0030-bps-stage-b-testnet-40-activation.md) (the BPS-envelope precedent — PALW launches on
  its OWN **10-BPS** genesis (`testnet-palw-10`), split **2 + 8** across two lanes, a PoW departure
  requiring a *new genesis / network*; the 40-BPS 8 + 32 split is retained as the later Stage-B
  `testnet-palw-40`). [ADR-0017](0017-all-active-staker-attestation.md) (which superseded ADR-0012's
  commit-reveal sortition — because that randomness beacon is retired, PALW must add **its own** PQ
  commit-reveal beacon rather than assume an existing one).
- **Scope rule:** this ADR **freezes the decisions and the boundary**; it does not restate the full
  wire format. Where a struct or number is load-bearing it is quoted verbatim and cross-referenced
  to the design section. Every parameter in §26 of the design is a **testnet start value, changeable
  only by a dedicated hard fork after benchmarking** — never a validator-tunable governance knob.

---

## 1. Context

Today the chain is single-lane Nakamoto PoW. `required_algo_id(bool) -> u8`
(`pow_layer0.rs:136`) returns `3` when active (BLAKE2b-512∥SHA3-512, ADR-0007 Phase 3) else `1`;
`check_algo_id` rejects any non-required id; `check_algo_id_known` accepts `{1,2,3}` for pruning
only. GHOSTDAG accumulates a **single** `blue_work: BlueWorkType` (`Uint192`,
`model/stores/ghostdag.rs:24`), summed via `calc_work(bits)` over blues
(`processes/ghostdag/protocol.rs:159`). Coinbase routes 70% to the worker (base 62% + inclusion 8%)
and 30% to validators (`params.rs`, `subsidy_validator_bps=3000`; split in `dns_finality.rs`
`split_block_reward`). There is **no** `algo_id=4`, no `WorkLane`, no randomness beacon, and no
component-work concept anywhere in the tree (grep-confirmed).

The MIL programme (ADR-0024) wants **real GPU inference to count as consensus work** — but three
constraints make the naive "put an LLM in the PoW" idea unimplementable:

1. **No re-execution on the block path.** A validator cannot re-run a multi-billion-parameter model
   (the 4B / 9B tiers of D8) inside a **~100 ms** block-acceptance budget (10-BPS PALW genesis; the
   40-BPS Stage-B profile would tighten this to ~25 ms, another reason to soak at 10 BPS first). TopLoc-style
   verification is cheaper than generation (teacher-forced prefill vs sequential decode) but still
   ~one full model forward — far too heavy for every block.
2. **PQ trust root.** Consensus roots are SHA3 / BLAKE2b / ML-DSA / ML-KEM. NVIDIA/TDX/SNP
   attestation chains are ECDSA/RSA and depend on live vendor infrastructure (RIM/OCSP/NRAS);
   rooting block validity in them both breaks the PQ posture and creates a vendor single point of
   failure. ADR-0024's attestation-as-root cannot be the consensus root.
3. **Privacy.** Real prompts, outputs, and hidden states must not go on-chain, and the
   requester↔provider mapping must not be recoverable from the public chain.

PALW resolves all three by **doing the compute first and off the block path**, replicating it,
auditing it asynchronously, bonding it, and certifying it with a PQ DNS quorum — so the DAG only
ever *verifies the one-time use of an already-certified ticket*, at hash-level cost.

---

## 2. Decision

### D1 — Two PoW lanes over a permanent hash floor
Do **not** retire `algo_id=3`. Keep it as a permanent hash-security/liveness **floor** and add
`POW_ALGO_ID_PALW_REPLICA = 4`. `required_algo_id` is replaced by a mixed-lane policy
(`WorkLane::{HashFloor, ReplicaPalw}`, `check_live_algo_id(algo_id, palw_active)`);
`check_algo_id_known` is extended to accept `4` for pruning. Rates (testnet start, design §5.2, **10-BPS
PALW genesis decided 2026-07-14**): **total 10 BPS / 100 ms**, hash lane **2 BPS** (500 ms target),
replica lane **8 BPS** (125 ms target), `GHOSTDAG K≈124`, max parents 16, mergeset limit 248 — on a
**new network ID + genesis + store-format version** (`testnet-palw-10`), so the live testnet-40 is left
untouched. The **2 : 8** split is exactly the cap ratio of D4 (compute ≤ 4× hash), so the hash floor is
a permanent **20 %** of block rate (2 / 10). The 40-BPS split (8 + 32, K=447, mergeset 512) is retained
as the later `testnet-palw-40` **Stage-B** stressnet profile, promoted only after the 10-BPS soak +
weight-ladder gates. *Rationale: a permanent hash floor turns a total compute-lane failure into a
still-live, still-hash-secured chain; launching PALW at 10 BPS gives the new hot-path (component work,
nullifier dedup, lane DAA, overlay lookups, ML-DSA authorization) real validation-time headroom
(100 ms vs 25 ms) and gentler GHOSTDAG pressure for its first production run. PALW's LLM throughput is
asynchronous (GPUs fill a ticket inventory; blocks only draw from it), so 10 BPS does not throttle
inference — only the per-block reward/work granularity.*

### D2 — k=2 replica-exact minting (replication in place of a proof at the leaf)
The same anonymous micro-batch, same fixed shape, same deterministic runtime is delivered to **two**
distinct bonded providers; a **Candidate Leaf** is minted only if both agree **exactly** on all
eight fields: `job_set_commitment`, `model_profile_id`, `runtime_class_id`, `shape_id`,
`output_commitment`, `canonical_gemm_trace_root`, `operation_schedule_commitment`, `quantum_count`.
The match is bound to the *primary GPU GEMMs* via `canonical_gemm_trace_root` — not just equal
answers. **Honest scope (design §1.2):** `canonical_gemm_trace_root` is **not** a succinct proof; it
is an auditable execution commitment whose soundness comes from the *composition* k=2 + canary +
bond + DNS certificate. Two colluding providers that also identify the canary can forge — mitigated,
not eliminated (see I-8, D5, §6). *Rationale: two independent identical executions substitute for a
SNARK at the leaf, at zero on-chain verification cost.*

### D3 — Asynchronous certification; block acceptance stays hash-cheap
Pipeline: `k=2 inference → exact match → register all leaves on-chain → beacon-selected canary audit
→ PQ DNS batch certificate → ticket activation → one-shot eligibility hash → algo-4 block`. At block
acceptance validators **never re-run Qwen**; `verify_replica_palw_header` does only cached-state
lookups: certificate active, ticket-nullifier / proof-type / activation-window / target-interval /
`chain_commit` match, `bits == lane_daa.expected_bits`, `eligibility_512 <= target`,
`compute_headroom() > 0`. **Activation-gate targets (not claims):** cached header p99 **< 5 ms**,
full block incl. ML-DSA authorization p99 **< 20 ms**, 248-mergeset dedup p99 < 20 ms, IBD ≥ 50 % of
algo-3-only baseline (§5, §6).

### D4 — Separated GHOSTDAG work with a hard compute cap `E = H + min(C, 4·H)`
GHOSTDAG keeps hash work `H` and certified compute work `C` **separately**
(`GhostdagData` gains `blue_hash_work` + `blue_compute_work` alongside the existing `blue_work`).
Fork choice still consumes a single **effective** `blue_work = E = H + min(C, 4·H)`
(`compute_to_hash_cap = 4`; `finalize_score_and_component_work` caps `C` at `4·H` with
checked/saturating big-int math; `SortableBlock` uses only `E`, components are not tie-breakers).
Pre-v3 blocks migrate as `blue_hash_work = blue_work, blue_compute_work = 0`. *Rationale: even if the
entire PALW/DNS-certificate stack is forged, a single forgery amplifies an attacker's own hash work
by at most 5× total — bounded degradation, not immunity (§6, problem A).*

### D5 — All leaves on-chain **before** the beacon (no hidden-leaf grinding)
Root-only registration is **banned** (I-2). At registration, on-chain go: `PalwBatchManifestV1`
(fixed `leaf_count`/`chunk_count`), **all** `PalwPublicLeafV1` in 64-leaf `PalwLeafChunkV1` chunks,
every `leaf_hash`, per-leaf slashable bond, provider-pair bond references, one-time reward scripts,
and the receipt-DA commitment — over PALW subnetworks **`0x30`–`0x37`** (`PROVIDER_BOND 0x30`,
`BATCH_MANIFEST 0x31`, `LEAF_CHUNK 0x32`, `BATCH_CERT 0x33`, `SLASHING 0x34`, `BEACON_COMMIT 0x35`,
`BEACON_REVEAL 0x36`, `PROVIDER_UNBOND 0x37`; the `0x30` band is currently free). A batch missing any
chunk stays `Incomplete` and can never become block-eligible. Batch state machine:
`Missing → Registering → Committed → Auditing → {Certified | Slashed | Expired}`,
`Certified —≥1 epoch→ Active → {Expired | Revoked}`; revocation is **non-retroactive**
(`PalwRevocationV1.effective_daa_score` invalidates only future unused leaves). Per-leaf economics
must satisfy `expected_fraud_profit − expected_penalty < 0` with
`penalty = q_audit·slash + leaf_bond + credential_loss` (testnet: `q_canary=1%`, ≥1 canary/batch,
`slash ≥ 100×` one-leaf reward, credential suspension ≥ 1000 epochs, unbond delay =
`ticket_expiry + max_reorg_horizon + fraud_evidence_window`). *Rationale: fixing every leaf hash
before the beacon removes the "hide many leaves, open only the winner" attack (problem B).*

### D6 — Consensus-derived fork binding + first-class header nullifier
A miner must **not** choose `chain_commit`. It is derived from a **lagged DNS-finalized checkpoint**
fixed *before* the target slot:
`chain_commit(S) = H("misaka-palw-chain-commit-v1" || dns_finalized_checkpoint_hash_at_or_before(S − LOOKBACK) || dns_finality_certificate_hash || S || network_id)`,
`LOOKBACK` > DNS finality + deepest shallow reorg. Each leaf is bound to **one** `target_daa_interval`
(`slot_digest = H("…slot-v1" || eligibility_beacon || batch_id || leaf_index || leaf_hash)`; testnet
window 60 s = 600 intervals @ 10 BPS) and gets **one draw**:
`eligibility_hash = H("…eligibility-v1" || network_id || eligibility_beacon || chain_commit(interval) || target_daa_interval || batch_id || leaf_index || leaf_hash || ticket_nullifier)`,
accepted iff `Uint512(eligibility_hash) ≤ target_512(bits) ∧ daa_score == target_daa_interval ∧
nonce == low64(ticket_nullifier)`. The **`ticket_nullifier` is a first-class Header v3 field**
(I-5), so double-use is deterministically detectable from the header DAG alone. Cross-fork reuse of a
ticket for a *different* header requires the one-time ticket-authority's **ML-DSA** signature
(`PalwBlockAuthorizationV1`, signed over a domain-separated header preimage with
`palw_authorization_hash = 0` to break the circular reference); a second signature over a different
header commitment is **cross-fork slashing evidence**. *Rationale: shallow forks after the checkpoint
draw the same ticket (no re-roll), and the nonce is pinned to the nullifier so it cannot be ground
(problem C).*

### D7 — A new PQ DNS PALW beacon (not a reused existing randomness source)
There is no reusable randomness beacon in-tree (confirmed: `dns_finality.rs` has epochs + PQ
validator signatures but no commit-reveal; ADR-0012's sortition was retired by ADR-0017). PALW adds
a **PQ-signed commit-reveal** beacon (`PalwBeaconCommitV1`/`PalwBeaconRevealV1`, ML-DSA, schedule
`E−2` commit / `E−1` reveal / `E` active;
`R_E = H("misaka-palw-beacon-v1" || R_{E−1} || dns_finalized_anchor(E−1) || sorted(valid_reveals) || sorted(missing_commitments) || E)`;
missing reveals slashed). Last-revealer bias is acknowledged and suppressed economically; a
`beacon_version` is reserved for a later swap to PQ-threshold randomness. **Degraded mode:** below
DNS-quality threshold, existing Active tickets use the prior seed for a short grace, **no new batch
activates**, after grace **algo-4 stops**, and **algo-3 continues** (I-6; the fallback seed's
compute-work multiplier is reduced toward 0). *Rationale: the design must not assume finality-as-
randomness; degradation must be safe, not a stall.*

### D8 — Two deterministic runtime tiers, to widen the participation base
Exact match is only meaningful against a pinned runtime. To broaden who can provide — from datacenter
GPUs down to VPS-class and node-co-located hardware — the algo-4 Replica lane carries **two runtime
tiers** (two on-chain profiles, each its own `model_profile_id` / `runtime_class_id` / shape table /
reference benchmark), *not* two PoW lanes:

| tier | project profile | model | quant | RAM | target participants |
|---|---|---|---|---|---|
| **PALW Standard** | `MISAKA-QW4-PALW-v1` | Qwen3.5-4B | Q4 | ≥ 8 GB | VPS / node co-location / broad base |
| **PALW Quality** | `MISAKA-QW9-PALW-v1` | Qwen3.5-9B | Q4 | ≥ 16 GB | standard useful inference |

Each tier pins: exact weights manifest, tokenizer, quantization, runtime image, kernel graph,
operation table, GPU-arch **class** (so a CPU/GPU/SKU difference is a *distinct* `runtime_class_id`),
tensor/pipeline topology, fixed shape table, greedy sampling, deterministic reduction, batch-invariant
execution (speculative decoding **forbidden** → startup failure). Consensus pins each tier's **exact
manifest hash**, not a model name (`Qwen3.5-4B` / `Qwen3.5-9B` are the source artifacts;
`MISAKA-QW4/QW9-PALW-v1` are the fixed project forks); `PalwParams.supported_profiles` lists both.
By **I-9** exact-match weight is granted **only within one tier** — a Standard leaf pairs with a
Standard leaf, a Quality leaf with a Quality leaf, never cross-tier — and each tier's per-leaf
compute quantum comes from its **own** reference benchmark (§21.2), so a broad Standard (4B) fleet is
credited *less* compute work per leaf than a Quality (9B) fleet, rather than being paid
large-model-equivalent work for cheap small-model leaves.
Q4 quantization tightens the determinism bar (quantized-kernel numerics vary more across hardware
than fp16), so batch-invariance/pinned-kernel-graph tests (§27.1) run **per tier and per arch class**.
Adding/changing either profile needs an on-chain manifest + reference-benchmark report hash +
activation DAA score. *Rationale: two small pinned tiers open the provider set to VPS-class hardware
while keeping exact-match soundness intra-tier and paying compute work proportional to each tier's
real cost.*

### D9 — Header v3 (`PALW_HEADER_VERSION = 3`), append-only and version-gated
Append to `Header`: `blue_hash_work`, `blue_compute_work` (`BlueWorkType`), `palw_batch_id`,
`palw_leaf_index (u32)`, `palw_ticket_nullifier`, `palw_epoch_certificate_hash`, `palw_chain_commit`,
`palw_target_daa_interval (u64)`, `palw_authorization_hash`, `palw_proof_type (u8)`. The preimage
appends these **after** the existing `overlay_commitment_root`, version-gated `>= 3`, in the frozen
order (`blue_hash_work, blue_compute_work, palw_batch_id, palw_leaf_index(LE), palw_ticket_nullifier,
palw_epoch_certificate_hash, palw_chain_commit, palw_target_daa_interval(LE), palw_authorization_hash,
palw_proof_type`). Pre-v3 headers do **not** feed the new fields into the preimage and must decode to
zero. `check_palw_header_shape` enforces: on the hash lane all PALW fields zero **and**
`blue_compute_work ≤ 4·blue_hash_work`; on the replica lane `version ≥ 3`, `batch_id ≠ 0`,
`ticket_nullifier ≠ 0`, `proof_type == ReplicaExactV1`, `nonce == low64(ticket_nullifier)`.
> **Implementation caveat (grounding):** the current *struct* field order has `blue_work` before
> `blue_score`, but the *hashed preimage* order (`hashing/header.rs`) is `blue_score` then
> `blue_work`. The append point is the **preimage** position after `overlay_commitment_root`; cite
> the preimage order, not the struct order, when wiring the v3 append.

### D10 — Coinbase: lane-asymmetric split, provider-pair base, red/duplicate unissued
The two lanes use **different** coinbase splits (amended 2026-07-13). The algo-3 **hash lane** keeps
**62 / 8 / 30** (worker-base / inclusion / validator). The algo-4 **PALW lane** halves the validator
share and routes the freed 15 % to the LLM compute source, giving **77 / 8 / 15**
(`PALW_PROVIDER_BASE_BPS = 7700`, `PALW_INCLUSION_BPS = 800`, `PALW_VALIDATOR_BPS = 1500`). For an
algo-4 **unique blue** source the base 77 % splits as **provider A 38.5 % / provider B 38.5 %**
(`provider_pool = subsidy·7700/10000`, `a = pool/2`, `b = pool−a`, A/B by canonical bond-outpoint
order, paid to one-time reward scripts); inclusion 8 % to the assembler; validator 15 %. A
`WorkRewardClass::{HashMiner, ReplicaPalw{…}}` is added to `BlockRewardData` and derived identically
in construction and validation, and selects the lane's split. **Red / duplicate PALW sources get
provider subsidy 0, and the unminted base is NOT redistributed to the current miner** — it is unissued
(testnet v0.2) or sent to security reserve. *Rationale: redistributing duplicate rewards to the
includer would pay people to mass-produce duplicate blocks — a reward design running in reverse.*
**Security trade (accepted, intentional):** halving the PALW-lane validator subsidy lowers the
DNS-finality (2-D reorg defense) budget. At the frozen 8 : 32 BPS split the effective validator
subsidy across all blocks is ≈ `0.2·30 % + 0.8·15 % = 18 %` (down from 30 %). This is a deliberate
tilt toward GPU-compute incentive on the PALW network only; the hash lane's 30 % is untouched, and the
knob is a network-param (hard-fork / re-genesis) not a live change.

### D11 — TEE non-authority (I-7)
Replica-lane validity contains **no** NVIDIA/TDX/SNP attestation. `PalwProofType` reserves
`{ReplicaExactV1=1, TeeRateLimitedV1=2, TransparentArgumentV1=3, WitnessHidingArgumentV1=4}`; TEE may
later serve only as a rate-limiter / private-audit accelerator / low-weight auxiliary — never a
full-weight leaf, never a bypass of the hash floor / bonds / public leaves / DNS certificate. On
vendor-PKI outage or compromise, only TEE features stop; Replica and hash lanes continue. *This is
the explicit departure from ADR-0024.*

### D12 — Data availability & pruning (I-6, I-12)
Manifest + all leaf chunks + certificate are on-chain PALW-subnetwork txs; the receipt body is an
erasure-coded PALW DA object whose root is on the leaf (auditors must have fetched it before
certifying; no DA → no certificate). Historic validity rides a `PalwEpochProofBundleV1` in the
pruning proof (beacon chain, manifests, leaf chunks, certificates, revocations, nullifier frontier
root — the verifier recomputes existence, quorum, activation/expiry, interval, chain-commit,
eligibility, component work, and nullifier dedup). `OverlaySnapshot` gains a **minimal** PALW
frontier (`palw_provider_bonds`, `palw_active_batches`, `palw_beacon_states`,
`palw_active_nullifiers`, `palw_lane_daa_state`) with a specified canonical sort — **not** all
historic leaves. A gossip cache is a speed-up, never a validity premise; a header whose dependency
state is not yet fetched is quarantined/orphaned, but a lead-window or hash-mismatch violation is
terminal-invalid.

### D13 — Privacy model under k=2
The old "only the single computing party ever knows the content" requirement is **incompatible with
k=2 and is corrected**: only the **requester and the two DNS-assigned providers** know the
question/answer; the public chain, validators, block assembler, and other providers do not. Provider
selection is beacon-derived (`H(seed || job_capability || {0,1}) mod active_provider_count`), then
rejection-sampled for distinct bond outpoint / operator group / matching runtime class / capacity /
region diversity / distinct relay session (I-8). Transport uses ML-KEM ephemeral channels, per-job
ML-DSA keys, fixed-size padded cells, ingress/egress relay separation, and salted prompt/output
commitments. **Unlinkability scope is honest:** it hides requester↔job from the chain and from a
*single* provider; it does **not** resist collusion of the whole dispatcher set or a global passive
eavesdropper — those need ≥1 non-colluding relay and are operational requirements + a testnet
benchmark, not cryptographic guarantees.

---

## 3. Implementation plan

**Phased, weight-0-first (design §28).** Phase 0 — this ADR + network fence: new 40-BPS (8 + 32)
testnet ID/genesis, Header v3 + store version reserved, algo-3 codified permanent. Phase 1 — off-chain
deterministic k=2 prototype (the two tiers `MISAKA-QW4-PALW-v1` / `MISAKA-QW9-PALW-v1`, one fixed
shape each, `VerifiableInferenceBackend`, exact output/trace match, pair receipts, per-tier
batch-invariance tests, **DAG weight 0**). Phase 2 — PALW
overlay + public leaves (`0x30`–`0x37`, bonds, manifest/chunks, state machine, **no** work credit).
Phase 3 — DNS PALW beacon + canary (commit/reveal, auditor selection, large secret canary corpus,
certificate, slashing/revocation, degraded mode). Phase 4 — Header v3 + algo-4 validation at
**ΔC = 0** (fields/P2P/RPC/store, eligibility, authorization, latency measurement). Phase 5 —
component GHOSTDAG work (`blue_hash_work`/`blue_compute_work`, nullifier window, deterministic dedup,
`min(C,4H)` cap, lane DAA, pruning-proof bundle; **first credit factor low, e.g. 1/16 of theoretical
ΔC**, raised only via later testnet hard forks). Phase 6 — coinbase pair split + red/duplicate rule.
Phase 7 — adversarial testnet (TEE fully off, DNS degraded, ≥30–50 % malicious providers,
hidden-leaf flood, private-fork/ticket reuse, DA withholding, LCU gaming, traffic analysis).

**Phase 8 — activation ladder:** Stage A compute weight **0 %** → B **25 %** → C **50 %** → D
**80 % max**, each with its own activation fence and metrics gate; **mainnet must not jump to 80 %.**

**Minimum first vertical slice (§33):** `mil/core` structs + hash test vectors → `mil/provider` mock
k=2 backend + exact matcher → `consensus/core` PALW payload structs / subnet IDs / params → stores +
state machine (weight 0) → DNS beacon + canary → Header v3 + P2P/RPC roundtrip + weight-0 verifier →
lane DAA + component work → coinbase pair split → pruning/IBD bundle → Qwen GPU adapter last.
**Freeze the wire format and test vectors before the first GPU PR.**

Exact per-file change lists (`consensus-core`, `consensus` engine incl. new
`processes/palw/{mod,validation,beacon,audit,work}.rs` + `model/stores/palw.rs`, protocol/RPC/mining,
MIL) and the full Rust skeletons (`ReplicaExecutionReceiptV1`, `ReplicaMatchRecordV1`,
`PalwProviderBondPayloadV1`, `PalwAuditorVoteV1`, `PalwParams`, 33 new `RuleError` variants) are in
design §23–§25.

---

## 4. New invariants (verbatim from design §4 — must hold in code and tests)

- **I-1 Hash floor:** `blue_compute_work ≤ 4·blue_hash_work` after effective-work computation; over-cap
  blocks are invalid, and with 0 credit headroom no algo-4 template is produced.
- **I-2 No hidden leaves:** `leaf_count` and every `leaf_hash[i]` are on-chain *before* the
  eligibility/audit beacon; root-only registration is forbidden.
- **I-3 One leaf, one draw:** a leaf is assigned to exactly one `target_daa_interval`; the nonce is
  fixed and a different nonce is rejected (no re-draw).
- **I-4 Consensus-derived chain binding:** `chain_commit` is derived by all nodes from a fixed
  DNS-finalized lagged checkpoint, never miner-chosen.
- **I-5 First-class nullifier:** `ticket_nullifier` lives in Header v3 — in the header hash, P2P,
  stores, and pruning proof — not a sidecar.
- **I-6 No out-of-band validity dependency:** manifest, all leaf chunks, certificate, and beacon
  state are obtainable on-chain or via the pruning-proof bundle; gossip cache is speed only.
- **I-7 TEE non-authority:** vendor attestation alone never issues an Active ticket, and no later TEE
  lane may bypass the hash floor / bonds / public leaves / DNS certificate.
- **I-8 Replica independence:** providers A and B have distinct bond outpoints, operator groups, and
  active session keys.
- **I-9 Deterministic class:** exact-match weight only within one `runtime_class_id`; cross-arch-class
  comparison is audit-only, never direct main-DAG work.
- **I-10 Real-job privacy:** real prompts/outputs/activation sketches are never publicly audited; full
  opening is canary-only.
- **I-11 Double-use slashability:** one authority signing the same nullifier over different headers is
  cross-fork slashing evidence; bond unlock is after ticket expiry and the max reorg/evidence window.
- **I-12 Historic reproducibility:** IBD and pruning verifiers recompute component work from the
  then-current profile, shape table, lane DAA, beacon, certificate, and nullifier rules.

---

## 5. Mandatory tests / acceptance gate

The design's §27 test matrix is the acceptance suite: **27.1** deterministic runtime (token-ID match
across ordering/batch-size/SKU/restart/TP-reorder; speculative decoding → startup fail; runtime/kernel
mismatch → receipt reject); **27.2** hidden-leaf (256-declared/255-posted, root-includes-unpublished,
post-beacon leaf-count change, duplicate index, cross-batch nullifier reuse — all rejected before
Active); **27.3** pair/collusion (same-bond, same-operator, one-sided receipt, output-only match,
trace-only match, dispatcher double-send); **27.4** beacon; **27.5** fork/nullifier (sibling reuse,
private-fork reuse, double authority sign, selected-parent-past reuse, duplicate red-coloring
preserving blue-anticone size); **27.6** work-cap property tests (`C_eff ≤ 4H`, `E = H + C_eff`,
`H ≤ E ≤ 5H`, monotonic for valid credited blocks, headroom==0 ⇒ algo-4 invalid, big-int/compact-
target fuzz); **27.7** lane DAA; **27.8** coinbase (`62/8/30` vs `31/31/8/30`, remainder, red/duplicate
zero, pruning-invariant); **27.9** DA withholding; **27.10** privacy correlation; **27.11** perf.

**40-BPS acceptance gate (§27.11):** cached PALW header p99 **< 5 ms**, full PALW block p99
**< 20 ms**, 248-mergeset dedup p99 < 20 ms, no unbounded allocation from remote payload, IBD ≥ 50 %
of algo-3-only baseline, 24 h stress with non-growing virtual-processor backlog. **Note — the budget
is tighter at 40 BPS:** the < 20 ms full-block target is now ~80 % of the 25 ms average interval (it
was 20 % of 100 ms in the 10-BPS draft), which makes the cached fast-path (D3) and this gate strictly
more binding — treat it as a hard activation gate, not a stretch goal. Bandwidth must be *measured*
on testnet (design §26.1: leaf_rate ≈ G/(k·q); the two small tiers have a **smaller per-tier q** than
a large model, so the same fleet mints *more* leaves/s and needs more descriptor bandwidth —
re-measure per tier). If over budget, raise per-tier `q`, enlarge batches, aggregate the ML-DSA-87 votes (4627 B
each) into an epoch certificate, or raise registration fees / shape quota — **never** revert to
root-only registration (that re-opens I-2).

---

## 6. Consequences & open items

**What this buys.** Real GPU inference becomes a bonded, replicated, audited, PQ-certified work
source whose *use* is verified at hash cost, while a total compute-lane failure degrades to a still-
live 8-BPS hash chain with at most 5× work amplification. Privacy holds against the chain and any
single provider.

**Residual risks (explicitly not eliminated).**
- **Bounded, not immune (problem A):** a *full* break of the PALW proof + DNS certificate lets an
  attacker amplify their own hash work up to **5×** (`E ≤ 5H`). The cap converts catastrophic
  unlimited mint into bounded amplification — it is not a security proof.
- **k=2 collusion:** two colluding providers that also identify the canary can forge a leaf;
  mitigated by random assignment, bond, canary, batch audit, and the hash floor — statistical/
  economic, **not** SNARK soundness.
- **Beacon bias:** commit-reveal has last-revealer bias (suppressed economically; `beacon_version`
  reserved for PQ-threshold randomness).
- **Metadata privacy** depends on ≥1 non-colluding relay/dispatcher; no global-eavesdropper
  resistance without ZK.
- **Nothing-at-stake surface:** compute tickets are accumulable work inventory (unlike hash PoW),
  handled by fork binding + authorization + slashing + short expiry.

**Whitepaper/DNS-paper corrections owed (design §31):** stop describing the chain as plain PoW —
fork-choice work is hash work composed with capped audited compute; DNS provides finality **and**
provider assignment, audit sampling, and ticket-activation randomness; re-evaluate λ / D_max / K for
both the 40-BPS total and the lane-halt 8-BPS (hash-floor-only) mode; the canonical name is *MISAKA Double Nakamoto Security
with Proof of Audited Compute and a Permanent Hash-Work Floor*; audit is probabilistic/economic, not
SNARK soundness.

**Stop conditions — do NOT raise algo-4 DAG weight above 0 until ALL hold (design §32):**
same-runtime-class non-attack exact output/trace **mismatch rate over 100k work units under spec**;
**≥30 % malicious-provider simulation yields negative fraud expected value**; hidden-leaf /
fork-reuse / DA-withholding tests pass; cached full validation p99 does not pressure the 25 ms
block-interval budget; pruning proof reproducible without cache; safe fallback to algo-3-only on DNS-degraded;
provider-pair concentration under limit; canary identifiability within statistical tolerance;
requester↔provider linkability under operational target; coinbase issuance + red/duplicate + component
work agree in property tests; **the Replica lane works with TEE code fully disabled.**

**Open decisions deferred to implementation/benchmark:** all §26 parameters (start values,
hard-fork-only); the beacon upgrade to PQ-threshold randomness; whether the unminted red/duplicate
base is unissued vs. sent to security reserve on mainnet; the Phase-5 initial credit factor ramp.
