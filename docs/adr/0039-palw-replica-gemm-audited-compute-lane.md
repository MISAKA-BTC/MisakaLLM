# ADR-0039 — PALW Replica-GEMM Lane: k=2 audited-compute PoW as a second block lane over a permanent hash floor

> **Reference tree:** `feat/mil-v0`. This ADR is the **decision record**; the buildable
> specification — every wire struct, frozen hash order, domain string, and exact parameter —
> lives in [`docs/design/misaka-palw-replica-gemm-v0.2.md`](../design/misaka-palw-replica-gemm-v0.2.md)
> (design v0.2, 35 sections). Code claims about the *current* tree below are grounded in
> `consensus/core/src/{pow_layer0.rs, header.rs, hashing/header.rs, subnets.rs, coinbase.rs,
> config/{bps.rs,params.rs}}`, `consensus/src/{model/stores/ghostdag.rs, processes/ghostdag/protocol.rs}`,
> and `consensus/core/src/dns_finality.rs`.

- **Status:** Proposed. The **inert foundation is implemented** on `feat/mil-v0` — every PALW type,
  store, pipeline seam, and pure predicate is gated on `palw_activation_daa_score == u64::MAX` and is
  **byte-identical on every live net** (`test_genesis_hashes` + the GHOSTDAG/difficulty/sanity golden
  suites are unchanged across all PALW commits). No live net runs PALW; **activation is a separate
  hard-fork / re-genesis** onto a *new* network ID and genesis (`testnet-palw-10`); the live 40-BPS
  testnet (ADR-0030) is not touched. At activation the compute lane runs at **DAG weight 0**; raising
  it follows an activation ladder (§3, Phase 8) gated on the stop conditions in §6. No mainnet path
  until every §6 stop condition holds.
- **Date:** 2026-07-13 (design v0.2; **v0.2 design-review remediation R1–R4 + precisifications
  P1/P2 recorded 2026-07-16** — see the changelog note below).
- **v0.2 design-review remediation (2026-07-16).** An external review of the v0.2 skeleton confirmed
  the structure is sound and the zk-avoidance is quantitatively correct, and named the highest-value
  non-zk precisifications. Four are now implemented as **pure, inert** consensus-core changes and two
  are recorded as spec precisifications:
  - **R1 (I-13 winner secrecy)** — the leaf carries only `ticket_nullifier_commitment = H(nullifier)`;
    the raw nullifier is disclosed at the header and consensus binds them. Commit `3fb5e67`.
  - **R2 (I-14 DA possession binding)** — `PalwAuditorVoteV1::signing_hash` now covers the
    beacon-selected `audit_sample_root`, so an auditor cannot sign without possessing the sampled
    receipt chunks. Commit `34fe771`.
  - **R3 (c_saved bond floor)** — admission now enforces an aggregate `min_leaf_bond_sompi` floor; the
    forgery-EV inequality (D5) is corrected to dominate `R + c_saved`, not just `R`. Commit `34fe771`.
  - **R4 (mismatch attribution)** — D14: k=2 non-agreement is now attributable (beacon-drawn +
    repeat-offender escalation to a reference re-run, slash only the deviator). Commit `34fe771`.
  - **P1 (hash-floor guarantee is rule-, not resource-, independence)** — D1.
  - **P2 (numeric effective compute cap per activation stage)** — D4.
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

> **Precisification P1 — the floor guarantees rule-independence, not resource-independence.** "A total
> compute-lane failure leaves a still-live, still-hash-secured chain" is a statement about the
> *consensus rules*: algo-3 blocks remain valid and sufficient by rule with no dependency on any PALW
> state, so a break of the entire PALW/DNS/certificate stack cannot stall or invalidate the hash lane.
> It is **not** a claim that the two lanes draw on independent *physical* resources. Miners, operators,
> hardware, bandwidth, and DNS validators can overlap, so a compute-lane collapse may correlate with
> hash-lane stress (e.g. a shared operator withdrawing both). The floor bounds the *rule-level* blast
> radius (chain stays live and hash-secured; §6 problem A caps work amplification at 5×); operational
> resource-diversity is a separate, measured objective (I-8 replica independence, D13 relay diversity),
> not something the floor provides.

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

> **Precisification P2 — the effective cap is per activation stage; 5× is the structural ceiling, not
> the operative bound.** `compute_to_hash_cap = 4` is the *structural* ceiling `E ≤ 5H`, reached only
> at 100 % compute weight. The activation ladder (§3, Phase 8) applies a stage weight `w` to the
> credited compute so the **operative** cap is `E ≤ H + min(C, w·4H)`. The numeric bound the network
> actually runs under, per stage:
>
> | stage | weight `w` | operative compute cap | effective work bound |
> |---|---|---|---|
> | A | 0 % | `min(C, 0)` = 0 | `E = H` (no compute credit; algo-4 templates suppressed) |
> | B | 25 % | `min(C, 1·H)` | `E ≤ H + 0.25·4H = 2H` |
> | C | 50 % | `min(C, 2·H)` | `E ≤ H + 0.50·4H = 3H` |
> | D | 80 % (mainnet max) | `min(C, 3.2·H)` | `E ≤ H + 0.80·4H = 4.2H` |
> | — | 100 % (structural only) | `min(C, 4·H)` | `E ≤ 5H` (never scheduled) |
>
> So the §6 "problem A" 5× amplification is the ceiling of the *cap*, not of any stage the network is
> ever scheduled to run: the worst operative amplification is **4.2×** at Stage D, and **2×** at the
> first credited stage. `finalize_score_and_component_work` computes the structural `min(C, 4H)`; the
> stage weight `w` is a separate re-genesis/hard-fork parameter (never a live knob, §2 D1 scope rule).

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

> **Precisification/fix R3 — the profit term is `R + c_saved`, and the bond floor must cover
> `c_saved`.** A forger's gain from faking a leaf is not just the block reward `R`; it also **avoids
> the GPU-execution cost `c_saved`** it would have spent running the real inference. The honest
> inequality is therefore `q_audit·slash + leaf_bond + credential_loss > R + c_saved`. Because the
> canary catch probability makes `q_audit·slash ≈ R` (it offsets the *reward*, not the saved cost),
> the term that must actually cover `c_saved` is `leaf_bond + credential_loss`. Consensus now enforces
> the bond half directly: `PalwBatchAdmissionParams.min_leaf_bond_sompi` is a per-leaf floor, and
> `admission_valid`/`apply_manifest` reject any manifest whose `total_leaf_bond_sompi <
> leaf_count · min_leaf_bond_sompi` (aggregate at manifest time; the per-leaf split is checked where
> leaves are admitted). Inert value `0`.
>
> **Calibration note (re-genesis, off-protocol input to the floor).** `min_leaf_bond_sompi` is set
> **per tier** at re-genesis to that tier's *measured* `c_saved` — the amortized GPU-seconds ×
> reference $/GPU-hour to produce one leaf on `MISAKA-QW4-PALW-v1` vs `MISAKA-QW9-PALW-v1` (the 4B
> Standard tier's `c_saved` is smaller, so its floor is lower; §21.2 per-tier benchmark). The floor is
> gated behind the **testnet soak** (measure real per-leaf GPU cost under the pinned runtime before
> fixing the number) and chosen from a **4-variable EV sweep** over `(p_collude, q_canary, slash,
> leaf_bond)` such that `expected_fraud_profit < 0` across the plausible collusion range with margin.
> Setting the floor from list-price GPU cost without the soak is explicitly disallowed (real amortized
> cost under batch-invariant execution differs from spot rental).

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

### D14 — Mismatch attribution (anti-griefing under k=2)
Non-agreement between the two replicas of a leaf is, by itself, a **griefing vector**: a malicious
provider paired with an honest one can deliberately emit a wrong output so *neither* is credited,
burning the honest partner's real GPU work at no cost to itself. The v0.1 rule ("no match → no
credit") punishes the victim exactly as hard as the attacker. D14 makes non-agreement
**attributable**. A committed mismatch (`PalwMismatchRecordV1{batch_id, leaf_index, provider_a,
provider_b, output_a ≠ output_b}`) is escalated to a **reference-runtime re-run** when either (a) a
deterministic audit-beacon draw `H("misaka-palw-mismatch-escalate-v1" || audit_beacon_seed ||
batch_id || leaf_index) mod 1e6 < escalation_rate_ppm`, or (b) one of the two bonds is at/over
`repeat_offender_threshold` prior mismatches (the per-provider counter is an off-protocol tracker,
design §24.6). The re-run yields the reference output; the party whose committed output **deviates** from it
is slashed (`SlashA`/`SlashB`), or both if neither matches (`SlashBoth`). Since `output_a ≠ output_b`,
at most one can match the reference, so **the honest partner is never slashed** — the grief becomes a
strictly-losing move for the attacker. `PalwMismatchParams{escalation_rate_ppm, repeat_offender_
threshold}` is inert (`0, 0` → escalate nothing) and calibrated at re-genesis (same EV discipline as
R3: escalation rate high enough that deliberate mismatch has negative expected value given the slash).
The escalation draw, verdict, and slash-target set are **pure**; the re-run and the counter are
off-protocol inputs consensus only checks. *Rationale: k=2 replaces a proof with agreement, so
disagreement must have a defined, attacker-borne cost — otherwise "make my honest partner fail" is a
free denial-of-reward attack against honest providers.*

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
- **I-13 Winner secrecy (R1):** a public leaf carries only `ticket_nullifier_commitment =
  H("misaka-palw-ticket-nf-commit-v1" || ticket_nullifier)`; the raw `ticket_nullifier` is disclosed
  only at the header, and consensus checks `ticket_nullifier_commitment(header.nullifier) ==
  leaf.ticket_nullifier_commitment`. So the on-chain leaf set (public *before* the beacon, I-2) does
  **not** reveal which ticket will win, while double-use detection (I-5) is unchanged. Leaf-uniqueness
  is enforced on the commitment.
- **I-14 DA possession binding (R2):** an auditor's signed message (`PalwAuditorVoteV1::signing_hash`)
  covers the beacon-selected `audit_sample_root`; since consensus independently re-derives that root
  from the audit beacon over the batch's receipt DA, a valid vote signature cannot be produced without
  identifying — hence possessing — the beacon-selected receipt chunks. "Certify without fetching" is
  closed structurally, not by an honesty assumption (this is the vote-signing half of D12/I-6).

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
  economic, **not** SNARK soundness. The *asymmetric* case — one malicious provider griefing an honest
  partner into a mutual no-credit — is now attackable-only-at-a-loss via D14 mismatch attribution
  (escalate to a reference re-run, slash only the deviator), so the honest partner is never the one
  penalized; it does not remove *symmetric* collusion, which the above composition bounds.
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

**Implementation status (2026-07-16).** The **inert consensus foundation is complete and byte-identical
on every live net** — every clause of the algo-4 acceptance rule is now wired and gated
(`palw_activation_daa_score == u64::MAX`): clauses 1–5 (nullifier/proof-type/leaf/cert/interval) +
the past-relative batch-view gate (C5), clause 6 (chain_commit) and clause 9 (eligibility draw) at body
stage via the **C6 header-carried-lagged-R_E** architecture (a design panel rejected the naive buried
`beacon_state` read as an IBD-order-dependent split; instead each v3 block carries its own `R_E` in the
retained `palw_beacon_seed` header field, authenticated at its own virtual stage, and a descendant reads
the *lagged* `R_E` from its finality-buried anchor's header field — present on every node, pruning-
surviving, reorg-stable), clause 8 (compute cap) at header validation, plus the cross-ancestor nullifier
dedup, the D3 pruning-bundle wire types, and R1–R4. Verified via `test_genesis_hashes` + P2P/RPC header
roundtrips + the GHOSTDAG/difficulty/sanity golden suites across every commit.

**Activation-only work — NOT inert-committable (the re-genesis cutover checklist).** The following
cannot land as gated, byte-identical code; they are the cutover itself and its external dependencies:
- **Clause 7 (lane-aware header difficulty):** the enforced header difficulty gate must branch on the
  algo-4 lane (bind `header.bits` to a pure-header-window lane-DAA retarget instead of the single-lane
  hash retarget) — a change to the LIVE difficulty path, safe only as an added `palw_active` branch that
  leaves the else-path textually identical; co-requisite is a body/header-stage lane-bits derivation
  (never the virtual-only, pruned `palw_lane_bits_store`).
- **algo-4 mining template:** the block-template builder must construct algo-4 headers (select a winning
  ticket, fill `palw_beacon_seed` from the node's own virtual `R_E`, resolve the same buried anchor for
  `chain_commit`) so construction == validation is physically closed.
- **D3 pruned-IBD frontier:** carry the PALW frontier on the `PruningPointOverlaySnapshot` **wrapper**
  (never the committed `OverlaySnapshot`, whose borsh feeds the live `overlay_commitment_root`), seed it
  on import, and add the `PalwEpochProofBundleV1` builder + verifier + P2P flow (§18.3/§18.4).
- **`LATEST_DB_VERSION` 7 → 8** bumped ONCE at the re-genesis cutover (the whole PALW bincode format),
  together with a **new network id + genesis** (`testnet-palw-10`) and a re-genesis recalibration of the
  DNS lag/backoff into the C6 band `finality_depth <= burial < pruning_depth`.
- **External infrastructure:** the real Qwen **CUDA** backend behind `VerifiableInferenceBackend`; the
  live **DNS PALW beacon** commit/reveal network; and the **weight-0 network** deployment + the §3
  Phase-8 weight ladder (0 → 25 → 50 → 80 %), each gated on the §6 stop conditions.
- **Residual security-review item (C6):** a buried anchor's `palw_beacon_seed` is authenticated only at
  the anchor's own virtual stage, so a forged-seed block stays body-valid (chain-disqualified); the
  clause-9 draw a descendant takes against it is bounded by the 5× `E`-cap and is **not** a split (all
  nodes read the same header field). The SLICE-5 band gate `burial >= finality_depth` mitigates it by
  requiring the anchor to be DNS-finality-settled, collapsing it into the standing I-4 trust.
