# PALW algo-4 devnet activation runbook (ADR-0039 P0→live)

Goal: get a **single local kaspad node to mine/accept one PALW algo-4 (proof-of-LLM) block**
using a **mock k=2 backend** and **no external DNS beacon network**. Derived from a verified
6-subsystem code map (2026-07-18). The PALW validation / difficulty / GHOSTDAG-work / reward /
nullifier / beacon-auth pipeline is **already wired and inert**, fenced on
`palw_activation_daa_score == u64::MAX`. What does NOT exist in live (non-test) code: an algo-4
**mining template**, an on-chain PALW **overlay-tx producer**, and a live-reachable
`skip_proof_of_work` (it is a per-preset field, `true` only for SIMNET).

Two goals with very different cost:
- **ACCEPT** one externally-built algo-4 block on a live node — the in-process E2E already proves the
  validator accepts + pays; Stages 1–6.
- **MINE** one through the node's own template — needs the template slice that does not exist; +Stage 7.

Mock k=2 is legitimate: consensus treats the inference leaf as **opaque** (it never re-runs the model),
and the `DegradedGrace` beacon path accepts blocks **without a live quorum**. So a real accepted algo-4
block needs **zero GPU and zero DNS network** — the cost is re-plumbing test-only seeding onto a live node.

## Landmines (fail-closed, re-genesis-time)
1. **Layer-0 PoW vs pinned nonce.** `check_pow_and_calc_block_level` runs the BLAKE2b-SHA3 hash floor for
   every header incl. algo-4, but clause 9 pins `nonce == low64(nullifier)`. No algo-4 PoW-bypass branch
   exists. Only live escape: `skip_proof_of_work = true` baked into the preset. Wrong ⇒ every algo-4 block `InvalidPoW`.
2. **Live overlay-store population.** The leaf/certificate/Active-view that `check_palw_ticket` reads are
   seeded directly by tests; nothing on a live node produces them, and honest batch activation requires one
   Healthy beacon epoch. Stage 4's devnet startup-seeding is the pragmatic stub — a real production path.
3. **Genesis hash + DNS consistency, atomically.** `DEVNET_PALW_GENESIS.bits` must equal `0x207fffff`
   (`is_consistent_for_activation`); the recomputed genesis hash must be exact; `dns_params` must satisfy
   `dns_v3_params_consistent` (the only consistency predicate enforced **live**; `is_consistent_for_activation`
   and `palw_checkpoint_params_consistent` are test-only). No `LATEST_DB_VERSION` bump needed for a **new**
   net (fresh DB); the 7→8 bump is only for re-genesis of an existing net.

## Stages

### Stage 1–3 — devnet-palw genesis + preset + selection — **DONE** (commit d02d1dd)
- `genesis.rs`: `DEVNET_PALW_GENESIS` (bits `0x207fffff`, coinbase "misaka-devnet-palw", hash via `gen_kaspa_pq_genesis_hashes`).
- `params.rs`: `DEVNET_PALW_PARAMS` from `DEVNET_PARAMS` + recipe (`palw_activation_daa_score=0`,
  `palw_lane_difficulty=DEVNET_PALW_LANE_DIFFICULTY`, `skip_proof_of_work=true`,
  `pow_blake2b_sha3_activation=always`, EVM off, min difficulty window pinned, scale=0). Inherits
  `palw_epoch_length_daa=100`, `palw_beacon_grace_epochs=1`, v3-consistent `GENESIS_ACTIVE_DNS_PARAMS`.
- `From<NetworkId>`: Devnet suffix 111 ⇒ `DEVNET_PALW_PARAMS`; `args.rs`: `--devnet --netsuffix=111`.
- Verified: boots as `devnet-111` (gRPC up, own genesis, no panic); `devnet_palw_preset_selected_and_active` green.
- Run: `kaspad --devnet --netsuffix=111 --appdir <fresh> --enable-unsynced-mining`.

### Stage 4 — live overlay-store seeding (crux for ACCEPT) — TODO (L, Medium-High risk)
Devnet-only startup hook seeding the selected-parent overlay view: `palw_store.insert_leaf`/`insert_certificate`
+ `palw_overlay_view_store` with a batch `Active`/certified view — porting `tests.rs:5156-5196` to the live DB.
Leaf from a mock k=2 match (`mil/provider/src/palw_replica.rs:284` pattern). Mockable: k=2 inference
(`MockDeterministicRuntime`), auditor cert (self-signed, single node ~100% stake), overlay-tx lifecycle
(bypassed by direct seeding — honest path is Stage 8).

### Stage 5 — buried DNS anchor + beacon seed (DegradedGrace) — TODO (M)
Mine a short algo-3 v3 chain (real template, trivial with `skip_proof_of_work`) so
`resolve_palw_lagged_anchor` (`processes/palw.rs:284`) returns a finality-buried anchor with an
authenticated non-zero `palw_beacon_seed`. With `grace>=1`, epoch-0 mode is `DegradedGrace` ⇒ block
accepted with no quorum; anchor resolution is burial-only. Keep the demo inside one PALW epoch (clause-10 carry=0).
Tune anchor windows small (`attestation_epoch_length_blue_score=4, lag=2, backoff=1`) if the buried anchor
does not resolve within the demo chain.

### Stage 6 — submit one algo-4 block (ACCEPT milestone) — TODO (M-L)
External tool replicating `mint_algo4` (`tests.rs:4924`): `pow_algo_id=4`, `bits=replica_bits`,
`nonce=low64(nullifier)`, all 8 ticket fields (`with_palw_fields`), `chain_commit` from the buried anchor,
`palw_beacon_seed`=template-derived own seed. Grind the nullifier so `palw_eligibility_win` passes (easy bits
⇒ ~1-2 tries). Submit via `submit_block` RPC (headers already transmit PALW fields on the wire). Expect
iteration debugging clauses 6/7/8/9 against live stores. Result: block → `StatusUTXOValid`; a merging child
pays the provider pair (`ReplicaPalw`, 77% split). Also accept algo-4 in `check_algo_id_known` (`pow_layer0.rs:160`).

**MINIMAL VIABLE MILESTONE = Stages 1→2→3→4→5→6** (one accepted algo-4 block; node accepts, does not mine).

### Stage 7 — algo-4 mining template (MINE) — TODO (L, High risk)
`build_block_template_from_virtual_state` (`processor.rs:4567`): make `required_algo_id` emit 4, wire
`palw_select_template_ticket`/`palw_template_candidate` over a **new per-node Active-ticket inventory**,
promote the `debug_assert` (`processor.rs:4745`) to a live gate, set `nonce=low64(nullifier)`, lane bits, and
all ticket fields; bypass the miner nonce-grind for algo-4. Touches the mining hot path (zero PALW awareness today).

### Stage 8 — honest overlay-tx + real beacon (production, not demo) — TODO (XL)
Overlay-tx producer (subnetworks 0x30-0x36), real commit-reveal beacon reaching Healthy,
`PalwBlockAuthorizationV1` (ML-DSA) body producer (validation consumer exists, no producer), pruning-boundary
transport (`PalwEpochProofBundleV1`). Out of scope for a single-node demo.

## Real-GPU version
Swap `MockDeterministicRuntime` → `QwenLocalBackend` (already a `VerifiableInferenceBackend`; drop-in via
`dispatch_k2_backends(&dyn ...)`) built `--features qwen-cuda`/`qwen-metal` + pinned GGUF. Two Qwen backends
on ONE host give a genuine k=2 match via local determinism. True cross-machine exactness needs the canonical
kernels (docs/design/misaka-canonical-compute-v1.md §19); `canonical_gemm_trace_root` currently commits to
output tokens, not a per-matmul §7.4 Merkle root.

## Honest effort
Many-days, not few-hours. Stages 1-3 (~1 day) DONE. Stages 4-6 are where days disappear: porting a
heavily-scaffolded in-process harness onto a live node with no seeding surface, then debugging clause-by-clause
against a running DB — realistically **3-6 focused days** for a first accepted block. MINE (Stage 7) adds
several more. Real cross-machine GPU is an open determinism problem, not a scheduling one.
