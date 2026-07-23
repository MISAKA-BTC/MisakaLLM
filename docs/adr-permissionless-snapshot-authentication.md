# ADR: Permissionless (chain-derived) pruning-snapshot authentication

Status: **Design + foundational primitives landed; wiring is a reviewed StopShip.**

This ADR records the design that removes the operator-pin trust anchor from Header-v4
pruning-snapshot import, so a fresh node on a permissionless valuable network can
authenticate a captured pruning boundary from the chain itself. It complements
`palw-pruning-snapshot-runbook.md` (§"Permissionless valuable-network gate") and
`palw-public-value-header-v4-antispam.md` (§6, §7), which name this as the open blocker.

This session landed the **pure cryptographic core** of the design and the ADR. It did
**not** change any live import path, relax the peer-import fence, or add an admitted
provenance. Everything under "Wiring (not yet landed)" remains a StopShip requiring
independent review, a fresh Header-v4 re-genesis, and multi-node soak.

## Context — what exists today

Two import provenances are admitted (`consensus/core/src/palw_pruned_frontier.rs`):

- `LegacyHeaderV3` — the closed-network trusted-data / headers-proof path.
- `OperatorPinnedCheckpoint` — a Header-v4 boundary authorized by an out-of-band
  operator pin (`PalwPruningSnapshotCheckpoint = pruning_point : payload_digest`). The pin
  is deliberately a digest of the **complete** canonical payload, so it transitively
  authenticates every transported anti-spam support row.

`palw_pruned_ibd_snapshot_import_allowed()` admits exactly `(v3, LegacyHeaderV3)` and
`(v4, OperatorPinnedCheckpoint)`; every other pairing and every future header version is
refused.

The durable install lands at `consensus/src/pipeline/virtual_processor/processor.rs`
(`import_pruning_point_palw_snapshot` → `self.db.write(batch)`) and the intrusive path at
`consensus/src/consensus/mod.rs` (`intrusive_pruning_point_update_with_palw_snapshot`).

The `c == v` authentication — recomputing `PalwSelectedParentStateV2::state_root()` and
comparing the folded `overlay_commitment_root` against the committed header field — runs in
`consensus/src/pipeline/virtual_processor/utxo_validation.rs`
(`verify_expected_utxo_state`), which only executes once the **first post-pruning-point
Header-v4 child body** is validated, i.e. **after** peer boundary rows were installed.

## Problem — two gaps the operator pin hides

1. **Install-before-verify.** The durable write precedes the `c == v` descendant check. A
   digest advertised by the same IBD peer is only transport integrity, not an independent
   authenticator. Without the operator pin, the boundary is installed before anything chain-
   derived has authenticated it.

2. **Unbound support rows.** Transported anti-spam `support_rows` are checked only for
   canonical shape, monotonicity, and closure completeness
   (`processor.rs::validate_pruned_spam_closure`). They are **not** bound to any header. The
   pruning-point row is bound to the PP header's `palw_spam_accumulator_commitment`, but the
   historical rows below the PP have no per-row header commitment and no below-PP headers are
   transported to check them against. Their only authentication today is the operator
   payload digest.

## Decision — the permissionless authentication design

Add a third, reviewed provenance `ChainDerivedHeaderBundle` that authenticates the boundary
from a **bounded, PoW-authenticated header bundle** transported alongside the snapshot,
verified **before** the durable write.

### Landed this session (pure, testable, fenced)

In `consensus/core/src/palw_pruned_frontier.rs`:

- `TransportedSpamHeaderCommitmentV1 { block_hash, spam_accumulator_commitment }` — one
  transported Header-v4 fact (the value a support row is bound against).
- `verify_support_rows_against_transported_headers(spam, pruning_point, headers)` — requires
  the transported header set to be **exactly** the PP row plus every support row (no
  missing, no extra, canonical strictly-increasing, no PP aliasing) and each header
  commitment to equal the corresponding row's `commitment()`. This is gap 2's binding as a
  pure function. It authenticates the *binding*, not the headers themselves.
- `reconstruct_selected_parent_state_from_pruning_payload(payload, paid_work_nullifiers,
  da_state_root)` — rebuilds `PalwSelectedParentStateV2` from the transported payload instead
  of installed stores. `state_root()` on the result is what a first-child `c == v` compares.
  Soundness does not depend on the caller deriving the two window/DA values correctly,
  because the root is compared against a PoW-authenticated header: any wrong field fails.

Tests: `permissionless_support_row_binding_accepts_matched_headers_and_rejects_tampering`
(positive + wrong-commitment / missing / extra / substituted / non-canonical / PP-alias),
`reconstruct_selected_parent_state_binds_every_transported_field`, and
`header_v4_peer_import_admits_no_permissionless_provenance` (fence still closed).

### Wiring (not yet landed — the StopShip)

1. **Transport a bounded authenticated header bundle** with the snapshot:
   - the descendant Header-v4 header(s) that commit the PP selected-parent state via
     `overlay_commitment_root` (the `c == v` anchor), and
   - the below-PP Header-v4 header commitments for every transported support row.
   Bound by a new digest domain and the existing 128-MiB / `MAX_PALW_PRUNING_SPAM_SUPPORT_ROWS`
   caps. P2P negotiates a new message; consensus-core keeps the same outer envelope fence.

2. **Authenticate the bundle from the chain**: each transported header must pass proof-of-work
   and objective-target validation and link into the selected chain by the same rules a live
   header does. This is the trust root that replaces the operator pin. The primitives above
   deliberately do not do this; the header processor's PoW/target path is reused here.

3. **Move `c == v` ahead of the durable write.** In
   `prepare_pruning_point_palw_snapshot_import` (read-only today), for
   `ChainDerivedHeaderBundle`: call `reconstruct_selected_parent_state_from_pruning_payload`,
   compute the folded `overlay_commitment_root` via the existing core composition
   (`palw_overlay_commitment_root_v2` + `OverlaySnapshot::versioned_commitment_root`), and
   require equality with the authenticated descendant header. Then call
   `verify_support_rows_against_transported_headers` with the authenticated below-PP header
   commitments. Only on success does `stage_prepared_...` + `self.db.write(batch)` run.

4. **Admission**: extend `palw_pruned_ibd_snapshot_import_allowed` to admit
   `(v4, ChainDerivedHeaderBundle)` **only** behind a new default-`false`
   `Config::palw_permissionless_snapshot_auth` lever, mirroring the `palw_algo4_accept`
   discipline. All six shipped presets keep it off; the PALW presets keep their
   archival/closed-network policy.

### 1c derivation specification (reverse-engineered from the store methods)

The importer must feed the verifier the same two derived values the live overlay-commitment path
computes (`processor.rs::versioned_overlay_commitment_root`, v4 branch), but sourced from the
transported payload. For the pruning-anchored case (selected parent == pruning point):

- **`paid_work_nullifiers`** — reproduce `palw_paid_work_window(pp, pp_daa)`. At import the anchor is the
  pruning point and no live blocks sit above it, so only the transported below-boundary window
  contributes (the store walk's `snapshot.payload.paid_work` branch, `processor.rs:4775-4781`):
  `{ nullifier : row ∈ payload.paid_work, pp_daa − row.block_daa_score ≤ walk_bound, nullifier ∈ row.job_nullifiers }`,
  deduplicated and sorted by `Hash64::as_bytes()`. `walk_bound = palw_batch_admission
  .paid_work_walk_bound_daa(palw_epoch_length_daa)` (network params). The backward-chain half of the
  walk must be shown to contribute nothing at the pruning boundary (its `stop_at` is the boundary).
- **`da_state_root`** — reproduce `palw_da_parent_state(pp, pp_daa).state_root()`. Candidate:
  `payload.da_snapshot.map(|s| s.state.state_root()).unwrap_or(PalwDaStateV1::default().state_root())`.
  This MUST be fixture-validated against `palw_da_parent_state`, because "parent state" clears the
  one-block `block_slashed_providers` delta and the transported `state` may or may not already have it
  cleared.
- **`legacy_overlay_root`** — `commitment_root()` of the transported, authenticated DNS/EVM
  `OverlaySnapshot` (the boundary already transports the required DNS overlay snapshot).

Because `verify_chain_derived_pruning_boundary` compares the fold against a PoW-authenticated child's
committed root, a wrong derivation fails **closed** (rejects a valid boundary) and never accepts an
invalid one. Correctness is therefore a functionality — not a safety — requirement, but it must still be
proven with a `TestConsensus` fixture that computes both the store-based and payload-based values and
asserts equality, and reviewed, before the lever is trusted. This is why 1c is not shipped speculatively.

### Auth/transport structural note (1b/1c/1d)

`PalwPruningSnapshotImportAuth { checkpoint, provenance }` is shaped around the operator pin and does not
fit the chain-derived path (which has no checkpoint). 1c/1d should carry `PalwChainDerivedAuthBundleV1`
through a distinct seam rather than forcing it into the checkpoint-shaped auth, and gate the importer on
`palw_pruned_ibd_chain_derived_import_allowed(config.palw_permissionless_snapshot_auth, header_version)`
plus a successful `verify_chain_derived_pruning_boundary` before `stage_prepared_...`/`db.write`.

## Consequences / honest status

- The reviewable cryptographic binding for both gaps now exists and is unit-tested in
  isolation, so the wiring can be reviewed against a fixed contract.
- Peer import behavior is **unchanged**: no new provenance is admitted, the fence test pins
  this, and every existing `palw_pruned_frontier` / import-auth test still passes.
- Public activation remains blocked on: the transport + PoW bundle authentication + pre-
  install rewiring above; a fresh Header-v4 re-genesis; independent review; and multi-node
  pruning/catch-up/reorg soak. This ADR does not authorize any preset change.

## Test / review plan for the wiring

- Reuse `first_post_pp_header_v4_rejects_each_tampered_selected_parent_component` as the
  pre-install `c == v` matrix (moved to run before staging for the new provenance).
- A processor test proving, for `ChainDerivedHeaderBundle`, that a tampered snapshot or an
  unauthenticated/mismatched header bundle fails **before** any `db.write`.
- Extend `palw_snapshot_auth` (IBD) and `palw_pruning_import_auth` (consensus) with the new
  provenance, still fenced by default.
- Independent review of the PoW-bundle authentication and the durable-write ordering before
  any re-genesis candidate sets the lever.
