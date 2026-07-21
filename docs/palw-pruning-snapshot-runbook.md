# PALW pruning snapshot runbook

This runbook covers the DB-v14 strict PALW pruning-boundary capture/recovery machinery, the existing
closed-network Header-v3 import path, and the explicitly operator-authenticated Header-v4 path. It
applies only after the network's PALW activation DAA and only to a non-genesis pruning point.
Header-v4 never trusts a peer digest by itself: the operator must preconfigure the exact pruning-point
hash and complete canonical snapshot-payload digest. Permissionless descendant/header-bundle
authentication remains a future path and a public-activation blocker.

## What is captured

`PalwPruningPointSnapshotV1` is one canonical Borsh object with a keyed BLAKE2b-512 payload digest. A usable snapshot is all-or-nothing and contains:

- the PALW execution frontier (beacon state, overlay view, lane bits, active nullifiers);
- one content-addressed manifest for every retained lifecycle entry; for an entry with `cert_hash`,
  the exact certificate and all `leaf_count` leaves whose zeroed-`batch_id` projection re-derives
  `leaf_root`; uncertified entries canonically carry no leaf bodies and may re-announce them with
  their manifest-membership proofs after the pruning boundary;
- the fork-local beacon accumulator;
- every provider-bond record as of the pruning point;
- the below-pruning-point paid-work window, including explicit empty selected-chain rows;
- the Header-v4 anti-spam pruning-point row and exactly one bounded selected-parent checkpoint
  (`next_power_of_two(window_daa)`, at most 65,536 support rows);
- the DA pruning snapshot, including obligations, challenges, counters, and timeout-dedup state.

The legacy `PalwPrunedFrontierV1` by itself is never accepted as an import.

## Normal operation

When the pruning point moves, the node builds and validates the complete snapshot before deleting any source row. The new pruning-point pointer, DA singleton, complete PALW snapshot singleton, and required DNS overlay snapshot commit in the same RocksDB batch. A capture error stops pruning; it never emits a partial boundary or advances the pointer alone.

Boundary capture/recovery holds the pruning-session write lock only through the pointer/sidecar batch.
It drops that guard before UTXO advancement and before the data pruner reacquires the same lock, so an
IBD session cannot race an old-boundary repair over a newer pruning point and the lock is not
re-entered. Because cache-backed batch stores publish their in-memory value before RocksDB commits,
any store-staging or final DB-write failure after staging begins is process-fatal. Returning and
retrying in-process could otherwise mistake unpersisted cache entries for a durable boundary.

After every ordinary header/body prune batch has committed, the node performs a separate anti-spam
reclaim pass while still holding the pruning-session guard. It enumerates and validates every
accumulator row, uses every row whose header still exists plus the pruning point as bounded closure
tips, and pins the current snapshot support rows without expanding another checkpoint below them.
This distinction is required for a fresh pruning import: the transported checkpoint is sufficient and
must not be asked to supply an older checkpoint that was never transported. A coalescing worklist
marks shared selected-parent closure once; retained proof/anticone/side-fork headers therefore remain
safe without quadratic walks over overlapping paths.

Rows outside the marked union are deleted only after the full read/header/parent/skip preflight, in one
separate RocksDB batch. Any iterator, header-presence, snapshot, or closure failure deletes zero rows;
any cache-backed staging or final write failure is fail-stop. Old support from a replaced catch-up or
boundary may exist until this post-prune pass, then is reclaimed if it is neither current support nor
inside a surviving-header closure. Do not manually delete old support rows between these phases.

During the existing closed-network Header-v3 headers-proof IBD path, the node:

1. validates and applies the pruning proof to staging header state;
2. requires the snapshot digest advertised in the earlier trusted-data package;
3. downloads at most 128 MiB, using the same exact outer-Borsh cap enforced by consensus-core,
   then decodes and canonically validates the exact pruning-point snapshot;
4. checks the pruning-point hash, DAA score, Header-v4 anti-spam commitment, local paid-work window, required components, component cardinalities, and payload digest;
5. atomically installs content blobs, provider, beacon, overlay, lane, nullifier, anti-spam, DA, and snapshot rows;
6. downloads the UTXO set and verifies every still-locked provider collateral amount and owner script before activating it;
7. marks the pruning UTXO set stable only after PALW, EVM, and DNS overlay sidecars have succeeded.

Any failure cancels staging or leaves the UTXO-stable flag false so another peer can be tried.
Pruning catch-up against the current live consensus has a stricter boundary: it downloads and
semantically preflights the PALW snapshot plus pruning path/anticone first, then commits the provider
registry, DA/PALW rows, pruning-point pointer, virtual state, tips, selected chain, missing-anticone set,
and unstable-UTXO flag in one RocksDB batch. There is no intermediate `old PP + new provider/snapshot`
state. Once that batch starts staging, an infrastructure write error is fail-stop for the cache-safety
reason above.
For Header-v4, the client looks up an exact local operator checkpoint before requesting peer snapshot
bytes. No matching pruning-point pin means no request and no import. If trusted data also contains a
snapshot digest it must equal the local pin; it is corroboration, not authority. After download, the
client recomputes the canonical complete-payload digest and compares it with the pin. The consensus
API receives typed `OperatorPinnedCheckpoint` provenance and independently rechecks exact Header-v4,
pruning-point hash, and payload digest before staging the first durable write. Header-v3 retains its
existing trusted-data/catch-up behavior, and every future header version is rejected.

## Configure an operator-authenticated Header-v4 boundary

Obtain the snapshot payload digest and pruning-point hash over an authenticated channel independent
of the IBD peer. Prefer two archive operators or a signed release manifest, and verify the transferred
file offline before configuring the node:

```bash
misaka node pruning-snapshot verify \
  --file /secure-transfer/palw-pruning-snapshot.borsh \
  --expect-pruning-point <128-hex-hash> \
  --expect-digest <128-hex-payload-digest>
```

Repeat the CLI option for every authorized boundary:

```bash
kaspad ... \
  --palw-pruning-snapshot-checkpoint=<128-hex-pruning-point>:<128-hex-payload-digest> \
  --palw-pruning-snapshot-checkpoint=<next-128-hex-pruning-point>:<next-128-hex-payload-digest>
```

The equivalent TOML configuration is:

```toml
palw-pruning-snapshot-checkpoints = [
  "<128-hex-pruning-point>:<128-hex-payload-digest>",
  "<next-128-hex-pruning-point>:<next-128-hex-payload-digest>",
]
```

Parsing is exact: each side is one 64-byte `Hash64` encoded as 128 hexadecimal characters, with one
colon and no `0x` prefix or whitespace. Repeating the same pruning point is refused even when the
digest is identical; two different digests for one point are a conflict and are also refused. Pins
are node-local import authorization. They do not activate algo-4, change consensus parameters, alter
any shipped preset, or relax the PALW presets' archival/peer-allowlist startup policy.

## Offline verification CLI

The verifier is read-only and never writes a datadir:

```bash
misaka node pruning-snapshot verify \
  --file /secure-transfer/palw-pruning-snapshot.borsh \
  --expect-pruning-point <64-byte-hash> \
  --expect-digest <trusted-data-digest>
```

Use `--output json` for automation. Exit code `10` means the file exceeded the transport cap or failed a safety pin/validation check. The command reports component counts so an operator can compare two independently obtained files without importing either one.

Snapshot export/import for live consensus is intentionally performed by the bounded P2P IBD flow. There is no CLI that writes snapshot bytes directly into RocksDB; bypassing the consensus importer would skip header, UTXO, DA, and atomicity checks.

## Startup recovery

At startup the pruning worker validates that the singleton is canonical and matches the current
pruning point/header. When the outer snapshot embeds a DA boundary, the separately persisted DA
singleton must be present and byte-identical (including its pruning-point tag); either half alone is an
invalid current boundary.

- If either required PALW/DA or DNS-overlay sidecar is missing, stale, or corrupt **and source rows remain**, the node deterministically rebuilds all missing sidecars and commits them in one RocksDB batch.
- On a non-archival node, if pruning already reached the retention-period root, repair of either sidecar is refused. Restore a matching pre-prune datadir/snapshot or use an allowed headers-proof IBD path from another peer.
- Archival nodes are always classified as retaining reconstruction rows, even when their retention checkpoint equals the retention root, because their pruner never deletes those rows.
- Reorg or intrusive catch-up replaces the selected-chain provider registry and singleton in one batch; old-chain rows cannot remain mixed with the new snapshot.
- A fresh anti-spam import retains exactly the transported checkpoint. Subsequent children are
  derivable without any pre-floor lookup; after the next boundary, the normal sweep reclaims old
  support while preserving current PP, proof/anticone, and side-fork closures.

Do not delete individual PALW/DA prefixes to “repair” a node. That turns a detectable complete-state failure into an unrecoverable partial view.

## DB-v14 cutover

`LATEST_DB_VERSION` is 14. The daemon requests a reset for every datadir at version 13 or earlier. Do not copy PALW overlay, pruning-snapshot, or DA prefixes from a pre-v14 datadir into a v14 datadir. Archive the old directory first if it is needed for forensic comparison.

After upgrade, confirm:

```bash
cargo test -p kaspa-consensus-core palw_pruned_frontier --lib
cargo test -p kaspa-consensus-core operator_checkpoint --lib
cargo test -p kaspa-consensus-core first_post_pp_header_v4_rejects_each_tampered_selected_parent_component --lib
cargo test -p kaspa-p2p-flows palw_snapshot_auth --lib
cargo test -p kaspa-consensus palw_pruning_import_auth --lib
cargo test -p kaspad palw_snapshot_checkpoint --lib
cargo test -p kaspa-consensus uncertified_pruning_import_accepts_leaf_reannouncement_with_manifest_membership_proof --lib
cargo test -p kaspa-consensus fresh_db_pruning_import_restores_first_post_pp_ticket_and_reward_blobs_after_restart --lib
cargo test -p kaspa-consensus palw_pruning_spam_closure_tests --lib
cargo test -p kaspa-consensus model::stores::palw_spam::tests --lib
cargo test -p kaspa-consensus palw_snapshot_recovery_tests --lib
cargo test -p kaspa-consensus palw_lane_bits --lib
cargo check -p kaspa-p2p-lib -p kaspa-p2p-flows --lib
cargo check -p misaka-cli --bin misaka
```

## Permissionless valuable-network gate

Snapshot transport is deterministic, bounded, atomic, and fail-closed. Without a configured operator
checkpoint, the advertised outer payload digest is still supplied by the same IBD peer, so it is only
transport integrity. In the Header-v4 operator path, the out-of-band pin is the trust anchor and the
peer cannot choose another canonical payload with the same authenticated digest.

Header-v4 defines the root needed to authenticate a captured pruning boundary at a re-genesis
boundary. Its versioned overlay commitment folds a domain-separated `PalwSelectedParentStateV2`
root covering the exact selected parent, execution frontier (beacon/batch/lane/nullifiers), beacon
accumulator, provider view, active paid-work nullifier set, DA state root, and the overlay view's
immutable active-batch references. The reference root is computed only from the block-keyed
lifecycle, never by enumerating a mutable local blob store. A first post-pruning-point child can
therefore reject any changed component. This is the basis of a future trustless path, but `c == v`
currently runs only with the descendant body, after peer state would have been installed. The
operator-pinned path does not depend on that unsafe ordering: it authenticates the complete payload
before installation. A permissionless path must still move descendant verification before the write
or transport and validate a bounded authenticated header bundle.

The directly pruning-point-header-bound anti-spam row does not by itself authenticate every older
support row transported for horizon and skip-link validation. Canonical ordering, monotonic counters,
and link shape prevent malformed witnesses, but are not a header commitment to each historical row.
The operator checkpoint is instead the keyed digest of the entire canonical snapshot payload, so any
support-row byte change produces another digest and is rejected before durable installation. A future
permissionless path cannot assume that operator trust; it must recursively bind those rows or verify
their corresponding transported Header-v4 preimages before installation.

Accepted lifecycle provenance is now block-keyed and staged atomically with the virtual UTXO commit.
Header-v4 parent completion waits for the selected parent's accepted row; strict pruning capture projects
the exact accepted manifest/leaves/certificate rather than treating raw mergeset observation as
acceptance. The lower-level raw-view seam remains deliberately fail-closed, as pinned by
`raw_but_unaccepted_manifest_view_entry_rejects_pruning_capture` and
`raw_invalid_certificate_view_entry_rejects_pruning_capture`.

The closure regressions `palw_pruning_snapshot_uses_accepted_block_keyed_lifecycle_provenance` and
`palw_pruned_ibd_matches_from_genesis_under_raw_overlay_adversary` now pin arrival-order-independent
capture and fresh-node equivalence. Public activation is still fenced because the current safe v4
path relies on an operator-selected trust anchor rather than permissionless chain-derived
authentication, and because live multi-node pruning/catch-up/reorg soak remains incomplete.

This does not retroactively strengthen the shipped pre-v4 schemas. Mainnet/simnet remain Header-v1,
ordinary testnet/devnet remain Header-v2, and the two PALW presets remain Header-v3; all six keep the
Header-v4 anti-spam mechanism inert. The PALW presets therefore retain their archival/closed-network
policy. A permissionless candidate must use a fresh Header-v4 genesis, move descendant/header-bundle
authentication before installation, independently verify retained anti-spam support rows, keep
provider and DA cardinality caps fail-closed, and pass independent review plus the remaining launch
gates (automatic owner-key response submission, DA availability/serving behavior, anti-spam calibration,
snapshot/pruning soak, public unbond/slash rehearsal and custody/incident procedures, and cross-device/runtime
measurements). The implemented operator checkpoint is suitable for an explicitly coordinated network,
but cannot substitute for deterministic chain-derived verification on a permissionless network.
