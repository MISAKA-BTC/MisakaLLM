# PALW closed shared testnet operator runbook

This runbook is for a **closed, IP-allowlisted, no-value** PALW wiring test. Prefer
`testnet-110`; use `devnet-111` only for local plumbing. It is not an activation guide and it must
not be used for a public or value-bearing network.

The safe envelope is deliberately narrow:

- use fresh, disposable per-node data directories and test-only keys/funds;
- bind node RPC to loopback only;
- allow P2P only between named operators at the firewall and with reciprocal `--connect`;
- start every node with the same binary, network ID, genesis, and `--palw-enable-algo4` setting;
- start every node from genesis before the network pruning point advances, and keep every node caught
  up continuously;
- keep `--archival` enabled for the lifetime of the database.

`--archival` retains local bodies but does not add the PALW provider registry to pruning-point IBD.
The node therefore fails closed before any P2P pruning-point snapshot import (including a genesis
UTXO reset that could leave later provider rows behind). Late joins and a node that
falls behind across the pruning point are unsupported: restore a matching full data-directory snapshot
from the same closed mesh or stop and coordinate a fresh network from genesis. Do not wipe a node and
try to rejoin the current tip.

See [ADR-0040](adr/0040-palw-single-pool-integer-canonical-remediation.md) and the
[T-shared progress record](palw-tshared-progress-2026-07-20.md) for the consensus rationale and
open gates.

## Network and ports

| Purpose | `testnet-110` | `devnet-111` | Exposure |
|---|---:|---:|---|
| Node arguments | `--testnet --netsuffix=110` | `--devnet --netsuffix=111` | n/a |
| P2P | `26411` | `26611` | approved peer IPs only |
| Node gRPC (ordinary miner/low-level RPC) | `26210` | `26610` | loopback |
| Node wRPC Borsh (validator/operator) | `27210` | `27610` | loopback |
| Node wRPC JSON (optional) | `28210` | `28610` | loopback |

P2P and RPC ports are not interchangeable. `palw-submit` uses **wRPC Borsh**, never the P2P
port. `testnet-110` keeps real Layer-0 algo-3 PoW; `devnet-111` skips that PoW and is therefore only a
local integration preset.

Build the three operator binaries from the exact same revision:

```sh
cargo build --release -p kaspad -p kaspa-pq-validator -p misaminer
```

## Minimum role topology

Roles may be co-located for this no-value wiring test, but identities and locked outpoints remain
distinct.

| Role | Minimum for wiring |
|---|---|
| Network | Two independently reachable archival `kaspad` nodes with reciprocal P2P connections |
| Supporting chain | At least one ordinary algo-3 miner, so DAA, confirmations, and UTXO maturity advance |
| DNS/beacon | Enough active DNS stake-bond validators to reach the configured 2/3 beacon quorum; run both `--enable-validator` and `--enable-beacon` |
| Leaf providers | Two distinct active PALW provider bonds (`provider_a_bond != provider_b_bond`) |
| Auditor | At least one additional active PALW provider credential and operator group not used by either leaf provider |
| Algo-4 miner | One ticket-authority key, its durable ticket-secret store, a PQ payout address, and at least one accepted `batch_id:leaf_index` |

The minimum provider registry is therefore **three distinct credentials/groups**: provider A,
provider B, and a non-excluded auditor C. This proves wiring, not independent quorum security. A more
meaningful closed test uses three equal-stake non-excluded auditors (two PASS votes reach 2/3), for five
distinct provider credentials/groups total. The configured committee size is 16 but selection caps at
the eligible candidate count.

DNS stake bonds and PALW provider bonds are separate objects. A PALW auditor is selected from the PALW
provider-bond view, not from the DNS stake registry. Always treat every such outpoint as locked.

## Start a reciprocal two-node mesh

On node A, replace `NODE_B_IP` with the stable source IP that A will actually observe:

```sh
./target/release/kaspad \
  --testnet --netsuffix=110 \
  --appdir=/absolute/path/palw-node-a \
  --archival --utxoindex \
  --listen=0.0.0.0:26411 \
  --rpclisten=127.0.0.1:26210 \
  --rpclisten-borsh=127.0.0.1:27210 \
  --connect=NODE_B_IP:26411 \
  --enable-unsynced-mining \
  --palw-enable-algo4
```

On node B, reciprocate with A's observed source IP:

```sh
./target/release/kaspad \
  --testnet --netsuffix=110 \
  --appdir=/absolute/path/palw-node-b \
  --archival --utxoindex \
  --listen=0.0.0.0:26411 \
  --rpclisten=127.0.0.1:26210 \
  --rpclisten-borsh=127.0.0.1:27210 \
  --connect=NODE_A_IP:26411 \
  --palw-enable-algo4
```

For more than two nodes, repeat `--connect=IP:P2P_PORT` for every approved peer needed by that node.
On a PALW preset, these entries have two effects:

1. address-manager discovery and DNS-seed outbound connections are disabled; only explicit permanent
   outbound peers are dialed;
2. the listener remains enabled, but rejects a remote **IP address** not present in the `--connect`
   list before the P2P handshake. The remote source port is intentionally not part of the allowlist.

This does not replace a firewall. NAT operators must allowlist the stable public/source IP seen by the
other node, not an internal address. Never expose gRPC or wRPC to the shared network.

The bootstrap supporting-chain miner submits to node A, so the fresh node A command above includes
`--enable-unsynced-mining`. The PALW testnet genesis has an intentionally historical timestamp; without
this flag RPC block submission is refused while the new network still has no current-timestamp tip.
After ordinary algo-3 blocks have advanced the sink into the current synchronization window, restart A
without the flag. Do not expose its mining RPC while the bootstrap exception is active.

For two local `devnet-111` processes, use `--devnet --netsuffix=111`, reciprocal loopback connects,
and non-colliding ports; for example A P2P/wRPC `26611/27610`, B P2P/wRPC `26612/27620`. Keep
`--archival`, `--utxoindex`, and `--palw-enable-algo4` on both, and use
`--enable-unsynced-mining` on the node receiving the initial supporting blocks.

Before registering PALW objects, confirm both nodes report network ID `testnet-110`, are synced to the
same selected chain, and are advancing via supporting blocks. A node without `--archival` refuses this
preset at startup. A node without `--connect` also refuses it.

## Bootstrap and fund the supporting chain

Generate a separate funding key for every provider identity. `keygen` creates the seed file with mode
0600 and prints its `funding_address`; the output file must not already exist:

```sh
./target/release/kaspa-pq-validator keygen \
  --network testnet-110 \
  --out /absolute/path/provider-a.seed

PROVIDER_A_FUNDING_ADDRESS='misakatest:replace-with-the-printed-funding-address'
```

Mine ordinary algo-3 supporting blocks against node A's **gRPC** port. The in-tree miner defaults to a
1,000 ms inter-block floor; keep that throttle explicit so the closed mesh has time to propagate each
block:

```sh
./target/release/misaminer \
  --pool 127.0.0.1:26210 \
  --network-id testnet-110 \
  --wallet "$PROVIDER_A_FUNDING_ADDRESS" \
  --worker bootstrap-provider-a \
  --blocks 1010 \
  --min-block-interval-ms 1000
```

`testnet-110` is a 10-BPS network whose coinbase maturity is 1,000 DAA (100 seconds at the configured
rate). With the conservative 1,000 ms miner throttle, 1,010 selected supporting blocks take about 17
minutes and leave the earliest rewards mature. More blocks may be required after rejected/side-chain
blocks. Query the address through node A's **wRPC Borsh** port:

```sh
./target/release/kaspa-pq-validator balance \
  --node-wrpc-borsh 127.0.0.1:27210 \
  --network testnet-110 \
  --address "$PROVIDER_A_FUNDING_ADDRESS"
```

Do not treat the displayed balance alone as proof that a particular coinbase is mature. Continue
mining until the address holds strictly more than the 10 MSK provider floor plus fees, the intended
funding rewards are at least 1,000 DAA old, and the exact provider-bond `palw-submit --dry-run` below
selects mature inputs successfully. Also require node B to reach the same selected tip before moving
on.

Repeat the key generation, mining, maturity wait, and balance/dry-run checks for provider B and every
auditor, substituting each role's own funding address and worker name. Do the same for a separately
keyed DNS validator when it needs its own stake funding. A provider bond cannot be sponsored from a
different provider's key: the payload owner public key must equal the `--validator-key` that signs and
funds the carrier.

## Bootstrap DNS finality and the PALW beacon

PALW activation needs a healthy DNS confirmation view and an epoch beacon. On `testnet-110`, one
active test-only DNS validator can meet the configured validator-count floor, but it must own a real
stake bond of at least 10 MSK and keep submitting both attestations and beacon commit/reveal carriers.
Use a dedicated 0600 key already funded and matured by the preceding section:

```sh
./target/release/kaspa-pq-validator bond \
  --node-wrpc-borsh 127.0.0.1:27210 \
  --network testnet-110 \
  --validator-key /absolute/path/dns-validator.seed \
  --amount 10MSK \
  --activation-daa-score 0 \
  --unbonding-period-blocks 12096300
```

The explicit `12096300` value is the testnet network floor (14 days at 10 BPS plus the 300-block
reorg horizon). The CLI's generic default is 700; do not rely on the registry silently clamping a
shorter declaration when recording operator intent. Save the printed `bond_outpoint`, mine supporting
blocks until the transaction is selected, then query it:

```sh
./target/release/misaminer \
  --pool 127.0.0.1:26210 \
  --network-id testnet-110 \
  --wallet "$DNS_VALIDATOR_FUNDING_ADDRESS" \
  --worker include-dns-bond \
  --blocks 2 \
  --min-block-interval-ms 1000

./target/release/kaspa-pq-validator status \
  --node-wrpc-borsh 127.0.0.1:27210 \
  --network testnet-110 \
  --stake-bond "$DNS_STAKE_BOND_OUTPOINT"
```

Do not continue until both nodes have the same selected tip and report this exact bond with
`bond_status: Active`, the expected amount, and the expected validator identity. Then stop node A
cleanly and restart it with the same mesh/RPC flags shown above, without the temporary
`--enable-unsynced-mining`, and add:

```text
--enable-validator
--enable-beacon
--validator-mode=active
--validator-key=/absolute/path/dns-validator.seed
--stake-bond=<dns-stake-txid>:0
```

The in-process service is the minimum deployment here because it drives both DNS attestations and the
PALW beacon. It creates `validator-state.json` (equivocation guard) and `beacon-secret.json`
(unrevealed commit openings) beneath the node A `testnet-110` app directory with owner-only
permissions. Preserve and back up both files with the validator key; never copy the same identity to a
second live host, run the standalone validator concurrently for that identity, or delete/reset these
files between restarts. Losing the former risks a conflicting signature; losing the latter can leave
committed stake in the beacon denominator without a reveal and stall the epoch.

For a multi-validator experiment, repeat key funding, `bond`, status verification, and the complete
durable validator/beacon setup for each distinct identity. Each identity needs its own funding UTXOs,
stake outpoint, state files, and node process. Keep ordinary algo-3 mining running so attestation and
beacon carriers enter separate supporting blocks; require both nodes' DNS status to become healthy
before lifecycle activation.

## Register provider collateral

The funding key needs a mature unlocked UTXO strictly larger than the 10 MSK provider floor plus the
fee. The commitment values below are 128-character hexadecimal `Hash64` values and must describe the
actual operator group, supported runtime class, shape, and reward-key set. Do not substitute arbitrary
values in a meaningful test. The output file must not already exist.

```sh
./target/release/kaspa-pq-validator palw-payload provider-bond \
  --network testnet-110 \
  --validator-key /absolute/path/provider-a.seed \
  --operator-group-id "$PROVIDER_A_GROUP_HASH64" \
  --runtime-class "$RUNTIME_CLASS_HASH64" \
  --capacity "${SHAPE_ID}=1" \
  --reward-key-root "$PROVIDER_A_REWARD_ROOT_HASH64" \
  --amount 10MSK \
  --unbond-delay-epochs 6 \
  --out /absolute/path/provider-a-bond.borsh
```

Preflight the exact carrier against node A without submitting it:

```sh
./target/release/kaspa-pq-validator palw-submit \
  --node-wrpc-borsh 127.0.0.1:27210 \
  --network testnet-110 \
  --validator-key /absolute/path/provider-a.seed \
  --kind provider-bond \
  --payload-file /absolute/path/provider-a-bond.borsh \
  --exclude-funding-outpoint "$DNS_STAKE_BOND_OUTPOINT" \
  --dry-run
```

Then submit the same payload without `--dry-run`:

```sh
./target/release/kaspa-pq-validator palw-submit \
  --node-wrpc-borsh 127.0.0.1:27210 \
  --network testnet-110 \
  --validator-key /absolute/path/provider-a.seed \
  --kind provider-bond \
  --payload-file /absolute/path/provider-a-bond.borsh \
  --exclude-funding-outpoint "$DNS_STAKE_BOND_OUTPOINT"
```

Record `locked_provider_bond_outpoint` from the output. Output 0 is collateral; the following output is
change. The command rejects a provider payload unless its owner public key equals `--validator-key`,
so an opaque payload cannot redirect the payer's coins into somebody else's bond. On every later
funded command, repeat `--exclude-funding-outpoint` for **all** DNS and PALW bonds controlled by that
funding key:

```text
--exclude-funding-outpoint <dns-stake-txid>:<index>
--exclude-funding-outpoint <palw-provider-txid>:0
```

Repeat generation and submission for provider B and every auditor, using their own keys and truthful
operator-group commitments. The command waits for the carrier's change outpoint to appear in the
selected-chain UTXO view by default; do not advance merely because a transaction entered the mempool.
Its output is deliberately named `carrier_selected_chain_change_outpoint`: this proves current
selected-chain inclusion, not finality and not that a contextual PALW mutation was applied.

Confirm the contextual mutation on both nodes with the bounded sink-bound probe (this queries exactly
one outpoint and never enumerates the provider registry):

```sh
./target/release/kaspa-pq-validator palw-status \
  --node-wrpc-borsh 127.0.0.1:27210 \
  --network testnet-110 \
  --provider-bond "$PALW_PROVIDER_BOND_OUTPOINT"
```

Require `provider.in_registry: true`, an appropriate effective status, and exact equality with the
payload for owner, group, amount, `runtime_classes`, `capacity_by_shape`, `reward_key_root`, and
`unbond_delay_epochs`. Any mismatch is a stop condition. Record `sink` and `sink_daa_score`; query the
peer at the same selected tip before comparing.

## Submit lifecycle carriers in separate blocks

`palw-submit` handles one already-built canonical Borsh payload. Only provider-bond payload generation
has a high-level CLI in this flow; manifest, leaf-chunk, and certificate payloads must currently come
from the constructors in `misaka-palw-miner` or a reviewed operator tool built on them.

The intended order is below, keeping the default wait after every transaction:

1. all required provider bonds;
2. one batch manifest;
3. each leaf chunk;
4. the batch certificate;
5. only then start algo-4 mining for an accepted leaf.

The common submission shape is:

```sh
./target/release/kaspa-pq-validator palw-submit \
  --node-wrpc-borsh 127.0.0.1:27210 \
  --network testnet-110 \
  --validator-key /absolute/path/funding.seed \
  --kind batch-manifest \
  --payload-file /absolute/path/manifest.borsh \
  --exclude-funding-outpoint "$DNS_STAKE_BOND_OUTPOINT" \
  --exclude-funding-outpoint "$PALW_PROVIDER_BOND_OUTPOINT"
```

Change `--kind` and `--payload-file` for `leaf-chunk` and `certificate`. For a leaf chunk, also supply
the authority material used when the leaves were constructed:

```text
--ticket-authority-key /absolute/path/ticket-authority.seed
--ticket-secret-file /absolute/path/ticket-secrets.json
```

Do not use `--unsafe-skip-ticket-secret-check` for an owned leaf. The check proves that each persisted
raw nullifier opens the registered commitment; losing this file makes the registered ticket
unmineable. It must already exist as a regular, non-symlink, owner-only file (mode 0600 on Unix); back
it up securely. Do not use `--no-wait`: a dependent object included in the same block as its
prerequisite is past-relative and can be ignored by PALW state.

Manifest submission additionally requires `registration_epoch` to equal the node's current PALW epoch
and, by default, at least 20 DAA of epoch headroom. If preflight refuses it, regenerate the manifest for
the current epoch; do not weaken the check. Certificate quorum uses the entire re-derived selected
slate as its denominator, so selected auditors that withhold their vote still count against 2/3.

After each manifest/leaf/certificate carrier reaches the selected-chain UTXO view, first advance the
supporting chain until both nodes have selected a child of the carrier block, then query both nodes:

```sh
./target/release/kaspa-pq-validator palw-status \
  --node-wrpc-borsh 127.0.0.1:27210 \
  --network testnet-110 \
  --batch-id "$PALW_BATCH_ID"
```

The extra supporting child is required: the past-relative `view(sink)` deliberately excludes the
sink's own body, so a carrier first appears in the view of a descendant. The probe returns that
fork-local carried lifecycle at a named `sink`, chunk presence as `present/declared`, leaf-blob
presence as a bounded count (never leaf contents), and both the carried certificate hash and whether
that content blob resolves. Compare peers only once their `sink` values match. Unlike the provider
result, these batch fields are not selected-chain acceptance proof: the view folds raw blue-mergeset
carriers before acceptance filtering and the bytes are read from global content stores. They are a
bounded diagnostic of the surfaces ticket resolution currently reads.

Check the fields appropriate to the stage: after the manifest require `batch.in_sink_view: true` and
`batch.manifest_present: true`; after each leaf chunk require the expected increase in
`batch.chunks`/`batch.leaf_blobs`; after the certificate require the expected
`batch.certificate_hash` and `batch.certificate_blob_present: true`. A missing stage-specific effect is
a stop condition even if the carrier transaction itself is visible. No batch presence field is proof
that its carrier was accepted on this fork. In particular, certificate blobs are globally
content-addressed, so the unresolved fork-scoped attestation-provenance blocker below applies even
when `certificate_blob_present: true`. Preserve both nodes' selected-chain/acceptance evidence and
internal audit facts for any claimed lifecycle run.

After recording separate selected-chain acceptance evidence and seeing the expected certificate/leaf
diagnostics, keep advancing the supporting chain and the beacon until `palw-status` reports
`batch.status: active`. Only then restart the assigned mining node with its common flags plus:

```text
--palw-mine
--palw-mine-address=<network-correct-ML-DSA-87-P2PKH-address>
--palw-ticket-authority-key-file=/absolute/path/ticket-authority.seed
--palw-ticket-secret-file=/absolute/path/ticket-secrets.json
--palw-leaf=<128-hex-batch-id>:<leaf-index>
```

At least one active DNS validator should also run:

```text
--enable-validator
--enable-beacon
--validator-mode=active
--validator-key=/absolute/path/dns-validator.seed
--stake-bond=<dns-stake-txid>:<index>
```

Keep `--palw-enable-algo4` on **every** node, not only the miner. Never toggle it on a subset of a live
mesh.

## Stop conditions and known blockers

Stop the test and preserve both data directories/logs if tips, accepted transaction sets, overlay
facts, or minted-block verdicts diverge. Do not assign value or open the firewall after a successful
wiring run. The following blockers remain:

- receipt DA and real auditor execution are absent from the operational path: produced leaves currently
  use a zero `receipt_da_root`, and no service fetches/replays receipt data before signing a verdict;
- PALW overlay blobs are written outside the virtual UTXO `WriteBatch`, so they are not crash-atomic;
  certificate provenance also remains globally readable across candidate forks instead of being
  fork-scoped and re-attested;
- algo-4 header anti-spam/rate-cost enforcement and the required performance/soak/calibration
  measurements are not complete;
- `palw_compute_work_scale` is intentionally `0`, the leaf-bond floor remains `0`, and long-horizon
  duplicate-work, dispute/slashing, and backend cross-machine determinism gates are not closed;
- the current CLI does not generate or submit the owner-signed PALW provider-unbond request and does
  not construct the post-delay sweep of collateral output 0. The consensus path recognizes delayed
  owner-authorized exit, but recovery still requires reviewed external tooling; treat provider
  collateral as unrecoverable for this disposable no-value run rather than assuming this runbook can
  reclaim it;
- pruning-point snapshots do not transport the selected-chain PALW provider registry. The node now
  refuses P2P pruning-state import before mutating local state, so late joins and recovery by
  wiping/re-syncing are intentionally unavailable; coordinated genesis start or a matching full
  data-directory snapshot is required;
- the current operator CLI only generates provider-bond artifacts; manifest/leaf/audit/certificate
  artifact generation is not shipped, so an external operator still cannot construct the full
  lifecycle from this runbook alone (the bounded `palw-status` probe can inspect the carried
  view/blob surfaces of reviewed artifacts once supplied, but cannot prove selected-chain acceptance).

These are activation blockers, not warnings to waive. This runbook currently demonstrates
closed-network transport and staged carrier construction/inclusion. Full lifecycle admission and
weightless algo-4 minting still require internal developer instrumentation and missing artifact tools.
