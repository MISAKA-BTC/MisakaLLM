# PALW shared closed testnet — Phase-0 wiring harness

A **portable, idempotent** bash harness that wires a **closed two-node PALW
testnet** end-to-end: supporting chain → node sync → DNS/beacon validator →
provider registry (A / B / auditor-C) → batch lifecycle → (optionally) the
algo-4 miner, with both-node consensus assertions.

This directory's **shared foundation** is two files, delivered and tested:

| File | Role |
|---|---|
| `env.example` | Every tunable as a documented env var, devnet-111 defaults, no hardcoded machine paths. Copy to `env.local`. |
| `common.sh` | Sourced by every stage script. `set -euo pipefail`; `load_env`; logging; bin paths; status wrappers; readiness gates; state persistence; PID/cleanup helpers. Idempotent + fail-closed. |

The per-stage scripts (below) source `common.sh`, call `load_env`, and each do
one job. `run-all.sh` chains them in order.

> **Honesty first (read §"Scope & limits").** This is **Phase-0 wiring only**.
> `TICKET_MODE=skip` (default) reaches `batch.status=active` but **cannot mint**
> an algo-4 block. `TICKET_MODE=mock` mints a **wiring-only, non-inference**
> block and needs a helper that is **specified, not shipped**. **Real inference
> needs the provider GPU tool**, which is out of scope here.

---

## Quick start (single host, two `kaspad` processes)

```sh
cd scripts/palw-shared-testnet
cp env.example env.local          # edit env.local if needed (git-ignored)

./run-all.sh                      # preflight → nodes → miner → DNS → providers
                                  # → lifecycle → verify (TICKET_MODE=skip)

./stop.sh                         # SIGTERM→SIGKILL every supervised process
```

Override any knob inline (environment wins over `env.local`):

```sh
NETWORK=testnet-110 NETSUFFIX=110 TICKET_MODE=mock ./run-all.sh
```

Point at a specific config file instead of `env.local`:

```sh
PALW_ENV_FILE=/path/to/env ./run-all.sh
```

---

## The shared foundation

### `load_env` (call once, right after sourcing `common.sh`)

```sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/common.sh"
load_env
```

`load_env`:

1. sources the config file (`$PALW_ENV_FILE` → `env.local` → `env.example`);
2. derives `REPO_ROOT` if unset (two levels up from this dir) and `realpath`s it;
3. creates `PALW_DATA_ROOT` + `node-a node-b logs keys artifacts` at mode `0700`;
4. overlays the generated `artifacts/state.env` (discovered outpoints/addresses);
5. validates every required var is non-empty (**fail-closed**);
6. binds `KASPAD` / `VAL` / `MINER` and verifies each is executable.

### What `common.sh` gives your script

- **Logging:** `log` / `warn` / `die` (stderr), `require_cmd`.
- **Bin paths:** `$KASPAD`, `$VAL` (`kaspa-pq-validator`), `$MINER` (`misaminer`).
- **Node addressing:** `node_wrpc`/`node_grpc`/`node_p2p_addr`/`node_appdir`/`node_log` `<a|b>`.
- **Status wrappers:** `node_status`, `palw_provider_status`, `palw_batch_status`.
- **Readiness gates** (loop to a deadline, return non-zero on timeout — always
  check the code): `wait_rpc_up`, `wait_peer_connected`, `wait_node_synced`,
  `wait_same_sink`, `wait_dns_confirmed`, `wait_batch_status`, `wait_inclusion`.
- **Epoch:** `current_epoch` (`sink_daa / 100`).
- **Hex:** `h64`, `zero128`, `rand_hex`, `reward_spk_p2pkh_mldsa`.
- **Discovered state:** `state_set` / `state_get` (idempotent `artifacts/state.env`).
- **Process lifecycle:** `write_pid` / `read_pid` / `is_running` (survives PID
  reuse) / `stop_pid` (SIGTERM→timeout→SIGKILL) / `register_cleanup` (EXIT/INT/TERM).

Every helper is idempotent and fail-closed; none echo seeds or nullifiers.

`wait_dns_confirmed` gates on **`dns_confirmed:true` + an advancing `dns_anchor`**
and deliberately **ignores `dns_health`** — that field is liveness-only and
flickers (e.g. `DegradedCertificateCensored`) on fresh nets because its trailing
window averages empty pre-validator epochs. It is **not** a consensus gate.

---

## Stage scripts

Run individually (each sources `common.sh` + `load_env`) or via `run-all.sh`.

| Script | Does |
|---|---|
| `preflight.sh` | Env + toolchain check; hash-compare the three release binaries. |
| `build-and-hash.sh` | `cargo build --release` and record binary hashes. |
| `node-a.sh` / `node-b.sh` | Start each `kaspad` (`--palw-enable-algo4` on **both**), gate `wait_rpc_up` + `wait_peer_connected`. |
| `restart-a-synced.sh` | STN-006: once synced, restart node A **without** `--enable-unsynced-mining`, into validator mode; re-verify same-sink. |
| `supporting-miner.sh` | Continuous algo-3 `misaminer` (inclusion needs a live miner). |
| `bootstrap-funds.sh` | Wait coinbase maturity (1000 DAA) for the funding keys. |
| `dns-validator.sh` | `bond` → restart node A with validator/beacon → `wait_dns_confirmed`. |
| `register-providers.sh` | Provider A / B / auditor-C `provider-bond` (distinct operator groups). |
| `create-lifecycle.sh` | Build manifest + leaf-chunk(s) **offline** (miner paused, no DAA drift). |
| `submit-lifecycle.sh` | Submit manifest → chunk → audit-facts → vote → certificate; `wait_inclusion` a child after each carrier. |
| `start-palw-miner.sh` | Node A `--palw-mine` (+ authority/secret/leaf). **Only reachable with `TICKET_MODE=mock`.** |
| `verify-consensus.sh` | Both-node tip / registry / batch / blockhash parity. |
| `verify-coinbase.sh` | A/B/Inclusion/Validator sompi split (or `N/A` in skip mode — no block minted). |
| `collect-artifacts.sh` | Redacted evidence bundle (never copies `*.seed`). |
| `stop.sh` | `stop_pid` every supervised process. |

---

## Environment variables

Full list with defaults and comments is in **`env.example`**. The load-bearing ones:

| Var | Default | Meaning |
|---|---|---|
| `REPO_ROOT` | *auto-derived* | Checkout with `target/release/{kaspad,kaspa-pq-validator,misaminer}`. Env-overridable. |
| `PALW_DATA_ROOT` | `$HOME/.palw-testnet/devnet-111` | Runtime state root (appdirs/logs/keys/artifacts), 0700. |
| `NETWORK` / `NETWORK_BASE` / `NETSUFFIX` | `devnet-111` / `devnet` / `111` | Full node id / bare base name (for `keygen`) / suffix. |
| `NODE_A_HOST` / `NODE_B_HOST` | `127.0.0.1` | P2P-reachable host for `--connect` (see two-host below). |
| `A_*_PORT` / `B_*_PORT` | 26611/26610/27610, 26612/26620/27620 | P2P / gRPC / wRPC-borsh ports. RPC binds `127.0.0.1` only. |
| `MINER_INTERVAL_MS` | `1000` | `misaminer --min-block-interval-ms`. |
| `LEAF_COUNT` | `1` | Leaves in the batch manifest. |
| `TICKET_MODE` | `skip` | `skip` \| `mock` (see §Scope & limits). |
| `*_AMOUNT` | `10MSK` | Bond amounts (provider floor 10 MSK). |
| Discovered slots | *(blank)* | `DNS_BOND`, `PROV_A_BOND`, `PROV_B_BOND`, `AUD_C_BOND`, `PALW_BATCH_ID`, `*_ADDR` — filled into `artifacts/state.env` by `state_set`. |

### Two-host mode

Set `NODE_A_HOST` / `NODE_B_HOST` to each host's routable/Tailscale address and
run the harness on each host. RPC stays on `127.0.0.1` (loopback only); P2P uses
those hosts for the pre-handshake `--connect` allowlist. On a single host, node
B keeps disjoint ports (the devnet defaults already do). **Validator/beacon
state (`validator-state.json`, `beacon-secret.json`) is per-node and must never
be copied to a second live host.**

---

## Scope & limits (honest)

**What this harness reaches (Phase 0, closed no-value wiring):**

- two `kaspad` nodes with `--palw-enable-algo4` on **all** nodes (identical, never
  a subset), reciprocal P2P, block production, both-node sync + same sink;
- DNS stake bond → in-process validator + beacon → `dns_confirmed:true` with an
  advancing `dns_anchor` (epochs advancing);
- provider A, provider B, and an **independent** auditor C (distinct operator
  groups) active in the registry;
- batch manifest → leaf-chunk → audit-facts → auditor vote → certificate, ending
  at **`batch.status=active`**;
- both-node tip / registry / batch parity assertions.

**What it does NOT do — do not overstate:**

- **`TICKET_MODE=skip` (default) cannot mint an algo-4 block.** The leaf-chunk is
  registered via `palw-submit --unsafe-skip-ticket-secret-check` (no ticket).
  This reaches `batch.status=active`, but a block with that leaf can **never** be
  mined. No coinbase, no minted block. This is the honest end state without a
  ticket.
- **`TICKET_MODE=mock` mints a WIRING-ONLY, non-inference block.** It needs a
  ticket whose raw nullifier opens the leaf's `ticket_nullifier_commitment` and a
  populated `TicketSecretStore`. **No standalone CLI populates that store** — the
  provider inference tool does. A ~40-line `mock-ticket` helper (see
  `mock-ticket/README.md`) closes this **for wiring only**; the leaf is a **mock,
  explicitly non-inference** leaf. That helper is **specified, not shipped** — the
  one honest TODO between "batch active" and "minted block" without a GPU.
- **Real inference requires the provider GPU tool** (`palw-providerd` + model),
  which is out of scope here (Phase 1). This harness never invokes the seeded
  test-only `palw_demo` path.
- **A single machine cannot prove real network partition / NAT / peer loss** — that
  needs two hosts. `NODE_A_HOST`/`NODE_B_HOST` enable it; the harness does not
  pretend a one-box run is a real network test.
- The algo-4 chain has **fork-choice weight 0** here: the harness proves algo-4
  block validity, propagation, and reward *plumbing* — **not** PALW chain security.

See `PHASE0-status.md` for the full audit-finding disposition and the Phase 1–4
roadmap.

---

## Files, state & safety

- **Config:** `env.example` (template) → `env.local` (yours, git-ignored).
- **State:** `$PALW_DATA_ROOT/artifacts/state.env` (discovered outpoints/addresses,
  written by `state_set`; sourced back by `load_env`). Idempotent.
- **Logs:** `$PALW_DATA_ROOT/logs/node-{a,b}.log`.
- **PIDs:** `$PALW_DATA_ROOT/<name>.pid` (pid + start-time + argv; `is_running`
  verifies all three to survive PID reuse).
- **Keys:** `$PALW_DATA_ROOT/keys/*` at `0600`. **Never** copied between hosts;
  never printed; never bundled by `collect-artifacts.sh`.
- RPC (gRPC + wRPC-borsh) binds loopback only. P2P binds `0.0.0.0` but the PALW
  preset rejects any IP not in `--connect` before the handshake.

Targets bash 3.2 (stock macOS) and Linux; BSD + GNU coreutils. Validated live
against two running devnet-111 nodes.
