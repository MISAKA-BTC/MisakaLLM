# `mock-ticket` — the one unshipped no-GPU piece (WIRING ONLY, NON-INFERENCE)

> **STATUS: SHIPPED — authored, built, and verified** (2026-07-24). The crate in
> this directory is a workspace member; `cargo build --release -p mock-ticket`
> produces `$REPO_ROOT/target/release/mock-ticket`. Its `ticket_nullifier_commitment`
> was cross-checked against an independent keyed-BLAKE2b-512 implementation (exact
> match), it is deterministic, and `store-add` writes an authority-bound
> `TicketSecretStore` that **refuses a foreign authority**. This is the piece that
> lets `TICKET_MODE=mock` mint a **wiring-only, non-inference** algo-4 block on a
> no-GPU box. **`TICKET_MODE=skip` (the default) does not need it** and reaches
> `batch.status=active` without it. The one step still unproven end-to-end is the
> full live `TICKET_MODE=mock` mint on a running mesh (needs the 2-node harness up);
> the ticket **crypto** it emits is verified.

`mock-ticket` closes the gap between **"batch active"** and **"minted block"**
on a machine with **no GPU and no provider daemon** — and it does so for
**wiring only**. The leaf it enables is a **mock, explicitly non-inference**
leaf. `mock-ticket` runs **no inference of any kind**.

This is **deliberately NOT** the seeded, test-only `palw_demo` shortcut. The leaf
is registered through the **real on-chain lifecycle carriers** (batch-manifest →
leaf-chunk → audit-facts → vote → certificate), so **both** nodes obtain it over
P2P. **Only the ticket secret is mock**, and it is labeled as such everywhere.

---

## 1. Why a ticket is needed at all

A PALW leaf publishes a **commitment** to its ticket nullifier, never the raw
nullifier:

```
leaf.ticket_nullifier_commitment = blake2b_512_keyed(
    "misaka-palw-ticket-nf-commit-v1",   // PALW_TICKET_NULLIFIER_COMMIT_DOMAIN
    raw_nullifier[64 bytes])
```

To **mint** the algo-4 block that carries the leaf, the miner must **disclose**
the raw 64-byte nullifier so consensus can check
`ticket_nullifier_commitment(disclosed) == leaf.ticket_nullifier_commitment`
(the canonical nonce is also pinned to it: `nonce == low64(nullifier)`). The
node reads that raw nullifier from a **`TicketSecretStore`** JSON keyed by
`(batch_id, leaf_index)`.

**No standalone CLI populates that store** — in production the **provider
inference tool** writes it as a by-product of doing the work. On a no-GPU box
there is no provider tool, so the store is never written, so **no block can ever
be minted** — even though the batch is `active`. `mock-ticket` is the smallest
honest thing that writes that one store entry **without pretending to compute**.

`TICKET_MODE=skip` sidesteps this entirely: it registers the leaf-chunk with
`palw-submit --unsafe-skip-ticket-secret-check` (no ticket), reaching
`batch.status=active` with **no mintable block**. That is the honest skip-path
end state. `mock-ticket` is only for operators who want the extra wiring step of
a real minted-but-non-inference block.

---

## 2. What it MUST do (single responsibility)

Given

- a **ticket-authority ML-DSA-87 seed** (the same seed the node reads via
  `--palw-ticket-authority-key-file`, i.e. `$TICKET_AUTHORITY_KEY`),
- a **raw 64-byte nullifier** (128 hex), read from a **file, never argv**
  (it is a secret), and
- a **`(batch_id, leaf_index)`** pair,

it MUST:

1. derive the authority ML-DSA-87 **verification key** from the seed and compute
   `authority_pk_hash = blake2b_512_keyed("misaka-palw-authorization-v1", vk)`;
2. compute `ticket_nullifier_commitment = blake2b_512_keyed("misaka-palw-ticket-nf-commit-v1", nullifier)`;
3. **print** both (to stdout — these are *public*, they end up in the on-chain
   leaf, so printing them is safe); and
4. in **record** mode, write the raw nullifier into an **authority-bound**
   `TicketSecretStore` JSON keyed by `(batch_id, leaf_index)`, mode `0600`.

It MUST **never** print or log the raw nullifier or the seed.

### It deliberately does NOT

- run inference, load a model, or contact any provider/GPU;
- fabricate, grind, or "win" eligibility — it only *stores* a nullifier the
  operator supplied;
- touch consensus, the mempool, or any network socket;
- invoke the seeded `palw_demo` path.

---

## 3. Reuse the real crypto — do NOT reimplement it

Every value above is already defined in the workspace. The helper MUST `use`
these, not hand-roll them — a hand-rolled commitment or store-key that differs by
one byte silently produces a **dead ticket** (the leaf stays on chain, eligible,
and mineable by no one).

| Concern | Reuse exactly | Location |
|---|---|---|
| Nullifier commitment | `palw::ticket_nullifier_commitment(&Hash64) -> Hash64` | `consensus/core/src/palw.rs:823` |
| …its domain | `PALW_TICKET_NULLIFIER_COMMIT_DOMAIN = b"misaka-palw-ticket-nf-commit-v1"` | `consensus/core/src/palw.rs:89` |
| Authority pk-hash | `blake2b_512_keyed(PALW_AUTHORIZATION_DOMAIN, vk)` (matches `binds_leaf_authority`) | `consensus/core/src/palw.rs:60`, `:2403` |
| Seed → ML-DSA-87 vk | `ValidatorKey::from_seed([u8; VALIDATOR_SEED_LEN]).public_key()` (`VALIDATOR_SEED_LEN = 32`) | `kaspa-pq-validator-core/src/lib.rs:42`, `:181`, `:190` |
| Secret store | `TicketSecretStore::load_or_empty(path, authority_pk_hash)` + `record_and_flush(batch_id, leaf_index, nullifier)` | `kaspa-pq-validator-core/src/lib.rs:1139`, `:1150`, `:1191` |
| Store key format | `ticket_secret_key = format!("{batch_id:?}:{leaf_index}")` — **used internally by `record_and_flush`; never format the key yourself** | `kaspa-pq-validator-core/src/lib.rs:1117` |

Using `record_and_flush` also gives you, for free and identically to the node:
authority binding (a foreign-authority file is **refused**), `0600` creation,
atomic temp+fsync+rename, and the **C-1 immutability guard** (refuses to
overwrite an existing entry with a *different* value). Do not reimplement any of
that.

### TicketSecretStore JSON shape (from `TicketSecretFile`, `lib.rs:1108`)

```json
{
  "version": 1,
  "authority_pk_hash": "<128 hex>",
  "secrets": {
    "<batch_id-debug-hex>:<leaf_index>": "<128 hex raw nullifier>"
  }
}
```

`version` is `TICKET_SECRET_FILE_VERSION = 1` (`lib.rs:1106`). This is exactly
what the node reads via `--palw-ticket-secret-file`, so the file the helper
writes and the file the miner loads MUST be the same path (`$TICKET_SECRET_FILE`)
and the same authority (`$TICKET_AUTHORITY_KEY`).

---

## 4. CLI (as shipped)

Secrets (seed, nullifier) go in via **files**, never argv — argv is
world-readable through `ps`. The helper has **two subcommands**, because
`batch_id` is content-derived and not known at leaf-authoring time. `--network`
is accepted for symmetry but does not affect any output (the ticket domains are
network-independent constants).

```
# AUTHOR-TIME (batch_id still 0): compute + print the two public commitments.
# Used to fill the UNBOUND leaf BEFORE the manifest exists. Touches no store.
mock-ticket commit \
  --authority-key  <path>    # ML-DSA-87 seed (== node's --palw-ticket-authority-key-file)
  --nullifier-file <path>    # 128 hex chars (64 bytes); read, NEVER printed
  [--network <net>]
# stdout (parsed by common.sh `_kv`):
#   ticket_nullifier_commitment: <128hex>
#   ticket_authority_pk_hash:    <128hex>

# RECORD (real batch_id known): write the nullifier into the authority-bound store.
# Used AFTER batch-manifest binds the batch_id.
mock-ticket store-add \
  --authority-key  <path>
  --secret-file    <path>    # TicketSecretStore JSON to create/update (0600, authority-bound)
  --batch-id       <128hex>  # real content-derived batch_id from batch-manifest
  --leaf-index     <u32>
  --nullifier-file <path>
  [--network <net>]
```

Both `ticket_nullifier_commitment` and `ticket_authority_pk_hash` are functions
of the nullifier/seed **only** (independent of `batch_id`), so `commit` needs no
batch id. `store-add` re-derives the authority pk-hash to bind the store, then
delegates the write to `TicketSecretStore::record_and_flush` (§3).

**Fail-closed behaviors (all exit non-zero, actionable message):**

- `--nullifier-file` not exactly 128 hex (64 bytes) → refuse.
- seed / nullifier / store file group- or world-readable → refuse (matches the
  store's `require_private_regular_file`).
- record mode with `--batch-id` = the all-zero sentinel → refuse: *"won't key a
  ticket secret under the all-zero batch_id; pass the real content-derived
  batch_id from batch-manifest."*
- store belongs to a different authority, or an existing `(batch_id, leaf_index)`
  entry holds a **different** nullifier → refuse (inherited from
  `load_or_empty` / `record_and_flush`).

**Idempotent:** re-running record mode with the **same** nullifier is a no-op
flush (the C-1 guard only rejects a *changed* value); print-only is pure.

### Build (this is the piece you must author first)

Author the crate under this directory as a workspace member, then:

```sh
cargo build --release -p mock-ticket   # produces $REPO_ROOT/target/release/mock-ticket
```

Because it depends on `kaspa-consensus-core` and `kaspa-pq-validator-core`, it
must be a workspace member so it can `use` the real functions in §3.

---

## 5. How `create-lifecycle.sh` invokes it

Integration lives in the harness's own script and obeys the shared rules
(`set -euo pipefail`; sources `common.sh`; idempotent; fail-closed;
`register_cleanup`; honest comments). It calls **`common.sh` helpers only** —
nothing here is reimplemented. This is the `TICKET_MODE=mock` branch of
`create-lifecycle.sh`:

```sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
. "$SCRIPT_DIR/common.sh"
load_env

if [ "$TICKET_MODE" = mock ]; then
    # HONEST: this authors a MOCK, explicitly NON-INFERENCE leaf that rides the
    # REAL on-chain carriers; only the ticket SECRET is mock. This is NOT the
    # seeded palw_demo path, and mock-ticket runs NO inference.

    # The helper is the ONE unshipped piece. Fail closed with the build recipe.
    MOCK_TICKET="$REPO_ROOT/target/release/mock-ticket"
    [ -x "$MOCK_TICKET" ] || die "TICKET_MODE=mock needs the mock-ticket helper (not shipped): author it under scripts/palw-shared-testnet/mock-ticket/ and 'cargo build --release -p mock-ticket' (see that README). Use TICKET_MODE=skip to reach batch.status=active without it."

    # Authority seed == the node's --palw-ticket-authority-key-file.
    [ -s "$TICKET_AUTHORITY_KEY" ] || die "ticket authority seed missing: $TICKET_AUTHORITY_KEY (create it once at 0600; it must equal the node's --palw-ticket-authority-key-file)"

    # Raw 64-byte nullifier. IDEMPOTENT: never regenerate an existing one — the
    # leaf's on-chain commitment opens ONLY to this value; a fresh nullifier
    # would orphan the already-registered leaf into a dead ticket.
    NF_FILE="$PALW_DATA_ROOT/keys/ticket-nullifier-0.hex"
    if [ ! -s "$NF_FILE" ]; then
        ( umask 077; rand_hex 64 > "$NF_FILE" )   # 128 hex = 64 bytes
        chmod 0600 "$NF_FILE" 2>/dev/null || true
        log "generated ticket nullifier -> $NF_FILE (0600, never printed)"
    else
        log "reusing existing ticket nullifier $NF_FILE (idempotent; not regenerated)"
    fi

    # ---- AUTHOR-TIME (batch_id still 0): 'commit' -> fill the UNBOUND leaf ----
    authored="$("$MOCK_TICKET" commit --authority-key "$TICKET_AUTHORITY_KEY" --nullifier-file "$NF_FILE")" \
        || die "mock-ticket commit failed (authority seed $TICKET_AUTHORITY_KEY)"
    nf_commit="$(printf '%s\n' "$authored" | _kv ticket_nullifier_commitment)"
    pk_hash="$(  printf '%s\n' "$authored" | _kv ticket_authority_pk_hash)"
    { [ "${#nf_commit}" -eq 128 ] && [ "${#pk_hash}" -eq 128 ]; } || die "mock-ticket did not return 128-hex commitment/pk_hash"
    state_set TICKET_NF_COMMITMENT     "$nf_commit"   # -> leaf.ticket_nullifier_commitment
    state_set TICKET_AUTHORITY_PK_HASH "$pk_hash"     # -> leaf.ticket_authority_pk_hash
    # ... author leaf-set.json with these two fields, batch_id=zero128, labeled a
    #     TICKET-MOCK / NON-INFERENCE leaf ...
fi

# ... existing skip-path code: build the manifest OFFLINE (miner paused, no DAA
#     drift), state_set PALW_BATCH_ID + write restamped leaves.batch.json ...

if [ "$TICKET_MODE" = mock ]; then
    # ---- RECORD (real batch_id now known): write the authority-bound store ----
    batch_id="$(state_get PALW_BATCH_ID)"
    case "$batch_id" in ''|*[!0-9a-f]*) die "PALW_BATCH_ID unset or non-128hex after batch-manifest";; esac
    [ "${#batch_id}" -eq 128 ] || die "PALW_BATCH_ID is not 128 hex: '$batch_id'"
    [ "$batch_id" != "$(zero128)" ] || die "PALW_BATCH_ID is the all-zero sentinel; batch-manifest did not bind the batch"

    # Any half-written store on failure is the store's own temp file (atomic
    # rename); still, drop a stray tmp if the helper is killed mid-flush.
    register_cleanup 'rm -f "'"$TICKET_SECRET_FILE"'.json.tmp" 2>/dev/null || true'

    # record_and_flush is idempotent (identical value = no-op; different = refuse).
    "$MOCK_TICKET" store-add \
        --authority-key  "$TICKET_AUTHORITY_KEY" \
        --secret-file    "$TICKET_SECRET_FILE" \
        --batch-id       "$batch_id" \
        --leaf-index     0 \
        --nullifier-file "$NF_FILE" >/dev/null \
        || die "mock-ticket store-add failed for (batch $batch_id, leaf 0); store $TICKET_SECRET_FILE"
    log "ticket secret recorded for (batch $batch_id, leaf 0) in $TICKET_SECRET_FILE (0600, authority-bound)"
fi
```

The `start-palw-miner.sh` stage then starts node A with
`--palw-ticket-authority-key-file "$TICKET_AUTHORITY_KEY"`,
`--palw-ticket-secret-file "$TICKET_SECRET_FILE"`, and
`--palw-leaf "$batch_id:0"` — the store written above is exactly what it loads.

---

## 6. Author + build + verify checklist

Honest TODO — the crypto is done; the live mint is the remaining step.

- [x] **Authored** the `mock-ticket` crate under this directory as a workspace
      member (`use`s the §3 functions; no reimplementation).
- [x] `cargo build --release -p mock-ticket` → `$REPO_ROOT/target/release/mock-ticket`
      (clean).
- [x] **Unit-verified** the commitment: `mock-ticket commit`'s
      `ticket_nullifier_commitment` matches an **independent** keyed-BLAKE2b-512
      (`blake2b_512_keyed("misaka-palw-ticket-nf-commit-v1", nullifier)`) exactly;
      output is deterministic; `store-add` writes a valid authority-bound
      `TicketSecretStore` (mode 0600) and **refuses a foreign authority**.
- [ ] **End-to-end verify (no GPU):** run the harness with `TICKET_MODE=mock`;
      confirm `batch.status=active`, then that `start-palw-miner.sh` mints an
      algo-4 block whose disclosed nullifier opens the leaf's commitment, and
      that `verify-consensus.sh` reports the minted-block parity on **both**
      nodes. *(Not yet run — needs the 2-node mesh up; the mint's crypto inputs
      are verified above.)*

---

## 7. Honesty footer — what this does NOT prove

- A minted block here is **wiring-only**: it proves algo-4 block **validity**,
  **propagation**, and reward **plumbing** — it is **not** a real inference
  result and carries **no** compute proof. The leaf is a mock.
- It does **not** replace the provider GPU tool (`palw-providerd` + model), which
  writes real ticket secrets as a by-product of real inference (Phase 1).
- It does **not** exercise real network partition / NAT / peer loss (needs two
  hosts), and the algo-4 chain still has **fork-choice weight 0** in this
  harness.
- It is, again, **not** `palw_demo`: the leaf reaches both nodes through the real
  on-chain carriers; only the ticket secret is mock, and it is labeled mock at
  every layer (leaf comment, state var names, this README).

See `../PHASE0-status.md` §4 for where this sits in the roadmap, and `../README.md`
§"Scope & limits" for the full honest boundary.
