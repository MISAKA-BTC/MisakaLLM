#!/usr/bin/env bash
# =============================================================================
# collect-artifacts.sh — STN-013: bundle the closed two-node PALW testnet's
#                        evidence into one portable, REDACTED directory.
#
#   usage:  ./collect-artifacts.sh [LABEL]      # LABEL overrides BUNDLE_LABEL
#           ./collect-artifacts.sh --help
#
# WHAT THIS PRODUCES (into artifacts/bundle-<LABEL>/):
#   binary-hashes.txt              copy of the STN-001 release-binary SHA-256s
#   node-a-status.txt              live `VAL status` dump from node A (over wRPC)
#   node-b-status.txt              live `VAL status` dump from node B
#   palw-status/                   `VAL palw-status` dumps, per identity, per node:
#       provider-A.node-{a,b}.txt  provider A provider-bond view
#       provider-B.node-{a,b}.txt  provider B provider-bond view
#       provider-C.node-{a,b}.txt  independent auditor C provider-bond view
#       batch.node-{a,b}.txt       batch view for PALW_BATCH_ID
#   outpoints-and-ids.txt          every captured tx/outpoint id + PALW_BATCH_ID
#                                  (+ any recorded algo-4 block hash / verdict)
#   logs/<name>.log.tail.txt       the tail of EVERY log under logs/
#   env.redacted                   PUBLIC config only (network/ports/commitment
#                                  ids/funding addresses/outpoints). Secrets are
#                                  REDACTED and *.seed / key material is NEVER
#                                  copied or referenced by value.
#   MANIFEST.txt                   listing of every bundled file: sha256, size, path
#
# HONEST SCOPE (read before trusting the bundle):
#   * It bundles REAL evidence: the status/palw-status dumps are read LIVE from
#     the two validators over independent wRPC; the ids come from the discovered
#     artifacts/state.env; the log tails are the real daemons' logs; the hashes
#     are the real just-built binaries. It NEVER invokes the seeded, test-only
#     `palw_demo` path and it mints nothing — there is no demo evidence here.
#   * The two status dumps prove what the two configured RPC endpoints saw. On a
#     SINGLE host that is two processes agreeing, NOT a network-partition proof
#     (STN-003) — the manifest states this plainly rather than overclaiming.
#   * NO seed or secret material is bundled. artifacts/state.env itself is NOT
#     copied (it can hold seed *paths*); only a redacted, allow-listed env is
#     emitted. keys/*.seed and the ticket secret store are never read or copied.
#     Log tails may contain seed FILE PATHS that daemons logged in their argv
#     (e.g. --validator-key <path>) but never seed CONTENTS — common.sh
#     guarantees "NO SECRETS TO ARGV / LOG".
#
# Design rules (shared with the whole harness):
#   * IDEMPOTENT   — this stage creates NO pids / keys / outpoints; it only READS
#                    them. The single thing it writes is the bundle directory,
#                    which it builds in a temp staging dir and moves into place
#                    atomically. It NEVER silently overwrites an existing bundle:
#                    an already-present artifacts/bundle-<LABEL>/ is fail-closed
#                    (pick a new label, or BUNDLE_FORCE=1 to replace — logged).
#   * FAIL-CLOSED  — any missing evidence (nodes down, unset outpoints/batch id,
#                    absent binary-hashes.txt, no logs) is a die() with an
#                    actionable message. BUNDLE_ALLOW_PARTIAL=1 downgrades those
#                    to recorded gaps (an honestly-labeled post-mortem bundle).
#   * TRAP-SAFE    — a register_cleanup trap removes the temp staging dir on any
#                    early EXIT/INT/TERM, so a failed run leaves no half-bundle.
#   * PORTABLE     — bash 3.2 (stock macOS) + Linux; BSD + GNU coreutils.
#
# Env knobs (all optional):
#   BUNDLE_LABEL=<s> / positional LABEL — bundle dir suffix (default "unlabeled";
#                    this script never synthesises one from date()). The label is
#                    validated as a safe single path component.
#   BUNDLE_FORCE=1 — replace an existing artifacts/bundle-<LABEL>/ (logged).
#   BUNDLE_ALLOW_PARTIAL=1 — still produce a bundle when some evidence is missing;
#                    each gap is recorded in-place instead of aborting.
#   BUNDLE_TAIL_LINES=<n> — lines per log tail (default 200).
#   BUNDLE_RPC_PROBE_SECS=<n> — per-node wRPC probe timeout, seconds (default 10).
#   PALW_ENV_FILE / env.local / env.example — config source (as load_env).
#
# It SOURCES common.sh and uses ONLY its helpers — it reimplements none of them.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$SCRIPT_DIR/common.sh"
# shellcheck source=remote.sh
. "$SCRIPT_DIR/remote.sh"   # node_is_remote / node_dispatch / remote host bundle pull (§5.4 cond 4)

# Per-stage log tag (respects an operator override).
PALW_LOG_TAG="${PALW_LOG_TAG:-collect-artifacts}"; export PALW_LOG_TAG

usage() {
    cat >&2 <<EOF
usage: ${0##*/} [LABEL|--help]

  Bundle the closed two-node PALW testnet's evidence into a portable, REDACTED
  directory  artifacts/bundle-<LABEL>/  (STN-013): the STN-001 binary hashes,
  live node A/B status dumps, provider (A/B/auditor-C) + batch palw-status
  dumps, every captured outpoint/tx id + PALW_BATCH_ID, the tail of every log,
  a PUBLIC-only redacted env, and a sha256 MANIFEST. It never copies *.seed and
  never bundles artifacts/state.env (which can hold seed paths).

  LABEL              Bundle directory suffix (overrides \$BUNDLE_LABEL; default
                     "unlabeled"). Must be a single safe path component.
  --help             Show this help and exit.

  Idempotent: creates no pids/keys/outpoints (reads only). Refuses to overwrite
  an existing bundle-<LABEL>/ — choose a new label or set BUNDLE_FORCE=1.
  Fail-closed on missing evidence unless BUNDLE_ALLOW_PARTIAL=1 (then each gap
  is recorded honestly in the bundle instead of aborting).
EOF
}

# ---------------------------------------------------------------------------
# Dispatch / arg validation BEFORE load_env so --help works unconfigured.
# A single optional positional is the label; anything more is fail-closed.
# ---------------------------------------------------------------------------
BUNDLE_LABEL_ARG=""
case "${1:-}" in
    -h|--help|help) usage; exit 0 ;;
    "")             : ;;
    -*)             usage; die "unknown option '$1' (this stage takes an optional LABEL or --help)." ;;
    *)              BUNDLE_LABEL_ARG="$1" ;;
esac
if [ "$#" -gt 1 ]; then usage; die "unexpected extra argument(s): ${*:2} (expected at most a single LABEL)."; fi

# External tools this script invokes directly (helpers rely on more, all present).
require_cmd awk grep mktemp install date tail find sort cp wc chmod

# Pick the available SHA-256 tool (used for the manifest integrity column):
# sha256sum (GNU coreutils) or `shasum -a 256` (BSD / stock macOS). Fail fast.
if command -v sha256sum >/dev/null 2>&1; then
    SHA256_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA256_TOOL="shasum -a 256"
else
    die "need 'sha256sum' or 'shasum' on PATH to hash bundle files (install coreutils, or use macOS's shasum)."
fi

# load_env: sources config, realpaths REPO_ROOT/PALW_DATA_ROOT, creates the 0700
# data dirs, overlays state.env, validates required vars, binds+verifies the
# three binaries. Fail-closed and re-runnable. We need PALW_DATA_ROOT (where the
# logs / artifacts / state live) and the node addressing/status helpers.
load_env

# ---------------------------------------------------------------------------
# Resolve + validate the bundle label (it becomes a directory name).
# ---------------------------------------------------------------------------
BUNDLE_LABEL="${BUNDLE_LABEL_ARG:-${BUNDLE_LABEL:-unlabeled}}"
case "$BUNDLE_LABEL" in
    ''|*[!A-Za-z0-9._-]*) die "invalid bundle label '$BUNDLE_LABEL' — use only letters, digits, '.', '-', '_' (it becomes a single directory name)." ;;
esac
case "$BUNDLE_LABEL" in
    .|..|-*) die "bundle label must not be '.', '..', or start with '-' (got '$BUNDLE_LABEL')." ;;
esac

ARTIFACTS_DIR="$PALW_DATA_ROOT/artifacts"
LOGS_DIR="$PALW_DATA_ROOT/logs"
HASHES_SRC="$ARTIFACTS_DIR/binary-hashes.txt"
BUNDLE_DIR="$ARTIFACTS_DIR/bundle-$BUNDLE_LABEL"

TAIL_LINES="${BUNDLE_TAIL_LINES:-200}"
case "$TAIL_LINES" in ''|*[!0-9]*) die "BUNDLE_TAIL_LINES must be a non-negative integer, got '$TAIL_LINES'." ;; esac
RPC_PROBE_SECS="${BUNDLE_RPC_PROBE_SECS:-10}"
case "$RPC_PROBE_SECS" in ''|*[!0-9]*) die "BUNDLE_RPC_PROBE_SECS must be a non-negative integer, got '$RPC_PROBE_SECS'." ;; esac

# ---------------------------------------------------------------------------
# Staging dir + cleanup trap. We build the whole bundle under a temp dir and
# only mv it into place at the very end, so a crash never leaves a half-bundle
# and never clobbers a prior-good one. $STAGE is expanded at trap time (see
# _run_cleanup's eval); it is blanked the instant the bundle is committed, and
# the guard makes an empty $STAGE a no-op so the committed dir is never removed.
# ---------------------------------------------------------------------------
install -d -m 0700 "$ARTIFACTS_DIR" || die "cannot create artifacts dir: $ARTIFACTS_DIR"
STAGE="$(mktemp -d "${BUNDLE_DIR}.partial.XXXXXX")" || die "mktemp -d failed near $BUNDLE_DIR"
register_cleanup '[ -n "${STAGE:-}" ] && rm -rf "$STAGE"'
install -d -m 0755 "$STAGE/palw-status" "$STAGE/logs" \
    || die "cannot create staging subdirs under $STAGE"

# ---------------------------------------------------------------------------
# gap <message> — record missing evidence. Fatal (fail-closed) by default; with
#   BUNDLE_ALLOW_PARTIAL=1 it warns, bumps the gap counter, and returns 0 so the
#   caller can write an honest placeholder and continue.
# ---------------------------------------------------------------------------
GAP_COUNT=0
gap() {
    GAP_COUNT=$(( GAP_COUNT + 1 ))
    if [ "${BUNDLE_ALLOW_PARTIAL:-}" = "1" ]; then
        warn "partial bundle: $*"
        return 0
    fi
    die "missing evidence: $*
Fix it and re-run, or set BUNDLE_ALLOW_PARTIAL=1 to bundle only what IS available
(an honestly-labeled post-mortem bundle)."
}

# run_capture <outfile> <rpc_ok 0|1> <desc> <cmd> [args...]
#   Capture a live status command's stdout+stderr into <outfile>. If the node's
#   RPC is not up (<rpc_ok> != 1) it writes an UNAVAILABLE marker instead of a
#   fabricated dump. A non-zero command still records its output plus an error
#   marker (never a false-clean dump).
run_capture() {
    local out="$1" ok="$2" desc="$3"; shift 3
    if [ "$ok" != "1" ]; then
        printf '<UNAVAILABLE: %s — node wRPC not answering at collection time>\n' "$desc" > "$out"
        warn "recorded UNAVAILABLE: $desc (node RPC down)"
        return 0
    fi
    if "$@" > "$out" 2>&1; then
        [ -s "$out" ] || printf '<empty response: %s>\n' "$desc" > "$out"
        log "captured: $desc -> ${out#$STAGE/}"
    else
        printf '\n<ERROR: %s — command exited non-zero; any partial output is above>\n' "$desc" >> "$out"
        warn "capture returned non-zero: $desc (recorded with an error marker)"
    fi
}

# _looks_secret <name> <value> — defence-in-depth guard for the redacted env.
#   The env allow-list below already excludes secrets by construction; this also
#   redacts any value that turns out to reference key material.
_looks_secret() {
    local name="$1" val="$2"
    case "$name" in
        *SEED*|*SECRET*|*PRIVATE*|*_KEY) return 0 ;;
    esac
    case "$val" in
        *.seed|*/keys/*) return 0 ;;
    esac
    if [ -n "$val" ] && [ -e "$val" ]; then
        case "$(realpath_p "$val")" in
            "$PALW_DATA_ROOT"/keys/*) return 0 ;;
        esac
    fi
    return 1
}

log "collecting evidence into staging dir for bundle-$BUNDLE_LABEL (network=$NETWORK, data=$PALW_DATA_ROOT)"

# ===========================================================================
# [1] binary-hashes.txt — copy the STN-001 release-binary attestation.
# ===========================================================================
if [ -s "$HASHES_SRC" ]; then
    cp "$HASHES_SRC" "$STAGE/binary-hashes.txt" || die "failed to copy $HASHES_SRC into the bundle."
    log "bundled binary-hashes.txt (STN-001)"
else
    gap "binary-hashes.txt not found at $HASHES_SRC — run ./build-and-hash.sh first (STN-001)."
    printf '<MISSING: %s — run ./build-and-hash.sh (STN-001) before collecting>\n' "$HASHES_SRC" \
        > "$STAGE/binary-hashes.txt"
fi

# ===========================================================================
# [2] Probe each node's wRPC once (short timeout). Live status/palw-status dumps
#     need the nodes up. Per-node flags drive UNAVAILABLE markers under partial.
# ===========================================================================
RPC_OK_A=0; RPC_OK_B=0
if wait_rpc_up a "$RPC_PROBE_SECS"; then RPC_OK_A=1; fi
if wait_rpc_up b "$RPC_PROBE_SECS"; then RPC_OK_B=1; fi
node_rpc_ok() { case "$(_node_label "$1")" in a) printf '%s' "$RPC_OK_A" ;; b) printf '%s' "$RPC_OK_B" ;; esac; }

if [ "$RPC_OK_A" != "1" ] || [ "$RPC_OK_B" != "1" ]; then
    gap "one or both node wRPC endpoints are not answering (A up=$RPC_OK_A [$(node_wrpc a)], B up=$RPC_OK_B [$(node_wrpc b)]) — live status/palw-status dumps require both nodes running. Start ./node-a.sh and ./node-b.sh."
fi

# ===========================================================================
# [3] Discovered ids from artifacts/state.env (public on-chain values). The
#     provider bonds and the batch id are required for a COMPLETE bundle.
# ===========================================================================
DNS_BOND="$(state_get DNS_BOND)"          # validator stake-bond outpoint (optional)
PROV_A_BOND="$(state_get PROV_A_BOND)"    # provider A provider-bond outpoint
PROV_B_BOND="$(state_get PROV_B_BOND)"    # provider B provider-bond outpoint
AUD_C_BOND="$(state_get AUD_C_BOND)"      # independent auditor C provider-bond outpoint
PALW_BATCH_ID="$(state_get PALW_BATCH_ID)" # batch id (128hex)

[ -n "$PROV_A_BOND" ]   || gap "PROV_A_BOND not recorded in $(state_file) — run ./register-providers.sh first."
[ -n "$PROV_B_BOND" ]   || gap "PROV_B_BOND not recorded in $(state_file) — run ./register-providers.sh first."
[ -n "$AUD_C_BOND" ]    || gap "AUD_C_BOND not recorded in $(state_file) — run ./register-providers.sh first."
[ -n "$PALW_BATCH_ID" ] || gap "PALW_BATCH_ID not recorded in $(state_file) — run the batch-manifest/lifecycle stage first."

# Non-fatal shape sanity for the batch id (record it as-is either way; it is
# evidence). A malformed id means an upstream stage is broken.
if [ -n "$PALW_BATCH_ID" ]; then
    case "$PALW_BATCH_ID" in *[!0-9a-fA-F]*) warn "PALW_BATCH_ID is not hex: '$PALW_BATCH_ID' (bundling as-is)." ;; esac
    [ "${#PALW_BATCH_ID}" -eq 128 ] || warn "PALW_BATCH_ID length ${#PALW_BATCH_ID} != 128 (bundling as-is)."
    [ "$PALW_BATCH_ID" != "$(zero128)" ] || warn "PALW_BATCH_ID is the all-zero unbound sentinel (bundling as-is)."
fi

# ---- outpoints-and-ids.txt: every captured id, public values only ----------
IDS_OUT="$STAGE/outpoints-and-ids.txt"
{
    printf '# PALW closed-testnet — captured tx/outpoint ids + batch id (STN-013)\n'
    printf '# generated: %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf '# network:   %s (base=%s suffix=%s)\n' "$NETWORK" "$NETWORK_BASE" "$NETSUFFIX"
    printf '# These are PUBLIC on-chain identifiers. No secret material appears here.\n'
    printf '\n'
    printf 'DNS_BOND               (validator stake-bond outpoint): %s\n' "${DNS_BOND:-<unset>}"
    printf 'PROV_A_BOND            (provider A provider-bond)      : %s\n' "${PROV_A_BOND:-<unset>}"
    printf 'PROV_B_BOND            (provider B provider-bond)      : %s\n' "${PROV_B_BOND:-<unset>}"
    printf 'AUD_C_BOND             (auditor  C provider-bond)      : %s\n' "${AUD_C_BOND:-<unset>}"
    printf 'PALW_BATCH_ID          (batch id, 128hex)             : %s\n' "${PALW_BATCH_ID:-<unset>}"
    printf '\n'
    printf '# Minted algo-4 block evidence (present only when TICKET_MODE=mock minted one;\n'
    printf '# algo-4 blocks carry fork-choice weight 0 (PALW-014) so they never become the sink):\n'
    printf 'PALW_ALGO4_BLOCK_HASH_A: %s\n' "$(state_get PALW_ALGO4_BLOCK_HASH_A || true)"
    printf 'PALW_ALGO4_BLOCK_HASH_B: %s\n' "$(state_get PALW_ALGO4_BLOCK_HASH_B || true)"
    printf 'PALW_ALGO4_ACCEPT_A    : %s\n' "$(state_get PALW_ALGO4_ACCEPT_A || true)"
    printf 'PALW_ALGO4_ACCEPT_B    : %s\n' "$(state_get PALW_ALGO4_ACCEPT_B || true)"
} > "$IDS_OUT"
log "bundled outpoints-and-ids.txt"

# ===========================================================================
# [4] Node A / B status dumps (live, over independent wRPC). If DNS_BOND is
#     recorded, pass it so the dump also carries stake_depth / bond_status.
# ===========================================================================
if [ -n "$DNS_BOND" ]; then
    run_capture "$STAGE/node-a-status.txt" "$RPC_OK_A" "node A status (stake-bond $DNS_BOND)" node_status a "$DNS_BOND"
    run_capture "$STAGE/node-b-status.txt" "$RPC_OK_B" "node B status (stake-bond $DNS_BOND)" node_status b "$DNS_BOND"
else
    run_capture "$STAGE/node-a-status.txt" "$RPC_OK_A" "node A status" node_status a
    run_capture "$STAGE/node-b-status.txt" "$RPC_OK_B" "node B status" node_status b
fi

# ===========================================================================
# [5] Provider + batch palw-status dumps, per identity, per node (A and B) so
#     the bundle carries both-node parity evidence, mirroring verify-consensus.
# ===========================================================================
dump_provider() {   # <label A|B|C> <bond outpoint>
    local label="$1" bond="$2" n out
    for n in a b; do
        out="$STAGE/palw-status/provider-$label.node-$n.txt"
        if [ -z "$bond" ]; then
            printf '<skipped: provider-%s bond outpoint not recorded in state.env>\n' "$label" > "$out"
        else
            run_capture "$out" "$(node_rpc_ok "$n")" "palw-status provider-$label ($bond) on node-$n" \
                palw_provider_status "$n" "$bond"
        fi
    done
}
dump_provider A "$PROV_A_BOND"
dump_provider B "$PROV_B_BOND"
dump_provider C "$AUD_C_BOND"

for n in a b; do
    out="$STAGE/palw-status/batch.node-$n.txt"
    if [ -z "$PALW_BATCH_ID" ]; then
        printf '<skipped: PALW_BATCH_ID not recorded in state.env>\n' > "$out"
    else
        run_capture "$out" "$(node_rpc_ok "$n")" "palw-status batch ($PALW_BATCH_ID) on node-$n" \
            palw_batch_status "$n" "$PALW_BATCH_ID"
    fi
done

# ===========================================================================
# [6] Tail of EVERY log under logs/ (node-a.log, node-b.log, miner-supporting.log,
#     and any rotated *.log.<ts>). Public daemon output; no seed CONTENTS appear.
# ===========================================================================
LOG_LIST="$(find "$LOGS_DIR" -type f -name '*.log*' 2>/dev/null | LC_ALL=C sort || true)"
if [ -z "$LOG_LIST" ]; then
    gap "no log files found under $LOGS_DIR — start the net (node-a.sh / node-b.sh / supporting-miner.sh) so there are logs to bundle."
    printf '<no log files present under %s at collection time>\n' "$LOGS_DIR" > "$STAGE/logs/NO-LOGS.txt"
else
    printf '%s\n' "$LOG_LIST" | while IFS= read -r lf; do
        [ -n "$lf" ] || continue
        base="$(basename "$lf")"
        out="$STAGE/logs/$base.tail.txt"
        {
            printf '# tail -n %s of %s (path on the collecting host)\n' "$TAIL_LINES" "$lf"
            tail -n "$TAIL_LINES" "$lf" 2>/dev/null || printf '<could not read %s>\n' "$lf"
        } > "$out"
    done
    log "bundled tails of $(printf '%s\n' "$LOG_LIST" | grep -c .) log file(s) (last $TAIL_LINES lines each)"
fi

# ===========================================================================
# [6b] REMOTE host bundles (§5.4 condition 4). Section [6] tails logs on the
#      COLLECTING host only. For a node whose host is REMOTE, its logs / pid
#      records / effective argv / disk metrics live on THAT host — so ask its
#      agent to bundle them host-local (`collect`, secrets excluded there) and
#      pull the archive back over one SSH hop (`collect-tar` streams a clean tar
#      on stdout; agent log lines go to stderr). Local nodes are already covered
#      by [6], so this loop no-ops on a single host.
# ===========================================================================
pull_remote_host_bundle() {   # <a|b>
    local n="$1" rname localdst host
    rname="agent-collect-$BUNDLE_LABEL"
    localdst="$STAGE/logs/remote-node-$n"
    install -d -m 0755 "$localdst" || { gap "cannot create $localdst"; return 0; }
    # 1. bundle host-local evidence on the node's own host (agent, secrets excluded).
    if ! node_dispatch "$n" collect "$rname" >/dev/null 2>"$localdst/agent-collect.log"; then
        gap "remote 'collect' on node-$n host failed (see $localdst/agent-collect.log)"; return 0
    fi
    # 2. stream the bundle back as a tar. stdout is the clean archive; the agent's
    #    log/warn lines go to stderr (captured separately, never into the tar).
    if node_dispatch "$n" collect-tar "$rname" >"$localdst/bundle.tar" 2>>"$localdst/agent-collect.log"; then
        if ( cd "$localdst" && tar -xf bundle.tar ) 2>/dev/null; then
            rm -f "$localdst/bundle.tar"
            log "pulled remote host bundle for node-$n -> ${localdst#$STAGE/}"
        else
            warn "could not extract remote bundle for node-$n (kept $localdst/bundle.tar for inspection)"
        fi
    else
        gap "could not pull remote bundle from node-$n host (collect-tar failed; see $localdst/agent-collect.log)"
    fi
    # defence-in-depth: a pulled bundle must never carry key material.
    find "$localdst" -type f -name '*.seed' -delete 2>/dev/null || true
}
for n in a b; do
    if node_is_remote "$n"; then
        log "collecting remote host bundle for node-$n ($(node_ssh_host "$n")) via its agent"
        pull_remote_host_bundle "$n"
    fi
done

# ===========================================================================
# [7] Redacted env — PUBLIC config only. Allow-list of names known to hold
#     network/topology config, public commitment ids, public funding addresses
#     and public on-chain outpoints. Secrets are excluded by name AND re-checked
#     per value (_looks_secret). *.seed and key material are NEVER emitted, and
#     artifacts/state.env is NOT copied (it can hold seed paths).
# ===========================================================================
PUBLIC_ENV_KEYS="
NETWORK NETWORK_BASE NETSUFFIX ADDR_PREFIX PALW_ENABLE_ALGO4
NODE_A_HOST NODE_B_HOST RPC_BIND
A_P2P_PORT A_GRPC_PORT A_WRPC_PORT B_P2P_PORT B_GRPC_PORT B_WRPC_PORT
MINER_INTERVAL_MS MINER_WORKER
LEAF_COUNT SHAPE_ID CAPACITY_COUNT TICKET_MODE
DNS_BOND_AMOUNT PROVIDER_A_AMOUNT PROVIDER_B_AMOUNT AUDITOR_AMOUNT
UNBONDING_PERIOD_BLOCKS UNBOND_DELAY_EPOCHS MIN_EPOCH_HEADROOM_DAA
OPERATOR_GROUP_A OPERATOR_GROUP_B OPERATOR_GROUP_AUD
RUNTIME_CLASS_ID MODEL_PROFILE_ID REWARD_KEY_ROOT_A REWARD_KEY_ROOT_B
AUDIT_POLICY_ID DESCRIPTOR_ROOT PROV_A_REWARD_PK_BYTE PROV_B_REWARD_PK_BYTE
DNS_BOND PROV_A_BOND PROV_B_BOND AUD_C_BOND PALW_BATCH_ID
DNS_ADDR PROV_A_ADDR PROV_B_ADDR AUD_C_ADDR PALW_MINE_ADDR SUPPORTING_ADDR
PALW_MINE_ADDRESS
PALW_ALGO4_BLOCK_HASH_A PALW_ALGO4_BLOCK_HASH_B PALW_ALGO4_ACCEPT_A PALW_ALGO4_ACCEPT_B
"
ENV_OUT="$STAGE/env.redacted"
{
    printf '# PALW closed-testnet — REDACTED public env (STN-013)\n'
    printf '# generated: %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf '# PUBLIC config / commitment ids / funding addresses / on-chain outpoints ONLY.\n'
    printf '# Secrets are omitted: NO *.seed, NO ticket secret store, NO key material, and\n'
    printf '# artifacts/state.env itself is NOT bundled (it can hold seed file paths).\n'
    printf '# REPO_ROOT / PALW_DATA_ROOT are host-local paths, deliberately not exported here.\n'
    printf '\n'
} > "$ENV_OUT"
for k in $PUBLIC_ENV_KEYS; do
    v="$(state_get "$k" || true)"
    if _looks_secret "$k" "$v"; then
        printf '# %s=<REDACTED: references key material — never exported>\n' "$k" >> "$ENV_OUT"
        warn "redacted $k in env.redacted (value looked like key material)"
    elif [ -z "$v" ]; then
        printf '# %s=<unset>\n' "$k" >> "$ENV_OUT"
    else
        printf 'export %s=%q\n' "$k" "$v" >> "$ENV_OUT"
    fi
done
log "bundled env.redacted (public config only; secrets redacted)"

# ===========================================================================
# [8] Defence-in-depth: refuse to publish a bundle that somehow contains a
#     .seed file. By construction we never copy from keys/, so this must be 0.
# ===========================================================================
if find "$STAGE" -type f -name '*.seed' 2>/dev/null | grep -q .; then
    die "internal error: a *.seed file ended up in the staged bundle — refusing to publish evidence containing key material. This is a bug; report it."
fi

# ===========================================================================
# [9] MANIFEST.txt — listing of every bundled file: sha256, byte size, path.
#     Written last and excluded from its own listing.
# ===========================================================================
MAN="$STAGE/MANIFEST.txt"
{
    printf 'PALW closed-testnet evidence bundle — MANIFEST (STN-013)\n'
    printf 'bundle label:        %s\n' "$BUNDLE_LABEL"
    printf 'generated:           %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'network:             %s (base=%s suffix=%s)\n' "$NETWORK" "$NETWORK_BASE" "$NETSUFFIX"
    printf 'ticket mode:         %s\n' "$TICKET_MODE"
    printf 'node A wRPC:         %s   (up at collection: %s)\n' "$(node_wrpc a)" "$( [ "$RPC_OK_A" = 1 ] && echo yes || echo no)"
    printf 'node B wRPC:         %s   (up at collection: %s)\n' "$(node_wrpc b)" "$( [ "$RPC_OK_B" = 1 ] && echo yes || echo no)"
    printf 'recorded gaps:       %s%s\n' "$GAP_COUNT" "$( [ "${BUNDLE_ALLOW_PARTIAL:-}" = 1 ] && printf ' (BUNDLE_ALLOW_PARTIAL=1: partial post-mortem bundle)' )"
    printf '\n'
    printf 'HONEST SCOPE: real evidence read LIVE from the two validators over independent\n'
    printf 'wRPC + real logs + real binary hashes. NOT the seeded test-only palw_demo path;\n'
    printf 'nothing was minted here. On a single host the two status dumps prove two\n'
    printf 'processes agree, NOT network-partition survival (STN-003). NO seed or secret\n'
    printf 'material is bundled; artifacts/state.env is not copied.\n'
    printf '\n'
    printf 'files (sha256  bytes  path):\n'
} > "$MAN"
# Compute the listing from within the stage so paths are bundle-relative. The
# subshell cd never changes this script's own working directory.
(
    cd "$STAGE" || exit 1
    find . -type f ! -name 'MANIFEST.txt' | LC_ALL=C sort | while IFS= read -r f; do
        rel="${f#./}"
        h="$($SHA256_TOOL "$f" 2>/dev/null | awk 'NR==1{print $1}')"
        [ -n "$h" ] || h="<hash-failed>"
        sz="$(wc -c < "$f" 2>/dev/null | tr -d ' ')"
        [ -n "$sz" ] || sz="?"
        printf '%s  %s  %s\n' "$h" "$sz" "$rel"
    done
) >> "$MAN" || die "failed to build the manifest listing."
log "bundled MANIFEST.txt"

# ===========================================================================
# Normalise permissions, then commit atomically (idempotent, never a silent
# overwrite). A prior bundle of the same label is replaced only with
# BUNDLE_FORCE=1, and that replacement is LOGGED.
# ===========================================================================
find "$STAGE" -type d -exec chmod 0755 {} + 2>/dev/null || true
find "$STAGE" -type f -exec chmod 0644 {} + 2>/dev/null || true

if [ -e "$BUNDLE_DIR" ]; then
    if [ "${BUNDLE_FORCE:-}" = "1" ]; then
        warn "bundle already exists at $BUNDLE_DIR; BUNDLE_FORCE=1 -> replacing it"
        rm -rf "$BUNDLE_DIR" || die "cannot remove existing bundle $BUNDLE_DIR for replacement."
        mv "$STAGE" "$BUNDLE_DIR" || die "failed to move staged bundle into place at $BUNDLE_DIR."
    else
        die "a bundle already exists at $BUNDLE_DIR — this harness will not silently overwrite evidence. Choose a new label (BUNDLE_LABEL=... or pass a LABEL arg), or set BUNDLE_FORCE=1 to replace it."
    fi
else
    mv "$STAGE" "$BUNDLE_DIR" || die "failed to move staged bundle into place at $BUNDLE_DIR."
fi
STAGE=""   # committed: the cleanup trap must not touch the published bundle

if [ "$GAP_COUNT" -gt 0 ]; then
    # Reachable only under BUNDLE_ALLOW_PARTIAL=1 (otherwise gap() already died).
    warn "STN-013 bundle written with $GAP_COUNT recorded gap(s) (BUNDLE_ALLOW_PARTIAL=1) -> $BUNDLE_DIR. See MANIFEST.txt and the in-place markers; this is an incomplete post-mortem bundle."
else
    log "STN-013 evidence bundle complete -> $BUNDLE_DIR (see MANIFEST.txt). No secrets bundled; no *.seed copied."
fi
exit 0
