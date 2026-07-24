#!/usr/bin/env bash
# =============================================================================
# preflight.sh — Phase-0 CLOSED two-node PALW testnet: environment + toolchain
#                gate. Runs BEFORE any node or miner is started.
#
# Audit-finding coverage (see PHASE0-status.md §2):
#   * STN-001  no hardcoded paths — everything is env-driven and realpath'd by
#              load_env; binaries identified only through $KASPAD/$VAL/$MINER.
#   * STN-002  data dirs created (load_env + an explicit idempotent re-create).
#   * STN-003  preflight part — host/port layout validated, two-host aware; a
#              single machine still cannot prove real partition/NAT (documented,
#              not pretended).
#   * STN-004  partial — asserts a clean, self-consistent STARTING state and
#              fails closed on any ambiguity (stray node on a foreign network,
#              divergent node_network between A and B).
#
# WHAT IT DOES (read-only except for the derived hash record):
#   1. load_env, then validate REPO_ROOT / PALW_DATA_ROOT / NETWORK and the six
#      ports (numeric, in range, disjoint on a single host).
#   2. Assert the three release binaries exist and are executable.
#   3. sha256 each -> artifacts/binary-hashes.txt (idempotent; if the recorded
#      hashes differ from the current binaries it says so LOUDLY, never silently
#      overwrites).
#   4. If PEER_BINARY_HASHES is set, compare per-binary and DIE on any mismatch
#      (every node in a closed net must run byte-identical binaries).
#   5. If either node is ALREADY up, assert both report the same node_network
#      and warn LOUDLY that --palw-enable-algo4 must be identical on every node
#      (it is a start-time override and CANNOT be introspected over RPC).
#
# WHAT IT DOES NOT DO: it starts no process, mines nothing, writes no keys, and
# never touches the seeded test-only palw_demo path. The only file it may write
# is the derived artifacts/binary-hashes.txt record.
#
# Idempotent + fail-closed + portable (bash 3.2 / BSD + GNU coreutils). It
# SOURCES common.sh and calls its helpers — it reimplements none of them.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$SCRIPT_DIR/common.sh"

PALW_LOG_TAG="preflight"
export PALW_LOG_TAG

# -----------------------------------------------------------------------------
# Cleanup trap, armed up front (LIFO). preflight starts no long-lived process;
# the only teardown is removing a half-written temp hash file on an early
# die/INT/TERM. _TMP_HASH is expanded at trap time (see _run_cleanup's eval).
# -----------------------------------------------------------------------------
_TMP_HASH=""
register_cleanup 'if [ -n "$_TMP_HASH" ]; then rm -f "$_TMP_HASH"; fi'

# load_env: sources config, realpaths REPO_ROOT/PALW_DATA_ROOT, creates the 0700
# data dirs, overlays state.env, validates required vars, binds+verifies the
# three binaries. Fail-closed and re-runnable.
load_env

# External tools this script uses directly (helpers rely on more, all present).
require_cmd awk mktemp install

# =============================================================================
# Local helpers (thin; never duplicate common.sh — these only add checks that
# common.sh does not provide: port validation and portable sha256).
# =============================================================================

# _valid_port <n> — 0 iff <n> is an integer TCP port in 1..65535.
_valid_port() {
    case "${1:-}" in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# _check_ports_distinct LABEL=PORT ... — die on the first colliding pair.
_check_ports_distinct() {
    local a b la lb pa pb
    for a in "$@"; do
        la="${a%%=*}"; pa="${a##*=}"
        for b in "$@"; do
            lb="${b%%=*}"; pb="${b##*=}"
            [ "$la" = "$lb" ] && continue
            if [ "$pa" = "$pb" ]; then
                die "port collision: $la and $lb both use $pa (remap disjoint ports in env.local)"
            fi
        done
    done
}

# _sha256 <file> — echo the lowercase 64-hex sha256 digest, via whichever tool
#   is present (sha256sum | shasum -a 256 | openssl). Fail-closed if none.
_sha256() {
    local f="${1:?file}"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$f" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$f" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$f" | awk '{print $NF}'
    else
        die "no sha256 tool found (need one of: sha256sum, shasum, openssl)"
    fi
}

# _hash_line <file> — echo "<64hex>  <basename>" for the manifest. Validates the
#   digest shape (fail-closed) so a truncated/garbled hash can never be recorded.
_hash_line() {
    local f="${1:?file}" h
    h="$(_sha256 "$f")"
    h="$(printf '%s' "$h" | tr 'A-F' 'a-f')"
    case "$h" in *[!0-9a-f]*) die "sha256 of $f is not hex: '$h'" ;; esac
    [ "${#h}" -eq 64 ] || die "sha256 of $f has wrong length (${#h} != 64): '$h'"
    printf '%s  %s\n' "$h" "$(basename "$f")"
}

# _write_hash_file — atomically (temp+mv) persist $FRESH_HASHES to $HASH_FILE.
_write_hash_file() {
    _TMP_HASH="$(mktemp "${HASH_FILE}.XXXXXX")" || die "mktemp failed near $HASH_FILE"
    printf '%s\n' "$FRESH_HASHES" > "$_TMP_HASH"
    chmod 0644 "$_TMP_HASH" 2>/dev/null || true
    mv "$_TMP_HASH" "$HASH_FILE"
    _TMP_HASH=""
    log "recorded binary hashes -> $HASH_FILE"
    while IFS= read -r _hl || [ -n "$_hl" ]; do
        [ -n "$_hl" ] && log "  $_hl"
    done <<PALW_HASH_MANIFEST
$FRESH_HASHES
PALW_HASH_MANIFEST
}

# =============================================================================
# 1. Validate environment (REPO_ROOT, PALW_DATA_ROOT, NETWORK, ports).
#    load_env already fail-closed on empty required vars and realpath'd the two
#    roots; here we re-affirm the load-bearing ones and add the port checks that
#    load_env does not perform.
# =============================================================================
for _v in REPO_ROOT PALW_DATA_ROOT NETWORK; do
    [ -n "${!_v:-}" ] || die "$_v is empty after load_env (define it in env.local / PALW_ENV_FILE)"
done
[ -d "$REPO_ROOT" ] || die "REPO_ROOT is not a directory: $REPO_ROOT"

for _pv in A_P2P_PORT A_GRPC_PORT A_WRPC_PORT B_P2P_PORT B_GRPC_PORT B_WRPC_PORT; do
    _valid_port "${!_pv}" || die "$_pv='${!_pv}' is not a valid TCP port (1-65535); fix env.local"
done

# Within a node the P2P / gRPC / wRPC ports must differ. On a SINGLE host
# (NODE_A_HOST == NODE_B_HOST — the devnet default) all six must be disjoint or
# the two kaspad processes collide. On TWO hosts each host owns its own port
# space, so only the per-node trio must be disjoint.
if [ "$NODE_A_HOST" = "$NODE_B_HOST" ]; then
    log "single-host layout (NODE_A_HOST == NODE_B_HOST == $NODE_A_HOST): all six ports must be disjoint"
    _check_ports_distinct \
        A_P2P="$A_P2P_PORT"  A_GRPC="$A_GRPC_PORT"  A_WRPC="$A_WRPC_PORT" \
        B_P2P="$B_P2P_PORT"  B_GRPC="$B_GRPC_PORT"  B_WRPC="$B_WRPC_PORT"
else
    log "two-host layout (A=$NODE_A_HOST B=$NODE_B_HOST): validating each node's port trio"
    _check_ports_distinct A_P2P="$A_P2P_PORT" A_GRPC="$A_GRPC_PORT" A_WRPC="$A_WRPC_PORT"
    _check_ports_distinct B_P2P="$B_P2P_PORT" B_GRPC="$B_GRPC_PORT" B_WRPC="$B_WRPC_PORT"
fi
log "ports OK (A p2p/grpc/wrpc=$A_P2P_PORT/$A_GRPC_PORT/$A_WRPC_PORT  B=$B_P2P_PORT/$B_GRPC_PORT/$B_WRPC_PORT)"

# Data dirs (STN-002). load_env already created these; install -d is idempotent
# and re-asserting here makes preflight own the invariant explicitly.
for _d in node-a node-b logs keys artifacts; do
    install -d -m 0700 "$PALW_DATA_ROOT/$_d" || die "cannot create $PALW_DATA_ROOT/$_d"
done
log "data dirs ready under $PALW_DATA_ROOT (node-a node-b logs keys artifacts, 0700)"

# =============================================================================
# 2. Assert the three release binaries exist and are executable.
#    load_env already bound + verified KASPAD/VAL/MINER; re-assert explicitly so
#    preflight owns STN-001 with an actionable message and a stable hash order.
# =============================================================================
_bins=("$KASPAD" "$VAL" "$MINER")
for _b in "${_bins[@]}"; do
    [ -e "$_b" ] || die "release binary missing: $_b (build it: ./build-and-hash.sh  or  cargo build --release)"
    [ -f "$_b" ] || die "release binary is not a regular file: $_b"
    [ -x "$_b" ] || die "release binary not executable: $_b (rebuild with cargo build --release)"
    [ -r "$_b" ] || die "release binary not readable: $_b"
done
log "release binaries present + executable: kaspad, kaspa-pq-validator, misaminer"

# TICKET_MODE=mock also needs the controller-only mock-ticket helper (a workspace
# member built by build-and-hash.sh). Local existence/exec only — it is NOT a node
# binary and is NEVER part of the cross-host binary attestation below.
if [ "${TICKET_MODE:-skip}" = mock ]; then
    _mock_bin="${MOCK_TICKET_BIN:-$REPO_ROOT/target/release/mock-ticket}"
    [ -x "$_mock_bin" ] || die "TICKET_MODE=mock requires the mock-ticket helper at $_mock_bin — build it with ./build-and-hash.sh (it now builds -p mock-ticket), or use TICKET_MODE=skip."
    log "mock-ticket helper present + executable: $_mock_bin (controller-only; not cross-host compared)"
fi

# =============================================================================
# 3. Hash the three binaries -> artifacts/binary-hashes.txt (idempotent).
#    A mismatch against an existing record means the binaries changed since the
#    last preflight (rebuilt/replaced) — reported LOUDLY, never silently.
# =============================================================================
HASH_FILE="$PALW_DATA_ROOT/artifacts/binary-hashes.txt"
install -d -m 0700 "$(dirname "$HASH_FILE")" || die "cannot create artifacts dir for $HASH_FILE"

# Stable order (kaspad, kaspa-pq-validator, misaminer). A die inside this
# command substitution propagates out and aborts the script (fail-closed).
FRESH_HASHES="$(
    for _b in "${_bins[@]}"; do
        _hash_line "$_b"
    done
)"

if [ -f "$HASH_FILE" ]; then
    # Compare only the attestation lines: build-and-hash.sh writes the same file
    # with leading `# ...` metadata/comment lines, so a raw `cat` would never match
    # FRESH_HASHES (bare "<hash>  <name>" lines) and would raise a false
    # "binaries changed" alarm + a non-idempotent rewrite. Strip comments/blank lines.
    EXISTING_HASHES="$(grep -Ev '^[[:space:]]*(#|$)' "$HASH_FILE")"
    if [ "$EXISTING_HASHES" = "$FRESH_HASHES" ]; then
        log "binary-hashes.txt already matches the current binaries (idempotent, unchanged): $HASH_FILE"
    else
        warn "recorded binary hashes DIFFER from the current binaries."
        warn "the release binaries changed since the last preflight (rebuilt or replaced)."
        warn "updating $HASH_FILE to reflect the CURRENT binaries (reported, not silent)."
        _write_hash_file
    fi
else
    _write_hash_file
fi

# =============================================================================
# 4. Peer binary-hash agreement (optional). PEER_BINARY_HASHES may be a path to
#    a peer's binary-hashes.txt OR the inline hash lines themselves. Every node
#    in a closed net MUST run byte-identical binaries; a mismatch means the two
#    hosts built different code -> fail closed.
# =============================================================================
if [ -n "${PEER_BINARY_HASHES:-}" ]; then
    if [ -f "$PEER_BINARY_HASHES" ] && [ -r "$PEER_BINARY_HASHES" ]; then
        PEER_HASHES="$(cat "$PEER_BINARY_HASHES")"
        PEER_SRC="file:$PEER_BINARY_HASHES"
    else
        PEER_HASHES="$PEER_BINARY_HASHES"
        PEER_SRC="inline"
    fi
    log "comparing local binaries against peer manifest ($PEER_SRC)"
    _mismatch=0
    for _b in "${_bins[@]}"; do
        _name="$(basename "$_b")"
        # our manifest is exactly "<hash>  <basename>"
        _ours="$(printf '%s\n' "$FRESH_HASHES" | awk -v b="$_name" '$2==b{print $1; exit}')"
        # peer manifest is tolerant: any line carrying a 64-hex token AND a field
        # whose basename == this binary (handles "hash name", "hash /path", and
        # "name hash" orderings; no awk interval expressions for portability).
        _theirs="$(printf '%s\n' "$PEER_HASHES" | awk -v b="$_name" '
            {
                h=""; n=""
                for (i=1;i<=NF;i++) if ($i ~ /^[0-9a-fA-F]+$/ && length($i)==64) h=$i
                for (i=1;i<=NF;i++) { p=$i; sub(/.*\//,"",p); if (p==b) n=p }
                if (h!="" && n!="") { print tolower(h); exit }
            }')"
        if [ -z "$_theirs" ]; then
            warn "peer manifest ($PEER_SRC) has NO entry for $_name"
            _mismatch=1
        elif [ "$_ours" != "$_theirs" ]; then
            warn "binary MISMATCH for $_name:"
            warn "  local: $_ours"
            warn "  peer : $_theirs"
            _mismatch=1
        else
            log "peer match: $_name $_ours"
        fi
    done
    if [ "$_mismatch" -ne 0 ]; then
        die "peer binary-hash mismatch (see WARN lines above): all nodes MUST run byte-identical binaries — rebuild every host from the same commit (if PEER_BINARY_HASHES was meant to be a file path, ensure it exists and is readable)"
    fi
    log "peer binary-hash agreement OK (all three match)"
else
    log "PEER_BINARY_HASHES not set — skipping cross-host binary agreement check"
fi

# =============================================================================
# 5. Already-running nodes: node_network parity + the --palw-enable-algo4 caveat.
#    node_status answers only if a node is up; node_network is the sole cross-
#    check RPC exposes. The algo-4 accept flag is a START-TIME override of the
#    shipped palw_algo4_accept=false and is NOT visible over RPC — preflight
#    cannot verify it, so it warns LOUDLY when any node is already up.
# =============================================================================
_status_a="$(node_status a 2>/dev/null || true)"
_status_b="$(node_status b 2>/dev/null || true)"
_net_a="$(printf '%s\n' "$_status_a" | _kv node_network)"
_net_b="$(printf '%s\n' "$_status_b" | _kv node_network)"
# STN-003/§9: node_genesis_hash is the genesis hash the node derives for its reported
# network (kaspa-pq-validator status). Lower-cased for a case-insensitive compare.
_gen_a="$(printf '%s\n' "$_status_a" | _kv node_genesis_hash | tr 'A-F' 'a-f')"
_gen_b="$(printf '%s\n' "$_status_b" | _kv node_genesis_hash | tr 'A-F' 'a-f')"

_a_up=0; [ -n "$_net_a" ] && _a_up=1
_b_up=0; [ -n "$_net_b" ] && _b_up=1
_a_state=down; [ "$_a_up" -eq 1 ] && _a_state=up
_b_state=down; [ "$_b_up" -eq 1 ] && _b_state=up
log "already-running check: node-a=$_a_state (network='${_net_a:-}')  node-b=$_b_state (network='${_net_b:-}')"

# Fail-closed: if BOTH nodes are up they MUST agree on node_network.
if [ "$_a_up" -eq 1 ] && [ "$_b_up" -eq 1 ]; then
    if [ "$_net_a" != "$_net_b" ]; then
        die "both nodes are up but report DIFFERENT node_network (A='$_net_a' B='$_net_b') — stop the stray node(s) before running the harness"
    fi
    log "both nodes up and agree on node_network=$_net_a"
fi

# =============================================================================
# 5b. Genesis-hash identity (STN-003/§9). The genesis hash is the explicit
#     network/config-identity pin that the binary-hash check alone only IMPLIES:
#     byte-identical binaries produce an identical genesis, but this asserts it and
#     lets an operator pin the expected value across independently-built hosts.
#     There is no RPC that returns a node's genesis, so the value comes from the
#     validator's status (Params::from(network_id).genesis.hash) — the same
#     derivation consensus trusts for the unbond replay guard.
# =============================================================================
# Fail-closed: if BOTH nodes are up they MUST report the same genesis.
if [ "$_a_up" -eq 1 ] && [ "$_b_up" -eq 1 ]; then
    if [ -n "$_gen_a" ] && [ -n "$_gen_b" ]; then
        if [ "$_gen_a" != "$_gen_b" ]; then
            die "both nodes are up but report DIFFERENT node_genesis_hash (A='$_gen_a' B='$_gen_b') — the hosts are on different genesis/consensus params; rebuild every host from the same commit and use the same NETWORK/NETSUFFIX"
        fi
        log "both nodes agree on node_genesis_hash=$_gen_a"
    else
        warn "node_genesis_hash not reported by one/both nodes (A='${_gen_a:-}' B='${_gen_b:-}') — an older validator binary predates this status field; rebuild via build-and-hash.sh to enable the genesis parity gate"
    fi
fi

# Optional operator pin: every up node's genesis MUST equal EXPECTED_GENESIS_HASH.
if [ -n "${EXPECTED_GENESIS_HASH:-}" ]; then
    _exp="$(printf '%s' "$EXPECTED_GENESIS_HASH" | tr 'A-F' 'a-f')"
    case "$_exp" in
        *[!0-9a-f]* | "") die "EXPECTED_GENESIS_HASH must be hex: '$EXPECTED_GENESIS_HASH'" ;;
    esac
    [ "${#_exp}" -eq 64 ] || die "EXPECTED_GENESIS_HASH must be 64 hex chars (a 32-byte block hash); got ${#_exp}: '$EXPECTED_GENESIS_HASH'"
    # <label> <observed-genesis> <up>
    _assert_expected_genesis() {
        [ "$3" -eq 1 ] || return 0
        if [ -z "$2" ]; then
            die "EXPECTED_GENESIS_HASH is set but node-$1 did not report node_genesis_hash (older validator binary?) — cannot verify the required genesis pin; rebuild via build-and-hash.sh"
        elif [ "$2" != "$_exp" ]; then
            die "node-$1 genesis MISMATCH: node_genesis_hash='$2' != EXPECTED_GENESIS_HASH='$_exp' — this node is NOT on the expected network/config"
        fi
        log "node-$1 genesis matches EXPECTED_GENESIS_HASH ($_exp)"
    }
    _assert_expected_genesis a "$_gen_a" "$_a_up"
    _assert_expected_genesis b "$_gen_b" "$_b_up"
fi

# Soft, loud heads-up if a running node's network does not match this config —
# usually a stray node from another network bound to our ports (node start would
# then fail on bind; surface it now). WARN, not die: node_network's exact string
# can vary across builds, so we do not hard-gate on equality with $NETWORK.
if [ "$_a_up" -eq 1 ] && [ "$_net_a" != "$NETWORK" ]; then
    warn "node-a reports node_network='$_net_a' but this harness is configured NETWORK='$NETWORK' — is a stray node bound to node-a's ports?"
fi
if [ "$_b_up" -eq 1 ] && [ "$_net_b" != "$NETWORK" ]; then
    warn "node-b reports node_network='$_net_b' but this harness is configured NETWORK='$NETWORK' — is a stray node bound to node-b's ports?"
fi

# The --palw-enable-algo4 consistency caveat. LOUD when any node is already up
# (we cannot restart it and cannot introspect its flag); a one-line reminder on
# a clean start.
if [ "$_a_up" -eq 1 ] || [ "$_b_up" -eq 1 ]; then
    warn "############################################################"
    warn "#  --palw-enable-algo4 CONSISTENCY (NOT verifiable via RPC) #"
    warn "############################################################"
    warn "One or more nodes are ALREADY running. --palw-enable-algo4 is a"
    warn "START-TIME override of the shipped palw_algo4_accept=false and is"
    warn "NOT exposed over RPC, so preflight cannot confirm it. It MUST be"
    warn "identical on EVERY node (all or none — never a subset)."
    warn "This host is configured PALW_ENABLE_ALGO4=${PALW_ENABLE_ALGO4:-unset}."
    warn "If any already-running node was started WITHOUT the same setting,"
    warn "stop the whole set and restart it consistently before proceeding."
    warn "############################################################"
else
    log "no node currently up on the configured RPC endpoints — clean start"
    log "reminder: start EVERY node with the same --palw-enable-algo4 setting (PALW_ENABLE_ALGO4=${PALW_ENABLE_ALGO4:-unset}); it cannot be checked over RPC"
fi

# -----------------------------------------------------------------------------
# Summary.
# -----------------------------------------------------------------------------
_peer_note=""
if [ -n "${PEER_BINARY_HASHES:-}" ]; then _peer_note=" + peer-agreed"; fi
log "preflight OK: env validated, binaries hashed$_peer_note, data dirs ready under $PALW_DATA_ROOT (NETWORK=$NETWORK, TICKET_MODE=$TICKET_MODE)"
