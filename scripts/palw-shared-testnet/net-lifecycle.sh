#!/usr/bin/env bash
# =============================================================================
# net-lifecycle.sh — controller-side SAFE stop / restart / freeze / verify for a
# LIVE multi-host PALW net (roadmap items 1 & 2). Runs on the CONTROLLER and
# drives each node ONLY through its host agent (node_dispatch) + host-local
# queries over the pinned-hostkey SSH transport. It never deletes chain data,
# keys, the manifest, binaries, or the coinbase-proof block, and it NEVER touches
# an unrelated deployment on the same hosts (it acts only on this net's ports /
# appdir / supervised names).
#
#   usage:  ./net-lifecycle.sh freeze [TAG]     # snapshot the RC baseline (live)
#           ./net-lifecycle.sh safe-stop        # ordered graceful shutdown
#           ./net-lifecycle.sh safe-restart     # bring the net back + re-verify
#           ./net-lifecycle.sh verify           # health snapshot
#           ./net-lifecycle.sh --help
#
# SAFE-STOP order (your spec): save artifacts -> stop miner -> WAIT both nodes
# converge to the same (daa, sink) -> stop node B -> stop node A (bootstrap, last)
# -> verify PIDs/ports clean. SAFE-RESTART: start A -> start B -> P2P reconnect ->
# re-verify manifest (idle) -> resume miner -> converge.
#
# The supporting miner runs on node A's host; its config is persisted at
# $NODE_A_DATA/miner.env (MINER_POOL/MINER_NETWORK/MINER_ADDR/MINER_INTERVAL_MS).
# Override the miner match / data dir via MINER_MATCH / NODE_A_DATA if needed.
#
# All shared behaviour lives in common.sh / remote.sh and is CALLED, not
# reimplemented.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$SCRIPT_DIR/common.sh"
# shellcheck source=remote.sh
. "$SCRIPT_DIR/remote.sh"

PALW_LOG_TAG="${PALW_LOG_TAG:-net-lifecycle}"; export PALW_LOG_TAG

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

ACTION="${1:-}"
case "$ACTION" in
    -h|--help|help|"") usage; [ -z "$ACTION" ] && exit 2 || exit 0 ;;
    freeze|safe-stop|safe-restart|verify) : ;;
    *) usage; echo "unknown action '$ACTION'" >&2; exit 2 ;;
esac

load_env

# Tunables.
NODE_A_DATA="${NODE_A_DATA:-/home/ubuntu/palw/data}"   # node A host data dir (holds miner.env)
MINER_MATCH="${MINER_MATCH:-misaminer.*$A_GRPC_PORT}"  # pgrep pattern for the supporting miner
CONVERGE_TIMEOUT="${CONVERGE_TIMEOUT:-90}"             # seconds to wait for A/B convergence
Q_TIMEOUT="${Q_TIMEOUT:-12}"                           # per host-local query timeout (Linux `timeout`)

# _remote_val <a|b> — path to kaspa-pq-validator on that node's host (from its harness dir).
_remote_val() {
    local dir
    case "$(_node_label "$1")" in
        a) dir="${A_REMOTE_DIR:-$COMMON_SH_DIR}" ;;
        b) dir="${B_REMOTE_DIR:-$COMMON_SH_DIR}" ;;
    esac
    printf '%s/target/release/kaspa-pq-validator\n' "${dir%/scripts/palw-shared-testnet}"
}
# _wrpc_port <a|b> — the node's OWN loopback wRPC port on its host.
_wrpc_port() { case "$(_node_label "$1")" in a) printf '%s' "$A_WRPC_PORT" ;; b) printf '%s' "$B_WRPC_PORT" ;; esac; }

# _node_daa_sink <a|b> — query the node HOST-LOCAL (robust: the node's own loopback
#   wRPC + Linux `timeout`, never the controller tunnel which can stall under load).
#   Echoes "<daa>|<sink-hash>" or "|" on failure. NEVER returns non-zero (a query
#   hiccup must not abort an in-progress stop under set -e).
_node_daa_sink() {
    local n="$1" val port out
    val="$(_remote_val "$n")"; port="$(_wrpc_port "$n")"
    out="$(remote_exec "$n" "timeout $Q_TIMEOUT '$val' palw-status --node-rpc 127.0.0.1:$port --network '$NETWORK' 2>/dev/null" 2>/dev/null \
        | awk -F': ' '/^sink:/{s=$2} /sink_daa_score/{d=$2} END{printf "%s|%s", d, s}')" || true
    printf '%s' "$out"
}

# _wait_converge — poll until A and B report the SAME (daa, sink), or timeout.
_wait_converge() {
    local deadline=$(( $(date +%s) + CONVERGE_TIMEOUT )) a b
    log "waiting for node A/B to converge to the same (daa, sink) [timeout ${CONVERGE_TIMEOUT}s]"
    while :; do
        a="$(_node_daa_sink a)"; b="$(_node_daa_sink b)"
        if [ -n "${a#*|}" ] && [ "$a" = "$b" ]; then
            log "converged: both nodes at daa=${a%%|*} sink=$(printf '%s' "${a#*|}" | cut -c1-24)…"
            return 0
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            warn "convergence not reached in ${CONVERGE_TIMEOUT}s (A=${a%%|*} B=${b%%|*}); proceeding — inspect before trusting a clean stop"
            return 1
        fi
        sleep 3
    done
}

_miner_stop() {
    log "stopping the supporting miner on node A's host (match: $MINER_MATCH)"
    # Best-effort, never abort the stop: pkill returns non-zero when nothing
    # matched, and the query can hiccup — all swallowed so the node stops still run.
    remote_exec a "pkill -f '$MINER_MATCH' 2>/dev/null; sleep 1; pkill -9 -f '$MINER_MATCH' 2>/dev/null; true" >/dev/null 2>&1 || true
    log "miner stop signalled"
    return 0
}

_miner_start() {
    log "resuming the supporting miner on node A's host (from $NODE_A_DATA/miner.env)"
    local miner="${A_REMOTE_DIR%/scripts/palw-shared-testnet}/target/release/misaminer"
    remote_exec a "set -a; . '$NODE_A_DATA/miner.env'; set +a; nohup '$miner' --pool \"\$MINER_POOL\" --network-id \"\$MINER_NETWORK\" --wallet \"\$MINER_ADDR\" --min-block-interval-ms \"\$MINER_INTERVAL_MS\" > '$NODE_A_DATA/logs/miner.log' 2>&1 & echo miner-pid \$!"
}

# _clean_report <a|b> — this net's leftover procs/ports on the host (NOT the
#   unrelated netsuffix=10 deployment, which we deliberately do not touch).
_clean_report() {
    local n="$1" port_a="$A_P2P_PORT" port_b="$B_P2P_PORT"
    remote_exec "$n" "
        echo '  this-net kaspad (appdir palw/data):'; pgrep -af 'kaspad.*palw/data' | sed 's/^/    /' || echo '    none';
        echo '  this-net miner:'; pgrep -af '$MINER_MATCH' | sed 's/^/    /' || echo '    none';
        echo '  this-net ports ($port_a/$port_b/${A_GRPC_PORT}/${B_GRPC_PORT}/${A_WRPC_PORT}/${B_WRPC_PORT}):'; ss -lntp 2>/dev/null | grep -E ':($port_a|$port_b|${A_GRPC_PORT}|${B_GRPC_PORT}|${A_WRPC_PORT}|${B_WRPC_PORT})\b' | sed 's/^/    /' || echo '    none';
        echo '  untouched netsuffix=10 (must still be present):'; pgrep -af 'kaspad.*netsuffix=10' | sed 's/^/    /' | head -1 || echo '    (none found)';
        echo '  disk:'; df -h \$HOME 2>/dev/null | awk 'NR==2{print \"    \"\$4\" free\"}'
    "
}

case "$ACTION" in
freeze)
    TAG="${2:-rc-$(state_get RUNALL_LAST_OK >/dev/null 2>&1; git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo baseline)}"
    RC="$PALW_DATA_ROOT/artifacts/rc-$TAG"
    install -d -m 0755 "$RC"
    log "freezing RC baseline -> $RC"
    # 1. consensus identity of both live nodes (server-side).
    for n in a b; do
        val="$(_remote_val "$n")"; port="$(_wrpc_port "$n")"
        remote_exec "$n" "timeout $Q_TIMEOUT '$val' status --node-rpc 127.0.0.1:$port --network '$NETWORK' 2>/dev/null" > "$RC/node-$n-identity.txt" || true
    done
    # 2. coinbase-proof block: the current sink, fetched from BOTH nodes (subsidy = the live emission).
    a="$(_node_daa_sink a)"; SINK="${a#*|}"
    if [ -n "$SINK" ]; then
        for n in a b; do
            val="$(_remote_val "$n")"; port="$(_wrpc_port "$n")"
            remote_exec "$n" "timeout $Q_TIMEOUT '$val' get-block --hash '$SINK' --node-wrpc-borsh 127.0.0.1:$port --network '$NETWORK' 2>/dev/null" > "$RC/coinbase-proof.node-$n.txt" || true
        done
    fi
    # 3. manifest + hashes + status doc.
    for f in network-manifest.json network-manifest.json.sig network-manifest.json.signers binary-hashes.txt; do
        [ -f "$PALW_DATA_ROOT/artifacts/$f" ] && cp "$PALW_DATA_ROOT/artifacts/$f" "$RC/" || true
    done
    [ -f "$SCRIPT_DIR/P0-P2-STATUS.md" ] && cp "$SCRIPT_DIR/P0-P2-STATUS.md" "$RC/"
    # 4. README baseline.
    {
        printf 'PALW shared-testnet release-candidate baseline\n'
        printf 'tag:          %s\n' "$TAG"
        printf 'commit:       %s\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf 'network:      %s (netsuffix %s)\n' "$NETWORK" "$NETSUFFIX"
        printf 'nodes:        A=%s:%s  B=%s:%s\n' "$NODE_A_HOST" "$A_P2P_PORT" "$NODE_B_HOST" "$B_P2P_PORT"
        printf 'sink@freeze:  %s (daa %s)\n' "$SINK" "${a%%|*}"
        printf 'coinbase S:   %s\n' "$(awk -F': ' '/coinbase_subsidy/{print $2" sompi"}' "$RC/coinbase-proof.node-a.txt" 2>/dev/null)"
        printf 'params_hash:  %s\n' "$(awk -F': ' '/node_params_hash/{print $2}' "$RC/node-a-identity.txt" 2>/dev/null)"
        printf 'genesis_hash: %s\n' "$(awk -F': ' '/node_genesis_hash/{print $2}' "$RC/node-a-identity.txt" 2>/dev/null | awk '{print $1}')"
    } > "$RC/RC-README.txt"
    log "RC baseline frozen: $RC"
    cat "$RC/RC-README.txt"
    ;;

safe-stop)
    # Orchestration path: prefer explicit guards over set -e so a single query /
    # ssh hiccup can NEVER leave the net half-stopped (the node stops must run).
    set +e
    log "SAFE-STOP: artifacts -> miner -> converge -> node B -> node A (bootstrap last)"
    # 1. best-effort artifact snapshot (never blocks the stop).
    "$SCRIPT_DIR/net-lifecycle.sh" freeze "prestop-$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo x)" >/dev/null 2>&1 || warn "artifact freeze skipped (non-fatal)"
    # 2. stop the miner FIRST so the DAG can quiesce.
    _miner_stop
    # 3. WAIT for both nodes to converge (your gate: same DAA + sink before stopping).
    _wait_converge || true
    # 4. stop node B, then node A (bootstrap) LAST — each via its host agent.
    log "stopping node B via its host agent"
    node_dispatch b stop || warn "node B stop reported an issue"
    log "stopping node A (bootstrap) via its host agent"
    node_dispatch a stop || warn "node A stop reported an issue"
    # 5. verify clean (this net only; the unrelated netsuffix=10 net is left running).
    log "post-stop verification (this net's procs/ports; netsuffix=10 left untouched):"
    for n in a b; do echo "node-$n host ($(node_ssh_host "$n")):"; _clean_report "$n"; done
    log "SAFE-STOP complete. Chain data / keys / manifest / binaries / proof block preserved."
    ;;

safe-restart)
    set +e
    log "SAFE-RESTART: start A -> start B -> P2P -> manifest re-verify -> miner -> converge"
    node_dispatch a start a bootstrap || die "node A start failed"
    node_dispatch b start b bootstrap || die "node B start failed"
    log "re-verifying the signed manifest against both live nodes (miner idle)"
    "$SCRIPT_DIR/network-manifest.sh" verify || warn "manifest re-verify reported an issue — inspect before trusting the restart"
    _miner_start
    _wait_converge || true
    log "SAFE-RESTART complete."
    ;;

verify)
    log "health snapshot:"
    for n in a b; do
        ds="$(_node_daa_sink "$n")"
        printf 'node-%s (%s): daa=%s sink=%s\n' "$(_node_label "$n")" "$(node_ssh_host "$n")" "${ds%%|*}" "$(printf '%s' "${ds#*|}" | cut -c1-24)…"
    done
    a="$(_node_daa_sink a)"; b="$(_node_daa_sink b)"
    [ -n "${a#*|}" ] && [ "$a" = "$b" ] && log "A/B at the SAME sink (converged)" || warn "A/B not at the same sink right now (may be mid-mining)"
    ;;
esac
exit 0
