#!/usr/bin/env bash
# negative-tests.sh — STN / G7 failure-and-recovery cases for the closed two-node
# PALW testnet. Each case perturbs the running net and asserts it recovers to a
# consistent state (both nodes up, peered, synced, SAME sink). Fail-closed: any
# case that does not recover exits non-zero with an actionable message.
#
# PREREQUISITE: a running 2-node net (./run-all.sh has brought up node-a + node-b +
# supporting-miner). These cases do NOT need a mint:
#   restart-a            node A restart -> re-sync -> same sink
#   restart-b            node B restart -> re-peer -> re-sync -> same sink
#   partition-reconnect  drop node B (partition proxy) -> A survives -> B rejoins -> same sink
#
# The following cases REQUIRE the mint path (TICKET_MODE=mock + an actually-minted
# algo-4 block, which needs a Healthy beacon to open activation — see PHASE0-status
# G3/G4/G5). They are wired as explicit SKIPs here until a mint is reproducible, so
# the harness never pretends to have tested what it cannot yet reach:
#   wrong-authority      submit a leaf-chunk with a mismatched ticket authority -> reject
#   duplicate-submit     re-submit an already-registered leaf -> idempotent/reject
#   reorg-parity         after a reorg, A and B agree on the selected sink
#
# usage:  ./negative-tests.sh [ all | <case> | list ]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd -P)"
PALW_LOG_TAG="${PALW_LOG_TAG:-neg-tests}"; export PALW_LOG_TAG
# shellcheck source=common.sh
. "$SCRIPT_DIR/common.sh"

CASES="restart-a restart-b partition-reconnect wrong-authority duplicate-submit reorg-parity"
NET_CASES="restart-a restart-b partition-reconnect"          # runnable without a mint
MINT_CASES="wrong-authority duplicate-submit reorg-parity"   # need a reproducible mint

# assert_healthy <a|b> — the standard post-perturbation recovery gate for one node.
assert_healthy() {
    local n="$1"
    wait_rpc_up        "$n" || die "G7: node-$n RPC did not come back up"
    wait_peer_connected "$n" || die "G7: node-$n did not re-establish its P2P peer"
    wait_node_synced   "$n" || die "G7: node-$n did not re-sync after the perturbation"
}

# assert_converged — both nodes up, peered, synced, and on the SAME sink.
assert_converged() {
    assert_healthy a
    assert_healthy b
    wait_same_sink || die "G7: nodes A and B did not converge to the same sink after recovery"
    log "G7: recovered — A and B are up, peered, synced, and on the same sink."
}

t_restart_a() {
    log "G7 restart-a: restarting node A (in-process validator/beacon) and asserting re-sync."
    bash "$SCRIPT_DIR/restart-a-synced.sh" || die "G7 restart-a: restart-a-synced.sh failed"
    assert_converged
    log "G7 restart-a: PASS"
}

t_restart_b() {
    log "G7 restart-b: stop+start node B and assert it re-peers, re-syncs, same sink."
    bash "$SCRIPT_DIR/node-b.sh" stop  || die "G7 restart-b: node-b stop failed"
    wait_rpc_up a || die "G7 restart-b: node A must stay up while B is down"
    bash "$SCRIPT_DIR/node-b.sh" start || die "G7 restart-b: node-b start failed"
    assert_converged
    log "G7 restart-b: PASS"
}

t_partition_reconnect() {
    # Single-host partition proxy: dropping node B severs the only A<->B link, so A
    # is isolated; restarting B forces a fresh handshake + catch-up. A TRUE network
    # partition (both nodes up, link cut) needs host-level firewalling on separate
    # hosts (iptables/pfctl on the P2P port) — documented, not simulated here.
    log "G7 partition-reconnect: sever A<->B (stop B), verify A survives, then rejoin B and re-converge."
    bash "$SCRIPT_DIR/node-b.sh" stop || die "G7 partition: node-b stop failed"
    wait_rpc_up a || die "G7 partition: node A did not survive the partition"
    log "G7 partition: node A survived isolation; reconnecting node B."
    bash "$SCRIPT_DIR/node-b.sh" start || die "G7 partition: node-b rejoin failed"
    assert_converged
    warn "G7 partition-reconnect: PASS (single-host proxy). A real link-cut partition test requires host-level firewalling on two separate hosts."
}

_skip_mint_case() {
    warn "G7 $1: SKIP — requires a reproducible algo-4 mint (TICKET_MODE=mock + Healthy beacon opening activation; see PHASE0-status G3/G4/G5). Not run so the harness never reports an untested pass."
}
t_wrong_authority()  { _skip_mint_case wrong-authority; }
t_duplicate_submit() { _skip_mint_case duplicate-submit; }
t_reorg_parity()     { _skip_mint_case reorg-parity; }

run_case() {
    case "$1" in
        restart-a)           t_restart_a ;;
        restart-b)           t_restart_b ;;
        partition-reconnect) t_partition_reconnect ;;
        wrong-authority)     t_wrong_authority ;;
        duplicate-submit)    t_duplicate_submit ;;
        reorg-parity)        t_reorg_parity ;;
        *) die "unknown case '$1' — one of: $CASES (or 'all' / 'list')" ;;
    esac
}

ACTION="${1:-all}"
case "$ACTION" in
    -h|--help|help) printf 'usage: ./negative-tests.sh [ all | <case> | list ]\ncases: %s\n' "$CASES"; exit 0 ;;
    list|--list)    printf 'net-runnable (no mint): %s\nmint-required (skipped): %s\n' "$NET_CASES" "$MINT_CASES"; exit 0 ;;
    all)
        load_env
        log "G7: running failure/recovery cases against the running 2-node net. Mint-dependent cases are SKIPPED (honest)."
        for c in $NET_CASES; do run_case "$c"; done
        for c in $MINT_CASES; do run_case "$c"; done
        log "G7: net-runnable cases complete. Mint-dependent cases were skipped (require a reproducible mint)."
        ;;
    *)  load_env; run_case "$ACTION" ;;
esac
