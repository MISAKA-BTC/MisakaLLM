#!/usr/bin/env bash
# negative-tests.sh — STN / G7 failure-and-recovery cases for the closed two-node
# PALW testnet, as a RELEASE GATE (review §9): every case reports PASS / FAIL /
# SKIP, the counts are machine-readable, and a SKIP is never a pass.
#
# PREREQUISITE: a running 2-node net (./run-all.sh has brought up node-a + node-b +
# supporting-miner). These cases do NOT need a mint:
#   restart-a            node A FORCE restart via its host agent (pid must change)
#                        -> re-sync -> same sink   (§9.3 fix: never a no-op)
#   restart-b            node B FORCE restart via its host agent -> re-peer -> same sink
#   partition-reconnect  drop node B (partition proxy) -> A survives -> B rejoins -> same sink
#
# The following cases REQUIRE the mint path (TICKET_MODE=mock + an actually-minted
# algo-4 block; real mints are currently blocked by unshipped DA/auditor/beacon
# infra — see PHASE0-status G3/G4/G5):
#   wrong-authority      submit a leaf-chunk with a mismatched ticket authority -> reject
#   duplicate-submit     re-submit an already-registered leaf -> idempotent/reject
#   reorg-parity         after a reorg, A and B agree on the selected sink
# SKIP vs FAIL is decided from EVIDENCE, not mode: with no recorded mint evidence a
# mint case SKIPs (structurally unreachable — honest); with mint evidence present an
# unimplemented case FAILs (its precondition is met; implement or explicitly waive).
#
# RESULT CONTRACT (review §9.5):
#   * per-case line:      `neg.case: <name> result=<PASS|FAIL|SKIP> [reason=...]`
#   * final summary line: `neg.result: pass=<n> fail=<n> skip=<n>`
#   * JSON report:        $PALW_DATA_ROOT/artifacts/negative-tests.json
#   * exit code:          non-zero iff fail>0, OR (NEG_RELEASE=1 and an UNJUSTIFIED
#                         skip occurred). Justified skip = mint case with no mint
#                         evidence. `all` therefore stays exit-0 on an honest
#                         skip-mode run while release mode still fail-closes on
#                         anything that should have run but did not.
#
# usage:  ./negative-tests.sh [ all | <case> | list ]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd -P)"
PALW_LOG_TAG="${PALW_LOG_TAG:-neg-tests}"; export PALW_LOG_TAG
# shellcheck source=common.sh
. "$SCRIPT_DIR/common.sh"
# shellcheck source=remote.sh
. "$SCRIPT_DIR/remote.sh"   # node_dispatch — restarts run via each node's HOST agent (§9.3)

CASES="restart-a restart-b partition-reconnect wrong-authority duplicate-submit reorg-parity"
NET_CASES="restart-a restart-b partition-reconnect"          # runnable without a mint
MINT_CASES="wrong-authority duplicate-submit reorg-parity"   # need a reproducible mint

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; UNJUSTIFIED_SKIPS=0
RESULTS=""   # space-list of "<case>=<RESULT>" for the JSON report

# _record <case> <PASS|FAIL|SKIP> [reason]
_record() {
    local name="$1" result="$2" reason="${3:-}"
    case "$result" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac
    RESULTS="$RESULTS $name=$result"
    if [ -n "$reason" ]; then
        printf 'neg.case: %s result=%s reason=%s\n' "$name" "$result" "$reason"
    else
        printf 'neg.case: %s result=%s\n' "$name" "$result"
    fi
}

# assert_healthy <a|b> — the standard post-perturbation recovery gate for one node.
assert_healthy() {
    local n="$1"
    wait_rpc_up        "$n" || { warn "G7: node-$n RPC did not come back up"; return 1; }
    wait_peer_connected "$n" || { warn "G7: node-$n did not re-establish its P2P peer"; return 1; }
    wait_node_synced   "$n" || { warn "G7: node-$n did not re-sync after the perturbation"; return 1; }
}

# assert_converged — both nodes up, peered, synced, and on the SAME sink.
assert_converged() {
    assert_healthy a || return 1
    assert_healthy b || return 1
    wait_same_sink || { warn "G7: nodes A and B did not converge to the same sink after recovery"; return 1; }
    log "G7: recovered — A and B are up, peered, synced, and on the same sink."
}

# _node_a_agent_mode — the mode to restart node A into, matching its CURRENT role
#   (validator when it runs the in-process validator; bootstrap otherwise). A
#   restart test must restart the SAME role, not silently change the topology.
_node_a_agent_mode() {
    local pid cmd
    if pid="$(read_pid node-a 2>/dev/null)" && [ -n "$pid" ]; then
        cmd="$(_proc_cmd "$pid")"
        case "$cmd" in
            *--palw-mine*)        printf 'miner\n'; return ;;
            *--enable-validator*) printf 'validator\n'; return ;;
        esac
    fi
    printf 'bootstrap\n'
}

t_restart_a() {
    # §9.3 fix: the restart runs through node A's HOST agent with --force, which
    # ASSERTS the pid/start-time changed — an idempotent no-op "restart" is a FAIL
    # inside the agent itself, never a silent pass here.
    local mode
    mode="$(_node_a_agent_mode)"
    log "G7 restart-a: FORCE-restarting node A via its host agent (mode=$mode; pid must change)."
    node_dispatch a restart a "$mode" --force || { _record restart-a FAIL "agent force-restart failed or pid unchanged"; return 1; }
    assert_converged || { _record restart-a FAIL "did not reconverge after restart"; return 1; }
    _record restart-a PASS
}

t_restart_b() {
    log "G7 restart-b: FORCE-restarting node B via its host agent (pid must change), assert re-peer + same sink."
    wait_rpc_up a || { _record restart-b FAIL "node A must be up before perturbing B"; return 1; }
    node_dispatch b restart b bootstrap --force || { _record restart-b FAIL "agent force-restart failed or pid unchanged"; return 1; }
    assert_converged || { _record restart-b FAIL "did not reconverge after restart"; return 1; }
    _record restart-b PASS
}

t_partition_reconnect() {
    # Single-host partition proxy: dropping node B severs the only A<->B link, so A
    # is isolated; restarting B forces a fresh handshake + catch-up. A TRUE network
    # partition (both nodes up, link cut) needs host-level firewalling on separate
    # hosts (iptables/pfctl on the P2P port) — documented, not simulated here.
    log "G7 partition-reconnect: sever A<->B (stop B), verify A survives, then rejoin B and re-converge."
    node_dispatch b stop b || { _record partition-reconnect FAIL "node-b stop failed"; return 1; }
    wait_rpc_up a || { _record partition-reconnect FAIL "node A did not survive the partition"; return 1; }
    log "G7 partition: node A survived isolation; reconnecting node B."
    node_dispatch b start b bootstrap || { _record partition-reconnect FAIL "node-b rejoin failed"; return 1; }
    assert_converged || { _record partition-reconnect FAIL "did not reconverge after rejoin"; return 1; }
    _record partition-reconnect PASS "single-host proxy; true link-cut partition needs two hosts + firewall"
}

# _mint_case <name> — SKIP/FAIL decision from EVIDENCE (review §9.5): no recorded
#   mint ⇒ justified SKIP; mint evidence present ⇒ the case's precondition is met
#   and an unimplemented case is a FAIL (implement it or explicitly waive).
_mint_case() {
    local name="$1" hA
    hA="$(state_get PALW_ALGO4_BLOCK_HASH_A || true)"
    if [ -z "$hA" ]; then
        _record "$name" SKIP "no algo-4 mint evidence recorded (real mints blocked by unshipped DA/auditor/beacon infra; see PHASE0-status G5)"
        return 0
    fi
    _record "$name" FAIL "mint evidence exists ($hA) but this case is NOT implemented — implement the negative case or explicitly waive it"
    return 1
}
t_wrong_authority()  { _mint_case wrong-authority; }
t_duplicate_submit() { _mint_case duplicate-submit; }
t_reorg_parity()     { _mint_case reorg-parity; }

run_case() {
    local rc=0
    case "$1" in
        restart-a)           t_restart_a || rc=1 ;;
        restart-b)           t_restart_b || rc=1 ;;
        partition-reconnect) t_partition_reconnect || rc=1 ;;
        wrong-authority)     t_wrong_authority || rc=1 ;;
        duplicate-submit)    t_duplicate_submit || rc=1 ;;
        reorg-parity)        t_reorg_parity || rc=1 ;;
        *) die "unknown case '$1' — one of: $CASES (or 'all' / 'list')" ;;
    esac
    return "$rc"
}

# _finish — emit the machine-readable summary + JSON report and pick the exit code.
_finish() {
    printf 'neg.result: pass=%s fail=%s skip=%s\n' "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
    # JSON report (review §9.6) — written best-effort next to the other artifacts.
    local json="$PALW_DATA_ROOT/artifacts/negative-tests.json" first=1 pair name result
    {
        printf '{"schema":"palw-negative-tests-v1","pass":%s,"fail":%s,"skip":%s,"release_mode":%s,"cases":{' \
            "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT" "$( [ "${NEG_RELEASE:-0}" = "1" ] && printf true || printf false )"
        for pair in $RESULTS; do
            name="${pair%%=*}"; result="${pair#*=}"
            [ "$first" = "1" ] || printf ','
            first=0
            printf '"%s":"%s"' "$name" "$result"
        done
        printf '}}\n'
    } > "$json" 2>/dev/null || warn "could not write $json"
    log "G7 report -> $json"

    if [ "$FAIL_COUNT" -gt 0 ]; then
        die "G7: $FAIL_COUNT case(s) FAILED — see the neg.case lines above."
    fi
    # Release gate (review §9.5): in release mode a skip is tolerated ONLY when it
    # is structurally justified (mint case without mint evidence). Any other skip
    # means something that should have run did not — NO-GO.
    if [ "${NEG_RELEASE:-0}" = "1" ] && [ "$UNJUSTIFIED_SKIPS" -gt 0 ]; then
        die "G7 release gate: $UNJUSTIFIED_SKIPS unjustified skip(s) — NO-GO."
    fi
    if [ "$SKIP_COUNT" -gt 0 ]; then
        log "G7: complete — pass=$PASS_COUNT, skip=$SKIP_COUNT (every skip is evidence-justified and reported; a skip is NOT a pass)."
    else
        log "G7: complete — all $PASS_COUNT case(s) passed, no skips."
    fi
    exit 0
}

ACTION="${1:-all}"
case "$ACTION" in
    -h|--help|help) printf 'usage: ./negative-tests.sh [ all | <case> | list ]\ncases: %s\nenv: NEG_RELEASE=1 -> unjustified skips are fatal (release gate)\n' "$CASES"; exit 0 ;;
    list|--list)    printf 'net-runnable (no mint): %s\nmint-required (evidence-gated SKIP/FAIL): %s\n' "$NET_CASES" "$MINT_CASES"; exit 0 ;;
    all)
        load_env
        log "G7: running failure/recovery cases against the running 2-node net (release_mode=${NEG_RELEASE:-0})."
        RC_ANY=0
        for c in $NET_CASES $MINT_CASES; do run_case "$c" || RC_ANY=1; done
        _finish
        ;;
    *)
        load_env
        run_case "$ACTION" || true
        _finish
        ;;
esac
