#!/usr/bin/env bash
# remote.sh — STN-014 / G2 multi-host transport helpers.
#
# Sourced by common.sh users to run start/stop/status/log/artifact operations
# against node A or node B whether the node is LOCAL (single-host, the default) or
# on a REMOTE host reached over SSH. A node is "remote" iff its ${A,B}_SSH_HOST env
# is set; otherwise every call runs locally, so single-host behaviour is unchanged.
#
# Security posture (matches the harness): RPC stays loopback on each node; the
# controller reaches a remote node's RPC only through an SSH `-L` tunnel (see
# A_WRPC_ENDPOINT / A_GRPC_ENDPOINT in env.example). SSH uses BatchMode (no
# password prompts) and pins the host key. Secrets are NEVER passed on argv.
#
# API (label is a|b):
#   node_ssh_host <a|b>            -> echoes the node's SSH host ("" if local)
#   node_is_remote <a|b>          -> exit 0 if remote, 1 if local
#   remote_exec <a|b> <cmd...>    -> run cmd on the node's host (local or via ssh)
#   remote_cat  <a|b> <path>      -> print a file from the node's host
#   remote_log_tail <a|b> [n]     -> tail -n N of the node's kaspad log
#   remote_pull <a|b> <src> <dst> -> copy a file FROM the node's host to local dst
#
# This file only defines functions; it never executes anything at source time.

# node_ssh_host <a|b> — the configured SSH target for that node, or "" (local).
node_ssh_host() {
    case "$(_node_label "$1")" in
        a) printf '%s\n' "${A_SSH_HOST:-}" ;;
        b) printf '%s\n' "${B_SSH_HOST:-}" ;;
    esac
}

# node_is_remote <a|b> — 0 (true) if an SSH host is configured for that node.
node_is_remote() { [ -n "$(node_ssh_host "$1")" ]; }

# _ssh <host> <cmd...> — batch-mode ssh with pinned host key. PALW_SSH_OPTS tunes it.
_ssh() {
    local host="$1"; shift
    # shellcheck disable=SC2086
    command ssh ${PALW_SSH_OPTS:--o BatchMode=yes -o StrictHostKeyChecking=accept-new} "$host" "$@"
}

# remote_exec <a|b> <cmd...> — run a command on the node's host. Local: exec directly.
# Remote: ssh. The command is passed as a single string to the remote shell, so quote
# arguments that must survive the remote shell yourself (helpers below do the common cases).
remote_exec() {
    local n="$1"; shift
    if node_is_remote "$n"; then
        _ssh "$(node_ssh_host "$n")" "$@"
    else
        "$@"
    fi
}

# remote_cat <a|b> <path> — print a file from the node's host (fails closed if absent).
remote_cat() {
    local n="$1" path="$2"
    if node_is_remote "$n"; then
        _ssh "$(node_ssh_host "$n")" "cat -- '$path'"
    else
        cat -- "$path"
    fi
}

# remote_log_tail <a|b> [n] — tail the node's kaspad log (node_log path is host-local,
# identical layout on every host since PALW_DATA_ROOT is per-host).
remote_log_tail() {
    local n="$1" lines="${2:-200}" path
    path="$(node_log "$n")"
    if node_is_remote "$n"; then
        _ssh "$(node_ssh_host "$n")" "tail -n ${lines} -- '$path' 2>/dev/null || true"
    else
        tail -n "$lines" -- "$path" 2>/dev/null || true
    fi
}

# remote_pull <a|b> <src-on-node-host> <local-dst> — copy a file back to the controller.
# Local: cp. Remote: scp over the same pinned-host-key SSH config.
remote_pull() {
    local n="$1" src="$2" dst="$3" host
    if node_is_remote "$n"; then
        host="$(node_ssh_host "$n")"
        # shellcheck disable=SC2086
        command scp ${PALW_SSH_OPTS:--o BatchMode=yes -o StrictHostKeyChecking=accept-new} "$host:$src" "$dst"
    else
        cp -- "$src" "$dst"
    fi
}

# preflight_ssh <a|b> — verify a remote node is reachable over SSH before the run
# depends on it (no-op for a local node). Fail-closed with an actionable message.
preflight_ssh() {
    local n="$1" host
    node_is_remote "$n" || return 0
    host="$(node_ssh_host "$n")"
    if _ssh "$host" 'true' >/dev/null 2>&1; then
        log "remote reachable: node-$n via ssh $host"
    else
        die "node-$n is configured remote (SSH host '$host') but 'ssh $host true' failed — check connectivity, the host key, and key-based auth (PALW_SSH_OPTS='${PALW_SSH_OPTS:-}'). RPC must be reached via an SSH -L tunnel (A_WRPC_ENDPOINT/B_WRPC_ENDPOINT), never a public bind."
    fi
}
