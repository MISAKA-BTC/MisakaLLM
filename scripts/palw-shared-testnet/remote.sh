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
#   remote_preflight_hostkey <a|b>-> fail-closed unless the node's SSH host key is
#                                    PINNED in PALW_KNOWN_HOSTS (condition 6)
#   node_dispatch <a|b> <verb> .. -> run palw-node-agent.sh <verb> on the node's
#                                    host (local exec single-host / ssh remote).
#                                    THE control-plane entry point: every node
#                                    mutation the controller triggers goes through
#                                    this, so the controller owns no node pid/secret.
#
# Host-key posture (§5.3 SSH hardening / §5.4 condition 6): the default SSH policy
# is FAIL-CLOSED — StrictHostKeyChecking=yes against a PINNED UserKnownHostsFile
# (PALW_KNOWN_HOSTS, default $PALW_DATA_ROOT/artifacts/known_hosts), IdentitiesOnly,
# PermitLocalCommand=no. A host-key MISMATCH aborts the connection (ssh refuses).
# First-connect TOFU is a deliberate, opt-in relaxation only (PALW_SSH_TOFU=1).
# An explicit PALW_SSH_OPTS overrides the computed policy verbatim (operator escape
# hatch). Secrets are NEVER passed on argv.
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

# _ssh_opts — echo the fail-closed SSH option string (condition 6). An explicit
#   PALW_SSH_OPTS overrides it verbatim; otherwise host-key checking is STRICT
#   against the pinned known_hosts, relaxed to first-connect TOFU only when
#   PALW_SSH_TOFU=1 is set on purpose.
_ssh_opts() {
    if [ -n "${PALW_SSH_OPTS:-}" ]; then printf '%s' "$PALW_SSH_OPTS"; return; fi
    local kh strict="yes"
    kh="${PALW_KNOWN_HOSTS:-${PALW_DATA_ROOT:-.}/artifacts/known_hosts}"
    [ "${PALW_SSH_TOFU:-0}" = "1" ] && strict="accept-new"
    printf -- '-o BatchMode=yes -o StrictHostKeyChecking=%s -o IdentitiesOnly=yes -o PermitLocalCommand=no -o UserKnownHostsFile=%s' \
        "$strict" "$kh"
}

# _ssh <host> <cmd...> — batch-mode ssh with a fail-closed, pinned host-key policy.
_ssh() {
    local host="$1"; shift
    # shellcheck disable=SC2086
    command ssh $(_ssh_opts) "$host" "$@"
}

# _shq <args...> — single-quote & space-join args so they survive ONE remote
#   shell hop intact (verbs/paths only; secrets never travel this path).
_shq() {
    local a out=""
    for a in "$@"; do
        out="$out '$(printf '%s' "$a" | sed "s/'/'\\\\''/g")'"
    done
    printf '%s' "${out# }"
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
        remote_preflight_hostkey "$n" || return 1
        host="$(node_ssh_host "$n")"
        # shellcheck disable=SC2086
        command scp $(_ssh_opts) "$host:$src" "$dst"
    else
        cp -- "$src" "$dst"
    fi
}

# remote_preflight_hostkey <a|b> — FAIL-CLOSED unless the remote node's SSH host
#   key is already PINNED in the known_hosts file (condition 6). No-op for a local
#   node, or when PALW_SSH_TOFU=1 deliberately allows first-connect pinning. This
#   is the EARLY, clear check; ssh's StrictHostKeyChecking=yes is the enforcement
#   that also rejects a MISMATCH (a changed key) at connect time.
remote_preflight_hostkey() {
    local n="$1" host hn kh
    node_is_remote "$n" || return 0
    [ "${PALW_SSH_TOFU:-0}" = "1" ] && return 0
    host="$(node_ssh_host "$n")"
    hn="${host##*@}"; hn="${hn%%:*}"
    kh="${PALW_KNOWN_HOSTS:-${PALW_DATA_ROOT:-.}/artifacts/known_hosts}"
    [ -f "$kh" ] || die "node-$n is remote but the pinned known_hosts is missing: $kh — provision it (ssh-keyscan -H '$hn' >> '$kh' AFTER verifying the fingerprint out-of-band), then re-run. Refusing first-connect TOFU by default; set PALW_SSH_TOFU=1 only for a deliberate initial pin."
    if ! ssh-keygen -F "$hn" -f "$kh" >/dev/null 2>&1; then
        die "node-$n host key for '$hn' is NOT pinned in $kh — fail-closed. Add it (ssh-keyscan -H '$hn' >> '$kh') after verifying the fingerprint out-of-band, then re-run."
    fi
    return 0
}

# preflight_ssh <a|b> — verify a remote node is reachable over SSH before the run
# depends on it (no-op for a local node). Fail-closed with an actionable message.
# Checks the host-key PIN first (condition 6), then a live BatchMode probe.
preflight_ssh() {
    local n="$1" host
    node_is_remote "$n" || return 0
    remote_preflight_hostkey "$n"
    host="$(node_ssh_host "$n")"
    if _ssh "$host" 'true' >/dev/null 2>&1; then
        log "remote reachable: node-$n via ssh $host (host key pinned)"
    else
        die "node-$n is configured remote (SSH host '$host') but 'ssh $host true' failed — check connectivity, the pinned host key (PALW_KNOWN_HOSTS=${PALW_KNOWN_HOSTS:-<data>/artifacts/known_hosts}), and key-based auth. RPC must be reached via an SSH -L tunnel (A_WRPC_ENDPOINT/B_WRPC_ENDPOINT), never a public bind."
    fi
}

# node_dispatch <a|b> <verb> [args...] — run palw-node-agent.sh <verb> on the
#   node's OWN host and stream its stdout/stderr back. Single-host (node local):
#   a plain local exec of the agent. Two-host (node remote): ssh into the pinned
#   host and run the agent from the harness dir there (identical layout per host).
#   This is the ONE call every node-mutating stage uses, so a controller never
#   restarts a node itself and never holds its pid file or seed (conditions 1-3).
#   Secrets never travel this path — only verbs, labels, and public paths do.
node_dispatch() {
    local n="$1" verb="$2"; shift 2
    if node_is_remote "$n"; then
        remote_preflight_hostkey "$n" || return 1
        local host dir
        host="$(node_ssh_host "$n")"
        # The harness dir on the remote host. Defaults to the SAME absolute path as
        # here (hosts are provisioned identically); override with PALW_REMOTE_DIR.
        dir="${PALW_REMOTE_DIR:-$COMMON_SH_DIR}"
        _ssh "$host" "cd $(_shq "$dir") && PALW_LOG_TAG=node-agent bash ./palw-node-agent.sh $verb $(_shq "$@")"
    else
        local agent="$COMMON_SH_DIR/palw-node-agent.sh"
        [ -f "$agent" ] || die "node_dispatch: palw-node-agent.sh not found at $agent (the host-local agent ships with the harness)"
        PALW_LOG_TAG=node-agent bash "$agent" "$verb" "$@"
    fi
}
