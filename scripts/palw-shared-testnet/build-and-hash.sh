#!/usr/bin/env bash
# =============================================================================
# build-and-hash.sh — build the three PALW release binaries and record their
#                     SHA-256 for cross-host comparison (STN-001).
#
# Stage job (one thing): from REPO_ROOT run
#     cargo build --release -p kaspad -p kaspa-pq-validator -p misaminer
# then write the SHA-256 of each produced binary to
#     $PALW_DATA_ROOT/artifacts/binary-hashes.txt
# so a second host can prove it runs a byte-identical build (preflight.sh
# hash-compares this file). This is STN-001's "binary hash compare".
#
# Sources common.sh and uses ITS helpers (log/warn/die/require_cmd/realpath_p,
# load_env, register_cleanup, PALW_DATA_ROOT/REPO_ROOT/KASPAD/VAL/MINER). It
# does not re-implement any of them.
#
# Design rules (shared with the rest of the harness):
#   * set -euo pipefail.
#   * IDEMPOTENT   — a clean re-run does not rebuild if binaries are current
#                    (BUILD_SKIP=1) and NEVER silently overwrites an existing
#                    binary-hashes.txt: identical -> left untouched, different
#                    -> fail-closed (override only with an explicit HASH_FORCE=1).
#   * FAIL-CLOSED  — every ambiguity is a die() with an actionable message.
#   * PORTABLE     — bash 3.2 (stock macOS) + Linux; BSD + GNU coreutils.
#   * HONEST       — records only the real, just-built binaries; makes no claim
#                    of a seeded / test-only / palw_demo path.
#
# Env knobs (all optional):
#   BUILD_SKIP=1   — skip cargo build IFF all three binaries already exist and
#                    are executable; otherwise fail-closed (nothing to hash).
#   BUILD_LABEL=<s>— free-text label recorded in the hashes file (e.g. a commit
#                    or a run tag). If unset the label is "unlabeled"; this
#                    script never calls date() to synthesise one.
#   HASH_FORCE=1   — permit overwriting an existing binary-hashes.txt whose
#                    recorded hashes differ from the current binaries.
#   PALW_ENV_FILE / env.local / env.example — config source (as load_env).
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$SCRIPT_DIR/common.sh"

PALW_LOG_TAG="build-and-hash"; export PALW_LOG_TAG

# Tools this script invokes directly (cargo is required only on the build path,
# checked there). sha256 has two portable spellings; detected below.
require_cmd awk grep mktemp

# Pick the available SHA-256 tool: sha256sum (GNU coreutils) or `shasum -a 256`
# (BSD / stock macOS). Fail fast BEFORE a multi-minute build if neither exists.
if command -v sha256sum >/dev/null 2>&1; then
    SHA256_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA256_TOOL="shasum -a 256"
else
    die "need 'sha256sum' or 'shasum' on PATH to hash the binaries (install coreutils, or use macOS's shasum)"
fi

# -----------------------------------------------------------------------------
# Bootstrap REPO_ROOT WITHOUT load_env (deliberate ordering).
#
# load_env() is the authoritative entry point, but its final step verifies that
# target/release/{kaspad,kaspa-pq-validator,misaminer} already exist and are
# executable — and THIS script is what produces them. On a first (clean) build
# there is nothing for load_env to bind yet, so it would die before we could
# build. We therefore resolve JUST REPO_ROOT here, exactly the way load_env
# does (PALW_ENV_FILE -> env.local -> env.example, else two levels up from this
# dir), build, and only THEN call load_env — by which point the binaries exist
# and load_env can bind + re-verify them. This is the minimum needed to know
# WHERE to build; it is not a re-implementation of any common.sh helper.
# -----------------------------------------------------------------------------
if [ -n "${PALW_ENV_FILE:-}" ]; then
    _cfg="$PALW_ENV_FILE"
elif [ -f "$COMMON_SH_DIR/env.local" ]; then
    _cfg="$COMMON_SH_DIR/env.local"
else
    _cfg="$COMMON_SH_DIR/env.example"
fi
[ -f "$_cfg" ] || die "config not found: $_cfg (copy env.example to env.local)"
# shellcheck disable=SC1090
set -a; . "$_cfg"; set +a
PALW_ENV_FILE="$_cfg"; export PALW_ENV_FILE   # pin, so the later load_env uses the SAME file

: "${REPO_ROOT:=$(cd "$COMMON_SH_DIR/../.." && pwd -P)}"
[ -d "$REPO_ROOT" ] || die "REPO_ROOT does not exist: $REPO_ROOT (set REPO_ROOT in $_cfg)"
REPO_ROOT="$(realpath_p "$REPO_ROOT")"; export REPO_ROOT

# Paths load_env will later bind to KASPAD/VAL/MINER. Used here for the
# pre-build presence check (load_env cannot run until they exist).
_bin_kaspad="$REPO_ROOT/target/release/kaspad"
_bin_val="$REPO_ROOT/target/release/kaspa-pq-validator"
_bin_miner="$REPO_ROOT/target/release/misaminer"
# Controller-only WIRING helper for TICKET_MODE=mock. Built here so mock mode is
# one-command, but it is NOT a node binary — it is hashed as metadata only and is
# NEVER part of the cross-host node attestation (peers do not run it).
_bin_mock="$REPO_ROOT/target/release/mock-ticket"

_all_bins_present() {
    [ -x "$_bin_kaspad" ] && [ -x "$_bin_val" ] && [ -x "$_bin_miner" ]
}

# -----------------------------------------------------------------------------
# Build (or honour BUILD_SKIP=1).
# -----------------------------------------------------------------------------
if [ "${BUILD_SKIP:-}" = "1" ]; then
    if _all_bins_present; then
        log "BUILD_SKIP=1 and all three release binaries already present under $REPO_ROOT/target/release — skipping cargo build"
    else
        die "BUILD_SKIP=1 but one or more binaries are missing/not executable under $REPO_ROOT/target/release (kaspad, kaspa-pq-validator, misaminer). Unset BUILD_SKIP=1 to build them."
    fi
else
    require_cmd cargo
    log "cargo build --release -p kaspad -p kaspa-pq-validator -p misaminer -p mock-ticket  (in $REPO_ROOT)"
    # Subshell cd so this script's own working directory is never changed.
    # mock-ticket is a workspace member (scripts/palw-shared-testnet/mock-ticket);
    # building it here makes TICKET_MODE=mock one-command (no separate cargo step).
    ( cd "$REPO_ROOT" && cargo build --release \
          -p kaspad -p kaspa-pq-validator -p misaminer -p mock-ticket ) \
        || die "cargo build failed in $REPO_ROOT — fix the error above and re-run (or set BUILD_SKIP=1 if the binaries are already built)."
    log "cargo build --release complete"
fi

# -----------------------------------------------------------------------------
# Now the binaries exist: hand off to load_env for the authoritative bind +
# executability re-verification (fail-closed) and to create the artifacts dir.
# -----------------------------------------------------------------------------
load_env   # binds KASPAD/VAL/MINER, verifies each is executable, makes 0700 dirs

# -----------------------------------------------------------------------------
# Hash the three verified binaries.
# -----------------------------------------------------------------------------
hash_of() {
    local f="$1" out
    [ -r "$f" ] || die "cannot read binary for hashing: $f"
    out="$($SHA256_TOOL "$f" 2>/dev/null | awk 'NR==1{print $1}')" || true
    case "$out" in
        ''|*[!0-9a-f]*) die "failed to compute sha256 of $f (tool: $SHA256_TOOL, got: '$out')" ;;
    esac
    [ "${#out}" -eq 64 ] || die "sha256 of $f has unexpected length ${#out} (expected 64): '$out'"
    printf '%s\n' "$out"
}

h_kaspad="$(hash_of "$KASPAD")"
h_val="$(hash_of "$VAL")"
h_miner="$(hash_of "$MINER")"

log "kaspad             $h_kaspad"
log "kaspa-pq-validator $h_val"
log "misaminer          $h_miner"

# -----------------------------------------------------------------------------
# Record to artifacts/binary-hashes.txt — idempotent, never a silent overwrite.
#   * Comment lines (# ...) are metadata (label/repo) and are NOT compared.
#   * The three "sha256  name" lines are the attestation and ARE compared.
# BUILD_LABEL is used verbatim if set; no date() fallback per the stage spec.
# -----------------------------------------------------------------------------
label="${BUILD_LABEL:-unlabeled}"
hashes_file="$PALW_DATA_ROOT/artifacts/binary-hashes.txt"

new_hashes="$(printf '%s  kaspad\n%s  kaspa-pq-validator\n%s  misaminer' \
    "$h_kaspad" "$h_val" "$h_miner")"

full_content="$(printf '%s\n' \
    "# PALW Phase-0 testnet — release binary SHA-256 (STN-001 cross-host compare)" \
    "# Compare this file (or just its 'sha256  name' lines) against the peer host" \
    "# to prove both nodes run byte-identical builds. Basenames + two-space gap" \
    "# so 'sha256sum -c' / 'shasum -a 256 -c' works when run from target/release." \
    "# build_label: $label" \
    "# repo_root:   $REPO_ROOT" \
    "$h_kaspad  kaspad" \
    "$h_val  kaspa-pq-validator" \
    "$h_miner  misaminer")"

# mock-ticket hash — recorded as a NON-compared metadata comment (# ...). It is a
# controller-only TICKET_MODE=mock helper, not a node binary, so peers do not run
# it and it must not be part of the cross-host attestation compared above.
if [ -x "$_bin_mock" ]; then
    h_mock="$(hash_of "$_bin_mock")"
    log "mock-ticket        $h_mock  (controller-only helper; NOT cross-host compared)"
    full_content="$full_content"$'\n'"# mock_ticket_sha256: $h_mock  (controller-only TICKET_MODE=mock helper; NOT part of the node attestation)"
else
    warn "mock-ticket not present at $_bin_mock — TICKET_MODE=mock will require it (create-lifecycle.sh builds/checks it). Not hashing."
fi

# Stage into a temp file first so a crash never leaves a half-written
# attestation; the cleanup trap removes the temp on ANY exit path.
tmp_hashes="$(mktemp "${hashes_file}.XXXXXX")" || die "mktemp failed under $(dirname "$hashes_file")"
register_cleanup "rm -f \"$tmp_hashes\""
printf '%s\n' "$full_content" > "$tmp_hashes" || die "failed staging hashes to $tmp_hashes"
chmod 0644 "$tmp_hashes" 2>/dev/null || true

if [ -f "$hashes_file" ]; then
    existing="$(grep -Ev '^[[:space:]]*(#|$)' "$hashes_file" 2>/dev/null || true)"
    if [ "$existing" = "$new_hashes" ]; then
        log "binary hashes unchanged; $hashes_file already records this exact set (idempotent — not rewritten)"
    elif [ "${HASH_FORCE:-}" = "1" ]; then
        warn "recorded hashes in $hashes_file DIFFER from the current binaries; HASH_FORCE=1 set -> overwriting"
        mv "$tmp_hashes" "$hashes_file" || die "failed to overwrite $hashes_file"
        log "overwrote binary hashes -> $hashes_file (label: $label)"
    else
        die "binary hashes DIFFER from the recorded set in $hashes_file.
The three binaries changed since that file was written (a new build/commit),
or the file came from a different host/build. This harness will not silently
overwrite a hash-attestation file. Choose one:
  * set HASH_FORCE=1 and re-run to overwrite with the current hashes, or
  * remove $hashes_file and re-run to record it fresh.
recorded (sha256  name):
$existing
current:
$new_hashes"
    fi
else
    mv "$tmp_hashes" "$hashes_file" || die "failed to write $hashes_file"
    log "wrote binary hashes -> $hashes_file (label: $label)"
fi

log "build-and-hash complete (STN-001): $hashes_file"
exit 0
