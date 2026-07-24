#!/usr/bin/env bash
# =============================================================================
# disk-slo.sh — §13.3 storage SLO monitor for the PALW closed testnet.
#
#   usage:  ./disk-slo.sh record            # append one sample to the history
#           ./disk-slo.sh status            # print current metrics + growth rate
#           ./disk-slo.sh gate lifecycle    # exit 1 iff free% < STOP threshold (20)
#           ./disk-slo.sh gate emergency    # exit 1 iff free% < EMERGENCY threshold (10)
#           ./disk-slo.sh --help
#
# WHAT IT MEASURES (host-local, honest — real numbers only):
#   * disk free % / bytes on the filesystem holding PALW_DATA_ROOT (df -P -k)
#   * consensus DB bytes for node A and node B appdirs (du -sk; a missing appdir
#     reports 0 — e.g. on a controller host or before first start)
#   * growth GiB/h + estimated hours-to-disk-full, derived from the RECORDED
#     history (artifacts/disk-history.tsv) — reported only when >= 2 samples
#     span >= 60s (never extrapolated from a single point).
#
# GATES (review doc §13.3; thresholds overridable via env):
#   WARN                free < DISK_WARN_PCT       (default 30) -> warn, exit 0
#   STOP NEW LIFECYCLE  free < DISK_STOP_PCT       (default 20) -> `gate lifecycle` exits 1
#   EMERGENCY STOP      free < DISK_EMERGENCY_PCT  (default 10) -> `gate emergency` exits 1
#
# WIRING: create-lifecycle.sh calls `gate lifecycle` before registering a new
# batch (a full disk mid-lifecycle corrupts RocksDB); palw-node-agent.sh's
# status/preflight embed the same metrics per host. `record` is cheap — every
# gate/status call also appends a sample, so a periodically-polled harness
# builds the history passively.
#
# Design rules: set -euo pipefail; bash 3.2 + BSD/GNU portable; sources
# common.sh (load_env) and reimplements nothing; fail-closed arg validation;
# the history file is append-only (never rewritten).
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$SCRIPT_DIR/common.sh"

PALW_LOG_TAG="${PALW_LOG_TAG:-disk-slo}"; export PALW_LOG_TAG

usage() {
    cat >&2 <<EOF
usage: ${0##*/} {record|status|gate lifecycle|gate emergency|--help}

  record           Append one (ts, disk, db) sample to artifacts/disk-history.tsv.
  status           Print free %, DB bytes, growth GiB/h + hours-to-full (needs
                   >= 2 recorded samples >= 60s apart), and the gate verdicts.
  gate lifecycle   Record a sample, then exit 1 iff free% < \${DISK_STOP_PCT:-20}
                   ("STOP NEW LIFECYCLE"). Warn (exit 0) below \${DISK_WARN_PCT:-30}.
  gate emergency   Record a sample, then exit 1 iff free% < \${DISK_EMERGENCY_PCT:-10}.
EOF
}

ACTION="${1:-}"
case "$ACTION" in
    -h|--help|help|"") usage; [ -z "$ACTION" ] && exit 2 || exit 0 ;;
    record|status) [ "$#" -eq 1 ] || { usage; die "'$ACTION' takes no further argument"; } ;;
    gate)
        case "${2:-}" in
            lifecycle|emergency) : ;;
            *) usage; die "gate needs 'lifecycle' or 'emergency', got '${2:-}'" ;;
        esac
        [ "$#" -eq 2 ] || { usage; die "gate takes exactly one sub-argument"; } ;;
    *) usage; die "unknown action '$ACTION'" ;;
esac

load_env

DISK_WARN_PCT="${DISK_WARN_PCT:-30}"
DISK_STOP_PCT="${DISK_STOP_PCT:-20}"
DISK_EMERGENCY_PCT="${DISK_EMERGENCY_PCT:-10}"
HISTORY="$PALW_DATA_ROOT/artifacts/disk-history.tsv"

# ---------------------------------------------------------------------------
# Metric collection (portable: df -P -k and du -sk work on BSD + GNU).
# ---------------------------------------------------------------------------
# _df_kb — echo "<total_kb> <avail_kb>" for the fs holding PALW_DATA_ROOT.
_df_kb() {
    df -P -k "$PALW_DATA_ROOT" 2>/dev/null | awk 'NR==2 {print $2, $4}'
}
# _du_kb <dir> — recursive KB of a dir; 0 when absent (controller host / pre-start).
_du_kb() {
    if [ -d "$1" ]; then du -sk "$1" 2>/dev/null | awk '{print $1}'; else printf '0'; fi
}

read -r TOTAL_KB AVAIL_KB <<EOF
$(_df_kb)
EOF
[ -n "${TOTAL_KB:-}" ] && [ "${TOTAL_KB:-0}" -gt 0 ] \
    || die "could not read df for $PALW_DATA_ROOT (df -P -k returned nothing usable)"
FREE_PCT=$(( AVAIL_KB * 100 / TOTAL_KB ))
DB_A_KB="$(_du_kb "$(node_appdir a)")"
DB_B_KB="$(_du_kb "$(node_appdir b)")"
NOW="$(date +%s)"

# ---------------------------------------------------------------------------
# record — append-only history: ts \t avail_kb \t total_kb \t db_a_kb \t db_b_kb
# ---------------------------------------------------------------------------
record_sample() {
    install -d -m 0700 "$(dirname "$HISTORY")"
    printf '%s\t%s\t%s\t%s\t%s\n' "$NOW" "$AVAIL_KB" "$TOTAL_KB" "$DB_A_KB" "$DB_B_KB" >> "$HISTORY"
}

# ---------------------------------------------------------------------------
# growth — derive GiB/h + hours-to-full from the OLDEST vs NEWEST history
# sample (>= 60s apart). Growth is measured on the DB dirs (what the net
# actually writes), fall-back to avail-shrink when DBs report 0 (remote layout).
# Emits "rate_gib_h hours_to_full" or "n/a n/a".
# ---------------------------------------------------------------------------
growth_estimate() {
    [ -s "$HISTORY" ] || { printf 'n/a n/a'; return 0; }
    awk -F'\t' -v now_avail="$AVAIL_KB" '
        NR==1 { t0=$1; a0=$2; db0=$4+$5 }
        { t1=$1; a1=$2; db1=$4+$5 }
        END {
            if (NR < 2 || t1 - t0 < 60) { print "n/a n/a"; exit }
            dt_h = (t1 - t0) / 3600.0
            growth_kb = db1 - db0
            if (growth_kb <= 0) growth_kb = a0 - a1   # fall back: disk actually consumed
            if (growth_kb <= 0) { print "0.000 inf"; exit }
            rate = growth_kb / 1048576.0 / dt_h       # GiB per hour
            ttf  = (now_avail / 1048576.0) / rate     # hours until the fs is full
            printf "%.3f %.1f", rate, ttf
        }' "$HISTORY"
}

# ---------------------------------------------------------------------------
# status / gates.
# ---------------------------------------------------------------------------
print_status() {
    read -r RATE TTF <<EOF
$(growth_estimate)
EOF
    printf 'disk.data_root: %s\n'        "$PALW_DATA_ROOT"
    printf 'disk.total_gib: %s\n'        "$(awk -v k="$TOTAL_KB" 'BEGIN{printf "%.1f", k/1048576}')"
    printf 'disk.free_gib: %s\n'         "$(awk -v k="$AVAIL_KB" 'BEGIN{printf "%.1f", k/1048576}')"
    printf 'disk.free_pct: %s\n'         "$FREE_PCT"
    printf 'db.node_a_gib: %s\n'         "$(awk -v k="$DB_A_KB" 'BEGIN{printf "%.2f", k/1048576}')"
    printf 'db.node_b_gib: %s\n'         "$(awk -v k="$DB_B_KB" 'BEGIN{printf "%.2f", k/1048576}')"
    printf 'growth.gib_per_hour: %s\n'   "$RATE"
    printf 'growth.hours_to_full: %s\n'  "$TTF"
    printf 'gate.warn_pct: %s (free<%s%% warns)\n'        "$DISK_WARN_PCT" "$DISK_WARN_PCT"
    printf 'gate.stop_lifecycle_pct: %s (free<%s%% blocks new lifecycles)\n' "$DISK_STOP_PCT" "$DISK_STOP_PCT"
    printf 'gate.emergency_pct: %s (free<%s%% emergency-stop)\n' "$DISK_EMERGENCY_PCT" "$DISK_EMERGENCY_PCT"
    printf 'history.samples: %s (%s)\n'  "$( [ -f "$HISTORY" ] && wc -l < "$HISTORY" | tr -d ' ' || printf 0)" "$HISTORY"
}

case "$ACTION" in
    record)
        record_sample
        log "recorded disk sample: free=${FREE_PCT}% db_a=${DB_A_KB}KB db_b=${DB_B_KB}KB -> $HISTORY"
        ;;
    status)
        record_sample
        print_status
        ;;
    gate)
        record_sample
        if [ "$FREE_PCT" -lt "$DISK_WARN_PCT" ]; then
            warn "disk free ${FREE_PCT}% < WARN ${DISK_WARN_PCT}% on $PALW_DATA_ROOT — plan a reset/snapshot soon (§13.4)"
        fi
        case "$2" in
            lifecycle)
                if [ "$FREE_PCT" -lt "$DISK_STOP_PCT" ]; then
                    die "STOP NEW LIFECYCLE: disk free ${FREE_PCT}% < ${DISK_STOP_PCT}% on $PALW_DATA_ROOT — refusing to register a new batch (a full disk mid-lifecycle corrupts RocksDB). Free space or reset the net, then retry."
                fi
                log "disk gate 'lifecycle' OK (free ${FREE_PCT}% >= ${DISK_STOP_PCT}%)"
                ;;
            emergency)
                if [ "$FREE_PCT" -lt "$DISK_EMERGENCY_PCT" ]; then
                    die "EMERGENCY: disk free ${FREE_PCT}% < ${DISK_EMERGENCY_PCT}% on $PALW_DATA_ROOT — stop the net (./stop.sh) and free space NOW."
                fi
                log "disk gate 'emergency' OK (free ${FREE_PCT}% >= ${DISK_EMERGENCY_PCT}%)"
                ;;
        esac
        ;;
esac
exit 0
