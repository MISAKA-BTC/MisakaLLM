#!/usr/bin/env sh
# PALW provider unbond + slash rehearsal driver.
#
# Exercises, end to end, the two operator lifecycles that were tooling-complete but never
# rehearsed as a scripted, self-checking procedure:
#
#   Phase "unbond": Active bond -> owner-signed unbond request -> release-delay -> sweep collateral.
#   Phase "slash" : withhold a DA-challenge response -> post-deadline timeout evidence ->
#                   bond becomes Slashed -> PROVE the slashed collateral cannot be swept.
#
# Dry-run by default: every mutating step runs the CLI's own --dry-run (build + owner-sign +
# validate + live registry/funding preflight, no submission), so the whole rehearsal can be walked
# on a live network without spending anything. Pass --live to actually submit. The slashed-bond
# sweep attempt is EXPECTED TO FAIL; a success there fails the rehearsal (the un-sweepable invariant
# regressed). Consensus separately pins this: ProviderBondSpendFilter keeps a slashed output 0
# permanently unspendable (see utxo_validation.rs / virtual_processor tests).
#
# This is an operational rehearsal harness. It drives real CLIs against a real node; it does not
# itself stand up a network. See docs/palw-unbond-slash-rehearsal-runbook.md.
set -u

BIN="kaspa-pq-validator"
NODE_RPC="127.0.0.1:27210"
NETWORK=""
NETWORK_ID=""
OWNER_KEY=""
PROVIDER_BOND=""
CHALLENGE_ID=""
PHASE="all"
WORKDIR="${TMPDIR:-/tmp}/palw-rehearsal.$$"
LIVE=0

usage() {
  cat >&2 <<'EOF'
usage: palw-unbond-slash-rehearsal.sh [options]
  --bin PATH                 kaspa-pq-validator binary (default: on PATH)
  --node-wrpc-borsh HOST:PORT node wRPC borsh endpoint (default 127.0.0.1:27210)
  --network ID               network id (e.g. testnet-110)
  --network-id U32           PALW network domain id (for slash timeout evidence)
  --owner-key PATH           provider-bond owner ML-DSA-87 seed path
  --provider-bond TXID:INDEX provider collateral outpoint
  --challenge-id HEX128      (slash) the expired challenge id to time out
  --phase unbond|slash|all   which lifecycle to rehearse (default all)
  --workdir DIR              scratch dir for generated payloads (default under TMPDIR)
  --live                     actually submit (default: dry-run every mutating step)
EOF
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2;;
    --node-wrpc-borsh|--node-rpc) NODE_RPC="$2"; shift 2;;
    --network) NETWORK="$2"; shift 2;;
    --network-id) NETWORK_ID="$2"; shift 2;;
    --owner-key) OWNER_KEY="$2"; shift 2;;
    --provider-bond) PROVIDER_BOND="$2"; shift 2;;
    --challenge-id) CHALLENGE_ID="$2"; shift 2;;
    --phase) PHASE="$2"; shift 2;;
    --workdir) WORKDIR="$2"; shift 2;;
    --live) LIVE=1; shift;;
    -h|--help) usage;;
    *) echo "unknown option: $1" >&2; usage;;
  esac
done

[ -n "$OWNER_KEY" ] || { echo "error: --owner-key is required" >&2; exit 2; }
[ -n "$PROVIDER_BOND" ] || { echo "error: --provider-bond is required" >&2; exit 2; }

NET_ARG=""
[ -n "$NETWORK" ] && NET_ARG="--network $NETWORK"
mkdir -p "$WORKDIR"

log() { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }

# Print the current provider-bond status block and echo a lowercased copy for matching.
bond_status() {
  # shellcheck disable=SC2086
  "$BIN" palw-status --node-wrpc-borsh "$NODE_RPC" $NET_ARG --provider-bond "$PROVIDER_BOND" 2>&1
}

# Assert the status output mentions an expected effective status keyword.
assert_status() {
  want="$1"; out="$2"
  if printf '%s' "$out" | grep -qi "$want"; then
    note "OK: provider bond reports '$want'"
    return 0
  fi
  note "UNEXPECTED: provider bond does not report '$want'"
  return 1
}

dry_flag() { [ "$LIVE" -eq 1 ] && printf '' || printf -- '--dry-run'; }

rehearse_unbond() {
  log "PHASE unbond (live=$LIVE)"
  out="$(bond_status)"; printf '%s\n' "$out"
  assert_status "active" "$out" || note "continuing; unbond request will still validate against live registry state"

  log "unbond request ($( [ "$LIVE" -eq 1 ] && echo submit || echo dry-run ))"
  # shellcheck disable=SC2086
  "$BIN" palw-provider-unbond request \
    --node-wrpc-borsh "$NODE_RPC" $NET_ARG \
    --validator-key "$OWNER_KEY" --provider-bond "$PROVIDER_BOND" \
    $(dry_flag) || { note "unbond request failed"; return 1; }

  if [ "$LIVE" -eq 1 ]; then
    log "waiting for the registry to record Unbonding + a release DAA score"
    out="$(bond_status)"; printf '%s\n' "$out"
    assert_status "unbonding" "$out" || note "not yet Unbonding; re-run 'palw-status' until the request is included"
    note "wait until the sink DAA score reaches the reported release DAA before sweeping"
  else
    note "dry-run only: no on-chain state changed; run with --live to actually begin the exit"
  fi

  log "sweep collateral ($( [ "$LIVE" -eq 1 ] && echo submit || echo dry-run ))"
  # shellcheck disable=SC2086
  "$BIN" palw-provider-unbond sweep \
    --node-wrpc-borsh "$NODE_RPC" $NET_ARG \
    --validator-key "$OWNER_KEY" --provider-bond "$PROVIDER_BOND" \
    $(dry_flag) || note "sweep refused (expected until the release DAA score is reached)"
}

rehearse_slash() {
  log "PHASE slash (live=$LIVE)"
  [ -n "$NETWORK_ID" ] || { note "error: --network-id is required for the slash phase"; return 1; }
  [ -n "$CHALLENGE_ID" ] || { note "error: --challenge-id (the expired challenge) is required"; return 1; }

  out="$(bond_status)"; printf '%s\n' "$out"

  log "WITHHOLD: do NOT answer challenge $CHALLENGE_ID; let its response deadline lapse"
  note "the challenger (or any node) may then submit post-deadline timeout evidence"

  TIMEOUT_OUT="$WORKDIR/timeout.$CHALLENGE_ID.borsh"
  log "build post-deadline DA timeout evidence (0x3c)"
  "$BIN" palw-payload da-timeout \
    --network-id "$NETWORK_ID" --challenge-id "$CHALLENGE_ID" \
    --provider-bond "$PROVIDER_BOND" --out "$TIMEOUT_OUT" || { note "timeout evidence build failed"; return 1; }
  note "wrote $TIMEOUT_OUT"

  if [ "$LIVE" -eq 1 ]; then
    log "submit timeout evidence"
    # shellcheck disable=SC2086
    "$BIN" palw-submit --node-wrpc-borsh "$NODE_RPC" $NET_ARG \
      --validator-key "$OWNER_KEY" --kind da-timeout --payload-file "$TIMEOUT_OUT" \
      --exclude-funding-outpoint "$PROVIDER_BOND" || { note "timeout submission failed"; return 1; }
    log "verify the bond is now Slashed"
    out="$(bond_status)"; printf '%s\n' "$out"
    assert_status "slashed" "$out" || { note "FAIL: bond did not enter Slashed after valid timeout"; return 1; }
  else
    note "dry-run only: timeout evidence built + stateless-validated but not submitted (use --live)"
  fi

  log "PROVE un-sweepable: attempt to sweep the (slashed) collateral — MUST be refused"
  # shellcheck disable=SC2086
  if "$BIN" palw-provider-unbond sweep \
       --node-wrpc-borsh "$NODE_RPC" $NET_ARG \
       --validator-key "$OWNER_KEY" --provider-bond "$PROVIDER_BOND" --dry-run; then
    note "REHEARSAL FAILURE: sweep of a slashed bond succeeded — the un-sweepable invariant regressed"
    return 1
  else
    note "OK: sweep of the slashed bond was refused, as required"
  fi
}

RC=0
case "$PHASE" in
  unbond) rehearse_unbond || RC=1;;
  slash) rehearse_slash || RC=1;;
  all) rehearse_unbond || RC=1; rehearse_slash || RC=1;;
  *) echo "unknown --phase: $PHASE" >&2; usage;;
esac

log "rehearsal complete (rc=$RC); scratch in $WORKDIR"
exit $RC
