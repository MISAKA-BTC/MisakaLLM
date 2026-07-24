#!/usr/bin/env bash
# =============================================================================
# network-manifest.sh — §11.3 signed network manifest for the PALW closed testnet.
#
#   usage:  ./network-manifest.sh generate            # build + sign the manifest
#           ./network-manifest.sh verify [FILE]       # verify signature + LIVE node identity
#           ./network-manifest.sh show [FILE]         # print the manifest
#           ./network-manifest.sh --help
#
# WHAT IT IS: one signed JSON document (misaka-palw-network-manifest-v1) pinning
# the release identity a shared net must agree on — network id, the ACTUAL
# genesis hash + consensus-params hash + header version + effective algo4 flag
# (all read from the RUNNING nodes' getConsensusIdentity RPC, never re-derived
# client-side), the release binary SHA-256s (STN-001), and the node roster.
# `verify` fail-closes when the signature is bad OR any LIVE node's identity
# differs from the pinned values (review §11.4: binary-hash mismatch, algo4-flag
# mismatch, params-hash mismatch are each fatal).
#
# SIGNATURE: OpenSSH `ssh-keygen -Y sign` (available on stock macOS + Linux) with
# the release coordinator's SSH key (PALW_MANIFEST_KEY, default ~/.ssh/id_ed25519)
# under the namespace `palw-manifest`. Verification uses an allowed-signers file
# (PALW_MANIFEST_SIGNERS, default <manifest>.signers) that pins WHO may sign —
# distribute that file out-of-band with the harness, like the SSH known_hosts.
#
# HONEST SCOPE: this signs and checks the CONFIGURED release identity; it cannot
# prove a node runs the hashed binary (no remote attestation). Combined with
# preflight's binary-hash comparison and the server-side identity RPC it closes
# the review's §11 "release identity is optional" gap for a closed testnet.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$SCRIPT_DIR/common.sh"

PALW_LOG_TAG="${PALW_LOG_TAG:-net-manifest}"; export PALW_LOG_TAG

usage() {
    cat >&2 <<EOF
usage: ${0##*/} {generate|verify [FILE]|show [FILE]|--help}

  generate      Read BOTH live nodes' getConsensusIdentity, require them to agree,
                bundle the STN-001 binary hashes + node roster, write
                artifacts/network-manifest.json and SIGN it (ssh-keygen -Y sign,
                key: \$PALW_MANIFEST_KEY, default ~/.ssh/id_ed25519).
  verify [FILE] Verify the detached signature against the allowed-signers pin
                (\$PALW_MANIFEST_SIGNERS, default FILE.signers) AND compare each
                LIVE node's identity RPC to the pinned values. Any mismatch dies.
  show [FILE]   Print the manifest.

Default FILE: \$PALW_DATA_ROOT/artifacts/network-manifest.json
EOF
}

ACTION="${1:-}"
case "$ACTION" in
    -h|--help|help|"") usage; [ -z "$ACTION" ] && exit 2 || exit 0 ;;
    generate|verify|show) : ;;
    *) usage; die "unknown action '$ACTION'" ;;
esac

require_cmd ssh-keygen python3
load_env

MANIFEST="${2:-$PALW_DATA_ROOT/artifacts/network-manifest.json}"
SIG="$MANIFEST.sig"
SIGNERS="${PALW_MANIFEST_SIGNERS:-$MANIFEST.signers}"
# The release-signing key is a DEDICATED key, never the operator's personal SSH
# identity: it is generated passphrase-less under keys/ on first `generate` (the
# coordinator machine), and only its PUBLIC half travels (in the .signers pin).
SIGNKEY="${PALW_MANIFEST_KEY:-$PALW_DATA_ROOT/keys/manifest-signing.key}"
NAMESPACE="palw-manifest"

# _identity <a|b> — the node's server-side consensus identity as `key: value` lines
#   (kaspa-pq-validator status prints node_genesis_hash/node_params_hash/...).
_identity() {
    local n="$1"
    _endpoint_open "$(node_wrpc "$n")" || die "node-$n wRPC $(node_wrpc "$n") is not answering — both nodes must be up"
    "$VAL" status --node-wrpc-borsh "$(node_wrpc "$n")" --network "$NETWORK" 2>/dev/null \
        || die "node-$n identity query failed"
}

# _ident_field <blob> <key> — extract one identity value.
_ident_field() { printf '%s\n' "$1" | awk -F': ' -v k="$2" '$1==k {print $2; exit}' | awk '{print $1}'; }

case "$ACTION" in
generate)
    log "reading LIVE consensus identity from both nodes (server-side getConsensusIdentity)"
    ID_A="$(_identity a)"
    ID_B="$(_identity b)"
    GEN_A="$(_ident_field "$ID_A" node_genesis_hash)";  GEN_B="$(_ident_field "$ID_B" node_genesis_hash)"
    PAR_A="$(_ident_field "$ID_A" node_params_hash)";   PAR_B="$(_ident_field "$ID_B" node_params_hash)"
    HV_A="$(_ident_field "$ID_A" node_header_version_effective)"; HV_B="$(_ident_field "$ID_B" node_header_version_effective)"
    A4_A="$(_ident_field "$ID_A" node_palw_algo4_accept)"; A4_B="$(_ident_field "$ID_B" node_palw_algo4_accept)"
    GIT_A="$(_ident_field "$ID_A" node_git_commit)"

    [ -n "$GEN_A" ] || die "node A did not report node_genesis_hash — its binary predates getConsensusIdentity; rebuild + restart both nodes first"
    [ -n "$PAR_A" ] || die "node A did not report node_params_hash — rebuild + restart both nodes first"
    # §11.4: the manifest pins ONE identity — refusing to sign a disagreeing pair
    # is the point (a mismatch here IS the incident, not an inconvenience).
    [ "$GEN_A" = "$GEN_B" ] || die "genesis hash disagrees between live nodes (A=$GEN_A B=$GEN_B) — refusing to sign a split-identity net"
    [ "$PAR_A" = "$PAR_B" ] || die "consensus params hash disagrees between live nodes (A=$PAR_A B=$PAR_B) — refusing to sign"
    [ "$HV_A" = "$HV_B" ]   || die "effective header version disagrees (A=$HV_A B=$HV_B) — refusing to sign"
    [ "$A4_A" = "$A4_B" ]   || die "effective palw_algo4_accept disagrees (A=$A4_A B=$A4_B) — refusing to sign"

    HASHES_FILE="$PALW_DATA_ROOT/artifacts/binary-hashes.txt"
    [ -s "$HASHES_FILE" ] || die "STN-001 binary hashes not found at $HASHES_FILE — run ./build-and-hash.sh first (the manifest pins the release binaries)"

    log "building $MANIFEST"
    MANIFEST_TMP="$(mktemp "$MANIFEST.XXXXXX")"
    GEN_A="$GEN_A" PAR_A="$PAR_A" HV_A="$HV_A" A4_A="$A4_A" GIT_A="$GIT_A" \
    NETWORK="$NETWORK" NETSUFFIX="$NETSUFFIX" HASHES_FILE="$HASHES_FILE" \
    NODE_A_HOST="$NODE_A_HOST" NODE_B_HOST="$NODE_B_HOST" A_P2P_PORT="$A_P2P_PORT" B_P2P_PORT="$B_P2P_PORT" \
    python3 - > "$MANIFEST_TMP" <<'PYEOF'
import json, os, sys
binaries = {}
with open(os.environ["HASHES_FILE"]) as f:
    for line in f:
        parts = line.split()
        # shasum/sha256sum format: "<64-hex>  <path>" — key by the path's basename.
        if len(parts) >= 2 and len(parts[0]) == 64 and all(c in "0123456789abcdef" for c in parts[0]):
            binaries[os.path.basename(parts[-1])] = "sha256:" + parts[0]
doc = {
    "schema": "misaka-palw-network-manifest-v1",
    "network_id": os.environ["NETWORK"],
    "netsuffix": int(os.environ["NETSUFFIX"]),
    "genesis_hash": os.environ["GEN_A"],
    "consensus_params_hash": os.environ["PAR_A"],
    "header_version": int(os.environ["HV_A"] or 0),
    "palw_algo4_accept": os.environ["A4_A"] == "true",
    "commit": os.environ.get("GIT_A", ""),
    "binaries": binaries,
    "nodes": [
        {"id": "node-a", "p2p": f'{os.environ["NODE_A_HOST"]}:{os.environ["A_P2P_PORT"]}', "role": ["archive", "validator"]},
        {"id": "node-b", "p2p": f'{os.environ["NODE_B_HOST"]}:{os.environ["B_P2P_PORT"]}', "role": ["archive"]},
    ],
}
json.dump(doc, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PYEOF
    mv "$MANIFEST_TMP" "$MANIFEST"

    if [ ! -f "$SIGNKEY" ]; then
        log "generating a DEDICATED release-signing key -> $SIGNKEY (ed25519, key stays on the coordinator; only the public half travels in the .signers pin)"
        install -d -m 0700 "$(dirname "$SIGNKEY")"
        ssh-keygen -t ed25519 -N '' -C 'palw-release-manifest' -f "$SIGNKEY" -q \
            || die "could not generate the release-signing key at $SIGNKEY"
    fi
    log "signing with $SIGNKEY (namespace $NAMESPACE)"
    # Remove any prior signature FIRST: ssh-keygen -Y sign PROMPTS interactively on
    # an existing .sig (hanging headless runs), and a stale signature for an older
    # manifest body would fail verification confusingly.
    rm -f "$SIG"
    ssh-keygen -Y sign -f "$SIGNKEY" -n "$NAMESPACE" "$MANIFEST" \
        || die "ssh-keygen -Y sign failed (the signature is REQUIRED — an unsigned manifest is not a release identity)"
    # ssh-keygen writes MANIFEST.sig next to the file.
    [ -s "$SIG" ] || die "expected signature at $SIG was not produced"

    # Emit a starter allowed-signers pin for the verifier side if none exists yet.
    if [ ! -f "$SIGNERS" ]; then
        printf 'palw-release %s\n' "$(awk '{print $1" "$2}' "$SIGNKEY.pub")" > "$SIGNERS"
        log "wrote allowed-signers pin -> $SIGNERS (distribute out-of-band with the harness)"
    fi
    log "manifest signed: $MANIFEST (+ .sig). Verify anywhere with: ./network-manifest.sh verify $MANIFEST"
    ;;

verify)
    [ -s "$MANIFEST" ] || die "manifest not found: $MANIFEST — shared mode requires a signed network manifest (generate it on the coordinator: ./network-manifest.sh generate)"
    [ -s "$SIG" ]      || die "manifest signature not found: $SIG — an unsigned manifest is not a release identity (fail-closed)"
    [ -s "$SIGNERS" ]  || die "allowed-signers pin not found: $SIGNERS — distribute it out-of-band (PALW_MANIFEST_SIGNERS)"

    log "verifying signature (allowed-signers: $SIGNERS)"
    ssh-keygen -Y verify -f "$SIGNERS" -I palw-release -n "$NAMESPACE" -s "$SIG" < "$MANIFEST" >/dev/null \
        || die "manifest SIGNATURE verification FAILED — do not join this net"
    log "signature OK"

    # Parse the pinned identity.
    PIN_GEN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["genesis_hash"])' "$MANIFEST")"
    PIN_PAR="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["consensus_params_hash"])' "$MANIFEST")"
    PIN_HV="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["header_version"])' "$MANIFEST")"
    PIN_A4="$(python3 -c 'import json,sys;print(str(json.load(open(sys.argv[1]))["palw_algo4_accept"]).lower())' "$MANIFEST")"
    PIN_NET="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["network_id"])' "$MANIFEST")"

    [ "$PIN_NET" = "$NETWORK" ] || die "manifest is for network '$PIN_NET' but this host is configured for '$NETWORK'"

    # Compare each LIVE node against the pin (review §11.4 — each mismatch fatal).
    for n in a b; do
        ID="$(_identity "$n")"
        GEN="$(_ident_field "$ID" node_genesis_hash)"
        PAR="$(_ident_field "$ID" node_params_hash)"
        HV="$(_ident_field "$ID" node_header_version_effective)"
        A4="$(_ident_field "$ID" node_palw_algo4_accept)"
        [ -n "$GEN" ] || die "node-$n does not serve getConsensusIdentity (older binary) — every node in a shared net must serve its identity"
        [ "$GEN" = "$PIN_GEN" ] || die "node-$n GENESIS mismatch: live=$GEN pinned=$PIN_GEN — different chain; do not proceed"
        [ "$PAR" = "$PIN_PAR" ] || die "node-$n PARAMS-HASH mismatch: live=$PAR pinned=$PIN_PAR — different consensus rules; do not proceed"
        [ "$HV" = "$PIN_HV" ]   || die "node-$n header-version mismatch: live=$HV pinned=$PIN_HV"
        [ "$A4" = "$PIN_A4" ]   || die "node-$n palw_algo4_accept mismatch: live=$A4 pinned=$PIN_A4 — one side would accept blocks the other rejects"
        log "node-$n identity matches the signed manifest (genesis/params/header-version/algo4)"
    done

    # Binary hashes: compare the LOCAL build's hashes to the pinned ones.
    HASHES_FILE="$PALW_DATA_ROOT/artifacts/binary-hashes.txt"
    if [ -s "$HASHES_FILE" ]; then
        MISMATCH="$(HASHES_FILE="$HASHES_FILE" MANIFEST="$MANIFEST" python3 - <<'PYEOF'
import json, os
pinned = json.load(open(os.environ["MANIFEST"]))["binaries"]
local = {}
with open(os.environ["HASHES_FILE"]) as f:
    for line in f:
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 64 and all(c in "0123456789abcdef" for c in parts[0]):
            local[os.path.basename(parts[-1])] = "sha256:" + parts[0]
bad = [f"{name}: local={local.get(name,'<absent>')} pinned={h}" for name, h in sorted(pinned.items())
       if name in local and local[name] != h]
print("; ".join(bad))
PYEOF
)"
        [ -z "$MISMATCH" ] || die "binary hash mismatch vs the signed manifest: $MISMATCH — this host runs a DIFFERENT build; do not proceed"
        log "local binary hashes match the signed manifest"
    else
        warn "no local binary-hashes.txt to compare (run ./build-and-hash.sh); node identity checks above still passed"
    fi
    log "manifest verification PASS: signature + both-node live identity + binary hashes"
    ;;

show)
    [ -s "$MANIFEST" ] || die "manifest not found: $MANIFEST"
    cat "$MANIFEST"
    ;;
esac
exit 0
