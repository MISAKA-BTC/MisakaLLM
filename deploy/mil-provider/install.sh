#!/usr/bin/env bash
# One-command MISAKA Inference Lane (MIL) provider onboarding (design §16.1).
#
# From a bare Ubuntu + GPU driver host, this:
#   1. generates the 32-byte provider seed (misaka-mil-provider keygen),
#   2. pulls the measured serving image + starts the sidecar via docker compose,
#   3. prints the provider identity and (dry-run) registration command.
#
# Goal: under 30 minutes from bare host to earning (§16.1). Attestation is the
# dev bundle in v0; the Tier-1 measured TEE image + real quote land in P2.
set -euo pipefail
cd "$(dirname "$0")"

MIL_HOME="${MIL_HOME:-$HOME/.misaka-mil}"
SEED_FILE="${MIL_SEED_FILE:-$MIL_HOME/provider.seed}"
NETWORK="${MIL_NETWORK:-testnet-10}"
LISTEN="${MIL_LISTEN:-0.0.0.0:37110}"
BACKEND="${MIL_BACKEND:-mock}"           # mock | vllm | llamacpp
BACKEND_ADDR="${MIL_BACKEND_ADDR:-vllm:8000}"
MODEL_NAME="${MIL_MODEL:-mil-core}"

command -v docker >/dev/null || { echo "docker not found — install Docker first"; exit 1; }
mkdir -p "$MIL_HOME"

# Build the provider binary image if not present (uses the workspace Dockerfile
# stage); operators may instead docker pull a published tag.
if ! docker image inspect misaka-mil-provider:local >/dev/null 2>&1; then
  echo ">> building misaka-mil-provider image"
  docker build -f Dockerfile -t misaka-mil-provider:local ../.. 2>/dev/null || {
    echo "   (image build skipped — provide a prebuilt 'misaka-mil-provider:local' or set the binary on PATH)"
  }
fi

if [[ ! -f "$SEED_FILE" ]]; then
  echo ">> generating provider seed at $SEED_FILE"
  if command -v misaka-mil-provider >/dev/null; then
    misaka-mil-provider keygen --out "$SEED_FILE"
  else
    docker run --rm -v "$MIL_HOME:/data" misaka-mil-provider:local keygen --out /data/provider.seed
  fi
  chmod 600 "$SEED_FILE"
else
  echo ">> reusing existing seed at $SEED_FILE"
fi

export MIL_HOME SEED_FILE NETWORK LISTEN BACKEND BACKEND_ADDR MODEL_NAME
echo ">> starting the MIL provider stack (docker compose up -d)"
docker compose up -d

cat <<EOF

MIL provider is up.
  seed:     $SEED_FILE   (keep this safe; it derives pk_kem + pk_receipt)
  listen:   $LISTEN
  backend:  $BACKEND ($BACKEND_ADDR)

Next steps:
  * check health:   docker compose logs -f mil-provider
  * open dashboard: xdg-open dashboard.html   (reads receipts.jsonl via 'stats')
  * register (dry-run):
      misaka-mil-provider register --provider-seed "$SEED_FILE" \\
        --funding-key <ml-dsa-seed> --network "$NETWORK"
    add --submit once you have funded the funding address.
EOF
