#!/usr/bin/env bash
# Reproducible build + test for the MISAKA Inference Lane (MIL) v1 EVM contracts
# (design §8.2 / §8.3 / §19). Installs the EXACT pinned dependency (forge-std),
# builds with the pinned solc (foundry.toml), and runs the Foundry tests. No
# OpenZeppelin dependency — the MIL contracts are self-contained.
set -euo pipefail
cd "$(dirname "$0")"

FORGE_STD_TAG="v1.9.4"

command -v forge >/dev/null || { echo "forge not found (install Foundry: https://getfoundry.sh)"; exit 1; }

echo ">> installing pinned deps"
forge install "foundry-rs/forge-std@${FORGE_STD_TAG}" --no-git

echo ">> clean build (solc pinned in foundry.toml)"
forge build --force

echo ">> test"
forge test -vv

echo ">> bytecode hashes (record when the source freezes)"
for c in ProviderRegistry ModelRegistry StakeManager RewardPool JobEscrow DisputeGame MilGovernance; do
  CREATION=$(jq -r '.bytecode.object' "out/${c}.sol/${c}.json")
  RUNTIME=$(jq -r '.deployedBytecode.object' "out/${c}.sol/${c}.json")
  echo "  ${c} creation keccak:  $(cast keccak "${CREATION}")"
  echo "  ${c} runtime  keccak:  $(cast keccak "${RUNTIME}")"
done
