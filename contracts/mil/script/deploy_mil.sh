#!/usr/bin/env bash
# =============================================================================
# MIL v1 payment-suite deploy driver (ADR-0025 / v0.6 §8.2).
#
# The `misaka evm deploy|call` CLI is ABI-agnostic (raw init_code / calldata),
# so this driver does all Solidity ABI encoding with `forge` + `cast` and feeds
# the CLI raw hex. It deploys the CORE PAYMENT PATH only — the five contracts
# JobEscrow.claim() actually needs — plus the ONE mandatory wiring call
# (RewardPool.setJobEscrow), without which the 4%+3% legs of every claim revert
# NotJobEscrow. DisputeGame / MilGovernance / Paymaster / Faucet are off the
# claim happy-path and are a separate follow-on.
#
# MODES:
#   encode  (default) — build every init_code + calldata and PRINT them. No node,
#                       no key, no broadcast. This is the P0 offline validation.
#   deploy            — actually send via `misaka evm deploy|call` (needs a live
#                       EVM lane + a funded owner key). Dry-run unless --submit.
#
# All onlyOwner setters MUST come from the SAME key used as initialOwner, or they
# revert NotOwner and leave the suite half-wired.
# =============================================================================
set -euo pipefail

# ---- config (override via env) --------------------------------------------
MODE="${MODE:-encode}"                       # encode | deploy
SUBMIT="${SUBMIT:-0}"                         # 1 = pass --yes (deploy mode only)
MISAKA="${MISAKA:-misaka}"                    # path to the misaka CLI
EVM_RPC_URL="${EVM_RPC_URL:-http://127.0.0.1:8545}"
KEY_FILE="${KEY_FILE:-}"                      # owner EVM key file (deploy mode)
OWNER="${OWNER:-}"                            # 0x owner/deployer addr (deploy mode: derived from KEY_FILE if empty)
TREASURY="${TREASURY:-0x000000000000000000000000000000000000dEaD}"
DNS_THRESHOLD="${DNS_THRESHOLD:-1000000000000000000000000}"   # 1,000,000 MSK (wei) — ABOVE demo claims so the DNS-final gate never fires (F005 avoidance)
MIN_STAKE_A="${MIN_STAKE_A:-500000000000000000000000}"        # 500k MSK
MIN_STAKE_B="${MIN_STAKE_B:-100000000000000000000000}"        # 100k MSK
OUT="${OUT:-out}"                             # forge artifact dir
WORK="${WORK:-$(mktemp -d)}"
# ---------------------------------------------------------------------------

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
command -v cast >/dev/null || { echo "!! cast (foundry) not found"; exit 1; }
command -v jq   >/dev/null || { echo "!! jq not found"; exit 1; }

echo "== forge build =="
forge build >/dev/null

# creation bytecode of a contract artifact
bytecode() { jq -r ".bytecode.object" "$OUT/$1.sol/$1.json"; }
strip0x()  { printf '%s' "${1#0x}"; }

# In deploy mode, derive OWNER from the key if not given.
if [ "$MODE" = "deploy" ]; then
  [ -n "$KEY_FILE" ] || { echo "!! deploy mode needs KEY_FILE"; exit 1; }
  if [ -z "$OWNER" ]; then
    OWNER="$($MISAKA evm wallet address --key-file "$KEY_FILE" --output json 2>/dev/null | jq -r '.address // .Address // empty')"
    [ -n "$OWNER" ] || { echo "!! could not derive OWNER from KEY_FILE"; exit 1; }
  fi
  BASE_NONCE="$(cast to-dec "$(cast rpc --rpc-url "$EVM_RPC_URL" eth_getTransactionCount "$OWNER" latest | tr -d '"')")"
else
  OWNER="${OWNER:-0x00000000000000000000000000000000000000A1}"   # placeholder for encode-only address math
  BASE_NONCE="${BASE_NONCE:-0}"
fi
echo "owner=$OWNER  base_nonce=$BASE_NONCE  mode=$MODE  submit=$SUBMIT"

# Pre-compute each contract's deterministic CREATE address (sender+nonce), so
# cross-wired ctor args are known before any deploy.
addr_at() { cast compute-address "$OWNER" --nonce "$1" | awk '{print $NF}'; }
REGISTRY_ADDR="$(addr_at $((BASE_NONCE+0)))"
STAKE_ADDR="$(addr_at $((BASE_NONCE+1)))"
MODEL_ADDR="$(addr_at $((BASE_NONCE+2)))"
REWARD_ADDR="$(addr_at $((BASE_NONCE+3)))"
ESCROW_ADDR="$(addr_at $((BASE_NONCE+4)))"
echo "predicted: registry=$REGISTRY_ADDR stake=$STAKE_ADDR model=$MODEL_ADDR reward=$REWARD_ADDR escrow=$ESCROW_ADDR"

# init_code = creation bytecode ‖ abi.encode(ctor args)
init_code() { # $1=contract  $2=ctor-sig  $3..=args
  local c="$1" sig="$2"; shift 2
  local bc; bc="$(bytecode "$c")"
  local args=""
  if [ -n "$sig" ]; then args="$(strip0x "$(cast abi-encode "$sig" "$@")")"; fi
  printf '0x%s%s' "$(strip0x "$bc")" "$args"
}

declare -a NAMES=(ProviderRegistry StakeManager ModelRegistry RewardPool JobEscrow)
declare -a INIT
INIT[0]="$(init_code ProviderRegistry 'constructor(address)' "$OWNER")"
INIT[1]="$(init_code StakeManager     'constructor(address,uint256,uint256)' "$OWNER" "$MIN_STAKE_A" "$MIN_STAKE_B")"
INIT[2]="$(init_code ModelRegistry    'constructor(address)' "$OWNER")"
INIT[3]="$(init_code RewardPool       'constructor(address,address)' "$OWNER" "$TREASURY")"
INIT[4]="$(init_code JobEscrow        'constructor(address,address,address,uint256)' "$OWNER" "$REGISTRY_ADDR" "$REWARD_ADDR" "$DNS_THRESHOLD")"

# Mandatory wiring: RewardPool.setJobEscrow(escrow)  (else claim's val/treasury legs revert)
SETESCROW_DATA="$(cast calldata 'setJobEscrow(address)' "$ESCROW_ADDR")"

echo
echo "== init_code sizes =="
for i in "${!NAMES[@]}"; do printf '  %-16s %6d bytes\n' "${NAMES[$i]}" "$(( (${#INIT[$i]} - 2) / 2 ))"; done
echo "  wiring RewardPool.setJobEscrow -> $ESCROW_ADDR  calldata=$SETESCROW_DATA"

if [ "$MODE" = "encode" ]; then
  for i in "${!NAMES[@]}"; do printf '%s\n' "${INIT[$i]}" > "$WORK/${NAMES[$i]}.initcode.hex"; done
  echo
  echo "ENCODE-ONLY complete. init_code + calldata written under: $WORK"
  echo "P0 validation passed: forge build + bytecode extract + ctor ABI-encode + CREATE-address math all OK."
  echo "To deploy on a live lane:  MODE=deploy KEY_FILE=... EVM_RPC_URL=... SUBMIT=1 $0"
  exit 0
fi

# ---- deploy mode ----------------------------------------------------------
YES=(); [ "$SUBMIT" = "1" ] && YES=(--yes --wait)
deploy_one() { # $1=name $2=initcode-hex
  local f="$WORK/$1.initcode.hex"; printf '%s' "$2" > "$f"
  echo "== deploy $1 =="
  $MISAKA evm deploy --evm-rpc-url "$EVM_RPC_URL" --bytecode-file "$f" --key-file "$KEY_FILE" "${YES[@]}"
}
for i in "${!NAMES[@]}"; do deploy_one "${NAMES[$i]}" "${INIT[$i]}"; done
echo "== wire RewardPool.setJobEscrow =="
$MISAKA evm call --evm-rpc-url "$EVM_RPC_URL" --to "$REWARD_ADDR" --data "$SETESCROW_DATA" --key-file "$KEY_FILE" "${YES[@]}"
echo "done. escrow=$ESCROW_ADDR registry=$REGISTRY_ADDR reward=$REWARD_ADDR"
