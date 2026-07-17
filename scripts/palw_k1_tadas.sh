#!/usr/bin/env bash
# ADR-0039 Canonical Compute v1 — K1 runbook for the tadas RTX host.
#
# Runs the real-Qwen single-node determinism (K1) + V_i generation + peak-VRAM harness on an NVIDIA GPU
# and prints a JSON report. Copy that JSON back so the measured values can be committed into a
# PalwComputeSetRecordV1 (vector_commitment, compute_work_scale evidence, peak-VRAM participation floor).
#
# This session (on the Mac) cannot reach the Tailscale-only host, so run this ON tadas:
#   ssh tadas@100.125.83.97          # from a machine on the tailnet
#   # get the repo there (clone the misakas feat/mil-v0 branch or rsync your working tree), then:
#   bash scripts/palw_k1_tadas.sh /path/to/qwen.gguf /path/to/tokenizer.json
#
# Args: $1 = GGUF weights path, $2 = tokenizer.json path. Env overrides: QWEN_MAX_NEW_TOKENS, QWEN_REPEATS.
set -euo pipefail

GGUF="${1:?usage: palw_k1_tadas.sh <qwen.gguf> <tokenizer.json>}"
TOK="${2:?usage: palw_k1_tadas.sh <qwen.gguf> <tokenizer.json>}"

export QWEN_GGUF_PATH="$GGUF"
export QWEN_TOKENIZER_PATH="$TOK"
export QWEN_MAX_NEW_TOKENS="${QWEN_MAX_NEW_TOKENS:-16}"
export QWEN_REPEATS="${QWEN_REPEATS:-5}"

echo "== PALW K1 harness on $(hostname) ==" >&2
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader >&2 || {
  echo "nvidia-smi not found — is this a CUDA host?" >&2; exit 1; }

# --features qwen-cuda for the RTX. (qwen-metal / qwen-backend also work for a smoke test elsewhere.)
cargo run --release -p misaka-mil-provider --features qwen-cuda --bin palw-k1-harness

echo >&2
echo "== done. Paste the JSON above back to integrate the set-record values. ==" >&2
