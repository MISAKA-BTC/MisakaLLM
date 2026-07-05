# misaka-compute-attestor (ADR-0024 §20, Phase A)

The MISAKA Inference Lane (MIL) **compute-attestor** sidecar — the security-issuance
role for GPU providers. It mirrors the DNS-validator epoch-attestation duty
([`kaspa-pq-validator`](../../kaspa-pq-validator)): each epoch it signs the
ready-to-attest chain anchor with its ML-DSA-87 key under the disjoint
`misaka-mil-v1/compute-attest/mldsa87` context, committing its device-certificate
hash (§20.5 device binding).

## Phase A = record only, zero liveness risk

This crate implements **Phase A** of ADR-0024: it **measures + records**, it does
**not** enter the reorg gate and does **not** change coinbase.

- The attestation is carried as an ordinary **NATIVE-tx payload** (the same
  `MilAnchorPayload` mechanism the v0 provider anchors use) — **no new
  subnetwork, no coinbase change, no consensus rule change.** A keeper/indexer
  reads these payloads to measure `compute_depth`.
- The issuance reward (reviving the `FeeSplitParams` service slot, §20.4) and the
  Phase-C reorg-gate dimension (Triple Nakamoto Security) are **separate,
  HF-gated steps** and are deliberately NOT in this crate. See
  [ADR-0024](../../docs/adr/0024-mil-gpu-attestation-computedepth.md).

## Usage

```bash
# 1. generate the attestor key + print the funding address
misaka-compute-attestor keygen --out attestor.seed --network testnet-10

# 2. fund the printed address, place a native bond, note its txid:index

# 3. run (dry-run by default; add --submit to broadcast)
misaka-compute-attestor run \
  --attestor-seed attestor.seed \
  --bond <bond-txid>:<index> \
  --device-cert-hash <128-hex TEE-cert or canary-profile hash> \
  --tier tee \
  --network testnet-10
# add --submit once the funding address has a mature UTXO
```

`status` prints the identity + funding address without connecting.

## What it signs

The `ComputeAttestation` (in `misaka-mil-core::compute_attest`) binds:
`version ‖ network_id ‖ attestor_id ‖ bond ‖ epoch ‖ target_hash ‖ target_daa_score
‖ device_cert_hash ‖ tier`, ML-DSA-87-signed under the compute-attest context and
verified with the portable libcrux backend (bit-identical accept/reject). The
`attestor_id` is `Hash64_k("misaka-mil-v1/compute-attest", pubkey)`, disjoint from
the DNS `validator_id` and the MIL `provider_id`.

## Weight is bond, not FLOPS (§20.3)

Consensus weight (when Phase C activates) is `min(bond, compute_bond_cap)` — a
slashable, unbond-delayed native bond that sets the cost-of-attack floor. GPU
existence (the device-cert / canary hash committed here) gates **eligibility**,
challengeable off-chain; it is never a weight.
