# MIL shielded-pool STARK cap-bench runbook (§SP-0 / O-SP-1)

The `mil-stark-cap-bench` tool sizes the two circuits from the frozen relations
and prints the cap regime, but it takes ONE measured input — the AIR area per
BLAKE2b-512 compression — and it does not measure a real proof size. This runbook
pins both by running the candidate provers on a real host. **Do the heavy builds
on `ubuntu@160.16.131.119`** (cargo 1.94, Linux x86_64 8c), not the Mac.

## What we are measuring

1. `constraints_per_compression` — AIR cells one BLAKE2b-512 (or, as a proxy, one
   Keccak-f) compression costs in each framework. Feeds `mil-stark-cap-bench <cpc>`.
2. `proof_bytes` — the actual serialized proof size for K compressions at
   ~96–100-bit security, so we know the real KB vs the 32 KiB cap and whether a
   recursion layer is needed (the O-SP-1 decision).

## Proxy circuit

Writing a full keyed-BLAKE2b AIR is the milestone work; for the *bench* use each
framework's shipped unfriendly-hash AIR as a same-class proxy and extrapolate:

- **Plonky3** — `p3-keccak-air` proves N Keccak-f[1600] permutations. Prove
  N ∈ {32, 64, 128} (our spend ≈ 106 BLAKE2b compressions), record trace rows,
  prove time, verify time, and serialized proof size. Field: BabyBear or M31.
- **stwo (Circle-STARK / M31)** — use the examples' hash/Blake component to prove
  N compressions; record the same. Note whether proof-size-optimized params
  (fewer FRI queries + higher grinding bits) bring a single proof under 32 KiB.

## Steps (on .119)

```
# Plonky3 proxy
git clone https://github.com/Plonky3/Plonky3 && cd Plonky3
cargo bench -p p3-keccak-air 2>&1 | tee /tmp/p3-keccak.txt        # rows + timings
# serialize a proof and `wc -c` it for N in {32,64,128}; log proof_bytes(N)

# stwo proxy
git clone https://github.com/starkware-libs/stwo && cd stwo
cargo run --release --example <blake_or_hash_example> 2>&1 | tee /tmp/stwo.txt
# vary FRI queries / grinding; log proof_bytes vs security_bits

# feed the measured area back into our sizing:
cargo run -p misaka-mil-shield-stark-prove --bin mil-stark-cap-bench <measured_cpc>
```

## Decision rule (records into ADR-0035)

- If a **single flat** proof for ~106 compressions is < 32 KiB at ≥ 96-bit
  security in either framework → no recursion needed for spend; pick the framework
  with the better client-side prove time.
- If not (the expected outcome, per the sizing tool) → a **hash-based STARK
  recursion/compression** layer is required. A pairing wrap (Groth16/BN254) is
  **prohibited** (SP-05: trusted-setup toxic waste = forgeable withdrawals). This
  is why Risc0/SP1 are oracle-only, not production verifiers.
- Record: `constraints_per_compression`, `proof_bytes(N)` per framework, the
  chosen backend, and whether recursion is in-scope for v1 or deferred.

The bench is a **decision input, not a consensus artifact** — nothing here runs in
block validation. The in-consensus verifier (`misaka-mil-shield-stark-verify`)
must additionally pass the SP-04 cross-platform (x86-64 + aarch64) accept/reject
conformance corpus before any activation.
