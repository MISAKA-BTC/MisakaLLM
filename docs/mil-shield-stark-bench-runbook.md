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

## Steps (on .119) — Plonky3 Circle-STARK/M31, EXECUTED

```
git clone --depth 1 https://github.com/Plonky3/Plonky3 && cd Plonky3
# add the postcard proof serializer to keccak-air dev-deps:
sed -i '/^proptest.workspace = true/i postcard = { workspace = true, features = ["alloc"] }' keccak-air/Cargo.toml
# drop in the harness (docs/bench/capbench_m31_keccak.rs) as an example:
cp <repo>/docs/bench/capbench_m31_keccak.rs keccak-air/examples/capbench.rs
cargo build --release --example capbench -p p3-keccak-air            # ~33 s on .119

# sweep: args = NUM_HASHES [num_queries] [log_blowup] [query_pow_bits]
B=./target/release/examples/capbench
$B 106 100 1 16    # spend proxy, ~116-bit
$B 106 16  5 16    # spend proxy, ~96-bit, tuned flat floor
```

The `sha256` variant (`prove_m31_sha256.rs`) uses `p3_sha256` only as the Merkle
commitment hash; the *proven* AIR is `KeccakAir`, so this is a Keccak-f proof over
M31 with a Circle-STARK PCS — the right unfriendly-hash proxy.

## Measured results (2026-07-10, .119, Plonky3 @ HEAD, M31 + CirclePcs)

| N (compressions) | blowup/queries/pow | ~security | proof |
|---|---|---|---|
| 106 (spend) | 1 / 100 / 16 | ~116-bit | **1,559 KiB** |
| 52 (claim) | 1 / 100 / 16 | ~116-bit | 1,522 KiB |
| 106 | 2 / 40 / 16 | ~96-bit | 686 KiB |
| 106 | 3 / 27 / 15 | ~96-bit | 500 KiB |
| 106 | 4 / 20 / 16 | ~96-bit | 399 KiB |
| 106 | 5 / 16 / 16 | ~96-bit | **342 KiB** (floor) |
| 256 / 512 | 1 / 100 / 16 | ~116-bit | 1,598 / 1,641 KiB |

**Findings.** (1) A flat proof is **342 KiB–1.56 MB = ~11–50× over the 32 KiB cap**.
(2) **Width-bound, not depth-bound**: 106→512 compressions barely moves the proof
(1,559→1,641 KiB), so our small circuit is already near its floor — the ~2,633-col
bit-decomposed Keccak AIR dominates per-query openings. (3) Higher FRI blowup
shrinks the proof but explodes prover cost. **⇒ recursion is mandatory (≈11–50×
compression); it is the load-bearing §SP-0 task.** An algebraic hash (Poseidon2,
~200× narrower) would nearly remove the recursion need but forks the committed F004
tree (ADR-0034 decision 2 — rejected).

## Still to measure

- **stwo** (`git clone starkware-libs/stwo`) — its recursion path (verify a proof
  inside a proof) to confirm the compressed size reaches < 32 KiB with no pairing.
  This is the number that closes the O-SP-1 cap question; the flat measurement above
  already proves flat is a non-starter.
- A real **keyed-BLAKE2b AIR** (vs the Keccak proxy) to pin the exact width.

## Decision rule (records into ADR-0035)

- Flat is a non-starter (measured megabyte). The open question is whether **PQ-only
  recursion** reaches < 32 KiB, or whether the DA cap must rise (ADR-0032) toward the
  realistic "tens of KiB, no pairing" target. Record the stwo recursion size when
  measured.

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
