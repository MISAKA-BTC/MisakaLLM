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

## Measured RECURSION results (2026-07-10, .119, Plonky3-recursion @ HEAD)

`recursive_keccak` (base Keccak uni-stark → N Poseidon2-hashed recursion layers,
KoalaBear, 106 hashes, 4 layers). The `common` helper already prints `Proof size`
per layer; the value converges to a fixed point ("a proof that verifies a proof"):

```
git clone --depth 1 https://github.com/Plonky3/Plonky3-recursion && cd Plonky3-recursion
cargo build --release --example recursive_keccak --features parallel     # ~3m11s
B=./target/release/examples/recursive_keccak
$B --num-hashes 106 --num-recursive-layers 4 --log-blowup 5 --query-pow-bits 16
# → last "Proof size:" line = converged outer proof
```

| recursion FRI blowup | converged outer proof |
|---|---|
| 2 | ~382 KiB |
| 3 | 286 KiB |
| 4 | 213 KiB |
| **5** (32× LDE, very costly) | **170 KiB** |
| quintic (D=5) @ blowup 4 | 275 KiB (worse) |

**Findings.** Hash-based recursion **does not reach 32 KiB** — floor ~170 KiB (~5×
over) at extreme blowup, ~213–382 KiB practical. The fixed point is high because the
recursion circuit must absorb the inner ~2,600-column Keccak trace openings; the
Poseidon2 recursion PCS (ADR-0035 §5.3) shrinks the Merkle-path part but not that
inner-width part. Timings (8-core/15 GB): base ~17 s, each recursive layer ~2.4 s,
peak ~7 GB (laptop-feasible, not phone). **⇒ Gate = T3 → ADR-0032 (raise the DA
cap).** This is experimental Plonky3-recursion on KoalaBear (2-adic); a stwo/M31
cross-check may do better (below).

## Structural reading (why it is a megabyte)

FRI proof size ≈ `num_queries × (opening cost ∝ trace WIDTH) + O(log² height)`. The
bit-decomposed Keccak AIR is ~2,633 columns, so each query opens ~11 KB and 100
queries ≈ 1.5 MB. The 106→512 flat-line (1,559→1,641 KiB) is the smoking gun: the
proof is **width-bound, not depth-bound**. This supersedes every prior *estimate*,
including the 50–100 KiB figure in the design-doc §8 and the ~150–350 KiB
literature range — all rejected by measurement.

## Decision thresholds — FROZEN before the stwo measurement (no moving goalposts)

Judge the measured **outer** (recursive / aggregated) proof at ≥ 96–100-bit
conjectured:

| gate | outer proof size | outcome |
|---|---|---|
| **T1** | ≤ 32 KiB | §SP-0 PASS. DA cap unchanged (ADR-0032 not needed). Small-batch, low-latency viable. |
| **T2** | 32 KiB < size ≤ ~120 KiB | Single proof occupies ~1 DAG block; practical use is batch-only. Cap held; ADR-0032 not triggered. |
| **T3** | > ~120 KiB | Fork: ADR-0032 (raise the DA cap + re-evaluate propagation risk) **or** revisit ADR-0034 (statement / tree). |

## Measurement items (one integration closes TWO open questions)

Record, per config — not size alone:

1. **outer proof size** (postcard bytes) → the T1/T2/T3 gate.
2. **prover wall-clock + peak RAM** → client-side viability. Recursion moves the
   pain from DA to the end-device prover; an inner-MB proof + a recursion layer at
   N seconds / M GB on a phone/laptop decides UX life-or-death. If too heavy, we are
   confirming why STRK20 keeps a central proving service.
3. **verifier wall-clock** → feeds `F006_VERIFY_GAS` calibration (O-SP-2) directly,
   so this one integration closes **O-SP-1 (cap) AND O-SP-2 (gas)** together.
4. **batch k sweep** (k ∈ {1, 8, 25}) → confirm the width-bound ⇒ "aggregation ≈
   free" prediction (outer size ~flat across k; per-tx DA = outer / k).

## stwo recursion cross-check (refinement, not blocker)

Plonky3-recursion already answered the gate (T3). A stwo/M31 cross-check may lower
the floor (M31 < KoalaBear field; StarkWare recursion is more mature), but it will
not change T3 unless it beats ~170 KiB by >5×, which is unlikely. stwo's recursion
is Cairo-based (verify stwo proofs in a Cairo program via stwo-cairo) — a heavier
integration than the Plonky3 example; do it only to tighten the ADR-0032 cap target.

- Clone `starkware-libs/stwo`; use its recursion/verifier example to verify an inner
  proof inside an outer proof; record the four items above.
- **Recursion-layer PCS hash = Poseidon2 (algebraic), NOT BLAKE2b.** The recursion
  circuit's cost is re-hashing the inner proof's Merkle openings, so a STARK-friendly
  PCS hash keeps it narrow (~200×). This is governed by `verifier_key_hash` /
  `circuit_version` and is **independent of the statement's F004 tree** — ADR-0034
  decision 2 constrains only the *statement* hash, not the PCS (ADR-0035 §5). Using
  BLAKE2b for the inner PCS would re-inflate the recursion circuit to ~2,600 columns
  and self-defeat. (PQ-consistent: SP-05 forbids *pairings*, not a hash-based
  algebraic hash; Poseidon2's youth is a risk-management note, not a structural break.)
- A real **keyed-BLAKE2b AIR** (vs the Keccak proxy) to pin the base statement width.

The bench is a **decision input, not a consensus artifact** — nothing here runs in
block validation. The in-consensus verifier (`misaka-mil-shield-stark-verify`) must
additionally pass the SP-04 cross-platform (x86-64 + aarch64) accept/reject
conformance corpus before any activation.
