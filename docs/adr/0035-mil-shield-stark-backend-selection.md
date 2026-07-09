# ADR-0035 — MIL shielded-pool STARK backend selection (O-SP-1)

- **Status:** Proposed (backend decision + cost groundwork; the prover, the
  measured bench, and the audit are the ADR-0033 §SP-0 milestone).
- **Date:** 2026-07-09
- **Extends:** ADR-0033 (§SP-0 hard gate, O-SP-1 open question), ADR-0034
  (reference→STARK swap; the `StarkVerifier` seam this backend plugs into).
- **Answers:** O-SP-1 — "zkVM (Risc0/SP1/S-two) vs hand-written STARK (Plonky3),
  decided by whether a single proof meets the 32 KiB cap." ADR-0033 anticipated
  this as its own ADR "once Phase SP-0 benchmarks land"; here is the decision
  frame, the cost model that drives it, and the two crates it lands in.

---

## 1. The decision is a size problem, and size is a hash problem

The shielded circuits are almost entirely one gadget: **keyed BLAKE2b-512**.
Everything else (value conservation, amount binding, token uniformity) is field
addition/comparison and is free by comparison. So the backend choice reduces to:
*how much BLAKE2b can we prove and still fit one proof under the 32 KiB DA cap
(§SP-0)?*

`misaka-mil-shield-stark-prove::cost` derives the exact BLAKE2b-512 compression
count from the frozen relations (`spend`, `provider`), and `mil-stark-cap-bench`
prints it. With the on-chain tree depth (`ShieldedPool.TREE_DEPTH = 20`) and the
keyed-BLAKE2b compression model (`1 key block + ⌈len/128⌉ message blocks`):

| circuit | hash calls | BLAKE2b-512 compressions | ~AIR area | ~2^k |
|---|---|---|---|---|
| spend (2-in / 2-out) | 50 | **106** | ~318k | 2^19 |
| provider-claim v2 | 25 | **52** | ~156k | 2^18 |

(Area = compressions × ~3000 cells/compression, the Keccak-class estimate; the
measured `.119` bench pins the real per-compression cost — see the runbook.)

The spend circuit is dominated (>70%) by the **40 Merkle-membership node hashes**
(2 inputs × depth 20). This is a Sapling-spend-class circuit (~2^18–2^19), and a
single **flat** FRI-STARK proof at that size and ~100-bit security is generally in
the tens-to-hundreds of KB — i.e. **over the 32 KiB cap**. So the design must
assume a **recursion/compression layer**, and the backend question becomes "which
stack gives a small, PQ-sound, client-side recursive proof?"

## 2. Hard constraint: soundness stays hash-based (SP-05)

The shielded pool's soundness is what stops MSK inflation: a forged proof mints
value from nothing (violates I-13 / SP-01). ADR-0033 SP-05 requires this be
**hash-based (PQ)**. That single constraint decides the field:

- **Pairing-based compression is prohibited.** A Groth16/BN254 wrap has a trusted
  setup whose toxic waste forges withdrawals, and its soundness is discrete-log
  (breakable by a CRQC). This directly disqualifies the *production* use of zkVMs
  whose only sub-cap proof is a Groth16 wrap.
- **Transparent STARK recursion is required** — compress a big STARK with an outer
  STARK, keeping soundness hash-based all the way down. No ceremony, PQ throughout.

`Backend::pq_only_subcap_path()` encodes exactly this gate.

## 3. Candidates

- **S-two / Circle-STARK (M31)** — StarkWare's prover, over the Mersenne-31 field.
  Purpose-built for **client-side proving** (prove on a phone/laptop), which is
  precisely our model (the prover runs on the provider box for claims, the wallet
  for spends; the witness never leaves the client). M31 + small-proof focus +
  native recursion make it the best fit for a sub-cap, PQ-only proof. **Front-runner.**
- **Plonky3 (BabyBear / KoalaBear / M31)** — a STARK *toolkit*: you author the AIR
  and the recursion yourself. Maximum control over field and layout; more to build
  and to audit. **Fallback** if S-two's tooling can't express the BLAKE2b AIR or
  the recursion we need.
- **Risc0 / SP1 (zkVMs)** — prove the *exact reference Rust* (`verify_reference`)
  with no hand-arithmetization, which is attractive for correctness. But their
  small on-chain proof is a **Groth16 wrap** (pairing), so they fail SP-05 for
  production. **Retained as an off-chain differential oracle** (P4): run the same
  statement through a zkVM to cross-check the hand-written verifier's accept/reject.

## 4. Decision

1. **Production backend: S-two / Circle-STARK (M31)**, with a **hash-based STARK
   recursion layer** to bring a spend/claim proof under 32 KiB. Plonky3 is the
   documented fallback. The final pick is confirmed by the measured `.119` bench
   (proof KB for ~106 BLAKE2b compressions in each) — the numbers, not the
   narrative, decide.
2. **Hash stays keyed BLAKE2b-512** (ADR-0034 decision 2): no friendly-hash swap,
   because it would fork the committed on-chain F004 Merkle tree and split the
   anonymity set. The cost of BLAKE2b-in-circuit is accepted and paid via recursion.
3. **zkVMs are oracle-only**, never the in-consensus verifier (SP-05).
4. **C-P6 (in-circuit ML-DSA-87 receipt) is deferred** to `circuit_version = 3`:
   at ~10²–10³× the spend circuit it is squarely recursion/zkVM territory and must
   not gate v1. Until then the receipt is checked off-circuit at the gateway (the
   honest v2 boundary from ADR-0034 §2.2).

## 5. What ships now (the groundwork, not the prover)

- **`misaka-mil-shield-stark-prove`** — the client-side prover crate. Ships the
  exact cost model + `mil-stark-cap-bench` (the O-SP-1 sizing tool) + a stable
  `prove(backend, circuit_version, vk, public_inputs, witness)` API that returns
  `BackendPending` until the milestone (so wallet/provider integration can be
  written against a fixed signature now).
- **`misaka-mil-shield-stark-verify`** — the in-consensus verifier crate.
  Implements `misaka_mil_shield::StarkVerifier` (the ADR-0034 §5 seam), so
  activation = "F006 calls `verify_shield_proof_with(bytes, vk, &StarkBackend)`".
  Inert (fail-closed, byte-identical to the reference-only node) until §SP-0. Its
  doc pins the SP-04 determinism rules the real verifier must obey.
- **`docs/mil-shield-stark-bench-runbook.md`** — how to run the measured proof-size
  bench on `.119` (Plonky3 `keccak-air` / stwo hash example as same-class proxies).

Nothing here changes consensus behavior: both crates are inert, the F006 fence is
`u64::MAX`, and no node yet links the verify crate into the precompile.

## 6. Gates before activation (unchanged §SP-0 discipline)

1. **Measured bench** (`.119`): a single proof for ~106 BLAKE2b compressions fits
   < 32 KiB at ≥ 96-bit security (via recursion) in the chosen backend.
2. **SP-04 conformance:** the in-consensus verifier is deterministic + portable +
   panic-free, with an x86-64 + aarch64 accept/reject corpus that agrees bit-for-bit
   (a divergence is a consensus split).
3. **Differential corpus (P4):** `reference_verify ⇔ stark_verify` over a shared
   `(stmt, wit)` corpus, plus a zkVM oracle cross-check.
4. **Audit** of the AIR + verifier + recursion (the soundness of the whole PQ
   island rests here).
5. **Activation** = F006 fence flip + proof-system policy `Reference → StarkOnly`
   (ADR-0034 §6), at a testnet re-genesis first, then mainnet.

## 7. Consequences

- **Positive.** The O-SP-1 question is answered on evidence: the circuits are
  sized from real structure, the SP-05 constraint cleanly rules out the
  pairing-wrap path, and the two crates give the prover/verifier a home wired into
  the existing seam. The decision (S-two + PQ recursion, Plonky3 fallback, zkVM
  oracle) is recorded and testable.
- **Cost / risk.** BLAKE2b-in-circuit + recursion is the real work — a
  multi-month, audited effort. If the measured bench shows even recursion can't
  reach 32 KiB, the fallbacks are (a) shrink the Merkle depth (smaller anonymity
  set — undesirable) or (b) raise the DA cap (an ADR-0032/EVM-lane change). Both
  are recorded here as levers, not defaults.
- **Honest boundary.** This ADR + these crates are the *decision and the scaffold*.
  They are not a working STARK. The prover, the measured cap proof, the SP-04
  corpus, and the audit remain the §SP-0 milestone, and the pool stays inert until
  all four land.
