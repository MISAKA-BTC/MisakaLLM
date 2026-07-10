# ADR-0035 — MIL shielded-pool STARK backend selection (O-SP-1)

> **Reference tree:** `feat/mil-v0` @ `d6e8297` (134 commits ahead of public main
> `9314c70`). The consensus cap cited here — `MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK =
> 32 KiB` (`consensus/core/src/evm/mod.rs`) — is this tree's Stage-B value; public
> main still carries `128 KiB`. They are the *same* ~1.25 MiB/s envelope at
> different BPS (ADR-0036 §1). Per-block sizes below are that envelope's 40-BPS
> slice; the load-bearing quantity is the envelope `E`, not the KiB figure.

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
(2 inputs × depth 20). Its **single flat Circle-STARK proof is a megabyte** — **measured** at 1.56 MB
(116-bit) down to a 342 KiB tuned floor (96-bit), i.e. **~11–50× over the 32 KiB
cap** (§4). So the design MUST assume a **recursion/compression layer**, and the
backend question becomes "which stack gives a small, PQ-sound, client-side
recursive proof?" — with the honest caveat (§4) that even recursion lands in the
*tens* of KiB, so sub-32-KiB is itself not free.

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

## 4. Evidence (measured, cited)

A primary-source review (2024–2026) plus a **real measurement on `.119`** confirm
the sizing and, critically, sharpen the honest boundary:

- **Measured (this repo, Plonky3 Circle-STARK over M31).** A real *flat* proof of N
  Keccak-f permutations — the unfriendly-hash proxy for keyed BLAKE2b — serialized
  with postcard (harness: `docs/bench/capbench_m31_keccak.rs`; repro in the
  runbook):

  | circuit (N compressions) | FRI blowup/queries/pow | ~security | proof |
  |---|---|---|---|
  | spend (106) | 1 / 100 / 16 | ~116-bit | **1,559 KiB** |
  | provider-claim (52) | 1 / 100 / 16 | ~116-bit | 1,522 KiB |
  | spend (106) | 2 / 40 / 16 | ~96-bit | 686 KiB |
  | spend (106) | 3 / 27 / 15 | ~96-bit | 500 KiB |
  | spend (106) | 5 / 16 / 16 | ~96-bit | **342 KiB** (tuned flat floor) |

  The flat proof is **~11× (tuned floor) to ~50× (baseline) over the 32 KiB cap** —
  *worse* than the ~150–350 KiB literature figure, because the bit-decomposed
  Keccak AIR is very wide (~2,633 columns) and per-query openings dominate. It is
  **width-bound, not depth-bound**: growing the circuit 106→512 hashes moves the
  proof only 1,559→1,641 KiB, so our small circuit already sits near its floor.
  Raising the FRI blowup shrinks the proof (342 KiB at blowup 5) but explodes
  prover time/memory. **Conclusion: a recursion layer is mandatory (flat is not
  merely "over cap," it is a megabyte)** — and the *measured recursion* (next) shows
  how far it actually gets: not to 32 KiB.
- **Measured recursion — the O-SP-1-closing number (this repo, `.119`,
  Plonky3-recursion `recursive_keccak`, KoalaBear + Poseidon2 recursion layers).**
  Multi-layer recursion of the 106-hash base proof converges to a fixed point (the
  size of "a proof that verifies a proof"):

  | recursion FRI blowup | converged outer proof |
  |---|---|
  | 2 | ~382 KiB |
  | 3 | 286 KiB |
  | 4 | 213 KiB |
  | 5 (32× LDE, very costly) | **170 KiB** |

  **Hash-based recursion does NOT reach the 32 KiB consensus cap**
  (`MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK`, verified — ~5× over at the ~170 KiB floor,
  ~7–12× over the ~213–382 KiB practical range). The fixed point is
  **self-referential**: the L1→L2→L3 series 499→384→382 KiB converges to the size of
  *the recursion circuit verifying itself*, **not** the inner statement — the ~2,600
  Keccak columns live only in L1 and are gone from L2 on. Two consequences: **(a)** the
  real keyed-BLAKE2b AIR width does NOT move the outer size — it only affects L0
  user-side proving (~17 s / 7 GB), so the **cap problem and the UX problem are
  independent variables**; **(b)** the only levers on the floor are **query count**
  (blowup / grinding, or a FRI successor — STIR/WHIR, ~1.5–3× smaller argument at
  equal security, *if* a mature Rust impl exists), **field size** (M31 < KoalaBear),
  and **recursion-impl maturity** (Plonky3-recursion is experimental; engineered
  stwo/SP1-class recursion may sit 1.3–2× lower). Timings (106 hashes, 8-core /
  15 GB): base ~17 s, each recursive layer ~2.4 s, peak ~7 GB — laptop-feasible, not
  phone. **⇒ indivisible: no single block fits it on any path (ADR-0036 §2).** Caveats: *experimental, unaudited* Plonky3-recursion on
  KoalaBear, not stwo/M31 (which may do better), no dedicated final-shrink layer;
  quintic (D=5) made it *worse* (275 KiB). External corroboration: Risc0 succinct
  (~200 KiB) and SP1 compressed STARK-only are hundreds-of-KiB-to-MB; the industry
  escapes small only via a Groth16 (pairing) wrap. **Nobody ships a tens-of-KiB
  PQ-only proof** — this is the world's floor, not a mistake.
- **Flat FRI does not fit (literature corroboration).** ethSTARK's *smallest* flat proof is 39.74 kB (80-bit,
  small trace); large traces run ~80 kB (80-bit) to ~110 kB (100-bit)
  (eprint 2021/582, Figs 5–6). Thaler's model puts 2^18 / 128-bit at ~270 KiB.
  For our hash-heavy circuit: **~150–350 KiB flat = 5–10× over the cap.**
- **The hard part is that even recursion is not automatically sub-cap.** A recursed
  hash-only proof still lands in the *tens* of KiB — proof-optimized Plonky2's floor
  is ~43 kB, itself > 32 KiB. **So "PQ-only AND < 32 KiB" is not an off-the-shelf
  configuration for any of the four**; hitting it needs aggressive tuning (high
  blowup + heavy grinding + a small field + a small final FRI layer + digest
  truncation to 20–25 B, per ethSTARK). **This tension — a hard 32 KiB on-chain cap
  vs hash-based (PQ) soundness — is the core §SP-0 open problem, not a solved
  setting.** Levers, recorded: (a) tune FRI hard for the M31/Circle path; (b) raise
  the DA cap (an ADR-0036 EVM-lane change) toward the realistic "tens of KiB, no
  pairing" target; (c) shrink Merkle depth (smaller anonymity set — undesirable).
- **zkVMs are confirmed pairing-locked at small size.** Risc0's hash-only *succinct*
  receipt is ~200 kB; its only on-chain-small proof is a Groth16 receipt over BN254.
  SP1's *compressed* recursive STARK is "constant size" but large/not-on-chain-
  optimized; its small proofs are BN254 Groth16 (~260 B) / PLONK (~868 B). Both
  small paths are pairing-based ⇒ SP-05-disqualified for production (oracle only).
- **stwo is the architectural PQ fit but audit-immature.** M31 + purely hash-based
  FRI, on-chain recursion **with no SNARK/pairing wrap** (as Starknet verifies stwo
  on L1), and client-side proving is its headline goal (recursive-verify of a 2^16
  proof ≈ 2.85 s on an M3 Max; default soundness 96-bit = 70 queries + 26 grinding).
  Caveat: **no public external audit report is posted yet.** The "~200-byte
  Circle-STARK proof" claim circulating online is false (that is SNARK-scale).
- **Plonky3 has an audited core but DIY recursion.** Core audited (Least Authority,
  Jul 2024), production-ready; fields BabyBear/KoalaBear/**M31**/Goldilocks; FRI is
  hash-only. But it is a *toolkit* (you author the AIR) and its recursion layer
  (`Plonky3-recursion`) is explicitly experimental/unaudited (2026).
- **Unfriendly-hash cost, measured.** Plonky3 `keccak-air` = 24 rows × 2,633 cols ≈
  63k cells per Keccak-f permutation; an algebraic hash (Poseidon2 ≈ 1 perm/row,
  ~298 cols) is ~200× cheaper. This is the measured price of ADR-0034 decision 2
  (keep keyed BLAKE2b so the committed F004 tree is not forked); the cost model uses
  the Keccak figure as the BLAKE2b proxy pending the `.119` measurement.

## 5. Decision

1. **Production backend: S-two / Circle-STARK (M31)**, with a **hash-based STARK
   recursion layer** to bring a spend/claim proof under 32 KiB. Plonky3 is the
   documented fallback. The final pick is confirmed by the measured `.119` bench
   (proof KB for ~106 BLAKE2b compressions in each) — the numbers, not the
   narrative, decide.
2. **Hash stays keyed BLAKE2b-512** (ADR-0034 decision 2): no friendly-hash swap,
   because it would fork the committed on-chain F004 Merkle tree and split the
   anonymity set. The cost of BLAKE2b-in-circuit is accepted and paid via recursion.
3. **The PCS hash is independent of the statement hash — and is where the width is
   won back.** ADR-0034 decision 2 constrains only the *statement* hash (the pool's
   F004 Merkle tree the circuit verifies); it does **not** reach the proof system's
   internal FRI/Merkle commitment hash, which is governed by `verifier_key_hash` /
   `circuit_version`. The recursion verifier circuit's cost is dominated by
   re-hashing the inner proof's Merkle openings, so choosing a **STARK-friendly PCS
   hash (Poseidon2) for the recursion layer** makes that circuit ~200× narrower and
   recovers the width reduction **without touching the committed tree**. Using
   BLAKE2b for the inner PCS would re-inflate the recursion circuit to ~2,600 columns
   and self-defeat. Whether a single outer proof reaches < 32 KiB turns almost
   entirely on this choice. PQ-consistent: SP-05 forbids *pairings*, not a hash-based
   algebraic hash (Poseidon2's relative youth is a risk-management note, not a
   structural break).
4. **Recursion is an SP-0 precondition, not an SP-4 improvement.** The measured
   megabyte flat proof (§4) means there is no flat-based v0.2 — any prior TPS
   estimate assuming a flat proof (incl. "10–25 TPS") is rejected. Recursion is what
   makes the pool exist at all.
5. **Batch aggregation is nearly free — a bonus of being width-bound.** Because the
   proof is width-bound (§4: 106→512 compressions is +5%), packing k JoinSplit/claim
   statements into one inner proof barely grows it, so **single-proof and batch
   aggregation are the same mechanism**: the recursion layer forced by SP-0 buys the
   v0.3 aggregation for free. Indicative per-tx DA and TPS at 10 BPS (to be replaced
   by the measured outer size):

   | config | per-tx DA | ~TPS @ 10 BPS |
   |---|---|---|
   | flat | 342 KiB–1.5 MB | **0 (over cap)** |
   | recursion, single (outer ~32 KiB) | ~36 KiB | ~36 |
   | recursion, batch k≈25 | ~5 KiB | **~250** (→ encNote floor ~385) |
6. **zkVMs are oracle-only**, never the in-consensus verifier (SP-05).
7. **C-P6 (in-circuit ML-DSA-87 receipt) is deferred** to `circuit_version = 3`:
   at ~10²–10³× the spend circuit it is squarely recursion/zkVM territory and must
   not gate v1. Until then the receipt is checked off-circuit at the gateway (the
   honest v2 boundary from ADR-0034 §2.2).

## 6. What ships now (the groundwork, not the prover)

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

## 7. Gates before activation (unchanged §SP-0 discipline)

1. **Measured cap bench — DONE, indivisible** (§4). Flat = a megabyte; hash-based
   recursion floors at ~170–382 KiB (Plonky3-recursion, KoalaBear + Poseidon2). No
   single block fits it on any path (ADR-0036 §2), so → ADR-0036 (chunk transport +
   windowed budget). Remaining refinements before activation: (a) a **stwo/M31** cross-check
   (may beat the KoalaBear floor); (b) a real keyed-BLAKE2b AIR (vs the Keccak
   proxy); (c) the verifier wall-clock number for O-SP-2 `F006_VERIFY_GAS`.
2. **SP-04 conformance:** the in-consensus verifier is deterministic + portable +
   panic-free, with an x86-64 + aarch64 accept/reject corpus that agrees bit-for-bit
   (a divergence is a consensus split).
3. **Differential corpus (P4):** `reference_verify ⇔ stark_verify` over a shared
   `(stmt, wit)` corpus, plus a zkVM oracle cross-check.
4. **Audit** of the AIR + verifier + recursion (the soundness of the whole PQ
   island rests here).
5. **Activation** = F006 fence flip + proof-system policy `Reference → StarkOnly`
   (ADR-0034 §6), at a testnet re-genesis first, then mainnet.

## 8. Consequences

- **Positive.** The O-SP-1 question is answered on evidence: the circuits are
  sized from real structure, the SP-05 constraint cleanly rules out the
  pairing-wrap path, and the two crates give the prover/verifier a home wired into
  the existing seam. The decision (S-two + PQ recursion, Plonky3 fallback, zkVM
  oracle) is recorded and testable.
- **Cost / risk — the measurement landed T3, resolved via the DA *envelope*, not a
  naive cap bump.** Both the flat proof (megabyte) and hash-based recursion
  (~170–382 KiB floor, §4) exceed the **32 KiB consensus cap**. But that cap is not
  arbitrary: `MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK`'s own derivation is **~1.2 MB/s DA
  envelope ÷ 40 BPS** — so the binding constraint is the *envelope*, not any per-block
  number. Because a single block cannot carry the proof on *any* path (ADR-0036 §2
  indivisibility lemma — even max STIR/WHIR floors at 57–113 KiB > cap), the resolution
  (**ADR-0036** — 0032 is Cancun) is **chunk transport**: split the outer into ≤32 KiB
  chunks so **every block stays its current size and the propagation profile is
  untouched**, gated by a **windowed budget** `Σ shielded-DA ≤ β·E·W` (β a
  BPS-invariant share of the envelope `E`). This is not a per-block cap raise at all —
  it asks in *rate*. Secondary levers (stwo/M31, STIR/WHIR) only tune the chunk count,
  never the need. The "sub-32-KiB PQ-proof" hope is **rejected by measurement**; the
  realistic PQ floor is hundreds of KiB, and the envelope — not the per-block cap —
  is what accommodates it.
- **Privacy is preserved by aggregation (witness-free).** Recursion consumes only the
  inner proof + public inputs, never the witness. So a user proves L0 locally (the
  ~1.5 MB flat proof is off-chain, harmless — only the outer touches the chain) and an
  aggregator recurses a bundle **without seeing any transaction content** — decisively
  unlike STRK20's Virtual-SNOS proving service that sees actions. The relayer/aggregator
  model does not weaken unlinkability. (A phone cannot do L0's ~7 GB ⇒ pair with a
  home/laptop prover; delegating the *witness* to a third-party prover WOULD break
  privacy and is forbidden — only proof *aggregation* may be delegated.)
- **Honest boundary.** This ADR + these crates are the *decision and the scaffold*.
  They are not a working STARK. The prover, the measured cap proof, the SP-04
  corpus, and the audit remain the §SP-0 milestone, and the pool stays inert until
  all four land.
