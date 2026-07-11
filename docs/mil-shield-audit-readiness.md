# MIL Shielded Pool — audit-readiness package (§SP-0 gate)

> **Purpose.** This is the document handed to an external auditor before the ADR-0033
> §SP-0 milestone. It scopes exactly what must be audited, states the trust model and
> the properties claimed, points at the proven-and-measured artifacts, and lists every
> known gap and caveat honestly. It is NOT a claim that the system is audited — it is
> the map an auditor needs. Nothing described here is activated on any network (the
> F006 activation fence is `u64::MAX` on all presets; see §7).

## 1. What the shielded pool is

A PQ, hash-based value pool on the MIL L2 (ADR-0033 §4). A **spend** consumes up to two
committed notes and creates two, proving Merkle membership + spend authority + nullifier
correctness + value conservation **without revealing which** notes are consumed. `shield`
(`v_pub_in>0`), `transfer` (both 0), and `unshield` (`v_pub_out>0`) are one parameterised
statement, so the anonymity set is never split. Every primitive is keyed BLAKE2b-512 (the
chain's canonical PQ hash) — no elliptic curves, no pairings; the succinct proof is a
hash-based STARK (ADR-0035), so soundness is fully post-quantum.

## 2. Audit scope (in priority order)

| # | component | source | what to audit |
|---|---|---|---|
| A | **The spend AIR** (the ZK relation) | `docs/bench/plonky3-shield-air/spend.rs` (build#4) | that the AIR accepts a trace **iff** `spend::verify_reference` accepts — no under-constraint (forgery), no over-constraint (liveness); the 66-bit value conservation; the dummy-input gating; the which-note-hiding MUX |
| B | **The hash gadget** | `compress.rs` (build#1) + `mil/blake2b-air` | that the compression AIR computes exactly keyed BLAKE2b-512 (diff-tested byte-for-byte vs `kaspa_hashes::blake2b_512_keyed`) |
| C | **The recursion** | `recursive_spend.rs` (build#5) + `Plonky3-recursion` | that the outer proof soundly attests the inner proof; the hiding config; the public-value binding across layers |
| D | **The in-consensus verifier** | `mil/shield-stark-verify/src/lib.rs` | SP-04 determinism + panic-freedom; the §SP-0 SEAM (§6) — the STARK verify + statement↔public-value binding that is **not yet implemented** |
| E | **The DA transport** | `mil/shield-da/src/lib.rs` | chunk/reassemble integrity; the settling-tx ↔ set_id binding (ADR-0036) |
| F | **The reference relation** | `mil/shield/src/{spend,note,merkle,proof,provider}.rs` | the semantics the ZK system must match; the pool caller obligations (§5) |
| G | **Upstream** | `Plonky3` (crates.io 0.6) + `Plonky3-recursion` | Plonky3 core was audited (Least Authority, Jul 2024); **Plonky3-recursion is explicitly experimental / unaudited (2026)** — this is the single largest external-audit surface |

## 3. Properties claimed (and how each is evidenced)

- **Soundness (no false spend passes).** The AIR is constraint-for-constraint equal to
  `verify_reference`; an adversarial 4-lens panel (under-constraint forgery, reference
  completeness, offset audit, degree/config) on build#4 found **zero circuit-logic
  defects**. Six semantic negatives reject (`--corrupt` / `--wrong-anchor` / `--wrong-nf`
  / `--steal` / `--bad-value` / `--dummy-nonzero`). *Auditor: re-run the panel; the STARK
  back-half binding (§6) is the un-evidenced piece.*
- **Completeness (every valid spend proves).** Positive cases (2 real inputs; 1 real +
  1 dummy) verify. The reference relation and the AIR agree on the full 2-in/2-out shape.
- **Zero-knowledge (witness hidden).** Proven under the **hiding FRI** variant
  (`HidingFriPcs` + salted `MerkleTreeHidingMmcs`). Empirically gated by a
  **witness-absence** test: no private word (sk, note fields, values, path, index) appears
  in the proof bytes — checked on the real 5.4 MB layer-0 proof (436 words absent) and the
  40 KB compressed outer proof. *Formal ZK rests on the hiding FRI; the witness-absence
  scan is a leakage smoke-test, not a proof of ZK.*
- **Which-note unlinkability.** The Merkle index is a **private** witness; membership is
  proven at a private index via the direction-bit MUX. Demonstrated at production depth 20.
- **Post-quantum.** Hash-based throughout (BLAKE2b-512 base statement, Poseidon2 recursion
  PCS). No secp/pairing on any path; the verifier crate's dep graph is secp-free.

## 4. Measured artifacts (reproducible)

All measured on the build host (`.119`, BabyBear + Poseidon2). Full commands in
`docs/bench/plonky3-shield-air/README.md` and the `recursive_spend.rs` header.

- **build#1** compression AIR: `host diff-test: trace h_out == on-chain digest = TRUE`,
  VERIFY ok, `--corrupt` → reject.
- **build#3** depth-20 membership (real node hash): VERIFY ok, prove 2.2 s, PRIVACY OK,
  3 negatives reject.
- **build#4** full spend: 64×110,471 cols, VERIFY ok, prove 6.2 s, 6 negatives reject,
  4-lens panel clean.
- **build#5** recursion: the REAL spend proof compresses **5.4 MB → 40,392 B = 2 × 32 KiB
  DA chunks**, witness hidden; tamper-negative rejects at the layer-1 circuit.
- **E2E** (`mil/shield/tests/private_transfer_e2e.rs`, reference level): shield → private
  transfer → re-spend, via envelope + 32 KiB DA chunking + pool application; double-spend,
  unknown-anchor, tampered/missing-chunk, same-note-both-slots all rejected. The real
  compressed proof rides the DA path byte-faithfully (`MIL_OUTER_PROOF`).

## 5. Trust model & caller obligations

- **Pinned verifier key.** `verifier_key_hash` is pinned on-chain (`ShieldedPool.spendVkHash`)
  and checked **before** any backend runs (`proof.rs:143`). It must be the hash of the
  final recursion layer's verifier key / circuit fingerprint, set by a **vk-pinning
  ceremony** (ADR-0034 §7 P5; deterministic, no toxic waste). *Auditor: the ceremony and
  what exactly the hash commits to.*
- **Sequential nullifier application (caller obligation).** Neither the relation nor the
  circuit enforces `nf_old[0] != nf_old[1]`; the pool caller MUST apply nullifiers
  **check-then-insert per nullifier, sequentially** (documented at `proof.rs:118`, mirrored
  by `ShieldedPool.sol _spend`). Batch application would accept the same note in both slots
  (value doubling) — pinned as a regression test (`private_transfer_e2e.rs`
  `same_note_in_both_slots_is_stopped_by_sequential_application`).
- **`ctx` is contract-recomputed.** The statement carries `ctx` but the relation does not
  constrain it; the contract recomputes and compares it (anti-malleability / fee / recipient
  binding lives at the contract layer, not the proof).

## 6. The §SP-0 SEAM — what is NOT yet done (the core audit obligation)

`verify_stark` (`mil/shield-stark-verify/src/lib.rs`) implements the **deterministic front
half** (bounds + panic-free borsh decode of the statement) and stops at a marked seam that
still returns `BackendPending`. The back half — the actual STARK verify + statement binding
— is the audit-gated §SP-0 work. It is currently fail-closed, so none of the below is a
*live* exploit; each is an **implementation obligation** whose omission is the named
value-forgery/theft vector. This list (from the 3-lens F006 review, commit `bce174c`) is
the checklist for whoever writes the back half. **Note the mock `Accepting` backend in
`proof.rs` tests returns the decoded statement with NO verification — a naive seam fill-in
that copies it is the exact CRITICAL-1 attack.**

1. **[CRITICAL] The proof cryptographically verifies against `vk_hash` — not merely
   decodes.** The envelope check (`proof.rs:143`) only string-compares the proof's
   *self-declared* `verifier_key_hash` field to the pinned value; it proves nothing about
   the bytes. `_vk_hash` is currently `_`-discarded — it must become load-bearing: hydrate
   the VK that hashes to `vk_hash`, then run the full FRI/DEEP-ALI verify (transcript, query
   openings, Merkle-cap authentication, out-of-domain constraint/quotient consistency).
   *Skip → any bytes with the pinned `verifier_key_hash` and a value-minting statement are
   accepted = unlimited counterfeit shielded value.* **Accept-test:** one-bit-mutated proof
   rejects; a proof under a different valid VK rejects.
2. **[CRITICAL] Statement ↔ public-value binding (the single most dangerous gap — a proof
   is a public, reusable object).** `decode_statement` parses `public_inputs` but nothing
   ties those bytes to the proof. Recompute the public-input field vector from the *decoded*
   statement under the frozen encoding and assert element-for-element equality with the
   values bound in the proof (`pack_public_values`), and require that same vector was
   absorbed into the transcript. *Skip → take any previously-valid proof and re-submit it
   with `public_inputs` swapped to a statement that redirects `cm_payout` / sets a large
   `v_pub_out` = value forgery by replay.* **Accept-test:** keep a valid proof, substitute a
   different well-formed statement of equal borsh length → must reject.
3. **[CRITICAL] Inner-circuit fingerprint matches `(vk_hash, circuit_version)`.** The outer
   proof carries a fingerprint of the inner AIR it verified; assert it equals the fingerprint
   the governance registry pins for `(vk_hash, circuit_version)`. *Skip → a valid proof of
   the easy circuit (or ProviderClaim) is accepted as a proof of the hard circuit (Spend), so
   value-conservation/nullifier constraints the pool assumes were never proven = value
   creation.* **Accept-test:** a genuine ProviderClaim proof submitted as `CIRCUIT_SPEND`
   (with a matching-length forged `SpendStatement`) rejects.
4. **[HIGH] Pinned Fiat-Shamir transcript (SP-04).** No `fri-transcript`/challenger domain
   exists in `domains.rs` yet. Define and freeze a versioned `misaka-shield-v1/fri-transcript`
   keyed-BLAKE2b-512 challenger with a pinned absorb/squeeze order (VK, public values, trace
   & quotient Merkle caps, per-round squeeze), M31-only, no SIMD-branch. *Skip →* (a)
   **soundness**: a biasable/precomputable challenger lets the prover grind challenges to
   forge a low-degree proof; (b) **consensus split**: byte-different transcript framing across
   node builds → different challenges → different accept/reject on the same input.
   **Accept-test:** x86-64 + aarch64 (SIMD on/off) byte-identical decision on a fixed vector;
   a Fiat-Shamir grinding negative.
5. **[HIGH] Pinned structural params validated by EXACT equality before the verify loop —
   both a DoS and a soundness guard.** `MAX_STARK_PROOF_BYTES` bounds byte length, not
   internal structure. Parse the proof's declared FRI query count / folding rounds /
   log-trace-degree / Merkle-cap height and assert each **equals** (not ≤) the pinned value
   for `(vk_hash, circuit_version)`. *Skip →* under-querying FRI lowers the soundness error
   (false proof passes); an over-declared degree/round count makes a byte-small proof do
   pathological work. **Accept-test:** a proof declaring fewer queries than pinned rejects;
   a byte-small proof declaring an oversized degree rejects before any hashing.

**Gas/size co-calibration [LOW].** `F006_VERIFY_GAS = 3_000_000` is a *flat* up-front charge
(`shielded.rs:86`); with `EVM_GAS_LIMIT = 7_500_000` only ⌊7.5M/3M⌋ = **2 F006 verifies per
chain block**, so 1 MiB × 2 is not a CPU-DoS. But the flat charge under-prices large proofs:
before activation, bench the worst case `verify(MAX_STARK_PROOF_BYTES, max pinned queries)`
on the slowest no-SIMD reference image and co-calibrate `(MAX_STARK_PROOF_BYTES,
F006_VERIFY_GAS)`; tighten `MAX_STARK_PROOF_BYTES` from the generous 1 MiB to the real
recursion-outer-proof max (~40–382 KiB). Item 5's exact-query check is what stops a
within-cap pathological proof from buying max work at min gas.

Wiring the real back half pulls in a **verify-only Plonky3 subset** (`p3-batch-stark` /
`p3-recursion`) into a consensus crate — the experimental, unaudited dependency ADR-0035 §8
flags. It must be no-rayon (determinism) and every `unwrap`/`assert`/index made fail-closed.

## 7. Activation gating (why nothing is live)

Two independent gates, both closed:

1. **Existence fence** `evm_f006_shielded_verify_activation_daa_score = u64::MAX` on **all
   four presets** (`consensus/core/src/config/params.rs`). While `u64::MAX`, the F006
   handler is never registered; `0x…F006` and the pool `0x…F010` are empty accounts;
   genesis/state roots unchanged. The reference→STARK swap (`kaspa-evm/src/shielded.rs`,
   commit `bce174c`) is therefore **behaviourally inert** — it routes STARK-tagged proofs
   to the fail-closed `StarkBackend`, returning the identical ABI result for every input.
2. **Acceptance policy.** Today `verify_shield_proof` accepts REFERENCE and rejects STARK
   (fail-closed). Production must flip to StarkOnly (SP-05/SP-09) — not yet a wired network
   parameter.

Activation = fence flip + policy flip, at a **testnet re-genesis first**, then mainnet — a
governance/HF decision, out of scope for code. The §SP-0 exit gates before either flip
(ADR-0035 §7): (1) cap-bench resolved via ADR-0036 chunk DA; (2) SP-04 conformance corpus
(x86-64 + aarch64, bit-for-bit); (3) differential corpus `reference_verify` ↔ `stark_verify`;
(4) **external audit** of AIR + verifier + recursion; (5) activation.

## 8. Known caveats (bench vs production)

- **FRI parameters.** Demonstrations use reduced security to fit measurement/RAM (the
  completed real-proof recursion used `--security-level` in the 23–61 range). True ~100-bit
  conjectured security needs more FRI queries → the layer-1 recursion of the 110,471-column
  inner AIR needs a **≥ 32 GB** box (the single 15 GB build host, shared with a testnet
  node, caps the achievable security). Production runs full security on a non-shared box.
- **Entropy.** The hiding salts must seed from OS entropy (`--prod-entropy`, `/dev/urandom`);
  the seeded bench default is NOT zero-knowledge.
- **Field.** BabyBear here; ADR-0035's production field is M31/Circle-STARK (a config swap).
- **`MAX_STARK_PROOF_BYTES` / `F006_VERIFY_GAS`** are provisional (ADR-0036 O-SP-1 / O-SP-2).

## 9. Adversarial review log

- build#4 spend AIR — 4-lens panel (under-constraint / completeness / offset / config):
  zero circuit-logic defects; config-level findings recorded in the file header.
- build#5 recursion + E2E — validated end to end; the same-note-both-slots pool finding
  pinned as a regression.
- F006 verifier front-half + swap (commit `bce174c`) — 3-lens panel (determinism/panic,
  §SP-0 seam obligations, inert-landing safety):
  - **Determinism/panic-freedom: CONFIRMED CLEAN.** No `unwrap`/`expect`/panic/slice-index
    on any attacker-controlled path; only fallible `try_from_slice` + length compares. No
    floats, no SIMD-dependent control flow, no map-iteration; the borsh error `String` is
    telemetry only (never consensus-branched). All error variants map uniformly to a reject
    at both boundaries. Malformed/truncated/trailing-byte/oversized inputs all `Err`, never
    unwind. Check order correct (proof cap → decode → public-input cap → decode).
  - **Inert-landing: CONFIRMED CLEAN** on every preset. Fence `u64::MAX` on
    mainnet/testnet/simnet/devnet → F006 handler never registered → `0x…F006` empty account,
    genesis/state roots unchanged. The swap touches only the pure verify body + the dep list;
    behaviourally byte-identical for every input class even if the fence were open. The new
    dep is secp-free / PQ-only / no-revm and adds **zero** new transitive crates (Cargo.lock
    diff = one line). A default (non-`evm`) node never links it.
  - **§SP-0 seam: 3 CRITICAL + 2 HIGH obligations** (the §6 checklist) — all correctly
    fail-closed today; none is a live exploit, each is a named forgery vector for the back
    half. Two doc-accuracy fixes applied (the size-cap allocation narrative; the
    `ProviderClaimStatement` = 328 B figure).
