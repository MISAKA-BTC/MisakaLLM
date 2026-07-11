# MIL Shielded Pool — audit-readiness package (§SP-0 gate)

> **Purpose.** This is the document handed to an external auditor before the ADR-0033
> §SP-0 milestone. It scopes exactly what must be audited, states the trust model and
> the properties claimed, points at the proven-and-measured artifacts, and lists every
> known gap and caveat honestly. It is NOT a claim that the system is audited — it is
> the map an auditor needs. Nothing described here is activated on any network (the
> F006 activation fence is `u64::MAX` on all presets; see §7).

> **Gate-status legend (audit D-01).** To prevent reading "landed" as "done", each gate
> below is one of five explicit stages, most-to-least complete:
> **[audited]** → **[E2E-pass]** (real artifact through prover→node→F006→contract) →
> **[CI-required]** (a mandatory job fails without it) → **[code-present]** (implemented,
> not yet a required-CI/E2E gate) → **[design]**. A claim of "code-present" is NOT
> end-to-end acceptance. As of the 2026-07-11 follow-up audit (snapshot `c8d729a`, verdict
> **A7 = NO-GO**), the honest high-water marks are: contract layer [E2E-pass via Foundry,
> but F006 mocked]; reference relations [code-present + unit-tested]; STARK verifier back
> half [**real-artifact-verified** under `--features stark-backend`, but NOT release-default,
> NOT CI-required — see A1/A3 note below]; C-P6 receipt circuit (v3) [design + isolated-gadget
> code-present, composition INCOMPLETE]; A2 statement surfacing [node-side code-present,
> prover-side surfacing INCOMPLETE]; A3 vk/manifest binding [code-present after K-01.1 fix:
> real commitment + lossless op fingerprint bound; full ceremony manifest still [design]]. No
> gate below is [audited]. Remaining activation blockers per the follow-up audit: C-06.1,
> C-06.2 (circuit half), K-01.2 (prover surfacing), K-01.3 (release backend + per-circuit VK
> registry), M-07 (real-backend/cross-arch/Foundry mandatory CI), A7 (governance HF).
>
> **A1/A3 real-artifact evidence (2026-07-11).** The real `verify_stark` back half was run
> against a genuine 100-bit-security recursion outer proof (`spend_outer_sec100.bin`, 171,765 B,
> generated under the pinned 100-bit FRI config): the proof **crypto-verifies AND its vk_hash
> matches** (`A1/A3 real backend: proof crypto-verifies + vk_hash matches; A2 node-binding
> fail-closed (prover surfacing pending)`), and a one-bit-tampered copy is rejected. Fail-closed
> is confirmed the other way too: the earlier `spend_outer_prod.bin` (103,082 B, pre-100-bit
> params) is REJECTED (`STARK verify rejected`) under the current pinned config — a proof made
> with non-pinned params cannot pass. This lifts the STARK back half (A1) + the vk_hash binding
> (A3) from "code-present" to **real-artifact-verified on aarch64** (the residual A2 prover
> surfacing keeps the node-binding fail-closed, and this is not yet a required-CI job = A5/M-07).
> Reproduce: `MIL_OUTER_PROOF=spend_outer_sec100.bin cargo test -p misaka-mil-shield-stark-verify
> --features stark-backend --release real_backend -- --nocapture`. The `sec100`/`prod` artifacts
> are byte-identical between the x86-64 build host and the aarch64 verifier (sha256 match).
>
> **A5 cross-arch VERIFY determinism (2026-07-11).** The identical `sec100` proof was verified on
> BOTH architectures with the real back half: **aarch64** (local) and **x86-64** (`.119`,
> `cargo 1.97`) each report the same verdict — `A1/A3 real backend: proof crypto-verifies +
> vk_hash matches` — and each rejects the 1-bit-tampered copy. Since the vk_hash is a
> deterministic keyed-BLAKE2b over the proof's canonical shape, a match on both arches means the
> vk_hash is bit-identical, and the accept/reject verdict is identical — so the VERIFY path is
> cross-arch deterministic. This closes the verify half of A5; the remaining A5 pieces are (a) the
> PROVING-side determinism (prove the same statement on x86-64 + aarch64, bit-compare the proof —
> needs the prover on a ≥32GB box, cf. A4) and (b) the reference↔stark differential corpus (needs
> paired statement/witness/proof triples from the prover), plus making both a required CI job (M-07).

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

1. **[CRITICAL — the pure verify is now DEMONSTRATED] The proof cryptographically verifies
   against `vk_hash` — not merely decodes.** The envelope check (`proof.rs:143`) only
   string-compares the proof's *self-declared* `verifier_key_hash` field; it proves nothing
   about the bytes. `_vk_hash` is currently `_`-discarded — it must become load-bearing.
   **Status:** the real, pure, deterministic STARK verify of the actual production proof is
   demonstrated: `recursive_spend.rs --verify-file` runs `p3_circuit_prover::
   BatchStarkProver::verify_all_tables` (no witness, no proving) on the 103,082-byte
   production outer proof and **accepts in 10.1 ms; a one-bit flip rejects** (`SP0-VERIFY ok`
   / `SP0-NEGATIVE ok`, `.119`). This is exactly the node-side verify. What remains to wire
   it into consensus: (a) vendor the verify-only Plonky3 subset (~30 crates: `p3-circuit-prover`
   + `p3-circuit` + `p3-poseidon2-circuit-air` + the published `p3-*` 0.6 — all `no_std`,
   secp-free, PQ, `p3-maybe-rayon` parallel feature OFF for determinism) behind a
   `mil-shield-stark-verify` cargo feature; (b) `vk_hash` = keyed-BLAKE2b over the canonical
   verify context (field, D, Poseidon2 id, FRI params, `security_level`, `table_packing`,
   `rows`, non-primitive ops, and `proof.stark_common.preprocessed.commitment` — the FRI
   params live in the verifier `config`, not the proof, so they must be pinned) — this is the
   legitimate keyed-BLAKE2b touch-point, OUTSIDE the FRI transcript (implemented: A3
   `compute_vk_hash` / `bind_artifact` in `mil-shield-stark-verify`). **Accept-test (met):**
   one-bit-mutated proof rejects; cross-platform bit-identical (A5).

   **A1 execute-ready wiring recipe** (recon-confirmed feasible; the git-dep commitment is
   the audit-gated final step — ADR-0035 §8):
   - **Deps (one entry):** `p3-circuit-prover = { git =
     "https://github.com/Plonky3/Plonky3-recursion", rev = "b3633970…", default-features =
     false, optional = true }` — cargo resolves the 4 sibling path-deps (`p3-circuit`,
     `p3-poseidon{1,2}-circuit-air`, `p3-poseidon-circuit-cols`) from the same repo; ~29
     net-new `p3-*` crates, all NET-NEW to the misakas lock, additive (rand 0.10 / serde
     1.0.228 / borsh 1.5.1 already unify; edition 2024, rust 1.88 OK). HEAD `b3633970` is on
     public `origin/main`, so the git rev == audited bytes.
   - **Feature:** `[features] stark-backend = ["dep:p3-circuit-prover", "dep:postcard"]`;
     the p3 subset is `#![no_std]` and `p3-maybe-rayon` **parallel is OFF by default** (opt-in
     only) → deterministic. The default node never enables the feature, so it stays lean and
     secp-free (kaspa-evm is itself `optional`, only under kaspad's `evm` feature).
   - **Body (`verify_stark`, `#[cfg(feature="stark-backend")]`):** `postcard::from_bytes::<
     BatchStarkProof<Cfg>>` → `proof.validate()` → reconstruct the **pinned production config**
     (a fixed library config, e.g. `p3_circuit_prover::config::baby_bear()`, so the FRI params
     are pinned, not CLI-driven — the verifier and prover share one library config, no example
     glue) → `BatchStarkProver::new(cfg).with_table_packing(..).register_poseidon2_table(..)
     .register_recompose_table(..)` → `verify_all_tables::<Challenge>(&proof)` → on `Ok`, check
     the reconstructed `VerifierContext` hashes to the pinned `vk_hash` (A3), read the
     statement from `proof.non_primitives[k].public_values` (A2 surfacing) or verify with the
     supplied statement, compare to the decoded on-chain statement, and return it. The
     `#[cfg(not(feature))]` arm keeps `BackendPending` (byte-identical inert node).
   - **Verify LOGIC already demonstrated** by `--verify-file` (the exact
     `verify_all_tables` path) on the real proof, cross-platform (A5). Only the workspace
     dep commitment + the `config::baby_bear`-pinned re-proof + A2 surfacing remain.
2. **[CRITICAL — binding ENFORCED + demonstrated; surfacing to the final proof is the
   remaining plumbing] Statement ↔ public-value binding.** The mechanism is sound and
   demonstrated: the layer-1 verification circuit takes the statement as its
   `air_public_targets` and CONSTRAINS the inner proof's committed public values to equal
   it (`verify_batch_circuit` + `pack_values(&pvs, ...)`, `recursive_spend.rs`). So a node
   that feeds the on-chain statement as those targets accepts **iff** the proof attests
   exactly that statement — a valid proof CANNOT be replayed onto a different statement.
   Demonstrated: `--tamper` flips one statement bit and the layer-1 run rejects
   (`STATEMENT-BINDING ok … the proof cannot be replayed onto a different statement`,
   `WitnessConflict`), while the correct statement verifies. *Skip the binding → take any
   valid proof and re-submit it with `public_inputs` swapped to a statement that redirects
   `cm_payout` / sets a large `v_pub_out` = value forgery by replay.*
   **Node-side binding — ✅ LANDED (fail-closed).** `verify_all_tables` binds `pvs` FROM the
   proof's own `non_primitives[k].public_values` (confirmed at `batch_stark_prover.rs:1794`
   / `1813`), so `verify_outer_proof` now returns those surfaced vectors and `verify_stark`
   requires one of them to equal `statement_to_pvs(on_chain_statement)` (frozen encoding: one
   BabyBear element per statement byte), else `StatementNotSurfaced`. A crypto-valid but
   unbound proof is REJECTED — it cannot be replayed onto a different statement at the
   consensus boundary. Tested: injective encoding + accept-on-match / reject-on-mismatch /
   fail-closed-on-absence (artifact-free unit tests), and the real 171,765-byte 100-bit
   production proof crypto-verifies (A1) while node-binding correctly fails closed.
   **Remaining (prover-side surfacing, plumbing not soundness):** the real proof's
   non-primitive tables carry EMPTY `public_values` — EMPIRICALLY CONFIRMED, not just from
   recon — because `into_recursion_input::<BatchOnly>()` (`recursion.rs:136`) hardcodes
   `table_public_inputs: vec![vec![]; num_tables]`. So `S` is committed-and-constrained
   inside layer 1 but not yet surfaced to layer N. The fix is a dedicated non-primitive
   **public-output table** carrying `statement_to_pvs(S)` through the recursion (recon option
   b). **The blocker is now EMPIRICALLY LOCATED, not merely "untested".** Reproduction (a copy
   of the pinned `Plonky3-recursion` workspace): setting `RecursionInput::BatchStark.table_
   public_inputs[Public]=[v]` on the fibonacci example — the minimal non-empty surfacing —
   builds, but `prove_next_layer` aborts with `PublicInputLengthMismatch { expected: 86, got:
   87 }` (exactly the one surfaced value). Root cause, by source: `build_verifier_circuit_impl`
   (`recursion/src/backend/fri.rs:401`) binds `table_public_inputs: _` — it **discards** them
   at circuit-BUILD time, so the verifier circuit allocates no public-input target for the
   surfaced value — while `pack_public_values` (`fri.rs:304`) **does** include them at
   PROVE time. So surfacing is not a call-site change: it requires teaching the core
   `verify_p3_batch_proof_circuit` to allocate public-input targets matching the non-empty
   `table_public_inputs` (and thread them through every layer so the fixed-point shape still
   converges). That is a **soundness-critical modification to the recursion verifier circuit**
   — it therefore belongs INSIDE the A6 audit scope (item 7 of §7), not as an unaudited
   pre-audit change. **Accept-test (node-side, MET):** a wrong statement rejects, absence fails
   closed; **remaining accept-test (A6-gated):** after the audited verifier-circuit change
   surfaces `S`, `verify_stark` accepts-on-match end-to-end (the node arm is ready and already
   exercises this branch when a proof carries a non-empty table).

   **A2 STATUS UPDATE (2026-07-12) — prover-side surfacing IMPLEMENTED + EMPIRICALLY
   VERIFIED end-to-end via a LOCAL patch of the pinned recursion tree.** The audited-scope
   verifier-circuit modification described above now exists as a reviewable diff —
   `docs/bench/plonky3-recursion-a2-surfacing.diff` (applies to `Plonky3-recursion` @
   `b3633970`; +2,753/−12 across 12 files; NOT vendored, NOT a dep bump) — and the full
   chain was demonstrated on this box (aarch64, 24 GB):

   - **Mechanism (recon option b, realized):** a new `public_surface` non-primitive table.
     `CircuitBuilder::add_public_surface(&targets)` consumes already-constrained circuit
     witnesses; the paired `PublicSurfaceAir` packs all `N` values into ONE active trace row
     (`lanes = N`, main width `N`, prep `[witness_idx, mult=−1]` per lane) and enforces
     (1) `is_first_row · (v_j − pv_j) = 0` — the proof's CLAIMED
     `non_primitives[k].public_values` must equal the COMMITTED cells — and
     (2) a `WitnessChecks` bus receive `[witness_idx_j, v_j, 0, 0, 0]` per lane — the
     committed cells must equal the circuit's witness values (the literal zeros also force
     each surfaced value to be base-field). So `public_values` = the circuit's witness
     values, with no prover freedom; the node channel (`verify_all_tables` binding `pvs`
     from `non_primitives[k].public_values`, confirmed above) verifies exactly this.
   - **Layer-by-layer binding argument (why this is NOT carry-only).** The soundness bar is
     that the surfaced targets must be the very targets the in-circuit verifier checks the
     inner proof against — and in the diff they are, by construction, a single expression
     with no intermediate witness allocation:
     - *Layer 1* (`recursive_spend.rs`): `verifier_inputs.air_public_targets[0]` are the
       3,232 statement-bit targets that `verify_batch_circuit` (a) observes in the
       in-circuit Fiat–Shamir transcript exactly as the native verifier observes `S`, and
       (b) feeds as the spend AIR's public values into the folded-constraint evaluation at
       ζ connected to the quotient — so any accepted assignment equals the `S` committed by
       the layer-0 proof (`--tamper` demonstrates the reject). The 404 byte targets passed
       to `add_public_surface` are ALU-constrained Horner sums (`Σ bit_k·2^k`) of those
       bit targets — the node's frozen `statement_to_pvs` encoding (1 borsh byte = 1
       BabyBear element; the AIR bit order is the borsh byte order, diff-tested vs
       `kaspa_hashes`). Hence `proof₁` surfaces exactly `statement_to_pvs(borsh(S))`.
     - *Layer k ≥ 2* (`fri.rs::build_verifier_circuit_impl`): the circuit allocates its 404
       public-input targets FROM the inner proof's `non_primitives[surface].public_values`
       count (`verify_p3_batch_proof_circuit`), (a) observes them in the in-circuit
       transcript, and (b) feeds them as the reconstructed `PublicSurfaceAir`'s public
       values into the ζ-evaluation of constraint (1) against the inner proof's committed
       openings, plus the inner LogUp terminal balance for (2). Any accepted assignment
       therefore equals what `proof_{k−1}` surfaced-and-bound. The diff then passes THE
       SAME `verifier_inputs.air_public_targets` (flattened) straight into
       `add_public_surface` — no fresh targets exist to substitute. By induction the final
       proof surfaces `statement_to_pvs(borsh(S))` exactly; an S′-substitution requires
       satisfying `is_first_row·(v − S′) = 0` against openings committed for `v = S`, i.e.
       breaking FRI/quotient soundness.
   - **Build/prove disagreement — resolved by construction (regression guard).** The
     `PublicInputLengthMismatch{expected:86, got:87}` failure mode is closed at both ends:
     `into_recursion_input` now derives `table_public_inputs` FROM the proof's own
     per-table `public_values` (instead of hardcoding empties), and
     `build_verifier_circuit_impl` validates the caller's `table_public_inputs` shape
     against the proof at circuit-BUILD time (typed error, not a witness-time mismatch).
     Callers passing all-empty tables for pre-surfacing proofs are behavior-identical
     (upstream suites: 26/26 green; unmodified `recursive_fibonacci` runs unchanged; the
     surface prover is only retained when the inner proof actually contains the table).
   - **Fixed-point convergence + prep-cache invariants — CONFIRMED.** The surfaced table is
     CONSTANT-SIZE (404) across layers; the unified `BatchOnly` chain still converges:
     spike witness_count `152,192 → 170,049 → 172,126 → 172,126` (fixed point, 5 layers);
     real sec-100 spend `562,357 → 567,984 → 567,984` (fixed point at layer 4). Hiding
     salts unchanged (drawn once, threaded through layers as before).
   - **Full ~100-bit pipeline re-run (this box):**
     `recursive_spend -- --security-level 100 --query-pow-bits 28 --l0-log-blowup 6
     --final-log-blowup 4 --prod-entropy --num-recursive-layers 4 --dump …` → layer 0
     hiding proof 10,886,969 B (41.9 s); layers 1–4: 1,026,969 B (131.8 s) / 949,784 B
     (79.9 s) / 950,980 B (19.6 s) / **final 555,019 B = 17 × 32 KiB chunks (48.1 s)**;
     `A2 SURFACING ok — final outer proof surfaces 404 public values == the statement under
     the frozen node encoding (1 borsh byte = 1 element)`; `PRIVACY OK (436 witness words
     scanned)`. Pure verify: `--verify-file` → `SP0-VERIFY ok … accepted in 19.3ms` +
     `A2 SURFACED statement: 404 elements, hex c8e2d5f8…` (byte-exact `SpendStatement`:
     `v_pub_in=25`, `v_pub_out=10`, `token_id=0` legible at offsets 384/392/400) +
     `SP0-NEGATIVE ok`. Note the final proof grew 171,765 → 555,019 B (the 404-wide table
     opens its row at every FRI query); still well under `MAX_STARK_PROOF_BYTES` = 1 MiB.
   - **Node-side acceptance — PASS at the PINNED 100-bit params** (no params-relaxed
     fallback needed). With a TEMPORARY `[patch."https://github.com/Plonky3/
     Plonky3-recursion"]` pointing at the patched tree and the new OFF-by-default feature
     `stark-backend-a2-surface` (which registers the surface table with the pinned
     verifier): `MIL_OUTER_PROOF=…/spend_outer_sec100_surfaced.bin cargo test -p
     misaka-mil-shield-stark-verify --features stark-backend-a2-surface --release` →
     `A2 real backend: crypto-verify + surfaced-statement binding both hold
     (accept-on-match, reject-on-mismatch)` and `A2 E2E: full verify_stark ACCEPTS the
     surfaced 404-byte SpendStatement and REJECTS a tampered one` — i.e. A1 crypto verify
     PASS + A3 vk_hash PASS + A2 `statement_is_bound` PASS on the true statement, and
     `Err(StatementNotSurfaced)` on a one-byte-different (still well-formed) statement;
     15/15 tests green. Baseline re-confirmed on the PRE-surfacing artifact
     (`spend_outer_sec100.bin`, 171,765 B): `A1/A3 … A2 node-binding fail-closed (prover
     surfacing pending)`.
   - **Adversarial self-checks:** `--tamper` (layer-1 wrong statement) rejects as before;
     NEW `--tamper-surfaced` packs an S′ ≠ S at layer 2 and is REJECTED at proving
     (`A2 SURFACE-BINDING ok — surfacing S' while the inner chain proves S is REJECTED`,
     `WitnessConflict`); a prover that fabricated traces instead would fail the outer
     STARK verify on the same constraints (checked verifier-side by `verify_all_tables`,
     which is what the node runs). Node-side: flipping one statement byte fails
     `statement_is_bound`; flipping one proof bit fails the crypto verify.
   - **Committed node state stays FAIL-CLOSED and PINNED.** The workspace keeps the
     `b3633970` pin and contains NO `[patch]`; `stark-backend-a2-surface` is OFF by default
     (and deliberately does not compile against the unpatched pin — enabling A2 acceptance
     REQUIRES the audit-gated diff). Default build/tests are byte-identical (13/13 green,
     no feature, no env); with plain `stark-backend`, a surfaced proof is REJECTED (unknown
     non-primitive table) and an unsurfaced one remains `StatementNotSurfaced`. The
     modified recursion tree is pending A6 review (item 7 of §7) before pinning/vendoring.
3. **[CRITICAL — ENFORCED via A3] Inner-circuit fingerprint matches `(vk_hash, circuit_version)`.**
   `verify_outer_proof` now recomputes the `VerifierContext` from the proof's PUBLIC circuit
   shape (`table_packing`, `rows`, per-op `NpoTypeId` fingerprints, `alu_variant`/`ext_degree`/
   `w_binomial`) + the pinned FRI/config params + **`circuit_version`**, and requires
   `compute_vk_hash(ctx) == vk_hash` before the crypto verify (`VkHashMismatch` otherwise).
   Because `circuit_version` AND the shape both feed the hash, a proof of the easy circuit
   submitted as `CIRCUIT_SPEND` recomputes to `H(spend_version ‖ easy_shape)`, which ≠ the
   pinned `H(spend_version ‖ spend_shape)` → rejected. *Skip → a valid proof of the easy
   circuit (or ProviderClaim) is accepted as a proof of the hard circuit (Spend), so
   value-conservation/nullifier constraints the pool assumes were never proven = value
   creation.* **Accept-test (met):** vs the real 100-bit proof, a wrong `vk_hash` →
   `VkHashMismatch`; the recomputed `vk_hash` passes; a `circuit_version`/shape mismatch
   changes the recomputed hash and rejects. **Residual:** the preprocessed-commitment binder
   (strongest per-circuit discriminator) is folded in when a public accessor lands; today the
   full table shape + params + version already defeat the substitution/downgrade attacks.
4. **[HIGH — architecture clarified] Fiat-Shamir transcript.** The recursion's FRI
   challenger is **fixed to Poseidon2** (`DuplexChallenger<BabyBear, Poseidon2BabyBear, 16, 8>`)
   and is **not swappable to keyed-BLAKE2b without re-arithmetizing every layer** (the
   in-circuit challenger, `recursion/src/challenger/circuit.rs`, hashes the transcript with
   in-circuit Poseidon2). Honest SP-04 reading: **the STARK's internal soundness transcript
   must stay Poseidon2**; keyed-BLAKE2b applies as the **outer consensus-controlled wrapper**
   — the `vk_hash` (item 1) plus a keyed-BLAKE2b binding digest over `(proof_bytes ‖ statement
   ‖ vk_hash)` recorded on-chain. That satisfies "a keyed-BLAKE2b transcript binds the
   artifact at the consensus boundary" while leaving the (correct, fixed) Poseidon2 FRI
   transcript alone. Determinism note: the verify path uses **no rayon of its own** and its
   accept/reject is order-independent (exact field arithmetic, per-query-independent Merkle
   checks); build with `p3-maybe-rayon` parallel OFF and `debug_assertions` off. *Skip →*
   consensus split (byte-different outer framing) or a de-pinned FRI param. **Accept-test:**
   x86-64 + aarch64 byte-identical decision on a fixed proof vector.
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

**A7 activation runbook (governance/HF — the sequence; the execution is multi-party).**
1. **Audit sign-off (A6)** on the AIR (build#4/6/7), the recursion, and the vendored
   verify subset (the `stark-backend` feature deps). *Blocks everything below.*
2. **vk-pinning ceremony:** freeze the production FRI params + `config::baby_bear`-class
   config; compute `vk_hash = compute_vk_hash(VerifierContext)` (A3) for `CIRCUIT_SPEND`
   and `CIRCUIT_PROVIDER_CLAIM`; set `ShieldedPool.spendVkHash` / `claimVkHash` via the
   `onlyOwner` setters (deterministic, no toxic waste).
3. **Build with `stark-backend`:** ship node images that enable the feature (the ~29-crate
   subset), verified byte-identical accept/reject across x86-64 + aarch64 (A5 conformance
   re-run on the release image) and passing the differential corpus (A5) accept ⇔ accept.
4. **Testnet re-genesis:** set `evm_f006_shielded_verify_activation_daa_score` to a future
   DAA on `TESTNET_PARAMS` (from `u64::MAX`) + flip the acceptance policy Reference→Both
   (transition) → StarkOnly. Soak: real shielded spends + anon claims settle via F006.
5. **Mainnet:** repeat 4 on `MAINNET_PARAMS` at a coordinated HF DAA, Reference→Both→StarkOnly.
Rollback at every step is the inverse fence set (`u64::MAX`) — the pool goes inert, no state
loss (genesis/roots are fence-independent). Nothing above is code we can execute
autonomously; the code paths (fence param, policy, vk setters, feature build) are all in
place and inert.

Activation = fence flip + policy flip, at a **testnet re-genesis first**, then mainnet — a
governance/HF decision, out of scope for code. The §SP-0 exit gates before either flip
(ADR-0035 §7): (1) cap-bench resolved via ADR-0036 chunk DA; (2) SP-04 conformance corpus
(x86-64 + aarch64, bit-for-bit); (3) differential corpus `reference_verify` ↔ `stark_verify`;
(4) **external audit** of AIR + verifier + recursion; (5) activation.

**Gate progress (A3/A5):**
- **(2) SP-04 cross-platform conformance — MET for the STARK verify.** The same real
  103,082-byte production outer proof, verified with `recursive_spend --verify-file`,
  yields a **bit-identical accept/reject on both architectures**: aarch64 (Apple Silicon)
  `SP0-VERIFY ok` + `SP0-NEGATIVE ok` (one-bit flip rejects), x86-64 (`.119`) identical.
  Only wall-clock differs (5.7 ms vs 17.3 ms) — the *decision* is platform-independent, as
  SP-04 requires. (The consensus-crate verify, once vendored (A1), runs the identical
  `verify_all_tables` path with rayon OFF, so this conformance transfers.)
- **(3) differential corpus — reference side pinned.** `mil/shield/tests/differential_corpus.rs`
  fixes 10 spend cases (2 valid + one per rejection class) with the exact `verify_reference`
  verdict, byte-deterministic across regenerations; build#4 `spend.rs`'s positive + 6
  negatives are STARK-side differential points. Full corpus-driven AIR replay (accept ⇔
  accept over all 10) lands once the verify back-half is vendored (A1).
  *Re-verified this session:* `2/2` green (reference pinned + byte-deterministic), and the
  corpus exports **10 cases / 25,502 bytes** via `MIL_CORPUS_OUT` for the STARK harness.
  **Cross-arch byte-identity — MET for the reference/SP-04 half (2026-07-12, real artifacts).**
  The corpus was independently regenerated on both architectures from HEAD `a69f9fe` and the
  exported borsh blobs are **byte-for-byte identical**: aarch64 (Darwin arm64, this host) and
  x86-64 (`.119`, Linux, cargo 1.97) both emit 25,502 bytes with sha256
  `caaf5db7fc904e3d7010fd5dc8ecf088a6743610b0016751844cce67c73df41a`, confirmed by `cmp`
  (0 differing bytes). This satisfies A5's "SP-04 determinism corpus x86-64 + aarch64
  bit-identical" requirement for the **reference oracle** (a pure function of fixed seeds — no
  RNG, no clock). The remaining A5 pieces are still the *prover-side* proving determinism
  (needs the prover on a ≥32 GB box, cf. A4) and the STARK-side corpus replay (needs the
  vendored verify back-half, A1) — both prover-gated, not reference-gated.
- **A4 — ~100-bit re-verified this session.** The dumped 100-bit outer proof
  (`spend_outer_sec100.bin`, **171,765 bytes**) crypto-verifies AND its recomputed `vk_hash`
  matches under the pinned back-half config `num_queries=18 / query_pow_bits=28 /
  log_blowup=4` — i.e. `28 + 18·4 = 100`-bit conjectured security — with A2 node-binding
  correctly fail-closed (`real_backend_verifies_the_production_proof_and_rejects_tampering`,
  feature `stark-backend`, `1 passed`). A4 is MET: a 100-bit proof exists and verifies; the
  "≥ 32 GB / 61-bit ceiling" was the `.119` (15 GB) box, not a protocol limit.
- **vk pinning (A3):** `compute_vk_hash` / `bind_artifact` (`mil-shield-stark-verify`) — the
  keyed-BLAKE2b vk fingerprint the ceremony pins + the consensus-boundary proof↔statement
  digest, sensitive to all 16 context fields.

## 8. Known caveats (bench vs production)

- **FRI parameters — ~100-bit MET (A4).** The real spend proof compresses to completion at
  **~100-bit conjectured security under production OS entropy** on a 24 GB box (aarch64):
  `--security-level 100 --query-pow-bits 28 --l0-log-blowup 6 --prod-entropy` → layer-0
  hiding proof 10.9 MB → **final outer 171,765 B = 6 × 32 KiB DA chunks**, witness hidden
  (436 words absent), 4 layers. (The earlier "≥ 32 GB / 61-bit ceiling" was a
  `.119`-model overestimate; the 24 GB box completed 100-bit with the layer-1 recursion of
  the 110,471-column inner AIR peaking well under 24 GB — ~12 queries.) The 61-bit
  (`.119`, node-shared) and 80-bit runs remain as the cheaper-box data points. **This
  100-bit production proof verifies bit-identically on both architectures** (aarch64 6.2 ms,
  x86-64 20.7 ms — the SP-04 conformance, A5).
- **Entropy.** Resolved for the demonstration: the hiding salts seed from OS entropy
  (`--prod-entropy`, full `SmallRng` seed from `/dev/urandom`, once per proof, stable across
  layers). The seeded bench default is NOT zero-knowledge (an observer recomputes the salts
  and de-blinds the witness) — production must use `--prod-entropy` (or a CSPRNG stream).
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
