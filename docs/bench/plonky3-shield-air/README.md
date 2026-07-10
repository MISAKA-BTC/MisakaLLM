# Plonky3 F004-AIR harness — production STARK prover (/goal (a) step 1)

> **Reference tree:** `feat/mil-v0` @ HEAD. This is the START of the production
> prover path (ADR-0035: hand-written PQ STARK, no zkVM, no pairing) — the harness +
> first real F004 constraint, running with **formal zero-knowledge**. The
> keyed-BLAKE2b-512 gadget is the remaining core (`docs/mil-shield-blake2b-air-spec.md`).

## What runs (measured, .119, Plonky3 @ HEAD)

`main.rs` is a real custom Plonky3 `Air` (`ShieldSumAir`) proving a genuine JoinSplit
constraint — **value conservation with hidden amounts**: "I know N private note
amounts summing to the public `total`" — under the **hiding / ZK FRI variant**
(`HidingFriPcs` + `MerkleTreeHidingMmcs`), so the amounts are not revealed:

```
PROVE+VERIFY ok — value conservation (Σ 8 hidden amounts = 1500) via HIDING FRI (formal ZK)
SOUNDNESS ok — a wrong public total is rejected
proof_bytes = 3350 (hiding variant)
```

This establishes the exact production harness the /goal (a) needs, distinct from the
SP1 prototype (`docs/bench/sp1-shielded-spend/`): a **hand-written Plonky3 AIR**, on
the **hiding (ZK) FRI** config the acceptance gate requires (ADR-0035; the SP1 prototype
is only succinct, not guaranteed ZK), proving + verifying + soundness-checking. Every
F004 gadget (membership, nullifier, commitment) plugs into this same harness.

## Build progression (all measured green on .119)

| file | gadget | status |
|---|---|---|
| `main.rs` | harness + `ShieldSumAir` value conservation, hiding-ZK FRI | ✅ |
| `atom.rs` | `Blake2bAtomAir` — 64-bit ARX atom (add/xor/rot) | ✅ + negative |
| `g.rs` | `Blake2bGAir` — full G function | ✅ + negative |
| `round.rs` | `Blake2bRoundAir` — 8 G's wired by σ (1 round) | ✅ + negative |
| `compress.rs` | `Blake2bCompressAir` — **build#1**: init + 12 rounds + feed-forward, unrolled (102,080 cols), diff-tested vs the on-chain digest | ✅ + negative |
| `merkle.rs` (toy, superseded) → `multirow.rs` | MUX + hiding mechanics (G-mix hash, depth 8), then the multi-row layout (one hash per row, depth 16) | ✅ history |
| `spend.rs` | `SpendAir` — the full spend relation composed (toy hash) | ✅ + negative |
| `merkle.rs` | **build#3**: `Blake2bMerklePathAir` — depth-**20** membership at a **PRIVATE index**, **one full BLAKE2b compression per row** (32×102,404), hiding-ZK + witness-absence, diff-tested vs the full keyed `hash_node` | ✅ + 3 negatives |

build#3 measured:

```
host diff-test: trace root == full-keyed-reference root: true (depth 20, rows 32, cols 102404)
VERIFY ok — depth-20 Merkle membership at a PRIVATE index proven with the REAL node hash
            (full 12-round keyed-BLAKE2b-512 per level), hiding-ZK [prove 2.2s, verify 65.6ms]
PRIVACY OK — leaf, 20 siblings and the intermediate path nodes (320 words) do not appear
             in the proof (4987805 bytes)
--corrupt / --flip-index / --wrong-root → NEGATIVE TEST PASS (OodEvaluationMismatch)
```

## Reproduce

```
# in a Plonky3 checkout, as a workspace member `shield-air` (deps = p3-* workspace deps
# + postcard); the hiding config is copied verbatim from uni-stark/tests/fib_air.rs.
cargo run --release -p shield-air              # the harness
cargo run --release -p shield-air --bin merkle # build#3 (also: --corrupt/--flip-index/--wrong-root)
```

## What is done vs remaining

- **Done:** the harness (hiding/ZK FRI — the §SP-0 privacy gate's requirement); the
  full keyed-BLAKE2b-512 compression AIR (build#1, accept ⇔ the on-chain digest); the
  **which-note-hiding membership at production depth-20 with the real node hash**
  (build#3, multi-row: one compression per row, private index, root publicly bound).
  BabyBear here; M31/Circle-STARK is the ADR-0035 production field (a config swap —
  `CirclePcs`, already used in the cap bench).
- **Remaining:** fold the real hash into `SpendAir` (commit/addr/nf as extra compression
  rows over multi-block messages), recurse the ~5 MB hiding proof to the DA-carriable
  size (`misaka-mil-shield-da`), wire F006, external audit, activation.
