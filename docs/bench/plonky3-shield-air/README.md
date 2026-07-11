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
| `spend.rs` (toy, superseded) | `SpendAir` — the full spend relation composed (toy hash) | ✅ history |
| `merkle.rs` | **build#3**: `Blake2bMerklePathAir` — depth-**20** membership at a **PRIVATE index**, **one full BLAKE2b compression per row** (32×102,404), hiding-ZK + witness-absence, diff-tested vs the full keyed `hash_node` | ✅ + 3 negatives |
| `spend.rs` | **build#4**: `Blake2bSpendAir` — the COMPLETE 2-in/2-out JoinSplit with ALL real hashes (`verify_reference` semantics: membership + authority + nullifier + faerie-gold rho + output commitments + dummy inputs + 66-bit value conservation), preprocessed row schedule, 64×110,471 | ✅ ×2 positive + 6 semantic negatives |
| `recursive_spend.rs` | **build#5**: recursive compression of the real spend proof (Plonky3-recursion) — layer 0 = build#4 as a hiding batch-STARK (salted Poseidon2 MMCS + preprocessed), layer 1 = manual verification circuit, layers 2..N = unified chaining to the fixed point. `--verify-file` = the §SP-0 pure verify | ✅ **real 5.4 MB proof → 40,392 B = 2 DA chunks, witness hidden**; spike full chain; tamper-negative; pure-verify 10 ms |
| `claim.rs` | **build#6**: `Blake2bClaimAir` — the ANONYMOUS PROVIDER CLAIM (ADR-0037 §2.1) with ALL real hashes (`provider::verify_reference`: claim_pk + provider-leaf + depth-20 membership at a PRIVATE index + session nullifier + shielded-payout commit + ctx), a strict subset of the spend reusing build#1-5, 32×104,961 | ✅ positive + 4 negatives; adversarial 3-lens = zero underconstraint |

build#3 measured:

```
host diff-test: trace root == full-keyed-reference root: true (depth 20, rows 32, cols 102404)
VERIFY ok — depth-20 Merkle membership at a PRIVATE index proven with the REAL node hash
            (full 12-round keyed-BLAKE2b-512 per level), hiding-ZK [prove 2.2s, verify 65.6ms]
PRIVACY OK — leaf, 20 siblings and the intermediate path nodes (320 words) do not appear
             in the proof (4987805 bytes)
--corrupt / --flip-index / --wrong-root → NEGATIVE TEST PASS (OodEvaluationMismatch)
```

build#4 measured:

```
host diff-test: all trace digests == full-keyed reference (addr/commit/nf/rho'/merkle): true
                (rows 64, cols 110471, prep 1044)
VERIFY ok — COMPLETE shielded spend proven with the REAL hashes (2-in/2-out: membership@depth-20
            + authority + nullifier + faerie-gold rho + output commitments + 66-bit value
            conservation), hiding-ZK [prove 6.2s, verify 69.6ms]   (--with-dummy also verifies)
PRIVACY OK — sks, note fields, values, leaves and both sibling paths (436 words) absent (5.4 MB)
--corrupt / --wrong-anchor / --wrong-nf / --steal / --bad-value / --dummy-nonzero → all rejected
```

An adversarial 4-lens panel (underconstraint / reference-completeness / layout / config)
found **no circuit-logic defect**. Standing caveats (bench config, not logic): FRI
`new_testing` is ~5-bit soundness (production needs ~100 queries); the hiding RNG is
seeded (production needs OS entropy); nullifier distinctness is a pool-caller rule
(sequential check-then-insert — documented in `mil/shield/src/proof.rs`).

build#5 measured (Plonky3-recursion `~/Plonky3-recursion`, BabyBear + Poseidon2, .119):

```
# THE REAL SPEND, recursively compressed end to end (sec=23, l0 lb=4 → 2 queries):
host diff-test: addr/commit/membership/rho' all true
layer 0 (hiding, salted Poseidon2 MMCS, preprocessed): 5,426,511 bytes, 69.5s
layer 1 → 66,318 B  (701.8s — verifies the 110,471-col inner AIR in-circuit)
layer 2 → 54,427 B ;  layer 3 → 40,392 B = 2 × 32 KiB DA chunks
RECURSION ok — final outer proof 40,392 bytes; PRIVACY OK (436 witness words absent)
→ the 40,392-byte outer proof rides the DA path + envelope byte-faithfully (mil/shield E2E)

# spike (tiny preprocessed AIR — cheap validation of the same path):
L0 65,272 B → L1 388 KB → L2 431 KB → L3 269,833 B = 9 chunks ; --tamper → NEGATIVE TEST PASS
```

```
# THE REAL SPEND under PRODUCTION OS ENTROPY, at the box's security ceiling
# (--security-level 61 --query-pow-bits 25 --l0-log-blowup 6 --prod-entropy, node stopped):
layer 0 hiding proof 7,611,506 bytes → L2 154,594 B → L3 167,950 B → L4 103,082 B = 4 × 32 KiB chunks
RECURSION ok — PRIVACY OK (436 witness words absent); ZK salts from /dev/urandom (non-reproducible)
→ the 103,082-byte outer proof rides the DA + envelope path byte-faithfully (mil/shield E2E)
```

**RAM note:** the first attempt (sec=40, l0 lb=4 → 6 queries) OOM-killed at layer 1
(12 GB) because `.119`'s 15 GB is shared with a testnet `kaspad` (~9.7 GB). Layer-1 memory
∝ layer-0 FRI queries = (sec−pow)/blowup; stopping the node (cleanly, via systemd) freed
~10 GB, and pushing security onto cheap PoW grinding (`--query-pow-bits 25`) held the query
count to 6 so layer 1 fit. **~61-bit conjectured is the ceiling on this 15 GB box**;
100-bit needs ≥32 GB (layer-0 LDE ∝ width·2^blowup vs layer-1 queries ∝ 1/blowup — no
15 GB-feasible blowup reaches it). The earlier `--security-level 23` seeded run remains the
cheap-repro path; production runs full security + `--prod-entropy` on a non-shared box.

## Reproduce

```
# shield-air bins (base circuits) — as a Plonky3 workspace member `shield-air`:
cargo run --release -p shield-air              # the harness
cargo run --release -p shield-air --bin merkle # build#3 (also: --corrupt/--flip-index/--wrong-root)
cargo run --release -p shield-air --bin spend  # build#4 (also: --with-dummy/--corrupt/--wrong-anchor/
                                               #   --wrong-nf/--steal/--bad-value/--dummy-nonzero)
cargo run --release -p shield-air --bin claim  # build#6 anon provider claim (also: --corrupt/--wrong-root/
                                               #   --wrong-nf/--steal)
# recursion driver — as an example in a Plonky3-RECURSION checkout (p3-* = crates.io 0.6):
cargo run --release --example recursive_spend -- --spike --num-recursive-layers 3 \
    --l0-log-blowup 8 --final-log-blowup 4              # full chain to 269 KB / 9 chunks
cargo run --release --example recursive_spend -- --spike --tamper --num-recursive-layers 1  # negative
cargo run --release --example recursive_spend -- --dump-l0 /tmp/spend_l0.bin --l0-log-blowup 3  # real layer 0
# then the whole transport + envelope, in-repo:
MIL_OUTER_PROOF=/tmp/spend_l0.bin cargo test -p misaka-mil-shield --test private_transfer_e2e -- --nocapture
# §SP-0 back-half: the REAL pure deterministic verify of a dumped outer proof (no proving):
cargo run --release --example recursive_spend -- --verify-file /tmp/spend_outer.bin \
    --security-level 61 --query-pow-bits 25 --l0-log-blowup 6 --final-log-blowup 4
#   → SP0-VERIFY ok — 103,082 bytes accepted in ~10 ms ; SP0-NEGATIVE ok — one-bit flip rejects
```

## What is done vs remaining

- **Done:** the harness (hiding/ZK FRI); the full keyed-BLAKE2b-512 compression AIR
  (build#1); which-note-hiding membership at production depth-20 with the real node
  hash (build#3); the COMPLETE spend relation with all real hashes (build#4,
  adversarially reviewed); the **recursion pipeline** (build#5) — spike-validated end
  to end (269 KB / 9 chunks, tamper-negative) with the real layer-0 hiding proof
  produced and transported through the DA layer; and the **reference-level
  private-transfer E2E** (`mil/shield/tests/private_transfer_e2e.rs`, 4/4 green):
  shield → private transfer → re-spend, envelope + 32 KiB DA chunking + pool
  application (root ring + sequential nullifier check-then-insert), with double-spend,
  unknown-anchor, tampered/missing-chunk, and same-note-both-slots all rejected.
  BabyBear here; M31/Circle-STARK is the ADR-0035 production field (a config swap).
  The **real spend proof compresses end to end** — 5.4 MB hiding layer-0 → 40,392 B =
  2 DA chunks, witness hidden — and that real compressed proof rides the DA + envelope
  path byte-faithfully.
- **Remaining:** production FRI parameters + entropy + full-security recursion on a
  non-shared box (the completed run used sec=23 to fit the RAM shared with a testnet
  node); wire F006; external audit; activation.
