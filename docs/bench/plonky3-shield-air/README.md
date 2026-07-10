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

## Reproduce

```
# in a Plonky3 checkout, as a workspace member `shield-air` (deps = p3-* workspace deps
# + postcard); the hiding config is copied verbatim from uni-stark/tests/fib_air.rs.
cargo run --release -p shield-air
```

## What is done vs remaining

- **Done:** the custom-AIR harness; the `ShieldSumAir` value-conservation constraint;
  the **hiding/ZK FRI** config (formal ZK — the §SP-0 privacy gate's requirement);
  prove + verify + soundness. BabyBear here; M31/Circle-STARK is the ADR-0035 production
  field (a config swap — `CirclePcs`, already used in the cap bench).
- **Remaining core:** the **keyed-BLAKE2b-512 AIR** (`docs/mil-shield-blake2b-air-spec.md`)
  — the membership (depth-20), nullifier, and commitment gadgets all reduce to it. This
  is the multi-month piece; the harness above is where it lands. Then: compose the full
  JoinSplit AIR, recurse to the DA-carriable size (`misaka-mil-shield-da`), wire F006,
  audit.
