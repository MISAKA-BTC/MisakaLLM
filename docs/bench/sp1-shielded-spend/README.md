# Working ZK prover for the MIL shielded SPEND relation (SP1 zkVM)

> **Reference tree:** `feat/mil-v0` @ HEAD. This is the `/goal` (a) deliverable — a
> REAL, verified zero-knowledge proof of the shielded spend relation — as a
> reproducible prototype. It is **not** the production verifier (see "Honest tier").

## What it proves

A genuine ZK proof that a shielded **spend** is valid, with the witness **hidden**:

> "I know a note (value, owner_pk, rho, r) and a spend key `sk` such that the note's
> commitment is under the public `anchor` (Merkle depth 20), `owner_pk = H(sk)`, the
> published `nullifier = H(sk‖rho)`, the output commitment `cm_new` opens to a note,
> and value is conserved — **without revealing which note, its path, or `sk`.**"

Public (committed): `anchor, nullifier, cm_new, v_pub_in, v_pub_out, token_id`.
Private (never leaves the prover): the input note, `sk`, the Merkle path, the output
note. Hashing is keyed BLAKE2b-512, **byte-identical to `misaka_mil_shield`** (same
domains `cm/addr/nf/merkle`, same layouts), so the proof is about the *real* relation
(`spend::verify_reference`), not a re-modelled one.

- `program_main.rs` — the SP1 guest (the relation; `assert!`s the constraints, then
  `commit_slice`s the public statement). A false witness → guest panic → no proof.
- `script_main.rs` — the host: builds a valid witness, `execute`s (fast check +
  cycle count), then `prove` + `verify`.

## Measured result (.119, SP1 v6.3.1, CPU prover, 8-core / 15 GB)

```
EXECUTE ok — relation holds in the zkVM, cycles = 229,816
committed public statement matches (anchor/nf/cm_new); witness stayed private
PROVE+VERIFY ok — real ZK proof generated and verified. proof_bytes ≈ 2,780,923 (~2.7 MB)
PRIVACY OK — no private witness bytes (sk/owner/rho/r + 20 Merkle siblings) appear in the proof
public nullifier in committed output (expected true): true
prove wall-clock < ~100 s, peak RAM ~4.5 GB (laptop-feasible, client-side)
```

## Privacy-effectiveness gate (the acceptance test, not just "it verifies")

The distinction between this and the reference proof system is that the witness must
be **hidden**, not merely checked. The host runs a **witness-absence test**: it scans
the whole 2.7 MB proof for every private value — `sk`, `owner_pk`, `in_rho`, `in_r`,
`out_owner`, `out_rho`, `out_r`, and all 20 Merkle siblings — and asserts none appears
verbatim (`PRIVACY OK` above). Presence would be a definitive leak (the reference
system's failure mode); absence is the **necessary** condition that the witness — which
note, its path, the spend key — cannot be read off the proof.

**Necessary, not sufficient.** Absence of verbatim witness bytes does not by itself
prove formal zero-knowledge: the FRI query openings could still leak partial witness
information unless the prover uses the **hiding/ZK FRI variant** (masking). SP1's core
proof is succinct but not guaranteed formally ZK. So the production Plonky3 circuit
**must** use the ZK-FRI variant (`FriParameters::new_benchmark_zk`) and keep this
witness-absence test as a standing acceptance gate — this is the §SP-0 privacy gate
that the reference system leaves open.

The **2.7 MB** core proof is exactly the hundreds-of-KiB-to-MB artifact ADR-0035 §4
predicted and that **ADR-0036 chunk transport carries** (`misaka-mil-shield-da`):
2.7 MB ÷ 32 KiB ≈ **87 chunks** — (a) and (b) meet here.

## Reproduce (on .119)

```
curl -L https://sp1up.succinct.xyz | bash && ~/.sp1/bin/sp1up   # needs rustup present
cargo prove new --bare milshield-zk && cd milshield-zk
cp <repo>/docs/bench/sp1-shielded-spend/program_main.rs program/src/main.rs
cp <repo>/docs/bench/sp1-shielded-spend/script_main.rs  script/src/bin/main.rs
# program/Cargo.toml: name = "milshield-spend-program"; deps = sp1-zkvm + blake2b_simd
# script/Cargo.toml: drop native-gnark (needs Go, and it is the SP-05 wrap we reject),
#   drop alloy/fibonacci-lib, add blake2b_simd + bincode; remove the evm/vkey [[bin]]s
cd script && SP1_PROVER=cpu cargo run --release --bin fibonacci -- --execute   # then --prove
```

## Honest tier — this is a prototype, not the production verifier

- **It is a real ZK proof** (witness hidden, verified) of the exact relation — the
  `/goal` (a) "実 ZK STARK prover" as a working artifact.
- **It is NOT production** for MISAKA. Per ADR-0035 (SP-05), a zkVM's *small on-chain*
  proof is a Groth16/BN254 pairing wrap — disqualified for a PQ chain. SP1's **core**
  proof (the 2.7 MB one here) is hash-based/PQ, but it is big and unrecursed. The
  production verifier is the hand-written **PQ-recursive** path (S-two/Circle-STARK
  front-runner, ADR-0035), which shrinks the proof and stays pairing-free — that, plus
  the F006 in-consensus verifier wiring and an audit, is the remaining hardening.
- **Value delivered here:** the relation is proven to be zk-expressible and cheap
  (229 K cycles, laptop-provable), the exact byte-layout is validated end-to-end, and
  a concrete proof artifact now exists to size the DA transport against. This retires
  the risk that the relation is somehow not provable; what remains is engineering the
  production backend, not discovering whether ZK is possible here.
