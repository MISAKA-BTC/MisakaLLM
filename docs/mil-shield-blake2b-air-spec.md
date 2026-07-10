# keyed-BLAKE2b-512 AIR spec — the remaining core of the F004 shielded circuit

> **Reference tree:** `feat/mil-v0` @ HEAD. This specs the one gadget that stands
> between the running Plonky3 harness (`docs/bench/plonky3-shield-air/`, value
> conservation under hiding-ZK FRI) and a full production JoinSplit prover. It is the
> multi-month core; this document makes it concrete + cost-bounded, not hand-wavy.

## Why this is the whole game

Every privacy-bearing constraint of the F004 JoinSplit (`spend::verify_reference`)
reduces to keyed BLAKE2b-512:

| gadget | keyed-BLAKE2b calls | domain |
|---|---|---|
| `commit(note)` | 1 (over ~204 B → 2 msg blocks) | `cm` |
| Merkle membership (depth 20) | 20 `hash_node` (128 B each) | `merkle` |
| `shielded_address(sk)` | 1 (64 B) | `addr` |
| `nullifier(sk, rho)` | 1 (128 B) | `nf` |
| output `commit` | 1 | `cm` |

≈ **24 keyed-BLAKE2b calls per spend** (membership dominates). The harness already
proves value conservation; wiring these hash gadgets in is the work. The hash **must**
be keyed BLAKE2b (the on-chain F004 tree) — an algebraic-hash swap forks the committed
tree (ADR-0034 decision 2). ADR-0035 §5.3's Poseidon2 is for the *recursion-layer PCS*,
not this base statement hash.

## BLAKE2b-512 compression = the atomic AIR

One compression `F(h, m, t, f)` (RFC 7693): 16 working words `v[0..16]` (64-bit),
**12 rounds**, each round = **8 G-functions** over a message-schedule permutation
`σ_r`. Keyed hashing prepends one padded key block (the domain) before the message.

`G(a, b, c, d, x, y)`:
```
a = a + b + x  (mod 2^64);  d = (d ^ a) >>> 32;  c = c + d  (mod 2^64);  b = (b ^ c) >>> 24
a = a + b + y  (mod 2^64);  d = (d ^ a) >>> 16;  c = c + d  (mod 2^64);  b = (b ^ c) >>> 63
```
So the atomic ops the AIR must constrain are: **add mod 2^64**, **XOR**, **fixed
rotation**. Over BabyBear/M31 (31-bit) a 64-bit word is not native, so:

## Column layout (per compression)

- **Bit form for XOR/rotate.** Each 64-bit word that is XOR'd or rotated is carried as
  **64 boolean columns** (constrained `b·(b−1)=0`). XOR of two bit-columns is
  `a + b − 2·a·b` (degree 2); a fixed rotation is a *reindexing* of bit-columns (free —
  wiring, no constraint). This is exactly why Keccak/BLAKE2b are "wide": the state is
  bit-decomposed.
- **Limb form for add mod 2^64.** Represent each 64-bit word as **two 32-bit limbs**
  (or 4×16 to keep range checks small); `add` is limb-wise with an explicit **carry
  column** ∈ {0,1} per limb and a range check that each limb < 2^k. Convert between
  bit-form and limb-form with a `Σ b_i·2^i = limb` linkage constraint where a word is
  used by both an add (limb) and an XOR (bits).
- **Round structure.** 12 rounds × (the 16 working words before/after) → a trace of
  ~12 row-groups; the message-schedule σ_r selects which `m[·]` each G consumes
  (a fixed per-round permutation baked into the AIR, no constraint).
- **Keying + finalization.** The key/domain block is a fixed public constant per gadget
  (the domain string, ≤ 64 B, padded to 128); the IV and the `t/f` finalization flags
  are public constants. The 64-byte digest is the low-8-word output re-serialized
  (bit→byte linkage).

Estimated area: BLAKE2b is ARX (add-heavy) vs Keccak's XOR/AND, so per-compression it
is the **same order** as the measured Keccak `keccak-air` (24 rows × 2,633 cols ≈ 63k
cells; ADR-0035 §4). 24 compressions/spend ⇒ ~1.5M cells ⇒ flat proof in the
megabyte class (matching the SP1 prototype's 2.7 MB) ⇒ **recursion + `misaka-mil-shield-da`
chunking are required** (already implemented/measured).

## Composition into the full JoinSplit AIR

1. **`Blake2bAir`** (this spec): one sub-table proving `out = F(h, m, …)`; a `hash(ctx,
   data) = digest` wrapper handling keying + multi-block absorption.
2. **`MerklePathAir`**: fold `leaf` through 20 siblings, each level a `Blake2bAir`
   `hash_node`; a **private index bit** per level selects `(cur,sib)` vs `(sib,cur)`
   (the which-note hiding — the privacy core).
3. **`SpendAir`** = `MerklePathAir` (membership) + `Blake2bAir`×{addr, nf, 2×commit} +
   the existing `ShieldSumAir` (value conservation) + `ctx` binding, sharing one trace
   via a lookup/bus (Plonky3 `LogUp`) so the sub-tables interlock.
4. **Hiding FRI** throughout (the harness already does this) + the standing
   **witness-absence acceptance gate** (`docs/bench/sp1-shielded-spend/` established the
   test): no private column value (note fields, `sk`, path, index bits) appears in the
   proof.

## Build order (fits the repo map)

1. `Blake2bAir` for ONE compression, **tested against the on-chain hash** on a corpus
   (the computed digest must equal the reference byte-for-byte) — the correctness gate
   before anything composes. **① trace generator DONE** (`misaka-mil-blake2b-air`):
   the compression + keyed hash + per-round witness ([`CompressionTrace`]), differential-
   tested byte-identical to `kaspa_hashes::blake2b_512_keyed` across 4 domains × 11 data
   lengths, feed-forward + chaining binding verified. **② ARX-atom constraints DONE**
   (`docs/bench/plonky3-shield-air/atom.rs`, `Blake2bAtomAir`): a real Plonky3 AIR
   proving the two 64-bit atoms — `S = (A+B) mod 2^64` (bit-level **ripple carry**;
   `p3-blake3-air`'s 32-bit `add2` accumulator trick does NOT generalize to 64-bit over
   a 31-bit field, so bit-level is the correct path) and `DP = rotr(D^A, 32)` (XOR
   degree-2 + rotate = bit reindex) — with **prove/verify green AND a negative test**
   (`--corrupt` flips one S bit ⇒ rejected `OodEvaluationMismatch`). **Remaining of #1:**
   compose the atoms into the full G (4 adds + 4 xor-rotates), the round (8 G + σ), init
   (h/IV/t/last), and feed-forward — driven by ①'s `CompressionTrace` — into one
   `Blake2bAir`, then diff-test accept ⇔ ①'s digest.
2. Multi-block `hash` wrapper + the 5 fixed domains.
3. `MerklePathAir` (depth 20) with the private index → the membership/privacy core.
4. Compose `SpendAir`; recurse (Plonky3-recursion, already measured) to the
   DA-carriable outer; chunk via `misaka-mil-shield-da`.
5. Differential test vs `spend::verify_reference` (accept ⇔ accept) + audit.

The harness (done) is where step 1 lands; steps 1–3 are the genuine multi-month
cryptographic core. Nothing here is exploratory — the SP1 prototype already proved the
relation is zk-expressible and cheap (229 K cycles); this is arithmetization
engineering against a known target.
