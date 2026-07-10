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
   (`--corrupt` flips one S bit ⇒ rejected `OodEvaluationMismatch`). **③ G-function DONE**
   (`docs/bench/plonky3-shield-air/g.rs`, `Blake2bGAir`): the full 8-step G composed
   from the atoms — `a1=a+b+x` (two ripple add2s ab=a+b, a1=ab+x), `d1=rotr(d^a1,32)`,
   `c1=c+d1`, `b1=rotr(b^c1,24)`, `a2=a1+b1+y`, `d2=rotr(d1^a2,16)`, `c2=c1+d2`,
   `b2=rotr(b1^c2,63)` — 16 words + 6 carry words = **1408 columns**, all boolean;
   **prove/verify green AND negative test** (`--corrupt` flips output a2 bit 7 ⇒ rejected).
   **Remaining of #1 — round + compression are the tiling of ③** (see build-order §Tiling
   below): 12 rounds × 8 G with the σ index threading, init (v from h/IV/t/last), and
   feed-forward `h_out=v_init^v_final^v_final[+8]`, driven by ①'s `CompressionTrace`
   (extended with intra-round G-step words), then diff-test accept ⇔ ①'s digest.

**✅ build#1 COMPLETE — the full keyed-BLAKE2b-512 compression AIR is proven +
diff-tested** (`docs/bench/plonky3-shield-air/{round,compress}.rs`). `Blake2bRoundAir`
= one round (8 G's, column + diagonal schedule, σ message wiring) proven + negative
test. `Blake2bCompressAir` = **init (v from h/IV/t/last) + 12 rounds (state threaded,
σ per round) + feed-forward (h_out = v_init ^ v_final ^ v_final[+8])**, 102,080 columns,
measured on `.119`:
```
host diff-test: trace h_out == reference 12-round digest: TRUE (NROUNDS=12)
VERIFY ok — full BLAKE2b compression proven (init + 12 rounds + feed-forward)
--corrupt (flip an h_out bit) → NEGATIVE TEST PASS — rejected OodEvaluationMismatch
```
i.e. **accept ⇔ ①'s on-chain digest**, with formal soundness. Unrolled: σ and
state-threading are FIXED column references (no lookup). This is the hardest gadget of
the whole shielded circuit. **✅ #3 privacy core DONE (which-note hiding)** — `MerklePathAir`
(`docs/bench/plonky3-shield-air/merkle.rs`): Merkle membership of a **PRIVATE leaf at a
PRIVATE index** under a public root, folding with a node hash and selecting left/right by
the private index bit (the MUX), proven with the **hiding/ZK FRI variant** (HidingFriPcs)
+ a **witness-absence privacy gate**. Measured on `.119` (depth 8):
```
VERIFY ok — Merkle membership at a PRIVATE index proven under the public root (hiding-ZK)
PRIVACY OK — the private leaf + 8 siblings (which-note witness) do not appear in the proof
--corrupt (tamper the leaf) → NEGATIVE TEST PASS — rejected
```
This is the *mechanism that makes which-note unknowable*: the index (which note) and the
path are hidden, formally (hiding-ZK) and empirically (witness-absence). The node hash is
the proven `Blake2bGAir` ARX mix; **production swaps in build#1's full compression at
depth 20 via the multi-row (one-compression-per-row) layout**. **✅ #4 the COMPLETE shielded SPEND circuit DONE**
— `SpendAir` (`docs/bench/plonky3-shield-air/spend.rs`) composes every private-spend
constraint into ONE statement: `addr=H(sk,sk)` (spend authority) + `leaf=H(H(value_in,
addr),rho)` (note commitment) + Merkle membership at a PRIVATE index (which-note hiding)
+ `nf=H(sk,rho)` (public nullifier) + value conservation `value_in+v_pub_in ==
value_out+v_pub_out` (amounts hidden). Proven with the hiding/ZK FRI variant + the
witness-absence gate. Measured on `.119` (depth 4):
```
VERIFY ok — COMPLETE shielded SPEND proven (addr+commit+membership+nullifier+value), hiding-ZK
PRIVACY OK — sk / value_in / rho / value_out / 4 siblings do not appear in the proof
--corrupt (tamper the hidden value) → NEGATIVE TEST PASS — rejected
```
So the FULL shielded-spend RELATION is a working, sound, privacy-preserving circuit:
public = {root, nf, v_pub_in, v_pub_out}; every witness (sk, amounts, rho, index, path)
is hidden, formally and empirically, and any tamper is rejected.

**✅ build#3 DONE — the node-hash swap at production depth**: `Blake2bMerklePathAir`
(`docs/bench/plonky3-shield-air/merkle.rs`, superseding the G-mix toy at that path;
`multirow.rs` proved the layout with the toy hash first): depth-**20** membership at a
PRIVATE index where **every level is build#1's full 12-round keyed-BLAKE2b-512
compression** — **one compression per row** (multi-row layout: 32 rows × 102,404 cols),
state threaded by `when_transition (next.cur == hout)`, the message MUXed by the private
direction bit (`m = dir ? sib‖cur : cur‖sib`, degree 2), and the root bound at exactly
row 19 by a sound counter + selector + running-sum indicator (`CNT/SEL/ACC`). The keyed
hash's key-block compression is identical for every node, so its chaining value
`h_merkle` is a PUBLIC constant pinned into `v_init` (with t=256, last=true) — one
compression per level instead of two; the host diff-test validates this shortcut against
the full two-compression keyed reference (on-chain `hash_node` semantics, key block
included). Measured on `.119`:
```
host diff-test: trace root == full-keyed-reference root: true (depth 20, rows 32, cols 102404)
VERIFY ok — depth-20 membership at a PRIVATE index, REAL node hash, hiding-ZK [prove 2.2 s, verify 65.6 ms]
PRIVACY OK — leaf, 20 siblings + intermediate path nodes (320 words) absent from the proof (4.99 MB)
--corrupt / --flip-index / --wrong-root → NEGATIVE TEST PASS (all rejected)
```
**✅ build#4 DONE — the COMPLETE spend relation with all real hashes**:
`Blake2bSpendAir` (`docs/bench/plonky3-shield-air/spend.rs`, superseding the toy):
the full 2-in/2-out JoinSplit of `spend::verify_reference`, one compression per row
(64 rows × 110,471 cols + 1,044 PREPROCESSED cols), all five domains real: per input
addr (1 row) + commit (2 rows, 204 B multi-block) + membership (20 rows) + nf (1 row),
per output faerie-gold rho' = H(nf₀‖nf₁‖j) (2 rows, 129 B) + commit (2 rows), plus
dummy-input gating (private enable bit: membership/authority/nf gated, value forced 0)
and **66-bit exact value conservation** (bit-ripple, no mod-2^64 wrap). Row types and
per-row v_init constants live in preprocessed columns (uni-stark `setup_preprocessed`/
`prove_with_preprocessed`, hiding-ZK compatible); multi-block chaining reuses the
universal `next.CUR == HOUT` transition (PCHAIN rows read v_init from CUR). Measured
on `.119`:
```
host diff-test: all trace digests == full-keyed reference: true (rows 64, cols 110471)
VERIFY ok — 2-in/2-out spend, hiding-ZK [prove 6.2 s, verify 69.6 ms]  (+ --with-dummy green)
PRIVACY OK — 436 private words absent from the proof (5.4 MB)
--corrupt/--wrong-anchor/--wrong-nf/--steal/--bad-value/--dummy-nonzero → all rejected
```
An adversarial 4-lens panel (underconstraint forgery / reference completeness /
offset audit / degree+config) found **zero circuit-logic defects**; its standing
findings are config-level: FRI `new_testing` ≈ 5-bit soundness (bench only —
production needs ~100 queries + grinding), seeded hiding RNG (production = OS
entropy), and nullifier distinctness being a pool-caller rule (sequential
check-then-insert per nf — now documented in `mil/shield/src/proof.rs`; Sprout-style).

**Remaining is hardening, not circuit design:** production FRI params + entropy →
recursion (the ~5.4 MB hiding proof → chunk-carriable) → chunk DA (done) → F006
verifier wiring → external audit → activation.

**✅ build#5 DONE — recursive compression + the private-transfer E2E**
(`docs/bench/plonky3-shield-air/recursive_spend.rs` + `mil/shield/tests/private_transfer_e2e.rs`).
The recursion (Plonky3-recursion, crates.io p3-* 0.6, BabyBear + Poseidon2) proves
each layer and chains to the verifier-circuit fixed point: **layer 0** = build#4 as a
single-instance **hiding batch-STARK** (salted `MerkleTreeHidingMmcs` + Poseidon2 +
preprocessed columns — the `tests/zk_hiding_mmcs.rs` topology with our AIR, the tested
lane; the unified `RecursionInput::UniStark` ZK path is not yet usable — it dies with a
`WitnessConflict`, found by the spike), **layer 1** = a manual verification circuit
(`BatchStarkVerifierInputsBuilder` + `verify_batch_circuit` +
`set_hiding_salted_fri_mmcs_private_data`) proven under a non-hiding outer config,
**layers 2..N** = the unified `into_recursion_input::<BatchOnly>` chain. Measured on `.119`:
```
spike (tiny preprocessed AIR): layer 0 65 KB → L1 388 KB → L2 431 KB → L3 269,833 B = 9 × 32 KiB chunks
RECURSION ok, PRIVACY OK ; --tamper → NEGATIVE TEST PASS (L1 circuit rejects the flipped public input)
real spend layer 0 (--dump-l0, lb=3): 8,696,406 B = 266 × 32 KiB chunks, hiding, PRIVACY OK (436 witness words)
```
The **reference-level private-transfer E2E** (`private_transfer_e2e.rs`, 4/4 green) runs
the WHOLE pipeline: shield 100 → Alice→Bob 60 (+40 change) → Bob→Carol 35, each via the
`ShieldProof` envelope, `misaka-mil-shield-da` 32 KiB chunking + out-of-order reassembly,
envelope verify, and pool application mirroring `ShieldedPool.sol` (root ring + SEQUENTIAL
nullifier check-then-insert + commitment insert). Double-spend, unknown-anchor,
tampered/missing chunk, and the same-note-in-both-slots inflation attempt are all
rejected; the real 8.7 MB layer-0 proof is transported through the same DA path
byte-faithfully (`MIL_OUTER_PROOF`).

**The one thing not run to completion:** recursively compressing the REAL 8.7 MB
layer-0 proof (as opposed to the spike) needs **~12–15 GB RAM** — layer 1 verifies a
110,471-column inner AIR in-circuit. `.119` has 15 GB but a testnet `kaspad` holds
~9.7 GB, and layer-0 LDE memory (∝ width·2^blowup) trades against layer-1 query count
(∝ 1/blowup), so no single blowup fits both in the ~5 GB free. The spike proves the
compression reaches the 170–382 KiB target band; finishing on the real proof needs the
full box RAM (temporarily free the testnet node) or the narrower one-G-per-row AIR.

### Tiling ③ → round → compression (design, now realized)

- **Round** = 8 sequential G's on the state `v[0..16]`: columns G's on `(0,4,8,12)`,
  `(1,5,9,13)`, `(2,6,10,14)`, `(3,7,11,15)`, then diagonals `(0,5,10,15)`, `(1,6,11,12)`,
  `(2,7,8,13)`, `(3,4,9,14)`; the message args are `m[σ[r][2k]], m[σ[r][2k+1]]`. Each G
  reuses ③'s constraint block; the 8 G's chain (G_{k+1} reads the words G_k wrote).
- **Compression** = init constraints (`v[0..8]=h`, `v[8..16]=IV`, `v[12]^=t_lo`,
  `v[13]^=t_hi`, `v[14]^=last?0xFF..:0` — the XORs are ③'s `xorrot` with shift 0) +
  12 rounds + feed-forward. **Layout options:** (a) *one G per row* over `96 = 12×8`
  rows with a routing/permutation (bus) argument threading the state — narrow trace,
  a lookup for the wiring; (b) *fully unrolled wide* — ~`96×1408` columns, one row per
  compression, no routing. **Measured reality picked (b) as one-compression-per-row**
  (build#3): the unrolled compression block is the row, rows = tree levels, no routing
  lookup, everything degree ≤ 2 — depth-20 proves in 2.2 s on `.119`. Proof size tracks
  width (~5 MB hiding) as predicted; the recursion layer absorbs it. The witness is ①'s
  `CompressionTrace` extended to record every G-step's intermediates (the ③ words),
  which ① already computes deterministically.
2. Multi-block `hash` wrapper + the 5 fixed domains.
3. `MerklePathAir` (depth 20) with the private index → the membership/privacy core.
4. Compose `SpendAir`; recurse (Plonky3-recursion, already measured) to the
   DA-carriable outer; chunk via `misaka-mil-shield-da`.
5. Differential test vs `spend::verify_reference` (accept ⇔ accept) + audit.

The harness (done) is where step 1 lands; steps 1–3 are the genuine multi-month
cryptographic core. Nothing here is exploratory — the SP1 prototype already proved the
relation is zk-expressible and cheap (229 K cycles); this is arithmetization
engineering against a known target.
