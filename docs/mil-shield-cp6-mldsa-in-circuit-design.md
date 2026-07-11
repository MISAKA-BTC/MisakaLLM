# C-P6 — in-circuit ML-DSA-87 receipt verify (design)

> **Status:** Design (inert). The soundness piece of the anonymous provider claim
> (ADR-0037 §2.4, `circuit_version=3`). This is the genuinely large, multi-week circuit
> — **not** a subset of the spend like build#6/#7. This document makes it concrete and
> honestly cost-bounds it, so the build is scoped rather than hand-waved.

## 1. Why C-P6 is load-bearing

The anonymous provider claim (build#6/#7) proves membership + nullifier + shielded payout
**without revealing which provider**. But it does NOT prove the claimant actually *served
the session* — it only binds `pk_receipt_hash` into the registry leaf. So today the
anonymous claim is one of:

- **unsound** — any registered provider could claim any session's escrow (value theft), or
- **non-private** — the receipt is checked off-circuit against the named ML-DSA-87 key
  (the v1 `JobEscrow.claim` path), which re-leaks the provider (ADR-0037 §1, surface #3/#11).

C-P6 closes this: it proves **"I know a valid ML-DSA-87 (FIPS-204) receipt, under the key
whose hash is my registry leaf, for this session"** — entirely inside the STARK, so the
receipt never appears in the clear. It is the difference between "some registered provider"
and "the provider that actually did this work", with which-provider still hidden.

## 2. What must be proven (statement)

Extend the claim witness with the receipt + signature + the receipt verification key `pk`
(all PRIVATE); add to the relation, in-circuit:

1. `pk_receipt_hash == H(pk)` — the key hashes to the value already bound in the registry
   leaf (build#6 F_LEAF). This ties the ML-DSA key to the anonymous membership.
2. `MLDSA87.Verify(pk, signing_message(receipt), signature) == accept` — the receipt is
   genuinely signed under `pk`.
3. `receipt.session_id`  is bound to the claim's `session_cm` (the receipt is for THIS
   session), and `receipt.cum_tokens` prices the claimed amount (feeds ADR-0037 §2.3).

Item 2 is the whole cost. Items 1 and 3 are cheap (one BLAKE2b — the build#1 gadget — and
field equalities).

## 3. FIPS-204 ML-DSA.Verify decomposed into AIR sub-gadgets

`ML-DSA-87` = Dilithium5: `(k,l) = (8,7)`, `q = 8380417 ≈ 2²³`, `n = 256`, `pk = 2592 B`,
`sig = 4627 B`. `Verify(pk, M, σ)`:

| step | operation | AIR sub-gadget | reuse? |
|---|---|---|---|
| a | parse `pk=(ρ,t1)`, `σ=(c̃,z,h)` | byte↔limb decode + range | build#1-style bit/limb columns |
| b | `A = ExpandA(ρ)` — 56 polys via SHAKE128 + rejection sampling | **Keccak-f[1600] AIR** + rejection-sample gadget | **new, but `p3-keccak-air` is a direct reference** (bit-decomposed permutation, exactly the build#1 pattern applied to Keccak) |
| c | `μ = SHAKE256(SHAKE256(pk) ‖ M)` | Keccak-f AIR (same gadget as b) | shares (b) |
| d | `c = SampleInBall(c̃)` — sparse ±1 challenge poly | SHAKE256 + a permutation/placement gadget | shares (b) + small new |
| e | `ŵ = A·ẑ − ĉ·t̂1·2ᵈ (mod q)` in the NTT domain | **256-pt NTT over Z_q** + 56 pointwise poly mults | **the genuinely new heavy gadget** (butterfly network; q < BabyBear/M31 so mod-q is native field + range checks) |
| f | `w1' = UseHint(h, w)` — high-bits with the hint | decompose/round + hint-bit gadget | new, small |
| g | `‖z‖∞ < γ1−β`, `#{h=1} ≤ ω`, `c̃ == H(μ ‖ w1'Encode)` | range checks + popcount + Keccak-f AIR | ranges are build#1-style; final hash shares (b) |

**The two genuinely new gadgets** are the **Keccak-f[1600] AIR** (SHAKE, steps b/c/d/g —
but `p3-keccak-air` already ships this, and it is the *same bit-decomposed-permutation
methodology* as our BLAKE2b build#1, just a different round function) and the **256-point
NTT over Z_q** (step e — a butterfly network of `256·8 = 2048` add/sub/mul-mod-q per poly,
over `k·l + …` polys). Everything else is byte-decode, range checks, and popcount — the
build#1-7 column-arithmetic we already have.

## 4. Cost & why it is multi-week, not multi-day

Rough area (per the ADR-0035 §4 methodology):

- **SHAKE (Keccak-f)**: `ExpandA` alone rejection-samples `k·l·n = 8·7·256 ≈ 14 k`
  coefficients, each needing SHAKE128 squeeze — on the order of **hundreds of Keccak-f
  permutations**; `p3-keccak-air` measures ~2,633 cols × 24 rows ≈ 63 k cells per
  permutation, so ExpandA ≈ **10⁷ cells**. `μ`, `SampleInBall`, and the final hash add more.
- **NTT + poly mult**: `(k·l + k + l)` NTTs × `256·log₂256 = 2048` butterflies, plus
  `k·l = 56` pointwise mults × 256 — order **10⁵–10⁶ mod-q field ops**, each with a range
  check.
- Total ≈ **10²–10³× the spend circuit** (build#4 was ~110 k cols × 64 rows). This is the
  ADR-0037 §2.4 estimate, confirmed by the structure: it is dominated by SHAKE, exactly as
  ML-DSA verification is dominated by `ExpandA` off-circuit.

So C-P6 is a **standalone multi-week build**, correctly its own `circuit_version=3` and its
own recursion sub-tree. It is NOT gated on build#6/#7 (those are `circuit_version={2,4}` and
already prove membership+nullifier+payout — the parts that don't need ML-DSA).

## 5. Build order (when scheduled)

1. **Keccak-f[1600] AIR — ✅ STEP 1 LANDED** (`docs/bench/plonky3-shield-air/keccak_shake.rs`).
   `p3-keccak-air` (a tested, byte-correct Keccak-f AIR) is integrated into the shield-air
   **hiding-ZK harness** and proves N permutations, with a soundness negative. Measured on
   `.119`: `VERIFY ok — 16 Keccak-f[1600] permutations, 512 rows × 2,633 cols = 1.35 M
   cells, hiding-ZK, prove 1.2 s; --corrupt → NEGATIVE TEST PASS`. So the SHAKE primitive
   (which `ExpandA`/`μ`/`SampleInBall`/the final hash all reduce to) proves in our harness.
   The measured 2,633 cols/perm confirms the C-P6 area estimate: `ExpandA` ≈ hundreds of
   permutations ⇒ ~10⁷ cells (§4). **SHAKE-sponge wrapper — ✅ LANDED**
   (`docs/bench/plonky3-shield-air/shake_sponge.rs`): the FIPS-202 sponge (pad10*1 + 0x1F
   domain separation, absorb/squeeze) over the *exact* `p3_keccak::KeccakF` permutation the
   AIR constrains, **diff-tested byte-for-byte vs `sha3::{Shake128,Shake256}`** — measured:
   `SHAKE SPONGE ok — 4096 SHAKE128/256 vectors match sha3 byte-for-byte (max out 5376 B;
   edge + 2000-case fuzz)`. So proving "the AIR ran KeccakF over these lanes" + "the sponge
   XORed/padded/squeezed this way" ≡ "the STARK computed SHAKE". The wrapper is now
   correctness-pinned; **b/c/d/g are unblocked** (each is this sponge + rejection-sample /
   placement / range bookkeeping over the proven permutation).
   **Sponge absorb + pad AIR — ✅ LANDED** (`docs/bench/plonky3-shield-air/shake_absorb_air.rs`):
   the wrapper's arithmetic itself is now a proven Plonky3 AIR — `state' = state ⊕ padded_block`
   over the SHAKE256 rate (17 lanes × 64 bits), with the FIPS-202 `pad10*1`/`0x1F` padding
   (`0x1F@byte0`, `0x80@byte135`) enforced as fixed block bits and XOR as build#1's degree-2
   `a+b−2ab`. Measured (local aarch64): `VERIFY ok — SHAKE256 sponge absorb + pad10*1/0x1F`;
   `--corrupt → OodEvaluationMismatch` (rejected). So the SHAKE side now has BOTH pieces the
   in-circuit hash needs proven — the permutation (`p3-keccak-air`) and the sponge bookkeeping
   (this AIR) — with `shake_sponge.rs` diff-testing their composition against `sha3`.
2. **256-pt NTT over Z_q AIR — ✅ STEP 2 ARITHMETIC ORACLE LANDED**
   (`docs/bench/plonky3-shield-air/ntt_zq.rs`). The **butterfly-trace generator** (the
   Cooley-Tukey / Gentleman-Sande `(a,b) → (a+ζb, a−ζb) mod q` sequence the AIR proves row by
   row, `q = 8380417`, `ζ = 1753` the primitive 512th root) is **diff-tested against a
   schoolbook negacyclic convolution** in `Z_q[x]/(x²⁵⁶+1)` — measured: `NTT-Zq ok — 2000
   random polynomials: intt∘ntt round-trips, and the NTT-domain product matches schoolbook
   negacyclic convolution coefficient-for-coefficient. Forward trace = 1024 butterflies`. So
   the exact arithmetic the AIR must constrain (butterfly network + per-output mod-q range
   check) is pinned and correct. **Mod-q multiply AIR — ✅ LANDED**
   (`docs/bench/plonky3-shield-air/ntt_mul_air.rs`): the butterfly's multiplicative core
   `t = ζ·b mod q` arithmetized as a real Plonky3 AIR and **proven + negative-tested**. The
   soundness subtlety is that `ζ·b` reaches `q² ≈ 2⁴⁶ ≫ p ≈ 2³¹`, so a single field equation
   `ζ·b = m·q + t` is UNSOUND (holds only mod p); the AIR uses a **base-`β=2¹²` limb carry
   chain** (`q = 1 + 2046·β`) so every intermediate stays `< 2²⁵ < p` and each field equation
   is exact over the integers, verifying `ζ·b = m·q + t` by limbifying both sides and asserting
   the limbs equal, plus `t<q`/`m<q` slack checks — the `Z_q` analogue of build#1's ARX
   ripple-carry. **Full butterfly AIR — ✅ LANDED**
   (`docs/bench/plonky3-shield-air/ntt_butterfly_air.rs`): the complete
   `(out0, out1) = (a + ζ·b, a − ζ·b) mod q` — the mod-q multiply above PLUS the single-carry
   add/sub halves (`a+t = out0 + kO0·q`, `a + kO1·q = t + out1`, every intermediate `< 2q < p`),
   with all five residues (`t, m, a, out0, out1`) `< q` range-checked. Measured (local aarch64):
   `VERIFY ok — 8 full NTT butterflies (a+ζb, a−ζb) mod q` over real Dilithium twiddles;
   `--corrupt → OodEvaluationMismatch` (rejected). 460 cols/butterfly. **Remaining in this
   step:** tile 1024 butterflies per transform (the `ntt_zq.rs` schedule) + move to the shield
   hiding-ZK config. Unblocks step e.
3. **ExpandA + SampleInBall + UseHint + norm/popcount** — compose (1)+(2) into the full
   `Verify`; diff-test the whole thing vs `libcrux_ml_dsa::ml_dsa_87::verify` byte-for-byte
   (the correctness gate: our in-circuit verify accepts **iff** libcrux accepts).
   **ExpandA rejection-sampling AIR — ✅ LANDED**
   (`docs/bench/plonky3-shield-air/rejection_sample_air.rs`): the dominant-cost piece of this
   step — the per-candidate `ACCEPT iff t < q` decision (`t = 3 SHAKE bytes & 0x7FFFFF`) —
   is a proven AIR. The novel gadget is a sound **`less-than → boolean`**: `t − q + lt·2²⁴ = diff`
   with `diff ∈ [0,2²⁴)` range-checked FORCES `lt = [t<q]` (a wrong flag pushes `diff` out of
   range in one direction or the other), every intermediate `< 2²⁵ < p`. Measured (local
   aarch64): `VERIFY ok — 8 ExpandA rejection-sample decisions (4 accept / 4 reject)`;
   `--corrupt → OodEvaluationMismatch` (rejected). This `lt`-comparator also serves the
   `‖z‖∞ < γ1−β` norm bound and `UseHint`'s range checks (same pattern).
   **Hint-weight bound AIR — ✅ LANDED** (`docs/bench/plonky3-shield-air/popcount_bound_air.rs`):
   the `#{h=1} ≤ ω` acceptance check (`ω=75`) — a 256-bit linear popcount `sum = Σ hᵢ` plus the
   same `sum + slack = ω` comparator (slack range-checked ⇒ `sum ≤ ω`). Measured (local
   aarch64): `VERIFY ok — hint-weight bound #{h=1} ≤ ω (weights 0/40/74/75)`;
   `--corrupt` (weight 76) `→ OodEvaluationMismatch` (rejected).
   **Decompose AIR — ✅ LANDED** (`docs/bench/plonky3-shield-air/decompose_air.rs`): the high/low
   split `r = r1·2γ2 + r0` (`2γ2=190464`, `r1∈[0,44]`, `r0∈[0,2γ2)`) at the heart of `UseHint`.
   Soundness note: `r1·2γ2 ≤ 44·190464 = q−1 < p`, so the split is an EXACT single field
   equation — no limb carry (unlike the mod-q multiply). Measured (local aarch64): `VERIFY ok —
   8 Decompose splits`; `--corrupt → OodEvaluationMismatch` (rejected). `UseHint` = this split +
   a `±1 mod 44` conditional on the hint bit (reuses the `lt` comparator).
   **SampleInBall shape AIR — ✅ LANDED** (`docs/bench/plonky3-shield-air/sampleinball_air.rs`):
   the challenge `c` must be ternary with exactly `τ=60` nonzeros — `cᵢ = posᵢ − negᵢ`,
   `posᵢ,negᵢ ∈ {0,1}`, `posᵢ·negᵢ = 0`, `Σ(posᵢ+negᵢ) = τ`. Measured (local aarch64):
   `VERIFY ok — SampleInBall shape (c ∈ {−1,0,+1}²⁵⁶, τ=60)`; `--corrupt → OodEvaluationMismatch`
   (rejected). The positional Fisher-Yates derivation reuses the SHAKE + rejection-sample AIRs.
   **All C-P6 sub-gadgets are now proven AIRs.**
   **Correctness-gate oracle — ✅ LANDED** (`docs/bench/plonky3-shield-air/mldsa_verify_oracle.rs`):
   the RHS of the "in-circuit accepts **iff** libcrux accepts" gate is now pinned —
   `libcrux_ml_dsa::ml_dsa_87` generates a valid signature and a family of tampered ones, and
   the harness records the verdict of each. Measured (local): `MLDSA ORACLE ok — valid sig
   ACCEPTS; 5 tamper classes (z / c̃ / message / context / pk) all REJECT; pk=2592 B,
   sig=4627 B`. This is the concrete reference the composed in-circuit `Verify` must reproduce
   accept⇔accept, and it confirms the byte structure the decode gadgets target. **Remaining in
   this step:** only the full `Verify` COMPOSITION — wire the proven sub-gadgets (SHAKE, NTT,
   rejection-sample, Decompose, SampleInBall, norm/popcount) into one relation,
   `circuit_version=3`, and diff-test the whole against this oracle. That composition + the
   same adversarial-review + audit gates as build#4-7 is the multi-week integration; the
   constituent gadgets it wires AND the reference oracle it targets are each pinned above.
4. **Compose into the claim** — `pk_receipt_hash == H(pk)` (build#1 gadget) + session binding;
   `circuit_version=3`; recurse; the same adversarial-review + audit gates as build#4-7.

## 6. Honest scope

C-P6 is the one part of the shielded-pool programme that is genuinely a **new large circuit**
rather than a reuse of build#1-7. The hash gadget has a strong reference (`p3-keccak-air`);
the NTT is standard but new; the composition + diff-test-vs-libcrux + audit is the multi-week
effort. Until it lands, the anonymous claim (build#6/#7) is sound **only** under the
assumption that the escrow separately establishes the claimant served the session — which,
if done via the named receipt, re-leaks the provider. C-P6 is what makes the anonymous claim
*both* sound *and* private simultaneously. It is inert until the same activation gate as the
rest of the pool (ADR-0034 §6).
