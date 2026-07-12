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
   **REFERENCE COMPOSITION — ✅ LANDED** (`docs/bench/plonky3-shield-air/mldsa_verify_ref.rs`):
   a **from-scratch FIPS-204 ML-DSA-87 `Verify`** — composing the SAME sub-operations the
   proven AIRs constrain (SHAKE `ExpandA`/`μ`/`SampleInBall`/final hash, the mod-q NTT +
   pointwise product, `Decompose`/`UseHint`, the `‖z‖∞<γ1−β` norm bound, the `#h≤ω` popcount,
   `w1Encode`) — **agrees with `libcrux_ml_dsa::ml_dsa_87` accept⇔reject on all 48 test cases**
   (12 valid → accept, 36 across 3 tamper classes → reject). So the sub-gadget DECOMPOSITION is
   proven correct end-to-end: the reference composition reconstructs ML-DSA verify exactly. This
   is the concrete TARGET the in-circuit AIR composition diff-tests against — the remaining work
   is arithmetizing THIS reference (recursive AIR wiring of the already-proven gadgets), not
   re-deriving the algorithm. (The NTT-domain alignment held on the first run because
   `ntt_zq.rs`'s plain NTT matches Dilithium's coefficient order — Montgomery only scales
   values, not indices.)
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
   split `r = r1·2γ2 + r0` (ML-DSA-87: `γ2=(q−1)/32`, `2γ2=523776`, `r1∈[0,16]`, `r0∈[0,2γ2)`)
   at the heart of `UseHint`.
   Soundness note: `r1·2γ2 ≤ 16·523776 = q−1 < p`, so the split is an EXACT single field
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
   **Real-signature decode + sub-gadget validation — ✅ LANDED**
   (`docs/bench/plonky3-shield-air/mldsa_parse_checks.rs`): the FIPS-204 `sig=(c̃,z,h)` decode
   (z-`BitUnpack`, h-`HintBitUnpack`) is implemented and run over **24 genuine
   `libcrux_ml_dsa::ml_dsa_87` signatures**, validating the two acceptance checks the proven
   sub-gadgets enforce on real data: `‖z‖∞ < γ1−β` (max seen `524153 < 524168` — real signing
   pushes `z` to the edge, so the bound is genuinely load-bearing) and `#{h=1} ≤ ω` (max seen
   `66 ≤ 75`); an out-of-norm `z` fails the norm gadget AND libcrux rejects it. So
   `popcount_bound_air.rs` + the norm comparator are shown correct on real ML-DSA-87
   signatures, and the sig-decode the composition needs is pinned. **(This composition work
   surfaced a real bug: `decompose_air.rs` had used ML-DSA-44's `γ2=(q−1)/88` instead of
   ML-DSA-87's `(q−1)/32`; fixed + re-verified.)**
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

### 6.1 claim-ctx binding — H-01 / H-05R (CLOSED)

The claim-v2 AIR (`docs/bench/plonky3-shield-air/claim_v2.rs`, `circuit_version=4`) previously
recomputed `ctx` in-circuit from a stale PRE-remediation 4-field preimage
(`H("claim-ctx", session_cm ‖ v_claim_cm ‖ cm_payout ‖ provider_nf)`, 256 B). The settling
contract and the Rust canonical (`MilShieldedEscrow._computeClaimCtx` /
`mil/shield/src/evm_ctx.rs::claim_ctx_onchain`) instead bind the **404-byte** deployment-scoped
preimage `chainId ‖ contract ‖ escrowId ‖ setRoot ‖ sessionCm ‖ grossSompi(32B) ‖ providerNf ‖
cmPayout ‖ keccak256(encNote)`. Under strict A2 statement binding the node binder
(`shield-stark-verify::statement_is_bound`) requires the proof's surfaced `PI_CTX` to equal the
statement's contract-computed ctx over the whole 392-byte claim-v2 statement — so the in-AIR
`H(256-byte)` diverged from the statement's `H(404-byte)` and **every honest claim would
fail-closed once claims were enabled** (latent High).

**Remediation (H-01):** the AIR now treats `PI_CTX` as an **OPAQUE bound public input** — the
in-AIR ctx recompute is DELETED (the `R_CTX_B1/R_CTX_B2` rows, `F_CTX_B1/F_CTX_B2` constraints,
and the `claim_ctx_v2_ref` reference are gone; `PI_CTX` stays declared in the frozen 392-byte
statement and surfaced as a public value). This mirrors the sibling spend AIR (`spend.rs`) and
the reference oracle `provider.rs::verify_reference_v2`, both of which already carry `ctx`
opaquely. It is **safe without loosening binding or expanding the statement**: the node binder
still forces `PI_CTX == claim_ctx_onchain(...)` byte-for-byte, and the verifier observes `PI_CTX`
in its challenger (a wrong ctx diverges Fiat-Shamir → `--wrong-ctx` rejected at the statement
level). The **404-byte contract ctx is now the sole authority**; cross-contract / cross-escrow /
gross / ciphertext malleability stays closed by that preimage. The claim-side layout is pinned
by the new differential test
`evm_ctx.rs::claim_ctx_matches_solidity_abi_encode_packed_layout` (independent 404-byte
`abi.encodePacked` reconstruction + 9 field-sensitivity negatives), the analog of the existing
spend-ctx layout pin.

## 7. Proven-components manifest (what is arithmetized vs what the composition still wires)

Every FIPS-204 `Verify` PRIMITIVE is now a proven Plonky3 AIR (each with a `--corrupt`
negative test and a diff-test against a plain reference). What remains is NOT new primitives —
it is the **composition**: wiring these into one `circuit_version=3` relation, at 256-pt /
multi-block scale, with the cross-component routing (the two routing techniques below are each
demonstrated soundly, and remain to be applied at full scale).

| FIPS-204 step | proven-AIR component(s) | file (`docs/bench/plonky3-shield-air/`) | status |
|---|---|---|---|
| a. parse `pk=(ρ,t1)` | `t1` SimpleBitPack unpack (10-bit) | `pkdecode_t1_air.rs` | ✅ proven + diff-tested |
| a. parse `σ=(c̃,z,h)` | z-`BitUnpack`, h-`HintBitUnpack` over 24 real libcrux sigs | `mldsa_parse_checks.rs` | ✅ validated on real sigs |
| b. `ExpandA` | Keccak-f[1600] AIR; sponge absorb+pad; rejection-sample (`t<q`) | `keccak_shake.rs`, `shake_absorb_air.rs`, `rejection_sample_air.rs` | ✅ proven |
| b/c/d/g. SHAKE | FIPS-202 sponge diff-tested byte-for-byte vs `sha3` | `shake_sponge.rs` | ✅ oracle-pinned |
| d. `SampleInBall` | ternary/τ shape; Fisher-Yates indexed-swap placement | `sampleinball_air.rs`, `sample_in_ball_air.rs` | ✅ both proven |
| e. matrix-vec (NTT) | mod-q multiply; forward butterfly; **complete 256-pt NTT** (all 1024 bf, schoolbook-validated); pointwise accumulate-reduce | `ntt_mul_air.rs`, `ntt_butterfly_air.rs`, `ntt_full_air.rs`, `ntt_accumulate_air.rs` | ✅ proven |
| e. inverse NTT | Gentleman-Sande butterfly (`out0=a+b`, `out1=ζ·(b−a)`) | `invntt_butterfly_air.rs` | ✅ proven |
| f. `UseHint` | Decompose (centered r0 + boundary); full UseHint (±1 mod 16); w1Encode | `decompose_air.rs`, `usehint_air.rs`, `w1encode_air.rs` | ✅ proven |
| g. accept: `‖z‖∞<γ1−β` | norm-bound window on the packed `t=γ1−z` | `norm_bound_air.rs` | ✅ proven |
| g. accept: `#h ≤ ω` | popcount bound; HintBitUnpack boundary-count monotonicity | `popcount_bound_air.rs`, `hint_weight_air.rs` | ✅ proven |
| g. accept: `c̃' == c̃` | 64-byte terminal challenge equality | `challenge_eq_air.rs` | ✅ proven |
| (target) accept⇔accept | from-scratch verify == libcrux (48 cases); libcrux oracle | `mldsa_verify_ref.rs`, `mldsa_verify_oracle.rs` | ✅ reference gate |

**Cross-component routing — both techniques demonstrated soundly (scale-up remaining):**
- **NTT layer↔layer routing:** `ntt_wired_air.rs` proves a complete n=4 NTT (2 layers) with the
  layer-2 butterfly INPUTS constrained EQUAL to the layer-1 OUTPUTS in-AIR (a prover cannot feed a
  layer anything but what the previous layer produced), validated by the convolution theorem.
  **✅ scaled to full depth — `ntt_wired8_air.rs`** now proves a COMPLETE n=8 NTT with ALL 3
  (=log₂8) layers wired: every layer's 4 butterfly inputs are `==`-bound to the prior layer's
  outputs (bf4.a==bf0.out0 … bf11.b==bf7.out1), twiddles pinned to `zetas[k]=ψ^brv3(k)` (ψ=1753^32,
  the primitive 16th root), convolution-theorem-validated, `--corrupt` (broken mid-network wire) →
  rejected. So the single-row `==`-routing is confirmed to compose cleanly through a full-depth
  layer schedule, not just one hop. The **remaining** step is the 256-pt scale-up, which needs the
  multi-row generalization — a permutation/lookup (LogUp) argument binding row-i outputs to the
  row-j inputs that read them — because uni-stark (this bench harness) has no cross-row lookup; the
  single-row `==` layout would be ~470 k columns at 1024 butterflies. That LogUp routing is the
  genuinely-remaining tiling infrastructure. **Forward+inverse pair complete at n=8:** the inverse
  transform is wired too — **`invntt_wired8_air.rs`** proves a COMPLETE Gentleman-Sande inverse n=8
  NTT with the same full-depth `==`-routing (all 3 layers, each layer's inputs bound to the prior
  layer's outputs), the GS gadget (add/sub-first then multiply the difference) pinned to the same
  zetas (the AIR's `ζ·(b−a)` convention absorbs Dilithium's `−zetas` sign). Ground truth: fed
  `ntt8(x)`, the unscaled output equals `8·x mod q` (the inverse undoes the forward up to the scalar
  n), and the reference `invntt8` with the `×n⁻¹` scaling round-trips over random x; `--corrupt` →
  rejected. So both directions of the routing are demonstrated at full small-transform depth; only
  the 256-pt multi-row LogUp scale-up remains.
  **✅ 256-pt SCALE-UP LANDED — NO LogUp needed: `ntt_wired256_air.rs` + `invntt_wired256_air.rs`.**
  The multi-row generalization turned out not to require a permutation/lookup argument at all: a
  **ONE-LAYER-PER-ROW** layout puts all 128 butterflies of layer r side by side in row r (128 × 460
  = 58,880 main cols fwd / 128 × 480 = 61,440 inv — inside the width budget `spend.rs` already
  demonstrated), which makes every inter-layer wire an ADJACENT-row (current,next) equality —
  plain uni-stark transitions. The per-layer wiring (stride len = 128 >> layer) is the union of
  per-layer routing sets, each gated by a PREPROCESSED one-hot layer flag (the `spend.rs` row-type
  technique; flags committed at setup, so routing cannot be disabled), and each wire binds the
  RECOMPOSED `lo + β·hi` value (both sides bit-constrained < 2²³ < p and range-checked < q, so
  field equality ⇒ integer equality ⇒ unique base-β limbs) — 256 constraints per transition
  instead of ~5888 per-bit ones. All 255 twiddles `zetas[k]=1753^brv8(k)` sit in preprocessed
  columns pinned per (row, slot); the 256 input + 256 output coefficients are bound to 512 public
  values via preprocessed row-0/row-7 indicators; height 16 = 8 real + 8 all-zero-butterfly
  padding rows (no flag set on rows ≥ 7, so nothing crosses the padding boundary or the cyclic
  wrap). Gates, all green on .119 (x86_64, release, bench FRI params): (1) convolution theorem
  `NTT(f)∘NTT(g)==NTT(f·g mod x²⁵⁶+1)` vs independent schoolbook + invNTT round-trip, 100 random
  pairs (inverse bin: unscaled `invNTT(NTT(x)) == 256·x mod q`, n_inv = 8347681); (2) host
  diff-test trace row-7 outputs == reference; (3) `VERIFY ok` — **fwd: prove 1.3 s / verify
  295.5 ms, 58,880 cols × 16 rows, prep 137, proof 4,449,060 B; inv: prove 1.3 s / verify
  313.7 ms, 61,440 cols × 16 rows, prep 137, proof 4,681,374 B**; (4) three negatives each,
  all `OodEvaluationMismatch`: `--corrupt-mid` (a layer-4 butterfly REFILLED as an
  internally-valid gadget with a+1 — only the cross-row routing is violated, the sharpest test
  that the wiring is load-bearing), `--corrupt-l1out` (layer-1 output flip), `--corrupt-twiddle`
  (ζ·b product cell tamper); (5) programmatic routing self-audit: exactly **1792 binding
  equalities (7 transitions × 256 values)**, every inter-layer input/output port bound exactly
  once (eval emits one gated equality per enumerated wire, so the audit covers the emitted set).
  Repro: `cargo run --release --bin ntt_wired256_air` (and `invntt_wired256_air`)
  `[--corrupt-mid|--corrupt-l1out|--corrupt-twiddle]` in `~/Plonky3/shield-air` on .119.
- **SHAKE multi-block threading:** the sponge (absorb XOR + pad + squeeze) is proven and the
  permutation is `p3-keccak-air`; threading the 25-lane state across the 8 rate-blocks of the
  `μ ‖ w1Encode` challenge input is the remaining wiring (the SHAKE analog of the NTT routing).
  **✅ LANDED — `shake_threaded_air.rs`: a COMPLETE multi-block SHAKE computation constrained
  end-to-end in ONE AIR** (multi-block absorb with FIPS-202 pad10*1/0x1F → Keccak-f[1600]
  between/after absorbs → multi-block squeeze), every cross-block sponge-state wire bound
  in-AIR — the prover cannot substitute any intermediate sponge state. `p3-keccak-air` lays
  out 24 rows per permutation, so consecutive sponge permutations sit in ADJACENT 24-row
  groups and every threading constraint is a plain (current,next) equality on the
  group-boundary transition, gated by PREPROCESSED one-hot boundary flags (the
  `ntt_wired256_air.rs` layer-flag technique). The row is `[KeccakCols | state-rate bits |
  block bits]` — the upstream eval is vendored verbatim reading `local[..NUM_KECCAK_COLS]`
  (only the borrow width changes; the private `BITS_PER_LIMB`/`RC_BITS` re-derived locally).
  Constraint set per boundary: absorb = rate lanes `next.preimage == out ⊕ block` via
  bit-XOR (`a+b−2ab`) recomposed to 16-bit limbs, with the state bits bound to the actual
  permutation output by limb recomposition (both sides bit-constrained < 2¹⁶ < p ⇒ field
  equality = integer equality, the recomposed-value-binding argument of item (i)), capacity
  lanes as DIRECT limb pass-through equalities; first absorb pins the ALL-ZERO initial
  state; squeeze boundaries thread the state through Keccak-f with NO xor (flag-gated
  identity on all 25 lanes); every non-message block byte pinned bit-wise to the pad10*1
  constants (0x1F/0x00/0x80, 0x9F when merged — cross-checked against the diff-tested host
  padder in the self-audit); message bytes and ALL squeeze-output bytes bound to PUBLIC
  VALUES. SHAKE256 (rate 136 B) is primary; **SHAKE128 (rate 168 B, the ExpandA path) is the
  SAME AIR with rate as a parameter**. Trace = NUM_PERMS × 24 rows padded to a power of two
  by `p3-keccak-air`'s own valid dummy-permutation padding; no flag on padding rows or the
  cyclic wrap. Gates, all green on .119 (x86_64, release, bench FRI params): (1) host
  oracle diff-test vs `sha3::{Shake256,Shake128}` byte-for-byte, 110 (rate × in-len ×
  out-len) vectors incl. rate−1/rate/rate+1 and 2-block squeezes, AND the proven trace's
  squeeze limbs re-read and compared vs `sha3` byte-for-byte; (2) `VERIFY ok` on three
  instances (each 3-block absorb + 2-block squeeze = 4 perms, 128 rows): **SHAKE256 msg
  300 B: prove 822.7 ms / verify 38.6 ms, 4,809 cols × 128 rows, prep 6, proof 353,496 B,
  572 publics; SHAKE256 msg 407 B (the 0x9F merged-pad corner): prove 800.6 ms / 39.6 ms,
  proof 359,756 B; SHAKE128 msg 400 B: prove 892.9 ms / 44.6 ms, 5,321 cols × 128 rows,
  proof 387,181 B**; (3) five negatives, all `OodEvaluationMismatch`: `--corrupt-thread`
  (one bit of the threaded state between perm k and absorb k+1 flipped, with every
  permutation internally valid and ALL downstream states + publics recomputed consistently
  — ONLY the absorb-boundary XOR wire is violated, the exact wire this AIR exists to bind),
  `--corrupt-pad` (0x1F domain bit, chain kept consistent — only the pad pin fails),
  `--corrupt-cap` (capacity lane across a boundary — caught by the pass-through equality),
  `--corrupt-squeeze` (state between squeeze blocks), `--corrupt-out` (squeeze output
  public byte); (4) programmatic constraint-coverage self-audit: **400 boundary equalities
  (4 events × 25 lanes × 4 limbs)** + 136 (SHAKE256) / 168 (SHAKE128) state-bit limb
  recompositions + output-limb public bindings, every (lane, limb) of every boundary and
  every block byte bound exactly once — no unbound boundary wire. Repro:
  `cargo run --release --bin shake_threaded_air
  [--corrupt-thread|--corrupt-pad|--corrupt-cap|--corrupt-squeeze|--corrupt-out]` in
  `~/Plonky3/shield-air` on .119.
- **ExpandA loop + matrix-vector wiring:** rejection sampling (`rejection_sample_air.rs`),
  one-hot placement (`sample_in_ball_air.rs`) and the NTT-domain accumulation
  (`ntt_accumulate_air.rs`) were separately-proven gadgets; wiring the ACTUAL verify dataflow
  `ŵ_i = Σ_{j<7} Â[i][j]∘ẑ[j] − ĉ∘(t̂1_i·2^d)` with the `Â[i][j]` rejection-sampled IN-AIR was
  the remaining integration. **✅ LANDED — `expanda_matvec_air.rs`: one FULL output row `i`
  (ALL l=7 ExpandA entries in-AIR, full 256 coefficients each — the per-row unit that repeats
  k=8 times in item (iv)) as ONE AIR.** Candidate rows (7 × C=320) each constrain one 3-byte
  SHAKE128 candidate: bytes bit-decomposed, `t` = low 23 bits (the `&0x7F` is a bit-drop),
  accept iff `t < q` via the proven lt-comparator (`t − q + lt·2²⁴ = diff`, `diff` 24-bit
  range-checked), running acceptance counter `cnt' = cnt + place`, the first-256 window
  `act = [cnt < 256]` (witnessed `u = 256 − cnt` 9-bit + the exact nonzero test `act = u·u⁻¹`,
  `u·(1−act) = 0`), and MANDATORY one-hot placement at slot `cnt` (`Σ sel = place = lt·act`,
  `Σ k·sel = cnt·place` — no skip, no duplicate, no reorder); every candidate's 24-bit value is
  bound to a public via a FACTORED 56×40 preprocessed one-hot (degree-3 gated equalities), so
  the whole stream budget window is pinned. Placed coefficients live in 7 threaded 256-wide
  A-banks: written by the flag-gated placement transition `next.A[k] = A[k] + sel_k·(t − A[k])`,
  identity-threaded on EVERY other transition down through the coefficient rows — per
  transition and bank EXACTLY ONE of {write, thread} is active (self-audited: 17,465
  bindings), so a placed coefficient cannot be altered after placement. Coefficient rows (256)
  run seven `Â∘ẑ` mod-q mult gadgets (the `ntt_mul_air.rs` base-2¹² limb-carry chains,
  verbatim), the `2^d`-scale gadget (ζ pinned to the constant 8192), the `ĉ∘t1s` gadget (its
  b-input `==`-bound to the t1s output — the c∘t1 wire), MATERIALIZED accumulate inputs
  `P[j] == az_j.t` / `PSUB == psub.t`, and the accumulate-reduce `Σ P − PSUB + q = out + k·q`
  (exact in-field: 7q < 2²⁶ < p; k 3-bit, out < q by slack); the mult b-inputs read the banks
  and the ẑ/t̂1/ĉ/ŵ publics via a FACTORED 16×16 one-hot "diagonal read" selecting the row's
  own coefficient index — NO LogUp, plain uni-stark. In-circuit ExpandA budget: C=320
  candidates per entry with `cnt == 256` enforced on the entry-last row (acceptance p = q/2²³ ≈
  1 − 2⁻¹⁰); a real stream needing more would take ≥ 64 rejections in 319 candidates,
  P < 2⁻³⁹⁹ per entry (< 2⁻³⁹⁶ per output row) — the standard in-circuit bound. Gates, all
  green on .119 (x86_64, release, bench FRI params): (1) host diff-test on REAL libcrux
  ML-DSA-87 data (the `mldsa_parse_checks.rs` deterministic keys; best-rejection scan picked
  key seed 5, output row i=0; ẑ/ĉ/t̂1 from a real signature of that key): all 7 in-AIR placed
  polys == reference ExpandA (SHAKE128(ρ‖j‖i), libcrux-pinned byte order) AND ŵ_0 == the
  reference matrix-vector row (the `mldsa_verify_ref.rs` NTT(t1·2^d) path; the in-AIR
  2^d·NTT(t1) leg diff-tested equal by linearity), coefficient-exact; the real streams contain
  **6 in-budget rejections** (per entry 1,0,1,1,0,2,1 — the reject path runs on real data), and
  a synthetic instance forces 119 rejections incl. the exact boundaries t = q (reject),
  t = q−1 (accept) and the bit-23 drop (0xFFFFFF); (2) `VERIFY ok` — **real: prove 25.5 s /
  verify 29.1 ms, 4,839 cols × 4,096 rows, prep 148, 4,800 publics, proof 404,715 B;
  synthetic: prove 25.2 s / verify 29.2 ms, proof 402,573 B**; (3) five semantic negatives,
  all `OodEvaluationMismatch`: `--corrupt-accept` (accept flag forged on a t ≥ q candidate —
  the lt-comparator breaks), `--corrupt-place` (one-hot moved off slot cnt = skip/duplicate),
  `--corrupt-coeff` (a placed bank coefficient tampered on its mult-read row — thread +
  diagonal-read wires break), `--corrupt-psum` (accumulate input tampered), `--corrupt-ct1`
  (psub gadget re-filled INTERNALLY-VALID with a substituted b-input — only the t1s→psub wire
  + PSUB binding break); (4) programmatic self-audit: 17,465 bank-transition bindings each
  exactly-once, one-hot coverage of all 2,240 candidate + 256 coefficient rows, 1,792 bank→mult
  diagonal reads + 1,792 ẑ pins + 768 t̂1/ĉ/ŵ pins + 2,240 stream bindings + 10 stage wires.
  Item (iv) binds `pi_stream` to `shake_threaded_air.rs` squeeze outputs and repeats the row
  unit k=8 times. Repro: `cargo run --release --bin expanda_matvec_air
  [--corrupt-accept|--corrupt-place|--corrupt-coeff|--corrupt-psum|--corrupt-ct1]` in
  `~/Plonky3/shield-air` on .119 (shield-air Cargo.toml needs `libcrux-ml-dsa = "=0.0.9"` for
  the real keys).
- **ExpandA SHAKE128 → `pi_stream` soundness binding (C-P6 item (iv), first slice):**
  `expanda_matvec_air.rs` consumes `pi_stream` (~2,240 candidate bytes) as an ASSUMED
  public while `shake_threaded_air.rs` proves the SHAKE128 that produces it *separately* —
  so binding "A was correctly derived from ρ" (the ML-DSA soundness statement: a free A
  lets a prover forge signatures) is the item-(iv) integration. **✅ LANDED for output
  row i=0 — `expanda_stream_bind_air.rs`** (commit `577d33e`), reaching all THREE binding
  targets a reviewer flagged as necessary — a naive `squeeze == pi_stream` over accepted
  bytes only is INSUFFICIENT: ① **full-stream byte-position** binding of the ENTIRE
  squeeze stream INCLUDING rejected 3-byte groups, so the `t<q` accept/reject decision is
  a function of the BOUND stream (a forged stream that shifts which groups accept is
  caught); ② **domain separation** — each of the l=7 entries j=0..6 bound to a DISTINCT
  `SHAKE128(ρ ‖ [j, i])`, nonce byte order `ρ ‖ [column j, row i]` verified against
  `mldsa_verify_ref::expand_a` / libcrux; ③ **ρ binding** — ρ committed as the SHAKE
  message input. **Realized as RECURSION-BIND, decided by MEASUREMENT (not a fuse)** — see
  the layout note below — as two proven uni-stark legs whose shared publics coincide by
  construction: **Leg S** (vendored `ShakeThreadedAir`, SHAKE128 rate 168, msg = `ρ‖[j,i]`
  = 34 B, S=6 perms) binds ③ ρ (32 message bytes) + ② the per-entry nonce `[j,i]`
  (2 message bytes, distinct per entry) + ① every squeeze byte to Keccak-f[1600] in-AIR;
  **Leg B** (`BindAir`) binds the L·960 squeeze bytes == L·320 `pi_stream` 24-bit packs,
  byte-position-aligned over the full stream, via a factored one-hot to publics
  `[squeeze bytes ‖ packs]`. Gates, all green on .119 (x86_64, release, bench FRI params):
  (1) host diff-test — all 7 entry streams == `sha3::Shake128(ρ‖[j,i])` byte-for-byte AND
  each placed `Â[0][j]` == `mldsa_verify_ref::expand_a` coefficient-exact on REAL libcrux
  ML-DSA-87 **seed-5** ρ; per-entry (rejections, 256th-accept idx) =
  `[(1,256),(0,255),(1,256),(1,256),(0,255),(2,257),(1,256)]` — real in-budget rejections
  present, so rejected 3-byte groups are actually exercised (independently reproduced by
  an external Python `hashlib` oracle, matching Rust exactly); (2) `VERIFY ok` — **Leg S:
  prove 1.7 s / verify 38.8 ms, 5,321 cols × 256 rows, prep 12, 1,042 publics, proof
  270,129 B** (entries 0..6 each); **Leg B: prove 1.6 s / verify 5.4 ms, 27 cols × 4,096
  rows, prep 96, 8,960 publics, proof 33,757 B**; (3) three semantic negatives, all
  `OodEvaluationMismatch`: `--corrupt-squeeze` (Leg S: entry-0 squeeze output public byte
  500 bumped, trace intact — reaches ①), `--corrupt-rejection-boundary` (Leg B: entry 0
  group 246, a REAL REJECTED `t≥q` candidate, its `pi_stream` pack forged to `0x000001`
  (`t<q`) to flip reject→accept with the bound bytes unchanged — proves ① binds
  rejected-group bytes), `--corrupt-element-boundary` (Leg S: prove nonce `[1,0]` but feed
  entry-0's squeeze stream as output publics — proves ② domain separation); (4) coverage
  self-audit: 6,720 full-stream byte bindings (= L·960 = 7·960), 2,240 pack bindings
  (= L·320), 7 per-entry nonce bindings, ρ bound as 32 shared SHAKE-input bytes — no
  stream byte / pack / entry left unbound; (5) bench FRI params
  (`log_blowup=2, num_queries=8, PoW 1`) are demonstration-only (stated in the header).
  Byte-identical vendored copy at `docs/bench/plonky3-shield-air/expanda_stream_bind_air.rs`
  (sha256 `3cdfe8b9…04455e7`, both sides). Repro: `cargo run --release --bin
  expanda_stream_bind_air [--corrupt-squeeze|--corrupt-rejection-boundary|--corrupt-element-boundary]`
  in `~/Plonky3/shield-air` on .119.
  **Why recursion-bind, not fuse (measured on .119):** a forced fuse (Keccak beside
  matvec, row-type overlay) measures **~10,160 cols × 4,096 ≈ 41.6 M cells** — width past
  the ~10 k threshold with Keccak WIDE, product > 2× the ~20 M-cell envelope — versus the
  two legs at ~1.36 M (Leg S, per entry) + ~0.11 M (Leg B) cells. Decisive on top of the
  size: uni-stark's single `(width,height)` cannot express the squeeze-output-row →
  candidate-row cross wire as an ADJACENT-row equality without a lookup, and the house
  technique bans LogUp, so the squeeze↔`pi_stream` binding must route through PUBLIC VALUES
  regardless of any fuse — hence keep `shake_threaded` and `expanda_matvec` as separate
  STARKs and prove `squeeze_output == pi_stream` over the full stream with a small binding
  AIR (the `recursive_spend.rs` recursion-tree / `challenge_eq_air.rs` public-equality
  shape). A forced outcome for this architecture, not a preference.
  **Still OPEN in item (iv):** (a) **k=8 replication** — only output row i=0 is bound; the
  full A is k·l = 8·7 = 56 entries and rows i=1..7 replicate the same per-row unit (~8×);
  (b) the **Leg-S↔Leg-B cross-leg tie** (Leg S squeeze-byte publics == Leg B byte inputs) is
  now **DISCHARGED on the REAL legs for one entry (row i=0)** — see *§7.1 "Real-leg cross-leg
  recursion binding"* below; what remains is the **L=7 replication** of that discharge, the
  sibling **Leg-B pack → `expanda_matvec` `pi_stream` tie**, and folding everything into ONE
  `circuit_version=3` relation.

**So the remaining B1 integration is precisely:** (i) ~~apply the NTT routing to 256-pt forward
+ inverse~~ **✅ DONE — `ntt_wired256_air.rs` / `invntt_wired256_air.rs`** (layer-per-row, no
LogUp; 1792 audited wires each; fwd prove 1.3 s / verify 295.5 ms @ 58,880 cols × 16 rows, inv
1.3 s / 313.7 ms @ 61,440 cols; 3 negatives each rejected — see the routing bullet above);
(ii) ~~thread the multi-block SHAKE~~ **✅ DONE — `shake_threaded_air.rs`** (absorb /
permute / squeeze wired in-AIR in ONE AIR, pad10*1/0x1F pinned, SHAKE128 as a rate
parameter; 400 audited boundary equalities; SHAKE256 prove 822.7 ms / verify 38.6 ms @
4,809 cols × 128 rows, SHAKE128 892.9 ms / 44.6 ms @ 5,321 cols; 5 negatives rejected —
see the threading bullet above); (iii) ~~wire the `ExpandA` rejection loop + the
matrix-vector~~ **✅ DONE — `expanda_matvec_air.rs`** (one full output row i with ALL l=7
ExpandA entries in-AIR — rejection-sample → mandatory one-hot placement → banked routing →
7 pointwise Â∘ẑ mults + ĉ∘(t̂1·2^d) → accumulate-reduce, every stage wire bound; REAL libcrux
ρ/ẑ/ĉ/t̂1 with 6 real in-budget rejections + a forced-rejection synthetic instance; prove
25.5 s / verify 29.1 ms @ 4,839 cols × 4,096 rows, 4,800 publics; 5 negatives rejected — see
the ExpandA bullet above; the k=8 row repetition + SHAKE binding is item (iv)); (iv) **✅
ExpandA SHAKE128→`pi_stream` binding LANDED for row i=0** — `expanda_stream_bind_air.rs`,
recursion-bind, ①full-stream / ②domain-sep / ③ρ all reached, 3 boundary negatives rejected
(see the ExpandA stream-binding bullet above) — then **still OPEN:** the k=8 row replication
(rows i=1..7 of the 56 = k·l A entries), the cross-leg recursion discharge
(`verify_batch_circuit` tying the two legs' publics into one outer proof), and folding
everything into ONE `circuit_version=3` relation
whose public output is the receipt statement; (v) diff-test the composed circuit accept⇔accept
against the libcrux oracle; (vi) the same adversarial-review + external audit gates as
build#4-7. No new primitive or algorithm remains — every constituent is proven above; the
work is the (multi-week) sound composition + audit.

**Reproducibility.** The arithmetization AIRs build and run as one batch — every
`*_air` binary is verified to both prove a valid trace (`VERIFY ok`) AND reject a `--corrupt`
one (`NEGATIVE TEST PASS`): `challenge_eq`, `hint_weight`, `invntt_butterfly`, `norm_bound`,
`ntt_accumulate`, `ntt_full` (all 1024 butterflies), `ntt_layer1`, `ntt_wired`, `pkdecode_t1`,
`sample_in_ball`, `usehint`, `w1encode` (+ the butterfly base) — 14/14 green (local aarch64,
release). The SHAKE side (`keccak_shake`, `shake_absorb`, `shake_sponge`) and the earlier
gadgets carry their own measured results above. This is the concrete evidence behind each
"✅ proven" row.

### 7.1 Soundness-wire inventory — every ML-DSA-87 `Verify` wire and its bound status

So the remaining item-(iv) composition work is explicit and **no wire is silently open**,
the table below enumerates every soundness-relevant wire of the ML-DSA-87 `Verify`
relation, the proven AIR that arithmetizes it, and its **bound status**:

- **BOUND** — the wire's cross-stage inputs/outputs are constrained in-circuit (within the
  stated scope; for the ExpandA-binding wires that scope is *output row i=0 only*).
- **GADGET_ONLY_NOT_WIRED** — the gadget is proven + diff-tested standalone (its own
  `--corrupt` negative passes), but its I/O is not yet bound to the adjacent stages; it
  reads/writes ASSUMED public values. This is the bulk of item (iv): plumbing, not new math.
- **FREE** — no binding *and*, for two rows, **no proven gadget at all** — a real gap that
  item (iv) must close before the composed `Verify` is sound.

#### Real-leg cross-leg recursion binding — the ExpandA Leg-S↔Leg-B tie, PROVEN on the actual legs

The cross-leg tie that item (iv) left as a *shared-public recursion assumption* (the driver
feeds identical host values to Leg S and Leg B) is now **discharged in-circuit on the REAL
ExpandA legs**, for one entry (output row i=0). This UPGRADES the earlier mechanism demo
(`crossleg_bind.rs`, commit `9c3b9ba`, which ran the binding on TINY STAND-IN legs — a
5-column constant `EqAir`, 4 publics) to the **actual `ShakeThreadedAir` + `BindAir`**.

- **Legs (both REAL, one entry):**
  - **Leg S** — the FULL `ShakeThreadedAir` (SHAKE128, rate 168; msg 34 B = ρ‖[j,i]; 6
    squeeze perms → 1008 squeeze bytes), **6665 cols × 256 rows, 1042 publics** (34 message
    bytes ‖ 1008 squeeze bytes), on **REAL libcrux ML-DSA-87 seed-5 ρ**
    (`24adbbdb76b9ec7bf82f629c642cc5d78a984429744c9534cf559e2f67ca1c0a`), nonce `[0,0]`.
  - **Leg B** — the FULL `BindAir` for l=1, **27 cols × 512 rows, 1280 publics** (960
    stream-input bytes ‖ 320 packs); binds all 960 stream bytes / 320 packs of that entry.
- **Format (STEP 0 assessment):** the shipped legs prove under `p3-uni-stark`
  (`prove_with_preprocessed`), but `verify_batch_circuit` consumes `p3-batch-stark` proofs, so
  each leg is **re-cast as a single-instance batch-STARK proof** — the AIR eval, the
  preprocessed trace, the trace generator, the public layout and the witness are IDENTICAL;
  only the proving harness changes (uni-stark → `prove_batch`; `p3-batch-stark` 0.6.1 batches
  preprocessed traces into a global commitment and the recursion verifies preprocessed
  instances). One faithful adaptation: `preprocessed_next_row_columns` uses the crate DEFAULT
  (open every preprocessed column at both `ζ` and `ζ·g`) instead of the uni-stark `vec![]`
  override — the batch-STARK recursion path (`recursive_spend.rs` shape) rejects proofs that
  omit the preprocessed next-row opening; the eval still reads only the current preprocessed
  row, so constraints/witness are unchanged. The field is re-cast BabyBear → KoalaBear (the
  AIRs are generic over `PrimeField64`; only the STARK config type changes) to match the
  KoalaBear D4/W16 recursion plumbing.
- **The binding:** one recursion circuit calls `verify_batch_circuit` on Leg S AND Leg B, then
  enforces **Leg-S squeeze-output publics == Leg-B stream-input publics** for all 960 stream
  bytes element-wise, each as `diff = cb.sub(pub_S[34+b], pub_B[b]); cb.assert_zero(diff)` (an
  ALU `sub` whose output is asserted zero — each public read once, keeping the Public-table
  LogUp balanced; a direct `connect` would break it). Recursion circuit **witness_count =
  1,332,831**.
- **Faithfulness gates (host, independent oracles, all PASS):** Leg S's in-AIR Keccak-f sponge
  output == `tiny_keccak` SHAKE128(ρ‖[0,0]) byte-for-byte (1008 B); the rejection-sampled
  `pi_stream` == the FIPS-204 incremental ExpandA reference **coefficient-exact (256/256**,
  1 in-budget rejection); Leg B packs == byte recomposition of the squeeze bytes (320/320).
  (ρ itself is libcrux's own keygen output, re-derived by libcrux's exact H() step
  `SHAKE256(seed‖[ROWS_IN_A=8, COLUMNS_IN_A=7])[0..32]` — libcrux-ml-dsa-0.0.9
  `ml_dsa_generic.rs::generate_key_pair` — via an independent SHAKE256, byte-identical.)
- **Outcomes (local, KoalaBear D4/W16, bench FRI params — NOT production soundness):**
  - Native layer-0 batch-STARK legs: **Leg S 1,209,407 B / 204.9 ms**, **Leg B 106,639 B /
    12.0 ms** (each also natively `verify_batch`-checked).
  - **[1] HONEST** (Leg B built over Leg S's OWN squeeze stream, cross-leg bind): the outer
    aggregated proof **prove+verify SUCCEEDS — 418,503 B, 11.2 s**.
  - **[2] NEGATIVE** (Leg S proves the nonce-`[0,0]` stream; Leg B is built over the DIFFERENT
    nonce-`[1,0]` stream — both individually VALID SHAKE proofs — then cross-leg bound): the
    outer proof **REJECTS at prove-time (~0.35 s, `WitnessConflict`** on the first differing
    squeeze byte, `0xA3` vs `0xC2`) — no outer proof is produced, because the two legs'
    surfaced squeeze publics are aliased to one witness slot and disagree.
- **Scope shipped vs deferred:** this is one ExpandA entry (row i=0, nonce `[0,0]`), both legs
  full and real. **Deferred:** k=8 replication, the L=7 all-entries aggregation (7 Leg-S proofs
  + one Leg-B(l=7) — identical mechanism, ~7× cost), the sibling Leg-B pack →
  `expanda_matvec` `pi_stream` tie, the full `circuit_version=3` composition, and items (v)/(vi).
- **Artifacts:** example `recursion/examples/expanda_crossleg.rs` (in the pinned Plonky3
  recursion clone at `b363397`); diff `docs/bench/plonky3-recursion-real-expanda-legs.diff`.
  Upstream no-regression: `cargo test -p p3-circuit -p p3-circuit-prover -p p3-recursion`
  green and `recursive_fibonacci` still verifies.

#### Three-stage HETEROGENEOUS ExpandA chain — SHAKE ∘ Bind ∘ matvec-placement, `ρ → Â` PROVEN

The 2-leg binding above proved `SHAKE(ρ) → squeeze → pi_stream`. This **chains a THIRD real
stage (`Leg M`, from `expanda_matvec_air.rs`)** onto it, so the full ExpandA relation
`SHAKE(ρ) → squeeze stream → pi_stream → rejection-sampled Â` is composed as **ONE recursion
tree over THREE HETEROGENEOUS gadgets** — a Keccak sponge (`ShakeThreadedAir`), a
byte-recomposition binder (`BindAir`), and a rejection-sample / one-hot-placement sampler
(`ExpandaPlaceAir`). This is the demonstration that the recursion tree composes DIFFERENT
gadgets, not just two SHAKE-family legs; the earlier Leg-B → matvec `pi_stream` tie (previously
"deferred") is now **PROVEN**.

- **Leg M — the ExpandA placement core** (rejection-sample → one-hot placement → A-bank →
  placed-`Â` readout). Constraints ported **VERBATIM** from `expanda_matvec_air.rs`: the sound
  lt-comparator rejection gadget (`t = b0+256·b1+65536·(b2&0x7F)`; accept iff `t<q` via
  `t − q + lt·2²⁴ = diff`, `diff` 24-bit range-checked), the one-hot placement
  (`sel` boolean, `Σ sel = place`, `Σ k·sel = cnt·place`, `place = lt·act`, `act = [cnt<N]`
  by the exact nonzero test), the A-bank write-xor-thread threading, and the factored
  coefficient one-hot "diagonal read" — here surfacing the placed `Â[k]` to an OUTPUT public
  instead of a mult b-input. **193 cols × 512 rows, 384 publics** (320 `pi_stream` INPUT packs
  ‖ 64 placed-`Â` OUTPUT coeffs).
- **STEP 0 scope decision — REDUCED-BUT-REAL** (the full l=7/256-coeff/4839×4096 matvec is
  infeasible as a 3rd in-circuit proof on 24 GB; ADR-0035): **l = 1** ExpandA entry (column
  j=0, output row i=0, nonce `[0,0]`), **N = 64** accepted coefficients (256 → 64), **C = 320
  candidate budget KEPT** so the `pi_stream` tie covers ALL 320 of Leg B's validated packs (not
  a prefix). Same constraints, only the counts shrink — a genuinely reduced real matvec, not a
  constant-column stand-in. **Deferred:** N=256 full, the pointwise `Â∘ẑ` mults + `ĉ∘(t̂1·2^d)`
  accumulate (the matrix-vector *arithmetic* tail → `ŵ_i`, wire 6), l=7 all-entries, k=8.
- **Two cross-stage ties, one outer proof** — the recursion circuit calls
  `verify_batch_circuit` on Leg S, Leg B AND Leg M, then enforces (each `diff = cb.sub(…);
  cb.assert_zero(diff)`, a `sub` asserted zero — one read per public, keeping the Public-table
  LogUp balanced):
  - **Tie 1 (S↔B):** `Leg-S squeeze-output publics[34+b] == Leg-B stream-input publics[b]`,
    b ∈ 0..960 (the 960 squeeze bytes).
  - **Tie 2 (B↔M):** `Leg-B pi_stream-output publics[960+r] == Leg-M pi_stream-input
    publics[r]`, r ∈ 0..320 (the 320 packed candidates).
  Recursion circuit **witness_count = 1,400,399** (vs 1,332,831 for the 2-leg case — the
  reduced Leg M is small: +67 k witness).
- **Faithfulness gates (host, all PASS):** the 2-leg gates above, plus **Leg M's in-AIR placed
  `Â[0][0][0..64] == FIPS-204 ExpandA reference, coefficient-exact** (first 64 accepted coeffs
  of the real-ρ ExpandA loop) — the reduced matvec is faithful.
- **Outcomes (local, KoalaBear D4/W16, bench FRI params — NOT production soundness):**
  - Native layer-0 batch-STARK legs: **Leg S 1,209,407 B / 209.9 ms**, **Leg B 106,639 B /
    12.6 ms**, **Leg M 152,526 B / 30.1 ms** (each also natively `verify_batch`-checked).
  - **[1] HONEST** (S ∘ B ∘ M all on nonce `[0,0]`, both ties): the outer aggregated proof
    **prove+verify SUCCEEDS — 418,370 B, witness_count 1,400,399, 11.7 s**.
  - **[2] NEG1 (PRIMARY — pi_stream mismatch):** Leg M built over the DIFFERENT nonce-`[1,0]`
    stream (a VALID ExpandA placement of a different candidate set); bound against Leg B's
    nonce-`[0,0]` packs, **Tie 2 fails → REJECTS at prove (~0.45 s, `WitnessConflict`**,
    `1163683` vs `1806786`) — no outer proof.
  - **[3] NEG2 (S↔B tie still rejects):** B and M both over nonce `[1,0]` (Tie 2 holds) but S
    over `[0,0]` → **Tie 1 fails → REJECTS at prove (~0.45 s, `WitnessConflict`**, `163` vs
    `194`).
- **Artifacts:** example `recursion/examples/expanda_chain3.rs` (self-contained; in the pinned
  Plonky3 recursion clone at `b363397`); diff `docs/bench/plonky3-recursion-expanda-chain3.diff`
  (Cargo.toml dev-deps + the example, apply-clean on pristine `b363397`). Upstream
  no-regression: `cargo test -p p3-circuit -p p3-circuit-prover -p p3-recursion` green
  (368/84/… pass, 0 fail) and `recursive_fibonacci` still verifies.

#### matvec ARITHMETIC tail — the recursion chain now outputs the REAL `ŵ_i` (`ρ → ŵ_i` COMPLETE)

The three-stage chain above stopped Leg M at the ExpandA *placement* core (`ρ → Â`). The
matrix-vector **arithmetic** — the pointwise `Â∘ẑ` mults, the `ĉ∘(t̂1·2^d)` subtractive leg and
the accumulate-reduce that turn `Â` into `ŵ_i` (wire 6, the value invNTT/UseHint consume
downstream) — was the DEFERRED "heavy tail". It is **now ported VERBATIM into Leg M**, so the
matvec stage is **COMPLETE through recursion**: the chain outputs the REAL
`ŵ_i = Σ_j Â[i][j]∘ẑ[j] − ĉ∘(t̂1_i·2^d)`, coefficient-exact vs the `mldsa_verify_ref.rs` matvec
row.

- **STEP 0 — ported IN-AIR (extend Leg M), NOT a 4th leg.** Either shape was allowed; extending
  Leg M's AIR (placement + arithmetic in ONE batch-STARK leg) is chosen because (a) *faithfulness*
  — `expanda_matvec_air.rs` (the reference) is ONE AIR where the placed bank feeds the mult
  b-input DIRECTLY via the "diagonal read", with `Â` never surfaced as a public; a 4th leg would
  invent a new `Â`-as-cross-leg-publics seam that does not exist in the reference; and (b) *24 GB
  fit* — each extra leg adds a whole `verify_batch_circuit` (a large fixed recursion-witness cost
  that dominates trace width), whereas extending Leg M reuses the existing 3rd in-circuit verify
  and only widens Leg M's own trace (193 → 1137 cols, **height unchanged at 512**).
- **Ported VERBATIM** from `expanda_matvec_air.rs` (reduced l=1/N=64): on the 64 coefficient rows,
  the base-2¹² limb-carry mod-q multiply `Â[0][k]·ẑ[0][k]` (`ntt_mul_air.rs`, 296 cols/gadget),
  the `2^d` scale `t̂1s = 8192·t̂1[k] mod q` (ζ pinned to 8192), the subtractive
  `psub = ĉ[k]·t̂1s mod q` (b-input ==-bound to the t1s output — the `ĉ∘t̂1` wire), and the
  accumulate-reduce `Σ P − PSUB + q = out + k·q` (in-field partial sums, `k ∈ [0,8)` canonical
  reduction — `ntt_accumulate_air.rs`). The placed bank feeds the mult b-input via the factored
  16×16→8×8 diagonal read; `ẑ/t̂1/ĉ` are INPUT publics and `ŵ_i[0..64]` is the OUTPUT public.
- **Scope shipped (REDUCED-BUT-REAL):** **l = 1** ExpandA entry (one additive product), **N = 64**
  coefficients, **C = 320** candidate budget KEPT (full Leg-B pack tie). `Â` is REAL FIPS-204
  ExpandA on real libcrux seed-5 ρ (`24adbbdb…67ca1c0a`, first 64 coeffs). NTT-domain arithmetic
  is pointwise, so the reduced 64-coeff row is the *same* arithmetic, count reduced. `ẑ/ĉ/t̂1` are
  representative canonical NTT-domain residues (< q) — the tail's job is the ARITHMETIC, not
  re-deriving `ẑ/ĉ/t̂1` (which come from their own stages/publics in the full composition).
- **Leg M** (placement + matvec): **1137 cols × 512 rows, 576 publics** (320 `pi_stream` INPUT ‖
  64 `ẑ` ‖ 64 `t̂1` ‖ 64 `ĉ` INPUT ‖ 64 `ŵ_i` OUTPUT), native batch proof **357,637 B / 65.2 ms**.
- **Faithfulness gates (host, all PASS):** placed `Â[0][0][0..64] == FIPS-204 ExpandA reference`
  AND **`ŵ_0[0..64] == the mldsa_verify_ref matvec row Σ Â∘ẑ − ĉ∘(t̂1·2^d)`, coefficient-exact**,
  on real ρ.
- **Outcomes (local, KoalaBear D4/W16, bench FRI params — NOT production soundness):**
  - **[1] HONEST** (S ∘ B ∘ M+matvec, both ties): outer aggregated proof **prove+verify
    SUCCEEDS — 418,284 B, witness_count 1,578,302, 11.6 s** (vs 1,400,399 for the placement-only
    chain — the arithmetic tail adds ~178 k witness, still 3 legs).
  - **[2] NEG1 / [3] NEG2** (cross-stage ties): unchanged — `pi_stream` / squeeze mismatches
    **REJECT at prove (`WitnessConflict`, ~0.46 s each)**.
  - **[4] NEG3 (matvec tamper, the tail's own AIR soundness):** a placed-`Â` coefficient tampered
    on its mult-read row (so `ŵ_i` is wrong) → **Leg M's own batch proof REJECTS at native verify
    (65 ms)**; a second variant tampers an accumulate partial-sum P[0] → **REJECTS (60 ms)**.
- **Artifacts:** example `recursion/examples/expanda_chain_matvec.rs` (self-contained; in the
  pinned Plonky3 recursion clone at `b363397`); diff
  `docs/bench/plonky3-recursion-matvec-tail.diff` (Cargo.toml dev-deps + the example, apply-clean
  on pristine `b363397`, byte-identical). Upstream no-regression:
  `cargo test -p p3-circuit -p p3-circuit-prover -p p3-recursion` green (368/84/… pass, 0 fail)
  and `recursive_fibonacci` still verifies.
- **Deferred (unchanged):** N=256 full, L=7 all-entries / k=8 all-rows, the invNTT stage that
  feeds `w`; the full `circuit_version=3` aggregation, and items (v)/(vi). (The UseHint +
  w1Encode + accept-SHAKE + challenge_eq accept-tail stages are now composed — see the next
  subsection.)

#### ACCEPT-TAIL — `w → UseHint → w1Encode → SHAKE256 → (c̃'==c̃)` COMPOSED through recursion (item (v) CORE)

The three ExpandA subsections above compose the **INPUT** end of `Verify` (`ρ → … → ŵ_i`). This
composes the **OUTPUT** end — the FIPS-204 accept decision that turns `w` into ACCEPT/REJECT —
as **ONE recursion tree over FOUR HETEROGENEOUS accept-side gadgets**, discharging item (v)'s
CORE (the accept⇔accept decision). Every gadget is a standalone-proven shield AIR ported
VERBATIM (constraints unchanged, counts reduced), re-cast BabyBear → KoalaBear (only Leg U's
is-zero-witness prime changes to KoalaBear's `p = 2130706433`); each is a single-instance
batch-STARK proof verified in-circuit by `verify_batch_circuit`.

- **STEP 0 — FOUR SEPARATE legs, THREE ties** (the shape the accept chain names; `w1(UseHint
  out)==w1Encode in`, `(μ‖w1Encode out)==SHAKE msg`, `SHAKE out==challenge_eq c̃'`). Legs U and E
  surface their per-row values as publics via the factored 2-D one-hot of `BindAir`; Leg S is the
  M-09-hardened `ShakeThreadedAir` **verbatim** (the SAME AIR the ExpandA chain uses, only rate
  136 = 17 lanes for SHAKE256); Leg C's terminal is `when_first_row` public surfacing.
  - **Leg U — UseHint** (`usehint_air.rs` verbatim): FIPS-204 `Decompose` (centered `r0` + the
    `r−r0==q−1` boundary) ∘ the hint `±1 mod 16` per coefficient. **147 cols × 256 rows, 256
    publics** (`w1[0..256]` OUTPUT). Native proof **123,286 B / 28.9 ms**.
  - **Leg E — w1Encode** (`w1encode_air.rs` verbatim): `SimpleBitPack` 4-bit `byte = c_lo+16·c_hi`.
    **19 cols × 128 rows, 384 publics** (256 coeff INPUT ‖ 128 byte OUTPUT). **71,901 B / 6.9 ms**.
  - **Leg S — SHAKE256** (`shake_threaded_air.rs` verbatim, rate 136): `c̃' = SHAKE256(μ‖w1Encode)`;
    192-byte message = 2 absorb blocks + 1 squeeze block = 2 Keccak-f perms. **5897 cols × 64 rows,
    328 publics** (192 message ‖ 136 squeeze bytes; `c̃'` = squeeze `[0..64]`). **1,183,753 B / 91.1 ms**.
  - **Leg C — challenge_eq** (`challenge_eq_air.rs` verbatim): the TERMINAL accept predicate
    `c̃'[i]==c̃[i]` over all 64 bytes. **1152 cols × 64 rows, 128 publics** (`cs`=supplied c̃ ‖
    `cr`=recomputed c̃'). **185,448 B / 14.1 ms**.
- **Scope shipped (REDUCED-BUT-REAL):** **NW1 = 256** = ONE ML-DSA-87 poly's `w1` (full verify has
  K=8 polys = 2048); `w1Encode` = 128 bytes; `μ‖w1Encode` = 192 B. `w` = representative canonical
  residues `< q` (the invNTT stage producing `w` is DEFERRED, as `ẑ/ĉ/t̂1` are representative in the
  matvec tail); `h` = a real hint-bit pattern exercising both `±1` branches; `μ` = a representative
  64-byte value. UseHint/Decompose is the REAL verbatim FIPS-204 gadget — `w1 ==
  mldsa_verify_ref::use_hint`, and `w1Encode == mldsa_verify_ref::w1_encode`.
- **Faithfulness gate (host, PASS):** `c̃' = SHAKE256(μ‖w1Encode)[0..64]` **byte-exact (64/64)**:
  the in-AIR Keccak-f sponge output == an INDEPENDENT `tiny_keccak` SHAKE256 (a distinct
  implementation). The accept predicate `ACCEPT iff c̃'==c̃` is the SAME predicate FIPS-204/libcrux
  use.
- **Three cross-stage ties, one outer proof** — the recursion circuit calls `verify_batch_circuit`
  on Legs U, E, S, C, then enforces (each `diff = cb.sub(…); cb.assert_zero(diff)`, one read per
  public):
  - **Tie 1 (U↔E):** `Leg-U w1[k] == Leg-E coeff_in[k]`, k ∈ 0..256.
  - **Tie 2 (E↔S):** `Leg-E byte_out[r] == Leg-S message[64+r]` (the w1Encode part of μ‖·), r ∈ 0..128.
  - **Tie 3 (S↔C):** `Leg-S squeeze[b] (c̃') == Leg-C cr[b]`, b ∈ 0..64.
- **Outcomes (local, KoalaBear D4/W16, bench FRI params — NOT production soundness):**
  - **[1] HONEST** (`cs == cr == c̃'`, all 3 ties): the outer aggregated proof **prove+verify
    SUCCEEDS = ACCEPT — 437,411 B, witness_count 1,443,765, 11.2 s**.
  - **[2] NEG-A (wrong c̃, the accept GATE):** Leg C over `cs != cr` (`cs[0]` flipped — a forged
    supplied c̃) → challenge_eq's own AIR (`cs[i]==cr[i]`) is unsatisfiable → **Leg C batch proof
    REJECTS at native verify** = the accept decision genuinely gates.
  - **[3] NEG-B1 (tamper a `w1` coeff):** Leg E built over a `w1'` differing in one coefficient (4→5)
    → Tie U↔E / E↔S mismatch → **REJECTS at prove (~0.42 s, `WitnessConflict`)**; `c̃'` would change.
  - **[4] NEG-B2 (tamper a `w1Encode` byte):** Leg S absorbs a `w1Encode'` differing in one byte
    (+16) → Tie E↔S mismatch → **REJECTS at prove (~0.41 s, `WitnessConflict`)**; `c̃'` changes.
- **BOTH ends of `Verify` now compose through recursion.** The ExpandA INPUT side (`ρ → SHAKE →
  stream → pi_stream → placed Â → ŵ_i`) and this OUTPUT/accept side (`w → UseHint → w1Encode →
  SHAKE256 → c̃'==c̃`) are each demonstrated as heterogeneous cross-stage-tied recursion trees on
  real gadget constraints — strong evidence the full `circuit_version=3` aggregation is achievable
  (the remaining seam is the invNTT stage bridging `ŵ_i → w`, plus full-scale coefficient counts).
  **UPDATE:** that seam is now closed (reduced scope) — the invNTT bridge lands as a real leg that
  JOINS this accept tail to the matvec front in ONE outer proof; see the next subsection,
  "invNTT BRIDGE".
- **Artifacts:** example `recursion/examples/accept_tail.rs` (self-contained; in the pinned Plonky3
  recursion clone at `b363397`); diff `docs/bench/plonky3-recursion-accept-tail.diff` (Cargo.toml
  dev-deps + the example, apply-clean AND build-clean on pristine `b363397`). Upstream
  no-regression: `cargo test -p p3-circuit -p p3-circuit-prover -p p3-recursion` green
  (368/84/… pass, 0 fail) and `recursive_fibonacci` still verifies.
- **Deferred:** full-scale coefficient counts (NW1=256 → K=8·256=2048; the μ‖w1Encode message then
  spans ~8 SHAKE256 absorb blocks), the invNTT stage feeding `w` (`ŵ_i → w`, the one relation that
  wires this accept-tail to the ExpandA/matvec front), the full `circuit_version=3` aggregation,
  and items (v) full corpus / (vi) audit.

#### invNTT BRIDGE — `ŵ_i → invNTT → w → UseHint` JOINS the two ends into ONE continuous recursion chain (the CAPSTONE)

The two subsections above each compose ONE end of `Verify`: the ExpandA/matvec INPUT end
(`ρ → … → ŵ_i`, NTT-domain OUTPUT publics) and the accept OUTPUT end (`w → UseHint → … → c̃'==c̃`,
which consumed `w` as a *representative* INPUT). **The only relation between them — wire 14, the
inverse NTT `w = invNTT(ŵ)` — was `GADGET_ONLY_NOT_WIRED`: the standalone 256-pt gadget existed
(`invntt_wired256_air.rs`) but its `PI_IN` was not bound to `ŵ_i` and its `PI_OUT` not bound to
UseHint.** This subsection LANDS that stage as a real batch-STARK **Leg I** and JOINS the two ends,
so **ONE outer proof covers the whole verify tail `matvec ŵ_i → invNTT → w → UseHint`** with the two
cross-stage ties that bridge the ends proven in-circuit.

- **STEP 0 — THREE legs, TWO NEW ties.** Legs M and U are the sibling examples' AIRs VERBATIM (Leg U
  EXTENDED only to also surface its `w` INPUT as publics — the extra binding the invNTT↔accept tie
  reads); Leg I is new. Each is a single-instance batch-STARK proof verified in-circuit by
  `verify_batch_circuit` (KoalaBear D4/W16). Reduced-but-real: the GS invNTT is the COMPLETE **n=8**
  transform (the reduced partner of the proven 256-pt file), not a partial slice.
  - **Leg M — matvec front** (`ExpandaPlaceAir` verbatim from `expanda_chain_matvec.rs`): placed
    `Â∘ẑ − ĉ∘(t̂1·2^d)`, on **REAL libcrux ML-DSA-87 seed-5 ρ**. **1137 cols × 512 rows, 576 publics**
    (320 `pi_stream` ‖ 64 ẑ ‖ 64 t̂1 ‖ 64 ĉ ‖ **64 ŵ_i OUTPUT**). Native proof **357,637 B / 95.6 ms**.
  - **Leg I — invNTT bridge** (NEW; GS constraints VERBATIM from `invntt_wired8_air.rs`): the COMPLETE
    Gentleman-Sande n=8 inverse — **12 GS butterflies `(a,b)→(a+b, ζ·(b−a)) mod q` across all 3 layers
    with FULL in-AIR cross-layer routing** (every layer's inputs constrained `==` the previous layer's
    outputs, every twiddle pinned to the canonical n=8 ζ) — PLUS the **`n⁻¹` = inv(8) mod q
    normalization as 8 further proven mod-q multiplies** (one per coefficient, the exact "one further
    mod-q mult per coeff" `invntt_wired256_air.rs` documents), reusing the same GS gadget with `a=0`.
    **9600 cols × 64 rows, 16 publics** (8 ŵ INPUT ‖ 8 `w` OUTPUT). Native proof **1,186,004 B / 95.1 ms**.
  - **Leg U — UseHint** (`usehint_air.rs` verbatim, EXTENDED): FIPS-204 Decompose ∘ hint. Surfaces
    BOTH the `w` INPUT and the `w1` OUTPUT via the factored one-hot. **147 cols × 256 rows, 512
    publics** (256 `w` INPUT ‖ 256 `w1` OUTPUT). Native proof **123,123 B / 19.2 ms**.
- **Faithfulness gates (host, independent oracles, all PASS):** GATE 0 — the invNTT gadget is a
  correct inverse: `invNTT(NTT(x)) == x` **coefficient-exact over 200 random `x`** (the `ntt_zq.rs`
  round-trip oracle, n=8, inv(8) scaled). GATE 1 — Leg I's trace output `w == invNTT(ŵ)` **coeff-exact**
  vs the reference for the ACTUAL `ŵ` slice used in the join. The `ŵ` fed to Leg I is matvec's REAL
  output `ŵ_i[0..8]` (asserted equal to Leg M's `ŵ` publics).
- **The two NEW ties, one outer proof** (each `diff = cb.sub(…); cb.assert_zero(diff)`, one read per public):
  - **Tie 1 (front↔invNTT):** `Leg-M ŵ_i[k] (OUTPUT) == Leg-I ŵ_in[k] (INPUT)`, k ∈ 0..8.
  - **Tie 2 (invNTT↔accept):** `Leg-I w_out[k] (OUTPUT) == Leg-U w_in[k] (INPUT)`, k ∈ 0..8.
- **Outcomes (local, KoalaBear D4/W16, bench FRI params — NOT production soundness):**
  - **[1] HONEST** (`ŵ→w` consistent, both ties): the outer aggregated proof **prove+verify SUCCEEDS
    = the WHOLE verify tail composes — 442,199 B, witness_count 2,097,851, 13.3 s**.
  - **[2] NEG-W (a `w` inconsistent with `invNTT(ŵ)` fed to UseHint):** Leg U over `w'` whose first
    coeff ≠ the bridge output → **Tie 2 (I↔U) mismatch → REJECTS at prove (~0.65 s, `WitnessConflict`)**.
  - **[3] NEG-BF (tamper one invNTT butterfly output):** perturb bf8's a-input (must equal bf4.out0)
    → Leg I's own in-AIR cross-layer routing is violated → **Leg I batch proof REJECTS at native verify**.
  - **[4] NEG-WH (the `ŵ` slice fed to invNTT ≠ matvec's real `ŵ`):** Leg I over `ŵ'` (internally a
    valid invNTT) → **Tie 1 (M↔I) mismatch → REJECTS at prove (~0.63 s)**.
- **Scope shipped (REDUCED-BUT-REAL):** invNTT = the COMPLETE n=8 GS transform (all 12 butterflies,
  3 layers, real pinned twiddles, + real inv(8) scaling) — the reduced point count (n=8, not 256) the
  task blesses, NOT a partial transform. The **8 coefficients that flow matvec→invNTT→UseHint** are
  bound by the two ties (matvec produces NM=64 ŵ, UseHint consumes NW1=256 `w`; the untied remainder
  is representative). `ŵ` fed to Leg I is matvec's REAL output slice; `w = invNTT(ŵ)` is diff-tested
  exact. Everything downstream of UseHint (`w1Encode → SHAKE256 → c̃'==c̃`) is the already-proven
  `accept_tail.rs`; this file re-proves only Leg U as the join anchor.
- **The whole `Verify` tail is now ONE continuous recursion chain.** With the invNTT landed as a real
  leg and both bridging ties proven, `matvec ŵ_i → invNTT → w → UseHint (→ w1Encode → SHAKE256 →
  c̃'==c̃)` composes end-to-end through recursion. The invNTT was the ONE relation (wire 14) that stood
  between the two previously-separate chains; it is now closed (reduced scope). **This is the strongest
  evidence yet that the full `circuit_version=3` aggregation is achievable — both ends AND the bridge
  all compose as heterogeneous cross-stage-tied recursion trees on real gadget constraints.**
- **Artifacts:** example `recursion/examples/verify_tail_join.rs` (self-contained; in the pinned
  Plonky3 recursion clone at `b363397`); diff `docs/bench/plonky3-recursion-verify-tail-join.diff`
  (Cargo.toml `tiny-keccak` dev-dep + the example — apply-clean AND build-clean AND **run-clean**
  (identical HONEST+3-negative results) on pristine `b363397`). Upstream no-regression: `cargo test -p
  p3-circuit -p p3-circuit-prover -p p3-recursion` green (368/84/… pass, 0 fail) and
  `recursive_fibonacci` still verifies.
- **Deferred:** the **n=256 full invNTT** (`invntt_wired256_air.rs` is proven standalone as a uni-stark
  AIR — 61,440 cols, 1024 butterflies, in-AIR routing — but slotting it as a batch-STARK recursion leg
  needs the multi-row-preprocessed adaptation the ExpandA legs used); the decode/μ front stages
  (wires 8–12) and the ĉ/t̂1 forward-NTT front stages (**wire 13 forward NTT is now closed for ẑ at
  reduced n=8** — see the FORWARD-NTT FRONT STAGE subsection immediately below); the full
  `circuit_version=3` aggregation (all stages + full K=8/L=7/N=256 counts in one tree); and items (v)
  full corpus / (vi) audit.

#### FORWARD-NTT FRONT STAGE — `z → forward NTT → ẑ → matvec` BINDS ẑ into the matvec (ẑ is now REAL `NTT(z)`, was representative)

The matvec front (`expanda_chain_matvec.rs`, and Leg M of the invNTT bridge above) consumed `ẑ / ĉ /
t̂1` (NTT-domain) as INPUT publics that were **REPRESENTATIVE canonical residues** `< q` — a
documented deferred gap ("the invNTT/forward-NTT stages feeding these are deferred"). This subsection
closes the FRONT gap for `ẑ`: it lands the forward NTT `ẑ = NTT(z)` as a real batch-STARK **Leg F**
and BINDS it into the matvec's `ẑ` INPUT, so **ONE outer proof covers `z → forward NTT → ẑ → matvec`**
with the cross-stage tie proven in-circuit — the matvec's `ẑ` is no longer representative but the REAL
forward NTT of a coefficient-domain `z`. It is the FORWARD partner of the invNTT bridge and mirrors it
exactly (`ntt_wired8_air.rs` is the forward Cooley-Tukey partner of `invntt_wired8_air.rs`).

- **STEP 0 — TWO legs, ONE NEW tie.** Leg M is `ExpandaPlaceAir` VERBATIM; Leg F is new. Each is a
  single-instance batch-STARK proof verified in-circuit by `verify_batch_circuit` (KoalaBear D4/W16).
  Reduced-but-real: the CT forward NTT is the COMPLETE **n=8** transform (the reduced partner of the
  proven 256-pt `ntt_wired256_air.rs`), not a partial slice.
  - **Leg F — forward NTT front** (NEW; CT constraints VERBATIM from `ntt_wired8_air.rs`): the COMPLETE
    Cooley-Tukey n=8 forward transform — **12 CT butterflies `(a,b)→(a+ζb, a−ζb) mod q` across all 3
    (=log₂8) layers with FULL in-AIR cross-layer routing** (every layer's inputs constrained `==` the
    previous layer's outputs `bf4.a==bf0.out0 … bf11.b==bf7.out1`, every twiddle pinned to the canonical
    n=8 `ζ[k]=ψ^brv3(k)`, `ψ=1753^32`). No `n⁻¹` scaling (that normalization belongs to the inverse
    transform only, so Leg F is exactly the 12 butterflies — NBF=12 vs Leg I's 20). **5520 cols × 64
    rows, 16 publics** (8 `z` INPUT ‖ **8 ẑ OUTPUT**). Native proof **706,537 B / 83.4 ms**.
  - **Leg M — matvec front** (`ExpandaPlaceAir` verbatim from `expanda_chain_matvec.rs`): placed
    `Â∘ẑ − ĉ∘(t̂1·2^d)`, consuming `ẑ` as INPUT publics (`PI_Z_M`), on **REAL libcrux ML-DSA-87 seed-5
    ρ**. **1137 cols × 512 rows, 576 publics** (320 `pi_stream` ‖ 64 ẑ ‖ 64 t̂1 ‖ 64 ĉ ‖ 64 ŵ_i OUTPUT).
    Native proof **357,710 B / 58.9 ms**. In the honest run `ẑ[0..8]` is OVERWRITTEN with Leg F's real
    `NTT(z)` (the tie binds those 8); `ẑ[8..64] / t̂1 / ĉ` stay representative.
- **Faithfulness gates (host, independent oracles, all PASS):** GATE 0 — Leg F's gadget is a genuine
  negacyclic NTT: the **convolution theorem `NTT(f)∘NTT(g) == NTT(f·g mod x⁸+1)`** (vs independent
  schoolbook) AND the forward/inverse **round-trip `invNTT(NTT(x)) == x`**, both **coefficient-exact over
  200 random `(f,g)`** — the `ntt_zq.rs` oracle at n=8. GATE 1 — Leg F's trace output `ẑ == NTT(z)`
  **coefficient-exact** vs the reference `ntt8` for the ACTUAL `z` used in the join, and Leg F's INPUT/
  OUTPUT publics equal `z / ẑ`.
- **The ONE NEW tie, one outer proof** (`diff = cb.sub(…); cb.assert_zero(diff)`, one read per public):
  - **Tie (front↔matvec):** `Leg-F ẑ[k] (OUTPUT) == Leg-M ẑ_in[k] (INPUT, PI_Z_M)`, k ∈ 0..8.
- **Outcomes (local, KoalaBear D4/W16, bench FRI params — NOT production soundness):**
  - **[1] HONEST** (matvec's `ẑ` = Leg F's real `NTT(z)`, tie on): the outer aggregated proof
    **prove+verify SUCCEEDS = the forward-NTT front stage is recursion-composed and BOUND into the
    matvec's ẑ input — 418,182 B, witness_count 1,285,380, 11.0 s**.
  - **[2] NEG-ZH (a `ẑ` fed to matvec inconsistent with `NTT(z)`):** matvec over `ẑ'` whose first coeff
    ≠ the forward-NTT output → **the tie (F↔M) mismatch → REJECTS at prove (~0.33 s, `WitnessConflict`
    2711990 vs 2711991)**.
  - **[3] NEG-BF (tamper one Leg F butterfly output):** perturb bf8's a-input (must equal bf4.out0) →
    Leg F's own in-AIR cross-layer routing is violated → **Leg F batch proof REJECTS at native verify**.
- **Scope shipped (REDUCED-BUT-REAL):** Leg F = the COMPLETE n=8 CT forward transform (all 12
  butterflies, 3 layers, real pinned twiddles) — the reduced point count (n=8, not 256) the invNTT
  bridge blessed, NOT a partial transform. The **8 ẑ coefficients that flow Leg F → matvec** are bound
  by the tie (matvec consumes NM=64 ẑ; the untied remainder `[8..64]` is representative). The `ẑ` tied
  into matvec is Leg F's REAL forward NTT of a `z`; `ẑ = NTT(z)` is diff-tested exact. Real `z` is a
  deterministic coefficient-domain input; `ρ` is REAL libcrux seed-5.
- **`ĉ = NTT(c)` and `t̂1 = NTT(t1)` are the IDENTICAL mechanism** — a forward-NTT leg plus a tie into
  the matvec's `ĉ / t̂1` inputs (`PI_C_M / PI_T1_M`), done the same way; `ẑ` is shipped here as the
  exemplar. With the invNTT bridge (wire 14) already closing the BACK of the matvec (`ŵ → invNTT → w`),
  this closes the FRONT of the matvec for `ẑ`: the pointwise `Â∘ẑ` now consumes a REAL forward NTT.
- **Artifacts:** example `recursion/examples/front_ntt_join.rs` (self-contained; in the pinned Plonky3
  recursion clone at `b363397`); diff `docs/bench/plonky3-recursion-front-ntt-join.diff` (Cargo.toml
  `tiny-keccak` dev-dep + the example — apply-clean on pristine `b363397`, build-clean AND run-clean in
  the clone). Upstream no-regression: `cargo test -p p3-circuit -p p3-circuit-prover -p p3-recursion`
  green (372/84/… pass, 0 fail) and `recursive_fibonacci` still verifies.
- **Deferred:** the ĉ/t̂1 forward-NTT legs (same mechanism); the **n=256 full forward NTT**
  (`ntt_wired256_air.rs` is proven standalone as a uni-stark AIR — 1024 butterflies, in-AIR routing —
  but slotting it as a batch-STARK recursion leg needs the multi-row-preprocessed adaptation);
  sigDecode/pkDecode/SampleInBall front stages that produce `z / c / t1` before the NTT; the full
  `circuit_version=3` aggregation; and items (v) full corpus / (vi) audit.

#### FRONT COMPLETION — c/t1 forward NTT (ĉ, t̂1 now REAL) + SampleInBall + pkDecode composed into the verify recursion chain

The FORWARD-NTT FRONT STAGE above shipped `ẑ = NTT(z)` and noted "`ĉ = NTT(c)` and `t̂1 = NTT(t1)` are the
IDENTICAL mechanism … `ẑ` is the exemplar", and the whole front left the byte-parse producers of `z / c /
t1` deferred. This subsection lands those remaining front stages as three new self-contained recursion
examples, so — for the reduced n=8 scope — the front of `Verify` composes through recursion from the
challenge/pk parse all the way to the matvec's NTT-domain inputs. **All three examples are HONEST-OK with
every negative rejecting; each new leg's gadget is diff-tested coefficient-exact vs its reference oracle
(`ntt_zq` / `mldsa_verify_ref` / `unpack10`).**

- **(1) `front_ntt_ct_join.rs` — ĉ AND t̂1 are now REAL forward NTTs (the other two exemplars).** FOUR
  heterogeneous legs in ONE outer proof: three `NttAir` forward-NTT legs (over `z`, `c`, `t1`) + the
  `ExpandaPlaceAir` matvec (real libcrux seed-5 ρ), with **THREE cross-stage ties**
  `Tie_z: F_z.ẑ == M.PI_Z_M`, `Tie_c: F_c.ĉ == M.PI_C_M`, `Tie_t1: F_t1.t̂1 == M.PI_T1_M` (each an ALU
  `sub`-assert-zero, one read per public). Real coefficient-domain inputs: `z` = residues `< q`, `c` = a
  τ-sparse ternary challenge slice (`−1 ≡ q−1`), `t1` = raw pkDecode values in `[0, 2^10)`. **GATE 1**:
  `ẑ==NTT(z)`, `ĉ==NTT(c)`, `t̂1==NTT(t1)` all coefficient-exact vs the `ntt_zq` reference. **[1] HONEST**:
  outer prove+verify SUCCEEDS = the matvec's `ẑ` AND `ĉ` AND `t̂1` are ALL real forward NTTs, none
  representative — **453,871 B, witness_count 3,365,046, 26.3 s**. **[2] NEG-CH** (matvec `ĉ[0] ≠ NTT(c)[0]`)
  → `Tie_c` mismatch → REJECTS (~1.3 s, `WitnessConflict`). **[3] NEG-T1** (matvec `t̂1[0] ≠ NTT(t1)[0]`) →
  `Tie_t1` mismatch → REJECTS (~1.1 s). **[4] NEG-BF** (tamper an `F_c` butterfly a-input) → that leg's
  in-AIR cross-layer routing → native batch verify REJECTS. This completes wire 13 for the reduced n=8
  scope: the matvec's three NTT-domain inputs are now all real forward NTTs.

- **(2) `sampleinball_join.rs` — the CONCEPTUALLY-NEW challenge-polynomial stage: `c = SampleInBall(c̃) →
  ĉ = NTT(c)`.** TWO heterogeneous legs, ONE tie: **Leg S** = a `SibAir` porting `sample_in_ball_air.rs`
  VERBATIM in structure (FIPS-204 Alg.29 Fisher-Yates: witnessed one-hot selectors `sel=[k==j]`/`indi=[k==i]`
  boolean+one-hot+index-bound, `a_j=Σ sel·a` read, `j≤i` by slack bits, exact swap `c[i]←c[j]; c[j]←±1`)
  PLUS the `sampleinball_air.rs` ball-membership check on the output (`cₖ=posₖ−negₖ`, `posₖ·negₖ=0`,
  `Σ(posₖ+negₖ)=τ`); the whole τ-step run is unrolled in ONE row (steps threaded `next_s==a_{s+1}`, `a_0=0`),
  exactly as `NttAir` carries a whole transform per row. **Leg F** = `NttAir` `ĉ=NTT(c)`. **Tie S↔F**:
  `Leg-S c[k] (OUTPUT) == Leg-F c_in[k] (INPUT, PI_Z)`, k∈0..8. **Representation:** the challenge is carried
  in the **mod-q residue alphabet `{0, 1, q−1}`** (ternary `a·(a−1)·(a−(q−1))=0`; placed sign
  `1+sgn·(q−2)∈{1,q−1}`) — the SAME identity `a∈{0,1,−1}` in the residue system the downstream NTT consumes,
  so the two stages compose by a direct field-equality tie (a representation choice, not a structural
  change). **Scope:** reduced **n=8, τ=4** (real ML-DSA-87 is n=256/τ=60); the `(i,j,sign)` placement
  sequence is derived from the REAL `SHAKE256(c̃)` stream (tiny-keccak) of a representative 64-byte `c̃`,
  exactly as `mldsa_verify_ref::sample_in_ball`. **Leg S: 176 cols × 64 rows, 8 pubs, 53,280 B.** Leg S's
  `c` is diff-tested coefficient-exact vs a reduced reference `sample_in_ball`. **[1] HONEST**: outer
  SUCCEEDS = the challenge-polynomial front stage is recursion-composed and bound into the forward NTT
  (`c` = REAL `SampleInBall(c̃)`) — **405,669 B, witness_count 1,082,851, 7.0 s**. **[2] NEG-STEP** (tamper a
  placement step's `next`) → swap-formula + threading → native REJECT. **[3] NEG-WEIGHT** (set `pos` at a
  zero coefficient ⇒ weight τ+1 / bad decomposition) → ball-membership → native REJECT. **[4] NEG-TIE**
  (NTT fed a `c ≠ SampleInBall`'s) → `Tie S↔F` mismatch → REJECTS at prove.

- **(3) `pkdecode_join.rs` — the DECODE partner: `t1 = pkDecode(pk) → t̂1 = NTT(t1)`.** TWO legs, ONE tie:
  **Leg P** = a `PkDecodeAir` porting `pkdecode_t1_air.rs` VERBATIM (FIPS-204 SimpleBitPack 10-bit unpack:
  4 coeffs from 5 packed bytes via 40 shared bits regrouped 10-bit-per-coeff vs 8-bit-per-byte), NG=2
  groups unrolled per row → 8 coefficients (= the n=8 NTT width). **Leg F** = `NttAir` `t̂1=NTT(t1)`.
  **Tie P↔F**: `Leg-P t1[k] (OUTPUT) == Leg-F t1_in[k] (INPUT, PI_Z)`, k∈0..8. **Leg P: 98 cols × 64 rows,
  8 pubs, 51,438 B.** `t1` diff-tested coefficient-exact vs the reference `unpack10`. **[1] HONEST**: outer
  SUCCEEDS = the pk-parse front stage is recursion-composed and bound into the forward NTT (`t1` = REAL
  pkDecode) — **405,622 B, witness_count 1,067,719, 7.1 s**. **[2] NEG-UNPACK** (tamper a coeff off its
  10-bit grouping) → native REJECT (a wrong-endianness / off-by-a-bit unpack is caught). **[3] NEG-TIE**
  (NTT fed a `t1 ≠ pkDecode`'s) → `Tie P↔F` mismatch → REJECTS at prove.

- **What is now recursion-composed + tied (reduced n=8):** the forward NTT is real for **all three** matvec
  inputs `ẑ / ĉ / t̂1` (was `ẑ`-only); the **SampleInBall → ĉ** and **pkDecode → t̂1** 2-stage front
  sub-chains are bound end-to-end. Combined with the invNTT bridge (wire 14) and the accept tail, the
  reduced-scope `Verify` now composes from challenge/pk parse through the matrix-vector product and back to
  the accept condition, all in cross-stage-tied recursion trees.
- **Real vs representative:** `ρ` = REAL libcrux seed-5; SampleInBall driven by a REAL `SHAKE256(c̃)`
  stream; `c`/`t1`/`ẑ`/`ĉ`/`t̂1` gadget outputs are all diff-tested exact vs their references. Representative
  (documented): the packed-t1 bytes are a valid SimpleBitPack encoding but not extracted from a specific
  libcrux key (the recursion clone has no libcrux dep); `z` is a deterministic coefficient-domain slice; the
  matvec's untied `[8..64]` NTT-domain remainders stay representative.
- **Artifacts:** examples `recursion/examples/front_ntt_ct_join.rs`, `sampleinball_join.rs`,
  `pkdecode_join.rs` (all self-contained; in the pinned Plonky3 recursion clone at `b363397`); diff
  `docs/bench/plonky3-recursion-front-completion.diff` (Cargo.toml `tiny-keccak`/`p3-keccak` dev-deps + the
  three examples — apply-clean on pristine `b363397`, build-clean AND run-clean). Upstream no-regression:
  `cargo test -p p3-circuit -p p3-circuit-prover -p p3-recursion` green (**633 passed / 0 failed / 13
  ignored**) and `recursive_fibonacci` still verifies.
- **Deferred (front):** the byte-parse → NTT sub-chains at **n=256 full** (SampleInBall n=256/τ=60,
  pkDecode 64 groups/poly, the n=256 forward NTT via the multi-row-preprocessed batch-STARK adaptation);
  **sigDecode `z` (20-bit BitUnpack + `‖z‖∞ < γ1−β`)** as a front leg (not built this pass); the full
  `circuit_version=3` aggregation; Solidity dispatch; and items (v) full corpus / (vi) audit. **(The
  `μ = SHAKE256(tr‖…‖M)` / `tr = SHAKE256(pk)` / `c̃' = SHAKE256(μ‖w1Encode)` hash front is now BUILT —
  see "DECODE/μ FRONT" immediately below.)**

#### DECODE/μ FRONT — `tr = SHAKE256(pk) → μ = SHAKE256(tr‖0x00‖len(ctx)‖ctx‖M) → c̃' = SHAKE256(μ‖w1Encode) → c̃'==c̃` in ONE AIR (wires 8/9/10/12)

The three chained SHAKE256 hashes that produce the FIPS-204 challenge — the "decode/μ derivation
front" — were the last front wires left at `GADGET_ONLY_NOT_WIRED` (`shake_threaded_air.rs` proved
ONE multi-block SHAKE, but the μ-framing and the tr→μ→c̃' chaining were unbound). **`mu_front_air.rs`
now binds all four (wires 8, 9, 10, 12) end-to-end in ONE AIR**, driven by a **REAL
`libcrux_ml_dsa::ml_dsa_87` key + signature**.

- **Three SHAKE256 SEGMENTS of one trace.** Each hash is a run of `p3-keccak-air` permutations
  (24 rows each) in adjacent 24-row groups — the exact multi-block threading of
  `shake_threaded_air.rs` — but here THREE segments sit back-to-back, each RESET to the all-zero
  sponge at its first permutation (a per-segment first-absorb-into-zero-state flag). Seg 0 =
  `tr = SHAKE256(pk)` (pk = 2592 B → 20 absorb perms), Seg 1 = `μ = SHAKE256(tr ‖ 0x00 ‖ len(ctx) ‖
  ctx ‖ M)` (1 perm), Seg 2 = `c̃' = SHAKE256(μ ‖ w1Encode)` (1088 B → 9 perms). 30 perms, height 1024.
- **Cross-hash ties = SHARED PUBLIC VALUES (no new constraint kind, NO recursion).** The vendored
  sponge already binds each message byte AND each squeeze-output byte to a public value; the GLOBAL
  public layout makes the intermediate digests appear EXACTLY ONCE, bound by BOTH the producing
  segment's output and the consuming segment's message: **seg0.out[0..64] and seg1.msg[0..64] → the
  same `TR` publics; seg1.out[0..64] and seg2.msg[0..64] → the same `MU` publics; seg2.out[0..64] →
  the `CTILDE` publics (= c̃).** So `seg1.msg[0..64] == tr == SHAKE256(pk)`, `seg2.msg[0..64] == μ ==
  SHAKE256(tr‖…‖M)`, and `c̃' == c̃` are all forced in-AIR — a prover cannot feed μ any `tr` other
  than `SHAKE256(pk)`, nor c̃' any `μ` other than the real one, nor accept unless `c̃' == c̃`. (Fusing
  3 small hashes into one STARK is measured-cheap — ≈30 perms — unlike the ExpandA legs whose fusion
  ADR-0035 measured too wide; the shared-public tie is the strictly-stronger in-one-STARK form of the
  cross-leg recursion tie.)
- **Gates, all green on .119** (x86_64, release, bench FRI params): **GATE 3** — the from-scratch
  FIPS-204 front reproduces the REAL libcrux accept: libcrux verifies the signature AND `c̃' == c̃`
  (|pk|=2592, |M|=10, ctx=`mil-receipt-v1`, |w1Encode|=1024); **GATE 1** — host sponge oracle ==
  `sha3::Shake256` byte-for-byte on all three real segment messages; **GATE 4** — coverage self-audit:
  100 boundary (lane,limb) wires, 3770 message-byte + 310 pad-byte block bindings across 3 segments,
  the 64-byte TR tie (seg0.out==seg1.msg) and 64-byte MU tie (seg1.out==seg2.msg) share public indices
  exactly; **GATE 2** — proven trace re-read: each segment's squeeze output == sha3 byte-for-byte;
  **VERIFY ok** — prove 10.7 s / verify 142.4 ms, 5897 cols × 1024 rows, prep 33, 4050 publics, proof
  472,744 B. **Four negatives, all `OodEvaluationMismatch`:** `--corrupt-thread` (a sponge-state wire
  between two perms of Seg 2), `--corrupt-tie` (a `tr` byte fed to μ ≠ `SHAKE256(pk)` — the shared-
  public tie is load-bearing), `--corrupt-ctilde` (c̃ byte flipped ⇒ `c̃' ≠ c̃`), `--corrupt-w1` (a w1
  message byte flipped ⇒ message-binding broken). Repro: `cargo run --release --bin mu_front_air
  [--corrupt-thread|--corrupt-tie|--corrupt-ctilde|--corrupt-w1]` in `~/Plonky3/shield-air`. Vendored
  byte-identical at `docs/bench/plonky3-shield-air/mu_front_air.rs` (sha256
  `69980649cf89fdef8cebac71f0844e3b139d90f77750b8e2350206c5abbef7a3`, both sides).
- **Scope / still deferred:** this is the HASH front only (the SHAKE framing + chaining + accept
  equality). Its inputs `pk`, `M`, `w1Encode` are bound to publics but not yet tied to the DOWNSTREAM
  gadgets that produce/consume them inside `circuit_version=3` — `w1Encode` to the UseHint output
  (wires 15/16), c̃ to sigDecode `σ[0..64]` (wire 23), and `pk` to pkDecode/ExpandA (wires 20/21) and
  the `pk_receipt_hash` bridge (wire 24). That binding is item (iv). Bench FRI params
  (`log_blowup=2, num_queries=8, PoW 1`) are demonstration-only (not production soundness).

#### DECODE/μ FRONT ∘ ACCEPT-TAIL — the μ-derivation now JOINS the accept chain through recursion

The flat `mu_front_air.rs` binds the hash front in ONE STARK; the complementary result is that the
same derivation **composes into the verify RECURSION chain**. `mu_accept_join.rs` (recursion example
in the pinned clone `b363397`; diff `docs/bench/plonky3-recursion-mu-accept-join.diff`, apply-clean
+ build-clean + run-clean on pristine `b363397`) extends the 4-leg accept-tail (`accept_tail.rs`,
wire 15→16→10→12) to **SIX heterogeneous batch-STARK legs in ONE outer recursion proof**:

- **Leg TR** = `ShakeThreadedAir` proving `tr = SHAKE256(pk)`; **Leg MU** = `ShakeThreadedAir`
  proving `μ = SHAKE256(tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M)`; then the existing **Leg U** (UseHint),
  **Leg E** (w1Encode), **Leg S** (`c̃' = SHAKE256(μ ‖ w1Encode)`), **Leg C** (challenge_eq `c̃'==c̃`).
- **FIVE cross-stage ties, each `cb.sub`+`cb.assert_zero` on the legs' `air_public_targets`:**
  **TR↔MU** (`tr` == μ's message prefix), **MU↔S** (`μ` == c̃''s message prefix), U↔E, E↔S, S↔C.
  So the `μ` that Leg S hashes is now a REAL `SHAKE256(pk)`-rooted value — no longer representative.
- **Results (.119, KoalaBear D4/W16, security=100 recursion params):** HONEST outer proof OK =
  **ACCEPT** (`pk→tr→μ→UseHint/w1Encode→SHAKE256→(c̃'==c̃)`), 455,188 B, witness_count 3,739,837,
  322.7 s; Leg TR / Leg MU batch proofs ~646 ms each; GATE 1 (`c̃'`) + GATE 2 (`tr`/`μ`) diff-tested
  byte-exact vs an independent tiny_keccak SHAKE256. **Four negatives all reject:** NEG-A (wrong c̃ →
  challenge_eq native reject), NEG-B1 (w1 coeff → Tie U↔E), NEG-B2 (w1Encode byte → Tie E↔S), and the
  new **NEG-TR** (a `tr` fed to μ ≠ `SHAKE256(pk)` → **Tie TR↔MU** WitnessConflict at prove) — the
  μ-derivation tie is load-bearing. So the decode/μ FRONT joins the accept TAIL in the recursion tree,
  mirroring how the ExpandA INPUT end already composes. **Scope: REDUCED (NW1=256 = one w1 poly, pk
  160 representative bytes); production-scale k=8/full-size is 32 GB-gated** (item iv). Vendored diff
  sha-consistent; example sha256 `1e6575fb1c001cac64e420bfc5da0f05da8e3433a927ac255d207ddc0c146ef3`.

| # | ML-DSA-87 `Verify` wire | Proven AIR(s) | Status |
|---|---|---|---|
| 1 | ExpandA ① FULL-STREAM byte-position: squeeze bytes → `pi_stream` (all candidates incl. rejected groups) | `expanda_stream_bind_air.rs` (Leg B) + `shake_threaded_air.rs`; recursion binding `expanda_crossleg.rs` / `expanda_chain3.rs` | **BOUND (row i=0)** — Leg-S↔Leg-B cross-leg tie PROVEN in-recursion on the REAL legs for one entry (§7.1 "Real-leg cross-leg recursion binding"); the **Leg-B → matvec `pi_stream` tie is now ALSO PROVEN** (Tie 2 of the §7.1 three-stage chain, `expanda_chain3.rs`; reduced l=1/N=64/C=320) — HONEST 3-stage outer proof OK, both mismatch NEGATIVES reject; k=8 + L=7 all-entries + N=256-full deferred |
| 2 | ExpandA ② DOMAIN SEPARATION: each `Â[i][j]` ← distinct `SHAKE128(ρ‖[j,i])`, correct nonce order | `expanda_stream_bind_air.rs` (Leg S nonce publics) | **BOUND (row i=0)** — this workflow (was FREE) |
| 3 | ExpandA ③ RHO BINDING: ρ committed as the SHAKE128 message input | `expanda_stream_bind_air.rs` (Leg S ρ publics) | **BOUND (row i=0)** — this workflow (was FREE) |
| 4 | ExpandA rejection sampling: accept iff `t<q` per 3-byte candidate; 256 accepts before C=320 | `expanda_matvec_air.rs`; recursion binding `expanda_chain3.rs` (Leg M) | **BOUND (reduced)** — the rejection gadget's `pi_stream` INPUT is now composed in-recursion with the BOUND Leg-B stream (Tie 2, §7.1 three-stage chain; l=1, N=64, C=320), placed `Â` diff-tested coeff-exact vs FIPS-204; N=256-full + L=7 + k=8 deferred |
| 5 | ExpandA one-hot placement: accepted coeff → slot `cnt` (no skip/dup/reorder), write-once banks | `expanda_matvec_air.rs`; recursion binding `expanda_chain3.rs` / `expanda_chain_matvec.rs` (Leg M) | **BOUND (reduced)** — placement + write-once A-banks now composed in-recursion; in `expanda_chain_matvec.rs` the placed `Â` feeds the matvec-arithmetic tail (wire 6) DIRECTLY via the bank→mult diagonal read (§7.1 "matvec ARITHMETIC tail"; l=1, N=64); N=256-full + L=7 + k=8 deferred |
| 6 | matvec accumulate `ŵ_i = Σ_{j<7} Â[i][j]∘ẑ[j] − ĉ∘(t̂1_i·2^d)` | `expanda_matvec_air.rs`; recursion binding `expanda_chain_matvec.rs` (Leg M tail) | **BOUND (reduced)** — the pointwise mult + `ĉ∘(t̂1·2^d)` leg + accumulate-reduce are now COMPOSED IN-RECURSION as Leg M's arithmetic tail (§7.1 "matvec ARITHMETIC tail"; l=1, N=64): the placed `Â` feeds the mult b-input DIRECTLY and `ŵ_i` is the OUTPUT public, diff-tested coeff-exact vs the `mldsa_verify_ref.rs` matvec row on real ρ; two matvec negatives reject. ẑ/ĉ/t̂1 = representative canonical publics; L=7/N=256-full/k=8 deferred |
| 7 | SHAKE128 Keccak-f[1600] + absorb/pad10*1/squeeze (the ExpandA XOF) | `shake_threaded_air.rs` | **BOUND (row i=0)** — both ends now pinned (ρ in, `pi_stream` out) via wires 1–3; squeeze **public bytes now 8-bit range-checked (M-09, `6d07a96`)** — canonical public byte interface (`(52,18)`≡`(308,17)` non-canonical pair rejected) |
| 8 | μ = SHAKE256(tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M) | `mu_front_air.rs` (Seg 1) | **BOUND** — §7.1 "DECODE/μ FRONT": the `tr‖0x00‖len(ctx)‖ctx‖M` message framing IS bound as μ's SHAKE256 input, with `tr` tied to Seg 0's output via a SHARED public (so μ consumes exactly `SHAKE256(pk)`); real libcrux ML-DSA-87 data, negatives reject |
| 9 | tr = SHAKE256(pk) | `mu_front_air.rs` (Seg 0) | **BOUND** — §7.1 "DECODE/μ FRONT": `tr = SHAKE256(pk)` proven in-AIR (pk = 2592-B message bound to publics = wire 21), its output tied into μ's message prefix; `--corrupt-tie` (a `tr ≠ SHAKE256(pk)`) rejects |
| 10 | c̃' = SHAKE256(μ ‖ w1Encode(w1)) — final challenge-hash | `mu_front_air.rs` (Seg 2) | **BOUND** — §7.1 "DECODE/μ FRONT": `μ ‖ w1Encode` bound as the SHAKE256 message (`μ` tied to Seg 1's output via a SHARED public), output bound to c̃ (wire 12); `--corrupt-w1` rejects. w1Encode's coeff→byte SimpleBitPack (wire 16) still to compose over the UseHint output |
| 11 | c = SampleInBall(c̃) → τ=60 sparse ±1 (Fisher-Yates) | `sample_in_ball_air.rs`, `sampleinball_air.rs`; recursion binding `sampleinball_join.rs` (Leg S, n=8/τ=4) | **BOUND (reduced, n=8/τ=4)** — SampleInBall now composes IN-RECURSION as Leg S (§7.1 "FRONT COMPLETION"): the full FIPS-204 Alg.29 Fisher-Yates placement (one-hot indexed swap, `j≤i` slack, threading, ball-membership) with its challenge `c` OUTPUT bound to the forward NTT's `c` INPUT (Tie S↔F) — the 2-stage sub-chain `c = SampleInBall(c̃) → ĉ = NTT(c)` in one outer proof; HONEST OK, all 3 negatives reject (step-tamper + weight/non-ball + tie-mismatch); `c` diff-tested exact vs reference `sample_in_ball`, driven by a REAL `SHAKE256(c̃)` stream. **n=256/τ=60-full deferred** |
| 12 | c̃' == c̃ terminal accept (the FIPS-204 accept condition) | `mu_front_air.rs` (Seg 2 output) / `challenge_eq_air.rs` | **BOUND** — §7.1 "DECODE/μ FRONT": the c̃' publics (Seg 2 output) ARE the c̃ publics, so the final challenge-hash equals c̃ or the proof fails; checked against the REAL signature's c̃ (`--corrupt-ctilde` rejects). Remaining: bind c̃ to sigDecode's `σ[0..64]` slice (wire 23) in the composed relation |
| 13 | forward NTT: ẑ=NTT(z), ĉ=NTT(c), t̂1=NTT(t1) | `ntt_wired256_air.rs` (n=256 gadget); recursion binding `front_ntt_join.rs` (ẑ) + `front_ntt_ct_join.rs` (ẑ, ĉ, t̂1 all real) (Leg F, n=8) | **BOUND (reduced, n=8) for ALL THREE** — the FORWARD-NTT FRONT now composes IN-RECURSION for `ẑ`, `ĉ` AND `t̂1` (§7.1 "FORWARD-NTT FRONT STAGE" + "FRONT COMPLETION"): three COMPLETE CT n=8 forward legs, their `ẑ/ĉ/t̂1` OUTPUTS bound to the matvec's three NTT-domain INPUTS (`Tie_z/Tie_c/Tie_t1` → `PI_Z_M/PI_C_M/PI_T1_M`) in ONE 4-leg outer proof — HONEST OK, all negatives reject (per-tie mismatch + butterfly-tamper); convolution-theorem + round-trip checked vs `ntt_zq`. So the matvec's `ẑ`/`ĉ`/`t̂1` are ALL REAL forward NTTs, none representative. The decode front stages feeding the NTT are now bound too — `SampleInBall → ĉ` (`sampleinball_join.rs`, wire 11) and `pkDecode t1 → t̂1` (`pkdecode_join.rs`). **n=256-full deferred** (needs the multi-row-preprocessed batch-STARK adaptation); sigDecode `z` front stage deferred |
| 14 | inverse NTT: w = invNTT(ŵ) (Gentleman-Sande) | `invntt_wired256_air.rs` (n=256 gadget); recursion binding `verify_tail_join.rs` (Leg I, n=8) | **BOUND (reduced, n=8)** — the invNTT BRIDGE now composes IN-RECURSION as Leg I (§7.1 "invNTT BRIDGE"): the COMPLETE GS n=8 inverse + inv(8) scaling, its `ŵ` INPUT bound to matvec `ŵ_i` (Tie 1 M↔I) and its `w` OUTPUT bound to UseHint's `w` INPUT (Tie 2 I↔U), both proven in one outer proof — HONEST OK, all 3 negatives reject; round-trip-checked `invNTT(NTT(x))==x`. **n=256-full deferred** (needs the multi-row-preprocessed batch-STARK adaptation) |
| 15 | w1 = UseHint(h, w): Decompose + hint ±1 mod 16 | `usehint_air.rs`, `decompose_air.rs`; recursion binding `accept_tail.rs` / `verify_tail_join.rs` (Leg U) | **BOUND (reduced)** — UseHint composes in-recursion in both accept_tail (w1 OUTPUT tied to w1Encode) and verify_tail_join, where its `w` INPUT is now bound to the invNTT bridge output (Tie 2 I↔U, §7.1 "invNTT BRIDGE"); N=256-full / K=8 / h-from-sigDecode deferred |
| 16 | w1Encode (SimpleBitPack 4-bit) | `w1encode_air.rs` | GADGET_ONLY_NOT_WIRED — `num_pis=0`; coeffs (UseHint) / bytes (→SHAKE) unbound |
| 17 | norm bound ‖z‖∞ < γ1−β (=524168) | `norm_bound_air.rs` | GADGET_ONLY_NOT_WIRED — `num_pis=0`; z-input not bound to sigDecode |
| 18 | hint weight #h ≤ ω (=75) | `hint_weight_air.rs`, `popcount_bound_air.rs` | GADGET_ONLY_NOT_WIRED — `num_pis=0`; h-input not bound to sigDecode |
| 19 | **hint CANONICITY: per-position strict-increase + unused-byte-zero (HintBitUnpack ⊥)** | `hint_canonicity_air.rs` (`cf157f2`) | **CLOSED (standalone gadget)** — 24 real libcrux hints match reference ⊥/accept, 3 negatives reject; a non-canonical hint meeting the weight bound is now caught. Composition into item (iv) over the shared `(y,Index)` block still pending |
| 20 | pkDecode t1 (SimpleBitPack 10-bit unpack) | `pkdecode_t1_air.rs` | GADGET_ONLY_NOT_WIRED — `num_pis=0`; t1 not bound to NTT / expanda; pk not a statement |
| 21 | pkDecode ρ (pk[0..32] slice) | none (plain slice) | N/A — soundness = wire 3 (RHO BINDING), now BOUND for row i=0 |
| 22 | sigDecode z (BitUnpack 20-bit: z=γ1−raw) | `norm_bound_air.rs` (value-range only) | GADGET_ONLY_NOT_WIRED — **partial:** 20-bit value range covered, exact byte→coeff regroup NOT built |
| 23 | sigDecode c̃ (slice) + h (HintBitUnpack envelope) | weight via wire 18; canonicity via `hint_canonicity_air.rs` | GADGET_ONLY_NOT_WIRED (canonicity now a CLOSED standalone gadget, wire 19, awaiting composition); `mldsa_parse_checks.rs` is host-only |
| 24 | **claim bridge: pk_receipt_hash == H(pk) — link a verified ML-DSA pk into the claim** | `pk_receipt_bind_air.rs` (`8208ee0`) | **BOUND (standalone gadget)** — proves `pk_receipt_hash == blake2b_512_keyed("misaka-mil-v1/provider-id", pk[2592])` in-AIR (`ident.rs::provider_id`, the `provider_leaf` value); the prover must exhibit the 2592-B preimage. Still needs composition: nothing yet forces that preimage to be the pk an in-AIR ML-DSA-87 *Verify* checks (the item-(iv) verify circuit) |
| 25 | claim-side: session_cm / provider_nf / cm_payout / ctx / depth-20 membership root | `claim.rs` (build#6), `recursive_spend.rs` (build#5) | BOUND — real BLAKE2b, adversarial-audited; but INDEPENDENT of the ML-DSA verify (no verified pk yet) |
| 26 | claim-side pricing: hidden-amount value commitment `v_claim_cm` (AMT ↔ PI_SHARE) | `claim_v2.rs` (build#7) | BOUND — closes ask-price inversion; same "not tied to in-circuit ML-DSA verify" caveat as wire 25 |

**Real gaps to close (beyond plumbing).** Most rows are `GADGET_ONLY_NOT_WIRED` —
proven math awaiting cross-stage binding, which is item (iv)'s bulk. Three rows were
sharper (no proven gadget, or only partial) and are called out so they are not lost in the
plumbing; **two of the three (wires 19 and 24) now have standalone gadgets**, leaving wire 22
partial:

- **Wire 19 — hint canonicity (CLOSED as a standalone gadget, `cf157f2`).** `hint_weight_air.rs`
  proves ONLY the monotone cumulative counts + `#h ≤ ω`; the complementary per-position
  strict-increase / unused-byte-zero half of `HintBitUnpack` (ref `mldsa_verify_ref.rs`
  enforces `pos ≤ last ⇒ ⊥` and unused-hint-bytes = 0) is now proven by the new
  `hint_canonicity_air.rs` — 24 real libcrux ML-DSA-87 hint blocks match the reference
  ⊥/accept, 3 negatives reject. A non-canonical hint that still meets the weight bound is now
  caught. **Remaining:** compose it with the weight gadget into the item-(iv) relation over the
  shared `(y, Index)` block — the gadget is done, the cross-stage binding is not.
- **Wire 24 — claim ⇐ ML-DSA-verify bridge (hash half BOUND as a standalone gadget, `8208ee0`;
  the verify half still needs building).** The new `pk_receipt_bind_air.rs` proves
  `pk_receipt_hash == blake2b_512_keyed("misaka-mil-v1/provider-id", pk[2592])` in-AIR (the
  `mil/core/src/ident.rs::provider_id` value that enters `provider_leaf`), so a prover can no
  longer place an arbitrary `pk_receipt_hash` in the leaf unlinked from a 2592-byte preimage.
  What remains is the link to an *actually-verified* ML-DSA pk: this bridge binds
  `pk_receipt_hash` to a preimage's hash, but nothing yet forces that preimage to be the same
  pk the (multi-week) in-AIR ML-DSA-87 `Verify` gadget checks — that composition is item (iv)'s
  ultimate consumer. The claim relation (wires 25–26) is sound *on its own statement* and now
  receives a hash-bound pk, but not yet a *verified* one.
- **Wire 22 — sigDecode z exact-byte regroup (partial).** Only the 20-bit *value range* of
  `t=γ1−z` is covered (inside `norm_bound_air.rs`); the exact byte→coefficient
  SimpleBitPack regrouping of the z-poly bytes has no dedicated AIR (only t1's 10-bit one
  exists). Flag for the item-(iv) sig-decode slice.

The three ExpandA binding wires (1–3) were moved from `GADGET_ONLY_NOT_WIRED` / `FREE` to
**BOUND (row i=0)** by the ExpandA-stream-binding work (`577d33e`); wire 21 (ρ slice) is N/A
because its soundness is exactly wire 3. Subsequently the two remaining FREE-without-a-gadget
rows got standalone gadgets — **wire 19** hint canonicity (`hint_canonicity_air.rs`, `cf157f2`)
and **wire 24** the `pk_receipt_hash == H(pk)` claim bridge (`pk_receipt_bind_air.rs`,
`8208ee0`) — and **wire 7**'s squeeze public bytes are now 8-bit range-checked (M-09,
`6d07a96`), so no wire is FREE-without-a-gadget any longer. What remains is the item-(iv)
composition: binding every gadget's `num_pis=0` I/O into one `circuit_version=3` relation (plus
the multi-week in-AIR ML-DSA-87 `Verify` that wire 24 must ultimately consume). Everything else
remains as above until item (iv) closes.

**Recursion cross-leg public-equality binding — MECHANISM demonstrated (stand-in legs).**
The ExpandA soundness wire (`577d33e`, `expanda_stream_bind_air.rs`) is realized as two
separate STARK proofs — Leg S (`ShakeThreadedAir`: squeeze bytes == `SHAKE128(ρ‖nonce)`,
exposed as *public* outputs) and Leg B (`BindAir`: `pi_stream` packs == the squeeze bytes).
Its verify agent flagged one remaining low (the "cross-leg discharge deferred" note on wires
1–3): the tie *(Leg-S output publics) == (Leg-B input publics)* was an **assumption** (shared
witness), not a proven in-circuit binding. That tie is exactly the general C-P6 wiring
question — every `GADGET_ONLY_NOT_WIRED` stage (wires 4–6, 8–18, 20, 22–23) has `num_pis=0`
I/O that must be bound to its neighbours **through the recursion layer**, not fused into one
AIR (the measured reason: ADR-0035, monolithic verify ≈1.9e9 cells vs the ~20M/15GB envelope).

The **mechanism** is now demonstrated on stand-in legs against the pinned Plonky3-recursion
rev `b363397` (example `recursion/examples/crossleg_bind.rs`, captured apply-clean as
`docs/bench/plonky3-recursion-crossleg-bind.diff`; local Apple-silicon run, KoalaBear D4 W16,
conjectured-security 100). A recursion circuit **verifies two inner batch-STARK proofs A and B
and constrains their surfaced `air_public_targets` equal in-circuit**, producing ONE outer
proof, using only the pinned API — `BatchStarkVerifierInputsBuilder::allocate` +
`verify_batch_circuit` per leg, then the element-wise equality as `assert_zero(pubA[k] −
pubB[k])` (the A2 statement-surfacing patch is **not** needed for a public-*equality* tie).
Results:
- **HONEST** (`pubA == pubB`, tie enforced): outer prove+verify **SUCCEEDS** — one aggregated
  proof ≈290 KB in ≈0.34 s; a single-leg control aggregates in ≈0.19 s (≈279 KB).
- **CONTROL** (`pubA != pubB`, **no** tie): both legs still verify and the outer proof
  succeeds — i.e. the two legs are individually valid, which is precisely the
  *shared-witness assumption* world where the cross-leg tie is UNPROVEN.
- **NEGATIVE** (`pubA != pubB`, tie enforced): the outer proof **FAILS to prove** — the
  recursion-circuit run is rejected (`WitnessConflict`, the mismatched-publics difference
  cannot equal 0), so no outer proof exists. Rejection is at PROVE (witness generation), per
  the recursion API's failure mode, not at verify.

So the ExpandA cross-leg tie is **discharged as a mechanism**: pairing a Leg-S proof of stream
X with a Leg-B proof over stream Y≠X cannot yield an outer proof. Engineering note recorded
for the item-(iv) build: route the equality through an ALU `sub`+`assert_zero`, **not** a
direct `connect(pubA, pubB)` — aliasing two *Public*-table inputs to one witness slot breaks
that table's LogUp balance and makes the honest outer proof fail `TerminalSumNonZero` (verified
on this harness); the `sub`+`assert_zero` form keeps each public read exactly once. This is the
**template** for wiring every `GADGET_ONLY_NOT_WIRED` stage together (the
`recursive_spend.rs` batch-stark → `verify_batch_circuit` → chained-layers pattern).

**Scope / still deferred (honest remainder).** This is the mechanism on *tiny stand-in* AIRs
(a 1-block, `width=NUM_PUB+1` constant-column AIR exposing 4 public values, with a
committed-but-not-public tag so the two legs are genuinely distinct proofs), **not** the real
ExpandA legs (Leg S ≈6665 cols × 256 rows, Leg B ≈27 cols × 4096 rows) — those slot into the
identical `verify_batch_circuit` + `assert_zero(sub)` wiring but were not run this session.
Also deferred: the k=8 ExpandA row replication (rows i=1..7), chaining *all* C-P6 stages
through the tree, the full `circuit_version=3` aggregation, and items (v)/(vi). The wire-1–3
table entries above keep their **BOUND (row i=0)** status; this addendum records that their
"cross-leg discharge" is no longer only an assumption at the mechanism level.
