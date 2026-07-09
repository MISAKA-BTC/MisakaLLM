# ADR-0034 — Reference → STARK proof-system swap for the MIL shielded pool

- **Status:** Proposed (design freeze; prover is the ADR-0033 §SP-0 milestone)
- **Date:** 2026-07-09
- **Supersedes / extends:** ADR-0033 (EVM shielded pool), ADR-0025 §21 (payment
  shield-ladder rung L2), the O-SP-1 open question ADR-0033 explicitly defers to
  "its own ADR once Phase SP-0 benchmarks land".
- **Scope:** how the shielded pool moves from `PROOF_SYSTEM_REFERENCE` (transparent,
  sound, **not** zero-knowledge — witness in the clear) to `PROOF_SYSTEM_STARK`
  (hash-based, zero-knowledge, succinct) **without touching** the envelope, the
  statements, the commitments, the on-chain Merkle tree, the F006 precompile
  interface, the contracts, or the activation fence. This ADR does **not** ship a
  prover; it freezes the contract the prover must satisfy and pins the one
  code-diff surface.

---

## 0. Why this is a swap, not a rewrite

The whole point of the ADR-0033 §5.1 envelope is that the proof system is a
runtime tag, not a structural commitment. Concretely, in `misaka-mil-shield`:

```
proof::ShieldProof {
    proof_system_id: u8,        // 0x01 REFERENCE | 0x02 STARK
    circuit_version: u16,       // 1 SPEND | 2 PROVIDER_CLAIM
    verifier_key_hash: Hash64,  // governance-pinned per (system, circuit)
    public_inputs: Vec<u8>,     // borsh(SpendStatement | ProviderClaimStatement)
    proof: Vec<u8>,             // REFERENCE: borsh(witness) · STARK: succinct proof
}
```

The public inputs are the **same bytes** in both systems (the contract rebuilds
them on-chain — `ShieldedPool._borshSpendStatement`,
`MilShieldedEscrow._borshClaimStatement` — so a proof only ever binds to state the
contract already enforces). The **only** field whose *meaning* changes is `proof`:
today it is `borsh(SpendWitness | ProviderClaimWitness)` in the clear; under STARK
it becomes the succinct proof bytes and the witness stays on the prover's device.

Therefore the swap is exactly one function arm (see §5): the
`PROOF_SYSTEM_STARK` branch of `proof::verify_shield_proof`, which today is

```rust
PROOF_SYSTEM_STARK => Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK)),
```

Everything else in the L2 stack — `note`/`merkle`/`spend`/`provider` relations,
`domains` keys, `ShieldedPool.sol`, `MilShieldedEscrow.sol`, `kaspa-evm::shielded`
(F006), `evm_f006_shielded_verify_activation_daa_score` — is frozen by this ADR
and does not change when the prover lands.

---

## 1. Decision (the four locked choices)

1. **The circuit *is* the reference relation** (no re-arithmetization). The STARK
   proves the statement "`verify_reference(stmt, wit)` returns `Ok`" for the
   private `wit` and public `stmt`, where `verify_reference` is *literally*
   `spend::verify_reference` / `provider::verify_reference`. The prover is a
   zk proof of that Rust execution (zkVM-style guest = the existing relation), so
   there is **no second source of truth** to drift: the transparent verifier and
   the STARK verify the identical predicate over the identical byte layout.

2. **Hash stays keyed BLAKE2b-512, proven in-circuit** — it is *not* swapped for a
   STARK-friendly hash. The on-chain Merkle tree, commitments, nullifiers, and
   `ctx` are already committed (F004 keyed-BLAKE2b in `ShieldedPool._node`,
   `Hash64Lib.keyed`), and the `domains` keys are frozen. A friendly-hash inner
   tree would fork the committed pool and split the anonymity set. The cost of
   BLAKE2b-in-circuit is the O-SP-1 benchmark gate (§7), not a reason to change
   the hash. (This is what makes the island **PQ from genesis** — soundness rests
   only on hash security, SP-05.)

3. **Backend = hash-based STARK, recursed to meet the 32 KiB cap — never a pairing
   wrap.** The production family is S-two / Circle-STARK over the M31 field
   (ADR-0033 §porting). If a single flat proof exceeds the ADR-0033 §SP-0 cap of
   32 KiB, it is compressed by **STARK-to-STARK recursion** (a succinct wrapper
   STARK), which keeps soundness hash-based (SP-05). A Groth16/pairing wrap
   (Risc0's default compression) is **prohibited**: it reintroduces a trusted
   setup whose toxic waste forges withdrawals = undetectable MSK inflation
   (violates I-13 / SP-01), and its soundness is discrete-log (not PQ).

4. **No trusted setup / no ceremony.** A transparent STARK has no toxic waste, so
   `verifier_key_hash` is a *deterministic commitment to the AIR/program image*
   (`vk = H_k("shield-vk", proof_system_id ‖ circuit_version ‖ air_image)`), not a
   ceremony output. Governance pins it (`setSpendVkHash` / `setClaimVkHash` /
   `MilShieldedEscrow.setClaimVkHash`), and a circuit change is a
   `circuit_version` bump + a new pinned hash — the same rotation the contracts
   already expose.

---

## 2. The frozen circuit specification (the AIR contract)

The prover MUST prove, in zero knowledge, exactly the relations below. These are a
verbatim restatement of the committed reference verifiers; freezing them here is
the load-bearing deliverable of this ADR. Byte layout = the borsh encoding already
emitted by the contracts; hashing = `blake2b_512_keyed(DOMAIN, ·)` with the frozen
`domains` keys.

### 2.1 `CIRCUIT_SPEND` (= 1) — value JoinSplit (2-in / 2-out)

Public inputs `SpendStatement { anchor, nf_old[2], cm_new[2], v_pub_in, v_pub_out,
token_id, ctx }`. Private witness `SpendWitness { notes_in[2], sk_in[2],
paths_in[2], enable_in[2], notes_out[2] }`. Constraints (⇔ `spend::verify_reference`):

- **C-S1 token uniformity:** every `notes_in[i].token_id == notes_out[j].token_id
  == stmt.token_id`.
- **C-S2 membership (enabled inputs):** for `enable_in[i]`,
  `verify_merkle_path(anchor, commit(notes_in[i]), paths_in[i])` — a
  `TREE_DEPTH`-level recompute with `hash_node = H_k("merkle", l‖r)`.
- **C-S3 spend authority:** `notes_in[i].owner_pk == H_k("addr", sk_in[i])`.
- **C-S4 nullifier correctness:** `nf_old[i] == H_k("nf", sk_in[i] ‖ notes_in[i].rho)`.
- **C-S5 dummy discipline:** for `!enable_in[i]`, `notes_in[i].value == 0` (no
  membership proven).
- **C-S6 Faerie-Gold output rho:** `notes_out[j].rho == H_k("rho", nf_old[0] ‖
  nf_old[1] ‖ j)`.
- **C-S7 output opening:** `cm_new[j] == commit(notes_out[j])` where
  `commit(n) = H_k("cm", value_le ‖ owner_pk ‖ rho ‖ r ‖ token_id_le)`.
- **C-S8 value conservation:** `Σ_i (enable_in[i] ? notes_in[i].value : 0) +
  v_pub_in == Σ_j notes_out[j].value + v_pub_out`, in `u128`, no overflow.

`ctx` is **not** re-derived in-circuit; it is a public input the contract binds
(chain/pool/to/fee) — the STARK only carries it forward so a proof cannot be
replayed into a different context (SP-07).

### 2.2 `CIRCUIT_PROVIDER_CLAIM` (= 2) — anonymous provider claim

Public inputs `ProviderClaimStatement { provider_set_root, session_cm, amount,
provider_nf, cm_payout, ctx }`. Private witness `ProviderClaimWitness {
pk_receipt_hash, claim_secret, leaf_index, path, payout_note }`. Constraints
(⇔ `provider::verify_reference`):

- **C-P1 set membership:** `verify_merkle_path(provider_set_root,
  provider_leaf(pk_receipt_hash, H_k("addr", claim_secret)), path)`, with
  `provider_leaf = H_k("provider-leaf", pk_receipt_hash ‖ claim_pk)`.
- **C-P2 session nullifier:** `provider_nf == H_k("provider-nf", claim_secret ‖
  session_cm)`.
- **C-P3 payout opening:** `cm_payout == commit(payout_note)`.
- **C-P4 amount binding:** `payout_note.value == amount`.
- **C-P5 ctx binding:** `ctx == H_k("claim-ctx", session_cm ‖ amount_le ‖ cm_payout
  ‖ provider_nf)`.

**The one relation upgrade the STARK enables (O-SP-1 / §6).** The reference C-P1
*binds* `pk_receipt_hash` into the leaf but does not verify the actual ML-DSA-87
receipt in-circuit — v1 does that on-chain against a *named* key via F003, which is
the leak. The production circuit adds:

- **C-P6 receipt validity (STARK-only):** the prover knows an ML-DSA-87 signature
  `σ` valid under the public key whose hash is `pk_receipt_hash`, over the exact
  163-byte receipt transcript (`MilConstants.RECEIPT_MESSAGE_LEN`) for
  `session_cm`, with cumulative-out consistent with `amount`.

C-P6 is a **circuit_version bump**, not a statement change (public inputs are
identical). It ships as `circuit_version = 3` (`CIRCUIT_PROVIDER_CLAIM_V2`) so the
membership-only claim (v2) and the receipt-verifying claim (v3) are independently
pinnable — the anonymity set is strictly stronger once C-P6 is live, because a
claim then proves *possession of a valid receipt*, not merely *registry
membership*. Until C-P6, the receipt is checked off-circuit at the gateway (the
honest v2 boundary).

---

## 3. Determinism is a consensus requirement (SP-04)

F006 runs inside block validation: **every** node must reach the *same*
accept/reject for the *same* `(vk, public_inputs, proof)`, bit-for-bit, on every
platform. This is the same hard requirement as the F003 audit finding H-2. The
verifier therefore MUST:

- use only fixed-width integer / field arithmetic (M31), no floats, no
  `f64`-derived transcript values;
- have **no SIMD-dependent control flow** — a data path may use SIMD, but the
  accept/reject decision must not branch on lane counts or CPU features
  (portable-verify conformance);
- draw all Fiat-Shamir challenges from a **fixed, versioned transcript** hashed
  with keyed BLAKE2b-512 (the chain's canonical hash), so the transcript is
  reproducible and PQ-aligned;
- be **panic-free**: malformed proof bytes / out-of-range field elements / bad
  lengths return `Err`, never unwind (F006 maps `Err → ABI false`).

A cross-platform conformance corpus (x86-64, aarch64) of accept and reject vectors
is a Phase SP-0 exit gate: any divergence is a consensus split, not a bug to patch
later.

---

## 4. The verifier crate boundary

Two new crates, split by trust surface so the heavy prover never enters consensus:

- **`misaka-mil-shield-stark-verify`** (in-consensus, `no_std`-friendly,
  panic-free, deterministic): exposes one function
  `verify_stark(circuit_version, vk, public_inputs, proof) -> Result<(), StarkError>`.
  This is the only new code that runs in block validation. It links into
  `misaka-mil-shield` behind the `StarkVerifier` seam (§5).
- **`misaka-mil-shield-stark-prove`** (client-side only, never in the node): the
  prover, run on the **provider's box** (claims) or the **user's wallet** (spends).
  The witness never leaves the client — this is what makes the payout unlinkable in
  practice, not just on-chain (complements the ADR-0025 U2 2-hop relay, the other
  axis). S-two targets client-side proving specifically.

The verifier and the reference verifier share the frozen statement/borsh types
from `misaka-mil-shield` (no duplication), so the differential test (§7) compiles
one corpus against both.

---

## 5. The one code-diff surface (pinned, and shipped inert now)

Today `proof::verify_shield_proof` hardcodes both proof-system arms. This ADR
refactors the STARK arm into a typed seam so the swap is a single, reviewed change
and the extension point is testable while inert:

```rust
pub trait StarkVerifier {
    fn verify(&self, circuit_version: u16, vk: &Hash64,
              public_inputs: &[u8], proof: &[u8]) -> Result<(), ShieldVerifyError>;
}

/// Inert until the ADR-0033 §SP-0 milestone — byte-identical to today's behavior.
pub struct InertStarkVerifier;
impl StarkVerifier for InertStarkVerifier {
    fn verify(&self, _v: u16, _vk: &Hash64, _pi: &[u8], _p: &[u8])
        -> Result<(), ShieldVerifyError> {
        Err(ShieldVerifyError::ProofSystemNotActivated(PROOF_SYSTEM_STARK))
    }
}

// existing entry point — unchanged signature, delegates to the inert verifier
pub fn verify_shield_proof(bytes: &[u8], pinned: &Hash64)
    -> Result<VerifiedStatement, ShieldVerifyError> {
    verify_shield_proof_with(bytes, pinned, &InertStarkVerifier)
}

// the extensible form: the STARK arm calls the injected verifier
pub fn verify_shield_proof_with<V: StarkVerifier>(
    bytes: &[u8], pinned: &Hash64, stark: &V,
) -> Result<VerifiedStatement, ShieldVerifyError> { /* … STARK arm → stark.verify(…) */ }
```

The production swap = construct `verify_shield_proof` with the real
`misaka-mil-shield-stark-verify::Backend` instead of `InertStarkVerifier`. **No
other file changes.** Because `InertStarkVerifier` returns the exact same error the
current arm returns, all existing tests (including
`proof::tests::stark_system_is_inert_not_accepted`) stay green and F006 stays
byte-identical.

---

## 6. Activation is two-dimensional (both fences must flip)

The pool going **live** and the pool being **private** are separate gates. A live
pool that accepts `PROOF_SYSTEM_REFERENCE` is *sound but not private* (the witness
is on-chain). So activation has two independent fences:

1. **F006 existence fence** — `evm_f006_shielded_verify_activation_daa_score`
   (currently `u64::MAX` on all four presets). Below it the precompile does not
   exist and `0x…F006` is an empty account (byte-identical execution).
2. **Proof-system acceptance policy** — which `proof_system_id` the verifier
   accepts. Today `verify_shield_proof` accepts REFERENCE unconditionally and
   rejects STARK. Production MUST be **STARK-only** (SP-05/SP-09): the policy
   becomes a network parameter with three settings —
   - `ReferenceCappedTestnet` — accept REFERENCE, but only where an escrow/DA cap
     bounds exposure (testnet stepping-stone; the current behavior, made explicit);
   - `StarkOnly` — accept STARK, reject REFERENCE (mainnet / production);
   - `Both` — transition window during a testnet re-genesis, so provers can
     migrate before REFERENCE is turned off.

Rollout mirrors the F003 / BPS re-genesis pattern already in the tree: flip both
fences at a **testnet re-genesis** first (policy `Both`, then `StarkOnly`),
validate, then mainnet. The genesis hash is unaffected (fences are not genesis
inputs), exactly as for F003.

---

## 7. Phasing (consistent with the fenced-milestone convention)

- **SP-0 (hard gate, non-negotiable).** A single proof for each circuit fits under
  32 KiB; the in-consensus verifier is deterministic + portable + panic-free
  (§3); a cross-platform conformance corpus passes. Until met, STARK stays inert
  (as shipped). *This is where the real cryptographic work (BLAKE2b-in-circuit
  cost, recursion for the cap) lives — genuinely months + external audit.*
- **P1 circuit freeze.** This ADR: `SpendStatement` / `ProviderClaimStatement` /
  `domains` / borsh layouts / constraints C-S1..8, C-P1..5 are frozen. C-P6
  (receipt-in-circuit) is specified as `circuit_version = 3`.
- **P2 verifier seam (this change).** Land `StarkVerifier` + `InertStarkVerifier` +
  `verify_shield_proof_with` (inert; behavior unchanged; tests green).
- **P3 backend.** Implement `misaka-mil-shield-stark-verify` +
  `-stark-prove`; select S-two vs Plonky3 by the SP-0 cap benchmark (O-SP-1).
- **P4 differential corpus.** For a shared corpus of `(stmt, wit)`:
  `reference_verify(stmt, wit).is_ok() ⇔ stark_verify(vk, pi(stmt), prove(stmt,
  wit)).is_ok()`, and every reject reason has a reject vector. This equivalence is
  the correctness guarantee of the swap.
- **P5 activation.** vk pinning ceremony (deterministic; no toxic waste) → testnet
  re-genesis (policy `Both` → `StarkOnly`) → audit → mainnet.

---

## 8. Consequences

- **Positive.** The privacy the L2 mechanism already encodes (blind-open +
  set-membership claim + shielded payout) becomes *real* — the witness (which note,
  which provider) leaves the chain. Soundness stays PQ (hash-based, no ceremony).
  The swap is one reviewed function arm; the contracts/precompile/fences never move.
- **Cost / risk.** BLAKE2b-in-circuit is expensive; meeting the 32 KiB cap may
  force hand-written circuits or recursion (O-SP-1). A pairing wrap would be
  cheaper but is prohibited (breaks SP-01/SP-05). The prover is client-side, so
  provider boxes need the proving cost budgeted (ADR-0029 economics).
- **Honest boundary.** This ADR delivers the *contract* and the *seam*. It does
  **not** deliver a prover — that is SP-0, gated and audited. Until then the STARK
  arm is inert and the pool is not activated. The other privacy axis — network-level
  IP unlinkability — is ADR-0025 U2 (SDK 2-hop relay), independent of this ADR.

---

## 9. Open question carried forward (O-SP-1)

zkVM (Risc0 / SP1 / S-two) vs hand-written STARK (Plonky3), decided by whether a
single proof meets the 32 KiB cap with BLAKE2b-in-circuit and PQ-only recursion.
Its own ADR once SP-0 benchmarks land, as ADR-0033 anticipated.
