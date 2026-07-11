# ADR-0037 — Fully-private provider reward flow (which-provider unlinkable, amount hidden)

- **Status:** Proposed (design; inert). Extends ADR-0025 §21, ADR-0033 (shielded pool),
  ADR-0034 (reference→STARK swap), ADR-0035/0036 (STARK backend + DA).
- **Goal (user requirement):** the reward path for MIL distributed-inference must be
  **fully private — nobody, not even through the payout, learns *which* provider executed
  a job**. Not "the on-chain claim event is anonymized" — the *whole* flow.

## 1. Why the claim circuit alone is not enough

The anonymous provider-claim ZK relation (`mil/shield/src/provider.rs`) proves membership
in the provider set + a per-session nullifier + a shielded payout, **without revealing
which** provider. That is necessary but closes only **one** of the deanonymization
surfaces. An adversarial trace of the end-to-end reward flow finds the provider still
identifiable at ~11 points; the dominant ones are NOT touched by the claim circuit:

| # | surface | leaks | closed by claim circuit? |
|---|---|---|---|
| 1 | Registration record (`ProviderRegistry` / `ProviderRegistrationV1`) — operator payout addr, `pkReceiptHash`, ask prices, `region`, `dataPlaneAddr` all public | enumerable anonymity set; per-model filter → often **1** | ❌ |
| 2 | Handshake: `ProviderIdentity{attestation, quote_hash, pk_receipt}` in **cleartext** ServerHello | provider ↔ session to the **requester** | ❌ |
| 3 | Receipt: `SignedReceipt.provider_pk` in the clear, ML-DSA-87-signed | receipt ↔ registration | ❌ |
| 4 | On-chain `ReceiptAnchorV1{provider_id, session_id, tokens…}` | public provider→session→work record | ❌ |
| **5** | **Public `amount: u64`** in `ProviderClaimStatement` + public per-provider **ask table** | **ask-price inversion → re-identify by payout magnitude** | ❌ |
| 6 | On-chain claim event / payout to `operatorOf(providerId)` (v1 `JobEscrow.claim`) | direct naming | ✅ (anonymous path replaces it) |
| 7 | Payout-note value == amount → re-linkage on later unshield | value fingerprint | partial |
| 8 | Timing: `openBlind`→`claimAnon` window + heartbeat / serving liveness | narrows to active provider | ❌ |
| 9 | Network: requester dials public `dataPlaneAddr` → provider **IP** | off-protocol | ❌ |
| 10 | Compute-attestor `ComputeAttestation{attestor_id, bond}` anchored | bond/timing correlate | ❌ |
| 11 | Soundness gap: C-P6 (in-circuit ML-DSA verify) unimplemented → the claim is either **unsound** (membership-only, any registered provider claims any session) or must expose the receipt (#3) | forces re-leak | ❌ |

**Conclusion.** "報酬でも誰が実行したかわからない" is a *system* property. This ADR specifies
the full closure, marking each mechanism **ZK-circuit** / **protocol** / **off-protocol**,
and the ordering. The two highest-leverage ZK items are **#5 (hide the amount)** and **#11
(make the claim sound in-circuit)**; the two highest-leverage protocol items are **#2
(blind handshake)** and **#1 (grow/blind the anonymity set)**.

## 2. ZK-circuit closures

### 2.1 Real-hash provider-claim AIR (gives the claim the build#1–5 treatment)

Today the claim exists only as the transparent reference relation; the STARK arm is inert
(`verify_stark` → `BackendPending` for `CIRCUIT_PROVIDER_CLAIM`). The claim is a **strict
subset of the spend** (measured: 52 BLAKE2b compressions vs the spend's 106), so it reuses
build#1–5 wholesale — `docs/bench/plonky3-shield-air/{compress,merkle}.rs` and the
`recursive_spend.rs` driver — with **no new gadget** below C-P6:

- `claim_pk = H(ADDR, claim_secret)` — 1 compression row (addr, 64 B), like the spend.
- `provider_leaf = H(PROVIDER_LEAF, pk_receipt_hash ‖ claim_pk)` — 128 B, 1 row.
- membership of `provider_leaf` under `provider_set_root` — depth-20 `MerklePathAir`
  (the spend's exact which-note-hiding MUX, one path instead of two).
- `provider_nf = H(PROVIDER_NF, claim_secret ‖ session_cm)` — 128 B, bound to a public nf.
- `cm_payout = commit(payout_note)` — 204 B, 2 rows (the spend's commit gadget).
- `ctx = H(CLAIM_CTX, session_cm ‖ amount ‖ cm_payout ‖ provider_nf)` — 1 row.

Build order mirrors the spend: assemble the schedule, diff-test each digest vs
`kaspa_hashes::blake2b_512_keyed`, prove under hiding-ZK, adversarially review, recurse.
`circuit_version = 2` (`CIRCUIT_PROVIDER_CLAIM`), already wired in the verify front-half's
`decode_statement`.

### 2.2 Hidden amount (closes #5 — the dominant ZK-addressable leak)

**Problem.** `ProviderClaimStatement.amount: u64` is public, and `gross =
ceilDiv(askIn·tokIn,1000)+ceilDiv(askOut·tokOut,1000)` is computed from the provider's
**public registered ask**. Given the public amount and the public per-provider ask table,
an adversary inverts to the small set of providers whose ask yields that magnitude — the
shield's own value-hiding is bypassed *at the claim boundary*.

**Change (new `circuit_version = 4`, "claim-v2"; the frozen v2 layout is not edited
in place — ADR-0034 §7 P1).** Replace the public `amount` with a hidden value:

- Statement: `amount: u64` → `v_claim_cm: Hash64` (a commitment to the claimed value,
  `commit_value(amount, blind)`), plus a **range proof** that `amount ∈ [0, 2^64)` in the
  circuit (the spend's bit-decomposition already gives this for free).
- Relation: prove in-circuit `payout_note.value == amount` AND `v_claim_cm ==
  commit_value(amount, blind)` — `amount` never appears in public inputs.
- Contract: `claimAnon` verifies the escrow's locked value covers the *committed* claim via
  a value-conservation check against a **committed/uniform price**, not the per-provider
  public ask (see 2.3). The `ClaimedAnon` event publishes only `cmPayout` and the
  commitment, never the magnitude.

This is exactly how the spend keeps note values private and publishes only conservation;
the claim must do the same instead of publishing `amount`.

### 2.3 Uniform / committed pricing (removes the ask fingerprint, supports #5)

Even with a hidden amount, if settlement is derived from a **per-provider public ask**, the
committed value is still a provider-specific quantity an adversary can bound. Options,
in increasing privacy:

1. **Uniform protocol price** per `(model_id, token)`: settlement uses a single public
   price for all providers of a model, so the payout magnitude carries no per-provider
   signal. (Simplest; the ADR-0029 economics must permit a uniform clearing price.)
2. **Committed ask**: providers commit `askIn/askOut` (only a commitment on-chain); the
   claim proves `gross` was computed under the committed ask without revealing it. Preserves
   ask diversity but hides it. Heavier circuit.

Recommendation: **uniform price for the anonymity-critical models**, committed ask as a
follow-up. Decouples the fund magnitude from provider identity.

### 2.4 C-P6 — in-circuit ML-DSA-87 receipt verify (closes #11, the soundness piece)

Until the receipt is verified **inside** the proof, the anonymous claim proves only "I am
*some* registered provider with a session nullifier" — any registered provider could claim
any session's escrow (a value-theft soundness hole), OR the receipt is checked off-circuit
against a named key (#3/#4), which re-leaks. C-P6 (`circuit_version = 3`, ADR-0033 §SP-0
O-SP-1) proves "I know a valid ML-DSA-87 (FIPS-204) receipt, under the key whose hash is my
registry leaf, for this session." Cost ~10²–10³× the spend circuit (SHAKE256/Keccak
expansion + NTTs over Z_q + matrix-vector + norm/hint checks) — the genuinely new,
recursion/zkVM-scale gadget. **This is load-bearing: without it the claim is unsound OR
non-private.** It is the single largest remaining circuit build.

## 3. Protocol closures (outside the proof)

- **#2 Blind handshake.** The provider must not send `pk_receipt`/attestation in cleartext.
  Replace the ServerHello identity with a **blinded attestation**: the provider proves (in
  the session-setup handshake or a lightweight ZK) it is a registered provider serving
  `model_id`, without sending its receipt key. The requester learns "a valid provider for
  my model", not which one. This is the hardest protocol change (the requester needs
  *some* assurance the server is legitimate); a group-signature / ring-attestation over the
  provider set is the natural primitive.
- **#3 Receipt without provider naming.** `SignedReceipt` must not carry `provider_pk`.
  Sign receipts under a **per-session key** derived from `claim_secret`, and bind that key
  to the registry leaf inside the claim proof (C-P6). The receipt then names a session, not
  a provider.
- **#4 Suppress the on-chain receipt anchor** on the anonymous path (it exists for the v1
  named flow); disputes use a ZK dispute proof, not a public anchor.
- **#1 Grow / blind the anonymity set.** The set is bounded by *registered* providers
  (v0 permissioned whitelist → single-digit). Mitigations: permissionless registration
  with a stake bond; **decoy leaves** so the set size is not the live-provider count;
  per-model sets large enough that model-filtering does not collapse to 1 (or prove
  membership in the *union* set, hiding the model too).
- **#8 Timing.** Batch/settle claims on a fixed cadence (an epoch settlement window) so the
  open→claim timing does not pinpoint the active provider; decouple heartbeat from claim.
- **#7 Denomination obfuscation.** Pay into the pool in **fixed denominations** (or split
  into standard notes) so the deposit and any later unshield carry no distinctive magnitude
  that re-links to the claim.

## 4. Off-protocol

- **#9 Network IP.** The requester dialing `dataPlaneAddr` exposes the provider IP,
  regardless of any proof. Only a **relay / mixnet** (the off-protocol SDK 2-hop relay
  already noted in `mil-shield-stark-prove`) hides it; document it as a deployment
  requirement, not a consensus mechanism.
- **#10 Compute-attestor correlation.** If a provider also runs the ADR-0024 attestor, its
  bond + attestor_id + timing correlate. Domain-separate the keys (already done) and, for
  full unlinkability, prove attestor liveness anonymously too (a separate set-membership) —
  or accept the correlation as a documented residual.

## 5. What this achieves, and the honest residual

With 2.1–2.4 + 3, the **on-chain and payment graph** names no provider: membership hides
which, the hidden amount + uniform price removes the magnitude fingerprint, C-P6 makes it
sound without a named receipt, and denomination obfuscation stops re-linkage. The
**requester** still learns it talked to *a* provider (#2/#9 are the hardest — a colluding
or Sybil requester + network observation can deanonymize outside any proof); closing those
fully needs the blind handshake + relay, which are protocol/deployment, not consensus. So:

- **Fully private against on-chain / third-party observers:** achievable with this ADR's ZK
  + protocol changes.
- **Fully private against the counterparty (requester):** requires the blind handshake +
  network relay; strong but not absolute (a determined colluding requester correlates).

This is the honest ceiling — the same one every private-service system faces (the
counterparty you transact with learns *something*). This ADR closes every surface the
protocol controls.

## 6. Ordering & status

1. **Real-hash claim AIR (2.1)** — build now, reusing build#1–5 (a subset of the spend).
   Gives the existing v2 relation the STARK treatment; inert behind the same fence.
2. **Hidden amount + uniform price (2.2/2.3)** — `circuit_version = 4`, statement change +
   contract change; the dominant ZK privacy win. Needs an economics sign-off (ADR-0029).
3. **C-P6 in-circuit ML-DSA verify (2.4)** — the soundness milestone; largest build.
4. **Blind handshake + receipt-without-naming (#2/#3)** — protocol; unblocks true
   counterparty privacy.
5. **Set growth, timing, denominations, relay** — hardening.

All inert until activation (the F006 fence + acceptance policy, ADR-0034 §6). Nothing here
changes a live network; this is the design that makes the reward flow fully private when
the shielded pool activates.
