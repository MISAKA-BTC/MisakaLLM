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

#### 2.3.1 Resolving the ADR-0029 economics tension (B2 blocker)

ADR-0029 prices per-provider (D4: each provider sets a heterogeneous `ask_floor` from its
own power tariff + CAPEX + stake cost; D5: USD-indexed, FSL-repriced). A flat uniform
price flattens those floors, so **B2 requires an ADR-0029 sign-off** — it is not
code-compatible out of the box. The resolution that preserves the D4 intent *and* removes
the fingerprint is the **committed-ask** path (option 2), not a flat price:

- Each provider commits `askCm = H(askIn ‖ askOut ‖ blind)` on registration (only the
  commitment is public; the ADR-0029 per-provider floor is preserved — the provider still
  sets its own ask, it is just hidden).
- The claim proves in-circuit: `gross = ⌈askIn·tokIn/1000⌉ + ⌈askOut·tokOut/1000⌉`,
  `providerWei = gross·0.88`, `v_claim_cm = commit_value(providerWei, blind)`, and
  `askCm = H(askIn ‖ askOut ‖ askBlind)` — i.e. the settled value is correctly priced
  under *the provider's own committed ask*, without revealing the ask or the amount. Token
  counts `tokIn/tokOut` are bound to the session (committed, not public) so they don't leak
  either.
- The escrow debits `gross` against `locked` via a range/≤ check on the committed value
  (a small in-circuit comparison), never a public magnitude.

This keeps ADR-0029's per-provider economics **entirely intact** (heterogeneous asks, USD
indexing, floors) while making both the ask and the settled amount unobservable — so the
economics sign-off is "adopt committed-ask registration", not "flatten to a uniform
price". The uniform-price option remains available for models where ask diversity is not
needed. **This is the recommended B2 resolution; it needs the ADR-0029 amendment + the
in-circuit multiply/compare gadget (a modest extension of build#7's value-commit row).**

#### 2.3.2 Contract change (B2, inert behind the F006 fence)

The whole `MilShieldedEscrow` already settles through the inert F006 fence, so the change
is inert until activation. Minimal diff (recon-confirmed): (1) storage + `onlyOwner` setter
for the pinned pricing parameter (`uniformPrice` per model, or the committed-ask verifier
key), mirroring `setProviderSetRoot`; (2) `ClaimPublic.amount: uint64` → `bytes v_claim_cm`
(64 B) + a length check; (3) delete the public split-equality (`pub.amount·SCALE !=
providerWei` SplitMismatch) — with a hidden amount the split binding moves in-circuit;
(4) compute `grossWei` from the pinned price × session token counts (or verify the
committed-ask gross in-circuit) instead of the unconstrained caller `grossSompi`, keeping
the `Overdraw` (`gross ≤ locked`) check and the 88/5/7 split; (5) bump the envelope circuit
id to `CIRCUIT_PROVIDER_CLAIM_V2 = 4` (do not edit the frozen v2 layout in place, ADR-0034
§7 P1). The `ClaimedAnon` event drops the magnitude. The forge test
`test_claimAnon_split_binding_enforced` is rewritten for v4 (no public magnitude to
mismatch; the plumbing test asserts the priced debit ≤ locked + `cmPayout` deposited +
event carries no magnitude — amount-hiding soundness is proven by the AIR, not the mock).

**Status (landed inert).** Item (1) is now in `MilShieldedEscrow`: the uniform-price half
(`uniformPricePer1k` + `setUniformPrice` + `snapshotPrice`) plus the hidden-amount claim
(`claimAnonV2`, `CIRCUIT_PROVIDER_CLAIM_V2 = 4`) shipped earlier; the committed-ask half of
the §2.3.1 resolution now ships too — `askCommitmentRoot` (64B keyed-BLAKE2b Merkle root
over per-provider `askCm` leaves) with the `onlyOwner` `setAskCommitmentRoot` setter
(64B-or-empty length gate, mirroring `setProviderSetRoot`) and `snapshotAskRoot` frozen at
`openBlind` (M-04 rotation safety). Because the root is a *set* commitment, no per-provider
`askCm` is ever a public per-identity value, so the on-chain surface leaks nothing; the
claim proves leaf-membership + gross-under-committed-ask entirely in-circuit. This is inert
staging (forge `test_B2_setAskCommitmentRoot_owner_and_length` + the extended
`test_M04_open_snapshots_provider_set`, 68/68). What remains for B2 is **not** on-chain: it
is (a) the ADR-0029 amendment to adopt the committed-ask model (economic sign-off), and (b)
the V3 claim path (`circuit_version = 5`) that binds `snapshotAskRoot` and its
multiply/compare gadget — a modest extension of build#7's value-commit row, gated on the
committed-ask circuit (build#8). Pinning a root before those exist changes nothing (the
whole contract is behind the F006 fence).

#### 2.3.3 Rounding & split semantics (NORMATIVE — audit 2026-07-11 C-01/C-02 closure)

The v2 split's integer semantics are frozen, in one place, as executable Rust:
`mil/shield/src/economics.rs::claim_v2_split` — operation-for-operation identical to
`claimAnonV2` (uint256 intermediates, floor division, checked arithmetic):
`grossSompi = (snapshotPrice * (tokIn + tokOut)) / 1000` (floor); `grossWei =
grossSompi * NATIVE_SCALE`; `providerWei = grossWei * 88 / 100`; **revert
`SplitMismatch` unless `providerWei % NATIVE_SCALE == 0`** (equivalent to `grossSompi
% 25 == 0`); `providerShareSompi = uint64(providerWei / NATIVE_SCALE)`; `burnWei =
grossWei * 5 / 100`; `poolWei = grossWei - providerWei - burnWei`. Once the gate
passes the 88/5/7 split is EXACT (no rounding loss); the only lossy steps are the
`/1000` gross floor and the (supply-unreachable) `uint64` cast. The revert-not-floor
choice is deliberate: flooring would strand sub-sompi dust; the gate keeps every
settled claim exact. **Consequence (liveness, normative for the pricing layer):** a
gross that is not a multiple of 25 sompi can NEVER settle — gateways/provider SDKs
MUST quantize token totals so `grossSompi % 25 == 0` (the section-3 denomination
ladder satisfies this whenever `price * denom / 1000` is a multiple of 25). Cross-
language drift is pinned by the shared vector file
`contracts/mil/test/vectors/claim_v2_split_vectors.json`, consumed by BOTH the Rust
spec test and forge (`MilClaimV2Split.t.sol`) against the live `claimAnonV2` —
boundaries: zero, the `/1000` floors, `gross % 25` in {1, 2, 24}, u64-max-adjacent
gross, the uint64-cast beyond supply, absolute-max u64 inputs.

**Statement + circuit binding (C-01, closed).** The v2 statement layout is frozen by
the schema manifest `mil/shield/src/statement_schema.rs`
(`PROVIDER_CLAIM_V2_STATEMENT_SCHEMA`, 392 B): `provider_set_root(64) || session_cm(64)
|| v_claim_cm(64) || provider_nf(64) || cm_payout(64) || le64(provider_share_sompi) ||
ctx(64)`, byte-identical to `_borshClaimStatementV2` (pinned by cross-language byte
tests on both sides). The relation `provider.rs::verify_reference_v2` and the claim-v2
AIR (`docs/bench/plonky3-shield-air/claim_v2.rs`, `PI_SHARE` public input constrained
bit-for-bit to the committed amount) both enforce `v_claim_cm ==
commit(provider_share_sompi)` and `payout_note.value == provider_share_sompi`, so a
proof can neither fund an undercollateralized note nor underpay the provider; payout
+/-1 mutations are rejected at every layer (Rust relation, node decode/binding, forge
statement bytes, AIR negatives `--share-plus`/`--share-minus`/`--swap-fields`).
Making the share an explicit public input costs no privacy under uniform pricing
(M-08: gross is publicly derivable from public token counts x snapshot price).


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

### 3.1 Execute-ready priority (B3)

Ordered by (leverage × tractability), so the protocol work is scheduled, not amorphous:

1. **Decoy set + set growth (#1) — most tractable, high leverage. ✅ LANDED (reference).**
   The which-provider circuit (build#6/#7) already hides the index; its anonymity is capped
   only by the set size. This is a *reference-level* change, no new circuit: seed the
   provider-set tree with **decoy leaves** (`provider_leaf(H(decoy_i), addr(decoy_i))` for
   unspendable secrets) so `set_size` ≫ live-provider count, and switch registration to
   permissionless-with-stake-bond. The claim proves membership among {real ∪ decoy}; a
   decoy cannot claim (no valid receipt under C-P6, and the escrow's nullifier/receipt
   gate rejects it). *Delivered: `decoy_set_enlarges_the_anonymity_set` in
   `anon_provider_claim_e2e.rs` — a real claim verifies against a {3 real ∪ 200 decoy} root
   (set ≥ 128) with the claiming leaf/index absent from the public statement.*
2. **Timing batch (#8) — protocol, tractable. ✅ LANDED (reference).** Settle `claimAnon`
   only at fixed epoch boundaries (a settlement window), decoupled from `heartbeat`/serving
   liveness, so the open→claim delay does not pinpoint the active provider. *Delivered:
   `timing_batching_breaks_arrival_order_linkage` pins the relayer invariant — claims settle
   in a canonical `provider_nf`-sorted order, so two arrival permutations settle
   bit-identically and the batch reorders vs arrival (the within-epoch timing channel is
   closed). The epoch-gated on-chain fence + batched-settlement runbook remain deployment
   work.*
3. **Denomination obfuscation (#7) — reference-level. ✅ LANDED (reference).** Quantize the
   **public token counts** driving `claimAnonV2`'s uniform-price gross UP to a fixed
   denomination ladder, so a whole range of true usages shares one public denomination (and
   the 88% payout note magnitude is likewise laddered). *Delivered:
   `denomination_bucketing_collapses_token_count_fingerprint` — 64 distinct usages collapse
   to ≤4 public denominations (busiest bucket ≥8), never underbilling, monotone; closes the
   count fingerprint that B2's uniform pricing alone leaves open.*
4. **Receipt without provider naming (#3) — protocol, harder. ⏳ OFF-CIRCUIT HALF LANDED
   (reference); circuit binding pends B1.** Sign receipts under a **per-session key** derived
   from `claim_secret` (not the registered `pk_receipt`), and bind that key to the registry
   leaf inside the claim proof (C-P6). *Delivered: the per-session key derivation
   `session_receipt_key(claim_secret, session_cm) = H_k("provider-session-rk", …)`
   (`mil/shield/src/provider.rs`) + the reference test
   `receipt_key_names_a_session_not_a_provider` in `anon_provider_claim_e2e.rs` — proves the key
   is deterministic, per-session-UNLINKABLE (one provider across two sessions → distinct keys),
   provider-NON-naming (no cleartext identifier), and domain-separated from the nullifier, yet
   bound to the same `claim_secret` whose `claim_pk = shielded_address(claim_secret)` sits in the
   registry leaf.* **Remaining (the circuit binding):** the C-P6 claim proof (B1) must prove
   "this session key was derived from the secret behind my registered leaf" — needs the in-circuit
   ML-DSA verify (B1) in place, so it is the last B3 item and is gated on B1.
5. **Blind handshake (#2) — ✅ LANDED (reference), reusing the membership primitive.** The
   provider must assure the requester it is a legitimate provider *for this model* without
   sending `pk_receipt`/attestation in cleartext. The key realization: this is the SAME
   set-membership relation the anonymous claim (build#6/#7) already proves — applied to a
   requester CHALLENGE instead of a payout. The provider proves "membership in the model's
   provider set ∧ knowledge of `claim_secret` ∧ binding to your challenge" via the deployed
   `provider_leaf`/membership machinery; the requester learns "a valid provider for my model
   answered", not which one — so no separate group-signature primitive is needed for the
   set-membership half. *Delivered: `blind_handshake_proves_membership_without_naming_provider`
   in `anon_provider_claim_e2e.rs` — a registered provider answers a challenge with leaf/pk
   hidden; the per-challenge handshake nullifier `H(claim_secret ‖ challenge)` is fresh so two
   responses are unlinkable; an unregistered impostor is rejected.* **Residual (the §5
   counterparty ceiling):** wrapping this membership proof in a transport where `pk_receipt`
   never transits, and hiding the network IP, remain deployment/relay concerns (§4 #9), and a
   colluding requester who correlates timing/IP is still outside what the proof closes.

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
