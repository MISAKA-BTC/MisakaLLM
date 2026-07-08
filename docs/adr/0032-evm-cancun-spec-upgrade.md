# ADR-0032: MISAKA EVM Cancun Spec Upgrade (opcodes-only, EIP-4844/7702 excluded)

## Status

**Proposed / Draft — awaiting sign-off. NOT implemented.**

Supersedes the `SpecId::SHANGHAI` pin frozen in [ADR-0020](0020-selected-parent-evm-lane.md) "Frozen
parameters (P0)" and the Audit-C1 spec-bump guard at `kaspa-evm/src/lib.rs:44-57`. Interacts with the
PQ-only invariant ([ADR-0019](0019-mldsa87-migration.md)) only via the `evm` cargo feature (the
secp256k1 domain is unchanged — this ADR touches the EVM interpreter spec, not the signature domain).

This is a **hard fork** delivered as a fenced re-genesis cutover, following the exact activation
pattern that landed the EVM lane itself on testnet (ADR-0020: `evm_activation_daa_score = 0` via a
re-genesis, genesis hash unchanged, `EVM_HEADER_VERSION` version-isolating old nodes).

Phase 1 (the consensus-neutral diagnostic) is separable and MAY ship independently ahead of this ADR;
it is documented here for completeness but requires no fork.

---

## Context

The EVM lane pins a single execution spec:

```rust
// kaspa-evm/src/lib.rs:44
pub const EVM_SPEC_ID: SpecId = SpecId::SHANGHAI;
```

This constant feeds **every** revm builder uniformly — the block executor (`executor.rs:286`), the
`eth_call`/`estimateGas` simulator (`sim.rs:95`), the flat state backend (`flat_backend.rs:311`), and
the tracer (`trace.rs:292/459`) — and is guarded by a compile-time `const _: assert!` plus the
`pq-ci-guard`, so a silent bump is a build error (`lib.rs:54-57`).

**The problem.** `solc` defaults `evmVersion=cancun` since **v0.8.25 (2024-03-14)**. Contracts built
with a default modern toolchain (Foundry/Hardhat on 0.8.25+) therefore emit **Cancun-gated opcodes**
in routine code paths:

| Opcode | EIP | Emitted by |
|---|---|---|
| `MCOPY` (0x5e) | EIP-5656 | dynamic-type ABI encode/decode, memory-copy codegen — e.g. **any `string`/`bytes` return**, `abi.encode` of dynamic types |
| `TLOAD`/`TSTORE` (0x5c/0x5d) | EIP-1153 | transient storage — e.g. OpenZeppelin `ReentrancyGuardTransient` |

At `SHANGHAI`, revm gates these behind `check!(CANCUN)`, which raises
`InstructionResult::NotActivated`. In the **committed** path this becomes a status-0 (class-4)
receipt; in the **simulate** path (`sim.rs:127`) the `HaltReason` is discarded via `..` and the
output forced empty, so `eth_call` returns a bare **`execution reverted: 0x`** — which masquerades as
a Solidity `require()` revert and actively misleads developers into diagnosing an "ABI bug".

**Observed symptom (report, 2026-07-08).** `string`-returning view functions (ERC20 `name()`/
`symbol()`, ERC721 `tokenURI()`, plain `string public` getters) revert `0x`, while `uint256`/`address`
getters work — the exact signature of "dynamic-return path hits `MCOPY`, single-word return does not".

**Two distinct problems, two distinct fixes.** (1) The misleading diagnostic is a recurring DX
footgun that a message fix removes but does **not** make Cancun bytecode run. (2) Only a spec bump
makes Cancun bytecode run, and the toolchain default makes that pressure structural, not incidental.
Telling every developer to pin `evmVersion=shanghai` is a permanent support burden fighting the
default. Hence a **phased-both** decision.

---

## Decision

Bump the EVM interpreter spec **Shanghai → Cancun**, scoped to **opcodes/semantics only**, with
EIP-4844 blob transactions and EIP-7702 set-code transactions **deliberately excluded**, delivered as
a **fenced, `evm_cancun_activation_daa_score`-gated re-genesis cutover**. Ship the consensus-neutral
diagnostic (Phase 1) first.

### What is IN scope

- **EIP-5656 `MCOPY`** — purely additive opcode.
- **EIP-1153 `TLOAD`/`TSTORE`** (transient storage) — purely additive opcodes.
- **EIP-6780** (SELFDESTRUCT only destroys when created in the same tx) — the **one true semantics
  change**; analysed below.
- **`BLOBHASH` (0x49) / `BLOBBASEFEE` (0x4a)** opcodes become valid. With blobs excluded they read
  from a **deterministic constant** blob env: `BLOBHASH` over an empty blob set returns 0,
  `BLOBBASEFEE` returns the minimum (from `blob_excess_gas_and_price = 0`). Both deterministic across
  nodes.

### What is OUT of scope (frozen exclusions)

- **EIP-4844 blob transactions (tx type `0x03`).** MISAKA has **no beacon/KZG/data-availability
  plane**. The tx-type allowlist `is_supported_tx_type` (`tx.rs:40-42`, `Legacy`/`Eip2930`/`Eip1559`)
  **stays closed**, making 4844 a classification **no-op**. This is what keeps the bump "additive
  opcodes" rather than "new consensus surface". Relaxing the allowlist is a **separate** consensus
  decision (a blob-gas market + versioned-hash commitment + DA plane) and is out of scope here.
- **EIP-7702 set-code / account-abstraction (tx type `0x04`).** Deferred; rejected at the allowlist
  today, stays rejected.

### The load-bearing technical gate (verified)

revm 14 **requires `block.blob_excess_gas_and_price = Some(..)` whenever `SpecId::CANCUN` is enabled**
(`validate_block_env` → `InvalidHeader::ExcessBlobGasNotSet`). MISAKA's env derivation
(`env.rs::derive_env` + `executor.rs:288-299 modify_block_env`, and the sim/flat_backend/trace builder
sites) sets `number/timestamp/coinbase/gas_limit/basefee/difficulty/prevrandao` but **never sets any
blob field** (verified: `grep blob_excess` over `kaspa-evm/src` = **0 hits**). `InvalidHeader` maps to
`EVMError::Header`, which hits the executor's hard `Err(other) =>` arm (`executor.rs:397/522`) →
`EvmExecError::InvalidTx` → **every block fails execution**.

> **A naive `EVM_SPEC_ID = CANCUN` flip bricks the lane.** The deterministic blob-env field MUST land
> (Phase 2) before the spec can be Cancun anywhere.

### Spec selection becomes fence-gated (code-structure change)

`EVM_SPEC_ID` can no longer be a single `const`. It becomes a deterministic selector on the executing
block's DAA score:

```rust
// replaces the const at lib.rs:44
pub fn evm_spec_for(daa_score: u64, params: &Params) -> SpecId {
    if daa_score >= params.evm_cancun_activation_daa_score { SpecId::CANCUN } else { SpecId::SHANGHAI }
}
```

Every builder site (`executor.rs:286`, `sim.rs:95`, `flat_backend.rs:311`, `trace.rs:292/459`,
`lib.rs:81/141`) consumes `evm_spec_for(block.daa_score, params)` instead of the const. The
`const _: assert!` guard (`lib.rs:54-57`) and `pq-ci-guard` are rewritten to assert the **fenced
selector's invariants** (pre-fence ⇒ Shanghai, post-fence ⇒ Cancun) rather than a frozen single id.

---

## EIP-6780 supply-conservation analysis (why the audit is bounded)

The spec-bump guard names EIP-6780 as load-bearing because the F002 (`MISAKA_WITHDRAW`) precompile and
the supply invariant were audited at Shanghai. The key finding: **the F002 burn is driven by withdraw
LOGS, not by F002's balance.**

- A withdraw is intercepted at the call handler (`withdraw.rs:134-189`), which transfers caller→F002
  and journals a LOG (`withdraw.rs:174,180`).
- Post-tx, the executor sums the **committed withdraw logs** into `withdrawn_wei` and burns exactly
  that out of F002 via `burn_balance` (`executor.rs:368-384`, v2 twin at 507), with a `checked_sub`
  that fails closed on underflow (`executor.rs:701-705`).
- The Shanghai residual (`executor.rs:24-31`): a `SELFDESTRUCT` with F002 as beneficiary force-credits
  F002 **outside** the intercept → no log, no `WithdrawOp`, no burn → wei stranded but **supply-
  neutral** (it never leaves `evm_total_native_balance`; F002 is deliberately never swept, because a
  sweep would be a new consensus rule). Pinned by `selfdestruct_to_f002_strands_value_supply_neutrally`
  (`executor.rs:1726-1787`).

Because burn is log-driven, a force-sent residual can only make F002's balance **larger** than the
burn sum — it **cannot** underflow the burn. **This decoupling holds identically under EIP-6780**, so
supply conservation does **not** break. EIP-6780 only makes the residual **rarer** (SELFDESTRUCT truly
destroys + force-sends only when the contract was created in the same tx) — but the residual test's
init-code `PUSH20 <f002>; SELFDESTRUCT` self-destructs *during creation*, so it **still** force-sends
post-Cancun. The residual class survives.

**What is owed** is therefore a re-decision + documentation, not a rewrite:
1. Re-affirm the **strand-and-don't-sweep** policy in writing (or, if reversed, add a sweep as a
   fenced-inert consensus rule).
2. Add a new test for the **not-created-in-same-tx** SELFDESTRUCT case (which EIP-6780 turns into a
   plain balance transfer, not a destroy).
3. Reword the now-stale "pre-EIP-6780" assertions in `executor.rs:24-31` / `lib.rs:47-48` / test docs.

---

## Skip-class boundary analysis (why the corpus is unaffected)

The skip↔revert boundary is drawn by **one** thing: revm returning `Err(EVMError::Transaction(_))`
(pre-execution invalid → deterministic **class-2 skip**: no receipt, no gas, no nonce change) vs
`Ok(ExecutionResult)` (executed → committed nonce+fee+receipt). Within `Ok`, `Success`/`Revert`/`Halt`
are flattened to `receipt.succeeded = result.is_success()` (`executor.rs:749`) — `Revert` and every
`Halt` reason alike become status-0 class-4 receipts.

Cancun does **not** move this line for the existing `Legacy`/`Eip2930`/`Eip1559` corpus:

- `MCOPY`/`TLOAD`/`TSTORE` today `Halt(NotActivated)` = committed class-4; under Cancun they
  **succeed**. That is a `Success`↔`Halt` shift for those specific contracts — **deterministic across
  nodes**, not a split in itself — but it changes `receipts_root` for any deployed contract that
  currently halts on those opcodes (see Open Questions).
- The revm `HaltReason` variant set is identical Shanghai vs Cancun; no new *skip* reasons appear
  **as long as the blob allowlist stays closed**. (If the allowlist were relaxed — out of scope — the
  Cancun blob `InvalidTransaction` reasons would funnel into the spec-agnostic class-2 catch-all at
  `executor.rs:393/515` and expand the skip set. This is exactly why the allowlist stays closed.)

**What is owed:** re-run the skip-class + supply-conservation suites at Cancun and demonstrate no
`state_root`/`receipts_root`/`skipped_tx_count` change for the existing corpus (Cancun intrinsic-gas/
access-list rules could in principle nudge the class-2 upfront-funds boundary — must be shown, not
assumed).

---

## Phased plan

| Phase | Content | Effort | Consensus impact |
|---|---|---|---|
| **1 — diagnostic (ship now)** | Capture the `HaltReason` discarded at `sim.rs:127` (`..`); distinguish `NotActivated` ("opcode requires a newer fork — recompile with `evmVersion=shanghai` or wait for the Cancun fork") from `OutOfGas`/`Revert` in the `eth_call`/`estimateGas` RPC error (code 3, free-form message). Add a sim-path unit test that an `MCOPY`/`TLOAD` probe yields the `NotActivated` diagnostic, not bare `0x`. | Low (~1d) | **None.** The executor never imports `sim`/`EthCallOutcome`; read-only RPC display, wire format unchanged. |
| **2 — env unbrick (no activation)** | Set a **deterministic** `blob_excess_gas_and_price` (blobs excluded ⇒ pin to `0`) in `derive_env` + every builder site (`executor.rs`, `sim.rs`, `flat_backend.rs`, `trace.rs`). Test that all paths set it identically. | Low–Med (~1–2d) | **None** while spec stays Shanghai (revm ignores the field pre-Cancun). Load-bearing only from Phase 4. |
| **3 — re-audit (Cancun feature-flag, no live activation)** | Run the **skip-class suite** (`class2_skips_leave_no_trace`, `class5_prefix_take_is_strict`, `gas_pool_v2_class2_skip_consumes_no_pool`, `gas_pool_v2_in_block_duplicate_is_class3`, `withdraw_cap_skips_overflow_and_preserves_state`) and **supply-conservation suite** (`f002_withdraw_emits_op_and_burns_from_evm`, `priority_fee_routes_...`, `deposit_claim_tip_...`, `deposit_credit_and_accepted_...`, `selfdestruct_to_f002_strands_value_supply_neutrally`) at `CANCUN`. Reword stale "pre-EIP-6780" assertions; ADD the not-created-in-same-tx SELFDESTRUCT test; ADD MCOPY/TLOAD/TSTORE execute-not-halt tests; write the F002 residual-policy note. Run consensus `--features evm` integration. | Med (~3–5d) | **None yet** — audit-only. This is the GREEN gate for Phase 4. |
| **4 — hard fork (fenced re-genesis)** | Replace the `EVM_SPEC_ID` const with `evm_spec_for(daa_score, params)`; add `evm_cancun_activation_daa_score` (u64::MAX inert; testnet re-genesis sets `0`); keep `is_supported_tx_type` closed (exclude 4844/7702); update the `const _: assert!` + `pq-ci-guard` + module docs in the SAME change; gate the cutover behind the fence as a re-genesis (never a live in-place flip); freeze `commitment_root` over a Cancun execution via consensus `--features evm`. | Med (~2–3d + testnet cutover) | **HARD FORK.** Changes all execution paths uniformly; `commitment_root` differs under Cancun; `evm_cancun_activation`-gated re-genesis, matched by the CI-guard frozen id. |

---

## Frozen parameters (proposed)

```
evm_cancun_activation_daa_score:
  MAINNET  = u64::MAX      (inert)
  TESTNET  = 0             (Cancun-active from a fresh re-genesis; genesis hash re-derived)
  DEVNET   = 0             (Cancun-active)
  SIMNET   = u64::MAX      (inert)

blob_excess_gas_and_price = BlobExcessGasAndPrice::new(0)   (deterministic; blobs excluded)
tx-type allowlist         = { Legacy, Eip2930, Eip1559 }    (unchanged — 4844/7702 excluded)
```

Rationale for `TESTNET = 0` via re-genesis (not a mid-chain DAA fence): this mirrors how
`evm_activation_daa_score = 0` shipped the EVM lane itself (ADR-0020) — a clean re-genesis avoids a
dual-spec history on the running testnet and lets the cutover ride an already-planned re-genesis
(BPS-25 Stage A / pruned-IBD) to save a mesh roll. A mid-chain DAA fence (`evm_spec_for` returning
different specs across a score boundary on one chain) is fully supported by the selector and is the
intended path for **mainnet**, where re-genesis is not an option.

---

## Blockers / sign-off checklist (must be GREEN before Phase 4 freeze)

- [ ] `blob_excess_gas_and_price` set deterministically at every builder site (Phase 2). *Verified
      today: 0 occurrences in `kaspa-evm`.*
- [ ] EIP-4844 allowlist policy frozen **closed** (`tx.rs:40-42` unchanged). Do NOT relax without a
      dedicated skip-class re-audit.
- [ ] F002 EIP-6780 residual policy re-decided in writing (strand-and-don't-sweep re-affirmed; burn is
      log-driven so supply holds) + not-created-in-same-tx SELFDESTRUCT test added.
- [ ] Supply-conservation suite re-run GREEN at `CANCUN`.
- [ ] Skip-class suite re-run GREEN at `CANCUN`; no `state_root`/`receipts_root`/`skipped_tx_count`
      change for the existing legacy/2930/1559 corpus.
- [ ] MCOPY/TLOAD/TSTORE execute-not-halt coverage added; no previously-`Success` tx flips to `Halt`
      (or vice versa) for the deployed corpus.
- [ ] `const _: assert!` (`lib.rs:54-57`) + `pq-ci-guard` rewritten for the fenced selector, landed in
      the SAME change as the bump.
- [ ] Consensus `--features evm` integration GREEN; `commitment_root` over a Cancun execution
      intentionally frozen before activation.

---

## Consequences

**Positive.** Cancun bytecode (the modern-toolchain default) executes: `string`/`bytes`/dynamic
returns, `abi.encode` of dynamic types, transient-storage reentrancy guards, and Uniswap-v4-class
EIP-1153 contracts all run. Removes the structural DX burden of fighting `evmVersion=cancun`.

**Negative / risk.** It is a hard fork; `commitment_root` changes under Cancun and must be intentionally
frozen. On testnet it needs a coordinated re-genesis/mesh-roll (operational risk, not code risk —
correctness is retired by Phases 2–3). Deployed testnet contracts that today *halt* on Cancun opcodes
will *succeed* after the fork — a behavior change for those specific contracts, to be communicated as
such (see Open Questions).

**Neutral.** Blobs/7702 excluded ⇒ no new tx type, no DA plane, no beacon predeploy — the attack/
consensus surface added is limited to the additive opcode set plus the EIP-6780 semantics change,
both bounded and audited.

---

## Alternatives considered

1. **Message-only (diagnostic, no fork).** Rejected as the *sole* fix: it is correct and ships now
   (Phase 1), but Cancun bytecode still cannot run — devs must keep recompiling `evmVersion=shanghai`.
   Mitigation, not resolution. Retained as Phase 1.
2. **Stay Shanghai + document the flag.** Rejected: `evmVersion=cancun` is the toolchain default, so
   this is a permanent, per-project, easy-to-forget support burden, not a one-time note.
3. **Full Cancun including EIP-4844 blobs.** Rejected: MISAKA has no beacon/KZG/DA plane; admitting
   blob txs adds a genuine new consensus surface (blob-gas market, versioned-hash commitment) with no
   MISAKA analogue, and expands the class-2 skip set. Excluding blobs keeps the bump additive.
4. **Hard-fork now (naive `const = CANCUN`).** Rejected: bricks the lane (missing
   `blob_excess_gas_and_price` fails every block) and skips the owed re-audits.

---

## Open questions

- Exact derivation for `blob_excess_gas_and_price` — constant `0` (recommended, blobs excluded) vs
  parent-EVM-header-derived. Either is fine if identical on all nodes; choose and test-lock before
  Phase 4.
- Cutover timing relative to other pending fenced changes (BPS-25 Stage A, pruned-IBD) — ride an
  already-planned re-genesis to avoid an extra mesh roll?
- Do any already-deployed testnet contracts hit MCOPY/transient-storage paths such that their
  `receipts_root` changes at the fork (halting → succeeding)? If so, communicate the cutover as
  behavior-changing for those specific contracts, not purely additive.
- EIP-7702 (set-code) — evaluate in a later pass or explicitly leave deferred alongside 4844.

---

## References

- [ADR-0019](0019-mldsa87-migration.md) — PQ-only invariant / secp isolation (`evm` feature).
- [ADR-0020](0020-selected-parent-evm-lane.md) — EVM lane, `evm_activation_daa_score` fence + re-genesis
  cutover pattern this ADR follows; Frozen-parameters P0 where the Shanghai pin originates.
- [ADR-0022](0022-pruned-ibd-evm-overlay-snapshot.md) — pruned-IBD / EVM overlay (co-scheduling
  candidate for the re-genesis).
- `kaspa-evm/src/lib.rs:44-57` (spec pin + C1 guard), `sim.rs:126-127` (Halt→empty output),
  `executor.rs:24-31/368-384/701-705/739-749` (F002 burn, receipt flatten), `withdraw.rs:134-189`
  (F002 intercept), `tx.rs:40-42` (tx-type allowlist), `env.rs` (block-env derivation, no blob field).
