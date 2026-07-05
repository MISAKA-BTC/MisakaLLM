# MISAKA Inference Lane (MIL) — v1 EVM contracts

The v1 (EVM-lane) settlement layer for the MISAKA Inference Lane, per
`MIL-design-v0.3.md` §8.2 / §8.3 / §19. Self-contained Solidity (forge-std only
in tests), Shanghai / solc 0.8.28, reproducible bytecode.

## Contracts

| Contract | Responsibility | Design |
|---|---|---|
| `ProviderRegistry` | Provider onboarding: quote hash, enclave key hashes, ask, tier, SLA, heartbeat, attestation refresh | §8.2 / §2.3 |
| `ModelRegistry` | Model entries + the single canonical `MIL-Core` pointer | §7.1 / §17.2 |
| `StakeManager` | `bond` / `requestUnbond` (7-day delay) / `withdraw` / `slash` (50/50 challenger/burn) | §5.5 |
| `RewardPool` | Bootstrap Fund receiver + epoch subsidy distribution (5% share cap) + validator/treasury fee sinks | §5.2b / §5.4 / §5.3 |
| `JobEscrow` | Session escrow `open` / `claim` (F003 receipt verify + cumulative settlement + 88/5/4/3 split) / `close` / `refund`; DNS-final threshold | §5.6 / §8.4 / §13.2 |
| `DisputeGame` | Tier-2 optimistic-replication dispute: challenger bond, committee verdict, 50% slash | §4.2 |
| `MilGovernance` | DAO model-update pipeline: 3 gates → stake vote → migration grace → enact; emergency rollback | §19 |

## On-chain receipt verification (§8.3)

`JobEscrow.claim` verifies an ML-DSA-87 **Proof-of-Inference receipt** on-chain
via the **F003 `MLDSA87_VERIFY` precompile, version `0x03`** (added in
`kaspa-evm/src/mldsa_verify.rs`). `MilReceiptLib` reconstructs the exact
163-byte receipt signing transcript that the provider enclave signed
(`misaka_mil_core::receipt::ReceiptBody::signing_message`) — the MIL wire format
is little-endian, so every integer field is byte-reversed. The Solidity
reconstruction is asserted byte-for-byte against a Rust-emitted fixture in
`test/MilReceipt.t.sol`.

The optional **F004 `HASH64`** precompile (keyed BLAKE2b-512) lets a contract
recompute `cm_req` / `receipt_hash` / `model_id` on-chain; both F003-v0x03 and
F004 are **fenced inert** (activation `u64::MAX` on every network) until the
coordinated EVM-HF, exactly like the existing F003 v0x01/v0x02.

## Build & test

```
./build.sh            # forge install + build + test (needs forge + cast on PATH)
# or
forge test -vv
```

17 tests pass (receipt-transcript cross-language fixture, full escrow claim +
fee split, DNS-final gating, stake/unbond, dispute slash, the DAO pipeline).

## Deployment order

1. `ProviderRegistry(owner)`, `StakeManager(owner, minA, minB)`, `ModelRegistry(owner)`
2. `RewardPool(owner, treasury)`
3. `JobEscrow(owner, registry, rewardPool, dnsThreshold)` → `rewardPool.setJobEscrow(escrow)`
4. `DisputeGame(owner, stakeManager, registry, challengerBond)` → `stakeManager.setSlasher(dispute)`, `dispute.setCommittee(...)`
5. `MilGovernance(owner, modelRegistry, bond, evalWindow, redteamWindow, grace)` → `modelRegistry.transferOwnership(governance)`, set `evaluator` / `voteWeigher`
6. `escrow.setDnsReporter(...)`, `rewardPool.setDistributor(...)`

Deploy each with the keyed `misaka evm deploy` (feature `evm-send`), as with the
NFT / PQ-account templates.

## Trust notes

- The MIL contracts are **secp256k1/ECDSA-authed** at the EVM layer (the lane's
  native auth); the *receipt* signatures they verify are post-quantum
  (ML-DSA-87 via F003). This mirrors the NFT / PQ-account templates' disclosure.
- "Burn" sends the 5% fee share and slash-burn to the conventional unspendable
  sink `0x…dEaD`; a true supply burn would bridge back to L1 (follow-on).
- `dnsFinalizedBlock` is fed by an authorized reporter in v1; a system-precompile
  exposure of the DNS-final anchor (§8.4) is the production path.
