# MIL v1 Payment — P2 Testnet Activation Runbook (coordinated EVM hard fork)

**Status: DRAFT — requires explicit go + activation-DAA selection before execution.**
This is the operational runbook for **P2** of the MIL v1 MSK-settlement plan
([memory / plan]): activating the **F003 `MLDSA87_VERIFY`** precompile on the live
**testnet-10** EVM lane so `JobEscrow.claim()` verifies real ML-DSA-87 receipts and
pays out 88/5/4/3 in MSK. P0 (real F003 verify + deploy driver) and P1 (on-lane
claim + full 88/5/4/3 payout, in-process) are **green and committed**
(`ae995eb` / `54a2d4b` / `080c988`). This document does NOT authorize execution.

> **This is a consensus hard fork on an EVM-active network.** The only code change
> is one `Params` field, but flipping it means every mesh node MUST run the new
> binary **before** the activation DAA or the EVM state root splits
> (`CommitmentMismatch` → chain split). Treat it with the same discipline as the
> already-shipped `evm_gas_pool_v2` fence (the exact precedent this mirrors).

---

## 0. What this HF does (and does NOT do)

**Does:** flips `TESTNET_PARAMS.evm_f003_mldsa_verify_activation_daa_score`
(`consensus/core/src/config/params.rs:1153`) from `u64::MAX` to a finite testnet
DAA. At/after that DAA every node registers the F003 (+F004 hash64, +F005
dns_finality — they share the F003 fence) precompiles in revm. Below the DAA
execution is **byte-identical** (the handler set is unchanged), so all prior EVM
state roots agree across old/new binaries.

**Does NOT:** touch coinbase, subsidy, the ADR-0018/0024 fee-split, genesis, or any
other network (`MAINNET` 1056 / `SIMNET` 1219 / `DEVNET` 1240 stay `u64::MAX`). No
re-genesis. Pure EVM-state-root activation fork. `coinbase.rs` has zero precompile
references — confirmed orthogonal.

**F005 posture (approved):** flipping F003 co-activates F005, which returns
`dnsFinalDaa = 0` (hardcoded, `consensus/src/processes/evm/mod.rs`). That is
deterministic (0 on every node) → state-root-safe, but makes the JobEscrow
DNS-final large-claim gate unusable (the oracle fallback is unreachable once F005
is active). **v1 avoids the gate entirely by deploying JobEscrow with
`dnsFinalClaimThreshold` ABOVE all demo claim sizes** (deploy_mil.sh default =
1,000,000 MSK). True trustless large-claim finality (real `dns_final_daa_score`
source) is a **separate later fork**, out of scope here.

---

## 1. Frozen parameters (confirm FINAL before building — consensus-frozen at activation)

| Constant | Value | Where |
|---|---|---|
| `F003_VERIFY_GAS` | **500_000** / verify | `consensus/core/src/evm/mod.rs` |
| `MAX_MLDSA_VERIFY_PER_EVM_BLOCK` | **64** | same |
| `F004_HASH64_GAS` | 6_000 | same |
| `F005_DNS_FINALITY_GAS` | 2_000 | same |
| Fee split | **88 / 5 / 4 / 3** (provider/burn/validator/treasury) | `JobEscrow.sol` |
| `dnsFinalClaimThreshold` (deploy arg) | **1,000,000 MSK** (above demo claims) | `deploy_mil.sh` |

These cannot change after activation without another fork. Sign off explicitly.

---

## 2. Node inventory (fill in + confirm access BEFORE anything)

Every node that **produces or validates** blocks on testnet-10 must be upgraded.
Known mesh from the running `.213` peer set (verify + complete this list — a single
missed miner/validator on the old binary splits the chain at the activation DAA):

| Node | Role | Access | On new binary? |
|---|---|---|---|
| `160.16.131.119` | build host + node | `ssh ubuntu@…119` (claude_key) | ☐ |
| `133.167.126.213` | node (pruned, `--vps-8gb`) | `ssh ubuntu@…213` (claude_key) | ☐ |
| `95.111.236.186` | node/validator | ☐ confirm | ☐ |
| `217.178.101.111` | node | ☐ confirm | ☐ |
| `207.180.230.3` | node | ☐ confirm | ☐ |
| miners | block producers | ☐ **enumerate — critical** | ☐ |
| RPC/EVM-serving nodes | eth_* / misakascan | ☐ | ☐ |

> The danger set is **miners** (they produce the blocks that cross the fence) and
> **validators**. RPC-only nodes that don't validate blocks are lower risk but must
> also be upgraded to serve correct `eth_getBalance` etc. after activation.

---

## 3. Activation-DAA selection (at build time)

The fence is a **compiled constant** — chosen once, cannot be walked back without a
rebuild, cannot change post-activation without another fork.

1. Read the live virtual DAA on a synced node (localhost wRPC):
   `misaka node doctor` / a `getBlockDagInfo` call → `virtualDaaScore` = **D_now**.
2. Read the block rate: testnet-10 `target_time_per_block` → **BPS**
   (blocks/sec). (gas-pool-v2 precedent: fence `2_125_000`, chosen ~90 min ahead.)
3. Pick roll headroom generously to cover build + roll + verify of ALL nodes:
   ```
   activation_DAA = D_now + BPS × roll_window_seconds
   ```
   Recommended `roll_window` = **comfortably longer than the real roll** (e.g. a
   few hours to a day of DAA), NOT the minimum. Too-close risks a node not
   swapping in time; too-far only wastes time and is safe. When unsure, go longer.
4. Record `D_now`, BPS, chosen `activation_DAA`, and the wall-clock estimate of
   when the network reaches it, in the go/no-go doc below.

---

## 4. Build the release binary

```bash
# On the build host (160.16.131.119 — heavy release build; sync feat/mil-v0 first).
# 1. Edit the ONE consensus line:
#    consensus/core/src/config/params.rs:1153
#    evm_f003_mldsa_verify_activation_daa_score: u64::MAX,   →   <activation_DAA>,
#    (leave MAINNET/SIMNET/DEVNET at u64::MAX)
# 2. Build the node WITH the evm feature:
cargo build --release --features evm -p kaspad
# 3. (optional) build the CLI for deploy/demo:
cargo build --release --features evm-send -p misaka-cli
# 4. Record the binary sha256 — every node must run THIS artifact.
sha256sum target/release/kaspad
```

Tag the exact commit + activation_DAA (e.g. git tag `mil-v1-f003-testnet-<DAA>`),
so the rolled binary is reproducible and rollback can rebuild the pre-fork one.

---

## 5. Roll procedure (per node — COMPLETE before the activation DAA)

For each node in §2, one at a time, keeping the mesh live:

```bash
# a. copy the new binary
scp target/release/kaspad ubuntu@<node>:/home/ubuntu/kpq-testnet-bin/kaspad.new
# b. stop the node (systemd or the launch method in use)
ssh ubuntu@<node> 'sudo systemctl stop <kaspad-unit>'   # or the pkill -x kaspad used in ops
# c. swap the binary
ssh ubuntu@<node> 'mv ~/kpq-testnet-bin/kaspad ~/kpq-testnet-bin/kaspad.old && mv ~/kpq-testnet-bin/kaspad.new ~/kpq-testnet-bin/kaspad && chmod +x ~/kpq-testnet-bin/kaspad'
# d. start + verify
ssh ubuntu@<node> 'sudo systemctl start <kaspad-unit>'
#    verify: same appdir/flags (NO --node args change), sha256 matches, node re-syncs to tip,
#    getBlockDagInfo virtualDaaScore advancing, isSynced=true.
```

**Roll invariants:**
- Below the activation DAA, old and new binaries produce **byte-identical** EVM
  state (the fence gates registration on `daa >= fence`). So a mixed old/new mesh
  agrees until the activation DAA — the roll can proceed node-by-node without a
  flag day. The danger window is strictly **at/after** the activation DAA.
- Do NOT change any `--node` flag, appdir, or genesis. Only the binary changes.
- After each node: confirm it re-synced to the current tip with no
  `CommitmentMismatch` in its log.

**Gate before the activation DAA:** every §2 node shows the new sha256 and is
synced. If the roll is NOT complete with margin before `activation_DAA`, **ABORT**
(the fence is baked in — you cannot move it without a rebuild; a partial roll at
the DAA splits the chain).

---

## 6. Cutover watch (as the network crosses `activation_DAA`)

- Watch every node's log for `CommitmentMismatch`
  (`consensus/src/processes/evm/mod.rs`) and for disqualifications around the
  activation DAA.
- Confirm the mesh stays on ONE tip (no fork): compare `sink`/`virtualDaaScore`
  and selected-tip hashes across nodes; misakascan should show a single chain.
- Smoke the precompile is live (any node, post-activation): a `staticcall` to
  `0x…F003` with a known-good fixture returns the 32-byte `true` word (the P1
  `F003Probe` bytecode, or `eth_call` to a deployed probe). This isolates
  "precompile active" from the full claim flow.

If clean across all nodes for a comfortable number of post-activation blocks →
proceed to deploy. If ANY node diverges → **rollback (§8) immediately.**

---

## 7. Deploy the MIL contracts + real-MSK demo (post-activation)

```bash
# 1. Fund an EVM owner key with MSK via the proven UTXO→EVM deposit-lock path
#    (memory: 0.99 MSK deposit→credit proven on testnet). Confirm eth_getBalance.
# 2. Deploy the core payment suite (threshold ABOVE demo claims → F005 gate never fires):
cd contracts/mil
MODE=deploy KEY_FILE=<owner-evm-key> EVM_RPC_URL=<node-eth-rpc> SUBMIT=1 \
  DNS_THRESHOLD=1000000000000000000000000 ./script/deploy_mil.sh
#    (deploys ProviderRegistry/StakeManager/ModelRegistry/RewardPool/JobEscrow +
#     RewardPool.setJobEscrow — all setters from the SAME owner key, else NotOwner)
# 3. Real-MSK claim demo BELOW threshold:
#    provider registers (real ML-DSA-87 receipt key) → requester opens escrow with
#    MSK → provider claims a real receipt → verify on-chain via eth RPC / misakascan
#    that provider got 88%, BURN_SINK 5%, RewardPool 4%+3% (exactly the P1 harness,
#    now on the live lane with real MSK).
```

Keep every demo claim size **< dnsFinalClaimThreshold** so the DNS-final gate is
never evaluated.

---

## 8. Rollback (if divergence appears at/after activation)

The flip only affects blocks **at/above** `activation_DAA`. If a split begins:

1. **Halt mining** on affected/upgraded nodes immediately (stop block production so
   the fork does not widen).
2. Rebuild with the fence set **back to `u64::MAX`** (or a higher, not-yet-reached
   DAA) and re-roll that binary to all nodes.
3. Because the change only affects post-activation blocks, reverting **before the
   network has produced many post-activation blocks** cleanly restores the
   pre-activation state root — the earlier the intervention, the cleaner.
4. Re-sync all nodes to the restored tip; confirm one chain; post-mortem the
   node(s) that diverged (almost always: a node still on the old binary, or a
   sha mismatch).

Rollback is cheapest in the first minutes after activation — hence §6's live
watch. The DEVNET dry-run (below) exercises this exact flip on a throwaway net.

---

## 9. Optional pre-flight: DEVNET dry-run of the flip

Before touching testnet, exercise the identical mechanism on a throwaway devnet
(devnet EVM lane is genesis-active): set `DEVNET_PARAMS.evm_f003_…` (params.rs:1240)
to a small finite DAA, build, run a local devnet, deploy via deploy_mil.sh, run a
claim, then **revert the devnet edit**. This validates the build + deploy + claim
end-to-end on a real fence flip with zero cost. (P1 already proved the claim logic
in-process; this proves the *flip + node* path.)

---

## 10. Go / No-Go checklist (all must be ✅ before flipping)

- ☐ Frozen params (§1) signed off as FINAL.
- ☐ Full node inventory (§2) enumerated — **all miners + validators identified**.
- ☐ Access confirmed to every node (or its operator committed to roll on schedule).
- ☐ `activation_DAA` chosen with generous headroom (§3); wall-clock ETA recorded.
- ☐ Release binary built from the tagged commit; sha256 recorded (§4).
- ☐ (recommended) DEVNET dry-run passed (§9).
- ☐ Rollback binary (fence at u64::MAX) pre-built and ready (§8).
- ☐ Live watch + comms channel ready for the cutover window (§6).
- ☐ Owner EVM key funded with MSK for the post-activation deploy (§7).

Only when every box is ✅ **and the user gives an explicit go** does the fence get
flipped and the binary rolled.
