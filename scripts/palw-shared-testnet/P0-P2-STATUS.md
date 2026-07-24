# P0 / P1 / P2 goal status — honest ledger

Date: 2026-07-24. Scope: the goal list "P0: 共有前に必須 (10) / P1: closed shared
testnet (9) / P2: public testnet (10)" against this harness + the Rust workspace.
Verification environment: one macOS host (no second host, no GPU, no multi-day
window). Every DONE below names its evidence; every BLOCKED names the missing
physical prerequisite — nothing is claimed beyond what ran.

## P0 — 共有前に必須

| # | Item | Status | Evidence / blocker |
|---|---|---|---|
| 1 | remote node agent / systemd | **DONE** | `palw-node-agent.sh` (§5.4, 15/15 acceptance test in `test-multihost-agent.sh`); systemd wrapper units in `systemd/` (oneshot wrappers — native Type=exec unit is Phase-B) |
| 2 | `activation_open` を RPC で公開 | **DONE (LIVE)** | `PalwActivationProbe` (consensus probe re-runs the EXACT `resolve_palw_lagged_anchor` → `resolve_palw_buried_epoch_seeds` → `palw_lagged_activation_open` walk the Certified→Active gate consumes) → `RpcPalwActivationState` (getPalwState wire v3) → `palw-status` prints `activation.*`. Wire roundtrip test passes. **LIVE on the warm devnet-111 chain: both nodes report `activation.open: true` with the IDENTICAL sample pair (epoch 826/825, distinct seeds — §6.5's exact requirement) + anchor + `derived_mode: healthy`** |
| 3 | mint 成功時に block hash 必須化 | **DONE** | `start-palw-miner.sh`: marker-level/hashless success paths REMOVED (128-hex required, both-node hash-pinned only); `run-all.sh` PASS requires recorded identical 128-hex hashes (evidence, not stage completion) |
| 4 | node A/B 双方による同一 block 確認 | **DONE** | `verify-consensus.sh`: mock+no-evidence ⇒ STOP (was silent N/A pass); with a hash, `get-block` MUST succeed against BOTH nodes' RPC with identical coinbase content |
| 5 | 後続 merging block から報酬検証 | **DONE (code + CLI smoke)** | new `kaspa-pq-validator find-reward-settlement`: children-DAG walk to the first merging chain block, blue/red classification (+ node `getCurrentBlockColor` cross-check), EXACT expected values via the real consensus fns (`split_block_subsidy`/`premium_split`), value+SPK multiset assertion; `verify-coinbase.sh` "PASS (deferred)" → **PARTIAL_DEFERRED** (machine-readable), auto-upgrades to PASS_SETTLED when the verifier locates+matches the settlement. LIVE smoke: correctly refuses a non-algo-4 source over the warm chain's RPC. Cannot be exercised end-to-end here: a REAL mint is blocked (unshipped DA/auditor infra — see G5 verdict in PHASE0-status) |
| 6 | negative tests を run-all へ統合 | **DONE** | `negative-tests` stage in `FULL_PLAN` (release mode `NEG_RELEASE=1`); per-case PASS/FAIL/SKIP + `neg.result:` line + `negative-tests.json`; SKIP is never a pass; unjustified skips fatal in release mode |
| 7 | restart test の実処理修正 | **DONE** | `restart-a`/`restart-b` now run through the host agent's `restart --force`, which asserts the pid/start-time CHANGED (the §9.3 already-validator no-op path is structurally impossible) |
| 8 | signed network manifest | **DONE (LIVE)** | `network-manifest.sh generate/verify`: misaka-palw-network-manifest-v1 JSON built from the LIVE nodes' `getConsensusIdentity` (refuses to sign a disagreeing pair), ssh-keygen -Y signature (dedicated auto-generated release key, never a personal SSH identity) + allowed-signers pin; `preflight.sh` REQUIRES a verified manifest in shared mode. **LIVE: generate + verify PASS on the warm chain (signature + both-node identity + binary hashes); NEGATIVE paths verified — tampered content REJECTED, valid-signature-but-wrong-genesis REJECTED against the live nodes** |
| 9 | genesis / binary hash / params hash 必須化 | **DONE (LIVE)** | new `getConsensusIdentity` RPC (server-side genesis hash, `Params::consensus_identity_hash()` over every consensus-sensitive field — unit-tested deterministic/sensitive/exclusion-correct — effective header version + EFFECTIVE `--palw-enable-algo4`, archival/utxoindex, git commit); `status` prints it and warns on preset drift; preflight verifies algo4 parity via RPC and dies on a split; manifest verify dies on any mismatch. **LIVE: both warm nodes serve identical `node_params_hash` (0d41a791…), `node_palw_algo4_accept: true` (runtime override correctly folded), `node_git_commit: cec00ff2…` (= the pushed main commit)** |
| 10 | disk / DB 成長監視 | **DONE** | `disk-slo.sh` (free%, du of both appdirs, growth GiB/h + hours-to-full from recorded history; WARN 30 / STOP-LIFECYCLE 20 / EMERGENCY 10); gated into `create-lifecycle.sh`; surfaced in the agent's status/collect. Live-smoked against the warm data root |

P0 verdict: **all ten items implemented and unit/syntax/live-smoke verified as
noted**. Items 2/5 carry an honest asterisk: their full end-to-end exercise needs
a restarted node (2) and a real minted block (5) — the latter is gated on
unshipped Phase-1 infra, not on this harness.

## P1 — closed shared testnet

| # | Item | Status | Evidence / blocker |
|---|---|---|---|
| 1 | operator 別の鍵生成 | **DONE (mechanism)** | agent `generate-operator-key <dns-validator\|provider-a\|provider-b\|auditor-c>`: host-local 0600 seed, public block only returned. The signed-carrier exchange (`palw-payload` offline build → controller submits) already separates build-with-seed from submit |
| 2 | node A/B を別 host へ配置 | **BLOCKED (hardware)** | needs a second reachable host. The control plane for it is shipped (§5.4 agent + node_dispatch + pinned SSH); the RTX/Tailscale box was offline when last probed |
| 3 | controller に秘密鍵を置かない | **DONE (control plane)** | §5.4 conditions 1-3 validated 15/15 on one box: agent owns pids+seeds, controller receives public identity only. Cross-host provider FUNDING flow untested pending P1-2 |
| 4 | provider onboarding 手順 | **PARTIAL** | key separation + carrier flow exist (P1-1); a written operator runbook remains TODO |
| 5 | faucet / bootstrap funding | **DONE (single-host)** | `bootstrap-funds.sh` (keygen + mine-to-maturity). A cross-host faucet daemon is not built |
| 6 | late join 試験 | **NOT RUN** | runnable on one host (third node joining an aged chain); not yet executed — honest TODO, no result claimed |
| 7 | pruning point 経由の同期試験 | **BLOCKED (by design)** | `palw_requires_archival` refuses pruned operation; PALW has NO pruning-point import path (PalwPrunedFrontier has neither writer nor reader). The honest test is "refuses fail-closed", which is enforced at startup |
| 8 | 24時間 soak | **BLOCKED (wall-clock)** | requires 24h of real time; the endurance harness exists (commit 4121131) but a completed 24h run cannot be produced inside this session |
| 9 | partition/reconnect 試験 | **PARTIAL** | single-host proxy (stop/rejoin B) passes as a negative-test case with honest labeling; a TRUE link-cut partition needs two hosts + firewall control (P1-2) |

## P2 — public testnet

Every P2 item is **BLOCKED on unshipped Phase-1+ infrastructure and/or public
operations** that no amount of harness work on this host can substitute:

| # | Item | Blocker |
|---|---|---|
| 1 | permissionless provider registration | needs real provider daemon + economic gating design (ADR-0040 gate classes) |
| 2 | ticket spam 対策 | Header-v4 (`palw_spam` non-inert) is a re-genesis; no preset ships it |
| 3 | bond/slashing 実運用 | dispute/fraud/slashing completion is listed unshipped in PHASE0-status |
| 4 | real PALW compute | needs `palw-providerd` + GPU inference (none on this host) |
| 5 | mock ticket 撤去 | meaningful only after P2-4 |
| 6 | provider version enforcement | needs P2-4 + release channel |
| 7 | network upgrade 手順 | governance/process doc — draftable, but only meaningful with >1 operator |
| 8 | snapshot 配布 | needs Header-v4 authenticated snapshot/import (unshipped) |
| 9 | explorer / status page | public infra deployment |
| 10 | 72時間+ soak | wall-clock + multi-operator |

## The one structural honesty note

A REAL algo-4 mint (which P0-5's full exercise and several P1/P2 items sit
behind) is **G5-BLOCKED-UNSHIPPED** on this closed no-GPU devnet: the certificate
blob can never be durably accepted because the DA-availability gate
(`PalwDaStateV1::certificate_allowed`) requires satisfied leaf-DA obligations
(needs providers + challenger + `palw-da-auto-respond`), and past that the
auditor 2/3 ML-DSA quorum. These are fail-closed gates working as designed. All
P0 tooling above is written so that WHEN that infra ships, the verification
chain (hash-pinned mint → both-node fetch → descendant settlement → exact
value/SPK match) runs unchanged.
