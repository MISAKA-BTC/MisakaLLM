# MISAKA 8GB-VPS 設計 §15.3 / §15.4 / §15.5 検証・敵対レビュー (v1)

**作成:** 2026-06-26 ／ **範囲:** 設計レビューのみ（コードは一切書いていない）
**対象ツリー:** ローカル `pr-19-s5f-generator-mldsa-recalibration` @ `104ff94`
**基準(参照実装):** 本番稼働中の修正 `misakas-main 3d56800` + 未コミット fix (== `ab6f90e`、`node_synced=true` 稼働実績)
**手法:** build-host `.119` での grounded 検証 + 13-agent 多レンズ敵対レビュー Workflow (`wf_81a7aa4c-ecd`)

---

## 付録 A: build-host (.119) ベースライン検証結果

`.119` の `misakas-ci-verify` = LIVE §15.4+P0-2 ツリー（参照実装）に対して:

| 項目 | 結果 |
|---|---|
| `cargo` ビルド | クリーン（dead_code warning 1件のみ: EVM activation fields、無害） |
| reachability suite (`cargo test -p kaspa-consensus --lib reachability`) | **12 passed / 0 failed** |
| pruning suite (`cargo test -p kaspa-consensus --lib pruning`) | **1 passed / 0 failed** |
| DNS suite (`cargo test -p kaspa-consensus --lib dns`) | **12 passed / 0 failed** |

**4ファイル sha256 parity（.119 実測）:**

| ツリー | dns_reorg hotfix | §15.4 reorder | P0-2(他3) |
|---|---|---|---|
| local `pr-19-s5f`@`104ff94` | ✓ | ✗ | ✗ |
| LIVE `misakas-ci-verify`@`3d56800`+fix | ✓ | ✓ | ✓ |
| `misaka-prea-build`(旧抽出) | ✗ | ✗ | ✗ |

→ 参照実装（§15.4+P0-2）ツリーはビルド・全関連テスト green を確認。ローカル開発ブランチは dns_reorg のみ。

---

## 0. エグゼクティブサマリ

2026-06-26 testnet-10 全停止の真因は **half-pruned DB（Trigger B）**。kill/disk-full/OOM が `prune()` の per-block reachability 削除（`pruning_processor/processor.rs:617` で commit）と `retention_checkpoint` の最終書き込み（`:650-651`、別バッチ）の間に割り込むと、reachability 行は物理削除済みなのに retention メタは旧 root を指したままの不整合 DB が残る。すると `resolve_virtual` 経路の **infallible** reachability クエリが `KeyNotFound` で panic → `core/src/panic.rs:29` の `process::exit(1)`（グローバル set_hook）で全プロセス終了 → 再起動 → 同箇所で再 panic = **決定論的クラッシュループ**。

本番修正は2本柱の **soft-heal**:
- **(A) §15.4 reorder** — `recover_pruning_workflows_if_needed()` を worker 起動**前**に同期実行
- **(B) P0-2** — `resolve_virtual` 経路4箇所の fallible 化（missing 行を「pruning point 以下」とみなし自己修復）

**ローカル `104ff94` は (B) 4箇所中 `dns_reorg_allows`（Trigger A=凍結アンカー専用）1箇所のみ、(A) は完全欠落。** → `104ff94` をデプロイ系譜にすると 2026-06-26 のクラッシュループが回帰する。

| 項目 | 判定 |
|---|---|
| **§15.3** preflight | **needs-revision** — 機構は実装可能だが「missing 行で hard-stop」既定が本番 soft-heal と正反対。書かれたままでは自己修復可能ノードを resync 必須の死ノード化。提案 discriminator は half-prune を検出すらしない |
| **§15.4** recovery 順 | **design-sound（核は正しく必須）+ needs-revision（記述不足）** — reorder は決定論的 deadlock を断つ唯一の手段。だが P0-2 を hard prerequisite に明記、blocking コスト・disk preflight host 不在・staging no-op 性が未記述 |
| **§15.5** DB write（短期 abort） | **superseded-by-live-fix** — 「panic→abort」は no-op（`panic.rs:29` が既にグローバル process exit） |
| **§15.5** DB write（全体） | **needs-revision** — 唯一 additive なのは 617/651 atomicity。加えて systemd StartLimit 誤配置の出荷ブロッカーを内包 |

---

## §15.3 起動時 reachability/DB preflight

### 設計の実コードとの整合性
store アクセサの主張は**すべて正確で実装可能**: `retention_checkpoint()`/`retention_period_root()`(`stores/pruning.rs`)、`utxoset_position()`(`pruning_meta.rs`)、`headers_selected_tip`、`virtual_stores.state.get()` の `parents`/`selected_parent`、`body_tips_store.get()`。un-mappable 項目なし。

しかし**核となる前提（missing reachability → DatabaseInconsistent で HARD-STOP）が本番 soft-heal と直接矛盾**。設計が依拠する「`dns_reorg_allows` が凍結アンカーを参照する唯一の reachability クエリ」は **Trigger A に対してのみ真**で、実インシデントの **Trigger B（half-pruned DB）を全くカバーしない**:
- **Trigger A**: `dns_reorg_allows`(`processor.rs:2578`)— 既に修正済み。凍結アンカー参照の唯一サイト。
- **Trigger B**: `virtual_finality_point`(`:599`)、body_tips filter(`:506`)、sink_search candidate(`:2705`)— **本ブランチでは infallible**。half-pruned DB で `dns_reorg` 到達前に panic。

### 敵対レビュー所見（severity 順）
- **[CRITICAL] hard-stop 既定が自己修復ノードを死ノード化** — half-pruned DB は RECOVERABLE（`recover_pruning_workflows_if_needed:201-203` の prune 完了 + P0-2 の transient 許容）。同じ missing 行で stop すれば両機構を無効化し、2026-06-26 の自己修復可能だったケースを resync 必須化。
- **[HIGH] discriminator が half-prune を検出しない** — half-pruned DB の reachability ツリーは atomic batch で内部整合、`retention_period_root` 行は**決して削除されない**(`processor.rs:464` で root スキップ)。`has_reachability_data(retention_period_root)` は TRUE を返し何も検出しない。stale なのは `retention_checkpoint` のみ。**「キー行 missing」を判定軸にしてはならない。**
- **[HIGH] TOCTOU / 時間非決定性** — recovery は複数バッチ commit + virtual を再 resolve しない。preflight が virtual_state.parents/body_tips/sink を読むと prune 跨ぎで reachability より正当に先行した過渡的 missing を見る。recovery と read のレースで同一 DB が stop-now と heal-later の異なる判定を生む。
- **[HIGH] startup 時点で transient と corruption を区別できない** — recovery 前は checkpoint が旧 root を指し行は削除済み。preflight は **recovery 完了後にのみ健全**。
- **[MEDIUM] RPC 経路の reachability も panic 面**(`consensus/mod.rs:1489`)— 起動後到達、一発 preflight でカバー不能。heal window 中の外部 poll が abort。
- **[MEDIUM] preflight 自身が infallible API で panic** — `has_reachability_data()` は `self.has().unwrap()`。store/IO error（§15.5 が対象とする disk fault）で preflight が置き換えるはずの panic と同箇所で panic。**fallible store API を使うこと。**
- **[MEDIUM] DatabaseInconsistent の置き場所** — 本ブランチの唯一の errors 変更 `config.rs`=`ConfigError`（store オープン前の CLI 検証）は**カテゴリ誤り**。stop は `errors/consensus.rs`（または新規 storage error）+ 明示的 process abort であるべき（`run_processors` は `Vec<JoinHandle>` を返し Result 経路なし）。
- **[MEDIUM] prune 再実行 idempotency は微妙** — `delete_block`(`inquirer.rs:79/94`)は二重呼びで `Err(DataInconsistency)`=**非 idempotent**。ただし prune 走査(`:460-469`)は削除済みを child 再 parenting で構造的にスキップし再呼びしない。「prune は idempotent」と無条件に書かないこと。
- **[LOW] chain iterator unwrap**(`reachability.rs:207/244`)は無限 chain を歩くため静的キー preflight では原理的にカバー不能。
- **[LOW] 狭い corruption には hard-stop が正しい** — `retention_period_root` より**上**の missing 行（中断 prune では説明不能=真の corruption）や pruning_point/headers_selected_tip/pruning_utxoset_position の dangling は stop が正。§15.3 は wholesale で誤りではなく **mis-scoped**。

### 判定: needs-revision（必須改訂）
1. preflight は **recovery 完了後にのみ実行**（「profile-independent at startup」を撤回）。
2. hard-stop は **「recovery が true/不要を返した AND 行が依然 missing AND 参照ブロックが retention_period_root より上」のときのみ**。below-root の missing は RECOVERABLE-SOFT として P0-2+retry に委ねる。recovery が false(defer) なら「判定不能→stop しない」。
3. 動的 virtual-tip 参照（body_tips, virtual_state.parents, selected_parent）を hard-stop 集合から除外し WARN+continue に降格。
4. preflight は fallible store API（`unwrap` 不可）。
5. DatabaseInconsistent は `errors/consensus.rs` 配置（`config.rs` 不可）。
6. **§15.3 は §15.4 + 欠落 P0-2 3箇所の strict superset としてのみ出荷**。単独出荷は crash-loop を resync-loop に置換するだけで回帰。

---

## §15.4 pruning recovery 起動順

### 設計の実コードとの整合性
**正確**（行は本ブランチ補正）: `run_processors`=`consensus/mod.rs:553`。`PruningProcessingMessage::Process` の唯一送信元 `virtual_processor:566`、受信 `pruning_processor:132`。`run_processors`(`:560-565`)は4 worker を即時・無条件 spawn、virtual spawn 前の同期 recovery **なし**。recovery は worker ループ内で最初の Process 後のみ(`:132-145`)、その producer は panic より後の `resolve_virtual:566`。**§15.4 reorder は本ブランチ非存在で確定。**

実際の起動 seam は2つだけ: `Consensus::new`（同期 store/genesis init）と `run_processors`（4 worker fire）。設計の「open DB→disk→transitional→recover→preflight→virtual→p2p/rpc」7フェーズは**そのままの形では存在しない**（disk-free チェックは経路上に host なし）。

### 敵対レビュー所見
- **[CRITICAL] `104ff94` as-is デプロイは 2026-06-26 を再現** — reorder 欠落 + P0-2 4中3 が panic 版。half-pruned DB で `:599`/`:506` が `:566`（唯一の Process producer）到達前に panic → worker(`:132`)は `recv()` で永久ブロック → in-loop recovery 到達不能。
- **[HIGH] §15.4 単独では不十分** — `recover_pruning_workflows_if_needed` は **何も heal せず false** を返せる（`confirm_pruning_depth_below_virtual` false `:183-184`、`is_in_transitional_ibd_state` `:189-190`、`advance_pruning_utxoset` 中断）。LIVE はこの後 deferred を log し worker spawn。P0-2 未修正なら `:599` が依然 panic。**P0-2 は hard prerequisite。**
- **[HIGH] preflight-after-recovery でも soft-defer を誤分類** — recovery が false-defer を返した（回復可能だが未回復）DB に §15.3 preflight が gate すると self-heal 可能ノードを誤分類。step 5 は「recovery が true AND 行 missing」を hard precondition に。
- **[HIGH] wall-clock ブロッキング（deadlock ではない）** — ネットワーク依存の真の hang はなし（recovery 入力は全てローカル永続状態）。だが `prune()`/`advance_pruning_utxoset` は大規模 half-pruned DB で**時間無制限**（proof build + per-block DB-write 走査 + 任意の full-UTXO MuHash 再計算）。p2p 起動前に全実行 → systemd `TimeoutStartSec`/watchdog 下で recovery 途中 kill が新ループを形成。runbook と idempotent-resumable 性質、「recovery はローカル状態のみ依存」invariant を明記。
- **[MEDIUM] disk preflight に host がない** — 「ただ recovery を移動」では、再起動ループを DB 再オープン前に断つ唯一の手段（disk-free preflight）を黙って落とす。(4a) recovery reorder と (4b) 新規 disk-preflight フェーズ（`ConsensusManager::worker` の `ctl.start()` 前 or daemon `core.run` 前）に分割すべき。
- **[MEDIUM] staging consensus 経路** — `StagingConsensus::new`→`run_processors` でも §15.4 recovery が走る。no-op であるべきだが `confirm_pruning_depth_below_virtual` が `virtual_stores.state.get().unwrap()`(`:722`)を読むため、初期化前 staging では clean defer でなく `.unwrap()` panic リスク。no-op 性と初期化済みを検証。
- **[MEDIUM] prune が pruning_lock write を取る**(`:346`)— 今は contention-free だが「recovery は async_runtime/p2p/RPC bind 前に完了」を hard ordering 要件に明記（`daemon.rs:987-988` の「Consensus must start first」を機構として引用）。
- **[MEDIUM] recovery 自身の prune() が再 panic** — `get_children` は child interval を `.unwrap()`。§15.5 で torn バッチが残ると recovery の prune 再実行が panic。recovery の panic-free は §15.5 の atomic-batch 保証に依存。
- **[LOW] in-loop trigger が冗長化** — reorder 後も in-loop trigger(`:133-145`)は第2 trigger として残す。責務分担（pre-spawn=crash-recovery / in-loop=transitional retry）と二重実行安全（`recovered` flag は worker ローカル）を note 化。

### 判定: design-sound（核は正しく必須）+ needs-revision（記述不足）
reorder の核は決定論的 deadlock を断つ唯一の手段で正しい。hook 配置（`run_processors` の spawn vec 前）は現アーキの RIGHT seam。文章として (i) P0-2 hard prerequisite、(ii) blocking + 運用ガードレール、(iii) disk preflight host 不在、(iv) staging no-op を補うこと。

---

## §15.5 DB write 失敗ポリシー

### 設計の実コードとの整合性
正確。`prune()` は reachability 削除(`:589`/`:617` commit)と `retention_checkpoint` 最終書き込み(`:650-651`、別バッチ)を non-atomic に持つ。`core/src/panic.rs:29` が `process::exit(1)` を**グローバル**（`set_hook` `:7`、`daemon.rs:290` インストール、`panic="abort"` なし=default unwind で hook 走行、consensus 配下に `catch_unwind` なし）。`CachedDbItem` は `db.write` 前に cache set。

### 敵対レビュー所見
- **[CRITICAL／出荷ブロッカー] systemd StartLimit 誤配置で無効化** — `misaka-bootstrap-pruned.service:16-17` / `misaka-recovery-sync.service:17-18` が `StartLimitIntervalSec=900`/`StartLimitBurst=5` を **`[Service]` セクション**に宣言（実ファイルで確認: `[Service]`=L7/L9、`[Install]`=L34/L31、StartLimit は間）。systemd はこれらを `[Unit]` ディレクティブとして扱い `[Service]` では無視 → 実効 default `10s`/`5`。`RestartSec=30` で5回再起動 ~150s ≫ 10s window のため **rate-limit が決して trip せず永久再起動**。`[Unit]` へ移動 + `systemd-analyze verify` の acceptance。**§15.4/§15.5 双方の loop-breaker として load-bearing。**
- **[HIGH] 短期「abort 化」は no-op／superseded** — worker-thread panic は `db.write().unwrap()` で**既に全プロセス終了**（グローバル set_hook→`process::exit(1)`）。zombie-thread は存在しない。さらに真因の OOM/SIGKILL/disk-full sequence 途中割り込みでは `db.write` が Err を返さないので abort policy は発火すらしない。
- **[HIGH] retention_checkpoint 書き込み(`:651`)での abort は corruption を製造** — `:617` 削除 commit 後に `:651` が transient ENOSPC で失敗 → `.unwrap()` abort が**まさに half-pruned DB を作る**。bounded retry-with-backoff（disk は失敗バッチ drop 後に空く）が checkpoint commit で不整合を回避できた。最も危険なサイトで retry より abort を選んでいる。
- **[HIGH] 「single-WriteBatch で per-block prune を atomic 化」は構造的に不可能** — `:617` は lock-yielding 走査ループ**内**の per-block flush、`:651` はループ**後**の単一 terminal write。merge 可能な co-located write ではない。真の crash-atomicity には (a) per-block ループ内で `retention_checkpoint` を monotonic high-water-mark として各チャンク削除と同一バッチ co-commit、または (b) 既存 restartable re-prune(`:201-203`)を canonical 修正と宣言して硬化、のいずれか。「last batch」案は window を閉じない。
- **[MEDIUM] cache-after-commit 長期項目は abort policy 自身に中和される** — 失敗時 abort は in-memory cache を破棄するので divergence が moot。cache-after-commit の価値は「失敗後もプロセスが走る」未来でのみ顕在化し abort と矛盾。両方を書いたまま出荷しない。
- **[LOW] OOM SIGKILL は panic.rs を完全バイパス** — `MemoryMax=7G`/`OOMPolicy=stop`。`:617→:651` window 中の OOM kill は SIGKILL で panic.rs 走らず同一 half-pruned DB を残す。617/651 atomicity 修正だけが SIGKILL に対する唯一の堅牢防御。
- **[LOW] disk preflight は transient にレーシー** — `df -P` 1回サンプル、flap しうる、別マウントの WAL/compaction temp 不可視。「loop を断つ」でなく「最頻ケースを減らす」に格下げし StartLimit を authoritative loop-breaker に。

### 判定: needs-revision／（短期 abort 項目は）superseded-by-live-fix
短期「abort 化」は `panic.rs:29` に対し no-op で削除。真因の crash-LOOP は clean exit では断てず §15.4+P0-2 が断つ。唯一 additive なのは **617/651 atomicity**（monotonic checkpoint or restartable re-prune 硬化）。加えて **systemd StartLimit 誤配置を即修正**。

---

## 中心的緊張: §15.3 hard-stop vs 実証済み LIVE soft-heal

§15.3「missing reachability で HARD-STOP」は LIVE「missing 行を許容して回復」と**正反対の哲学**。half-pruned DB（実インシデント）を §15.3 が hard-stop すると、§15.4 recovery + P0-2 が self-heal したはずのノードを operator resync 必須の死ノードに変える。

**裁定:** `retention_period_root` 境界は discriminator として**正しいが、それ自体が half-prune を検出する手段ではなく、recovery が回復不能 corruption を残したかを判定する手段**。half-prune の検出・修復は recovery（`prune()` 再実行）が行い、§15.3 はその**残渣**だけを見る。

**推奨（明確な結論）: §15.3 は hard-stop だが、「§15.4 recovery 実行後の、回復不能 corruption に対してのみ」の hard-stop とする。**
1. raw startup では走らせない（§15.4 step 5 順序を hard precondition、「profile-independent at startup」撤回）。
2. recovery が true（完了 or 不要）を返した場合のみ判定。false(defer) は stop しない。
3. 境界は recovery 後に読んだ `retention_period_root`。below-root missing=RECOVERABLE-SOFT（P0-2+retry）、above-root missing=真の corruption=hard-stop。pruning_point/headers_selected_tip/pruning_utxoset_position の dangling も hard-stop クラス。
4. 動的 virtual-tip 参照は hard-stop 集合から除外し WARN+continue。
5. §15.3 は §15.4+P0-2 の strict superset としてのみ出荷。
6. hard-stop は `errors/consensus.rs` variant + 明示 process abort。fallible store API。

要するに **warn-only でも無条件 hard-stop でもなく、§15.4 recovery 後・above-root のみ**。soft-heal が第一機構、§15.3 hard-stop は最後の砦の corruption detector。

---

## パリティ / 回帰

| 項目 | local `pr-19-s5f`@`104ff94` | LIVE `3d56800`+fix(==`ab6f90e`) |
|---|---|---|
| dns_reorg_allows(Trigger A) | YES(`:2578`) | YES — **パリティ** |
| §15.4 同期 recovery reorder | **NO**(`:560-565` 即時 spawn) | YES — **回帰** |
| P0-2 virtual_finality_point(`:599`) | **NO**(infallible) | YES — **回帰** |
| P0-2 body_tips filter(`:506`) | **NO**(infallible) | YES — **回帰** |
| P0-2 sink_search candidate(`:2705`) | **NO**(infallible) | YES — **回帰** |
| §15.5 617/651 atomicity | NO | NO（両者未実装） |

`104ff94` は **Trigger A（凍結アンカー、低頻度サブケース）のみ保護**、**Trigger B（half-pruned DB、実インシデント主因）は無防備**。

**forward-port 優先度（設計レベル、不可分の単一ゲート、降順）:**
1. **§15.4 reorder**(`mod.rs:558-560` 同期 recovery + soft-defer log) — deadlock を断つ唯一の手段
2. **P0-2 virtual_finality_point(`:599`)** — resolve_virtual が最初に当たる panic
3. **P0-2 body_tips filter(`:506`)** — (2) と同時着地必須
4. **P0-2 sink_search candidate(`:2705`)** — 同一経路、同時着地

**§15.4 単独・部分 port を禁ずる。PREA(`104ff94`)系譜の任意のデプロイは、上記が両方着地するまでブロック。** 加えて recovery 自身の `get_children` panic リスク（§15.5 atomicity 依存）と staging no-op 性を forward-port 時に検証。

---

## 結論: 推奨オペレーション順序（設計レベル、コードは書かない）

1. **【最優先・回帰阻止】** PREA `104ff94` 系譜のデプロイをブロック。§15.4 reorder + P0-2 3サイトを**不可分ゲート**として forward-port する設計合意。
2. **【出荷ブロッカー】** systemd unit2本の `StartLimit*` を `[Unit]` セクションへ移動。`systemd-analyze verify` の acceptance 追加。
3. **§15.4** を承認しつつ (i) P0-2 hard prerequisite、(ii) blocking + watchdog runbook、(iii) disk-preflight host 不在（4a/4b 分割）、(iv) staging no-op を追記。
4. **§15.3** を「中心的緊張」推奨に従い改訂（recovery 後・above-root のみの hard-stop、動的 tip 除外、fallible API、`errors/consensus.rs` 配置、§15.4+P0-2 superset）。
5. **§15.5** の短期 abort を削除（no-op/superseded）。617/651 atomicity を唯一の真の追加項目として保持。cache-after-commit は落とすか survive-and-rollback に pivot。transient ENOSPC は retention_checkpoint で abort せず bounded retry。
6. recovery prune 再実行の idempotency 不変条件を文書化（retention_checkpoint を最終単一 commit に保つ / 走査を live reachability ツリー由来に保つ / `delete_block` 自体は非 idempotent）。

**注記:** 本レビューでコードは一切書いていない。.119 baseline は付録 A（reachability 12/12・pruning 1/1・DNS 12/12、全 green）。

