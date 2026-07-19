# PALW / T-shared 進捗記録 — 2026-07-20

ADR-0040（T-shared remediation）以降の作業記録。**何が閉じ、何が閉じていないか**を、後から
検証できる形で残すことが目的である。

関連: [ADR-0039](adr/0039-palw-replica-gemm-audited-compute.md) /
[ADR-0040](adr/0040-palw-single-pool-integer-canonical-remediation.md)

---

## 1. 現在の状態（一目で）

| 項目 | 状態 |
|---|---|
| `misakas/main` | **未更新**（tip `2268924` のまま） |
| PR [#53](https://github.com/MISAKA-BTC/misakas/pull/53) | **OPEN**（未マージ） |
| activation | **禁止のまま**。`palw_algo4_accept: false` × 6 preset、`true` は 0 件 |
| genesis hash | **不変**（`write_header_preimage` 無変更） |
| `LATEST_DB_VERSION` | 7 → **9**（`main` から見て 1 回の bump） |

**PALW leaf の支払いは 1 件も発生していない。** algo-4 は全 preset で受理されない。

### ブランチ

```
misakas/main  2268924
      │
      └─ feat/dns-dormancy-core-on-main   ← PR #53（push 済・未マージ）
             DNS dormancy コア + PALW 全体 + 採掘 producer + MTP + ADR-0040

feat/mil-v0（ローカルのみ・未 push）
      └─ 3377afb → f607030 → e996761 → e478600
```

`feat/mil-v0` が**権威ブランチ**。移植先ブランチはそこから cherry-pick する。

---

## 2. 本セッションのコミット（`feat/mil-v0`）

| SHA | 規模 | 内容 |
|---|---|---|
| `3377afb` | 11 files, +186/−248 | premine 13B → 10B、単一 UTXO 化、供給 25B |
| `f607030` | 26 files, +1794/−513 | **T-shared 障壁 4 件を閉鎖** |
| `e996761` | 8 files, +963/−117 | 残り P1（P1-14 完了、DOS-01/PCPB 再分類、ADR 整合） |
| `e478600` | 7 files, +451/−154 | **P1-5 DOS-02 を削除で閉鎖**（DB 8→9） |

移植先ブランチ: `fe38589`（ADR-0040 移植）+ `e6a56f3`（T-shared 修正の re-sync）。
`e996761` + `e478600` の移植は**実行中**。

---

## 3. premine 13B → 10B（`3377afb`）

40 vault × 0.1B + main 9B（41 UTXO）を、**ネットワーク毎 1 UTXO × 10B** に集約。
総供給 28B → **25B**（premine 10B + 採掘 15B、採掘側は不変）。

| ネットワーク | 宛先 |
|---|---|
| mainnet | `misaka:qfckqxaa…q0asl7` |
| testnet / devnet / simnet | `misakatest:qflkp962…ke8k` |

- `utxo_commitment` 2 値、genesis `hash` **7 variant** を再固定。`hash_merkle_root` は coinbase
  payload のみに commit するため**不変**。
- audit M-07 の round-trip assert が、乖離した genesis を起動不能に保つ。
- `TESTNET_MAIN_SEED` 由来の Claude 管理鍵は**廃止**。seed 再現性テストは「prefix 固定」＋
  「premine が実際に指定 custody script へ払う」検証に置換。
- ADR-0027 / MTP 設計 doc を改訂（プール原資「vault 1 本」→「単一 grant からの切り出し」）。

---

## 4. T-shared 障壁 4 件（`f607030`）

**ADR が DONE と記載していた P1-6 が、まさに防ぐはずの攻撃を通していた。**

### 4.1 AUTH-02 が「ブロック」でなく「同値類」を束縛していた（critical）

authorization の binding が手書きの **9 値 allowlist** だった。algo-4 は PoW 免除なので、
その外側は全て自由:

`utxo_commitment` / `accepted_id_merkle_root` / `pruning_point` / `overlay_commitment_root` /
`palw_beacon_seed` / `palw_epoch_certificate_hash` / **level ≥ 1 の parent 順**
（level 0 のみ束縛、上位 level は post-PoW が HashSet 比較なので順列が通る）

観測者が正直な algo-4 ブロックの署名を再利用して**無限個の有効ブロック**を作れた。さらに
virtual 段の 5 フィールドは chain candidate にならないブロックでは**一切検証されない**ため、
ゴミ値が恒久的に DAG に残る。nullifier 重複は RED 着色でしかなく妥当性判定ではないので止まらない。

**修正 = allowlist の廃止。** `write_header_preimage` が出す**正準ヘッダ preimage そのもの**に、
`palw_authorization_hash` = 0（循環のため必然的に除外）と authed merkle root の 2 置換だけを
加えて commit する。ブロックハッシュ writer を**再利用**するので、将来ヘッダにフィールドが
増えても自動的に束縛され、drift しうる並行 serializer が存在しない。鍵付きドメインは
`PalwAuthPreimageHash64` で分離。**writer 本体は無変更＝genesis hash 不動。**

### 4.2 0x38 authorization tx が可鍛（high）

clause 7 は authed root から 0x38 を除外し、`auth.hash()` は payload のみを覆う。よって
`lock_time` を変えるだけで **2^64 個の有効ブロックハッシュ**が作れた。コードコメントは
「出力を持たないので価値を動かさない」と主張していたが、**強制するコードが無かった**。

isolation で version / inputs / outputs / lock_time / gas / 宣言 mass を pin し、borsh
round-trip 一致も要求。再監査が **`mass` は AtomicU64 の内部可変で tx hash に入る**生きた可鍛軸だと
発見し、これも pin した。

### 4.3 §12′ supersession が自己申告値を信用（critical）

比較子が body/mergeset 座標で `cert.approving_stake` を読むが、そこでは
`verify_certificate_attestation` が未実行で bond view も無い。`u128::MAX` + ジャンク投票 1 本で
常勝できた。**§12′ を body 座標の機構として撤回**（§5.6.1 → §5.6.1a/b）。certificate window は
tally を bond view から再計算する attested 座標へ移動。

### 4.4 certificate が batch に未束縛（medium、ADR P1-4「部分 DONE」）

`resolve_palw_binding` が hash だけで証明書を解決していた。**resolver 内**に cross-check を
置いたので、現在および将来の全 caller が継承する（`CertBatchMismatch`）。

### 4.5 併せて

`LATEST_DB_VERSION` 7 → 8。store の「全 preset で inert（u64::MAX）」という正当化は**偽**だった
（testnet-palw-110 / devnet-palw-111 は `palw_activation_daa_score = 0` で毎ブロック書く）。

---

## 5. 残り P1（`e996761`）— 実装しないことが成果だった項目

### P1-14 残余 6 項目：完了

| ID | 処置 |
|---|---|
| ECON-02 | coinbase 出力上限を PALW の 3 出力に合わせる（`3·(k+1)+1`） |
| ECON-04 | **削除**。production 呼び出し元ゼロ、かつ production と最大 2 sompi 食い違う「第二の答え」だった |
| SS-04 | revocation を非遡及に。`is_block_eligible_at` と `retain` の**両方**（後者が第二の扉） |
| SS-05 | **据え置き（判断）**。誤った doc は既に修正済み、store は HOLD 源を明示して保持 |
| TGT-02 / TGT-03 | **削除**（`slot_digest` / `target_daa_interval` / `PALW_SLOT_DOMAIN`）。退役ドメインの「再利用禁止」はコメント → **テスト強制**へ |

### P1-8（DOS-01）: 実装せず ACTIVATION 級へ再分類

`check_pow_algo_id` は `validate_header_in_isolation` の 2 行目で、GHOSTDAG も `commit_header` も
走る前に algo-4 を弾く。pruning-proof 経路は lever と無関係に拒否する。**lever が閉じている限り
到達不能。**

閉じる道は 3 つとも再 genesis 級 — IBD 再設計 / Header v4 / §16 lane DAA との協調設計。
ADR §5.13 に「activation の未達前提条件」として記録。

### P1-10（PCPB）: 着手せず、原子スライス設計を §5.14 へ

`PalwPublicLeafV1` は bincode 永続化されるのでフィールド追加は DB version bump 必須、更新すべき
producer も不在。**ADR 自身の警告「半端に入れる方が危険である」**（P1-7 の差し戻しが実例）に従った。

副産物で実在の穴を修正: `PalwPublicLeafV1` / `PalwBatchManifestV1` は永続化されるのに layout pin
テストから漏れていた。

---

## 6. P1-5 / DOS-02（`e478600`）— cap ではなく削除で閉鎖

### 問題

`PalwBatchViewV1` は**毎ブロック clone + 永続化**される。`batches` には cap があるが
`job_nullifiers` には無い。しかも claim が**無条件**で、`apply_leaf_chunk` の戻り値は捨てられる。
よって**拒否された chunk も 64 個の nullifier を恒久 claim** する。

約 640 エントリ（72 B）/ブロック、攻撃者が選んだ expiry まで保持。攻撃コストは manifest 1 本
（`min_leaf_bond_sompi = 0`）＋通常の採掘のみ。`palw_algo4_accept` はこの経路を塞がず、PALW 2 preset は
`palw_activation_daa_score = 0` なので**共有ネットが動くまさにその preset で毎ブロック実行される**。

### なぜ cap ではなく削除か

3 案の設計パネルで **cap 案は敗退した**。この set には **reader が存在しない** — `claim_job_nullifier`
の戻り値は何も後続の無い `continue` に流れ、`job_nullifier_spent` に production reader が無い。
P1-9 の重複作業拒否は**元々強制されていなかった**ので、削除しても稼働中のものは何も失われない。
逆に cap は「何もしない機構」の encoding コストと攻撃面を温存する。

reader を配線するのも単なる配線作業ではない。first-claim-wins で所有権束縛が無いため、**どんな
reader も観測者に honest provider を 1 トランザクションで殺す手段を与える**。claim を leaf の bond
outpoint に束縛するには `ActiveBondView` が要り、それは view を動かせない virtual 座標にしか無い
（BIND-03 で確定済み）。

**P1-9 は body 座標から撤回（明示的な仕様変更）**、activation gate **G16 / P1-9-RELAND** へ再登録。
view は batch cap のみで有界: `≤ max_view_batches · (64 + 253) ≈ 325 KB`（実測 305 KB / 飽和時）。

`LATEST_DB_VERSION` 8 → 9（pin と daemon の upgrade arm も同時）。

---

## 7. 自分の監査が自分の退行を 2 度捕まえた（教訓）

本セッションで最も再発しやすい欠陥。**両方とも私が持ち込み、敵対監査が検出した。**

### 7.1 consensus 規則を実行時可変フラグで fence した

ECON-02 は当初、coinbase 出力上限を `palw_algo4_accept` で分岐させていた。このレバーは
`--palw-enable-algo4` で**実行時に変わる**一方、上限は algo-3 を含む**全 coinbase** を支配する。
フラグの有無が違う運用者同士が**通常の algo-3 ブロックの妥当性で不一致**になる — 抑えようとした
緩和より悪い、運用フラグ由来の**合意分裂**。

静的な `palw_activation_daa_score != u64::MAX` へ付け替え、両レバーの独立性を pin するテストを追加。

> **規則: 新しい consensus fence は必ず静的な preset 定数にすること。** 実行時に変わる値は不可。

### 7.2 「宣言された不変条件」に強制が無かった

`PalwBatchAdmissionParams::is_consistent_for_activation` /
`LaneDifficultyParams::is_consistent_for_activation` /
`PalwParams::is_structurally_valid`（doc に「config-build 時に呼ぶ」と明記）——
**3 つとも production 呼び出し元がゼロ**。全て手動保守の preset 配列に対する `#[test]` assertion で、
リストに追加し忘れた preset は誰にも検査されない。

`kaspad/src/daemon.rs` に起動時 preflight を新設（archival 拒否と同じ「省略ではなく拒否」原則）。

> **規則: コメントだけが守る境界は境界ではない。** doc が「呼ばれる」と書いたら、呼び出し元を作るか
> 記述を直すか、どちらかを必ず行う。

### 7.3 その他の再発防止

- **`cargo fmt -p <pkg>` はパッケージ全体を再整形する。** HEAD が rustfmt 未適用だったため、27 ファイルの
  無関係な reflow 差分が発生した。`git diff -w` は行分割を消さないので「-w が空 = fmt のみ」判定は誤り。
- **移植時は staged stat を元コミットと突き合わせる。** HEAD 側が空の衝突 hunk は「配置の曖昧さ」で
  あることが多く、丸ごと採ると**baseline のコードを過剰取り込み**する（実際に 316 行やった）。
- **要約された部分集合を producer に渡さない。** 9 スカラーで header を表現する構造こそが
  AUTH-02 の穴の作り方だった。Header を無損失で渡すこと。

---

## 8. 未解決（activation 前に必須）

いずれも**稼働中の穴ではない**（algo-4 が受理されないため）。ADR に記録済み。

| 項目 | 内容 |
|---|---|
| **DOS-01 / P1-8** | algo-4 header 受入にコスト関数が無い。P0-3 だけが押さえている。閉じるには再 genesis 級の設計が必要 |
| **P1-10 PCPB** | 未着手。原子スライス設計は §5.14 |
| **refuse-at-cap の検閲レバー** | 立ち退きは防ぐが**先占**は防がない。`min_leaf_bond_sompi = 0` で admission がほぼ無償なため、採掘できる攻撃者が expiry 窓の間 honest provider を締め出せる。価格付けは re-genesis 時の較正事項 |
| **CHUNK-INDEX SQUAT** | 観測者が chunk_index ビットを消費できる。P1-9-RELAND と同じ所有権束縛が必要 |
| **P1-9-RELAND / G16** | 重複作業拒否の再着地。所有権束縛が前提 |
| **SS-04 の二重表現** | `revoked_from_daa`（非遡及・production）と `PalwBatchStatus::Revoked`（終端・遡及）。`FraudEvidence` は production 参照ゼロなので**潜在的**。配線する者が先に解決する義務をコードに明記済み |

---

## 9. 次にやること

1. **`e996761` + `e478600` の移植**（実行中）。PR #53 に追加すれば DB bump が 1 回で済み、
   レビュアーが 2 度確認する必要もなくなる。
2. **PR #53 のレビューとマージ判断。** マージは運用判断を含む — 下記参照。
3. `feat/mil-v0` の push 要否（現状ローカルのみ）。

### マージ前に判断が要る点

- **`LATEST_DB_VERSION` 7 → 9 は PALW preset に限らず全ノードに DB wipe を要求する。**
  既存の testnet-10 ノードも再同期が必要。これはコードレビューではなく**運用判断**。
- コードは main に載るが **activation は別レバー**。`palw_algo4_accept: false` のまま出荷され、
  既存 4 ネットは `palw_activation_daa_score = u64::MAX` で挙動不変。
  ADR §7.1.1 の 3 レバー（land / accept / weight）のうち **land のみ**。

---

## 10. 検証基準値（2026-07-20 時点、`feat/mil-v0`）

```
consensus-core  413 passed + 1 ignored   （セッション開始時 404）
consensus       219 passed               （同 205）
kaspad           24 passed
mtp              21 / mtp-service  33 / dnsseeder 4
workspace      1841 passed / 0 failed
```

`cargo build --workspace` clean、`config::genesis` 通過、`palw_algo4_accept: false` × 6。

> 数値は手で書き換えず、必ず `cargo test -p <crate> --lib` を実行して転記すること。
> この種の行は同じ作業ツリー内でも古くなる。
