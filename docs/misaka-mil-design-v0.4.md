# MIL — MISAKA Inference Lane 設計書 v0.4

分散型GPU推論レイヤー: Akash型計算市場のLLM推論特化版 + TEE秘匿推論

対象: `MISAKA-BTC/misakas`（rusty-kaspa PQ-only fork / ML-DSA-87 / Hash64 = keyed BLAKE2b-512 / GHOSTDAG / DNSファイナリティ / EVMレーン計画）
ステータス: Draft（レビュー用）
日付: 2026-07-05
変更履歴: v0.2 — §13〜16 追補。v0.3 — §17〜19（Dolphin 3 / 差別化 / DAO更新）追補。v0.4 — misakas-main実コード（ADR-0018 §D/§E/§F）を確認し§5を実装準拠に改訂、§20 GPUアテステーション層（ComputeDepth・発行分配）を追加。旧「coinbase再分配c」オプションは§20に置換

> このファイルは [ADR-0024](adr/0024-mil-gpu-attestation-computedepth.md) の源泉設計であり、
> 実装状況は次の2平面で分かれる:
> - **推論市場平面(EVMレーン + データプレーン)** — `mil/` crate 群・`contracts/mil/` 契約群・
>   F003v0x03/F004/F005 precompile(fenced-inert)・TS/Swift SDK は branch `feat/mil-v0` に**実装済み**。
> - **セキュリティ発行平面(§20 ComputeDepth)** — 本文書 §20。base コンセンサス(fee split / reorg gate)を
>   変える HF 案で、**未実装**。ADR-0024 がその凍結。

---

## 0. 要約

misakas上にGPU計算市場を「LLM推論特化」で載せる。GPUプロバイダはLlamaをTEE（NVIDIA Confidential Computing）内で実行し、プロンプト・応答はML-KEM-1024 + AES-256-GCMでE2E暗号化する。平文が存在する場所はリクエスタ端末とGPU TEE内部のみで、ホストOS・プロバイダ運営者・ネットワーク・チェーンのいずれからも不可視。チェーン（コントロールプレーン）に載るのはHash64コミットメントとenclave署名レシートだけで、推論内容は一切載らない。

報酬原資は (1) 推論手数料（MSK建て市場価格）を主、(2) プレマイン由来のCompute Bootstrap Fundを立ち上げ補助とする。既存の15Bネットワーク発行（マイナー向けcoinbase）とDNSファイナリティ報酬オーバーレイ（バリデータ向け）のコンセンサスルールには当面手を入れず、推論手数料の一部をDNSバリデータプールとバーンに分配することで、既存2役（miner / validator）に第3役（GPU provider）を経済的に接続する。coinbase再分配（c ≤ 5〜10%）は将来オプションとしてHF keyingで残す。

標準スクリプトがML-DSA-87 P2PKHのみ（P2SH無効）である以上、ネイティブUTXOで条件付きエスクローは表現できない。よって決済ロジックの本命はEVMレーン契約（v1）であり、それまでは許可制テストネット運用（v0、DNSバリデータのsidecar/overlayパターンを踏襲）とする。

カノニカルAIは単一モデル**MIL-Core**（v1 = Dolphin 3.0 / Llama 3.1 8Bベース）とし、全プロバイダが同一重みを提供する。数ヶ月毎の更新は、再現可能ベンチ・ブラインドアリーナ・レッドチーム窓の3ゲートを通過した候補へのステーク加重DAO投票で行う（§17・§19）。対GPT/Claudeの差別化軸は素の知能ではなく、モデル来歴の暗号学的検証可能性・構造的no-retention・system prompt主権に置き、金融分析と開発支援はモデル分岐でなくAgent Profile層で分化させる（§18）。

---

## 5. 報酬設計

### 5.1 統合対象の現状（misakas-main実コード確認済み）

coinbase分配はADR-0018 §Fの3系統 × 3受取者（`FeeSplitParams`、bps建て、`consensus/core/src/dns_finality.rs`）:

| 系統 | worker（miner） | validator（§Eプール） | service（休眠） |
|---|---|---|---|
| subsidy（DNS Active, Stage 3） | **70%**（base 62 + inclusion 8〔§D bounty原資〕） | **30%**（25→30へ引上げ済み、再genesis同便） | 0 |
| subsidy（bootstrap期） | 90%（82 + 8） | 10% | 0 |
| normal tx fee | 90% | 10% | 0 |
| DNS finality fee（EVM_DEPOSIT_LOCK） | 25% | 75% | 0 |

§Eプールはエポック毎にfirst-includedバリデータへ**stake比例**（分母 = expected_stake）で分配され、未消化残余はdon't-mint（反キャプチャ）。serviceスロットは「Node報酬をSybil耐性欠如で廃止した跡地」としてborsh互換のため0で温存されている — §20はここを復活させる。GPU Providerは新設: 市場役 = EVM契約（§8）、セキュリティ役 = ネイティブoverlay（§20）の2平面。

### 5.2 原資の3層構造

**(a) 推論手数料（主・恒久）**: リクエスタがMSKで支払う市場価格。プロバイダのask掲示（モデルクラス毎、per-1k-in/out tokens）に対し最安マッチ。需要がそのまま原資であり、発行に依存しない。

**(b) アテステーション発行（恒久・§20）**: GPUプロバイダがバリデータと同型のエポック署名役務を負い、subsidyのcompute pool（休眠serviceスロットの復活、6%）から `min(bond, cap) / expected_compute_bond` 比例で受け取る。推論量ではなく**署名参加とボンド**への支払いとすることで、検証不能な「有用計算への発行補助」を排除し、ファーミングを構造的に封じる（Node報酬がSybil耐性欠如で廃止された前例への回答、§20.5）。

**(c) Compute Bootstrap Fund（時限・需要側へ再照準）**: v0.3までFundが担っていたアイドル電力の下支えは(b)の発行が引き受けるため、Fundはアリーナ費用（§19.3-G2）・faucet（§14.3）・fine-tune RFP（§19.2）など**需要側**のブートストラップ専用とする。原資はプレマインX%（キーセレモニー時に確定、変更不能）。旧v0.3の「coinbase再分配 c ≤ 10%」オプションは§20の設計で置換し、上限10%の考え方はcompute poolの将来上限として引き継ぐ。30Bキャップは不変（発行総量は増えない）。

### 5.3 手数料分配（パラメータ、初期値提案）

| 宛先 | 割合 | 趣旨 |
|---|---|---|
| Provider | 88% | 計算対価 |
| Burn | 5% | AI需要 → MSK希少性の連動（EIP-1559類似） |
| DNS Validator Pool | 4% | 決済保証（大口claimはDNSファイナリティ必須、§8.4）の対価。**既存valへの追加報酬**はここで実現 |
| Treasury | 3% | 監査・レジストリ運営 |

### 5.4 発行（compute pool）の分配 — §Eミラー

アテステーションのエポックはDNSと同一（100 blue score ≈ 10s @10BPS）。当該エポックでアテステーションtxがfirst-includedされたアテスタiへ、

```
reward_i = compute_pool_epoch × min(bond_i, bond_cap) / expected_compute_bond
```

を`compute_participation_outputs`（§20.4、§Eの`validator_participation_outputs`のミラー）で支払う。Σ支払い ≤ pool であり、**未消化残余はvalidator poolへ還流**する（滑走）。旧v0.3のBootstrap Fund分配式（g·u·q·√s）は発行側から退役し、GPUクラス・canary成績・レピュテーションは以後チャレンジ根拠（§20.5）と手数料側のマッチング優先度にのみ使う。canaryの集計窓は216,000 blue score（≈6h）を維持。

### 5.5 ステークとスラッシュ

| クラス | 最低ステーク（案） | 事由 → ペナルティ |
|---|---|---|
| A（H100+ CC, Tier1） | 500k MSK | 不正レシート（enclave鍵漏洩含む）→ 全額 |
| B（24GB+ VRAM, Tier2） | 100k MSK | Tier2出力不一致 → 50%（半分challenger、半分burn） |
| 共通 | — | タイムアウト/失踪 → 軽微スラッシュ + escrow全額refund。attestation失効放置 → 登録凍結（スラッシュなし） |

unbond遅延 = 7日（紛争窓口 + DNSファイナリティ余裕）。DNSバリデータの既存20Mボンドとは独立（兼業可）。

### 5.6 精算フロー

`open(max_cost lock)` → TTFB期限 → 512トークン毎レシート → `claim(最新レシート)`で累積分をいつでも引き出し → `close`または timeout refund。累積方式により持ち逃げ/踏み倒しを同時に封じる。プロバイダの最大露出 = 512トークン分の計算のみ。

---

## 20. GPUアテステーション層 — ComputeDepthと発行分配

### 20.1 原則: 発行はセキュリティ、手数料は推論

発行（subsidy）から「推論という有用計算」へ直接支払うと、需要が無い局面での支払い根拠が検証不能になり、ファーミングを招く — 実装がNode報酬を「Sybil-prone」として廃止した判断と同型の問題である。よってGPUプロバイダへの発行分配は、**バリデータと同一カテゴリの検証可能な役務 = エポック・アテステーション**への対価としてのみ行う。推論への対価は手数料（§5.3）に限る。この分離により「なぜGPUに発行を出すのか」への答えが「チェーンの改変防止に署名で参加しているから」という、オンチェーンで監査可能な事実になる。

### 20.2 役務: バリデータ同型のエポック署名（第3の確認次元）

コンピュート・アテスタは`kaspa-pq-validator-core`のミラー実装（`misaka-compute-attestor`）として、DNSバリデータと**同一のエポック（100 blue score）・同一のアンカー形式**でエポック境界のchain blockに署名する（ドメイン分離: `misaka-mil-v1/compute-attest`、エポック追従モードも同一）。これが第3の確認次元になる:

```
work_depth    ≥ required_work_depth      （PoW — 既存）
stake_depth   ≥ required_stake_depth     （DNS validator — 既存）
compute_depth ≥ required_compute_depth   （compute attestor — 本節、Phase Cで発効）
```

ボンドはバリデータと同じネイティブUTXO方式（bond txid:index参照、ML-DSA-87 P2PKH）。**アテスタ役 = ネイティブオーバーレイ、推論市場役 = EVMレーン**という2平面を明確に分離し、coinbase構築・検証がEVM状態に依存しない性質を守る（プロバイダは通常両方のボンドを積む。重複のUXはSDKが吸収）。

### 20.3 重みの基礎はボンド、FLOPSではない

合意上の重み（compute_depth寄与・発行取り分）は `min(bond_i, bond_cap)` に置き、計算能力そのものには置かない。計算力は時間貸しで調達可能（クラウドGPU）であり、FLOPS加重は攻撃コストを「数時間のレンタル費用」まで下げてしまう。ボンドはスラッシュ可能・unbond遅延付きの拘束資本として攻撃コストの下限を与える。GPU実在性（デバイス証明書・canary）は重みではなく**参加資格**に使う（§20.5）。

### 20.4 発行の配管 — 休眠serviceスロットの復活と滑走

`FeeSplitParams`のservice系フィールド（borsh互換のため0で温存中）をcompute poolとして復活させる。**フィールド追加ゼロ**。

| | 現行（DNS Active） | HF-MIL後（提案A・推奨） |
|---|---|---|
| subsidy worker（base + inclusion） | 62 + 8 = **70%** | **70%（不変）** |
| subsidy validator（§E） | **30%** | 名目 **24%**（実効 24〜30%、下記滑走） |
| subsidy compute（service復活） | 0% | **6%**（将来上限10%、ガバナンス/HF） |
| normal fee / finality fee | 90/10/0・25/75/0 | 不変（finality feeへのcompute参加はPhase Bで検討） |

分配は§5.4の式を`compute_participation_outputs`（§Eミラー）で実行し、**未消化残余をvalidator poolへ還流**する。効果: compute集合のボンド総量が`expected_compute_bond`に達するまで、バリデータの実効取り分は30%からcompute実払い分だけ漸減する滑走曲線になり、30→24の断絶的カットが起きない（misakastakeステーカー保護）。還流はマイナーに渡らないため§Eの反キャプチャ性質は保存される。数値参考: 初年度発行 ≈ 1.2B MSK → compute満額6% ≈ 72M MSK/年、validator下限24% ≈ 288M MSK/年。

代替案の比較: **B（worker 70→64から捻出）**はPoW予算と「miner stays majority」原則（コードコメント明記）に触る。**C（両側から3ずつ）**は政治的合意点だが原則が濁る。推奨はA — 25→30への引上げが買った「stakeファイナリティ強化」と同じ予算カテゴリ（ファイナリティ予算30%）の内側で、独立した第2アテスタ集合を購入する構図になるため。

§Dのworker inclusion bounty（8%プール、`worker_inclusion_bounty`）は対象証明書に**コンピュート・アテステーションtxを追加**し、第3集合の取り込みをマイナー報酬で買う（検閲耐性）。

### 20.5 Sybil耐性とスラッシュ — 廃止されたNode報酬の再生条件

Node報酬はSybil耐性の欠如で廃止された。compute poolが同じ轍を踏まない条件を3点で構成する:

1. **ボンド**: 参加自体に拘束資本（§20.3）。Sybil分割はbond_cap回避の意味しか持たず、cap設計で限界化する。
2. **デバイス束縛**: 登録txペイロードにTEEデバイス証明書ハッシュ（Tier1）またはcanary実測プロファイル（Tier2）をコミットする。虚偽・重複は誰でもチャレンジでき、立証時はPoS-v2の4-wayスラッシュ経路（reporter 10 / reserve 40 / victim 40 / burn 10）を転用して没収。canary（§4.3）は合意には入れず、チャレンジ根拠とレピュテーションに限定する — coinbase検証の決定性をEVM/オフチェーン状態に依存させないため。
3. **Equivocation**: 同一エポックで矛盾するアンカーへの二重署名は`kaspa-pq-signer`の反equivocation機構の検出対象とし、重スラッシュ。

### 20.6 ゲーティングの段階導入と限界の明示

**Phase A（記録・報酬のみ）**: compute_depthを計測・記録し発行を支払うが、リオルグゲートには入れない。ライブネスリスクゼロで集合の参加実績を蓄積する。

**Phase B（MIL内ゲート）**: 大口escrow claim（§8.4のDNSファイナル条件）に `compute_depth ≥ θ` を追加。GPU経済の決済をGPU自身のアテステーションが守る自己参照構造で、基層ファイナリティには影響しない。

**Phase C（TNS = Triple Nakamoto Security）**: リオルグゲートのANDに第3次元を追加。攻撃者は work AND stake AND compute の3次元同時多数を要し、攻撃コストは概ね加法的に積み上がる。発動はHFとし、参加率がクォーラム未満のエポックがK回続いた場合の**自動サスペンド（ヒステリシス付き）**を必ず併設してライブネス劣化を防ぐ（min_active_validators=1と同種の低参加リスクをここでも監査対象とする）。

**限界を隠さない**: AND合成の限界的な安全性向上は、stake集合とcompute集合の**独立性**に比例する。両集合が同一主体に占められるなら第3次元の追加安全性はゼロに漸近する。デバイス証明書は独立性の部分的担保（物理GPUの取得を要求）だが証明ではない。これはDNS論文レビューで指摘済みのseparation theorem課題と同根であり、ComputeDepth込みの合成定理とcost-of-attack下界はFC 2027追補の研究項目とする（§12-19）。

### 20.7 実装タッチポイント（misakas-main実コード）

| 箇所 | 変更 |
|---|---|
| `consensus/core/src/dns_finality.rs`（FeeSplitParams） | service系bpsをcompute poolとして復活: subsidy 2400/600設定。フィールド追加なし |
| 同（validator_participation_outputs） | `compute_participation_outputs`をミラー実装。分母 = expected_compute_bond、残余 → validator pool還流 |
| 同（work/stake depth・is_dns_confirmed） | `compute_depth` / `required_compute_depth` を追加（Phase Cまでゲート非参加） |
| 同（worker_inclusion_bounty） | 対象証明書にcompute attestation txを追加 |
| `consensus/core/src/config/params.rs`（fee_split preset） | 新bps。**メインネット未ローンチのうちは再genesis同便が最小差分**（25→30変更と同じ手筋）。ローンチ後ならactivation fence（pos_v2/EVMと同型） |
| `kaspa-pq-validator-core` | フォークして`misaka-compute-attestor`（差分 = ドメイン分離とボンドクラスのみ） |
| PoS-v2 slashing経路 / `kaspa-pq-signer` | デバイス証明チャレンジ・equivocationスラッシュに転用 |

---

> 注: §1〜§4・§6〜§19・付録は v0.3 から不変(本ファイルは v0.4 の差分核心 §5/§20 を保持)。
> v0.3 全文は実装済み crate 群(`mil/*`)・契約(`contracts/mil/`)・SDK に反映済み。
