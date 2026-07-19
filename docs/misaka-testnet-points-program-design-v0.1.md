# MISAKA Testnet ポイント・プログラム(MTP)設計書 v0.1

**版:** v0.1(draft — レビュー待ち)
**日付:** 2026-07-06
**対象:** MISAKA testnet(現行 testnet-10、以後 testnet-25/40/50 の各段を含む)における貢献活動のポイント化、計算システム、および TGE(mainnet 起動)時の MSK 配分設計。**testnet のみを対象とし、mainnet 上の活動は対象外。**
**関連:** [BPS 加速 + IBD 高速同期 設計書 v0.1](misaka-bps-acceleration-design-v0.1.md) / [ADR-0026](adr/0026-bps-acceleration-ibd-fast-sync.md)(Stage A/B/C・ゲート計測)、[ADR-0017](adr/0017-all-active-staker-attestation.md)(attestation 記録)、[ADR-0018](adr/0018-quality-gated-stakescore-inclusion-economics.md)(品質ゲートの先例)、`SECURITY.md`(脆弱性の私的開示)、`consensus/core/src/config/premine.rs`(vault 構造)
**表記:** コード上の単位名は KAS/sompi を継承しているが、本書ではトークン呼称を MSK に統一する。

> このファイルは [ADR-0027](adr/0027-testnet-points-program.md) の一次ソースとして配置している。

## §1 目的と非目的
### 1.1 目的
- **G1 — 貢献の定量化:** バグ報告・動作確認/フィードバック・ノード運営・ネットワーク安定化/インフラ貢献の 4 系統をポイント化し、TGE 時の MSK 配分に透明・検証可能な形で接続する。
- **G2 — BPS 計画との整合:** ポイントの重み付けを、BPS 10→50 段階計画のゲート計測が**実際に必要とする行動**(地理分散ノードの常時稼働、Stage ごとの IBD ベンチ提出、分断ドリル/負荷試験への参加、consensus/EVM/オーバーレイのバグ発見)に直結させる。プログラム自体が計測インフラの一部となる。
- **G3 — 単独運営で回る:** 週次バッチの決定的スコアリング + 署名付き公開台帳 + GitHub ベースの異議申立に限定し、恒常的な人手判断を最小化する。

### 1.2 非目的
- **NG1:** testnet コインへの価値付与(faucet 配布の testnet MSK は無価値のまま。ポイントとは無関係)。
- **NG2:** ポイントの即時換金・譲渡。精算は TGE 一括(§6)。
- **NG3:** 法的助言(§9 は注意喚起と未決事項の列挙のみ)。

## §2 設計原則
1. **決定性:** スコアは「収集済み事実 × 公開ルール」の純関数。ルールファイルのハッシュを各エポック台帳に刻み、同一入力からは誰でも同一台帳を再計算できる。
2. **検証可能性:** 台帳はプログラム運営鍵(ML-DSA-87)で署名して公開し、各得点に根拠(crawler サンプル、オンチェーン attestation、GitHub issue、tx id)をリンクする。
3. **シビル抵抗は「実コスト」で:** ノード得点は同期実体(tip 新鮮性)を要求する。Stage B/C では 40–50 BPS のフルノード維持自体が実コストであり、自然なシビル抑止になる。
4. **量より質:** ADR-0018 の品質ゲート思想を踏襲。低品質・重複・窓外の量産行為は 0 点または減点。
5. **裁量条項:** ポイントは非譲渡の会計単位であり、それ自体に価値・請求権はない。最終配分は運営裁量を留保する(§9 と連動した法的安全弁)。

## §3 対象活動カタログとスコアリング
**エポック:** 1 週間(UTC 月曜 00:00 起点)。**Stage 係数 m_stage:** Stage A(25 BPS)= ×1.0、Stage B(40)= ×1.25、Stage C(50)= ×1.5。全カテゴリに適用(高 BPS 段ほど参加コストとデータ価値が高いため)。

### 3.1 C1 — ノード運営(プール配分 40%)
| 活動 | 点数(/エポック) | 検証方法 |
| --- | --- | --- |
| フルノード稼働 | 100 × u × m_geo × m_ver × d_n | crawler(独・日 2 拠点から 10 分間隔で P2P handshake)。成功 = handshake OK ∧ 広告 sink の timestamp が 300 秒以内(**同期必須**)。u = 成功率 |
| validator / attestor 参加 | 200 × a | オンチェーン attestation 記録(ADR-0017 / `rewarded_epochs_store`)。a = 参加エポック率。**当該週に slashing/evidence 事象があれば週没収** |
| IBD ベンチ提出 | 50 / 回 | BPS 設計書 §5.6 のタイミングスクリプト出力 + ログ提出。Stage ごと最大 2 回(遠隔 1 + 同リージョン 1) |
| 分断/負荷ドリル参加 | 100 / イベント | 事前告知イベント(§7.3)への参加をノード ID で確認 |
- **m_geo = 1.5**: 独・日以外のリージョン(伝播多様性 = 50 BPS 計測にそのまま寄与)。
- **m_ver = 1.2**: リリース(re-genesis 含む)公開から 72 時間以内の追随(段階移行の一斉更新を誘導)。
- **d_n(逓減):** 同一 ID の 1 台目 ×1.0、2 台目 ×0.5、3 台目 ×0.25、4 台目以降 0。同一 /24 または同一 ASN は最大 2 台まで計上(§5)。

### 3.2 C2 — バグ報告(30%)
| 深刻度 | 例 | 点数 |
| --- | --- | --- |
| S0 Critical | consensus 分裂、資金喪失、PQ 健全性、リモートクラッシュ | 5,000 |
| S1 High | ノードクラッシュ/DoS、EVM state 分岐、オーバーレイ finality 障害 | 2,000 |
| S2 Medium | 同期失敗のエッジケース、RPC 不整合、リソースリーク | 500 |
| S3 Low | 軽微な不具合、docs、UX | 100 |
ルール: 初報のみ満点、重複は 10%。再現手順必須(なければトリアージ保留)。**脆弱性は `SECURITY.md` の私的経路必須** — 公開 issue 化した場合は没収。受理された修正 PR には同深刻度の点数を追加加点。トリアージは GitHub ラベル(付録 D)で行い、判断根拠を issue 上に公開する。

### 3.3 C3 — 動作確認・フィードバック(15%)
| 活動 | 点数 | 検証方法 |
| --- | --- | --- |
| テストキャンペーン完走 | 30–100 / 件 | Stage ごとに公開するチェックリスト(例: ML-DSA ウォレット送受金 E2E、EVM deposit-claim → withdraw、faucet → tx → explorer 突合)。tx id 等の証跡付き提出 |
| 受理フィードバック | 20–50 / 件 | 再現性・具体性のある報告(仕様提案含む)を maintainer がラベル付けで受理 |
| 負荷試験窓での tx 生成 | 1 pt / 受理 100 tx(上限 100 / イベント) | **告知済みの負荷試験窓内のみ**。chain-indexer が登録アドレスの受理 tx を集計。窓外のスパムは 0 点 |

### 3.4 C4 — ネットワーク安定化・インフラ(15%)
| 活動 | 点数(/エポック) | 検証方法 |
| --- | --- | --- |
| 公開シーダー/ブートストラップ | 150 | 登録制 + crawler 疎通 |
| 同リージョン IBD シード | 150 | BPS 設計書 I-0 §5.2 連動。帯域 SLO を満たす登録ノード |
| explorer / faucet / 監視ダッシュボード等の公開運用 | 100–300(tier) | maintainer 査定(公開 URL + 稼働確認) |
| docs・ツーリング・翻訳の受理 PR | 50–500 / 件(tier) | GitHub |

## §4 ポイント計算システム
### 4.1 構成
```
[registry] 登録(署名チャレンジ検証: kaspa-pq-validator-core 再利用)
[collectors]
  ├ p2p-crawler ×2 拠点(独・日): handshake / version / sink 新鮮性 → uptime サンプル
  ├ chain-indexer: attestation 参加率、負荷窓 tx 集計、slashing 事象(gRPC/ストア読取)
  ├ github-sync: issues/PR とトリアージラベル(付録 D)
  └ campaign-forms: キャンペーン/IBD ベンチ提出(証跡ファイル添付)
[scoring engine] 週次バッチ(UTC 月曜)。事実 → §3 ルールの純関数。ルール yaml + ハッシュ固定
[ledger] エポックごとの署名付き JSONL(付録 C)。misakascan + リポジトリ points/ に公開
[dashboard] misakascan 上のリーダーボード(表示は登録ハンドルのみ)
```
### 4.2 データスキーマ(SQLite)
`identities(id, github, address, registered_at)` / `nodes(node_id, identity, asn, subnet, region, kind)` / `uptime_samples(node_id, ts, vantage, ok, sink_ts)` / `attestations(identity, epoch, attested, slashed)` / `gh_events(identity, issue, label, points, ts)` / `submissions(identity, kind, evidence_uri, points, status)` / `epoch_scores(epoch, identity, c1..c4, evidence[])`

### 4.3 エポック処理
1. 月曜 00:00 UTC で収集締め → `inputs_hash`(全事実の BLAKE2b-512)確定
2. scoring engine 実行 → `epoch_scores`
3. 水曜までに署名付き台帳を公開
4. **7 日間の異議申立窓**(GitHub issue テンプレート、根拠リンク必須)
5. 確定。訂正はエポック再発行(旧版は保持し supersedes を明記)

### 4.4 再ジェネシス耐性
台帳・累積ポイントは**オフチェーン**であり、testnet-25/40/50 の barrier re-genesis を跨いで持続する。オンチェーン証跡(tx id、attestation)は network suffix 付きで参照する(例: `testnet-40:txid…`)。旧 suffix の証跡は当該 Stage の台帳でのみ有効。

### 4.5 実装規模
単一サービス(Rust 推奨、署名検証は `kaspa-pq-validator-core` 流用)+ cron。crawler は既存 seeder ホスト(独・日)に同居可能。見積り 1–2 週間。

## §5 本人性とシビル耐性
- **登録:** 参加者は `misakatest:` アドレスの ML-DSA-87 鍵でサーバ発行チャレンジに署名し、GitHub ハンドルと紐付ける(メッセージ形式は付録 B)。1 人 1 ID(自己申告 + 発覚時は全没収)。
- **ノード計上制限:** §3.1 の逓減 d_n に加え、同一 /24・同一 ASN は最大 2 台(登録済みインフラ枠を除く)。
- **同期実体の強制:** uptime サンプルは sink timestamp 300 秒以内を要求。ハートビート偽装ではなく実同期ノードのみが得点する。
- **個人上限:** 精算時、1 ID あたり総プールの **5%** を上限とし、超過分は同一カテゴリ内で再配分(§6.3)。

## §6 報酬配分設計
### 6.1 プール(O1)
**既定案: genesis premine から 100M MSK(premine 10B の ≈1.0%、総供給 25B の ≈0.4%)を MTP 専用枠として区分する。**(2026-07-20 改訂: premine は 40 vault × 0.1B + 9B main から **単一 10B main UTXO/ネットワーク** に再 genesis された。vault 構造は存在しないため「vault 1 本」表現は廃止。)追加の genesis 変更は不要で、プール規模は vault 本数に量子化されず任意額を main UTXO からの通常送金で切り出せる。

### 6.2 カテゴリ配分(O2)
C1 ノード運営 **40%** / C2 バグ報告 **30%** / C3 動作確認・FB **15%** / C4 インフラ **15%**。

### 6.3 精算式(TGE 時に一括)
```
reward_i = Σ_c  Pool · w_c · pts_{i,c} / Σ_j pts_{j,c}
```
適用順: (1) 上式で仮配分 → (2) 個人上限 5% でクリップ → (3) 超過分を同カテゴリの未クリップ参加者へ点数比で再配分(1 回のみ) → (4) 端数切捨て、残余はエコシステム枠へ。

### 6.4 権利確定と請求(O3)
- プールの 0.1% 超(= 10 万 MSK 超)を受け取る ID は **25% を TGE、残 75% を 6 ヶ月線形**。それ以下は TGE 一括。
- **請求フロー(PQ 鍵連続性):** 登録済み testnet 鍵で「mainnet 受取アドレス(`misaka:`)」を署名して提出。テストネットでの本人性がそのまま mainnet 請求の認証になる。
- TGE から 6 ヶ月未請求分はエコシステム枠へ返還。

### 6.5 ポイントの法的性格
ポイントは非譲渡・換金保証なしの会計単位であり、MSK 受領の権利を構成しない(最終配分は運営裁量。規約文言は §9/O4 の法務レビュー後に確定)。

## §7 運用
- **週次サイクル:** §4.3 の通り(締め → 公開 → 異議 7 日 → 確定)。
- **トリアージ SLA:** S0 24h / S1 72h / S2–S3 ベストエフォート(単独運営のため、SLA はトリアージ着手までの時間とする)。
- **イベントカレンダー:** Stage A/B/C の soak・負荷試験(包絡飽和 24h)・分断ドリル(60s)・IBD ベンチ窓を **BPS 設計書 §6 の日程と同一のカレンダー**で事前告知する。ドリル参加点(C1)と負荷窓 tx 点(C3)はこのカレンダー掲載イベントに限る。
- **期間:** プログラム開始 〜 TGE。累積スナップショットを毎月公開。
- **中間インセンティブ(任意・無価値):** リーダーボード表彰、Discord ロール、mainnet 初期 allowlist 等。金銭価値のある中間配布は行わない。

## §8 リスクと対策
| # | リスク | 対策 |
| --- | --- | --- |
| R1 | uptime ファーミング(未同期ノード・多重立て) | tip 新鮮性 300s、逓減 d_n、/24・ASN 上限、高 BPS 段の実コスト |
| R2 | バグ報告の量産・重複スパム | 初報のみ・重複 10%・再現手順必須・S 判定はラベルで公開 |
| R3 | 負荷 tx ファーミング | 告知窓内のみ加点 + 上限 100 pt/イベント |
| R4 | トリアージの単独集中(恣意性疑義) | 判断根拠を issue 上で公開、異議申立窓、ルール yaml のハッシュ固定 |
| R5 | 台帳改竄・遡及変更の疑義 | inputs_hash + rules_hash + ML-DSA 署名、訂正は supersedes 付き再発行 |
| R6 | 報酬期待に起因する法的リスク | §6.5 の性格規定 + §9 の法務レビューを公表前提条件とする |
| R7 | 集中(1 ID がプールを占有) | 個人上限 5% + カテゴリ内再配分 |

## §9 法務・コンプライアンス(注意喚起 — 法的助言ではない)
TGE 時のトークン配布は、受領者の居住地により税務・規制(日本では資金決済法/金融商品取引法上の整理、交換業該当性、贈与・雑所得課税等)に服し得る。**本プログラムの公表前に、(a) 地域適格性(制裁対象・特定法域の除外)、(b) KYC 要否としきい値、(c) 規約文言(ポイント無価値・裁量条項・変更権)、(d) 配布方式(自己請求型 vs 送付型)について法務レビューを必須とする(O4)。** 本書はスキーム設計のみを規定する。

## §10 未決事項(Open Decisions)
| # | 論点 | 既定案 | 決定タイミング |
| --- | --- | --- | --- |
| O1 | プール総量と原資 | 10B premine からの 100M MSK 切り出し(≈0.4% of 25B) | 法務レビュー後・公表前 |
| O2 | カテゴリ配分 | 40/30/15/15 | 公表前 |
| O3 | 個人上限・vesting | 5% / 25%+75% 6M 線形 | 公表前 |
| O4 | 地域適格性・KYC・規約 | — | 法務レビュー(公表の前提条件) |
| O5 | ASN/逓減の係数 | §3.1/§5 の値 | Stage A 実測後に再調整可 |
| O6 | S0–S3 の点数と私的開示運用 | §3.2 | 公表前(SECURITY.md へ追記) |
| O7 | heartbeat 併用の要否 | crawler のみで開始 | Stage A 後 |
| O8 | 中間表彰の内容 | 無価値特典のみ | 任意 |

## §11 付録
### 付録 A — 計算式まとめ
```
pts_node(epoch)      = 100 · u · m_geo · m_ver · d_n · m_stage
pts_validator(epoch) = 200 · a · m_stage        (slashed週は 0)
pts_bug              = S(severity) · (初報 ? 1.0 : 0.1) · m_stage   (+ 修正PR受理で S を追加)
pts_c3, pts_c4       = §3.3 / §3.4 の固定値 · m_stage
reward_i             = Σ_c Pool·w_c·pts_ic/Σ_j pts_jc → 5% cap → カテゴリ内再配分
```
### 付録 B — 登録・請求メッセージ形式(ML-DSA-87 署名対象)
```
MISAKA-TESTNET-POINTS-REGISTRATION v1
network: testnet-25
github: <handle>
address: misakatest:qq…
nonce: <server-issued 32B hex>
issued_at: 2026-07-06T00:00:00Z
```
```
MISAKA-TESTNET-POINTS-CLAIM v1
identity: gh:<handle>
mainnet_address: misaka:qq…
total_points_ack: <確定台帳の合計>
nonce: <server-issued 32B hex>
```
### 付録 C — エポック台帳エントリ(JSONL)
```json
{
  "epoch": 12,
  "range": ["2026-09-21T00:00:00Z", "2026-09-28T00:00:00Z"],
  "network": "testnet-40",
  "rules_hash": "b2b512:…",
  "inputs_hash": "b2b512:…",
  "scores": [
    {"id": "gh:alice", "c1": 152.5, "c2": 0, "c3": 60, "c4": 150,
     "evidence": ["crawler:node_ab12/u=0.97", "gh:misakas#241", "campaign:evm-e2e-04"]}
  ],
  "sig_mldsa87": "…"
}
```
### 付録 D — GitHub ラベル定義
`sev/S0..S3`(深刻度)、`points/accepted`、`points/duplicate-of-#N`、`points/rejected`(理由コメント必須)、`points/needs-repro`、`campaign/<id>`。
### 付録 E — BPS 計画との対応表
| BPS 設計書のゲート計測 | 供給源となる MTP 活動 |
| --- | --- |
| IBD SLO(M-IBD、遠隔/同リージョン) | C1 IBD ベンチ提出 |
| 分断ドリル回復・orphan 率 | C1 ドリル参加ノード群 |
| mergeset p99 / tips(地理分散下) | C1 常時稼働ノード(m_geo が分散を誘導) |
| 包絡飽和 24h 負荷試験 | C3 負荷窓 tx 生成 |
| Stage 移行の一斉更新(re-genesis) | C1 m_ver(72h 追随ボーナス) |
| consensus/EVM/オーバーレイ欠陥の発見 | C2(S0–S1) |
