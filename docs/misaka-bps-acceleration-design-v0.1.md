# MISAKA BPS 加速(10→50)+ IBD 高速同期 設計書 v0.1

**版:** v0.1(draft — レビュー待ち)
**日付:** 2026-07-06
**対象:** `misakas` L1 コンセンサス(GHOSTDAG/DAG パラメータ)、p2p/IBD、DNS/PoS-v2 オーバーレイ、EVM レーンの各キャップ。対象コミット `3b5e986`。
**関連:** ADR-0005(mass 較正)、ADR-0007(PoW)、ADR-0008(Hash64)、ADR-0019(ML-DSA-87)、ADR-0020(EVM レーン / O13)、ADR-0022(pruned IBD の EVM/オーバーレイ snapshot)
**採択時:** 本書の合意事項は [ADR-0026](adr/0026-bps-acceleration-ibd-fast-sync.md)(パラメータ凍結)として要約を切り出す。

> このファイルは ADR-0026 の一次ソースとして配置している。以下、設計書 v0.1 本文。

## §1 目的と非目的
### 1.1 目的(Goals)
- **G1 — BPS 段階引き上げ:** testnet の blockrate を 10 → 25 → 40 → 50 BPS に段階的に引き上げる。各段で安全性前提(D=5s, δ=0.01)を維持し、**毎秒スループット包絡を不変に保つ**(worst-case 帯域 ≈ 6.3 MB/s、EVM 300M gas/s、L1 ≈ 250 tx/s 相当)。
- **G2 — IBD 高速化:** 50 BPS 時点(pruning 窓 5.4M ブロック)でも、フル同期の壁時計時間を **現行 10 BPS の実測ベースライン以下** に抑える(定量ゲートは §5.1 / §6)。
- **G3 — 移行の単純性:** 各段は barrier re-genesis で実施(前例: EVM v2 ヘッダ移行)。ライブフォーク経路(ForkedParam 化)は §4.3 として温存し、メインネット稼働後の BPS 変更に備える。

### 1.2 非目的(Non-goals)
- **NG1:** 50 超の BPS。`target_time_per_block` の µs 化、log 空間 k 算出への全面置換、mergeset/親数設計の見直し(≒ DAGKnight 級)を要するため対象外(§9 付録 A に理由を記録)。
- **NG2:** ボディの複数ピア並列ダウンロード(I-3 として将来枠に留める)。
- **NG3:** PoW(ADR-0007)、PQ 署名(ADR-0019)、EVM セマンティクス(ADR-0020/0023)の変更。キャップ数値のみ扱う。

## §2 制約と前提(コード検証済み)
現行は mainnet/testnet とも `blockrate: BlockrateParams::new::<10>()`(k=124, 100ms)。DAG パラメータは `consensus/core/src/config/bps.rs` の `Bps<BPS>` const 導出に一元化されている。以下は本設計の前提となる **構造制約の梯子**(いずれもコード上で確認済み):
1. **ms 約数制約:** `target_time_per_block()` は `1000 % BPS != 0` で const panic。有効値ラダーは …, 25, 40, 50, **100**, … と 50 の次が 100 に飛ぶ。
2. **k 算出の f64 限界:** `calculate_ghostdag_k` は `e^-x` が f64 で x ≳ 745 において 0 に潰れ無限ループ。D=5 では **BPS ≤ 74** までしか計算できない(50 → x=500 は余裕)。
3. **クランプ:** `max_block_parents` は 16 上限、`mergeset_size_limit` は 512 上限(ストレージ O(#headers × mergeset_limit) を理由とする upstream の意図的キャップ)。`KType = u16` は k=553 に対して十分。
4. **実運用律速:** 過去の独↔日 DAG 分断(λ·D_max ≲ k 違反)が示す通り、第一律速はネットワーク実効伝播。ブロック単位のサイズキャップが worst-case 伝播 = D の根拠を規定する。

**検証:** `calculate_ghostdag_k` を Python にポートし、既存テーブル(1→18, 10→124, 25→288, 32→362)との一致を確認した上で本書の k 値を導出している(§9 付録 A)。

## §3 ステージ・パラメータ設計
### 3.1 導出パラメータ(D=5s, δ=0.01)
`BlockrateParams::new::<BPS>()` が自動導出する値。**変更点は k テーブルへのエントリ追加と const generic の差し替えのみ**(diff は付録 C)。

| 項目 | 現行 10 | Stage A: 25 | Stage B: 40 | Stage C: 50 | 備考 |
| --- | --- | --- | --- | --- | --- |
| `target_time_per_block` | 100ms | 40ms | 25ms | 20ms | 1000 % BPS == 0 |
| `ghostdag_k` | 124 | 288 | 447 | **553** | x = 2·5·BPS, δ=0.01 |
| `max_block_parents` | 16 | 16 | 16 | 16 | k/2 はクランプ上限に張り付く |
| `mergeset_size_limit` | 248 | 512 (2k=576) | 512 (2k=894) | 512 (2k=1106) | 512 キャップ(O2) |
| `merge_depth` | 36,000 | 90,000 | 144,000 | 180,000 | 1h |
| `finality_depth` | 432,000 | 1,080,000 | 1,728,000 | 2,160,000 | 12h |
| `pruning_depth` | 1,080,000 | 2,700,000 | 4,320,000 | 5,400,000 | 30h(下限式は全段で PRUNING_DURATION 側が支配) |
| PMT sample rate | 100 | 250 | 400 | 500 | 窓サイズ自体は BPS 不変 |
| DAA sample rate | 40 | 100 | 160 | 200 | 同上(661 サンプル) |
| `coinbase_maturity` | 1,000 | 2,500 | 4,000 | 5,000 | 100s |
| year-1 subsidy/block (sompi) | 370,468,345 | 148,187,338 | 92,617,087 | 74,093,669 | `SUBSIDY_BY_MONTH_TABLE[0]` の div_ceil。毎秒排出不変(§4.2) |

### 3.2 包絡不変キャップ(ブロック建て定数の縮小)
ブロック建てのサイズ/実行キャップは BPS に自動追随しないため、**毎秒包絡一定** を原則に縮小する。これが D=5s 前提(=k の根拠)を守る実質条件。

| 項目 | 現行 10 | A: 25 | B: 40 | C: 50 | 包絡 |
| --- | --- | --- | --- | --- | --- |
| `max_block_mass` | 500,000 | 200,000 | 125,000 | 100,000 | 5.0M grams/s |
| `MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK` | 128 KiB | 48 KiB | 32 KiB | 24 KiB | ≈1.2 MB/s |
| `MAX_EVM_ACCEPTED_GAS_PER_CHAIN_BLOCK` | 30M | 12M | 7.5M | 6M | 300M gas/s |
| worst-case 帯域(header ~2KB 込) | 6.3 MB/s | ~6.3 MB/s | ~6.4 MB/s | ~6.3 MB/s | 不変 |
| worst-case ブロック | 618 KiB | ~245 KiB | ~156 KiB | ~124 KiB | 単発伝播も改善 |
| L1 tx/s 目安(ML-DSA 1-in/2-out ≈ 18k grams) | ~270 | ~275 | ~240 | ~250 | ほぼ不変 |

**注意(consensus 整合):** testnet は EVM genesis-active(`evm_activation_daa_score: 0`)のため、EVM payload / gas キャップの変更は **稼働中メッシュに対しては consensus fork** に相当する(gas-pool v2 の activation 運用と同種)。本設計では各段が re-genesis のため、キャップ変更は re-genesis に同梱して整合を取る。mainnet は inert(u64::MAX)なので ADR-0020 O13 の記述通り activation 前の数値変更は非 HF。

### 3.3 DNS / PoS-v2 オーバーレイ
- **`required_work_depth` — 変更不要。** blue work 建て(Uint576)であり、網全体の work/s は BPS に依存しない(ブロック難易度が 1/5 になるだけ)。したがって同一しきい値の wall-clock 到達時間・攻撃コストとも BPS 不変。これは設計上の利点としてそのまま維持する。
- **`epoch_length_blocks` / `attestation_epoch_length_blue_score`: 100 → 250 / 400 / 500(= ×BPS/10)。** ブロック建てのため放置すると実時間エポックが 10s → 2s に縮み、epoch-following poll の attestor に 5 倍負荷がかかる(DegradedStakeQualityLow の再発条件)。実時間 10s を維持する。attestor 側 SLO: エポック毎 attestation 欠落率 < 0.1%。
- **pruning point の移動速度が 5 倍**(ブロック数基準)になるため、ADR-0022 のオーバーレイ snapshot(`stake_bonds_store` / `reserve_balance_store` / `epoch_accumulator` / EVM state)の生成・転送頻度とサイズを IBD 計測項目に含める(§5.6)。

### 3.4 perf / p2p 追随
| 箇所 | 現行 | 変更 | 理由 |
| --- | --- | --- | --- |
| `PerfParams.header_data_cache_size` | 10,000 | 65,536 | 50 BPS で ~22 分ぶんを確保(現行値は ~3.3 分ぶんに劣化する) |
| `PerfParams.block_window_cache_size` | 2,000 | 8,192 | DAA/PMT 窓オブジェクトの余裕 |
| `block_data_cache_size` の `bps().clamp(1,10)` | ×10 上限 | `clamp(1, 50)` へ拡張 or 明示値 | 50 BPS でスケールが止まる |
| `MAX_ORPHANS_UPPER_BOUND`(flow_context.rs) | 1,024 | 4,096 | 50 BPS では ~20 秒ぶんしかない(10 BPS 時は ~100 秒ぶん)。分断復旧・バースト耐性 |
| relay flows(`bps/2`) | 自動 | 変更不要 | 25 並列に自動追随 |
| reachability(`DEFAULT_REINDEX_DEPTH=100`, slack 2^14) | 据え置き | 監視のみ | 挿入レート 5 倍による reindex スパイク頻度を M 指標化 |

### 3.5 自動整合(変更不要)項目
sampled DAA/PMT 窓サイズ(BPS 非依存)、`pruning_proof_m=1000`、`max_block_level`(難易度分布が log2(5)≈2.3 レベル下方シフトするだけで無害)、coinbase の `bps_history` 経由 subsidy 分割、`num_relay_flows`。

## §4 移行方式
### 4.1 採用: barrier re-genesis(段階ごと)
前例(EVM v2 ヘッダの barrier re-genesis)に倣い、各 Stage を新 genesis で立ち上げる。手順チェックリスト:
1. パラメータ commit(付録 C の diff 一式 + k テーブル拡張)
2. genesis 再計算(nonce/hash)。**suffix 運用は O7**: `NetworkId::with_suffix(Testnet, BPS)`(testnet-25 / -40 / -50)として旧メッシュとの誤接続を構造的に排除する案を推奨(P2P ポートの割当表を添付のこと)
3. シード(seeder1/2.misakascan.com)・全ノード・miner・attestor の一斉更新、faucet/premine 再投入
4. attestor 再ブート(epoch 定数変更の反映確認)、explorer/indexer の窓再設定
5. ゲート計測開始(§6)

### 4.2 排出整合
`pre_crescendo_target_time_per_block = 1000/BPS` として re-genesis すれば `bps_history = BPS/BPS`(定数)となり、per-block subsidy は genesis から `SUBSIDY_BY_MONTH_TABLE[i].div_ceil(BPS)`。**毎秒・毎月排出は 3.1 表の通り不変**(div_ceil 剰余は既存テストの許容範囲: 最大 (BPS−1) sompi/ブロック)。

### 4.3 温存: ライブフォーク経路(メインネット用)
`BlockrateParams` の struct コメントが想定する通り、**forked instance 化**(pre/post + activation)で mid-chain BPS 変更が可能。必要作業: (a) upstream Crescendo の ForkedParam 化 diff の移植(k / mergeset / merge_depth / finality / pruning の全コンシューマを score-aware 化)、(b) KIP-14 型 DAA 遷移(`MIN_DIFFICULTY_WINDOW_SIZE=150` の注記が既にこの用途)、(c) coinbase は `bps_history` が既にフォーク対応済みのため追加作業なし。本書のスコープでは設計のみ記録し、実装しない。

## §5 IBD 高速同期設計
### 5.1 ボトルネックモデルと SLO
IBD は headers-proof 同期(proof + pruning point anticone → L1 UTXO import(+ ADR-0022 の EVM/オーバーレイ snapshot)→ 前方ヘッダ/ボディ)。50 BPS の支配項は **pruning 窓 5.4M ブロックのヘッダ転送と処理**:
- ワイヤ量: 5.4M × ~2 KB(Hash64・16 親)≈ **10.8 GB**。単一 TCP ストリーム(現行 IBD は単一 syncer ピア)では独↔日 RTT ~250ms の cwnd 律速で 8–12 MB/s 程度 → **15–23 分が転送だけで消える**。同リージョンなら 2.5–5 分。
- 処理レート: 受信+検証+書込で **≥ 3,000 blk/s 持続** が 30 分完走の必要条件(A: 1,500 / B: 2,400)。

**SLO(空ブロック時、Stage ごとに計測):**
| ゲート | 定義 |
| --- | --- |
| 主ゲート(相対) | Stage A で実測したベースライン B_A に対し、C の IBD 時間 ≤ B_A × (5.4M / 2.7M) = 2×B_A を **下回る**こと(= I-1 の改善が窓拡大を相殺) |
| ストレッチ(絶対) | C: 遠隔(独↔日)≤ 30 分、同リージョン ≤ 12 分 |
| 載荷時 | 包絡飽和 24h 後の再同期で、遠隔 ≤ 2h(I-2 有効時 ≤ 45 分目標) |

### 5.2 I-0 — 運用層(ゼロコード、即日)
1. **TCP: BBR + バッファ拡大**(`net.ipv4.tcp_congestion_control=bbr`、`tcp_rmem/wmem` 最大値引き上げ)。高 RTT 単一ストリームの IBD には最も費用対効果が高い。
2. **同リージョン専用シード** を各拠点に 1 台(独・日)。IBD の syncer 選択が近接ピアに当たるだけで §5.1 の転送項が 1/4〜1/8 になる。
3. **`--ram-scale` 引き上げ + `--rocksdb-cache-size` 明示**(HDD プリセットは base 256MB × scale)、**`rocksdb_wal_dir` で WAL を別 NVMe に分離**(実装済みフラグ)。IBD 中の compaction stall を削減。
4. **ビルド:** `RUSTFLAGS="-C target-cpu=native"`。libcrux-ml-dsa(=0.0.9 pin)は SIMD 63.9µs vs portable 76.5µs(自前ベンチ)。`blake2b_simd` / `keccak?/asm` が default で有効なことをリリースビルドで確認(no-asm 経路の混入禁止)。

### 5.3 I-1 — プロトコル/キャッシュ小改修
| # | 変更 | 現行 | 案 | 補足 |
| --- | --- | --- | --- | --- |
| 1 | `IBD_BATCH_SIZE`(streams.rs:24) | 99 | 256(検証後 512) | gRPC メッセージ上限・請求フロー(`request_*` 系の `chunks(IBD_BATCH_SIZE)`)と同時に引き上げ |
| 2 | ヘッダ先読み深度(flow.rs の `prev_jobs` パターン) | 1 チャンク | 3 チャンク | `Vec<BlockValidationFuture>` を `VecDeque` 化し「受信 1 + 処理中 2」を常時維持。チャンク内はすでに block processor へ並列投入済みのため、受信の切れ目削減が主効果 |
| 3 | pruning UTXO 転送(v7/v8 `request_pruning_point_utxo_set`) | `CHUNK_SIZE=1000`、ack every 99 | 4,096 + 受信/適用のパイプライン化 | 受信タスクと store 適用タスクを分離 |
| 4 | `PerfParams` / orphan pool | §3.4 | §3.4 | IBD 中のヘッダ再読込と orphan 再解決ラウンドを削減 |
| 5 | スレッド明示 | 0(=論理コア) | `block_processors_num_threads` / `virtual_processor_num_threads` を物理コアへ | NUMA 環境では pin |

### 5.4 I-2 — DNS ファイナリティ・トラステッド同期(fork 固有の目玉)
**概要:** ノードローカル opt-in フラグ `--ibd-trust-dns-finality`(default: off)。attestor クォーラム署名済みの finalized `(blue_score, hash)` を DNS オーバーレイから取得し、IBD 中に `header.blue_score ≤ finalized_blue_score` のブロックボディについて **script/ML-DSA 検証のみをスキップ** する。PoW・ヘッダ連鎖・merkle・EVM コミットメント・pruning point の UTXO コミットメント検証は従来通り実施。

**実装アンカー(既存機構の再利用):**
- tx 検証フラグは既に 3 値存在: `TxValidationFlags::{Full, SkipScriptChecks, SkipMassCheck}`(`transaction_validator/tx_validation_in_utxo_context.rs:21`)。`utxo_validation.rs:267` には selected-parent に対する `SkipScriptChecks` 分岐の前例があり、**同分岐に `blue_score ≤ finalized && trust_flag` の条件を OR するだけの局所パッチ**で成立する。
- 信頼クラスの前例: pruning anticone の `validate_and_insert_trusted_block(TrustedBlock)`(consensus/mod.rs:908、ibd/flow.rs:533/855)。本機構はそれより弱い緩和(署名検証のみスキップ)であり、新しい検証カテゴリを作らない。

**信頼モデルと等価性の論証:** reorg gate(2-D dominance)は既に同一 attestor セットの署名を安全性仮定に組み込んでいる。IBD で同セットの finalized 署名を参照しても **新規の信頼仮定は追加されない**。attestor 鍵漏洩時の最悪ケースでも、(a) 状態遷移は pruning point の `utxo_commitment` 検証に拘束され、(b) フラグは default off かつノードローカル(consensus ルール不変・メッシュ内混在可)。O5: testnet default on / mainnet default off を提案。

**効果モデル:** スキップ量 = 窓内 tx 数 × ~64µs(ML-DSA verify)/ 並列度。空ブロックでは効果ゼロに近い(正直に明記)。載荷時(250 tx/s × 30h ≈ 27M tx)は単純計算 ~29 CPU-min/コア → 16C rayon で **~2 分の短縮 + virtual 経路の直列待ち解消**が主効果。ADR-0022 の snapshot import とは独立・併用可能。

### 5.5 I-3 — 将来枠(本書では設計のみ)
複数ピアからのボディ並列ダウンロード(syncer 多重化、上流未実装の大工事)。ヘッダ圧縮は Hash64 主体で圧縮率が低く優先度低。

### 5.6 計測ハーネス
新規ノード同期のタイミングスクリプト(fresh datadir → sync 完了までのフェーズ別時間: negotiate / proof / anticone / UTXO+snapshot / headers / bodies)、Prometheus 系メトリクス: headers/s、bodies/s、chunk RTT、RocksDB stall time、reindex 発火回数、orphan 数、ADR-0022 snapshot サイズ/転送時間。

## §6 段階計画とゲート
各 Stage: re-genesis → **soak ≥ 7 日** → 負荷試験(包絡飽和 24h: L1 tx スパム + EVM gas 飽和)→ 分断ドリル → exit 判定。

| Exit ゲート | Stage A (25) | Stage B (40) | Stage C (50) |
| --- | --- | --- | --- |
| mergeset size p99 / p999 | < 144 / < 288 | < 223 / < 447 | < 276 / < 553 |
| tips 平均(定常) | < 2·λ·d̂ かつ発散なし | 同左 | 同左 |
| orphan 率 | < 1% | < 1% | < 1% |
| virtual processing p99 | < 40ms | < 25ms | < 20ms |
| DAA | 目標間隔 ±10% 帯に 24h 収束・非発振 | 同左 | 同左 |
| 分断ドリル(60s 人為分断) | 自動回復 < 5 分、DAA 帯復帰 < 30 分 | 同左 | 同左 |
| attestation 欠落率 | < 0.1% | 同左 | 同左 |
| IBD | §5.1 SLO | 同左 | 同左(主ゲート必達) |

- **Stage A(testnet-25, k=288):** k テーブル既存範囲。I-0/I-1 を同梱し、IBD ベースライン B_A を確定。
- **Stage B(testnet-40, k=447):** テーブル拡張後の最初の未踏値。C の予行。
- **Stage C(testnet-50, k=553):** 現行アーキの実質上限。**O1 判定点**: mergeset p99 > k/2 が持続する場合、D=6(k=658)で再 genesis するか 40 BPS で確定する。
- 分断ドリルの回復容量根拠: mergeset 上限 512 × BPS/s(C で 25,600 blk/s 相当)≫ 生成レート。

## §7 リスク
| # | リスク | 影響 | 緩和 |
| --- | --- | --- | --- |
| R1 | 16 親クランプ ≪ 平均 tip 数(実効遅延 0.5–1s で 25–50)による log ラウンド合流 → 実効 D 増 | k 前提の侵食 | ゲート計測 + O1(D=6/k=658 予備値) |
| R2 | mergeset cap 512 < 2k(PHANTOM 前提からの逸脱) | 分断復旧の逐次化 | 回復容量 25,600 blk/s で実用充分。O2 で引上げ可否を保留 |
| R3 | reachability reindex スパイク(挿入 5 倍) | レイテンシ尾部 | 監視 + 必要時 slack/深度調整 |
| R4 | RocksDB 書込/compaction 増、ローリング DB 22–38 GB @C(空ブロック時) | I/O stall | NVMe 必須、WAL 分離、cache 拡大(I-0) |
| R5 | attestor poll 遅延(エポック定数の追随漏れ) | DegradedStakeQualityLow 再発 | §3.3 の ×BPS/10、SLO 監視 |
| R6 | f64 k 算出限界(BPS > 74 で不能) | 将来拡張阻害 | O6: log 空間版 `calculate_ghostdag_k` を併設 |
| R7 | EVM 実行が virtual 経路に直列(gas 6M が 20ms に収まらない負荷形状) | ブロック処理遅延 | gas 実測プロファイル、必要なら O3 で減額 |
| R8 | pruning point の移動 5 倍化による ADR-0022 snapshot 頻度/サイズ増 | IBD・アーカイブ影響 | §5.6 で計測項目化 |

## §8 未決事項(Open Decisions)
| # | 論点 | 案 | 決定タイミング |
| --- | --- | --- | --- |
| O1 | D=5 維持 vs D=6(k=658)@50 | まず D=5/k=553、ゲート計測で判定 | Stage C soak 後 |
| O2 | mergeset cap 512 維持 vs 引上げ | 512 維持を既定 | Stage C 分断ドリル後 |
| O3 | EVM per-chain-block gas 最終値(ADR-0020 O13 と統合) | 300M gas/s 包絡 → 6M @50 | Stage B 負荷試験後 |
| O4 | エポック実時間 10s 固定(×BPS/10) vs attestor 高速 poll 化 | ×BPS/10 を既定 | Stage A |
| O5 | trusted-IBD(I-2)の default | testnet on / mainnet off | I-2 実装時 |
| O6 | log 空間 k 実装の採否 | 併設(テーブル生成用) | 任意 |
| O7 | re-genesis の suffix/ポート運用 | suffix = BPS(testnet-25/40/50) | Stage A 前 |

## §9 付録
### 付録 A — k 導出と検証
PHANTOM 式(bps.rs 実装のポート)で x = 2Dλ、δ = 0.01。既存テーブル 1→18 / 10→124 / 25→288 / 32→362 の再現を確認済み。参考値: D=6 → k(50)=658、D=7 → k(50)=762、log 空間計算で k(100)=1074(現行 f64 実装では算出不能)。**50 超が非目的(NG1)である理由**: ms 約数ラダー(50 の次が 100)、f64 限界(BPS≤74)、k=1074 が mergeset cap の 2 倍超となり O(#headers×L) 前提が崩壊、の 3 点が同時に立つため。

`gen_ghostdag_table` を 33..=64 に拡張した場合のドロップイン値(f64 実装と同一アルゴリズムで算出):
```rust
33 => 373, 34 => 384, 35 => 394, 36 => 405, 37 => 415, 38 => 426, 39 => 437, 40 => 447,
41 => 458, 42 => 468, 43 => 479, 44 => 490, 45 => 500, 46 => 511, 47 => 521, 48 => 532, 49 => 542, 50 => 553,
51 => 563, 52 => 574, 53 => 584, 54 => 595, 55 => 605, 56 => 616, 57 => 626, 58 => 637, 59 => 647, 60 => 658,
61 => 668, 62 => 679, 63 => 689, 64 => 700,
```

### 付録 B — 帯域・ストレージ試算
- worst-case 帯域(§3.2 キャップ適用後): 全段 ~6.3–6.4 MB/s。空ブロック時の実流量はヘッダ ~2KB × BPS(C で ~150 KB/s)。
- ローリング DB(30h 窓、メタデータ ~4–7 KB/blk 想定・空ブロック時): A ≈ 11–19 GB、B ≈ 17–30 GB、C ≈ 22–38 GB。
- IBD ワイヤ量(ヘッダ): A ≈ 5.4 GB、B ≈ 8.6 GB、C ≈ 10.8 GB。

### 付録 C — diff スケッチ(ファイル別)
```rust
// consensus/core/src/config/bps.rs — ghostdag_k() の match に付録 A の 33..=64 を追記
// consensus/core/src/config/params.rs — Stage ごとに re-genesis で差し替え
blockrate: BlockrateParams::new::<50>(),          // A: <25>, B: <40>
pre_crescendo_target_time_per_block: 20,          // = 1000/BPS
max_block_mass: 100_000,                          // §3.2(A: 200_000, B: 125_000)
net: NetworkId::with_suffix(NetworkType::Testnet, 50),  // O7 採択時
// DNS オーバーレイ(TESTNET_DNS_PARAMS / PRODUCTION_DNS_PARAMS)
epoch_length_blocks: 500,                         // ×BPS/10(A: 250, B: 400)
attestation_epoch_length_blue_score: 500,         // 同上。required_work_depth は不変(§3.3)
// consensus/core/src/evm/mod.rs
pub const MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK: usize = 24 * 1024;   // A: 48K, B: 32K
pub const MAX_EVM_ACCEPTED_GAS_PER_CHAIN_BLOCK: u64 = 6_000_000;    // A: 12M, B: 7.5M
// consensus/core/src/config/constants.rs (perf)
const BASELINE_HEADER_DATA_CACHE_SIZE: usize = 65_536;
const BASELINE_BLOCK_WINDOW_CACHE_SIZE: usize = 8_192;
self.block_data_cache_size *= consensus_params.bps().clamp(1, 50) as usize;
// protocol/flows/src/flow_context.rs
const MAX_ORPHANS_UPPER_BOUND: usize = 4096;
// protocol/flows/src/ibd/streams.rs (I-1)
pub const IBD_BATCH_SIZE: usize = 256;
// protocol/flows/src/ibd/flow.rs (I-1) — prev_jobs を VecDeque 化し先読み深度 3 に
// consensus/src/pipeline/virtual_processor/utxo_validation.rs:267 (I-2)
let validation_flags = if is_selected_parent
    || (self.ibd_trust_dns_finality && header_blue_score <= dns_finalized_blue_score) {
    TxValidationFlags::SkipScriptChecks
} else {
    TxValidationFlags::Full
};
// + kaspad/src/args.rs: --ibd-trust-dns-finality (default false)
```

### 付録 D — 監視メトリクス一覧
mergeset size 分布(p50/p99/p999)、DAG tips 数、orphan 数/率、`virtual processing time` p50/p99、DAA 実測ブロック間隔、reindex 発火回数と所要、RocksDB stall/compaction 時間、IBD フェーズ別時間(§5.6)、attestation 欠落率、EVM 実行時間/chain block、snapshot サイズ(ADR-0022)。ゲート閾値は §6 の表を正とする。
