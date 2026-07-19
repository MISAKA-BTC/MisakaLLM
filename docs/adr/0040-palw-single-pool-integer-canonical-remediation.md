# ADR-0040 — PALW 単一プール整数正準化: remediation + 仕様凍結 + activation gate + testnet ladder

- **Status:** Proposed（**activation 禁止**。本 ADR は停止措置と remediation 順序を定める文書であり、活性化許可ではない）
- **Date:** 2026-07-19
- **Supersedes / amends:**
  - [ADR-0039](0039-palw-replica-gemm-audited-compute-lane.md) — §8（k=2 匿名配送と provider 選択）、§10.2（auditor 選出）、§17（coinbase）の各一部を改訂
  - [`docs/design/misaka-palw-replica-gemm-v0.2.md`](../design/misaka-palw-replica-gemm-v0.2.md) §10.2 — auditor 抽選の outpoint 単位を credential 単位へ
  - [`docs/design/misaka-canonical-compute-v1.md`](../design/misaka-canonical-compute-v1.md) §15（tier 順序）、§18（初期 2 class）、§19.8（cross-vendor pool）— 下記 §3.6 の決定により改訂
- **Consumes:** 外部監査 2 本（`PALW_Node_Consensus_Security_Audit_2026-07-19`、`PALW_3Vendor_SelfOrder_Verification_Audit_2026-07-19`）と外部仕様 `PALW_QW36_INT_W4A8_Formal_Spec_v0.1`
- **対象ツリー:** `feat/mil-v0`（本 ADR の行番号の基準）および `feat/dns-dormancy-core-on-main`（`consensus/core/src/palw.rs` が +15 行オフセット、`mil/miner/` を追加で持つ）。**両ツリーに remediation が必要**

---

## 0. 本文書の位置づけと検証方法

本 ADR は 3 つの入力を 1 本に統合する。

1. **PALW consensus 監査**（7 Critical / 12 High / 6 Medium）
2. **3 ベンダー自家発注・検証監査**（10 実装所見 + 4 仕様修正）
3. **QW36-INT-W4A8 正式仕様 v0.1**（凍結対象）

**検証方法。** 両監査の主張を実コードに対して行単位で再検証し、さらに 5 レンズ（binding / arithmetic /
store-state / DoS / economics）の独立スイープを行い、各所見を敵対的反証にかけた。**43 件が反証を生き残り、
7 件が棄却された。**

さらに**本 ADR 自身を 4 レンズ（matrix 精度 / gate 判定可能性 / S0 階層 / 内部整合）で敵対的レビューにかけ、
23 件の欠陥を検出して修正した。** 主なものは (a) accept lever の解除条件が 3 箇所に書かれ互いに 2 Critical
分ずれていたこと、(b) §3.3 の committed K 境界が未強制の W4 域に依拠していたこと、(c) `runtime_class_id`
除去が 1 箇所ではなく 5 箇所であること。**これらは初稿に実在した欠陥であり、修正済みである。**

最後に **§2.6 の強制点走査を実施**し、7 件の gap を検出（11 件棄却、**84 件を CLEAN として明示確認**）。
うち 1 件（SAMPLE-01）は、**既存 ADR-0039 が達成済みとして記録している remediation が実際には
片翼しか実装されていない**ことを明らかにした（§2.6.2）。

監査報告の引用パスは実在しない（`mil/palw/src/palw.rs` 等）。これは**陳腐化ではなく書誌上の誤り**であり、監査は別ブランチ（`feat/dns-dormancy-core-on-main`、`validate_certificate` が L1980）を対象としていた。同関数の本体は両ツリーで**バイト同一**であるため、両監査とも内容は現行である。

**棄却された 7 件**は本文書の matrix に載せない（記録は §2.4）。監査の信頼度を下げるためではなく、remediation の優先度を正しく保つためである。

---

## 1. 中核判断 — なぜ単一プールなのか

### 1.1 一次資料

現行コードは**ハードウェア多様性を合意上の要件にしている**。[`mil/core/src/palw.rs:250`](../../mil/core/src/palw.rs):

```rust
// Diversity is REQUIRED, not merely allowed: the two replicas must be different classes.
&& self.runtime_class_id != other.runtime_class_id
```

その 2 行下に、なぜ token しか比較しないかの理由が書かれている。

```rust
// NOT compared: `canonical_gemm_trace_root` AND `operation_schedule_commitment` — both are
// class-dependent (raw fp32 kernels / tile schedule) and diverge cross-vendor by design; the only
// cross-vendor invariant is the token `output_commitment` (the argmax answer).
```

これが弱点の因果関係そのものである。

```text
カーネルが浮動小数点
        ↓
execution root が cross-vendor で本質的に乖離
        ↓
argmax token 比較へ後退
        ↓
独立性の代理としてハードウェアラベルの相違を後付け
```

**数学が支えられなかったから、看板が耐荷重になった。** 上記 2 つのコメントは、その経緯の一次資料である。

### 1.2 整数ドメインが解消する

execution root が cross-vendor 不変になった瞬間、全 root を比較できる。比較できるようになった時点で、ハードウェア多様性要件は**不要**（root 一致がより強い証拠）かつ**執行不能**（ベンダー名は自己申告であり permissionless に証明できない）の両方になる。

したがって述語の削除は厳密に正しい。**単一プール化は三ベンダー設計の緩和ではなく、整数ドメインが獲得する当然の帰結である。**

### 1.3 最終構成

```text
QW36-INT-W4A8-V1
        │
        ▼
単一 Canonical Compute Class      (compute_set_id — 合意対象)
        │
        ▼
単一 Bonded Provider Registry     (credential 単位 — 合意対象)
        │
        ├─ 今回は A として実行
        ├─ 別ジョブでは B として複製
        └─ 別 batch では Auditor として監査
```

役割は future beacon で一時割当する。**単一プールとは「A が自分で自分を承認できる」という意味ではない。全員が同じ登録集合に属し、各ジョブの役割だけを commit 後の乱数で分ける、という意味である。**

NVIDIA / AMD / Apple / CPU reference の違いは、正準結果が一致する限り合意層には関係しない。

---

## 2. 統合 finding matrix

**Reachability の定義。** `PROD` = 活性化 preset（`testnet-palw` / `devnet-palw`、`palw_activation_daa_score = 0`）で到達可能。`PRIM` = プリミティブに欠陥は実在するが production 呼び出し元がゼロ。`DOC` = 設計文書のみ。

**Fence 状態（検証済）。** mainnet / testnet-10 / simnet / devnet は `palw_activation_daa_score = u64::MAX`（inert）。`testnet-palw`(110) / `devnet-palw`(111) のみ activation = 0、`palw_compute_work_scale = 0`。したがって **mainnet 露出はゼロだが、PALW preset 上では PROD 所見は現に到達可能である。**

> **注記（陳腐化コメント）。** `body_validation_in_context.rs:85` の「Inert on every shipped preset」は**誤り**。`consensus/core/src/config/params.rs:1337/:1385` が PALW preset で activation = 0 を設定している。

### 2.1 Critical（activation 前に必須）

| ID | 所見 | 位置 | 到達性 |
|---|---|---|---|
| **BIND-01** | leaf blob が `manifest.leaf_root` に一度も照合されない。`palw_leaf_root()` は非テスト呼び出し元ゼロ。任意の者が任意の Active batch へ leaf を注入でき、**lane の PoW 全体（clause 9）がオフライン grind 可能** | `consensus/src/processes/palw.rs:127` | PROD |
| **CERT-01** | `validate_certificate` は version / vote 数 / epoch 順序 / **署名長** / outpoint 順序のみ検査。ML-DSA 署名・auditor stake・quorum・`manifest_hash` / `leaf_root` は未検証。正しい長さの偽署名 cert が受理される | `consensus/core/src/palw.rs:1965` | PROD |
| **LEAF-01** | leaf store は `(batch_id, leaf_index)` へ plain write（put-if-absent 無し）。報酬時に **mutable な現 leaf を再読込**するため、受理後の上書きで報酬先を差し替え可能（77% worker base） | `consensus/src/model/stores/palw.rs:155`<br>`utxo_validation.rs:405` | PROD |
| **ECON-01** | **coinbase poison / chain bricking。** leaf の reward script は長さ 1024 のみ検査。だが coinbase output は ML-DSA-87 P2PKH のみ・150 バイト以下が必須。非 PQ または 151〜1024 バイトの script を持つ leaf は受理されるが、導出される coinbase が isolation 検証に落ち、**algo-4 source を merge する全ブロックが恒久的に無効化** | `consensus/src/processes/coinbase.rs:186` | PROD |
| **DOS-01** | algo-4 header は Layer-0 PoW を**完全免除**。header 段階の全 store write（**O(nullifier-retention) の BTreeMap clone + persist を毎 header**）が無償。`palw_compute_work_scale = 0` のため compute cap は**構造上一度も発火しない** | `pre_ghostdag_validation.rs:178` | PROD |

### 2.2 High

| ID | 所見 | 位置 | 到達性 |
|---|---|---|---|
| AUTH-01 | **block authorization が完全に死んでいる。** `palw_authorization_hash` は生成も比較もされない。`PalwBlockAuthorizationV1` は構築箇所ゼロ・`signing_hash` 無し・block body 転送経路（subnetwork）無し。**「計算されるが検証されない」より強く、そもそも計算されない** | `consensus/core/src/palw.rs:1220` | PROD |
| AUTH-02 | `eligibility_hash` は**ブロック内容を一切 bind しない**（parents / merkle root / coinbase / header hash を含まない）。当選 header は raw nullifier を開示するため、**観測者が同一当選から任意の競合ブロックを無制限に再鋳造できる** | `consensus/core/src/palw.rs:264` | PROD |
| AUTH-03 | `leaf.ticket_authority_pk_hash` は production 読み手ゼロ。`PalwTicketBinding` に射影されず、いかなる述語にも到達しない | `consensus/core/src/palw.rs:873` | PROD |
| TGT-01 | PALW target interval は**chain state から導出されず header から読まれる**（I-3 が空文化） | `body_validation_in_context.rs:148` | PROD |
| BIND-02 | `PalwBatchLifecycleV1.cert_hash` / `leaf_root` / `leaf_count` は view に書かれるが**一度も比較されない**。header の cert 参照は `cert_hash.is_some()` のみを要求 → **store 内の任意の cert blob が任意の header を充足** | `consensus/core/src/palw.rs:2206` | PROD |
| BIND-03 | body 段の解決先 store は virtual commit 時にのみ書かれ、batch view は mergeset・blob は acceptance と**2 つの座標系が不一致** | `body_validation_in_context.rs:144` | PROD |
| BIND-04 | PALW overlay state に pruning-point / trusted-block import 経路が無い。virtual 段で leaf 欠落 panic、空 view で algo-4 を恒久拒否 | `utxo_validation.rs:405` | PROD |
| DOS-02 | `commit_palw_overlay_view` が**acceptance フィルタ無し**に全 mergeset-blue tx の PALW effect を fold → never-accepted / 手数料無し / 二重支払 tx が view を変更 | `body_processor/processor.rs:356` | PROD |
| VIEW-01 | `commit_palw_overlay_view` は `mergeset_blues.filter(!= selected_parent)` を fold するが、**ブロック自身は自分の mergeset に含まれない**ため、**自 body の PALW effect が自 view に入らない**。同一ブロックで登録した batch を同一ブロックの ticket が参照できない。意図的な可能性はあるが**文書化されておらず、C-03 の指摘の半分はこちら** | `body_processor/processor.rs:356` | PROD |
| DOS-03 | `PalwBatchViewV1` に batch **数**の上限が無い。毎ブロック clone + persist するため、手数料のみで律速される manifest flood が増幅 | `body_processor/processor.rs:352` | PROD |
| DOS-04 | `admission_valid` が `activation_not_before_epoch` に上限を課さないため、view entry を恒久 pin 可能 | `consensus/core/src/palw.rs:973` | PROD |
| SS-01 | `PalwPrunedFrontier` store は writer / reader ともにゼロ → PALW preset で pruned / trusted IBD が 3 箇所の fail-closed panic に当たる | `consensus/src/model/stores/palw_pruned_frontier.rs:52` | PROD |
| DA-01 | `receipt_da_root` の**提供義務に強制点が無い**。設計 §10.5 は fraud window 中の P2P 取得可能性を要求し、§5 は DA 拒否を自動 slash 可能な客観的 fault と宣言するが、DA object 仕様・時間境界・P2P request message・challenge tx のいずれも存在しない。**義務を負ったように読める空の root** | `consensus/core/src/palw.rs:875` | PROD |
| SAMPLE-01 | `audit_sample_root` は非テスト読み取りゼロ。doc は consensus が独立再導出すると**直説法で**述べるが実装は無く、**ADR-0039 R2 は達成済みと記載**（§2.6.2） | `consensus/core/src/palw.rs:1010` | PROD |
| AUTHSET-01 | `auditor_set_commitment` は repo 全体で読み手ゼロ。auditor 集合が beacon 選出であるという設計 §10.1/§10.2 の主張に強制点が無い | `consensus/core/src/palw.rs:1156` | PROD |
| SEL-01 | provider / auditor 抽選が **bond 加重でない**。`auditor_score` は outpoint 単位ハッシュ順、`provider_index` は一様。**最低 bond も無い**（`amount_sompi != 0` のみ）ため bond 分割が無償 → 100 分割で抽選券 100 枚 | `consensus/core/src/palw.rs:2490`, `:2527`, `:1896` | PRIM |
| PCPB-01 | PCPB が ticket 検証に接続されていない。`palw_challenge_fresh` / `palw_pcpb_derive_b` / `palw_dispatch_proof_valid` は production 呼び出し元ゼロ。`PalwPublicLeafV1` に challenge commitment / A_commit / snapshot root / dispatch proof / assignment proof が**全て存在しない** | `consensus/core/src/palw.rs:146` | PROD |
| INT-01 | **整数 oracle が自身の凍結規則に違反。** `canonical_int_gemm` は `&[i8]`（−128 を許容）を取るが doc は `K·127²` 境界を前提。accumulator 境界 assert 無し、overflow flag 無し。**release で無警告 wrap、debug で panic** → ビルド構成で結果が変わる | `mil/core/src/palw_canonical.rs:49` | PRIM |
| MATCH-01 | `runtime_class_id` は `gpu_arch_class` と `kernel_graph_hash` を構造的に含み、さらに **Qwen backend が trace root を `runtime_class_id` から導出**している → cross-backend の trace 一致は構造上不可能 | `mil/core/src/palw.rs:138`<br>`qwen_backend.rs:158` | PRIM |
| ECON-03 | 77% provider base が**解決済み担保ゼロ**に対して支払われる。provider-bond tx は consensus state を生まず、leaf bond outpoint は解決されない | `consensus/src/processes/palw.rs:113` | PROD |

### 2.3 Medium / Low（抜粋）

| ID | 所見 | 位置 | 到達性 |
|---|---|---|---|
| AO-02 | `apply_leaf_chunk` が固定 256-bit bitmap を添字。**出荷 params では到達不能**（`max_batch_leaves` が bitmap 幅以下に制約される）が、params 変更で潜在化する。**latent** | `consensus/core/src/palw.rs:2348` | PRIM |
| AO-03 | `lane_expected_bits` / `lane_retarget_bits` が未証明の `min_samples >= 1` 前提 → 空 unwrap と Uint320 ゼロ除算。**出荷値 `min_samples: 60` かつ `is_consistent` が window 以下を強制するため到達不能。latent（誤設定時のみ）** | `processes/difficulty.rs:338` | PRIM |
| QUORUM-02 | `beacon_quorum_reached` は `den == 0` と `committed_stake == 0` を守護するが **`num == 0` を守護しない** → RHS が 0 となり vacuously true。姉妹関数 `quorum_reached` と**独立の**未計上欠陥 | `consensus/core/src/palw.rs:728` | PROD |
| SHAPE-01 | `check_palw_header_shape` / `ensure_all_palw_fields_zero` が未実装 → 活性化後、algo-3 header が任意の非ゼロ PALW field を持てる（v3 hash preimage には入る） | `pre_ghostdag_validation.rs:73` | PROD |
| SLASH-01 | §12.4 cross-fork 二重使用 slashing に evidence 型・verifier・penalty 経路のいずれも無い。`SUBNETWORK_ID_PALW_SLASHING` を decode する箇所が無い | `consensus/core/src/palw.rs:1218` | DOC |
| ECON-02 | PALW blue source は最大 3 coinbase output を出すが、cap は blue source あたり 1 output 想定の `ghostdag_k + 2` | `processes/coinbase.rs:177` | PROD |
| ECON-04 | `provider_pair_split` の bps 直乗算が production の剰余ベース分割と数 sompi 食い違う | `consensus/core/src/palw.rs:2575` | PRIM |
| SS-04 | revocation が完全に遡及的でエントリを削除。`revoked_from_daa` が何とも比較されない | `consensus/core/src/palw.rs:2233` | PRIM |
| SS-05 | `DbPalwLaneBitsStore` は「毎ブロック書かれる」と doc が主張するが writer ゼロ → lane retarget の HOLD source が genesis bits に恒久固定 | `consensus/src/model/stores/palw_lane_bits.rs:17` | PRIM |
| TGT-02 | `target_daa_interval` / `slot_digest` は production 呼び出し元ゼロ | `consensus/core/src/palw.rs:256` | PRIM |
| TGT-03 | `active_window_intervals = 0` が単一 slot へ暗黙に潰れる。doc が主張する caller 側検証は存在しない | `consensus/core/src/palw.rs:257` | PRIM |
| DEMO-01 | `--palw-demo-mint` は**もはや devnet 限定ではない**。gate が `TESTNET_PALW_PARAMS.net` を受理する一方、CLI help は "devnet-palw ONLY" のまま（陳腐化）。偽 leaf・空 vote cert・Active view を実 store へ直接注入する | `palw_demo.rs:54`<br>`kaspad/src/args.rs:557` | PROD |
| DOC-01 | `consensus/pow/src/lib.rs:235` は algo-4 が「同じ hash floor 上にあり、全 replica block が hash-floor PoW を行う」と記述。**DOS-01 により現在は虚偽** | `consensus/pow/src/lib.rs:235` | DOC |
| DOC-02 | `diverse_replica_match` の doc コメント（:229）は schedule を比較すると記述、inline コメント（:251）は比較しないと記述。コードは inline 側と一致 → doc が cross-vendor 規則の強度を**誤表示** | `mil/core/src/palw.rs:229` | DOC |

### 2.4 反証により棄却（7 件・記録のみ）

compute-work accumulator の cap 混同 / `BlueWorkType::MAX` の Uint192 wrap / `is_structurally_valid` 内 overflow / `palw_proof_type` の truncating cast / audit window の単一 epoch 潰れ / `merge_from` の DAA semantics / `check_palw_ticket` の無制限 chain walk。いずれも敵対的検証で守護条件または到達不能性が確認された。

### 2.5 監査間の重複対応

| 監査 1 | 監査 2 | 本 ADR |
|---|---|---|
| C-01 cert 未検証 | #5 | CERT-01 |
| C-02 leaf 上書き→報酬窃取 | #9 | LEAF-01 + **BIND-01**（より深い根因） |
| C-03 fork-local view 式誤り | — | **DOS-02**（raw tx / acceptance 未照合）+ **VIEW-01**（自 body 未 fold）— 監査の指摘は 2 つに分かれる |
| C-04 resolver 未 cross-bind | #9(d) | BIND-02 / BIND-05 |
| C-05 authorization dead code | — | **AUTH-01/02/03**（監査より強い: 生成すらされない） |
| C-06 target interval 自己申告 | — | TGT-01（"one-shot 倍率" の主張のみ**棄却**） |
| C-07 algo-4 header DoS | #10 | DOS-01 |
| — | #1 整数 backend 不在 | INT-01 / MATCH-01 |
| — | #2 token-only 照合 | MATCH-01 |
| — | #3 PCPB 未接続 | PCPB-01 |
| — | #4 選択が bond 非加重 | SEL-01 |
| — | #6 producer が監査していない | §6 P2 |
| — | #7 demo が証明を直接 seed | DEMO-01 |
| — | #8 dispute/slash 未完 | SLASH-01 / ECON-03 |
| — | — | **ECON-01・DOS-03/04・SS-01・AO-02/03・QUORUM-02 は両監査とも未検出** |

### 2.6 欠陥クラス — 「規則の存在」と「規則の強制」の乖離

本 ADR の所見のうち 2 件は**同一の一般形**を持ち、これは単発のバグではなく走査すべき欠陥クラスである。

> ある規則がオブジェクトの**性質**を主張しているのに、そのオブジェクトが合意層へは **hash としてしか**到達しない、あるいは規則が散文・doc コメントにしか存在しない。
> **hash は preimage を束縛するが、preimage の性質を強制できない。** 性質規則を強制できるのは、実バイト列（または実型付き値）が合意視野に入る点だけである。

| 事例 | 主張された性質 | 規則の在処 | 強制点 |
|---|---|---|---|
| **ECON-01** | reward script は ML-DSA-87 P2PKH かつ ≤150B | coinbase 検証則（PALW 経路の外） | **不在** → 構築不能な coinbase |
| **INT-01** | int8 域は [−127,127]、saturation 禁止 | `canonical-compute-v1` §10（散文・凍結済） | **不在** → 型（`&[i8]`）が規則を破る |

この 2 件は「規則が無かった」のではない。**規則は正しく凍結されていたのに、強制点が無かった。** 文書の品質と実装の安全性が独立でありうることの実例である。

**したがって走査を制度化する。** 全 hash-committed オブジェクトについて次を機械的に問う。

```text
(1) その preimage の「性質」を主張する規則が、どこか（ADR / 設計文書 / コードコメント / 仕様）に存在するか
    ─ 単なる byte 一致・束縛の主張は対象外
(2) 存在するなら、バイト列が合意視野に入り性質を検査できる点は file:line でどこか
(3) そのような点が無ければ finding
    ─ 「性質規則なし・byte 一致のみ」と確認できた場合は CLEAN として明示的に記録する
```

**この走査は G15（`Activation`）として activation gate に入る**（§7.2）。ゲート表の「判定可能性」レンズが *ゲートは機械検査可能か* を問うのに対し、G15 は *規則は執行点を持つか* を問う。**両者は対である。**

#### 2.6.1 初回走査の結果

実施済み。**7 件の gap、11 件が反証で棄却、84 件を CLEAN として明示確認。**

| ID | オブジェクト | 主張された性質 | 強制点 | 重大度 |
|---|---|---|---|---|
| **DA-01** | `receipt_da_root` | 「fraud window 中は P2P で取得可能」「DA unavailable 時は certificate を発行しない」（設計 §10.5）。ADR §5 は **DA 拒否を客観的 fault として自動 slash 可能**と宣言 | **不在** — DA object の仕様・時間境界・P2P request message・challenge tx のいずれも無い | high |
| **SAMPLE-01** | `audit_sample_root` | 「consensus が beacon から独立に再導出するため、sampled chunk を所持せずに署名できない」 | **不在** — 非テスト読み取りゼロ（§2.6.2） | high |
| **AUTHSET-01** | `auditor_set_commitment` | auditor 集合が beacon 選出であること（設計 §10.1/§10.2） | **不在** — repo 全体で読み手ゼロ | high |
| **BIND-01** | manifest `leaf_root` ↔ 格納 leaf | leaves が `leaf_root` へ reduce すること | **不在**（§2.1 と同一） | critical |
| **PMC-01** | `private_match_commitment` | canary dispute 時に等値照合される | **不在** | medium |
| **AUTH-01** | `header_preimage_commitment` | authorization が header を bind する | **不在**（§2.2 と同一） | medium |

**走査で判明した重要事実 — 一部の対象は存在しない。** `lut_root` / `rope_table_root` / `assignment_proof_root` / `provider_snapshot_root` / `sample_plan_root` / `reward_set_root` は**コードに存在しない**（仕様・本 ADR 上の名前のみ）。走査対象リストを実在物へ写像することが走査の前提である。

**CLEAN 側で最も有用な 3 件。**

- **`PalwBeaconCommitV1.commitment`** — **継続的義務が完全に閉じている唯一の PALW オブジェクト**であり、commit → reveal → 期限 → 不履行の客観判定が揃っている。**DA-01 を直す際の正しい雛形はこれである。**
- **`ticket_nullifier_commitment`** — 純粋な byte 一致であり、かつ強制点が実在する（`verify_palw_ticket_store_facts`、`consensus/core/src/palw.rs:390-392` が実際に開示する）。
- **`reward_set_root` / provider reward script** — **§3.4.1 で採った設計により構造的に CLEAN**。実バイトを registry 状態に持たせ hash を識別子へ降格したため、性質規則が hash に委任されない。本レンズに対する正答の形である。

#### 2.6.2 派生する文書整合性の問題 — 「達成済み」と書かれた未達成の remediation

SAMPLE-01 は単なる未実装ではない。**既存文書が達成済みとして記録している。**

`consensus/core/src/palw.rs:1011-1012` は**直説法**で次を述べる。

```text
since consensus independently re-derives `audit_sample_root` from the audit beacon over the
batch's receipt DA, a valid signature cannot be produced without identifying — hence
possessing — the beacon-selected receipt chunks.
```

しかし `audit_sample_root` の非テスト読み取りは**ゼロ**である（`palw_demo.rs:151` の `Hash64::default()` のみ）。同じ主張が設計 v0.2 §205（I-14）と **ADR-0039 の R2 に「実装済み remediation」として記載**されている。

> ADR-0039:27-29 — 「`PalwAuditorVoteV1::signing_hash` now covers the beacon-selected `audit_sample_root`, so an auditor cannot sign without possessing the sampled receipt chunks. Commit `34fe771`.」

**署名が当該 field を覆うのは事実だが、主張された性質はそこからは従わない。** producer が `audit_sample_root` を自由に供給できる以上、任意の値に対して正当に署名できる。所持を強制するのは **consensus 側の独立再導出**であり、それが存在しない。

**したがって R2 は達成されていない。** 本 ADR は ADR-0039 の R2 記載を「片翼のみ実装」へ**訂正することを要求する**（§6 P0-2 に含める）。これは §2.6 の欠陥クラスが**文書層に現れた形**であり、レンズが設計どおり機能したことの実証でもある。誤記を残すと、レビュアーは I-14 を消化済みとして通過する。

---

## 3. 仕様凍結 — QW36-INT-W4A8-V1

### 3.1 単一 canonical compute class

```text
compute_set_id =
H(
    model artifact hash
    || integer arithmetic ruleset hash
    || LUT roots
    || tokenizer hash
    || chat template hash
    || semantic schedule version
    || trace scheme version
    || CU ruleset version
    || overflow budget table hash          ← §3.3 参照
)
```

正式クラスは当面 1 つ（`QW36_INT_W4A8_V1`）。将来 `V2` を導入する場合のみ別クラスとして並走させる。

### 3.2 合意対象と非合意対象の分離

| 合意対象 | 非合意（telemetry） |
|---|---|
| `compute_set_id` / artifact hash | CUDA / ROCm / Metal |
| `canonical_execution_root` | GPU 型番 / driver version |
| `operation_schedule_root` | kernel ID / tile size / threadgroup size |
| `output_commitment` | compiler ISA / 実行時間 |
| `expert_route_root` / `state_transition_root` | |
| `canonical_compute_units` | |

```rust
pub struct ImplementationTelemetryV1 {
    pub implementation_id: Hash64,
    pub backend_hint: BackendHint,
    pub device_hint: Vec<u8>,
    pub build_hash: Hash64,
}
```

**MATCH-01 が示す通り、これは名前の付け替えでは済まない。** 現行 `runtime_class_id` は `gpu_arch_class` と `kernel_graph_hash` を構造的に含み、さらに Qwen backend が **trace root 自体を `runtime_class_id` から導出**している（`qwen_backend.rs:158-180`）。したがって:

- `compute_set_id`（合意）と `implementation_id`（非合意）を **Receipt v2 で別スロットに分離**する
- trace root の導出から `runtime_class_id` を**除去**する（除去しない限り cross-backend 一致は構造上不可能）

### 3.3 厳密整数 — oracle は最も厳格な実装である

**正当性の根拠は `mod 2^32` wrapping ではなく、全中間値が overflow しないことである。**

`misaka-canonical-compute-v1.md` §10 は既に `127²` 境界を凍結し、saturation を順序依存として**禁止**している。欠けているのは散文規則の**強制**であり、INT-01 はまさに「散文の規則が型で違反されていた」事例である。

#### 実装の非対称配置

| 層 | 検査 | 根拠 |
|---|---|---|
| **oracle**（仕様の実行可能形） | 入力域を型で拘束、累積は `checked_add` または i64 + assert、**違反時に大声で落ちる** | hot path でないため検査コストは無視できる |
| **高速カーネル** | 境界表の証明に依拠し wrap のままでよい | 境界表が overflow 不能を保証する |

**両オペランドを型で拘束する。** activation だけを縛ると、凍結した W4 域が何にも強制されず、下表の committed K 境界が根拠を失う（現行 `canonical_int_gemm` は**両オペランドとも生の `&[i8]`** を取り、doc block はどちらが weight かすら述べていない）。

```rust
/// A8: −128 を型で排除する。`try_from` が唯一の構築経路。
pub struct QInt8(i8);

impl TryFrom<i8> for QInt8 {
    type Error = QuantBoundError;
    fn try_from(v: i8) -> Result<Self, Self::Error> {
        if v == i8::MIN { return Err(QuantBoundError::ReservedMinusOneTwentyEight); }
        Ok(QInt8(v))
    }
}

/// W4: 凍結域 [−8, 7]。**この型が無ければ下表の K 上限 2,113,665 は成立しない。**
pub struct QInt4(i8);

impl TryFrom<i8> for QInt4 {
    type Error = QuantBoundError;
    fn try_from(v: i8) -> Result<Self, Self::Error> {
        if !(-8..=7).contains(&v) { return Err(QuantBoundError::W4OutOfRange(v)); }
        Ok(QInt4(v))
    }
}

/// 署名でオペランドの役割を固定する（現行の `(&[i8], &[i8])` は役割が不定）。
pub fn canonical_int_gemm(w: &[QInt4], a: &[QInt8], m: usize, k: usize, n: usize) -> Vec<i32>;
```

#### 境界の数値

| 構成 | 最悪 \|product\| | K=2¹⁷ での累積 | K の上限 | 判定 |
|---|---|---|---|---|
| W8A8、−128 許容（監査が批判した草案） | 16384 = 2¹⁴ | 2147483648 | 131071 | **i32::MAX を 1 超過** |
| **現行 `canonical_int_gemm` の署名（両側 raw `i8`）** | **16384** | **2147483648** | **131071** | **上記草案と同一 — K=2¹⁷ で 1 超過** |
| `QInt8` を activation のみに適用（当初 P3-1） | 16256 | 2130706432 | 132104 | 安全だが**凍結域を強制していない** |
| W8A8、両側 [−127,127] | 16129 | 2114060288 | 133144 | 安全（余裕 33423359） |
| **W4A8 = 本仕様**（W4∈[−8,7]、A8∈[−127,127]） | **1016** | **133169152** | **2113665 ≒ 2²¹** | 安全（16× の余裕） |

> **第 2 行が本質である。** 現行 `canonical_int_gemm` は両オペランドとも raw `i8` を取るため、**監査が批判した「−128 許容 W8A8」草案とビット単位で同一の危険域**にある。K=2¹⁷ で累積はちょうど 1 だけ i32 を超える。release では無警告 wrap、debug では panic — すなわち**ビルド構成で結果が変わる**。K1 oracle としては失格である。
>
> **K 上限 2,113,665 は `QInt4` による W4 型強制を前提とする条件付きの数値である。** `QInt8` を activation にだけ適用しても実効上限は 132,104 にとどまり、committed 値は約 **16 倍の過大主張**になる。`compute_set_id` が被覆する境界表には、**どの型でどちらのオペランドを縛るかまで**含めること。

**W4 の選択は品質上の妥協ではなく、参加可能性の要件である。** 35B を W8A8 にすると重みだけで約 38GB となり Apple 32GB 機を完全に排除する。W4A8 なら約 19GB で、KV cache の余地を残して収まる。単一プールが実機多様性を持てるのは、この選択の結果である。

#### conformance の拒否ベクタ

適合性試験には**拒否ベクタ**を含める。以下は「計算せず量子化境界で拒否する」ことが正答である。

```text
K0-R1  −128 を含む activation 入力       → QuantBoundError::ReservedMinusOneTwentyEight
K0-R2  境界表を超える K                   → shape 拒否（計算しない）
K0-R3  境界表に無い op × shape の組       → 未登録として拒否
K0-R4  saturating 実装との差分検出        → saturation は順序依存につき不適合
K0-R5  [−8,7] を外れる weight 入力        → QuantBoundError::W4OutOfRange
```

**`overflow budget table hash` を `compute_set_id` の被覆に入れる**（§3.1）。INT-01 は、境界表が ruleset hash に含まれていなければ「散文の規則」に留まり型で破られうることの実証である。

> **未了。** 凍結対象の 35B W4A8 set について、`canonical-compute-v1` §10 の overflow budget 表は **QW9 shape table 向けにのみ存在する**。35B-A3B 用の op × max-shape 表は未作成であり、`compute_set_id` の入力が確定しない。§10-9 の決定事項とする。

#### int64 / hierarchical requant 経路

§10 は softmax·V（seq 32k で ≈1e11）を **int32 に収まらない**ものとして分類し、int64 accumulator または spec 固定の 128 位置境界での hierarchical requant を要求する。`hierarchical_int_reduce` は実装済みだが**呼び出し元が無い**。この経路は S0-a では捕まらないため、**S0-b の出口条件に明示的に含める**（§8）。

**`overflow budget table hash` を `compute_set_id` の被覆に入れる**（§3.1）。INT-01 は、境界表が ruleset hash に含まれていなければ「散文の規則」に留まり型で破られうることの実証である。

### 3.4 単一 bonded provider registry

```rust
pub struct PalwProviderRecordV1 {
    pub credential_id: Hash64,
    pub compute_set_id: Hash64,

    pub bonded_value: u128,
    pub bond_outpoint: Outpoint,
    pub bond_activation_epoch: u64,
    pub unbonding_epoch: Option<u64>,

    pub conformance_valid_until: u64,

    /// ECON-01 閉鎖（§3.4.1）。**hash ではなく実バイト列を状態として保持する。**
    /// 上限 150 byte は ECON-01 の規則自身が与えるため、provider あたりの状態コストは自明。
    pub reward_script: ScriptPublicKey,

    pub registration_epoch: u64,
    pub status: ProviderStatus,
}
```

#### 3.4.1 ECON-01 の単点閉鎖 — hash は束縛であって検証ではない

**hash は preimage を束縛するが、preimage の性質を強制できない。** PQ class + ≤150B は「バイト列が合意視野に入る点」でしか強制できない。

当初案（registry に `reward_script_hash` を置き admission で性質検証）では閉鎖が二点に割れる。

```text
(1) admission 時の性質検証        … PQ class + ≤150B
(2) coinbase 構築時の同一性検査   … H(producer 供給バイト列) == reward_script_hash
```

(2) が consensus 経路に必要になり、さらに「バイト列が入手できず coinbase を組めない」**DA エッジ**が生まれる。

**150B 規則自体がバイト列の状態格納を正当化する。** 上限が既に与えられている以上、registry に実バイトを持たせるのが正しい。

| | 当初案 | 採用案 |
|---|---|---|
| registry | `reward_script_hash: Hash64` | **`reward_script: ScriptPublicKey`（実バイト）** |
| leaf / `reward_set_root` / snapshot | 実バイト | **`reward_script_hash` へ降格**（コンパクト識別子） |
| coinbase 構築 | producer 供給 + hash 照合 | **状態読みのみ** |
| DA エッジ | あり | **消滅** |
| 閉鎖点 | 2 点 | **1 点（admission 検証 + 状態格納）** |

#### 3.4.2 回転経路を同じゲートに通す

reward script の更新を許すなら、以下 2 つを規則として置く。

1. **更新 TX も admission 時検証（P0-4）を通る。** 登録経路と更新経路で強制点が食い違ってはならない。
2. **支払いに適用されるのは leaf に束縛された時点の script である。** 成熟窓の途中で credential が侵害され script が差し替えられる race を封じる。

leaf の `reward_set_root` 凍結が既にその受け皿であるため、規則を 1 行足すだけでよい（§4.2 / §6 P1-2 の immutable snapshot と同じ機構）。

**抽選は credential 単位に bond を集約してから行う。** これが SEL-01（outpoint 単位抽選 = bond 100 分割で抽選券 100 枚）の直接の修正である。除外条件: A 自身の credential / 同一 delegation root / unbonding 中 / conformance 期限切れ / 過去の選択 B / bond 未熟成。

**自己ペア禁止の限界を明記する。** 同一 credential の自己ペアは防げるが、同一人物が別 credential を作る Sybil は防げない。したがって安全性は §5 の β で評価する。

### 3.5 適合性ゲートが証明するもの

適合性試験は「特定 GPU を使った証明」**ではない**。証明するのは「現在の実装が正準結果を返せる」ことだけである。目的は誤実装・古い runtime・壊れた LUT・driver 更新による drift の排除であり、**不正防止は複製・bond・監査・slash が担当する**（答えを埋め込んだ専用プログラムでも適合試験は通過しうるため）。

### 3.6 既存文書との衝突 — 人間の決定が必要な事項

検証により、凍結対象仕様と既存の凍結済み設計文書の間に**構造的な衝突**が判明した。コードは仲裁できない。

| ID | 衝突 | 決定要求 |
|---|---|---|
| **SC-01** | `canonical-compute-v1` §15 は整数 W4A8 を **fp genesis tier の次の第 2 tier** と順序付ける。本仕様はそれを**唯一の genesis mint-grade set** とする — 順序の完全な反転 | §15 を書き換えるか、本仕様の適用を遅らせるか |
| **SC-02** | §15 は 9B fp、§19.5b Scope note は 35B abliterated、**コードは第 3 の identity**（4B/35B-abliterated Q4 fp の 2 tier 分類、A3B 無し・W4A8 無し・arithmetic profile 無し）を符号化。**3 者が相互に不一致** | 正準 identity を 1 つ確定する |
| **SC-05** | §18 は初期 pool を **Metal + CUDA の 2 class に凍結**し AMD/ROCm を明示的に先送り | 単一プール化により**この衝突は消滅**（class 自体を廃止するため） |
| **SC-07** | §19.8 の cross-vendor diverse-replica k=2 pool は §A が凍結した参加モデル。本仕様は token-only cross-vendor match を weight 0 に降格 = **§19.8 を削除する** | 単一プール化により**意図的な削除として確定**（§1.2 の論法） |
| **SC-09** | leaf wire schema は 2 provider に対し `runtime_class_id` を **1 つ**しか持たず、`PalwProofType` に diverse / integer 判別子が無い → §19.8 の「fork surface は不変」は**偽** | LeafV2 移行（§4）に同梱 |
| **SC-08** | `PalwComputeSetRecordV1` は登録の**形**は提供するが本仕様が要する field を持たず、「weight 0 へ降格」が**表現できない**（省略された set は解決不能になるだけ） | `weight_factor_bps = 0` を明示的に表現可能にする |
| **SC-13** | QW4 を I-9 cross-tier 試験の予約 fixture として残すか、単一 set へ潰すか。**コードは 2 tier の存在に hard-depend** | 決定要求 |
| **SC-14** | Level-3 品質ゲートは §A では前提条件、本仕様では迂回される。`integer_tier_eval_passes` は存在するが committed budget も calibration も無い | 決定要求 |
| **SC-11** | §4「Q4 dequantization and integer dot」は §A の凍結節。本仕様の Q4_K_M 降格がこれを完全に孤児化する | 決定要求 |
| **SC-12** | 本仕様が降格する "graph-fallback" と "Generic operation pricing" は、§A にもコードにも**対応する成果物が存在しない** → 降格が空振り | 用語を実在物へ写像するか削除 |
| **SC-15** | k=2 ペアリング鍵をどちらが支配するか: §13「同一 set_id」（実装済）か、本仕様の「3 backend 横断の同一 arithmetic profile」か | 単一プール化により **`compute_set_id` 一致に確定** |

**単一プール化により SC-05 / SC-07 / SC-15 は解決する。残る SC-01 / SC-02 / SC-08 / SC-11 / SC-13 / SC-14 は人間の判断を要する。**

---

## 4. Leaf v2 と役割割当

### 4.1 PCPB（post-commitment provider binding）

```text
job_challenge = H(network_id || epoch_beacon || scheduler_job_id
                  || requester_credential || request_commitment || shape_id)
```

**epoch 共通 challenge ではなく job 単位で一意にする。** 同一 epoch 内で同じ prompt・同じ challenge prefix を複数ジョブ登録すると activation を再利用できるため。

```text
A_commit = H("palw/self-order-commit/v1" || job_descriptor || receipt_fields || r_blind)
```

順序（**チェーン上の epoch / TX 順序で検証。ローカル時計を信用しない**）:

```text
A_commit + escrow lock
        ↓
provider snapshot 固定（A_commit 以前に確定した epoch E−k）
        ↓
future beacon で B を bond 加重抽選
        ↓
B receipt（必ず A_commit を含む）
        ↓
A reveal（r_blind 開示）
```

### 4.2 Leaf v2

adaptive `m` を採るなら A/B 二者固定 leaf では足りない。

```rust
pub struct PalwReplicaLeafV2 {
    pub version: u16,

    pub compute_set_id: Hash64,
    pub scheduler_job_id: Hash64,
    pub job_challenge_commitment: Hash64,
    pub job_nullifier: Hash64,

    pub a_commit: Hash64,
    pub provider_snapshot_root: Hash64,
    pub assignment_proof_root: Hash64,

    pub replica_count: u16,
    pub replica_set_root: Hash64,

    pub output_commitment: Hash64,
    pub operation_schedule_commitment: Hash64,
    pub canonical_execution_root: Hash64,
    pub expert_route_root: Hash64,
    pub state_transition_root: Hash64,

    pub canonical_compute_units: u128,

    pub reward_set_root: Hash64,
    pub receipt_da_root: Hash64,
}
```

**現行の二者 leaf を維持する場合、v1 は `m = 1` へ固定する必要がある。**

### 4.3 Exact match

```text
compute_set_id / shape_id / job_challenge
output_commitment / operation_schedule_commitment / canonical_execution_root
expert_route_root / state_transition_root / canonical_compute_units
generated token count / stop reason
```

を全て bit 一致させる。**CUDA / ROCm / Metal は比較しない。**

不一致時は即座に帰責しない: `mismatch → leaf 凍結 → 報酬凍結 → 紛争処理`。

### 4.4 述語削除は原子的に

**`runtime_class_id != other` の削除は、root 照合強化と同一コミットで行う。単独先行は不可。**

fp のまま述語だけを外すと、独立性の証拠が「実行が 2 回起きた」だけに痩せ、cross-class 一致が担っていた数値頑健性・実装独立性の信号が消える**中間状態**が生まれる。Q4/fp レシートが weight 0 である限り実害は封じられるが、**弱い中間状態をコミット履歴にも作らない**。

**`runtime_class_id` の除去は 2 述語 × 3 導出点の計 5 箇所であり、1 箇所ではない。** 特に見落としやすいのが `exact_match`（`mil/core/src/palw.rs:223`）で、これは `self == other` を全 8 field に対して行うため **`runtime_class_id` の一致を要求する**。単一プール下でこれを残すと、異なるハードウェアの 2 provider は**正準結果が bit 一致していても永久に mint 経路へ乗らない**。多様性述語だけ削除して `exact_match` を放置すると、禁止が要求へ反転するだけである。

変更単位:

```text
[単一コミット]
  ── 述語（2 箇所）
  − diverse_replica_match: runtime_class_id != other      mil/core/src/palw.rs:250   (削除)
  − exact_match: self == other が runtime_class_id を含む  mil/core/src/palw.rs:223   (field を除外)
  + compute_set_id == other                                                          (追加)
  + canonical_execution_root == other
  + operation_schedule_commitment == other
  + expert_route_root == other
  + state_transition_root == other
  + canonical_compute_units == other

  ── trace 導出（3 箇所。ここを残すと root が backend の関数のままになる）
  − qwen_backend.rs:158-174     trace_in / sched_in への runtime_class_id fold
  − palw_replica.rs:63-75       同上（MockDeterministicRuntime）
  − domains.rs:72               runtime_class_id の定義から gpu_arch / kernel_graph を分離
                                → compute_set_id（合意） / implementation_id（非合意）へ

  ── wire
  + ReplicaMatchKey に compute_set_id スロット追加、runtime_class_id を
    implementation_id へ改名し**照合対象から外す**            mil/core/src/palw.rs:211

  ── doc
  + doc コメント :229 の訂正（schedule を比較すると誤記）      (DOC-02)
```

> **順序上の含意。** trace 導出（3 箇所）を先に直さない限り、述語に root 比較を足しても**必ず不一致になる** — root が backend 識別子の関数だからである。したがってこの 5 箇所は論理的にも単一コミットでなければならず、「まず述語だけ」は技術的に不可能である。

---

## 5. セキュリティ sizing — β が主、W は従

### 5.1 なぜ W 単独では不十分か

総 bond `W = 100 億円` でも一人が 90% を持てば `β = 0.9`。**W は「分散している」ことの証拠にならない。**

```text
攻撃成功確率 ≈ β^m

β_max   : プロトコルが耐えると仮定する最大攻撃 bond 比率（ガバナンス宣言値）
ε_pair  : replica 割当で許容する失敗確率
m       : replica 数

β_max^m ≤ ε_pair
```

`W` の用途は**絶対的な slash 可能額**であり、最低ネットワーク健全性 / 最大 mint 発行量 / 成熟窓 / reward cap を決める。

### 5.2 観測集中度は β_max の**下界**にしかならない

Sybil は観測をむしろ分散側に偽装する。したがって bond 集中テレメトリ（top-k credential share / HHI / delegation-root クラスタ）が言えるのは

> 宣言 β_max はこの値**未満ではありえない**

という床だけであり、**天井は永遠に言えない**。

### 5.3 宣言に責任を持たせる機構 — 自動縮退

**観測集中度が宣言 β_max を超えた瞬間、プロトコル則で自動縮退する。**

```text
observed_concentration > declared_β_max
        ↓  (会議を開くのではなく、チェーンが締まる)
m 増加
q 増加
成熟窓 延長
mint cap 低下
        ↓
W < W_min まで悪化した場合
        ↓
mint 停止
```

これにより宣言には**常に保守側へ倒れる誘因**がつき、「誰も責任を負わない数値に対して m を sizing する」問題が閉じる。

### 5.4 監査率 q

```text
q × P(attribution succeeds) × effective_slash  >  fraud_gain
```

**紛争で帰責できないなら、見かけ上 bond が大きくても `effective_slash` はゼロである。** したがって fraud-proof が無い段階で高額報酬を有効化してはならない（現状 ECON-03: 77% base が解決済み担保ゼロに対して支払われる）。

### 5.5 多数決で帰責しない

A と B が結託していれば 2 対 1 で honest referee を負けにできる。**人数が増えても知性は増えない。** 計算不正の自動 slash は §6 P4 の `PalwIntegerTraceVmV1` 完成後に限る。

自動 slash 可能なのは客観的 fault のみ: 署名不正 / 期限切れ / opening 拒否 / DA 拒否 / 二重 commit。

---

## 5.6 実装状況（2026-07-19 時点）

`feat/mil-v0` にて実装済み。`consensus-core 404 / consensus 205 / mtp 21 / mtp-service 33 / dnsseeder 4` green + 実機確認 + 実ノード live 検証済、workspace の lib/bin ともビルド通過。

| 項目 | 状態 | 実装 |
|---|---|---|
| **P0-1** DEMO-01 | **DONE** | `palw_demo.rs:54` の gate を **devnet-palw 限定へ戻した**（`TESTNET_PALW_PARAMS` 受理を削除）。module docs と CLI help は元から正しく、コードのみが乖離していた |
| **P0-2** DOC-01/02, SAMPLE-01 | **DONE** | `body_validation_in_context.rs`（2 箇所）/ `consensus/pow/src/lib.rs:235` / `mil/core/src/palw.rs:229` を訂正。**`palw.rs:1011` の「consensus が再導出する」直説法を「I-14 は片翼のみ実装」へ書き換え**（§2.6.2） |
| **P0-3** DOS-01 | **DONE** | `Params::palw_algo4_accept` を新設し**全 preset で `false`**。`check_pow_algo_id` で reject → **GHOSTDAG・reachability・header 段 store write のすべてより前**。新エラー `RuleError::PalwAlgo4NotAccepted` |
| **P0-4** ECON-01 | **DONE** | `palw_reward_script_is_coinbase_representable()` を新設し `validate_public_leaf` に配線。**「≤150 かつ PQ」より強く、69 バイト ML-DSA-87 P2PKH テンプレートとの厳密一致**を要求 |
| **P0-5** CERT-01, QUORUM-02 | **DONE** | `quorum_reached` に `total==0` / `num==0` 守護。**`beacon_quorum_reached` にも `num==0` を追加**（姉妹関数にも同じ穴があった） |
| **P1-1** BIND-01, LEAF-01 | **DONE** | `insert_leaf` を **content-addressed write-once** 化（同一内容は冪等、異内容は拒否）。LeafChunk arm に **manifest 存在 / content-derived batch_id / `leaf_index < leaf_count` / leaf の batch_id 一致**を追加 |
| **P1-4** BIND-02/05 | **部分 DONE** | Certificate arm で **`manifest_hash == manifest.content_id()` と `leaf_root == manifest.leaf_root`** を永続化前に検証。**identity 半分のみ**（下記） |
| **P1-11** DOS-04 | **部分 DONE** | `admission_valid` に `activation_not_before_epoch` の**上限**を追加（slack = 1 lead window）。`expiry` を activation 相対で束縛するだけでは far-future activation による view 恒久 pin を防げないため。DOS-03 / AO-02 / AO-03 は未着手 |

**新規テスト（gate evidence）:**

```text
G1  palw_algo4_rejected_while_accept_lever_closed              全 preset の既定 false + 実拒否
G2  palw_reward_script_admission_matches_coinbase_representability   受理⇒支払可能 / 拒否例 7 種
G3  leaf_chunk_admission_binds_to_manifest_and_is_write_once    注入拒否 + 冪等 + 上書き拒否
G4  certificate_must_bind_to_its_batch_manifest_and_leaf_root   orphan / 誤 manifest / 誤 leaf_root
G7  (DOS-04) admission の activation 上限 — slack 内 3 値 / 境界外 / u64::MAX/2 の pin 試行
```

| **P1-3** CERT-01 | **DONE** | `verify_certificate_attestation()` を新設。**auditor 集合は既存の active DNS stake-bond view**（設計 §10.2）— 新規 bond store は不要だった。各 vote の **ML-DSA-87 署名を bond の `validator_pubkey` で検証**、bond の active 判定、bond 重複拒否、**stake 加重 quorum**。専用 context `PALW_AUDITOR_MLDSA87_CONTEXT` で beacon 署名との replay を遮断 |
| **algo-4 の実運用** | **DONE** | `--palw-enable-algo4` を新設。既定は全 preset で閉。PALW 非活性 net では警告して無視。demo-mint が **block/virtual 両段の verdict をログ**するよう修正（従来は「not found post-insert」で理由不明だった） |

### live 検証（実ノード、devnet-palw / netsuffix=111）

`kaspad` + `kaspa-pq-miner` で algo-3 supporting chain を採掘し、algo-4 ブロックを実パイプラインへ投入。

```text
レバー開（--palw-enable-algo4）:
  PALW demo: algo-4 proof-of-LLM block 5777119757c6f425... ACCEPTED on the live daemon
  (block stage = StatusUTXOPendingVerification, virtual stage = StatusUTXOValid)

レバー閉（既定）:
  PALW demo: algo-4 block e0d38ead456d911b... REJECTED by the pipeline:
  algo-4 (PALW replica) blocks are not accepted on this network:
  the ADR-0040 activation gates have not been released (palw_algo4_accept = false)
```

**同一構成で両方向とも再現する。** これが「algo-4 testnet が実施可能」かつ「既定では安全」であることの実証である。

### 意図的に未着手（依存関係のため）

**CERT-01 の attestation は実装したが、quorum の分母が「投票した bond の stake」であり「beacon が選出した eligible set の stake」ではない。** auditor 選出自体（`sample_auditors_by_score`）はまだ stake 加重でなく production 呼び出し元も無い（SEL-01 / P2-1）。したがって現状の証明書が証明するのは *「参加した bonded stake の num/den 以上が署名した」* であり、*「監査すべき集合の num/den 以上が署名した」* ではない。`audit_sample_root` の再導出（SAMPLE-01 / P2-7）も未実装のため、I-14 の所持性は依然未証明である。

**この差は実在し、G4 を `StopShip` ではなく `Activation` クラスに置いている理由である。** ただし前進は装飾的ではない — 証明書の偽造には、**実際に bond され slash 可能な stake の quorum 相当から、生きた ML-DSA-87 署名**が必要になった（従来は「正しい長さのバイト列」で足りた）。

同様に **DA-01 / SAMPLE-01 / AUTHSET-01 / PCPB-01 / TGT-01 / AUTH-01..03 / BIND-03/04 / DOS-02/03/04 / SS-01** は未着手。§11 の判定は変わらない — **公開 testnet には P0+P1 の完了が必要**であり、現時点で完了しているのは **P0 全 5 項目**と **P1 の 3 項目（P1-1 / P1-4 部分 / P1-11 部分）**である。

### テスト側で判明した設計上の含意

`palw_algo4_leaf_not_active_rejected_e2e` は **seed 済み leaf を後から変異させて**いた。write-once 化により不可能となったため、env に `leaf_edit` フックを追加し**最初の書き込み前に**leaf を整形する形へ変更した。これは単なるテスト修正ではない — clause-9 の eligibility grind は leaf を hash するため、**grind 後の leaf 変異はブロックが依拠する当の draw を無効化する**。write-once はこの順序を型で強制する。

---

## 5.6.1 §12′ — certificate supersession（票検閲の暫定対策・実装済み）

**塞いだ穴。** 分母が「参加 stake」である限り、同一 batch に対し**異なる票部分集合 = 異なる有効証明書**が成立する。集約者が honest 票を落として分母を縮め、少数結託 stake で `num/den` を跨げる。これは §12 の「producer は単なる集約者」という前提を、producer の役割ではなく**分母の定義**が破っている。

> **⚠️ この節は撤回された。下の「5.6.1a CERT-TRUST — §12′ supersession の撤回」が現行仕様である。**
> 以下 4 段落は撤回前の規則であり、記録として残す。

**規則（撤回済み）。** より大きい approving stake を持つ証明書は既存を**置換できる**。検閲された票を保持する誰もが後から完全版を公開できるため、検閲は決定的ではなく不安定になる。「誰でも同じ votes から組み立てられる」を利便性から**安全性**へ昇格させる。

**置換窓は expiry ではなく activation で閉じる（撤回済み）。** `current_epoch < cert_activation_epoch` の間のみ置換可。activation 後は ticket が既に参照しうるため、置換は既発行ブロックの eligibility と報酬基盤を遡って動かす — leaf に対して P1-1/P1-2 が閉じたのと同じ「支払済みブロック下の可変状態」障害である。

**決定性（撤回済み）。** 同点は低い方の cert hash が勝つ。view は選択親+mergeset から毎ブロック再構築されるため、reorg は supersession を経路依存に継承せず最初から再評価する。

**比較子の健全性（**この主張が誤りだった** — 撤回理由そのもの）。** `approving_stake` を証明書のフィールドとして宣言する（body 段の view builder に bond view が無いため）。ただし信頼はしない — `verify_certificate_attestation` が active bond view から再集計し、宣言値が不一致なら拒否する、としていた。

---

## 5.6.1a CERT-TRUST — §12′ supersession の**撤回**（仕様変更・実装済み）

**穴。** 上の「比較子の健全性」は **call order を誤っていた**。`verify_certificate_attestation` は `apply_palw_overlay_effect`（virtual/acceptance 座標）からしか呼ばれず、**store への永続化を守るだけ**である。一方 supersession 比較子は `commit_palw_overlay_view`（body/mergeset 座標）で動く。しかも当該 fold は acceptance filter を持たない生 mergeset tx を読むため（DOS-02 の既知の帰結）、**証明書 tx は accept される必要すらない**。

結果として、stake ゼロ・bond ゼロ・有効署名ゼロの攻撃者が `approving_stake = u128::MAX`、`expiry_epoch = 0` の 0x33 overlay tx を 1 本ブロードキャストするだけで:

1. 比較子に無条件で勝ち、honest 証明書を view から**恒久的に締め出す**（以後どの honest 値も `> u128::MAX` を満たせない）;
2. `is_block_eligible_at` が読む `cert_expiry_epoch` を 0 にし、対象 batch の algo-4 ブロックを全て `PalwTicketInvalid` にする — 実 GPU work・bond・報酬窓ごと**batch を破壊**する。

batch_id ごとに繰り返せば第三者 provider を全滅させられる。これは T-shared 脅威モデルそのものである。

**修正の方針 — 検査の移設ではなく信頼の除去。** bond view は virtual chain traversal で積み上がるため body 座標には**構造的に存在しない**。body 段で検証しようとすれば ADR 本文が退けた acceptance 座標の consensus split を再導入する。したがって **検証できない座標は、その値で順位づけしてはならない**。

**新しい規則（実装済み）。**

* `PalwBatchViewV1::apply_certificate(batch_id, cert_hash, current_daa)` — `approving_stake` も window も引数から**消えた**。
* 遷移は `Committed | Auditing → Certified` の**昇格のみ**。`cert_hash` は `None → Some` の **write-once**。既に `Certified` の entry は**一切変化しない**（`false` を返す）。
* `is_block_eligible_at` から `cert_activation_epoch <= epoch < cert_expiry_epoch` を**削除**。証明書窓の権威は attested blob 側（`resolve_palw_binding` → `cert_active`、`palw_store` は `verify_certificate_attestation` の後ろでしか書かれない）に一本化する。view 側の複製は冗長かつ DoS 面そのものだった。
* `cert_approving_stake` / `cert_activation_epoch` / `cert_expiry_epoch` / `PalwBatchAdmissionParams::supersession_window_daa` は **inert**（読み手なし・書き手なし）。struct から消さないのは borsh encoding 安定のため。`certificate_frozen_at` は削除（production caller ゼロ）。
* `verify_certificate_attestation` の check (4)（`cert.approving_stake != pass_stake`）は**そのまま維持**。virtual 座標では `approving_stake` は今も実 commitment である。

**安全性の議論。** fold の遷移は全て**単調（permissive 方向のみ）**になった。未検証 tx が達成できる最大は「attested blob の無い `cert_hash` で batch を `Certified` に昇格させる」ことだが、採掘には `palw_store` から解決できる attested 証明書が別途必要なので**何も買えない**。破壊的遷移が 1 つでも残れば、それがそのままゼロコスト検閲原始になる。

**失われるもの（明示）。** 「より支持の厚い証明書が弱い証明書を置換する」は body 座標の機構としては**もはや成立しない**。ただし反検閲の目的自体は失われない — 証明書は content-addressed で `palw_store` に**共存**し、miner は `palw_epoch_certificate_hash` で好きな attested 証明書を名指せる。少数派 assembly を先に載せても、より完全な assembly を抑圧できない。stake 順の canonical winner が要るなら、それは bond view があり tally を実際に再計算する **virtual 座標**に置くべきである。

**票検閲の残余（S3 の正直な現状）。** 参加 stake 分母のもとでは検閲版証明書は今も *valid* である。これを本当に閉じるのは eligible-set 分母（SEL-01 + I-14 `audit_sample_root` 再導出）であり、body 座標のいかなる規則もその代替にならない。

## 5.6.1b CERT-BATCH — 証明書の batch 束縛と write-once 化（実装済み）

`resolve_palw_binding` は `palw_epoch_certificate_hash` を **hash だけ**で store から引き、`cert.batch_id` を header の `palw_batch_id` と照合していなかった。証明書の identity は decode されて捨てられていた（BIND-02 の store 側チェックは *永続化時* のもので、*参照時* を守らない）。

* `PalwBindingError::CertBatchMismatch` を追加し（`CertAbsent` に潰さない — 「blob が無い」と「他人の blob だ」は別の運用事象）、resolver 内で `cert.batch_id != batch_id` を拒否する。resolver に置くことで現在と将来の全 caller が継承する。
* `DbPalwStore::insert_certificate` を `insert_leaf` に倣い **content 単位の write-once** 化。証明書は `cert.hash()` で keyed なので、同一 key への異内容書き込みは hash collision であり silent overwrite ではなく fail-closed が正しい。

**同一 batch 内でどの証明書を名指せるかは pin しない（意図的）。** view の first-arrival `cert_hash` を強制すると、未検証の overlay tx 1 本に検閲レバーを与えることになり、CERT-TRUST で取り除いた失敗そのものを再導入する。同一 batch の代替証明書はいずれも quorum-attested かつ manifest/leaf_root 束縛済みであり、また観測者にとって当該 header フィールドは自由ではない — clause 7 の authorization は header preimage 全体（`palw_epoch_certificate_hash` を含む）を束縛する。

### bond 評価時点の訂正（§12′）

当初 `pov_daa_score = 包含ブロックの DAA` としていたが、これは**包含時評価**であり誤り。eligibility は B 割当と同じ意味論で**選出 snapshot で凍結**すべきである。包含時評価だと、証明書を保持する攻撃者が honest auditor の bond 失効直後を選んで包含でき、その票を無効化して honest 証明書を殺すか、検閲版に supersession 比較を勝たせられる。

修正: `pov_daa_score = cert.audit_beacon_epoch × epoch_len`。この epoch は証明書の committed field であり**全票の `signing_hash` が覆う**ため、票収集後に狙い直せない。

### `select_top_auditors` → `sample_auditors_by_score` へ改名

"top" は *stake 上位* と読め、それは**常任クジラ委員会**（事前特定可能・買収可能・DoS 可能な固定集合）であり、beacon シード加重抽選とは別物である。実装は元からハッシュスコア順（= 未加重抽選）でそうではなかったが、**名前が実装者をそちらへ誘導する**。`runtime_class_id` のレビューで指摘された「名前が同じまま中身が入れ替わる」失敗形そのもの。

### §D 署名ドメイン表

`consensus/core/src/signature_domains.rs` を新設。cross-protocol replay を**個別対処ではなくクラスで**閉じる。全 ML-DSA-87 署名 context を 1 表に列挙し、テストが (a) 相互相異、(b) **prefix-free**（ctx が可変長フィールドと連結される実装に変わった場合に `"A"` と `"AB"` が混同されうるため）、(c) PALW 2 件の命名規約逸脱の pin（改名は全署名を変えるため re-genesis 限定）を強制する。未実装の署名対象（AUTH-01 の block authorization 等）は `PENDING_SIGNATURE_DOMAINS` に列挙し、実装時に既存 const を流用させない。

---

## 5.7 §16′ — 動的 replica premium π（実装済み・中立固定で inert）

§16 の「均等配分」を**固定 50/50 から有界制御器の中立点へ再解釈**する。実装 `consensus/core/src/palw_premium.rs`（12 tests green）。

### なぜ動的化が安全か

**分配比は結託経済に対して不変。** 自己結託（A も sybil B も攻撃者）では攻撃者が leaf 価値の合計を取るため、A:B をどう動かしても偽造 EV は 1 ビットも変わらない。reroll 壁 `β^m > m/(m+1)`・escrow の `c_A` 係留・監査壁 `q·S > V` はいずれも分配比と直交する。動くのは正直参加者の供給誘因だけであり、それこそが動かしたい量である。

### 信号（偽装が高くつく向きに選ぶ）

| 信号 | 向き | 偽装コスト |
|---|---|---|
| `r` = shortfall 率（期限失敗 CU / 発注 CU） | 過負荷（上）| 実 no-show が必要 = ペナルティ + 自分の B 収入放棄 |
| `I` = 割当強度（発注 CU / snapshot bond）| 過剰供給（下）| bond 注入は自分が B に引かれる → honest 稼得か no-show(→r) しかない |

**レイテンシは意図的に不使用。** 期限内の遅延はカルテルがタダで作れる唯一の量であり、無料で希少性を偽装できる。したがって**期限が計測器**になる（`T_deadline` = 無負荷 p99 × 1.5–2、S2 で実測）。

需要側偽装（ジョブ洪水）は challenge-in-context + escrow + 複製費のため実仕事でしか作れない。それは偽装ではなく需要そのものなので、制御器が応答してよい。

### 時間基盤とコホート会計

窓は **DAA score** で切る（pruning 不変・視点非依存）。selected-chain index を基盤にして archival と IBD が割れた既知の致命傷をそのまま回避する。各 `A_commit` は**受理された窓のコホート**に帰属し、`close(w) + L` で確定する（L = B 期限 + reveal + finality 深度）— これで「需要は窓 w、納品は w+1」の成長期バイアスが消える。入力は **DNS finality 済み effects のみ**。

### 更新規則

状態は 1 スカラー `π`（bps、中立 = 10000）。分配は m 非依存の重み式:

```text
A の重み = 1、各 B の重み = π
σ_A = 1/(1 + m·π)     σ_B = π/(1 + m·π)
π は leaf の commit 窓で凍結（payout 時ではない）
```

`hold` 条件は degraded（健全性機構と二重制御しない）/ 薄市場（Poisson 分解能未満）/ bootstrap / deadband（帯 `[r_lo, r_hi]` 自体）/ rate-limit。非対称 κ（希少性に速く 1.5%、過剰に遅く 0.75%）+ 連続 C 窓のデバウンス。

### 安定性 — 私が仕様の条件を読み違えた点の訂正

パラメータ表の `κ·M_mat ≤ Δ_cap` を**ハード条件として実装したところ、genesis 既定値が自己矛盾した**（1.5% × 14 = 21% > 10%）。再検討の結果、これは既定値の誤りではなく**条件の位置づけの読み違い**だった。

| regime | 条件 | 束縛するもの |
|---|---|---|
| structural | `κ·M ≤ Δ_cap` | step 幅のみで足り、ring buffer は発火しない |
| **limiter（genesis 既定）** | `κ·M > Δ_cap` | ⌈Δ_cap/κ⌉ ≈ 7 窓で limiter が発火 = **より厳しい制御** |

**両 regime とも maturation 期間の総移動量は `Δ_cap` に束縛される** — 束縛するのは step 幅ではなく ring buffer である。structural を必須にすると 21% cap か 0.71%/窓のどちらかを強いられ、**実際の境界を緩めて見かけ上厳しい条件を満たすことになる**。よって `is_consistent` が要求するのは「cap が最小 π で 1 step 以上を許すこと」（さもなくば制御器は静かに凍結する）とし、`step_bound_is_structural()` を別途公開して regime を判別可能にした。

### 中立点の byte 同一性（landing 安全性の核）

`π = 1` で `σ_A = σ_B = 1/(1+m)`、かつ **m=1 では整数演算が従来の `a = base/2; b = base − a` をバイト単位で再現する**（`neutral_pi_is_byte_identical_to_half` が `u64::MAX/2` まで含む probe で検証）。中立点を離れないネットは従来と完全に同一の支払いを行うため、**制御器の導入自体は合意結果を一切変えない**。

### 適用点

`coinbase.rs` の `a = base/2` を `premium_split(base, m, π)` へ置換。π は `WorkRewardClass::ReplicaPalw` に載せ、`palw_work_reward_class` が leaf 解決と同時に決める — construction と validation が構造的に同一値を見る。

**現状 `palw_premium_at_window()` は中立固定**。制御器本体は実装・試験済みだが、窓状態の永続化と finality 済みコホート標本の駆動は **P2-6/P2-7 の DA/receipt 会計**を要するため未接続。したがってこのスライスは**構造上 inert** である。

### 残作業

| # | 内容 |
|---|---|
| §16′-1 | `PalwWindowSample` を finality 済み effects から導出（P2-6/P2-7 依存） |
| §16′-2 | 窓状態の block-keyed 永続化（beacon 状態と同じ再帰） |
| §16′-3 | **実装済**（式・esc・徴収経路・destination）。残りは実 no-show 検出イベントからの呼び出し配線のみ。詳細は §16′-3 節 |
| §16′-4 | S1: `I` 基線 / S2: `T_deadline` と `r₀` 実測 → `N_STAT` 検算 / S3–S4 敵対テスト 3 本（カルテル選択的 no-show・ジョブ洪水・bond 引抜きステップ応答） |
| §16′-5 | テレメトリに `(r, I, π)` の epoch 系列を公開（β 監視と同枠） |
| §16′-6 | LeafV2 の `a_commit` で commit 窓を厳密化（v1 は `registered_epoch` で近似） |

### §16′-3 no-show ペナルティ（ζ 連動）— 実装済み

```text
penalty = max( P₀ , ζ · (π_live − 1)⁺ · R̂ ) · esc(k)
π_live  = イベント窓の制御器値（leaf の凍結 π ではない）
R̂       = σ_B(π_live, m) · V̄_leaf
esc(k)  = μ^min(k, k_cap)
既定: ζ = 2, μ = 2, k_cap = 4, **P₀ = V̄_leaf の 3.5%**（回転 sybil 較正後）
```

**徴収経路。** 引落しは当該 provider の **bond から**（escrow は A の資産であり B の fault の担保ではない）。bond < penalty なら bond を 0 まで回収し `suspended`（再 bond まで抽選除外 — bond の尽きた provider は slash 不能であり、slash 不能な provider を抽選してはならない）。

**行き先は焼却または epoch 監査予算で、A へは 1 sompi も流さない。** `NoShowPenaltyDestination` に `ToRequester` variant を**設けない**ことで「A が B の no-show から利得する」を型で表現不能にした。A に入れる設計は eclipse-grinding（A が honest B を黙らせて reroll を稼ぐ）に報酬を付ける。A の救済は escrow 中立な reroll と遅延補償に留め、B の罰と A の補償を同じ資金で結ばない。

#### `pump_ev_negative` — 2 度の訂正を経た最終形

**第 1 の訂正（私の初稿）**: ζ + P₀ だけでは pump が黒字（140k < 167k）になる。理由は「**ζ 項は最も必要な時に最も小さい**」こと — pump の支払い中はまだ π が中立近傍で `(π−1)⁺ ≈ 0` なので実質 P₀ しか課されない。当初はここから「esc(k) が主要因」と結論した。

**第 2 の訂正（レビュー指摘・こちらが正しい）**: **その均衡には穴がある。** `esc(k)` は **credential 単位**に累積するため、**回転 sybil カルテル**（min-bond credential を多数保有し no-show を分散、全イベントを `k=0` で打つ）が escalation をほぼ完全に回避する。credential 量産コストは min-bond の粒度だけで、β を持つカルテルには実質無料。この攻撃者の下でコストは平坦モデルに退化し、**pump は再び黒字になる**。

したがって真の目標状態は「**平坦モデル単独で EV 負**」であり、**esc は defense-in-depth へ降格**する。

**P₀ の再較正。** 条件を導出すると（カルテルの割当量は両辺で相殺されるため per-slot 比較）:

```text
cost = P₀ · W                gain = Δσ_B · V̄_leaf · (M − W)
W = ⌈Δ_cap / κ_up⌉ = 7,  M = 14,  Δσ_B = 238 bps
require  P₀ > Δσ_B · (M − W) / W = 238 bps = 2.38%
```

| P₀ | flat cost | margin | 判定 |
|---|---|---|---|
| 2.00%（旧既定） | 140,000 | 0.84× | pump が黒字 |
| 2.38% | 166,600 | 1.00× | 分岐点（余裕なし） |
| **3.50%（新既定）** | **245,000** | **1.47×** | **EV 負** |

**較正条件そのものを機械検査可能にした。** ただし片側では不十分なので、**両側不等式 + 空間の非空性**まで持ち上げた（`p0_window_bps()` / `p0_window_is_non_empty()` / `p0_is_calibrated()` を `is_consistent()` に組込）。**3.5% はハードコードせず、現行 params から窓を再計算する。**

| 境界 | 導出元 | genesis 値 |
|---|---|---|
| 下界（pump 撃退） | `Δσ_B·(M−W)/W`, `W=⌈Δ_cap/κ_up⌉` | 238 bps |
| 上界 A（eclipse 被害者） | `p0_max_bps_eclipse` | 1000 bps |
| 上界 B（honest 無害性） | `harmless·10000/r₀` | **500 bps**（こちらが binding） |
| **有効窓** | | **(238, 500]** — 既定 350 は内部 |

上界 B が示すとおり、honest provider は `r₀`（無負荷 shortfall 基線）分の no-show を無過失で被るので、期待コストは `r₀ × P₀ = 0.10%`/leaf に収まる必要がある。

**非空性が本質。** 「現在の点が合法」ではなく「**パラメータ空間が居住可能**」を主張する。将来 pump 下界が harm 上界を超えたら安全な P₀ は存在せず、正しい応答は静かに片側へ倒すことではなく **CI を止めて Δ_cap/κ/M を再バランスすること**。テストは (a) 下界が κ_up・M_mat に追随して動くこと、(b) `r₀` 倍増で上界が締まり現行 P₀ が拒否されること、(c) 窓が空になる params で `is_consistent` が拒否することを pin する。

**P₀ 上限との両立**（eclipse 被害者を破滅させない）も 2 点確認済み:
1. N_STAT 超の市場では pump に多数イベントが必要 → **defeat に要する per-event P₀ は絶対値として小さい**（被害者が払うのは 1 イベント分であって campaign 全体ではない）
2. 薄市場では **N_STAT hold が π ごと凍結するので pump 自体が不能** — 既存の統計ガードが偶然でなく安全上の仕事をしている

`pump_ev_negative` の敵対者モデルは**回転 sybil（全イベント k=0）**に差し替え済み。旧 pin（`flat_cost < gain`）は反転し、現在は `rotating_cost > gain` を assert する。esc は「怠惰な攻撃者は回転する攻撃者より*多く*払う」という surplus 側の assert に降格した。

---

## 5.9 §ROUND-REG — オペ別丸め表（実装済み）

`consensus/core/src/rounding_registry.rs`。**丸め・切捨て・飽和・LUT 補間を行う全 consensus site が 1 行を持つ。** 境界表で無 overflow が証明済みの純粋整数 add/mul は行不要（判断が発生しないため）。署名ドメイン表と同型の enforcement point。

**既定は RNE**。half-up は反復更新下で上方ドリフトする（π が乗法再帰であることで実証済み）。逸脱は行で理由とともに宣言し、テストが理由の非空を強制する。

| id | site | モード | overflow |
|---|---|---|---|
| R-01 | model/requant int32→int8 | **RNE**（§3.3 の half-up 式を本行が上書き = §3.1 との不一致の恒久解） | clamp [−127,127] |
| R-02 | model/softmax 正規化除算 | floor（厳密整数除算） | 不可 |
| R-03 | model/isqrt (RMSNorm) | floor（定義） | 不可 |
| R-04 | model/LUT index 導出 | truncate | clamp |
| R-05 | econ/π 更新・σ・EMA | RNE | **assert**（oracle は静かに飽和せず大声で落ちる） |
| R-06 | econ/esc(k) | 厳密整数冪 | saturating |
| R-07 | lottery/⌊CU/Q⌋ | floor | 不可 |
| R-08 | daa/難易度 retarget | **LegacyFrozen**（consensus 凍結済。移行ではなく宣言） | saturating |

運用規則 2 つをテストで強制:
1. **行 id = conformance vector id**（表とベクタが 1:1 で drift しない）
2. `gemmlowp` の `SQRDMULH`（round-half-away, −2³¹ corner）は R-01 を差し替えず**別 id で宣言**し、`MUTUALLY_EXCLUSIVE_ROUNDING_IDS` が両者の同時有効化を禁止する。個々には正当な 2 つの丸めが 1 site で静かに共存することが consensus split であり、しかも cross-vendor でしか露見しない種類のもの。

---

## 5.9.1 §16″ — MTP C5（LLM マイニング 30%）と faucet 防御

settle ループのバグは「**weight があっても経路が無ければ配分ではない**」を示した。逆向きの命題も真であり、より危険である — **経路があっても防御が無ければ配分ではなく蛇口**になる。testnet points は TGE 価値の先物なので、stub 網での farming は実質無料の sybil 収穫であり、**30% という大きさはその分だけ標的になる**。

したがって **C5 は手動加算のみ**（`c5_auto_award_enabled() == false`）を初期状態として固定した。auto 加算の前提条件を `C5_AUTO_AWARD_PRECONDITIONS` として列挙し、テストが短縮を拒否する:

1. global job-nullifier dedup（P1-9）を加算経路で強制
2. k=2 exact-match 通過分のみ creditable
3. credential 単位の epoch cap
4. SEL-01 / AUTH-02 の閉鎖

stub ゲート期の C5 は **provisional**（`c5_is_provisional()`）— Q4_K_M レシートや bond-0 期と同じ較正用使い捨ての系譜であり、確定した権利ではない。ポイントと並べて状態を記録しておくことが、後で約束の内容を争わずに割り引ける唯一の方法である。

---

## 5.11 §P1-6 — AUTH-02（当選 ticket 再鋳造）の閉鎖

**T-shared を塞いでいた最大の障壁。** 当選 algo-4 header は raw `ticket_nullifier` を開示し（I-13 の秘匿は mint で終わる）、`eligibility_hash` はブロック内容を一切束縛しない。したがって**観測者が同一当選から任意の競合ブロックを無制限に再鋳造できた**。seeder が第三者に配るネットで開けば他人のノードへの合意層 DoS 面になる — activation ではなく **T-shared を gate する**理由がこれである。

### なぜ署名で、単純案では駄目か

「miner script を `eligibility_hash` に束縛する」案は単純だが、**払出 script を変えて grind できる**ため nonce を `low64(nullifier)` に固定した意味を壊す。束縛値は正当保持者には*固定*で観測者には*偽造不能*である必要があり、それを同時に満たすのは署名だけである。

### 実装

`PalwBlockAuthorizationV1` は宣言のみで構築箇所ゼロ・`signing_hash` 無し・搬送経路無しだった（AUTH-01）。

- `palw_header_preimage_commitment(...)` — parents / **auth tx を除いた tx merkle root** / ticket 座標 / **timestamp**
- `signing_hash(network_id)` — 専用 context（署名ドメイン表へ pending から昇格）
- `binds_leaf_authority()` — leaf の `ticket_authority_pk_hash` と照合（**AUTH-03**: 読み手ゼロだった）
- subnetwork `0x38` で block body 搬送、body 検証 **clause 7** で強制
- 入力ゼロを許容（ブロックメタデータであり送金ではない）。1 ブロック 1 個・出力ゼロ・algo-4 限定・有効署名必須で bounded

**循環の回避**: authorization は自分を含む merkle root にコミットできないため、束縛する root は **auth tx を除外**したものにした。除外は 1 個だけなので miner が選ぶ tx 集合は完全に束縛される。

### 攻撃再現テストが私の修正の穴を捕捉した

`palw_algo4_reminted_ticket_is_rejected_auth02` を書いたところ **replay が成功した**。preimage が `timestamp` を束縛しておらず、timestamp 以外同一の 2 ブロックが同じ preimage を持つため、honest の authorization をそのまま自分のブロックへ移せた。

**これが攻撃再現テストを書く理由そのものである** — 「修正した」という主張ではなく攻撃の失敗を確認する形にしていなければ、この穴は残っていた。timestamp を束縛して閉鎖。

### 続報 — allowlist 方式そのものが誤りだった（**TOTAL binding へ置換**）

上記の「残る header フィールドは GHOSTDAG/UTXO 由来で自由に選べない」という前提は **誤りだった**。敵対監査が実証したとおり:

* `utxo_commitment` / `accepted_id_merkle_root` / `pruning_point` / `overlay_commitment_root` / `palw_beacon_seed` の 5 つは **virtual/UTXO 段でしか検証されない**。virtual 段は selected-chain 候補にしか到達しないため、**chain block にならない variant では一度も検証されない**。しかも失敗しても `StatusDisqualifiedFromChain` であり、ブロックは DAG に残る。
* `palw_epoch_certificate_hash` は store 上で active な任意の cert を名乗れる（複数の attested 証明書が同時に active になりうる。当時は §12′ supersession をその根拠に挙げていたが、supersession は 5.6.1a で撤回された — 共存は content-addressed store の性質そのものであり、撤回後も成り立つ）。なお TOTAL binding 化により**この軸は観測者に対しては閉じている**（preimage が当該フィールドを含む）。miner 自身については 5.6.1b で cross-batch のみ閉じた。
* `bits` は algo-4 が Layer-0 hash floor から免除されているため自由。
* level ≥ 1 の parents は `check_indirect_parents` が **HashSet 比較**なので順列が自由。header hash は順序込みで hash する。
* authorization tx 自身が自由: 入力ゼロ ⇒ 任意の `lock_time` が vacuously finalized ⇒ **2^64 通りの txid = 2^64 通りの `hash_merkle_root`** が同一 `authed_root` と同一署名を共有する。

algo-4 は PoW 免除なので、これらは全て**コストゼロで無限に valid な双子ブロックを作れる軸**であり、AUTH-02 の目的（観測者による再鋳造の阻止）はその条件で敗れていた。しかも allowlist である以上、**将来 header フィールドを 1 つ足すたびに黙って穴が開く**。

**修正**: 9 値の allowlist を廃止し、`palw_authorization_commitment(network_id, header, authed_root)`（`consensus/core/src/hashing/header.rs`）へ置換した。これはブロック自身の header preimage を、**ブロックハッシュと同じ `write_header_preimage` を再利用して**（第 2 のシリアライザを持たない = drift しない）専用ドメイン `PalwAuthPreimageHash64` で hash したものであり、置換は 2 つだけ:

1. `palw_authorization_hash := 0` — 循環のため必然的に除外
2. `hash_merkle_root := authed_root` — 同上（実 root は authorization tx を含む）

**ブロックハッシュの preimage 及びバイト順は一切変更していない。genesis hash は不変**（`test_genesis_hashes` / `gen_kaspa_pq_genesis_hashes` はそのまま緑）。

**補完（Fix 2）**: 除外される 1 個の tx を正準化した。clause 7 は auth tx に `version == TX_VERSION`・入力ゼロ・出力ゼロ・`lock_time == 0`・`gas == 0`・`mass == 0`・payload が parse 済み authorization の borsh 再直列化とバイト一致、を要求する。これにより `authed_root` が決まれば実 `hash_merkle_root` は**ただ 1 通り**になり、`lock_time` 軸が独立に閉じる。

**運用コスト（正直な下振れ）**: 署名往復は template を完成させた**後**、submit の**前**に行う必要があり、署名後は template を再構築できない。新しい parent の到着・coinbase retarget・virtual 由来コミットメントの再計算はいずれも署名を無効化し、ticket 抽選を無駄にする。miner は往復中 parents/timestamp/virtual 由来フィールドを固定し、stale な署名は当選の喪失として扱うこと。これは修正に内在するコストであり、束縛を減らすことがまさに脆弱性そのものである。

**残余リスク（版の結合）**: authorization commitment が header preimage レイアウトに依存するため、**将来 header フィールドを追加すると authorization commitment も変わる**。これは意図した fail-closed 特性（新フィールドは自動的に束縛される）だが、PALW authorization と block header schema が版として結合したことを意味する。

**テスト**: `palw_authorization_commitment_binds_every_header_field`（consensus-core、監査が列挙した全フィールド + level ≥ 1 parents の順序を 1 フィールドずつ変異させ commitment が動くことを網羅的に確認）、`palw_authorization_commitment_excludes_exactly_the_two_circular_fields`、`palw_authorization_commitment_is_domain_separated_from_the_block_hash`、および pipeline 側の `palw_algo4_authorization_binds_every_header_field_auth02`（accept 半分 + 署名後改竄が clause 7 で落ちる reject 半分）。既存の `palw_algo4_reminted_ticket_is_rejected_auth02` は無変更で緑のまま。

### 続報 2 — AUTH-TXSHAPE: 正準化を isolation へ引き上げ、**位置**も固定した

Fix 2（clause 7 内の正準形要求）は**述べる場所と網羅範囲が足りていなかった**。敵対監査の再指摘:

* **位置が自由だった。** `authed_txs` は subnetwork で**フィルタした**リストなので、auth tx を n 個の tx の間で移動しても `authed_root` は不変=署名は有効なまま、実 merkle の葉順だけが入れ替わる。**1 authorization あたり n 通りのブロックハッシュ**が、やはりコストゼロで作れる。auth tx のバイトを固定しても、この軸は独立に開いたままだった。
* **`check_transaction_inputs_count` のコメントが嘘だった。** 「出力ゼロ」「1 ブロック 1 個」を*既に強制されている事実*として書いていたが、当時それを強制するコードは存在しなかった（出力ゼロは `SlashingEvidence` にはあり 0x38 には無い、という非対称）。
* **正準形が contextual 経路にしか無かった。** mempool / block-template（BBT）は `validate_tx_in_isolation` しか通らないため、安価な構造規則が高価な contextual 経路の裏に置かれていた。

**修正**:

1. `check_palw_block_authorization_shape`（`tx_validation_in_isolation.rs`、`validate_tx_in_isolation` の**先頭**）を新設。`Transaction` の全フィールドを列挙して固定する — `version`（`TX_VERSION`）/ `inputs` 空 / `outputs` 空 / `lock_time == 0` / `gas == 0` / `mass == 0`。`subnetwork_id` は判別子そのもの、`id` は導出、`payload` は `validate_block_authorization` の borsh 往復比較（今回追加）。新エラー `TxRuleError::NonCanonicalPalwAuthorizationTx(&'static str)` は**破れたフィールド名を運ぶ**。context-free なので mempool/BBT 面も同時に覆う。
2. clause 7 の tx 探索を `.find(subnetwork == 0x38)` から **`transactions.last()` の検査**へ変更。これで実 `hash_merkle_root` は (authed tx リスト, authorization payload) の**決定的関数**になり、両方とも署名が束縛済みなので **1 authorization = 1 ブロックハッシュ**が成立する。clause 7 側の正準形チェックは isolation 規則の**再述**として残す（消費地点で規則が読めるように。両者は同期させること）。
3. `check_transaction_inputs_count` のコメントを、**強制されている内容の記述**へ書き換えた。

**設計上の確約（将来の回帰口）**: authorization は template 確定**後**にブロック生成者が組み立てるブロックメタデータであり、**リレーされる mempool tx では断じてない**。だから `mass == 0` 固定が安全である（storage mass を刻む template builder を通らない）。逆に言えば、将来 tx をソート/並べ替えする template コードは **authorization をソート対象から外して末尾に再付加**しなければならない。ここが最も静かに壊れる箇所である。

**producer**: `palw_demo.rs` と `virtual_processor/tests.rs` の 2 箇所とも既に正準形・末尾 push だったため**変更不要**（`0` リテラルを `TX_VERSION` に明示化し、規則を指すコメントを付けた）。mil/ と kaspad/ には 0x38 の構築箇所が無い。将来 mil/ の miner を実 authorization 発行に配線する際は、この正準形に従うこと。

**テスト**: `palw_block_authorization_tx_canonical_shape`（isolation、固定フィールドごとに REJECT 1 本 + ACCEPT + 非 0x38 が無影響であること）、`palw_algo4_authorization_tx_shape_and_position_are_pinned_authtxshape`（end-to-end、ACCEPT 半分 + 署名後改竄 6 軸の REJECT + **位置移動の REJECT**、位置の方は filler tx 入り 3 tx ブロックで内側の枠を作り、同構成の未改竄ブロックが accept される control 付き）。`lock_time` 軸は `palw_algo4_authorization_binds_every_header_field_auth02` の 1 ケースから**この新テストへ移し、6 軸へ拡張した** — 正準形が isolation で落ちるようになり clause 7 エラーとして現れなくなったため（同テストの共通アサーションは「clause 7」）。**削除ではなく移動と拡張**である。

**残余（今回閉じていない）**: 1 authorization = 1 ブロック が回復しても、algo-4 header は依然 Layer-0 hash floor 免除であり、header 段の流量を縛るのは clause 9 の当選・k=2 exact-match・provider bond だけである（本 ADR が既に記録している DOS-01）。本修正は AUTH-02 の性質を回復するものであって、algo-4 header lane を rate-limit するものではない。

### 副次的に見つかった実バグ

`mass/mod.rs:406` が**入力ゼロの tx で 0 除算**していた。coinbase は別経路のため到達不能だったが、authorization も入力ゼロなので新たに到達可能になった。UTXO を消費も生成もしない tx の storage mass はゼロが正しい。

---

## 5.12 §T-shared — 到達可能な範囲の完了と、残る 1 つの決定

### 完了（T-shared 安全性に直結）

| 項目 | 内容 |
|---|---|
| P1-6 AUTH-01/02/03 | 最大の障壁。攻撃再現テスト付きで閉鎖（§5.11） |
| P1-2 LEAF-01 | P1-1 の write-once により**スナップショット不要**と判明 |
| P1-9 | global job nullifier |
| P1-11 | AO-02（bitmap 境界を構造化）/ AO-03（`min_samples ≥ 1` を validity へ）/ DOS-03（view batch cap） |
| P1-12 SHAPE-01 | 活性化*後*の header shape 規則 |
| VIEW-01 | 「自 body を fold しない」を**意図的仕様として明文化 + テスト**（監査は欠陥と読んだが、同一ブロックでの register-and-spend を防ぐ意図的な設計） |
| seeder 拒否 | `misaka-dnsseeder` が PALW ネット（suffix 110/111）を**明示的に拒否して起動失敗**。「載せない」は設定の不在で、`--network-id testnet-110` 一つで消える |

### 座標の決定 — view は body/mergeset 座標に**留まる**（移動不可）

P1-5 / P1-13 の前提だった「座標をどちらに寄せるか」は、調べた結果**選択の余地が無い**と判明した。

`check_palw_ticket` は **body 検証**で `view(SP)` を解決する。acceptance データは **virtual 処理された（= chain block になった）ブロックにしか存在しない**。side-chain の選択親は virtual 処理されないため、acceptance 座標の view はそこで `None` になり、body 検証の成否が chain 選択順・到着順に依存する — **恒久的で順序依存の `StatusInvalid` = consensus split**。資源問題を直すために合意分裂を導入することになる。

したがって **view が mergeset 座標にあるのは必然であり、見落としではない**。DOS-02 は「fold を acceptance で濾す」のではなく「**未受理 fold が達成しうる範囲を有界にする**」ことで閉じる:

* 偽造 batch は Active になれない — `apply_certificate` が実 ML-DSA quorum を要求（P1-3）
* view エントリ数は cap 済み（`max_view_batches`、DOS-03）
* leaf は write-once かつ manifest 境界内（P1-1）
* fold 元は全て mergeset **blue** = 誰かが採掘したブロック。view slot の消費は**ブロック生産コスト**を伴う

残余は「miner による有界な slot 消費」であり、cap が正しさの問題を容量の問題へ変換する。**`max_view_batches` を将来引き上げる際は、この論証を再検証すること。**

### P1-7（TGT-01）— **誤検出だった**

監査は interval を「header 自己申告で consensus 導出でない」としたが、clause 5 は `h_daa_score == binding.target_daa_interval` を要求する。`daa_score` は GHOSTDAG 後に合意検証される past の関数なので、**miner が名乗れる interval は自分で選べない値だけ**である。

`slot_digest` からの導出を実装して差し戻した経緯はコード内に記録済み。**ギャップは監査のモデル側にあり、「修正」は正しい規則を壊すところだった。**

### P1-13（BIND-04 / SS-01）— panic を明示的拒否へ

PALW overlay state に pruned-IBD import 経路が無い（`PalwPrunedFrontier` は writer/reader ゼロ）ため、pruned ノードは受理済み algo-4 ブロックの leaf 欠落で**同期中に panic** する。

完全な import は別スライスなので、**PALW preset に `palw_requires_archival = true` を置き、非 archival 起動を理由付きで拒否**した。障害を停止時の明示メッセージへ変換する — seeder の拒否と同じ「省略ではなく拒否」原則。実機で両方向確認済み（拒否 exit=1 / `--archival` で正常起動）。

### デプロイ層 — 閉鎖はノードが強制する

| 強制点 | 内容 |
|---|---|
| **seeder 拒否** | `misaka-dnsseeder` が suffix 110/111 で起動失敗。seeder こそがネットを共有化する機構だから |
| **peer allowlist** | PALW preset は `--connect-peers` 必須。無指定なら起動拒否 |
| **archival 必須** | pruned-IBD import 経路が無いため、panic ではなく起動時拒否（P1-13） |

**「閉鎖」を広告の不在ではなく到達性の不在にした。** seeder 非掲載は*announce* を止めるだけで、netsuffix を知る者は接続できる。活性化ゲート未達のネットではこの差が安全論証の全てなので、**ノード自身が outbound-only を強制**する。firewall に委ねないのは、seeder が省略ではなく拒否する理由と同じ — **誰かが設定を覚えていることに依存する閉鎖は閉鎖ではない**。

3 つとも実機で両方向確認済み（拒否 exit=1 / 条件を満たせば正常起動）。

### S3 検閲テスト — 実ネット不要と判明

「Δ_super 較正に実ネットが要る」としていたが、**検閲は「fork-relative view がどの証明書を受理するか」の主張**であり、view は accepted effects の純関数なので in-process で完全に表現できる。`s3_vote_censorship_is_unstable_not_decisive` が 4 性質を固定する:

1. 検閲証明書は**初期状態では受理される**（参加分母下では実際に valid — それが穴）
2. 落とされた票を持つ者が完全版を出せば **supersede する**
3. **Δ_super が応答の窓を保証する** — 検閲者が公開と activation を同一 epoch に揃えても
4. 窓経過後は結果が安定 — honest 証明書に対する再検閲は不可能

最後に `Δ_super = 0` で**検閲が成功すること**も assert している。Δ_super が装飾でなく耐荷重であることの証明である。

実ネットが要るのは Δ_super の**数値較正**（finality 深度の 1–2 倍）であって、機構の正しさではない。

### 旧・残 3 項目

**P1-5（DOS-02）/ P1-7（TGT-01）/ P1-13（BIND-04）は独立した作業ではない。** すべて **view が mergeset 座標にあり acceptance が virtual 座標にある**（BIND-03）ことに帰着する。

* **P1-5**: view の fold が raw mergeset tx を読むため、never-accepted / 二重支払 tx が view を動かす。acceptance filter は body 段では原理的に書けない（acceptance は virtual 段の性質）。
* **P1-7**: interval 導出は**実装して動作したが差し戻した** — clause 5 が既に `interval == daa_score` を前提に束縛しており、規則が 2 本になって正直なブロックが全て落ちた。着地には clause 5 の意味論変更が要る。
* **P1-13**: pruned-IBD import 経路の新設。どの座標の状態を import するかが未定では設計できない。

**半端に入れる方が危険である。** P1-7 の差し戻しがその実例で、2 本目の規則は正直なブロックを拒否しながら、両者が食い違う箇所では interval を miner 選択のまま残した。

**必要な決定**: view を acceptance 座標へ移すか、mergeset 座標のまま acceptance 相当の性質を別途保証するか。決まれば **P1-5 と BIND-03 が同時に閉じ**、P1-7 の clause 5 再定義も安全に行える。これは実装判断ではなく合意規則の設計判断であり、独断で寄せるべきではない。

---

## 5.10 §OWN — runtime ↔ node 所有権表（**FROZEN 2026-07-20**）

外部 `runtime-palw` のレシートを node に統合する際、**写す前にどちらの規約が原本かを凍結する。** 順序を逆にすると、写した瞬間に不整合が固定される。

| 規約 | 原本 | 帰結 |
|---|---|---|
| 署名方式・鍵体系 | **node**（ML-DSA-87 のみ） | runtime の Ed25519 経路は排除 |
| ハッシュ関数・幅・keying | **node**（keyed BLAKE2b-512 / Hash64） | 合意が再計算する全値が対象 |
| 射影・match 述語 | **node**（§4.3 exact-match 集合） | `runtime_class_id` は非合意 telemetry |
| ドメインタグ台帳 | **node** の `signature_domains.rs`（**単一台帳**） | runtime は行を*追加*し、独自表を持たない |
| レシートの意味内容（フィールド集合・trace 語彙・正準直列化） | **runtime** | ただし上 4 規約の下で再表現 |

**台帳の一本化が肝である。** 表が 2 枚になった瞬間に drift 面が復活し、`signature_domains.rs` の prefix-free 強制も片翼になる。

### 衝突 1（署名）— ML-DSA-87、鍵は credential

mint に効く経路（receipt / leaf / vote）の署名は全て ML-DSA-87、**署名鍵 = 登録 credential 鍵**を v1 とする。delegation（credential が署名したセッション鍵）は運用要求が出てから導入し、その場合も**セッション鍵は 87 のまま**（パラメタセットを 2 つにしない）。

runtime の Ed25519 は EVM が secp256k1 に対して行ったのと同じ手筋 — **feature-gate で「provably-Ed25519-free な mint 経路バイナリ」**にする。既存 final-v7 系レシートは移行せず破棄。新規署名対象は `PENDING_SIGNATURE_DOMAINS` から正式行へ昇格させる（既存 const の流用禁止は据え置き）。

### 衝突 2（ハッシュ）— Hash64 keyed BLAKE2b-512 を全面採用

判定基準は「**合意側の誰かが再計算する値か**」。`output_commitment` / checkpoint・execution root / route root / state root / schedule commitment は全て該当し、端から端まで同一関数でなければ再計算照合が成立しない。keyed BLAKE2b の key/context がチェーンのドメイン分離機構なので、**runtime の各ハッシュ site も台帳の行**（prefix-free 対象）になる。

BLAKE3 は、**S0 実測で BLAKE2b が受領税目標（<1%）を割ると判明した場合にのみ**、宣言行付きの第二ハッシュとして検討する。既定は一本。

### 衝突 3（射影）— `MatchProjectionV2` として作り直す

V1 の `runtime_class_id` 一致要件をコピーすると「異機種が bit 一致しても永久に mint されない」— 単一プール化の否定になる。§4.4 の原子性規則を runtime 側にも適用し、**射影の再定義と diversity 述語の削除を同一統合で**行う。

中身は §4.3 の exact-match 集合、`runtime_class_id` は `ImplementationTelemetry` へ。**V1 の名前は再利用しない** — 「名前だけ同じで中身をすり替えると未来の実装者が泣く」は本 ADR 自身の言葉である（`sample_auditors_by_score` 改名と同じ理由）。

### Receipt v3 一括破壊変更

上 3 点は個別に入れず、予約済みバンドル（ML-DSA envelope / Hash64 / leaf フィールド / challenge 束縛 / checkpoint root）へ吸収し**破壊は 1 回**。runtime 側の作業順:

```text
台帳行の追加 → Hash64 化 → ML-DSA 化(Ed25519 gate-out) → ProjectionV2
        ↓
ここまで来て初めて「domain タグ・フィールド順序・エンディアンを写す」が安全になる
```

---

## 6. Remediation 順序

### P0 — 停止措置（即時。activation 前の絶対条件）

| # | 内容 | 対応所見 |
|---|---|---|
| P0-1 | **`--palw-demo-mint` を devnet-palw 限定へ戻す**（gate と CLI help の両方）。または production `ConsensusApi` から除去 | DEMO-01 |
| P0-2 | 陳腐化コメント・**虚偽の達成記載**の訂正。**ADR-0039 R2 を「片翼のみ実装」へ訂正**（§2.6.2）、`palw.rs:1011` の直説法を義務形へ。その他**最低限**: `body_validation_in_context.rs:85`、`consensus/pow/src/lib.rs:235`、`mil/core/src/palw.rs:229`、`kaspad/src/args.rs:557`、`pre_ghostdag_validation.rs:43/:71/:90`。**この列挙は網羅ではない** — G1 の verifier は「PALW 関連の inert/hash-floor 主張コメントを機械走査し、活性化 preset の実挙動と矛盾しないこと」を検査する | DOC-01/02 |
| P0-3 | PALW preset へ `palw_algo4_accept: bool` を追加し、`testnet-palw`(110) / `devnet-palw`(111) で既定 **false**。false の間 algo-4 header を reject。**解除条件は §7.1.1 の規範文に従う（ここには書かない）** | 全 PROD 所見 |
| P0-4 | leaf の `reward_script` に **coinbase output 規則（PQ class + 150 byte）を admission 時点で適用** | **ECON-01** |
| P0-5 | `quorum_reached` に `total_auditor_stake == 0` **および** `num == 0` の守護を追加。**併せて `beacon_quorum_reached` にも `num == 0` 守護を追加**（下記注記） | CERT-01, QUORUM-02 |

> **P0-5 の根拠と、由来の訂正。** 姉妹関数 `beacon_quorum_reached`（`consensus/core/src/palw.rs:728-747`）は
> `den == 0` と `committed_stake == 0` の守護を持ち、後者のコメントは**この vacuous `0 >= 0` バグを名指しで識別している**。
> したがって「見落としであって設計判断ではない」という結論は正しい。
>
> ただし移植元は**半分しか存在しない**。`beacon_quorum_reached` に **`num == 0` の守護は無い**（`:735-737` は `den` のみ）。
> `num == 0` なら RHS が 0 となり beacon 側も vacuously true になるため、**これは certificate quorum とは独立の未計上欠陥である**
> （§2.3 QUORUM-02）。P0-5 は両関数を同時に修正する。

### P1 — consensus integrity（activation の前提）

| # | 内容 | 対応所見 |
|---|---|---|
| P1-1 | leaf を **content-addressed かつ immutable** に保存（put-if-absent）。`leaf_root` reduction を実装し `palw_leaf_root()` を実際に呼ぶ | **BIND-01** / LEAF-01 |
| P1-2 | 報酬時に mutable leaf store を再参照しない。**accepted block 時点の leaf hash / reward scripts / certificate hash を immutable snapshot として固定** | LEAF-01 |
| P1-3 | certificate の contextual verifier: ML-DSA 署名 / auditor bond / 選出 / stake / quorum / `auditor_set_commitment` / `manifest_hash` / `leaf_root` | CERT-01 |
| P1-4 | manifest ↔ leaf ↔ certificate ↔ ticket ↔ header の**完全 binding**（`cert.batch_id == header.batch_id`、`cert.leaf_root == manifest.leaf_root`、leaf membership） | BIND-02/05 |
| P1-5 | **accepted** PALW effect のみで batch view を構築（mergeset raw tx を使わない）。**自 body の effect を fold するか否かを明示的に決定し文書化する** | DOS-02, VIEW-01 |
| P1-6 | block authorization の**実装**（型・`signing_hash`・subnetwork 転送・検証節）。`eligibility_hash` に header commitment を bind | **AUTH-01/02/03** |
| P1-7 | target interval を header 申告ではなく **consensus 導出**へ | TGT-01 |
| P1-8 | algo-4 header anti-spam: full-block 受信時のみ header pipeline へ入れる、または header 段で compact ticket witness を検査 | **DOS-01** |
| P1-9 | job nullifier の **global consensus state** による重複拒否 | PCPB-01 |
| P1-10 | PCPB を pure helper から ticket validation へ接続。leaf に challenge / A_commit / snapshot root / assignment proof を追加 | PCPB-01 |
| P1-11 | view の batch 数上限、`activation_not_before_epoch` 上限、bitmap 境界、`min_samples` 前提の強制 | DOS-03/04, AO-02/03 |
| P1-12 | header shape 規則（活性化後の algo-3 header の PALW field ゼロ強制） | SHAPE-01 |
| P1-14 | **残余 Medium/Low の割当**（catch-all にしない）: `ECON-02` coinbase output cap を PALW の最大 3 output に合わせる / `ECON-04` `provider_pair_split` を production の剰余ベース分割へ統一 / `SS-04` revocation の遡及性を `revoked_from_daa` 比較で非遡及へ / `SS-05` `DbPalwLaneBitsStore` に writer を付ける（または store を削除し HOLD 源を明示） / `TGT-02` `target_daa_interval`・`slot_digest` を実経路へ接続（または削除） / `TGT-03` `active_window_intervals == 0` を admission で拒否 | ECON-02/04, SS-04/05, TGT-02/03 |
| **P1-6** AUTH-01/02/03 | **DONE** — T-shared の最大障壁。`PalwBlockAuthorizationV1` に `signing_hash` / preimage commitment / `binds_header` / `binds_leaf_authority` を実装、subnetwork `0x38` で block body 搬送、body 検証 clause 7 で強制。leaf の `ticket_authority_pk_hash` を `PalwResolvedBinding` へ射影（AUTH-03: 読み手ゼロだった）。詳細は §5.11 | AUTH-01/02/03 |
| **P1-2** LEAF-01 | **DONE**（スナップショット不要と判明）: P1-1 の write-once により `(batch_id, leaf_index)` のバイト列が受理後に変化しないため、報酬時の再読込は body 検証が証明した内容を必ず返す。スナップショットは既に不変なデータの複製になる。加えて clause 9 が `leaf_hash` を hash するので、同一キーの別 leaf はそもそも draw を満たさない |
| **P1-11** AO-02/03, DOS-03 | **DONE**: `chunk_count ≤ PALW_CHUNK_BITMAP_BITS` を admission で構造的に強制（AO-02）/ `min_samples >= 1` を lane params の validity へ（AO-03、文書化された前提を実際の前提に）/ `max_view_batches` cap（DOS-03、**上限で admission 拒否・既存 batch の追い出しはしない** — 追い出すと資源境界が検閲手段になる） |
| **P1-12** SHAPE-01 | **DONE**: 活性化*後*の algo-3 header に ticket field ゼロを強制。従来は活性化*前*のみで、後半は無制約だった（v3 preimage に入るため header malleability） |
| P1-9 | **DONE**（global job nullifier）: `PalwBatchViewV1.job_nullifiers` を新設し、leaf chunk 適用時に claim。**ticket nullifier とは別集合**（保持期間が違う: ticket は reorg horizon ≈1200 DAA、job は batch 生存期間全体）。first-claim wins、再 claim は expiry を延長しない、retain は記録 expiry で切る | P1-9 |
| P1-15 | **DONE**（class レジストリ / SC-08）: `resolve_compute_set` → `PalwSetResolution{Active,NotGoverning,Unregistered}`。**未登録は fallback ではなくゼロ**（fail-closed）。旧 `resolve_compute_work_scale` は `#[deprecated]` 化し、hazard をテストで pin | SC-08 |
| P1-13 | **PALW overlay state の pruning-point / trusted-block import 経路を新設**（`PalwPrunedFrontier` の writer/reader、pruned/trusted IBD 時の leaf・view 再構成）。**回帰テストではなく新規実装であるため G7 に畳まない**（§7.2 の注記） | BIND-04, SS-01 |

### P2 — 参加者集合と監査

| # | 内容 | 対応所見 |
|---|---|---|
| P2-1 | 単一 provider registry。**credential 単位の bond 集約**と bond 加重非復元抽選 | SEL-01 |
| P2-2 | 最低 bond / 成熟窓 / unbonding / conformance 期限の実装 | SEL-01, ECON-03 |
| P2-3 | auditor が実際に監査する（DA 取得 / PCPB 検証 / sample replay / execution root 比較 / trace opening / pool coverage / canary） | 監査 2 #6 |
| P2-4 | `audit_sample_root` を producer 任意入力ではなく **beacon + manifest + DA inventory から全ノードが再導出** | CERT-01 |
| P2-5 | provider bond の存在・額・熟成・unbond・slash を consensus state として実装 | ECON-03 |
| P2-6 | **`receipt_da_root` の決着**: (A) DA 層が無い間は field を削除するか、(B) DA object 仕様 + `da_retention_epochs` による時間境界 + P2P request/response + 不履行を証明する challenge tx を**単一 slice として**実装する。雛形は `PalwBeaconCommitV1` の commit/reveal/期限（PALW で継続的義務が閉じている唯一の例） | DA-01 |
| P2-7 | `audit_sample_root` を beacon + manifest + committed leaf 集合から**全ノードが再導出**し、不一致 certificate を拒否。`auditor_set_commitment` の照合を追加 | SAMPLE-01, AUTHSET-01 |

### P3 — 整数正準化

| # | 内容 |
|---|---|
| P3-1 | `QInt8` newtype（−128 を型で排除）、oracle の `checked_add` / assert 化、拒否ベクタ追加 → **INT-01** |
| P3-2 | trace root 導出から `runtime_class_id` を除去 → **MATCH-01** |
| P3-3 | `compute_set_id` / `implementation_id` を Receipt v2 で分離 |
| P3-4 | 述語削除 + 全 root exact match を**原子的コミット**で（§4.4） |
| P3-5 | 境界表を `compute_set_id` の被覆へ |
| P3-6 | 3 backend + CPU reference の整数実装と pairwise conformance |

### P4 — 経済と紛争

| # | 内容 |
|---|---|
| P4-1 | `PalwIntegerTraceVmV1`（versioned canonical op を 1 step 決定的に実行） |
| P4-2 | semantic Merkle 二分探索による帰責 |
| P4-3 | 自動 slash を客観的 fault に限定 → VM 完成後に計算不正を追加 |
| P4-4 | β 自動縮退機構（§5.3） |
| P4-5 | adaptive `m` と `base/(1+m)` 報酬一般化（`reward_set_root` が受け皿、LeafV2 移行に同梱） |

> **報酬の現状。** coinbase の 38.5%/38.5% は `a = base/2; b = base − a`（`processes/coinbase.rs:183`）であり、**m = 1 の均等配分として既に正しい**。検証者プレミアムは存在しないため削除対象は無い。adaptive m で `base/(1+m)` へ一般化するのみ。

---

## 7. Activation gates

### 7.1 生成方式（drift 面を増やさない）

**ゲート表は散文で二重管理しない。** `mint.rs` ゲート表と同じ原則で、Rust の const table を単一の真実源とし、markdown はテストが生成する。

```rust
// consensus/core/src/palw_gates.rs
pub struct PalwActivationGate {
    pub id: &'static str,
    pub title: &'static str,
    pub blocking: GateClass,          // StopShip | Activation | WeightRaise
    pub evidence: GateEvidence,       // TestSuite | Measurement | ExternalAudit | Signoff
    pub verifier: &'static str,       // 到達を判定するテスト名 / 計測名
}

pub const PALW_ACTIVATION_GATES: &[PalwActivationGate] = &[ /* G1.. */ ];
```

```text
#[test] fn palw_gate_table_matches_adr_0040()
    → docs/adr/0040 §7.2 の <!-- BEGIN GENERATED --> ブロックと const table を突合。乖離で落ちる。
#[test] fn every_gate_verifier_resolves()
    → verifier 名が実在の #[test] / bench / measurement harness に解決することを確認。
      文字列の非空チェックでは不十分（「後で決める」を型で防ぐ、が空振りする）。
#[test] fn gate_class_lever_mapping_is_total()
    → 各 gate の blocking が §7.1.1 の lever へ一意に写り、
      StopShip ∪ Activation が accept flip の前提条件と厳密一致することを確認。
```

#### 7.1.1 lever ↔ gate の規範定義（**本文書中でここにのみ書く**）

PALW には**独立した 3 つの lever** がある。`consensus/core/src/config/params.rs:376-378` が既に acceptance と fork-choice credit を別 lever として扱っており（"Stage A can accept and measure the replica lane with `scale = 0`"）、本 ADR はそこへ 3 つ目を追加する。

| Lever | 実体 | 解除に要する gate class |
|---|---|---|
| **land** | PALW コードを preset へ載せること | `StopShip` |
| **accept** | `palw_algo4_accept` を false → true | **全 `StopShip` + 全 `Activation`** |
| **weight** | `palw_compute_work_scale` / `weight_factor_bps` を 0 超へ | 上記 + `WeightRaise`（= **G14**）|

> **規範文。** algo-4 accept を true にできるのは、**全 `StopShip` gate と全 `Activation` gate が PASS した時に限る。**
> `palw_compute_work_scale` が 0 を超えられるのは、それに加えて**全 `WeightRaise` gate が PASS した時に限る。**
>
> **範囲（「G1–G13」等）で書かない。** ゲートを 1 本追加するたびに散文が壊れ、しかも生成ブロックの外にあるため
> 差分検出できない。クラスが唯一の量化子である。

**この写像は §7.1 の const table が唯一の真実源であり、§6 / §9 は再掲しない。** 以前の草案では accept の解除条件が P0-3 と §7.2 脚注と GateClass 分類の 3 箇所に書かれ、**互いに 2 つの Critical 分ずれていた**（G1–G4 は §2.1 の 5 Critical のうち 3 つしか覆わず、DOS-01 は G6、LEAF-01 は G7 に係る）。散文は生成ブロックの外にあるため `palw_gate_table_matches_adr_0040()` では検出できない。よって `gate_class_lever_mapping_is_total()` を置く。

### 7.2 ゲート定義

`misaka-palw-replica-gemm-v0.2.md` §32 の既存停止条件を**置換せず拡張**する。

以下は const table からの生成ブロックである（手編集禁止）。

<!-- BEGIN GENERATED: PALW_ACTIVATION_GATES -->

| ID | 種別 | 閉じる所見 | ゲート | 証拠 | verifier |
|---|---|---|---|---|---|
| **G1** | StopShip | DEMO-01, DOC-01/02 | P0-1/2 完了 + `palw_algo4_accept` が両 PALW preset で既定 false かつ false の間 algo-4 header を reject | TestSuite | `palw_p0_stop_measures_hold` |
| **G2** | StopShip | ECON-01 | 任意の登録 reward script から導出した coinbase が isolation 検証を通る（property test）**かつ** 規則違反 script が admission で落ちる（拒否テスト） | TestSuite | `palw_reward_script_coinbase_representable` |
| **G3** | StopShip | BIND-01, LEAF-01 | leaf が `manifest.leaf_root` に reduce することの強制、注入 leaf の拒否、**および同一 key への異内容再書き込みの拒否**（content-address + put-if-absent） | TestSuite | `palw_leaf_membership_and_immutability` |
| **G4** | StopShip | CERT-01 | 偽署名 / zero-stake / `num==0` / 未選出 auditor / 不整合 root の各 certificate が拒否される | TestSuite | `palw_certificate_contextual_reject` |
| **G5** | Activation | AUTH-01/02/03 | authorization の生成・転送・検証と `eligibility_hash` への header commitment bind。**当選 ticket の再鋳造不能性テスト** | TestSuite | `palw_ticket_not_restampable` |
| **G6** | Activation | DOS-01 | algo-4 header の無償受理経路が無いこと。**閾値は §10-8 で確定**（header flood 下の per-header DB write 数と p99 処理時間の上限） | Measurement | `palw_header_spam_bounded` |
| **G7** | Activation | TGT-01, BIND-02/03, DOS-02/03/04, VIEW-01, QUORUM-02, ECON-03, PCPB-01, SHAPE-01, SAMPLE-01, AUTHSET-01, DA-01 | **左列に列挙した所見 ID ごと**に回帰テストが存在し緑（catch-all 禁止。ID 表は const table が保持し、§2 の PROD 行と突合される） | TestSuite | `palw_prod_findings_all_covered` |
| **G8** | Activation | — | 正準 artifact を**二者独立生成**し byte hash 一致。`PalwComputeSetRecordV1` を committed 状態として登録 | Measurement | `palw_artifact_reproducible` |
| **G9** | Activation | INT-01 | 全 K0/K1 ベクタ（**拒否ベクタ K0-R1..R5 含む**）が CPU reference と各 backend で一致。**cross-machine のため Measurement** | Measurement | `palw_conformance_vectors_match` |
| **G10** | Activation | MATCH-01 | pairwise cross-backend: 短 job 1,000 件・long job 100 件・最大 prefill・MoE 境界（router tie / expert merge）・recurrent 境界で**不一致ゼロ** | Measurement | `palw_cross_backend_pairwise` |
| **G11** | Activation | — | 72 時間 soak で不一致ゼロ | Measurement | `palw_soak_72h` |
| **G12** | Activation | PCPB-01 | PCPB / escrow / reroll / timeout / global nullifier の multi-node E2E | TestSuite | `palw_pcpb_e2e` |
| **G13** | Activation | SEL-01, SLASH-01 | **実 auditor quorum** の E2E（偽造 certificate / zero-stake quorum / **credential 単位集約による bond 分割 Sybil** / auditor withhold / reorg） | TestSuite | `palw_auditor_quorum_e2e` |
| **G14** | WeightRaise | — | β 自動縮退機構が稼働し、観測集中度が宣言 β_max を下回る。`weight_factor_bps` は 0 から段階的にのみ上昇 | Measurement + Signoff | `palw_beta_degradation_live` |
| **G15** | Activation | DA-01, SAMPLE-01, AUTHSET-01, PMC-01 | **強制点走査（§2.6）が gap ゼロ**: 全 hash-committed オブジェクトについて、preimage の性質を主張する規則には合意視野内の強制点が存在する。**初回走査済み — 現在 gap 7 件**（§2.6.1） | TestSuite | `palw_enforcement_points_total` |

<!-- END GENERATED -->

> **BIND-04 / SS-01（pruned-IBD 経路）は G7 の列挙に含めず、§6 P1-13 で独立に扱う。** これらは「テストを足す」ではなく「存在しない import 経路を作る」課題であり、回帰テストゲートに畳むと実装が不可視化される。

**解除条件は §7.1.1 の規範文が唯一の定義である。本節は再掲しない。**

---

## 8. Testnet ladder S0–S6

T0–T4 を置換する。

### S0 — Canonical conformance（**内部階層を持つ。単塊にしない**）

S0 を 1 つの塊にすると必ずそこで停滞する。以下の階層で刻む。

| 段 | 対象 | 出口条件 |
|---|---|---|
| **S0-a** | primitive: INT4 unpack / INT8 GEMM / INT32 累積 / RNE | CPU reference と全 backend で bit 一致 + 拒否ベクタが正しく落ちる |
| **S0-b** | requant: fixed scale / right shift / clamp / bias 適用順序 / **int64 累積および 128 位置境界での hierarchical requant**（§10 が int32 に収まらないと分類する softmax·V 経路。`hierarchical_int_reduce` は実装済だが呼び出し元が無い） | 同上 + 境界跨ぎで総和が block 幅に依存しないこと |
| **S0-c** | LUT: softmax / rsqrt / SiLU / RoPE table | LUT byte root 一致 + runtime 生成の不在確認 |
| **S0-d** | 単層: RMSNorm / attention / MoE router / top-k tie / **expert merge の縮約順序** / **shared expert 実行** / **gated-delta recurrent state 遷移**（A3B は MoE + hybrid recurrent。両者の spec 章は未執筆＝§10-10） | 1 layer state root 一致 + recurrent state root 一致 |
| **S0-e** | モデル級: 短 end-to-end → 長 prefill → 256〜1024 decode → recurrent state 成長 → **argmax tie-break（同値 logit で小さい token id）** | 全 root 一致、不一致ゼロ、**tie 判別ベクタが全 backend で同一 token を選ぶ** |

各段の出口は次段の入口である。`743652581b0b9725` の単一一致は **S0-e の出発点であって S0 の証明ではない**（リポジトリ外の実測値であり、committed conformance vector ではない）。

**許容誤差はゼロ。** `benign mismatch = 0` が出口条件。

#### S0 → S1 の接続（欠けやすい一段）

S0-e の出口は「実装同士が一致した」ことしか示さない。S1 が消費するのは**committed な集合定義**であるため、両者の間に成果物を作る段が要る。

```text
S0-e 出口（全 backend bit 一致）
        ↓
S0-f: 一致したベクタ集合を vector_commitment へ畳み、
      artifact_sha256 / 境界表 / LUT roots / schedule version と併せて
      PalwComputeSetRecordV1 を構成し、weight_factor_bps = 0 で登録   ← G8 が判定
        ↓
S1 入口（registry が参照すべき compute_set_id が存在する）
```

**S0-f を欠くと S1 は「どの集合に適合するのか」を指せない。** `PalwComputeSetRecordV1` は `consensus/core/src/palw.rs:2801` に型として存在するが、登録経路は未配線である（§3.6 SC-08）。

#### 各段の出口述語

S1–S6 も同様に、出口を「その段で新たに**反証されなかった**主張」として書く。

| 段 | 出口述語 |
|---|---|
| S1 | 抽選が credential 単位集約で行われ、bond 分割が抽選確率を変えないことを実測で確認 |
| S2 | A_commit 前に snapshot が凍結され、B が A の結果を参照できないことを timing 込みで確認。reroll 上限が効く |
| S3 | 偽造 certificate・zero-stake quorum・未選出 auditor が**全て拒否**され、正当な quorum のみ通る |
| S4 | 故意 mismatch から divergent op / tensor chunk が一意に特定でき、escrow が honest 側の費用を補償する |
| S5 | 上記が実ネットワーク条件（reorg / pruning / IBD / crash）下でも保持される |
| S6 | 縮退機構が実際に発火し、cap が意図どおり効く |

### S1 — Single Registry

provider registration / bond / 成熟 / conformance 期限 / frozen snapshot / **credential 単位加重抽選**。報酬 = 0。

### S2 — PCPB

A commit / future beacon による B 割当 / B receipt / A reveal / timeout / reroll / escrow / global nullifier。multi-node。報酬 = 0。

### S3 — Real BatchCertificate

独立 auditor 選出 / sample plan / replay / vote / quorum / certificate TX / reorg / duplicate certificate / **偽造署名試験**。

### S4 — Dispute shadow mode

mismatch を故意に発生させ、divergent op 特定 → tensor chunk 特定 → timeout 処理 → escrow 補償まで。**correctness slash は無効のまま。**

### S5 — No-value public testnet

```text
compute weight = 0
provider reward = test token のみ
main subsidy への影響 = なし
```

### S6 — Capped activation

全 gate 通過後: mint cap 小 / `m` 固定 / `q` 高め / 成熟窓長め から開始。

### 8.1 certificate 方式の位置づけ

| 方式 | 用途 | 報酬 |
|---|---|---|
| seeded certificate | unit / demo fixture のみ | 0 |
| quorum=1 self-audit | TX 配線・状態機械試験のみ | 0 |
| 独立 auditor quorum | **公開 testnet 以降は必須** | 条件付き有効 |

---

## 9. 停止条件

`misaka-palw-replica-gemm-v0.2.md` §32 の既存停止条件に**加えて**、以下のいずれかが満たせない場合 algo-4 の DAG weight を 0 から上げない。

- §2.1 の Critical および §2.2 の PROD High が全て閉鎖され、回帰テストが緑
- §7.1.1 の規範文が定める **weight lever の解除条件**が満たされている（判定は §7.1 の const table。本節は条件を再掲しない）
- 帰責可能性が実証されている（`effective_slash > 0`。§5.4）
- β 自動縮退機構が稼働している（§5.3）
- 正準 artifact hash が実値で固定され、二者独立生成で一致（`artifact_sha256 = TBD_BEFORE_ACTIVATION` のままでは不可）

**mainnet 経路は本 ADR の範囲外。** remediation 完了と独立再監査を経た別 ADR を要する。

---

## 10. 未決定事項（人間の判断を要する）

1. **SC-01/SC-02** — 正準 identity の確定。`canonical-compute-v1` §15（9B fp genesis）、§19.5b（35B abliterated）、コード（4B/35B Q4 fp の 2 tier）の 3 者不一致を 1 つへ。
2. **SC-13** — QW4 を I-9 cross-tier 試験 fixture として残すか、単一 set へ潰すか（コードは 2 tier に hard-depend）。
3. **SC-14** — Level-3 品質ゲートを前提条件として残すか。`integer_tier_eval_passes` に committed budget と calibration が無い。
4. **SC-11** — §4「Q4 dequantization and integer dot」の扱い（Q4_K_M 降格により孤児化）。
5. **SC-08** — `weight_factor_bps = 0` を明示表現可能にする wire 変更の可否。
6. **LeafV2 移行のタイミング** — re-genesis に同梱するか、v1 を `m = 1` 固定で運用するか。
7. **β_max の宣言値**と `ε_pair` の初期値、および §5.3 の縮退曲線。
8. **§5.3 の縮退が consensus 則かガバナンス手続きか。** 観測集中度は `PalwProviderRecordV1` の credential
   集約から**決定的に計算できる**ため consensus 則にできるが、`delegation_root`（同一運営者クラスタの識別）
   に対応する field が現状存在しない。field を追加して consensus 則にするか、クラスタ判定を off-chain に
   残してガバナンス手続きにするかで、**G14 の証拠種別が変わる**。
9. **G6 の閾値** — algo-4 header flood 下の per-header DB write 数と p99 処理時間の上限。現状 G6 は数値の
   無い唯一の Measurement gate であり、gate struct に閾値を保持する field も無い。
10. **35B-A3B 用 overflow budget 表**（op × max-shape）。`canonical-compute-v1` §10 の表は QW9 shape table
    向けにのみ存在し、凍結対象 set の `compute_set_id` 入力が確定しない。
11. **A3B の MoE / gated-delta recurrent の spec 章**。S0-d の単層出口述語の前提であり、両章とも未執筆。

---

## 11. 最終判断

```text
閉鎖 devnet の no-value 配線試験        : 開始可能（P0 完了後）
既知実機による conformance 試験         : 整数 backend 実装後に可能（S0）
公開 no-value testnet                   : 現状は不可（P0+P1 必須）
provider 報酬付き testnet               : 不可
PALW compute weight 有効化              : 不可
mainnet mint-grade                      : 不可
```

**単一プール化は設計を整理するが、未検証 certificate が突然安全になる魔法ではない。配線の穴は配線の穴のままである。**

本 ADR の最重要不変条件を再掲する。

> 単一プールとは、A が自分で自分を承認できるという意味ではない。
> 全員が同じ登録集合に所属し、各ジョブの役割だけを commit 後の乱数で分けるという意味である。
