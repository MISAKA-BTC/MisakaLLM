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

最後に **§2.6 の強制点走査を実施**し、初回走査で gap を検出（11 件棄却、**84 件を CLEAN として明示確認**。
初回の gap 内訳は §2.6.1 の表を正とする）。うち 1 件（SAMPLE-01）は、**既存 ADR-0039 が達成済みとして記録
している remediation が実際には片翼しか実装されていない**ことを明らかにした（§2.6.2）。**その後の
remediation で残 gap は 2 件（DA-01 / PMC-01、ともに off-chain）まで縮小した**（BIND-01=P1-1 / AUTH-01=§5.11 /
SAMPLE-01・AUTHSET-01=§5.17 CERT-REDERIVE で閉鎖）。この現状は meta-test `palw_enforcement_points_total`
が機械的に pin する（§2.6.1 / §7.2 G15）。

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

> **読み方（重要）。** §2.1 / §2.2 / §2.3 の各行は **監査時点で発見されたままの所見**であり、`位置` 列の file:line も**当時のもの**である。remediation で行が移動・書き換えられているため、現在の行番号としては読まないこと。**現在の状態は §5.6 / §5.6.1a / §5.6.1b / §5.11 / §5.12 / §6 の各表が正である。**
>
> 特に紛れやすい対応を先に置く。
>
> | 本節の所見 | 現在の状態 | 参照 |
> |---|---|---|
> | AUTH-01 / AUTH-02 / AUTH-03 | **CLOSED** — authorization は生成・搬送・検証まで実装。束縛は 9 値 allowlist ではなく **header preimage 全体**（`palw_authorization_commitment`）。0x38 tx の形と**位置**も pin 済み | §5.11（続報 / 続報 2） |
> | BIND-01 / LEAF-01 | **CLOSED** — `insert_leaf` の content-addressed write-once 化 | §5.6 P1-1 |
> | CERT-01 / QUORUM-02 | **CLOSED** — `verify_certificate_attestation` + `num==0` 守護 | §5.6 P0-5 / P1-3 |
> | BIND-02 | **CLOSED** — 永続化時（§5.6 P1-4）+ **参照時**（`resolve_palw_binding` の `CertBatchMismatch`、§5.6.1b） | §5.6.1b |
> | ECON-01 / DOS-01（拒否経路）/ DEMO-01 / DOC-01/02 | **CLOSED** — P0 全 5 項目 | §5.6 |
> | TGT-01 | **棄却**（監査側のモデル誤り） | §5.12 P1-7 |
> | DOS-02 / BIND-03 | **DOS-02 = CLOSED**（削除により、§5.12「P1-5 / DOS-02」）。BIND-03 は座標決定として**確定**（view は body/mergeset に留まる） | §5.12 |

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
| **DOS-01** | algo-4 header は Layer-0 PoW を**完全免除**。header 段階の全 store write（BTreeMap clone + persist を毎 header）が無償。`palw_compute_work_scale = 0` のため compute cap は**構造上一度も発火しない**。**訂正（§5.13）**: コスト境界は当初記載の `O(nullifier-retention)` ではなく **`O(retention × mergeset_size_limit)`**（10 BPS で 1,200 × 248 ≈ 297,600 entry ≈ **21 MB / header**）。理由は fold が `mergeset_blues` 全件で `mergeset_non_daa` に濾されない一方、prune は blue 自身の `daa_score` を鍵にするため | `pre_ghostdag_validation.rs:130`<br>`header_processor/processor.rs:416-443` | PROD |

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
| DOS-02 | `commit_palw_overlay_view` が**acceptance フィルタ無し**に全 mergeset-blue tx の PALW effect を fold → never-accepted / 手数料無し / 二重支払 tx が view を変更。**真の重大部分は無制限 `job_nullifiers`**（ブロック毎に clone・再永続化される構造へ ~640 件/block） | `body_processor/processor.rs:356` | **CLOSED（削除）** |
| VIEW-01 | `commit_palw_overlay_view` は `mergeset_blues.filter(!= selected_parent)` を fold するが、**ブロック自身は自分の mergeset に含まれない**ため、**自 body の PALW effect が自 view に入らない**。同一ブロックで登録した batch を同一ブロックの ticket が参照できない。意図的な可能性はあるが**文書化されておらず、C-03 の指摘の半分はこちら** | `body_processor/processor.rs:356` | PROD |
| DOS-03 | `PalwBatchViewV1` に batch **数**の上限が無い。毎ブロック clone + persist するため、手数料のみで律速される manifest flood が増幅 | `body_processor/processor.rs:352` | PROD |
| DOS-04 | `admission_valid` が `activation_not_before_epoch` に上限を課さないため、view entry を恒久 pin 可能 | `consensus/core/src/palw.rs:973` | PROD |
| SS-01 | `PalwPrunedFrontier` store は writer / reader ともにゼロ → PALW preset で pruned / trusted IBD が 3 箇所の fail-closed panic に当たる | `consensus/src/model/stores/palw_pruned_frontier.rs:52` | PROD |
| DA-01 | `receipt_da_root` の**提供義務に強制点が無い**。設計 §10.5 は fraud window 中の P2P 取得可能性を要求し、§5 は DA 拒否を自動 slash 可能な客観的 fault と宣言するが、DA object 仕様・時間境界・P2P request message・challenge tx のいずれも存在しない。**義務を負ったように読める空の root** | `consensus/core/src/palw.rs:875` | PROD |
| SAMPLE-01 | `audit_sample_root` は非テスト読み取りゼロ。doc は consensus が独立再導出すると**直説法で**述べるが実装は無く、**ADR-0039 R2 は達成済みと記載**（§2.6.2）。**設計を精緻化（§5.17、DESIGN-ONLY）**: 再導出関数が存在せず、sample 対象の receipt chunk は**オフチェーン DA**で consensus は root を再計算不能 → 健全版は on-chain per-leaf DA-commitment 上の root への**再定義**を要する spec 変更。activation-blocking（P2-7）。**LANDED（§5.17、INERT・2026-07-20）**: `palw_deterministic_sample`+`palw_audit_sample_root` 再導出を `verify_certificate_attestation` に配線、vote は再導出 root 上で検証 | `consensus/src/processes/palw.rs`（verifier）/`consensus/core/src/palw.rs`（primitives） | PROD → **LANDED（§5.17）** |
| AUTHSET-01 | `auditor_set_commitment` は repo 全体で読み手ゼロ。auditor 集合が beacon 選出であるという設計 §10.1/§10.2 の主張に強制点が無い。**設計を精緻化（§5.17、DESIGN-ONLY）**: commitment 照合には選択関数が要るが唯一の実在物 `sample_auditors_by_score` は未加重（SEL-01）で doc が production caller を禁じる → **SEL-01 の加重サンプラーの上でしか着地できない**。activation-blocking（P2-7）。**LANDED（§5.17、INERT・2026-07-20）**: `select_auditor_committee` 再導出+commitment 照合+slate 外投票拒否を配線 | `consensus/src/processes/palw.rs`（verifier） | PROD → **LANDED（§5.17）** |
| SEL-01 | provider / auditor 抽選が **bond 加重でない**。`auditor_score` は outpoint 単位ハッシュ順、`provider_index` は一様。**最低 bond も無い**（`amount_sompi != 0` のみ）ため bond 分割が無償 → 100 分割で抽選券 100 枚。**資本下限側は ECON-03 で CLOSED（§2.3′）** — 加重に使える解決済み担保が実在。**加重サンプラーは §5.17 で LANDED（INERT・2026-07-20）**: `aggregate_provider_credentials_at`+`palw_weighted_sample_without_replacement`+`select_auditor_committee` が唯一の選択器として verifier/producer 両方に配線、G13/P2-1 | `consensus/core/src/palw.rs`, `consensus/src/processes/palw.rs` | PRIM → **CLOSED（§5.17、INERT）** |
| PCPB-01 | PCPB が ticket 検証に接続されていない。`palw_challenge_fresh` / `palw_pcpb_derive_b` / `palw_dispatch_proof_valid` は production 呼び出し元ゼロ。`PalwPublicLeafV1` に challenge commitment / A_commit / snapshot root / dispatch proof / assignment proof が**全て存在しない** | `consensus/core/src/palw.rs:146` | PROD |
| INT-01 | **整数 oracle が自身の凍結規則に違反。** `canonical_int_gemm` は `&[i8]`（−128 を許容）を取るが doc は `K·127²` 境界を前提。accumulator 境界 assert 無し、overflow flag 無し。**release で無警告 wrap、debug で panic** → ビルド構成で結果が変わる | `mil/core/src/palw_canonical.rs:49` | PRIM |
| MATCH-01 | `runtime_class_id` は `gpu_arch_class` と `kernel_graph_hash` を構造的に含み、さらに **Qwen backend が trace root を `runtime_class_id` から導出**している → cross-backend の trace 一致は構造上不可能 | `mil/core/src/palw.rs:138`<br>`qwen_backend.rs:158` | PRIM |
| ECON-03 | 77% provider base が**解決済み担保ゼロ**に対して支払われる。provider-bond tx は consensus state を生まず、leaf bond outpoint は解決されない | `consensus/src/processes/palw.rs:113` | PROD → **部分 CLOSED（下記 §2.3′）** |

### 2.3′ ECON-03 の現況（leg 1/2/3/4/5 + THE WIRE + CRITICAL-1 実装済み、slashing 未着手）

**丸め上げ禁止。** 以下は「何が enforced になったか」と「何が依然として enforced でないか」を、行ごとに実コードの位置とともに述べる。

#### CLOSED（実コードで強制され、テストが存在する）

| 内容 | 強制点 | テスト |
|---|---|---|
| **値ロック**（`amount_sompi` が output-0 の value と一致し、output-0 が owner の ML-DSA-87 P2PKH を支払う） | `validate_provider_bond_tx`（isolation validator — 拒否が loud な座標） | `econ03_a_provider_bond_with_no_backing_is_rejected` |
| **registry（prefix 241）に writer が存在する。** 受理された `0x30` tx が selected-chain commit で `PalwProviderBondRecord` として書かれる | `stage_palw_provider_bond_mutations`（virtual_processor/processor.rs、`stage_dns_bond_mutations` と同一 batch・同一 detach-before-attach 順） | `econ03_funded_provider_bond_tx_enters_the_registry`（実際に funded・ML-DSA-87 署名済みの tx を採掘して store を確認） |
| **leaf の bond outpoint が解決される。** `provider_a_bond` / `provider_b_bond` の**両方**が支払いブロックの point of view で `Active` に解決しない限り、**77% base は支払われない** | `palw_work_reward_class`（virtual_processor/utxo_validation.rs）→ `WorkRewardClass::ReplicaPalwUnbackedCollateral`（全軸ゼロ支払い） | `palw_algo4_unbacked_provider_bond_pays_nothing_e2e`（UNKNOWN / UNBONDING / PARTIAL の 3 系）、`palw_unbacked_collateral_sources_pay_nothing` |
| **status は DAA stamp から導出**（mutable `status` field を持たない）。apply/revert が構成上厳密な逆写像 | `effective_provider_bond_status` | `econ03_view_apply_and_revert_are_exact_inverses`, `econ03_registry_walk_is_reorg_path_independent` |
| **authorized exit（leg 5）に production caller がある。** `0x37` は owner の ML-DSA-87 署名が network/bond 束縛 digest 上で検証されない限り no-op（下記 leg 5 注も参照） | `palw_provider_unbond_authorized` ← `ProviderUnbondAuthFilter`（per-tx mergeset acceptance SKIP） | `econ03_only_the_bond_owner_can_request_an_exit` ほか |
| **spend gate（leg 4）が存在する。** bond の locked output-0 は、bond が releasable（`Unbonding` かつ clamp 済み release DAA を過ぎた）でない限り**使えない**。DNS の `BondSpendFilter` と同型・同座標（per-tx mergeset acceptance SKIP、own-body ではなく **mergeset 全体**を被覆）。leg 5 が先在するため confiscation にならない（release path がある） | `ProviderBondSpendFilter::locks`（utxo_validation.rs）→ `is_provider_bond_releasable_at` | `allows_spend_of_releasable_bond` / `locks_active_and_pending_unlocks_releasable_and_non_bond` / `locks_every_non_releasable_branch_and_unlocks_the_released`（merge-blue 回帰） |
| **CRITICAL-1 — leaf は自身が名指す bond を CONTROL していることを証明する。** bond を `Active` に解決するだけでは不十分（bond outpoint は素の値であり、他人の実在 active bond を名指せる）。leaf の `provider_{a,b}_reward_script` が **各 bond の owner を支払う**（`== provider_bond_lock_spk(bond.owner_public_key)`）ことを要求 → payee ≡ bond owner ≡ slashable party を同一 identity に束縛。他人の bond を名指すと他人に支払われるため窃取が成立しない。**leaf format 変更なし**（両側が既に commit する field の純粋比較 — LEAF_LEN/LEAF_FNV/layout pin/LATEST_DB_VERSION いずれも不動）。不一致は `ReplicaPalwUnbackedCollateral`（未解決担保と同じ全軸ゼロ支払い） | `palw_work_reward_class`（utxo_validation.rs、解決 branch に fold、reward/mergeset 座標） | `palw_algo4_leaf_naming_unowned_bond_pays_nothing_e2e`（BOTH / PARTIAL の 2 系、merge-blue child 座標で被覆） |
| **anti-split floor が effective になった**（SEL-01 の資本下限側のみ）。sub-floor bond は registry に入らず、したがって `Active` に解決せず、報酬を裏付けられない | `palw_provider_bond_mutations_from_accepted_txs` の drop + `is_consistent_for_activation` の `min_provider_bond_sompi != 0` | `econ03_funded_provider_bond_tx_enters_the_registry`（at-floor は登録・sub-floor は不登録を **store 上で**確認） |

**支払い規則の位置決定（BIND-03 との整合、明記）。** 解決は **reward/virtual 座標**に置いた。`validate_public_leaf` は point of view を持たない context-free validator であり、body 座標に point-of-view 読みを持ち込むことは BIND-03 で確定済みに反する。また body で解決すると、第三者の unbond のタイミングで受理済み batch を遡って無効化できてしまう。`validate_public_leaf` の `provider_a_bond != provider_b_bond` は**形状規則として残す**（1 本の bond が pair の両側を裏付けることを防ぐ）が、経済的な load-bearing 性は失った。

**未解決担保時の挙動（規則であって comment ではない）。** `WorkRewardClass::ReplicaPalwUnbackedCollateral` — provider 出力なし・fee-worker 出力なし・inclusion pool 加算なし・validator pool ゼロ。`ReplicaPalwHalted` / `ReplicaPalwDuplicateWork` と同じ §17.4 burn-by-don't-mint。**reward-only であり block 無効化ではない**（無効化すると第三者が unbond のタイミングで採掘済みブロックを brick できる）。**G16 の duplicate-work claim より前に評価**する — 未担保 leaf に `job_nullifier` を消費させると、無償の未担保 leaf で job id を毒し、正当に bond された同一 job の source を duplicate 扱いにできるため。

#### 依然として OPEN（ECON-03 は CLOSED ではない）

1. **slashing が配線されていない。** `PalwProviderBondMutation::Slash` に **producer が無い**（`palw_provider_bond_mutations_from_accepted_txs` は `Insert` と `Unbond` しか emit しない）。dispute / fraud proof が存在しないため、bond は解決・拘束できるが没収できない。**§5.16（DESIGN-ONLY）で原因を精緻化した**: producer が書けないのは書き忘れではなく、**equivocating authority を slashable bond に束縛する LINK がデータに存在しない**ため（evidence は bond outpoint を運ばず、authority hash と bond-owner hash は異関数で、両者を結ぶ on-chain 規則も store も無い）→ slash target が導出不能。閉鎖には re-genesis 級の binding 決定が要る。SLASH-01 / §6 #8 のまま**未着手**。
2. **pruned-IBD で prefix 241 が運ばれない。** `import_pruning_point_utxo_set` 経路は空の view を渡す（BIND-04 / SS-01 が PALW overlay 全般について述べているのと同じ穴）。
3. **SEL-01 の抽選加重は未着手。** 閉じたのは資本下限のみであり、`auditor_score` / `provider_index` は依然として bond 加重でない。

したがって ECON-03 の原文「provider-bond tx は consensus state を生まず、leaf bond outpoint は解決されない」は**もはや正しくない**。担保は**拘束されており（leg 4 spend gate）**、**被支払者に所有されている（CRITICAL-1）** — つまり「77% base は解決済み・拘束済み・所有済みの担保に対して支払われる」は真になった。残る唯一の欠落は**没収可能性（slashable）**であり、それは slashing producer / fraud proof が揃ってから。fraud proof が無い段階で高額報酬を有効化してはならない（§6 #8 / mainnet activation gate）。

> **leg 5 の DoS 形状を修正した（2026-07-20）。** unbond authorizer は当初、mergeset 全体に不正な `0x37` が
> 1 件あればブロックごと拒否していた。miner は merge する merge-blue ブロックの中身を選べないので、これは
> **合意レベルの DoS**（攻撃者が不正 `0x37` を含むブロックを公開 → それを merge する正直なブロックが全て無効）
> だった。DNS bond spend gate が同型の欠陥から学んだ「ブロック拒否ではなく受理時 SKIP」へ移した:
> 不正な `0x37` は **no-op**（record を一切変えない）となり、authorized のみが適用される。`ProviderUnbondAuthFilter`
> が `BondSpendFilter` と同座標（per-tx mergeset acceptance）で選別する。旧 `RuleError::PalwProviderUnbondUnauthorized`
> は撤去し tombstone コメントのみ残した。leg 5 が正しい形になったことで、leg 4（spend gate）を安全に載せる前提が整った。

### 2.3 Medium / Low（抜粋）

| ID | 所見 | 位置 | 到達性 |
|---|---|---|---|
| AO-02 | `apply_leaf_chunk` が固定 256-bit bitmap を添字。**出荷 params では到達不能**（`max_batch_leaves` が bitmap 幅以下に制約される）が、params 変更で潜在化する。**latent** | `consensus/core/src/palw.rs:2348` | PRIM |
| AO-03 | `lane_expected_bits` / `lane_retarget_bits` が未証明の `min_samples >= 1` 前提 → 空 unwrap と Uint320 ゼロ除算。**出荷値 `min_samples: 60` かつ `is_consistent` が window 以下を強制するため到達不能。latent（誤設定時のみ）** | `processes/difficulty.rs:338` | PRIM |
| QUORUM-02 | `beacon_quorum_reached` は `den == 0` と `committed_stake == 0` を守護するが **`num == 0` を守護しない** → RHS が 0 となり vacuously true。姉妹関数 `quorum_reached` と**独立の**未計上欠陥 | `consensus/core/src/palw.rs:728` | PROD |
| SHAPE-01 | `check_palw_header_shape` / `ensure_all_palw_fields_zero` が未実装 → 活性化後、algo-3 header が任意の非ゼロ PALW field を持てる（v3 hash preimage には入る） | `pre_ghostdag_validation.rs:73` | PROD |
| SLASH-01 | §12.4 cross-fork 二重使用 slashing に verifier・penalty 経路が無い。**原因を精緻化した（§5.16、DESIGN-ONLY）**: mutation（`Slash` apply/revert）・evidence primitive（`PalwBlockAuthorizationV1`）・DNS 先例は全て在庫。真の blocker は **authority → bond LINK がデータに無い**こと（evidence は `authority_public_key` しか運ばず bond outpoint を名指さない。leaf の keyed `ticket_authority_pk_hash` は bond の unkeyed `owner_pubkey_hash` と equate 不能。authority を bond に束縛する規則も store も無い）→ producer が slash target を導出できない。加えて `SUBNETWORK_ID_PALW_SLASHING = 0x34` は **dangling mislabel**（0x34 は `from_subnetwork_byte` で **Revocation** に decode される live landmine）。閉鎖は re-genesis 級の binding 決定を要する（§5.16.9）。**第二経路の依存を明示（2026-07-20）**: §24.5 replica-mismatch 層（`PalwMismatchRecordV1`）は `provider_a`/`provider_b` bond outpoint を**直接持ち** `attribute()`+`slash_targets()` も在庫なので §12.4 の LINK 欠落を回避できる — **ただし mismatch 帰責は「参照ランタイム再実行」前提であり、それは G8-G11 の cross-device 実測機構そのものに依存する。よって SLASH-01 の実装可能版は S0（cross-device 実測完了）を待つ**。すなわち slashing は「コードの問題」ではなく「測定の問題」の側にある。**未着手** | `consensus/core/src/palw.rs:1811`（evidence primitive）, `subnets.rs:215`（0x34 mislabel、除去済み）, `:1190`（§24.5 mismatch、bond outpoint 保持） | DOC → **DESIGN-ONLY（§5.16）+ 実装版は測定待ち** |
| ECON-02 | **RESOLVED（fenced 緩和）** — PALW blue source は最大 3 coinbase output を出すが、cap は blue source あたり 1 output 想定の `ghostdag_k + 2` だった。`TransactionValidator::coinbase_outputs_limit()` へ切り出し、`params.palw_algo4_accept` で分岐（off: `k+2` = 従来と byte 同一 / on: `3(k+1)+1`）。**cap の拡大は緩和であり、無 fence で出すと live testnet-10 が fork する**ため fence 必須。**別件として明示的に残す**: cap は §E validator 出力・§D bounty を数えておらず、これは PALW 非依存の既存 latent cliff（`coinbase_output_cap_ignores_validator_and_bounty_tail` で pin） | `tx_validation_in_isolation.rs` | PROD |
| ECON-04 | **RESOLVED（削除）** — `provider_pair_split` は production 呼び出し元ゼロの dead code だった（実 mispayment ではなく spec drift）。**統一ではなく削除**: production 呼び出し元を持たない split 実装は correct-by-construction に保てず、drift して次の監査者を誤導するだけ（実際そうなった — テスト名が `coinbase_provider_split_...` で coinbase 規則を pin していると誤示）。唯一の真実源は `split_block_subsidy(...).worker_base_sompi` → `premium_split`。テストは production 合成を pin するよう**書き換えた（spec 変更に伴うテスト変更）** | `consensus/core/src/palw.rs` | PRIM |
| SS-04 | **RESOLVED** — `is_block_eligible_at(epoch)` → `(epoch, daa)`、`revoked_from_daa.is_none_or(|from| daa < from)` で §9.5 非遡及を実装（従来は `is_none()` = 完全遡及で、`mark_revoked` の doc が主張する性質をコードが持っていなかった）。`resolvable_batch` も同様。**加えて `retain` も DAA 対応**: `palw_batch_referenceable(revoked: bool)` が entry ごと落とすため、gate だけ直すと**未来日付の revocation が eviction 経由で遡及性を再導入**する。production caller は `body_validation_in_context.rs`（`header.daa_score`）と `body_processor/processor.rs`（`cur_daa`） | `consensus/core/src/palw.rs` | PRIM |
| SS-05 | **RESOLVED（第2の腕 = HOLD 源の明示。コード変更なし）** — 指摘された欠陥「doc が『毎ブロック書かれる』と主張するが writer ゼロ」は既に解消済み: `palw_lane_bits.rs:17-31` は現在**逆のことを明記**し、旧 fence 論拠が偽であることを名指しで反証し、HOLD 源が `genesis_{hash,replica}_bits`（読み口は `processes/palw.rs::resolve_palw_lane_hold_bits`）であることを述べ、自身を OPEN activation blocker と宣言している。**writer は追加しない**（clause 7 lane-retarget 配線 = activation scope、本 phase 対象外）。**store も削除しない**（`DatabaseStorePrefixes::PalwLaneBits = 245` は予約済み、read seam は将来配線が必要とする既テストの橋。削除→再追加は churn とリスクが純増） | `consensus/src/model/stores/palw_lane_bits.rs:17-31` | PRIM |
| TGT-02<br>+ TGT-03 | **RESOLVED（削除。2行は1箇所なので統合）** — `slot_digest` / `target_daa_interval` を削除（`PALW_SLOT_DOMAIN` も retire、文字列は衝突回避のため予約明記）。**配線ではなく削除の理由**: この導出は一度実装され、clause 5（`header.daa_score == binding.target_daa_interval`）と矛盾して全正直 block が `IntervalMismatch` になったため**意図的に除去された**（`body_validation_in_context.rs:170-177` に記録）。「実経路へ接続」は既知の壊れた第2 interval 規則の再導入要求にあたる。**capability の実際の出所**: interval は依然 consensus 由来 — clause 5 が header の `daa_score`（post-GHOSTDAG 検証済み、miner が選べない）に pin する。これが I-3 の求めた性質。**TGT-03 は独立に存在しない**: `active_window_intervals` は削除した関数の引数としてのみ存在し、params field も admission 経路も無い（`.max(1)` で panic もしない）。削除で消滅する — 削除済みコードに guard を足させないため統合行として記録 | `consensus/core/src/palw.rs` | PRIM |
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
| — | #8 dispute/slash 未完 | SLASH-01 / ECON-03（**§5.16 DESIGN-ONLY**: LINK 欠落が blocker、未着手） |
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

実施済み。**初回走査時点で 6 件の gap、11 件が反証で棄却、84 件を CLEAN として明示確認。**（旧版は「7 件」と書いていたが下表は 6 行であり、数が表と合っていなかった。表が正である。）

**現在の残 gap は 2 件**（DA-01 / PMC-01。BIND-01 は P1-1、AUTH-01 は §5.11、**SAMPLE-01 / AUTHSET-01 は §5.17 CERT-REDERIVE** で強制点を獲得し閉じた。下表の「現状」列を参照）。この 2 件（ともに off-chain = GapOffchain）は meta-test `palw_enforcement_points_total`（const `PALW_ENFORCEMENT_POINTS`）が Enforced 点の fn 実在照合とあわせて厳密に pin する。

| ID | オブジェクト | 主張された性質 | 強制点（初回走査時） | 現状 | 重大度 |
|---|---|---|---|---|---|
| **DA-01** | `receipt_da_root` | 「fraud window 中は P2P で取得可能」「DA unavailable 時は certificate を発行しない」（設計 §10.5）。ADR §5 は **DA 拒否を客観的 fault として自動 slash 可能**と宣言 | **不在** — DA object の仕様・時間境界・P2P request message・challenge tx のいずれも無い | **OPEN**（P2-6） | high |
| **SAMPLE-01** | `audit_sample_root` | 再定義（§5.17.6）: 証明書が beacon 選出 on-chain leaf の `receipt_da_root` に厳密に commit する（I-14 のオフチェーン所持性は**対象外**） | **LANDED（INERT）** — `verify_certificate_attestation` が再導出し不一致を拒否、vote は再導出 root で検証 | **CLOSED — LANDED（§5.17、2026-07-20）**。全 preset INERT（`palw_algo4_accept=false`） | high |
| **AUTHSET-01** | `auditor_set_commitment` | auditor 集合が beacon 選出であること（設計 §10.1/§10.2） | **LANDED（INERT）** — `select_auditor_committee` 再導出+照合、slate 外投票拒否 | **CLOSED — LANDED（§5.17、2026-07-20）**。SEL-01 加重サンプラー上に着地 | high |
| **BIND-01** | manifest `leaf_root` ↔ 格納 leaf | leaves が `leaf_root` へ reduce すること | **不在**（§2.1 と同一） | **CLOSED** — P1-1 で `insert_leaf` を content-addressed write-once 化し、LeafChunk arm に manifest 存在 / content-derived `batch_id` / `leaf_index < leaf_count` を強制（§5.6 P1-1） | critical |
| **PMC-01** | `private_match_commitment` | canary dispute 時に等値照合される | **不在** | **OPEN**（P4 dispute 依存） | medium |
| **AUTH-01** | `header_preimage_commitment` | authorization が header を bind する | **不在**（§2.2 と同一） | **CLOSED** — `palw_authorization_commitment(network_id, header, authed_root)`（`consensus/core/src/hashing/header.rs`）が block 自身の header preimage 全体を束縛し、body 検証 clause 7 が強制（§5.11 続報 / 続報 2） | medium |

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

**R2 の両翼が揃うのは §5.17 の原子スライス着地をもってである（2026-07-20 着地・INERT）。** 当初 ADR-0039 の R2 記載は「片翼のみ実装」だった（署名の coverage はあるが consensus 側の独立再導出が不在）。§5.17 スライスがその残る半翼 — `verify_certificate_attestation` での `audit_sample_root` **独立再導出**と再導出 root 上での vote 署名検証 — を着地させた。**ただし I-14 の元の「オフチェーン receipt chunk 所持」性質そのものは達成されない**: §5.17.6 の再定義により、強制されるのは「証明書が beacon 選出 leaf の on-chain `receipt_da_root` に厳密に commit する」という**より弱い（が consensus が再導出可能な）性質**である。したがって「R2 = I-14 所持性の達成」は依然**不成立**であり、「R2 = 再導出可能な被覆性の強制」は**成立（activation-gated、INERT）**。この降格の受容が §5.17.11(1) の spec 判断である。誤って「I-14 所持性が達成された」と書けばレビュアーはオフチェーン DA 攻撃面を消化済みとして通過するため、この区別を残す。

**健全な再導出の設計は §5.17（DESIGN-ONLY）に固定した。** そこで判明した決定的事実: `audit_sample_root` の再導出は「既存関数の等値検査」ではなく、対象 receipt chunk が**オフチェーン DA** であるため consensus は root を再計算できず、**on-chain per-leaf DA-commitment 上の root への再定義**（I-14 所持性より弱いが強制可能な性質）という spec 判断を要する。**加えて本 run で `palw.rs:65-67`（`PALW_AUDITOR_VOTE_DOMAIN` の const doc）に P0-2 が見落とした同型の直説法が残っていたことを発見し、非直説法へ訂正した**（§5.17.9）。~~R2 の残る半翼は §5.17 の activation スライスまで未達成のままである。~~ → **2026-07-20 に §5.17 原子スライスが着地し、再導出被覆性は強制される（INERT、上記 R2 区別のとおり I-14 所持性そのものは対象外）。**

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

## 5.6 実装状況（2026-07-20 時点）

`feat/mil-v0` にて実装済み。`cargo test --lib` 実測で `consensus-core 411（+1 ignored、PALW 無関係の既存 `bps.rs`）/ consensus 217 / mtp 21 / mtp-service 33 / dnsseeder 4 / kaspad 24` green + 実機確認 + 実ノード live 検証済、workspace の lib/bin ともビルド通過。

> 数値は手で書き換えず、必ず `cargo test -p <crate> --lib` を実行して転記すること。内訳: 2026-07-19 の `consensus-core 404 / consensus 205` → §5.11 続報 / 続報 2 の AUTH 系テストと §5.6.1a/b の CERT 系テストで `408 / 210` → 本 P1 スライス（SS-04 非遡及 / TGT 削除 / ECON-02 上限 / P1-10 layout pin / TGT-02 retired-domain 強制）で `411 / 217`。
>
> **この行自体が陳腐化しやすい。** 直前の改訂は同じ作業ツリー内で既に古くなっていた（測定後に更にテストが増えた）。数値を引用する前に必ず測り直すこと。

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

**この差は実在し、`Activation` クラスの gate（G13 — SEL-01 / SLASH-01）が塞ぐべきものである。** ただし前進は装飾的ではない — 証明書の偽造には、**実際に bond され slash 可能な stake の quorum 相当から、生きた ML-DSA-87 署名**が必要になった（従来は「正しい長さのバイト列」で足りた）。

> **訂正（gate class の帰属）。** 旧版はこの段落を「**G4** を `StopShip` ではなく `Activation` に置いている理由」と書いていたが、§7.2 の表では **G4 は `StopShip`** である。両者は矛盾しており、**§7.2 の表を正**とする。
>
> 理由: G4 が閉じるのは CERT-01（証明書の contextual 検証 — 偽署名 / zero-stake / `num==0` / 不整合 root の拒否）であり、これは §2.1 Critical そのものなので `StopShip` が正しい。ここで論じている残余は「quorum の**分母**が参加 stake であって beacon 選出 eligible set でない」ことであり、その根は **auditor 選出が bond 加重でない（SEL-01）** ことにある。SEL-01 を閉じる gate は **G13（`Activation`）** である。したがって帰属先が誤っていたのであって、クラス分類が誤っていたのではない。
>
> **lever 上の含意（§7.1.1）。** `accept` の解除には全 `StopShip` + 全 `Activation` が要るため、この訂正は accept 条件を一切動かさない。動くのは `land` lever の条件であり、G4 を `Activation` へ落とすと「CERT-01 未閉鎖のまま preset へ載せてよい」と読めてしまう。それは本 ADR の意図ではない。
>
> **G4 と G13 の境界（あわせて明記）。** §7.2 の G4 行の記述に含まれる「未選出 auditor の拒否」は選出機構（SEL-01）に依存するため、実質は **G13 側の負荷**である。G4 は「宣言された auditor 集合に対する attestation 検証」まで、G13 は「その集合が beacon 選出であること」までと読むこと。行の文言そのものは履歴として残す。

**残る未着手（正確な内訳）。** **DA-01 / TGT-01（→ §5.12 で誤検出と判明）/ BIND-03（座標決定として確定・§5.12）/ ECON-03**（**DOS-02 は §5.12 のとおり削除で CLOSED**） が未着手ないし設計上の残余である。**SAMPLE-01 / AUTHSET-01 / SEL-01 の 3 件は §5.17 の原子スライスとして LANDED（2026-07-20、全 preset INERT）** — seed resolver + 加重 credential 集約サンプラー + `audit_sample_root` 再定義 + committee/sample-size パラメタ + 有界 inclusion 窓を `verify_certificate_attestation` に配線し、producer（`mil/miner/src/audit.rs`）を同一関数上に rebuild。ただし SAMPLE-01 の I-14 オフチェーン所持性そのものは再定義により対象外（§2.6.2 の R2 区別）。一方、旧版がこの行で「未着手」と列挙していた **PCPB-01（P1-9 分）/ AUTH-01/02/03 / BIND-04 / DOS-03 / DOS-04 / SS-01** は、その後の作業で閉じた（§5.11・§5.12・§6 P1 表）。

現時点の P1 の内訳は次のとおりである（旧版の「P1 の 3 項目」は remediation 前の数）。

* **完了 9 項目**: P1-1 / P1-2 / P1-3 / **P1-5** / P1-6 / P1-11 / P1-12 / P1-14 / P1-15（**P1-9 は body 座標から撤回 = SPEC CHANGE**、§5.12）
* **部分 2 項目**: P1-4（identity 半分のみ。ただし参照時の cross-bind は §5.6.1b で追加）/ P1-13（`palw_requires_archival` による**起動時拒否**まで。pruned-IBD import 経路そのものは未実装）
* **棄却 1 項目**: P1-7（TGT-01 — 監査側のモデル誤り、§5.12）
* **未着手 2 項目**: P1-8（activation 級へ再分類）/ P1-10（PCPB を ticket validation へ接続）。加えて **P1-9-RELAND** を activation 級 gate として新規登録（§5.12）
* **再分類 1 項目**: **P1-8**（DOS-01 の header anti-spam）→ **activation 級 blocker**（§5.13）。P0-3 により現在は到達不能。設計方向は確定（Option C 主 / B 補完 / A 棄却）だが、実装はいずれも re-genesis 級かつ §16 lane DAA との同時設計を要するため本 remediation の範囲外。**「未着手」ではなく「解除前提条件として登録済み」である。**

**それでも §11 の判定は変わらない — 公開 no-value testnet は依然「不可」である。** P1-5（DOS-02）は §5.12 のとおり**削除で閉じた**が、判定は項目数では動かない: 残る **P1-8 / P1-10** と、新規登録した **P1-9-RELAND**（activation 級・DA/audit slice 依存）、および §5.12 併記の **CHUNK-INDEX SQUAT**（設計 §5.15 ACCEPT-BIND/M2 → **2026-07-20 実装済み**）が未解決である。加えて §5.15.3 のとおり **StopShip gate G3 は verifier が存在せず、その第 1 節は一度も強制されていなかった**（**同日 実在化**、§7.2 G3 行を実在 verifier 群へ差し替え）。**「P1 の残りが少ない」ことと「P1 が完了した」ことは別である。** なお全 6 preset で `palw_algo4_accept = false` は維持されており、PALW leaf は 1 件も支払われない。

> **2026-07-20 の更新後も §11 の判定は動かない。** CHUNK-INDEX SQUAT の利益の出る半分が閉じ、G3 が実在化したのは前進だが、判定を止めているのは **P1-8 / P1-10 / P1-9-RELAND（G16、M2 で前提が立っただけで未実装）** であり、いずれも本 slice の対象外である。さらに本 slice 自身が **live E2E 未検証**であり、`let _ =` の握り潰し（`virtual_processor/processor.rs:1800-1801`）が残る以上、**producer 側の drift は今も無言で lane を止め得る** — 大声で落ちるのは cross-crate golden だけで、それは実ネットではなく CI の性質である。**判定: 公開 no-value testnet は依然「不可」。**

### テスト側で判明した設計上の含意

`palw_algo4_leaf_not_active_rejected_e2e` は **seed 済み leaf を後から変異させて**いた。write-once 化により不可能となったため、env に `leaf_edit` フックを追加し**最初の書き込み前に**leaf を整形する形へ変更した。これは単なるテスト修正ではない — clause-9 の eligibility grind は leaf を hash するため、**grind 後の leaf 変異はブロックが依拠する当の draw を無効化する**。write-once はこの順序を型で強制する。

---

## 5.6.1 §12′ — certificate supersession（票検閲の暫定対策・**撤回済み。以下は歴史記録**）

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

当初 `pov_daa_score = 包含ブロックの DAA` としていたが、これは**包含時評価**であり誤り。eligibility は B 割当と同じ意味論で**選出 snapshot で凍結**すべきである。包含時評価だと、証明書を保持する攻撃者が honest auditor の bond 失効直後を選んで包含でき、その票を無効化して honest 証明書を殺せる。

> **註（撤回に伴う訂正）。** 旧版はここに「または検閲版に supersession 比較を勝たせられる」と併記していた。supersession 比較子は §5.6.1a で撤回されたため、この攻撃経路はもはや存在しない。**残る動機は「票の無効化による honest 証明書の破壊」だけであり、本訂正はそちら側の理由だけで依然として必要である**（`verify_certificate_attestation` の check (4) は virtual 座標で今も `approving_stake` を実 commitment として再集計するため、bond 評価時点は現に耐荷重である）。

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

- `palw_header_preimage_commitment(...)` — **当初は 9 値の allowlist（parents / auth tx を除いた tx merkle root / ticket 座標 / timestamp）だった。この方式は誤りであり、下の「続報」で TOTAL binding へ置換済み。現行は `palw_authorization_commitment(network_id, header, authed_root)` の薄い委譲であり、束縛範囲は header preimage 全体である**
- `signing_hash(network_id)` — 専用 context（署名ドメイン表へ pending から昇格）
- `binds_leaf_authority()` — leaf の `ticket_authority_pk_hash` と照合（**AUTH-03**: 読み手ゼロだった）
- subnetwork `0x38` で block body 搬送、body 検証 **clause 7** で強制
- 入力ゼロを許容（ブロックメタデータであり送金ではない）。algo-4 限定・有効署名必須。**「1 ブロック 1 個・出力ゼロ」は当時は強制されておらず（当時の記述は誤り）、下の「続報 2 — AUTH-TXSHAPE」で `check_palw_block_authorization_shape` と clause 7 の `transactions.last()` 検査によって初めて実際に bounded になった**

**循環の回避**: authorization は自分を含む merkle root にコミットできないため、束縛する root は **auth tx を除外**したものにした。除外は 1 個だけなので miner が選ぶ tx 集合は完全に束縛される。

### 攻撃再現テストが私の修正の穴を捕捉した

`palw_algo4_reminted_ticket_is_rejected_auth02` を書いたところ **replay が成功した**。preimage が `timestamp` を束縛しておらず、timestamp 以外同一の 2 ブロックが同じ preimage を持つため、honest の authorization をそのまま自分のブロックへ移せた。

**これが攻撃再現テストを書く理由そのものである** — 「修正した」という主張ではなく攻撃の失敗を確認する形にしていなければ、この穴は残っていた。timestamp を束縛して閉鎖。

### 続報 — allowlist 方式そのものが誤りだった（**TOTAL binding へ置換**）

上記の「残る header フィールドは GHOSTDAG/UTXO 由来で自由に選べない」という前提は **誤りだった**。敵対監査が実証したとおり:

* `utxo_commitment` / `accepted_id_merkle_root` / `pruning_point` / `overlay_commitment_root` / `palw_beacon_seed` の 5 つは **virtual/UTXO 段でしか検証されない**。virtual 段は selected-chain 候補にしか到達しないため、**chain block にならない variant では一度も検証されない**。しかも失敗しても `StatusDisqualifiedFromChain` であり、ブロックは DAG に残る。
* `palw_epoch_certificate_hash` は store 上で active な任意の cert を名乗れる（複数の attested 証明書が同時に active になりうる。当時は §12′ supersession をその根拠に挙げていたが、supersession は 5.6.1a で撤回された — 共存は content-addressed store の性質そのものであり、撤回後も成り立つ）。なお TOTAL binding 化により**この軸は観測者に対しては閉じている**（preimage が当該フィールドを含む）。miner 自身については 5.6.1b で cross-batch のみ閉じた。
* ~~`bits` は algo-4 が Layer-0 hash floor から免除されているため自由。~~ **【訂正 — この 1 行は誤りだった。§5.13 参照】** algo-4 の `bits` は**自由ではなく consensus 導出**である。`pre_pow_validation.rs:44-53` が `header.daa_score >= palw_activation_daa_score` のとき `calculate_palw_lane_difficulty_bits`（同 :67-90、DAA window を当該 lane に濾した §16.3 lane retarget）で `expected_bits` を計算し、不一致を `RuleError::UnexpectedDifficulty` で拒否する。Layer-0 hash **floor** の免除（`check_pow_and_calc_block_level` が algo-4 に `Ok(0)` を返す、`pre_ghostdag_validation.rs:216-220`）と、`bits` **フィールドの値が自由に選べるか**は別の話であり、当時これを混同していた。<br>**帰結 (1)**: TOTAL binding 化は `bits` を含む全フィールドを束縛するので**この訂正で AUTH-02 の修正が弱まることはない**（修正は上位集合）。<br>**帰結 (2)**: clause 9 の抽選 target は miner が選べない。<br>**帰結 (3)**: **`bits` が自由であることを前提に置いた議論は再導出を要する** — 特に BIND-01 の compute-work grind 論証は `pre_pow_validation.rs:44-53` から改めて導くこと。
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
| ~~P1-9~~ | ~~global job nullifier~~ → **撤回（SPEC CHANGE、§5.12）**。body 座標には reader が存在せず、強制されていなかった。activation 級 gate **G16 / P1-9-RELAND** として再登録済み |
| P1-11 | AO-02（bitmap 境界を構造化）/ AO-03（`min_samples ≥ 1` を validity へ）/ DOS-03（view batch cap） |
| P1-12 SHAPE-01 | 活性化*後*の header shape 規則 |
| VIEW-01 | 「自 body を fold しない」を**意図的仕様として明文化 + テスト**（監査は欠陥と読んだが、同一ブロックでの register-and-spend を防ぐ意図的な設計） |
| seeder 拒否 | `misaka-dnsseeder` が PALW ネット（suffix 110/111）を**明示的に拒否して起動失敗**。「載せない」は設定の不在で、`--network-id testnet-110` 一つで消える |
| CERT-TRUST | §12′ supersession の**撤回**。未検証座標での順位づけを除去し、証明書 fold を write-once・単調のみへ（§5.6.1a） |
| CERT-BATCH | `resolve_palw_binding` の `cert.batch_id == header.palw_batch_id` 照合（`CertBatchMismatch`）+ `insert_certificate` の content write-once 化（§5.6.1b） |
| `LATEST_DB_VERSION` | PALW overlay 永続化型の encoding 変更に伴い **7 → 8**、続いて P1-5 の `job_nullifiers` 削除に伴い **8 → 9** へ bump（削除も追加と同様に positional encoding を壊す）。layout-pin テストが将来の無言変更を落とす（§7.2 の註） |

### 座標の決定 — view は body/mergeset 座標に**留まる**（移動不可）

P1-5 / P1-13 の前提だった「座標をどちらに寄せるか」は、調べた結果**選択の余地が無い**と判明した。

`check_palw_ticket` は **body 検証**で `view(SP)` を解決する。acceptance データは **virtual 処理された（= chain block になった）ブロックにしか存在しない**。side-chain の選択親は virtual 処理されないため、acceptance 座標の view はそこで `None` になり、body 検証の成否が chain 選択順・到着順に依存する — **恒久的で順序依存の `StatusInvalid` = consensus split**。資源問題を直すために合意分裂を導入することになる。

したがって **view が mergeset 座標にあるのは必然であり、見落としではない**。DOS-02 は「fold を acceptance で濾す」のではなく「**未受理 fold が達成しうる範囲を有界にする**」ことで閉じる:

* **fold は per-leaf state を一切書かない**（P1-5、下記）。leaf chunk 1 本あたり最大 64 件を無制限に積んでいた `job_nullifiers` は**削除**された。永続 view は `|batches| ≤ max_view_batches` のみ
* 偽造 batch は Active になれない — ただし境界は `apply_certificate` **ではない**。§12′ 撤回後の `apply_certificate` は**何も検証しない**（body 座標には bond view が無い）。実際の境界は **store gate** = `insert_certificate` を守る `verify_certificate_attestation`（virtual 座標、実 ML-DSA quorum）であり、ticket は**その store を読む。view の `cert_hash` は読まない**。旧版がここで P1-3 を境界としていたのは §5.6.1 の call-order 誤りと同型の誤りであり、訂正する
* view エントリ数は cap 済み（`max_view_batches`、DOS-03）。しかもこの cap は**もはや文書だけの保証ではない** — `PalwBatchAdmissionParams::is_consistent_for_activation()` を新設し、`palw_batch_admission` doc が主張していた「activated preset で `0` を拒否する整合性検査」を実在させた（従来この検査はツリー内のどこにも存在せず、params の 1 語編集で cap を無言で無効化できた）。全 6 preset に対する `palw_activated_presets_bound_the_view` が強制する
* leaf は write-once かつ manifest 境界内（P1-1）
* fold 元は全て mergeset **blue** = 誰かが採掘したブロック。view slot の消費は**ブロック生産コスト**を伴う

残余は「miner による有界な **view slot** 消費」であり、cap が正しさの問題を容量の問題へ変換する。**`max_view_batches` を将来引き上げる際は、この論証を再検証すること。** なお `min_leaf_bond_sompi = 0`（全 preset）である限り manifest admission は**無料**であり、この残余の価格はゼロである（再 genesis で再校正、下記 d(ii)）。

### P1-5 / DOS-02 — **cap ではなく削除で閉じた（DONE）**

**強制される最悪値は厳密・パラメータ非依存である: `|job_nullifiers| = 0 件 / 0 byte`、あらゆる fork のあらゆる高さで。** 永続 view の上界は既に強制済みの `max_view_batches` のみに帰着する:

```
sizeof(view(B)) ≤ 8 + |batches| · (64 + LIFECYCLE_LEN)
                ≤ 8 + max_view_batches · 317 byte  = 1024 · 317 ≈ 325 KB
```

**何が問題だったか。** `PalwBatchViewV1` はブロック毎に clone・再永続化されるのに、`job_nullifiers` にだけ cap が無かった。しかも claim は**無条件**だった: manifest 参照なし・`leaf_index` 境界なし・batch status gate なし・所有権束縛なし（leaf と batch の唯一の紐付けは `leaf.batch_id == chunk.batch_id` で、`batch_id` は**公開値**）。claim は `apply_leaf_chunk` の**前に、かつ独立に**行われ、`apply_leaf_chunk` の bool は**捨てられていた**ため、`apply_leaf_chunk` が拒否する chunk（重複 `chunk_index` / 範囲外 / 非 Registering）でも最大 64 件を恒久 claim できた。isolation は chunk あたり 64 leaf（`PALW_MAX_LEAVES_PER_CHUNK`）、leaf は borsh ~750-850 B なので ~50 KB/tx、標準 mass 制限下でブロックあたり ~10 tx ⇒ **ブロックあたり ~640 件の 72 byte エントリが無制限に積まれ、攻撃者が選んだ expiry まで保持される**。攻撃コストは manifest 1 本（両 live-fold preset で `min_leaf_bond_sompi = 0`）と通常のブロック生産のみ。**fence はこれを守らない**: `commit_palw_overlay_view` は `palw_activation_daa_score = 0` の `testnet-palw-110` / `devnet-palw-111` で**全ブロックに対して行を書く**し、`palw_algo4_accept = false` はこの経路を gate しない。

**なぜ削除が上界設定に勝るか。** 読み手のいない機構を cap 付きで出荷することは、本 ADR が繰り返し警告してきた「半配線機構」そのものである。そして cap を入れても**検閲レバーは残る**（refuse-at-cap は、誰かが拒否を配線した日に lane 全体の検閲手段になる）。この座標では読み手を**正当に**持てないことが決定的である（下記 §P1-9）。

**consensus 中立性の証明（レビューではなく構成による）。** view の唯一の consensus 読み手は `body_validation_in_context` → `resolvable_batch` → `is_block_eligible_at` であり、読むのは `revoked_from_daa` / `status` / `cert_hash` / `expiry_epoch` **のみ**。`job_nullifiers` を読むものは存在しない。削除後の `batches` は、**あらゆる入力・あらゆる preset に対して従来と byte 同一**である。新たな入力を一切読まないので順序依存が入る余地も無く、むしろ削除は fold 唯一の**非可換・非 content-addressed・所有権非束縛**な操作（攻撃者選択の 64 byte 値に対する first-claim-wins。記録される expiry は `unwrap_or(0)` 経由で fork ごとに違った）を取り除く。回帰テスト `leaf_chunk_fold_is_independent_of_leaf_content` がこれを pin する。

**付随して直った件。** `MemSizeEstimator for PalwBatchViewV1` は `batches.len()` しか数えておらず `job_nullifiers` に**盲目**だった（block-keyed view cache は 1 行あたり最大 ~18.9 MB を見えないまま抱えうる）。これも所見の一部であり、フィールドを非存在にしたことで解消した。

### P1-9 — body 座標から**撤回**する（SPEC CHANGE）

これは cleanup ではなく**仕様変更**である。§12′ CERT-TRUST supersession 削除と同じ扱いで記録する。

**そもそも強制されていなかった。** `claim_job_nullifier` の bool は「それ以外に何も無いループ本体を終える `continue`」に入っており完全に dead、`job_nullifier_spent` は production 読み手ゼロ。**重複作業拒否は今日この瞬間も UNENFORCED** であり、削除しても「現に効いているもの」は何も失われない。テスト `global_job_nullifier_rejects_cross_batch_duplicate_work` は**主題そのものが消滅するため削除**した — **通っているテストであり、何かを緑にするために弱めたのではない**。

**この座標では armed にできない。** 拒否を実際に有効化すると、正直な provider の batch に対する **1 tx 恒久 brick** になる: 拒否された chunk は bitmap bit を立てず、popcount は `chunk_count` に届かず、`advance_epoch_gated` が `Registering if epoch > deadline ⇒ Expired` を取る。これを直す所有権束縛には `ActiveBondView` が要るが、それは virtual 座標にしか存在せず、view をそこへ動かすことは確定済みの BIND-03 論証が禁じている（本節冒頭）。`PalwLeafChunkV1` に Merkle path は無く、ML-DSA 検証も無く、`min_leaf_bond_sompi = 0` である。**検証できない値で順位付けしてはならない**（CERT-TRUST と同一の原則）。

**この穴を他の何かが埋めているか — 埋めていない（確認済み）。** `PalwActiveNullifierSet` は別物で寿命が reorg horizon（≈1200 DAA）、`validate_leaf_chunk` は **1 chunk 内**の `ticket_nullifier_commitment` 一意性しか見ず `job_nullifier` に触れない、`insert_leaf` は `(batch_id, leaf_index)` keyed で `DbPalwStore` に job_nullifier index は存在しない。**それでも運べる**理由は一つ: 全 6 preset で `palw_algo4_accept = false` ⇒ PALW ticket は mint されず leaf は 1 件も**支払われない**。「重複して**支払われた**作業」は、このツリーが到達しうる全状態で**到達不能**である。

### P1-9-RELAND — **Activation 級 gate として再登録**（CERT-01 / G4 と同列）

能力は放棄しない。記憶ではなく**構成として** mainnet activation を塞ぐ。束縛要件:

1. **REWARD/virtual 座標**に、coinbase 構築が読む **reward 規則**として着地させる（そこでは construction == validation なので BIND-03 の不一致が生じない）。**acceptance state を入力とする body-validity 規則としては絶対に置かない。**
2. claim は provider の **ML-DSA 署名**によって**認可**される。署名対象は `ReplicaExecutionReceiptV1::signing_hash` で、これは既に `job_nullifier` を commit している（`palw.rs:854`、確認済み）。したがって「署名付き receipt を伴わない複製 nullifier」は何も claim できず、first-claim-wins は **first-RIGHTFUL-claim-wins** になる。**(2) 無しにいかなる座標へも再着地させてはならない。**

**未解決の下位問題（配線作業ではなく DA/audit slice 依存）**: leaf が commit しているのは `receipt_a_hash` / `receipt_b_hash` だけなので、reward 座標が **receipt 自体を resolve できる**必要がある。

### 併記（本 slice では**畳み込まない**、記録のみ）

* **(i) CHUNK-INDEX SQUAT**: `batch_id` は公開なので、観測者が公開 `batch_id` を写して junk chunk で bit i を立てると、正直な chunk i が重複として拒否され、batch は「`leaf_root` に還元されない leaf 群を抱えたまま」completeness に到達する。**これは今日も存在し、本 slice では未変更**。修正にはやはり所有権束縛が要る。 → **設計確定（2026-07-20、§5.15 ACCEPT-BIND/M2）**: 所有権束縛のうち**必要な半分は identity ではなく content 束縛**である。`leaf_root` を Merkle 化し、ACCEPTANCE 座標の LeafChunk arm で per-leaf membership proof を `insert_leaf` の**前**に検証すれば、**THEFT（reward script / ticket 鍵の窃取）は BLAKE2b-512 の second preimage 問題に帰着**し、**DENIAL は `insert_leaf` の同一内容冪等性の帰結として閉じる**（gate を通る chunk は正直な chunk と byte 一致するため）。**bitmap の半分は閉じない**が、M2 後の bitmap は store にも reward にも ticket にも影響しない**不活性な completeness hint** であり、CERT-TRUST 配下へ再分類する。 → **実装済み（2026-07-20、同日）**: THEFT half は閉じた（squatter は他人の `batch_id` の下に自分の reward script / ticket 鍵を書けない — `LeafMembershipProofInvalid` で `insert_leaf` 到達前に拒否、store 上で表明済み）。DENIAL half も閉じた（gate 通過 chunk は正直な chunk と byte 一致 → `insert_leaf` の冪等経路、`chunk_index_squat_is_rejected_before_the_leaf_is_stored` が「squatter が先行しても正直な provider が後から成功する」ことを表明）。**bitmap half は宣言どおり未閉鎖のまま CERT-TRUST 配下へ再分類**（junk chunk は依然 bit を消費でき `Registering → Committed` を早発させ得るが、store / reward / ticket のいずれにも影響しない）。**したがって本項目は「閉じた」ではなく「利益の出る半分が閉じ、残る半分が無害化された」。`chunks_present` 削除は別 slice。**
* **(ii)** `min_leaf_bond_sompi = 0`（`PalwBatchAdmissionParams::INERT` を 6 preset すべてが継承。preset 自身のフィールドではない）⇒ manifest admission が**無料**であり、view slot 残余と (i) の squat の価格をゼロにしている。**再 genesis で再校正すること。**

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

### S3 検閲テスト — 実ネット不要（結論は維持、機構は入れ替わった）

**維持される結論。** 「Δ_super 較正に実ネットが要る」としていた当初判断は誤りである。**検閲は「fork-relative view がどの証明書を受理するか」の主張**であり、view は effects の純関数なので in-process で完全に表現できる。この結論は supersession 撤回後も変わらない。

**入れ替わった機構。** 撤回前は `s3_vote_censorship_is_unstable_not_decisive` という**肯定的**な性質（「より完全な証明書が検閲版を置換する」）を固定していた。supersession が §5.6.1a で撤回されたため、現行テストは `consensus/core/src/palw.rs` の

```text
s3_vote_censorship_is_not_remediable_at_the_body_coordinate
```

であり、固定する性質は**否定的**なものへ反転した。**敵対的な証明書は honest 証明書を追い出せず、誰の eligibility も縮められず、何も凍結できない。**

| # | 現行テストが固定する性質 | 撤回前の対応する主張 |
|---|---|---|
| 1 | 検閲証明書は view 上では**受理される**（参加分母下では実際に valid — それが穴） | 同左（**唯一そのまま残った項**） |
| 2 | 後から出た**より完全な証明書は view 上では supersede しない**。first arrival が立つ | 「supersede する」— **反転** |
| 3 | **その view race に負けても完全版は何も失わない**。view の `cert_hash` は「一度でも certified されたか」のビットであって許可証ではなく、batch は宣言された生存期間を通じて block-eligible のままである | 「Δ_super が応答の窓を保証する」— **削除**（窓は存在しない） |
| 4 | 対称に、**検閲者も後続の証明書で何かを短縮・移動できない**（`Certified` entry は不変） | 「窓経過後は結果が安定」— **書き換え**（安定性の根拠が窓ではなく単調性になった） |

**なぜ性質が否定的でよいのか。** 反検閲の目的自体は失われていない。証明書は content-addressed で `palw_store` に**共存**し、miner は `palw_epoch_certificate_hash` で任意の attested 証明書を名指せる。少数派 assembly を先に載せても、より完全な assembly を抑圧できない。**body 座標に要求すべきなのは「順位づけ」ではなく「破壊的遷移がゼロであること」**であり、それが現行テストの主張である（§5.6.1a の単調性論証と同じもの）。

**削除された assert について明示。** 撤回前は最後に「`Δ_super = 0` なら検閲が成功する」を assert し、Δ_super が耐荷重であることを示していた。`Δ_super`（`supersession_window_daa`）は現在**読み手ゼロの inert フィールド**であり、その assert は存在しない。**inert であること自体は別テストで pin されている** — `consensus/core/src/palw.rs` の `inflated_approving_stake_cannot_displace_or_brick_a_certified_batch`（`cert_approving_stake` / `cert_activation_epoch` / `cert_expiry_epoch` が書かれないこと + `u128::MAX` 宣言が batch を brick できないことを直接 assert）および `certificate_fold_is_write_once_and_monotone`（fold の単調性）。

**残余（正直に）。** 参加 stake 分母のもとでは、検閲版証明書は今も *valid* である。これを本当に閉じるのは **eligible-set 分母（SEL-01 + I-14 `audit_sample_root` 再導出）** であり、それは bond view が実在する **virtual 座標**にしか置けない。**body 座標のいかなる規則もその代替にならない。** したがって S3 で実ネットが要るのは、機構の正しさでも Δ_super の較正でもなく、**SEL-01 / I-14 が着地した後の eligible-set 分母の挙動**である。

### 旧・残 3 項目

**P1-5（DOS-02）/ P1-7（TGT-01）/ P1-13（BIND-04）は独立した作業ではない。** すべて **view が mergeset 座標にあり acceptance が virtual 座標にある**（BIND-03）ことに帰着する。

* **P1-5**: view の fold が raw mergeset tx を読むため、never-accepted / 二重支払 tx が view を動かす。acceptance filter は body 段では原理的に書けない（acceptance は virtual 段の性質）。
* **P1-7**: interval 導出は**実装して動作したが差し戻した** — clause 5 が既に `interval == daa_score` を前提に束縛しており、規則が 2 本になって正直なブロックが全て落ちた。着地には clause 5 の意味論変更が要る。
* **P1-13**: pruned-IBD import 経路の新設。どの座標の状態を import するかが未定では設計できない。

**半端に入れる方が危険である。** P1-7 の差し戻しがその実例で、2 本目の規則は正直なブロックを拒否しながら、両者が食い違う箇所では interval を miner 選択のまま残した。

**必要な決定**: view を acceptance 座標へ移すか、mergeset 座標のまま acceptance 相当の性質を別途保証するか。決まれば **P1-5 と BIND-03 が同時に閉じ**、P1-7 の clause 5 再定義も安全に行える。これは実装判断ではなく合意規則の設計判断であり、独断で寄せるべきではない。

---

## 5.13 §P1-8 — DOS-01（algo-4 header anti-spam）の**再分類**と設計方向の確定

**結論を先に書く: この項目はパッチで閉じられない。T-shared 級ではなく activation 級の blocker として再分類し、`palw_algo4_accept` を解除するための名前付き前提条件として登録する。今フェーズではコードを一切変更していない。**

### 5.13.1 なぜ今日「穴」ではないのか（P0-3 の位置の確認）

`pre_ghostdag_validation.rs:130` の `check_pow_algo_id` が `!palw_algo4_accept` のとき `pow_algo_id == 4` を `RuleError::PalwAlgo4NotAccepted` で拒否する。この関数は同 :18 で呼ばれ、`validate_header_in_isolation` の**2 行目**である。`processor.rs:308` はこれを `ghostdag()`（:333）・`pre_pow_validation`（:334）・`commit_header`（:309）の**すべてより前**に実行する。それより前に走る algo-4 固有処理は存在しない（`check_header_version`（:17）のみで、これはゼロフィールド比較 2 回）。trusted-header 経路（:346）も同じ `validate_header_in_isolation` を通る。pruning-proof 経路は独立かつより厳格で、`validate.rs:197-200` の `check_algo_id` が `required_algo_id ∈ {1,3}` しか許さない（`pow_layer0.rs:144`）ため、lever と無関係に id 4 を拒否する。

lever は 6 preset すべてで `false`（`params.rs:1228, 1341, 1408, 1459, 1534, 1570`）。よって **DOS-01 は現在到達不能であり、閉じるべきは「lever を開ける前」である。**

**供給経路の限定（記録）**: header-only 受理はリレーでは起きない — `blockrelay/flow.rs:137-139` が body 無し block を hard reject する。唯一の経路は IBD header-sync（`ibd/flow.rs:567, 576, 661` が `Block::from_header_arc` で投入）であり、PALW preset は `--connect-peers` allowlist（`daemon.rs:442`, `palw_requires_peer_allowlist`）と `--archival` を要求するため、その peer になれる主体は限定される。

### 5.13.2 lever を開けた場合に攻撃者が払うコスト — **ゼロ**

ticket も leaf も certificate も authority 署名も、**すべて body 段**である。`check_palw_ticket` は `body_validation_in_context.rs:26` から呼ばれる（定義 :97）。clause 9 の抽選（algo-4 にとって唯一 PoW 相当のもの）は :213-237、clause 7 の AUTH-02 authorization + ML-DSA-87 署名 + 正準 tx 形状 + 末尾位置固定は :265-330。**header pipeline はこのいずれも呼ばない。**

compute cap は代替にならない。`validate_palw_compute_headroom`（`post_pow_validation.rs:28-38`）は `compute_headroom(H, C, 4) == 0` のときだけ error を返すが、`compute_headroom` は saturating な `4H − C`（`palw.rs:2905-2907`）。`C` は `normalize_palw_work(header.bits, palw_compute_work_scale)` で積まれ（`ghostdag/protocol.rs:288`）、両 PALW preset で `palw_compute_work_scale = 0`（`params.rs:1413, 1463`）ゆえ `normalize_palw_work` は 0 を返す（`difficulty.rs:267-270`）。よって `C == 0`、headroom は `4H` で非 genesis ブロックでは常に非ゼロ。**「cap は構造上一度も発火しない」という本 ADR の記載は CONFIRMED。**

### 5.13.3 ノード側コストの訂正（2 件）

**(1) nullifier window の境界は `O(retention)` ではない。** 実体は `processor.rs:416-443`。guard は `header.daa_score >= palw_activation_daa_score && ctx.hash != genesis` **のみ**で、lane にも accept lever にも係らない。per header で `get_daa_score(sp)`・`PalwActiveNullifierSet` の全 `.clone()`・mergeset blue ごとの `get_header`・`prune_below`（全走査 retain）・`insert_batch`（`has()` 読み + 集合全体の borsh 再直列化、`palw_nullifier.rs:60-67`）を行う。要素は `BTreeMap<Hash64, u64>`（`palw.rs:3037-3039`）で `HASH64_SIZE = 64` ゆえ 72 byte/entry。

**訂正の核心**: :434 の fold は `mergeset_blues` **全件**を回り `mergeset_non_daa` で濾されない。一方 :441 の prune は各 blue **自身の** `daa_score` を鍵にする。したがって DAA 除外 blue は prune 下限を進めないまま entry を増やす。真の境界は `O(retention × mergeset_size_limit)` = 1,200 × 248（10 BPS ⇒ `ghostdag_k = 124`、`mergeset_size_limit = 2k`、`bps.rs:40, 78-79`）≈ **297,600 entry ≈ 21 MB を per header で clone + 再直列化**。DOS-01 が記述する無償 header 受理がそのまま二次的増幅を駆動する。

**(2) lever と無関係に今日走っているコスト（本 ADR に記載が無かった）。** `pre_pow_validation.rs:67-90` は DAA window の各要素につき `headers_store.get_header(item.0.hash)` を呼ぶ（:74-79）。`DIFFICULTY_SAMPLED_WINDOW_SIZE = ceil(2641/4) = 661`（`constants.rs:57-63`）ゆえ **per header 661 回**。これは lane にも accept lever にも係らず、`palw_activation_daa_score = 0` の testnet-palw-110 / devnet-palw-111 で**全ブロックが払う**。

> **重大度の下方訂正（私自身の一次調査による）**: 本件を「661 回の完全 Header デシリアライズ」と記述するのは**過大である**。`headers_store` は 80 MB の `tracked_bytes` キャッシュを持ち（`storage.rs:192`, `headers_builder`）、`get_header` は `CachedDbAccess` 経由で、常駐時は**ハッシュ表参照 + `Arc` clone** でありデシリアライズは発生しない。DAA window は隣接ブロック間でほぼ完全に重なるため定常状態では常駐する。よって実コストは「compact 経路に対する定数倍のオーバーヘッド」であって「今日の支配的コスト」ではない。**この訂正のため、本フェーズでは本件に対するコード変更を行わない**（後述 5.13.5）。記録は残す — 将来キャッシュ予算を絞る、あるいは window を拡大する変更が入った時点で再評価すべき既知の非効率だからである。

### 5.13.4 設計方向の確定 — **Option C を主、Option B を補完、Option A は棄却**

本 ADR §6 の P1-8 行は「full-block 受信時のみ header pipeline へ入れる、または header 段で compact ticket witness を検査」の 2 案を挙げていた。コードに突き合わせた結果を確定する。

**Option A（full-block 受信を header 受理の条件にする）— 棄却。** これは小さな gate ではなく IBD の再設計であり、記述どおりには実装不能と判断する。headers-first sync は body を取得する前に GHOSTDAG・blue_work・pruning point を確立するために存在する（`ibd/flow.rs:567, 661`）。algo-4 ブロックは blue_work を運び mergeset member にもなる通常の DAG member なので header-sync 中に飛ばせない — 飛ばせば DAG が再構成できない。header-sync 中に body を要求すればその時点で body 検証が必要になるが、body 検証は block-keyed overlay-view store からの `view(SP)`（`body_validation_in_context.rs:132-137`）と `palw_store` の leaf / cert blob（:154-161）を要し、**いずれも header-sync 時点では存在しない**。header-only で構成される pruning proof とも合成できない。**consensus risk: 高** — IBD を壊すか、body/virtual 状態と header sync の間に順序依存を持ち込むかであり、後者は P1-5 が既に consensus split として棄却したのと同一クラスの順序依存 `StatusInvalid`（`body_processor/processor.rs:386-392`）である。**再提案しないこと。**

**Option B（header 段の compact ticket witness）— 単独では lane を閉じない。補完としてのみ採る。** clause 9 の抽選（`body_validation_in_context.rs:213-237`）の各入力を header 段での可用性で分類した:

| 入力 | header 段で可用か | 根拠 |
|---|---|---|
| lagged DNS anchor | **可** | `resolve_palw_lagged_anchor`（:118-121）は header + reachability のみで解決 |
| `anchor_header.palw_beacon_seed` | **可** | header フィールド |
| `expected_chain_commit` | **可** | anchor fact + `palw_target_daa_interval` + network id の純関数（:203-208） |
| `header.bits` | **可** | §5.11 の訂正どおり header 段で consensus 導出（`pre_pow_validation.rs:44-53`） |
| `nonce == digest_low_u64(nullifier)` pin | **可** | `palw.rs:314` |
| **`resolved.leaf_hash`** | **不可** | `resolve_palw_binding` が content-addressed `palw_store` を読む（:154-161）。書き込みは virtual 座標 |

**唯一の blocker が `leaf_hash` である。** IBD header-sync 時点でこの blob は無いので、header 段 clause 9 検査は**正直な algo-4 header すべてに対して fail-closed**となり header-sync が停止する — P1-5 が棄却したのと同じ到着順序依存の再導入である。これを解くには (i) leaf preimage を header と一緒に wire に載せる（Header v3 schema に該当フィールドは無く、追加は **Header v4 = re-genesis**。しかも §5.11 の「版の結合」残余リスクどおり `palw_authorization_commitment` も動く）か、(ii) 抽選 digest から `leaf_hash` を落とす（登録 leaf と抽選の結合が切れ、ticket の目的が失われる）しかない。**consensus risk: 中〜高、かつ re-genesis 級。**

**Option C（新規・主案）: GHOSTDAG のみから計算できる構造的な lane 別 rate limit。** mergeset あたり、あるいは DAA window あたりの algo-4 blue 数を header 段で上限する。overlay 状態も header-sync に無い store 読み出しも要さず、`HeaderProcessingContext` に既にある `ghostdag_data` の純関数であり、`check_mergeset_size_limit`（`post_pow_validation.rs:64-71`）の隣に自然に収まる。ticket を**認証する**ふりをせず header 流量だけを縛る点が要である。**consensus risk**: 新規 consensus 規則（fork / re-genesis）であり lane throughput を変えるため、§16 lane DAA および `palw_compute_work_scale` と**同時に**設計する必要がある。後付けで足してはならない。

**確定**: **C を主案、B を補完**（C が流量を縛り、B が到達可能な範囲で ticket を認証する）。**A は調査済み棄却として記録**。

### 5.13.5 本フェーズで**やらなかったこと**とその理由

* **admission gate を入れなかった。** A / B / C いずれも本 remediation の範囲外であり、いずれも re-genesis 級かつ §16 lane DAA との同時設計を要する。**着手すれば本 ADR 自身が警告する「半端に入れる方が危険」（§5.12）の実例になる。**
* **§5.13.3 (1) のコストを縛らなかった。** 集合の内容は consensus である。fold を `mergeset_non_daa` で濾せば nullifier を落とすことになり **fail-open**（cross-ancestor ticket 再利用の再開）。境界は consensus 規則の変更なしには縮められない。
* **`palw_algo4_accept` で nullifier window の書き込みを gate しなかった。** 一見安全に見えるが**不健全**である: このレバーは `--palw-enable-algo4` により**実行時に切替可能**（`args.rs:345-352`）。off で運用 → 行が書かれない → オペレータが on に切替 → active な SP の window が欠落 → fail-closed panic（`processor.rs:427`）、あるいは GHOSTDAG dedup が空 seed になり **fail-open**（`protocol.rs:218-224`）。永続 store の書き込みを実行時可変フラグに係らせてはならない。
* **§5.13.3 (2) に手を入れなかった。** 同項の重大度訂正のとおり、キャッシュ常駐下では利得が定数倍に留まる一方、`CompactHeaderData` への `pow_algo_id` 追加は全ネットワークの永続形式変更である。「閉じている lane のために consensus risk を持ち込まない」という本フェーズの制約に対し、リスク／利得が見合わない。

### 5.13.6 登録する前提条件（G6 の規範表現）

> **algo-4 header 受理にはコスト関数が存在しない。それを縛っているのは P0-3（`palw_algo4_accept = false`）ただ一つである。header 段の admission 規則が存在するまで、このレバーを解除してはならない。**

これは §7.1.1 の gate class に既にある **G6** の規範表現であり、G6 の判定条件は §5.13.4 の Option C（+ B）の実装を指す。

### 5.13.7 テスト（本フェーズで追加）

コード変更が無いフェーズでも、**本節が主張する事実は機械検査に落とす** — 文書だけの主張は静かに腐るからである。

* `palw_algo4_bits_is_consensus_derived_not_free` — §5.11 の `bits` 訂正を pin する。lever を開けた algo-4 ブロックの `bits` を改竄すると `RuleError::UnexpectedDifficulty` で落ちること、および無改竄の同型ブロックが受理されること（control）。
* `palw_dos01_has_no_work_based_bound` — DOS-01 の前提を pin する。両 PALW preset で lane が active・`palw_algo4_accept == false`・`palw_compute_work_scale == 0` であること、および `normalize_palw_work(bits, 0) == 0` ⇒ `compute_headroom` が発火しないこと。**将来 scale を非ゼロにすれば compute cap が縛りになると誤認する変更**を、この assertion が捕まえる。

### 5.13.8 実装監査 — sampled DAA window 比率案の棄却（2026-07-20）

`replica_count < 4 × hash_count + burst` を候補 header の DAA window に適用する案を試作したが、activation 可能な防御にはならないため撤去した。現行 window heap は全 header horizon ではなく lane difficulty 用の標本であり、例えば testnet 10 BPS の `sample_rate = 40` では攻撃者が sampled 位置へ algo-3、未標本位置へ algo-4 を配置して比率検査を回避できる。また同じ selected past を共有する sibling 群は全て同一 count を観測する。

既存 `VaryingWindow` を `sample_rate = 1` で全走査する方法も、10 BPS の現行 horizon では候補ごとに約 26,440 block を再構築し、cache も持たないため、それ自体が header DoS になる。selected-parent iterator は off-chain mergeset DAA block を落とすので代替にならない。

従って Option C は、専用の認証済み fork-local accumulator を commit/delete/pruning/trusted-data/template/validation へ一貫して実装するまで未実装とする。別案として header 全体へ束縛された objective stamp / compact witness、および transport 境界も必要である。出荷 preset の `palw_algo4_accept = false` を維持し、DOS-01 / G6 は `Measurement` のまま、公開・有価値ネットワークの activation blocker とする。

---

## 5.14 §P1-10 — PCPB は**本 run で着手しない**。原子スライスとしての設計（2026-07-20 確定）

### 5.14.1 結論

**PCPB（post-commitment provider binding）を今 wiring してはならない。** 本節はその判断の根拠と、後続 run が着手する際の完全な設計を規範として固定する。ADR 冒頭の「半端に入れる方が危険である」がここに直接適用され、かつ **P1-7 の失敗様式と構造が一致する**（§5.12「P1-7（TGT-01）」参照: clause 5 の横に第二の interval 規則を足した結果、正直なブロックが全て `IntervalMismatch` で落ちた）。

現状の実測（コード根拠）:

* 三つの純関数 `palw_challenge_fresh` / `palw_pcpb_derive_b` / `palw_dispatch_proof_valid`（`consensus/core/src/palw.rs`）には **production caller がゼロ**。参照は同ファイルの unit test のみ。
* `PalwPublicLeafV1` に PCPB のフィールドが**一つも無い**（challenge commitment / `challenge_epoch` / `a_commit` / `provider_snapshot_root` / `assignment_proof_root` / dispatch-proof のいずれも）。`validate_public_leaf` も当然何も見ていない。
* production の body 検証は `verify_palw_ticket_store_facts`（clause 1–5）のみ。九節版 `verify_palw_ticket` は production caller ゼロ。PCPB が接続されるべき clause 6/7/9 は、`consensus/src/processes/palw.rs` の記述どおり**意図的に非強制**である（部分ゲートは grind 可能だから）。
* ~~leaf-chunk overlay tx の**プロデューサが存在しない**。全構築点は test か devnet demo。~~ **← 2026-07-20 §5.15 (M2) で FALSE になった。** 実プロデューサは 3 本存在する（miner `manifest_leaf_root` / `build_leaf_chunk`、auditor `AuditRound`、参照 mint `palw_demo`）。**これが §5.14.1 の前提のうち M2 が動かした唯一の項目である**（下 §5.14.6 で全項目を再検証した）。
* provider registry / provider snapshot / assignment proof / PALW job escrow は**在庫ゼロ**。`PalwParams` に freshness window `w`・snapshot lag `k`・post-commit Δ が無い。
* epoch 別 beacon seed が**引けない**。`PalwBeaconStateV1` は現行 seed 1 個のみを持ち、`PalwBeaconAccumViewV1::retain_future_of` は現 epoch 以下を**削除する** — PCPB が必要とする過去 epoch がまさに捨てられている。

### 5.14.2 新規発見（本 run） — `PalwDispatchProof` は現在の形では**接続不能**

`PalwDispatchProof::BothSlotsBeacon { slot_a_beacon_ok, slot_b_beacon_ok }` と `SelfAPlusPcpb { .., b_receipt_binds_a_commit }` は **caller が渡す既決の `bool`**、すなわち検証器が到達すべき結論そのものである。これが leaf/header/payload に載った瞬間、`palw_dispatch_proof_valid` の外部ディスパッチ枝は `true && true` の恒真式に退化する。実質的な検査は `b_claimed == palw_pcpb_derive_b(R_{E+Δ}, a_commit)` 一本だけ。

したがって **「三つの helper を verifier に繋ぐ」作業は成立しない。** enum を検証可能な証拠へ作り直すことが前提条件であり、これは本節のスライスの一部である。この事実は `consensus/core/src/palw.rs` の `PalwDispatchProof` の doc comment にも記した（将来の run が「繋ぐだけ」と誤認するのを防ぐため）。

### 5.14.3 原子スライスの内容（順不同・全て同時）

1. **Leaf v2 wire format**。§4.2 の `PalwReplicaLeafV2` に合わせ、少なくとも次を追加する。
   * `job_challenge_commitment: Hash64` — §4.1 の `job_challenge` のコミットメント。**epoch 共通ではなく job 単位**（`scheduler_job_id` / `requester_credential` / `request_commitment` を含む）。現行 `mil/core/src/palw.rs` の `execution_challenge` はこの 3 つを欠くため、そのままでは使えない（要差し替え）。
   * `challenge_epoch: u64` — freshness 判定の対象。
   * `a_commit: Hash64` — A の escrow-lock 済みレシートコミットメント。
   * `provider_snapshot_root: Hash64` — E−k の bond 加重スナップショット根。
   * `assignment_proof_root: Hash64` — 加重抽選 + membership 証人の根。
   * dispatch-proof を**検証可能な証拠**として持つ構造（§5.14.2）。beacon 割当枝は per-slot の assignment 証人、self 枝は B の署名レシート本体（`a_commit` 束縛を宣言でなく検査するため）。
2. **DB format cutover 8 → 9**。leaf は `DbPalwStore` を通じて bincode 永続化されるため、フィールド追加は**オンディスク形式の破壊**である。`consensus/src/consensus/factory.rs` の `LATEST_DB_VERSION` を 9 へ、`kaspad/src/daemon.rs` の `'db_upgrade` hard-reset arm を 8 まで覆うよう拡張する（片方だけは無意味を通り越して有害 — 既存 test の doc 参照）。
3. **`PalwDispatchProof` の再設計**と `palw_dispatch_proof_valid` の書き直し。既存 3 unit test は**仕様変更に伴い変更する**（弱体化ではない）。
4. **epoch 別 beacon seed 履歴**。`retain_future_of` が捨てている範囲を、block-keyed かつ pruning-safe な store か header-walk resolver で引けるようにする。clause 9 の eligibility beacon は buried anchor の単一遅延値であり、epoch index ではない — PCPB はそれとは別の読み取り面を要求する。
5. **provider registry + epoch 別 bond 加重スナップショット**（E−k でオンチェーン commit）、および assignment proof（加重抽選 + membership）の形式と検証器。全て新規。
6. **`PalwParams` 追加フィールド** — freshness window `w`、snapshot lag `k`、post-commit Δ。**6 preset 全て**に置き、params 一貫性テストを追加する。
7. **`leaf.registered_epoch` を chunk の acceptance epoch に固定する**。これが P1-7 の罠そのもの: 現行の leaf は `registered_epoch < activation_epoch < expiry_epoch` という**関係的制約しか持たない**（manifest 側は `registration_epoch != accept_epoch` を拒否しているのに、leaf 側は固定されていない）。この状態で `palw_challenge_fresh` を leaf フィールド上に掛けると freshness は grind 可能であり、固定を追加すれば**別座標の第二規則**になる — P1-7 と同一の失敗様式。ゆえに 1 と 7 は分離できない。
8. **実プロデューサ**。A_commit + escrow lock → snapshot 固定 → future beacon による B 抽選 → A_commit を含む B receipt → A reveal → leaf-chunk overlay tx builder。`mil/` 側は改修ではなく**新規実装**である。
9. **ゲート G7 / G12**。G7 = 本 finding の回帰テストを `palw_prod_findings_all_covered` に登録。G12 = `palw_pcpb_e2e` の複数ノード E2E。**G12 は本環境では実行不可**。

### 5.14.4 なぜ分割できないのか（規範）

* leaf フィールドは beacon 履歴とスナップショットが無ければ**検証不能な飾り**である（1 は 4・5 に依存）。
* freshness は 7 が無ければ grind 可能（1 は 7 に依存）。
* dispatch proof は 3 が無ければ恒真（1 は 3 に依存）。
* いずれの前置部分集合も、**正直なブロックを落とす規則**か**攻撃者の宣言 `bool` を受理する規則**のどちらかを出荷する。

よって本スライスは §4.2 Leaf v2 / re-genesis cutover と同時に着地させる（§6 P1 および §11 の該当項目に既に位置づけられている）。**`palw_algo4_accept` は `false` のまま。本節は activation lever に一切触れない。**

### 5.14.5 本 run で実施した（ゼロリスクの）2 件

* `PalwDispatchProof` の doc comment に §5.14.2 の発見を記録。挙動変更なし。
* **永続化レイアウト pin の穴を塞いだ** — `palw_persisted_layouts_are_pinned_to_latest_db_version_8` は Lifecycle / View / Cert しか pin しておらず、同じく bincode 永続化される **`PalwPublicLeafV1` と `PalwBatchManifestV1` が対象外**だった。この guard は「ADR-0040 が一度バンプ無しでレイアウトを変えた」ために存在するのに、**Leaf v2 スライスが最初に触る 2 構造体**がちょうど抜けていた。両者を長さ + FNV-1a byte digest で pin（`LEAF_LEN = 796` / `MANIFEST_LEN = 472`）。これにより §5.14.3 の項目 2 は**自動的に検出される**。

### 5.14.6 M2 後の再検証（2026-07-20）— **PCPB 本体は依然 design-only。ただし item 7 は単独で SOUND になった**

§5.14 は M2（§5.15）より前に書かれた。M2 が着地したので前提を 1 件ずつ実コードで再検証した。

**再検証の結果（コード実測）:**

| §5.14.1 の前提 | M2 後の状態 |
|---|---|
| 3 つの純関数に production caller ゼロ | **不変。** `palw_challenge_fresh` / `palw_pcpb_derive_b` / `palw_dispatch_proof_valid` の参照は今も `consensus/core/src/palw.rs` の unit test のみ |
| `PalwPublicLeafV1` に PCPB フィールドが一つも無い | **不変。** challenge commitment / `challenge_epoch` / `a_commit` / `provider_snapshot_root` / `assignment_proof_root` / dispatch proof のいずれも無い（`LEAF_LEN = 796` / `LEAF_FNV` は動いていない） |
| 九節版 `verify_palw_ticket` に production caller ゼロ | **不変。** production は `verify_palw_ticket_store_facts`（clause 1–5）のみ |
| `PalwDispatchProof` が宣言 `bool` 形状（§5.14.2） | **不変。** 再設計されていない |
| provider registry / snapshot / assignment proof / escrow が在庫ゼロ、`PalwParams` に `w`/`k`/Δ 無し | **不変** |
| epoch 別 beacon seed が引けない | **不変** |
| leaf-chunk のプロデューサが存在しない | **FALSE になった**（M2、上記 §5.14.1 の取り消し線） |

**したがって「3 つの helper を verifier に繋ぐ」という最小着手は今も成立しない** — 繋ぐ先の入力（challenge / A_commit / snapshot root / dispatch 証拠）が leaf に一つも無く、`PalwDispatchProof` を今の形で leaf に載せれば §5.14.2 のとおり外部枝は恒真式に退化する。**§5.14.3 の項目 1/3/4/5/6/8 と §5.14.4 の分割不能論は、そのまま有効である。**

**ただし項目 7 だけは分離できる — そして M2 がそれを SOUND にした。**

§5.14.4 の 4 つの論拠はいずれも**項目 1（leaf フィールド追加）が何に依存するか**を述べたものであり、項目 7 が項目 1 に依存するとは述べていない。項目 7 を単独で入れたとき §5.14.4 の 2 つの角（正直なブロックを落とす／宣言 `bool` を受理する）のどちらにも当たらないことを確認した: 新しい `bool` を一切導入せず、正直なプロデューサは両値を自分で作るので必ず満たせる。

M2 前にこれを入れても**無意味**だった理由が本質である: leaf は `(batch_id, leaf_index)` で差し替え可能だったので、epoch を pin しても pin された leaf 自体が別物にされ得た。M2 後は `registered_epoch` が `leaf_hash` → `leaf_root` → `content_id() == batch_id` の中にあり、`registration_epoch` も `content_id()` の中にあるため、**両値は同一の `batch_id` に同時に封じられている**。よって等値検査は恒久的な束縛になる。

**実装した（本 run）:**

1. **acceptance 座標の epoch pin。** `apply_palw_overlay_effect` の LeafChunk arm に `leaf.registered_epoch == manifest.registration_epoch` を追加（新変種 `PalwOverlayError::LeafRegistrationEpochMismatch`）。membership gate の**前**、`leaf.batch_id` cross-check の直後。
2. **producer 側の鏡像。** `build_batch_manifest` が不一致 leaf を拒否（`RegistrationError::LeafRegistrationEpochMismatch`）。`manifest_leaf_root` の**前**で落とす — その先では `batch_id` が確定し、restamp で辻褄を合わせることが原理的に不可能（leaf を書き換えれば root が動き id が動く）になるため、不一致 batch は「間違い」ではなく**恒久的に使用不能**になる。
3. **fixture の統一。** consensus 側 `FIXTURE_REGISTRATION_EPOCH` / miner 側 `FIXTURE_REGISTRATION_EPOCH`。**旧 fixture は leaf `3` / policy `5` で、規則が禁じる乖離そのものを model していた**（consensus 側は leaf `5` / manifest `1`）。audit fixture は cross-crate golden（`golden_leaf`）を動かせないので policy の lead で吸収し、assert 済みの activation 7 / expiry 13 を保存した。

**この pin が買うもの（連鎖）:** mineable ⇒ `check_palw_ticket` の `view.resolvable_batch` ⇒ `apply_manifest` ⇒ `admission_valid` が `registration_epoch == accept_epoch` を強制 ⇒（本 run）`leaf.registered_epoch == registration_epoch`。**これで §5.14.3 項目 7 は完成する** — `leaf.registered_epoch` は batch の実 acceptance epoch に固定された。

**買わないもの（明示）:** PCPB は一切入っていない。challenge freshness は**依然として掛けられない**（`challenge_epoch` field が無い）。acceptance arm 単体は実 epoch を知らない — leaf↔manifest を束縛するだけで、manifest↔carrier epoch は view の admission gate が別に束縛する。view に入らない batch は任意の宣言 epoch で store され得るが、それは mint できない。**また `palw_premium_at_window` は今日 neutral 定数を返すので、閉じた自由度は現時点で経済的効果を持たない** — sampler が着地する**前**に閉じたことが価値であって、今何かが直っているわけではない。

**未着手として残るもの:** §5.14.3 の項目 1 / 2（DB cutover）/ 3 / 4 / 5 / 6 / 8 / 9。**P1-10 は CLOSED ではない。** §11 の判定は動かない。

---

## 5.15 §ACCEPT-BIND — CHUNK-INDEX SQUAT / G16 の前提を閉じる **leaf Merkle 束縛**（2026-07-20 設計確定・**同日 実装済み**）

### 5.15.1 結論

**CHUNK-INDEX SQUAT（§5.12 併記 (i)）と P1-9-RELAND（G16）は、同一の欠落した性質に還元される — leaf-chunk の主張が、その仕事の所有者に束縛されていない。** 本節はその閉鎖を **ACCEPT-BIND/M2** として規範に固定する: `leaf_root` を平坦ハッシュから **Merkle 根**へ作り直し、**ACCEPTANCE 座標**の LeafChunk arm で **per-leaf membership proof** を検証する。

> **実装済み（2026-07-20）。** 本節は「設計のみ」として書かれたが、同日 §5.15.9 の実装順序 (i)-(vii) を **1 スライスで** 実行した。原子性の要件は満たしている — core hashing・v2 payload・3 producer（miner `manifest_leaf_root` / `build_leaf_chunk`、auditor `AuditRound`、参照 mint `palw_demo`）・cross-crate golden・acceptance gate・fixture 再構築・DB 9→10 が同一スライスに入っている。**activation lever は一切動かしていない**: `palw_algo4_accept` は全 6 preset で `false`、`palw_activation_daa_score` 不変、`write_header_preimage` 不変（genesis hash 不動、`config::genesis` test 無改変）、新規 fence ゼロ。**body 座標は byte 単位で不変**（`apply_leaf_chunk` / `PalwBatchLifecycleV1` / `PalwBatchViewV1` / body fold）。
>
> **未閉鎖のまま残るものは §5.15.8 のとおりで、実装によって減っていない** — 特に bitmap の偽造可能性、`let _ =` の握り潰し、CERT-TRUST。**また本 slice は live 検証を経ていない**（unit / 統合 test は全緑だが、実 `testnet-palw` ネットでの E2E は未実施）。§11 の判定は本実装では動かない（§11 参照）。

**本節は activation lever に一切触れない。** `palw_algo4_accept` は全 6 preset で `false` のまま、`palw_activation_daa_score` は不変、`write_header_preimage` は不変（本節の対象は header preimage に一切入らないため **genesis hash は動かない**）。**新規 fence を導入しない** — これは re-genesis で配る無条件の format 変更であり、`--palw-enable-algo4` が runtime に書き換える `palw_algo4_accept` に consensus 規則を吊るす過去の事故様式は原理的に発生しない。

### 5.15.2 コード実測（本 run で再検証。3 件は従来の記述の**訂正**である）

**確認された事実:**

* `palw_leaf_root`（`consensus/core/src/palw.rs:2412`）には **consensus caller がゼロ**。全参照は定義 :2412、同ファイル unit test :5075/:5076/:5088、および `mil/miner/src/registration.rs:17,106` のみ。
* `apply_leaf_chunk`（:2775-2777）の doc は「呼び出し側が §9.3 completeness gate（blob-store 層）で chunk の leaf を `leaf_root` に対して検証する」と書くが、**その gate は存在しない**。ADR-0040 が繰り返し踏んできた失敗様式（**文書化されただけで強制されない束縛**）そのものである。
* `apply_leaf_chunk(&mut self, batch_id, chunk_index)` は引数 2 つのみ（:2778-2796）。判定は {batch 在席, `status == Registering`, `chunk_index < chunk_count`, bit 未設定} の 4 つで、**leaf を一切見ない**。bitmap 充填で `ChunksAndBondsComplete`。
* body fold（`consensus/src/pipeline/body_processor/processor.rs:453-465`）は戻り値 `bool` を捨て、`c.leaves` に触れない。
* acceptance arm（`consensus/src/processes/palw.rs:302-359`）の検査は manifest 在席 / `batch_id_is_content_derived` / `leaf_index < manifest.leaf_count` / `leaf.batch_id == c.batch_id`（**攻撃者が自分の leaf に書いた自己申告値**）のみ。その後 `insert_leaf`。
* `PalwBatchManifestV1` は 13 field。`content_id()` = `batch_id` を 0 にした borsh の keyed blake2b。`admission_valid` は**所有権を検査しない** — 提出者の署名も、bond の実在も、stake も見ない。唯一の経済的検査は**集約フロア** `total_leaf_bond_sompi >= leaf_count · min_leaf_bond_sompi`（`consensus/core/src/palw.rs:1005-1012`）だが、`min_leaf_bond_sompi` は `PalwBatchAdmissionParams::INERT`（`palw.rs:2486`）で **0** であり、6 preset すべてがこの INERT 値を継承するため実際には**空虚**である。（訂正 2026-07-20: 旧記述は「bond / stake / 署名を一切検査せず」としていたがフロア検査は存在する。また `min_leaf_bond_sompi` は**ネットワーク preset のフィールドではなく** `PalwBatchAdmissionParams` のフィールドである — `consensus/core/src/config/` に該当 grep hit は無い。「全 preset で 0」は結果として真だが、経路は preset ではなく INERT 継承である。）
* `LATEST_DB_VERSION = 9`（`factory.rs:94`）、pin :508、daemon arm `if version <= 8 {`（`kaspad/src/daemon.rs:664`）。`factory.rs:525-540` が**新境界の存在と旧境界の不在を双方向で**表明するため、片側だけの bump はビルドを落とす。
* `let _ = apply_palw_overlay_effect(...)`（`virtual_processor/processor.rs:1800-1801`）— overlay の error は**全て黙って捨てられる**。

**訂正・鋭利化（3 件）:**

1. **`insert_leaf` は「同一内容に対して冪等」であり、厳密な first-writer-wins ではない**（`stores/palw.rs:192-206`、判定は `leaf_hash()` の一致）。その doc 自身が欠落した束縛を "the separate completeness gate (BIND-01)" と名指している。**これは load-bearing である**: leaf の**内容**が束縛されれば、front-run は「攻撃者が手数料を払って被害者のデータを公開する」に退化し、正直な provider の tx も**そのまま成功する**。すなわち **denial の半分は content 束縛の帰結として閉じ、write-once は一切触らない**。
2. **certificate 時点の gate では DENIAL は閉じない。** 「CERTIFICATE admission で store から平坦 `leaf_root` を再計算する」案は THEFT は閉じるが、汚染 leaf は既に格納済み、正直な leaf は異内容として拒否され続け、batch は**恒久的に certify 不能**になる。さらに `batch_id == content_id` ゆえ同一 manifest の再登録は**同じ汚染鍵を再利用する**。**gate は `insert_leaf` より前に発火しなければならない** — これは body 座標 ML-DSA のコストとは独立に、その構造だけで当該案を棄却する。
3. **payload 予算は実測で足りる。** `PALW_MAX_OVERLAY_PAYLOAD_BYTES = 512 KiB`（:1977）、`PALW_MAX_LEAVES_PER_CHUNK = 64`（:1059）、`PALW_MAX_BATCH_LEAVES_V1 = 256`（:1979）、`LEAF_LEN = 796`。満杯 chunk は現行 ~51 KiB、64 leaf × 8 sibling × 64 B = 32 KiB を足して **~83 KiB** で cap の内側。**Merkle proof は支払える**（推測ではなく計算）。

### 5.15.3 本 run の新規発見 — **G3 は verifier が存在しない StopShip gate である**

`G3`（§7.2、StopShip、BIND-01 / LEAF-01）が指す verifier **`palw_leaf_membership_and_immutability` は本 tree のどこにも存在しない**（`.rs` 全走査でヒットは本 ADR 自身の 1 行のみ）。そして G3 の第 1 節「leaf が `manifest.leaf_root` に reduce することの強制」は、**まさに §5.15.2 で存在しないと確認した gate である**。

すなわち **StopShip gate が、存在しない検査を、存在しない test 名で閉じたことにしていた。** これは §2.6 の強制点走査（G15）が本来捕えるべき類型であり、G3 の第 2 節（write-once）だけが `insert_leaf` として実在する。**G3 の行を §5.15.10 で訂正する。**

### 5.15.4 設計 — M2 のみ

**body 座標には何も足さず、何も引かない。** `apply_leaf_chunk` / `PalwBatchLifecycleV1` / `PalwBatchViewV1` / `body_processor/processor.rs:453-465` の fold は **byte 単位で不変**。

**(1) `palw_leaf_root` → `palw_leaf_merkle_root(ordered_batch_id_zeroed_leaf_hashes: &[Hash64]) -> Hash64`**（`consensus/core/src/palw.rs`、:2406-2419 の平坦構成を置換）。構成を明示的に pin する:

* 深さ `d = ceil(log2(max(leaf_count, 1)))`、**一様**。欠落 leaf は定数 `H_EMPTY = blake2b_512_keyed(PALW_LEAF_MERKLE_EMPTY_DOMAIN, &[])` で `2^d` までパディングする。**一様パディング（末尾複製ではない）**は奇数アリティ由来の second-preimage 族を根絶し、全 proof をちょうど `d` sibling に揃える。
* leaf node: `blake2b_512_keyed(PALW_LEAF_MERKLE_LEAF_DOMAIN, leaf_index_le32 ‖ leaf_hash)`。**index を leaf node に束縛する**ので、有効な leaf を別 index で replay できない。
* internal node: `blake2b_512_keyed(PALW_LEAF_MERKLE_NODE_DOMAIN, left ‖ right)`。leaf domain と**素**（古典的な leaf/internal 混同防御）。
* root: `blake2b_512_keyed(PALW_LEAF_ROOT_DOMAIN, leaf_count_le64 ‖ apex)`。既存 root domain を再利用することで `leaf_root` 値は他の全 digest と素なまま保たれ、count 前置は :5075-5076 が既に表明している 2 性質（順序感応・個数感応）を保存する。

**(2) `PalwLeafChunkV1` → `version = 2`**、`proofs: Vec<PalwLeafMembershipProofV1>` を追加。proof は **sibling のみ**（`Vec<Hash64>`）で、**方向 bit は `leaf_index` から導出する — 攻撃者に渡させない**。

> **訂正（本 run の実測）: `check_palw_version` は全 payload 種で共有され、`version == PALW_PAYLOAD_VERSION_V1`（= 1）を強制する**（:2064-2066）。したがって `validate_leaf_chunk` に「加えて `version == 2` を要求する」ことは**できない** — 現状の共有検査が 2 を先に落とす。正しくは **`PALW_LEAF_CHUNK_VERSION_V2: u16 = 2` を新設し、`validate_leaf_chunk` だけが `check_palw_version` の呼び出しをこの leaf-chunk 専用検査へ差し替える**。他 arm の v1 検査は不変。

`validate_leaf_chunk`（:2225-2243、文脈非依存の検証器）が追加で要求するもの:

* `chunk.version == PALW_LEAF_CHUNK_VERSION_V2`。**v1 は拒否する** — `proofs` を空で default する寛容な parse は穴を丸ごと再開する。
* `proofs.len() == leaves.len()`。既存の**厳密増加 `leaf_index` 検査**（:2239）と併せて、proof は sort 済み leaf 列と index 整列する。
* `proof.len() <= 8`（`PALW_MAX_BATCH_LEAVES_V1 = 256` からの静的上界）。

**厳密検査 `proof.len() == ceil_log2(leaf_count)` はここには置けない** — `leaf_count` は manifest field であり、文脈非依存の検証器は manifest を持たない。**この分割は明記する価値がある**: 文脈非依存の上界は不正 chunk を**安く**落とすためのもの、厳密上界は proof を**一意**にするためのものである。

**(3) gate 本体**（`consensus/src/processes/palw.rs`、LeafChunk arm、既存の per-leaf ループ内、`leaf_index < manifest.leaf_count` と `leaf.batch_id == c.batch_id` の**後**、`insert_leaf` の**前**）:

* `c.proofs[i].len() as u32 == ceil_log2(manifest.leaf_count)` を**ハッシュ計算の前に**要求する（長短どちらも拒否）。
* `let mut p = leaf.clone(); p.batch_id = Hash64::default();` と射影して `p.leaf_hash()`。
* `leaf.leaf_index` の bit で sibling を畳み、結果が `manifest.leaf_root` と一致することを要求する。
* 失敗時は新 variant `PalwOverlayError::LeafMembershipProofInvalid`。arm は既に**最初の不正 leaf で return する**ので、partial-chunk の意味論は変わらない。

### 5.15.5 なぜこの座標だけが成立し、BIND-03 が届かないのか

manifest は当該 arm で**既に引かれている**（`store.batch_manifest(c.batch_id)`、`processes/palw.rs:313`）。本検査は **store 読み出しを増やさず、bond view を要さず、body 座標から acceptance データを消費せず、新しい失敗処理も作らない** — `LeafMembershipProofInvalid` は `UnknownBatch` / `LeafIndexOutOfRange` / `LeafBatchIdMismatch` / `LeafImmutabilityViolation` と同じ同値類に入り、その結果は丸ごと `virtual_processor/processor.rs:1800-1801` で捨てられる。**StatusInvalid を生み得ないのだから、順序依存の StatusInvalid も生み得ない。**

**§5.12 の座標決定（BIND-03）は再議しない。** batch view は acceptance/virtual 座標へ移動できず、body 座標で bond view を要する設計は全て着地不能である。M2 はそのどちらも要求しない。

### 5.15.6 棄却した代案（記録として）

* **chunk 単位の `chunk_digests: Vec<Hash64>` を manifest に持たせる案。** 束縛粒度が **chunk** なので、producer の切り方が digest を計算した切り方と byte 一致していなければならない。`build_leaf_chunk`（`mil/miner/src/registration.rs:245-271`、実読: 任意の `Vec<PalwPublicLeafV1>` と任意の `chunk_index` を取り、**manifest との紐付けが無い**）ゆえ、この drift は起こり得るどころか**既定**であり、しかも**無言で失敗する**。Merkle は **leaf 粒度** — store key `(batch_id, leaf_index)` と同じ粒度 — なので**どんな chunk 分割でも検証が通る**。無言失敗の一族が丸ごと消える。加えて**永続化 byte はゼロ増**（`leaf_root` は `Hash64` のまま、manifest 構造体は動かず、per-block clone される view も不変）。`chunk_digests` は MANIFEST_LEN を動かし、manifest 1 件あたり最大 16 KiB を足す。
* **manifest に submitter 鍵を書く案（identity 束縛）。** body 座標で検証可能ではあるが、(i) 鍵ハッシュを `PalwBatchLifecycleV1` に写す = **P1-5 が削ったばかりのコスト**（毎ブロック clone・再永続化される構造体の肥大）を復活させる、(ii) 今日 algo-4 ブロック 1 個につき 1 回の ML-DSA-87 verify を **chunk tx 1 件につき 1 回**へ増やす（質量計算のやり直しを要する新規 DoS 軸）、(iii) **そもそも所有権証明ではない** — `admission_valid` はその鍵を bond にも stake にも署名にも束縛しないので、得られるのは `batch_id` ごとの chunk 供給権の一意性だけ。**content 束縛だけで squat の要件は満たされる**（同一 chunk の再送は冪等ゆえ無害）。**identity 束縛は本 blocker の閉鎖に不要であり、結合してはならない。**
* **bitmap 削除 / FSM 畳み込み（M1）。** 独立した第 2 の consensus 規則変更（lifecycle レイアウト削除、新 `(Registering, AuditBeaconReached)` 辺、孤児化する `Committed`、`advance_epoch_gated` の腑分け）を、**順序独立性の論証が自明に検証可能であるべき**変更に混ぜることになる。かつ**不要**である: M2 後の bitmap は store にも reward 経路にも mint 経路にも影響しない **completeness の hint** に過ぎず、その偽造可能性は既登録の CERT-TRUST の真部分集合。**M2 を着地させ、bitmap 削除は別の view-format 変更として起票する。**

### 5.15.7 何が閉じるか（正確に）

* **THEFT（利益の出る半分）**: squatter は正直な `batch_id` の下で `provider_a/b_reward_script` / `ticket_authority_pk_hash` / `ticket_nullifier_commitment` を**著せなくなる**。これらは `leaf_hash` の中にあり、`leaf_hash` は `manifest.leaf_root` へ proof を通さねばならず、`leaf_root` は `content_id()` の中にあり、`batch_id == content_id()` は Manifest arm と（`batch_id_is_content_derived` 経由で）LeafChunk arm の**両方**で強制されている。`(batch_id, i)` に他人の leaf を書くには **BLAKE2b-512 の second preimage** が要る。`utxo_validation.rs:439-461` が読み `processes/coinbase.rs:177-206` が出力する **77 % worker base は、manifest 著者の script 以外にはなり得なくなる。**
* **DENIAL**: gate を通る chunk は正直な chunk と **byte 一致**であり、それを `insert_leaf` は冪等として扱う。**write-once / LEAF-01 は無傷** — 本変更が縛るのは「誰が**最初**であってよいか」であって「誰が**上書き**してよいか」ではない。
* **P1-9 / G16 の前提**: `job_nullifier`（`palw.rs:900`）は今日、consensus が何も検査しない自由 field である（`private_match_commitment`（:795-814）はこれを**含まず**、consensus reader も無い）。ゆえに**どの座標に置いても** first-claim-wins registry は回避可能である。M2 の後、`job_nullifier` は `leaf_hash` → Merkle → `leaf_root` → `batch_id` の中に入り、**不変かつ batch 束縛**になる。**追加の format コストはゼロ**: `PalwPublicLeafV1` は動かない（`LEAF_LEN = 796` / LEAF_FNV は pin されたままでなければならず、**そこが動いたら patch のバグである**）。

### 5.15.8 開いたまま残るもの（含意ではなく記録として）

* **bitmap は body 座標で依然偽造可能**（junk chunk が bit を消費し、`Registering → Committed` が早発する）。M2 後はどの store にも reward にも ticket にも影響しない。`chunks_present` 削除の後続 slice を推奨。
* **CERT-TRUST**: `apply_certificate`（:2837-2860）は何も検証しない。load-bearing な gate は store 側の `verify_certificate_attestation`（`processes/palw.rs:160-230`）であり、本節では触れない。
* **`max_view_batches` の cap 先取りによる検閲**。`min_leaf_bond_sompi == 0`（INERT 継承）によりほぼ無料。不変・別起票。
* **`let _ =` の握り潰し**（`virtual_processor/processor.rs:1800-1801`）。M2 は `LeafImmutabilityViolation` をほぼ到達不能にするので見直す good reason にはなるが、**それをブロック無効性へ変えること自体が consensus 規則変更であり、必ず別 patch でなければならない。**
* **正直な旗（独立検証済み・ADR の行として持つ価値がある）**: 「body 座標は acceptance が書いた state を読まない」という枠組みは**本 tree では既に偽である** — `check_palw_ticket`（`body_validation_in_context.rs:97-165`）が `resolve_palw_binding` を呼び、それが `palw_store` を読む。M2 はこの既存の BIND-03 型露出を**広げも消しもしない**（許容 leaf 集合を狭めるだけで、許容性は content で決まるため、leaf を格納するどの fork も**同じ** leaf を格納する）。だが**この枠組みを額面どおり受け取る査読者は評価を誤る。**

### 5.15.9 なぜ原子的でなければならないか（規範）

健全な修正は **re-genesis 級の 1 スライス**である: consensus-core で `leaf_root` の意味論が変わり、`PalwLeafChunkV1` が proof 付き v2 になり、acceptance arm が検証器を得、**miner**（`manifest_leaf_root` / `build_leaf_chunk`）と **auditor**（`mil/miner/src/audit.rs` の `AuditRound.leaf_root` — consensus が `processes/palw.rs:386-388` で `cert.leaf_root != manifest.leaf_root` として cross-bind している）が**歩調を揃えて**動き、手書き `leaf_root` fixture 約 30 件を作り直し、MANIFEST/LEAF pin を再導出し、`LATEST_DB_VERSION` 9→10 + `factory.rs:508` pin + `kaspad/src/daemon.rs` の `if version <= 8 {` → `<= 9 {` が**同時に**動く。

**部分着地は全て、大きな失敗ではなく無言の lane 全停止になる。** `apply_palw_overlay_effect` の結果は `virtual_processor/processor.rs:1800-1801` で捨てられる（`let _ =`、実測）ので、**miner/auditor の射影を伴わずに consensus 検証器だけが着地すると、どこにも error が出ないまま正直な chunk が一切格納されず、全 certificate が拒否される。** これは本 ADR 自身が警告する **P1-7 の様式（半端に入れる方が危険）** そのものである。

かつ**本 run では検証できない**: 正しさは cross-crate golden vector（miner 根 == consensus 根、auditor 根 == manifest 根）と、敵対 fixture 群を作り直して**各々が元の理由で落ち続けること**の確認に依存し、本 worktree は重い consensus crate を build するため、プロジェクト規約上 `.119` build host へ回る。**ADR が持てる設計が正直な出口であり、producer を伴わない Merkle 根は brick した lane である。**

**実装順序（後日 1 commit として実行する場合）**: (i) core hashing + domain 定数 + 構成 golden → (ii) `PalwLeafChunkV1` v2 + 文脈非依存検証器 → (iii) miner `manifest_leaf_root` / `build_leaf_chunk` + auditor `AuditRound.leaf_root` → (iv) miner 根 == consensus 根 == auditor 根 の cross-crate golden → (v) acceptance gate + 新 error variant → (vi) fixture 再構築 → (vii) pin + DB version の三点同時。**(i)-(iv) は (v) と同時に着地しなければならない** — producer 無き検証器が brick の failure mode である。

> **実行結果（2026-07-20）— (i)-(vii) を 1 スライスで完了。** 原子性は満たした。上の懸念のうち**訂正すべき 1 点**: 「本 run では検証できない」は**過大だった**。ローカル worktree で `cargo check --workspace --tests` と関連 unit / 統合 test は問題なく走り、cross-crate golden も敵対 fixture の再構築も**ここで**確認できた（`.119` を要するのは release build であって test ではない）。**依然として本環境で検証できないのは live E2E のみ** — 実 `testnet-palw` ネット上で miner→chunk→auditor→certificate が通ることは未確認であり、この slice の残余リスクはそこに集中している。
>
> **(iii) の producer は 3 つではなく 4 つだった。** 下の補記が挙げる miner / auditor / 参照 mint に加え、`consensus/src/pipeline/virtual_processor/tests.rs` の algo-4 統合 harness が **4 つ目の `leaf_root` 生成箇所**である。ここも `leaf_root: Hash64::default()` 相当のリテラルを書いていたため、gate 着地と同時に無言で全ブロックが不合格になる経路だった。参照 mint と共有の `seeded_single_leaf_root` へ寄せて解消した — **producer の棚卸しは 2 回続けて漏れており、これは「grep して数える」で足りる作業ではないという記録として残す。**
>
> **(vi) の実測**: `leaf_root` を持つ手書き fixture のうち**構成に依存していたのは少数**で、大半は `leaf_root` を不透明な `Hash64` として使う body 座標 / lifecycle / borsh-layout fixture だった（§5.15.4 のとおり body 座標は不変なので、これは正しい姿である）。**導出に直したのは実際に gate を通る fixture のみ**、リテラルのまま残したものは「不透明な filler である」ことを根拠に残した。**約 30 件という見積りは、置換すべき件数としては過大だった。**

> **producer の棚卸しに 1 件抜けがあったので補う（2026-07-20）。** 上の (iii) は miner と auditor しか挙げていなかったが、**3 つ目の producer が `consensus/src/consensus/palw_demo.rs` にある**（`:90`, `:161`）。これは `--palw-mine` が毎 tick 駆動する参照 mint で、`batch_id` と leaf を seeded store へ直接書く。Merkle 化後もこの経路が古い平坦根のまま leaf を seed すると、**acceptance gate が membership proof を要求する側に回った瞬間に、この mint だけが無言で通らなくなる** — しかも `--palw-mine` service は mint 失敗を `NotReady` に分類して warn を抑制する設計なので、**最も静かに壊れる producer である**。(iii) に含めること。
>
> 併せて記録する。この slice の敵対監査は **5 件目の construction != validation** を発見した: `mil/miner/src/mining.rs` の `full_self_contained_mining_round_end_to_end` が、実 manifest を組み立てておきながら `AuditRound` には `manifest_hash: h(0x11)` / `leaf_root: h(0x22)` というリテラルを渡していた。consensus は `cert.manifest_hash == manifest.content_id()` と `cert.leaf_root == manifest.leaf_root` を要求する（`processes/palw.rs:384-389`）ので、**「end-to-end」を名乗るテストが、実運用なら `CertificateManifestMismatch` で落ちる経路を通していた**。実値へ修正済み（producer 自体は正しく、テストだけが検証していなかった）。Merkle 化は fixture を全面的に作り直すため、**この種の「リテラルで通しているだけ」の箇所が他にも露出する可能性が高い** — (vi) の fixture 再構築では、置換ではなく**導出**に直すこと。

### 5.15.10 format / DB 規律

`leaf_root` は `Hash64` 型のままなので **MANIFEST_LEN 472 / MANIFEST_FNV は動かない**。しかし **`leaf_root` の値は全て動き、ゆえに全 `content_id()` が動き、ゆえに全 `batch_id` が動く。**

> **重大**: pin fixture は `leaf_root` に**リテラル `h(0x43)`** を使うため、**pin test は本変更を構造的に検出できない。** 緑の pin を「format 変更なし」の証拠として読んではならない。**構成レベルの golden が必須である。**（同じ構造的盲点が `mil/miner/src/audit.rs:248` のリテラル `h(0x22)` にもある。）

`PalwLeafChunkV1` v2 は **wire format** であり bincode 永続化されず、pin の対象外。**LIFECYCLE 253 / VIEW 335 / CERT 494 / LEAF 796 は全て pin されたまま動いてはならない — どれかが動いたら本設計の範囲外を触っている。**

`LATEST_DB_VERSION` 9→10（`factory.rs:94`）、その pin（:508）、`kaspad/src/daemon.rs:664` の `if version <= 8 {` → `if version <= 9 {` を **1 commit で**動かす。`factory.rs:525-540` が新境界の存在と旧境界の不在を**双方向で**表明するため、片側だけの bump は build を落とす。pin test は `..._to_latest_db_version_10` へ改名し、その header に **MANIFEST は byte を動かさずに意味論が動いた**ことを記録する。

### 5.15.11 明示する SPEC CHANGE（静かな編集にしない）

> **実行済み（2026-07-20）。** 下表の 4 つの doc 書き換えはコードに入っている: `consensus/core/src/palw.rs`（旧 `palw_leaf_root` → `palw_leaf_merkle_root` の doc、および `PalwBatchViewV1` の fold doc）、`mil/miner/src/registration.rs::manifest_leaf_root`、`consensus/src/model/stores/palw.rs::insert_leaf`。**「存在しない gate を名指す doc」を「実在する gate を名指す doc」に替えることが、この表の全趣旨である** — ADR-0040 が繰り返し踏んだ失敗様式（文書化されただけで強制されない束縛）の逆をやっている。

| 位置 | 現在の記述 | 変更後 |
|---|---|---|
| `palw.rs:2406-2411` | 「leaf presence は batch が chunk-complete になった時点で検証される（§9.3）。per-leaf の Merkle proof ではない」 | **SUPERSEDED** — まさに per-leaf の Merkle proof になる |
| `palw.rs:2775-2777` | 「呼び出し側が §9.3 completeness gate で検証する」 | **その gate は存在しなかった**（`palw_leaf_root` の consensus caller ゼロ、実測）。実在する gate（blob-store 層・per leaf）を指すよう書き直す |
| `mil/miner/src/registration.rs:92-94` | 「consensus は格納 leaf から `leaf_root` を再計算しない … audit 層向けの producer 側 content commitment であって consensus 強制の束縛ではない」 | **偽になる** — 書き直す |
| `stores/palw.rs:191` | 「`manifest.leaf_root` への束縛は別の completeness gate（BIND-01）」 | その gate が**存在するようになる** |
| §5.12 併記 (i) | CHUNK-INDEX SQUAT = 未修正 | **leaf content の半分で閉じる**。bitmap の半分は CERT-TRUST 配下の**不活性な completeness hint** へ再分類 |
| §7.2 G3 | verifier `palw_leaf_membership_and_immutability` | **本 tree に存在しない**（§5.15.3）。第 1 節は本節で初めて実在化し、第 2 節（write-once）のみが `insert_leaf` として実在していた。**実装後（2026-07-20）: 存在しない名前を作って埋めるのではなく、G3 行を実在する verifier 群へ差し替えた**（§7.2 参照） |

### 5.15.12 テスト計画（本設計が要求する最小集合）

* **CROSS-CRATE GOLDEN（miner）**: 固定の複数 leaf fixture に対し `mil::miner::registration::manifest_leaf_root(fixture) == kaspa_consensus_core::palw::palw_leaf_merkle_root(batch_id 零化射影ハッシュ)` を、**pin された定数**に対して表明する。**本変更で最も価値の高い 1 本** — miner/consensus の drift は無言で失敗する。
* **CROSS-CRATE GOLDEN（auditor）**: `mil/miner/src/audit.rs` が `PalwBatchCertificateV1` に載せる `leaf_root` が新構成下で `manifest.leaf_root` と一致する（consensus は `processes/palw.rs:386-388` で cross-bind する）。ここが drift すると**全 certificate が error 表面なしで拒否される**。第 2 の無言死経路であり、忘れやすい。
* **E2E ROUND TRIP**: `build_batch_manifest` + `build_leaf_chunk` で組んだ batch が**実物の** acceptance arm（`apply_palw_overlay_effect`、LeafChunk）を通り、全 leaf が格納される。**multi-chunk（`leaf_count > 64`）**と、**2 冪でない `leaf_count`**（一様 `H_EMPTY` パディングの被覆）を必ず含める。
* **SQUAT NEGATIVE**: 正直な `batch_id` の下で `provider_a_reward_script` / `ticket_authority_pk_hash` を差し替えた leaf が `LeafMembershipProofInvalid` で拒否され、**格納されない**ことを戻り値でなく **store で**表明する。reward 経路と対にし、`palw_work_reward_class` が正直な script を読み続けることを確認する。
* **WRITE-ONCE の被覆を空洞化させない**: 既存の LEAF-01 泥棒 fixture（`processes/palw.rs` ~:887-899, ~:928-935）を**有効な membership proof 付きで再構築**し、`insert_leaf` の write-once 検査に**到達して**落ちる状態を維持する。digest gate で落ちる新 test は**その横に**追加する — **置き換えではない**。同じ監査を全敵対 fixture（`palw.rs` :4288, :4348, :4507, :5075-5088, :5200-5208 / `processes/palw.rs` :772, :806, :864, :873, :880）に施し、各々が**元の名前の理由で**落ち続けることを確認する。**test を消さずに実被覆を失う最有力経路がこれである。**
* **IDEMPOTENT REPLAY**: 正直な chunk 格納後、**同一 chunk の再送**（無害な front-run / reorg replay）が `insert_leaf` の `leaf_hash` 一致経路で成功し続ける。**denial 閉鎖の主張を真にしているのはこれであり、論じるのでなく表明しなければならない。**
* **MERKLE 健全性 negative**: (a) 有効な leaf+proof を**別 leaf_index** で replay → 拒否（index が leaf node に束縛されている）、(b) `proof.len() != ceil_log2(leaf_count)` を**長短両方**で拒否、かつ**ハッシュ計算前に**拒否、(c) internal node digest を leaf として提示 → 拒否（leaf/internal domain 分離）、(d) :5075-5076 の順序・個数の表明が保存され、Merkle 根へ拡張されている。
* **VERSION-2 厳格性**: v1 の `PalwLeafChunkV1` payload が `validate_leaf_chunk` で**拒否**される（`proofs` を空 default にして parse されない）。寛容な parse は穴を丸ごと再開する。
* **FIXED-POINT 回帰**: producer が組んだ manifest が新 `leaf_root` の下で `batch_id_is_content_derived()` を満たす。**加えて negative** — 非射影（`batch_id` を埋めた）版は検証を**通らない**ことを明示的に表明し、将来の「この 2 つの leaf hash を重複除去しよう」という整理が**大声で**落ちるようにする。註: `resolve_palw_binding`（`processes/palw.rs:471`）は eligibility 抽選のため**意図的に `batch_id` を埋めたまま** `leaf_hash()` を使う。ゆえに tree は同一 leaf の**意図的に異なる 2 つのハッシュ**を持つことになり、**両方の call site に大きな註釈が要る。**
* **PIN + DB 三点**: `palw_persisted_layouts_are_pinned_to_latest_db_version_10` へ改名。LIFECYCLE 253 / VIEW 335 / CERT 494 / LEAF 796 / MANIFEST 472 と各 FNV が**全て不変**であることを表明（動いたら本 patch のバグ）。`latest_db_version_is_pinned` と `daemon_hard_reset_arm_covers_the_version_left_behind` が `LATEST_DB_VERSION = 10` と daemon 側 `if version <= 9 {` で通ることを確認。**pin fixture が `h(0x43)` リテラルゆえ本変更を構造的に検出できない以上、構成 golden は必須であり、緑の pin を証拠として受け取ってはならない。**
* **DOMAIN 登録**: 新 3 定数（`PALW_LEAF_MERKLE_LEAF_DOMAIN` / `_NODE_DOMAIN` / `_EMPTY_DOMAIN`）が `domain_strings_are_pinned_and_fit_key_limit`（:6090）で値 pin され、既存全 PALW domain と**対互いに相異**であること。
  > **訂正**: `retired_slot_domain_is_never_reused`（:6068-6087）は各 domain が `PALW_RETIRED_SLOT_DOMAIN` と異なることしか表明しない。**pairwise distinctness test ではなく、未登録の新定数を検出しない。** ゆえに「登録漏れは既存 test が捕える」と考えてはならない — **本スライスで真の pairwise 表明を追加すること。**
* **PAYLOAD 上界**: 満杯 chunk（64 leaf・深さ 8 proof・~83 KiB）が `validate_palw_overlay_payload` の 512 KiB `PALW_MAX_OVERLAY_PAYLOAD_BYTES` を通ること、および過長 proof の chunk が Merkle 計算前に文脈非依存の `proof.len() <= 8` で拒否されること。

### 5.15.13 P1-9-RELAND（G16）— **別 commit・Activation 級・本 patch の一部ではない**

**fold の comment を字義どおり実装してはならない。** 本 run で両半分とも**実装不能であることを再検証した**:

* `ActiveBondView` が持つのは **DNS stake bond**（`StakeBondRecord.validator_pubkey`）であって PALW provider bond ではない。
* provider-bond payload は**永続化されない**（`PalwOverlayEffect::ProviderBond(_bond) => Ok(())`、`processes/palw.rs:289-293`、直接確認）。
* `ReplicaExecutionReceiptV1::signature` は自身の doc が言うとおり **"a wire field only"**（`palw.rs:842-844`）で、consensus 側 decoder は存在しない。

**この comment は本作業の一部として訂正すること。**

着地先: `palw_work_reward_class`（`virtual_processor/utxo_validation.rs:387`）。key = **M2 で commit 済みになった** `leaf.job_nullifier`。効果 = `WorkRewardClass::ReplicaPalwHalted`（:414）に倣う **script 無しの末尾クラス**。paid-set は **`RewardedEpochSet` walk モデル**（per-block 行 `processor.rs:1704-1706`、`selected_chain_overlay_window`（`processor.rs:3072-3110`）で再構成、`pruning_processor/processor.rs:508` で刈る）— **carried map にしない、攻撃者申告 field での eviction にしない。** `overlay_window_walk_bound`（`processor.rs:3049-3056`）は **admission 側の recency filter と対にして初めて強制される**（`utxo_validation.rs:1058-1061` の類推）。それ無しではこの bound は comment に過ぎない。

**ADR に明記する**: reward のみの規則は payout を留保するが、**ブロックそのものも、`E = H + min(C, 4H)` の下での lane weight も、difficulty 持分も留保しない。** 先例は `ReplicaPalwHalted`。**ADR-0040 が lane work 寄与の零化まで意図しているかは、コード上の何も決めていない未決の仕様問題である — 推測しないこと。**

回帰 guard `no_job_nullifier_registry_at_the_body_coordinate`（`processes/palw.rs:677-703`）が走査するのは `consensus/core/src/palw.rs` / `body_processor/processor.rs` / `processes/palw.rs` の 3 file のみ。**reward 座標の実装はその全てより外側に住むので、禁止識別子を避けた命名（`paid_work_ids` / `record_paid_work`）を使うこと。この test は編集しない。**

#### 実装結果（2026-07-20）— **BOUNDED-WINDOW 版が着地。G16 は閉じていない**

着地した規則は本節が想定したとおり reward/virtual 座標にあり（`palw_work_reward_class`、`utxo_validation.rs`）、paid-set は `RewardedEpochSet` walk モデルの忠実な写し（新 block-keyed CF `PalwPaidWork` + `palw_paid_work_window` の selected-chain walk + pruning 連動、DB 10→11）。**P1-5 が削除した形状は再導入していない**: view に載らない・clone されない・entry は「受理された algo-4 block が実際に payout を得た」ときのみ生じ・上限は既存の mergeset size limit。

**ただし walk が bounded である以上、閉じるのは「両 batch の生存窓が重なる範囲での重複請求」までである。** 同一 `job_nullifier` を今日の batch と 1 年後の batch に登録する経路は、どの bounded walk からも見えない。これを閉じるには (a) 恒久 nullifier 集合＝無限成長 state（P1-5 が削除した形状そのもの）か、(b) `job_nullifier` を最近の beacon/epoch に束縛する leaf format 変更（`LEAF_LEN`/`LEAF_FNV` が動く）のいずれかが要る。**どちらも本 slice の範囲外であり、前者は「見つけた所見」であって出荷物ではない。** 導出可能性は `PalwBatchAdmissionParams::max_batch_life_epochs`（`admission_valid` が実際に強制する 3 条項からの合成、探索テストで tight 性まで表明）に固定した。

**もう 1 つの activation blocker（新規）**: pruned-IBD joiner は pruning point 以下に row を持たないため、その直上 `paid_work_walk_bound_daa` 分の帯で walk が短い prefix を返す。paid-set を pruning-point snapshot に載せれば閉じるが、その snapshot の borsh 符号化は `Header::overlay_commitment_root` の preimage なので、**mainnet を含む全ネットの header commitment が動く**。よって wiring ではなく header 変更であり、別 slice。パラメータ側の関係（walk < pruning_depth）は `palw_paid_work_walk_stays_above_the_pruning_point` で全 6 preset に強制済み。

**結論: G16 は Activation 級のまま。**「前提が閉じた」を「gate が閉じた」と読むなという本節の警告は、そのまま「bounded 版が入った」を「G16 が閉じた」と読むなにも適用される。

---

## 5.16 §SLASH — SLASH-01（§12.4 cross-fork 二重使用 slashing）の設計。**DESIGN-ONLY — 実装しない**（2026-07-20 確定）

### 5.16.1 結論

**SLASH-01 は本 run で wiring しない。実装は成立しない。** 機械の大半は既に建っている（下記）にもかかわらず、`implement` にならない理由は 1 つに集約される: **equivocation を働いた ticket authority を slashable な bond に束縛する LINK が、データモデルに存在しない。** 証拠は authority を `authority_public_key` でしか名指さず bond outpoint を運ばない。したがって slash producer が emit すべき target outpoint が**導出不能**である。これは ordering の問題でも wiring の欠落でもなく、**データモデルの gap** であり、閉じるには leaf acceptance semantics を変える re-genesis 級の設計判断（§5.16.6）が要る。本節はその判断の材料と、判断が下った後に着地させる完全な設計を規範として固定する。ADR 冒頭「半端に入れる方が危険である」がここに直接適用される — target を発明すれば、equivocator ではなく leaf の compute provider を没収してしまう（§5.16.5）。

**したがって §2.3 の SLASH-01 行・§2.3′ の OPEN #1・§6 #8・G13 の SLASH-01 分は、いずれも「未着手」から動かない。** 本節が動かすのは 1 点のみ: **原因を「producer が無い」から「LINK が無い（producer は target を持てない）」へ精緻化する**こと、および 0x34 mislabel の landmine を記録することである。

### 5.16.2 既に建っている機械（設計前に確認した実コード）

丸め上げ禁止。SLASH-01 を「producer を 1 本足すだけ」と誤読させないため、存在するものを列挙する。

* **mutation は本物**。`PalwProviderBondMutation::Slash(TransactionOutpoint, u64)`（`consensus/core/src/palw.rs:1514`）は apply が `slashed_at_daa_score` を set（`:1733`）、revert が clear（`:1755`）— 前進/逆順反復で厳密な逆写像（`ProviderBondView::apply`/`revert`、`:1722`/`:1744`）。`effective_provider_bond_status`（`:1527`）は `slashed_at_daa_score.is_some_and(|s| pov_daa >= s)` で `Slashed` を返し、既に terminal 扱いである。
* **evidence primitive も本物**。`PalwBlockAuthorizationV1`（`:1811`）= `(version, batch_id, leaf_index, ticket_nullifier, header_preimage_commitment, authority_public_key, signature)`。各々が `signing_hash(network_id)`（`:1870`）を context `PALW_AUTHORIZATION_MLDSA87_CONTEXT`（`:123`）で ML-DSA-87 署名し、body clause 7（`body_validation_in_context.rs:352-360`）で検証される。**同一 authority が同一 ticket slot を DIFFERENT header commitment へ二度署名すれば、それが二重使用の証明**であり、これは primitive 自身の doc（`:1811-1835`）が名指す攻撃そのものである。
* **DNS に完全な先例がある**。`validate_slashing_evidence_payload`（`dns_finality.rs:3666`）+ `validate_slashing_evidence_tx`（`:3703`）= stateless verifier、`slashing_side_effects_from_evidence`（`:3009`）+ `resolve_slashing_side_effects`（`:3076`）= stateful 効果解決。equivocation の 2 半分が本当に conflicting（同 slot・異内容）であることを検査し、self-identical を `EvidenceNotIncompatible`（`:3488`）、slot 不一致を `EvidenceTripleMismatch`（`:3485`）で拒否する。

**建っていないものは 1 つ**: `palw_provider_bond_mutations_from_accepted_txs`（`:1603`）は `Insert` と `Unbond` しか emit せず、`Slash` の **producer が無い**。だが producer が書けない理由は §5.16.5 の LINK gap であって、書き忘れではない。

### 5.16.3 0x34 の衝突 — **先に決着させた**。`SUBNETWORK_ID_PALW_SLASHING` は dangling mislabel

`SUBNETWORK_ID_PALW_SLASHING = 0x34`（`subnets.rs:215`）だが、`PalwTxKind::from_subnetwork_byte(0x34) => Revocation`（`palw.rs:2506`）である。**1 つの subnetwork byte が両方であることはできない。** 実コードで真偽を確定した:

* **0x34 は Revocation として decode され、validate まで wired**。frozen payload `PalwRevocationV1`（`palw.rs:2442`）、stateless validator `validate_revocation`（`:2916`）が overlay switch（`:2964`）で routing、pruning bundle `PalwEpochProofBundleV1.revocations`（`:2229`）で carriage される。**ただし effect の適用は未配線**: `PalwBatchViewV1::mark_revoked`（→ `revoked_from_daa`、`is_block_eligible_at` が SS-04 の §9.5 非遡及で比較する対象）には **production caller が無い**（`palw.rs` の参照は doc とテストのみ）。したがって「revocation が batch を eligibility から外す」経路は**まだ発火しない** — decode/validate は実在し、状態遷移の適用はしていない。Revocation は vestigial ではないが「完全に wired」でもない。それでも **0x34 が slashing でなく Revocation に一意 decode される**という SLASH-01 の landmine 論証には影響しない（decode 段は wired 済み）。この gap 自体は別途 §9.5 revocation-apply として起票。**（2026-07-20 訂正: 旧記述は「完全に wired」としていたが `mark_revoked` の caller 不在を見落としていた。この doc-vs-code 型の過大記述こそ本 ADR が繰り返し踏んできた欠陥である。）**
* **`SUBNETWORK_ID_PALW_SLASHING` は死んだ mislabel**。唯一の使用箇所は自身の doc comment と `PALW_BAND` test 配列（`subnets.rs:244`）の membership のみで、そこですら `palw_tx_kind() == Some(0x34)` を主張するだけ。**0x34 を slashing として decode するコードは存在しない** — `from_subnetwork_byte(0x34)` は Revocation を返す。つまり `SUBNETWORK_ID_PALW_SLASHING` で提出された tx は **Revocation として decode・検証される**。これは live な consensus-fault landmine である。

**決着**: この定数は slashing carrier として使ってはならない — **リネームまたは除去**する。slashing evidence は**新しい subnetwork byte に載せる**。band `0x30..=0x38` は満杯（`is_palw_overlay`、`subnets.rs:103`; 0x38 = BlockAuthorization、`:233`）で、次の空きは **0x39**（現在 `subnets.rs:273` で "just above band" と主張されている）。`PalwTxKind::SlashingEvidence` を 0x39 に置く = band を `0x30..=0x39` へ拡張する **wire 変更**であり、これは PALW re-genesis でのみ admissible — 0x38 拡張が使ったのと同じ正当化（`subnets.rs:228`）である。**この決着自体が wire/design 変更であって pure wiring ではない**ことが、scope が design-only であるもう 1 つの理由である。

### 5.16.4 stateless evidence verifier（設計。LINK が立てば isolation で検証可能な半分）

新 0x39 payload 上の `validate_slashing_evidence`（DNS の `dns_finality.rs:3666`/`:3703` を鏡像）は、2 つの `PalwBlockAuthorizationV1` を decode し、**provable equivocation** の全条件を要求する:

1. `auth_a.authority_public_key == auth_b.authority_public_key`（同一 equivocator）。
2. 同一 ticket slot: `(batch_id, leaf_index, ticket_nullifier)` が両者で一致。
3. `header_preimage_commitment` が**相違**する — 二重使用そのもの（1 枚の当選 ticket を 2 つの競合 header へ restamp）。
4. 両署名が共有 key + `PALW_AUTHORIZATION_MLDSA87_CONTEXT` の下で ML-DSA-87 検証（clause 7 の `verify_mldsa87_with_context` を鏡像）。
5. evidence tx は **output ゼロ**（純粋な evidence carrier。reporter reward があるなら consensus side-effect として mint。DNS `validate_slashing_evidence_tx` と同型）。

**anti-grief**: 条件 3 が self-identical 半分（等しい `header_preimage_commitment`）を拒否する — DNS の `EvidenceNotIncompatible` の analog。**1 本の正直な authorization を 2 回 replay しても slash は起きない**（同一 commitment なので条件 3 が落ちる）。slot 不一致は `EvidenceTripleMismatch` の analog。この半分は 2 つの authorization に対して**純粋**で、chain state を一切読まない。

### 5.16.5 **THE FINDING — authority → bond LINK がデータに存在しない**（load-bearing）

これが slashing を今実装できない決定的理由である。DNS 先例が機能するのは、**署名されたオブジェクト自身が slashable bond を名指す**からだ: `SlashingEvidencePayload.bond_outpoint`（`dns_finality.rs:506`）は explicit で、equivocate する各 `StakeAttestation` が自分の `bond_outpoint` を埋め込み、それが payload の値と等しいことが検査される（`:3676-3682`）。**PALW の署名 authorization は bond を名指さない** — `PalwBlockAuthorizationV1`（`palw.rs:1811`）に bond outpoint field が無い。

さらに 3 つの identity が**別々の役割**で、互いに変換できない:

* **authority**: leaf は `ticket_authority_pk_hash`（`palw.rs:946`）を **KEYED** hash `blake2b_512_keyed(PALW_AUTHORIZATION_DOMAIN, pk)` として保存（producer は `binds_leaf_authority`、`:1888`。clause 7 が実際に強制、`body_validation_in_context.rs:347`）。
* **provider bond owner**: bond record は `owner_pubkey_hash = validator_id_from_pubkey(pk)`（producer `palw.rs:1626`、定義 `dns_finality.rs:1455`）= **UNKEYED** blake2b-512。
* **provider outpoints**: leaf は 2 provider を **outpoint** `provider_a_bond` / `provider_b_bond`（`palw.rs:942-943`）で保存。

**2 つの identity hash は異なる関数なので equate できない**: `leaf.ticket_authority_pk_hash`（keyed）は bond の `owner_pubkey_hash`（unkeyed）と決して一致しない。唯一考えられる橋は、evidence が運ぶ full key に対する `validator_id_from_pubkey(authority_public_key)` である。**しかし、ticket authority が provider bond を post したことを要求・記録する on-chain 規則も store も存在しない**（確認済み: `consensus/src/model/stores/palw.rs` に authority pk/hash → bond outpoint の mapping は無い）。CRITICAL-1（§2.3′）は payee ≡ provider-bond owner を束縛するが、**ticket authority については何も言わない** — authority は provider_a でも provider_b でも、いかなる bonded party でもない、自由で独立な key であってよい。

したがって「authority を owner とする bond を slash する」には**well-defined な target が無い**。そして leaf の provider_a/b bond を authority の equivocation で slash すれば、**equivocator ではなく compute provider（別人）を没収する**。SLASH-01 を閉じるには次の**どちらか**が要る:

* **(A)** 新しい consensus binding 規則 — `leaf.ticket_authority_pk_hash == ticket_authority_pk_hash(provider_X_bond.owner_public_key)`、すなわち authority を leaf の named provider の 1 つに強制する。これは **leaf acceptance semantics の変更で re-genesis reach**。
* **(B)** 存在しない authority-role bond を新設する。

どちらも producer wiring ではなく設計判断である。**task の指示どおり、LINK を発明せず停止する。**

### 5.16.6 stateful 半分・producer が住む座標（設計。LINK 依存で今は書けない）

LINK が立った後にのみ書ける 2 つの片:

* **block-validity 半分** `palw_slashing_evidence_genuine`（DNS `resolve_slashing_side_effects`、`dns_finality.rs:3076` を鏡像）: equivocator の bond を selected-parent の `ProviderBondView`（`palw.rs:1705`）に対して解決し、block の daa_score で `Active`/`Unbonding` を要求。**この片が BLOCKED**なのは解決ステップの input が無いから — evidence は bond を名指さず、authority→bond mapping が無い（§5.16.5）。
* **producer** `palw_slashing_mutations_from_accepted_txs`: leg-4/5 の unbond producer と**同一の acceptance/virtual 座標**（`palw_provider_bond_mutations_from_accepted_txs`、`palw.rs:1603`。`stage_palw_provider_bond_mutations` が apply、reorg revert は `..._for_chain_block` が re-derive）に置く。genuine な各 0x39 evidence に対し `PalwProviderBondMutation::Slash(resolved_bond_outpoint, accepted_daa_score)` を emit。mutation の apply/revert は既に逆写像として存在する（`:1733`/`:1755`）。**blocker**: `resolved_bond_outpoint` が導出不能（§5.16.5）。

### 5.16.7 order-independence（構成上満たされる。ordering は blocker ではない）

legs 4/5 と同じく構成すれば order-independent: mutation は block の accepted txs から**固定 selected-parent point of view**で `ProviderBondView`（in-memory、`palw.rs:1705`）に対して導出し、最後に commit された prefix の global store を読まない（`ProviderBondView` doc が名指す chain-split hazard、`:1662-1712`）。`Slash` apply/revert は前進/逆順で厳密な逆写像なので、異なる reorg 経路で同一 block へ到達した 2 ノードは同一 view を持つ。**unauthorized/malformed evidence は NO-OP skip（`continue`）であって block-reject ではない** — leg 5 で除去した merge-blue mergeset DoS 形状を再現しないため。stateless evidence 検査は 2 authorization に対して純粋。**block 内 dedup** は target bond outpoint で行い（DNS `slashing_side_effects_from_evidence`、`:3009` を鏡像）、複数の equivocation 証明が tx 順に関わらず 1 bond を高々 1 回 slash する。**order-independent な実装を妨げているのは唯一 target 導出の欠落（§5.16.5）であり、ordering ではない。**

### 5.16.8 format 影響 — **本 slice はゼロ（design-only）**

コード変更が無いので `LATEST_DB_VERSION` は **11 のまま**（`consensus/src/consensus/factory.rs:102`）、pin 移動も daemon arm 変更も無い。記録として、後日実装する場合: `PalwTxKind::SlashingEvidence` を 0x39 に追加 + 新 evidence payload 型 + `is_palw_overlay`/`palw_tx_kind` を `0x30..=0x39` へ拡張（`subnets.rs:103`/`:110`）+ band-edge test（`:253`/`:273`）は **wire 変更で re-genesis のみ**。**bond record format 自体は動かない**: `slashed_at_daa_score` は既に `PalwProviderBondRecord` にあり、staging apply/revert は既に `Slash` を扱う（`palw.rs:1733`/`:1755`）ので、永続 registry format は変わらず mutation のために `LATEST_DB_VERSION` を動かす必要は無い。ただし §5.16.5 (A) の authority→bond binding 規則は **leaf acceptance semantics を変えうる**（byte-neutral なのは algo4 が全 preset で inert だからにすぎない）— これが re-genesis 級の部分である。

### 5.16.9 次の設計ステップ（load-bearing decision）

producer/verifier に先立って決めるべきは 1 点: **re-genesis scope で、§12.4 の equivocating authority をどう slashable bond に束縛するか。** 有力候補は §5.16.5 (A) — leaf の `ticket_authority_pk_hash` を `ticket_authority_pk_hash(provider_a_bond.owner_public_key)` に等しくなるよう要求し、authority ≡ named provider にすることで `validator_id_from_pubkey(authority_public_key)` が実在 bond を解決するようにする。この決定が下るまで producer も verifier も書けない。**`palw_algo4_accept` は全 preset で `false` のまま。本節は activation lever に一切触れない。**

---

## 5.17 §CERT-REDERIVE — AUTHSET-01 / SAMPLE-01 / SEL-01（証明書宣言値の consensus 再導出）。~~**DESIGN-ONLY — 本 run で実装しない**~~ → **IMPLEMENTED（原子スライス着地・INERT）**（2026-07-20）

> **実装ステータス更新（2026-07-20、本節末尾の DESIGN-ONLY 記述に優先する）。** §5.17.11 の 2 load-bearing decision（(1) `audit_sample_root` のオンチェーン再定義、(2) 有界 inclusion 窓規則）がいずれも下り、原子スライスを着地させた。着地物:
> - **seed resolver**: `resolve_palw_audit_epoch_seed`（buried selected-parent walk、§5.17.3）を `verify_certificate_attestation` 座標に配線。解決不能 ⇒ FAIL-CLOSED。有界 inclusion 窓 `palw_certificate_included_within_audit_window`（N = `palw_audit_epoch_inclusion_window_epochs`）も同座標で強制。
> - **AUTHSET-01**: `select_auditor_committee`（SEL-01 加重サンプラー）を frozen provider-bond view 上で再導出し、`cert.auditor_set_commitment` 不一致・slate 外投票を拒否。除外集合は batch の leaf の `provider_{a,b}_bond` credential + operator group。
> - **SAMPLE-01（再定義）**: `audit_sample_root := palw_audit_sample_root({ leaf[i].receipt_da_root : i ∈ palw_deterministic_sample(prev_seed, batch_id, leaf_count, sample_size) })`。vote は**再導出 root** 上で署名検証。これは valid 証明書の field が持つべき内容を変える **activation-gated な意味論変更**（§5.17.6 の I-14 降格を受容）。
> - **SEL-01**: 加重サンプラーが唯一の選択器となり、producer（`mil/miner/src/audit.rs::select_audit_slate` / `derive_audit_sample_root`）が verifier と同一関数を composeするので drift 不能。
> - **座標の登録簿修正（§5.17.2 の scaffold 語法の精緻化・declared）**: 投票は DNS `ActiveBondView` ではなく PALW `ProviderBondView` に解決し、`owner_public_key` + ECON-03 `amount_sompi` で重みづけ。§5.17.2 が "bond_view = ActiveBondView" と書くのは P1-3 scaffold の名残であり、SEL-01 の除外意味論（operator-group / provider bond）が provider 登録簿を要求する以上、auditor = provider が唯一整合的。
> - **新パラメタ**: `palw_audit_sample_size`（config-not-DB、全 6 preset inert）。`palw_audit_committee_size` は既存。活性化 preset での非ゼロは `palw_activated_presets_bound_the_view` で強制。
> - **不変条件維持**: `LATEST_DB_VERSION` = 11 不動（永続 format 不触）、`palw_algo4_accept` = false 全 6 preset、`palw_activation_daa_score` 不変、genesis hash 不動、BODY 座標 byte 同一。**全ネットで INERT**（no certificate is enforced on a live chain）だが、re-genesis が wholesale で活性化するため live 前提で実装。
> - **SUMMARY-BIND activation blocker（2026-07-20 発見）**: `PalwAuditorVoteV1::signing_hash` は `network_id / batch_id / audit_beacon_epoch / audit_sample_root / bond / verdict / checked_leaf_bitmap_root` を束縛するが、certificate-level の `passed_leaf_count` / `rejected_leaf_bitmap_root` は束縛しない。従って同じ有効 vote 集合を別 summary に再包装でき、現 verifier は `passed_leaf_count > 0` 以外を再導出しない。現時点で両 field に production reader は無いため latent だが、**公開・有価値 network の activation blocker**とし、wire/signing rule が束縛するまで payout / slash / fraud 判定の根拠にしてはならない。operator tooling の named regression `certificate_summary_fields_are_assembler_authored_and_not_vote_bound` がこの制限を固定する。即席の wire 変更は本原子 slice に混ぜない。
>
> 以下の 5.17.1–5.17.11 は着地前の**設計固定**であり、規範として残す（着地物がこれを満たす）。「本 run では書かない/実装しない」の記述は上記により**上書き**される。

### 5.17.1 結論

**3 件を design-only として固定する。** AUTHSET-01（`auditor_set_commitment` の読み手ゼロ）・SAMPLE-01（`audit_sample_root` の非テスト読み手ゼロ）・SEL-01（抽選が bond 非加重）は、いずれも同一の欠陥形 — **証明書が宣言する値を、beacon 可視状態から consensus が再導出せず、宣言をそのまま信頼している** — の 3 つの現れである。§2.6 の欠陥クラス（規則の存在 ≠ 規則の強制）そのものであり、CERT-TRUST（§5.6.1a）が一度閉じたのと同じ class である。

**3 件は独立に着地できない**（§5.17.7 で証明）。したがって本節は、着地スライスが原子的に満たすべき完全な設計を規範として固定し、コードは 1 行も書かない。動かすのは記述のみ:

- **AUTHSET-01** は SEL-01 に依存する。commitment を再計算して照合するには**選択関数**が要るが、実在する唯一の `sample_auditors_by_score`（`consensus/core/src/palw.rs:4014`）は**未加重 per-outpoint 抽選** = SEL-01 の欠陥そのもので、その doc（`:4008-4013`）自身が「加重版が着地するまで production caller を持ってはならない」と明言する。未加重 sampler の上に commitment を強制すれば、**Sybil 分割可能な抽選を consensus に hard-fork する** — 「壊れた機構を半端に強制する方が、強制しないより悪い」という ADR 冒頭かつ task の禁則そのもの。よって AUTHSET-01 は SEL-01 の加重 sampler の上でしか着地できない。
- **SAMPLE-01** は「関数を呼ぶ verifier 側等値検査」ではない。再導出関数は**存在しない**（`auditor_set_commitment` に相当する対物が無い）うえ、sample 対象である receipt chunk は**オフチェーン DA**（`receipt_da_root` は leaf に hash されるオフチェーン artifact、`palw.rs:846-869`）で、consensus はその内容を保持せず root を再計算できない。I-14 の所持性は本質的にオフチェーンで、**オンチェーン再導出では証明不能**。健全版は §5.17.6 の**再定義**（オンチェーン per-leaf DA commitment 上の root）を要する — spec 変更である。
- **SEL-01** の資本下限側は ECON-03 で閉じた（§2.3′: `min_provider_bond_sompi != 0` + registry + sub-floor drop）。**残るのは抽選加重**であり、いまや加重に使える**解決済み担保が実在する**（旧試行時は担保が無かった。§5.17.5）。

### 5.17.2 座標 — 唯一の強制点は virtual の証明書検証

再導出を置く座標は 1 つに確定している。**`verify_certificate_attestation`（`consensus/src/processes/palw.rs:210`）** — 証明書 blob が永続化前に gate される唯一の場所であり、`apply_palw_overlay_effect` の `Certificate` arm（`PalwOverlayEffect::Certificate`、`:46`）からのみ到達し、それを駆動するのは VIRTUAL processor の acceptance walk `process_palw_acceptance`（`virtual_processor/processor.rs:1847-1854`）である。

**この座標で手中にある order-independent 入力**（全て検証対象ブロックに fork-local）:

- `network_id`（config、`palw_network_id`、`processor.rs:297`）。
- **`pov_daa_score = cert.audit_beacon_epoch * epoch_len`**（`processor.rs:1849`）— **凍結された選択スナップショット DAA**。`cur_daa` ではなく証明書自身が commit した `audit_beacon_epoch` から導出される。これが正しい point of view である: `audit_beacon_epoch` は各 vote の `signing_hash`（`palw.rs:1157-1162`）に覆われるため、vote 収集後に狙い直せない。legs 4/5 が使う「verifier は current でなく凍結スナップショットを読む」規律と同一。
- **`bond_view = selected_parent の ActiveBondView`**（DNS stake bonds）— `active_bond_at(outpoint, pov_daa_score)`、すなわち監査スナップショット時点で凍結した eligibility。ActiveBondView の apply/revert が厳密な逆写像（`dns_finality.rs`）なので、任意の reorg 経路で同一ブロックへ到達した 2 ノードは同一 view を持つ = order-independent。
- quorum num/den（config、`palw_audit_quorum_num/den`、`params.rs:449-450`、2/3）。

### 5.17.3 欠けている入力 — 監査エポックの beacon SEED（load-bearing）

`sample_auditors_by_score` / `auditor_score`（`palw.rs:3986`）は `prev_seed = R_{audit_beacon_epoch-1}` を要求するが、**これは ctx に無い**。order-independent な seed の唯一の出所は**ブロック鍵付き `header.palw_beacon_seed`**（Header v3、既に P2P/RPC 搬送済み）であって、**エポック鍵付きの `accum` store ではない** — 後者は side branch が先に処理されると R_E を汚染する（`processor.rs:1824-1833` が R_E について明示的に読み取りを禁じている。読めば split）。

**確立済みの order-independent パターンが既に在庫**: `resolve_palw_buried_epoch_seeds`（`consensus/src/processes/palw.rs:899`）は SELECTED-PARENT chain を `reachability.default_backward_chain_iterator`（`:910`）で下り、各 buried header の `palw_beacon_seed` を読む — 「(headers, reachability) 上の過去の純関数、virtual/beacon-store 読みなし」。virtual processor は `headers_store`（`processor.rs:201`）+ `reachability_service`（`:341`）+ `palw_epoch_length_daa`（`:284`）+ `palw_network_id`（`:297`）を持つので、同型の buried walk がこの座標で構成できる。

**ORDER-INDEPENDENCE 証明。** walk は固定ブロックの selected parent から開始し、その at/below の header のみを読む。証明書制約（`validate_certificate`、`palw.rs:2895`: `audit_beacon_epoch <= certificate_epoch < activation_epoch < expiry_epoch`、および `admission_valid` の有界窓）により `audit_beacon_epoch` は inclusion から有界かつ埋没可能な距離に留まるので、seed header は確定した selected-chain 履歴であり、当該ブロックを検証する全ノードが同一に解決する。

**FRAGILITY（実装時の明示規則。暗黙にしてはならない）。** `audit_beacon_epoch` が pruned、または header が pre-activation / zero-seed の場合、walk は fail-open する — このとき検証は **FAIL-CLOSED（証明書を拒否）** でなければならない。それが健全であるためには、**「証明書は自身の監査エポックから N エポック以内に inclusion されねばならない」という有界規則を追加**し、正当な証明書が stranded しないことを保証する必要がある。**この規則はまだ存在しない**（追加は着地スライスの一部）。

### 5.17.4 AUTHSET-01 の目標仕様

1. `prev_seed = R_{audit_beacon_epoch-1}` を §5.17.3 の buried walk で解決。解決不能なら fail-closed。
2. `candidates` = `bond_view` の全 bond のうち `active_bond_at(pov_daa_score)` を満たすもの、MINUS 除外集合。除外集合（設計 §10.2「登録中の provider と関連 bond は scoring 前に caller が除外」、`palw.rs:3985`）は batch のオンチェーン leaf から導出する: `cert.batch_id` の各 leaf の `provider_a_bond` / `provider_b_bond`（leaf store）+ operator-group 兄弟。これは新規 plumbing（leaf 列挙 + provider-bond cross-reference）。
3. `slate = <加重サンプラー>(prev_seed, batch_id, candidates, committee_size)`。`cert.auditor_set_commitment == auditor_set_commitment(slate)`（`palw.rs:4038`。内部で sort するので order-independent）を要求。加えて **votes の bond 集合 ⊆ slate**（さもなくば選出委員会の外から票が来る）。
4. **欠けている config**: auditor 委員会の**サイズ**パラメタが無い（quorum num/den しか無い、`params.rs:449`）。**`palw_audit_committee_size` パラメタが必要。**

**決定的な entanglement**: step 3 は選択関数を要するが、唯一の実在物 `sample_auditors_by_score` は未加重（SEL-01）で、その doc が production caller の取得を禁じている。よって **AUTHSET-01 は SEL-01 の加重サンプラーの上でしか着地できない** — activation-blocking（gate G7/G15、P2-7）であり、単独の verifier 変更ではない。既存 doc は既に正直である（`auditor_set_commitment` `palw.rs:4036`「Inert... until the audit slice enforces the binding」、`verify_certificate_attestation` の "Honest scope limit" `palw.rs:199-205`）。直すべき doc regression は無く、gap は enforcement 自身であって activation-class。

### 5.17.5 SEL-01 の目標仕様 — credential 単位 bond 加重・非復元抽選

閉じたのは資本下限のみ（§2.3′）。残余は抽選加重。**ECON-03 が値ロック + registry（prefix 241）+ sub-floor drop を着地させたので、加重に使える解決済み担保が実在する** — 旧試行が blocked だった理由（担保が consensus state に無い）は消えた。目標:

- `auditor_score`（per-outpoint hash 順、`palw.rs:3986`）と `provider_index`（一様、`:3949`）を、**credential 単位に集約した bond stake で加重した非復元抽選**へ置換する。credential 単位集約が SEL-01 の直接修正である（§4.1: outpoint 単位 = 100 分割で抽選券 100 枚 → credential 単位 = 分割しても総 stake 不変）。
- 除外条件（§4.1）: A 自身の credential / 同一 delegation root / unbonding 中 / conformance 期限切れ / 過去の選択 B / bond 未熟成。
- **G13（`Activation`）** が SEL-01 + SLASH-01 を負う。加重は order-independent な `bond_view`（§5.17.2）上で行うので座標は AUTHSET-01 と共有する。

### 5.17.6 SAMPLE-01 の目標仕様 — なぜ単純な等値検査でないか

1. **`audit_sample_root` の再導出関数はツリーに存在しない**（grep 確認: 非テスト読み手ゼロ、かつ再導出の producer もゼロ）。AUTHSET-01 と違い、呼ぶべき `auditor_set_commitment` 相当が無い。ゼロから設計する必要がある。
2. **根本的なデータ可用性 blocker**: `audit_sample_root` は「auditor が fetch した beacon 選出 receipt CHUNK」に commit する意図（`palw.rs:65-67`、`:1141`）だが、receipt body はオフチェーン receipt DA（`ReplicaExecutionReceiptV1` / `receipt_da_root` は leaf に hash されるオフチェーン artifact、`palw.rs:846-869`, `948`）に住む。**consensus は chunk 内容を保持せず、その上の root を再計算できない。** I-14 の所持性は本質的にオフチェーンで、consensus 再導出は「auditor がオフチェーンバイトを fetch した」ことを証明できない。
3. **健全な consensus 側再導出の最強形は REDEFINITION である**: `audit_sample_root := merkle_root({ leaf[i].receipt_da_root : i ∈ beacon_selected_indices })`、ここで `beacon_selected_indices = deterministic_sample(prev_seed, batch_id, leaf_count, sample_size)` を**オンチェーン leaf commitment 上で**取る。これは「証明書は beacon 選出 leaf の receipt-DA commitment に厳密に commit する」を束縛する — I-14 所持性より弱いが**強制可能**な性質。要件: (a) 監査エポック seed（AUTHSET-01 と同じ buried-walk blocker）、(b) 新規サンプリング関数、(c) 新規 sample-size パラメタ、(d) batch の全 leaf 読み（新規 plumbing）、(e) **この再定義が受容可能という spec 判断**（valid 証明書の field が持つべき内容を変える = activation-gated な意味論変更）。
4. vote `signing_hash` を **再導出した root** に対して検査する（`cert.audit_sample_root` ではなく）。現状 `verify_certificate_attestation` は `cert.audit_sample_root` の上に署名する（`palw.rs:218`）。再導出後は digest が再導出値を使い、`cert.audit_sample_root != rederived` を拒否する。

**結論: SAMPLE-01 は「関数は在り、verifier 側変更」として着地不能。** 新規導出 + spec 級再定義（オフチェーン内容は到達不能）+ seed 基盤 + 新規パラメタを要する。activation-blocking（gate P2-7）。現行 doc（`palw.rs:1141-1156`）は既に訂正済み（非直説法）だが、`palw.rs:65-67` の const doc に**同型の直説法が残っていた**（P0-2 が見落とし。本 run で訂正、§5.17.9）。機構自体は未実装のままで、doc は未実装と言い続けねばならない。

### 5.17.7 なぜ 3 件は原子的にしか着地できないか（規範）

`rederive-only`（AUTHSET/SAMPLE の再導出だけ足す）は検査で崩壊する:

1. **AUTHSET-01 は SEL-01 非独立**（§5.17.4）。commitment を強制するには sampler が要り、唯一の実在物は Sybil 分割可能な未加重抽選で、その doc が production caller を禁じる。その上に commitment を強制 = 壊れた選択を consensus に hard-fork = 「半端に強制する方が悪い」禁則。ゆえに AUTHSET-01 は rederive-only に入れられず、SEL-01 が先。
2. **SAMPLE-01 は「既存関数の等値検査」でない**（§5.17.6）。導出関数が無く、対象 chunk はオフチェーン DA で consensus は root を再計算不能。健全版は再定義 + spec 判断 + 新パラメタ + seed 基盤。
3. **両再導出 + SEL-01 の加重選択は、座標に未配線の共通前提を共有する** — 監査エポック beacon seed の order-independent 解決（§5.17.3）。実現可能（buried walk パターン + virtual の headers/reachability）だが新規 plumbing であり、pruning fail-closed edge が有界 inclusion 窓規則を要求する。

3 件が entangle（AUTHSET は SEL の sampler を要し、両者は seed 基盤を要し、SAMPLE はその上に spec 再定義を要する）するため、all-three 未満のいかなる pass も、壊れた機構を enshrine（未加重 sampler 上の AUTHSET）するか、自己申告値を信頼（健全な再導出なしの SAMPLE）する — 両方 CERT-TRUST class。**保守的で正しい判断は design-only**: 3 件を精密に仕様化し、doc を正直に保ち（既に非直説法で gap を flag 済み）、AUTHSET-01/SAMPLE-01/SEL-01 を既存 `palw_activation_daa_score` fence の背後の activation-blocking gate として起票し、専用 activation スライスに **seed resolver + 加重 credential 集約サンプラー + `audit_sample_root` 再定義 + committee/sample-size パラメタ** を、commitment/root 検査および producer（`mil/miner/src/audit.rs`）と**原子的・lockstep で**着地させる。本 pass はコードを 1 行も着地させない。

### 5.17.8 format 影響 — 再導出/verifier ロジックはゼロ、パラメタは config-not-DB

証明書 wire 型 `PalwBatchCertificateV1` は既に `auditor_set_commitment` / `audit_sample_root` / `audit_beacon_epoch` / `approving_stake` / `votes`（`palw.rs:1292-1314`）を運ぶ — enforcement は**これらを読むだけで field を足さない**。seed は `header.palw_beacon_seed`（Header v3、既に P2P/RPC 搬送）。bond view（`ActiveBondView` / `ProviderBondView`）と leaf store は既存・既永続。よって再導出検査は**永続 format に一切触れない**: `LATEST_DB_VERSION` は **11 のまま**、pin 移動なし、daemon arm なし、genesis hash 不動、`write_header_preimage` 不触、BODY 座標 byte 同一。新規 config パラメタ（`palw_audit_committee_size` / `palw_audit_sample_size`）は **config であって DB でなく**、全 6 preset で inert 出荷。SAMPLE-01 の `audit_sample_root` 再定義は証明書**意味論**を変えるが DB/wire format は変えず、activation の背後に gate される（format cutover ではない）。format を動かす唯一の可能性は eligible-set 除外が新規永続 index を要する場合だが、**要さない**（leaf は既に store 済み）。**着地担当者は version/pin/daemon の三点組に触れてはならず、`palw_algo4_accept=false` を全 6 preset で、`palw_activation_daa_score` を不変に保つこと** — 全 enforcement は既存 fence 背後の activation-class であり、新 runtime-mutable fence は決して作らない。

### 5.17.9 本 run で実施した唯一のコード変更 — SAMPLE-01 の残存直説法 doc の訂正

P0-2 は `palw.rs:1011`（現 `:1141-1156`）と 3 箇所を非直説法へ訂正したが、**`palw.rs:65-67` の `PALW_AUDITOR_VOTE_DOMAIN` doc に同型の直説法が残っていた** — 「vote 署名が beacon 選出 `audit_sample_root` を覆うので、証明書は receipt chunk を fetch せずに署名できない」。これは SAMPLE-01 の欠陥そのもの（未配線機構を直説法で主張）であり、task RULES（「未配線機構を present tense で書かない」「自己申告値は再導出するか信頼を明示 open gate とする」）の直接違反。本 run で非直説法へ訂正した（§5.17.6 と一貫）。**これは comment のみの変更**で、`LATEST_DB_VERSION` / pin / genesis / BODY 座標いずれも不動。

### 5.17.10 着地スライスが要求する最小テスト集合（設計。本 run では書かない）

- 誤った `auditor_set_commitment` を宣言する証明書が**拒否**される（AUTHSET-01）。
- 任意の（再導出でない）sample の上に署名された vote が**拒否**される（SAMPLE-01）。
- 正直な再導出パスは依然**検証成功**する。
- 再導出が**order-independent**（ブロックへの reorg 経路に依らず同一結果）— buried seed walk と bond view の両方について。
- credential 単位集約により **bond 分割 Sybil が抽選券を増やさない**（SEL-01、G13 の cross-crate E2E `producer_built_certificate_round_trips_through_verify_certificate_attestation` に fold）。

### 5.17.11 次の設計ステップ（load-bearing decision）

producer/verifier に先立って決めるべきは 2 点: (1) **`audit_sample_root` を §5.17.6 のオンチェーン再定義で置くという spec 判断**（I-14 のオフチェーン所持性を、オンチェーン DA-commitment 被覆という弱いが強制可能な性質へ降格することの受容）。(2) **有界 inclusion 窓規則**（§5.17.3 の pruning fail-closed が正当な証明書を stranding しないための N エポック上限）。この 2 判断が下るまで、seed resolver・加重サンプラー・再定義・パラメタは原子スライスとして着地できない。**`palw_algo4_accept` は全 preset で `false` のまま。本節は activation lever に一切触れない。**

---

## 5.10 §OWN — runtime ↔ node 所有権表（**FROZEN 2026-07-20**）

外部 `runtime-palw` のレシートを node に統合する際、**写す前にどちらの規約が原本かを凍結する。** 順序を逆にすると、写した瞬間に不整合が固定される。

| 規約 | 原本 | 帰結 |
|---|---|---|
| 署名方式・鍵体系 | **node**（ML-DSA-87 のみ） | runtime の Ed25519 経路は排除 |
| ハッシュ関数・幅・keying | **node**（keyed BLAKE2b-512 / Hash64） | 合意が再計算する全値が対象 |
| 射影・match 述語 | **node**（§4.3 exact-match 集合） | `runtime_class_id` は非合意 telemetry |
| 署名コンテキスト台帳 | **node** の `signature_domains.rs` | Receipt v3 行は core const と byte equality test で固定 |
| Receipt v3 hash-domain / wire / 正準直列化 | **node** の `mil/palw/src/receipt_v3.rs` | fixed-width・宣言順・LE。runtime は golden vector で byte 一致させる |
| 実行内容（trace 語彙・各 root の生成規則） | **runtime** | node 所有の Receipt v3 フィールドへ格納し、署名対象 wire は変更しない |

**所有権の一本化が肝である。** 署名コンテキストの registry と Receipt v3 hash-domain 定数は用途が異なるためファイルは分かれるが、どちらも node が原本であり runtime は独自規約を持たない。Receipt v3 は可変長 field framing ではなく fixed-width canonical body と domain-keyed hash を採用する。node fixture と runtime production encoder を同じ golden vector へ通す cross-repository test が drift を検出する。

**2026-07-20 実装 status:** `mil/palw/src/receipt_v3.rs` が body/projection/pair/output/nullifier の正準 bytes と hash-domain、ML-DSA-87 verification を所有する。`consensus/core/src/palw.rs` と `signature_domains.rs` は Receipt v3 署名コンテキストを登録し、`consensus/tests/receipt_v3_domain_alignment.rs` が byte equality を固定する。外部 `runtime-palw` は同じ固定長 LE encoder、credential binding、execution nullifier、output commitment、署名コンテキストを production CLI まで使用し、node fixture の canonical body/digest/pair-id と一致する。

### 衝突 1（署名）— ML-DSA-87、鍵は credential

mint に効く経路（receipt / leaf / vote）の署名は全て ML-DSA-87、**署名鍵 = 登録 credential 鍵**を v1 とする。delegation（credential が署名したセッション鍵）は運用要求が出てから導入し、その場合も**セッション鍵は 87 のまま**（パラメタセットを 2 つにしない）。

runtime の Ed25519 は EVM が secp256k1 に対して行ったのと同じ手筋 — **feature-gate で「provably-Ed25519-free な mint 経路バイナリ」**にする。既存 final-v7 系レシートは移行せず破棄。新規署名対象は `PENDING_SIGNATURE_DOMAINS` から正式行へ昇格させる（既存 const の流用禁止は据え置き）。

### 衝突 2（ハッシュ）— Hash64 keyed BLAKE2b-512 を全面採用

判定基準は「**合意側の誰かが再計算する値か**」。`output_commitment` / checkpoint・execution root / route root / state root / schedule commitment は全て該当し、端から端まで同一関数でなければ再計算照合が成立しない。Receipt v3 自体が再計算する projection/body/id/nullifier/output/pair は `mil/palw/src/receipt_v3.rs` の byte-domain const を原本とし、fixed-width preimage で曖昧性を排除する。runtime 固有 root の内部 domain は node-owned Receipt v3 wire とは分離して管理する。

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
| P1-5 | ~~**accepted** PALW effect のみで batch view を構築~~ → **座標移動は不可（BIND-03、§5.12）**。代わりに fold の達成範囲を有界化する: 無制限 `job_nullifiers` を**削除**し、`max_view_batches` を実在の整合性検査で強制する | DOS-02, VIEW-01 |
| P1-6 | block authorization の**実装**（型・`signing_hash`・subnetwork 転送・検証節）。`eligibility_hash` に header commitment を bind | **AUTH-01/02/03** |
| P1-7 | target interval を header 申告ではなく **consensus 導出**へ | TGT-01 |
| P1-8 | algo-4 header anti-spam。**再分類済み（§5.13）: T-shared 級ではなく activation 級。**方向は確定 — **Option C（GHOSTDAG のみから計算する lane 別 rate limit）を主案、Option B（header 段 compact ticket witness、`leaf_hash` の不可用性ゆえ単独では不足）を補完、Option A（full-block 受信を header 受理の条件にする）は IBD 再設計かつ P1-5 と同型の順序依存につき棄却**。§16 lane DAA と同時設計すること | **DOS-01** |
| P1-9 | job nullifier の **global consensus state** による重複拒否 → **body 座標から撤回（SPEC CHANGE）**。**P1-9-RELAND** として reward/virtual 座標 + ML-DSA 署名認可を要件とする activation 級 gate へ再登録（§5.12） | PCPB-01 |
| P1-10 | PCPB を pure helper から ticket validation へ接続。leaf に challenge / A_commit / snapshot root / assignment proof を追加。**部分（2026-07-20、§5.14.6）**: §5.14.3 **項目 7 のみ**着地（`leaf.registered_epoch == manifest.registration_epoch` を acceptance 座標で強制 + producer 鏡像）。**PCPB 本体は未着手** — 3 helper は今も production caller ゼロ、leaf に PCPB field ゼロ、`PalwDispatchProof` は宣言 `bool` のまま | PCPB-01 |
| P1-11 | view の batch 数上限、`activation_not_before_epoch` 上限、bitmap 境界、`min_samples` 前提の強制 | DOS-03/04, AO-02/03 |
| P1-12 | header shape 規則（活性化後の algo-3 header の PALW field ゼロ強制） | SHAPE-01 |
| **P1-14** | **DONE — 残余 Medium/Low、6件を6件として個別に解決（catch-all にしない）。** 各項目の理由と到達点は §5.6 の該当行に記載。要約: **ECON-02** = `palw_algo4_accept` で fence した cap 拡大（`k+2` → `3(k+1)+1`）。fence は必須（cap 緩和の無 fence 出荷 = live fork）。§E/§D tail の既存 cliff は PALW 非依存の**別件として明示的に残し**、テストで pin。**ECON-04** = `provider_pair_split` **削除**（呼び出し元ゼロの spec drift。統一ではなく削除 — 真実源を1つにする）。テストは production 合成を pin するよう書き換え。**SS-04** = `is_block_eligible_at` / `resolvable_batch` / `retain` を DAA 対応にし §9.5 非遡及を実装。`retain` も含めるのは、gate だけでは**未来日付 revocation が eviction 経由で遡及性を再導入**するため。**SS-05** = **第2の腕（HOLD 源の明示）で closed、コード変更なし**。writer は activation scope、store は prefix 245 予約済みで削除しない。**TGT-02 + TGT-03** = **削除**（1箇所なので行を統合）。配線は既知の壊れた規則の再導入。interval の真の出所は clause 5 の `daa_score` pin | ECON-02/04, SS-04/05, TGT-02/03 |
| **P1-6** AUTH-01/02/03 | **DONE** — T-shared の最大障壁。`PalwBlockAuthorizationV1` に `signing_hash` / preimage commitment / `binds_header` / `binds_leaf_authority` を実装、subnetwork `0x38` で block body 搬送、body 検証 clause 7 で強制。leaf の `ticket_authority_pk_hash` を `PalwResolvedBinding` へ射影（AUTH-03: 読み手ゼロだった）。詳細は §5.11 | AUTH-01/02/03 |
| **P1-2** LEAF-01 | **DONE**（スナップショット不要と判明）: P1-1 の write-once により `(batch_id, leaf_index)` のバイト列が受理後に変化しないため、報酬時の再読込は body 検証が証明した内容を必ず返す。スナップショットは既に不変なデータの複製になる。加えて clause 9 が `leaf_hash` を hash するので、同一キーの別 leaf はそもそも draw を満たさない |
| **P1-11** AO-02/03, DOS-03 | **DONE**: `chunk_count ≤ PALW_CHUNK_BITMAP_BITS` を admission で構造的に強制（AO-02）/ `min_samples >= 1` を lane params の validity へ（AO-03、文書化された前提を実際の前提に）/ `max_view_batches` cap（DOS-03、**上限で admission 拒否・既存 batch の追い出しはしない** — 追い出すと資源境界が検閲手段になる） |
| **P1-12** SHAPE-01 | **DONE**: 活性化*後*の algo-3 header に ticket field ゼロを強制。従来は活性化*前*のみで、後半は無制約だった（v3 preimage に入るため header malleability） |
| **P1-5** DOS-02 | **DONE（削除で閉じた）**: `PalwBatchViewV1.job_nullifiers` と `claim_job_nullifier` / `job_nullifier_spent` を**削除**。fold の LeafChunk arm は `view.apply_leaf_chunk(&c.batch_id, c.chunk_index);` 1 行。強制上界は `|job_nullifiers| = 0`、view 全体は `max_view_batches` のみ。`PalwBatchAdmissionParams::is_consistent_for_activation()` を新設し全 preset で強制。`LATEST_DB_VERSION` 8 → 9 | DOS-02 |
| ~~P1-9~~ | **撤回（SPEC CHANGE）**: 旧「`PalwBatchViewV1.job_nullifiers` を新設し leaf chunk 適用時に claim」は**一度も強制されていなかった**（bool は dead な `continue`、`job_nullifier_spent` は読み手ゼロ）。この座標では認可できず、armed にすると正直な batch を 1 tx で brick する。**P1-9-RELAND** へ（§5.12） | PCPB-01 |
| P1-15 | **DONE**（class レジストリ / SC-08）: `resolve_compute_set` → `PalwSetResolution{Active,NotGoverning,Unregistered}`。**未登録は fallback ではなくゼロ**（fail-closed）。旧 `resolve_compute_work_scale` は `#[deprecated]` 化し、hazard をテストで pin | SC-08 |
| P1-13 | **PALW overlay state の pruning-point / trusted-block import 経路を新設**（`PalwPrunedFrontier` の writer/reader、pruned/trusted IBD 時の leaf・view 再構成）。**回帰テストではなく新規実装であるため G7 に畳まない**（§7.2 の注記） | BIND-04, SS-01 |

> **P1 の集計（§5.6 と同一・二重管理しないための唯一の再掲点）。** 完了 9（P1-1 / P1-2 / P1-3 / **P1-5** / P1-6 / P1-11 / P1-12 / P1-14 / P1-15）、部分 2（P1-4 / P1-13）、棄却 1（P1-7）、**撤回 1（P1-9 — SPEC CHANGE、P1-9-RELAND へ）**、未着手 2（P1-8 / P1-10）+ 新規 activation 級 1（**P1-9-RELAND**）。**§11 の判定は項目数では動かない。**
>
> **P1 に含まれない付随作業**: PALW overlay 永続化型の encoding 変更に伴う `LATEST_DB_VERSION` **7 → 8**、および P1-5 の `job_nullifiers` 削除に伴う **8 → 9** の bump（§7.2 の註）。これはゲートでも整合性修正でもなく、activation 時に一度だけ通る不可逆な format cutover である。

### P2 — 参加者集合と監査

| # | 内容 | 対応所見 |
|---|---|---|
| P2-1 | 単一 provider registry。**credential 単位の bond 集約**と bond 加重非復元抽選。**設計固定: §5.17.5（DESIGN-ONLY）** — 資本下限は ECON-03 で CLOSED、残る加重を order-independent `bond_view` 上で | SEL-01 |
| P2-2 | 最低 bond / 成熟窓 / unbonding / conformance 期限の実装 | SEL-01, ECON-03 |
| P2-3 | auditor が実際に監査する（DA 取得 / PCPB 検証 / sample replay / execution root 比較 / trace opening / pool coverage / canary） | 監査 2 #6 |
| P2-4 | `audit_sample_root` を producer 任意入力ではなく **beacon + manifest + DA inventory から全ノードが再導出**。**設計固定: §5.17.6（DESIGN-ONLY）** — オフチェーン DA 内容は再計算不能ゆえ on-chain per-leaf DA-commitment 上の root へ**再定義**する spec 判断が前提 | CERT-01 |
| P2-5 | provider bond の存在・額・熟成・unbond・slash を consensus state として実装 | ECON-03 |
| P2-6 | **`receipt_da_root` の決着**: (A) DA 層が無い間は field を削除するか、(B) DA object 仕様 + `da_retention_epochs` による時間境界 + P2P request/response + 不履行を証明する challenge tx を**単一 slice として**実装する。雛形は `PalwBeaconCommitV1` の commit/reveal/期限（PALW で継続的義務が閉じている唯一の例） | DA-01 |
| P2-7 | `audit_sample_root` を beacon + manifest + committed leaf 集合から**全ノードが再導出**し、不一致 certificate を拒否。`auditor_set_commitment` の照合を追加。**設計固定: §5.17（DESIGN-ONLY）** — 座標 `verify_certificate_attestation`（virtual）/ 監査エポック seed は buried selected-parent walk で解決 / pruning は fail-closed（有界 inclusion 窓規則が前提）/ **AUTHSET-01 は SEL-01 の加重サンプラーの上でしか着地できず 3 件は原子的にのみ着地可能** | SAMPLE-01, AUTHSET-01 |

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

> **⚠️ 現状の正確な記述（2026-07-20）。以下の生成方式は _設計であって実装ではない_。**
> `consensus/core/src/palw_gates.rs` は**存在せず**、`PALW_ACTIVATION_GATES` const table も、下に列挙する 3 本の meta-test（`palw_gate_table_matches_adr_0040` / `every_gate_verifier_resolves` / `gate_class_lever_mapping_is_total`）も、§7.2 の `verifier` 列に並ぶ 15 個のテスト名も、**repo 内のどこにも解決しない**。
>
> したがって **§7.2 の `<!-- BEGIN GENERATED -->` ブロックは、実際には手で維持されている散文である。** 「機械検査済み」と自称しながら手編集されている状態は、本 ADR が §2.6 で消そうとした「**規則の存在と規則の強制の乖離**」そのものである。実際これが原因で、G4 の gate class 矛盾（§5.6 の訂正註を参照）が検出されずに残っていた。
>
> **この乖離を閉じる作業は本項目に畳まない。** `palw_gates.rs` + meta-test 3 本 + 15 個の verifier を実在させるのは独立したスライスであり、半端に入れることは本 ADR が繰り返し警告している失敗形である。**そのスライスが着地するまで、§7.2 は手編集可・ただし編集のたびに §2 / §6 と人手で突合すること**とする。着地後にこの註を削除する。

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

以下は const table からの生成ブロック**となる予定**の領域である。**§7.1 の註のとおり、現時点では生成器も const table も存在せず、手で維持されている。** marker は将来の生成器の投入点として残す。

<!-- BEGIN GENERATED: PALW_ACTIVATION_GATES -->

| ID | 種別 | 閉じる所見 | ゲート | 証拠 | verifier |
|---|---|---|---|---|---|
| **G1** | StopShip | DEMO-01, DOC-01/02 | P0-1/2 完了 + `palw_algo4_accept` が両 PALW preset で既定 false かつ false の間 algo-4 header を reject | TestSuite | `palw_algo4_rejected_while_accept_lever_closed`（`consensus/src/pipeline/virtual_processor/tests.rs`）/ `palw_activated_presets_bound_the_view`（`consensus/core/src/config/params.rs`） |
| **G2** | StopShip | ECON-01 | 任意の登録 reward script から導出した coinbase が isolation 検証を通る（property test）**かつ** 規則違反 script が admission で落ちる（拒否テスト） | TestSuite | `palw_reward_script_admission_matches_coinbase_representability`（`consensus/core/src/palw.rs`） |
| **G3** | StopShip | BIND-01, LEAF-01 | leaf が `manifest.leaf_root` に reduce することの強制、注入 leaf の拒否、**および同一 key への異内容再書き込みの拒否**（content-address + put-if-absent）。**訂正 2026-07-20（§5.15.3）: 本行の verifier は tree に存在せず、第 1 節（`leaf_root` への reduce 強制）は `palw_leaf_root` の consensus caller がゼロである以上**強制されていなかった**。実在していたのは第 2 節（write-once）= `insert_leaf` のみ。**更新 2026-07-20（§5.15 実装）: 第 1 節が実在化した** — acceptance 座標の LeafChunk arm が `insert_leaf` の前に per-leaf Merkle membership proof を検証する。**第 2 節は「outrank されたが撤去されていない」**: M2 通過 chunk は正直な chunk と byte 一致するため write-once はこの arm 経由ではほぼ到達不能になったが、検査自体は残り、専用 test で到達・発火を表明している。**G3 は code-level では閉じた。ただし live E2E 未検証。** | TestSuite | **実在する verifier 群**（この行の旧 verifier 名は tree に一度も存在しなかった phantom であり、辻褄合わせの同名 test は作らない — 以下は実在名のみ。旧 phantom 名は本行から drop 済み）: `chunk_index_squat_is_rejected_before_the_leaf_is_stored`（第 1 節・攻撃そのもの）/ `leaf_chunk_admission_binds_to_manifest_and_is_write_once` / `a_member_leaf_cannot_be_replayed_at_another_index` / `membership_proof_length_is_exact_in_both_directions` / `leaf_write_once_still_fires_after_the_membership_gate`（第 2 節が**到達され**発火することの表明）/ `reward_scripts_are_immutable_after_acceptance`（reward 帰結 + write-once の独立表明）。構成側は `palw_leaf_merkle_root_construction_golden` / `palw_leaf_merkle_root_cross_crate_golden_vector` |
| **G4** | StopShip | CERT-01 | 偽署名 / zero-stake / `num==0` / 未選出 auditor / 不整合 root の各 certificate が拒否される | TestSuite | `certificate_stake_weighted_quorum`（`consensus/core/src/palw.rs`・zero-stake / `num==0` の定足数 vacuity）/ `certificate_attestation_rederives_committee_sample_and_signatures`（`consensus/src/processes/palw.rs`・偽署名 / 未選出 auditor / 不整合 root / quorum-short / approving-stake。旧 §5.17 spec-change で `certificate_attestation_requires_real_signatures_over_active_bonded_stake` から改名） |
| **G5** | Activation | AUTH-01/02/03 | authorization の生成・転送・検証と `eligibility_hash` への header commitment bind。**当選 ticket の再鋳造不能性テスト** | TestSuite | `palw_algo4_reminted_ticket_is_rejected_auth02` / `palw_algo4_authorization_binds_every_header_field_auth02`（ともに `consensus/src/pipeline/virtual_processor/tests.rs`） |
| **G6** | Activation | DOS-01 | algo-4 header の無償受理経路が無いこと。**閾値は §10-8 で確定**（header flood 下の per-header DB write 数と p99 処理時間の上限） | Measurement | `palw_header_spam_bounded`（測定ゲート・test 未実装） |
| **G7** | Activation | TGT-01, BIND-02/03, DOS-02/03/04, VIEW-01, QUORUM-02, ECON-03, PCPB-01, SHAPE-01, SAMPLE-01, AUTHSET-01, DA-01 | **左列に列挙した所見 ID ごと**に回帰テストが存在し緑（catch-all 禁止。ID 表は const table が保持し、§2 の PROD 行と突合される） | TestSuite | `palw_prod_findings_all_covered`（`consensus/core/src/palw.rs` の `#[cfg(test)] mod tests`、const `PALW_PROD_FINDINGS`）— 全 §2 PROD 所見（25 件）を実回帰テストへ写像し、ID 集合を §2 PROD 行と厳密突合。**verifier は実在するが gate は operationally 未閉鎖**（BIND-04 / SS-01 は archival 要件で緩和のみ・consensus test 無し、DA-01 / PCPB-01 は off-chain、ECON-03 は slashing 未着手） |
| **G8** | Activation | — | 正準 artifact を**二者独立生成**し byte hash 一致。`PalwComputeSetRecordV1` を committed 状態として登録 | Measurement | `palw_artifact_reproducible`（測定ゲート・test 未実装） |
| **G9** | Activation | INT-01 | 全 K0/K1 ベクタ（**拒否ベクタ K0-R1..R5 含む**）が CPU reference と各 backend で一致。**cross-machine のため Measurement** | Measurement | `palw_conformance_vectors_match`（測定ゲート・test 未実装） |
| **G10** | Activation | MATCH-01 | pairwise cross-backend: 短 job 1,000 件・long job 100 件・最大 prefill・MoE 境界（router tie / expert merge）・recurrent 境界で**不一致ゼロ** | Measurement | `palw_cross_backend_pairwise`（測定ゲート・test 未実装） |
| **G11** | Activation | — | 72 時間 soak で不一致ゼロ | Measurement | `palw_soak_72h`（測定ゲート・test 未実装） |
| **G12** | Activation | PCPB-01 | PCPB / escrow / reroll / timeout / global nullifier の multi-node E2E | TestSuite | `palw_pcpb_e2e`（機構未実装・test 未実装） |
| **G13** | Activation | SEL-01, SLASH-01 | **実 auditor quorum** の E2E（偽造 certificate / zero-stake quorum / **credential 単位集約による bond 分割 Sybil** / auditor withhold / reorg） | TestSuite | **VerifierExists（2026-07-20 昇格）— code-verifiable なコアが着地。** `producer_built_certificate_round_trips_through_verify_certificate_attestation`（`consensus/src/processes/palw.rs`）が REAL miner quorum producer（`misaka_palw_miner::audit`）の certificate を REAL `verify_certificate_attestation` へ cross-crate で通す: 正直 accept（純 verifier + acceptance arm 両方）+ 偽署名 / slate 外 vote / 誤 `auditor_set_commitment` / 誤 `audit_sample_root` / stake-short quorum / bond 分割 の各拒否を**それぞれの error variant で**表明。補助 verifier: `certificate_attestation_rederives_committee_sample_and_signatures` / `certificate_stake_weighted_quorum`（zero-stake / `num==0` vacuity）/ `sel01_credential_aggregation_makes_bond_splitting_worthless`。**INTEGRATION-BOUND（単一プロセスで表現不能・本 gate の TestSuite 面に残る）: auditor WITHHOLD（network partition が要る）と multi-node / REORG（複数ノード + 競合チェーン）。SLASH-01（cross-fork 二重使用）も未着手。** G16 の bounded-window 注記と同じく、**verifier 実在 ≠ operationally 閉鎖**（G3 再発防止であって閉鎖ではない） |
| **G14** | WeightRaise | — | β 自動縮退機構が稼働し、観測集中度が宣言 β_max を下回る。`weight_factor_bps` は 0 から段階的にのみ上昇 | Measurement + Signoff | `palw_beta_degradation_live`（測定ゲート・test 未実装） |
| **G16** | Activation | PCPB-01（P1-9-RELAND） | **job nullifier 重複作業拒否**が **reward/virtual 座標**に、coinbase 構築が読む reward 規則として存在する（body-validity 規則としてではない）。claim は provider の ML-DSA 署名（`ReplicaExecutionReceiptV1::signing_hash`、`job_nullifier` を commit）で**認可**され、署名なき複製 nullifier は何も claim できない。**body/mergeset 座標に first-claim-wins registry が再出現していないこと**も同時に検査（§5.12）。**前提条件（§5.15.13）: `job_nullifier` は今日 consensus が何も検査しない自由 field なので、どの座標の registry も回避可能である。§5.15（ACCEPT-BIND/M2）が `job_nullifier` を `leaf_hash` → Merkle → `leaf_root` → `batch_id` に封じて初めて本 gate は意味を持つ — M2 は G16 の前提であって選択肢ではない。** **更新 2026-07-20: この前提は満たされた。** M2 実装により `job_nullifier` は `leaf_hash` の中に入り、`leaf_hash` は membership proof で `manifest.leaf_root` に開かれ、`leaf_root` は `content_id() == batch_id` の中にあるため、**格納 leaf の `job_nullifier` は不変かつ batch 束縛になった**（`PalwPublicLeafV1` は不変 = `LEAF_LEN` 796 / LEAF_FNV は動いていない）。**更新 2026-07-20（実装）: reward 座標に BOUNDED-WINDOW の重複作業拒否が着地した。G16 は依然 CLOSED ではない。**
着地物は `palw_work_reward_class`（`utxo_validation.rs:490`）の `paid_work.insert(leaf.job_nullifier)` 失敗で
`WorkRewardClass::ReplicaPalwDuplicateWork` を返す規則で、paid-set は新 block-keyed store
`PalwPaidWork`（prefix 248）を **`paid_work_walk_bound_daa` で有界な selected-chain walk** により再構成する。
P1-5 が削除した形とは 4 軸すべてで構造的に異なる（block-keyed で子へ clone されない / 支払い時のみ書かれる /
walk が有界 / 実際に読まれる）。walk は pruning point で停止し、pruning processor で回収される。

**閉じていない理由（過小評価しないこと）**: walk が有界であるため、**同一 job_nullifier を「今の batch」と
「1 年後の別 batch」に登録すると、2 つの claim は DAA 上いくらでも離れられ、どの有界 walk も両方を見ない。**
G16 行が要求する *global* な重複拒否には、有界 walk ではなく恒久的な paid-set（= P1-5 が資源上の理由で
消した形）か、別の封じ込め（例: job_nullifier を epoch に束縛する）が要る。**これは設計判断であり、
本実装の延長では閉じない。** 併せて、fold comment が言う ML-DSA 認可は — 前提が立っただけで、reward 座標の registry（`palw_work_reward_class` + `RewardedEpochSet` walk）は 1 行も書かれていない。**「前提が閉じた」を「gate が閉じた」と読まないこと。** G16 は Activation 級・別 commit のまま 併せて訂正: fold の comment が言う ML-DSA 認可は**現状のコードでは両半分とも実装不能**（`ActiveBondView` は DNS stake bond のみ、provider bond は永続化されず、receipt `signature` は wire field で decoder 無し）。着地先は `palw_work_reward_class`、paid-set は `RewardedEpochSet` walk（§5.15.13） | TestSuite | `palw_job_nullifier_reland_at_reward_coordinate` / `palw_job_nullifier_reland_dedups_across_chain_blocks`（ともに `consensus/src/pipeline/virtual_processor/tests.rs`）/ `no_job_nullifier_registry_at_the_body_coordinate`（`consensus/src/processes/palw.rs`）。表中の `job_nullifier` / `leaf_hash` / `leaf_root` は field 名であって verifier ではない |
| **G15** | Activation | DA-01, PMC-01 | **強制点走査（§2.6）が gap ゼロ**: 全 hash-committed オブジェクトについて、preimage の性質を主張する規則には合意視野内の強制点が存在する。**初回走査済み — 現在 gap 2 件**（DA-01 / PMC-01。**SAMPLE-01 / AUTHSET-01 は §5.17 CERT-REDERIVE で強制点を獲得**し gap から外れた、BIND-01 は P1-1、AUTH-01 は §5.11 で閉鎖。§2.6.1） | TestSuite | `palw_enforcement_points_total`（`consensus/core/src/palw.rs` の `#[cfg(test)] mod tests`、const `PALW_ENFORCEMENT_POINTS`）— 全 Enforced 点の fn 実在を照合し、gap を厳密 2 件（DA-01 / PMC-01、ともに GapOffchain）に pin。**gate は gap > 0 のため operationally 未閉鎖**（verifier 実在は G3 再発防止であって閉鎖ではない） |

<!-- END GENERATED -->

> **この verifier 列の健全性は機械検査される（G3 事故の再発防止）。** `kaspa-consensus-core` の
> `palw_gate_table_verifiers_all_resolve`（`consensus/core/src/palw.rs` の `#[cfg(test)] mod tests`、
> const `PALW_GATE_VERIFIERS` を保持）が本表の全 verifier を workspace 内の実 `fn <name>` に照合する:
> VerifierExists ゲート（G1 / G2 / G3 / G4 / G5 / **G7 / G13 / G15** / G16）は名指しした test が実在しなければ
> build が落ち（まさに G3 に欠けていた検査）、Measurement / Unimplemented ゲート（G6 / G8-G12 / G14 の該当行）は
> 逆に「未実装」と記した test が実在してはならない — 実在したら status を上げよ、という nudge として fail する。
> **G7 / G15 は 2026-07-20 に Unimplemented → VerifierExists へ昇格した**（それぞれ meta-test
> `palw_prod_findings_all_covered` / `palw_enforcement_points_total` が着地）。**同日 G13 も昇格した** —
> cross-crate の auditor-quorum E2E `producer_built_certificate_round_trips_through_verify_certificate_attestation`
> が着地し、残るは WITHHOLD / REORG / SLASH-01 の integration 面のみ。verifier 実在 ≠ gate 閉鎖（G16 と同様、
> いずれも operationally 未閉鎖のまま）。**本表の verifier 名はこの const registry と一致していなければならず、
> registry が source of truth である。**

> **G7 と ECON-03（2026-07-20 ECON-03 THE WIRE 実装後の訂正）。** G7 行が ECON-03 を列挙している以上、この
> gate は「ECON-03 の回帰テストが存在し緑であること」を要求する。**部分的に満たされた**: §2.3′ の CLOSED 表に
> 挙げた 6 本（`econ03_funded_provider_bond_tx_enters_the_registry` / `palw_algo4_unbacked_provider_bond_pays_nothing_e2e`
> / `palw_unbacked_collateral_sources_pay_nothing` / `econ03_only_active_bonds_resolve_as_collateral` /
> `econ03_registry_walk_is_reorg_path_independent` / `econ03_view_apply_and_revert_are_exact_inverses`）が
> 実在し緑である。**しかし G7 は閉じない。** 理由は 2 つあり、いずれも丸め上げてはならない:
>
> 1. **ECON-03 自体が閉じていない。** spend gate（leg 4）と CRITICAL-1（所有束縛）は実装・緑になったが、**slashing producer が依然として無い**（§2.3′ の OPEN 3 項の筆頭）。担保は拘束・所有されたが**没収できない**。
>    回帰テストが揃うのは所見が閉じた後であって、部分実装の段階で「ID ごとの回帰テストがある」と読むのは誤りである。
> 2. **訂正（2026-07-20）: verifier `palw_prod_findings_all_covered` は着地した。** かつて本項は「本 tree に
>    存在しない phantom」と記していたが、いまや `consensus/core/src/palw.rs` の `#[cfg(test)] mod tests` に
>    実在し（const `PALW_PROD_FINDINGS` + meta-test）、全 §2 PROD 所見（25 件）を実回帰テストへ写像し ID 集合を
>    §2 と厳密突合する。G3 でそうしたように実在 verifier 群へ差し替えた（辻褄合わせの同名 test は作っていない）。
>    **ただし verifier 実在は gate 閉鎖を意味しない**: G7 は上記 1（ECON-03 slashing 未着手）に加え、BIND-04 /
>    SS-01（archival 要件で緩和のみ・consensus 側 pruned-IBD import 未実装 → const で `Unimplemented`）・DA-01 /
>    PCPB-01（off-chain → `Unimplemented`）が未閉鎖のため、operationally 未閉鎖のままである。meta-test が保証
>    するのは「PROD 所見ごとに honest な coverage 状態が登録され、`Covered` の test 名が実在し、新 PROD 行の
>    無登録追加が build を落とす」ことであって、全所見の閉鎖ではない。**§2.6 の強制点走査（G15、
>    `palw_enforcement_points_total`）も同時に着地した。**

> **G13 と ECON-03（同上）。** G13 は SEL-01 + SLASH-01 を負う。ECON-03 の実装は G13 を**前進させたが閉じていない**:
>
> - **前進**: SEL-01 のうち **「最低 bond が無い（`amount_sompi != 0` のみ）ため bond 分割が無償」**の半分は閉じた。
>   sub-floor bond は registry に入らず（`palw_provider_bond_mutations_from_accepted_txs` の drop）、`Active` に
>   解決せず、報酬を裏付けない。非空性は `is_consistent_for_activation` が全 activated preset に対して強制する。
>   `econ03_funded_provider_bond_tx_enters_the_registry` が store 上でこれを表明する。
> - **未着手（G13 を止めている本体）**: 抽選そのものは依然 **bond 加重でない** — `auditor_score` は outpoint 単位
>   ハッシュ順、`provider_index` は一様のままで、resolved collateral を読んでいない。資本下限は分割の**費用**を
>   上げるだけで、**加重**の代わりにはならない。
> - **SLASH-01 は 1 mm も動いていない。** `PalwProviderBondMutation::Slash` に **producer が存在しない**
>   （mutation builder は `Insert` と `Unbond` しか emit しない）。bond は解決できるが没収できない。
>   **§5.16（DESIGN-ONLY）で原因を確定した**: producer が書けないのは、equivocating authority を
>   slashable bond に束縛する **LINK がデータに無い**ため（evidence は `authority_public_key` しか運ばず、
>   leaf の keyed `ticket_authority_pk_hash` は bond の unkeyed `owner_pubkey_hash` と equate 不能、
>   authority を bond に束縛する規則も store も無い）。DNS 先例（`SlashingEvidencePayload.bond_outpoint` が
>   署名オブジェクト内で bond を名指す）との決定的な差である。閉鎖は leaf acceptance semantics を変える
>   re-genesis 級の binding 決定（§5.16.9）を要し、producer/verifier はその後にしか書けない。
>   併せて `SUBNETWORK_ID_PALW_SLASHING = 0x34` は dangling mislabel（0x34 は Revocation に decode される）で、
>   slashing は新 byte 0x39 へ載せる re-genesis 変更になる（§5.16.3）。
>   G13 行が要求する E2E のうち **code-verifiable なコアは 2026-07-20 に着地した**（cross-crate verifier
>   `producer_built_certificate_round_trips_through_verify_certificate_attestation`: 偽造 certificate / zero-stake quorum /
>   bond 分割 Sybil / slate 外 vote / stake-short は表明済み）。**残る WITHHOLD / REORG は integration-bound、
>   SLASH-01 は上記のとおり未着手** — つまり verifier は VerifierExists へ昇格したが、G13 は operationally 未閉鎖のままである。

> **BIND-04 / SS-01（pruned-IBD 経路）は G7 の列挙に含めず、§6 P1-13 で独立に扱う。** これらは「テストを足す」ではなく「存在しない import 経路を作る」課題であり、回帰テストゲートに畳むと実装が不可視化される。

> **G4 と G13 の境界（§5.6 の訂正註と対）。** **G4 は `StopShip` が正であり、変更しない。** G4 行に書かれた「未選出 auditor の拒否」は auditor 選出機構（SEL-01）に依存するため、実質の負荷は **G13（`Activation`）** 側にある。読み分けは次のとおり:
> - **G4** = 宣言された auditor 集合に対する **attestation 検証**（ML-DSA-87 署名 / bond active / bond 重複 / stake 加重 quorum / `num==0` / 不整合 root）。§5.6 P1-3 で実装済み。
> - **G13** = その集合が **beacon 選出であり bond 加重である**こと（SEL-01）+ cross-fork 二重使用 slashing（SLASH-01）。SEL-01 の再導出 + certificate quorum の cross-crate E2E は着地（VerifierExists）; SLASH-01 と WITHHOLD / REORG は未着手。
>
> `accept` lever は全 `StopShip` + 全 `Activation` を要求するため、この読み分けは accept 条件を動かさない。動くのは `land` lever の条件である。

> **`LATEST_DB_VERSION` 7 → 8 → 9 の format cutover（ゲート表の外にあるが activation 手順の一部）。** PALW overlay state の永続化型（`PalwBatchLifecycleV1` / `PalwBatchViewV1` / 証明書 / `PalwBeaconEpochAccumV1`）の encoding 変更に伴い **7 → 8**、続いて P1-5 が `PalwBatchViewV1.job_nullifiers` を**削除**したことに伴い **8 → 9** へ bump 済みである（削除も positional encoding を壊す）。`kaspad/src/daemon.rs` の hard-reset arm も `version <= 8` へ同時更新済み — bump 単独は loop の末尾 `assert_eq!` を踏むため無変更より悪い。**コストの範囲を誤って狭く書いていたので訂正する（2026-07-20）。** `LATEST_DB_VERSION` は
> ネットワーク別ではなく**単一のグローバル定数**であり、`should_upgrade()` は preset を見ない。したがって
> hard reset は PALW preset の運用者に限らず、**この版へ in-place 更新する全ノード（mainnet / testnet-10 /
> devnet / simnet を含む）が対象**である。PALW 行を 1 件も持たないノードも再同期を要求される。
> live な PALW ネットワークが存在しないことは、PALW *データ*が失われないという意味であって、
> 再同期が要らないという意味ではない。この差はリリース告知で必ず明示すること。genesis hash は不変（`write_header_preimage` 未変更、`PalwBatchViewV1` は store 行であり header 素材ではない）。
>
> - encoding は `consensus/core/src/palw.rs` の layout-pin テスト（bincode バイト長 + バイト列 pin）が押さえており、**フィールド追加・並べ替え・型変更のいずれでも「bump `LATEST_DB_VERSION`」を明示するメッセージで落ちる**。
> - bump と `factory.rs` の migration arm は**必ず同時に動かすこと**。arm 無しで bump するとループの `assert_eq!` に落ちて、案内ではなく起動時 panic になる。
> - PALW preset では `palw_algo4_accept = false` でも beacon accumulator の行自体は書かれるため、この型の encoding は inert ではなく **cutover の対象である**。
>
> 本項は「ゲート」ではなく**不可逆な運用手順**なので §7.2 の表には行を作らない。activation runbook 側で扱うこと。

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

> **remediation 後も判定は変わらない（2026-07-20 再確認）。** P1-5（DOS-02）は §5.12 のとおり**削除で閉じ**、P1-9 は body 座標から**撤回**された（SPEC CHANGE）。それでも公開 no-value testnet を止めているのは残る **P1-8 / P1-10**、新規 activation 級 **P1-9-RELAND**（DA/audit slice 依存）、および §5.12 併記の **CHUNK-INDEX SQUAT**（設計 §5.15 → **同日実装済み**: THEFT/DENIAL half 閉鎖、bitmap half は無害化のうえ CERT-TRUST へ再分類）である。さらに本日 **StopShip gate G3 の verifier が非実在**であることが判明した（§5.15.3）ため判定は一度**後退**したが、**同日の §5.15 実装で G3 は code-level では閉じた**（live E2E は未検証）。**それでも判定は変わらない** — 残る **P1-8 / P1-10 / P1-9-RELAND**（M2 で前提が立っただけで未実装）が公開 no-value testnet を止めている。項目数の進捗はこの判定に影響しない。
>
> あわせて、`palw_algo4_accept` は**全 6 preset で `false`** のままである（`consensus/core/src/config/params.rs`）。本 ADR の remediation はいずれも lever を動かしていない。

> **判定を「実体化した索引」の上で言い直す（2026-07-20、`palw_gate_table_verifiers_all_resolve` 導入後）。** ゲート表の verifier 名は従来 15 個中 1 個しか実在せず（G3 事故の全体版）、残量集計は壊れた索引の上の数字だった。同日、全 16 gate を authoritative な const registry へ固定し meta-test で強制した。その索引の上で `accept` lever（= 公開 testnet / T-shared に必要 = 全 StopShip + 全 Activation）を分解すると:
>
> - **StopShip G1-G4 = `VerifierExists`**（code-level で閉じ、実在 verifier で強制）。**`land` lever は開けられる。**
> - **Activation で code-verifiable なもの: G5（AUTH-02）/ G7 / G13 / G15 / G16。** G7 / G15 は 2026-07-20 に、**G13 も同日**（cross-crate auditor-quorum E2E `producer_built_certificate_round_trips_through_verify_certificate_attestation`）に Unimplemented → VerifierExists へ昇格した。G16 は bounded-window（前提は §5.17 で立ち、部分実装済み）。**いずれも verifier 実在 ≠ operationally 閉鎖** — 下記の 3 バケツの残余は消えていない。
> - **Activation で `Unimplemented` は G12（PCPB multi-node E2E）のみ**へ縮んだ。ただし上の VerifierExists 昇格分を含め、operationally 未閉鎖の残余は掘削の結果 **3 バケツ**に帰着する — (a) **オフチェーン DA 所持証明**（SAMPLE-01/DA-01/PCPB。consensus が保持しないバイトの root は再計算不能。§5.17.6 の弱い再定義までが consensus 側の限界で、I-14 所持性は原理的に測定 = G8-G11 に帰着）、(b) **再 genesis 級のデータモデル欠落**（SLASH-01 の authority→bond LINK 不在 = G13 の残り半分。第二経路 §24.5 も参照ランタイム再実行 = G8-G11 依存）、(c) **測定そのもの**（G13 の WITHHOLD / REORG、G12 の multi-node もここ）。
> - **Activation で `Measurement`: G6 / G8 / G9 / G10 / G11、および WeightRaise の G14。** 72h soak・複数 GPU・cross-device 実測が**定義そのもの**であり、コードでは 1 mm も進まない。
>
> **したがって公開 no-value testnet を止めているのは「未実装のコード」ではなく「未実施の測定」である。** DA-01 / SLASH-01 / PCPB の正しい「完了」は**コード着地ではなく設計凍結 + activation-blocker 登録**（§5.16 / §5.14 / §5.17.6 に凍結済み）であり、それらの実装可能版は S0（cross-device 実測完了）を待つ。**T-shared までの残りは、この時点でコードの問題ではなく測定の問題である。**

**単一プール化は設計を整理するが、未検証 certificate が突然安全になる魔法ではない。配線の穴は配線の穴のままである。そして残る穴の大半は、いまや配線ではなく実機と実時間で塞ぐ側にある。**

本 ADR の最重要不変条件を再掲する。

> 単一プールとは、A が自分で自分を承認できるという意味ではない。
> 全員が同じ登録集合に所属し、各ジョブの役割だけを commit 後の乱数で分けるという意味である。
