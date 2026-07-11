# MISAKA MIL ShieldedPool 追跡監査（fe3d6fa）修正対応報告書（再監査提出用）

**対応日:** 2026-07-12
**対象ブランチ:** `feat/mil-v0`
**監査 snapshot:** `fe3d6fa63c56d460eecfa0104f286160b04ad349`（`rusty-kaspa-feat-mil-v0-fe3d6fa.zip`、SHA-256 `b9dbc916cc7a7b43d31d2784918bb410385dfc72ffa5f33245b993beea25d2f4`）
**対象監査:** `MISAKA_MIL_ShieldedPool_Reaudit_fe3d6fa_2026-07-11.md`（基準 `c8d729a` 追跡監査、Critical 3 / High 2 / Medium 1 / Info 3）
**修正後 HEAD（remediation tip）:** `a3a943b19b79bc67e6464b07757a3a2702398756`（本報告書コミットはこの直上）

> **A7 activation 判定について:** 監査の **NO-GO に同意する**。本対応で C-01 / C-02 / K-01 / M-05 はコードレベルで閉鎖したが、C-03（C-P6 full receipt circuit）は統合作業中であり、G10（独立監査）/ G11（canary・rollback rehearsal）/ G12（activation-height-only release 再監査）は本質的に外部・運用ゲートである。**F006 fence（全 preset `u64::MAX`）は本対応後も維持する。**

---

## 0. エグゼクティブサマリー

- **Critical 3 件のうち 2 件（C-01, K-01）をコードで閉鎖、High 1 件（C-02）を閉鎖、Medium 1 件（M-05）を triage + fuzz corpus で閉鎖。** 残る Critical は C-03（C-P6 統合）のみで、並行トラックで進行中（正直な status: 未完・数週間規模）。
- **修正コミット（いずれも `fe3d6fa` の後、`feat/mil-v0` 上）:**

| Finding | Triage 判定 | 修正 commit |
|---|---|---|
| C-01 | TRUE_GAP | `2f42976da1b2fae2868a79b329c56c7ce9950f80` |
| C-02 | PARTIALLY_TRUE（証拠行は scanner artifact、根本 gap は実在） | `2f42976da1b2fae2868a79b329c56c7ce9950f80` |
| K-01 | PARTIALLY_TRUE（compare 欠落・anchor 汚染は STALE/FALSE、独立 manifest 欠落・table_order 非拘束は TRUE） | `8b68fbda024e8c6c63198928036dad6eefb32f4e` |
| M-05 | 証拠は STALE_OR_FALSE、triage 要求自体は正当 → 閉鎖 | `7e95d3245965ee39637a81be496a139239df9855` |
| C-03 | 監査に同意（FAIL） | 未閉鎖 — 並行トラック進行中（`33449e9` = 256-pt in-AIR NTT routing） |
| G10/G11/G12/A7 | 監査に同意 | 外部・運用ゲート、fence 維持 |

- **検証方式:** 各 finding を read-only の敵対的 triage（file:line 検証、監査主張と現ツリーの突合）→ 修正レーン → **独立の敵対的検証レーン**（テスト再実行・constraint 実在確認・.119 での AIR 再証明を含む）の 3 段で処理。3 検証レーン全てが verdict **SOUND**。
- **テスト:** forge **71/71**、`misaka-mil-shield` release **58/58**（42+10+2+4）、`misaka-mil-shield-stark-verify` default **19/19**、同 `--features stark-backend --release` + 実 103KB 系 artifact **25/25**。本報告書作成時に headline suite を最終再実行して確認（§4）。
- **コンセンサス安全性:** 本対応の全変更は F006 fence（全 preset `u64::MAX`）の内側で inert。Solidity の資金経路（`MilShieldedEscrow.sol`）は **byte-identical（無変更）**。circuit_version=4 は Rust/node で decode・検証可能になったが **未登録・未凍結**（`vk_hash: None` → `CircuitVkNotFrozen` fail-closed）。
- **未デプロイ:** push / activation / release はいずれも未実施。

---

## 1. 修正方針と検証

1. 監査の各 finding について、引用 file:line を**現ツリーと `fe3d6fa` の両方に対して**検証した（過去監査で stale/false 主張が繰り返されたため、TRUE gap と scanner artifact の分離を第一義とした）。
2. finding ごとに read-only 敵対的 triage エージェント → 修正レーン → 独立検証レーンを直列化。検証レーンは修正の主張を信用せず、テストを自ら再実行し（.119 での AIR 再証明を含む）、constraint がコメントでなく実コードであることをソースで確認した。
3. 修正は crate 単位でビルド + テスト + clippy + fmt。資金経路（Solidity）は無変更とし、差分テストは**実 `claimAnonV2` を driving** する形で追加した。
4. 1 コミット = 1 finding 群（C-01/C-02、K-01、M-05）。各コミットは並行レーンのコミット（`33449e9` C-P6 NTT、`5bd6062` A2 surfacing）の上に積んだ（rebase なし）。

---

## 2. Critical

### C-01 [Critical] claimAnonV2 支払額 binding を監査可能な実装として確認できない

**監査の主張:** 契約側は `providerShareSompi` を v2 statement の公開入力に追加したが、対応 AIR はコメントのみ更新され、実際の public values・trace・制約へ反映されていない。未拘束なら未担保 note、ずれれば恒常的 fail-closed。

**Triage 判定: TRUE_GAP（監査は正しい）。** `fe3d6fa` 時点の跨層状態:

- Solidity のみが share を持つ: `contracts/mil/src/MilShieldedEscrow.sol:314-328` が `grossSompi=(snapshotPrice*(tokIn+tokOut))/1000`（floor）→ `providerWei=(grossWei*88)/100` → whole-sompi gate → `providerShareSompi` を計算し、`_borshClaimStatementV2`（:436-446）が 392 byte statement `setRoot(64)‖sessionCm(64)‖vClaimCm(64)‖providerNf(64)‖cmPayout(64)‖le64(share)‖ctx(64)` を circuit_version=4（:38, :455）で構築。
- Rust には v2 statement 型が存在しなかった（`mil/shield/src/proof.rs` は circuit 1/2 のみ、dispatch に circuit-4 arm なし; `mil/shield/src/provider.rs` は v1 関係式のみ）。
- node verifier（`mil/shield-stark-verify`）は circuit 4 → `UnknownCircuit` fail-closed（凍結サイズ表も 404/328 B のみ）。
- AIR（`docs/bench/plonky3-shield-air/claim_v2.rs`）で `providerShareSompi` は**ヘッダコメントにのみ**出現し、実 public values は 6 語（share なし）。`AMT` は `v_claim_cm`/`cm_payout` に拘束されるが**契約計算 share に対しては自由な private witness** — 監査の核心主張どおり。
- 現状の net posture は全経路 fail-closed（監査の言う benign branch）だが、circuit 4 をこのまま配線すれば未担保 note が現実化する。

**対応（commit `2f42976`）:**

1. **Statement schema manifest**（監査の修正要件そのもの）: `mil/shield/src/statement_schema.rs`（新規 340 行）— circuit_version ごとの field 名 / 順序 / 幅 / offset を単一 manifest 化（spend 404 B / claim-v1 328 B / claim-v2 392 B）。Solidity `abi.encodePacked` layout を独立再構成する byte-differential テスト付き（`evm_ctx.rs` の確立済みパターンを statement bytes へ適用）。share の mutation が bytes `[320,328)` に局在することもテストで固定。
2. **Rust circuit-4 を end-to-end で実装**: `ProviderClaimStatementV2`/`ProviderClaimWitnessV2` + `verify_reference_v2`（`mil/shield/src/provider.rs:165/280`）— membership・nullifier に加え `v_claim_cm == H(value-domain, amount‖blind)`、`cm_payout` opens、`note.value == amount`、**`amount == provider_share_sompi`（C-06.2 の等式をコメントでなく実行コードに）**、`token_id == 0`。`CIRCUIT_PROVIDER_CLAIM_V2 = 4`（`proof.rs:29`）+ dispatch arm（:205）。node verifier に circuit-4 decode arm + manifest 由来サイズ assert。
3. **AIR の実拘束（C-01 の核心）**: `docs/bench/plonky3-shield-air/claim_v2.rs` に `PI_SHARE`（:177）— 凍結 borsh 位置（cm_payout と ctx の間）の **64 個の実 public bit-values** を追加し、`F_VCM`/`F_CM_B1` が既に参照する private `AMT` global と **bit 単位で等値拘束**（独立検証レーンが「全行・非ゲートの `builder.assert_eq(row[AMT+k], pis[PI_SHARE+k])`、boolean 拘束付き」であることをソースで確認）。これにより `v_claim_cm == commit(providerShareSompi)` **かつ** `payout_note.value == providerShareSompi` が in-circuit で成立。
4. **実証明での positive/negative E2E**（監査の acceptance test）: .119 で再証明 — positive `VERIFY ok`（prove 2.9s / verify 66.6ms）+ PRIVACY smoke OK、negative 7/7 拒否（既存 `--corrupt/--wrong-root/--wrong-nf/--steal` + 新規 **`--share-plus/--share-minus/--swap-fields`**）。新 negative は share=amount±1 を公開して trace は正直な amount を commit する系で、拒否はまさに新 `PI_SHARE==AMT` 拘束による。vendored copy は byte-identical（SHA-256 `0efaf898f3d773b77a876753711800987a7fcb400cf3691615b77cb036a9e527` 両側一致）。独立検証レーンが .119 で**再実行し再確認**した。

**残余（正直な開示）:**
- bench AIR はテスト用 FRI パラメータ（2 queries）での回路ロジック実証であり、production soundness proof ではない（従来の build#N run と同じ but し書き）。
- AIR の PI encoding（6+1 hash の bit 分解）と node の `statement_to_pvs`（borsh statement の byte-per-element）の照合は手動規約であり、circuit 4 の production STARK backend 着地時に機械的に pin する必要がある（現状は BackendPending/fail-closed のため悪用面なし）。
- circuit 4 は **未登録・inert**: K-01 manifest に `vk_hash: None`、STARK backend は fail-closed、F006 fence は `u64::MAX`。activation surface は一切変更していない。

### C-03 [Critical] C-P6 full receipt circuit は sub-gadget 群から統合済み Provider Claim AIR へ到達していない

**監査の主張:** Keccak/SHAKE、NTT、UseHint 等の部品が存在しても、full ML-DSA verification・receipt transcript・session/counter/pricing を一つの AIR に接続した証拠が不足。

**Triage 判定: 監査に同意（FAIL は正当）。本対応では閉鎖しない。** 正直な status:

- C-P6 統合は**並行トラックで進行中**。`fe3d6fa` 以降に `33449e9`（**256-pt full in-AIR cross-layer NTT routing**、layer-per-row・LogUp なし）が着地し、sub-gadget 層（ExpandA/SampleInBall/UseHint/norm/decode/SHAKE multi-block/NTT fwd+inv）は完了している。
- 残るのは **composition**（全 gadget を Provider Claim witness・circuit-version dispatch・receipt transcript・session/counter/pricing と同一 constraint system に統合し、libcrux full-signature differential を通す）であり、見積りは**数週間規模**（設計: `docs/mil-shield-cp6-mldsa-in-circuit-design.md`、commit `82377ee` 起点）。
- それまで circuit 3 dispatch が存在しないのは意図した fail-closed であり、**C-03 が open である限り A7 は NO-GO のまま**という監査の結論に同意する。

### K-01 [Critical] A3 circuit/VK binding はなお独立な pinned manifest として完全でない

**監査の主張:** actual proof commitment / 独立 expected commitment / 比較 / public schema・PCS・FRI・version のいずれかが欠落（`compare=該当参照なし`）。同じ粗い shape の別 preprocessed program に差替え可能。dimensions 表では `table_order: False`。

**Triage 判定: PARTIALLY_TRUE。** 監査の主張を成分分解した:

| 成分 | 判定 | 根拠（file:line） |
|---|---|---|
| 「compare が存在しない」 | **STALE_OR_FALSE**（scanner artifact） | `fe3d6fa` の `mil/shield-stark-verify/src/lib.rs:484-485` に明示比較 `if super::compute_vk_hash(&context_from_proof(circuit_version, &proof)) != *vk_hash { return Err(StarkVerifyError::VkHashMismatch); }` が存在（`git show fe3d6fa:` で逐語確認）。crypto verify（`verify_all_tables`）より**前に無条件**実行。実 artifact での wrong-vk 拒否テストも存在（:820-824）。監査引用行 104/411/444/717/759 は binding サイト自体であり、scanner が比較の字句パターンを見逃した。 |
| 「trust anchor が proof/attacker 由来」 | **STALE_OR_FALSE** | expected vk の全経路は contract storage（`ShieldedPool.sol:41/97-99` `spendVkHash` / `MilShieldedEscrow` `claimVkHash`、owner-set、M-04 session snapshot）→ contract 自身が envelope 構築（`ShieldedPool.sol:325-338`、attacker 供給は proofField のみ）→ F006 calldata → `proof.rs:173-175` 等値強制 → `lib.rs:484` shape 再計算比較。circuit_version も vk_hash に混入し cross-circuit swap を拒否。 |
| 「独立な signed release manifest が無い」 | **TRUE_GAP** | in-repo の expected 導出は `expected_vk_hash(proof)` = proof 自身から導出（ceremony 手順として循環）。K-01.3 registry（`01ea86f`）は F006 経路に未配線・production 定数なし。監査者が proof 非依存に vk_hash を再計算できる列挙が存在しなかった。 |
| 「table_order 非拘束」 | **TRUE**（監査の dimensions 表が正しい） | `canonical()` が non_primitive_ops を sort し、同一 multiset の並べ替えが同一 vk_hash（当時のテストがこれを仕様として assert していた）。 |
| その他 dimensions（commitment/rows/lanes/air_variant/public_schema/pcs_fri/circuit_version = True） | **正確**（3 点のニュアンス含め本対応で閉鎖） | 94c9573（K-01.1）の per-table 64B fingerprint + 実 PCS commitment 拘束、4cc7d63（A3 transcript freeze）等。 |

**対応（commit `8b68fbd`）:**

1. **独立 pinned manifest（trust anchor）**: `mil/shield-stark-verify/src/manifest.rs`（新規）— circuit_version ごとの `const CircuitManifest`（1 spend / 2 claim-v1 / 4 claim-v2; **circuit 3 = C-P6 は意図的に不在** = 検証不能）。フィールド: statement schema id/長（C-01 manifest と相互ロック）、field/ext/poseidon2_id、transcript KAT（A3 freeze 値）、全 FRI/PCS パラメータ、M-05R metadata bounds、`vk_hash: Option`、`preprocessed_commitment: Option`、pinned recursion rev（workspace Cargo.toml の git pin と `include_str!` で test-assert）。**verify 経路はこの compiled-in 表のみを参照**し、caller/contract 供給 key は manifest pin と等値でなければ `VkHashMismatch`、未凍結回路は `CircuitVkNotFrozen` で fail-closed（`lib.rs:314`）。proof 由来値が expected になる経路は型的に存在しない（proof 由来導出 `ceremony_vk_hash`/`ceremony_preprocessed_commitment` は ceremony 専用と文書化、verify 経路から不使用を検証レーンが確認）。
2. **table_order 拘束**: `canonical()` の sort を廃止し、`VerifierContext.non_primitive_ops` を**順序拘束**に変更。旧「順序不変」テストを反転（permutation / 2-entry swap ⇒ 別 vk_hash）し、実 171,765 byte artifact の 2-table swap ⇒ `VkHashMismatch` を assert（swap が実際に実行されたことをログで確認済み）。
3. **Full-manifest verify + 重複排除**: `verify_outer_proof` が 型 pin（`ManifestMismatch`）→ live Fiat-Shamir KAT（`TranscriptDrift`）→ metadata bounds → **raw preprocessed-commitment byte 比較**（`PreprocessedCommitmentMismatch` — vk fold-in から独立、監査の proof 非依存 auditability 要件を充足）→ A3 vk 再計算 → crypto の順で検査。FRI 定数の手書き二重管理（`pinned_config()` vs `context_from_proof`）を `config_from_manifest` に単一化。
4. **Acceptance corpus（監査の acceptance test）**: (a) default build — 全 precheck field mutation の typed 拒否 + self-consistency locks + 未凍結 fail-closed; (b) 実 artifact — **decision-bearing manifest 全 field を 1 つずつ mutate → 全拒否**、実 artifact が real preprocessed columns を commit（≠ sentinel）を assert; (c) hermetic **alternate-AIR 実証明テスト** — pinned config 下で 2 つの異なる回路を実際に証明し、各々が自己導出 key で crypto-verify する（= 監査が禁じる循環 anchor）ことを示した上で、manifest anchor が全差替え方向・cross-circuit re-badge・未凍結経路を **crypto 前に**拒否することを assert; (d) F006 レベルの新テスト `stark_arm_expected_vk_is_node_pinned_not_calldata` — self-consistent な attacker（calldata vk == proof vk）ペアが両 policy で ABI-false。

**残余（正直な開示）:**
- `vk_hash`/`preprocessed_commitment` は全 manifest で `None` = **回路凍結 ceremony 待ち**（機構は完備、未凍結中は fail-closed）。vk_hash の意味論は order-binding + manifest 給電で変化したが、凍結済み production vk は存在しなかったため re-ceremony の無効化はない。
- 監査の言う「署名済み」は Rust-const 設計では release binary の署名/hash-pinning が manifest を署名する形で実現（module docs に明記）。detached ML-DSA signed JSON が必要なら ceremony 時に `ceremony_*` 関数の出力を直列化する。
- `a2_patch_sha256` は並行 A2 レーンが当該 diff を活発に所有するため `None`（ceremony 時に凍結）。`recursion_rev` は provenance フィールドで runtime 拒否ではなく static lock（性質上 runtime 検査不能、テストで drift を検出）。
- `max_public_values_per_table` の manifest-side mutation assert は pre-A2 artifact では空虚のため省略（proof-side の cap 境界 mutation は M-05 コミットの typed corpus が被覆 — branch 全体としては被覆済み）。

---

## 3. High

### C-02 [High] Provider Claim の fee/net 等式は実装候補だが丸め・overflow の E2E 閉鎖が不足

**監査の主張:** claim AIR に ratio/fee 関連の実コードが存在する（証拠: `mil/shield-stark-prove/src/lib.rs:137`）が、Solidity と完全一致する整数意味論の real E2E が必要。境界値の丸め差は未担保 note または claim 停止になる。

**Triage 判定: PARTIALLY_TRUE。**
- **証拠行は scanner artifact**: `mil/shield-stark-prove/src/lib.rs:137` は `assert!(80 * 100 / c.blake2b_compressions >= 70)` — Merkle 圧縮比の**証明コストモデルのテスト**であり fee/net 制約コードではない。`fe3d6fa` 時点で fee/ratio コードは**どの AIR/Rust crate にも存在しなかった**（88%/FEE 系 grep 空振り）。
- **根本 gap は実在し、監査の想定より深い**: split 全体（/1000 floor、88/5/7、whole-sompi gate、uint64 cast）は Solidity にのみ存在し、単一仕様・Rust mirror・differential vector・境界テストが皆無。whole-sompi gate は `gross ≡ 0 (mod 25)` と等価であり、例えば price=2, tokens=51,000（gross=102）は `claimAnonV2` が**恒久 revert**（監査の「claim 停止」branch が具体的に到達可能）。当時唯一の v2 forge test は gross=100（25 の倍数）で revert 経路を一度も通らなかった。

**対応（commit `2f42976`、C-01 と同一コミット）:**

1. **単一規範仕様**: `mil/shield/src/economics.rs::claim_v2_split`（:238）— `claimAnonV2` の整数意味論を dependency-free の U256 limb 演算で厳密再現（uint256 中間値、floor 除算、whole-sompi gate ⇔ `gross%25==0`、truncating uint64 cast、88/5/7 の 3 leg 厳密値）。丸め意味論は **ADR-0037 §2.3.3（NORMATIVE）**として凍結。
2. **Rust/Solidity 共有 vector**（監査の修正要件「単一仕様から生成」）: `contracts/mil/test/vectors/claim_v2_split_vectors.json` — 12 境界 vector（zero、/1000 floor 25999→25 / 999→0、`gross%25 ∈ {1,2,24}` の SplitMismatch 群、near-u64-max、uint64-cast truncation、abs-max u64 入力）。**同一ファイル**を Rust unit test と新 forge suite `MilClaimV2Split.t.sol` の両方が消費。独立検証レーンが全 12 vector を Solidity 意味論から**第三実装（Python）で再計算し全一致**を確認。
3. **実 E2E**: forge suite は helper でなく**実 `claimAnonV2` を driving**（3 つの wei leg 全 assert、従来未実行だった v2 `SplitMismatch` revert、gross=102 の恒久 revert + `refundAfter` 経由の資金回収 liveness を固定）。net±1 mutation（監査の acceptance test）は Rust relation / borsh byte / forge statement bytes / AIR negative の **4 層全て**で拒否を assert。
4. C-01 の `verify_reference_v2` により `note.value == amount == provider_share_sompi` が relation として成立し、`gross → 88/5/7 → net → note value` が単一のテスト済み連鎖として閉鎖。

**残余・判断の開示:**
- **丸め意味論の選択**: revert-on-non-whole-sompi gate を**維持**した（資金経路変更は remediation スコープ外）。gateway/provider SDK は `gross ≡ 0 (mod 25)` へ量子化する義務を負う（ADR-0037 §2.3.3 に規範化、恒久 revert の帰結はテストで固定）。dust-flooring（≤24 sompi 相当を pool leg へ吸収）への変更を governance が選ぶ場合は別途の contract 変更。
- **in-AIR 価格演算（gross→88% を回路内で計算）は現設計では不要**であり存在しない — 契約が split を計算し、回路は結果 share を bind する。full in-circuit pricing は committed-ask V3（build#8 系）のフォローアップ。

### A7 [High] activation gate — NO-GO

**監査の主張:** Critical/High blocker が残るため activation 不可。fence は安全境界であり解除してはならない。

**判定: 全面同意。** 本対応後も **A7 = NO-GO を自己宣言**する。根拠: C-03 が open（§2）、G10/G11/G12 は本質的に外部・運用ゲートで未着手(§5 参照)。**F006 fence（全 preset `u64::MAX`、`consensus/core/src/config/params.rs`）は本対応で一切変更していない**。監査の推奨修正順序 6（独立外部監査 → canary/rollback rehearsal → activation-height-only release の再監査）に従う。

---

## 4. Medium / Info

### M-05 [Medium] MIL proof/claim production surface に panic 候補が残る

**監査の主張:** 候補 16 行（全て `wallet/keys/src/kaspa_pq_wasm.rs`）+ repo 全域 metrics。攻撃者制御 proof/receipt から到達可能なものは node DoS。

**Triage 判定: 証拠は STALE_OR_FALSE、「Open for reachability triage」という要求自体は正当 → triage を完遂し閉鎖。**
- 引用ファイルは WASM wallet binding であり **kaspad は wallet-keys を一切リンクしない**（cargo tree で確認、default と `--features evm` の両方）— node liveness と無関係。引用 16 行中 12 行は `#[cfg(test)] mod tests`（:290 開始）内 = production 成果物からコンパイル除外。残り 4 行は構造的に不可謬な hex encode。全体 metrics は tests/tooling 込みの repo 全域スキャン値で到達可能性の主張ではない。
- **実 triage の結論**: F006 系 4 surface（`mil/shield`、`mil/shield-da`、`mil/shield-stark-verify`、`kaspa-evm/src/shielded.rs`）の全行読査で、攻撃者到達パスに自前コードの panic site は**ゼロ**（全て Result 化 + cap 済; H-02 の 8MiB cap / M-06 の `.get()` / M-05R metadata bounds の実在を file:line で確認）。**真の残 gap は 1 件のみ** = `stark-backend` feature ON での vendored Plonky3 `verify_all_tables` に対する malformed outer-proof fuzz corpus の欠如（`edfdc92` が明示的に別トラック化していたもの）。

**対応（commit `7e95d32`、テストのみ +487/−38、production コード無変更 = triage 通りの正しい no-op）:**

1. `malformed_outer_proofs_never_panic`（feature=stark-backend）— hermetic seed（pinned config 下で in-test 生成した実証明、20k byte 変異）+ 実 artifact（2k byte 変異 + typed corpus: M-05R cap 境界/境界+1/usize::MAX、vk-bound shape ±1、public-values 0→cap/cap+1、max_tables 超過複製）を **catch_unwind なし**で駆動、panic ゼロ（vendored p3 への patch 不要と実証）。
2. `malformed_da_wire_bytes_never_panic`（mil/shield-da）— descriptor/chunk の borsh wire 変異 20k、decodable な非同一変異は全て fail-closed。
3. 既存 envelope fuzz（`edfdc92`）の seed を spend 単独 → 全登録回路（spend + claim v1 + v2）へ拡張。
4. **テスト基盤の実バグを発見・修正**: 旧 LCG fuzz 生成器の下位ビット周期病理により mutation クラスが飢餓していた（DA corpus で decodable 変異 0/20k を実測）— splitmix64 化 + 最低到達数 assert を恒久化。

**残余（正直な開示）:**
- stark-backend feature の fuzz は **CI 未配線**（feature 自体が CI job に無い = M-07 back half の既知項目）。hermetic corpus は artifact 不要で走るため、job 新設時にそのまま required 化できる。
- 実 artifact は pre-A2（public_values 空）のため pv-bump 変異は空虚 — A2-surfaced artifact 凍結後に再実行が必要（コードは seed 非依存で記述済み）。
- **receipt corpus** は F003 precompile という別 surface の課題として別チケット化。**ciphertext corpus** は vacuous — consensus は note ciphertext を decode しない（contract は `keccak256(encNote)` のみ bind、ML-KEM 復号は wallet 側 off-consensus）ことを grep で確認し、対象パス不存在として閉鎖（本書がその記録）。

### M-03/04 [Info] design artifacts — Present

同意。versioned design（ADR-0034/0035/0036/0037 + `docs/mil-shield-cp6-mldsa-in-circuit-design.md`）と invariant-to-test の対応は本対応でさらに強化された（statement schema manifest / economics 仕様 / verifier manifest がそれぞれ対応テストを自己文書内に持つ）。設計変更時の対応テスト更新 required 化は CI 運用側フォローアップ。

### M-07 [Info] activation CI matrix — Statically complete

同意。監査指摘の repo 外項目（branch protection、immutable artifact、runner architecture の運用証跡）は release process 側で対応する。既知の残り: stark-backend feature の required CI job（M-05 残余と同一項目）。なお本対応最終時点で branch tip は fmt/clippy clean（`a3a943b` で M-05 コミットの rustfmt 残差 2 hunk を解消済み）。

### P3-01 [Info] production StarkOnly / backend 配線 — Candidate closed

同意。StarkOnly は consensus param としてコード完備（mainnet policy）、fence は全 preset `u64::MAX`。K-01 対応により STARK arm の trust anchor は node-compiled manifest となり、contract-pinned から一段強化された。reference fallback の compile-time 排除（release build feature attestation）は release engineering フォローアップとして残る（reference arm は fenced・escrow-capped の stepping-stone であり、production StarkOnly policy が拒否する）。

---

## 5. A7 activation acceptance checklist（G1-G12）— 本対応後の自己評価

| Gate | 必須条件 | 監査判定 | 本対応後（自己評価、再監査で要確認） |
|---|---|---|---|
| G1 | C-01/C-02 statement・経済等式を全層で固定 | FAIL | **コードレベルで閉鎖**（`2f42976`: schema manifest + AIR 実拘束 + 4 層 mutation + 共有 vector） |
| G2 | C-P6 full receipt circuit + full differential | FAIL | **OPEN（同意）** — 並行トラック進行中、数週間規模 |
| G3 | A3 pinned actual commitment / schema / PCS manifest | FAIL | **機構は閉鎖**（`8b68fbd`: 独立 manifest + 順序拘束 + full-field mutation）。`vk_hash` の実値 pin は回路凍結 ceremony 時（未凍結中 fail-closed） |
| G4 | production StarkOnly + backend release build | PASS WITH CONDITIONS | 不変（release attestation は運用側） |
| G5 | real proof Rust verifier + Solidity E2E | PASS | 維持 + 拡張（v2 実 E2E、実 artifact manifest corpus） |
| G6 | full differential + mutation corpus | PASS | 維持 + 拡張（経済 split differential、share±1、manifest 全 field） |
| G7 | cross-architecture deterministic transcript | PASS | 不変 |
| G8 | panic-free bounded decode / resource caps | FAIL | **閉鎖**（`7e95d32`: 到達性 triage + outer-proof/DA/envelope fuzz、panic ゼロ）。stark-backend CI 配線が残条件 |
| G9 | M-03/M-04 versioned design + executable invariants | PASS WITH CONDITIONS | 維持 + 強化 |
| G10 | independent verifier/circuit audit | NOT EVIDENCED | **OPEN（同意）** — 本質的に外部。本書 + 修正 commit 群がその入力 |
| G11 | canary caps、monitoring、pause/rollback rehearsal | NOT EVIDENCED | **OPEN（同意）** — 運用 rehearsal 未実施 |
| G12 | activation-height-only release の最終差分監査 | NOT STARTED | **OPEN（同意）** — G2/G10/G11 の後段 |

**結論: G2/G10/G11/G12 が open である限り A7 = NO-GO。監査と完全に一致する。**

---

## 6. ビルド・テスト証跡

本報告書作成時（remediation tip `a3a943b`）に headline suite を最終再実行した:

| 対象 | 結果 |
|---|---|
| `forge test`（contracts/mil、9 suites） | **71/71 passed**（旧 68 + 新 3: split differential / statement layout+share binding / non-whole-sompi 恒久 revert+refund） |
| `cargo test -p misaka-mil-shield --release` | **58/58**（unit 42 + anon_provider_claim_e2e 10 + differential_corpus 2 + private_transfer_e2e 4） |
| `cargo test -p misaka-mil-shield-stark-verify`（default） | **19/19**（STARK arm は `CircuitVkNotFrozen` fail-closed） |
| 同 `--features stark-backend --release` + 実 artifact（`MIL_OUTER_PROOF`） | **25/25**（102-110s; manifest 全 field mutation / table reorder / alternate-AIR / outer-proof fuzz を含む — 修正時 + 独立検証レーンで実行） |
| `cargo test -p misaka-mil-shield-da --release` | **13/13**（修正時） |
| `cargo test -p kaspa-evm shielded` / `cargo check -p kaspa-evm` | **6/6** / clean（修正時 + 検証レーン） |
| AIR 実証明（.119、claim_v2） | positive VERIFY ok + PRIVACY OK、**negative 7/7 拒否**（修正時 + 独立検証レーンで各 1 回、計 2 回） |
| clippy（3 shield crate、default と stark-backend、--all-targets）/ `cargo fmt --check` | 0 warnings / clean（`a3a943b` 後） |

**独立敵対的検証:** 3 修正レーン全てに独立検証エージェントを起動し、いずれも verdict **SOUND**（テスト自己再実行・constraint のソース確認・.119 再証明・経済 vector の第三実装再計算・commit hygiene 監査を含む）。

---

## 7. 残フォローアップ

| 項目 | 種別 | 内容 |
|---|---|---|
| **C-03 / G2** | activation blocker | C-P6 composition（sub-gadget → 統合 Provider Claim AIR + libcrux full differential）。並行トラック進行中 |
| **VK freeze ceremony** | activation 前提 | 回路凍結時に manifest の `vk_hash`/`preprocessed_commitment`/`a2_patch_sha256` を実値 pin（機構・テストは完備） |
| **stark-backend CI job** | CI | feature ON の fuzz + manifest corpus を required 化（hermetic corpus は artifact 不要） |
| **pv-bump corpus 再実行** | QA | A2-surfaced artifact 凍結後（コードは対応済み） |
| **receipt corpus** | 別 surface | F003 precompile 入力 fuzz（別チケット化済み） |
| **AIR PI encoding の機械的 pin** | C-P6/backend 着地時 | AIR bit 分解 ↔ node `statement_to_pvs` byte encoding の照合を機械 assert 化 |
| **dust-flooring 代替案** | governance | SplitMismatch revert 維持 vs pool-leg 吸収は governance 判断（現状は revert + SDK 量子化義務を規範化） |
| **G10/G11/G12** | 外部・運用 | 独立監査 → canary/monitoring/rollback rehearsal → activation-height-only release 差分監査 |

---

## 8. 再監査提出物チェックリスト

- [x] 修正 commit hash — §0 表（`2f42976da1b2fae2868a79b329c56c7ce9950f80` / `8b68fbda024e8c6c63198928036dad6eefb32f4e` / `7e95d3245965ee39637a81be496a139239df9855` + hygiene `a3a943b19b79bc67e6464b07757a3a2702398756`）
- [x] source ブランチ / HEAD — `feat/mil-v0` / `a3a943b`（+ 本書コミット）
- [x] `cargo test` / `forge test` 結果 — §6（最終再実行値）
- [x] 実 proof での positive/negative E2E — §2 C-01（.119、2 回実行）
- [x] stale/false 主張の file:line 反証 — §2 K-01 / §4 M-05
- [x] 独立敵対的検証 — 3 レーン全て SOUND（§6）
- [ ] C-P6 統合（C-03/G2） — 進行中、閉鎖後に差分再監査を要請
- [ ] VK freeze ceremony 成果物 — 回路凍結時
- [ ] 独立外部監査 / canary・rollback rehearsal / activation-height-only release 再監査（G10/G11/G12） — 未着手（外部・運用）

> 本対応は静的修正 + 実証明 E2E + 独立敵対的検証であり、**A7 activation の解除を主張するものではない**。C-03 閉鎖と VK ceremony の後、本書と修正 commit 群を入力として G10 独立監査へ進むことを推奨する。
