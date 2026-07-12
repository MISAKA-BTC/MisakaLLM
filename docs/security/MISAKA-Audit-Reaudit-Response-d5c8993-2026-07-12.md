# MISAKA MIL ShieldedPool 追跡監査（d5c8993）修正対応報告書（再監査提出用）

**対応日:** 2026-07-12
**対象ブランチ:** `feat/mil-v0`
**監査 snapshot:** `d5c8993a45e5f547535429ced72dd27d8698c315`（`rusty-kaspa-feat-mil-v0-d5c8993.zip`、input archive SHA-256 `295a2d37ca8183e38d492863b9b580a9c97f31a294cac6fb0b097b75f789b912`）
**対象監査:** `MISAKA MIL Shielded Pool 再監査報告書 — Snapshot d5c8993`（基準 `fe3d6fa`→`d5c8993` 差分、独立 static / semantic follow-up review、Critical 1 / High 3 / Medium 8 / Low 3）
**修正後 HEAD（remediation tip）:** `266bbe36227ca0e75e9744b6eb2a4753770b2b0a`（本報告書コミットはこの直上）

> **A7 activation 判定について:** 監査の **NO-GO に全面同意する**。本対応で H-01 / M-02 / M-04 / M-07 / L-02 をコードで閉鎖し、H-02 / H-03 / M-03 / M-05 / M-06 / M-08 / L-03 を「build-graph・doc・honesty レベルで前進、実体は外部/数週間ゲート」として位置付け直し、C-03 は sub-gadget + in-AIR wiring を前進させたが **統合（full receipt-circuit integration）は未達で OPEN のまま**である。**F006 fence（全 4 preset `u64::MAX`）は本対応で一切変更しておらず、anonymous claim も default disabled のまま維持する。** VK/manifest anchor は全 circuit で未凍結（`vk_hash: None`）。監査が指摘する封じ込め control をすべて閉じたまま保つ。

---

## 0. エグゼクティブサマリー

- **監査の核心である H-01（claim ctx の跨層不整合、latent High）を実装で閉鎖した。** これは監査が「activation 後に正規 claim が決定論的に停止し、誤対応すれば replay/盗難へ転化し得る」とした真の cross-layer defect であり、我々の敵対的 triage も **CONFIRMED TRUE_GAP（latent）** と判定した。
- **C-03（C-P6 full receipt authorization）は監査に同意して OPEN のまま。** sub-gadget と in-AIR wiring は前進した（本対応で SHAKE multi-block threading・full `l=7` ExpandA + matrix-vector を敵対的検証済みの in-AIR AIR として着地、いずれも SOUND）が、**単一 relation への composition（item iv）・libcrux accept-diff（item v）・外部監査（item vi）は未達**であり、**sub-gadget + wiring の完成 ≠ full-receipt-circuit 統合**であることを明言する。C-03 は Critical activation blocker のまま。
- **修正コミット（いずれも `d5c8993` の後、`feat/mil-v0` 上、rebase なし）:**

| Finding | Triage 判定 | 修正/前進 commit |
|---|---|---|
| C-03 | 監査に同意（Open は正当） | `40d183b`（SHAKE threading AIR）+ `5139412`（ExpandA+matvec AIR）= **PROGRESS のみ、閉鎖せず** |
| H-01 | **CONFIRMED TRUE_GAP（latent）** | `266bbe36227ca0e75e9744b6eb2a4753770b2b0a` |
| H-02 | PARTIALLY_TRUE（build-graph は実在 gap、reproducible/signed は外部） | `bf6c3198c67d79376987b30426cc4adab45127c9` |
| H-03 | PARTIALLY_TRUE（stub は事実、API honesty を修正・実 prover は外部） | `bf6c3198c67d79376987b30426cc4adab45127c9` |
| M-01 | TRUE_GAP（H-03 実 prover 依存、数週間） | 未閉鎖 — 外部（実 prover 着地後） |
| M-02 | PARTIALLY_TRUE（node 側 uniqueness を閉鎖、soundness 半分は patch 内） | `b7316df5f6799480e25b5d49178ab1c98c1c94ca` |
| M-03（K-01 freeze） | Operational gate（機構は完備、原子凍結は ceremony） | `b7316df`（on-disk patch-hash pin） |
| M-04 | TRUE_GAP → 契約層で閉鎖 | `b7316df` |
| M-05 | PARTIALLY_TRUE（doc 不整合、backend 実装は BabyBear で一貫） | `b7316df`（ADR-0035 supersession note） |
| M-06 | PARTIALLY_TRUE（compile gate 追加、CI infra 本体は外部） | `bf6c319`（activation-feature-graph job） |
| M-07 | **TRUE_GAP（helper は dead code だった）→ 閉鎖** | `b7316df`（helper）+ `f51a106decc15fa5428309ad6be4899f8cfc5dec`（quote path 配線） |
| M-08 | PARTIALLY_TRUE（DA producer/consumer cap を整合、gas/metadata 較正は外部） | `b7316df`（m8 chunk cap align） |
| L-01 | 判定同意（Low、consensus-neutral・inert 中は無害） | 未閉鎖 — ceremony hardening へ |
| L-02 | TRUE_GAP → 閉鎖（m8 と同一 fix） | `b7316df` |
| L-03 | PARTIALLY_TRUE（activation-story を修正、full manifest 再生成は follow-up） | `bf6c319` |

- **検証方式:** 各 finding を read-only の敵対的 triage（file:line を `d5c8993` と現ツリー両方で突合）→ 修正レーン → 独立検証で処理した。H-01 は .119 で claim_v2 AIR を再証明（positive VERIFY ok + PRIVACY OK + 全 negative 8/8 拒否、`--wrong-ctx` を含む）。C-P6 の 2 AIR は敵対的検証で **SOUND**（full `l=7` in-AIR ExpandA 行、libcrux-pinned reference に対し係数厳密一致）。
- **テスト（本報告書作成時に最終再実行、§8 に verbatim）:** forge **75/75**、`misaka-mil-shield` release **59/59**（43+10+2+4）、`misaka-mil-shield-stark-verify` **21/21**、`misaka-mil-shield-da` **14/14**、`misaka-mil-provider` **42/42**（41 lib + 1 e2e）、`cargo check -p kaspa-evm --features shield-stark-backend` clean、`cargo check -p kaspad --features evm` clean。
- **コンセンサス安全性:** 全変更は F006 fence（全 preset `u64::MAX`）の内側で inert。circuit 4 は decode/verify 可能だが **未登録・未凍結**（`CircuitVkNotFrozen` fail-closed）。circuit 3（C-P6）は schema/manifest/prover/contract dispatch のいずれにも意図的に不在。
- **未デプロイ:** push / activation / release はいずれも未実施。

---

## 1. 修正方針と検証

1. 監査の各 finding について、引用 file:line を **`d5c8993` と現ツリーの両方**に対して検証した。過去監査同様、TRUE gap と scanner artifact / stale の分離を第一義とした。ただし本監査は前回より精度が高く、**H-01（ctx 不整合）と M-07（helper が dead code）は監査/フォローアップが正しく、我々も TRUE_GAP と確認した**。
2. finding ごとに read-only 敵対的 triage → 修正レーン → 独立検証。C-P6 は .119（`~/Plonky3/shield-air`）で in-AIR AIR を再証明。資金経路（Solidity `MilShieldedEscrow.sol`）の変更は m4（circuit-version snapshot）に限定し、資金分配ロジックは無変更。
3. コミットは finding 群単位（Lane B = H-02/H-03、Lane C = Medium 群、H-01、m7 wiring、C-P6×2）に分け、いずれも並行レーンの上に rebase なしで積んだ。
4. **正直な開示を最優先**した。H-02/H-03/M-01/M-03/M-05/M-06/M-08 は本対応で「閉鎖」を主張せず、build-graph/doc/honesty レベルの前進と、外部/数週間ゲートの残余を明確に分離して記述する（§9）。

---

## 2. Critical

### C-03 [Critical] C-P6 receipt 認可が実際の claim 経路に統合されていない

**監査の主張:** 本番 claim entrypoint は依然 circuit 2/4 のみを検証し、有効 receipt・ML-DSA 署名・receipt 公開鍵・単調 counter・pricing 認可を含まない。`claimsEnabled` は owner が変更できる bool にすぎない。circuit 3 は statement schema・verifier manifest・prover dispatch・contract dispatch のすべてに不在。独立に circuit 3 を完成させても、実 claim relation へ sound に composition されるか同一 settlement で原子的に検証されなければ現行関数は保護されない。

**証拠行（監査引用）:**
- `contracts/mil/src/MilShieldedEscrow.sol:66-71, 138-143, 214-264, 281-342, 448-477`
- `mil/shield/src/provider.rs:17-29, 165-204, 224-313`
- `mil/shield/src/statement_schema.rs:144-152, 181-186`
- `mil/shield-stark-verify/src/manifest.rs:165-177`
- `mil/shield-stark-prove/src/lib.rs:94-111`

**Triage 判定: 監査に同意（Open は正当）。本対応では閉鎖しない。** 正直な status:

- **前進（本対応、いずれも PROGRESS のみ）:**
  - `40d183b` — **multi-block SHAKE threading AIR**（`docs/bench/plonky3-shield-air/shake_threaded_air.rs`、1004 行新規）。absorb/permute/squeeze を in-AIR で配線し、複数ブロック跨りの状態 threading を実装。C-P6 composition item (ii)。
  - `5139412` — **full `l=7` ExpandA rejection-sampling + matrix-vector AIR**（`docs/bench/plonky3-shield-air/expanda_matvec_air.rs`、1341 行新規）。ML-DSA の行列 A を SHAKE から in-AIR で展開し matrix-vector 積まで配線。C-P6 composition item (iii)。
  - 両 AIR は独立敵対的検証で verdict **SOUND**（full `l=7` in-AIR ExpandA 行、libcrux-pinned reference に対し係数厳密一致）。設計は `docs/mil-shield-cp6-mldsa-in-circuit-design.md` に追記済み。
  - （`d5c8993` の audited tree には既に `33449e9` = 256-pt full in-AIR cross-layer NTT routing が含まれる。）
- **残る未達（C-03 が OPEN である理由、いずれも本対応で未着手）:**
  - item (iv) **single-relation composition** — 全 gadget（ExpandA/SampleInBall/UseHint/norm/decode/SHAKE multi-block/NTT fwd+inv/matvec）を **一つの constraint system** に統合し、Provider Claim witness・circuit-version dispatch・receipt transcript・session/counter/pricing と接続する。
  - item (v) **libcrux full-signature accept-diff** — 統合回路の accept/reject を libcrux の full ML-DSA-87 verify と differential で一致させる。
  - item (vi) **外部監査**。
- **明言:** **sub-gadget の完成 + in-AIR wiring の完成 ≠ full-receipt-circuit の統合**である。統合は単一 constraint system・circuit-3 dispatch・contract 原子 settlement を要し、見積りは**数週間規模**。**C-03 が open である限り A7 は NO-GO** という監査の結論に完全に同意する。circuit 3 dispatch の不在は意図した fail-closed であり、監査の Failure シナリオ（owner が `claimsEnabled=true` にしても receipt 不在で settle 可能になる）は circuit 3 の統合完了時に初めて閉じる。

---

## 3. High

### H-01 [High] Provider Claim AIR と contract が互換性のない ctx 意味論を拘束している

**監査の主張:** Solidity contract と `evm_ctx.rs` は 404-byte deployment-scoped preimage（chainId・contract address・escrow ID・root・session・full-width gross・nullifier・payout commitment・ciphertext hash）から ctx を計算するが、claim-v2 AIR は `ctx = H(session_cm ‖ v_claim_cm ‖ cm_payout ‖ provider_nf)` の 256-byte legacy preimage を拘束している。strict A2 binding では正規 proof が legacy ctx を surface するのに対し contract は deployment-scoped ctx を statement に入れるため、**全 claim が fail-closed** になる。liveness 回復のため node comparison を緩めれば cross-contract/escrow/gross/ciphertext malleability を再導入する。

**証拠行（監査引用）:** `contracts/mil/src/MilShieldedEscrow.sol:371-408`、`mil/shield/src/evm_ctx.rs:59-85`、`docs/bench/plonky3-shield-air/claim_v2.rs:4-6, 515-521, 652-653, 780-786`

**Triage 判定: CONFIRMED TRUE_GAP（latent High）。監査は正しい。** 敵対的 triage で三層が三つの異なる ctx preimage を bind していることを確認した:

1. Solidity `contracts/mil/src/MilShieldedEscrow.sol` `_computeClaimCtx`（現ツリー `:425-448`、domain `"misaka-shield-v1/claim-ctx"`）= `H_k` over 404-byte deployment-scoped preimage: `chainId(32) ‖ address(this)(20) ‖ escrowId(32) ‖ setRoot(64) ‖ sessionCm(64) ‖ grossSompi(32) ‖ providerNf(64) ‖ cmPayout(64) ‖ keccak256(encNote)(32)`。
2. Rust canonical `mil/shield/src/evm_ctx.rs::claim_ctx_onchain`（`:63-`）が **同一 404-byte preimage を byte-for-byte 再構成**（監査 snapshot 時点では spend-only の layout differential test のみ存在し、**claim 相当が欠落**していた）。
3. AIR `docs/bench/plonky3-shield-air/claim_v2.rs` が `PI_CTX = H_k("claim-ctx", OLD 256-byte 4-field session_cm‖v_claim_cm‖cm_payout‖provider_nf)` を制約（R_CTX_B1/B2 行、F_CTX_B1/F_CTX_B2 制約、`claim_ctx_v2_ref` reference）。file header 自身が audit item H-05R としてこれを認めていた。
4. `mil/shield/src/provider.rs:280 verify_reference_v2` は ctx を **OPAQUE な bound public input** として扱う（recompute しない — spend AIR も同様）。
5. Node binder `mil/shield-stark-verify/src/lib.rs statement_is_bound` は surfaced pv == statement_to_pvs を **392-byte claim-v2 statement 全体（ctx offset 328..392 を含む）**で要求。

→ strict A2 binding では AIR の `PI_CTX==H(256-byte)` が contract statement の `ctx==H(404-byte)` と乖離し、**claims 有効化後は全正規 claim が fail-closed**。監査の主張どおりの latent High。

**対応（commit `266bbe3`、コードベース自身の設計が支持する opaque-ctx fix）:**

1. **claim_v2 AIR で `PI_CTX` を OPAQUE な bound public input 化**（`docs/bench/plonky3-shield-air/claim_v2.rs`）: in-AIR ctx recompute を**削除**（`R_CTX_B1/R_CTX_B2` 行、`F_CTX_B1/F_CTX_B2` 制約、`claim_ctx_v2_ref` reference と trace-builder 使用、`CLAIM_CTX_DOMAIN` 定数）。`PI_CTX` は凍結 392-byte statement 内に宣言されたまま public value として surface されるが、**どの行でも制約されない**（active 行は 28→26、padding 6）。これは sibling の spend AIR と `verify_reference_v2` の扱いと一致。**404-byte contract ctx が唯一の authority**であり、malleability は node binder（surfaced pv == contract ctx を byte-for-byte）+ Fiat-Shamir での `PI_CTX` observation により閉じたまま。**statement 拡張なし・binding 緩和なし**（代替案の「404-byte を in-AIR で完全 recompute」は 392-byte statement に無い 5 個の新 public input + frozen-schema 変更を要するため採らない）。
2. **新 negative `--wrong-ctx`**: `PI_CTX` を反転した proof は (a) STARK は受理（in-AIR 制約が無いため）、(b) verifier が challenger で `PI_CTX` を observe するため **honest statement では verify しない**（Fiat-Shamir 非 malleability）、(c) node binder が tamper を拒否 — の三事実を実証。ctx は opaque だが statement level で拘束されることを示す。
3. **claim 側 differential test を追加**（`mil/shield/src/evm_ctx.rs`）: `claim_ctx_matches_solidity_abi_encode_packed_layout`（現ツリー `:265-`）— 独立な 404-byte `abi.encodePacked` 再構成 + 9 field-sensitivity negatives（spend-ctx layout pin `:179` の claim 版）。監査が指摘した「spend のみ存在、claim 欠落」を解消。
4. **.119 で claim_v2 AIR を再証明**: host diff-test true、`VERIFY ok`（prove 2.9s / verify 73.5ms、105,537 cols × 32 rows、prep 1033、proof 5,166,476 B）、`PRIVACY OK`、全 negatives（`--corrupt/--wrong-root/--wrong-nf/--steal/--share-plus/--share-minus/--swap-fields/--wrong-ctx`）拒否。vendored copy byte-identical。設計 doc §6.1 に H-01/H-05R closure と safety 論拠を追記。

**残余（正直な開示）:** AIR の PI encoding（hash の bit 分解）と node の `statement_to_pvs`（borsh byte-per-element）の照合は手動規約であり、circuit 4 の production STARK backend 着地時に機械 pin が必要（C-P6/backend 着地時項目）。現状 BackendPending/fail-closed のため悪用面なし。

### H-02 [High] 宣言された release graph に real backend と A2 patch が含まれていない

**監査の主張:** `stark-backend` / `stark-backend-a2-surface` は default off。`kaspa-evm` は verifier dependency へ両 feature を forward していない。workspace に A2 recursion 用の active patch がなく、CI も `stark-backend` のみを build し A2 surface feature を build しない。ゆえに通常の release graph は fail-closed のままで「activation は fence flip だけ」という comment と矛盾。

**証拠行（監査引用）:** `mil/shield-stark-verify/Cargo.toml:24-58`、`kaspa-evm/Cargo.toml:29-33`、`Cargo.toml:182-204`、`kaspa-evm/src/shielded.rs:55-60, 86-94`、`.github/workflows/ci.yaml:162-168`

**Triage 判定: PARTIALLY_TRUE。** feature 未 forward・CI が activation config を compile しない・"fence flip だけ" comment の 3 点は**実在 gap**（監査正）。一方「A2 patch が無い」は設計上の fail-closed（patch は A6-gated、pin は ceremony）であり gap ではなく posture。

**対応（commit `bf6c319`、Lane B、全 inert / build-graph のみ）:**

1. **feature forwarding**（`kaspa-evm/Cargo.toml` に `[features]` 追加）: `shield-stark-backend = ["misaka-mil-shield-stark-verify/stark-backend"]`（実 verify back-half、CI で compile 確認）。`shield-stark-a2-surface = ["misaka-mil-shield-stark-verify/stark-backend-a2-surface"]` は**宣言するが audit-gated `[patch]` なしでは UNBUILDABLE**（`register_public_surface_table` が無く E0599）= 意図した fail-closed（監査済み patch が pin されるまで誰も A2 acceptance を有効化できない）。`kaspad/Cargo.toml` に `evm-shield-stark = ["evm", "kaspa-evm/shield-stark-backend"]` を追加し、node が manifest 編集なしで実 back-half を有効化可能に。default node は INERT verifier を link。
2. **activation-story doc 修正**（PARTIALLY_TRUE への対応）: `kaspa-evm/src/shielded.rs` と `docs/mil-shield-audit-readiness.md` の要約を「fence flip + policy change」から **実 A7 5-step sequence**へ修正 — (1) build-graph feature、(2) audit-gated A2 `[patch]`、(3) vk-pinning ceremony、(4) fence flip、(5) policy flip。readiness.md §7 を authoritative runbook として参照。
3. **CI activation-feature-graph compile gate**（`.github/workflows/ci.yaml` に新 job）: `cargo check -p kaspad --features evm`（activation base graph）と `cargo check -p kaspa-evm --features shield-stark-backend`（実 verify back-half forwarding）を compile。「exact activation config が compile する」gap を閉鎖。

**残余（正直な開示、外部/数週間）:** H-02(b) A2 `[patch]` の pin は **A6-gated**（監査済み recursion patch の ceremony 時 pin）。H-02(d) **reproducible + signed release binary**（clean checkout・local patch なしで exact release binary を build、feature/dependency commit を attest、2 独立 build が bit-identical accept/reject）は**外部/数週間**。これらは compile gate では代替できず、release engineering + ceremony の作業。

### H-03 [High] production client prover が stub のままで circuit 4 にも未対応

**監査の主張:** public client-side `prove()` API は circuit 1/2 で `BackendPending` を返し circuit 4 を unknown 扱い。bench program は production prover API ではなく、stable artifact provenance・wallet/provider integration・release 互換性を提供しない。

**証拠行（監査引用）:** `mil/shield-stark-prove/src/lib.rs:85-111`、`docs/bench/plonky3-shield-air/README.md:40-42, 115`

**Triage 判定: PARTIALLY_TRUE。** 「prover は stub」は事実（実 prover は未実装）。ただし監査が正しく指摘した bug は **circuit 4 が `UnknownCircuit(4)` として誤報される** 点であり、これは修正すべき API honesty の不整合。実 prover の実装は本質的に**数週間規模の外部作業**。

**対応（commit `bf6c319`、Lane B）:**

- `prove()` が circuit 4（`CIRCUIT_PROVIDER_CLAIM_V2`）を認識し、circuit 1/2 と同じく `BackendPending` を返すよう修正（`mil/shield-stark-prove/src/lib.rs`）。既知の凍結 circuit（AIR 実在・in-consensus verifier 登録済み・prover のみ pending）に対して `BackendPending` を返すのが honest な回答であり、`UnknownCircuit` は誤解を招く。test は 1/2/4 → `BackendPending`、未知 version（3, 999）→ `UnknownCircuit` を assert（6 passed）。

**残余（正直な開示、外部/数週間）:** **real production prover crate**（全 enabled circuit 対応、node と同一 versioned schema/manifest param/entropy/recursion-A2 surface/VK ceremony artifact、secure-randomness failure を明示 error 化）は**数週間規模**。**M-01/m1 の real-proof differential はこの実 prover に依存**するため、実 prover 着地までは M-01 も閉じられない。

---

## 4. Medium

### M-01 [Medium] P4 real-proof differential が Provider Claim を end-to-end で覆っていない

**監査の主張:** recursion/A2 pipeline は spend statement を対象。claim-v2 には flat AIR と static/reference test があるが、392-byte statement を recursion→A2→node verifier→F006→`MilShieldedEscrow` まで運ぶ production artifact が無い。CI も real-artifact E2E/cross-arch/fuzz を別 infra の pending 作業と記載。

**証拠行（監査引用）:** `docs/bench/plonky3-shield-air/recursive_spend.rs:1399-1418, 1492-1514, 1764-1782`、`docs/bench/plonky3-shield-air/claim_v2.rs:165-179, 884-895`、`.github/workflows/ci.yaml:137-143`

**Triage 判定: TRUE_GAP（監査正）。本対応では閉鎖しない。** claim-v2 の real-proof E2E corpus は **H-03 の実 prover に依存**する（並行 hand encoder ではなく frozen schema manifest から statement を生成する要件）。実 prover 着地後に、各 enabled circuit で reference relation→flat AIR→recursive proof→A2 surface→node verifier→F006 ABI→contract state transition を 1 本の required P4 corpus として統合する。**外部/数週間**（H-03 の後段）。H-01 の ctx mismatch がまさにこの種の cross-layer defect であったことは監査の指摘どおりであり、本対応で H-01 を閉じたことが当該 corpus 完成前の暫定緩和になっている。

### M-02 [Medium] A2 node binding が untyped で public_surface の一意性を要求しない

**監査の主張:** `statement_is_bound` は任意の non-primitive table の public-value vector が statement encoding と一致すれば受理し（`contains`）、`public_surface` operation が正確に 1 つ存在し期待 shape/schema を持つことを要求しない。値制御可能または statement 無関係な別 table があると、inner statement 由来 surface でなくその table へ結び付け得る。

**証拠行（監査引用）:** `mil/shield-stark-verify/src/lib.rs:220-239, 600-676`

**Triage 判定: PARTIALLY_TRUE（defense-in-depth gap）。** node が返す値は `public_values` のみで op type を持たないため、監査の言う semantic ambiguity は実在。ただし exact VK pin が現時点の surface を狭めているため即時 exploit ではない。

**対応（commit `b7316df`、Lane C）:**

- `statement_is_bound`（現ツリー `mil/shield-stark-verify/src/lib.rs:251`）を **EXACTLY ONE** non-primitive table が statement を surface することを要求する fail-closed rule に変更: `surfaced.iter().filter(|t| *t == &expected).count() == 1`。ZERO surfacing（crypto-valid だが unbound = replayable、critical case）と MORE THAN ONE（ambiguous/duplicate）の双方を拒否。旧 `contains`（accept-on-ANY）を置換。+1 test。

**残余（正直な開示、外部/数週間 — soundness 半分）:** 完全に sound な rule は surface table を `public_surface` NpoTypeId（op type）で選択し、別 op type の decoy table（値が偶然一致）を **TYPE で排除**する。この op-type discriminator は audit-gated A2-patched recursion tree（`register_public_surface_table`、`docs/bench/plonky3-recursion-a2-surfacing.diff`）にのみ存在し、その `PublicSurfaceAir` first-row 制約が **patch 内の数週間規模 soundness 半分**。それが着地するまで uniqueness-by-content が surfaced vector で可能な最も厳密な node 側 check。

### M-03（K-01 freeze）[Medium] K-01 機構は改善したが activation trust anchor が原子的に凍結されていない

**監査の主張:** independent manifest は circuit version/schema/field/config/transcript KAT/table order/metadata/actual preprocessed commitment を bind し前回の circular A3 問題を実質修正したが、全 circuit で `vk_hash=None`・`preprocessed_commitment=None`・`a2_patch_sha256=None`、circuit 3 も不在。release 前に required tuple が all-or-none で揃うことを code で強制していない。

**証拠行（監査引用）:** `mil/shield-stark-verify/src/manifest.rs:41-53, 112-129, 135-177`、`mil/shield-stark-verify/src/lib.rs:287-316, 646-657`

**Triage 判定: Operational gate（監査同意）。** 機構は完備・fail-closed で安全だが activation-ready ではない、という監査の位置付けは正確。原子凍結（all-or-none freeze record）は本質的に ceremony 作業。

**対応（commit `b7316df`、Lane C — m3）:**

- A2 patch の on-disk SHA-256 を manifest に pin（`mil/shield-stark-verify/src/manifest.rs::A2_PATCH_SHA256_ONDISK = "28e6d560bb1e56ec64c9598d49f921ece6f82e54a3d32746d9bb3da04a3d53d6"`）。embedded diff を hash し cross-check する test（`a2_patch_diff_hash_matches_the_pinned_manifest_value`）を追加し、patch file と manifest が silent drift しないことを保証（sha2 を dev-dep 追加、verify 19→21）。凍結される per-circuit `a2_patch_sha256` は必ずこの on-disk pin と一致する。

**残余（正直な開示、外部 ceremony）:** **vk/patch freeze ceremony** — circuit ごとに version/statement schema hash/exact source+dependency hash/**audited** A2 patch hash/field-config/transcript KAT/**vk_hash**/**raw preprocessed commitment**/resource shape/**signed artifact hash** を 1 つの atomic freeze record とし、必須 field の一部が unset な build を拒否する強制、および独立 ceremony recomputation の一致確認。circuit 3 は full composition audit 後にのみ追加。これは回路確定（C-03 閉鎖）後の external/operational 作業。

### M-04 [Medium] Escrow が claim circuit version を snapshot または強制していない

**監査の主張:** 各 escrow は 1 つの `snapshotVk` のみ snapshot する一方、contract は circuit 2 と 4 へ hardcode された複数 claim 関数を公開する。将来の receipt circuit 3 は comment のみで dispatch がない。strict per-circuit K-01 では VK hash が回路ごとに異なるため、1 つの unversioned snapshot で複数 relation を曖昧なく認可できない。governance rotation 前に開いた escrow が snapshot VK と対応しない claim 関数を選べる。

**証拠行（監査引用）:** `contracts/mil/src/MilShieldedEscrow.sol:80-93, 161-199, 448-477`、`mil/shield-stark-verify/src/manifest.rs:165-177`

**Triage 判定: TRUE_GAP（監査正）→ 契約層で閉鎖。**

**対応（commit `b7316df`、Lane C — m4）:**

- `Escrow` struct に `uint16 snapshotClaimCircuit` を追加し、`openBlind` 時に governance-pinned `activeClaimCircuit` を凍結（M-04 の root/VK/price freeze と同様）。onlyOwner setter `setActiveClaimCircuit`（`0`=unpinned=両 path 受理=pre-m4 behavior、`2`/`4`=cohort lock、他値は `BadLen` 拒否 = 検証不能 circuit に pin 不可）。`claimAnon` は circuit 2、`claimAnonV2` は circuit 4 を `_assertClaimCircuit` で verify 前に assert（**契約自身が wrong-circuit claim を F006 proof と独立に拒否** = defense-in-depth）。rotation between open and claim が in-flight escrow を別 circuit へ retarget できない。+4 forge test（wrong-circuit 拒否 / happy path / setter guard / unpinned-open-either-path）。

**残余（正直な開示）:** receipt-required escrow から legacy circuit を呼べなくする恒久無効化と、in-flight escrow の migration/refund rule の完全定義は C-P6（circuit 3）着地時に確定する。現状は unpinned=`0` で pre-m4 互換、pin 時に cohort を lock する可逆な段階実装。

### M-05 [Medium] production field/backend 方針と実装 verifier が不一致

**監査の主張:** ADR-0035 は S-two/Circle-STARK over M31 を production backend、Plonky3 を fallback とするが、実装 verifier/manifest/transcript KAT/A2 patch/proof format/type-level check は BabyBear/Plonky3 固有。config swap では済まない。BabyBear で audit/ceremony 後に M31/Circle へ変更すると proof format/transcript/field encoding/AIR assumption/VK/resource/監査 scope が無効化。

**証拠行（監査引用）:** `docs/adr/0035-mil-shield-stark-backend-selection.md:164-202`、`mil/shield-stark-verify/src/manifest.rs:83-103, 141-160`、`mil/shield-stark-verify/src/lib.rs:614-624`、`mil/shield-stark-verify/Cargo.toml:21-45`

**Triage 判定: PARTIALLY_TRUE。** 実装は既に BabyBear/Plonky3-recursion で一貫しており（manifest の `field_tag=0 // BabyBear`、`poseidon2_id=0x0416`、`ext_degree=4`、`recursion_rev=PINNED_RECURSION_REV`）、gap は **ADR doc が実装より前の M31 front-runner 記述を残していた doc 不整合**。監査が警告する「BabyBear で ceremony 後に M31 へ変更」のリスクは、doc を実装に合わせることで解消。

**対応（commit `b7316df`、Lane C — m5）:**

- ADR-0035 §5 に **superseding note** を追加: **shipping production backend は Plonky3-recursion（BabyBear）**（in-consensus verifier が凍結される field）、**S-two/Circle-STARK（M31）は pre-activation cross-check / target**（fence flip 前に評価、現 manifest は pin しない）と明記。§4 の bench が KoalaBear で採取された点を反映し、**BabyBear vs KoalaBear の naming を manifest.rs の frozen field（BabyBear）に統一**（両者は同 degree-4/width-16 Poseidon2 Circle-STARK family で sizing 結論は共通、正規は BabyBear pin）。field 変更は new `circuit_version` + re-ceremony（K-01）を要すると明記。

**残余（正直な開示、外部 governance）:** 外部監査と VK freeze の前に **governance-level で final backend を確定**する。BabyBear/Plonky3 採用ならこの supersession が正式改定、M31/Circle 採用なら選択 stack 実装 + AIR/recursion/transcript/resource/differential の全面再監査。実装は既に BabyBear で一貫しているため後者は現時点で非選択。

### M-06 [Medium] security CI と release provenance が未完成

**監査の主張:** 新 CI job は有用だが A2 feature compilation・real claim/spend artifact・aarch64/no-SIMD determinism・production prover・required differential mutation corpus・gas/resource benchmark を含まない。Foundry は mutable `@v1`、forge-std は immutable commit でなく tag。branch protection と signed release evidence は archive 外で未確認。

**証拠行（監査引用）:** `.github/workflows/ci.yaml:137-185`、`mil/shield-stark-verify/Cargo.toml:46-58`、`docs/security/MISAKA-Audit-Reaudit-Response-fe3d6fa-2026-07-12.md:155-169, 173-190`

**Triage 判定: PARTIALLY_TRUE。** 「exact activation config が compile されない」部分は本対応で閉鎖。残る infra（cross-arch/fuzz-in-CI/signed provenance/immutable pin/benchmark）は監査どおり未完成で、本質的に CI/release-engineering の外部作業。

**対応（commit `bf6c319`、Lane B）:**

- 新 CI job **"Activation Feature Graph (H-02)"** が `cargo check -p kaspad --features evm` と `cargo check -p kaspa-evm --features shield-stark-backend` を compile（activation config が green で通ることを保証）。third-party action は commit-pin（`actions/checkout@34e1148…`、`dtolnay/rust-toolchain@29eef33…` 等）。forge-std は release tag `v1.9.4`（branch ではない）で据置。

**残余（正直な開示、外部/数週間 — CI infra）:** exact release feature graph（A2-patched dependency 込み）・全 circuit real artifact・**x86-64/aarch64/no-SIMD decision parity**・malformed-proof fuzz の CI 配線・contract E2E・client prover・worst-case resource benchmark を immutable required job 化し、**signed provenance**（署名済み test/proof/benchmark artifact を hash 付き保持）を整備する。stark-backend feature 自体が CI job に無い点も含め、これらは release process 側の**数週間規模**作業。

### M-07 [Medium] claim-v2 whole-sompi gate が production pricing path で強制されていない

**監査の主張:** contract は 88% provider share が exact whole sompi でないと意図的 revert（`grossSompi % 25 == 0` と同値）。gateway/provider SDK が quantize すべきと記載されるが in-scope production path に強制実装は無く、quantization は test にのみ現れる。通常の price/token 組合せで gross が 25 の倍数にならず claim が恒久 settle 不能になり、回復は delay 後 refund のみ。

**証拠行（監査引用）:** `contracts/mil/src/MilShieldedEscrow.sol:304-328`、`mil/shield/src/economics.rs:20-45, 229-269`、`mil/shield/tests/anon_provider_claim_e2e.rs:476-491`

**Triage 判定: TRUE_GAP（監査正）。さらに follow-up で helper が dead code だったことを確認 → 閉鎖。** Lane C（`b7316df`）が whole-sompi guard を `mil/provider/src/economics.rs`（`served_gross_sompi`/`checked_gross_sompi`/`quantize_gross_up`/`is_whole_sompi_gross`、`WHOLE_SOMPI_GROSS_STEP=25`）として追加したが、**Medium-lane の独立検証で当該 helper が repo 全域で ZERO callers = pricing entry で何も強制していない dead code** であることを発見。監査の「production path に強制実装が無い」という指摘を helper 追加だけでは閉じられていなかった。

**対応（helper: `b7316df` / wiring: `f51a106`）:**

- `f51a106` が guard を provider の実 gross 経路 2 箇所に配線:
  - `mil/provider/src/store.rs::SessionRecord::from_outcome`（**LIVE な settlement-record producer**、main.rs が全 settled session で呼ぶ）が two-sided job cost を `quantize_gross_up` で whole-sompi ladder に UP 量子化（記録 `gross_sompi` は常に 25 の倍数、round-up < 2.5e-7 MSK、任意の settlement が claimable）。
  - `mil/provider/src/config.rs::ServingConfig::shielded_quote_gross_sompi`（source-side reject-mode gate）が uniform-price escrow gross を `checked_gross_sompi` で計算し、**requester が escrow に資金を lock する前に**不 claim 可能な price/token 組合せを拒否。
  - helper を `lib.rs` から re-export。両 call site で escrow-funding SDK path（v1 §8.2）が本 gate を経由すべき旨を documented。test は実関数を driving（`shielded_quote_gate_rejects_unclaimable_gross_at_the_source` = price 2 · 51,000 tokens → gross 102 → `GrossNotWholeSompi` 拒否；`from_outcome_quantizes_gross_onto_the_whole_sompi_ladder`）。provider 39→41 lib。

**残余（正直な開示）:** v0 provider は direct-pay（in-crate escrow なし）。escrow-funding SDK path（v1 §8.2）実装時に `shielded_quote_gross_sompi` 経由を必須化する（現状は両 call site に documented）。permanent revert を dust rule に変える案は別途 governance 判断（現状は revert + source-side quantize 義務）。

### M-08 [Medium] F006 proof・metadata・DA・gas cap が暫定値のまま

**監査の主張:** verifier は最大 1 MiB を受理、manifest metadata bound も意図的に広い。DA reassembly は 8 MiB だが `chunk_proof` は最大 128 MiB descriptor を生成し得る。F006 は 7,500,000 block gas limit に対し 3,000,000 固定 gas を課すが、frozen proof shape/metadata を slow/no-SIMD architecture で測った独立 worst-case benchmark が無い。

**証拠行（監査引用）:** `mil/shield-stark-verify/src/lib.rs:143-165, 629-644`、`mil/shield-stark-verify/src/manifest.rs:92-110, 145-160`、`mil/shield-da/src/lib.rs:31-40, 125-168`、`consensus/core/src/evm/mod.rs:158-161, 215-222`

**Triage 判定: PARTIALLY_TRUE。** DA producer/consumer cap の不整合（producer 128 MiB > consumer 8 MiB）は明確な consistency defect（= L-02 と同一）で本対応で閉鎖。proof/metadata/gas cap の worst-case 較正は本質的に hardware benchmark 作業で外部。

**対応（commit `b7316df`、Lane C — m8）:**

- `mil/shield-da/src/lib.rs::chunk_proof` が `MAX_REASSEMBLED_PROOF_BYTES`（8 MiB、`validate_descriptor`/`reassemble` と同一 ceiling）を超える proof を拒否するよう変更（旧: `MAX_CHUNKS × MAX_CHUNK_BYTES` = 128 MiB）。producer が consumer で reassemble 不能な chunk set を emit できない。+1 regression test（da 13→14）。

**残余（正直な開示、外部 — hardware calibration）:** circuit freeze 時に table count/rows/lanes/public values/proof bytes/DA chunks を exact または狭い bound へ固定し、**slowest supported no-SIMD hardware で worst valid + adversarial reject case を benchmark** して安全 margin 付きで gas/block limit を較正、producer/reassembler/verifier/transaction cap を全一致させる。これは vk ceremony の hardware calibration であり本対応スコープ外。

---

## 5. Low

### L-01 [Low] consensus verifier に silent serialization fallback と expect が残る

**監査の主張:** verifier context 構築に複数の `postcard::to_allocvec(...).unwrap_or_default()`、`compute_vk_hash` に `borsh::to_vec(...).expect(...)`。empty bytes への fallback は error state を潰し、`expect` は panic-free posture と整合しない。

**証拠行（監査引用）:** `mil/shield-stark-verify/src/lib.rs:128-130, 504-570`

**Triage 判定: 監査に同意（Low）。本対応では未閉鎖。** 現 type は serialize 可能で attacker exploit は無く（監査も「maintenance 由来」と明記）、F006 fence が `u64::MAX` の間は consensus-neutral。context 構築と VK hash を typed `Result` 化して全 serialization error を fail-closed にする hardening は **VK freeze ceremony 前の hardening** として実施する（decision-bearing encoding から `unwrap`/`expect`/`unwrap_or_default` を除去）。A7 blocker ではない（監査判定 No）。

### L-02 [Low] DA chunk producer が自分の validator で拒否される proof を受理する

**監査の主張:** `chunk_proof` は 128 MiB まで許可するが `validate_descriptor`/`reassemble` は 8 MiB 超を拒否。producer が返した descriptor/chunk set を同 library の consumer path で処理できない範囲がある。

**証拠行（監査引用）:** `mil/shield-da/src/lib.rs:31-40, 125-168, 202-219`

**Triage 判定: TRUE_GAP → 閉鎖（M-08/m8 と同一 fix、commit `b7316df`）。** `chunk_proof` の producer cap を consumer と同一の `MAX_REASSEMBLED_PROOF_BYTES`（8 MiB）に整合。成功した全 `chunk_proof` 結果が `validate_descriptor` を通り `reassemble` で round-trip することを test で固定（`m08_chunk_proof_producer_cap_aligns_with_reassembly_cap`）。A7 blocker ではない（監査判定 No）。

### L-03 [Low] audit-readiness 文書に矛盾する実装 status が混在する

**監査の主張:** readiness 文書は snapshot c8d729a 時点の「verifier back half と statement binding は未実装」を残しつつ後段で A1/A2/A3 実装と local patch を説明。production field 選択と activation 手順も現 feature graph と不一致。

**証拠行（監査引用）:** `docs/mil-shield-audit-readiness.md:14-23, 69, 130-190, 233-326, 386-419, 457-473`

**Triage 判定: PARTIALLY_TRUE。** activation-story の不整合は本対応で修正、full な snapshot-specific readiness manifest 再生成は follow-up。

**対応（commit `bf6c319`）:** readiness.md の要約行と `kaspa-evm/src/shielded.rs` の comment を実 A7 5-step sequence へ修正し §7 を authoritative runbook として指す（H-02 の一部として）。

**残余（正直な開示）:** implemented / independently reproduced / repository self-reported / pending / operational evidence を明確分離した **snapshot-specific readiness manifest** を生成し、矛盾する追記方式をやめ stale section を削除する doc 作業を follow-up として残す。A7 blocker ではない（監査判定 No）。

---

## 6. 前回指摘（fe3d6fa 監査）の閉鎖状況 — 本監査（d5c8993）の評価と我々の応答

監査報告書「前回 Finding の閉鎖状況」表の各行に対する我々の応答:

| Item | Topic | 監査（d5c8993）の現状評価 | 我々の応答 |
|---|---|---|---|
| C-01 | claim-v2 public share / note-value binding | schema/relation/AIR レベルで **Closed**（392-byte schema、PI_SHARE=AMT、contract share field 確認）。real recursive/contract proof は M-01 に残る | 同意。schema/AIR binding は `2f42976`（前回）で閉鎖済み。real-proof E2E は H-03 実 prover 依存（M-01、外部） |
| C-02 | Solidity/Rust economic split parity | 意味論上 **Closed**（12 共有 vector を独立 Python 再計算し全一致） | 同意。ECO-01/ECO-02 が独立再現。native suite 再実行は §8 の forge/rust で green |
| C-03 | full receipt authorization | **Open**（receipt/signature/counter/pricing constraint および circuit-3 dispatch なし） | 同意。§2 参照。本対応で SHAKE threading + ExpandA/matvec AIR を前進（SOUND）、統合は未達で Open のまま |
| K-01 | A3 circuit/VK binding | 機構は大幅改善、**operational freeze は Open**（independent manifest + actual commitment binding 着地、全 anchor は None、A2 source は release graph 外） | 同意。§4 M-03 参照。m3 で on-disk patch-hash を pin、原子 freeze は ceremony（外部） |
| M-03/M-04 | design / snapshot invariant | **Partial**（root/VK/price snapshot は存在、claim circuit version 未 snapshot、C-P6 migration 未定義） | 部分対応。claim circuit version 未 snapshot は §4 M-04（`b7316df`）で閉鎖。C-P6 migration は C-03 着地時 |
| M-05 | panic/resource hardening | **Partial**（metadata cap 着地、serialization fallback/expect と ceremony tightening が残る） | 同意。serialization fallback/expect は §5 L-01（ceremony hardening へ）。ceremony tightening は M-03 の外部 freeze |
| M-07 | activation CI | **Partial**（reference/backend/Forge job 着地、exact A2 release/real artifact/cross-arch/prover/fuzz/provenance が残る） | 同意。§4 M-06 参照。activation-feature-graph compile gate を追加（`bf6c319`）、残りは CI infra（外部/数週間） |
| A7 | activation | **NO-GO**（Critical/High と roadmap blocker が残る、全 preset で F006=u64::MAX） | 全面同意。fence 維持、claims disabled 維持 |

---

## 7. A7 activation acceptance gate（G1-G12）— 本対応後の自己評価

| Gate | 最低 evidence | 監査判定 | 本対応後（自己評価、再監査で要確認） |
|---|---|---|---|
| G1 Relation parity | 全 enabled circuit で reference/AIR/recursion/surface/F006/contract 一致 | PARTIAL | **前進**（H-01 で ctx 層の乖離を閉鎖 `266bbe3`）。real-proof 一致は M-01/H-03（外部）待ち → PARTIAL のまま |
| G2 C-P6 full receipt | 資金移動 claim へ receipt/signature/counter/pricing を composition | FAIL | **OPEN（同意）** — sub-gadget + wiring 前進、統合は未達（§2）。数週間規模 |
| G3 K-01 freeze | VK/raw commitment/source-dep-A2 hash/schema/params/shape を atomic signed manifest へ固定 | FAIL | 機構完備 + m3 patch-hash pin（`b7316df`）。**原子 freeze は ceremony（外部）** → FAIL のまま |
| G4 Typed A2 | exactly one manifest-pinned public_surface | FAIL | node 側 uniqueness を閉鎖（`b7316df`）。**type-based soundness 半分は audit-gated patch 内（外部）** → FAIL のまま |
| G5 Production prover | 全 enabled circuit 対応 + secure entropy/provenance | FAIL | API honesty 修正（circuit-4 → BackendPending、`bf6c319`）。**実 prover は外部/数週間** → FAIL のまま |
| G6 P4 real-proof | F006/contract まで positive/mutation-negative | FAIL | **OPEN（同意）** — H-03 実 prover 依存（M-01、外部） |
| G7 SP-04 portability | x86-64/aarch64/no-SIMD で decision 一致 | FAIL | **OPEN（同意）** — cross-arch CI infra（M-06、外部） |
| G8 Resource/gas | slowest hardware worst-case benchmark と exact cap | FAIL | DA producer/consumer cap を整合（`b7316df`）。**hardware 較正は外部**（M-08） → FAIL のまま |
| G9 CI/release | exact feature/patch/immutable tool/required check/signed artifact | FAIL | activation-feature-graph compile gate 追加（`bf6c319`）。**signed provenance/immutable/cross-arch は外部** → FAIL のまま |
| G10 Independent audit | native/upstream audit | PARTIAL | **OPEN（同意）** — 本 static follow-up は native/upstream audit を代替しない。本書 + 修正 commit 群がその入力 |
| G11 Canary/rollback | capped canary/monitoring/pause-refund-rollback rehearsal | NOT EVIDENCED | **OPEN（同意）** — 運用 rehearsal 未実施 |
| G12 Activation-only release | final diff を manifest value と activation height へ限定 | NOT AVAILABLE | **OPEN（同意）** — G2/G3/G10/G11 の後段 |

**結論: G2–G12 が open/partial である限り A7 = NO-GO。監査と完全に一致する。** F006 fence（全 preset `u64::MAX`）を維持し、anonymous claim を disabled のまま維持し、Critical/High および activation-blocking Medium が real/reproducible evidence で閉鎖され新規外部監査を通るまで claim VK を freeze/deploy しない。

---

## 8. ビルド・テスト証跡（§results — 本報告書作成時の最終再実行、verbatim）

すべて remediation tip `266bbe3` の作業ツリーで最終再実行した。commit で実行:
`cd contracts/mil && forge test`; `cargo test -p misaka-mil-shield --release`; `cargo test -p misaka-mil-shield-stark-verify`; `cargo test -p misaka-mil-shield-da`; `cargo test -p misaka-mil-provider`; `cargo check -p kaspa-evm --features shield-stark-backend`; `cargo check -p kaspad --features evm`。

```
# forge test (contracts/mil, 9 suites)
Ran 9 test suites in 18.60ms (82.74ms CPU time): 75 tests passed, 0 failed, 0 skipped (75 total tests)
  … 含む test_m4_setActiveClaimCircuit_owner_and_valid / test_m4_snapshot_circuit_happy_path /
    test_m4_unpinned_open_accepts_either_path_despite_later_pin / test_m4_wrong_circuit_claim_rejected

# cargo test -p misaka-mil-shield --release
     Running unittests src/lib.rs
test result: ok. 43 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
     Running tests/anon_provider_claim_e2e.rs
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
     Running tests/differential_corpus.rs
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
     Running tests/private_transfer_e2e.rs
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
   Doc-tests misaka_mil_shield
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
# → 59/59 (43 unit + 10 + 2 + 4)。unit 42→43 は H-01 の claim_ctx differential test 追加分。

# cargo test -p misaka-mil-shield-stark-verify (default = INERT verifier)
     Running unittests src/lib.rs
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
   Doc-tests: test result: ok. 0 passed; 0 failed; …
# → 21/21 (19→21 は m3 A2 patch-hash pin の drift test 2 本)。STARK arm は CircuitVkNotFrozen fail-closed。

# cargo test -p misaka-mil-shield-da
     Running unittests src/lib.rs
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
# → 14/14 (13→14 は m8 producer/consumer cap alignment 回帰テスト)。

# cargo test -p misaka-mil-provider
     Running unittests src/lib.rs
test result: ok. 41 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
     Running unittests src/main.rs
test result: ok. 0 passed; 0 failed; …
     Running tests/e2e_tcp.rs
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
   Doc-tests: test result: ok. 0 passed; …
# → 42/42 (41 lib + 1 e2e)。m7 helper + quote-path wiring テストを含む。

# cargo check -p kaspa-evm --features shield-stark-backend
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.78s   # EVM_CHECK_EXIT=0

# cargo check -p kaspad --features evm
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 12.38s  # KASPAD_CHECK_EXIT=0
```

**独立敵対的検証:** H-01 は .119（`~/Plonky3/shield-air`）で claim_v2 AIR を再証明（`VERIFY ok` prove 2.9s / verify 73.5ms、105,537 cols × 32 rows、proof 5,166,476 B、`PRIVACY OK`、negative 8/8 拒否 — `--wrong-ctx` 含む、vendored copy byte-identical）。C-P6 の 2 AIR（`40d183b`/`5139412`）は full `l=7` in-AIR ExpandA 行が libcrux-pinned reference に係数厳密一致で verdict **SOUND**。

---

## 9. 残フォローアップ（正直な外部 / 数週間ゲート — overclaim しない）

以下は本対応で**閉じていない**。いずれも実証明 + 新規外部監査なしに閉じたと主張しない。**これらが real proof + fresh audit で閉じるまで A7 は NO-GO を維持し、F006 fence は `u64::MAX` のまま**であることに我々は同意する。

| 項目 | 種別 | 内容 |
|---|---|---|
| **C-03 / G2** | Critical activation blocker | C-P6 composition item (iv) single-relation composition / (v) libcrux accept-diff / (vi) 外部監査。sub-gadget + wiring 完成 ≠ full-receipt-circuit 統合。数週間規模 |
| **H-02(b)** | 外部（A6-gated） | A2 `[patch]` の pin（監査済み recursion patch の ceremony 時 pin） |
| **H-02(d)** | 外部 | reproducible + signed release binary（clean checkout・no local patch・feature/dependency attest・2 独立 build が bit-identical） |
| **H-03 / M-01（m1）** | 外部/数週間 | real production prover crate。M-01 の real-proof differential はこれに依存 |
| **M-02（m2）soundness 半分** | 外部/数週間 | `PublicSurfaceAir` first-row binding（audit-gated patch 内の type-based surface selection） |
| **M-03（m3）freeze ceremony** | 外部 ceremony | vk_hash / raw preprocessed commitment / audited a2_patch_sha256 / signed artifact の atomic all-or-none freeze。回路確定後 |
| **M-06（m6）CI infra** | 外部/数週間 | aarch64/no-SIMD parity・fuzz-in-CI・signed provenance・immutable pin・resource benchmark の required job 化 |
| **M-08（m8）hardware calibration** | 外部 | proof/metadata/gas cap の slowest no-SIMD hardware worst-case 較正 |
| **L-01** | ceremony hardening | verifier context / VK hash の typed-`Result` 化（silent fallback/expect 除去） |
| **L-03** | doc follow-up | snapshot-specific readiness manifest 再生成 + stale section 削除 |
| **G10/G11/G12** | 外部・運用 | 独立外部監査 → canary/monitoring/rollback rehearsal → activation-height-only release 差分監査 |

---

## 10. 再監査提出物チェックリスト

- [x] 修正 commit hash — §0 表（`266bbe3…` H-01 / `bf6c319…` H-02・H-03・M-06・L-03 / `b7316df…` M-02・M-03・M-04・M-05・M-08・L-02 + m7 helper / `f51a106…` m7 wiring / `40d183b…`・`5139412…` C-P6 前進）
- [x] source ブランチ / HEAD — `feat/mil-v0` / `266bbe3`（+ 本書コミット）
- [x] `cargo test` / `forge test` 結果 — §8（最終再実行値、verbatim）
- [x] 実 proof での positive/negative E2E — §3 H-01（.119、negative 8/8 に `--wrong-ctx` 追加）
- [x] TRUE_GAP / PARTIALLY_TRUE / STALE の file:line 判定 — §2–§5
- [x] C-P6 前進の SOUND 検証 — §2（SHAKE threading + ExpandA/matvec、libcrux-pinned 係数一致）
- [ ] C-03 統合（item iv/v/vi） — 数週間規模、閉鎖後に差分再監査を要請
- [ ] 実 prover / M-01 real-proof corpus（H-03） — 外部/数週間
- [ ] VK/patch atomic freeze ceremony（M-03） — 回路確定後、外部
- [ ] CI infra / cross-arch / signed provenance（M-06） — 外部/数週間
- [ ] 独立外部監査 / canary・rollback rehearsal / activation-height-only release 再監査（G10/G11/G12） — 外部・運用

> 本対応は静的修正 + 実証明 E2E（H-01）+ C-P6 sub-gadget/wiring の SOUND 前進 + 正直な外部ゲート開示であり、**A7 activation の解除を主張するものではない**。C-03 統合・実 prover・atomic freeze ceremony・CI infra の後、本書と修正 commit 群を入力として G10 独立監査へ進むことを推奨する。**F006 fence（全 preset `u64::MAX`）と claims disabled は本対応後も維持する。**
