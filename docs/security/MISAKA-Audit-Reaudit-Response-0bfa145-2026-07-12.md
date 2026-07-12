# MISAKA MIL ShieldedPool 追跡監査（0bfa145）修正対応報告書（再監査提出用）

**対応日:** 2026-07-12
**対象ブランチ:** `feat/mil-v0`
**監査 snapshot:** `0bfa145a6e37e303bfda6942a5db775050c109d6`（`rusty-kaspa-feat-mil-v0-0bfa145.zip`、input archive SHA-256 `446f1e104b080459d3bb99bb2f0054de61e1921af780b5a7a42ec57d095a9684`）
**対象監査:** `MISAKA MIL Shielded Pool セキュリティ再監査報告書 — Snapshot 0bfa145`（基準 `d5c8993`→`0bfa145` 差分、独立 static / semantic follow-up review、Critical 1 / High 2 / Medium 8 / Low 2、A7 blocker 11 件）
**修正後 HEAD（remediation tip）:** `8208ee02af2624cc43daf1b60aac485455bf74a2`（本報告書コミットはこの直上）

> **A7 activation 判定について:** 監査の **NO-GO に全面同意する**。本対応で M-04 / M-07 / M-09 をコードで閉鎖し、H-02 / M-02 / M-06 を「build-graph・node-side・honesty レベルで前進、soundness/infra の残余は外部/数週間ゲート」として位置付け直し、C-03 は inventory の残 FREE gap（hint canonicity・pk_receipt bridge）を sub-gadget として閉じ ExpandA stream binding を BOUND 化したが **統合（full receipt-circuit integration）は未達で OPEN のまま**である。H-03 / M-01 / M-03 / M-08 / L-01 / L-03 は本対応で「閉鎖」を主張せず外部/数週間ゲートとして残す。**F006 fence（全 4 preset `u64::MAX`）は本対応で一切変更しておらず、anonymous claim も default disabled のまま維持する。** VK/manifest anchor は全 circuit で未凍結（`vk_hash: None`）。監査が §9 で列挙した containment control をすべて閉じたまま保つ。

---

## 0. エグゼクティブサマリー

- **C-03（C-P6 full receipt authorization）は監査に同意して OPEN のまま = Critical activation blocker を維持する。** 本対応で inventory の残る 2 つの真の gap を sub-gadget として閉じた（wire 19 **hint canonicity** = `cf157f2`、wire 24 **pk_receipt bridge** `pk_receipt_hash == H(pk)` = 本 workflow `8208ee0`、いずれも敵対的検証で SOUND）が、**単一 relation への composition（item iv）・circuit-3 dispatch・real-proof E2E は未達**であり、**sub-gadget の完成 ≠ full-receipt-circuit の統合**であることを明言する。監査が新たに要求した wire ごとの soundness inventory（`ce8fdb1`、design §7）はまさに「ほぼ全 wire が `GADGET_ONLY_NOT_WIRED`（gadget は証明済み・composition = recursion 配線が未達）」であることを我々自身が開示したものであり、C-03 が Critical のまま留まる根拠と一致する。
- **監査が正しく指摘した 3 つの実 gap をコードで閉鎖した:** M-04（escrow が circuit/VK を別 setter から snapshot し mixed pair / wildcard-0 を許す `TRUE_GAP`）→ 契約層で atomic policy に集約、M-07（`quantize_gross_up(u64::MAX)` が 25 の倍数でない値を返す `TRUE_GAP`）→ overflow band を clamp-down、M-09（SHAKE squeeze の公開 byte が個別に 8-bit 拘束されず `(52,18)`≡`(308,17)` の非 canonical pair を許す `TRUE_GAP`）→ 出力 byte を 8-bit range-check。
- **修正コミット（いずれも `0bfa145` の後、`feat/mil-v0` 上、rebase なし）:**

| Finding | Triage 判定 | 修正/前進 commit |
|---|---|---|
| C-03 | 監査に同意（Open は正当） | `577d33e`（ExpandA→`pi_stream` binding）+ `ce8fdb1`（soundness-wire inventory + ADR-0035）+ `cf157f2`（hint canonicity AIR）+ `8208ee0`（pk_receipt bridge、本 workflow）= **PROGRESS のみ、閉鎖せず** |
| H-02 | PARTIALLY_TRUE（combined graph は実在 gap、A2 patch/signed は外部） | `36d67cbe465bb78fa3b1206cdd6bd7f9473b8840` |
| H-03 | PARTIALLY_TRUE（circuit-4 の honesty は前回閉鎖済、実 prover は外部/数週間） | 未閉鎖 — 外部（`0bfa145` に既存の `bf6c319` API honesty で BackendPending 化済） |
| M-01 | TRUE_GAP（H-03 実 prover 依存、数週間） | 未閉鎖 — 外部（実 prover 着地後） |
| M-02 | PARTIALLY_TRUE（node 側 empty-fail-closed を追加、TYPE-selection 半分は patch 内） | `f7ef99455d04655c55bb03da324b493bfd78e7bd` |
| M-03 | Operational gate（機構は完備、原子 freeze は ceremony） | 未閉鎖 — 外部（`0bfa145` に既存の `b7316df` on-disk patch-hash pin） |
| M-04 | **TRUE_GAP → 契約層で閉鎖** | `f7ef99455d04655c55bb03da324b493bfd78e7bd` |
| M-06 | PARTIALLY_TRUE（combined compile gate を追加、CI infra 本体は外部） | `36d67cbe465bb78fa3b1206cdd6bd7f9473b8840` |
| M-07 | **TRUE_GAP（boundary bug）→ 閉鎖** | `bae4a3f9cf7d426ff32860917fd752c02a0074a3` |
| M-08 | PARTIALLY_TRUE（DA cap は `0bfa145` で閉鎖済、hardware 較正は外部） | 未閉鎖 — 外部（DA cap は `0bfa145` に既存の `b7316df`、監査 §7.4 で Closed 確認） |
| M-09 | **TRUE_GAP → 閉鎖** | `6d07a9681c59525f374336873415c673a9479574` |
| L-01 | 判定同意（Low、A7 blocker でない） | 未閉鎖 — ceremony hardening へ |
| L-03 | PARTIALLY_TRUE（activation-story は前回修正済、full manifest 再生成は follow-up） | 未閉鎖 — doc follow-up |

- **検証方式:** 各 finding を read-only の敵対的 triage（file:line を `0bfa145` と現ツリー両方で突合）→ 修正レーン → 独立検証で処理した。C-P6 の新 AIR（`hint_canonicity_air.rs`・`pk_receipt_bind_air.rs`）は .119（`~/Plonky3/shield-air`）で再証明（positive VERIFY ok + PRIVACY OK + 全 negative 拒否）し、vendored copy を byte-identical（sha256 一致）で確認した。
- **テスト（本報告書作成時に最終再実行、§8 に verbatim）:** forge **76/76**、`misaka-mil-shield` release **59/59**（43+10+2+4）、`misaka-mil-shield-stark-verify` **22/22**、`misaka-mil-shield-da` **14/14**、`misaka-mil-provider` **43/43**（42 lib + 1 e2e）。
- **コンセンサス安全性:** 全変更は F006 fence（全 preset `u64::MAX`）の内側で inert。circuit 4 は decode/verify 可能だが **未登録・未凍結**（`CircuitVkNotFrozen` fail-closed）。circuit 3（C-P6）は schema/manifest/prover/contract dispatch のいずれにも意図的に不在。
- **未デプロイ:** push / activation / release はいずれも未実施。

---

## 1. 修正方針と検証

1. 監査の各 finding について、引用 file:line を **`0bfa145` と現ツリーの両方**に対して検証した。TRUE gap と scanner artifact / stale の分離を第一義とし、本監査は前回同様に精度が高く、**M-04（mixed pair / wildcard-0）・M-07（u64::MAX boundary）・M-09（非 canonical byte pair）は監査の PoC どおりの TRUE_GAP と確認した**。
2. finding ごとに read-only 敵対的 triage → 修正レーン → 独立検証。C-P6 の 2 つの新 AIR は .119 で in-AIR 証明。資金経路（Solidity `MilShieldedEscrow.sol`）の変更は M-04（atomic claim policy）に限定し、資金分配ロジックは無変更。
3. コミットは finding 群単位（C-P6 inventory 前進、H-02/M-06、M-02/M-04、M-07、M-09、pk_receipt bridge）に分け、いずれも並行レーンの上に rebase なしで積んだ。
4. **正直な開示を最優先**した。H-03/M-01/M-03/M-08/L-01/L-03 は本対応で「閉鎖」を主張せず、外部/数週間ゲートの残余を明確に分離して記述する（§9）。監査 §7「Positive Security Changes Confirmed」が確認した `0bfa145` 既存の閉鎖（H-01 ctx 統一・C-01/C-02 value binding・A3/K-01 機構・DA cap）はそのまま維持する。

---

## 2. Critical

### C-03 [Critical] C-P6 full receipt authorization が settlement 経路に統合されていない

**監査の主張:** `claimAnon`/`claimAnonV2` は circuit 2/4 のみを使い、`setActiveClaimCircuit` も 0/2/4 しか許さず receipt circuit 3 を選べない。`ProviderClaimWitness(V2)` は membership / claim secret / Merkle path / payout note / amount を持つが receipt body・ML-DSA 署名・provider receipt 公開鍵・monotonic counter・token/pricing transcript を持たない。`statement_schema.rs` は `schema_for_circuit(3) == None`、verifier manifest も 1/2/4 のみ登録、production prover は 3 を `UnknownCircuit`。ゆえに SHAKE/NTT/UseHint/ExpandA 等の sub-gadget が個別に proof を生成できても資金移動を認可する relation には接続されていない。F006/VK/manifest を有効化し owner が `claimsEnabled=true` にすると、登録 provider は実 session の receipt なしで自身の membership/nullifier/payout proof を作り open escrow を settle でき、per-provider nullifier が異なるため receipt-free claim が繰り返され得る。

**証拠行（監査引用）:** `contracts/mil/src/MilShieldedEscrow.sol:33-38,66-71,152-179,249-382`、`mil/shield/src/provider.rs:17-29,128-196,216-305`、`mil/shield/src/statement_schema.rs:107-185`、`mil/shield-stark-verify/src/manifest.rs:177-189`、`mil/shield-stark-prove/src/lib.rs:94-119`

**Triage 判定: 監査に同意（Open は正当）。本対応では閉鎖しない。** 正直な status:

- **前進（本対応、いずれも PROGRESS のみ）:**
  - `577d33e` — **ExpandA SHAKE128 stream → `pi_stream` soundness binding**（`docs/bench/plonky3-shield-air/expanda_stream_bind_air.rs`、1131 行新規）。full-stream byte-position・domain separation（nonce 順 `ρ‖[j,i]`）・ρ binding の 3 wire を **row i=0 について BOUND** 化（3 boundary negatives）。design §7 wire 1–3 が `GADGET_ONLY_NOT_WIRED`/`FREE` → `BOUND (row i=0)` へ移る。
  - `ce8fdb1` — **soundness-wire inventory**（`docs/mil-shield-cp6-mldsa-in-circuit-design.md` §7.1、26 wire を列挙）+ ADR-0035 の measurement-forced-recursion note。**「ほぼ全 wire が `GADGET_ONLY_NOT_WIRED`（gadget は証明済みだが I/O が隣接 stage に未 bind、`num_pis=0`）」であることを我々自身が明示開示**し、監査 §1.2-①「sub-gadget が揃った段階であり receipt authorization として完成していない」と同一結論に到達している。
  - `cf157f2` — **HintBitUnpack canonicity AIR**（`docs/bench/plonky3-shield-air/hint_canonicity_air.rs`、572 行新規）。inventory の **wire 19（FREE — 従来 proven gadget が皆無）**を閉鎖。per-position strict-increase + unused-byte-zero を証明し、24 個の実 libcrux ML-DSA-87 hint block に対し reference `HintBitUnpack` の ⊥/accept と一致、3 negatives（`--corrupt-nonincreasing`/`--corrupt-padnonzero`/`--corrupt-crossboundary`）が拒否。
  - `8208ee0`（**本 workflow**）— **pk_receipt bridge `pk_receipt_hash == H(pk)` IN-AIR**（`docs/bench/plonky3-shield-air/pk_receipt_bind_air.rs`、757 行新規）。inventory の **wire 24（FREE — claim が `pk_receipt_hash` を無条件に信頼、item iv の最終消費者）**を **standalone gadget として BOUND** 化。2592-byte ML-DSA-87 vk `pk` を 22 回の keyed-BLAKE2b-512 compression（key-block 1 + `⌈2592/128⌉`=21 message block、32 行 pad）で多ブロック連鎖し、公開 64-byte `pk_receipt_hash` が `blake2b_512_keyed("misaka-mil-v1/provider-id", pk)`（= `mil/core/src/ident.rs::provider_id`、`mil/core/src/domains.rs:34` の domain）であることを in-AIR で証明。**prover は任意の `pk_receipt_hash` を leaf に置けなくなり、公開値にハッシュする 2592-byte preimage を trace に提示せねばならない。**
- **残る未達（C-03 が OPEN である理由、いずれも本対応で未着手）:**
  - item (iv) **single-relation composition** — 全 gadget（ExpandA/SampleInBall/UseHint/hint-canonicity/norm/decode/SHAKE multi-block/NTT fwd+inv/matvec/**pk_receipt bridge**）を **一つの `circuit_version=3` constraint system** に統合し、Provider Claim witness・circuit-3 dispatch・receipt transcript・session/counter/pricing と接続する。inventory がまさに「gadget は揃うが cross-stage の I/O binding（`num_pis=0` の解消）がほぼ全 wire で未達」であることを示す。
  - item (v) **libcrux full-signature accept-diff** — 統合回路の accept/reject を libcrux の full ML-DSA-87 verify と differential で一致。
  - item (vi) **外部監査** + Solidity dispatch + real-proof E2E（M-01）。
- **明言:** **sub-gadget の完成 + 一部 wire の in-AIR binding ≠ full-receipt-circuit の統合**である。統合は単一 constraint system・circuit-3 dispatch・contract 原子 settlement を要し、見積りは**数週間規模**。**C-03 が open である限り A7 は NO-GO** という監査の結論に完全に同意する。circuit 3 dispatch の不在は意図した fail-closed であり、監査の Failure シナリオ（`claimsEnabled=true` で receipt 不在の settle が可能になる）は circuit 3 の統合完了時に初めて閉じる。

---

## 3. High

### H-02 [High] exact activation node graph と A2-patched verifier が再現 build されていない

**監査の主張:** `kaspa-evm`/`kaspad` の backend feature forwarding は改善だが、CI の activation job は `kaspad --features evm` と `kaspa-evm --features shield-stark-backend` を**別々に** check し、node が実際に使う `kaspad --features evm-shield-stark` を build しない。feature unification / optional dependency / node-level link failure が検出されない。さらに A2 feature は workspace-pinned unpatched recursion revision に対し意図的に compile せず、root `Cargo.toml` に active `[patch]` が無いため、A1 backend のみの node と statement surface を登録した activation node の間に再現可能な release graph が存在しない。

**証拠行（監査引用）:** `mil/shield-stark-verify/Cargo.toml:38-56`、`kaspa-evm/Cargo.toml:55-77`、`kaspad/Cargo.toml:84-93`、`Cargo.toml:188-190`、`.github/workflows/ci.yaml:187-220`

**Triage 判定: PARTIALLY_TRUE。** 「combined graph（`evm-shield-stark`）が CI で compile されない」は**実在 gap**（監査正）。一方「A2 patch が無い」は設計上の fail-closed（patch は A6-gated、pin は ceremony）であり gap ではなく posture。

**対応（commit `36d67cb`、全 inert / compile gate のみ）:**

- activation-feature-graph job に **combined config の compile step** を追加（`.github/workflows/ci.yaml`）: `cargo check -p kaspad --features evm-shield-stark`（= `["evm", "kaspa-evm/shield-stark-backend"]`、**activated validator が実際に走らせる非 default node config**、EVM レーン + 実 STARK verify back-half を 1 build に統合）。two-half を別々に check していた既存 step では half 間の feature-unification break が green で通り抜けていた。本 step はそれを閉鎖する。**COMPILE gate のみ**（この feature を on にしても F006 fence `u64::MAX` で behaviourally inert、fence flip は strictly-later な A7 step）。既存の別 step も残置。A2 の `shield-stark-a2-surface` variant は audit-gated recursion `[patch]` なしでは意図的に UNBUILDABLE（H-02b、外部）であり本 step では build しない。ローカルで `cargo check -p kaspad --features evm-shield-stark` clean（exit 0）を確認。

**残余（正直な開示、外部/数週間）:** H-02(b) A2 `[patch]` の pin は **A6-gated**（監査済み recursion patch の ceremony 時 pin）。H-02(d) **reproducible + signed release binary**（clean checkout・local patch なし・feature/dependency attest・2 独立 build が bit-identical accept/reject）は**外部/数週間**の release engineering + ceremony 作業。compile gate では代替できない。

### H-03 [High] production client prover が fail-closed stub のまま

**監査の主張:** `prove()` は circuit 1/2/4 を recognized 化したが結果は全て `BackendPending`、circuit 3 は `UnknownCircuit`。bench binary に proof 生成コードが存在することは、versioned API・secure entropy・artifact provenance・wallet/provider integration を備えた production prover の代替にならない。

**証拠行（監査引用）:** `mil/shield-stark-prove/src/lib.rs:85-119,177-190`

**Triage 判定: PARTIALLY_TRUE。監査に同意 = 実 prover は外部/数週間。** 「prover は stub」は事実。前回 remediation（`bf6c319`、`0bfa145` に既存）で circuit-4 を `UnknownCircuit` → `BackendPending` に正した API honesty の修正は着地済みで、本監査もそれを前提に「known pending にしただけ」と正しく評価している。本対応で新たな閉鎖は主張しない。

**残余（正直な開示、外部/数週間）:** **real production prover crate**（全 enabled circuit 対応、node と同一 versioned schema/manifest param/secure entropy/artifact provenance、deterministic bench entropy を production mode で不可能化）は**数週間規模**。**M-01 の real-proof differential はこの実 prover に依存**する。実 prover 着地までは H-03/M-01 とも閉じられない。

---

## 4. Medium

### M-01 [Medium] P4 に real-proof Provider Claim end-to-end differential corpus が無い

**監査の主張:** flat AIR / reference test は多いが、最終 claim proof を one artifact として recursion→typed A2 surface→node verifier→F006 ABI→Solidity settlement へ通す required test が無い。C-P6 design 自身が item (iv)「ONE `circuit_version=3` relation」への composition を remaining work と明記する。field order / byte packing / statement length / surface table type / VK・circuit dispatch / contract snapshot のいずれかがずれれば全 claim が停止し、前回の `ctx` mismatch はまさにこの種の cross-layer defect であった。

**証拠行（監査引用）:** `docs/bench/plonky3-shield-air/claim_v2.rs`、`docs/mil-shield-cp6-mldsa-in-circuit-design.md:413-432`、`.github/workflows/ci.yaml:137-143`

**Triage 判定: TRUE_GAP（監査正）。本対応では閉鎖しない。** claim-v2 の real-proof E2E corpus は **H-03 の実 prover に依存**する（frozen schema manifest から statement を生成する要件、並行 hand encoder ではない）。実 prover 着地後に各 enabled circuit で reference relation→flat AIR→recursive proof→A2 surface→node verifier→F006 ABI→contract state transition を 1 本の required P4 corpus として統合し、全 statement field / byte order / circuit id / VK / table type / proof bit に negative mutation を付け、x86-64/aarch64/no-SIMD の decision 一致を要求する。**外部/数週間**（H-03 の後段）。前回 `0bfa145` で H-01 ctx mismatch を閉じたことが当該 corpus 完成前の暫定緩和になっている点は監査の指摘どおり。

### M-02 [Medium] A2 statement binding が typed `public_surface` identity でなく値内容で table を選ぶ

**監査の主張:** `statement_is_bound` は expected vector が non-primitive table 群に「ちょうど 1 回」現れることを要求し旧 `contains` より改善したが、backend は verify 後に各 table の `public_values` のみ返し `op_type` を捨てる。node binder はその vector が `public_surface` table 由来か別 non-primitive operation 由来かを識別できない。exact VK pin が現 surface を狭めるため即時 exploit ではない（Confidence Medium）が、value 保全境界では type による選択が必要。

**証拠行（監査引用）:** `mil/shield-stark-verify/src/lib.rs:219-254,670-692`

**Triage 判定: PARTIALLY_TRUE（defense-in-depth gap）。** node が返す値は `public_values` のみで op type を持たないため semantic ambiguity は実在。ただし exact VK pin と全 `vk_hash: None` の fail-closed により即時 exploit ではない。

**対応（commit `f7ef994`、Lane 2、node 側で到達可能な tightening のみ）:**

- `statement_is_bound`（`mil/shield-stark-verify/src/lib.rs`）に **EMPTY-statement fail-closed guard** を追加: `public_inputs.is_empty()` なら即 `false`。これが無いと `expected` が空 vector になり、単一の空 surfaced table が `count() == 1` を満たして **proof を「何にも」bind** してしまう（crypto-valid だが unbound = replayable の critical case）。production statement は `manifest_precheck` で length-pin（≥ 328 B）済だが、本 guard で fail-closed 性が upstream length gate 依存でなく **total** になる。既存の `count() == 1`（ZERO/複数 surfacing を拒否）guard は維持。+1 test（`statement_binding_rejects_empty_statement`）。stark-verify **21→22**。

**残余（正直な開示、外部/数週間 — soundness 半分、監査に同意）:** 完全に sound な rule は surface table を manifest-pinned `public_surface` NpoTypeId（op type）で選択し、別 op type の decoy table（値が偶然一致）を **TYPE で排除**する。これは in-session では到達不能で、二重に閉じている: (1) `backend::verify_outer_proof` は op-type tag を返さない、(2) typed `public_surface` op（`register_public_surface_table` / `PublicSurfaceAir` first-row 制約）は audit-gated A2-patched recursion tree（`docs/bench/plonky3-recursion-a2-surfacing.diff`、`manifest::A2_PATCH_SHA256_ONDISK` で pin）にのみ存在し、feature+`[patch]` 無しでは未登録 → 拒否。type-selection 半分は A2 patch と同一 vk-pinning ceremony で凍結される**数週間規模**。それまでは unique-content（`count == 1`）+ empty-statement guard が surfaced vector で可能な最も厳密な node 側 check。

### M-03 [Medium] K-01 freeze anchor が一つの atomic manifest state として強制されていない

**監査の主張:** manifest は `vk_hash`・raw `preprocessed_commitment`・`a2_patch_sha256` を別々の `Option` で保持し全値 `None`（fail-closed）。`manifest_precheck` は VK/schema/statement length/transcript KAT を確認するが「VK が `Some` なら PP commitment と A2 provenance も必須」という atomic invariant を要求しない。backend は PP anchor が `Some` の時のみ比較するため、VK だけを transcribe した partial manifest でも crypto verify へ進める。manifest state を `Unfrozen`/`Frozen`（VK・raw PP commitment・typed table manifest・schema hash・recursion revision・A2 source hash・transcript/config hash 必須）の 2 状態にし partial を compile/test/runtime で拒否せよ。

**証拠行（監査引用）:** `mil/shield-stark-verify/src/manifest.rs:41-73,83-195`、`mil/shield-stark-verify/src/lib.rs:302-332,661-672`

**Triage 判定: Operational gate（監査同意）。** 機構は完備・fail-closed で安全だが activation-ready ではない、という監査の位置付けは正確。原子凍結（all-or-none freeze record + partial 拒否の型強制）は本質的に ceremony 作業。前回 remediation（`b7316df`、`0bfa145` に既存）で A2 patch の on-disk SHA-256 を manifest に pin し drift test を追加した機構は監査 §7.3 で確認されている。

**残余（正直な開示、外部 ceremony）:** **vk/patch freeze ceremony** — manifest state を `Unfrozen`/`Frozen` enum とし、circuit ごとに version/statement schema hash/exact source+dependency hash/**audited** A2 patch hash/field-config/transcript KAT/**vk_hash**/**raw preprocessed commitment**/resource shape/**signed artifact hash** を 1 つの atomic freeze record にまとめ、必須 field の一部が unset な build を compile/test/runtime で拒否する強制、および独立 ceremony recomputation の一致確認。circuit 3 は full composition audit（C-03 閉鎖）後にのみ追加。回路確定後の external/operational 作業。

### M-04 [Medium] Escrow の circuit/VK policy が別々に変更可能な global から snapshot される

**監査の主張:** `activeClaimCircuit` と `claimVkHash` は別 setter で更新され `openBlind` が両 global を snapshot する。governance が circuit 2/VK2 → 4/VK4 へ移行する際、先に circuit を 4 にし VK 変更前に escrow が open されると `(4,VK2)` を永久保存、逆順で `(2,VK4)`。snapshot circuit 0 は 2/4 のどちらも許すが snapshot VK は一つで、per-circuit manifest が異なる VK を要求するなら一方は必ず fail。receipt circuit 3 追加で同問題が拡大。atomic immutable claim-policy id（単一 circuit/VK/schema/manifest/receipt requirement に mapping）を snapshot し、new escrow の wildcard 0 を除去せよ。

**証拠行（監査引用）:** `contracts/mil/src/MilShieldedEscrow.sol:73-105,168-198,217-235,249-266,319-339`

**Triage 判定: TRUE_GAP（監査正）→ 契約層で閉鎖。**

**対応（commit `f7ef994`、Lane 2 — 資金分配ロジック無変更）:**

- 5 つの独立 policy setter（`setActiveClaimCircuit`/`setClaimVkHash`/`setProviderSetRoot`/`setUniformPrice`/`setAskCommitmentRoot`）を **1 つの atomic `setClaimPolicy(circuit, vk, price, setRoot, askRoot)`** に置換（`contracts/mil/src/MilShieldedEscrow.sol`）。coherent tuple を単一 call で書き `claimPolicyId` を bump するため、**escrow は 2 つの governance call の間で不整合な `(circuit, VK)` pair を snapshot できない**（監査の mid-update race を閉鎖）。**wildcard を拒否:** setter は specific circuit（2 XOR 4）を要求、`openBlind` は `activeClaimCircuit==0` の間 `ClaimPolicyUnset` で revert、`_assertClaimCircuit` は STRICT equality にしたため circuit 0 は settlement を authorize できない。escrow は open 時に policy tuple 全体 + `snapshotPolicyId` を凍結。forge **75→76**（`test_M04_setClaimPolicy_owner_and_valid_circuit`（0/3 拒否含む）/`test_M04_wildcard0_openBlind_rejected`/`test_M04_atomic_policy_snapshot`（cross-paired `(circuit,VK)` 不成立）/`test_m4_wrong_circuit_claim_rejected`/`test_m4_snapshot_circuit_happy_path`/`test_setClaimPolicy_only_owner`/`test_B2_setClaimPolicy_askroot_owner_and_length`）。

**残余（正直な開示）:** monotonic `claimPolicyId` が single circuit/VK/price/root を atomic に束ねるが、監査が理想とする「policy id → **statement schema hash / manifest / receipt requirement** まで含む immutable mapping」と「receipt-required escrow から legacy circuit を恒久無効化」は C-P6（circuit 3）着地時に確定する。現状は 2/4 の atomic cohort lock（wildcard 0 除去済）で、circuit 3 統合時に receipt-enforcing policy へ拡張する。

### M-06 [Medium] activation CI と artifact provenance が未完成

**監査の主張:** component compile と Forge job は追加されたが、activation-quality gate として exact node activation feature・A2-patched source・production prover・real outer proof・cross-architecture/no-SIMD・mutation/fuzz・slowest-hardware resource benchmark・signed SBOM/provenance が required job でない。Foundry toolchain も floating `stable`。

**証拠行（監査引用）:** `.github/workflows/ci.yaml:137-220`、`docs/mil-shield-audit-readiness.md §7`

**Triage 判定: PARTIALLY_TRUE。** 「combined activation config が CI で compile されない」部分は本対応（H-02 と同一 commit `36d67cb`）で閉鎖。残る infra（cross-arch/no-SIMD/fuzz-in-CI/signed provenance/immutable pin/resource benchmark/real artifact）は監査どおり未完成で本質的に CI/release-engineering の外部作業。

**対応（commit `36d67cb`）:** activation-feature-graph job に `cargo check -p kaspad --features evm-shield-stark`（combined activation config）を追加（H-02 参照）。「exact activation config が green で link する」gap を閉鎖。

**残余（正直な開示、外部/数週間 — CI infra）:** exact release feature graph（A2-patched dependency 込み）・全 circuit real artifact・**x86-64/aarch64/no-SIMD decision parity**・malformed-proof fuzz の CI 配線・contract E2E・client prover・worst-case resource benchmark を immutable required job（branch protection）化し、**signed SBOM/provenance**（署名済み test/proof/benchmark artifact を hash + 環境 metadata 付きで archive）を整備、third-party action を immutable commit-pin、Foundry toolchain を固定する。これらは release process 側の**数週間規模**作業。

### M-07 [Medium] whole-sompi quote が funding path に未配線で quantizer が u64::MAX で壊れる

**監査の主張:** `shielded_quote_gross_sompi` は正しい reject-mode helper だが source comment 自身が「future SDK path MUST route」と記し production funding call site が無いため、unclaimable gross を funding 前に拒否する不変条件が API で強制されていない。さらに `quantize_gross_up` は overflow 時に `saturating_add` し、`u64::MAX % 25 == 15` で次の倍数への +10 が saturate して `u64::MAX` を返す（remainder 15 のまま = 非 claimable）。test は `u64::MAX` を返すことだけ assert し claimability の loop から max を除外している。**PoC:** `input=18446744073709551615, step=25, result=18446744073709551615, result % 25 = 15`。

**証拠行（監査引用）:** `mil/provider/src/config.rs:69-98`、`mil/provider/src/economics.rs:134-199,385-429`、`mil/provider/src/store.rs:29-68`

**Triage 判定: TRUE_GAP（監査の boundary PoC は正しい）→ 閉鎖。** `quantize_gross_up(u64::MAX)` が非 25-倍数を返す boundary bug は、まさに guard が閉じるべき `claimAnonV2` SplitMismatch liveness trap（fractional-sompi provider share で escrow が永久ロック）を再び開いていた。

**対応（commit `bae4a3f`）:**

- `quantize_gross_up`（`mil/provider/src/economics.rs`）を `saturating_add` → `checked_add` に変更し、top 25-wide overflow band `(MAX_WHOLE_SOMPI_GROSS, u64::MAX]` では新 const **`MAX_WHOLE_SOMPI_GROSS = u64::MAX - (u64::MAX % 25) = u64::MAX - 15`（表現可能な最大の 25 の倍数）へ clamp DOWN**。結果は**常に** `WHOLE_SOMPI_GROSS_STEP`（25）の倍数、panic なし。
- **clamp（reject でなく）を選んだ理由**は responsibility を quote gate と分担するため: (a) **pre-funding QUOTE path**（`config.rs` `shielded_quote_gross_sompi` → `checked_gross_sompi`）は requester が escrow に資金を lock する**前**に overflow/非倍数を **reject**、(b) **post-serving RECORD path**（`store.rs` `SessionRecord::from_outcome` → `quantize_gross_up`）は既に served なので常に claimable な gross を emit し fail/panic しない（sidecar を live に保つ）。overflow band は `≈ 6×` 全 30 B MSK 供給で **legitimate economics からは物理的に到達不能**、そこで clamp-down するのは既に不可能なコストを過小申告する fail-safe（provider は less を claim、over-claim しない、escrow は常に settleable）。`Result` 化は `from_outcome` を fallible にし out-of-scope の `main.rs` へ波及するため採らない。
- **authoritative-path check:** production の gross producer 2 箇所（`config.rs` quote → reject、`store.rs` record → quantize）が両方 gated。唯一の bypass は `#[cfg(test)]` の `rec()` fixture（funding path でない）。+1 test（`quantize_gross_up_never_emits_a_non_multiple_on_the_overflow_band`、`u64::MAX`/`u64::MAX-1`/最大倍数/normal/top-band sweep で結果 ≡ 0 (mod 25) を assert）。provider **42 lib + 1 e2e**。

**残余（正直な開示）:** v0 provider は direct-pay（in-crate escrow なし）で、**authoritative escrow-funding SDK path（v1 §8.2）は未実装** — 監査の「production funding call site が存在しない」は v1 の未実装部分に対応する。その path 実装時に `shielded_quote_gross_sompi` 経由を必須化する（現状は両 call site に documented、reachable な gross producer は全 gated）。permanent revert を dust rule に変える案は別途 governance 判断。

### M-08 [Medium] proof/metadata/DA/gas cap が measured/frozen でなく暫定

**監査の主張:** DA producer/consumer cap が 8 MiB へ揃った点は閉鎖。一方 in-consensus STARK verifier は proof cap 1 MiB、manifest metadata cap（64 tables / 2^24 rows / 2^12 lanes / 2^16 public values）が広く、F006 gas が final production proof / slowest no-SIMD verifier に対し独立較正されていない。A3 VK hash が exact shape を verify loop 前に拘束するため任意 metadata がそのまま heavy verify へ進むわけではないが、valid final artifact の最大 CPU/RAM・block-level throughput・DA transport・gas charge の co-calibration が activation acceptance evidence として必要。

**証拠行（監査引用）:** `mil/shield-stark-verify/src/lib.rs:150-162,641-669`、`mil/shield-stark-verify/src/manifest.rs:104-173`、`mil/shield-da/src/lib.rs:20-45,125-150`

**Triage 判定: PARTIALLY_TRUE。** DA producer/consumer cap の整合（8 MiB）は前回 remediation（`b7316df`、`0bfa145` に既存）で閉鎖済であり、監査 §7.4 でも Closed と確認されている。proof/metadata/gas cap の worst-case 較正は本質的に hardware benchmark 作業で外部。本対応で新たな閉鎖は主張しない。

**残余（正直な開示、外部 — hardware calibration）:** circuit freeze 時に table count/rows/lanes/public values/proof bytes/DA chunks を exact または狭い bound へ固定し、1 MiB cap を measured maximum + bounded margin へ tighten、**slowest supported no-SIMD hardware で worst valid + adversarial reject case を benchmark** して gas/block limit を較正、producer/reassembler/verifier/transaction cap を全一致させる。vk ceremony の hardware calibration であり本対応スコープ外。

### M-09 [Medium] `shake_threaded_air` が squeeze 公開値を 8-bit byte に拘束していない

**監査の主張:** SHAKE AIR は input side（message byte）を boolean block bit から再構成し canonical だが、squeeze output side は各 16-bit limb に `out == pis[base] + 256 * pis[base+1]` のみを課し、`pis[base]`/`pis[base+1]` に boolean decomposition も 0..255 range constraint も無い。BabyBear field 内で `(lo,hi)=(52,18)` と `(308,17)` は共に valid field element で両方が `4660` を表す。既存 `--corrupt-out` は 1 field element を +1 するため等価な非 canonical pair を検査しない。advertised な public-byte interface が非 canonical で、後段（ExpandA 等）へ渡す C-P6 item (iv) composition で recomposition semantics が曖昧になる。

**証拠行（監査引用）:** `docs/bench/plonky3-shield-air/shake_threaded_air.rs:38-40,421-465,512-523,858-870`

**Triage 判定: TRUE_GAP（監査の等価 pair PoC `(52,18)`≡`(308,17)` は正しい）→ 閉鎖。**

**対応（commit `6d07a96`）:**

- `shake_threaded_air.rs` の squeeze 公開出力 byte を **各々 8-bit range-check**（boolean 分解 / `< 256` 拘束）し、`out = lo + 256·hi` の `lo`/`hi` が canonical byte であることを in-AIR で強制（`docs/bench/plonky3-shield-air/shake_threaded_air.rs`）。非 byte field 値と代数的に等価な非 canonical pair を拒否する negative（`--corrupt-noncanonical`、`(52,18)` vs `(308,17)` 型の等価 pair）を追加。**canonical public byte interface** に修正。
- 併せて `expanda_stream_bind_air.rs` の ExpandA→`pi_stream` binding を**再証明**（`docs/bench/plonky3-shield-air/expanda_stream_bind_air.rs`）。この canonical byte 修正により、item (iv) で SHAKE output を ExpandA 等の内部 dataflow へ渡す際の recomposition semantics が **typed byte として** 一意化され、Leg-S の limitation を source で閉じる。

**残余（正直な開示）:** 監査の acceptance criteria「composed SHAKE→ExpandA/full receipt proof が differentially tested」は C-03 item (iv) の composition で満たされる（本 finding 自体の byte canonicality は閉鎖済、composition は §2 の残作業）。

---

## 5. Low

### L-01 [Low] consensus verifier の context encoding に expect / silent default fallback が残る

**監査の主張:** `compute_vk_hash` が in-memory Borsh serialization を `expect`、context construction の複数箇所が postcard failure を `unwrap_or_default()` で空 bytes へ変換。現型では failure は想定しにくいが consensus trust anchor で silent fallback を許す理由はなく、将来の型変更や custom serializer error が panic または hash alias に化ける。

**証拠行（監査引用）:** `mil/shield-stark-verify/src/lib.rs:129,524,531,559,568,582-583`

**Triage 判定: 監査に同意（Low、A7 blocker でない）。本対応では未閉鎖。** 現 type は serialize 可能で attacker exploit は無く、F006 fence が `u64::MAX` の間は consensus-neutral。context 構築と VK hash を typed `Result` 化し全 serialization error を fail-closed にする hardening（`unwrap`/`expect`/`unwrap_or_default` 除去、fault-injection test で typed error 伝播・panic なし・fallback hash material なしを確認）は **VK freeze ceremony 前の hardening** として実施する。監査も A7 blocker=No。

### L-03 [Low] audit-readiness 文書に旧 seam status と landed backend が混在

**監査の主張:** readiness 文書は backend 機構が landing した説明と同時に「`verify_stark` は front half で止まり `BackendPending`」「back half not yet done」という旧 snapshot 記述を残し、snapshot-specific status が混在して外部監査・activation operator の判断を誤らせる。code/manifests/CI から snapshot-specific control matrix を生成し旧記述を削除、demonstrated bench code / compiled release code / activated consensus code を明確分離せよ。

**証拠行（監査引用）:** `docs/mil-shield-audit-readiness.md:130-160 and later status text`

**Triage 判定: PARTIALLY_TRUE。** activation-story の不整合は前回 remediation（`bf6c319`、`0bfa145` に既存）で実 A7 5-step sequence へ修正済。**full な snapshot-specific control matrix 再生成**は follow-up doc 作業として残る。監査も A7 blocker=No。

**残余（正直な開示）:** implemented / independently reproduced / repository self-reported / pending / operational evidence を明確分離し、各 roadmap item に one current status + source hash + executable acceptance gate を与え、矛盾する `BackendPending`/back-half 記述を除去した **snapshot-specific readiness manifest** を生成する doc 作業。A7 blocker ではない。

---

## 6. 前回差分（監査 §4 / §7）に対する応答 — 閉鎖または改善を確認した項目

監査報告書 §4「Differential Review: Previous Findings」および §7「Positive Security Changes Confirmed」の各行に対する我々の応答:

| Item | 監査（0bfa145）の評価 | 我々の応答 |
|---|---|---|
| C-01/C-02 amount/share binding | **Closed at static/semantic level**（392-byte schema、public share、private amount、value commitment、payout note、contract-computed split） | 同意。real-proof E2E は M-01（H-03 実 prover 依存、外部）。§7.2 の value conservation 維持 |
| C-03 full receipt authorization | **Open / Critical**（circuit 3・receipt witness・signature/counter/pricing relation・contract dispatch なし） | 同意。§2 参照。本対応で wire 19/24 の FREE gap を sub-gadget 化 + ExpandA を BOUND 化（SOUND）、統合は未達で Open のまま |
| H-01 claim ctx mismatch | **Closed statically**（Solidity/Rust 404-byte layout 一致、AIR は opaque `PI_CTX`。最終 closure は typed A2 依存） | 同意。`0bfa145`（= H-01 residuals commit）で閉鎖済。最終 anti-replay は M-02 typed A2 + M-01 real E2E。§7.1 の ctx 統一維持 |
| H-02 release graph | **Partial improvement / Open**（feature forwarding 追加、exact node+A2 build は未成立） | 同意。§3 H-02 参照。combined `evm-shield-stark` compile gate 追加（`36d67cb`）、A2 patch/signed binary は外部 |
| H-03 production prover | **Open**（circuit 4 を known pending にしただけ） | 同意。§3 H-03 参照。実 prover は外部/数週間 |
| K-01 / A3 | **Mechanism improved / freeze Open**（actual preprocessed commitment・A2 patch hash pin 追加、全 production anchor は None） | 同意。§4 M-03 参照。原子 freeze は ceremony（外部）。§7.3 の A3/K-01 機構維持 |
| M-04 circuit snapshot | **Partial**（circuit number は snapshot、circuit/VK 別 setter、wildcard 0 残存） | **本対応で閉鎖**。atomic `setClaimPolicy` + wildcard-0 除去 + STRICT circuit assert（`f7ef994`、forge 76）。§4 M-04 |
| M-05 backend ADR mismatch | **Closed at design level**（BabyBear/Plonky3 shipping backend を superseding choice として文書化） | 同意。前回 remediation（ADR-0035 supersession note、`0bfa145` に既存）で閉鎖済。field 変更は new `circuit_version` + re-ceremony（K-01） |
| M-07 quote invariant | **Partial / Open**（checked helper 追加、funding path 未配線、max boundary bug） | **boundary bug を本対応で閉鎖**。`quantize_gross_up` overflow band clamp-down（`bae4a3f`）。funding path は reachable producer 全 gated、v1 SDK path は未実装残余。§4 M-07 |
| L-02 DA producer cap | **Closed**（producer が consumer と同じ 8 MiB cap） | 同意。前回 remediation（`b7316df`、`0bfa145` に既存）で閉鎖済。§7.4 の DA cap alignment 維持 |
| A7 | **NO-GO**（11 blocker 残存、全 preset F006=u64::MAX） | 全面同意。fence 維持、claims disabled 維持、manifest anchor 未 freeze 維持 |

---

## 7. A7 activation acceptance gate（G1-G15）— 本対応後の自己評価

監査 §8 の 15 gate に対する本対応後の自己評価（再監査で要確認）:

| Gate | 必須状態 | 監査判定 | 本対応後（自己評価） |
|---|---|---|---|
| G1 Receipt authorization | full circuit 3 が receipt/signature/key/session/counter/pricing/payout を one relation で証明 | Fail | **OPEN（同意）** — wire 19/24 の FREE gap を sub-gadget 化・ExpandA を BOUND 化したが統合は未達（§2）。数週間規模 |
| G2 Legacy-path retirement | receipt-required escrow を circuit 2/4 で settle 不能 | Fail | **OPEN（同意）** — circuit 3 統合時に確定（M-04 で atomic policy 化・wildcard 0 除去は先行） |
| G3 Typed A2 | exactly one manifest-pinned `public_surface` op | Fail | node 側で empty-fail-closed + `count==1`（`f7ef994`）。**type-based soundness 半分は audit-gated patch 内（外部）** → Fail のまま |
| G4 Atomic K-01 | VK/PP/schema/table/A2 source/transcript/config を一体 freeze | Fail | 機構完備 + on-disk patch-hash pin（`0bfa145` 既存）。**原子 freeze（Unfrozen/Frozen 型強制）は ceremony（外部）** → Fail のまま |
| G5 Production prover | wallet/provider 向け全 enabled circuit | Fail | **OPEN（同意）** — API honesty 済、実 prover は外部/数週間（H-03） |
| G6 Exact node build | backend+A2 を含む `kaspad` release config | Fail | combined `evm-shield-stark` compile gate 追加（`36d67cb`）。**A2 patch + reproducible signed binary は外部** → Fail のまま |
| G7 P4 real-proof E2E | reference→AIR→recursion→A2→F006→contract | Fail | **OPEN（同意）** — H-03 実 prover 依存（M-01、外部） |
| G8 Escrow policy | atomic circuit/VK/manifest snapshot、wildcard なし | Fail | **前進（本対応、`f7ef994`）** — atomic `setClaimPolicy` + wildcard-0 除去。**schema/manifest/receipt requirement まで含む policy id と receipt-enforcing 化は circuit 3 着地時** → Partial（再監査で要確認） |
| G9 Pricing invariant | authoritative funding API で whole-sompi 強制 | Fail | **前進（本対応、`bae4a3f`）** — quantizer boundary 閉鎖、reachable producer 全 gated。**v1 escrow-funding SDK path は未実装** → Partial（再監査で要確認） |
| G10 AIR byte canonicality | SHAKE output 各 byte を 8-bit 拘束 | Fail | **閉鎖（本対応、`6d07a96`）** — squeeze 公開 byte を 8-bit range-check、非 canonical pair reject。composition での differential は G7 後段 |
| G11 Determinism | x86-64/aarch64/no-SIMD decision 一致 | Not evidenced | **OPEN（同意）** — cross-arch CI infra（M-06、外部） |
| G12 Resources | final cap/gas/CPU/RAM を slowest hardware で較正 | Not evidenced | **OPEN（同意）** — hardware 較正（M-08、外部）。DA cap は整合済 |
| G13 CI/provenance | immutable actions、required gates、signed SBOM/artifacts | Partial | combined compile gate 追加（`36d67cb`）。**signed provenance/immutable/cross-arch は外部** → Partial のまま |
| G14 External audit | AIR/recursion/A2/verifier/contract の closure review | Pending | **OPEN（同意）** — 本 static follow-up は native/upstream audit を代替しない。本書 + 修正 commit 群がその入力 |
| G15 Rollout | testnet re-genesis/canary/rollback drill 後に mainnet governance | Pending | **OPEN（同意）** — 運用 rehearsal 未実施 |

**結論: G1–G15 の Critical/High/activation-blocking Medium が open/partial である限り A7 = NO-GO。監査と完全に一致する。** F006 fence（全 preset `u64::MAX`）を維持し、anonymous claim を disabled のまま維持し、Critical/High および activation-blocking Medium が real/reproducible evidence で閉鎖され新規外部監査を通るまで claim VK を freeze/deploy しない。G8/G9/G10 は本対応で partial/closed へ前進したが、いずれも G1（C-03）が open である限り単独では activation を許さない。

---

## 8. ビルド・テスト証跡（§results — 本報告書作成時の最終再実行、verbatim）

すべて remediation tip `8208ee0` の作業ツリーで最終再実行した（ローカル Mac、cargo 1.94.1 / forge 1.7.1）。実行コマンド:
`cd contracts/mil && forge test`; `cargo test -p misaka-mil-shield --release`; `cargo test -p misaka-mil-shield-stark-verify`; `cargo test -p misaka-mil-shield-da`; `cargo test -p misaka-mil-provider`。

```
# forge test (contracts/mil, 9 suites)
Ran 9 test suites in 33.81ms (114.47ms CPU time): 76 tests passed, 0 failed, 0 skipped (76 total tests)
  … 含む M-04: test_M04_setClaimPolicy_owner_and_valid_circuit / test_M04_wildcard0_openBlind_rejected /
    test_M04_atomic_policy_snapshot / test_m4_wrong_circuit_claim_rejected / test_m4_snapshot_circuit_happy_path

# cargo test -p misaka-mil-shield --release
     Running unittests src/lib.rs
test result: ok. 43 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
     Running tests/anon_provider_claim_e2e.rs
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/differential_corpus.rs
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/private_transfer_e2e.rs
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
   Doc-tests misaka_mil_shield
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
# → 59/59 (43 unit + 10 + 2 + 4)。

# cargo test -p misaka-mil-shield-stark-verify (default = INERT verifier)
     Running unittests src/lib.rs
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
   Doc-tests misaka_mil_shield_stark_verify
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
# → 22/22 (21→22 は M-02 empty-statement fail-closed test)。STARK arm は CircuitVkNotFrozen fail-closed。

# cargo test -p misaka-mil-shield-da
     Running unittests src/lib.rs
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.49s
   Doc-tests misaka_mil_shield_da
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
# → 14/14。DA producer/consumer cap は 8 MiB で整合済（監査 §7.4 Closed）。

# cargo test -p misaka-mil-provider
     Running unittests src/lib.rs
test result: ok. 42 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
     Running unittests src/main.rs
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/e2e_tcp.rs
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s
   Doc-tests misaka_mil_provider
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
# → 43/43 (42 lib + 1 e2e)。42 lib は M-07 の overflow-band test を含む(41→42)。
```

**独立敵対的検証（C-P6 新 AIR、.119 `~/Plonky3/shield-air`、vendored copy byte-identical）:**

- `hint_canonicity_air.rs`（`cf157f2`）: host diff-test — 24 個の実 libcrux ML-DSA-87 hint block で AIR canonicity verdict == reference `HintBitUnpack` ⊥/accept 一致；`VERIFY ok`；negative 3/3 拒否（`--corrupt-nonincreasing`/`--corrupt-padnonzero`/`--corrupt-crossboundary`）。inventory wire 19（FREE — 従来 gadget 皆無）を閉鎖。
- `pk_receipt_bind_air.rs`（`8208ee0`、本 workflow）: host diff-test — final-row `HOUT == blake2b_512_keyed("misaka-mil-v1/provider-id", pk[2592])`（in-file word-level `keyed_ref` AND `blake2b_simd` library の両方、REAL libcrux `ml_dsa_87` vk に対し byte-for-byte）；`VERIFY ok`（prove 2.1s / verify 62.7ms、101,888 cols × 32 rows、prep 1028、proof 4,981,810 B、hiding-ZK）；`PRIVACY OK`（private pk の 324 個 nonzero word が proof に不在）；negative 2/2 拒否（`--corrupt-pk`/`--corrupt-hash`、OodEvaluationMismatch）；self-audit = key-block(1)+⌈2592/128⌉(21)=22 compressions・chain wires 15872・pad bits pinned 768・canonical output 64 bytes。vendored sha256 `2c1faa953b49da4fcf8ca704f40bd2a087aa5fd94fc4bba8696f5a61bfe5faf6` 両側一致。inventory wire 24（FREE — claim が `pk_receipt_hash` を無条件信頼）を standalone gadget として BOUND 化。
- いずれも **bench-FRI**（`new_testing(_,2)`=2 queries ~5-bit、deterministic seed）で CIRCUIT LOGIC を証明するもので binding soundness / ZK ではない（production は ~100 queries/grinding + OS entropy、header caveat に明記）。`PRIVACY OK` は witness-absence の smoke test。

---

## 9. 残フォローアップ（正直な外部 / 数週間ゲート — overclaim しない）

以下は本対応で**閉じていない**。いずれも実証明 + 新規外部監査なしに閉じたと主張しない。**これらが real proof + fresh audit で閉じるまで A7 は NO-GO を維持し、F006 fence は `u64::MAX` のまま**であることに我々は同意する。

| 項目 | 種別 | 内容 |
|---|---|---|
| **C-03 / G1-G2** | Critical activation blocker | C-P6 composition item (iv) single-relation composition（全 gadget を 1 つの `circuit_version=3` へ、`num_pis=0` の cross-stage binding を全 wire で解消）/ (v) libcrux accept-diff / (vi) 外部監査 + circuit-3 dispatch + real-proof E2E。sub-gadget + 部分 wiring 完成 ≠ full-receipt-circuit 統合。数週間規模 |
| **H-02(b)** | 外部（A6-gated） | A2 `[patch]` の pin（監査済み recursion patch の ceremony 時 pin） |
| **H-02(d)** | 外部 | reproducible + signed release binary（clean checkout・no local patch・feature/dependency attest・2 独立 build が bit-identical） |
| **H-03 / M-01** | 外部/数週間 | real production prover crate。M-01 の real-proof differential corpus はこれに依存 |
| **M-02 soundness 半分** | 外部/数週間 | typed `public_surface` NpoTypeId 選択（`PublicSurfaceAir` first-row binding、audit-gated patch 内、verify 出力に op-type tag を surface） |
| **M-03 freeze ceremony** | 外部 ceremony | manifest state を Unfrozen/Frozen enum とし vk_hash / raw PP commitment / audited a2_patch_sha256 / typed table / schema / recursion rev / transcript-config / signed artifact を atomic all-or-none freeze。partial 拒否の型強制。回路確定後 |
| **M-06 CI infra** | 外部/数週間 | exact release build・A2 patch build・production prover・real proof E2E・aarch64/no-SIMD parity・mutation/fuzz・resource benchmark・immutable action pin・signed SBOM/provenance の required gate 化 |
| **M-08 hardware calibration** | 外部 | proof/metadata/gas cap の slowest no-SIMD hardware worst-case 較正（DA cap は整合済） |
| **L-01** | ceremony hardening | verifier context / VK hash の typed-`Result` 化（silent fallback/expect 除去、fault-injection test） |
| **L-03** | doc follow-up | snapshot-specific readiness control matrix 再生成 + 旧 BackendPending/back-half 記述削除 |
| **G8/G9 残余** | circuit 3 / v1 SDK | escrow policy id の schema/manifest/receipt-requirement 拡張 + receipt-enforcing 化（C-03 後）/ v1 escrow-funding SDK の checked-quote 必須化 |
| **G14/G15** | 外部・運用 | 独立外部監査 → canary/monitoring/rollback rehearsal → activation-height-only release 差分監査 |

---

## 10. 再監査提出物チェックリスト

- [x] 修正 commit hash — §0 表（`f7ef994…` M-04・M-02 / `bae4a3f…` M-07 / `6d07a96…` M-09 / `36d67cb…` H-02・M-06 / `577d33e…`・`ce8fdb1…`・`cf157f2…`・`8208ee0…` C-03 前進）
- [x] source ブランチ / HEAD — `feat/mil-v0` / `8208ee0`（+ 本書コミット）
- [x] `cargo test` / `forge test` 結果 — §8（最終再実行値、verbatim。forge 76 / shield 59 / stark-verify 22 / da 14 / provider 43）
- [x] C-P6 新 AIR の SOUND 検証 — §8（hint_canonicity 24 実 hint 一致 + 3 negatives、pk_receipt bridge host diff-test + VERIFY + 2 negatives + PRIVACY OK、vendored byte-identical）
- [x] TRUE_GAP / PARTIALLY_TRUE / STALE の file:line 判定 — §2–§5
- [x] 監査 §4/§7 の閉鎖確認項目への応答 — §6
- [ ] C-03 統合（item iv/v/vi） — 数週間規模、閉鎖後に差分再監査を要請
- [ ] 実 prover / M-01 real-proof corpus（H-03） — 外部/数週間
- [ ] VK/patch atomic freeze ceremony（M-03、Unfrozen/Frozen 型強制） — 回路確定後、外部
- [ ] CI infra / cross-arch / signed provenance（M-06） — 外部/数週間
- [ ] hardware gas/resource 較正（M-08） — 外部
- [ ] 独立外部監査 / canary・rollback rehearsal / activation-height-only release 再監査（G14/G15） — 外部・運用

> 本対応は静的修正（M-04/M-07/M-09 閉鎖、M-02/H-02/M-06 前進）+ C-P6 inventory の残 FREE gap（hint canonicity・pk_receipt bridge）の SOUND な sub-gadget 化 + 正直な外部ゲート開示であり、**A7 activation の解除を主張するものではない**。C-03 統合・実 prover・atomic freeze ceremony・CI infra の後、本書と修正 commit 群を入力として G14 独立監査へ進むことを推奨する。**F006 fence（全 preset `u64::MAX`）と claims disabled は本対応後も維持する。**
