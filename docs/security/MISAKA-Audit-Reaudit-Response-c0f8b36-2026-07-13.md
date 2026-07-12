# MISAKA MIL ShieldedPool 追跡監査（c0f8b36）修正対応報告書（再監査提出用）

**対応日:** 2026-07-13
**対象ブランチ:** `feat/mil-v0`
**監査 snapshot:** `c0f8b36faeab5a1db931f5556bb4c12c56e51ad7`（`rusty-kaspa-feat-mil-v0-c0f8b36.zip`、input archive SHA-256 `a0ccd1daead882c0e7df2498a83781905dc6937d3e77fe2e10158ed1253f479e`、`MISAKA_MIL_ShieldedPool_Reaudit_c0f8b36_2026-07-12_Evidence.zip`）
**対象監査:** `MISAKA MIL Shielded Pool Follow-up Security Audit — Snapshot c0f8b36`（基準 `0bfa145`→`c0f8b36` 差分、independent static / semantic follow-up review、Critical 1 / High 3 / Medium 7 / Low 3、A7 blocker 11 件、decision = **A7 activation NO-GO**）

> **A7 activation 判定について:** 監査の **NO-GO に全面同意する**。本対応で **H-04 / M-07 / M-10 / L-01 / L-04** をコードで閉鎖し、**C-03** は circuit-3 production surface（`24d221d`、INERT）+ ML-DSA-87 verify の **decode/μ 導出 front**（`mu_front_air.rs`、wires 8/9/10/12 を実 libcrux 署名上で in-AIR BOUND 化）で前進させたが、**full-scale k=8 の single `circuit_version=3` relation への集約（item iv）は未達で OPEN のまま**である。H-02 / H-03 / M-01 / M-02 / M-03 / M-06 / M-08 / L-03 は本対応で「閉鎖」を主張せず外部 / 数週間 / ceremony ゲートとして残す。**F006 fence（全 4 preset `u64::MAX`）は本対応で一切変更しておらず、anonymous claim も default disabled、VK/manifest anchor も全 circuit 未凍結（`vk_hash: None`）のまま維持する。**

> **物理制約の正直な開示（重要）:** 本対応時点で production-scale の full ML-DSA-87 verify 集約 STARK 証明は**実行環境の制約で生成できていない**。ヘビー proving host（`.119`）は 15 GB RAM（空き ~7 GB）で、full-scale n=256 の集約 STARK は ADR-0035 の見積り上 **≥32 GB を要する**。加えて recursion clone（`Plonky3-recursion` @ `b363397` + join examples）は現 host に不在で、reduced-scale の recursion 合成も再構築を要する。したがって本対応の C-03 前進は **単一 STARK に fuse 可能な front 部分（decode/μ）に限定**され、full-scale k=8 集約と real-proof E2E は依然として **ハードウェア + 数週間ゲート**である。過大表現しない（L-03）。

---

## 0. エグゼクティブサマリー

- **監査が正しく指摘した実 gap を 5 件コードで閉鎖した:** **H-04**（匿名 receipt 鍵アーキテクチャと実装の矛盾）→ 別 INERT anonymous serving lane で長期鍵リンク除去、**M-10**（pk_receipt bridge の型/authoritative 性）→ 固定長 `PkReceipt([u8;2592])` newtype、**M-07**（whole-sompi quote が funding path 未配線）→ `setClaimPolicy` の funding-entry price gate、**L-04**（`quantize_gross_up` の u64 上端契約破れ）→ overflow band clamp-down + `checked_quantize_gross_up`、**L-01**（trust-anchor serialization の panic/silent fallback）→ `compute_vk_hash`/`context_from_proof`/`encode_preprocessed` を typed `Result` 化し empty-fallback aliasing を除去。
- **C-03（Critical、C-P6 full receipt authorization）は監査に同意して OPEN のまま = Critical activation blocker を維持する。** 本対応での前進（いずれも PROGRESS のみ、閉鎖せず）:
  - `24d221d` — **circuit_version=3 production surface**（statement schema 456 B + reference-policy dispatch + verifier manifest（`vk_hash: None` ⇒ `CircuitVkNotFrozen` fail-closed）+ Solidity `claimAnonV3`、すべて INERT / fail-closed）。
  - `mu_front_air.rs`（**本対応**）— ML-DSA-87 verify の **decode/μ 導出 front**（wires 8/9/10/12）を、実 libcrux ML-DSA-87 鍵 + 署名の上で **ONE AIR に BOUND 化**: `tr=SHAKE256(pk) → μ=SHAKE256(tr‖0x00‖len(ctx)‖ctx‖M) → c̃'=SHAKE256(μ‖w1Encode) → c̃'==c̃`、cross-hash tie（tr→μ / μ→c̃'）を **SHARED public 経由で in-circuit 拘束**（recursion 不要）。GATE 1–4 + VERIFY 全 green、4 negatives（`--corrupt-thread`/`--corrupt-tie`/`--corrupt-ctilde`/`--corrupt-w1`）すべて reject。**これは C-03 の front 部分の前進であり、full-scale k=8 集約（item iv）ではない。**
- **修正コミット（いずれも `c0f8b36` の後、`feat/mil-v0` 上、rebase なし）:**

| Finding | Sev | Triage 判定 | 修正/前進 commit |
|---|---|---|---|
| C-03 | Critical | 監査に同意（Open は正当） | `24d221d`（circuit-3 surface、INERT）+ `mu_front_air.rs`（decode/μ front、wires 8/9/10/12 BOUND） = **PROGRESS のみ、閉鎖せず** |
| H-02 | High | PARTIALLY_TRUE（combined compile gate は `0bfa145` 既存 `36d67cb`） | 未閉鎖 — 外部（A2 patch pin / reproducible signed binary） |
| H-03 | High | PARTIALLY_TRUE（API honesty 済、実 prover は外部） | 未閉鎖 — 外部 / 数週間 |
| H-04 | High | **TRUE_GAP（newly identified）→ 閉鎖** | `b620796` |
| M-01 | Medium | TRUE_GAP（H-03 実 prover 依存） | 未閉鎖 — 外部 / 数週間 |
| M-02 | Medium | PARTIALLY_TRUE（node 側 empty-fail-closed は `0bfa145` 既存 `f7ef994`） | 未閉鎖 — typed-surface soundness 半分は外部 |
| M-03 | Medium | Operational gate（機構完備、原子 freeze は ceremony） | 未閉鎖 — 外部 ceremony |
| M-06 | Medium | PARTIALLY_TRUE（combined compile gate は `0bfa145` 既存） | 未閉鎖 — 外部 CI infra |
| M-07 | Medium | **TRUE_GAP → 閉鎖** | `6b82b36` |
| M-08 | Medium | PARTIALLY_TRUE（DA cap 整合済、hardware 較正は外部） | 未閉鎖 — 外部 hardware |
| M-10 | Medium | **TRUE_GAP（newly identified）→ 閉鎖** | `b620796` |
| L-01 | Low | **TRUE（trust-anchor hardening）→ 閉鎖** | **本対応**（`mil/shield-stark-verify/src/lib.rs`、typed `Result`） |
| L-03 | Low | PARTIALLY_TRUE（honest separation 維持、full manifest doc は follow-up） | 部分 — 本書 + wire inventory で honest 分離、full readiness matrix は follow-up |
| L-04 | Low | **TRUE_GAP（newly identified）→ 閉鎖** | `6b82b36` |

- **コンセンサス安全性:** 全変更は F006 fence（全 preset `u64::MAX`）の内側で inert。circuit 3（C-P6）/ circuit 4 は decode/verify 可能だが **未登録・未凍結**（`CircuitVkNotFrozen` fail-closed）。`mu_front_air.rs` は `docs/bench/` 配下の standalone flat-AIR bench であり、コンセンサス経路 / node binary には一切リンクされない。
- **未デプロイ:** activation / VK freeze / claimsEnabled はいずれも未実施。

---

## 1. 修正方針と検証

1. 監査の各 finding について引用 file:line を **`c0f8b36` と現ツリーの両方**で検証し、TRUE gap と stale / posture を分離した。本監査も前回同様に精度が高く、**H-04（長期鍵リンク）・M-10（pk_receipt 型/authoritative）・M-07（funding path 未配線）・L-04（u64 上端契約）は監査どおりの TRUE_GAP** と確認した。
2. finding ごとに read-only 敵対的 triage → 修正レーン → 独立検証。`mu_front_air.rs` は `.119`（`~/Plonky3/shield-air`）で **実 libcrux ML-DSA-87 署名**の上で prove/verify + 4 negatives を実行し、vendored copy を byte-identical（sha256 一致）で確認した。
3. **正直な開示を最優先**した。C-03 は front 前進に留め「閉鎖」を主張しない。H-02/H-03/M-01/M-02/M-03/M-06/M-08/L-03 は外部 / 数週間 / ceremony ゲートとして明確に分離する（§9）。**production-scale 集約が現ハードウェアで不可能である事実を §0 と §2 で明示開示する。**

---

## 2. Critical

### C-03 [Critical] C-P6 full receipt認可がsettlement経路へ未統合

**監査の主張:** 匿名 claim 経路は circuit 2/4 のみ受理し、receipt-validity 用 circuit 3 は Solidity policy / statement schema / verifier manifest / production prover のいずれにも登録されていない。SHAKE/ExpandA/NTT/UseHint/hint canonicity/pk_receipt binding 等の AIR は前進だが、複数 wire が `GADGET_ONLY_NOT_WIRED`、k=8/L=7/N=256 full-scale + full `circuit_version=3` aggregation + receipt/session/counter/pricing/settlement への composition は未完。個別 gadget が proof を持つことと資金移動の認可条件になることは同義でない。

**Triage 判定: 監査に同意（Open は正当）。本対応では閉鎖しない。** 正直な status:

- **前進（本対応、いずれも PROGRESS のみ）:**
  - `24d221d` — **circuit_version=3 production surface（INERT / fail-closed）**。`PROVIDER_CLAIM_V3_STATEMENT_SCHEMA`（456 B、byte-differential test で pin）+ `verify_reference_v3(_with_pk)`（claim-v2 checks + receipt-authorization binding）+ proof.rs の reference-policy dispatch arm（`CIRCUIT_PROVIDER_CLAIM_V3=3`）+ shield-stark-verify の circuit-3 `CircuitManifest`（`vk_hash: None` ⇒ `CircuitVkNotFrozen` で triple-locked fail-closed）+ Solidity `MilShieldedEscrow.claimAnonV3`（`claimsEnabled=false` + F006 fence の内側）。「production 表面は完成、prover + vk freeze + activation は外部」という位置づけ。
  - `mu_front_air.rs`（**本対応**）— ML-DSA-87 `Verify` の **decode/μ 導出 front（wires 8/9/10/12）を ONE AIR に BOUND 化**。従来 `shake_threaded_air.rs` は単一 multi-block SHAKE を証明するのみで、μ の framing（`tr‖0x00‖len(ctx)‖ctx‖M` を μ の message として）と `tr→μ→c̃'` の chaining は unbound（`GADGET_ONLY_NOT_WIRED`）だった。本 AIR は 3 つの SHAKE256 を 1 トレースの 3 セグメント（各 all-zero reset）として連結し、**cross-hash tie（`seg0.out[0..64]==seg1.msg[0..64]==tr`、`seg1.out[0..64]==seg2.msg[0..64]==μ`、`seg2.out[0..64]==c̃`）を SHARED public value で in-circuit 拘束**（新制約型不要、recursion 不要）。**実 libcrux ML-DSA-87 鍵 + 署名**駆動、GATE 3 で libcrux accept ⇔ `c̃'==c̃` を確認、4 negatives（sponge-state / tie / c̃ / w1）すべて reject。**prove 10.7 s / verify 142 ms、5897 cols × 1024 rows、4050 publics、proof 472,744 B**（bench FRI params、demonstration-only）。vendored `docs/bench/plonky3-shield-air/mu_front_air.rs`（sha256 `69980649…bef7a3`、両側一致）。これで front 側の残 `GADGET_ONLY_NOT_WIRED`（μ/tr/c̃'）が BOUND へ移り、item (iv) の残は「front を downstream gadget（UseHint→w1Encode、sigDecode→c̃、pkDecode/ExpandA→pk）に束ねる composition」に狭まる。
- **残る未達（C-03 が OPEN である理由）:**
  - item (iv) **full-scale single-relation composition** — 全 gadget（ExpandA/SampleInBall/UseHint/hint-canonicity/norm/decode/SHAKE multi-block/NTT fwd+inv/matvec/**μ-front**/pk_receipt bridge）を **一つの `circuit_version=3` constraint system**に、**k=8 / L=7 / N=256 full-scale** で統合し、Provider Claim witness・circuit-3 dispatch・receipt transcript・session/counter/pricing と接続する。
  - item (v) **libcrux full-signature accept-diff**（統合回路 accept/reject == libcrux full verify）。
  - item (vi) 外部監査 + Solidity dispatch + real-proof E2E（M-01）。
  - **ハードウェア:** full-scale 集約 STARK は ≥32 GB を要する（現 host 15 GB）+ recursion clone 再構築が前提。**現セッションでは production-scale 集約は未生成。**
- **明言:** **front の in-AIR binding + circuit-3 surface ≠ full-receipt-circuit の統合**である。**C-03 が open である限り A7 は NO-GO** という監査の結論に完全に同意する。

---

## 3. High

### H-04 [High] 匿名receipt鍵アーキテクチャと実サービス実装が矛盾する

**監査の主張:** ADR-0037 の匿名 path は handshake が長期 pk_receipt を平文送信しないこと・`SignedReceipt` が `provider_pk` を持たないこと・claim_secret 由来の per-session key で receipt を署名することを要求する。しかし実装は `ProviderIdentity` に長期 pk_receipt を格納して handshake 提示し、`ProviderContext` が長期 `ReceiptSigner` を保持、`SignedReceipt` も `provider_pk` 自己包含。追加された `session_receipt_key` は 64-byte Hash64 を返すだけで ML-DSA-87 keygen / signing / verification / C-P6 relation に未接続。→ requester/relay/receipt-log が長期 public key で複数 session を同一 provider に linkでき、which-provider privacy が破れる。

**Triage 判定: TRUE_GAP（newly identified、監査正）→ 閉鎖。** 対応（commit `b620796`）:

- **別 INERT anonymous serving lane を新設**（ADR-0037 §3 #2/#3）。live named v0 lane（`SignedReceipt`/`accept_channel`/`ProviderContext.receipt_signer`）は byte-for-byte 不変のまま、匿名 lane が三つの audited point すべてで長期鍵リンクを除去する:
  - `mil/core/receipt.rs`: `ReceiptSigner::from_session_key(session_rk)` が（従来 dangling だった）session_receipt_key 導出を実 ML-DSA-87 keygen に接続（64-byte `session_rk` を 32-byte seed に圧縮、新 `MIL_SESSION_RK_SEED_DOMAIN`）。新 `AnonSignedReceipt { body, signature }`（**provider_pk なし**）+ `sign_anon`/`verify_with_key` + `AnonReceiptChainVerifier`。
  - `mil/core/ident.rs`: `session_id_anon(kem_ct, nonce_req)`（quote_hash を含まないので session id が provider epoch を名指さない）+ `MIL_SESSION_ANON_DOMAIN`。
  - `mil/channel/wire.rs`: `AnonServerHello`（pk_receipt なし、per-session `session_pk` + ephemeral `pk_kem` を carry）、`accept_channel_anon`/`establish_channel_anon`。
  - `mil/provider/anon.rs`: `serve_session_anon(session_rk, …)` — ephemeral KEM、per-session signer、provider-non-naming receipt。main.rs へ未配線（INERT、fail-closed）。
- **強制されること:** requester / relay / receipt-log は 3 つの audited point で長期鍵を一切観測しない。**残余（正直な開示、out of session）:** in-circuit leaf↔per-session-key binding（C-P6/B1）、blind membership attestation（§3 #2、mil-shield では reference-only）、claim_secret→provider plumbing。

### H-02 [High] A2を含むexact activation release graphが再現build されない — PARTIALLY_TRUE（外部）
### H-03 [High] production client prover が fail-closed stub のまま — PARTIALLY_TRUE（外部 / 数週間）

いずれも `0bfa145` サイクルと状態不変（H-02 の combined `evm-shield-stark` compile gate は `36d67cb` で既に追加済、A2 patch pin / reproducible signed binary / real prover は外部）。本対応で新たな閉鎖は主張しない（§9）。

---

## 4. Medium

### M-07 [Medium] whole-sompi quote invariantがauthoritative funding pathへ未配線

**監査の主張:** `checked_gross_sompi` / `shielded_quote_gross_sompi` は正しい pre-funding reject helper だが、実際の authoritative funding/quote path が存在せず不変条件が API で強制されない。post-service `SessionRecord` の quantize は on-chain settlement amount を変えない。→ guard を通らない価格/token 組で escrow を fund すると contract-computed gross の 88% が whole-sompi にならず、provider claim が `SplitMismatch` で永久失敗しうる。

**Triage 判定: TRUE_GAP（監査正）→ 閉鎖。** 対応（commit `6b82b36`）:

- `MilShieldedEscrow.setClaimPolicy` が **`WHOLE_SOMPI_PRICE_STEP`（25_000）の倍数でない uniform price を新 `PriceNotWholeSompi` error で拒否**。倍数なら `gross = 25·(price/25_000)·tokens` が全 token count で 25 の exact 倍数（/1000 floor 剰余なし）となり、admit された escrow は claim-time `SplitMismatch` trap に決して当たらない — funding-time liveness hazard を **governance-time rejection** に置換。per-claim `SplitMismatch` は belt-and-suspenders として残置。
- `misaka_mil_shield::economics` に mirror の `WHOLE_SOMPI_PRICE_STEP` + `price_yields_whole_sompi` を追加し、gate が permanently-settleable な escrow のみ admit することを SOUND-and-TIGHT property test（`claim_v2_split` が gated price で決して SplitMismatch しない、広範な token grid）で証明。forge 81/81。
- **残余（正直な開示）:** v0 provider は direct-pay（in-crate escrow なし）で、authoritative escrow-funding SDK path（v1 §8.2）は未実装。その path 実装時に `shielded_quote_gross_sompi` 経由を必須化する（現状 reachable な gross producer は全 gated）。

### M-10 [Medium] pk_receipt bridgeが型安全でもauthoritativeでもない

**監査の主張:** `pk_receipt_hash_of` / `ProviderLeaf::from_pk` / `enforce_pk_receipt_binding` が `&[u8]` を受け、ML-DSA-87 pk の 2592-byte 長を型/runtime で強制しない。任意長 bytes の hash を「real ML-DSA key 由来」として扱える。加えて主要 `verify_reference(_v2)` は opaque `pk_receipt_hash` のみ使い実 key を消費しない。

**Triage 判定: TRUE_GAP（newly identified、監査正）→ 閉鎖。** 対応（commit `b620796`）:

- `mil/shield/provider.rs` に **length-checked `PkReceipt([u8; 2592])` newtype**（checked `new`/`TryFrom`、新 `PkReceiptBadLength` error）を導入。`pk_receipt_hash_of` / `ProviderLeaf::from_pk[_and_secret]` / `enforce_pk_receipt_binding` / `verify_reference*_with_pk` が `&PkReceipt` を取るので、**wrong-length key が provider_id hash に到達し得ない**。`misaka_mil_core::ident::provider_id` との byte-identity を differential test で保持、`MIL_MLDSA87_PK_LEN` を mil-core に pin。
- **残余（正直な開示）:** 同じ key bytes を identity hash と in-circuit ML-DSA-87 verify の双方へ一度だけ供給する full binding は circuit_version=3 の job（C-03 item iv）。standalone `pk_receipt_bind_air.rs`（`8208ee0`、wire 24）が `pk_receipt_hash == H(pk)` を in-AIR で証明済だが、その pk が *verify される* pk であることの強制は item (iv)。

### M-01 / M-02 / M-03 / M-06 / M-08 — 外部 / 数週間 / ceremony（本対応で新規閉鎖を主張しない）

`0bfa145` サイクルと同じ位置づけ（M-02 の node 側 empty-statement fail-closed は `f7ef994`、DA cap 整合は `b7316df` で既存）。詳細は §9。

---

## 5. Low

### L-01 [Low] trust-anchor serializationにpanicまたはsilent fallbackが残る

**監査の主張:** `compute_vk_hash` は in-memory Borsh serialization を `expect`、`context_from_proof` 系は `postcard::to_allocvec` 失敗を `unwrap_or_default()` で空 bytes に変換。現型では失敗しにくいが、trust anchor 生成で panic または「異なる context が同じ empty fallback へ縮退（hash alias）」を許す理由はない。

**Triage 判定: TRUE（監査に同意、A7 blocker でない）→ 閉鎖。** 対応（**本対応**、`mil/shield-stark-verify/src/lib.rs`）:

- `compute_vk_hash` / `encode_preprocessed` / `context_from_proof` を **typed `Result<_, StarkVerifyError>` 化**し、新 `StarkVerifyError::ContextSerialization(&'static str)`（fail-closed、telemetry-only、consensus-branch しない）を追加。**全 `unwrap_or_default()` / `expect` を除去**: これで (a) serialization 失敗が panic でなく明示 `Err` になり、(b) empty-fallback aliasing（異なる context が `b""` に縮退して同一 `vk_hash` になる）が構造的に消える。backend caller（`ceremony_vk_hash`/`ceremony_preprocessed_commitment`/`verify_outer_proof`）は `?` 伝播に更新。
- **acceptance:** 新 test `vk_hash_is_a_typed_result_without_empty_fallback_aliasing` — 正常 context は `Ok`、空 vs 実 `preprocessed_commitment` は決して同一 `vk_hash` にならない（no empty-fallback aliasing）。default build **24/24**（23→24）green、`stark-backend` feature build clean。全変更は F006 fence の内側で inert（consensus-neutral）。

### L-04 [Low] quantize_gross_upのAPI契約がu64上端で成立しない

**監査の主張:** doc は「smallest claimable gross >= gross」と説明するが、u64 上端 25-wide band では overflow 回避のため `MAX_WHOLE_SOMPI_GROSS` へ clamp down（PoC: `quantize_gross_up(u64::MAX)=18,446,744,073,709,551,600`、入力より 15 小さい）。結果は 25 の倍数だが round-up 性が破れる。

**Triage 判定: TRUE_GAP（newly identified、監査正）→ 閉鎖。** 対応（commit `6b82b36`）:

- `quantize_gross_up` を `saturating_add` → `checked_add` に変更し、top 25-wide overflow band `(MAX_WHOLE_SOMPI_GROSS, u64::MAX]` を `MAX_WHOLE_SOMPI_GROSS = u64::MAX − (u64::MAX % 25)` へ clamp DOWN（結果は**常に** 25 の倍数、panic なし）。doc を honest 化（unconditional round-up でなく「in-range ceil-to-25 / physically-unreachable band で clamp-down」）。
- round-up の honest contract が必要な caller 向けに `checked_quantize_gross_up -> Result<u64, QuoteError::Overflow>`（`>=`-or-reject）を split-out。record path（total、non-panicking）は挙動不変。property test `quantize_gross_up_never_emits_a_non_multiple_on_the_overflow_band`。

### L-03 [Low] readiness文書と実装状態が一部過大表現・不整合 — 部分（honest 分離を維持）

本書 + `docs/mil-shield-cp6-mldsa-in-circuit-design.md §7.1` の wire inventory は各 wire を `BOUND` / `GADGET_ONLY_NOT_WIRED` / `FREE` で明示し、μ-front の `BOUND` 化と C-03 の OPEN・full-scale 未達を honest に分離している。full な snapshot-specific readiness control matrix 再生成は follow-up doc（A7 blocker でない）。

---

## 6. 前回差分（監査の Closed/Improved 評価）への応答

監査 summary の `closed_or_improved`（C-01/C-02 amount/share binding、H-01 claim ctx、M-04 circuit snapshot、M-05 backend ADR、M-09 SHAKE byte canonicality、L-02 DA cap）はすべて `0bfa145` 以前で閉鎖済であり、本対応で維持する。M-09（`shake_threaded_air.rs` の squeeze 公開 byte 8-bit range-check）は本対応の `mu_front_air.rs` にも継承され、各 segment の squeeze output byte が canonical に拘束される。

---

## 7. A7 activation acceptance gate（G1-G15）— 本対応後の自己評価

| Gate | 監査判定 | 本対応後（自己評価） |
|---|---|---|
| G1 Receipt authorization | Fail | **OPEN（同意）** — circuit-3 surface（`24d221d`）+ decode/μ front（`mu_front_air.rs`）で前進、full-scale k=8 集約は未達。数週間 + ≥32 GB |
| G2 Legacy-path retirement | Fail | **OPEN（同意）** — circuit 3 統合時に確定 |
| G3 Typed A2 | Fail | node 側 empty-fail-closed（`0bfa145`）。type-based soundness 半分は外部 |
| G4 Atomic K-01 | Fail | 機構完備 + on-disk patch-hash pin。原子 freeze は ceremony（外部） |
| G5 Production prover | Fail | **OPEN（同意）** — API honesty 済、実 prover は外部 / 数週間（H-03） |
| G6 Exact node build | Fail | combined compile gate（`36d67cb`）。A2 patch + signed binary は外部 |
| G7 P4 real-proof E2E | Fail | **OPEN（同意）** — H-03 実 prover 依存（M-01） |
| G8 Escrow policy | Partial | atomic `setClaimPolicy` + wildcard-0 除去（`0bfa145`）+ whole-sompi price gate（`6b82b36`、M-07）。receipt-enforcing 化は circuit 3 着地時 |
| G9 Pricing invariant | Partial | **閉鎖前進（`6b82b36`）** — funding-entry whole-sompi gate + quantizer boundary（L-04）。v1 SDK path は未実装 |
| G10 AIR byte canonicality | 前回閉鎖 | 維持 + `mu_front_air.rs` に継承（M-09） |
| G11 Determinism | Not evidenced | **OPEN（同意）** — cross-arch CI infra（M-06、外部） |
| G12 Resources | Not evidenced | **OPEN（同意）** — hardware 較正（M-08、外部） |
| G13 CI/provenance | Partial | combined compile gate。signed provenance / cross-arch は外部 |
| G14 External audit | Pending | **OPEN（同意）** — 本 static follow-up は native/upstream audit を代替しない |
| G15 Rollout | Pending | **OPEN（同意）** — 運用 rehearsal 未実施 |

**結論: G1（C-03）が open である限り A7 = NO-GO。監査と完全に一致する。** F006 fence（全 preset `u64::MAX`）維持、anonymous claim disabled 維持、manifest anchor 未 freeze 維持。

---

## 8. ビルド・テスト証跡

- `mil/shield-stark-verify`（**L-01**、default = INERT verifier）: **24/24**（23→24、`vk_hash_is_a_typed_result_without_empty_fallback_aliasing` 追加）。`--features stark-backend` build clean（backend module の `context_from_proof`/`compute_vk_hash`/`encode_preprocessed` の `Result` 化 caller 込み）。
- `mu_front_air.rs`（**decode/μ front**、`.119` `~/Plonky3/shield-air`、実 libcrux ML-DSA-87 署名）: GATE 1（host sponge == sha3、3 real msg）/ GATE 2（trace re-read == sha3）/ GATE 3（reference front == libcrux accept ∧ `c̃'==c̃`）/ GATE 4（coverage self-audit: 100 wires、3770 msg + 310 pad bindings、TR/MU tie が public index を厳密に共有）+ **VERIFY ok**（prove 10.7 s / verify 142 ms、5897 cols × 1024 rows、prep 33、4050 publics、proof 472,744 B）。4 negatives（`--corrupt-thread`/`--corrupt-tie`/`--corrupt-ctilde`/`--corrupt-w1`）すべて `OodEvaluationMismatch` で reject。vendored sha256 `69980649cf89fdef8cebac71f0844e3b139d90f77750b8e2350206c5abbef7a3`（両側一致）。
- 既存の H-04/M-07/M-10 remediation の crate test（`b620796`/`6b82b36`）は各コミットメッセージに記載（mil-core 38 / mil-channel 13 / mil-provider 45 / mil-shield 59 / forge 81）。

---

## 9. 残フォローアップ（正直な外部 / 数週間 / hardware ゲート — overclaim しない）

以下は本対応で**閉じていない**。実証明 + 新規外部監査なしに閉じたと主張しない。**これらが real proof + fresh audit で閉じるまで A7 は NO-GO を維持し、F006 fence は `u64::MAX` のまま**であることに同意する。

| 項目 | 種別 | 内容 |
|---|---|---|
| **C-03 / G1-G2** | Critical activation blocker + **hardware** | item (iv) full-scale（k=8/L=7/N=256）single `circuit_version=3` composition（front を含む全 gadget を 1 relation へ、cross-stage binding を全 wire で解消）/ (v) libcrux accept-diff / (vi) 外部監査 + circuit-3 dispatch + real-proof E2E。**≥32 GB proving box + recursion clone（`b363397`）再構築が前提。数週間規模。** decode/μ front（本対応）は front 部分の前進であり統合ではない |
| **H-02(b)/(d)** | 外部（A6-gated / release eng） | A2 `[patch]` の pin / reproducible + signed release binary |
| **H-03 / M-01** | 外部 / 数週間 | real production prover crate + real-proof E2E differential corpus |
| **M-02 soundness 半分** | 外部 / 数週間 | typed `public_surface` NpoTypeId 選択（audit-gated A2 patch 内） |
| **M-03 freeze ceremony** | 外部 ceremony | manifest を Unfrozen/Frozen enum とし全 anchor を atomic all-or-none freeze |
| **M-06 CI infra** | 外部 / 数週間 | exact release build / A2 patch build / production prover / real proof E2E / cross-arch parity / fuzz / resource benchmark / signed SBOM の required gate 化 |
| **M-08 hardware calibration** | 外部 | proof/metadata/gas cap の slowest no-SIMD hardware worst-case 較正 |
| **L-03 doc follow-up** | doc | full snapshot-specific readiness control matrix 再生成 |
| **G14/G15** | 外部・運用 | 独立外部監査 → canary/rollback rehearsal → activation-height-only release 差分監査 |

> 本対応は静的修正（**H-04/M-07/M-10/L-01/L-04 閉鎖**）+ **C-P6 decode/μ front の in-AIR BOUND 化（`mu_front_air.rs`、実 libcrux 署名、4 negatives）** + circuit-3 production surface（INERT）+ 正直な外部/ハードウェアゲート開示であり、**A7 activation の解除を主張するものではない**。full-scale k=8 集約（≥32 GB + recursion clone）・実 prover・atomic freeze ceremony・CI infra の後、本書と修正 commit 群を入力として G14 独立監査へ進むことを推奨する。**F006 fence（全 preset `u64::MAX`）と claims disabled は本対応後も維持する。**
