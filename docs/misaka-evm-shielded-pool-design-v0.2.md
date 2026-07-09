# MISAKA EVM Shielded Pool 設計書 v0.2

Status 2026-07-09. **Proposed — design only, nothing implemented.** 本書は EVM レーン
(ADR-0020 の `revm` バックエンド, Shanghai pin) 上に、送信者・受信者・金額・トークン種別を
秘匿する「シールドプール」を追加する最小設計である。移植元選定は
[ADR-0033](adr/0033-evm-shielded-pool-porting-source.md) に分離した。本書の各 §N は当該 ADR
から参照される。

関連: [`misaka-evm-design-v0.4.md`](misaka-evm-design-v0.4.md) (EVM レーン本体),
[`misaka-base-3lane-execution-design-v0.1.md`](misaka-base-3lane-execution-design-v0.1.md)
(Lane 3 = proof-verified parallel EVM; 本書の verifier precompile と escrow 規則はこの設計の
proof-system policy §8.12 / native token §10.3 / asset gate §10.5 の枠内に収める),
[`docs/evm-differences-from-ethereum.md`](evm-differences-from-ethereum.md) (precompile policy),
`kaspa-evm/src/precompiles.rs` (F002/F003 登録シーム), `kaspa-evm/src/mldsa_verify.rs`
(F003 = 本書 F006 の実装テンプレート), `consensus/core/src/evm/mod.rs` (EVM 定数)。

---

## §0 結論

3 行で:

1. **プライバシー方式は Zcash 系 (commitment + nullifier + membership 証明) を採る**が、
   Zcash/Starknet いずれの実装バイナリも移植不可 (曲線・VM・証明系が非互換)。実体は「監査済み
   仕様の Solidity + Rust 再実装」であり、証明系は **STARK 系 (ハッシュ仮定のみ)** を採用して
   検証を **F006 verifier precompile** としてノードに追加する ([ADR-0033](adr/0033-evm-shielded-pool-porting-source.md))。
2. **健全性 (偽造引き出し = インフレ耐性) は最初から PQ**。EVM レーンで secp256k1 を許して
   いても、シールドプールからの引き出し健全性だけはハッシュ仮定に閉じるため量子機に対して壊れない。
   これは EVM レーンにおける唯一の「フル PQ 島」であり、投資家向けの差別化点になる (§11)。
3. **秘匿性 (note 暗号) は X25519 + ML-KEM-1024 ハイブリッド**にする (EC 単独は不可・PQ 必須・
   形はハイブリッド・パラメータ 1024)。EC 単独の ECDH note 暗号は harvest-now-
   decrypt-later で過去のシールド取引が遡及的に剥がれる — アカウント鍵は量子機到来前に移行できても、
   *過去の秘匿は移行できない*。README がすでにトランスポート層 ML-KEM ハイブリッドに言及して
   いるため、レイヤー横断で一貫する。

本設計が採用しないもの:

- 固定額ミキサー (Tornado 型)。額面が量子化されて見えるため「金額秘匿」を満たさない (§1.3)。
- confidential-amount のみ方式 (Solana CT 型)。宛先が公開のままで「相手秘匿」を満たさない。
- pairing / trusted setup を用いる証明系 (Groth16/PLONK)。CRS toxic waste を量子機が dlog で
  復元でき、シールドプールから偽造引き出し = 検出不能インフレになる ([ADR-0033](adr/0033-evm-shielded-pool-porting-source.md) の却下理由 R-2)。
- AMM スワップ・貸付・ブリッジ着金用の open note (実行時金額確定プレースホルダ)。DeFi 合成は
  v0.3 以降。v0.2 は **送金のみ** (shield / private transfer / unshield)。
- Lane 3 (parallel EVM) への実装。シールドプールは Lane 2 (現行 ETH 互換 EVM) の
  システムコントラクトとして載せる (§2.1)。Lane 3 の proof pipeline とは verifier precompile を
  共有しうるが、v0.2 では独立させる。

---

## §1 目的・非目的・不可縮小性

### 1.1 目的

- EVM レーン上の MSK (および将来の ERC-20) について、送信者アドレス・受信者アドレス・金額・
  トークン種別を公開ビューから秘匿した送金を可能にする。プライバシー水準は Zcash Sapling/Orchard 相当
  (匿名集合内で送受信者と金額を隠す)。
- 秘匿引き出しの健全性 (プール残高保存則) を **量子耐性**にする。
- 規制対応のため、選択的開示 (viewing key を監査人に渡すと受信 note の金額・memo が見えるが spend は
  できない) を第一級で持つ。
- UTXO レーン・DAG consensus・供給保存則 (I-13) を不変に保つ。EVM レーンの secp256k1-free 既定
  ビルド方針 (ADR-0020 §20) と衝突しない (verifier precompile は署名スキームを追加しない)。

### 1.2 非目的

- shield / unshield 境界における金額・タイミング相関の消去。これはプール設計では消せず、運用
  ハイジーン (relayer, 遅延, 分割) の領域である (§10.2)。Zcash の t↔z 境界と同じ制約。
- MetaMask 完全互換のシールド UX。シールド送金には専用ウォレット prover が要る (§7)。
- Lane 3 の parallel/object モデルとの統合。
- 単一 note の物理的逐次限界の解消 (nullifier 集合への追記は逐次だが、これはプールの安全性の核)。

### 1.3 なぜこれ以上削れないか (不可縮小性)

「送信者・受信者・金額を匿名集合内で隠す」の情報理論的下限は
**commitment + nullifier + membership 証明**の 3 点セットである:

- **commitment** がないと金額・宛先を隠せない。
- **nullifier** がないと二重支払いを防げない (かつ nullifier は spend 時に *どの* commitment を
  消費したか漏らしてはならない — これが membership 証明を要求する)。
- **membership 証明 (Merkle + ZK)** がないと「有効な note を消費した」ことを送信元 note を明かさずに
  示せない。

Tornado 型固定額ミキサーはこの下限を金額次元で満たさず、confidential-amount のみは宛先次元で
満たさない。本設計はこの下限に MISAKA 固有の PQ 制約 (健全性ハッシュ仮定 + note 暗号 ML-KEM) を
足した最小形である。

---

## §2 アーキテクチャ概要

### 2.1 配置

シールドプールは **Lane 2 (現行 ETH 互換 EVM) 上のシステムコントラクト**として実装する。理由:

- Lane 2 はテストネットで稼働中の唯一の EVM レーンであり (ADR-0020)、`revm` 実行・keccak-MPT
  state・EIP-1559 basefee をそのまま使える。
- Lane 3 (proof-verified parallel EVM, 3-lane 設計 §8) はまだ shadow mode すら未到達 (§18 Phase 4)
  であり、その proof pipeline に依存すると本機能全体が Lane 3 の activation gate (§10.5) にブロック
  される。シールドプールは自前の verifier precompile を持つため、Lane 2 に閉じて独立に出荷できる。

3 コンポーネント:

| # | コンポーネント | 位置 | 新規性 |
|---|---|---|---|
| ① | `ShieldedPool` システムコントラクト | Lane 2, 予約アドレス `0x…F010` | Solidity 再実装 |
| ② | **F006** `SHIELDED_VERIFY` precompile | ノード (consensus-critical) | `mldsa_verify.rs` と同型の登録シーム |
| ③ | ウォレット prover + note スキャナ | オフチェーン (ユーザー端末) | 自前運用 |

### 2.2 データフロー

```text
shield (公開 MSK → シールド):
  user → ShieldedPool.shield{value}(cm_new[], encNote[])
       → プール残高 += value, Merkle tree に cm 追記

private transfer (シールド → シールド, 完全秘匿):
  wallet prover が STARK proof 生成 (端末)
       → relayer or user → ShieldedPool.transfer(proof, anchor, nf[], cm[], ctx, encNote[])
       → F006 が proof 検証 → nullifier 記録, cm 追記, プール残高不変

unshield (シールド → 公開):
  wallet prover が proof 生成
       → ShieldedPool.unshield(proof, anchor, nf[], cm[], vPubOut, to, ctx)
       → F006 検証 → プール残高 -= vPubOut, `to` に送金
```

3 動作は **同一 F006 回路のパラメタ化** (`v_pub_in > 0` / 両 0 / `v_pub_out > 0`) で兼用する。
回路が 1 つなのは匿名集合を分割しない (shield 専用回路と transfer 専用回路で集合が割れると匿名性が
下がる) ためである。

### 2.3 現行実装への接地

`consensus/core/src/evm/mod.rs` の予約システムアドレスは現在 `F001` (WMISAKA predeploy) /
`F002` (WITHDRAW) / `F003` (MLDSA87_VERIFY) / `F004` (HASH64, keyed BLAKE2b-512) /
`F005` (DNS_FINALITY) の 5 つ。`F004`/`F005` は MIL/PREA 系 precompile 群として追加され
`F003` の activation fence を共有する既存予約であり、シールドプールとは無関係。したがって
本設計は衝突を避けて次の空きスロット **`F006`/`F010`** を使う (この採番修正は
[ADR-0033](adr/0033-evm-shielded-pool-porting-source.md) の code-grounding で確定):

- `0x…F006` = `SHIELDED_VERIFY` precompile (verifier)。
- `0x…F010` = `ShieldedPool` システムコントラクト (通常コントラクトとして activation state に
  predeploy; precompile ではない。`WMISAKA_ADDRESS` = `F001` と同じ扱い)。

F006 は `F003` (`mldsa_verify.rs`) と**同型の call-frame interception 登録シーム**で載せる —
`register_all_misaka_precompiles(handler, ...)` に `f006_active` を足し、activation fence
(`evm_f006_shielded_verify_activation_daa_score`, 全ネットワークで `u64::MAX` 初期値) 未満では
未登録 = 空アカウント扱いで genesis/state-root 不変 (F003 と同じ inert 性)。

---

## §3 Note と Commitment

### 3.1 Note 構造

```text
Note = (
  value      : u64          // wei ではなく sompi 単位 (EVM_NATIVE_SCALE で wei 換算)
  a_pk       : Hash256      // 受信者の shielded address (= H("addr", sk))
  rho        : Hash256      // nullifier seed (出力時に決定, §3.3)
  r          : Hash256      // commitment trapdoor (乱数)
  token_id   : u32          // 0 = MSK; 将来 ERC-20 は登録 id
)
```

`value` を wei でなく sompi (8 decimals) で持つのは、UTXO レーンとの supply 保存 (I-13) を
シールドプール内でも exact に保つため。プール残高は wei で持つが、shield/unshield 境界で
`EVM_NATIVE_SCALE` の exact multiple を強制する (F002 withdraw と同じ規則, v0.4 §9.1)。

### 3.2 Commitment

```text
cm = H("MISAKA_SHIELD_CM_V1", value ‖ a_pk ‖ rho ‖ r ‖ token_id)
```

H は F006 回路内でアクセラレートされているハッシュ (§5.3 参照)。ドメイン分離文字列は
`consensus/core/src/evm/mod.rs` の既存 `MISAKA_EVM_*_CONTEXT` 群と同じ命名規約に従い、activation で
凍結する。

### 3.3 Nullifier と rho 束縛 (Faerie Gold 対策)

```text
nf = H("MISAKA_SHIELD_NF_V1", sk ‖ rho)

出力 note の rho:
  rho'_j = H("MISAKA_SHIELD_RHO_V1", nf_old_1 ‖ nf_old_2 ‖ j)   (j = 出力 index)
```

出力 note の `rho'` を入力の nullifier に束縛することで、同一 rho を持つ note を 2 つ作らせて片方しか
使えなくする **Faerie Gold 攻撃**を防ぐ。nullifier のグローバル一意性から出力 rho の一意性が導かれる
(Zcash Sprout と同じ構造)。これは回路制約 4 行 (§4.1) で表現する。

---

## §4 F006 回路仕様 (JoinSplit statement, 2-in / 2-out)

### 4.1 statement

```text
公開入力 (public inputs, F006 の calldata に載る):
  anchor              // Merkle root history ring 内のいずれかの root
  nf_old[2]           // 消費 note の nullifier (ダミー入力はランダム値)
  cm_new[2]           // 新規 note commitment
  v_pub_in            // 公開入金額 (shield 時のみ非零)
  v_pub_out           // 公開出金額 (unshield 時のみ非零)
  token_id            // このトランザクションのトークン種別
  ctx                 // H(chain_id ‖ pool_addr ‖ to ‖ fee ‖ v_pub_out ‖ token_id ‖ ...)

witness (proof 生成時のみ, 公開されない):
  入力 i (i∈{1,2}): note_i, sk_i, merkle_path_i, enable_i
  出力 j (j∈{1,2}): (v'_j, a_pk'_j, r'_j)

制約:
  1. enable_i = 1 ⇒ MerkleVerify(anchor, path_i, cm_i)
     cm_i = H("MISAKA_SHIELD_CM_V1", v_i ‖ a_pk_i ‖ rho_i ‖ r_i ‖ token_id)
     enable_i = 0 (ダミー) ⇒ v_i = 0 を強制, membership 免除
  2. a_pk_i = H("MISAKA_SHIELD_ADDR_V1", sk_i)          // spend 権限
  3. nf_old_i = H("MISAKA_SHIELD_NF_V1", sk_i ‖ rho_i)
  4. rho'_j = H("MISAKA_SHIELD_RHO_V1", nf_old_1 ‖ nf_old_2 ‖ j)  // Faerie Gold 対策
  5. cm_new_j = H("MISAKA_SHIELD_CM_V1", v'_j ‖ a_pk'_j ‖ rho'_j ‖ r'_j ‖ token_id)
  6. Σ v_in + v_pub_in = Σ v'_out + v_pub_out           // 値保存
  7. 全 value に 64-bit range check                     // オーバーフロー/負値防止
  8. 全 note が同一 token_id                            // トークン混同防止
```

### 4.2 ctx の役割 (盗難 / リプレイ / クロスチェーン防止)

`ctx` は F006 回路の外 (`ShieldedPool` コントラクト側) で実際のコールパラメータから再計算して
照合する:

- **relayer 盗難防止:** unshield 先 `to` と `v_pub_out` を ctx に含めるため、relayer が
  proof を横取りして `to` を自分に差し替えても ctx が一致せず revert する。
- **クロスチェーン/クロスレーン リプレイ防止:** `chain_id` (= `EVM_CHAIN_ID` = `0x4D534B`) と
  `pool_addr` を含めるため、同一 proof を別ネットワーク/別レーンで再利用できない (3-lane I-04 と
  整合)。
- **手数料束縛:** `fee` を含めるため、proof 生成時に想定した手数料が改竄されない。

### 4.3 ダミー入力・出力

2-in/2-out 固定にするのは回路サイズを一定に保ち匿名性を均一化するため。実際の送金が 1 入力 1 出力でも、
残りは `enable=0` のダミー (value 0, membership 免除) で埋める。これにより「入力数・出力数」からの
サイドチャネルを消す (Sprout と同じ)。

---

## §5 証明系と F006 precompile

### 5.1 証明系ポリシー (3-lane §8.12 と整合)

3-lane 設計 §8.12 は Lane 3 に「pairing-based proof のみを使う場合は classical security であり、
native asset escrow に上限を設ける。PQ settlement を維持するなら hash-based proof を長期要件と
する」と定めている。シールドプールはこの規律を**そのまま継承**し、より強く:

- **hash-based STARK のみを production で受理する** (`proof_system_id` = STARK)。pairing-based は
  健全性が量子機に対して壊れる ([ADR-0033](adr/0033-evm-shielded-pool-porting-source.md) R-2) ため、
  テストネットの踏み台としても escrow cap 下でしか許さない。
- proof system は `proof_system_id` / `circuit_version` / `verifier_key_hash` で version 化する
  (3-lane §8.12 と同じ 3 つ組)。
- verifier upgrade は Base hard fork または明示 governance activation とする (3-lane I-23)。

### 5.2 F006 precompile インターフェース

`mldsa_verify.rs` の F003 と同じ設計:

```text
address: 0x…F006  (MISAKA_SHIELDED_VERIFY_PRECOMPILE)

calldata (version-discriminated, input[0]):
  0x01 (transfer): version(1) ‖ proof_system_id(1) ‖ circuit_version(2) ‖
                   verifier_key_hash(32) ‖ public_inputs_len(4) ‖ public_inputs(..) ‖
                   proof(..)

output: 32-byte ABI bool (0x…01 valid / 0x…00 otherwise)

性質:
  - PURE verify: state を変えず value を動かさない → STATICCALL からも到達可 (F003 と同じ)。
    non-payable: 非零 msg.value は revert (F003 と同じ、value 座礁防止)。
  - 任意の malformed length / unknown version / verifier_key_hash 不一致 / invalid proof は
    ABI false を返す。NEVER panic, NEVER revert (F003 と同じ fail-closed)。
  - F006_VERIFY_GAS を dispatch 前に一括課金 (malformed flood も同額) → per-block/per-tx の
    STARK 検証 CPU の決定的上限。
  - 決定性: verifier は libcrux 同様に単一 portable 実装を呼ぶ (per-CPU SIMD 分岐なし)。
    accept/reject が全ノード bit-identical でなければ consensus split になる (F003 audit H-2 と
    同じ要件)。
```

### 5.3 回路内ハッシュの選択

回路制約 (§4.1) の H は 2 択:

- **選択肢 A (推奨, prover 高速):** zkVM がアクセラレートするハッシュ (Risc0 なら SHA-256, S-two/
  Circle STARK なら Poseidon over M31) をドメイン分離して使う。prover 時間が実用的。
- **選択肢 B (Hash64 統一):** MISAKA の keyed BLAKE2b-512 (Hash64) で統一。consensus identity と
  文字通り同一ハッシュになり美しいが、zkVM 内加速がないため prover 時間が数倍〜十数倍。

v0.2 は**選択肢 A** を採る。Hash64 統一は美観上の利益はあるが prover UX を壊す。ただし F006 が
検証するのは STARK proof であり、その proof が内部で使うハッシュはコントラクトからは
`verifier_key_hash` にコミットされるだけなので、A/B は将来 `circuit_version` で切替可能
(consensus 変更を伴う)。

### 5.4 集約 (v0.3+)

STARK proof は 1 件 100〜300KB (zkVM succinct) で、これが DA 予算の支配項 (§8)。v0.3 で recursion
集約 (k 件の joinsplit を 1 proof に畳む) を入れる。3-lane §8 の Lane 3 proof pipeline が recursion を
前提にしているため、その verifier crate を共有できる可能性がある。

---

## §6 Consensus 統合と Skip Semantics

### 6.1 delayed acceptance 下での扱い

EVM レーンは mergeset delayed acceptance (v0.4 §3) で実行される。シールドプール tx は通常の EVM
user tx として payload に載り、accepting chain block で実行される。追加の consensus 難度はほぼない:

- **nullifier 衝突:** 同一 nullifier を消費する 2 tx が同一 accepting block の canonical order に
  並んだ場合、後者は `ShieldedPool` コントラクト内の `require(!nullifiers[nf])` で revert する。
  これは **クラス 4 (実行時失敗)** (v0.4 §6.1) であり、block は valid のまま。DAG 並行性特有の問題は
  既存 skip class の枠内に収まる。
- **anchor 陳腐化:** proof は過去の Merkle root (anchor) に対して作られる。accepting block 時点で
  anchor が root history ring から溢れていれば `ShieldedPool` が revert (クラス 4)。ring 深さを
  DNS finality 窓より大きく取ることでこれを回避する (§6.3)。

### 6.2 skip class への割当

| 事象 | クラス (v0.4 §6.1) | 帰責 |
|---|---|---|
| calldata 不正・proof 長不正 | 4 (実行時失敗, F006 が ABI false → コントラクト revert) | user |
| nullifier 二重消費 | 4 (コントラクト revert) | user |
| anchor が ring 外 | 4 (コントラクト revert) | user |
| F006 proof invalid | 4 (F006 false → コントラクト revert) | user |
| shield 時 msg.value が `EVM_NATIVE_SCALE` の非整数倍 | 4 (コントラクト revert, F002 と同規則) | user |

**すべてクラス 4 に閉じる**のが本設計の安全側の要点: F006 は fail-closed で ABI false を返すのみ
(revert しない) で、判断は必ず `ShieldedPool` コントラクトの Solidity 側 revert に落ちる。したがって
payload block を invalid にする経路が存在せず、悪意ある proof flood は攻撃者のガスを焼くだけ。

### 6.3 anchor / DNS finality

- `ShieldedPool` は Merkle root history を ring buffer で保持する。ring 深さ ≥ DNS finality 深さ
  相当 (ADR-0009; 現行 production preset の stake-depth) にする。
- ウォレットは **DNS-final な root に対して proof を作る**運用規約とする。これにより reorg で anchor が
  巻き戻って再証明が必要になる事態を消す (reorg は pointer 切替のみ, v0.4 §10 / I-3 と整合)。
- cm 追記・nullifier 記録はコントラクト storage への通常書き込みなので、reorg 時は既存の
  reversed-diff / pointer 切替経路で自動的に巻き戻る (F002 の synthetic UTXO materialization と
  同じ性質)。

---

## §7 Note 暗号と選択的開示

### 7.1 X25519 + ML-KEM-1024 ハイブリッド note 暗号

出力 note を受信者だけが復号できるよう暗号化して on-chain に載せる (`encNote`)。方式は
**X25519 (classical) + ML-KEM-1024 (PQ) の PQ/classical ハイブリッド KEM**。共有秘密は両者を
KDF に通して 1 本にまとめ、AEAD 鍵にする。攻撃者は秘匿を剥がすのに **X25519 と ML-KEM の両方を
破らねばならない**:

```text
シールドアドレス公開部: a_pk(32) ‖ x25519_pk(32) ‖ ml_kem_ek(1568)   // 計 ≈ 1.63 KB

encNote (出力あたり):
  x25519_eph_pk(32) ‖ ml_kem_ct(1568) ‖ AEAD_seal(K, note_plaintext)   (≈ 1.73 KB/出力)

共有秘密の導出 (送信側):
  ss_ec  = X25519(eph_sk, recipient_x25519_pk)
  ss_pq  = ML_KEM_1024.Encaps(recipient_ml_kem_ek) → (ml_kem_ct, ss_pq)
  K      = KDF("MISAKA_SHIELD_NOTE_V1", ss_ec ‖ ss_pq ‖ transcript)   // 両秘密を束ねる
```

ECDH 単独でなくこのハイブリッドにするのは HNDL 対策 (§0-3): PQ 成分 (ML-KEM-1024) が量子機に対する
秘匿を担い、過去のシールド取引が遡及的に剥がれない。そこへ X25519 を **+32B の保険**として重ねる —
ML-KEM は若い標準なので、実装バグや将来の解析に対し「両方を破らないと開かない」冗長性を持たせる
(TLS 1.3 `X25519MLKEM768` / Signal PQXDH と同形)。**EC 単独を却下しつつ EC を捨てない**理由は、EVM
レーンが EC 許容であり純血主義で外す利得がないため ([ADR-0033](adr/0033-evm-shielded-pool-porting-source.md)
R-4 / Decision item 2)。パラメータを 1024 (Cat 5) に固定するのは、CNSA 2.0 が指定する
ML-KEM-1024 + ML-DSA-87 のペアを (MISAKA は既に ML-DSA-87) 完成させ、*不可逆な唯一の部品*を Cat 3 に
落とさないため。KDF に AEAD を重ねる (KEM+AEAD) ので KEM が破れても対称鍵秘匿が残る保険も従来通り持つ。

### 7.2 note スキャン

ウォレットは全 `encNote` を trial-decrypt して自分宛て note を発見する。これは Zcash と同じ
「note discovery」問題で、匿名集合が大きいほどスキャンコストが増える。v0.2 では全件スキャン
(brute force)。将来最適化 (Zcash の light client / Starknet の discovery service 相当) は別途。

### 7.3 選択的開示 (監査対応)

ハイブリッド復号材 (**X25519 秘密鍵 + ML-KEM-1024 decapsulation key** の組) がそのまま
**incoming viewing key** になる:

- 監査人にこのハイブリッド復号材を渡すと、その利用者宛ての受信 note の金額・memo・token_id が
  見えるが、`sk` (spend authority) は渡さないので **spend はできない**。両秘密が揃って初めて
  `encNote` を開けるので、片方だけでは復号できない (§7.1 と整合)。
- Starknet STRK20 の「プール参加時に暗号化 viewing key を on-chain 登録し、規制要請時に指定監査人が
  その利用者分だけ復号」というスコープ付き監査モデル ([ADR-0033](adr/0033-evm-shielded-pool-porting-source.md)
  で移植元として評価) をそのまま借用できる。他の利用者の note には触れない。

これにより「Zcash 級プライバシー + 選択的開示」を投資家/規制に対してセットで提示できる。

---

## §8 サイズと容量・DA への影響

### 8.1 サイズ

| 要素 | サイズ |
|---|---|
| シールドアドレス | a_pk 32B + x25519_pk 32B + ML-KEM-1024 ek 1568B ≈ 1.63 KB |
| encNote (出力あたり) | x25519_eph 32B + ct 1568B + AEAD 本文 ≈ 1.73 KB (X25519 は +32B のみ) |
| STARK proof (zkVM succinct) | **100〜300 KB** (支配項) |
| STARK proof (手書き Plonky3 回路) | 50〜100 KB (工数増, v0.3+) |

### 8.2 容量制約との衝突

ここが MISAKA の容量制約と直に衝突する。EVM レーンの inclusion cap は
`MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK` = 32 KiB / DAG block
(`consensus/core/src/evm/mod.rs`)。**単一 STARK proof (100〜300KB) が 1 DAG block の payload cap を
単独で超えうる**。

対策:

- **v0.2:** proof を複数 DAG block に分割掲載できないため、まず **手書き回路 (50〜100KB)** か
  **強い recursion 圧縮**で単一 proof を 32 KiB 未満に収めることを activation の hard precondition と
  する。収まらない限りシールドプールは activate しない。
- **execution cap:** `MAX_EVM_ACCEPTED_GAS_PER_CHAIN_BLOCK` = `EVM_GAS_LIMIT` = 7.5M。F006 の
  `F006_VERIFY_GAS` を高く設定 (STARK 検証 CPU に見合う; F003 の 500k を参考に、STARK 検証はより重い
  ので数 M gas 級を想定) することで per-block のシールド tx 数を正直に絞る。
- **fee:** mass/gas 価格を正直に高く設定する。シールド tx 1 件は通常 tx 数十件分の DA/CPU を食う。
- **v0.3:** recursion 集約で k 件を 1 proof に畳み、DA 予算あたりのシールド tx 数を上げる。

### 8.3 gas 定数 (提案, activation で凍結)

`consensus/core/src/evm/mod.rs` に追加する定数 (F003 群と同じ命名):

```text
MISAKA_SHIELDED_VERIFY_PRECOMPILE = 0x…F006
MISAKA_SHIELDED_POOL_ADDRESS      = 0x…F010   // predeploy, not precompile
F006_VERIFY_GAS                   = TBD (STARK 検証ベンチ後; 低スペック no-SIMD 参照機で確定)
MAX_SHIELDED_VERIFY_PER_EVM_BLOCK = EVM_GAS_LIMIT / F006_VERIFY_GAS (gas-implied ceiling)
MAX_SHIELDED_PROOF_BYTES          = ≤ MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK 未満を強制
evm_f006_shielded_verify_activation_daa_score = u64::MAX (全ネットワーク, inert)
```

F003 と同じく、これらは `u64::MAX` inert 下では自由に調整可能で、activation DAA を設定した後の変更は
hard fork。

---

## §9 供給保存則

3-lane I-13 (`native supply はBase escrow + all lane balancesの保存則を満たす`) をシールドプール内でも
維持する:

```text
プール不変条件:
  ShieldedPool.balance(token_id) == Σ (未消費 note の value)   // token_id ごと

境界:
  shield:   Lane 2 公開残高 debit  → プール残高 += value, cm 追記 (供給中立)
  transfer: プール残高不変 (Σ in = Σ out, 制約 6)
  unshield: プール残高 -= v_pub_out → `to` に credit (供給中立)
```

MSK (token_id=0) については、プール残高は Base escrow → Lane 2 balance → ShieldedPool balance の
入れ子になる。UTXO レーンの supply root of truth (Base, 3-lane §10.3) は不変で、シールドプールは
Lane 2 balance の内訳を秘匿するだけであり新規発行はしない。これは F006 健全性 (制約 6 + range check)
が保証し、その健全性がハッシュ仮定に閉じる (量子耐性) のが §0-2 の核心である。

---

## §10 落とし穴

### 10.1 fee / ガスのプライバシー穴

joinsplit を提出する EOA とガス支払いは**公開**である。自分のメインアドレスから提出すると、
そのアドレスとシールド操作が紐付いて台無しになる。

- **最小対策:** `v_pub_out` の一部を relayer 報酬に充てる relayer パターン (Railgun 方式)。ユーザーは
  proof を relayer に渡し、relayer がガスを払って提出、報酬をプールから受け取る。ctx が relayer 差し替え
  盗難を防ぐ (§4.2)。
- **relayer 信頼:** relayer は検閲 (提出拒否) はできるが、盗難・改竄はできない (ctx 束縛)。複数 relayer /
  自己提出のフォールバックを持つ。

### 10.2 shield/unshield 境界相関

shield 時の入金額・タイミングと unshield 時の出金額・タイミングが相関すると、匿名性が下がる
(Zcash の t↔z と同じ)。これはプール設計では消せない:

- 運用ハイジーン: 標準額での shield、時間分散、複数回に分割した unshield。
- v0.2 の非目的 (§1.2) として明記し、ウォレット UX で警告する。

### 10.3 セキュリティ downgrade 表示

Lane 1 (PQ-EVM) から Lane 2 のシールドプールへ資産を動かす場合、ML-DSA 保護から secp256k1 保護への
downgrade になる (3-lane I-21 / §10.4)。ウォレットは明示確認を必須とし、自動 routing で downgrade
してはならない。ただしシールドプール内の**健全性**は PQ (§0-2) なので、「送金認可は secp256k1、
プール残高保存は PQ」という混在をウォレットで正確に表示する。

---

## §11 セキュリティ不変条件

3-lane §16 の書式に倣う。SP = Shielded Pool:

```text
SP-01: ShieldedPool.balance(token) == Σ 未消費 note value(token) を常に満たす (供給保存)。
SP-02: nullifier は一度記録されたら二度消費できない (二重支払い防止)。
SP-03: F006 は fail-closed: 任意の invalid proof / malformed input は ABI false を返し、
       revert も panic もしない。判断は必ず ShieldedPool の Solidity revert に落ちる。
SP-04: F006 の accept/reject は全ノード bit-identical (portable verifier, SIMD 分岐なし)。
SP-05: production は hash-based STARK proof のみ受理する (健全性が量子耐性; pairing 系は
       escrow cap 下のテストネット踏み台に限る)。
SP-06: note 暗号は X25519 + ML-KEM-1024 ハイブリッド (剥がすには両方を破る必要)。過去のシールド
       取引は量子機で遡及復号できない。
SP-07: proof は ctx (chain_id ‖ pool_addr ‖ to ‖ fee ‖ ...) に束縛され、relayer 盗難・
       クロスチェーン/クロスレーン リプレイができない (3-lane I-04 と整合)。
SP-08: anchor は DNS-final root history ring 内に限る。ring 外 anchor の proof は revert。
SP-09: cm 追記・nullifier 記録は通常 storage 書き込みで、reorg は pointer 切替のみで巻き戻る
       (v0.4 I-3 と整合)。
SP-10: F006 の per-block 検証数は F006_VERIFY_GAS の gas-implied ceiling で bound される。
SP-11: incoming viewing key (X25519 秘密 + ML-KEM decap key のハイブリッド復号材) は金額/memo を開示するが spend authority を
       与えない (選択的開示、監査対応)。
SP-12: シールド tx はクラス 1〜5 (v0.4 §6.1) の枠内でのみ skip/revert し、payload block を
       invalid にしない。
```

---

## §12 脅威モデル

3-lane §17 の書式:

| 脅威 | 影響 | 緩和 |
|---|---|---|
| 偽造 proof でプールから引き出し | インフレ (供給破壊) | F006 健全性 + STARK ハッシュ仮定 (量子耐性)。SP-01/SP-05 |
| 量子機による過去シールド取引のデアノン | プライバシー遡及崩壊 | X25519+ML-KEM-1024 ハイブリッド note 暗号。SP-06 |
| relayer による proof 横取り/宛先改竄 | 資金盗難 | ctx 束縛。SP-07 |
| nullifier 二重消費 | 二重支払い | コントラクト require + クラス 4 revert。SP-02 |
| anchor 巻き戻しによる再証明強要 | liveness/UX | DNS-final anchor 規約。SP-08 |
| proof flood (malformed) | DoS | F006_VERIFY_GAS 前払い + gas ceiling。SP-10 |
| verifier 実装の CPU 非決定性 | consensus split | portable verifier。SP-04 |
| shield/unshield 境界相関 | 匿名性低下 | 運用ハイジーン (非目的, §1.2/§10.2) |
| fee/EOA からの送信者特定 | 送信者秘匿崩壊 | relayer パターン。§10.1 |

---

## §13 Activation と移行計画

3-lane §18 の Phase 書式。シールドプールは **Lane 2 が Phase 2 (Lane 2 migration) 完了後**に載る。

### Phase SP-0 — prerequisite (hard gate)

- 単一 STARK proof が `MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK` (32 KiB) 未満に収まることを実測確認
  (手書き回路 or recursion 圧縮)。収まらない限り activate しない。
- F006 portable verifier の bit-identical 性を低スペック no-SIMD 参照機で確認 (F003 audit H-2 と同じ)。
- `F006_VERIFY_GAS` を STARK 検証ベンチで確定。

### Phase SP-1 — F006 + ShieldedPool predeploy (inert)

- `0x…F006` / `0x…F010` を予約。activation DAA = `u64::MAX` で inert (空アカウント扱い)。
- コントラクトを activation state に predeploy するが fence 下では到達不能。

### Phase SP-2 — testnet activate (escrow cap)

- testnet で activation DAA を設定。プール escrow に上限 (cap) を設け、withdraw rate limit と
  emergency freeze を実装 (3-lane §10.5 の asset gate 相当)。
- replay / exactly-once / supply-invariant property test を通す。
- invalid proof / verifier bug 時の停止手順を確認。

### Phase SP-3 — production audit + activate

- production audit 完了 (F006 verifier + ShieldedPool コントラクト + X25519+ML-KEM-1024 ハイブリッド note 暗号)。
- cap 解除は audit 後の別 activation。

### Phase SP-4 — recursion 集約 (v0.3)

- k 件の joinsplit を 1 proof に畳む。DA 予算あたりのシールド tx 数を上げる。
- 3-lane Lane 3 の recursion verifier と crate 共有を検討。

### Phase SP-5 — ERC-20 対応 (v0.3+)

- token_id > 0 を有効化。任意 ERC-20 のシールド送金 (Starknet STRK20 相当の「任意トークン秘匿」)。

---

## §14 未解決 (Open Questions)

- **O-SP-1:** 証明系選定 — zkVM (Risc0/SP1/S-two) vs 手書き STARK (Plonky3)。DA cap (32 KiB) を
  単独 proof で満たせるかが分岐点。[ADR-0033](adr/0033-evm-shielded-pool-porting-source.md) と連動。
- **O-SP-2:** `F006_VERIFY_GAS` の数値確定 (低スペック参照機ベンチ)。
- **O-SP-3:** 回路内ハッシュ (§5.3 選択肢 A) の具体 (SHA-256 vs Poseidon/M31)。zkVM 選定に従属。
- **O-SP-4:** note discovery 最適化 (全件スキャン → light client / discovery service)。
- **O-SP-5:** anchor ring 深さの数値 (DNS finality 窓との関係)。
- **O-SP-6:** relayer 市場の設計 (報酬・複数 relayer・検閲耐性)。
- **O-SP-7:** ERC-20 の token_id 登録メカニズム (v0.3)。
- **O-SP-8:** recursion 集約の proof system が Lane 3 と共有可能か (crate 再利用)。

---

## 付録 A: 移植元比較 (要約; 詳細は ADR-0033)

| 移植元 | そのまま度 | ノード改修 | 健全性 PQ | 秘匿性 PQ |
|---|---|---|---|---|
| Railgun 系 (Ethereum EVM, Groth16) | コントラクトほぼ無改修 | ゼロ | ✗ (Groth16 + trusted setup) | ✗ |
| **STRK20 仕様移植 (S-two/STARK)** ← 本命 | 仕様移植 + precompile | F006 1 個 | ✓ | X25519+ML-KEM-1024 ハイブリッドで ✓ |
| PQ-Sprout (zkVM 自作) | フル自作 | F006 1 個 | ✓ | ✓ |

STRK20 仕様移植と PQ-Sprout 自作は**実質同一アーキテクチャに収斂**し、違いは「回路/仕様を自作するか、
監査済み STRK20 から抽出するか」だけ。推奨は二段構え: テストネット踏み台に Railgun 型 (escrow cap 下)、
本命は STRK20 仕様 + S-two 系 F006 + X25519+ML-KEM-1024 ハイブリッド note 暗号。「EVM レーンに ECC が居ても、シールドプール
だけはフル PQ 健全性」は STRK20 にも Railgun にもない売り文句になる。
