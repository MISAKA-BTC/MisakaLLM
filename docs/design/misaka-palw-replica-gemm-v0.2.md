# MISAKA PALW Replica-GEMM Lane v0.2

**副題:** k=2決定論的Qwen推論を実GEMM作業として発行し、非同期認証後のブロック検証をハッシュ級へ近づける設計（PALW genesisは10 BPS、40 BPSはStage-B）  
**状態:** Draft / testnet-only / hard-fork前提  
**対象リポジトリ:** `misakas-mil-v0`、branch `feat/mil-v0`、確認時commit `b4cdfa1`  
**想定モデル(2段階):** PALW Standard=`MISAKA-QW4-PALW-v1`（Qwen3.5-4B Q4、RAM≥8GB、VPS・ノード同居・広い参加層）+ PALW Quality=`MISAKA-QW9-PALW-v1`（Qwen3.5-9B Q4、RAM≥16GB、標準的な有用推論）  
**コンセンサス分類:** Proof of Audited Compute + permanent hash floor  
**日付:** 2026-07-13

---

## 0. 実装判断の要約

本設計は、既存の `algo_id = 3` BLAKE2b-512 ∥ SHA3-512 PoWを廃止しない。恒久的なhash安全性フロアとして残し、その上に `algo_id = 4` の **Replica PALW lane** を追加する。

Replica PALW laneでは、同じ匿名ジョブ・同じ固定shape・同じ決定論runtimeを、DNSビーコンで選ばれた異なる2つのbonded providerへ配送する。両者がQwen推論を行い、次の値が完全一致した場合だけ、計算済みleaf候補を作る。

- `job_set_commitment`
- `model_profile_id`
- `runtime_class_id`
- `shape_id`
- `output_commitment`
- `canonical_gemm_trace_root`
- `operation_schedule_commitment`
- `quantum_count`

leaf候補は、全leafハッシュ、公開descriptor、provider bond、leaf bondとともにオンチェーン登録する。登録後のDNS由来ビーコンでcanary監査対象を決め、監査期間を通過したbatchだけを `Active` にする。ブロック生成時は、既にActiveになったticketについて一回だけeligibility hashを計算する。validatorはQwenを再実行せず、オンチェーンstate lookup、nullifier、lane difficulty、固定chain commitment、ticket hash、キャッシュ済みbatch certificateを検証する。

**10 BPS PALW genesis**の初期配分は次とする（比率は40 BPSと同一の1:4）。

| lane | algo | 目標BPS | 役割 |
|---|---:|---:|---|
| Hash floor | 3 | 2 BPS | 恒久的な外部資源コスト、PALW全壊時の安全性・livenessフロア |
| Replica PALW | 4 | 8 BPS | k=2の決定論的Qwen実GEMM、監査済みticketによるblock資格 |
| 合計 | mixed | 10 BPS | 100ms平均block interval |

GHOSTDAGの累積workは、hash workとcompute workを別々に保持する。

```text
H(B) = cumulative blue hash work
C(B) = cumulative unique certified compute work
E(B) = H(B) + min(C(B), 4 * H(B))
```

`E(B)` が従来の `blue_work` としてfork choiceへ入る。したがって、PALW側が完全に偽造可能になっても、computeによるwork増幅はhash workの4倍までである。これはPALW破綻を無害化するものではないが、TEE偽造1件で無限workが生じるcatastrophic failureを、最大5倍のwork増幅へ制限する。hash laneを「移行期だけ」とする案は撤回する。

本設計の中心的な非目標も明記する。

1. fine-tuningされたLLM自身の自己申告を暗号学的証明とは扱わない。
2. 4B/9B級推論を各validatorが25ms以内に再実行する設計にはしない。
3. TEEのECDSA/RSA attestation chainをコンセンサスの信頼rootにしない。
4. 実ジョブのactivationやhidden stateを公開監査しない。
5. k=2を採用するため、「質問内容を知る計算者は常に1者だけ」という旧要件は維持できない。質問内容を知るのは requester と選ばれた2 providerだけであり、公開validator・block producer・一般ノードには開示しない。

---

## 1. 達成する性質

### 1.1 必須要件

- 質問本文、回答本文、token IDs、hidden stateをオンチェーンへ出さない。
- requesterとprovider pairの対応を公開chainから復元できない。
- provider AとBは互いの長期identityを配送時に知らなくてもよい。
- 同じ仕事を異なる2 providerが実行し、完全一致した計算だけticket候補にする。
- GPUで実行されたQwenの主要GEMMを `canonical_gemm_trace_root` へ拘束する。
- 証明・監査・batch certificationはブロック生成経路の外で非同期に行う。
- block検証はQwen再実行を含めず、40 BPSで十分なheadroomを持つ。
- 全leafハッシュと必要な公開descriptorを、beacon確定前にオンチェーンへ置く。
- ticketをnonce代わりに無限grindさせず、一leaf、一target interval、一抽選に固定する。
- ticketの二重使用をheader DAGだけから決定論的に検出できる。
- pruning proofとIBDが帯域外cacheへ依存しない。
- TEE停止、NVIDIA NRAS停止、attestation失効時にもhash laneとReplica laneが継続できる。
- 暗号学的なコンセンサスrootはSHA3/BLAKE2b/ML-DSA/ML-KEM等のPQ方針に揃える。

### 1.2 明示的な限界

- k=2の両providerが結託し、canary識別にも成功した場合、同じ偽commitmentを作る余地は残る。このリスクはランダムprovider割当、bond、canary、batch監査、hash floorで抑える。
- promptの「社会的有用性」は、内容を見ないvalidatorには判定できない。workの有用性は、実requesterの支払、固定shape quota、job capability、canary、需要市場で経済的に担保する。
- requester-provider関係のネットワークメタデータ秘匿は、relayの少なくとも1経路が非結託であることに依存する。ZKなしで完全なグローバル受動盗聴者耐性は主張しない。
- `canonical_gemm_trace_root` は単独ではsuccinct proofではない。これは監査可能な実行commitmentであり、soundnessはk=2、canary、bond、DNS certificateによって構成する。

---

## 2. 現行コード監査と変更方針

現行コードには相当数の足場がある。全部作り直す必要はない。作り直しは設計者の気分を満たすが、バグにも同じだけ栄養を与える。

| 現行箇所 | 現状 | v0.2での変更 |
|---|---|---|
| `consensus/core/src/config/bps.rs` | `Bps<10>`(K≈124)/`Bps<40>`(K=447)が存在 | PALW testnetを明示的に `BlockrateParams::new::<10>()` で再genesis(`testnet-palw-10`、既存testnet-40とは別network ID)。40 BPSはStage-B `testnet-palw-40` へ |
| `consensus/core/src/config/params.rs` | mainnetは10 BPS、既存testnet系には40 BPS設定が残る | 既存testnet-40を無言で変更せず、10 BPS(`Bps<10>`)でPALW専用network IDとgenesisを追加 |
| `consensus/core/src/pow_layer0.rs` | algo 1/2/3。live networkは単一algoを要求 | `POW_ALGO_ID_PALW_REPLICA = 4`、mixed-lane policyへ変更 |
| `consensus/pow/src/lib.rs` | `StateLayer0` が全algoを同期PoWとして処理 | algo 3用Stateとalgo 4用ticket verifierを分離 |
| `pre_ghostdag_validation.rs` | header単体でLayer0 PoWを検証 | algo 4は構文・one-shot hashを確認し、state依存部分はparent context後へ移動 |
| `pre_pow_validation.rs` | 単一DAA window、単一expected bits | algo別DAA windowとexpected bits |
| `header.rs` | `pow_algo_id` は既に第一級field、`blue_work` は1本 | v3 headerにPALW参照、nullifier、component workを追加 |
| `hashing/header.rs` | v2 EVM fieldsがversion gate、overlay rootは常時 | PALW fieldsを `PALW_HEADER_VERSION = 3` でappend-only gate |
| `ghostdag/protocol.rs` | `calc_work(bits)` を全blueへ加算 | hash/compute component分離、nullifier dedup、compute cap |
| `model/stores/ghostdag.rs` | `blue_score`, `blue_work` のみ | `blue_hash_work`, `blue_compute_work` を追加 |
| `pruning_proof/validate.rs` | header PoWとGHOSTDAGを再計算 | PALW epoch certificate/leaf chunk/beacon proof bundleを追加 |
| `dns_finality.rs` | DNS overlayとPQ validator署名は存在 | PALW専用PQ commit-reveal beaconを新設 |
| ADR-0012/0017 | 旧commit-reveal sortition案は撤回済み | 「既存DNS randomnessがある」と仮定しない |
| `mil/core/src/job.rs` | `Tier::Open` はgreedyを強制 | PALW固定shape、runtime class、job-set commitmentを追加 |
| `mil/core/src/model.rs` | weights/runtime imageをpin | kernel graph、GPU arch class、quant、tokenizer、shape tableまでpin |
| `mil/provider/src/backend.rs` | token/chunk出力のみ | `VerifiableInferenceBackend` とtrace metadataを追加 |
| `mil/core/src/canary.rs` | 少数の固定canary template | 識別困難な大規模・生成型canaryへ置換 |
| `mil/provider/src/anon.rs` | per-session PQ keyの匿名laneはinert | k=2配送、固定padding、ephemeral job capabilityへ接続 |
| `mil/attest` | classical vendor chainのpinningが存在 | TEEは任意のrate limiterに限定、work発行の単独rootにはしない |
| `consensus/core/src/subnets.rs` | DNS 0x10帯、EVM 0x20帯 | PALW 0x30帯を追加 |
| `OverlaySnapshot` | DNS bond/reserve/windowのみcommit | PALW active state、beacon、batch/cert frontierを追加 |
| `BlockRewardData` | 1本のworker script | PALW provider pair reward classを追加 |

---

## 3. コンセンサス上の用語

### 3.1 Work Unit

`Work Unit` は1つの質問ではなく、固定tensor shapeへpadding/packingされた匿名microbatchである。GPU効率とLCU gaming対策のため、1 ticket leafは1つの固定operation scheduleを表す。

### 3.2 Replica Pair

同じWork Unitを実行する、異なるbond outpointに結び付いた2 provider。pairは前epochのDNS beaconで選ぶ。requesterや単独providerが相方を選んではならない。

### 3.3 Candidate Leaf

2 providerのreceiptが一致したが、まだ監査・certificateが完了していない計算単位。

### 3.4 Active Ticket

全leaf公開、bond reserve、audit window、DNS PALW certificateを通過し、対象epoch・slotでblock資格抽選へ使えるleaf。

### 3.5 GEMM Trace

固定runtimeが、各主要GEMM/attention/MoE opのcanonical operation ID、shape、整数accumulator checksum、selected expert、出力commitmentを順にhash chainへ吸収したもの。本文やactivationは公開しない。

### 3.6 Proof

v0.2の `proof_type = ReplicaExactV1` はSNARKではない。2 providerの一致receipt、公開leaf、監査結果、DNS certificateの組合せを「非同期認証」と呼ぶ。コード上のenumには将来のtransparent argumentやzkML用IDを予約する。

---

## 4. セキュリティ不変条件

以下は実装とテストで必ず守る。

### I-1: Hash floor

```text
blue_compute_work <= 4 * blue_hash_work
```

有効work計算後に必ず成立する。compute creditがcapを超えるblockは無効にするか、credit可能な残量が0ならalgo 4 templateを生成しない。

### I-2: No hidden leaves

batchの `leaf_count` と全 `leaf_hash[i]` は、eligibility/audit beacon確定前にchainへ掲載される。rootだけの登録は禁止する。

### I-3: One leaf, one draw

leafは1つの `target_daa_interval` にだけ割り当てる。block nonceを変更して再抽選してはならない。algo 4ではnonceを固定値にし、異なるnonceをrejectする。

### I-4: Consensus-derived chain binding

`chain_commit` をminerが自由に選んではならない。固定されたDNS-finalized anchorとlagged selected-chain checkpointから全ノードが同じ値を導出する。

### I-5: First-class nullifier

`ticket_nullifier` はsidecarだけに置かずHeader v3へ入れる。header hash、P2P、store、pruning proofすべてに含める。

### I-6: No out-of-band validity dependency

batch manifest、全leaf chunk、certificate、beacon stateはオンチェーンまたはpruning proof bundleで取得できなければならない。gossip cacheは高速化であり、正当性の前提ではない。

### I-7: TEE non-authority

vendor attestationだけでActive ticketを発行しない。TEE laneを後で追加しても、hash floor、bond、公開leaf、DNS certificateを迂回させない。

### I-8: Replica independence

provider AとBは異なるbond outpoint、異なるoperator group、異なるactive session keyでなければならない。同一operator group判定は登録時のbond metadataとslashing evidenceで行う。

### I-9: Deterministic class

完全一致weightを得られるのは同じ `runtime_class_id` のpairだけ。異なるGPU arch class間の許容帯比較はaudit-onlyから始め、main DAG workへ直接入れない。

### I-10: Real-job privacy

実ジョブのprompt、output、activation sketchを公開監査しない。full openingはprotocol-owned canaryだけに許可する。

### I-11: Double-use slashability

同じticket authorityが同じnullifierで異なるheaderを署名した証拠は、forkをまたいでもslashing evidenceになる。bond unlockはticket expiryと最大reorg/evidence windowより後にする。

### I-12: Historic reproducibility

IBDとpruning proof verifierは、当時のmodel profile、shape table、lane DAA、beacon、batch certificate、nullifier ruleからcomponent workを再計算できなければならない。

### I-13: Winner secrecy（当選秘匿、R1 / 2026-07-16）

public leaf は当選する ticket を露出してはならない。leaf が持つのは `ticket_nullifier_commitment = H("misaka-palw-ticket-nf-commit-v1" || ticket_nullifier)` のみであり、生の `ticket_nullifier` は header でのみ開示される。consensus は `ticket_nullifier_commitment(header.nullifier) == leaf.ticket_nullifier_commitment` を検証する。これにより、beacon より前に公開される leaf 集合（I-2）は「どの ticket が当選するか」を漏らさない一方、二重使用検出（I-5）は生の nullifier が header に現れるため不変。leaf uniqueness も commitment 上で判定する。実装: `consensus/core/src/palw.rs` `ticket_nullifier_commitment` / `PalwPublicLeafV1.ticket_nullifier_commitment` / `PalwTicketBinding`、pure・inert（コミット `3fb5e67`）。

### I-14: DA possession binding（監査人の受領コミット、R2 / 2026-07-16）

auditor の署名対象 (`PalwAuditorVoteV1::signing_hash`) は beacon が選んだ `audit_sample_root` を含む。consensus は audit beacon から batch の receipt DA 上で同じ root を独立に再導出するため、選ばれた receipt chunk を特定＝所持していなければ有効な vote 署名を作れない。「取得せずに certify する」という信頼前提を構造的に閉じる（D12/I-6 の vote 署名側）。実装: `PalwAuditorVoteV1::signing_hash(network_id, batch_id, audit_beacon_epoch, audit_sample_root)`、pure・inert（コミット `34fe771`）。

---

## 5. 10 BPS mixed-laneコンセンサス（PALW genesis; 40 BPSはStage-Bへ）

### 5.1 lane policy

現行の `required_algo_id(bool) -> u8` は、hard cut-off型の単一algo設計である。これを次へ置換する。

```rust
pub const POW_ALGO_ID_BLAKE2B_SHA3: u8 = 3;
pub const POW_ALGO_ID_PALW_REPLICA: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkLane {
    HashFloor,
    ReplicaPalw,
}

pub fn check_live_algo_id(
    algo_id: u8,
    palw_active: bool,
) -> Result<WorkLane, PowLayer0Error> {
    match algo_id {
        POW_ALGO_ID_BLAKE2B_SHA3 => Ok(WorkLane::HashFloor),
        POW_ALGO_ID_PALW_REPLICA if palw_active => Ok(WorkLane::ReplicaPalw),
        _ => Err(PowLayer0Error::UnknownAlgoId(algo_id)),
    }
}
```

`check_algo_id_known` はhistorical pruning用に1/2/3/4を受理し、live ruleはactivation DAA scoreとnetwork paramsを確認する。

### 5.2 BPS設定（10 BPS PALW genesis、2026-07-14 決定）

PALW testnetは**専用の10 BPS genesis（`testnet-palw-10`）**で開始する。lane比率(1:4)とhash floor比率(20%)は40 BPSと同一なので、coinbase splitとepoch単位のwindowは不変で、DAA単位のwindowだけ実時間維持で1/4になる。

```rust
pub struct WorkLaneRateParams {
    pub total_bps: u64,           // 10
    pub hash_lane_bps: u64,       // 2
    pub replica_lane_bps: u64,    // 8
    pub compute_to_hash_cap: u64, // 4
}
```

- total target interval: 100ms
- hash lane target interval: 500ms（2 BPS）
- replica lane target interval: 125ms（8 BPS）
- GHOSTDAG K: `≈124`
- max parents: `16`
- mergeset size limit: `248`

10 BPSを選ぶ理由: 新しいconsensus hot-path（component work、nullifier dedup、lane DAA、overlay lookup、ML-DSA authorization）に検証時間の余裕（100ms対25ms）と穏やかなGHOSTDAG圧力（K≈124対447）を与え、最初の本番条件で問題を局所化するため。PALWのLLM計算は非同期（GPUがticket在庫を作り、blockは在庫を消費するだけ）なので、10 BPSでも推論スループットは制限されない。40 BPS split（8+32、K=447、mergeset 512、epoch 400 DAA、retention 4800 DAA）は後段の`testnet-palw-40` Stage-Bストレスネットとして保持し、10 BPS soak + weight ladder gate通過後に昇格する。

既存testnetの40 BPS設定を同じnetwork IDのまま変更しない。PALW testnetは新しいgenesis、network suffix、store format versionを使う。

### 5.3 component work

各source blockのwork deltaをlane別に計算する。

```text
ΔH(x) = calc_work_512(x.bits)                    if x.algo == 3
ΔH(x) = 0                                        otherwise

ΔC(x) = normalize_palw_work(x.bits, profile_id)  if x.algo == 4
ΔC(x) = 0                                        otherwise
```

PALW v0.2では1leafを固定quantumにするため、`normalize_palw_work` は基本的にlane targetから得るworkへ固定scaleを掛けるだけにする。provider自己申告のFLOP数やwall-clock秒を直接信用しない。

新block `B` のGHOSTDAG計算では、selected parentと新たにblueとなるmergeset source blockをconsensus orderで処理する。

```text
H_raw = H(selected_parent) + Σ unique_blue_hash ΔH(x)
C_raw = C(selected_parent) + Σ unique_blue_palw ΔC(x)
C_cap = min(C_raw, 4 * H_raw)
E     = H_raw + C_cap
```

Header v3には `blue_hash_work`, `blue_compute_work`, `blue_work=E` をすべて入れ、post-GHOSTDAG validationで3値を再計算する。

`C_cap = min(C_raw, 4*H_raw)` は**構造上限**であり、`E ≤ 5H`（100% compute weight）に対応する。実運用の cap はこれではなく、activation ladder（§28 / ADR §3 Phase 8）の stage weight `w` を掛けた `E ≤ H + min(C, w·4H)` である（P2 / 2026-07-16 明確化）。

| stage | weight `w` | operative compute cap | effective work bound |
|---|---|---|---|
| A | 0% | `min(C, 0)` = 0 | `E = H`（compute creditなし、algo-4 template抑止）|
| B | 25% | `min(C, 1·H)` | `E ≤ H + 0.25·4H = 2H` |
| C | 50% | `min(C, 2·H)` | `E ≤ H + 0.50·4H = 3H` |
| D | 80%（mainnet上限）| `min(C, 3.2·H)` | `E ≤ H + 0.80·4H = 4.2H` |
| — | 100%（構造上限のみ）| `min(C, 4·H)` | `E ≤ 5H`（スケジュールしない）|

したがって §29 problem A の「5× 増幅」は cap の天井であってネットワークが走る stage の値ではない。実運用の最悪増幅は Stage D の **4.2×**、最初に credit する Stage B で **2×**。`finalize_score_and_component_work` は構造上の `min(C, 4H)` を計算し、stage weight `w` は別の re-genesis / hard-fork パラメータ（live knob ではない）。

### 5.4 cap到達時

compute headroomが0のとき、nodeはalgo 4 templateを返さない。受信したalgo 4 blockも `PalwComputeCapExhausted` でrejectする。zero-work blockを受理してblue scoreだけ増やすと、DAAとGHOSTDAGを別の抜け道にしてしまうためである。

---

## 6. 二段階決定論runtime（PALW Standard `MISAKA-QW4-PALW-v1` / Quality `MISAKA-QW9-PALW-v1`）

### 6.1 モデル名

参加層を広げるため、algo 4 Replica laneは**2つのruntime tier**を持つ（それぞれ独立の `model_profile_id` / `runtime_class_id` / shape table / reference benchmark。PoW laneは増やさない）。

| tier | project profile | model | quant | RAM | 用途 |
|---|---|---|---|---|---|
| **PALW Standard** | `MISAKA-QW4-PALW-v1` | Qwen3.5-4B | Q4 | ≥8GB | VPS・ノード同居・広い参加層 |
| **PALW Quality** | `MISAKA-QW9-PALW-v1` | Qwen3.5-9B | Q4 | ≥16GB | 標準的な有用推論 |

通称（`qwen3.5-4b` / `qwen3.5-9b`）はプロジェクト上の呼称として扱い、コンセンサスは名称でなく**各tierのmanifest hash**を信頼する。公式配布物のexact artifact、派生weight、tokenizer、quantization、runtimeをtier毎に固定し、`MISAKA-QW4/QW9-PALW-v1` として登録する（`PalwParams.supported_profiles` に両方）。exact trace matchは**同一tier内のみ**（I-9）で、compute quantumはtier毎のreference benchmark（§21.2）から得るため、広いStandard(4B) fleetはQuality(9B)より1 leafあたり少ないcompute workにcreditされる。Q4量子化は決定性の要件を厳しくする（量子化kernelのnumericsはfp16より機種差が出やすい）ため、batch-invariant/kernel-graph testはtier毎・arch class毎に行う。公式のモデル名が似ているから同一だろう、というコンセンサス規則は採用しない。製品名はhash関数ではない。

### 6.2 runtime manifest

`mil/core/src/model.rs` を拡張する。

```rust
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwRuntimeProfileV1 {
    pub version: u16,
    pub model_id: Hash64,
    pub tokenizer_hash: Hash64,
    pub quantization_manifest_hash: Hash64,
    pub runtime_image_hash: Hash64,
    pub kernel_graph_hash: Hash64,
    pub operation_table_hash: Hash64,
    pub shape_table_hash: Hash64,
    pub gpu_arch_class: u32,
    pub tensor_parallel_degree: u16,
    pub pipeline_parallel_degree: u16,
    pub deterministic_reduction: bool,
    pub batch_invariant: bool,
    pub speculative_decode: bool,
    pub sampling: SamplingParams,
}
```

v0.2のActive profileは次を必須にする。

- greedy decode
- speculative decoding禁止
- batch-invariant kernels
- deterministic reduction order
- fixed integer/fixed-point quantization profile
- fixed tokenizer
- fixed MoE routing tie-break
- fixed padding tokenとmask規則
- fixed tensor/pipeline parallel topology
- 同一GPU architecture class内でのみexact trace match

### 6.3 fixed shape table

LCU gamingを防ぐため、任意shapeを認めない。例としてtestnet初期値を次とする。

| shape_id | prefill tokens | decode tokens | microbatch | 用途 | epoch quota |
|---:|---:|---:|---:|---|---:|
| 0 | 512 | 128 | 8 | decode寄り短文 | 35% |
| 1 | 2,048 | 256 | 4 | 標準 | 40% |
| 2 | 8,192 | 256 | 1 | long-context | 20% |
| 3 | 16,384 | 128 | 1 | prefill監査 | 5% |

表の値はtestnet計測で変更可能だが、変更はprofile IDとactivation fenceを伴う。各shapeは参照GPU class上の実測、operation count、HBM traffic、prefill/decode比率を持つ。

```rust
pub struct PalwShapeProfileV1 {
    pub shape_id: u16,
    pub prefill_tokens: u32,
    pub decode_tokens: u32,
    pub microbatch: u16,
    pub canonical_mac_units: u128,
    pub canonical_memory_units: u128,
    pub quantum_count: u16,
    pub epoch_quota_bps: u16,
}
```

`quantum_count` はprofileから決まり、runtime reportで増減できない。短い実ジョブはpaddingし、複数ジョブを固定microbatchへpackingする。

### 6.4 backend API

既存 `InferenceBackend` は一般serving用として残し、PALW用traitを分離する。

```rust
#[async_trait]
pub trait VerifiableInferenceBackend: Send + Sync {
    async fn infer_with_trace(
        &self,
        encrypted_job_set: &[u8],
        job: &PalwJobSpecV1,
        challenge: PalwExecutionChallengeV1,
    ) -> Result<DeterministicInferenceOutputV1, BackendError>;
}

pub struct DeterministicInferenceOutputV1 {
    pub output_token_ids: Vec<Vec<u32>>,
    pub output_commitment: Hash64,
    pub canonical_gemm_trace_root: Hash64,
    pub operation_schedule_commitment: Hash64,
    pub operation_counters: PalwOperationCountersV1,
    pub shape_id: u16,
    pub quantum_count: u16,
}
```

通常のtext chunkはrequesterへ暗号化して返す。ticket作成経路へはtoken本文を渡さず、commitmentとtrace metadataだけを渡す。

---

## 7. 実GEMMをwork sourceへする

### 7.1 何を「採掘作業」と呼ぶか

algo 4の重い資源消費はQwenの次の演算である。

- attention projection GEMM
- MoE routerとselected expert GEMM
- feed-forward GEMM
- vocabulary projection
- KV cache read/writeに対応する固定operation accounting
- fixed-point normalization/activation lookup

SHA3/BLAKE2bは、これらの実行から生じるcommitmentを圧縮し、ticket抽選を行うためだけに使う。

### 7.2 canonical operation ID

各runtime profileはoperation graphを固定し、各opへ連番を与える。

```rust
pub struct PalwOperationIdV1 {
    pub layer: u16,
    pub token_phase: u8, // prefill/decode
    pub microbatch_index: u16,
    pub op_index: u32,
    pub expert_index: u16,
    pub tile_schedule_id: u16,
}
```

MoEの非選択expertを実行したと偽ってworkを増やすことはできない。選択expertとcanonical operation scheduleがtraceへ入る。

### 7.3 trace chain

providerへ配送する `PalwExecutionChallengeV1` は、直前に確定したDNS beacon、job capability、runtime profileから導出する。

```text
challenge = H(
    "misaka-palw-exec-challenge-v1" ||
    previous_dns_beacon ||
    blinded_job_capability ||
    model_profile_id ||
    shape_id
)
```

GEMM kernelは主要tile/reductionのcanonical checksumを逐次吸収する。

```text
t_0 = H(domain || challenge || runtime_profile_id || job_set_commitment)

t_(i+1) = H(
    t_i ||
    operation_id ||
    input_tensor_commitment ||
    integer_accumulator_checksum ||
    output_tensor_commitment ||
    selected_expert_ids ||
    overflow_flags
)

canonical_gemm_trace_root = t_final
```

checksumは学習headが出す文字列ではなく、固定kernel/runtime instrumentationが生成する。providerが独自runtimeを使うこと自体は止められないため、正当性は次の4層で支える。

1. k=2独立providerのexact match
2. beacon選択canaryのfull rerun/prefill audit
3. provider/leaf bondとslashing
4. hash work floor

### 7.4 output commitment

両providerへ同じjob-secret-derived saltを配送する。

```text
output_commitment = H(
    "misaka-palw-output-v1" ||
    output_salt ||
    tokenizer_hash ||
    canonical_borsh(output_token_ids)
)
```

公開chainにsaltとtoken IDsは出さない。`output_commitment` 自体もpublic leaf descriptorへ直接置かず、private match commitmentの内側へ入れる。

### 7.5 exact match条件

```rust
fn replica_outputs_match(
    a: &ReplicaExecutionReceiptV1,
    b: &ReplicaExecutionReceiptV1,
) -> bool {
    a.provider_bond != b.provider_bond
        && a.model_profile_id == b.model_profile_id
        && a.runtime_class_id == b.runtime_class_id
        && a.shape_id == b.shape_id
        && a.job_set_commitment == b.job_set_commitment
        && a.output_commitment == b.output_commitment
        && a.canonical_gemm_trace_root == b.canonical_gemm_trace_root
        && a.operation_schedule_commitment == b.operation_schedule_commitment
        && a.quantum_count == b.quantum_count
}
```

一致しない場合、ticketは発行しない。requesterには結果を返せるが、coinbase/DAG work資格にはならない。

---

## 8. k=2匿名配送とprovider選択

### 8.1 選択

requesterがprovider pairを指定すると、自己複製や結託pairを選べる。そこで、前epochのDNS PALW beaconからpairを決める。

```text
provider_index_a = H(seed || job_capability || 0) mod active_provider_count
provider_index_b = H(seed || job_capability || 1) mod active_provider_count
```

次を満たすまでrejection samplingする。

- bond outpointが異なる
- operator groupが異なる
- runtime classが一致
- shape capacityがある
- region diversity policyを満たす
- providerが同一relay sessionにいない

### 8.2 配送

```text
Requester
   │ encrypted prompt + job secret
   ▼
Ingress mix relay
   │ fixed-size padded cells
   ▼
Threshold scheduler / dispatcher
   ├── encrypted work unit ──► Provider A
   └── encrypted work unit ──► Provider B
```

公開chainにはrequester ID、session ID、prompt hashのunsalted値を出さない。dispatcherがmappingを知るため、v0.2のunlinkabilityは「公開chainと単独providerから隠す」であり、dispatcher全体の結託には耐えない。dispatcherはDNS-selected複数者とし、少なくとも1者非結託を仮定する。

### 8.3 job capability

各work unitは一回限りのbearer capabilityを持つ。

```rust
pub struct PalwJobCapabilityV1 {
    pub version: u16,
    pub capability_nullifier: Hash64,
    pub job_set_commitment: Hash64,
    pub model_profile_id: Hash64,
    pub shape_id: u16,
    pub not_before_epoch: u64,
    pub expires_epoch: u64,
    pub requester_fee_commitment: Hash64,
}
```

capabilityの公開値はランダムnullifierだけで、requester addressへ直接結び付けない。発行・支払の完全なunlinkabilityは別のshielded settlementなしには保証しない。

---
## 9. 公開leaf、bond、batch認証

### 9.1 なぜrootだけでは不足するか

batch rootだけを先に出し、当選leafだけ後から開く方式は禁止する。偽leafを大量にrootへ詰め、beacon後に当選したleafだけを実在したことにするhidden-leaf grindingを防げないためである。

v0.2では、登録時に次をすべてオンチェーン化する。

- batch manifest
- `leaf_count`
- 全 `PalwPublicLeafV1`
- 全 `leaf_hash`
- leafごとのbond reserve
- provider pairのbond参照
- provider pairのone-time reward scripts
- hidden receipt bundleのDA commitment
- certificate activation条件

### 9.2 public leaf

```rust
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PalwPublicLeafV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub leaf_index: u32,

    /// Same scheduled work unit cannot mint another leaf.
    pub job_nullifier: Hash64,
    /// Same ticket cannot contribute twice to the DAG.
    pub ticket_nullifier: Hash64,

    pub model_profile_id: Hash64,
    pub runtime_class_id: Hash64,
    pub shape_id: u16,
    pub quantum_count: u16,
    pub proof_type: u8,

    pub provider_a_bond: TransactionOutpoint,
    pub provider_b_bond: TransactionOutpoint,
    pub provider_a_reward_script: ScriptPublicKey,
    pub provider_b_reward_script: ScriptPublicKey,

    pub ticket_authority_pk_hash: Hash64,
    pub private_match_commitment: Hash64,
    pub receipt_da_root: Hash64,

    pub registered_epoch: u64,
    pub activation_epoch: u64,
    pub expiry_epoch: u64,
    pub leaf_bond_sompi: u64,
}
```

`private_match_commitment` は次をcommitする。

```text
H(
  output_commitment ||
  canonical_gemm_trace_root ||
  operation_schedule_commitment ||
  job_set_commitment ||
  receipt_a_hash ||
  receipt_b_hash
)
```

本文は公開しないが、後のcanary disputeではcommitmentとの一致を検証できる。

### 9.3 batch manifestとleaf chunk

現行MIL anchorの8 KiB上限へ256 leafを無理に詰め込まない。PALW専用subnetworkを追加し、64 leaf単位でchunk化する。

```rust
pub struct PalwBatchManifestV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub registration_epoch: u64,
    pub model_profile_id: Hash64,
    pub runtime_class_id: Hash64,
    pub leaf_count: u32,
    pub chunk_count: u16,
    pub leaf_root: Hash64,
    pub descriptor_root: Hash64,
    pub total_leaf_bond_sompi: u64,
    pub audit_policy_id: Hash64,
    pub activation_not_before_epoch: u64,
    pub expiry_epoch: u64,
}

pub struct PalwLeafChunkV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub chunk_index: u16,
    pub leaves: Vec<PalwPublicLeafV1>, // max 64
}
```

manifestだけ存在しchunkが欠けるbatchは `Incomplete` のまま期限切れにする。block資格には絶対に使えない。

### 9.4 subnetwork IDs

`consensus/core/src/subnets.rs` に次を予約する。

```rust
pub const SUBNETWORK_ID_PALW_PROVIDER_BOND: SubnetworkId = SubnetworkId::from_byte(0x30);
pub const SUBNETWORK_ID_PALW_BATCH_MANIFEST: SubnetworkId = SubnetworkId::from_byte(0x31);
pub const SUBNETWORK_ID_PALW_LEAF_CHUNK: SubnetworkId = SubnetworkId::from_byte(0x32);
pub const SUBNETWORK_ID_PALW_BATCH_CERT: SubnetworkId = SubnetworkId::from_byte(0x33);
pub const SUBNETWORK_ID_PALW_SLASHING: SubnetworkId = SubnetworkId::from_byte(0x34);
pub const SUBNETWORK_ID_PALW_BEACON_COMMIT: SubnetworkId = SubnetworkId::from_byte(0x35);
pub const SUBNETWORK_ID_PALW_BEACON_REVEAL: SubnetworkId = SubnetworkId::from_byte(0x36);
pub const SUBNETWORK_ID_PALW_PROVIDER_UNBOND: SubnetworkId = SubnetworkId::from_byte(0x37);
```

`SubnetworkId::is_palw_overlay()` と `palw_tx_kind()` を追加し、payload length、canonical ordering、duplicate index、epoch fenceをstateless/stateful両方で検証する。

### 9.5 batch state machine

```text
Missing
  └─manifest accepted──► Registering
Registering
  └─all chunks + bonds──► Committed
Committed
  └─audit beacon────────► Auditing
Auditing
  ├─certificate quorum──► Certified
  ├─failed audit────────► Slashed
  └─timeout─────────────► Expired
Certified
  └─activation epoch────► Active
Active
  ├─expiry──────────────► Expired
  └─fraud evidence──────► Revoked
```

`Certified` から `Active` まで1 epoch以上の遅延を置き、certificateとleaf stateが全nodeへ到達する余裕を作る。

**revocationは過去workを遡及削除しない。** `PalwRevocationV1` は `effective_daa_score` を持ち、そのscore以後の未使用leafだけを無効化する。既に受理され、その時点で有効なcertificateに基づいてcreditされたblockを後日のfraud evidenceで巻き戻すと、opMLと同じ遅延reorg問題を輸入するためである。後日発見した不正はbond slash、残leaf失効、credential停止で処理し、historic verifierは「block時点のcertificate状態」を再現する。

### 9.6 bond条件

各leafはprovider bondとは別にslashable reserveを持つ。

```text
expected_fraud_profit = p_win * (block_reward + c_saved)     # ← R3: c_saved を含む
expected_penalty      = q_audit * slash_amount + leaf_bond + credential_loss

必須条件:
expected_fraud_profit - expected_penalty < 0
```

**R3（c_saved 較正、2026-07-16）.** forger の利得は block reward `R` だけではない。実推論を走らせずに済ませることで**回避した GPU 実行コスト `c_saved`** も利得である。したがって正しい不等式は `q_audit·slash + leaf_bond + credential_loss > R + c_saved`。canary catch により `q_audit·slash ≈ R`（利得のうち*報酬*を相殺）となるため、`c_saved` を実際に覆うべき項は `leaf_bond + credential_loss` である。consensus は bond 側を admission で直接強制する: `PalwBatchAdmissionParams.min_leaf_bond_sompi`（leaf あたり floor）を追加し、`admission_valid`/`apply_manifest` が `total_leaf_bond_sompi < leaf_count · min_leaf_bond_sompi` の manifest を reject する（manifest 時点は集約チェック、per-leaf 分配は leaf admission 側）。inert 値 `0`（コミット `34fe771`）。

**較正ノート（re-genesis、floor への off-protocol 入力）.** `min_leaf_bond_sompi` は re-genesis で**tier ごと**に、その tier の*実測* `c_saved`（`MISAKA-QW4-PALW-v1` vs `MISAKA-QW9-PALW-v1` の 1 leaf あたり amortized GPU-seconds × 基準 $/GPU-hour。4B Standard は `c_saved` が小さく floor も低い。§21.2 tier別 benchmark）に設定する。floor は**testnet soak** を gate とし（pinned runtime 下の実 per-leaf GPU コストを測ってから固定）、`(p_collude, q_canary, slash, leaf_bond)` の**4変数 EV sweep** で妥当な結託レンジ全域にわたり `expected_fraud_profit < 0` にマージンを持たせて選ぶ。soak 抜きの list-price GPU コストからの設定は明示的に禁止（batch-invariant execution 下の実 amortized コストは spot rental と乖離する）。

testnet初期値:

- `q_canary = 1%`
- batchごとに最低1 leafをcanary audit
- `slash_amount >= 100 × 1 leafの最大期待block報酬`
- provider credential suspension: 最低1,000 epochs
- unbond delay: `ticket_expiry + max_reorg_horizon + fraud_evidence_window`
- `min_leaf_bond_sompi >= per-tier c_saved`（R3。inert=0、re-genesis で tier別較正）

数値は観測したwin rate、GPU供給、報酬額に合わせてhard-fork可能parameterとして調整する。validatorが自由に変更できるgovernance knobにはしない。

---

## 10. 非同期監査とcertificate

### 10.1 certificateの意味

`PalwBatchCertificateV1` は「推論を数学的に証明した」ものではない。次をDNS-selected auditor quorumが確認した事実を表す。

- 全leafがbeacon前に公開済み
- leaf indexに欠番・重複がない
- provider A/Bが異なるactive bond
- pair receiptの固定項目が一致
- provider signatureがML-DSAで有効
- job nullifierが未使用
- shape quotaを超えていない
- 選択されたcanary auditが合格
- leaf bondがlock済み
- receipt DA commitmentが取得可能

```rust
pub struct PalwBatchCertificateV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub manifest_hash: Hash64,
    pub leaf_root: Hash64,
    pub audit_beacon_epoch: u64,
    pub audit_sample_root: Hash64,
    pub passed_leaf_count: u32,
    pub rejected_leaf_bitmap_root: Hash64,
    pub certificate_epoch: u64,
    pub activation_epoch: u64,
    pub expiry_epoch: u64,
    pub auditor_set_commitment: Hash64,
    pub votes: Vec<PalwAuditorVoteV1>,
}
```

`votes` は現行DNS bond viewから選ばれたauditorのML-DSA署名。batch activation時に全nodeが検証し、以後はcertificate hashをstate cacheで参照する。ML-DSA署名のnative aggregationを仮定しない。

### 10.2 auditor選択

前epoch seed `R_(E-1)` で、active DNS bond setからweight付きでauditorを選ぶ。batchを登録したproviderや直接関係するbondは除外する。

```text
auditor_score_i = H(R_(E-1) || batch_id || bond_outpoint_i)
```

初期testnetは小さな固定上限、例えば16 auditor、2/3 stake-weight quorumを使う。mainnet化前にsignature帯域とcentralizationを測る。

### 10.3 canary audit

full openingを許可するのはprotocol-owned canaryだけである。

canaryの監査では、auditorは次を得る。

- prompt plaintextまたはprotocol-owned seed
- expected tokenizer input
- output tokens
- selected trace openings
- runtime profile
- provider receipts

同じ決定論runtimeでteacher-forced prefill/replayし、output commitmentとtrace sampleを検証する。TopLoc型のhidden-state top-k sketchを使う場合もcanary限定とし、実ジョブのactivationを公開しない。

現行 `mil/core/src/canary.rs` の少数固定templateはproviderに識別されやすいため、次へ置換する。

- 大規模秘密canary corpus
- epoch seedから生成するgrammar/property-based prompts
- 実ジョブshape分布と同一のpadding
- canary labelはproviderから不可視
- revealはbatch commitment後
- 同一canaryの再利用を禁止

### 10.4 実ジョブ監査

実ジョブについて許す監査は次だけである。

1. k=2 exact output/trace match
2. requesterが明示許可したk=3 private rerun
3. requesterが明示許可したTEE内audit
4. requester自身による暗号化dispute

実ジョブのactivation sketch、embedding、promptをpublic auditorへ開示しない。embedding inversionを招いてまで「監査しました」と胸を張るのは、鍵をドアの横へ貼って防犯チェック済みと言うのと同程度である。

### 10.5 receipt DA

providerのfull receiptと必要なcanary openingは、erasure-coded PALW DA objectとして配布し、そのrootをleafへcommitする。通常block検証はfull receiptを読まない。ただし次を満たす。

- certificate前にauditor quorumが取得済み
- fraud window中はP2Pで取得可能
- pruning proofにはhistoric certificateと必要なslash evidenceを含める
- DA unavailable時はbatch certificateを発行しない

「cacheにあるはず」はデータ可用性仕様ではない。

---

## 11. DNS PALW beacon

### 11.1 現行DNSとの関係

現行コードにはDNS finalityとPQ validator署名があるが、PALWがそのまま利用できるbias-resistant epoch randomnessは実装済みとは扱わない。旧commit-reveal sortition案はADR上でsupersedeされているため、新しいPALW beacon state machineを明示的に実装する。

### 11.2 commit-reveal

初期v0.2はPQ署名付きcommit-revealとslashingを使う。

```rust
pub struct PalwBeaconCommitV1 {
    pub version: u16,
    pub epoch: u64,
    pub bond_outpoint: TransactionOutpoint,
    pub commitment: Hash64, // H(epoch || random_64 || bond)
    pub signature: Vec<u8>, // ML-DSA
}

pub struct PalwBeaconRevealV1 {
    pub version: u16,
    pub epoch: u64,
    pub bond_outpoint: TransactionOutpoint,
    pub random_64: [u8; 64],
    pub signature: Vec<u8>,
}
```

- epoch `E-2`: commit
- epoch `E-1`: reveal
- epoch `E`: seed active

#### 11.2.1 phase座標の凍結（acceptance epoch）

`E-2` / `E-1` のleadは、txを**受理したchain blockのDAA epoch**（acceptance epoch）で測る。carrier block（txを内包したmergeset source）のepochでは**ない**。この座標はactivation前に凍結する。

- **決定性 / c==v**: acceptance epochは受理側blockのDAA scoreの関数であり、templateとvalidationの双方が単一のselected-parent POVから同一に導出できる。
- **carrier-block座標は単一POVから安全に得られない**: mergeset sourceごとに、その source自身のepoch時点でbond/署名を検証するためのblock-keyedなbond viewとoutcomeが必要になり、決定的に構成できない。
- **安全性は不変**: phase述語は `target == accept_epoch + lead` を厳密に固定するため、遅延・先行して受理されたtxはdropされるだけで別epochへ**再照準できない**。includeタイミングを選べるminerが得るのは検閲のみ（既存の一般的性質）であり、grinding優位は生じない。
- **一貫性**: DNS attestation / slashing など他の `acceptance_data` 駆動overlayと同一座標。

```text
R_E = H(
  "misaka-palw-beacon-v1" ||
  R_(E-1) ||
  dns_finalized_anchor(E-1) ||
  canonical_sorted(valid_reveals_E) ||
  canonical_sorted(missing_commitments_E) ||
  E
)
```

missing revealはslashする。単純commit-revealにはlast-revealer biasが残るため、v0.2ではこれを経済的に抑制し、mainnet候補ではrecovery shareまたはPQ threshold randomnessへ置換可能な`beacon_version`を予約する。

### 11.3 degraded mode

DNS qualityが閾値未満またはbeacon quorum不足の場合:

1. 既存Active ticketの短いgrace windowは前seedを使う。
2. 新batchをActiveにしない。
3. grace終了後、algo 4 blockを無効化する。
4. algo 3 hash laneは継続する。

fallback seedを使うtestnet modeでは、現在tipではなく十分lagしたselected-chain windowを使う。

```text
R_fallback = H(
  previous_seed ||
  finalized_anchor ||
  MerkleRoot(block_hashes in lagged wide window) ||
  epoch
)
```

これは完全なunbiasabilityを与えない。したがってfallback中のcompute work倍率を下げるか、最終的には0にする。

---

## 12. ticket slot、fork binding、eligibility

### 12.1 miner-selectable `chain_commit` を禁止する

`chain_commit = H(current_tip)` をblock producerが自由に変えられると、それ自体がnonceになり、forkを作るたびにticketを再抽選できる。したがって `chain_commit` はtarget intervalより前に確定した、全node同一のcheckpointから導出する。

```text
chain_commit(S) = H(
  "misaka-palw-chain-commit-v1" ||
  dns_finalized_checkpoint_hash_at_or_before(S - LOOKBACK) ||
  dns_finality_certificate_hash_for_that_checkpoint ||
  S ||
  network_id
)
```

- `LOOKBACK` はDNS finalityと最大浅いreorgを超える。
- checkpointは単なるlagged tipではなく、DNS certificateで確定済みのselected-chain blockである。
- target interval `S` はleafごとに1つだけ。
- checkpointより前から分岐するprivate forkは、同じDNS certificateを持たない限りticketを使えない。
- checkpoint以後のshallow forkでは同じdrawになるため、forkごとの再抽選はできない。

#### 12.1.1 `dns_finality_certificate_hash` v1 の凍結（confirmation-evidence digest）

v1 は署名付き証明書オブジェクトではなく、**確認済み anchor 自身の凍結事実**の domain 分離 digest とする（3-lens design panel で敵対検証済み）。

```text
dns_finality_certificate_hash_v1 = H(
  "misaka-palw-dns-cert-v1" ||
  anchor_hash || anchor_blue_score || anchor_daa_score ||
  anchor_overlay_commitment_root
)
```

- **全 preimage フィールドは anchor block 固有**（header-committed・lag 埋没済み・work+stake 両深度で確認済み・どの target interval よりも厳密に前に固定）。`anchor_overlay_commitment_root` が「どの bond/stake 集合が確認したか」を churn なしに束縛する（validator_set_commitment の実体化）。
- **意図的に除外**（いずれも panel が構築した grinding/split 経路）: 境界時点の bond view に対する bond-set commitment（安価な self-bond の包含選択で 2^n 通りの再抽選）、`confirmation_epoch`（境界で 2 値化・carried anchor で未定義）、生の work/stake depth（block ごとに成長）。
- **解決規則**: header の `expected_chain_commit` は、その header の **selected parent が carry する単一の beacon record**（clause 9 が R_E を読むのと同一の 1 回読み出し）から導出する。cert と seed は同一 provenance を共有し、clause 6 は clause 9 を超える fork 自由度を追加しない。境界跨ぎ header は前 epoch の凍結事実に束縛される（c==v は構造的）。
- **carry 規則**: anchor 事実は confirmed anchor が**前進した時のみ**再計算し、不変の間は親 record の事実を逐語 carry する（anchor-pure なので決定性は保存、anchor header の再読も不要）。
- **fail-closed**: DNS 確認済み anchor が無い間（bootstrap の zero anchor）は certificate を導出しない。zero-cert の `chain_commit` は全 private fork が再現可能で I-4 を無効化するため、その間 algo-4 は受理しない（C5 で enforce）。
- **params 前提**: `palw_checkpoint_params_consistent`（`lag + backoff >= max_reorg_horizon` かつ確認深度が非自明）を PALW re-genesis の preflight / C5 activation gate とする。現行 testnet DNS 値（lag 100 + backoff 20 < horizon 300）は不成立であり、re-genesis で lag/backoff を再校正する。`dns_v3_params_consistent` には**入れない**（稼働中 net の DNS overlay を即座に不活性化するため）。
- **v2 予約**: 実証明書オブジェクトは新 domain で `chain_commit` の第2引数（不透明 digest）の意味のみ差し替えて導入可能。

### 12.2 target interval

batch activation後、leafは1つのtarget DAA intervalへ割り当てる。

```text
slot_digest = H(
  "misaka-palw-slot-v1" ||
  eligibility_beacon ||
  batch_id ||
  leaf_index ||
  leaf_hash
)

target_daa_interval = active_from + (slot_digest mod active_window_intervals)
```

`active_window_intervals` は短くし、expiryはmerge-depth boundより十分小さくする。testnet初期値は60秒、40 BPSで2400 intervals。

### 12.3 one-shot eligibility

```text
eligibility_hash = H(
  "misaka-palw-eligibility-v1" ||
  network_id ||
  eligibility_beacon ||
  chain_commit(target_daa_interval) ||
  target_daa_interval ||
  batch_id ||
  leaf_index ||
  leaf_hash ||
  ticket_nullifier
)
```

受理条件:

```text
Uint512(eligibility_hash) <= target_512(header.bits)
header.daa_score == target_daa_interval
header.nonce == low64(ticket_nullifier)
```

nonceを変えてもeligibility inputは変わらないうえ、canonical nonce以外をrejectする。

### 12.4 fork上の二重使用

同一ticketを異なるheaderへ使用するにはticket authorityの署名が必要である。

```rust
pub struct PalwBlockAuthorizationV1 {
    pub version: u16,
    pub batch_id: Hash64,
    pub leaf_index: u32,
    pub ticket_nullifier: Hash64,
    pub header_preimage_commitment: Hash64,
    pub authority_public_key: Vec<u8>,
    pub signature: Vec<u8>, // ML-DSA
}
```

- leafは `ticket_authority_pk_hash` をcommit済み。authorityはbatch作成時に両provider receiptが承認したone-time assembler keyであり、対応bondを持つ。
- authorizationはblock bodyのPALW payloadに置く。
- Headerは `palw_authorization_hash` をcommitする。
- 署名messageは `palw_authorization_hash = 0` としてcanonical encodeしたHeader fields、transaction root、parent set、ticket nullifierをdomain-separated hashした値とする。これで署名payloadとHeader hashの循環参照を避ける。
- final Headerの `palw_authorization_hash` は完成したauthorization payloadのhashである。
- 同じauthority/nullifierが異なるheader commitmentへ署名した場合、forkをまたぐslashing evidenceになる。
- bond unlock delayはevidence提出期限より後。

公開後に署名をコピーして別headerを作ることはできない。秘密鍵まで公開する単純hash preimage方式は採用しない。

---

## 13. Header v3

### 13.1 新field

`consensus/core/src/constants.rs`:

```rust
pub const PALW_HEADER_VERSION: u16 = 3;
```

`consensus/core/src/header.rs` の `Header` にappendする。

```rust
pub blue_hash_work: BlueWorkType,
pub blue_compute_work: BlueWorkType,

pub palw_batch_id: Hash64,
pub palw_leaf_index: u32,
pub palw_ticket_nullifier: Hash64,
pub palw_epoch_certificate_hash: Hash64,
pub palw_chain_commit: Hash64,
pub palw_target_daa_interval: u64,
pub palw_authorization_hash: Hash64,
pub palw_proof_type: u8,
```

algo 3では全PALW fieldをzeroにする。version < 3では新fieldをhash preimageへ入れず、decode後にzeroであることを要求する。

### 13.2 frozen hash order

`consensus/core/src/hashing/header.rs` で、既存 `overlay_commitment_root` の後へversion-gated appendを行う。

```rust
if header.version >= PALW_HEADER_VERSION {
    hasher.write_blue_work(header.blue_hash_work);
    hasher.write_blue_work(header.blue_compute_work);
    hasher.update(header.palw_batch_id);
    hasher.update(header.palw_leaf_index.to_le_bytes());
    hasher.update(header.palw_ticket_nullifier);
    hasher.update(header.palw_epoch_certificate_hash);
    hasher.update(header.palw_chain_commit);
    hasher.update(header.palw_target_daa_interval.to_le_bytes());
    hasher.update(header.palw_authorization_hash);
    hasher.update([header.palw_proof_type]);
}
```

この順序はtestnet activation後にfrozenとする。Header constructor、P2P protobuf、RPC DTO、DB shim、genesis builder、test fixturesを同時に変更する。

### 13.3 header shape rule

```rust
fn check_palw_header_shape(header: &Header, active: bool) -> Result<(), RuleError> {
    match header.pow_algo_id {
        POW_ALGO_ID_BLAKE2B_SHA3 => {
            ensure_all_palw_fields_zero(header)?;
            ensure!(header.blue_compute_work <= 4 * header.blue_hash_work);
        }
        POW_ALGO_ID_PALW_REPLICA if active => {
            ensure!(header.version >= PALW_HEADER_VERSION);
            ensure!(!header.palw_batch_id.is_zero());
            ensure!(!header.palw_ticket_nullifier.is_zero());
            ensure!(header.palw_proof_type == PalwProofType::ReplicaExactV1 as u8);
            ensure!(header.nonce == low64(header.palw_ticket_nullifier));
        }
        _ => return Err(RuleError::UnexpectedPowAlgo(header.pow_algo_id)),
    }
    Ok(())
}
```

---

## 14. Block検証パイプライン

### 14.1 現行pathの分割

現在の `check_pow_and_calc_block_level` は `StateLayer0` を同期実行する。v0.2では次へ分ける。

```rust
pub enum WorkProofOutcome {
    Hash {
        pow_512: Uint512,
        block_level: BlockLevel,
    },
    ReplicaPalw {
        eligibility_512: Uint512,
        block_level: BlockLevel,
        ticket: PalwTicketRef,
    },
}
```

- pre-ghostdag isolation: algo、version、zero/nonzero field、canonical nonce、cheap hash syntax
- parents known後: lane DAA、beacon、chain commit、batch Active、leaf lookup、certificate、target interval
- body validation: ML-DSA authorization、coinbase pair reward、PALW payload hash
- post-ghostdag: component work、nullifier dedup、blue fields

### 14.2 fast verifier

```rust
fn verify_replica_palw_header(
    header: &Header,
    ctx: &PalwConsensusContext,
) -> Result<WorkProofOutcome, RuleError> {
    let cert = ctx
        .certificate_store
        .get(header.palw_epoch_certificate_hash)
        .ok_or(RuleError::PalwCertificateMissing)?;

    let leaf = ctx
        .leaf_store
        .get(header.palw_batch_id, header.palw_leaf_index)
        .ok_or(RuleError::PalwLeafMissing)?;

    ensure!(cert.is_active_at(header.daa_score));
    ensure!(leaf.ticket_nullifier == header.palw_ticket_nullifier);
    ensure!(leaf.proof_type == header.palw_proof_type);
    ensure!(leaf.activation_epoch <= ctx.epoch(header.daa_score));
    ensure!(ctx.epoch(header.daa_score) < leaf.expiry_epoch);
    ensure!(leaf.target_daa_interval(ctx.beacon_store)? == header.daa_score);

    let expected_chain_commit = ctx.chain_commit(header.daa_score)?;
    ensure!(header.palw_chain_commit == expected_chain_commit);

    let expected_bits = ctx.lane_daa.expected_bits(WorkLane::ReplicaPalw)?;
    ensure!(header.bits == expected_bits);

    let digest = calculate_palw_eligibility(header, &leaf, ctx)?;
    let target = Uint512::from_compact_target_bits_512(header.bits);
    ensure!(Uint512::from_le_bytes(digest) <= target);

    ensure!(ctx.compute_headroom() > Uint512::ZERO);

    Ok(WorkProofOutcome::ReplicaPalw {
        eligibility_512: Uint512::from_le_bytes(digest),
        block_level: calc_level_from_pow_512(digest.into(), ctx.max_block_level),
        ticket: PalwTicketRef::new(header.palw_batch_id, header.palw_leaf_index),
    })
}
```

### 14.3 性能目標

40 BPSでは平均25msある。cached stateでのalgo 4 header pathのtestnet目標を次に置く（25ms intervalに対しtight）。

- p50 < 1ms
- p99 < 5ms
- ML-DSA block authorizationを含むfull block validation p99 < 20ms
- IBD時のcertificate検証はbatch単位でamortize

これは設計目標であり、実測前に達成済みとは書かない。validatorがQwenを再実行するpathはblock acceptanceへ入れない。

### 14.4 §14.2 enforcement stage の設計凍結（C5 architecture、B-vs-C panel + linchpin verify）

algo-4 ticket 検証(clause 1-9)をどの pipeline stage で enforce するかを、3-verdict + 3 adversarial-verify で確定した。B(mergeset/header 由来の past-relative overlay)vs C(header 段階 work-credit gating)。

**linchpin(全 verify CONFIRMED)**: `ghostdag()` coloring は純トポロジカルで body status を見ないため、header 段階で invalid-ticket ブロック X の compute work は「X を merge-blue で取り込む全ブロック」に credit される。**しかし body-DAG 下方閉包**(`check_parent_bodies_exist` が全 direct parent に body を要求 → 「body を持つ」は direct-parent DAG 上で下方閉包 → StatusInvalid の X は body-valid ブロックの past に決して入れない)により、**X の work は authoritative UTXO chain(body_tips seed の sink search)へ到達しない**。よって work-credit を header に置いたままで **consensus 安全**。C の header-gating は UTXO chain にとって非問題を解いている。

**残余(3層分解)**: `headers_selected_tip`(bodyless header-relay/IBD heuristic)は body 要件なしに `header.blue_work` を読むため、`palw_compute_work_scale > 0` で invalid-ticket work により膨張しうる。ただし `E = H + min(C, 4H)`(cap 4)で **≤5× 有界**・full PoW コスト・body validation で self-heal・既存の valid-PoW/bad-body header 膨張と同クラス。authoritative chain は安全。

**確定 = B(synthesis、C の burial を吸収)**:
1. **compute-work credit = HEADER のまま**(landed)。body 閉包が isolate。fork-choice 手術・循環なし。
2. **ticket 解決(batch/leaf/cert/nullifier)= 選択親で解決する past-relative overlay を HEADER で mergeset から構築**(landed の nullifier set と同型: `view(B) = view(SP(B)) ⊕ Δ(mergeset(B))`)。**これは B の isolation を決定的にするために必須**(現状の tip-global 読みは consensus split=C4 blocker)。PALW overlay tx を payload/fee-only にして健全化。これで batch/cert 解決が nullifier dedup + compute-work と**同一座標**(header-mergeset)= 内部整合。
3. **acceptance 本質の clause(eligibility DRAW/R_E, chain_commit)= FINALITY-BURIED beacon/anchor を読む**(burial 深度で既に virtual-commit 済・全ノード一致)。**C の lag/burial の洞察を採用**(header ではなく検証 stage で)。buried anchor は既に header-committed(`palw_lagged_dns_anchor_candidate`)。
4. **残余の header_selected_tip leak = 任意の後続 hardening**(header work-credit を header-mergeset overlay で gate、buried/mergeset 由来なので循環なし)。**安全性の blocker ではない**。

**migration**: 全 inert、activation = re-genesis。凍結: 新 per-block store(PalwOverlayView、PalwNullifierStore 同型、header-mergeset 構築)を `LATEST_DB_VERSION 7→8` cutover に同梱、`check_palw_ticket` を `view(SP(B))` 解決へ書換、buried-beacon draw の配線。**header wire-format 変更なし**。C が却下される決め手: C は header で gate するが必要な buried overlay(batch/cert/R_E)は acceptance 由来(virtual-commit)で headers-first IBD 時に header 段階では未生成 → header→virtual 反転で headers-first sync を破壊。header で使える形にすると B を lag sampling したものに collapse。

---

## 15. GHOSTDAG、nullifier dedup、component work

### 15.1 store変更

`consensus/src/model/stores/ghostdag.rs`:

```rust
pub struct GhostdagData {
    pub blue_score: u64,
    pub blue_work: BlueWorkType,
    pub blue_hash_work: BlueWorkType,
    pub blue_compute_work: BlueWorkType,
    pub selected_parent: BlockHash,
    pub mergeset_blues: BlockHashes,
    pub mergeset_reds: BlockHashes,
    pub blues_anticone_sizes: HashKTypeMap,
}

pub struct CompactGhostdagData {
    pub blue_score: u64,
    pub blue_work: BlueWorkType,
    pub blue_hash_work: BlueWorkType,
    pub blue_compute_work: BlueWorkType,
    pub selected_parent: BlockHash,
}
```

pre-v3 historic dataのmigration viewは:

```text
blue_hash_work = blue_work
blue_compute_work = 0
```

とする。DB serialization変更のため、PALW networkはre-genesisとstore version bumpを必須にする。

### 15.2 active nullifier window

expiryが短いため、全履歴nullifierを保持しない。

```rust
pub trait PalwNullifierStoreReader {
    fn contains_in_past_window(
        &self,
        selected_parent: BlockHash,
        nullifier: Hash64,
        min_daa: u64,
    ) -> Result<bool, StoreError>;

    fn active_nullifiers(
        &self,
        block: BlockHash,
    ) -> Result<Arc<PalwActiveNullifierSet>, StoreError>;
}
```

testnet初期値:

- ticket active window: 2,400 blocks相当
- nullifier retention: 4,800 blocks相当
- slashing evidence index: max reorg horizon + unbond delayまで

active setはpersistent delta構造またはcopy-on-write sorted setで実装し、Headerのnullifierから決定論的に再構成可能にする。Bloom filterだけでconsensus判定しない。

### 15.3 duplicate rule

新blockのGHOSTDAG mergesetを従来通りk-clusterで並べた後、PALW dedup passを行う。

1. selected parent pastのactive nullifier setをseedにする。
2. mergeset candidatesを既存のconsensus order、すなわちascending blue work + hash tie-breakで処理する。
3. algo 3は通常処理。
4. algo 4でnullifier未出ならsetへ追加し、blue候補を維持。
5. 既出なら `PalwDuplicateTicket` としてredへ移し、blue score/workへ加算しない。

```rust
fn apply_palw_dedup(
    data: &mut GhostdagData,
    headers: &dyn HeaderStoreReader,
    active: &mut PalwActiveNullifierSet,
) -> Result<(), StoreError> {
    let ordered = data.consensus_ordered_mergeset_without_selected_parent(/* store */).collect::<Vec<_>>();
    for hash in ordered {
        let h = headers.get_header(hash)?;
        if h.pow_algo_id != POW_ALGO_ID_PALW_REPLICA {
            continue;
        }
        if !active.insert(h.palw_ticket_nullifier) {
            data.remove_blue_and_add_red(hash)?;
        }
    }
    Ok(())
}
```

実際には既存GHOSTDAG coloring中に統合し、blue anticone sizeとvector orderが壊れないようにする。後からvectorだけ移す簡易実装は禁止する。

### 15.4 source block work

Kaspa系GHOSTDAGでは、block自身のworkはそのblockのHeader `blue_work` に直接足されるのではなく、子blockがsource blockをblue mergesetへ取り込むときに累積へ入る。したがって、PALW sourceのnullifierとreward classはsource Header/leaf stateから参照し、子のGHOSTDAG計算で一度だけcreditする。

### 15.5 finalize

```rust
pub fn finalize_score_and_component_work(
    &mut self,
    blue_score: u64,
    blue_hash_work: BlueWorkType,
    blue_compute_work_raw: BlueWorkType,
    cap_ratio: u64,
) {
    let cap = blue_hash_work.saturating_mul(cap_ratio.into());
    let blue_compute_work = blue_compute_work_raw.min(cap);
    self.blue_score = blue_score;
    self.blue_hash_work = blue_hash_work;
    self.blue_compute_work = blue_compute_work;
    self.blue_work = blue_hash_work + blue_compute_work;
}
```

big-int演算はchecked/saturating semanticsをconsensusで固定し、property testする。

### 15.6 ordering

`SortableBlock` は従来通りeffective `blue_work` を使う。component値はtie-breakに追加しない。fork choice規則を必要以上に複雑化しないためである。

---

## 16. lane別DAA

### 16.1 必要性

単一DAAのままalgo 3/4を混ぜると、ticket供給とhash rateのどちらかが他方のdifficultyを操作できる。`WindowManager` をlane-awareにする。

```rust
pub trait WindowManager {
    fn block_daa_window_for_lane(
        &self,
        ghostdag_data: &GhostdagData,
        lane: WorkLane,
    ) -> Result<DaaWindow, RuleError>;

    fn calculate_difficulty_bits_for_lane(
        &self,
        lane: WorkLane,
        ghostdag_data: &GhostdagData,
        daa_window: &DaaWindow,
    ) -> u32;
}
```

### 16.2 sampling rule

- hash lane window: credited blue algo 3 source blocksのみ
- compute lane window: unique、Active、credited blue algo 4 source blocksのみ
- red、duplicate、revoked、zero-headroom PALW blockはsampleに入れない
- `daa_score` 自体はtotal DAG progressionとして維持

### 16.3 target

```rust
LaneDifficultyParams {
    hash_target_time_ms: 125,
    replica_target_time_ms: 31,
    hash_window_size: ...,
    replica_window_size: ...,
    min_samples: ...,
    genesis_hash_bits: ...,
    genesis_replica_bits: ...,
}
```

lane sample不足時は、直近lane bitsを維持し、突然min difficultyへ落とさない。testnetでemergency ruleを試す場合もnetwork paramsへ明示する。

#### 16.3.1 clause 7 `expected_bits` の設計凍結（3-lens panel）

- **構造的ブロッカー**: replica lane は `get_bits(selected_parent)` で HOLD 元を読めない。1:4 split では algo-4 ブロックの selected parent は通常 algo-3 で、その `header.bits` は **hash lane** の難易度。逆も真（activation 後は hash lane も、selected parent が algo-4 のとき汚染される）。従って**両 lane の現在 bits をブロックごとに carry する block-keyed store**が必須。
- **lane-bits store**: `PalwLaneBits`（prefix 245、`BlockHash → {hash_bits, replica_bits}`）。daa≥activation の全ブロックが両 bits を書き込み、空 window の HOLD は `genesis_{hash,replica}_bits` に fallback。depth-1 再帰（Adjust は window から再計算、HOLD のみ親 1 読み）なので R_E のような multi-epoch replay 問題は無い。
- **retarget cadence**: hash lane と同じ **per-block**（per-epoch は境界での burst 操作 + D1 replay 再燃）。`max_adjust_factor` clamp で sparse-GPU 起動時の 1-step collapse を防ぐ。sample index は **lane-filtered 系列**上で増加（total-DAG sample_rate と独立）。
- **sampler**: `algo==4 && credited_blue`。GHOSTDAG coloring が duplicate ticket を既に red にする（`mergeset_blues` から除外）ので `unique` は実質無料。ただし cross-ancestor dedup は **C4 依存**（現状 within-mergeset + selected-parent seed のみ）。`Active/revoked` は各ブロックの acceptance 時 `check_palw_ticket` で担保され、accepted+credited_blue ⟹ Active。overlay 読みは sampler 内で不要。
- **engine 分離**: live `calculate_difficulty_bits` は clamp が無いので**一切変更しない**（clamp 追加は golden drift）。専用 lane 経路（両 lane を扱う）を palw-active 時のみ通す。activation は re-genesis なので mid-chain の difficulty step 不連続は無い。
- **CompactHeaderData 不拡張**: bincode で 28→29B になり既存 testnet の全 row が restart 時 decode 失敗（silent DB break、genesis test は捕捉せず）。algo_id は palw-active 経路で full header から読む。
- **params 前提**: `is_consistent_for_activation(genesis_bits)` = `genesis_hash_bits == genesis header bits`（inert-vs-active HOLD 一致）∧ genesis bits 非ゼロ ∧ `min_samples ≤ window`。re-genesis preflight。
- **enforcement**: このスライスは params + store + pure retarget core (`lane_retarget_bits`) + tested HOLD bridge のみ。**per-lane window build + commit-time write + lane-aware bits 検証 + template は次スライス**（sampler の exact soundness は C4 依存、enforcement は C5 で 9 clause 一括 flip）。

### 16.4 ticket oversupply

登録ticket数がblock targetを大きく上回るのは正常である。compute difficultyがone-shot eligibilityの当選率を調整し、1秒あたり約32 ticketだけがblockへ使われる。登録rateのspamはpayload fee、batch bond、epoch quotaで抑える。

---
## 17. coinbase 70%の接続

### 17.1 基本方針（amended 2026-07-13：レーン非対称）

現行コードのworker側は概ね、base 62%、inclusion 8%、validator 30%である。**algo 3 hash laneはこの62/8/30を維持する。** algo 4 PALW laneはvalidator分を30%→15%へ半減し、その余剰15%をLLM計算ソース（provider pair）へ回すため **base 77% / inclusion 8% / validator 15%** とする（レーン別split）。

| source block | worker base | inclusion 8% | validator |
|---|---|---|---|
| algo 3 hash | source hash minerへ **62%** | current includerへ8% | **30%**（現行通り） |
| algo 4 PALW | provider Aへ **38.5%**、provider Bへ **38.5%**（base **77%**） | current includer/assemblerへ8% | **15%** |

algo 4 blockでは77%が実LLM GPU計算者へ、8%がDAG inclusion/block assemblyへ、validatorは15%へ流れる。transaction feeの通常classはblock assemblerへ、finality feeは既存DNS splitを維持する。

**validator予算への影響（意図的・受容済）**：PALW-lane validatorを半減するとDNS finality（2-D reorg防御）予算が下がる。8:32のBPS splitでは全ブロック加重の実効validator subsidyは概ね `0.2·30% + 0.8·15% = 18%`（旧30%から約−40%）。hash laneの30%は不変で、これはPALWネットワークのnetwork-param（hard-fork / re-genesis）であり、liveの変更ではない。

### 17.2 reward data

`consensus/core/src/coinbase.rs`:

```rust
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum WorkRewardClass {
    HashMiner,
    ReplicaPalw {
        batch_id: Hash64,
        leaf_index: u32,
        provider_a_script: ScriptPublicKey,
        provider_b_script: ScriptPublicKey,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlockRewardData {
    pub subsidy: u64,
    pub total_fees: u64,
    pub finality_fees: u64,
    pub script_public_key: ScriptPublicKey, // assembler/source miner
    pub work_reward_class: WorkRewardClass,
}
```

`calculate_utxo_state` とcoinbase constructionの両方が同じsource HeaderとPALW leaf stateから `work_reward_class` を導出し、construction == validationを維持する。

### 17.3 blue PALW source

unique blueとしてcreditされたsource blockだけprovider rewardを得る。

```rust
let provider_pool = subsidy * 77 / 100; // PALW_PROVIDER_BASE_BPS = 7700（62%+validator由来15%）
let provider_a = provider_pool / 2;
let provider_b = provider_pool - provider_a;
```

端数規則を固定し、A/Bの並びはbond outpointのcanonical orderで決める。provider pairのreward scriptはleaf登録時のone-time scriptで、長期provider addressとのlinkabilityを減らす。

### 17.4 red/duplicate PALW source

- duplicate ticketとしてredへ落ちたsource: provider subsidy 0
- 通常のanticone競合でredになったPALW source: provider subsidy 0
- requester service fee: chain coinbaseとは独立に、契約に従って支払可能
- mintされなかったprovider base部分: current minerへ再配分しない

再配分すると、duplicate PALW blockを大量に作りcurrent includerが得をする。未発行扱いまたはsecurity reserveへ明示的に送る。testnet v0.2は未発行とし、issuance accountingへ反映する。

### 17.5 inclusion 8%

既存 `worker inclusion pool` の意味を維持する。PALW sourceのprovider pairとblock assemblerは同一でも別でもよい。assemblerはticket authorityのauthorizationを取得し、valid blockを組み立てる。

### 17.6 coinbase validation

full block validationは次を確認する。

1. algo 4 sourceがunique blue creditを得ている。
2. Headerのbatch/leaf refがActive leafと一致。
3. provider reward scriptsがleaf descriptorと一致。
4. base 77%の38.5/38.5 splitと端数規則、およびPALW-lane validator 15%が一致。
5. duplicate/red sourceにprovider outputがない。
6. current inclusion outputとvalidator outputsが現行規則に一致。

---

## 18. PALW overlay state、データ可用性、pruning/IBD

### 18.1 store群

新規 `consensus/src/model/stores/palw.rs` を追加する。

```rust
pub trait PalwStoreReader {
    fn provider_bond(&self, outpoint: TransactionOutpoint) -> Result<PalwProviderBondRecord, StoreError>;
    fn batch_manifest(&self, batch_id: Hash64) -> Result<PalwBatchManifestV1, StoreError>;
    fn leaf(&self, batch_id: Hash64, leaf_index: u32) -> Result<PalwPublicLeafV1, StoreError>;
    fn certificate(&self, cert_hash: Hash64) -> Result<PalwBatchCertificateV1, StoreError>;
    fn batch_status(&self, batch_id: Hash64) -> Result<PalwBatchStatus, StoreError>;
    fn beacon(&self, epoch: u64) -> Result<PalwBeaconStateV1, StoreError>;
    fn nullifier_status(&self, nullifier: Hash64) -> Result<PalwNullifierStatus, StoreError>;
}
```

DB prefixesを分離する。

```text
palw/provider-bond/
palw/batch-manifest/
palw/leaf/
palw/certificate/
palw/batch-status/
palw/beacon-commit/
palw/beacon-reveal/
palw/beacon-state/
palw/nullifier/
palw/slashing/
palw/lane-daa/
```

### 18.2 OverlaySnapshot

現行 `OverlaySnapshot` へPALW raw stateを追加する。ただし全historic leafをsnapshotへ入れない。pruning pointからactive/fraud-window stateを再構築できる最小集合をcommitする。

#### 18.2.1 past-relative overlay view の設計凍結（C4 3-lens panel）

tip-global な `DbPalwStore` 読みを past-relative 化する。panel が 3 つの選択肢を検証:

- **full-carry(beacon accum 流)は却下**: leaf 841B × 256 + cert(ML-DSA-87 署名 4.6KB × auditor)= ~292KB/batch。**batch 数の上限パラメータが無く**、block mass から ~22 batch/s ⇒ active window で ~385MB、evidence window で ~3.8GB を chain block ごとに clone+borsh+RocksDB = **GB/s の write 増幅**。§18.2 の「全 historic leaf を入れない」に反する。
- **採用 = hybrid**: fork 依存の **compact な presence+status のみ carry**(`PalwBatchViewV1`: `batch_id → PalwBatchLifecycleV1`、~230B/batch = 1300× 削減)。不変 CONTENT(leaf/manifest/cert)は content-addressed blob store に置く。
- **content-addressing が前提**: `batch_id` は attacker 選択の manifest フィールドで hash ではない → 2 fork が同一キーに異なる manifest/leaf を登録可。修正: `batch_id == content_id()`(batch_id を除いた manifest の hash)を admission で強制、leaves は `leaf_root == palw_leaf_root(ordered leaf_hashes)` に §9.3 completeness で還元。これで blob store は衝突耐性で **write-once**、fork-relativity は compact view のみが担う。
- **admission 検証が必須**(現状ゼロ): `expiry_epoch = u64::MAX` の manifest が view を永久固定できる。`admission_valid` = content-address + version + leaf_count 境界 + chunk_count 厳密一致 + `registration_epoch == accept_epoch`(§11.2.1 phase freeze)+ activation/expiry の有界化。
- **retain 述語**(§18.2 の active/fraud-window 最小集合): `palw_batch_referenceable` = terminal/revoked は drop、Active/Certified は `epoch < expiry`、pre-cert は registration+lead+audit 予算まで。**evidence window は含めない**(expired batch への fraud は header verdict を変えない=それは bond record の寿命)。epoch 単調で `retain_future_of` と同論法。

**stage 分岐(C5 の前提、C4 では決めない — panel が凍結を禁止)**: `check_palw_ticket` は body validation で走るが、view は virtual-commit(chain block のみ、ノードローカル・到着順集合)で書かれる → **body での selected-parent view 読みは consensus split**(`PalwTicketInvalid` は StatusInvalid で永久拒否)。かつ virtual へ移すと、`ghostdag()` が algo-4 の compute work を **HEADER で ticket 検証なしに credit** 済み・virtual の制裁は disqualify-from-chain のみ(work は DAG に残る)ため work-credit closure を失う。header 段階 work-credit と fork-relative state の整合(lag/burial 規律、`chain_commit` の DNS-confirmed lagged anchor と同型)は C5 の前提。よって C4 は **type + content-addressing + admission + retain の pure 部分のみ**を出荷し、builder(write-site + apply 座標=mergeset vs acceptance)は据え置く。

```rust
pub struct OverlaySnapshot {
    pub bonds: Vec<StakeBondRecord>,
    pub reserve_balance: u64,
    pub window: Vec<BlockOverlayContribution>,

    pub palw_provider_bonds: Vec<PalwProviderBondRecord>,
    pub palw_active_batches: Vec<PalwActiveBatchSnapshotV1>,
    pub palw_beacon_states: Vec<PalwBeaconStateV1>,
    pub palw_active_nullifiers: Vec<PalwNullifierSnapshotV1>,
    pub palw_lane_daa_state: PalwLaneDaaSnapshotV1,
}
```

canonical sort orderを明記する。

- provider bond: outpoint ascending
- batch: batch ID ascending
- leaf/chunk: `(batch_id, leaf_index)` ascending
- beacon: epoch ascending
- nullifier: hash ascending

`overlay_commitment_root` の変更はhard forkであり、新genesisを使う。

### 18.3 pruning proof bundle

headerだけではhistoric PALW ticketのcertificate/leafを検証できない。pruning proofへ次を追加する。

```rust
pub struct PalwEpochProofBundleV1 {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub beacon_chain: Vec<PalwBeaconCheckpointV1>,
    pub batch_manifests: Vec<PalwBatchManifestV1>,
    pub leaf_chunks: Vec<PalwLeafChunkV1>,
    pub certificates: Vec<PalwBatchCertificateV1>,
    pub revocations: Vec<PalwRevocationV1>,
    pub nullifier_frontier_root: Hash64,
}
```

pruning verifierは、proof内で参照されたalgo 4 Headerについて:

1. batch/leaf存在
2. certificate quorum
3. activation/expiry
4. beacon chain
5. target interval
6. chain commit
7. eligibility hash
8. component work
9. nullifier dedup

を再計算する。

### 18.4 P2P

`protocol/p2p` に明示的なrequest/response flowを追加する。

- `RequestPalwEpochProof`
- `PalwEpochProofChunk`
- `RequestPalwBatch`
- `PalwBatchChunk`
- `RequestPalwCertificate`

block header受信時のgossip cache missは、単にinvalidとはせず「依存state未取得」としてorphan/quarantineし、オンチェーン順序を確認後に再処理する。ただし依存txが必要なN-block leadを満たさないblockはinvalidである。

### 18.5 registration lead

batch manifestと全leaf chunkは、最短でもactivationの20 blocks前では足りない。40 BPSでは0.5秒しかないため、epoch単位で余裕を持たせる。

初期値:

- registration: activationの最低2 epochs前、約20秒
- audit/certification window: 6 epochs、約60秒
- certificate inclusion: activationの最低1 epoch前、約10秒

---

## 19. プライバシー仕様

### 19.1 誰が何を知るか

| 主体 | prompt | answer | requester identity | provider pair | leaf ID |
|---|---|---|---|---|---|
| requester | 知る | 知る | 自身 | 原則知らない/optional | private mappingのみ |
| provider A | 知る | 自身の出力 | 知らない | Bを知らない | 自分のjob capability |
| provider B | 知る | 自身の出力 | 知らない | Aを知らない | 自分のjob capability |
| dispatcher quorum | encrypted shareまたは一部mapping | 不要 | ingress次第 | 選択時に知る | 知る |
| public validator | 知らない | 知らない | 知らない | bond pairは公開 | 知る |
| block assembler | 知らない | 知らない | 知らない | reward scriptsを知る | 知る |

v0.2ではprovider bond pairは公開する。これによりdistinctness、slashing、rewardをZKなしで検証できる。公開されるのは「この2 providerがある匿名work leafを処理した」という事実であり、誰の質問か、何を質問したかではない。

### 19.2 transport

- ML-KEM ephemeral channel
- per-job/session ML-DSA key
- fixed-size padding cells
- batch送信
- minimum response delay bucket
- ingress/egress relay分離
- providerからrequester IPを隠す
- public leaf登録時刻を個別応答時刻からずらす
- 1 leafを複数匿名jobのmicrobatch rootにする

### 19.3 commitment salt

prompt/output commitmentはjob secret由来のsaltを必須にする。unsalted prompt hashを公開しない。既知質問辞書からの総当たりを防ぐ。

### 19.4 k=2による要件変更

旧要件の「その計算者以外は内容を知らない」は、k=2と論理的に両立しない。v0.2の正確な表現は次である。

> 質問と回答の内容を知るのはrequesterと、DNSにより匿名に割り当てられた2つの計算providerだけである。公開chain、validator、block assembler、その他providerには秘匿する。

この変更をUI、whitepaper、API disclosureに明記する。

### 19.5 traffic analysis

paddingだけでグローバル受動盗聴者を防げるとは書かない。relay非結託、cover traffic、batchingを運用要件とする。provider response timeとleaf registration timeの相関を測るprivacy benchmarkをtestnet acceptance criteriaへ入れる。

---

## 20. TEEの位置づけ

### 20.1 v0.2では必須でない

Replica laneのvalidity条件にNVIDIA/TDX/SNP attestationを含めない。vendor PKIがECDSA/RSAであっても、コンセンサスのPQ rootを汚染しない。

### 20.2 将来のoptional用途

`PalwProofType` に次を予約する。

```rust
pub enum PalwProofType {
    ReplicaExactV1 = 1,
    TeeRateLimitedV1 = 2,
    TransparentArgumentV1 = 3,
    WitnessHidingArgumentV1 = 4,
}
```

TEEは将来、次だけに利用できる。

- provider registration rate limit
- private auditの高速化
- real-job trace openingをenclave内だけで照合
- replica pairの片側が一時不足した際の低weight補助lane

TEE-only leafへfull compute weightを与えない。NRAS/OCSP/RIM unavailable、vendor key失効、GPU CC failure時はTEE機能だけを停止し、Replica laneとhash laneを継続する。

### 20.3 TEE compromise response

- vendor root compromise flagをPALW overlayで配布
- affected runtime classの新規certificate停止
- 既存Active TEE-assisted batchをrevocation fence以後無効化
- ReplicaExactV1 batchは影響を受けない
- hash lane rate/difficultyは独立

---

## 21. model/runtime registrationとLCU gaming対策

### 21.1 profile activation

model profileを追加・変更するには、on-chain manifest、reference benchmark report hash、activation DAA scoreを固定する。soft configやprovider自己申告で変えない。

### 21.2 reference benchmark

各shapeについて複数SKU、複数batch、温度/clock rangeで測る。

- canonical MAC count
- HBM bytes
- measured median/p95 runtime
- prefill/decode比率
- power/thermal sensitivity
- deterministic kernel overhead
- trace instrumentation overhead

consensus creditはoperation scheduleに基づき、最速GPUのwall-clock秒を直接creditしない。各tierの `reference GPU-seconds`（4B/9Bで別）は経済説明であり、wire fieldは固定operation quantumである。

### 21.3 shape quota

epochごとにshape別leaf上限を設ける。安いprefillだけ、短いdecodeだけ、空promptだけへ最適化することを防ぐ。quota超過leafはcertificate対象外。

### 21.4 work unit packing

各shapeのtensorを満たすため、dispatcherは複数実ジョブをmicrobatchへpackingする。dummy paddingだけで全量を埋める比率に上限を設ける。

```rust
pub struct PalwOperationCountersV1 {
    pub real_prefill_tokens: u32,
    pub padded_prefill_tokens: u32,
    pub real_decode_tokens: u32,
    pub padded_decode_tokens: u32,
    pub selected_expert_ops: u64,
    pub canonical_mac_units: u128,
    pub canonical_memory_units: u128,
}
```

このcounterは監査用であり、profile以上のquantumを自己申告できない。

### 21.5 garbage workload

内容秘匿下でsemantic utilityは判定できない。そのため、次を組み合わせる。

- requester fee floor
- job capability発行rate
- real/padded token比率監査
- canary
- shape quota
- provider reputationはconsensus workと分離

「長い無意味な文字列をQwenへ入れたから社会に役立った」という主張をコンセンサスに判定させない。

---

## 22. block templateとmining API

### 22.1 template request

現行 `build_block_template_with_evm` は単一lane前提で、`virtual_state.bits` と `required_algo_id` を直接Headerへ入れる。PALWではminer/provider coordinatorがlaneとticket candidateを指定する。

```rust
pub enum TemplateWorkRequest {
    HashFloor,
    ReplicaPalw {
        batch_id: Hash64,
        leaf_index: u32,
    },
}

pub struct PalwTemplateData {
    pub ticket: PalwTicketRef,
    pub authorization: PalwBlockAuthorizationV1,
}
```

Consensus API:

```rust
fn build_block_template_with_work(
    &self,
    miner_data: MinerData,
    selector: Box<dyn TemplateTransactionSelector>,
    build_mode: TemplateBuildMode,
    evm: EvmTemplateData,
    work: TemplateWorkRequest,
) -> Result<BlockTemplate, RuleError>;
```

### 22.2 hash template

- lane-specific hash bits
- algo 3
- PALW Header fields zero
- nonce miningを従来通り実施

### 22.3 PALW template

- Active leafをstateから再取得
- target DAA intervalが現在template intervalと一致
- ticket未使用
- compute headroomあり
- lane-specific replica bits
- canonical nonce
- PALW Header fields
- authorization payload
- provider reward class

assemblerが指定したleaf descriptorをそのまま信用せず、consensus storeからderiveする。

### 22.4 ticket candidate RPC

新RPCは秘密promptを扱わない。

- `getPalwActiveTickets`
- `getPalwTicketTemplate(batch_id, leaf_index)`
- `submitPalwBlockAuthorization`
- `getPalwLaneState`
- `getPalwBatchStatus`

RPC responseにはoutput commitment、prompt commitment、receipt detailsを含めない。

### 22.5 template cache

`VirtualStateApproxId` はeffective `blue_work` だけでなく、PALW state frontierとlane bitsをcache keyへ含める。

```rust
pub struct VirtualStateApproxId {
    daa_score: u64,
    blue_work: BlueWorkType,
    palw_state_root: Hash64,
    hash_lane_bits: u32,
    replica_lane_bits: u32,
    sink: BlockHash,
}
```

certification/expiry/nullifier更新でvirtual sinkが変わらなくてもtemplateをinvalidateする必要がある。

---

## 23. 正確なコード変更一覧

### 23.1 consensus-core

| file | 変更 |
|---|---|
| `consensus/core/src/constants.rs` | `PALW_HEADER_VERSION = 3`、activation constants |
| `consensus/core/src/pow_layer0.rs` | algo 4、mixed-lane rule、historical known rule |
| `consensus/core/src/header.rs` | component workとPALW first-class fields、constructors/builders |
| `consensus/core/src/hashing/header.rs` | v3 frozen preimage append、test vectors |
| `consensus/core/src/subnets.rs` | 0x30–0x37 PALW IDs、`is_palw_overlay()` |
| `consensus/core/src/coinbase.rs` | `WorkRewardClass`、PALW pair reward data |
| `consensus/core/src/block.rs` | `TemplateWorkRequest`/PALW template metadata |
| `consensus/core/src/config/bps.rs` | 40 BPS（`Bps<40>`）presetを使用、PALW lane docs/tests |
| `consensus/core/src/config/params.rs` | PALW activation、lane BPS、cap、epochs、bonds、new testnet genesis |
| `consensus/core/src/palw.rs` | 新規。全wire structs、domains、hash helpers、enums |
| `consensus/core/src/dns_finality.rs` | PALW beacon structs、overlay snapshot field |

### 23.2 consensus engine

| file | 変更 |
|---|---|
| `consensus/src/pipeline/header_processor/pre_ghostdag_validation.rs` | algo 3 PoWとalgo 4 header-shape verifierを分岐 |
| `pre_pow_validation.rs` | lane DAA、batch/leaf/cert/beacon/chain commit validation |
| `post_pow_validation.rs` | component workとHeader 3値の照合 |
| `consensus/src/processes/window.rs` | lane-aware DAA window |
| `consensus/src/processes/difficulty.rs` | lane target time、independent samples |
| `consensus/src/processes/ghostdag/protocol.rs` | nullifier-aware coloring、component work、cap |
| `consensus/src/model/stores/ghostdag.rs` | component fieldsとaccessors |
| `consensus/src/model/stores/headers.rs` | compact headerへalgo/nullifier/component fields |
| `consensus/src/model/stores/palw.rs` | 新規PALW state stores |
| `consensus/src/processes/palw/mod.rs` | state transition coordinator |
| `consensus/src/processes/palw/validation.rs` | payload/state validation |
| `consensus/src/processes/palw/beacon.rs` | commit/reveal/fallback/degraded |
| `consensus/src/processes/palw/audit.rs` | certificate/revocation/slashing |
| `consensus/src/processes/palw/work.rs` | eligibility、slot、chain commit、component work |
| `consensus/src/processes/coinbase.rs` | provider pair outputs、red/duplicate rule |
| `consensus/src/processes/pruning_proof/*` | PALW epoch proof bundleとhistoric validation |
| `consensus/src/pipeline/virtual_processor/processor.rs` | lane-aware template construction、overlay snapshot |

### 23.3 protocol/RPC/mining

| file/area | 変更 |
|---|---|
| `protocol/p2p/proto/p2p.proto` | Header v3 fields、PALW proof/batch request messages |
| `protocol/p2p/src/convert/header.rs` | encode/decode、zero pre-v3 guards |
| `protocol/flows` | batch/cert/pruning proof fetch flow |
| RPC model/converters | component work、PALW refs、lane state APIs |
| `mining/src/block_template/*` | `TemplateWorkRequest`、cache invalidation |
| stratum/miner API | algo 3 nonce workとalgo 4 ticket templateを分離 |

### 23.4 MIL

| file | 変更 |
|---|---|
| `mil/core/src/job.rs` | `PalwJobSpecV1`、shape、job-set commitment |
| `mil/core/src/model.rs` | `PalwRuntimeProfileV1`、shape table |
| `mil/core/src/palw/receipt.rs` | pair execution receipts |
| `mil/core/src/palw/trace.rs` | canonical operation/trace domains |
| `mil/core/src/palw/batch.rs` | candidate leaf、manifest、match logic |
| `mil/core/src/canary.rs` | large secret/generative canaries |
| `mil/provider/src/backend.rs` | `VerifiableInferenceBackend` |
| `mil/provider/src/palw/runtime.rs` | vLLM/CUDA instrumentation adapter |
| `mil/provider/src/palw/replica.rs` | receipt signing/matching client |
| `mil/provider/src/palw/batcher.rs` | fixed-shape microbatch packing |
| `mil/provider/src/anon.rs` | k=2 dispatch path、padding、ephemeral keys |
| `mil/attest/*` | optional TEE rate-limit flagのみ、consensus authority禁止 |

---

## 24. Rustデータ構造スケルトン

### 24.1 provider receipt

```rust
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ReplicaExecutionReceiptV1 {
    pub version: u16,
    pub provider_bond: TransactionOutpoint,
    pub session_public_key: Vec<u8>,
    pub job_nullifier: Hash64,
    pub job_set_commitment: Hash64,
    pub model_profile_id: Hash64,
    pub runtime_class_id: Hash64,
    pub shape_id: u16,
    pub quantum_count: u16,
    pub output_commitment: Hash64,
    pub canonical_gemm_trace_root: Hash64,
    pub operation_schedule_commitment: Hash64,
    pub receipt_da_root: Hash64,
    pub completed_at_epoch: u64,
    pub signature: Vec<u8>,
}
```

署名domain:

```text
"misaka-palw-replica-receipt-v1"
```

### 24.2 private match record

```rust
pub struct ReplicaMatchRecordV1 {
    pub receipt_a_hash: Hash64,
    pub receipt_b_hash: Hash64,
    pub job_nullifier: Hash64,
    pub output_commitment: Hash64,
    pub canonical_gemm_trace_root: Hash64,
    pub operation_schedule_commitment: Hash64,
    pub matched_at_epoch: u64,
}
```

このrecord本文はreceipt DAへ置き、public leafはcommitmentだけを持つ。

### 24.3 provider bond

```rust
pub struct PalwProviderBondPayloadV1 {
    pub version: u16,
    pub owner_public_key: Vec<u8>, // ML-DSA
    pub operator_group_id: Hash64,
    pub runtime_classes: Vec<Hash64>,
    pub capacity_by_shape: Vec<(u16, u32)>,
    pub reward_key_root: Hash64,
    pub amount_sompi: u64,
    pub unbond_delay_epochs: u64,
}
```

`operator_group_id` の自己申告だけではSybilを防げないため、bond額、network telemetry、slashing evidence、pair selection diversityを組み合わせる。

### 24.4 batch certificate vote

```rust
pub struct PalwAuditorVoteV1 {
    pub bond_outpoint: TransactionOutpoint,
    pub vote: u8, // pass/reject
    pub checked_leaf_bitmap_root: Hash64,
    pub signature: Vec<u8>, // covers signing_hash(...) 以下、自身は除外
}

// I-14 / R2: 監査人が署名する message。beacon が選んだ audit_sample_root を含めることで、
// 「取得せず certify」を構造的に閉じる（PALW_AUDITOR_VOTE_DOMAIN = "misaka-palw-auditor-vote-v1"）。
impl PalwAuditorVoteV1 {
    pub fn signing_hash(
        &self, network_id: u32, batch_id: &Hash64,
        audit_beacon_epoch: u64, audit_sample_root: &Hash64,
    ) -> Hash64 { /* network_id, batch_id, audit_beacon_epoch, audit_sample_root,
                     bond_outpoint, vote, checked_leaf_bitmap_root を domain-keyed hash */ }
}
```

同一batchへの二重voteはDNS slashing evidenceにする。

### 24.5 consensus params

```rust
pub struct PalwParams {
    pub activation_daa_score: u64,
    pub total_bps: u64,
    pub hash_lane_bps: u64,
    pub replica_lane_bps: u64,
    pub compute_to_hash_cap: u64,

    pub epoch_length_daa: u64,
    pub registration_lead_epochs: u64,
    pub audit_window_epochs: u64,
    pub active_window_epochs: u64,
    pub nullifier_retention_daa: u64,
    pub evidence_window_epochs: u64,

    pub max_batch_leaves: u32,
    pub max_leaf_chunk_leaves: u16,
    pub min_leaf_bond_sompi: u64,
    pub canary_sample_bps: u16,
    pub min_canaries_per_batch: u16,

    pub auditor_count: u16,
    pub auditor_quorum_num: u16,
    pub auditor_quorum_den: u16,

    pub dns_degraded_grace_epochs: u64,
    pub supported_profiles: Vec<Hash64>,

    // R4 (§24.6) mismatch attribution。inert = {0, 0}。
    pub mismatch: PalwMismatchParams,
}
```

### 24.6 mismatch attribution（R4、anti-griefing、2026-07-16）

k=2 の非一致（mismatch）は、それ自体が**グリーフィング経路**である: 悪意の provider が正直な相方と組み、故意に誤出力を出せば*どちらも* credit されず、相方の実 GPU work を無コストで焼ける。v0.1 の「不一致→credit なし」は被害者を攻撃者と同罰にする。R4 は非一致を**帰責可能**にする。

```rust
pub struct PalwMismatchRecordV1 {
    pub batch_id: Hash64,
    pub leaf_index: u32,
    pub provider_a: TransactionOutpoint,
    pub provider_b: TransactionOutpoint,
    pub output_a: Hash64,   // ≠ output_b が mismatch そのもの
    pub output_b: Hash64,
}
pub enum PalwMismatchVerdict { SlashA, SlashB, SlashBoth, NotAMismatch }
pub struct PalwMismatchParams { pub escalation_rate_ppm: u32, pub repeat_offender_threshold: u32 }
```

- **escalation（reference re-run への昇格）**: (a) audit beacon 由来の決定的抽選 `H("misaka-palw-mismatch-escalate-v1" || audit_beacon_seed || batch_id || leaf_index) mod 1e6 < escalation_rate_ppm`、または (b) いずれかの bond が `repeat_offender_threshold` 以上の過去 mismatch を持つ（per-provider カウンタは off-protocol tracker）。
- **attribution**: reference runtime の権威出力に対し、committed output が**乖離**した側を slash（`SlashA`/`SlashB`、どちらも一致しなければ `SlashBoth`）。`output_a ≠ output_b` より reference に一致し得るのは最大 1 者なので、**正直な相方は決して slash されない** → グリーフは攻撃者にとって純損の手になる。
- 抽選・verdict・slash target 集合は **pure**。re-run と counter は consensus が検証するだけの off-protocol 入力。`PalwMismatchParams` は inert（`0, 0` → 何も escalate しない）で、re-genesis 時に R3 と同じ EV 規律（故意 mismatch の期待値が負になる escalation rate）で較正。

実装: `consensus/core/src/palw.rs` `PalwMismatchRecordV1`/`PalwMismatchVerdict`/`PalwMismatchParams`（`escalation_draw`/`is_escalated`/`attribute`/`slash_targets`）、pure・inert（コミット `34fe771`）。

---

## 25. エラー設計

`RuleError` に少なくとも次を追加する。

```text
UnknownPalwProofType
PalwHeaderFieldsNonZeroOnHashLane
PalwHeaderVersionTooLow
PalwBatchMissing
PalwBatchIncomplete
PalwBatchNotCertified
PalwBatchRevoked
PalwCertificateMissing
PalwCertificateInvalid
PalwLeafMissing
PalwLeafHashMismatch
PalwTicketNotActive
PalwTicketExpired
PalwTargetIntervalMismatch
PalwChainCommitMismatch
PalwBeaconUnavailable
PalwBeaconDegraded
PalwUnexpectedDifficulty
PalwEligibilityAboveTarget
PalwCanonicalNonceMismatch
PalwAuthorizationMissing
PalwAuthorizationInvalid
PalwTicketAuthorityMismatch
PalwTicketAlreadyInPast
PalwDuplicateTicketInMergeset
PalwComputeCapExhausted
PalwProviderPairNotDistinct
PalwProviderBondInactive
PalwShapeQuotaExceeded
PalwLeafBondInsufficient
PalwDataUnavailable
PalwCoinbaseSplitMismatch
PalwComponentWorkMismatch
```

missing stateとinvalid stateを区別する。P2P取得中のdependency missを即ban対象にしない一方、lead window違反やhash mismatchはterminal invalidとする。

---

## 26. testnet初期parameter

以下は開始値であり、ベンチマーク後に専用hard forkで変更する。

**10 BPS PALW genesis(`testnet-palw-10`、2026-07-14 決定)**。DAA単位のwindowは実時間維持で40 BPS値の1/4、epoch単位はそのまま。

| parameter | 初期値 | 根拠 |
|---|---:|---|
| total BPS | 10 | 100ms、専用PALW genesis |
| hash lane | 2 BPS | 20% permanent block-rate floor |
| replica lane | 8 BPS | compute主lane |
| compute/hash cap | 4 | effective workの20%をhashへ拘束 |
| GHOSTDAG K | ≈124 | 10 BPS（Bps<10>） preset |
| max parents | 16 | preset |
| mergeset limit | 248 | preset |
| PALW epoch | 100 DAA | 約10秒（10 BPS） |
| registration lead | 2 epochs | 約20秒 |
| audit window | 6 epochs | 約60秒 |
| certificate lead | 1 epoch | 約10秒 |
| ticket active window | 6 epochs | 約60秒 |
| nullifier retention | 1,200 DAA | 約120秒、testnet余裕込み |
| max leaves/batch | 256 | 監査・DAの上限 |
| leaves/chunk | 64 | payload size制御 |
| reference quantum | tier毎（4B/9B、benchmark由来） | 実wireは固定operation schedule |
| replica k | 2 | TEE不要lane |
| canary sample | 1% | 最低1/batch |
| auditor count | 16 | testnet帯域との妥協 |
| auditor quorum | 2/3 weight | DNS certificate |
| DNS degraded grace | 1 epoch | 以後algo 4停止 |
| cached header p99 | <5ms目標 | 100ms budgetの5% |
| full block p99 | <20ms目標 | PQ authorization込み、100ms budgetの20% |

（後段の`testnet-palw-40` Stage-B: total 40 / hash 8 / replica 32 / K=447 / mergeset 512 / epoch 400 DAA / retention 4,800 DAA。10 BPS soak + weight ladder gate通過後に昇格。）

各tierの `quantum`（4B/9Bで別）は参照SKUでの説明値であり、providerが測定した秒数を申告する方式ではない。

### 26.1 帯域上限の概算

provider GPU台数を `G`、replica数を `k=2`、1 providerあたりquantum秒を `q` とすると、最大candidate leaf rateは概ね次である。

```text
leaf_rate ≈ G / (k * q)
```

例として `G=10,000`, `q=10秒` なら約500 leaf/sである。public descriptorを256 bytesと仮定すると約128 KB/s、256 leaf batchに16 auditorのML-DSA-87 voteを付ける場合、現行repo定数のsignature 4,627 bytesからcertificateだけで約145 KB/s相当になる。transaction framing前でも合計は約273 KB/s、40 BPSでは平均約7 KB/blockである（**4B/9B tierはqが小さくleaf_rate/帯域はさらに増える** — tier毎に再測する）。descriptorが512 bytesならさらに増える。

したがってtestnetでは次を必ず測る。

- actual serialized `PalwPublicLeafV1` size
- batch certificate vote size
- block massへのPALW epoch平均負荷
- provider数増加時のregistration pressure
- full receipt DAの別帯域

上限を超える場合は、`q` を30秒以上へ増やす、batchを大きくする、auditor数を減らさずepoch certificateへ票をまとめる、registration fee/rate limitを上げる。全leaf公開要件をroot-onlyへ戻して帯域を節約してはならない。そこを削ると問題Bが元気に復活する。

---
## 27. テスト計画

### 27.1 deterministic runtime

必須test matrix:

- 同一prompt、同一profile、異なるbatch orderingでtoken IDs完全一致
- 同一prompt、同一profile、batch size変更で完全一致
- 同一GPU arch class内の複数SKUでtrace root完全一致
- process restart後に完全一致
- tensor parallel worker順序変更で完全一致
- MoE expert tie時のcanonical tie-break
- padding量変更がjob-set commitmentとmask規則に従う
- speculative decodingが有効ならstartup fail
- runtime image/kernel graph mismatchでreceipt reject

異なるarch class間のexact matchが崩れる場合、その組合せは同一Replica classとして登録しない。

### 27.2 hidden-leaf attack

- manifest 256 leaf宣言、255 chunkだけ掲載
- root内へ未公開leafを含める
- beacon後にleaf count変更
- duplicate leaf index
- 同じjob nullifierを別batchへ再登録
- public descriptorとleaf hash不一致

すべてActive化前にrejectする。

### 27.3 pair/collusion

- 同一bondのA/B
- 異なるbondだが同じoperator group
- 片側receipt欠落
- outputだけ一致、trace不一致
- traceだけ一致、output不一致
- shape/quantum mismatch
- provider signature差替え
- dispatcherが同じproviderへ二重配送

### 27.4 beacon

- commitなしreveal
- reveal preimage mismatch
- duplicate reveal
- last revealer withholding
- quorum不足
- DNS degraded transition
- fallback seed determinism
- epoch boundary reorg
- future epoch replay

### 27.5 fork/nullifier

- 同じticketを兄弟blockで使用
- 同じticketをprivate forkで使用
- 同じauthorityによる二重header署名
- selected-parent pastで再使用
- mergeset内duplicateのcanonical first selection
- expiry直前/直後
- pruning pointをまたぐevidence
- duplicate red化でblue anticone sizeが一致

### 27.6 work cap

property tests:

```text
C_effective <= 4H
E = H + C_effective
H <= E <= 5H
E is monotonic for valid credited blocks
no algo4 block is valid when remaining compute headroom == 0
```

big-int overflow、compact target境界、zero genesis work、maximum bitsをfuzzする。

### 27.7 DAA

- hash供給のみ
- compute供給のみ
- hash 8 BPS / compute 32 BPS定常
- lane急停止
- ticket flooding
- duplicate PALW block flooding
- timestamp skew
- reorgでlane samplesが変化
- sample不足fallback

### 27.8 coinbase

- algo3 62/8/30
- algo4 38.5/38.5/8/15（レーン非対称、validator半減）
- odd subsidy端数
- red PALWにprovider outputがない
- duplicate PALWにprovider outputがない
- source blockとcurrent includerのscript混同がない
- finality fee splitとの共存
- pruning/IBD後も同じexpected coinbase

### 27.9 data availability

- certificateはあるがleaf chunk欠落
- leafはあるがmanifest欠落
- pruning bundleにhistoric cert欠落
- certificate cacheを全削除してIBD
- P2P peerが偽chunkを返す
- max payload boundary
- erasure-coded receipt DA unavailable

### 27.10 privacy

- response timingとleaf registration timingの相関
- packet size分類
- microbatch人数推定
- provider reward script再利用
- requester funding addressとjob nullifierのlinkability
- canary識別率
- relay 1者/2者結託時のmetadata漏洩

### 27.11 performance

専用benchmark binaryを追加する。

```text
bench_palw_header_cached
bench_palw_header_cold_leaf_store
bench_palw_certificate_activation
bench_palw_mldsa_authorization
bench_palw_ghostdag_dedup_248
bench_palw_nullifier_window_4800
bench_palw_pruning_bundle
bench_palw_coinbase_pair_split
```

40 BPS acceptance gate:

- cached PALW header p99 < 5ms
- full PALW block p99 < 20ms
- 248 mergeset dedup p99 < 20ms
- no unbounded allocation from remote payload
- IBD throughputがalgo3-only baselineの50%未満へ落ちない
- 24時間stress testでvirtual processor backlogが増加し続けない

---

## 28. 実装フェーズ

### Phase 0: ADRとnetwork fence

- PALW用ADR作成
- consensusを「Proof of Audited Compute + hash floor」と明記
- 40 BPS（8+32）専用testnet ID/genesis
- Header v3/store version予約
- algo 3永久維持を仕様化

**完了条件:** genesis、params、protocol versionが既存networkと混ざらない。

### Phase 1: off-chain k=2 deterministic prototype

- `MISAKA-QW4-PALW-v1` / `MISAKA-QW9-PALW-v1` manifest（2 tier）
- 固定shape 1つ
- `VerifiableInferenceBackend`
- output/trace exact match
- pair receipt ML-DSA
- batch-invariant runtime tests

DAG weightは0。まず本当に2台で一致するかを測る。設計書の中ではGPUはいつも従順だが、実機は文書を読まない。

### Phase 2: PALW overlayと公開leaf

- 0x30–0x37 subnetwork
- provider bond
- manifest/chunks
- leaf bond
- batch state machine
- all-leaf publication
- no block work credit

### Phase 3: DNS PALW beaconとcanary

- commit/reveal
- auditor selection
- large canary corpus
- batch certificate
- slashing/revocation
- degraded mode

### Phase 4: Header v3とalgo 4 validation、weight 0

- header fields/P2P/RPC/store
- ticket slot/eligibility
- authorization
- block accepted as experimental lane but `ΔC=0`
- validation latency計測

### Phase 5: component GHOSTDAG work

- `blue_hash_work` / `blue_compute_work`
- nullifier window
- deterministic dedup
- compute cap
- lane DAA
- pruning proof extension

最初のcredit factorは低くする。例: theoretical `ΔC` の1/16から開始し、testnet hard forkで段階的に上げる。

### Phase 6: coinbase

- algo4 provider 38.5/38.5（base 77%）
- inclusion 8, validator 15（レーン非対称）
- red/duplicate no provider subsidy
- service fee settlement

### Phase 7: adversarial testnet

- TEE全停止
- DNS degraded
- 50% malicious provider
- hidden leaf flood
- private fork/ticket reuse
- DA withholding
- LCU gaming
- traffic analysis

### Phase 8: activation ladder

```text
Stage A: algo4 accepted, compute weight 0%
Stage B: compute cap 25% of effective work
Stage C: compute cap 50%
Stage D: compute cap 80% maximum
```

各stageは別activation fenceとmetrics gateを持つ。mainnetで一気に80%へ飛ばさない。

---

## 29. 問題A〜Eへの対応表

### 問題A: TEE単根とPQ衝突

**対応:**

- TEEをalgo 4のvalidity rootから除外
- k=2 ReplicaExactV1を主laneにする
- vendor ECDSA/RSA chainはoptional metadata
- algo3を8 BPSで永久維持
- effective workを `H + min(C, 4H)` に制限
- TEE outage/revocationでReplica/Hash laneを止めない

**残余リスク:** PALW証明・DNS certificateが全面破綻すると、攻撃者は自身のhash workを最大5倍へ増幅できる。hash floorは破綻を無害化せず、catastrophic unlimited mintをbounded amplificationへ変える。

### 問題B: hidden leaf grinding

**対応:**

- 全leaf hashとdescriptorをbeacon前にオンチェーン掲載
- manifestのleaf count/chunk count固定
- leafごとにbond
- audit beaconは登録後
- batch certificate前にDA確認
- missing chunkはActive不可
- blockはtx/stateの `(batch_id, leaf_index)` を参照しMerkle path不要

### 問題C: beacon grinding、fork再利用

**対応:**

- PALW専用DNS PQ commit-reveal beacon
- chain-derived randomnessをcurrent minerが選べない
- target intervalを1つに固定
- `chain_commit` はlagged DNS-finalized checkpointから導出
- nonce固定
- header first-class nullifier
- ticket authorityのML-DSA block authorization
- 二重header署名をslash
- expiryを短くし、bond unlockを長くする
- shallow fork merge時はdeterministic dedup

**重要な補正:** `chain_commit` を「現在掘りたいforkのtip」から作ると、それ自体が再抽選nonceになる。本設計ではtarget slotより前に確定したcheckpointから作る。

### 問題D: work内在性とGHOSTDAG

**対応:**

- nullifierをHeader v3へ入れる
- Headerにcomponent cumulative workを入れる
- active nullifier setはheader DAGから再構成可能
- mergeset consensus orderでduplicateをredへ落とす
- selected-parent past duplicateはinvalid
- compact GHOSTDAG/store/pruning proofをcomponent-awareへ更新
- `blue_work` はeffective workとして既存ordering APIを維持

### 問題E: certificate DA

**対応:**

- manifest、全leaf chunks、certificateをPALW subnetwork txとしてchainへ置く
- N-blockではなくepoch単位のregistration lead
- cache missはP2Pでオンチェーンobjectを取得
- pruning proofへhistoric PALW bundle
- OverlaySnapshotへactive state frontier
- receipt本文は通常block validityに不要だが、DA rootとaudit取得をcertificate条件にする

---

## 30. 中程度の問題への対応

### 30.1 LCU gaming

- 任意token countをworkへしない
- fixed shape/menu
- reference operation table
- shape quota
- real/padded比率
- provider wall-clock申告を不採用
- cheapest shapeだけのbatchをcertificateしない

### 30.2 非決定性

- 同一runtime classだけexact pair
- batch-invariant kernel必須
- deterministic reduction/greedy/MoE tie-break
- GPU arch classをruntime IDへ含める
- cross-class比較はTopLoc型audit-only
- speculative decoding禁止

### 30.3 監査とprivacy

- 実ジョブactivationを公開しない
- real jobはk=2 exact matchが主検証
- full openingはcanaryだけ
- private k=3/TEE auditはrequester opt-in
- prompt/output commitmentにsecret salt

### 30.4 NVIDIA単一障害点

- Replica laneはNVIDIA attestationを不要にする
- NVIDIA/NRAS停止はTEE補助機能だけ停止
- hash laneとDNS PQ certificateは継続
- GPU vendorをruntime classとして追加可能

---

## 31. Whitepaper/DNS論文の修正点

PALWを導入したchainを単純なPoWと記述し続けない。次を明示する。

1. fork choice workはhash workとaudited compute workの合成である。
2. compute ticketの発行安全性は、k=2独立性、DNS beacon/certificate、bond、canaryに依存する。
3. DNSはfinalityだけでなく、provider割当、audit sampling、ticket activation randomnessを提供する。
4. compute側が破綻した際の安全性は `compute_to_hash_cap` でbounded degradationする。
5. hash laneはliveness/safety floorとして恒久的に存在する。
6. λ、D_max、Kの議論はtotal 40 BPSとlane停止時8 BPSの両modeについて再評価する。
7. ticketは蓄積可能なwork inventoryであり、hash PoWと異なるnothing-at-stake面を持つ。fork binding、authorization、slashing、expiryで処理する。
8. 監査は確率的・経済的であり、SNARK soundnessではない。

呼称は次が正確である。

> MISAKA Double Nakamoto Security with Proof of Audited Compute and a Permanent Hash-Work Floor

---

## 32. mainnetへ進めない停止条件

次のいずれかが満たせない場合、algo 4のDAG weightを0から上げない。

- 同一runtime classで10万work unit中、非攻撃条件のexact output/trace mismatch率が規定以下
- malicious provider 30%以上のsimulationでfraud期待値が負
- hidden-leaf/fork-reuse/DA withholdingテストを通過
- cached full validation p99が25ms block-interval budgetを圧迫しない
- pruning proofをcacheなしで再現可能
- DNS degraded時にalgo3-onlyへ安全に縮退
- provider selectionのpair concentrationが上限以下
- canary識別率が統計的に許容範囲
- traffic analysisでrequester-provider linkabilityが運用目標以下
- coinbase issuance、red/duplicate処理、component workがproperty testで一致
- TEEコードを完全disableしたbuildでもReplica laneが動作

---

## 33. 最初に実装する最小vertical slice

最初のPR群は次の順に小さく切る。

1. `mil/core`: runtime/shape/receipt/trace structsとhash test vectors
2. `mil/provider`: mock deterministic k=2 backendとexact matcher
3. `consensus/core`: PALW payload structs、subnetwork IDs、params
4. `consensus`: manifest/leaf stores、state machine、weight 0
5. DNS PALW beaconとcanary certificate
6. Header v3 fields、P2P/RPC roundtrip、algo4 weight 0 verifier
7. lane DAAとcomponent GHOSTDAG work
8. coinbase pair split
9. pruning/IBD bundle
10. Qwen GPU runtime adapter

最初のGPU PRより前にwire formatとtest vectorsを固定する。CUDAを書き終えてから「Header fieldが足りない」と気付くのは、非常に人間らしいが避けられる。

---

## 34. 参考資料

本設計は以下を実装上の参考とする。ただし各方式をそのままコンセンサスproofとして採用するものではない。

1. **TopLoc: A Locality Sensitive Hashing Scheme for Trustless Verifiable Inference**  
   https://arxiv.org/abs/2501.16007  
   decodeとteacher-forced prefillの非対称性、hidden-state sketch、GPU差への許容帯。PALWではcanary監査とcross-class auditの参考に限定する。

2. **vLLM Batch Invariance**  
   https://docs.vllm.ai/en/latest/features/batch_invariance/  
   batch size/orderから独立した決定論的実行の実装参考。beta機能をそのまま追従せず、runtime imageとkernel graphをpinする。

3. **NVIDIA Attestation Documentation**  
   https://docs.nvidia.com/attestation/index.html  
   GPU attestation、RIM/OCSP/NRASの可用性・vendor依存を評価する。v0.2ではコンセンサスrootにしない。

4. **Qwen3.5-4B official model card** — PALW Standard tier  
   https://huggingface.co/Qwen/Qwen3.5-4B  
   RAM≥8GB / Q4、VPS・ノード同居・広い参加層向け。コンセンサスはモデル名でなくexact manifest hashをpinする。

5. **Qwen3.5-9B official model card** — PALW Quality tier  
   https://huggingface.co/Qwen/Qwen3.5-9B  
   RAM≥16GB / Q4、標準的な有用推論向け。`MISAKA-QW4/QW9-PALW-v1` はプロジェクト固定フォーク名とし、曖昧な通称をwire identityに使わない。

---

## 35. 最終仕様

v0.2で採用する決定は次である。

```text
Consensus rate       : 40 BPS
Hash lane            : algo 3, target 8 BPS, permanent
Open GPU lane        : algo 4, target 32 BPS, k=2 exact replica
Model identity       : 2 tiers - Standard(Qwen3.5-4B Q4,>=8GB) + Quality(Qwen3.5-9B Q4,>=16GB), exact manifest hash per tier
Heavy work           : deterministic Qwen GEMM/attention/MoE operation schedule
Work evidence        : output commitment + canonical GEMM trace root
Proof timing         : asynchronous batch certification
Block verification   : on-chain state lookup + nullifier + lane DAA + one-shot hash
Leaf publication     : all leaves/descriptors on chain before beacon
Audit                : beacon-selected canary, full opening only for canary
Security root        : hash floor + PQ DNS certificate + bonds + replication
TEE                   : optional accelerator/rate limiter only
Fork binding         : fixed target slot + consensus-derived lagged chain commit
Double use           : first-class header nullifier + ML-DSA authorization + slashing
GHOSTDAG work        : H + min(C, 4H)
Coinbase algo 4      : provider A 38.5%, provider B 38.5%, inclusion 8%, validators 15%（hash lane=62/8/30）
Data availability    : manifest, leaves, certificate on chain; pruning bundle required
```

この構成では、LLMの実GEMMがGPU資源を消費する採掘作業となる一方、block acceptance pathはQwen再実行から切り離される。SHA3のような検証非対称性をLLM単体へ魔法のfine-tuningで生やすのではなく、**計算を先に行い、複製・監査・bond・DNS certificateで非同期に資格化し、DAGではその資格の一回使用だけを高速検証する**。

それが、秘密質問、consumer GPU、PQ方針、40 BPS、GHOSTDAGを同時に壊さず成立させる実装可能な境界である。
