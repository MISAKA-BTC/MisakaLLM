# ADR-0033: EVM Shielded Pool — Porting Source Selection

## Status
**Proposed — 2026-07-09. Nothing is implemented.** This ADR selects the *source of truth*
for the EVM-lane shielded pool (private transfers with Zcash-level privacy: sender, receiver,
amount, and token type hidden). It is the code-grounded freeze of the porting-source decision in
[`docs/misaka-evm-shielded-pool-design-v0.2.md`](../misaka-evm-shielded-pool-design-v0.2.md);
every "§N" below points to a section of that document.

> **Code-grounding corrections (2026-07-09).** The initial draft was reconciled against the current
> `consensus/core/src/evm/mod.rs` / `kaspa-evm` tree (feat/mil-v0 line). Four factual fixes were
> applied and carry through this ADR and the design doc:
> 1. **ADR number 0024 → 0033.** `0024` is already taken by
>    [ADR-0024](0024-mil-gpu-attestation-computedepth.md) (MIL GPU attestation); `0032` is the Cancun
>    spec ADR. `0033` is the next free number.
> 2. **Shielded verifier precompile `F004` → `F006`.** `F004` (`HASH64`, keyed BLAKE2b-512) and
>    `F005` (`DNS_FINALITY`) are **already reserved** by the MIL/PREA precompile set and share the
>    F003 activation fence. `F006` is the next free slot (`F006`–`F010` are all unused); the pool
>    contract keeps `F010`. All `F004`/`F004_VERIFY_GAS`/`evm_f004_…` references were renamed to
>    `F006`/`F006_VERIFY_GAS`/`evm_f006_…`.
> 3. **`MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK` = 32 KiB, not 128 KiB.** The actual constant is
>    `32 * 1024`. This makes the §SP-0 hard precondition **≈4× tighter**: a 100–300 KB proof exceeds
>    the cap by ~3–10×, so a hand-written circuit or recursion compression is even more load-bearing.
> 4. **`EVM_GAS_LIMIT` = 7,500,000, not 30M** (`MAX_EVM_ACCEPTED_GAS_PER_CHAIN_BLOCK = EVM_GAS_LIMIT`).
>    This lowers `MAX_SHIELDED_VERIFY_PER_EVM_BLOCK` accordingly and reinforces that `F006_VERIFY_GAS`
>    (a multi-M-gas STARK verify) admits only a handful of shielded txs per chain block.
>
> `EVM_CHAIN_ID = 0x4D_53_4B` and `EVM_NATIVE_SCALE = 10^10` were confirmed correct. Note (§13):
> these constants live on the feat/mil-v0 line; `F004`/`F005` do **not** exist on `main` yet, so a
> shielded-pool activation must target a branch where the MIL precompile set has landed (or the
> reservation must be re-checked at that time).

**Relationship to existing ADRs.** This ADR does **not** relax the PQ-only stance of
[ADR-0019](0019-mldsa87-migration.md): that stance governs the **UTXO lane**. Per the README scope
note, the PQ claims cover UTXO tx authorization (ML-DSA-87), not the EVM lane, which is permitted to
use secp256k1 ([ADR-0020](0020-selected-parent-evm-lane.md) §20). The shielded pool lives on **Lane 2**
(the current ETH-compatible EVM, ADR-0020) and adds **no new signature scheme** — it adds one
verifier precompile. It inherits the proof-system policy of the three-lane design
([ADR-0023](0023-base-three-lane-execution.md) §8.12), the cross-lane native-token conservation rule
(§10.3, invariant I-13), and the asset-gate discipline (§10.5). The verifier precompile is registered
through the **same activation-fenced call-frame interception seam** as F003 (`MLDSA87_VERIFY`,
`kaspa-evm/src/mldsa_verify.rs` + `kaspa-evm/src/precompiles.rs`).

> **Hard precondition (§13 Phase SP-0 — non-negotiable gate).** A single STARK proof must fit under
> `MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK` = 32 KiB (`consensus/core/src/evm/mod.rs`). Today a succinct
> zkVM proof is 100–300 KB and can exceed that cap *by itself*. No shielded-pool activation may occur
> on any network until a single proof provably fits the DAG-block payload cap (via a hand-written
> circuit or recursion compression) **and** the F006 portable verifier is confirmed bit-identical on a
> low-end no-SIMD reference image. Until then F006 / `ShieldedPool` stay at `u64::MAX` (inert, empty-
> account behaviour, genesis/state-root unchanged — identical to F003 below its fence).

## Context

We want private transfers on the EVM lane with the same privacy surface as Zcash Sapling/Orchard:
hide **sender, receiver, amount, and token type** within an anonymity set. Three concrete artifacts
exist to port *from*, and the information-theoretic floor for this privacy surface is fixed
(§1.3): **commitment + nullifier + membership proof**. The only real decision is which battle-tested
implementation of that floor to re-implement, and which cryptographic primitives to swap in.

Two hard constraints shape the choice:

1. **Soundness must be post-quantum.** A forged proof lets an attacker withdraw from the pool = an
   undetectable inflation of MSK supply (violates I-13 / SP-01). If soundness rests on a discrete-log
   or pairing assumption, a quantum computer breaks it. This is the *only* property that cannot be
   fixed by migrating keys later — a forged withdrawal is permanent supply damage.

2. **Note-encryption confidentiality must be post-quantum.** Note encryption over ECDH is broken by
   harvest-now-decrypt-later: an adversary records shielded chain data now and decrypts every past
   shielded transaction once a quantum computer exists. Account keys can migrate before Q-day, but
   **past confidentiality cannot** — it is retroactively stripped.

Note the asymmetry with the UTXO lane: the EVM lane *may* use ECC for **transaction authorization**
(a live key can migrate off secp256k1 before Q-day). But shielded-pool **soundness** and **past
confidentiality** are not migratable, so they must be PQ from day one even though the surrounding lane
is not. This makes the shielded pool the one full-PQ island inside an EC-permissive lane — which is
also its differentiator (§0-2): existing privacy chains (Zcash, Starknet STRK20, Railgun) all carry
one or both of these quantum vulnerabilities.

### The three candidate sources

**Candidate 1 — Railgun-family (Ethereum EVM, Groth16 shielded pool).**
Audited Solidity shielded-pool contracts that run on any EVM with the standard BN254 precompiles
(0x06–0x08). If the EVM lane exposes those (it is `revm`-backed, ADR-0020), the contracts deploy with
near-zero modification and proofs verify in ~200 B / tens-of-thousands of gas.

**Candidate 2 — Starknet STRK20 (StarkWare, live on mainnet 2026-06-09).**
A protocol-level framework hiding sender, receiver, token type, and amount by default — exactly the
target surface. First asset was strkBTC (shielded wrapped BTC, 2026-05). Its core (per the
OpenZeppelin audit of `starkware-libs/starknet-privacy`) is a UTXO-based Starknet Privacy Pool: notes
with encrypted amounts, nullifiers derived from viewing keys, deposit → private transact → withdraw
without sender-recipient linkage. Proofs are STARK-based (S-two / Circle STARK over the M31 field,
Rust, fully open-source, the production Starknet prover since 2025-11), designed for **client-side
proving**. Compliance is a scoped audit path: on joining the pool a user registers an encrypted
viewing key on-chain; on a regulatory request a designated auditor decrypts *that user's* key only.
Eli Ben-Sasson (StarkWare CEO) is a Zcash co-founder, so the design is a direct descendant of Zcash.

**Candidate 3 — PQ-Sprout (fully self-authored zkVM circuit).**
Re-implement Zcash's original Sprout 2-in/2-out JoinSplit spec (whose internals are already almost
entirely hash-based — PRFs and commitments are SHA-256; only the proof system and note encryption are
EC-dependent), swapping the proof system to a FRI-style STARK and note encryption to ML-KEM. Battle-
tested spec (Zcash protocol spec §Sprout), but the circuit and prover are built from scratch.

### Why "port as-is" is impossible for Candidates 1 and 2

- **Candidate 1 (Railgun):** deploys as-is *only if* we accept Groth16. That is exactly the soundness
  failure in constraint 1 — a quantum computer recovers the trusted-setup toxic waste via discrete log
  and forges withdrawals. Usable as a throwaway testnet stepping-stone under an escrow cap, not as the
  production source.

- **Candidate 2 (STRK20):** three binding-layer mismatches block a byte-level port. **(a) Language:**
  contracts are all Cairo (`privacy.cairo` et al.); Cairo VM bytecode does not run on the EVM — this is
  a spec re-implementation (Solidity rewrite), not a code deploy. **(b) Verification location:** STRK20
  proofs are verified at the sequencer level using the same infrastructure Starknet uses to prove its
  own blocks, and today a centralized proving service runs a Virtual SNOS off-chain that proves action
  batches. That "verification fused into the L2 OS/proof pipeline" is the most Starknet-specific part
  and has no analogue on the EVM lane; bringing it over means adding a **Circle-STARK verifier as a
  node precompile** — which converges on exactly the "STARK verifier precompile + pool contract"
  shape. **(c) Surrounding infra:** the discovery service (indexes encrypted on-chain data to fetch
  relevant notes), proving service, auditor infrastructure, and wallets are off-chain components we run
  ourselves, not port.

The consequence is that **Candidate 2 and Candidate 3 converge on the same architecture** — a STARK
verifier precompile plus a commitment/nullifier pool contract. The only difference is whether the
circuit and spec are authored from scratch (Candidate 3) or extracted from the audited, mainnet-proven
STRK20 (Candidate 2). Candidate 2 dominates Candidate 3 on trust (audited + $1.3T-cumulative-volume
prover lineage) at equal architectural cost.

## Decision

**Adopt the STRK20 design (Candidate 2) as the primary porting source, re-implemented on Lane 2**, with
three MISAKA-specific substitutions:

1. **Proof system → hash-based STARK only** in production (`proof_system_id` = STARK), verified by a new
   **F006 `SHIELDED_VERIFY` precompile** registered through the F003 seam. Skip the Virtual SNOS service
   layer entirely and prove **client-side** on the user's device (S-two targets exactly this). A pairing-
   based proof is permitted **only** on testnet under an escrow cap as a stepping-stone; it never carries
   production native-asset settlement (inherits [ADR-0023](0023-base-three-lane-execution.md) §8.12).

2. **Note encryption → X25519 + ML-KEM-1024 hybrid KEM** (both shared secrets fed through a KDF, then
   AEAD), replacing STRK20's channel-key/Poseidon note encryption path. This is a **PQ/classical hybrid
   KEM** (the TLS 1.3 `X25519MLKEM768` / Signal PQXDH shape, at Cat-5), *not* EC-alone — R-4 rejects
   standalone ECDH, and this is strictly stronger than either component. Three reasons the note-encryption
   layer is the one place we refuse a byte-level port and pay PQ from genesis:
   - **Asymmetric bet — defer the cost, avoid the irreversible harm.** The size cost is ~1–2% today and
     only bites the DA floor at v0.3+, and there are two escape hatches (note-discovery optimization O-SP-4
     and address versioning) — whereas shielded chain data recorded now under an EC-only scheme is
     *permanently* deanonymizable post-Q (harvest-now-decrypt-later, constraint 2). A bet whose downside is
     irreversible belongs on the heavy side.
   - **CNSA 2.0 pair completes at 1024.** CNSA 2.0 specifies **ML-KEM-1024 + ML-DSA-87**; MISAKA already
     runs ML-DSA-87 (ADR-0019), so 1024 (Cat 5) finishes the government-procurement-grade pair. 768 would
     leave "the one irreversible component sits at Cat 3" — the same reasoning that put Kyber-1024 in
     Signal's long-lived-message PQXDH. This ADR therefore **fixes 1024** (not an open 768-vs-1024 knob).
   - **X25519 is +32 B of insurance.** ML-KEM is a young standard; layering X25519 means an attacker must
     break *both* (classical dlog **and** ML-KEM) to strip confidentiality — cover against an ML-KEM
     implementation bug or future cryptanalysis. Since the EVM lane is EC-permissive there is no purity
     reason to drop it, and it matches the TLS/Signal industry direction. Past confidentiality is not
     migratable, so this hybrid is frozen from genesis.

3. **Compliance model → borrow STRK20's scoped viewing-key path verbatim.** The **hybrid decapsulation
   material** (the X25519 secret + the ML-KEM-1024 decapsulation key) is the incoming viewing key: hand it
   to an auditor to reveal a user's received-note amounts/memos without granting spend authority, touching
   no other user's data (SP-11).

**Placement:** Lane 2 (not Lane 3). Lane 3's proof pipeline has not reached shadow mode
([ADR-0023](0023-base-three-lane-execution.md) §18 Phase 4); depending on it would block the shielded
pool behind Lane 3's asset gate (§10.5). The shielded pool carries its own F006 verifier, so it ships
independently on Lane 2.

**Rollout is two-track:** a Railgun-type pool under an escrow cap as an early testnet stepping-stone
(fast validation, EC soundness acknowledged and cap-bounded), with the STRK20-spec + S-two-family F006 +
X25519+ML-KEM-1024 hybrid note encryption as the production target. The tagline "even with ECC in the EVM lane, the shielded pool's
withdrawal soundness is full-PQ" exists in neither STRK20 nor Railgun.

### Reserved addresses / constants (proposed, frozen at activation)

Added to `consensus/core/src/evm/mod.rs` alongside the existing **F001–F005** reserved group
(`F001` WMISAKA / `F002` WITHDRAW / `F003` MLDSA87_VERIFY / `F004` HASH64 / `F005` DNS_FINALITY —
`F004`/`F005` belong to the MIL/PREA precompile set and share the F003 fence). The shielded
verifier therefore takes the next free slot **`F006`** (not `F004`, which the original draft
proposed before this ADR was code-grounded against the current `mod.rs`); the pool contract takes
`F010` (free). See the "Code-grounding corrections" note above:

```text
MISAKA_SHIELDED_VERIFY_PRECOMPILE = 0x…F006   // pure verify, STATICCALL-reachable, non-payable
MISAKA_SHIELDED_POOL_ADDRESS      = 0x…F010   // predeploy contract (like WMISAKA=F001), NOT a precompile
F006_VERIFY_GAS                   = TBD        // O-SP-2; charged up-front, malformed flood pays same
MAX_SHIELDED_VERIFY_PER_EVM_BLOCK = EVM_GAS_LIMIT / F006_VERIFY_GAS   // gas-implied ceiling
MAX_SHIELDED_PROOF_BYTES          < MAX_EVM_PAYLOAD_BYTES_PER_DAG_BLOCK   // hard precondition
evm_f006_shielded_verify_activation_daa_score = u64::MAX   // inert on every network
```

## Rejected Options

- **R-1 — Railgun/Groth16 as production source.** Rejected for soundness: quantum recovery of the
  trusted-setup toxic waste forges withdrawals (undetectable inflation, violates SP-01). Retained only
  as a cap-bounded testnet stepping-stone.

- **R-2 — Any pairing-based proof (Groth16/PLONK/Halo2-with-pairing) in production.** Same soundness
  failure as R-1; also violates [ADR-0023](0023-base-three-lane-execution.md) §8.12 (pairing-only ⇒
  classical security ⇒ escrow-capped).

- **R-3 — Byte-level Cairo port of STRK20.** Impossible: Cairo VM bytecode does not run on `revm`
  (mismatch (a)), and STRK20's Virtual-SNOS/sequencer-fused verification has no EVM-lane analogue
  (mismatch (b)). Adopted as a *spec* source instead.

- **R-4 — *Standalone* ECDH note encryption (Zcash/STRK20-style channel keys).** Rejected for
  confidentiality: harvest-now-decrypt-later retroactively strips all past shielded transactions once a
  quantum computer exists (constraint 2). Note the scope: what is rejected is EC **alone**. The chosen
  scheme is the **X25519 + ML-KEM-1024 hybrid KEM** (Decision item 2) — the ML-KEM component supplies the
  PQ confidentiality that defeats HNDL, and X25519 is layered *on top* as +32 B insurance against an
  ML-KEM implementation bug or future cryptanalysis (breaking it needs both). Dropping X25519 (ML-KEM
  alone) is a weaker, purity-driven option not taken: since the lane is EC-permissive there is no reason
  to forgo the classical hedge, matching TLS 1.3 / Signal PQXDH.

- **R-5 — Fixed-denomination mixer (Tornado-type).** Does not meet the target surface: amounts are
  quantized and visible, failing amount privacy (§1.3). Not a commitment/nullifier pool.

- **R-6 — Confidential-amount-only (Solana CT / Sui Confidential Transfers style).** Recipient stays
  public, failing recipient privacy (§1.3).

- **R-7 — Placement on Lane 3.** Would gate the shielded pool behind Lane 3's un-shipped proof
  pipeline and asset gate ([ADR-0023](0023-base-three-lane-execution.md) §10.5 / §18). Placed on Lane 2
  with a self-contained F006 verifier instead.

- **R-8 — Hash64 (keyed BLAKE2b-512) as the in-circuit hash (§5.3 option B).** Aesthetically unifies
  with consensus identity but has no zkVM acceleration, inflating prover time several- to ten-fold and
  breaking prover UX. Deferred: the in-circuit hash is committed via `verifier_key_hash`, so it is
  switchable later under `circuit_version` (a consensus change). v0.2 uses an accelerated hash
  (SHA-256 or Poseidon/M31, §5.3 option A).

## Consequences

**Positive.**
- Soundness is PQ from genesis (SP-05): the one full-PQ island in an EC-permissive lane, and a
  differentiator no existing privacy chain has.
- Past confidentiality is PQ (SP-06): immune to harvest-now-decrypt-later, unlike Zcash/STRK20/Railgun.
- Reuses a mainnet-proven, audited design and a Rust STARK verifier crate (S-two lineage) that drops
  into the EVM lane's Rust codebase as a precompile; client-side proving skips STRK20's centralized
  Virtual-SNOS service.
- Scoped compliance (SP-11) borrowed verbatim gives investors/regulators "Zcash-level privacy +
  selective disclosure" as a package.
- Converges with the pre-existing PQ-Sprout design (Candidate 3), so no prior design work is wasted —
  STRK20 lands as the reference implementation and lowers the circuit-authoring effort.

**Negative / cost.**
- A new consensus-critical F006 precompile: a portable STARK verifier must be bit-identical across CPUs
  (SP-04) or it is a consensus split (same requirement as F003 audit H-2).
- Proof size (100–300 KB) collides with the 32 KiB DAG-block payload cap; the hard precondition (Phase
  SP-0) blocks activation until a single proof fits, forcing a hand-written circuit or recursion up
  front.
- A shielded tx costs tens of normal txs' worth of DA/CPU; mass/gas must be priced honestly high, and
  throughput is DA-bounded until recursion aggregation (§13 Phase SP-4 / v0.3).
- Note encryption at the X25519 + ML-KEM-1024 hybrid adds ~1.1 KB per output note over an EC-only scheme
  (the ML-KEM ct/ek dominate; the X25519 layer is only +32 B on top), and the full-scan note-discovery
  cost grows with the anonymity set (O-SP-4). The ~1–2% overhead is deferrable (bites the DA floor only at
  v0.3+) and has escape hatches (O-SP-4, address versioning); the confidentiality it buys is not
  recoverable after the fact, which is why the hybrid is paid from genesis.
- The self-authored hybrid note-encryption path (X25519 + ML-KEM-1024 KDF + AEAD) and the spec extraction
  from Cairo are net-new work requiring their own audit (Phase SP-3), i.e. the port is not free even
  though the design is borrowed.

**Follow-on decisions (do not belong in this ADR).**
- **Proof system: zkVM (Risc0/SP1/S-two) vs hand-written STARK (Plonky3)** — driven by whether a single
  proof can meet the 32 KiB cap (O-SP-1). Natural as its own ADR once Phase SP-0 benchmarks land.
- ~~ML-KEM category (768 vs 1024)~~ — **DECIDED, not open: ML-KEM-1024** (Decision item 2). CNSA 2.0
  specifies ML-KEM-1024 + ML-DSA-87, and the note-encryption confidentiality is the one irreversible
  component, so it is fixed at Cat 5 rather than left as a size-budget knob. (Recorded here only to close
  the question.)
- **Aggregation scheme** and whether it shares a verifier crate with Lane 3 (O-SP-8).

## References
- Design: [`docs/misaka-evm-shielded-pool-design-v0.2.md`](../misaka-evm-shielded-pool-design-v0.2.md)
- EVM lane: [ADR-0020](0020-selected-parent-evm-lane.md),
  [`docs/misaka-evm-design-v0.4.md`](../misaka-evm-design-v0.4.md),
  [`docs/evm-differences-from-ethereum.md`](../evm-differences-from-ethereum.md)
- Three-lane proof/settlement policy: [ADR-0023](0023-base-three-lane-execution.md) (§8.12, §10.3, §10.5)
- PQ scheme: [ADR-0019](0019-mldsa87-migration.md)
- DNS finality (anchor ring depth): [ADR-0009](0009-dns-probabilistic-finality.md)
- Precompile seam / verifier template: `kaspa-evm/src/precompiles.rs`,
  `kaspa-evm/src/mldsa_verify.rs`, `consensus/core/src/evm/mod.rs`
- External source (spec only, not code): StarkWare STRK20 + `starkware-libs/starknet-privacy`
  (OpenZeppelin audit), S-two / Circle STARK prover.
