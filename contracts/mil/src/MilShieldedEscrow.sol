// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilConstants, ShieldVerifyLib, MilOwned} from "./MilCommon.sol";

interface IShieldedPool {
    function depositNote(bytes calldata cm, bytes calldata encNote) external payable;
}

/// @title MilShieldedEscrow — blind-open + anonymous provider claim (ADR-0025 §21).
/// @notice The which-GPU-unlinkable settlement path that replaces v1
///         `JobEscrow.open(providerId)` + `claim(providerId, pubkey, signature)`.
///
///         - `openBlind` locks MSK for a session identified only by a commitment
///           (`sessionCm` = `cmReq`). It NEVER names a `providerId`, so the escrow
///           does not reveal which provider will serve it.
///         - `claimAnon` settles by proving — via F006 (provider-claim circuit) —
///           that "ONE of the registered active providers holds a valid receipt
///           for this session", deriving a per-session provider nullifier
///           (at-most-once), WITHOUT revealing which provider. The 88% share is
///           paid into the `ShieldedPool` as a hidden note (`cmPayout`), so the
///           payout address never names the provider either; 5% burns and 4%+3%
///           go to the reward pool (the v1 split, §5.3).
///
///         Together this removes every on-chain artifact that says which GPU
///         produced a response. The provider-set root is governance-maintained
///         from the (public) provider registry; membership is proven in zero
///         knowledge inside the F006 proof.
contract MilShieldedEscrow is MilOwned {
    IShieldedPool public immutable pool;
    address public rewardPool; // receives the 4%+3% (validator + treasury) legs
    uint8 internal constant PROOF_SYSTEM_STARK = 0x02;
    uint16 internal constant CIRCUIT_PROVIDER_CLAIM = 2;
    /// The HIDDEN-AMOUNT claim (ADR-0037 §2.2 / build#7): the public `amount` is replaced
    /// by a hiding value commitment `v_claim_cm`; the payout magnitude is settled under a
    /// UNIFORM protocol price so it carries no per-provider signal (closes ask-price
    /// inversion, ADR-0037 surface #5). Inert behind the same F006 fence.
    uint16 internal constant CIRCUIT_PROVIDER_CLAIM_V2 = 4;
    /// The RECEIPT-AUTHORIZED claim (C-P6 / ADR-0037 §2.4, `circuit_version=3`): the hidden-amount
    /// claim-v2 statement PLUS a `receiptCm` binding a VALID in-circuit ML-DSA-87 service receipt,
    /// so a settlement is authorized only against a genuine receipt for the session (closing the
    /// value-theft soundness hole where v2 proves membership + nullifier + payout but NOT that the
    /// claimant served the session). INERT behind the same F006 fence + `claimsEnabled=false`; the
    /// circuit-3 vk is unfrozen (F006 rejects fail-closed) until the C-P6 prover + audit + activation.
    uint16 internal constant CIRCUIT_PROVIDER_CLAIM_V3 = 3;
    uint256 public constant NATIVE_SCALE = 10_000_000_000;

    /// Governance-pinned Merkle root (64B) over registered active providers, and
    /// the provider-claim circuit verifier key (64B).
    bytes public providerSetRoot;
    bytes public claimVkHash;
    /// UNIFORM price per 1k tokens (sompi), governance-pinned. Because it is the SAME for
    /// every provider of a model, the resulting gross carries no per-provider ask
    /// fingerprint — the ADR-0037 §2.3 uniform-price option (the committed-ask variant is
    /// a heavier follow-up that also hides the token counts).
    uint64 public uniformPricePer1k;

    /// COMMITTED-ASK root (64B keyed-BLAKE2b Merkle root over the per-provider ask
    /// commitments `askCm = H(askIn ‖ askOut ‖ blind)`), governance-pinned — the ADR-0037
    /// §2.3.1 resolution of the B2/ADR-0029 tension. Unlike a flat uniform price, this
    /// preserves each provider's heterogeneous ADR-0029 floor (the provider still sets its
    /// own ask; only the commitment is public) while removing the on-chain fingerprint: the
    /// per-provider `askCm` is a Merkle *leaf*, never a public per-identity value, so a claim
    /// proves leaf-membership + `gross` priced under the committed ask IN-CIRCUIT without
    /// naming the leaf. Only the root is on-chain here. Staged inert exactly like
    /// `uniformPricePer1k` was: the V3 claim (circuit_version=5) that binds `snapshotAskRoot`
    /// and proves gross-under-committed-ask is the follow-up, gated on the committed-ask
    /// circuit (build#8 — the modest multiply/compare extension of build#7's value-commit
    /// row). Empty (length 0) until governance adopts the committed-ask model. Inert behind
    /// the same F006 fence.
    bytes public askCommitmentRoot;

    /// (C-06) Anonymous claims are DISABLED until the receipt-validity circuit
    /// (`circuit_version=3`, C-P6) is live and audited. The current claim relation proves
    /// membership + nullifier + payout but NOT that the claimant actually served the
    /// session (no receipt/signature/counter), so any registered provider could otherwise
    /// drain a blind escrow. Governance flips this only once C-P6 is activated.
    bool public claimsEnabled;

    /// (audit M-04) The governance-pinned "active claim circuit" — the `circuit_version` an
    /// escrow opened NOW must be settled under. Set ONLY by the ATOMIC `setClaimPolicy` (never a
    /// standalone setter) so it can never diverge from its paired `claimVkHash`, and snapshotted
    /// into each escrow at `openBlind` so a governance rotation between open and claim cannot
    /// retarget an in-flight escrow. `0` = UNCONFIGURED (no policy set yet): the WILDCARD is
    /// REJECTED — `openBlind` reverts `ClaimPolicyUnset` while this is `0`, and every claim path
    /// requires the snapshot to EQUAL its hardcoded circuit, so `0` can never authorize
    /// settlement. Once governance pins a specific circuit (`claimAnon` = 2 XOR `claimAnonV2` = 4)
    /// an escrow opened afterward is LOCKED to exactly that circuit and the other claim path
    /// reverts `WrongClaimCircuit` (defense-in-depth, independent of the F006 proof).
    uint16 public activeClaimCircuit;

    /// (audit M-04) Monotonic version of the ATOMIC claim policy. `setClaimPolicy` bumps it on
    /// every coherent (circuit, VK, price, provider-set root, ask root) update, and `openBlind`
    /// snapshots it into the escrow — so the frozen policy is identifiable as ONE specific,
    /// internally-consistent version and a partial/inconsistent tuple can never be snapshotted.
    uint64 public claimPolicyId;

    /// (H-01) Seconds a requester must wait after `openBlind` before it may `refundBlind`,
    /// so a provider has a guaranteed window to claim first (no refund front-run). Settable
    /// by governance; seeded to a nonzero floor in the constructor.
    uint64 public refundDelay;
    uint64 public constant MIN_REFUND_DELAY = 1 hours;
    uint64 public constant MAX_REFUND_DELAY = 30 days; // ceiling so funds can't be locked indefinitely

    struct Escrow {
        address requester;
        uint256 locked; // wei
        bytes sessionCm; // 64
        bool open;
        uint64 refundAfter; // (H-01) block.timestamp before which refund is blocked
        // (M-04) the provider-set root + claim VK + uniform price snapshotted AT OPEN, so a
        // governance rotation between open and claim neither invalidates the in-flight proof,
        // shifts the eligible provider set, nor retroactively re-prices the in-flight session.
        bytes snapshotRoot; // 64
        bytes snapshotVk; // 64
        uint64 snapshotPrice; // (M-04) uniformPricePer1k frozen at open
        bytes snapshotAskRoot; // (M-04) askCommitmentRoot frozen at open (empty until adopted)
        uint16 snapshotClaimCircuit; // (M-04) activeClaimCircuit frozen at open (always 2 XOR 4)
        uint64 snapshotPolicyId; // (M-04) claimPolicyId frozen at open — the atomic-policy version
    }

    mapping(bytes32 => Escrow) public escrows;
    mapping(bytes32 => bool) public providerNfSpent; // keccak(nf64) => spent

    event OpenedBlind(bytes32 indexed escrowId, address indexed requester, uint256 lockedWei);
    event ClaimedAnon(bytes32 indexed escrowId, uint256 grossWei, uint256 providerWei, bytes cmPayout);
    /// v2 event: NO magnitude (the payout is committed in `vClaimCm`); only the
    /// commitment + the shielded payout note are surfaced.
    event ClaimedAnonV2(bytes32 indexed escrowId, bytes vClaimCm, bytes cmPayout);
    /// v3 event (receipt-authorized): as v2 plus the receipt-verify commitment `receiptCm`; still
    /// NO public magnitude and NO provider identity.
    event ClaimedAnonV3(bytes32 indexed escrowId, bytes vClaimCm, bytes receiptCm, bytes cmPayout);
    event RefundedBlind(bytes32 indexed escrowId, address indexed requester, uint256 amountWei);
    /// (audit M-04) The single event for an ATOMIC claim-policy update — the whole coherent
    /// tuple (circuit, VK, price, provider-set root, ask root) and its new version, so an
    /// off-chain indexer sees the policy change as one indivisible record (never a partial pair).
    event ClaimPolicyUpdated(
        uint64 indexed policyId, uint16 circuitVersion, bytes vkHash, uint64 pricePer1k, bytes setRoot, bytes askRoot
    );

    error BadLen();
    error EscrowExists();
    error NoEscrow();
    error NotRequester();
    error SessionMismatch();
    error ProviderNfSpent();
    error ProofInvalid();
    error SplitMismatch();
    error Overdraw();
    error ClaimsDisabled();
    error RefundTooEarly();
    error WrongClaimCircuit();
    error ClaimPolicyUnset();

    event ClaimsEnabledUpdated(bool enabled);
    event RefundDelayUpdated(uint64 secondsDelay);

    constructor(
        address initialOwner,
        address shieldedPool,
        address rewardPool_,
        bytes memory setRoot,
        bytes memory vkHash
    ) MilOwned(initialOwner) {
        if (setRoot.length != 64 || vkHash.length != 64) revert BadLen();
        pool = IShieldedPool(shieldedPool);
        rewardPool = rewardPool_;
        providerSetRoot = setRoot;
        claimVkHash = vkHash;
        refundDelay = MIN_REFUND_DELAY;
        // (audit M-04) `activeClaimCircuit`/`claimPolicyId` start at 0 = UNCONFIGURED: no escrow
        // can `openBlind` until governance sets the atomic claim policy via `setClaimPolicy`.
    }

    /// @notice (C-06) Governance enables anonymous claims — ONLY after the receipt-validity
    ///         circuit (C-P6) is activated and audited. Off by default.
    function setClaimsEnabled(bool enabled) external onlyOwner {
        claimsEnabled = enabled;
        emit ClaimsEnabledUpdated(enabled);
    }

    /// @notice (H-01) Governance sets the post-open refund delay, bounded to
    ///         `[MIN_REFUND_DELAY, MAX_REFUND_DELAY]` so it can neither be zeroed (refund
    ///         front-run) nor set so large that requester funds are locked indefinitely.
    function setRefundDelay(uint64 secondsDelay) external onlyOwner {
        if (secondsDelay < MIN_REFUND_DELAY || secondsDelay > MAX_REFUND_DELAY) revert BadLen();
        refundDelay = secondsDelay;
        emit RefundDelayUpdated(secondsDelay);
    }

    /// @notice (audit M-04) Governance sets the ENTIRE claim policy ATOMICALLY. The claim
    ///         circuit, its verifier key, the uniform price, the provider-set (anonymity) root,
    ///         and the committed-ask root are written in a SINGLE call, bumping `claimPolicyId`.
    ///         This closes the auditor's mid-update race: with separate `setActiveClaimCircuit` /
    ///         `setClaimVkHash` setters, an escrow `openBlind`'d BETWEEN two governance calls
    ///         could permanently snapshot an INCONSISTENT (circuit, VK) pair. Here the pair (and
    ///         the price/roots) can only ever change together, so every escrow snapshot is one
    ///         coherent policy version.
    ///
    ///         The circuit MUST be a SPECIFIC registered claim circuit — `CIRCUIT_PROVIDER_CLAIM`
    ///         (2) XOR `CIRCUIT_PROVIDER_CLAIM_V2` (4). The pre-M-04 WILDCARD (`0`) is REJECTED
    ///         here, so no single VK can ever authorize BOTH circuits; `vkHash` is the key paired
    ///         with THAT circuit. (Provider-set rotations as providers join/leave re-supply the
    ///         whole tuple — pass the current VK/price/roots for the unchanged fields — the
    ///         atomicity is the point.)
    function setClaimPolicy(
        uint16 circuitVersion,
        bytes calldata vkHash,
        uint64 pricePer1k,
        bytes calldata setRoot,
        bytes calldata askRoot
    ) external onlyOwner {
        // (M-04 wildcard-0 rejection) a policy MUST pin a SPECIFIC claim circuit — 2 (public
        // amount) XOR 4 (hidden amount) XOR 3 (receipt-authorized, C-P6). Circuit 3 is a COMPLETE
        // but INERT surface: it is dispatchable in the policy so an escrow can be locked to it, but
        // a circuit-3 claim is fail-closed at F006 (unfrozen vk) and gated by claimsEnabled=false
        // until C-P6 activates. The wildcard (0) and any unregistered id are still rejected.
        if (
            circuitVersion != CIRCUIT_PROVIDER_CLAIM && circuitVersion != CIRCUIT_PROVIDER_CLAIM_V2
                && circuitVersion != CIRCUIT_PROVIDER_CLAIM_V3
        ) {
            revert BadLen();
        }
        if (vkHash.length != 64 || setRoot.length != 64) revert BadLen();
        if (askRoot.length != 0 && askRoot.length != 64) revert BadLen(); // 64B or empty (unadopted)
        activeClaimCircuit = circuitVersion;
        claimVkHash = vkHash;
        uniformPricePer1k = pricePer1k;
        providerSetRoot = setRoot;
        askCommitmentRoot = askRoot;
        uint64 id = claimPolicyId + 1;
        claimPolicyId = id;
        emit ClaimPolicyUpdated(id, circuitVersion, vkHash, pricePer1k, setRoot, askRoot);
    }

    /// @dev (audit M-04) Enforce the escrow's snapshotted claim circuit EQUALS this claim path's
    ///      hardcoded circuit. STRICT equality rejects the wildcard (`0` never authorizes
    ///      settlement) and any cross-circuit claim; combined with the `openBlind` gate, an
    ///      escrow always carries a specific pinned circuit (2 XOR 4) and its atomically-paired VK.
    function _assertClaimCircuit(uint16 snapshot, uint16 pathCircuit) internal pure {
        if (snapshot != pathCircuit) revert WrongClaimCircuit();
    }

    /// @notice Open an escrow for a session WITHOUT naming a provider. The requester
    ///         cannot refund until `refundDelay` has elapsed, so a provider has a
    ///         guaranteed claim window (audit H-01).
    function openBlind(bytes32 escrowId, bytes calldata sessionCm) external payable {
        if (sessionCm.length != 64) revert BadLen();
        // (audit M-04) an escrow MUST pin a SPECIFIC claim circuit at open — the wildcard (`0`,
        // i.e. no claim policy configured yet) can never authorize settlement, so opening one is
        // rejected up front rather than locking funds into a permanently unclaimable escrow.
        if (activeClaimCircuit == 0) revert ClaimPolicyUnset();
        if (escrows[escrowId].requester != address(0)) revert EscrowExists();
        escrows[escrowId] = Escrow({
            requester: msg.sender,
            locked: msg.value,
            sessionCm: sessionCm,
            open: true,
            refundAfter: uint64(block.timestamp) + refundDelay,
            // (M-04) freeze the WHOLE coherent claim policy at open, so a governance rotation
            // between open and claim can neither shift the eligible set, re-price, retarget the
            // claim circuit, nor split the (circuit, VK) pair of an in-flight escrow.
            snapshotRoot: providerSetRoot,
            snapshotVk: claimVkHash,
            snapshotPrice: uniformPricePer1k,
            snapshotAskRoot: askCommitmentRoot,
            snapshotClaimCircuit: activeClaimCircuit,
            snapshotPolicyId: claimPolicyId
        });
        emit OpenedBlind(escrowId, msg.sender, msg.value);
    }

    struct ClaimPublic {
        bytes sessionCm; // 64 — must equal the escrow's
        uint64 amount; // sompi — the provider's shielded payout note value (88% share)
        bytes providerNf; // 64 — per-session provider nullifier
        bytes cmPayout; // 64 — the shielded payout note commitment
    }

    /// @notice Settle an escrow anonymously. `grossSompi` is the full session cost
    ///         (public; only the provider identity is hidden). The 88% provider
    ///         share is paid into the pool as `cmPayout`; the proof binds
    ///         `pub.amount` == that share and `pub.providerNf` to the session.
    function claimAnon(
        bytes32 escrowId,
        ClaimPublic calldata pub,
        uint64 grossSompi,
        bytes calldata proofField,
        bytes calldata encNote
    ) external {
        if (!claimsEnabled) revert ClaimsDisabled(); // (C-06)
        Escrow storage e = escrows[escrowId];
        if (e.requester == address(0) || !e.open) revert NoEscrow();
        if (pub.sessionCm.length != 64 || pub.providerNf.length != 64 || pub.cmPayout.length != 64) {
            revert BadLen();
        }
        if (keccak256(pub.sessionCm) != keccak256(e.sessionCm)) revert SessionMismatch();
        // (audit m4) defense-in-depth: this path settles circuit 2; reject if the escrow was
        // opened while governance had pinned a DIFFERENT active claim circuit.
        _assertClaimCircuit(e.snapshotClaimCircuit, CIRCUIT_PROVIDER_CLAIM);

        bytes32 nk = keccak256(pub.providerNf);
        if (providerNfSpent[nk]) revert ProviderNfSpent();
        providerNfSpent[nk] = true;

        // Split the gross cost (§5.3). Provider share is paid privately; the
        // proof binds pub.amount (the note value) to exactly this 88% share.
        uint256 grossWei = uint256(grossSompi) * NATIVE_SCALE;
        if (grossWei > e.locked) revert Overdraw();
        uint256 providerWei = (grossWei * MilConstants.FEE_PROVIDER_PCT) / 100;
        uint256 burnWei = (grossWei * MilConstants.FEE_BURN_PCT) / 100;
        uint256 poolWei = grossWei - providerWei - burnWei; // validator+treasury (lossless)
        if (uint256(pub.amount) * NATIVE_SCALE != providerWei) revert SplitMismatch();

        // (H-05 / C-05) recompute ctx binding chain, contract, escrowId, gross, and the
        // ciphertext hash — never a caller field. (M-04) against the OPEN-time snapshot.
        bytes memory ctx =
            _computeClaimCtx(escrowId, e.snapshotRoot, pub.sessionCm, grossSompi, pub.providerNf, pub.cmPayout, encNote);

        // Verify: a registered provider (unidentified) holds a valid session
        // receipt, at most once, paid into cmPayout — via F006 provider-claim.
        bytes memory pi = _borshClaimStatement(e.snapshotRoot, pub, ctx);
        bytes memory shieldProof = _borshShieldProof(e.snapshotVk, pi, proofField);
        if (!ShieldVerifyLib.verify(shieldProof, e.snapshotVk)) revert ProofInvalid();

        e.locked -= grossWei;

        // 88% → shielded pool as a hidden note (provider identity never on-chain).
        pool.depositNote{value: providerWei}(pub.cmPayout, encNote);
        // 5% burn, 4%+3% → reward pool.
        (bool okB,) = payable(MilConstants.BURN_SINK).call{value: burnWei}("");
        require(okB, "MIL: burn failed");
        (bool okP,) = payable(rewardPool).call{value: poolWei}("");
        require(okP, "MIL: reward transfer failed");

        emit ClaimedAnon(escrowId, grossWei, providerWei, pub.cmPayout);
    }

    /// Public inputs for the HIDDEN-AMOUNT claim (circuit_version=4): the magnitude is
    /// gone, replaced by `vClaimCm` (a hiding commitment to the payout the proof binds).
    struct ClaimPublicV2 {
        bytes sessionCm; // 64
        bytes vClaimCm; // 64 — value commitment, replaces the public amount
        bytes providerNf; // 64
        bytes cmPayout; // 64
    }

    /// @notice Settle anonymously with a HIDDEN amount (ADR-0037 §2.2/§2.3, B2). The
    ///         gross is derived from the UNIFORM protocol price × public token counts, so
    ///         it carries no per-provider ask fingerprint; the exact payout note value is
    ///         committed in `vClaimCm` and proven in-circuit (no public magnitude to
    ///         mismatch — the split binding moved inside the F006 proof). Inert until
    ///         F006 activation, like `claimAnon`.
    function claimAnonV2(
        bytes32 escrowId,
        ClaimPublicV2 calldata pub,
        uint64 tokIn,
        uint64 tokOut,
        bytes calldata proofField,
        bytes calldata encNote
    ) external {
        if (!claimsEnabled) revert ClaimsDisabled(); // (C-06)
        Escrow storage e = escrows[escrowId];
        if (e.requester == address(0) || !e.open) revert NoEscrow();
        if (
            pub.sessionCm.length != 64 || pub.vClaimCm.length != 64 || pub.providerNf.length != 64
                || pub.cmPayout.length != 64
        ) {
            revert BadLen();
        }
        if (keccak256(pub.sessionCm) != keccak256(e.sessionCm)) revert SessionMismatch();
        // (audit m4) defense-in-depth: this path settles circuit 4 (hidden-amount claim).
        _assertClaimCircuit(e.snapshotClaimCircuit, CIRCUIT_PROVIDER_CLAIM_V2);

        bytes32 nk = keccak256(pub.providerNf);
        if (providerNfSpent[nk]) revert ProviderNfSpent();
        providerNfSpent[nk] = true;

        // Uniform pricing: gross = price · (tokIn + tokOut) / 1000, at the price SNAPSHOTTED
        // at open (M-04) so a later governance `setClaimPolicy` cannot retroactively re-price
        // an in-flight escrow. Public, but IDENTICAL for every provider, so the magnitude is
        // not a per-provider fingerprint.
        //
        // (audit M-08) NOTE ON PRIVACY: `tokIn`/`tokOut` are public calldata and `snapshotPrice`
        // is public, so `gross` and the 88% payout are publicly DERIVABLE. `vClaimCm` therefore
        // provides *provider unlinkability under uniform pricing*, NOT amount hiding. True
        // amount privacy requires moving the token counts + pricing inside the proof (ADR-0037
        // §2.3 follow-on); the spec is corrected to this weaker-but-accurate claim.
        uint256 grossSompi = (uint256(e.snapshotPrice) * (uint256(tokIn) + uint256(tokOut))) / 1000;
        uint256 grossWei = grossSompi * NATIVE_SCALE;
        if (grossWei > e.locked) revert Overdraw();
        uint256 providerWei = (grossWei * MilConstants.FEE_PROVIDER_PCT) / 100;
        // (audit NEW-4) the payout note value must be a WHOLE sompi, else the shielded note
        // (whose value is in sompi) cannot open to `providerWei` wei and dust would be stranded.
        if (providerWei % NATIVE_SCALE != 0) revert SplitMismatch();

        // (audit C-06.2) VALUE-CONSERVATION BINDING: the contract-computed provider share
        // (whole sompi = 88%-of-gross) is surfaced as an EXPLICIT canonical public input; the
        // F006 claim circuit MUST prove `vClaimCm == commit(providerShareSompi)`, so a proof
        // cannot bind a larger private amount than the contract funds (no undercollateralized
        // note). The verify (ctx recompute + statement + proof decode) is in a helper to keep
        // this frame shallow (via-IR stack budget).
        _verifyClaimV2(escrowId, e, pub, grossSompi, uint64(providerWei / NATIVE_SCALE), proofField, encNote);

        e.locked -= grossWei;
        pool.depositNote{value: providerWei}(pub.cmPayout, encNote);
        // Fee split (5% burn / remainder to the reward pool), computed AFTER the verify so the
        // intermediates are not live across the ctx/statement build (stack depth).
        uint256 burnWei = (grossWei * MilConstants.FEE_BURN_PCT) / 100;
        uint256 poolWei = grossWei - providerWei - burnWei;
        (bool okB,) = payable(MilConstants.BURN_SINK).call{value: burnWei}("");
        require(okB, "MIL: burn failed");
        (bool okP,) = payable(rewardPool).call{value: poolWei}("");
        require(okP, "MIL: reward transfer failed");

        emit ClaimedAnonV2(escrowId, pub.vClaimCm, pub.cmPayout);
    }

    /// Public inputs for the RECEIPT-AUTHORIZED claim (circuit_version=3, C-P6): the hidden-amount
    /// v2 fields PLUS `receiptCm`, the receipt-verify commitment binding a valid in-circuit
    /// ML-DSA-87 receipt for this session.
    struct ClaimPublicV3 {
        bytes sessionCm; // 64
        bytes vClaimCm; // 64 — value commitment, replaces the public amount
        bytes providerNf; // 64
        bytes cmPayout; // 64
        bytes receiptCm; // 64 — receipt-verify commitment (C-P6)
    }

    /// @notice Settle anonymously with a HIDDEN amount AND a RECEIPT AUTHORIZATION (C-P6 /
    ///         ADR-0037 §2.4). Identical economics to `claimAnonV2` (uniform-price gross, 88/5/7
    ///         split, whole-sompi payout), with one added public input — `receiptCm` — that the
    ///         circuit-3 proof binds to a valid ML-DSA-87 service receipt, so a registered provider
    ///         that did NOT serve the session cannot settle. **INERT until activation:** gated by
    ///         `claimsEnabled=false` (C-06) and the F006 fence, and circuit 3's vk is unfrozen so
    ///         F006 rejects fail-closed — a circuit-3 claim reverts today at every layer.
    function claimAnonV3(
        bytes32 escrowId,
        ClaimPublicV3 calldata pub,
        uint64 tokIn,
        uint64 tokOut,
        bytes calldata proofField,
        bytes calldata encNote
    ) external {
        if (!claimsEnabled) revert ClaimsDisabled(); // (C-06) — off until C-P6 is live
        Escrow storage e = escrows[escrowId];
        if (e.requester == address(0) || !e.open) revert NoEscrow();
        if (
            pub.sessionCm.length != 64 || pub.vClaimCm.length != 64 || pub.providerNf.length != 64
                || pub.cmPayout.length != 64 || pub.receiptCm.length != 64
        ) {
            revert BadLen();
        }
        if (keccak256(pub.sessionCm) != keccak256(e.sessionCm)) revert SessionMismatch();
        // (audit M-04) defense-in-depth: this path settles circuit 3 (receipt-authorized claim).
        _assertClaimCircuit(e.snapshotClaimCircuit, CIRCUIT_PROVIDER_CLAIM_V3);

        bytes32 nk = keccak256(pub.providerNf);
        if (providerNfSpent[nk]) revert ProviderNfSpent();
        providerNfSpent[nk] = true;

        // Uniform pricing identical to v2 (snapshotted price, whole-sompi payout).
        uint256 grossSompi = (uint256(e.snapshotPrice) * (uint256(tokIn) + uint256(tokOut))) / 1000;
        uint256 grossWei = grossSompi * NATIVE_SCALE;
        if (grossWei > e.locked) revert Overdraw();
        uint256 providerWei = (grossWei * MilConstants.FEE_PROVIDER_PCT) / 100;
        if (providerWei % NATIVE_SCALE != 0) revert SplitMismatch();

        // (C-06.2) the contract-computed share is surfaced to the circuit-3 statement; the verify
        // (ctx recompute + v3 statement + proof decode) is in a helper for the via-IR stack budget.
        _verifyClaimV3(escrowId, e, pub, grossSompi, uint64(providerWei / NATIVE_SCALE), proofField, encNote);

        e.locked -= grossWei;
        pool.depositNote{value: providerWei}(pub.cmPayout, encNote);
        uint256 burnWei = (grossWei * MilConstants.FEE_BURN_PCT) / 100;
        uint256 poolWei = grossWei - providerWei - burnWei;
        (bool okB,) = payable(MilConstants.BURN_SINK).call{value: burnWei}("");
        require(okB, "MIL: burn failed");
        (bool okP,) = payable(rewardPool).call{value: poolWei}("");
        require(okP, "MIL: reward transfer failed");

        emit ClaimedAnonV3(escrowId, pub.vClaimCm, pub.receiptCm, pub.cmPayout);
    }

    /// @notice Requester reclaims the unspent remainder — only AFTER `refundAfter`, so a
    ///         provider's claim cannot be front-run by an immediate refund (audit H-01).
    function refundBlind(bytes32 escrowId) external {
        Escrow storage e = escrows[escrowId];
        if (e.requester != msg.sender) revert NotRequester();
        if (block.timestamp < e.refundAfter) revert RefundTooEarly();
        uint256 amt = e.locked;
        e.locked = 0;
        e.open = false;
        (bool ok,) = payable(msg.sender).call{value: amt}("");
        require(ok, "MIL: refund failed");
        emit RefundedBlind(escrowId, msg.sender, amt);
    }

    /// @dev The v2 claim verify (ctx recompute → statement → proof decode → F006 verify), split
    ///      out of `claimAnonV2` so its byte-buffer locals do not inflate the caller's stack
    ///      frame (via-IR stack budget). Reverts `ProofInvalid` on any failure. Reads only the
    ///      escrow's OPEN-time snapshot (root/VK) for replay/rotation safety (M-04).
    function _verifyClaimV2(
        bytes32 escrowId,
        Escrow storage e,
        ClaimPublicV2 calldata pub,
        uint256 grossSompi,
        uint64 providerShareSompi,
        bytes calldata proofField,
        bytes calldata encNote
    ) internal {
        // (H-05 / C-05) ctx binds chain/contract/escrowId/gross(full width)/ciphertext, against
        // the OPEN-time provider-set / VK snapshot (M-04).
        bytes memory ctx =
            _computeClaimCtx(escrowId, e.snapshotRoot, pub.sessionCm, grossSompi, pub.providerNf, pub.cmPayout, encNote);
        bytes memory pi = _borshClaimStatementV2(e.snapshotRoot, pub, providerShareSompi, ctx);
        bytes memory shieldProof = _borshShieldProofV2(e.snapshotVk, pi, proofField);
        if (!ShieldVerifyLib.verify(shieldProof, e.snapshotVk)) revert ProofInvalid();
    }

    /// @dev The v3 claim verify (ctx recompute → v3 statement → circuit-3 proof decode → F006
    ///      verify), split out of `claimAnonV3` for the via-IR stack budget (like `_verifyClaimV2`).
    ///      Reverts `ProofInvalid` on any failure — which, while circuit 3's vk is unfrozen, is the
    ///      guaranteed outcome (F006 fails closed). Reads only the escrow's OPEN-time snapshot.
    function _verifyClaimV3(
        bytes32 escrowId,
        Escrow storage e,
        ClaimPublicV3 calldata pub,
        uint256 grossSompi,
        uint64 providerShareSompi,
        bytes calldata proofField,
        bytes calldata encNote
    ) internal {
        // (H-05 / C-05) ctx binds chain/contract/escrowId/gross(full width)/ciphertext, against the
        // OPEN-time provider-set / VK snapshot (M-04). Same 404-byte preimage as v1/v2 (receiptCm is
        // bound by the proof, not the ctx).
        bytes memory ctx =
            _computeClaimCtx(escrowId, e.snapshotRoot, pub.sessionCm, grossSompi, pub.providerNf, pub.cmPayout, encNote);
        bytes memory pi = _borshClaimStatementV3(e.snapshotRoot, pub, providerShareSompi, ctx);
        bytes memory shieldProof = _borshShieldProofV3(e.snapshotVk, pi, proofField);
        if (!ShieldVerifyLib.verify(shieldProof, e.snapshotVk)) revert ProofInvalid();
    }

    /// @dev The canonical claim context (64B Hash64 via F004), binding the deployment
    ///      (chain, this contract), the specific escrow, the gross, the payout, the
    ///      nullifier, and the ciphertext hash — recomputed on-chain so a claim proof is
    ///      valid for exactly one (chain, contract, escrow) and cannot be replayed across
    ///      deployments or have its ciphertext swapped (audit H-05 / H-04 / C-05).
    function _computeClaimCtx(
        bytes32 escrowId,
        bytes memory setRoot,
        bytes calldata sessionCm,
        uint256 grossSompi,
        bytes calldata providerNf,
        bytes calldata cmPayout,
        bytes calldata encNote
    ) internal view returns (bytes memory) {
        // `grossSompi` is bound as a FULL 32-byte word (no u64 truncation), so two gross
        // values sharing the low 64 bits cannot collide in ctx (audit NEW-2). `setRoot` is
        // the escrow's OPEN-time snapshot (audit M-04), not the live global.
        bytes memory pre = abi.encodePacked(
            uint256(block.chainid),
            address(this),
            escrowId,
            setRoot,
            sessionCm,
            grossSompi,
            providerNf,
            cmPayout,
            keccak256(encNote)
        );
        return _hash64(bytes("misaka-shield-v1/claim-ctx"), pre);
    }

    /// @dev keyed BLAKE2b-512 via F004 (`key_len(1) ‖ key ‖ data`).
    function _hash64(bytes memory domainKey, bytes memory data) internal view returns (bytes memory out) {
        require(domainKey.length <= 64, "MIL: key too long");
        bytes memory input = abi.encodePacked(uint8(domainKey.length), domainKey, data);
        (bool ok, bytes memory ret) = MilConstants.F004.staticcall(input);
        require(ok && ret.length == 64, "MIL: F004 failed");
        out = ret;
    }

    /// @dev borsh(ProviderClaimStatement): provider_set_root(64) ‖ session_cm(64)
    ///      ‖ amount(u64 LE) ‖ provider_nf(64) ‖ cm_payout(64) ‖ ctx(64). `setRoot` is the
    ///      escrow's open-time snapshot (M-04); `ctx` is the contract-recomputed value.
    function _borshClaimStatement(bytes memory setRoot, ClaimPublic calldata pub, bytes memory ctx)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(setRoot, pub.sessionCm, _le64(pub.amount), pub.providerNf, pub.cmPayout, ctx);
    }

    /// @dev borsh(ProviderClaimStatement v2): provider_set_root(64) ‖ session_cm(64)
    ///      ‖ v_claim_cm(64) ‖ provider_nf(64) ‖ cm_payout(64) ‖ provider_share_sompi(u64 LE)
    ///      ‖ ctx(64). The v_claim_cm hides the amount from the event, and `provider_share_sompi`
    ///      is the contract-computed 88%-of-gross the circuit MUST bind `v_claim_cm` to (audit
    ///      C-06.2 value conservation). `setRoot` is the open-time snapshot (M-04); `ctx` recomputed.
    function _borshClaimStatementV2(
        bytes memory setRoot,
        ClaimPublicV2 calldata pub,
        uint64 providerShareSompi,
        bytes memory ctx
    ) internal pure returns (bytes memory) {
        // Two-step concat to keep the number of live dynamic arrays per abi.encodePacked
        // within the via-IR stack budget.
        bytes memory head = abi.encodePacked(setRoot, pub.sessionCm, pub.vClaimCm, pub.providerNf, pub.cmPayout);
        return abi.encodePacked(head, _le64(providerShareSompi), ctx);
    }

    function _borshShieldProofV2(bytes memory vk, bytes memory pi, bytes calldata proofField)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            PROOF_SYSTEM_STARK,
            _le16(CIRCUIT_PROVIDER_CLAIM_V2),
            vk,
            _le32(uint32(pi.length)),
            pi,
            _le32(uint32(proofField.length)),
            proofField
        );
    }

    /// @dev borsh(ProviderClaimStatement v3): provider_set_root(64) ‖ session_cm(64) ‖ v_claim_cm(64)
    ///      ‖ provider_nf(64) ‖ cm_payout(64) ‖ receipt_cm(64) ‖ provider_share_sompi(u64 LE) ‖ ctx(64)
    ///      = 456 bytes. Byte-identical to the Rust schema `PROVIDER_CLAIM_V3_STATEMENT_SCHEMA`: the
    ///      claim-v2 layout with `receipt_cm` inserted after `cm_payout`, so `provider_share_sompi`
    ///      and `ctx` keep their v2 ORDER but shift to [384,392)/[392,456). Multi-step concat to keep
    ///      the live dynamic-array count per `abi.encodePacked` within the via-IR stack budget.
    function _borshClaimStatementV3(
        bytes memory setRoot,
        ClaimPublicV3 calldata pub,
        uint64 providerShareSompi,
        bytes memory ctx
    ) internal pure returns (bytes memory) {
        bytes memory head = abi.encodePacked(setRoot, pub.sessionCm, pub.vClaimCm, pub.providerNf, pub.cmPayout);
        bytes memory head2 = abi.encodePacked(head, pub.receiptCm, _le64(providerShareSompi));
        return abi.encodePacked(head2, ctx);
    }

    function _borshShieldProofV3(bytes memory vk, bytes memory pi, bytes calldata proofField)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            PROOF_SYSTEM_STARK,
            _le16(CIRCUIT_PROVIDER_CLAIM_V3),
            vk,
            _le32(uint32(pi.length)),
            pi,
            _le32(uint32(proofField.length)),
            proofField
        );
    }

    function _borshShieldProof(bytes memory vk, bytes memory pi, bytes calldata proofField)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            PROOF_SYSTEM_STARK,
            _le16(CIRCUIT_PROVIDER_CLAIM),
            vk,
            _le32(uint32(pi.length)),
            pi,
            _le32(uint32(proofField.length)),
            proofField
        );
    }

    function _le16(uint16 v) internal pure returns (bytes memory o) {
        o = new bytes(2);
        o[0] = bytes1(uint8(v));
        o[1] = bytes1(uint8(v >> 8));
    }

    function _le32(uint32 v) internal pure returns (bytes memory o) {
        o = new bytes(4);
        for (uint256 i = 0; i < 4; i++) {
            o[i] = bytes1(uint8(v >> (8 * i)));
        }
    }

    function _le64(uint64 v) internal pure returns (bytes memory o) {
        o = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            o[i] = bytes1(uint8(v >> (8 * i)));
        }
    }
}
