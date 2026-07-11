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

    struct Escrow {
        address requester;
        uint256 locked; // wei
        bytes sessionCm; // 64
        bool open;
    }

    mapping(bytes32 => Escrow) public escrows;
    mapping(bytes32 => bool) public providerNfSpent; // keccak(nf64) => spent

    event OpenedBlind(bytes32 indexed escrowId, address indexed requester, uint256 lockedWei);
    event ClaimedAnon(bytes32 indexed escrowId, uint256 grossWei, uint256 providerWei, bytes cmPayout);
    /// v2 event: NO magnitude (the payout is committed in `vClaimCm`); only the
    /// commitment + the shielded payout note are surfaced.
    event ClaimedAnonV2(bytes32 indexed escrowId, bytes vClaimCm, bytes cmPayout);
    event RefundedBlind(bytes32 indexed escrowId, address indexed requester, uint256 amountWei);
    event ProviderSetRootUpdated(bytes root);
    event UniformPriceUpdated(uint64 pricePer1k);

    error BadLen();
    error EscrowExists();
    error NoEscrow();
    error NotRequester();
    error SessionMismatch();
    error ProviderNfSpent();
    error ProofInvalid();
    error SplitMismatch();
    error Overdraw();

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
    }

    /// @notice Governance updates the anonymity-set root as providers join/leave.
    function setProviderSetRoot(bytes calldata root) external onlyOwner {
        if (root.length != 64) revert BadLen();
        providerSetRoot = root;
        emit ProviderSetRootUpdated(root);
    }

    function setClaimVkHash(bytes calldata vkHash) external onlyOwner {
        if (vkHash.length != 64) revert BadLen();
        claimVkHash = vkHash;
    }

    /// @notice Governance pins the uniform per-1k-token price (ADR-0037 §2.3 / B2).
    function setUniformPrice(uint64 pricePer1k) external onlyOwner {
        uniformPricePer1k = pricePer1k;
        emit UniformPriceUpdated(pricePer1k);
    }

    /// @notice Open an escrow for a session WITHOUT naming a provider.
    function openBlind(bytes32 escrowId, bytes calldata sessionCm) external payable {
        if (sessionCm.length != 64) revert BadLen();
        if (escrows[escrowId].requester != address(0)) revert EscrowExists();
        escrows[escrowId] = Escrow({requester: msg.sender, locked: msg.value, sessionCm: sessionCm, open: true});
        emit OpenedBlind(escrowId, msg.sender, msg.value);
    }

    struct ClaimPublic {
        bytes sessionCm; // 64 — must equal the escrow's
        uint64 amount; // sompi — the provider's shielded payout note value (88% share)
        bytes providerNf; // 64 — per-session provider nullifier
        bytes cmPayout; // 64 — the shielded payout note commitment
        bytes ctx; // 64
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
        Escrow storage e = escrows[escrowId];
        if (e.requester == address(0) || !e.open) revert NoEscrow();
        if (
            pub.sessionCm.length != 64 || pub.providerNf.length != 64 || pub.cmPayout.length != 64
                || pub.ctx.length != 64
        ) {
            revert BadLen();
        }
        if (keccak256(pub.sessionCm) != keccak256(e.sessionCm)) revert SessionMismatch();

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

        // Verify: a registered provider (unidentified) holds a valid session
        // receipt, at most once, paid into cmPayout — via F006 provider-claim.
        bytes memory pi = _borshClaimStatement(pub);
        bytes memory shieldProof = _borshShieldProof(pi, proofField);
        if (!ShieldVerifyLib.verify(shieldProof, claimVkHash)) revert ProofInvalid();

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
        bytes ctx; // 64
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
        Escrow storage e = escrows[escrowId];
        if (e.requester == address(0) || !e.open) revert NoEscrow();
        if (
            pub.sessionCm.length != 64 || pub.vClaimCm.length != 64 || pub.providerNf.length != 64
                || pub.cmPayout.length != 64 || pub.ctx.length != 64
        ) {
            revert BadLen();
        }
        if (keccak256(pub.sessionCm) != keccak256(e.sessionCm)) revert SessionMismatch();

        bytes32 nk = keccak256(pub.providerNf);
        if (providerNfSpent[nk]) revert ProviderNfSpent();
        providerNfSpent[nk] = true;

        // Uniform pricing: gross = price · (tokIn + tokOut) / 1000. Public, but IDENTICAL
        // for every provider, so the magnitude is not a per-provider fingerprint.
        uint256 grossSompi = (uint256(uniformPricePer1k) * (uint256(tokIn) + uint256(tokOut))) / 1000;
        uint256 grossWei = grossSompi * NATIVE_SCALE;
        if (grossWei > e.locked) revert Overdraw();
        uint256 providerWei = (grossWei * MilConstants.FEE_PROVIDER_PCT) / 100;
        uint256 burnWei = (grossWei * MilConstants.FEE_BURN_PCT) / 100;
        uint256 poolWei = grossWei - providerWei - burnWei;
        // NOTE: no public `amount == 88%` SplitMismatch here — that binding is IN-CIRCUIT
        // (the proof binds vClaimCm = commit(providerWei) and value == amount, build#7).

        bytes memory pi = _borshClaimStatementV2(pub);
        bytes memory shieldProof = _borshShieldProofV2(pi, proofField);
        if (!ShieldVerifyLib.verify(shieldProof, claimVkHash)) revert ProofInvalid();

        e.locked -= grossWei;
        pool.depositNote{value: providerWei}(pub.cmPayout, encNote);
        (bool okB,) = payable(MilConstants.BURN_SINK).call{value: burnWei}("");
        require(okB, "MIL: burn failed");
        (bool okP,) = payable(rewardPool).call{value: poolWei}("");
        require(okP, "MIL: reward transfer failed");

        emit ClaimedAnonV2(escrowId, pub.vClaimCm, pub.cmPayout);
    }

    /// @notice Requester reclaims the unspent remainder (session done / timed out).
    function refundBlind(bytes32 escrowId) external {
        Escrow storage e = escrows[escrowId];
        if (e.requester != msg.sender) revert NotRequester();
        uint256 amt = e.locked;
        e.locked = 0;
        e.open = false;
        (bool ok,) = payable(msg.sender).call{value: amt}("");
        require(ok, "MIL: refund failed");
        emit RefundedBlind(escrowId, msg.sender, amt);
    }

    /// @dev borsh(ProviderClaimStatement): provider_set_root(64) ‖ session_cm(64)
    ///      ‖ amount(u64 LE) ‖ provider_nf(64) ‖ cm_payout(64) ‖ ctx(64).
    function _borshClaimStatement(ClaimPublic calldata pub) internal view returns (bytes memory) {
        return
            abi.encodePacked(providerSetRoot, pub.sessionCm, _le64(pub.amount), pub.providerNf, pub.cmPayout, pub.ctx);
    }

    /// @dev borsh(ProviderClaimStatement v2): provider_set_root(64) ‖ session_cm(64)
    ///      ‖ v_claim_cm(64) ‖ provider_nf(64) ‖ cm_payout(64) ‖ ctx(64). Matches
    ///      docs/bench/plonky3-shield-air/claim_v2.rs (the public amount is replaced by
    ///      the 64-byte value commitment).
    function _borshClaimStatementV2(ClaimPublicV2 calldata pub) internal view returns (bytes memory) {
        return abi.encodePacked(providerSetRoot, pub.sessionCm, pub.vClaimCm, pub.providerNf, pub.cmPayout, pub.ctx);
    }

    function _borshShieldProofV2(bytes memory pi, bytes calldata proofField) internal view returns (bytes memory) {
        return abi.encodePacked(
            PROOF_SYSTEM_STARK,
            _le16(CIRCUIT_PROVIDER_CLAIM_V2),
            claimVkHash,
            _le32(uint32(pi.length)),
            pi,
            _le32(uint32(proofField.length)),
            proofField
        );
    }

    function _borshShieldProof(bytes memory pi, bytes calldata proofField) internal view returns (bytes memory) {
        return abi.encodePacked(
            PROOF_SYSTEM_STARK,
            _le16(CIRCUIT_PROVIDER_CLAIM),
            claimVkHash,
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
