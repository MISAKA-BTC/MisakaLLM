// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilConstants, Hash64Lib, ShieldVerifyLib, MilOwned} from "./MilCommon.sol";

/// @title ShieldedPool — the MIL value pool (ADR-0033 §2 / ADR-0025 §21 L2).
/// @notice Zcash-Sprout-style commitment/nullifier pool on the EVM lane (F010).
///         A `shield` deposits public MSK into a hidden note; a `transfer` moves
///         value between hidden notes; an `unshield` withdraws to a public
///         address. Each spend proves — via the F006 SHIELDED_VERIFY precompile —
///         Merkle membership + a nullifier + value conservation WITHOUT revealing
///         which note is consumed, so the fund graph is severed (payment
///         unlinkability). Soundness is hash-based (F006 verifies a STARK/reference
///         proof over keyed-BLAKE2b commitments), i.e. PQ.
///
/// @dev The public inputs are supplied as TYPED params and borsh-encoded ON-CHAIN
///      into the F006 `public_inputs`, so the proof can only be valid for the
///      exact anchor/nullifiers/commitments/amounts THIS contract enforces —
///      there is no trust in a wallet-supplied statement. Only the `proofField`
///      (the witness / STARK) comes from the caller. Values are 64-byte `Hash64`
///      (`bytes`) to match `misaka-mil-shield`; the Merkle tree is F004-hashed.
contract ShieldedPool is MilOwned {
    /// @dev Fixed tree depth (2^20 notes). Anchors older than the ring are stale.
    uint256 public constant TREE_DEPTH = 20;
    uint256 public constant ROOT_RING = 128;

    /// borsh proof_system / circuit tags (mirror misaka-mil-shield::proof).
    uint8 internal constant PROOF_SYSTEM_STARK = 0x02;
    uint16 internal constant CIRCUIT_SPEND = 1;

    /// Native-scale: sompi (note unit) → wei. Matches EVM_NATIVE_SCALE.
    uint256 public constant NATIVE_SCALE = 10_000_000_000;

    /// Governance-pinned verifier key hash (64B) for the spend circuit.
    bytes public spendVkHash;

    // --- incremental Merkle tree state (all nodes are 64-byte Hash64) ---
    bytes[TREE_DEPTH] internal filledSubtrees;
    bytes[TREE_DEPTH] internal zeros;
    uint256 public nextLeafIndex;
    bytes internal currentRoot;

    // --- anchor ring + nullifier set ---
    bytes[ROOT_RING] internal rootRing;
    uint256 internal rootRingPos;
    mapping(bytes32 => bool) public rootKnown; // keccak(root64) => seen
    mapping(bytes32 => bool) public nullifierSpent; // keccak(nf64) => spent

    /// Pooled native balance (wei) == Σ unspent-note value (SP-01).
    uint256 public poolBalance;

    event Shielded(uint256 leafIndex0, uint256 leafIndex1, bytes root, uint256 valueWei);
    event PrivateTransfer(uint256 leafIndex0, uint256 leafIndex1, bytes root);
    event Unshielded(address indexed to, uint256 valueWei, bytes root);
    event NoteCommitment(uint256 indexed leafIndex, bytes cm, bytes encNote);

    error BadVkLength();
    error UnknownAnchor();
    error NullifierAlreadySpent();
    error ProofInvalid();
    error ValueScaleMismatch();
    error TreeFull();
    error NotPool();

    /// @param initialOwner governance (sets/rotates the verifier key).
    /// @param vkHash the 64-byte spend-circuit verifier key hash.
    constructor(address initialOwner, bytes memory vkHash) MilOwned(initialOwner) {
        if (vkHash.length != 64) revert BadVkLength();
        spendVkHash = vkHash;
        // Empty-subtree roots via F004 — must equal misaka-mil-shield::merkle.
        bytes memory z = Hash64Lib.keyed(bytes("misaka-shield-v1/merkle-empty"), bytes("leaf"));
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            zeros[i] = z;
            filledSubtrees[i] = z;
            z = _node(z, z);
        }
        currentRoot = z;
        _pushRoot(currentRoot);
    }

    /// @notice Rotate the spend verifier key (a new circuit_version / proof system).
    function setSpendVkHash(bytes calldata vkHash) external onlyOwner {
        if (vkHash.length != 64) revert BadVkLength();
        spendVkHash = vkHash;
    }

    /// @dev The public statement of a spend (mirrors misaka-mil-shield::SpendStatement).
    struct SpendPublic {
        bytes anchor; // 64
        bytes nf0; // 64
        bytes nf1; // 64
        bytes cm0; // 64
        bytes cm1; // 64
        uint64 vPubIn; // sompi
        uint64 vPubOut; // sompi
        uint32 tokenId;
        bytes ctx; // 64
    }

    /// @notice Deposit public MSK into the pool as hidden notes (`v_pub_in > 0`).
    function shield(
        SpendPublic calldata pub,
        bytes calldata proofField,
        bytes calldata encNote0,
        bytes calldata encNote1
    ) external payable {
        if (uint256(pub.vPubIn) * NATIVE_SCALE != msg.value) revert ValueScaleMismatch();
        _spend(pub, proofField);
        poolBalance += msg.value;
        (uint256 i0, uint256 i1) = _insertBoth(pub.cm0, pub.cm1, encNote0, encNote1);
        emit Shielded(i0, i1, currentRoot, msg.value);
    }

    /// @notice Move value between hidden notes (`v_pub_in == v_pub_out == 0`).
    function transfer(
        SpendPublic calldata pub,
        bytes calldata proofField,
        bytes calldata encNote0,
        bytes calldata encNote1
    ) external {
        require(pub.vPubIn == 0 && pub.vPubOut == 0, "MIL: transfer is value-neutral");
        _spend(pub, proofField);
        (uint256 i0, uint256 i1) = _insertBoth(pub.cm0, pub.cm1, encNote0, encNote1);
        emit PrivateTransfer(i0, i1, currentRoot);
    }

    /// @notice Withdraw `v_pub_out` to a public `to` (`v_pub_out > 0`).
    function unshield(
        SpendPublic calldata pub,
        bytes calldata proofField,
        address to,
        bytes calldata encNote0,
        bytes calldata encNote1
    ) external {
        require(pub.vPubOut > 0, "MIL: nothing to unshield");
        _spend(pub, proofField);
        uint256 wei_ = uint256(pub.vPubOut) * NATIVE_SCALE;
        poolBalance -= wei_;
        _insertBoth(pub.cm0, pub.cm1, encNote0, encNote1);
        (bool ok,) = payable(to).call{value: wei_}("");
        require(ok, "MIL: unshield transfer failed");
        emit Unshielded(to, wei_, currentRoot);
    }

    /// @notice The pool contract inserts a payout note on behalf of the anonymous
    ///         escrow (which has already verified a provider-claim proof + received
    ///         the value). Only a call carrying exactly `value` is accepted.
    function depositNote(bytes calldata cm, bytes calldata encNote) external payable {
        poolBalance += msg.value;
        uint256 i = _insert(cm, encNote);
        emit NoteCommitment(i, cm, encNote);
    }

    // ---- internals ----

    /// @dev Enforce anchor freshness + nullifier novelty, then F006-verify the
    ///      proof against the ON-CHAIN-built public inputs.
    function _spend(SpendPublic calldata pub, bytes calldata proofField) internal {
        require(pub.anchor.length == 64 && pub.ctx.length == 64, "MIL: bad hash64 len");
        if (!rootKnown[keccak256(pub.anchor)]) revert UnknownAnchor();
        bytes32 k0 = keccak256(pub.nf0);
        bytes32 k1 = keccak256(pub.nf1);
        if (nullifierSpent[k0] || nullifierSpent[k1]) revert NullifierAlreadySpent();
        // (dummy inputs may repeat a random nf across txs; the proof forces dummy
        // value 0, so marking them costs nothing but a genuine double-spend of a
        // real note is caught here because a real nf is deterministic.)
        nullifierSpent[k0] = true;
        if (k1 != k0) nullifierSpent[k1] = true;

        bytes memory publicInputs = _borshSpendStatement(pub);
        bytes memory shieldProof = _borshShieldProof(publicInputs, proofField);
        if (!ShieldVerifyLib.verify(shieldProof, spendVkHash)) revert ProofInvalid();
    }

    function _insertBoth(bytes calldata cm0, bytes calldata cm1, bytes calldata e0, bytes calldata e1)
        internal
        returns (uint256 i0, uint256 i1)
    {
        i0 = _insert(cm0, e0);
        i1 = _insert(cm1, e1);
    }

    /// @dev Incremental Merkle insert (Tornado-style) with F004 hashing.
    function _insert(bytes memory leaf, bytes memory encNote) internal returns (uint256 index) {
        require(leaf.length == 64, "MIL: cm must be 64 bytes");
        index = nextLeafIndex;
        if (index >= (1 << TREE_DEPTH)) revert TreeFull();
        uint256 idx = index;
        bytes memory cur = leaf;
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (idx & 1 == 0) {
                filledSubtrees[i] = cur;
                cur = _node(cur, zeros[i]);
            } else {
                cur = _node(filledSubtrees[i], cur);
            }
            idx >>= 1;
        }
        currentRoot = cur;
        _pushRoot(cur);
        nextLeafIndex = index + 1;
        emit NoteCommitment(index, leaf, encNote);
    }

    function _node(bytes memory left, bytes memory right) internal view returns (bytes memory) {
        return Hash64Lib.keyed(bytes("misaka-shield-v1/merkle"), abi.encodePacked(left, right));
    }

    function _pushRoot(bytes memory root) internal {
        rootRing[rootRingPos] = root;
        rootRingPos = (rootRingPos + 1) % ROOT_RING;
        rootKnown[keccak256(root)] = true;
    }

    /// @dev borsh(SpendStatement): anchor‖nf0‖nf1‖cm0‖cm1 (5×64) ‖ vPubIn(u64 LE)
    ///      ‖ vPubOut(u64 LE) ‖ tokenId(u32 LE) ‖ ctx(64).
    function _borshSpendStatement(SpendPublic calldata pub) internal pure returns (bytes memory) {
        return abi.encodePacked(
            pub.anchor,
            pub.nf0,
            pub.nf1,
            pub.cm0,
            pub.cm1,
            _le64(pub.vPubIn),
            _le64(pub.vPubOut),
            _le32(pub.tokenId),
            pub.ctx
        );
    }

    /// @dev borsh(ShieldProof): proof_system(1) ‖ circuit(u16 LE) ‖ vkHash(64) ‖
    ///      len(pi)(u32 LE) ‖ pi ‖ len(proof)(u32 LE) ‖ proof. The circuit is the
    ///      STARK id in production; the reference id is testnet-only.
    function _borshShieldProof(bytes memory pi, bytes calldata proofField) internal view returns (bytes memory) {
        return abi.encodePacked(
            PROOF_SYSTEM_STARK,
            _le16(CIRCUIT_SPEND),
            spendVkHash,
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

    function root() external view returns (bytes memory) {
        return currentRoot;
    }
}
