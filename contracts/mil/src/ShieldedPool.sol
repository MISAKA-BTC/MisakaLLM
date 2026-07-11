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

    /// Action discriminators bound into `ctx` so a proof for one entrypoint cannot be
    /// replayed onto another (audit C-02/C-05).
    uint8 internal constant ACTION_SHIELD = 1;
    uint8 internal constant ACTION_TRANSFER = 2;
    uint8 internal constant ACTION_UNSHIELD = 3;

    /// Native-scale: sompi (note unit) → wei. Matches EVM_NATIVE_SCALE.
    uint256 public constant NATIVE_SCALE = 10_000_000_000;

    /// Governance-pinned verifier key hash (64B) for the spend circuit.
    bytes public spendVkHash;

    /// The ONLY address permitted to call `depositNote` (the anonymous escrow), set
    /// by governance after deployment. `depositNote` mints a note commitment WITHOUT
    /// a spend proof, so it must never be callable by an arbitrary EOA (audit C-01).
    address public noteIssuer;

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
    error DuplicateInputNullifier();
    error ProofInvalid();
    error ValueScaleMismatch();
    error TreeFull();
    error NotIssuer();
    error BadMode();
    error BadHashLen();
    error BadTokenId();

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

    /// @notice Governance authorizes the single note-issuer (the anonymous escrow).
    ///         `depositNote` is the ONLY value-into-the-tree path without a spend
    ///         proof, so it must be locked to one audited contract (audit C-01).
    function setNoteIssuer(address issuer) external onlyOwner {
        noteIssuer = issuer;
    }

    /// @dev The public statement of a spend (mirrors misaka-mil-shield::SpendStatement).
    ///      `ctx` is NOT a caller field: the contract RECOMPUTES it from the canonical
    ///      binding (chain, pool, action, recipient, amounts, token, commitments,
    ///      ciphertext hashes) so a proof cannot be replayed onto a different recipient,
    ///      action, chain, or ciphertext (audit C-05 / H-04).
    struct SpendPublic {
        bytes anchor; // 64
        bytes nf0; // 64
        bytes nf1; // 64
        bytes cm0; // 64
        bytes cm1; // 64
        uint64 vPubIn; // sompi
        uint64 vPubOut; // sompi
        uint32 tokenId;
    }

    /// @notice Deposit public MSK into the pool as hidden notes (`v_pub_in > 0`,
    ///         `v_pub_out == 0`).
    function shield(
        SpendPublic calldata pub,
        bytes calldata proofField,
        bytes calldata encNote0,
        bytes calldata encNote1
    ) external payable {
        // Mode strictness (audit C-02): shield is deposit-only.
        if (!(pub.vPubIn > 0 && pub.vPubOut == 0)) revert BadMode();
        if (uint256(pub.vPubIn) * NATIVE_SCALE != msg.value) revert ValueScaleMismatch();
        _spend(pub, proofField, ACTION_SHIELD, address(0), encNote0, encNote1);
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
        if (!(pub.vPubIn == 0 && pub.vPubOut == 0)) revert BadMode();
        _spend(pub, proofField, ACTION_TRANSFER, address(0), encNote0, encNote1);
        (uint256 i0, uint256 i1) = _insertBoth(pub.cm0, pub.cm1, encNote0, encNote1);
        emit PrivateTransfer(i0, i1, currentRoot);
    }

    /// @notice Withdraw `v_pub_out` to a public `to` (`v_pub_in == 0`, `v_pub_out > 0`).
    ///         `to` is bound into the recomputed `ctx`, so the withdrawal cannot be
    ///         front-run onto a different recipient (audit C-05).
    function unshield(
        SpendPublic calldata pub,
        bytes calldata proofField,
        address to,
        bytes calldata encNote0,
        bytes calldata encNote1
    ) external {
        // Mode strictness (audit C-02): unshield is withdraw-only, no phantom deposit.
        if (!(pub.vPubIn == 0 && pub.vPubOut > 0)) revert BadMode();
        _spend(pub, proofField, ACTION_UNSHIELD, to, encNote0, encNote1);
        uint256 wei_ = uint256(pub.vPubOut) * NATIVE_SCALE;
        poolBalance -= wei_;
        _insertBoth(pub.cm0, pub.cm1, encNote0, encNote1);
        (bool ok,) = payable(to).call{value: wei_}("");
        require(ok, "MIL: unshield transfer failed");
        emit Unshielded(to, wei_, currentRoot);
    }

    /// @notice The anonymous escrow inserts a provider payout note (it has already
    ///         F006-verified a provider-claim proof + forwarded the value). Restricted
    ///         to the single authorized `noteIssuer` — an arbitrary caller must NOT be
    ///         able to mint an unbacked commitment into the tree (audit C-01).
    function depositNote(bytes calldata cm, bytes calldata encNote) external payable {
        if (msg.sender != noteIssuer || noteIssuer == address(0)) revert NotIssuer();
        poolBalance += msg.value;
        uint256 i = _insert(cm, encNote);
        emit NoteCommitment(i, cm, encNote);
    }

    // ---- internals ----

    /// @dev Enforce fixed-width fields + anchor freshness + nullifier distinctness &
    ///      novelty, RECOMPUTE the canonical `ctx`, then F006-verify the proof against
    ///      the ON-CHAIN-built public inputs.
    function _spend(
        SpendPublic calldata pub,
        bytes calldata proofField,
        uint8 action,
        address to,
        bytes calldata encNote0,
        bytes calldata encNote1
    ) internal {
        // (C-04) EVERY Hash64 field must be exactly 64 bytes, so the borsh statement
        // has fixed field boundaries and the spent-map key is the canonical 64-byte
        // nullifier — not a caller-chosen variable-length slice.
        if (
            pub.anchor.length != 64 || pub.nf0.length != 64 || pub.nf1.length != 64 || pub.cm0.length != 64
                || pub.cm1.length != 64
        ) {
            revert BadHashLen();
        }
        // (M-02) v1 is a single-asset native (MSK) pool.
        if (pub.tokenId != 0) revert BadTokenId();
        if (!rootKnown[keccak256(pub.anchor)]) revert UnknownAnchor();

        bytes32 k0 = keccak256(pub.nf0);
        bytes32 k1 = keccak256(pub.nf1);
        // (C-03) the SAME note in both input lanes double-counts value; the relation
        // does not forbid nf0==nf1, so reject it here. Honest wallets always give the
        // two lanes distinct nullifiers (real notes differ; dummy nfs are randomized).
        if (k0 == k1) revert DuplicateInputNullifier();
        if (nullifierSpent[k0] || nullifierSpent[k1]) revert NullifierAlreadySpent();
        // sequential check-then-insert (both distinct, both novel per the checks above).
        nullifierSpent[k0] = true;
        nullifierSpent[k1] = true;

        // (C-05 / H-04) canonical ctx binds chain, pool, action, recipient, amounts,
        // token, output commitments, and the ciphertext hashes — recomputed here, never
        // taken from the caller, so no field can be swapped post-proof.
        bytes memory ctx = _computeCtx(action, to, pub, keccak256(encNote0), keccak256(encNote1));

        bytes memory publicInputs = _borshSpendStatement(pub, ctx);
        bytes memory shieldProof = _borshShieldProof(publicInputs, proofField);
        if (!ShieldVerifyLib.verify(shieldProof, spendVkHash)) revert ProofInvalid();
    }

    /// @dev The canonical spend context (64B Hash64 via F004). A proof is only valid
    ///      for the exact (chain, pool, action, recipient, amounts, token, commitments,
    ///      ciphertexts) it was generated against — closing recipient front-run (C-05),
    ///      cross-action/chain/deployment replay, and ciphertext substitution (H-04).
    function _computeCtx(uint8 action, address to, SpendPublic calldata pub, bytes32 encHash0, bytes32 encHash1)
        internal
        view
        returns (bytes memory)
    {
        bytes memory pre = abi.encodePacked(
            uint256(block.chainid),
            address(this),
            action,
            to,
            _le64(pub.vPubIn),
            _le64(pub.vPubOut),
            _le32(pub.tokenId),
            pub.cm0,
            pub.cm1,
            encHash0,
            encHash1
        );
        return Hash64Lib.keyed(bytes("misaka-shield-v1/spend-ctx"), pre);
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

    /// @dev Advance the anchor ring. The displaced root is REMOVED from `rootKnown`
    ///      so only the most recent `ROOT_RING` anchors are accepted — the freshness
    ///      window the design assumes (audit M-01). Each `_insert` produces a distinct
    ///      root (the tree changes every leaf), so a root never occupies two slots and
    ///      the simple evict-then-mark is correct without a reference count.
    function _pushRoot(bytes memory root) internal {
        bytes memory evicted = rootRing[rootRingPos];
        if (evicted.length == 64) {
            rootKnown[keccak256(evicted)] = false;
        }
        rootRing[rootRingPos] = root;
        rootRingPos = (rootRingPos + 1) % ROOT_RING;
        rootKnown[keccak256(root)] = true;
    }

    /// @dev borsh(SpendStatement): anchor‖nf0‖nf1‖cm0‖cm1 (5×64) ‖ vPubIn(u64 LE)
    ///      ‖ vPubOut(u64 LE) ‖ tokenId(u32 LE) ‖ ctx(64). `ctx` is the contract-
    ///      recomputed value, never a caller field.
    function _borshSpendStatement(SpendPublic calldata pub, bytes memory ctx) internal pure returns (bytes memory) {
        return abi.encodePacked(
            pub.anchor,
            pub.nf0,
            pub.nf1,
            pub.cm0,
            pub.cm1,
            _le64(pub.vPubIn),
            _le64(pub.vPubOut),
            _le32(pub.tokenId),
            ctx
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
