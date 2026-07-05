// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilOwned} from "./MilCommon.sol";

/// @title ModelRegistry — MIL model registry + MIL-Core pointer (design §7.1, §17.2).
/// @notice Owner (Treasury in v1, Governance later) manages model entries and
///         the single canonical `MIL-Core` pointer. `model_id` and
///         `runtime_image_hash` are the keyed-BLAKE2b-512 commitments the
///         attestation measurement must match (§3.2) — this is where the
///         "which weights produced this answer" provenance chain is rooted
///         (§17.3).
contract ModelRegistry is MilOwned {
    uint8 internal constant TIER_ALLOWED_TEE = 0x01;
    uint8 internal constant TIER_ALLOWED_OPEN = 0x02;

    struct ModelEntry {
        bytes32 modelId; // Hash64_k("misaka-mil-v1/model", weights_manifest) low 32
        bytes32 runtimeImageHash; // measured runtime container
        uint32 ctxLen;
        uint8 tierAllowed; // bitmask of TIER_ALLOWED_*
        uint32 licenseFlags;
        bool registered;
    }

    mapping(bytes32 => ModelEntry) internal _models;

    /// @dev The single canonical MIL-Core model pointer (§17.2d). Updating it is
    ///      how a governance-approved model change takes the whole network at
    ///      once; the DAO update pipeline (§19) calls `setMilCore`.
    bytes32 public milCore;

    event ModelRegistered(bytes32 indexed modelId, bytes32 runtimeImageHash, uint8 tierAllowed);
    event ModelDeactivated(bytes32 indexed modelId);
    event MilCoreUpdated(bytes32 indexed previous, bytes32 indexed current);

    error UnknownModel();
    error AlreadyRegistered();

    constructor(address initialOwner) MilOwned(initialOwner) {}

    function registerModel(
        bytes32 modelId,
        bytes32 runtimeImageHash,
        uint32 ctxLen,
        uint8 tierAllowed,
        uint32 licenseFlags
    ) external onlyOwner {
        if (_models[modelId].registered) revert AlreadyRegistered();
        _models[modelId] = ModelEntry({
            modelId: modelId,
            runtimeImageHash: runtimeImageHash,
            ctxLen: ctxLen,
            tierAllowed: tierAllowed,
            licenseFlags: licenseFlags,
            registered: true
        });
        emit ModelRegistered(modelId, runtimeImageHash, tierAllowed);
    }

    function deactivateModel(bytes32 modelId) external onlyOwner {
        if (!_models[modelId].registered) revert UnknownModel();
        _models[modelId].registered = false;
        emit ModelDeactivated(modelId);
    }

    /// @notice Point MIL-Core at a registered model. Callable by owner; when a
    ///         `MilGovernance` is installed as owner, this is the target of a
    ///         passed model-update vote (§19.4).
    function setMilCore(bytes32 modelId) external onlyOwner {
        if (!_models[modelId].registered) revert UnknownModel();
        bytes32 prev = milCore;
        milCore = modelId;
        emit MilCoreUpdated(prev, modelId);
    }

    function get(bytes32 modelId) external view returns (ModelEntry memory) {
        return _models[modelId];
    }

    function isRegistered(bytes32 modelId) external view returns (bool) {
        return _models[modelId].registered;
    }
}
