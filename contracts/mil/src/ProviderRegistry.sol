// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilConstants, MilOwned} from "./MilCommon.sol";

/// @title ProviderRegistry — MIL provider onboarding (design §8.2).
/// @notice A provider registers its attestation quote hash, enclave keys, ask
///         price, tier, and data-plane address. v0's off-chain anchor
///         (`ProviderRegistrationV1`) becomes this on-chain record in v1.
///         The full 2592-byte `pk_receipt` is not stored (gas); the registry
///         keeps its keccak hash and a claimer supplies the full key, which
///         `JobEscrow` checks before verifying a receipt.
contract ProviderRegistry is MilOwned {
    enum Tier {
        Tee, // Tier 1 (TEE-confidential)
        Open // Tier 2 (provider-visible)
    }

    struct Provider {
        address operator; // the EVM address that registered / claims payouts
        bytes32 providerId; // Hash64_k("misaka-mil-v1/provider-id", pk_receipt), low 32 bytes
        bytes32 quoteHash; // attestation quote hash pinned at registration
        bytes32 modelId; // served model (MIL-Core in v1)
        bytes32 pkReceiptHash; // keccak256(pk_receipt) — JobEscrow checks the supplied key
        bytes32 pkKemHash; // keccak256(pk_kem) — informational binding
        Tier tier;
        uint32 gpuClassWeight; // attested class weight g (§5.4)
        uint64 askInPer1k; // sompi per 1000 input tokens
        uint64 askOutPer1k; // sompi per 1000 output tokens
        uint32 ttfbMs;
        uint32 minTps;
        uint64 lastHeartbeat; // block number of the last heartbeat
        bool active;
        bool hot; // model is VRAM-resident (§13.4a) — SDKs prefer hot
        bytes32 entityCredentialHash; // optional FSL entity-bound credential (§8.6); 0 = none
        string region;
        string dataPlaneAddr;
    }

    /// @dev providerId (bytes32) → record.
    mapping(bytes32 => Provider) internal _providers;
    /// @dev operator address → its providerId (one active registration per operator).
    mapping(address => bytes32) public operatorToProvider;

    event ProviderRegistered(bytes32 indexed providerId, address indexed operator, bytes32 modelId, Tier tier);
    event ProviderUpdated(bytes32 indexed providerId, uint64 askInPer1k, uint64 askOutPer1k);
    event AttestationUpdated(bytes32 indexed providerId, bytes32 quoteHash);
    event Heartbeat(bytes32 indexed providerId, uint64 blockNumber);
    event ProviderDeregistered(bytes32 indexed providerId);
    event HotUpdated(bytes32 indexed providerId, bool hot);
    event EntityCredentialUpdated(bytes32 indexed providerId, bytes32 credentialHash);

    error AlreadyRegistered();
    error UnknownProvider();
    error NotProviderOperator();
    error BadFeeSplit();

    constructor(address initialOwner) MilOwned(initialOwner) {
        // Compile-time invariant: the fee split must sum to 100 (§5.3).
        if (
            MilConstants.FEE_PROVIDER_PCT + MilConstants.FEE_BURN_PCT + MilConstants.FEE_VALIDATOR_PCT
                + MilConstants.FEE_TREASURY_PCT != 100
        ) revert BadFeeSplit();
    }

    struct RegisterParams {
        bytes32 providerId;
        bytes32 quoteHash;
        bytes32 modelId;
        bytes32 pkReceiptHash;
        bytes32 pkKemHash;
        Tier tier;
        uint32 gpuClassWeight;
        uint64 askInPer1k;
        uint64 askOutPer1k;
        uint32 ttfbMs;
        uint32 minTps;
        bool hot;
        bytes32 entityCredentialHash;
        string region;
        string dataPlaneAddr;
    }

    function register(RegisterParams calldata p) external {
        if (_providers[p.providerId].operator != address(0)) revert AlreadyRegistered();
        if (operatorToProvider[msg.sender] != bytes32(0)) revert AlreadyRegistered();

        _providers[p.providerId] = Provider({
            operator: msg.sender,
            providerId: p.providerId,
            quoteHash: p.quoteHash,
            modelId: p.modelId,
            pkReceiptHash: p.pkReceiptHash,
            pkKemHash: p.pkKemHash,
            tier: p.tier,
            gpuClassWeight: p.gpuClassWeight,
            askInPer1k: p.askInPer1k,
            askOutPer1k: p.askOutPer1k,
            ttfbMs: p.ttfbMs,
            minTps: p.minTps,
            lastHeartbeat: uint64(block.number),
            active: true,
            hot: p.hot,
            entityCredentialHash: p.entityCredentialHash,
            region: p.region,
            dataPlaneAddr: p.dataPlaneAddr
        });
        operatorToProvider[msg.sender] = p.providerId;
        emit ProviderRegistered(p.providerId, msg.sender, p.modelId, p.tier);
    }

    /// @notice Advertise/retract hot (VRAM-resident) status (§13.4a).
    function setHot(bytes32 providerId, bool hot) external onlyProviderOperator(providerId) {
        _providers[providerId].hot = hot;
        emit HotUpdated(providerId, hot);
    }

    /// @notice Attach an FSL entity-bound credential hash (§8.6) for enterprise
    ///         filtering (legal existence / location / DC certification).
    function setEntityCredential(bytes32 providerId, bytes32 credentialHash)
        external
        onlyProviderOperator(providerId)
    {
        _providers[providerId].entityCredentialHash = credentialHash;
        emit EntityCredentialUpdated(providerId, credentialHash);
    }

    modifier onlyProviderOperator(bytes32 providerId) {
        if (_providers[providerId].operator == address(0)) revert UnknownProvider();
        if (_providers[providerId].operator != msg.sender) revert NotProviderOperator();
        _;
    }

    /// @notice Update the ask price + SLA (MSK price tracking is done by the
    ///         provider updating its ask, §6.2).
    function updateAsk(bytes32 providerId, uint64 askInPer1k, uint64 askOutPer1k, uint32 ttfbMs, uint32 minTps)
        external
        onlyProviderOperator(providerId)
    {
        Provider storage pr = _providers[providerId];
        pr.askInPer1k = askInPer1k;
        pr.askOutPer1k = askOutPer1k;
        pr.ttfbMs = ttfbMs;
        pr.minTps = minTps;
        emit ProviderUpdated(providerId, askInPer1k, askOutPer1k);
    }

    /// @notice Refresh the attestation quote hash (per attestation epoch, §13.3).
    function updateAttestation(bytes32 providerId, bytes32 quoteHash) external onlyProviderOperator(providerId) {
        _providers[providerId].quoteHash = quoteHash;
        emit AttestationUpdated(providerId, quoteHash);
    }

    function heartbeat(bytes32 providerId) external onlyProviderOperator(providerId) {
        _providers[providerId].lastHeartbeat = uint64(block.number);
        emit Heartbeat(providerId, uint64(block.number));
    }

    function deregister(bytes32 providerId) external onlyProviderOperator(providerId) {
        _providers[providerId].active = false;
        delete operatorToProvider[msg.sender];
        emit ProviderDeregistered(providerId);
    }

    // --- views (used by JobEscrow / RewardPool / DisputeGame) ---

    function get(bytes32 providerId) external view returns (Provider memory) {
        return _providers[providerId];
    }

    function operatorOf(bytes32 providerId) external view returns (address) {
        return _providers[providerId].operator;
    }

    function pkReceiptHashOf(bytes32 providerId) external view returns (bytes32) {
        return _providers[providerId].pkReceiptHash;
    }

    function asks(bytes32 providerId) external view returns (uint64 askInPer1k, uint64 askOutPer1k) {
        Provider storage pr = _providers[providerId];
        return (pr.askInPer1k, pr.askOutPer1k);
    }

    function isActive(bytes32 providerId) external view returns (bool) {
        return _providers[providerId].active;
    }
}
