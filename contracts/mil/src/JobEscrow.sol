// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilConstants, MilOwned, MilReceipt, MilReceiptLib} from "./MilCommon.sol";

interface IProviderRegistryView {
    function operatorOf(bytes32 providerId) external view returns (address);
    function pkReceiptHashOf(bytes32 providerId) external view returns (bytes32);
    function asks(bytes32 providerId) external view returns (uint64 askInPer1k, uint64 askOutPer1k);
    function isActive(bytes32 providerId) external view returns (bool);
}

interface IRewardPoolSink {
    function receiveValidatorShare() external payable;
    function receiveTreasuryShare() external payable;
}

/// @title JobEscrow — MIL session escrow + receipt settlement (design §5.6, §8.4, §13.2).
/// @notice The requester locks MSK once per SESSION (§13.2 — not per request);
///         the provider settles against the single latest cumulative receipt
///         (§4.1) any number of times. On each claim the newly-earned amount is
///         split 88/5/4/3 (provider/burn/validator-pool/treasury, §5.3). The
///         provider's maximum exposure is one receipt interval (§5.6): unclaimed
///         work simply refunds to the requester. Large claims/refunds require the
///         escrow's open block to be DNS-final (§8.4).
contract JobEscrow is MilOwned {
    using MilReceiptLib for MilReceipt;

    IProviderRegistryView public immutable registry;
    IRewardPoolSink public immutable rewardPool;

    /// @dev Claims/refunds whose cumulative settled cost exceeds this require a
    ///      DNS-final open block (§8.4). Governance-tunable.
    uint256 public dnsFinalClaimThreshold;
    /// @dev Latest DNS-finalized block number, fed by the authorized reporter.
    ///      (v1: the node pushes the stake-confirmed anchor's blue-score-mapped
    ///      block; a system precompile exposure is the production follow-on.)
    uint256 public dnsFinalizedBlock;
    address public dnsReporter;

    struct Escrow {
        address requester;
        bytes32 providerId;
        bytes32 cmReq; // salted request commitment (§3.3)
        bytes32 sessionHash; // keccak256(sessionId) — bound to every receipt
        uint256 locked; // MSK locked at open (the session budget)
        uint256 settledCost; // cumulative fee settled so far (pre-split)
        uint64 lastCounter; // last receipt counter claimed (monotonicity)
        uint64 openBlock; // EVM block the escrow opened at (oracle DNS-final path)
        uint256 openDaa; // L1 DAA at open from F005 (precompile DNS-final path); 0 if F005 inert
        bool closed;
        bool finalized; // a final receipt was claimed → no more claims
    }

    mapping(bytes32 => Escrow) internal _escrows;

    uint256 private _reentryGuard;

    /// v0.13 §24.7: optional counter-cyclical burn router. When set, the 5% burn
    /// leg is sent here (which splits it between the native eater and the Provider
    /// Stabilization Pool by network revenue); when unset (default), it goes
    /// straight to BURN_SINK — byte-identical to the pre-router behavior.
    address public burnRouter;

    event Opened(bytes32 indexed escrowId, address indexed requester, bytes32 indexed providerId, uint256 locked);
    event Claimed(
        bytes32 indexed escrowId,
        bytes32 indexed providerId,
        uint64 counter,
        uint256 delta,
        uint256 toProvider,
        bool isFinal
    );
    event Refunded(bytes32 indexed escrowId, address indexed requester, uint256 amount);
    event Closed(bytes32 indexed escrowId);
    event DnsFinalizedBlockUpdated(uint256 blockNumber);
    event BurnRouterUpdated(address indexed router);

    error EscrowExists();
    error UnknownEscrow();
    error NotRequester();
    error NotProviderOperator();
    error ProviderInactive();
    error SessionMismatch();
    error PubkeyMismatch();
    error BadReceiptSignature();
    error NonMonotonicCounter();
    error AlreadyFinalized();
    error CostExceedsLocked();
    error NotClosed();
    error NotDnsFinal();
    error Reentrancy();
    error ZeroValue();

    modifier nonReentrant() {
        if (_reentryGuard == 1) revert Reentrancy();
        _reentryGuard = 1;
        _;
        _reentryGuard = 0;
    }

    constructor(address initialOwner, address _registry, address _rewardPool, uint256 _dnsFinalClaimThreshold)
        MilOwned(initialOwner)
    {
        registry = IProviderRegistryView(_registry);
        rewardPool = IRewardPoolSink(_rewardPool);
        dnsFinalClaimThreshold = _dnsFinalClaimThreshold;
    }

    function setDnsReporter(address reporter) external onlyOwner {
        dnsReporter = reporter;
    }

    function setDnsFinalClaimThreshold(uint256 threshold) external onlyOwner {
        dnsFinalClaimThreshold = threshold;
    }

    /// @notice v0.13 §24.7: point the 5% burn leg at the counter-cyclical
    ///         BurnRouter. Unset (address(0), the default) keeps the burn going
    ///         straight to BURN_SINK — identical to the pre-router behavior.
    function setBurnRouter(address router) external onlyOwner {
        burnRouter = router;
        emit BurnRouterUpdated(router);
    }

    /// @notice The node/keeper pushes the latest DNS-finalized block (§8.4).
    function reportDnsFinalizedBlock(uint256 blockNumber) external {
        require(msg.sender == dnsReporter, "MIL: not dns reporter");
        require(blockNumber >= dnsFinalizedBlock, "MIL: dns block must not regress");
        dnsFinalizedBlock = blockNumber;
        emit DnsFinalizedBlockUpdated(blockNumber);
    }

    /// @notice Open a session escrow, locking `msg.value` as the session budget.
    ///         `escrowId` is chosen by the requester (e.g. keccak of sessionId)
    ///         and must be unused.
    function open(bytes32 escrowId, bytes32 providerId, bytes calldata sessionId, bytes32 cmReq) external payable {
        if (msg.value == 0) revert ZeroValue();
        if (_escrows[escrowId].requester != address(0)) revert EscrowExists();
        if (!registry.isActive(providerId)) revert ProviderInactive();
        require(sessionId.length == 64, "MIL: sessionId must be 64 bytes");

        (, uint256 currentDaa,) = _readF005();
        _escrows[escrowId] = Escrow({
            requester: msg.sender,
            providerId: providerId,
            cmReq: cmReq,
            sessionHash: keccak256(sessionId),
            locked: msg.value,
            settledCost: 0,
            lastCounter: 0,
            openBlock: uint64(block.number),
            openDaa: currentDaa,
            closed: false,
            finalized: false
        });
        emit Opened(escrowId, msg.sender, providerId, msg.value);
    }

    /// @notice Settle against the latest cumulative receipt. Only the provider
    ///         operator. Verifies the ML-DSA-87 receipt (F003 v0x03), enforces
    ///         session + counter monotonicity, computes the new cumulative cost
    ///         from the registered ask, and splits the delta 88/5/4/3.
    function claim(bytes32 escrowId, MilReceipt calldata receipt, bytes calldata pubkey, bytes calldata signature)
        external
        nonReentrant
    {
        Escrow storage e = _escrows[escrowId];
        if (e.requester == address(0)) revert UnknownEscrow();
        if (e.finalized) revert AlreadyFinalized();
        if (msg.sender != registry.operatorOf(e.providerId)) revert NotProviderOperator();

        // the receipt must be for THIS session and this provider's key
        if (keccak256(receipt.sessionId) != e.sessionHash) revert SessionMismatch();
        if (keccak256(pubkey) != registry.pkReceiptHashOf(e.providerId)) revert PubkeyMismatch();
        if (receipt.counter <= e.lastCounter) revert NonMonotonicCounter();

        // ML-DSA-87 verify via F003 v0x03
        MilReceipt memory r = receipt;
        if (!r.verify(pubkey, signature)) revert BadReceiptSignature();

        // cumulative cost from the registered ask (§6.2), rounded up per side
        (uint64 askIn, uint64 askOut) = registry.asks(e.providerId);
        uint256 newCost = _ceilDiv(uint256(askIn) * receipt.cumTokensIn, 1000)
            + _ceilDiv(uint256(askOut) * receipt.cumTokensOut, 1000);
        require(newCost >= e.settledCost, "MIL: cost must not decrease");
        if (newCost > e.locked) revert CostExceedsLocked();

        // §8.4: large cumulative settlements require a DNS-final open block
        if (newCost > dnsFinalClaimThreshold && !_openIsDnsFinal(e)) revert NotDnsFinal();

        uint256 delta = newCost - e.settledCost;
        e.settledCost = newCost;
        e.lastCounter = receipt.counter;
        if (receipt.isFinal) e.finalized = true;

        (uint256 toProvider, uint256 toBurn, uint256 toValidator, uint256 toTreasury) = _split(delta);
        address providerAddr = registry.operatorOf(e.providerId);

        if (toProvider > 0) {
            (bool ok,) = payable(providerAddr).call{value: toProvider}("");
            require(ok, "MIL: provider transfer failed");
        }
        if (toBurn > 0) {
            // v0.13 §24.7: route the burn leg through the counter-cyclical
            // BurnRouter when set (it splits burn vs Provider Stabilization Pool
            // by network revenue); otherwise burn directly to BURN_SINK.
            //
            // Liveness decoupling (adversarial-review hardening): the router is a
            // live external dependency on the critical claim path. If a set router
            // reverts (governance misconfig / a later-broken pool), fall back to a
            // direct BURN_SINK send so the provider/validator/treasury legs still
            // settle. BURN_SINK (0x…dEaD) is an EOA and can never revert, so the
            // burn — and the whole claim — always completes.
            bool burned;
            if (burnRouter != address(0)) {
                (burned,) = burnRouter.call{value: toBurn}("");
            }
            if (!burned) {
                (bool ok,) = payable(MilConstants.BURN_SINK).call{value: toBurn}("");
                require(ok, "MIL: burn transfer failed");
            }
        }
        if (toValidator > 0) rewardPool.receiveValidatorShare{value: toValidator}();
        if (toTreasury > 0) rewardPool.receiveTreasuryShare{value: toTreasury}();

        emit Claimed(escrowId, e.providerId, receipt.counter, delta, toProvider, receipt.isFinal);
    }

    /// @notice Close the escrow (requester or provider), enabling refund of the
    ///         unsettled remainder.
    function close(bytes32 escrowId) external {
        Escrow storage e = _escrows[escrowId];
        if (e.requester == address(0)) revert UnknownEscrow();
        bool isParty = msg.sender == e.requester || msg.sender == registry.operatorOf(e.providerId);
        if (!isParty) revert NotRequester();
        e.closed = true;
        emit Closed(escrowId);
    }

    /// @notice Refund the requester the unsettled remainder after close. Large
    ///         refunds also require a DNS-final open block (§8.4).
    function refund(bytes32 escrowId) external nonReentrant {
        Escrow storage e = _escrows[escrowId];
        if (e.requester == address(0)) revert UnknownEscrow();
        if (msg.sender != e.requester) revert NotRequester();
        if (!e.closed) revert NotClosed();
        uint256 remainder = e.locked - e.settledCost;
        require(remainder > 0, "MIL: nothing to refund");
        if (remainder > dnsFinalClaimThreshold && !_openIsDnsFinal(e)) revert NotDnsFinal();

        e.locked = e.settledCost; // remainder consumed
        (bool ok,) = payable(e.requester).call{value: remainder}("");
        require(ok, "MIL: refund transfer failed");
        emit Refunded(escrowId, e.requester, remainder);
    }

    // --- views / helpers ---

    function get(bytes32 escrowId) external view returns (Escrow memory) {
        return _escrows[escrowId];
    }

    function _split(uint256 amount)
        internal
        pure
        returns (uint256 toProvider, uint256 toBurn, uint256 toValidator, uint256 toTreasury)
    {
        toBurn = (amount * MilConstants.FEE_BURN_PCT) / 100;
        toValidator = (amount * MilConstants.FEE_VALIDATOR_PCT) / 100;
        toTreasury = (amount * MilConstants.FEE_TREASURY_PCT) / 100;
        toProvider = amount - toBurn - toValidator - toTreasury; // remainder → provider (lossless)
    }

    function _ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return a == 0 ? 0 : (a - 1) / b + 1;
    }

    /// @dev Read the F005 DNS-finality precompile (§8.4). `active` is false when
    ///      F005 is fenced-inert (returns no data) — callers then fall back to
    ///      the oracle. Never reverts.
    function _readF005() internal view returns (bool active, uint256 currentDaa, uint256 dnsFinalDaa) {
        (bool ok, bytes memory ret) = MilConstants.F005.staticcall("");
        if (ok && ret.length == 64) {
            (currentDaa, dnsFinalDaa) = abi.decode(ret, (uint256, uint256));
            active = true;
        }
    }

    /// @dev Whether an escrow's open is DNS-final (§8.4). Prefers the F005
    ///      precompile (open-block L1 DAA ≤ latest DNS-final anchor DAA); when
    ///      F005 is inert, falls back to the authorized-reporter oracle
    ///      (open EVM block ≤ the reported DNS-finalized block).
    function _openIsDnsFinal(Escrow storage e) internal view returns (bool) {
        (bool active,, uint256 dnsFinalDaa) = _readF005();
        if (active) {
            return e.openDaa != 0 && e.openDaa <= dnsFinalDaa;
        }
        return e.openBlock <= dnsFinalizedBlock;
    }
}
