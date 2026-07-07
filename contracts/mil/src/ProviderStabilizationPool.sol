// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilOwned} from "./MilCommon.sol";

/// @title ProviderStabilizationPool (PSP) — MIL v0.13 §24.7.
/// @notice Holds the counter-cyclical `1 - s` share from the BurnRouter and pays
///         it out per epoch to providers **by verified served-tokens, not bond**
///         — so the support is a fee-side top-up to those who actually served
///         (keeping ADR-0029 D3's "fee = utilization" axis intact). Each entity is
///         capped at `shareCapBps` (5%) of the distributable pool per epoch;
///         standby devices are excluded (the off-chain distributor only submits
///         non-standby served tokens, mirroring the router's indicator denominator).
///
///         Fee-side, not issuance: the pool can only ever pay out flow the network
///         actually earned (routed here by the BurnRouter), so zero revenue ⇒ zero
///         payout — no dilution path (ADR-0029 precondition 5).
///
///         **Pull-payment** (adversarial-review hardening): `distribute()` only
///         *credits* each provider's `owed` balance — it makes NO external call —
///         and each provider `withdraw()`s independently. A hostile/reverting
///         provider address therefore harms only itself; it can never revert or
///         gas-bomb the whole epoch's distribution (the classic push-payment
///         griefing DoS). Distribution accounting runs over `balance − totalOwed`
///         so already-credited-but-unwithdrawn flow is never re-distributed.
contract ProviderStabilizationPool is MilOwned {
    uint256 internal constant BPS = 10_000;

    /// Per-entity cap as a fraction of the distributable pool at distribution time.
    uint256 public shareCapBps;
    /// The authorized distributor (off-chain served-token aggregator).
    address public distributor;
    /// Epochs already distributed (anti-replay).
    mapping(uint256 => bool) public distributed;

    /// Pull-payment ledger: unwithdrawn credits per provider.
    mapping(address => uint256) public owed;
    /// Sum of all unwithdrawn credits — a liability against `balance`. Distribution
    /// runs over `balance − totalOwed`, so a prior epoch's credited-but-unwithdrawn
    /// amount is never counted as fresh distributable flow.
    uint256 public totalOwed;

    event DistributorUpdated(address indexed distributor);
    event ShareCapUpdated(uint256 shareCapBps);
    event Funded(address indexed from, uint256 amount);
    event Distributed(uint256 indexed epoch, uint256 totalCredited, uint256 recipients);
    /// @notice Per-provider allocation — the audit trail an epoch's split can be
    ///         reconciled against off-chain (against the router's `I` indicator).
    event Credited(uint256 indexed epoch, address indexed provider, uint256 amount);
    event Withdrawn(address indexed provider, uint256 amount);

    error NotDistributor();
    error EpochAlreadyDistributed();
    error LengthMismatch();
    error NoServedTokens();
    error BadShareCap();
    error TransferFailed();
    /// providers[] must be strictly ascending (unique) so the per-entity cap binds
    /// per payout address; the distributor merges same-address ids upstream.
    error ProvidersNotSorted();
    error NothingToWithdraw();

    constructor(address initialOwner, uint256 _shareCapBps) MilOwned(initialOwner) {
        if (_shareCapBps == 0 || _shareCapBps > BPS) revert BadShareCap();
        shareCapBps = _shareCapBps;
    }

    modifier onlyDistributor() {
        if (msg.sender != distributor) revert NotDistributor();
        _;
    }

    function setDistributor(address _distributor) external onlyOwner {
        distributor = _distributor;
        emit DistributorUpdated(_distributor);
    }

    function setShareCap(uint256 _shareCapBps) external onlyOwner {
        if (_shareCapBps == 0 || _shareCapBps > BPS) revert BadShareCap();
        shareCapBps = _shareCapBps;
        emit ShareCapUpdated(_shareCapBps);
    }

    /// @dev The BurnRouter (and anyone) funds the pool by sending value.
    receive() external payable {
        emit Funded(msg.sender, msg.value);
    }

    /// @notice Credit the distributable pool for `epoch` by served-tokens:
    ///         `owed_i += min(served_i / Σserved, shareCap) × distributable`, where
    ///         `distributable = balance − totalOwed`. The un-allocated remainder
    ///         (from the cap and integer flooring) simply stays in `balance` and
    ///         rolls into the next epoch's `distributable`. This function makes NO
    ///         external call — providers pull via [`withdraw`].
    ///
    ///         `providers` MUST be strictly ascending (hence unique): the per-entity
    ///         5% cap then binds per payout address, and the distributor is expected
    ///         to merge multiple provider-ids that share one payout address (summing
    ///         their served tokens) before calling. Standby providers MUST be omitted
    ///         (excluded from both the payout and the denominator).
    function distribute(uint256 epoch, address[] calldata providers, uint256[] calldata servedTokens)
        external
        onlyDistributor
    {
        if (distributed[epoch]) revert EpochAlreadyDistributed();
        if (providers.length != servedTokens.length) revert LengthMismatch();

        uint256 totalServed;
        for (uint256 i = 0; i < servedTokens.length; i++) {
            totalServed += servedTokens[i];
        }
        if (totalServed == 0) revert NoServedTokens();

        distributed[epoch] = true; // effects before any state-dependent read
        // Distribute only the fresh (uncommitted) balance — never re-count flow
        // already credited to a prior epoch's providers but not yet withdrawn.
        uint256 distributable = address(this).balance - totalOwed;
        uint256 cap = distributable * shareCapBps / BPS;

        uint256 totalCredited;
        address prev = address(0);
        for (uint256 i = 0; i < providers.length; i++) {
            address p = providers[i];
            if (p <= prev) revert ProvidersNotSorted(); // strictly ascending ⇒ unique
            prev = p;

            uint256 amount = servedTokens[i] * distributable / totalServed;
            if (amount > cap) amount = cap;
            if (amount == 0) continue;

            owed[p] += amount;
            totalCredited += amount;
            emit Credited(epoch, p, amount);
        }
        totalOwed += totalCredited;
        emit Distributed(epoch, totalCredited, providers.length);
    }

    /// @notice Pull the caller's accrued top-up. A reverting recipient harms only
    ///         itself. Effects-before-interactions: the balance is zeroed and the
    ///         liability decremented before the transfer, so a reentrant call sees
    ///         nothing to withdraw.
    function withdraw() external {
        uint256 amount = owed[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        owed[msg.sender] = 0;
        totalOwed -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Withdrawn(msg.sender, amount);
    }
}
