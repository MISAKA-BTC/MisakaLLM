// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilConstants, MilOwned} from "./MilCommon.sol";

/// @title DelegatedStakeManager — MSK-holder delegation to GPU providers (§16.2).
/// @notice Lets an MSK holder delegate stake toward a provider's pool and earn
///         a set share of the provider's income (§16.2), while a Tier-2 slash
///         is borne **proportionally** by every delegator (§12-9). Proportional
///         slashing/rewards without per-delegator iteration is achieved with a
///         **shares** accounting per provider pool: a slash lowers the pool's
///         exchange rate, a reward raises it, and each delegator's claim is
///         `shares · poolBalance / totalShares`. Complements the provider's own
///         self-stake in `StakeManager`.
contract DelegatedStakeManager is MilOwned {
    uint256 public constant UNDELEGATE_DELAY = 7 days;

    /// @dev The DisputeGame (authorized to slash).
    address public slasher;

    struct Pool {
        uint256 balance; // total MSK backing the pool (delegated + rewards − slashes)
        uint256 totalShares; // total shares outstanding
        uint16 delegatorSharePct; // provider-set 10..30% of income routed to delegators (§16.2)
        address operator; // the provider operator (sets the share, forwards rewards)
    }

    struct Unbonding {
        uint256 amount;
        uint256 readyAt;
    }

    /// @dev providerId → pool.
    mapping(bytes32 => Pool) public pools;
    /// @dev providerId → delegator → shares.
    mapping(bytes32 => mapping(address => uint256)) public shares;
    /// @dev providerId → delegator → pending withdrawal.
    mapping(bytes32 => mapping(address => Unbonding)) public unbonding;

    event PoolOpened(bytes32 indexed providerId, address indexed operator, uint16 delegatorSharePct);
    event Delegated(bytes32 indexed providerId, address indexed delegator, uint256 amount, uint256 sharesMinted);
    event UndelegateRequested(bytes32 indexed providerId, address indexed delegator, uint256 amount, uint256 readyAt);
    event Withdrawn(bytes32 indexed providerId, address indexed delegator, uint256 amount);
    event RewardsDistributed(bytes32 indexed providerId, uint256 amount);
    event PoolSlashed(bytes32 indexed providerId, uint256 amount, uint256 burned);
    event SlasherUpdated(address indexed slasher);

    error NotSlasher();
    error PoolNotOpen();
    error PoolExists();
    error BadSharePct();
    error ZeroAmount();
    error InsufficientShares();
    error NothingToWithdraw();
    error NotReady();
    error NotOperator();

    constructor(address initialOwner) MilOwned(initialOwner) {}

    function setSlasher(address _slasher) external onlyOwner {
        slasher = _slasher;
        emit SlasherUpdated(_slasher);
    }

    /// @notice A provider opens its delegation pool, setting the delegator income
    ///         share (10..30%, §16.2 / §10 delegation_fee is the complement).
    function openPool(bytes32 providerId, uint16 delegatorSharePct) external {
        if (pools[providerId].operator != address(0)) revert PoolExists();
        if (delegatorSharePct < 10 || delegatorSharePct > 30) revert BadSharePct();
        pools[providerId] =
            Pool({balance: 0, totalShares: 0, delegatorSharePct: delegatorSharePct, operator: msg.sender});
        emit PoolOpened(providerId, msg.sender, delegatorSharePct);
    }

    /// @notice Delegate `msg.value` toward `providerId`, minting pool shares at
    ///         the current exchange rate.
    function delegate(bytes32 providerId) external payable {
        if (msg.value == 0) revert ZeroAmount();
        Pool storage p = pools[providerId];
        if (p.operator == address(0)) revert PoolNotOpen();
        uint256 minted = p.totalShares == 0 ? msg.value : (msg.value * p.totalShares) / p.balance;
        p.balance += msg.value;
        p.totalShares += minted;
        shares[providerId][msg.sender] += minted;
        emit Delegated(providerId, msg.sender, msg.value, minted);
    }

    /// @notice The provider forwards the delegators' income share (§16.2), which
    ///         raises the pool exchange rate for all delegators pro-rata.
    function distributeRewards(bytes32 providerId) external payable {
        Pool storage p = pools[providerId];
        if (p.operator == address(0)) revert PoolNotOpen();
        if (msg.sender != p.operator) revert NotOperator();
        if (msg.value == 0) revert ZeroAmount();
        p.balance += msg.value; // no new shares → every share is worth more
        emit RewardsDistributed(providerId, msg.value);
    }

    /// @notice Redeem `shareAmount` shares, starting the 7-day undelegation timer
    ///         on the underlying MSK (valued at the current exchange rate).
    function requestUndelegate(bytes32 providerId, uint256 shareAmount) external {
        if (shareAmount == 0) revert ZeroAmount();
        Pool storage p = pools[providerId];
        uint256 held = shares[providerId][msg.sender];
        if (shareAmount > held) revert InsufficientShares();
        uint256 amount = (shareAmount * p.balance) / p.totalShares;
        shares[providerId][msg.sender] = held - shareAmount;
        p.totalShares -= shareAmount;
        p.balance -= amount;
        Unbonding storage u = unbonding[providerId][msg.sender];
        u.amount += amount;
        u.readyAt = block.timestamp + UNDELEGATE_DELAY;
        emit UndelegateRequested(providerId, msg.sender, amount, u.readyAt);
    }

    /// @notice Withdraw matured undelegated MSK.
    function withdraw(bytes32 providerId) external {
        Unbonding storage u = unbonding[providerId][msg.sender];
        uint256 amount = u.amount;
        if (amount == 0) revert NothingToWithdraw();
        if (block.timestamp < u.readyAt) revert NotReady();
        u.amount = 0;
        u.readyAt = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "MIL: undelegate transfer failed");
        emit Withdrawn(providerId, msg.sender, amount);
    }

    /// @notice Slash the pool by `amount`: half to `beneficiary` (challenger),
    ///         half burned (§5.5). The loss is borne pro-rata by every delegator
    ///         via the dropped exchange rate — no iteration. Only the DisputeGame.
    function slashPool(bytes32 providerId, uint256 amount, address payable beneficiary) external {
        if (msg.sender != slasher) revert NotSlasher();
        Pool storage p = pools[providerId];
        if (p.operator == address(0)) revert PoolNotOpen();
        if (amount > p.balance) amount = p.balance;
        if (amount == 0) revert ZeroAmount();
        p.balance -= amount; // exchange rate drops → all delegators lose pro-rata
        uint256 toChallenger = amount / 2;
        uint256 toBurn = amount - toChallenger;
        if (toChallenger > 0) {
            (bool ok,) = beneficiary.call{value: toChallenger}("");
            require(ok, "MIL: challenger transfer failed");
        }
        if (toBurn > 0) {
            (bool ok,) = payable(MilConstants.BURN_SINK).call{value: toBurn}("");
            require(ok, "MIL: burn transfer failed");
        }
        emit PoolSlashed(providerId, amount, toBurn);
    }

    /// @notice A delegator's current underlying MSK value (shares × rate).
    function delegatedValue(bytes32 providerId, address delegator) external view returns (uint256) {
        Pool storage p = pools[providerId];
        if (p.totalShares == 0) return 0;
        return (shares[providerId][delegator] * p.balance) / p.totalShares;
    }
}
