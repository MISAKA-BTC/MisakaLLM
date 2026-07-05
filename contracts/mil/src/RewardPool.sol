// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilConstants, MilOwned} from "./MilCommon.sol";

/// @title RewardPool — Compute Bootstrap Fund receiver + epoch subsidy payout
///         + fee-split sinks (design §5.2b, §5.4, §5.3).
/// @notice Holds the bootstrap fund and the validator-pool + treasury fee
///         shares that `JobEscrow` forwards. Epoch subsidy payouts are computed
///         off-chain from the §5.4 weight formula (the √-dampened weight is
///         impractical to recompute on-chain) and submitted by the authorized
///         `distributor`; on-chain the pool enforces (a) the per-entity 5% share
///         cap, (b) that the epoch total never exceeds the pool balance, and (c)
///         one distribution per epoch. Treasury funds are withdrawable by the
///         treasury address.
contract RewardPool is MilOwned {
    /// @dev Per-entity share cap of an epoch pool: 5% = 50_000 ppm (§5.4).
    uint256 public constant SHARE_CAP_PPM = 50_000;

    address public distributor; // submits epoch payouts (an operator/keeper role)
    address public treasury; // withdraws the accumulated treasury share
    address public jobEscrow; // the only address allowed to push fee shares

    /// @dev Accumulated treasury fee share (§5.3), withdrawable by `treasury`.
    uint256 public treasuryBalance;
    /// @dev Accumulated validator-pool fee share (§5.3), added to the subsidy pool.
    uint256 public validatorPoolBalance;
    /// @dev Bootstrap-fund + validator-pool funds available for epoch subsidy.
    uint256 public subsidyPool;

    mapping(uint256 => bool) public epochDistributed;

    event BootstrapFunded(address indexed from, uint256 amount);
    event ValidatorShareReceived(uint256 amount);
    event TreasuryShareReceived(uint256 amount);
    event EpochDistributed(uint256 indexed epoch, uint256 total, uint256 recipients);
    event TreasuryWithdrawn(address indexed to, uint256 amount);
    event DistributorUpdated(address indexed distributor);
    event JobEscrowUpdated(address indexed jobEscrow);

    error NotDistributor();
    error NotJobEscrow();
    error NotTreasury();
    error EpochAlreadyDistributed();
    error PayoutExceedsPool();
    error ShareCapExceeded();
    error LengthMismatch();

    constructor(address initialOwner, address _treasury) MilOwned(initialOwner) {
        treasury = _treasury;
    }

    function setDistributor(address _distributor) external onlyOwner {
        distributor = _distributor;
        emit DistributorUpdated(_distributor);
    }

    function setTreasury(address _treasury) external onlyOwner {
        treasury = _treasury;
    }

    function setJobEscrow(address _jobEscrow) external onlyOwner {
        jobEscrow = _jobEscrow;
        emit JobEscrowUpdated(_jobEscrow);
    }

    /// @notice Fund the bootstrap pool (§5.2b): the key-ceremony stream tops up
    ///         the subsidy pool over 4 years.
    function fundBootstrap() external payable {
        subsidyPool += msg.value;
        emit BootstrapFunded(msg.sender, msg.value);
    }

    /// @notice Receive the 4% validator-pool fee share from JobEscrow (§5.3).
    ///         Rolls into the subsidy pool (validators are paid from the same
    ///         epoch distribution machinery).
    function receiveValidatorShare() external payable {
        if (msg.sender != jobEscrow) revert NotJobEscrow();
        validatorPoolBalance += msg.value;
        subsidyPool += msg.value;
        emit ValidatorShareReceived(msg.value);
    }

    /// @notice Receive the 3% treasury fee share from JobEscrow (§5.3).
    function receiveTreasuryShare() external payable {
        if (msg.sender != jobEscrow) revert NotJobEscrow();
        treasuryBalance += msg.value;
        emit TreasuryShareReceived(msg.value);
    }

    /// @notice Distribute one epoch's subsidy pool (§5.4). `poolForEpoch` is the
    ///         portion of `subsidyPool` allocated to this epoch (chosen by the
    ///         distributor per the逓減 schedule); each payout must be ≤ 5% of it
    ///         and the sum ≤ the epoch pool ≤ the contract's subsidy balance.
    function distributeEpoch(
        uint256 epoch,
        uint256 poolForEpoch,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external {
        if (msg.sender != distributor) revert NotDistributor();
        if (epochDistributed[epoch]) revert EpochAlreadyDistributed();
        if (recipients.length != amounts.length) revert LengthMismatch();
        if (poolForEpoch > subsidyPool) revert PayoutExceedsPool();

        uint256 cap = (poolForEpoch * SHARE_CAP_PPM) / 1_000_000;
        uint256 total;
        for (uint256 i = 0; i < amounts.length; i++) {
            if (amounts[i] > cap) revert ShareCapExceeded();
            total += amounts[i];
        }
        if (total > poolForEpoch) revert PayoutExceedsPool();

        epochDistributed[epoch] = true;
        subsidyPool -= total; // only the distributed amount leaves the pool; surplus rolls forward
        for (uint256 i = 0; i < recipients.length; i++) {
            if (amounts[i] == 0) continue;
            (bool ok,) = payable(recipients[i]).call{value: amounts[i]}("");
            require(ok, "MIL: subsidy transfer failed");
        }
        emit EpochDistributed(epoch, total, recipients.length);
    }

    /// @notice Withdraw the accumulated treasury share to the treasury address.
    function withdrawTreasury(uint256 amount) external {
        if (msg.sender != treasury) revert NotTreasury();
        require(amount <= treasuryBalance, "MIL: over treasury balance");
        treasuryBalance -= amount;
        (bool ok,) = payable(treasury).call{value: amount}("");
        require(ok, "MIL: treasury transfer failed");
        emit TreasuryWithdrawn(treasury, amount);
    }
}
