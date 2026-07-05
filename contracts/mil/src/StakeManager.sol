// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilConstants, MilOwned} from "./MilCommon.sol";

/// @title StakeManager — MIL provider stake, unbond, and slash (design §5.5).
/// @notice Providers bond MSK toward their `providerId`; unbonding has a 7-day
///         delay (dispute window + DNS-finality margin). Slashing is restricted
///         to the authorized `slasher` (the DisputeGame), which splits a Tier-2
///         mismatch 50/50 challenger/burn. Min stakes are class-configurable
///         (governance) since the wei scale is lane-specific.
contract StakeManager is MilOwned {
    uint256 public constant UNBOND_DELAY = 7 days;

    /// @dev Min bond for class A (Tier 1, TEE) and class B (Tier 2), in wei.
    uint256 public minStakeClassA;
    uint256 public minStakeClassB;

    /// @dev The only address allowed to slash (set to the DisputeGame).
    address public slasher;

    struct Bond {
        uint256 amount; // currently bonded (excludes unbonding)
        uint256 unbonding; // requested-to-unbond, locked until unbondReadyAt
        uint256 unbondReadyAt; // timestamp the unbonding amount becomes withdrawable
    }

    /// @dev staker address → their bond.
    mapping(address => Bond) public bonds;
    /// @dev staker → the providerId they back.
    mapping(address => bytes32) public stakedProvider;

    event Bonded(address indexed staker, bytes32 indexed providerId, uint256 amount, uint256 total);
    event UnbondRequested(address indexed staker, uint256 amount, uint256 readyAt);
    event Withdrawn(address indexed staker, uint256 amount);
    event Slashed(address indexed staker, uint256 amount, address indexed beneficiary, uint256 burned);
    event SlasherUpdated(address indexed slasher);
    event MinStakeUpdated(uint256 classA, uint256 classB);

    error NotSlasher();
    error NothingToWithdraw();
    error UnbondNotReady();
    error InsufficientBonded();
    error ZeroAmount();

    constructor(address initialOwner, uint256 _minStakeClassA, uint256 _minStakeClassB) MilOwned(initialOwner) {
        minStakeClassA = _minStakeClassA;
        minStakeClassB = _minStakeClassB;
    }

    function setSlasher(address _slasher) external onlyOwner {
        slasher = _slasher;
        emit SlasherUpdated(_slasher);
    }

    function setMinStakes(uint256 classA, uint256 classB) external onlyOwner {
        minStakeClassA = classA;
        minStakeClassB = classB;
        emit MinStakeUpdated(classA, classB);
    }

    /// @notice Bond `msg.value` toward `providerId`. Additive.
    function bond(bytes32 providerId) external payable {
        if (msg.value == 0) revert ZeroAmount();
        Bond storage b = bonds[msg.sender];
        b.amount += msg.value;
        stakedProvider[msg.sender] = providerId;
        emit Bonded(msg.sender, providerId, msg.value, b.amount);
    }

    /// @notice Start unbonding `amount`; withdrawable after `UNBOND_DELAY`.
    ///         Resets the timer on the whole unbonding balance (simple + safe).
    function requestUnbond(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        Bond storage b = bonds[msg.sender];
        if (amount > b.amount) revert InsufficientBonded();
        b.amount -= amount;
        b.unbonding += amount;
        b.unbondReadyAt = block.timestamp + UNBOND_DELAY;
        emit UnbondRequested(msg.sender, amount, b.unbondReadyAt);
    }

    /// @notice Withdraw the matured unbonding balance.
    function withdraw() external {
        Bond storage b = bonds[msg.sender];
        uint256 amount = b.unbonding;
        if (amount == 0) revert NothingToWithdraw();
        if (block.timestamp < b.unbondReadyAt) revert UnbondNotReady();
        b.unbonding = 0;
        b.unbondReadyAt = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "MIL: withdraw transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    /// @notice Slash `amount` of `staker`'s ACTIVE bond: half to `beneficiary`
    ///         (the challenger), half burned (§5.5). Only the DisputeGame.
    ///         Slashing hits the active bond first, then the unbonding balance,
    ///         so a provider cannot dodge a slash by unbonding after the offense.
    function slash(address staker, uint256 amount, address payable beneficiary) external {
        if (msg.sender != slasher) revert NotSlasher();
        if (amount == 0) revert ZeroAmount();
        Bond storage b = bonds[staker];
        uint256 total = b.amount + b.unbonding;
        if (amount > total) amount = total; // clamp: cannot slash more than exists
        // consume active bond first, then unbonding
        if (amount <= b.amount) {
            b.amount -= amount;
        } else {
            uint256 fromUnbonding = amount - b.amount;
            b.amount = 0;
            b.unbonding -= fromUnbonding;
        }
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
        emit Slashed(staker, amount, beneficiary, toBurn);
    }

    function bondedAmount(address staker) external view returns (uint256) {
        return bonds[staker].amount;
    }
}
