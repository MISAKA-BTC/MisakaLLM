// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilOwned} from "./MilCommon.sol";

/// @title Faucet — experience-credit dispenser (design §14.3c / §10 faucet).
/// @notice Dispenses a small MSK amount (1–2 conversations' worth) from the
///         Bootstrap Fund so a new user can try MIL without procuring MSK.
///         Sybil-suppressed by (a) a per-address cooldown window and (b) a light
///         proof-of-work: the caller must find a `nonce` such that
///         `keccak256(recipient ‖ epoch ‖ nonce)` has ≥ `powBits` leading zero
///         bits, making mass-farming costly without a full PoW chain.
contract Faucet is MilOwned {
    /// @dev MSK per successful claim.
    uint256 public dripAmount;
    /// @dev Cooldown between claims per recipient.
    uint256 public cooldown;
    /// @dev Required leading zero bits of the PoW digest.
    uint8 public powBits;
    /// @dev Rotating epoch (bumpable by owner) so stale PoW solutions expire.
    uint256 public epoch;

    mapping(address => uint256) public lastClaim;

    event Funded(address indexed from, uint256 amount);
    event Claimed(address indexed recipient, uint256 amount);
    event ParamsUpdated(uint256 dripAmount, uint256 cooldown, uint8 powBits);
    event EpochBumped(uint256 epoch);

    error CooldownActive(uint256 readyAt);
    error BadPow();
    error Drained();

    constructor(address initialOwner, uint256 _dripAmount, uint256 _cooldown, uint8 _powBits) MilOwned(initialOwner) {
        dripAmount = _dripAmount;
        cooldown = _cooldown;
        powBits = _powBits;
    }

    /// @notice Top up the faucet from the Bootstrap Fund.
    function fund() external payable {
        emit Funded(msg.sender, msg.value);
    }

    function setParams(uint256 _dripAmount, uint256 _cooldown, uint8 _powBits) external onlyOwner {
        dripAmount = _dripAmount;
        cooldown = _cooldown;
        powBits = _powBits;
        emit ParamsUpdated(_dripAmount, _cooldown, _powBits);
    }

    /// @notice Rotate the PoW epoch (invalidates precomputed solutions).
    function bumpEpoch() external onlyOwner {
        epoch += 1;
        emit EpochBumped(epoch);
    }

    /// @notice Whether `digest` has at least `bits` leading zero bits.
    function _hasLeadingZeroBits(bytes32 digest, uint8 bits) internal pure returns (bool) {
        // digest < 2^(256-bits)  ⇔  the top `bits` bits are zero.
        return uint256(digest) < (uint256(1) << (256 - bits));
    }

    /// @notice The PoW challenge digest for `recipient` at the current epoch.
    function challenge(address recipient, uint256 nonce) public view returns (bytes32) {
        return keccak256(abi.encodePacked(recipient, epoch, nonce));
    }

    /// @notice Claim the drip for `recipient` by presenting a valid PoW `nonce`.
    ///         Anyone may submit on a recipient's behalf (a relayer), but the
    ///         cooldown is keyed to the recipient.
    function claim(address recipient, uint256 nonce) external {
        uint256 ready = lastClaim[recipient] + cooldown;
        if (lastClaim[recipient] != 0 && block.timestamp < ready) revert CooldownActive(ready);
        if (!_hasLeadingZeroBits(challenge(recipient, nonce), powBits)) revert BadPow();
        if (address(this).balance < dripAmount) revert Drained();
        lastClaim[recipient] = block.timestamp;
        (bool ok,) = payable(recipient).call{value: dripAmount}("");
        require(ok, "MIL: faucet transfer failed");
        emit Claimed(recipient, dripAmount);
    }
}
