// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilOwned} from "./MilCommon.sol";

interface IJobEscrowOpen {
    function open(bytes32 escrowId, bytes32 providerId, bytes calldata sessionId, bytes32 cmReq) external payable;
}

/// @title Paymaster — sponsored escrow opens (design §14.3b).
/// @notice An app developer deposits MSK and authorizes a relayer to open
///         `JobEscrow` sessions on behalf of end-users, who pay in fiat
///         off-chain. The Paymaster becomes the on-chain requester (refunds
///         return here), so end-users never need a wallet — MIL as a B2B2C
///         inference base. Per-sponsor balance + a per-open cap bound exposure.
contract Paymaster is MilOwned {
    IJobEscrowOpen public immutable jobEscrow;

    /// @dev sponsor (app dev) → deposited balance.
    mapping(address => uint256) public balanceOf;
    /// @dev sponsor → authorized relayer that may spend its balance.
    mapping(address => address) public relayerOf;
    /// @dev sponsor → max MSK per sponsored open (0 = unset → blocked).
    mapping(address => uint256) public perOpenCap;

    event Deposited(address indexed sponsor, uint256 amount, uint256 balance);
    event Withdrawn(address indexed sponsor, uint256 amount);
    event RelayerSet(address indexed sponsor, address indexed relayer);
    event PerOpenCapSet(address indexed sponsor, uint256 cap);
    event Sponsored(address indexed sponsor, bytes32 indexed escrowId, uint256 amount);

    error NotRelayer();
    error OverCap();
    error InsufficientBalance();
    error ZeroAmount();

    constructor(address initialOwner, address _jobEscrow) MilOwned(initialOwner) {
        jobEscrow = IJobEscrowOpen(_jobEscrow);
    }

    /// @notice Deposit MSK to sponsor future opens.
    function deposit() external payable {
        if (msg.value == 0) revert ZeroAmount();
        balanceOf[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value, balanceOf[msg.sender]);
    }

    /// @notice Withdraw unspent sponsor balance.
    function withdraw(uint256 amount) external {
        if (amount > balanceOf[msg.sender]) revert InsufficientBalance();
        balanceOf[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "MIL: paymaster withdraw failed");
        emit Withdrawn(msg.sender, amount);
    }

    function setRelayer(address relayer) external {
        relayerOf[msg.sender] = relayer;
        emit RelayerSet(msg.sender, relayer);
    }

    function setPerOpenCap(uint256 cap) external {
        perOpenCap[msg.sender] = cap;
        emit PerOpenCapSet(msg.sender, cap);
    }

    /// @notice The sponsor's authorized relayer opens a `JobEscrow` session
    ///         funded from the sponsor's balance (≤ its per-open cap). Refunds
    ///         return to this contract; the sponsor reclaims them via [`reclaim`].
    function sponsorOpen(
        address sponsor,
        uint256 amount,
        bytes32 escrowId,
        bytes32 providerId,
        bytes calldata sessionId,
        bytes32 cmReq
    ) external {
        if (msg.sender != relayerOf[sponsor]) revert NotRelayer();
        if (amount == 0) revert ZeroAmount();
        uint256 cap = perOpenCap[sponsor];
        if (cap == 0 || amount > cap) revert OverCap();
        if (amount > balanceOf[sponsor]) revert InsufficientBalance();
        balanceOf[sponsor] -= amount;
        jobEscrow.open{value: amount}(escrowId, providerId, sessionId, cmReq);
        emit Sponsored(sponsor, escrowId, amount);
    }

    /// @notice Credit escrow refunds (which return here as the on-chain
    ///         requester) back to `sponsor`'s balance. Any MSK the JobEscrow
    ///         refunds to this contract is pooled; the owner attributes it to
    ///         the sponsor that opened the session (off-chain-reconciled) and
    ///         calls this to make it withdrawable.
    function reclaim(address sponsor, uint256 amount) external onlyOwner {
        require(amount <= address(this).balance, "MIL: over contract balance");
        balanceOf[sponsor] += amount;
    }

    /// @dev Accept escrow refunds.
    receive() external payable {}
}
