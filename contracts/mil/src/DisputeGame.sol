// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilConstants, MilOwned} from "./MilCommon.sol";

interface IStakeManagerSlash {
    function slash(address staker, uint256 amount, address payable beneficiary) external;
    function bondedAmount(address staker) external view returns (uint256);
}

interface IProviderRegistryOperator {
    function operatorOf(bytes32 providerId) external view returns (address);
}

/// @title DisputeGame — MIL Tier-2 optimistic-replication dispute (design §4.2).
/// @notice Anyone may challenge a Tier-2 provider's output by posting a bond and
///         the evidence hash. A VRF-selected verifier committee re-runs the job
///         under the deterministic profile; the aggregated verdict is submitted
///         by the authorized `committee` address. If the provider's output did
///         NOT match, 50% of its stake is slashed (StakeManager splits that
///         50/50 challenger/burn, §5.5) and the challenger's bond is returned;
///         otherwise the challenger's bond is forfeited to burn.
contract DisputeGame is MilOwned {
    IStakeManagerSlash public immutable stakeManager;
    IProviderRegistryOperator public immutable registry;

    /// @dev Required challenger bond (governance-tunable).
    uint256 public challengerBond;
    /// @dev The authorized verdict submitter (the VRF committee aggregator).
    address public committee;

    enum Status {
        None,
        Open,
        ResolvedGuilty,
        ResolvedInnocent
    }

    struct Dispute {
        address challenger;
        bytes32 providerId;
        bytes32 evidenceHash;
        uint256 bond;
        uint64 openedAt;
        Status status;
    }

    mapping(bytes32 => Dispute) public disputes;
    uint256 private _reentryGuard;

    event DisputeOpened(bytes32 indexed disputeId, bytes32 indexed providerId, address indexed challenger, bytes32 evidenceHash);
    event DisputeResolved(bytes32 indexed disputeId, bool providerGuilty, uint256 slashed);
    event CommitteeUpdated(address indexed committee);
    event ChallengerBondUpdated(uint256 bond);

    error NotCommittee();
    error BadBond();
    error DisputeExists();
    error UnknownDispute();
    error AlreadyResolved();
    error Reentrancy();

    modifier nonReentrant() {
        if (_reentryGuard == 1) revert Reentrancy();
        _reentryGuard = 1;
        _;
        _reentryGuard = 0;
    }

    constructor(address initialOwner, address _stakeManager, address _registry, uint256 _challengerBond)
        MilOwned(initialOwner)
    {
        stakeManager = IStakeManagerSlash(_stakeManager);
        registry = IProviderRegistryOperator(_registry);
        challengerBond = _challengerBond;
    }

    function setCommittee(address _committee) external onlyOwner {
        committee = _committee;
        emit CommitteeUpdated(_committee);
    }

    function setChallengerBond(uint256 bond) external onlyOwner {
        challengerBond = bond;
        emit ChallengerBondUpdated(bond);
    }

    /// @notice Open a Tier-2 dispute over `providerId`'s output, posting the
    ///         exact challenger bond and the evidence package hash (§8.6 FSL
    ///         forensic format off-chain).
    function openDispute(bytes32 disputeId, bytes32 providerId, bytes32 evidenceHash) external payable {
        if (msg.value != challengerBond) revert BadBond();
        if (disputes[disputeId].status != Status.None) revert DisputeExists();
        disputes[disputeId] = Dispute({
            challenger: msg.sender,
            providerId: providerId,
            evidenceHash: evidenceHash,
            bond: msg.value,
            openedAt: uint64(block.number),
            status: Status.Open
        });
        emit DisputeOpened(disputeId, providerId, msg.sender, evidenceHash);
    }

    /// @notice Submit the committee verdict. Guilty → slash 50% of the provider
    ///         operator's stake (StakeManager splits it 50/50 challenger/burn)
    ///         and return the challenger bond; innocent → forfeit the challenger
    ///         bond to burn.
    function resolve(bytes32 disputeId, bool providerGuilty) external nonReentrant {
        if (msg.sender != committee) revert NotCommittee();
        Dispute storage d = disputes[disputeId];
        if (d.status == Status.None) revert UnknownDispute();
        if (d.status != Status.Open) revert AlreadyResolved();

        uint256 slashed;
        if (providerGuilty) {
            d.status = Status.ResolvedGuilty;
            address operator = registry.operatorOf(d.providerId);
            uint256 bonded = stakeManager.bondedAmount(operator);
            slashed = bonded / 2; // §5.5: Tier-2 mismatch → 50% of stake
            if (slashed > 0) {
                // StakeManager sends half of `slashed` to the challenger, half burns.
                stakeManager.slash(operator, slashed, payable(d.challenger));
            }
            // return the challenger's bond
            (bool ok,) = payable(d.challenger).call{value: d.bond}("");
            require(ok, "MIL: bond return failed");
        } else {
            d.status = Status.ResolvedInnocent;
            // forfeit the challenger bond to burn (spam deterrent)
            (bool ok,) = payable(MilConstants.BURN_SINK).call{value: d.bond}("");
            require(ok, "MIL: bond forfeit failed");
        }
        emit DisputeResolved(disputeId, providerGuilty, slashed);
    }
}
