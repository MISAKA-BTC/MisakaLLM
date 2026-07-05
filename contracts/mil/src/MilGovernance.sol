// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilOwned} from "./MilCommon.sol";

interface IModelRegistrySetCore {
    function setMilCore(bytes32 modelId) external;
    function isRegistered(bytes32 modelId) external view returns (bool);
}

/// @title MilGovernance — DAO model-update pipeline (design §19).
/// @notice Drives the `MIL-Core` pointer through the 3-gate + stake-vote
///         pipeline. On-chain this contract records the pipeline state machine,
///         holds the proposer bond, tallies the stake-weighted vote, and — on a
///         passed proposal after the migration grace — calls
///         `ModelRegistry.setMilCore`. The heavy evaluation itself is off-chain
///         (G1 reproducible bench reusing the Tier-2 determinism harness, G2
///         blind arena Bradley–Terry, G3 red-team window); their pass/fail
///         verdicts are anchored here by the authorized `evaluator`. Voting
///         weight is supplied by the authorized `voteWeigher` (stake +
///         paid-fee weight, §19.4/§19.3-G2) so this contract does not itself
///         need to read every stake source.
///
///         To install: the ModelRegistry owner transfers ownership to this
///         contract, so only a governance-approved `enact` can move MIL-Core.
contract MilGovernance is MilOwned {
    IModelRegistrySetCore public immutable modelRegistry;

    uint256 public proposerBond; // §10: 1M MSK
    uint256 public evalWindow; // §10: 4 weeks (seconds)
    uint256 public redteamWindow; // §10: 2 weeks (seconds)
    uint256 public migrationGrace; // §10: 2 weeks (seconds)
    uint256 public quorumPpm; // §10: 10% = 100_000 ppm
    uint256 public approvalPpm; // §10: 60% = 600_000 ppm
    uint256 public emergencyApprovalPpm; // §10: 75% = 750_000 ppm

    address public evaluator; // anchors G1/G2/G3 verdicts
    address public voteWeigher; // supplies stake/fee vote weights

    enum Phase {
        None,
        Proposed, // bond posted, awaiting gate verdicts
        GatesPassed, // G1+G2+G3 all passed → voting open
        Rejected, // a gate failed or the vote failed → bond outcome settled
        Passed, // vote passed → migration grace running
        Enacted // grace elapsed → MIL-Core moved
    }

    struct Proposal {
        address proposer;
        bytes32 modelId; // candidate model (must be registered before enact)
        uint256 bond;
        uint64 createdAt;
        bool g1Bench;
        bool g2Arena;
        bool g3Redteam;
        Phase phase;
        uint64 votingClosesAt;
        uint64 graceEndsAt;
        uint256 totalWeight; // total eligible weight snapshot for quorum
        uint256 forWeight;
        uint256 againstWeight;
    }

    mapping(bytes32 => Proposal) public proposals;
    /// @dev per-proposal voted flag, keyed by (proposalId, voter).
    mapping(bytes32 => mapping(address => bool)) public voted;

    event Proposed(bytes32 indexed proposalId, address indexed proposer, bytes32 modelId, uint256 bond);
    event GateRecorded(bytes32 indexed proposalId, uint8 gate, bool passed);
    event VotingOpened(bytes32 indexed proposalId, uint256 totalWeight, uint64 closesAt);
    event Voted(bytes32 indexed proposalId, address indexed voter, bool support, uint256 weight);
    event ProposalPassed(bytes32 indexed proposalId, uint64 graceEndsAt);
    event ProposalRejected(bytes32 indexed proposalId);
    event Enacted(bytes32 indexed proposalId, bytes32 modelId);
    event EmergencyRollback(bytes32 modelId);
    event BondReturned(bytes32 indexed proposalId, address to, uint256 amount);
    event BondForfeited(bytes32 indexed proposalId, uint256 amount);

    error NotEvaluator();
    error NotWeigher();
    error BadBond();
    error ProposalExists();
    error UnknownProposal();
    error WrongPhase();
    error GatesNotPassed();
    error AlreadyVoted();
    error VotingClosed();
    error VotingOpen();
    error GraceNotElapsed();
    error ModelNotRegistered();

    constructor(
        address initialOwner,
        address _modelRegistry,
        uint256 _proposerBond,
        uint256 _evalWindow,
        uint256 _redteamWindow,
        uint256 _migrationGrace
    ) MilOwned(initialOwner) {
        modelRegistry = IModelRegistrySetCore(_modelRegistry);
        proposerBond = _proposerBond;
        evalWindow = _evalWindow;
        redteamWindow = _redteamWindow;
        migrationGrace = _migrationGrace;
        quorumPpm = 100_000; // 10%
        approvalPpm = 600_000; // 60%
        emergencyApprovalPpm = 750_000; // 75%
    }

    function setEvaluator(address _evaluator) external onlyOwner {
        evaluator = _evaluator;
    }

    function setVoteWeigher(address _voteWeigher) external onlyOwner {
        voteWeigher = _voteWeigher;
    }

    function setThresholds(uint256 _quorumPpm, uint256 _approvalPpm, uint256 _emergencyApprovalPpm) external onlyOwner {
        quorumPpm = _quorumPpm;
        approvalPpm = _approvalPpm;
        emergencyApprovalPpm = _emergencyApprovalPpm;
    }

    /// @notice Propose a candidate `modelId`, posting the exact proposer bond
    ///         (§19.2). Full provenance disclosure is off-chain; its hash may be
    ///         carried in `modelId`'s registry entry.
    function propose(bytes32 proposalId, bytes32 modelId) external payable {
        if (msg.value != proposerBond) revert BadBond();
        if (proposals[proposalId].phase != Phase.None) revert ProposalExists();
        proposals[proposalId] = Proposal({
            proposer: msg.sender,
            modelId: modelId,
            bond: msg.value,
            createdAt: uint64(block.timestamp),
            g1Bench: false,
            g2Arena: false,
            g3Redteam: false,
            phase: Phase.Proposed,
            votingClosesAt: 0,
            graceEndsAt: 0,
            totalWeight: 0,
            forWeight: 0,
            againstWeight: 0
        });
        emit Proposed(proposalId, msg.sender, modelId, msg.value);
    }

    /// @notice Anchor a gate verdict (§19.3). gate: 1=G1 bench, 2=G2 arena,
    ///         3=G3 red-team. A failed gate rejects the proposal and forfeits the
    ///         bond (a red-team backdoor finding, §19.3-G3). When all three pass,
    ///         voting opens with the supplied eligible `totalWeight` snapshot.
    function recordGate(bytes32 proposalId, uint8 gate, bool passed, uint256 totalWeight) external {
        if (msg.sender != evaluator) revert NotEvaluator();
        Proposal storage p = proposals[proposalId];
        if (p.phase != Phase.Proposed) revert WrongPhase();

        if (!passed) {
            p.phase = Phase.Rejected;
            _forfeitBond(proposalId, p);
            emit GateRecorded(proposalId, gate, false);
            emit ProposalRejected(proposalId);
            return;
        }
        if (gate == 1) p.g1Bench = true;
        else if (gate == 2) p.g2Arena = true;
        else if (gate == 3) p.g3Redteam = true;
        emit GateRecorded(proposalId, gate, true);

        if (p.g1Bench && p.g2Arena && p.g3Redteam) {
            p.phase = Phase.GatesPassed;
            p.totalWeight = totalWeight;
            p.votingClosesAt = uint64(block.timestamp + evalWindow);
            emit VotingOpened(proposalId, totalWeight, p.votingClosesAt);
        }
    }

    /// @notice Cast a stake/fee-weighted vote (§19.4). The weight is attested by
    ///         the authorized `voteWeigher` (it aggregates DNS-validator +
    ///         provider + delegator + self-locked-MSK stake and G2 paid-fee
    ///         weight off-chain), preventing double-count and self-buying beyond
    ///         its accounting. One vote per (proposal, voter).
    function castVote(bytes32 proposalId, address voter, bool support, uint256 weight) external {
        if (msg.sender != voteWeigher) revert NotWeigher();
        Proposal storage p = proposals[proposalId];
        if (p.phase != Phase.GatesPassed) revert GatesNotPassed();
        if (block.timestamp > p.votingClosesAt) revert VotingClosed();
        if (voted[proposalId][voter]) revert AlreadyVoted();
        voted[proposalId][voter] = true;
        if (support) p.forWeight += weight;
        else p.againstWeight += weight;
        emit Voted(proposalId, voter, support, weight);
    }

    /// @notice Close voting and tally (§19.4): quorum 10% of the total weight,
    ///         approval 60% of votes cast. Pass → migration grace; fail → reject
    ///         (bond returned — a lost vote is not misconduct).
    function tally(bytes32 proposalId) external {
        Proposal storage p = proposals[proposalId];
        if (p.phase != Phase.GatesPassed) revert GatesNotPassed();
        if (block.timestamp <= p.votingClosesAt) revert VotingOpen();

        uint256 cast = p.forWeight + p.againstWeight;
        bool quorumMet = p.totalWeight > 0 && cast * 1_000_000 >= p.totalWeight * quorumPpm;
        bool approved = cast > 0 && p.forWeight * 1_000_000 >= cast * approvalPpm;

        if (quorumMet && approved) {
            p.phase = Phase.Passed;
            p.graceEndsAt = uint64(block.timestamp + migrationGrace);
            _returnBond(proposalId, p);
            emit ProposalPassed(proposalId, p.graceEndsAt);
        } else {
            p.phase = Phase.Rejected;
            _returnBond(proposalId, p);
            emit ProposalRejected(proposalId);
        }
    }

    /// @notice After the migration grace (§19.4), enact the pointer move. The
    ///         candidate must be registered in the ModelRegistry by now.
    function enact(bytes32 proposalId) external {
        Proposal storage p = proposals[proposalId];
        if (p.phase != Phase.Passed) revert WrongPhase();
        if (block.timestamp < p.graceEndsAt) revert GraceNotElapsed();
        if (!modelRegistry.isRegistered(p.modelId)) revert ModelNotRegistered();
        p.phase = Phase.Enacted;
        modelRegistry.setMilCore(p.modelId);
        emit Enacted(proposalId, p.modelId);
    }

    /// @notice Emergency rollback (§19.4): a 24h fast-track at 75% is run
    ///         off-chain by the same vote machinery; the owner (a governance
    ///         multisig / the DAO executor) points MIL-Core back to a known-good
    ///         `modelId` immediately. Kept as an owner action so a critical
    ///         defect is not gated on a fresh full pipeline.
    function emergencyRollback(bytes32 modelId) external onlyOwner {
        if (!modelRegistry.isRegistered(modelId)) revert ModelNotRegistered();
        modelRegistry.setMilCore(modelId);
        emit EmergencyRollback(modelId);
    }

    function _returnBond(bytes32 proposalId, Proposal storage p) internal {
        uint256 amount = p.bond;
        if (amount == 0) return;
        p.bond = 0;
        (bool ok,) = payable(p.proposer).call{value: amount}("");
        require(ok, "MIL: bond return failed");
        emit BondReturned(proposalId, p.proposer, amount);
    }

    function _forfeitBond(bytes32 proposalId, Proposal storage p) internal {
        uint256 amount = p.bond;
        if (amount == 0) return;
        p.bond = 0;
        // §19.3-G3: a forfeited bond funds the red-team bounty pool; send to owner
        // (the treasury/governance executor) which routes it.
        (bool ok,) = payable(owner).call{value: amount}("");
        require(ok, "MIL: bond forfeit failed");
        emit BondForfeited(proposalId, amount);
    }
}
