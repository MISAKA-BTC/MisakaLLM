// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ModelRegistry} from "../src/ModelRegistry.sol";
import {MilGovernance} from "../src/MilGovernance.sol";

/// @dev DAO model-update pipeline (§19): 3 gates → stake vote → migration grace
///      → enact. The evaluator/weigher roles stand in for the off-chain
///      G1/G2/G3 harnesses and the stake+fee weight accountant.
contract MilGovernanceTest is Test {
    ModelRegistry internal models;
    MilGovernance internal gov;

    address internal owner = address(0xA11CE);
    address internal evaluator = address(0xE7A1);
    address internal weigher = address(0x8E16);
    address internal proposer = address(0x9720);

    bytes32 internal candidate = keccak256("dolphin-3.1-8b");
    uint256 internal constant BOND = 1 ether;
    uint256 internal constant EVAL_WINDOW = 4 weeks;
    uint256 internal constant GRACE = 2 weeks;

    function setUp() public {
        models = new ModelRegistry(owner);
        gov = new MilGovernance(owner, address(models), BOND, EVAL_WINDOW, 2 weeks, GRACE);

        vm.startPrank(owner);
        gov.setEvaluator(evaluator);
        gov.setVoteWeigher(weigher);
        // register the candidate + hand ModelRegistry ownership to governance
        models.registerModel(candidate, keccak256("runtime"), 131072, 0x03, 1);
        models.transferOwnership(address(gov));
        vm.stopPrank();

        vm.deal(proposer, 10 ether);
    }

    function _passAllGates(bytes32 pid) internal {
        vm.startPrank(evaluator);
        gov.recordGate(pid, 1, true, 0);
        gov.recordGate(pid, 2, true, 0);
        gov.recordGate(pid, 3, true, 1000); // totalWeight snapshot = 1000
        vm.stopPrank();
    }

    function test_full_pipeline_passes_and_enacts() public {
        bytes32 pid = keccak256("prop-1");
        vm.prank(proposer);
        gov.propose{value: BOND}(pid, candidate);
        _passAllGates(pid);

        // stake-weighted vote: 700 for / 100 against of 1000 total → quorum 80% ≥ 10%, approval 87.5% ≥ 60%
        vm.startPrank(weigher);
        gov.castVote(pid, address(0x1), true, 700);
        gov.castVote(pid, address(0x2), false, 100);
        vm.stopPrank();

        vm.warp(block.timestamp + EVAL_WINDOW + 1);
        uint256 proposerBefore = proposer.balance;
        gov.tally(pid);
        assertEq(proposer.balance - proposerBefore, BOND, "bond returned on a passed vote");

        // migration grace must elapse before enact
        vm.expectRevert(MilGovernance.GraceNotElapsed.selector);
        gov.enact(pid);

        vm.warp(block.timestamp + GRACE + 1);
        gov.enact(pid);
        assertEq(models.milCore(), candidate, "MIL-Core pointer moved to the candidate");
    }

    function test_failed_gate_rejects_and_forfeits_bond() public {
        bytes32 pid = keccak256("prop-2");
        vm.prank(proposer);
        gov.propose{value: BOND}(pid, candidate);

        uint256 ownerBefore = owner.balance;
        // G3 red-team finds a backdoor → fail
        vm.prank(evaluator);
        gov.recordGate(pid, 3, false, 0);

        (,,,,,,, MilGovernance.Phase phase,,,,,) = gov.proposals(pid);
        assertEq(uint8(phase), uint8(MilGovernance.Phase.Rejected));
        assertEq(owner.balance - ownerBefore, BOND, "forfeited bond routed to the treasury/owner");
    }

    function test_failed_vote_rejects_but_returns_bond() public {
        bytes32 pid = keccak256("prop-3");
        vm.prank(proposer);
        gov.propose{value: BOND}(pid, candidate);
        _passAllGates(pid);

        // below quorum: only 50 of 1000 vote
        vm.prank(weigher);
        gov.castVote(pid, address(0x1), true, 50);

        vm.warp(block.timestamp + EVAL_WINDOW + 1);
        uint256 proposerBefore = proposer.balance;
        gov.tally(pid);
        assertEq(proposer.balance - proposerBefore, BOND, "bond returned on a lost vote (not misconduct)");
        assertEq(models.milCore(), bytes32(0), "pointer unchanged");
    }

    function test_emergency_rollback() public {
        bytes32 good = keccak256("known-good");
        // gov owns ModelRegistry now, so register the known-good model as gov
        vm.prank(address(gov));
        models.registerModel(good, keccak256("rt2"), 131072, 0x03, 1);

        // the governance owner (multisig/executor) can fast-track a rollback (§19.4)
        vm.prank(owner);
        gov.emergencyRollback(good);
        assertEq(models.milCore(), good);
    }
}
