// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {DelegatedStakeManager} from "../src/DelegatedStakeManager.sol";
import {Paymaster} from "../src/Paymaster.sol";
import {Faucet} from "../src/Faucet.sol";
import {MilConstants} from "../src/MilCommon.sol";

contract MilDelegationTest is Test {
    DelegatedStakeManager internal del;
    address internal owner = address(0xA11CE);
    address internal provider = address(0x9E0);
    address internal slasher = address(0xD15);
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);
    bytes32 internal pid = keccak256("provider-1");

    function setUp() public {
        del = new DelegatedStakeManager(owner);
        vm.prank(owner);
        del.setSlasher(slasher);
        vm.prank(provider);
        del.openPool(pid, 20); // 20% delegator income share
        vm.deal(alice, 1000 ether);
        vm.deal(bob, 1000 ether);
        vm.deal(provider, 1000 ether);
    }

    function test_delegate_rewards_raise_all_shares() public {
        vm.prank(alice);
        del.delegate{value: 100 ether}(pid);
        vm.prank(bob);
        del.delegate{value: 300 ether}(pid);
        // alice:bob = 1:3
        assertEq(del.delegatedValue(pid, alice), 100 ether);
        assertEq(del.delegatedValue(pid, bob), 300 ether);

        // provider forwards 40 MSK of delegator income → pool rate rises pro-rata
        vm.prank(provider);
        del.distributeRewards{value: 40 ether}(pid);
        assertEq(del.delegatedValue(pid, alice), 110 ether); // +25% of 40
        assertEq(del.delegatedValue(pid, bob), 330 ether); // +75% of 40
    }

    function test_slash_is_proportional_across_delegators() public {
        vm.prank(alice);
        del.delegate{value: 100 ether}(pid);
        vm.prank(bob);
        del.delegate{value: 100 ether}(pid);

        address challenger = address(0xCA11);
        uint256 burnBefore = MilConstants.BURN_SINK.balance;
        // slash 80 MSK from the pool (of 200) → each delegator loses 40 (pro-rata)
        vm.prank(slasher);
        del.slashPool(pid, 80 ether, payable(challenger));

        assertEq(del.delegatedValue(pid, alice), 60 ether);
        assertEq(del.delegatedValue(pid, bob), 60 ether);
        assertEq(challenger.balance, 40 ether); // half of slash
        assertEq(MilConstants.BURN_SINK.balance - burnBefore, 40 ether); // half burned
    }

    function test_undelegate_delay_and_withdraw() public {
        vm.prank(alice);
        del.delegate{value: 100 ether}(pid);
        uint256 aliceShares = del.shares(pid, alice);
        vm.prank(alice);
        del.requestUndelegate(pid, aliceShares);

        vm.prank(alice);
        vm.expectRevert(DelegatedStakeManager.NotReady.selector);
        del.withdraw(pid);

        vm.warp(block.timestamp + 7 days);
        uint256 before = alice.balance;
        vm.prank(alice);
        del.withdraw(pid);
        assertEq(alice.balance - before, 100 ether);
    }

    function test_bad_share_pct_rejected() public {
        vm.prank(address(0xF00));
        vm.expectRevert(DelegatedStakeManager.BadSharePct.selector);
        del.openPool(keccak256("p2"), 5);
    }
}

contract MockEscrowOpen {
    event Opened(bytes32 escrowId, uint256 value);

    function open(bytes32 escrowId, bytes32, bytes calldata, bytes32) external payable {
        emit Opened(escrowId, msg.value);
    }
}

contract MilPaymasterTest is Test {
    Paymaster internal pm;
    MockEscrowOpen internal escrow;
    address internal owner = address(0xA11CE);
    address internal sponsor = address(0x5A0);
    address internal relayer = address(0x9E1A);

    function setUp() public {
        escrow = new MockEscrowOpen();
        pm = new Paymaster(owner, address(escrow));
        vm.deal(sponsor, 100 ether);
    }

    function test_sponsored_open_spends_from_sponsor_balance() public {
        vm.prank(sponsor);
        pm.deposit{value: 50 ether}();
        vm.prank(sponsor);
        pm.setRelayer(relayer);
        vm.prank(sponsor);
        pm.setPerOpenCap(10 ether);

        vm.prank(relayer);
        pm.sponsorOpen(sponsor, 5 ether, keccak256("e1"), keccak256("p1"), new bytes(64), keccak256("cm"));
        assertEq(pm.balanceOf(sponsor), 45 ether);
        assertEq(address(escrow).balance, 5 ether);
    }

    function test_over_cap_and_unauthorized_rejected() public {
        vm.prank(sponsor);
        pm.deposit{value: 50 ether}();
        vm.prank(sponsor);
        pm.setRelayer(relayer);
        vm.prank(sponsor);
        pm.setPerOpenCap(10 ether);

        vm.prank(relayer);
        vm.expectRevert(Paymaster.OverCap.selector);
        pm.sponsorOpen(sponsor, 20 ether, keccak256("e2"), keccak256("p1"), new bytes(64), keccak256("cm"));

        vm.prank(address(0xBAD));
        vm.expectRevert(Paymaster.NotRelayer.selector);
        pm.sponsorOpen(sponsor, 5 ether, keccak256("e3"), keccak256("p1"), new bytes(64), keccak256("cm"));
    }
}

contract MilFaucetTest is Test {
    Faucet internal faucet;
    address internal owner = address(0xA11CE);
    address internal user = address(0x0501);

    function setUp() public {
        // low difficulty (8 bits) so the test can mine quickly
        faucet = new Faucet(owner, 1 ether, 1 days, 8);
        vm.deal(owner, 100 ether);
        vm.prank(owner);
        faucet.fund{value: 100 ether}();
    }

    function _mine(address recipient) internal view returns (uint256) {
        for (uint256 n = 0; n < 100000; n++) {
            if (uint256(faucet.challenge(recipient, n)) < (uint256(1) << (256 - 8))) {
                return n;
            }
        }
        revert("no pow found");
    }

    function test_claim_with_valid_pow_and_cooldown() public {
        uint256 nonce = _mine(user);
        uint256 before = user.balance;
        faucet.claim(user, nonce);
        assertEq(user.balance - before, 1 ether);

        // immediate re-claim blocked by cooldown
        uint256 nonce2 = _mine(user);
        vm.expectRevert(abi.encodeWithSelector(Faucet.CooldownActive.selector, block.timestamp + 1 days));
        faucet.claim(user, nonce2);

        // after cooldown, claim again
        vm.warp(block.timestamp + 1 days);
        uint256 nonce3 = _mine(user);
        faucet.claim(user, nonce3);
        assertEq(user.balance, before + 2 ether);
    }

    function test_bad_pow_rejected() public {
        // nonce 0 almost certainly fails an 8-bit target for this user
        if (uint256(faucet.challenge(user, 0)) < (uint256(1) << (256 - 8))) {
            return; // (astronomically unlikely) skip if it happens to pass
        }
        vm.expectRevert(Faucet.BadPow.selector);
        faucet.claim(user, 0);
    }
}
