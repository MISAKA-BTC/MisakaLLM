// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {MilConstants} from "../src/MilCommon.sol";
import {BurnRouter} from "../src/BurnRouter.sol";
import {ProviderStabilizationPool} from "../src/ProviderStabilizationPool.sol";

/// A provider whose payout reverts on receipt - the push-payment griefing vector.
/// Under the pull-payment PSP it can only brick its OWN withdraw(), never the batch.
contract RevertingReceiver {
    receive() external payable {
        revert("nope");
    }

    function tryWithdraw(ProviderStabilizationPool p) external {
        p.withdraw();
    }
}

contract MilBurnRouterTest is Test {
    address internal constant BURN = 0x000000000000000000000000000000000000dEaD;

    address internal owner = address(0xA11CE);
    address internal reporter = address(0xE0);
    address internal distributor = address(0xD1);

    BurnRouter internal router;
    ProviderStabilizationPool internal pool;

    // Band: iLow=100, iHigh=300, staleness 50 blocks.
    function setUp() public {
        vm.roll(1000); // start well past block 0 so staleness math is clean
        router = new BurnRouter(owner, 100, 300, 50);
        pool = new ProviderStabilizationPool(owner, 500); // 5% cap
        vm.startPrank(owner);
        router.setPool(address(pool));
        router.setReporter(reporter);
        pool.setDistributor(distributor);
        vm.stopPrank();
        vm.deal(address(this), 100 ether);
    }

    function _route(uint256 amount) internal {
        (bool ok,) = address(router).call{value: amount}("");
        require(ok, "route failed");
    }

    // --- burn share ramp ---

    function test_unset_indicator_is_all_burn() public view {
        // no report yet => fail-safe s=1.
        assertEq(router.currentBurnShareBps(), 10_000);
    }

    function test_low_revenue_all_pool_high_revenue_all_burn() public {
        vm.prank(reporter);
        router.reportIndicator(100); // == iLow => s=0
        assertEq(router.currentBurnShareBps(), 0);

        vm.prank(reporter);
        router.reportIndicator(50); // below iLow => s=0
        assertEq(router.currentBurnShareBps(), 0);

        vm.prank(reporter);
        router.reportIndicator(300); // == iHigh => s=1
        assertEq(router.currentBurnShareBps(), 10_000);

        vm.prank(reporter);
        router.reportIndicator(1000); // above iHigh => s=1
        assertEq(router.currentBurnShareBps(), 10_000);
    }

    function test_linear_ramp_midpoint() public {
        vm.prank(reporter);
        router.reportIndicator(200); // midpoint of [100,300] => s=0.5
        assertEq(router.currentBurnShareBps(), 5_000);
    }

    function test_stale_indicator_fails_safe_to_all_burn() public {
        vm.prank(reporter);
        router.reportIndicator(100); // would be s=0 (all-pool) while fresh
        assertEq(router.currentBurnShareBps(), 0);
        vm.roll(block.number + 51); // now stale (> 50 blocks)
        assertEq(router.currentBurnShareBps(), 10_000, "stale => all-burn fail-safe");
    }

    function test_no_pool_is_all_burn() public {
        BurnRouter r2 = new BurnRouter(owner, 100, 300, 50);
        vm.prank(owner);
        r2.setReporter(reporter);
        vm.prank(reporter);
        r2.reportIndicator(100); // s=0 band, but no pool set
        assertEq(r2.currentBurnShareBps(), 10_000, "no pool => all-burn");
    }

    // --- routing splits the flow ---

    function test_route_splits_by_current_share() public {
        vm.prank(reporter);
        router.reportIndicator(200); // s=0.5
        vm.roll(block.number + 1); // still fresh
        uint256 burnBefore = BURN.balance;
        uint256 poolBefore = address(pool).balance;

        _route(1000);

        assertEq(BURN.balance - burnBefore, 500, "half burned");
        assertEq(address(pool).balance - poolBefore, 500, "half to pool");
    }

    function test_route_all_pool_when_low_revenue() public {
        vm.prank(reporter);
        router.reportIndicator(80); // below iLow => s=0 => all pool, buy still happened
        _route(1000);
        assertEq(address(pool).balance, 1000, "low revenue => all to PSP");
        assertEq(BURN.balance, 0);
    }

    // --- PSP distribution (pull-payment) ---

    function _provs2(address a, address b, uint256 sa, uint256 sb)
        internal
        pure
        returns (address[] memory provs, uint256[] memory served)
    {
        provs = new address[](2);
        provs[0] = a;
        provs[1] = b;
        served = new uint256[](2);
        served[0] = sa;
        served[1] = sb;
    }

    function test_psp_credits_by_served_tokens_then_pulls() public {
        // No cap: use a fresh pool with 100% cap to isolate proportionality.
        ProviderStabilizationPool p = new ProviderStabilizationPool(owner, 10_000);
        vm.prank(owner);
        p.setDistributor(distributor);
        vm.deal(address(p), 1000);

        address a = address(0xA);
        address b = address(0xB);
        (address[] memory provs, uint256[] memory served) = _provs2(a, b, 300, 700);

        vm.prank(distributor);
        p.distribute(7, provs, served);
        // distribute only CREDITS - no balance moves yet.
        assertEq(p.owed(a), 300, "30% credited by served-tokens");
        assertEq(p.owed(b), 700, "70% credited by served-tokens");
        assertEq(p.totalOwed(), 1000);
        assertEq(a.balance, 0);

        // each provider pulls independently.
        vm.prank(a);
        p.withdraw();
        vm.prank(b);
        p.withdraw();
        assertEq(a.balance, 300);
        assertEq(b.balance, 700);
        assertEq(p.totalOwed(), 0);
        assertEq(address(p).balance, 0, "fully drained");
    }

    function test_psp_5pct_cap_binds_and_remainder_rolls_over() public {
        vm.deal(address(pool), 1000);
        address a = address(0xA);
        address b = address(0xB);
        (address[] memory provs, uint256[] memory served) = _provs2(a, b, 900, 100);
        // 900/1000 and 100/1000 shares, both capped to 5% of 1000 = 50.

        vm.prank(distributor);
        pool.distribute(1, provs, served);
        assertEq(pool.owed(a), 50, "5% cap");
        assertEq(pool.owed(b), 50, "5% cap");
        assertEq(pool.totalOwed(), 100);
        // The capped remainder stays in the pool balance for the next epoch.
        assertEq(address(pool).balance, 1000, "nothing withdrawn yet; remainder retained");
    }

    function test_psp_cross_epoch_no_double_count_and_conservation() public {
        vm.deal(address(pool), 1000);
        address a = address(0xA);
        address b = address(0xB);

        // Epoch 1: capped at 50 each → 100 credited, 900 remains distributable.
        (address[] memory p1, uint256[] memory s1) = _provs2(a, b, 900, 100);
        vm.prank(distributor);
        pool.distribute(1, p1, s1);
        assertEq(pool.totalOwed(), 100);

        // Epoch 2 must distribute over (balance - totalOwed) = 900, NOT the full
        // 1000 - epoch 1's credited-but-unwithdrawn 100 is never re-counted.
        // cap = 5% of 900 = 45.
        (address[] memory p2, uint256[] memory s2) = _provs2(a, b, 900, 100);
        vm.prank(distributor);
        pool.distribute(2, p2, s2);
        assertEq(pool.owed(a), 95, "50 (ep1) + 45 (ep2 cap of 900)");
        assertEq(pool.owed(b), 95);
        assertEq(pool.totalOwed(), 190);

        // Conservation: everything withdrawn + retained remainder == original 1000.
        vm.prank(a);
        pool.withdraw();
        vm.prank(b);
        pool.withdraw();
        assertEq(a.balance + b.balance + address(pool).balance, 1000, "no value minted or lost");
        assertEq(pool.totalOwed(), 0);
    }

    function test_psp_reverting_provider_only_harms_itself() public {
        vm.deal(address(pool), 1000);
        RevertingReceiver bad = new RevertingReceiver();
        address good = address(0xB);
        // ascending order: bad receiver deployed early → low address; ensure order.
        address lo = address(bad) < good ? address(bad) : good;
        address hi = address(bad) < good ? good : address(bad);
        (address[] memory provs, uint256[] memory served) = _provs2(lo, hi, 500, 500);

        // distribute never touches the recipients (pull), so it cannot be griefed.
        vm.prank(distributor);
        pool.distribute(1, provs, served);
        assertEq(pool.owed(address(bad)), 50, "credited despite reverting receive");
        assertEq(pool.owed(good), 50);

        // the honest provider pulls successfully; the griefer's own withdraw reverts.
        vm.prank(good);
        pool.withdraw();
        assertEq(good.balance, 50, "honest provider paid - not blocked by the griefer");

        vm.expectRevert(ProviderStabilizationPool.TransferFailed.selector);
        bad.tryWithdraw(pool);
        assertEq(pool.owed(address(bad)), 50, "griefer still only harms itself");
    }

    function test_psp_requires_strictly_ascending_unique_providers() public {
        vm.deal(address(pool), 1000);
        address x = address(0xC);
        // duplicate address [x, x] would double the per-entity cap → rejected.
        (address[] memory provs, uint256[] memory served) = _provs2(x, x, 500, 500);
        vm.prank(distributor);
        vm.expectRevert(ProviderStabilizationPool.ProvidersNotSorted.selector);
        pool.distribute(1, provs, served);

        // descending order also rejected.
        (address[] memory provs2, uint256[] memory served2) = _provs2(address(0xB), address(0xA), 1, 1);
        vm.prank(distributor);
        vm.expectRevert(ProviderStabilizationPool.ProvidersNotSorted.selector);
        pool.distribute(2, provs2, served2);
    }

    function test_psp_epoch_replay_and_auth_guards() public {
        vm.deal(address(pool), 1000);
        address[] memory provs = new address[](1);
        provs[0] = address(0xA);
        uint256[] memory served = new uint256[](1);
        served[0] = 100;

        // non-distributor rejected
        vm.expectRevert(ProviderStabilizationPool.NotDistributor.selector);
        pool.distribute(1, provs, served);

        vm.prank(distributor);
        pool.distribute(1, provs, served);
        // same epoch twice rejected
        vm.prank(distributor);
        vm.expectRevert(ProviderStabilizationPool.EpochAlreadyDistributed.selector);
        pool.distribute(1, provs, served);
    }

    function test_router_reporter_and_owner_guards() public {
        vm.expectRevert(BurnRouter.NotReporter.selector);
        router.reportIndicator(200);

        vm.expectRevert(); // NotOwner (from MilOwned)
        router.setBand(1, 2, 10);
    }
}
