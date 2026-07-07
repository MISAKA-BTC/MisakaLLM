// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {MilConstants, MilReceipt} from "../src/MilCommon.sol";
import {ProviderRegistry} from "../src/ProviderRegistry.sol";
import {StakeManager} from "../src/StakeManager.sol";
import {RewardPool} from "../src/RewardPool.sol";
import {JobEscrow} from "../src/JobEscrow.sol";
import {DisputeGame} from "../src/DisputeGame.sol";
import {BurnRouter} from "../src/BurnRouter.sol";
import {ProviderStabilizationPool} from "../src/ProviderStabilizationPool.sol";

/// @dev F003 mocks - Foundry cannot run the lattice precompile, so the receipt
///      signature verify is mocked (the real ML-DSA-87 verify is proven by the
///      Rust `mldsa_verify.rs` v0x03 test).
contract MockF003True {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(true);
    }
}

contract MockF003False {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(false);
    }
}

/// @dev Mock F005 DNS-finality precompile returning a settable (currentDaa, dnsFinalDaa).
contract MockF005 {
    uint256 public currentDaa;
    uint256 public dnsFinalDaa;

    function set(uint256 c, uint256 f) external {
        currentDaa = c;
        dnsFinalDaa = f;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(currentDaa, dnsFinalDaa);
    }
}

/// A burnRouter that reverts on receipt - proves JobEscrow's BURN_SINK fallback
/// keeps claim() live when a set router misbehaves (governance-footgun defense).
contract RevertingSink {
    receive() external payable {
        revert("router down");
    }
}

contract MilFlowTest is Test {
    address internal constant F003 = address(0x0000000000000000000000000000000000F003);
    address internal constant F005 = address(0x0000000000000000000000000000000000F005);

    ProviderRegistry internal registry;
    StakeManager internal stake;
    RewardPool internal pool;
    JobEscrow internal escrow;
    DisputeGame internal dispute;

    address internal owner = address(0xA11CE);
    address internal treasury = address(0x7EEA);
    address internal provider = address(0x9E0);
    address internal requester = address(0xBEEF);
    address internal committee = address(0xC0);
    address internal dnsReporter = address(0xD5);

    bytes internal pubkey = new bytes(2592);
    bytes internal sig = new bytes(4627);
    bytes32 internal providerId = keccak256("provider-1");
    bytes internal sessionId = _repeat(0xAB, 64);

    uint64 internal constant ASK_IN = 1_000_000; // wei per 1k input tokens
    uint64 internal constant ASK_OUT = 1_000_000; // wei per 1k output tokens
    uint256 internal constant DNS_THRESHOLD = 100 ether;

    function setUp() public {
        registry = new ProviderRegistry(owner);
        stake = new StakeManager(owner, 500 ether, 100 ether);
        pool = new RewardPool(owner, treasury);
        escrow = new JobEscrow(owner, address(registry), address(pool), DNS_THRESHOLD);
        dispute = new DisputeGame(owner, address(stake), address(registry), 1 ether);

        vm.startPrank(owner);
        pool.setJobEscrow(address(escrow));
        stake.setSlasher(address(dispute));
        dispute.setCommittee(committee);
        escrow.setDnsReporter(dnsReporter);
        vm.stopPrank();

        // register the provider (pkReceiptHash binds the enclave key)
        vm.prank(provider);
        registry.register(
            ProviderRegistry.RegisterParams({
                providerId: providerId,
                quoteHash: keccak256("quote"),
                modelId: keccak256("mil-core"),
                pkReceiptHash: keccak256(pubkey),
                pkKemHash: keccak256("kem"),
                tier: ProviderRegistry.Tier.Open,
                gpuClassWeight: 1,
                askInPer1k: ASK_IN,
                askOutPer1k: ASK_OUT,
                ttfbMs: 1500,
                minTps: 20,
                hot: true,
                entityCredentialHash: bytes32(0),
                region: "local",
                dataPlaneAddr: "127.0.0.1:37110"
            })
        );

        vm.deal(requester, 1000 ether);
        vm.deal(provider, 1000 ether);
    }

    function _receipt(uint64 counter, uint64 cumIn, uint64 cumOut, bool isFinal)
        internal
        view
        returns (MilReceipt memory r)
    {
        r.version = 1;
        r.sessionId = sessionId;
        r.counter = counter;
        r.cumTokensIn = cumIn;
        r.cumTokensOut = cumOut;
        r.timestampMs = 1_780_000_000_000 + counter;
        r.cmResp = _repeat(0xCD, 64);
        r.isFinal = isFinal;
    }

    function _open(bytes32 escrowId, uint256 lock) internal {
        vm.prank(requester);
        escrow.open{value: lock}(escrowId, providerId, sessionId, keccak256("cm_req"));
    }

    // --- registration ---

    function test_provider_registration_binds_operator_and_ask() public view {
        assertEq(registry.operatorOf(providerId), provider);
        assertTrue(registry.isActive(providerId));
        (uint64 aIn, uint64 aOut) = registry.asks(providerId);
        assertEq(aIn, ASK_IN);
        assertEq(aOut, ASK_OUT);
    }

    // --- job escrow claim + fee split ---

    function test_claim_settles_cumulative_and_splits_fees() public {
        vm.etch(F003, address(new MockF003True()).code);
        bytes32 id = keccak256("escrow-1");
        _open(id, 10 ether);

        // cumulative cost: ceil(ASK_IN*100/1000) + ceil(ASK_OUT*1536/1000)
        uint256 expectedCost = (uint256(ASK_IN) * 100 + 999) / 1000 + (uint256(ASK_OUT) * 1536 + 999) / 1000;

        uint256 provBefore = provider.balance;
        uint256 burnBefore = MilConstants.BURN_SINK.balance;

        vm.prank(provider);
        escrow.claim(id, _receipt(1, 100, 1536, false), pubkey, sig);

        // 88/5/4/3 split of the delta (== full cost on first claim), lossless
        uint256 burn = expectedCost * 5 / 100;
        uint256 val = expectedCost * 4 / 100;
        uint256 treas = expectedCost * 3 / 100;
        uint256 prov = expectedCost - burn - val - treas;
        assertEq(provider.balance - provBefore, prov);
        assertEq(MilConstants.BURN_SINK.balance - burnBefore, burn);
        assertEq(pool.validatorPoolBalance(), val);
        assertEq(pool.treasuryBalance(), treas);
        assertEq(prov + burn + val + treas, expectedCost, "split is lossless");

        JobEscrow.Escrow memory e = escrow.get(id);
        assertEq(e.settledCost, expectedCost);
        assertEq(e.lastCounter, 1);
    }

    function test_claim_burn_leg_routes_through_burn_router_when_set() public {
        vm.etch(F003, address(new MockF003True()).code);

        // Wire the counter-cyclical burn router with a live pool at s=0.5.
        address reporter = address(0xE0);
        BurnRouter router = new BurnRouter(owner, 100, 300, 1_000);
        ProviderStabilizationPool psp = new ProviderStabilizationPool(owner, 500);
        vm.startPrank(owner);
        router.setPool(address(psp));
        router.setReporter(reporter);
        escrow.setBurnRouter(address(router));
        vm.stopPrank();
        vm.prank(reporter);
        router.reportIndicator(200); // midpoint of [100,300] => s=0.5

        bytes32 id = keccak256("escrow-router");
        _open(id, 10 ether);
        uint256 expectedCost = (uint256(ASK_IN) * 100 + 999) / 1000 + (uint256(ASK_OUT) * 1536 + 999) / 1000;
        uint256 burn = expectedCost * 5 / 100;

        uint256 sinkBefore = MilConstants.BURN_SINK.balance;
        uint256 pspBefore = address(psp).balance;
        uint256 provBefore = provider.balance;

        vm.prank(provider);
        escrow.claim(id, _receipt(1, 100, 1536, false), pubkey, sig);

        // The 5% burn leg flowed into the router, which split it 50/50 at s=0.5:
        // half to the native eater, half to the Provider Stabilization Pool.
        uint256 burned = burn * 5_000 / 10_000;
        assertEq(MilConstants.BURN_SINK.balance - sinkBefore, burned, "half of burn leg to eater");
        assertEq(address(psp).balance - pspBefore, burn - burned, "half of burn leg to PSP");
        assertEq(
            (MilConstants.BURN_SINK.balance - sinkBefore) + (address(psp).balance - pspBefore),
            burn,
            "router conserves the 5% burn leg"
        );
        // The OTHER three legs (88/4/3) are unaffected by routing the burn leg.
        uint256 val = expectedCost * 4 / 100;
        uint256 treas = expectedCost * 3 / 100;
        assertEq(provider.balance - provBefore, expectedCost - burn - val - treas, "provider still gets 88%");
        assertEq(pool.validatorPoolBalance(), val, "validator 4% unaffected");
        assertEq(pool.treasuryBalance(), treas, "treasury 3% unaffected");
    }

    function test_end_to_end_escrow_to_router_to_psp_distribution() public {
        vm.etch(F003, address(new MockF003True()).code);

        // Wire escrow -> router(s=0) -> PSP so the full 5% burn leg funds the PSP.
        address reporter = address(0xE1);
        address distributor = address(0xD2);
        BurnRouter router = new BurnRouter(owner, 100, 300, 1_000);
        ProviderStabilizationPool psp = new ProviderStabilizationPool(owner, 10_000); // 100% cap for a clean split
        vm.startPrank(owner);
        router.setPool(address(psp));
        router.setReporter(reporter);
        psp.setDistributor(distributor);
        escrow.setBurnRouter(address(router));
        vm.stopPrank();
        vm.prank(reporter);
        router.reportIndicator(50); // below iLow => s=0 => entire burn leg goes to PSP

        bytes32 id = keccak256("escrow-e2e");
        _open(id, 10 ether);
        uint256 expectedCost = (uint256(ASK_IN) * 100 + 999) / 1000 + (uint256(ASK_OUT) * 1536 + 999) / 1000;
        uint256 burn = expectedCost * 5 / 100;

        vm.prank(provider);
        escrow.claim(id, _receipt(1, 100, 1536, false), pubkey, sig);
        assertEq(address(psp).balance, burn, "s=0 routes the whole burn leg to the PSP");

        // The distributor tops up one served provider, who pulls it.
        address served = address(0xF00D);
        address[] memory provs = new address[](1);
        provs[0] = served;
        uint256[] memory tokens = new uint256[](1);
        tokens[0] = 1000;
        vm.prank(distributor);
        psp.distribute(1, provs, tokens);
        assertEq(psp.owed(served), burn, "served provider credited the routed flow");
        vm.prank(served);
        psp.withdraw();
        assertEq(served.balance, burn, "provider pulled the counter-cyclical top-up");
    }

    function test_claim_falls_back_to_burn_sink_when_router_reverts() public {
        vm.etch(F003, address(new MockF003True()).code);

        // A router with no pool set + a fresh (never-reported) indicator would
        // route all-burn fine; instead point burnRouter at a contract that reverts
        // on receive to prove the claim still settles via the BURN_SINK fallback.
        RevertingSink bad = new RevertingSink();
        vm.prank(owner);
        escrow.setBurnRouter(address(bad));

        bytes32 id = keccak256("escrow-fallback");
        _open(id, 10 ether);
        uint256 expectedCost = (uint256(ASK_IN) * 100 + 999) / 1000 + (uint256(ASK_OUT) * 1536 + 999) / 1000;
        uint256 burn = expectedCost * 5 / 100;
        uint256 sinkBefore = MilConstants.BURN_SINK.balance;

        // The claim must NOT revert - the burn leg falls back to BURN_SINK.
        vm.prank(provider);
        escrow.claim(id, _receipt(1, 100, 1536, false), pubkey, sig);
        assertEq(MilConstants.BURN_SINK.balance - sinkBefore, burn, "burn fell back to the eater; claim still settled");
        assertEq(address(bad).balance, 0, "reverting router received nothing");
    }

    function test_claim_is_incremental_across_receipts() public {
        vm.etch(F003, address(new MockF003True()).code);
        bytes32 id = keccak256("escrow-2");
        _open(id, 10 ether);

        vm.prank(provider);
        escrow.claim(id, _receipt(1, 100, 512, false), pubkey, sig);
        uint256 cost1 = escrow.get(id).settledCost;

        vm.prank(provider);
        escrow.claim(id, _receipt(2, 100, 1536, true), pubkey, sig);
        uint256 cost2 = escrow.get(id).settledCost;

        assertGt(cost2, cost1, "cumulative settlement grows");
        assertTrue(escrow.get(id).finalized);

        // no claims after final
        vm.prank(provider);
        vm.expectRevert(JobEscrow.AlreadyFinalized.selector);
        escrow.claim(id, _receipt(3, 100, 2000, false), pubkey, sig);
    }

    function test_claim_rejects_bad_signature() public {
        vm.etch(F003, address(new MockF003False()).code);
        bytes32 id = keccak256("escrow-3");
        _open(id, 10 ether);
        vm.prank(provider);
        vm.expectRevert(JobEscrow.BadReceiptSignature.selector);
        escrow.claim(id, _receipt(1, 100, 512, false), pubkey, sig);
    }

    function test_claim_rejects_session_and_pubkey_and_counter() public {
        vm.etch(F003, address(new MockF003True()).code);
        bytes32 id = keccak256("escrow-4");
        _open(id, 10 ether);

        // wrong session id
        MilReceipt memory wrongSession = _receipt(1, 100, 512, false);
        wrongSession.sessionId = _repeat(0x11, 64);
        vm.prank(provider);
        vm.expectRevert(JobEscrow.SessionMismatch.selector);
        escrow.claim(id, wrongSession, pubkey, sig);

        // wrong pubkey (does not match registered hash)
        bytes memory wrongPk = new bytes(2592);
        wrongPk[0] = 0x01;
        vm.prank(provider);
        vm.expectRevert(JobEscrow.PubkeyMismatch.selector);
        escrow.claim(id, _receipt(1, 100, 512, false), wrongPk, sig);

        // non-provider caller
        vm.prank(requester);
        vm.expectRevert(JobEscrow.NotProviderOperator.selector);
        escrow.claim(id, _receipt(1, 100, 512, false), pubkey, sig);

        // good claim, then a non-increasing counter
        vm.prank(provider);
        escrow.claim(id, _receipt(2, 100, 512, false), pubkey, sig);
        vm.prank(provider);
        vm.expectRevert(JobEscrow.NonMonotonicCounter.selector);
        escrow.claim(id, _receipt(2, 100, 1024, false), pubkey, sig);
    }

    function test_dns_final_threshold_gates_large_claims() public {
        vm.etch(F003, address(new MockF003True()).code);
        bytes32 id = keccak256("escrow-5");
        _open(id, 1000 ether);

        // a claim whose cumulative cost exceeds the threshold needs a DNS-final open block
        uint64 bigOut = uint64((DNS_THRESHOLD / ASK_OUT) * 1000 + 1000); // cost > threshold
        vm.prank(provider);
        vm.expectRevert(JobEscrow.NotDnsFinal.selector);
        escrow.claim(id, _receipt(1, 0, bigOut, false), pubkey, sig);

        // report the open block as DNS-final → claim succeeds
        vm.prank(dnsReporter);
        escrow.reportDnsFinalizedBlock(block.number);
        vm.prank(provider);
        escrow.claim(id, _receipt(1, 0, bigOut, false), pubkey, sig);
        assertGt(escrow.get(id).settledCost, DNS_THRESHOLD);
    }

    function test_dns_final_via_f005_precompile() public {
        vm.etch(F003, address(new MockF003True()).code);
        // install a mock F005 with settable storage
        MockF005 mock = new MockF005();
        vm.etch(F005, address(mock).code);
        bytes32 id = keccak256("escrow-f005");

        // F005 reports the current block DAA = 1000 at open time
        MockF005(F005).set(1000, 0);
        _open(id, 1000 ether); // openDaa recorded = 1000

        uint64 bigOut = uint64((DNS_THRESHOLD / ASK_OUT) * 1000 + 1000);

        // DNS-final anchor DAA = 500 < openDaa(1000) → open not yet DNS-final → revert
        MockF005(F005).set(1000, 500);
        vm.prank(provider);
        vm.expectRevert(JobEscrow.NotDnsFinal.selector);
        escrow.claim(id, _receipt(1, 0, bigOut, false), pubkey, sig);

        // DNS-final anchor advances to DAA = 2000 ≥ openDaa(1000) → open is DNS-final → ok
        MockF005(F005).set(1000, 2000);
        vm.prank(provider);
        escrow.claim(id, _receipt(1, 0, bigOut, false), pubkey, sig);
        assertGt(escrow.get(id).settledCost, DNS_THRESHOLD);
    }

    function test_refund_after_close() public {
        vm.etch(F003, address(new MockF003True()).code);
        bytes32 id = keccak256("escrow-6");
        _open(id, 10 ether);
        vm.prank(provider);
        escrow.claim(id, _receipt(1, 100, 512, true), pubkey, sig);
        uint256 settled = escrow.get(id).settledCost;

        vm.prank(requester);
        escrow.close(id);

        uint256 before = requester.balance;
        vm.prank(requester);
        escrow.refund(id);
        assertEq(requester.balance - before, 10 ether - settled, "requester gets the unsettled remainder");
    }

    // --- stake / unbond ---

    function test_stake_bond_unbond_delay() public {
        vm.prank(provider);
        stake.bond{value: 200 ether}(providerId);
        assertEq(stake.bondedAmount(provider), 200 ether);

        vm.prank(provider);
        stake.requestUnbond(50 ether);
        assertEq(stake.bondedAmount(provider), 150 ether);

        // cannot withdraw before the 7-day delay
        vm.prank(provider);
        vm.expectRevert(StakeManager.UnbondNotReady.selector);
        stake.withdraw();

        vm.warp(block.timestamp + 7 days);
        uint256 before = provider.balance;
        vm.prank(provider);
        stake.withdraw();
        assertEq(provider.balance - before, 50 ether);
    }

    // --- dispute / slash ---

    function test_dispute_guilty_slashes_50pct() public {
        vm.prank(provider);
        stake.bond{value: 200 ether}(providerId);

        address challenger = address(0xCA11);
        vm.deal(challenger, 10 ether);
        bytes32 dId = keccak256("dispute-1");
        vm.prank(challenger);
        dispute.openDispute{value: 1 ether}(dId, providerId, keccak256("evidence"));

        uint256 challBefore = challenger.balance;
        uint256 burnBefore = MilConstants.BURN_SINK.balance;

        vm.prank(committee);
        dispute.resolve(dId, true);

        // 50% of 200 = 100 slashed; StakeManager splits it 50/50 challenger/burn
        assertEq(stake.bondedAmount(provider), 100 ether, "50% slashed");
        // challenger: bond returned (1) + half of slash (50)
        assertEq(challenger.balance - challBefore, 1 ether + 50 ether);
        assertEq(MilConstants.BURN_SINK.balance - burnBefore, 50 ether);
    }

    function test_dispute_innocent_forfeits_bond() public {
        address challenger = address(0xCA12);
        vm.deal(challenger, 10 ether);
        bytes32 dId = keccak256("dispute-2");
        vm.prank(challenger);
        dispute.openDispute{value: 1 ether}(dId, providerId, keccak256("evidence"));

        uint256 burnBefore = MilConstants.BURN_SINK.balance;
        vm.prank(committee);
        dispute.resolve(dId, false);
        assertEq(MilConstants.BURN_SINK.balance - burnBefore, 1 ether, "innocent challenger bond burned");
    }

    function _repeat(uint8 b, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = bytes1(b);
        }
    }
}
