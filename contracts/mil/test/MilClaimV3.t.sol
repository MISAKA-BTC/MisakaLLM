// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {MilShieldedEscrow} from "../src/MilShieldedEscrow.sol";
import {MilConstants} from "../src/MilCommon.sol";
import {MockF004, MockF006True, MockF006False} from "./MilShielded.t.sol";

/// Exposes the internal v3 statement builder so the circuit-3 layout pin can be asserted directly
/// (it is otherwise reachable only through F006, which the mock short-circuits). Pure passthrough.
contract MilShieldedEscrowV3Harness is MilShieldedEscrow {
    constructor(address o, address pool_, address reward, bytes memory setRoot, bytes memory vkHash)
        MilShieldedEscrow(o, pool_, reward, setRoot, vkHash)
    {}

    function borshClaimStatementV3(
        bytes memory setRoot,
        ClaimPublicV3 calldata pub,
        uint64 providerShareSompi,
        bytes memory ctx
    ) external pure returns (bytes memory) {
        return _borshClaimStatementV3(setRoot, pub, providerShareSompi, ctx);
    }
}

/// The circuit_version=3 (C-P6 receipt-authorized claim) PRODUCTION SURFACE — COMPLETE but INERT.
/// Mirrors how the circuit-4 (claim-v2) surface is tested (`MilClaimV2Split.t.sol`):
///
/// - `test_v3_dispatchable_in_policy` — circuit 3 is pinnable via the ATOMIC `setClaimPolicy` and
///   snapshotted into an escrow at open, so an escrow can be LOCKED to the receipt-authorized path.
/// - `test_v3_statement_layout_matches_rust_schema` — the frozen 456-byte v3 statement layout
///   (schema: `mil/shield/src/statement_schema.rs::PROVIDER_CLAIM_V3_STATEMENT_SCHEMA`) is pinned
///   against an independent byte reconstruction; the `receiptCm` insertion sits at [320,384) and
///   pushes `providerShareSompi` to [384,392) and `ctx` to [392,456).
/// - `test_v3_claim_fail_closed_while_inert` — a circuit-3 claim is fail-closed at BOTH the C-06
///   `claimsEnabled` gate AND the F006 verify (unfrozen circuit-3 vk ⇒ F006 rejects) — the two
///   independent locks that keep it inert until C-P6 activates.
/// - `test_v3_dispatch_plumbing_settles_under_mock_true` — with F006 mocked TRUE (the plumbing
///   proof only), the full dispatch settles: statement builds, split computes, `ClaimedAnonV3`
///   emits — demonstrating the surface is COMPLETE, not a stub.
contract MilClaimV3Test is Test {
    address constant F004 = address(0x0000000000000000000000000000000000F004);
    address constant F006 = address(0x0000000000000000000000000000000000F006);
    uint256 constant SCALE = 10_000_000_000;

    ShieldedPool pool;
    MilShieldedEscrowV3Harness escrow;
    address owner = address(0xA11CE);
    address rewardPool = address(0xBEEF);
    bytes vk = _b64(0xB0);
    bytes setRoot = _b64(0x5E);

    function _b64(uint8 fill) internal pure returns (bytes memory b) {
        b = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            b[i] = bytes1(fill);
        }
    }

    function setUp() public {
        vm.etch(F004, address(new MockF004()).code);
        vm.etch(F006, address(new MockF006True()).code);
        pool = new ShieldedPool(owner, vk);
        escrow = new MilShieldedEscrowV3Harness(owner, address(pool), rewardPool, setRoot, vk);
        vm.startPrank(owner);
        pool.setNoteIssuer(address(escrow));
        escrow.setClaimsEnabled(true);
        // pin the C-P6 receipt-authorized circuit (3) as the ATOMIC claim policy.
        escrow.setClaimPolicy(3, vk, 2, setRoot, hex"");
        vm.stopPrank();
    }

    function _claimPubV3(bytes memory sessionCm, uint8 vcm, uint8 nf, uint8 cmPayout, uint8 receiptCm)
        internal
        pure
        returns (MilShieldedEscrow.ClaimPublicV3 memory c)
    {
        c.sessionCm = sessionCm;
        c.vClaimCm = _b64(vcm);
        c.providerNf = _b64(nf);
        c.cmPayout = _b64(cmPayout);
        c.receiptCm = _b64(receiptCm);
    }

    /// Circuit 3 is dispatchable in the atomic policy and snapshotted at open.
    function test_v3_dispatchable_in_policy() public {
        assertEq(escrow.activeClaimCircuit(), 3, "circuit 3 pinned in the active policy");
        bytes memory session = _b64(0x77);
        bytes32 id = keccak256("job-v3-dispatch");
        escrow.openBlind{value: 100 * SCALE}(id, session);
        (,,,,,,,,, uint16 snapCircuit,) = escrow.escrows(id);
        assertEq(snapCircuit, 3, "escrow locked to circuit 3 (C-P6) at open");
        // and the wrong-path guard holds: claimAnonV2 (circuit 4) against a circuit-3 escrow reverts.
        MilShieldedEscrow.ClaimPublicV2 memory c2;
        c2.sessionCm = session;
        c2.vClaimCm = _b64(0xCA);
        c2.providerNf = _b64(0x01);
        c2.cmPayout = _b64(0x90);
        vm.expectRevert(MilShieldedEscrow.WrongClaimCircuit.selector);
        escrow.claimAnonV2(id, c2, 30_000, 20_000, hex"aa", hex"");
    }

    /// The frozen 456-byte v3 statement layout on the CONTRACT side, matched to the Rust schema:
    /// setRoot(64) ‖ sessionCm(64) ‖ vClaimCm(64) ‖ providerNf(64) ‖ cmPayout(64) ‖ receiptCm(64)
    /// ‖ le64(providerShareSompi) ‖ ctx(64). receiptCm occupies [320,384); share [384,392); ctx
    /// [392,456). Field mutations move ONLY their own range.
    function test_v3_statement_layout_matches_rust_schema() public view {
        bytes memory root = _b64(0x5E);
        MilShieldedEscrow.ClaimPublicV3 memory c = _claimPubV3(_b64(0x77), 0xCA, 0x01, 0x90, 0xE7);
        bytes memory ctx = _b64(0xC7);
        uint64 share = 0x0102030405060708;

        bytes memory s1 = escrow.borshClaimStatementV3(root, c, share, ctx);
        assertEq(s1.length, 456, "v3 statement is the schema-frozen 456 bytes");

        // independent byte-level reconstruction (le64 built by hand, not _le64).
        bytes memory le64 = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            le64[i] = bytes1(uint8(share >> (8 * i)));
        }
        bytes memory expected = bytes.concat(root, c.sessionCm, c.vClaimCm, c.providerNf, c.cmPayout, c.receiptCm, le64, ctx);
        assertEq(keccak256(s1), keccak256(expected), "layout == independently reconstructed packed bytes");

        // receiptCm sits at [320,384): mutating it moves ONLY those bytes.
        MilShieldedEscrow.ClaimPublicV3 memory c2 = _claimPubV3(_b64(0x77), 0xCA, 0x01, 0x90, 0xEE);
        bytes memory s2 = escrow.borshClaimStatementV3(root, c2, share, ctx);
        assertTrue(keccak256(s1) != keccak256(s2), "receiptCm mutation must change the statement");
        for (uint256 i = 0; i < 456; i++) {
            if (i >= 320 && i < 384) continue;
            assertEq(s1[i], s2[i], "receiptCm mutation must be localized to [320,384)");
        }

        // share le64 sits at [384,392): +1 moves ONLY those 8 bytes (and is little-endian).
        bytes memory s3 = escrow.borshClaimStatementV3(root, c, share + 1, ctx);
        for (uint256 i = 0; i < 456; i++) {
            if (i >= 384 && i < 392) continue;
            assertEq(s1[i], s3[i], "share mutation must be localized to [384,392)");
        }
        assertEq(uint8(s1[384]), 0x08, "le64: LSB first");
        assertEq(uint8(s1[391]), 0x01, "le64: MSB last");
        // ctx occupies the final [392,456).
        assertEq(uint8(s1[392]), 0xC7, "ctx starts at offset 392");
        assertEq(uint8(s1[455]), 0xC7, "ctx ends at offset 455");
    }

    /// A circuit-3 claim is fail-closed while inert — at BOTH the C-06 claimsEnabled gate and the
    /// F006 verify (unfrozen circuit-3 vk ⇒ F006 rejects fail-closed).
    function test_v3_claim_fail_closed_while_inert() public {
        bytes memory session = _b64(0x77);

        // (1) F006 rejects: model the production reality that circuit 3's vk is unfrozen, so F006
        //     returns false. The claim reaches the verify (all pre-checks pass) and reverts ProofInvalid.
        vm.etch(F006, address(new MockF006False()).code);
        bytes32 id = keccak256("job-v3-failclosed");
        escrow.openBlind{value: 100 * SCALE}(id, session);
        MilShieldedEscrow.ClaimPublicV3 memory c = _claimPubV3(session, 0xCA, 0x01, 0x90, 0xE7);
        vm.expectRevert(MilShieldedEscrow.ProofInvalid.selector);
        escrow.claimAnonV3(id, c, 30_000, 20_000, hex"deadbeef", hex"");

        // (2) the C-06 gate: a fresh escrow with claims DISABLED reverts ClaimsDisabled before any
        //     verify — the second independent lock keeping circuit 3 inert until C-P6 activation.
        MilShieldedEscrow e2 = new MilShieldedEscrow(owner, address(pool), rewardPool, setRoot, vk);
        vm.prank(owner);
        e2.setClaimPolicy(3, vk, 2, setRoot, hex""); // policy set so openBlind is allowed, claims still off
        bytes32 id2 = keccak256("job-v3-disabled");
        e2.openBlind{value: 100 * SCALE}(id2, session);
        vm.expectRevert(MilShieldedEscrow.ClaimsDisabled.selector);
        e2.claimAnonV3(id2, c, 30_000, 20_000, hex"deadbeef", hex"");
    }

    /// PLUMBING proof only (F006 mocked TRUE): the full circuit-3 dispatch settles end-to-end —
    /// statement builds, the 88/5/7 split computes, and `ClaimedAnonV3` emits with the receipt
    /// commitment. This demonstrates the surface is COMPLETE (not a stub); it does NOT weaken the
    /// inert guarantee, which rests on the real F006 rejecting the unfrozen circuit-3 vk (test above).
    function test_v3_dispatch_plumbing_settles_under_mock_true() public {
        bytes memory session = _b64(0x77);
        bytes32 id = keccak256("job-v3-plumbing");
        escrow.openBlind{value: 100 * SCALE}(id, session);

        // 30k in + 20k out = 50k tokens, price 2 ⇒ gross 100 sompi.
        uint256 grossWei = ((uint256(2) * (uint256(30_000) + 20_000)) / 1000) * SCALE;
        uint256 providerWei = (grossWei * 88) / 100;
        uint256 burnWei = (grossWei * 5) / 100;
        uint256 poolLeg = grossWei - providerWei - burnWei;
        uint256 burnBefore = MilConstants.BURN_SINK.balance;
        uint256 rewardBefore = rewardPool.balance;

        MilShieldedEscrow.ClaimPublicV3 memory c = _claimPubV3(session, 0xCA, 0x02, 0x91, 0xE7);
        vm.expectEmit(true, false, false, true, address(escrow));
        emit MilShieldedEscrow.ClaimedAnonV3(id, c.vClaimCm, c.receiptCm, c.cmPayout);
        escrow.claimAnonV3(id, c, 30_000, 20_000, hex"deadbeef", hex"");

        assertEq(pool.poolBalance(), providerWei, "88% into shielded pool as a note");
        assertEq(MilConstants.BURN_SINK.balance - burnBefore, burnWei, "5% burned");
        assertEq(rewardPool.balance - rewardBefore, poolLeg, "7% to reward pool");
        assertTrue(escrow.providerNfSpent(keccak256(c.providerNf)), "provider nullifier spent");
    }

    receive() external payable {}
}
