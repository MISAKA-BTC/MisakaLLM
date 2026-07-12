// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {MilShieldedEscrow} from "../src/MilShieldedEscrow.sol";
import {MilConstants} from "../src/MilCommon.sol";
import {MockF004, MockF006True} from "./MilShielded.t.sol";

/// Exposes the internal v2 statement builder so the audit C-01 layout pin can be
/// asserted directly (it is otherwise reachable only through F006, which the mock
/// short-circuits). No behavior change — pure passthrough.
contract MilShieldedEscrowHarness is MilShieldedEscrow {
    constructor(address o, address pool_, address reward, bytes memory setRoot, bytes memory vkHash)
        MilShieldedEscrow(o, pool_, reward, setRoot, vkHash)
    {}

    function borshClaimStatementV2(
        bytes memory setRoot,
        ClaimPublicV2 calldata pub,
        uint64 providerShareSompi,
        bytes memory ctx
    ) external pure returns (bytes memory) {
        return _borshClaimStatementV2(setRoot, pub, providerShareSompi, ctx);
    }
}

/// Audit 2026-07-11 C-01/C-02 — the claim-v2 ECONOMIC-EQUALITY differential and the
/// STATEMENT-LAYOUT pin, on the LIVE contract code path:
///
/// - `test_claimV2_split_vectors_differential` drives the SHARED vector file
///   (`test/vectors/claim_v2_split_vectors.json`, also consumed byte-identically by
///   the Rust spec `mil/shield/src/economics.rs::claim_v2_split`) through the real
///   `claimAnonV2`, asserting every wei leg (88% pool deposit / 5% burn / 7% reward)
///   and every SplitMismatch revert — so Solidity and Rust can never drift without a
///   red test on whichever side moved.
/// - `test_claimV2_statement_layout_and_share_binding` pins the frozen 392-byte v2
///   statement (schema: `mil/shield/src/statement_schema.rs`) and that flipping the
///   contract-computed `providerShareSompi` moves EXACTLY the le64 field at [320,328).
contract MilClaimV2SplitTest is Test {
    address constant F004 = address(0x0000000000000000000000000000000000F004);
    address constant F006 = address(0x0000000000000000000000000000000000F006);
    uint256 constant SCALE = 10_000_000_000;
    string constant VECTORS_PATH = "test/vectors/claim_v2_split_vectors.json";

    ShieldedPool pool;
    MilShieldedEscrowHarness escrow;
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
        escrow = new MilShieldedEscrowHarness(owner, address(pool), rewardPool, setRoot, vk);
        vm.startPrank(owner);
        pool.setNoteIssuer(address(escrow));
        escrow.setClaimsEnabled(true);
        vm.stopPrank();
    }

    function _claimPubV2(bytes memory sessionCm, uint8 vcm, uint8 nf, uint8 cmPayout)
        internal
        pure
        returns (MilShieldedEscrow.ClaimPublicV2 memory c)
    {
        c.sessionCm = sessionCm;
        c.vClaimCm = _b64(vcm);
        c.providerNf = _b64(nf);
        c.cmPayout = _b64(cmPayout);
    }

    function _vecUint(string memory json, uint256 i, string memory field) internal pure returns (uint256) {
        // values are DECIMAL STRINGS in the vector file (uint256-exact, no JSON
        // number precision loss) — parse the string, then the integer.
        return vm.parseUint(vm.parseJsonString(json, string.concat(".vectors[", vm.toString(i), "].", field)));
    }

    /// (audit C-02 acceptance) Every shared vector, driven through the LIVE
    /// `claimAnonV2`: settle vectors must move exactly the Rust-computed wei on all
    /// three legs; revert vectors must SplitMismatch. Boundaries covered: zero, the
    /// /1000 floors, gross % 25 ∈ {1, 2, 24}, u64-max-adjacent gross, the uint64
    /// share cast beyond supply, and absolute-max u64 inputs.
    function test_claimV2_split_vectors_differential() public {
        string memory json = vm.readFile(VECTORS_PATH);
        uint256 count = vm.parseJsonUint(json, ".count");
        assertGe(count, 12, "boundary corpus present");
        uint256 okCount;
        uint256 revertCount;
        for (uint256 i = 0; i < count; i++) {
            string memory name = vm.parseJsonString(json, string.concat(".vectors[", vm.toString(i), "].name"));
            uint64 price = uint64(_vecUint(json, i, "price"));
            uint64 tokIn = uint64(_vecUint(json, i, "tokIn"));
            uint64 tokOut = uint64(_vecUint(json, i, "tokOut"));
            bool ok = vm.parseJsonBool(json, string.concat(".vectors[", vm.toString(i), "].ok"));
            uint256 grossWei = _vecUint(json, i, "grossWei");

            // fresh escrow per vector; the uniform price is snapshotted at open (M-04).
            bytes32 id = keccak256(abi.encodePacked("c02-vector", i));
            bytes memory session = _b64(0x77);
            vm.prank(owner);
            escrow.setUniformPrice(price);
            vm.deal(address(this), grossWei + 1 ether);
            escrow.openBlind{value: grossWei}(id, session);

            // unique nullifier/commitment per vector (nf reuse would ProviderNfSpent).
            MilShieldedEscrow.ClaimPublicV2 memory c = _claimPubV2(session, 0xCA, uint8(i + 1), uint8(0x90 + i));

            if (ok) {
                uint256 poolBefore = pool.poolBalance();
                uint256 burnBefore = MilConstants.BURN_SINK.balance;
                uint256 rewardBefore = rewardPool.balance;
                escrow.claimAnonV2(id, c, tokIn, tokOut, hex"deadbeef", hex"");
                assertEq(pool.poolBalance() - poolBefore, _vecUint(json, i, "providerWei"), string.concat(name, ": 88% pool leg"));
                assertEq(
                    MilConstants.BURN_SINK.balance - burnBefore, _vecUint(json, i, "burnWei"), string.concat(name, ": 5% burn leg")
                );
                assertEq(rewardPool.balance - rewardBefore, _vecUint(json, i, "poolWei"), string.concat(name, ": 7% reward leg"));
                // we locked EXACTLY grossWei, so the escrow must be fully debited.
                (, uint256 lockedAfter,,,,,,,,) = escrow.escrows(id);
                assertEq(lockedAfter, 0, string.concat(name, ": grossWei fully debited"));
                okCount++;
            } else {
                vm.expectRevert(MilShieldedEscrow.SplitMismatch.selector);
                escrow.claimAnonV2(id, c, tokIn, tokOut, hex"deadbeef", hex"");
                revertCount++;
            }
        }
        assertGe(okCount, 6, "settle vectors exercised");
        assertGe(revertCount, 4, "SplitMismatch vectors exercised");
    }

    /// (audit C-01) The frozen v2 statement layout on the CONTRACT side: 392 bytes,
    /// `setRoot(64) || sessionCm(64) || vClaimCm(64) || providerNf(64) || cmPayout(64)
    /// || le64(providerShareSompi) || ctx(64)` — independently reconstructed — and the
    /// payout mutation (share flip / ±1) moves EXACTLY the bytes at [320,328), so a
    /// tampered share can never alias any other field (the Rust schema manifest
    /// `PROVIDER_CLAIM_V2_STATEMENT_SCHEMA` pins the same offsets).
    function test_claimV2_statement_layout_and_share_binding() public view {
        bytes memory root = _b64(0x5E);
        MilShieldedEscrow.ClaimPublicV2 memory c = _claimPubV2(_b64(0x77), 0xCA, 0x01, 0x90);
        bytes memory ctx = _b64(0xC7);
        uint64 share = 0x0102030405060708;

        bytes memory s1 = escrow.borshClaimStatementV2(root, c, share, ctx);
        assertEq(s1.length, 392, "v2 statement is the schema-frozen 392 bytes");

        // independent byte-level reconstruction (le64 built by hand, not _le64).
        bytes memory le64 = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            le64[i] = bytes1(uint8(share >> (8 * i)));
        }
        bytes memory expected = bytes.concat(root, c.sessionCm, c.vClaimCm, c.providerNf, c.cmPayout, le64, ctx);
        assertEq(keccak256(s1), keccak256(expected), "layout == independently reconstructed packed bytes");

        // payout mutations: +1, -1, bit-63 flip — each moves ONLY [320,328).
        uint64[3] memory mutants = [share + 1, share - 1, share ^ (uint64(1) << 63)];
        for (uint256 m = 0; m < 3; m++) {
            bytes memory s2 = escrow.borshClaimStatementV2(root, c, mutants[m], ctx);
            assertEq(s2.length, 392);
            assertTrue(keccak256(s1) != keccak256(s2), "share mutation must change the statement");
            for (uint256 i = 0; i < 392; i++) {
                if (i >= 320 && i < 328) continue;
                assertEq(s1[i], s2[i], "share mutation must be localized to the le64 field");
            }
        }
        // and the field is little-endian (byte 320 is the LSB) — matching borsh u64.
        assertEq(uint8(s1[320]), 0x08, "le64: LSB first");
        assertEq(uint8(s1[327]), 0x01, "le64: MSB last");
    }

    /// (audit C-02, liveness consequence pinned) A gross that is not a multiple of 25
    /// sompi (price 2 x 51,000 tokens => gross 102) makes claimAnonV2 revert
    /// SplitMismatch PERMANENTLY — no state is consumed (the nullifier stays unspent),
    /// retrying can never succeed, and the requester's only exit is refundBlind after
    /// the delay. The pricing layer must quantize gross to multiples of 25 (see
    /// mil/shield/src/economics.rs normative semantics).
    function test_claimAnonV2_nonwhole_sompi_reverts_permanently_then_refunds() public {
        bytes32 id = keccak256("c02-gross-102");
        bytes memory session = _b64(0x77);
        vm.prank(owner);
        escrow.setUniformPrice(2);
        uint256 lockWei = 102 * SCALE;
        vm.deal(address(this), lockWei + 1 ether);
        escrow.openBlind{value: lockWei}(id, session);

        MilShieldedEscrow.ClaimPublicV2 memory c = _claimPubV2(session, 0xCA, 0x01, 0x90);
        vm.expectRevert(MilShieldedEscrow.SplitMismatch.selector);
        escrow.claimAnonV2(id, c, 51_000, 0, hex"deadbeef", hex"");
        // the revert rolled the nullifier back — a retry hits the SAME wall, not
        // ProviderNfSpent: the claim is permanently unsettleable at these inputs.
        vm.expectRevert(MilShieldedEscrow.SplitMismatch.selector);
        escrow.claimAnonV2(id, c, 51_000, 0, hex"deadbeef", hex"");

        // the only exit: requester refund after the H-01 delay.
        vm.warp(block.timestamp + 1 hours + 1);
        uint256 before = address(this).balance;
        escrow.refundBlind(id);
        assertEq(address(this).balance - before, lockWei, "locked funds recoverable only via refund");
    }

    receive() external payable {}
}
