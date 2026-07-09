// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {MilShieldedEscrow} from "../src/MilShieldedEscrow.sol";
import {MilConstants} from "../src/MilCommon.sol";

/// F004 mock: returns a deterministic 64-byte "keyed BLAKE2b" so the pool's
/// incremental Merkle tree + anchor ring are stable in tests. (Real hash
/// consistency with misaka-mil-shield is validated Rust-side.)
contract MockF004 {
    fallback(bytes calldata input) external returns (bytes memory) {
        return abi.encodePacked(keccak256(input), keccak256(abi.encodePacked(input, uint8(0xA5))));
    }
}

/// F006 mock (always valid): returns the 32-byte ABI-true word.
contract MockF006True {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(1));
    }
}

/// F006 mock (always invalid): returns ABI-false.
contract MockF006False {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(0));
    }
}

contract MilShieldedTest is Test {
    address constant F004 = address(0x0000000000000000000000000000000000F004);
    address constant F006 = address(0x0000000000000000000000000000000000F006);
    uint256 constant SCALE = 10_000_000_000;

    ShieldedPool pool;
    MilShieldedEscrow escrow;
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
        escrow = new MilShieldedEscrow(owner, address(pool), rewardPool, setRoot, vk);
    }

    // ---- ShieldedPool value path ----

    function _spendPub(bytes memory anchor, uint8 nfa, uint8 nfb, uint8 cma, uint8 cmb, uint64 vin, uint64 vout)
        internal
        pure
        returns (ShieldedPool.SpendPublic memory p)
    {
        p.anchor = anchor;
        p.nf0 = _b64(nfa);
        p.nf1 = _b64(nfb);
        p.cm0 = _b64(cma);
        p.cm1 = _b64(cmb);
        p.vPubIn = vin;
        p.vPubOut = vout;
        p.tokenId = 0;
        p.ctx = _b64(0xC7);
    }

    function test_shield_credits_pool_and_moves_root() public {
        bytes memory anchor = pool.root(); // the genesis root is a known anchor
        uint64 sompi = 100;
        ShieldedPool.SpendPublic memory p = _spendPub(anchor, 0x01, 0x02, 0x11, 0x12, sompi, 0);
        pool.shield{value: uint256(sompi) * SCALE}(p, hex"deadbeef", hex"", hex"");
        assertEq(pool.poolBalance(), uint256(sompi) * SCALE, "pool credited");
        assertTrue(pool.nullifierSpent(keccak256(p.nf0)), "nf0 marked spent");
    }

    function test_shield_wrong_value_scale_reverts() public {
        bytes memory anchor = pool.root();
        ShieldedPool.SpendPublic memory p = _spendPub(anchor, 0x01, 0x02, 0x11, 0x12, 100, 0);
        vm.expectRevert(ShieldedPool.ValueScaleMismatch.selector);
        pool.shield{value: 1}(p, hex"deadbeef", hex"", hex"");
    }

    function test_double_spend_nullifier_rejected() public {
        bytes memory anchor = pool.root();
        ShieldedPool.SpendPublic memory p = _spendPub(anchor, 0x01, 0x02, 0x11, 0x12, 100, 0);
        pool.shield{value: 100 * SCALE}(p, hex"aa", hex"", hex"");
        // reuse nf0 on a fresh anchor → rejected
        bytes memory anchor2 = pool.root();
        ShieldedPool.SpendPublic memory q = _spendPub(anchor2, 0x01, 0x03, 0x21, 0x22, 50, 0);
        vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
        pool.shield{value: 50 * SCALE}(q, hex"bb", hex"", hex"");
    }

    function test_unknown_anchor_rejected() public {
        ShieldedPool.SpendPublic memory p = _spendPub(_b64(0xFF), 0x01, 0x02, 0x11, 0x12, 100, 0);
        vm.expectRevert(ShieldedPool.UnknownAnchor.selector);
        pool.shield{value: 100 * SCALE}(p, hex"aa", hex"", hex"");
    }

    function test_invalid_proof_rejected() public {
        vm.etch(F006, address(new MockF006False()).code);
        bytes memory anchor = pool.root();
        ShieldedPool.SpendPublic memory p = _spendPub(anchor, 0x01, 0x02, 0x11, 0x12, 100, 0);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.shield{value: 100 * SCALE}(p, hex"aa", hex"", hex"");
    }

    function test_unshield_pays_out_and_debits_pool() public {
        // shield 100, then unshield 40 to `to`
        bytes memory a0 = pool.root();
        pool.shield{value: 100 * SCALE}(_spendPub(a0, 0x01, 0x02, 0x11, 0x12, 100, 0), hex"aa", hex"", hex"");
        address to = address(0xD00D);
        bytes memory a1 = pool.root();
        ShieldedPool.SpendPublic memory p = _spendPub(a1, 0x03, 0x04, 0x31, 0x32, 0, 40);
        pool.unshield(p, hex"bb", to, hex"", hex"");
        assertEq(to.balance, 40 * SCALE, "recipient paid");
        assertEq(pool.poolBalance(), 60 * SCALE, "pool debited");
    }

    // ---- anonymous escrow ----

    function _claimPub(bytes memory sessionCm, uint64 amount, uint8 nf, uint8 cmPayout)
        internal
        pure
        returns (MilShieldedEscrow.ClaimPublic memory c)
    {
        c.sessionCm = sessionCm;
        c.amount = amount;
        c.providerNf = _b64(nf);
        c.cmPayout = _b64(cmPayout);
        c.ctx = _b64(0xC7);
    }

    function test_openBlind_and_claimAnon_split_88_5_7() public {
        bytes memory session = _b64(0x77);
        bytes32 id = keccak256("job-1");
        uint256 lockWei = 100 * SCALE;
        escrow.openBlind{value: lockWei}(id, session);

        uint64 gross = 100; // sompi
        uint256 grossWei = uint256(gross) * SCALE;
        uint256 providerWei = (grossWei * 88) / 100;
        uint256 burnWei = (grossWei * 5) / 100;
        uint256 poolLeg = grossWei - providerWei - burnWei;
        uint64 providerSompi = uint64(providerWei / SCALE);

        uint256 burnBefore = MilConstants.BURN_SINK.balance;
        MilShieldedEscrow.ClaimPublic memory c = _claimPub(session, providerSompi, 0x01, 0x90);
        escrow.claimAnon(id, c, gross, hex"deadbeef", hex"");

        assertEq(pool.poolBalance(), providerWei, "88% paid into shielded pool as a note");
        assertEq(MilConstants.BURN_SINK.balance - burnBefore, burnWei, "5% burned");
        assertEq(rewardPool.balance, poolLeg, "4%+3% to reward pool");
        assertTrue(escrow.providerNfSpent(keccak256(c.providerNf)), "provider nullifier spent");
        // NOTHING on-chain names a provider: no providerId, no operator address.
    }

    function test_double_claim_same_provider_nullifier_rejected() public {
        bytes memory session = _b64(0x77);
        bytes32 id = keccak256("job-2");
        escrow.openBlind{value: 100 * SCALE}(id, session);
        uint64 providerSompi = uint64(((uint256(100) * SCALE * 88) / 100) / SCALE);
        MilShieldedEscrow.ClaimPublic memory c = _claimPub(session, providerSompi, 0x01, 0x90);
        escrow.claimAnon(id, c, 100, hex"aa", hex"");
        // same provider nullifier → rejected (at-most-once per session)
        vm.expectRevert(MilShieldedEscrow.ProviderNfSpent.selector);
        escrow.claimAnon(id, c, 100, hex"aa", hex"");
    }

    function test_claimAnon_wrong_session_rejected() public {
        escrow.openBlind{value: 100 * SCALE}(keccak256("job-3"), _b64(0x77));
        MilShieldedEscrow.ClaimPublic memory c = _claimPub(_b64(0x99), 88, 0x01, 0x90); // wrong session
        vm.expectRevert(MilShieldedEscrow.SessionMismatch.selector);
        escrow.claimAnon(keccak256("job-3"), c, 100, hex"aa", hex"");
    }

    function test_claimAnon_split_binding_enforced() public {
        bytes memory session = _b64(0x77);
        bytes32 id = keccak256("job-4");
        escrow.openBlind{value: 100 * SCALE}(id, session);
        // pub.amount does not equal the 88% share → SplitMismatch
        MilShieldedEscrow.ClaimPublic memory c = _claimPub(session, 50, 0x01, 0x90);
        vm.expectRevert(MilShieldedEscrow.SplitMismatch.selector);
        escrow.claimAnon(id, c, 100, hex"aa", hex"");
    }

    function test_refundBlind_returns_remainder() public {
        bytes32 id = keccak256("job-5");
        escrow.openBlind{value: 100 * SCALE}(id, _b64(0x77));
        uint256 before = address(this).balance;
        escrow.refundBlind(id);
        assertEq(address(this).balance - before, 100 * SCALE, "remainder refunded");
    }

    receive() external payable {}
}
