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

/// Exposes internals so the audit regressions can assert the ctx binding + root-ring
/// eviction directly (they are otherwise reachable only through F006, which the mock
/// short-circuits).
contract ShieldedPoolHarness is ShieldedPool {
    constructor(address o, bytes memory vk) ShieldedPool(o, vk) {}

    function ctxFor(uint8 action, address to, SpendPublic calldata pub, bytes calldata e0, bytes calldata e1)
        external
        view
        returns (bytes memory)
    {
        return _computeCtx(action, to, pub, keccak256(e0), keccak256(e1));
    }

    function insertLeaf(bytes calldata cm) external returns (uint256) {
        return _insert(cm, hex"");
    }

    uint8 public constant A_SHIELD = 1;
    uint8 public constant A_TRANSFER = 2;
    uint8 public constant A_UNSHIELD = 3;
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
        // (audit C-01) only the escrow may mint payout notes; (C-06) enable claims for
        // the settlement tests (production keeps them off until the receipt circuit lands).
        vm.startPrank(owner);
        pool.setNoteIssuer(address(escrow));
        escrow.setClaimsEnabled(true);
        // (M-04) configure the ATOMIC claim policy (default = circuit 2 / public-amount claim);
        // a pinned non-zero circuit is now REQUIRED before any openBlind (wildcard-0 rejected).
        escrow.setClaimPolicy(2, vk, 0, setRoot, hex"");
        vm.stopPrank();
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
        // (H-01) refund is blocked until the claim window elapses.
        vm.expectRevert(MilShieldedEscrow.RefundTooEarly.selector);
        escrow.refundBlind(id);
        vm.warp(block.timestamp + 1 hours + 1);
        uint256 before = address(this).balance;
        escrow.refundBlind(id);
        assertEq(address(this).balance - before, 100 * SCALE, "remainder refunded");
    }

    // ---- anonymous escrow, HIDDEN amount (B2 / ADR-0037 §2.3) ----

    function _claimPubV2(bytes memory sessionCm, uint8 vcm, uint8 nf, uint8 cmPayout)
        internal
        pure
        returns (MilShieldedEscrow.ClaimPublicV2 memory c)
    {
        c.sessionCm = sessionCm;
        c.vClaimCm = _b64(vcm); // value commitment — carries NO clear magnitude
        c.providerNf = _b64(nf);
        c.cmPayout = _b64(cmPayout);
    }

    function test_claimAnonV2_uniform_price_hidden_amount() public {
        bytes memory session = _b64(0x77);
        bytes32 id = keccak256("job-v2-1");
        // Uniform protocol price: 50_000 sompi / 1k tokens — IDENTICAL for every provider and a
        // whole-sompi denomination (multiple of 25_000, the M-07 funding gate), set (with circuit 4)
        // as an ATOMIC policy BEFORE open so it is snapshotted into the escrow (M-04).
        uint64 price = 50_000;
        vm.prank(owner);
        escrow.setClaimPolicy(4, vk, price, setRoot, hex"");

        // 30,000 in + 20,000 out = 50,000 tokens ⇒ gross = 50_000·50 = 2_500_000 sompi (≡ 0 mod 25).
        uint64 tokIn = 30_000;
        uint64 tokOut = 20_000;
        uint256 grossWei = ((uint256(price) * (uint256(tokIn) + tokOut)) / 1000) * SCALE;
        escrow.openBlind{value: grossWei}(id, session);
        uint256 providerWei = (grossWei * 88) / 100;
        uint256 burnWei = (grossWei * 5) / 100;
        uint256 poolLeg = grossWei - providerWei - burnWei;

        uint256 burnBefore = MilConstants.BURN_SINK.balance;
        uint256 rewardBefore = rewardPool.balance;

        MilShieldedEscrow.ClaimPublicV2 memory c = _claimPubV2(session, 0xCA, 0x01, 0x90);
        // The event MUST NOT carry a public magnitude — only the value commitment.
        vm.expectEmit(true, false, false, true, address(escrow));
        emit MilShieldedEscrow.ClaimedAnonV2(id, c.vClaimCm, c.cmPayout);
        escrow.claimAnonV2(id, c, tokIn, tokOut, hex"deadbeef", hex"");

        assertEq(pool.poolBalance(), providerWei, "88% into shielded pool as a note");
        assertEq(MilConstants.BURN_SINK.balance - burnBefore, burnWei, "5% burned");
        assertEq(rewardPool.balance - rewardBefore, poolLeg, "7% to reward pool");
        assertTrue(escrow.providerNfSpent(keccak256(c.providerNf)), "provider nullifier spent");
        // The remainder stays locked; nothing on-chain reveals the amount or the provider.
    }

    function test_claimAnonV2_double_spend_rejected() public {
        bytes memory session = _b64(0x77);
        bytes32 id = keccak256("job-v2-2");
        vm.prank(owner);
        escrow.setClaimPolicy(4, vk, 50_000, setRoot, hex""); // whole-sompi price (M-07); 50k·50k/1k = 2_500_000 gross
        escrow.openBlind{value: 2_500_000 * SCALE}(id, session);
        MilShieldedEscrow.ClaimPublicV2 memory c = _claimPubV2(session, 0xCA, 0x01, 0x90);
        escrow.claimAnonV2(id, c, 30_000, 20_000, hex"aa", hex"");
        vm.expectRevert(MilShieldedEscrow.ProviderNfSpent.selector);
        escrow.claimAnonV2(id, c, 30_000, 20_000, hex"aa", hex"");
    }

    function test_claimAnonV2_overdraw_rejected() public {
        bytes memory session = _b64(0x77);
        bytes32 id = keccak256("job-v2-3");
        vm.prank(owner);
        escrow.setClaimPolicy(4, vk, 50_000, setRoot, hex""); // whole-sompi price (M-07); 50k·50k/1k = 2_500_000 sompi > 10 locked
        escrow.openBlind{value: 10 * SCALE}(id, session);
        MilShieldedEscrow.ClaimPublicV2 memory c = _claimPubV2(session, 0xCA, 0x01, 0x90);
        vm.expectRevert(MilShieldedEscrow.Overdraw.selector);
        escrow.claimAnonV2(id, c, 30_000, 20_000, hex"aa", hex"");
    }

    function test_setClaimPolicy_only_owner() public {
        vm.expectRevert();
        escrow.setClaimPolicy(2, vk, 5, setRoot, hex"");
    }

    // ==== audit 2026-07-11 regressions (C-01..C-06, H-01, H-04, M-01, M-02) ====

    /// C-01: an arbitrary EOA cannot mint an unbacked note; only the authorized escrow.
    function test_C01_depositNote_only_issuer() public {
        vm.expectRevert(ShieldedPool.NotIssuer.selector);
        pool.depositNote(_b64(0x33), hex""); // called by the test EOA, not the escrow
        // the authorized issuer (escrow) can, via claimAnon — already exercised.
    }

    /// C-02: shield may not carry a public output; unshield may not carry a public input.
    function test_C02_mode_strictness() public {
        bytes memory anchor = pool.root();
        ShieldedPool.SpendPublic memory bad = _spendPub(anchor, 0x01, 0x02, 0x11, 0x12, 100, 5); // vOut>0 on shield
        vm.expectRevert(ShieldedPool.BadMode.selector);
        pool.shield{value: 100 * SCALE}(bad, hex"aa", hex"", hex"");

        ShieldedPool.SpendPublic memory bad2 = _spendPub(anchor, 0x03, 0x04, 0x21, 0x22, 7, 40); // vIn>0 on unshield
        vm.expectRevert(ShieldedPool.BadMode.selector);
        pool.unshield(bad2, hex"aa", address(0xD00D), hex"", hex"");
    }

    /// C-03: the SAME note in both input lanes (nf0==nf1) is rejected (no value double-count).
    function test_C03_duplicate_input_nullifier_rejected() public {
        bytes memory anchor = pool.root();
        ShieldedPool.SpendPublic memory p = _spendPub(anchor, 0x07, 0x07, 0x11, 0x12, 100, 0); // nf0==nf1
        vm.expectRevert(ShieldedPool.DuplicateInputNullifier.selector);
        pool.shield{value: 100 * SCALE}(p, hex"aa", hex"", hex"");
    }

    /// C-04: every Hash64 field must be exactly 64 bytes (no boundary-shift replay).
    function test_C04_noncanonical_hash_length_rejected() public {
        bytes memory anchor = pool.root();
        ShieldedPool.SpendPublic memory p = _spendPub(anchor, 0x01, 0x02, 0x11, 0x12, 100, 0);
        p.nf0 = new bytes(63); // 63/65 split attempt
        vm.expectRevert(ShieldedPool.BadHashLen.selector);
        pool.shield{value: 100 * SCALE}(p, hex"aa", hex"", hex"");
    }

    /// C-05 / H-04: the recomputed ctx binds recipient, action, and ciphertext, so a
    /// proof cannot be replayed onto a different `to` / entrypoint / encNote.
    function test_C05_ctx_binds_recipient_action_ciphertext() public {
        ShieldedPoolHarness h = new ShieldedPoolHarness(owner, vk);
        ShieldedPool.SpendPublic memory p = _spendPub(h.root(), 0x03, 0x04, 0x31, 0x32, 0, 40);
        bytes memory ctxVictim = h.ctxFor(h.A_UNSHIELD(), address(0xD00D), p, hex"e0", hex"e1");
        bytes memory ctxAttacker = h.ctxFor(h.A_UNSHIELD(), address(0xBAD), p, hex"e0", hex"e1");
        bytes memory ctxShield = h.ctxFor(h.A_SHIELD(), address(0xD00D), p, hex"e0", hex"e1");
        bytes memory ctxCipher = h.ctxFor(h.A_UNSHIELD(), address(0xD00D), p, hex"ff", hex"e1");
        assertTrue(keccak256(ctxVictim) != keccak256(ctxAttacker), "ctx binds recipient (front-run closed)");
        assertTrue(keccak256(ctxVictim) != keccak256(ctxShield), "ctx binds the action");
        assertTrue(keccak256(ctxVictim) != keccak256(ctxCipher), "ctx binds the ciphertext (H-04)");
    }

    /// C-06: anonymous claims are DISABLED by default (until the receipt circuit lands).
    function test_C06_claims_disabled_by_default() public {
        MilShieldedEscrow e2 = new MilShieldedEscrow(owner, address(pool), rewardPool, setRoot, vk);
        // configure a claim policy so openBlind is allowed (M-04), but leave claims DISABLED
        // (the C-06 default) so the claim path is what reverts.
        vm.prank(owner);
        e2.setClaimPolicy(2, vk, 0, setRoot, hex"");
        bytes memory session = _b64(0x77);
        bytes32 id = keccak256("job-c06");
        e2.openBlind{value: 100 * SCALE}(id, session);
        MilShieldedEscrow.ClaimPublic memory c = _claimPub(session, 88, 0x01, 0x90);
        vm.expectRevert(MilShieldedEscrow.ClaimsDisabled.selector);
        e2.claimAnon(id, c, 100, hex"aa", hex"");
    }

    /// M-01: only the most recent ROOT_RING anchors stay known (freshness window works).
    function test_M01_root_ring_evicts_stale_anchors() public {
        ShieldedPoolHarness h = new ShieldedPoolHarness(owner, vk);
        bytes memory genesis = h.root();
        assertTrue(h.rootKnown(keccak256(genesis)), "genesis initially known");
        // ROOT_RING (128) fresh inserts evict the genesis slot.
        for (uint256 i = 0; i < 128; i++) {
            h.insertLeaf(_b64(uint8(i + 1)));
        }
        assertFalse(h.rootKnown(keccak256(genesis)), "stale genesis anchor evicted");
    }

    /// M-04: openBlind snapshots the WHOLE atomic claim policy (provider-set root, VK, price,
    /// ask root, circuit, policy version), so a later governance rotation does not shift the
    /// eligible set / re-price / retarget / re-key an in-flight claim.
    function test_M04_open_snapshots_provider_set() public {
        bytes memory session = _b64(0x77);
        bytes32 id = keccak256("job-m04");
        uint64 priceA = 50_000; // whole-sompi price (M-07 funding gate: multiple of 25_000)
        bytes memory askRootA = _b64(0x5A);
        // policy A (circuit 2), adopted (atomically) before open.
        vm.prank(owner);
        escrow.setClaimPolicy(2, vk, priceA, setRoot, askRootA);
        uint64 policyAId = escrow.claimPolicyId();
        escrow.openBlind{value: 100 * SCALE}(id, session);
        // governance rotates the ENTIRE policy AFTER open (new circuit, vk, price, root, askRoot).
        vm.prank(owner);
        escrow.setClaimPolicy(4, _b64(0xB1), priceA + 25_000, _b64(0xAA), _b64(0x6B)); // 75_000, another whole-sompi price
        (
            ,
            ,
            ,
            ,
            ,
            bytes memory snapRoot,
            bytes memory snapVk,
            uint64 snapPrice,
            bytes memory snapAskRoot,
            uint16 snapCircuit,
            uint64 snapPolicyId
        ) = escrow.escrows(id);
        assertEq(keccak256(snapRoot), keccak256(setRoot), "provider-set root frozen at open");
        assertEq(keccak256(snapVk), keccak256(vk), "vk frozen at open");
        assertEq(snapPrice, priceA, "price frozen at open (M-04)");
        assertEq(keccak256(snapAskRoot), keccak256(askRootA), "ask-root frozen at open (M-04)");
        assertEq(snapCircuit, 2, "claim-circuit frozen at open (M-04, pinned 2)");
        assertEq(snapPolicyId, policyAId, "policy version frozen at open (M-04 atomic snapshot)");
        assertTrue(keccak256(escrow.providerSetRoot()) != keccak256(setRoot), "global root actually rotated");
        assertTrue(escrow.uniformPricePer1k() != priceA, "global price actually rotated");
        assertTrue(keccak256(escrow.askCommitmentRoot()) != keccak256(askRootA), "global ask-root rotated");
        assertTrue(escrow.claimPolicyId() != policyAId, "global policy version advanced");
    }

    /// B2 (ADR-0037 §2.3.1): the committed-ask root is now set as part of the ATOMIC claim
    /// policy (M-04), length-gated (64B or empty). Owner-only; preserves per-provider ADR-0029
    /// floors while hiding them; the claim binding is the gated V3 follow-up, so pinning a root
    /// is inert. Empty by default (committed-ask model not yet adopted).
    function test_B2_setClaimPolicy_askroot_owner_and_length() public {
        assertEq(escrow.askCommitmentRoot().length, 0, "committed-ask model unset by default");
        // non-owner cannot set the policy / ask root
        vm.expectRevert();
        escrow.setClaimPolicy(2, vk, 0, setRoot, _b64(0x5A));
        // wrong ask-root length rejected (must be 64B or empty)
        vm.prank(owner);
        vm.expectRevert(MilShieldedEscrow.BadLen.selector);
        escrow.setClaimPolicy(2, vk, 0, setRoot, new bytes(63));
        // owner pins a valid 64B ask root
        vm.prank(owner);
        escrow.setClaimPolicy(2, vk, 0, setRoot, _b64(0x5A));
        assertEq(keccak256(escrow.askCommitmentRoot()), keccak256(_b64(0x5A)), "ask root pinned");
        // and may withdraw the committed-ask model (empty)
        vm.prank(owner);
        escrow.setClaimPolicy(2, vk, 0, setRoot, hex"");
        assertEq(escrow.askCommitmentRoot().length, 0, "committed-ask model withdrawn");
    }

    /// M-02: the native pool rejects non-zero tokenId.
    function test_M02_nonzero_tokenid_rejected() public {
        bytes memory anchor = pool.root();
        ShieldedPool.SpendPublic memory p = _spendPub(anchor, 0x01, 0x02, 0x11, 0x12, 100, 0);
        p.tokenId = 7;
        vm.expectRevert(ShieldedPool.BadTokenId.selector);
        pool.shield{value: 100 * SCALE}(p, hex"aa", hex"", hex"");
    }

    // ==== audit M-04: atomic claim policy + wildcard-0 rejection ====

    /// M-04: the pinned claim circuit is snapshotted at open, and each claim path asserts its
    /// hardcoded circuit == the snapshot (STRICT). Pinning circuit 4 then calling claimAnon
    /// (circuit 2) — and pinning circuit 2 then calling claimAnonV2 (circuit 4) — both revert
    /// WrongClaimCircuit, so a governance-pinned cohort cannot be settled by the wrong path.
    function test_m4_wrong_circuit_claim_rejected() public {
        bytes memory session = _b64(0x77);
        // Pin circuit 4 (hidden-amount): an escrow opened now is locked to claimAnonV2. (Price is
        // irrelevant here — the claim reverts on the circuit mismatch before any gross is computed.)
        vm.prank(owner);
        escrow.setClaimPolicy(4, vk, 0, setRoot, hex"");
        bytes32 id4 = keccak256("job-m4-pinned4");
        escrow.openBlind{value: 100 * SCALE}(id4, session);
        // claimAnon (circuit 2) against a circuit-4 escrow is rejected.
        MilShieldedEscrow.ClaimPublic memory c = _claimPub(session, 88, 0x01, 0x90);
        vm.expectRevert(MilShieldedEscrow.WrongClaimCircuit.selector);
        escrow.claimAnon(id4, c, 100, hex"aa", hex"");

        // Pin circuit 2 (public amount): an escrow opened now is locked to claimAnon.
        vm.prank(owner);
        escrow.setClaimPolicy(2, vk, 0, setRoot, hex"");
        bytes32 id2 = keccak256("job-m4-pinned2");
        escrow.openBlind{value: 100 * SCALE}(id2, session);
        // claimAnonV2 (circuit 4) against a circuit-2 escrow is rejected.
        MilShieldedEscrow.ClaimPublicV2 memory c2 = _claimPubV2(session, 0xCA, 0x01, 0x90);
        vm.expectRevert(MilShieldedEscrow.WrongClaimCircuit.selector);
        escrow.claimAnonV2(id2, c2, 30_000, 20_000, hex"aa", hex"");
    }

    /// M-04: the open→claim happy path through the atomic-policy snapshot. Pinning the matching
    /// circuit records it in the escrow and lets that path settle normally.
    function test_m4_snapshot_circuit_happy_path() public {
        bytes memory session = _b64(0x77);

        // Pin circuit 2, open, and confirm the snapshot + a successful claimAnon.
        vm.prank(owner);
        escrow.setClaimPolicy(2, vk, 0, setRoot, hex"");
        bytes32 id2 = keccak256("job-m4-happy2");
        escrow.openBlind{value: 100 * SCALE}(id2, session);
        (,,,,,,,,, uint16 snap2,) = escrow.escrows(id2);
        assertEq(snap2, 2, "circuit-2 pin snapshotted at open");
        uint64 providerSompi = uint64(((uint256(100) * SCALE * 88) / 100) / SCALE);
        MilShieldedEscrow.ClaimPublic memory c = _claimPub(session, providerSompi, 0x01, 0x90);
        escrow.claimAnon(id2, c, 100, hex"deadbeef", hex"");
        assertEq(pool.poolBalance(), uint256(providerSompi) * SCALE, "circuit-2 claim settled through the snapshot");

        // Pin circuit 4, open, and confirm the snapshot + a successful claimAnonV2. (Whole-sompi
        // price 50_000 · 50k/1k = 2_500_000 sompi gross, M-07 gate; lock ≥ gross to settle.)
        vm.prank(owner);
        escrow.setClaimPolicy(4, vk, 50_000, setRoot, hex"");
        bytes32 id4 = keccak256("job-m4-happy4");
        escrow.openBlind{value: 2_500_000 * SCALE}(id4, session);
        (,,,,,,,,, uint16 snap4,) = escrow.escrows(id4);
        assertEq(snap4, 4, "circuit-4 pin snapshotted at open");
        MilShieldedEscrow.ClaimPublicV2 memory c4 = _claimPubV2(session, 0xCA, 0x02, 0x91);
        escrow.claimAnonV2(id4, c4, 30_000, 20_000, hex"deadbeef", hex"");
        assertTrue(escrow.providerNfSpent(keccak256(c4.providerNf)), "circuit-4 claim settled through the snapshot");
    }

    /// M-04: the ATOMIC policy setter is owner-only and rejects the WILDCARD (0) and any
    /// unregistered circuit id — only a SPECIFIC 2 XOR 4 with a 64B VK is accepted.
    function test_M04_setClaimPolicy_owner_and_valid_circuit() public {
        vm.expectRevert(); // non-owner
        escrow.setClaimPolicy(2, vk, 0, setRoot, hex"");
        // the WILDCARD (0) is now REJECTED — a policy must pin a specific circuit.
        vm.prank(owner);
        vm.expectRevert(MilShieldedEscrow.BadLen.selector);
        escrow.setClaimPolicy(0, vk, 0, setRoot, hex"");
        // an UNREGISTERED circuit id (e.g. 5, the committed-ask V3 follow-up, not yet built) is
        // rejected — only 2 XOR 4 XOR 3 are dispatchable.
        vm.prank(owner);
        vm.expectRevert(MilShieldedEscrow.BadLen.selector);
        escrow.setClaimPolicy(5, vk, 0, setRoot, hex"");
        // a non-64B VK is rejected (coherent-tuple validation).
        vm.prank(owner);
        vm.expectRevert(MilShieldedEscrow.BadLen.selector);
        escrow.setClaimPolicy(2, new bytes(63), 0, setRoot, hex"");
        // valid pins (2, 4, and now the C-P6 receipt circuit 3) accepted; the getter reflects the
        // latest. Circuit 3 is dispatchable as a COMPLETE but INERT surface (its claim path is
        // fail-closed at F006 + claimsEnabled until C-P6 activates).
        vm.prank(owner);
        escrow.setClaimPolicy(4, vk, 0, setRoot, hex"");
        assertEq(escrow.activeClaimCircuit(), 4, "circuit 4 pinned");
        vm.prank(owner);
        escrow.setClaimPolicy(3, vk, 0, setRoot, hex"");
        assertEq(escrow.activeClaimCircuit(), 3, "circuit 3 (C-P6 receipt) pinned");
        vm.prank(owner);
        escrow.setClaimPolicy(2, vk, 0, setRoot, hex"");
        assertEq(escrow.activeClaimCircuit(), 2, "circuit 2 pinned");
    }

    /// (audit M-04) WILDCARD-0 can never authorize settlement: a fresh escrow leaves the claim
    /// policy UNCONFIGURED (activeClaimCircuit == 0), so openBlind reverts ClaimPolicyUnset — the
    /// wildcard is rejected at open, and thus can never reach a claim path at all.
    function test_M04_wildcard0_openBlind_rejected() public {
        MilShieldedEscrow e2 = new MilShieldedEscrow(owner, address(pool), rewardPool, setRoot, vk);
        vm.prank(owner);
        e2.setClaimsEnabled(true);
        assertEq(e2.activeClaimCircuit(), 0, "unconfigured: wildcard 0");
        assertEq(e2.claimPolicyId(), 0, "no policy version yet");
        bytes memory session = _b64(0x77);
        vm.expectRevert(MilShieldedEscrow.ClaimPolicyUnset.selector);
        e2.openBlind{value: 100 * SCALE}(keccak256("job-wild0"), session);
    }

    /// (audit M-04) ATOMIC policy snapshot / no inconsistent (circuit, VK) pair: the circuit and
    /// its VK (and price/roots) can ONLY change together via setClaimPolicy, so no mid-update
    /// race can store a cross pair. Policy A (circuit 2, vkA) and policy B (circuit 4, vkB) each
    /// snapshot their OWN coherent pair — an escrow never carries (2, vkB) or (4, vkA).
    function test_M04_atomic_policy_snapshot() public {
        bytes memory session = _b64(0x77);
        bytes memory vkA = _b64(0xA1);
        bytes memory rootA = _b64(0xA2);
        bytes memory askA = _b64(0xA3);
        bytes memory vkB = _b64(0xB1);
        bytes memory rootB = _b64(0xB2);

        // policy A (circuit 2), open eA. (Whole-sompi prices, M-07 gate: multiples of 25_000.)
        vm.prank(owner);
        escrow.setClaimPolicy(2, vkA, 50_000, rootA, askA);
        uint64 idA = escrow.claimPolicyId();
        bytes32 eA = keccak256("job-atomicA");
        escrow.openBlind{value: 100 * SCALE}(eA, session);

        // policy B (circuit 4, different vk/root/price), open eB.
        vm.prank(owner);
        escrow.setClaimPolicy(4, vkB, 75_000, rootB, hex"");
        uint64 idB = escrow.claimPolicyId();
        bytes32 eB = keccak256("job-atomicB");
        escrow.openBlind{value: 100 * SCALE}(eB, session);

        (,,,,, bytes memory r1, bytes memory v1, uint64 p1, bytes memory a1, uint16 c1, uint64 pid1) = escrow.escrows(eA);
        (,,,,, bytes memory r2, bytes memory v2, uint64 p2,, uint16 c2, uint64 pid2) = escrow.escrows(eB);

        // eA froze policy A's coherent pair — circuit 2 with vkA (never vkB).
        assertEq(c1, 2, "eA circuit == policy A");
        assertEq(keccak256(v1), keccak256(vkA), "eA vk == policy A vk (coherent pair)");
        assertEq(keccak256(r1), keccak256(rootA), "eA root == policy A");
        assertEq(p1, 50_000, "eA price == policy A");
        assertEq(keccak256(a1), keccak256(askA), "eA ask == policy A");
        assertEq(pid1, idA, "eA policy version == A");
        assertTrue(keccak256(v1) != keccak256(vkB), "eA never cross-pairs policy B vk");

        // eB froze policy B's coherent pair — circuit 4 with vkB.
        assertEq(c2, 4, "eB circuit == policy B");
        assertEq(keccak256(v2), keccak256(vkB), "eB vk == policy B vk (coherent pair)");
        assertEq(keccak256(r2), keccak256(rootB), "eB root == policy B");
        assertEq(p2, 75_000, "eB price == policy B");
        assertEq(pid2, idB, "eB policy version == B");
        assertTrue(pid1 != pid2, "distinct policy versions frozen");
    }

    /// (audit M-07) FUNDING-TIME whole-sompi gate: `setClaimPolicy` REJECTS any uniform price that
    /// is not a multiple of 25_000. Such a price could snapshot an escrow whose gross is not
    /// ≡ 0 (mod 25) for some token count, permanently trapping it at claimAnonV2/V3 SplitMismatch —
    /// so the trap is refused at governance time. 0 and exact multiples of 25_000 are accepted.
    function test_M07_setClaimPolicy_rejects_non_whole_sompi_price() public {
        vm.startPrank(owner);
        // non-multiples of 25_000 (including just-off-by-one at the step boundary) are rejected.
        vm.expectRevert(MilShieldedEscrow.PriceNotWholeSompi.selector);
        escrow.setClaimPolicy(4, vk, 1, setRoot, hex"");
        vm.expectRevert(MilShieldedEscrow.PriceNotWholeSompi.selector);
        escrow.setClaimPolicy(4, vk, 24_999, setRoot, hex"");
        vm.expectRevert(MilShieldedEscrow.PriceNotWholeSompi.selector);
        escrow.setClaimPolicy(4, vk, 25_001, setRoot, hex"");
        // 0 and exact multiples of 25_000 are accepted (the getter reflects the latest).
        escrow.setClaimPolicy(4, vk, 0, setRoot, hex"");
        assertEq(escrow.uniformPricePer1k(), 0, "price 0 accepted");
        escrow.setClaimPolicy(4, vk, 25_000, setRoot, hex"");
        assertEq(escrow.uniformPricePer1k(), 25_000, "25_000 accepted");
        escrow.setClaimPolicy(4, vk, 50_000, setRoot, hex"");
        assertEq(escrow.uniformPricePer1k(), 50_000, "50_000 accepted");
        vm.stopPrank();
    }

    receive() external payable {}
}
