// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {MilConstants, MilLE, MilReceipt, MilReceiptLib} from "../src/MilCommon.sol";

/// @dev Exercises the receipt-transcript reconstruction against a byte-exact
///      fixture emitted by the Rust `ReceiptBody::signing_message()` (mil-core),
///      proving the Solidity LE encoding matches the enclave's signing message.
contract MilReceiptTest is Test {
    using MilReceiptLib for MilReceipt;

    function _fixtureReceipt() internal pure returns (MilReceipt memory r) {
        r.version = 1;
        r.sessionId = _repeat(0xAB, 64);
        r.counter = 3;
        r.cumTokensIn = 100;
        r.cumTokensOut = 1536;
        r.timestampMs = 1_780_000_000_123;
        r.cmResp = _repeat(0xCD, 64);
        r.isFinal = true;
    }

    // The exact 163-byte message produced by mil-core for the fixture above.
    bytes internal constant FIXTURE_MESSAGE =
        hex"0100abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab0300000000000000640000000000000000060000000000007b8844709e010000cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd01";

    function test_message_matches_rust_signing_message() public pure {
        MilReceipt memory r = _fixtureReceipt();
        bytes memory got = MilReceiptLib.message(r);
        assertEq(got.length, MilConstants.RECEIPT_MESSAGE_LEN);
        assertEq(got, FIXTURE_MESSAGE, "Solidity transcript must equal the Rust signing_message byte-for-byte");
    }

    function test_le_encoding() public pure {
        assertEq(MilLE.le16(1), hex"0100");
        assertEq(MilLE.le16(0x0102), hex"0201");
        assertEq(MilLE.le64(3), hex"0300000000000000");
        assertEq(MilLE.le64(1536), hex"0006000000000000");
    }

    /// @dev External wrapper so `vm.expectRevert` catches the internal-library
    ///      revert at a lower call depth.
    function externalMessage(MilReceipt memory r) external pure returns (bytes memory) {
        return MilReceiptLib.message(r);
    }

    function test_message_rejects_wrong_hash64_lengths() public {
        MilReceipt memory r = _fixtureReceipt();
        r.sessionId = _repeat(0xAB, 63);
        vm.expectRevert("MIL: sessionId must be 64 bytes");
        this.externalMessage(r);
    }

    function _repeat(uint8 b, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = bytes1(b);
        }
    }
}
