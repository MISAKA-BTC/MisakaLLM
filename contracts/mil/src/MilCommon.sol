// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title MIL shared constants, access control, and the receipt-verification library.
/// @notice MISAKA Inference Lane (MIL) v1 EVM-lane primitives (design §8.2/§8.3).
///         All contracts in this suite are self-contained (forge-std only in
///         tests) and interoperate through constructor-injected addresses.

/// @dev ML-DSA-87 sizes (FIPS 204) — must match the Rust consts
///      `MLDSA87_PK_LEN=2592`, `MLDSA87_SIG_LEN=4627`.
library MilConstants {
    uint256 internal constant MLDSA87_PK_LEN = 2592;
    uint256 internal constant MLDSA87_SIG_LEN = 4627;

    /// @dev F003 MLDSA87_VERIFY precompile; version 0x03 = MIL receipt/message verify.
    address internal constant F003 = address(0x0000000000000000000000000000000000F003);
    uint8 internal constant F003_VERSION_MIL_RECEIPT = 0x03;

    /// @dev F004 HASH64 (keyed BLAKE2b-512) precompile.
    address internal constant F004 = address(0x0000000000000000000000000000000000F004);

    /// @dev F005 DNS_FINALITY precompile (§8.4): returns
    ///      `abi.encode(uint256 currentDaa, uint256 dnsFinalDaa)`.
    address internal constant F005 = address(0x0000000000000000000000000000000000F005);

    /// @dev The exact byte-length of a v1 MIL receipt signing transcript
    ///      (`misaka_mil_core::receipt::ReceiptBody::signing_message`):
    ///      version(2) ‖ session_id(64) ‖ counter(8) ‖ cum_in(8) ‖ cum_out(8)
    ///      ‖ ts(8) ‖ cm_resp(64) ‖ is_final(1) = 163.
    uint256 internal constant RECEIPT_MESSAGE_LEN = 163;
    uint16 internal constant MIL_PROTOCOL_VERSION = 1;

    /// @dev Fee split (§5.3), in percent. Must sum to 100.
    uint256 internal constant FEE_PROVIDER_PCT = 88;
    uint256 internal constant FEE_BURN_PCT = 5;
    uint256 internal constant FEE_VALIDATOR_PCT = 4;
    uint256 internal constant FEE_TREASURY_PCT = 3;

    /// @dev Where the burn share is sent (conventional unspendable sink).
    address internal constant BURN_SINK = address(0x000000000000000000000000000000000000dEaD);
}

/// @dev Little-endian integer encoding — the MIL wire format is LE (Rust
///      `to_le_bytes`), while Solidity's `abi.encodePacked` is big-endian, so
///      every integer field of the receipt transcript is byte-reversed here.
library MilLE {
    function le16(uint16 v) internal pure returns (bytes memory out) {
        out = new bytes(2);
        out[0] = bytes1(uint8(v));
        out[1] = bytes1(uint8(v >> 8));
    }

    function le64(uint64 v) internal pure returns (bytes memory out) {
        out = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            out[i] = bytes1(uint8(v >> (8 * i)));
        }
    }
}

/// @dev The canonical v1 MIL receipt fields (mirrors the Rust `ReceiptBody`).
struct MilReceipt {
    uint16 version;
    bytes sessionId; // 64 bytes (Hash64)
    uint64 counter;
    uint64 cumTokensIn;
    uint64 cumTokensOut;
    uint64 timestampMs;
    bytes cmResp; // 64 bytes (Hash64)
    bool isFinal;
}

/// @dev Reconstruct + ML-DSA-87-verify a MIL receipt on-chain via F003 v0x03.
library MilReceiptLib {
    using MilLE for uint16;
    using MilLE for uint64;

    /// @notice Reconstruct the 163-byte receipt signing transcript that the
    ///         provider enclave signed. Reverts if the Hash64 fields are not
    ///         exactly 64 bytes.
    function message(MilReceipt memory r) internal pure returns (bytes memory msgBytes) {
        require(r.sessionId.length == 64, "MIL: sessionId must be 64 bytes");
        require(r.cmResp.length == 64, "MIL: cmResp must be 64 bytes");
        msgBytes = abi.encodePacked(
            MilLE.le16(r.version),
            r.sessionId,
            MilLE.le64(r.counter),
            MilLE.le64(r.cumTokensIn),
            MilLE.le64(r.cumTokensOut),
            MilLE.le64(r.timestampMs),
            r.cmResp,
            r.isFinal ? bytes1(0x01) : bytes1(0x00)
        );
        require(msgBytes.length == MilConstants.RECEIPT_MESSAGE_LEN, "MIL: bad transcript length");
    }

    /// @notice Verify `signature` over the receipt transcript under `pubkey`
    ///         via the F003 v0x03 precompile. Returns false on any malformed
    ///         input or bad signature (never reverts on a verify failure).
    ///         Reverts only on wrong key/sig lengths (caller bug).
    function verify(MilReceipt memory r, bytes memory pubkey, bytes memory signature) internal view returns (bool) {
        require(pubkey.length == MilConstants.MLDSA87_PK_LEN, "MIL: bad pubkey length");
        require(signature.length == MilConstants.MLDSA87_SIG_LEN, "MIL: bad signature length");
        bytes memory input =
            abi.encodePacked(MilConstants.F003_VERSION_MIL_RECEIPT, pubkey, signature, message(r));
        (bool ok, bytes memory ret) = MilConstants.F003.staticcall(input);
        return ok && ret.length == 32 && uint8(ret[31]) == 1;
    }
}

/// @dev Minimal single-owner access control (self-contained, no OpenZeppelin).
abstract contract MilOwned {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error ZeroAddress();

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
