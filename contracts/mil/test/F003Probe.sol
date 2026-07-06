// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @dev On-lane proof aid: `check` staticcalls the F003 (0x…F003) precompile with
///      `version‖pubkey‖sig‖message` — the exact call MilReceiptLib.verify makes
///      inside JobEscrow.claim() — and stores the verified bit in slot 0. forge can
///      only mock F003; this runs through kaspa-evm's revm with the real precompile.
contract F003Probe {
    address constant F003 = address(0xF003);
    bool public lastOk; // storage slot 0

    function check(bytes calldata input) external {
        (bool s, bytes memory ret) = F003.staticcall(input);
        lastOk = s && ret.length == 32 && ret[31] == 0x01;
    }
}
