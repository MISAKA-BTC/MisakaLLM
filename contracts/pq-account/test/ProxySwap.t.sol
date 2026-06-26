// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {MisakaPqSmartAccount} from "../src/MisakaPqSmartAccount.sol";

/// EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1.
bytes32 constant EIP1967_IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

/// A trivial implementation a proxy could point at — exposes the generic `poke(uint256)`
/// selector the session would call. Its presence is irrelevant to the deny (the account
/// never inspects the impl); it only makes the scenario concrete.
contract Impl {
    function poke(uint256) external payable returns (uint256) {
        return 1;
    }
}

/// A UUPS / ERC-1822 proxy mock: it exposes `proxiableUUID()` returning the EIP-1967 impl
/// slot constant (the canonical UUPS signal), and stores its implementation in that very
/// slot — so the bytecode (`codehash`) is STABLE across an `upgradeTo`, exactly the H-2 hole
/// a `codeHashPin` over the proxy bytecode would fail to close.
contract UupsProxyMock {
    constructor(address impl) {
        assembly {
            sstore(EIP1967_IMPL_SLOT, impl)
        }
    }

    function proxiableUUID() external pure returns (bytes32) {
        return EIP1967_IMPL_SLOT;
    }

    /// Swap the implementation without changing the proxy's own bytecode (codehash stays fixed).
    function upgradeTo(address impl) external {
        assembly {
            sstore(EIP1967_IMPL_SLOT, impl)
        }
    }

    /// Forward the generic call to whatever the impl slot currently points at, so absent the
    /// account's deny the session op would actually execute against the (swappable) impl.
    fallback() external payable {
        address impl;
        assembly {
            impl := sload(EIP1967_IMPL_SLOT)
        }
        (bool ok, bytes memory ret) = impl.delegatecall(msg.data);
        require(ok, "proxy: impl reverted");
        assembly {
            return(add(ret, 0x20), mload(ret))
        }
    }

    receive() external payable {}
}

/// A Transparent / Beacon-style proxy mock: it exposes `implementation()` returning a
/// non-zero address (the OZ Transparent/Beacon signal). It does NOT expose `proxiableUUID()`.
contract TransparentProxyMock {
    address public impl;

    constructor(address impl_) {
        impl = impl_;
    }

    function implementation() external view returns (address) {
        return impl;
    }

    /// Swap the implementation without changing the proxy bytecode.
    function upgradeTo(address impl_) external {
        impl = impl_;
    }

    function poke(uint256) external payable returns (uint256) {
        return 2;
    }
}

/// A plain (non-proxy) contract — neither `proxiableUUID()` nor `implementation()`. Used to
/// prove the H-2 deny is SCOPED to detected proxies: a generic pinned call to an ordinary
/// contract still succeeds (no over-broad regression).
contract PlainTarget {
    uint256 public last;

    function poke(uint256 x) external payable returns (uint256) {
        last = x;
        return x;
    }
}

/// H-2: a `codeHashPin` pins only the TARGET's bytecode. For an EIP-1967/UUPS/Transparent
/// upgradeable proxy the proxy bytecode (`codehash`) is stable while the implementation slot
/// is swapped, so the pin does NOT prevent an implementation swap under the grant. The account
/// now DEFAULT-DENIES (option A) a generic session call to a detected upgradeable proxy.
contract ProxySwapTest is Test {
    MisakaPqSmartAccount internal account;

    uint256 internal constant SK = 0xA11CE;
    uint64 internal constant VERSION = 1;
    uint8 internal constant TS_NATIVE = 0;

    function setUp() public {
        account = new MisakaPqSmartAccount(
            bytes32(uint256(0x7777)), bytes32(uint256(0x8888)), bytes32(uint256(0x1111)), bytes32(uint256(0x2222)), VERSION
        );
        vm.deal(address(account), 100 ether);
    }

    // --------------------------------------------------------------------- helpers

    function _sk() internal pure returns (address) {
        return vm.addr(SK);
    }

    function _sessionSig(address tgt, uint256 value, bytes memory callData, uint64 callIndex)
        internal
        view
        returns (bytes memory)
    {
        bytes32 domain = keccak256("MISAKA_PQ_EXECUTE_SESSION_V1");
        bytes32 opHash = keccak256(
            abi.encode(domain, block.chainid, address(account), VERSION, tgt, value, keccak256(callData), callIndex, uint256(0))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SK, opHash);
        return abi.encodePacked(r, s, v);
    }

    function _grantV2(MisakaPqSmartAccount.PolicyEntry[] memory entries, uint128 maxNative, uint64 maxCalls) internal {
        vm.prank(address(account));
        account.grantSessionV2(_sk(), type(uint64).max, maxCalls, maxNative, entries);
    }

    function _entryPinned(bytes32 key, uint8 std, uint256 maxPerCall, uint256 maxTotal, uint256 id, bytes32 codeHashPin)
        internal
        pure
        returns (MisakaPqSmartAccount.PolicyEntry memory)
    {
        return MisakaPqSmartAccount.PolicyEntry({
            targetSelectorKey: key,
            standard: std,
            maxPerCall: maxPerCall,
            maxTotal: maxTotal,
            erc1155TokenId: id,
            codeHashPin: codeHashPin
        });
    }

    function _grantGenericPinned(address target, bytes4 sel, bytes32 pin) internal {
        MisakaPqSmartAccount.PolicyEntry[] memory e = new MisakaPqSmartAccount.PolicyEntry[](1);
        e[0] = _entryPinned(account.allowKey(target, sel), TS_NATIVE, 0, 0, 0, pin);
        _grantV2(e, 1 ether, 5);
    }

    // ----------------------------------------------------------------------- tests

    /// CORE H-2 assertion: same proxy codehash + a CHANGED implementation => the generic
    /// session call is rejected. The grant pins the proxy's bytecode (`address(proxy).codehash`),
    /// which is byte-identical before and after `upgradeTo`, so the pin "matches" — yet the call
    /// is denied because the target is a detected upgradeable proxy.
    function test_uups_proxy_same_codehash_swapped_impl_is_rejected() public {
        Impl implA = new Impl();
        Impl implB = new Impl();
        UupsProxyMock proxy = new UupsProxyMock(address(implA));
        bytes4 sel = Impl.poke.selector;
        bytes32 pin = address(proxy).codehash; // pin the PROXY bytecode (the only thing pinnable)

        _grantGenericPinned(address(proxy), sel, pin);

        // Swap the implementation; the proxy's own bytecode (codehash) is unchanged.
        bytes32 codehashBefore = address(proxy).codehash;
        proxy.upgradeTo(address(implB));
        assertEq(address(proxy).codehash, codehashBefore, "proxy codehash must be stable across impl swap");
        assertEq(address(proxy).codehash, pin, "pin still matches the proxy bytecode after the swap");

        bytes memory cd = abi.encodeWithSelector(sel, uint256(0));
        vm.expectRevert("PQ: generic session call to an upgradeable proxy denied");
        account.executeSession(address(proxy), 0, cd, 0, _sessionSig(address(proxy), 0, cd, 0), 0);
    }

    /// Even WITHOUT a swap, the generic call to a UUPS proxy is denied at grant-execute time —
    /// the deny does not depend on observing a swap (which the account cannot see), only on the
    /// target being detectably upgradeable.
    function test_uups_proxy_generic_call_denied_even_with_matching_pin() public {
        Impl implA = new Impl();
        UupsProxyMock proxy = new UupsProxyMock(address(implA));
        bytes4 sel = Impl.poke.selector;

        _grantGenericPinned(address(proxy), sel, address(proxy).codehash);

        bytes memory cd = abi.encodeWithSelector(sel, uint256(0));
        vm.expectRevert("PQ: generic session call to an upgradeable proxy denied");
        account.executeSession(address(proxy), 0, cd, 0, _sessionSig(address(proxy), 0, cd, 0), 0);
    }

    /// Transparent/Beacon detection: a proxy exposing only `implementation()` (non-zero) is
    /// likewise denied, and a post-swap call (same codehash, different impl) stays denied.
    function test_transparent_proxy_swapped_impl_is_rejected() public {
        Impl implA = new Impl();
        Impl implB = new Impl();
        TransparentProxyMock proxy = new TransparentProxyMock(address(implA));
        bytes4 sel = TransparentProxyMock.poke.selector;
        bytes32 pin = address(proxy).codehash;

        _grantGenericPinned(address(proxy), sel, pin);

        proxy.upgradeTo(address(implB));
        assertEq(address(proxy).codehash, pin, "transparent proxy codehash stable across impl swap");

        bytes memory cd = abi.encodeWithSelector(sel, uint256(0));
        vm.expectRevert("PQ: generic session call to an upgradeable proxy denied");
        account.executeSession(address(proxy), 0, cd, 0, _sessionSig(address(proxy), 0, cd, 0), 0);
    }

    /// Scope check (no over-broad regression): a generic pinned call to an ORDINARY contract
    /// (not a proxy — exposes neither proxiableUUID nor implementation) still succeeds.
    function test_plain_contract_generic_pinned_call_still_allowed() public {
        PlainTarget tgt = new PlainTarget();
        bytes4 sel = PlainTarget.poke.selector;

        _grantGenericPinned(address(tgt), sel, address(tgt).codehash);

        bytes memory cd = abi.encodeWithSelector(sel, uint256(7));
        account.executeSession(address(tgt), 0, cd, 0, _sessionSig(address(tgt), 0, cd, 0), 0);
        assertEq(tgt.last(), 7, "generic pinned call to a non-proxy executes");
    }
}
