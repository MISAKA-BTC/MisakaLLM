// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MilConstants, MilOwned} from "./MilCommon.sol";

/// @title BurnRouter — MIL v0.13 §24.7 counter-cyclical burn router.
/// @notice The single EVM-lane contract every burn-bound flow passes through:
///         B1 (JobEscrow's 5% burn leg) and B2 (the gateway's burn-margin buy).
///         The buy/collect is UNCONDITIONAL — value always arrives here; only the
///         DESTINATION switches with network revenue. A revenue indicator `I`
///         (off-chain: 7-day fee USD / non-standby active devices, reporter-fed)
///         drives a continuous ramp `s = clamp((I - iLow)/(iHigh - iLow), 0, 1)`:
///         `s` of the flow burns (to the native eater sink), `1 - s` funds the
///         Provider Stabilization Pool.
///
///         Design invariants (ADR-0029 D9 / precondition 5):
///         - Touches ONLY already-earned flow — never issuance, cap, or the
///           70/25/5 coinbase split. Zero flow ⇒ zero pool (no dilution path).
///         - Continuous ramp, not a binary threshold (no boundary flap / cliff).
///         - FSL-read failure (stale or unset indicator, or no pool) ⇒ `s = 1`
///           (ALL-burn) — never routes to the pool on bad data.
contract BurnRouter is MilOwned {
    /// @dev Basis-points denominator (100% = 10_000).
    uint256 internal constant BPS = 10_000;

    /// The Provider Stabilization Pool that receives the `1 - s` share. While
    /// unset, `s` is forced to 1 (all-burn) — value is never stranded.
    address public pool;
    /// The authorized indicator reporter (off-chain aggregator).
    address public reporter;

    /// Ramp band: below `iLow` ⇒ s=0 (all-pool); at/above `iHigh` ⇒ s=1 (all-burn).
    uint256 public iLow;
    uint256 public iHigh;

    /// Latest reported indicator and the block it was reported at.
    uint256 public currentI;
    uint256 public indicatorBlock;
    /// Reports older than this many blocks are stale ⇒ fail-safe to all-burn.
    uint256 public maxStaleBlocks;
    /// True once a first indicator has been reported.
    bool public indicatorSet;

    event PoolUpdated(address indexed pool);
    event ReporterUpdated(address indexed reporter);
    event BandUpdated(uint256 iLow, uint256 iHigh, uint256 maxStaleBlocks);
    event IndicatorReported(uint256 indexed i, uint256 atBlock);
    /// @notice Emitted on every routed flow — the Proof-of-Buyback anchor (§23.8).
    event Routed(uint256 amount, uint256 sBps, uint256 burned, uint256 toPool);

    error NotReporter();
    error BadBand();
    error NothingToRoute();
    error TransferFailed();

    constructor(address initialOwner, uint256 _iLow, uint256 _iHigh, uint256 _maxStaleBlocks) MilOwned(initialOwner) {
        if (_iHigh <= _iLow) revert BadBand();
        iLow = _iLow;
        iHigh = _iHigh;
        maxStaleBlocks = _maxStaleBlocks;
    }

    modifier onlyReporter() {
        if (msg.sender != reporter) revert NotReporter();
        _;
    }

    function setPool(address _pool) external onlyOwner {
        pool = _pool;
        emit PoolUpdated(_pool);
    }

    function setReporter(address _reporter) external onlyOwner {
        reporter = _reporter;
        emit ReporterUpdated(_reporter);
    }

    function setBand(uint256 _iLow, uint256 _iHigh, uint256 _maxStaleBlocks) external onlyOwner {
        if (_iHigh <= _iLow) revert BadBand();
        iLow = _iLow;
        iHigh = _iHigh;
        maxStaleBlocks = _maxStaleBlocks;
        emit BandUpdated(_iLow, _iHigh, _maxStaleBlocks);
    }

    /// @notice Report the current revenue indicator (off-chain: 7d fee USD /
    ///         non-standby active devices). Resets the staleness clock.
    function reportIndicator(uint256 i) external onlyReporter {
        currentI = i;
        indicatorBlock = block.number;
        indicatorSet = true;
        emit IndicatorReported(i, block.number);
    }

    /// @notice The current burn share in basis points (0..10_000). Public so
    ///         reporters, dashboards, and Proof-of-Buyback can pre-compute it.
    function currentBurnShareBps() public view returns (uint256) {
        // Fail-safe to all-burn: no pool, never reported, or stale.
        if (pool == address(0) || !indicatorSet || block.number - indicatorBlock > maxStaleBlocks) {
            return BPS;
        }
        if (currentI <= iLow) return 0; // low revenue ⇒ all-pool
        if (currentI >= iHigh) return BPS; // high revenue ⇒ all-burn
        return (currentI - iLow) * BPS / (iHigh - iLow); // linear ramp
    }

    /// @notice Route the incoming flow: `s` burns, `1 - s` funds the pool.
    ///         Permissionless (the value IS the flow to split); called by
    ///         JobEscrow (B1) and the gateway (B2), or by a plain send.
    function route() public payable {
        _route(msg.value);
    }

    /// @dev A plain value send routes the same way (JobEscrow's `.call{value}("")`).
    receive() external payable {
        _route(msg.value);
    }

    function _route(uint256 amount) internal {
        if (amount == 0) revert NothingToRoute();
        uint256 sBps = currentBurnShareBps();
        uint256 burned = amount * sBps / BPS;
        uint256 toPool = amount - burned;

        if (burned > 0) {
            (bool okBurn,) = payable(MilConstants.BURN_SINK).call{value: burned}("");
            if (!okBurn) revert TransferFailed();
        }
        if (toPool > 0) {
            // sBps < BPS ⇒ pool is set (currentBurnShareBps returns BPS when pool==0).
            (bool okPool,) = payable(pool).call{value: toPool}("");
            if (!okPool) revert TransferFailed();
        }
        emit Routed(amount, sBps, burned, toPool);
    }
}
