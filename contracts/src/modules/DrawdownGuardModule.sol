// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDrawdownGuardModule} from "./IDrawdownGuardModule.sol";

/**
 * @title DrawdownGuardModule — On-Chain Portfolio Floor Enforcement
 * @notice Prevents the AI agent from losing more than a configurable
 *         percentage of the vault's initial deposit.
 *
 *         Example: initialBalance = 10 ETH, maxDrawdownBps = 500 (5%)
 *         → Vault must always hold ≥ 9.5 ETH. If a tx would breach
 *         this floor, the EVM reverts it AND auto-revokes the session key.
 *
 *         This is the ultimate dead man's switch — hardcoded in consensus.
 */
contract DrawdownGuardModule is IDrawdownGuardModule {
    address public owner;

    /// @notice Maximum allowed drawdown in basis points (100 = 1%).
    uint256 public maxDrawdownBps;

    event DrawdownConfigured(uint256 maxDrawdownBps);

    constructor(address owner_, uint256 maxDrawdownBps_) {
        owner = owner_;
        maxDrawdownBps = maxDrawdownBps_;
        emit DrawdownConfigured(maxDrawdownBps_);
    }

    /// @inheritdoc IDrawdownGuardModule
    function checkDrawdown(
        address vault,
        uint256 amount,
        uint256 initialBalance
    ) external view override returns (bool allowed, string memory reason) {
        if (initialBalance == 0) {
            return (true, "");
        }

        uint256 currentBalance = vault.balance;

        // Would the vault balance after this tx be below the floor?
        if (amount > currentBalance) {
            return (false, "DRAWDOWN: insufficient balance");
        }

        uint256 balanceAfter = currentBalance - amount;
        uint256 floor = initialBalance * (10000 - maxDrawdownBps) / 10000;

        if (balanceAfter < floor) {
            return (
                false,
                string(
                    abi.encodePacked(
                        "DRAWDOWN: would breach ",
                        _bpsToString(maxDrawdownBps),
                        "% floor"
                    )
                )
            );
        }

        return (true, "");
    }

    /// @notice Update the drawdown limit (owner only).
    function configure(uint256 maxDrawdownBps_) external {
        require(msg.sender == owner, "DrawdownGuard: not owner");
        require(maxDrawdownBps_ <= 10000, "DrawdownGuard: invalid bps");
        maxDrawdownBps = maxDrawdownBps_;
        emit DrawdownConfigured(maxDrawdownBps_);
    }

    /// @notice Compute the floor balance for a given initial deposit.
    function computeFloor(uint256 initialBalance_) external view returns (uint256) {
        return initialBalance_ * (10000 - maxDrawdownBps) / 10000;
    }

    // ── Internal helpers ────────────────────────────────────────

    function _bpsToString(uint256 bps) internal pure returns (string memory) {
        // Simple: return "X" for single/double digit percentages
        uint256 pct = bps / 100;
        if (pct < 10) {
            bytes memory b = new bytes(1);
            b[0] = bytes1(uint8(48 + pct));
            return string(b);
        }
        bytes memory b = new bytes(2);
        b[0] = bytes1(uint8(48 + pct / 10));
        b[1] = bytes1(uint8(48 + pct % 10));
        return string(b);
    }
}
