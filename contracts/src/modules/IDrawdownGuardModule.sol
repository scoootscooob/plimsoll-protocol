// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IDrawdownGuardModule — Interface for portfolio floor enforcement.
 */
interface IDrawdownGuardModule {
    /// @notice Check if spending `amount` would breach the drawdown floor.
    /// @param vault The vault address (to check balance).
    /// @param amount The proposed spend in wei.
    /// @param initialBalance The vault's initial deposit (high-water mark).
    /// @return allowed True if the drawdown is within limits.
    /// @return reason Human-readable rejection reason (empty if allowed).
    function checkDrawdown(address vault, uint256 amount, uint256 initialBalance)
        external
        view
        returns (bool allowed, string memory reason);
}
