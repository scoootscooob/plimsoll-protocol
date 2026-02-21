// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IVelocityLimitModule — Interface for on-chain spend velocity caps.
 */
interface IVelocityLimitModule {
    /// @notice Check if a spend of `amount` wei is within velocity limits.
    /// @return allowed True if the spend is permitted.
    /// @return reason Human-readable rejection reason (empty if allowed).
    function checkVelocity(address agent, uint256 amount)
        external
        returns (bool allowed, string memory reason);

    /// @notice Record a spend (called after successful execution).
    function recordSpend(address agent, uint256 amount) external;
}
