// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ITargetWhitelistModule — Interface for destination address validation.
 */
interface ITargetWhitelistModule {
    /// @notice Check if `target` is an approved destination.
    /// @return allowed True if the target is whitelisted.
    /// @return reason Human-readable rejection reason (empty if allowed).
    function checkTarget(address target)
        external
        view
        returns (bool allowed, string memory reason);
}
