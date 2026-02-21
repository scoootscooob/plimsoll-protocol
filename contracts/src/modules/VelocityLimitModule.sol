// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVelocityLimitModule} from "./IVelocityLimitModule.sol";

/**
 * @title VelocityLimitModule — On-Chain PID-Inspired Spend Velocity Cap
 * @notice Enforces a maximum spend rate (wei per hour) for each agent.
 *         Uses a sliding window with configurable parameters.
 *
 *         This is the Solidity translation of Aegis Python's
 *         CapitalVelocityEngine — deterministic math, on-chain enforcement.
 */
contract VelocityLimitModule is IVelocityLimitModule {
    address public vault;
    address public owner;

    uint256 public maxPerHour;        // Maximum wei per rolling hour
    uint256 public maxSingleTx;       // Maximum wei per single transaction
    uint256 public windowSeconds;     // Observation window (default 3600)

    struct SpendRecord {
        uint256 timestamp;
        uint256 amount;
    }

    // Agent → spend history (circular buffer via dynamic array)
    mapping(address => SpendRecord[]) public spendHistory;
    mapping(address => uint256) public windowTotal;

    event VelocityConfigured(uint256 maxPerHour, uint256 maxSingleTx, uint256 window);
    event SpendRecorded(address indexed agent, uint256 amount, uint256 windowTotal);

    modifier onlyVaultOrOwner() {
        require(
            msg.sender == vault || msg.sender == owner,
            "VelocityLimit: unauthorized"
        );
        _;
    }

    constructor(
        address vault_,
        uint256 maxPerHour_,
        uint256 maxSingleTx_,
        uint256 windowSeconds_
    ) {
        vault = vault_;
        owner = msg.sender;
        maxPerHour = maxPerHour_;
        maxSingleTx = maxSingleTx_;
        windowSeconds = windowSeconds_ > 0 ? windowSeconds_ : 3600;
        emit VelocityConfigured(maxPerHour_, maxSingleTx_, windowSeconds);
    }

    /// @inheritdoc IVelocityLimitModule
    function checkVelocity(address agent, uint256 amount)
        external
        override
        returns (bool allowed, string memory reason)
    {
        // Single tx cap
        if (amount > maxSingleTx) {
            return (false, "VELOCITY: single tx exceeds cap");
        }

        // Prune expired records and compute window total
        _pruneExpired(agent);

        uint256 projectedTotal = windowTotal[agent] + amount;
        if (projectedTotal > maxPerHour) {
            return (false, "VELOCITY: hourly spend rate exceeded");
        }

        // Record the spend
        spendHistory[agent].push(SpendRecord({
            timestamp: block.timestamp,
            amount: amount
        }));
        windowTotal[agent] = projectedTotal;

        emit SpendRecorded(agent, amount, projectedTotal);
        return (true, "");
    }

    /// @inheritdoc IVelocityLimitModule
    function recordSpend(address agent, uint256 amount) external override onlyVaultOrOwner {
        spendHistory[agent].push(SpendRecord({
            timestamp: block.timestamp,
            amount: amount
        }));
        windowTotal[agent] += amount;
    }

    /// @notice Update velocity parameters (owner only).
    function configure(
        uint256 maxPerHour_,
        uint256 maxSingleTx_,
        uint256 windowSeconds_
    ) external {
        require(msg.sender == owner, "VelocityLimit: not owner");
        maxPerHour = maxPerHour_;
        maxSingleTx = maxSingleTx_;
        windowSeconds = windowSeconds_ > 0 ? windowSeconds_ : 3600;
        emit VelocityConfigured(maxPerHour_, maxSingleTx_, windowSeconds);
    }

    // ── Internal ────────────────────────────────────────────────

    function _pruneExpired(address agent) internal {
        SpendRecord[] storage records = spendHistory[agent];
        uint256 cutoff = block.timestamp > windowSeconds ? block.timestamp - windowSeconds : 0;
        uint256 pruned = 0;

        // Count expired records from the front
        for (uint256 i = 0; i < records.length; i++) {
            if (records[i].timestamp >= cutoff) break;
            windowTotal[agent] -= records[i].amount;
            pruned++;
        }

        // Shift remaining records to the front
        if (pruned > 0) {
            uint256 remaining = records.length - pruned;
            for (uint256 i = 0; i < remaining; i++) {
                records[i] = records[i + pruned];
            }
            for (uint256 i = 0; i < pruned; i++) {
                records.pop();
            }
        }
    }

    function getWindowTotal(address agent) external view returns (uint256) {
        return windowTotal[agent];
    }
}
