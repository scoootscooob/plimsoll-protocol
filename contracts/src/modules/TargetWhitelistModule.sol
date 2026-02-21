// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ITargetWhitelistModule} from "./ITargetWhitelistModule.sol";

/**
 * @title TargetWhitelistModule — On-Chain Destination Validation
 * @notice Only allows the AI agent to interact with pre-approved contracts.
 *         The owner (human/DAO) manages the whitelist. The agent cannot
 *         modify it, even if prompt-injected.
 */
contract TargetWhitelistModule is ITargetWhitelistModule {
    address public owner;

    mapping(address => bool) public whitelisted;
    address[] public whitelistedList;

    event TargetAdded(address indexed target);
    event TargetRemoved(address indexed target);

    modifier onlyOwner() {
        require(msg.sender == owner, "Whitelist: not owner");
        _;
    }

    constructor(address owner_) {
        owner = owner_;
    }

    /// @notice Add a target to the whitelist.
    function addTarget(address target) external onlyOwner {
        require(target != address(0), "Whitelist: zero address");
        if (!whitelisted[target]) {
            whitelisted[target] = true;
            whitelistedList.push(target);
            emit TargetAdded(target);
        }
    }

    /// @notice Remove a target from the whitelist.
    function removeTarget(address target) external onlyOwner {
        if (whitelisted[target]) {
            whitelisted[target] = false;
            emit TargetRemoved(target);
        }
    }

    /// @notice Batch add targets.
    function addTargets(address[] calldata targets) external onlyOwner {
        for (uint256 i = 0; i < targets.length; i++) {
            if (targets[i] != address(0) && !whitelisted[targets[i]]) {
                whitelisted[targets[i]] = true;
                whitelistedList.push(targets[i]);
                emit TargetAdded(targets[i]);
            }
        }
    }

    /// @inheritdoc ITargetWhitelistModule
    function checkTarget(address target)
        external
        view
        override
        returns (bool allowed, string memory reason)
    {
        if (whitelisted[target]) {
            return (true, "");
        }
        return (false, "WHITELIST: target not approved");
    }

    function getWhitelistCount() external view returns (uint256) {
        return whitelistedList.length;
    }
}
