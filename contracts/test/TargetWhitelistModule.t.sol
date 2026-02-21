// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/modules/TargetWhitelistModule.sol";

/// @title TargetWhitelistModule Test Suite
contract TargetWhitelistModuleTest is Test {
    TargetWhitelistModule mod;
    address owner_ = address(this);
    address target1 = address(0xC0DE);
    address target2 = address(0xBEEF);
    address target3 = address(0xCAFE);
    address hacker = address(0xBAD);

    function setUp() public {
        mod = new TargetWhitelistModule(owner_);
    }

    // ── Add / Remove ─────────────────────────────────────────────

    function test_add_target() public {
        mod.addTarget(target1);
        (bool allowed,) = mod.checkTarget(target1);
        assertTrue(allowed);
    }

    function test_add_target_idempotent() public {
        mod.addTarget(target1);
        mod.addTarget(target1); // should not duplicate
        assertEq(mod.getWhitelistCount(), 1);
    }

    function test_add_target_rejects_zero() public {
        vm.expectRevert("Whitelist: zero address");
        mod.addTarget(address(0));
    }

    function test_remove_target() public {
        mod.addTarget(target1);
        mod.removeTarget(target1);
        (bool allowed,) = mod.checkTarget(target1);
        assertFalse(allowed);
    }

    function test_remove_nonexistent_noop() public {
        mod.removeTarget(target1); // should not revert
    }

    function test_add_target_only_owner() public {
        vm.prank(hacker);
        vm.expectRevert("Whitelist: not owner");
        mod.addTarget(target1);
    }

    function test_remove_target_only_owner() public {
        vm.prank(hacker);
        vm.expectRevert("Whitelist: not owner");
        mod.removeTarget(target1);
    }

    // ── Batch Add ────────────────────────────────────────────────

    function test_batch_add_targets() public {
        address[] memory targets = new address[](3);
        targets[0] = target1;
        targets[1] = target2;
        targets[2] = target3;
        mod.addTargets(targets);

        assertEq(mod.getWhitelistCount(), 3);
        (bool a1,) = mod.checkTarget(target1);
        (bool a2,) = mod.checkTarget(target2);
        (bool a3,) = mod.checkTarget(target3);
        assertTrue(a1);
        assertTrue(a2);
        assertTrue(a3);
    }

    function test_batch_add_skips_zero_and_duplicates() public {
        mod.addTarget(target1);
        address[] memory targets = new address[](3);
        targets[0] = target1;          // duplicate — skip
        targets[1] = address(0);       // zero — skip
        targets[2] = target2;          // new — add
        mod.addTargets(targets);

        assertEq(mod.getWhitelistCount(), 2); // target1 + target2
    }

    function test_batch_add_only_owner() public {
        address[] memory targets = new address[](1);
        targets[0] = target1;
        vm.prank(hacker);
        vm.expectRevert("Whitelist: not owner");
        mod.addTargets(targets);
    }

    // ── Check Target ─────────────────────────────────────────────

    function test_check_non_whitelisted() public view {
        (bool allowed, string memory reason) = mod.checkTarget(hacker);
        assertFalse(allowed);
        assertEq(reason, "WHITELIST: target not approved");
    }

    function test_check_whitelisted_returns_empty_reason() public {
        mod.addTarget(target1);
        (bool allowed, string memory reason) = mod.checkTarget(target1);
        assertTrue(allowed);
        assertEq(bytes(reason).length, 0);
    }

    // ── Events ───────────────────────────────────────────────────

    function test_add_emits_event() public {
        vm.expectEmit(true, false, false, false);
        emit TargetWhitelistModule.TargetAdded(target1);
        mod.addTarget(target1);
    }

    function test_remove_emits_event() public {
        mod.addTarget(target1);
        vm.expectEmit(true, false, false, false);
        emit TargetWhitelistModule.TargetRemoved(target1);
        mod.removeTarget(target1);
    }

    // ── Whitelist Count ──────────────────────────────────────────

    function test_whitelist_count() public {
        assertEq(mod.getWhitelistCount(), 0);
        mod.addTarget(target1);
        assertEq(mod.getWhitelistCount(), 1);
        mod.addTarget(target2);
        assertEq(mod.getWhitelistCount(), 2);
    }
}
