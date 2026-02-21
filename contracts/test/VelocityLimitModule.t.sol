// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/modules/VelocityLimitModule.sol";

/// @title VelocityLimitModule Test Suite
contract VelocityLimitModuleTest is Test {
    VelocityLimitModule mod;
    address vault = address(0xBA01);
    address agent = address(0xA1);
    address agent2 = address(0xA2);

    function setUp() public {
        // Warp to realistic timestamp to avoid underflow in _pruneExpired
        vm.warp(1700000000);

        mod = new VelocityLimitModule(
            vault,
            10 ether,    // maxPerHour
            5 ether,     // maxSingleTx
            3600         // windowSeconds
        );
    }

    // ── Constructor ──────────────────────────────────────────────

    function test_constructor_params() public view {
        assertEq(mod.vault(), vault);
        assertEq(mod.maxPerHour(), 10 ether);
        assertEq(mod.maxSingleTx(), 5 ether);
        assertEq(mod.windowSeconds(), 3600);
    }

    function test_constructor_default_window() public {
        VelocityLimitModule m = new VelocityLimitModule(vault, 1 ether, 1 ether, 0);
        assertEq(m.windowSeconds(), 3600);
    }

    // ── Single Transaction Cap ───────────────────────────────────

    function test_single_tx_within_cap() public {
        (bool allowed,) = mod.checkVelocity(agent, 4 ether);
        assertTrue(allowed);
    }

    function test_single_tx_at_cap() public {
        (bool allowed,) = mod.checkVelocity(agent, 5 ether);
        assertTrue(allowed);
    }

    function test_single_tx_exceeds_cap() public {
        (bool allowed, string memory reason) = mod.checkVelocity(agent, 6 ether);
        assertFalse(allowed);
        assertEq(reason, "VELOCITY: single tx exceeds cap");
    }

    // ── Hourly Rate Limit ────────────────────────────────────────

    function test_hourly_within_limit() public {
        mod.checkVelocity(agent, 3 ether);
        mod.checkVelocity(agent, 3 ether);
        (bool allowed,) = mod.checkVelocity(agent, 3 ether);
        assertTrue(allowed);
    }

    function test_hourly_at_limit() public {
        mod.checkVelocity(agent, 5 ether);
        (bool allowed,) = mod.checkVelocity(agent, 5 ether);
        assertTrue(allowed);
    }

    function test_hourly_exceeds_limit() public {
        mod.checkVelocity(agent, 5 ether);
        mod.checkVelocity(agent, 5 ether);
        // Total = 10 ETH, adding 1 would exceed
        (bool allowed, string memory reason) = mod.checkVelocity(agent, 1 ether);
        assertFalse(allowed);
        assertEq(reason, "VELOCITY: hourly spend rate exceeded");
    }

    // ── Window Expiry ────────────────────────────────────────────

    function test_window_expiry_allows_more() public {
        mod.checkVelocity(agent, 5 ether);
        mod.checkVelocity(agent, 5 ether);
        // Total = 10 ETH at capacity

        // Fast forward 1 hour + 1 second
        vm.warp(block.timestamp + 3601);

        // Old records pruned — window clear
        (bool allowed,) = mod.checkVelocity(agent, 5 ether);
        assertTrue(allowed);
    }

    function test_partial_window_expiry() public {
        // Spend 5 ETH at t=0
        mod.checkVelocity(agent, 5 ether);

        // Spend 4 ETH at t=1800 (30 min)
        vm.warp(block.timestamp + 1800);
        mod.checkVelocity(agent, 4 ether);

        // At t=3601, first spend expires, second remains
        vm.warp(block.timestamp + 1801);
        // windowTotal should be ~4 ETH (first 5 expired)
        (bool allowed,) = mod.checkVelocity(agent, 5 ether);
        assertTrue(allowed);
    }

    // ── Per-Agent Isolation ──────────────────────────────────────

    function test_agents_have_separate_budgets() public {
        mod.checkVelocity(agent, 5 ether);
        mod.checkVelocity(agent, 5 ether);
        // Agent 1 at capacity

        // Agent 2 should be unaffected
        (bool allowed,) = mod.checkVelocity(agent2, 5 ether);
        assertTrue(allowed);
    }

    // ── recordSpend ──────────────────────────────────────────────

    function test_record_spend_authorized() public {
        vm.prank(vault);
        mod.recordSpend(agent, 3 ether);
        assertEq(mod.getWindowTotal(agent), 3 ether);
    }

    function test_record_spend_by_owner() public {
        mod.recordSpend(agent, 2 ether);
        assertEq(mod.getWindowTotal(agent), 2 ether);
    }

    function test_record_spend_unauthorized() public {
        vm.prank(agent);
        vm.expectRevert("VelocityLimit: unauthorized");
        mod.recordSpend(agent, 1 ether);
    }

    // ── Configure ────────────────────────────────────────────────

    function test_configure_updates_params() public {
        mod.configure(20 ether, 10 ether, 7200);
        assertEq(mod.maxPerHour(), 20 ether);
        assertEq(mod.maxSingleTx(), 10 ether);
        assertEq(mod.windowSeconds(), 7200);
    }

    function test_configure_only_owner() public {
        vm.prank(agent);
        vm.expectRevert("VelocityLimit: not owner");
        mod.configure(1 ether, 1 ether, 1);
    }

    function test_configure_emits_event() public {
        vm.expectEmit(false, false, false, true);
        emit VelocityLimitModule.VelocityConfigured(20 ether, 10 ether, 7200);
        mod.configure(20 ether, 10 ether, 7200);
    }

    // ── View Function ────────────────────────────────────────────

    function test_get_window_total() public {
        mod.checkVelocity(agent, 3 ether);
        mod.checkVelocity(agent, 2 ether);
        assertEq(mod.getWindowTotal(agent), 5 ether);
    }

    // ── Fuzz ─────────────────────────────────────────────────────

    function testFuzz_single_tx_cap(uint96 amount) public {
        vm.assume(amount > 0);
        (bool allowed,) = mod.checkVelocity(agent, amount);
        if (amount > 5 ether) {
            assertFalse(allowed);
        }
    }
}
