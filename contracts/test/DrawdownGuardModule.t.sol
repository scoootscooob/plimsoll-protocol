// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/modules/DrawdownGuardModule.sol";

/// @title DrawdownGuardModule Test Suite
contract DrawdownGuardModuleTest is Test {
    DrawdownGuardModule mod;
    address owner_ = address(this);
    address vault;

    function setUp() public {
        mod = new DrawdownGuardModule(owner_, 500); // 5% max drawdown
        // Create a vault-like address with 10 ETH
        vault = address(0xBA01);
        vm.deal(vault, 10 ether);
    }

    // ── Constructor ──────────────────────────────────────────────

    function test_constructor_params() public view {
        assertEq(mod.owner(), owner_);
        assertEq(mod.maxDrawdownBps(), 500);
    }

    // ── Drawdown Checks ──────────────────────────────────────────

    function test_within_floor() public view {
        // 10 ETH initial, 5% floor = 9.5 ETH
        // Spend 0.4 ETH → balance 9.6 ETH > 9.5 ETH → allowed
        (bool allowed,) = mod.checkDrawdown(vault, 0.4 ether, 10 ether);
        assertTrue(allowed);
    }

    function test_exactly_at_floor() public view {
        // Spend 0.5 ETH → balance 9.5 ETH == floor → allowed (not less than)
        (bool allowed,) = mod.checkDrawdown(vault, 0.5 ether, 10 ether);
        assertTrue(allowed);
    }

    function test_below_floor() public view {
        // Spend 0.6 ETH → balance 9.4 ETH < 9.5 ETH → blocked
        (bool allowed, string memory reason) = mod.checkDrawdown(vault, 0.6 ether, 10 ether);
        assertFalse(allowed);
        assertTrue(bytes(reason).length > 0);
    }

    function test_insufficient_balance() public view {
        // Spend more than the vault holds
        (bool allowed, string memory reason) = mod.checkDrawdown(vault, 11 ether, 10 ether);
        assertFalse(allowed);
        assertEq(reason, "DRAWDOWN: insufficient balance");
    }

    function test_zero_initial_balance_passthrough() public view {
        // initialBalance = 0 means no tracking yet → always allow
        (bool allowed,) = mod.checkDrawdown(vault, 5 ether, 0);
        assertTrue(allowed);
    }

    function test_large_drawdown_percent() public {
        // 50% drawdown limit
        mod.configure(5000);
        // 10 ETH vault, floor = 5 ETH
        // Spend 4.9 ETH → balance 5.1 > 5.0 → ok
        (bool allowed,) = mod.checkDrawdown(vault, 4.9 ether, 10 ether);
        assertTrue(allowed);

        // Spend 5.1 ETH → balance 4.9 < 5.0 → blocked
        (bool blocked,) = mod.checkDrawdown(vault, 5.1 ether, 10 ether);
        assertFalse(blocked);
    }

    function test_1_percent_drawdown() public {
        mod.configure(100); // 1%
        // 10 ETH vault, floor = 9.9 ETH
        (bool a1,) = mod.checkDrawdown(vault, 0.09 ether, 10 ether);
        assertTrue(a1);

        (bool a2,) = mod.checkDrawdown(vault, 0.11 ether, 10 ether);
        assertFalse(a2);
    }

    // ── Configure ────────────────────────────────────────────────

    function test_configure_updates_bps() public {
        mod.configure(1000);
        assertEq(mod.maxDrawdownBps(), 1000);
    }

    function test_configure_only_owner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert("DrawdownGuard: not owner");
        mod.configure(1000);
    }

    function test_configure_rejects_over_10000() public {
        vm.expectRevert("DrawdownGuard: invalid bps");
        mod.configure(10001);
    }

    function test_configure_allows_10000() public {
        mod.configure(10000); // 100% drawdown = no floor
        assertEq(mod.maxDrawdownBps(), 10000);
    }

    function test_configure_emits_event() public {
        vm.expectEmit(false, false, false, true);
        emit DrawdownGuardModule.DrawdownConfigured(2000);
        mod.configure(2000);
    }

    // ── computeFloor ─────────────────────────────────────────────

    function test_compute_floor() public view {
        // 5% of 10 ETH → floor = 9.5 ETH
        uint256 floor = mod.computeFloor(10 ether);
        assertEq(floor, 9.5 ether);
    }

    function test_compute_floor_zero() public view {
        uint256 floor = mod.computeFloor(0);
        assertEq(floor, 0);
    }

    function test_compute_floor_100_pct() public {
        mod.configure(10000); // 100% drawdown
        uint256 floor = mod.computeFloor(10 ether);
        assertEq(floor, 0);
    }

    // ── Fuzz ─────────────────────────────────────────────────────

    function testFuzz_floor_always_below_initial(uint96 initial, uint16 bps) public {
        vm.assume(initial > 0);
        vm.assume(bps <= 10000);
        mod.configure(bps);
        uint256 floor = mod.computeFloor(initial);
        assertLe(floor, initial);
    }
}
