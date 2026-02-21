// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AegisAttestation.sol";

/// @title AegisAttestation (PoBR) Test Suite
contract AegisAttestationTest is Test {
    AegisAttestation attestation;
    address registrar = address(this);
    address vault1 = address(0xABC);
    address vault2 = address(0xDEF);
    address vaultOwner = address(0xA11CE);
    address hacker = address(0xBAD);

    function setUp() public {
        attestation = new AegisAttestation();
    }

    // ── Constructor ──────────────────────────────────────────────

    function test_constructor_sets_registrar() public view {
        assertEq(attestation.registrar(), registrar);
    }

    // ── Attest ───────────────────────────────────────────────────

    function test_attest_creates_attestation() public {
        attestation.attest(
            vault1,
            vaultOwner,
            500,             // 5% max drawdown
            10 ether,        // max daily spend
            5,               // whitelisted targets
            true,            // velocity active
            true,            // drawdown active
            true             // whitelist active
        );

        assertTrue(attestation.isAttested(vault1));
    }

    function test_attest_stores_all_fields() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);

        AegisAttestation.Attestation memory a = attestation.getAttestation(vault1);
        assertEq(a.vault, vault1);
        assertEq(a.owner, vaultOwner);
        assertEq(a.maxDrawdownBps, 500);
        assertEq(a.maxDailySpendWei, 10 ether);
        assertEq(a.whitelistedTargets, 5);
        assertTrue(a.velocityModuleActive);
        assertTrue(a.drawdownModuleActive);
        assertTrue(a.whitelistModuleActive);
        assertTrue(a.valid);
        assertGt(a.createdAt, 0);
        assertEq(a.createdAt, a.updatedAt);
    }

    function test_attest_emits_event() public {
        vm.expectEmit(true, true, false, true);
        emit AegisAttestation.AttestationCreated(vault1, vaultOwner, 500, 10 ether);
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
    }

    function test_attest_rejects_zero_vault() public {
        vm.expectRevert("PoBR: zero vault");
        attestation.attest(address(0), vaultOwner, 500, 10 ether, 5, true, true, true);
    }

    function test_attest_rejects_duplicate() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        vm.expectRevert("PoBR: already attested");
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
    }

    function test_attest_only_registrar() public {
        vm.prank(hacker);
        vm.expectRevert("PoBR: not registrar");
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
    }

    // ── Update ───────────────────────────────────────────────────

    function test_update_attestation() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);

        vm.warp(block.timestamp + 100);
        attestation.update(vault1, 1000, 20 ether, 10);

        AegisAttestation.Attestation memory a = attestation.getAttestation(vault1);
        assertEq(a.maxDrawdownBps, 1000);
        assertEq(a.maxDailySpendWei, 20 ether);
        assertEq(a.whitelistedTargets, 10);
        assertGt(a.updatedAt, a.createdAt);
    }

    function test_update_emits_event() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        vm.expectEmit(true, false, false, false);
        emit AegisAttestation.AttestationUpdated(vault1);
        attestation.update(vault1, 1000, 20 ether, 10);
    }

    function test_update_not_attested() public {
        vm.expectRevert("PoBR: not attested");
        attestation.update(vault1, 1000, 20 ether, 10);
    }

    function test_update_only_registrar() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        vm.prank(hacker);
        vm.expectRevert("PoBR: not registrar");
        attestation.update(vault1, 1000, 20 ether, 10);
    }

    // ── Revoke ───────────────────────────────────────────────────

    function test_revoke_attestation() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        attestation.revoke(vault1, "Drawdown breached");
        assertFalse(attestation.isAttested(vault1));
    }

    function test_revoke_emits_event() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        vm.expectEmit(true, false, false, true);
        emit AegisAttestation.AttestationRevoked(vault1, "Test revoke");
        attestation.revoke(vault1, "Test revoke");
    }

    function test_revoke_not_attested() public {
        vm.expectRevert("PoBR: not attested");
        attestation.revoke(vault1, "reason");
    }

    function test_revoke_only_registrar() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        vm.prank(hacker);
        vm.expectRevert("PoBR: not registrar");
        attestation.revoke(vault1, "reason");
    }

    // ── View Functions ───────────────────────────────────────────

    function test_is_attested_false_by_default() public view {
        assertFalse(attestation.isAttested(vault1));
    }

    function test_get_max_drawdown() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        assertEq(attestation.getMaxDrawdown(vault1), 500);
    }

    function test_get_max_drawdown_not_attested() public {
        vm.expectRevert("PoBR: not attested");
        attestation.getMaxDrawdown(vault1);
    }

    function test_attested_count() public {
        assertEq(attestation.attestedCount(), 0);
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        assertEq(attestation.attestedCount(), 1);
        attestation.attest(vault2, vaultOwner, 300, 5 ether, 3, true, false, true);
        assertEq(attestation.attestedCount(), 2);
    }

    function test_revoked_still_counted_but_not_valid() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        attestation.revoke(vault1, "test");
        // Still in the array
        assertEq(attestation.attestedCount(), 1);
        // But not valid
        assertFalse(attestation.isAttested(vault1));
    }

    // ── Transfer Registrar ───────────────────────────────────────

    function test_transfer_registrar() public {
        address newRegistrar = address(0x1234);
        attestation.transferRegistrar(newRegistrar);
        assertEq(attestation.registrar(), newRegistrar);
    }

    function test_transfer_registrar_rejects_zero() public {
        vm.expectRevert("PoBR: zero registrar");
        attestation.transferRegistrar(address(0));
    }

    function test_transfer_registrar_only_registrar() public {
        vm.prank(hacker);
        vm.expectRevert("PoBR: not registrar");
        attestation.transferRegistrar(address(0x123));
    }

    function test_new_registrar_can_attest() public {
        address newRegistrar = address(0x1234);
        attestation.transferRegistrar(newRegistrar);

        vm.prank(newRegistrar);
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        assertTrue(attestation.isAttested(vault1));
    }

    // ── Multiple Vaults ──────────────────────────────────────────

    function test_multiple_vaults_independent() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        attestation.attest(vault2, vaultOwner, 300, 5 ether, 3, true, false, true);

        AegisAttestation.Attestation memory a1 = attestation.getAttestation(vault1);
        AegisAttestation.Attestation memory a2 = attestation.getAttestation(vault2);

        assertEq(a1.maxDrawdownBps, 500);
        assertEq(a2.maxDrawdownBps, 300);
        assertFalse(a2.drawdownModuleActive);
        assertTrue(a1.drawdownModuleActive);
    }

    // ── Re-attest after revoke ───────────────────────────────────

    function test_cannot_re_attest_while_valid() public {
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
        vm.expectRevert("PoBR: already attested");
        attestation.attest(vault1, vaultOwner, 500, 10 ether, 5, true, true, true);
    }
}
