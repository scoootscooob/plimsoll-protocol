// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AegisEASAdapter.sol";
import "../src/AegisAttestation.sol";

/// @title Mock EAS contract for testing the adapter
contract MockEAS {
    uint256 private _counter;
    mapping(bytes32 => bool) public revoked;

    function attest(
        IEAS.AttestationRequest calldata
    ) external payable returns (bytes32) {
        _counter++;
        return bytes32(_counter);
    }

    function revoke(IEAS.RevocationRequest calldata request) external payable {
        revoked[request.data.uid] = true;
    }
}

/// @title AegisEASAdapter Test Suite
contract AegisEASAdapterTest is Test {
    AegisAttestation registry;
    MockEAS mockEAS;
    AegisEASAdapter adapter;

    address vault1 = address(0xABC);
    address vaultOwner = address(0xA11CE);
    bytes32 schemaUID = keccak256("aegis-pobr-v1");

    function setUp() public {
        registry = new AegisAttestation();
        mockEAS = new MockEAS();
        adapter = new AegisEASAdapter(
            address(registry),
            address(mockEAS),
            schemaUID
        );

        // Create an attestation in the Aegis registry
        registry.attest(
            vault1,
            vaultOwner,
            500,            // 5% max drawdown
            10 ether,       // max daily spend
            5,              // whitelisted targets
            true,           // velocity active
            true,           // drawdown active
            true            // whitelist active
        );
    }

    // ── Constructor ──────────────────────────────────────────────

    function test_constructor_sets_addresses() public view {
        assertEq(address(adapter.aegisRegistry()), address(registry));
        assertEq(address(adapter.eas()), address(mockEAS));
        assertEq(adapter.schemaUID(), schemaUID);
        assertEq(adapter.owner(), address(this));
    }

    function test_constructor_rejects_zero_registry() public {
        vm.expectRevert("EASAdapter: zero registry");
        new AegisEASAdapter(address(0), address(mockEAS), schemaUID);
    }

    function test_constructor_rejects_zero_eas() public {
        vm.expectRevert("EASAdapter: zero EAS");
        new AegisEASAdapter(address(registry), address(0), schemaUID);
    }

    // ── Create EAS Attestation ───────────────────────────────────

    function test_create_eas_attestation() public {
        bytes32 uid = adapter.createEASAttestation(vault1);
        assertTrue(uid != bytes32(0));
        assertTrue(adapter.hasEASAttestation(vault1));
        assertEq(adapter.getEASUID(vault1), uid);
    }

    function test_create_eas_attestation_not_attested() public {
        address unknown = address(0xDEAD);
        vm.expectRevert("EASAdapter: vault not attested in Aegis");
        adapter.createEASAttestation(unknown);
    }

    function test_create_eas_attestation_already_exists() public {
        adapter.createEASAttestation(vault1);
        vm.expectRevert("EASAdapter: already attested in EAS");
        adapter.createEASAttestation(vault1);
    }

    function test_create_emits_event() public {
        vm.expectEmit(true, false, false, false);
        emit AegisEASAdapter.EASAttestationCreated(vault1, bytes32(uint256(1)));
        adapter.createEASAttestation(vault1);
    }

    // ── Revoke EAS Attestation ───────────────────────────────────

    function test_revoke_eas_attestation() public {
        adapter.createEASAttestation(vault1);
        assertTrue(adapter.hasEASAttestation(vault1));

        adapter.revokeEASAttestation(vault1);
        assertFalse(adapter.hasEASAttestation(vault1));
    }

    function test_revoke_no_attestation() public {
        vm.expectRevert("EASAdapter: no EAS attestation");
        adapter.revokeEASAttestation(vault1);
    }

    function test_revoke_only_owner() public {
        adapter.createEASAttestation(vault1);
        vm.prank(address(0xBAD));
        vm.expectRevert("EASAdapter: not owner");
        adapter.revokeEASAttestation(vault1);
    }

    // ── Sync Attestation ─────────────────────────────────────────

    function test_sync_creates_new_if_none_exists() public {
        bytes32 uid = adapter.syncAttestation(vault1);
        assertTrue(uid != bytes32(0));
        assertTrue(adapter.hasEASAttestation(vault1));
    }

    function test_sync_revokes_old_and_creates_new() public {
        bytes32 oldUid = adapter.createEASAttestation(vault1);
        bytes32 newUid = adapter.syncAttestation(vault1);
        assertTrue(newUid != oldUid);
        assertEq(adapter.getEASUID(vault1), newUid);
    }

    // ── View Functions ───────────────────────────────────────────

    function test_has_eas_attestation_default_false() public view {
        assertFalse(adapter.hasEASAttestation(address(0xDEAD)));
    }

    function test_get_eas_uid_default_zero() public view {
        assertEq(adapter.getEASUID(address(0xDEAD)), bytes32(0));
    }

    function test_compute_schema_hash() public view {
        bytes32 hash = adapter.computeSchemaHash();
        assertTrue(hash != bytes32(0));
    }

    // ── Admin Functions ──────────────────────────────────────────

    function test_update_schema() public {
        bytes32 newSchema = keccak256("aegis-pobr-v2");
        adapter.updateSchema(newSchema);
        assertEq(adapter.schemaUID(), newSchema);
    }

    function test_update_schema_only_owner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert("EASAdapter: not owner");
        adapter.updateSchema(bytes32(0));
    }

    function test_transfer_ownership() public {
        address newOwner = address(0xFACE);
        adapter.transferOwnership(newOwner);
        assertEq(adapter.owner(), newOwner);
    }

    function test_transfer_ownership_rejects_zero() public {
        vm.expectRevert("EASAdapter: zero owner");
        adapter.transferOwnership(address(0));
    }

    function test_transfer_ownership_only_owner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert("EASAdapter: not owner");
        adapter.transferOwnership(address(0xFACE));
    }
}
