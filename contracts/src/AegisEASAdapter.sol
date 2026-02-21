// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AegisEASAdapter — Bridge between AegisAttestation and Ethereum Attestation Service
 *
 * @notice Translates Aegis PoBR attestations into EAS-compatible attestations.
 *         This allows DeFi protocols that already integrate with EAS to verify
 *         Aegis-governed vault risk parameters without custom integrations.
 *
 * EAS Schema (UID: register on https://easscan.org):
 *   bytes32 schemaId = keccak256(
 *     "address vault, address owner, uint256 maxDrawdownBps, uint256 maxDailySpendWei,
 *      uint256 whitelistedTargets, bool velocityActive, bool drawdownActive,
 *      bool whitelistActive"
 *   )
 *
 * Architecture:
 *   AegisVault → AegisAttestation (on-chain registry)
 *                       ↓
 *               AegisEASAdapter (this contract)
 *                       ↓
 *               EAS (Ethereum Attestation Service)
 *                       ↓
 *               DeFi Protocols (Aave, Morpho, etc.)
 */

/// @dev Minimal EAS interface for creating attestations.
interface IEAS {
    struct AttestationRequest {
        bytes32 schema;
        AttestationRequestData data;
    }

    struct AttestationRequestData {
        address recipient;
        uint64 expirationTime;
        bool revocable;
        bytes32 refUID;
        bytes data;
        uint256 value;
    }

    function attest(AttestationRequest calldata request) external payable returns (bytes32);
    function revoke(RevocationRequest calldata request) external payable;

    struct RevocationRequest {
        bytes32 schema;
        RevocationRequestData data;
    }

    struct RevocationRequestData {
        bytes32 uid;
        uint256 value;
    }
}

/// @dev Minimal interface for the AegisAttestation registry.
interface IAegisAttestation {
    struct Attestation {
        address vault;
        address owner;
        uint256 maxDrawdownBps;
        uint256 maxDailySpendWei;
        uint256 whitelistedTargets;
        bool velocityModuleActive;
        bool drawdownModuleActive;
        bool whitelistModuleActive;
        uint256 createdAt;
        uint256 updatedAt;
        bool valid;
    }

    function getAttestation(address vault) external view returns (Attestation memory);
    function isAttested(address vault) external view returns (bool);
}

contract AegisEASAdapter {
    // ── State ───────────────────────────────────────────────────

    /// @notice The Aegis PoBR attestation registry.
    IAegisAttestation public immutable aegisRegistry;

    /// @notice The Ethereum Attestation Service contract.
    IEAS public immutable eas;

    /// @notice The EAS schema UID for Aegis PoBR attestations.
    bytes32 public schemaUID;

    /// @notice Contract owner (can update schema UID).
    address public owner;

    /// @notice Mapping from vault address to EAS attestation UID.
    mapping(address => bytes32) public easAttestations;

    // ── Events ──────────────────────────────────────────────────

    event EASAttestationCreated(address indexed vault, bytes32 indexed uid);
    event EASAttestationRevoked(address indexed vault, bytes32 indexed uid);
    event SchemaUpdated(bytes32 indexed newSchema);

    // ── Modifiers ───────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "EASAdapter: not owner");
        _;
    }

    // ── Constructor ─────────────────────────────────────────────

    constructor(
        address aegisRegistry_,
        address eas_,
        bytes32 schemaUID_
    ) {
        require(aegisRegistry_ != address(0), "EASAdapter: zero registry");
        require(eas_ != address(0), "EASAdapter: zero EAS");

        aegisRegistry = IAegisAttestation(aegisRegistry_);
        eas = IEAS(eas_);
        schemaUID = schemaUID_;
        owner = msg.sender;
    }

    // ── Core Functions ──────────────────────────────────────────

    /**
     * @notice Create an EAS attestation for an Aegis-governed vault.
     * @dev Reads the vault's PoBR data from AegisAttestation and encodes
     *      it into an EAS-compatible attestation.
     * @param vault The vault address to attest.
     * @return uid The EAS attestation UID.
     */
    function createEASAttestation(address vault) external returns (bytes32 uid) {
        require(aegisRegistry.isAttested(vault), "EASAdapter: vault not attested in Aegis");
        require(easAttestations[vault] == bytes32(0), "EASAdapter: already attested in EAS");

        IAegisAttestation.Attestation memory a = aegisRegistry.getAttestation(vault);

        // Encode the PoBR data into EAS schema format
        bytes memory encodedData = abi.encode(
            a.vault,
            a.owner,
            a.maxDrawdownBps,
            a.maxDailySpendWei,
            a.whitelistedTargets,
            a.velocityModuleActive,
            a.drawdownModuleActive,
            a.whitelistModuleActive
        );

        // Create EAS attestation
        IEAS.AttestationRequest memory request = IEAS.AttestationRequest({
            schema: schemaUID,
            data: IEAS.AttestationRequestData({
                recipient: vault,
                expirationTime: 0, // No expiration
                revocable: true,
                refUID: bytes32(0),
                data: encodedData,
                value: 0
            })
        });

        uid = eas.attest(request);
        easAttestations[vault] = uid;

        emit EASAttestationCreated(vault, uid);
    }

    /**
     * @notice Revoke an EAS attestation for a vault.
     * @dev Should be called when the Aegis attestation is revoked
     *      (e.g., drawdown floor breached, owner manually revokes).
     * @param vault The vault address to revoke.
     */
    function revokeEASAttestation(address vault) external onlyOwner {
        bytes32 uid = easAttestations[vault];
        require(uid != bytes32(0), "EASAdapter: no EAS attestation");

        IEAS.RevocationRequest memory request = IEAS.RevocationRequest({
            schema: schemaUID,
            data: IEAS.RevocationRequestData({
                uid: uid,
                value: 0
            })
        });

        eas.revoke(request);
        delete easAttestations[vault];

        emit EASAttestationRevoked(vault, uid);
    }

    /**
     * @notice Sync an existing Aegis attestation update to EAS.
     * @dev Revokes old and creates new EAS attestation with updated data.
     * @param vault The vault to re-attest.
     * @return uid The new EAS attestation UID.
     */
    function syncAttestation(address vault) external returns (bytes32 uid) {
        bytes32 oldUid = easAttestations[vault];

        // Revoke old if exists
        if (oldUid != bytes32(0)) {
            IEAS.RevocationRequest memory revokeReq = IEAS.RevocationRequest({
                schema: schemaUID,
                data: IEAS.RevocationRequestData({
                    uid: oldUid,
                    value: 0
                })
            });
            eas.revoke(revokeReq);
            delete easAttestations[vault];
            emit EASAttestationRevoked(vault, oldUid);
        }

        // Create fresh attestation with current data
        require(aegisRegistry.isAttested(vault), "EASAdapter: vault not attested in Aegis");

        IAegisAttestation.Attestation memory a = aegisRegistry.getAttestation(vault);

        bytes memory encodedData = abi.encode(
            a.vault,
            a.owner,
            a.maxDrawdownBps,
            a.maxDailySpendWei,
            a.whitelistedTargets,
            a.velocityModuleActive,
            a.drawdownModuleActive,
            a.whitelistModuleActive
        );

        IEAS.AttestationRequest memory request = IEAS.AttestationRequest({
            schema: schemaUID,
            data: IEAS.AttestationRequestData({
                recipient: vault,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: encodedData,
                value: 0
            })
        });

        uid = eas.attest(request);
        easAttestations[vault] = uid;

        emit EASAttestationCreated(vault, uid);
    }

    // ── View Functions ──────────────────────────────────────────

    /**
     * @notice Check if a vault has an active EAS attestation.
     * @param vault The vault to check.
     * @return True if the vault has an active EAS attestation.
     */
    function hasEASAttestation(address vault) external view returns (bool) {
        return easAttestations[vault] != bytes32(0);
    }

    /**
     * @notice Get the EAS UID for a vault's attestation.
     * @param vault The vault to query.
     * @return The EAS attestation UID (bytes32(0) if none).
     */
    function getEASUID(address vault) external view returns (bytes32) {
        return easAttestations[vault];
    }

    /**
     * @notice Compute the EAS schema UID for the Aegis PoBR schema.
     * @dev This is a helper — the actual schema must be registered on EAS first.
     * @return The keccak256 of the schema definition.
     */
    function computeSchemaHash() external pure returns (bytes32) {
        return keccak256(
            "address vault,address owner,uint256 maxDrawdownBps,uint256 maxDailySpendWei,uint256 whitelistedTargets,bool velocityActive,bool drawdownActive,bool whitelistActive"
        );
    }

    // ── Admin ───────────────────────────────────────────────────

    /**
     * @notice Update the EAS schema UID (in case of schema migration).
     * @param newSchemaUID The new schema UID.
     */
    function updateSchema(bytes32 newSchemaUID) external onlyOwner {
        schemaUID = newSchemaUID;
        emit SchemaUpdated(newSchemaUID);
    }

    /**
     * @notice Transfer adapter ownership.
     * @param newOwner The new owner address.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "EASAdapter: zero owner");
        owner = newOwner;
    }
}
