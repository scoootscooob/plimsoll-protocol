// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PlimsollAttestation — Proof of Bounded Risk (PoBR)
 * @notice On-chain registry of Plimsoll-governed vaults and their risk parameters.
 *
 * When a human configures an PlimsollVault, this contract mints an attestation:
 *   "Vault 0xABC is governed by AI, max daily drawdown = 5%"
 *
 * DeFi protocols (Aave, Morpho, etc.) query this registry to:
 *   - Verify an agent's vault has math-enforced risk bounds
 *   - Grant under-collateralized leverage based on bounded downside
 *   - Revoke credit if attestation is invalidated
 *
 * Compatible with Ethereum Attestation Service (EAS) schema.
 * This is the standalone version; EAS adapter is in the roadmap.
 */
contract PlimsollAttestation {
    address public registrar;   // Plimsoll protocol authority

    struct Attestation {
        address vault;
        address owner;
        uint256 maxDrawdownBps;       // e.g., 500 = 5%
        uint256 maxDailySpendWei;
        uint256 whitelistedTargets;
        bool velocityModuleActive;
        bool drawdownModuleActive;
        bool whitelistModuleActive;
        uint256 createdAt;
        uint256 updatedAt;
        bool valid;
    }

    // Vault address → attestation
    mapping(address => Attestation) public attestations;
    address[] public attestedVaults;

    event AttestationCreated(
        address indexed vault,
        address indexed owner,
        uint256 maxDrawdownBps,
        uint256 maxDailySpendWei
    );
    event AttestationUpdated(address indexed vault);
    event AttestationRevoked(address indexed vault, string reason);

    modifier onlyRegistrar() {
        require(msg.sender == registrar, "PoBR: not registrar");
        _;
    }

    constructor() {
        registrar = msg.sender;
    }

    /// @notice Create a new PoBR attestation for a vault.
    function attest(
        address vault,
        address owner_,
        uint256 maxDrawdownBps_,
        uint256 maxDailySpendWei_,
        uint256 whitelistedTargets_,
        bool velocityActive_,
        bool drawdownActive_,
        bool whitelistActive_
    ) external onlyRegistrar {
        require(vault != address(0), "PoBR: zero vault");
        require(!attestations[vault].valid, "PoBR: already attested");

        attestations[vault] = Attestation({
            vault: vault,
            owner: owner_,
            maxDrawdownBps: maxDrawdownBps_,
            maxDailySpendWei: maxDailySpendWei_,
            whitelistedTargets: whitelistedTargets_,
            velocityModuleActive: velocityActive_,
            drawdownModuleActive: drawdownActive_,
            whitelistModuleActive: whitelistActive_,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            valid: true
        });

        attestedVaults.push(vault);

        emit AttestationCreated(vault, owner_, maxDrawdownBps_, maxDailySpendWei_);
    }

    /// @notice Update an existing attestation.
    function update(
        address vault,
        uint256 maxDrawdownBps_,
        uint256 maxDailySpendWei_,
        uint256 whitelistedTargets_
    ) external onlyRegistrar {
        Attestation storage a = attestations[vault];
        require(a.valid, "PoBR: not attested");

        a.maxDrawdownBps = maxDrawdownBps_;
        a.maxDailySpendWei = maxDailySpendWei_;
        a.whitelistedTargets = whitelistedTargets_;
        a.updatedAt = block.timestamp;

        emit AttestationUpdated(vault);
    }

    /// @notice Revoke an attestation (e.g., drawdown breached).
    function revoke(address vault, string calldata reason) external onlyRegistrar {
        Attestation storage a = attestations[vault];
        require(a.valid, "PoBR: not attested");
        a.valid = false;
        emit AttestationRevoked(vault, reason);
    }

    // ── View functions (for DeFi protocol integration) ──────────

    /// @notice Check if a vault has a valid PoBR attestation.
    function isAttested(address vault) external view returns (bool) {
        return attestations[vault].valid;
    }

    /// @notice Get the maximum drawdown in basis points for a vault.
    function getMaxDrawdown(address vault) external view returns (uint256) {
        require(attestations[vault].valid, "PoBR: not attested");
        return attestations[vault].maxDrawdownBps;
    }

    /// @notice Get full attestation details.
    function getAttestation(address vault) external view returns (Attestation memory) {
        return attestations[vault];
    }

    /// @notice Count of attested vaults.
    function attestedCount() external view returns (uint256) {
        return attestedVaults.length;
    }

    /// @notice Transfer registrar authority.
    function transferRegistrar(address newRegistrar) external onlyRegistrar {
        require(newRegistrar != address(0), "PoBR: zero registrar");
        registrar = newRegistrar;
    }
}
