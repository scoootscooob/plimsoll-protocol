// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/PlimsollVault.sol";
import "../src/modules/VelocityLimitModule.sol";
import "../src/modules/TargetWhitelistModule.sol";
import "../src/modules/DrawdownGuardModule.sol";
import "../src/PlimsollAttestation.sol";

/**
 * @title Deploy — Full Plimsoll V5 deployment script
 *
 * Usage:
 *   forge script script/Deploy.s.sol:Deploy \
 *     --rpc-url $SEPOLIA_RPC_URL \
 *     --broadcast \
 *     --verify \
 *     -vvvv
 *
 * Environment Variables:
 *   DEPLOYER_PRIVATE_KEY   — Private key of the deployer/owner
 *   VAULT_OWNER            — (optional) Address to own the vault (default: deployer)
 *   MAX_PER_HOUR           — (optional) Velocity limit in wei (default: 10 ETH)
 *   MAX_SINGLE_TX          — (optional) Single tx cap in wei (default: 5 ETH)
 *   MAX_DRAWDOWN_BPS       — (optional) Drawdown limit (default: 500 = 5%)
 *   INITIAL_DEPOSIT        — (optional) Initial deposit in wei (default: 0)
 *   WHITELISTED_TARGETS    — (optional) Comma-separated target addresses
 */
contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);
        address vaultOwner = vm.envOr("VAULT_OWNER", deployer);

        uint256 maxPerHour = vm.envOr("MAX_PER_HOUR", uint256(10 ether));
        uint256 maxSingleTx = vm.envOr("MAX_SINGLE_TX", uint256(5 ether));
        uint256 maxDrawdownBps = vm.envOr("MAX_DRAWDOWN_BPS", uint256(500));
        uint256 initialDeposit = vm.envOr("INITIAL_DEPOSIT", uint256(0));

        console.log("=== Plimsoll V5 Deployment ===");
        console.log("Deployer:       ", deployer);
        console.log("Vault Owner:    ", vaultOwner);
        console.log("Max Per Hour:   ", maxPerHour);
        console.log("Max Single Tx:  ", maxSingleTx);
        console.log("Max Drawdown:   ", maxDrawdownBps, "bps");

        vm.startBroadcast(deployerKey);

        // ── 1. Deploy PlimsollVault ─────────────────────────────────
        PlimsollVault vault = new PlimsollVault(vaultOwner);
        console.log("PlimsollVault:     ", address(vault));

        // ── 2. Deploy VelocityLimitModule ────────────────────────
        VelocityLimitModule velocity = new VelocityLimitModule(
            address(vault),
            maxPerHour,
            maxSingleTx,
            3600          // 1 hour window
        );
        console.log("VelocityLimit:  ", address(velocity));

        // ── 3. Deploy TargetWhitelistModule ──────────────────────
        TargetWhitelistModule whitelist = new TargetWhitelistModule(vaultOwner);
        console.log("Whitelist:      ", address(whitelist));

        // ── 4. Deploy DrawdownGuardModule ────────────────────────
        DrawdownGuardModule drawdown = new DrawdownGuardModule(
            vaultOwner,
            maxDrawdownBps
        );
        console.log("DrawdownGuard:  ", address(drawdown));

        // ── 5. Deploy PlimsollAttestation (PoBR) ────────────────────
        PlimsollAttestation attestation = new PlimsollAttestation();
        console.log("Attestation:    ", address(attestation));

        // ── 6. Wire modules to vault ─────────────────────────────
        // Only the owner can set modules — if deployer != owner, skip
        if (deployer == vaultOwner) {
            vault.setModules(
                address(velocity),
                address(whitelist),
                address(drawdown)
            );
            console.log("Modules wired to vault");

            // ── 7. Initial deposit (optional) ────────────────────
            if (initialDeposit > 0) {
                vault.deposit{value: initialDeposit}();
                console.log("Deposited:      ", initialDeposit, "wei");
            }

            // ── 8. Create PoBR attestation ───────────────────────
            attestation.attest(
                address(vault),
                vaultOwner,
                maxDrawdownBps,
                maxPerHour * 24,    // daily spend estimate
                0,                  // whitelisted targets (add later)
                true,               // velocity active
                true,               // drawdown active
                true                // whitelist active
            );
            console.log("PoBR attestation created");
        } else {
            console.log("NOTICE: Deployer != owner, modules not wired.");
            console.log("Owner must call vault.setModules() manually.");
        }

        vm.stopBroadcast();

        // ── Summary ──────────────────────────────────────────────
        console.log("\n=== Deployment Summary ===");
        console.log("PlimsollVault:          ", address(vault));
        console.log("VelocityLimitModule: ", address(velocity));
        console.log("TargetWhitelistModule:", address(whitelist));
        console.log("DrawdownGuardModule: ", address(drawdown));
        console.log("PlimsollAttestation:    ", address(attestation));
        console.log("\nNext steps:");
        console.log("1. Add whitelisted targets:  whitelist.addTarget(0x...)");
        console.log("2. Fund the vault:           vault.deposit{value: X}()");
        console.log("3. Issue agent session key:  vault.issueSessionKey(...)");
        console.log("4. Point agent RPC to Plimsoll proxy");
    }
}
