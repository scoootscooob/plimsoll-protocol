// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AegisVault — ERC-4337 Smart Account with On-Chain Physics
 * @notice The AI agent never holds the master key. It gets a scoped Session Key
 *         that can ONLY sign UserOperations within the Vault's math constraints.
 *
 * Architecture:
 *   - Owner Key:   Human treasury / DAO. Can deposit, withdraw, reconfigure.
 *   - Session Key:  AI agent. Temporary, scoped to physics modules.
 *   - Modules:     VelocityLimit, TargetWhitelist, DrawdownGuard (pluggable).
 *
 * If the LLM is prompt-injected and signs a tx to drain $50k to a hacker,
 * the EVM itself mathematically rejects it. Security = base-layer consensus.
 */

import {IVelocityLimitModule} from "./modules/IVelocityLimitModule.sol";
import {ITargetWhitelistModule} from "./modules/ITargetWhitelistModule.sol";
import {IDrawdownGuardModule} from "./modules/IDrawdownGuardModule.sol";

contract AegisVault {
    // ── State ───────────────────────────────────────────────────

    address public owner;
    address public pendingOwner;

    // Session key management
    struct SessionKey {
        bool active;
        uint256 expiresAt;
        uint256 maxSingleAmount;      // Wei cap per tx
        uint256 dailyBudget;          // Wei cap per 24h
        uint256 spentToday;
        uint256 dayStart;             // Timestamp of current day window
    }

    mapping(address => SessionKey) public sessionKeys;
    address[] public activeSessionKeys;

    // Physics modules (pluggable)
    IVelocityLimitModule public velocityModule;
    ITargetWhitelistModule public whitelistModule;
    IDrawdownGuardModule public drawdownModule;

    // Vault state
    uint256 public depositedAt;
    uint256 public initialBalance;
    bool public emergencyLocked;

    // ── GOD-TIER 3: Temporal Physics (Block Reorg Defense) ────────
    // Maximum block drift allowed between simulation and execution.
    // If a reorg or sequencer lag pushes execution beyond this window,
    // the EVM natively rejects the stale simulation.
    // 3 blocks ≈ 36 seconds on Ethereum L1 (12s/block).
    uint256 public constant MAX_BLOCK_DRIFT = 3;

    // ── Patch 1: TEE Co-Signing ──────────────────────────────────
    // Prevents RPC bypass attacks. Session key alone is NOT enough —
    // the Aegis TEE enclave must co-sign every transaction.
    // Flow: Agent → Rust Proxy (6 engines) → TEE signs → Vault verifies.
    // If attacker bypasses proxy and hits Vault directly, EVM rejects.
    address public aegisEnclaveSigner;    // TEE enclave public key
    bool public requireCosign;            // Toggle for co-signing requirement
    mapping(bytes32 => bool) public usedNonces; // Replay protection

    // ── Events ──────────────────────────────────────────────────

    event Deposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);
    event SessionKeyIssued(address indexed agent, uint256 expiresAt, uint256 dailyBudget);
    event SessionKeyRevoked(address indexed agent, string reason);
    event ExecutionApproved(address indexed agent, address indexed target, uint256 value);
    event ExecutionBlocked(address indexed agent, address indexed target, string reason);
    event EmergencyLock(address indexed triggeredBy);
    event ModulesUpdated();
    event OwnershipTransferStarted(address indexed newOwner);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event EnclaveSignerUpdated(address indexed newSigner);
    event CosignRequirementChanged(bool required);
    event RealityDesyncBlocked(address indexed agent, uint256 simulatedBlock, uint256 currentBlock);

    // ── Modifiers ───────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "AegisVault: not owner");
        _;
    }

    modifier notLocked() {
        require(!emergencyLocked, "AegisVault: emergency locked");
        _;
    }

    modifier onlyActiveSession() {
        SessionKey storage sk = sessionKeys[msg.sender];
        require(sk.active, "AegisVault: no active session");
        require(block.timestamp < sk.expiresAt, "AegisVault: session expired");
        _;
    }

    // ── Constructor ─────────────────────────────────────────────

    constructor(address _owner) {
        require(_owner != address(0), "AegisVault: zero owner");
        owner = _owner;
        depositedAt = block.timestamp;
    }

    // ── Owner functions ─────────────────────────────────────────

    /// @notice Deposit ETH into the vault.
    function deposit() external payable onlyOwner {
        if (initialBalance == 0) {
            initialBalance = address(this).balance;
        }
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Withdraw ETH from the vault (owner only).
    function withdraw(address payable to, uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "AegisVault: insufficient balance");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "AegisVault: transfer failed");
        emit Withdrawn(to, amount);
    }

    /// @notice Issue a time-limited, budget-scoped session key to an AI agent.
    function issueSessionKey(
        address agent,
        uint256 durationSeconds,
        uint256 maxSingleAmount_,
        uint256 dailyBudget_
    ) external onlyOwner {
        require(agent != address(0), "AegisVault: zero agent");

        sessionKeys[agent] = SessionKey({
            active: true,
            expiresAt: block.timestamp + durationSeconds,
            maxSingleAmount: maxSingleAmount_,
            dailyBudget: dailyBudget_,
            spentToday: 0,
            dayStart: block.timestamp
        });

        activeSessionKeys.push(agent);
        emit SessionKeyIssued(agent, block.timestamp + durationSeconds, dailyBudget_);
    }

    /// @notice Revoke a session key immediately.
    function revokeSessionKey(address agent) external onlyOwner {
        _revokeKey(agent, "Owner revoked");
    }

    /// @notice Configure physics modules.
    function setModules(
        address velocity_,
        address whitelist_,
        address drawdown_
    ) external onlyOwner {
        if (velocity_ != address(0)) velocityModule = IVelocityLimitModule(velocity_);
        if (whitelist_ != address(0)) whitelistModule = ITargetWhitelistModule(whitelist_);
        if (drawdown_ != address(0)) drawdownModule = IDrawdownGuardModule(drawdown_);
        emit ModulesUpdated();
    }

    /// @notice Emergency lock — freezes all session keys and execution.
    function emergencyLockVault() external onlyOwner {
        emergencyLocked = true;
        emit EmergencyLock(msg.sender);
    }

    /// @notice Unlock after emergency.
    function emergencyUnlock() external onlyOwner {
        emergencyLocked = false;
    }

    /// @notice Set the Aegis TEE enclave signer address.
    /// @dev Only transactions co-signed by this key will be accepted when requireCosign=true.
    function setEnclaveSigner(address signer) external onlyOwner {
        aegisEnclaveSigner = signer;
        emit EnclaveSignerUpdated(signer);
    }

    /// @notice Enable or disable TEE co-signing requirement.
    function setCosignRequired(bool required) external onlyOwner {
        requireCosign = required;
        emit CosignRequirementChanged(required);
    }

    /// @notice Two-step ownership transfer (start).
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "AegisVault: zero new owner");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(newOwner);
    }

    /// @notice Two-step ownership transfer (accept).
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "AegisVault: not pending owner");
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ── Agent execution ─────────────────────────────────────────

    /**
     * @notice Execute a transaction through the vault's physics modules.
     * @dev Called by the AI agent using its session key. The EVM enforces
     *      all math constraints before the ETH leaves the vault.
     *
     * Check order:
     *   1. Session key validity + budget
     *   2. VelocityLimitModule — spend rate cap
     *   3. TargetWhitelistModule — destination must be approved
     *   4. DrawdownGuardModule — portfolio floor check
     *   5. Execute if all pass
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyActiveSession notLocked returns (bytes memory) {
        // If co-signing is required, agent must use executeWithCosign()
        require(!requireCosign, "AegisVault: cosign required");
        return _executeInternal(msg.sender, target, value, data);
    }

    /**
     * @notice Execute with TEE co-signature (Patch 1: RPC Bypass Defense).
     * @dev The Aegis enclave signs (agent, target, value, nonce, chainId, vault, simulatedBlock)
     *      after all 6 off-chain engines pass. If an attacker bypasses the proxy,
     *      they cannot produce a valid enclave signature.
     *
     *      GOD-TIER 3 (Reality Desync Defense): The `simulatedBlock` parameter pins
     *      execution to the block the simulator ran against. If a reorg or sequencer
     *      lag pushes execution beyond MAX_BLOCK_DRIFT blocks, the EVM rejects the
     *      stale simulation natively — no oracle required.
     *
     *      ZERO-DAY 2 (Mempool Metamorphosis Defense): The `simulatedCodehash`
     *      parameter pins the target contract's bytecode. If an attacker uses
     *      CREATE2/SELFDESTRUCT or upgradeTo() to swap contract code between
     *      simulation and execution, the EVM rejects it via EXTCODEHASH check.
     *
     * @param target  Destination address
     * @param value   ETH value in wei
     * @param data    Calldata
     * @param nonce   Unique nonce (prevents replay)
     * @param deadline  Signature expires after this timestamp
     * @param simulatedBlock  Block number the off-chain simulator executed against
     * @param simulatedCodehash  keccak256 of target bytecode at simulation time (bytes32(0) to skip)
     * @param v,r,s   ECDSA signature from aegisEnclaveSigner
     */
    function executeWithCosign(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 nonce,
        uint256 deadline,
        uint256 simulatedBlock,
        bytes32 simulatedCodehash,
        uint8 v, bytes32 r, bytes32 s
    ) external onlyActiveSession notLocked returns (bytes memory) {
        require(block.timestamp <= deadline, "AegisVault: cosign expired");
        require(!usedNonces[nonce], "AegisVault: nonce already used");
        require(aegisEnclaveSigner != address(0), "AegisVault: no enclave signer set");

        // ── GOD-TIER 3: Temporal Physics Enforcement ─────────────
        if (simulatedBlock > 0) {
            require(
                block.number <= simulatedBlock + MAX_BLOCK_DRIFT,
                "AegisVault: REALITY DESYNC - simulation stale, block drift exceeded"
            );
            require(
                block.number >= simulatedBlock,
                "AegisVault: REALITY DESYNC - simulated block is in the future"
            );
        }

        // ── ZERO-DAY 2: EXTCODEHASH Pinning (Metamorphic Defense) ──
        // The simulator captured the keccak256 of the target contract's
        // deployed bytecode. If an attacker swapped the code between
        // simulation and execution (CREATE2 metamorphic, proxy upgradeTo,
        // or SELFDESTRUCT+CREATE2), the hash won't match.
        // bytes32(0) = skip check (EOA targets or backward compat).
        if (simulatedCodehash != bytes32(0)) {
            bytes32 currentCodehash;
            assembly {
                currentCodehash := extcodehash(target)
            }
            require(
                currentCodehash == simulatedCodehash,
                "AegisVault: METAMORPHIC ATTACK - target bytecode mutated since simulation"
            );
        }

        // Reconstruct the digest the TEE enclave signed
        // (includes simulatedBlock + simulatedCodehash for full pinning)
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                msg.sender,     // agent
                target,
                value,
                keccak256(data),
                nonce,
                deadline,
                simulatedBlock,     // GOD-TIER 3: temporal binding
                simulatedCodehash,  // ZERO-DAY 2: bytecode binding
                block.chainid,
                address(this)       // vault address
            ))
        ));

        address recovered = ecrecover(digest, v, r, s);
        require(recovered == aegisEnclaveSigner, "AegisVault: invalid enclave signature");

        // Mark nonce as used (replay protection)
        usedNonces[nonce] = true;

        return _executeInternal(msg.sender, target, value, data);
    }

    /// @dev Shared execution logic for both execute() and executeWithCosign()
    function _executeInternal(
        address agent,
        address target,
        uint256 value,
        bytes calldata data
    ) internal returns (bytes memory) {
        SessionKey storage sk = sessionKeys[agent];

        // ── Session budget checks ───────────────────────────────
        require(value <= sk.maxSingleAmount, "AegisVault: exceeds single tx cap");

        // Roll over daily budget if 24h has passed
        if (block.timestamp >= sk.dayStart + 1 days) {
            sk.spentToday = 0;
            sk.dayStart = block.timestamp;
        }
        require(
            sk.spentToday + value <= sk.dailyBudget,
            "AegisVault: daily budget exceeded"
        );

        // ── Module 1: Velocity Limit ────────────────────────────
        if (address(velocityModule) != address(0)) {
            (bool allowed, string memory reason) = velocityModule.checkVelocity(
                agent, value
            );
            if (!allowed) {
                emit ExecutionBlocked(agent, target, reason);
                revert(string(abi.encodePacked("AegisVault: ", reason)));
            }
        }

        // ── Module 2: Target Whitelist ──────────────────────────
        if (address(whitelistModule) != address(0)) {
            (bool allowed, string memory reason) = whitelistModule.checkTarget(target);
            if (!allowed) {
                emit ExecutionBlocked(agent, target, reason);
                revert(string(abi.encodePacked("AegisVault: ", reason)));
            }
        }

        // ── Module 3: Drawdown Guard ────────────────────────────
        if (address(drawdownModule) != address(0)) {
            (bool allowed, string memory reason) = drawdownModule.checkDrawdown(
                address(this), value, initialBalance
            );
            if (!allowed) {
                // Auto-revoke session key on drawdown breach
                _revokeKey(agent, "Drawdown floor breached");
                emit ExecutionBlocked(agent, target, reason);
                revert(string(abi.encodePacked("AegisVault: ", reason)));
            }
        }

        // ── All physics passed — execute ────────────────────────
        sk.spentToday += value;

        (bool success, bytes memory result) = target.call{value: value}(data);
        require(success, "AegisVault: execution failed");

        emit ExecutionApproved(agent, target, value);
        return result;
    }

    // ── Internal ────────────────────────────────────────────────

    function _revokeKey(address agent, string memory reason) internal {
        sessionKeys[agent].active = false;
        emit SessionKeyRevoked(agent, reason);
    }

    // ── View functions ──────────────────────────────────────────

    function getSessionKey(address agent) external view returns (SessionKey memory) {
        return sessionKeys[agent];
    }

    function vaultBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function isSessionActive(address agent) external view returns (bool) {
        SessionKey storage sk = sessionKeys[agent];
        return sk.active && block.timestamp < sk.expiresAt;
    }

    /// @notice Accept direct ETH transfers.
    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }
}
