// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AegisVault.sol";
import "../src/modules/VelocityLimitModule.sol";
import "../src/modules/TargetWhitelistModule.sol";
import "../src/modules/DrawdownGuardModule.sol";

/// @title AegisVault Test Suite — Comprehensive coverage
contract AegisVaultTest is Test {
    AegisVault vault;
    VelocityLimitModule velocityMod;
    TargetWhitelistModule whitelistMod;
    DrawdownGuardModule drawdownMod;

    address owner = address(0xA11CE);
    address agent = address(0xB0B);
    address target1 = address(0xC0DE);
    address target2 = address(0xDEAD);
    address hacker = address(0xBAD);
    address newOwner = address(0xFACE);

    // ── Setup ────────────────────────────────────────────────────

    function setUp() public {
        // Warp to a realistic timestamp to avoid underflows in VelocityLimitModule
        vm.warp(1700000000);

        vm.deal(owner, 100 ether);
        vm.deal(agent, 1 ether);

        vm.startPrank(owner);
        vault = new AegisVault(owner);

        // Deploy modules — vault-aware
        velocityMod = new VelocityLimitModule(
            address(vault),
            10 ether,    // maxPerHour
            5 ether,     // maxSingleTx
            3600         // windowSeconds
        );

        whitelistMod = new TargetWhitelistModule(owner);
        whitelistMod.addTarget(target1);
        whitelistMod.addTarget(target2);

        drawdownMod = new DrawdownGuardModule(owner, 5000); // 50% max drawdown (floor = 5 ETH for 10 ETH deposit)

        // Wire modules
        vault.setModules(
            address(velocityMod),
            address(whitelistMod),
            address(drawdownMod)
        );

        // Deposit 10 ETH
        vault.deposit{value: 10 ether}();

        // Issue session key to agent: 24h, 5 ETH single, 8 ETH daily
        vault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        vm.stopPrank();
    }

    // ── Constructor ──────────────────────────────────────────────

    function test_constructor_sets_owner() public view {
        assertEq(vault.owner(), owner);
    }

    function test_constructor_rejects_zero_owner() public {
        vm.expectRevert("AegisVault: zero owner");
        new AegisVault(address(0));
    }

    function test_constructor_sets_depositedAt() public view {
        assertGt(vault.depositedAt(), 0);
    }

    // ── Deposit ──────────────────────────────────────────────────

    function test_deposit_increases_balance() public {
        uint256 before = vault.vaultBalance();
        vm.prank(owner);
        vault.deposit{value: 5 ether}();
        assertEq(vault.vaultBalance(), before + 5 ether);
    }

    function test_deposit_emits_event() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit AegisVault.Deposited(owner, 3 ether);
        vault.deposit{value: 3 ether}();
    }

    function test_deposit_only_owner() public {
        vm.deal(agent, 10 ether);
        vm.prank(agent);
        vm.expectRevert("AegisVault: not owner");
        vault.deposit{value: 1 ether}();
    }

    function test_deposit_sets_initial_balance_once() public view {
        // initialBalance was set during setUp deposit
        assertEq(vault.initialBalance(), 10 ether);
    }

    function test_receive_accepts_direct_transfer() public {
        vm.deal(address(0x999), 2 ether);
        vm.prank(address(0x999));
        (bool ok,) = address(vault).call{value: 2 ether}("");
        assertTrue(ok);
        assertEq(vault.vaultBalance(), 12 ether);
    }

    // ── Withdraw ─────────────────────────────────────────────────

    function test_withdraw_sends_eth() public {
        uint256 before = target1.balance;
        vm.prank(owner);
        vault.withdraw(payable(target1), 2 ether);
        assertEq(target1.balance, before + 2 ether);
    }

    function test_withdraw_insufficient() public {
        vm.prank(owner);
        vm.expectRevert("AegisVault: insufficient balance");
        vault.withdraw(payable(target1), 999 ether);
    }

    function test_withdraw_only_owner() public {
        vm.prank(agent);
        vm.expectRevert("AegisVault: not owner");
        vault.withdraw(payable(agent), 1 ether);
    }

    // ── Session Key Lifecycle ────────────────────────────────────

    function test_session_key_is_active() public view {
        assertTrue(vault.isSessionActive(agent));
    }

    function test_session_key_info() public view {
        AegisVault.SessionKey memory sk = vault.getSessionKey(agent);
        assertTrue(sk.active);
        assertEq(sk.maxSingleAmount, 5 ether);
        assertEq(sk.dailyBudget, 8 ether);
        assertEq(sk.spentToday, 0);
    }

    function test_session_key_reject_zero_agent() public {
        vm.prank(owner);
        vm.expectRevert("AegisVault: zero agent");
        vault.issueSessionKey(address(0), 86400, 1 ether, 1 ether);
    }

    function test_session_key_expiry() public {
        // Fast forward past expiration
        vm.warp(block.timestamp + 86401);
        assertFalse(vault.isSessionActive(agent));
    }

    function test_revoke_session_key() public {
        vm.prank(owner);
        vault.revokeSessionKey(agent);
        assertFalse(vault.isSessionActive(agent));
    }

    function test_revoke_emits_event() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit AegisVault.SessionKeyRevoked(agent, "Owner revoked");
        vault.revokeSessionKey(agent);
    }

    function test_revoke_only_owner() public {
        vm.prank(agent);
        vm.expectRevert("AegisVault: not owner");
        vault.revokeSessionKey(agent);
    }

    function test_issue_multiple_session_keys() public {
        address agent2 = address(0xBEEF);
        vm.prank(owner);
        vault.issueSessionKey(agent2, 86400, 1 ether, 2 ether);
        assertTrue(vault.isSessionActive(agent2));
        assertTrue(vault.isSessionActive(agent));
    }

    // ── Execute — Happy Path ─────────────────────────────────────

    function test_execute_sends_eth() public {
        uint256 before = target1.balance;
        vm.prank(agent);
        vault.execute(target1, 1 ether, "");
        assertEq(target1.balance, before + 1 ether);
    }

    function test_execute_updates_spent_today() public {
        vm.prank(agent);
        vault.execute(target1, 1 ether, "");
        AegisVault.SessionKey memory sk = vault.getSessionKey(agent);
        assertEq(sk.spentToday, 1 ether);
    }

    function test_execute_emits_approval_event() public {
        // Use a vault without modules so only ExecutionApproved is emitted
        vm.startPrank(owner);
        AegisVault bareVault = new AegisVault(owner);
        bareVault.deposit{value: 10 ether}();
        bareVault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        vm.stopPrank();

        vm.prank(agent);
        vm.expectEmit(true, true, false, true);
        emit AegisVault.ExecutionApproved(agent, target1, 1 ether);
        bareVault.execute(target1, 1 ether, "");
    }

    function test_execute_multiple_txs_within_budget() public {
        vm.startPrank(agent);
        vault.execute(target1, 2 ether, "");
        vault.execute(target2, 3 ether, "");
        vm.stopPrank();

        AegisVault.SessionKey memory sk = vault.getSessionKey(agent);
        assertEq(sk.spentToday, 5 ether);
    }

    // ── Execute — Session Key Enforcement ─────────────────────────

    function test_execute_no_session_key() public {
        vm.prank(hacker);
        vm.expectRevert("AegisVault: no active session");
        vault.execute(target1, 1 ether, "");
    }

    function test_execute_expired_session() public {
        vm.warp(block.timestamp + 86401);
        vm.prank(agent);
        vm.expectRevert("AegisVault: session expired");
        vault.execute(target1, 1 ether, "");
    }

    function test_execute_exceeds_single_cap() public {
        vm.prank(agent);
        vm.expectRevert("AegisVault: exceeds single tx cap");
        vault.execute(target1, 6 ether, "");
    }

    function test_execute_exceeds_daily_budget() public {
        vm.startPrank(agent);
        vault.execute(target1, 5 ether, "");
        // Now 5 ETH spent, 3 ETH remaining in daily budget
        vm.expectRevert("AegisVault: daily budget exceeded");
        vault.execute(target2, 4 ether, "");
        vm.stopPrank();
    }

    function test_execute_daily_budget_resets_after_24h() public {
        // Issue a 48-hour session key so it survives the time warp
        vm.prank(owner);
        vault.issueSessionKey(agent, 172800, 5 ether, 8 ether);

        // Use smaller amounts that stay within 50% drawdown floor (5 ETH)
        vm.startPrank(agent);
        vault.execute(target1, 2 ether, "");
        vault.execute(target2, 2 ether, "");
        // 4 ETH spent, balance = 6 ETH > floor 5 ETH

        // Advance 24h+1s
        vm.warp(block.timestamp + 86401);

        // Daily budget should have reset — can spend again
        vault.execute(target1, 1 ether, "");
        vm.stopPrank();

        AegisVault.SessionKey memory sk = vault.getSessionKey(agent);
        assertEq(sk.spentToday, 1 ether);
    }

    // ── Execute — Module Enforcement ────────────────────────────

    function test_execute_velocity_single_cap() public {
        // velocityMod.maxSingleTx = 5 ETH, but session maxSingle also 5 ETH
        // Try sending exactly at the limit — should work
        vm.prank(agent);
        vault.execute(target1, 5 ether, "");
        assertEq(target1.balance, 5 ether);
    }

    function test_execute_velocity_hourly_exceeded() public {
        // maxPerHour = 10 ETH — send 2+2+2+2+2 = 10 within drawdown floor, then 1 more (fail)
        // But we can only spend ~5 ETH total due to 50% drawdown floor
        // So: deposit more first to allow larger spending
        vm.prank(owner);
        vault.deposit{value: 30 ether}();
        // Now vault has 40 ETH, initial stays 10 ETH, floor = 5 ETH (50% of 10)
        // Can spend up to 35 ETH total before hitting floor

        vm.prank(owner);
        vault.issueSessionKey(agent, 86400, 5 ether, 20 ether);

        vm.startPrank(agent);
        vault.execute(target1, 5 ether, "");
        vault.execute(target2, 5 ether, "");
        // Velocity module recorded 10 ETH this hour = at capacity

        vm.expectRevert(); // "AegisVault: VELOCITY: hourly spend rate exceeded"
        vault.execute(target1, 1 ether, "");
        vm.stopPrank();
    }

    function test_execute_whitelist_blocked() public {
        // target that's NOT whitelisted
        vm.prank(agent);
        vm.expectRevert(); // "AegisVault: WHITELIST: target not approved"
        vault.execute(hacker, 1 ether, "");
    }

    function test_execute_drawdown_breach_reverts() public {
        // initialBalance = 10 ETH, maxDrawdown = 50% → floor = 5 ETH
        // Need session key with higher single cap for this test
        vm.prank(owner);
        vault.issueSessionKey(agent, 86400, 6 ether, 10 ether);

        // Sending 5.1 ETH (balance → 4.9 ETH < 5 ETH floor) should breach and revert
        vm.prank(agent);
        vm.expectRevert(); // "AegisVault: DRAWDOWN: would breach 50% floor"
        vault.execute(target1, 5.1 ether, "");

        // Note: revert rolls back ALL state changes including the _revokeKey call
        // The vault balance should be unchanged
        assertEq(vault.vaultBalance(), 10 ether);
    }

    function test_execute_drawdown_within_floor_passes() public {
        // Send 4.9 ETH → balance 5.1 ETH > 5 ETH floor → ok
        vm.prank(agent);
        vault.execute(target1, 4.9 ether, "");
        assertEq(vault.vaultBalance(), 5.1 ether);
    }

    // ── Emergency Lock ───────────────────────────────────────────

    function test_emergency_lock() public {
        vm.prank(owner);
        vault.emergencyLockVault();
        assertTrue(vault.emergencyLocked());
    }

    function test_emergency_lock_blocks_execution() public {
        vm.prank(owner);
        vault.emergencyLockVault();

        vm.prank(agent);
        vm.expectRevert("AegisVault: emergency locked");
        vault.execute(target1, 0.1 ether, "");
    }

    function test_emergency_unlock() public {
        vm.prank(owner);
        vault.emergencyLockVault();
        vm.prank(owner);
        vault.emergencyUnlock();
        assertFalse(vault.emergencyLocked());

        // Agent can execute again
        vm.prank(agent);
        vault.execute(target1, 0.1 ether, "");
    }

    function test_emergency_lock_only_owner() public {
        vm.prank(agent);
        vm.expectRevert("AegisVault: not owner");
        vault.emergencyLockVault();
    }

    function test_emergency_lock_emits_event() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit AegisVault.EmergencyLock(owner);
        vault.emergencyLockVault();
    }

    // ── Ownership Transfer (Two-Step) ────────────────────────────

    function test_transfer_ownership_start() public {
        vm.prank(owner);
        vault.transferOwnership(newOwner);
        assertEq(vault.pendingOwner(), newOwner);
    }

    function test_transfer_ownership_accept() public {
        vm.prank(owner);
        vault.transferOwnership(newOwner);

        vm.prank(newOwner);
        vault.acceptOwnership();
        assertEq(vault.owner(), newOwner);
        assertEq(vault.pendingOwner(), address(0));
    }

    function test_transfer_ownership_emits_events() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit AegisVault.OwnershipTransferStarted(newOwner);
        vault.transferOwnership(newOwner);

        vm.prank(newOwner);
        vm.expectEmit(true, true, false, false);
        emit AegisVault.OwnershipTransferred(owner, newOwner);
        vault.acceptOwnership();
    }

    function test_transfer_ownership_reject_zero() public {
        vm.prank(owner);
        vm.expectRevert("AegisVault: zero new owner");
        vault.transferOwnership(address(0));
    }

    function test_accept_ownership_wrong_sender() public {
        vm.prank(owner);
        vault.transferOwnership(newOwner);

        vm.prank(hacker);
        vm.expectRevert("AegisVault: not pending owner");
        vault.acceptOwnership();
    }

    function test_new_owner_can_manage_vault() public {
        vm.prank(owner);
        vault.transferOwnership(newOwner);
        vm.prank(newOwner);
        vault.acceptOwnership();

        // New owner should be able to issue session keys
        vm.prank(newOwner);
        vault.issueSessionKey(address(0x1234), 86400, 1 ether, 2 ether);
        assertTrue(vault.isSessionActive(address(0x1234)));
    }

    // ── Module Configuration ─────────────────────────────────────

    function test_set_modules() public {
        // Deploy new modules
        vm.startPrank(owner);
        VelocityLimitModule newVel = new VelocityLimitModule(
            address(vault), 20 ether, 10 ether, 3600
        );
        vault.setModules(address(newVel), address(0), address(0));
        vm.stopPrank();

        assertEq(address(vault.velocityModule()), address(newVel));
        // Whitelist and drawdown remain unchanged when passing address(0)
        assertEq(address(vault.whitelistModule()), address(whitelistMod));
        assertEq(address(vault.drawdownModule()), address(drawdownMod));
    }

    function test_set_modules_only_owner() public {
        vm.prank(agent);
        vm.expectRevert("AegisVault: not owner");
        vault.setModules(address(0), address(0), address(0));
    }

    function test_set_modules_emits_event() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, false);
        emit AegisVault.ModulesUpdated();
        vault.setModules(address(0), address(0), address(0));
    }

    // ── No-Module Execute ────────────────────────────────────────

    function test_execute_without_modules() public {
        // Deploy fresh vault with no modules
        vm.startPrank(owner);
        AegisVault bareVault = new AegisVault(owner);
        bareVault.deposit{value: 10 ether}();
        bareVault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        vm.stopPrank();

        // Agent can execute without any modules enforcing
        vm.prank(agent);
        bareVault.execute(target1, 1 ether, "");
        assertEq(target1.balance, 1 ether);
    }

    // ── View Functions ───────────────────────────────────────────

    function test_vault_balance() public view {
        assertEq(vault.vaultBalance(), 10 ether);
    }

    function test_get_session_key_nonexistent() public view {
        AegisVault.SessionKey memory sk = vault.getSessionKey(hacker);
        assertFalse(sk.active);
        assertEq(sk.expiresAt, 0);
    }

    // ── Fuzz Tests ───────────────────────────────────────────────

    function testFuzz_deposit_amount(uint96 amount) public {
        vm.assume(amount > 0);
        vm.deal(owner, uint256(amount) + 100 ether);
        uint256 before = vault.vaultBalance();
        vm.prank(owner);
        vault.deposit{value: amount}();
        assertEq(vault.vaultBalance(), before + amount);
    }

    function testFuzz_execute_within_cap(uint96 amount) public {
        // Amount must be: <= 5 ETH (single cap + velocity), <= 4.9 ETH (50% drawdown floor for 10 ETH)
        vm.assume(amount > 0 && amount <= 4.9 ether);
        vm.prank(agent);
        vault.execute(target1, amount, "");
    }

    // ═══════════════════════════════════════════════════════════════
    // GOD-TIER 3: Block Reorg "Reality Desync" Defense
    // ═══════════════════════════════════════════════════════════════

    function test_max_block_drift_constant() public view {
        assertEq(vault.MAX_BLOCK_DRIFT(), 3);
    }

    /// @dev Helper to set up cosigning with a known TEE private key
    function _setupCosign() internal returns (uint256 teePrivKey, address teeSigner) {
        teePrivKey = 0xBEEF;
        teeSigner = vm.addr(teePrivKey);
        vm.startPrank(owner);
        vault.setEnclaveSigner(teeSigner);
        vault.setCosignRequired(true);
        vm.stopPrank();
    }

    /// @dev Helper to create a cosigned digest for executeWithCosign
    function _createCosignDigest(
        address _agent,
        address _target,
        uint256 _value,
        bytes memory _data,
        bytes32 _nonce,
        uint256 _deadline,
        uint256 _simulatedBlock,
        bytes32 _simulatedCodehash
    ) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                _agent,
                _target,
                _value,
                keccak256(_data),
                _nonce,
                _deadline,
                _simulatedBlock,
                _simulatedCodehash,
                block.chainid,
                address(vault)
            ))
        ));
    }

    function test_god_tier_3_within_drift_passes() public {
        (uint256 teePrivKey, ) = _setupCosign();

        bytes32 nonce = keccak256("nonce1");
        uint256 deadline = block.timestamp + 3600;
        uint256 simulatedBlock = block.number; // Current block — drift = 0
        bytes32 simulatedCodehash = bytes32(0); // Skip codehash check

        // Remove modules for simplicity in this test
        vm.prank(owner);
        AegisVault bareVault = new AegisVault(owner);
        vm.startPrank(owner);
        bareVault.deposit{value: 10 ether}();
        bareVault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        address teeSigner = vm.addr(teePrivKey);
        bareVault.setEnclaveSigner(teeSigner);
        bareVault.setCosignRequired(true);
        vm.stopPrank();

        // Create signature (includes simulatedCodehash for ZERO-DAY 2)
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                agent, target1, uint256(1 ether), keccak256(""),
                nonce, deadline, simulatedBlock, simulatedCodehash,
                block.chainid, address(bareVault)
            ))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePrivKey, digest);

        vm.prank(agent);
        bareVault.executeWithCosign(target1, 1 ether, "", nonce, deadline, simulatedBlock, simulatedCodehash, v, r, s);
        assertEq(target1.balance, 1 ether);
    }

    function test_god_tier_3_stale_simulation_blocked() public {
        (uint256 teePrivKey, ) = _setupCosign();

        // Set up bare vault for this test
        vm.startPrank(owner);
        AegisVault bareVault = new AegisVault(owner);
        bareVault.deposit{value: 10 ether}();
        bareVault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        address teeSigner = vm.addr(teePrivKey);
        bareVault.setEnclaveSigner(teeSigner);
        bareVault.setCosignRequired(true);
        vm.stopPrank();

        // Use a hardcoded stale block number (block 1 = default foundry start).
        // We roll to block 100, so drift = 99, well beyond MAX_BLOCK_DRIFT=3.
        uint256 staleBlock = 1;
        bytes32 simulatedCodehash = bytes32(0);
        vm.roll(100);

        bytes32 nonce = keccak256("nonce_stale");
        uint256 deadline = block.timestamp + 3600;

        // Sign with the stale block number
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                agent, target1, uint256(1 ether), keccak256(""),
                nonce, deadline, staleBlock, simulatedCodehash,
                block.chainid, address(bareVault)
            ))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePrivKey, digest);

        vm.prank(agent);
        vm.expectRevert("AegisVault: REALITY DESYNC - simulation stale, block drift exceeded");
        bareVault.executeWithCosign(target1, 1 ether, "", nonce, deadline, staleBlock, simulatedCodehash, v, r, s);
    }

    function test_god_tier_3_exactly_at_drift_passes() public {
        (uint256 teePrivKey, ) = _setupCosign();

        vm.startPrank(owner);
        AegisVault bareVault = new AegisVault(owner);
        bareVault.deposit{value: 10 ether}();
        bareVault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        address teeSigner = vm.addr(teePrivKey);
        bareVault.setEnclaveSigner(teeSigner);
        bareVault.setCosignRequired(true);
        vm.stopPrank();

        uint256 simulatedBlock = block.number;
        bytes32 simulatedCodehash = bytes32(0);

        // Roll forward exactly 3 blocks (at MAX_BLOCK_DRIFT boundary)
        vm.roll(block.number + 3);

        bytes32 nonce = keccak256("nonce_boundary");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                agent, target1, uint256(1 ether), keccak256(""),
                nonce, deadline, simulatedBlock, simulatedCodehash,
                block.chainid, address(bareVault)
            ))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePrivKey, digest);

        // Should pass — exactly at drift boundary
        vm.prank(agent);
        bareVault.executeWithCosign(target1, 1 ether, "", nonce, deadline, simulatedBlock, simulatedCodehash, v, r, s);
        assertEq(target1.balance, 1 ether);
    }

    function test_god_tier_3_future_simulated_block_rejected() public {
        (uint256 teePrivKey, ) = _setupCosign();

        vm.startPrank(owner);
        AegisVault bareVault = new AegisVault(owner);
        bareVault.deposit{value: 10 ether}();
        bareVault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        address teeSigner = vm.addr(teePrivKey);
        bareVault.setEnclaveSigner(teeSigner);
        bareVault.setCosignRequired(true);
        vm.stopPrank();

        // Simulated block in the future
        uint256 simulatedBlock = block.number + 10;
        bytes32 simulatedCodehash = bytes32(0);

        bytes32 nonce = keccak256("nonce_future");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                agent, target1, uint256(1 ether), keccak256(""),
                nonce, deadline, simulatedBlock, simulatedCodehash,
                block.chainid, address(bareVault)
            ))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePrivKey, digest);

        vm.prank(agent);
        vm.expectRevert("AegisVault: REALITY DESYNC - simulated block is in the future");
        bareVault.executeWithCosign(target1, 1 ether, "", nonce, deadline, simulatedBlock, simulatedCodehash, v, r, s);
    }

    function test_god_tier_3_zero_simulated_block_skips_check() public {
        (uint256 teePrivKey, ) = _setupCosign();

        vm.startPrank(owner);
        AegisVault bareVault = new AegisVault(owner);
        bareVault.deposit{value: 10 ether}();
        bareVault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        address teeSigner = vm.addr(teePrivKey);
        bareVault.setEnclaveSigner(teeSigner);
        bareVault.setCosignRequired(true);
        vm.stopPrank();

        // simulatedBlock = 0 → temporal check is skipped (backward compat)
        uint256 simulatedBlock = 0;
        bytes32 simulatedCodehash = bytes32(0);

        // Roll forward far
        vm.roll(block.number + 100);

        bytes32 nonce = keccak256("nonce_zero");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                agent, target1, uint256(1 ether), keccak256(""),
                nonce, deadline, simulatedBlock, simulatedCodehash,
                block.chainid, address(bareVault)
            ))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePrivKey, digest);

        // Should pass — simulatedBlock=0 skips temporal check
        vm.prank(agent);
        bareVault.executeWithCosign(target1, 1 ether, "", nonce, deadline, simulatedBlock, simulatedCodehash, v, r, s);
        assertEq(target1.balance, 1 ether);
    }

    // ═══════════════════════════════════════════════════════════════
    // ZERO-DAY 2: Mempool Metamorphosis — EXTCODEHASH Pinning
    // ═══════════════════════════════════════════════════════════════

    function test_zero_day_2_codehash_zero_skips_check() public {
        (uint256 teePrivKey, ) = _setupCosign();

        vm.startPrank(owner);
        AegisVault bareVault = new AegisVault(owner);
        bareVault.deposit{value: 10 ether}();
        bareVault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        address teeSigner = vm.addr(teePrivKey);
        bareVault.setEnclaveSigner(teeSigner);
        bareVault.setCosignRequired(true);
        vm.stopPrank();

        uint256 simulatedBlock = block.number;
        bytes32 simulatedCodehash = bytes32(0); // Skip EXTCODEHASH check

        bytes32 nonce = keccak256("nonce_codehash_zero");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                agent, target1, uint256(1 ether), keccak256(""),
                nonce, deadline, simulatedBlock, simulatedCodehash,
                block.chainid, address(bareVault)
            ))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePrivKey, digest);

        // Should pass — bytes32(0) skips EXTCODEHASH check (EOA targets)
        vm.prank(agent);
        bareVault.executeWithCosign(target1, 1 ether, "", nonce, deadline, simulatedBlock, simulatedCodehash, v, r, s);
        assertEq(target1.balance, 1 ether);
    }

    function test_zero_day_2_wrong_codehash_blocked() public {
        (uint256 teePrivKey, ) = _setupCosign();

        // Deploy a simple contract to have a non-zero EXTCODEHASH
        DummyContract dummy = new DummyContract();
        address dummyAddr = address(dummy);

        vm.startPrank(owner);
        AegisVault bareVault = new AegisVault(owner);
        bareVault.deposit{value: 10 ether}();
        bareVault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        address teeSigner = vm.addr(teePrivKey);
        bareVault.setEnclaveSigner(teeSigner);
        bareVault.setCosignRequired(true);
        // Whitelist the dummy contract
        TargetWhitelistModule wl = new TargetWhitelistModule(owner);
        wl.addTarget(dummyAddr);
        bareVault.setModules(address(0), address(wl), address(0));
        vm.stopPrank();

        uint256 simulatedBlock = block.number;
        // Use a WRONG codehash — simulates metamorphic attack
        bytes32 fakeCodehash = bytes32(uint256(0xDEADBEEF));

        bytes32 nonce = keccak256("nonce_wrong_codehash");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                agent, dummyAddr, uint256(0), keccak256(""),
                nonce, deadline, simulatedBlock, fakeCodehash,
                block.chainid, address(bareVault)
            ))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePrivKey, digest);

        vm.prank(agent);
        vm.expectRevert("AegisVault: METAMORPHIC ATTACK - target bytecode mutated since simulation");
        bareVault.executeWithCosign(dummyAddr, 0, "", nonce, deadline, simulatedBlock, fakeCodehash, v, r, s);
    }

    function test_zero_day_2_correct_codehash_passes() public {
        (uint256 teePrivKey, ) = _setupCosign();

        // Deploy a simple contract to have a non-zero EXTCODEHASH
        DummyContract dummy = new DummyContract();
        address dummyAddr = address(dummy);

        // Get the actual EXTCODEHASH
        bytes32 actualCodehash;
        assembly {
            actualCodehash := extcodehash(dummyAddr)
        }

        vm.startPrank(owner);
        AegisVault bareVault = new AegisVault(owner);
        bareVault.deposit{value: 10 ether}();
        bareVault.issueSessionKey(agent, 86400, 5 ether, 8 ether);
        address teeSigner = vm.addr(teePrivKey);
        bareVault.setEnclaveSigner(teeSigner);
        bareVault.setCosignRequired(true);
        // Whitelist the dummy contract
        TargetWhitelistModule wl = new TargetWhitelistModule(owner);
        wl.addTarget(dummyAddr);
        bareVault.setModules(address(0), address(wl), address(0));
        vm.stopPrank();

        uint256 simulatedBlock = block.number;

        bytes32 nonce = keccak256("nonce_correct_codehash");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(
                agent, dummyAddr, uint256(0), keccak256(""),
                nonce, deadline, simulatedBlock, actualCodehash,
                block.chainid, address(bareVault)
            ))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(teePrivKey, digest);

        // Should pass — correct codehash matches
        vm.prank(agent);
        bareVault.executeWithCosign(dummyAddr, 0, "", nonce, deadline, simulatedBlock, actualCodehash, v, r, s);
    }
}

/// @dev Dummy contract used for EXTCODEHASH testing (ZERO-DAY 2)
contract DummyContract {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    receive() external payable {}
}
