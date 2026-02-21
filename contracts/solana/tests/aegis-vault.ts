/**
 * Aegis Vault — Solana Anchor Program Tests.
 *
 * Validates the full lifecycle: initialize → deposit → issue session →
 * execute with cosign → revoke → emergency lock/unlock.
 *
 * The core invariant: the agent CANNOT move SOL from the PDA unless
 * BOTH the agent AND the Aegis proxy cosigner sign the instruction.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AegisVault } from "../target/types/aegis_vault";
import { assert } from "chai";

describe("aegis-vault", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.AegisVault as Program<AegisVault>;
  const owner = provider.wallet;

  // Cosigner (simulates the Aegis Rust Proxy Ed25519 key)
  const cosigner = anchor.web3.Keypair.generate();
  // AI agent
  const agent = anchor.web3.Keypair.generate();
  // Recipient
  const recipient = anchor.web3.Keypair.generate();

  let vaultPda: anchor.web3.PublicKey;
  let vaultBump: number;
  let sessionPda: anchor.web3.PublicKey;
  let sessionBump: number;

  before(async () => {
    // Derive PDAs
    [vaultPda, vaultBump] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("aegis-vault"), owner.publicKey.toBuffer()],
      program.programId
    );

    [sessionPda, sessionBump] = anchor.web3.PublicKey.findProgramAddressSync(
      [
        Buffer.from("aegis-session"),
        vaultPda.toBuffer(),
        agent.publicKey.toBuffer(),
      ],
      program.programId
    );

    // Airdrop SOL for tests
    const sig = await provider.connection.requestAirdrop(
      owner.publicKey,
      10 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig);

    const sig2 = await provider.connection.requestAirdrop(
      recipient.publicKey,
      0.1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig2);
  });

  it("initializes the vault", async () => {
    await program.methods
      .initialize(
        cosigner.publicKey,
        500, // 5% max drawdown
        new anchor.BN(2 * anchor.web3.LAMPORTS_PER_SOL), // 2 SOL/hr velocity
        new anchor.BN(3600) // 1hr window
      )
      .accounts({
        vault: vaultPda,
        owner: owner.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const vault = await program.account.vaultState.fetch(vaultPda);
    assert.ok(vault.owner.equals(owner.publicKey));
    assert.ok(vault.cosigner.equals(cosigner.publicKey));
    assert.isFalse(vault.emergencyLocked);
    assert.equal(vault.maxDrawdownBps, 500);
    assert.ok(vault.velocityMaxPerHour.eq(new anchor.BN(2e9)));
  });

  it("deposits SOL into the vault", async () => {
    const amount = new anchor.BN(5 * anchor.web3.LAMPORTS_PER_SOL);

    await program.methods
      .deposit(amount)
      .accounts({
        vault: vaultPda,
        owner: owner.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const vault = await program.account.vaultState.fetch(vaultPda);
    assert.ok(vault.initialBalance.eq(amount));
  });

  it("issues a session key to the agent", async () => {
    await program.methods
      .issueSessionKey(
        agent.publicKey,
        new anchor.BN(86400), // 24h duration
        new anchor.BN(1 * anchor.web3.LAMPORTS_PER_SOL), // 1 SOL max per tx
        new anchor.BN(3 * anchor.web3.LAMPORTS_PER_SOL) // 3 SOL daily budget
      )
      .accounts({
        vault: vaultPda,
        session: sessionPda,
        owner: owner.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const session = await program.account.sessionState.fetch(sessionPda);
    assert.ok(session.agent.equals(agent.publicKey));
    assert.isTrue(session.active);
    assert.ok(session.dailyBudget.eq(new anchor.BN(3e9)));
  });

  it("executes a transfer with agent + cosigner", async () => {
    const amount = new anchor.BN(0.5 * anchor.web3.LAMPORTS_PER_SOL);
    const recipientBefore = await provider.connection.getBalance(
      recipient.publicKey
    );

    await program.methods
      .execute(amount)
      .accounts({
        vault: vaultPda,
        session: sessionPda,
        agent: agent.publicKey,
        cosigner: cosigner.publicKey,
        recipient: recipient.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([agent, cosigner])
      .rpc();

    const recipientAfter = await provider.connection.getBalance(
      recipient.publicKey
    );
    assert.ok(recipientAfter - recipientBefore >= 0.5 * 1e9 - 10000);

    const session = await program.account.sessionState.fetch(sessionPda);
    assert.ok(session.spentToday.eq(amount));
  });

  it("rejects execution without cosigner", async () => {
    const fakeCosigner = anchor.web3.Keypair.generate();
    const amount = new anchor.BN(0.1 * anchor.web3.LAMPORTS_PER_SOL);

    try {
      await program.methods
        .execute(amount)
        .accounts({
          vault: vaultPda,
          session: sessionPda,
          agent: agent.publicKey,
          cosigner: fakeCosigner.publicKey,
          recipient: recipient.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([agent, fakeCosigner])
        .rpc();
      assert.fail("Should have rejected invalid cosigner");
    } catch (err) {
      assert.include(err.toString(), "InvalidCosigner");
    }
  });

  it("rejects execution exceeding single-tx cap", async () => {
    const amount = new anchor.BN(2 * anchor.web3.LAMPORTS_PER_SOL); // 2 SOL > 1 SOL cap

    try {
      await program.methods
        .execute(amount)
        .accounts({
          vault: vaultPda,
          session: sessionPda,
          agent: agent.publicKey,
          cosigner: cosigner.publicKey,
          recipient: recipient.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([agent, cosigner])
        .rpc();
      assert.fail("Should have rejected exceeding single-tx cap");
    } catch (err) {
      assert.include(err.toString(), "ExceedsSingleTxCap");
    }
  });

  it("emergency lock blocks execution", async () => {
    // Lock the vault
    await program.methods
      .emergencyLock()
      .accounts({
        vault: vaultPda,
        owner: owner.publicKey,
      })
      .rpc();

    const vault = await program.account.vaultState.fetch(vaultPda);
    assert.isTrue(vault.emergencyLocked);

    // Try to execute — should fail
    const amount = new anchor.BN(0.1 * anchor.web3.LAMPORTS_PER_SOL);
    try {
      await program.methods
        .execute(amount)
        .accounts({
          vault: vaultPda,
          session: sessionPda,
          agent: agent.publicKey,
          cosigner: cosigner.publicKey,
          recipient: recipient.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([agent, cosigner])
        .rpc();
      assert.fail("Should have rejected — vault is locked");
    } catch (err) {
      assert.include(err.toString(), "EmergencyLocked");
    }

    // Unlock
    await program.methods
      .emergencyUnlock()
      .accounts({
        vault: vaultPda,
        owner: owner.publicKey,
      })
      .rpc();
  });

  it("revokes session key", async () => {
    await program.methods
      .revokeSessionKey()
      .accounts({
        vault: vaultPda,
        session: sessionPda,
        owner: owner.publicKey,
      })
      .rpc();

    const session = await program.account.sessionState.fetch(sessionPda);
    assert.isFalse(session.active);

    // Try to execute with revoked key — should fail
    const amount = new anchor.BN(0.1 * anchor.web3.LAMPORTS_PER_SOL);
    try {
      await program.methods
        .execute(amount)
        .accounts({
          vault: vaultPda,
          session: sessionPda,
          agent: agent.publicKey,
          cosigner: cosigner.publicKey,
          recipient: recipient.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([agent, cosigner])
        .rpc();
      assert.fail("Should have rejected — session revoked");
    } catch (err) {
      assert.include(err.toString(), "SessionInactive");
    }
  });

  it("configures physics parameters", async () => {
    await program.methods
      .configurePhysics(
        1000, // 10% drawdown
        new anchor.BN(5 * anchor.web3.LAMPORTS_PER_SOL), // 5 SOL/hr
        new anchor.BN(7200) // 2hr window
      )
      .accounts({
        vault: vaultPda,
        owner: owner.publicKey,
      })
      .rpc();

    const vault = await program.account.vaultState.fetch(vaultPda);
    assert.equal(vault.maxDrawdownBps, 1000);
    assert.ok(vault.velocityMaxPerHour.eq(new anchor.BN(5e9)));
    assert.ok(vault.velocityWindowSecs.eq(new anchor.BN(7200)));
  });

  it("updates the cosigner", async () => {
    const newCosigner = anchor.web3.Keypair.generate();

    await program.methods
      .setCosigner(newCosigner.publicKey)
      .accounts({
        vault: vaultPda,
        owner: owner.publicKey,
      })
      .rpc();

    const vault = await program.account.vaultState.fetch(vaultPda);
    assert.ok(vault.cosigner.equals(newCosigner.publicKey));
  });

  it("withdraws SOL (owner only)", async () => {
    const amount = new anchor.BN(1 * anchor.web3.LAMPORTS_PER_SOL);
    const before = await provider.connection.getBalance(owner.publicKey);

    await program.methods
      .withdraw(amount)
      .accounts({
        vault: vaultPda,
        owner: owner.publicKey,
        recipient: owner.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const after = await provider.connection.getBalance(owner.publicKey);
    // Owner should have received ~1 SOL (minus tx fees)
    assert.ok(after > before + 0.9 * 1e9);
  });
});
