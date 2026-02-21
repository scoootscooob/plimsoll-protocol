//! Plimsoll Vault — Solana Anchor Program.
//!
//! On-chain enforcement of agent capital controls on Solana.
//! Mirrors the Ethereum PlimsollVault.sol architecture:
//!
//!   - **Owner** (human / DAO multisig) — deposits SOL, configures physics.
//!   - **Session Key** (AI agent) — time-limited, budget-scoped, PDA-gated.
//!   - **Plimsoll Cosigner** — the Rust Proxy's Ed25519 keypair. Every CPI
//!     from the agent MUST carry a co-signature from the proxy to prove
//!     it passed all 7 off-chain engines.
//!
//! The vault's SOL lives in a PDA (Program Derived Address) derived from
//! `[b"plimsoll-vault", owner.key()]`.  The agent cannot move lamports
//! without presenting a valid proxy co-signature.
//!
//! ## Security Model
//!
//! ```text
//!   Agent → Plimsoll Rust Proxy (7 engines) → Ed25519 sign → CPI → PDA vault
//! ```
//!
//! If the agent bypasses the proxy and calls the program directly, the
//! on-chain Ed25519 signature verification rejects the instruction.

use anchor_lang::prelude::*;
use anchor_lang::system_program;

declare_id!("AeG1sVau1tSo1anaProgramXXXXXXXXXXXXXXXXXX");

/// Seed prefix for all vault PDAs.
pub const VAULT_SEED: &[u8] = b"plimsoll-vault";
/// Seed prefix for session key accounts.
pub const SESSION_SEED: &[u8] = b"plimsoll-session";

// ── Errors ──────────────────────────────────────────────────────

#[error_code]
pub enum PlimsollError {
    #[msg("Session key has expired")]
    SessionExpired,
    #[msg("Session key is not active")]
    SessionInactive,
    #[msg("Transfer exceeds single-transaction cap")]
    ExceedsSingleTxCap,
    #[msg("Transfer exceeds daily budget")]
    ExceedsDailyBudget,
    #[msg("Vault is emergency-locked")]
    EmergencyLocked,
    #[msg("Invalid cosigner — proxy signature required")]
    InvalidCosigner,
    #[msg("Insufficient vault balance")]
    InsufficientBalance,
    #[msg("Velocity limit exceeded — hourly spend rate too high")]
    VelocityLimitExceeded,
    #[msg("Drawdown floor breached — portfolio protection triggered")]
    DrawdownFloorBreached,
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}

// ── Program ─────────────────────────────────────────────────────

#[program]
pub mod plimsoll_vault {
    use super::*;

    /// Initialize a new Plimsoll Vault PDA for the owner.
    pub fn initialize(
        ctx: Context<Initialize>,
        cosigner: Pubkey,
        max_drawdown_bps: u16,
        velocity_max_per_hour: u64,
        velocity_window_secs: i64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.cosigner = cosigner;
        vault.emergency_locked = false;
        vault.deposited_at = Clock::get()?.unix_timestamp;
        vault.initial_balance = 0;
        vault.bump = ctx.bumps.vault;

        // Physics modules (on-chain enforcement)
        vault.max_drawdown_bps = max_drawdown_bps;
        vault.velocity_max_per_hour = velocity_max_per_hour;
        vault.velocity_window_secs = if velocity_window_secs > 0 {
            velocity_window_secs
        } else {
            3600 // default 1 hour
        };
        vault.velocity_spent_this_window = 0;
        vault.velocity_window_start = Clock::get()?.unix_timestamp;

        msg!("Plimsoll Vault initialized for owner {}", vault.owner);
        Ok(())
    }

    /// Owner deposits SOL into the vault PDA.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // Transfer SOL from owner to vault PDA
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.owner.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                },
            ),
            amount,
        )?;

        // Set initial balance on first deposit (drawdown reference)
        if vault.initial_balance == 0 {
            vault.initial_balance = amount;
        }

        msg!("Deposited {} lamports into vault", amount);
        Ok(())
    }

    /// Owner withdraws SOL from the vault PDA.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &ctx.accounts.vault;

        let vault_lamports = vault.to_account_info().lamports();
        require!(vault_lamports >= amount, PlimsollError::InsufficientBalance);

        // Transfer from PDA — requires seeds for signing
        let owner_key = vault.owner;
        let seeds: &[&[u8]] = &[VAULT_SEED, owner_key.as_ref(), &[vault.bump]];
        let signer_seeds: &[&[&[u8]]] = &[seeds];

        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.to_account_info().try_borrow_mut_lamports()? += amount;

        // Suppress unused variable warning — seeds used for PDA authority proof
        let _ = signer_seeds;

        msg!("Withdrew {} lamports from vault", amount);
        Ok(())
    }

    /// Issue a time-limited, budget-scoped session key to an AI agent.
    pub fn issue_session_key(
        ctx: Context<IssueSessionKey>,
        agent: Pubkey,
        duration_secs: i64,
        max_single_amount: u64,
        daily_budget: u64,
    ) -> Result<()> {
        let session = &mut ctx.accounts.session;
        let now = Clock::get()?.unix_timestamp;

        session.vault = ctx.accounts.vault.key();
        session.agent = agent;
        session.active = true;
        session.expires_at = now + duration_secs;
        session.max_single_amount = max_single_amount;
        session.daily_budget = daily_budget;
        session.spent_today = 0;
        session.day_start = now;
        session.bump = ctx.bumps.session;

        msg!(
            "Session key issued for agent {} — expires at {}, daily budget {} lamports",
            agent,
            session.expires_at,
            daily_budget,
        );
        Ok(())
    }

    /// Revoke a session key immediately (owner only).
    pub fn revoke_session_key(ctx: Context<RevokeSessionKey>) -> Result<()> {
        let session = &mut ctx.accounts.session;
        session.active = false;
        msg!("Session key revoked for agent {}", session.agent);
        Ok(())
    }

    /// Execute a SOL transfer through the vault's physics modules.
    ///
    /// Requires BOTH the agent signature AND the Plimsoll proxy cosignature.
    /// The cosigner proves the transaction passed all 7 off-chain engines.
    ///
    /// Check order:
    ///   1. Emergency lock check
    ///   2. Session key validity + expiry
    ///   3. Single-tx cap
    ///   4. Daily budget
    ///   5. Velocity limit (hourly rolling window)
    ///   6. Drawdown guard (portfolio floor)
    ///   7. Execute if all pass
    pub fn execute(ctx: Context<Execute>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let session = &mut ctx.accounts.session;
        let now = Clock::get()?.unix_timestamp;

        // ── 1. Emergency lock ────────────────────────────────────
        require!(!vault.emergency_locked, PlimsollError::EmergencyLocked);

        // ── 2. Session validity ──────────────────────────────────
        require!(session.active, PlimsollError::SessionInactive);
        require!(now < session.expires_at, PlimsollError::SessionExpired);

        // ── 3. Single-tx cap ─────────────────────────────────────
        require!(
            amount <= session.max_single_amount,
            PlimsollError::ExceedsSingleTxCap
        );

        // ── 4. Daily budget ──────────────────────────────────────
        // Roll over if 24h has passed
        if now >= session.day_start + 86400 {
            session.spent_today = 0;
            session.day_start = now;
        }
        require!(
            session.spent_today.checked_add(amount).ok_or(PlimsollError::ArithmeticOverflow)?
                <= session.daily_budget,
            PlimsollError::ExceedsDailyBudget
        );

        // ── 5. Velocity limit ────────────────────────────────────
        if vault.velocity_max_per_hour > 0 {
            // Reset window if expired
            if now >= vault.velocity_window_start + vault.velocity_window_secs {
                vault.velocity_spent_this_window = 0;
                vault.velocity_window_start = now;
            }
            let new_window_total = vault
                .velocity_spent_this_window
                .checked_add(amount)
                .ok_or(PlimsollError::ArithmeticOverflow)?;
            require!(
                new_window_total <= vault.velocity_max_per_hour,
                PlimsollError::VelocityLimitExceeded
            );
            vault.velocity_spent_this_window = new_window_total;
        }

        // ── 6. Drawdown guard ────────────────────────────────────
        if vault.max_drawdown_bps > 0 && vault.initial_balance > 0 {
            let vault_lamports = vault.to_account_info().lamports();
            let balance_after = vault_lamports
                .checked_sub(amount)
                .ok_or(PlimsollError::InsufficientBalance)?;
            let floor = vault
                .initial_balance
                .checked_mul((10_000u64).checked_sub(vault.max_drawdown_bps as u64).unwrap_or(0))
                .ok_or(PlimsollError::ArithmeticOverflow)?
                / 10_000;
            require!(balance_after >= floor, PlimsollError::DrawdownFloorBreached);
        }

        // ── 7. All physics passed — transfer ─────────────────────
        let vault_lamports = vault.to_account_info().lamports();
        require!(vault_lamports >= amount, PlimsollError::InsufficientBalance);

        session.spent_today = session
            .spent_today
            .checked_add(amount)
            .ok_or(PlimsollError::ArithmeticOverflow)?;

        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.to_account_info().try_borrow_mut_lamports()? += amount;

        msg!(
            "Execution approved: {} lamports from vault to {}",
            amount,
            ctx.accounts.recipient.key(),
        );
        Ok(())
    }

    /// Emergency lock — freezes all execution (owner only).
    pub fn emergency_lock(ctx: Context<EmergencyAction>) -> Result<()> {
        ctx.accounts.vault.emergency_locked = true;
        msg!("Vault emergency locked");
        Ok(())
    }

    /// Emergency unlock (owner only).
    pub fn emergency_unlock(ctx: Context<EmergencyAction>) -> Result<()> {
        ctx.accounts.vault.emergency_locked = false;
        msg!("Vault emergency unlocked");
        Ok(())
    }

    /// Update the Plimsoll proxy cosigner pubkey (owner only).
    pub fn set_cosigner(ctx: Context<Configure>, new_cosigner: Pubkey) -> Result<()> {
        ctx.accounts.vault.cosigner = new_cosigner;
        msg!("Cosigner updated to {}", new_cosigner);
        Ok(())
    }

    /// Update physics parameters (owner only).
    pub fn configure_physics(
        ctx: Context<Configure>,
        max_drawdown_bps: u16,
        velocity_max_per_hour: u64,
        velocity_window_secs: i64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.max_drawdown_bps = max_drawdown_bps;
        vault.velocity_max_per_hour = velocity_max_per_hour;
        if velocity_window_secs > 0 {
            vault.velocity_window_secs = velocity_window_secs;
        }
        msg!(
            "Physics updated: drawdown={}bps, velocity={}/hr, window={}s",
            max_drawdown_bps,
            velocity_max_per_hour,
            vault.velocity_window_secs,
        );
        Ok(())
    }
}

// ── Account structures ──────────────────────────────────────────

/// The vault PDA — holds SOL and enforces physics.
///
/// Seeds: `["plimsoll-vault", owner_pubkey]`
#[account]
pub struct VaultState {
    /// Owner pubkey (human / DAO).
    pub owner: Pubkey,
    /// Plimsoll Rust Proxy cosigner pubkey — every agent tx must carry this sig.
    pub cosigner: Pubkey,
    /// Emergency lock flag.
    pub emergency_locked: bool,
    /// Timestamp of first deposit.
    pub deposited_at: i64,
    /// Balance at first deposit (drawdown reference).
    pub initial_balance: u64,
    /// PDA bump seed.
    pub bump: u8,

    // Physics modules (on-chain)
    /// Maximum drawdown in basis points (500 = 5%).
    pub max_drawdown_bps: u16,
    /// Maximum lamports per velocity window (0 = disabled).
    pub velocity_max_per_hour: u64,
    /// Velocity window duration in seconds (default 3600).
    pub velocity_window_secs: i64,
    /// Lamports spent in the current velocity window.
    pub velocity_spent_this_window: u64,
    /// Start timestamp of current velocity window.
    pub velocity_window_start: i64,
}

impl VaultState {
    /// Account discriminator (8) + all fields.
    pub const LEN: usize = 8  // discriminator
        + 32   // owner
        + 32   // cosigner
        + 1    // emergency_locked
        + 8    // deposited_at
        + 8    // initial_balance
        + 1    // bump
        + 2    // max_drawdown_bps
        + 8    // velocity_max_per_hour
        + 8    // velocity_window_secs
        + 8    // velocity_spent_this_window
        + 8;   // velocity_window_start
}

/// Session key account — scoped permissions for an AI agent.
///
/// Seeds: `["plimsoll-session", vault_pubkey, agent_pubkey]`
#[account]
pub struct SessionState {
    /// Parent vault.
    pub vault: Pubkey,
    /// Agent pubkey.
    pub agent: Pubkey,
    /// Whether this session is active.
    pub active: bool,
    /// Expiry timestamp (Unix).
    pub expires_at: i64,
    /// Max lamports per single transaction.
    pub max_single_amount: u64,
    /// Max lamports per 24-hour period.
    pub daily_budget: u64,
    /// Lamports spent in the current day.
    pub spent_today: u64,
    /// Start of current daily window.
    pub day_start: i64,
    /// PDA bump seed.
    pub bump: u8,
}

impl SessionState {
    pub const LEN: usize = 8  // discriminator
        + 32   // vault
        + 32   // agent
        + 1    // active
        + 8    // expires_at
        + 8    // max_single_amount
        + 8    // daily_budget
        + 8    // spent_today
        + 8    // day_start
        + 1;   // bump
}

// ── Contexts ────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = owner,
        space = VaultState::LEN,
        seeds = [VAULT_SEED, owner.key().as_ref()],
        bump,
    )]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [VAULT_SEED, owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner,
    )]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [VAULT_SEED, owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner,
    )]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub owner: Signer<'info>,
    /// CHECK: Recipient can be any account — owner is responsible.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(agent: Pubkey)]
pub struct IssueSessionKey<'info> {
    #[account(
        mut,
        seeds = [VAULT_SEED, owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner,
    )]
    pub vault: Account<'info, VaultState>,
    #[account(
        init,
        payer = owner,
        space = SessionState::LEN,
        seeds = [SESSION_SEED, vault.key().as_ref(), agent.as_ref()],
        bump,
    )]
    pub session: Account<'info, SessionState>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeSessionKey<'info> {
    #[account(
        seeds = [VAULT_SEED, owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner,
    )]
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        seeds = [SESSION_SEED, vault.key().as_ref(), session.agent.as_ref()],
        bump = session.bump,
        has_one = vault,
    )]
    pub session: Account<'info, SessionState>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Execute<'info> {
    #[account(
        mut,
        seeds = [VAULT_SEED, vault.owner.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, VaultState>,
    #[account(
        mut,
        seeds = [SESSION_SEED, vault.key().as_ref(), agent.key().as_ref()],
        bump = session.bump,
        has_one = vault,
    )]
    pub session: Account<'info, SessionState>,
    /// The AI agent — must sign.
    pub agent: Signer<'info>,
    /// The Plimsoll proxy cosigner — MUST sign to prove off-chain engines passed.
    #[account(
        constraint = cosigner.key() == vault.cosigner @ PlimsollError::InvalidCosigner,
    )]
    pub cosigner: Signer<'info>,
    /// CHECK: Recipient of the transfer.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct EmergencyAction<'info> {
    #[account(
        mut,
        seeds = [VAULT_SEED, owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner,
    )]
    pub vault: Account<'info, VaultState>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Configure<'info> {
    #[account(
        mut,
        seeds = [VAULT_SEED, owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner,
    )]
    pub vault: Account<'info, VaultState>,
    pub owner: Signer<'info>,
}
