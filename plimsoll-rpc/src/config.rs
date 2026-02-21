//! Configuration for the Plimsoll RPC Proxy.

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    /// Upstream Ethereum RPC URL (Alchemy, Infura, etc.)
    pub upstream_rpc_url: String,

    /// Host to bind to
    pub host: String,

    /// Port to listen on
    pub port: u16,

    /// Fee in basis points (1 bps = 0.01%)
    pub fee_bps: u16,

    /// Fee collector address (receives the protocol fee)
    pub fee_collector: String,

    /// Maximum allowed net-worth loss percentage in simulation
    pub max_loss_pct: f64,

    /// Block transactions that modify token approvals
    pub block_approval_changes: bool,

    /// Enable Flashbots MEV-shielded routing
    pub flashbots_enabled: bool,

    /// Flashbots relay URL
    pub flashbots_relay_url: String,

    /// Block number to fork from (0 = latest)
    pub fork_block: u64,

    /// Zero-Day 1: Simulation gas ceiling (default: 5M).
    /// Prevents flashloan gas bomb attacks from pegging CPU.
    pub simulation_gas_ceiling: u64,

    /// Zero-Day 1: Simulation wall-clock timeout in milliseconds (default: 50ms).
    /// Catches opcodes cheap in gas but expensive in real time.
    pub simulation_timeout_ms: u64,

    /// Zero-Day 3: Maximum bundle deadline in seconds from current block timestamp.
    /// Prevents MEV builders from holding transactions indefinitely.
    pub max_bundle_deadline_secs: u64,

    // ── v1.0.2: Zero-Day Patch Configuration ─────────────────────

    /// Patch 1 (Trojan Receipt): Sanitize read-path RPC responses to strip
    /// LLM control tokens injected in malicious contract return data.
    pub sanitize_read_responses: bool,

    /// Patch 2 (Schrödinger's State): Detect non-deterministic JUMPI conditions
    /// caused by environmental opcodes (BLOCKHASH, COINBASE, TIMESTAMP, etc.).
    pub detect_non_determinism: bool,

    /// Patch 3 (Cross-Chain Replay): Expected chainId for EIP-712 domain
    /// validation. 0 = disabled (backward compatibility).
    pub expected_chain_id: u64,

    /// Patch 4 (Paymaster Slashing): Maximum gas per UserOperation.
    /// 0 = disabled.
    pub max_userop_gas: u64,

    /// Patch 4 (Paymaster Slashing): Maximum revert strikes before sever.
    /// 0 = disabled.
    pub revert_strike_max: u32,

    /// Patch 4 (Paymaster Slashing): Rolling window in seconds for revert strikes.
    pub revert_strike_window_secs: u64,

    // ── v1.0.3: Bounty Patch Configuration ──────────────────────────

    /// Bounty 1 (JSON Pollution): Reject JSON-RPC requests with duplicate
    /// keys in transaction objects to prevent parser divergence attacks.
    pub reject_duplicate_json_keys: bool,

    /// Bounty 2 (Proxy Illusion): Check EIP-1967 implementation storage slot
    /// to detect proxy upgrades between simulation and execution.
    pub check_proxy_impl_slot: bool,

    /// Bounty 3 (L1 Data Fee): Chain ID for L2-aware TVAR computation.
    /// On L2 rollups, TVAR includes L1 data posting cost.
    pub chain_id: u64,

    /// Bounty 4 (Gas Black Hole): Gas anomaly ratio threshold.
    /// If receipt.gasUsed / simulated.gasUsed > this ratio, record a strike.
    /// 0.0 = disabled.
    pub gas_anomaly_ratio: f64,

    // ── v1.0.4: Kill-Shot Configuration ──────────────────────────────

    /// Kill-Shot 1 (Bundler Illusion): ERC-4337 Bundler address for tx.origin.
    /// When set, the simulator overrides tx.origin to this address instead of
    /// defaulting to tx.caller, matching ERC-4337 on-chain reality where
    /// tx.origin is the Bundler (e.g., Alchemy), not the agent.
    /// Empty string = disabled (backward compat).
    pub bundler_address: String,

    /// Kill-Shot 2 (PVG Heist): Maximum preVerificationGas allowed.
    /// ERC-4337 PVG is a flat Bundler fee paid BEFORE execution, invisible
    /// to the EVM simulator. Capping it prevents Paymaster drain.
    /// 0 = disabled (backward compat).
    pub max_pre_verification_gas: u64,

    /// Kill-Shot 3 (Bridge Refund Hijack): Enable bridge parameter validation.
    /// When true, validates that refund addresses in bridge calldata (Arbitrum,
    /// Optimism) match the sender to prevent excess fee theft.
    pub bridge_refund_check: bool,

    /// Kill-Shot 3: Comma-separated list of known bridge contract addresses.
    pub bridge_contracts: String,

    /// Kill-Shot 4 (Permit2 Time-Bomb): Maximum permit signature duration in seconds.
    /// EIP-712 signatures with expiration/deadline beyond this window are rejected.
    /// Prevents immortal signatures that can be reused after the legitimate swap.
    /// 0 = disabled (backward compat).
    pub max_permit_duration_secs: u64,

    // ── v2.0: Multi-Chain Configuration ─────────────────────────────

    /// Enable Solana transaction interception (sendTransaction method).
    /// When true, Solana JSON-RPC calls are analysed for unauthorized
    /// writable accounts before forwarding.
    /// false = disabled (default, backward compat).
    pub svm_enabled: bool,

    /// Comma-separated Solana account pubkeys allowed to be writable.
    /// Empty = allow all (no whitelist enforcement).
    pub svm_whitelisted_accounts: String,

    /// Enable Bitcoin PSBT interception (signrawtransaction/signpsbt).
    /// false = disabled (default, backward compat).
    pub utxo_enabled: bool,

    /// Maximum implicit miner fee in USD for Bitcoin PSBTs.
    /// Transactions exceeding this are blocked (Conservation of Mass).
    pub utxo_max_fee_usd: f64,

    /// Fallback BTC/USD price for PSBT fee calculation.
    pub btc_price_usd: f64,

    /// Enable HTTP forward proxy on a separate port.
    /// false = disabled (default, backward compat).
    pub http_proxy_enabled: bool,

    /// Port for the HTTP forward proxy (default 8080).
    pub http_proxy_port: u16,

    /// Comma-separated domains governed by the HTTP proxy.
    /// Only these domains have their costs tracked.
    pub http_governed_domains: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            upstream_rpc_url: std::env::var("PLIMSOLL_UPSTREAM_RPC")
                .unwrap_or_else(|_| "https://eth-mainnet.g.alchemy.com/v2/demo".into()),
            host: std::env::var("PLIMSOLL_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("PLIMSOLL_PORT")
                .unwrap_or_else(|_| "8545".into())
                .parse()
                .context("Invalid PLIMSOLL_PORT")?,
            fee_bps: std::env::var("PLIMSOLL_FEE_BPS")
                .unwrap_or_else(|_| "2".into())
                .parse()
                .context("Invalid PLIMSOLL_FEE_BPS")?,
            fee_collector: std::env::var("PLIMSOLL_FEE_COLLECTOR")
                .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".into()),
            max_loss_pct: std::env::var("PLIMSOLL_MAX_LOSS_PCT")
                .unwrap_or_else(|_| "20.0".into())
                .parse()
                .context("Invalid PLIMSOLL_MAX_LOSS_PCT")?,
            block_approval_changes: std::env::var("PLIMSOLL_BLOCK_APPROVALS")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
            flashbots_enabled: std::env::var("PLIMSOLL_FLASHBOTS_ENABLED")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            flashbots_relay_url: std::env::var("PLIMSOLL_FLASHBOTS_RELAY")
                .unwrap_or_else(|_| "https://relay.flashbots.net".into()),
            fork_block: std::env::var("PLIMSOLL_FORK_BLOCK")
                .unwrap_or_else(|_| "0".into())
                .parse()
                .unwrap_or(0),
            simulation_gas_ceiling: std::env::var("PLIMSOLL_SIM_GAS_CEILING")
                .unwrap_or_else(|_| "5000000".into())
                .parse()
                .unwrap_or(5_000_000),
            simulation_timeout_ms: std::env::var("PLIMSOLL_SIM_TIMEOUT_MS")
                .unwrap_or_else(|_| "50".into())
                .parse()
                .unwrap_or(50),
            max_bundle_deadline_secs: std::env::var("PLIMSOLL_MAX_BUNDLE_DEADLINE")
                .unwrap_or_else(|_| "24".into())
                .parse()
                .unwrap_or(24),
            sanitize_read_responses: std::env::var("PLIMSOLL_SANITIZE_READS")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            detect_non_determinism: std::env::var("PLIMSOLL_DETECT_NONDET")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            expected_chain_id: std::env::var("PLIMSOLL_EXPECTED_CHAIN_ID")
                .unwrap_or_else(|_| "0".into())
                .parse()
                .unwrap_or(0),
            max_userop_gas: std::env::var("PLIMSOLL_MAX_USEROP_GAS")
                .unwrap_or_else(|_| "0".into())
                .parse()
                .unwrap_or(0),
            revert_strike_max: std::env::var("PLIMSOLL_REVERT_STRIKE_MAX")
                .unwrap_or_else(|_| "0".into())
                .parse()
                .unwrap_or(0),
            revert_strike_window_secs: std::env::var("PLIMSOLL_REVERT_STRIKE_WINDOW")
                .unwrap_or_else(|_| "300".into())
                .parse()
                .unwrap_or(300),
            reject_duplicate_json_keys: std::env::var("PLIMSOLL_REJECT_DUPLICATE_KEYS")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            check_proxy_impl_slot: std::env::var("PLIMSOLL_CHECK_PROXY_IMPL")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            chain_id: std::env::var("PLIMSOLL_CHAIN_ID")
                .unwrap_or_else(|_| "1".into())
                .parse()
                .unwrap_or(1),
            gas_anomaly_ratio: std::env::var("PLIMSOLL_GAS_ANOMALY_RATIO")
                .unwrap_or_else(|_| "0.0".into())
                .parse()
                .unwrap_or(0.0),
            bundler_address: std::env::var("PLIMSOLL_BUNDLER_ADDRESS")
                .unwrap_or_else(|_| "".into()),
            max_pre_verification_gas: std::env::var("PLIMSOLL_MAX_PVG")
                .unwrap_or_else(|_| "0".into())
                .parse()
                .unwrap_or(0),
            bridge_refund_check: std::env::var("PLIMSOLL_BRIDGE_REFUND_CHECK")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            bridge_contracts: std::env::var("PLIMSOLL_BRIDGE_CONTRACTS")
                .unwrap_or_else(|_| "".into()),
            max_permit_duration_secs: std::env::var("PLIMSOLL_MAX_PERMIT_DURATION")
                .unwrap_or_else(|_| "0".into())
                .parse()
                .unwrap_or(0),
            // v2.0: Multi-Chain
            svm_enabled: std::env::var("PLIMSOLL_SVM_ENABLED")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            svm_whitelisted_accounts: std::env::var("PLIMSOLL_SVM_WHITELISTED_ACCOUNTS")
                .unwrap_or_else(|_| "".into()),
            utxo_enabled: std::env::var("PLIMSOLL_UTXO_ENABLED")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            utxo_max_fee_usd: std::env::var("PLIMSOLL_UTXO_MAX_FEE_USD")
                .unwrap_or_else(|_| "50.0".into())
                .parse()
                .unwrap_or(50.0),
            btc_price_usd: std::env::var("PLIMSOLL_BTC_PRICE_USD")
                .unwrap_or_else(|_| "60000.0".into())
                .parse()
                .unwrap_or(60_000.0),
            http_proxy_enabled: std::env::var("PLIMSOLL_HTTP_PROXY_ENABLED")
                .unwrap_or_else(|_| "false".into())
                .parse()
                .unwrap_or(false),
            http_proxy_port: std::env::var("PLIMSOLL_HTTP_PROXY_PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .unwrap_or(8080),
            http_governed_domains: std::env::var("PLIMSOLL_HTTP_GOVERNED_DOMAINS")
                .unwrap_or_else(|_| "".into()),
        })
    }
}
