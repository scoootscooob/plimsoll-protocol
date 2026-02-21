//! Database schema and configuration for the Plimsoll Fleet Indexer.
//!
//! Defines the universal event schema that normalizes events from
//! Ethereum, Solana, and future chains into a single queryable format.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::env;

// ── Configuration ───────────────────────────────────────────────

/// Chain configuration for the indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Human-readable chain name (e.g., "ethereum", "base", "solana").
    pub name: String,
    /// Chain type: "evm" or "solana".
    pub chain_type: String,
    /// Numeric chain ID (for EVM chains).
    pub chain_id: u64,
    /// WebSocket RPC endpoint for real-time subscription.
    pub ws_url: String,
    /// HTTP RPC endpoint for historical backfill.
    pub http_url: String,
    /// PlimsollVault contract address (EVM) or program ID (Solana).
    pub contract_address: String,
    /// Block to start indexing from (0 = latest).
    pub start_block: u64,
    /// Number of confirmations before considering finalized.
    pub confirmations: u64,
}

/// Top-level indexer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerConfig {
    /// PostgreSQL connection string.
    pub database_url: String,
    /// Chains to index.
    pub chains: Vec<ChainConfig>,
    /// Batch size for database inserts.
    pub batch_size: usize,
    /// Flush interval in milliseconds.
    pub flush_interval_ms: u64,
}

impl IndexerConfig {
    /// Load configuration from environment variables.
    ///
    /// Example env vars:
    ///   DATABASE_URL=postgres://user:pass@localhost/plimsoll
    ///   PLIMSOLL_CHAINS=ethereum,base,solana
    ///   PLIMSOLL_CHAIN_ETHEREUM_WS=wss://eth-mainnet.ws.alchemyapi.io/v2/KEY
    ///   PLIMSOLL_CHAIN_ETHEREUM_HTTP=https://eth-mainnet.g.alchemy.com/v2/KEY
    ///   PLIMSOLL_CHAIN_ETHEREUM_CONTRACT=0x...
    ///   PLIMSOLL_CHAIN_ETHEREUM_ID=1
    pub fn from_env() -> Self {
        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/plimsoll_indexer".into());

        let chain_names: Vec<String> = env::var("PLIMSOLL_CHAINS")
            .unwrap_or_else(|_| "ethereum".into())
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .collect();

        let chains: Vec<ChainConfig> = chain_names
            .iter()
            .map(|name| {
                let prefix = format!("PLIMSOLL_CHAIN_{}", name.to_uppercase());
                ChainConfig {
                    name: name.clone(),
                    chain_type: env::var(format!("{}_TYPE", prefix))
                        .unwrap_or_else(|_| {
                            if name == "solana" { "solana".into() } else { "evm".into() }
                        }),
                    chain_id: env::var(format!("{}_ID", prefix))
                        .unwrap_or_else(|_| default_chain_id(name).to_string())
                        .parse()
                        .unwrap_or(1),
                    ws_url: env::var(format!("{}_WS", prefix))
                        .unwrap_or_else(|_| default_ws_url(name)),
                    http_url: env::var(format!("{}_HTTP", prefix))
                        .unwrap_or_else(|_| default_http_url(name)),
                    contract_address: env::var(format!("{}_CONTRACT", prefix))
                        .unwrap_or_default(),
                    start_block: env::var(format!("{}_START_BLOCK", prefix))
                        .unwrap_or_else(|_| "0".into())
                        .parse()
                        .unwrap_or(0),
                    confirmations: env::var(format!("{}_CONFIRMATIONS", prefix))
                        .unwrap_or_else(|_| default_confirmations(name).to_string())
                        .parse()
                        .unwrap_or(12),
                }
            })
            .collect();

        IndexerConfig {
            database_url,
            chains,
            batch_size: env::var("PLIMSOLL_BATCH_SIZE")
                .unwrap_or_else(|_| "100".into())
                .parse()
                .unwrap_or(100),
            flush_interval_ms: env::var("PLIMSOLL_FLUSH_INTERVAL_MS")
                .unwrap_or_else(|_| "500".into())
                .parse()
                .unwrap_or(500),
        }
    }
}

fn default_chain_id(name: &str) -> u64 {
    match name {
        "ethereum" => 1,
        "base" => 8453,
        "arbitrum" => 42161,
        "polygon" => 137,
        "optimism" => 10,
        "solana" => 0, // Not applicable
        _ => 1,
    }
}

fn default_ws_url(name: &str) -> String {
    match name {
        "solana" => "wss://api.mainnet-beta.solana.com".into(),
        _ => "ws://localhost:8546".into(),
    }
}

fn default_http_url(name: &str) -> String {
    match name {
        "solana" => "https://api.mainnet-beta.solana.com".into(),
        _ => "http://localhost:8545".into(),
    }
}

fn default_confirmations(name: &str) -> u64 {
    match name {
        "ethereum" => 12,
        "base" | "optimism" | "arbitrum" => 1, // L2s have faster finality
        "polygon" => 128,
        "solana" => 32,
        _ => 12,
    }
}

// ── Universal Event Schema ──────────────────────────────────────

/// The event type categorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    ExecutionApproved,
    ExecutionBlocked,
    SessionKeyIssued,
    SessionKeyRevoked,
    Deposited,
    Withdrawn,
    EmergencyLock,
    EmergencyUnlock,
    VelocityLimitHit,
    DrawdownFloorBreached,
    PaymasterAutoRevoked,
    GasAnomalyDetected,
    ProxyUpgradeBlocked,
    CosignRejected,
}

/// Universal indexed event — normalized across all chains.
///
/// This is the core data model that maps every chain-specific event
/// into a single queryable schema.  The React dashboard reads from
/// the `plimsoll_events` table populated with these records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedEvent {
    // ── Identity ─────────────────────────────────────────────
    /// Unique event ID (chain_id:tx_hash:log_index).
    pub id: String,
    /// Chain name (e.g., "ethereum", "base", "solana").
    pub chain_name: String,
    /// Numeric chain ID (EVM) or 0 (Solana).
    pub chain_id: u64,
    /// Transaction hash (hex for EVM, base58 for Solana).
    pub tx_hash: String,
    /// Log index within the transaction.
    pub log_index: u32,

    // ── Event data ───────────────────────────────────────────
    /// Categorized event type.
    pub event_type: EventType,
    /// Vault address (EVM address or Solana PDA).
    pub vault_address: String,
    /// Agent address (session key holder).
    pub agent_address: String,
    /// Target address of the transaction (if applicable).
    pub target_address: String,
    /// Amount in the chain's native token (wei for EVM, lamports for Solana).
    pub amount_raw: u64,
    /// Amount in USD (enriched by the processor).
    pub amount_usd: f64,
    /// Human-readable reason (for blocked events).
    pub reason: String,

    // ── Metadata ─────────────────────────────────────────────
    /// Block number.
    pub block_number: u64,
    /// Block timestamp (UTC).
    pub block_timestamp: DateTime<Utc>,
    /// When this event was indexed.
    pub indexed_at: DateTime<Utc>,
    /// Additional chain-specific metadata (JSON).
    pub metadata: serde_json::Value,
}

impl IndexedEvent {
    /// Generate the composite deduplication key.
    pub fn dedup_key(&self) -> String {
        format!("{}:{}:{}", self.chain_id, self.tx_hash, self.log_index)
    }
}

// ── SQL Schema ──────────────────────────────────────────────────

/// SQL DDL for creating the database schema.
///
/// Uses PostgreSQL partitioning by chain_id for optimal query performance.
/// The composite index on (vault_address, chain_id, block_timestamp)
/// enables the dashboard to load 5,000 agents in <40ms.
pub const CREATE_SCHEMA_SQL: &str = r#"
-- Plimsoll Fleet Indexer — PostgreSQL Schema
-- Partitioned by chain_id for multi-chain query performance.

CREATE TABLE IF NOT EXISTS plimsoll_events (
    id                TEXT PRIMARY KEY,
    chain_name        TEXT NOT NULL,
    chain_id          BIGINT NOT NULL,
    tx_hash           TEXT NOT NULL,
    log_index         INTEGER NOT NULL,
    event_type        TEXT NOT NULL,
    vault_address     TEXT NOT NULL,
    agent_address     TEXT NOT NULL DEFAULT '',
    target_address    TEXT NOT NULL DEFAULT '',
    amount_raw        BIGINT NOT NULL DEFAULT 0,
    amount_usd        DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    reason            TEXT NOT NULL DEFAULT '',
    block_number      BIGINT NOT NULL,
    block_timestamp   TIMESTAMPTZ NOT NULL,
    indexed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata          JSONB NOT NULL DEFAULT '{}'
) PARTITION BY LIST (chain_id);

-- Partitions for each supported chain
CREATE TABLE IF NOT EXISTS plimsoll_events_ethereum PARTITION OF plimsoll_events
    FOR VALUES IN (1);
CREATE TABLE IF NOT EXISTS plimsoll_events_base PARTITION OF plimsoll_events
    FOR VALUES IN (8453);
CREATE TABLE IF NOT EXISTS plimsoll_events_arbitrum PARTITION OF plimsoll_events
    FOR VALUES IN (42161);
CREATE TABLE IF NOT EXISTS plimsoll_events_polygon PARTITION OF plimsoll_events
    FOR VALUES IN (137);
CREATE TABLE IF NOT EXISTS plimsoll_events_optimism PARTITION OF plimsoll_events
    FOR VALUES IN (10);
CREATE TABLE IF NOT EXISTS plimsoll_events_solana PARTITION OF plimsoll_events
    FOR VALUES IN (0);

-- Default partition for unknown chains
CREATE TABLE IF NOT EXISTS plimsoll_events_default PARTITION OF plimsoll_events
    DEFAULT;

-- Indexes for dashboard queries (<40ms for 5,000 agents)
CREATE INDEX IF NOT EXISTS idx_events_vault_chain_time
    ON plimsoll_events (vault_address, chain_id, block_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_agent_time
    ON plimsoll_events (agent_address, block_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_type_time
    ON plimsoll_events (event_type, block_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_tx_hash
    ON plimsoll_events (tx_hash);
CREATE INDEX IF NOT EXISTS idx_events_block_number
    ON plimsoll_events (chain_id, block_number DESC);

-- Materialized view for real-time agent statistics
-- Refresh every 10 seconds via pg_cron or application-level timer
CREATE MATERIALIZED VIEW IF NOT EXISTS agent_stats AS
SELECT
    vault_address,
    agent_address,
    chain_id,
    chain_name,
    COUNT(*) FILTER (WHERE event_type = 'ExecutionApproved') AS total_approved,
    COUNT(*) FILTER (WHERE event_type = 'ExecutionBlocked') AS total_blocked,
    COALESCE(SUM(amount_usd) FILTER (WHERE event_type = 'ExecutionApproved'), 0) AS total_spend_usd,
    MAX(block_timestamp) AS last_activity,
    COUNT(DISTINCT DATE_TRUNC('day', block_timestamp)) AS active_days
FROM plimsoll_events
WHERE agent_address != ''
GROUP BY vault_address, agent_address, chain_id, chain_name;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_stats_unique
    ON agent_stats (vault_address, agent_address, chain_id);

-- Vault state snapshot (latest known state per vault)
CREATE TABLE IF NOT EXISTS vault_state (
    vault_address     TEXT NOT NULL,
    chain_id          BIGINT NOT NULL,
    chain_name        TEXT NOT NULL,
    balance_raw       BIGINT NOT NULL DEFAULT 0,
    balance_usd       DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    active_sessions   INTEGER NOT NULL DEFAULT 0,
    emergency_locked  BOOLEAN NOT NULL DEFAULT FALSE,
    total_deposited   BIGINT NOT NULL DEFAULT 0,
    total_withdrawn   BIGINT NOT NULL DEFAULT 0,
    last_block        BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_address, chain_id)
);

CREATE INDEX IF NOT EXISTS idx_vault_state_chain
    ON vault_state (chain_id, vault_address);
"#;

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_indexed_event_dedup_key() {
        let event = IndexedEvent {
            id: "1:0xabc:0".into(),
            chain_name: "ethereum".into(),
            chain_id: 1,
            tx_hash: "0xabc".into(),
            log_index: 0,
            event_type: EventType::ExecutionApproved,
            vault_address: "0x123".into(),
            agent_address: "0x456".into(),
            target_address: "0x789".into(),
            amount_raw: 1_000_000_000,
            amount_usd: 3000.0,
            reason: String::new(),
            block_number: 12345,
            block_timestamp: Utc::now(),
            indexed_at: Utc::now(),
            metadata: serde_json::json!({}),
        };

        assert_eq!(event.dedup_key(), "1:0xabc:0");
    }

    #[test]
    fn test_default_chain_ids() {
        assert_eq!(default_chain_id("ethereum"), 1);
        assert_eq!(default_chain_id("base"), 8453);
        assert_eq!(default_chain_id("arbitrum"), 42161);
        assert_eq!(default_chain_id("polygon"), 137);
        assert_eq!(default_chain_id("solana"), 0);
    }

    #[test]
    fn test_default_confirmations() {
        assert_eq!(default_confirmations("ethereum"), 12);
        assert_eq!(default_confirmations("base"), 1);
        assert_eq!(default_confirmations("solana"), 32);
    }

    #[test]
    fn test_config_from_env_defaults() {
        // With no env vars set, should use defaults
        let config = IndexerConfig::from_env();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.flush_interval_ms, 500);
    }

    #[test]
    fn test_event_type_serialization() {
        let event_type = EventType::ExecutionBlocked;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("ExecutionBlocked"));

        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event_type);
    }

    #[test]
    fn test_sql_schema_contains_partitions() {
        assert!(CREATE_SCHEMA_SQL.contains("PARTITION BY LIST (chain_id)"));
        assert!(CREATE_SCHEMA_SQL.contains("plimsoll_events_ethereum"));
        assert!(CREATE_SCHEMA_SQL.contains("plimsoll_events_base"));
        assert!(CREATE_SCHEMA_SQL.contains("plimsoll_events_solana"));
    }

    #[test]
    fn test_sql_schema_has_performance_indexes() {
        assert!(CREATE_SCHEMA_SQL.contains("idx_events_vault_chain_time"));
        assert!(CREATE_SCHEMA_SQL.contains("idx_events_agent_time"));
        assert!(CREATE_SCHEMA_SQL.contains("idx_events_tx_hash"));
    }

    #[test]
    fn test_sql_schema_has_materialized_view() {
        assert!(CREATE_SCHEMA_SQL.contains("agent_stats"));
        assert!(CREATE_SCHEMA_SQL.contains("total_approved"));
        assert!(CREATE_SCHEMA_SQL.contains("total_blocked"));
        assert!(CREATE_SCHEMA_SQL.contains("total_spend_usd"));
    }

    #[test]
    fn test_sql_schema_has_vault_state() {
        assert!(CREATE_SCHEMA_SQL.contains("vault_state"));
        assert!(CREATE_SCHEMA_SQL.contains("emergency_locked"));
        assert!(CREATE_SCHEMA_SQL.contains("active_sessions"));
    }
}
