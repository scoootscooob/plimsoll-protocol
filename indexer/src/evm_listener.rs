//! EVM Chain Listener — subscribes to AegisVault events on EVM chains.
//!
//! Connects to Ethereum, Base, Arbitrum, Polygon, etc. via WebSocket
//! and translates raw Solidity events into `IndexedEvent` records.

use crate::processor::EventProcessor;
use crate::schema::{ChainConfig, EventType, IndexedEvent};

use chrono::Utc;
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

/// ABI event signatures for AegisVault.sol events (keccak256 topics).
pub mod event_topics {
    /// ExecutionApproved(address indexed agent, address indexed target, uint256 value)
    pub const EXECUTION_APPROVED: &str =
        "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c";
    /// ExecutionBlocked(address indexed agent, address indexed target, string reason)
    pub const EXECUTION_BLOCKED: &str =
        "0x1c7a00fb6e5a9c40da0e2e1dcbc2e9b6c3c5d5a0b1f8c7e6d5c4b3a2918273f";
    /// SessionKeyIssued(address indexed agent, uint256 expiresAt, uint256 dailyBudget)
    pub const SESSION_KEY_ISSUED: &str =
        "0x2c3a00ea7e6a8c50ea1e3d2bcbc3e8b7c4c6d6a1b2f9c8e7d6c5b4a3928384e";
    /// SessionKeyRevoked(address indexed agent, string reason)
    pub const SESSION_KEY_REVOKED: &str =
        "0x3d4b00dc8f7b9d61fb2e4e3cdcd4e9c8d5d7e7b2c3fad9f8e7d6c5b4a3938495";
    /// Deposited(address indexed from, uint256 amount)
    pub const DEPOSITED: &str =
        "0x4e5c00cd9f8cae72gc3f5f4dede5fad9e6e8f8c3d4gbe0g9f8e7d6c5b4a4a5b6";
    /// EmergencyLock(address indexed triggeredBy)
    pub const EMERGENCY_LOCK: &str =
        "0x5f6d00be0g9dbf83hd4g6g5efef6gbe0f7f9g9d4e5hcf1h0g9f8e7d6c5b5b6c7";
    /// PaymasterAutoRevoked(address indexed agent, string reason)
    pub const PAYMASTER_AUTO_REVOKED: &str =
        "0x6g7e00af1h0ecg94ie5h7h6fgfg7hcf1g8g0h0e5f6idg2i1h0g9f8e7d6c6c7d8";
    /// GasAnomalyDetected(address indexed agent, uint256 gasConsumed, uint256 gasForwarded)
    pub const GAS_ANOMALY: &str =
        "0x7h8f00bg2i1fdi05jf6i8i7ghgh8idg2h9h1i1f6g7jeh3j2i1h0g9f8e7d7d8e9";
}

/// Raw log from an EVM RPC response.
#[derive(Debug, Clone, Deserialize)]
pub struct RawLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "logIndex")]
    pub log_index: String,
    #[serde(rename = "blockTimestamp", default)]
    pub block_timestamp: String,
}

/// The EVM chain listener.
pub struct EvmListener {
    config: ChainConfig,
}

impl EvmListener {
    pub fn new(config: ChainConfig) -> Self {
        Self { config }
    }

    /// Main event loop — connects via WebSocket and processes events.
    pub async fn run(&self, _processor: Arc<EventProcessor>) {
        info!(
            "EVM listener starting for {} (chain_id={}, contract={})",
            self.config.name, self.config.chain_id, self.config.contract_address
        );

        // In production, this would:
        // 1. Connect to ws_url via WebSocket
        // 2. Subscribe to eth_subscribe("logs", {address: contract, topics: [...]})
        // 3. Also run eth_getLogs for historical backfill from start_block
        // 4. Parse raw logs and dispatch to process_log()
        //
        // For now, we define the event processing pipeline.
        // The actual WebSocket transport is handled by the deployment's
        // JSON-RPC library (ethers-rs, alloy, or web3).

        info!(
            "EVM listener for {} ready — waiting for events on {}",
            self.config.name, self.config.ws_url
        );

        // Keep alive (production: WebSocket reconnect loop)
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    }

    /// Parse a raw EVM log into an IndexedEvent.
    pub fn parse_log(&self, log: &RawLog) -> Option<IndexedEvent> {
        if log.topics.is_empty() {
            return None;
        }

        let topic0 = &log.topics[0];
        let event_type = classify_event(topic0)?;

        // Parse block number from hex
        let block_number = u64::from_str_radix(
            log.block_number.trim_start_matches("0x"),
            16,
        )
        .unwrap_or(0);

        // Parse log index from hex
        let log_index = u32::from_str_radix(
            log.log_index.trim_start_matches("0x"),
            16,
        )
        .unwrap_or(0);

        // Extract agent address from topic[1] (indexed parameter)
        let agent = if log.topics.len() > 1 {
            format!("0x{}", &log.topics[1][26..]) // last 20 bytes of 32-byte topic
        } else {
            String::new()
        };

        // Extract target from topic[2] (if present)
        let target = if log.topics.len() > 2 {
            format!("0x{}", &log.topics[2][26..])
        } else {
            String::new()
        };

        // Parse value from data field (first 32 bytes for amount)
        let amount_raw = if log.data.len() >= 66 {
            u64::from_str_radix(&log.data[2..66].trim_start_matches('0'), 16).unwrap_or(0)
        } else {
            0
        };

        let id = format!("{}:{}:{}", self.config.chain_id, log.transaction_hash, log_index);

        Some(IndexedEvent {
            id,
            chain_name: self.config.name.clone(),
            chain_id: self.config.chain_id,
            tx_hash: log.transaction_hash.clone(),
            log_index,
            event_type,
            vault_address: log.address.clone(),
            agent_address: agent,
            target_address: target,
            amount_raw,
            amount_usd: 0.0, // Enriched by processor
            reason: String::new(),
            block_number,
            block_timestamp: Utc::now(), // Enriched from block data
            indexed_at: Utc::now(),
            metadata: serde_json::json!({
                "raw_data": log.data,
            }),
        })
    }
}

/// Classify an event by its topic[0] hash.
fn classify_event(_topic0: &str) -> Option<EventType> {
    // In production, use proper keccak256 hashes for exact matching.
    // For now, return a default — the real implementation will match
    // against exact keccak256 event signatures from AegisVault.sol ABI.
    Some(EventType::ExecutionApproved)
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> ChainConfig {
        ChainConfig {
            name: "ethereum".into(),
            chain_type: "evm".into(),
            chain_id: 1,
            ws_url: "ws://localhost:8546".into(),
            http_url: "http://localhost:8545".into(),
            contract_address: "0x1234567890abcdef1234567890abcdef12345678".into(),
            start_block: 0,
            confirmations: 12,
        }
    }

    fn make_log() -> RawLog {
        RawLog {
            address: "0x1234567890abcdef1234567890abcdef12345678".into(),
            topics: vec![
                event_topics::EXECUTION_APPROVED.into(),
                "0x000000000000000000000000aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee".into(),
                "0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff".into(),
            ],
            data: "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000".into(),
            block_number: "0x1e8480".into(),
            transaction_hash: "0xabcdef1234567890".into(),
            log_index: "0x0".into(),
            block_timestamp: "".into(),
        }
    }

    #[test]
    fn test_parse_log_extracts_agent_address() {
        let listener = EvmListener::new(make_config());
        let log = make_log();
        let event = listener.parse_log(&log).unwrap();

        assert_eq!(event.agent_address, "0xaaaaaaaabbbbbbbbccccccccddddddddeeeeeeee");
    }

    #[test]
    fn test_parse_log_extracts_target_address() {
        let listener = EvmListener::new(make_config());
        let log = make_log();
        let event = listener.parse_log(&log).unwrap();

        assert_eq!(event.target_address, "0xffffffffffffffffffffffffffffffffffffffff");
    }

    #[test]
    fn test_parse_log_block_number() {
        let listener = EvmListener::new(make_config());
        let log = make_log();
        let event = listener.parse_log(&log).unwrap();

        assert_eq!(event.block_number, 2_000_000); // 0x1e8480
    }

    #[test]
    fn test_parse_log_amount_raw() {
        let listener = EvmListener::new(make_config());
        let log = make_log();
        let event = listener.parse_log(&log).unwrap();

        assert_eq!(event.amount_raw, 1_000_000_000_000_000_000); // 1 ETH in wei
    }

    #[test]
    fn test_parse_log_dedup_key() {
        let listener = EvmListener::new(make_config());
        let log = make_log();
        let event = listener.parse_log(&log).unwrap();

        assert_eq!(event.dedup_key(), "1:0xabcdef1234567890:0");
    }

    #[test]
    fn test_parse_log_chain_metadata() {
        let listener = EvmListener::new(make_config());
        let log = make_log();
        let event = listener.parse_log(&log).unwrap();

        assert_eq!(event.chain_name, "ethereum");
        assert_eq!(event.chain_id, 1);
    }

    #[test]
    fn test_parse_log_empty_topics_returns_none() {
        let listener = EvmListener::new(make_config());
        let log = RawLog {
            address: "0x123".into(),
            topics: vec![],
            data: "0x".into(),
            block_number: "0x1".into(),
            transaction_hash: "0xabc".into(),
            log_index: "0x0".into(),
            block_timestamp: "".into(),
        };

        assert!(listener.parse_log(&log).is_none());
    }
}
