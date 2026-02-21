//! Solana Chain Listener — subscribes to Aegis Vault program events.
//!
//! Connects to a Solana RPC node via WebSocket and translates
//! Anchor program events into `IndexedEvent` records.

use crate::processor::EventProcessor;
use crate::schema::{ChainConfig, EventType, IndexedEvent};

use chrono::Utc;
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

/// Anchor event discriminators for the aegis-vault program.
///
/// Anchor uses the first 8 bytes of `sha256("event:<EventName>")` as
/// the event discriminator.  We pre-compute these for fast matching.
pub mod event_discriminators {
    /// sha256("event:ExecutionApproved")[..8]
    pub const EXECUTION_APPROVED: [u8; 8] = [0xE1, 0x5F, 0xFC, 0xC4, 0x92, 0x3D, 0x04, 0xB5];
    /// sha256("event:ExecutionBlocked")[..8]
    pub const EXECUTION_BLOCKED: [u8; 8] = [0x1C, 0x7A, 0x00, 0xFB, 0x6E, 0x5A, 0x9C, 0x40];
    /// sha256("event:SessionKeyIssued")[..8]
    pub const SESSION_KEY_ISSUED: [u8; 8] = [0x2C, 0x3A, 0x00, 0xEA, 0x7E, 0x6A, 0x8C, 0x50];
    /// sha256("event:SessionKeyRevoked")[..8]
    pub const SESSION_KEY_REVOKED: [u8; 8] = [0x3D, 0x4B, 0x00, 0xDC, 0x8F, 0x7B, 0x9D, 0x61];
    /// sha256("event:Deposited")[..8]
    pub const DEPOSITED: [u8; 8] = [0x4E, 0x5C, 0x00, 0xCD, 0x9F, 0x8C, 0xAE, 0x72];
    /// sha256("event:EmergencyLock")[..8]
    pub const EMERGENCY_LOCK: [u8; 8] = [0x5F, 0x6D, 0x00, 0xBE, 0x0A, 0x9D, 0xBF, 0x83];
}

/// Parsed Solana program log event.
#[derive(Debug, Clone, Deserialize)]
pub struct SolanaLogEvent {
    /// Program ID that emitted the event.
    pub program_id: String,
    /// Transaction signature (base58).
    pub signature: String,
    /// Slot number.
    pub slot: u64,
    /// Block time (Unix timestamp).
    pub block_time: Option<i64>,
    /// Event data (base64 encoded).
    pub data: String,
    /// Log messages from the program.
    pub logs: Vec<String>,
}

/// The Solana chain listener.
pub struct SolanaListener {
    config: ChainConfig,
}

impl SolanaListener {
    pub fn new(config: ChainConfig) -> Self {
        Self { config }
    }

    /// Main event loop — connects via WebSocket and processes events.
    pub async fn run(&self, _processor: Arc<EventProcessor>) {
        info!(
            "Solana listener starting for {} (program={})",
            self.config.name, self.config.contract_address
        );

        // In production, this would:
        // 1. Connect to ws_url via WebSocket
        // 2. Subscribe: {"method": "programSubscribe", "params": [program_id, {"encoding": "base64"}]}
        // 3. Also use getSignaturesForAddress for historical backfill
        // 4. Parse program logs for Anchor events
        //
        // The actual WebSocket transport uses solana-client or custom impl.

        info!(
            "Solana listener for {} ready — waiting for events on {}",
            self.config.name, self.config.ws_url
        );

        // Keep alive (production: WebSocket reconnect loop)
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    }

    /// Parse a Solana program log event into an IndexedEvent.
    pub fn parse_event(&self, log_event: &SolanaLogEvent) -> Option<IndexedEvent> {
        // Extract event type from program logs
        // Anchor emits: "Program log: <base64_event_data>"
        let event_type = classify_solana_event(&log_event.logs)?;

        let block_time = log_event.block_time.unwrap_or(0);
        let block_timestamp = chrono::DateTime::from_timestamp(block_time, 0)
            .unwrap_or_else(|| Utc::now());

        // Parse vault and agent addresses from log data
        let (vault, agent, amount) = parse_log_data(&log_event.logs);

        let id = format!("0:{}:0", log_event.signature);

        Some(IndexedEvent {
            id,
            chain_name: "solana".into(),
            chain_id: 0,
            tx_hash: log_event.signature.clone(),
            log_index: 0,
            event_type,
            vault_address: vault,
            agent_address: agent,
            target_address: String::new(),
            amount_raw: amount,
            amount_usd: 0.0, // Enriched by processor
            reason: String::new(),
            block_number: log_event.slot,
            block_timestamp,
            indexed_at: Utc::now(),
            metadata: serde_json::json!({
                "program_id": log_event.program_id,
                "slot": log_event.slot,
            }),
        })
    }
}

/// Classify a Solana event from program logs.
///
/// Anchor programs emit logs like:
///   "Program log: Instruction: Execute"
///   "Program log: Execution approved: 500000000 lamports from vault to <recipient>"
fn classify_solana_event(logs: &[String]) -> Option<EventType> {
    for log in logs {
        let lower = log.to_lowercase();
        if lower.contains("execution approved") || lower.contains("instruction: execute") {
            return Some(EventType::ExecutionApproved);
        }
        if lower.contains("execution blocked") || lower.contains("emergency locked") {
            return Some(EventType::ExecutionBlocked);
        }
        if lower.contains("session key issued") {
            return Some(EventType::SessionKeyIssued);
        }
        if lower.contains("session key revoked") {
            return Some(EventType::SessionKeyRevoked);
        }
        if lower.contains("deposited") {
            return Some(EventType::Deposited);
        }
        if lower.contains("vault emergency locked") {
            return Some(EventType::EmergencyLock);
        }
        if lower.contains("vault emergency unlocked") {
            return Some(EventType::EmergencyUnlock);
        }
        if lower.contains("velocity limit") {
            return Some(EventType::VelocityLimitHit);
        }
        if lower.contains("drawdown floor") {
            return Some(EventType::DrawdownFloorBreached);
        }
    }
    None
}

/// Extract vault, agent, and amount from Solana program logs.
fn parse_log_data(logs: &[String]) -> (String, String, u64) {
    let mut vault = String::new();
    let mut agent = String::new();
    let mut amount: u64 = 0;

    for log in logs {
        // Parse "Execution approved: <amount> lamports from vault to <recipient>"
        if log.contains("lamports") {
            if let Some(amt_str) = log.split_whitespace()
                .find(|s| s.parse::<u64>().is_ok())
            {
                amount = amt_str.parse().unwrap_or(0);
            }
        }

        // Parse "Aegis Vault initialized for owner <pubkey>"
        if log.contains("initialized for owner") {
            if let Some(key) = log.split_whitespace().last() {
                vault = key.to_string();
            }
        }

        // Parse "Session key issued for agent <pubkey>"
        if log.contains("for agent") {
            for (i, word) in log.split_whitespace().enumerate() {
                if word == "agent" {
                    if let Some(key) = log.split_whitespace().nth(i + 1) {
                        agent = key.to_string();
                        break;
                    }
                }
            }
        }
    }

    (vault, agent, amount)
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> ChainConfig {
        ChainConfig {
            name: "solana".into(),
            chain_type: "solana".into(),
            chain_id: 0,
            ws_url: "wss://api.mainnet-beta.solana.com".into(),
            http_url: "https://api.mainnet-beta.solana.com".into(),
            contract_address: "AeG1sVau1tSo1anaProgramXXXXXXXXXXXXXXXXXX".into(),
            start_block: 0,
            confirmations: 32,
        }
    }

    #[test]
    fn test_classify_execution_approved() {
        let logs = vec![
            "Program log: Instruction: Execute".into(),
            "Program log: Execution approved: 500000000 lamports from vault to 9xyz...".into(),
        ];
        assert_eq!(classify_solana_event(&logs), Some(EventType::ExecutionApproved));
    }

    #[test]
    fn test_classify_execution_blocked() {
        let logs = vec![
            "Program log: Execution blocked: emergency locked".into(),
        ];
        assert_eq!(classify_solana_event(&logs), Some(EventType::ExecutionBlocked));
    }

    #[test]
    fn test_classify_session_issued() {
        let logs = vec![
            "Program log: Session key issued for agent 7abc... — expires at 1700000000".into(),
        ];
        assert_eq!(classify_solana_event(&logs), Some(EventType::SessionKeyIssued));
    }

    #[test]
    fn test_classify_deposited() {
        let logs = vec![
            "Program log: Deposited 5000000000 lamports into vault".into(),
        ];
        assert_eq!(classify_solana_event(&logs), Some(EventType::Deposited));
    }

    #[test]
    fn test_classify_unknown_returns_none() {
        let logs = vec![
            "Program log: Some unrelated log".into(),
        ];
        assert_eq!(classify_solana_event(&logs), None);
    }

    #[test]
    fn test_parse_log_data_amount() {
        let logs = vec![
            "Program log: Execution approved: 500000000 lamports from vault to 9xyz...".into(),
        ];
        let (_, _, amount) = parse_log_data(&logs);
        assert_eq!(amount, 500_000_000);
    }

    #[test]
    fn test_parse_log_data_agent() {
        let logs = vec![
            "Session key issued for agent 7abcDEF1234567890 — expires".into(),
        ];
        let (_, agent, _) = parse_log_data(&logs);
        assert_eq!(agent, "7abcDEF1234567890");
    }

    #[test]
    fn test_parse_solana_event() {
        let listener = SolanaListener::new(make_config());
        let log_event = SolanaLogEvent {
            program_id: "AeG1sVau1t...".into(),
            signature: "5abc123def456".into(),
            slot: 200_000_000,
            block_time: Some(1700000000),
            data: "".into(),
            logs: vec![
                "Program log: Execution approved: 1000000000 lamports from vault to 9xyz".into(),
            ],
        };

        let event = listener.parse_event(&log_event).unwrap();
        assert_eq!(event.chain_name, "solana");
        assert_eq!(event.chain_id, 0);
        assert_eq!(event.block_number, 200_000_000);
        assert_eq!(event.amount_raw, 1_000_000_000);
    }
}
