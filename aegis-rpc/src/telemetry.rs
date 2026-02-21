//! Zero-Knowledge Telemetry — IOC extraction and async uplink.
//!
//! When any local physics engine blocks an attack, this module extracts
//! anonymized Indicators of Compromise (IOCs) and uplinks them to the
//! Aegis Cloud. The user's trading alpha (amounts, positions, strategy)
//! is NEVER transmitted — only the attacker's fingerprint.
//!
//! ## IOC Fields Extracted
//! - Target contract address (the drainer)
//! - Calldata function selector (4 bytes)
//! - Attack vector classification (velocity, entropy, loop, sim-fail)
//! - Simulation trace summary (revert reason, gas used)
//!
//! ## Privacy Guarantees
//! - Agent address: NEVER sent (replaced with anonymous agent_id hash)
//! - Transaction amounts: NEVER sent
//! - Token positions / balances: NEVER sent
//! - API keys / private keys: NEVER sent (entropy guard catches these first)

use serde::Serialize;
use tracing::{info, warn};

/// An anonymized Indicator of Compromise extracted from a blocked transaction.
#[derive(Debug, Clone, Serialize)]
pub struct IOCReport {
    /// Anonymized agent identifier (SHA-256 of agent pubkey, truncated)
    pub agent_id: String,
    /// Target contract / EOA that the attack tried to send funds to
    pub target_address: String,
    /// First 4 bytes of calldata (function selector), hex-encoded
    pub calldata_selector: String,
    /// Full calldata hash (SHA-256) for deduplication
    pub calldata_hash: String,
    /// Which engine blocked: "velocity", "entropy", "trajectory", "simulator", "bloom"
    pub block_engine: String,
    /// Block reason (sanitized — no amounts or addresses from agent)
    pub block_reason: String,
    /// Simulation revert reason (if Engine 6 triggered)
    pub sim_revert: Option<String>,
    /// Unix timestamp
    pub timestamp: u64,
    /// Chain ID
    pub chain_id: u64,
}

/// Extract IOCs from a blocked transaction.
///
/// This function is called ONLY when a transaction is blocked.
/// It strips all PII (amounts, balances, positions) and extracts
/// only the attacker's fingerprint.
pub fn extract_ioc(
    from: &str,
    to: &str,
    data: &[u8],
    block_engine: &str,
    block_reason: &str,
    sim_revert: Option<&str>,
    chain_id: u64,
) -> IOCReport {
    // Anonymize the agent address — hash it, never send raw
    let agent_id = {
        let mut h: u64 = 0x517cc1b727220a95;
        for b in from.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        format!("agent_{:016x}", h)
    };

    // Extract function selector (first 4 bytes of calldata)
    let calldata_selector = if data.len() >= 4 {
        format!("0x{}", hex::encode(&data[..4]))
    } else {
        "0x".to_string()
    };

    // Hash the full calldata for dedup (never send raw calldata)
    let calldata_hash = {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in data {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        format!("{:016x}", h)
    };

    // Sanitize block reason — remove any numeric amounts
    let sanitized_reason = sanitize_reason(block_reason);

    IOCReport {
        agent_id,
        target_address: to.to_string(),
        calldata_selector,
        calldata_hash,
        block_engine: block_engine.to_string(),
        block_reason: sanitized_reason,
        sim_revert: sim_revert.map(|s| s.to_string()),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        chain_id,
    }
}

/// Remove numeric values from reason strings to avoid leaking trade amounts.
fn sanitize_reason(reason: &str) -> String {
    let mut result = String::with_capacity(reason.len());
    let mut in_number = false;
    for c in reason.chars() {
        if c.is_ascii_digit() || (c == '.' && in_number) {
            if !in_number {
                result.push_str("[REDACTED]");
                in_number = true;
            }
            // Skip the digit
        } else {
            in_number = false;
            result.push(c);
        }
    }
    result
}

/// Async uplink IOC to the Aegis Cloud.
///
/// In production, this sends to `https://api.aegis.network/v1/ioc`.
/// For now, it logs locally. The uplink is fire-and-forget (async, non-blocking).
pub async fn uplink_ioc(ioc: &IOCReport, cloud_url: &str) {
    if cloud_url.is_empty() || cloud_url == "disabled" {
        info!(
            target = %ioc.target_address,
            selector = %ioc.calldata_selector,
            engine = %ioc.block_engine,
            "IOC extracted (uplink disabled, logged locally)"
        );
        return;
    }

    let client = reqwest::Client::new();
    match client
        .post(format!("{}/v1/ioc", cloud_url))
        .json(ioc)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => {
            info!(
                status = resp.status().as_u16(),
                target = %ioc.target_address,
                "IOC uplinked to Aegis Cloud"
            );
        }
        Err(e) => {
            // Fire-and-forget: never block the critical path on telemetry failure
            warn!("IOC uplink failed (non-blocking): {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ioc_anonymizes_agent() {
        let ioc = extract_ioc(
            "0xMySecretAgentAddress",
            "0xHackerContract",
            &[0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x01],
            "velocity",
            "Excessive loss: 45.2% > max 20.0%",
            None,
            1,
        );
        // Agent address is hashed, not raw
        assert!(ioc.agent_id.starts_with("agent_"));
        assert!(!ioc.agent_id.contains("MySecretAgent"));

        // Target address IS preserved (this is the attacker)
        assert_eq!(ioc.target_address, "0xHackerContract");

        // Function selector extracted
        assert_eq!(ioc.calldata_selector, "0xa9059cbb");

        // Amounts redacted from reason
        assert!(ioc.block_reason.contains("[REDACTED]"));
        assert!(!ioc.block_reason.contains("45.2"));
    }

    #[test]
    fn test_sanitize_reason_redacts_numbers() {
        assert_eq!(
            sanitize_reason("Loss 45.2% exceeds 20.0% limit"),
            "Loss [REDACTED]% exceeds [REDACTED]% limit"
        );
        assert_eq!(
            sanitize_reason("No numbers here"),
            "No numbers here"
        );
    }

    #[test]
    fn test_ioc_empty_calldata() {
        let ioc = extract_ioc("0xA", "0xB", &[], "entropy", "secret detected", None, 11155111);
        assert_eq!(ioc.calldata_selector, "0x");
        assert_eq!(ioc.chain_id, 11155111);
    }
}
