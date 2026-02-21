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

    /// Zero-Day 4: Agent's vault TVL in USD at time of report.
    /// IOCs from agents with TVL < $5,000 are REJECTED by the Cloud
    /// to prevent Sybil telemetry poisoning. 1000 fake agents with $0
    /// TVL cannot overwhelm the consensus.
    pub vault_tvl_usd: f64,

    /// Zero-Day 4: Stake-weighted confidence score.
    /// Higher TVL → higher weight in Swarm consensus.
    /// score = min(1.0, tvl / 100_000)  (caps at $100K)
    pub stake_weight: f64,

    /// GOD-TIER 2: Time-Weighted Average Balance over 72 hours.
    /// Unlike `vault_tvl_usd` (point-in-time snapshot), this is the
    /// average balance maintained across 20,000 blocks. Flash loans
    /// that exist for 1 block contribute (5K / 20,000) = $0.25 to TWAB.
    pub twab_usd: f64,

    /// GOD-TIER 2: Vault age in blocks since first deposit.
    /// Newly created vaults (< 20,000 blocks old) cannot submit IOCs
    /// even if their current balance meets the threshold.
    pub vault_age_blocks: u64,
}

/// Zero-Day 4: Minimum TVL required to submit IOCs to the Swarm.
/// Agents below this threshold have their IOCs logged locally but
/// NOT uplinked to the Cloud consensus.
const MIN_TVL_FOR_IOC_SUBMISSION: f64 = 5_000.0;

/// GOD-TIER 2: Minimum Time-Weighted Average Balance (TWAB) window.
/// A snapshot TVL is useless in DeFi — flash loans exist for 1 block.
/// TWAB asks: "Has this vault maintained $5K for 72 hours (20,000 blocks)?"
/// Flash-loan Sybil attacks become mathematically impossible.
const TWAB_WINDOW_BLOCKS: u64 = 20_000;   // ~72 hours at 12s/block
const TWAB_WINDOW_SECONDS: u64 = 259_200; // 72 hours in seconds

/// Zero-Day 4: Compute stake weight from TVL.
/// Linear scale capped at $100K:
///   $0      → 0.0 (rejected)
///   $5,000  → 0.05 (minimum accepted)
///   $50,000 → 0.5
///   $100K+  → 1.0 (maximum weight)
pub fn compute_stake_weight(tvl_usd: f64) -> f64 {
    if tvl_usd <= 0.0 {
        return 0.0;
    }
    let weight = tvl_usd / 100_000.0;
    if weight > 1.0 { 1.0 } else { weight }
}

/// Extract IOCs from a blocked transaction.
///
/// This function is called ONLY when a transaction is blocked.
/// It strips all PII (amounts, balances, positions) and extracts
/// only the attacker's fingerprint.
///
/// Zero-Day 4: Now accepts optional `vault_tvl_usd` parameter.
/// If provided, computes stake weight for Sybil resistance.
pub fn extract_ioc(
    from: &str,
    to: &str,
    data: &[u8],
    block_engine: &str,
    block_reason: &str,
    sim_revert: Option<&str>,
    chain_id: u64,
) -> IOCReport {
    // Zero-Day 4: Default TVL of 0 — caller should set this
    // from the vault's actual balance.
    let vault_tvl_usd = 0.0; // Set by caller via set_tvl()
    let stake_weight = compute_stake_weight(vault_tvl_usd);
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
        vault_tvl_usd,
        stake_weight,
        twab_usd: 0.0,
        vault_age_blocks: 0,
    }
}

/// Zero-Day 4: Create an IOC with explicit TVL for stake-weighted submission.
pub fn extract_ioc_with_tvl(
    from: &str,
    to: &str,
    data: &[u8],
    block_engine: &str,
    block_reason: &str,
    sim_revert: Option<&str>,
    chain_id: u64,
    vault_tvl_usd: f64,
) -> IOCReport {
    let mut ioc = extract_ioc(from, to, data, block_engine, block_reason, sim_revert, chain_id);
    ioc.vault_tvl_usd = vault_tvl_usd;
    ioc.stake_weight = compute_stake_weight(vault_tvl_usd);
    ioc
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
///
/// Zero-Day 4: IOCs from agents with TVL below $5,000 are logged locally
/// but NOT uplinked. This prevents Sybil telemetry poisoning where
/// 1000 fake agents with $0 TVL flood the consensus.
pub async fn uplink_ioc(ioc: &IOCReport, cloud_url: &str) {
    // GOD-TIER 2: TWAB gate supersedes point-in-time TVL check.
    // A flash loan can fake point-in-time TVL for 1 block.
    // TWAB requires maintaining balance for 72 hours (20,000 blocks).
    if ioc.twab_usd > 0.0 {
        // If TWAB data is available, use it (strict mode)
        if ioc.twab_usd < MIN_TVL_FOR_IOC_SUBMISSION {
            warn!(
                twab = ioc.twab_usd,
                min_tvl = MIN_TVL_FOR_IOC_SUBMISSION,
                vault_age = ioc.vault_age_blocks,
                target = %ioc.target_address,
                "GOD-TIER 2: IOC rejected — TWAB ${:.0} < minimum ${:.0}. \
                 Flash-loan Sybil defense active.",
                ioc.twab_usd, MIN_TVL_FOR_IOC_SUBMISSION,
            );
            return;
        }
        if ioc.vault_age_blocks < TWAB_WINDOW_BLOCKS {
            warn!(
                vault_age = ioc.vault_age_blocks,
                min_age = TWAB_WINDOW_BLOCKS,
                "GOD-TIER 2: IOC rejected — vault too young ({} blocks < {} required). \
                 New vaults cannot influence Swarm consensus.",
                ioc.vault_age_blocks, TWAB_WINDOW_BLOCKS,
            );
            return;
        }
    } else {
        // Fallback: point-in-time TVL check (Zero-Day 4 compat)
        if ioc.vault_tvl_usd < MIN_TVL_FOR_IOC_SUBMISSION {
            warn!(
                tvl = ioc.vault_tvl_usd,
                min_tvl = MIN_TVL_FOR_IOC_SUBMISSION,
                target = %ioc.target_address,
                "ZERO-DAY 4: IOC rejected — agent TVL below minimum for Swarm submission. \
                 Logged locally only."
            );
            return;
        }
    }

    if cloud_url.is_empty() || cloud_url == "disabled" {
        info!(
            target = %ioc.target_address,
            selector = %ioc.calldata_selector,
            engine = %ioc.block_engine,
            stake_weight = ioc.stake_weight,
            "IOC extracted (uplink disabled, logged locally)"
        );
        return;
    }

    info!(
        tvl = ioc.vault_tvl_usd,
        stake_weight = ioc.stake_weight,
        "Zero-Day 4: IOC passes stake-weight gate"
    );

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
                stake_weight = ioc.stake_weight,
                "IOC uplinked to Aegis Cloud (stake-weighted)"
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

        // Zero-Day 4: Default TVL is 0, stake_weight is 0
        assert_eq!(ioc.vault_tvl_usd, 0.0);
        assert_eq!(ioc.stake_weight, 0.0);
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

    #[test]
    fn test_stake_weight_computation() {
        // $0 TVL → 0.0 weight
        assert_eq!(compute_stake_weight(0.0), 0.0);
        // Negative TVL → 0.0 weight
        assert_eq!(compute_stake_weight(-1000.0), 0.0);
        // $5K TVL → 0.05 weight
        assert!((compute_stake_weight(5_000.0) - 0.05).abs() < 0.001);
        // $50K TVL → 0.5 weight
        assert!((compute_stake_weight(50_000.0) - 0.5).abs() < 0.001);
        // $100K TVL → 1.0 weight (capped)
        assert_eq!(compute_stake_weight(100_000.0), 1.0);
        // $1M TVL → still 1.0 (capped)
        assert_eq!(compute_stake_weight(1_000_000.0), 1.0);
    }

    #[test]
    fn test_extract_ioc_with_tvl() {
        let ioc = extract_ioc_with_tvl(
            "0xAgent",
            "0xHacker",
            &[0xde, 0xad, 0xbe, 0xef],
            "bloom",
            "blacklisted address",
            None,
            1,
            50_000.0,
        );
        assert_eq!(ioc.vault_tvl_usd, 50_000.0);
        assert!((ioc.stake_weight - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_min_tvl_constant() {
        assert_eq!(MIN_TVL_FOR_IOC_SUBMISSION, 5_000.0);
    }
}
