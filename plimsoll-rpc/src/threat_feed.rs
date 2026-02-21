//! Engine 0: Global Bloom Filter — The Swarm's Immune System.
//!
//! Every Plimsoll proxy maintains a local Compressed Bloom Filter containing
//! confirmed attacker addresses, malicious calldata selectors, and drainer
//! contract hashes. This filter is streamed from the Plimsoll Cloud via
//! WebSocket and updated in real-time.
//!
//! ## Architecture
//!
//! ```text
//! Plimsoll Cloud (compiles Sybil consensus)
//!       │
//!       ▼ WebSocket push
//! ┌─────────────────────────────────┐
//! │  Local Bloom Filter (Engine 0)  │ ← O(1) sub-ms lookup
//! │  - Attacker addresses           │
//! │  - Malicious selectors          │
//! │  - Drainer contract hashes      │
//! └─────────────────────────────────┘
//!       │
//!       ▼ Pre-flight check (before Engine 1-6)
//!   BLOCK or PASS
//! ```
//!
//! ## Anti-Griefing Heuristics
//!
//! The Swarm cannot be weaponized to blacklist legitimate protocols:
//! - Flagged addresses are cross-referenced against on-chain TVL + contract age
//! - Verified contracts with >$1M TVL and >6 months age are IMMUNE
//! - Only newly deployed, unverified, or low-reputation addresses can be blacklisted
//! - Minimum consensus threshold: 5+ independent agents must flag within 10 minutes

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use tracing::warn;

/// Compressed Bloom Filter for O(1) threat lookups.
///
/// In production, this would be a proper Bloom filter with configurable
/// false-positive rate (e.g., 0.01%). For the initial implementation,
/// we use a HashSet (zero false positives, slightly more memory) that
/// gets replaced by a proper Bloom filter when the dataset grows.
#[derive(Debug, Clone)]
pub struct ThreatFilter {
    /// Blacklisted addresses (lowercase, with 0x prefix)
    addresses: HashSet<String>,
    /// Blacklisted function selectors (4-byte hex, e.g., "0xa9059cbb")
    selectors: HashSet<String>,
    /// Blacklisted calldata hashes
    calldata_hashes: HashSet<String>,
    /// Filter version (incremented on each Cloud push)
    pub version: u64,
    /// Number of contributing agents for this version
    pub consensus_count: u64,
    /// Timestamp of last update
    pub last_updated: u64,
}

impl ThreatFilter {
    pub fn new() -> Self {
        Self {
            addresses: HashSet::new(),
            selectors: HashSet::new(),
            calldata_hashes: HashSet::new(),
            version: 0,
            consensus_count: 0,
            last_updated: 0,
        }
    }

    /// Check if a target address is globally blacklisted.
    /// O(1) lookup.
    pub fn is_address_blacklisted(&self, address: &str) -> bool {
        self.addresses.contains(&address.to_lowercase())
    }

    /// Check if a function selector is globally blacklisted.
    /// O(1) lookup.
    pub fn is_selector_blacklisted(&self, selector: &str) -> bool {
        self.selectors.contains(&selector.to_lowercase())
    }

    /// Check if a calldata hash is globally blacklisted.
    pub fn is_calldata_blacklisted(&self, hash: &str) -> bool {
        self.calldata_hashes.contains(hash)
    }

    /// Full pre-flight check: address OR selector OR calldata.
    /// Returns (is_blocked, reason) tuple.
    pub fn check(&self, address: &str, selector: &str, calldata_hash: &str) -> (bool, String) {
        if self.is_address_blacklisted(address) {
            return (true, format!(
                "ENGINE 0: Address {} is globally blacklisted (Swarm consensus: {} agents, v{})",
                address, self.consensus_count, self.version,
            ));
        }
        if !selector.is_empty() && self.is_selector_blacklisted(selector) {
            return (true, format!(
                "ENGINE 0: Selector {} is globally blacklisted (known drainer signature)",
                selector,
            ));
        }
        if !calldata_hash.is_empty() && self.is_calldata_blacklisted(calldata_hash) {
            return (true, format!(
                "ENGINE 0: Calldata hash {} matches known exploit payload",
                calldata_hash,
            ));
        }
        (false, String::new())
    }

    /// Add a threat to the local filter (called on Cloud push).
    pub fn add_address(&mut self, address: &str) {
        self.addresses.insert(address.to_lowercase());
    }

    pub fn add_selector(&mut self, selector: &str) {
        self.selectors.insert(selector.to_lowercase());
    }

    pub fn add_calldata_hash(&mut self, hash: &str) {
        self.calldata_hashes.insert(hash.to_string());
    }

    /// Replace the entire filter with a Cloud-pushed update.
    pub fn replace_from_cloud(
        &mut self,
        addresses: Vec<String>,
        selectors: Vec<String>,
        calldata_hashes: Vec<String>,
        version: u64,
        consensus_count: u64,
    ) {
        self.addresses = addresses.into_iter().map(|a| a.to_lowercase()).collect();
        self.selectors = selectors.into_iter().map(|s| s.to_lowercase()).collect();
        self.calldata_hashes = calldata_hashes.into_iter().collect();
        self.version = version;
        self.consensus_count = consensus_count;
        self.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Number of entries in the filter.
    pub fn len(&self) -> usize {
        self.addresses.len() + self.selectors.len() + self.calldata_hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Thread-safe global threat filter, shared across all request handlers.
pub type SharedThreatFilter = Arc<RwLock<ThreatFilter>>;

/// Create a new shared threat filter.
pub fn new_shared_filter() -> SharedThreatFilter {
    Arc::new(RwLock::new(ThreatFilter::new()))
}

/// Engine 0 pre-flight check using the shared filter.
///
/// This runs BEFORE Engines 1-6. If the target is in the global blacklist,
/// the transaction drops in sub-millisecond time.
pub fn engine0_check(
    filter: &SharedThreatFilter,
    target: &str,
    data: &[u8],
) -> (bool, String) {
    let selector = if data.len() >= 4 {
        format!("0x{}", hex::encode(&data[..4]))
    } else {
        String::new()
    };

    // Hash calldata for lookup
    let calldata_hash = {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in data {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        format!("{:016x}", h)
    };

    match filter.read() {
        Ok(f) => {
            if f.is_empty() {
                return (false, String::new()); // No filter loaded yet
            }
            f.check(target, &selector, &calldata_hash)
        }
        Err(_) => {
            warn!("Threat filter lock poisoned — failing open");
            (false, String::new())
        }
    }
}

/// Zero-Day 4: Validate an incoming IOC submission for Sybil resistance.
///
/// Returns (accepted, reason). An IOC is rejected if:
/// - The submitting agent's vault TVL is below $5,000
/// - The stake weight is 0 (no skin in the game)
///
/// Accepted IOCs are weighted by TVL in the Swarm consensus:
/// - $5K TVL agent's vote counts 0.05
/// - $100K+ TVL agent's vote counts 1.0
pub fn validate_ioc_submission(vault_tvl_usd: f64, stake_weight: f64) -> (bool, String) {
    const MIN_TVL: f64 = 5_000.0;

    if vault_tvl_usd < MIN_TVL {
        return (false, format!(
            "ZERO-DAY 4: IOC rejected — agent TVL ${:.0} < minimum ${:.0}. \
             Sybil resistance requires skin in the game.",
            vault_tvl_usd, MIN_TVL,
        ));
    }

    if stake_weight <= 0.0 {
        return (false, format!(
            "ZERO-DAY 4: IOC rejected — stake weight {:.4} is zero or negative.",
            stake_weight,
        ));
    }

    (true, format!(
        "IOC accepted with stake weight {:.4} (TVL ${:.0})",
        stake_weight, vault_tvl_usd,
    ))
}

/// Anti-Griefing Heuristic: determines if an address is immune to blacklisting.
///
/// In production, this queries on-chain data (TVL, contract age, verification status)
/// via Alchemy/DefiLlama APIs. Addresses that are:
/// - Verified contracts with >$1M TVL
/// - Deployed >6 months ago
/// - Used by >1000 unique addresses
/// ... are IMMUNE to Swarm blacklisting (anti-griefing).
pub struct AntiGriefing;

impl AntiGriefing {
    /// Well-known protocol addresses that are ALWAYS immune.
    const IMMUNE_PROTOCOLS: &'static [&'static str] = &[
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2 Router
        "0xe592427a0aece92de3edee1f18e0157c05861564", // Uniswap V3 Router
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45", // Uniswap Universal Router
        "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2", // Aave V3 Pool
        "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9", // Aave V2 Pool
        "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b", // Compound Comptroller
        "0xdef1c0ded9bec7f1a1670819833240f027b25eff", // 0x Exchange Proxy
        "0x1111111254eeb25477b68fb85ed929f73a960582", // 1inch Router
        "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f", // SushiSwap Router
    ];

    /// Check if an address is immune to Swarm blacklisting.
    pub fn is_immune(address: &str) -> bool {
        let addr_lower = address.to_lowercase();
        Self::IMMUNE_PROTOCOLS.iter().any(|p| *p == addr_lower)
    }

    /// Validate a proposed blacklist entry against anti-griefing rules.
    /// Returns (should_add, reason).
    pub fn validate_blacklist_entry(address: &str) -> (bool, String) {
        if Self::is_immune(address) {
            return (false, format!(
                "ANTI-GRIEF: {} is a verified protocol (immune to blacklisting)",
                address,
            ));
        }
        // In production: query on-chain TVL, age, verification status
        // For now: all non-immune addresses are candidates
        (true, "Address eligible for blacklisting".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_filter_allows_all() {
        let filter = new_shared_filter();
        let (blocked, _) = engine0_check(&filter, "0xAnything", &[0xa9, 0x05, 0x9c, 0xbb]);
        assert!(!blocked);
    }

    #[test]
    fn test_blacklisted_address_blocked() {
        let filter = new_shared_filter();
        {
            let mut f = filter.write().unwrap();
            f.add_address("0xHacker123");
            f.version = 1;
            f.consensus_count = 12;
        }
        let (blocked, reason) = engine0_check(&filter, "0xhacker123", &[]);
        assert!(blocked);
        assert!(reason.contains("globally blacklisted"));
        assert!(reason.contains("12 agents"));
    }

    #[test]
    fn test_blacklisted_selector_blocked() {
        let filter = new_shared_filter();
        {
            let mut f = filter.write().unwrap();
            f.add_selector("0xdeadbeef");
            f.version = 2;
        }
        let (blocked, reason) = engine0_check(&filter, "0xSafe", &[0xde, 0xad, 0xbe, 0xef, 0x00]);
        assert!(blocked);
        assert!(reason.contains("known drainer signature"));
    }

    #[test]
    fn test_clean_tx_passes() {
        let filter = new_shared_filter();
        {
            let mut f = filter.write().unwrap();
            f.add_address("0xBadGuy");
            f.version = 1;
        }
        let (blocked, _) = engine0_check(&filter, "0xGoodGuy", &[0x01, 0x02, 0x03, 0x04]);
        assert!(!blocked);
    }

    #[test]
    fn test_replace_from_cloud() {
        let filter = new_shared_filter();
        {
            let mut f = filter.write().unwrap();
            f.add_address("0xOldThreat");
        }
        {
            let mut f = filter.write().unwrap();
            f.replace_from_cloud(
                vec!["0xNewThreat1".to_string(), "0xNewThreat2".to_string()],
                vec![],
                vec![],
                42,
                100,
            );
        }
        // Old threat is gone
        let (b1, _) = engine0_check(&filter, "0xoldthreat", &[]);
        assert!(!b1);
        // New threats are active
        let (b2, _) = engine0_check(&filter, "0xnewthreat1", &[]);
        assert!(b2);
        let f = filter.read().unwrap();
        assert_eq!(f.version, 42);
        assert_eq!(f.consensus_count, 100);
    }

    #[test]
    fn test_anti_griefing_uniswap_immune() {
        assert!(AntiGriefing::is_immune(
            "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        ));
        let (should_add, reason) = AntiGriefing::validate_blacklist_entry(
            "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        );
        assert!(!should_add);
        assert!(reason.contains("immune"));
    }

    #[test]
    fn test_anti_griefing_unknown_address_eligible() {
        let (should_add, _) = AntiGriefing::validate_blacklist_entry("0xNewDrainer123");
        assert!(should_add);
    }

    #[test]
    fn test_filter_len() {
        let mut f = ThreatFilter::new();
        assert!(f.is_empty());
        f.add_address("0xa");
        f.add_selector("0xb");
        f.add_calldata_hash("c");
        assert_eq!(f.len(), 3);
    }

    // ── Zero-Day 4: Sybil Telemetry Poisoning Tests ─────────────

    #[test]
    fn test_ioc_submission_rejected_low_tvl() {
        let (accepted, reason) = validate_ioc_submission(1_000.0, 0.01);
        assert!(!accepted);
        assert!(reason.contains("ZERO-DAY 4"));
        assert!(reason.contains("Sybil resistance"));
    }

    #[test]
    fn test_ioc_submission_rejected_zero_tvl() {
        let (accepted, _) = validate_ioc_submission(0.0, 0.0);
        assert!(!accepted);
    }

    #[test]
    fn test_ioc_submission_accepted_sufficient_tvl() {
        let (accepted, reason) = validate_ioc_submission(10_000.0, 0.1);
        assert!(accepted);
        assert!(reason.contains("stake weight"));
    }

    #[test]
    fn test_ioc_submission_accepted_high_tvl() {
        let (accepted, reason) = validate_ioc_submission(500_000.0, 1.0);
        assert!(accepted);
        assert!(reason.contains("1.0000"));
    }

    #[test]
    fn test_ioc_submission_rejected_zero_stake_weight() {
        let (accepted, reason) = validate_ioc_submission(6_000.0, 0.0);
        assert!(!accepted);
        assert!(reason.contains("zero or negative"));
    }
}
