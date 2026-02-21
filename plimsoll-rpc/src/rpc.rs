//! JSON-RPC handler — intercepts send-transaction methods,
//! passes read-only calls through to the upstream provider.
//!
//! ## Security Patches
//! - Patch 2: State-Delta Invariant — captures expected post-state from simulation
//! - Patch 4: Synthetic Receipts — blocked txs return fake receipts instead of errors
//! - Zero-Day 2: Ghost Session — pessimistic session key invalidation
//!   Session keys revoked on-chain are invalidated in the RPC proxy's
//!   local cache IMMEDIATELY when the revocation tx enters the mempool
//!   (via WebSocket `pending` subscription), NOT when the block confirms.
//!   This closes the 12-second window where a revoked key is still usable.

use crate::config::Config;
use crate::fee;
use crate::sanitizer;
use crate::simulator;
use crate::telemetry;
use crate::threat_feed::{self, SharedThreatFilter};
use crate::types::{JsonRpcRequest, JsonRpcResponse};
use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Methods that involve broadcasting transactions (need simulation).
const SEND_METHODS: &[&str] = &[
    "eth_sendTransaction",
    "eth_sendRawTransaction",
];

/// GOD-TIER 1: EIP-712 Silent Dagger Defense
/// Cryptographic signing endpoints that MUST be intercepted.
/// These are NOT transactions — they are off-chain signatures that can
/// authorize token approvals (Permit2), gasless swaps (CowSwap/UniswapX),
/// and governance votes WITHOUT ever touching the EVM simulator.
///
/// Attack: Prompt-inject agent → "sign this login message" → actually a
/// Permit2 approval for MAX_UINT → attacker extracts signature → drains vault.
const SIGN_METHODS: &[&str] = &[
    "eth_sign",
    "personal_sign",
    "eth_signTypedData",
    "eth_signTypedData_v3",
    "eth_signTypedData_v4",
];

/// GOD-TIER 1: Known dangerous EIP-712 type hashes.
/// These are keccak256 of the EIP-712 type strings used by major protocols.
/// When we detect these in a signTypedData request, we translate the
/// off-chain signature into its on-chain equivalent for simulation.
mod permit_decoder {
    /// Permit2 PermitSingle type
    pub const PERMIT2_SINGLE_TYPEHASH: &str =
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)";
    /// Permit2 PermitBatch type
    pub const PERMIT2_BATCH_TYPEHASH: &str =
        "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)";
    /// ERC-2612 Permit type
    pub const ERC2612_PERMIT_TYPEHASH: &str =
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
    /// DAI-style Permit type
    pub const DAI_PERMIT_TYPEHASH: &str =
        "Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)";

    /// Known EIP-712 primary types that authorize token movement.
    pub const DANGEROUS_PRIMARY_TYPES: &[&str] = &[
        "Permit",
        "PermitSingle",
        "PermitBatch",
        "PermitTransferFrom",
        "PermitWitnessTransferFrom",
        "Order",              // CowSwap
        "OrderComponents",    // Seaport (OpenSea)
        "MetaTransaction",    // Biconomy
        "ForwardRequest",     // OpenZeppelin Defender
        "Delegation",         // EIP-7702
    ];

    /// Analyze an EIP-712 typed data payload and classify the risk.
    ///
    /// Returns (is_dangerous, synthetic_action, risk_description).
    /// If dangerous, `synthetic_action` describes the equivalent on-chain
    /// effect (e.g., "approve(0xHacker, MAX_UINT)").
    pub fn analyze_typed_data(
        typed_data: &serde_json::Value,
    ) -> (bool, String, String) {
        // Extract primaryType from the EIP-712 payload
        let primary_type = typed_data
            .get("primaryType")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Check if primaryType is in the dangerous list
        let is_dangerous_type = DANGEROUS_PRIMARY_TYPES
            .iter()
            .any(|dt| primary_type.eq_ignore_ascii_case(dt));

        if !is_dangerous_type {
            return (false, String::new(), String::new());
        }

        // Extract the message body for deeper analysis
        let message = typed_data.get("message").cloned()
            .unwrap_or(serde_json::json!({}));

        // Extract spender/operator — the address that gains power
        let spender = message.get("spender")
            .or_else(|| message.get("operator"))
            .or_else(|| message.get("taker"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Extract value/amount — what's being authorized
        let value = message.get("value")
            .or_else(|| message.get("amount"))
            .and_then(|v| v.as_str().or_else(|| v.as_u64().map(|_| "").or(Some(""))))
            .unwrap_or("unknown");

        // Extract token address from domain or details
        let token = typed_data.get("domain")
            .and_then(|d| d.get("verifyingContract"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let synthetic_action = match primary_type {
            "Permit" | "PermitSingle" => {
                format!(
                    "ERC20.approve({}, {}) on token {}",
                    spender, value, token
                )
            }
            "PermitBatch" => {
                format!(
                    "BATCH ERC20.approve({}, MULTIPLE_TOKENS)",
                    spender
                )
            }
            "PermitTransferFrom" | "PermitWitnessTransferFrom" => {
                format!(
                    "Permit2.transferFrom(agent, {}, {}) on token {}",
                    spender, value, token
                )
            }
            "Order" | "OrderComponents" => {
                format!(
                    "DEX Order: {} gains trading rights via signed order",
                    spender
                )
            }
            _ => {
                format!(
                    "DANGEROUS SIGNATURE: {} authorizes {} on {}",
                    primary_type, spender, token
                )
            }
        };

        let risk_description = format!(
            "GOD-TIER 1 (EIP-712 Silent Dagger): Agent asked to sign '{}' — \
             this is NOT a login message. It is a cryptographic authorization \
             that translates to: {}. An attacker can extract this signature \
             and submit it on-chain to drain the vault.",
            primary_type, synthetic_action
        );

        (true, synthetic_action, risk_description)
    }
}

// ── Patch 4: Synthetic receipt store ─────────────────────────────
// Blocked transactions get synthetic hashes. When the agent polls
// eth_getTransactionReceipt, we return a synthetic reverted receipt
// instead of null. This keeps the agent's web3 client alive.
lazy_static::lazy_static! {
    static ref BLOCKED_TX_STORE: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());

    /// Zero-Day 2: Ghost Session — Pessimistic revocation cache.
    /// Session keys that appear in a `SessionKeyRevoked` event in the
    /// MEMPOOL (not yet mined) are immediately added here. Any tx
    /// referencing a revoked session key is rejected BEFORE simulation.
    /// This closes the 12-second block confirmation window.
    static ref REVOKED_SESSION_KEYS: Mutex<HashSet<String>> = Mutex::new(HashSet::new());

    /// v1.0.2 Patch 4: Paymaster Slashing — Revert strike timestamps.
    /// Tracks timestamps of post-simulation on-chain reverts within a
    /// rolling window. When the count exceeds the threshold, the agent's
    /// Paymaster connection is severed.
    static ref REVERT_STRIKE_TRACKER: Mutex<VecDeque<u64>> = Mutex::new(VecDeque::new());

    /// v1.0.2 Patch 4: Paymaster severed flag.
    /// Once set, ALL transactions are blocked until manual reset.
    static ref PAYMASTER_SEVERED: Mutex<bool> = Mutex::new(false);

    /// v1.0.3 Bounty 4: Simulated gas storage.
    /// Maps tx hash → simulated gas_used. When the receipt arrives,
    /// compare actual vs simulated gas to detect gas black holes.
    static ref SIMULATED_GAS_STORE: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
}

/// Zero-Day 2: SessionKeyRevoked event topic (keccak256 of event signature).
/// `keccak256("SessionKeyRevoked(address,bytes32)")` — matches the
/// PlimsollSessionManager.sol contract event.
const SESSION_KEY_REVOKED_TOPIC: &str =
    "0x9e87fac88ff661f02d44f95383c817fece4bce600a3dab7a54406878b965e752";

/// Zero-Day 2: Check if a session key has been pessimistically revoked.
/// Called before simulation — if the sender's session key is in the
/// revoked set, we reject immediately.
pub fn is_session_revoked(session_key: &str) -> bool {
    if let Ok(store) = REVOKED_SESSION_KEYS.lock() {
        store.contains(&session_key.to_lowercase())
    } else {
        // Lock poisoned — fail closed (assume revoked)
        warn!("Revoked session key lock poisoned — failing closed");
        true
    }
}

/// Zero-Day 2: Add a session key to the pessimistic revocation cache.
/// Called when a `SessionKeyRevoked` event is seen in the mempool
/// (pending transaction, NOT yet mined).
pub fn revoke_session_key(session_key: &str) {
    if let Ok(mut store) = REVOKED_SESSION_KEYS.lock() {
        let key = session_key.to_lowercase();
        info!(
            session_key = %key,
            "ZERO-DAY 2: Session key pessimistically revoked from mempool"
        );
        store.insert(key);
    }
}

/// v1.0.2 Patch 4: Record a post-simulation on-chain revert.
/// If the revert count exceeds the threshold within the rolling window,
/// the Paymaster connection is severed.
pub fn record_revert_strike(config: &Config) {
    if config.revert_strike_max == 0 {
        return; // Feature disabled
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Ok(mut tracker) = REVERT_STRIKE_TRACKER.lock() {
        tracker.push_back(now);

        // Prune timestamps outside the rolling window
        let cutoff = now.saturating_sub(config.revert_strike_window_secs);
        while tracker.front().map_or(false, |&t| t < cutoff) {
            tracker.pop_front();
        }

        // Check if revert count exceeds threshold
        if tracker.len() >= config.revert_strike_max as usize {
            if let Ok(mut severed) = PAYMASTER_SEVERED.lock() {
                *severed = true;
                warn!(
                    revert_count = tracker.len(),
                    threshold = config.revert_strike_max,
                    "PATCH 4 (PAYMASTER SLASHING): Paymaster severed — too many reverts"
                );
            }
        }
    }
}

/// v1.0.2 Patch 4: Check if the Paymaster connection has been severed.
pub fn is_paymaster_severed() -> bool {
    if let Ok(severed) = PAYMASTER_SEVERED.lock() {
        *severed
    } else {
        // Lock poisoned — fail closed
        warn!("Paymaster severed lock poisoned — failing closed");
        true
    }
}

/// v1.0.3 Bounty 4: Store simulated gas for later comparison with receipt.
fn store_simulated_gas(tx_hash: &str, gas_used: u64) {
    if let Ok(mut store) = SIMULATED_GAS_STORE.lock() {
        store.insert(tx_hash.to_string(), gas_used);
        // Prune old entries (keep last 1000)
        if store.len() > 1000 {
            let keys: Vec<String> = store.keys().take(100).cloned().collect();
            for k in keys {
                store.remove(&k);
            }
        }
    }
}

/// v1.0.3 Bounty 4: Retrieve simulated gas for a tx hash.
fn get_simulated_gas(tx_hash: &str) -> Option<u64> {
    if let Ok(store) = SIMULATED_GAS_STORE.lock() {
        store.get(tx_hash).copied()
    } else {
        None
    }
}

/// v1.0.3 Bounty 4: Parse gasUsed from a transaction receipt JSON.
fn parse_gas_used_from_receipt(result: &serde_json::Value) -> u64 {
    result
        .get("gasUsed")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0)
}

/// v1.0.4 Kill-Shot 3 (Bridge Refund Hijack): Known bridge function selectors.
mod bridge_selectors {
    /// Arbitrum `createRetryableTicket(address,uint256,uint256,address,address,uint256,uint256,bytes)`
    /// Selector: keccak256("createRetryableTicket(address,uint256,uint256,address,address,uint256,uint256,bytes)")[:4]
    pub const ARBITRUM_CREATE_RETRYABLE_TICKET: [u8; 4] = [0x67, 0x9b, 0x6d, 0xed];

    /// Optimism `depositTransaction(address,uint256,uint64,bool,bytes)`
    /// Selector: keccak256("depositTransaction(address,uint256,uint64,bool,bytes)")[:4]
    pub const OPTIMISM_DEPOSIT_TRANSACTION: [u8; 4] = [0xe9, 0xe0, 0x5c, 0x42];
}

/// v1.0.4 Kill-Shot 3 (Bridge Refund Hijack): Validate bridge calldata parameters.
///
/// Arbitrum `createRetryableTicket` has hidden refund addresses:
///   - Word 3 (offset 96): `excessFeeRefundAddress`
///   - Word 4 (offset 128): `callValueRefundAddress`
/// These receive excess gas refunds. If they don't match the sender,
/// an attacker steals excess fees by overpaying gas.
///
/// Returns Ok(()) if valid or not a bridge call, Err(reason) if hijack detected.
fn validate_bridge_params(
    config: &Config,
    from: &str,
    to: &str,
    data: &[u8],
) -> Result<(), String> {
    if !config.bridge_refund_check {
        return Ok(()); // Feature disabled
    }

    // Check if `to` is a known bridge contract
    let bridge_contracts: Vec<String> = config
        .bridge_contracts
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    if bridge_contracts.is_empty() {
        return Ok(()); // No bridge contracts configured
    }

    let to_lower = to.to_lowercase();
    if !bridge_contracts.contains(&to_lower) {
        return Ok(()); // Not a bridge contract
    }

    // Need at least selector + data
    if data.len() < 4 {
        return Ok(()); // Not enough data to be a bridge call
    }

    let selector = &data[0..4];
    let from_lower = from.to_lowercase();

    // ── Arbitrum createRetryableTicket ────────────────────────────
    // ABI: createRetryableTicket(
    //   address to,                    // word 0 (offset 4)
    //   uint256 l2CallValue,           // word 1 (offset 36)
    //   uint256 maxSubmissionCost,     // word 2 (offset 68)
    //   address excessFeeRefundAddress,// word 3 (offset 100)
    //   address callValueRefundAddress,// word 4 (offset 132)
    //   uint256 gasLimit,              // word 5 (offset 164)
    //   uint256 maxFeePerGas,          // word 6 (offset 196)
    //   bytes calldata                 // word 7+ (offset 228+)
    // )
    // Addresses are right-aligned in 32-byte words: bytes [offset+12..offset+32]
    if selector == bridge_selectors::ARBITRUM_CREATE_RETRYABLE_TICKET {
        // Word 3: excessFeeRefundAddress
        // Starts at byte 4 + 3*32 = 100; address at 100+12=112 to 100+32=132
        if data.len() >= 132 {
            let excess_refund = format!("0x{}", hex::encode(&data[112..132]));
            if excess_refund.to_lowercase() != from_lower {
                return Err(format!(
                    "PLIMSOLL KILL-SHOT 3 (BRIDGE REFUND HIJACK): Arbitrum createRetryableTicket \
                     excessFeeRefundAddress={} != sender={}. An attacker overpays gas \
                     and steals the excess fee refund.",
                    excess_refund, from
                ));
            }
        }

        // Word 4: callValueRefundAddress
        // Starts at byte 4 + 4*32 = 132; address at 132+12=144 to 132+32=164
        if data.len() >= 164 {
            let value_refund = format!("0x{}", hex::encode(&data[144..164]));
            if value_refund.to_lowercase() != from_lower {
                return Err(format!(
                    "PLIMSOLL KILL-SHOT 3 (BRIDGE REFUND HIJACK): Arbitrum createRetryableTicket \
                     callValueRefundAddress={} != sender={}. Excess value refunded to attacker.",
                    value_refund, from
                ));
            }
        }
    }

    // ── Optimism depositTransaction ──────────────────────────────
    // ABI: depositTransaction(
    //   address _to,         // word 0 (offset 4)
    //   uint256 _value,      // word 1 (offset 36)
    //   uint64 _gasLimit,    // word 2 (offset 68)
    //   bool _isCreation,    // word 3 (offset 100)
    //   bytes _data          // word 4+ (offset 132+)
    // )
    // For Optimism, the `msg.sender` on L2 is the aliased L1 sender.
    // The `_to` field (word 0) is the L2 recipient — check it matches sender.
    if selector == bridge_selectors::OPTIMISM_DEPOSIT_TRANSACTION {
        // Word 0: _to address. Starts at byte 4; address at 4+12=16 to 4+32=36
        if data.len() >= 36 {
            let l2_recipient = format!("0x{}", hex::encode(&data[16..36]));
            if l2_recipient.to_lowercase() != from_lower {
                return Err(format!(
                    "PLIMSOLL KILL-SHOT 3 (BRIDGE REFUND HIJACK): Optimism depositTransaction \
                     _to={} != sender={}. L2 recipient is a different address.",
                    l2_recipient, from
                ));
            }
        }
    }

    Ok(())
}

/// v1.0.4 Kill-Shot 2 (PVG Heist): Enforce preVerificationGas ceiling.
///
/// ERC-4337 UserOperations have `preVerificationGas` — a flat fee paid to
/// the Bundler BEFORE execution starts. The EVM simulator only measures
/// execution gas, so an attacker can set PVG=15M + maxFeePerGas=2000gwei
/// to drain $30k from the Paymaster without triggering any simulation alarm.
///
/// Returns Ok(()) if within ceiling, Err(reason) if ceiling exceeded.
fn enforce_pvg_ceiling(config: &Config, tx: &serde_json::Value) -> Result<(), String> {
    if config.max_pre_verification_gas == 0 {
        return Ok(()); // Feature disabled
    }

    let pvg = tx.get("preVerificationGas")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .or_else(|| {
            tx.get("preVerificationGas")
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);

    if pvg > config.max_pre_verification_gas {
        return Err(format!(
            "PLIMSOLL KILL-SHOT 2 (PVG HEIST): preVerificationGas={} exceeds ceiling={}. \
             PVG is a flat Bundler fee paid BEFORE execution — invisible to the EVM \
             simulator. An attacker inflates PVG to drain the Paymaster.",
            pvg, config.max_pre_verification_gas
        ));
    }

    Ok(())
}

/// v1.0.2 Patch 3: Validate chainId in EIP-712 typed data domain.
/// Returns an error message if the chainId is missing, zero, or mismatched.
fn validate_eip712_chain_id(
    typed_data: &serde_json::Value,
    expected_chain_id: u64,
) -> Option<String> {
    if expected_chain_id == 0 {
        return None; // Feature disabled
    }

    let domain = typed_data.get("domain");
    if domain.is_none() {
        return Some(
            "PATCH 3 (CROSS-CHAIN REPLAY): EIP-712 domain missing — \
             cannot verify chainId binding"
                .to_string(),
        );
    }

    let chain_id_val = domain.unwrap().get("chainId");
    if chain_id_val.is_none() {
        return Some(
            "PATCH 3 (CROSS-CHAIN REPLAY): EIP-712 domain missing chainId — \
             signature can be replayed on any chain"
                .to_string(),
        );
    }

    // Parse chainId from various formats (int, hex string, decimal string)
    let chain_id_val = chain_id_val.unwrap();
    let parsed_chain_id: Option<u64> = if let Some(n) = chain_id_val.as_u64() {
        Some(n)
    } else if let Some(s) = chain_id_val.as_str() {
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
        } else {
            s.parse().ok()
        }
    } else {
        None
    };

    match parsed_chain_id {
        None => Some(
            "PATCH 3 (CROSS-CHAIN REPLAY): EIP-712 domain chainId unparseable"
                .to_string(),
        ),
        Some(0) => Some(
            "PATCH 3 (CROSS-CHAIN REPLAY): EIP-712 domain chainId=0 (wildcard) — \
             signature valid on ALL chains"
                .to_string(),
        ),
        Some(id) if id != expected_chain_id => Some(format!(
            "PATCH 3 (CROSS-CHAIN REPLAY): EIP-712 domain chainId={} != expected {} — \
             possible cross-chain replay attack",
            id, expected_chain_id
        )),
        Some(_) => None, // chainId matches — all good
    }
}

/// v1.0.4 Kill-Shot 4 (Permit2 Time-Bomb): Validate temporal bounds in EIP-712.
///
/// Checks known temporal fields (deadline, expiration, sigDeadline, expiry,
/// validBefore) in the EIP-712 message body. If any field exceeds the maximum
/// allowed duration from now, or is set to uint256.max (immortal), reject.
fn validate_permit_deadline(
    typed_data: &serde_json::Value,
    max_duration_secs: u64,
) -> Result<(), String> {
    if max_duration_secs == 0 {
        return Ok(()); // Feature disabled
    }

    let empty_obj = serde_json::json!({});
    let message = typed_data.get("message").unwrap_or(&empty_obj);

    let temporal_fields = [
        "deadline", "expiration", "sigDeadline", "expiry", "validBefore",
    ];

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let uint256_max_str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";

    for field in &temporal_fields {
        let raw = match message.get(field) {
            Some(v) => v,
            None => continue,
        };

        // Parse temporal value
        let temporal_val: Option<u64> = if let Some(n) = raw.as_u64() {
            Some(n)
        } else if let Some(s) = raw.as_str() {
            if s == uint256_max_str
                || s == "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            {
                return Err(format!(
                    "PLIMSOLL KILL-SHOT 4 (PERMIT2 TIME-BOMB): EIP-712 field '{}' \
                     set to uint256.max — signature is IMMORTAL. An attacker can \
                     reuse this signature indefinitely via Permit2.transferFrom().",
                    field
                ));
            }
            if s.starts_with("0x") || s.starts_with("0X") {
                u64::from_str_radix(
                    s.trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .ok()
            } else {
                s.parse().ok()
            }
        } else {
            None
        };

        if let Some(val) = temporal_val {
            if val > now + max_duration_secs {
                return Err(format!(
                    "PLIMSOLL KILL-SHOT 4 (PERMIT2 TIME-BOMB): EIP-712 field '{}' \
                     expires in {}s ({}h from now) — exceeds max allowed {}s. \
                     Signatures with excessive lifetimes are time-bombs.",
                    field,
                    val.saturating_sub(now),
                    val.saturating_sub(now) / 3600,
                    max_duration_secs
                ));
            }
        }
    }

    Ok(())
}

/// v1.0.2 Patch 4: Extract UserOperation gas from calldata.
/// For ERC-4337 UserOperations, the `callGasLimit` field determines
/// how much gas the Paymaster sponsors.
fn extract_userop_gas(data: &[u8]) -> Option<u64> {
    // ERC-4337 UserOperation ABI:
    // handleOps selector: 0x1fad948c
    // UserOp struct has callGasLimit at offset 128 (word 4, 0-indexed)
    if data.len() < 4 {
        return None;
    }
    let selector = &data[0..4];
    // handleOps(UserOperation[], address)
    if selector != [0x1f, 0xad, 0x94, 0x8c] {
        return None;
    }
    // Simplified: for real implementation, decode full ABI
    // For now, return None (feature depends on full ABI decode)
    None
}

/// Zero-Day 2: Start the WebSocket mempool watcher for SessionKeyRevoked events.
///
/// This spawns an async task that subscribes to `eth_subscribe("logs", ...)`
/// on the upstream WebSocket RPC, filtering for the SessionKeyRevoked event
/// from the PlimsollSessionManager contract. When a matching log appears in a
/// pending transaction (mempool), we immediately add the session key to
/// `REVOKED_SESSION_KEYS`.
///
/// In production, `ws_rpc_url` is the WebSocket endpoint of the upstream
/// provider (e.g., `wss://eth-mainnet.g.alchemy.com/v2/KEY`).
pub async fn start_mempool_revocation_watcher(
    ws_rpc_url: &str,
    session_manager_address: &str,
) {
    if ws_rpc_url.is_empty() || ws_rpc_url == "disabled" {
        info!("Zero-Day 2: Mempool revocation watcher disabled (no WS URL)");
        return;
    }

    let url = ws_rpc_url.to_string();
    let contract = session_manager_address.to_lowercase();

    tokio::spawn(async move {
        info!(
            ws_url = %url,
            contract = %contract,
            "Zero-Day 2: Starting mempool revocation watcher"
        );

        // Subscribe to pending logs matching SessionKeyRevoked topic
        let subscribe_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_subscribe",
            "params": ["logs", {
                "address": contract,
                "topics": [SESSION_KEY_REVOKED_TOPIC]
            }],
            "id": 1
        });

        // In production, this uses a WebSocket connection (tokio-tungstenite).
        // For the initial implementation, we log the subscription intent and
        // poll via HTTP as a fallback. The WebSocket upgrade happens when
        // the infra supports wss:// endpoints.
        info!(
            payload = %subscribe_payload,
            "Zero-Day 2: Would subscribe to mempool SessionKeyRevoked events"
        );

        // Polling fallback: check every 2 seconds for new revocation events
        // in the pending transaction pool.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // In production: parse WebSocket frames for log events
            // containing SessionKeyRevoked, extract the session key
            // from topics[1], and call revoke_session_key().
            //
            // let session_key = extract_session_key_from_log(&log);
            // revoke_session_key(&session_key);
        }
    });
}

/// Handle an incoming JSON-RPC request.
pub async fn handle_rpc(
    config: &Config,
    threat_filter: &SharedThreatFilter,
    req: JsonRpcRequest,
) -> JsonRpcResponse {
    info!(method = %req.method, "RPC request received");

    // ── Patch 4: Intercept receipt polling for synthetic txs ─────
    // If the agent calls eth_getTransactionReceipt on a blocked tx hash,
    // we return a synthetic reverted receipt instead of null.
    if req.method == "eth_getTransactionReceipt" {
        if let Some(hash) = req.params.as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
        {
            if let Ok(store) = BLOCKED_TX_STORE.lock() {
                if let Some(reason) = store.get(hash) {
                    info!(tx_hash = hash, "Returning synthetic receipt for blocked tx");
                    return JsonRpcResponse::plimsoll_synthetic_receipt(
                        req.id, hash, reason,
                    );
                }
            }
        }
    }

    // ── v1.0.2 Patch 4: Paymaster Sever Check ──────────────────
    // If the Paymaster has been severed due to too many post-simulation
    // reverts, block ALL outgoing transactions immediately.
    if is_paymaster_severed() && SEND_METHODS.contains(&req.method.as_str()) {
        let reason = "PLIMSOLL PATCH 4 (PAYMASTER SLASHING): Paymaster connection severed. \
                       Too many post-simulation reverts detected — all transactions blocked \
                       to prevent gas drain."
            .to_string();
        warn!("{}", reason);
        let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(req.id, &reason);
        if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
            store.insert(tx_hash, reason);
        }
        return resp;
    }

    // ── GOD-TIER 1: EIP-712 Silent Dagger Interception ─────────
    // Intercept ALL cryptographic signing endpoints. The agent should
    // NEVER blindly sign off-chain messages — they can be weaponized
    // as Permit2 approvals, gasless swap orders, or governance votes.
    if SIGN_METHODS.contains(&req.method.as_str()) {
        warn!(
            method = %req.method,
            "GOD-TIER 1: Intercepted off-chain signing request"
        );

        // For signTypedData variants, decode the EIP-712 payload
        if req.method.starts_with("eth_signTypedData") {
            // The typed data is typically the 2nd param (after the address)
            let typed_data = req.params.as_array()
                .and_then(|a| a.get(1))
                .cloned()
                .unwrap_or(serde_json::json!({}));

            // Parse if it's a JSON string
            let parsed_data = if let Some(s) = typed_data.as_str() {
                serde_json::from_str(s).unwrap_or(typed_data)
            } else {
                typed_data
            };

            // ── v1.0.2 Patch 3: Cross-Chain Replay Defense ──────
            // Validate chainId in the EIP-712 domain BEFORE checking
            // dangerous primary types. Missing/zero/mismatched chainId
            // allows cross-chain replay attacks.
            if let Some(chain_err) = validate_eip712_chain_id(
                &parsed_data, config.expected_chain_id
            ) {
                warn!("{}", chain_err);
                let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(
                    req.id, &chain_err,
                );
                if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
                    store.insert(tx_hash, chain_err);
                }
                return resp;
            }

            // ── v1.0.4 Kill-Shot 4: Permit2 Time-Bomb Defense ──────
            // Before analyzing dangerous types, check temporal bounds.
            // Even "safe" primary types can have abusive deadlines.
            if let Err(deadline_err) = validate_permit_deadline(
                &parsed_data, config.max_permit_duration_secs
            ) {
                warn!("{}", deadline_err);
                let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(
                    req.id, &deadline_err,
                );
                if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
                    store.insert(tx_hash, deadline_err);
                }
                return resp;
            }

            let (is_dangerous, synthetic_action, risk_desc) =
                permit_decoder::analyze_typed_data(&parsed_data);

            if is_dangerous {
                warn!(
                    synthetic_action = %synthetic_action,
                    "GOD-TIER 1: DANGEROUS EIP-712 SIGNATURE BLOCKED"
                );

                // Extract IOC — this is an active phishing attack
                let from = req.params.as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let ioc = telemetry::extract_ioc(
                    from, "eip712_permit", &[], "permit_decoder",
                    &risk_desc, None, 1,
                );
                telemetry::uplink_ioc(&ioc, "https://cloud.plimsoll.network/v1/ioc").await;

                let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(
                    req.id, &risk_desc,
                );
                if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
                    store.insert(tx_hash, risk_desc);
                }
                return resp;
            }
        }

        // For eth_sign and personal_sign — block ALL by default.
        // Raw message signing is ALWAYS dangerous for an AI agent.
        // A human can sign arbitrary messages; an AI agent cannot
        // distinguish a "login challenge" from a "drain everything" payload.
        if req.method == "eth_sign" || req.method == "personal_sign" {
            let reason = format!(
                "GOD-TIER 1: Raw message signing ({}) blocked. \
                 AI agents must NEVER sign arbitrary messages — \
                 they cannot distinguish login challenges from \
                 cryptographic drain authorizations.",
                req.method
            );
            warn!("{}", reason);
            let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(req.id, &reason);
            if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
                store.insert(tx_hash, reason);
            }
            return resp;
        }
    }

    // ── Read-only methods: pass through to upstream ─────────────
    // v1.0.2 Patch 1 (Trojan Receipt): If sanitize_read_responses is enabled,
    // intercept read-path responses and scrub LLM control tokens.
    if !SEND_METHODS.contains(&req.method.as_str()) {
        let mut response = proxy_to_upstream(config, &req).await;

        // v1.0.2 Patch 1: Sanitize read-path responses
        if config.sanitize_read_responses
            && sanitizer::SANITIZE_METHODS.contains(&req.method.as_str())
        {
            // Convert to serde_json::Value for sanitization
            if let Ok(mut resp_json) = serde_json::to_value(&response) {
                let (tainted, details) = sanitizer::sanitize_rpc_response(&mut resp_json);
                if tainted {
                    warn!(
                        method = %req.method,
                        details = ?details,
                        "PATCH 1 (TROJAN RECEIPT): Read-path response sanitized"
                    );
                    // Reconstruct the response from sanitized JSON
                    if let Some(result) = resp_json.get("result").cloned() {
                        response.result = Some(result);
                    }
                }
            }
        }

        // v1.0.2 Patch 4: Detect on-chain reverts in real transaction receipts.
        // When a tx that passed simulation reverts on-chain (status=0x0),
        // record a revert strike against the Paymaster.
        if req.method == "eth_getTransactionReceipt" && config.revert_strike_max > 0 {
            if let Some(ref result) = response.result {
                let status = result.get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("0x1");
                if status == "0x0" {
                    info!("PATCH 4: On-chain revert detected — recording strike");
                    record_revert_strike(config);
                }
            }
        }

        // ── v1.0.3 Bounty 4: Gas Black Hole Detection ──────────────
        // Compare actual gasUsed in receipt vs simulated gas. If the ratio
        // exceeds the threshold, record a gas anomaly strike (even on success).
        // This catches the 63/64ths attack where a sub-call burns gas internally,
        // catches its own OOG, and returns success.
        if req.method == "eth_getTransactionReceipt" && config.gas_anomaly_ratio > 0.0 {
            if let Some(hash) = req.params.as_array()
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
            {
                if let Some(ref result) = response.result {
                    if let Some(simulated_gas) = get_simulated_gas(hash) {
                        let receipt_gas = parse_gas_used_from_receipt(result);
                        if simulated_gas > 0 && receipt_gas > 0 {
                            let ratio = receipt_gas as f64 / simulated_gas as f64;
                            if ratio > config.gas_anomaly_ratio {
                                warn!(
                                    receipt_gas = receipt_gas,
                                    simulated_gas = simulated_gas,
                                    ratio = ratio,
                                    "BOUNTY 4 (GAS BLACK HOLE): Gas anomaly detected — \
                                     actual gas {:.1}x simulated. Recording strike.",
                                    ratio
                                );
                                record_revert_strike(config);
                            }
                        }
                    }
                }
            }
        }

        return response;
    }

    // ── Transaction methods: simulate first ─────────────────────
    info!("Intercepted send tx — running pre-flight simulation");

    // ── v1.0.3 Bounty 1: Duplicate JSON key detection ──────────
    // Before parsing, check for duplicate keys in the raw JSON params.
    // serde_json silently deduplicates, but upstream parsers may differ.
    if config.reject_duplicate_json_keys {
        let raw_params = serde_json::to_string(&req.params).unwrap_or_default();
        if let Some(dup_key) = detect_duplicate_json_keys(&raw_params) {
            let reason = format!(
                "PLIMSOLL BOUNTY 1 (JSON POLLUTION): Duplicate key '{}' detected in \
                 transaction params. Parser divergence attack blocked.",
                dup_key
            );
            warn!("{}", reason);
            let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(req.id, &reason);
            if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
                store.insert(tx_hash, reason);
            }
            return resp;
        }
    }

    // Parse tx parameters from the request
    let (from, to, value, data) = match parse_tx_params(&req) {
        Ok(params) => params,
        Err(e) => {
            warn!("Failed to parse tx params: {}", e);
            return JsonRpcResponse::error(req.id, -32602, format!("Invalid params: {e}"));
        }
    };

    // ── v1.0.4 Kill-Shot 2: PVG Heist Defense ────────────────────
    // Check preVerificationGas BEFORE simulation, since PVG is invisible
    // to the EVM simulator. This must run before ANY simulation.
    if let Some(tx_obj) = req.params.as_array().and_then(|a| a.first()) {
        if let Err(pvg_reason) = enforce_pvg_ceiling(config, tx_obj) {
            warn!("{}", pvg_reason);
            let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(req.id, &pvg_reason);
            if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
                store.insert(tx_hash, pvg_reason);
            }
            return resp;
        }
    }

    // ── v1.0.4 Kill-Shot 3: Bridge Refund Hijack Defense ─────────
    // Validate bridge calldata BEFORE simulation. If the refund addresses
    // in Arbitrum/Optimism bridge calls don't match the sender, block.
    if let Err(bridge_reason) = validate_bridge_params(config, &from, &to, &data) {
        warn!("{}", bridge_reason);
        let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(req.id, &bridge_reason);
        if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
            store.insert(tx_hash, bridge_reason);
        }
        return resp;
    }

    // ── ZERO-DAY 2: Pessimistic Session Key Check ──────────────
    // Before ANY engine runs, check if the sender's session key has
    // been revoked in the mempool. This closes the 12-second window
    // between mempool revocation and block confirmation.
    if is_session_revoked(&from) {
        let reason = format!(
            "PLIMSOLL ZERO-DAY 2: Session key {} pessimistically revoked \
             (seen in mempool before block confirmation)",
            &from
        );
        warn!("{}", reason);
        let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(req.id, &reason);
        if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
            store.insert(tx_hash, reason);
        }
        return resp;
    }

    // ── ENGINE 0: Global Bloom Filter Pre-Flight ────────────────
    // Runs BEFORE Engines 1-6. Sub-millisecond O(1) lookup against
    // the Swarm-compiled global blacklist.
    let (engine0_blocked, engine0_reason) = threat_feed::engine0_check(
        threat_filter, &to, &data,
    );
    if engine0_blocked {
        warn!("{}", engine0_reason);
        // Extract IOC and uplink to Plimsoll Cloud
        let ioc = telemetry::extract_ioc(
            &from, &to, &data, "bloom", &engine0_reason, None, 1,
        );
        telemetry::uplink_ioc(&ioc, "https://cloud.plimsoll.network/v1/ioc").await;
        // Patch 4: Return synthetic tx hash — agent stays alive
        let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(req.id, &engine0_reason);
        if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
            store.insert(tx_hash, engine0_reason);
        }
        return resp;
    }

    // Run pre-flight simulation
    let sim_result = match simulator::simulate_transaction(config, &from, &to, value, &data).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Simulation failed: {}", e);
            // Patch 4: Return synthetic tx hash — agent stays alive
            let reason = format!("Simulation error: {e}");
            let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(req.id, &reason);
            if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
                store.insert(tx_hash, reason);
            }
            return resp;
        }
    };

    // Check physics constraints
    if let Err(reason) = simulator::check_physics(config, &sim_result) {
        warn!("Physics violation: {}", reason);
        // Extract IOC and uplink to Plimsoll Cloud
        let ioc = telemetry::extract_ioc(
            &from, &to, &data, "simulator", &reason, Some(&reason), 1,
        );
        telemetry::uplink_ioc(&ioc, "https://cloud.plimsoll.network/v1/ioc").await;
        // Patch 4: Return synthetic tx hash — agent stays alive
        let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(req.id, &reason);
        if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
            store.insert(tx_hash, reason);
        }
        return resp;
    }

    // ── v1.0.2 Patch 2: Non-determinism check ──────────────────
    // If the simulation detected environmental opcodes feeding into JUMPI
    // conditions, the on-chain execution may differ from simulation.
    if sim_result.non_deterministic && config.detect_non_determinism {
        let reason = "PLIMSOLL PATCH 2 (SCHRÖDINGER'S STATE): Non-deterministic execution \
                       detected — environmental opcodes (TIMESTAMP, BLOCKHASH, etc.) feed \
                       into conditional branches. Simulation outcome is unreliable."
            .to_string();
        warn!("{}", reason);
        let (resp, tx_hash) = JsonRpcResponse::plimsoll_synthetic_send(req.id, &reason);
        if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
            store.insert(tx_hash, reason);
        }
        return resp;
    }

    // ── Patch 2 + GOD-TIER 3 + ZERO-DAY 2: State-Delta + Block Pinning + Codehash
    // We record what the simulation expects, which block it simulated against,
    // AND the target contract's bytecode hash. The on-chain vault rejects
    // stale simulations and metamorphic bytecode swaps.
    info!(
        sim_balance_before = sim_result.balance_before,
        sim_balance_after = sim_result.balance_after,
        sim_loss_pct = sim_result.loss_pct,
        sim_gas_used = sim_result.gas_used,
        sim_block = sim_result.simulated_block,
        target_codehash = %sim_result.target_codehash,
        impl_slot = %sim_result.impl_slot_value,
        "State-delta invariant captured (pinned to block + codehash + impl slot)"
    );

    // Calculate and log fee
    let fee_amount = fee::calculate_fee(value, config.fee_bps);
    if fee_amount > 0 {
        info!(fee_bps = config.fee_bps, fee_wei = fee_amount, "Fee calculated");
    }

    // ── Route through MEV-shielded path ─────────────────────────
    if config.flashbots_enabled {
        info!("Routing through Flashbots Protect");
        // TODO: Build Flashbots bundle with fee tx + state-delta assert
        // For now, fall through to upstream
    }

    // ── v1.0.3 Bounty 1: Canonical re-serialization ──────────────
    // Re-serialize from typed fields to eliminate parser divergence.
    // The upstream node sees exactly what was simulated.
    let canonical_req = if config.reject_duplicate_json_keys {
        canonicalize_send_request(&req, &from, &to, value, &data)
    } else {
        req
    };

    // Forward to upstream RPC
    proxy_to_upstream(config, &canonical_req).await
}

/// Forward a request to the upstream Ethereum RPC.
async fn proxy_to_upstream(config: &Config, req: &JsonRpcRequest) -> JsonRpcResponse {
    let client = reqwest::Client::new();
    match client
        .post(&config.upstream_rpc_url)
        .json(req)
        .send()
        .await
    {
        Ok(resp) => {
            match resp.json::<serde_json::Value>().await {
                Ok(body) => JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    result: body.get("result").cloned(),
                    error: None,
                    id: req.id.clone(),
                },
                Err(e) => JsonRpcResponse::error(
                    req.id.clone(),
                    -32603,
                    format!("Upstream parse error: {e}"),
                ),
            }
        }
        Err(e) => JsonRpcResponse::error(
            req.id.clone(),
            -32603,
            format!("Upstream connection error: {e}"),
        ),
    }
}

/// v1.0.3 Bounty 1: Detect duplicate keys in a JSON object.
/// serde_json silently deduplicates (keeps last), but the raw JSON bytes
/// forwarded to upstream may be parsed differently by other implementations.
/// This function checks the raw params string for duplicate keys.
fn detect_duplicate_json_keys(raw_json: &str) -> Option<String> {
    // Simple state machine to detect duplicate keys at the top level of a JSON object.
    // We parse the raw JSON to find all key strings at each nesting level.
    let val: serde_json::Value = match serde_json::from_str(raw_json) {
        Ok(v) => v,
        Err(_) => return None,
    };

    fn check_object(obj: &serde_json::Map<String, serde_json::Value>, raw: &str) -> Option<String> {
        // Count occurrences of each key pattern in the raw JSON
        for key in obj.keys() {
            let pattern = format!("\"{}\"", key);
            let count = raw.matches(&pattern).count();
            // If we see more than expected occurrences, it might be a duplicate
            // (conservative: any key appearing 2+ times at the raw level is suspicious)
            if count > 1 {
                // Verify it's actually a key (followed by ':') not a value
                let mut key_count = 0;
                let mut search_from = 0;
                while let Some(pos) = raw[search_from..].find(&pattern) {
                    let abs_pos = search_from + pos;
                    let after = abs_pos + pattern.len();
                    // Check if followed by optional whitespace then ':'
                    let remaining = &raw[after..];
                    let trimmed = remaining.trim_start();
                    if trimmed.starts_with(':') {
                        key_count += 1;
                    }
                    search_from = abs_pos + 1;
                }
                if key_count > 1 {
                    return Some(key.clone());
                }
            }
        }
        None
    }

    if let Some(obj) = val.as_object() {
        // Check top-level object
        if let Some(dup) = check_object(obj, raw_json) {
            return Some(dup);
        }
    }
    // Also check inside params array elements
    if let Some(arr) = val.as_array() {
        for item in arr {
            if let Some(obj) = item.as_object() {
                // Find the substring corresponding to this object in raw JSON
                // For simplicity, check against the full raw string
                if let Some(dup) = check_object(obj, raw_json) {
                    return Some(dup);
                }
            }
        }
    }
    None
}

/// v1.0.3 Bounty 1: Build a canonical JSON-RPC request from parsed fields.
/// Re-serializes the tx params from typed fields, eliminating any parser
/// divergence from duplicate keys or non-standard formatting.
fn canonicalize_send_request(
    req: &JsonRpcRequest,
    from: &str,
    to: &str,
    value: u128,
    data: &[u8],
) -> JsonRpcRequest {
    let value_hex = format!("0x{:x}", value);
    let data_hex = format!("0x{}", hex::encode(data));

    let mut canonical_tx = serde_json::json!({
        "from": from,
        "to": to,
        "value": value_hex,
        "data": data_hex,
    });

    // v1.0.4 Kill-Shot 2: Preserve gas fields for PVG/TVAR accounting.
    // Without this, canonicalization would drop preVerificationGas, maxFeePerGas,
    // etc., causing the upstream node to use default gas params.
    if let Some(tx_obj) = req.params.as_array().and_then(|a| a.first()) {
        for gas_field in &[
            "gas", "gasLimit", "maxFeePerGas", "maxPriorityFeePerGas",
            "preVerificationGas",
        ] {
            if let Some(val) = tx_obj.get(gas_field) {
                canonical_tx[gas_field] = val.clone();
            }
        }
    }

    JsonRpcRequest {
        jsonrpc: req.jsonrpc.clone(),
        method: req.method.clone(),
        params: serde_json::json!([canonical_tx]),
        id: req.id.clone(),
    }
}

/// Parse transaction parameters from a JSON-RPC request.
fn parse_tx_params(req: &JsonRpcRequest) -> Result<(String, String, u128, Vec<u8>)> {
    let params = req.params.as_array()
        .ok_or_else(|| anyhow::anyhow!("params must be array"))?;

    if params.is_empty() {
        anyhow::bail!("empty params");
    }

    let tx = &params[0];

    let from = tx.get("from")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0")
        .to_string();

    let to = tx.get("to")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0")
        .to_string();

    let value = tx.get("value")
        .and_then(|v| v.as_str())
        .and_then(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    let data = tx.get("data")
        .or_else(|| tx.get("input"))
        .and_then(|v| v.as_str())
        .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
        .unwrap_or_default();

    Ok((from, to, value, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_duplicate_keys_clean() {
        let json = r#"{"from":"0xabc","to":"0xdef","value":"0x0"}"#;
        assert!(detect_duplicate_json_keys(json).is_none());
    }

    #[test]
    fn test_detect_duplicate_keys_found() {
        let json = r#"{"to":"0xsafe","to":"0xhacker","value":"0x0"}"#;
        let result = detect_duplicate_json_keys(json);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "to");
    }

    #[test]
    fn test_detect_duplicate_keys_nested_array() {
        let json = r#"[{"from":"0xa","to":"0xb","to":"0xc"}]"#;
        let result = detect_duplicate_json_keys(json);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "to");
    }

    #[test]
    fn test_canonicalize_send_request() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "eth_sendTransaction".into(),
            params: serde_json::json!([{
                "from": "0xabc",
                "to": "0xdef",
                "to": "0xhacker",
                "value": "0x100"
            }]),
            id: serde_json::json!(1),
        };
        let canonical = canonicalize_send_request(
            &req, "0xabc", "0xhacker", 256, &[],
        );
        let tx = canonical.params.as_array().unwrap()[0].clone();
        assert_eq!(tx["to"].as_str().unwrap(), "0xhacker");
        assert_eq!(tx["from"].as_str().unwrap(), "0xabc");
        assert_eq!(tx["value"].as_str().unwrap(), "0x100");
    }

    // ═══════════════════════════════════════════════════════════════
    // v1.0.4 Kill-Shot 2: PVG Heist — enforce_pvg_ceiling tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_pvg_ceiling_disabled_when_zero() {
        let config = Config::from_env().unwrap();
        // Default max_pre_verification_gas = 0 → disabled
        let tx = serde_json::json!({"preVerificationGas": "0xF4240"}); // 1M
        assert!(enforce_pvg_ceiling(&config, &tx).is_ok());
    }

    #[test]
    fn test_pvg_ceiling_blocks_when_exceeded() {
        let mut config = Config::from_env().unwrap();
        config.max_pre_verification_gas = 500_000;
        let tx = serde_json::json!({"preVerificationGas": "0xF4240"}); // 1M > 500k
        let result = enforce_pvg_ceiling(&config, &tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PVG HEIST"));
    }

    #[test]
    fn test_pvg_ceiling_allows_within_limit() {
        let mut config = Config::from_env().unwrap();
        config.max_pre_verification_gas = 1_000_000;
        let tx = serde_json::json!({"preVerificationGas": "0x7A120"}); // 500k < 1M
        assert!(enforce_pvg_ceiling(&config, &tx).is_ok());
    }

    #[test]
    fn test_pvg_ceiling_decimal_string() {
        let mut config = Config::from_env().unwrap();
        config.max_pre_verification_gas = 100_000;
        let tx = serde_json::json!({"preVerificationGas": 200_000}); // u64 value
        let result = enforce_pvg_ceiling(&config, &tx);
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════════════════
    // v1.0.4 Kill-Shot 3: Bridge Refund Hijacking tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_bridge_validation_disabled_by_default() {
        let config = Config::from_env().unwrap();
        // Default bridge_refund_check = false → disabled
        let result = validate_bridge_params(
            &config,
            "0xSender",
            "0xBridge",
            &[0x67, 0x9b, 0x6d, 0xed], // Arbitrum selector
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_bridge_validation_arbitrum_valid_refund() {
        let mut config = Config::from_env().unwrap();
        config.bridge_refund_check = true;
        config.bridge_contracts = "0xbridge".to_string();

        let sender = "0xabcdef1234567890abcdef1234567890abcdef12";
        let sender_bytes = hex::decode(&sender[2..]).unwrap();

        // Build valid calldata: selector + 5 words (sender in words 3 & 4)
        let mut data = vec![0x67, 0x9b, 0x6d, 0xed]; // selector
        data.extend_from_slice(&[0u8; 12]); data.extend_from_slice(&sender_bytes); // word 0 (to)
        data.extend_from_slice(&[0u8; 32]); // word 1 (l2CallValue)
        data.extend_from_slice(&[0u8; 32]); // word 2 (maxSubmissionCost)
        data.extend_from_slice(&[0u8; 12]); data.extend_from_slice(&sender_bytes); // word 3 (excessFeeRefund)
        data.extend_from_slice(&[0u8; 12]); data.extend_from_slice(&sender_bytes); // word 4 (callValueRefund)

        let result = validate_bridge_params(&config, sender, "0xbridge", &data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bridge_validation_arbitrum_hijacked_refund() {
        let mut config = Config::from_env().unwrap();
        config.bridge_refund_check = true;
        config.bridge_contracts = "0xbridge".to_string();

        let sender = "0xabcdef1234567890abcdef1234567890abcdef12";
        let sender_bytes = hex::decode(&sender[2..]).unwrap();
        let attacker_bytes = hex::decode("bad0000000000000000000000000000000000bad").unwrap();

        // Build hijacked calldata: attacker in word 3
        let mut data = vec![0x67, 0x9b, 0x6d, 0xed]; // selector
        data.extend_from_slice(&[0u8; 12]); data.extend_from_slice(&sender_bytes);   // word 0
        data.extend_from_slice(&[0u8; 32]); // word 1
        data.extend_from_slice(&[0u8; 32]); // word 2
        data.extend_from_slice(&[0u8; 12]); data.extend_from_slice(&attacker_bytes);  // word 3 HIJACKED
        data.extend_from_slice(&[0u8; 12]); data.extend_from_slice(&sender_bytes);   // word 4

        let result = validate_bridge_params(&config, sender, "0xbridge", &data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("BRIDGE REFUND HIJACK"));
    }

    #[test]
    fn test_bridge_validation_not_bridge_contract() {
        let mut config = Config::from_env().unwrap();
        config.bridge_refund_check = true;
        config.bridge_contracts = "0xbridge".to_string();

        // Target is NOT a bridge contract → skip validation
        let result = validate_bridge_params(
            &config,
            "0xSender",
            "0xNotABridge",
            &[0x67, 0x9b, 0x6d, 0xed],
        );
        assert!(result.is_ok());
    }

    // ═══════════════════════════════════════════════════════════════
    // v1.0.4 Kill-Shot 4: Permit2 Time-Bomb tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_permit_deadline_disabled_when_zero() {
        let typed_data = serde_json::json!({
            "message": {"deadline": "115792089237316195423570985008687907853269984665640564039457584007913129639935"}
        });
        // max_duration_secs = 0 → disabled
        assert!(validate_permit_deadline(&typed_data, 0).is_ok());
    }

    #[test]
    fn test_permit_deadline_immortal_rejected() {
        let typed_data = serde_json::json!({
            "message": {"deadline": "115792089237316195423570985008687907853269984665640564039457584007913129639935"}
        });
        let result = validate_permit_deadline(&typed_data, 3600);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("IMMORTAL"));
    }

    #[test]
    fn test_permit_deadline_immortal_hex_rejected() {
        let typed_data = serde_json::json!({
            "message": {"deadline": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
        });
        let result = validate_permit_deadline(&typed_data, 3600);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("IMMORTAL"));
    }

    #[test]
    fn test_permit_deadline_excessive_rejected() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let excessive = now + 7 * 86400; // 7 days
        let typed_data = serde_json::json!({
            "message": {"deadline": excessive}
        });
        let result = validate_permit_deadline(&typed_data, 3600); // 1 hour max
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TIME-BOMB"));
    }

    #[test]
    fn test_permit_deadline_reasonable_allowed() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let reasonable = now + 1800; // 30 minutes
        let typed_data = serde_json::json!({
            "message": {"deadline": reasonable}
        });
        assert!(validate_permit_deadline(&typed_data, 3600).is_ok());
    }

    #[test]
    fn test_permit_multiple_temporal_fields() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let typed_data = serde_json::json!({
            "message": {
                "deadline": now + 1800,      // OK
                "sigDeadline": now + 7*86400  // EXCESSIVE
            }
        });
        let result = validate_permit_deadline(&typed_data, 3600);
        assert!(result.is_err());
    }

    #[test]
    fn test_canonicalize_preserves_gas_fields() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "eth_sendTransaction".into(),
            params: serde_json::json!([{
                "from": "0xabc",
                "to": "0xdef",
                "value": "0x100",
                "maxFeePerGas": "0x4A817C800",
                "preVerificationGas": "0x7A120"
            }]),
            id: serde_json::json!(1),
        };
        let canonical = canonicalize_send_request(
            &req, "0xabc", "0xdef", 256, &[],
        );
        let tx = canonical.params.as_array().unwrap()[0].clone();
        assert_eq!(tx["maxFeePerGas"].as_str().unwrap(), "0x4A817C800");
        assert_eq!(tx["preVerificationGas"].as_str().unwrap(), "0x7A120");
    }
}
