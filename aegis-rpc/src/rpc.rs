//! JSON-RPC handler — intercepts send-transaction methods,
//! passes read-only calls through to the upstream provider.
//!
//! ## Security Patches
//! - Patch 2: State-Delta Invariant — captures expected post-state from simulation
//! - Patch 4: Synthetic Receipts — blocked txs return fake receipts instead of errors

use crate::config::Config;
use crate::fee;
use crate::simulator;
use crate::telemetry;
use crate::threat_feed::{self, SharedThreatFilter};
use crate::types::{JsonRpcRequest, JsonRpcResponse};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{info, warn};

/// Methods that involve broadcasting transactions (need simulation).
const SEND_METHODS: &[&str] = &[
    "eth_sendTransaction",
    "eth_sendRawTransaction",
];

// ── Patch 4: Synthetic receipt store ─────────────────────────────
// Blocked transactions get synthetic hashes. When the agent polls
// eth_getTransactionReceipt, we return a synthetic reverted receipt
// instead of null. This keeps the agent's web3 client alive.
lazy_static::lazy_static! {
    static ref BLOCKED_TX_STORE: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
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
                    return JsonRpcResponse::aegis_synthetic_receipt(
                        req.id, hash, reason,
                    );
                }
            }
        }
    }

    // ── Read-only methods: pass through to upstream ─────────────
    if !SEND_METHODS.contains(&req.method.as_str()) {
        return proxy_to_upstream(config, &req).await;
    }

    // ── Transaction methods: simulate first ─────────────────────
    info!("Intercepted send tx — running pre-flight simulation");

    // Parse tx parameters from the request
    let (from, to, value, data) = match parse_tx_params(&req) {
        Ok(params) => params,
        Err(e) => {
            warn!("Failed to parse tx params: {}", e);
            return JsonRpcResponse::error(req.id, -32602, format!("Invalid params: {e}"));
        }
    };

    // ── ENGINE 0: Global Bloom Filter Pre-Flight ────────────────
    // Runs BEFORE Engines 1-6. Sub-millisecond O(1) lookup against
    // the Swarm-compiled global blacklist.
    let (engine0_blocked, engine0_reason) = threat_feed::engine0_check(
        threat_filter, &to, &data,
    );
    if engine0_blocked {
        warn!("{}", engine0_reason);
        // Extract IOC and uplink to Aegis Cloud
        let ioc = telemetry::extract_ioc(
            &from, &to, &data, "bloom", &engine0_reason, None, 1,
        );
        telemetry::uplink_ioc(&ioc, "https://cloud.aegis.network/v1/ioc").await;
        // Patch 4: Return synthetic tx hash — agent stays alive
        let (resp, tx_hash) = JsonRpcResponse::aegis_synthetic_send(req.id, &engine0_reason);
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
            let (resp, tx_hash) = JsonRpcResponse::aegis_synthetic_send(req.id, &reason);
            if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
                store.insert(tx_hash, reason);
            }
            return resp;
        }
    };

    // Check physics constraints
    if let Err(reason) = simulator::check_physics(config, &sim_result) {
        warn!("Physics violation: {}", reason);
        // Extract IOC and uplink to Aegis Cloud
        let ioc = telemetry::extract_ioc(
            &from, &to, &data, "simulator", &reason, Some(&reason), 1,
        );
        telemetry::uplink_ioc(&ioc, "https://cloud.aegis.network/v1/ioc").await;
        // Patch 4: Return synthetic tx hash — agent stays alive
        let (resp, tx_hash) = JsonRpcResponse::aegis_synthetic_send(req.id, &reason);
        if let Ok(mut store) = BLOCKED_TX_STORE.lock() {
            store.insert(tx_hash, reason);
        }
        return resp;
    }

    // ── Patch 2: State-Delta Invariant Capture ───────────────────
    // The "Volkswagen" defense: we record what the simulation EXPECTS
    // the post-execution state to look like. Downstream tooling (or
    // an on-chain wrapper) can assert these invariants.
    info!(
        sim_balance_before = sim_result.balance_before,
        sim_balance_after = sim_result.balance_after,
        sim_loss_pct = sim_result.loss_pct,
        sim_gas_used = sim_result.gas_used,
        "State-delta invariant captured from simulation"
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

    // Forward to upstream RPC
    proxy_to_upstream(config, &req).await
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
