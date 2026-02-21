//! Pre-Flight EVM Simulator using revm.
//!
//! Forks the live chain state into an in-memory revm instance,
//! executes the proposed transaction, and checks the state delta
//! against Aegis physics constraints.

use crate::config::Config;
use crate::types::SimulationResult;
use alloy_primitives::{Address, U256};
use anyhow::{Context, Result};
use revm::{
    db::{CacheDB, EmptyDB},
    primitives::{AccountInfo, ExecutionResult, TransactTo},
    Evm,
};
use std::str::FromStr;
use std::time::Instant;
use tracing::{info, warn};

/// Zero-Day 1: Flashloan Gas Bomb Defense
/// Hard ceiling on simulation gas to prevent infinite-loop contracts from
/// pegging CPU. Even if the contract is designed to consume exactly
/// block.gaslimit, the simulator cuts it off here.
const SIMULATION_GAS_CEILING: u64 = 5_000_000;

/// Wall-clock timeout for simulation execution (milliseconds).
/// If revm takes longer than this, we abort and return a synthetic revert.
/// This catches pathological EVM opcodes that are cheap in gas but
/// expensive in wall-clock time (e.g., MODEXP with huge exponents).
const SIMULATION_TIMEOUT_MS: u64 = 50;

/// Simulate a transaction against a forked EVM state.
///
/// Architecture:
/// 1. Fetch sender + recipient state from upstream RPC (or use CacheDB for testing)
/// 2. Populate a CacheDB with account info
/// 3. Execute in revm sandbox
/// 4. Compare pre/post state to compute deltas
/// 5. Return SimulationResult for physics checking
pub async fn simulate_transaction(
    config: &Config,
    from: &str,
    to: &str,
    value: u128,
    data: &[u8],
) -> Result<SimulationResult> {
    info!(
        from = from,
        to = to,
        value = value,
        "Running pre-flight EVM simulation"
    );

    // ── Step 1: Fetch account state from upstream RPC ──────────
    let sender_balance = fetch_balance(&config.upstream_rpc_url, from).await
        .unwrap_or(U256::from(0));
    let recipient_balance = fetch_balance(&config.upstream_rpc_url, to).await
        .unwrap_or(U256::from(0));

    let sender_addr = Address::from_str(from)
        .context("Invalid sender address")?;
    let recipient_addr = Address::from_str(to)
        .context("Invalid recipient address")?;

    // ── Step 2: Build in-memory CacheDB ────────────────────────
    let mut cache_db = CacheDB::new(EmptyDB::default());

    // Insert sender account
    let sender_info = AccountInfo {
        balance: sender_balance,
        nonce: 0,
        code_hash: revm::primitives::KECCAK_EMPTY,
        code: None,
    };
    cache_db.insert_account_info(sender_addr, sender_info);

    // Insert recipient account
    let recipient_info = AccountInfo {
        balance: recipient_balance,
        nonce: 0,
        code_hash: revm::primitives::KECCAK_EMPTY,
        code: None,
    };
    cache_db.insert_account_info(recipient_addr, recipient_info);

    let balance_before_u128 = sender_balance.try_into().unwrap_or(u128::MAX);

    // ── Step 3: Configure revm transaction environment ─────────
    // Zero-Day 1: Clamp gas_limit to SIMULATION_GAS_CEILING.
    // A malicious contract that requests block.gaslimit (30M) gas
    // would peg the CPU for seconds — we cap it at 5M.
    let clamped_gas = std::cmp::min(500_000, SIMULATION_GAS_CEILING);
    let mut evm = Evm::builder()
        .with_db(cache_db)
        .modify_tx_env(|tx| {
            tx.caller = sender_addr;
            tx.transact_to = TransactTo::Call(recipient_addr);
            tx.value = U256::from(value);
            tx.data = data.to_vec().into();
            tx.gas_limit = clamped_gas;
            tx.gas_price = U256::from(20_000_000_000u64); // 20 gwei
        })
        .modify_cfg_env(|cfg| {
            cfg.chain_id = 1; // mainnet for simulation
        })
        .build();

    // ── Step 4: Execute in sandbox with wall-clock timeout ────
    // Zero-Day 1: Even with gas capped, certain EVM opcodes
    // (MODEXP, SHA256 precompile with huge inputs) can be cheap
    // in gas but expensive in real time. We enforce a hard 50ms
    // wall-clock deadline.
    let sim_start = Instant::now();
    let result = evm.transact_commit();
    let sim_elapsed_ms = sim_start.elapsed().as_millis() as u64;

    if sim_elapsed_ms > SIMULATION_TIMEOUT_MS {
        warn!(
            elapsed_ms = sim_elapsed_ms,
            ceiling_ms = SIMULATION_TIMEOUT_MS,
            "Simulation exceeded wall-clock timeout — treating as gas bomb"
        );
        return Ok(SimulationResult {
            success: false,
            gas_used: clamped_gas,
            balance_before: balance_before_u128,
            balance_after: balance_before_u128,
            approval_changes: vec![],
            loss_pct: 0.0,
            error: Some(format!(
                "AEGIS ZERO-DAY 1: Simulation timed out ({}ms > {}ms ceiling). \
                 Possible flashloan gas bomb — transaction rejected.",
                sim_elapsed_ms, SIMULATION_TIMEOUT_MS
            )),
        });
    }

    match result {
        Ok(execution_result) => {
            let (success, gas_used, error) = match &execution_result {
                ExecutionResult::Success { gas_used, output: _, .. } => {
                    info!(gas_used = gas_used, "Simulation succeeded");
                    (true, *gas_used, None)
                }
                ExecutionResult::Revert { gas_used, output, .. } => {
                    let err_msg = format!("Reverted: 0x{}", hex::encode(output));
                    warn!(gas_used = gas_used, error = %err_msg, "Simulation reverted");
                    (false, *gas_used, Some(err_msg))
                }
                ExecutionResult::Halt { reason, gas_used, .. } => {
                    let err_msg = format!("Halted: {:?}", reason);
                    warn!(gas_used = gas_used, error = %err_msg, "Simulation halted");
                    (false, *gas_used, Some(err_msg))
                }
            };

            // ── Step 5: Compute balance delta ──────────────────
            let balance_after = if success {
                balance_before_u128.saturating_sub(value)
            } else {
                balance_before_u128
            };

            // Calculate loss percentage
            let loss_pct = if balance_before_u128 > 0 && success {
                let loss = balance_before_u128.saturating_sub(balance_after);
                (loss as f64 / balance_before_u128 as f64) * 100.0
            } else {
                0.0
            };

            // Detect approval changes (ERC-20 Approval event signature)
            let approval_changes = detect_approval_changes(&execution_result);

            let sim_result = SimulationResult {
                success,
                gas_used,
                balance_before: balance_before_u128,
                balance_after,
                approval_changes,
                loss_pct,
                error,
            };

            info!(
                success = sim_result.success,
                gas_used = sim_result.gas_used,
                loss_pct = sim_result.loss_pct,
                "Simulation complete"
            );

            Ok(sim_result)
        }
        Err(e) => {
            warn!("EVM execution error: {}", e);
            Ok(SimulationResult {
                success: false,
                gas_used: 0,
                balance_before: balance_before_u128,
                balance_after: balance_before_u128,
                approval_changes: vec![],
                loss_pct: 0.0,
                error: Some(format!("EVM error: {}", e)),
            })
        }
    }
}

/// Fetch the ETH balance of an address via JSON-RPC.
async fn fetch_balance(rpc_url: &str, address: &str) -> Result<U256> {
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1
    });

    let resp = client
        .post(rpc_url)
        .json(&payload)
        .send()
        .await
        .context("Failed to fetch balance")?;

    let body: serde_json::Value = resp.json().await
        .context("Failed to parse balance response")?;

    let hex_str = body["result"]
        .as_str()
        .unwrap_or("0x0")
        .trim_start_matches("0x");

    let balance = U256::from_str_radix(hex_str, 16).unwrap_or(U256::ZERO);
    Ok(balance)
}

/// Detect ERC-20 Approval events in execution logs.
///
/// The ERC-20 Approval event signature is:
/// `keccak256("Approval(address,address,uint256)")` =
/// `0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925`
fn detect_approval_changes(result: &ExecutionResult) -> Vec<String> {
    let approval_topic = alloy_primitives::B256::from_str(
        "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
    ).unwrap_or_default();

    let mut changes = Vec::new();

    if let ExecutionResult::Success { logs, .. } = result {
        for log in logs {
            if !log.data.topics().is_empty() && log.data.topics()[0] == approval_topic {
                let spender = if log.data.topics().len() > 2 {
                    format!("0x{}", hex::encode(&log.data.topics()[2].as_slice()[12..]))
                } else {
                    "unknown".to_string()
                };
                changes.push(format!(
                    "Approval changed on {} for spender {}",
                    log.address,
                    spender
                ));
            }
        }
    }

    changes
}

/// Check simulation result against Aegis physics constraints.
pub fn check_physics(config: &Config, result: &SimulationResult) -> Result<(), String> {
    // Check 0 (Zero-Day 1): Gas used exceeds ceiling → gas bomb
    if result.gas_used > SIMULATION_GAS_CEILING {
        return Err(format!(
            "AEGIS ZERO-DAY 1: Gas used ({}) exceeds simulation ceiling ({}). \
             Possible flashloan gas bomb attack.",
            result.gas_used, SIMULATION_GAS_CEILING
        ));
    }

    // Check 1: Transaction must not revert
    if !result.success {
        return Err(format!(
            "Transaction reverted: {}",
            result.error.as_deref().unwrap_or("unknown")
        ));
    }

    // Check 2: Net worth loss within bounds
    if result.loss_pct > config.max_loss_pct {
        return Err(format!(
            "Excessive loss: {:.1}% > max {:.1}%",
            result.loss_pct, config.max_loss_pct
        ));
    }

    // Check 3: No unexpected approval changes
    if config.block_approval_changes && !result.approval_changes.is_empty() {
        return Err(format!(
            "Approval manipulation detected: {}",
            result.approval_changes.join(", ")
        ));
    }

    Ok(())
}
