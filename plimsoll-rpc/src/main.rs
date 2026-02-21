#![allow(dead_code)]
//! Plimsoll RPC Proxy — The Execution Highway for AI Agent Transactions.
//!
//! Instead of agents broadcasting directly to the public mempool,
//! they point their RPC URL to `https://rpc.plimsoll.network`.
//!
//! The proxy:
//!   1. Intercepts every `eth_sendTransaction` / `eth_sendRawTransaction`
//!   2. Simulates the tx in a local revm shadow-fork
//!   3. Checks the state delta against physics (max loss, approval drain, etc.)
//!   4. Routes passing txs through Flashbots Protect (MEV-shielded)
//!   5. Collects a 1-2 bps fee on successful execution
//!
//! ## Architecture
//!
//! ```text
//! AI Agent
//!    │
//!    ▼
//! ┌──────────────────────────────────────┐
//! │  Plimsoll RPC Proxy (this binary)       │
//! │  ┌──────────────┐ ┌───────────────┐  │
//! │  │ Pre-Flight   │ │  MEV Shield   │  │
//! │  │ Simulator    │ │  (Flashbots)  │  │
//! │  │ (revm fork)  │ │               │  │
//! │  └──────┬───────┘ └───────┬───────┘  │
//! │         │                 │           │
//! │         ▼                 ▼           │
//! │  ┌──────────────────────────────┐    │
//! │  │     Fee Collector (1-2 bps)  │    │
//! │  └──────────────────────────────┘    │
//! └──────────────────────────────────────┘
//!    │
//!    ▼
//! Ethereum Mainnet (via private block builders)
//! ```

mod config;
mod fee;
mod flashbots;
mod http_proxy;
mod inspector;
mod router;
mod rpc;
mod sanitizer;
mod simulator;
mod svm_simulator;
mod telemetry;
mod threat_feed;
mod types;
mod utxo_guard;

use anyhow::Result;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("plimsoll_rpc=info,tower_http=debug")),
        )
        .init();

    let cfg = config::Config::from_env()?;
    tracing::info!(
        "Plimsoll RPC Proxy v{} starting on {}:{}",
        env!("CARGO_PKG_VERSION"),
        cfg.host,
        cfg.port
    );
    tracing::info!("Upstream RPC: {}", cfg.upstream_rpc_url);
    tracing::info!("Fee: {} bps", cfg.fee_bps);
    tracing::info!(
        "Max loss: {}%, MEV shield: {}",
        cfg.max_loss_pct,
        if cfg.flashbots_enabled {
            "Flashbots"
        } else {
            "disabled"
        }
    );
    tracing::info!("Engine 0: Swarm Bloom Filter enabled (pre-flight blacklist)");

    let app = router::build_router(cfg).await?;

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8545").await?;
    tracing::info!("Listening on 0.0.0.0:8545");

    axum::serve(listener, app).await?;
    Ok(())
}
