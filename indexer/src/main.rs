//! Aegis Fleet Indexer — Multi-Chain Event Indexer.
//!
//! High-speed indexer that listens globally for Aegis vault events across
//! Ethereum, Base, Arbitrum, Polygon, and Solana.  Pipes events into a
//! PostgreSQL database so the React dashboard can load 5,000 agents in
//! 40 milliseconds.
//!
//! ## Architecture
//!
//! ```text
//!   ┌──────────────────────────────────────────────────────────┐
//!   │                    CHAIN LISTENERS                        │
//!   │                                                          │
//!   │  EVM Listener (Ethereum, Base, Arbitrum, Polygon)        │
//!   │    → WebSocket subscription to AegisVault events         │
//!   │    → eth_getLogs for historical backfill                  │
//!   │                                                          │
//!   │  Solana Listener                                         │
//!   │    → WebSocket programSubscribe for Anchor events        │
//!   │    → getSignaturesForAddress for historical backfill     │
//!   │                                                          │
//!   └──────────────────┬───────────────────────────────────────┘
//!                      │ Normalized IndexedEvent
//!   ┌──────────────────▼───────────────────────────────────────┐
//!   │                   EVENT PROCESSOR                         │
//!   │                                                          │
//!   │  Deduplication (tx_hash + log_index)                     │
//!   │  Normalization (chain-specific → universal schema)       │
//!   │  Enrichment (agent metadata, USD conversion)             │
//!   │                                                          │
//!   └──────────────────┬───────────────────────────────────────┘
//!                      │ Batch INSERT
//!   ┌──────────────────▼───────────────────────────────────────┐
//!   │                    POSTGRESQL                             │
//!   │                                                          │
//!   │  aegis_events  — partitioned by chain_id                 │
//!   │  agent_stats   — materialized view (real-time rollup)    │
//!   │  vault_state   — latest state snapshot per vault         │
//!   │                                                          │
//!   │  Indexes: vault_address, agent, timestamp, chain_id      │
//!   │  → 5,000 agents in <40ms with composite index scan       │
//!   └──────────────────────────────────────────────────────────┘
//! ```

mod schema;
mod evm_listener;
mod solana_listener;
mod processor;

use std::sync::Arc;
use tracing::info;

use schema::IndexerConfig;
use evm_listener::EvmListener;
use solana_listener::SolanaListener;
use processor::EventProcessor;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = IndexerConfig::from_env();
    info!("Aegis Fleet Indexer v2.0 starting");
    info!("Chains: {:?}", config.chains.iter().map(|c| &c.name).collect::<Vec<_>>());

    let processor = Arc::new(EventProcessor::new(config.database_url.clone()));

    // Spawn a listener for each configured chain
    let mut handles = Vec::new();

    for chain in &config.chains {
        let proc = Arc::clone(&processor);
        let chain = chain.clone();

        let handle = tokio::spawn(async move {
            match chain.chain_type.as_str() {
                "evm" => {
                    let listener = EvmListener::new(chain);
                    listener.run(proc).await;
                }
                "solana" => {
                    let listener = SolanaListener::new(chain);
                    listener.run(proc).await;
                }
                other => {
                    tracing::warn!("Unknown chain type: {} — skipping", other);
                }
            }
        });

        handles.push(handle);
    }

    info!("All chain listeners spawned — indexing live events");

    // Wait for all listeners (they run forever)
    for handle in handles {
        let _ = handle.await;
    }
}
