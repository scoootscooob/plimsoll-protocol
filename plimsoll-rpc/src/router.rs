//! Axum router setup for the Plimsoll RPC Proxy.

use crate::config::Config;
use crate::rpc;
use crate::threat_feed::{self, SharedThreatFilter};
use crate::types::JsonRpcRequest;
use anyhow::Result;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    /// Engine 0: Global Bloom Filter — shared across all request handlers.
    pub threat_filter: SharedThreatFilter,
}

/// Build the Axum router with all RPC routes.
pub async fn build_router(config: Config) -> Result<Router> {
    let threat_filter = threat_feed::new_shared_filter();
    tracing::info!("Engine 0 threat filter initialized (empty, awaiting Cloud push)");

    let state = Arc::new(AppState { config, threat_filter });

    let app = Router::new()
        .route("/", post(handle_rpc))
        .route("/health", axum::routing::get(health))
        .layer(CorsLayer::permissive())
        .with_state(state);

    Ok(app)
}

/// POST / — Main JSON-RPC endpoint.
async fn handle_rpc(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JsonRpcRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let response = rpc::handle_rpc(&state.config, &state.threat_filter, req).await;
    (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
}

/// GET /health — Health check endpoint.
async fn health() -> &'static str {
    "plimsoll-rpc OK"
}
