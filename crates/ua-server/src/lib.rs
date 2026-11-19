//! Adapters over the governed tool registry: MCP (stdio and Streamable
//! HTTP), the HTTP/JSON API, and the web UI. Every adapter resolves a
//! [`ua_core::Caller`] and calls [`ua_tools::Registry::call`]; none of them
//! runs a tool directly.

pub mod api;
pub mod auth;
pub mod login;
pub mod mcp;
pub mod oauth;

use std::sync::Arc;

use axum::Router;
use tokio_util::sync::CancellationToken;
use ua_tools::{Hub, Registry};

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    pub hub: Hub,
    pub registry: Arc<Registry>,
}

pub const INSTRUCTIONS: &str = "Agent-operations hub. One governed tool surface for every agent: tasks, plans, \
delegation, messages, memory, vault and workspace tools behind identity, profile, policy and approval checks. \
Search memory before asking the user to repeat themselves. Calls that need a human return approval_required with \
an approval id; retry the identical call after it is approved.";

/// Build the full HTTP router: `/mcp`, `/api`, health.
pub fn router(state: AppState, ct: CancellationToken) -> Router {
    let mcp = mcp::http_service(state.clone(), ct);
    Router::new()
        .nest_service("/mcp", mcp)
        .merge(api::routes())
        .merge(oauth::routes())
        .merge(login::routes())
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth::authenticate))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Serve HTTP until `ct` is cancelled.
pub async fn serve_http(state: AppState, ct: CancellationToken) -> anyhow::Result<()> {
    let bind = state.hub.cfg().bind;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, tools = state.registry.len(), "hub listening");
    let app = router(state, ct.clone());
    axum::serve(listener, app).with_graceful_shutdown(async move { ct.cancelled_owned().await }).await?;
    Ok(())
}
