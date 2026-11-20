//! Adapters over the governed tool registry: MCP (stdio and Streamable
//! HTTP), the HTTP/JSON API, and the web UI. Every adapter resolves a
//! [`ua_core::Caller`] and calls [`ua_tools::Registry::call`]; none of them
//! runs a tool directly.

pub mod api;
pub mod auth;
pub mod compat_api;
pub mod events;
pub mod github_api;
pub mod guard;
pub mod login;
pub mod mcp;
pub mod node_api;
pub mod oauth;
pub mod platform_api;
pub mod ui;

use std::sync::Arc;

use axum::Router;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use ua_tools::{Hub, Registry};

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    pub hub: Hub,
    pub registry: Arc<Registry>,
    /// The browser-session cookie key, cached so authenticated UI requests
    /// do not read `ui_keys` ([`login::CookieKeyCache`]).
    pub cookie_key: Arc<login::CookieKeyCache>,
    /// Cancelled when the server shuts down: long-lived responses (event
    /// streams) end on it so a graceful shutdown does not wait on them.
    /// [`router`] sets it to the server's token.
    pub shutdown: CancellationToken,
    /// MCP tool calls in flight, each run as its own task so a shutdown can
    /// wait for it even when the MCP session it came from is torn down.
    pub calls: TaskTracker,
}

impl AppState {
    pub fn new(hub: Hub, registry: Arc<Registry>) -> Self {
        Self {
            hub,
            registry,
            cookie_key: Arc::new(login::CookieKeyCache::new()),
            shutdown: CancellationToken::new(),
            calls: TaskTracker::new(),
        }
    }
}

pub const INSTRUCTIONS: &str = "Agent-operations hub. One governed tool surface for every agent: tasks, plans, \
delegation, messages, memory, vault and workspace tools behind identity, profile, policy and approval checks. \
Search memory before asking the user to repeat themselves. Calls that need a human return approval_required with \
an approval id; retry the identical call after it is approved.";

/// Build the full HTTP router: `/mcp`, `/api`, health. Cancelling `ct`
/// ends MCP sessions and open event streams.
pub fn router(state: AppState, ct: CancellationToken) -> Router {
    let state = AppState { shutdown: ct.clone(), ..state };
    let mcp = mcp::http_service(state.clone(), ct);
    Router::new()
        .nest_service("/mcp", mcp)
        .merge(api::routes())
        .merge(oauth::routes())
        .merge(login::routes())
        .merge(compat_api::routes())
        .merge(github_api::routes())
        .merge(node_api::routes())
        .merge(platform_api::routes())
        .merge(ui::routes())
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth::authenticate))
        .layer(axum::middleware::from_fn_with_state(state.clone(), guard::protect))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Serve HTTP until `ct` is cancelled.
pub async fn serve_http(state: AppState, ct: CancellationToken) -> anyhow::Result<()> {
    let bind = state.hub.cfg().bind;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, tools = state.registry.len(), "hub listening");
    let app = router(state, ct.clone()).into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum::serve(listener, app).with_graceful_shutdown(async move { ct.cancelled_owned().await }).await?;
    Ok(())
}
