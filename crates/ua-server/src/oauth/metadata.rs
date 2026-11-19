//! RFC 8414 authorization server metadata and RFC 9728 protected resource
//! metadata. Both are public, cacheable and CORS-open so browser-based MCP
//! clients can discover the server.

use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use ua_core::Config;

use super::{SCOPE, issuer, mcp_resource, not_enabled};
use crate::AppState;

fn cors_json(v: Value) -> Response {
    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"), (header::CACHE_CONTROL, "public, max-age=300")], Json(v))
        .into_response()
}

/// The authorization server metadata document.
pub fn as_metadata(cfg: &Config) -> Value {
    let iss = issuer(cfg);
    let auth_methods = ["none", "client_secret_basic", "client_secret_post"];
    let mut m = json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/oauth/authorize"),
        "token_endpoint": format!("{iss}/oauth/token"),
        "revocation_endpoint": format!("{iss}/oauth/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": auth_methods,
        "revocation_endpoint_auth_methods_supported": auth_methods,
        "scopes_supported": [SCOPE],
        "authorization_response_iss_parameter_supported": true,
        "client_id_metadata_document_supported": cfg.oauth_cimd_enabled,
    });
    if cfg.oauth_dcr_enabled {
        m["registration_endpoint"] = json!(format!("{iss}/oauth/register"));
    }
    m
}

/// Protected resource metadata for `resource`.
pub fn pr_metadata(cfg: &Config, resource: String) -> Value {
    json!({
        "resource": resource,
        "authorization_servers": [issuer(cfg)],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
        "resource_name": "ua-rust hub",
    })
}

pub async fn authorization_server(State(state): State<AppState>) -> Response {
    let cfg = state.hub.cfg();
    if !cfg.oauth_enabled {
        return not_enabled();
    }
    cors_json(as_metadata(cfg))
}

pub async fn protected_resource_mcp(State(state): State<AppState>) -> Response {
    let cfg = state.hub.cfg();
    if !cfg.oauth_enabled {
        return not_enabled();
    }
    cors_json(pr_metadata(cfg, mcp_resource(cfg)))
}

/// The root document describes the whole hub; a token for it is also valid
/// on `/mcp`.
pub async fn protected_resource_root(State(state): State<AppState>) -> Response {
    let cfg = state.hub.cfg();
    if !cfg.oauth_enabled {
        return not_enabled();
    }
    cors_json(pr_metadata(cfg, issuer(cfg)))
}
