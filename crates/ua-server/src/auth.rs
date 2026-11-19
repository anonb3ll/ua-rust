//! HTTP authentication: bearer tokens bound to identities.
//!
//! Static tokens come from configuration (`UA_AGENT_TOKENS`); managed tokens
//! are stored as SHA-256 hashes in `agent_tokens`. Comparison is constant
//! time. With `enforce_auth` off, requests without a token run as the local
//! anonymous identity with the full tool surface, like stdio.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use ua_core::ActorKind;

use crate::AppState;

/// The verified principal of one HTTP request.
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub label: String,
    pub kind: ActorKind,
    pub verified: bool,
}

/// Label used for unauthenticated local callers.
pub const LOCAL_LABEL: &str = "local";

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ").map(str::trim)
}

/// Resolve a presented token to an identity label.
pub fn lookup_token(state: &AppState, token: &str) -> Option<String> {
    let presented = token.as_bytes();
    let mut found = None;
    // Check every static entry so timing does not depend on the match position.
    for (label, secret) in state.hub.cfg().static_tokens() {
        if bool::from(secret.expose_secret().as_bytes().ct_eq(presented)) {
            found = Some(label);
        }
    }
    if found.is_some() {
        return found;
    }
    let hash = hex::encode(Sha256::digest(presented));
    state
        .hub
        .db()
        .read(|c| {
            use rusqlite::OptionalExtension;
            Ok(c.query_row(
                "SELECT agent_label FROM agent_tokens WHERE token_hash = ?1 AND status = 'active' \
                 AND (expires_at IS NULL OR expires_at > ?2)",
                rusqlite::params![hash, ua_core::time::now()],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
        })
        .ok()
        .flatten()
}

pub async fn authenticate(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let public = path == "/healthz" || path.starts_with("/.well-known/");
    let identity = match bearer(req.headers()) {
        Some(tok) => match lookup_token(&state, tok) {
            Some(label) => {
                let kind = if state.hub.cfg().is_human(&label) { ActorKind::Human } else { ActorKind::Agent };
                AuthIdentity { label, kind, verified: true }
            }
            None => return unauthorized("invalid token"),
        },
        None if state.hub.cfg().enforce_auth && !public => return unauthorized("bearer token required"),
        None => AuthIdentity { label: LOCAL_LABEL.into(), kind: ActorKind::Anonymous, verified: false },
    };
    req.extensions_mut().insert(identity);
    next.run(req).await
}

fn unauthorized(msg: &str) -> Response {
    let body = serde_json::json!({ "ok": false, "error": "unauthenticated", "message": msg });
    (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")], axum::Json(body)).into_response()
}

/// Build the governed caller for one request.
pub fn caller_for(
    state: &AppState,
    id: &AuthIdentity,
    session_key: Option<String>,
    transport: ua_core::identity::Transport,
) -> ua_core::Caller {
    let profile = ua_tools::sessions::resolve_profile(&state.hub, &id.label, session_key.as_deref());
    ua_core::Caller {
        label: id.label.clone(),
        kind: id.kind,
        profile,
        // Only verified callers are filtered; local anonymous use keeps the
        // full surface, as stdio does.
        enforce_profile: id.verified,
        session_key,
        transport,
    }
}

/// Client session key: the legacy MCP session header, else `X-UA-Session`.
pub fn session_key(headers: &HeaderMap) -> Option<String> {
    ["mcp-session-id", "x-ua-session"]
        .iter()
        .find_map(|h| headers.get(*h).and_then(|v| v.to_str().ok()))
        .map(|s| s.chars().take(128).collect())
}
