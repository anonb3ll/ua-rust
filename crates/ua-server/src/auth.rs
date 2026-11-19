//! HTTP authentication.
//!
//! Three bearer credentials, tried in order:
//! 1. static tokens from configuration (`UA_AGENT_TOKENS`),
//! 2. managed tokens, stored as SHA-256 digests in `agent_tokens`,
//! 3. OAuth access tokens (`uao_…`, digests in `oauth_tokens`), checked for
//!    expiry, revocation and audience: a token for `<issuer>/mcp` is valid on
//!    `/mcp` only; a token for `<issuer>` is valid on `/mcp` and `/api`.
//!
//! Without a bearer, a Control Center session cookie authenticates `/ui` and
//! `/api` requests (never `/mcp`), and every state-changing cookie request
//! must carry the session's CSRF token in `X-CSRF-Token`.
//!
//! Comparison is constant time. A 401 carries the RFC 9728 challenge
//! (`resource_metadata`) when OAuth is on. With `enforce_auth` off, requests
//! without a credential run as the local anonymous identity with the full
//! tool surface, like stdio.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use ua_core::ActorKind;

use crate::AppState;
use crate::login::{self, CSRF_HEADER};
use crate::oauth;

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

/// Resolve a presented static or managed token to an identity label.
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

fn path_is(path: &str, prefix: &str) -> bool {
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

/// Resolve any bearer credential for a request to `path`.
pub fn resolve_bearer(state: &AppState, token: &str, path: &str) -> Option<AuthIdentity> {
    let cfg = state.hub.cfg();
    if let Some(label) = lookup_token(state, token) {
        let kind = if cfg.is_human(&label) { ActorKind::Human } else { ActorKind::Agent };
        return Some(AuthIdentity { label, kind, verified: true });
    }
    if !cfg.oauth_enabled || !token.starts_with(oauth::ACCESS_PREFIX) {
        return None;
    }
    let access = oauth::store::lookup_access(state, token)?;
    // Audience (RFC 8707): the hub-wide resource covers /mcp and /api; the
    // MCP resource covers /mcp only.
    let hub_wide = access.resource == oauth::issuer(cfg);
    let audience_ok = hub_wide || (access.resource == oauth::mcp_resource(cfg) && path_is(path, "/mcp"));
    // OAuth grants never act as a human, even if the configuration changed.
    (audience_ok && !cfg.is_human(&access.subject)).then_some(AuthIdentity {
        label: access.subject,
        kind: ActorKind::Agent,
        verified: true,
    })
}

fn is_public_path(path: &str) -> bool {
    path == "/healthz"
        || path.starts_with("/.well-known/")
        || path_is(path, "/oauth")
        || path_is(path, "/login")
        || path == "/logout"
}

pub async fn authenticate(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let public = is_public_path(&path);
    let cookie_scope = path_is(&path, "/ui") || path_is(&path, "/api");
    let identity = if let Some(tok) = bearer(req.headers()) {
        match resolve_bearer(&state, tok, &path) {
            Some(id) => id,
            None if public => anonymous(),
            None => return unauthorized(&state, Some("invalid_token"), "invalid token"),
        }
    } else if let Some(session) =
        cookie_scope.then(|| login::session_from_headers(&state, req.headers())).flatten()
    {
        if login::is_unsafe(req.method()) {
            let provided = req.headers().get(CSRF_HEADER).and_then(|v| v.to_str().ok());
            if !login::csrf_matches(&session, provided) {
                let body = serde_json::json!({ "ok": false, "error": "csrf", "message": "missing or wrong X-CSRF-Token" });
                return (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
            }
        }
        let id = AuthIdentity { label: session.label.clone(), kind: ActorKind::Human, verified: true };
        req.extensions_mut().insert(session);
        id
    } else if state.hub.cfg().enforce_auth && !public {
        if path_is(&path, "/ui") && matches!(*req.method(), Method::GET | Method::HEAD) {
            let next = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
            let q = url::form_urlencoded::Serializer::new(String::new()).append_pair("next", &next).finish();
            return Redirect::to(&format!("/login?{q}")).into_response();
        }
        return unauthorized(&state, None, "bearer token required");
    } else {
        anonymous()
    };
    req.extensions_mut().insert(identity);
    next.run(req).await
}

fn anonymous() -> AuthIdentity {
    AuthIdentity { label: LOCAL_LABEL.into(), kind: ActorKind::Anonymous, verified: false }
}

fn unauthorized(state: &AppState, error: Option<&str>, msg: &str) -> Response {
    let body = serde_json::json!({ "ok": false, "error": "unauthenticated", "message": msg });
    let challenge = oauth::www_authenticate(state.hub.cfg(), error);
    (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, challenge)], axum::Json(body)).into_response()
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
