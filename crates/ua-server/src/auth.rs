//! HTTP authentication.
//!
//! A bearer starting `uas_` is a node session credential and is checked
//! only as one ([`ua_tools::families::node_queue::credentials::verify`],
//! every request, nothing cached). It is accepted on `/mcp`, `/api/tools`
//! and `/api/whoami` only (any other path answers 403), and runs as the
//! item's agent under the `acp-session` profile and the credential's grant.
//!
//! Other bearer credentials, tried in order:
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
//! (`resource_metadata`) when OAuth is on. With `enforce_auth` off — a
//! single-organization mode only, refused whenever `orgs` holds any
//! organization other than `default` (active or suspended) — requests without
//! a credential run as the local anonymous identity with the full tool
//! surface, like stdio.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use secrecy::ExposeSecret;
use subtle::ConstantTimeEq;
use ua_core::{ActorKind, Profile};
use ua_tools::families::node_queue::credentials;
use ua_tools::grant::SessionGrant;

use crate::AppState;
use crate::login::{self, CSRF_HEADER};
use crate::oauth;

/// The verified principal of one HTTP request.
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub label: String,
    pub kind: ActorKind,
    pub verified: bool,
    /// Set for a node session credential: the request runs under this grant.
    pub grant: Option<Arc<SessionGrant>>,
    /// The organization the credential resolves to: a managed token's
    /// (`agent_tokens.org_id`, its agent's), a session credential's
    /// (`session_credentials.org_id`), else the default organization (static
    /// tokens, OAuth grants, Control Center sessions and anonymous callers).
    pub org_id: String,
}

impl AuthIdentity {
    /// An identity in the default organization.
    pub fn in_default(label: impl Into<String>, kind: ActorKind, verified: bool) -> Self {
        Self { label: label.into(), kind, verified, grant: None, org_id: ua_core::DEFAULT_ORG.to_string() }
    }
}

/// Label used for unauthenticated local callers.
pub use ua_core::identity::LOCAL_LABEL;

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ").map(str::trim)
}

/// Resolve a presented static or managed token to an identity label and
/// its organization. Blocking: it reads `agent_tokens` and `agents`.
///
/// A static token is hub configuration and always resolves to the default
/// organization; it is refused while another organization's agent holds
/// its label. A managed token resolves to its own organization, which must
/// be its agent's ([`ua_tools::families::tokens::resolve_managed_token`]).
pub fn lookup_token(state: &AppState, token: &str) -> Option<(String, String)> {
    let presented = token.as_bytes();
    let mut found = None;
    // Check every static entry so timing does not depend on the match position.
    for (label, secret) in state.hub.cfg().static_tokens() {
        if bool::from(secret.expose_secret().as_bytes().ct_eq(presented)) {
            found = Some(label);
        }
    }
    let reserved = ua_tools::families::agents::Reserved::of(state.hub.cfg());
    if let Some(label) = found {
        let elsewhere = state
            .hub
            .db()
            .read(|c| ua_tools::families::tokens::held_outside_default(c, &reserved, &label))
            .unwrap_or(true);
        return (!elsewhere).then(|| (label, ua_core::DEFAULT_ORG.to_string()));
    }
    state
        .hub
        .db()
        .read(|c| ua_tools::families::tokens::resolve_managed_token(c, &reserved, token))
        .ok()
        .flatten()
}

fn path_is(path: &str, prefix: &str) -> bool {
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

/// Whether a row of another organization holds `label`, for a credential
/// that always resolves to the default organization (a Control Center
/// session, a Slack human). Fails closed: an unreadable state refuses.
pub async fn held_outside_default(state: &AppState, label: &str) -> bool {
    let label = label.to_string();
    let reserved = ua_tools::families::agents::Reserved::of(state.hub.cfg());
    state
        .hub
        .db()
        .read_async(move |c| ua_tools::families::tokens::held_outside_default(c, &reserved, &label))
        .await
        .unwrap_or(true)
}

/// Whether `label` is a retired agent identity. Fails closed: an unreadable
/// lifecycle state refuses the credential for now.
fn retired(state: &AppState, label: &str) -> bool {
    state.hub.db().read(|c| ua_tools::families::governance::is_retired(c, label)).unwrap_or(true)
}

/// Resolve any bearer credential for a request to `path`. A retired agent
/// identity resolves to nothing, whichever credential it presents (a static
/// token in configuration cannot be revoked any other way). The lookups
/// (managed tokens, OAuth tokens, agent lifecycle) run off the async runtime.
pub async fn resolve_bearer(state: &AppState, token: &str, path: &str) -> Option<AuthIdentity> {
    let (state, token, path) = (state.clone(), token.to_string(), path.to_string());
    tokio::task::spawn_blocking(move || resolve_bearer_blocking(&state, &token, &path)).await.ok().flatten()
}

/// [`resolve_bearer`] for code already off the async runtime: it reads the
/// database on the calling thread.
pub fn resolve_bearer_blocking(state: &AppState, token: &str, path: &str) -> Option<AuthIdentity> {
    // A session credential is never a static, managed or OAuth token.
    if credentials::is_session_token(token) {
        return None;
    }
    let cfg = state.hub.cfg();
    if let Some((label, org_id)) = lookup_token(state, token) {
        // Human identities are hub configuration, the default organization's.
        let kind = if org_id == ua_core::DEFAULT_ORG && cfg.is_human(&label) {
            ActorKind::Human
        } else {
            ActorKind::Agent
        };
        if kind == ActorKind::Agent && retired(state, &label) {
            return None;
        }
        return Some(AuthIdentity { label, kind, verified: true, grant: None, org_id });
    }
    if !cfg.oauth_enabled || !token.starts_with(oauth::ACCESS_PREFIX) {
        return None;
    }
    let access = oauth::store::lookup_access(state, token)?;
    // Audience (RFC 8707): the hub-wide resource covers /mcp and /api; the
    // MCP resource covers /mcp only.
    let hub_wide = access.resource == oauth::issuer(cfg);
    let audience_ok = hub_wide || (access.resource == oauth::mcp_resource(cfg) && path_is(path, "/mcp"));
    // OAuth grants never act as a human, even if the configuration changed,
    // and never fall back to the `developer` default: an identity whose
    // explicit profile was removed from configuration is refused. A grant
    // carries no organization yet, so it resolves to the default one and is
    // refused for a subject another organization's agent holds.
    let reserved = ua_tools::families::agents::Reserved::of(cfg);
    let elsewhere = state
        .hub
        .db()
        .read(|c| ua_tools::families::tokens::held_outside_default(c, &reserved, &access.subject))
        .unwrap_or(true);
    (audience_ok
        && !cfg.is_human(&access.subject)
        && cfg.explicit_profile(&access.subject).is_some()
        && !elsewhere
        && !retired(state, &access.subject))
    .then(|| AuthIdentity::in_default(access.subject, ActorKind::Agent, true))
}

/// The paths a session credential is accepted on: each runs its registry
/// calls inside the credential's grant.
fn session_credential_path(path: &str) -> bool {
    path_is(path, "/mcp") || path_is(path, "/api/tools") || path == "/api/whoami"
}

/// Verify a `uas_` bearer for `path`: the identity, or the refusal to send.
async fn resolve_session_credential(
    state: &AppState,
    token: &str,
    path: &str,
) -> Result<AuthIdentity, Box<Response>> {
    if !session_credential_path(path) {
        let body = serde_json::json!({
            "ok": false,
            "error": "denied",
            "reason_code": "session_credential_path",
            "message": "a session credential is valid on /mcp, /api/tools and /api/whoami only",
        });
        return Err(Box::new((StatusCode::FORBIDDEN, axum::Json(body)).into_response()));
    }
    let (hub, token) = (state.hub.clone(), token.to_string());
    match tokio::task::spawn_blocking(move || credentials::verify(&hub, &token)).await {
        Ok(Ok(v)) => Ok(AuthIdentity {
            label: v.subject,
            kind: ActorKind::Agent,
            verified: true,
            grant: Some(Arc::new(v.grant)),
            org_id: v.org,
        }),
        Ok(Err(refused)) => Err(Box::new(unauthorized(
            state,
            Some("invalid_token"),
            &format!("session credential refused: {}", refused.check),
        ))),
        Err(_) => {
            Err(Box::new(unauthorized(state, Some("invalid_token"), "session credential refused: internal")))
        }
    }
}

fn is_public_path(path: &str) -> bool {
    path == "/healthz"
        || path.starts_with("/.well-known/")
        || path_is(path, "/oauth")
        || path_is(path, "/login")
        || path == "/logout"
        // GitHub signs its deliveries instead (see `github_api`): the default
        // organization's route and each organization's one segment below it.
        || crate::github_api::is_webhook_path(path)
        // Slack signs its requests too (see `slack_api`); 404 unless mounted.
        || crate::slack_api::is_slack_path(path)
}

/// Enforce the single-organization rule for unauthenticated mode (`enforce_auth = false`).
///
/// When `enforce_auth` is `false`, `orgs` must hold no organization other than
/// `default` (active or suspended). Counts are read directly from the store,
/// never from a caller, and any unreadable or missing `orgs` table fails
/// closed.
pub fn check_auth_policy(hub: &ua_tools::Hub) -> ua_core::UaResult<()> {
    if hub.cfg().enforce_auth {
        return Ok(());
    }
    let counts = hub.db().read(ua_store::org::org_counts)?.ok_or_else(|| {
        ua_core::UaError::denied(
            "auth_required_multi_org",
            "refusing to run with enforce_auth = false: orgs table is missing",
        )
    })?;
    if counts.has_non_default() {
        return Err(ua_core::UaError::denied(
            "auth_required_multi_org",
            format!(
                "refusing to run with enforce_auth = false while the store holds {} organizations \
                 ({} non-default, active or suspended): unauthenticated mode is single-organization \
                 only; set enforce_auth = true (UA_ENFORCE_AUTH=true)",
                counts.total, counts.non_default
            ),
        ));
    }
    Ok(())
}

/// TTL for caching a passing (`Ok(())`) single-organization auth-policy check
/// on live unauthenticated event streams. Keeps per-event delivery from taking
/// a pooled reader on every broadcast while bounding any stale window to ~1 s
/// (HTTP requests and `StreamAuth::recheck` still bypass the cache, and any
/// failure invalidates it immediately).
pub const AUTH_POLICY_CACHE_TTL: Duration = Duration::from_secs(1);

/// Short-TTL cache for the single-organization auth-policy check on live
/// unauthenticated event streams. Only `Ok(())` is cached; failures are never
/// cached and immediately clear any cached entry.
pub struct AuthPolicyCache {
    ttl: Duration,
    last_ok: Mutex<Option<Instant>>,
}

impl AuthPolicyCache {
    pub fn new() -> Self {
        Self::with_ttl(AUTH_POLICY_CACHE_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self { ttl, last_ok: Mutex::new(None) }
    }

    /// True when a passing check completed within `ttl`.
    pub fn is_fresh(&self) -> bool {
        let guard = self.last_ok.lock().unwrap_or_else(|e| e.into_inner());
        guard.is_some_and(|at| at.elapsed() < self.ttl)
    }

    /// Record a passing single-organization check.
    pub fn record_ok(&self) {
        *self.last_ok.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    }

    /// Clear any cached passing check immediately (called on any failure).
    pub fn invalidate(&self) {
        *self.last_ok.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

impl Default for AuthPolicyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Fixed response message for refused unauthenticated requests so internal
/// store errors or organization metadata never leak to anonymous callers.
const UNAUTH_REFUSED_MSG: &str =
    "authentication required: unauthenticated mode is single-organization only; set enforce_auth = true";

/// Request-time fail-closed check for unauthenticated non-public HTTP requests
/// when `enforce_auth` is `false`. Re-reads `orgs` from the store (uncached)
/// so creating a second organization while the hub is running closes anonymous
/// HTTP access immediately with zero window.
async fn check_unauthenticated_allowed(state: &AppState) -> Result<(), &'static str> {
    let hub = state.hub.clone();
    match tokio::task::spawn_blocking(move || check_auth_policy(&hub)).await {
        Ok(Ok(())) => {
            state.auth_policy.record_ok();
            Ok(())
        }
        Ok(Err(e)) => {
            state.auth_policy.invalidate();
            tracing::warn!(error = %e, "refusing unauthenticated request");
            Err(UNAUTH_REFUSED_MSG)
        }
        Err(e) => {
            state.auth_policy.invalidate();
            tracing::warn!(error = %e, "refusing unauthenticated request: auth policy check task failed");
            Err(UNAUTH_REFUSED_MSG)
        }
    }
}

pub async fn authenticate(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let public = is_public_path(&path);
    let cookie_scope = path_is(&path, "/ui") || path_is(&path, "/api");
    let identity = if let Some(tok) =
        bearer(req.headers()).filter(|t| !public && credentials::is_session_token(t))
    {
        match resolve_session_credential(&state, tok, &path).await {
            Ok(id) => id,
            Err(resp) => return *resp,
        }
    } else if let Some(tok) = bearer(req.headers()) {
        match resolve_bearer(&state, tok, &path).await {
            Some(id) => id,
            None if public => anonymous(),
            None => return unauthorized(&state, Some("invalid_token"), "invalid token"),
        }
    } else if let Some(session) =
        if cookie_scope { login::session_from_headers(&state, req.headers()).await } else { None }
    {
        if login::is_unsafe(req.method()) {
            let provided = req.headers().get(CSRF_HEADER).and_then(|v| v.to_str().ok());
            if !login::csrf_matches(&session, provided) {
                let body = serde_json::json!({ "ok": false, "error": "csrf", "message": "missing or wrong X-CSRF-Token" });
                return (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
            }
        }
        // A Control Center session is a configured human, the default
        // organization's: refused, like a static token, while a row of
        // another organization holds its label. Defence in depth: it cannot
        // fire today, because a human identity is a configuration-reserved
        // label (`agents::Reserved`), which `held_outside_default` always
        // answers as the default organization's. It stays so a later change
        // to the reservation cannot quietly let such a session in.
        if held_outside_default(&state, &session.label).await {
            return unauthorized(&state, Some("invalid_token"), "session refused");
        }
        let id = AuthIdentity::in_default(session.label.clone(), ActorKind::Human, true);
        req.extensions_mut().insert(session);
        id
    } else if state.hub.cfg().enforce_auth && !public {
        if path_is(&path, "/ui") && matches!(*req.method(), Method::GET | Method::HEAD) {
            let next = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
            let q = url::form_urlencoded::Serializer::new(String::new()).append_pair("next", &next).finish();
            return Redirect::to(&format!("/login?{q}")).into_response();
        }
        return unauthorized(&state, None, "bearer token required");
    } else if !public {
        match check_unauthenticated_allowed(&state).await {
            Ok(()) => anonymous(),
            Err(msg) => return unauthorized(&state, None, msg),
        }
    } else {
        anonymous()
    };
    req.extensions_mut().insert(identity);
    next.run(req).await
}

fn anonymous() -> AuthIdentity {
    AuthIdentity::in_default(LOCAL_LABEL, ActorKind::Anonymous, false)
}

fn unauthorized(state: &AppState, error: Option<&str>, msg: &str) -> Response {
    let body = serde_json::json!({ "ok": false, "error": "unauthenticated", "message": msg });
    let challenge = oauth::www_authenticate(state.hub.cfg(), error);
    (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, challenge)], axum::Json(body)).into_response()
}

/// Build the governed caller for one request, in the organization the
/// credential resolved to ([`AuthIdentity::org_id`]): the resolver is the one
/// source of a caller's organization besides the hub's own jobs.
pub fn caller_for(
    state: &AppState,
    id: &AuthIdentity,
    session_key: Option<String>,
    transport: ua_core::identity::Transport,
) -> ua_core::Caller {
    // A session credential runs under its fixed profile; no client session
    // key can rebind it.
    if id.grant.is_some() {
        return ua_core::Caller {
            label: id.label.clone(),
            kind: id.kind,
            profile: Profile::AcpSession,
            enforce_profile: true,
            session_key: None,
            transport,
            org_id: id.org_id.clone(),
        };
    }
    let profile =
        ua_tools::sessions::resolve_profile(&state.hub, &id.org_id, &id.label, session_key.as_deref());
    ua_core::Caller {
        label: id.label.clone(),
        kind: id.kind,
        profile,
        // Only verified callers are filtered; local anonymous use keeps the
        // full surface, as stdio does.
        enforce_profile: id.verified,
        session_key,
        transport,
        org_id: id.org_id.clone(),
    }
}

/// Client session key: the legacy MCP session header, else `X-UA-Session`.
pub fn session_key(headers: &HeaderMap) -> Option<String> {
    ["mcp-session-id", "x-ua-session"]
        .iter()
        .find_map(|h| headers.get(*h).and_then(|v| v.to_str().ok()))
        .map(|s| s.chars().take(128).collect())
}
