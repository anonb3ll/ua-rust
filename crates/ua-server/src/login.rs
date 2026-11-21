//! Browser sign-in for the Control Center.
//!
//! A human signs in with a passkey (WebAuthn, `webauthn-rs`). On a fresh
//! install there is no passkey yet, so `ua login-link <label>` prints a
//! short-lived, single-use URL that opens one session; the human then
//! registers a passkey at `/login/passkeys`.
//!
//! A session is a random id in an encrypted (`PrivateCookieJar`) cookie named
//! `ua_session`: `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` unless
//! `ui_cookie_secure` is off. The database keeps only its SHA-256 digest plus
//! a per-session CSRF token. The auth middleware honours the cookie on `/ui`
//! and `/api` only, never on `/mcp`, and requires the `X-CSRF-Token` header
//! on every state-changing cookie request. See `docs/auth.md`.
//!
//! Routes:
//! - `GET  /login`                          sign-in page
//! - `POST /login/passkey/start|finish`     passkey assertion ceremony
//! - `GET|POST /login/link`                 one-time login link (POST consumes)
//! - `POST /logout`
//! - `GET  /login/passkeys`                 manage passkeys (signed in)
//! - `POST /login/passkeys/register/start|finish`
//! - `GET  /api/session`                    who is signed in, plus the CSRF token

use std::sync::RwLock;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Json, Router};
use axum_extra::extract::cookie::{Cookie, Key, PrivateCookieJar, SameSite};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};
use ua_tools::Hub;
use ua_tools::families::tokens::digest;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Url, Uuid, Webauthn, WebauthnBuilder,
};

use crate::AppState;
use crate::auth::AuthIdentity;
use crate::oauth::{html_escape, html_page, random_token, ts_in};

/// Name of the browser session cookie.
pub const SESSION_COOKIE: &str = "ua_session";
/// Header carrying the CSRF token on state-changing cookie requests.
pub const CSRF_HEADER: &str = "x-csrf-token";
const SESSION_PREFIX: &str = "uis_";
const LINK_PREFIX: &str = "ual_";
const CEREMONY_TTL_SECS: i64 = 300;

/// A live browser session, inserted as a request extension on cookie-authenticated
/// `/ui` and `/api` requests. Templates render `csrf_token` into forms or an
/// `hx-headers` attribute.
#[derive(Debug, Clone)]
pub struct UiSession {
    pub label: String,
    pub csrf_token: String,
    pub expires_at: String,
    pub(crate) id_hash: String,
}

/// The CSRF token of the request's browser session, if it has one. The UI
/// calls this from a handler that received the request extensions.
pub fn csrf_token(ext: &axum::http::Extensions) -> Option<&str> {
    ext.get::<UiSession>().map(|s| s.csrf_token.as_str())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(login_page))
        .route("/login/passkey/start", post(passkey_login_start))
        .route("/login/passkey/finish", post(passkey_login_finish))
        .route("/login/link", get(link_page).post(link_consume))
        .route("/logout", post(logout))
        .route("/login/passkeys", get(passkeys_page))
        .route("/login/passkeys/register/start", post(passkey_register_start))
        .route("/login/passkeys/register/finish", post(passkey_register_finish))
        .route("/api/session", get(api_session))
        .route(LOGIN_JS_PATH, get(login_js))
        .route(PAGE_CSS_PATH, get(page_css))
}

// ---------------------------------------------------------------- sessions

/// How long the in-memory copy of the cookie key is trusted before it is
/// read again. Bounds how long a key replaced outside this process (the
/// `ui_keys` row deleted or rewritten) keeps being used.
pub const COOKIE_KEY_TTL: Duration = Duration::from_secs(60);

/// The cookie encryption key, cached in [`AppState`] so an authenticated UI
/// request does not query `ui_keys` to *read* a cookie. The key is created
/// on first use and re-read at most every [`COOKIE_KEY_TTL`], at once after
/// [`CookieKeyCache::invalidate`], and on every sign-in: a new cookie is
/// always encrypted with the key `ui_keys` holds now, never a cached copy
/// the table no longer has.
///
/// Nothing in the hub deletes or replaces the row; rotating means deleting
/// it outside the hub (the next read creates a new key). Code that ever
/// does so in-process must call [`CookieKeyCache::invalidate`].
pub struct CookieKeyCache {
    slot: RwLock<Option<(Key, Instant)>>,
    ttl: Duration,
}

impl Default for CookieKeyCache {
    fn default() -> Self {
        Self::with_ttl(COOKIE_KEY_TTL)
    }
}

impl CookieKeyCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// A cache whose copy lapses after `ttl` (tests use a short one).
    pub fn with_ttl(ttl: Duration) -> Self {
        Self { slot: RwLock::new(None), ttl }
    }

    /// Drop the cached key; the next request reads `ui_keys` again.
    pub fn invalidate(&self) {
        *self.slot.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn fresh(&self) -> Option<Key> {
        let slot = self.slot.read().unwrap_or_else(|e| e.into_inner());
        slot.as_ref().filter(|(_, at)| at.elapsed() < self.ttl).map(|(k, _)| k.clone())
    }

    fn store(&self, key: &Key) {
        *self.slot.write().unwrap_or_else(|e| e.into_inner()) = Some((key.clone(), Instant::now()));
    }
}

fn parse_key(hexkey: &str) -> UaResult<Key> {
    let bytes = hex::decode(hexkey).map_err(|_| UaError::internal("cookie key is corrupt"))?;
    Key::try_from(bytes.as_slice()).map_err(|_| UaError::internal("cookie key is too short"))
}

/// Read the cookie key from `ui_keys`, creating it on first use. Blocking.
fn load_cookie_key(hub: &Hub) -> UaResult<Key> {
    let read = |hub: &Hub| {
        hub.db().read(|c| {
            Ok(c.query_row("SELECT key_hex FROM ui_keys WHERE name = 'cookie'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?)
        })
    };
    if let Some(hexkey) = read(hub)? {
        return parse_key(&hexkey);
    }
    let fresh = hex::encode(Key::generate().master());
    hub.db().write(|tx| {
        tx.execute(
            "INSERT OR IGNORE INTO ui_keys (name, key_hex, created_at) VALUES ('cookie', ?1, ?2)",
            params![fresh, ua_core::time::now()],
        )?;
        Ok(())
    })?;
    // Another process may have won the insert: use whichever key is stored.
    parse_key(&read(hub)?.ok_or_else(|| UaError::internal("cookie key missing"))?)
}

/// The cookie key: the cached copy, else read off the async runtime.
async fn cookie_key(state: &AppState) -> UaResult<Key> {
    if let Some(k) = state.cookie_key.fresh() {
        return Ok(k);
    }
    stored_cookie_key(state).await
}

/// The key `ui_keys` holds now (created if missing), read off the async
/// runtime; it replaces the cached copy. Used to encrypt every new cookie.
async fn stored_cookie_key(state: &AppState) -> UaResult<Key> {
    let hub = state.hub.clone();
    let key = tokio::task::spawn_blocking(move || load_cookie_key(&hub))
        .await
        .map_err(|e| UaError::internal(format!("blocking task failed: {e}")))??;
    state.cookie_key.store(&key);
    Ok(key)
}

/// [`cookie_key`] for code already off the async runtime.
fn cookie_key_blocking(state: &AppState) -> UaResult<Key> {
    if let Some(k) = state.cookie_key.fresh() {
        return Ok(k);
    }
    let key = load_cookie_key(&state.hub)?;
    state.cookie_key.store(&key);
    Ok(key)
}

/// The digest of the session id in the request's (decrypted) cookie.
fn session_id_hash(headers: &HeaderMap, key: Key) -> Option<String> {
    let jar = PrivateCookieJar::from_headers(headers, key);
    let raw = jar.get(SESSION_COOKIE)?.value().to_string();
    Some(digest(&raw))
}

type SessionRow = (String, String, String);

fn session_row(c: &rusqlite::Connection, id_hash: &str) -> UaResult<Option<SessionRow>> {
    Ok(c.query_row(
        "SELECT label, csrf, expires_at FROM ui_sessions WHERE id_hash = ?1 AND revoked_at IS NULL \
         AND expires_at > ?2",
        params![id_hash, ua_core::time::now()],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
    )
    .optional()?)
}

fn live_session(state: &AppState, row: SessionRow, id_hash: String) -> Option<UiSession> {
    let (label, csrf_token, expires_at) = row;
    state.hub.cfg().is_human(&label).then_some(UiSession { label, csrf_token, expires_at, id_hash })
}

/// The live session named by the request's cookie. Only configured human
/// identities hold sessions; a label removed from `human_identities` loses
/// its sessions at once. The cookie key comes from the in-memory cache and
/// the session row is read off the async runtime.
pub async fn session_from_headers(state: &AppState, headers: &HeaderMap) -> Option<UiSession> {
    if !headers.contains_key(header::COOKIE) {
        return None;
    }
    let key = cookie_key(state).await.ok()?;
    let id_hash = session_id_hash(headers, key)?;
    let h = id_hash.clone();
    let row = state.hub.db().read_async(move |c| session_row(c, &h)).await.ok().flatten()?;
    live_session(state, row, id_hash)
}

/// [`session_from_headers`] for code already off the async runtime (the
/// event stream's periodic re-check).
pub fn session_from_headers_blocking(state: &AppState, headers: &HeaderMap) -> Option<UiSession> {
    if !headers.contains_key(header::COOKIE) {
        return None;
    }
    let key = cookie_key_blocking(state).ok()?;
    let id_hash = session_id_hash(headers, key)?;
    let row = state.hub.db().read(|c| session_row(c, &id_hash)).ok().flatten()?;
    live_session(state, row, id_hash)
}

/// Constant-time CSRF check.
pub fn csrf_matches(session: &UiSession, provided: Option<&str>) -> bool {
    provided.is_some_and(|p| bool::from(p.as_bytes().ct_eq(session.csrf_token.as_bytes())))
}

/// Whether a method changes state (and so needs the CSRF header).
pub fn is_unsafe(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Open a session for `label`. Returns the raw cookie value.
async fn create_session(
    state: &AppState,
    label: &str,
    method: &str,
    headers: &HeaderMap,
) -> UaResult<String> {
    let raw = random_token(SESSION_PREFIX);
    let csrf = random_token("");
    let ttl = state.hub.cfg().ui_session_ttl_hours.clamp(1, 24 * 30) as i64 * 3600;
    let ua: Option<String> = header_str(headers, "user-agent").map(|s| s.chars().take(300).collect());
    let (hash, label, method) = (digest(&raw), label.to_string(), method.to_string());
    state
        .hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now();
            tx.execute(
                "INSERT INTO ui_sessions (id_hash, label, csrf, method, created_at, expires_at, last_seen_at, user_agent) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5, ?7)",
                params![hash, label, csrf, method, now, ts_in(ttl), ua],
            )?;
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG, "agent.ui.login", json!({ "identity": label, "method": method }))
                    .by(label.clone()),
            )?;
            Ok(())
        })
        .await?;
    Ok(raw)
}

/// A browser-session cookie (no `Max-Age`): the server-side row bounds its
/// life, and closing the browser drops it.
fn session_cookie(state: &AppState, raw: String) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, raw))
        .http_only(true)
        .secure(state.hub.cfg().ui_cookie_secure)
        .same_site(SameSite::Lax)
        .path("/")
        .build()
}

/// A response that sets a fresh session cookie.
async fn with_session(state: &AppState, raw: String, resp: Response) -> Response {
    match stored_cookie_key(state).await {
        Ok(key) => (PrivateCookieJar::new(key).add(session_cookie(state, raw)), resp).into_response(),
        Err(e) => server_error(e),
    }
}

fn clear_cookie(state: &AppState) -> String {
    let secure = if state.hub.cfg().ui_cookie_secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure}")
}

/// Mint a single-use login link for a human identity. Prints nothing; the
/// caller (the `ua login-link` CLI) shows the URL to the operator.
pub fn create_login_link(hub: &Hub, label: &str, created_by: &str) -> UaResult<String> {
    if !hub.cfg().is_human(label) {
        return Err(UaError::invalid(format!("{label} is not listed in human_identities")));
    }
    let raw = random_token(LINK_PREFIX);
    let ttl = hub.cfg().login_link_ttl_secs.clamp(30, 24 * 3600) as i64;
    let (hash, label, by) = (digest(&raw), label.to_string(), created_by.to_string());
    hub.db().write(|tx| {
        tx.execute(
            "INSERT INTO login_links (token_hash, label, created_by, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![hash, label, by, ua_core::time::now(), ts_in(ttl)],
        )?;
        ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "agent.ui.login_link_created", json!({ "identity": label })).by(by.clone()))?;
        Ok(())
    })?;
    Ok(format!("{}/login/link?token={raw}", hub.cfg().public_base_url()))
}

/// Keep post-login redirects on this site.
fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n)
            if n.starts_with('/')
                && !n.starts_with("//")
                && !n.starts_with("/\\")
                && !n.contains(['\r', '\n']) =>
        {
            n.to_string()
        }
        _ => "/ui".into(),
    }
}

fn server_error(e: UaError) -> Response {
    tracing::warn!(error = %e, "login error");
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "internal error")
}

fn json_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "ok": false, "error": code, "message": message })),
    )
        .into_response()
}

// ---------------------------------------------------------------- passkeys

/// Whether `url` is an origin browsers treat as potentially trustworthy
/// without TLS: `http://localhost` (and `*.localhost`) or a loopback address.
fn is_loopback_origin(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// A startup warning when browser sign-in cannot work at the effective
/// public origin: plain `http://` on a non-loopback host while the session
/// cookie is `Secure` (browsers drop it) or passkeys are usable (WebAuthn
/// needs a secure context). `None` when the origin is fine.
///
/// `ua serve` warns rather than refuses: bearer-token clients on `/mcp` and
/// `/api` still work over plain HTTP on a trusted network.
pub fn insecure_origin_warning(cfg: &ua_core::Config) -> Option<String> {
    let origin = url::Url::parse(&cfg.public_base_url()).ok()?;
    if origin.scheme() != "http" || is_loopback_origin(&origin) {
        return None;
    }
    let mut broken = Vec::new();
    if cfg.ui_cookie_secure {
        broken.push("browsers drop the Secure session cookie on http://, so sign-in bounces back to /login");
    }
    if !cfg.human_identities.is_empty() {
        broken.push("passkeys need a secure context (https:// or localhost)");
    }
    if broken.is_empty() {
        return None;
    }
    Some(format!(
        "the public origin {} is plain http on a non-loopback host: {}. Serve the hub over HTTPS \
         (for example a private-network TLS terminator such as `tailscale serve`, or a reverse proxy) and set \
         public_url to the https:// address; see docs/auth.md",
        origin.origin().ascii_serialization(),
        broken.join("; ")
    ))
}

fn webauthn(state: &AppState) -> Result<Webauthn, String> {
    let cfg = state.hub.cfg();
    let origin = Url::parse(&cfg.public_base_url()).map_err(|e| format!("public_url is not a URL: {e}"))?;
    let rp_id = match &cfg.webauthn_rp_id {
        Some(id) => id.clone(),
        None => origin.host_str().ok_or("public_url has no host")?.to_string(),
    };
    WebauthnBuilder::new(&rp_id, &origin)
        .and_then(|b| b.rp_name("ua-rust hub").build())
        .map_err(|e| format!("passkeys are unavailable: {e}"))
}

fn user_uuid(label: &str) -> Uuid {
    use sha2::Digest;
    let d = sha2::Sha256::digest(label.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    Uuid::from_bytes(b)
}

async fn load_passkeys(hub: &Hub, label: &str) -> UaResult<Vec<(String, Passkey)>> {
    let label = label.to_string();
    hub.db()
        .read_async(move |c| {
            let mut stmt =
                c.prepare("SELECT cred_id, passkey FROM passkeys WHERE label = ?1 ORDER BY created_at")?;
            let rows: Vec<(String, String)> =
                stmt.query_map([&label], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
            Ok(rows
                .into_iter()
                .filter_map(|(id, pk)| serde_json::from_str::<Passkey>(&pk).ok().map(|p| (id, p)))
                .collect())
        })
        .await
}

fn cred_key(p: &Passkey) -> String {
    serde_json::to_value(p.cred_id()).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

async fn save_state(
    hub: &Hub,
    kind: &str,
    label: &str,
    session_hash: Option<&str>,
    state: &impl serde::Serialize,
) -> UaResult<String> {
    let id = random_token("uaw_");
    let state_json = serde_json::to_string(state).map_err(|e| UaError::internal(e.to_string()))?;
    let (hash, kind, label, session_hash) =
        (digest(&id), kind.to_string(), label.to_string(), session_hash.map(str::to_string));
    hub.db()
        .write_async(move |tx| {
            tx.execute("DELETE FROM webauthn_states WHERE expires_at <= ?1", [ua_core::time::now()])?;
            tx.execute(
                "INSERT INTO webauthn_states (id_hash, kind, label, session_hash, state, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![hash, kind, label, session_hash, state_json, ts_in(CEREMONY_TTL_SECS)],
            )?;
            Ok(())
        })
        .await?;
    Ok(id)
}

/// Consume a ceremony state (single use). Returns `(label, state_json)`.
async fn take_state(
    hub: &Hub,
    id: &str,
    kind: &str,
    session_hash: Option<&str>,
) -> UaResult<Option<(String, String)>> {
    let (hash, kind, session_hash) = (digest(id), kind.to_string(), session_hash.map(str::to_string));
    hub.db()
        .write_async(move |tx| {
            let row: Option<(String, String, Option<String>, String)> = tx
                .query_row(
                    "SELECT label, state, session_hash, expires_at FROM webauthn_states WHERE id_hash = ?1 AND kind = ?2",
                    params![hash, kind],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            tx.execute("DELETE FROM webauthn_states WHERE id_hash = ?1", [&hash])?;
            Ok(row.and_then(|(label, state, sess, expires)| {
                (expires > ua_core::time::now() && sess == session_hash).then_some((label, state))
            }))
        })
        .await
}

#[derive(Deserialize)]
struct LoginStart {
    label: String,
}

async fn passkey_login_start(State(state): State<AppState>, Json(body): Json<LoginStart>) -> Response {
    let label = body.label.trim().to_string();
    let generic =
        || json_error(StatusCode::BAD_REQUEST, "no_passkey", "no passkey is registered for that identity");
    if !state.hub.cfg().is_human(&label) {
        return generic();
    }
    let wa = match webauthn(&state) {
        Ok(w) => w,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, "passkeys_unavailable", &e),
    };
    let keys = match load_passkeys(&state.hub, &label).await {
        Ok(k) if !k.is_empty() => k,
        Ok(_) => return generic(),
        Err(e) => return server_error(e),
    };
    let creds: Vec<Passkey> = keys.into_iter().map(|(_, p)| p).collect();
    let (options, auth_state) = match wa.start_passkey_authentication(&creds) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, "passkey_error", &e.to_string()),
    };
    match save_state(&state.hub, "login", &label, None, &auth_state).await {
        Ok(id) => Json(json!({ "ok": true, "state_id": id, "options": options })).into_response(),
        Err(e) => server_error(e),
    }
}

#[derive(Deserialize)]
struct LoginFinish {
    state_id: String,
    credential: PublicKeyCredential,
    next: Option<String>,
}

async fn passkey_login_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginFinish>,
) -> Response {
    let refused =
        || json_error(StatusCode::UNAUTHORIZED, "passkey_refused", "the passkey sign-in was not accepted");
    let wa = match webauthn(&state) {
        Ok(w) => w,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, "passkeys_unavailable", &e),
    };
    let (label, st) = match take_state(&state.hub, &body.state_id, "login", None).await {
        Ok(Some(v)) => v,
        Ok(None) => return refused(),
        Err(e) => return server_error(e),
    };
    let Ok(auth_state) = serde_json::from_str::<PasskeyAuthentication>(&st) else { return refused() };
    let result = match wa.finish_passkey_authentication(&body.credential, &auth_state) {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(identity = %label, error = %e, "passkey assertion refused");
            return refused();
        }
    };
    if !state.hub.cfg().is_human(&label) {
        return refused();
    }
    // Store the new counter / backup state on the matching credential.
    if let Ok(keys) = load_passkeys(&state.hub, &label).await {
        let updated: Vec<(String, String)> = keys
            .into_iter()
            .filter_map(|(id, mut pk)| {
                (pk.update_credential(&result) == Some(true) || pk.cred_id() == result.cred_id())
                    .then(|| (id, serde_json::to_string(&pk).unwrap_or_default()))
            })
            .collect();
        if !updated.is_empty() {
            let _ = state
                .hub
                .db()
                .write_async(move |tx| {
                    for (id, json) in &updated {
                        tx.execute(
                            "UPDATE passkeys SET passkey = ?2, last_used_at = ?3 WHERE cred_id = ?1",
                            params![id, json, ua_core::time::now()],
                        )?;
                    }
                    Ok(())
                })
                .await;
        }
    }
    match create_session(&state, &label, "passkey", &headers).await {
        Ok(raw) => {
            let next = safe_next(body.next.as_deref());
            with_session(
                &state,
                raw,
                Json(json!({ "ok": true, "identity": label, "next": next })).into_response(),
            )
            .await
        }
        Err(e) => server_error(e),
    }
}

async fn passkey_register_start(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(sess) = session_from_headers(&state, &headers).await else {
        return json_error(StatusCode::UNAUTHORIZED, "unauthenticated", "sign in first");
    };
    if !csrf_matches(&sess, header_str(&headers, CSRF_HEADER)) {
        return json_error(StatusCode::FORBIDDEN, "csrf", "missing or wrong CSRF token");
    }
    let wa = match webauthn(&state) {
        Ok(w) => w,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, "passkeys_unavailable", &e),
    };
    let exclude = load_passkeys(&state.hub, &sess.label)
        .await
        .map(|k| k.into_iter().map(|(_, p)| p.cred_id().clone()).collect::<Vec<_>>())
        .unwrap_or_default();
    let (options, reg_state) = match wa.start_passkey_registration(
        user_uuid(&sess.label),
        &sess.label,
        &sess.label,
        Some(exclude),
    ) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, "passkey_error", &e.to_string()),
    };
    match save_state(&state.hub, "register", &sess.label, Some(&sess.id_hash), &reg_state).await {
        Ok(id) => Json(json!({ "ok": true, "state_id": id, "options": options })).into_response(),
        Err(e) => server_error(e),
    }
}

#[derive(Deserialize)]
struct RegisterFinish {
    state_id: String,
    credential: RegisterPublicKeyCredential,
    name: Option<String>,
}

async fn passkey_register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterFinish>,
) -> Response {
    let Some(sess) = session_from_headers(&state, &headers).await else {
        return json_error(StatusCode::UNAUTHORIZED, "unauthenticated", "sign in first");
    };
    if !csrf_matches(&sess, header_str(&headers, CSRF_HEADER)) {
        return json_error(StatusCode::FORBIDDEN, "csrf", "missing or wrong CSRF token");
    }
    let wa = match webauthn(&state) {
        Ok(w) => w,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, "passkeys_unavailable", &e),
    };
    let st = match take_state(&state.hub, &body.state_id, "register", Some(&sess.id_hash)).await {
        Ok(Some((label, st))) if label == sess.label => st,
        Ok(_) => return json_error(StatusCode::BAD_REQUEST, "expired", "registration expired; start again"),
        Err(e) => return server_error(e),
    };
    let Ok(reg_state) = serde_json::from_str::<PasskeyRegistration>(&st) else {
        return json_error(StatusCode::BAD_REQUEST, "expired", "registration expired; start again");
    };
    let passkey = match wa.finish_passkey_registration(&body.credential, &reg_state) {
        Ok(p) => p,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, "passkey_refused", &e.to_string()),
    };
    let name: String = body.name.unwrap_or_default().chars().filter(|c| !c.is_control()).take(60).collect();
    let (id, json, label) =
        (cred_key(&passkey), serde_json::to_string(&passkey).unwrap_or_default(), sess.label);
    let res = state
        .hub
        .db()
        .write_async(move |tx| {
            tx.execute(
                "INSERT INTO passkeys (cred_id, label, name, passkey, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, label, (!name.trim().is_empty()).then_some(name.trim()), json, ua_core::time::now()],
            )?;
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG, "agent.ui.passkey_registered", json!({ "identity": label }))
                    .by(label.clone()),
            )?;
            Ok(())
        })
        .await;
    match res {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(UaError::Conflict(_)) => {
            json_error(StatusCode::CONFLICT, "duplicate", "that passkey is already registered")
        }
        Err(e) => server_error(e),
    }
}

// ---------------------------------------------------------------- login link

#[derive(Deserialize)]
struct LinkQuery {
    token: Option<String>,
}

/// Show a confirmation button. The GET never consumes the link, so a link
/// preview or prefetch cannot burn it.
async fn link_page(Query(q): Query<LinkQuery>) -> Response {
    let token = q.token.unwrap_or_default();
    let body = format!(
        "<h1>Sign in to the hub</h1><p>This one-time link opens a Control Center session in this browser.</p>\
<form method=\"post\" action=\"/login/link\"><input type=\"hidden\" name=\"token\" value=\"{}\">\
<button type=\"submit\">Continue</button></form>",
        html_escape(&token)
    );
    html_page(StatusCode::OK, "Sign in", &body)
}

#[derive(Deserialize)]
struct LinkForm {
    token: String,
}

async fn link_consume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<LinkForm>,
) -> Response {
    let hash = digest(f.token.trim());
    let consumed = state
        .hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now();
            let label: Option<String> = tx
                .query_row(
                    "SELECT label FROM login_links WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
                    params![hash, now],
                    |r| r.get(0),
                )
                .optional()?;
            if label.is_some() {
                tx.execute("UPDATE login_links SET used_at = ?2 WHERE token_hash = ?1", params![hash, now])?;
            }
            Ok(label)
        })
        .await;
    let label = match consumed {
        Ok(Some(l)) if state.hub.cfg().is_human(&l) => l,
        Ok(_) => {
            return html_page(
                StatusCode::BAD_REQUEST,
                "Link expired",
                "<h1>This link is no longer valid</h1><p>Login links work once and expire quickly. Run \
                 <code>ua login-link &lt;label&gt;</code> for a new one.</p>",
            );
        }
        Err(e) => return server_error(e),
    };
    match create_session(&state, &label, "login_link", &headers).await {
        Ok(raw) => with_session(&state, raw, Redirect::to("/login/passkeys").into_response()).await,
        Err(e) => server_error(e),
    }
}

// ---------------------------------------------------------------- logout, session

#[derive(Deserialize)]
struct LogoutForm {
    csrf: Option<String>,
}

async fn logout(State(state): State<AppState>, headers: HeaderMap, Form(f): Form<LogoutForm>) -> Response {
    if let Some(sess) = session_from_headers(&state, &headers).await {
        let provided = header_str(&headers, CSRF_HEADER).or(f.csrf.as_deref());
        if !csrf_matches(&sess, provided) {
            return json_error(StatusCode::FORBIDDEN, "csrf", "missing or wrong CSRF token");
        }
        let (hash, label) = (sess.id_hash.clone(), sess.label.clone());
        let res = state
            .hub
            .db()
            .write_async(move |tx| {
                tx.execute(
                    "UPDATE ui_sessions SET revoked_at = ?2 WHERE id_hash = ?1 AND revoked_at IS NULL",
                    params![hash, ua_core::time::now()],
                )?;
                ledger::append(
                    tx,
                    EventInput::new(ua_core::DEFAULT_ORG, "agent.ui.logout", json!({ "identity": label }))
                        .by(label.clone()),
                )?;
                Ok(())
            })
            .await;
        if let Err(e) = res {
            return server_error(e);
        }
    }
    ([(header::SET_COOKIE, clear_cookie(&state))], Redirect::to("/login")).into_response()
}

/// `GET /api/session`: the caller's identity and, for a cookie session, its
/// CSRF token and the header to send it in.
async fn api_session(
    Extension(id): Extension<AuthIdentity>,
    session: Option<Extension<UiSession>>,
) -> Json<Value> {
    let mut v = json!({
        "identity": id.label,
        "kind": id.kind,
        "verified": id.verified,
        "auth": if session.is_some() { "cookie" } else if id.verified { "bearer" } else { "none" },
        "csrf_header": "X-CSRF-Token",
    });
    if let Some(Extension(s)) = session {
        v["csrf_token"] = json!(s.csrf_token);
        v["expires_at"] = json!(s.expires_at);
    }
    Json(v)
}

// ---------------------------------------------------------------- pages

/// The sign-in pages' script and the shared page style, served from the hub
/// so the pages carry no inline script or style (see the CSP in
/// [`crate::oauth::html_page`]).
pub const LOGIN_JS_PATH: &str = "/login/assets/login.js";
pub const PAGE_CSS_PATH: &str = "/login/assets/page.css";
const LOGIN_JS: &str = include_str!("../assets/login/login.js");
const PAGE_CSS: &str = include_str!("../assets/login/page.css");

fn asset(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-cache"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

async fn login_js() -> Response {
    asset("text/javascript; charset=utf-8", LOGIN_JS)
}

async fn page_css() -> Response {
    asset("text/css; charset=utf-8", PAGE_CSS)
}

#[derive(Deserialize)]
struct LoginQuery {
    next: Option<String>,
}

async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Response {
    let next = safe_next(q.next.as_deref());
    if session_from_headers(&state, &headers).await.is_some() {
        return Redirect::to(&next).into_response();
    }
    let body = format!(
        "<h1>Sign in</h1><label for=\"label\">Identity</label><input id=\"label\" autocomplete=\"username webauthn\" \
value=\"{first}\"><button id=\"go\" type=\"button\" data-next=\"{next}\">Sign in with a passkey</button>\
<p id=\"msg\" class=\"hint\"></p>\
<p class=\"hint\">First sign-in on a new hub: run <code>ua login-link &lt;label&gt;</code> on the hub host and open \
the link it prints, then register a passkey.</p><script src=\"{LOGIN_JS_PATH}\" defer></script>",
        first = html_escape(state.hub.cfg().human_identities.first().map(String::as_str).unwrap_or("")),
        next = html_escape(&next),
    );
    html_page(StatusCode::OK, "Sign in", &body)
}

async fn passkeys_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(sess) = session_from_headers(&state, &headers).await else {
        return Redirect::to("/login?next=/login/passkeys").into_response();
    };
    let label = sess.label.clone();
    let keys: Vec<(String, Option<String>, String, Option<String>)> = state
        .hub
        .db()
        .read_async(move |c| {
            let mut stmt =
                c.prepare("SELECT cred_id, name, created_at, last_used_at FROM passkeys WHERE label = ?1 ORDER BY created_at")?;
            Ok(stmt
                .query_map([&label], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<_, _>>()?)
        })
        .await
        .unwrap_or_default();
    let list: String = if keys.is_empty() {
        "<p class=\"hint\">No passkey yet. Register one so you can sign in without a login link.</p>".into()
    } else {
        keys.iter()
            .map(|(_, name, created, used)| {
                format!(
                    "<li>{} <span class=\"hint\">added {}, last used {}</span></li>",
                    html_escape(name.as_deref().unwrap_or("passkey")),
                    html_escape(created),
                    html_escape(used.as_deref().unwrap_or("never"))
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let body = format!(
        "<h1>Passkeys for {label}</h1><ul>{list}</ul><label for=\"name\">Name for a new passkey</label>\
<input id=\"name\" placeholder=\"laptop\"><button id=\"add\" type=\"button\" data-csrf=\"{csrf}\">Register a passkey</button>\
<p id=\"msg\" class=\"hint\"></p><p><a href=\"/ui\">Open the Control Center</a></p>\
<form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
<button class=\"secondary\" type=\"submit\">Sign out</button></form><script src=\"{LOGIN_JS_PATH}\" defer></script>",
        label = html_escape(&sess.label),
        csrf = html_escape(&sess.csrf_token),
    );
    html_page(StatusCode::OK, "Passkeys", &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_stays_on_site() {
        assert_eq!(safe_next(Some("/ui/tasks")), "/ui/tasks");
        assert_eq!(safe_next(Some("//evil.example.com")), "/ui");
        assert_eq!(safe_next(Some("https://evil.example.com")), "/ui");
        assert_eq!(safe_next(Some("/\\evil.example.com")), "/ui");
        assert_eq!(safe_next(None), "/ui");
    }

    #[test]
    fn plain_http_remote_origin_is_flagged() {
        let mut cfg = ua_core::Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        // Default: http://127.0.0.1:8765 is loopback, a secure context.
        assert!(insecure_origin_warning(&cfg).is_none());
        for ok in ["http://localhost:8765", "http://[::1]:8765", "https://hub.example.com"] {
            cfg.public_url = Some(ok.into());
            assert!(insecure_origin_warning(&cfg).is_none(), "{ok}");
        }
        cfg.public_url = Some("http://hub.example.com".into());
        let w = insecure_origin_warning(&cfg).expect("warns");
        assert!(w.contains("Secure session cookie") && w.contains("passkeys"), "{w}");
        // Bound to every interface without a public_url: http://0.0.0.0:8765.
        cfg.public_url = None;
        cfg.bind = "0.0.0.0:8765".parse().unwrap();
        assert!(insecure_origin_warning(&cfg).is_some());
        // Nothing browser-facing is on: no warning.
        cfg.ui_cookie_secure = false;
        cfg.human_identities.clear();
        assert!(insecure_origin_warning(&cfg).is_none());
    }
}
