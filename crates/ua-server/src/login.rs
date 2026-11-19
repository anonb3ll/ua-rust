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
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Url,
    Uuid, Webauthn, WebauthnBuilder,
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
}

// ---------------------------------------------------------------- sessions

/// The cookie encryption key, created on first use and kept in `ui_keys`.
fn cookie_key(hub: &Hub) -> UaResult<Key> {
    let read = |hub: &Hub| {
        hub.db().read(|c| {
            Ok(c.query_row("SELECT key_hex FROM ui_keys WHERE name = 'cookie'", [], |r| r.get::<_, String>(0))
                .optional()?)
        })
    };
    if let Some(hexkey) = read(hub)? {
        let bytes = hex::decode(hexkey).map_err(|_| UaError::internal("cookie key is corrupt"))?;
        return Key::try_from(bytes.as_slice()).map_err(|_| UaError::internal("cookie key is too short"));
    }
    let fresh = hex::encode(Key::generate().master());
    hub.db().write(|tx| {
        tx.execute(
            "INSERT OR IGNORE INTO ui_keys (name, key_hex, created_at) VALUES ('cookie', ?1, ?2)",
            params![fresh, ua_core::time::now()],
        )?;
        Ok(())
    })?;
    let hexkey = read(hub)?.ok_or_else(|| UaError::internal("cookie key missing"))?;
    let bytes = hex::decode(hexkey).map_err(|_| UaError::internal("cookie key is corrupt"))?;
    Key::try_from(bytes.as_slice()).map_err(|_| UaError::internal("cookie key is too short"))
}

/// The live session named by the request's cookie. Only configured human
/// identities hold sessions; a label removed from `human_identities` loses
/// its sessions at once.
pub fn session_from_headers(state: &AppState, headers: &HeaderMap) -> Option<UiSession> {
    if !headers.contains_key(header::COOKIE) {
        return None;
    }
    let key = cookie_key(&state.hub).ok()?;
    let jar = PrivateCookieJar::from_headers(headers, key);
    let raw = jar.get(SESSION_COOKIE)?.value().to_string();
    let id_hash = digest(&raw);
    let row = state
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT label, csrf, expires_at FROM ui_sessions WHERE id_hash = ?1 AND revoked_at IS NULL \
                 AND expires_at > ?2",
                params![id_hash, ua_core::time::now()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
            )
            .optional()?)
        })
        .ok()
        .flatten()?;
    let (label, csrf_token, expires_at) = row;
    state.hub.cfg().is_human(&label).then_some(UiSession { label, csrf_token, expires_at, id_hash })
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
fn create_session(state: &AppState, label: &str, method: &str, headers: &HeaderMap) -> UaResult<String> {
    let raw = random_token(SESSION_PREFIX);
    let csrf = random_token("");
    let ttl = state.hub.cfg().ui_session_ttl_hours.clamp(1, 24 * 30) as i64 * 3600;
    let ua: Option<String> = header_str(headers, "user-agent").map(|s| s.chars().take(300).collect());
    let (hash, label, method) = (digest(&raw), label.to_string(), method.to_string());
    state.hub.db().write(|tx| {
        let now = ua_core::time::now();
        tx.execute(
            "INSERT INTO ui_sessions (id_hash, label, csrf, method, created_at, expires_at, last_seen_at, user_agent) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5, ?7)",
            params![hash, label, csrf, method, now, ts_in(ttl), ua],
        )?;
        ledger::append(tx, EventInput::new("agent.ui.login", json!({ "identity": label, "method": method })).by(label.clone()))?;
        Ok(())
    })?;
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
fn with_session(state: &AppState, raw: String, resp: Response) -> Response {
    match cookie_key(&state.hub) {
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
        ledger::append(tx, EventInput::new("agent.ui.login_link_created", json!({ "identity": label })).by(by.clone()))?;
        Ok(())
    })?;
    Ok(format!("{}/login/link?token={raw}", hub.cfg().public_base_url()))
}

/// Keep post-login redirects on this site.
fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.starts_with("/\\") && !n.contains(['\r', '\n']) => {
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
    (status, [(header::CACHE_CONTROL, "no-store")], Json(json!({ "ok": false, "error": code, "message": message })))
        .into_response()
}

// ---------------------------------------------------------------- passkeys

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

fn load_passkeys(hub: &Hub, label: &str) -> UaResult<Vec<(String, Passkey)>> {
    hub.db().read(|c| {
        let mut stmt = c.prepare("SELECT cred_id, passkey FROM passkeys WHERE label = ?1 ORDER BY created_at")?;
        let rows: Vec<(String, String)> =
            stmt.query_map([label], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(id, pk)| serde_json::from_str::<Passkey>(&pk).ok().map(|p| (id, p)))
            .collect())
    })
}

fn cred_key(p: &Passkey) -> String {
    serde_json::to_value(p.cred_id()).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn save_state(
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
    hub.db().write(|tx| {
        tx.execute("DELETE FROM webauthn_states WHERE expires_at <= ?1", [ua_core::time::now()])?;
        tx.execute(
            "INSERT INTO webauthn_states (id_hash, kind, label, session_hash, state, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![hash, kind, label, session_hash, state_json, ts_in(CEREMONY_TTL_SECS)],
        )?;
        Ok(())
    })?;
    Ok(id)
}

/// Consume a ceremony state (single use). Returns `(label, state_json)`.
fn take_state(hub: &Hub, id: &str, kind: &str, session_hash: Option<&str>) -> UaResult<Option<(String, String)>> {
    let (hash, kind, session_hash) = (digest(id), kind.to_string(), session_hash.map(str::to_string));
    hub.db().write(|tx| {
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
}

#[derive(Deserialize)]
struct LoginStart {
    label: String,
}

async fn passkey_login_start(State(state): State<AppState>, Json(body): Json<LoginStart>) -> Response {
    let label = body.label.trim().to_string();
    let generic = || json_error(StatusCode::BAD_REQUEST, "no_passkey", "no passkey is registered for that identity");
    if !state.hub.cfg().is_human(&label) {
        return generic();
    }
    let wa = match webauthn(&state) {
        Ok(w) => w,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, "passkeys_unavailable", &e),
    };
    let keys = match load_passkeys(&state.hub, &label) {
        Ok(k) if !k.is_empty() => k,
        Ok(_) => return generic(),
        Err(e) => return server_error(e),
    };
    let creds: Vec<Passkey> = keys.into_iter().map(|(_, p)| p).collect();
    let (options, auth_state) = match wa.start_passkey_authentication(&creds) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, "passkey_error", &e.to_string()),
    };
    match save_state(&state.hub, "login", &label, None, &auth_state) {
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
    let refused = || json_error(StatusCode::UNAUTHORIZED, "passkey_refused", "the passkey sign-in was not accepted");
    let wa = match webauthn(&state) {
        Ok(w) => w,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, "passkeys_unavailable", &e),
    };
    let (label, st) = match take_state(&state.hub, &body.state_id, "login", None) {
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
    if let Ok(keys) = load_passkeys(&state.hub, &label) {
        for (id, mut pk) in keys {
            if pk.update_credential(&result) == Some(true) || pk.cred_id() == result.cred_id() {
                let json = serde_json::to_string(&pk).unwrap_or_default();
                let _ = state.hub.db().write(|tx| {
                    tx.execute(
                        "UPDATE passkeys SET passkey = ?2, last_used_at = ?3 WHERE cred_id = ?1",
                        params![id, json, ua_core::time::now()],
                    )?;
                    Ok(())
                });
            }
        }
    }
    match create_session(&state, &label, "passkey", &headers) {
        Ok(raw) => {
            let next = safe_next(body.next.as_deref());
            with_session(&state, raw, Json(json!({ "ok": true, "identity": label, "next": next })).into_response())
        }
        Err(e) => server_error(e),
    }
}

async fn passkey_register_start(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(sess) = session_from_headers(&state, &headers) else {
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
        .map(|k| k.into_iter().map(|(_, p)| p.cred_id().clone()).collect::<Vec<_>>())
        .unwrap_or_default();
    let (options, reg_state) =
        match wa.start_passkey_registration(user_uuid(&sess.label), &sess.label, &sess.label, Some(exclude)) {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, "passkey_error", &e.to_string()),
        };
    match save_state(&state.hub, "register", &sess.label, Some(&sess.id_hash), &reg_state) {
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
    let Some(sess) = session_from_headers(&state, &headers) else {
        return json_error(StatusCode::UNAUTHORIZED, "unauthenticated", "sign in first");
    };
    if !csrf_matches(&sess, header_str(&headers, CSRF_HEADER)) {
        return json_error(StatusCode::FORBIDDEN, "csrf", "missing or wrong CSRF token");
    }
    let wa = match webauthn(&state) {
        Ok(w) => w,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, "passkeys_unavailable", &e),
    };
    let st = match take_state(&state.hub, &body.state_id, "register", Some(&sess.id_hash)) {
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
    let (id, json, label) = (cred_key(&passkey), serde_json::to_string(&passkey).unwrap_or_default(), sess.label);
    let res = state.hub.db().write(|tx| {
        tx.execute(
            "INSERT INTO passkeys (cred_id, label, name, passkey, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, label, (!name.trim().is_empty()).then_some(name.trim()), json, ua_core::time::now()],
        )?;
        ledger::append(tx, EventInput::new("agent.ui.passkey_registered", json!({ "identity": label })).by(label.clone()))?;
        Ok(())
    });
    match res {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(UaError::Conflict(_)) => json_error(StatusCode::CONFLICT, "duplicate", "that passkey is already registered"),
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

async fn link_consume(State(state): State<AppState>, headers: HeaderMap, Form(f): Form<LinkForm>) -> Response {
    let hash = digest(f.token.trim());
    let consumed = state.hub.db().write(|tx| {
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
    });
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
    match create_session(&state, &label, "login_link", &headers) {
        Ok(raw) => with_session(&state, raw, Redirect::to("/login/passkeys").into_response()),
        Err(e) => server_error(e),
    }
}

// ---------------------------------------------------------------- logout, session

#[derive(Deserialize)]
struct LogoutForm {
    csrf: Option<String>,
}

async fn logout(State(state): State<AppState>, headers: HeaderMap, Form(f): Form<LogoutForm>) -> Response {
    if let Some(sess) = session_from_headers(&state, &headers) {
        let provided = header_str(&headers, CSRF_HEADER).or(f.csrf.as_deref());
        if !csrf_matches(&sess, provided) {
            return json_error(StatusCode::FORBIDDEN, "csrf", "missing or wrong CSRF token");
        }
        let (hash, label) = (sess.id_hash.clone(), sess.label.clone());
        let res = state.hub.db().write(|tx| {
            tx.execute(
                "UPDATE ui_sessions SET revoked_at = ?2 WHERE id_hash = ?1 AND revoked_at IS NULL",
                params![hash, ua_core::time::now()],
            )?;
            ledger::append(tx, EventInput::new("agent.ui.logout", json!({ "identity": label })).by(label.clone()))?;
            Ok(())
        });
        if let Err(e) = res {
            return server_error(e);
        }
    }
    ([(header::SET_COOKIE, clear_cookie(&state))], Redirect::to("/login")).into_response()
}

/// `GET /api/session`: the caller's identity and, for a cookie session, its
/// CSRF token and the header to send it in.
async fn api_session(Extension(id): Extension<AuthIdentity>, session: Option<Extension<UiSession>>) -> Json<Value> {
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

const B64U_JS: &str = "const b64u={dec:s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((s.length+3)%4)),c=>c.charCodeAt(0)),\
enc:b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')};\
function say(m){document.getElementById('msg').textContent=m;}";

#[derive(Deserialize)]
struct LoginQuery {
    next: Option<String>,
}

async fn login_page(State(state): State<AppState>, headers: HeaderMap, Query(q): Query<LoginQuery>) -> Response {
    let next = safe_next(q.next.as_deref());
    if session_from_headers(&state, &headers).is_some() {
        return Redirect::to(&next).into_response();
    }
    let body = format!(
        "<h1>Sign in</h1><label for=\"label\">Identity</label><input id=\"label\" autocomplete=\"username webauthn\" \
value=\"{first}\"><button id=\"go\" type=\"button\">Sign in with a passkey</button><p id=\"msg\" class=\"hint\"></p>\
<p class=\"hint\">First sign-in on a new hub: run <code>ua login-link &lt;label&gt;</code> on the hub host and open \
the link it prints, then register a passkey.</p>\
<script>{B64U_JS}\
document.getElementById('go').onclick=async()=>{{try{{\
const label=document.getElementById('label').value.trim();\
let r=await fetch('/login/passkey/start',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{label}})}});\
let j=await r.json();if(!r.ok)return say(j.message||'Sign-in failed');\
const pk=j.options.publicKey;pk.challenge=b64u.dec(pk.challenge);(pk.allowCredentials||[]).forEach(c=>c.id=b64u.dec(c.id));\
const c=await navigator.credentials.get({{publicKey:pk}});\
const credential={{id:c.id,rawId:b64u.enc(c.rawId),type:c.type,extensions:{{}},response:{{\
authenticatorData:b64u.enc(c.response.authenticatorData),clientDataJSON:b64u.enc(c.response.clientDataJSON),\
signature:b64u.enc(c.response.signature),userHandle:c.response.userHandle?b64u.enc(c.response.userHandle):null}}}};\
r=await fetch('/login/passkey/finish',{{method:'POST',headers:{{'content-type':'application/json'}},\
body:JSON.stringify({{state_id:j.state_id,credential,next:{next_js}}})}});\
j=await r.json();if(!r.ok)return say(j.message||'Sign-in failed');location.href=j.next;\
}}catch(e){{say('Sign-in was cancelled or failed.');}}}};</script>",
        first = html_escape(state.hub.cfg().human_identities.first().map(String::as_str).unwrap_or("")),
        next_js = serde_json::to_string(&next).unwrap_or_else(|_| "\"/ui\"".into()).replace('<', "\\u003c"),
    );
    html_page(StatusCode::OK, "Sign in", &body)
}

async fn passkeys_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(sess) = session_from_headers(&state, &headers) else {
        return Redirect::to("/login?next=/login/passkeys").into_response();
    };
    let keys: Vec<(String, Option<String>, String, Option<String>)> = state
        .hub
        .db()
        .read(|c| {
            let mut stmt =
                c.prepare("SELECT cred_id, name, created_at, last_used_at FROM passkeys WHERE label = ?1 ORDER BY created_at")?;
            Ok(stmt
                .query_map([&sess.label], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<_, _>>()?)
        })
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
    let csrf_js = serde_json::to_string(&sess.csrf_token).unwrap_or_default();
    let body = format!(
        "<h1>Passkeys for {label}</h1><ul>{list}</ul><label for=\"name\">Name for a new passkey</label>\
<input id=\"name\" placeholder=\"laptop\"><button id=\"add\" type=\"button\">Register a passkey</button>\
<p id=\"msg\" class=\"hint\"></p><p><a href=\"/ui\">Open the Control Center</a></p>\
<form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
<button class=\"secondary\" type=\"submit\">Sign out</button></form>\
<script>{B64U_JS}const csrf={csrf_js};\
document.getElementById('add').onclick=async()=>{{try{{\
const h={{'content-type':'application/json','X-CSRF-Token':csrf}};\
let r=await fetch('/login/passkeys/register/start',{{method:'POST',headers:h}});let j=await r.json();\
if(!r.ok)return say(j.message||'Could not start');const pk=j.options.publicKey;\
pk.challenge=b64u.dec(pk.challenge);pk.user.id=b64u.dec(pk.user.id);(pk.excludeCredentials||[]).forEach(c=>c.id=b64u.dec(c.id));\
const c=await navigator.credentials.create({{publicKey:pk}});\
const credential={{id:c.id,rawId:b64u.enc(c.rawId),type:c.type,extensions:{{}},response:{{\
attestationObject:b64u.enc(c.response.attestationObject),clientDataJSON:b64u.enc(c.response.clientDataJSON)}}}};\
r=await fetch('/login/passkeys/register/finish',{{method:'POST',headers:h,body:JSON.stringify({{state_id:j.state_id,credential,\
name:document.getElementById('name').value}})}});j=await r.json();if(!r.ok)return say(j.message||'Registration failed');\
location.reload();}}catch(e){{say('Registration was cancelled or failed.');}}}};</script>",
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
}
