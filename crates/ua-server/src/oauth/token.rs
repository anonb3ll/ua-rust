//! `/oauth/token` and `/oauth/revoke` (RFC 7009).
//!
//! Refresh tokens rotate on every use. Presenting a refresh token that was
//! already rotated is treated as theft: the whole grant (every access and
//! refresh token of that sign-in) is revoked. Re-presenting a used
//! authorization code does the same.

use std::collections::HashMap;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rusqlite::{OptionalExtension, params};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use ua_store::{EventInput, ledger};
use ua_tools::families::tokens::{digest, revoke_family};

use super::authorize::pkce_shaped;
use super::store::{Client, ClientKind, ClientLookup, GrantInfo, Issued, insert_grant, issue_tokens, load_client, new_family_id};
use super::{SCOPE, accepted_resource, not_enabled};
use crate::AppState;

const MAX_FORM: usize = 16 * 1024;

fn no_store(status: StatusCode, body: serde_json::Value) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")], Json(body)).into_response()
}

fn token_error(error: &str, description: &str) -> Response {
    let status = if error == "invalid_client" { StatusCode::UNAUTHORIZED } else { StatusCode::BAD_REQUEST };
    let mut resp = no_store(status, json!({ "error": error, "error_description": description }));
    if status == StatusCode::UNAUTHORIZED
        && let Ok(v) = "Basic realm=\"ua\"".parse()
    {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    resp
}

/// Parse an `application/x-www-form-urlencoded` body. Repeated parameters
/// are refused (RFC 6749 §3.1).
fn parse_form(headers: &HeaderMap, body: &[u8]) -> Result<HashMap<String, String>, Response> {
    let ctype = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ctype.to_ascii_lowercase().starts_with("application/x-www-form-urlencoded") {
        return Err(token_error("invalid_request", "body must be application/x-www-form-urlencoded"));
    }
    if body.len() > MAX_FORM {
        return Err(token_error("invalid_request", "request body is too large"));
    }
    let mut out = HashMap::new();
    for (k, v) in url::form_urlencoded::parse(body) {
        if out.insert(k.to_string(), v.to_string()).is_some() {
            return Err(token_error("invalid_request", &format!("parameter {k} is repeated")));
        }
    }
    Ok(out)
}

/// Authenticate the client: `client_secret_basic`, `client_secret_post`, or
/// `none` for public clients.
async fn authenticate_client(
    state: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Result<Client, Response> {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .map(str::trim);
    let (client_id, secret) = match basic {
        Some(b) => {
            if form.contains_key("client_secret") {
                return Err(token_error("invalid_request", "use one client authentication method"));
            }
            let decoded = STANDARD.decode(b).ok().and_then(|d| String::from_utf8(d).ok());
            let Some((id, secret)) = decoded.as_deref().and_then(|d| d.split_once(':')) else {
                return Err(token_error("invalid_client", "malformed Basic credentials"));
            };
            let dec = |s: &str| url::form_urlencoded::parse(format!("x={s}").as_bytes()).next().map(|(_, v)| v.to_string());
            let (Some(id), Some(secret)) = (dec(id), dec(secret)) else {
                return Err(token_error("invalid_client", "malformed Basic credentials"));
            };
            if form.get("client_id").is_some_and(|f| *f != id) {
                return Err(token_error("invalid_client", "client_id does not match the credentials"));
            }
            (id, Some(secret))
        }
        None => match form.get("client_id") {
            Some(id) => (id.clone(), form.get("client_secret").cloned()),
            None => return Err(token_error("invalid_client", "client authentication is required")),
        },
    };
    let client = match load_client(state, &client_id).await {
        Ok(ClientLookup::Found(c)) => c,
        Ok(_) => return Err(token_error("invalid_client", "unknown client")),
        Err(_) => return Err(token_error("server_error", "the client registry is unavailable")),
    };
    match (&secret, client.is_public()) {
        (None, true) => Ok(client),
        (Some(s), false) if client.secret_matches(s) => Ok(client),
        (Some(_), true) => Err(token_error("invalid_client", "public clients do not use a secret")),
        _ => Err(token_error("invalid_client", "client authentication failed")),
    }
}

pub async fn token(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !state.hub.cfg().oauth_enabled {
        return not_enabled();
    }
    let form = match parse_form(&headers, &body) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let client = match authenticate_client(&state, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => authorization_code(&state, client, &form).await,
        Some("refresh_token") => refresh(&state, client, &form).await,
        Some("client_credentials") => client_credentials(&state, client, &form).await,
        Some(_) => token_error("unsupported_grant_type", "unsupported grant_type"),
        None => token_error("invalid_request", "grant_type is required"),
    }
}

enum Outcome {
    Issued(Issued),
    Refused(&'static str, String),
}

fn finish(res: ua_core::UaResult<Outcome>) -> Response {
    match res {
        Ok(Outcome::Issued(t)) => no_store(StatusCode::OK, t.to_json()),
        Ok(Outcome::Refused(e, d)) => token_error(e, &d),
        Err(e) => {
            tracing::warn!(error = %e, "token endpoint failed");
            token_error("server_error", "the token could not be issued")
        }
    }
}

async fn authorization_code(state: &AppState, client: Client, form: &HashMap<String, String>) -> Response {
    if !client.allows_grant("authorization_code") {
        return token_error("unauthorized_client", "client is not registered for authorization_code");
    }
    let (Some(code), Some(redirect_uri), Some(verifier)) =
        (form.get("code"), form.get("redirect_uri"), form.get("code_verifier"))
    else {
        return token_error("invalid_request", "code, redirect_uri and code_verifier are required");
    };
    if !pkce_shaped(verifier) {
        return token_error("invalid_grant", "code_verifier is malformed");
    }
    let resource_param = form.get("resource").cloned();
    let (code_hash, redirect_uri, verifier) = (digest(code), redirect_uri.clone(), verifier.clone());
    let cfg = state.hub.cfg().clone();
    let with_refresh = client.allows_grant("refresh_token");
    let client_id = client.client_id.clone();
    let res = state
        .hub
        .db()
        .write_async(move |tx| {
            type Row = (String, String, String, String, String, String, String, String, Option<String>);
            let row: Option<Row> = tx
                .query_row(
                    "SELECT family_id, client_id, redirect_uri, code_challenge, scope, resource, subject, expires_at, \
                     used_at FROM oauth_codes WHERE code_hash = ?1",
                    [&code_hash],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                            r.get(8)?,
                        ))
                    },
                )
                .optional()?;
            let Some((family, code_client, code_redirect, challenge, scope, resource, subject, expires, used)) = row
            else {
                return Ok(Outcome::Refused("invalid_grant", "authorization code is not valid".into()));
            };
            if used.is_some() {
                // A replayed code: revoke whatever the first exchange issued.
                revoke_family(tx, &family, "code_reuse")?;
                ledger::append(
                    tx,
                    EventInput::new("agent.oauth.code_reuse", json!({ "client_id": code_client, "session_id": family }))
                        .by("oauth"),
                )?;
                return Ok(Outcome::Refused("invalid_grant", "authorization code was already used".into()));
            }
            tx.execute("UPDATE oauth_codes SET used_at = ?2 WHERE code_hash = ?1", params![code_hash, ua_core::time::now()])?;
            if expires <= ua_core::time::now() {
                return Ok(Outcome::Refused("invalid_grant", "authorization code expired".into()));
            }
            if code_client != client_id {
                return Ok(Outcome::Refused("invalid_grant", "authorization code was issued to another client".into()));
            }
            if code_redirect != redirect_uri {
                return Ok(Outcome::Refused("invalid_grant", "redirect_uri does not match the authorization request".into()));
            }
            let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            if !bool::from(computed.as_bytes().ct_eq(challenge.as_bytes())) {
                return Ok(Outcome::Refused("invalid_grant", "code_verifier does not match the code_challenge".into()));
            }
            if let Some(r) = resource_param.as_deref()
                && accepted_resource(&cfg, Some(r)).as_deref() != Some(resource.as_str())
            {
                return Ok(Outcome::Refused("invalid_target", "resource does not match the authorization request".into()));
            }
            let g = GrantInfo { family_id: &family, client_id: &client_id, subject: &subject, scope: &scope, resource: &resource };
            Ok(Outcome::Issued(issue_tokens(tx, &cfg, &g, with_refresh)?))
        })
        .await;
    finish(res)
}

async fn refresh(state: &AppState, client: Client, form: &HashMap<String, String>) -> Response {
    if !client.allows_grant("refresh_token") {
        return token_error("unauthorized_client", "client is not registered for refresh_token");
    }
    let Some(raw) = form.get("refresh_token") else {
        return token_error("invalid_request", "refresh_token is required");
    };
    if let Some(scope) = form.get("scope")
        && scope.split_whitespace().any(|s| s != SCOPE)
    {
        return token_error("invalid_scope", "a refresh may not widen the granted scope");
    }
    let resource_param = form.get("resource").cloned();
    let hash = digest(raw);
    let cfg = state.hub.cfg().clone();
    let client_id = client.client_id.clone();
    let res = state
        .hub
        .db()
        .write_async(move |tx| {
            type Row = (String, String, String, String, String, String, String, Option<String>);
            let row: Option<Row> = tx
                .query_row(
                    "SELECT t.family_id, t.client_id, t.subject, t.scope, t.resource, t.status, t.expires_at, g.revoked_at \
                     FROM oauth_tokens t JOIN oauth_grants g ON g.family_id = t.family_id \
                     WHERE t.token_hash = ?1 AND t.kind = 'refresh'",
                    [&hash],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
                )
                .optional()?;
            let Some((family, token_client, subject, scope, resource, status, expires, revoked)) = row else {
                return Ok(Outcome::Refused("invalid_grant", "refresh token is not valid".into()));
            };
            if token_client != client_id {
                return Ok(Outcome::Refused("invalid_grant", "refresh token was issued to another client".into()));
            }
            if status == "rotated" {
                // Reuse of a rotated token: someone holds a copy. End the sign-in.
                let n = revoke_family(tx, &family, "refresh_reuse")?;
                ledger::append(
                    tx,
                    EventInput::new(
                        "agent.oauth.refresh_reuse",
                        json!({ "client_id": token_client, "identity": subject, "session_id": family, "revoked_tokens": n }),
                    )
                    .by("oauth"),
                )?;
                return Ok(Outcome::Refused("invalid_grant", "refresh token was already used; the session is revoked".into()));
            }
            if status != "active" || revoked.is_some() || expires <= ua_core::time::now() {
                return Ok(Outcome::Refused("invalid_grant", "refresh token is not valid".into()));
            }
            if cfg.is_human(&subject) {
                return Ok(Outcome::Refused("invalid_grant", "grant identity is not allowed".into()));
            }
            if let Some(r) = resource_param.as_deref()
                && accepted_resource(&cfg, Some(r)).as_deref() != Some(resource.as_str())
            {
                return Ok(Outcome::Refused("invalid_target", "resource does not match the grant".into()));
            }
            tx.execute("UPDATE oauth_tokens SET status = 'rotated' WHERE token_hash = ?1", [&hash])?;
            let g = GrantInfo { family_id: &family, client_id: &client_id, subject: &subject, scope: &scope, resource: &resource };
            Ok(Outcome::Issued(issue_tokens(tx, &cfg, &g, true)?))
        })
        .await;
    finish(res)
}

async fn client_credentials(state: &AppState, client: Client, form: &HashMap<String, String>) -> Response {
    let ClientKind::Configured { identity } = client.kind.clone() else {
        return token_error("unauthorized_client", "client_credentials is limited to configured clients");
    };
    let cfg = state.hub.cfg().clone();
    if cfg.is_human(&identity) {
        return token_error("unauthorized_client", "a client may not act as a human identity");
    }
    let Some(resource) = accepted_resource(&cfg, form.get("resource").map(String::as_str)) else {
        return token_error("invalid_target", "resource is not served by this hub");
    };
    let res = state
        .hub
        .db()
        .write_async(move |tx| {
            let family = new_family_id();
            let g = GrantInfo { family_id: &family, client_id: &client.client_id, subject: &identity, scope: SCOPE, resource: &resource };
            insert_grant(tx, &g, &client.client_name, "configuration", "client_credentials")?;
            Ok(Outcome::Issued(issue_tokens(tx, &cfg, &g, false)?))
        })
        .await;
    finish(res)
}

/// RFC 7009 revocation. Answers 200 for unknown tokens. Revoking a refresh
/// token ends its whole sign-in; revoking an access token ends only it.
pub async fn revoke(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !state.hub.cfg().oauth_enabled {
        return not_enabled();
    }
    let form = match parse_form(&headers, &body) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let client = match authenticate_client(&state, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(token) = form.get("token") else {
        return token_error("invalid_request", "token is required");
    };
    let (hash, client_id) = (digest(token), client.client_id.clone());
    let res = state
        .hub
        .db()
        .write_async(move |tx| {
            let row: Option<(String, String, String)> = tx
                .query_row(
                    "SELECT kind, family_id, client_id FROM oauth_tokens WHERE token_hash = ?1",
                    [&hash],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((kind, family, owner)) = row else { return Ok(()) };
            if owner != client_id {
                return Ok(());
            }
            if kind == "refresh" {
                revoke_family(tx, &family, "client_revoke")?;
            } else {
                tx.execute(
                    "UPDATE oauth_tokens SET status = 'revoked', revoked_at = ?2 WHERE token_hash = ?1",
                    params![hash, ua_core::time::now()],
                )?;
            }
            ledger::append(
                tx,
                EventInput::new("agent.oauth.token_revoked", json!({ "client_id": owner, "kind": kind, "session_id": family }))
                    .by("oauth"),
            )?;
            Ok(())
        })
        .await;
    match res {
        Ok(()) => no_store(StatusCode::OK, json!({})),
        Err(e) => {
            tracing::warn!(error = %e, "revocation failed");
            token_error("server_error", "revocation failed")
        }
    }
}
