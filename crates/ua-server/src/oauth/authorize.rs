//! `/oauth/authorize`: the authorization code request and the consent page.
//!
//! `GET` validates the request (client, exact redirect URI, PKCE S256,
//! resource indicator), sends a visitor without a Control Center session to
//! `/login`, and renders a consent page for the signed-in human. `POST`
//! records the decision. Approval binds the grant to one of the configured
//! `oauth_identities` (never a human identity) and redirects with `code`,
//! `state` and `iss` (RFC 9207). Errors that cannot be trusted to a redirect
//! (unknown client, bad redirect URI) are shown as a page instead.

use axum::Form;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use ua_store::{EventInput, ledger};
use ua_tools::families::tokens::digest;

use super::store::{ClientKind, ClientLookup, GrantInfo, insert_grant, load_client, new_family_id};
use super::{
    CODE_PREFIX, CODE_TTL_SECS, REQUEST_TTL_SECS, SCOPE, accepted_resource, html_escape, html_page, issuer,
    not_enabled, random_token, ts_in,
};
use crate::AppState;
use crate::login::{csrf_matches, session_from_headers};

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    resource: Option<String>,
}

/// A validated request waiting for the human's decision.
#[derive(Debug, Serialize, Deserialize)]
struct Pending {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    scope: String,
    resource: String,
}

fn error_page(status: StatusCode, msg: &str) -> Response {
    html_page(
        status,
        "Authorization error",
        &format!("<h1>Authorization request refused</h1><p>{}</p>", html_escape(msg)),
    )
}

/// Redirect back to the client with OAuth parameters plus `iss`.
fn redirect_with(redirect_uri: &str, iss: &str, pairs: &[(&str, &str)], state: Option<&str>) -> Response {
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return error_page(StatusCode::BAD_REQUEST, "invalid redirect_uri");
    };
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in pairs {
            q.append_pair(k, v);
        }
        if let Some(s) = state {
            q.append_pair("state", s);
        }
        q.append_pair("iss", iss);
    }
    Redirect::to(url.as_str()).into_response()
}

fn redirect_error(p: &Pending, iss: &str, error: &str, description: &str) -> Response {
    redirect_with(
        &p.redirect_uri,
        iss,
        &[("error", error), ("error_description", description)],
        p.state.as_deref(),
    )
}

/// PKCE values are 43-128 unreserved characters (RFC 7636 §4.1-4.2).
pub fn pkce_shaped(s: &str) -> bool {
    (43..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// Exact match, except that a loopback redirect may use any port
/// (OAuth 2.1 §8.4.2, native apps).
pub fn redirect_matches(registered: &str, presented: &str) -> bool {
    if registered == presented {
        return true;
    }
    let (Ok(mut a), Ok(mut b)) = (url::Url::parse(registered), url::Url::parse(presented)) else {
        return false;
    };
    if a.scheme() != "http"
        || !super::register::is_loopback_host(&a)
        || !super::register::is_loopback_host(&b)
    {
        return false;
    }
    let _ = a.set_port(None);
    let _ = b.set_port(None);
    a == b
}

pub async fn show(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let cfg = state.hub.cfg();
    if !cfg.oauth_enabled {
        return not_enabled();
    }
    let iss = issuer(cfg);
    let Some(client_id) = q.client_id.as_deref().filter(|c| !c.is_empty()) else {
        return error_page(StatusCode::BAD_REQUEST, "client_id is missing");
    };
    let client = match load_client(&state, client_id).await {
        Ok(ClientLookup::Found(c)) => c,
        Ok(ClientLookup::Rejected(reason)) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                &format!("client metadata document refused: {reason}"),
            );
        }
        Ok(ClientLookup::Unknown) => return error_page(StatusCode::BAD_REQUEST, "unknown client_id"),
        Err(e) => {
            tracing::warn!(error = %e, "client lookup failed");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "the client registry is unavailable");
        }
    };
    if matches!(client.kind, ClientKind::Configured { .. }) {
        return error_page(StatusCode::BAD_REQUEST, "this client may only use the client_credentials grant");
    }
    let Some(redirect_uri) = q.redirect_uri.clone().filter(|r| !r.is_empty()) else {
        return error_page(StatusCode::BAD_REQUEST, "redirect_uri is required");
    };
    if !client.redirect_uris.iter().any(|r| redirect_matches(r, &redirect_uri)) {
        return error_page(StatusCode::BAD_REQUEST, "redirect_uri is not registered for this client");
    }

    // From here on, errors go back to the client.
    let mut p = Pending {
        client_id: client.client_id.clone(),
        client_name: client.client_name.clone(),
        redirect_uri,
        state: q.state.clone(),
        code_challenge: String::new(),
        scope: SCOPE.into(),
        resource: String::new(),
    };
    if q.response_type.as_deref() != Some("code") {
        return redirect_error(&p, &iss, "unsupported_response_type", "only response_type=code is supported");
    }
    if !client.allows_grant("authorization_code") {
        return redirect_error(
            &p,
            &iss,
            "unauthorized_client",
            "client is not registered for authorization_code",
        );
    }
    match (q.code_challenge.as_deref(), q.code_challenge_method.as_deref()) {
        (Some(c), Some("S256")) if pkce_shaped(c) => p.code_challenge = c.to_string(),
        _ => {
            return redirect_error(
                &p,
                &iss,
                "invalid_request",
                "PKCE with code_challenge_method=S256 is required",
            );
        }
    }
    match accepted_resource(cfg, q.resource.as_deref()) {
        Some(r) => p.resource = r,
        None => return redirect_error(&p, &iss, "invalid_target", "resource is not served by this hub"),
    }
    // Unknown scopes are dropped; the hub grants `mcp` (tools are filtered by profile).
    let _ = q.scope;

    let Some(session) = session_from_headers(&state, &headers).await else {
        let next = uri.path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_default();
        let target = url::form_urlencoded::Serializer::new(String::new()).append_pair("next", &next).finish();
        return Redirect::to(&format!("/login?{target}")).into_response();
    };
    let identities: Vec<&String> = cfg.oauth_identities.iter().filter(|l| !cfg.is_human(l)).collect();
    if identities.is_empty() {
        return error_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "no OAuth identities are configured (oauth_identities)",
        );
    }

    let request_id = random_token("uaq_");
    let row = (
        digest(&request_id),
        session.id_hash.clone(),
        p.client_id.clone(),
        serde_json::to_string(&p).unwrap_or_default(),
    );
    let saved = state
        .hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now();
            tx.execute("DELETE FROM oauth_requests WHERE expires_at <= ?1", [&now])?;
            tx.execute(
                "INSERT INTO oauth_requests (id_hash, session_hash, client_id, params, created_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![row.0, row.1, row.2, row.3, now, ts_in(REQUEST_TTL_SECS)],
            )?;
            Ok(())
        })
        .await;
    if let Err(e) = saved {
        tracing::warn!(error = %e, "could not store consent request");
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "could not start the authorization");
    }

    let redirect_host = url::Url::parse(&p.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let options: String = identities
        .iter()
        .map(|l| format!("<option value=\"{0}\">{0}</option>", html_escape(l)))
        .collect::<Vec<_>>()
        .join("");
    let source = match client.kind {
        ClientKind::MetadataDocument => "identified by its metadata document URL",
        _ => "registered with this hub",
    };
    // What the grant reaches: the MCP endpoint, or the whole hub (the JSON API
    // and tools; the only resource of a build without the mcp-server feature).
    let reach = if p.resource == super::mcp_resource(cfg) {
        "this hub's MCP tools"
    } else {
        "this hub's API and tools"
    };
    let body = format!(
        "<h1>Authorize {name}</h1>\
<p><strong>{name}</strong> ({source}) asks to use {reach}.</p>\
<p class=\"hint\">Resource: <code>{resource}</code></p>\
<p class=\"hint\">After approval you are sent back to <code>{host}</code>. Signed in as <strong>{human}</strong>.</p>\
<form method=\"post\" action=\"/oauth/authorize\">\
<input type=\"hidden\" name=\"request_id\" value=\"{rid}\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
<label for=\"identity\">Act as identity</label><select id=\"identity\" name=\"identity\">{options}</select>\
<p class=\"hint\">The client's calls are attributed to this identity and limited to its profile.</p>\
<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>\
<button class=\"secondary\" type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form>",
        name = html_escape(&client.client_name),
        resource = html_escape(&p.resource),
        host = html_escape(&redirect_host),
        human = html_escape(&session.label),
        rid = html_escape(&request_id),
        csrf = html_escape(&session.csrf_token),
    );
    html_page(StatusCode::OK, "Authorize", &body)
}

#[derive(Debug, Deserialize)]
pub struct DecisionForm {
    request_id: String,
    csrf: String,
    decision: String,
    identity: Option<String>,
}

pub async fn decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<DecisionForm>,
) -> Response {
    let cfg = state.hub.cfg();
    if !cfg.oauth_enabled {
        return not_enabled();
    }
    let iss = issuer(cfg);
    let Some(session) = session_from_headers(&state, &headers).await else {
        return error_page(StatusCode::UNAUTHORIZED, "your session has ended; sign in and start again");
    };
    if !csrf_matches(&session, Some(&f.csrf)) {
        return error_page(StatusCode::FORBIDDEN, "the form is stale or was not sent by this hub");
    }
    let (rid_hash, sess_hash) = (digest(&f.request_id), session.id_hash.clone());
    let pending = state
        .hub
        .db()
        .write_async(move |tx| {
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT params, expires_at FROM oauth_requests WHERE id_hash = ?1 AND session_hash = ?2",
                    params![rid_hash, sess_hash],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            tx.execute("DELETE FROM oauth_requests WHERE id_hash = ?1", [&rid_hash])?;
            Ok(row.filter(|(_, exp)| *exp > ua_core::time::now()).map(|(p, _)| p))
        })
        .await;
    let p: Pending = match pending {
        Ok(Some(raw)) => match serde_json::from_str(&raw) {
            Ok(p) => p,
            Err(_) => return error_page(StatusCode::BAD_REQUEST, "the authorization request is corrupt"),
        },
        Ok(None) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "this authorization request expired or was already used",
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "consent lookup failed");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "could not complete the authorization");
        }
    };
    if f.decision != "approve" {
        return redirect_error(&p, &iss, "access_denied", "the operator denied the request");
    }
    let identity = f.identity.unwrap_or_default();
    if !cfg.oauth_identities.contains(&identity) || cfg.is_human(&identity) {
        return error_page(StatusCode::BAD_REQUEST, "that identity may not be used for OAuth grants");
    }

    let code = random_token(CODE_PREFIX);
    let family = new_family_id();
    let (code_hash, human) = (digest(&code), session.label.clone());
    let p2 = (p.client_id.clone(), p.client_name.clone(), p.redirect_uri.clone(), p.code_challenge.clone());
    let (scope, resource) = (p.scope.clone(), p.resource.clone());
    let res = state
        .hub
        .db()
        .write_async(move |tx| {
            let g = GrantInfo {
                family_id: &family,
                client_id: &p2.0,
                subject: &identity,
                scope: &scope,
                resource: &resource,
            };
            insert_grant(tx, &g, &p2.1, &human, "authorization_code")?;
            tx.execute(
                "INSERT INTO oauth_codes (code_hash, family_id, client_id, redirect_uri, code_challenge, scope, \
                 resource, subject, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    code_hash,
                    family,
                    p2.0,
                    p2.2,
                    p2.3,
                    scope,
                    resource,
                    identity,
                    ua_core::time::now(),
                    ts_in(CODE_TTL_SECS)
                ],
            )?;
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG,
                    "agent.oauth.consent",
                    json!({ "client_id": p2.0, "identity": identity, "approved_by": human, "session_id": family }),
                )
                .by(human.clone()),
            )?;
            Ok(())
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "could not record consent");
        return redirect_error(&p, &iss, "server_error", "could not record the approval");
    }
    redirect_with(&p.redirect_uri, &iss, &[("code", &code)], p.state.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_ports_float() {
        assert!(redirect_matches("http://127.0.0.1/cb", "http://127.0.0.1:53111/cb"));
        assert!(redirect_matches("http://localhost:3000/cb", "http://localhost:4000/cb"));
        assert!(!redirect_matches("http://127.0.0.1/cb", "http://127.0.0.1:5/other"));
        assert!(!redirect_matches("https://app.example.com/cb", "https://app.example.com:444/cb"));
        assert!(!redirect_matches("https://app.example.com/cb", "https://app.example.com/cb?x=1"));
    }
}
