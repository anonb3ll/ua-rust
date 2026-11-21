//! RFC 7591 dynamic client registration. Deprecated by the MCP spec in
//! favour of Client ID Metadata Documents but kept for older clients;
//! `oauth_dcr_enabled = false` turns it off.
//!
//! Registration is unauthenticated, so it is bounded three ways and can
//! never lock legitimate clients out:
//! - A client that never received a grant is pruned after
//!   `oauth_dcr_unused_ttl_hours` (on each registration and when `ua serve`
//!   starts).
//! - Clients without a grant are capped at [`MAX_UNUSED_CLIENTS`]; a new
//!   registration beyond it evicts the oldest of them instead of failing.
//!   Only clients that hold a grant count against [`MAX_GRANTED_CLIENTS`].
//! - Each remote address may register `oauth_dcr_rate_per_hour` clients per
//!   hour. Behind a loopback reverse proxy the address is the last
//!   `X-Forwarded-For` entry.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::params;
use serde_json::{Value, json};
use ua_core::UaResult;
use ua_store::{EventInput, WriteTx, ledger};
use ua_tools::Hub;
use ua_tools::families::tokens::digest;

use super::{SCOPE, not_enabled, random_token};
use crate::AppState;

/// Clients holding at least one grant kept at most; registration fails beyond it.
pub const MAX_GRANTED_CLIENTS: i64 = 10_000;
/// Clients without a grant kept at most; the oldest is evicted beyond it.
pub const MAX_UNUSED_CLIENTS: i64 = 1000;
/// Rate-limit window for registrations per remote address.
const RATE_WINDOW: Duration = Duration::from_secs(3600);
/// Remote addresses tracked before old windows are dropped.
const RATE_TABLE_MAX: usize = 10_000;
const MAX_BODY: usize = 16 * 1024;
const MAX_REDIRECTS: usize = 10;

fn reg_error(code: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": code, "error_description": description })),
    )
        .into_response()
}

/// A redirect URI a client may register: `https`, `http` on a loopback host,
/// or a private-use scheme for native apps. No fragments.
pub fn check_redirect_uri(raw: &str) -> Result<(), String> {
    if raw.len() > 2048 {
        return Err("redirect_uri is too long".into());
    }
    let url = url::Url::parse(raw).map_err(|_| format!("redirect_uri {raw:?} is not an absolute URI"))?;
    if url.fragment().is_some() {
        return Err("redirect_uri may not contain a fragment".into());
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(&url) => Ok(()),
        "http" => Err("http redirect_uris are allowed only on loopback hosts".into()),
        "javascript" | "data" | "file" | "vbscript" | "blob" | "about" | "ws" | "wss" | "ftp" => {
            Err(format!("redirect_uri scheme {} is not allowed", url.scheme()))
        }
        _ => Ok(()),
    }
}

pub fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn string_list(v: Option<&Value>, field: &str) -> Result<Option<Vec<String>>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| {
                x.as_str().map(str::to_string).ok_or_else(|| format!("{field} must be a list of strings"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(format!("{field} must be a list of strings")),
    }
}

/// `WHERE` clause selecting clients that never received a grant and have
/// no consent request in flight.
const UNUSED: &str = "NOT EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_id = oauth_clients.client_id) \
     AND NOT EXISTS (SELECT 1 FROM oauth_requests r WHERE r.client_id = oauth_clients.client_id \
     AND r.expires_at > ?1)";

/// Delete registered clients that never received a grant and are older than
/// `oauth_dcr_unused_ttl_hours`. Returns how many were removed.
pub fn prune_unused_clients_tx(tx: &mut WriteTx<'_>, ttl_hours: f64) -> UaResult<usize> {
    let now = ua_core::time::now();
    let ttl = (ttl_hours.max(0.0) * 3600.0) as i64;
    let cutoff = super::ts_in(-ttl);
    let n = tx.execute(
        &format!("DELETE FROM oauth_clients WHERE created_at < ?2 AND {UNUSED}"),
        params![now, cutoff],
    )?;
    if n > 0 {
        pruned_event(tx, n, "unused_ttl")?;
    }
    Ok(n)
}

fn pruned_event(tx: &mut WriteTx<'_>, count: usize, reason: &str) -> UaResult<()> {
    ledger::append(
        tx,
        EventInput::new(
            ua_core::DEFAULT_ORG,
            "agent.oauth.clients_pruned",
            json!({ "count": count, "reason": reason }),
        )
        .by("oauth"),
    )?;
    Ok(())
}

/// [`prune_unused_clients_tx`] in its own write, for `ua serve` startup.
pub async fn prune_unused_clients(hub: &Hub) -> UaResult<usize> {
    let ttl = hub.cfg().oauth_dcr_unused_ttl_hours;
    hub.db().write_async(move |tx| prune_unused_clients_tx(tx, ttl)).await
}

static RATE: LazyLock<Mutex<HashMap<IpAddr, (Instant, u32)>>> = LazyLock::new(Mutex::default);

/// The remote address a registration is charged to: the peer, or the last
/// `X-Forwarded-For` entry when the peer is a loopback proxy. `None` when
/// the server runs without connection info (in-process tests).
fn remote_addr(peer: Option<SocketAddr>, headers: &HeaderMap) -> Option<IpAddr> {
    let peer = peer?.ip();
    if peer.is_loopback()
        && let Some(fwd) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
    {
        return Some(fwd);
    }
    Some(peer)
}

/// Count one registration for `addr`; false when it is over the limit.
fn rate_ok(addr: IpAddr, per_hour: u32) -> bool {
    let Ok(mut table) = RATE.lock() else { return true };
    let now = Instant::now();
    if table.len() >= RATE_TABLE_MAX {
        table.retain(|_, (start, _)| now.duration_since(*start) < RATE_WINDOW);
    }
    let entry = table.entry(addr).or_insert((now, 0));
    if now.duration_since(entry.0) >= RATE_WINDOW {
        *entry = (now, 0);
    }
    if entry.1 >= per_hour {
        return false;
    }
    entry.1 += 1;
    true
}

pub async fn register(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let cfg = state.hub.cfg();
    if !cfg.oauth_enabled || !cfg.oauth_dcr_enabled {
        return not_enabled();
    }
    if let Some(addr) = remote_addr(peer.map(|Extension(ConnectInfo(a))| a), &headers)
        && !rate_ok(addr, cfg.oauth_dcr_rate_per_hour)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::CACHE_CONTROL, "no-store"), (header::RETRY_AFTER, "3600")],
            Json(json!({ "error": "invalid_client_metadata", "error_description": "too many registrations from this address; try again later" })),
        )
            .into_response();
    }
    if body.len() > MAX_BODY {
        return reg_error("invalid_client_metadata", "registration request is too large");
    }
    let Ok(Value::Object(meta)) = serde_json::from_slice::<Value>(&body) else {
        return reg_error("invalid_client_metadata", "body must be a JSON object");
    };
    let redirect_uris = match string_list(meta.get("redirect_uris"), "redirect_uris") {
        Ok(Some(v)) if !v.is_empty() && v.len() <= MAX_REDIRECTS => v,
        Ok(_) => return reg_error("invalid_redirect_uri", "redirect_uris must list 1 to 10 URIs"),
        Err(e) => return reg_error("invalid_redirect_uri", &e),
    };
    for uri in &redirect_uris {
        if let Err(e) = check_redirect_uri(uri) {
            return reg_error("invalid_redirect_uri", &e);
        }
    }
    let grant_types = match string_list(meta.get("grant_types"), "grant_types") {
        Ok(v) => v.unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]),
        Err(e) => return reg_error("invalid_client_metadata", &e),
    };
    if grant_types.is_empty() || grant_types.iter().any(|g| g != "authorization_code" && g != "refresh_token")
    {
        return reg_error(
            "invalid_client_metadata",
            "grant_types may contain only authorization_code and refresh_token",
        );
    }
    match string_list(meta.get("response_types"), "response_types") {
        Ok(None) => {}
        Ok(Some(v)) if v.iter().all(|r| r == "code") => {}
        _ => return reg_error("invalid_client_metadata", "response_types may contain only code"),
    }
    let method = meta.get("token_endpoint_auth_method").and_then(Value::as_str).unwrap_or("none").to_string();
    if !matches!(method.as_str(), "none" | "client_secret_basic" | "client_secret_post") {
        return reg_error("invalid_client_metadata", "unsupported token_endpoint_auth_method");
    }
    let client_name: String = meta
        .get("client_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    let client_name = client_name.trim().to_string();

    let client_id = format!("ua-client-{}", ulid::Ulid::generate().to_string().to_lowercase());
    let secret = (method != "none").then(|| random_token("uas_"));
    let secret_hash = secret.as_deref().map(digest);
    let now = ua_core::time::now();
    let issued_at = jiff::Timestamp::now().as_second();
    let mut stored = meta.clone();
    stored.remove("client_secret");
    stored.remove("client_id");

    let row = (
        client_id.clone(),
        (!client_name.is_empty()).then(|| client_name.clone()),
        serde_json::to_string(&redirect_uris).unwrap_or_default(),
        serde_json::to_string(&grant_types).unwrap_or_default(),
        method.clone(),
        secret_hash,
        Value::Object(stored).to_string(),
        now,
    );
    let ttl_hours = cfg.oauth_dcr_unused_ttl_hours;
    let res = state
        .hub
        .db()
        .write_async(move |tx| {
            prune_unused_clients_tx(tx, ttl_hours)?;
            let now = ua_core::time::now();
            let granted: i64 = tx.query_row(
                &format!("SELECT COUNT(*) FROM oauth_clients WHERE NOT ({UNUSED})"),
                [&now],
                |r| r.get(0),
            )?;
            if granted >= MAX_GRANTED_CLIENTS {
                return Ok(false);
            }
            let unused: i64 = tx.query_row(
                &format!("SELECT COUNT(*) FROM oauth_clients WHERE {UNUSED}"),
                [&now],
                |r| r.get(0),
            )?;
            if unused >= MAX_UNUSED_CLIENTS {
                let evicted = tx.execute(
                    &format!(
                        "DELETE FROM oauth_clients WHERE client_id IN (SELECT client_id FROM oauth_clients \
                         WHERE {UNUSED} ORDER BY created_at, client_id LIMIT ?2)"
                    ),
                    params![now, unused - MAX_UNUSED_CLIENTS + 1],
                )?;
                pruned_event(tx, evicted, "unused_cap")?;
            }
            tx.execute(
                "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, grant_types, \
                 token_endpoint_auth_method, secret_hash, metadata, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7],
            )?;
            ua_store::ledger::append(
                tx,
                ua_store::EventInput::new(ua_core::DEFAULT_ORG, "agent.oauth.client_registered", json!({ "client_id": row.0 }))
                    .by("oauth"),
            )?;
            Ok(true)
        })
        .await;
    match res {
        Ok(true) => {}
        Ok(false) => return reg_error("invalid_client_metadata", "the client registry is full"),
        Err(e) => {
            tracing::warn!(error = %e, "client registration failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "server_error" })))
                .into_response();
        }
    }

    let mut out = json!({
        "client_id": client_id,
        "client_id_issued_at": issued_at,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": method,
        "scope": SCOPE,
    });
    if !client_name.is_empty() {
        out["client_name"] = json!(client_name);
    }
    if let Some(s) = secret {
        out["client_secret"] = json!(s);
        out["client_secret_expires_at"] = json!(0);
    }
    (StatusCode::CREATED, [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")], Json(out))
        .into_response()
}
