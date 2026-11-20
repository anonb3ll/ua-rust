//! The remote-node device plane, with the Python hub's routes and shapes.
//!
//! | Route | Tool |
//! |---|---|
//! | `POST /api/node/register`  | `node_register` |
//! | `POST /api/node/heartbeat` | `node_heartbeat` |
//! | `POST /api/node/dispatch`  | `node_dispatch` (201; 202 while the approval is pending) |
//! | `POST /api/node/claim`     | `node_claim` |
//! | `POST /api/node/receipt`   | `node_receipt` (201; 200 for a duplicate) |
//! | `POST /api/node/events`    | `node_events` |
//! | `POST /api/node/followups` | `node_followups` |
//! | `POST /api/node/permission`| `node_permission` |
//! | `POST /api/node/session_credential` | `node_session_credential` (201, `Cache-Control: no-store`) |
//! | `POST /api/node/wake`      | `node_wake` (long-poll, `offer_version` 3) |
//! | `POST /api/node/wake/check` | `node_wake_check` |
//! | `POST /api/node/wake/receipt` | `node_wake_receipt` (200; `duplicate: true` for a resend) |
//! | `GET  /api/nodes`          | `node_list`, plus `recent_items` from `node_items` |
//! | `GET  /api/nodes/acceptance` | `coordination_manage` `node_acceptance_status` (`?node=`) |
//!
//! A node calls out with its agent's bearer token; it never listens. The
//! node's owner is that verified agent: the tools refuse a human or
//! unauthenticated caller and take no owner from the body. Refusals answer
//! `{"error": message, "code": reason}`, so a retired node sees
//! `code = "node_retired"` (403) and an unregistered one a 404 saying
//! "not registered", which is what the node software keys on. A session
//! credential refusal also carries `reason` (the same code), which is what
//! the node keys on there.
//!
//! The harness config bundle (`/api/node/config`) is not built yet and
//! answers `501`.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Extension, Json, Router};
use serde_json::{Value, json};
use ua_core::UaError;
use ua_core::identity::Transport;

use crate::AppState;
use crate::api::status_for;
use crate::auth::{AuthIdentity, caller_for, session_key};
use crate::compat_api::{not_built, object_body};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/node/register", post(register))
        .route("/api/node/heartbeat", post(heartbeat))
        .route(
            "/api/node/dispatch",
            post(|s, i, h, b| tool_route(s, i, h, b, "node_dispatch", Created::Always)),
        )
        .route("/api/node/claim", post(|s, i, h, b| tool_route(s, i, h, b, "node_claim", Created::Never)))
        .route(
            "/api/node/receipt",
            post(|s, i, h, b| tool_route(s, i, h, b, "node_receipt", Created::UnlessDuplicate)),
        )
        .route("/api/node/events", post(|s, i, h, b| tool_route(s, i, h, b, "node_events", Created::Never)))
        .route(
            "/api/node/followups",
            post(|s, i, h, b| tool_route(s, i, h, b, "node_followups", Created::Never)),
        )
        .route(
            "/api/node/permission",
            post(|s, i, h, b| tool_route(s, i, h, b, "node_permission", Created::Never)),
        )
        .route("/api/node/session_credential", post(session_credential))
        .route("/api/node/wake", post(|s, i, h, b| tool_route(s, i, h, b, "node_wake", Created::Never)))
        .route(
            "/api/node/wake/check",
            post(|s, i, h, b| tool_route(s, i, h, b, "node_wake_check", Created::Never)),
        )
        .route(
            "/api/node/wake/receipt",
            post(|s, i, h, b| tool_route(s, i, h, b, "node_wake_receipt", Created::Never)),
        )
        .route(
            "/api/node/{*rest}",
            any(|| async { not_built("node_config", "the harness config bundle route") }),
        )
        .route("/api/nodes", get(list))
        .route("/api/nodes/acceptance", get(acceptance))
}

/// `{"error", "code"}`: a denial's reason code, else the error's code. An
/// internal error's detail is never sent.
fn node_err_body(e: &UaError) -> Value {
    let code = e.reason_code().unwrap_or(e.code()).to_string();
    let message = match e {
        UaError::Internal(_) => "internal error".to_string(),
        other => other.to_string(),
    };
    json!({ "error": message, "code": code })
}

fn node_err(e: &UaError) -> Response {
    (status_for(e), Json(node_err_body(e))).into_response()
}

/// When a success answers `201 Created`.
#[derive(Clone, Copy)]
enum Created {
    Never,
    Always,
    /// Unless the result says `duplicate: true` (a retried receipt).
    UnlessDuplicate,
}

async fn tool_route(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    body: Bytes,
    tool: &'static str,
    created: Created,
) -> Response {
    let mut resp = call(&state, &id, &headers, tool, &body).await;
    if resp.status() == StatusCode::OK {
        let new = match created {
            Created::Never => false,
            Created::Always => true,
            Created::UnlessDuplicate => resp.extensions().get::<Duplicate>().is_none(),
        };
        if new {
            *resp.status_mut() = StatusCode::CREATED;
        }
    }
    resp
}

/// Marks a response whose result was `duplicate: true`.
#[derive(Clone, Copy)]
struct Duplicate;

async fn call(
    state: &AppState,
    id: &AuthIdentity,
    headers: &HeaderMap,
    tool: &str,
    body: &Bytes,
) -> Response {
    let args = match object_body(body) {
        Ok(m) => Value::Object(m),
        Err(r) => return *r,
    };
    let caller = caller_for(state, id, session_key(headers), Transport::Http);
    match state.registry.call(&state.hub, &caller, tool, args).await {
        Ok(v) => {
            let dup = v.get("duplicate") == Some(&json!(true));
            let mut resp = Json(v).into_response();
            if dup {
                resp.extensions_mut().insert(Duplicate);
            }
            resp
        }
        Err(UaError::ApprovalRequired { approval_id, .. }) => (
            StatusCode::ACCEPTED,
            Json(json!({ "approval_id": approval_id, "code": "approval_required", "status": "pending", "tool": tool })),
        )
            .into_response(),
        Err(e) => node_err(&e),
    }
}

async fn register(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    call(&state, &id, &headers, "node_register", &body).await
}

async fn heartbeat(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    call(&state, &id, &headers, "node_heartbeat", &body).await
}

/// `POST /api/node/session_credential`: the value is in this response once;
/// it is never cached. A refusal carries `reason` for the node.
async fn session_credential(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut resp = call(&state, &id, &headers, "node_session_credential", &body).await;
    if resp.status() == StatusCode::OK {
        *resp.status_mut() = StatusCode::CREATED;
    } else if resp.status() != StatusCode::ACCEPTED {
        let status = resp.status();
        let bytes =
            axum::body::to_bytes(std::mem::take(resp.body_mut()), 64 * 1024).await.unwrap_or_default();
        let mut v: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
        v["reason"] = v["code"].clone();
        resp = (status, Json(v)).into_response();
    }
    resp.headers_mut()
        .insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    resp
}

#[derive(serde::Deserialize)]
struct AcceptanceQuery {
    node: Option<String>,
}

/// `GET /api/nodes/acceptance`: one node's live evaluation (`?node=`), or
/// every node's stored summary. Read-only.
async fn acceptance(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<AcceptanceQuery>,
) -> Response {
    let caller = caller_for(&state, &id, session_key(&headers), Transport::Http);
    let mut params = json!({});
    if let Some(n) = q.node.filter(|n| !n.trim().is_empty()) {
        params["node"] = json!(n);
    }
    let args = json!({ "action": "node_acceptance_status", "params": params });
    match state.registry.call(&state.hub, &caller, "coordination_manage", args).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => node_err(&e),
    }
}

async fn list(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
) -> Response {
    let caller = caller_for(&state, &id, session_key(&headers), Transport::Http);
    match state.registry.call(&state.hub, &caller, "node_list", json!({})).await {
        Ok(mut v) => {
            // Recent work the caller may see; the listing stands without it.
            let items = state.registry.call(&state.hub, &caller, "node_items", json!({ "limit": 25 })).await;
            v["recent_items"] = items.map(|i| i["items"].clone()).unwrap_or_else(|_| json!([]));
            Json(v).into_response()
        }
        Err(e) => {
            let mut body = node_err_body(&e);
            body["nodes"] = json!([]);
            (status_for(&e), Json(body)).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_are_masked() {
        let body = node_err_body(&UaError::internal("disk I/O error at /var/lib/hub/ua.db"));
        assert_eq!(body, json!({ "error": "internal error", "code": "internal" }));
        let body = node_err_body(&UaError::denied("node_retired", "node retired"));
        assert_eq!(body["code"], "node_retired");
    }
}
