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
//! | `GET  /api/nodes`          | `node_list`, plus `recent_items` from `node_items` |
//!
//! A node calls out with its agent's bearer token; it never listens. The
//! node's owner is that verified agent: the tools refuse a human or
//! unauthenticated caller and take no owner from the body. Refusals answer
//! `{"error": message, "code": reason}`, so a retired node sees
//! `code = "node_retired"` (403) and an unregistered one a 404 saying
//! "not registered", which is what the node software keys on.
//!
//! The idle-session wake transport (`/api/node/wake*`), the harness config
//! bundle (`/api/node/config`) and session credentials
//! (`/api/node/session_credential`) are not built yet and answer `501`.

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
        .route(
            "/api/node/{*rest}",
            any(|| async { not_built("node_wake", "the node wake, config and session credential routes") }),
        )
        .route("/api/nodes", get(list))
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
