//! The remote-node device plane, with the Python hub's routes and shapes.
//!
//! | Route | Tool |
//! |---|---|
//! | `POST /api/node/register`  | `node_register` |
//! | `POST /api/node/heartbeat` | `node_heartbeat` |
//! | `GET  /api/nodes`          | `node_list` |
//!
//! A node calls out with its agent's bearer token; it never listens. The
//! node's owner is that verified agent: the tools refuse a human or
//! unauthenticated caller and take no owner from the body. Refusals answer
//! `{"error": message, "code": reason}`, so a retired node sees
//! `code = "node_retired"` (403) and an unregistered one a 404 saying
//! "not registered", which is what the node software keys on.
//!
//! The work queue routes (`/api/node/claim`, `/api/node/receipt`, ...) are
//! not built yet and answer `501`.

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
        .route("/api/node/{*rest}", any(|| async { not_built("node_queue", "the node work queue") }))
        .route("/api/nodes", get(list))
}

/// `{"error", "code"}`: a denial's reason code, else the error's code.
fn node_err(e: &UaError) -> Response {
    let code = match e {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    };
    let message = match e {
        UaError::Internal(_) => "internal error".to_string(),
        other => other.to_string(),
    };
    (status_for(e), Json(json!({ "error": message, "code": code }))).into_response()
}

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
        Ok(v) => Json(v).into_response(),
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
        Ok(v) => Json(v).into_response(),
        Err(e) => (status_for(&e), Json(json!({ "nodes": [], "error": e.to_string() }))).into_response(),
    }
}
