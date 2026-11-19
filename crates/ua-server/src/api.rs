//! HTTP/JSON API.
//!
//! - `GET  /healthz`                 liveness, no auth
//! - `GET  /api/whoami`              the verified caller and profile
//! - `GET  /api/tools`               tools visible to the caller
//! - `POST /api/tools/{name}`        call a tool with a JSON arguments body
//! - `GET  /api/events/stream`       ledger events as server-sent events

use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use futures::Stream;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::UaError;
use ua_core::identity::Transport;

use crate::AppState;
use crate::auth::{AuthIdentity, caller_for, session_key};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/whoami", get(whoami))
        .route("/api/tools", get(list_tools))
        .route("/api/tools/{name}", post(call_tool))
        .route("/api/events/stream", get(event_stream))
}

async fn healthz(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION"), "tools": state.registry.len() }))
}

async fn whoami(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
) -> Json<Value> {
    let caller = caller_for(&state, &id, session_key(&headers), Transport::Http);
    Json(json!({
        "identity": caller.label,
        "kind": caller.kind,
        "verified": id.verified,
        "profile": caller.profile.as_str(),
    }))
}

async fn list_tools(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
) -> Json<Value> {
    let caller = caller_for(&state, &id, session_key(&headers), Transport::Http);
    let tools: Vec<Value> = state
        .registry
        .visible_to(&caller)
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "family": t.family,
                "read_only": t.read_only,
                "input_schema": t.input_schema,
            })
        })
        .collect();
    Json(json!({ "count": tools.len(), "tools": tools }))
}

/// Map an error to an HTTP status.
pub fn status_for(e: &UaError) -> StatusCode {
    match e {
        UaError::InvalidArgument(_) => StatusCode::BAD_REQUEST,
        UaError::NotFound(_) => StatusCode::NOT_FOUND,
        UaError::Denied { .. } => StatusCode::FORBIDDEN,
        UaError::ApprovalRequired { .. } => StatusCode::ACCEPTED,
        UaError::Conflict(_) => StatusCode::CONFLICT,
        UaError::Unauthenticated(_) => StatusCode::UNAUTHORIZED,
        UaError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn call_tool(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Option<Json<Value>>,
) -> Response {
    let caller = caller_for(&state, &id, session_key(&headers), Transport::Http);
    let args = body.map(|Json(v)| v).unwrap_or(Value::Null);
    match state.registry.call(&state.hub, &caller, &name, args).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (status_for(&e), Json(e.to_json())).into_response(),
    }
}

#[derive(Deserialize)]
struct StreamQuery {
    channel_prefix: Option<String>,
}

async fn event_stream(
    State(state): State<AppState>,
    Query(q): Query<StreamQuery>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.hub.db().subscribe();
    let prefix = q.channel_prefix.unwrap_or_default();
    let stream = futures::stream::unfold((rx, prefix), |(mut rx, prefix)| async move {
        loop {
            match rx.recv().await {
                Ok(ev) if ev.channel.starts_with(&prefix) => {
                    let data = serde_json::to_string(&ev).unwrap_or_default();
                    let sse = SseEvent::default().event(ev.channel.clone()).id(ev.seq.to_string()).data(data);
                    return Some((Ok(sse), (rx, prefix)));
                }
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
