//! HTTP/JSON API.
//!
//! - `GET  /healthz`                 liveness, no auth
//! - `GET  /api/whoami`              the verified caller and profile
//! - `GET  /api/tools`               tools visible to the caller
//! - `POST /api/tools/{name}`        call a tool with a JSON arguments body
//! - `GET  /api/events/stream`       ledger events as server-sent events (scoped, resumable)

use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::UaError;
use ua_core::identity::Transport;
use ua_tools::families::events::EventScope;

use crate::AppState;
use crate::auth::{AuthIdentity, caller_for, session_key};
use crate::events::{self, StreamItem};

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
    /// Resume after this seq when no `Last-Event-ID` header is sent.
    after_seq: Option<i64>,
}

/// Ledger events as server-sent events: event name = channel, id = seq,
/// data = the event as JSON. A `gap` event names a range that may be
/// missing. Scoped and resumable as described in [`crate::events`].
async fn event_stream(
    State(state): State<AppState>,
    Extension(id): Extension<AuthIdentity>,
    headers: HeaderMap,
    Query(q): Query<StreamQuery>,
) -> Response {
    let caller = caller_for(&state, &id, session_key(&headers), Transport::Http);
    let scope = EventScope { channels: None, channel_prefix: q.channel_prefix.filter(|p| !p.is_empty()) };
    let resume = events::resume_point(&headers, q.after_seq);
    match events::open(&state, &caller, scope, resume).await {
        Ok(stream) => Sse::new(stream.map(sse_json)).keep_alive(KeepAlive::default()).into_response(),
        Err(e) => (status_for(&e), Json(e.to_json())).into_response(),
    }
}

fn sse_json(item: StreamItem) -> Result<SseEvent, Infallible> {
    Ok(match item {
        StreamItem::Event(ev) => {
            let data = serde_json::to_string(&ev).unwrap_or_default();
            SseEvent::default().event(ev.channel.clone()).id(ev.seq.to_string()).data(data)
        }
        StreamItem::Gap { after_seq, until_seq, reason } => SseEvent::default()
            .event("gap")
            .data(StreamItem::gap_json(after_seq, until_seq, reason).to_string()),
    })
}
