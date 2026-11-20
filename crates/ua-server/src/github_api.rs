//! `POST /api/github/webhook`: GitHub deliveries.
//!
//! The route takes no bearer token (GitHub cannot send one): the delivery
//! authenticates itself with `X-Hub-Signature-256`, an HMAC-SHA256 of the raw
//! body under the secret `github_webhook_secret_env` names. Everything after
//! reading the body (signature, replay check, effects) is
//! [`ua_tools::families::github::receive`]; its effects run as governed
//! registry calls under the hub's GitHub identity. The body must be
//! `application/json` (the JSON API guard refuses anything else) and at most
//! 5 MiB.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::json;
use ua_tools::families::github::{WebhookDelivery, receive};

use crate::AppState;

/// The webhook path; the auth layer lets it through without a bearer.
pub const WEBHOOK_PATH: &str = "/api/github/webhook";
const MAX_BODY: usize = 5 * 1024 * 1024;

pub fn routes() -> Router<AppState> {
    Router::new().route(WEBHOOK_PATH, post(webhook).layer(DefaultBodyLimit::max(MAX_BODY)))
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

async fn webhook(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let delivery = WebhookDelivery {
        event: header(&headers, "x-github-event").unwrap_or_default(),
        delivery_id: header(&headers, "x-github-delivery").unwrap_or_default(),
        signature: header(&headers, "x-hub-signature-256"),
        body: &body,
    };
    match receive(&state.hub, delivery).await {
        Ok(v) => (StatusCode::OK, axum::Json(v)).into_response(),
        Err(e) => {
            let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            if status.is_server_error() {
                tracing::warn!(code = e.code(), "GitHub webhook delivery failed: {}", e.message());
            }
            let body = json!({ "ok": false, "error": e.code(), "message": e.message() });
            (status, axum::Json(body)).into_response()
        }
    }
}
