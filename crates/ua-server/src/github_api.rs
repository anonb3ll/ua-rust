//! GitHub deliveries: `POST /api/github/webhook/{org}` for each organization,
//! and `POST /api/github/webhook` for the default organization.
//!
//! Neither route takes a bearer token (GitHub cannot send one): a delivery
//! authenticates itself with `X-Hub-Signature-256`, an HMAC-SHA256 of the raw
//! body under the routed organization's own webhook secret, and only that
//! one secret is checked. Everything after reading the body (signature,
//! replay check, effects) is [`ua_tools::families::github::receive_org`];
//! its effects run as governed registry calls under the hub's GitHub
//! identity for that organization. The body must be `application/json` (the
//! JSON API guard refuses anything else) and at most 5 MiB.
//!
//! Both routes share one cap, `github_webhook_max_in_flight` (default 4):
//! a delivery that arrives while that many are being read or handled is
//! answered 429 `busy` before its body is read, with nothing recorded, so
//! GitHub's redelivery is processed normally.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::json;
use tokio::sync::Semaphore;
use ua_core::Config;
use ua_tools::families::github::{WebhookDelivery, WebhookError, receive_org};

use crate::AppState;

/// The default organization's webhook path; the auth layer lets it, and one
/// path segment below it ([`is_webhook_path`]), through without a bearer.
pub const WEBHOOK_PATH: &str = "/api/github/webhook";
/// Each organization's webhook route, by organization id.
pub const ORG_WEBHOOK_PATH: &str = "/api/github/webhook/{org}";
const MAX_BODY: usize = 5 * 1024 * 1024;
/// The cap's upper bound, whatever the configuration says.
const MAX_IN_FLIGHT_CEILING: usize = 256;

/// Whether `path` is one of the webhook routes: [`WEBHOOK_PATH`] or exactly
/// one non-empty segment below it.
pub fn is_webhook_path(path: &str) -> bool {
    path == WEBHOOK_PATH
        || path
            .strip_prefix(WEBHOOK_PATH)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|org| !org.is_empty() && !org.contains('/'))
}

/// The configured cap: `github_webhook_max_in_flight`, at least 1 and at
/// most [`MAX_IN_FLIGHT_CEILING`].
pub fn max_in_flight(cfg: &Config) -> usize {
    cfg.github_webhook_max_in_flight.clamp(1, MAX_IN_FLIGHT_CEILING)
}

pub fn routes(cfg: &Config) -> Router<AppState> {
    let gate = Arc::new(Semaphore::new(max_in_flight(cfg)));
    // The gate wraps the body limit and the handler, so a delivery holds its
    // permit while its body is read, not only while it is handled.
    let capped = |r: axum::routing::MethodRouter<AppState>| {
        r.layer(DefaultBodyLimit::max(MAX_BODY)).layer(middleware::from_fn_with_state(gate.clone(), cap))
    };
    Router::new()
        .route(WEBHOOK_PATH, capped(post(default_webhook)))
        .route(ORG_WEBHOOK_PATH, capped(post(org_webhook)))
}

/// Turn a delivery away when [`max_in_flight`] are already being read or
/// handled. Nothing is read, recorded or ledgered, and the log line is
/// debug only: anyone can send these.
async fn cap(State(gate): State<Arc<Semaphore>>, req: Request, next: Next) -> Response {
    let Ok(_permit) = gate.try_acquire() else {
        tracing::debug!("GitHub webhook: too many deliveries in flight; turned one away");
        let body = json!({
            "ok": false, "error": "busy",
            "message": "too many GitHub deliveries in flight; redeliver shortly",
        });
        let mut resp = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
        resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    };
    next.run(req).await
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

async fn default_webhook(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    webhook(&state, ua_core::DEFAULT_ORG, &headers, &body).await
}

async fn org_webhook(
    State(state): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    webhook(&state, &org, &headers, &body).await
}

async fn webhook(state: &AppState, org: &str, headers: &HeaderMap, body: &[u8]) -> Response {
    let delivery = WebhookDelivery {
        event: header(headers, "x-github-event").unwrap_or_default(),
        delivery_id: header(headers, "x-github-delivery").unwrap_or_default(),
        signature: header(headers, "x-hub-signature-256"),
        body,
    };
    match receive_org(&state.hub, org, delivery).await {
        Ok(v) => (StatusCode::OK, axum::Json(v)).into_response(),
        Err(e) => {
            let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            if status.is_server_error() {
                // receive_org has logged another organization's failure with
                // its text and answers it neutrally; this line carries only
                // what the sender is told.
                tracing::warn!(code = e.code(), "GitHub webhook delivery failed: {}", e.message());
            } else if e == WebhookError::BadSignature {
                tracing::debug!("refused a GitHub delivery");
            }
            let body = json!({ "ok": false, "error": e.code(), "message": e.message() });
            (status, axum::Json(body)).into_response()
        }
    }
}
