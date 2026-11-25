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
//! Both routes share one cap, `github_webhook_max_in_flight` (default 16,
//! clamped to 1-256): a delivery holds one slot while its body is read and
//! while it is handled. When every slot is taken a delivery waits up to
//! `github_webhook_busy_wait_ms` (default 2000) for one, then is answered
//! 429 `busy` before its body is read, with nothing recorded. Once it holds
//! a slot it has `github_webhook_read_timeout_ms` (default 10000, GitHub's
//! own delivery timeout) to send its whole body; a slower one is answered
//! 408 `timeout` and its slot freed, so a sender that declares a body and
//! never sends it holds a slot for that long at most. A declared length
//! over 5 MiB is answered 413 before a slot is taken.
//!
//! **A turned-away delivery is lost unless something brings it back.**
//! GitHub does not redeliver a failed delivery on its own. Enable the poller
//! (`github_poll_interval_s`) as a backstop: it reconciles merged pull
//! requests and checks whatever the webhook missed. A delivery answered 429
//! or 408 can also be redelivered by hand from the hook's "Recent
//! Deliveries" page on GitHub.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::rejection::PathRejection;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use http_body_util::{BodyExt, LengthLimitError, Limited};
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

/// How long a delivery holding a slot may take to send its body:
/// `github_webhook_read_timeout_ms`, clamped to 50 ms-60 s.
pub fn read_timeout(cfg: &Config) -> Duration {
    Duration::from_millis(cfg.github_webhook_read_timeout_ms.clamp(50, 60_000))
}

/// How long a delivery waits for a slot before it is answered 429:
/// `github_webhook_busy_wait_ms`, at most 10 s.
pub fn busy_wait(cfg: &Config) -> Duration {
    Duration::from_millis(cfg.github_webhook_busy_wait_ms.min(10_000))
}

/// The shared cap and its two deadlines.
#[derive(Clone)]
struct Gate {
    slots: Arc<Semaphore>,
    wait: Duration,
    read: Duration,
}

pub fn routes(cfg: &Config) -> Router<AppState> {
    let gate = Gate {
        slots: Arc::new(Semaphore::new(max_in_flight(cfg))),
        wait: busy_wait(cfg),
        read: read_timeout(cfg),
    };
    // The gate wraps the body limit and the handler, and reads the body
    // itself under its deadline, so a delivery holds its slot while its body
    // is read, not only while it is handled, and never longer than the
    // deadline for the read.
    let capped = |r: axum::routing::MethodRouter<AppState>| {
        r.layer(DefaultBodyLimit::max(MAX_BODY)).layer(middleware::from_fn_with_state(gate.clone(), cap))
    };
    Router::new()
        .route(WEBHOOK_PATH, capped(post(default_webhook)))
        .route(ORG_WEBHOOK_PATH, capped(post(org_webhook)))
}

/// A refusal by the gate. Nothing is read further, recorded or ledgered.
fn turned_away(status: StatusCode, error: &str, message: &str) -> Response {
    let body = json!({ "ok": false, "error": error, "message": message });
    (status, axum::Json(body)).into_response()
}

/// Take a slot (waiting up to [`busy_wait`]), then read the whole body
/// within [`read_timeout`], then hand the buffered request on. The log
/// lines are debug only: anyone can send these.
async fn cap(State(gate): State<Gate>, req: Request, next: Next) -> Response {
    let declared = header(req.headers(), header::CONTENT_LENGTH.as_str()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > MAX_BODY as u64) {
        return turned_away(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "the body is larger than 5 MiB");
    }
    let Ok(Ok(permit)) = tokio::time::timeout(gate.wait, gate.slots.clone().acquire_owned()).await else {
        tracing::debug!("GitHub webhook: too many deliveries in flight; turned one away");
        let mut resp = turned_away(
            StatusCode::TOO_MANY_REQUESTS,
            "busy",
            "too many GitHub deliveries in flight; redeliver shortly",
        );
        resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    };
    let (parts, body) = req.into_parts();
    let bytes = match tokio::time::timeout(gate.read, Limited::new(body, MAX_BODY).collect()).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return turned_away(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "the body is larger than 5 MiB");
        }
        Ok(Err(_)) => {
            return turned_away(StatusCode::BAD_REQUEST, "bad_request", "the body could not be read");
        }
        Err(_) => {
            // The permit is dropped with this return: the slot is free again.
            tracing::debug!("GitHub webhook: a delivery's body did not arrive in time; turned it away");
            return turned_away(
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                "the body was not received in time; redeliver it",
            );
        }
    };
    let resp = next.run(Request::from_parts(parts, Body::from(bytes))).await;
    drop(permit);
    resp
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

async fn default_webhook(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    webhook(&state, ua_core::DEFAULT_ORG, &headers, &body).await
}

/// An organization id that does not even decode (not UTF-8, say) is
/// refused like any other malformed id: the same checks, the same 401.
async fn org_webhook(
    State(state): State<AppState>,
    org: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let org = org.map(|Path(org)| org).unwrap_or_default();
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
