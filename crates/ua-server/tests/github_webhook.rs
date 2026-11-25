//! The GitHub webhook routes: `POST /api/github/webhook` (the default
//! organization) and `POST /api/github/webhook/{org}`, through the full
//! router. Every refusal is the same bytes, both routes need no bearer, and
//! both share the in-flight cap. Every value is fake.

mod common;

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode, header};
use common::{TestHub, json_body, post_json};
use http_body_util::BodyExt;
use secrecy::SecretString;
use serde_json::json;
use ua_core::Config;

const HUB_HOOK: &str = "fake-hub-webhook-not-real-5e10";
const WRONG_HOOK: &str = "fake-wrong-webhook-not-real-5e10";

fn config(hub_secret: bool) -> Config {
    let mut cfg = common::config();
    if hub_secret {
        cfg.github_webhook_secret_value = Some(SecretString::from(HUB_HOOK));
    }
    cfg
}

fn hub_with_orgs(cfg: Config) -> TestHub {
    let hub = TestHub::new(cfg);
    hub.state
        .hub
        .db()
        .write(|tx| {
            tx.execute_batch(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) VALUES
                    ('org-b', 'org-b', 'org-b', '[\"developer\"]', '2026-01-01T00:00:00+00:00'),
                    ('org-s', 'org-s', 'org-s', '[\"developer\"]', '2026-01-01T00:00:00+00:00');
                 UPDATE orgs SET status = 'suspended' WHERE id = 'org-s';",
            )?;
            Ok(())
        })
        .unwrap();
    hub
}

fn ping(path: &str, secret: Option<&str>, delivery: &str) -> Request<Body> {
    // A distinct body per delivery: the same body twice is a replay.
    let body = json!({ "zen": format!("fake {delivery}") });
    let sig =
        secret.map(|s| ua_tools::families::github::signature_for(s.as_bytes(), body.to_string().as_bytes()));
    let mut headers = vec![("x-github-event", "ping"), ("x-github-delivery", delivery)];
    if let Some(sig) = sig.as_deref() {
        headers.push(("x-hub-signature-256", sig));
    }
    post_json(path, &body, &headers)
}

/// Status, content type and the exact body bytes.
async fn answer(hub: &TestHub, req: Request<Body>) -> (StatusCode, String, Bytes) {
    let resp = hub.send(req).await;
    let status = resp.status();
    let ct =
        resp.headers().get(header::CONTENT_TYPE).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
    (status, ct, resp.into_body().collect().await.unwrap().to_bytes())
}

/// Unknown, suspended, secretless and malformed organizations, and bad or
/// missing signatures on either route, are one answer byte for byte; the
/// default organization's route without a secret too.
#[tokio::test]
async fn every_refusal_is_byte_identical_on_both_routes() {
    let hub = hub_with_orgs(config(true));
    let reference = answer(&hub, ping("/api/github/webhook/org-nope", Some(HUB_HOOK), "p-1")).await;
    assert_eq!(reference.0, StatusCode::UNAUTHORIZED);
    let v: serde_json::Value = serde_json::from_slice(&reference.2).unwrap();
    assert_eq!(v["error"], "bad_signature", "{v}");
    let cases = [
        ("suspended", ping("/api/github/webhook/org-s", Some(HUB_HOOK), "p-2")),
        ("no secret", ping("/api/github/webhook/org-b", Some(HUB_HOOK), "p-3")),
        ("malformed id", ping("/api/github/webhook/org%20b", Some(HUB_HOOK), "p-4")),
        ("id not UTF-8", ping("/api/github/webhook/%FF", Some(HUB_HOOK), "p-11")),
        ("bad signature, org route", ping("/api/github/webhook/org-b", Some(WRONG_HOOK), "p-5")),
        ("no signature, org route", ping("/api/github/webhook/org-b", None, "p-6")),
        ("bad signature, default route", ping("/api/github/webhook", Some(WRONG_HOOK), "p-7")),
        ("bad signature, default by id", ping("/api/github/webhook/default", Some(WRONG_HOOK), "p-8")),
        ("no signature, default route", ping("/api/github/webhook", None, "p-9")),
    ];
    for (what, req) in cases {
        assert_eq!(answer(&hub, req).await, reference, "{what}");
    }
    // A hub with no default secret answers the same.
    let bare = hub_with_orgs(config(false));
    assert_eq!(answer(&bare, ping("/api/github/webhook", Some(HUB_HOOK), "p-10")).await, reference, "unset");
    // Nothing was recorded for any of them.
    let n: i64 = hub
        .state
        .hub
        .db()
        .read(|c| Ok(c.query_row("SELECT count(*) FROM inbound_deliveries", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(n, 0);
}

/// The default organization's secret works on the bare route and on
/// `/api/github/webhook/default`, and on no other organization's route.
/// Neither route needs a bearer; a deeper path is not a webhook route.
#[tokio::test]
async fn the_default_secret_verifies_only_the_default_organizations_routes() {
    let hub = hub_with_orgs(config(true));
    let resp = hub.send(ping("/api/github/webhook", Some(HUB_HOOK), "d-1")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["handled"], "ping");
    let resp = hub.send(ping("/api/github/webhook/default", Some(HUB_HOOK), "d-2")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["org_id"], "default");
    let resp = hub.send(ping("/api/github/webhook/org-b", Some(HUB_HOOK), "d-3")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(resp).await["error"], "bad_signature");
    // Two segments below is not a public path: the bearer check answers.
    let resp = hub.send(ping("/api/github/webhook/org-b/x", Some(HUB_HOOK), "d-4")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(json_body(resp).await["error"], "bad_signature");
}

/// A body that never ends: a delivery reading it holds its permit.
fn stalled(path: &str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-github-event", "ping")
        .header("x-github-delivery", "stalled-1")
        .body(Body::from_stream(futures::stream::pending::<Result<Bytes, std::io::Error>>()))
        .unwrap()
}

/// Drive `fut` until it is waiting (on its body, or for a slot).
async fn park<F: std::future::Future + Unpin>(fut: &mut F) {
    for _ in 0..20 {
        assert!(futures::poll!(&mut *fut).is_pending(), "the stalled delivery was answered");
        tokio::task::yield_now().await;
    }
}

/// A stalled delivery to `path`, started and parked on its body.
async fn start_stalled(
    hub: &TestHub,
    path: &str,
) -> std::pin::Pin<
    Box<impl std::future::Future<Output = Result<axum::response::Response, std::convert::Infallible>>>,
> {
    use tower::ServiceExt;
    let mut fut = Box::pin(hub.app.clone().oneshot(stalled(path)));
    park(&mut fut).await;
    fut
}

/// With every slot held by a delivery whose body is still being read, the
/// next one, on either route, waits `github_webhook_busy_wait_ms` and is
/// then answered 429 `busy` with `Retry-After`, and nothing is recorded:
/// the cap still trips under true overload. Once the first goes away,
/// deliveries are taken again.
#[tokio::test]
async fn the_in_flight_cap_turns_deliveries_away() {
    let mut cfg = config(true);
    cfg.github_webhook_max_in_flight = 2;
    cfg.github_webhook_busy_wait_ms = 50;
    cfg.github_webhook_read_timeout_ms = 60_000;
    let hub = hub_with_orgs(cfg);
    let first = start_stalled(&hub, "/api/github/webhook/org-b").await;
    let second = start_stalled(&hub, "/api/github/webhook").await;
    let started = std::time::Instant::now();
    let busy = hub.send(ping("/api/github/webhook", Some(HUB_HOOK), "c-1")).await;
    assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(started.elapsed() >= std::time::Duration::from_millis(50), "it waited for a slot first");
    assert_eq!(busy.headers().get(header::RETRY_AFTER).unwrap(), "1");
    assert_eq!(json_body(busy).await["error"], "busy");
    let resp = hub.send(ping("/api/github/webhook/org-b", Some(HUB_HOOK), "c-2")).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "the cap covers both routes");

    drop(first);
    let resp = hub.send(ping("/api/github/webhook", Some(HUB_HOOK), "c-3")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    drop(second);
    let n: i64 = hub
        .state
        .hub
        .db()
        .read(|c| Ok(c.query_row("SELECT count(*) FROM inbound_deliveries", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(n, 2, "only the one delivery taken was recorded (its id and body)");
}

/// A delivery that declares a body and never sends it holds its slot for
/// `github_webhook_read_timeout_ms` at most: it is then answered 408
/// `timeout`, and its slot serves the next delivery.
#[tokio::test]
async fn a_stalled_body_releases_its_slot_after_the_deadline() {
    let mut cfg = config(true);
    cfg.github_webhook_max_in_flight = 1;
    cfg.github_webhook_busy_wait_ms = 0;
    cfg.github_webhook_read_timeout_ms = 200;
    let hub = hub_with_orgs(cfg);
    let stalled = start_stalled(&hub, "/api/github/webhook/org-b").await;
    let busy = hub.send(ping("/api/github/webhook", Some(HUB_HOOK), "t-1")).await;
    assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS, "the slot is held while the body is awaited");
    let started = std::time::Instant::now();
    let resp = stalled.await.unwrap();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(json_body(resp).await["error"], "timeout");
    let resp = hub.send(ping("/api/github/webhook", Some(HUB_HOOK), "t-2")).await;
    assert_eq!(resp.status(), StatusCode::OK, "the slot was freed");
}

/// Stalled senders below the cap leave room: a real delivery is answered at
/// once, long before their deadline.
#[tokio::test]
async fn stalled_senders_below_the_cap_do_not_block_a_real_delivery() {
    let mut cfg = config(true);
    cfg.github_webhook_max_in_flight = 4;
    cfg.github_webhook_busy_wait_ms = 0;
    cfg.github_webhook_read_timeout_ms = 60_000;
    let hub = hub_with_orgs(cfg);
    let mut held = Vec::new();
    for path in ["/api/github/webhook", "/api/github/webhook/org-b", "/api/github/webhook/org-nope"] {
        held.push(start_stalled(&hub, path).await);
    }
    let resp = hub.send(ping("/api/github/webhook", Some(HUB_HOOK), "r-1")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["handled"], "ping");
    drop(held);
}

/// A declared body over 5 MiB is refused before it takes a slot.
#[tokio::test]
async fn an_oversized_declared_body_is_refused_without_a_slot() {
    let mut cfg = config(true);
    cfg.github_webhook_max_in_flight = 1;
    cfg.github_webhook_busy_wait_ms = 0;
    let hub = hub_with_orgs(cfg);
    let _held = start_stalled(&hub, "/api/github/webhook").await;
    let req = Request::post("/api/github/webhook")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, (5 * 1024 * 1024 + 1).to_string())
        .body(Body::from_stream(futures::stream::pending::<Result<Bytes, std::io::Error>>()))
        .unwrap();
    assert_eq!(hub.send(req).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn the_cap_defaults_to_sixteen_and_is_at_least_one() {
    use std::time::Duration;
    use ua_server::github_api::{busy_wait, max_in_flight, read_timeout};
    let mut cfg = Config::default();
    assert_eq!(max_in_flight(&cfg), 16);
    assert_eq!(read_timeout(&cfg), Duration::from_secs(10));
    assert_eq!(busy_wait(&cfg), Duration::from_secs(2));
    cfg.github_webhook_max_in_flight = 0;
    assert_eq!(max_in_flight(&cfg), 1);
    cfg.github_webhook_max_in_flight = 1_000_000;
    assert_eq!(max_in_flight(&cfg), 256);
    cfg.github_webhook_read_timeout_ms = 0;
    assert_eq!(read_timeout(&cfg), Duration::from_millis(50));
    cfg.github_webhook_read_timeout_ms = u64::MAX;
    assert_eq!(read_timeout(&cfg), Duration::from_secs(60));
    cfg.github_webhook_busy_wait_ms = u64::MAX;
    assert_eq!(busy_wait(&cfg), Duration::from_secs(10));
    assert!(ua_server::github_api::is_webhook_path("/api/github/webhook"));
    assert!(ua_server::github_api::is_webhook_path("/api/github/webhook/org-b"));
    assert!(!ua_server::github_api::is_webhook_path("/api/github/webhook/"));
    assert!(!ua_server::github_api::is_webhook_path("/api/github/webhook/a/b"));
    assert!(!ua_server::github_api::is_webhook_path("/api/github/webhooks"));
}
