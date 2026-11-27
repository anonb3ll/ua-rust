//! Multi-organization fail-closed auth enforcement (#2807):
//! - `enforce_auth = false` is a single-organization mode only.
//! - With only `default` in `orgs`, unauthenticated loopback requests keep
//!   single-organization parity.
//! - As soon as `orgs` holds any organization other than `default` (active or
//!   suspended), `serve_http` refuses to start, live unauthenticated non-public
//!   HTTP requests fail closed immediately with a fixed 401 message (without
//!   leaking store details), and open anonymous event streams revoke with
//!   `auth_revoked`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Response, StatusCode};
use http_body_util::BodyExt;
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use ua_server::AppState;
use ua_store::{EventInput, ledger};
use ua_tools::{Hub, builtin_registry};

use common::{TestHub, config, get, json_body, post_json, text_body};

fn insert_org(hub: &Hub, id: &str, status: &str) {
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, status, allowed_profiles, created_at) \
                 VALUES (?1, ?1, ?2, ?3, '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                rusqlite::params![id, format!("Org {id}"), status],
            )?;
            Ok(())
        })
        .unwrap();
}

fn append_event(hub: &Hub, channel: &str) -> i64 {
    hub.db()
        .write(|tx| {
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, channel, json!({})).by("tester"))
        })
        .unwrap()
        .unwrap()
        .seq
}

async fn read_until_contains(body: &mut Body, needle: &str) -> String {
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !text.contains(needle) {
        let frame = tokio::time::timeout_at(deadline, body.frame())
            .await
            .unwrap_or_else(|_| panic!("stream stalled waiting for {needle:?}; got {text:?}"))
            .unwrap_or_else(|| panic!("stream ended before {needle:?}; got {text:?}"))
            .unwrap();
        if let Ok(data) = frame.into_data() {
            text.push_str(&String::from_utf8_lossy(&data));
        }
    }
    text
}

async fn expect_auth_revoked(resp: Response<Body>, expected_reason: &str, forbidden_text: Option<&str>) {
    let mut body = resp.into_body();
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    text.push_str(&String::from_utf8_lossy(&data));
                }
            }
            Ok(None) | Ok(Some(Err(_))) => break,
            Err(_) => panic!("stream remained open instead of revoking; got {text:?}"),
        }
    }
    if let Some(forbidden) = forbidden_text {
        assert!(!text.contains(forbidden), "unexpected event {forbidden:?} delivered in {text:?}");
    }
    let at =
        text.rfind("event: auth_revoked\n").unwrap_or_else(|| panic!("no auth_revoked event in {text:?}"));
    let tail = &text[at..];
    let data = tail.lines().find_map(|l| l.strip_prefix("data: ")).expect("auth_revoked data");
    let v: Value = serde_json::from_str(data).unwrap();
    assert_eq!(v["auth_revoked"], true);
    assert_eq!(v["reason"], expected_reason);
    assert!(
        !tail.lines().any(|l| l.starts_with("event: ") && l != "event: auth_revoked"),
        "events delivered after auth_revoked: {tail:?}"
    );
}

#[tokio::test]
async fn unauthenticated_requests_fail_closed_immediately_when_second_org_appears() {
    let mut cfg = config();
    cfg.enforce_auth = false;
    cfg.agent_tokens = Some(SecretString::from("builder-1:tok-builder-1".to_string()));
    let h = TestHub::new(cfg);

    // 1. Single-organization parity: with only `default`, unauthenticated requests succeed.
    let who = h.send(get("/api/whoami", None, None)).await;
    assert_eq!(who.status(), StatusCode::OK);
    let who_json = json_body(who).await;
    assert_eq!(who_json["verified"], false);
    assert_eq!(who_json["identity"], ua_server::auth::LOCAL_LABEL);

    let tools = h.send(post_json("/api/tools/task_list", &json!({}), &[])).await;
    assert_eq!(tools.status(), StatusCode::OK);

    let ui = h.send(get("/ui/messages", None, None)).await;
    assert_eq!(ui.status(), StatusCode::OK);

    // 2. Create a second (active) organization while the hub is running: zero window.
    insert_org(&h.state.hub, "org-b", "active");

    for req in [
        get("/api/whoami", None, None),
        get("/api/tools", None, None),
        post_json("/api/tools/message_list", &json!({}), &[]),
        get("/ui/messages", None, None),
    ] {
        let resp = h.send(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = json_body(resp).await;
        assert_eq!(body["error"], "unauthenticated");
        let msg = body["message"].as_str().unwrap_or_default();
        assert!(msg.contains("single-organization only"), "{body}");
        assert!(msg.contains("enforce_auth = true"), "{body}");
        assert!(!msg.contains("2 organizations"), "should not leak store counts to anonymous caller: {body}");
    }

    // Public health endpoint remains reachable.
    let health = h.send(get("/healthz", None, None)).await;
    assert_eq!(health.status(), StatusCode::OK);

    // Authenticated requests still resolve their verified identity (never anonymous).
    let authed = h.send(get("/api/whoami", None, Some("tok-builder-1"))).await;
    assert_eq!(authed.status(), StatusCode::OK);
    let authed_json = json_body(authed).await;
    assert_eq!(authed_json["verified"], true);
    assert_eq!(authed_json["identity"], "builder-1");

    // 3. Suspending the second organization STILL fails closed (active or suspended).
    h.state
        .hub
        .db()
        .write(|tx| {
            tx.execute("UPDATE orgs SET status = 'suspended' WHERE id = 'org-b'", [])?;
            Ok(())
        })
        .unwrap();

    let resp = h.send(get("/api/whoami", None, None)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(resp).await;
    assert!(body["message"].as_str().unwrap_or_default().contains("single-organization only"), "{body}");

    // 4. A missing/unreadable `orgs` table fails closed with the fixed message (never SQLite error text).
    h.state
        .hub
        .db()
        .write(|tx| {
            tx.execute_batch("PRAGMA foreign_keys = OFF; DROP TABLE orgs;")?;
            Ok(())
        })
        .unwrap();
    let resp = h.send(get("/api/whoami", None, None)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(resp).await;
    let msg = body["message"].as_str().unwrap_or_default();
    assert!(msg.contains("single-organization only"), "{body}");
    assert!(!msg.contains("orgs table"), "should not leak store error text: {body}");
    assert!(!msg.contains("no such table"), "should not leak sqlite error text: {body}");
}

#[tokio::test]
async fn open_anonymous_event_streams_revoke_when_second_org_appears() {
    let mut cfg = config();
    cfg.enforce_auth = false;
    let h = TestHub::new(cfg);

    // Open both SSE endpoints anonymously while only `default` exists.
    let api_resp = h.send(get("/api/events/stream?channel_prefix=test.keep", None, None)).await;
    assert_eq!(api_resp.status(), StatusCode::OK);
    let mut api_body = api_resp.into_body();

    let ui_resp = h.send(get("/ui/activity/stream?channel_prefix=test.keep", None, None)).await;
    assert_eq!(ui_resp.status(), StatusCode::OK);
    let mut ui_body = ui_resp.into_body();

    // Confirm both streams deliver events in single-org mode and populate the 1 s per-event cache.
    let before = append_event(&h.state.hub, "test.keep");
    read_until_contains(&mut api_body, &format!("id: {before}\n")).await;
    read_until_contains(&mut ui_body, &format!("id: {before}\n")).await;
    assert!(h.state.auth_policy.is_fresh());

    // Insert a second organization while both streams are open.
    insert_org(&h.state.hub, "org-b", "active");

    // Once the ~1 s per-event cache TTL expires, the next event revokes both streams without
    // delivering the post-TTL event.
    tokio::time::sleep(ua_server::auth::AUTH_POLICY_CACHE_TTL + Duration::from_millis(50)).await;
    let after = append_event(&h.state.hub, "test.keep");
    let forbidden = format!("id: {after}\n");
    expect_auth_revoked(Response::new(api_body), "auth_required_multi_org", Some(&forbidden)).await;
    expect_auth_revoked(Response::new(ui_body), "auth_required_multi_org", Some(&forbidden)).await;

    // New anonymous stream opens are refused with 401.
    for path in ["/api/events/stream", "/ui/activity/stream"] {
        let resp = h.send(get(path, None, None)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn open_anonymous_stream_revokes_immediately_on_auth_channel_even_while_cache_is_fresh() {
    let mut cfg = config();
    cfg.enforce_auth = false;
    let h = TestHub::new(cfg);

    let api_resp = h.send(get("/api/events/stream?channel_prefix=test.keep", None, None)).await;
    assert_eq!(api_resp.status(), StatusCode::OK);
    let mut api_body = api_resp.into_body();

    let before = append_event(&h.state.hub, "test.keep");
    read_until_contains(&mut api_body, &format!("id: {before}\n")).await;
    assert!(h.state.auth_policy.is_fresh());

    insert_org(&h.state.hub, "org-b", "active");
    // Auth-channel re-check bypasses the 1 s per-event cache and revokes without waiting for TTL.
    append_event(&h.state.hub, "agent.config.revision");
    let after = append_event(&h.state.hub, "test.keep");
    let forbidden = format!("id: {after}\n");
    expect_auth_revoked(Response::new(api_body), "auth_required_multi_org", Some(&forbidden)).await;
    assert!(!h.state.auth_policy.is_fresh());
}

#[tokio::test]
async fn failed_http_auth_check_invalidates_stream_cache_immediately() {
    let mut cfg = config();
    cfg.enforce_auth = false;
    let h = TestHub::new(cfg);

    let api_resp = h.send(get("/api/events/stream?channel_prefix=test.keep", None, None)).await;
    assert_eq!(api_resp.status(), StatusCode::OK);
    let mut api_body = api_resp.into_body();

    let before = append_event(&h.state.hub, "test.keep");
    read_until_contains(&mut api_body, &format!("id: {before}\n")).await;
    assert!(h.state.auth_policy.is_fresh());

    // Insert org-b, then trigger a failed unauthenticated HTTP request without sleeping for TTL:
    // the failed HTTP check must invalidate `AppState::auth_policy` so the open stream revokes
    // on the very next event without waiting for the 1 s TTL.
    insert_org(&h.state.hub, "org-b", "active");
    let resp = h.send(get("/api/whoami", None, None)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(!h.state.auth_policy.is_fresh(), "failed HTTP auth check must invalidate stream cache");

    let after = append_event(&h.state.hub, "test.keep");
    let forbidden = format!("id: {after}\n");
    expect_auth_revoked(Response::new(api_body), "auth_required_multi_org", Some(&forbidden)).await;
}

#[tokio::test]
async fn serve_http_refuses_to_bind_when_auth_off_and_second_org_exists() {
    for status in ["active", "suspended"] {
        let mut cfg = config();
        cfg.enforce_auth = false;
        cfg.bind = "127.0.0.1:0".parse().unwrap();
        let hub = Hub::in_memory(cfg).unwrap();
        insert_org(&hub, "org-b", status);

        let state = AppState::new(hub, Arc::new(builtin_registry()));
        let shutdown = CancellationToken::new();
        let err = match tokio::time::timeout(
            Duration::from_secs(5),
            ua_server::serve_http(state, shutdown.clone()),
        )
        .await
        {
            Ok(res) => res.expect_err("serve_http must refuse auth-off with a second org"),
            Err(_) => {
                shutdown.cancel();
                panic!("serve_http bound and kept serving instead of refusing auth-off with status={status}");
            }
        };
        let msg = err.to_string();
        assert!(msg.contains("2 organizations"), "status={status}: {msg}");
        assert!(msg.contains("enforce_auth = false"), "status={status}: {msg}");
    }

    // Single-organization parity: `check_auth_policy` passes with only `default`.
    let mut single_cfg = config();
    single_cfg.enforce_auth = false;
    single_cfg.bind = "127.0.0.1:0".parse().unwrap();
    let single_hub = Hub::in_memory(single_cfg).unwrap();
    ua_server::auth::check_auth_policy(&single_hub).unwrap();
    // Ensure `/healthz` body helper stays used without warnings.
    let _ = text_body;
}
