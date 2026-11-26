//! Multi-organization fail-closed auth enforcement (#2807):
//! - `enforce_auth = false` is a single-organization mode only.
//! - With only `default` in `orgs`, unauthenticated loopback requests keep
//!   single-organization parity.
//! - As soon as `orgs` holds any organization other than `default` (active or
//!   suspended), `serve_http` refuses to start AND live unauthenticated
//!   non-public HTTP requests fail closed immediately with 401 naming the
//!   organization count read from the store.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use secrecy::SecretString;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use ua_server::AppState;
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
        assert!(msg.contains("2 organizations"), "{body}");
        assert!(msg.contains("enforce_auth = false"), "{body}");
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
    assert!(body["message"].as_str().unwrap_or_default().contains("2 organizations"), "{body}");
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
        let err = ua_server::serve_http(state, CancellationToken::new())
            .await
            .expect_err("serve_http must refuse auth-off with a second org");
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
