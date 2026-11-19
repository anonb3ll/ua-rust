//! The node device plane over HTTP: who may register and heartbeat, the
//! refusal shapes a node keys on, and the read-only listing.

mod common;

use axum::http::StatusCode;
use common::{TestHub, get, json_body, post_json};
use secrecy::SecretString;
use serde_json::json;
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};

const BUILDER: &str = "builder-1-test-token-0001";
const OTHER: &str = "builder-2-test-token-0002";
const OPERATOR: &str = "operator-test-token-0003";

fn config() -> Config {
    let mut cfg = common::config();
    cfg.oauth_enabled = false;
    cfg.agent_tokens =
        Some(SecretString::from(format!("builder-1:{BUILDER},builder-2:{OTHER},operator:{OPERATOR}")));
    cfg
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

async fn post(
    hub: &TestHub,
    path: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let auth = token.map(bearer);
    let headers: Vec<(&str, &str)> = auth.as_deref().map(|a| vec![("authorization", a)]).unwrap_or_default();
    let resp = hub.send(post_json(path, &body, &headers)).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

#[tokio::test]
async fn an_agent_registers_heartbeats_and_lists_its_node() {
    let hub = TestHub::new(config());
    let facts = json!({ "backends": ["codex"], "worktree_roots": [{ "path": "/srv/work", "realpath": "/srv/work" }] });
    let (status, v) = post(
        &hub,
        "/api/node/register",
        Some(BUILDER),
        json!({ "node": "node-a", "facts": facts, "version": "0.1.0" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["agent"], "builder-1");
    assert_eq!(v["first_registration"], true);

    let (status, v) = post(
        &hub,
        "/api/node/heartbeat",
        Some(BUILDER),
        json!({ "node": "node-a", "running": null, "progress": null }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["cancel"], json!([]));

    let resp = hub.send(get("/api/nodes", None, Some(OTHER))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["nodes"][0]["node"], "node-a");
    assert_eq!(v["nodes"][0]["status"], "live");
    assert_eq!(v["nodes"][0]["backends"], json!(["codex"]));
    assert_eq!(v["nodes"][0]["worktree_roots"], json!(["/srv/work"]));
    assert_eq!(v["retired_nodes"], json!([]));
}

#[tokio::test]
async fn only_an_authenticated_agent_owns_a_node() {
    let hub = TestHub::new(config());
    let (status, _) = post(&hub, "/api/node/register", None, json!({ "node": "node-a" })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, v) = post(&hub, "/api/node/register", Some(OPERATOR), json!({ "node": "node-a" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "agent_identity_required");

    // The owner comes from the credential, never the body.
    let (status, v) =
        post(&hub, "/api/node/register", Some(OTHER), json!({ "node": "node-a", "agent": "builder-1" }))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");

    let (status, _) = post(&hub, "/api/node/register", Some(BUILDER), json!({ "node": "node-a" })).await;
    assert_eq!(status, StatusCode::OK);
    let (status, v) = post(&hub, "/api/node/heartbeat", Some(OTHER), json!({ "node": "node-a" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "node_owned_elsewhere");

    let (status, v) = post(&hub, "/api/node/heartbeat", Some(BUILDER), json!({ "node": "node-z" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{v}");
    assert!(v["error"].as_str().unwrap().contains("not registered"), "{v}");
}

#[tokio::test]
async fn a_retired_node_is_refused_with_node_retired() {
    let hub = TestHub::new(config());
    let (status, _) = post(&hub, "/api/node/register", Some(BUILDER), json!({ "node": "node-a" })).await;
    assert_eq!(status, StatusCode::OK);

    let operator = Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Http,
    };
    hub.state
        .registry
        .call(
            &hub.state.hub,
            &operator,
            "coordination_manage",
            json!({ "action": "node_retire", "params": { "node": "node-a", "reason": "decommissioned" } }),
        )
        .await
        .unwrap();

    for path in ["/api/node/heartbeat", "/api/node/register"] {
        let (status, v) = post(&hub, path, Some(BUILDER), json!({ "node": "node-a" })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {v}");
        assert_eq!(v["code"], "node_retired", "{path}");
    }
    let v = json_body(hub.send(get("/api/nodes", None, Some(BUILDER))).await).await;
    assert_eq!(v["nodes"], json!([]));
    assert_eq!(v["retired_nodes"][0]["node"], "node-a");
}

#[tokio::test]
async fn queue_routes_are_not_built_yet() {
    let hub = TestHub::new(config());
    let (status, v) = post(&hub, "/api/node/claim", Some(BUILDER), json!({ "node": "node-a" })).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{v}");
    assert_eq!(v["capability"], "node_queue");
    let resp = hub.send(get("/api/nodes/acceptance", None, Some(BUILDER))).await;
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}
