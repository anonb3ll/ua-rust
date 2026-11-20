//! The harness config bundle over HTTP: `GET|POST /api/node/config` with the
//! Python hub's request and response shapes (get, report, applied, the
//! `202 approval_pending` answer), its refusals, and `GET /api/harness-config`.

mod common;

use axum::http::StatusCode;
use common::{TestHub, get, json_body, post_json};
use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};

const BUILDER: &str = "builder-1-test-token-0001";
const OTHER: &str = "builder-2-test-token-0002";
const OPS: &str = "ops-bot-test-token-0003";

fn config() -> Config {
    let mut cfg = common::config();
    cfg.oauth_enabled = false;
    cfg.agent_tokens =
        Some(SecretString::from(format!("builder-1:{BUILDER},builder-2:{OTHER},ops-bot:{OPS}")));
    cfg.lifecycle_operators = Some(vec!["operator".into(), "ops-bot".into()]);
    cfg
}

fn as_caller(label: &str, kind: ActorKind) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile: Profile::Developer,
        enforce_profile: kind != ActorKind::Human,
        session_key: None,
        transport: Transport::Http,
    }
}

async fn tool(hub: &TestHub, who: &Caller, name: &str, args: Value) -> Result<Value, UaError> {
    hub.state.registry.call(&hub.state.hub, who, name, args).await
}

async fn approve(hub: &TestHub, id: i64) {
    let human = as_caller("operator", ActorKind::Human);
    tool(hub, &human, "approval_resolve", json!({ "id": id, "decision": "approve" })).await.unwrap();
}

async fn post(hub: &TestHub, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let auth = format!("Bearer {token}");
    let resp = hub.send(post_json(path, &body, &[("authorization", &auth)])).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

async fn publish(hub: &TestHub, bundle: Value) {
    let ops = as_caller("ops-bot", ActorKind::Agent);
    let args = json!({ "bundle": bundle });
    let Err(UaError::ApprovalRequired { approval_id, .. }) =
        tool(hub, &ops, "harness_config_publish", args.clone()).await
    else {
        panic!("publish should park for approval");
    };
    approve(hub, approval_id).await;
    tool(hub, &ops, "harness_config_publish", args).await.unwrap();
}

#[tokio::test]
async fn a_node_pulls_reports_and_applies_its_config_over_http() {
    let hub = TestHub::new(config());
    let (status, _) = post(&hub, "/api/node/register", BUILDER, json!({ "node": "node-a" })).await;
    assert_eq!(status, StatusCode::OK);

    // GET carries the node on the query string.
    let resp = hub.send(get("/api/node/config", None, Some(BUILDER))).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = hub.send(get("/api/node/config?node=node-a", None, Some(BUILDER))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(
        v,
        json!({ "bundle": null, "version": null, "rendered": {}, "apply_grants": [], "proposal_mode": true })
    );

    publish(&hub, json!({ "version": "2026.1", "rules": { "claude": "Run the tests.\n" } })).await;
    let resp = hub.send(get("/api/node/config?node=node-a", None, Some(BUILDER))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let got = json_body(resp).await;
    assert_eq!(got["version"], "2026.1");
    assert_eq!(got["published_by"], "ops-bot");
    assert_eq!(got["config_root_hint"], "~/.unified_agent/harness-config");
    let claude = got["rendered"]["claude"].clone();
    assert_eq!(claude["content"], "Run the tests.\n");
    assert_eq!(claude["path"], "CLAUDE.md");

    // What the Python node sends: {node, action, bundle_version, proposals}.
    let proposal = json!({
        "surface": "claude", "path": "CLAUDE.md", "desired_hash": claude["hash"],
        "observed_hash": null, "diff": "--- a/CLAUDE.md\n+++ b/CLAUDE.md\n",
    });
    let report =
        json!({ "node": "node-a", "action": "report", "bundle_version": "2026.1", "proposals": [proposal] });
    let (status, r) = post(&hub, "/api/node/config", BUILDER, report.clone()).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["ok"], true);
    assert_eq!(r["bundle_version"], "2026.1");
    let p = &r["proposals"][0];
    assert_eq!(p["status"], "pending");
    assert!(p["proposal_id"].as_str().unwrap().starts_with("hc-"), "{p}");
    let approval_id = p["approval_id"].as_i64().unwrap();
    assert_eq!(r["apply_grants"], json!([]));

    // Applying before the approval: 202 in the Python hub's shape.
    let applied =
        json!({ "node": "node-a", "action": "applied", "surface": "claude", "desired_hash": claude["hash"] });
    let (status, v) = post(&hub, "/api/node/config", BUILDER, applied.clone()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{v}");
    assert_eq!(
        v,
        json!({ "status": "approval_pending", "approval_id": approval_id, "code": "approval_required", "tool": "harness_config_apply" })
    );

    approve(&hub, approval_id).await;
    let (status, v) =
        post(&hub, "/api/node/config", BUILDER, json!({ "node": "node-a", "action": "get" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["apply_grants"][0]["surface"], "claude", "{v}");
    assert_eq!(v["apply_grants"][0]["bundle_version"], "2026.1");

    let (status, v) = post(&hub, "/api/node/config", BUILDER, applied.clone()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], true);
    assert_eq!(v["proposal_id"], p["proposal_id"]);
    assert_eq!(v["approval_id"], approval_id);
    // The pass and the proposal are spent.
    let (status, v) = post(&hub, "/api/node/config", BUILDER, applied).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{v}");

    let resp = hub.send(get("/api/harness-config", None, Some(BUILDER))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["active"]["version"], "2026.1");
    assert_eq!(v["recent_proposals"][0]["status"], "applied");
}

#[tokio::test]
async fn bad_reports_and_foreign_nodes_are_refused() {
    let hub = TestHub::new(config());
    post(&hub, "/api/node/register", BUILDER, json!({ "node": "node-a" })).await;

    // No bundle yet: a report has nothing to target.
    let (status, v) = post(
        &hub,
        "/api/node/config",
        BUILDER,
        json!({ "node": "node-a", "action": "report", "proposals": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{v}");

    publish(&hub, json!({ "version": "v1" })).await;
    let (_, got) = post(&hub, "/api/node/config", BUILDER, json!({ "node": "node-a" })).await;
    let hash = got["rendered"]["agents"]["hash"].clone();
    let p = json!({ "surface": "agents", "path": "AGENTS.md", "desired_hash": hash });

    let cases = [
        (json!({ "action": "report", "bundle_version": "v0", "proposals": [p] }), StatusCode::CONFLICT),
        // The version is required, and the path is the hub's, not the node's.
        (json!({ "action": "report", "proposals": [p] }), StatusCode::BAD_REQUEST),
        (
            json!({ "action": "report", "bundle_version": "v1", "proposals": [{ "surface": "agents", "path": "CLAUDE.md", "desired_hash": hash }] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "action": "report", "bundle_version": "v1", "proposals": vec![p.clone(); 33] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "action": "report", "bundle_version": "v1", "proposals": [{ "surface": "agents", "path": "AGENTS.md", "desired_hash": "0".repeat(64) }] }),
            StatusCode::CONFLICT,
        ),
        (
            json!({ "action": "report", "bundle_version": "v1", "proposals": [{ "surface": "agents", "path": "../x", "desired_hash": hash }] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "action": "report", "bundle_version": "v1", "proposals": [{ "surface": "nope", "path": "x", "desired_hash": "0".repeat(64) }] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "action": "applied", "surface": "agents", "desired_hash": "short" }),
            StatusCode::BAD_REQUEST,
        ),
        (json!({ "action": "applied", "surface": "agents", "desired_hash": hash }), StatusCode::NOT_FOUND),
        (json!({ "action": "sync" }), StatusCode::BAD_REQUEST),
        (json!({ "action": "get", "extra": 1 }), StatusCode::BAD_REQUEST),
    ];
    for (mut body, want) in cases {
        body["node"] = json!("node-a");
        let (status, v) = post(&hub, "/api/node/config", BUILDER, body.clone()).await;
        assert_eq!(status, want, "{body}: {v}");
        assert!(v["error"].is_string(), "{v}");
    }

    // Another agent cannot read or report for this node.
    for body in [
        json!({ "node": "node-a" }),
        json!({ "node": "node-a", "action": "report", "bundle_version": "v1", "proposals": [p] }),
    ] {
        let (status, v) = post(&hub, "/api/node/config", OTHER, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(v["code"], "node_owned_elsewhere");
    }
    let resp = hub.send(get("/api/node/config?node=node-a", None, Some(OTHER))).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = hub.send(get("/api/node/config?node=node-a", None, None)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
