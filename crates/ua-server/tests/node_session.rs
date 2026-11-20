//! Node session credentials and device acceptance over HTTP: the mint
//! route, where a `uas_` bearer is accepted and what it may call, and the
//! acceptance listing.

mod common;

use axum::http::{StatusCode, header};
use common::{TestHub, get, json_body, post_json};
use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};

const BUILDER: &str = "builder-1-test-token-0001";
const OTHER: &str = "builder-2-test-token-0002";

fn config(enabled: bool) -> Config {
    let mut cfg = common::config();
    cfg.oauth_enabled = false;
    cfg.session_credentials_enabled = enabled;
    cfg.agent_tokens = Some(SecretString::from(format!("builder-1:{BUILDER},builder-2:{OTHER}")));
    cfg
}

fn human() -> Caller {
    Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        session_key: None,
        transport: Transport::Http,
    }
}

async fn post(hub: &TestHub, path: &str, token: &str, body: Value) -> (StatusCode, Value, Option<String>) {
    let auth = format!("Bearer {token}");
    let resp = hub.send(post_json(path, &body, &[("authorization", &auth)])).await;
    let status = resp.status();
    let cache = resp.headers().get(header::CACHE_CONTROL).and_then(|v| v.to_str().ok()).map(str::to_string);
    (status, json_body(resp).await, cache)
}

/// A registered node running one claimed `acp:claude` item; returns its id.
async fn running_item(hub: &TestHub) -> String {
    let facts = json!({
        "backends": ["acp:claude"],
        "worktree_roots": [{ "path": "/srv/work", "realpath": "/srv/work" }],
        "node_features": ["acp_session_mcp", "session_settings"],
    });
    let (status, v, _) =
        post(hub, "/api/node/register", BUILDER, json!({ "node": "node-a", "facts": facts })).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["hub_features"].as_array().unwrap().contains(&json!("acp_session_mcp")), "{v}");
    let ask =
        json!({ "node": "node-a", "backend": "acp:claude", "prompt": "review", "cwd": "/srv/work/repo" });
    let (status, v, _) = post(hub, "/api/node/dispatch", OTHER, ask.clone()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{v}");
    hub.state
        .registry
        .call(
            &hub.state.hub,
            &human(),
            "approval_resolve",
            json!({ "id": v["approval_id"], "decision": "approve" }),
        )
        .await
        .unwrap();
    let (status, v, _) = post(hub, "/api/node/dispatch", OTHER, ask).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let id = v["item_id"].as_str().unwrap().to_string();
    let (status, v, _) = post(hub, "/api/node/claim", BUILDER, json!({ "node": "node-a" })).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["item"]["item_id"], id.as_str());
    id
}

#[tokio::test]
async fn a_minted_credential_reaches_only_its_paths_and_tools() {
    let hub = TestHub::new(config(true));
    let item = running_item(&hub).await;

    let mint = json!({ "node": "node-a", "item_id": item, "attempt": 1 });
    let (status, v, cache) = post(&hub, "/api/node/session_credential", BUILDER, mint.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    let cred = v["credential"].as_str().unwrap().to_string();
    assert!(cred.starts_with("uas_"));

    // Another agent cannot mint for this node; the refusal names a reason.
    let (status, v, _) = post(&hub, "/api/node/session_credential", OTHER, mint.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["reason"], "node_binding");

    // It runs as the item's agent under the acp-session profile.
    let resp = hub.send(get("/api/whoami", None, Some(&cred))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let me = json_body(resp).await;
    assert_eq!(me["identity"], "builder-1");
    assert_eq!(me["profile"], "acp-session");
    assert_eq!(me["session_credential"]["item_id"], item.as_str());

    let listed = json_body(hub.send(get("/api/tools", None, Some(&cred))).await).await;
    let names: Vec<&str> =
        listed["tools"].as_array().unwrap().iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(names.contains(&"task_list") && !names.contains(&"task_add"), "{names:?}");
    assert_eq!(listed["count"], me["session_credential"]["tools"].as_array().unwrap().len());

    let (status, v, _) = post(&hub, "/api/tools/task_list", &cred, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, v, _) = post(&hub, "/api/tools/task_add", &cred, json!({ "title": "x" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["reason_code"], "profile_denied");

    // Any other path is refused, even one the agent's own token reaches.
    let resp = hub.send(get("/api/nodes", None, Some(&cred))).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(resp).await["reason_code"], "session_credential_path");
    let (status, _, _) = post(&hub, "/api/node/heartbeat", &cred, json!({ "node": "node-a" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // MCP accepts it.
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } }
    });
    let auth = format!("Bearer {cred}");
    let headers = [
        ("authorization", auth.as_str()),
        ("accept", "application/json, text/event-stream"),
        ("host", "localhost"),
    ];
    let resp = hub.send(post_json("/mcp", &init, &headers)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // The receipt ends it, on every path.
    let receipt =
        json!({ "node": "node-a", "item_id": item, "receipt": { "status": "finished", "attempt": 1 } });
    let (status, v, _) = post(&hub, "/api/node/receipt", BUILDER, receipt).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let resp = hub.send(get("/api/whoami", None, Some(&cred))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = hub.send(post_json("/mcp", &init, &headers)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let (status, v, _) = post(&hub, "/api/node/session_credential", BUILDER, mint).await;
    assert_eq!(status, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["reason"], "item_not_claimed");
}

#[tokio::test]
async fn a_hub_with_session_credentials_off_refuses_the_mint() {
    let hub = TestHub::new(config(false));
    let item = running_item(&hub).await;
    let (status, v, cache) = post(
        &hub,
        "/api/node/session_credential",
        BUILDER,
        json!({ "node": "node-a", "item_id": item, "attempt": 1 }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["reason"], "disabled");
    assert_eq!(cache.as_deref(), Some("no-store"));
    // A uas_ value is never tried as another kind of token.
    let fake = format!("uas_{}", "A".repeat(43));
    assert_eq!(hub.send(get("/api/whoami", None, Some(&fake))).await.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_acceptance_listing_reads_every_node_or_one() {
    let hub = TestHub::new(config(false));
    let (status, _, _) = post(&hub, "/api/node/register", BUILDER, json!({ "node": "node-a" })).await;
    assert_eq!(status, StatusCode::OK);
    let resp = hub.send(get("/api/nodes/acceptance", None, Some(OTHER))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v, json!({ "nodes": {}, "required": false }));
    let resp = hub.send(get("/api/nodes/acceptance?node=node-a", None, Some(OTHER))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["state"], "not_run");
    let resp = hub.send(get("/api/nodes/acceptance?node=bad%20name", None, Some(OTHER))).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
