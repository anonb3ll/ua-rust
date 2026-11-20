//! Read-path write amplification: pages the hub composes from several
//! read-only tool calls (`/ui/*`, `GET /api/board`) write no `tool_calls`
//! rows, the activity page verifies the ledger only on demand, and MCP and
//! HTTP tool calls still record one row each.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use ua_core::{Caller, Config, identity::Transport};
use ua_server::AppState;
use ua_tools::{Hub, builtin_registry};

const OPERATOR: &str = "operator-test-token-0001";

fn app() -> (Router, AppState) {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.enforce_auth = true;
    cfg.agent_tokens = Some(SecretString::from(format!("operator:{OPERATOR}")));
    cfg.human_identities = vec!["operator".into()];
    cfg.profiles.insert("operator".into(), "operator".into());
    let state = AppState::new(Hub::in_memory(cfg).unwrap(), Arc::new(builtin_registry()));
    (ua_server::router(state.clone(), CancellationToken::new()), state)
}

async fn send(app: &Router, req: Request<Body>) -> Response<Body> {
    app.clone().oneshot(req).await.unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).header(header::AUTHORIZATION, format!("Bearer {OPERATOR}")).body(Body::empty()).unwrap()
}

async fn body_text(resp: Response<Body>) -> String {
    String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

/// `tool_calls` rows per tool.
fn rows(state: &AppState) -> Vec<(String, i64)> {
    state
        .hub
        .db()
        .read(|c| {
            let mut stmt = c.prepare("SELECT tool, COUNT(*) FROM tool_calls GROUP BY tool ORDER BY tool")?;
            Ok(stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
        })
        .unwrap()
}

fn total(state: &AppState) -> i64 {
    rows(state).iter().map(|(_, n)| n).sum()
}

async fn seed(state: &AppState) {
    let local = Caller::local("local", Transport::Cli);
    for (title, status) in [("Wire the board", "open"), ("Review the board", "doing")] {
        let t = state.registry.call(&state.hub, &local, "task_add", json!({ "title": title })).await.unwrap();
        if status != "open" {
            let id = t["task"]["id"].as_i64().or_else(|| t["id"].as_i64()).unwrap();
            state
                .registry
                .call(&state.hub, &local, "task_update", json!({ "id": id, "status": status }))
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn composed_read_pages_write_no_tool_calls_rows() {
    let (app, state) = app();
    seed(&state).await;
    let before = total(&state);

    // (Not /ui/agents: `session_list` reaps stale sessions, a write, so it is
    // not read-only and its row is kept.)
    for uri in ["/ui/work", "/ui/work?q=board", "/ui/inbox", "/ui/plans", "/ui/memory", "/ui/activity"] {
        let resp = send(&app, get(uri)).await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
    }
    let board = send(&app, get("/api/board?include_cancelled=1")).await;
    assert_eq!(board.status(), StatusCode::OK);
    let v: Value = serde_json::from_str(&body_text(board).await).unwrap();
    assert!(v.to_string().contains("Wire the board"), "{v}");

    assert_eq!(total(&state), before, "a page view wrote tool_calls rows: {:?}", rows(&state));
}

#[tokio::test]
async fn the_activity_page_verifies_the_chain_only_on_request() {
    let (app, state) = app();
    seed(&state).await;
    let html = body_text(send(&app, get("/ui/activity")).await).await;
    assert!(html.contains("Verify the hash chain"), "{html}");
    assert!(!html.contains("Ledger hash chain verified"), "{html}");

    let html = body_text(send(&app, get("/ui/activity?verify=1")).await).await;
    assert!(html.contains("Ledger hash chain verified"), "{html}");
    let html = body_text(send(&app, get("/ui/activity?channel_prefix=agent.task.&verify=1")).await).await;
    assert!(html.contains("Ledger hash chain verified"), "{html}");
    let html = body_text(send(&app, get("/ui/activity?channel_prefix=agent.task.")).await).await;
    assert!(
        html.contains("name=\"channel_prefix\" value=\"agent.task.\""),
        "the verify form keeps the filter"
    );
}

#[tokio::test]
async fn tool_calls_from_clients_still_record_one_row_each() {
    let (app, state) = app();
    seed(&state).await;
    let before = total(&state);

    // HTTP tool call.
    let req = Request::post("/api/tools/task_list")
        .header(header::AUTHORIZATION, format!("Bearer {OPERATOR}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "status": "open" }).to_string()))
        .unwrap();
    assert_eq!(send(&app, req).await.status(), StatusCode::OK);
    assert_eq!(total(&state), before + 1);

    // A registry call outside a page scope (the MCP adapter's path).
    let local = Caller::local("local", Transport::Mcp);
    state.registry.call(&state.hub, &local, "dependency_list", json!({})).await.unwrap();
    assert_eq!(total(&state), before + 2);

    // Inside a page scope, a call that changes state and a read that fails
    // are still recorded; only a successful read-only call is not.
    let reg = state.registry.clone();
    let hub = state.hub.clone();
    ua_tools::registry::page_reads(async {
        reg.call(&hub, &local, "task_list", json!({})).await.unwrap();
        reg.call(&hub, &local, "task_add", json!({ "title": "Written from a page" })).await.unwrap();
        assert!(reg.call(&hub, &local, "plan_get", json!({ "plan_id": "missing" })).await.is_err());
    })
    .await;
    let by_tool = rows(&state);
    assert_eq!(total(&state), before + 4, "{by_tool:?}");
    assert!(by_tool.iter().any(|(t, _)| t == "plan_get"), "{by_tool:?}");
}
