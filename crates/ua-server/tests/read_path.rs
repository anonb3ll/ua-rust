//! Read-path write amplification: pages the hub composes from several
//! read-only tool calls write no `tool_calls` rows for a verified human's
//! browser session only; any other caller is recorded (one summary row per
//! `/api/board` view, every call on `/ui`). The activity page verifies the
//! ledger only on demand, and MCP and HTTP tool calls still record one row
//! each.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{TestHub, get, text_body};
use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::{Caller, Config, identity::Transport};

const BUILDER: &str = "builder-test-token-0001";

fn config() -> Config {
    let mut cfg = common::config();
    cfg.agent_tokens = Some(SecretString::from(format!("builder-1:{BUILDER}")));
    cfg
}

/// `(tool, page, count)` of every `tool_calls` row.
fn rows(hub: &TestHub) -> Vec<(String, bool, i64)> {
    hub.state
        .hub
        .db()
        .read(|c| {
            let mut stmt = c.prepare(
                "SELECT tool, page, COUNT(*) FROM tool_calls GROUP BY tool, page ORDER BY tool, page",
            )?;
            Ok(stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?)
        })
        .unwrap()
}

fn total(hub: &TestHub) -> i64 {
    rows(hub).iter().map(|(_, _, n)| n).sum()
}

async fn seed(hub: &TestHub) {
    let local = Caller::local("local", Transport::Cli);
    let s = &hub.state;
    for title in ["Wire the board", "Review the board"] {
        s.registry.call(&s.hub, &local, "task_add", json!({ "title": title })).await.unwrap();
    }
}

const PAGES: [&str; 6] =
    ["/ui/work", "/ui/work?q=board", "/ui/inbox", "/ui/plans", "/ui/memory", "/ui/activity"];

#[tokio::test]
async fn a_human_browser_session_composes_pages_without_tool_calls_rows() {
    let hub = TestHub::new(config());
    seed(&hub).await;
    let cookie = hub.sign_in("operator").await;
    let before = total(&hub);
    // (Not /ui/agents: `session_list` reaps stale sessions, a write, so it is
    // not read-only and its row is kept.)
    for uri in PAGES {
        let resp = hub.send(get(uri, Some(&cookie), None)).await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
    }
    let board = hub.send(get("/api/board?include_cancelled=1", Some(&cookie), None)).await;
    assert_eq!(board.status(), StatusCode::OK);
    assert!(text_body(board).await.contains("Wire the board"));
    assert_eq!(total(&hub), before, "a page view wrote tool_calls rows: {:?}", rows(&hub));
}

/// An agent bearer token reading the board is recorded: one summary row per
/// view (not the six or eight inner reads), visible to the activity, perf
/// and evidence reports.
#[tokio::test]
async fn an_agent_reading_the_board_leaves_one_summary_row_per_view() {
    let hub = TestHub::new(config());
    seed(&hub).await;
    let before = total(&hub);
    for _ in 0..2 {
        let resp = hub.send(get("/api/board", None, Some(BUILDER))).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let after = rows(&hub);
    assert_eq!(total(&hub), before + 2, "{after:?}");
    assert!(after.contains(&("api_board".to_string(), false, 2)), "{after:?}");
    let builder: i64 = hub
        .state
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM tool_calls WHERE caller = 'builder-1' AND tool = 'api_board' AND outcome = 'ok'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(builder, 2);

    // The same agent on a /ui page is recorded call by call, as before.
    let before = total(&hub);
    assert_eq!(hub.send(get("/ui/work", None, Some(BUILDER))).await.status(), StatusCode::OK);
    assert_eq!(total(&hub), before + 6, "{:?}", rows(&hub));
}

/// With a policy file loaded every call reserves its row up front (rate
/// limits must count it), so a page view records its reads even for a
/// human's browser session.
#[tokio::test]
async fn with_a_policy_file_every_page_read_keeps_its_row() {
    let policy = std::env::temp_dir().join(format!("ua-read-path-policy-{}.yaml", std::process::id()));
    std::fs::write(&policy, "version: 1\nrules: []\n").unwrap();
    let mut cfg = config();
    cfg.policy_file = Some(policy);
    let hub = TestHub::new(cfg);
    seed(&hub).await;
    let cookie = hub.sign_in("operator").await;
    let before = total(&hub);
    assert_eq!(hub.send(get("/ui/work", Some(&cookie), None)).await.status(), StatusCode::OK);
    let after = rows(&hub);
    assert_eq!(total(&hub), before + 6, "{after:?}");
    assert!(after.iter().all(|(_, page, _)| !page), "reserved rows are ordinary rows: {after:?}");
}

#[tokio::test]
async fn the_activity_page_verifies_the_chain_only_on_request() {
    let hub = TestHub::new(config());
    seed(&hub).await;
    let cookie = hub.sign_in("operator").await;
    let page = |uri: &'static str| {
        let (hub, cookie) = (&hub, cookie.clone());
        async move { text_body(hub.send(get(uri, Some(&cookie), None)).await).await }
    };
    let html = page("/ui/activity").await;
    assert!(html.contains("Verify the hash chain"), "{html}");
    assert!(!html.contains("Ledger hash chain verified"), "{html}");
    assert!(page("/ui/activity?verify=1").await.contains("Ledger hash chain verified"));
    assert!(
        page("/ui/activity?channel_prefix=agent.task.&verify=1").await.contains("Ledger hash chain verified")
    );
    let html = page("/ui/activity?channel_prefix=agent.task.").await;
    assert!(
        html.contains("name=\"channel_prefix\" value=\"agent.task.\""),
        "the verify form keeps the filter"
    );
}

#[tokio::test]
async fn tool_calls_from_clients_still_record_one_row_each() {
    let hub = TestHub::new(config());
    seed(&hub).await;
    let before = total(&hub);
    let req = Request::post("/api/tools/task_list")
        .header(header::AUTHORIZATION, format!("Bearer {BUILDER}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "status": "open" }).to_string()))
        .unwrap();
    let resp = hub.send(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let _: Value = serde_json::from_str(&text_body(resp).await).unwrap();
    assert_eq!(total(&hub), before + 1);
    let local = Caller::local("local", Transport::Mcp);
    let s = &hub.state;
    s.registry.call(&s.hub, &local, "dependency_list", json!({})).await.unwrap();
    assert_eq!(total(&hub), before + 2);
}

/// An MCP `tools/call` runs as its own tracked task (so a shutdown can wait
/// for it) and records one row, as before.
#[cfg(feature = "mcp-server")]
#[tokio::test]
async fn an_mcp_tool_call_is_tracked_and_recorded() {
    let hub = TestHub::new(config());
    seed(&hub).await;
    let before = total(&hub);
    let call = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "task_list", "arguments": { "status": "open" },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    let auth = format!("Bearer {BUILDER}");
    let resp = hub
        .send(common::post_json(
            "/mcp",
            &call,
            &[
                ("authorization", &auth),
                ("accept", "application/json, text/event-stream"),
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", "task_list"),
                ("host", "localhost"),
            ],
        ))
        .await;
    let status = resp.status();
    let body = text_body(resp).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Wire the board"), "{body}");
    assert_eq!(total(&hub), before + 1, "{:?}", rows(&hub));
    assert!(hub.state.calls.is_empty(), "the tracked call finished");
}
