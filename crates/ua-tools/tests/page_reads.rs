//! `registry::page_reads` and `registry::page_view`: which calls inside a
//! page composition leave no `tool_calls` row, which are always recorded,
//! and how recorded page rows stay out of rate calculations.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::registry::{page_reads, page_view};
use ua_tools::{Hub, Registry, builtin_registry};

fn hub_with(f: impl FnOnce(&mut Config)) -> Hub {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into()];
    f(&mut cfg);
    Hub::in_memory(cfg).unwrap()
}

fn human() -> Caller {
    Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        session_key: None,
        transport: Transport::Ui,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn agent(label: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

/// `(tool, page, outcome)` of every row, in order.
fn rows(hub: &Hub) -> Vec<(String, bool, String)> {
    hub.db()
        .read(|c| {
            let mut stmt = c.prepare("SELECT tool, page, outcome FROM tool_calls ORDER BY id")?;
            Ok(stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?)
        })
        .unwrap()
}

async fn decisions(reg: &Registry, hub: &Hub) -> u64 {
    let v = reg
        .call(hub, &human(), "event_log_query", json!({ "channels": ["agent.gateway.decision"] }))
        .await
        .unwrap();
    v["count"].as_u64().unwrap()
}

async fn anomalies(reg: &Registry, hub: &Hub) -> Vec<Value> {
    let v = reg.call(hub, &human(), "observability_manage", json!({ "action": "anomalies" })).await.unwrap();
    v["anomalies"].as_array().unwrap().iter().filter(|a| a["rule"] == "tool_error_rate").cloned().collect()
}

#[tokio::test]
async fn successful_skip_eligible_reads_leave_no_row_and_failures_are_page_rows() {
    let (hub, reg) = (hub_with(|_| {}), builtin_registry());
    page_reads(async {
        reg.call(&hub, &human(), "task_list", json!({})).await.unwrap();
        assert!(reg.call(&hub, &human(), "plan_get", json!({ "plan_id": "missing" })).await.is_err());
        // A write in the scope records as usual.
        reg.call(&hub, &human(), "task_add", json!({ "title": "From a page" })).await.unwrap();
    })
    .await;
    let r = rows(&hub);
    assert_eq!(r.len(), 2, "{r:?}");
    assert_eq!((r[0].0.as_str(), r[0].1), ("plan_get", true));
    assert_eq!((r[1].0.as_str(), r[1].1, r[1].2.as_str()), ("task_add", false, "ok"));
}

/// M2: thirty failed page reads with their successes unrecorded must not
/// look like a failing tool. The same failures outside a page do.
#[tokio::test]
async fn failed_page_reads_do_not_raise_a_false_error_rate_anomaly() {
    let (hub, reg) = (hub_with(|_| {}), builtin_registry());
    page_reads(async {
        for _ in 0..30 {
            assert!(reg.call(&hub, &human(), "plan_get", json!({ "plan_id": "missing" })).await.is_err());
        }
    })
    .await;
    assert_eq!(rows(&hub).iter().filter(|(t, page, _)| t == "plan_get" && *page).count(), 30);
    assert!(anomalies(&reg, &hub).await.is_empty(), "{:?}", anomalies(&reg, &hub).await);
    let m = reg.call(&hub, &human(), "observability_manage", json!({ "action": "metrics" })).await.unwrap();
    assert!(!m.to_string().contains("\"errors\":30"), "{m}");

    // Control: the same failures from a client are an anomaly.
    let (hub2, reg2) = (hub_with(|_| {}), builtin_registry());
    for _ in 0..30 {
        assert!(reg2.call(&hub2, &human(), "plan_get", json!({ "plan_id": "missing" })).await.is_err());
    }
    assert_eq!(anomalies(&reg2, &hub2).await.len(), 1);
}

/// L1: a read-only tool behind the approval gate is always recorded, even
/// inside a page.
#[tokio::test]
async fn a_gated_read_only_call_in_a_page_is_recorded() {
    let hub = hub_with(|c| c.approval_tools = vec!["task_list".into()]);
    let reg = builtin_registry();
    let lead = agent("reviewer-1", Profile::Lead);
    let id = match reg.call(&hub, &lead, "task_list", json!({})).await.unwrap_err() {
        UaError::ApprovalRequired { approval_id, .. } => approval_id,
        other => panic!("{other:?}"),
    };
    reg.call(&hub, &human(), "approval_resolve", json!({ "id": id, "decision": "approve" })).await.unwrap();
    let before = rows(&hub).len();
    page_reads(async { reg.call(&hub, &lead, "task_list", json!({})).await.unwrap() }).await;
    let r = rows(&hub);
    assert_eq!(r.len(), before + 1, "{r:?}");
    assert_eq!(r.last().unwrap(), &("task_list".to_string(), false, "ok".to_string()));
}

/// L2: a read-only tool with a side effect for these arguments is recorded
/// in a page; the same tool without it is not.
#[tokio::test]
async fn side_effecting_reads_in_a_page_are_recorded() {
    let (hub, reg) = (hub_with(|_| {}), builtin_registry());
    let b1 = agent("builder-1", Profile::Developer);
    let id = reg.call(&hub, &b1, "memory_save", json!({ "content": "Keep the cache warm." })).await.unwrap()
        ["id"]
        .as_str()
        .unwrap()
        .to_string();
    let session =
        reg.call(&hub, &b1, "session_start", json!({ "kind": "executor" })).await.unwrap()["session_id"]
            .as_str()
            .unwrap()
            .to_string();
    let before = rows(&hub).len();
    page_reads(async {
        reg.call(&hub, &b1, "memory_search", json!({ "query": "cache" })).await.unwrap();
        reg.call(&hub, &b1, "memory_get", json!({ "id": id })).await.unwrap();
        reg.call(&hub, &b1, "message_list", json!({ "session_id": session })).await.unwrap();
        // No side effect for these: no row.
        reg.call(&hub, &b1, "memory_get", json!({ "id": id, "count_access": false })).await.unwrap();
        reg.call(&hub, &b1, "message_list", json!({})).await.unwrap();
    })
    .await;
    let tools: Vec<String> = rows(&hub)[before..].iter().map(|r| r.0.clone()).collect();
    assert_eq!(tools, ["memory_search", "memory_get", "message_list"]);
}

/// A profile refusal inside a page is still a ledgered gateway decision.
#[tokio::test]
async fn a_refusal_inside_a_page_is_still_ledgered() {
    let (hub, reg) = (hub_with(|_| {}), builtin_registry());
    let public = agent("viewer-1", Profile::Public);
    let before = decisions(&reg, &hub).await;
    let e = page_reads(reg.call(&hub, &public, "event_log_query", json!({}))).await.unwrap_err();
    assert_eq!(e.code(), "denied");
    assert_eq!(decisions(&reg, &hub).await, before + 1);
}

/// `page_view` writes one row for the view, carrying the first inner
/// failure's code; inner successes leave none.
#[tokio::test]
async fn a_page_view_writes_one_summary_row() {
    let (hub, reg) = (hub_with(|_| {}), builtin_registry());
    let b1 = agent("builder-1", Profile::Developer);
    page_view(&hub, &b1, "api_board", async {
        for _ in 0..5 {
            reg.call(&hub, &b1, "task_list", json!({})).await.unwrap();
        }
    })
    .await;
    assert_eq!(rows(&hub), [("api_board".to_string(), false, "ok".to_string())]);
    page_view(&hub, &b1, "api_board", async {
        reg.call(&hub, &b1, "task_list", json!({})).await.unwrap();
        let _ = reg.call(&hub, &b1, "plan_get", json!({ "plan_id": "missing" })).await;
    })
    .await;
    let r = rows(&hub);
    assert_eq!(r.len(), 3, "{r:?}");
    assert_eq!((r[1].0.as_str(), r[1].1), ("plan_get", true));
    assert_eq!((r[2].0.as_str(), r[2].1, r[2].2.as_str()), ("api_board", false, "not_found"));
}
