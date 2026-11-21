//! Which adapter an approval decision came through is kept on the approval
//! row (`resolved_transport`) and in the `agent.approval.resolved` ledger
//! event, so an approval made from chat is told apart from one made in the
//! Control Center. Evidence only: who may approve does not change.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_store::ledger::{self, EventQuery};
use ua_tools::{Hub, Registry, approvals, builtin_registry};

fn hub() -> Hub {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into()];
    cfg.approval_tools = vec!["task_add".into()];
    Hub::in_memory(cfg).unwrap()
}

fn agent() -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: None,
        org_id: ua_core::DEFAULT_ORG.into(),
        transport: Transport::Mcp,
    }
}

fn human(transport: Transport) -> Caller {
    Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Coordinator,
        enforce_profile: true,
        session_key: None,
        org_id: ua_core::DEFAULT_ORG.into(),
        transport,
    }
}

async fn pending(reg: &Registry, hub: &Hub, title: &str) -> i64 {
    match reg.call(hub, &agent(), "task_add", json!({ "title": title })).await {
        Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
        other => panic!("expected approval_required, got {other:?}"),
    }
}

async fn resolved_events(hub: &Hub) -> Vec<Value> {
    hub.db()
        .read_async(|c| {
            ledger::query(
                c,
                &EventQuery { channels: Some(vec!["agent.approval.resolved".into()]), ..Default::default() },
            )
        })
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.payload)
        .collect()
}

#[tokio::test]
async fn the_decision_records_the_transport_it_came_through() {
    let (reg, hub) = (builtin_registry(), hub());
    let from_slack = pending(&reg, &hub, "approved from chat").await;
    let from_ui = pending(&reg, &hub, "approved in the control center").await;
    let denied_over_http = pending(&reg, &hub, "denied over the API").await;
    for (id, transport, decision) in [
        (from_slack, Transport::Slack, "approve"),
        (from_ui, Transport::Ui, "approve"),
        (denied_over_http, Transport::Http, "deny"),
    ] {
        reg.call(&hub, &human(transport), "approval_resolve", json!({ "id": id, "decision": decision }))
            .await
            .unwrap();
    }
    let row = |id: i64| hub.db().read(|c| approvals::get(c, id)).unwrap();
    assert_eq!(row(from_slack).resolved_transport.as_deref(), Some("slack"));
    assert_eq!(row(from_ui).resolved_transport.as_deref(), Some("ui"));
    assert_eq!(row(denied_over_http).resolved_transport.as_deref(), Some("http"));
    // Who resolved it is unchanged.
    assert_eq!(row(from_slack).resolved_by.as_deref(), Some("operator"));

    let events = resolved_events(&hub).await;
    let by_id = |id: i64| events.iter().find(|e| e["approval_id"] == id).unwrap().clone();
    assert_eq!(by_id(from_slack)["transport"], "slack");
    assert_eq!(by_id(from_ui)["transport"], "ui");
    assert_eq!(by_id(denied_over_http)["transport"], "http");
    assert_eq!(by_id(from_slack)["resolved_by"], "operator");

    // The list outputs carry it too.
    let listed = reg.call(&hub, &human(Transport::Http), "approval_pending", json!({})).await.unwrap();
    let live = listed["approved_unconsumed"].as_array().unwrap();
    let slack_row = live.iter().find(|a| a["id"] == from_slack).unwrap();
    assert_eq!(slack_row["resolved_transport"], "slack");
    // A still-pending row has none.
    let fresh = pending(&reg, &hub, "not yet resolved").await;
    let listed = reg.call(&hub, &human(Transport::Http), "approval_pending", json!({})).await.unwrap();
    let p = listed["pending"].as_array().unwrap().iter().find(|a| a["id"] == fresh).unwrap().clone();
    assert!(p["resolved_transport"].is_null(), "{p}");
    // The ledger chain still verifies with the larger payload.
    let verified = reg.call(&hub, &human(Transport::Http), "event_log_verify", json!({})).await.unwrap();
    assert_eq!(verified["ok"], true, "{verified}");
}

#[tokio::test]
async fn gate_behaviour_is_unchanged_by_the_transport() {
    let (reg, hub) = (builtin_registry(), hub());
    let id = pending(&reg, &hub, "still needs a human").await;
    // An agent still cannot approve, from any transport.
    let mut a = agent();
    a.transport = Transport::Slack;
    a.profile = Profile::Coordinator;
    let err =
        reg.call(&hub, &a, "approval_resolve", json!({ "id": id, "decision": "approve" })).await.unwrap_err();
    assert_eq!(err.reason_code(), Some("not_human"));
    assert!(hub.db().read(|c| approvals::get(c, id)).unwrap().resolved_transport.is_none());
}

/// A database from before `approvals.v2`: the column is added, old rows read
/// as NULL (rendered as unknown), and new decisions fill it.
#[test]
fn an_older_database_gains_the_column_and_old_rows_read_as_unknown() {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    let all = ua_tools::schema_parts();
    let before: Vec<_> = all.iter().copied().filter(|p| p.name != "approvals.v2").collect();
    ua_store::schema::apply(&mut conn, &before).unwrap();
    conn.execute(
        "INSERT INTO approvals (tool, payload, requested_by, status, resolved_by, created_at, updated_at, resolved_at) \
         VALUES ('task_add', '{}', 'builder-1', 'approved', 'operator', '2026-01-01T00:00:00Z', \
         '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    let id = conn.last_insert_rowid();
    let applied = ua_store::schema::apply(&mut conn, &all).unwrap();
    assert_eq!(applied, ["approvals.v2"]);
    let row = approvals::get(&conn, id).unwrap();
    assert_eq!(row.resolved_by.as_deref(), Some("operator"));
    assert!(row.resolved_transport.is_none());
    let v = serde_json::to_value(&row).unwrap();
    assert!(v["resolved_transport"].is_null(), "{v}");
}
