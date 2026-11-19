//! Evidence reports and state consistency checks.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

fn hub() -> Hub {
    Hub::in_memory(Config::for_home(std::env::temp_dir())).unwrap()
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some(format!("{label}-key")),
        transport: Transport::Mcp,
    }
}

async fn call(reg: &Registry, hub: &Hub, who: &Caller, tool: &str, args: Value) -> Value {
    reg.call(hub, who, tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
}

fn exec(hub: &Hub, sql: &str) {
    let sql = sql.to_string();
    hub.db()
        .write(move |tx| {
            tx.execute_batch(&sql)?;
            Ok(())
        })
        .unwrap();
}

fn synthetic_calls(hub: &Hub, caller: &str, n: usize, failed: usize) {
    let caller = caller.to_string();
    hub.db()
        .write(move |tx| {
            for i in 0..n {
                tx.execute(
                    "INSERT INTO tool_calls (tool, caller, profile, transport, started_at, duration_ms, outcome) \
                     VALUES ('synthetic_build', ?1, 'developer', 'mcp', ?2, 10, ?3)",
                    rusqlite::params![caller, ua_core::time::now(), if i < failed { "internal" } else { "ok" }],
                )?;
            }
            Ok(())
        })
        .unwrap();
}

/// A task taken from creation to done with evidence.
async fn finished_task(reg: &Registry, hub: &Hub, who: &Caller) -> i64 {
    let id =
        call(reg, hub, who, "task_add", json!({ "title": "ship the widget" })).await["id"].as_i64().unwrap();
    call(reg, hub, who, "task_claim", json!({ "id": id, "agent": who.label })).await;
    synthetic_calls(hub, &who.label, 4, 1);
    call(
        reg,
        hub,
        who,
        "task_update",
        json!({
            "id": id,
            "status": "done",
            "evidence_ref": "https://github.com/example/widgets/pull/7 merged as abc1234def",
        }),
    )
    .await;
    id
}

#[tokio::test]
async fn report_for_a_finished_task() {
    let hub = hub();
    let reg = builtin_registry();
    let who = agent("builder-1");
    let id = finished_task(&reg, &hub, &who).await;
    // An unrelated task must not appear.
    call(&reg, &hub, &who, "task_add", json!({ "title": "other" })).await;

    let report = call(&reg, &hub, &who, "evidence_report", json!({ "task_id": id })).await;
    assert_eq!(report["report_type"], "user_attributable_evidence");
    assert_eq!(report["total_records"], 1);
    assert_eq!(report["chain_integrity"]["status"], "valid");
    assert_eq!(report["chain_integrity"]["verified"], true);
    assert!(report["chain_integrity"]["head_hash"].is_string());
    assert_eq!(report["clean_pass"], true);
    assert_eq!(report["gate_failures"], json!([]));

    let rec = &report["records"][0];
    assert_eq!(rec["task_id"], id);
    assert_eq!(rec["agent"], "builder-1");
    assert_eq!(rec["action"]["status"], "done");
    let channels: Vec<&str> =
        rec["events"].as_array().unwrap().iter().map(|e| e["channel"].as_str().unwrap()).collect();
    for ch in ["agent.task.created", "agent.task.claimed", "agent.task.updated", "agent.task.completed"] {
        assert!(channels.contains(&ch), "{ch} missing from {channels:?}");
    }
    let proof = &rec["proof"];
    assert_eq!(proof["pr_url"], "https://github.com/example/widgets/pull/7");
    assert_eq!(proof["commit_sha"], "abc1234def");
    assert_eq!(proof["merge_verified"], false);
    assert_eq!(proof["tamper_evident"], true);
    assert_eq!(proof["event_hashes"].as_array().unwrap().len(), channels.len());
    // Synthetic calls plus the real task_claim / task_update calls by the claimant.
    let calls = &rec["tool_calls"];
    assert_eq!(calls["attribution"], "caller_and_window");
    assert_eq!(calls["by_tool"]["synthetic_build"]["calls"], 4);
    assert_eq!(calls["by_tool"]["synthetic_build"]["errors"], 1);
    assert!(calls["total"].as_i64().unwrap() >= 5);

    // Filters: agent and pr match, a foreign agent and PR do not.
    let by_agent =
        call(&reg, &hub, &who, "evidence_report", json!({ "agent": "builder-1", "pr": "pull/7" })).await;
    assert_eq!(by_agent["total_records"], 1);
    let none = call(&reg, &hub, &who, "evidence_report", json!({ "agent": "builder-2" })).await;
    assert_eq!(none["total_records"], 0);
    let windowed = call(&reg, &hub, &who, "evidence_report", json!({ "until": "2000-01-01" })).await;
    assert_eq!(windowed["total_records"], 0);
    let limited = call(&reg, &hub, &who, "evidence_report", json!({ "limit": 1 })).await;
    assert_eq!(limited["total_records"], 1);
    assert_eq!(limited["truncated"], true);

    // Items name node dispatches, which this build does not have.
    let item = call(&reg, &hub, &who, "evidence_report", json!({ "item": "nd-0123456789abcdef" })).await;
    assert_eq!(item["total_records"], 0);
    let bad = reg.call(&hub, &who, "evidence_report", json!({ "item": "bogus" })).await.unwrap_err();
    assert_eq!(bad.code(), "invalid_argument");
}

#[tokio::test]
async fn project_chain_and_tampered_ledger() {
    let hub = hub();
    let reg = builtin_registry();
    let who = agent("builder-1");
    let plain =
        call(&reg, &hub, &who, "task_add", json!({ "title": "no marker" })).await["id"].as_i64().unwrap();
    let err = reg.call(&hub, &who, "evidence_report", json!({ "project_id": plain })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = reg.call(&hub, &who, "evidence_report", json!({ "project_id": 9999 })).await.unwrap_err();
    assert_eq!(err.code(), "not_found");

    let root =
        call(&reg, &hub, &who, "task_add", json!({ "title": "project", "notes": "[project-spec] build it" }))
            .await["id"]
            .as_i64()
            .unwrap();
    let child = call(&reg, &hub, &who, "task_add", json!({ "title": "step", "parent_id": root })).await["id"]
        .as_i64()
        .unwrap();
    call(
        &reg,
        &hub,
        &who,
        "task_update",
        json!({ "id": child, "status": "done", "evidence_ref": "deadbeef1" }),
    )
    .await;
    let report = call(&reg, &hub, &who, "evidence_report", json!({ "project_id": root })).await;
    let chain = &report["project_chain"];
    assert_eq!(chain["project_id"], root);
    assert_eq!(chain["task_ids"], json!([root, child]));
    assert_eq!(chain["done_task_ids"], json!([child]));
    assert_eq!(chain["status"], "partial");
    assert_eq!(chain["evidence"][0]["commit_sha"], "deadbeef1");

    exec(&hub, "DROP TRIGGER event_log_no_update; UPDATE event_log SET payload = '{}' WHERE seq = 1;");
    let report = call(&reg, &hub, &who, "evidence_report", json!({ "task_id": child })).await;
    assert_eq!(report["chain_integrity"]["status"], "tampered");
    assert_eq!(report["chain_integrity"]["first_bad_seq"], 1);
    assert_eq!(report["clean_pass"], false);
    assert_eq!(report["gate_failures"], json!(["evidence_chain_integrity"]));
    assert_eq!(report["records"][0]["proof"]["tamper_evident"], false);
}

#[tokio::test]
async fn state_sync_verify_detects_and_repairs_drift() {
    let hub = hub();
    let reg = builtin_registry();
    let who = agent("builder-1");
    call(&reg, &hub, &who, "task_add", json!({ "title": "indexed" })).await;
    call(&reg, &hub, &who, "memory_save", json!({ "content": "remember this", "title": "r" })).await;

    let clean = call(&reg, &hub, &who, "state_sync_verify", json!({})).await;
    assert_eq!(clean["in_sync"], true, "{clean}");
    assert_eq!(clean["resynced"], false);
    assert_eq!(clean["task_db_count"], 1);
    assert_eq!(clean["memory_db_count"], 1);
    let indexes: Vec<&str> =
        clean["checks"]["fts"].as_array().unwrap().iter().map(|f| f["index"].as_str().unwrap()).collect();
    assert!(indexes.contains(&"task_fts") && indexes.contains(&"memory_fts"), "{indexes:?}");

    // A row written behind the index's back, and a dangling supersession.
    let now = ua_core::time::now();
    exec(
        &hub,
        &format!(
            "DROP TRIGGER task_fts_ai;
             INSERT INTO tasks (title, created_at, updated_at) VALUES ('unindexed', '{now}', '{now}');
             INSERT INTO memory (id, content, created_at, updated_at, superseded_by)
                 VALUES ('orphan-note', 'x', '{now}', '{now}', 'no-such-note');"
        ),
    );
    let drift = call(&reg, &hub, &who, "state_sync_verify", json!({})).await;
    assert_eq!(drift["in_sync"], false);
    assert_eq!(drift["resynced"], true);
    assert_eq!(drift["drift_details"]["fts_drift"], json!(["task_fts"]));
    assert_eq!(drift["checks"]["dangling_references"]["by_reference"]["memory.superseded_by->memory"], 1);
    let task_fts =
        drift["checks"]["fts"].as_array().unwrap().iter().find(|f| f["index"] == "task_fts").unwrap();
    assert_eq!(task_fts["missing_from_index"], 1);

    // The index was rebuilt; only the dangling reference remains.
    let after = call(&reg, &hub, &who, "state_sync_verify", json!({})).await;
    assert_eq!(after["drift_details"]["fts_drift"], json!([]));
    assert_eq!(after["resynced"], false);
    assert_eq!(after["drift_details"]["dangling_references"], 1);
    let hits = call(&reg, &hub, &who, "task_list", json!({ "status": "all", "query": "unindexed" })).await;
    assert!(hits.to_string().contains("unindexed"), "{hits}");
}
