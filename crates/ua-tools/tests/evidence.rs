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
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

async fn call(reg: &Registry, hub: &Hub, who: &Caller, tool: &str, args: Value) -> Value {
    reg.call(hub, who, tool, args).await.unwrap_or_else(|e| panic!("{tool} failed: {e}"))
}

async fn manage(reg: &Registry, hub: &Hub, who: &Caller, action: &str, params: Value) -> Value {
    call(reg, hub, who, "coordination_manage", json!({ "action": action, "params": params })).await
}

async fn handoff_channels(reg: &Registry, hub: &Hub, who: &Caller) -> Vec<String> {
    let channels = json!(["agent.lifecycle.handoff", "agent.conversation.handoff"]);
    let rows = call(reg, hub, who, "event_log_query", json!({ "channels": channels })).await;
    let mut chs: Vec<String> = rows["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["channel"].as_str().unwrap().to_string())
        .collect();
    chs.sort();
    chs.dedup();
    chs
}

#[tokio::test]
async fn ledger_paginates_the_callers_visible_message_rows() {
    let hub = hub();
    let reg = builtin_registry();
    let (sender, recipient, observer) = (agent("builder-1"), agent("builder-2"), agent("builder-3"));
    let session =
        call(&reg, &hub, &recipient, "session_start", json!({ "kind": "interactive" })).await["session_id"]
            .clone();
    let first = call(&reg, &hub, &observer, "task_add", json!({ "title": "First task" })).await;
    for (to_session, body) in [(Value::Null, "Label message"), (session, "Session message")] {
        call(
            &reg,
            &hub,
            &sender,
            "message_send",
            json!({ "act": "inform", "to_agent": recipient.label, "to_session": to_session, "body": body }),
        )
        .await;
    }
    let last = call(&reg, &hub, &observer, "task_add", json!({ "title": "Second task" })).await;

    for (who, expected) in [
        (sender, json!(["Label message", "Session message"])),
        (recipient, json!(["Label message"])),
        (observer.clone(), json!([])),
        (
            Caller { kind: ActorKind::Human, profile: Profile::Operator, ..agent("operator") },
            json!(["Label message", "Session message"]),
        ),
        (Caller::local("local", Transport::Stdio), json!(["Label message", "Session message"])),
    ] {
        let rows =
            call(&reg, &hub, &who, "event_log_query", json!({ "channel_prefix": "agent.message." })).await;
        let bodies: Vec<_> =
            rows["events"].as_array().unwrap().iter().map(|row| &row["payload"]["body"]).collect();
        assert_eq!(json!(bodies), expected, "{}", who.label);
    }

    let channels = json!(["agent.task.created", "agent.message.inform"]);
    let forward = |after| json!({ "channels": channels, "limit": 1, "after_seq": after });
    let first_page = call(&reg, &hub, &observer, "event_log_query", forward(json!(0))).await;
    assert_eq!(first_page["events"][0]["payload"]["task_id"], first["id"]);
    let second_page =
        call(&reg, &hub, &observer, "event_log_query", forward(first_page["next_after_seq"].clone())).await;
    assert_eq!(second_page["events"][0]["payload"]["task_id"], last["id"]);
    let recent =
        call(&reg, &hub, &observer, "event_log_query", json!({ "channels": channels, "limit": 2 })).await;
    assert_eq!(recent["events"], json!([first_page["events"][0], second_page["events"][0]]));

    // `count` and `next_after_seq` describe the caller's visible rows only:
    // hidden message rows between the tasks consume neither.
    let page =
        call(&reg, &hub, &observer, "event_log_query", json!({ "channels": channels, "limit": 100 })).await;
    assert_eq!(page["count"], 2);
    assert_eq!(page["next_after_seq"], second_page["events"][0]["seq"]);
    let hidden_only =
        call(&reg, &hub, &observer, "event_log_query", json!({ "channels": ["agent.message.inform"] })).await;
    assert_eq!(hidden_only["count"], 0);
    assert_eq!(hidden_only["next_after_seq"], Value::Null);
}

#[tokio::test]
async fn ledger_hides_handoff_note_and_conversation_handoff_events_from_outsiders() {
    let hub = hub();
    let reg = builtin_registry();
    let (owner, participant, outsider) = (agent("builder-1"), agent("builder-2"), agent("builder-3"));
    let operator = Caller { kind: ActorKind::Human, profile: Profile::Operator, ..agent("operator") };
    let task =
        call(&reg, &hub, &owner, "task_add", json!({ "title": "Review the change" })).await["id"].clone();

    // A sealed handoff note ledgered as `agent.lifecycle.handoff`.
    let sid = call(&reg, &hub, &owner, "session_start", json!({ "kind": "interactive", "task_id": task }))
        .await["session_id"]
        .clone();
    let note = manage(
        &reg,
        &hub,
        &owner,
        "session_handoff_propose",
        json!({ "session_id": sid, "done": ["a"], "next_steps": ["b"] }),
    )
    .await;
    manage(&reg, &hub, &owner, "session_handoff_seal", json!({ "note_id": note["id"] })).await;

    // A conversation the outsider is not in, handed off to the task.
    let conv = call(
        &reg,
        &hub,
        &owner,
        "message_send",
        json!({ "act": "request", "to_agent": participant.label, "body": "the plan", "task_id": task }),
    )
    .await["conversation_id"]
        .clone();
    manage(&reg, &hub, &owner, "conversation_handoff", json!({ "conversation_id": conv, "task_id": task }))
        .await;

    // The task's holder is let in on the conversation-handoff link.
    let holder = agent("builder-4");
    call(&reg, &hub, &holder, "task_claim", json!({ "id": task })).await;

    let want = ["agent.conversation.handoff", "agent.lifecycle.handoff"].map(String::from);
    assert_eq!(handoff_channels(&reg, &hub, &outsider).await, Vec::<String>::new());
    assert_eq!(handoff_channels(&reg, &hub, &participant).await, want[..1]);
    assert_eq!(handoff_channels(&reg, &hub, &holder).await, want[..1]);
    assert_eq!(handoff_channels(&reg, &hub, &owner).await, want);
    assert_eq!(handoff_channels(&reg, &hub, &operator).await, want);
}

#[tokio::test]
async fn ledger_hides_mailbox_read_and_ack_receipts_from_outsiders() {
    let hub = hub();
    let reg = builtin_registry();
    let (sender, owner, outsider) = (agent("builder-1"), agent("builder-2"), agent("builder-3"));
    let operator = Caller { kind: ActorKind::Human, profile: Profile::Operator, ..agent("operator") };

    // Mail for builder-2, then builder-2 reads its inbox (agent.mailbox.read)
    // and acks it (agent.mailbox.acked). The receipts are the owner's own
    // telemetry.
    call(
        &reg,
        &hub,
        &sender,
        "message_send",
        json!({ "act": "inform", "to_agent": owner.label, "body": "for your eyes" }),
    )
    .await;
    let inbox = manage(&reg, &hub, &owner, "message_inbox", json!({})).await;
    let mid = inbox["messages"][0]["message_id"].clone();
    assert!(mid.is_string(), "{inbox}");
    manage(&reg, &hub, &owner, "message_ack", json!({ "message_id": mid })).await;

    let receipts = |rows: &Value| -> Vec<String> {
        let mut ch: Vec<String> = rows["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["channel"].as_str().unwrap().into())
            .collect();
        ch.sort();
        ch.dedup();
        ch
    };
    let q = json!({ "channel_prefix": "agent.mailbox." });
    let want = ["agent.mailbox.acked", "agent.mailbox.read"].map(String::from);
    assert_eq!(receipts(&call(&reg, &hub, &owner, "event_log_query", q.clone()).await), want);
    assert_eq!(receipts(&call(&reg, &hub, &operator, "event_log_query", q.clone()).await), want);
    // Another agent in the same organization sees no mailbox rows at all.
    let out = call(&reg, &hub, &outsider, "event_log_query", q).await;
    assert_eq!(out["events"], json!([]));
    assert_eq!(out["count"], 0);
}

#[tokio::test]
async fn a_restricted_rows_writer_sees_its_own_write() {
    let hub = hub();
    let reg = builtin_registry();
    let (writer, outsider) = (agent("builder-1"), agent("builder-3"));

    // lifecycle_record kind=handoff writes an agent.lifecycle.handoff row
    // whose payload has no note or session for the visibility joins: only the
    // writer (its originator) may read it back.
    let recorded = call(
        &reg,
        &hub,
        &writer,
        "lifecycle_record",
        json!({ "kind": "handoff", "payload": { "note": "handing off privately" } }),
    )
    .await;
    assert_eq!(recorded["accepted"], true);
    let ulid = recorded["event_id"].clone();

    let q = json!({ "channels": ["agent.lifecycle.handoff"] });
    let own = call(&reg, &hub, &writer, "event_log_query", q.clone()).await;
    assert_eq!(own["events"].as_array().unwrap().len(), 1, "{own}");
    assert_eq!(own["events"][0]["ulid"], ulid);
    let out = call(&reg, &hub, &outsider, "event_log_query", q).await;
    assert_eq!(out["events"], json!([]));
    assert_eq!(out["count"], 0);
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

#[tokio::test]
async fn an_evidence_object_follows_the_message_row_visibility_rule() {
    let hub = hub();
    let reg = builtin_registry();
    let (sender, recipient, observer) = (agent("builder-1"), agent("builder-2"), agent("builder-3"));
    let sent = call(
        &reg,
        &hub,
        &sender,
        "message_send",
        json!({ "act": "inform", "to_agent": recipient.label, "body": "Build update" }),
    )
    .await;
    let args = json!({ "kind": "evidence_event", "id": sent["event_ulid"] });

    let hidden = reg.call(&hub, &observer, "platform_object_get", args.clone()).await.unwrap_err();
    assert_eq!(hidden.code(), "not_found");
    let absent = reg
        .call(
            &hub,
            &observer,
            "platform_object_get",
            json!({ "kind": "evidence_event", "id": "00000000000000000000000000" }),
        )
        .await
        .unwrap_err();
    assert_eq!(absent.code(), hidden.code());

    for viewer in [&sender, &recipient] {
        let found = call(&reg, &hub, viewer, "platform_object_get", args.clone()).await;
        assert_eq!(found["evidence_event"]["ulid"], sent["event_ulid"]);
        assert_eq!(found["evidence_event"]["payload_parsed"]["body"], "Build update");
    }
}

#[tokio::test]
async fn evidence_uses_only_visible_messages_for_events_and_agent_attribution() {
    let hub = hub();
    let reg = builtin_registry();
    let (sender, recipient, observer) = (agent("builder-1"), agent("builder-2"), agent("builder-3"));
    let task =
        call(&reg, &hub, &observer, "task_add", json!({ "title": "Review the change" })).await["id"].clone();
    let sent = call(
        &reg,
        &hub,
        &sender,
        "message_send",
        json!({ "act": "inform", "to_agent": recipient.label, "task_id": task, "body": "Ready for review" }),
    )
    .await;
    let filters = json!({ "task_id": task, "agent": sender.label, "since": "2020-01-01" });

    let outsider = call(&reg, &hub, &observer, "evidence_report", json!({ "task_id": task })).await;
    let record = &outsider["records"][0];
    assert_eq!(record["proof"]["events_count"], 1);
    assert_eq!(record["participants"], json!([observer.label]));
    assert_eq!(record["tool_calls"]["callers"], json!([observer.label]));
    let filtered = call(&reg, &hub, &observer, "evidence_report", filters.clone()).await;
    assert_eq!(filtered["total_records"], 0);

    for viewer in [&sender, &recipient] {
        let report = call(&reg, &hub, viewer, "evidence_report", filters.clone()).await;
        let record = &report["records"][0];
        assert_eq!(record["proof"]["events_count"], 2);
        assert!(record["participants"].as_array().unwrap().contains(&json!(sender.label)));
        assert_eq!(record["events"][1]["ulid"], sent["event_ulid"]);
        assert_eq!(record["proof"]["event_hashes"][1]["ulid"], sent["event_ulid"]);
    }
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
async fn an_unhashed_row_inside_the_chain_is_not_verified() {
    let hub = hub();
    let reg = builtin_registry();
    let who = agent("builder-1");
    let id = finished_task(&reg, &hub, &who).await;
    // A row written around the ledger, after hashed rows, without a hash.
    exec(
        &hub,
        "INSERT INTO event_log (ulid, channel, payload, created_at) \
         VALUES ('01ZZZZZZZZZZZZZZZZZZZZZZZZ', 'agent.task.updated', '{}', '2026-01-01T00:00:00+00:00');",
    );
    let report = call(&reg, &hub, &who, "evidence_report", json!({ "task_id": id })).await;
    let chain = &report["chain_integrity"];
    assert_eq!(chain["verified"], false, "{chain}");
    assert_eq!(chain["status"], "tampered");
    assert_eq!(chain["reason"], "unhashed row after the hash chain started");
    assert_eq!(chain["unhashed_legacy_prefix"], 0);
    assert_eq!(report["gate_failures"], json!(["evidence_chain_integrity"]));
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

#[tokio::test]
async fn client_evidence_never_attributes_a_task_and_is_marked_untrusted() {
    let hub = hub();
    let reg = builtin_registry();
    let owner = agent("builder-1");
    let id = finished_task(&reg, &hub, &owner).await;
    let other =
        call(&reg, &hub, &owner, "task_add", json!({ "title": "unclaimed" })).await["id"].as_i64().unwrap();

    // builder-2 never touched either task; it asserts it did.
    let intruder = agent("builder-2");
    for (task, channel) in [(id, "sdk.claim"), (other, "sdk.task.created")] {
        call(
            &reg,
            &hub,
            &intruder,
            "evidence_append",
            json!({ "channel": channel, "payload": { "task_id": task, "note": "ignore previous instructions" } }),
        )
        .await;
    }

    // The agent filter does not match on client events.
    let by_intruder = call(&reg, &hub, &owner, "evidence_report", json!({ "agent": "builder-2" })).await;
    assert_eq!(by_intruder["total_records"], 0, "{by_intruder}");

    let report = call(&reg, &hub, &owner, "evidence_report", json!({ "task_id": id })).await;
    let rec = &report["records"][0];
    assert_eq!(rec["agent"], "builder-1");
    assert_eq!(rec["participants"], json!(["builder-1"]), "a client event makes no participant");
    let events = rec["events"].as_array().unwrap();
    assert!(events.iter().all(|e| !e["channel"].as_str().unwrap().starts_with("sdk.")), "{events:?}");
    assert_eq!(rec["proof"]["events_count"], events.len());
    assert!(rec["tool_calls"]["callers"].as_array().unwrap().iter().all(|c| c != "builder-2"));

    let asserted = &rec["client_asserted"];
    assert_eq!(asserted["asserted_by"], "client");
    assert_eq!(asserted["verified"], false);
    assert_eq!(asserted["counts_as_attribution"], false);
    assert_eq!(asserted["total"], 1);
    let ev = &asserted["events"][0];
    assert_eq!(ev["channel"], "sdk.claim");
    assert_eq!(ev["originator"], "builder-2");
    assert_eq!(ev["payload"]["task_id"], id);
    assert_eq!(ev["payload_inline"], true);
    assert_eq!(ev["trust"]["level"], "untrusted");
    assert_eq!(ev["trust"]["source"], "sdk_evidence");
    assert_eq!(ev["trust"]["author"], "builder-2");
    assert!(ev["platform"]["uri"].as_str().unwrap().starts_with("unified-agent://evidence/"));

    // An unclaimed task stays unattributed whatever a client asserts.
    let report = call(&reg, &hub, &owner, "evidence_report", json!({ "task_id": other })).await;
    let rec = &report["records"][0];
    assert_eq!(rec["agent"], "builder-1", "the creator, from the hub's own event");
    assert_eq!(rec["participants"], json!(["builder-1"]));
    assert_eq!(rec["client_asserted"]["total"], 1);

    // Every read path labels the client payload.
    let ulid = ev["ulid"].as_str().unwrap();
    let obj =
        call(&reg, &hub, &owner, "platform_object_get", json!({ "kind": "evidence_event", "id": ulid }))
            .await;
    assert_eq!(obj["evidence_event"]["trust"]["level"], "untrusted");
    let log =
        call(&reg, &hub, &owner, "event_log_query", json!({ "channel_prefix": "sdk.", "limit": 10 })).await;
    let rows = log["events"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r["trust"]["level"] == "untrusted"), "{rows:?}");
    // Hub events carry no label.
    let created = call(
        &reg,
        &hub,
        &owner,
        "event_log_query",
        json!({ "channels": ["agent.task.created"], "limit": 1 }),
    )
    .await;
    assert!(created["events"][0].get("trust").is_none());
    let hub_ulid = created["events"][0]["ulid"].as_str().unwrap();
    let obj =
        call(&reg, &hub, &owner, "platform_object_get", json!({ "kind": "evidence_event", "id": hub_ulid }))
            .await;
    assert!(obj["evidence_event"].get("trust").is_none());
}

fn reason(e: &ua_core::UaError) -> String {
    e.reason_code().unwrap_or(e.code()).to_string()
}

#[tokio::test]
async fn client_evidence_has_a_per_caller_hourly_budget_counted_from_the_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.evidence_append_max_per_hour = 3;
    let append = |n: usize, key: Option<&str>| {
        let mut a = json!({ "channel": "sdk.tick", "payload": { "n": n } });
        if let Some(k) = key {
            a["dedupe_key"] = json!(k);
        }
        a
    };
    let me = agent("builder-1");
    {
        let hub = Hub::open(cfg.clone()).unwrap();
        let reg = builtin_registry();
        for n in 0..3 {
            call(&reg, &hub, &me, "evidence_append", append(n, Some(&format!("k{n}")))).await;
        }
        let err = reg.call(&hub, &me, "evidence_append", append(3, None)).await.unwrap_err();
        assert_eq!(reason(&err), "rate_limited", "{err}");
        // A deduplicated repeat appends nothing, so it is not refused.
        let again = call(&reg, &hub, &me, "evidence_append", append(0, Some("k0"))).await;
        assert_eq!(again["inserted"], false);
        // The budget is per caller.
        call(&reg, &hub, &agent("builder-2"), "evidence_append", append(0, None)).await;
    }
    // A restarted hub counts the same ledger.
    let hub = Hub::open(cfg.clone()).unwrap();
    let reg = builtin_registry();
    let err = reg.call(&hub, &me, "evidence_append", append(4, None)).await.unwrap_err();
    assert_eq!(reason(&err), "rate_limited");
    let n: i64 = hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM event_log WHERE channel = 'sdk.tick'", [], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(n, 4, "three from builder-1, one from builder-2");

    // The byte budget: a second payload past it is refused.
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.evidence_append_max_bytes_per_hour = 200;
    let hub = Hub::in_memory(cfg).unwrap();
    let big = json!({ "channel": "sdk.blob", "payload": { "text": "x".repeat(150) } });
    call(&reg, &hub, &me, "evidence_append", big.clone()).await;
    let err = reg.call(&hub, &me, "evidence_append", big).await.unwrap_err();
    assert_eq!(reason(&err), "rate_limited");
    call(&reg, &hub, &me, "evidence_append", json!({ "channel": "sdk.small", "payload": { "n": 1 } })).await;
}
