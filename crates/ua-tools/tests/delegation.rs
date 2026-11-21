//! Delegation: child tasks, claim fencing, handoff and the spec standard.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const SPEC: &str = "\
### Objective
Add a CSV export to the report page.

### Scope
- src/report.rs

### Definition of Done
- Calling export on a report with two rows returns a CSV with a header and two lines
- An empty report is refused with an error naming the report id
- Gates: the test suite, lint, format check and CI pass

### TDD Constraints
- Stub: none

### Boundaries
- Do not change the report schema
";

fn hub_with(cfg: impl FnOnce(&mut Config)) -> Hub {
    let mut c = Config::for_home(std::env::temp_dir());
    c.human_identities = vec!["operator".into()];
    cfg(&mut c);
    Hub::in_memory(c).unwrap()
}

fn hub() -> Hub {
    hub_with(|_| {})
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Operator, ..agent("operator") }
}

async fn delegate(reg: &Registry, hub: &Hub, from: &Caller, to: &str) -> Value {
    reg.call(hub, from, "delegate", json!({ "task_spec": SPEC, "to_agent": to, "deadline": "2020-01-01" }))
        .await
        .unwrap()
}

fn task_row(hub: &Hub, id: i64) -> (String, String, String, String, i64) {
    hub.db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT title, notes, status, lane, untrusted FROM tasks WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?)
        })
        .unwrap()
}

#[tokio::test]
async fn delegate_creates_a_child_task_and_a_pending_row() {
    let (hub, reg, from) = (hub(), builtin_registry(), agent("lead-1"));
    let out = delegate(&reg, &hub, &from, "builder-1").await;
    let task_id = out["task_id"].as_i64().unwrap();
    assert!(out["delegation_id"].as_i64().unwrap() > 0);
    assert_eq!(out["memory_id"], Value::Null);

    let (title, notes, status, lane, untrusted) = task_row(&hub, task_id);
    assert_eq!(title, "Add a CSV export to the report page.");
    assert!(notes.starts_with("[delegated-by: lead-1] [delegated-to: builder-1]"), "{notes}");
    assert!(notes.contains("[deadline: 2020-01-01]"));
    assert!(notes.contains("task-spec:\n### Objective"));
    assert_eq!((status.as_str(), lane.as_str(), untrusted), ("open", "builder-1", 0));

    let list = reg.call(&hub, &from, "delegate_list", json!({})).await.unwrap();
    let row = &list["delegations"][0];
    assert_eq!(row["status"], "pending");
    assert_eq!(row["from_agent"], "lead-1");
    assert_eq!(row["overdue"], true);
    assert_eq!(list["truncated"], false);

    let ev = reg
        .call(&hub, &Caller::system(), "event_log_query", json!({ "channels": ["agent.delegation.created"] }))
        .await
        .unwrap();
    assert_eq!(ev["count"], 1);
    assert_eq!(ev["events"][0]["payload"]["task_id"], task_id);

    // Self-delegation, bad labels, bad callbacks and bad deadlines are refused.
    for args in [
        json!({ "task_spec": SPEC, "to_agent": "lead-1" }),
        json!({ "task_spec": SPEC, "to_agent": "bad label" }),
        json!({ "task_spec": SPEC, "to_agent": "builder-1", "callback": "email" }),
        json!({ "task_spec": SPEC, "to_agent": "builder-1", "deadline": "next tuesday" }),
        json!({ "task_spec": SPEC, "to_agent": "builder-1", "parent_task_id": 999 }),
    ] {
        let err = reg.call(&hub, &from, "delegate", args.clone()).await.unwrap_err();
        assert!(matches!(err.code(), "invalid_argument" | "not_found"), "{args}: {err}");
    }
    // A verified agent cannot delegate in another agent's name.
    let spoof = reg
        .call(
            &hub,
            &from,
            "delegate",
            json!({ "task_spec": SPEC, "from_agent": "lead-2", "to_agent": "builder-1" }),
        )
        .await
        .unwrap_err();
    assert_eq!(spoof.code(), "denied");
}

#[tokio::test]
async fn untrusted_parent_makes_an_untrusted_child() {
    let (hub, reg, from) = (hub(), builtin_registry(), agent("lead-1"));
    let parent = hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO tasks (title, created_at, updated_at, untrusted, project) VALUES ('p', 'x', 'x', 1, 'web')",
                [],
            )?;
            Ok(tx.last_insert_rowid())
        })
        .unwrap();
    let out = reg
        .call(
            &hub,
            &from,
            "delegate",
            json!({ "task_spec": SPEC, "to_agent": "builder-1", "parent_task_id": parent }),
        )
        .await
        .unwrap();
    let (_, _, _, _, untrusted) = task_row(&hub, out["task_id"].as_i64().unwrap());
    assert_eq!(untrusted, 1);
}

#[tokio::test]
async fn spec_standard_is_enforced_and_exposed() {
    let (hub, reg, from) = (hub(), builtin_registry(), agent("lead-1"));

    let weak = "### Objective\nx\n### Scope\ny\n### Definition of Done\n- cargo build passes\n- CI is green\n\
                ### TDD\nz\n### Boundaries\n- none\n";
    let err = reg.call(&hub, &from, "delegate", json!({ "task_spec": weak, "to_agent": "builder-1" })).await;
    let err = err.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert!(err.to_string().contains("no observable behaviour"), "{err}");

    let check = reg.call(&hub, &from, "delegation_spec_check", json!({ "task_spec": weak })).await.unwrap();
    assert_eq!(check["ok"], false);
    assert_eq!(check["dod_criteria"], 2);
    assert_eq!(check["behavioural_criteria"], 0);

    let missing =
        reg.call(&hub, &from, "delegation_spec_check", json!({ "task_spec": "do the thing" })).await.unwrap();
    assert_eq!(missing["sections_missing"].as_array().unwrap().len(), 5);

    let good = reg.call(&hub, &from, "delegation_spec_check", json!({ "task_spec": SPEC })).await.unwrap();
    assert_eq!(good["ok"], true, "{good}");
    assert_eq!(good["dod_criteria"], 3);
    assert_eq!(good["behavioural_criteria"], 2);

    let tpl = reg.call(&hub, &from, "delegation_spec_template", json!({})).await.unwrap();
    assert_eq!(tpl["required_sections"].as_array().unwrap().len(), 5);
    assert!(tpl["template"].as_str().unwrap().contains("### Definition of Done"));

    let built = reg
        .call(
            &hub,
            &from,
            "delegation_spec_build",
            json!({
                "objective": "Export reports as CSV",
                "scope_files": "- src/report.rs\n- src/csv.rs",
                "dod_criteria": ["export returns two lines for two rows", "an empty report is refused"],
            }),
        )
        .await
        .unwrap();
    assert_eq!(built["ok"], true);
    assert!(built["spec"].as_str().unwrap().contains("- src/csv.rs"));
    let built_spec = built["spec"].as_str().unwrap().to_string();
    reg.call(&hub, &from, "delegate", json!({ "task_spec": built_spec, "to_agent": "builder-1" }))
        .await
        .unwrap();

    let refused = reg
        .call(
            &hub,
            &from,
            "delegation_spec_build",
            json!({ "objective": "x", "dod_criteria": ["CI passes"] }),
        )
        .await
        .unwrap_err();
    assert_eq!(refused.code(), "invalid_argument");
    let advisory = reg
        .call(
            &hub,
            &from,
            "delegation_spec_build",
            json!({ "objective": "x", "dod_criteria": ["CI passes"], "auto_validate": false }),
        )
        .await
        .unwrap();
    assert_eq!(advisory["ok"], false);
}

#[tokio::test]
async fn claim_generation_fences_every_transition() {
    let (hub, reg, from) = (hub(), builtin_registry(), agent("lead-1"));
    let me = agent("builder-1");
    let id = delegate(&reg, &hub, &from, "builder-1").await["delegation_id"].as_i64().unwrap();

    // Only the addressee can claim.
    let wrong = reg.call(&hub, &agent("builder-9"), "delegate_claim", json!({ "id": id })).await.unwrap();
    assert_eq!(wrong["claimed"], false);

    let c1 = reg.call(&hub, &me, "delegate_claim", json!({ "id": id })).await.unwrap();
    assert_eq!(c1["claimed"], true);
    assert_eq!(c1["delegation"]["status"], "in_flight");
    assert_eq!(c1["delegation"]["claim_generation"], 1);
    assert_eq!(c1["delegation"]["attempts"], 1);
    let c1b = reg.call(&hub, &me, "delegate_claim", json!({ "id": id })).await.unwrap();
    assert_eq!(c1b["claimed"], false);

    // Release needs the generation it holds.
    let missing = reg.call(&hub, &me, "delegate_release", json!({ "id": id })).await.unwrap_err();
    assert_eq!(missing.code(), "invalid_argument");
    let stale = reg
        .call(&hub, &me, "delegate_release", json!({ "id": id, "expected_claim_generation": 0 }))
        .await
        .unwrap();
    assert_eq!(stale["released"], false);
    let rel = reg
        .call(&hub, &me, "delegate_release", json!({ "id": id, "expected_claim_generation": 1 }))
        .await
        .unwrap();
    assert_eq!(rel["released"], true);

    let c2 = reg.call(&hub, &me, "delegate_claim", json!({ "id": id })).await.unwrap();
    assert_eq!(c2["delegation"]["claim_generation"], 2);

    // A delayed write from the first attempt cannot finish the second.
    let manage = |action: &str, params: Value| {
        let (reg, hub, me) = (reg.clone(), hub.clone(), me.clone());
        let action = action.to_string();
        async move {
            reg.call(&hub, &me, "delegation_manage", json!({ "action": action, "params": params })).await
        }
    };
    let old = manage("complete", json!({ "id": id, "expected_claim_generation": 1, "result": "late" }))
        .await
        .unwrap();
    assert_eq!(old["completed"], false);
    let old = manage("fail", json!({ "id": id, "expected_claim_generation": 1 })).await.unwrap();
    assert_eq!(old["failed"], false);

    // Retry keeps attempts; then the current generation completes it.
    let rt = manage("retry", json!({ "id": id, "expected_claim_generation": 2, "reason": "flaky" }))
        .await
        .unwrap();
    assert_eq!(rt["retried"], true);
    let c3 = reg.call(&hub, &me, "delegate_claim", json!({ "id": id })).await.unwrap();
    assert_eq!(c3["delegation"]["attempts"], 2, "release undid one attempt; retry kept one");
    assert_eq!(c3["delegation"]["claim_generation"], 3);

    // A run fence that does not match the task's run changes nothing.
    let fenced = manage(
        "complete",
        json!({ "id": id, "expected_claim_generation": 3, "expected_run_id": "run-x", "result": "ok" }),
    )
    .await
    .unwrap();
    assert_eq!(fenced, json!({ "completed": false, "reason": "run_not_current" }));

    let done = manage("complete", json!({ "id": id, "expected_claim_generation": 3, "result": "ok" }))
        .await
        .unwrap();
    assert_eq!(done["completed"], true);
    let row = manage("get", json!({ "id": id })).await.unwrap();
    assert_eq!(row["delegation"]["status"], "completed");
    assert_eq!(row["delegation"]["callback_result"], "ok");
    assert!(row["delegation"]["completed_at"].is_string());

    // Terminal rows do not move again.
    let cancel = reg.call(&hub, &from, "delegate_cancel", json!({ "id": id })).await.unwrap();
    assert_eq!(cancel["cancelled"], false);

    let ev = reg
        .call(&hub, &Caller::system(), "event_log_query", json!({ "channel_prefix": "agent.delegation." }))
        .await
        .unwrap();
    let ch: Vec<&str> =
        ev["events"].as_array().unwrap().iter().map(|e| e["channel"].as_str().unwrap()).collect();
    assert_eq!(
        ch,
        [
            "agent.delegation.created",
            "agent.delegation.claimed",
            "agent.delegation.released",
            "agent.delegation.claimed",
            "agent.delegation.retried",
            "agent.delegation.claimed",
            "agent.delegation.completed",
        ]
    );
}

#[tokio::test]
async fn cancel_is_for_the_delegator_or_assignee() {
    let (hub, reg, from) = (hub(), builtin_registry(), agent("lead-1"));
    let id = delegate(&reg, &hub, &from, "builder-1").await["delegation_id"].as_i64().unwrap();
    let outsider = reg.call(&hub, &agent("builder-9"), "delegate_cancel", json!({ "id": id })).await.unwrap();
    assert_eq!(outsider["cancelled"], false);
    let spoof = reg
        .call(&hub, &agent("builder-9"), "delegate_cancel", json!({ "id": id, "agent": "lead-1" }))
        .await
        .unwrap_err();
    assert_eq!(spoof.code(), "denied");
    let ok =
        reg.call(&hub, &from, "delegate_cancel", json!({ "id": id, "reason": "not needed" })).await.unwrap();
    assert_eq!(ok["cancelled"], true);
    let rows = reg.call(&hub, &from, "delegate_list", json!({ "status": "cancelled" })).await.unwrap();
    assert_eq!(rows["delegations"][0]["callback_result"], "not needed");
}

#[tokio::test]
async fn concurrent_delegate_claim_has_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::open(Config::for_home(dir.path())).unwrap();
    let reg = builtin_registry();
    let id = delegate(&reg, &hub, &agent("lead-1"), "builder-1").await["delegation_id"].as_i64().unwrap();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let (hub, reg) = (hub.clone(), reg.clone());
        handles.push(tokio::spawn(async move {
            reg.call(&hub, &agent("builder-1"), "delegate_claim", json!({ "id": id })).await.unwrap()
        }));
    }
    let mut wins = 0;
    for h in handles {
        if h.await.unwrap()["claimed"] == true {
            wins += 1;
        }
    }
    assert_eq!(wins, 1);
}

#[tokio::test]
async fn handoff_creates_a_task_and_lists_metadata_only() {
    let (hub, reg, from) = (hub(), builtin_registry(), agent("lead-1"));
    let h = reg
        .call(&hub, &from, "handoff", json!({ "task_spec": SPEC, "to_agent": "builder-2" }))
        .await
        .unwrap();
    assert_eq!(h["status"], "pending");
    let task_id = h["task_id"].as_i64().unwrap();
    let (_, notes, status, lane, _) = task_row(&hub, task_id);
    assert!(notes.contains("[delegated-to: builder-2]"));
    assert_eq!((status.as_str(), lane.as_str()), ("open", "builder-2"));

    let row = reg
        .call(
            &hub,
            &from,
            "delegation_manage",
            json!({ "action": "get", "params": { "id": h["handoff_id"] } }),
        )
        .await
        .unwrap();
    assert_eq!(row["delegation"]["callback"], "none");

    let list = reg.call(&hub, &from, "handoff_list", json!({})).await.unwrap();
    let first = list["handoffs"][0].as_object().unwrap();
    assert_eq!(first["task_id"], task_id);
    assert!(!first.contains_key("task_spec"));
    assert!(!first.contains_key("callback_result"));
}

#[tokio::test]
async fn idempotency_key_replays_and_lookup_recovers() {
    let (hub, reg, from) = (hub(), builtin_registry(), agent("lead-1"));
    let args = json!({ "task_spec": SPEC, "to_agent": "builder-1", "idempotency_key": "req-1" });
    let a = reg.call(&hub, &from, "delegate", args.clone()).await.unwrap();
    let b = reg.call(&hub, &from, "delegate", args).await.unwrap();
    assert_eq!(a, b);
    let rows = reg.call(&hub, &from, "delegate_list", json!({ "status": "all" })).await.unwrap();
    assert_eq!(rows["delegations"].as_array().unwrap().len(), 1);

    let other = reg
        .call(
            &hub,
            &from,
            "delegate",
            json!({ "task_spec": SPEC, "to_agent": "builder-2", "idempotency_key": "req-1" }),
        )
        .await
        .unwrap_err();
    assert_eq!(other.code(), "conflict");

    let manage = |params: Value| {
        reg.call(&hub, &from, "delegation_manage", json!({ "action": "lookup", "params": params }))
    };
    let found = manage(json!({ "idempotency_key": "req-1" })).await.unwrap();
    assert_eq!(found["state"], "committed");
    assert_eq!(found["result"], a);
    let none = manage(json!({ "idempotency_key": "req-2" })).await.unwrap();
    assert_eq!(none["state"], "not_found");
    // Another identity's key reads as not found.
    let theirs = reg
        .call(
            &hub,
            &agent("lead-2"),
            "delegation_manage",
            json!({ "action": "lookup", "params": { "idempotency_key": "req-1" } }),
        )
        .await
        .unwrap();
    assert_eq!(theirs["state"], "not_found");
}

#[tokio::test]
async fn approval_listed_delegate_gates_handoff_too() {
    let hub = hub_with(|c| c.approval_tools = vec!["delegate".into()]);
    let (reg, from) = (builtin_registry(), agent("lead-1"));
    let args = json!({ "task_spec": SPEC, "to_agent": "builder-1" });
    let parked = reg.call(&hub, &from, "handoff", args.clone()).await.unwrap_err();
    let approval_id = match parked {
        ua_core::UaError::ApprovalRequired { approval_id, ref tool } => {
            assert_eq!(tool, "delegate");
            approval_id
        }
        other => panic!("expected an approval, got {other:?}"),
    };
    let none = reg.call(&hub, &from, "handoff_list", json!({})).await.unwrap();
    assert!(none["handoffs"].as_array().unwrap().is_empty());

    reg.call(&hub, &human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
        .await
        .unwrap();
    let ok = reg.call(&hub, &from, "handoff", args.clone()).await.unwrap();
    assert_eq!(ok["status"], "pending");
    // The pass was one-shot.
    let again = reg.call(&hub, &from, "handoff", args).await.unwrap_err();
    assert_eq!(again.code(), "approval_required");
}

#[tokio::test]
async fn manage_actions_and_aliases() {
    let (hub, reg, from) = (hub(), builtin_registry(), agent("lead-1"));
    let call = |action: &str, params: Value| {
        reg.call(&hub, &from, "delegation_manage", json!({ "action": action, "params": params }))
    };
    let created = call("create", json!({ "task_spec": SPEC, "to_agent": "builder-1" })).await.unwrap();
    assert!(created["task_id"].is_i64());
    let listed = call("delegate_list", json!({ "to_agent": "builder-1" })).await.unwrap();
    assert_eq!(listed["delegations"].as_array().unwrap().len(), 1);
    assert_eq!(call("spec_template", json!({})).await.unwrap()["required_sections"][0], "objective");
    assert_eq!(call("delegation_spec_check", json!({ "task_spec": SPEC })).await.unwrap()["ok"], true);
    assert_eq!(call("ledger", json!({})).await.unwrap_err().code(), "invalid_argument");
    assert!(call("list", json!({ "nope": 1 })).await.unwrap_err().to_string().contains("invalid params"));
    for name in [
        "delegate",
        "delegate_list",
        "delegate_claim",
        "delegate_release",
        "delegate_cancel",
        "delegation_manage",
        "handoff",
        "handoff_list",
        "delegation_spec_check",
        "delegation_spec_template",
        "delegation_spec_build",
    ] {
        assert!(reg.get(name).is_some(), "{name} is not registered");
    }
}
