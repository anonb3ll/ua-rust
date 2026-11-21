//! Plans: lifecycle, dependency-aware claims, checkpoints and structure edits.

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
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

async fn manage(
    reg: &Registry,
    hub: &Hub,
    who: &Caller,
    action: &str,
    params: Value,
) -> ua_core::UaResult<Value> {
    reg.call(hub, who, "plan_manage", json!({ "action": action, "params": params })).await
}

async fn create_chain(reg: &Registry, hub: &Hub, who: &Caller) -> String {
    let out = manage(
        reg,
        hub,
        who,
        "create",
        json!({
            "goal": "Ship the importer\n\nRead, convert, publish.",
            "steps": [
                "read the source",
                {"description": "convert rows", "depends_on": [0], "owner": "builder-2"},
                {"description": "publish", "depends_on": [0, 1]},
            ],
        }),
    )
    .await
    .unwrap();
    out["plan_id"].as_str().unwrap().to_string()
}

async fn channels(reg: &Registry, hub: &Hub) -> Vec<String> {
    let ev = reg
        .call(
            hub,
            &Caller::system(),
            "event_log_query",
            json!({ "channel_prefix": "agent.plan.", "limit": 1000 }),
        )
        .await
        .unwrap();
    ev["events"].as_array().unwrap().iter().map(|e| e["channel"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn lifecycle_create_update_handoff_completes() {
    let (hub, reg, me) = (hub(), builtin_registry(), agent("builder-1"));
    let id = create_chain(&reg, &hub, &me).await;

    let got = reg.call(&hub, &me, "plan_get", json!({ "plan_id": id })).await.unwrap();
    assert_eq!(got["plan"]["title"], "Ship the importer");
    assert_eq!(got["plan"]["description"], "Read, convert, publish.");
    assert_eq!(got["plan"]["author"], "builder-1");
    assert_eq!(got["plan"]["needs_human"], false);
    assert_eq!(got["steps"].as_array().unwrap().len(), 3);
    assert_eq!(got["steps"][2]["depends_on"], json!([0, 1]));
    assert_eq!(got["next_step_idx"], 0);

    let upd = reg
        .call(
            &hub,
            &me,
            "plan_update",
            json!({ "plan_id": id, "step_idx": 0, "status": "done", "note": "read" }),
        )
        .await
        .unwrap();
    assert!(upd["step"]["done_at"].is_string());
    assert_eq!(upd["next_step_idx"], 1);

    let bad =
        reg.call(&hub, &me, "plan_update", json!({ "plan_id": id, "step_idx": 0, "status": "nope" })).await;
    assert_eq!(bad.unwrap_err().code(), "invalid_argument");

    let h = reg
        .call(&hub, &me, "plan_handoff", json!({ "plan_id": id, "step_idx": 1, "outputs": {"rows": 42} }))
        .await
        .unwrap();
    assert_eq!(h["step"]["status"], "done");
    assert_eq!(h["step"]["outputs"]["rows"], 42);
    assert_eq!(h["next_step"]["step_idx"], 2);
    assert_eq!(h["notified"], false);

    let last = manage(&reg, &hub, &me, "handoff", json!({ "plan_id": id, "step_idx": 2 })).await.unwrap();
    assert_eq!(last["next_step"], Value::Null);
    assert_eq!(last["plan"]["status"], "done");

    let done = reg.call(&hub, &me, "plan_list", json!({ "status": "done" })).await.unwrap();
    assert_eq!(done["plans"].as_array().unwrap().len(), 1);
    let active = reg.call(&hub, &me, "plan_list", json!({})).await.unwrap();
    assert!(active["plans"].as_array().unwrap().is_empty());

    let ch = channels(&reg, &hub).await;
    for want in
        ["agent.plan.created", "agent.plan.step_updated", "agent.plan.handoff", "agent.plan.completed"]
    {
        assert!(ch.iter().any(|c| c == want), "missing {want} in {ch:?}");
    }

    let del = reg.call(&hub, &me, "plan_delete", json!({ "plan_id": id })).await.unwrap();
    assert_eq!(del["deleted"], true);
    let gone = reg.call(&hub, &me, "plan_get", json!({ "plan_id": id })).await.unwrap_err();
    assert_eq!(gone.code(), "not_found");
}

#[tokio::test]
async fn step_claim_respects_dependencies() {
    let (hub, reg, me) = (hub(), builtin_registry(), agent("builder-1"));
    let id = create_chain(&reg, &hub, &me).await;

    let blocked =
        reg.call(&hub, &me, "plan_step_claim", json!({ "plan_id": id, "step_idx": 2 })).await.unwrap_err();
    assert_eq!(blocked.code(), "conflict");
    assert!(blocked.to_string().contains("depends on"), "{blocked}");

    let c0 = reg.call(&hub, &me, "plan_step_claim", json!({ "plan_id": id, "step_idx": 0 })).await.unwrap();
    assert_eq!(c0["claimed"], true);
    assert_eq!(c0["step"]["owner"], "builder-1");
    assert_eq!(c0["step"]["status"], "doing");

    // A doing step cannot be claimed again, even by its owner.
    let again =
        reg.call(&hub, &me, "plan_step_claim", json!({ "plan_id": id, "step_idx": 0 })).await.unwrap_err();
    assert_eq!(again.code(), "conflict");

    reg.call(&hub, &me, "plan_handoff", json!({ "plan_id": id, "step_idx": 0 })).await.unwrap();
    // Step 1 is owned by builder-2: only builder-2 may claim it.
    let other =
        reg.call(&hub, &me, "plan_step_claim", json!({ "plan_id": id, "step_idx": 1 })).await.unwrap_err();
    assert!(other.to_string().contains("builder-2"), "{other}");
    let b2 = agent("builder-2");
    manage(&reg, &hub, &b2, "claim", json!({ "plan_id": id, "step_idx": 1 })).await.unwrap();
    let still =
        manage(&reg, &hub, &b2, "step_claim", json!({ "plan_id": id, "step_idx": 2 })).await.unwrap_err();
    assert_eq!(still.code(), "conflict");
    reg.call(&hub, &b2, "plan_handoff", json!({ "plan_id": id, "step_idx": 1 })).await.unwrap();
    let c2 = manage(&reg, &hub, &b2, "step_claim", json!({ "plan_id": id, "step_idx": 2 })).await.unwrap();
    assert_eq!(c2["step"]["owner"], "builder-2");

    // A verified agent cannot claim in another agent's name.
    let spoof = reg
        .call(&hub, &me, "plan_step_claim", json!({ "plan_id": id, "step_idx": 2, "agent": "builder-2" }))
        .await
        .unwrap_err();
    assert_eq!(spoof.code(), "denied");
}

#[tokio::test]
async fn cycles_and_bad_steps_are_refused() {
    let (hub, reg, me) = (hub(), builtin_registry(), agent("builder-1"));
    for steps in [
        json!([{"description": "a", "depends_on": [1]}, {"description": "b", "depends_on": [0]}]),
        json!([{"description": "a", "depends_on": [0]}]),
        json!([{"description": "a", "depends_on": [5]}]),
        json!([{"description": "  "}]),
        json!([]),
        json!([3]),
    ] {
        let err =
            reg.call(&hub, &me, "plan_create", json!({ "goal": "g", "steps": steps })).await.unwrap_err();
        assert_eq!(err.code(), "invalid_argument", "{steps}: {err}");
    }
}

#[tokio::test]
async fn concurrent_step_claim_has_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::open(Config::for_home(dir.path())).unwrap();
    let reg = builtin_registry();
    let id =
        manage(&reg, &hub, &agent("lead-1"), "create", json!({ "goal": "race", "steps": ["only step"] }))
            .await
            .unwrap()["plan_id"]
            .as_str()
            .unwrap()
            .to_string();

    let mut handles = Vec::new();
    for i in 0..8 {
        let (hub, reg, id) = (hub.clone(), reg.clone(), id.clone());
        handles.push(tokio::spawn(async move {
            let who = agent(&format!("builder-{i}"));
            reg.call(&hub, &who, "plan_step_claim", json!({ "plan_id": id, "step_idx": 0 })).await
        }));
    }
    let mut wins = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(v) => {
                assert_eq!(v["claimed"], true);
                wins += 1;
            }
            Err(e) => assert_eq!(e.code(), "conflict", "{e}"),
        }
    }
    assert_eq!(wins, 1);
}

#[tokio::test]
async fn checkpoint_and_resume() {
    let (hub, reg, me) = (hub(), builtin_registry(), agent("builder-1"));
    let id = create_chain(&reg, &hub, &me).await;

    let none = reg.call(&hub, &me, "plan_resume", json!({ "plan_id": id })).await.unwrap();
    assert_eq!(none["checkpoint"], Value::Null);
    assert_eq!(none["next_step_idx"], 0);

    let c1 = reg
        .call(
            &hub,
            &me,
            "plan_checkpoint",
            json!({ "plan_id": id, "memory_ids": ["m1"], "file_paths": ["src/lib.rs"], "note": "first" }),
        )
        .await
        .unwrap();
    assert_eq!(c1["seq"], 1);
    assert_eq!(c1["checkpoint"]["context"]["step_state"][0]["status"], "open");

    reg.call(&hub, &me, "plan_update", json!({ "plan_id": id, "step_idx": 0, "status": "done" }))
        .await
        .unwrap();
    let c2 =
        manage(&reg, &hub, &me, "checkpoint", json!({ "plan_id": id, "outputs": {"k": "v"} })).await.unwrap();
    assert_eq!(c2["seq"], 2);

    let latest = reg.call(&hub, &me, "plan_resume", json!({ "plan_id": id })).await.unwrap();
    assert_eq!(latest["checkpoint"]["seq"], 2);
    assert_eq!(latest["checkpoint"]["context"]["outputs"]["k"], "v");
    assert_eq!(latest["checkpoint"]["context"]["step_state"][0]["status"], "done");
    assert_eq!(latest["next_step_idx"], 1);

    let first =
        reg.call(&hub, &me, "plan_resume", json!({ "plan_id": id, "from_checkpoint": 1 })).await.unwrap();
    assert_eq!(first["checkpoint"]["context"]["memory_ids"], json!(["m1"]));
    let missing = reg.call(&hub, &me, "plan_resume", json!({ "plan_id": id, "from_checkpoint": 9 })).await;
    assert_eq!(missing.unwrap_err().code(), "not_found");

    let got = reg.call(&hub, &me, "plan_get", json!({ "plan_id": id })).await.unwrap();
    assert_eq!(got["checkpoints"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn retries_escalate_to_a_human() {
    let (hub, reg, me) = (hub(), builtin_registry(), agent("builder-1"));
    let id = create_chain(&reg, &hub, &me).await;
    for n in 1..=3 {
        let r = reg
            .call(
                &hub,
                &me,
                "plan_step_retry",
                json!({ "plan_id": id, "step_idx": 0, "reason": format!("try {n}") }),
            )
            .await
            .unwrap();
        assert_eq!(r["retries"], n);
        assert_eq!(r["escalated"], n == 3);
        assert_eq!(r["step"]["status"], if n == 3 { "blocked" } else { "failed" });
    }
    let got = reg.call(&hub, &me, "plan_get", json!({ "plan_id": id })).await.unwrap();
    assert_eq!(got["plan"]["status"], "blocked");
    assert_eq!(got["plan"]["needs_human"], true);
    assert!(got["steps"][0]["note"].as_str().unwrap().contains("[retry 3/3"));
    let blocked = reg.call(&hub, &me, "plan_list", json!({ "status": "blocked" })).await.unwrap();
    assert_eq!(blocked["plans"][0]["needs_human"], true);
    let empty =
        reg.call(&hub, &me, "plan_step_retry", json!({ "plan_id": id, "step_idx": 0, "reason": " " })).await;
    assert_eq!(empty.unwrap_err().code(), "invalid_argument");
}

#[tokio::test]
async fn structure_edits_keep_dependencies_and_claimed_steps() {
    let (hub, reg, me) = (hub(), builtin_registry(), agent("builder-1"));
    let id = create_chain(&reg, &hub, &me).await;
    let rev = |v: &Value| v["plan"]["revision"].as_i64().unwrap();

    let got = reg.call(&hub, &me, "plan_get", json!({ "plan_id": id })).await.unwrap();
    let r0 = rev(&got);
    let step0_id = got["steps"][0]["id"].as_i64().unwrap();

    // Insert at the front: every index and dependency moves by one.
    let added = manage(
        &reg,
        &hub,
        &me,
        "step_add",
        json!({ "plan_id": id, "description": "prepare", "position": 0, "expected_revision": r0 }),
    )
    .await
    .unwrap();
    assert_eq!(added["step"]["step_idx"], 0);
    assert_eq!(added["steps"][3]["depends_on"], json!([1, 2]));
    assert_eq!(added["steps"][1]["id"], step0_id);
    let r1 = rev(&added);
    assert!(r1 > r0);

    // A stale revision is a conflict and writes nothing.
    let stale = manage(
        &reg,
        &hub,
        &me,
        "step_edit",
        json!({ "plan_id": id, "step_idx": 0, "description": "x", "expected_revision": r0 }),
    )
    .await
    .unwrap_err();
    assert_eq!(stale.code(), "conflict");

    // An index-addressed write that names a moved step is a conflict.
    let moved = reg
        .call(
            &hub,
            &me,
            "plan_update",
            json!({ "plan_id": id, "step_idx": 0, "note": "n", "expected_step_id": step0_id }),
        )
        .await
        .unwrap_err();
    assert_eq!(moved.code(), "conflict");

    // A step another step depends on cannot be removed.
    let dep =
        manage(&reg, &hub, &me, "step_remove", json!({ "plan_id": id, "step_idx": 1 })).await.unwrap_err();
    assert!(dep.to_string().contains("depends on it"), "{dep}");

    // A reorder that moves a step ahead of its dependency is refused.
    let ahead = manage(&reg, &hub, &me, "step_reorder", json!({ "plan_id": id, "order": [0, 3, 1, 2] }))
        .await
        .unwrap_err();
    assert_eq!(ahead.code(), "invalid_argument");
    let ok = manage(&reg, &hub, &me, "step_reorder", json!({ "plan_id": id, "order": [1, 0, 2, 3] }))
        .await
        .unwrap();
    assert_eq!(ok["steps"][0]["id"], step0_id);
    assert_eq!(ok["steps"][3]["depends_on"], json!([0, 2]));

    // A claimed step is never edited or renumbered.
    reg.call(&hub, &me, "plan_step_claim", json!({ "plan_id": id, "step_idx": 0 })).await.unwrap();
    let claimed =
        manage(&reg, &hub, &me, "step_edit", json!({ "plan_id": id, "step_idx": 0, "description": "x" }))
            .await
            .unwrap_err();
    assert_eq!(claimed.code(), "conflict");
    let renumber =
        manage(&reg, &hub, &me, "step_add", json!({ "plan_id": id, "description": "x", "position": 0 }))
            .await
            .unwrap_err();
    assert_eq!(renumber.code(), "conflict");

    // Removing an unclaimed tail step works.
    let removed_ok =
        manage(&reg, &hub, &me, "step_add", json!({ "plan_id": id, "description": "tail" })).await.unwrap();
    let tail = removed_ok["step"]["step_idx"].as_i64().unwrap();
    let rm =
        manage(&reg, &hub, &me, "step_remove", json!({ "plan_id": id, "step_idx": tail })).await.unwrap();
    assert_eq!(rm["removed"]["description"], "tail");

    // Title and description live in the goal.
    let e = manage(&reg, &hub, &me, "edit", json!({ "plan_id": id, "title": "New title" })).await.unwrap();
    assert_eq!(e["plan"]["title"], "New title");
    assert_eq!(e["plan"]["description"], "Read, convert, publish.");
    let e = manage(&reg, &hub, &me, "edit", json!({ "plan_id": id, "description": "" })).await.unwrap();
    assert_eq!(e["plan"]["goal"], "New title");
    let bad =
        manage(&reg, &hub, &me, "edit", json!({ "plan_id": id, "title": "two\nlines" })).await.unwrap_err();
    assert_eq!(bad.code(), "invalid_argument");
}

#[tokio::test]
async fn close_keeps_history_and_refuses_twice() {
    let (hub, reg, me) = (hub(), builtin_registry(), agent("builder-1"));
    let id = create_chain(&reg, &hub, &me).await;
    let c = manage(
        &reg,
        &hub,
        &me,
        "close",
        json!({ "plan_id": id, "reason": "superseded", "outputs": {"pr": "1"} }),
    )
    .await
    .unwrap();
    assert_eq!(c["plan"]["status"], "abandoned");
    assert_eq!(c["checkpoint"]["context"]["outputs"]["closed_as"], "abandoned");
    assert_eq!(c["checkpoint"]["context"]["outputs"]["pr"], "1");
    let again = manage(&reg, &hub, &me, "close", json!({ "plan_id": id, "reason": "x" })).await.unwrap_err();
    assert_eq!(again.code(), "conflict");
    let claim = manage(&reg, &hub, &me, "claim", json!({ "plan_id": id, "step_idx": 0 })).await.unwrap_err();
    assert_eq!(claim.code(), "conflict");
    let abandoned = reg.call(&hub, &me, "plan_list", json!({ "status": "abandoned" })).await.unwrap();
    assert_eq!(abandoned["plans"].as_array().unwrap().len(), 1);
    assert!(channels(&reg, &hub).await.iter().any(|c| c == "agent.plan.closed"));
}

#[tokio::test]
async fn manage_validates_actions_and_params() {
    let (hub, reg, me) = (hub(), builtin_registry(), agent("builder-1"));
    let err = manage(&reg, &hub, &me, "explode", json!({})).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = manage(&reg, &hub, &me, "list", json!({ "bogus": 1 })).await.unwrap_err();
    assert!(err.to_string().contains("invalid params"), "{err}");
    // Legacy names work as action aliases.
    let ok = manage(&reg, &hub, &me, "plan_list", json!({ "status": "all" })).await.unwrap();
    assert!(ok["plans"].is_array());
    for name in [
        "plan_create",
        "plan_update",
        "plan_get",
        "plan_list",
        "plan_checkpoint",
        "plan_resume",
        "plan_step_retry",
        "plan_step_claim",
        "plan_handoff",
        "plan_delete",
        "plan_manage",
    ] {
        assert!(reg.get(name).is_some(), "{name} is not registered");
    }
}
