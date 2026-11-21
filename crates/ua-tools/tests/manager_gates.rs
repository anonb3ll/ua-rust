//! A gate on a tool's name holds however its action is reached: through the
//! standalone tool, or through a consolidated tool (`plan_manage`,
//! `delegation_manage`, ...) whose action runs the same handler. An action
//! with no standalone tool is gated as `tool:action`. See `ua_tools::routes`.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{ApprovalRequest, Hub, Registry, builtin_registry};

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

struct Env {
    _dir: tempfile::TempDir,
    hub: Hub,
    reg: Registry,
}

fn env(policy: Option<&str>, tweak: impl FnOnce(&mut Config)) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.human_identities = vec!["operator".into()];
    if let Some(yaml) = policy {
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, yaml).unwrap();
        cfg.policy_file = Some(path);
    }
    tweak(&mut cfg);
    let hub = Hub::in_memory(cfg).unwrap();
    Env { _dir: dir, hub, reg: builtin_registry() }
}

fn agent(label: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

fn dev() -> Caller {
    agent("builder-1", Profile::Developer)
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, ..agent("operator", Profile::Operator) }
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    }
}

fn pending(e: UaError) -> (String, i64) {
    match e {
        UaError::ApprovalRequired { tool, approval_id } => (tool, approval_id),
        other => panic!("expected a pending approval, got {other:?}"),
    }
}

impl Env {
    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn manage(&self, who: &Caller, tool: &str, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, tool, json!({ "action": action, "params": params })).await
    }

    async fn approve(&self, id: i64) {
        self.call(&human(), "approval_resolve", json!({ "id": id, "decision": "approve" })).await.unwrap();
    }

    async fn plan(&self, who: &Caller) -> String {
        let out = self.call(who, "plan_create", json!({ "goal": "g", "steps": ["a"] })).await.unwrap();
        out["plan_id"].as_str().unwrap().to_string()
    }

    fn approvals(&self) -> Vec<(String, String, String)> {
        self.hub
            .db()
            .read(|c| {
                let mut st = c.prepare("SELECT tool, payload, status FROM approvals ORDER BY id")?;
                let rows = st
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .unwrap()
    }

    fn tool_calls(&self) -> Vec<(String, Option<String>, String)> {
        self.hub
            .db()
            .read(|c| {
                let mut st = c.prepare("SELECT tool, action_tool, outcome FROM tool_calls ORDER BY id")?;
                let rows = st
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .unwrap()
    }

    async fn events(&self, channel: &str) -> Vec<Value> {
        let out = self
            .call(&human(), "event_log_query", json!({ "channels": [channel], "limit": 200 }))
            .await
            .unwrap();
        out["events"].as_array().cloned().unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// approval_tools

#[tokio::test]
async fn approval_tools_on_the_standalone_name_gates_the_manager_action() {
    let e = env(None, |c| c.approval_tools = vec!["plan_delete".into()]);
    let me = dev();
    let (a, b) = (e.plan(&me).await, e.plan(&me).await);

    // Through the manager the delete parks under the standalone name.
    let (tool, id) =
        pending(e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap_err());
    assert_eq!(tool, "plan_delete");
    // The approval binds what a direct plan_delete call binds.
    let rows = e.approvals();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "plan_delete");
    assert_eq!(rows[0].1, format!("{{\"plan_id\":\"{a}\"}}"));

    e.approve(id).await;
    let out = e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap();
    assert_eq!(out["deleted"], true);
    // One pass, one call.
    let again = e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap_err();
    assert_eq!(again.code(), "approval_required");
    // A different plan needs its own approval.
    let (tool, _) =
        pending(e.manage(&me, "plan_manage", "delete", json!({ "plan_id": b })).await.unwrap_err());
    assert_eq!(tool, "plan_delete");
}

#[tokio::test]
async fn one_approval_serves_either_door_once() {
    let e = env(None, |c| c.approval_tools = vec!["plan_delete".into()]);
    let me = dev();
    let (a, b) = (e.plan(&me).await, e.plan(&me).await);

    // Approved for the standalone tool, run through the manager.
    let (_, id) = pending(e.call(&me, "plan_delete", json!({ "plan_id": a })).await.unwrap_err());
    e.approve(id).await;
    assert_eq!(
        e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap()["deleted"],
        true
    );
    assert_eq!(
        e.call(&me, "plan_delete", json!({ "plan_id": a })).await.unwrap_err().code(),
        "approval_required"
    );

    // Approved through the manager, run as the standalone tool.
    let (_, id) = pending(e.manage(&me, "plan_manage", "delete", json!({ "plan_id": b })).await.unwrap_err());
    e.approve(id).await;
    assert_eq!(e.call(&me, "plan_delete", json!({ "plan_id": b })).await.unwrap()["deleted"], true);
    let again = e.manage(&me, "plan_manage", "delete", json!({ "plan_id": b })).await.unwrap_err();
    assert_eq!(again.code(), "approval_required");
}

#[tokio::test]
async fn the_record_names_the_door_and_the_action() {
    let e = env(None, |c| c.approval_tools = vec!["plan_delete".into()]);
    let me = dev();
    let a = e.plan(&me).await;
    let (_, id) = pending(e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap_err());
    e.approve(id).await;
    e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap();
    e.call(&me, "plan_list", json!({})).await.unwrap();

    let calls = e.tool_calls();
    assert!(calls.contains(&("plan_manage".into(), Some("plan_delete".into()), "ok".into())), "{calls:?}");
    assert!(calls.contains(&("plan_list".into(), None, "ok".into())), "{calls:?}");

    let requested = e.events("agent.approval.requested").await;
    assert_eq!(requested[0]["payload"]["tool"], "plan_delete");
    assert_eq!(requested[0]["payload"]["via"], "plan_manage");
    let consumed = e.events("agent.approval.consumed").await;
    assert_eq!(consumed[0]["payload"]["via"], "plan_manage");
}

#[tokio::test]
async fn an_ungated_manager_action_still_runs_without_approval() {
    let e = env(None, |c| c.approval_tools = vec!["plan_delete".into()]);
    let me = dev();
    let a = e.plan(&me).await;
    e.manage(&me, "plan_manage", "get", json!({ "plan_id": a })).await.unwrap();
    e.manage(&me, "plan_manage", "list", json!({})).await.unwrap();
    e.manage(&me, "plan_manage", "close", json!({ "plan_id": a, "reason": "dropped" })).await.unwrap();
    assert!(e.approvals().is_empty());
    // Standalone calls behave as before.
    let b = e.plan(&me).await;
    assert_eq!(
        e.call(&me, "plan_delete", json!({ "plan_id": b })).await.unwrap_err().code(),
        "approval_required"
    );
}

#[tokio::test]
async fn an_own_key_gates_an_action_with_no_standalone_tool() {
    let e = env(None, |c| c.approval_tools = vec!["plan_manage:close".into()]);
    let me = dev();
    let a = e.plan(&me).await;
    let params = json!({ "plan_id": a, "reason": "dropped" });
    let (tool, id) = pending(e.manage(&me, "plan_manage", "close", params.clone()).await.unwrap_err());
    assert_eq!(tool, "plan_manage:close");
    // Other actions of the same tool are not gated by it.
    e.manage(&me, "plan_manage", "edit", json!({ "plan_id": a, "title": "t" })).await.unwrap();
    e.approve(id).await;
    let out = e.manage(&me, "plan_manage", "close", params.clone()).await.unwrap();
    assert_eq!(out["plan"]["status"], "abandoned");
    let calls = e.tool_calls();
    assert!(
        calls.contains(&("plan_manage".into(), Some("plan_manage:close".into()), "ok".into())),
        "{calls:?}"
    );
}

#[tokio::test]
async fn gating_the_manager_and_the_action_asks_once() {
    let e = env(None, |c| c.approval_tools = vec!["plan_manage".into(), "plan_delete".into()]);
    let me = dev();
    let a = e.plan(&me).await;
    let (tool, id) =
        pending(e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap_err());
    assert_eq!(tool, "plan_delete");
    e.approve(id).await;
    assert_eq!(
        e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap()["deleted"],
        true
    );
    assert_eq!(e.approvals().len(), 1);
    // The manager's own gate still holds for every other action.
    let (tool, _) = pending(e.manage(&me, "plan_manage", "list", json!({})).await.unwrap_err());
    assert_eq!(tool, "plan_manage");
}

#[tokio::test]
async fn a_delegation_through_the_manager_is_approved_once_as_delegate() {
    let e = env(None, |c| c.approval_tools = vec!["delegate".into()]);
    let me = agent("lead-1", Profile::Developer);
    let params = json!({ "task_spec": SPEC, "to_agent": "builder-1" });
    let (tool, id) = pending(e.manage(&me, "delegation_manage", "create", params.clone()).await.unwrap_err());
    assert_eq!(tool, "delegate");
    e.approve(id).await;
    let out = e.manage(&me, "delegation_manage", "create", params.clone()).await.unwrap();
    assert!(out["delegation_id"].as_i64().is_some(), "{out}");
    let rows = e.approvals();
    assert_eq!(rows.len(), 1, "one logical call, one approval: {rows:?}");
    assert_eq!(rows[0].2, "consumed");
    // The same approval would have served a direct `delegate` call.
    let (_, id) = pending(e.call(&me, "delegate", params.clone()).await.unwrap_err());
    e.approve(id).await;
    e.manage(&me, "delegation_manage", "create", params).await.unwrap();
}

#[tokio::test]
async fn a_nested_governed_call_is_gated_once() {
    let e = env(None, |c| c.approval_tools = vec!["export_migration_manifest".into()]);
    let me = agent("coord-1", Profile::Coordinator);
    let (tool, id) = pending(e.manage(&me, "export_data", "manifest", json!({})).await.unwrap_err());
    assert_eq!(tool, "export_migration_manifest");
    e.approve(id).await;
    e.manage(&me, "export_data", "manifest", json!({})).await.unwrap();
    let rows = e.approvals();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].2, "consumed");
}

#[tokio::test]
async fn a_request_ahead_binds_the_standalone_name() {
    let e = env(None, |c| c.approval_tools = vec!["plan_delete".into()]);
    let me = dev();
    let a = e.plan(&me).await;
    let args = json!({ "action": "delete", "params": { "plan_id": a } });
    let got = e.reg.approval_request(&e.hub, &me, "plan_manage", args).await.unwrap();
    assert_eq!(
        got,
        ApprovalRequest::Payload { tool: "plan_delete".into(), payload: json!({ "plan_id": a }) }
    );
    let ungated = json!({ "action": "list" });
    assert_eq!(
        e.reg.approval_request(&e.hub, &me, "plan_manage", ungated).await.unwrap(),
        ApprovalRequest::NotGated
    );
}

#[tokio::test]
async fn an_unknown_action_is_refused_before_it_runs() {
    let e = env(None, |_| {});
    let err = e.manage(&dev(), "plan_manage", "explode", json!({})).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert!(err.to_string().contains("unknown action"), "{err}");
    // A tool the profile hides still reads as hidden.
    let err = e.manage(&dev(), "relay_manage", "explode", json!({})).await.unwrap_err();
    assert_eq!(reason(&err), "profile_denied");
}

// ---------------------------------------------------------------------------
// Policy rules

/// One action per consolidated tool that runs a standalone tool's handler,
/// with arguments that pass validation.
fn standalone_cases() -> Vec<(&'static str, &'static str, Value, &'static str)> {
    vec![
        ("plan_manage", "list", json!({}), "plan_list"),
        ("delegation_manage", "list", json!({}), "delegate_list"),
        ("observability_manage", "metrics", json!({}), "metrics_snapshot"),
        ("coordination_manage", "agent_list", json!({}), "agent_list"),
        ("autonomous_cycle_manage", "list", json!({}), "autonomous_cycle_list"),
        ("export_data", "tasks", json!({ "write_to_vault": false }), "export_tasks"),
    ]
}

/// One action per consolidated tool whose actions have no standalone tool.
fn own_cases() -> Vec<(&'static str, Value)> {
    vec![
        ("config_revision_manage", json!({ "action": "list" })),
        ("relay_manage", json!({ "action": "list", "params": {} })),
        ("oauth_device_manage", json!({ "action": "list" })),
        ("mcp_gateway", json!({ "action": "list", "server": "s" })),
        ("skill_registry", json!({ "action": "list", "params": {} })),
        ("node_config", json!({ "action": "get", "node": "n" })),
        ("task_comment", json!({ "action": "list", "params": { "task_id": 1 } })),
        ("goal_manage", json!({ "action": "list", "params": {} })),
        ("plan_manage", json!({ "action": "close", "params": {} })),
        ("delegation_manage", json!({ "action": "get", "params": {} })),
        ("observability_manage", json!({ "action": "delegation_stats", "params": {} })),
        ("coordination_manage", json!({ "action": "queue_health", "params": {} })),
        ("autonomous_cycle_manage", json!({ "action": "get_for_task", "params": {} })),
    ]
}

fn rules(action: &str, names: &[String]) -> String {
    let mut y = String::from("rules:\n");
    for (i, n) in names.iter().enumerate() {
        y.push_str(&format!("  - {{name: r{i}, type: tool, tool: \"{n}\", action: {action}}}\n"));
    }
    y
}

#[tokio::test]
async fn a_policy_deny_on_the_standalone_name_holds_through_every_manager() {
    let names: Vec<String> = standalone_cases().iter().map(|c| c.3.to_string()).collect();
    let e = env(Some(&rules("deny", &names)), |_| {});
    let me = agent("coord-1", Profile::Coordinator);
    for (tool, action, params, standalone) in standalone_cases() {
        let err = e.manage(&me, tool, action, params.clone()).await.unwrap_err();
        assert_eq!(reason(&err), "policy_deny", "{tool} {action}: {err}");
        assert!(err.to_string().contains(standalone), "{err}");
        assert_eq!(reason(&e.call(&me, standalone, params).await.unwrap_err()), "policy_deny");
    }
    let decisions = e.events("agent.gateway.decision").await;
    let via_plan = decisions
        .iter()
        .find(|d| d["payload"]["tool"] == "plan_manage")
        .expect("a decision for the manager call");
    assert_eq!(via_plan["payload"]["action_tool"], "plan_list");
    assert_eq!(via_plan["payload"]["rule"], "r0");
}

#[tokio::test]
async fn a_require_approval_rule_on_the_standalone_name_holds_through_every_manager() {
    let names: Vec<String> = standalone_cases().iter().map(|c| c.3.to_string()).collect();
    let e = env(Some(&rules("require_approval", &names)), |_| {});
    let me = agent("coord-1", Profile::Coordinator);
    for (tool, action, params, standalone) in standalone_cases() {
        let err = e.manage(&me, tool, action, params.clone()).await.unwrap_err();
        let (gate, _) = pending(err);
        assert_eq!(gate, standalone, "{tool} {action}");
    }
}

#[tokio::test]
async fn a_policy_deny_on_an_own_key_holds_for_every_manager() {
    let reg = builtin_registry();
    let cases: Vec<(&str, Value)> = own_cases().into_iter().filter(|(t, _)| reg.get(t).is_some()).collect();
    let keys: Vec<String> = cases
        .iter()
        .map(|(t, a)| format!("{t}:{}", a.get("action").and_then(Value::as_str).unwrap()))
        .collect();
    let e = env(Some(&rules("deny", &keys)), |_| {});
    let me = agent("coord-1", Profile::Coordinator);
    for ((tool, args), key) in cases.into_iter().zip(&keys) {
        let err = e.call(&me, tool, args).await.unwrap_err();
        assert_eq!(reason(&err), "policy_deny", "{key}: {err}");
        assert!(err.to_string().contains(key.as_str()), "{err}");
    }
}

#[tokio::test]
async fn a_rate_limit_on_the_standalone_name_counts_manager_calls() {
    let yaml = "rules:\n  - {name: one_list, type: rate_limit, tool: plan_list, max_calls: 1, window_seconds: 60, action: deny}\n";
    let e = env(Some(yaml), |_| {});
    let me = dev();
    e.call(&me, "plan_list", json!({})).await.unwrap();
    let err = e.manage(&me, "plan_manage", "list", json!({})).await.unwrap_err();
    assert_eq!(reason(&err), "rate_limited");
    // And the other way round, for another caller.
    let other = agent("builder-2", Profile::Developer);
    e.manage(&other, "plan_manage", "list", json!({})).await.unwrap();
    assert_eq!(reason(&e.call(&other, "plan_list", json!({})).await.unwrap_err()), "rate_limited");
}

#[tokio::test]
async fn default_deny_is_held_by_the_manager_name_alone() {
    // A policy that allows plan_manage by name does not need a rule for each
    // of its actions; one that does not allow it still refuses it.
    let yaml =
        "default_action: deny\nrules:\n  - {name: plans, type: tool, tool: plan_manage, action: allow}\n";
    let e = env(Some(yaml), |_| {});
    let me = dev();
    e.manage(&me, "plan_manage", "list", json!({})).await.unwrap();
    assert_eq!(reason(&e.call(&me, "plan_list", json!({})).await.unwrap_err()), "default_deny");
    let err = e.manage(&me, "delegation_manage", "list", json!({})).await.unwrap_err();
    assert_eq!(reason(&err), "default_deny");
}

#[tokio::test]
async fn a_threshold_on_the_standalone_arguments_reads_the_params() {
    let yaml = "rules:\n  - {name: small, type: threshold, tool: agent_activity, field: limit, max: 10, action: deny}\n";
    let e = env(Some(yaml), |_| {});
    let me = dev();
    e.manage(&me, "observability_manage", "activity", json!({ "limit": 5 })).await.unwrap();
    let err = e.manage(&me, "observability_manage", "activity", json!({ "limit": 50 })).await.unwrap_err();
    assert_eq!(reason(&err), "threshold_breached");
}

// ---------------------------------------------------------------------------
// Profiles

#[tokio::test]
async fn a_profile_that_cannot_call_the_standalone_tool_cannot_run_it_through_the_manager() {
    let e = env(None, |_| {});
    // research sees plan_manage, and is granted plan actions by name.
    let r = agent("research-1", Profile::Research);
    e.manage(&r, "plan_manage", "plan_create", json!({ "goal": "g", "steps": ["a"] })).await.unwrap();
    for action in ["plan_delete", "delete", "plan_step_claim"] {
        let err = e.manage(&r, "plan_manage", action, json!({ "plan_id": "x" })).await.unwrap_err();
        assert!(matches!(reason(&err).as_str(), "action_denied" | "profile_denied"), "{action}: {err}");
    }
    // remote-assistant sees observability_manage and is granted agent_list,
    // not agent_activity.
    let ra = agent("remote-1", Profile::RemoteAssistant);
    e.manage(&ra, "observability_manage", "agent_list", json!({})).await.unwrap();
    for action in ["agent_activity", "activity"] {
        let err = e.manage(&ra, "observability_manage", action, json!({})).await.unwrap_err();
        assert!(matches!(reason(&err).as_str(), "action_denied" | "profile_denied"), "{action}: {err}");
    }
    // A developer cannot reach a migration manifest through export_data.
    let err = e.manage(&dev(), "export_data", "manifest", json!({})).await.unwrap_err();
    assert_eq!(reason(&err), "profile_denied");
}

// ---------------------------------------------------------------------------
// Validation of gate names

#[tokio::test]
async fn the_doctor_flags_an_unknown_action_key() {
    let e = env(
        Some("rules:\n  - {name: typo, type: tool, tool: \"plan_manage:delete\", action: deny}\n"),
        |c| {
            c.approval_tools =
                vec!["plan_manage:close".into(), "plan_manage:delete".into(), "goal_manage:nope".into()]
        },
    );
    let out = e.call(&agent("coord-1", Profile::Coordinator), "system_doctor", json!({})).await.unwrap();
    let find = |name: &str| -> Value {
        out["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["capability"] == name)
            .cloned()
            .unwrap_or(Value::Null)
    };
    let approvals = find("approval_gating");
    assert_eq!(approvals["status"], "DEGRADED", "{approvals}");
    let detail = approvals["detail"].as_str().unwrap();
    assert!(detail.contains("plan_manage:delete: that action is gated as plan_delete"), "{detail}");
    assert!(detail.contains("goal_manage:nope"), "{detail}");
    assert!(!detail.contains("plan_manage:close"), "{detail}");
    let policy = find("policy_file");
    assert_eq!(policy["status"], "DEGRADED", "{policy}");
    assert!(policy["detail"].as_str().unwrap().contains("gated as plan_delete"), "{policy}");
}

// ---------------------------------------------------------------------------
// Every action reaches a handler arm; calls with no action

/// Arguments every call of `tool` needs besides `action`, so a call reaches
/// the handler's dispatch.
fn base_args(tool: &str) -> Value {
    match tool {
        "mcp_gateway" => json!({ "server": "s" }),
        "node_config" => json!({ "node": "n" }),
        "config_revision_manage" | "oauth_device_manage" => json!({}),
        _ => json!({ "params": {} }),
    }
}

#[tokio::test]
async fn every_action_in_the_table_reaches_a_handler_arm() {
    // The table is each tool's dispatch list (handlers dispatch on
    // `routes::action_of`): an action listed without an arm answers
    // `routes::unhandled`, which this test refuses.
    let e = env(None, |_| {});
    let me = agent("coord-1", Profile::Coordinator);
    for m in ua_tools::routes::MANAGERS {
        if e.reg.get(m.tool).is_none() {
            continue;
        }
        for (action, _) in m.actions {
            let mut args = base_args(m.tool);
            args["action"] = json!(action);
            let call = e.call(&me, m.tool, args);
            let out = tokio::time::timeout(std::time::Duration::from_secs(20), call)
                .await
                .unwrap_or_else(|_| panic!("{}:{action} did not answer within 20s", m.tool));
            if let Err(err) = out {
                assert!(!err.to_string().contains("has no handler"), "{}:{action}: {err}", m.tool);
            }
        }
    }
}

#[tokio::test]
async fn a_call_with_no_action_is_gated_as_its_default_action() {
    // oauth_device_manage `{}` lists sessions: a rule on its `list` key must
    // hold for it, as for every tool whose action has a default.
    let defaults: Vec<(&str, &str)> = ua_tools::routes::MANAGERS
        .iter()
        .filter(|m| builtin_registry().get(m.tool).is_some())
        .filter_map(|m| m.default_action.map(|d| (m.tool, d)))
        .collect();
    assert!(defaults.contains(&("oauth_device_manage", "list")), "{defaults:?}");
    let keys: Vec<String> = defaults.iter().map(|(t, d)| format!("{t}:{d}")).collect();
    let e = env(Some(&rules("deny", &keys)), |_| {});
    let me = agent("coord-1", Profile::Coordinator);
    for (tool, default) in defaults {
        let none = e.call(&me, tool, base_args(tool)).await.unwrap_err();
        assert_eq!(reason(&none), "policy_deny", "{tool} with no action: {none}");
        let mut named = base_args(tool);
        named["action"] = json!(default);
        assert_eq!(reason(&e.call(&me, tool, named).await.unwrap_err()), "policy_deny", "{tool}");
    }
    let calls = e.tool_calls();
    assert!(calls.is_empty() || calls.iter().all(|c| c.2 != "ok"), "{calls:?}");
}

// ---------------------------------------------------------------------------
// handoff is a door to delegate

#[tokio::test]
async fn handoff_is_held_to_delegates_profile_entry() {
    let e = env(None, |_| {});
    let reviewer = agent("reviewer-1", Profile::Reviewer);
    let args = json!({ "task_spec": SPEC, "to_agent": "builder-1" });
    assert_eq!(reason(&e.call(&reviewer, "delegate", args.clone()).await.unwrap_err()), "profile_denied");
    let err = e.call(&reviewer, "handoff", args.clone()).await.unwrap_err();
    assert_eq!(reason(&err), "profile_denied", "{err}");
    // A profile that may delegate may hand off.
    let out = e.call(&agent("lead-1", Profile::Developer), "handoff", args).await.unwrap();
    assert_eq!(out["status"], "pending");
}

#[tokio::test]
async fn handoff_is_held_to_delegates_policy_rules() {
    let e = env(Some(&rules("deny", &["delegate".to_string()])), |_| {});
    let me = agent("lead-1", Profile::Developer);
    let args = json!({ "task_spec": SPEC, "to_agent": "builder-1" });
    let err = e.call(&me, "handoff", args.clone()).await.unwrap_err();
    assert_eq!(reason(&err), "policy_deny", "{err}");
    let decisions = e.events("agent.gateway.decision").await;
    let d = decisions.iter().find(|d| d["payload"]["tool"] == "handoff").expect("a decision for handoff");
    assert_eq!(d["payload"]["action_tool"], "delegate");

    let e = env(Some(&rules("require_approval", &["delegate".to_string()])), |_| {});
    let (tool, id) = pending(e.call(&me, "handoff", args.clone()).await.unwrap_err());
    assert_eq!(tool, "delegate");
    e.approve(id).await;
    assert_eq!(e.call(&me, "handoff", args.clone()).await.unwrap()["status"], "pending");
    // The approval binds what the equivalent `delegate` call binds.
    let direct = json!({ "task_spec": SPEC, "to_agent": "builder-1", "callback": "none" });
    let (_, id) = pending(e.call(&me, "delegate", direct).await.unwrap_err());
    e.approve(id).await;
    e.call(&me, "handoff", args).await.unwrap();
    assert_eq!(e.approvals().len(), 2);
}

// ---------------------------------------------------------------------------
// A misspelled key still gates; a handler's own approval is the only one

#[tokio::test]
async fn a_manager_spelling_of_a_standalone_action_gates_the_standalone_tool() {
    let e = env(None, |c| c.approval_tools = vec!["plan_manage:delete".into()]);
    let me = dev();
    let a = e.plan(&me).await;
    let (tool, _) = pending(e.call(&me, "plan_delete", json!({ "plan_id": a })).await.unwrap_err());
    assert_eq!(tool, "plan_delete");
    let (tool, _) =
        pending(e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap_err());
    assert_eq!(tool, "plan_delete");

    let e = env(Some(&rules("deny", &["plan_manage:delete".to_string()])), |_| {});
    let a = e.plan(&me).await;
    assert_eq!(
        reason(&e.call(&me, "plan_delete", json!({ "plan_id": a })).await.unwrap_err()),
        "policy_deny"
    );
    let err = e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap_err();
    assert_eq!(reason(&err), "policy_deny");
}

#[tokio::test]
async fn an_own_key_on_a_handler_gated_action_asks_once() {
    let e = env(None, |c| c.approval_tools = vec!["oauth_device_manage:revoke".into()]);
    let me = agent("coord-1", Profile::Coordinator);
    let args = json!({ "action": "revoke", "identity": "agent-x" });
    // Request-ahead agrees with the call: the handler binds the approval.
    let ahead = e.reg.approval_request(&e.hub, &me, "oauth_device_manage", args.clone()).await.unwrap();
    assert_eq!(ahead, ApprovalRequest::GatesInHandler);
    let (tool, id) = pending(e.call(&me, "oauth_device_manage", args.clone()).await.unwrap_err());
    assert_eq!(tool, "oauth_device_manage");
    e.approve(id).await;
    e.call(&me, "oauth_device_manage", args).await.unwrap();
    assert_eq!(e.approvals().len(), 1, "{:?}", e.approvals());
}

#[tokio::test]
async fn an_own_key_the_registry_binds_is_requestable() {
    let e = env(None, |c| c.approval_tools = vec!["plan_manage:close".into()]);
    let me = dev();
    let a = e.plan(&me).await;
    let args = json!({ "action": "close", "params": { "plan_id": a, "reason": "r" } });
    let ahead = e.reg.approval_request(&e.hub, &me, "plan_manage", args.clone()).await.unwrap();
    assert_eq!(ahead, ApprovalRequest::Payload { tool: "plan_manage:close".into(), payload: args });
}

// ---------------------------------------------------------------------------
// The read side

#[tokio::test]
async fn a_plan_object_read_is_held_to_plan_get() {
    let e = env(Some(&rules("deny", &["plan_get".to_string()])), |_| {});
    let me = dev();
    let a = e.plan(&me).await;
    let err = e.call(&me, "platform_object_get", json!({ "kind": "plan", "id": a })).await.unwrap_err();
    assert_eq!(reason(&err), "policy_deny", "{err}");

    let e = env(None, |c| c.approval_tools = vec!["plan_get".into()]);
    let a = e.plan(&me).await;
    let err = e.call(&me, "platform_object_get", json!({ "kind": "plan", "id": a })).await.unwrap_err();
    assert_eq!(reason(&err), "approval_required", "{err}");
    let e = env(None, |_| {});
    let a = e.plan(&me).await;
    e.call(&me, "platform_object_get", json!({ "kind": "plan", "id": a })).await.unwrap();
}

// ---------------------------------------------------------------------------
// A mapped action is the same operation as its standalone tool

/// What one hub was seeded with, for building arguments.
struct Seed {
    plan_id: String,
    delegation_id: i64,
    cycle_id: String,
}

async fn seed(e: &Env, me: &Caller) -> Seed {
    let plan = e.call(me, "plan_create", json!({ "goal": "g", "steps": ["a", "b"] })).await.unwrap();
    let lead = agent("lead-1", Profile::Developer);
    let d = e.call(&lead, "delegate", json!({ "task_spec": SPEC, "to_agent": me.label })).await.unwrap();
    let c =
        e.call(me, "autonomous_cycle_start", json!({ "agent": me.label, "max_rework": 1 })).await.unwrap();
    let cycle_id =
        c["cycle_id"].as_str().or_else(|| c["cycle"]["id"].as_str()).unwrap_or_default().to_string();
    assert!(!cycle_id.is_empty(), "{c}");
    Seed {
        plan_id: plan["plan_id"].as_str().unwrap().to_string(),
        delegation_id: d["delegation_id"].as_i64().unwrap(),
        cycle_id,
    }
}

/// Arguments for each standalone tool a consolidated action runs: a call
/// that succeeds where the seed allows, so the two doors' results compare.
fn fixture(tool: &str, s: &Seed, me: &str) -> Value {
    let (p, d, c) = (&s.plan_id, s.delegation_id, &s.cycle_id);
    match tool {
        "plan_create" => json!({ "goal": "g2", "steps": ["x"] }),
        "plan_update" => json!({ "plan_id": p, "step_idx": 0, "note": "n" }),
        "plan_get" | "plan_resume" | "plan_delete" => json!({ "plan_id": p }),
        "plan_list" => json!({ "status": "all" }),
        "plan_checkpoint" => json!({ "plan_id": p, "note": "n" }),
        "plan_step_retry" => json!({ "plan_id": p, "step_idx": 0, "reason": "r" }),
        "plan_step_claim" => json!({ "plan_id": p, "step_idx": 0 }),
        "plan_handoff" => json!({ "plan_id": p, "step_idx": 0 }),
        "delegate" => json!({ "task_spec": SPEC, "to_agent": "builder-9" }),
        "delegate_list" => json!({ "status": "all" }),
        "delegate_claim" => json!({ "id": d }),
        "delegate_release" => json!({ "id": d }),
        "delegate_cancel" => json!({ "id": d, "reason": "r" }),
        "delegation_spec_check" => json!({ "task_spec": SPEC }),
        "delegation_spec_template" => json!({}),
        "delegation_spec_build" => json!({ "objective": "o", "auto_validate": false }),
        "agent_activity" | "metrics_snapshot" | "check_anomalies" | "perf_summary" | "agent_list"
        | "agent_context" => {
            json!({})
        }
        "autonomous_cycle_start" => json!({ "agent": me, "max_rework": 1 }),
        "autonomous_cycle_get" => json!({ "cycle_id": c }),
        "autonomous_cycle_list" => json!({}),
        "autonomous_cycle_kill" => json!({ "cycle_id": c, "agent": me, "reason": "r" }),
        "autonomous_cycle_record_usage" => {
            json!({ "cycle_id": c, "agent": me, "elapsed_s": 1.0, "tokens": 1, "retries": 0, "cost_cents": 0.0 })
        }
        "autonomous_cycle_transition" => {
            json!({ "cycle_id": c, "to_state": "implement", "idempotency_key": "k-1", "agent": me })
        }
        "export_tasks" | "export_memory" | "export_journal" => json!({ "write_to_vault": false }),
        other => panic!("no fixture for {other}: add one so its mapping is checked"),
    }
}

/// A result's shape: its top-level keys, or the error code and the message
/// with the hub's own ids replaced.
fn shape(out: &Result<Value, UaError>, s: &Seed) -> String {
    match out {
        Ok(v) => match v.as_object() {
            Some(o) => format!("ok {:?}", o.keys().collect::<Vec<_>>()),
            None => format!("ok {v}"),
        },
        Err(e) => {
            let msg = e
                .to_string()
                .replace(&s.plan_id, "<plan>")
                .replace(&s.cycle_id, "<cycle>")
                .replace(&s.delegation_id.to_string(), "<delegation>");
            // The consolidated tool names the action in front of the error.
            let core = msg.rsplit(": ").next().unwrap_or(&msg).to_string();
            format!("err {} {core}", e.code())
        }
    }
}

#[tokio::test]
async fn every_mapped_action_is_the_same_operation_as_its_standalone_tool() {
    let me = agent("coord-1", Profile::Coordinator);
    for m in ua_tools::routes::MANAGERS {
        for (action, target) in m.actions {
            let ua_tools::routes::Target::Standalone(standalone) = target else { continue };
            // The same argument struct: an unknown field is refused with the
            // struct's whole field list.
            let e = env(None, |_| {});
            let probe = json!({ "__probe": true });
            let direct = e.call(&me, standalone, probe.clone()).await.unwrap_err().to_string();
            let routed = e.manage(&me, m.tool, action, probe).await.unwrap_err().to_string();
            let fields = |m: &str| m.find("unknown field").map(|i| m[i..].to_string());
            assert!(fields(&direct).is_some(), "{standalone}: {direct}");
            assert_eq!(fields(&direct), fields(&routed), "{}:{action} -> {standalone}", m.tool);

            // The same effect: each door on the same arguments in an
            // identically seeded hub answers with the same shape.
            let (a, b) = (env(None, |_| {}), env(None, |_| {}));
            let (sa, sb) = (seed(&a, &me).await, seed(&b, &me).await);
            let one = a.call(&me, standalone, fixture(standalone, &sa, &me.label)).await;
            let two = b.manage(&me, m.tool, action, fixture(standalone, &sb, &me.label)).await;
            assert_eq!(shape(&one, &sa), shape(&two, &sb), "{}:{action} -> {standalone}", m.tool);
            // And the same state afterwards.
            let after = |e: &Env| {
                e.hub
                    .db()
                    .read(|c| {
                        let n = |t: &str| -> i64 {
                            c.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap_or(-1)
                        };
                        Ok((
                            n("plans"),
                            n("plan_steps"),
                            n("delegations"),
                            n("autonomous_cycles"),
                            n("event_log"),
                        ))
                    })
                    .unwrap()
            };
            assert_eq!(after(&a), after(&b), "{}:{action} -> {standalone}: state differs", m.tool);
        }
    }
}

// ---------------------------------------------------------------------------
// An alias spelling restricts, never permits

#[tokio::test]
async fn an_allow_written_as_a_manager_spelling_opens_nothing_else() {
    // Under default deny, allows for plan_manage, plan_create and the
    // spelling plan_manage:delete: a direct plan_delete stays refused, as it
    // was before the spelling was read.
    let yaml = "default_action: deny\nrules:\n  - {name: a, type: tool, tool: plan_manage, action: allow}\n  - {name: b, type: tool, tool: plan_create, action: allow}\n  - {name: c, type: tool, tool: \"plan_manage:delete\", action: allow}\n";
    let e = env(Some(yaml), |_| {});
    let me = dev();
    let a = e.plan(&me).await;
    let err = e.call(&me, "plan_delete", json!({ "plan_id": a })).await.unwrap_err();
    assert_eq!(reason(&err), "default_deny", "{err}");
    // The manager door is allowed by its own name, as before.
    assert_eq!(
        e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap()["deleted"],
        true
    );
}

#[tokio::test]
async fn a_deny_written_either_way_holds_through_both_doors() {
    for spelling in ["plan_delete", "plan_manage:delete"] {
        let yaml = format!("rules:\n  - {{name: d, type: tool, tool: \"{spelling}\", action: deny}}\n");
        let e = env(Some(&yaml), |_| {});
        let me = dev();
        let a = e.plan(&me).await;
        let direct = e.call(&me, "plan_delete", json!({ "plan_id": a })).await.unwrap_err();
        assert_eq!(reason(&direct), "policy_deny", "{spelling}: {direct}");
        let routed = e.manage(&me, "plan_manage", "delete", json!({ "plan_id": a })).await.unwrap_err();
        assert_eq!(reason(&routed), "policy_deny", "{spelling}: {routed}");
    }
    // A require_approval spelled the manager way parks either door, and does
    // not count as a permission under default deny.
    let yaml = "default_action: deny\nrules:\n  - {name: r, type: tool, tool: \"plan_manage:delete\", action: require_approval}\n";
    let e = env(Some(yaml), |_| {});
    let me = dev();
    let err = e.call(&me, "plan_delete", json!({ "plan_id": "p" })).await.unwrap_err();
    assert_eq!(reason(&err), "default_deny", "{err}");
}

// ---------------------------------------------------------------------------
// A malformed action never reaches a handler

#[tokio::test]
async fn a_non_string_action_is_refused_before_any_handler_runs() {
    let e = env(None, |_| {});
    let me = agent("coord-1", Profile::Coordinator);
    // With a default action and without one.
    for tool in ["oauth_device_manage", "plan_manage"] {
        for bad in [json!(123), json!(false), json!({ "a": 1 }), json!(["list"])] {
            let err = e.call(&me, tool, json!({ "action": bad, "params": {} })).await.unwrap_err();
            assert_eq!(err.code(), "invalid_argument", "{tool} {bad}: {err}");
            assert!(err.to_string().contains("must be a string"), "{tool} {bad}: {err}");
        }
    }
    // A handler that ran would have recorded its call; the refusal ran none.
    assert!(e.tool_calls().is_empty(), "{:?}", e.tool_calls());
    // `null` is absent: refused where there is no default.
    let err = e.call(&me, "plan_manage", json!({ "action": null })).await.unwrap_err();
    assert!(err.to_string().contains("action is required"), "{err}");
    assert!(e.tool_calls().is_empty());
}

#[tokio::test]
async fn a_null_action_is_gated_as_the_default() {
    // route() has one rule: null is absent, so the call is gated as the
    // default action. oauth_device_manage's handler then refuses null for its
    // defaulted String action, so the call never runs, whatever the gates say.
    let e = env(Some(&rules("deny", &["oauth_device_manage:list".to_string()])), |_| {});
    let me = agent("coord-1", Profile::Coordinator);
    let err = e.call(&me, "oauth_device_manage", json!({ "action": null })).await.unwrap_err();
    assert_eq!(reason(&err), "policy_deny", "{err}");

    let e = env(None, |_| {});
    let err = e.call(&me, "oauth_device_manage", json!({ "action": null })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument", "{err}");
    let calls = e.tool_calls();
    assert_eq!(
        calls,
        vec![(
            "oauth_device_manage".into(),
            Some("oauth_device_manage:list".into()),
            "invalid_argument".into()
        )],
        "gated as the default, then refused by the handler; nothing ran"
    );
    // config_revision_manage defaults a String action the same way.
    let ok = e.call(&me, "config_revision_manage", json!({ "action": null })).await;
    assert_eq!(ok.unwrap_err().code(), "invalid_argument", "config_revision_manage refuses null too");
}

// ---------------------------------------------------------------------------
// Every door is held to its target's gates

/// Arguments a call through each door accepts; a new door needs one.
fn door_args(door: &str) -> Value {
    match door {
        "handoff" => json!({ "task_spec": SPEC, "to_agent": "builder-1" }),
        other => panic!("no arguments for door {other}: add a case so its gates are checked"),
    }
}

#[tokio::test]
async fn every_door_is_held_to_its_targets_gates() {
    let reg = builtin_registry();
    assert!(!ua_tools::routes::DOORS.is_empty());
    for d in ua_tools::routes::DOORS {
        assert!(reg.get(d.tool).is_some(), "door {} is not a tool", d.tool);
        assert!(reg.get(d.target).is_some(), "door {} targets {}, which is not a tool", d.tool, d.target);
        let me = agent("lead-1", Profile::Developer);
        let args = door_args(d.tool);

        // Policy deny and require_approval on the target name.
        let e = env(Some(&rules("deny", &[d.target.to_string()])), |_| {});
        let err = e.call(&me, d.tool, args.clone()).await.unwrap_err();
        assert_eq!(reason(&err), "policy_deny", "{} -> {}: {err}", d.tool, d.target);
        let e = env(Some(&rules("require_approval", &[d.target.to_string()])), |_| {});
        let (tool, _) = pending(e.call(&me, d.tool, args.clone()).await.unwrap_err());
        assert_eq!(tool, d.target, "{}", d.tool);

        // approval_tools on the target name, bound as the target's call.
        let e = env(None, |c| c.approval_tools = vec![d.target.to_string()]);
        let (tool, _) = pending(e.call(&me, d.tool, args.clone()).await.unwrap_err());
        assert_eq!(tool, d.target, "{}", d.tool);
        let rows = e.approvals();
        let bound: Value = serde_json::from_str(&rows[0].1).unwrap();
        assert_eq!(bound, (d.args)(&args), "{} binds the target's arguments", d.tool);

        // Every profile that sees the door but not the target is refused.
        let e = env(None, |_| {});
        for p in Profile::ALL.into_iter().filter(|p| p.assignable()) {
            if p.allows_tool(d.tool) && !p.allows_routed(d.target) {
                let err = e.call(&agent("x-1", p), d.tool, args.clone()).await.unwrap_err();
                assert_eq!(reason(&err), "profile_denied", "{} as {p}: {err}", d.tool);
            }
        }
        // And a profile that may call the target may use the door.
        e.call(&me, d.tool, args).await.unwrap();
    }
}
