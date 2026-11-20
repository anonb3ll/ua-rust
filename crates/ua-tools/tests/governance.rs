//! Governance controls through the governed registry: agent lifecycle, task
//! subtree holds, operator claim release, work proposals with frozen
//! contracts, project repo bindings, the stale-worktree sweep and audit
//! triage. The one claim gate is exercised on every path that hands out
//! work: task_claim, task_update into doing, dispatch_task, node_dispatch
//! and node_claim.

use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

struct H {
    hub: Hub,
    reg: Registry,
    dir: tempfile::TempDir,
}

fn caller(label: &str, kind: ActorKind) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
    }
}

/// The node's own agent, which also claims tasks.
fn builder() -> Caller {
    caller("builder-1", ActorKind::Agent)
}

/// Another agent.
fn lead() -> Caller {
    caller("lead-1", ActorKind::Agent)
}

fn human() -> Caller {
    Caller { profile: Profile::Operator, enforce_profile: false, ..caller("operator", ActorKind::Human) }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
}

const NODE: &str = "node-a";

impl H {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        cfg.workspace = Some(dir.path().join("ws"));
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), dir }
    }

    fn ws(&self) -> std::path::PathBuf {
        self.dir.path().join("ws").canonicalize().unwrap()
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) failed: {e:?}"),
        }
    }

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> UaError {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => panic!("{tool}({args}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    async fn act(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
    }

    async fn act_ok(&self, who: &Caller, action: &str, params: Value) -> Value {
        match self.act(who, action, params.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{action}({params}) failed: {e:?}"),
        }
    }

    async fn act_err(&self, who: &Caller, action: &str, params: Value) -> UaError {
        match self.act(who, action, params.clone()).await {
            Ok(v) => panic!("{action}({params}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    /// Park the call, approve it as the operator, and retry it.
    async fn gated(&self, who: &Caller, tool: &str, args: Value) -> Value {
        let parked = self.call(who, tool, args.clone()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, .. } = parked else {
            panic!("expected an approval: {parked:?}")
        };
        self.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
        self.ok(who, tool, args).await
    }

    async fn task(&self, title: &str, parent: Option<i64>) -> i64 {
        let mut args = json!({ "title": title });
        if let Some(p) = parent {
            args["parent_id"] = json!(p);
        }
        self.ok(&lead(), "task_add", args).await["id"].as_i64().unwrap()
    }

    async fn register_node(&self) {
        self.ok(
            &builder(),
            "node_register",
            json!({ "node": NODE, "facts": {
                "backends": ["codex"],
                "worktree_roots": [{ "path": "/srv/work", "realpath": "/srv/work", "exists": true }],
            } }),
        )
        .await;
    }

    fn node_args(task_id: Option<i64>) -> Value {
        let mut a =
            json!({ "node": NODE, "backend": "codex", "prompt": "fix the build", "cwd": "/srv/work/repo" });
        if let Some(t) = task_id {
            a["task_id"] = json!(t);
        }
        a
    }

    fn sql(&self, sql: &str) {
        let sql = sql.to_string();
        self.hub.db().write(move |tx| Ok(tx.execute_batch(&sql)?)).unwrap();
    }

    fn scalar(&self, sql: &str) -> Value {
        let sql = sql.to_string();
        self.hub
            .db()
            .read(move |c| {
                Ok(c.query_row(&sql, [], |r| {
                    Ok(match r.get::<_, rusqlite::types::Value>(0)? {
                        rusqlite::types::Value::Null => Value::Null,
                        rusqlite::types::Value::Integer(i) => json!(i),
                        rusqlite::types::Value::Real(f) => json!(f),
                        rusqlite::types::Value::Text(t) => json!(t),
                        rusqlite::types::Value::Blob(_) => json!("<blob>"),
                    })
                })?)
            })
            .unwrap()
    }

    fn events(&self, channel: &str) -> i64 {
        self.scalar(&format!("SELECT COUNT(*) FROM event_log WHERE channel = '{channel}'")).as_i64().unwrap()
    }
}

// --- agent lifecycle ------------------------------------------------------------

#[tokio::test]
async fn a_paused_agent_takes_no_work_until_it_is_resumed() {
    let h = H::new();
    h.register_node().await;
    let queued = h.gated(&lead(), "node_dispatch", H::node_args(None)).await;
    let item = queued["item_id"].as_str().unwrap().to_string();
    let t = h.task("Port the widget", None).await;

    // Only an operator may pause another agent.
    let e = h.act_err(&lead(), "agent_pause", json!({ "agent": "builder-1", "reason": "x" })).await;
    assert_eq!(reason(&e), "not_own_agent");
    let e = h.act_err(&human(), "agent_pause", json!({ "agent": "builder-1" })).await;
    assert_eq!(e.code(), "invalid_argument", "a pause needs a reason");
    let paused = h.act_ok(&human(), "agent_pause", json!({ "agent": "builder-1", "reason": "audit" })).await;
    assert_eq!(paused["state"], "paused");
    assert_eq!(paused["changed"], true);
    let again = h.act_ok(&human(), "agent_pause", json!({ "agent": "builder-1", "reason": "audit" })).await;
    assert_eq!(again["changed"], false, "pausing twice is a no-op");
    assert_eq!(h.act_ok(&lead(), "agent_state", json!({ "agent": "builder-1" })).await["state"], "paused");

    // Every path that hands out work refuses it with the same code.
    let e = h.err(&builder(), "task_claim", json!({ "id": t })).await;
    assert_eq!(reason(&e), "agent_paused");
    let e = h.err(&builder(), "task_update", json!({ "id": t, "status": "doing" })).await;
    assert_eq!(reason(&e), "agent_paused");
    let e = h.err(&builder(), "dispatch_task", json!({ "task_id": t, "agent": "builder-1" })).await;
    assert_eq!(reason(&e), "agent_paused", "refused before any approval is asked for");
    let e = h.err(&lead(), "node_dispatch", H::node_args(None)).await;
    assert_eq!(reason(&e), "agent_paused", "the node's owner is paused");
    let e = h.err(&builder(), "node_claim", json!({ "node": NODE })).await;
    assert_eq!(reason(&e), "agent_paused");
    assert_eq!(
        h.scalar(&format!("SELECT status FROM node_dispatch WHERE id = '{item}'")),
        "queued",
        "queued node work waits for the resume"
    );

    // The agent cannot lift an operator's pause; an operator can.
    let e = h.act_err(&builder(), "agent_resume", json!({ "agent": "builder-1" })).await;
    assert_eq!(reason(&e), "resume_needs_operator");
    let resumed = h.act_ok(&human(), "agent_resume", json!({ "agent": "builder-1" })).await;
    assert_eq!(resumed["state"], "active");
    let claimed = h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    assert_eq!(claimed["claimed"], true);
    let got = h.ok(&builder(), "node_claim", json!({ "node": NODE })).await;
    assert_eq!(got["item"]["item_id"], item);
    assert!(h.events("agent.lifecycle") >= 2);

    // An agent may pause and resume itself.
    h.act_ok(&lead(), "agent_pause", json!({ "agent": "lead-1", "reason": "break" })).await;
    let e = h.err(&lead(), "task_claim", json!({ "id": h.task("Another", None).await })).await;
    assert_eq!(reason(&e), "agent_paused");
    h.act_ok(&lead(), "agent_resume", json!({ "agent": "lead-1" })).await;

    let states = h.act_ok(&lead(), "agent_states", json!({})).await;
    assert!(states["agents"].as_array().unwrap().iter().any(|a| a["agent"] == "builder-1"));
    assert!(states["registered"].as_array().unwrap().iter().any(|a| a["agent"] == "builder-1"));
}

#[tokio::test]
async fn terminate_releases_the_agents_doing_claims() {
    let h = H::new();
    let t = h.task("Long job", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    let out =
        h.act_ok(&human(), "agent_terminate", json!({ "agent": "builder-1", "reason": "runaway" })).await;
    assert_eq!(out["state"], "terminated");
    assert!(out["stops"].as_array().unwrap().iter().any(|s| s["control"] == "released"), "{out}");
    assert_eq!(h.scalar(&format!("SELECT status FROM tasks WHERE id = {t}")), "open");
    assert_eq!(h.scalar(&format!("SELECT claimed_by FROM tasks WHERE id = {t}")), Value::Null);
    let e = h.err(&builder(), "task_claim", json!({ "id": t })).await;
    assert_eq!(reason(&e), "agent_terminated");
    let e = h.act_err(&human(), "agent_pause", json!({ "agent": "builder-1", "reason": "x" })).await;
    assert_eq!(e.code(), "invalid_argument", "a terminated agent is resumed before a pause");
    h.ok(&lead(), "task_claim", json!({ "id": t })).await;
}

#[tokio::test]
async fn retire_is_refused_with_doing_claims_and_revokes_the_agents_tokens() {
    let h = H::new();
    let now = ua_core::time::now();
    h.sql(&format!(
        "INSERT INTO agent_tokens (agent_label, token_hash, issued_at) VALUES ('builder-1', 'aa', '{now}');
         INSERT INTO agent_tokens (agent_label, token_hash, issued_at) VALUES ('builder-1', 'bb', '{now}');
         INSERT INTO agent_tokens (agent_label, token_hash, issued_at) VALUES ('lead-1', 'cc', '{now}');"
    ));
    let t = h.task("In flight", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": t })).await;

    let e = h.act_err(&builder(), "agent_retire", json!({ "agent": "builder-1", "reason": "done" })).await;
    assert_eq!(reason(&e), "not_lifecycle_operator", "not even for its own label");
    let e = h
        .act_err(&human(), "agent_retire", json!({ "agent": "builder-1", "reason": "decommissioned" }))
        .await;
    assert_eq!(reason(&e), "agent_has_doing_claims");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM agent_tokens WHERE status = 'active'"), 3, "nothing changed");

    h.ok(&builder(), "task_update", json!({ "id": t, "status": "done" })).await;
    let out = h
        .act_ok(
            &human(),
            "agent_retire",
            json!({ "agent": "builder-1", "reason": "decommissioned", "owner": "operator" }),
        )
        .await;
    assert_eq!(out["state"], "retired");
    assert_eq!(out["owner_of_record"], "operator");
    assert_eq!(out["revoked"]["agent_tokens"].as_array().unwrap().len(), 2);
    assert_eq!(
        h.scalar("SELECT COUNT(*) FROM agent_tokens WHERE agent_label = 'builder-1' AND status = 'revoked'"),
        2
    );
    assert_eq!(h.scalar("SELECT status FROM agent_tokens WHERE agent_label = 'lead-1'"), "active");
    assert_eq!(h.events("agent.token.revoked"), 1);

    // Resume cannot undo a retirement; the retired identity takes no work.
    let e = h.act_err(&human(), "agent_resume", json!({ "agent": "builder-1" })).await;
    assert_eq!(reason(&e), "agent_retired");
    let e = h.err(&builder(), "task_claim", json!({ "id": h.task("Next", None).await })).await;
    assert_eq!(reason(&e), "agent_retired");
    let is_retired = h.hub.db().read(|c| ua_tools::families::governance::is_retired(c, "Builder-1")).unwrap();
    assert!(is_retired, "matched without regard to case");

    // Unretire is explicit and re-issues nothing.
    let out = h.act_ok(&human(), "agent_unretire", json!({ "agent": "builder-1" })).await;
    assert_eq!(out["state"], "active");
    assert_eq!(
        h.scalar("SELECT COUNT(*) FROM agent_tokens WHERE agent_label = 'builder-1' AND status = 'active'"),
        0
    );
}

// --- task holds -----------------------------------------------------------------

#[tokio::test]
async fn a_held_subtree_refuses_new_work_while_a_live_renewal_passes() {
    let h = H::new();
    h.register_node().await;
    let root = h.task("Epic", None).await;
    let child = h.task("Child", Some(root)).await;
    let grandchild = h.task("Grandchild", Some(child)).await;
    let outside = h.task("Elsewhere", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": child })).await;
    let queued = h.gated(&lead(), "node_dispatch", H::node_args(Some(grandchild))).await;
    let item = queued["item_id"].as_str().unwrap().to_string();

    let e = h.act_err(&lead(), "task_hold", json!({ "root_task_id": root })).await;
    assert_eq!(e.code(), "invalid_argument", "a hold needs a reason");
    let held = h.act_ok(&lead(), "task_hold", json!({ "root_task_id": root, "reason": "re-plan" })).await;
    assert_eq!(held["changed"], true);
    let hold_id = held["hold"]["id"].as_i64().unwrap();
    assert_eq!(held["hold"]["member_ids"], json!([root, child, grandchild]));
    let again = h.act_ok(&lead(), "task_hold", json!({ "root_task_id": root, "reason": "re-plan" })).await;
    assert_eq!(again["changed"], false, "one active hold per root");

    for (tool, args) in [
        ("task_claim", json!({ "id": grandchild })),
        ("task_update", json!({ "id": grandchild, "status": "doing" })),
        ("dispatch_task", json!({ "task_id": grandchild, "agent": "builder-1" })),
        ("node_dispatch", H::node_args(Some(grandchild))),
    ] {
        let who = if tool == "node_dispatch" { lead() } else { builder() };
        let e = h.err(&who, tool, args).await;
        assert_eq!(reason(&e), "task_held", "{tool}");
    }
    // The node skips a held item and keeps it queued.
    let got = h.ok(&builder(), "node_claim", json!({ "node": NODE })).await;
    assert_eq!(got["item"], Value::Null);
    assert_eq!(h.scalar(&format!("SELECT status FROM node_dispatch WHERE id = '{item}'")), "queued");
    // A live renewal by the current claimant passes; a task outside does too.
    let renewed = h.ok(&builder(), "task_claim", json!({ "id": child })).await;
    assert_eq!(renewed["renewal"], true);
    h.ok(&builder(), "task_claim", json!({ "id": outside })).await;
    // A takeover by another agent is not a renewal.
    h.sql(&format!("UPDATE tasks SET lock_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = {child}"));
    let e = h.err(&lead(), "task_claim", json!({ "id": child })).await;
    assert_eq!(reason(&e), "task_held");

    let list = h.act_ok(&lead(), "task_holds", json!({})).await;
    assert_eq!(list["holds"].as_array().unwrap().len(), 1);
    let got = h.act_ok(&lead(), "task_hold_get", json!({ "hold_id": hold_id })).await;
    assert_eq!(got["members"][2]["status_at_hold"], "open");

    // Only the creator or an operator releases it.
    let e = h.act_err(&builder(), "task_hold", json!({ "root_task_id": root, "mode": "resume" })).await;
    assert_eq!(reason(&e), "not_hold_owner");
    let released = h.act_ok(&lead(), "task_hold", json!({ "root_task_id": root, "mode": "resume" })).await;
    assert_eq!(released["released"], true);
    assert_eq!(released["hold"]["status"], "released");
    let got = h.ok(&builder(), "node_claim", json!({ "node": NODE })).await;
    assert_eq!(got["item"]["item_id"], item);
    h.ok(&lead(), "task_claim", json!({ "id": grandchild })).await;
    assert!(h.events("agent.task.hold") >= 2);
}

#[tokio::test]
async fn an_after_runs_finish_hold_releases_itself_when_the_subtree_goes_idle() {
    let h = H::new();
    let root = h.task("Sprint", None).await;
    let child = h.task("Running", Some(root)).await;
    let idle = h.task("Idle sprint", None).await;
    let e = h
        .act_err(
            &lead(),
            "task_hold",
            json!({ "root_task_id": idle, "reason": "x", "release_policy": "after_active_runs_finish" }),
        )
        .await;
    assert_eq!(e.code(), "invalid_argument", "nothing is running there");
    let e = h
        .act_err(
            &lead(),
            "task_hold",
            json!({ "root_task_id": root, "mode": "cancel", "reason": "x", "release_policy": "after_active_runs_finish" }),
        )
        .await;
    assert_eq!(e.code(), "invalid_argument");

    h.ok(&builder(), "task_claim", json!({ "id": child })).await;
    h.act_ok(
        &lead(),
        "task_hold",
        json!({ "root_task_id": root, "reason": "drain", "release_policy": "after_active_runs_finish" }),
    )
    .await;
    assert_eq!(h.act_ok(&lead(), "task_holds", json!({})).await["holds"].as_array().unwrap().len(), 1);
    h.ok(&builder(), "task_update", json!({ "id": child, "status": "done" })).await;
    let list = h.act_ok(&lead(), "task_holds", json!({})).await;
    assert_eq!(list["holds"].as_array().unwrap().len(), 0, "released on read: {list}");
    let all = h.act_ok(&lead(), "task_holds", json!({ "status": "all" })).await;
    assert_eq!(all["holds"][0]["released_by"], "task-hold:after_active_runs_finish");
}

#[tokio::test]
async fn a_cancel_hold_stops_member_node_work_and_restore_releases_it() {
    let h = H::new();
    h.register_node().await;
    let root = h.task("Epic", None).await;
    let child = h.task("Child", Some(root)).await;
    let queued = h.gated(&lead(), "node_dispatch", H::node_args(Some(child))).await;
    let item = queued["item_id"].as_str().unwrap().to_string();
    let out = h
        .act_ok(&lead(), "task_hold", json!({ "root_task_id": root, "mode": "cancel", "reason": "stop" }))
        .await;
    let reqs = out["cancel_requests"].as_array().unwrap();
    assert_eq!(reqs.len(), 1, "{out}");
    assert_eq!(reqs[0]["control"], "requested");
    assert_eq!(h.scalar(&format!("SELECT status FROM node_dispatch WHERE id = '{item}'")), "cancelled");
    assert_eq!(out["hold"]["cancelling"], false);
    let restored = h.act_ok(&lead(), "task_hold", json!({ "root_task_id": root, "mode": "restore" })).await;
    assert_eq!(restored["released"], true);
}

// --- claim release --------------------------------------------------------------

#[tokio::test]
async fn an_operator_claim_release_is_fenced() {
    let h = H::new();
    let t = h.task("Stuck", None).await;
    let claimed = h.ok(&builder(), "task_claim", json!({ "id": t })).await;
    let generation = claimed["claimed_at"].as_str().unwrap().to_string();

    let e = h
        .act_err(
            &lead(),
            "task_claim_release",
            json!({ "task_id": t, "expected_claimant": "builder-1", "reason": "x" }),
        )
        .await;
    assert_eq!(reason(&e), "not_lifecycle_operator");
    let e = h
        .act_err(
            &human(),
            "task_claim_release",
            json!({ "task_id": t, "expected_claimant": "lead-1", "reason": "x" }),
        )
        .await;
    assert_eq!(e.code(), "conflict", "wrong claimant");
    let e = h
        .act_err(
            &human(),
            "task_claim_release",
            json!({ "task_id": t, "expected_claimant": "builder-1", "reason": "x",
                    "expected_claimed_at": "2000-01-01T00:00:00+00:00" }),
        )
        .await;
    assert_eq!(e.code(), "conflict", "another claim generation");
    let e = h
        .act_err(
            &human(),
            "task_claim_release",
            json!({ "task_id": t, "expected_claimant": "builder-1", "reason": "x", "expected_run_id": "run-x" }),
        )
        .await;
    assert_eq!(e.code(), "conflict", "another run");
    let e = h
        .act_err(&human(), "task_claim_release", json!({ "task_id": t, "expected_claimant": "builder-1" }))
        .await;
    assert_eq!(e.code(), "invalid_argument", "a reason is required");

    let out = h
        .act_ok(
            &human(),
            "task_claim_release",
            json!({ "task_id": t, "expected_claimant": "builder-1", "reason": "hand over",
                    "expected_claimed_at": generation }),
        )
        .await;
    assert_eq!(out["task"]["status"], "open");
    assert_eq!(out["task"]["claimed_by"], Value::Null);
    assert_eq!(out["released"]["authority"], "human_operator");
    assert!(out["task"]["notes"].as_str().unwrap().contains("[claim-released]"));
    assert!(out["released"]["event_ulid"].is_string());
    h.ok(&lead(), "task_claim", json!({ "id": t })).await;

    // A finished task has no claim to transfer.
    let done = h.task("Finished", None).await;
    h.ok(&builder(), "task_claim", json!({ "id": done })).await;
    h.ok(&builder(), "task_update", json!({ "id": done, "status": "done" })).await;
    let e = h
        .act_err(
            &human(),
            "task_claim_release",
            json!({ "task_id": done, "expected_claimant": "builder-1", "reason": "x" }),
        )
        .await;
    assert_eq!(e.code(), "conflict");
}

// --- work proposals -------------------------------------------------------------

#[tokio::test]
async fn approved_proposal_items_become_tasks_whose_contract_is_rechecked_at_claim() {
    let h = H::new();
    let filed = h
        .act_ok(
            &lead(),
            "work_proposal_file",
            json!({ "title": "Hardening batch", "items": [
                { "title": "Pin the actions", "notes": "Pin every action to a SHA.",
                  "scope": { "repo": "owner/name", "files": [".github/b.yml", ".github/a.yml"] }, "priority": "high" },
                { "title": "Rotate the key" },
                { "title": "Drop the shim" },
            ] }),
        )
        .await;
    let pid = filed["proposal"]["id"].as_str().unwrap().to_string();
    assert_eq!(filed["proposal"]["status"], "pending");
    assert_eq!(filed["proposal"]["items"][0]["scope"]["files"], json!([".github/a.yml", ".github/b.yml"]));
    let e = h
        .act_err(
            &lead(),
            "work_proposal_file",
            json!({ "title": "x", "items": [{ "title": "y", "extra": 1 }] }),
        )
        .await;
    assert_eq!(e.code(), "invalid_argument", "unknown item fields are refused");
    let e = h.act_err(&lead(), "work_proposal_file", json!({ "title": "x", "items": [] })).await;
    assert_eq!(e.code(), "invalid_argument");

    // Only a human decides.
    let e = h
        .act_err(
            &lead(),
            "work_proposal_decide",
            json!({ "proposal_id": pid, "decisions": [{ "index": 0, "approve": true }] }),
        )
        .await;
    assert_eq!(reason(&e), "human_required");
    let decided = h
        .act_ok(
            &human(),
            "work_proposal_decide",
            json!({ "proposal_id": pid, "decisions": [
                { "index": 0, "approve": true },
                { "index": 1, "approve": true, "edits": { "title": "Rotate the signing key" } },
                { "index": 2, "approve": false },
            ] }),
        )
        .await;
    let items = decided["proposal"]["items"].as_array().unwrap();
    assert_eq!(decided["proposal"]["status"], "approved");
    assert_eq!(items[0]["status"], "approved");
    assert_eq!(items[1]["edited"], true);
    assert_ne!(items[1]["filed_digest"], items[1]["contract_digest"], "the edit re-froze the contract");
    assert_eq!(items[2]["status"], "rejected");
    assert_eq!(items[2]["task_id"], Value::Null);
    let t0 = items[0]["task_id"].as_i64().unwrap();
    let t1 = items[1]["task_id"].as_i64().unwrap();
    let notes0 = h.scalar(&format!("SELECT notes FROM tasks WHERE id = {t0}"));
    let digest0 = items[0]["contract_digest"].as_str().unwrap();
    assert!(notes0.as_str().unwrap().contains(&format!("[contract: {digest0}]")), "{notes0}");
    assert_eq!(h.scalar(&format!("SELECT title FROM tasks WHERE id = {t1}")), "Rotate the signing key");
    let e = h
        .act_err(
            &human(),
            "work_proposal_decide",
            json!({ "proposal_id": pid, "decisions": [{ "index": 0, "approve": true }] }),
        )
        .await;
    assert_eq!(e.code(), "conflict", "already decided");

    // The untouched task claims; a drifted one is refused.
    h.ok(&builder(), "task_claim", json!({ "id": t0 })).await;
    h.ok(&lead(), "task_update", json!({ "id": t1, "title": "Rotate whatever" })).await;
    let e = h.err(&builder(), "task_claim", json!({ "id": t1 })).await;
    assert_eq!(reason(&e), "contract_mismatch");
    h.ok(&lead(), "task_update", json!({ "id": t1, "title": "Rotate the signing key" })).await;
    h.ok(&lead(), "task_update", json!({ "id": t1, "append_note": "progress: started" })).await;
    let claimed = h.ok(&builder(), "task_claim", json!({ "id": t1 })).await;
    assert_eq!(claimed["claimed"], true, "appended lines do not break the contract");
    // A notes rewrite does.
    let t2 = {
        let p = h
            .act_ok(
                &lead(),
                "work_proposal_file",
                json!({ "title": "One more", "items": [{ "title": "Tidy", "notes": "a" }] }),
            )
            .await;
        let id = p["proposal"]["id"].as_str().unwrap().to_string();
        let d = h
            .act_ok(
                &human(),
                "work_proposal_decide",
                json!({ "proposal_id": id, "decisions": [{ "index": 0, "approve": true }] }),
            )
            .await;
        d["proposal"]["items"][0]["task_id"].as_i64().unwrap()
    };
    h.ok(&lead(), "task_update", json!({ "id": t2, "notes": "something else" })).await;
    let e = h.err(&builder(), "task_update", json!({ "id": t2, "status": "doing" })).await;
    assert_eq!(reason(&e), "contract_mismatch");

    // Withdraw: the proposer only, before any decision.
    let e = h.act_err(&lead(), "work_proposal_withdraw", json!({ "proposal_id": pid })).await;
    assert_eq!(e.code(), "conflict");
    let p = h
        .act_ok(&lead(), "work_proposal_file", json!({ "title": "Later", "items": [{ "title": "Maybe" }] }))
        .await;
    let later = p["proposal"]["id"].as_str().unwrap().to_string();
    let e = h.act_err(&builder(), "work_proposal_withdraw", json!({ "proposal_id": later })).await;
    assert_eq!(reason(&e), "not_proposer");
    let w = h
        .act_ok(&lead(), "work_proposal_withdraw", json!({ "proposal_id": later, "reason": "dropped" }))
        .await;
    assert_eq!(w["proposal"]["status"], "withdrawn");

    let list = h.act_ok(&lead(), "work_proposal_list", json!({ "proposer": "lead-1" })).await;
    assert_eq!(list["proposals"].as_array().unwrap().len(), 3);
    assert_eq!(
        h.act_ok(&lead(), "work_proposal_get", json!({ "proposal_id": pid })).await["proposal"]["id"],
        pid
    );
    let r = h.act_ok(&lead(), "work_proposal_recover", json!({ "older_than_s": 0 })).await;
    assert_eq!(r["recovered_forward"], json!([]));
    assert!(h.events("agent.work_proposal.item_approved") >= 3);
}

// --- project repo bindings ------------------------------------------------------

#[tokio::test]
async fn project_repos_bind_normalized_and_unbind() {
    let h = H::new();
    let e = h
        .act_err(&lead(), "project_repo_bind", json!({ "project": "web", "repo": "https://example.com/o/r" }))
        .await;
    assert_eq!(e.code(), "invalid_argument");
    let b = h
        .act_ok(
            &lead(),
            "project_repo_bind",
            json!({ "project": "web", "repo": "git@github.com:Owner/Web.git", "default_branch": "main" }),
        )
        .await;
    assert_eq!(b["binding"]["repo"], "owner/web");
    assert_eq!(b["binding"]["bound_by"], "lead-1");
    assert_eq!(
        h.act_ok(&lead(), "project_repo_get", json!({ "project": "web" })).await["binding"]["repo"],
        "owner/web"
    );
    h.task("Something", None).await;
    let list = h.act_ok(&lead(), "project_repo_list", json!({})).await;
    let projects: Vec<&str> =
        list["projects"].as_array().unwrap().iter().map(|p| p["project"].as_str().unwrap()).collect();
    assert_eq!(projects, ["default", "web"]);
    let u = h.act_ok(&lead(), "project_repo_unbind", json!({ "project": "web" })).await;
    assert_eq!(u["unbound"], true);
    assert_eq!(
        h.act_ok(&lead(), "project_repo_get", json!({ "project": "web" })).await["binding"],
        Value::Null
    );
    assert_eq!(h.events("project.repo.bound"), 1);
    assert_eq!(h.events("project.repo.unbound"), 1);
}

// --- stale worktrees ------------------------------------------------------------

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

#[tokio::test]
async fn stale_worktree_cleanup_dry_runs_and_keeps_anything_with_work() {
    let h = H::new();
    let ws = h.ws();
    git(&ws, &["init", "-q", "-b", "main"]);
    std::fs::write(ws.join("README.md"), "hello\n").unwrap();
    git(&ws, &["add", "README.md"]);
    git(&ws, &["commit", "-q", "-m", "init"]);
    let merged = h.task("Merged", None).await;
    let dirty = h.task("Dirty", None).await;
    let ahead = h.task("Ahead", None).await;
    let fresh = h.task("Fresh", None).await;
    for (id, branch) in [(merged, "b-merged"), (dirty, "b-dirty"), (ahead, "b-ahead"), (fresh, "b-fresh")] {
        git(&ws, &["worktree", "add", "-q", "-b", branch, &format!(".worktrees/task-{id}")]);
    }
    git(&ws, &["worktree", "add", "-q", "-b", "rel", ".worktrees/release-1"]);
    std::fs::create_dir_all(ws.join(".worktrees/scratch")).unwrap();
    std::fs::write(ws.join(format!(".worktrees/task-{dirty}/wip.txt")), "unsaved\n").unwrap();
    let ahead_dir = ws.join(format!(".worktrees/task-{ahead}"));
    std::fs::write(ahead_dir.join("new.txt"), "work\n").unwrap();
    git(&ahead_dir, &["add", "new.txt"]);
    git(&ahead_dir, &["commit", "-q", "-m", "unmerged work"]);
    h.sql(&format!("UPDATE tasks SET status = 'done' WHERE id IN ({merged}, {dirty}, {ahead})"));

    let dry = h.ok(&lead(), "cleanup_stale_worktrees", json!({})).await;
    assert_eq!(dry["dry_run"], true, "dry run is the default");
    assert_eq!(dry["cleaned_count"], 0);
    let stale: Vec<&str> =
        dry["stale_worktrees"].as_array().unwrap().iter().map(|c| c["path"].as_str().unwrap()).collect();
    assert_eq!(stale.len(), 3, "{dry}");
    assert!(stale.iter().all(|p| !p.contains("release-") && !p.contains(&format!("task-{fresh}"))));
    assert!(dry["skipped"].as_array().unwrap().iter().any(|s| s["path"] == ".worktrees/scratch"));
    for id in [merged, dirty, ahead] {
        assert!(ws.join(format!(".worktrees/task-{id}")).exists());
    }

    let real = h.ok(&lead(), "cleanup_stale_worktrees", json!({ "dry_run": false })).await;
    assert_eq!(real["cleaned_count"], 1, "{real}");
    assert!(!ws.join(format!(".worktrees/task-{merged}")).exists(), "the clean, merged one is removed");
    let retained: Vec<(String, String)> = real["retained"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (r["path"].as_str().unwrap().to_string(), r["retained_because"].as_str().unwrap().to_string())
        })
        .collect();
    assert!(retained.contains(&(format!(".worktrees/task-{dirty}"), "uncommitted_changes".into())), "{real}");
    assert!(retained.contains(&(format!(".worktrees/task-{ahead}"), "unmerged_content".into())), "{real}");
    assert!(ws.join(format!(".worktrees/task-{dirty}/wip.txt")).exists());
    assert!(ahead_dir.exists());
    assert!(ws.join(".worktrees/release-1").exists());
    assert_eq!(h.events("agent.git.worktrees_cleaned"), 1);
}

// --- audit triage ---------------------------------------------------------------

#[tokio::test]
async fn audit_triage_files_deduplicated_tasks_and_nothing_on_a_clean_audit() {
    let h = H::new();
    let ws = h.ws();
    std::fs::write(ws.join("README.md"), "# hello\n").unwrap();
    let clean = h.ok(&lead(), "audit_triage_tasks", json!({})).await;
    assert_eq!(clean["created"], 0, "{clean}");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM tasks"), 0);

    std::fs::create_dir_all(ws.join("deploy")).unwrap();
    std::fs::write(
        ws.join("deploy/id.pem"),
        "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    let dry = h.ok(&lead(), "audit_triage_tasks", json!({ "dry_run": true })).await;
    assert!(dry["created"].as_i64().unwrap() >= 1, "{dry}");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM tasks"), 0, "a dry run files nothing");
    let filed = h.ok(&lead(), "audit_triage_tasks", json!({})).await;
    let n = filed["created"].as_i64().unwrap();
    assert!(n >= 1);
    assert_eq!(h.scalar("SELECT COUNT(*) FROM tasks"), n);
    let notes = h.scalar("SELECT notes FROM tasks ORDER BY id LIMIT 1");
    assert!(notes.as_str().unwrap().starts_with("[audit-triage: "), "{notes}");
    let again = h.ok(&lead(), "audit_triage_tasks", json!({})).await;
    assert_eq!(again["created"], 0, "open tasks dedupe their groups");
    assert_eq!(again["skipped"].as_array().unwrap().len() as i64, n);

    // A closed task means addressed; closed with [accepted-risk] keeps it quiet.
    h.sql("UPDATE tasks SET status = 'done'");
    let refiled = h.ok(&lead(), "audit_triage_tasks", json!({})).await;
    assert_eq!(refiled["created"].as_i64().unwrap(), n);
    h.sql("UPDATE tasks SET status = 'done', notes = notes || char(10) || '[accepted-risk]'");
    let quiet = h.ok(&lead(), "audit_triage_tasks", json!({})).await;
    assert_eq!(quiet["created"], 0);
}

#[tokio::test]
async fn pausing_an_agent_cancels_its_live_dispatch_runs() {
    let h = H::new();
    let t = h.task("Dispatched", None).await;
    let run = h.gated(&builder(), "dispatch_task", json!({ "task_id": t, "agent": "builder-1" })).await;
    let run_id = run["run_id"].as_str().unwrap().to_string();
    let out = h.act_ok(&human(), "agent_pause", json!({ "agent": "builder-1", "reason": "audit" })).await;
    let stop = out["stops"].as_array().unwrap().iter().find(|s| s["path"] == "dispatch").cloned().unwrap();
    assert_eq!(stop["ref"], run_id);
    assert!(matches!(stop["control"].as_str(), Some("confirmed" | "requested")), "{out}");
    assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{run_id}'")), "cancelled");
    assert!(h.events("agent.lifecycle") >= 2, "the change and the stops are ledgered");
}

#[tokio::test]
async fn a_cancel_hold_cancels_member_runs_under_their_authority_and_restore_waits_for_them() {
    let h = H::new();
    let root = h.task("Epic", None).await;
    let child = h.task("Child", Some(root)).await;
    let sibling = h.task("Sibling", Some(root)).await;
    let run = h.gated(&builder(), "dispatch_task", json!({ "task_id": child, "agent": "builder-1" })).await;
    let run_id = run["run_id"].as_str().unwrap().to_string();

    // Another agent's run is not this caller's to cancel; the hold still stands.
    let out = h
        .act_ok(&lead(), "task_hold", json!({ "root_task_id": root, "mode": "cancel", "reason": "stop" }))
        .await;
    assert_eq!(out["cancel_requests"][0]["control"], "refused", "{out}");
    let e = h.err(&lead(), "task_claim", json!({ "id": sibling })).await;
    assert_eq!(reason(&e), "task_held");
    h.act_ok(&lead(), "task_hold", json!({ "root_task_id": root, "mode": "resume" })).await;

    // The run's own agent (or an operator) may.
    let out = h
        .act_ok(&builder(), "task_hold", json!({ "root_task_id": root, "mode": "cancel", "reason": "stop" }))
        .await;
    let req = &out["cancel_requests"][0];
    assert_eq!(req["ref"], run_id);
    assert!(matches!(req["control"].as_str(), Some("confirmed" | "requested")), "{out}");
    let member =
        out["hold"]["members"].as_array().unwrap().iter().find(|m| m["task_id"] == child).cloned().unwrap();
    assert_eq!(member["cancel_requested_by_hold"], true);
    assert_eq!(member["cancelled_run_id"], run_id);
    let restored =
        h.act_ok(&builder(), "task_hold", json!({ "root_task_id": root, "mode": "restore" })).await;
    assert_eq!(restored["released"], true, "{restored}");
    assert_eq!(restored["restored"][0]["control"], "closed");
}
