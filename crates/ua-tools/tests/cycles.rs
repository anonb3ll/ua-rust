//! Autonomous cycles through the governed registry path.

use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

struct H {
    hub: Hub,
    reg: Registry,
    _dir: tempfile::TempDir,
}

impl H {
    fn with(tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path());
        cfg.human_identities = vec!["operator".into()];
        cfg.autonomy_max_tokens = 1000;
        tweak(&mut cfg);
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _dir: dir }
    }

    fn new() -> Self {
        Self::with(|_| {})
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) failed: {e}"),
        }
    }

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> UaError {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => panic!("{tool}({args}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    async fn manage(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "autonomous_cycle_manage", json!({ "action": action, "params": params })).await
    }

    async fn start(&self, who: &Caller, extra: Value) -> Value {
        let mut params = json!({ "agent": who.label });
        if let (Some(p), Value::Object(e)) = (params.as_object_mut(), extra) {
            p.extend(e);
        }
        self.manage(who, "start", params).await.unwrap()["cycle"].clone()
    }

    async fn go(&self, who: &Caller, cycle: &str, to: &str, key: &str) -> Result<Value, UaError> {
        self.manage(
            who,
            "transition",
            json!({ "cycle_id": cycle, "to_state": to, "idempotency_key": key, "agent": who.label }),
        )
        .await
    }

    async fn approve(&self, id: i64) {
        self.ok(&human(), "approval_resolve", json!({ "id": id, "decision": "approve" })).await;
    }
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Operator, enforce_profile: false, ..agent("operator") }
}

fn approval_id(e: &UaError) -> i64 {
    match e {
        UaError::ApprovalRequired { approval_id, .. } => *approval_id,
        other => panic!("expected an approval, got {other}"),
    }
}

/// Walk a fresh cycle to `reviewing`.
async fn to_reviewing(h: &H, who: &Caller, cycle: &str) {
    for (i, st) in ["delegated", "executing", "validating", "reviewing"].iter().enumerate() {
        h.go(who, cycle, st, &format!("walk-{i}")).await.unwrap();
    }
}

#[tokio::test]
async fn legal_transitions_apply_and_illegal_ones_are_refused() {
    let h = H::new();
    let b = agent("builder-1");
    let cycle = h.start(&b, json!({})).await;
    let id = cycle["id"].as_str().unwrap();
    assert_eq!(cycle["state"], "plan");
    assert_eq!(cycle["version"], 0);
    assert_eq!(cycle["max_tokens"], 1000, "defaults come from the hub config");

    let e = h.go(&b, id, "executing", "k1").await.unwrap_err();
    assert_eq!(e.code(), "conflict");
    assert!(e.to_string().contains("invalid transition"), "{e}");
    let e = h.go(&b, id, "nowhere", "k1").await.unwrap_err();
    assert_eq!(e.code(), "invalid_argument");

    let out = h.go(&b, id, "delegated", "k1").await.unwrap();
    assert_eq!(out["cycle"]["state"], "delegated");
    assert_eq!(out["cycle"]["version"], 1);
    assert_eq!(out["transition"]["from_state"], "plan");

    // Stopping states need a reason; acting as someone else is refused.
    let e = h.go(&b, id, "failed", "k2").await.unwrap_err();
    assert!(e.to_string().contains("reason"), "{e}");
    let e = h
        .manage(
            &b,
            "transition",
            json!({ "cycle_id": id, "to_state": "executing", "idempotency_key": "k9", "agent": "builder-2" }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), "denied");

    // pr needs verifiable evidence.
    for (i, st) in ["executing", "validating", "reviewing"].iter().enumerate() {
        h.go(&b, id, st, &format!("w{i}")).await.unwrap();
    }
    let e = h
        .manage(&b, "transition", json!({ "cycle_id": id, "to_state": "pr", "idempotency_key": "p", "agent": "builder-1", "pr_url": "see chat" }))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("verifiable"), "{e}");

    let got = h.ok(&b, "autonomous_cycle_get", json!({ "cycle_id": id })).await;
    assert_eq!(got["transitions"].as_array().unwrap().len(), 4);
    let listed = h.ok(&b, "autonomous_cycle_list", json!({ "state": "validating" })).await;
    assert!(listed["cycles"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn idempotent_transitions_and_version_conflicts() {
    let h = H::new();
    let b = agent("builder-1");
    let id = h.start(&b, json!({})).await["id"].as_str().unwrap().to_string();
    let first = h.go(&b, &id, "delegated", "same-key").await.unwrap();
    assert_eq!(first["idempotent"], false);
    let again = h.go(&b, &id, "delegated", "same-key").await.unwrap();
    assert_eq!(again["idempotent"], true);
    assert_eq!(again["cycle"]["version"], 1, "the retry changed nothing");
    let e = h.go(&b, &id, "executing", "same-key").await.unwrap_err();
    assert!(e.to_string().contains("idempotency key"), "{e}");

    let stale = h
        .manage(&b, "transition", json!({ "cycle_id": id, "to_state": "executing", "idempotency_key": "k2", "agent": "builder-1", "expected_version": 0 }))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), "conflict");
    assert!(stale.to_string().contains("stale cycle version"), "{stale}");
    let fresh = h
        .manage(&b, "transition", json!({ "cycle_id": id, "to_state": "executing", "idempotency_key": "k2", "agent": "builder-1", "expected_version": 1 }))
        .await
        .unwrap();
    assert_eq!(fresh["cycle"]["version"], 2);
}

#[tokio::test]
async fn gated_states_wait_for_a_human_and_rework_is_bounded() {
    let h = H::new();
    let b = agent("builder-1");
    let id = h.start(&b, json!({ "max_rework": 1 })).await["id"].as_str().unwrap().to_string();
    h.go(&b, &id, "delegated", "a").await.unwrap();
    h.go(&b, &id, "executing", "b").await.unwrap();
    h.go(&b, &id, "rework", "c").await.unwrap();
    h.go(&b, &id, "executing", "d").await.unwrap();
    let blocked = h.go(&b, &id, "rework", "e").await.unwrap();
    assert_eq!(blocked["cycle"]["state"], "blocked");
    assert_eq!(blocked["cycle"]["stop_reason"], "rework budget exhausted");

    // Escalating to failed is approval-gated, then retried with the same key.
    let args = json!({ "cycle_id": id, "to_state": "failed", "idempotency_key": "f", "agent": "builder-1", "reason": "give up" });
    let e = h.manage(&b, "transition", args.clone()).await.unwrap_err();
    h.approve(approval_id(&e)).await;
    let failed = h.manage(&b, "transition", args).await.unwrap();
    assert_eq!(failed["cycle"]["state"], "failed");
    let e = h
        .err(&b, "autonomous_cycle_kill", json!({ "cycle_id": id, "agent": "builder-1", "reason": "x" }))
        .await;
    assert_eq!(e.code(), "conflict", "a terminal cycle cannot be killed");
}

#[tokio::test]
async fn pr_without_green_path_needs_approval_and_completed_too() {
    let h = H::new();
    let b = agent("builder-1");
    let id = h.start(&b, json!({})).await["id"].as_str().unwrap().to_string();
    to_reviewing(&h, &b, &id).await;
    let pr = json!({ "cycle_id": id, "to_state": "pr", "idempotency_key": "pr", "agent": "builder-1", "pr_url": "https://example.com/pr/1" });
    let e = h.manage(&b, "transition", pr.clone()).await.unwrap_err();
    h.approve(approval_id(&e)).await;
    assert_eq!(h.manage(&b, "transition", pr).await.unwrap()["cycle"]["state"], "pr");

    let verdict = h.ok(&b, "autonomous_cycle_green_path_eligibility", json!({ "cycle_id": id })).await;
    assert_eq!(verdict["eligible"], false);
    assert!(verdict["reasons"].to_string().contains("cycle has no task"), "{verdict}");
    let e = h.go(&b, &id, "completed", "done").await.unwrap_err();
    assert_eq!(e.code(), "approval_required");
}

#[tokio::test]
async fn budget_exhaustion_blocks_and_attempt_usage_is_idempotent() {
    let h = H::new();
    let b = agent("builder-1");
    let task = h.ok(&b, "task_add", json!({ "title": "Cycle work" })).await["id"].as_i64().unwrap();
    h.ok(&b, "task_claim", json!({ "id": task })).await;
    let id = h.start(&b, json!({ "task_id": task, "budgets": { "tokens": 100 } })).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let e = h
        .manage(&b, "start", json!({ "agent": "builder-1", "budgets": { "tokens": -1 } }))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("positive"), "{e}");

    let usage = |tokens: i64, key: Option<&str>| {
        let mut p = json!({ "cycle_id": id, "agent": "builder-1", "tokens": tokens });
        if let Some(k) = key {
            p["usage_run_id"] = json!("run-1");
            p["usage_id"] = json!(k);
        }
        p
    };
    let out = h.manage(&b, "record_usage", usage(60, Some("u1"))).await.unwrap();
    assert_eq!(out["blocked"], false);
    let replay = h.manage(&b, "record_usage", usage(60, Some("u1"))).await.unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["cycle"]["used_tokens"], 60, "a replay adds nothing");
    let e = h.manage(&b, "record_usage", usage(61, Some("u1"))).await.unwrap_err();
    assert_eq!(e.code(), "conflict");
    // Attempt-keyed usage belongs to the task's claimant.
    let other = agent("builder-2");
    let e = h
        .manage(&other, "record_usage", json!({ "cycle_id": id, "agent": "builder-2", "tokens": 1, "usage_run_id": "r", "usage_id": "x" }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "denied");

    let out = h.manage(&b, "record_usage", usage(50, None)).await.unwrap();
    assert_eq!(out["blocked"], true);
    assert_eq!(out["cycle"]["state"], "blocked");
    assert_eq!(out["reason"], "autonomy budget exhausted: tokens");

    let found = h.manage(&b, "get_for_task", json!({ "task_id": task })).await.unwrap();
    assert_eq!(found["cycle"]["id"], id.as_str());
}

#[tokio::test]
async fn kill_switch_stops_any_live_cycle_and_capabilities_are_checked() {
    let h = H::new();
    let b = agent("builder-1");
    let id = h.start(&b, json!({ "capabilities": ["task_list"] })).await["id"].as_str().unwrap().to_string();
    h.go(&b, &id, "delegated", "a").await.unwrap();
    h.go(&b, &id, "executing", "b").await.unwrap();
    let denied = h
        .manage(&b, "transition", json!({ "cycle_id": id, "to_state": "validating", "idempotency_key": "c", "agent": "builder-1", "capability": "run_cmd" }))
        .await
        .unwrap();
    assert_eq!(denied["cycle"]["state"], "blocked");
    assert!(denied["cycle"]["stop_reason"].as_str().unwrap().contains("capability policy denied"));

    let killed = h
        .manage(&b, "kill", json!({ "cycle_id": id, "agent": "builder-1", "reason": "operator stop" }))
        .await
        .unwrap();
    assert_eq!(killed["cycle"]["state"], "killed");
    assert_eq!(killed["killed_from"], "blocked");
    let e = h
        .manage(&b, "kill", json!({ "cycle_id": id, "agent": "builder-1", "reason": "again" }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "conflict");
    let e = h.go(&b, &id, "plan", "z").await.unwrap_err();
    assert_eq!(e.code(), "conflict");

    // A capability outside the agent's default profile starts the cycle blocked.
    let blocked = h.start(&b, json!({ "capabilities": ["notify"] })).await;
    assert_eq!(blocked["state"], "blocked");
    // A killed cycle still governs its task.
    let found = h.manage(&b, "list", json!({ "state": "killed" })).await.unwrap();
    assert_eq!(found["cycles"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn steward_profile_cannot_reach_the_cycle_manager() {
    let h = H::new();
    let s = Caller { profile: Profile::Steward, ..agent("steward-1") };
    let e = h.manage(&s, "list", json!({})).await.unwrap_err();
    assert_eq!(e.code(), "denied");
}

fn git(dir: &Path, args: &[&str]) {
    let st = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=builder", "-c", "user.email=builder@example.com"])
        .args(args)
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?}");
}

/// A repository with `main` and a task branch that changed `path`.
fn repo(path: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    git(d, &["init", "-q", "-b", "main"]);
    std::fs::write(d.join("README.md"), "base\n").unwrap();
    git(d, &["add", "."]);
    git(d, &["commit", "-qm", "base"]);
    git(d, &["checkout", "-qb", "task"]);
    let file = d.join(path);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "change\n").unwrap();
    git(d, &["add", "."]);
    git(d, &["commit", "-qm", "change"]);
    dir
}

async fn cycle_at_pr(h: &H, b: &Caller, wt: &Path) -> String {
    let task = h.ok(b, "task_add", json!({ "title": "Green" })).await["id"].as_i64().unwrap();
    h.ok(b, "task_claim", json!({ "id": task, "worktree_path": wt.to_string_lossy(), "branch": "task" }))
        .await;
    let id = h.start(b, json!({ "task_id": task })).await["id"].as_str().unwrap().to_string();
    to_reviewing(h, b, &id).await;
    let pr = json!({ "cycle_id": id, "to_state": "pr", "idempotency_key": "pr", "agent": b.label, "pr_url": "https://example.com/pr/2" });
    if let Err(e) = h.manage(b, "transition", pr.clone()).await {
        h.approve(approval_id(&e)).await;
        h.manage(b, "transition", pr).await.unwrap();
    }
    id
}

#[tokio::test]
async fn green_path_merges_without_a_human_only_when_every_check_passes() {
    if Command::new("git").arg("--version").output().is_err() {
        return;
    }
    let b = agent("builder-1");

    // No validation command configured: never eligible.
    let h = H::new();
    let wt = repo("src/lib.rs");
    let id = cycle_at_pr(&h, &b, wt.path()).await;
    let v = h.ok(&b, "autonomous_cycle_green_path_eligibility", json!({ "cycle_id": id })).await;
    assert_eq!(v["eligible"], false);
    assert!(v["reasons"].to_string().contains("no validation gates configured"), "{v}");

    // A passing validation command on a clean change: completed with no approval.
    let h = H::with(|c| c.cycle_validation_command = vec!["true".into()]);
    let id = cycle_at_pr(&h, &b, wt.path()).await;
    let v = h.ok(&b, "autonomous_cycle_green_path_eligibility", json!({ "cycle_id": id })).await;
    assert_eq!(v["eligible"], true, "{v}");
    let done = h.go(&b, &id, "completed", "merge").await.unwrap();
    assert_eq!(done["cycle"]["state"], "completed");
    assert!(done["transition"]["reason"].as_str().unwrap().starts_with("[green-path auto-merge]"));

    // A red-tier path holds for a human.
    let red = repo("deploy/unit.service");
    let id = cycle_at_pr(&h, &b, red.path()).await;
    let v = h.ok(&b, "autonomous_cycle_green_path_eligibility", json!({ "cycle_id": id })).await;
    assert!(v["reasons"].to_string().contains("red-tier"), "{v}");
    assert_eq!(h.go(&b, &id, "completed", "merge").await.unwrap_err().code(), "approval_required");

    // A failing validation command holds too.
    let h = H::with(|c| c.cycle_validation_command = vec!["false".into()]);
    let id = cycle_at_pr(&h, &b, wt.path()).await;
    let v = h.ok(&b, "autonomous_cycle_green_path_eligibility", json!({ "cycle_id": id })).await;
    assert!(v["reasons"].to_string().contains("validation gates failed"), "{v}");
}
