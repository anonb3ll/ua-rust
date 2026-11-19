//! The dispatch family through the governed registry path: the run state
//! machine, fencing, identity binding, cancellation, lease expiry and real
//! harness spawns (unix only).

use std::time::Duration;

use serde_json::{Value, json};
use ua_core::config::HarnessConfig;
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::families::dispatch::{executor, reap_expired_leases};
use ua_tools::{Hub, Registry, builtin_registry};

struct H {
    hub: Hub,
    reg: Registry,
    dir: tempfile::TempDir,
}

fn harness(argv: &[&str], timeout_s: u64) -> HarnessConfig {
    HarnessConfig {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        timeout_s,
        ..HarnessConfig::default()
    }
}

impl H {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(f: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        cfg.harnesses.insert("env".into(), harness(&["/usr/bin/env"], 20));
        cfg.harnesses
            .insert("echo".into(), harness(&["/bin/sh", "-c", "echo ok; echo \"$1\"", "sh", "{prompt}"], 20));
        cfg.harnesses.insert("exit3".into(), harness(&["/bin/sh", "-c", "echo bad >&2; exit 3"], 20));
        cfg.harnesses.insert("sleep".into(), harness(&["/bin/sh", "-c", "exec sleep 30"], 60));
        cfg.harnesses.insert(
            "hang".into(),
            harness(&["/bin/sh", "-c", "sleep 30 & echo $! > grandchild.pid; wait"], 1),
        );
        let mut noisy = harness(&["/bin/sh", "-c", "yes | head -c 10000"], 20);
        noisy.output_cap_bytes = 100;
        cfg.harnesses.insert("noisy".into(), noisy);
        f(&mut cfg);
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), dir }
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

    /// Call an always-gated tool: park it, approve it as the operator, retry.
    async fn gated(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        let parked = self.call(who, tool, args.clone()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, .. } = parked else {
            panic!("expected an approval: {parked}")
        };
        self.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
        self.call(who, tool, args).await
    }

    async fn task(&self) -> i64 {
        let id =
            self.ok(&lead(), "task_add", json!({ "title": "Port the widget" })).await["id"].as_i64().unwrap();
        let wt = self.dir.path().join(format!("wt-{id}"));
        std::fs::create_dir_all(&wt).unwrap();
        self.sql(&format!("UPDATE tasks SET worktree_path = '{}' WHERE id = {id}", wt.display()));
        id
    }

    async fn dispatch(&self, task_id: i64, harness: Option<&str>) -> Value {
        let mut args = json!({ "task_id": task_id, "agent": "agent-1" });
        if let Some(h) = harness {
            args["harness"] = json!(h);
        }
        self.gated(&agent("agent-1"), "dispatch_task", args).await.unwrap()
    }

    /// The approval row for `id`, payload parsed.
    fn approval_payload(&self, id: i64) -> Value {
        let text = self.scalar(&format!("SELECT payload FROM approvals WHERE id = {id}"));
        serde_json::from_str(text.as_str().unwrap()).unwrap()
    }

    fn sql(&self, stmt: &str) {
        let stmt = stmt.to_string();
        self.hub
            .db()
            .write(move |tx| {
                tx.execute_batch(&stmt)?;
                Ok(())
            })
            .unwrap();
    }

    fn scalar(&self, q: &str) -> Value {
        let q = q.to_string();
        self.hub
            .db()
            .read(move |c| {
                Ok(c.query_row(&q, [], |r| {
                    Ok(match r.get_ref(0)? {
                        rusqlite::types::ValueRef::Null => Value::Null,
                        rusqlite::types::ValueRef::Integer(n) => json!(n),
                        rusqlite::types::ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
                        other => json!(format!("{other:?}")),
                    })
                })?)
            })
            .unwrap()
    }

    async fn receipt(&self, run_id: &str) -> Value {
        self.ok(&human(), "dispatch_delivery_receipt", json!({ "run_id": run_id })).await
    }

    /// Poll the receipt until `done` holds (at most 20 s).
    async fn wait_for(&self, run_id: &str, done: impl Fn(&Value) -> bool) -> Value {
        for _ in 0..200 {
            let r = self.receipt(run_id).await;
            if done(&r) {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("run {run_id} never reached the expected state: {}", self.receipt(run_id).await);
    }

    fn log(&self, receipt: &Value) -> String {
        std::fs::read_to_string(receipt["log_path"].as_str().unwrap()).unwrap()
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

fn lead() -> Caller {
    agent("lead-1")
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Operator, enforce_profile: false, ..agent("operator") }
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.to_string(),
    }
}

fn states(receipt: &Value) -> Vec<String> {
    receipt["transitions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["state"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn dispatch_task_is_always_gated_and_records_a_stub_run() {
    let h = H::new();
    let tid = h.task().await;
    let args = json!({ "task_id": tid, "agent": "agent-1" });
    let parked = h.err(&agent("agent-1"), "dispatch_task", args.clone()).await;
    assert_eq!(parked.code(), "approval_required");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM dispatch_runs"), json!(0), "nothing runs before approval");

    let run = h.dispatch(tid, None).await;
    assert_eq!(run["ok"], true);
    assert_eq!(run["state"], "launched");
    assert_eq!(run["stub"], true);
    assert_eq!(run["fence"], 1);
    let rid = run["run_id"].as_str().unwrap();
    assert!(rid.starts_with(&format!("run-{tid}-")), "{rid}");

    assert_eq!(h.scalar(&format!("SELECT claimed_by FROM tasks WHERE id = {tid}")), "agent-1");
    assert_eq!(h.scalar(&format!("SELECT current_run_id FROM tasks WHERE id = {tid}")), json!(rid));
    let r = h.receipt(rid).await;
    assert_eq!(states(&r), ["claimed", "launched"]);
    assert_eq!(r["approval_outcome"], "approved");
    assert!(r["approval_id"].is_i64(), "the consumed approval is linked to the run: {r}");
    assert_eq!(r["lease"]["active"], true);
    assert_eq!(r["terminal"], false);

    // One live run per task, refused before any approval is requested.
    let dup = h.err(&agent("agent-2"), "dispatch_task", json!({ "task_id": tid, "agent": "agent-2" })).await;
    assert!(dup.to_string().contains("task_claimed") || dup.to_string().contains("already_claimed"), "{dup}");

    // An unknown harness is refused.
    let tid2 = h.task().await;
    let bad = h
        .err(
            &agent("agent-1"),
            "dispatch_task",
            json!({ "task_id": tid2, "agent": "agent-1", "harness": "nope" }),
        )
        .await;
    assert_eq!(bad.code(), "invalid_argument");

    let list = h.ok(&human(), "dispatch_delivery_receipts_list", json!({ "task_id": tid })).await;
    assert_eq!(list["count"], 1);
    assert_eq!(list["terminal_count"], 0);
}

#[tokio::test]
async fn report_self_is_bound_to_the_run_agent() {
    let h = H::new();
    let tid = h.task().await;
    let rid = h.dispatch(tid, None).await["run_id"].as_str().unwrap().to_string();

    let wrong = h
        .err(
            &agent("agent-2"),
            "dispatch_report_self",
            json!({ "state": "finished", "run_id": rid, "evidence": "abc" }),
        )
        .await;
    assert_eq!(reason(&wrong), "identity_mismatch");

    let anon = Caller::local("agent-1", Transport::Mcp);
    let e = h
        .err(&anon, "dispatch_report_self", json!({ "state": "finished", "run_id": rid, "evidence": "x" }))
        .await;
    assert_eq!(reason(&e), "unauthenticated");

    let me = agent("agent-1");
    let e = h.err(&me, "dispatch_report_self", json!({ "state": "finished", "run_id": rid })).await;
    assert_eq!(e.code(), "invalid_argument", "finished needs evidence");
    let e = h.err(&me, "dispatch_report_self", json!({ "state": "running", "run_id": rid })).await;
    assert_eq!(e.code(), "invalid_argument", "only finished, failed or blocked");
    let e = h.err(&me, "dispatch_report_self", json!({ "state": "failed", "run_id": "run-404" })).await;
    assert_eq!(e.code(), "not_found");

    let done = h
        .ok(
            &me,
            "dispatch_report_self",
            json!({ "state": "finished", "run_id": rid, "evidence": "commit 0123abc", "usage": { "tokens": 42 } }),
        )
        .await;
    assert_eq!(done["ok"], true, "{done}");
    assert_eq!(h.scalar(&format!("SELECT status FROM tasks WHERE id = {tid}")), "done");
    assert_eq!(h.scalar(&format!("SELECT evidence_ref FROM tasks WHERE id = {tid}")), "commit 0123abc");
    assert_eq!(h.scalar(&format!("SELECT current_run_id FROM tasks WHERE id = {tid}")), Value::Null);

    let r = h.receipt(&rid).await;
    assert_eq!(r["run_state"], "finished");
    assert_eq!(r["terminal"], true);
    assert_eq!(r["final_task_state"], "done");
    assert_eq!(r["usage"]["tokens"], 42);
    let receipts = r["receipts"].as_array().unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["source"], "self_report");
    assert_eq!(receipts[0]["reported_by"], "agent-1");
    assert_eq!(receipts[0]["receipt_hash"].as_str().unwrap().len(), 64);

    // A duplicate report is information, not a second edge.
    let again = h.ok(&me, "dispatch_report_self", json!({ "state": "failed", "run_id": rid })).await;
    assert_eq!(again["ok"], false);
    assert_eq!(again["outcome"]["reason"], "already_terminal");
}

#[tokio::test]
async fn illegal_transitions_are_refused() {
    let h = H::new();
    let tid = h.task().await;
    let rid = h.dispatch(tid, None).await["run_id"].as_str().unwrap().to_string();
    let me = agent("agent-1");

    // A live run cannot be resumed.
    let e = h.gated(&me, "dispatch_resume", json!({ "run_id": rid })).await.unwrap_err();
    assert!(e.to_string().contains("already_active"), "{e}");

    h.ok(
        &me,
        "dispatch_report_self",
        json!({ "state": "blocked", "run_id": rid, "failure_reason": "needs input" }),
    )
    .await;
    // blocked is terminal for reports and cancels...
    let r = h
        .ok(&me, "dispatch_report_self", json!({ "state": "finished", "run_id": rid, "evidence": "x" }))
        .await;
    assert_eq!(r["outcome"]["reason"], "already_terminal");
    let c = h.ok(&me, "dispatch_cancel", json!({ "run_id": rid })).await;
    assert_eq!(c["ok"], false);
    assert_eq!(c["reason"], "already_terminal");
    // ...and not resumable.
    let e = h.gated(&me, "dispatch_resume", json!({ "run_id": rid })).await.unwrap_err();
    assert!(e.to_string().contains("unresumable_state_blocked"), "{e}");

    // A finished run never moves again.
    let tid2 = h.task().await;
    let rid2 = h.dispatch(tid2, None).await["run_id"].as_str().unwrap().to_string();
    h.ok(&me, "dispatch_report_self", json!({ "state": "finished", "run_id": rid2, "evidence": "pr/1" }))
        .await;
    let e = h.gated(&me, "dispatch_resume", json!({ "run_id": rid2 })).await.unwrap_err();
    assert!(e.to_string().contains("terminal_finished"), "{e}");
    assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{rid2}'")), "finished");

    // The operator-only tools refuse other profiles at the gateway.
    let e = h.err(&me, "dispatch_confirm_cancellation", json!({ "run_id": rid })).await;
    assert_eq!(reason(&e), "profile_denied");
    // An operator can close out a blocked run, never a finished one.
    let e = h.err(&human(), "dispatch_confirm_cancellation", json!({ "run_id": rid2 })).await;
    assert!(e.to_string().contains("not_reconcilable"), "{e}");
}

#[tokio::test]
async fn cancel_confirm_and_resume_under_a_new_fence() {
    let h = H::new();
    let tid = h.task().await;
    let rid = h.dispatch(tid, None).await["run_id"].as_str().unwrap().to_string();
    let me = agent("agent-1");

    // A pid this hub did not start, still alive: it must not be signalled,
    // and cessation cannot be confirmed.
    let foreign = std::process::id();
    h.sql(&format!("UPDATE dispatch_runs SET pid = {foreign} WHERE run_id = '{rid}'"));
    let e = h.err(&agent("agent-2"), "dispatch_cancel", json!({ "run_id": rid })).await;
    assert_eq!(reason(&e), "identity_mismatch");
    let c = h.ok(&me, "dispatch_cancel", json!({ "run_id": rid, "reason": "wrong branch" })).await;
    assert_eq!(c["ok"], true, "{c}");
    assert_eq!(c["state"], "cancelled");
    assert_eq!(c["termination"], "not_ours");
    assert_eq!(c["cessation"], "unknown");

    // Unconfirmed cessation keeps the slot and blocks a resume.
    let e = h.gated(&me, "dispatch_resume", json!({ "run_id": rid })).await.unwrap_err();
    assert!(e.to_string().contains("cessation_unconfirmed"), "{e}");
    let e = h.err(&me, "dispatch_task", json!({ "task_id": tid, "agent": "agent-1" })).await;
    assert!(e.to_string().contains("already_claimed"), "{e}");
    let again = h.ok(&me, "dispatch_cancel", json!({ "run_id": rid })).await;
    assert_eq!(again["reason"], "already_terminal");

    // The operator retries (still not ours), then confirms.
    let retry = h.ok(&human(), "dispatch_retry_cancellation", json!({ "run_id": rid })).await;
    assert_eq!(retry["cessation"], "unknown");
    let ok = h
        .ok(&human(), "dispatch_confirm_cancellation", json!({ "run_id": rid, "note": "host rebuilt" }))
        .await;
    assert_eq!(ok["cessation"], "confirmed");
    let e = h.err(&human(), "dispatch_confirm_cancellation", json!({ "run_id": rid })).await;
    assert!(e.to_string().contains("not_reconcilable"), "a confirmed cancellation is final: {e}");

    let resumed = h.gated(&me, "dispatch_resume", json!({ "run_id": rid })).await.unwrap();
    assert_eq!(resumed["ok"], true, "{resumed}");
    assert_eq!(resumed["fence"], 2);
    assert_eq!(resumed["state"], "launched");
    assert_eq!(h.scalar(&format!("SELECT attempt FROM dispatch_runs WHERE run_id = '{rid}'")), 2);
    assert_eq!(h.scalar(&format!("SELECT pid FROM dispatch_runs WHERE run_id = '{rid}'")), Value::Null);

    // A report from the first attempt is fenced off.
    let stale = h
        .ok(
            &me,
            "dispatch_report_self",
            json!({ "state": "finished", "run_id": rid, "evidence": "old", "fence": 1 }),
        )
        .await;
    assert_eq!(stale["ok"], false);
    assert_eq!(stale["outcome"]["reason"], "stale_fence");
    let fresh = h
        .ok(
            &me,
            "dispatch_report_self",
            json!({ "state": "finished", "run_id": rid, "evidence": "new", "fence": 2 }),
        )
        .await;
    assert_eq!(fresh["ok"], true, "{fresh}");

    let r = h.receipt(&rid).await;
    assert_eq!(
        states(&r),
        [
            "claimed",
            "launched",
            "cancel_requested",
            "cancelled",
            "cancelled",
            "cancelled",
            "resumed",
            "launched",
            "finished"
        ]
    );
    let sources: Vec<&str> =
        r["receipts"].as_array().unwrap().iter().map(|x| x["source"].as_str().unwrap()).collect();
    assert_eq!(sources, ["cancel", "operator", "operator", "self_report"]);
    assert_eq!(r["retry_count"], 1);
}

#[tokio::test]
async fn lease_expiry_hands_a_run_back() {
    let h = H::new();
    let me = agent("agent-1");

    let tid = h.task().await;
    let rid = h.dispatch(tid, None).await["run_id"].as_str().unwrap().to_string();
    let untouched = reap_expired_leases(&h.hub).unwrap();
    assert!(untouched["reclaimed"].as_array().unwrap().is_empty(), "a live lease is left alone");

    h.sql(&format!(
        "UPDATE dispatch_runs SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE run_id = '{rid}'"
    ));
    let swept = reap_expired_leases(&h.hub).unwrap();
    assert_eq!(swept["reclaimed"][0]["run_id"], json!(rid), "{swept}");
    assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{rid}'")), "retryable");
    assert_eq!(
        h.scalar(&format!("SELECT failure_reason FROM dispatch_runs WHERE run_id = '{rid}'")),
        "lease_expired"
    );
    assert_eq!(h.scalar(&format!("SELECT current_run_id FROM tasks WHERE id = {tid}")), Value::Null);

    // A late report from the expired attempt is refused; a resume takes over.
    let late =
        h.ok(&me, "dispatch_report_self", json!({ "state": "failed", "run_id": rid, "fence": 0 })).await;
    assert_eq!(late["outcome"]["reason"], "stale_fence");
    let resumed = h.gated(&me, "dispatch_resume", json!({ "run_id": rid })).await.unwrap();
    assert_eq!(resumed["fence"], 2);

    // An expired run whose recorded pid is alive but not ours fails with an
    // unknown outcome, which a resume refuses.
    let tid2 = h.task().await;
    let rid2 = h.dispatch(tid2, None).await["run_id"].as_str().unwrap().to_string();
    h.sql(&format!(
        "UPDATE dispatch_runs SET pid = {}, lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE run_id = '{rid2}'",
        std::process::id()
    ));
    let swept = reap_expired_leases(&h.hub).unwrap();
    assert_eq!(swept["failed"][0]["run_id"], json!(rid2), "{swept}");
    let e = h.gated(&me, "dispatch_resume", json!({ "run_id": rid2 })).await.unwrap_err();
    assert!(e.to_string().contains("outcome_unknown"), "{e}");

    // An unfinished cancellation is reconciled first, never reclaimed.
    let tid3 = h.task().await;
    let rid3 = h.dispatch(tid3, None).await["run_id"].as_str().unwrap().to_string();
    h.sql(&format!(
        "UPDATE dispatch_runs SET termination_outcome = 'requested', lease_expires_at = '2000-01-01T00:00:00+00:00' \
         WHERE run_id = '{rid3}'"
    ));
    let swept = reap_expired_leases(&h.hub).unwrap();
    assert_eq!(swept["reconciled"][0]["run_id"], json!(rid3), "{swept}");
    assert_eq!(swept["reconciled"][0]["cessation"], "confirmed");
    assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{rid3}'")), "cancelled");
}

fn operator_agent(label: &str) -> Caller {
    // An operator-profile agent session that does not enforce profiles (the
    // shipped operator allowlist hides dispatch_task and dispatch_cancel).
    Caller { profile: Profile::Operator, enforce_profile: false, ..agent(label) }
}

#[tokio::test]
async fn the_approval_binds_the_resolved_workdir_argv_and_prompt() {
    let h = H::new();
    let me = agent("agent-1");
    let tid = h.task().await;
    let args = json!({ "task_id": tid, "agent": "agent-1", "harness": "echo" });

    let parked = h.err(&me, "dispatch_task", args.clone()).await;
    let UaError::ApprovalRequired { approval_id, .. } = parked else { panic!("{parked}") };
    let p = h.approval_payload(approval_id);
    let wt = std::fs::canonicalize(h.dir.path().join(format!("wt-{tid}"))).unwrap();
    assert_eq!(p["workdir"], json!(wt.display().to_string()), "{p}");
    assert_eq!(p["argv"][0], "/bin/sh");
    assert_eq!(p["prompt_source"], "task");
    assert_eq!(p["prompt_sha256"].as_str().unwrap().len(), 64);
    // The approver sees the prompt the hub built from the task.
    let preview = p["prompt_text"].as_str().unwrap();
    assert!(preview.starts_with(&format!("Task #{tid}: Port the widget")), "{p}");
    assert!(preview.contains("dispatch_report_self"), "{p}");
    assert_eq!(p["prompt_bytes"], json!(preview.len()), "a short prompt is shown whole");
    assert!(p["run_id"].as_str().unwrap().starts_with(&format!("run-{tid}-")));
    assert!(p.get("passes_token_of").is_none(), "no token is passed: {p}");
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;

    // The task changes after the approval: the default prompt no longer
    // hashes to what was approved, so the pass is refused.
    h.sql(&format!("UPDATE tasks SET notes = 'also delete the backups' WHERE id = {tid}"));
    let e = h.err(&me, "dispatch_task", args.clone()).await;
    assert_eq!(reason(&e), "approval_binding_changed", "{e}");
    assert!(e.to_string().contains("prompt_sha256"), "{e}");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM dispatch_runs"), json!(0), "nothing ran");
    assert_eq!(
        h.scalar(&format!("SELECT status FROM approvals WHERE id = {approval_id}")),
        "approved",
        "the stale pass is not consumed"
    );

    // A moved worktree is caught the same way.
    let tid2 = h.task().await;
    let args2 = json!({ "task_id": tid2, "agent": "agent-1", "harness": "echo" });
    let UaError::ApprovalRequired { approval_id: a2, .. } = h.err(&me, "dispatch_task", args2.clone()).await
    else {
        panic!()
    };
    h.ok(&human(), "approval_resolve", json!({ "id": a2, "decision": "approve" })).await;
    let other = h.dir.path().join("elsewhere");
    std::fs::create_dir_all(&other).unwrap();
    h.sql(&format!("UPDATE tasks SET worktree_path = '{}' WHERE id = {tid2}", other.display()));
    let e = h.err(&me, "dispatch_task", args2).await;
    assert!(e.to_string().contains("workdir"), "{e}");

    // Approving the request for the current values lets the call run,
    // linked to that approval.
    let current = h.scalar(&format!(
        "SELECT id FROM approvals WHERE status = 'pending' AND json_extract(payload, '$.task_id') = {tid}"
    ));
    h.ok(&human(), "approval_resolve", json!({ "id": current, "decision": "approve" })).await;
    let run = h.ok(&me, "dispatch_task", args).await;
    assert_eq!(run["ok"], true, "{run}");
    let rid = run["run_id"].as_str().unwrap().to_string();
    let r = h.wait_for(&rid, |r| r["terminal"] == true).await;
    assert_eq!(r["approval_outcome"], "approved");
    let linked = r["approval_id"].as_i64().unwrap();
    assert_eq!(h.approval_payload(linked)["run_id"], json!(rid));
    assert_eq!(
        h.scalar(&format!("SELECT prompt_sha256 FROM dispatch_runs WHERE run_id = '{rid}'")),
        h.approval_payload(linked)["prompt_sha256"]
    );
}

#[tokio::test]
async fn a_task_prompt_and_an_args_prompt_are_both_shown_whole() {
    let h = H::new();
    let me = agent("agent-1");
    let tid = h.task().await;
    h.sql(&format!("UPDATE tasks SET notes = '{}' WHERE id = {tid}", "\u{e9}".repeat(3000)));
    let args = json!({ "task_id": tid, "agent": "agent-1" });
    let UaError::ApprovalRequired { approval_id, .. } = h.err(&me, "dispatch_task", args).await else {
        panic!()
    };
    let p = h.approval_payload(approval_id);
    let text = p["prompt_text"].as_str().unwrap();
    assert!(text.contains(&"\u{e9}".repeat(3000)), "nothing is cut from the approver's view: {p}");
    assert_eq!(p["prompt_bytes"], json!(text.len()), "{p}");
    assert!(p.get("prompt").is_none());

    let tid2 = h.task().await;
    let args = json!({ "task_id": tid2, "agent": "agent-1", "prompt": "do the thing" });
    let UaError::ApprovalRequired { approval_id, .. } = h.err(&me, "dispatch_task", args).await else {
        panic!()
    };
    let p = h.approval_payload(approval_id);
    assert_eq!(p["prompt"], "do the thing");
    assert_eq!(p["prompt_source"], "args");
    assert!(p.get("prompt_text").is_none() && p.get("prompt_bytes").is_none(), "{p}");
}

/// The stale-pass check reads only unexpired passes, and only the latest
/// few, inside the write transaction.
#[tokio::test]
async fn stale_pass_detection_is_bounded() {
    let h = H::new();
    let me = agent("agent-1");
    let tid = h.task().await;
    let args = json!({ "task_id": tid, "agent": "agent-1" });
    let UaError::ApprovalRequired { approval_id, .. } = h.err(&me, "dispatch_task", args.clone()).await
    else {
        panic!()
    };
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    h.sql(&format!("UPDATE tasks SET notes = 'changed' WHERE id = {tid}"));
    let e = h.err(&me, "dispatch_task", args.clone()).await;
    assert_eq!(reason(&e), "approval_binding_changed", "{e}");

    // Fifty newer passes for other calls push it out of the scan.
    let now = ua_core::time::now();
    let rows: Vec<String> = (0..50)
        .map(|i| {
            format!(
                "INSERT INTO approvals (tool, payload, requested_by, status, created_at, updated_at, resolved_at) \
                 VALUES ('dispatch_task', '{{\"task_id\":{}}}', 'agent-1', 'approved', '{now}', '{now}', '{now}');",
                10_000 + i
            )
        })
        .collect();
    h.sql(&rows.join("\n"));
    let e = h.err(&me, "dispatch_task", args.clone()).await;
    assert!(matches!(e, UaError::ApprovalRequired { .. }), "{e}");
    h.sql("DELETE FROM approvals WHERE json_extract(payload, '$.task_id') >= 10000");
    let e = h.err(&me, "dispatch_task", args.clone()).await;
    assert_eq!(reason(&e), "approval_binding_changed", "{e}");

    // An expired pass is not reported either.
    h.sql(&format!(
        "UPDATE approvals SET resolved_at = '2000-01-01T00:00:00+00:00' WHERE id = {approval_id}"
    ));
    let e = h.err(&me, "dispatch_task", args).await;
    assert!(matches!(e, UaError::ApprovalRequired { .. }), "{e}");
}

#[tokio::test]
async fn a_receipt_without_a_linked_approval_is_unlinked() {
    let h = H::new();
    let tid = h.task().await;
    let rid = h.dispatch(tid, None).await["run_id"].as_str().unwrap().to_string();
    assert_eq!(h.receipt(&rid).await["approval_outcome"], "approved");
    h.sql(&format!("UPDATE approvals SET run_id = NULL WHERE run_id = '{rid}'"));
    let r = h.receipt(&rid).await;
    assert_eq!(r["approval_outcome"], "unlinked", "{r}");
    assert_eq!(r["approval_id"], Value::Null);
    assert_eq!(r["policy_outcome"], "approved", "the claim itself happened");
}

#[tokio::test]
async fn dispatch_task_checks_the_caller_against_the_agent() {
    let h = H::with(|c| {
        let mut h = harness(&["/usr/bin/env"], 20);
        h.pass_agent_token = true;
        c.harnesses.insert("tokened".into(), h);
    });
    let tid = h.task().await;
    let args = json!({ "task_id": tid, "agent": "agent-1" });

    let anon = Caller::local("agent-1", Transport::Mcp);
    assert_eq!(reason(&h.err(&anon, "dispatch_task", args.clone()).await), "unauthenticated");
    // Another developer cannot dispatch work in agent-1's name.
    assert_eq!(reason(&h.err(&lead(), "dispatch_task", args.clone()).await), "identity_mismatch");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM approvals"), json!(0), "a refused caller requests nothing");

    // The agent itself, an operator-profile agent and a human may.
    for who in [agent("agent-1"), operator_agent("ops-1"), Caller { label: "lead-human".into(), ..human() }] {
        let e = h.err(&who, "dispatch_task", args.clone()).await;
        assert_eq!(e.code(), "approval_required", "{}: {e}", who.label);
    }

    // A harness that passes the agent's token says so on the approval.
    let tid2 = h.task().await;
    let e = h
        .err(
            &agent("agent-1"),
            "dispatch_task",
            json!({ "task_id": tid2, "agent": "agent-1", "harness": "tokened" }),
        )
        .await;
    let UaError::ApprovalRequired { approval_id, .. } = e else { panic!("{e}") };
    assert_eq!(h.approval_payload(approval_id)["passes_token_of"], "agent-1");
}

#[tokio::test]
async fn a_workdir_inside_the_hub_home_is_refused() {
    let h = H::new();
    let tid = h.task().await;
    let inside = h.hub.cfg().home.join("projects").join("x");
    std::fs::create_dir_all(&inside).unwrap();
    h.sql(&format!("UPDATE tasks SET worktree_path = '{}' WHERE id = {tid}", inside.display()));
    let e = h
        .err(
            &agent("agent-1"),
            "dispatch_task",
            json!({ "task_id": tid, "agent": "agent-1", "harness": "echo" }),
        )
        .await;
    assert_eq!(e.code(), "invalid_argument");
    assert!(e.to_string().contains("hub home"), "{e}");
}

#[cfg(unix)]
mod spawn {
    use super::*;

    #[tokio::test]
    async fn a_harness_runs_with_a_scrubbed_environment() {
        let h = H::with(|c| c.agent_tokens = Some("agent-1:tok-agent-one".to_string().into()));
        assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some(), "the test process carries cargo variables");
        let tid = h.task().await;
        let run = h.dispatch(tid, Some("env")).await;
        assert_eq!(run["ok"], true, "{run}");
        assert_eq!(run["spawned"], true);
        let rid = run["run_id"].as_str().unwrap().to_string();

        let r = h.wait_for(&rid, |r| r["terminal"] == true).await;
        assert_eq!(r["run_state"], "finished", "{r}");
        assert_eq!(r["exit"]["code"], 0);
        assert_eq!(r["final_task_state"], "done");
        assert_eq!(r["receipts"][0]["source"], "supervisor");
        assert!(r["evidence_ref"].as_str().unwrap().starts_with("run-log:"));

        let log = h.log(&r);
        let names: Vec<&str> =
            log.lines().skip(1).filter_map(|l| l.split_once('=').map(|(k, _)| k)).collect();
        let mut allowed: Vec<&str> = executor::SAFE_ENV.to_vec();
        allowed.extend(executor::BINDING_ENV);
        for n in &names {
            assert!(allowed.contains(n), "{n} reached the child");
        }
        assert!(log.contains(&format!("UA_DISPATCH_RUN_ID={rid}")));
        assert!(log.contains("UA_DISPATCH_FENCE=1"));
        assert!(log.contains("UA_AGENT_LABEL=agent-1"));
        assert!(!log.contains("CARGO_MANIFEST_DIR"));
        assert!(!log.contains("tok-agent-one"), "the agent token is passed only when the harness opts in");
    }

    #[tokio::test]
    async fn exit_codes_and_output_are_captured() {
        let h = H::new();
        let me = agent("agent-1");
        let tid = h.task().await;
        let args =
            json!({ "task_id": tid, "agent": "agent-1", "harness": "echo", "prompt": "a; rm -rf / && b" });
        let run = h.gated(&me, "dispatch_task", args).await.unwrap();
        let r = h.wait_for(run["run_id"].as_str().unwrap(), |r| r["terminal"] == true).await;
        assert_eq!(r["run_state"], "finished");
        let log = h.log(&r);
        assert!(log.contains("ok\n"), "{log}");
        assert!(log.contains("a; rm -rf / && b\n"), "the prompt is one literal argument: {log}");

        let tid = h.task().await;
        let rid = h.dispatch(tid, Some("exit3")).await["run_id"].as_str().unwrap().to_string();
        let r = h.wait_for(&rid, |r| r["terminal"] == true).await;
        assert_eq!(r["run_state"], "failed");
        assert_eq!(r["exit"]["code"], 3);
        assert_eq!(r["failure_reason"], "exit_code:3");
        assert!(h.log(&r).contains("bad"), "stderr is logged");
        assert_eq!(r["final_task_state"], "doing", "a failed run does not close the task");
        // The supervisor's report is final: a late self-report is refused.
        let late = h
            .ok(&me, "dispatch_report_self", json!({ "state": "finished", "run_id": rid, "evidence": "x" }))
            .await;
        assert_eq!(late["outcome"]["reason"], "already_terminal");

        let tid = h.task().await;
        let rid = h.dispatch(tid, Some("noisy")).await["run_id"].as_str().unwrap().to_string();
        let r = h.wait_for(&rid, |r| r["terminal"] == true).await;
        assert_eq!(r["exit"]["output_bytes"], 10000);
        assert_eq!(r["exit"]["output_truncated"], true);
        let body = h.log(&r);
        let header = body.lines().next().unwrap().len() + 1;
        assert_eq!(body.len() - header, 100, "the log keeps exactly the cap");
    }

    #[tokio::test]
    async fn a_timeout_kills_the_whole_process_group() {
        let h = H::new();
        let tid = h.task().await;
        let started = std::time::Instant::now();
        let rid = h.dispatch(tid, Some("hang")).await["run_id"].as_str().unwrap().to_string();
        let r = h.wait_for(&rid, |r| r["terminal"] == true).await;
        assert!(started.elapsed() < Duration::from_secs(15), "took {:?}", started.elapsed());
        assert_eq!(r["run_state"], "failed");
        assert_eq!(r["failure_reason"], "timeout_after_1s");
        assert_eq!(r["exit"]["timed_out"], true);
        assert_eq!(r["exit"]["signal"], 9);

        let pidfile = h.dir.path().join(format!("wt-{tid}")).join("grandchild.pid");
        let grandchild: i64 = std::fs::read_to_string(pidfile).unwrap().trim().parse().unwrap();
        let mut alive = true;
        for _ in 0..50 {
            alive = executor::pid_is_alive(Some(grandchild));
            if !alive {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!alive, "the backgrounded grandchild {grandchild} survived the timeout");
    }

    #[tokio::test]
    async fn cancel_stops_a_running_harness_and_resume_relaunches_it() {
        let h = H::new();
        let me = agent("agent-1");
        let tid = h.task().await;
        let run = h.dispatch(tid, Some("sleep")).await;
        assert_eq!(run["state"], "running", "{run}");
        let rid = run["run_id"].as_str().unwrap().to_string();
        let pid = run["pid"].as_i64().unwrap();
        assert!(executor::supervises(&rid, 1));

        let c = h.ok(&me, "dispatch_cancel", json!({ "run_id": rid })).await;
        assert_eq!(c["termination"], "killed", "{c}");
        assert_eq!(c["cessation"], "confirmed");
        let r = h.wait_for(&rid, |r| r["exit"]["signal"].is_i64()).await;
        assert_eq!(r["run_state"], "cancelled", "the supervisor's exit report does not overwrite the cancel");
        assert_eq!(r["exit"]["signal"], 9);
        assert!(!executor::pid_is_alive(Some(pid)));
        assert!(!executor::supervises(&rid, 1));

        let resumed = h.gated(&me, "dispatch_resume", json!({ "run_id": rid })).await.unwrap();
        assert_eq!(resumed["state"], "running", "{resumed}");
        assert_eq!(resumed["fence"], 2);
        let pid2 = resumed["pid"].as_i64().unwrap();
        assert_ne!(pid, pid2);
        let log = std::fs::read_to_string(resumed["log_path"].as_str().unwrap()).unwrap();
        assert!(log.contains("fence 1") && log.contains("fence 2"), "both attempts share the run log: {log}");

        // Clean up the second attempt.
        let c = h.ok(&me, "dispatch_cancel", json!({ "run_id": rid })).await;
        assert_eq!(c["cessation"], "confirmed");
        h.wait_for(&rid, |r| r["exit"]["signal"].is_i64()).await;
    }

    /// A resume relaunches under the hub's current config. The approval for
    /// it names only the run, so it must not run a harness whose argv, env
    /// allowlist or token passing differ from what the run's approval bound.
    #[tokio::test]
    async fn a_resume_refuses_a_harness_changed_since_the_approval() {
        let h = H::new();
        let me = agent("agent-1");
        let tid = h.task().await;
        let rid = h.dispatch(tid, Some("exit3")).await["run_id"].as_str().unwrap().to_string();
        assert_eq!(h.wait_for(&rid, |r| r["terminal"] == true).await["run_state"], "failed");

        // The same database under an edited harness definition (a restart
        // with a new config file).
        let mut cfg = h.hub.cfg().clone();
        let edited = cfg.harnesses.get_mut("exit3").unwrap();
        edited.argv = vec!["/bin/sh".into(), "-c".into(), "echo something else".into()];
        edited.env_allowlist = vec!["EXTRA_SECRET".into()];
        let changed = Hub::new(cfg, h.hub.db().clone());
        let args = json!({ "run_id": rid });
        let parked = h.reg.call(&changed, &me, "dispatch_resume", args.clone()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, .. } = parked else { panic!("{parked}") };
        h.reg
            .call(&changed, &human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
            .await
            .unwrap();
        let e = h.reg.call(&changed, &me, "dispatch_resume", args).await.unwrap_err();
        assert_eq!(reason(&e), "approval_binding_changed", "{e}");
        assert!(e.to_string().contains("argv") && e.to_string().contains("env_allowlist"), "{e}");
        assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{rid}'")), "failed");
        assert_eq!(h.scalar(&format!("SELECT fence FROM dispatch_runs WHERE run_id = '{rid}'")), json!(1));

        // Under the config the run was approved for, the resume goes ahead.
        let resumed = h.gated(&me, "dispatch_resume", json!({ "run_id": rid })).await.unwrap();
        assert_eq!(resumed["fence"], 2, "{resumed}");
        h.wait_for(&rid, |r| r["terminal"] == true).await;
    }

    #[tokio::test]
    async fn an_operator_cancels_another_agents_running_harness() {
        let h = H::new();
        let tid = h.task().await;
        let run = h.dispatch(tid, Some("sleep")).await;
        assert_eq!(run["state"], "running", "{run}");
        let rid = run["run_id"].as_str().unwrap().to_string();
        let pid = run["pid"].as_i64().unwrap();

        let e = h.err(&agent("agent-2"), "dispatch_cancel", json!({ "run_id": rid })).await;
        assert_eq!(reason(&e), "identity_mismatch", "a peer still cannot cancel it");

        let c = h
            .ok(&operator_agent("ops-1"), "dispatch_cancel", json!({ "run_id": rid, "reason": "runaway" }))
            .await;
        assert_eq!(c["ok"], true, "{c}");
        assert_eq!(c["termination"], "killed");
        assert_eq!(c["cessation"], "confirmed");
        assert_eq!(c["cancelled_by"], "ops-1");
        let r = h.wait_for(&rid, |r| r["exit"]["signal"].is_i64()).await;
        assert_eq!(r["run_state"], "cancelled");
        assert_eq!(r["cancelled_by"], "ops-1");
        assert!(r["receipts"].as_array().unwrap().iter().any(|x| x["reported_by"] == "ops-1"));
        assert!(!executor::pid_is_alive(Some(pid)));

        // A human can cancel too.
        let tid2 = h.task().await;
        let rid2 = h.dispatch(tid2, Some("sleep")).await["run_id"].as_str().unwrap().to_string();
        let c = h.ok(&human(), "dispatch_cancel", json!({ "run_id": rid2 })).await;
        assert_eq!(c["cessation"], "confirmed", "{c}");
        assert_eq!(c["cancelled_by"], "operator");
        h.wait_for(&rid2, |r| r["exit"]["signal"].is_i64()).await;
    }

    #[tokio::test]
    async fn run_logs_are_private_and_a_missing_program_is_a_config_failure() {
        use std::os::unix::fs::PermissionsExt;
        let h = H::with(|c| {
            c.harnesses.insert("missing".into(), harness(&["/nonexistent/agent-cli", "{prompt}"], 5));
        });
        let tid = h.task().await;
        let rid = h.dispatch(tid, Some("echo")).await["run_id"].as_str().unwrap().to_string();
        let r = h.wait_for(&rid, |r| r["terminal"] == true).await;
        let log = std::path::PathBuf::from(r["log_path"].as_str().unwrap());
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&log), 0o600);
        assert_eq!(mode(log.parent().unwrap()), 0o700);

        let tid = h.task().await;
        let run = h.dispatch(tid, Some("missing")).await;
        assert_eq!(run["ok"], false, "{run}");
        assert_eq!(run["reason"], "launch_failed");
        let rid = run["run_id"].as_str().unwrap();
        assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{rid}'")), "failed");
        assert_eq!(
            h.scalar(&format!("SELECT failure_class FROM dispatch_runs WHERE run_id = '{rid}'")),
            "config"
        );
    }

    /// A process group standing in for a harness an earlier hub process
    /// launched: `/bin/sh -c script` leads a new group. A thread reaps the
    /// leader when it exits, as init does once that hub is gone. Returns the
    /// leader's pid and start time, its stdin, and its stdout lines.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn spawn_group(
        script: &str,
    ) -> (i64, i64, std::process::ChildStdin, std::io::Lines<std::io::BufReader<std::process::ChildStdout>>)
    {
        use std::io::BufRead;
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = i64::from(child.id());
        let start = executor::proc_identity(pid).expect("the leader is running").start_time;
        let stdin = child.stdin.take().unwrap();
        let lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        (pid, start, stdin, lines)
    }

    /// Point a stub run at a recorded child and its supervising hub process,
    /// and let its lease run out.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn record_child(h: &H, rid: &str, pid: i64, start: i64, supervisor: (i64, i64)) {
        h.sql(&format!(
            "UPDATE dispatch_runs SET pid = {pid}, pgid = {pid}, pid_start_time = {start}, \
             supervisor_pid = {}, supervisor_start_time = {}, \
             lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE run_id = '{rid}'",
            supervisor.0, supervisor.1
        ));
    }

    /// A supervisor identity that is proven gone: this process's pid with a
    /// start time it never had (the pid was reused).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn gone_supervisor() -> (i64, i64) {
        (i64::from(std::process::id()), 1)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn wait_dead(pid: i64) -> bool {
        for _ in 0..50 {
            if !executor::pid_is_alive(Some(pid)) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    /// The launch records what the orphan proof needs: the child's pid,
    /// group and start time, and the supervising hub process.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn a_launch_records_the_child_identity() {
        let h = H::new();
        let tid = h.task().await;
        let run = h.dispatch(tid, Some("sleep")).await;
        let rid = run["run_id"].as_str().unwrap().to_string();
        let pid = run["pid"].as_i64().unwrap();
        let col = |c: &str| h.scalar(&format!("SELECT {c} FROM dispatch_runs WHERE run_id = '{rid}'"));
        assert_eq!(col("pgid"), json!(pid));
        assert_eq!(col("pid_start_time"), json!(executor::proc_identity(pid).unwrap().start_time));
        assert_eq!(col("supervisor_pid"), json!(std::process::id()));
        assert_eq!(col("supervisor_start_time"), json!(executor::own_identity().unwrap().1));
        let c = h.ok(&agent("agent-1"), "dispatch_cancel", json!({ "run_id": rid })).await;
        assert_eq!(c["termination"], "killed");
        h.wait_for(&rid, |r| r["exit"]["signal"].is_i64()).await;
    }

    /// A restarted hub finds a run whose child is still running: it proves
    /// the pid is its orphan (start time and group match, the supervisor is
    /// gone), kills the group and hands the run back.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn the_restart_sweep_kills_a_proven_orphan() {
        let h = H::new();
        let tid = h.task().await;
        let rid = h.dispatch(tid, None).await["run_id"].as_str().unwrap().to_string();
        let (pid, start, _stdin, _out) = spawn_group("exec sleep 30");
        record_child(&h, &rid, pid, start, gone_supervisor());
        assert!(!executor::supervises(&rid, 1));

        let swept = reap_expired_leases(&h.hub).unwrap();
        assert_eq!(swept["reclaimed"][0]["run_id"], json!(rid), "{swept}");
        assert_eq!(swept["reclaimed"][0]["termination"], "killed_orphan");
        assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{rid}'")), "retryable");
        assert_eq!(
            h.scalar(&format!("SELECT failure_reason FROM dispatch_runs WHERE run_id = '{rid}'")),
            "lease_expired_orphan_killed"
        );
        assert!(wait_dead(pid).await, "the orphan {pid} survived the sweep");

        // Cessation is proven, so the run can be resumed.
        let resumed = h.gated(&agent("agent-1"), "dispatch_resume", json!({ "run_id": rid })).await.unwrap();
        assert_eq!(resumed["fence"], 2, "{resumed}");
    }

    /// The recorded leader exited but a child it forked still holds the
    /// group: the run is not reported stopped. Without proof that the
    /// supervising hub is gone nothing is signalled and the outcome is
    /// unknown; with it, the group is killed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn a_group_outliving_its_leader_is_not_already_gone() {
        let h = H::new();
        let (pid, start, stdin, mut out) =
            spawn_group("sleep 30 </dev/null >/dev/null 2>&1 & echo $!; read x; exit 0");
        let member: i64 = out.next().unwrap().unwrap().trim().parse().unwrap();
        drop(stdin);
        assert!(wait_dead(pid).await, "the leader {pid} did not exit");
        assert!(executor::pid_is_alive(Some(member)));

        // The supervisor is still alive (here: the group member itself).
        let tid = h.task().await;
        let rid = h.dispatch(tid, None).await["run_id"].as_str().unwrap().to_string();
        let live_sup = (member, executor::proc_identity(member).unwrap().start_time);
        record_child(&h, &rid, pid, start, live_sup);
        let swept = reap_expired_leases(&h.hub).unwrap();
        assert_eq!(swept["failed"][0]["run_id"], json!(rid), "{swept}");
        assert_eq!(swept["failed"][0]["termination"], "not_ours");
        assert_eq!(
            h.scalar(&format!("SELECT failure_reason FROM dispatch_runs WHERE run_id = '{rid}'")),
            "lease_expired_outcome_unknown"
        );
        assert!(executor::pid_is_alive(Some(member)), "nothing was signalled");

        // The supervisor is proven gone: the group is killed.
        let tid2 = h.task().await;
        let rid2 = h.dispatch(tid2, None).await["run_id"].as_str().unwrap().to_string();
        record_child(&h, &rid2, pid, start, gone_supervisor());
        let swept = reap_expired_leases(&h.hub).unwrap();
        assert_eq!(swept["reclaimed"][0]["run_id"], json!(rid2), "{swept}");
        assert_eq!(swept["reclaimed"][0]["termination"], "killed_orphan");
        assert!(wait_dead(member).await, "the group member {member} survived the sweep");

        // Once the group is empty the run is already gone.
        let tid3 = h.task().await;
        let rid3 = h.dispatch(tid3, None).await["run_id"].as_str().unwrap().to_string();
        record_child(&h, &rid3, pid, start, gone_supervisor());
        let swept = reap_expired_leases(&h.hub).unwrap();
        assert_eq!(swept["reclaimed"][0]["termination"], "already_gone", "{swept}");
    }

    /// A pid whose start time does not match the record was reused: the
    /// recorded child is gone, and nothing is signalled.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn a_reused_pid_is_gone_not_ours() {
        let h = H::new();
        let tid = h.task().await;
        let rid = h.dispatch(tid, None).await["run_id"].as_str().unwrap().to_string();
        let me = std::process::id();
        h.sql(&format!(
            "UPDATE dispatch_runs SET pid = {me}, pgid = {me}, pid_start_time = 1, supervisor_pid = 1, \
             supervisor_start_time = 1 WHERE run_id = '{rid}'"
        ));
        let c = h.ok(&agent("agent-1"), "dispatch_cancel", json!({ "run_id": rid })).await;
        assert_eq!(c["termination"], "already_gone", "{c}");
        assert_eq!(c["cessation"], "confirmed");
    }
}
