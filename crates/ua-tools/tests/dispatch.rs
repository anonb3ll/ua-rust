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
        self.gated(&lead(), "dispatch_task", args).await.unwrap()
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
    let parked = h.err(&lead(), "dispatch_task", args.clone()).await;
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

    // One live run per task.
    let dup =
        h.gated(&lead(), "dispatch_task", json!({ "task_id": tid, "agent": "agent-2" })).await.unwrap_err();
    assert!(dup.to_string().contains("task_claimed") || dup.to_string().contains("already_claimed"), "{dup}");

    // An unknown harness is refused.
    let tid2 = h.task().await;
    let bad = h
        .gated(&lead(), "dispatch_task", json!({ "task_id": tid2, "agent": "agent-1", "harness": "nope" }))
        .await;
    assert_eq!(bad.unwrap_err().code(), "invalid_argument");

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
    let e =
        h.gated(&lead(), "dispatch_task", json!({ "task_id": tid, "agent": "agent-1" })).await.unwrap_err();
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
        let run = h.gated(&lead(), "dispatch_task", args).await.unwrap();
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
}
