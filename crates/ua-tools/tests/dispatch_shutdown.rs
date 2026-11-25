//! A hub shutdown with dispatch runs in flight (unix only; its own test
//! binary, because the shutdown flag is process-wide): each child's group is
//! stopped (SIGTERM, then SIGKILL for a group that ignores it), no
//! grandchild outlives the run, and the run is recorded `retryable` with a
//! `hub_shutdown` receipt.

#![cfg(unix)]

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use ua_core::config::HarnessConfig;
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::families::dispatch::executor;
use ua_tools::{Hub, Registry, builtin_registry};

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
    Caller { kind: ActorKind::Human, profile: Profile::Operator, enforce_profile: false, ..agent("operator") }
}

fn harness(script: &str) -> HarnessConfig {
    HarnessConfig {
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        timeout_s: 600,
        ..HarnessConfig::default()
    }
}

struct H {
    hub: Hub,
    reg: Registry,
    dir: tempfile::TempDir,
}

impl H {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path().join("home"));
        cfg.human_identities = vec!["operator".into()];
        // Stops on SIGTERM, with a backgrounded grandchild in its group.
        cfg.harnesses.insert("polite".into(), harness("sleep 300 & echo $! > grandchild.pid; wait"));
        // Ignores SIGTERM (and so does its grandchild): needs the SIGKILL.
        cfg.harnesses
            .insert("stubborn".into(), harness("trap '' TERM; sleep 300 & echo $! > grandchild.pid; wait"));
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), dir }
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        match self.reg.call(&self.hub, who, tool, args.clone()).await {
            Ok(v) => v,
            Err(e) => panic!("{tool}({args}) failed: {e}"),
        }
    }

    async fn task(&self) -> (i64, std::path::PathBuf) {
        let id = self.ok(&agent("lead-1"), "task_add", json!({ "title": "Long run" })).await["id"]
            .as_i64()
            .unwrap();
        let wt = self.dir.path().join(format!("wt-{id}"));
        std::fs::create_dir_all(&wt).unwrap();
        let sql = format!("UPDATE tasks SET worktree_path = '{}' WHERE id = {id}", wt.display());
        self.hub
            .db()
            .write(move |tx| {
                tx.execute_batch(&sql)?;
                Ok(())
            })
            .unwrap();
        (id, wt)
    }

    async fn dispatch(&self, task_id: i64, harness: &str) -> String {
        let args = json!({ "task_id": task_id, "agent": "agent-1", "harness": harness });
        let me = agent("agent-1");
        let UaError::ApprovalRequired { approval_id, .. } =
            self.reg.call(&self.hub, &me, "dispatch_task", args.clone()).await.unwrap_err()
        else {
            panic!("expected an approval")
        };
        self.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
        let run = self.ok(&me, "dispatch_task", args).await;
        assert_eq!(run["state"], "running", "{run}");
        run["run_id"].as_str().unwrap().to_string()
    }
}

async fn grandchild(wt: &std::path::Path) -> i64 {
    let file = wt.join("grandchild.pid");
    for _ in 0..100 {
        if let Some(pid) = std::fs::read_to_string(&file).ok().and_then(|s| s.trim().parse().ok()) {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no grandchild pid in {}", file.display());
}

#[tokio::test]
async fn runs_in_flight_end_with_a_hub_shutdown_receipt_and_no_grandchild() {
    let h = H::new();
    let mut runs = Vec::new();
    for harness in ["polite", "stubborn"] {
        let (tid, wt) = h.task().await;
        let rid = h.dispatch(tid, harness).await;
        runs.push((rid, grandchild(&wt).await));
    }
    for (_, g) in &runs {
        assert!(executor::pid_is_alive(Some(*g)), "grandchild {g} runs before the shutdown");
    }

    let started = Instant::now();
    let report = executor::drain_supervisors(tokio::time::Instant::now() + Duration::from_secs(8)).await;
    let took = started.elapsed();
    assert_eq!(report, executor::DrainReport { stopped: 2, unfinished: 0 }, "took {took:?}");
    // Runs get until 3 s before the deadline; the stubborn group then needs
    // the SIGKILL after the 2 s SIGTERM grace.
    assert!(took >= Duration::from_secs(5) && took < Duration::from_secs(8), "{took:?}");

    for (rid, g) in &runs {
        let r = h.ok(&human(), "dispatch_delivery_receipt", json!({ "run_id": rid })).await;
        assert_eq!(r["run_state"], "retryable", "{r}");
        assert_eq!(r["failure_reason"], "hub_shutdown", "{r}");
        let last = r["receipts"].as_array().unwrap().last().cloned().unwrap();
        assert_eq!(last["source"], "hub_shutdown", "{r}");
        assert_eq!(last["state"], "retryable", "{r}");
        assert!(!executor::supervises(rid, 1));
        let mut alive = true;
        for _ in 0..20 {
            alive = executor::pid_is_alive(Some(*g));
            if !alive {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!alive, "grandchild {g} of run {rid} survived the shutdown");
    }
}
