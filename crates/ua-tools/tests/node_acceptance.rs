//! Device acceptance through the governed registry: the two harmless jobs,
//! the hub's own mid-run cancel, the five checks, operator attestation, the
//! deadline, and `node_require_acceptance` holding real work.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

struct H {
    hub: Hub,
    reg: Registry,
}

fn caller(label: &str, kind: ActorKind) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

fn device() -> Caller {
    caller("builder-1", ActorKind::Agent)
}

fn lead() -> Caller {
    caller("lead-1", ActorKind::Agent)
}

fn human() -> Caller {
    Caller { profile: Profile::Operator, enforce_profile: false, ..caller("operator", ActorKind::Human) }
}

fn reason(e: &UaError) -> String {
    e.reason_code().map(str::to_string).unwrap_or_else(|| e.to_string())
}

const NODE: &str = "node-a";

fn receipt_text(run: &str) -> String {
    let data: String = (1..=3).map(|i| format!("ua-node acceptance {run} step {i}/3\n")).collect();
    format!("acceptance:complete run={run} bytes={} sha256={}", data.len(), hex::encode(Sha256::digest(data)))
}

impl H {
    fn new(require: bool) -> Self {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        cfg.node_require_acceptance = require;
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry() }
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

    async fn manage(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
    }

    async fn register(&self) {
        let facts = json!({
            "backends": ["codex", "acceptance"],
            "worktree_roots": [{ "path": "/srv/work", "realpath": "/srv/work", "exists": true }],
        });
        self.ok(&device(), "node_register", json!({ "node": NODE, "facts": facts })).await;
    }

    async fn claim(&self) -> Value {
        self.ok(&device(), "node_claim", json!({ "node": NODE })).await["item"].clone()
    }

    async fn events(&self, item: &str, events: Value) {
        self.ok(&device(), "node_events", json!({ "node": NODE, "item_id": item, "events": events })).await;
    }

    async fn receipt(&self, item: &str, receipt: Value) {
        self.ok(&device(), "node_receipt", json!({ "node": NODE, "item_id": item, "receipt": receipt }))
            .await;
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
                        rusqlite::types::Value::Text(t) => json!(t),
                        _ => json!("?"),
                    })
                })?)
            })
            .unwrap()
    }

    /// Start a run and play the device's part honestly. Returns the run id.
    async fn pass_diagnostics(&self) -> String {
        let run = self.manage(&device(), "node_acceptance_start", json!({ "node": NODE })).await.unwrap();
        assert_eq!(run["state"], "pending", "{run}");
        let run_id = run["run_id"].as_str().unwrap().to_string();
        let (complete, cancel) = (
            run["complete_item_id"].as_str().unwrap().to_string(),
            run["cancel_item_id"].as_str().unwrap().to_string(),
        );

        // The complete job: launch, three ordered steps, the digest receipt.
        let item = self.claim().await;
        assert_eq!(item["item_id"], complete.as_str());
        assert_eq!(item["backend"], "acceptance");
        let spec: Value = serde_json::from_str(item["prompt"].as_str().unwrap()).unwrap();
        assert_eq!(spec["acceptance"], "complete");
        assert_eq!(spec["run"], run_id.as_str());
        let mut evs = vec![json!({ "kind": "acceptance_launch", "data": { "run": run_id } })];
        for step in 1..=3 {
            evs.push(
                json!({ "kind": "acceptance_progress", "data": { "run": run_id, "step": step, "of": 3 } }),
            );
        }
        self.events(&complete, json!(evs)).await;
        self.receipt(
            &complete,
            json!({ "status": "finished", "attempt": 1, "backend_status": "success", "text": receipt_text(&run_id) }),
        )
        .await;

        // The cancel job: the hub cancels it once it reports progress.
        let item = self.claim().await;
        assert_eq!(item["item_id"], cancel.as_str());
        self.events(
            &cancel,
            json!([
                { "kind": "acceptance_launch", "data": { "run": run_id } },
                { "kind": "acceptance_progress", "data": { "run": run_id, "step": 1, "of": 2 } },
            ]),
        )
        .await;
        assert_eq!(
            self.scalar(&format!("SELECT cancel_requested FROM node_dispatch WHERE id = '{cancel}'")),
            json!(1)
        );
        let beat = self.ok(&device(), "node_heartbeat", json!({ "node": NODE, "running": cancel })).await;
        assert_eq!(beat["cancel"], json!([cancel]));
        self.events(
            &cancel,
            json!([{ "kind": "acceptance_stopped", "data": { "run": run_id, "confirmed": true, "at_step": 1 } }]),
        )
        .await;
        self.receipt(&cancel, json!({ "status": "killed", "attempt": 1, "reason": "cancelled_by_hub" }))
            .await;
        run_id
    }
}

#[tokio::test]
async fn a_node_passes_diagnostics_and_an_operator_attests() {
    let h = H::new(false);
    h.register().await;
    // Another agent may not start a run on this node.
    let e = h.manage(&lead(), "node_acceptance_start", json!({ "node": NODE })).await.unwrap_err();
    assert_eq!(reason(&e), "not_node_agent");
    let status = h.manage(&lead(), "node_acceptance_status", json!({ "node": NODE })).await.unwrap();
    assert_eq!(status["state"], "not_run");

    let run_id = h.pass_diagnostics().await;
    // The receipt re-evaluated the run: every check passes, and it waits on a human.
    let v = h.manage(&device(), "node_acceptance_evaluate", json!({ "node": NODE })).await.unwrap();
    assert_eq!(v["state"], "pending", "{v}");
    for check in ["launch", "progress", "receipt", "cancel_confirmed", "revocation"] {
        assert_eq!(v["checks"][check]["status"], "pass", "{check}: {v}");
    }
    assert_eq!(v["diagnostics_passed"], true);
    assert!(v["reason"].as_str().unwrap().starts_with("awaiting_operator_attestation"), "{v}");

    // A second start while pending is refused.
    let e = h.manage(&device(), "node_acceptance_start", json!({ "node": NODE })).await.unwrap_err();
    assert_eq!(reason(&e), "acceptance_pending");

    // Attestation: an operator, not the node's agent, for the exact run.
    let attest = |run: &str| json!({ "node": NODE, "run_id": run, "evidence_ref": "checked the node's spool by hand" });
    let e = h.manage(&device(), "node_acceptance_attest", attest(&run_id)).await.unwrap_err();
    assert_eq!(reason(&e), "not_operator");
    let e = h.manage(&human(), "node_acceptance_attest", attest("acc-0000000000000000")).await.unwrap_err();
    assert_eq!(reason(&e), "acceptance_not_pending");
    let e = h
        .manage(
            &human(),
            "node_acceptance_attest",
            json!({ "node": NODE, "run_id": run_id, "evidence_ref": " " }),
        )
        .await
        .unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)));
    let v = h.manage(&human(), "node_acceptance_attest", attest(&run_id)).await.unwrap();
    assert_eq!(v["state"], "accepted", "{v}");
    assert_eq!(v["attested_by"], "operator");

    let all = h.manage(&lead(), "node_acceptance_status", json!({})).await.unwrap();
    assert_eq!(all["nodes"][NODE]["state"], "accepted", "{all}");
    assert_eq!(all["required"], false);
    let events = h.scalar(
        "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.node' \
         AND json_extract(payload, '$.kind') IN ('acceptance_started', 'acceptance_attested')",
    );
    assert_eq!(events, json!(2));
}

#[tokio::test]
async fn a_wrong_digest_or_a_missed_deadline_fails_the_run() {
    let h = H::new(false);
    h.register().await;
    let run = h.manage(&device(), "node_acceptance_start", json!({ "node": NODE })).await.unwrap();
    let run_id = run["run_id"].as_str().unwrap().to_string();
    let complete = run["complete_item_id"].as_str().unwrap().to_string();
    let cancel = run["cancel_item_id"].as_str().unwrap().to_string();
    h.claim().await;
    h.events(&complete, json!([{ "kind": "acceptance_launch", "data": { "run": run_id } }])).await;
    h.receipt(
        &complete,
        json!({ "status": "finished", "attempt": 1, "backend_status": "success", "text": "made up" }),
    )
    .await;
    let v = h.manage(&lead(), "node_acceptance_status", json!({ "node": NODE })).await.unwrap();
    assert_eq!(v["state"], "failed", "{v}");
    // The failure was recorded by the receipt and the run's open item cancelled.
    assert_eq!(h.scalar("SELECT state FROM node_acceptance"), "failed");
    assert_eq!(h.scalar(&format!("SELECT status FROM node_dispatch WHERE id = '{cancel}'")), "cancelled");

    // A fresh run that nobody finishes times out.
    let run = h.manage(&device(), "node_acceptance_start", json!({ "node": NODE })).await.unwrap();
    assert_eq!(run["state"], "pending");
    h.sql("UPDATE node_acceptance SET started_at = '2020-01-01T00:00:00+00:00'");
    let v = h.manage(&device(), "node_acceptance_evaluate", json!({ "node": NODE })).await.unwrap();
    assert_eq!(v["state"], "failed");
    assert!(v["reason"].as_str().unwrap().starts_with("timed_out"), "{v}");
    assert_eq!(
        h.scalar("SELECT COUNT(*) FROM node_dispatch WHERE backend = 'acceptance' AND status IN ('queued','claimed')"),
        json!(0)
    );
}

#[tokio::test]
async fn required_acceptance_holds_real_work_until_attested() {
    let h = H::new(true);
    h.register().await;
    let ask = json!({ "node": NODE, "backend": "codex", "prompt": "fix it", "cwd": "/srv/work/repo" });
    // Refused before anyone is asked to approve it.
    let e = h.call(&lead(), "node_dispatch", ask.clone()).await.unwrap_err();
    assert_eq!(reason(&e), "node_not_accepted");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM approvals"), json!(0));
    // Acceptance itself is never queued through node_dispatch.
    let mut own = ask.clone();
    own["backend"] = json!("acceptance");
    assert!(matches!(h.call(&lead(), "node_dispatch", own).await, Err(UaError::InvalidArgument(_))));

    // A real item already in the queue (queued before the setting) is skipped.
    let mut cfg = h.hub.cfg().clone();
    cfg.node_require_acceptance = false;
    let open = H { hub: Hub::new(cfg, h.hub.db().clone()), reg: builtin_registry() };
    let parked = open.call(&lead(), "node_dispatch", ask.clone()).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = parked else { panic!("{parked:?}") };
    open.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let real = open.ok(&lead(), "node_dispatch", ask.clone()).await["item_id"].as_str().unwrap().to_string();
    assert_eq!(h.claim().await, Value::Null, "real work waits for acceptance");

    let run_id = h.pass_diagnostics().await;
    assert_eq!(h.claim().await, Value::Null, "diagnostics alone accept nothing");
    h.manage(
        &human(),
        "node_acceptance_attest",
        json!({ "node": NODE, "run_id": run_id, "evidence_ref": "operator verified the output file" }),
    )
    .await
    .unwrap();
    assert_eq!(h.claim().await["item_id"], real.as_str());
    let parked = h.call(&lead(), "node_dispatch", ask).await.unwrap_err();
    assert!(matches!(parked, UaError::ApprovalRequired { .. }), "{parked:?}");
}

impl H {
    /// Pass diagnostics and have an operator attest the run.
    async fn accept(&self) {
        let run_id = self.pass_diagnostics().await;
        self.manage(
            &human(),
            "node_acceptance_attest",
            json!({ "node": NODE, "run_id": run_id, "evidence_ref": "operator verified the output file" }),
        )
        .await
        .unwrap();
        assert!(self.admits_work().await, "an attested node takes work");
    }

    /// Whether real work for the node passes the acceptance gate (it parks
    /// for approval rather than being refused node_not_accepted).
    async fn admits_work(&self) -> bool {
        let ask = json!({ "node": NODE, "backend": "codex", "prompt": "fix it", "cwd": "/srv/work/repo" });
        match self.call(&lead(), "node_dispatch", ask).await {
            Err(UaError::ApprovalRequired { .. }) => true,
            Err(e) if reason(&e) == "node_not_accepted" => false,
            other => panic!("unexpected dispatch outcome {other:?}"),
        }
    }

    fn stored_state(&self) -> Value {
        self.scalar(&format!(
            "SELECT state || ':' || COALESCE(reason, '') FROM node_acceptance WHERE node = '{NODE}'"
        ))
    }

    async fn lifecycle(&self, action: &str, extra: Value) {
        let mut params = json!({ "node": NODE, "reason": "maintenance" });
        for (k, v) in extra.as_object().unwrap() {
            params[k] = v.clone();
        }
        self.manage(&human(), action, params).await.unwrap();
    }
}

#[tokio::test]
async fn acceptance_does_not_survive_node_lifecycle_changes() {
    let h = H::new(true);
    h.register().await;
    h.accept().await;

    // Retire and un-retire: the node runs acceptance again.
    h.lifecycle("node_retire", json!({})).await;
    h.lifecycle("node_unretire", json!({})).await;
    h.register().await;
    assert!(!h.admits_work().await, "retirement voids acceptance");
    assert!(
        h.stored_state().as_str().unwrap().starts_with("failed:voided: node_retired"),
        "{}",
        h.stored_state()
    );
    let status = h.manage(&human(), "node_acceptance_status", json!({ "node": NODE })).await.unwrap();
    assert_eq!(status["state"], "failed", "{status}");

    // Forget and register afresh: no acceptance carried over.
    h.accept().await;
    h.lifecycle("node_retire", json!({})).await;
    h.lifecycle("node_forget", json!({})).await;
    assert_eq!(h.scalar("SELECT COUNT(*) FROM node_acceptance"), json!(0));
    h.register().await;
    assert!(!h.admits_work().await, "a forgotten node starts unaccepted");

    // Reassigned away and back: voided.
    h.accept().await;
    h.lifecycle("node_reassign", json!({ "to_agent": "builder-2" })).await;
    h.lifecycle("node_reassign", json!({ "to_agent": "builder-1" })).await;
    h.register().await;
    assert!(!h.admits_work().await, "reassignment voids acceptance");
    assert!(h.stored_state().as_str().unwrap().contains("node_reassigned"));

    // An identical re-registration (a restart) keeps it.
    h.accept().await;
    h.register().await;
    assert!(h.admits_work().await, "a restart with the same facts keeps acceptance");

    // A first code_sha by heartbeat keeps it; a different one voids it.
    let sha = |c: char| c.to_string().repeat(40);
    h.ok(&device(), "node_heartbeat", json!({ "node": NODE, "facts": { "code_sha": sha('a') } })).await;
    assert!(h.admits_work().await);
    h.ok(&device(), "node_heartbeat", json!({ "node": NODE, "facts": { "code_sha": sha('b') } })).await;
    assert!(!h.admits_work().await, "new code voids acceptance");
    assert!(h.stored_state().as_str().unwrap().contains("code_sha"), "{}", h.stored_state());

    // A registration with other backends or harnesses voids it too.
    h.accept().await;
    let facts = json!({
        "backends": ["codex", "acceptance", "acp:claude"],
        "worktree_roots": [{ "path": "/srv/work", "realpath": "/srv/work", "exists": true }],
    });
    h.ok(&device(), "node_register", json!({ "node": NODE, "facts": facts })).await;
    assert!(!h.admits_work().await, "new backends void acceptance");
    assert!(h.stored_state().as_str().unwrap().contains("backends"), "{}", h.stored_state());
    h.accept().await;
    let mut facts = facts;
    facts["harnesses"] = json!({ "codex": { "bin": "codex", "version": "2.0" } });
    h.ok(&device(), "node_register", json!({ "node": NODE, "facts": facts })).await;
    assert!(!h.admits_work().await, "new harnesses void acceptance");

    let voided = h.scalar(
        "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.node' \
         AND json_extract(payload, '$.kind') = 'acceptance_failed' \
         AND json_extract(payload, '$.reason') LIKE 'voided:%'",
    );
    assert_eq!(voided, json!(6), "one ledgered void per change");
}
