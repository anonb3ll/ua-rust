//! The remote-node work queue through the governed registry: approval-bound
//! enqueue, claims under an attempt fence and lease, durable claim
//! operations, receipts, cancellation, waits, supervised commands,
//! follow-ups, permission prompts, and dispatch runs routed to a node.

use serde_json::{Value, json};
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
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

/// The node's own agent.
fn device() -> Caller {
    caller("builder-1", ActorKind::Agent)
}

/// An agent asking for work on the node.
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

impl H {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(f: impl FnOnce(&mut Config)) -> Self {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        f(&mut cfg);
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

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> UaError {
        match self.call(who, tool, args.clone()).await {
            Ok(v) => panic!("{tool}({args}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    async fn manage(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
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

    async fn register(&self, facts: Value) {
        self.ok(&device(), "node_register", json!({ "node": NODE, "facts": facts })).await;
    }

    async fn register_default(&self) {
        self.register(json!({
            "backends": ["codex", "acp:claude", "command"],
            "worktree_roots": [{ "path": "/srv/work", "realpath": "/srv/work", "exists": true }],
            "node_features": ["acp_followups", "session_settings"],
        }))
        .await;
    }

    async fn queue(&self, extra: Value) -> String {
        let mut args =
            json!({ "node": NODE, "backend": "codex", "prompt": "fix the build", "cwd": "/srv/work/repo" });
        for (k, v) in extra.as_object().unwrap() {
            args[k] = v.clone();
        }
        let out = self.gated(&lead(), "node_dispatch", args).await;
        out["item_id"].as_str().unwrap().to_string()
    }

    async fn claim(&self) -> Value {
        self.ok(&device(), "node_claim", json!({ "node": NODE })).await
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

    fn events(&self, kind: &str) -> i64 {
        self.scalar(&format!(
            "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.node' AND json_extract(payload, '$.kind') = '{kind}'"
        ))
        .as_i64()
        .unwrap()
    }
}

#[tokio::test]
async fn work_is_approved_claimed_and_settled_by_its_receipt() {
    let h = H::new();
    h.register_default().await;

    // The approval binds what will run.
    let args =
        json!({ "node": NODE, "backend": "codex", "prompt": "fix the build", "cwd": "/srv/work/repo" });
    let e = h.err(&lead(), "node_dispatch", args.clone()).await;
    let UaError::ApprovalRequired { approval_id, tool } = e else { panic!("expected an approval") };
    assert_eq!(tool, "node_dispatch");
    let payload: Value = serde_json::from_str(
        h.scalar(&format!("SELECT payload FROM approvals WHERE id = {approval_id}")).as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(payload["prompt"], "fix the build");
    assert_eq!(payload["cwd"], "/srv/work/repo");
    assert_eq!(payload["timeout_s"], 3600);
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let queued = h.ok(&lead(), "node_dispatch", args.clone()).await;
    assert_eq!(queued["status"], "queued");
    assert!(queued.get("waiting").is_none(), "the node is live: {queued}");
    let id = queued["item_id"].as_str().unwrap().to_string();
    // The pass is used once.
    let again = h.err(&lead(), "node_dispatch", args).await;
    assert!(matches!(again, UaError::ApprovalRequired { .. }));

    // Only the node's own agent claims.
    let e = h.err(&lead(), "node_claim", json!({ "node": NODE })).await;
    assert_eq!(reason(&e), "node_owned_elsewhere");
    let claimed = h.claim().await;
    let item = &claimed["item"];
    assert_eq!(item["item_id"], id);
    assert_eq!(item["attempt"], 1);
    assert_eq!(item["prompt"], "fix the build");
    assert!(item["lease_expires_at"].is_string());
    assert_eq!(h.claim().await["item"], Value::Null, "nothing else queued");

    // A heartbeat renews the lease and records progress.
    h.sql(&format!(
        "UPDATE node_dispatch SET lease_expires_at = '2099-01-01T00:00:00+00:00' WHERE id = '{id}'"
    ));
    let beat = h
        .ok(&device(), "node_heartbeat", json!({ "node": NODE, "running": id, "progress": "compiling" }))
        .await;
    assert_eq!(beat["cancel"], json!([]));
    assert_ne!(
        h.scalar(&format!("SELECT lease_expires_at FROM node_dispatch WHERE id = '{id}'")),
        "2099-01-01T00:00:00+00:00"
    );
    assert_eq!(h.events("progress"), 1);

    // Events are recorded and redacted.
    let ev = h
        .ok(
            &device(),
            "node_events",
            json!({ "node": NODE, "item_id": id, "events": [
                { "kind": "agent_message", "text": "key ghp_0123456789abcdefghijklmnopqrstuvwxyz0123" },
                "not an object",
            ]}),
        )
        .await;
    assert_eq!(ev, json!({ "recorded": 1, "dropped": 1 }));
    let stored = h.scalar(
        "SELECT payload FROM event_log WHERE json_extract(payload, '$.kind') = 'acp_event' ORDER BY seq DESC LIMIT 1",
    );
    assert!(!stored.as_str().unwrap().contains("ghp_0123456789"), "{stored}");

    // A receipt for another attempt is refused; the right one settles it.
    let e = h
        .err(
            &device(),
            "node_receipt",
            json!({ "node": NODE, "item_id": id, "receipt": { "status": "finished", "attempt": 7 } }),
        )
        .await;
    assert_eq!(reason(&e), "stale_attempt");
    // A receipt must name its attempt.
    for attempt in [Value::Null, json!("1"), json!(1.5)] {
        let mut r = json!({ "status": "finished" });
        if !attempt.is_null() {
            r["attempt"] = attempt;
        }
        let e = h.err(&device(), "node_receipt", json!({ "node": NODE, "item_id": id, "receipt": r })).await;
        assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");
        assert!(e.to_string().contains("receipt.attempt is required"), "{e}");
    }
    let receipt = json!({
        "status": "finished", "attempt": 1, "exit_code": 0, "secret": "x",
        "text": "done; pushed with ghp_0123456789abcdefghijklmnopqrstuvwxyz0123",
    });
    let out =
        h.ok(&device(), "node_receipt", json!({ "node": NODE, "item_id": id, "receipt": receipt })).await;
    assert_eq!(out["duplicate"], false);
    assert_eq!(out["status"], "finished");
    assert_eq!(out["evidence_ref"], format!("node:{NODE}:{id}"));
    assert!(out["receipt"].get("secret").is_none());
    // Free text is redacted before it is stored.
    assert!(out["receipt"]["text"].as_str().unwrap().starts_with("done; pushed with "));
    let stored = h.scalar(&format!("SELECT receipt_json FROM node_dispatch WHERE id = '{id}'"));
    assert!(!stored.as_str().unwrap().contains("ghp_0123456789"), "{stored}");
    let dup = h
        .ok(
            &device(),
            "node_receipt",
            json!({ "node": NODE, "item_id": id, "receipt": { "status": "failed", "attempt": 1 } }),
        )
        .await;
    assert_eq!(dup["duplicate"], true);
    assert_eq!(dup["receipt"]["status"], "finished", "the first receipt stands");

    // Listings: the requester and the node's agent see it, others do not.
    let mine = h.ok(&lead(), "node_items", json!({})).await;
    assert_eq!(mine["items"][0]["item_id"], id);
    assert_eq!(mine["items"][0]["outcome"]["status"], "finished");
    assert!(mine["items"][0].get("prompt").is_none());
    let one = h.ok(&device(), "node_items", json!({ "item_id": id })).await;
    assert_eq!(one["item"]["prompt"], "fix the build");
    let stranger = h.ok(&caller("stranger", ActorKind::Agent), "node_items", json!({})).await;
    assert_eq!(stranger["items"], json!([]));
    assert_eq!(h.events("enqueue"), 1);
    assert_eq!(h.events("claim"), 1);
    assert_eq!(h.events("receipt"), 1);
}

#[tokio::test]
async fn requests_are_validated_before_an_approval_is_asked() {
    let h = H::new();
    h.register_default().await;
    let base = json!({ "node": NODE, "backend": "codex", "prompt": "p", "cwd": "/srv/work" });
    let with = |k: &str, v: Value| {
        let mut a = base.clone();
        a[k] = v;
        a
    };
    let e = h.err(&lead(), "node_dispatch", with("backend", json!("nope"))).await;
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");
    let e = h.err(&lead(), "node_dispatch", with("timeout_s", json!(0))).await;
    assert!(matches!(e, UaError::InvalidArgument(_)));
    let e = h.err(&lead(), "node_dispatch", with("permission_mode", json!("full-access"))).await;
    assert!(e.to_string().contains("acp"), "{e}");
    let e = h.err(&lead(), "node_dispatch", with("node", json!("ghost"))).await;
    assert!(matches!(e, UaError::NotFound(_)));
    let e = h.err(&lead(), "node_dispatch", with("backend", json!("claude"))).await;
    assert_eq!(reason(&e), "backend_unavailable");
    let e = h.err(&lead(), "node_dispatch", with("backend", json!("command"))).await;
    assert!(e.to_string().contains("node_command_start"));
    assert_eq!(h.scalar("SELECT COUNT(*) FROM approvals"), json!(0), "no approval was asked for");

    // A retired node takes no work.
    h.ok(
        &human(),
        "coordination_manage",
        json!({ "action": "node_retire", "params": { "node": NODE, "reason": "gone" } }),
    )
    .await;
    let e = h.err(&lead(), "node_dispatch", base).await;
    assert_eq!(reason(&e), "node_retired");
}

#[tokio::test]
async fn a_launch_key_returns_the_item_it_queued() {
    let h = H::new();
    h.register_default().await;
    let id = h.queue(json!({ "launch_key": "launch-0001" })).await;
    let args = json!({ "node": NODE, "backend": "codex", "prompt": "fix the build", "cwd": "/srv/work/repo", "launch_key": "launch-0001" });
    let again = h.ok(&lead(), "node_dispatch", args).await;
    assert_eq!(again["item_id"], id);
    assert_eq!(again["replayed"], true);
}

#[tokio::test]
async fn a_lapsed_lease_fails_the_item_and_its_outcome_needs_reconciling() {
    let h = H::new();
    h.register_default().await;
    let id = h.queue(json!({})).await;
    h.claim().await;
    h.sql(&format!(
        "UPDATE node_dispatch SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = '{id}'"
    ));
    // The next claim sweeps it.
    assert_eq!(h.claim().await["item"], Value::Null);
    assert_eq!(h.scalar(&format!("SELECT status FROM node_dispatch WHERE id = '{id}'")), "failed");
    let e = h
        .err(
            &device(),
            "node_receipt",
            json!({ "node": NODE, "item_id": id, "receipt": { "status": "finished", "attempt": 1 } }),
        )
        .await;
    assert_eq!(reason(&e), "outcome_unknown");
    let listed = h.ok(&lead(), "node_items", json!({ "item_id": id })).await;
    assert_eq!(listed["item"]["outcome_unknown"], true);
    assert_eq!(listed["item"]["restartable"], false);
    let e = h.manage(&lead(), "node_item_restart", json!({ "item_id": id })).await.unwrap_err();
    assert!(e.to_string().contains("reconcile"), "{e}");
}

#[tokio::test]
async fn a_claim_operation_returns_the_same_item_when_asked_again() {
    let h = H::new();
    h.register_default().await;
    let id = h.queue(json!({})).await;
    let now = jiff::Timestamp::now().as_second();
    let op = json!({ "id": "0123456789abcdef0123456789abcdef", "mode": "claim", "issued_at": now });
    let first = h.ok(&device(), "node_claim", json!({ "node": NODE, "claim_op": op })).await;
    assert_eq!(first["item"]["item_id"], id);
    assert_eq!(first["claim_op"]["state"], "bound");
    let again = h.ok(&device(), "node_claim", json!({ "node": NODE, "claim_op": op })).await;
    assert_eq!(again["item"]["item_id"], id, "the lost answer is returned again");
    assert_eq!(again["item"]["attempt"], 1, "without a second claim");
    assert_eq!(h.scalar(&format!("SELECT attempts FROM node_dispatch WHERE id = '{id}'")), json!(1));

    // The same id with a different issue time is another request.
    let other = json!({ "id": "0123456789abcdef0123456789abcdef", "mode": "claim", "issued_at": now - 5 });
    let e = h.err(&device(), "node_claim", json!({ "node": NODE, "claim_op": other })).await;
    assert!(e.to_string().contains("conflicts"), "{e}");

    // A reconcile of an unknown operation settles it as no claim.
    let rec = json!({ "id": "ffffffffffffffffffffffffffffffff", "mode": "reconcile", "issued_at": now });
    let out = h.ok(&device(), "node_claim", json!({ "node": NODE, "claim_op": rec })).await;
    assert_eq!(out["item"], Value::Null);
    assert_eq!(out["claim_op"]["state"], "no_claim");
    assert_eq!(out["claim_op"]["reason"], "reconciled_unknown");

    // Once the item has a receipt the bound operation no longer executes.
    h.ok(
        &device(),
        "node_receipt",
        json!({ "node": NODE, "item_id": id, "receipt": { "status": "finished", "attempt": 1 } }),
    )
    .await;
    let after = h.ok(&device(), "node_claim", json!({ "node": NODE, "claim_op": op })).await;
    assert_eq!(after["item"], Value::Null);
    assert_eq!(after["claim_op"]["executable"], false);
    assert_eq!(after["claim_op"]["reason"], "receipt_stored");

    let bad = json!({ "id": "0123", "mode": "claim", "issued_at": now });
    assert!(matches!(
        h.err(&device(), "node_claim", json!({ "node": NODE, "claim_op": bad })).await,
        UaError::InvalidArgument(_)
    ));
}

#[tokio::test]
async fn cancels_end_queued_work_and_reach_claimed_work_by_heartbeat() {
    let h = H::new();
    h.register_default().await;
    let a = h.queue(json!({ "prompt": "first" })).await;
    let b = h.queue(json!({ "prompt": "second" })).await;
    // A stranger may not cancel.
    let e = h
        .manage(&caller("stranger", ActorKind::Agent), "node_item_cancel", json!({ "item_id": b }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "not_item_owner");
    let out = h.manage(&lead(), "node_item_cancel", json!({ "item_id": b })).await.unwrap();
    assert_eq!(out["status"], "cancelled");

    assert_eq!(h.claim().await["item"]["item_id"], a);
    let out =
        h.manage(&lead(), "node_item_cancel", json!({ "item_id": a, "reason": "not needed" })).await.unwrap();
    assert_eq!(out["status"], "claimed");
    assert_eq!(out["cancel_requested"], true);
    let beat = h.ok(&device(), "node_heartbeat", json!({ "node": NODE, "running": a })).await;
    assert_eq!(beat["cancel"], json!([a]));
    let r = h
        .ok(&device(), "node_receipt", json!({ "node": NODE, "item_id": a, "receipt": { "status": "killed", "attempt": 1, "reason": "cancelled_by_hub" } }))
        .await;
    assert_eq!(r["status"], "killed");
    assert_eq!(h.claim().await["item"], Value::Null, "the cancelled item is never claimed");
}

#[tokio::test]
async fn work_for_an_offline_node_waits_then_fails() {
    let h = H::new();
    h.register_default().await;
    h.sql("UPDATE nodes SET last_heartbeat = '2000-01-01T00:00:00+00:00'");
    let out = h
        .gated(
            &lead(),
            "node_dispatch",
            json!({ "node": NODE, "backend": "codex", "prompt": "p", "cwd": "/srv/work" }),
        )
        .await;
    assert_eq!(out["waiting"]["reason"], "node_offline");
    assert_eq!(out["waiting"]["active"], true);
    let id = out["item_id"].as_str().unwrap().to_string();
    h.sql(&format!(
        "UPDATE node_dispatch SET wait_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = '{id}'"
    ));
    let swept = ua_tools::families::node_queue::sweep(&h.hub, None).unwrap();
    assert_eq!(swept["waits_expired"], json!([id]));
    let item = h.ok(&lead(), "node_items", json!({ "item_id": id })).await;
    assert_eq!(item["item"]["status"], "failed");
    assert_eq!(item["item"]["receipt"]["reason"], "waiting_expired_node_offline");
    assert_eq!(item["item"]["restartable"], true);
}

#[tokio::test]
async fn a_node_with_open_work_cannot_be_retired() {
    let h = H::new();
    h.register_default().await;
    let id = h.queue(json!({})).await;
    let retire = json!({ "action": "node_retire", "params": { "node": NODE, "reason": "moving" } });
    let e = h.err(&human(), "coordination_manage", retire.clone()).await;
    assert!(matches!(e, UaError::Conflict(_)), "{e:?}");
    assert!(e.to_string().contains(&id), "{e}");
    let e = h
        .err(&human(), "coordination_manage", json!({ "action": "node_reassign", "params": { "node": NODE, "to_agent": "builder-2", "reason": "moving" } }))
        .await;
    assert!(e.to_string().contains(&id), "{e}");
    h.manage(&lead(), "node_item_cancel", json!({ "item_id": id })).await.unwrap();
    let out = h.ok(&human(), "coordination_manage", retire).await;
    assert_eq!(out["retired"], true);
}

#[tokio::test]
async fn a_supervised_command_needs_its_fence_and_notifies_its_owner() {
    let h = H::new();
    h.register_default().await;
    let params = json!({ "node": NODE, "argv": ["cargo", "test", "--all"], "cwd": "/srv/work/repo", "timeout_s": 600 });
    let parked = h.manage(&lead(), "node_command_start", params.clone()).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = parked else { panic!("expected an approval") };
    let payload = h.scalar(&format!("SELECT payload FROM approvals WHERE id = {approval_id}"));
    assert!(payload.as_str().unwrap().contains("\"command\":[\"cargo\",\"test\",\"--all\"]"), "{payload}");
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let out = h.manage(&lead(), "node_command_start", params).await.unwrap();
    assert_eq!(out["owner_agent"], "lead-1");
    let id = out["item_id"].as_str().unwrap().to_string();

    let claimed = h.claim().await;
    let token = claimed["item"]["command"]["fence_token"].as_str().unwrap().to_string();
    assert_eq!(claimed["item"]["command"]["argv"], json!(["cargo", "test", "--all"]));
    let status = h.manage(&lead(), "node_command_status", json!({ "item_id": id })).await.unwrap();
    assert_eq!(status["status"], "claimed");
    assert!(!status.to_string().contains(&token), "status never shows the fence token");
    let e = h
        .manage(&caller("stranger", ActorKind::Agent), "node_command_status", json!({ "item_id": id }))
        .await
        .unwrap_err();
    assert!(matches!(e, UaError::NotFound(_)));

    let bad = json!({ "status": "finished", "attempt": 1, "exit_code": 0, "fence_token": "0".repeat(32) });
    let e = h.err(&device(), "node_receipt", json!({ "node": NODE, "item_id": id, "receipt": bad })).await;
    assert_eq!(reason(&e), "stale_fence");
    assert_eq!(h.events("stale_fence"), 1);
    let good = json!({ "status": "finished", "attempt": 1, "exit_code": 0, "fence_token": token, "log_path": "/srv/logs/command.log" });
    h.ok(&device(), "node_receipt", json!({ "node": NODE, "item_id": id, "receipt": good })).await;

    let status = h.manage(&lead(), "node_command_status", json!({ "item_id": id })).await.unwrap();
    assert_eq!(status["exit_code"], 0);
    assert_eq!(status["log_path"], "/srv/logs/command.log");
    let inbox = h.ok(&lead(), "message_list", json!({ "to_agent": "lead-1" })).await;
    let notice = &inbox["messages"][0];
    assert_eq!(notice["from_agent"], "hub-node");
    assert_eq!(notice["client_message_id"], format!("node-command-{id}-1-finished"));
    assert_eq!(h.scalar("SELECT message_id FROM node_command_notice"), notice["message_id"]);
    assert!(notice["body"].as_str().unwrap().contains("cargo test --all"), "{notice}");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM node_command_notice WHERE sent_at IS NOT NULL"), json!(1));
}

#[tokio::test]
async fn an_idle_claim_retries_only_its_own_nodes_notices() {
    let h = H::new();
    h.register_default().await;
    // Two finished commands, one on another node, each with a notice owed.
    let ts = "2026-01-01T00:00:00+00:00";
    for (item, node) in [("nd-00000000000000aa", NODE), ("nd-00000000000000bb", "node-b")] {
        h.sql(&format!(
            "INSERT INTO node_dispatch (id, node, agent, backend, prompt, cwd, timeout_s, status, attempts, \
             created_by, created_at, updated_at) VALUES ('{item}', '{node}', 'builder-1', 'command', 'p', '/srv', \
             60, 'finished', 1, 'lead-1', '{ts}', '{ts}'); \
             INSERT INTO node_command_notice (item_id, attempt, terminal, owner_agent, body, created_at) \
             VALUES ('{item}', 1, 'finished', 'lead-1', 'done', '{ts}');"
        ));
    }
    let sent = |item: &str| {
        h.scalar(&format!("SELECT sent_at IS NOT NULL FROM node_command_notice WHERE item_id = '{item}'"))
    };
    assert_eq!(h.claim().await["item"], Value::Null);
    assert_eq!(sent("nd-00000000000000aa"), json!(1), "this node's notice is retried");
    assert_eq!(sent("nd-00000000000000bb"), json!(0), "another node's is left to the sweep");
    ua_tools::families::node_queue::sweep(&h.hub, None).unwrap();
    assert_eq!(sent("nd-00000000000000bb"), json!(1));
}

#[tokio::test]
async fn follow_ups_reach_a_running_acp_session() {
    let h = H::new();
    h.register_default().await;
    let id = h.queue(json!({ "backend": "acp:claude" })).await;
    let item = h.claim().await;
    assert_eq!(item["item"]["permission_mode"], "supervised");

    // A human's follow-up needs no approval.
    let f = h
        .ok(&human(), "node_followup", json!({ "item_id": id, "mode": "steer", "body": "also run clippy", "idempotency_key": "steer-0001" }))
        .await;
    assert_eq!(f["approval"], "not_required_operator");
    let dup = h
        .ok(&human(), "node_followup", json!({ "item_id": id, "mode": "steer", "body": "also run clippy", "idempotency_key": "steer-0001" }))
        .await;
    assert_eq!(dup["duplicate"], true);
    let e = h
        .err(
            &human(),
            "node_followup",
            json!({ "item_id": id, "mode": "queue", "body": "other", "idempotency_key": "steer-0001" }),
        )
        .await;
    assert!(matches!(e, UaError::Conflict(_)));
    // The requester's follow-up needs a one-time approval; a stranger's is refused.
    let e = h
        .err(
            &caller("stranger", ActorKind::Agent),
            "node_followup",
            json!({ "item_id": id, "mode": "queue", "body": "x", "idempotency_key": "queue-0001" }),
        )
        .await;
    assert_eq!(reason(&e), "not_item_owner");
    // The approval is its own tool, bound to the session and the exact text.
    let ask =
        json!({ "item_id": id, "mode": "queue", "body": "then open a PR", "idempotency_key": "queue-0002" });
    let parked = h.err(&lead(), "node_followup", ask.clone()).await;
    let UaError::ApprovalRequired { approval_id, tool } = parked else {
        panic!("expected an approval: {parked:?}")
    };
    assert_eq!(tool, "node_followup");
    let payload: Value = serde_json::from_str(
        h.scalar(&format!("SELECT payload FROM approvals WHERE id = {approval_id}")).as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(payload["summary"], format!("follow-up (queue) into {id} on {NODE}"));
    assert_eq!(payload["prompt"], "then open a PR");
    assert_eq!(payload["backend"], "acp:claude");
    assert_eq!(payload["cwd"], "/srv/work/repo");
    assert_eq!(
        payload["followup"],
        json!({ "item_id": id, "mode": "queue", "idempotency_key": "queue-0002" })
    );
    assert_eq!(
        h.scalar("SELECT COUNT(*) FROM approvals WHERE tool = 'node_dispatch' AND status = 'pending'"),
        json!(0)
    );
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let g = h.ok(&lead(), "node_followup", ask).await;
    assert_eq!(g["approval"], "gate_passed");

    // The node polls, acknowledges, and reports delivery.
    let poll = h.ok(&device(), "node_followups", json!({ "node": NODE, "item_id": id })).await;
    let ids: Vec<String> =
        poll["followups"].as_array().unwrap().iter().map(|f| f["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(ids.len(), 2);
    let poll = h.ok(&device(), "node_followups", json!({ "node": NODE, "item_id": id, "ack": ids })).await;
    assert_eq!(poll["followups"], json!([]));
    h.ok(
        &device(),
        "node_events",
        json!({ "node": NODE, "item_id": id, "events": [{ "kind": "followup_delivered", "data": { "followup_id": ids[0], "turn_id": "t1" } }] }),
    )
    .await;
    // The receipt drops the one never confirmed.
    h.ok(
        &device(),
        "node_receipt",
        json!({ "node": NODE, "item_id": id, "receipt": { "status": "finished", "attempt": 1 } }),
    )
    .await;
    let one = h.ok(&lead(), "node_items", json!({ "item_id": id })).await;
    let statuses: Vec<&str> =
        one["item"]["followups"].as_array().unwrap().iter().map(|f| f["status"].as_str().unwrap()).collect();
    assert_eq!(statuses, ["delivered", "dropped"]);

    // Not for a non-ACP item.
    let other = h.queue(json!({})).await;
    let e = h
        .err(
            &human(),
            "node_followup",
            json!({ "item_id": other, "mode": "queue", "body": "x", "idempotency_key": "queue-0003" }),
        )
        .await;
    assert!(e.to_string().contains("acp"), "{e}");
}

#[tokio::test]
async fn a_permission_prompt_waits_for_a_human_and_is_used_once() {
    let h = H::new();
    h.register_default().await;
    let id = h.queue(json!({ "backend": "acp:claude" })).await;
    h.claim().await;
    let ask = json!({
        "node": NODE, "item_id": id, "session_id": "sess-1",
        "tool_call": { "title": "rm -rf target", "kind": "execute" },
        "options": [{ "optionId": "yes", "name": "Allow", "kind": "allow_once" }, { "optionId": "no", "name": "Reject", "kind": "reject_once" }],
    });
    let first = h.ok(&device(), "node_permission", ask.clone()).await;
    assert_eq!(first["status"], "pending");
    let approval_id = first["approval_id"].as_i64().unwrap();
    assert_eq!(
        h.ok(&device(), "node_permission", ask.clone()).await["approval_id"],
        approval_id,
        "the same row"
    );
    // The node's agent cannot decide for itself.
    let e = h.err(&device(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    assert!(!matches!(e, UaError::ApprovalRequired { .. }), "{e:?}");
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let decided = h.ok(&device(), "node_permission", ask.clone()).await;
    assert_eq!(decided["status"], "approved");
    assert_eq!(decided["option_id"], "yes");
    let next = h.ok(&device(), "node_permission", ask.clone()).await;
    assert_eq!(next["status"], "pending", "an approval answers one prompt");

    // A prompt the node could not apply an approval to is denied without asking.
    let mut reject_only = ask.clone();
    reject_only["options"] = json!([{ "optionId": "no", "name": "Reject", "kind": "reject_once" }]);
    let before = h.scalar("SELECT COUNT(*) FROM approvals WHERE tool = 'acp_permission'");
    let refused = h.ok(&device(), "node_permission", reject_only).await;
    assert_eq!(refused, json!({ "status": "denied", "reason": "no_allow_option" }));
    let mut no_options = ask.clone();
    no_options["options"] = json!([]);
    assert_eq!(h.ok(&device(), "node_permission", no_options).await["reason"], "no_allow_option");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM approvals WHERE tool = 'acp_permission'"), before);

    // A cancelled item's prompts are denied without asking anyone.
    h.manage(&lead(), "node_item_cancel", json!({ "item_id": id })).await.unwrap();
    let denied = h.ok(&device(), "node_permission", ask).await;
    assert_eq!(denied["status"], "denied");
    assert_eq!(denied["reason"], "cancel_requested");
}

async fn routed_task(h: &H) -> i64 {
    let id = h.ok(&lead(), "task_add", json!({ "title": "Port the widget" })).await["id"].as_i64().unwrap();
    h.sql(&format!("UPDATE tasks SET worktree_path = '/srv/work/widget' WHERE id = {id}"));
    id
}

#[tokio::test]
async fn a_dispatch_run_routed_to_a_node_follows_its_item() {
    let h = H::new();
    h.register_default().await;
    let tid = routed_task(&h).await;
    let builder = device();
    let out = h
        .gated(
            &builder,
            "dispatch_task",
            json!({ "task_id": tid, "agent": "builder-1", "node": NODE, "prompt": "port it" }),
        )
        .await;
    assert_eq!(out["routed"], "node");
    assert_eq!(out["state"], "launched");
    assert_eq!(out["backend"], "codex", "the node's first backend");
    assert_eq!(out["cwd"], "/srv/work/widget", "the task worktree under a node root");
    let run_id = out["run_id"].as_str().unwrap().to_string();
    let item_id = out["item_id"].as_str().unwrap().to_string();
    let payload =
        h.scalar("SELECT payload FROM approvals WHERE tool = 'dispatch_task' ORDER BY id DESC LIMIT 1");
    assert!(payload.as_str().unwrap().contains("\"node\":\"node-a\""), "{payload}");

    // The node claims it: the run is running.
    let claimed = h.claim().await;
    assert_eq!(claimed["item"]["run_id"], run_id);
    assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{run_id}'")), "running");
    // The dispatch reaper leaves it to the queue even past its lease.
    h.sql(&format!(
        "UPDATE dispatch_runs SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE run_id = '{run_id}'"
    ));
    ua_tools::families::dispatch::reap_expired_leases(&h.hub).unwrap();
    assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{run_id}'")), "running");

    // The receipt finishes the run with the item as evidence.
    let r = h
        .ok(
            &device(),
            "node_receipt",
            json!({ "node": NODE, "item_id": item_id, "receipt": { "status": "finished", "attempt": 1 } }),
        )
        .await;
    assert_eq!(r["run_outcome"]["ok"], true, "{r}");
    assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{run_id}'")), "finished");
    assert_eq!(
        h.scalar(&format!("SELECT evidence_ref FROM dispatch_runs WHERE run_id = '{run_id}'")),
        format!("node:{NODE}:{item_id}")
    );
    let e = h.err(&builder, "dispatch_resume", json!({ "run_id": run_id })).await;
    assert!(matches!(e, UaError::Conflict(_)), "{e:?}");
}

#[tokio::test]
async fn cancelling_a_routed_run_waits_for_the_node_to_confirm() {
    let h = H::new();
    h.register_default().await;
    let tid = routed_task(&h).await;
    let out = h
        .gated(
            &device(),
            "dispatch_task",
            json!({ "task_id": tid, "agent": "builder-1", "node": NODE, "prompt": "port it" }),
        )
        .await;
    let run_id = out["run_id"].as_str().unwrap().to_string();
    let item_id = out["item_id"].as_str().unwrap().to_string();
    h.claim().await;
    let c = h.ok(&device(), "dispatch_cancel", json!({ "run_id": run_id })).await;
    assert_eq!(c["termination"], "node_cancel_requested");
    assert_eq!(c["cessation"], "unknown");
    let beat = h.ok(&device(), "node_heartbeat", json!({ "node": NODE, "running": item_id })).await;
    assert_eq!(beat["cancel"], json!([item_id]));
    h.ok(
        &device(),
        "node_receipt",
        json!({ "node": NODE, "item_id": item_id, "receipt": { "status": "killed", "attempt": 1 } }),
    )
    .await;
    assert_eq!(
        h.scalar(&format!("SELECT termination_outcome FROM dispatch_runs WHERE run_id = '{run_id}'")),
        "confirmed"
    );
}

#[tokio::test]
async fn a_routed_run_needs_a_node_of_its_agent() {
    let h = H::new();
    h.register_default().await;
    let tid = routed_task(&h).await;
    let e = h.err(&lead(), "dispatch_task", json!({ "task_id": tid, "agent": "lead-1", "node": NODE })).await;
    assert_eq!(reason(&e), "node_owned_elsewhere");
    let e = h
        .err(&lead(), "dispatch_task", json!({ "task_id": tid, "agent": "lead-1", "backend": "codex" }))
        .await;
    assert!(matches!(e, UaError::InvalidArgument(_)));
}

#[tokio::test]
async fn a_waiting_claim_picks_up_work_queued_while_it_waits() {
    let h = std::sync::Arc::new(H::new());
    h.register_default().await;
    let h2 = h.clone();
    let waiter =
        tokio::spawn(
            async move { h2.ok(&device(), "node_claim", json!({ "node": NODE, "wait_s": 5 })).await },
        );
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let id = h.queue(json!({})).await;
    let got = waiter.await.unwrap();
    assert_eq!(got["item"]["item_id"], id);
}

// --- review regressions ---------------------------------------------------------

async fn routed(h: &H) -> (String, String) {
    let tid = routed_task(h).await;
    let out = h
        .gated(&device(), "dispatch_task", json!({ "task_id": tid, "agent": "builder-1", "node": NODE }))
        .await;
    (out["run_id"].as_str().unwrap().to_string(), out["item_id"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn an_interrupted_cancel_of_a_routed_run_is_finished_by_the_queue() {
    // The cancel recorded its intent and was cut off; the item's wait then ran out.
    let h = H::new();
    h.register_default().await;
    h.sql("UPDATE nodes SET last_heartbeat = '2000-01-01T00:00:00+00:00'");
    let (run, item) = routed(&h).await;
    h.sql(&format!("UPDATE dispatch_runs SET termination_outcome = 'requested' WHERE run_id = '{run}'"));
    h.sql(&format!(
        "UPDATE node_dispatch SET wait_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = '{item}'"
    ));
    ua_tools::families::node_queue::sweep(&h.hub, None).unwrap();
    assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{run}'")), "cancelled");
    assert_eq!(
        h.scalar(&format!("SELECT termination_outcome FROM dispatch_runs WHERE run_id = '{run}'")),
        "confirmed"
    );

    // A claimed item whose lease lapsed: cancelled, cessation unknown.
    let h = H::new();
    h.register_default().await;
    let (run, item) = routed(&h).await;
    h.claim().await;
    h.sql(&format!("UPDATE dispatch_runs SET termination_outcome = 'requested' WHERE run_id = '{run}'"));
    h.sql(&format!(
        "UPDATE node_dispatch SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = '{item}'"
    ));
    ua_tools::families::node_queue::sweep(&h.hub, None).unwrap();
    assert_eq!(h.scalar(&format!("SELECT state FROM dispatch_runs WHERE run_id = '{run}'")), "cancelled");
    assert_eq!(
        h.scalar(&format!("SELECT termination_outcome FROM dispatch_runs WHERE run_id = '{run}'")),
        "unknown"
    );

    // The reaper finishes an interrupted cancel of a queued item.
    let h = H::new();
    h.register_default().await;
    let (run, item) = routed(&h).await;
    h.sql(&format!("UPDATE dispatch_runs SET termination_outcome = 'requested' WHERE run_id = '{run}'"));
    ua_tools::families::dispatch::reap_expired_leases(&h.hub).unwrap();
    assert_eq!(h.scalar(&format!("SELECT status FROM node_dispatch WHERE id = '{item}'")), "cancelled");
    assert_eq!(
        h.scalar(&format!("SELECT termination_outcome FROM dispatch_runs WHERE run_id = '{run}'")),
        "confirmed"
    );
}

#[tokio::test]
async fn a_routed_run_is_reported_by_its_node_not_by_the_session() {
    let h = H::new();
    h.register_default().await;
    let (run, item) = routed(&h).await;
    let prompt = h.scalar(&format!("SELECT prompt FROM node_dispatch WHERE id = '{item}'"));
    assert!(!prompt.as_str().unwrap().contains("dispatch_report_self"), "{prompt}");
    h.claim().await;
    let e = h
        .err(
            &device(),
            "dispatch_report_self",
            json!({ "run_id": run, "state": "finished", "evidence": "abc123" }),
        )
        .await;
    assert!(matches!(e, UaError::Conflict(_)), "{e:?}");
    let beat = h.ok(&device(), "node_heartbeat", json!({ "node": NODE, "running": item })).await;
    assert_eq!(beat["cancel"], json!([]));
}

#[tokio::test]
async fn an_unscoped_agent_gets_no_permission_or_follow_up() {
    let h = H::with(|cfg| {
        cfg.agent_scopes.insert("builder-1".into(), "none".into());
        cfg.agent_scopes.insert("lead-1".into(), "dispatch".into());
    });
    h.register_default().await;
    let id = h.queue(json!({ "backend": "acp:claude" })).await;
    h.claim().await;
    let ask = json!({ "node": NODE, "item_id": id, "session_id": "s", "tool_call": { "title": "x" } });
    let e = h.err(&device(), "node_permission", ask).await;
    assert!(!matches!(e, UaError::ApprovalRequired { .. }), "{e:?}");
    // The node's agent may otherwise send follow-ups; not while unscoped.
    let e = h
        .err(
            &device(),
            "node_followup",
            json!({ "item_id": id, "mode": "queue", "body": "x", "idempotency_key": "queue-0009" }),
        )
        .await;
    assert!(!matches!(e, UaError::ApprovalRequired { .. }), "{e:?}");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM approvals WHERE tool = 'acp_permission'"), json!(0));
    assert_eq!(h.scalar("SELECT COUNT(*) FROM approvals WHERE tool = 'node_followup'"), json!(0));
}

/// A routine that runs unattended under a human's label is an agent. Its
/// follow-up gets no human shortcut: into a session it did not request it is
/// refused, and into one requested under that label it waits for the same
/// one-time approval as any agent's.
#[tokio::test]
async fn an_unattended_routine_gets_no_human_shortcut_on_follow_ups() {
    let h = H::new();
    h.register_default().await;
    let routine = caller("operator", ActorKind::Agent);
    let id = h.queue(json!({ "backend": "acp:claude" })).await;
    h.claim().await;
    let ask =
        json!({ "item_id": id, "mode": "queue", "body": "also push", "idempotency_key": "routine-0001" });
    let e = h.err(&routine, "node_followup", ask.clone()).await;
    assert_eq!(reason(&e), "not_item_owner");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM node_followups"), json!(0));
    assert_eq!(h.scalar("SELECT COUNT(*) FROM approvals WHERE tool = 'node_followup'"), json!(0));

    // Requested under the human's label: allowed, behind the approval.
    h.sql(&format!("UPDATE node_dispatch SET created_by = 'operator' WHERE id = '{id}'"));
    let parked = h.err(&routine, "node_followup", ask.clone()).await;
    let UaError::ApprovalRequired { tool, .. } = parked else { panic!("expected an approval: {parked:?}") };
    assert_eq!(tool, "node_followup");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM node_followups"), json!(0));

    // The human, as themselves, still needs none.
    let f = h
        .ok(
            &human(),
            "node_followup",
            json!({ "item_id": id, "mode": "queue", "body": "also push", "idempotency_key": "human-0001" }),
        )
        .await;
    assert_eq!(f["approval"], "not_required_operator");
    assert_eq!(f["operator_authored"], true);
}

#[tokio::test]
async fn a_launch_key_belongs_to_its_caller_and_request() {
    let h = H::new();
    h.register_default().await;
    h.queue(json!({ "launch_key": "launch-0002" })).await;
    let mut args = json!({ "node": NODE, "backend": "codex", "prompt": "something else", "cwd": "/srv/work/repo", "launch_key": "launch-0002" });
    let e = h.err(&lead(), "node_dispatch", args.clone()).await;
    assert_eq!(reason(&e), "launch_key_reused");
    args["prompt"] = json!("fix the build");
    let e = h.err(&caller("snoop-1", ActorKind::Agent), "node_dispatch", args).await;
    assert_eq!(reason(&e), "launch_key_reused");
    assert!(!e.to_string().contains("nd-"), "nothing about the item leaks: {e}");
}

#[tokio::test]
async fn the_listing_limit_counts_only_visible_items() {
    let h = H::new();
    h.register_default().await;
    let mine = h.queue(json!({})).await;
    let other = caller("other-1", ActorKind::Agent);
    for i in 0..3 {
        let args = json!({ "node": NODE, "backend": "codex", "prompt": format!("p{i}"), "cwd": "/srv/work" });
        h.gated(&other, "node_dispatch", args).await;
    }
    let v = h.ok(&lead(), "node_items", json!({ "limit": 1 })).await;
    assert_eq!(v["items"][0]["item_id"], mine);
}

#[tokio::test]
async fn a_lapsed_item_is_reconciled_then_restartable() {
    let h = H::new();
    h.register_default().await;
    let id = h.queue(json!({})).await;
    h.claim().await;
    // Cancel is relayed once on the ledger however many beats it takes.
    h.manage(&lead(), "node_item_cancel", json!({ "item_id": id })).await.unwrap();
    for _ in 0..3 {
        h.ok(&device(), "node_heartbeat", json!({ "node": NODE, "running": id })).await;
    }
    assert_eq!(h.events("cancel_relayed"), 1);
    h.sql(&format!(
        "UPDATE node_dispatch SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE id = '{id}'"
    ));
    h.claim().await;
    let e = h
        .manage(
            &lead(),
            "node_item_reconcile",
            json!({ "item_id": id, "status": "killed", "note": "log shows it stopped" }),
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "not_item_owner");
    let r = h
        .manage(
            &device(),
            "node_item_reconcile",
            json!({ "item_id": id, "status": "killed", "note": "node spool shows it stopped" }),
        )
        .await
        .unwrap();
    assert_eq!(r["restartable"], true);
    let item = h.ok(&lead(), "node_items", json!({ "item_id": id })).await;
    assert_eq!(item["item"]["status"], "killed");
    assert_eq!(item["item"]["receipt"]["prior"]["reason"], "lease_expired_outcome_unknown");
    let parked = h.manage(&lead(), "node_item_restart", json!({ "item_id": id })).await.unwrap_err();
    assert!(matches!(parked, UaError::ApprovalRequired { .. }), "{parked:?}");
}

#[tokio::test]
async fn an_adopted_command_notifies_the_chosen_session() {
    let h = H::new();
    h.register_default().await;
    let session = h
        .ok(&lead(), "session_start", json!({ "kind": "interactive", "external_session_id": "ext-1" }))
        .await["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let params = json!({ "node": NODE, "argv": ["make"], "cwd": "/srv/work" });
    let parked = h.manage(&lead(), "node_command_start", params.clone()).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = parked else { panic!() };
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let id = h.manage(&lead(), "node_command_start", params).await.unwrap()["item_id"]
        .as_str()
        .unwrap()
        .to_string();
    h.manage(&lead(), "node_command_adopt", json!({ "item_id": id, "session_id": session })).await.unwrap();
    let token = h.claim().await["item"]["command"]["fence_token"].as_str().unwrap().to_string();
    h.ok(&device(), "node_receipt", json!({ "node": NODE, "item_id": id, "receipt": { "status": "failed", "attempt": 1, "exit_code": 2, "fence_token": token } }))
        .await;
    assert_eq!(h.scalar("SELECT target_session FROM message_index WHERE sender = 'hub-node'"), session);
}

/// Node command adoption is human-only: neither a lifecycle-operator agent
/// nor an unattended routine under a human's label may adopt another agent's
/// command; a human may.
#[tokio::test]
async fn command_adoption_is_for_a_verified_human_only() {
    let h = H::with(|c| c.lifecycle_operators = Some(vec!["operator".into(), "fleet-bot".into()]));
    h.register_default().await;
    let params = json!({ "node": NODE, "argv": ["make"], "cwd": "/srv/work" });
    let parked = h.manage(&lead(), "node_command_start", params.clone()).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = parked else { panic!() };
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    let id = h.manage(&lead(), "node_command_start", params).await.unwrap()["item_id"]
        .as_str()
        .unwrap()
        .to_string();
    let fleet = Caller { label: "fleet-bot".into(), ..lead() };
    let routine = Caller { kind: ActorKind::Agent, ..human() };
    for who in [fleet, routine] {
        let e = h.manage(&who, "node_command_adopt", json!({ "item_id": id })).await.unwrap_err();
        assert!(e.to_string().contains("may adopt"), "{}: {e}", who.label);
    }
    h.manage(&human(), "node_command_adopt", json!({ "item_id": id })).await.unwrap();
}
