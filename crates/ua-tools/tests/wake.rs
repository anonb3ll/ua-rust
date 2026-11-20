//! Idle-session wakes through the governed registry: consent (request, human
//! grant, decline), host scoping, the offer / check / receipt protocol and
//! its budget (debounce, floor, retry, final skips, breaker).

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const EXT: &str = "codex:0b6f1d2e-3c4a-4b5c-8d6e-7f8091a2b3c4";

struct W {
    hub: Hub,
    reg: Registry,
}

fn caller(label: &str, kind: ActorKind) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Http,
    }
}

fn agent(label: &str) -> Caller {
    caller(label, ActorKind::Agent)
}

fn human() -> Caller {
    caller("operator", ActorKind::Human)
}

fn code(e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    }
}

impl W {
    fn new() -> Self {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry() }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.call(who, tool, args.clone()).await.unwrap_or_else(|e| panic!("{tool}({args}) failed: {e}"))
    }

    async fn manage(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "coordination_manage", json!({ "action": action, "params": params })).await
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

    fn scalar_i(&self, q: &str) -> i64 {
        let q = q.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&q, [], |r| r.get(0))?)).unwrap()
    }

    /// `node-agent` registers node `name`; `builder-1` opens a session on
    /// `host`. Returns the session id.
    async fn setup(&self, node: &str, host: &str) -> String {
        self.ok(
            &agent("node-agent"),
            "node_register",
            json!({ "node": node, "facts": { "backends": ["codex"] } }),
        )
        .await;
        let s = self
            .ok(
                &agent("builder-1"),
                "session_start",
                json!({ "kind": "interactive", "external_session_id": EXT, "host": host }),
            )
            .await;
        s["session_id"].as_str().unwrap().to_string()
    }

    async fn arm(&self, sid: &str) {
        self.manage(&agent("builder-1"), "session_wake_opt_in", json!({ "session_id": sid })).await.unwrap();
        self.manage(&human(), "session_wake_grant", json!({ "session_id": sid })).await.unwrap();
    }

    async fn send(&self, act: &str, expects_reply: bool) {
        self.ok(
            &agent("lead-1"),
            "message_send",
            json!({ "act": act, "to_agent": "builder-1", "body": "please look", "expects_reply": expects_reply }),
        )
        .await;
    }

    /// Age all mail past the debounce.
    fn age_mail(&self) {
        self.sql(
            "UPDATE message_index SET created_at = strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now', '-90 seconds')",
        );
    }

    async fn poll(&self, node: &str) -> Vec<Value> {
        let v = self.ok(&agent("node-agent"), "node_wake", json!({ "node": node, "offer_version": 3 })).await;
        v["wakes"].as_array().unwrap().clone()
    }

    async fn check(&self, offer: &Value) -> Value {
        self.ok(
            &agent("node-agent"),
            "node_wake_check",
            json!({
                "node": "box", "session_id": offer["session_id"], "seq": offer["newest_seq"],
                "expires_at": offer["expires_at"], "offer_id": offer["offer_id"],
            }),
        )
        .await
    }

    async fn receipt(&self, offer: &Value, outcome: &str, reason: Option<&str>) -> Value {
        let mut body = json!({
            "node": "box", "session_id": offer["session_id"], "seq": offer["newest_seq"], "outcome": outcome,
            "expires_at": offer["expires_at"], "offer_id": offer["offer_id"],
        });
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        if outcome == "delivered" {
            body["delivered_at"] = json!(ua_core::time::now_ms() as f64 / 1000.0);
        }
        self.ok(&agent("node-agent"), "node_wake_receipt", body).await
    }

    async fn status(&self, sid: &str) -> Value {
        self.manage(&human(), "session_wake_status", json!({ "session_id": sid })).await.unwrap()
    }
}

#[tokio::test]
async fn consent_takes_a_request_and_a_human_grant_and_a_decline_sticks() {
    let w = W::new();
    let sid = w.setup("box", "box.local").await;

    // Only the session's own agent asks; asking enables nothing.
    let e =
        w.manage(&agent("lead-1"), "session_wake_opt_in", json!({ "session_id": sid })).await.unwrap_err();
    assert_eq!(code(&e), "not_session_owner");
    let v = w.manage(&agent("builder-1"), "session_wake_opt_in", json!({ "session_id": sid })).await.unwrap();
    assert_eq!(v["changed"], true);
    assert_eq!(v["state"]["requested"], true);
    assert_eq!(v["state"]["granted"], false);
    w.send("request", false).await;
    w.age_mail();
    assert!(w.poll("box").await.is_empty(), "a request without a grant is never offered");

    // An agent cannot grant, even its own session.
    let e =
        w.manage(&agent("builder-1"), "session_wake_grant", json!({ "session_id": sid })).await.unwrap_err();
    assert_eq!(code(&e), "human_required");
    let v = w.manage(&human(), "session_wake_grant", json!({ "session_id": sid })).await.unwrap();
    assert_eq!(v["granted"], true);
    assert_eq!(v["requested"], true);
    assert_eq!(w.poll("box").await.len(), 1);

    // The session's own agent declines; the grant goes and the outstanding
    // offer with it. Asking again does not clear the decline.
    let v = w
        .manage(
            &agent("builder-1"),
            "session_wake_decline",
            json!({ "session_id": sid, "reason": "not now" }),
        )
        .await
        .unwrap();
    assert_eq!(v["declined"], true);
    assert_eq!(v["granted"], false);
    assert_eq!(v["decline_reason"], "not now");
    let e =
        w.manage(&agent("lead-1"), "session_wake_decline", json!({ "session_id": sid })).await.unwrap_err();
    assert_eq!(code(&e), "not_authorized");
    w.manage(&agent("builder-1"), "session_wake_opt_in", json!({ "session_id": sid, "wake": false }))
        .await
        .unwrap();
    w.manage(&agent("builder-1"), "session_wake_opt_in", json!({ "session_id": sid })).await.unwrap();
    assert_eq!(w.status(&sid).await["declined"], true);
    assert_eq!(w.scalar_i("SELECT COUNT(*) FROM session_wake_offers WHERE invalidated_at IS NULL"), 0);

    // Only a later grant clears it.
    w.manage(&human(), "session_wake_grant", json!({ "session_id": sid })).await.unwrap();
    let st = w.status(&sid).await;
    assert_eq!((st["declined"].clone(), st["granted"].clone()), (json!(false), json!(true)));
    assert_eq!(w.scalar_i("SELECT COUNT(*) FROM event_log WHERE channel = 'agent.wake.grant'"), 3);
    assert_eq!(w.scalar_i("SELECT COUNT(*) FROM event_log WHERE channel = 'agent.wake.request'"), 3);

    // An agent sees its own sessions' wake state; another agent learns nothing.
    let e =
        w.manage(&agent("lead-1"), "session_wake_status", json!({ "session_id": sid })).await.unwrap_err();
    assert_eq!(code(&e), "not_found");
    let v = w.manage(&agent("builder-1"), "session_wake_status", json!({})).await.unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["summary"]["granted"], 1);
    let v = w.manage(&agent("lead-1"), "session_wake_status", json!({})).await.unwrap();
    assert_eq!(v["count"], 0);
}

#[tokio::test]
async fn offers_go_only_to_the_node_on_the_sessions_host() {
    let w = W::new();
    let sid = w.setup("box", "BOX.example.com").await;
    w.ok(
        &agent("node-agent"),
        "node_register",
        json!({ "node": "other", "facts": { "backends": ["codex"] } }),
    )
    .await;
    w.arm(&sid).await;
    w.send("request", false).await;
    w.age_mail();

    assert!(w.poll("other").await.is_empty(), "another host sees nothing");
    let e = w
        .call(&agent("lead-1"), "node_wake", json!({ "node": "box", "offer_version": 3 }))
        .await
        .unwrap_err();
    assert_eq!(code(&e), "node_owned_elsewhere");
    let e = w.call(&human(), "node_wake", json!({ "node": "box", "offer_version": 3 })).await.unwrap_err();
    assert_eq!(code(&e), "agent_identity_required");
    let e = w.call(&agent("node-agent"), "node_wake", json!({ "node": "box" })).await.unwrap_err();
    assert!(e.to_string().contains("offer_version=3"), "{e}");

    let offers = w.poll("box").await;
    assert_eq!(offers.len(), 1);
    let o = &offers[0];
    assert_eq!(o["session_id"], sid);
    assert_eq!(o["external_session_id"], EXT);
    assert_eq!(o["unread"], 1);
    assert_eq!(o["offer_id"].as_str().unwrap().len(), 32);
    let keys: Vec<&String> = o.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 6, "ids and counts only: {o}");
    assert!(!o.to_string().contains("please look"), "no message text reaches a wake");
}

#[tokio::test]
async fn an_offer_is_checked_once_and_its_receipt_is_idempotent() {
    let w = W::new();
    let sid = w.setup("box", "box").await;
    w.arm(&sid).await;

    // inform without expects_reply waits for the hooks; a fresh request is
    // held by the debounce.
    w.send("inform", false).await;
    w.age_mail();
    assert!(w.poll("box").await.is_empty());
    w.send("request", false).await;
    assert!(w.poll("box").await.is_empty(), "debounce");
    w.age_mail();
    let offer = w.poll("box").await.remove(0);
    assert_eq!(offer["unread"], 2, "the count is every unread message");
    assert!(w.poll("box").await.is_empty(), "an outstanding offer blocks a re-offer");

    let c = w.check(&offer).await;
    assert_eq!(c["valid"], true, "{c}");
    assert!(c["remaining_s"].as_f64().unwrap() > 100.0);
    assert_eq!(w.check(&offer).await["valid"], false, "one attempt per offer");
    let mut forged = offer.clone();
    forged["expires_at"] = json!(offer["expires_at"].as_f64().unwrap() + 60.0);
    assert_eq!(w.check(&forged).await["valid"], false);

    let r = w.receipt(&offer, "delivered", None).await;
    assert_eq!((r["recorded"].clone(), r["duplicate"].clone()), (json!(true), json!(false)));
    let r = w.receipt(&offer, "delivered", None).await;
    assert_eq!((r["recorded"].clone(), r["duplicate"].clone()), (json!(false), json!(true)));
    let st = w.status(&sid).await;
    assert_eq!(st["last_outcome"], "delivered");
    assert_eq!(st["unacked_wakes"], 1);
    assert_eq!(st["wakes_last_hour"], 1);
    assert_eq!(w.scalar_i("SELECT COUNT(*) FROM event_log WHERE channel = 'agent.wake.attempt'"), 1);

    // New mail inside the floor waits; past the floor it is offered.
    w.send("query", false).await;
    w.age_mail();
    assert!(w.poll("box").await.is_empty(), "floor");
    w.sql(
        "UPDATE session_wake SET last_wake_at = last_wake_at - 700, last_attempt_at = last_attempt_at - 700",
    );
    let offer = w.poll("box").await.remove(0);
    assert_eq!(offer["unread"], 3);

    // A busy pane is retried after the hold; a final skip gives the mail up.
    w.check(&offer).await;
    w.receipt(&offer, "skipped", Some("focused")).await;
    assert_eq!(w.status(&sid).await["attempts"], 1);
    assert!(w.poll("box").await.is_empty(), "retry hold");
    w.sql(
        "UPDATE session_wake SET retry_at = retry_at - 60, last_wake_at = last_wake_at - 700, \
         last_attempt_at = last_attempt_at - 700",
    );
    let offer = w.poll("box").await.remove(0);
    w.receipt(&offer, "skipped", Some("no_match")).await;
    let st = w.status(&sid).await;
    assert_eq!((st["attempts"].clone(), st["retry_at"].clone()), (json!(0), Value::Null));
    w.sql(
        "UPDATE session_wake SET last_wake_at = last_wake_at - 700, last_attempt_at = last_attempt_at - 700",
    );
    assert!(w.poll("box").await.is_empty(), "the given-up set is left to the hooks");

    // A receipt from a stranger's node or for an unknown session is refused.
    let e = w
        .call(
            &agent("lead-1"),
            "node_wake_receipt",
            json!({ "node": "box", "session_id": sid, "seq": 1, "outcome": "failed",
                    "expires_at": 1.0, "offer_id": "0".repeat(32) }),
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), "node_owned_elsewhere");
    let e = w
        .call(
            &agent("node-agent"),
            "node_wake_receipt",
            json!({ "node": "box", "session_id": "nope", "seq": 1, "outcome": "failed",
                    "expires_at": 1.0, "offer_id": "0".repeat(32) }),
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), "not_found");
}

#[tokio::test]
async fn the_breaker_pauses_a_session_until_it_reads_its_mail() {
    let w = W::new();
    let sid = w.setup("box", "box").await;
    w.arm(&sid).await;
    w.send("handoff", false).await;
    w.age_mail();
    w.sql(&format!(
        "UPDATE session_wake SET unacked_wakes = 3, last_wake_at = (julianday('now') - 2440587.5) * 86400.0 - 700 \
         WHERE session_id = '{sid}'"
    ));
    assert!(w.poll("box").await.is_empty());
    assert_eq!(w.status(&sid).await["paused_reason"], "no_inbox_read");

    // Reading the inbox through the session resets it.
    w.ok(
        &agent("builder-1"),
        "coordination_manage",
        json!({ "action": "message_inbox", "params": { "session_id": sid } }),
    )
    .await;
    w.send("request", true).await;
    w.age_mail();
    // The read lands in the same second as the reset check would compare;
    // move the last wake back so the read is strictly after it.
    w.sql("UPDATE session_wake SET last_wake_at = last_wake_at - 5");
    let offers = w.poll("box").await;
    assert_eq!(offers.len(), 1, "a read resets the breaker");
    assert_eq!(w.status(&sid).await["paused_reason"], Value::Null);
}

#[tokio::test]
async fn revoking_consent_invalidates_the_outstanding_offer() {
    let w = W::new();
    let sid = w.setup("box", "box").await;
    w.arm(&sid).await;
    w.send("request", false).await;
    w.age_mail();
    let offer = w.poll("box").await.remove(0);
    w.manage(&human(), "session_wake_grant", json!({ "session_id": sid, "grant": false })).await.unwrap();
    assert_eq!(w.check(&offer).await["valid"], false);
    let r = w.receipt(&offer, "delivered", None).await;
    assert_eq!(r["recorded"], false, "an unreserved offer cannot be reported delivered");
}

#[tokio::test]
async fn live_sessions_keep_an_idle_granted_session_open() {
    let w = W::new();
    let sid = w.setup("box", "box").await;
    w.arm(&sid).await;
    w.sql(&format!(
        "UPDATE agent_sessions SET status = 'abandoned', exit_status = 'no_heartbeat' WHERE id = '{sid}'"
    ));
    w.ok(
        &agent("node-agent"),
        "node_wake",
        json!({ "node": "box", "offer_version": 3, "live_sessions": [EXT, "claude-other"] }),
    )
    .await;
    assert_eq!(w.status(&sid).await["session_status"], "running");
    assert_eq!(w.scalar_i("SELECT COUNT(*) FROM event_log WHERE channel = 'agent.wake.session_revived'"), 1);

    // A session its agent ended stays ended.
    w.sql(&format!("UPDATE agent_sessions SET status = 'completed', exit_status = 'ok' WHERE id = '{sid}'"));
    w.ok(
        &agent("node-agent"),
        "node_wake",
        json!({ "node": "box", "offer_version": 3, "live_sessions": [EXT] }),
    )
    .await;
    assert_eq!(w.status(&sid).await["session_status"], "completed");
    let e = w
        .call(
            &agent("node-agent"),
            "node_wake",
            json!({ "node": "box", "offer_version": 3, "live_sessions": vec!["x"; 65] }),
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), "invalid_argument");
}
