//! Node session credentials through the governed registry: the mint's
//! refusals, the grant a verified credential runs under, and every way a
//! credential stops working.

use std::sync::Arc;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::families::node_queue::credentials::{self, Verified};
use ua_tools::{Hub, Registry, builtin_registry, grant};

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

impl H {
    fn new() -> Self {
        Self::with(|c| c.session_credentials_enabled = true)
    }

    fn with(f: impl FnOnce(&mut Config)) -> Self {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        cfg.lifecycle_operators = Some(vec!["operator".into(), "fleet-bot".into()]);
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

    async fn gated(&self, who: &Caller, tool: &str, args: Value) -> Value {
        let parked = self.call(who, tool, args.clone()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, .. } = parked else {
            panic!("expected an approval: {parked:?}")
        };
        self.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
        self.ok(who, tool, args).await
    }

    async fn register(&self, features: Value) {
        let facts = json!({
            "backends": ["codex", "acp:claude"],
            "worktree_roots": [{ "path": "/srv/work", "realpath": "/srv/work", "exists": true }],
            "node_features": features,
        });
        self.ok(&device(), "node_register", json!({ "node": NODE, "facts": facts })).await;
    }

    async fn task(&self, title: &str) -> i64 {
        let t = self.ok(&lead(), "task_add", json!({ "title": title })).await;
        t["id"].as_i64().or_else(|| t["task"]["id"].as_i64()).unwrap_or_else(|| panic!("task id in {t}"))
    }

    /// Queue an item and claim it; returns its id.
    async fn running(&self, backend: &str, task_id: Option<i64>) -> String {
        let mut args = json!({ "node": NODE, "backend": backend, "prompt": "work", "cwd": "/srv/work/repo" });
        if let Some(t) = task_id {
            args["task_id"] = json!(t);
        }
        let id = self.gated(&lead(), "node_dispatch", args).await["item_id"].as_str().unwrap().to_string();
        let claimed = self.ok(&device(), "node_claim", json!({ "node": NODE })).await;
        assert_eq!(claimed["item"]["item_id"], id);
        id
    }

    async fn mint(&self, item: &str, attempt: i64) -> Result<Value, UaError> {
        self.call(
            &device(),
            "node_session_credential",
            json!({ "node": NODE, "item_id": item, "attempt": attempt }),
        )
        .await
    }

    fn verify(&self, token: &str) -> Result<Verified, &'static str> {
        credentials::verify(&self.hub, token).map_err(|r| r.check)
    }

    /// Call a tool as a verified credential would over HTTP.
    async fn as_session(&self, v: &Verified, tool: &str, args: Value) -> Result<Value, UaError> {
        let c = Caller {
            label: v.subject.clone(),
            kind: ActorKind::Agent,
            profile: Profile::AcpSession,
            enforce_profile: true,
            session_key: None,
            transport: Transport::Mcp,
            org_id: ua_core::DEFAULT_ORG.into(),
        };
        grant::scope(Some(Arc::new(v.grant.clone())), self.reg.call(&self.hub, &c, tool, args)).await
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

    fn events(&self, channel: &str) -> i64 {
        self.scalar(&format!("SELECT COUNT(*) FROM event_log WHERE channel = '{channel}'")).as_i64().unwrap()
    }
}

#[tokio::test]
async fn a_credential_is_minted_once_and_runs_under_its_grant() {
    let h = H::new();
    h.register(json!(["acp_session_mcp", "session_settings"])).await;
    let task = h.task("port the parser").await;
    let other = h.task("something else").await;
    let item = h.running("acp:claude", Some(task)).await;

    let out = h.mint(&item, 1).await.unwrap();
    let value = out["credential"].as_str().unwrap().to_string();
    assert!(value.starts_with("uas_") && value.len() == 47, "{value}");
    let cid = out["credential_id"].as_str().unwrap().to_string();
    assert_eq!(cid.len(), 16);
    assert_eq!(out["mcp_server_name"], "unified-agent");
    let tools: Vec<&str> = out["tools"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(tools.contains(&"task_comment") && tools.contains(&"task_list"), "{tools:?}");
    assert!(!tools.iter().any(|t| t.starts_with("memory_")), "{tools:?}");
    assert!(!tools.contains(&"task_add") && !tools.contains(&"node_session_credential"), "{tools:?}");

    // Only the digest is stored, and no event carries the value.
    let stored =
        h.scalar(&format!("SELECT token_sha256 FROM session_credentials WHERE credential_id = '{cid}'"));
    assert_eq!(stored.as_str().unwrap().len(), 64);
    let leaked = h.scalar(&format!("SELECT COUNT(*) FROM event_log WHERE payload LIKE '%{}%'", &value[4..]));
    assert_eq!(leaked, json!(0));
    assert_eq!(h.events("hub.session_credential.minted"), 1);

    // The expiry is the claim's lease deadline.
    let claimed_at = h.scalar(&format!("SELECT claimed_at FROM node_dispatch WHERE id = '{item}'"));
    let claimed = jiff::Timestamp::from_str_ish(claimed_at.as_str().unwrap());
    let expires = jiff::Timestamp::from_str_ish(out["expires_at"].as_str().unwrap());
    assert_eq!((expires - claimed).as_secs(), 3600 + 300);

    let v = h.verify(&value).unwrap();
    assert_eq!(v.subject, "builder-1");
    assert_eq!(v.grant.item_id, item);
    assert_eq!(v.grant.task_id, Some(task));

    // The grant: its tools only, and comments on its own task only.
    h.as_session(&v, "task_list", json!({})).await.unwrap();
    let e = h.as_session(&v, "task_add", json!({ "title": "x" })).await.unwrap_err();
    assert_eq!(reason(&e), "profile_denied");
    let e = h
        .as_session(&v, "node_session_credential", json!({ "node": NODE, "item_id": item, "attempt": 1 }))
        .await;
    assert_eq!(reason(&e.unwrap_err()), "profile_denied");
    h.as_session(
        &v,
        "task_comment",
        json!({ "action": "append", "params": { "task_id": task, "body": "progress" } }),
    )
    .await
    .unwrap();
    let e = h
        .as_session(
            &v,
            "task_comment",
            json!({ "action": "append", "params": { "task_id": other, "body": "x" } }),
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "session_task_scope");
    let listed = h.reg.visible_to(&Caller { profile: Profile::AcpSession, ..device() }).count();
    let in_scope = grant::scope(Some(Arc::new(v.grant.clone())), async {
        h.reg.visible_to(&Caller { profile: Profile::AcpSession, ..device() }).count()
    })
    .await;
    assert_eq!(in_scope, v.grant.tools.len());
    assert_eq!(listed, 0, "the profile without a grant sees nothing");

    // A second mint for the same attempt supersedes the first.
    let second = h.mint(&item, 1).await.unwrap();
    assert_eq!(h.verify(&value).unwrap_err(), "unknown_or_revoked");
    let second = second["credential"].as_str().unwrap().to_string();
    h.verify(&second).unwrap();
    assert_eq!(
        h.scalar(&format!("SELECT revoke_reason FROM session_credentials WHERE credential_id = '{cid}'")),
        "superseded"
    );

    // The receipt ends the session.
    h.ok(
        &device(),
        "node_receipt",
        json!({ "node": NODE, "item_id": item, "receipt": { "status": "finished", "attempt": 1 } }),
    )
    .await;
    assert_eq!(h.verify(&second).unwrap_err(), "unknown_or_revoked");
    assert_eq!(
        h.scalar("SELECT COUNT(*) FROM session_credentials WHERE revoke_reason = 'session_end'"),
        json!(1)
    );
    assert!(h.events("hub.session_credential.revoked") >= 2);
}

trait Ish {
    fn from_str_ish(s: &str) -> jiff::Timestamp;
}

impl Ish for jiff::Timestamp {
    fn from_str_ish(s: &str) -> jiff::Timestamp {
        s.parse().unwrap()
    }
}

#[tokio::test]
async fn the_mint_refuses_with_the_python_reasons() {
    // Off by default.
    let off = H::with(|_| {});
    off.register(json!(["acp_session_mcp", "session_settings"])).await;
    let item = off.running("acp:claude", None).await;
    assert_eq!(reason(&off.mint(&item, 1).await.unwrap_err()), "disabled");

    // A node that does not advertise the feature.
    let h = H::new();
    h.register(json!(["session_settings"])).await;
    let item = h.running("acp:claude", None).await;
    assert_eq!(reason(&h.mint(&item, 1).await.unwrap_err()), "node_feature_missing");

    let h = H::new();
    h.register(json!(["acp_session_mcp", "session_settings"])).await;
    let codex = h.running("codex", None).await;
    assert_eq!(reason(&h.mint(&codex, 1).await.unwrap_err()), "not_acp");
    h.ok(
        &device(),
        "node_receipt",
        json!({ "node": NODE, "item_id": codex, "receipt": { "status": "finished", "attempt": 1 } }),
    )
    .await;
    assert_eq!(reason(&h.mint(&codex, 1).await.unwrap_err()), "not_acp");

    let task = h.task("t").await;
    let item = h.running("acp:claude", Some(task)).await;
    assert_eq!(reason(&h.mint(&item, 2).await.unwrap_err()), "stale_attempt");
    let e = h
        .call(&device(), "node_session_credential", json!({ "node": NODE, "item_id": item, "attempt": 0 }))
        .await;
    assert!(matches!(e, Err(UaError::InvalidArgument(_))));
    // Another agent's node.
    let e = h
        .call(&lead(), "node_session_credential", json!({ "node": NODE, "item_id": item, "attempt": 1 }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "node_binding");
    // A human never mints.
    let e = h
        .call(&human(), "node_session_credential", json!({ "node": NODE, "item_id": item, "attempt": 1 }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "agent_identity_required");

    h.sql(&format!("UPDATE tasks SET status = 'done' WHERE id = {task}"));
    assert_eq!(reason(&h.mint(&item, 1).await.unwrap_err()), "task_closed");
    h.sql(&format!("UPDATE tasks SET status = 'open' WHERE id = {task}"));
    h.sql(
        "INSERT INTO agent_lifecycle (agent, state, action, actor, since) \
         VALUES ('builder-1', 'retired', 'retire', 'operator', '2026-01-01T00:00:00+00:00')",
    );
    assert_eq!(reason(&h.mint(&item, 1).await.unwrap_err()), "agent_retired");
    h.sql("DELETE FROM agent_lifecycle");
    h.mint(&item, 1).await.unwrap();

    h.manage(&lead(), "node_item_cancel", json!({ "item_id": item })).await.unwrap();
    assert_eq!(reason(&h.mint(&item, 1).await.unwrap_err()), "cancel_requested");
    // The cancel revoked the minted one.
    assert_eq!(
        h.scalar("SELECT COUNT(*) FROM session_credentials WHERE revoke_reason = 'cancelled'"),
        json!(1)
    );
    assert!(h.events("hub.session_credential.refused") >= 1);

    // An item queued but not yet claimed.
    let h = H::new();
    h.register(json!(["acp_session_mcp", "session_settings"])).await;
    let args = json!({ "node": NODE, "backend": "acp:claude", "prompt": "w", "cwd": "/srv/work/repo" });
    let queued = h.gated(&lead(), "node_dispatch", args).await["item_id"].as_str().unwrap().to_string();
    assert_eq!(reason(&h.mint(&queued, 1).await.unwrap_err()), "item_not_claimed");

    // The item's agent configured as a human identity.
    let h = H::with(|c| {
        c.session_credentials_enabled = true;
        c.human_identities.push("builder-1".into());
    });
    h.register(json!(["acp_session_mcp", "session_settings"])).await;
    let item = h.running("acp:claude", None).await;
    assert_eq!(reason(&h.mint(&item, 1).await.unwrap_err()), "human_subject");
}

async fn fresh(h: &H, item: &str) -> String {
    h.mint(item, 1).await.unwrap()["credential"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_credential_lapses_slides_and_is_revoked() {
    let h = H::new();
    h.register(json!(["acp_session_mcp", "session_settings"])).await;
    let task = h.task("t").await;
    let item = h.running("acp:claude", Some(task)).await;

    // Malformed and unknown values.
    assert_eq!(h.verify("uas_short").unwrap_err(), "unknown");
    assert_eq!(h.verify(&format!("uas_{}", "A".repeat(43))).unwrap_err(), "unknown_or_revoked");

    // A heartbeat for the item slides the idle window, never past the expiry.
    let value = fresh(&h, &item).await;
    h.sql("UPDATE session_credentials SET idle_expires_at = strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now', '+20 seconds')");
    h.ok(&device(), "node_heartbeat", json!({ "node": NODE, "running": item })).await;
    let idle = h.scalar("SELECT idle_expires_at FROM session_credentials WHERE revoked_at IS NULL");
    let left =
        (idle.as_str().unwrap().parse::<jiff::Timestamp>().unwrap() - jiff::Timestamp::now()).as_secs();
    assert!(left > 500, "slid to {idle}");

    // An idle window that lapsed is written as a revocation on the next use.
    h.sql("UPDATE session_credentials SET idle_expires_at = '2020-01-01T00:00:00+00:00' WHERE revoked_at IS NULL");
    assert_eq!(h.verify(&value).unwrap_err(), "idle_expired");
    assert_eq!(h.scalar("SELECT revoke_reason FROM session_credentials"), "idle_expired");

    // A closed task ends access.
    let value = fresh(&h, &item).await;
    h.verify(&value).unwrap();
    h.sql(&format!("UPDATE tasks SET status = 'done' WHERE id = {task}"));
    assert_eq!(h.verify(&value).unwrap_err(), "task_closed");
    h.sql(&format!("UPDATE tasks SET status = 'open' WHERE id = {task}"));

    // A node gone quiet.
    let value = fresh(&h, &item).await;
    h.sql("UPDATE nodes SET last_heartbeat = '2020-01-01T00:00:00+00:00'");
    assert_eq!(h.verify(&value).unwrap_err(), "node_stale");
    h.ok(&device(), "node_heartbeat", json!({ "node": NODE })).await;
    h.verify(&value).unwrap();

    // Turning the setting off refuses every outstanding credential.
    let mut cfg = h.hub.cfg().clone();
    cfg.session_credentials_enabled = false;
    let off = Hub::new(cfg, h.hub.db().clone());
    assert_eq!(credentials::verify(&off, &value).unwrap_err().check, "flag_off");

    // Operators (verified humans) revoke; nobody else does, a lifecycle
    // operator included.
    let e = h.manage(&lead(), "session_credential_revoke", json!({ "item_id": item })).await.unwrap_err();
    assert_eq!(reason(&e), "not_operator");
    let fleet = Caller { label: "fleet-bot".into(), ..lead() };
    let e = h.manage(&fleet, "session_credential_revoke", json!({ "item_id": item })).await.unwrap_err();
    assert_eq!(reason(&e), "not_operator");
    let e = h.manage(&human(), "session_credential_revoke", json!({ "item_id": item, "node": NODE })).await;
    assert!(matches!(e, Err(UaError::InvalidArgument(_))));
    let out = h.manage(&human(), "session_credential_revoke", json!({ "item_id": item })).await.unwrap();
    assert_eq!(out["count"], 1);
    assert_eq!(out["credentials"][0]["state"], "revoked");
    assert_eq!(out["credentials"][0]["revoke_reason"], "operator");
    assert!(out.to_string().find("uas_").is_none(), "{out}");
    assert_eq!(h.verify(&value).unwrap_err(), "unknown_or_revoked");

    // A lapsed lease revokes too.
    let value = fresh(&h, &item).await;
    h.sql("UPDATE node_dispatch SET lease_expires_at = '2020-01-01T00:00:00+00:00'");
    ua_tools::families::node_queue::sweep(&h.hub, None).unwrap();
    assert_eq!(h.verify(&value).unwrap_err(), "unknown_or_revoked");
    assert_eq!(
        h.scalar("SELECT COUNT(*) FROM session_credentials WHERE revoke_reason = 'lease_expired'"),
        json!(1)
    );
}

#[tokio::test]
async fn retiring_the_agent_revokes_its_credentials() {
    let h = H::new();
    h.register(json!(["acp_session_mcp", "session_settings"])).await;
    let item = h.running("acp:claude", None).await;
    let value = h.mint(&item, 1).await.unwrap()["credential"].as_str().unwrap().to_string();
    h.manage(&human(), "agent_retire", json!({ "agent": "builder-1", "reason": "decommissioned" }))
        .await
        .unwrap();
    assert!(h.verify(&value).is_err());
    assert_eq!(h.scalar("SELECT COUNT(*) FROM session_credentials WHERE revoked_at IS NULL"), json!(0));
}

#[tokio::test]
async fn the_hub_advertises_session_credentials_at_registration() {
    let h = H::new();
    let out = h.ok(&device(), "node_register", json!({ "node": NODE })).await;
    assert!(out["hub_features"].as_array().unwrap().contains(&json!("acp_session_mcp")), "{out}");
    // A managed token never takes the session-credential prefix.
    let e = h
        .err(
            &human(),
            "agent_token_issue",
            json!({ "agent_label": "builder-1", "value": format!("uas_{}", "a".repeat(40)) }),
        )
        .await;
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");
}

#[tokio::test]
async fn the_acp_session_profile_cannot_be_activated_or_used_without_a_grant() {
    let h = H::new();
    // Not by an agent (it ranks below developer), not by a human.
    let agent = Caller { enforce_profile: false, ..device() };
    for who in [agent, Caller { session_key: Some("s2".into()), ..human() }] {
        let e = h.err(&who, "profile_activate", json!({ "profile": "acp-session" })).await;
        assert_eq!(reason(&e), "profile_reserved", "{}", who.label);
    }
    // A caller that somehow holds the profile, with no grant bound, gets
    // nothing: not even the profile's own tools.
    let orphan = Caller { profile: Profile::AcpSession, ..device() };
    let task = h.task("t").await;
    for (tool, args) in [
        ("task_comment", json!({ "action": "append", "params": { "task_id": task, "body": "x" } })),
        ("evidence_report", json!({})),
        ("task_list", json!({})),
        ("profile_status", json!({})),
    ] {
        let e = h.err(&orphan, tool, args).await;
        assert_eq!(reason(&e), "session_grant_required", "{tool}");
    }
    let unenforced = Caller { enforce_profile: false, ..orphan.clone() };
    let e = h.err(&unenforced, "task_list", json!({})).await;
    assert_eq!(reason(&e), "session_grant_required");
    assert_eq!(h.reg.visible_to(&orphan).count(), 0);
    // A policy overlay or profile default naming it is refused as well.
    assert!(!ua_tools::policy::overlay_allowed(Profile::AcpSession, Profile::Developer, ["task_list"]));
}

#[tokio::test]
async fn a_credential_reads_only_its_own_task() {
    let h = H::new();
    h.register(json!(["acp_session_mcp", "session_settings"])).await;
    let task = h.task("port the parser").await;
    let other = h.task("something else").await;
    let item = h.running("acp:claude", Some(task)).await;
    let value = h.mint(&item, 1).await.unwrap()["credential"].as_str().unwrap().to_string();
    let v = h.verify(&value).unwrap();

    // session_packet: defaults to the grant's task; another task is refused.
    let p = h.as_session(&v, "session_packet", json!({})).await.unwrap();
    assert_eq!(p["task"]["id"], json!(task), "{p}");
    h.as_session(&v, "session_packet", json!({ "task_id": task })).await.unwrap();
    for args in [json!({ "task_id": other }), json!({ "session_id": "s-other" })] {
        let e = h.as_session(&v, "session_packet", args).await.unwrap_err();
        assert_eq!(reason(&e), "session_task_scope");
    }

    // evidence_report: the grant's task only.
    let r = h.as_session(&v, "evidence_report", json!({})).await.unwrap();
    let ids: Vec<i64> =
        r["records"].as_array().unwrap().iter().filter_map(|x| x["task_id"].as_i64()).collect();
    assert_eq!(ids, vec![task], "{r}");
    for args in [json!({ "task_id": other }), json!({ "project_id": other })] {
        let e = h.as_session(&v, "evidence_report", args).await.unwrap_err();
        assert_eq!(reason(&e), "session_task_scope");
    }

    // task_list: whatever the filters, at most the grant's task.
    let l = h.as_session(&v, "task_list", json!({ "status": "all" })).await.unwrap();
    let ids: Vec<i64> = l["tasks"].as_array().unwrap().iter().filter_map(|x| x["id"].as_i64()).collect();
    assert_eq!(ids, vec![task], "{l}");
    let l = h.as_session(&v, "task_list", json!({ "status": "all", "query": "something" })).await.unwrap();
    assert!(l["tasks"].as_array().unwrap().iter().all(|x| x["id"] == json!(task)), "{l}");
    // Outside a grant the same caller label lists both.
    let all = h.ok(&device(), "task_list", json!({ "status": "all" })).await;
    assert!(all["tasks"].as_array().unwrap().len() >= 2);

    // An item without a task reads no task at all.
    h.ok(
        &device(),
        "node_receipt",
        json!({ "node": NODE, "item_id": item, "receipt": { "status": "finished", "attempt": 1 } }),
    )
    .await;
    let bare = h.running("acp:claude", None).await;
    let value = h.mint(&bare, 1).await.unwrap()["credential"].as_str().unwrap().to_string();
    let v = h.verify(&value).unwrap();
    let l = h.as_session(&v, "task_list", json!({ "status": "all" })).await.unwrap();
    assert_eq!(l["tasks"], json!([]));
    let e = h.as_session(&v, "session_packet", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), "session_task_scope");
}

#[tokio::test]
async fn the_mint_refuses_an_item_not_bound_to_the_nodes_owner() {
    let h = H::new();
    h.register(json!(["acp_session_mcp", "session_settings"])).await;
    let item = h.running("acp:claude", None).await;
    h.sql(&format!("UPDATE node_dispatch SET agent = 'builder-2' WHERE id = '{item}'"));
    assert_eq!(reason(&h.mint(&item, 1).await.unwrap_err()), "node_binding");
    assert_eq!(h.scalar("SELECT COUNT(*) FROM session_credentials"), json!(0));
}

#[tokio::test]
async fn replayed_credentials_are_each_ledgered() {
    let h = H::new();
    let before = h.events("hub.session_credential.refused");
    // Distinct unknown values: one refusal event each.
    for c in ['B', 'C', 'D'] {
        assert_eq!(h.verify(&format!("uas_{}", c.to_string().repeat(43))).unwrap_err(), "unknown_or_revoked");
    }
    assert_eq!(h.events("hub.session_credential.refused") - before, 3);
    // The same value again within the interval is not ledgered twice.
    assert!(h.verify(&format!("uas_{}", "B".repeat(43))).is_err());
    assert_eq!(h.events("hub.session_credential.refused") - before, 3);
}
