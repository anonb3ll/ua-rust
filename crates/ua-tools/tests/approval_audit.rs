//! The audit record of approvals: every approval event carries the SHA-256
//! of the canonical payload it concerns, the resolved event the expiry that
//! applied, and a call refused because of its approval state leaves an
//! `agent.approval.refused` event that survives the refused call.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_store::ledger::{self, EventQuery};
use ua_tools::approvals::{self, GateOutcome};
use ua_tools::{Hub, Registry, builtin_registry};

fn hub() -> Hub {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into()];
    cfg.approval_tools = vec!["task_add".into()];
    Hub::in_memory(cfg).unwrap()
}

fn caller(label: &str, kind: ActorKind) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile: if kind == ActorKind::Human { Profile::Coordinator } else { Profile::Developer },
        enforce_profile: true,
        session_key: None,
        org_id: ua_core::DEFAULT_ORG.into(),
        transport: Transport::Mcp,
    }
}

fn agent() -> Caller {
    caller("builder-1", ActorKind::Agent)
}

fn human() -> Caller {
    caller("operator", ActorKind::Human)
}

async fn add(reg: &Registry, hub: &Hub, title: &str) -> Result<Value, UaError> {
    reg.call(hub, &agent(), "task_add", json!({ "title": title })).await
}

async fn pending(reg: &Registry, hub: &Hub, title: &str) -> i64 {
    match add(reg, hub, title).await {
        Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
        other => panic!("expected approval_required, got {other:?}"),
    }
}

async fn resolve(reg: &Registry, hub: &Hub, id: i64, decision: &str) {
    reg.call(hub, &human(), "approval_resolve", json!({ "id": id, "decision": decision })).await.unwrap();
}

fn events(hub: &Hub, channel: &str) -> Vec<Value> {
    hub.db()
        .read(|c| {
            ledger::query(c, &EventQuery { channels: Some(vec![channel.into()]), ..Default::default() })
        })
        .unwrap()
        .into_iter()
        .map(|e| e.payload)
        .collect()
}

fn stored_sha(hub: &Hub, id: i64) -> String {
    let row = hub.db().read(|c| approvals::get(c, id)).unwrap();
    approvals::payload_sha256(&row.tool, &row.payload)
}

#[tokio::test]
async fn request_decision_and_use_carry_one_payload_hash() {
    let (reg, hub) = (builtin_registry(), hub());
    let id = pending(&reg, &hub, "hash me").await;
    resolve(&reg, &hub, id, "approve").await;
    add(&reg, &hub, "hash me").await.unwrap();

    let sha = stored_sha(&hub, id);
    assert_eq!(sha.len(), 64);
    let requested = events(&hub, "agent.approval.requested");
    let resolved = events(&hub, "agent.approval.resolved");
    let consumed = events(&hub, "agent.approval.consumed");
    for (what, e) in [("requested", &requested[0]), ("resolved", &resolved[0]), ("consumed", &consumed[0])] {
        assert_eq!(e["approval_id"], id, "{what}: {e}");
        assert_eq!(e["payload_sha256"], sha.as_str(), "{what}: {e}");
        assert!(!e.to_string().contains("hash me"), "{what} carries the payload: {e}");
    }
    // The resolved event records when the pass expires.
    let row = hub.db().read(|c| approvals::get(c, id)).unwrap();
    let at = |s: &str| ua_core::time::parse_ts(s).unwrap();
    let expires = at(resolved[0]["expires_at"].as_str().expect("expires_at on an approval"));
    let ttl = (hub.cfg().approval_pass_ttl_hours * 3600.0) as i64;
    assert_eq!(expires.as_second() - at(row.resolved_at.as_deref().unwrap()).as_second(), ttl);
    assert!(events(&hub, approvals::REFUSED).is_empty());
}

#[tokio::test]
async fn a_denied_call_is_refused_and_ledgered() {
    let (reg, hub) = (builtin_registry(), hub());
    let id = pending(&reg, &hub, "no thanks").await;
    resolve(&reg, &hub, id, "deny").await;
    let denied = events(&hub, "agent.approval.resolved");
    assert!(denied[0].get("expires_at").is_none(), "a denial has no expiry: {}", denied[0]);
    let e = add(&reg, &hub, "no thanks").await.unwrap_err();
    assert_eq!(e.reason_code(), Some("approval_denied"), "the caller's error is unchanged: {e:?}");
    let refused = events(&hub, approvals::REFUSED);
    assert_eq!(refused.len(), 1, "{refused:?}");
    let r = &refused[0];
    assert_eq!((r["reason"].as_str(), r["tool"].as_str()), (Some("denied"), Some("task_add")), "{r}");
    assert_eq!((r["approval_id"].as_i64(), r["requested_by"].as_str()), (Some(id), Some("builder-1")));
    let sha = stored_sha(&hub, id);
    assert_eq!(
        (r["approved_payload_sha256"].as_str(), r["presented_payload_sha256"].as_str()),
        (Some(&*sha), Some(&*sha))
    );
    assert!(!r.to_string().contains("no thanks"), "{r}");
}

#[tokio::test]
async fn an_expired_pass_is_refused_once_and_ledgered() {
    let (reg, hub) = (builtin_registry(), hub());
    let id = pending(&reg, &hub, "too late").await;
    resolve(&reg, &hub, id, "approve").await;
    hub.db()
        .write(move |tx| {
            Ok(tx.execute(
                "UPDATE approvals SET resolved_at = '2020-01-01T00:00:00+00:00' WHERE id = ?1",
                [id],
            )?)
        })
        .unwrap();
    // The caller sees a new request, as before; the expiry is in the ledger.
    let fresh = pending(&reg, &hub, "too late").await;
    assert_ne!(fresh, id);
    assert_eq!(pending(&reg, &hub, "too late").await, fresh, "the retry reuses the new request");
    let refused = events(&hub, approvals::REFUSED);
    assert_eq!(refused.len(), 1, "one expiry, one event: {refused:?}");
    let r = &refused[0];
    assert_eq!((r["reason"].as_str(), r["approval_id"].as_i64()), (Some("expired"), Some(id)), "{r}");
    let ttl = (hub.cfg().approval_pass_ttl_hours * 3600.0) as i64;
    let expected = ua_core::time::parse_ts("2020-01-01T00:00:00+00:00").unwrap().as_second() + ttl;
    assert_eq!(
        ua_core::time::parse_ts(r["expired_at"].as_str().unwrap()).unwrap().as_second(),
        expected,
        "{r}"
    );
}

#[tokio::test]
async fn a_refusal_survives_the_handler_that_rolls_back() {
    let (reg, hub) = (builtin_registry(), hub());
    let id = pending(&reg, &hub, "rolled back").await;
    resolve(&reg, &hub, id, "deny").await;
    // A handler that gates inside its own write and fails on the denial: the
    // whole transaction rolls back, the refusal does not.
    let (cfg, who) = (hub.cfg().clone(), agent());
    let err = hub
        .db()
        .write(move |tx| -> ua_core::UaResult<()> {
            tx.execute("UPDATE approvals SET reason = 'rolled-back' WHERE id = ?1", [id])?;
            match approvals::gate(tx, &cfg, &who, "task_add", &json!({ "title": "rolled back" }))? {
                GateOutcome::Denied { approval_id, .. } => {
                    Err(UaError::denied("approval_denied", format!("approval {approval_id} was denied")))
                }
                other => panic!("expected a denial, got {other:?}"),
            }
        })
        .unwrap_err();
    assert_eq!(err.reason_code(), Some("approval_denied"));
    let row = hub.db().read(|c| approvals::get(c, id)).unwrap();
    assert_ne!(row.reason.as_deref(), Some("rolled-back"), "the handler's own write rolled back");
    let refused = events(&hub, approvals::REFUSED);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(
        (refused[0]["reason"].as_str(), refused[0]["approval_id"].as_i64()),
        (Some("denied"), Some(id))
    );
    assert!(hub.db().read(ledger::verify).unwrap().ok, "the chain verifies with the kept event");
}
