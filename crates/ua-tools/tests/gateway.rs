//! The governed call path: profiles, the approval gate and the ledger.

use serde_json::json;
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::{Hub, builtin_registry};

fn hub() -> Hub {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into()];
    cfg.approval_tools = vec!["event_log_verify".into()];
    Hub::in_memory(cfg).unwrap()
}

fn agent(label: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, ..agent("operator", Profile::Operator) }
}

#[tokio::test]
async fn profile_filter_and_denial_event() {
    let hub = hub();
    let reg = builtin_registry();
    let dev = agent("builder-1", Profile::Developer);
    assert!(reg.visible_to(&dev).all(|t| t.name != "approval_resolve"));

    let err =
        reg.call(&hub, &dev, "approval_resolve", json!({"id": 1, "decision": "approve"})).await.unwrap_err();
    assert_eq!(err.code(), "denied");

    let events = reg
        .call(&hub, &human(), "event_log_query", json!({"channels": ["agent.gateway.decision"]}))
        .await
        .unwrap();
    assert_eq!(events["count"], 1);
    assert_eq!(events["events"][0]["payload"]["reason_code"], "profile_denied");
}

#[tokio::test]
async fn unknown_arguments_are_refused() {
    let hub = hub();
    let reg = builtin_registry();
    let err =
        reg.call(&hub, &human(), "event_log_query", json!({"limit": 5, "bogus": true})).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

#[tokio::test]
async fn approval_gate_round_trip() {
    let hub = hub();
    let reg = builtin_registry();
    let lead_agent = agent("reviewer-1", Profile::Lead);

    // First call parks; a retry reuses the same pending row.
    let e1 = reg.call(&hub, &lead_agent, "event_log_verify", json!({})).await.unwrap_err();
    let e2 = reg.call(&hub, &lead_agent, "event_log_verify", json!({})).await.unwrap_err();
    let id = match (&e1, &e2) {
        (
            ua_core::UaError::ApprovalRequired { approval_id: a, .. },
            ua_core::UaError::ApprovalRequired { approval_id: b, .. },
        ) => {
            assert_eq!(a, b);
            *a
        }
        other => panic!("expected pending approvals, got {other:?}"),
    };

    // An agent cannot approve; the requester cannot approve themselves.
    let other_agent = agent("builder-1", Profile::Coordinator);
    assert!(
        reg.call(&hub, &other_agent, "approval_resolve", json!({"id": id, "decision": "approve"}))
            .await
            .is_err()
    );

    reg.call(&hub, &human(), "approval_resolve", json!({"id": id, "decision": "approve"})).await.unwrap();

    // The pass is consumed exactly once.
    let ok = reg.call(&hub, &lead_agent, "event_log_verify", json!({})).await.unwrap();
    assert_eq!(ok["ok"], true);
    let again = reg.call(&hub, &lead_agent, "event_log_verify", json!({})).await.unwrap_err();
    assert_eq!(again.code(), "approval_required");

    // Denial sticks to the exact call.
    let pending = reg.call(&hub, &human(), "approval_pending", json!({})).await.unwrap();
    let next_id = pending["pending"][0]["id"].as_i64().unwrap();
    reg.call(
        &hub,
        &human(),
        "approval_resolve",
        json!({"id": next_id, "decision": "deny", "reason": "not now"}),
    )
    .await
    .unwrap();
    let denied = reg.call(&hub, &lead_agent, "event_log_verify", json!({})).await.unwrap_err();
    assert!(denied.to_string().contains("not now"), "{denied}");
}

#[tokio::test]
async fn profile_activation_rules() {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.profiles.insert("lead-1".into(), "coordinator".into());
    let hub = Hub::in_memory(cfg).unwrap();
    let reg = builtin_registry();

    // Developer sessions do not see profile_activate at all.
    let dev = agent("builder-1", Profile::Developer);
    let err = reg.call(&hub, &dev, "profile_activate", json!({"profile": "research"})).await.unwrap_err();
    assert_eq!(err.code(), "denied");

    // An unfiltered local agent still cannot escalate above its default.
    let local = Caller { enforce_profile: false, ..dev.clone() };
    let err =
        reg.call(&hub, &local, "profile_activate", json!({"profile": "coordinator"})).await.unwrap_err();
    assert!(err.to_string().contains("only a human"), "{err}");

    // Downgrading is allowed and binds to this session only.
    let lead = agent("lead-1", Profile::Coordinator);
    reg.call(&hub, &lead, "profile_activate", json!({"profile": "research"})).await.unwrap();
    assert_eq!(ua_tools::sessions::resolve_profile(&hub, "lead-1", Some("s1")), Profile::Research);
    assert_eq!(ua_tools::sessions::resolve_profile(&hub, "lead-1", Some("other")), Profile::Coordinator);

    // A legacy profile name activates the profile it names.
    let other = Caller { session_key: Some("s2".into()), ..lead.clone() };
    let out = reg.call(&hub, &other, "profile_activate", json!({"profile": "steward"})).await.unwrap();
    assert_eq!(out["profile"], "reviewer");
    assert_eq!(ua_tools::sessions::resolve_profile(&hub, "lead-1", Some("s2")), Profile::Reviewer);
}

#[tokio::test]
async fn unverified_callers_cannot_approve_by_naming_a_human() {
    let hub = hub();
    let reg = builtin_registry();
    let lead_agent = agent("reviewer-1", Profile::Lead);
    let id = match reg.call(&hub, &lead_agent, "event_log_verify", json!({})).await.unwrap_err() {
        ua_core::UaError::ApprovalRequired { approval_id, .. } => approval_id,
        other => panic!("expected a pending approval, got {other:?}"),
    };

    // A local (stdio or unauthenticated HTTP) caller claims to be the operator.
    let local = Caller::local("local", Transport::Stdio);
    let err = reg
        .call(
            &hub,
            &local,
            "approval_resolve",
            json!({"id": id, "decision": "approve", "resolved_by": "operator"}),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "denied", "{err}");
    let err = reg
        .call(&hub, &local, "approval_resolve", json!({"id": id, "decision": "approve"}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("verified human"), "{err}");

    // Nor may it deny or revoke someone else's request.
    let err =
        reg.call(&hub, &local, "approval_resolve", json!({"id": id, "decision": "deny"})).await.unwrap_err();
    assert_eq!(err.code(), "denied", "{err}");

    // A verified agent cannot pass a human name either.
    let other = agent("builder-1", Profile::Coordinator);
    let err = reg
        .call(
            &hub,
            &other,
            "approval_resolve",
            json!({"id": id, "decision": "approve", "resolved_by": "operator"}),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "denied", "{err}");

    // The request is still pending and the gated call still parks.
    let again = reg.call(&hub, &lead_agent, "event_log_verify", json!({})).await.unwrap_err();
    assert_eq!(again.code(), "approval_required");
}
