//! The organization registry through the governed call path.
//!
//! Two rules the registry cannot leave to the caller: every write needs a
//! verified human operator in the row's organization, and a role grant needs a
//! one-time human approval. An agent-kind caller — however senior its profile —
//! is refused before the row is read or written.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, builtin_registry};

fn hub() -> Hub {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into(), "lead".into()];
    Hub::in_memory(cfg).unwrap()
}

fn caller(label: &str, kind: ActorKind, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn agent(label: &str) -> Caller {
    caller(label, ActorKind::Agent, Profile::Developer)
}

fn human(label: &str) -> Caller {
    // Coordinator sees every tool; the operator allow-list would hide the
    // registry family before the authority check ever ran.
    caller(label, ActorKind::Human, Profile::Coordinator)
}

fn status(report: &Value, capability: &str) -> String {
    report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == capability).unwrap()["status"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn a_write_tool_refuses_an_agent_caller() {
    let hub = hub();
    let reg = builtin_registry();
    let who = agent("builder-1");
    let err = reg
        .call(
            &hub,
            &who,
            "org_office_register",
            json!({ "slug": "platform", "name": "Platform", "profiles": ["developer"] }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "denied");
    assert_eq!(err.reason_code(), Some("authority_required"), "{err:?}");
}

#[tokio::test]
async fn register_and_read_round_trip() {
    let hub = hub();
    let reg = builtin_registry();
    let who = human("operator");

    let err = reg
        .call(
            &hub,
            &who,
            "org_office_register",
            json!({ "slug": "platform", "name": "Platform", "profiles": ["developer"], "org_id": "other" }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");

    let office = reg
        .call(
            &hub,
            &who,
            "org_office_register",
            json!({ "slug": "platform", "name": "Platform", "profiles": ["developer"] }),
        )
        .await
        .unwrap();
    assert_eq!(office["changed"], true);
    assert_eq!(office["office"]["slug"], "platform");

    // A role grant is always gated: the first call parks, a second human
    // approves, and the requester's identical call then passes.
    let parked = reg
        .call(&hub, &who, "org_role_register", json!({ "label": "operator", "role": "org_owner" }))
        .await
        .unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = parked else {
        panic!("expected an approval request, got {parked:?}");
    };
    reg.call(&hub, &human("lead"), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
        .await
        .unwrap();
    let granted = reg
        .call(&hub, &who, "org_role_register", json!({ "label": "operator", "role": "org_owner" }))
        .await
        .unwrap();
    assert_eq!(granted["changed"], true);
    assert_eq!(granted["role"]["role"], "org_owner");
    assert_eq!(granted["role"]["label"], "operator");

    reg.call(
        &hub,
        &who,
        "org_seat_register",
        json!({ "label": "builder-1", "office": "platform", "profile": "developer" }),
    )
    .await
    .unwrap();
    reg.call(&hub, &who, "org_service_register", json!({ "label": "bridge-sender" })).await.unwrap();

    let view = reg.call(&hub, &who, "org_registry_read", json!({})).await.unwrap();
    assert_eq!(view["org_id"], "default");
    assert_eq!(view["offices"][0]["slug"], "platform");
    assert_eq!(view["roles"][0]["role"], "org_owner");
    assert_eq!(view["seats"][0]["agent_kind"], "local");
    assert_eq!(view["service_identities"][0], "bridge-sender");
}

#[tokio::test]
async fn another_organizations_agent_never_leaks_into_the_default_read() {
    let hub = hub();
    let reg = builtin_registry();
    let who = human("operator");

    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                 VALUES ('org-b', 'org-b', 'Org B', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            tx.execute(
                "INSERT INTO agents (label, org_id, kind, created_at, updated_at) \
                 VALUES ('builder-b', 'org-b', 'agent', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    let view = reg.call(&hub, &who, "org_registry_read", json!({})).await.unwrap();
    assert_eq!(view["org_id"], "default");
    assert_eq!(view["findings"], json!([]), "org-b's agent must not appear: {view}");
    let report = reg.call(&hub, &who, "system_doctor", json!({})).await.unwrap();
    assert_eq!(status(&report, "org_registry"), "LIVE");
}
