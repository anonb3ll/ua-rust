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

#[tokio::test]
async fn org_settings_update_requires_human_operator_approval_and_records_ledger_event() {
    let hub = hub();
    let reg = builtin_registry();
    let who = human("operator");

    // 1. Agent caller is refused even if its always-gated request is approved.
    let agent_who = agent("builder-1");
    let agent_parked = reg
        .call(&hub, &agent_who, "org_settings_update", json!({ "allow_remote_embedder": true }))
        .await
        .unwrap_err();
    let UaError::ApprovalRequired { approval_id: agent_approval_id, .. } = agent_parked else {
        panic!("expected ApprovalRequired for always-gated org_settings_update, got {agent_parked:?}");
    };
    reg.call(
        &hub,
        &human("lead"),
        "approval_resolve",
        json!({ "id": agent_approval_id, "decision": "approve" }),
    )
    .await
    .unwrap();
    let agent_err = reg
        .call(&hub, &agent_who, "org_settings_update", json!({ "allow_remote_embedder": true }))
        .await
        .unwrap_err();
    assert_eq!(agent_err.code(), "denied");
    assert_eq!(agent_err.reason_code(), Some("authority_required"), "{agent_err:?}");

    // 2. Caller cannot target another organization via `org_id` (deny_unknown_fields).
    let unknown_args = json!({ "allow_remote_embedder": true, "org_id": "other" });
    let unknown_parked = reg.call(&hub, &who, "org_settings_update", unknown_args.clone()).await.unwrap_err();
    let UaError::ApprovalRequired { approval_id: unknown_id, .. } = unknown_parked else {
        panic!("expected ApprovalRequired, got {unknown_parked:?}");
    };
    reg.call(&hub, &human("lead"), "approval_resolve", json!({ "id": unknown_id, "decision": "approve" }))
        .await
        .unwrap();
    let unknown_err = reg.call(&hub, &who, "org_settings_update", unknown_args).await.unwrap_err();
    assert_eq!(unknown_err.code(), "invalid_argument");

    // 3. Verified human operator call is always gated: parks until a second human approves.
    let parked = reg
        .call(&hub, &who, "org_settings_update", json!({ "allow_remote_embedder": true }))
        .await
        .unwrap_err();
    let UaError::ApprovalRequired { approval_id, .. } = parked else {
        panic!("expected ApprovalRequired for org_settings_update, got {parked:?}");
    };
    reg.call(&hub, &human("lead"), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
        .await
        .unwrap();

    let enabled =
        reg.call(&hub, &who, "org_settings_update", json!({ "allow_remote_embedder": true })).await.unwrap();
    assert_eq!(enabled["changed"], true);
    assert_eq!(enabled["settings"]["allow_remote_embedder"], true);

    let (flag, events): (i64, Vec<String>) = hub
        .db()
        .read(|c| {
            let flag: i64 =
                c.query_row("SELECT allow_remote_embedder FROM orgs WHERE id = 'default'", [], |r| r.get(0))?;
            let mut stmt =
                c.prepare("SELECT payload FROM event_log WHERE channel = 'agent.org.settings' ORDER BY seq")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok((flag, rows.collect::<Result<Vec<_>, _>>()?))
        })
        .unwrap();
    assert_eq!(flag, 1);
    assert_eq!(events.len(), 1);
    let ev: Value = serde_json::from_str(&events[0]).unwrap();
    assert_eq!(ev["org_id"], "default");
    assert_eq!(ev["allow_remote_embedder"]["old"], false);
    assert_eq!(ev["allow_remote_embedder"]["new"], true);

    // 4. Re-applying the same value (after approval) is idempotent and appends no duplicate event.
    let parked_same = reg
        .call(&hub, &who, "org_settings_update", json!({ "allow_remote_embedder": true }))
        .await
        .unwrap_err();
    let UaError::ApprovalRequired { approval_id: id2, .. } = parked_same else {
        panic!("expected ApprovalRequired, got {parked_same:?}");
    };
    reg.call(&hub, &human("lead"), "approval_resolve", json!({ "id": id2, "decision": "approve" }))
        .await
        .unwrap();
    let same =
        reg.call(&hub, &who, "org_settings_update", json!({ "allow_remote_embedder": true })).await.unwrap();
    assert_eq!(same["changed"], false);
    let event_count: i64 = hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM event_log WHERE channel = 'agent.org.settings'", [], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(event_count, 1);
}

#[tokio::test]
async fn org_settings_update_refuses_non_default_org_callers_without_touching_default() {
    let hub = hub();
    let reg = builtin_registry();
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                 VALUES ('org-b', 'org-b', 'Org B', '[\"developer\",\"coordinator\"]', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    let caller_in_b = |label: &str, kind: ActorKind, profile: Profile| Caller {
        org_id: "org-b".into(),
        ..caller(label, kind, profile)
    };
    let approve_row = |id: i64| {
        let now = ua_core::time::now();
        hub.db()
            .write(|tx| {
                tx.execute(
                    "UPDATE approvals SET status = 'approved', resolved_by = 'lead-b', \
                     resolved_at = ?2, updated_at = ?2 WHERE id = ?1",
                    rusqlite::params![id, now],
                )?;
                Ok(())
            })
            .unwrap();
    };

    // 1. Human operator in `org-b` is refused by `require_same_org` until `organization.v2`
    //    lands memberships — and never falls back to mutating the default org.
    let op_b = caller_in_b("operator", ActorKind::Human, Profile::Coordinator);
    let parked_op = reg
        .call(&hub, &op_b, "org_settings_update", json!({ "allow_remote_embedder": true }))
        .await
        .unwrap_err();
    let UaError::ApprovalRequired { approval_id: op_id, .. } = parked_op else {
        panic!("expected ApprovalRequired for org-b operator, got {parked_op:?}");
    };
    approve_row(op_id);
    let op_err = reg
        .call(&hub, &op_b, "org_settings_update", json!({ "allow_remote_embedder": true }))
        .await
        .unwrap_err();
    assert_eq!(op_err.code(), "denied");
    assert_eq!(op_err.reason_code(), Some("org_mismatch"), "{op_err:?}");

    // 2. Agent in `org-b` is also refused even if its approval row is marked approved.
    let agent_b = caller_in_b("builder-b", ActorKind::Agent, Profile::Developer);
    let parked_ag = reg
        .call(&hub, &agent_b, "org_settings_update", json!({ "allow_remote_embedder": true }))
        .await
        .unwrap_err();
    let UaError::ApprovalRequired { approval_id: ag_id, .. } = parked_ag else {
        panic!("expected ApprovalRequired for org-b agent, got {parked_ag:?}");
    };
    approve_row(ag_id);
    let ag_err = reg
        .call(&hub, &agent_b, "org_settings_update", json!({ "allow_remote_embedder": true }))
        .await
        .unwrap_err();
    assert_eq!(ag_err.code(), "denied");
    assert_eq!(ag_err.reason_code(), Some("org_mismatch"), "{ag_err:?}");

    // 3. Neither org's flag nor the ledger was touched.
    let (def_flag, b_flag, events): (i64, i64, i64) = hub
        .db()
        .read(|c| {
            let def: i64 =
                c.query_row("SELECT allow_remote_embedder FROM orgs WHERE id = 'default'", [], |r| r.get(0))?;
            let b: i64 =
                c.query_row("SELECT allow_remote_embedder FROM orgs WHERE id = 'org-b'", [], |r| r.get(0))?;
            let ev: i64 = c.query_row(
                "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.org.settings'",
                [],
                |r| r.get(0),
            )?;
            Ok((def, b, ev))
        })
        .unwrap();
    assert_eq!((def_flag, b_flag, events), (0, 0, 0));

    // 4. `families/org.rs` must scope every handler to `ctx.caller.org_id`, never hardcoding
    //    `DEFAULT_ORG` or `"default"` (which `require_same_org` would otherwise mask until v2).
    let org_src =
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/families/org.rs"))
            .unwrap();
    assert!(!org_src.contains("DEFAULT_ORG"), "families/org.rs must not hardcode DEFAULT_ORG");
    assert!(!org_src.contains("\"default\""), "families/org.rs must not hardcode \"default\"");
}
