//! Credential tools: managed agent tokens and OAuth session management.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::families::tokens::digest;
use ua_tools::{Hub, builtin_registry};

const VALUE_A: &str = "test-token-value-aaaaaaaaaaaaaaaaaaaaaaaa";
const VALUE_B: &str = "test-token-value-bbbbbbbbbbbbbbbbbbbbbbbb";

fn hub() -> Hub {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into()];
    Hub::in_memory(cfg).unwrap()
}

fn agent(label: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Coordinator,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, ..agent("operator") }
}

fn no_raw_value(v: &Value, raw: &str) {
    assert!(!v.to_string().contains(raw), "a tool response leaked a token value");
}

#[tokio::test]
async fn issue_is_human_only_and_never_returns_the_value() {
    let (hub, reg) = (hub(), builtin_registry());
    let err = reg
        .call(
            &hub,
            &agent("builder-1"),
            "agent_token_issue",
            json!({ "agent_label": "builder-1", "value": VALUE_A }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "denied");

    let out = reg
        .call(
            &hub,
            &human(),
            "agent_token_issue",
            json!({ "agent_label": "builder-1", "value": VALUE_A, "ttl_days": 7 }),
        )
        .await
        .unwrap();
    no_raw_value(&out, VALUE_A);
    assert_eq!(out["token_hash"], digest(VALUE_A));
    assert!(out["expires_at"].is_string());

    // The same value cannot be registered twice.
    let dup = reg
        .call(&hub, &human(), "agent_token_issue", json!({ "agent_label": "builder-2", "value": VALUE_A }))
        .await
        .unwrap_err();
    assert_eq!(dup.code(), "conflict");

    // Short values and OAuth-shaped values are refused.
    for bad in
        ["short", "uao_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "has space aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    {
        let e = reg
            .call(&hub, &human(), "agent_token_issue", json!({ "agent_label": "builder-1", "value": bad }))
            .await
            .unwrap_err();
        assert_eq!(e.code(), "invalid_argument", "{bad}");
    }
}

#[tokio::test]
async fn rotate_links_rows_and_list_shows_metadata() {
    let (hub, reg) = (hub(), builtin_registry());
    reg.call(&hub, &human(), "agent_token_issue", json!({ "agent_label": "builder-1", "value": VALUE_A }))
        .await
        .unwrap();
    let err = reg
        .call(
            &hub,
            &agent("builder-1"),
            "agent_token_rotate",
            json!({ "agent_label": "builder-1", "new_value": VALUE_B }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "denied");

    let rot = reg
        .call(
            &hub,
            &human(),
            "agent_token_rotate",
            json!({ "agent_label": "builder-1", "new_value": VALUE_B }),
        )
        .await
        .unwrap();
    no_raw_value(&rot, VALUE_B);
    assert!(rot["previous_token_id"].is_i64());

    let all =
        reg.call(&hub, &agent("x"), "agent_token_list", json!({ "agent_label": "builder-1" })).await.unwrap();
    no_raw_value(&all, VALUE_A);
    no_raw_value(&all, VALUE_B);
    assert_eq!(all["count"], 2);
    let active =
        reg.call(&hub, &agent("x"), "agent_token_list", json!({ "status": "active" })).await.unwrap();
    assert_eq!(active["count"], 1);
    assert_eq!(active["tokens"][0]["rotated_from"], rot["previous_token_id"]);
    let bad =
        reg.call(&hub, &agent("x"), "agent_token_list", json!({ "status": "bogus" })).await.unwrap_err();
    assert_eq!(bad.code(), "invalid_argument");
}

fn seed_grant(hub: &Hub, family: &str, subject: &str) {
    hub.db()
        .write(|tx| {
            let now = ua_core::time::now();
            tx.execute(
                "INSERT INTO oauth_grants (family_id, client_id, client_name, subject, approved_by, grant_type, scope, \
                 resource, created_at) VALUES (?1, 'c1', 'Client', ?2, 'operator', 'authorization_code', 'mcp', \
                 'https://hub.example.com/mcp', ?3)",
                rusqlite::params![family, subject, now],
            )?;
            for kind in ["access", "refresh"] {
                tx.execute(
                    "INSERT INTO oauth_tokens (token_hash, kind, family_id, client_id, subject, scope, resource, \
                     issued_at, expires_at) VALUES (?1, ?2, ?3, 'c1', ?4, 'mcp', 'https://hub.example.com/mcp', ?5, \
                     '9999-01-01T00:00:00Z')",
                    rusqlite::params![digest(&format!("{family}-{kind}")), kind, family, subject, now],
                )?;
            }
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn device_revoke_needs_approval() {
    let (hub, reg) = (hub(), builtin_registry());
    seed_grant(&hub, "fam1", "remote-agent");
    seed_grant(&hub, "fam2", "remote-agent");
    let me = agent("builder-1");

    let listed = reg.call(&hub, &me, "oauth_device_manage", json!({ "action": "list" })).await.unwrap();
    assert_eq!(listed["session_count"], 2);

    let bad = reg
        .call(
            &hub,
            &me,
            "oauth_device_manage",
            json!({ "action": "revoke", "session_id": "fam1", "identity": "x" }),
        )
        .await
        .unwrap_err();
    assert_eq!(bad.code(), "invalid_argument");

    let args = json!({ "action": "revoke", "session_id": "fam1" });
    let pending = reg.call(&hub, &me, "oauth_device_manage", args.clone()).await.unwrap_err();
    let ua_core::UaError::ApprovalRequired { approval_id, .. } = pending else {
        panic!("expected approval_required")
    };
    // Nothing is revoked before approval.
    let still = reg.call(&hub, &me, "oauth_device_manage", json!({})).await.unwrap();
    assert_eq!(still["session_count"], 2);

    reg.call(&hub, &human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
        .await
        .unwrap();
    let done = reg.call(&hub, &me, "oauth_device_manage", args).await.unwrap();
    assert_eq!(done["revoked_sessions"], 1);
    assert_eq!(done["revoked_tokens"], 2);

    let after = reg.call(&hub, &me, "oauth_device_manage", json!({})).await.unwrap();
    assert_eq!(after["session_count"], 1);
    assert_eq!(after["sessions"][0]["session_id"], "fam2");
}
