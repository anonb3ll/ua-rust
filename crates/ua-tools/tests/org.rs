//! The organization registry through the governed call path.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::{Hub, builtin_registry};

fn hub() -> Hub {
    Hub::in_memory(Config::for_home(std::env::temp_dir())).unwrap()
}

fn dev(label: &str) -> Caller {
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

fn status(report: &Value, capability: &str) -> String {
    report["checks"].as_array().unwrap().iter().find(|c| c["capability"] == capability).unwrap()["status"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn register_and_read_round_trip() {
    let hub = hub();
    let reg = builtin_registry();
    let who = dev("builder-1");

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
            json!({ "slug": "platform", "name": "Platform", "profiles": ["developer", "reviewer"] }),
        )
        .await
        .unwrap();
    assert_eq!(office["changed"], true);
    assert_eq!(office["office"]["slug"], "platform");

    reg.call(&hub, &who, "org_role_register", json!({ "label": "operator", "role": "org_owner" }))
        .await
        .unwrap();
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
    assert_eq!(view["offices"][0]["name"], "Platform");
    assert_eq!(view["roles"][0]["role"], "org_owner");
    assert_eq!(view["seats"][0]["office"], "platform");
    assert_eq!(view["seats"][0]["agent_kind"], "local");
    assert_eq!(view["service_identities"][0], "bridge-sender");
    assert!(view["findings"].as_array().unwrap().is_empty(), "{view}");

    let closed =
        reg.call(&hub, &who, "org_registry_read", json!({ "agent_labels": ["builder-1"] })).await.unwrap();
    let issues: Vec<&str> =
        closed["findings"].as_array().unwrap().iter().map(|f| f["issue"].as_str().unwrap()).collect();
    assert!(issues.contains(&"service_identity_not_in_agent_labels"), "{closed}");
}

#[tokio::test]
async fn doctor_flags_an_active_identity_without_an_office() {
    let hub = hub();
    let reg = builtin_registry();
    let who = dev("builder-1");
    let report = reg.call(&hub, &who, "system_doctor", json!({})).await.unwrap();
    assert_eq!(status(&report, "org_registry"), "LIVE");

    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO agents (label, created_at, updated_at) VALUES ('stray-agent', ?1, ?1)",
                [ua_core::time::now()],
            )?;
            Ok(())
        })
        .unwrap();
    let report = reg.call(&hub, &who, "system_doctor", json!({})).await.unwrap();
    assert_eq!(status(&report, "org_registry"), "MISCONFIGURED");
    let detail = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == "org_registry")
        .unwrap()["detail"]
        .as_str()
        .unwrap();
    assert!(detail.contains("stray-agent: active_identity_without_office"), "{detail}");
}
