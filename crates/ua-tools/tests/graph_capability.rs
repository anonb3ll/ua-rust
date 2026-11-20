//! The planning canvas and the capability tools through the registry.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

fn caller(label: &str, kind: ActorKind, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Mcp,
    }
}

fn dev() -> Caller {
    caller("builder-1", ActorKind::Agent, Profile::Developer)
}

fn setup() -> (Hub, Registry) {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into()];
    cfg.profiles.insert("scout-1".into(), "research".into());
    cfg.profiles.insert("boss".into(), "chief-of-staff".into());
    cfg.profiles.insert("dev-1".into(), "developer".into());
    (Hub::in_memory(cfg).unwrap(), builtin_registry())
}

async fn ok(reg: &Registry, hub: &Hub, who: &Caller, tool: &str, args: Value) -> Value {
    reg.call(hub, who, tool, args.clone()).await.unwrap_or_else(|e| panic!("{tool}({args}) failed: {e:?}"))
}

fn scene() -> Value {
    json!({ "elements": [
        { "id": "a", "type": "rectangle" },
        { "id": "ta", "type": "text", "text": "Design", "containerId": "a" },
        { "id": "b", "type": "rectangle", "label": "Build" },
        { "id": "e", "type": "arrow", "startBinding": { "elementId": "a" }, "endBinding": { "elementId": "b" } },
    ]})
}

#[tokio::test]
async fn a_canvas_round_trips_with_suggestions_and_refuses_a_stale_write() {
    let (hub, reg) = setup();
    let empty = ok(&reg, &hub, &dev(), "graph_canvas_read", json!({ "board_id": "sprint-1" })).await;
    assert_eq!(empty["exists"], false);
    assert_eq!(empty["parsed"]["node_count"], 0);

    let w = ok(&reg, &hub, &dev(), "graph_canvas_write", json!({ "board_id": "Sprint-1", "scene": scene() }))
        .await;
    assert_eq!(w["board_id"], "sprint-1");
    assert_eq!(w["updated_by"], "builder-1");
    let first = w["updated_at"].as_str().unwrap().to_string();

    let r = ok(&reg, &hub, &dev(), "graph_canvas_read", json!({ "board_id": "sprint-1" })).await;
    assert_eq!(r["exists"], true);
    assert_eq!(r["scene"], scene());
    assert_eq!(r["parsed"]["dependency_suggestions"][0]["to_title"], "Build");

    // Someone else writes; a write based on the old read is refused.
    let other = caller("builder-2", ActorKind::Agent, Profile::Developer);
    let w2 = ok(
        &reg,
        &hub,
        &other,
        "graph_canvas_write",
        json!({ "board_id": "sprint-1", "scene": { "elements": [] }, "expected_updated_at": first }),
    )
    .await;
    assert_ne!(w2["updated_at"], first);
    let e = reg
        .call(
            &hub,
            &dev(),
            "graph_canvas_write",
            json!({ "board_id": "sprint-1", "scene": scene(), "expected_updated_at": first }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.reason_code(), Some("stale_canvas"), "{e:?}");

    // Attribution cannot be spoofed; anonymous callers cannot write.
    let e = reg
        .call(&hub, &dev(), "graph_canvas_write", json!({ "scene": {}, "agent": "someone-else" }))
        .await
        .unwrap_err();
    assert_eq!(e.reason_code(), Some("identity_mismatch"));
    let anon = caller("anon", ActorKind::Anonymous, Profile::Developer);
    assert!(reg.call(&hub, &anon, "graph_canvas_write", json!({ "scene": {} })).await.is_err());
    let e = reg
        .call(&hub, &dev(), "graph_canvas_write", json!({ "scene": { "elements": "x" } }))
        .await
        .unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)));
    let n: i64 = hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM event_log WHERE channel = 'agent.graph.canvas_write'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(n, 2);
}

#[tokio::test]
async fn capability_follows_the_agents_profile() {
    let (hub, reg) = setup();
    let t = ok(
        &reg,
        &hub,
        &dev(),
        "task_add",
        json!({ "title": "Port it", "notes": "[requires: fs_read, run_cmd]" }),
    )
    .await;
    let id = t["id"].as_i64().unwrap();

    let d =
        ok(&reg, &hub, &dev(), "check_agent_capability", json!({ "task_id": id, "agent_label": "dev-1" }))
            .await;
    assert_eq!(d["profile"], "developer");
    assert_eq!(d["capable"], true);
    assert_eq!(d["missing_tools"], json!([]));
    // A label with no token, profile or registration is not an agent.
    let e = reg
        .call(&hub, &dev(), "check_agent_capability", json!({ "task_id": id, "agent_label": "builder-1" }))
        .await
        .unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)));
    let scout =
        ok(&reg, &hub, &dev(), "check_agent_capability", json!({ "task_id": id, "agent_label": "scout-1" }))
            .await;
    assert_eq!(scout["profile"], "research");
    assert_eq!(scout["capable"], false);
    assert_eq!(scout["missing_tools"], json!(["run_cmd"]));
    let boss =
        ok(&reg, &hub, &dev(), "check_agent_capability", json!({ "task_id": id, "agent_label": "boss" }))
            .await;
    assert_eq!(boss["capable"], true);
    assert_eq!(boss["allowed_tools"], Value::Null);

    let t2 = ok(&reg, &hub, &dev(), "task_add", json!({ "title": "x", "notes": "[requires: no_such_tool]" }))
        .await;
    let u = ok(
        &reg,
        &hub,
        &dev(),
        "check_agent_capability",
        json!({ "task_id": t2["id"], "agent_label": "boss" }),
    )
    .await;
    assert_eq!(u["unknown_tools"], json!(["no_such_tool"]));
    assert_eq!(u["capable"], false);

    let e = reg
        .call(&hub, &dev(), "check_agent_capability", json!({ "task_id": id, "agent_label": "nobody" }))
        .await
        .unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)));

    let cat =
        ok(&reg, &hub, &dev(), "capability_catalog", json!({ "task_id": id, "agent_label": "scout-1" }))
            .await;
    assert_eq!(cat["read_only"], true);
    assert!(cat["mcp_tools"].as_array().unwrap().iter().any(|t| t == "graph_canvas_read"));
    assert!(cat["tool_families"]["graph"].as_array().unwrap().iter().any(|t| t == "graph_canvas_write"));
    assert!(
        cat["boundaries"]["approval_gated_tools"].as_array().unwrap().iter().any(|t| t == "node_dispatch")
    );
    assert_eq!(cat["prerequisites"]["ready"], false);
    assert_eq!(cat["mcp_client_matrix"]["server"]["capabilities"]["tool_annotations"]["status"], "supported");
    let e = reg.call(&hub, &dev(), "capability_catalog", json!({ "task_id": id })).await.unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)));

    // The research profile may read the catalog too.
    let scout = caller("scout-1", ActorKind::Agent, Profile::Research);
    ok(&reg, &hub, &scout, "capability_catalog", json!({})).await;
}
