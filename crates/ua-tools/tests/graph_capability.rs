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
    setup_with(|_| {})
}

fn setup_with(tweak: impl FnOnce(&mut Config)) -> (Hub, Registry) {
    let mut cfg = Config::for_home(std::env::temp_dir());
    cfg.human_identities = vec!["operator".into()];
    cfg.profiles.insert("scout-1".into(), "research".into());
    cfg.profiles.insert("boss".into(), "chief-of-staff".into());
    cfg.profiles.insert("dev-1".into(), "developer".into());
    tweak(&mut cfg);
    (Hub::in_memory(cfg).unwrap(), builtin_registry())
}

fn events(hub: &Hub, channel: &str) -> i64 {
    hub.db()
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM event_log WHERE channel = ?1", [channel], |r| r.get(0))?)
        })
        .unwrap()
}

async fn write(reg: &Registry, hub: &Hub, who: &Caller, board: &str, scene: Value) -> Result<Value, UaError> {
    reg.call(hub, who, "graph_canvas_write", json!({ "board_id": board, "scene": scene })).await
}

fn labeled(label: &str) -> Value {
    json!({ "elements": [{ "id": "n", "type": "rectangle", "label": label }] })
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
    assert_eq!(r["corrupt"], false);
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
    assert_eq!(events(&hub, "agent.graph.canvas_write"), 2);
}

#[tokio::test]
async fn new_boards_are_capped_per_agent_and_per_hub_but_updates_are_not() {
    let (hub, reg) = setup_with(|c| {
        c.graph_canvas_max_boards_per_agent = 2;
        c.graph_canvas_max_boards = 4;
    });
    // An imported board has no creator: it counts toward the hub, not anyone.
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO graph_canvas_scenes (board_id, scene_json, updated_by, updated_at) \
                 VALUES ('imported', '{}', 'py', '2026-01-01T00:00:00Z')",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    let other = caller("builder-2", ActorKind::Agent, Profile::Developer);
    for b in ["a", "b"] {
        assert_eq!(write(&reg, &hub, &dev(), b, scene()).await.unwrap()["created"], true);
    }
    let e = write(&reg, &hub, &dev(), "c", scene()).await.unwrap_err();
    assert_eq!(e.reason_code(), Some("canvas_limit"), "{e:?}");
    // Updating an existing board, even another agent's, is never capped.
    assert_eq!(write(&reg, &hub, &dev(), "a", labeled("x")).await.unwrap()["created"], false);
    assert_eq!(write(&reg, &hub, &dev(), "imported", labeled("x")).await.unwrap()["created"], false);
    // builder-2 fills the hub (4 boards), then is refused by the hub cap.
    write(&reg, &hub, &other, "c", scene()).await.unwrap();
    let e = write(&reg, &hub, &other, "d", scene()).await.unwrap_err();
    assert_eq!(e.reason_code(), Some("canvas_limit"), "{e:?}");
    write(&reg, &hub, &other, "b", scene()).await.unwrap();
    let creators: Vec<(String, Option<String>)> = hub
        .db()
        .read(|c| {
            let mut st =
                c.prepare("SELECT board_id, created_by FROM graph_canvas_scenes ORDER BY board_id")?;
            Ok(st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
        })
        .unwrap();
    let who = |s: &str| Some(s.to_string());
    assert_eq!(
        creators,
        [
            ("a".into(), who("builder-1")),
            ("b".into(), who("builder-1")),
            ("c".into(), who("builder-2")),
            ("imported".into(), None),
        ]
    );
}

#[tokio::test]
async fn overwrites_keep_a_bounded_history_that_can_be_restored() {
    let (hub, reg) = setup_with(|c| c.graph_canvas_history_max = 2);
    let w1 = write(&reg, &hub, &dev(), "plan", labeled("v1")).await.unwrap();
    assert_eq!(w1["kept_revision"], Value::Null);
    for v in ["v2", "v3", "v4"] {
        write(&reg, &hub, &dev(), "plan", labeled(v)).await.unwrap();
    }
    // Three overwrites kept v1, v2, v3 as revisions 1-3; only the newest two remain.
    let h = ok(&reg, &hub, &dev(), "graph_canvas_history", json!({ "board_id": "plan" })).await;
    assert_eq!(h["exists"], true);
    assert_eq!(h["history_max"], 2);
    let revs = h["revisions"].as_array().unwrap();
    assert_eq!(revs.iter().map(|r| r["revision"].clone()).collect::<Vec<_>>(), [json!(3), json!(2)]);
    assert!(revs.iter().all(|r| r.get("scene").is_none() && r["replaced_by"] == "builder-1"));
    let e = reg
        .call(&hub, &dev(), "graph_canvas_history", json!({ "board_id": "plan", "revision": 1 }))
        .await
        .unwrap_err();
    assert!(matches!(e, UaError::NotFound(_)), "{e:?}");
    let r2 =
        ok(&reg, &hub, &dev(), "graph_canvas_history", json!({ "board_id": "plan", "revision": 2 })).await;
    assert_eq!(r2["scene"], labeled("v2"));
    assert_eq!(r2["corrupt"], false);
    assert_eq!(r2["parsed"]["task_suggestions"][0]["title"], "v2");

    // Restore v2 over v4 as builder-2; v4 is kept, so the restore can be undone.
    let cur = ok(&reg, &hub, &dev(), "graph_canvas_read", json!({ "board_id": "plan" })).await;
    let other = caller("builder-2", ActorKind::Agent, Profile::Developer);
    let e = reg
        .call(
            &hub,
            &other,
            "graph_canvas_restore",
            json!({ "board_id": "plan", "revision": 2, "expected_updated_at": "2000-01-01T00:00:00Z" }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.reason_code(), Some("stale_canvas"), "{e:?}");
    let res = ok(
        &reg,
        &hub,
        &other,
        "graph_canvas_restore",
        json!({ "board_id": "plan", "revision": 2, "expected_updated_at": cur["updated_at"] }),
    )
    .await;
    assert_eq!(res["restored_revision"], 2);
    assert_eq!(res["updated_by"], "builder-2");
    assert_eq!(res["kept_revision"], 4);
    let now = ok(&reg, &hub, &dev(), "graph_canvas_read", json!({ "board_id": "plan" })).await;
    assert_eq!(now["scene"], labeled("v2"));
    assert_eq!(now["updated_by"], "builder-2");
    let r4 =
        ok(&reg, &hub, &dev(), "graph_canvas_history", json!({ "board_id": "plan", "revision": 4 })).await;
    assert_eq!(r4["scene"], labeled("v4"));
    assert_eq!(events(&hub, "agent.graph.canvas_restore"), 1);
    let e = reg
        .call(&hub, &dev(), "graph_canvas_restore", json!({ "board_id": "plan", "revision": 99 }))
        .await
        .unwrap_err();
    assert!(matches!(e, UaError::NotFound(_)), "{e:?}");
    let anon = caller("anon", ActorKind::Anonymous, Profile::Developer);
    assert!(
        reg.call(&hub, &anon, "graph_canvas_restore", json!({ "board_id": "plan", "revision": 3 }))
            .await
            .is_err()
    );

    // History off: overwrites keep nothing.
    let (hub, reg) = setup_with(|c| c.graph_canvas_history_max = 0);
    write(&reg, &hub, &dev(), "plan", labeled("v1")).await.unwrap();
    let w = write(&reg, &hub, &dev(), "plan", labeled("v2")).await.unwrap();
    assert_eq!(w["kept_revision"], Value::Null);
    let h = ok(&reg, &hub, &dev(), "graph_canvas_history", json!({ "board_id": "plan" })).await;
    assert_eq!(h["revisions"], json!([]));
}

#[tokio::test]
async fn a_corrupt_stored_scene_reads_as_corrupt() {
    let (hub, reg) = setup();
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO graph_canvas_scenes (board_id, scene_json, updated_by, updated_at) \
                 VALUES ('bad', '{not json', 'py', '2026-01-01T00:00:00Z'), \
                        ('list', '[1, 2]', 'py', '2026-01-01T00:00:00Z')",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    for b in ["bad", "list"] {
        let r = ok(&reg, &hub, &dev(), "graph_canvas_read", json!({ "board_id": b })).await;
        assert_eq!(r["exists"], true);
        assert_eq!(r["corrupt"], true, "{b}");
        assert_eq!(r["scene"], Value::Null);
        assert_eq!(r["parsed"]["node_count"], 0);
    }
    // Overwriting a corrupt board keeps it as a revision that cannot be restored.
    write(&reg, &hub, &dev(), "bad", scene()).await.unwrap();
    let r1 =
        ok(&reg, &hub, &dev(), "graph_canvas_history", json!({ "board_id": "bad", "revision": 1 })).await;
    assert_eq!(r1["corrupt"], true);
    let e = reg
        .call(&hub, &dev(), "graph_canvas_restore", json!({ "board_id": "bad", "revision": 1 }))
        .await
        .unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)), "{e:?}");
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
    for t in ["graph_canvas_write", "graph_canvas_history", "graph_canvas_restore"] {
        assert!(cat["tool_families"]["graph"].as_array().unwrap().iter().any(|x| x == t), "{t}");
    }
    assert_eq!(cat["prerequisites"]["ready"], false);
    assert_eq!(cat["mcp_client_matrix"]["server"]["capabilities"]["tool_annotations"]["status"], "supported");
    let e = reg.call(&hub, &dev(), "capability_catalog", json!({ "task_id": id })).await.unwrap_err();
    assert!(matches!(e, UaError::InvalidArgument(_)));

    // The research profile may read the catalog too.
    let scout = caller("scout-1", ActorKind::Agent, Profile::Research);
    ok(&reg, &hub, &scout, "capability_catalog", json!({})).await;

    // Requirements are case-folded.
    let t3 =
        ok(&reg, &hub, &dev(), "task_add", json!({ "title": "y", "notes": "[requires: FS_READ]" })).await;
    let c3 = ok(
        &reg,
        &hub,
        &dev(),
        "check_agent_capability",
        json!({ "task_id": t3["id"], "agent_label": "scout-1" }),
    )
    .await;
    assert_eq!(c3["required_tools"], json!(["fs_read"]));
    assert_eq!(c3["unknown_tools"], json!([]));
    assert_eq!(c3["capable"], true);
}

fn gates(cat: &Value) -> Vec<String> {
    cat["prerequisites"]["missing_config"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            assert!(m["action"].is_string() && m["detail"].is_string(), "{m}");
            m["gate"].as_str().unwrap().to_string()
        })
        .collect()
}

#[tokio::test]
async fn readiness_needs_an_identity_and_an_executor() {
    let (hub, reg) = setup();
    let t = ok(&reg, &hub, &dev(), "task_add", json!({ "title": "Port it", "notes": "[requires: fs_read]" }))
        .await;
    let id = t["id"].as_i64().unwrap();
    let catalog = |label: &str| json!({ "task_id": id, "agent_label": label });

    // A human label is known but has no token or profile; nothing can run work.
    let c = ok(&reg, &hub, &dev(), "capability_catalog", catalog("operator")).await;
    assert_eq!(c["prerequisites"]["capable"], true);
    assert_eq!(c["prerequisites"]["ready"], false);
    assert_eq!(gates(&c), ["agent_identity", "executor"]);

    // dev-1 has a profile but no harness and no node.
    let c = ok(&reg, &hub, &dev(), "capability_catalog", catalog("dev-1")).await;
    assert_eq!(gates(&c), ["executor"]);
    assert_eq!(c["prerequisites"]["ready"], false);

    // Another agent's live node does not count; dev-1's own does.
    let b1 = caller("builder-1", ActorKind::Agent, Profile::Developer);
    ok(&reg, &hub, &b1, "node_register", json!({ "node": "box-b1" })).await;
    let c = ok(&reg, &hub, &dev(), "capability_catalog", catalog("dev-1")).await;
    assert_eq!(gates(&c), ["executor"]);
    let d1 = caller("dev-1", ActorKind::Agent, Profile::Developer);
    ok(&reg, &hub, &d1, "node_register", json!({ "node": "box-d1" })).await;
    let c = ok(&reg, &hub, &dev(), "capability_catalog", catalog("dev-1")).await;
    assert_eq!(gates(&c), Vec::<String>::new());
    assert_eq!(c["prerequisites"]["ready"], true);

    // A configured harness is an executor for anyone.
    let (hub, reg) = setup_with(|c| {
        c.harnesses.insert(
            "echo".into(),
            toml::from_str("argv = [\"echo\", \"{prompt}\"]\ntimeout_s = 5\n").expect("harness"),
        );
    });
    let t = ok(&reg, &hub, &dev(), "task_add", json!({ "title": "Port it", "notes": "[requires: fs_read]" }))
        .await;
    let c =
        ok(&reg, &hub, &dev(), "capability_catalog", json!({ "task_id": t["id"], "agent_label": "dev-1" }))
            .await;
    assert_eq!(c["prerequisites"]["ready"], true);
}

#[tokio::test]
async fn the_hub_map_is_shown_to_operators_only() {
    let (hub, reg) = setup_with(|c| c.lifecycle_operators = Some(vec!["ops-bot".into()]));
    ok(&reg, &hub, &dev(), "agent_heartbeat", json!({ "host": "box-1.internal" })).await;

    let plain = ok(&reg, &hub, &dev(), "capability_catalog", json!({})).await;
    assert_eq!(plain["redacted"], json!(["boundaries", "health", "agents.host"]));
    assert_eq!(plain["boundaries"], Value::Null);
    assert_eq!(plain["health"], Value::Null);
    let agents = plain["agents"].as_array().unwrap();
    assert!(!agents.is_empty());
    assert!(agents.iter().all(|a| a.get("host").is_none()), "{agents:?}");

    let human = caller("operator", ActorKind::Human, Profile::ChiefOfStaff);
    let ops_bot = caller("ops-bot", ActorKind::Agent, Profile::Developer);
    let boss = caller("boss", ActorKind::Agent, Profile::ChiefOfStaff);
    for who in [human, ops_bot, boss] {
        let full = ok(&reg, &hub, &who, "capability_catalog", json!({})).await;
        assert_eq!(full["redacted"], json!([]), "{}", who.label);
        assert!(
            full["boundaries"]["approval_gated_tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t == "node_dispatch")
        );
        assert_eq!(full["health"]["hub_auth"]["gate"], "enforce_auth");
        assert!(full["agents"].as_array().unwrap().iter().any(|a| a["host"] == "box-1.internal"));
    }
}
