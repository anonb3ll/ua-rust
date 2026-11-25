//! Organization keys, migration and tool isolation for canvas boards and revisions.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, identity::Transport};
use ua_tools::{Hub, builtin_registry};

const OTHER: &str = "other";
const UNKNOWN: &str = "missing-org";
const PARTS: [&str; 2] = ["graph_canvas.v2.tenant_keys", "organization.v1.tools.graph"];

fn caller(org: &str) -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn add_org(hub: &Hub) {
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                 VALUES (?1, ?1, 'Other', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                [OTHER],
            )?;
            Ok(())
        })
        .unwrap();
}

fn old_parts() -> Vec<ua_store::Part> {
    ua_tools::schema_parts().into_iter().filter(|p| !PARTS.contains(&p.name)).collect()
}

#[test]
fn upgrade_preserves_scenes_and_history_and_can_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO graph_canvas_scenes (board_id, scene_json, updated_by, updated_at, created_by)
                 VALUES ('plan', '{\"version\":2}', 'builder-2', 'later', 'builder-1');
                 INSERT INTO graph_canvas_revisions
                     (board_id, revision, scene_json, updated_by, updated_at, replaced_at, replaced_by)
                 VALUES ('plan', 1, '{\"version\":1}', 'builder-1', 'earlier', 'later', 'builder-2');",
            )?;
            Ok(())
        })
        .unwrap();
    }
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        hub.db()
            .read(|c| {
                let scene: (String, String, String, String, String, String) = c.query_row(
                    "SELECT org_id, board_id, scene_json, updated_by, updated_at, created_by
                     FROM graph_canvas_scenes",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )?;
                assert_eq!(
                    scene,
                    (
                        DEFAULT_ORG.into(),
                        "plan".into(),
                        r#"{"version":2}"#.into(),
                        "builder-2".into(),
                        "later".into(),
                        "builder-1".into()
                    )
                );
                let history: (String, String, i64, String, String, String, String, String) = c.query_row(
                    "SELECT org_id, board_id, revision, scene_json, updated_by, updated_at, replaced_at,
                            replaced_by FROM graph_canvas_revisions",
                    [],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                        ))
                    },
                )?;
                assert_eq!(
                    history,
                    (
                        DEFAULT_ORG.into(),
                        "plan".into(),
                        1,
                        r#"{"version":1}"#.into(),
                        "builder-1".into(),
                        "earlier".into(),
                        "later".into(),
                        "builder-2".into()
                    )
                );
                for part in PARTS {
                    let count: i64 =
                        c.query_row("SELECT count(*) FROM schema_parts WHERE name = ?1", [part], |r| {
                            r.get(0)
                        })?;
                    assert_eq!(count, 1, "{part}");
                }
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn failed_rebuild_leaves_the_original_tables_intact() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());
    {
        let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
        db.write(|tx| {
            tx.execute(
                "INSERT INTO graph_canvas_revisions
                     (board_id, revision, scene_json, updated_by, updated_at, replaced_at, replaced_by)
                 VALUES ('orphan', 1, '{}', 'builder-1', 'earlier', 'later', 'builder-1')",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    }
    assert!(Hub::open(cfg.clone()).is_err());
    let db = ua_store::Db::open(&cfg.db_path(), &old_parts()).unwrap();
    db.read(|c| {
        for table in ["graph_canvas_scenes", "graph_canvas_revisions"] {
            let columns: i64 = c.query_row(
                "SELECT count(*) FROM pragma_table_info(?1) WHERE name = 'org_id'",
                [table],
                |r| r.get(0),
            )?;
            assert_eq!(columns, 0, "{table}");
        }
        let board: String = c.query_row("SELECT board_id FROM graph_canvas_revisions", [], |r| r.get(0))?;
        assert_eq!(board, "orphan");
        Ok(())
    })
    .unwrap();
}

#[test]
fn storage_rejects_unknown_orgs_reassignment_and_cross_org_parents() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::in_memory(Config::for_home(dir.path())).unwrap();
    add_org(&hub);
    let scene = "INSERT INTO graph_canvas_scenes (org_id, board_id, scene_json, updated_by, updated_at)
                 VALUES (?1, 'plan', '{}', 'builder-1', 'now')";
    let revision = "INSERT INTO graph_canvas_revisions
                       (org_id, board_id, revision, scene_json, updated_by, updated_at, replaced_at, replaced_by)
                    VALUES (?1, 'plan', 1, '{}', 'builder-1', 'earlier', 'now', 'builder-1')";
    hub.db()
        .write(|tx| {
            for sql in [scene, revision] {
                let err = tx.execute(sql, [UNKNOWN]).unwrap_err().to_string();
                assert!(err.contains("unknown organization"), "{err}");
                tx.execute(sql, [DEFAULT_ORG])?;
            }
            let err = tx.execute(revision, [OTHER]).unwrap_err().to_string();
            assert!(err.contains("FOREIGN KEY constraint failed"), "{err}");
            for sql in [
                "UPDATE graph_canvas_scenes SET org_id = ?1",
                "UPDATE graph_canvas_revisions SET org_id = ?1",
            ] {
                let err = tx.execute(sql, [OTHER]).unwrap_err().to_string();
                assert!(err.contains("org_id cannot change"), "{err}");
            }
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn organizations_share_board_names_but_have_independent_scenes_history_and_caps() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.graph_canvas_max_boards = 2;
    cfg.graph_canvas_max_boards_per_agent = 1;
    cfg.graph_canvas_history_max = 2;
    cfg.graph_canvas_history_max_bytes = 80;
    let hub = Hub::in_memory(cfg).unwrap();
    add_org(&hub);
    let reg = builtin_registry();
    let call = |org, tool, args| {
        let who = caller(org);
        let (reg, hub) = (&reg, &hub);
        async move { reg.call(hub, &who, tool, args).await }
    };
    let write = |org, text| call(org, "graph_canvas_write", json!({"scene":{"text":text}}));
    let read = |org| call(org, "graph_canvas_read", json!({}));
    let history = |org, revision| call(org, "graph_canvas_history", json!({"revision":revision}));
    let restore = |org, revision| call(org, "graph_canvas_restore", json!({"revision":revision}));

    assert_eq!(write(DEFAULT_ORG, "original").await.unwrap()["created"], true);
    assert_eq!(write(DEFAULT_ORG, "current").await.unwrap()["kept_revision"], 1);
    assert_eq!(read(OTHER).await.unwrap()["exists"], false);
    let empty = call(OTHER, "graph_canvas_history", json!({})).await.unwrap();
    assert_eq!(empty["exists"], false);
    assert_eq!(empty["revisions"], json!([]));
    assert_eq!(history(OTHER, 1).await.unwrap_err().code(), "not_found");
    assert_eq!(restore(OTHER, 1).await.unwrap_err().code(), "not_found");

    assert_eq!(write(OTHER, "other-original").await.unwrap()["created"], true);
    assert_eq!(write(OTHER, "other-current").await.unwrap()["kept_revision"], 1);
    assert_eq!(read(DEFAULT_ORG).await.unwrap()["scene"], json!({"text":"current"}));
    assert_eq!(read(OTHER).await.unwrap()["scene"], json!({"text":"other-current"}));
    assert_eq!(history(DEFAULT_ORG, 1).await.unwrap()["scene"], json!({"text":"original"}));
    assert_eq!(history(OTHER, 1).await.unwrap()["scene"], json!({"text":"other-original"}));
    assert_eq!(restore(OTHER, 1).await.unwrap()["kept_revision"], 2);
    assert_eq!(read(OTHER).await.unwrap()["scene"], json!({"text":"other-original"}));
    assert_eq!(restore(DEFAULT_ORG, 1).await.unwrap()["kept_revision"], 2);
    assert_eq!(read(DEFAULT_ORG).await.unwrap()["scene"], json!({"text":"original"}));

    let large = "x".repeat(100);
    write(OTHER, &large).await.unwrap();
    assert_eq!(history(OTHER, 1).await.unwrap_err().code(), "not_found");
    assert_eq!(write(OTHER, "small").await.unwrap()["kept_revision"], Value::Null);
    let list = call(OTHER, "graph_canvas_history", json!({})).await.unwrap();
    assert_eq!(list["revisions"], json!([]));
    let list = call(DEFAULT_ORG, "graph_canvas_history", json!({})).await.unwrap();
    assert_eq!(list["revisions"].as_array().unwrap().len(), 2);

    let err = call(OTHER, "graph_canvas_write", json!({"board_id":"second", "scene":{}})).await.unwrap_err();
    assert_eq!(err.reason_code(), Some("canvas_limit"));
    assert!(err.to_string().contains("graph_canvas_max_boards_per_agent"));
    let mut other_builder = caller(OTHER);
    other_builder.label = "builder-2".into();
    let saved = reg
        .call(&hub, &other_builder, "graph_canvas_write", json!({"board_id":"second","scene":{}}))
        .await
        .unwrap();
    assert_eq!(saved["created"], true, "the default org's board does not count toward the org cap");

    for err in [write(UNKNOWN, "invalid").await.unwrap_err(), restore(UNKNOWN, 99).await.unwrap_err()] {
        // The registry refuses the organization before the tool runs.
        assert_eq!(err.reason_code(), Some("unknown_organization"), "{err}");
        assert!(err.to_string().contains("unknown organization"), "{err}");
    }
    hub.db()
        .read(|c| {
            let counts: (i64, i64, i64, i64) = c.query_row(
                "SELECT (SELECT count(*) FROM graph_canvas_scenes),
                        (SELECT count(*) FROM graph_canvas_revisions),
                        (SELECT count(*) FROM event_log WHERE channel = 'agent.graph.canvas_write'),
                        (SELECT count(*) FROM event_log WHERE channel = 'agent.graph.canvas_restore')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            assert_eq!(counts, (3, 2, 7, 2));
            let (org, payload): (String, String) = c.query_row(
                "SELECT org_id, payload FROM event_log WHERE channel = 'agent.graph.canvas_restore'
                 ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            assert_eq!(org, DEFAULT_ORG);
            assert_eq!(
                serde_json::from_str::<Value>(&payload)?,
                json!({"board_id":"default", "revision":1, "size_bytes":19,
                       "node_count":0, "edge_count":0, "created":false, "kept_revision":2})
            );
            assert!(ua_store::ledger::verify(c)?.ok);
            Ok(())
        })
        .unwrap();
}
