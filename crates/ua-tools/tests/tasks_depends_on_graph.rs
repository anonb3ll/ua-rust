//! C2a (`docs/graph.md`): `task_dependencies` migrated directly onto
//! `graph_edges(kind = 'depends_on')` behind `dependency_add`,
//! `dependency_list`, and `dependency_remove`, with `task_dependencies` frozen
//! read-only and migration counts recorded and surfaced in `system_doctor`.

#[path = "../../ua-core/tests/support/mod.rs"]
mod support;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";

fn agent(label: &str, org: &str) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some(format!("{label}-s")),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn coordinator(label: &str, org: &str) -> Caller {
    Caller { profile: Profile::Coordinator, ..agent(label, org) }
}

fn add_org(hub: &Hub, id: &str) {
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                 VALUES (?1, ?1, 'Org B', '[\"developer\",\"coordinator\"]', '2026-01-01T00:00:00+00:00')",
                [id],
            )?;
            Ok(())
        })
        .unwrap();
}

struct H {
    hub: Hub,
    reg: Registry,
    _dir: tempfile::TempDir,
}

impl H {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::for_home(dir.path());
        let hub = Hub::in_memory(cfg).unwrap();
        add_org(&hub, ORG_B);
        Self { hub, reg: builtin_registry(), _dir: dir }
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.reg
            .call(&self.hub, who, tool, args.clone())
            .await
            .unwrap_or_else(|e| panic!("{tool}({args}): {e:?}"))
    }

    async fn err(&self, who: &Caller, tool: &str, args: Value) -> UaError {
        self.reg.call(&self.hub, who, tool, args).await.expect_err(&format!("{tool} should fail"))
    }

    async fn add_task(&self, who: &Caller, title: &str) -> i64 {
        self.ok(who, "task_add", json!({ "title": title })).await["id"].as_i64().unwrap()
    }
}

#[tokio::test]
async fn dependency_add_list_remove_use_graph_edges_and_retract_without_delete() {
    let h = H::new();
    let b1 = agent("builder-1", DEFAULT_ORG);
    let b2 = agent("builder-2", DEFAULT_ORG);

    let a = h.add_task(&b1, "Task A").await;
    let b = h.add_task(&b1, "Task B").await;

    let added = h.ok(&b1, "dependency_add", json!({ "task_id": a, "depends_on_task_id": b })).await;
    let dep = &added["dependency"];
    let dep_id = dep["id"].as_i64().unwrap();
    assert_eq!(dep["task_id"], a);
    assert_eq!(dep["depends_on_task_id"], b);
    assert_eq!(dep["created_by"], "builder-1");
    assert!(dep["created_at"].is_string());

    // Stored in graph_edges, never in the frozen legacy task_dependencies table.
    let (legacy_cnt, live_graph_cnt): (i64, i64) = h
        .hub
        .db()
        .read(|c| {
            let legacy: i64 = c.query_row("SELECT COUNT(*) FROM task_dependencies", [], |r| r.get(0))?;
            let live: i64 = c.query_row(
                "SELECT COUNT(*) FROM graph_edges WHERE org_id = 'default' AND kind = 'depends_on' AND valid_to IS NULL",
                [],
                |r| r.get(0),
            )?;
            Ok((legacy, live))
        })
        .unwrap();
    assert_eq!(legacy_cnt, 0);
    assert_eq!(live_graph_cnt, 1);

    // Visible through governed graph_neighbors traversal as well as dependency_list.
    let nbrs = h
        .ok(
            &b1,
            "graph_neighbors",
            json!({ "kind": "task", "external_id": a.to_string(), "direction": "out", "edge_kinds": ["depends_on"] }),
        )
        .await;
    assert_eq!(nbrs["neighbors"].as_array().unwrap().len(), 1);
    assert_eq!(nbrs["neighbors"][0]["node"]["external_id"], b.to_string());

    // Creator-only delete: another agent is refused with not_dependency_creator.
    let denied = h.err(&b2, "dependency_remove", json!({ "dependency_id": dep_id })).await;
    assert_eq!(denied.code(), "denied");
    assert_eq!(denied.reason_code(), Some("not_dependency_creator"));

    // Creator removes: closes with valid_to, never deletes the graph_edges row.
    let removed = h.ok(&b1, "dependency_remove", json!({ "dependency_id": dep_id })).await;
    assert_eq!(removed, json!({ "removed": true, "dependency_id": dep_id }));

    let listed = h.ok(&b1, "dependency_list", json!({})).await;
    assert!(listed["dependencies"].as_array().unwrap().is_empty());

    let (total_rows, closed_rows, orig_by): (i64, i64, String) = h
        .hub
        .db()
        .read(|c| {
            let total: i64 = c.query_row(
                "SELECT COUNT(*) FROM graph_edges WHERE org_id = 'default' AND kind = 'depends_on'",
                [],
                |r| r.get(0),
            )?;
            let closed: i64 = c.query_row(
                "SELECT COUNT(*) FROM graph_edges WHERE org_id = 'default' AND kind = 'depends_on' AND valid_to IS NOT NULL",
                [],
                |r| r.get(0),
            )?;
            let by: String = c.query_row(
                "SELECT asserted_by FROM graph_edges WHERE org_id = 'default' AND kind = 'depends_on'",
                [],
                |r| r.get(0),
            )?;
            Ok((total, closed, by))
        })
        .unwrap();
    assert_eq!(total_rows, 1, "retract must close, never delete");
    assert_eq!(closed_rows, 1);
    assert_eq!(orig_by, "builder-1");

    // Removing again returns not_found.
    assert_eq!(h.err(&b1, "dependency_remove", json!({ "dependency_id": dep_id })).await.code(), "not_found");

    // Re-adding creates a new live edge with a strictly greater dependency_id.
    let readded = h.ok(&b2, "dependency_add", json!({ "task_id": a, "depends_on_task_id": b })).await;
    let dep_id_2 = readded["dependency"]["id"].as_i64().unwrap();
    assert!(dep_id_2 > dep_id, "re-added dependency must get a new monotonic id");
    assert_eq!(readded["dependency"]["created_by"], "builder-2");
}

#[tokio::test]
async fn dependency_add_refuses_cycle_and_cycle_check_bound_exceeded() {
    let h = H::new();
    let b1 = agent("builder-1", DEFAULT_ORG);

    // 1. Real cycle returns invalid_argument(cycle_detected).
    let t1 = h.add_task(&b1, "T1").await;
    let t2 = h.add_task(&b1, "T2").await;
    let t3 = h.add_task(&b1, "T3").await;
    h.ok(&b1, "dependency_add", json!({ "task_id": t1, "depends_on_task_id": t2 })).await;
    h.ok(&b1, "dependency_add", json!({ "task_id": t2, "depends_on_task_id": t3 })).await;
    let cyc = h.err(&b1, "dependency_add", json!({ "task_id": t3, "depends_on_task_id": t1 })).await;
    assert_eq!(cyc.code(), "invalid_argument");
    assert_eq!(cyc.reason_code(), Some("cycle_detected"));

    // 2. Reachable subgraph exceeding CycleCheckPolicy's 1,000-node cap returns
    //    invalid_argument(cycle_check_bound_exceeded) and writes nothing.
    let chain_len = ua_graph::CYCLE_CHECK_MAX_NODES + 2; // 1,002 tasks -> 1,001 reachable nodes
    let base_id = 10_000i64;
    let now = ua_core::time::now();
    h.hub
        .db()
        .write(|tx| {
            {
                let mut tstmt = tx.prepare(
                    "INSERT INTO tasks (id, org_id, title, created_at, updated_at) \
                     VALUES (?1, 'default', ?2, ?3, ?3)",
                )?;
                let mut nstmt = tx.prepare(
                    "INSERT INTO graph_nodes (id, org_id, kind, external_id, display_label, visibility, \
                     asserted_by, asserted_by_kind, source_kind, source_ref, meta_json, created_at, updated_at) \
                     VALUES (?1, 'default', 'task', ?2, ?3, 'org', 'system', 'system', 'import', ?4, '{}', ?5, ?5)",
                )?;
                let mut estmt = tx.prepare(
                    "INSERT INTO graph_edges (id, org_id, src_id, dst_id, kind, assertion_scope, state, weight, \
                     asserted_by, asserted_by_kind, asserted_at, source_kind, source_ref, valid_from, valid_to, meta_json) \
                     VALUES (?1, 'default', ?2, ?3, 'depends_on', '', 'active', 1.0, 'builder-1', 'agent', ?4, \
                     'import', ?5, ?4, NULL, ?6)",
                )?;
                for i in 0..=chain_len {
                    let tid = base_id + i as i64;
                    let nid = format!("node-chain-{tid}");
                    tstmt.execute(rusqlite::params![tid, format!("Chain {i}"), now])?;
                    nstmt.execute(rusqlite::params![
                        nid,
                        tid.to_string(),
                        format!("Chain {i}"),
                        format!("import:test:{tid}"),
                        now,
                    ])?;
                }
                for i in 0..(chain_len - 1) {
                    let src_tid = base_id + i as i64;
                    let dst_tid = base_id + (i + 1) as i64;
                    let eid = format!("edge-chain-{i}");
                    let dep_id = base_id + i as i64;
                    estmt.execute(rusqlite::params![
                        eid,
                        format!("node-chain-{src_tid}"),
                        format!("node-chain-{dst_tid}"),
                        now,
                        format!("import:test:edge:{i}"),
                        format!("{{\"dependency_id\":{dep_id}}}"),
                    ])?;
                }
            }
            Ok(())
        })
        .unwrap();

    let extra_task = base_id + chain_len as i64;
    let head_task = base_id;
    let edges_before: i64 = h
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM graph_edges WHERE kind = 'depends_on'", [], |r| r.get(0))?)
        })
        .unwrap();

    // `extra_task -> head_task` walks from `head_task` along 1,001 reachable nodes,
    // tripping CYCLE_CHECK_MAX_NODES (1,000) fail-closed.
    let err =
        h.err(&b1, "dependency_add", json!({ "task_id": extra_task, "depends_on_task_id": head_task })).await;
    assert_eq!(err.code(), "invalid_argument", "{err}");
    assert_eq!(err.reason_code(), Some("cycle_check_bound_exceeded"), "{err}");

    let edges_after: i64 = h
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM graph_edges WHERE kind = 'depends_on'", [], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(edges_after, edges_before, "bound refusal must write nothing");
}

#[tokio::test]
async fn migration_copies_counts_records_skips_freezes_table_and_surfaces_in_doctor() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());

    // Build a pre-C2a database (every schema part except `tasks.v3.depends_on_graph`).
    let pre_c2a: Vec<ua_store::Part> =
        ua_tools::schema_parts().into_iter().filter(|p| p.name != "tasks.v3.depends_on_graph").collect();
    {
        let db = ua_store::Db::open(&cfg.db_path(), &pre_c2a).unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                     VALUES ('org-b', 'org-b', 'Org B', '[\"developer\",\"coordinator\"]', '2026-01-01T00:00:00+00:00');
                 INSERT INTO tasks (id, org_id, title, created_at, updated_at) VALUES
                     (1, 'default', 'Task 1', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (2, 'default', 'Task 2', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (3, 'default', 'Task 3', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (4, 'default', 'Task 4', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (20, 'org-b', 'OrgB 20', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (21, 'org-b', 'OrgB 21', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');
                 -- id=10: valid default-org edge with RFC 3339 timestamp
                 INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_by, created_at)
                     VALUES (10, 'default', 2, 1, 'builder-1', '2026-01-03T12:00:00+00:00');
                 -- id=11: valid default-org edge with legacy non-RFC3339 timestamp
                 INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_by, created_at)
                     VALUES (11, 'default', 3, 2, 'builder-2', 'legacy-ts');
                 -- id=12: corrupt cycle back to task 2 -> skipped (cycle_detected)
                 INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_by, created_at)
                     VALUES (12, 'default', 1, 2, 'builder-1', '2026-01-03T12:05:00+00:00');
                 -- id=13: invalid blank creator -> skipped (invalid_creator)
                 INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_by, created_at)
                     VALUES (13, 'default', 4, 1, '   ', '2026-01-03T12:06:00+00:00');
                 -- id=14: non-default org row -> skipped (non_default_org)
                 INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_by, created_at)
                     VALUES (14, 'org-b', 21, 20, 'orgb-agent', '2026-01-03T12:07:00+00:00');",
            )?;
            Ok(())
        })
        .unwrap();
    }

    // Open twice to verify idempotency across restarts.
    for _ in 0..2 {
        let hub = Hub::open(cfg.clone()).unwrap();
        let summary = hub
            .db()
            .read(|c| Ok(ua_tools::families::tasks::depends_on_migration_summary(c)))
            .unwrap()
            .expect("migration summary recorded in schema_procedures");
        assert_eq!(summary["total"], 5, "{summary}");
        assert_eq!(summary["copied"], 2, "{summary}");
        assert_eq!(summary["skipped_total"], 3, "{summary}");
        assert_eq!(summary["skipped"]["cycle_detected"], 1, "{summary}");
        assert_eq!(summary["skipped"]["invalid_creator"], 1, "{summary}");
        assert_eq!(summary["skipped"]["non_default_org"], 1, "{summary}");
        assert_eq!(summary["nodes_ensured"], 3, "{summary}");
        assert_eq!(
            summary["skipped_rows"],
            json!([
                { "id": 12, "reason": "cycle_detected" },
                { "id": 13, "reason": "invalid_creator" },
                { "id": 14, "reason": "non_default_org" },
            ]),
            "{summary}"
        );
        // Zero foreign org text or labels in schema_procedures.
        assert!(!summary.to_string().contains("org-b"));
        assert!(!summary.to_string().contains("orgb-agent"));
    }

    let hub = Hub::open(cfg).unwrap();
    let reg = builtin_registry();
    let b1 = agent("builder-1", DEFAULT_ORG);
    let coord_default = coordinator("lead-1", DEFAULT_ORG);
    let coord_b = coordinator("lead-1", ORG_B);

    // Migrated rows answer through dependency_list with exact legacy ids & timestamps.
    let listed = reg.call(&hub, &b1, "dependency_list", json!({})).await.unwrap();
    assert_eq!(
        listed["dependencies"],
        json!([
            {
                "id": 10,
                "task_id": 2,
                "depends_on_task_id": 1,
                "created_by": "builder-1",
                "created_at": "2026-01-03T12:00:00+00:00",
            },
            {
                "id": 11,
                "task_id": 3,
                "depends_on_task_id": 2,
                "created_by": "builder-2",
                "created_at": "legacy-ts",
            },
        ])
    );

    // Migrated edges and ensured task nodes carry source_kind = 'import'.
    let (node_sources, edge_sources): (Vec<String>, Vec<String>) = hub
        .db()
        .read(|c| {
            let ns = c
                .prepare("SELECT DISTINCT source_kind FROM graph_nodes WHERE kind = 'task'")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            let es = c
                .prepare("SELECT DISTINCT source_kind FROM graph_edges WHERE kind = 'depends_on'")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok((ns, es))
        })
        .unwrap();
    assert_eq!(node_sources, vec!["import"]);
    assert_eq!(edge_sources, vec!["import"]);

    // system_doctor surfaces the migration counts for default org only.
    let doc_default = reg.call(&hub, &coord_default, "system_doctor", json!({})).await.unwrap();
    assert_eq!(doc_default["database"]["depends_on_migration"]["copied"], 2, "{doc_default}");
    assert_eq!(doc_default["database"]["depends_on_migration"]["skipped_total"], 3, "{doc_default}");
    let db_finding =
        doc_default["checks"].as_array().unwrap().iter().find(|f| f["capability"] == "database").unwrap();
    assert!(db_finding["detail"].as_str().unwrap().contains("skipped 3 row(s)"), "{db_finding}");
    let doc_b = reg.call(&hub, &coord_b, "system_doctor", json!({})).await.unwrap();
    assert!(doc_b["database"]["depends_on_migration"].is_null(), "{doc_b}");

    // Freeze triggers block direct INSERT, UPDATE, and DELETE for default-org rows
    // on task_dependencies, while leaving non-default-org rows writable until #2790.
    for sql in [
        "INSERT INTO task_dependencies (org_id, task_id, depends_on_task_id, created_by, created_at) \
         VALUES ('default', 4, 2, 'builder-1', '2026-01-04T00:00:00+00:00')",
        "UPDATE task_dependencies SET created_by = 'tamper' WHERE id = 10",
        "DELETE FROM task_dependencies WHERE id = 10",
    ] {
        let err = hub
            .db()
            .write(|tx| {
                tx.execute_batch(sql)?;
                Ok(())
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("frozen read-only for default org"), "{sql}: {err}");
    }

    // New dependency_add allocates an id strictly greater than max legacy id (14).
    let added = reg
        .call(&hub, &b1, "dependency_add", json!({ "task_id": 4, "depends_on_task_id": 3 }))
        .await
        .unwrap();
    assert_eq!(added["dependency"]["id"], 15, "{added}");

    // Deleting task 3 closes its live depends_on edges in graph_edges AND succeeds
    // even though task_dependencies still holds frozen row id=11 (ON DELETE CASCADE).
    let del = reg.call(&hub, &b1, "task_delete", json!({ "id": 3 })).await.unwrap();
    assert_eq!(del["deleted"], true);
    let listed_after = reg.call(&hub, &b1, "dependency_list", json!({})).await.unwrap();
    let remaining_ids: Vec<i64> =
        listed_after["dependencies"].as_array().unwrap().iter().map(|d| d["id"].as_i64().unwrap()).collect();
    assert_eq!(remaining_ids, vec![10], "edges 11 and 15 incident to deleted task 3 must be retracted");
}

#[tokio::test]
async fn upgraded_hub_never_reuses_deleted_legacy_dependency_ids_and_preserves_legacy_creators() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());

    // Pre-C2a database with legacy ids 5, 7, and a removed id 9 (so sqlite_sequence = 9),
    // plus legacy creators `"System"` and `" builder-1 "`.
    let pre_c2a: Vec<ua_store::Part> =
        ua_tools::schema_parts().into_iter().filter(|p| p.name != "tasks.v3.depends_on_graph").collect();
    {
        let db = ua_store::Db::open(&cfg.db_path(), &pre_c2a).unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO tasks (id, org_id, title, created_at, updated_at) VALUES
                     (1, 'default', 'T1', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (2, 'default', 'T2', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (3, 'default', 'T3', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (4, 'default', 'T4', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');
                 INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_by, created_at)
                     VALUES (5, 'default', 2, 1, 'System', '2026-01-03T12:00:00+00:00');
                 INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_by, created_at)
                     VALUES (7, 'default', 3, 2, ' builder-1 ', '2026-01-03T12:01:00+00:00');
                 INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_by, created_at)
                     VALUES (9, 'default', 4, 3, 'builder-2', '2026-01-03T12:02:00+00:00');
                 DELETE FROM task_dependencies WHERE id = 9;",
            )?;
            Ok(())
        })
        .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    let reg = builtin_registry();
    let b1 = agent("builder-1", DEFAULT_ORG);

    // M1: sqlite_sequence was 9 even though MAX(id) is 7; next dependency_add must be 10.
    let added = reg
        .call(&hub, &b1, "dependency_add", json!({ "task_id": 4, "depends_on_task_id": 1 }))
        .await
        .unwrap();
    assert_eq!(added["dependency"]["id"], 10, "must honor sqlite_sequence floor 9: {added}");

    // Low 3: `"System"` and `" builder-1 "` migrated cleanly (zero skips) and preserve created_by.
    let summary =
        hub.db().read(|c| Ok(ua_tools::families::tasks::depends_on_migration_summary(c))).unwrap().unwrap();
    assert_eq!(summary["copied"], 2, "{summary}");
    assert_eq!(summary["skipped_total"], 0, "{summary}");

    let listed = reg.call(&hub, &b1, "dependency_list", json!({})).await.unwrap();
    let deps = listed["dependencies"].as_array().unwrap();
    assert_eq!(deps[0]["id"], 5);
    assert_eq!(deps[0]["created_by"], "System");
    assert_eq!(deps[1]["id"], 7);
    assert_eq!(deps[1]["created_by"], " builder-1 ");

    // Creator `builder-1` can still remove the legacy `" builder-1 "` dependency.
    let removed = reg.call(&hub, &b1, "dependency_remove", json!({ "dependency_id": 7 })).await.unwrap();
    assert_eq!(removed, json!({ "removed": true, "dependency_id": 7 }));
}

#[tokio::test]
async fn non_default_org_stays_on_task_dependencies_with_full_readiness_parity() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(dir.path());

    // Pre-C2a database with an existing org-b dependency: 21 depends on 20 (both open).
    let pre_c2a: Vec<ua_store::Part> =
        ua_tools::schema_parts().into_iter().filter(|p| p.name != "tasks.v3.depends_on_graph").collect();
    {
        let db = ua_store::Db::open(&cfg.db_path(), &pre_c2a).unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                     VALUES ('org-b', 'org-b', 'Org B', '[\"developer\",\"coordinator\"]', '2026-01-01T00:00:00+00:00');
                 INSERT INTO tasks (id, org_id, title, status, created_at, updated_at) VALUES
                     (10, 'default', 'Default 10', 'open', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (11, 'default', 'Default 11', 'open', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (20, 'org-b', 'OrgB 20', 'open', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00'),
                     (21, 'org-b', 'OrgB 21', 'open', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');
                 INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_by, created_at)
                     VALUES (14, 'org-b', 21, 20, 'builder-1', '2026-01-03T12:07:00+00:00');",
            )?;
            Ok(())
        })
        .unwrap();
    }

    let hub = Hub::open(cfg).unwrap();
    let reg = builtin_registry();
    let a = agent("builder-1", DEFAULT_ORG);
    let b = agent("builder-1", ORG_B);
    let b2 = agent("builder-2", ORG_B);
    let coord_b = coordinator("lead-1", ORG_B);
    let ghost = agent("builder-1", "missing-org");

    // Pre-existing org-b dependency survives upgrade and blocks task 21 in the frontier.
    let list_b = reg.call(&hub, &b, "dependency_list", json!({})).await.unwrap();
    assert_eq!(list_b["dependencies"].as_array().unwrap().len(), 1, "{list_b}");
    assert_eq!(list_b["dependencies"][0]["id"], 14);
    assert_eq!(list_b["dependencies"][0]["task_id"], 21);
    assert_eq!(list_b["dependencies"][0]["depends_on_task_id"], 20);

    let frontier_before = reg.call(&hub, &b, "task_list", json!({ "frontier": true })).await.unwrap();
    let frontier_ids_before: Vec<i64> =
        frontier_before["tasks"].as_array().unwrap().iter().map(|t| t["id"].as_i64().unwrap()).collect();
    assert_eq!(frontier_ids_before, vec![20], "blocked task 21 must stay out of org-b frontier");

    // Completing prerequisite 20 makes 21 appear in frontier AND continuity ready_unowned.
    reg.call(&hub, &b, "task_update", json!({ "id": 20, "status": "done" })).await.unwrap();
    let frontier_after = reg.call(&hub, &b, "task_list", json!({ "frontier": true })).await.unwrap();
    let frontier_ids_after: Vec<i64> =
        frontier_after["tasks"].as_array().unwrap().iter().map(|t| t["id"].as_i64().unwrap()).collect();
    assert_eq!(frontier_ids_after, vec![21], "unblocked task 21 must appear in org-b frontier");

    let queue_b =
        reg.call(&hub, &coord_b, "coordination_manage", json!({ "action": "queue_health" })).await.unwrap();
    assert_eq!(queue_b["ready_unowned"], 1, "unblocked task 21 must count in org-b ready_unowned: {queue_b}");

    // Default org writes to graph_edges (id 15) and advances sqlite_sequence so org-b's
    // next task_dependencies insert gets 16 (zero id collision across orgs).
    let dep_a = reg
        .call(&hub, &a, "dependency_add", json!({ "task_id": 11, "depends_on_task_id": 10 }))
        .await
        .unwrap()["dependency"]["id"]
        .as_i64()
        .unwrap();
    assert_eq!(dep_a, 15);

    let tb3 =
        reg.call(&hub, &b, "task_add", json!({ "title": "OrgB 3" })).await.unwrap()["id"].as_i64().unwrap();
    let dep_b2 = reg
        .call(&hub, &b, "dependency_add", json!({ "task_id": tb3, "depends_on_task_id": 21 }))
        .await
        .unwrap()["dependency"]["id"]
        .as_i64()
        .unwrap();
    assert_eq!(dep_b2, 16, "org-b dependency_add must not collide with default-org dep_id 15");

    // Cycle check and creator-only remove still work for org-b on task_dependencies.
    let cyc = reg
        .call(&hub, &b, "dependency_add", json!({ "task_id": 21, "depends_on_task_id": tb3 }))
        .await
        .unwrap_err();
    assert_eq!(cyc.code(), "invalid_argument");

    let denied =
        reg.call(&hub, &b2, "dependency_remove", json!({ "dependency_id": dep_b2 })).await.unwrap_err();
    assert_eq!(denied.reason_code(), Some("not_dependency_creator"));

    let removed = reg.call(&hub, &b, "dependency_remove", json!({ "dependency_id": dep_b2 })).await.unwrap();
    assert_eq!(removed, json!({ "removed": true, "dependency_id": dep_b2 }));

    // Cross-org isolation: default org cannot see org-b edges or tasks, and unknown org is refused.
    let list_a = reg.call(&hub, &a, "dependency_list", json!({})).await.unwrap();
    let a_ids: Vec<i64> =
        list_a["dependencies"].as_array().unwrap().iter().map(|d| d["id"].as_i64().unwrap()).collect();
    assert_eq!(a_ids, vec![dep_a]);

    let e_foreign = reg
        .call(&hub, &a, "dependency_add", json!({ "task_id": 10, "depends_on_task_id": 20 }))
        .await
        .unwrap_err();
    assert_eq!(e_foreign.code(), "not_found");

    let e_ghost = reg
        .call(&hub, &ghost, "dependency_add", json!({ "task_id": 10, "depends_on_task_id": 11 }))
        .await
        .unwrap_err();
    assert_eq!(e_ghost.reason_code(), Some("unknown_organization"));
}

#[tokio::test]
async fn default_org_readiness_queries_use_integer_primary_key_lookup_for_prerequisites() {
    let h = H::new();
    let b1 = agent("builder-1", DEFAULT_ORG);
    let t1 = h.add_task(&b1, "Prereq").await;
    let t2 = h.add_task(&b1, "Dependent").await;
    h.ok(&b1, "dependency_add", json!({ "task_id": t2, "depends_on_task_id": t1 })).await;

    let frontier_sql = "EXPLAIN QUERY PLAN \
        SELECT * FROM tasks WHERE org_id = 'default' \
        AND status NOT IN ('done', 'cancelled') AND NOT EXISTS ( \
            SELECT 1 FROM graph_nodes gn_src \
            JOIN graph_edges ge ON ge.org_id = gn_src.org_id AND ge.src_id = gn_src.id \
                AND ge.kind = 'depends_on' AND ge.state = 'active' AND ge.valid_to IS NULL \
            JOIN graph_nodes gn_dst ON gn_dst.org_id = ge.org_id AND gn_dst.id = ge.dst_id \
                AND gn_dst.kind = 'task' \
            JOIN tasks pre ON pre.id = CAST(gn_dst.external_id AS INTEGER) \
                AND pre.org_id = tasks.org_id \
            WHERE gn_src.org_id = tasks.org_id AND gn_src.kind = 'task' \
              AND gn_src.external_id = CAST(tasks.id AS TEXT) \
              AND pre.status NOT IN ('done', 'cancelled') \
        )";
    let ready_unowned_sql = "EXPLAIN QUERY PLAN \
        SELECT * FROM tasks WHERE org_id = 'default' AND archived_at IS NULL AND parked_at IS NULL \
        AND status NOT IN ('done','cancelled') \
        AND NOT EXISTS ( \
            SELECT 1 FROM graph_nodes gn_src \
            JOIN graph_edges ge ON ge.org_id = gn_src.org_id AND ge.src_id = gn_src.id \
                AND ge.kind = 'depends_on' AND ge.state = 'active' AND ge.valid_to IS NULL \
            JOIN graph_nodes gn_dst ON gn_dst.org_id = ge.org_id AND gn_dst.id = ge.dst_id \
                AND gn_dst.kind = 'task' \
            JOIN tasks p ON p.id = CAST(gn_dst.external_id AS INTEGER) AND p.org_id = 'default' \
            WHERE gn_src.org_id = 'default' AND gn_src.kind = 'task' \
              AND gn_src.external_id = CAST(tasks.id AS TEXT) \
              AND p.status NOT IN ('done','cancelled') \
        )";

    for (label, sql, alias) in
        [("task_list(frontier)", frontier_sql, "pre"), ("ready_unowned", ready_unowned_sql, "p")]
    {
        let plan: Vec<String> = h
            .hub
            .db()
            .read(|c| {
                let mut stmt = c.prepare(sql)?;
                let rows = stmt.query_map([], |r| r.get::<_, String>(3))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap();
        let joined = plan.join("\n");
        let want = format!("SEARCH {alias} USING INTEGER PRIMARY KEY (rowid=?)");
        assert!(
            joined.contains(&want),
            "{label} must look up prerequisite task `{alias}` by INTEGER PRIMARY KEY, got:\n{joined}"
        );
    }
}

/// Split masked Rust source into `fn <name>(...) { ... }` function bodies
/// (returning `(fn_name, body_start_offset, body_slice)`).
fn extract_fn_bodies(masked: &str) -> Vec<(&str, usize, &str)> {
    let b = masked.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b.get(i..i + 2) == Some(b"fn")
            && (i == 0 || !is_ident(b[i - 1]))
            && b.get(i + 2).is_some_and(|c| c.is_ascii_whitespace())
        {
            let mut k = i + 2;
            while k < b.len() && b[k].is_ascii_whitespace() {
                k += 1;
            }
            let name_start = k;
            while k < b.len() && is_ident(b[k]) {
                k += 1;
            }
            let name = &masked[name_start..k];
            if !name.is_empty() {
                let mut paren_depth = 0usize;
                let mut angle_depth = 0usize;
                while k < b.len() {
                    match b[k] {
                        b'(' => paren_depth += 1,
                        b')' => paren_depth = paren_depth.saturating_sub(1),
                        b'<' if paren_depth == 0 => angle_depth += 1,
                        b'>' if paren_depth == 0 && b.get(k.saturating_sub(1)) != Some(&b'-') => {
                            angle_depth = angle_depth.saturating_sub(1);
                        }
                        b';' if paren_depth == 0 && angle_depth == 0 => break,
                        b'{' if paren_depth == 0 && angle_depth == 0 => {
                            let body_start = k;
                            let mut depth = 0usize;
                            while k < b.len() {
                                if b[k] == b'{' {
                                    depth += 1;
                                } else if b[k] == b'}' {
                                    depth -= 1;
                                    if depth == 0 {
                                        out.push((name, body_start, &masked[body_start..=k]));
                                        break;
                                    }
                                }
                                k += 1;
                            }
                            break;
                        }
                        _ => {}
                    }
                    k += 1;
                }
            }
        }
        i += 1;
    }
    out
}

/// Check that every non-test graph `dependency_id` allocator (`next_dependency_id(`)
/// lives in `crates/ua-tools/src/families/tasks/graph.rs` and has a matching
/// `advance_dependency_sequence(` call in the **same function** after it, so
/// `sqlite_sequence('task_dependencies')` never falls behind `graph_edges` and
/// non-default organizations writing `task_dependencies` never collide on ids.
/// Returns `(violations, total_allocators_found)`.
fn dependency_sequence_guard_violations(files: &[(std::path::PathBuf, String)]) -> (Vec<String>, usize) {
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let call_positions = |masked: &str, name: &str| -> Vec<usize> {
        let needle = format!("{name}(");
        support::find_all(masked, &needle)
            .filter(|&at| {
                // Skip the function's own `fn <name>(` definition.
                let before = masked[..at].trim_end();
                let prev_word =
                    before.rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).next().unwrap_or("");
                prev_word != "fn" && (at == 0 || !is_ident(masked.as_bytes()[at - 1]))
            })
            .collect()
    };

    let mut violations = Vec::new();
    let mut total_allocators = 0usize;
    for (path, src) in files {
        let path_str = path.display().to_string().replace('\\', "/");
        let masked = support::without_tests(src);
        let file_allocs = call_positions(&masked, "next_dependency_id");
        let file_advances = call_positions(&masked, "advance_dependency_sequence");
        if file_allocs.is_empty() && file_advances.is_empty() {
            continue;
        }
        total_allocators += file_allocs.len();
        if !path_str.ends_with("crates/ua-tools/src/families/tasks/graph.rs") {
            violations.push(format!(
                "{path_str}: unexpected dependency_id allocator outside crates/ua-tools/src/families/tasks/graph.rs"
            ));
            continue;
        }
        let mut matched_allocs = 0usize;
        for (fn_name, body_start, body) in extract_fn_bodies(&masked) {
            let allocs = call_positions(body, "next_dependency_id");
            let advances = call_positions(body, "advance_dependency_sequence");
            if allocs.is_empty() {
                continue;
            }
            matched_allocs += allocs.len();
            if allocs.len() != advances.len() {
                violations.push(format!(
                    "{path_str}::{fn_name}: found {} `next_dependency_id(` call(s) but {} \
                     `advance_dependency_sequence(` call(s) in the same function; every graph \
                     dependency_id allocator must advance sqlite_sequence('task_dependencies')",
                    allocs.len(),
                    advances.len()
                ));
                continue;
            }
            for (alloc_at, adv_at) in allocs.iter().zip(advances.iter()) {
                if adv_at <= alloc_at {
                    violations.push(format!(
                        "{path_str}:{}: in `{fn_name}`, `advance_dependency_sequence` must be called after `next_dependency_id`",
                        support::line_of(&masked, body_start + *alloc_at)
                    ));
                }
            }
        }
        if matched_allocs != file_allocs.len() {
            violations
                .push(format!("{path_str}: found `next_dependency_id(` outside an analyzed function body"));
        }
    }
    (violations, total_allocators)
}

#[test]
fn every_graph_dependency_id_allocator_calls_advance_dependency_sequence() {
    let files = support::sources();
    assert!(files.len() > 100, "found only {} workspace source files", files.len());
    let (violations, total_allocators) = dependency_sequence_guard_violations(&files);
    assert!(
        total_allocators >= 1,
        "expected at least 1 graph dependency_id allocator (`next_dependency_id(`); update this guard if renamed"
    );
    assert!(violations.is_empty(), "dependency_id sequence guard violations:\n{}", violations.join("\n"));

    // Self-check: a missing `advance_dependency_sequence` call is caught.
    let bad = vec![(
        std::path::PathBuf::from("crates/ua-tools/src/families/tasks/graph.rs"),
        r#"
            fn next_dependency_id(c: &Connection) -> i64 { 1 }
            fn advance_dependency_sequence(c: &Connection, id: i64) {}
            fn dep_add(tx: &Connection) {
                let id = next_dependency_id(tx);
                let _ = id;
            }
        "#
        .to_string(),
    )];
    let (caught, _) = dependency_sequence_guard_violations(&bad);
    assert_eq!(caught.len(), 1, "{caught:?}");
    assert!(caught[0].contains("advance_dependency_sequence"), "{caught:?}");

    // Self-check: an `advance_dependency_sequence` call in a DIFFERENT function does not satisfy
    // the allocator's function (paired per function, not just by file-level position).
    let wrong_fn = vec![(
        std::path::PathBuf::from("crates/ua-tools/src/families/tasks/graph.rs"),
        r#"
            fn next_dependency_id(c: &Connection) -> i64 { 1 }
            fn advance_dependency_sequence(c: &Connection, id: i64) {}
            fn dep_add(tx: &Connection) {
                let id = next_dependency_id(tx);
                let _ = id;
            }
            fn unrelated(tx: &Connection) {
                advance_dependency_sequence(tx, 1);
            }
        "#
        .to_string(),
    )];
    let (caught_wrong_fn, _) = dependency_sequence_guard_violations(&wrong_fn);
    assert_eq!(caught_wrong_fn.len(), 1, "{caught_wrong_fn:?}");
    assert!(caught_wrong_fn[0].contains("dep_add"), "{caught_wrong_fn:?}");

    // Self-check: an allocator added in another file is caught.
    let rogue = vec![(
        std::path::PathBuf::from("crates/ua-tools/src/families/tasks/write.rs"),
        "fn sneak(tx: &Connection) { let id = next_dependency_id(tx); advance_dependency_sequence(tx, id); }"
            .to_string(),
    )];
    let (caught_rogue, _) = dependency_sequence_guard_violations(&rogue);
    assert_eq!(caught_rogue.len(), 1, "{caught_rogue:?}");
}
