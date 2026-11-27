//! Domain and storage-level tests for `ua-graph` and `ua-store::graph`
//! (`docs/graph.md`, C1 acceptance tests).

use rusqlite::Connection;
use serde_json::json;
use ua_core::{DEFAULT_ORG, UaError};
use ua_graph::{
    AssertEdgeRequest, AssertedByKind, CycleCheckBounds, CycleCheckPolicy, EVENT_EDGE_UPDATED,
    EVENT_NODE_UPDATED, EdgeKind, EdgeState, EnsureNodeRequest, FieldPatch, KHopRequest, NeighborsRequest,
    NodeKind, OwnerType, PrincipalId, Provenance, RetractEdgeRequest, SeedExpandRequest, SeedInput,
    ShortestPathRequest, SourceKind, UpdateEdgeWeightRequest, UpdateNodeRequest, Visibility, WalkDirection,
    assert_edge, check_acyclic, graph_edge_update_weight, graph_node_ensure, graph_node_update, k_hop,
    neighbors, node_get, retract_edge, schema_parts, seed_expand, shortest_path,
};
use ua_store::graph::{
    EdgeDirection, GraphNodePatch, GraphRead, GraphRepo, NewGraphEdge, NewGraphNode, SqliteGraph,
    VisibilityScope,
};
use ua_store::{Db, Part, ledger, org};

fn open_graph_db() -> Db {
    let mut parts: Vec<Part> =
        vec![ledger::SCHEMA.into(), ledger::META_SCHEMA.into(), org::STORE_PART.into()];
    parts.extend(schema_parts());
    let db = Db::open_in_memory(&parts).expect("open in-memory graph db");
    // Seed a second organization (`org-b`) for cross-org tests.
    db.write(|tx| {
        tx.execute(
            "INSERT INTO orgs (id, slug, display_name, status, created_at) \
             VALUES ('org-b', 'org-b', 'Org B', 'active', ?1)",
            [ua_core::time::now()],
        )?;
        Ok(())
    })
    .expect("seed org-b");
    db
}

fn prov_agent(label: &str) -> Provenance {
    Provenance {
        asserted_by: PrincipalId::new(label).unwrap(),
        asserted_by_kind: AssertedByKind::Agent,
        source_kind: SourceKind::Event,
        source_ref: "tool:test".to_string(),
    }
}

fn prov_system_import() -> Provenance {
    Provenance {
        asserted_by: PrincipalId::system(),
        asserted_by_kind: AssertedByKind::System,
        source_kind: SourceKind::Import,
        source_ref: "import:fixture".to_string(),
    }
}

fn ensure_org_node(db: &Db, org_id: &str, kind: NodeKind, ext: &str) -> ua_store::graph::GraphNodeRow {
    let prov = if org_id == DEFAULT_ORG { prov_agent("builder-1") } else { prov_system_import() };
    db.write(|tx| {
        let (row, _) = graph_node_ensure(
            tx,
            EnsureNodeRequest {
                org_id: org_id.to_string(),
                kind,
                external_id: ext.to_string(),
                display_label: Some(format!("{kind}:{ext}")),
                visibility: Visibility::Org,
                team_id: None,
                owner_type: None,
                owner_id: None,
                provenance: prov,
                meta_json: None,
                max_nodes_per_org: 0,
            },
        )?;
        Ok(row)
    })
    .expect("ensure node")
}

#[test]
fn ddl_immutability_triggers_and_system_check_constraints() {
    let db = open_graph_db();
    let n1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, "t1");
    let n2 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, "t2");

    let e1 = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n1.id.clone(),
                    dst_id: n2.id.clone(),
                    kind: EdgeKind::DependsOn,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .expect("assert depends_on");

    // 1. Immutability triggers on graph_nodes (including `id` and provenance).
    for col_stmt in [
        "UPDATE graph_nodes SET id = 'new-id' WHERE id = ?1",
        "UPDATE graph_nodes SET kind = 'goal' WHERE id = ?1",
        "UPDATE graph_nodes SET external_id = 'changed' WHERE id = ?1",
        "UPDATE graph_nodes SET asserted_by = 'other' WHERE id = ?1",
        "UPDATE graph_nodes SET asserted_by_kind = 'person' WHERE id = ?1",
        "UPDATE graph_nodes SET source_kind = 'import' WHERE id = ?1",
        "UPDATE graph_nodes SET source_ref = 'import:x' WHERE id = ?1",
        "UPDATE graph_nodes SET created_at = '2020-01-01T00:00:00+00:00' WHERE id = ?1",
        "DELETE FROM graph_nodes WHERE id = ?1",
    ] {
        let res = db.write(|tx| {
            tx.execute(col_stmt, [&n1.id])?;
            Ok(())
        });
        assert!(res.is_err(), "expected trigger abort for: {col_stmt}");
    }

    // 2. Immutability triggers on graph_edges (including `id`, endpoints, provenance, delete, revert).
    for col_stmt in [
        "UPDATE graph_edges SET id = 'new-edge-id' WHERE id = ?1",
        "UPDATE graph_edges SET src_id = dst_id WHERE id = ?1",
        "UPDATE graph_edges SET dst_id = src_id WHERE id = ?1",
        "UPDATE graph_edges SET kind = 'subtask_of' WHERE id = ?1",
        "UPDATE graph_edges SET assertion_scope = 'x' WHERE id = ?1",
        "UPDATE graph_edges SET asserted_by = 'other' WHERE id = ?1",
        "UPDATE graph_edges SET asserted_by_kind = 'person' WHERE id = ?1",
        "UPDATE graph_edges SET asserted_at = '2020-01-01T00:00:00+00:00' WHERE id = ?1",
        "UPDATE graph_edges SET source_kind = 'import' WHERE id = ?1",
        "UPDATE graph_edges SET source_ref = 'import:x' WHERE id = ?1",
        "UPDATE graph_edges SET valid_from = '2020-01-01T00:00:00+00:00' WHERE id = ?1",
        "UPDATE graph_edges SET state = 'proposed' WHERE id = ?1",
        "DELETE FROM graph_edges WHERE id = ?1",
    ] {
        let res = db.write(|tx| {
            tx.execute(col_stmt, [&e1.id])?;
            Ok(())
        });
        assert!(res.is_err(), "expected trigger abort for: {col_stmt}");
    }

    // 3. graph_edges_valid_to_once: closing once works; changing/reopening aborts.
    let now_ts = ua_core::time::now();
    db.write(|tx| {
        tx.execute("UPDATE graph_edges SET valid_to = ?1 WHERE id = ?2", [&now_ts, &e1.id])?;
        Ok(())
    })
    .expect("close once");
    assert!(
        db.write(|tx| {
            tx.execute("UPDATE graph_edges SET valid_to = NULL WHERE id = ?1", [&e1.id])?;
            Ok(())
        })
        .is_err(),
        "reopening a closed edge must abort"
    );

    // 4. CHECK ((asserted_by = 'system') = (asserted_by_kind = 'system')) on both tables.
    for (ab, abk) in [("system", "agent"), ("builder-1", "system")] {
        let node_res = db.write(|tx| {
            tx.execute(
                "INSERT INTO graph_nodes (id, org_id, kind, external_id, asserted_by, asserted_by_kind, \
                 source_kind, source_ref, created_at, updated_at) \
                 VALUES ('bad-n', 'default', 'task', 'bad-ext', ?1, ?2, 'tool', 'tool:x', ?3, ?3)",
                rusqlite::params![ab, abk, now_ts],
            )?;
            Ok(())
        });
        assert!(node_res.is_err(), "graph_nodes CHECK must reject ({ab}, {abk})");

        let edge_res = db.write(|tx| {
            tx.execute(
                "INSERT INTO graph_edges (id, org_id, src_id, dst_id, kind, asserted_by, asserted_by_kind, \
                 asserted_at, source_kind, source_ref, valid_from) \
                 VALUES ('bad-e', 'default', ?1, ?2, 'depends_on', ?3, ?4, ?5, 'tool', 'tool:x', ?5)",
                rusqlite::params![n1.id, n2.id, ab, abk, now_ts],
            )?;
            Ok(())
        });
        assert!(edge_res.is_err(), "graph_edges CHECK must reject ({ab}, {abk})");
    }
}

#[test]
fn cross_org_endpoint_fence_holds_with_foreign_keys_off_and_on() {
    for fk in ["OFF", "ON"] {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute(&format!("PRAGMA foreign_keys = {fk};"), []).unwrap();
        let mut parts: Vec<Part> =
            vec![ledger::SCHEMA.into(), ledger::META_SCHEMA.into(), org::STORE_PART.into()];
        parts.extend(schema_parts());
        ua_store::schema::apply(&mut conn, &parts).unwrap();
        let ts = ua_core::time::now();
        conn.execute(
            "INSERT INTO orgs (id, slug, display_name, status, created_at) \
             VALUES ('org-b', 'org-b', 'Org B', 'active', ?1)",
            [&ts],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO graph_nodes (id, org_id, kind, external_id, asserted_by, asserted_by_kind, \
             source_kind, source_ref, created_at, updated_at) \
             VALUES ('n-a', 'default', 'task', '1', 'system', 'system', 'import', 'import:1', ?1, ?1)",
            [&ts],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO graph_nodes (id, org_id, kind, external_id, asserted_by, asserted_by_kind, \
             source_kind, source_ref, created_at, updated_at) \
             VALUES ('n-b', 'org-b', 'task', '1', 'system', 'system', 'import', 'import:1', ?1, ?1)",
            [&ts],
        )
        .unwrap();

        let err = conn.execute(
            "INSERT INTO graph_edges (id, org_id, src_id, dst_id, kind, asserted_by, asserted_by_kind, \
             asserted_at, source_kind, source_ref, valid_from) \
             VALUES ('e-cross', 'default', 'n-a', 'n-b', 'depends_on', 'system', 'system', ?1, 'import', 'import:1', ?1)",
            [&ts],
        );
        assert!(err.is_err(), "cross-org edge insert must abort with PRAGMA foreign_keys = {fk}");
    }
}

#[test]
fn valid_to_le_now_enforced_through_repo_even_though_db_alone_accepts_future() {
    let db = open_graph_db();
    let n1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "m1");
    let n2 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "m2");
    let n3 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "m3");
    let now_ts = ua_core::time::now();
    let future_ts = "2099-01-01T00:00:00+00:00";

    // Confirm raw SQL alone accepts a future valid_to (as documented).
    db.write(|tx| {
        tx.execute(
            "INSERT INTO graph_edges (id, org_id, src_id, dst_id, kind, asserted_by, asserted_by_kind, \
             asserted_at, source_kind, source_ref, valid_from, valid_to) \
             VALUES ('raw-future', 'default', ?1, ?2, 'extends', 'builder-1', 'agent', ?3, 'tool', 'tool:raw', ?3, ?4)",
            rusqlite::params![n1.id, n2.id, now_ts, future_ts],
        )?;
        Ok(())
    })
    .expect("raw SQL accepts future valid_to");

    // Through GraphRepo::insert_edge, future valid_to is refused.
    let err = db
        .write(|tx| {
            tx.insert_edge(&NewGraphEdge {
                id: ulid::Ulid::generate().to_string(),
                org_id: DEFAULT_ORG.into(),
                src_id: n2.id.clone(),
                dst_id: n3.id.clone(),
                kind: "extends".into(),
                assertion_scope: String::new(),
                state: "active".into(),
                weight: 1.0,
                asserted_by: "builder-1".into(),
                asserted_by_kind: "agent".into(),
                asserted_at: now_ts.clone(),
                source_kind: "tool".into(),
                source_ref: "tool:test".into(),
                valid_from: now_ts.clone(),
                valid_to: Some(future_ts.into()),
                meta_json: "{}".into(),
            })
        })
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert_eq!(err.reason_code(), Some("future_valid_to"));

    // Through GraphRepo::close_edge, future valid_to is also refused.
    let live = db
        .write(|tx| {
            tx.insert_edge(&NewGraphEdge {
                id: ulid::Ulid::generate().to_string(),
                org_id: DEFAULT_ORG.into(),
                src_id: n2.id.clone(),
                dst_id: n3.id.clone(),
                kind: "extends".into(),
                assertion_scope: String::new(),
                state: "active".into(),
                weight: 1.0,
                asserted_by: "builder-1".into(),
                asserted_by_kind: "agent".into(),
                asserted_at: now_ts.clone(),
                source_kind: "tool".into(),
                source_ref: "tool:test".into(),
                valid_from: now_ts.clone(),
                valid_to: None,
                meta_json: "{}".into(),
            })
        })
        .expect("insert live edge");

    let close_err = db.write(|tx| tx.close_edge(DEFAULT_ORG, &live.id, future_ts)).unwrap_err();
    assert_eq!(close_err.code(), "invalid_argument");
    assert_eq!(close_err.reason_code(), Some("future_valid_to"));

    // Backdating valid_from on non-import edges is also refused.
    let backdate_err = db
        .write(|tx| {
            tx.insert_edge(&NewGraphEdge {
                id: ulid::Ulid::generate().to_string(),
                org_id: DEFAULT_ORG.into(),
                src_id: n3.id.clone(),
                dst_id: n1.id.clone(),
                kind: "extends".into(),
                assertion_scope: String::new(),
                state: "active".into(),
                weight: 1.0,
                asserted_by: "builder-1".into(),
                asserted_by_kind: "agent".into(),
                asserted_at: now_ts.clone(),
                source_kind: "event".into(),
                source_ref: "event:1".into(),
                valid_from: "2020-01-01T00:00:00+00:00".into(),
                valid_to: None,
                meta_json: "{}".into(),
            })
        })
        .unwrap_err();
    assert_eq!(backdate_err.code(), "invalid_argument");
}

#[test]
fn non_default_org_non_system_asserted_by_is_refused_in_repo_and_domain() {
    let db = open_graph_db();
    let now_ts = ua_core::time::now();

    // Direct GraphRepo::ensure_node with non-system principal in org-b -> refused.
    let err = db
        .write(|tx| {
            tx.ensure_node(&NewGraphNode {
                id: ulid::Ulid::generate().to_string(),
                org_id: "org-b".into(),
                kind: "task".into(),
                external_id: "t1".into(),
                display_label: None,
                visibility: "org".into(),
                team_id: None,
                owner_type: None,
                owner_id: None,
                asserted_by: "builder-1".into(),
                asserted_by_kind: "agent".into(),
                source_kind: "event".into(),
                source_ref: "event:1".into(),
                meta_json: "{}".into(),
                created_at: now_ts.clone(),
                updated_at: now_ts.clone(),
            })
        })
        .unwrap_err();
    assert_eq!(err.code(), "denied");
    assert_eq!(err.reason_code(), Some("principal_id_required"));

    // System import in org-b succeeds.
    let b1 = ensure_org_node(&db, "org-b", NodeKind::Task, "t1");
    let b2 = ensure_org_node(&db, "org-b", NodeKind::Task, "t2");

    // Direct GraphRepo::insert_edge with non-system principal in org-b -> refused.
    let edge_err = db
        .write(|tx| {
            tx.insert_edge(&NewGraphEdge {
                id: ulid::Ulid::generate().to_string(),
                org_id: "org-b".into(),
                src_id: b1.id.clone(),
                dst_id: b2.id.clone(),
                kind: "depends_on".into(),
                assertion_scope: String::new(),
                state: "active".into(),
                weight: 1.0,
                asserted_by: "builder-1".into(),
                asserted_by_kind: "agent".into(),
                asserted_at: now_ts.clone(),
                source_kind: "event".into(),
                source_ref: "event:2".into(),
                valid_from: now_ts.clone(),
                valid_to: None,
                meta_json: "{}".into(),
            })
        })
        .unwrap_err();
    assert_eq!(edge_err.code(), "denied");
    assert_eq!(edge_err.reason_code(), Some("principal_id_required"));
}

#[test]
fn cycle_detected_vs_cycle_check_bound_exceeded_are_distinct() {
    let db = open_graph_db();
    // Build a 15-node chain: n0 -> n1 -> ... -> n14
    let nodes: Vec<_> =
        (0..15).map(|i| ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, &format!("c-{i}"))).collect();
    db.write(|tx| {
        for w in nodes.windows(2) {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: w[0].id.clone(),
                    dst_id: w[1].id.clone(),
                    kind: EdgeKind::DependsOn,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
        }
        Ok(())
    })
    .expect("seed chain");

    // 1. Real cycle: n14 -> n0 => invalid_argument + cycle_detected
    let cyc_err = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: nodes[14].id.clone(),
                    dst_id: nodes[0].id.clone(),
                    kind: EdgeKind::DependsOn,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap_err();
    assert_eq!(cyc_err.code(), "invalid_argument");
    assert_eq!(cyc_err.reason_code(), Some("cycle_detected"));

    // 2. Node-cap bound hit (non-cyclic edge n_new -> n0 with max_nodes = 5) => cycle_check_bound_exceeded
    let n_new = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, "c-new");
    let node_bound_err = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n_new.id.clone(),
                    dst_id: nodes[0].id.clone(),
                    kind: EdgeKind::DependsOn,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::all(CycleCheckBounds {
                        max_nodes: 5,
                        max_edges: 5_000,
                        deadline_ms: ua_graph::CYCLE_CHECK_DEADLINE_MS,
                    }),
                },
            )
        })
        .unwrap_err();
    assert_eq!(node_bound_err.code(), "invalid_argument");
    assert_eq!(node_bound_err.reason_code(), Some("cycle_check_bound_exceeded"));

    // 3. Edge-cap bound hit => cycle_check_bound_exceeded
    let edge_bound_err = db
        .read_mut(|conn| {
            let mut repo = SqliteGraph::new(conn);
            check_acyclic(
                &mut repo,
                DEFAULT_ORG,
                &n_new.id,
                &nodes[0].id,
                EdgeKind::DependsOn,
                CycleCheckBounds {
                    max_nodes: 1_000,
                    max_edges: 4,
                    deadline_ms: ua_graph::CYCLE_CHECK_DEADLINE_MS,
                },
            )
        })
        .unwrap_err();
    assert_eq!(edge_bound_err.code(), "invalid_argument");
    assert_eq!(edge_bound_err.reason_code(), Some("cycle_check_bound_exceeded"));

    // 4. Deadline bound hit (0 ms) => cycle_check_bound_exceeded
    let deadline_err = db
        .read_mut(|conn| {
            let mut repo = SqliteGraph::new(conn);
            check_acyclic(
                &mut repo,
                DEFAULT_ORG,
                &n_new.id,
                &nodes[0].id,
                EdgeKind::DependsOn,
                CycleCheckBounds { max_nodes: 1_000, max_edges: 5_000, deadline_ms: 0 },
            )
        })
        .unwrap_err();
    assert_eq!(deadline_err.code(), "invalid_argument");
    assert_eq!(deadline_err.reason_code(), Some("cycle_check_bound_exceeded"));
    assert!(deadline_err.to_string().contains("deadline"), "{deadline_err}");

    // 5. Default wall-clock backstop is generous (>= 1,000 ms, work bounds are primary)
    //    and a completed bounded answer is never discarded due to post-query scheduling delay,
    //    while an in-flight SQL deadline interrupt maps to cycle_check_bound_exceeded.
    const {
        assert!(ua_graph::CYCLE_CHECK_DEADLINE_MS >= 1_000);
    }
    struct PreemptedRead {
        outcome: ua_store::graph::AcyclicReachOutcome,
        sleep_ms: u64,
    }
    impl ua_store::graph::GraphRead for PreemptedRead {
        fn require_org_exists(&mut self, _: &str) -> ua_core::UaResult<()> {
            unreachable!()
        }
        fn get_node_by_id(
            &mut self,
            _: &str,
            _: &str,
            _: &VisibilityScope,
        ) -> ua_core::UaResult<Option<ua_store::graph::GraphNodeRow>> {
            unreachable!()
        }
        fn get_node_by_external(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
            _: &VisibilityScope,
        ) -> ua_core::UaResult<Option<ua_store::graph::GraphNodeRow>> {
            unreachable!()
        }
        fn get_nodes_by_ids(
            &mut self,
            _: &str,
            _: &[String],
            _: &VisibilityScope,
        ) -> ua_core::UaResult<Vec<ua_store::graph::GraphNodeRow>> {
            unreachable!()
        }
        fn get_edge_by_id(
            &mut self,
            _: &str,
            _: &str,
        ) -> ua_core::UaResult<Option<ua_store::graph::GraphEdgeRow>> {
            unreachable!()
        }
        fn get_edges_by_ids(
            &mut self,
            _: &str,
            _: &[String],
        ) -> ua_core::UaResult<Vec<ua_store::graph::GraphEdgeRow>> {
            unreachable!()
        }
        fn get_edges_by_rowids(
            &mut self,
            _: &str,
            _: &[i64],
        ) -> ua_core::UaResult<Vec<(i64, ua_store::graph::GraphEdgeRow)>> {
            unreachable!()
        }
        fn count_org_nodes(&mut self, _: &str) -> ua_core::UaResult<u64> {
            unreachable!()
        }
        fn count_org_edges(&mut self, _: &str) -> ua_core::UaResult<u64> {
            unreachable!()
        }
        fn count_node_live_edges_capped(&mut self, _: &str, _: &str, _: usize) -> ua_core::UaResult<usize> {
            unreachable!()
        }
        fn with_deadline<F, T>(&mut self, _: std::time::Instant, f: F) -> ua_core::UaResult<T>
        where
            F: FnOnce(&mut Self) -> ua_core::UaResult<T>,
        {
            f(self)
        }
        fn adjacent_edges(
            &mut self,
            _: &ua_store::graph::AdjacencyQuery,
        ) -> ua_core::UaResult<Vec<ua_store::graph::AdjacencyEntry>> {
            unreachable!()
        }
        fn compact_adjacent(
            &mut self,
            _: &str,
            _: &str,
            _: EdgeDirection,
            _: &ua_store::graph::EdgeFilter,
            _: &VisibilityScope,
            _: usize,
        ) -> ua_core::UaResult<Vec<ua_store::graph::CompactAdjEdge>> {
            unreachable!()
        }
        fn with_compact_adjacent<F, T>(
            &mut self,
            _: &str,
            _: EdgeDirection,
            _: &ua_store::graph::EdgeFilter,
            _: &VisibilityScope,
            _: F,
        ) -> ua_core::UaResult<T>
        where
            F: FnOnce(
                &mut dyn FnMut(
                    &str,
                    EdgeDirection,
                    usize,
                    &mut Vec<ua_store::graph::CompactAdjEdge>,
                ) -> ua_core::UaResult<()>,
            ) -> ua_core::UaResult<T>,
        {
            unreachable!()
        }
        fn bounded_acyclic_reach(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: usize,
            _: usize,
            _: std::time::Instant,
        ) -> ua_core::UaResult<ua_store::graph::AcyclicReachOutcome> {
            if self.sleep_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(self.sleep_ms));
            }
            Ok(self.outcome.clone())
        }
        fn eligible_degree(
            &mut self,
            _: &str,
            _: &str,
            _: EdgeDirection,
            _: &ua_store::graph::EdgeFilter,
            _: &VisibilityScope,
            _: usize,
        ) -> ua_core::UaResult<usize> {
            unreachable!()
        }
        fn outgoing_live_targets_of_kind_into(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
            _: usize,
            _: &mut Vec<String>,
        ) -> ua_core::UaResult<()> {
            unreachable!()
        }
        fn exact_ppr_slice(
            &mut self,
            _: &str,
            _: &ua_store::graph::EdgeFilter,
            _: &VisibilityScope,
            _: usize,
            _: usize,
        ) -> ua_core::UaResult<Option<ua_store::graph::ExactPprSlice>> {
            unreachable!()
        }
    }

    // Completed bounded proof is preserved even if thread was delayed past deadline_ms.
    let mut completed =
        PreemptedRead { outcome: ua_store::graph::AcyclicReachOutcome::Acyclic, sleep_ms: 15 };
    check_acyclic(
        &mut completed,
        DEFAULT_ORG,
        "a",
        "b",
        EdgeKind::DependsOn,
        CycleCheckBounds { max_nodes: 1_000, max_edges: 5_000, deadline_ms: 5 },
    )
    .expect("already-completed bounded acyclic proof must not be discarded");

    // In-flight SQL progress-handler deadline interrupt still fails closed with cycle_check_bound_exceeded.
    let mut interrupted = PreemptedRead {
        outcome: ua_store::graph::AcyclicReachOutcome::BoundExceeded("deadline"),
        sleep_ms: 0,
    };
    let int_err = check_acyclic(
        &mut interrupted,
        DEFAULT_ORG,
        "a",
        "b",
        EdgeKind::DependsOn,
        CycleCheckBounds { max_nodes: 1_000, max_edges: 5_000, deadline_ms: 2_000 },
    )
    .unwrap_err();
    assert_eq!(int_err.code(), "invalid_argument");
    assert_eq!(int_err.reason_code(), Some("cycle_check_bound_exceeded"));
    assert!(int_err.to_string().contains("exceeded deadline of 2000 ms"), "{int_err}");
}

#[test]
fn assert_never_creates_nodes_and_validates_endpoint_kinds() {
    let db = open_graph_db();
    let goal1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Goal, "g1");
    let goal2 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Goal, "g2");
    let note1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "mn1");
    let foreign_note = ensure_org_node(&db, "org-b", NodeKind::MemoryNote, "mn-foreign");

    // Missing endpoint -> not_found, node count unchanged.
    let before_count = db.read_mut(|c| SqliteGraph::new(c).count_org_nodes(DEFAULT_ORG)).unwrap();
    let miss_err = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: note1.id.clone(),
                    dst_id: "01MISSINGNODE00000000000000".into(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap_err();
    let foreign_err = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: note1.id.clone(),
                    dst_id: foreign_note.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap_err();
    assert_eq!(miss_err.code(), "not_found");
    assert_eq!(foreign_err.code(), "not_found");
    assert_eq!(miss_err.to_string(), foreign_err.to_string(), "zero existence oracle");
    let after_count = db.read_mut(|c| SqliteGraph::new(c).count_org_nodes(DEFAULT_ORG)).unwrap();
    assert_eq!(before_count, after_count, "assert_edge must never create nodes");

    // Endpoint-kind mismatch: `depends_on` between `goal` nodes -> invalid_endpoint_kind.
    let kind_err = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: goal1.id.clone(),
                    dst_id: goal2.id.clone(),
                    kind: EdgeKind::DependsOn,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap_err();
    assert_eq!(kind_err.code(), "invalid_argument");
    assert_eq!(kind_err.reason_code(), Some("invalid_endpoint_kind"));

    // Generic mismatch: `extends` between `goal` and `memory_note` -> invalid_endpoint_kind.
    let gen_kind_err = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: goal1.id.clone(),
                    dst_id: note1.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap_err();
    assert_eq!(gen_kind_err.code(), "invalid_argument");
    assert_eq!(gen_kind_err.reason_code(), Some("invalid_endpoint_kind"));
}

#[test]
fn same_org_visibility_before_after_invariant_and_as_of_reads() {
    let db = open_graph_db();
    let n_a = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "public-a");
    let n_b = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "public-b");
    let n_c = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "public-c");

    // Seed public edges A -> B -> C
    let e_ab = db
        .write(|tx| {
            let e1 = assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n_a.id.clone(),
                    dst_id: n_b.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n_b.id.clone(),
                    dst_id: n_c.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
            Ok(e1)
        })
        .unwrap();

    let outsider = VisibilityScope::for_principal("agent", "outsider", vec![]);
    let owner = VisibilityScope::for_principal("agent", "owner-1", vec![]);

    let snapshot = |scope: &VisibilityScope| {
        db.read_mut(|conn| {
            let mut repo = SqliteGraph::new(conn);
            let nbrs = neighbors(
                &mut repo,
                NeighborsRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: Some(n_a.id.clone()),
                    kind: None,
                    external_id: None,
                    direction: EdgeDirection::Both,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    limit: Some(50),
                    cursor: None,
                    deadline_ms: None,
                    scope: scope.clone(),
                },
            )?;
            let kh = k_hop(
                &mut repo,
                KHopRequest {
                    org_id: DEFAULT_ORG.into(),
                    seed_ids: vec![n_a.id.clone()],
                    max_hops: Some(2),
                    direction: EdgeDirection::Both,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    max_nodes: Some(50),
                    max_edges: Some(50),
                    max_degree_per_node: Some(50),
                    max_visited_edges: Some(100),
                    skip_hubs_over: Some(2),
                    deadline_ms: None,
                    scope: scope.clone(),
                },
            )?;
            let sp = shortest_path(
                &mut repo,
                ShortestPathRequest {
                    org_id: DEFAULT_ORG.into(),
                    from_id: n_a.id.clone(),
                    to_id: n_c.id.clone(),
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    max_depth: Some(4),
                    deadline_ms: None,
                    scope: scope.clone(),
                },
            )?;
            let ppr = seed_expand(
                &mut repo,
                SeedExpandRequest {
                    org_id: DEFAULT_ORG.into(),
                    seeds: vec![SeedInput { node_id: n_a.id.clone(), weight: 1.0 }],
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    walk_direction: WalkDirection::Undirected,
                    damping: None,
                    max_iters: None,
                    eps: None,
                    max_results: Some(10),
                    skip_hubs_over: Some(2),
                    deadline_ms: None,
                    scope: scope.clone(),
                },
            )?;
            Ok(json!({ "nbrs": nbrs, "kh": kh, "sp": sp, "ppr": ppr }))
        })
        .unwrap()
    };

    let before = snapshot(&outsider);

    // Add 5 private memory_notes owned by `owner-1` linked directly from `n_a`
    // (enough to push `n_a`'s raw degree well past `skip_hubs_over = 2`!).
    db.write(|tx| {
        for i in 0..5 {
            let (priv_n, _) = graph_node_ensure(
                tx,
                EnsureNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    kind: NodeKind::MemoryNote,
                    external_id: format!("secret-{i}"),
                    display_label: Some("secret".into()),
                    visibility: Visibility::Private,
                    team_id: None,
                    owner_type: Some(OwnerType::Agent),
                    owner_id: Some("owner-1".into()),
                    provenance: prov_agent("owner-1"),
                    meta_json: None,
                    max_nodes_per_org: 0,
                },
            )?;
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n_a.id.clone(),
                    dst_id: priv_n.id,
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 10.0,
                    provenance: prov_agent("owner-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: owner.clone(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
        }
        Ok(())
    })
    .expect("add private notes");

    let after = snapshot(&outsider);
    assert_eq!(
        before, after,
        "hidden private nodes/edges must never alter outsider output, hub cutoff, PPR scores, or shortest paths"
    );

    // Owner DOES see the private nodes.
    let owner_view = snapshot(&owner);
    assert_eq!(owner_view["nbrs"]["neighbors"].as_array().unwrap().len(), 6);

    // Historical as_of read: insert an imported edge [2025-01-01, 2025-06-01),
    // verify visible at 2025-03-01 and invisible at 2025-06-01 (half-open).
    let hist_edge = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n_c.id.clone(),
                    dst_id: n_a.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 2.0,
                    provenance: prov_system_import(),
                    valid_from: Some("2025-01-01T00:00:00+00:00".into()),
                    valid_to: Some("2025-06-01T00:00:00+00:00".into()),
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .expect("import historical edge");

    let at_mid = db
        .read_mut(|conn| {
            let mut repo = SqliteGraph::new(conn);
            neighbors(
                &mut repo,
                NeighborsRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: Some(n_c.id.clone()),
                    kind: None,
                    external_id: None,
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![EdgeKind::Extends],
                    node_kinds: vec![],
                    as_of: Some("2025-03-01T00:00:00+00:00".into()),
                    include_proposed: false,
                    limit: None,
                    cursor: None,
                    deadline_ms: None,
                    scope: outsider.clone(),
                },
            )
        })
        .unwrap();
    assert_eq!(at_mid.neighbors.len(), 1);
    assert_eq!(at_mid.neighbors[0].edge.id, hist_edge.id);

    let at_end = db
        .read_mut(|conn| {
            let mut repo = SqliteGraph::new(conn);
            neighbors(
                &mut repo,
                NeighborsRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: Some(n_c.id.clone()),
                    kind: None,
                    external_id: None,
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![EdgeKind::Extends],
                    node_kinds: vec![],
                    as_of: Some("2025-06-01T00:00:00+00:00".into()),
                    include_proposed: false,
                    limit: None,
                    cursor: None,
                    deadline_ms: None,
                    scope: outsider.clone(),
                },
            )
        })
        .unwrap();
    assert!(at_end.neighbors.is_empty(), "half-open [valid_from, valid_to) excludes valid_to");

    // Retract e_ab and verify node_get still returns identical not_found for foreign/missing.
    db.write(|tx| {
        retract_edge(
            tx,
            RetractEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                edge_id: e_ab.id.clone(),
                retractor: PrincipalId::new("builder-1").unwrap(),
                retractor_kind: AssertedByKind::Agent,
                valid_to: None,
                generic: true,
            },
        )
    })
    .expect("retract e_ab");

    let missing_node_err = db
        .read_mut(|c| node_get(&mut SqliteGraph::new(c), DEFAULT_ORG, Some("no-such"), None, None, &outsider))
        .unwrap_err();
    assert!(matches!(missing_node_err, UaError::NotFound(_)));
}

#[test]
fn node_ensure_idempotency_n_to_1_cardinality_and_traversal_bounds() {
    let db = open_graph_db();

    // 1. graph_node_ensure is idempotent and touches nothing on second call.
    let (first, created1) = db
        .write(|tx| {
            graph_node_ensure(
                tx,
                EnsureNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    kind: NodeKind::Task,
                    external_id: "idem-1".into(),
                    display_label: Some("original".into()),
                    visibility: Visibility::Org,
                    team_id: None,
                    owner_type: None,
                    owner_id: None,
                    provenance: prov_agent("builder-1"),
                    meta_json: None,
                    max_nodes_per_org: 0,
                },
            )
        })
        .unwrap();
    assert!(created1);
    let (second, created2) = db
        .write(|tx| {
            graph_node_ensure(
                tx,
                EnsureNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    kind: NodeKind::Task,
                    external_id: "idem-1".into(),
                    display_label: Some("mutated".into()),
                    visibility: Visibility::Private,
                    team_id: None,
                    owner_type: Some(OwnerType::Agent),
                    owner_id: Some("attacker".into()),
                    provenance: prov_agent("attacker"),
                    meta_json: None,
                    max_nodes_per_org: 0,
                },
            )
        })
        .unwrap();
    assert!(!created2);
    assert_eq!(first.id, second.id);
    assert_eq!(second.display_label.as_deref(), Some("original"));
    assert_eq!(second.visibility, "org");

    // 2. N:1 single-out live uniqueness (`serves_goal`) + mirror-close carve-out.
    let g1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Goal, "goal-1");
    let g2 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Goal, "goal-2");
    let sg1 = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: first.id.clone(),
                    dst_id: g1.id.clone(),
                    kind: EdgeKind::ServesGoal,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap();
    // Second live serves_goal from same task conflicts on idx_graph_edges_single_out_live.
    let n1_conflict = db.write(|tx| {
        assert_edge(
            tx,
            AssertEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                src_id: first.id.clone(),
                dst_id: g2.id.clone(),
                kind: EdgeKind::ServesGoal,
                assertion_scope: String::new(),
                state: EdgeState::Active,
                weight: 1.0,
                provenance: prov_agent("builder-1"),
                valid_from: None,
                valid_to: None,
                meta_json: None,
                scope: VisibilityScope::org_only(),
                generic: false,
                max_edges_per_org: 0,
                max_live_edges_per_node: 0,
                cycle_bounds: CycleCheckPolicy::default(),
            },
        )
    });
    assert!(n1_conflict.is_err(), "N:1 serves_goal must refuse a second live outgoing edge");

    // Closing the first edge via valid_to permits asserting a new serves_goal edge.
    db.write(|tx| {
        retract_edge(
            tx,
            RetractEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                edge_id: sg1.id.clone(),
                retractor: PrincipalId::new("builder-1").unwrap(),
                retractor_kind: AssertedByKind::Agent,
                valid_to: None,
                generic: false,
            },
        )?;
        assert_edge(
            tx,
            AssertEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                src_id: first.id.clone(),
                dst_id: g2.id.clone(),
                kind: EdgeKind::ServesGoal,
                assertion_scope: String::new(),
                state: EdgeState::Active,
                weight: 1.0,
                provenance: prov_agent("builder-1"),
                valid_from: None,
                valid_to: None,
                meta_json: None,
                scope: VisibilityScope::org_only(),
                generic: false,
                max_edges_per_org: 0,
                max_live_edges_per_node: 0,
                cycle_bounds: CycleCheckPolicy::default(),
            },
        )
    })
    .expect("re-asserting after close must succeed");

    // 3. Neighbors cursor pagination + k_hop cycle immunity & hard cap refusals.
    let v1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::VaultNote, "v1");
    let v2 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::VaultNote, "v2");
    let v3 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::VaultNote, "v3");
    db.write(|tx| {
        for (s, d, w) in [(&v1, &v2, 3.0), (&v1, &v3, 2.0), (&v2, &v1, 1.0)] {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: s.id.clone(),
                    dst_id: d.id.clone(),
                    kind: EdgeKind::LinksTo,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: w,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
        }
        Ok(())
    })
    .unwrap();

    let scope = VisibilityScope::org_only();
    let page1 = db
        .read_mut(|c| {
            neighbors(
                &mut SqliteGraph::new(c),
                NeighborsRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: Some(v1.id.clone()),
                    kind: None,
                    external_id: None,
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![EdgeKind::LinksTo],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    limit: Some(1),
                    cursor: None,
                    deadline_ms: None,
                    scope: scope.clone(),
                },
            )
        })
        .unwrap();
    assert!(page1.truncated);
    assert_eq!(page1.neighbors.len(), 1);
    assert_eq!(page1.neighbors[0].node.id, v2.id);

    let page2 = db
        .read_mut(|c| {
            neighbors(
                &mut SqliteGraph::new(c),
                NeighborsRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: Some(v1.id.clone()),
                    kind: None,
                    external_id: None,
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![EdgeKind::LinksTo],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    limit: Some(1),
                    cursor: page1.next_cursor,
                    deadline_ms: None,
                    scope: scope.clone(),
                },
            )
        })
        .unwrap();
    assert!(!page2.truncated);
    assert_eq!(page2.neighbors.len(), 1);
    assert_eq!(page2.neighbors[0].node.id, v3.id);

    // Cycle immunity on v1 <-> v2 and hard-cap refusals (> 4 hops, > 6 depth).
    let cyc_khop = db
        .read_mut(|c| {
            k_hop(
                &mut SqliteGraph::new(c),
                KHopRequest {
                    org_id: DEFAULT_ORG.into(),
                    seed_ids: vec![v1.id.clone()],
                    max_hops: Some(4),
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![EdgeKind::LinksTo],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    max_nodes: None,
                    max_edges: None,
                    max_degree_per_node: None,
                    max_visited_edges: None,
                    skip_hubs_over: None,
                    deadline_ms: None,
                    scope: scope.clone(),
                },
            )
        })
        .unwrap();
    assert_eq!(cyc_khop.nodes.len(), 3);

    let bad_hops = db
        .read_mut(|c| {
            k_hop(
                &mut SqliteGraph::new(c),
                KHopRequest {
                    org_id: DEFAULT_ORG.into(),
                    seed_ids: vec![v1.id.clone()],
                    max_hops: Some(5),
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    max_nodes: None,
                    max_edges: None,
                    max_degree_per_node: None,
                    max_visited_edges: None,
                    skip_hubs_over: None,
                    deadline_ms: None,
                    scope: scope.clone(),
                },
            )
        })
        .unwrap_err();
    assert_eq!(bad_hops.code(), "invalid_argument");

    let bad_depth = db
        .read_mut(|c| {
            shortest_path(
                &mut SqliteGraph::new(c),
                ShortestPathRequest {
                    org_id: DEFAULT_ORG.into(),
                    from_id: v1.id.clone(),
                    to_id: v3.id.clone(),
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    max_depth: Some(7),
                    deadline_ms: None,
                    scope: scope.clone(),
                },
            )
        })
        .unwrap_err();
    assert_eq!(bad_depth.code(), "invalid_argument");
}

#[test]
fn org_quota_counters_are_trigger_maintained_transactional_and_enforced() {
    let db = open_graph_db();

    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_nodes(DEFAULT_ORG)).unwrap(), 0);
    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_edges(DEFAULT_ORG)).unwrap(), 0);

    // Insert 2 nodes in default org and 1 in org-b; verify O(1) counter table matches exact row counts.
    let n1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "q-1");
    let n2 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "q-2");
    let _b1 = ensure_org_node(&db, "org-b", NodeKind::MemoryNote, "qb-1");

    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_nodes(DEFAULT_ORG)).unwrap(), 2);
    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_nodes("org-b")).unwrap(), 1);

    // Rolled-back transaction must NOT leave stale increments in graph_org_counts.
    let rollback: Result<(), UaError> = db.write(|tx| {
        graph_node_ensure(
            tx,
            EnsureNodeRequest {
                org_id: DEFAULT_ORG.into(),
                kind: NodeKind::MemoryNote,
                external_id: "q-rolled-back".into(),
                display_label: None,
                visibility: Visibility::Org,
                team_id: None,
                owner_type: None,
                owner_id: None,
                provenance: prov_agent("builder-1"),
                meta_json: None,
                max_nodes_per_org: 0,
            },
        )?;
        Err(UaError::invalid("force rollback"))
    });
    assert!(rollback.is_err());
    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_nodes(DEFAULT_ORG)).unwrap(), 2);

    // Node quota enforced at max_nodes_per_org = 2.
    let node_quota_err = db
        .write(|tx| {
            graph_node_ensure(
                tx,
                EnsureNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    kind: NodeKind::MemoryNote,
                    external_id: "q-3".into(),
                    display_label: None,
                    visibility: Visibility::Org,
                    team_id: None,
                    owner_type: None,
                    owner_id: None,
                    provenance: prov_agent("builder-1"),
                    meta_json: None,
                    max_nodes_per_org: 2,
                },
            )
        })
        .unwrap_err();
    assert_eq!(node_quota_err.code(), "denied");
    assert_eq!(node_quota_err.reason_code(), Some("graph_quota_exceeded"));

    // Assert 1 edge -> counter becomes 1; second edge with max_edges_per_org = 1 is refused.
    db.write(|tx| {
        assert_edge(
            tx,
            AssertEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                src_id: n1.id.clone(),
                dst_id: n2.id.clone(),
                kind: EdgeKind::Extends,
                assertion_scope: String::new(),
                state: EdgeState::Active,
                weight: 1.0,
                provenance: prov_agent("builder-1"),
                valid_from: None,
                valid_to: None,
                meta_json: None,
                scope: VisibilityScope::org_only(),
                generic: true,
                max_edges_per_org: 2,
                max_live_edges_per_node: 0,
                cycle_bounds: CycleCheckPolicy::default(),
            },
        )
    })
    .unwrap();
    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_edges(DEFAULT_ORG)).unwrap(), 1);
    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_edges("org-b")).unwrap(), 0);

    let edge_quota_err = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n2.id.clone(),
                    dst_id: n1.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 1,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap_err();
    assert_eq!(edge_quota_err.code(), "denied");
    assert_eq!(edge_quota_err.reason_code(), Some("graph_quota_exceeded"));
}

/// Wrapper that delegates `GraphRepo` to `WriteTx` except `record_event` returns `None`,
/// exercising the no-ledger-seq `source_kind` fallback cleanly.
struct NoLedgerRepo<'a, 'b>(&'a mut ua_store::db::WriteTx<'b>);

impl GraphRead for NoLedgerRepo<'_, '_> {
    fn require_org_exists(&mut self, org_id: &str) -> ua_core::UaResult<()> {
        self.0.require_org_exists(org_id)
    }
    fn get_node_by_id(
        &mut self,
        org_id: &str,
        id: &str,
        scope: &VisibilityScope,
    ) -> ua_core::UaResult<Option<ua_store::graph::GraphNodeRow>> {
        self.0.get_node_by_id(org_id, id, scope)
    }
    fn get_node_by_external(
        &mut self,
        org_id: &str,
        kind: &str,
        external_id: &str,
        scope: &VisibilityScope,
    ) -> ua_core::UaResult<Option<ua_store::graph::GraphNodeRow>> {
        self.0.get_node_by_external(org_id, kind, external_id, scope)
    }
    fn get_nodes_by_ids(
        &mut self,
        org_id: &str,
        ids: &[String],
        scope: &VisibilityScope,
    ) -> ua_core::UaResult<Vec<ua_store::graph::GraphNodeRow>> {
        self.0.get_nodes_by_ids(org_id, ids, scope)
    }
    fn get_edge_by_id(
        &mut self,
        org_id: &str,
        id: &str,
    ) -> ua_core::UaResult<Option<ua_store::graph::GraphEdgeRow>> {
        self.0.get_edge_by_id(org_id, id)
    }
    fn get_edges_by_ids(
        &mut self,
        org_id: &str,
        ids: &[String],
    ) -> ua_core::UaResult<Vec<ua_store::graph::GraphEdgeRow>> {
        self.0.get_edges_by_ids(org_id, ids)
    }
    fn get_edges_by_rowids(
        &mut self,
        org_id: &str,
        rowids: &[i64],
    ) -> ua_core::UaResult<Vec<(i64, ua_store::graph::GraphEdgeRow)>> {
        self.0.get_edges_by_rowids(org_id, rowids)
    }
    fn count_org_nodes(&mut self, org_id: &str) -> ua_core::UaResult<u64> {
        self.0.count_org_nodes(org_id)
    }
    fn count_org_edges(&mut self, org_id: &str) -> ua_core::UaResult<u64> {
        self.0.count_org_edges(org_id)
    }
    fn count_node_live_edges_capped(
        &mut self,
        org_id: &str,
        node_id: &str,
        cap: usize,
    ) -> ua_core::UaResult<usize> {
        self.0.count_node_live_edges_capped(org_id, node_id, cap)
    }
    fn with_deadline<F, T>(&mut self, deadline: std::time::Instant, f: F) -> ua_core::UaResult<T>
    where
        Self: Sized,
        F: FnOnce(&mut Self) -> ua_core::UaResult<T>,
    {
        if std::time::Instant::now() >= deadline {
            return Err(UaError::invalid_code(ua_store::graph::DEADLINE_REASON_CODE, "deadline"));
        }
        f(self)
    }
    fn adjacent_edges(
        &mut self,
        query: &ua_store::graph::AdjacencyQuery,
    ) -> ua_core::UaResult<Vec<ua_store::graph::AdjacencyEntry>> {
        self.0.adjacent_edges(query)
    }
    fn compact_adjacent(
        &mut self,
        org_id: &str,
        node_id: &str,
        direction: EdgeDirection,
        filter: &ua_store::graph::EdgeFilter,
        scope: &VisibilityScope,
        limit: usize,
    ) -> ua_core::UaResult<Vec<ua_store::graph::CompactAdjEdge>> {
        self.0.compact_adjacent(org_id, node_id, direction, filter, scope, limit)
    }
    fn with_compact_adjacent<F, T>(
        &mut self,
        org_id: &str,
        directions: EdgeDirection,
        filter: &ua_store::graph::EdgeFilter,
        scope: &VisibilityScope,
        f: F,
    ) -> ua_core::UaResult<T>
    where
        F: FnOnce(
            &mut dyn FnMut(
                &str,
                EdgeDirection,
                usize,
                &mut Vec<ua_store::graph::CompactAdjEdge>,
            ) -> ua_core::UaResult<()>,
        ) -> ua_core::UaResult<T>,
    {
        self.0.with_compact_adjacent(org_id, directions, filter, scope, f)
    }
    fn bounded_acyclic_reach(
        &mut self,
        org_id: &str,
        src_id: &str,
        dst_id: &str,
        kind: &str,
        max_nodes: usize,
        max_edges: usize,
        deadline: std::time::Instant,
    ) -> ua_core::UaResult<ua_store::graph::AcyclicReachOutcome> {
        self.0.bounded_acyclic_reach(org_id, src_id, dst_id, kind, max_nodes, max_edges, deadline)
    }
    fn eligible_degree(
        &mut self,
        org_id: &str,
        node_id: &str,
        direction: EdgeDirection,
        filter: &ua_store::graph::EdgeFilter,
        scope: &VisibilityScope,
        cap_plus_one: usize,
    ) -> ua_core::UaResult<usize> {
        self.0.eligible_degree(org_id, node_id, direction, filter, scope, cap_plus_one)
    }
    fn outgoing_live_targets_of_kind_into(
        &mut self,
        org_id: &str,
        src_id: &str,
        kind: &str,
        limit: usize,
        out: &mut Vec<String>,
    ) -> ua_core::UaResult<()> {
        self.0.outgoing_live_targets_of_kind_into(org_id, src_id, kind, limit, out)
    }
    fn exact_ppr_slice(
        &mut self,
        org_id: &str,
        filter: &ua_store::graph::EdgeFilter,
        scope: &VisibilityScope,
        max_nodes: usize,
        max_edges: usize,
    ) -> ua_core::UaResult<Option<ua_store::graph::ExactPprSlice>> {
        self.0.exact_ppr_slice(org_id, filter, scope, max_nodes, max_edges)
    }
}

impl GraphRepo for NoLedgerRepo<'_, '_> {
    fn find_node_by_id_internal(
        &mut self,
        org_id: &str,
        id: &str,
    ) -> ua_core::UaResult<Option<ua_store::graph::GraphNodeRow>> {
        self.0.find_node_by_id_internal(org_id, id)
    }
    fn find_node_by_external_internal(
        &mut self,
        org_id: &str,
        kind: &str,
        external_id: &str,
    ) -> ua_core::UaResult<Option<ua_store::graph::GraphNodeRow>> {
        self.0.find_node_by_external_internal(org_id, kind, external_id)
    }
    fn ensure_node(
        &mut self,
        node: &NewGraphNode,
    ) -> ua_core::UaResult<(ua_store::graph::GraphNodeRow, bool)> {
        self.0.ensure_node(node)
    }
    fn update_node_mutable(
        &mut self,
        org_id: &str,
        id: &str,
        patch: &GraphNodePatch,
    ) -> ua_core::UaResult<Option<ua_store::graph::GraphNodeRow>> {
        self.0.update_node_mutable(org_id, id, patch)
    }
    fn insert_edge(&mut self, edge: &NewGraphEdge) -> ua_core::UaResult<ua_store::graph::GraphEdgeRow> {
        self.0.insert_edge(edge)
    }
    fn update_edge_weight(
        &mut self,
        org_id: &str,
        edge_id: &str,
        weight: f64,
    ) -> ua_core::UaResult<Option<ua_store::graph::GraphEdgeRow>> {
        self.0.update_edge_weight(org_id, edge_id, weight)
    }
    fn insert_nodes_batch(&mut self, nodes: &[NewGraphNode]) -> ua_core::UaResult<usize> {
        self.0.insert_nodes_batch(nodes)
    }
    fn insert_edges_batch(&mut self, edges: &[NewGraphEdge]) -> ua_core::UaResult<usize> {
        self.0.insert_edges_batch(edges)
    }
    fn close_edge(
        &mut self,
        org_id: &str,
        edge_id: &str,
        valid_to: &str,
    ) -> ua_core::UaResult<Option<ua_store::graph::GraphEdgeRow>> {
        self.0.close_edge(org_id, edge_id, valid_to)
    }
    fn record_event(
        &mut self,
        _channel: &str,
        _payload: serde_json::Value,
        _originator: &str,
    ) -> ua_core::UaResult<Option<i64>> {
        Ok(None)
    }
}

#[test]
fn generic_assertion_scope_refused_per_node_live_cap_and_source_kind_fallback() {
    let db = open_graph_db();
    let n1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "s1");
    let n2 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "s2");
    let n3 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "s3");
    let n4 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "s4");

    // 1. Generic assert with non-empty assertion_scope is refused (`reserved_assertion_scope`).
    let scope_err = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n1.id.clone(),
                    dst_id: n2.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: "note:42".into(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap_err();
    assert_eq!(scope_err.code(), "denied");
    assert_eq!(scope_err.reason_code(), Some("reserved_assertion_scope"));

    // Domain-internal assert (generic = false) MAY use `note:` scopes.
    let scoped = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n1.id.clone(),
                    dst_id: n2.id.clone(),
                    kind: EdgeKind::Evidence,
                    assertion_scope: "note:42".into(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap();
    assert_eq!(scoped.assertion_scope, "note:42");

    // 2. Per-node live-edge cap counts out + in live edges on both endpoints and releases on retract.
    // n1 currently has 1 live outgoing edge (n1 -> n2). Add 1 incoming (n3 -> n1) with cap = 2 -> succeeds.
    let e_in = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n3.id.clone(),
                    dst_id: n1.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 2,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap();

    // Now n1 has 2 live incident edges (1 out + 1 in); a 3rd edge touching n1 (as src or dst) is refused.
    for (src, dst) in [(&n1.id, &n4.id), (&n4.id, &n1.id)] {
        let cap_err = db
            .write(|tx| {
                assert_edge(
                    tx,
                    AssertEdgeRequest {
                        org_id: DEFAULT_ORG.into(),
                        src_id: src.clone(),
                        dst_id: dst.clone(),
                        kind: EdgeKind::Extends,
                        assertion_scope: String::new(),
                        state: EdgeState::Active,
                        weight: 1.0,
                        provenance: prov_agent("builder-1"),
                        valid_from: None,
                        valid_to: None,
                        meta_json: None,
                        scope: VisibilityScope::org_only(),
                        generic: true,
                        max_edges_per_org: 0,
                        max_live_edges_per_node: 2,
                        cycle_bounds: CycleCheckPolicy::default(),
                    },
                )
            })
            .unwrap_err();
        assert_eq!(cap_err.code(), "denied");
        assert_eq!(cap_err.reason_code(), Some("node_edge_limit_exceeded"));
    }

    // Retracting e_in frees a live-edge slot on n1 so n1 -> n4 succeeds under cap = 2.
    db.write(|tx| {
        retract_edge(
            tx,
            RetractEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                edge_id: e_in.id.clone(),
                retractor: PrincipalId::new("builder-1").unwrap(),
                retractor_kind: AssertedByKind::Agent,
                valid_to: None,
                generic: true,
            },
        )?;
        assert_edge(
            tx,
            AssertEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                src_id: n1.id.clone(),
                dst_id: n4.id.clone(),
                kind: EdgeKind::Extends,
                assertion_scope: String::new(),
                state: EdgeState::Active,
                weight: 1.0,
                provenance: prov_agent("builder-1"),
                valid_from: None,
                valid_to: None,
                meta_json: None,
                scope: VisibilityScope::org_only(),
                generic: true,
                max_edges_per_org: 0,
                max_live_edges_per_node: 2,
                cycle_bounds: CycleCheckPolicy::default(),
            },
        )
    })
    .expect("retracting frees per-node live-edge capacity");

    // 3. No-ledger-seq fallback: when record_event returns None, SourceKind::Event falls back to `tool`.
    let (nl_node, nl_edge) = db
        .write(|tx| {
            let mut repo = NoLedgerRepo(tx);
            let (node, _) = graph_node_ensure(
                &mut repo,
                EnsureNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    kind: NodeKind::MemoryNote,
                    external_id: "no-ledger-node".into(),
                    display_label: None,
                    visibility: Visibility::Org,
                    team_id: None,
                    owner_type: None,
                    owner_id: None,
                    provenance: prov_agent("builder-1"),
                    meta_json: None,
                    max_nodes_per_org: 0,
                },
            )?;
            let edge = assert_edge(
                &mut repo,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: node.id.clone(),
                    dst_id: n2.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
            Ok((node, edge))
        })
        .unwrap();
    assert_eq!(nl_node.source_kind, "tool");
    assert_eq!(nl_node.source_ref, "tool:test");
    assert_eq!(nl_edge.source_kind, "tool");
    assert_eq!(nl_edge.source_ref, "tool:test");
}

#[test]
fn sql_deadline_enforcement_exact_ppr_scan_cap_skip_hubs_clamp_and_endpoint_node_kinds() {
    let db = open_graph_db();
    let n_a = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "dn-a");
    let n_b = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "dn-b");
    let t_a = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, "dt-a");

    // 1. Live SQLite progress_handler interrupts an already-expired deadline and cleans up cleanly.
    db.read_mut(|conn| {
        {
            let mut repo = SqliteGraph::new(conn);
            let past = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_millis(10))
                .unwrap_or_else(std::time::Instant::now);
            let err = repo
                .with_deadline(past, |r| r.get_node_by_id(DEFAULT_ORG, &n_a.id, &VisibilityScope::org_only()))
                .unwrap_err();
            assert!(ua_store::graph::is_deadline_error(&err));
        }

        // Verify progress_handler actually interrupts a heavy recursive SQL query mid-execution
        // and leaves the connection clean for subsequent reads.
        let soon = std::time::Instant::now() + std::time::Duration::from_millis(5);
        conn.progress_handler(1_000, Some(move || std::time::Instant::now() >= soon))?;
        let sql_res: rusqlite::Result<i64> = conn.query_row(
            "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < 100000000) \
             SELECT MAX(x) FROM cnt",
            [],
            |r| r.get(0),
        );
        conn.progress_handler(0, None::<fn() -> bool>)?;
        assert!(sql_res.is_err(), "progress_handler must interrupt long-running SQL");
        assert!(
            SqliteGraph::new(conn)
                .get_node_by_id(DEFAULT_ORG, &n_a.id, &VisibilityScope::org_only())?
                .is_some()
        );
        Ok(())
    })
    .unwrap();

    // 2. bounded_acyclic_reach respects SQL deadline and returns BoundExceeded("deadline").
    let past = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_millis(10))
        .unwrap_or_else(std::time::Instant::now);
    let reach = db
        .read_mut(|conn| {
            SqliteGraph::new(conn).bounded_acyclic_reach(
                DEFAULT_ORG,
                &n_a.id,
                &n_b.id,
                "depends_on",
                1_000,
                5_000,
                past,
            )
        })
        .unwrap();
    assert_eq!(reach, ua_store::graph::AcyclicReachOutcome::BoundExceeded("deadline"));

    // 3. exact_ppr_slice scan cap: seed 25 private edges (invisible to outsider) + 1 visible edge;
    //    with max_edges = 10 (scan_cap = 20), exact_ppr_slice stops scanning and returns Ok(None).
    let owner = VisibilityScope::for_principal("agent", "owner-scan", vec![]);
    let outsider = VisibilityScope::for_principal("agent", "outsider-scan", vec![]);
    db.write(|tx| {
        assert_edge(
            tx,
            AssertEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                src_id: n_a.id.clone(),
                dst_id: n_b.id.clone(),
                kind: EdgeKind::Extends,
                assertion_scope: String::new(),
                state: EdgeState::Active,
                weight: 1.0,
                provenance: prov_agent("owner-scan"),
                valid_from: None,
                valid_to: None,
                meta_json: None,
                scope: owner.clone(),
                generic: true,
                max_edges_per_org: 0,
                max_live_edges_per_node: 0,
                cycle_bounds: CycleCheckPolicy::default(),
            },
        )?;
        let mut priv_nodes = Vec::new();
        for i in 0..26 {
            let (pn, _) = graph_node_ensure(
                tx,
                EnsureNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    kind: NodeKind::MemoryNote,
                    external_id: format!("scan-priv-{i}"),
                    display_label: None,
                    visibility: Visibility::Private,
                    team_id: None,
                    owner_type: Some(OwnerType::Agent),
                    owner_id: Some("owner-scan".into()),
                    provenance: prov_agent("owner-scan"),
                    meta_json: None,
                    max_nodes_per_org: 0,
                },
            )?;
            priv_nodes.push(pn);
        }
        for w in priv_nodes.windows(2) {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: w[0].id.clone(),
                    dst_id: w[1].id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("owner-scan"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: owner.clone(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
        }
        Ok(())
    })
    .unwrap();

    let slice = db
        .read_mut(|conn| {
            let filter = ua_store::graph::EdgeFilter {
                as_of: ua_core::time::now(),
                edge_kinds: vec![],
                node_kinds: vec![],
                include_proposed: false,
            };
            SqliteGraph::new(conn).exact_ppr_slice(DEFAULT_ORG, &filter, &outsider, 5_000, 10)
        })
        .unwrap();
    assert!(slice.is_none(), "exact_ppr_slice must bail out once scanned edges exceed scan cap");

    // 4. skip_hubs_over = usize::MAX is clamped safely (never wraps to SQL LIMIT -1).
    let kh = db
        .read_mut(|conn| {
            k_hop(
                &mut SqliteGraph::new(conn),
                KHopRequest {
                    org_id: DEFAULT_ORG.into(),
                    seed_ids: vec![n_a.id.clone()],
                    max_hops: Some(2),
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    max_nodes: Some(50),
                    max_edges: Some(50),
                    max_degree_per_node: Some(50),
                    max_visited_edges: Some(500),
                    skip_hubs_over: Some(usize::MAX),
                    deadline_ms: Some(500),
                    scope: outsider.clone(),
                },
            )
        })
        .unwrap();
    assert_eq!(kh.nodes.len(), 2);

    let ppr = db
        .read_mut(|conn| {
            seed_expand(
                &mut SqliteGraph::new(conn),
                SeedExpandRequest {
                    org_id: DEFAULT_ORG.into(),
                    seeds: vec![SeedInput { node_id: n_a.id.clone(), weight: 1.0 }],
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    walk_direction: WalkDirection::Undirected,
                    damping: None,
                    max_iters: None,
                    eps: None,
                    max_results: Some(10),
                    skip_hubs_over: Some(usize::MAX),
                    deadline_ms: Some(500),
                    scope: outsider.clone(),
                },
            )
        })
        .unwrap();
    assert!(!ppr.results.is_empty());

    // 5. shortest_path checks node_kinds on both endpoints (including self-path and direct edge).
    db.write(|tx| {
        assert_edge(
            tx,
            AssertEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                src_id: n_a.id.clone(),
                dst_id: t_a.id.clone(),
                kind: EdgeKind::Evidence,
                assertion_scope: String::new(),
                state: EdgeState::Active,
                weight: 1.0,
                provenance: prov_agent("builder-1"),
                valid_from: None,
                valid_to: None,
                meta_json: None,
                scope: VisibilityScope::org_only(),
                generic: false,
                max_edges_per_org: 0,
                max_live_edges_per_node: 0,
                cycle_bounds: CycleCheckPolicy::default(),
            },
        )
    })
    .unwrap();

    // Direct edge n_a (memory_note) -> t_a (task): filtering node_kinds = [Task] must exclude n_a!
    let sp_endpoint_filtered = db
        .read_mut(|conn| {
            shortest_path(
                &mut SqliteGraph::new(conn),
                ShortestPathRequest {
                    org_id: DEFAULT_ORG.into(),
                    from_id: n_a.id.clone(),
                    to_id: t_a.id.clone(),
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![],
                    node_kinds: vec![NodeKind::Task],
                    as_of: None,
                    include_proposed: false,
                    max_depth: Some(4),
                    deadline_ms: Some(500),
                    scope: outsider.clone(),
                },
            )
        })
        .unwrap();
    assert!(!sp_endpoint_filtered.found, "shortest_path must check node_kinds on from_id");

    // Self-path on n_a (memory_note) with node_kinds = [Task] must also return found = false.
    let sp_self_filtered = db
        .read_mut(|conn| {
            shortest_path(
                &mut SqliteGraph::new(conn),
                ShortestPathRequest {
                    org_id: DEFAULT_ORG.into(),
                    from_id: n_a.id.clone(),
                    to_id: n_a.id.clone(),
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![],
                    node_kinds: vec![NodeKind::Task],
                    as_of: None,
                    include_proposed: false,
                    max_depth: Some(4),
                    deadline_ms: Some(500),
                    scope: outsider.clone(),
                },
            )
        })
        .unwrap();
    assert!(!sp_self_filtered.found, "shortest_path self-path must respect node_kinds");

    // 6. neighbors returns truncated = true when SQL hits its deadline.
    struct DeadlineHitRead<'a>(SqliteGraph<'a>);
    impl GraphRead for DeadlineHitRead<'_> {
        fn require_org_exists(&mut self, org_id: &str) -> ua_core::UaResult<()> {
            self.0.require_org_exists(org_id)
        }
        fn get_node_by_id(
            &mut self,
            org_id: &str,
            id: &str,
            scope: &VisibilityScope,
        ) -> ua_core::UaResult<Option<ua_store::graph::GraphNodeRow>> {
            self.0.get_node_by_id(org_id, id, scope)
        }
        fn get_node_by_external(
            &mut self,
            org_id: &str,
            kind: &str,
            external_id: &str,
            scope: &VisibilityScope,
        ) -> ua_core::UaResult<Option<ua_store::graph::GraphNodeRow>> {
            self.0.get_node_by_external(org_id, kind, external_id, scope)
        }
        fn get_nodes_by_ids(
            &mut self,
            org_id: &str,
            ids: &[String],
            scope: &VisibilityScope,
        ) -> ua_core::UaResult<Vec<ua_store::graph::GraphNodeRow>> {
            self.0.get_nodes_by_ids(org_id, ids, scope)
        }
        fn get_edge_by_id(
            &mut self,
            org_id: &str,
            id: &str,
        ) -> ua_core::UaResult<Option<ua_store::graph::GraphEdgeRow>> {
            self.0.get_edge_by_id(org_id, id)
        }
        fn get_edges_by_ids(
            &mut self,
            org_id: &str,
            ids: &[String],
        ) -> ua_core::UaResult<Vec<ua_store::graph::GraphEdgeRow>> {
            self.0.get_edges_by_ids(org_id, ids)
        }
        fn get_edges_by_rowids(
            &mut self,
            org_id: &str,
            rowids: &[i64],
        ) -> ua_core::UaResult<Vec<(i64, ua_store::graph::GraphEdgeRow)>> {
            self.0.get_edges_by_rowids(org_id, rowids)
        }
        fn count_org_nodes(&mut self, org_id: &str) -> ua_core::UaResult<u64> {
            self.0.count_org_nodes(org_id)
        }
        fn count_org_edges(&mut self, org_id: &str) -> ua_core::UaResult<u64> {
            self.0.count_org_edges(org_id)
        }
        fn count_node_live_edges_capped(
            &mut self,
            org_id: &str,
            node_id: &str,
            cap: usize,
        ) -> ua_core::UaResult<usize> {
            self.0.count_node_live_edges_capped(org_id, node_id, cap)
        }
        fn with_deadline<F, T>(&mut self, _deadline: std::time::Instant, _f: F) -> ua_core::UaResult<T>
        where
            Self: Sized,
            F: FnOnce(&mut Self) -> ua_core::UaResult<T>,
        {
            Err(UaError::invalid_code(ua_store::graph::DEADLINE_REASON_CODE, "simulated deadline"))
        }
        fn adjacent_edges(
            &mut self,
            query: &ua_store::graph::AdjacencyQuery,
        ) -> ua_core::UaResult<Vec<ua_store::graph::AdjacencyEntry>> {
            self.0.adjacent_edges(query)
        }
        fn compact_adjacent(
            &mut self,
            org_id: &str,
            node_id: &str,
            direction: EdgeDirection,
            filter: &ua_store::graph::EdgeFilter,
            scope: &VisibilityScope,
            limit: usize,
        ) -> ua_core::UaResult<Vec<ua_store::graph::CompactAdjEdge>> {
            self.0.compact_adjacent(org_id, node_id, direction, filter, scope, limit)
        }
        fn with_compact_adjacent<F, T>(
            &mut self,
            org_id: &str,
            directions: EdgeDirection,
            filter: &ua_store::graph::EdgeFilter,
            scope: &VisibilityScope,
            f: F,
        ) -> ua_core::UaResult<T>
        where
            F: FnOnce(
                &mut dyn FnMut(
                    &str,
                    EdgeDirection,
                    usize,
                    &mut Vec<ua_store::graph::CompactAdjEdge>,
                ) -> ua_core::UaResult<()>,
            ) -> ua_core::UaResult<T>,
        {
            self.0.with_compact_adjacent(org_id, directions, filter, scope, f)
        }
        fn bounded_acyclic_reach(
            &mut self,
            org_id: &str,
            src_id: &str,
            dst_id: &str,
            kind: &str,
            max_nodes: usize,
            max_edges: usize,
            deadline: std::time::Instant,
        ) -> ua_core::UaResult<ua_store::graph::AcyclicReachOutcome> {
            self.0.bounded_acyclic_reach(org_id, src_id, dst_id, kind, max_nodes, max_edges, deadline)
        }
        fn eligible_degree(
            &mut self,
            org_id: &str,
            node_id: &str,
            direction: EdgeDirection,
            filter: &ua_store::graph::EdgeFilter,
            scope: &VisibilityScope,
            cap_plus_one: usize,
        ) -> ua_core::UaResult<usize> {
            self.0.eligible_degree(org_id, node_id, direction, filter, scope, cap_plus_one)
        }
        fn outgoing_live_targets_of_kind_into(
            &mut self,
            org_id: &str,
            src_id: &str,
            kind: &str,
            limit: usize,
            out: &mut Vec<String>,
        ) -> ua_core::UaResult<()> {
            self.0.outgoing_live_targets_of_kind_into(org_id, src_id, kind, limit, out)
        }
        fn exact_ppr_slice(
            &mut self,
            org_id: &str,
            filter: &ua_store::graph::EdgeFilter,
            scope: &VisibilityScope,
            max_nodes: usize,
            max_edges: usize,
        ) -> ua_core::UaResult<Option<ua_store::graph::ExactPprSlice>> {
            self.0.exact_ppr_slice(org_id, filter, scope, max_nodes, max_edges)
        }
    }

    let nbr_deadline = db
        .read_mut(|conn| {
            let mut r = DeadlineHitRead(SqliteGraph::new(conn));
            neighbors(
                &mut r,
                NeighborsRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: Some(n_a.id.clone()),
                    kind: None,
                    external_id: None,
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    limit: Some(10),
                    cursor: None,
                    deadline_ms: Some(1),
                    scope: outsider.clone(),
                },
            )
        })
        .unwrap();
    assert!(nbr_deadline.truncated, "neighbors must return truncated = true on deadline");
    assert!(nbr_deadline.next_cursor.is_none());
}

#[test]
fn writer_deadline_slot_is_disarmed_after_cycle_check() {
    let db = open_graph_db();
    let t1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, "wd-1");
    let t2 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, "wd-2");
    let t3 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, "wd-3");

    // 1. Run a bounded cycle check on the writer connection with a tight 5 ms deadline
    //    (both the succeeding path and the refused-cycle error path).
    db.write(|tx| {
        assert_edge(
            tx,
            AssertEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                src_id: t1.id.clone(),
                dst_id: t2.id.clone(),
                kind: EdgeKind::DependsOn,
                assertion_scope: String::new(),
                state: EdgeState::Active,
                weight: 1.0,
                provenance: prov_agent("builder-1"),
                valid_from: None,
                valid_to: None,
                meta_json: None,
                scope: VisibilityScope::org_only(),
                generic: false,
                max_edges_per_org: 0,
                max_live_edges_per_node: 0,
                cycle_bounds: CycleCheckPolicy::all(CycleCheckBounds {
                    max_nodes: 1_000,
                    max_edges: 5_000,
                    deadline_ms: 5,
                }),
            },
        )
    })
    .expect("first acyclic depends_on write succeeds");

    let cyc_err = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: t2.id.clone(),
                    dst_id: t1.id.clone(),
                    kind: EdgeKind::DependsOn,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::all(CycleCheckBounds {
                        max_nodes: 1_000,
                        max_edges: 5_000,
                        deadline_ms: 5,
                    }),
                },
            )
        })
        .unwrap_err();
    assert_eq!(cyc_err.reason_code(), Some("cycle_detected"));

    // 2. Sleep strictly past the 5 ms deadline used by the cycle checks above.
    std::thread::sleep(std::time::Duration::from_millis(15));

    // 3. A subsequent ordinary write on the same writer executing well over the 2,000-opcode
    //    progress_handler cadence must succeed (fails with SQLITE_INTERRUPT if the writer
    //    deadline slot was left armed).
    let later = db
        .write(|tx| {
            let max_x: i64 = tx.query_row(
                "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 5000) \
                 SELECT MAX(x) FROM c",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(max_x, 5_000);
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: t2.id.clone(),
                    dst_id: t3.id.clone(),
                    kind: EdgeKind::DependsOn,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .expect("later ordinary write past previous cycle-check deadline must succeed");
    assert_eq!(later.dst_id, t3.id);
}

#[test]
fn principal_id_reserves_system_case_insensitively_and_on_deserialize() {
    for raw in ["system", "System", "SYSTEM", " system ", "\tsYsTeM\n"] {
        let err = PrincipalId::new(raw).expect_err("reserved system id must be rejected");
        assert_eq!(err.code(), "invalid_argument", "{raw:?}: {err:?}");
        assert_eq!(err.reason_code(), Some("reserved_principal_id"), "{raw:?}: {err:?}");

        let json_str = serde_json::to_string(raw).unwrap();
        let deser_err = serde_json::from_str::<PrincipalId>(&json_str)
            .expect_err("deserializing reserved system principal must fail");
        assert!(deser_err.to_string().contains("reserved"), "{raw:?}: {deser_err}");
    }

    // Non-system IDs containing "system" as a substring remain valid.
    let ok = PrincipalId::new("system-worker-1").expect("non-exact system prefix allowed");
    assert!(!ok.is_system());
    assert_eq!(ok.as_str(), "system-worker-1");

    // Only PrincipalId::system() constructs the reserved system principal.
    let sys = PrincipalId::system();
    assert!(sys.is_system());
    assert_eq!(sys.as_str(), "system");

    // Provenance::validate still enforces the (system <-> System) pairing.
    let bad_prov = Provenance {
        asserted_by: PrincipalId::system(),
        asserted_by_kind: AssertedByKind::Agent,
        source_kind: SourceKind::Tool,
        source_ref: "tool:x".into(),
    };
    assert_eq!(bad_prov.validate().unwrap_err().code(), "invalid_argument");

    let good_prov = Provenance {
        asserted_by: PrincipalId::system(),
        asserted_by_kind: AssertedByKind::System,
        source_kind: SourceKind::Mirror,
        source_ref: "mirror:x".into(),
    };
    good_prov.validate().expect("system principal with System kind is valid");
}

#[test]
fn per_kind_cycle_check_policy_enforces_independent_caps_per_edge_kind() {
    // Policy coverage matches EdgeKind::is_acyclic() across every closed edge kind.
    let default_policy = CycleCheckPolicy::default();
    for kind in EdgeKind::ALL {
        assert_eq!(
            default_policy.bounds_for(kind).is_some(),
            kind.is_acyclic(),
            "CycleCheckPolicy::bounds_for({kind}) must match EdgeKind::is_acyclic()"
        );
    }

    let db = open_graph_db();
    // Build a 6-node chain (t0 -> t1 -> t2 -> t3 -> t4 -> t5) for both depends_on and subtask_of.
    let tasks: Vec<_> =
        (0..=5).map(|i| ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, &format!("pk-t{i}"))).collect();
    let chain_src = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, "pk-src");

    for kind in [EdgeKind::DependsOn, EdgeKind::SubtaskOf] {
        for i in 0..5 {
            db.write(|tx| {
                assert_edge(
                    tx,
                    AssertEdgeRequest {
                        org_id: DEFAULT_ORG.into(),
                        src_id: tasks[i].id.clone(),
                        dst_id: tasks[i + 1].id.clone(),
                        kind,
                        assertion_scope: String::new(),
                        state: EdgeState::Active,
                        weight: 1.0,
                        provenance: prov_agent("builder-1"),
                        valid_from: None,
                        valid_to: None,
                        meta_json: None,
                        scope: VisibilityScope::org_only(),
                        generic: false,
                        max_edges_per_org: 0,
                        max_live_edges_per_node: 0,
                        cycle_bounds: default_policy,
                    },
                )
            })
            .expect("seed chain edge");
        }
    }

    // One policy: generous cap for `depends_on` (20 nodes), tight cap for `subtask_of` (3 nodes).
    let policy = CycleCheckPolicy::default()
        .with_kind(EdgeKind::DependsOn, CycleCheckBounds { max_nodes: 20, max_edges: 100, deadline_ms: 50 })
        .with_kind(EdgeKind::SubtaskOf, CycleCheckBounds { max_nodes: 3, max_edges: 100, deadline_ms: 50 });

    // `subtask_of` hits its 3-node cap on the 6-node chain -> cycle_check_bound_exceeded.
    let sub_err = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: chain_src.id.clone(),
                    dst_id: tasks[0].id.clone(),
                    kind: EdgeKind::SubtaskOf,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: policy,
                },
            )
        })
        .unwrap_err();
    assert_eq!(sub_err.code(), "invalid_argument");
    assert_eq!(sub_err.reason_code(), Some("cycle_check_bound_exceeded"));

    // Same policy: `depends_on` passes because its per-kind cap is 20 nodes.
    let dep = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: chain_src.id.clone(),
                    dst_id: tasks[0].id.clone(),
                    kind: EdgeKind::DependsOn,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: policy,
                },
            )
        })
        .expect("depends_on must use its own higher per-kind cap");
    assert_eq!(dep.kind, "depends_on");
}

#[test]
fn graph_org_counts_no_delete_trigger_preserves_quota_accounting() {
    let db = open_graph_db();
    let n1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, "nd-1");
    let n2 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Task, "nd-2");
    db.write(|tx| {
        assert_edge(
            tx,
            AssertEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                src_id: n1.id.clone(),
                dst_id: n2.id.clone(),
                kind: EdgeKind::DependsOn,
                assertion_scope: String::new(),
                state: EdgeState::Active,
                weight: 1.0,
                provenance: prov_agent("builder-1"),
                valid_from: None,
                valid_to: None,
                meta_json: None,
                scope: VisibilityScope::org_only(),
                generic: false,
                max_edges_per_org: 0,
                max_live_edges_per_node: 0,
                cycle_bounds: CycleCheckPolicy::default(),
            },
        )
    })
    .unwrap();

    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_nodes(DEFAULT_ORG)).unwrap(), 2);
    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_edges(DEFAULT_ORG)).unwrap(), 1);

    let del_err = db
        .write(|tx| {
            tx.execute("DELETE FROM graph_org_counts WHERE org_id = ?1", [DEFAULT_ORG])?;
            Ok(())
        })
        .expect_err("DELETE on graph_org_counts must abort");
    assert!(
        del_err.to_string().contains("graph organization counters cannot be deleted"),
        "unexpected error: {del_err}"
    );

    // Counters remain intact after the aborted DELETE.
    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_nodes(DEFAULT_ORG)).unwrap(), 2);
    assert_eq!(db.read_mut(|c| SqliteGraph::new(c).count_org_edges(DEFAULT_ORG)).unwrap(), 1);
}

#[test]
fn graph_node_update_records_same_tx_event_rolls_back_atomically_and_keeps_identity_immutable() {
    let db = open_graph_db();
    let orig = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "upd-1");

    // 1. No-op update writes neither row change nor ledger event.
    let (same, changed) = db
        .write(|tx| {
            graph_node_update(
                tx,
                UpdateNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: orig.id.clone(),
                    actor: PrincipalId::new("builder-1").unwrap(),
                    actor_kind: AssertedByKind::Agent,
                    visibility: None,
                    team_id: FieldPatch::Unchanged,
                    owner_type: FieldPatch::Unchanged,
                    owner_id: FieldPatch::Unchanged,
                    display_label: FieldPatch::Unchanged,
                    meta_json: None,
                    archived_at: FieldPatch::Unchanged,
                },
            )
        })
        .unwrap();
    assert!(!changed);
    assert_eq!(same, orig);
    let ev_count: i64 = db
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM event_log WHERE channel = ?1", [EVENT_NODE_UPDATED], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(ev_count, 0);

    // 2. Rolled-back transaction reverts BOTH the graph_nodes update AND event_log row.
    let rb: Result<(), UaError> = db.write(|tx| {
        let (_, ch) = graph_node_update(
            tx,
            UpdateNodeRequest {
                org_id: DEFAULT_ORG.into(),
                node_id: orig.id.clone(),
                actor: PrincipalId::new("builder-1").unwrap(),
                actor_kind: AssertedByKind::Agent,
                visibility: Some(Visibility::Private),
                team_id: FieldPatch::Unchanged,
                owner_type: FieldPatch::Set(OwnerType::Agent),
                owner_id: FieldPatch::Set("builder-1".into()),
                display_label: FieldPatch::Set("rolled-back-label".into()),
                meta_json: Some(json!({"rb": true})),
                archived_at: FieldPatch::Unchanged,
            },
        )?;
        assert!(ch);
        Err(UaError::invalid("force rollback"))
    });
    assert!(rb.is_err());
    let after_rb = db
        .read_mut(|c| SqliteGraph::new(c).get_node_by_id(DEFAULT_ORG, &orig.id, &VisibilityScope::org_only()))
        .unwrap()
        .expect("node still org-visible after rollback");
    assert_eq!(after_rb.visibility, "org");
    assert_eq!(after_rb.display_label, orig.display_label);
    let ev_count_after_rb: i64 = db
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM event_log WHERE channel = ?1", [EVENT_NODE_UPDATED], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(ev_count_after_rb, 0, "rolled-back node update must not leave a ledger event");

    // 3. Committed update updates mutable fields, records attributed event with
    //    changed_fields + safe old/new values (omitting display_label / meta_json
    //    content from event payload), and leaves identity/provenance untouched.
    let archive_ts = ua_core::time::now();
    let (updated, changed) = db
        .write(|tx| {
            graph_node_update(
                tx,
                UpdateNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: orig.id.clone(),
                    actor: PrincipalId::new("operator-1").unwrap(),
                    actor_kind: AssertedByKind::Person,
                    visibility: Some(Visibility::Private),
                    team_id: FieldPatch::Clear,
                    owner_type: FieldPatch::Set(OwnerType::Human),
                    owner_id: FieldPatch::Set("operator-1".into()),
                    display_label: FieldPatch::Set("sensitive-title-text".into()),
                    meta_json: Some(json!({"secret_note": "do-not-log-in-event"})),
                    archived_at: FieldPatch::Set(archive_ts.clone()),
                },
            )
        })
        .unwrap();
    assert!(changed);
    assert_eq!(updated.visibility, "private");
    assert_eq!(updated.owner_type.as_deref(), Some("human"));
    assert_eq!(updated.owner_id.as_deref(), Some("operator-1"));
    assert_eq!(updated.display_label.as_deref(), Some("sensitive-title-text"));
    assert_eq!(updated.meta_json, r#"{"secret_note":"do-not-log-in-event"}"#);
    assert_eq!(updated.archived_at.as_deref(), Some(archive_ts.as_str()));
    // Identity & provenance columns remain identical.
    assert_eq!(updated.id, orig.id);
    assert_eq!(updated.org_id, orig.org_id);
    assert_eq!(updated.kind, orig.kind);
    assert_eq!(updated.external_id, orig.external_id);
    assert_eq!(updated.asserted_by, orig.asserted_by);
    assert_eq!(updated.asserted_by_kind, orig.asserted_by_kind);
    assert_eq!(updated.source_kind, orig.source_kind);
    assert_eq!(updated.source_ref, orig.source_ref);
    assert_eq!(updated.created_at, orig.created_at);

    let (originator, payload_str): (String, String) = db
        .read(|c| {
            Ok(c.query_row(
                "SELECT originator, payload FROM event_log WHERE channel = ?1 ORDER BY seq DESC LIMIT 1",
                [EVENT_NODE_UPDATED],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(originator, "operator-1");
    assert!(
        !payload_str.contains("sensitive-title-text"),
        "event must not leak display_label: {payload_str}"
    );
    assert!(!payload_str.contains("do-not-log-in-event"), "event must not leak meta_json: {payload_str}");
    let ev: serde_json::Value = serde_json::from_str(&payload_str).unwrap();
    assert_eq!(ev["org_id"], DEFAULT_ORG);
    assert_eq!(ev["node_id"], orig.id);
    assert_eq!(ev["kind"], "memory_note");
    assert_eq!(ev["updated_by"], "operator-1");
    assert_eq!(ev["updated_by_kind"], "person");
    assert_eq!(ev["old_visibility"], "org");
    assert_eq!(ev["new_visibility"], "private");
    assert_eq!(ev["old_archived_at"], serde_json::Value::Null);
    assert_eq!(ev["new_archived_at"], archive_ts);
    let fields: Vec<&str> =
        ev["changed_fields"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
    for expected in ["visibility", "owner_type", "owner_id", "display_label", "meta_json", "archived_at"] {
        assert!(fields.contains(&expected), "missing {expected} in {fields:?}");
    }

    // 4. Schema immutability triggers still refuse modifying identity/provenance columns.
    for sql in [
        "UPDATE graph_nodes SET kind = 'task' WHERE id = ?1",
        "UPDATE graph_nodes SET external_id = 'mutated' WHERE id = ?1",
        "UPDATE graph_nodes SET asserted_by = 'someone-else' WHERE id = ?1",
        "UPDATE graph_nodes SET created_at = '2020-01-01T00:00:00+00:00' WHERE id = ?1",
    ] {
        assert!(
            db.write(|tx| {
                tx.execute(sql, [&orig.id])?;
                Ok(())
            })
            .is_err(),
            "immutability trigger must still reject {sql}"
        );
    }

    // 5. Validation guards: team without team_id, private without owner, future archived_at.
    let bad_team = db
        .write(|tx| {
            graph_node_update(
                tx,
                UpdateNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: orig.id.clone(),
                    actor: PrincipalId::new("operator-1").unwrap(),
                    actor_kind: AssertedByKind::Person,
                    visibility: Some(Visibility::Team),
                    team_id: FieldPatch::Clear,
                    owner_type: FieldPatch::Unchanged,
                    owner_id: FieldPatch::Unchanged,
                    display_label: FieldPatch::Unchanged,
                    meta_json: None,
                    archived_at: FieldPatch::Unchanged,
                },
            )
        })
        .unwrap_err();
    assert_eq!(bad_team.code(), "invalid_argument");

    let future_arch = db
        .write(|tx| {
            graph_node_update(
                tx,
                UpdateNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: orig.id.clone(),
                    actor: PrincipalId::new("operator-1").unwrap(),
                    actor_kind: AssertedByKind::Person,
                    visibility: None,
                    team_id: FieldPatch::Unchanged,
                    owner_type: FieldPatch::Unchanged,
                    owner_id: FieldPatch::Unchanged,
                    display_label: FieldPatch::Unchanged,
                    meta_json: None,
                    archived_at: FieldPatch::Set("2099-01-01T00:00:00+00:00".into()),
                },
            )
        })
        .unwrap_err();
    assert_eq!(future_arch.code(), "invalid_argument");
    assert_eq!(future_arch.reason_code(), Some("future_archived_at"));

    // 6. Length and control-character limits on team_id and owner_id (both update and ensure).
    let long_id = "x".repeat(129);
    for (bad_team, bad_owner) in [
        (FieldPatch::Set(long_id.clone()), FieldPatch::Unchanged),
        (FieldPatch::Set("bad\nteam".into()), FieldPatch::Unchanged),
        (FieldPatch::Set("bad\x00team".into()), FieldPatch::Unchanged),
        (FieldPatch::Unchanged, FieldPatch::Set(long_id.clone())),
        (FieldPatch::Unchanged, FieldPatch::Set("bad\x1bowner".into())),
    ] {
        let err = db
            .write(|tx| {
                graph_node_update(
                    tx,
                    UpdateNodeRequest {
                        org_id: DEFAULT_ORG.into(),
                        node_id: orig.id.clone(),
                        actor: PrincipalId::new("operator-1").unwrap(),
                        actor_kind: AssertedByKind::Person,
                        visibility: None,
                        team_id: bad_team,
                        owner_type: FieldPatch::Unchanged,
                        owner_id: bad_owner,
                        display_label: FieldPatch::Unchanged,
                        meta_json: None,
                        archived_at: FieldPatch::Unchanged,
                    },
                )
            })
            .unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
    }
    let bad_ensure_team = db
        .write(|tx| {
            graph_node_ensure(
                tx,
                EnsureNodeRequest {
                    org_id: DEFAULT_ORG.into(),
                    kind: NodeKind::MemoryNote,
                    external_id: "bad-tid-ensure".into(),
                    display_label: None,
                    visibility: Visibility::Team,
                    team_id: Some(long_id),
                    owner_type: None,
                    owner_id: None,
                    provenance: prov_agent("builder-1"),
                    meta_json: None,
                    max_nodes_per_org: 0,
                },
            )
        })
        .unwrap_err();
    assert_eq!(bad_ensure_team.code(), "invalid_argument");
}

#[test]
fn graph_node_update_non_default_org_redacts_ledger_and_enforces_system_actor_and_isolation() {
    let db = open_graph_db();
    let default_node = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "def-iso");
    let org_b_node = ensure_org_node(&db, "org-b", NodeKind::MemoryNote, "orgb-secret-ext");

    // 1. Cross-org isolation: updating default_node as org-b returns not_found.
    let cross_err = db
        .write(|tx| {
            graph_node_update(
                tx,
                UpdateNodeRequest {
                    org_id: "org-b".into(),
                    node_id: default_node.id.clone(),
                    actor: PrincipalId::system(),
                    actor_kind: AssertedByKind::System,
                    visibility: None,
                    team_id: FieldPatch::Unchanged,
                    owner_type: FieldPatch::Unchanged,
                    owner_id: FieldPatch::Unchanged,
                    display_label: FieldPatch::Set("nope".into()),
                    meta_json: None,
                    archived_at: FieldPatch::Unchanged,
                },
            )
        })
        .unwrap_err();
    assert_eq!(cross_err.code(), "not_found");

    // 2. Pre-#2790 fence: non-system actor in non-default org is refused.
    let non_sys_err = db
        .write(|tx| {
            graph_node_update(
                tx,
                UpdateNodeRequest {
                    org_id: "org-b".into(),
                    node_id: org_b_node.id.clone(),
                    actor: PrincipalId::new("builder-b").unwrap(),
                    actor_kind: AssertedByKind::Agent,
                    visibility: None,
                    team_id: FieldPatch::Unchanged,
                    owner_type: FieldPatch::Unchanged,
                    owner_id: FieldPatch::Unchanged,
                    display_label: FieldPatch::Set("nope".into()),
                    meta_json: None,
                    archived_at: FieldPatch::Unchanged,
                },
            )
        })
        .unwrap_err();
    assert_eq!(non_sys_err.code(), "denied");
    assert_eq!(non_sys_err.reason_code(), Some("principal_id_required"));

    // 3. System update in org-b succeeds and redacts ORG-EVENT-DEFAULT fields.
    let ts = ua_core::time::now();
    let (_, changed) = db
        .write(|tx| {
            graph_node_update(
                tx,
                UpdateNodeRequest {
                    org_id: "org-b".into(),
                    node_id: org_b_node.id.clone(),
                    actor: PrincipalId::system(),
                    actor_kind: AssertedByKind::System,
                    visibility: Some(Visibility::Team),
                    team_id: FieldPatch::Set("secret-team-99".into()),
                    owner_type: FieldPatch::Set(OwnerType::Agent),
                    owner_id: FieldPatch::Set("secret-owner-99".into()),
                    display_label: FieldPatch::Set("secret-orgb-label".into()),
                    meta_json: Some(json!({"confidential": "secret-meta-99"})),
                    archived_at: FieldPatch::Set(ts),
                },
            )
        })
        .unwrap();
    assert!(changed);

    let (originator, payload_str): (String, String) = db
        .read(|c| {
            Ok(c.query_row(
                "SELECT originator, payload FROM event_log WHERE channel = ?1 ORDER BY seq DESC LIMIT 1",
                [EVENT_NODE_UPDATED],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(originator, "system");
    for secret in
        ["secret-orgb-label", "secret-meta-99", "secret-team-99", "secret-owner-99", "orgb-secret-ext"]
    {
        assert!(!payload_str.contains(secret), "non-default event leaked {secret}: {payload_str}");
    }
    let ev: serde_json::Value = serde_json::from_str(&payload_str).unwrap();
    assert_eq!(ev["org_id"], "org-b");
    assert_eq!(ev["node_id"], org_b_node.id);
    assert_eq!(ev["kind"], "memory_note");
    assert_eq!(ev["old_visibility"], "org");
    assert_eq!(ev["new_visibility"], "team");
    assert_eq!(ev["old_archived"], false);
    assert_eq!(ev["new_archived"], true);
    assert!(ev.get("updated_by").is_none());
    assert!(ev.get("display_label").is_none());
    assert!(ev.get("meta_json").is_none());
}

#[test]
fn graph_node_update_visibility_and_archive_changes_reflect_in_traversals() {
    let db = open_graph_db();
    let seed = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "vis-seed");
    let target = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "vis-target");

    db.write(|tx| {
        assert_edge(
            tx,
            AssertEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                src_id: seed.id.clone(),
                dst_id: target.id.clone(),
                kind: EdgeKind::Extends,
                assertion_scope: String::new(),
                state: EdgeState::Active,
                weight: 1.0,
                provenance: prov_agent("builder-1"),
                valid_from: None,
                valid_to: None,
                meta_json: None,
                scope: VisibilityScope::org_only(),
                generic: true,
                max_edges_per_org: 0,
                max_live_edges_per_node: 0,
                cycle_bounds: CycleCheckPolicy::default(),
            },
        )
    })
    .unwrap();

    let outsider = VisibilityScope::for_principal("agent", "outsider", vec![]);
    let owner = VisibilityScope::for_principal("agent", "owner-1", vec![]);
    let teammate = VisibilityScope::for_principal("agent", "teammate-1", vec!["team-alpha".into()]);

    let can_traverse = |scope: &VisibilityScope| -> bool {
        let got_node = db
            .read_mut(|c| {
                node_get(&mut SqliteGraph::new(c), DEFAULT_ORG, Some(&target.id), None, None, scope)
            })
            .is_ok();
        let nbrs = db
            .read_mut(|c| {
                neighbors(
                    &mut SqliteGraph::new(c),
                    NeighborsRequest {
                        org_id: DEFAULT_ORG.into(),
                        node_id: Some(seed.id.clone()),
                        kind: None,
                        external_id: None,
                        direction: EdgeDirection::Out,
                        edge_kinds: vec![],
                        node_kinds: vec![],
                        as_of: None,
                        include_proposed: false,
                        limit: Some(10),
                        cursor: None,
                        deadline_ms: None,
                        scope: scope.clone(),
                    },
                )
            })
            .unwrap();
        let kh = db
            .read_mut(|c| {
                k_hop(
                    &mut SqliteGraph::new(c),
                    KHopRequest {
                        org_id: DEFAULT_ORG.into(),
                        seed_ids: vec![seed.id.clone()],
                        max_hops: Some(1),
                        direction: EdgeDirection::Out,
                        edge_kinds: vec![],
                        node_kinds: vec![],
                        as_of: None,
                        include_proposed: false,
                        max_nodes: None,
                        max_edges: None,
                        max_degree_per_node: None,
                        max_visited_edges: None,
                        skip_hubs_over: None,
                        deadline_ms: None,
                        scope: scope.clone(),
                    },
                )
            })
            .unwrap();
        let has_nbr = nbrs.neighbors.iter().any(|n| n.node.id == target.id);
        let has_kh = kh.nodes.iter().any(|n| n.id == target.id);
        assert_eq!(got_node, has_nbr, "node_get and neighbors must agree");
        assert_eq!(got_node, has_kh, "node_get and k_hop must agree");
        got_node
    };

    // Initially `org`: visible to everyone.
    assert!(can_traverse(&outsider));
    assert!(can_traverse(&owner));

    // Flip `org` -> `private` (owned by `owner-1`): outsider loses visibility; owner retains it.
    db.write(|tx| {
        graph_node_update(
            tx,
            UpdateNodeRequest {
                org_id: DEFAULT_ORG.into(),
                node_id: target.id.clone(),
                actor: PrincipalId::new("owner-1").unwrap(),
                actor_kind: AssertedByKind::Agent,
                visibility: Some(Visibility::Private),
                team_id: FieldPatch::Clear,
                owner_type: FieldPatch::Set(OwnerType::Agent),
                owner_id: FieldPatch::Set("owner-1".into()),
                display_label: FieldPatch::Unchanged,
                meta_json: None,
                archived_at: FieldPatch::Unchanged,
            },
        )
    })
    .unwrap();
    assert!(!can_traverse(&outsider), "outsider must not see private node");
    assert!(can_traverse(&owner), "owner must still see private node");

    // Flip `private` -> `team` (`team-alpha`): teammate sees it; outsider & non-member owner do not.
    db.write(|tx| {
        graph_node_update(
            tx,
            UpdateNodeRequest {
                org_id: DEFAULT_ORG.into(),
                node_id: target.id.clone(),
                actor: PrincipalId::new("owner-1").unwrap(),
                actor_kind: AssertedByKind::Agent,
                visibility: Some(Visibility::Team),
                team_id: FieldPatch::Set("team-alpha".into()),
                owner_type: FieldPatch::Clear,
                owner_id: FieldPatch::Clear,
                display_label: FieldPatch::Unchanged,
                meta_json: None,
                archived_at: FieldPatch::Unchanged,
            },
        )
    })
    .unwrap();
    assert!(!can_traverse(&outsider));
    assert!(!can_traverse(&owner));
    assert!(can_traverse(&teammate));

    // Archive node: hidden from everyone including teammate.
    db.write(|tx| {
        graph_node_update(
            tx,
            UpdateNodeRequest {
                org_id: DEFAULT_ORG.into(),
                node_id: target.id.clone(),
                actor: PrincipalId::new("owner-1").unwrap(),
                actor_kind: AssertedByKind::Agent,
                visibility: None,
                team_id: FieldPatch::Unchanged,
                owner_type: FieldPatch::Unchanged,
                owner_id: FieldPatch::Unchanged,
                display_label: FieldPatch::Unchanged,
                meta_json: None,
                archived_at: FieldPatch::Set(ua_core::time::now()),
            },
        )
    })
    .unwrap();
    assert!(!can_traverse(&teammate), "archived node must be excluded from traversals");

    // Unarchive + flip back to `org`: visible to everyone again.
    db.write(|tx| {
        graph_node_update(
            tx,
            UpdateNodeRequest {
                org_id: DEFAULT_ORG.into(),
                node_id: target.id.clone(),
                actor: PrincipalId::new("owner-1").unwrap(),
                actor_kind: AssertedByKind::Agent,
                visibility: Some(Visibility::Org),
                team_id: FieldPatch::Clear,
                owner_type: FieldPatch::Clear,
                owner_id: FieldPatch::Clear,
                display_label: FieldPatch::Unchanged,
                meta_json: None,
                archived_at: FieldPatch::Clear,
            },
        )
    })
    .unwrap();
    assert!(can_traverse(&outsider));
}

#[test]
fn graph_edge_update_weight_records_same_tx_event_rolls_back_redacts_and_updates_traversal_ranking() {
    let db = open_graph_db();
    let seed = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "ew-seed");
    let a = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "ew-a");
    let b = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "ew-b");

    let (ea, eb) = db
        .write(|tx| {
            let ea = assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: seed.id.clone(),
                    dst_id: a.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 2.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
            let eb = assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: seed.id.clone(),
                    dst_id: b.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_agent("builder-1"),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: true,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
            Ok((ea, eb))
        })
        .unwrap();

    // Invalid weights refused.
    for bad_w in [0.0, -1.0, 1000.1, f64::NAN, f64::INFINITY] {
        let err = db
            .write(|tx| {
                graph_edge_update_weight(
                    tx,
                    UpdateEdgeWeightRequest {
                        org_id: DEFAULT_ORG.into(),
                        edge_id: eb.id.clone(),
                        actor: PrincipalId::new("builder-1").unwrap(),
                        actor_kind: AssertedByKind::Agent,
                        weight: bad_w,
                    },
                )
            })
            .unwrap_err();
        assert_eq!(err.code(), "invalid_argument", "weight={bad_w}");
    }

    // Rolled-back update reverts weight and event_log.
    let rb: Result<(), UaError> = db.write(|tx| {
        graph_edge_update_weight(
            tx,
            UpdateEdgeWeightRequest {
                org_id: DEFAULT_ORG.into(),
                edge_id: eb.id.clone(),
                actor: PrincipalId::new("builder-1").unwrap(),
                actor_kind: AssertedByKind::Agent,
                weight: 10.0,
            },
        )?;
        Err(UaError::invalid("force rollback"))
    });
    assert!(rb.is_err());
    assert_eq!(
        db.read_mut(|c| SqliteGraph::new(c).get_edge_by_id(DEFAULT_ORG, &eb.id)).unwrap().unwrap().weight,
        1.0
    );
    let ev_rb: i64 = db
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM event_log WHERE channel = ?1", [EVENT_EDGE_UPDATED], |r| {
                r.get(0)
            })?)
        })
        .unwrap();
    assert_eq!(ev_rb, 0);

    // Raise `eb` weight from 1.0 -> 5.0: `neighbors` ordering flips so `b` comes before `a`.
    let (updated, changed) = db
        .write(|tx| {
            graph_edge_update_weight(
                tx,
                UpdateEdgeWeightRequest {
                    org_id: DEFAULT_ORG.into(),
                    edge_id: eb.id.clone(),
                    actor: PrincipalId::new("builder-1").unwrap(),
                    actor_kind: AssertedByKind::Agent,
                    weight: 5.0,
                },
            )
        })
        .unwrap();
    assert!(changed);
    assert_eq!(updated.weight, 5.0);

    let nbrs = db
        .read_mut(|c| {
            neighbors(
                &mut SqliteGraph::new(c),
                NeighborsRequest {
                    org_id: DEFAULT_ORG.into(),
                    node_id: Some(seed.id.clone()),
                    kind: None,
                    external_id: None,
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: None,
                    include_proposed: false,
                    limit: Some(10),
                    cursor: None,
                    deadline_ms: None,
                    scope: VisibilityScope::org_only(),
                },
            )
        })
        .unwrap();
    assert_eq!(nbrs.neighbors[0].node.id, b.id, "higher-weight edge must rank first");
    assert_eq!(nbrs.neighbors[1].node.id, a.id);

    let (orig_ev, payload_str): (String, String) = db
        .read(|c| {
            Ok(c.query_row(
                "SELECT originator, payload FROM event_log WHERE channel = ?1 ORDER BY seq DESC LIMIT 1",
                [EVENT_EDGE_UPDATED],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(orig_ev, "builder-1");
    let ev: serde_json::Value = serde_json::from_str(&payload_str).unwrap();
    assert_eq!(ev["edge_id"], eb.id);
    assert_eq!(ev["old_weight"], 1.0);
    assert_eq!(ev["new_weight"], 5.0);
    assert_eq!(ev["changed_fields"], json!(["weight"]));
    assert_eq!(ev["updated_by"], "builder-1");

    // Retracted/closed edge refuses weight updates (`edge_already_closed`).
    db.write(|tx| {
        retract_edge(
            tx,
            RetractEdgeRequest {
                org_id: DEFAULT_ORG.into(),
                edge_id: ea.id.clone(),
                retractor: PrincipalId::new("builder-1").unwrap(),
                retractor_kind: AssertedByKind::Agent,
                valid_to: None,
                generic: true,
            },
        )
    })
    .unwrap();
    let closed_err = db
        .write(|tx| {
            graph_edge_update_weight(
                tx,
                UpdateEdgeWeightRequest {
                    org_id: DEFAULT_ORG.into(),
                    edge_id: ea.id.clone(),
                    actor: PrincipalId::new("builder-1").unwrap(),
                    actor_kind: AssertedByKind::Agent,
                    weight: 3.0,
                },
            )
        })
        .unwrap_err();
    assert_eq!(closed_err.code(), "conflict");
    assert_eq!(closed_err.reason_code(), Some("edge_already_closed"));

    // Non-default org edge weight update redacts actor and uses originator `system`.
    let ob1 = ensure_org_node(&db, "org-b", NodeKind::MemoryNote, "ob-ew-1");
    let ob2 = ensure_org_node(&db, "org-b", NodeKind::MemoryNote, "ob-ew-2");
    let ob_edge = db
        .write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: "org-b".into(),
                    src_id: ob1.id.clone(),
                    dst_id: ob2.id.clone(),
                    kind: EdgeKind::Extends,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: prov_system_import(),
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )
        })
        .unwrap();
    let (_, ch) = db
        .write(|tx| {
            graph_edge_update_weight(
                tx,
                UpdateEdgeWeightRequest {
                    org_id: "org-b".into(),
                    edge_id: ob_edge.id.clone(),
                    actor: PrincipalId::system(),
                    actor_kind: AssertedByKind::System,
                    weight: 4.5,
                },
            )
        })
        .unwrap();
    assert!(ch);
    let (ob_orig, ob_payload): (String, String) = db
        .read(|c| {
            Ok(c.query_row(
                "SELECT originator, payload FROM event_log WHERE channel = ?1 ORDER BY seq DESC LIMIT 1",
                [EVENT_EDGE_UPDATED],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(ob_orig, "system");
    let ob_ev: serde_json::Value = serde_json::from_str(&ob_payload).unwrap();
    assert_eq!(ob_ev["org_id"], "org-b");
    assert_eq!(ob_ev["edge_id"], ob_edge.id);
    assert_eq!(ob_ev["old_weight"], 1.0);
    assert_eq!(ob_ev["new_weight"], 4.5);
    assert!(ob_ev.get("updated_by").is_none());
}
