//! Domain and storage-level tests for `ua-graph` and `ua-store::graph`
//! (`docs/graph.md`, C1 acceptance tests).

use rusqlite::Connection;
use serde_json::json;
use ua_core::{DEFAULT_ORG, UaError};
use ua_graph::{
    AssertEdgeRequest, AssertedByKind, CycleCheckBounds, EdgeKind, EdgeState, EnsureNodeRequest, KHopRequest,
    NeighborsRequest, NodeKind, OwnerType, PrincipalId, Provenance, RetractEdgeRequest, SeedExpandRequest,
    SeedInput, ShortestPathRequest, SourceKind, Visibility, WalkDirection, assert_edge, check_acyclic,
    graph_node_ensure, k_hop, neighbors, node_get, retract_edge, schema_parts, seed_expand, shortest_path,
};
use ua_store::graph::{
    EdgeDirection, GraphRead, GraphRepo, NewGraphEdge, NewGraphNode, SqliteGraph, VisibilityScope,
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
                    cycle_bounds: CycleCheckBounds::default(),
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
                    cycle_bounds: CycleCheckBounds::default(),
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
                    cycle_bounds: CycleCheckBounds::default(),
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
                    cycle_bounds: CycleCheckBounds { max_nodes: 5, max_edges: 5_000, deadline_ms: 50 },
                },
            )
        })
        .unwrap_err();
    assert_eq!(node_bound_err.code(), "invalid_argument");
    assert_eq!(node_bound_err.reason_code(), Some("cycle_check_bound_exceeded"));

    // 3. Edge-cap bound hit => cycle_check_bound_exceeded
    let edge_bound_err = db
        .read(|conn| {
            let mut repo = SqliteGraph::new(conn);
            check_acyclic(
                &mut repo,
                DEFAULT_ORG,
                &n_new.id,
                &nodes[0].id,
                EdgeKind::DependsOn,
                CycleCheckBounds { max_nodes: 1_000, max_edges: 4, deadline_ms: 50 },
            )
        })
        .unwrap_err();
    assert_eq!(edge_bound_err.code(), "invalid_argument");
    assert_eq!(edge_bound_err.reason_code(), Some("cycle_check_bound_exceeded"));

    // 4. Deadline bound hit (0 ms) => cycle_check_bound_exceeded
    let deadline_err = db
        .read(|conn| {
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
}

#[test]
fn assert_never_creates_nodes_and_validates_endpoint_kinds() {
    let db = open_graph_db();
    let goal1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Goal, "g1");
    let goal2 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::Goal, "g2");
    let note1 = ensure_org_node(&db, DEFAULT_ORG, NodeKind::MemoryNote, "mn1");
    let foreign_note = ensure_org_node(&db, "org-b", NodeKind::MemoryNote, "mn-foreign");

    // Missing endpoint -> not_found, node count unchanged.
    let before_count = db.read(|c| SqliteGraph::new(c).count_org_nodes(DEFAULT_ORG)).unwrap();
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
                    cycle_bounds: CycleCheckBounds::default(),
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
                    cycle_bounds: CycleCheckBounds::default(),
                },
            )
        })
        .unwrap_err();
    assert_eq!(miss_err.code(), "not_found");
    assert_eq!(foreign_err.code(), "not_found");
    assert_eq!(miss_err.to_string(), foreign_err.to_string(), "zero existence oracle");
    let after_count = db.read(|c| SqliteGraph::new(c).count_org_nodes(DEFAULT_ORG)).unwrap();
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
                    cycle_bounds: CycleCheckBounds::default(),
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
                    cycle_bounds: CycleCheckBounds::default(),
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
                    cycle_bounds: CycleCheckBounds::default(),
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
                    cycle_bounds: CycleCheckBounds::default(),
                },
            )?;
            Ok(e1)
        })
        .unwrap();

    let outsider = VisibilityScope::for_principal("agent", "outsider", vec![]);
    let owner = VisibilityScope::for_principal("agent", "owner-1", vec![]);

    let snapshot = |scope: &VisibilityScope| {
        db.read(|conn| {
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
                    cycle_bounds: CycleCheckBounds::default(),
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
                    cycle_bounds: CycleCheckBounds::default(),
                },
            )
        })
        .expect("import historical edge");

    let at_mid = db
        .read(|conn| {
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
        .read(|conn| {
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
        .read(|c| node_get(&mut SqliteGraph::new(c), DEFAULT_ORG, Some("no-such"), None, None, &outsider))
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
                    cycle_bounds: CycleCheckBounds::default(),
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
                cycle_bounds: CycleCheckBounds::default(),
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
                cycle_bounds: CycleCheckBounds::default(),
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
                    cycle_bounds: CycleCheckBounds::default(),
                },
            )?;
        }
        Ok(())
    })
    .unwrap();

    let scope = VisibilityScope::org_only();
    let page1 = db
        .read(|c| {
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
        .read(|c| {
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
        .read(|c| {
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
        .read(|c| {
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
        .read(|c| {
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
