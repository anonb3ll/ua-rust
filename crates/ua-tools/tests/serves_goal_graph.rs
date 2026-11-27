//! C2 slice b (`docs/graph.md`): the default organization's task→goal link
//! is a `serves_goal` graph edge (task node → goal node) written through
//! `ua-graph`; `goal_manage` keeps its contract. Every other organization
//! stays on `task_goal_links` until #2790. `goals.v3.serves_goal_graph`
//! copies the default organization's legacy rows onto edges as imports and
//! freezes the old table for that organization.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const ORG_B: &str = "org-b";
const PART: &str = "goals.v3.serves_goal_graph";
const OLD_LINKED_AT: &str = "2025-03-04T05:06:07+00:00";

fn add_org(db: &ua_store::Db, id: &str) {
    db.write(|tx| {
        tx.execute(
            "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
             VALUES (?1, ?1, 'Org B', '[\"developer\",\"coordinator\"]', '2026-01-01T00:00:00+00:00')",
            [id],
        )?;
        Ok(())
    })
    .unwrap();
}

fn agent(org: &str) -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("builder-1-s".into()),
        transport: Transport::Mcp,
        org_id: org.into(),
    }
}

fn operator() -> Caller {
    Caller {
        label: "operator".into(),
        kind: ActorKind::Human,
        profile: Profile::Operator,
        enforce_profile: false,
        session_key: Some("operator-s".into()),
        transport: Transport::Mcp,
        org_id: DEFAULT_ORG.into(),
    }
}

fn cfg(dir: &std::path::Path) -> Config {
    let mut cfg = Config::for_home(dir);
    cfg.human_identities = vec!["operator".into()];
    cfg
}

struct H {
    hub: Hub,
    reg: Registry,
    _dir: tempfile::TempDir,
}

impl H {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let hub = Hub::in_memory(cfg(dir.path())).unwrap();
        add_org(hub.db(), ORG_B);
        Self { hub, reg: builtin_registry(), _dir: dir }
    }

    fn of(hub: Hub, dir: tempfile::TempDir) -> Self {
        Self { hub, reg: builtin_registry(), _dir: dir }
    }

    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, tool, args).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.call(who, tool, args.clone()).await.unwrap_or_else(|e| panic!("{tool}({args}): {e:?}"))
    }

    async fn goal(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.call(who, "goal_manage", json!({ "action": action, "params": params })).await
    }

    async fn goal_ok(&self, who: &Caller, action: &str, params: Value) -> Value {
        self.goal(who, action, params.clone())
            .await
            .unwrap_or_else(|e| panic!("goal {action}({params}): {e:?}"))
    }

    async fn add_goal(&self, who: &Caller, title: &str, parent: Option<i64>) -> i64 {
        let mut p = json!({ "title": title, "project": "web" });
        if let Some(pid) = parent {
            p["parent_goal_id"] = json!(pid);
        }
        self.goal_ok(who, "add", p).await["goal"]["id"].as_i64().unwrap()
    }

    async fn task(&self, who: &Caller, title: &str) -> i64 {
        self.ok(who, "task_add", json!({ "title": title, "project": "web" })).await["id"].as_i64().unwrap()
    }

    fn count(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    fn text(&self, sql: &str) -> Option<String> {
        let sql = sql.to_string();
        self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
    }

    fn sql(&self, sql: &str) -> Result<(), String> {
        let sql = sql.to_string();
        self.hub
            .db()
            .write(move |tx| {
                tx.execute_batch(&sql)?;
                Ok(())
            })
            .map_err(|e| e.to_string())
    }

    /// `serves_goal` edges of task `task` as `goal:live` (`live` is 1 for a
    /// live edge), oldest first.
    fn edges(&self, task: i64) -> Vec<String> {
        self.hub
            .db()
            .read(move |c| {
                Ok(c.prepare(
                    "SELECT g.external_id || ':' || (e.valid_to IS NULL) FROM graph_edges e \
                     JOIN graph_nodes t ON t.org_id = e.org_id AND t.id = e.src_id \
                     JOIN graph_nodes g ON g.org_id = e.org_id AND g.id = e.dst_id \
                     WHERE e.org_id = 'default' AND e.kind = 'serves_goal' AND t.kind = 'task' \
                     AND t.external_id = ?1 ORDER BY e.rowid",
                )?
                .query_map([task.to_string()], |r| r.get(0))?
                .collect::<Result<_, _>>()?)
            })
            .unwrap()
    }

    fn events(&self, channel: &str) -> i64 {
        self.count(&format!("SELECT COUNT(*) FROM event_log WHERE channel = '{channel}'"))
    }
}

fn chain(v: &Value) -> Vec<i64> {
    v["chain"].as_array().unwrap().iter().map(|g| g["id"].as_i64().unwrap()).collect()
}

#[tokio::test]
async fn link_asserts_an_edge_and_unlink_closes_it() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let root = h.add_goal(&a, "Root", None).await;
    let child = h.add_goal(&a, "Child", Some(root)).await;
    let t = h.task(&a, "Task").await;

    let v = h.goal_ok(&a, "link", json!({ "task_id": t, "goal_id": child })).await;
    assert_eq!(v["edge"], "goal_task", "{v}");
    assert_eq!(v["why_chain"]["goal_id"], child, "{v}");
    assert_eq!(chain(&v["why_chain"]), [root, child], "{v}");
    assert_eq!(h.edges(t), [format!("{child}:1")]);
    assert_eq!(
        h.count("SELECT COUNT(*) FROM task_goal_links"),
        0,
        "the default organization writes no legacy row"
    );
    // Provenance: the acting agent, a domain (event) write citing its ledger event.
    let row = h
        .text(
            "SELECT asserted_by || '|' || asserted_by_kind || '|' || source_kind || '|' || source_ref \
             FROM graph_edges WHERE kind = 'serves_goal'",
        )
        .unwrap();
    let seq = h.count("SELECT MAX(seq) FROM event_log WHERE channel = 'agent.graph.edge_asserted'");
    assert_eq!(row, format!("builder-1|agent|event|event:{seq}"));
    assert_eq!(h.events("agent.goal.linked"), 1);
    assert_eq!(h.events("agent.graph.node_created"), 2);
    assert_eq!(h.events("agent.graph.edge_asserted"), 1);

    // Linking again to the same goal changes nothing.
    h.goal_ok(&a, "link", json!({ "task_id": t, "goal_id": child })).await;
    assert_eq!((h.edges(t).len(), h.events("agent.goal.linked")), (1, 1));

    // Ancestry walks serves_goal then goal_parent, unchanged.
    let v = h.goal_ok(&a, "ancestry", json!({ "task_id": t })).await;
    assert_eq!((v["goal_id"].as_i64(), chain(&v)), (Some(child), vec![root, child]), "{v}");
    assert_eq!(v["edge"], "goal_ancestry", "{v}");
    // A linked task still cannot move to another project.
    let e = h.call(&a, "task_update", json!({ "id": t, "project": "other" })).await.unwrap_err();
    assert!(e.to_string().contains("serves a goal"), "{e}");

    // Unlink closes the edge; the row stays.
    let v = h.goal_ok(&a, "unlink", json!({ "task_id": t, "goal_id": child })).await;
    assert_eq!(v, json!({ "task_id": t, "goal_id": child, "edge": "goal_task", "unlinked": true }));
    assert_eq!(h.edges(t), [format!("{child}:0")]);
    assert_eq!(h.events("agent.goal.unlinked"), 1);
    assert_eq!(h.events("agent.graph.edge_retracted"), 1);
    let v = h.goal_ok(&a, "ancestry", json!({ "task_id": t })).await;
    assert!(v["goal_id"].is_null() && chain(&v).is_empty(), "{v}");
    let e = h.goal(&a, "unlink", json!({ "task_id": t, "goal_id": child })).await.unwrap_err();
    assert!(e.to_string().contains("serves no goal"), "{e}");
    h.ok(&a, "task_update", json!({ "id": t, "project": "other" })).await;
    h.ok(&a, "task_update", json!({ "id": t, "project": "web" })).await;

    // Re-linking asserts a new edge; history stays readable.
    h.goal_ok(&a, "link", json!({ "task_id": t, "goal_id": root })).await;
    assert_eq!(h.edges(t), [format!("{child}:0"), format!("{root}:1")]);
    assert_eq!(h.events("agent.graph.node_created"), 3, "the task node is reused, the root's is new");

    // Deleting the task closes its live edge (the old table cascaded).
    h.ok(&operator(), "task_delete", json!({ "id": t })).await;
    assert_eq!(h.edges(t), [format!("{child}:0"), format!("{root}:0")]);
}

#[tokio::test]
async fn a_task_has_at_most_one_live_serves_goal_edge() {
    let h = H::new();
    let a = agent(DEFAULT_ORG);
    let g1 = h.add_goal(&a, "One", None).await;
    let g2 = h.add_goal(&a, "Two", None).await;
    let t = h.task(&a, "Task").await;
    h.goal_ok(&a, "link", json!({ "task_id": t, "goal_id": g1 })).await;

    // A link to a second goal is refused as before and writes nothing.
    let before = (h.count("SELECT COUNT(*) FROM graph_edges"), h.count("SELECT COUNT(*) FROM event_log"));
    let e = h.goal(&a, "link", json!({ "task_id": t, "goal_id": g2 })).await.unwrap_err();
    assert!(e.to_string().contains("single-valued"), "{e}");
    assert_eq!(
        (h.count("SELECT COUNT(*) FROM graph_edges"), h.count("SELECT COUNT(*) FROM event_log")),
        before
    );
    assert_eq!(h.edges(t), [format!("{g1}:1")]);

    // Moving the task: unlink closes the old edge, link asserts the new one.
    h.goal_ok(&a, "unlink", json!({ "task_id": t, "goal_id": g1 })).await;
    h.goal_ok(&a, "link", json!({ "task_id": t, "goal_id": g2 })).await;
    assert_eq!(h.edges(t), [format!("{g1}:0"), format!("{g2}:1")]);
    let v = h.goal_ok(&a, "ancestry", json!({ "task_id": t })).await;
    assert_eq!(v["goal_id"], g2, "{v}");

    // The store itself refuses a second live edge from the task.
    let e = h
        .sql(&format!(
            "INSERT INTO graph_edges (id, org_id, src_id, dst_id, kind, asserted_by, asserted_by_kind, asserted_at,
                 source_kind, source_ref, valid_from)
             SELECT 'EXTRA', 'default', t.id, g.id, 'serves_goal', 'system', 'system', '2026-01-01T00:00:00+00:00',
                 'import', 'import:test', '2026-01-01T00:00:00+00:00'
             FROM graph_nodes t, graph_nodes g
             WHERE t.kind = 'task' AND t.external_id = '{t}' AND g.kind = 'goal' AND g.external_id = '{g1}'"
        ))
        .unwrap_err();
    assert!(e.contains("UNIQUE"), "{e}");
}

#[tokio::test]
async fn another_organization_stays_on_task_goal_links() {
    let h = H::new();
    let b = agent(ORG_B);
    let a = agent(DEFAULT_ORG);
    let gb = h.add_goal(&b, "B goal", None).await;
    let tb = h.task(&b, "B task").await;
    let ga = h.add_goal(&a, "A goal", None).await;
    let ta = h.task(&a, "A task").await;

    let v = h.goal_ok(&b, "link", json!({ "task_id": tb, "goal_id": gb })).await;
    assert_eq!(v["why_chain"]["goal_id"], gb, "{v}");
    assert_eq!(
        h.count(&format!("SELECT COUNT(*) FROM task_goal_links WHERE org_id = 'org-b' AND task_id = {tb}")),
        1
    );
    assert_eq!(h.count("SELECT COUNT(*) FROM graph_nodes"), 0, "organization B never reaches the graph");
    assert_eq!(h.count("SELECT COUNT(*) FROM event_log WHERE channel LIKE 'agent.graph.%'"), 0);
    let v = h.goal_ok(&b, "ancestry", json!({ "task_id": tb })).await;
    assert_eq!(v["goal_id"], gb, "{v}");

    // Each organization's goals and tasks answer as missing to the other.
    for (who, task, goal) in [(&a, tb, ga), (&a, ta, gb), (&b, ta, gb), (&b, tb, ga)] {
        let e = h.goal(who, "link", json!({ "task_id": task, "goal_id": goal })).await.unwrap_err();
        assert_eq!(e.code(), "not_found", "{e}");
    }
    assert_eq!(h.count("SELECT COUNT(*) FROM graph_edges"), 0);

    h.goal_ok(&b, "unlink", json!({ "task_id": tb, "goal_id": gb })).await;
    assert_eq!(h.count("SELECT COUNT(*) FROM task_goal_links"), 0);
    assert_eq!(h.count("SELECT COUNT(*) FROM graph_nodes"), 0);
    // Organization B's events stay neutral.
    assert_eq!(
        h.count(
            "SELECT COUNT(*) FROM event_log WHERE channel IN ('agent.goal.linked', 'agent.goal.unlinked') \
             AND originator <> 'system'"
        ),
        0
    );
}

/// A database written before the part: its default links are copied onto
/// edges as imports (counted), the part deletes no row, the old table is
/// frozen for the default organization, and organization B's link is
/// untouched. A row whose task already has a live edge, or whose task is
/// another organization's, is skipped and counted.
#[tokio::test]
async fn the_upgrade_copies_default_links_onto_edges_and_freezes_the_table() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg(dir.path());
    {
        let old: Vec<ua_store::Part> =
            ua_tools::schema_parts().into_iter().filter(|p| p.name != PART).collect();
        let db = ua_store::Db::open(&cfg.db_path(), &old).unwrap();
        add_org(&db, ORG_B);
        db.write(|tx| {
            tx.execute_batch(&format!(
                "INSERT INTO tasks (id, org_id, title, project, created_at, updated_at) VALUES
                     (1, 'default', 'One', 'web', 'x', 'x'), (2, 'default', 'Two', 'web', 'x', 'x'),
                     (3, 'org-b', 'Three', 'web', 'x', 'x'), (4, 'org-b', 'Four', 'web', 'x', 'x'),
                     (5, 'default', 'Five', 'web', 'x', 'x');
                 INSERT INTO goals (id, org_id, title, project, created_at, updated_at) VALUES
                     (1, 'default', 'Root', 'web', 'x', 'x');
                 INSERT INTO goals (id, org_id, title, project, parent_goal_id, created_at, updated_at) VALUES
                     (2, 'default', 'Child', 'web', 1, 'x', 'x'), (3, 'org-b', 'B', 'web', NULL, 'x', 'x');
                 INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_by, linked_at) VALUES
                     ('default', 1, 2, 'lead-1', '{OLD_LINKED_AT}'), ('default', 2, 1, NULL, 'not a time'),
                     ('org-b', 3, 3, 'b-agent', '{OLD_LINKED_AT}');
                 DROP TRIGGER task_goal_links_org_parent;
                 INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_at) VALUES ('default', 4, 1, 'x');
                 INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_at) VALUES ('default', 5, 2, 'x');
                 INSERT INTO graph_nodes (id, org_id, kind, external_id, asserted_by, asserted_by_kind, source_kind,
                     source_ref, created_at, updated_at) VALUES
                     ('N5', 'default', 'task', '5', 'system', 'system', 'import', 'import:pre', '{OLD_LINKED_AT}',
                      '{OLD_LINKED_AT}'),
                     ('G1', 'default', 'goal', '1', 'system', 'system', 'import', 'import:pre', '{OLD_LINKED_AT}',
                      '{OLD_LINKED_AT}');
                 INSERT INTO graph_edges (id, org_id, src_id, dst_id, kind, asserted_by, asserted_by_kind, asserted_at,
                     source_kind, source_ref, valid_from) VALUES
                     ('E5', 'default', 'N5', 'G1', 'serves_goal', 'system', 'system', '{OLD_LINKED_AT}', 'import',
                      'import:pre', '{OLD_LINKED_AT}');"
            ))?;
            Ok(())
        })
        .unwrap();
    }
    // Open twice: the part runs once.
    for _ in 0..2 {
        drop(Hub::open(cfg.clone()).unwrap());
    }
    let h = H::of(Hub::open(cfg).unwrap(), dir);

    // Copied: tasks 1 and 2. Skipped: task 4 (another organization's task)
    // and task 5 (its live edge to goal 1 predates the part and wins).
    assert_eq!(h.edges(1), ["2:1"]);
    assert_eq!(h.edges(2), ["1:1"]);
    assert_eq!(h.edges(4), Vec::<String>::new());
    assert_eq!(h.edges(5), ["1:1"]);
    let v = h.goal_ok(&agent(DEFAULT_ORG), "ancestry", json!({ "task_id": 5 })).await;
    assert_eq!(v["goal_id"], 1, "the legacy row is hidden behind the live edge: {v}");
    let e1 = h
        .text(
            "SELECT e.asserted_by || '|' || e.asserted_by_kind || '|' || e.source_kind || '|' || e.source_ref || \
             '|' || e.valid_from || '|' || e.meta_json FROM graph_edges e JOIN graph_nodes t ON t.id = e.src_id \
             WHERE t.external_id = '1' AND t.kind = 'task'",
        )
        .unwrap();
    assert_eq!(
        e1,
        format!("system|system|import|import:task_goal_links:1|{OLD_LINKED_AT}|{{\"linked_by\":\"lead-1\"}}")
    );
    assert_eq!(h.count("SELECT COUNT(*) FROM graph_nodes WHERE org_id <> 'default'"), 0);
    assert_eq!(h.count("SELECT COUNT(*) FROM graph_nodes WHERE source_kind <> 'import'"), 0);
    assert_eq!(
        h.count("SELECT COUNT(*) FROM event_log WHERE channel LIKE 'agent.graph.%'"),
        0,
        "no ledger event"
    );
    // Nothing dropped: every legacy row is still there.
    assert_eq!(h.count("SELECT COUNT(*) FROM task_goal_links"), 5);
    // The counts are recorded in the part's audit SQL and by the doctor.
    let want = json!({
        "total": 4,
        "copied": 2,
        "skipped_total": 2,
        "skipped": { "already_linked": 1, "missing_task": 1 },
        "skipped_rows": [{ "task_id": 4, "reason": "missing_task" }, { "task_id": 5, "reason": "already_linked" }],
    });
    let audit =
        h.text(&format!("SELECT generated_sql FROM schema_procedures WHERE name = '{PART}'")).unwrap();
    assert!(audit.contains(&format!("goals.v3.serves_goal_graph summary: {want}")), "{audit}");
    let doctor = h.ok(&operator(), "system_doctor", json!({})).await;
    assert_eq!(doctor["database"]["serves_goal_migration"], want, "{doctor}");
    let db_b =
        h.ok(&Caller { org_id: ORG_B.into(), ..operator() }, "system_doctor", json!({})).await["database"]
            .clone();
    assert!(db_b["serves_goal_migration"].is_null(), "{db_b}");

    // The tools read the copied links.
    let a = agent(DEFAULT_ORG);
    let v = h.goal_ok(&a, "ancestry", json!({ "task_id": 1 })).await;
    assert_eq!((v["goal_id"].as_i64(), chain(&v)), (Some(2), vec![1, 2]), "{v}");
    let e = h.goal(&a, "link", json!({ "task_id": 1, "goal_id": 1 })).await.unwrap_err();
    assert!(e.to_string().contains("single-valued"), "{e}");
    // Unlink closes the copied edge and removes the legacy row.
    h.goal_ok(&a, "unlink", json!({ "task_id": 1, "goal_id": 2 })).await;
    assert_eq!(h.edges(1), ["2:0"]);
    assert_eq!(h.count("SELECT COUNT(*) FROM task_goal_links WHERE org_id = 'default' AND task_id = 1"), 0);
    let v = h.goal_ok(&a, "ancestry", json!({ "task_id": 1 })).await;
    assert!(v["goal_id"].is_null(), "{v}");
    h.goal_ok(&a, "link", json!({ "task_id": 1, "goal_id": 1 })).await;
    assert_eq!(h.edges(1), ["2:0", "1:1"]);
    assert_eq!(h.count("SELECT COUNT(*) FROM task_goal_links WHERE org_id = 'default' AND task_id = 1"), 0);

    // Organization B's link is still its legacy row.
    let v = h.goal_ok(&agent(ORG_B), "ancestry", json!({ "task_id": 3 })).await;
    assert_eq!(v["goal_id"], 3, "{v}");

    // The old table takes no new or changed default-organization link.
    for sql in [
        "INSERT INTO tasks (id, org_id, title, project, created_at, updated_at) VALUES (9, 'default', 'N', 'web', 'x', 'x');
         INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_at) VALUES ('default', 9, 1, 'x')",
        "UPDATE task_goal_links SET goal_id = 1 WHERE task_id = 2",
        "UPDATE task_goal_links SET linked_by = 'x' WHERE task_id = 2",
    ] {
        let e = h.sql(sql).unwrap_err();
        assert!(e.contains("serves_goal graph edges"), "{sql}: {e}");
    }
    // Organization B's rows are not frozen.
    h.sql("UPDATE task_goal_links SET linked_by = 'b-other' WHERE task_id = 3").unwrap();
}

/// An unverified caller's claimed label is recorded as an agent, never as
/// the hub: a claimed `system` is refused in the default organization and
/// writes nothing, while organization B (no principal recorded) is unchanged.
#[tokio::test]
async fn a_claimed_label_never_records_the_hub() {
    let h = H::new();
    let local = Caller::local("local-dev", Transport::Cli);
    let a = agent(DEFAULT_ORG);
    let g = h.add_goal(&a, "Goal", None).await;
    let t = h.task(&a, "Task").await;

    let before = (h.count("SELECT COUNT(*) FROM graph_edges"), h.count("SELECT COUNT(*) FROM event_log"));
    let e =
        h.goal(&local, "link", json!({ "task_id": t, "goal_id": g, "author": "System" })).await.unwrap_err();
    assert_eq!(e.reason_code(), Some("reserved_principal_id"), "{e}");
    assert_eq!(
        (h.count("SELECT COUNT(*) FROM graph_edges"), h.count("SELECT COUNT(*) FROM event_log")),
        before
    );

    h.goal_ok(&local, "link", json!({ "task_id": t, "goal_id": g, "author": "night-agent" })).await;
    assert_eq!(
        h.text("SELECT asserted_by || '|' || asserted_by_kind FROM graph_edges WHERE kind = 'serves_goal'")
            .unwrap(),
        "night-agent|agent"
    );
    assert_eq!(h.count("SELECT COUNT(*) FROM graph_edges WHERE asserted_by_kind = 'system'"), 0);
}
