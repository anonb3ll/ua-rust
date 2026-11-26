//! The single goal a task serves (`docs/graph.md`, C2 slice b).
//!
//! **Default organization:** the link is a `serves_goal` edge (task node →
//! goal node) in the shared graph store, written through `ua-graph`
//! (`graph_node_ensure`, `assert_edge`, `retract_edge`) in the caller's
//! write transaction. `idx_graph_edges_single_out_live` keeps at most one
//! live edge per task; unlinking closes the edge (`valid_to = now`) and never
//! deletes it. `goals.v3.serves_goal_graph` copied the legacy rows and
//! `task_goal_links_default_frozen` refuses every new default-organization
//! row there. Reads fall back to the old table only when the task has no
//! live edge: a legacy row whose task and goal are both the default
//! organization's but that was not copied (only on a database assembled
//! without the part's prerequisites) answers until it is unlinked.
//!
//! **Every other organization:** `task_goal_links`, exactly as before,
//! until #2790 supplies immutable principal IDs. A graph write there with a
//! caller's label is refused (`principal_id_required`), and stamping
//! `'system'` would lose who linked the task.

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;
use std::collections::BTreeMap;
use ua_core::{Caller, DEFAULT_ORG, UaResult};

use serde_json::Value;
use ua_graph::{
    AssertEdgeRequest, AssertedByKind, CycleCheckPolicy, EdgeKind, EdgeState, EnsureNodeRequest, NodeKind,
    PrincipalId, Provenance, RetractEdgeRequest, SourceKind, Visibility,
};
use ua_store::graph::{
    AdjacencyQuery, EdgeDirection, EdgeFilter, GraphRead, GraphRepo, MigrationGraph, SqliteGraph,
    VisibilityScope,
};
use ua_store::{Procedure, WriteTx};

/// `source_ref` prefix of the edges `goals.v3.serves_goal_graph` copied:
/// `import:task_goal_links:<task_id>`, the legacy row's key.
pub const LEGACY_SOURCE_PREFIX: &str = "import:task_goal_links:";

/// The graph limits a link write honours (`Config::graph_max_*`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct GraphCaps {
    pub max_nodes_per_org: u64,
    pub max_edges_per_org: u64,
    pub max_live_edges_per_node: u64,
}

impl GraphCaps {
    pub(crate) fn of(cfg: &ua_core::Config) -> Self {
        Self {
            max_nodes_per_org: cfg.graph_max_nodes_per_org,
            max_edges_per_org: cfg.graph_max_edges_per_org,
            max_live_edges_per_node: cfg.graph_max_live_edges_per_node,
        }
    }
}

/// A default-organization link or unlink's recorded principal, or why the
/// acting label cannot be one.
pub(crate) type Actor = UaResult<(PrincipalId, AssertedByKind)>;

/// The principal a default-organization graph write records: the acting
/// label (provisional until #2790 backfills stable ids), as a person when the
/// caller is a verified human, else as an agent (an unverified caller's
/// claimed label included). Never `system`: a label `PrincipalId` refuses
/// (the reserved `system`, an over-long one) is refused when a
/// default-organization link or unlink would record it, as `dependency_add`
/// refuses it. Other organizations never record a principal, so the result
/// is only checked on the default organization's path.
pub(crate) fn graph_actor(caller: &Caller, who: &str) -> Actor {
    let principal = PrincipalId::new(who)?;
    let kind = if ua_org::authz::human(caller) { AssertedByKind::Person } else { AssertedByKind::Agent };
    Ok((principal, kind))
}

/// The live `serves_goal` edge of task `task_id` in the default organization:
/// `(edge id, goal id)`.
fn live_edge<R: GraphRead>(repo: &mut R, task_id: i64) -> UaResult<Option<(String, i64)>> {
    let scope = VisibilityScope::org_only();
    let Some(task) =
        repo.get_node_by_external(DEFAULT_ORG, NodeKind::Task.as_str(), &task_id.to_string(), &scope)?
    else {
        return Ok(None);
    };
    let entries = repo.adjacent_edges(&AdjacencyQuery {
        org_id: DEFAULT_ORG.to_string(),
        node_id: task.id,
        direction: EdgeDirection::Out,
        filter: EdgeFilter {
            as_of: ua_core::time::now(),
            edge_kinds: vec![EdgeKind::ServesGoal.as_str().to_string()],
            node_kinds: vec![NodeKind::Goal.as_str().to_string()],
            include_proposed: false,
        },
        scope,
        limit: 1,
        cursor: None,
    })?;
    Ok(entries.into_iter().next().and_then(|e| e.neighbor.external_id.parse().ok().map(|g| (e.edge.id, g))))
}

/// The goal of a `task_goal_links` row of organization `org`.
fn legacy_goal(conn: &Connection, org: &str, task_id: i64) -> UaResult<Option<i64>> {
    Ok(conn
        .query_row(
            "SELECT goal_id FROM task_goal_links WHERE org_id = ?1 AND task_id = ?2",
            params![org, task_id],
            |r| r.get(0),
        )
        .optional()?)
}

/// The goal task `task_id` serves in organization `org`, inside a write.
pub(crate) fn served_goal_tx(tx: &mut WriteTx<'_>, org: &str, task_id: i64) -> UaResult<Option<i64>> {
    if org == DEFAULT_ORG
        && let Some((_, g)) = live_edge(tx, task_id)?
    {
        return Ok(Some(g));
    }
    legacy_goal(tx, org, task_id)
}

/// The goal task `task_id` serves in organization `org`, on a reader.
pub(crate) fn served_goal_read(conn: &mut Connection, org: &str, task_id: i64) -> UaResult<Option<i64>> {
    if org == DEFAULT_ORG
        && let Some((_, g)) = live_edge(&mut SqliteGraph::new(conn), task_id)?
    {
        return Ok(Some(g));
    }
    legacy_goal(conn, org, task_id)
}

/// Record that task `task_id` serves goal `goal_id` (the caller checked both
/// exist in `org` and that the task serves no goal yet).
pub(crate) fn link(
    tx: &mut WriteTx<'_>,
    org: &str,
    task_id: i64,
    goal_id: i64,
    who: &str,
    actor: Actor,
    caps: GraphCaps,
) -> UaResult<()> {
    if org != DEFAULT_ORG {
        tx.execute(
            "INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_by, linked_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![org, task_id, goal_id, who, ua_core::time::now()],
        )?;
        return Ok(());
    }
    let (asserted_by, asserted_by_kind) = actor?;
    let provenance = Provenance {
        asserted_by,
        asserted_by_kind,
        source_kind: SourceKind::Event,
        source_ref: "tool:goal_manage".to_string(),
    };
    let node = |tx: &mut WriteTx<'_>, kind: NodeKind, id: i64| {
        ua_graph::graph_node_ensure(
            tx,
            EnsureNodeRequest {
                org_id: DEFAULT_ORG.to_string(),
                kind,
                external_id: id.to_string(),
                display_label: None,
                visibility: Visibility::Org,
                team_id: None,
                owner_type: None,
                owner_id: None,
                provenance: provenance.clone(),
                meta_json: None,
                max_nodes_per_org: caps.max_nodes_per_org,
            },
        )
        .map(|(n, _)| n.id)
    };
    let src_id = node(tx, NodeKind::Task, task_id)?;
    let dst_id = node(tx, NodeKind::Goal, goal_id)?;
    ua_graph::assert_edge(
        tx,
        AssertEdgeRequest {
            org_id: DEFAULT_ORG.to_string(),
            src_id,
            dst_id,
            kind: EdgeKind::ServesGoal,
            assertion_scope: String::new(),
            state: EdgeState::Active,
            weight: 1.0,
            provenance,
            valid_from: None,
            valid_to: None,
            meta_json: None,
            scope: VisibilityScope::org_only(),
            generic: false,
            max_edges_per_org: caps.max_edges_per_org,
            max_live_edges_per_node: caps.max_live_edges_per_node,
            cycle_bounds: CycleCheckPolicy::default(),
        },
    )?;
    Ok(())
}

/// Stop task `task_id` serving its goal (the caller checked which one). In
/// the default organization the live edge is closed, never deleted; a legacy
/// row, in any organization, is removed as before.
pub(crate) fn unlink(tx: &mut WriteTx<'_>, org: &str, task_id: i64, actor: Actor) -> UaResult<()> {
    if org == DEFAULT_ORG {
        close_live(tx, task_id, actor?)?;
    }
    tx.execute("DELETE FROM task_goal_links WHERE org_id = ?1 AND task_id = ?2", params![org, task_id])?;
    Ok(())
}

/// Close the live edges of default-organization tasks that are being
/// deleted, as the old table's `ON DELETE CASCADE` removed their rows. A
/// hub-internal projection of the delete, so the hub (`system`) retracts,
/// as `task_delete` does for `depends_on`.
pub(crate) fn close_for_deleted_tasks(tx: &mut WriteTx<'_>, org: &str, task_ids: &[i64]) -> UaResult<()> {
    if org != DEFAULT_ORG {
        return Ok(());
    }
    for &id in task_ids {
        close_live(tx, id, (PrincipalId::system(), AssertedByKind::System))?;
    }
    Ok(())
}

fn close_live(tx: &mut WriteTx<'_>, task_id: i64, actor: (PrincipalId, AssertedByKind)) -> UaResult<()> {
    if let Some((edge_id, _)) = live_edge(tx, task_id)? {
        ua_graph::retract_edge(
            tx,
            RetractEdgeRequest {
                org_id: DEFAULT_ORG.to_string(),
                edge_id,
                retractor: actor.0,
                retractor_kind: actor.1,
                valid_to: None,
                generic: false,
            },
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Copying legacy links (the schema part and `ua import`)
// ---------------------------------------------------------------------------

const MIGRATION_PART_NAME: &str = "goals.v3.serves_goal_graph";
const MIGRATION_SUMMARY_PREFIX: &str = "goals.v3.serves_goal_graph summary: ";

/// Copy one default-organization task→goal link into the graph as an
/// import, inside a migration or `ua import` transaction, through
/// [`MigrationGraph`] (no ledger event: a schema part cannot append to the
/// ledger, and `ua import` copies the source ledger as it is):
/// `graph_node_ensure` for the task and goal nodes and `assert_edge` for a
/// live `serves_goal` edge, all `asserted_by = 'system'`,
/// `source_kind = 'import'` and `source_ref = source_ref`. The edge's
/// `valid_from` is `linked_at` when it is a timestamp no later than now (an
/// import may carry history), else the import time with the raw value kept
/// in `meta_json.legacy_linked_at`; `linked_by` is kept in
/// `meta_json.linked_by`. Caps are not applied (an upgrade copies what is
/// there).
///
/// Returns `Ok(None)` when copied, or `Ok(Some(reason))` when skipped,
/// writing nothing: `missing_task` / `missing_goal` (not the default
/// organization's) or `already_linked` (the task already has a live
/// `serves_goal` edge).
pub fn import_legacy_link(
    conn: &Connection,
    task_id: i64,
    goal_id: i64,
    linked_by: Option<&str>,
    linked_at: Option<&str>,
    source_ref: &str,
) -> UaResult<Option<&'static str>> {
    let exists = |table: &str, id: i64| -> UaResult<bool> {
        Ok(conn
            .query_row(
                &format!("SELECT 1 FROM {table} WHERE org_id = ?1 AND id = ?2"),
                params![DEFAULT_ORG, id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    };
    if !exists("tasks", task_id)? {
        return Ok(Some("missing_task"));
    }
    if !exists("goals", goal_id)? {
        return Ok(Some("missing_goal"));
    }
    let mut repo = MigrationGraph::new(conn);
    if let Some(task) =
        repo.find_node_by_external_internal(DEFAULT_ORG, NodeKind::Task.as_str(), &task_id.to_string())?
        && !repo
            .outgoing_live_targets_of_kind(DEFAULT_ORG, &task.id, EdgeKind::ServesGoal.as_str(), 1)?
            .is_empty()
    {
        return Ok(Some("already_linked"));
    }
    let provenance = Provenance {
        asserted_by: PrincipalId::system(),
        asserted_by_kind: AssertedByKind::System,
        source_kind: SourceKind::Import,
        source_ref: source_ref.to_string(),
    };
    let mut node = |kind: NodeKind, id: i64| {
        ua_graph::graph_node_ensure(
            &mut repo,
            EnsureNodeRequest {
                org_id: DEFAULT_ORG.to_string(),
                kind,
                external_id: id.to_string(),
                display_label: None,
                visibility: Visibility::Org,
                team_id: None,
                owner_type: None,
                owner_id: None,
                provenance: provenance.clone(),
                meta_json: None,
                max_nodes_per_org: 0,
            },
        )
        .map(|(n, _)| n.id)
    };
    let src_id = node(NodeKind::Task, task_id)?;
    let dst_id = node(NodeKind::Goal, goal_id)?;
    let now = ua_core::time::now();
    let mut meta = serde_json::Map::new();
    if let Some(by) = linked_by.map(str::trim).filter(|s| !s.is_empty() && s.len() <= 256) {
        meta.insert("linked_by".into(), json!(by));
    }
    let valid_from = match linked_at.map(|t| ua_graph::normalize_timestamp(t, "linked_at")) {
        Some(Ok(ts)) if ts <= now => Some(ts),
        Some(_) => {
            if let Some(raw) = linked_at.filter(|t| t.len() <= 256) {
                meta.insert("legacy_linked_at".into(), json!(raw));
            }
            None
        }
        None => None,
    };
    ua_graph::assert_edge(
        &mut repo,
        AssertEdgeRequest {
            org_id: DEFAULT_ORG.to_string(),
            src_id,
            dst_id,
            kind: EdgeKind::ServesGoal,
            assertion_scope: String::new(),
            state: EdgeState::Active,
            weight: 1.0,
            provenance,
            valid_from,
            valid_to: None,
            meta_json: Some(Value::Object(meta)),
            scope: VisibilityScope::org_only(),
            generic: false,
            max_edges_per_org: 0,
            max_live_edges_per_node: 0,
            cycle_bounds: CycleCheckPolicy::for_import(),
        },
    )?;
    Ok(None)
}

/// `goals.v3.serves_goal_graph`: copy every default-organization
/// `task_goal_links` row into the graph ([`import_legacy_link`], `source_ref`
/// `import:task_goal_links:<task_id>`, `valid_from` the row's `linked_at`)
/// and install `task_goal_links_default_frozen` and
/// `task_goal_links_default_frozen_update`, which refuse a new or changed
/// default-organization row. The part deletes no row; a skipped row stays in
/// the old table, where it is served to no one (its task or goal is not the
/// default organization's) or hidden behind the task's live edge. Later,
/// `unlink` removes a task's legacy row and deleting the task cascades it.
/// The copied and skipped counts (by reason, with the skipped task ids) are
/// recorded in this part's audit SQL (`schema_procedures`) and reported by
/// `system_doctor` ([`serves_goal_migration_summary`]).
///
/// Applied after the graph parts. On a database whose `task_goal_links` has
/// no `org_id` yet (only one assembled from a subset of the parts, as an
/// upgrade test does) it copies nothing and installs nothing.
pub const SERVES_GOAL_GRAPH: Procedure =
    Procedure { name: MIGRATION_PART_NAME, version: 1, standalone: false, run: copy_legacy_links, args: &[] };

const FREEZE_SQL: &str = "
CREATE TRIGGER IF NOT EXISTS task_goal_links_default_frozen BEFORE INSERT ON task_goal_links
WHEN NEW.org_id = 'default' AND EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id = 'default')
BEGIN SELECT RAISE(ABORT, 'the default organization''s task goal links are serves_goal graph edges'); END;
CREATE TRIGGER IF NOT EXISTS task_goal_links_default_frozen_update
BEFORE UPDATE OF task_id, goal_id, linked_by, linked_at ON task_goal_links
WHEN OLD.org_id = 'default' OR NEW.org_id = 'default'
BEGIN SELECT RAISE(ABORT, 'the default organization''s task goal links are serves_goal graph edges'); END;
";

/// A legacy link: task, goal, `linked_by`, `linked_at`.
type LegacyRow = (i64, i64, Option<String>, Option<String>);

fn copy_legacy_links(conn: &Connection, _: &'static [&'static str]) -> anyhow::Result<String> {
    let has_org: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('task_goal_links') WHERE name = 'org_id'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)?;
    if !has_org {
        return Ok("-- task_goal_links has no org_id: nothing copied, no trigger installed".to_string());
    }
    let rows: Vec<LegacyRow> = conn
        .prepare(
            "SELECT task_id, goal_id, CAST(linked_by AS TEXT), CAST(linked_at AS TEXT) \
             FROM task_goal_links WHERE org_id = 'default' ORDER BY task_id",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    let total = rows.len() as u64;
    let mut copied = 0u64;
    let mut skipped: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut skipped_rows: Vec<Value> = Vec::new();
    for (task_id, goal_id, by, at) in rows {
        let source_ref = format!("{LEGACY_SOURCE_PREFIX}{task_id}");
        match import_legacy_link(conn, task_id, goal_id, by.as_deref(), at.as_deref(), &source_ref)? {
            None => copied += 1,
            Some(reason) => {
                *skipped.entry(reason).or_default() += 1;
                // Neutral ids and the reason only.
                skipped_rows.push(json!({ "task_id": task_id, "reason": reason }));
            }
        }
    }
    conn.execute_batch(FREEZE_SQL)?;
    let skipped_total: u64 = skipped.values().sum();
    let summary = json!({
        "total": total,
        "copied": copied,
        "skipped_total": skipped_total,
        "skipped": skipped,
        "skipped_rows": skipped_rows,
    });
    Ok(format!("-- {MIGRATION_SUMMARY_PREFIX}{summary}\n{FREEZE_SQL}"))
}

/// The structured summary [`SERVES_GOAL_GRAPH`] recorded in
/// `schema_procedures`, if it ran and copied (for `system_doctor`).
pub fn serves_goal_migration_summary(conn: &Connection) -> Option<Value> {
    let sql: String = conn
        .query_row(
            "SELECT generated_sql FROM schema_procedures WHERE name = ?1",
            [MIGRATION_PART_NAME],
            |r| r.get(0),
        )
        .optional()
        .ok()??;
    sql.lines().find_map(|line| {
        line.strip_prefix(&format!("-- {MIGRATION_SUMMARY_PREFIX}"))
            .and_then(|rest| serde_json::from_str::<Value>(rest.trim()).ok())
    })
}
