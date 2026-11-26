//! The single goal a task serves (`docs/graph.md`, C2 slice b).
//!
//! **Default organization:** the link is a `serves_goal` edge (task node →
//! goal node) in the shared graph store, written through `ua-graph`
//! (`graph_node_ensure`, `assert_edge`, `retract_edge`) in the caller's
//! write transaction. `idx_graph_edges_single_out_live` keeps at most one
//! live edge per task; unlinking closes the edge (`valid_to = now`) and never
//! deletes it. A default-organization `task_goal_links` row that the
//! `goals.v3.serves_goal_graph` part did not copy (none on a database that
//! applied the parts in order) is still served from the old table until it
//! is unlinked, and `task_goal_links_default_frozen` refuses every new
//! default-organization row there.
//!
//! **Every other organization:** `task_goal_links`, exactly as before,
//! until #2790 supplies immutable principal IDs. A graph write there with a
//! caller's label is refused (`principal_id_required`), and stamping
//! `'system'` would lose who linked the task.

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;
use ua_core::{Caller, DEFAULT_ORG, UaResult};
use ua_graph::{
    AssertEdgeRequest, AssertedByKind, CycleCheckPolicy, EdgeKind, EdgeState, EnsureNodeRequest, NodeKind,
    PrincipalId, Provenance, RetractEdgeRequest, SourceKind, Visibility,
};
use ua_store::graph::{AdjacencyQuery, EdgeDirection, EdgeFilter, GraphRead, SqliteGraph, VisibilityScope};
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

/// The principal a default-organization graph write records: the acting
/// label (provisional until #2790 backfills stable ids), as a person when the
/// caller is a verified human, else as an agent. A label `PrincipalId`
/// refuses (the reserved `system`, an over-long one) is recorded as the hub
/// itself rather than failing a link that worked before.
pub(crate) fn graph_actor(caller: &Caller, who: &str) -> (PrincipalId, AssertedByKind) {
    match PrincipalId::new(who) {
        Ok(p) if ua_org::authz::human(caller) => (p, AssertedByKind::Person),
        Ok(p) => (p, AssertedByKind::Agent),
        Err(_) => (PrincipalId::system(), AssertedByKind::System),
    }
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
    actor: (PrincipalId, AssertedByKind),
    caps: GraphCaps,
) -> UaResult<()> {
    if org != DEFAULT_ORG {
        tx.execute(
            "INSERT INTO task_goal_links (org_id, task_id, goal_id, linked_by, linked_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![org, task_id, goal_id, who, ua_core::time::now()],
        )?;
        return Ok(());
    }
    let provenance = Provenance {
        asserted_by: actor.0,
        asserted_by_kind: actor.1,
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
pub(crate) fn unlink(
    tx: &mut WriteTx<'_>,
    org: &str,
    task_id: i64,
    actor: (PrincipalId, AssertedByKind),
) -> UaResult<()> {
    if org == DEFAULT_ORG {
        close_live(tx, task_id, actor)?;
    }
    tx.execute("DELETE FROM task_goal_links WHERE org_id = ?1 AND task_id = ?2", params![org, task_id])?;
    Ok(())
}

/// Close the live edges of default-organization tasks that are being
/// deleted, as the old table's `ON DELETE CASCADE` removed their rows.
pub(crate) fn close_for_deleted_tasks(
    tx: &mut WriteTx<'_>,
    org: &str,
    task_ids: &[i64],
    actor: (PrincipalId, AssertedByKind),
) -> UaResult<()> {
    if org != DEFAULT_ORG {
        return Ok(());
    }
    for &id in task_ids {
        close_live(tx, id, actor.clone())?;
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

/// Copy one default-organization task→goal link into the graph as an
/// import: task and goal nodes created if absent and a live `serves_goal`
/// edge, all `asserted_by = 'system'`, `source_kind = 'import'` and
/// `source_ref = source_ref`. The edge's `valid_from` is `linked_at` when it
/// is a timestamp no later than now (an import may carry history), else now;
/// `linked_by` is kept in the edge's `meta_json`.
///
/// Writes no ledger event (a schema part cannot append to the ledger, and
/// `ua import` copies the source ledger as it is). Returns `false`, writing
/// nothing, when the task already has a live `serves_goal` edge. The caller
/// checks that the task and the goal are the default organization's.
pub fn import_legacy_link(
    conn: &Connection,
    task_id: i64,
    goal_id: i64,
    linked_by: Option<&str>,
    linked_at: Option<&str>,
    source_ref: &str,
) -> UaResult<bool> {
    let now = ua_core::time::now();
    let src = import_node(conn, NodeKind::Task, task_id, source_ref, &now)?;
    let live: Option<String> = conn
        .query_row(
            "SELECT id FROM graph_edges WHERE org_id = ?1 AND src_id = ?2 AND kind = 'serves_goal' \
             AND valid_to IS NULL",
            params![DEFAULT_ORG, src],
            |r| r.get(0),
        )
        .optional()?;
    if live.is_some() {
        return Ok(false);
    }
    let dst = import_node(conn, NodeKind::Goal, goal_id, source_ref, &now)?;
    let valid_from = linked_at
        .and_then(|t| ua_graph::normalize_timestamp(t, "linked_at").ok())
        .filter(|t| *t <= now)
        .unwrap_or_else(|| now.clone());
    let meta = match linked_by.map(str::trim).filter(|s| !s.is_empty()) {
        Some(by) => json!({ "linked_by": by }).to_string(),
        None => "{}".to_string(),
    };
    let meta = if meta.len() <= 4096 { meta } else { "{}".to_string() };
    conn.execute(
        "INSERT INTO graph_edges (id, org_id, src_id, dst_id, kind, assertion_scope, state, weight, asserted_by, \
         asserted_by_kind, asserted_at, source_kind, source_ref, valid_from, valid_to, meta_json) \
         VALUES (?1, ?2, ?3, ?4, 'serves_goal', '', 'active', 1.0, 'system', 'system', ?5, 'import', ?6, ?7, NULL, ?8)",
        params![ulid::Ulid::generate().to_string(), DEFAULT_ORG, src, dst, now, source_ref, valid_from, meta],
    )?;
    Ok(true)
}

/// The id of the default organization's `kind` node for `id`, created as an
/// import when absent.
fn import_node(conn: &Connection, kind: NodeKind, id: i64, source_ref: &str, now: &str) -> UaResult<String> {
    let ext = id.to_string();
    let found: Option<String> = conn
        .query_row(
            "SELECT id FROM graph_nodes WHERE org_id = ?1 AND kind = ?2 AND external_id = ?3",
            params![DEFAULT_ORG, kind.as_str(), ext],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(found) = found {
        return Ok(found);
    }
    let node = ulid::Ulid::generate().to_string();
    conn.execute(
        "INSERT INTO graph_nodes (id, org_id, kind, external_id, display_label, visibility, team_id, owner_type, \
         owner_id, asserted_by, asserted_by_kind, source_kind, source_ref, meta_json, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, NULL, 'org', NULL, NULL, NULL, 'system', 'system', 'import', ?5, '{}', ?6, ?6)",
        params![node, DEFAULT_ORG, kind.as_str(), ext, source_ref, now],
    )?;
    Ok(node)
}

/// `goals.v3.serves_goal_graph`: copy every default-organization
/// `task_goal_links` row into the graph ([`import_legacy_link`], `source_ref`
/// `import:task_goal_links:<task_id>`, `valid_from` the row's `linked_at`)
/// and install `task_goal_links_default_frozen` and
/// `task_goal_links_default_frozen_update`, which refuse a new or changed
/// default-organization row. Rows stay in the old table (nothing is dropped);
/// a row is skipped, and stays there and served, when its task or goal is not
/// the default organization's or its task already has a live edge. The
/// counts are recorded in this part's audit SQL (`schema_procedures`) and
/// reported by `system_doctor` ([`legacy_link_counts`]).
///
/// Applied after the graph parts. On a database whose `task_goal_links` has
/// no `org_id` yet (only one assembled from a subset of the parts, as an
/// upgrade test does) it copies nothing and installs nothing.
pub const SERVES_GOAL_GRAPH: Procedure = Procedure {
    name: "goals.v3.serves_goal_graph",
    version: 1,
    standalone: false,
    run: copy_legacy_links,
    args: &[],
};

const FREEZE_SQL: &str = "
CREATE TRIGGER IF NOT EXISTS task_goal_links_default_frozen BEFORE INSERT ON task_goal_links
WHEN NEW.org_id = 'default' AND EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id = 'default')
BEGIN SELECT RAISE(ABORT, 'the default organization''s task goal links are serves_goal graph edges'); END;
CREATE TRIGGER IF NOT EXISTS task_goal_links_default_frozen_update
BEFORE UPDATE OF task_id, goal_id, linked_by, linked_at ON task_goal_links
WHEN OLD.org_id = 'default' OR NEW.org_id = 'default'
BEGIN SELECT RAISE(ABORT, 'the default organization''s task goal links are serves_goal graph edges'); END;
";

/// A legacy link: task, goal, `linked_by`, `linked_at`, and whether its
/// task and goal are both in the row's (default) organization.
type LegacyRow = (i64, i64, Option<String>, Option<String>, bool);

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
            "SELECT l.task_id, l.goal_id, CAST(l.linked_by AS TEXT), CAST(l.linked_at AS TEXT), \
                    EXISTS (SELECT 1 FROM tasks t WHERE t.id = l.task_id AND t.org_id = l.org_id) \
                    AND EXISTS (SELECT 1 FROM goals g WHERE g.id = l.goal_id AND g.org_id = l.org_id) \
             FROM task_goal_links l WHERE l.org_id = 'default' ORDER BY l.task_id",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
        .collect::<Result<_, _>>()?;
    let (mut copied, mut skipped) = (0u64, 0u64);
    for (task_id, goal_id, by, at, same_org) in rows {
        let source_ref = format!("{LEGACY_SOURCE_PREFIX}{task_id}");
        if same_org && import_legacy_link(conn, task_id, goal_id, by.as_deref(), at.as_deref(), &source_ref)?
        {
            copied += 1;
        } else {
            skipped += 1;
        }
    }
    conn.execute_batch(FREEZE_SQL)?;
    Ok(format!(
        "-- copy each default task_goal_links row into graph_nodes/graph_edges (serves_goal, source_kind import, \
         source_ref {LEGACY_SOURCE_PREFIX}<task_id>)\n-- task_goal_links default rows: {copied} copied, {skipped} \
         skipped\n{FREEZE_SQL}"
    ))
}

/// `(copied, not copied)`: the default organization's `serves_goal` edges
/// [`SERVES_GOAL_GRAPH`] copied, and its `task_goal_links` rows still served
/// from the old table because they were not. Hub-wide; for `system_doctor`.
pub(crate) fn legacy_link_counts(c: &Connection) -> rusqlite::Result<(i64, i64)> {
    let copied = c.query_row(
        "SELECT COUNT(*) FROM graph_edges WHERE org_id = 'default' AND kind = 'serves_goal' \
         AND source_kind = 'import' AND substr(source_ref, 1, ?2) = ?1",
        params![LEGACY_SOURCE_PREFIX, LEGACY_SOURCE_PREFIX.len() as i64],
        |r| r.get(0),
    )?;
    let pending = c.query_row(
        "SELECT COUNT(*) FROM task_goal_links l WHERE l.org_id = 'default' AND NOT EXISTS ( \
           SELECT 1 FROM graph_edges e WHERE e.org_id = 'default' AND e.source_kind = 'import' \
           AND e.source_ref = ?1 || l.task_id)",
        [LEGACY_SOURCE_PREFIX],
        |r| r.get(0),
    )?;
    Ok((copied, pending))
}
