//! `dependency_add`, `dependency_list`, `dependency_remove`, `lineage` and
//! `project_build`.
//!
//! C2a (`docs/graph.md`): `dependency_add`, `dependency_list` and
//! `dependency_remove` read and write `graph_edges(kind = 'depends_on')`
//! directly (default organization only until immutable principal IDs land in
//! `#2790`). The legacy `task_dependencies` table is migrated once by
//! [`DEPENDS_ON_GRAPH_PART`] (`tasks.v3.depends_on_graph`) and frozen
//! read-only by write-blocking triggers.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{Caller, DEFAULT_ORG, UaError, UaResult};
use ua_graph::{
    AssertEdgeRequest, AssertedByKind, CycleCheckPolicy, EdgeKind, EdgeState, EnsureNodeRequest, NodeKind,
    PrincipalId, Provenance, RetractEdgeRequest, SourceKind, Visibility, normalize_timestamp,
};
use ua_org::authz::human;
use ua_store::graph::{GraphRepo, MigrationGraph, VisibilityScope};
use ua_store::{EventInput, Procedure, WriteTx, ledger};

use super::*;
use crate::registry::{Registry, ToolCtx, tool};

const MIGRATION_PART_NAME: &str = "tasks.v3.depends_on_graph";
const MIGRATION_SUMMARY_PREFIX: &str = "tasks.v3.depends_on_graph summary: ";

const DEPENDS_ON_INDEX_SQL: &str = "\
CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_edges_depends_on_dep_id
    ON graph_edges (json_extract(meta_json, '$.dependency_id'))
    WHERE kind = 'depends_on' AND json_extract(meta_json, '$.dependency_id') IS NOT NULL;";

const TASK_DEPENDENCIES_FREEZE_SQL: &str = "\
CREATE TRIGGER IF NOT EXISTS task_dependencies_frozen_insert
BEFORE INSERT ON task_dependencies
BEGIN
    SELECT RAISE(ABORT, 'task_dependencies is frozen read-only; use graph_edges (depends_on)');
END;
CREATE TRIGGER IF NOT EXISTS task_dependencies_frozen_update
BEFORE UPDATE ON task_dependencies
BEGIN
    SELECT RAISE(ABORT, 'task_dependencies is frozen read-only; use graph_edges (depends_on)');
END;
CREATE TRIGGER IF NOT EXISTS task_dependencies_frozen_delete
BEFORE DELETE ON task_dependencies
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = OLD.task_id)
  AND EXISTS (SELECT 1 FROM tasks WHERE id = OLD.depends_on_task_id)
BEGIN
    SELECT RAISE(ABORT, 'task_dependencies is frozen read-only; use graph_edges (depends_on)');
END;";

/// `tasks.v3.depends_on_graph` (C2a): additive migration that copies existing
/// default-organization `task_dependencies` rows into
/// `graph_edges(kind = 'depends_on')` (with task nodes ensured via
/// [`ua_graph::graph_node_ensure`] and provenance `source_kind = 'import'`),
/// installs the unique partial index on `dependency_id`, and freezes
/// `task_dependencies` read-only with triggers that block new writes, edits,
/// and direct deletes while permitting `ON DELETE CASCADE` when a parent
/// `tasks` row is deleted.
///
/// Every copied and skipped row (with reason and row id) is counted and
/// recorded atomically in `schema_procedures.generated_sql` and surfaced by
/// `system_doctor` (`docs/organization.md`, item 11; `docs/graph.md`).
/// Non-default-organization rows are skipped (`non_default_org`) and remain
/// intact in the frozen table until `#2790` lands.
pub const DEPENDS_ON_GRAPH_PART: Procedure = Procedure {
    name: MIGRATION_PART_NAME,
    version: 1,
    standalone: false,
    run: migrate_task_dependencies_to_graph,
    args: &["task_dependencies", "graph_edges"],
};

/// Parse the structured migration summary recorded by
/// [`DEPENDS_ON_GRAPH_PART`] in `schema_procedures`, if present.
pub fn depends_on_migration_summary(conn: &Connection) -> Option<Value> {
    let sql: String = conn
        .query_row(
            "SELECT generated_sql FROM schema_procedures WHERE name = ?1",
            [MIGRATION_PART_NAME],
            |r| r.get(0),
        )
        .optional()
        .ok()??;
    for line in sql.lines() {
        if let Some(rest) = line.strip_prefix(&format!("-- {MIGRATION_SUMMARY_PREFIX}"))
            && let Ok(v) = serde_json::from_str::<Value>(rest.trim())
        {
            return Some(v);
        }
    }
    None
}

fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn creator_principal_for_import(raw: &str) -> Result<(PrincipalId, AssertedByKind), &'static str> {
    let trimmed = raw.trim();
    if trimmed == "system" {
        return Ok((PrincipalId::system(), AssertedByKind::System));
    }
    PrincipalId::new(trimmed).map(|p| (p, AssertedByKind::Agent)).map_err(|_| "invalid_creator")
}

fn creator_principal_for_caller(caller: &Caller, by: &str) -> UaResult<(PrincipalId, AssertedByKind)> {
    let principal = PrincipalId::new(by)?;
    let kind = if human(caller) { AssertedByKind::Person } else { AssertedByKind::Agent };
    Ok((principal, kind))
}

fn non_default_org_refusal(tool_name: &str, org: &str) -> UaError {
    UaError::denied(
        "principal_id_required",
        format!(
            "{tool_name} in non-default organization {org:?} is refused until immutable principal IDs (#2790) land"
        ),
    )
}

fn ensure_task_node<R: GraphRepo>(
    repo: &mut R,
    org_id: &str,
    task_id: i64,
    title: Option<&str>,
    provenance: Provenance,
    max_nodes_per_org: u64,
) -> UaResult<(ua_store::graph::GraphNodeRow, bool)> {
    ua_graph::graph_node_ensure(
        repo,
        EnsureNodeRequest {
            org_id: org_id.to_string(),
            kind: NodeKind::Task,
            external_id: task_id.to_string(),
            display_label: title.map(|t| truncate_utf8(t, 256)),
            visibility: Visibility::Org,
            team_id: None,
            owner_type: None,
            owner_id: None,
            provenance,
            meta_json: None,
            max_nodes_per_org,
        },
    )
}

fn live_depends_on_edge_id(
    conn: &Connection,
    org: &str,
    src_node_id: &str,
    dst_node_id: &str,
) -> UaResult<Option<i64>> {
    Ok(conn
        .query_row(
            "SELECT COALESCE(json_extract(meta_json, '$.dependency_id'), rowid) \
             FROM graph_edges \
             WHERE org_id = ?1 AND src_id = ?2 AND dst_id = ?3 \
               AND kind = 'depends_on' AND assertion_scope = '' AND valid_to IS NULL",
            params![org, src_node_id, dst_node_id],
            |r| r.get(0),
        )
        .optional()?)
}

fn next_dependency_id(conn: &Connection) -> UaResult<i64> {
    let max_id: i64 = conn.query_row(
        "SELECT MAX(v) FROM ( \
             SELECT COALESCE(MAX(id), 0) AS v FROM task_dependencies \
             UNION ALL \
             SELECT COALESCE(MAX(json_extract(meta_json, '$.dependency_id')), 0) AS v \
             FROM graph_edges \
             WHERE kind = 'depends_on' AND json_extract(meta_json, '$.dependency_id') IS NOT NULL \
         )",
        [],
        |r| r.get(0),
    )?;
    Ok(max_id + 1)
}

/// Copy one legacy `task_dependencies` row into `graph_edges(kind = 'depends_on')`
/// inside an existing migration or `ua-import` transaction (no ledger append).
///
/// Returns `Ok(Ok(nodes_created))` when copied, or `Ok(Err(skip_reason))` when
/// the row cannot be represented in `graph_edges` and should be counted as
/// skipped.
fn copy_dependency_row_import(
    conn: &Connection,
    dep_id: i64,
    org_id: &str,
    task_id: i64,
    depends_on_task_id: i64,
    created_by: &str,
    created_at: &str,
) -> UaResult<Result<u64, &'static str>> {
    if org_id != DEFAULT_ORG {
        return Ok(Err("non_default_org"));
    }
    if task_id == depends_on_task_id {
        return Ok(Err("self_loop"));
    }
    let src_title: Option<String> = conn
        .query_row(
            "SELECT title FROM tasks WHERE org_id = ?1 AND id = ?2",
            params![DEFAULT_ORG, task_id],
            |r| r.get(0),
        )
        .optional()?;
    let dst_title: Option<String> = conn
        .query_row(
            "SELECT title FROM tasks WHERE org_id = ?1 AND id = ?2",
            params![DEFAULT_ORG, depends_on_task_id],
            |r| r.get(0),
        )
        .optional()?;
    let (Some(src_title), Some(dst_title)) = (src_title, dst_title) else {
        return Ok(Err("missing_task"));
    };
    let (creator, creator_kind) = match creator_principal_for_import(created_by) {
        Ok(pair) => pair,
        Err(reason) => return Ok(Err(reason)),
    };

    let mut repo = MigrationGraph::new(conn);
    let mut nodes_created = 0u64;
    let (src_node, created_src) = ensure_task_node(
        &mut repo,
        DEFAULT_ORG,
        task_id,
        Some(&src_title),
        Provenance {
            asserted_by: PrincipalId::system(),
            asserted_by_kind: AssertedByKind::System,
            source_kind: SourceKind::Import,
            source_ref: format!("import:task_dependencies:task:{task_id}"),
        },
        0,
    )?;
    if created_src {
        nodes_created += 1;
    }
    let (dst_node, created_dst) = ensure_task_node(
        &mut repo,
        DEFAULT_ORG,
        depends_on_task_id,
        Some(&dst_title),
        Provenance {
            asserted_by: PrincipalId::system(),
            asserted_by_kind: AssertedByKind::System,
            source_kind: SourceKind::Import,
            source_ref: format!("import:task_dependencies:task:{depends_on_task_id}"),
        },
        0,
    )?;
    if created_dst {
        nodes_created += 1;
    }

    if live_depends_on_edge_id(conn, DEFAULT_ORG, &src_node.id, &dst_node.id)?.is_some() {
        return Ok(Err("already_exists"));
    }

    let now_str = now();
    let (valid_from, meta_json) = match normalize_timestamp(created_at, "valid_from") {
        Ok(ts) if ts <= now_str => (Some(ts), json!({ "dependency_id": dep_id })),
        _ => (None, json!({ "dependency_id": dep_id, "legacy_created_at": created_at })),
    };

    let req = AssertEdgeRequest {
        org_id: DEFAULT_ORG.to_string(),
        src_id: src_node.id,
        dst_id: dst_node.id,
        kind: EdgeKind::DependsOn,
        assertion_scope: String::new(),
        state: EdgeState::Active,
        weight: 1.0,
        provenance: Provenance {
            asserted_by: creator,
            asserted_by_kind: creator_kind,
            source_kind: SourceKind::Import,
            source_ref: format!("import:task_dependencies:{dep_id}"),
        },
        valid_from,
        valid_to: None,
        meta_json: Some(meta_json),
        scope: VisibilityScope::org_only(),
        generic: false,
        max_edges_per_org: 0,
        max_live_edges_per_node: 0,
        cycle_bounds: CycleCheckPolicy::default(),
    };
    match ua_graph::assert_edge(&mut repo, req) {
        Ok(_) => Ok(Ok(nodes_created)),
        Err(err) => {
            let reason = match err.reason_code() {
                Some("cycle_detected") => "cycle_detected",
                Some("cycle_check_bound_exceeded") => "cycle_check_bound_exceeded",
                _ => "insert_failed",
            };
            Ok(Err(reason))
        }
    }
}

/// Import one Python-hub `task_dependencies` row into
/// `graph_edges(kind = 'depends_on')` (used by `ua-import`, because
/// `task_dependencies` is frozen read-only on C2a databases).
///
/// Returns `Ok(None)` when copied, or `Ok(Some(reason))` when skipped.
pub fn import_task_dependency(
    conn: &Connection,
    dep_id: i64,
    task_id: i64,
    depends_on_task_id: i64,
    created_by: &str,
    created_at: &str,
) -> UaResult<Option<&'static str>> {
    match copy_dependency_row_import(
        conn,
        dep_id,
        DEFAULT_ORG,
        task_id,
        depends_on_task_id,
        created_by,
        created_at,
    )? {
        Ok(_) => Ok(None),
        Err(reason) => Ok(Some(reason)),
    }
}

fn migrate_task_dependencies_to_graph(
    conn: &Connection,
    _args: &'static [&'static str],
) -> anyhow::Result<String> {
    conn.execute_batch(DEPENDS_ON_INDEX_SQL)?;

    let rows: Vec<(i64, String, i64, i64, String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT id, org_id, task_id, depends_on_task_id, created_by, created_at \
             FROM task_dependencies ORDER BY id ASC",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
            .collect::<Result<_, _>>()?
    };

    let total = rows.len() as u64;
    let mut copied = 0u64;
    let mut nodes_ensured = 0u64;
    let mut skipped_by_reason: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut skipped_rows: Vec<Value> = Vec::new();

    for (id, org_id, task_id, depends_on_task_id, created_by, created_at) in rows {
        match copy_dependency_row_import(
            conn,
            id,
            &org_id,
            task_id,
            depends_on_task_id,
            &created_by,
            &created_at,
        )? {
            Ok(n) => {
                copied += 1;
                nodes_ensured += n;
            }
            Err(reason) => {
                *skipped_by_reason.entry(reason).or_default() += 1;
                // Record neutral row id and reason only (no foreign org_id or label text).
                skipped_rows.push(json!({ "id": id, "reason": reason }));
            }
        }
    }

    conn.execute_batch(TASK_DEPENDENCIES_FREEZE_SQL)?;

    let skipped_total: u64 = skipped_by_reason.values().sum();
    let summary = json!({
        "total": total,
        "copied": copied,
        "skipped_total": skipped_total,
        "skipped": skipped_by_reason,
        "skipped_rows": skipped_rows,
        "nodes_ensured": nodes_ensured,
    });

    Ok(format!(
        "-- {MIGRATION_SUMMARY_PREFIX}{summary}\n{DEPENDS_ON_INDEX_SQL}\n{TASK_DEPENDENCIES_FREEZE_SQL}"
    ))
}

/// Close (retract with `valid_to = now`) every live `depends_on` edge in `org`
/// incident to any task in `subtree`. Called from `task_delete` inside the
/// same write transaction before `DELETE FROM tasks`.
pub(crate) fn retract_task_dependencies_for_subtree(
    tx: &mut WriteTx<'_>,
    org: &str,
    subtree: &[i64],
) -> UaResult<()> {
    if subtree.is_empty() {
        return Ok(());
    }
    let ids_json = serde_json::to_string(subtree)?;
    let edge_ids: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT DISTINCT e.id \
             FROM graph_edges e \
             JOIN graph_nodes n ON n.org_id = e.org_id AND n.kind = 'task' \
               AND (n.id = e.src_id OR n.id = e.dst_id) \
             WHERE e.org_id = ?1 \
               AND e.kind = 'depends_on' \
               AND e.valid_to IS NULL \
               AND n.external_id IN (SELECT CAST(value AS TEXT) FROM json_each(?2)) \
             ORDER BY e.id ASC",
        )?;
        stmt.query_map(params![org, ids_json], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    for edge_id in edge_ids {
        ua_graph::retract_edge(
            tx,
            RetractEdgeRequest {
                org_id: org.to_string(),
                edge_id,
                retractor: PrincipalId::system(),
                retractor_kind: AssertedByKind::System,
                valid_to: None,
                generic: false,
            },
        )?;
    }
    Ok(())
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DepListArgs {
    /// Page size, 1-2000 (default 500).
    pub limit: Option<i64>,
    /// Only this task's prerequisite edges.
    pub task_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DepAddArgs {
    /// The dependent task.
    pub task_id: i64,
    /// The prerequisite it waits on.
    pub depends_on_task_id: i64,
    /// Acting agent. A verified caller may only act as itself.
    pub agent: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DepRemoveArgs {
    /// Edge id from `dependency_list`.
    pub dependency_id: i64,
    /// Acting agent. Only the edge's creator may remove it.
    pub agent: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LineageArgs {
    /// Task id. Unknown ids return `{empty: true}`, not an error.
    pub task_id: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectBuildArgs {
    /// The `[project-spec]` task that becomes the project root.
    pub parent_task_id: i64,
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "dependency_list",
            "List explicit task prerequisite edges ordered by edge id. Returns {dependencies, truncated}.",
            |ctx: ToolCtx, a: DepListArgs| async move {
                let org = ctx.caller.org_id.clone();
                ctx.hub.db().read_async(move |c| dep_list(c, &org, a)).await
            },
        )
        .family("tasks")
        .read_only(),
    );
    r.add(
        tool(
            "dependency_add",
            "Add a prerequisite edge (task_id waits on depends_on_task_id). Refuses self-links, duplicates \
             and cycles. Returns {dependency}.",
            |ctx: ToolCtx, a: DepAddArgs| async move { dep_add(ctx, a).await },
        )
        .family("tasks"),
    );
    r.add(
        tool(
            "dependency_remove",
            "Remove a prerequisite edge; only its creator may. Returns {removed, dependency_id}.",
            |ctx: ToolCtx, a: DepRemoveArgs| async move { dep_remove(ctx, a).await },
        )
        .family("tasks"),
    );
    r.add(
        tool(
            "lineage",
            "Per-task execution lineage: delegations, dispatch runs, autonomous cycles and refs \
             (pr_url, worktree_path, branch). Unknown tasks return {empty: true}.",
            |ctx: ToolCtx, a: LineageArgs| async move {
                let org = ctx.caller.org_id.clone();
                ctx.hub.db().read_async(move |c| lineage(c, &org, a)).await
            },
        )
        .family("tasks")
        .read_only(),
    );
    r.add(
        tool(
            "project_build",
            "Register a [project-spec] task as a project root (project_id equals its id) and record \
             agent.project.built. Creates no child tasks. Returns {project_id, parent_task_id, identity, event_ulid}.",
            |ctx: ToolCtx, a: ProjectBuildArgs| async move { project_build(ctx, a).await },
        )
        .family("tasks"),
    );
}

fn dep_list(conn: &Connection, org: &str, a: DepListArgs) -> UaResult<Value> {
    let limit = a.limit.unwrap_or(500).clamp(1, 2000);
    let mut stmt = conn.prepare(
        "SELECT COALESCE(json_extract(e.meta_json, '$.dependency_id'), e.rowid) AS id, \
                CAST(src.external_id AS INTEGER) AS task_id, \
                CAST(dst.external_id AS INTEGER) AS depends_on_task_id, \
                e.asserted_by AS created_by, \
                COALESCE(json_extract(e.meta_json, '$.legacy_created_at'), e.valid_from) AS created_at \
         FROM graph_edges e \
         JOIN graph_nodes src ON src.org_id = e.org_id AND src.id = e.src_id AND src.kind = 'task' \
         JOIN graph_nodes dst ON dst.org_id = e.org_id AND dst.id = e.dst_id AND dst.kind = 'task' \
         WHERE e.org_id = ?3 \
           AND e.kind = 'depends_on' \
           AND e.state = 'active' \
           AND e.valid_to IS NULL \
           AND (?1 IS NULL OR src.external_id = CAST(?1 AS TEXT)) \
         ORDER BY id ASC \
         LIMIT ?2",
    )?;
    let mut rows: Vec<Map<String, Value>> =
        stmt.query_map(params![a.task_id, limit + 1, org], row_object)?.collect::<Result<_, _>>()?;
    let truncated = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    Ok(json!({ "dependencies": rows, "truncated": truncated }))
}

async fn dep_add(ctx: ToolCtx, a: DepAddArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    if org != DEFAULT_ORG {
        return Err(non_default_org_refusal("dependency_add", &org));
    }
    let by = acting_identity(&ctx.caller, a.agent.as_deref())?;
    let (principal, asserted_by_kind) = creator_principal_for_caller(&ctx.caller, &by)?;
    if a.task_id == a.depends_on_task_id {
        return Err(UaError::invalid("a task cannot depend on itself"));
    }
    let max_nodes_per_org = ctx.hub.cfg().graph_max_nodes_per_org;
    let max_edges_per_org = ctx.hub.cfg().graph_max_edges_per_org;
    let max_live_edges_per_node = ctx.hub.cfg().graph_max_live_edges_per_node;
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let src_task = require_task(tx, &org, a.task_id)?;
            let dst_task = require_task(tx, &org, a.depends_on_task_id)?;

            let node_prov = Provenance {
                asserted_by: principal.clone(),
                asserted_by_kind,
                source_kind: SourceKind::Event,
                source_ref: "tool:dependency_add".to_string(),
            };
            let (src_node, _) = ensure_task_node(
                tx,
                &org,
                a.task_id,
                str_field(&src_task, "title"),
                node_prov.clone(),
                max_nodes_per_org,
            )?;
            let (dst_node, _) = ensure_task_node(
                tx,
                &org,
                a.depends_on_task_id,
                str_field(&dst_task, "title"),
                node_prov,
                max_nodes_per_org,
            )?;

            if let Some(existing_id) = live_depends_on_edge_id(tx, &org, &src_node.id, &dst_node.id)? {
                return Err(UaError::conflict(format!("dependency already exists (id {existing_id})")));
            }

            let dep_id = next_dependency_id(tx)?;
            let edge = ua_graph::assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: org.clone(),
                    src_id: src_node.id,
                    dst_id: dst_node.id,
                    kind: EdgeKind::DependsOn,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: Provenance {
                        asserted_by: principal,
                        asserted_by_kind,
                        source_kind: SourceKind::Event,
                        source_ref: "tool:dependency_add".to_string(),
                    },
                    valid_from: None,
                    valid_to: None,
                    meta_json: Some(json!({ "dependency_id": dep_id })),
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org,
                    max_live_edges_per_node,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;

            emit(
                tx,
                &org,
                "agent.task.dependency_added",
                json!({ "dependency_id": dep_id, "task_id": a.task_id, "depends_on_task_id": a.depends_on_task_id }),
                &by,
            )?;
            Ok(json!({
                "dependency": {
                    "id": dep_id,
                    "task_id": a.task_id,
                    "depends_on_task_id": a.depends_on_task_id,
                    "created_by": edge.asserted_by,
                    "created_at": edge.valid_from,
                }
            }))
        })
        .await
}

async fn dep_remove(ctx: ToolCtx, a: DepRemoveArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    if org != DEFAULT_ORG {
        return Err(non_default_org_refusal("dependency_remove", &org));
    }
    let by = acting_identity(&ctx.caller, a.agent.as_deref())?;
    let (retractor, retractor_kind) = creator_principal_for_caller(&ctx.caller, &by)?;
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let found: Option<(String, i64, i64, String)> = tx
                .query_row(
                    "SELECT e.id, \
                            CAST(src.external_id AS INTEGER), \
                            CAST(dst.external_id AS INTEGER), \
                            e.asserted_by \
                     FROM graph_edges e \
                     JOIN graph_nodes src ON src.org_id = e.org_id AND src.id = e.src_id AND src.kind = 'task' \
                     JOIN graph_nodes dst ON dst.org_id = e.org_id AND dst.id = e.dst_id AND dst.kind = 'task' \
                     WHERE e.org_id = ?1 \
                       AND e.kind = 'depends_on' \
                       AND e.state = 'active' \
                       AND e.valid_to IS NULL \
                       AND COALESCE(json_extract(e.meta_json, '$.dependency_id'), e.rowid) = ?2",
                    params![org, a.dependency_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let (edge_id, task_id, depends_on_task_id, created_by) = found
                .ok_or_else(|| UaError::not_found(format!("no dependency with id {}", a.dependency_id)))?;
            if created_by != by {
                return Err(UaError::denied(
                    "not_dependency_creator",
                    "only the dependency creator may remove this edge",
                ));
            }
            ua_graph::retract_edge(
                tx,
                RetractEdgeRequest {
                    org_id: org.clone(),
                    edge_id,
                    retractor,
                    retractor_kind,
                    valid_to: None,
                    generic: false,
                },
            )?;
            emit(
                tx,
                &org,
                "agent.task.dependency_removed",
                json!({
                    "dependency_id": a.dependency_id,
                    "task_id": task_id,
                    "depends_on_task_id": depends_on_task_id,
                }),
                &by,
            )?;
            Ok(json!({ "removed": true, "dependency_id": a.dependency_id }))
        })
        .await
}

fn lineage(conn: &Connection, org: &str, a: LineageArgs) -> UaResult<Value> {
    let row = task_object(conn, org, a.task_id)?;
    let get = |k: &str| row.as_ref().and_then(|r| str_field(r, k)).map(String::from);
    let worktree_path = get("worktree_path");
    let branch = get("branch");
    let pr_url = get("evidence_ref").filter(|e| e.starts_with("http"));
    let empty = worktree_path.is_none() && branch.is_none() && pr_url.is_none();
    Ok(json!({
        "task": { "id": a.task_id, "title": get("title") },
        "lineage": {
            "delegations": [],
            "dispatch_runs": [],
            "autonomous_cycles": [],
            "refs": { "pr_url": pr_url, "worktree_path": worktree_path, "branch": branch },
        },
        "empty": empty,
    }))
}

async fn project_build(ctx: ToolCtx, a: ProjectBuildArgs) -> UaResult<Value> {
    if !is_verified(&ctx.caller) {
        return Err(UaError::denied(
            "unverified_identity",
            "project_build requires a verified agent identity",
        ));
    }
    let identity = ctx.caller.label.clone();
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let id = a.parent_task_id;
            let row = require_task(tx, &org, id)?;
            if !has_marker(str_field(&row, "notes").unwrap_or_default(), PROJECT_SPEC_MARKER) {
                return Err(UaError::invalid(format!("task {id} does not carry {PROJECT_SPEC_MARKER}")));
            }
            if let Some(holder) = str_field(&row, "claimed_by").map(str::trim).filter(|s| !s.is_empty())
                && holder != identity
            {
                return Err(UaError::conflict(format!("task {id} is claimed by {holder}, not {identity}")));
            }
            // ORG-EVENT-DEFAULT: as `emit`, another organization's event
            // carries no label and a neutral originator.
            let by = if org == ua_core::DEFAULT_ORG { identity.clone() } else { "system".to_string() };
            let event = ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "agent.project.built",
                    json!({ "parent_task_id": id, "project_id": id, "identity": ledger_text(&org, &identity) }),
                )
                .by(by),
            )?;
            Ok(json!({
                "project_id": id,
                "parent_task_id": id,
                "identity": identity,
                "event_ulid": event.map(|e| e.ulid),
            }))
        })
        .await
}
