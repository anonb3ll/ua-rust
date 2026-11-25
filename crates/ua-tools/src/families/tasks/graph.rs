//! `dependency_add`, `dependency_list`, `dependency_remove`, `lineage` and
//! `project_build`.

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use super::*;
use crate::registry::{Registry, ToolCtx, tool};

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

/// Dependency `id` of organization `org`; another organization's edge
/// answers as a missing one.
fn edge(conn: &Connection, org: &str, id: i64) -> UaResult<Option<Map<String, Value>>> {
    Ok(conn
        .query_row(
            "SELECT id, task_id, depends_on_task_id, created_by, created_at FROM task_dependencies \
             WHERE org_id = ?1 AND id = ?2",
            params![org, id],
            row_object,
        )
        .optional()?)
}

fn dep_list(conn: &Connection, org: &str, a: DepListArgs) -> UaResult<Value> {
    let limit = a.limit.unwrap_or(500).clamp(1, 2000);
    let mut stmt = conn.prepare(
        "SELECT id, task_id, depends_on_task_id, created_by, created_at FROM task_dependencies \
         WHERE org_id = ?3 AND (?1 IS NULL OR task_id = ?1) ORDER BY id LIMIT ?2",
    )?;
    let mut rows: Vec<Map<String, Value>> =
        stmt.query_map(params![a.task_id, limit + 1, org], row_object)?.collect::<Result<_, _>>()?;
    let truncated = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    Ok(json!({ "dependencies": rows, "truncated": truncated }))
}

async fn dep_add(ctx: ToolCtx, a: DepAddArgs) -> UaResult<Value> {
    let by = acting_identity(&ctx.caller, a.agent.as_deref())?;
    if a.task_id == a.depends_on_task_id {
        return Err(UaError::invalid("a task cannot depend on itself"));
    }
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            require_task(tx, &org, a.task_id)?;
            require_task(tx, &org, a.depends_on_task_id)?;
            // A cycle exists when the prerequisite already (transitively) waits on the dependent.
            let cycle: Option<i64> = tx
                .query_row(
                    "WITH RECURSIVE reachable(id) AS (
                        SELECT depends_on_task_id FROM task_dependencies WHERE org_id = ?3 AND task_id = ?1
                        UNION
                        SELECT d.depends_on_task_id FROM task_dependencies d JOIN reachable r ON d.task_id = r.id
                        WHERE d.org_id = ?3
                    ) SELECT 1 FROM reachable WHERE id = ?2 LIMIT 1",
                    params![a.depends_on_task_id, a.task_id, org],
                    |r| r.get(0),
                )
                .optional()?;
            if cycle.is_some() {
                return Err(UaError::invalid(format!(
                    "dependency would create a cycle: task {} already depends on task {}",
                    a.depends_on_task_id, a.task_id
                )));
            }
            let exists: Option<i64> = tx
                .query_row(
                    "SELECT id FROM task_dependencies WHERE org_id = ?3 AND task_id = ?1 AND depends_on_task_id = ?2",
                    params![a.task_id, a.depends_on_task_id, org],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(id) = exists {
                return Err(UaError::conflict(format!("dependency already exists (id {id})")));
            }
            tx.execute(
                "INSERT INTO task_dependencies (org_id, task_id, depends_on_task_id, created_by, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![org, a.task_id, a.depends_on_task_id, by, now()],
            )?;
            let id = tx.last_insert_rowid();
            emit(
                tx,
                &org,
                "agent.task.dependency_added",
                json!({ "dependency_id": id, "task_id": a.task_id, "depends_on_task_id": a.depends_on_task_id }),
                &by,
            )?;
            Ok(json!({ "dependency": edge(tx, &org, id)? }))
        })
        .await
}

async fn dep_remove(ctx: ToolCtx, a: DepRemoveArgs) -> UaResult<Value> {
    let by = acting_identity(&ctx.caller, a.agent.as_deref())?;
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let row = edge(tx, &org, a.dependency_id)?
                .ok_or_else(|| UaError::not_found(format!("no dependency with id {}", a.dependency_id)))?;
            if str_field(&row, "created_by") != Some(by.as_str()) {
                return Err(UaError::denied(
                    "not_dependency_creator",
                    "only the dependency creator may remove this edge",
                ));
            }
            tx.execute(
                "DELETE FROM task_dependencies WHERE org_id = ?1 AND id = ?2",
                params![org, a.dependency_id],
            )?;
            emit(
                tx,
                &org,
                "agent.task.dependency_removed",
                json!({ "dependency_id": a.dependency_id, "task_id": row["task_id"],
                        "depends_on_task_id": row["depends_on_task_id"] }),
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
