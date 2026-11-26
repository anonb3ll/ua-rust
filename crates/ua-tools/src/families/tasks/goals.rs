//! `goal_manage(action, params)`: goals as a why-chain.
//!
//! `parent_goal_id` is why-ancestry (root first). The single goal a task
//! serves is a `serves_goal` graph edge in the default organization and a
//! `task_goal_links` row in any other ([`super::goal_links`]). Neither is
//! `tasks.parent_id` nesting nor the `task_dependencies` prerequisite graph.

use std::collections::{BTreeMap, HashSet};

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};

use super::goal_links::{self, GraphCaps};
use super::*;
use crate::registry::{Registry, ToolCtx, tool};

const MAX_GOAL_DEPTH: usize = 8;
const GOAL_STATUSES: [&str; 3] = ["open", "achieved", "abandoned"];
const CLOSED: [&str; 2] = ["achieved", "abandoned"];
const EDGE_ANCESTRY: &str = "goal_ancestry";
const EDGE_TASK: &str = "goal_task";
const MEANING: &str = "goal_ancestry is why (root first). goal_task is the goal a task serves. \
task_dependency (dependency_add) is the prerequisite DAG. tasks.parent_id is decomposition nesting. \
These are different edges.";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoalArgs {
    /// `add`, `list`, `tree`, `get`, `link`, `unlink`, `edit`, `close`,
    /// `reopen` or `ancestry`.
    pub action: String,
    /// Action arguments. add: `title`, `statement?`, `parent_goal_id?`,
    /// `project?`, `author?`. list/tree: `project?`. get: `goal_id`.
    /// link/unlink: `task_id`, `goal_id`. edit: `goal_id`, `title?`,
    /// `statement?`. close: `goal_id`, `status?` (`achieved` default or
    /// `abandoned`), `reason?`. reopen: `goal_id`, `reason?`. ancestry:
    /// `task_id`. Writes take an optional `expected_revision`.
    pub params: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddParams {
    title: String,
    statement: Option<String>,
    parent_goal_id: Option<i64>,
    project: Option<String>,
    author: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectParams {
    project: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoalIdParams {
    goal_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkParams {
    task_id: i64,
    goal_id: i64,
    author: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditParams {
    goal_id: i64,
    title: Option<String>,
    statement: Option<String>,
    expected_revision: Option<i64>,
    author: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusParams {
    goal_id: i64,
    status: Option<String>,
    reason: Option<String>,
    expected_revision: Option<i64>,
    author: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskIdParams {
    task_id: i64,
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "goal_manage",
            "Goals as a why-chain. action: add, list, tree, get, link, unlink, edit, close, reopen, ancestry. \
             Linking sets the one goal a task serves; it is not a dependency and not task nesting.",
            |ctx: ToolCtx, a: GoalArgs| async move { manage(ctx, a).await },
        )
        .family("tasks"),
    );
}

fn author(ctx: &ToolCtx, claimed: Option<&str>) -> UaResult<String> {
    if is_verified(&ctx.caller) {
        Ok(ctx.caller.label.clone())
    } else {
        acting_identity(&ctx.caller, claimed)
    }
}

async fn manage(ctx: ToolCtx, a: GoalArgs) -> UaResult<Value> {
    let action = crate::routes::action_of("goal_manage", Some(&a.action))?;
    let db = ctx.hub.db().clone();
    // Every goal, link and task a goal action reads or writes is the caller's
    // organization's: another organization's goal answers as a missing one.
    // The organization comes from the caller only (`params.org_id` is an
    // unknown field and refused).
    let org = ctx.caller.org_id.clone();
    match action {
        "add" => {
            let p: AddParams = parse_params("add", a.params)?;
            let who = author(&ctx, p.author.as_deref())?;
            db.write_async(move |tx| add(tx, &org, p, &who)).await
        }
        "list" => {
            let p: ProjectParams = parse_params("list", a.params)?;
            db.read_async(move |c| {
                Ok(json!({ "goals": list(c, &org, p.project.as_deref())?, "edge": EDGE_ANCESTRY, "meaning": MEANING }))
            })
            .await
        }
        "tree" => {
            let p: ProjectParams = parse_params("tree", a.params)?;
            db.read_async(move |c| tree(c, &org, p.project.as_deref())).await
        }
        "get" => {
            let p: GoalIdParams = parse_params("get", a.params)?;
            db.read_async(move |c| detail(c, &org, p.goal_id)).await
        }
        "link" => {
            let p: LinkParams = parse_params("link", a.params)?;
            let who = author(&ctx, p.author.as_deref())?;
            let actor = goal_links::graph_actor(&ctx.caller, &who);
            let caps = GraphCaps::of(ctx.hub.cfg());
            db.write_async(move |tx| link(tx, &org, p, &who, actor, caps)).await
        }
        "unlink" => {
            let p: LinkParams = parse_params("unlink", a.params)?;
            let who = author(&ctx, p.author.as_deref())?;
            let actor = goal_links::graph_actor(&ctx.caller, &who);
            db.write_async(move |tx| unlink(tx, &org, p, &who, actor)).await
        }
        "edit" => {
            let p: EditParams = parse_params("edit", a.params)?;
            let who = author(&ctx, p.author.as_deref())?;
            db.write_async(move |tx| edit(tx, &org, p, &who)).await
        }
        "close" | "reopen" => {
            let p: StatusParams = parse_params(action, a.params)?;
            let status = if action == "reopen" {
                "open".to_string()
            } else {
                let s = p.status.clone().unwrap_or_else(|| "achieved".into());
                if !CLOSED.contains(&s.as_str()) {
                    return Err(UaError::invalid("close takes status achieved or abandoned"));
                }
                s
            };
            let who = author(&ctx, p.author.as_deref())?;
            db.write_async(move |tx| set_status(tx, &org, p, &status, &who)).await
        }
        "ancestry" => {
            let p: TaskIdParams = parse_params("ancestry", a.params)?;
            db.read_mut_async(move |c| {
                let served = match task_object(c, &org, p.task_id)? {
                    Some(_) => goal_links::served_goal_read(c, &org, p.task_id)?,
                    None => None,
                };
                why_chain(c, &org, p.task_id, served)
            })
            .await
        }
        other => Err(crate::routes::unhandled("goal_manage", other)),
    }
}

/// Goal `id` of organization `org`, without its `org_id`, or `None`. Another
/// organization's goal answers exactly as a missing one.
fn goal(conn: &Connection, org: &str, id: i64) -> UaResult<Option<Map<String, Value>>> {
    Ok(conn
        .query_row("SELECT * FROM goals WHERE org_id = ?1 AND id = ?2", params![org, id], task_row)
        .optional()?)
}

fn require_goal(conn: &Connection, org: &str, id: i64) -> UaResult<Map<String, Value>> {
    goal(conn, org, id)?.ok_or_else(|| UaError::not_found(format!("unknown goal: {id}")))
}

/// Root-first goal ids ending at `id`, all of organization `org`. Cycles and
/// over-deep chains fail closed.
fn ancestry_ids(conn: &Connection, org: &str, id: i64) -> UaResult<Vec<i64>> {
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut current = Some(id);
    while let Some(cur) = current {
        if !seen.insert(cur) {
            return Err(UaError::invalid("goal ancestry contains a cycle"));
        }
        if chain.len() >= MAX_GOAL_DEPTH {
            return Err(UaError::invalid(format!("goal ancestry is deeper than {MAX_GOAL_DEPTH}")));
        }
        let row = require_goal(conn, org, cur)?;
        chain.push(cur);
        current = int_field(&row, "parent_goal_id");
    }
    chain.reverse();
    Ok(chain)
}

fn check_title(title: &str) -> UaResult<String> {
    let t = title.trim();
    if t.is_empty() || t.contains('\n') || t.chars().count() > 200 {
        return Err(UaError::invalid("title must be one nonempty line of at most 200 characters"));
    }
    Ok(t.to_string())
}

fn check_statement(s: &str) -> UaResult<String> {
    let s = s.trim();
    if s.chars().count() > 4000 {
        return Err(UaError::invalid("statement must be at most 4000 characters"));
    }
    Ok(s.to_string())
}

fn check_revision(row: &Map<String, Value>, expected: Option<i64>) -> UaResult<()> {
    let current = int_field(row, "revision").unwrap_or(1);
    if let Some(e) = expected
        && e != current
    {
        return Err(UaError::conflict(format!(
            "goal {} changed since it was read (revision {current}, expected {e}); reload it and try again",
            row["id"]
        )));
    }
    Ok(())
}

fn goal_reply(conn: &Connection, org: &str, id: i64) -> UaResult<Value> {
    Ok(json!({ "goal": require_goal(conn, org, id)?, "edge": EDGE_ANCESTRY, "meaning": MEANING }))
}

fn add(tx: &mut ua_store::WriteTx<'_>, org: &str, p: AddParams, who: &str) -> UaResult<Value> {
    require_org(tx, org)?;
    let title = check_title(&p.title)?;
    let statement = check_statement(p.statement.as_deref().unwrap_or_default())?;
    let project = match p.project.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(proj) => check_slug("project", proj)?,
        None => "default".to_string(),
    };
    if let Some(pid) = p.parent_goal_id {
        let parent =
            goal(tx, org, pid)?.ok_or_else(|| UaError::invalid(format!("unknown parent goal: {pid}")))?;
        if str_field(&parent, "project") != Some(project.as_str()) {
            return Err(UaError::invalid("parent goal must belong to the same project"));
        }
        if ancestry_ids(tx, org, pid)?.len() >= MAX_GOAL_DEPTH {
            return Err(UaError::invalid(format!("goal ancestry is deeper than {MAX_GOAL_DEPTH}")));
        }
    }
    let ts = now();
    tx.execute(
        "INSERT INTO goals (org_id, title, statement, parent_goal_id, project, status, created_by, created_at, \
         updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6, ?7, ?7)",
        params![org, title, statement, p.parent_goal_id, project, who, ts],
    )?;
    let id = tx.last_insert_rowid();
    emit(tx, org, "agent.goal.created", json!({ "goal_id": id, "parent_goal_id": p.parent_goal_id }), who)?;
    goal_reply(tx, org, id)
}

fn list(conn: &Connection, org: &str, project: Option<&str>) -> UaResult<Vec<Map<String, Value>>> {
    let mut stmt =
        conn.prepare("SELECT * FROM goals WHERE org_id = ?1 AND (?2 IS NULL OR project = ?2) ORDER BY id")?;
    let rows = stmt.query_map(params![org, project], task_row)?.collect::<Result<_, _>>()?;
    Ok(rows)
}

fn tree(conn: &Connection, org: &str, project: Option<&str>) -> UaResult<Value> {
    let goals = list(conn, org, project)?;
    let visible: HashSet<i64> = goals.iter().filter_map(|g| int_field(g, "id")).collect();
    let mut by_parent: BTreeMap<Option<i64>, Vec<Map<String, Value>>> = BTreeMap::new();
    for g in &goals {
        let parent = int_field(g, "parent_goal_id").filter(|p| visible.contains(p));
        by_parent.entry(parent).or_default().push(g.clone());
    }
    fn nest(
        g: &Map<String, Value>,
        by_parent: &BTreeMap<Option<i64>, Vec<Map<String, Value>>>,
        placed: &mut HashSet<i64>,
    ) -> Value {
        let id = int_field(g, "id").unwrap_or_default();
        placed.insert(id);
        let mut children = Vec::new();
        for child in by_parent.get(&Some(id)).into_iter().flatten() {
            if !placed.contains(&int_field(child, "id").unwrap_or_default()) {
                children.push(nest(child, by_parent, placed));
            }
        }
        let mut out = g.clone();
        out.insert("children".into(), Value::Array(children));
        Value::Object(out)
    }
    let mut placed = HashSet::new();
    let mut roots: Vec<Value> =
        by_parent.get(&None).into_iter().flatten().map(|g| nest(g, &by_parent, &mut placed)).collect();
    for g in &goals {
        if !placed.contains(&int_field(g, "id").unwrap_or_default()) {
            roots.push(nest(g, &by_parent, &mut placed));
        }
    }
    Ok(json!({ "tree": roots, "edge": EDGE_ANCESTRY, "meaning": MEANING }))
}

fn detail(conn: &Connection, org: &str, id: i64) -> UaResult<Value> {
    let g = require_goal(conn, org, id)?;
    let chain: Vec<Map<String, Value>> = ancestry_ids(conn, org, id)?
        .into_iter()
        .map(|gid| require_goal(conn, org, gid))
        .collect::<UaResult<_>>()?;
    Ok(json!({ "goal": g, "ancestry": chain, "edge": EDGE_ANCESTRY, "meaning": MEANING }))
}

/// The why-chain of task `task_id`, which serves goal `served` (read by
/// the caller through organization `org`'s links only).
fn why_chain(conn: &Connection, org: &str, task_id: i64, served: Option<i64>) -> UaResult<Value> {
    let task = task_object(conn, org, task_id)?
        .ok_or_else(|| UaError::not_found(format!("unknown task: {task_id}")))?;
    let unlinked = json!({ "task_id": task_id, "goal_id": null, "edge": EDGE_ANCESTRY, "chain": [], "meaning": MEANING });
    let Some(goal_id) = served else { return Ok(unlinked) };
    let Some(g) = goal(conn, org, goal_id)? else { return Ok(unlinked) };
    if str_field(&g, "project") != str_field(&task, "project") {
        return Ok(unlinked);
    }
    let d = detail(conn, org, goal_id)?;
    Ok(
        json!({ "task_id": task_id, "goal_id": goal_id, "edge": EDGE_ANCESTRY, "chain": d["ancestry"], "meaning": MEANING }),
    )
}

fn link(
    tx: &mut ua_store::WriteTx<'_>,
    org: &str,
    p: LinkParams,
    who: &str,
    actor: (ua_graph::PrincipalId, ua_graph::AssertedByKind),
    caps: GraphCaps,
) -> UaResult<Value> {
    require_org(tx, org)?;
    let task = task_object(tx, org, p.task_id)?
        .ok_or_else(|| UaError::not_found(format!("unknown task: {}", p.task_id)))?;
    let g = require_goal(tx, org, p.goal_id)?;
    if str_field(&task, "project") != str_field(&g, "project") {
        return Err(UaError::invalid("task and goal must belong to the same project"));
    }
    ancestry_ids(tx, org, p.goal_id)?;
    if let Some(existing) = goal_links::served_goal_tx(tx, org, p.task_id)? {
        if existing != p.goal_id {
            return Err(UaError::invalid(format!(
                "task {} already serves goal {existing}; goal_task is single-valued",
                p.task_id
            )));
        }
    } else {
        goal_links::link(tx, org, p.task_id, p.goal_id, who, actor, caps)?;
        emit(tx, org, "agent.goal.linked", json!({ "task_id": p.task_id, "goal_id": p.goal_id }), who)?;
    }
    let served = goal_links::served_goal_tx(tx, org, p.task_id)?;
    Ok(json!({
        "task_id": p.task_id,
        "goal_id": p.goal_id,
        "edge": EDGE_TASK,
        "why_chain": why_chain(tx, org, p.task_id, served)?,
    }))
}

fn unlink(
    tx: &mut ua_store::WriteTx<'_>,
    org: &str,
    p: LinkParams,
    who: &str,
    actor: (ua_graph::PrincipalId, ua_graph::AssertedByKind),
) -> UaResult<Value> {
    require_org(tx, org)?;
    if task_object(tx, org, p.task_id)?.is_none() {
        return Err(UaError::not_found(format!("unknown task: {}", p.task_id)));
    }
    require_goal(tx, org, p.goal_id)?;
    match goal_links::served_goal_tx(tx, org, p.task_id)? {
        None => return Err(UaError::invalid(format!("task {} serves no goal", p.task_id))),
        Some(g) if g != p.goal_id => {
            return Err(UaError::invalid(format!(
                "task {} serves goal {g}, not goal {}",
                p.task_id, p.goal_id
            )));
        }
        Some(_) => {}
    }
    goal_links::unlink(tx, org, p.task_id, actor)?;
    emit(tx, org, "agent.goal.unlinked", json!({ "task_id": p.task_id, "goal_id": p.goal_id }), who)?;
    Ok(json!({ "task_id": p.task_id, "goal_id": p.goal_id, "edge": EDGE_TASK, "unlinked": true }))
}

fn edit(tx: &mut ua_store::WriteTx<'_>, org: &str, p: EditParams, who: &str) -> UaResult<Value> {
    require_org(tx, org)?;
    if p.title.is_none() && p.statement.is_none() {
        return Err(UaError::invalid("pass title, statement or both"));
    }
    let title = p.title.as_deref().map(check_title).transpose()?;
    let statement = p.statement.as_deref().map(check_statement).transpose()?;
    let row = require_goal(tx, org, p.goal_id)?;
    check_revision(&row, p.expected_revision)?;
    tx.execute(
        "UPDATE goals SET title = COALESCE(?1, title), statement = COALESCE(?2, statement), updated_at = ?3, \
         revision = revision + 1 WHERE org_id = ?5 AND id = ?4",
        params![title, statement, now(), p.goal_id, org],
    )?;
    let mut fields = Vec::new();
    if title.is_some() {
        fields.push("title");
    }
    if statement.is_some() {
        fields.push("statement");
    }
    emit(tx, org, "agent.goal.updated", json!({ "goal_id": p.goal_id, "fields": fields }), who)?;
    goal_reply(tx, org, p.goal_id)
}

fn set_status(
    tx: &mut ua_store::WriteTx<'_>,
    org: &str,
    p: StatusParams,
    status: &str,
    who: &str,
) -> UaResult<Value> {
    debug_assert!(GOAL_STATUSES.contains(&status));
    require_org(tx, org)?;
    let reason = p.reason.as_deref().unwrap_or_default().trim().to_string();
    if reason.chars().count() > 4000 {
        return Err(UaError::invalid("reason must be at most 4000 characters"));
    }
    let row = require_goal(tx, org, p.goal_id)?;
    check_revision(&row, p.expected_revision)?;
    let current = str_field(&row, "status").unwrap_or("open").to_string();
    if current == status || (CLOSED.contains(&status) && CLOSED.contains(&current.as_str())) {
        return Err(UaError::conflict(format!("goal {} is already {current}", p.goal_id)));
    }
    tx.execute(
        "UPDATE goals SET status = ?1, updated_at = ?2, revision = revision + 1 WHERE org_id = ?4 AND id = ?3",
        params![status, now(), p.goal_id, org],
    )?;
    let channel = if status == "open" { "agent.goal.reopened" } else { "agent.goal.closed" };
    emit(
        tx,
        org,
        channel,
        json!({ "goal_id": p.goal_id, "from": current, "status": status, "reason": ledger_text(org, &reason) }),
        who,
    )?;
    goal_reply(tx, org, p.goal_id)
}
