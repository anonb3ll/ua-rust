//! Runs: one read-only projection over every store that records a run.
//!
//! Tools: `run_list` and `run_get`.
//!
//! | `kind` | Store | `run_id` |
//! |---|---|---|
//! | `dispatch` | `dispatch_runs` (approved harness dispatch) | `run-<task>-<hex>` |
//! | `session` | `agent_sessions` (agent, harness and node sessions) | the session id |
//! | `workflow` | `workflow_runs` (YAML workflows and LangGraph runs) | the workflow run id |
//! | `node` | `node_dispatch` (remote-node work items) | `nd-<16 hex>` |
//!
//! Each store keeps its own state vocabulary; `status` reports it verbatim
//! and every row adds the same uniform fields: `kind`, `task_id`, `agent`,
//! `outcome`, `started_at`, `ended_at`, `lease_expires_at`, `abandoned`,
//! `abandon_reason` and `links` (platform object references plus the ledger
//! events that record the run). Store-specific fields pass through beside
//! them.
//!
//! Reads never write. A lapsed lease or a stale session heartbeat reports
//! `abandoned` on read; the stored row is left for the reapers.
//!
//! Workflow runs are tenant data: only the caller's organization's are read
//! (`organization.v1.tools.workflows`); another organization's run answers as
//! a missing one.
//!
//! Visibility follows the stores' own tools: dispatch, session and workflow
//! runs are visible to whoever may call these tools (as with
//! `dispatch_delivery_receipts_list`, `session_list` and
//! `langgraph_checkpoints`); a node item only to its requester, the node's
//! agent, a command's owner and operators (as with `node_items`).
//!
//! Pagination is a stable `(started_at, run_id)` descending cursor
//! (`<started_at>|<run_id>`). Each store contributes at most `limit + 1`
//! rows past the cursor, so no page scans a whole store.

use std::collections::HashMap;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, Row, params_from_iter};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{Caller, UaError, UaResult};

use super::agents::{SESSION_ABANDON_MINUTES, ago, verified};
use super::dispatch::CHANNEL_TRANSITION;
use super::node_queue::{self, ITEM_COLS, item_from_row};
use super::platform::object_ref;
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, tool};
use ua_org::authz::{Authority, Authz};

/// Every run kind this hub records.
pub const KINDS: [&str; 4] = ["dispatch", "session", "workflow", "node"];

/// The kinds the TypeScript SDK's `Run` schema accepts (it also names
/// `selfpickup`, which this hub has no store for). `GET /api/runs` without a
/// `kind` lists these.
pub const SDK_KINDS: [&str; 2] = ["dispatch", "session"];

/// Kinds the SDK names that this hub does not record: a filter on one is an
/// empty page, not an error.
const ABSENT_KINDS: [&str; 1] = ["selfpickup"];

pub const DEFAULT_LIMIT: i64 = 100;
pub const MAX_LIMIT: i64 = 500;

/// Ledger events linked per run, oldest first.
const EVIDENCE_CAP: usize = 50;
const CHUNK: usize = 400;

const CHANNEL_WORKFLOW: &str = "agent.workflow.finished";

/// Dispatch states whose attempt has ended: the terminal set plus
/// `retryable` (the attempt stopped and its lease was released; a resume may
/// reopen the run, so `status` stays verbatim).
const DISPATCH_ENDED: [&str; 7] =
    ["finished", "failed", "blocked", "denied", "cancelled", "expired", "retryable"];
const DISPATCH_LIVE: [&str; 3] = ["claimed", "launched", "running"];
const SESSION_OPEN: [&str; 3] = ["starting", "running", "waiting"];
const WORKFLOW_ENDED: [&str; 3] = ["done", "failed", "denied"];

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// One kind: `dispatch`, `session`, `workflow` or `node` (`selfpickup` is
    /// accepted and always empty here). Omitted: every kind, or `kinds`.
    pub kind: Option<String>,
    /// Several kinds (ignored when `kind` is set).
    pub kinds: Option<Vec<String>>,
    /// Only runs of this agent label.
    pub agent: Option<String>,
    /// Only runs for this task.
    pub task_id: Option<i64>,
    /// Page size, 1-500 (default 100).
    pub limit: Option<i64>,
    /// A previous page's `next_cursor`.
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetArgs {
    /// A dispatch run id, session id, workflow run id or node item id.
    pub run_id: String,
    /// Look the id up only in this kind's store. Omitted: every kind, or `kinds`.
    pub kind: Option<String>,
    /// Look the id up only in these kinds' stores (ignored when `kind` is set).
    pub kinds: Option<Vec<String>>,
}

/// Who is reading, for node-item visibility and the workflow runs'
/// organization.
struct Viewer {
    who: Option<String>,
    maintainer: bool,
    org: String,
}

impl Viewer {
    fn of(hub: &Hub, caller: &Caller) -> Self {
        let who = verified(caller).map(str::to_string);
        let maintainer = who.is_some()
            && Authz::new(hub.cfg()).holds(
                caller,
                &[Authority::Operator, Authority::LifecycleOperator],
                ua_core::DEFAULT_ORG,
            );
        Self { who, maintainer, org: caller.org_id.clone() }
    }
}

/// Filters every store query takes.
struct Filter<'a> {
    agent: Option<&'a str>,
    task_id: Option<i64>,
    after: Option<&'a (String, String)>,
    run_id: Option<&'a str>,
    limit: i64,
}

/// `WHERE` clauses and binds for one store, keyed on its own column names.
fn clauses(f: &Filter<'_>, agent_col: &str, ts_col: &str, id_col: &str) -> (Vec<String>, Vec<SqlValue>) {
    let mut sql = vec!["1 = 1".to_string()];
    let mut binds = Vec::new();
    if let Some(a) = f.agent {
        sql.push(format!("{agent_col} = ?"));
        binds.push(SqlValue::Text(a.to_string()));
    }
    if let Some(t) = f.task_id {
        sql.push("task_id = ?".into());
        binds.push(SqlValue::Integer(t));
    }
    if let Some((ts, id)) = f.after {
        sql.push(format!("({ts_col} < ? OR ({ts_col} = ? AND {id_col} < ?))"));
        binds.push(SqlValue::Text(ts.clone()));
        binds.push(SqlValue::Text(ts.clone()));
        binds.push(SqlValue::Text(id.clone()));
    }
    if let Some(r) = f.run_id {
        sql.push(format!("{id_col} = ?"));
        binds.push(SqlValue::Text(r.to_string()));
    }
    (sql, binds)
}

fn query_rows<T>(
    c: &Connection,
    sql: &str,
    binds: Vec<SqlValue>,
    map: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
) -> UaResult<Vec<T>> {
    let mut stmt = c.prepare(sql)?;
    let rows = stmt.query_map(params_from_iter(binds), map)?.collect::<Result<Vec<T>, _>>()?;
    Ok(rows)
}

/// Links every row starts with; evidence is filled per page.
fn base_links(self_kind: &str, run_id: &str, task_id: Option<i64>) -> Value {
    json!({
        "self": object_ref(self_kind, run_id),
        "task": task_id.and_then(|t| object_ref("task", &t.to_string())),
        "delegation": null,
        "dispatch_run": null,
        "evidence": [],
    })
}

fn lapsed(lease: Option<&str>, now: &str) -> bool {
    lease.is_some_and(|l| l <= now)
}

// --- dispatch ----------------------------------------------------------------

fn dispatch_rows(c: &Connection, f: &Filter<'_>, org: &str, now: &str) -> UaResult<Vec<Value>> {
    let (mut w, mut binds) = clauses(f, "agent_label", "created_at", "run_id");
    w.push("org_id = ?".into());
    binds.push(SqlValue::Text(org.to_string()));
    binds.push(SqlValue::Integer(f.limit));
    let sql = format!(
        "SELECT run_id, task_id, delegation_id, agent_label, harness, state, lease_expires_at, attempt, fence, \
         failure_reason, failure_class, evidence_ref, termination_outcome, created_at, updated_at, started_at, \
         ended_at FROM dispatch_runs WHERE {} ORDER BY created_at DESC, run_id DESC LIMIT ?",
        w.join(" AND ")
    );
    query_rows(c, &sql, binds, |r| {
        let run_id: String = r.get(0)?;
        let task_id: i64 = r.get(1)?;
        let delegation_id: Option<i64> = r.get(2)?;
        let state: String = r.get(5)?;
        let lease: Option<String> = r.get(6)?;
        let updated_at: String = r.get(14)?;
        let ended_col: Option<String> = r.get(16)?;
        let ended = DISPATCH_ENDED.contains(&state.as_str());
        let lease_lapsed = DISPATCH_LIVE.contains(&state.as_str()) && lapsed(lease.as_deref(), now);
        let reason = if state == "expired" {
            Some("expired")
        } else if lease_lapsed {
            Some("lease_expired")
        } else {
            None
        };
        let mut links = base_links("run", &run_id, Some(task_id));
        links["delegation"] = json!(delegation_id.and_then(|d| object_ref("delegation", &d.to_string())));
        Ok(json!({
            "run_id": run_id,
            "kind": "dispatch",
            "task_id": task_id,
            "agent": r.get::<_, String>(3)?,
            "status": state,
            "outcome": if ended { Some(state.clone()) } else { None },
            "started_at": r.get::<_, String>(13)?,
            "ended_at": if ended { Some(ended_col.unwrap_or(updated_at)) } else { None },
            "lease_expires_at": lease,
            "abandoned": reason.is_some(),
            "abandon_reason": reason,
            "harness": r.get::<_, Option<String>>(4)?,
            "attempt": r.get::<_, i64>(7)?,
            "fence": r.get::<_, i64>(8)?,
            "delegation_id": delegation_id,
            "evidence_ref": r.get::<_, Option<String>>(11)?,
            "failure_reason": r.get::<_, Option<String>>(9)?,
            "failure_class": r.get::<_, Option<String>>(10)?,
            "termination_outcome": r.get::<_, Option<String>>(12)?,
            "launched_at": r.get::<_, Option<String>>(15)?,
            "links": links,
        }))
    })
}

// --- sessions ------------------------------------------------------------------

fn session_rows(c: &Connection, f: &Filter<'_>, stale_before: &str) -> UaResult<Vec<Value>> {
    let (w, mut binds) = clauses(f, "agent", "started_at", "id");
    binds.push(SqlValue::Integer(f.limit));
    let sql = format!(
        "SELECT id, agent, kind, status, started_at, ended_at, last_heartbeat_at, task_id, delegation_id, \
         exit_status, external_session_id, host, model FROM agent_sessions WHERE {} \
         ORDER BY started_at DESC, id DESC LIMIT ?",
        w.join(" AND ")
    );
    query_rows(c, &sql, binds, |r| {
        let id: String = r.get(0)?;
        let status: String = r.get(3)?;
        let heartbeat: String = r.get(6)?;
        let task_id: Option<i64> = r.get(7)?;
        let delegation_id: Option<i64> = r.get(8)?;
        let stale = SESSION_OPEN.contains(&status.as_str()) && heartbeat.as_str() < stale_before;
        let exit: Option<String> = r.get(9)?;
        let mut links = base_links("session", &id, task_id);
        links["delegation"] = json!(delegation_id.and_then(|d| object_ref("delegation", &d.to_string())));
        Ok(json!({
            "run_id": id,
            "kind": "session",
            "task_id": task_id,
            "agent": r.get::<_, String>(1)?,
            "status": if stale { "abandoned".to_string() } else { status.clone() },
            "outcome": exit,
            "started_at": r.get::<_, String>(4)?,
            "ended_at": r.get::<_, Option<String>>(5)?,
            "lease_expires_at": null,
            "abandoned": status == "abandoned" || stale,
            "abandon_reason": if stale { Some("stale_heartbeat") } else { None },
            "session_kind": r.get::<_, String>(2)?,
            "exit_status": exit,
            "last_seen_at": heartbeat,
            "delegation_id": delegation_id,
            "host": r.get::<_, Option<String>>(11)?,
            "model": r.get::<_, Option<String>>(12)?,
            "external_session_id": r.get::<_, Option<String>>(10)?,
            "links": links,
        }))
    })
}

// --- workflows -----------------------------------------------------------------

fn workflow_rows(c: &Connection, f: &Filter<'_>, org: &str, now: &str) -> UaResult<Vec<Value>> {
    let (mut w, mut binds) = clauses(f, "owner", "created_at", "run_id");
    w.push("org_id = ?".into());
    binds.push(SqlValue::Text(org.to_string()));
    binds.push(SqlValue::Integer(f.limit));
    let sql = format!(
        "SELECT run_id, kind, name, task_id, owner, status, next_step, error, lease_expires_at, created_at, \
         updated_at, completed_at FROM workflow_runs WHERE {} ORDER BY created_at DESC, run_id DESC LIMIT ?",
        w.join(" AND ")
    );
    query_rows(c, &sql, binds, |r| {
        let run_id: String = r.get(0)?;
        let task_id: Option<i64> = r.get(3)?;
        let status: String = r.get(5)?;
        let lease: Option<String> = r.get(8)?;
        let ended = WORKFLOW_ENDED.contains(&status.as_str());
        let lease_lapsed = status == "running" && lapsed(lease.as_deref(), now);
        let completed: Option<String> = r.get(11)?;
        let updated: String = r.get(10)?;
        Ok(json!({
            "run_id": run_id,
            "kind": "workflow",
            "task_id": task_id,
            "agent": r.get::<_, String>(4)?,
            "status": status,
            "outcome": if ended { Some(status.clone()) } else { None },
            "started_at": r.get::<_, String>(9)?,
            "ended_at": if ended { Some(completed.unwrap_or(updated)) } else { None },
            "lease_expires_at": lease,
            "abandoned": lease_lapsed,
            "abandon_reason": if lease_lapsed { Some("lease_expired") } else { None },
            "workflow_kind": r.get::<_, String>(1)?,
            "name": r.get::<_, String>(2)?,
            "next_step": r.get::<_, i64>(6)?,
            "error": r.get::<_, Option<String>>(7)?,
            "links": base_links("run", &run_id, task_id),
        }))
    })
}

// --- node items ----------------------------------------------------------------

fn node_rows(c: &Connection, f: &Filter<'_>, viewer: &Viewer, now: &str) -> UaResult<Vec<Value>> {
    let (mut w, mut binds) = clauses(f, "agent", "created_at", "id");
    w.push("org_id = ?".into());
    binds.push(SqlValue::Text(viewer.org.clone()));
    if !viewer.maintainer {
        let Some(who) = viewer.who.as_deref() else { return Ok(Vec::new()) };
        w.push(
            "(created_by = ? OR agent = ? OR id IN (SELECT item_id FROM node_command WHERE owner_agent = ? \
             AND org_id = node_dispatch.org_id))"
                .into(),
        );
        for _ in 0..3 {
            binds.push(SqlValue::Text(who.to_string()));
        }
    }
    binds.push(SqlValue::Integer(f.limit));
    let sql = format!(
        "SELECT {ITEM_COLS} FROM node_dispatch WHERE {} ORDER BY created_at DESC, id DESC LIMIT ?",
        w.join(" AND ")
    );
    let items = query_rows(c, &sql, binds, item_from_row)?;
    Ok(items
        .into_iter()
        .map(|item| {
            let ended = item.is_terminal();
            let receipt = item.receipt();
            let lease_lapsed = item.status == "claimed" && lapsed(item.lease_expires_at.as_deref(), now);
            let outcome = ended.then(|| {
                receipt
                    .as_ref()
                    .and_then(|r| r["status"].as_str().map(str::to_string))
                    .unwrap_or_else(|| item.status.clone())
            });
            let mut links = base_links("run", &item.id, item.task_id);
            links["dispatch_run"] = json!(item.run_id.as_deref().and_then(|r| object_ref("run", r)));
            json!({
                "run_id": item.id,
                "kind": "node",
                "task_id": item.task_id,
                "agent": item.agent,
                "status": item.status,
                "outcome": outcome,
                "started_at": item.created_at,
                "ended_at": if ended { item.completed_at.clone() } else { None },
                "lease_expires_at": item.lease_expires_at,
                "abandoned": lease_lapsed,
                "abandon_reason": if lease_lapsed { Some("lease_expired") } else { None },
                "node": item.node,
                "backend": item.backend,
                "requested_by": item.created_by,
                "attempts": item.attempts,
                "cancel_requested": item.cancel_requested,
                "claimed_at": item.claimed_at,
                "dispatch_run_id": item.run_id,
                "session_id": item.session_id,
                "wait_reason": item.wait_reason,
                "evidence_ref": node_queue::evidence_ref(&item.node, &item.id),
                "outcome_unknown": item.outcome_unknown(),
                "links": links,
            })
        })
        .collect())
}

// --- evidence links --------------------------------------------------------------

/// Event ULIDs per value of `$.<field>` on one channel, oldest first.
fn events_by(
    c: &Connection,
    channel: &str,
    field: &str,
    ids: &[String],
) -> UaResult<HashMap<String, Vec<String>>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for chunk in ids.chunks(CHUNK) {
        let marks = vec!["?"; chunk.len()].join(",");
        let sql = format!(
            "SELECT ulid, json_extract(payload, '$.{field}') FROM event_log \
             WHERE channel = ? AND json_extract(payload, '$.{field}') IN ({marks}) ORDER BY seq"
        );
        let mut binds = vec![SqlValue::Text(channel.to_string())];
        binds.extend(chunk.iter().map(|i| SqlValue::Text(i.clone())));
        for (ulid, key) in
            query_rows(c, &sql, binds, |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?
        {
            if let Some(k) = key {
                out.entry(k).or_default().push(ulid);
            }
        }
    }
    Ok(out)
}

fn evidence_refs(ulids: &[String]) -> Value {
    Value::Array(ulids.iter().take(EVIDENCE_CAP).filter_map(|u| object_ref("evidence_event", u)).collect())
}

/// Fill `links.evidence` (and a session's `links.dispatch_run`) for a page.
/// `org` is the reader's organization: a session links only to its node
/// items in it.
fn attach_links(c: &Connection, org: &str, rows: &mut [Value]) -> UaResult<()> {
    let ids_of = |rows: &[Value], kind: &str| -> Vec<String> {
        rows.iter()
            .filter(|r| r["kind"] == kind)
            .filter_map(|r| r["run_id"].as_str().map(str::to_string))
            .collect()
    };
    let transitions = events_by(c, CHANNEL_TRANSITION, "run_id", &ids_of(rows, "dispatch"))?;
    let finished = events_by(c, CHANNEL_WORKFLOW, "run_id", &ids_of(rows, "workflow"))?;

    // A session is bound to node items by the node's external session id.
    let external: Vec<String> = rows
        .iter()
        .filter(|r| r["kind"] == "session")
        .filter_map(|r| r["external_session_id"].as_str().map(str::to_string))
        .collect();
    let mut items_by_session: HashMap<String, Vec<(String, Option<String>)>> = HashMap::new();
    for chunk in external.chunks(CHUNK) {
        let marks = vec!["?"; chunk.len()].join(",");
        let sql = format!(
            "SELECT id, run_id, session_id FROM node_dispatch WHERE org_id = ? AND session_id IN ({marks}) \
             ORDER BY created_at, id"
        );
        let mut binds = vec![SqlValue::Text(org.to_string())];
        binds.extend(chunk.iter().map(|s| SqlValue::Text(s.clone())));
        for (id, run, session) in query_rows(c, &sql, binds, |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, String>(2)?))
        })? {
            items_by_session.entry(session).or_default().push((id, run));
        }
    }
    let mut item_ids = ids_of(rows, "node");
    item_ids.extend(items_by_session.values().flatten().map(|(id, _)| id.clone()));
    let node_events = events_by(c, node_queue::CHANNEL, "item_id", &item_ids)?;

    for row in rows.iter_mut() {
        let id = row["run_id"].as_str().unwrap_or_default().to_string();
        let ulids: Vec<String> = match row["kind"].as_str() {
            Some("dispatch") => transitions.get(&id).cloned().unwrap_or_default(),
            Some("workflow") => finished.get(&id).cloned().unwrap_or_default(),
            Some("node") => node_events.get(&id).cloned().unwrap_or_default(),
            Some("session") => {
                let items = row["external_session_id"]
                    .as_str()
                    .and_then(|s| items_by_session.get(s))
                    .cloned()
                    .unwrap_or_default();
                if let Some(run) = items.iter().find_map(|(_, r)| r.clone()) {
                    row["links"]["dispatch_run"] = json!(object_ref("run", &run));
                }
                items
                    .iter()
                    .flat_map(|(item, _)| node_events.get(item).cloned().unwrap_or_default())
                    .collect()
            }
            _ => Vec::new(),
        };
        row["links"]["evidence"] = evidence_refs(&ulids);
    }
    Ok(())
}

// --- reads -----------------------------------------------------------------------

fn parse_cursor(raw: Option<&str>) -> UaResult<Option<(String, String)>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else { return Ok(None) };
    match raw.split_once('|') {
        Some((ts, id)) if !ts.is_empty() && !id.is_empty() && !id.contains('|') => {
            Ok(Some((ts.to_string(), id.to_string())))
        }
        _ => Err(UaError::invalid("malformed cursor; pass a previous page's next_cursor")),
    }
}

fn cursor_of(row: &Value) -> String {
    format!(
        "{}|{}",
        row["started_at"].as_str().unwrap_or_default(),
        row["run_id"].as_str().unwrap_or_default()
    )
}

/// The kinds a list covers, validated.
pub fn resolve_kinds(kind: Option<&str>, kinds: Option<&[String]>) -> UaResult<Vec<String>> {
    let wanted: Vec<String> = match (kind.map(str::trim).filter(|k| !k.is_empty()), kinds) {
        (Some(k), _) => vec![k.to_string()],
        (None, Some(ks)) if !ks.is_empty() => ks.iter().map(|k| k.trim().to_string()).collect(),
        _ => KINDS.iter().map(|k| k.to_string()).collect(),
    };
    for k in &wanted {
        if !KINDS.contains(&k.as_str()) && !ABSENT_KINDS.contains(&k.as_str()) {
            return Err(UaError::invalid(format!(
                "kind must be one of {}; got {k:?}",
                KINDS.iter().chain(ABSENT_KINDS.iter()).copied().collect::<Vec<_>>().join(", ")
            )));
        }
    }
    Ok(wanted)
}

fn list(c: &Connection, viewer: &Viewer, a: &ListArgs) -> UaResult<Value> {
    let kinds = resolve_kinds(a.kind.as_deref(), a.kinds.as_deref())?;
    let cap = a.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let after = parse_cursor(a.cursor.as_deref())?;
    let agent = a.agent.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let f = Filter { agent, task_id: a.task_id, after: after.as_ref(), run_id: None, limit: cap + 1 };
    let now = ua_core::time::now();
    let has = |k: &str| kinds.iter().any(|w| w == k);
    let mut rows = Vec::new();
    if has("dispatch") {
        rows.extend(dispatch_rows(c, &f, &viewer.org, &now)?);
    }
    if has("session") {
        rows.extend(session_rows(c, &f, &ago(SESSION_ABANDON_MINUTES * 60))?);
    }
    if has("workflow") {
        rows.extend(workflow_rows(c, &f, &viewer.org, &now)?);
    }
    if has("node") {
        rows.extend(node_rows(c, &f, viewer, &now)?);
    }
    rows.sort_by(|x, y| {
        let key = |r: &Value| {
            (
                r["started_at"].as_str().unwrap_or_default().to_string(),
                r["run_id"].as_str().unwrap_or_default().to_string(),
            )
        };
        key(y).cmp(&key(x))
    });
    let truncated = rows.len() as i64 > cap;
    rows.truncate(cap as usize);
    attach_links(c, &viewer.org, &mut rows)?;
    let next = if truncated { rows.last().map(cursor_of) } else { None };
    Ok(json!({
        "runs": rows,
        "count": rows.len(),
        "truncated": truncated,
        "next_cursor": next,
        "limit": cap,
        "kinds": kinds,
    }))
}

/// One run row by id from the first of `kinds`' stores that holds it, else
/// `None`.
fn get(c: &Connection, viewer: &Viewer, run_id: &str, kinds: &[String]) -> UaResult<Option<Value>> {
    let rid = run_id.trim();
    if rid.is_empty() || rid.len() > 128 {
        return Ok(None);
    }
    let f = Filter { agent: None, task_id: None, after: None, run_id: Some(rid), limit: 1 };
    let now = ua_core::time::now();
    let has = |k: &str| kinds.iter().any(|w| w == k);
    let mut rows = Vec::new();
    if has("dispatch") {
        rows = dispatch_rows(c, &f, &viewer.org, &now)?;
    }
    if rows.is_empty() && has("session") {
        rows = session_rows(c, &f, &ago(SESSION_ABANDON_MINUTES * 60))?;
    }
    if rows.is_empty() && has("workflow") {
        rows = workflow_rows(c, &f, &viewer.org, &now)?;
    }
    if rows.is_empty() && has("node") {
        rows = node_rows(c, &f, viewer, &now)?;
    }
    attach_links(c, &viewer.org, &mut rows)?;
    Ok(rows.into_iter().next())
}

/// `run_get` for other readers in this crate (the platform `run` object).
pub(crate) fn read_one(
    hub: &Hub,
    caller: &Caller,
    conn: &Connection,
    run_id: &str,
) -> UaResult<Option<Value>> {
    let all: Vec<String> = KINDS.iter().map(|k| k.to_string()).collect();
    get(conn, &Viewer::of(hub, caller), run_id, &all)
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "run_list",
            "List runs from every run store as one uniform row shape, newest first: dispatch runs (`dispatch`), \
             agent and node sessions (`session`), workflow and LangGraph runs (`workflow`) and remote-node work \
             items (`node`). Each row has run_id, kind, task_id, agent, status (the store's own state), outcome, \
             started_at, ended_at, lease_expires_at, abandoned and abandon_reason (a lapsed lease or stale \
             heartbeat, judged on read) and links {self, task, delegation, dispatch_run, evidence}, plus \
             kind-specific fields. Filters: kind or kinds, agent, task_id. Cursor-paginated: pass next_cursor \
             back as cursor. Node items are listed only to their requester, the node's agent, a command's owner \
             and operators. Returns {runs, count, truncated, next_cursor, limit, kinds}.",
            |ctx: ToolCtx, a: ListArgs| async move {
                let viewer = Viewer::of(&ctx.hub, &ctx.caller);
                ctx.hub.db().read_async(move |c| list(c, &viewer, &a)).await
            },
        )
        .family("runs")
        .read_only(),
    );
    r.add(
        tool(
            "run_get",
            "Read one run by id (dispatch run, session, workflow run or node item) in the run_list row shape. \
             kind or kinds limit the stores looked in (default: every kind, as run_list). Returns {run}; an \
             unknown id, a run of a kind not asked for, or a node item not visible to you, is not found.",
            |ctx: ToolCtx, a: GetArgs| async move {
                let kinds = resolve_kinds(a.kind.as_deref(), a.kinds.as_deref())?;
                let viewer = Viewer::of(&ctx.hub, &ctx.caller);
                let rid = a.run_id;
                let row =
                    ctx.hub.db().read_async(move |c| get(c, &viewer, &rid, &kinds).map(|r| (r, rid))).await?;
                match row {
                    (Some(run), _) => Ok(json!({ "run": run })),
                    (None, rid) => Err(UaError::not_found(format!("unknown run {rid:?}"))),
                }
            },
        )
        .family("runs")
        .read_only(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip_and_reject_garbage() {
        let row = json!({ "started_at": "2026-11-01T10:00:00+00:00", "run_id": "run-1-aa" });
        let c = cursor_of(&row);
        assert_eq!(
            parse_cursor(Some(&c)).unwrap(),
            Some(("2026-11-01T10:00:00+00:00".into(), "run-1-aa".into()))
        );
        assert_eq!(parse_cursor(None).unwrap(), None);
        for bad in ["nope", "|x", "x|", "a|b|c"] {
            assert!(parse_cursor(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn kinds_default_to_every_store_and_reject_unknown_names() {
        assert_eq!(resolve_kinds(None, None).unwrap(), KINDS.to_vec());
        assert_eq!(resolve_kinds(Some("node"), None).unwrap(), vec!["node"]);
        assert_eq!(resolve_kinds(Some("selfpickup"), None).unwrap(), vec!["selfpickup"]);
        let ks = vec!["dispatch".to_string(), "session".to_string()];
        assert_eq!(resolve_kinds(None, Some(&ks)).unwrap(), ks);
        assert!(resolve_kinds(Some("bogus"), None).is_err());
    }
}
