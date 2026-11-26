//! `task_list`, including ranked `query=` search over the `task_fts` index.

use rusqlite::types::Value as Sql;
use rusqlite::{Connection, params_from_iter};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};

use super::*;
use crate::registry::{Registry, ToolCtx, tool};

const PRIORITY_RANK_SQL: &str = "CASE priority WHEN 'high' THEN 0 WHEN 'med' THEN 1 ELSE 2 END";
const CURSOR_VERSION: i64 = 1;
const FTS_CANDIDATE_CAP: usize = 200;
const W_LEXICAL: f64 = 0.5;
const W_RECENCY: f64 = 0.3;
const RECENCY_HALF_LIFE_DAYS: f64 = 15.0;
const REVIEW_MARKER: &str = "[waiting-for: review]";
/// The implicit status filter with `stage`: every unfinished status.
const UNFINISHED: &str = "unfinished";

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// `open` (default), `doing`, `waiting_review`, `blocked`, `done`, `cancelled` or `all`.
    pub status: Option<String>,
    /// Direct children of this task only.
    pub parent_id: Option<i64>,
    /// Substring match on notes (literal, case-insensitive for ASCII).
    pub notes_contain: Option<String>,
    /// `high`, `med` or `low`.
    pub priority: Option<String>,
    /// Page size: 1-500 for full rows, 1-100000 for compact (ranked mode: 1-100). Default 100.
    pub limit: Option<i64>,
    /// Only tasks stamped with this source host (case-insensitive).
    pub source_host: Option<String>,
    /// `true` lists only archived tasks; default lists only unarchived ones.
    #[serde(default)]
    pub archived: bool,
    /// `true` lists only parked tasks (parked with `queue_park` or folded into
    /// a parked root; `status` still filters, pass `all` for every status).
    /// Default leaves parked tasks out. Exclusive with `archived`.
    #[serde(default)]
    pub parked: bool,
    /// `full` (default) or `compact` (drops notes bodies; adds `notes_chars`
    /// and marker flags).
    pub fields: Option<String>,
    /// Only this project stream. Omitted lists every project.
    pub project: Option<String>,
    /// Only this domain.
    pub domain: Option<String>,
    /// Only this lane.
    pub lane: Option<String>,
    /// Only tasks with `due_at` at or before this value.
    pub due_before: Option<String>,
    /// Only tasks completed at or after this value.
    pub completed_after: Option<String>,
    /// Only unfinished tasks whose every prerequisite is done or cancelled.
    #[serde(default)]
    pub frontier: bool,
    /// Only `doing` tasks whose lease has expired.
    #[serde(default)]
    pub stale_claims: bool,
    /// Opaque keyset cursor from a previous page's `next_cursor` (same filters).
    pub cursor: Option<String>,
    /// Only tasks created at or after this RFC 3339 instant (offset required).
    pub created_since: Option<String>,
    /// Only tasks updated at or after this RFC 3339 instant (offset required).
    pub updated_since: Option<String>,
    /// Ranked mode: relevance search over title and notes within the same
    /// filters. Exclusive with `notes_contain` and `cursor`.
    pub query: Option<String>,
    /// Only tasks whose workflow record (`task_workflow_set`) is at this
    /// stage: plan, implement, verify, review, merge, deploy, prove or done.
    /// Without `status`, every unfinished status is listed.
    /// `stage="review"` is the review queue.
    pub stage: Option<String>,
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "task_list",
            "List tasks by status (or all), sorted by priority then age, with keyset pagination. \
             Pass query= for ranked full-text search. Parked tasks are left out unless parked=true (the parked \
             view; parking is not cancelling). stage= filters on the workflow stage (stage=review is the \
             review queue; without status it lists every unfinished status). Returns {tasks, truncated, \
             next_cursor, limit}.",
            |ctx: ToolCtx, a: ListArgs| async move {
                let pin = crate::grant::pinned_task();
                let org = ctx.caller.org_id.clone();
                ctx.hub.db().read_async(move |c| list(c, &org, a, pin)).await
            },
        )
        .family("tasks")
        .read_only(),
    );
}

struct Filter {
    clauses: Vec<String>,
    values: Vec<Sql>,
}

impl Filter {
    /// Add a clause whose bare `?` placeholders bind `vals` in order.
    fn push(&mut self, clause: &str, vals: impl IntoIterator<Item = Sql>) {
        let mut vals = vals.into_iter();
        let mut parts = clause.split('?');
        let mut out = parts.next().unwrap_or_default().to_string();
        for part in parts {
            if let Some(v) = vals.next() {
                self.values.push(v);
            }
            out.push_str(&format!("?{}", self.values.len()));
            out.push_str(part);
        }
        self.clauses.push(out);
    }

    fn sql(&self) -> String {
        if self.clauses.is_empty() { "1".into() } else { self.clauses.join(" AND ") }
    }
}

fn since_bound(field: &str, value: &str) -> UaResult<String> {
    let ts = ua_core::time::parse_ts(value.trim()).ok_or_else(|| {
        UaError::invalid(format!(
            "{field} must be an RFC 3339 time with a UTC offset (Z or +HH:MM), not {value:?}"
        ))
    })?;
    Ok(ts.strftime("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string())
}

fn encode_cursor(rank: i64, created_at: &str, id: i64) -> String {
    hex::encode(json!([CURSOR_VERSION, rank, created_at, id]).to_string())
}

fn decode_cursor(cursor: &str) -> UaResult<(i64, String, i64)> {
    let bad = || UaError::invalid("cursor is not a task_list cursor");
    let raw = hex::decode(cursor).map_err(|_| bad())?;
    let v: Value = serde_json::from_slice(&raw).map_err(|_| bad())?;
    let arr = v.as_array().filter(|a| a.len() == 4).ok_or_else(bad)?;
    if arr[0].as_i64() != Some(CURSOR_VERSION) {
        return Err(bad());
    }
    let (Some(rank), Some(created), Some(id)) = (arr[1].as_i64(), arr[2].as_str(), arr[3].as_i64()) else {
        return Err(bad());
    };
    if encode_cursor(rank, created, id) != cursor {
        return Err(bad());
    }
    Ok((rank, created.to_string(), id))
}

/// Live `[waiting-for: review]`: present and not a forward-looking mention.
fn waiting_for_review(notes: &str, status: &str) -> bool {
    if is_terminal(status) {
        return false;
    }
    let mut stripped = notes.to_ascii_lowercase();
    for q in [" when done", " once shipped"] {
        stripped = stripped.replace(&format!("{REVIEW_MARKER}{q}"), "");
    }
    stripped.contains(REVIEW_MARKER)
}

/// Drop the notes body; keep its length and the queue marker flags.
fn compact(row: &mut Map<String, Value>) {
    let notes = match row.remove("notes") {
        Some(Value::String(s)) => s,
        _ => String::new(),
    };
    let status = str_field(row, "status").unwrap_or_default().to_string();
    row.insert("notes_chars".into(), json!(notes.chars().count()));
    row.insert("waiting_for_review".into(), json!(waiting_for_review(&notes, &status)));
    row.insert("notes_archived".into(), json!(notes.to_ascii_lowercase().contains("[archived")));
}

fn shape(
    conn: &Connection,
    org: &str,
    mut row: Map<String, Value>,
    compact_rows: bool,
) -> UaResult<Map<String, Value>> {
    decorate(conn, org, &mut row)?;
    if compact_rows {
        compact(&mut row);
    }
    Ok(row)
}

/// `pin`: a session credential's task ([`crate::grant::pinned_task`]); the
/// listing then holds that task at most, whatever the other filters say.
/// Only organization `org`'s tasks are listed or searched.
fn list(conn: &Connection, org: &str, a: ListArgs, pin: Option<Option<i64>>) -> UaResult<Value> {
    let default_status = if a.stage.is_some() { UNFINISHED } else { "open" };
    let status = a.status.clone().unwrap_or_else(|| default_status.into());
    if status != "all" && status != UNFINISHED {
        check_one_of("status", &status, &STATUSES)?;
    }
    if let Some(p) = &a.priority {
        check_one_of("priority", p, &PRIORITIES)?;
    }
    let fields = a.fields.clone().unwrap_or_else(|| "full".into());
    check_one_of("fields", &fields, &["full", "compact"])?;
    let compact_rows = fields == "compact";
    if a.query.is_some() && a.notes_contain.is_some() {
        return Err(UaError::invalid(
            "query (ranked search) and notes_contain (substring search) are mutually exclusive -- pick one mode",
        ));
    }
    if a.query.is_some() && a.cursor.is_some() {
        return Err(UaError::invalid("query (ranked mode) does not support cursor pagination"));
    }

    let mut f = Filter { clauses: Vec::new(), values: Vec::new() };
    // The organization leads every listing and the ranked search's
    // `eligible` set, so another organization's rows never reach the FTS
    // candidate cap.
    f.push("org_id = ?", [Sql::Text(org.to_string())]);
    match pin {
        None => {}
        Some(Some(id)) => f.push("id = ?", [Sql::Integer(id)]),
        Some(None) => f.push("0", []),
    }
    if let Some(p) = &a.project {
        f.push("project = ?", [Sql::Text(check_slug("project", p)?)]);
    }
    if let Some(d) = &a.domain {
        f.push("domain = ?", [Sql::Text(check_slug("domain", d)?)]);
    }
    if let Some(l) = &a.lane {
        f.push("lane = ?", [Sql::Text(check_slug("lane", l)?)]);
    }
    if let Some(d) = &a.due_before {
        f.push("due_at IS NOT NULL AND due_at <= ?", [Sql::Text(d.clone())]);
    }
    if let Some(c) = &a.completed_after {
        f.push("completed_at IS NOT NULL AND completed_at >= ?", [Sql::Text(c.clone())]);
    }
    if a.frontier {
        if org == ua_core::DEFAULT_ORG {
            f.push(
                "status NOT IN ('done', 'cancelled') AND NOT EXISTS ( \
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
                 )",
                [],
            );
        } else {
            f.push(
                "status NOT IN ('done', 'cancelled') AND NOT EXISTS ( \
                     SELECT 1 FROM task_dependencies d \
                     JOIN tasks pre ON pre.id = d.depends_on_task_id AND pre.org_id = tasks.org_id \
                     WHERE d.org_id = tasks.org_id AND d.task_id = tasks.id \
                       AND pre.status NOT IN ('done', 'cancelled') \
                 )",
                [],
            );
        }
    }
    if a.stale_claims {
        f.push(
            "status = 'doing' AND lock_expires_at IS NOT NULL AND lock_expires_at <= ?",
            [Sql::Text(now())],
        );
    }
    if status == UNFINISHED {
        f.push("status NOT IN ('done', 'cancelled')", []);
    } else if status != "all" {
        f.push("status = ?", [Sql::Text(status)]);
    }
    if let Some(stage) = &a.stage {
        let stage = stage.trim();
        if !crate::families::continuity::STAGES.contains(&stage) {
            return Err(UaError::invalid(format!(
                "stage must be one of {:?}",
                crate::families::continuity::STAGES
            )));
        }
        f.push(
            "id IN (SELECT task_id FROM task_workflow WHERE org_id = ? AND stage = ?)",
            [Sql::Text(org.to_string()), Sql::Text(stage.to_string())],
        );
    }
    if let Some(p) = a.parent_id {
        f.push("parent_id = ?", [Sql::Integer(p)]);
    }
    if let Some(n) = &a.notes_contain {
        let lit = n.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        f.push("notes LIKE ? ESCAPE '\\'", [Sql::Text(format!("%{lit}%"))]);
    }
    if let Some(p) = &a.priority {
        f.push("priority = ?", [Sql::Text(p.clone())]);
    }
    if let Some(h) = &a.source_host {
        f.push("lower(source_host) = lower(?)", [Sql::Text(h.clone())]);
    }
    if a.archived && a.parked {
        return Err(UaError::invalid("archived and parked are separate views; pass one of them"));
    }
    f.push(if a.archived { "archived_at IS NOT NULL" } else { "archived_at IS NULL" }, []);
    f.push(if a.parked { "parked_at IS NOT NULL" } else { "parked_at IS NULL" }, []);
    if let Some(v) = &a.created_since {
        f.push("julianday(created_at) >= julianday(?)", [Sql::Text(since_bound("created_since", v)?)]);
    }
    if let Some(v) = &a.updated_since {
        f.push("julianday(updated_at) >= julianday(?)", [Sql::Text(since_bound("updated_since", v)?)]);
    }

    let limit = a.limit.unwrap_or(100);
    if let Some(q) = &a.query {
        return ranked(conn, org, q, &f, limit.clamp(1, 100), compact_rows);
    }

    if let Some(c) = &a.cursor {
        let (rank, created_at, after_id) = decode_cursor(c)?;
        f.push(
            &format!(
                "({PRIORITY_RANK_SQL} > ? OR ({PRIORITY_RANK_SQL} = ? AND (created_at > ? OR (created_at = ? AND id > ?))))"
            ),
            [
                Sql::Integer(rank),
                Sql::Integer(rank),
                Sql::Text(created_at.clone()),
                Sql::Text(created_at),
                Sql::Integer(after_id),
            ],
        );
    }
    let max = if compact_rows { 100_000 } else { 500 };
    let effective = limit.clamp(1, max);
    let sql = format!(
        "SELECT *, {PRIORITY_RANK_SQL} AS _page_rank FROM tasks WHERE {} ORDER BY _page_rank, created_at, id LIMIT {}",
        f.sql(),
        effective + 1
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows: Vec<Map<String, Value>> =
        stmt.query_map(params_from_iter(f.values.iter()), task_row)?.collect::<Result<_, _>>()?;
    let truncated = rows.len() as i64 > effective;
    rows.truncate(effective as usize);
    let next_cursor = if truncated {
        rows.last().map(|r| {
            encode_cursor(
                int_field(r, "_page_rank").unwrap_or(2),
                str_field(r, "created_at").unwrap_or_default(),
                int_field(r, "id").unwrap_or_default(),
            )
        })
    } else {
        None
    };
    let mut tasks = Vec::with_capacity(rows.len());
    for mut row in rows {
        row.remove("_page_rank");
        tasks.push(Value::Object(shape(conn, org, row, compact_rows)?));
    }
    Ok(json!({ "tasks": tasks, "truncated": truncated, "next_cursor": next_cursor, "limit": effective }))
}

/// OR-join query tokens as quoted FTS5 phrases, neutralizing FTS syntax.
fn fts_or_query(query: &str) -> String {
    query
        .split_whitespace()
        .map(|t| t.replace('"', ""))
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{t}\""))
        .collect::<Vec<_>>()
        .join(" OR ")
}

/// Ranked search over `f`'s eligible rows, which lead with `org`'s filter.
/// Accepted residual: bm25's term statistics (document frequencies, average
/// length) come from the whole hub-wide `task_fts` index, so another
/// organization's tasks can shift a score's value, but never which rows
/// match or are returned.
fn ranked(
    conn: &Connection,
    org: &str,
    query: &str,
    f: &Filter,
    limit: i64,
    compact_rows: bool,
) -> UaResult<Value> {
    let cleaned = query.trim();
    if cleaned.is_empty() {
        return Err(UaError::invalid("query must contain at least one search term"));
    }
    let fts = fts_or_query(cleaned);
    let empty =
        || json!({ "tasks": [], "truncated": false, "next_cursor": null, "limit": limit, "ranked": true });
    if fts.is_empty() {
        return Ok(empty());
    }
    let mut values = f.values.clone();
    values.push(Sql::Text(fts));
    let sql = format!(
        "SELECT task_fts.rowid, bm25(task_fts), snippet(task_fts, 1, '[', ']', ' … ', 20) \
         FROM task_fts JOIN (SELECT id FROM tasks WHERE {}) eligible ON eligible.id = task_fts.rowid \
         WHERE task_fts MATCH ?{} ORDER BY bm25(task_fts) LIMIT {}",
        f.sql(),
        values.len(),
        FTS_CANDIDATE_CAP + 1
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut hits: Vec<(i64, f64, Option<String>)> = stmt
        .query_map(params_from_iter(values.iter()), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let fts_truncated = hits.len() > FTS_CANDIDATE_CAP;
    hits.truncate(FTS_CANDIDATE_CAP);
    if hits.is_empty() {
        return Ok(empty());
    }

    // bm25 is negative; better matches are more negative. Normalize against
    // the best match in this result set so the lexical term spans 0..1.
    let best = hits.iter().map(|h| -h.1).fold(0.0_f64, f64::max);
    let now_ms = ua_core::time::now_ms();
    let mut scored = Vec::with_capacity(hits.len());
    for (id, bm25, snippet) in hits {
        let Some(row) = task_object(conn, org, id)? else { continue };
        let lexical = if best > 0.0 { ((-bm25) / best).clamp(0.0, 1.0) } else { 1.0 };
        let age_days = str_field(&row, "updated_at")
            .and_then(ua_core::time::parse_ts)
            .map(|t| ((now_ms - t.as_millisecond()).max(0) as f64) / 86_400_000.0)
            .unwrap_or(0.0);
        let recency = 2f64.powf(-age_days / RECENCY_HALF_LIFE_DAYS);
        let score = W_LEXICAL * lexical + W_RECENCY * recency;
        let explanation = json!({
            "why": ["lexical"],
            "lexical": round4(lexical),
            "semantic": null,
            "recency": round4(recency),
            "salience": null,
            "access": null,
            "not_applicable": [
                "semantic (no embedding index in this build)",
                "salience (memory-only signal; tasks have no relevance-importance field)",
                "access (memory-only signal; tasks have no read-access counter)",
            ],
            "snippet": snippet,
        });
        scored.push((score, id, row, explanation));
    }
    scored.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
    let truncated = fts_truncated || scored.len() as i64 > limit;
    scored.truncate(limit as usize);
    let mut tasks = Vec::with_capacity(scored.len());
    for (score, _, row, explanation) in scored {
        let mut row = shape(conn, org, row, compact_rows)?;
        row.insert("combined_score".into(), json!((score * 1e6).round() / 1e6));
        row.insert("explanation".into(), explanation);
        tasks.push(Value::Object(row));
    }
    Ok(json!({ "tasks": tasks, "truncated": truncated, "next_cursor": null, "limit": limit, "ranked": true }))
}

fn round4(x: f64) -> f64 {
    (x * 1e4).round() / 1e4
}
