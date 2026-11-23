//! The task queue: tasks, claims, dependencies, comments and goals.
//!
//! Tools: `task_add`, `task_update`, `task_list`, `task_delete`,
//! `task_claim`, `dependency_add`, `dependency_list`, `dependency_remove`,
//! `lineage`, `project_build`, `task_comment` and `goal_manage`.
//!
//! The `tasks` and `task_dependencies` tables are shared and live in
//! `core_schema.rs`. This family owns the full-text index over tasks, the
//! comment thread tables and the goal tables.

mod comments;
mod goals;
mod graph;
mod list;
mod write;

pub(crate) use write::{NewTask, insert_task};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use ua_core::{ActorKind, Caller, UaError, UaResult};
use ua_store::{EventInput, Procedure, SchemaPart, WriteTx, ledger};

use crate::registry::Registry;

/// Ranked search index over task title and notes, kept in sync by triggers.
/// The final statement indexes rows that existed before this part applied.
pub const SEARCH_SCHEMA: SchemaPart = SchemaPart {
    name: "tasks.search.v1",
    sql: "
CREATE VIRTUAL TABLE IF NOT EXISTS task_fts USING fts5(
    title, notes, content='tasks', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS task_fts_ai AFTER INSERT ON tasks BEGIN
    INSERT INTO task_fts(rowid, title, notes) VALUES (new.id, new.title, new.notes);
END;
CREATE TRIGGER IF NOT EXISTS task_fts_ad AFTER DELETE ON tasks BEGIN
    INSERT INTO task_fts(task_fts, rowid, title, notes) VALUES ('delete', old.id, old.title, old.notes);
END;
CREATE TRIGGER IF NOT EXISTS task_fts_au AFTER UPDATE OF title, notes ON tasks BEGIN
    INSERT INTO task_fts(task_fts, rowid, title, notes) VALUES ('delete', old.id, old.title, old.notes);
    INSERT INTO task_fts(rowid, title, notes) VALUES (new.id, new.title, new.notes);
END;
INSERT INTO task_fts(task_fts) VALUES ('rebuild');
",
};

/// Append-only comment threads on tasks.
pub const COMMENTS_SCHEMA: SchemaPart = SchemaPart {
    name: "tasks.comments.v1",
    sql: "
CREATE TABLE IF NOT EXISTS task_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    parent_comment_id INTEGER REFERENCES task_comments(id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    mentions TEXT NOT NULL DEFAULT '[]',
    refs TEXT NOT NULL DEFAULT '{}',
    idempotency_key TEXT,
    thread_revision INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_comments_task ON task_comments(task_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_task_comments_idem
    ON task_comments(task_id, author, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS task_comment_threads (
    task_id INTEGER PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
",
};

/// Goals (a why-chain) and the single goal each task serves.
pub const GOALS_SCHEMA: SchemaPart = SchemaPart {
    name: "tasks.goals.v1",
    sql: "
CREATE TABLE IF NOT EXISTS goals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    statement TEXT NOT NULL DEFAULT '',
    parent_goal_id INTEGER REFERENCES goals(id) ON DELETE SET NULL,
    project TEXT NOT NULL DEFAULT 'default',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','achieved','abandoned')),
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_goals_parent ON goals(parent_goal_id);
CREATE TABLE IF NOT EXISTS task_goal_links (
    task_id INTEGER PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
    goal_id INTEGER NOT NULL REFERENCES goals(id) ON DELETE CASCADE,
    linked_by TEXT,
    linked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_goal_links_goal ON task_goal_links(goal_id);
",
};

/// `organization.v1.tools.tasks`: `org_id` on `tasks`, `task_dependencies`,
/// `task_comments` and `task_comment_threads` (existing rows backfilled to the
/// default organization) and their generated `*_org_exists` /
/// `*_org_immutable` triggers. No key rebuild: a task id is a hub-global
/// AUTOINCREMENT id (Decision 3: task identity never moves between
/// organizations), and every child key is led by a task or comment id, so two
/// organizations can never collide. `task_fts` is an external-content index
/// over `tasks` and takes no column: every search filters through `tasks`.
/// Applied after the tasks parts and `organization.v1.store`.
pub const TENANT_PART: Procedure = ua_store::org::tenant_part(
    "organization.v1.tools.tasks",
    &["tasks", "task_dependencies", "task_comments", "task_comment_threads"],
);

/// `tasks.v2.org_scope`: indexes led by `org_id` for the hot task reads (the
/// status and project queues, a claimant's tasks), and triggers that keep
/// every task reference inside one organization: a task's `parent_id` and
/// `folded_into`, both ends of a dependency, and a comment's task and parent
/// comment (the foreign keys alone would accept a row in another
/// organization). A missing target is still the foreign key's error. Applied
/// after [`TENANT_PART`] and the continuity parking columns.
pub const ORG_SCOPE: SchemaPart = SchemaPart {
    name: "tasks.v2.org_scope",
    sql: "
CREATE INDEX IF NOT EXISTS idx_tasks_org_status ON tasks(org_id, status, priority);
CREATE INDEX IF NOT EXISTS idx_tasks_org_project ON tasks(org_id, project, status);
CREATE INDEX IF NOT EXISTS idx_tasks_org_claimed ON tasks(org_id, claimed_by);
CREATE INDEX IF NOT EXISTS idx_task_dependencies_org_task ON task_dependencies(org_id, task_id);

CREATE TRIGGER IF NOT EXISTS tasks_org_parent BEFORE INSERT ON tasks
WHEN EXISTS (SELECT 1 FROM tasks WHERE id IN (NEW.parent_id, NEW.folded_into) AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS tasks_org_parent_update BEFORE UPDATE OF parent_id, folded_into ON tasks
WHEN EXISTS (SELECT 1 FROM tasks WHERE id IN (NEW.parent_id, NEW.folded_into) AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS task_dependencies_org_parent BEFORE INSERT ON task_dependencies
WHEN EXISTS (SELECT 1 FROM tasks WHERE id IN (NEW.task_id, NEW.depends_on_task_id) AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS task_dependencies_org_parent_update
BEFORE UPDATE OF task_id, depends_on_task_id ON task_dependencies
WHEN EXISTS (SELECT 1 FROM tasks WHERE id IN (NEW.task_id, NEW.depends_on_task_id) AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS task_comments_org_parent BEFORE INSERT ON task_comments
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM task_comments WHERE id = NEW.parent_comment_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task or comment belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS task_comments_org_parent_update
BEFORE UPDATE OF task_id, parent_comment_id ON task_comments
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM task_comments WHERE id = NEW.parent_comment_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task or comment belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS task_comment_threads_org_parent BEFORE INSERT ON task_comment_threads
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS task_comment_threads_org_parent_update BEFORE UPDATE OF task_id ON task_comment_threads
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
",
};

pub fn schema_parts() -> Vec<SchemaPart> {
    vec![SEARCH_SCHEMA, COMMENTS_SCHEMA, GOALS_SCHEMA]
}

pub fn register(r: &mut Registry) {
    write::register(r);
    list::register(r);
    graph::register(r);
    comments::register(r);
    goals::register(r);
}

// ---------------------------------------------------------------------------
// Shared vocabulary
// ---------------------------------------------------------------------------

pub(crate) const STATUSES: [&str; 6] = ["open", "doing", "waiting_review", "blocked", "done", "cancelled"];
pub(crate) const TERMINAL: [&str; 2] = ["done", "cancelled"];
pub(crate) const PRIORITIES: [&str; 3] = ["high", "med", "low"];
/// Root depth is 0; a child of a depth-8 task is refused.
pub(crate) const MAX_DEPTH: usize = 8;
/// Lanes any agent may claim from without naming the lane.
pub(crate) const OPEN_POOL_LANES: [&str; 2] = ["default", "dispatch-ready"];
/// Umbrella lanes that are never claimable work.
pub(crate) const UNCLAIMABLE_LANES: [&str; 1] = ["tracking"];
pub(crate) const DEFAULT_LEASE_SECONDS: i64 = 3600;
pub(crate) const MAX_LEASE_SECONDS: i64 = 7 * 86400;
pub(crate) const PROJECT_SPEC_MARKER: &str = "[project-spec]";

/// ORG-GITHUB-DEFAULT: the organization the hub's GitHub and CI paths
/// without a caller (the webhook, the poller, the CI status check, the head
/// re-verification and merged-PR reconciliation) act in. Those paths run as
/// the hub, which is the default organization, and every task they scan or
/// close is filtered to it (`t.org_id = TASK_ORG`), so a delivery for a
/// repository two organizations bind never touches another organization's
/// task. Every other task lookup takes the task row's own organization.
/// Removed when the GitHub family resolves each delivery to its task's
/// organization (`docs/organization.md`).
pub(crate) const TASK_ORG: &str = ua_core::DEFAULT_ORG;
/// Active statuses in rollup order: the first present wins `derived_status`.
const ROLLUP_ORDER: [&str; 4] = ["blocked", "doing", "waiting_review", "open"];

pub(crate) fn is_terminal(status: &str) -> bool {
    TERMINAL.contains(&status)
}

pub(crate) fn check_one_of(field: &str, value: &str, allowed: &[&str]) -> UaResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(UaError::invalid(format!("{field} must be one of {allowed:?}, not {value:?}")))
    }
}

/// A project, domain or lane value: 1-64 characters of letters, digits,
/// `.`, `_` or `-`, starting with a letter or digit.
pub fn check_slug(field: &str, value: &str) -> UaResult<String> {
    let v = value.trim();
    let ok = !v.is_empty()
        && v.len() <= 64
        && v.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(v.to_string())
    } else {
        Err(UaError::invalid(format!(
            "{field} must be 1-64 letters, digits, '.', '_' or '-' starting with a letter or digit, not {value:?}"
        )))
    }
}

/// Whether `text` carries `marker` (case-insensitive) with no backtick
/// touching either side. A backticked marker is a quotation, not a marker.
pub(crate) fn has_marker(text: &str, marker: &str) -> bool {
    let hay = text.to_ascii_lowercase();
    let needle = marker.to_ascii_lowercase();
    let bytes = hay.as_bytes();
    let mut from = 0;
    while let Some(pos) = hay[from..].find(&needle) {
        let start = from + pos;
        let end = start + needle.len();
        let before = start.checked_sub(1).map(|i| bytes[i]);
        let after = bytes.get(end).copied();
        if before != Some(b'`') && after != Some(b'`') {
            return true;
        }
        from = start + 1;
    }
    false
}

/// `[urgency: now|next|later]` from the notes; the most urgent wins.
pub(crate) fn urgency(notes: &str) -> Option<&'static str> {
    ["now", "next", "later"].into_iter().find(|level| has_marker(notes, &format!("[urgency: {level}]")))
}

pub(crate) fn urgency_rank(level: Option<&str>) -> i64 {
    match level {
        Some("now") => 0,
        Some("later") => 2,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// Identity and time
// ---------------------------------------------------------------------------

/// Whether the caller carries a verified identity.
pub(crate) fn is_verified(caller: &Caller) -> bool {
    caller.kind != ActorKind::Anonymous
}

/// The identity a write acts as. A verified caller always acts as itself and
/// may not name someone else; an unverified local caller may name an agent,
/// else its configured local label is used.
pub(crate) fn acting_identity(caller: &Caller, claimed: Option<&str>) -> UaResult<String> {
    let claimed = claimed.map(str::trim).filter(|s| !s.is_empty());
    if is_verified(caller) {
        if let Some(name) = claimed
            && name != caller.label
        {
            return Err(UaError::denied(
                "identity_mismatch",
                format!("requested identity {name:?} but the caller is verified as {:?}", caller.label),
            ));
        }
        return Ok(caller.label.clone());
    }
    let label = claimed.unwrap_or(caller.label.as_str()).trim();
    if label.is_empty() {
        return Err(UaError::invalid("an agent label is required"));
    }
    Ok(label.to_string())
}

pub(crate) fn now() -> String {
    ua_core::time::now()
}

/// A task revision (`updated_at`) strictly newer than `previous`, at
/// microsecond precision, so two writes in one second stay ordered and an
/// `expected_updated_at` guard can tell them apart.
pub(crate) fn next_revision(previous: Option<&str>) -> String {
    let mut micros = jiff::Timestamp::now().as_microsecond();
    if let Some(prev) = previous.and_then(ua_core::time::parse_ts) {
        let p = prev.as_microsecond();
        if micros <= p {
            micros = p + 1;
        }
    }
    let ts = jiff::Timestamp::from_microsecond(micros).unwrap_or_else(|_| jiff::Timestamp::now());
    ts.strftime("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
}

/// `now + seconds` in the storage form.
pub(crate) fn after_seconds(seconds: i64) -> String {
    let ts = jiff::Timestamp::now();
    let later = ts.checked_add(jiff::SignedDuration::from_secs(seconds)).unwrap_or(ts);
    ua_core::time::format_ts(later)
}

/// Whether timestamp `a` is at or before `b`. Unparseable values compare as text.
pub(crate) fn ts_le(a: &str, b: &str) -> bool {
    match (ua_core::time::parse_ts(a), ua_core::time::parse_ts(b)) {
        (Some(x), Some(y)) => x <= y,
        _ => a <= b,
    }
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// Every column of a row as a JSON object.
pub(crate) fn row_object(row: &rusqlite::Row<'_>) -> rusqlite::Result<Map<String, Value>> {
    let stmt = row.as_ref();
    let mut out = Map::new();
    for i in 0..stmt.column_count() {
        let name = stmt.column_name(i)?.to_string();
        let v = match row.get_ref(i)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(n) => json!(n),
            ValueRef::Real(f) => json!(f),
            ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(b) => Value::String(hex::encode(b)),
        };
        out.insert(name, v);
    }
    Ok(out)
}

/// A task row as a JSON object without its `org_id`: a task reply keeps the
/// shape it had before tasks carried an organization (the caller's own).
pub(crate) fn task_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Map<String, Value>> {
    let mut m = row_object(row)?;
    m.remove("org_id");
    Ok(m)
}

/// Task `id` of organization `org` as a JSON object, or `None` when it does
/// not exist. Another organization's task answers exactly as a missing one.
pub(crate) fn task_object(conn: &Connection, org: &str, id: i64) -> UaResult<Option<Map<String, Value>>> {
    Ok(conn
        .query_row("SELECT * FROM tasks WHERE org_id = ?1 AND id = ?2", params![org, id], task_row)
        .optional()?)
}

pub(crate) fn require_task(conn: &Connection, org: &str, id: i64) -> UaResult<Map<String, Value>> {
    task_object(conn, org, id)?.ok_or_else(|| UaError::not_found(format!("no task with id {id}")))
}

/// The organization task `id` belongs to, for a job with no caller that acts
/// on the task's own organization. `None` when the task does not exist.
pub(crate) fn task_org(conn: &Connection, id: i64) -> UaResult<Option<String>> {
    Ok(conn.query_row("SELECT org_id FROM tasks WHERE id = ?1", [id], |r| r.get(0)).optional()?)
}

/// Refuse an organization `orgs` does not hold, before anything is written.
/// The `org_exists` triggers fire only on insert, so a write with nothing to
/// insert (an update, a delete) would otherwise pass.
pub(crate) fn require_org(c: &Connection, org: &str) -> UaResult<()> {
    let known = c.query_row("SELECT 1 FROM orgs WHERE id = ?1", [org], |_| Ok(())).optional()?.is_some();
    if !known {
        return Err(UaError::denied(
            "unknown_organization",
            format!("unknown organization {org:?}; no task was changed"),
        ));
    }
    Ok(())
}

pub(crate) fn str_field<'a>(row: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    row.get(key).and_then(Value::as_str)
}

pub(crate) fn int_field(row: &Map<String, Value>, key: &str) -> Option<i64> {
    row.get(key).and_then(Value::as_i64)
}

/// Add the derived fields every task reply carries: `urgency`,
/// `urgency_rank`, `lineage` (ancestor ids root-first) and, on a
/// `[project-spec]` root, `rollup`.
pub(crate) fn decorate(conn: &Connection, org: &str, row: &mut Map<String, Value>) -> UaResult<()> {
    let id = int_field(row, "id").unwrap_or_default();
    let notes = str_field(row, "notes").unwrap_or_default().to_string();
    let level = urgency(&notes);
    row.insert("urgency".into(), json!(level));
    row.insert("urgency_rank".into(), json!(urgency_rank(level)));
    row.insert("lineage".into(), json!(ancestors(conn, org, id)?));
    if has_marker(&notes, PROJECT_SPEC_MARKER) {
        row.insert("rollup".into(), rollup(conn, org, id)?);
    }
    Ok(())
}

/// The full task reply: row plus derived fields.
pub(crate) fn task_reply(conn: &Connection, org: &str, id: i64) -> UaResult<Value> {
    let mut row = require_task(conn, org, id)?;
    decorate(conn, org, &mut row)?;
    Ok(Value::Object(row))
}

/// Ancestor ids root-first, excluding `id`. A stored cycle fails closed.
pub(crate) fn ancestors(conn: &Connection, org: &str, id: i64) -> UaResult<Vec<i64>> {
    let mut chain = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = id;
    loop {
        if !seen.insert(current) {
            return Err(UaError::internal(format!("task {id} has a parent cycle")));
        }
        // The parent counts only when it is in `org` too: the
        // `tasks_org_parent` triggers keep it there, and this does not rely
        // on them.
        let parent: Option<i64> = conn
            .query_row(
                "SELECT p.id FROM tasks t JOIN tasks p ON p.id = t.parent_id AND p.org_id = ?1 \
                 WHERE t.org_id = ?1 AND t.id = ?2",
                params![org, current],
                |r| r.get(0),
            )
            .optional()?;
        match parent {
            Some(p) => {
                chain.push(p);
                current = p;
            }
            _ => break,
        }
    }
    chain.reverse();
    Ok(chain)
}

/// `id` plus every descendant, in organization `org` (empty when `id` is
/// another organization's task).
pub(crate) fn subtree_ids(conn: &Connection, org: &str, id: i64) -> UaResult<Vec<i64>> {
    let mut stmt = conn.prepare(
        "WITH RECURSIVE subtree(id) AS (
            SELECT id FROM tasks WHERE org_id = ?1 AND id = ?2
            UNION ALL
            SELECT t.id FROM tasks t JOIN subtree s ON t.parent_id = s.id WHERE t.org_id = ?1
        ) SELECT id FROM subtree",
    )?;
    let ids = stmt.query_map(params![org, id], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(ids)
}

/// Longest downward path from `id` to a leaf (0 for a leaf).
pub(crate) fn subtree_height(conn: &Connection, org: &str, id: i64) -> UaResult<usize> {
    let h: Option<i64> = conn.query_row(
        "WITH RECURSIVE subtree(id, depth) AS (
            SELECT id, 0 FROM tasks WHERE org_id = ?1 AND id = ?2
            UNION ALL
            SELECT t.id, s.depth + 1 FROM tasks t JOIN subtree s ON t.parent_id = s.id
            WHERE t.org_id = ?1 AND s.depth < 64
        ) SELECT MAX(depth) FROM subtree",
        params![org, id],
        |r| r.get(0),
    )?;
    Ok(h.unwrap_or(0).max(0) as usize)
}

/// Refuse a missing parent, a cycle, or a depth-cap breach. `moving` is the
/// task being reparented (`None` when creating a child).
pub(crate) fn check_nesting(
    conn: &Connection,
    org: &str,
    parent_id: i64,
    moving: Option<i64>,
) -> UaResult<()> {
    if moving == Some(parent_id) {
        return Err(UaError::invalid("a task cannot be its own parent"));
    }
    if task_object(conn, org, parent_id)?.is_none() {
        return Err(UaError::invalid(format!("no task with id {parent_id} to use as parent")));
    }
    let lineage = ancestors(conn, org, parent_id)?;
    if let Some(m) = moving
        && lineage.contains(&m)
    {
        return Err(UaError::invalid(format!("reparenting task {m} under {parent_id} would create a cycle")));
    }
    let extra = match moving {
        Some(m) => subtree_height(conn, org, m)?,
        None => 0,
    };
    if lineage.len() + 1 + extra > MAX_DEPTH {
        return Err(UaError::invalid(format!(
            "nesting depth cap is {MAX_DEPTH} (task {parent_id} is at depth {}{})",
            lineage.len(),
            if extra > 0 { format!(", subtree height {extra}") } else { String::new() }
        )));
    }
    Ok(())
}

/// Derived status of a `[project-spec]` root from its whole subtree.
pub(crate) fn rollup(conn: &Connection, org: &str, root: i64) -> UaResult<Value> {
    let mut stmt = conn.prepare(
        "WITH RECURSIVE subtree(id) AS (
            SELECT id FROM tasks WHERE org_id = ?1 AND parent_id = ?2
            UNION ALL
            SELECT t.id FROM tasks t JOIN subtree s ON t.parent_id = s.id WHERE t.org_id = ?1
        ) SELECT tasks.id, tasks.title, tasks.status FROM tasks JOIN subtree ON subtree.id = tasks.id
          WHERE tasks.org_id = ?1 ORDER BY tasks.id",
    )?;
    let rows: Vec<(i64, String, String)> = stmt
        .query_map(params![org, root], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let mut counts = Map::new();
    for s in STATUSES {
        counts.insert(s.into(), json!(0));
    }
    let mut active = Vec::new();
    for (id, title, status) in &rows {
        let n = counts.get(status.as_str()).and_then(Value::as_i64).unwrap_or(0);
        counts.insert(status.clone(), json!(n + 1));
        if !is_terminal(status) {
            active.push(json!({ "id": id, "status": status, "title": title }));
        }
    }
    let derived = ROLLUP_ORDER
        .into_iter()
        .find(|s| counts.get(*s).and_then(Value::as_i64).unwrap_or(0) > 0)
        .unwrap_or("done");
    Ok(json!({
        "complete": active.is_empty(),
        "derived_status": derived,
        "active": active,
        "counts": counts,
    }))
}

// ---------------------------------------------------------------------------
// Ledger and idempotency
// ---------------------------------------------------------------------------

/// Append a task event about a row of organization `org`.
///
/// ORG-EVENT-DEFAULT: the ledger row stays in the default organization until
/// `org_guard` admits another. So a non-default task's event carries no free
/// text and no caller-supplied label (callers pass titles, notes, comment
/// bodies, reasons and labels through [`ledger_text`] / [`ledger_label`]),
/// and its originator is the neutral `system`, never the acting agent.
pub(crate) fn emit(tx: &mut WriteTx<'_>, org: &str, channel: &str, payload: Value, by: &str) -> UaResult<()> {
    let by = if org == ua_core::DEFAULT_ORG { by } else { "system" };
    ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, channel, payload).by(by.to_string()))?;
    Ok(())
}

pub(crate) use crate::families::plans::{ledger_label, ledger_text};

/// The stored key of a client idempotency key. `idempotency_keys` is still a
/// hub-wide table (its `(org_id, principal, key)` rebuild is a later change),
/// so another organization's key is prefixed with its organization and can
/// never replay the default organization's reply, or a third's. The default
/// organization keeps the `<tool>:<key>` form other readers rely on.
pub(crate) fn idem_key(org: &str, tool: &str, key: &str) -> String {
    if org == ua_core::DEFAULT_ORG { format!("{tool}:{key}") } else { format!("org:{org}/{tool}:{key}") }
}

/// A stored reply for (`tool`, `key`), if this key was already used.
pub(crate) fn idempotent_replay(
    conn: &Connection,
    org: &str,
    tool: &str,
    key: &str,
) -> UaResult<Option<Value>> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT result_json FROM idempotency_keys WHERE key = ?1 AND tool = ?2",
            [idem_key(org, tool, key), tool.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(stored.map(|s| serde_json::from_str(&s).unwrap_or(Value::String(s))))
}

pub(crate) fn idempotent_record(
    tx: &WriteTx<'_>,
    org: &str,
    tool: &str,
    key: &str,
    result: &Value,
) -> UaResult<()> {
    tx.execute(
        "INSERT INTO idempotency_keys (key, tool, result_json, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![idem_key(org, tool, key), tool, result.to_string(), now()],
    )?;
    Ok(())
}

pub(crate) fn check_idempotency_key(key: Option<&str>) -> UaResult<Option<String>> {
    match key.map(str::trim) {
        None | Some("") => Ok(None),
        Some(k) if k.len() > 200 => Err(UaError::invalid("idempotency_key must be at most 200 characters")),
        Some(k) => Ok(Some(k.to_string())),
    }
}

/// Parse an action's `params` object into its typed struct. Unknown keys
/// are refused like unknown top-level arguments.
pub(crate) fn parse_params<T: serde::de::DeserializeOwned>(
    action: &str,
    params: Option<Value>,
) -> UaResult<T> {
    let v = match params {
        None | Some(Value::Null) => json!({}),
        Some(v @ Value::Object(_)) => v,
        Some(_) => return Err(UaError::invalid("params must be an object")),
    };
    serde_json::from_value(v).map_err(|e| UaError::invalid(format!("{action}: {e}")))
}
