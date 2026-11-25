//! Routines: durable, opt-in scheduled work.
//!
//! A routine fires on a five-field UTC cron schedule (`trigger: cron`) or on
//! an external event (`trigger: api|webhook`, through `routine_fire` with a
//! stable idempotency key). Each fire writes one receipt in `routine_runs`
//! and, unless skipped or suppressed, creates a task. A routine may also name
//! a reviewed workflow: each created fire then runs that workflow as the
//! routine's owner (the identity that added it), under the owner's default
//! profile, through the same governed path as any call. An unattended fire
//! (the scheduler, or someone other than a human owner firing by hand) runs
//! as an agent, never with human authority.
//!
//! Only the routine's owner, verified, or a verified human may fire or pause
//! a routine.
//!
//! Cron fires happen only in [`tick`], one transaction per tick, and the
//! unique `(routine_id, fire_key)` makes a repeated or racing tick harmless.
//! `ua serve` runs a tick once a minute when `routines_enabled` is set.
//!
//! Both tables are tenant data (`org_id`, `organization.v1.tools.routines`,
//! `routines.v2.org_indexes`). A routine belongs to its owner's organization
//! (the caller that added it); every receipt takes its routine's
//! organization, and the tools read and write only the caller's
//! organization's rows: another organization's routine answers as a missing
//! one. The scheduler has no caller: it fires every due routine with that
//! routine's own organization, and creates its task in that organization
//! (`routines.v3.task_org` keeps a receipt's task in the receipt's
//! organization). A routine's workflow still runs only in the default
//! organization (its owner's caller cannot yet be built in another), so a
//! fire elsewhere records its workflow as `not_run`.

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{ActorKind, Caller, UaError, UaResult, identity::Transport};
use ua_store::{EventInput, Procedure, SchemaPart, WriteTx, ledger};

use crate::families::plans::{row_map, write_identity};
use crate::families::tasks::check_slug;
use crate::families::workflows;
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, blocking, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "routines.v1",
    sql: "
CREATE TABLE IF NOT EXISTS routines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    notes TEXT,
    trigger TEXT NOT NULL CHECK (trigger IN ('cron','api','webhook')),
    schedule TEXT,
    lane TEXT NOT NULL,
    project TEXT NOT NULL,
    domain TEXT NOT NULL,
    concurrency TEXT NOT NULL CHECK (concurrency IN ('skip','queue')),
    catch_up TEXT NOT NULL CHECK (catch_up IN ('none','last','all')),
    paused INTEGER NOT NULL DEFAULT 0,
    cursor_at TEXT NOT NULL,
    activity_gate TEXT NOT NULL DEFAULT 'always' CHECK (activity_gate IN ('always','require_activity')),
    activity_gate_scope TEXT NOT NULL DEFAULT 'org' CHECK (activity_gate_scope IN ('org','project')),
    workflow TEXT,
    workflow_inputs TEXT,
    owner TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK ((trigger = 'cron' AND schedule IS NOT NULL) OR (trigger != 'cron' AND schedule IS NULL))
);

CREATE TABLE IF NOT EXISTS routine_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    routine_id INTEGER NOT NULL REFERENCES routines(id) ON DELETE CASCADE,
    fire_key TEXT NOT NULL,
    scheduled_for TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('created','queued','skipped','suppressed')),
    task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    reason TEXT,
    window_start TEXT,
    gate_matched INTEGER,
    subject_key TEXT,
    workflow_run_id TEXT,
    workflow_status TEXT,
    UNIQUE (routine_id, fire_key)
);
CREATE INDEX IF NOT EXISTS idx_routine_runs_task ON routine_runs(task_id);
",
};

/// `organization.v1.tools.routines`: `org_id` on `routines` and
/// `routine_runs` (existing rows backfilled to the default organization) and
/// their generated `*_org_exists` / `*_org_immutable` triggers. No key
/// rebuild: `routines` is keyed by its AUTOINCREMENT id, and the receipts'
/// `UNIQUE (routine_id, fire_key)` is led by that hub-global id, so two
/// organizations can never collide on it. Applied after `routines.v1` and
/// `organization.v1.store`.
pub const TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.tools.routines", &["routines", "routine_runs"]);

/// `routines.v2.org_indexes`: the indexes the per-organization reads use, and
/// the same-organization rule between a receipt and its routine (the
/// existence trigger alone would let a receipt in one organization point at
/// another's routine). Applied after [`TENANT_PART`], which adds the column.
pub const ORG_SCHEMA: SchemaPart = SchemaPart {
    name: "routines.v2.org_indexes",
    sql: "
CREATE INDEX IF NOT EXISTS idx_routines_org ON routines(org_id, id);
CREATE INDEX IF NOT EXISTS idx_routine_runs_org_routine ON routine_runs(org_id, routine_id, id);

CREATE TRIGGER IF NOT EXISTS routine_runs_same_org
BEFORE INSERT ON routine_runs
WHEN NEW.org_id IS NOT (SELECT org_id FROM routines WHERE id = NEW.routine_id)
BEGIN SELECT RAISE(ABORT, 'a routine run must be in its routine''s organization'); END;

CREATE TRIGGER IF NOT EXISTS routine_runs_same_org_update
BEFORE UPDATE OF routine_id ON routine_runs
WHEN NEW.org_id IS NOT (SELECT org_id FROM routines WHERE id = NEW.routine_id)
BEGIN SELECT RAISE(ABORT, 'a routine run must be in its routine''s organization'); END;
",
};

/// `routines.v3.task_org`: a routine run's `task_id` points at a task in the
/// run's own organization (the foreign key alone would accept another
/// organization's task). A missing task is still the foreign key's error.
/// Applied after `organization.v1.tools.tasks`.
pub const TASK_ORG_SCHEMA: SchemaPart = SchemaPart {
    name: "routines.v3.task_org",
    sql: "
CREATE TRIGGER IF NOT EXISTS routine_runs_task_org BEFORE INSERT ON routine_runs
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'a routine run must point at a task in its own organization'); END;
CREATE TRIGGER IF NOT EXISTS routine_runs_task_org_update BEFORE UPDATE OF task_id ON routine_runs
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'a routine run must point at a task in its own organization'); END;
",
};

const MAX_DUE_PER_TICK: usize = 100;
const MAX_RECENT_RUNS: i64 = 100;
pub const SKIP_OVERLAP: &str = "overlap";
pub const SKIP_NO_SIGNAL: &str = "no_signal";
pub const SKIP_SELF_ECHO: &str = "self_echo";
pub const SKIP_CATCH_UP_NONE: &str = "catch_up_none";
/// The skip reason older builds recorded for a fire of a routine outside the
/// default organization, before tasks carried an organization. No fire is
/// skipped for it any more (each creates its task in its routine's
/// organization); the value stays so existing receipts still read.
pub const SKIP_ORG_TASKS: &str = "org_tasks_unavailable";
const RECENT_RUN_COLUMNS: &str = "id, fire_key, scheduled_for, status, reason, subject_key, task_id, created_at, \
     window_start, gate_matched, workflow_run_id, workflow_status";

// ---------------------------------------------------------------------------
// Cron

fn parse_cron(schedule: &str) -> UaResult<croner::Cron> {
    if schedule.split_whitespace().count() != 5 {
        return Err(UaError::invalid("cron schedule must have five UTC fields"));
    }
    croner::parser::CronParser::builder()
        .seconds(croner::parser::Seconds::Disallowed)
        .year(croner::parser::Year::Disallowed)
        // Day-of-month and day-of-week must both match, as in the original hub.
        .dom_and_dow(true)
        .build()
        .parse(schedule)
        .map_err(|e| UaError::invalid(format!("invalid cron schedule: {e}")))
}

fn to_chrono(ts: jiff::Timestamp) -> UaResult<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(ts.as_second(), 0)
        .ok_or_else(|| UaError::invalid("timestamp out of range"))
}

fn from_chrono(dt: chrono::DateTime<chrono::Utc>) -> UaResult<jiff::Timestamp> {
    jiff::Timestamp::from_second(dt.timestamp())
        .map_err(|e| UaError::invalid(format!("timestamp out of range: {e}")))
}

fn minute_floor(ts: jiff::Timestamp) -> jiff::Timestamp {
    let s = ts.as_second();
    jiff::Timestamp::from_second(s - s.rem_euclid(60)).unwrap_or(ts)
}

/// Next occurrence strictly after `after`.
pub fn cron_next(schedule: &str, after: jiff::Timestamp) -> UaResult<jiff::Timestamp> {
    let cron = parse_cron(schedule)?;
    let next = cron
        .find_next_occurrence(&to_chrono(after)?, false)
        .map_err(|e| UaError::invalid(format!("cron schedule has no next occurrence: {e}")))?;
    from_chrono(next)
}

/// Latest occurrence in `(after, cutoff]`, without replaying the ones between.
fn cron_latest(
    schedule: &str,
    cutoff: jiff::Timestamp,
    after: jiff::Timestamp,
) -> UaResult<Option<jiff::Timestamp>> {
    let cron = parse_cron(schedule)?;
    let Ok(prev) = cron.find_previous_occurrence(&to_chrono(cutoff)?, true) else { return Ok(None) };
    let prev = from_chrono(prev)?;
    Ok((prev > after).then_some(prev))
}

fn parse_ts(s: &str) -> UaResult<jiff::Timestamp> {
    ua_core::time::parse_ts(s)
        .ok_or_else(|| UaError::invalid(format!("timestamp {s:?} must be RFC 3339 with an offset")))
}

// ---------------------------------------------------------------------------
// Firing

struct Fire {
    status: &'static str,
    task_id: Option<i64>,
    reason: Option<&'static str>,
    created_new: bool,
    run_row: Option<i64>,
}

/// The routine's oldest unfinished task.
fn active_task(c: &Connection, org: &str, routine_id: i64) -> UaResult<Option<i64>> {
    Ok(c.query_row(
        "SELECT t.id FROM routine_runs rr JOIN tasks t ON t.id = rr.task_id AND t.org_id = rr.org_id \
         WHERE rr.routine_id = ?1 AND rr.org_id = ?2 AND t.status NOT IN ('done','cancelled') \
         ORDER BY rr.id LIMIT 1",
        params![routine_id, org],
        |r| r.get(0),
    )
    .optional()?)
}

/// When the activity window opens: the previous fire or suppression, else creation.
fn window_start(c: &Connection, routine: &Map<String, Value>) -> UaResult<String> {
    let id = routine["id"].as_i64().unwrap_or_default();
    let prior: Option<String> = c
        .query_row(
            "SELECT created_at FROM routine_runs WHERE routine_id = ?1 AND org_id = ?2 \
             AND status IN ('created','queued','suppressed') ORDER BY id DESC LIMIT 1",
            params![id, org_of(routine)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(prior.unwrap_or_else(|| routine["created_at"].as_str().unwrap_or_default().to_string()))
}

/// `(matched, echoes)`: activity in the gate's scope at or after `since`.
/// Tasks any routine created, events about them, routine bookkeeping and the
/// workflow runs routines started are echoes, never activity. Only the
/// routine's organization counts: its tasks, its receipts and its ledger
/// rows.
fn scope_activity(c: &Connection, routine: &Map<String, Value>, since: &str) -> UaResult<(i64, i64)> {
    let project_scope = i64::from(routine["activity_gate_scope"] == "project");
    let project = routine["project"].as_str().unwrap_or_default();
    let org = org_of(routine);
    let own = "SELECT task_id FROM routine_runs WHERE task_id IS NOT NULL AND org_id = ?4";
    let own_runs =
        "SELECT workflow_run_id FROM routine_runs WHERE workflow_run_id IS NOT NULL AND org_id = ?4";
    let (tasks, task_echoes): (i64, i64) = c.query_row(
        &format!(
            "SELECT count(*), COALESCE(SUM(id IN ({own})), 0) FROM tasks \
             WHERE org_id = ?4 AND (created_at >= ?1 OR updated_at >= ?1) AND (?2 = 0 OR project = ?3)"
        ),
        params![since, project_scope, project, org],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (events, event_echoes): (i64, i64) = c.query_row(
        &format!(
            "WITH ev AS (SELECT dedupe_key, CAST(json_extract(payload, '$.task_id') AS INTEGER) AS task_id, \
             json_extract(payload, '$.run_id') AS run_id FROM event_log WHERE created_at >= ?1 AND org_id = ?4) \
             SELECT count(*), COALESCE(SUM((dedupe_key IS NOT NULL AND (dedupe_key LIKE 'routine:%' \
             OR dedupe_key LIKE 'routine-run:%')) OR (task_id IS NOT NULL AND task_id IN ({own})) \
             OR (run_id IS NOT NULL AND run_id IN ({own_runs}))), 0) FROM ev \
             WHERE (?2 = 0 OR task_id IN (SELECT id FROM tasks WHERE org_id = ?4 AND project = ?3))"
        ),
        params![since, project_scope, project, org],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let echoes = task_echoes + event_echoes;
    Ok((tasks + events - echoes, echoes))
}

fn create_fire(
    tx: &mut WriteTx<'_>,
    routine: &Map<String, Value>,
    fire_key: &str,
    at: jiff::Timestamp,
    by: &str,
) -> UaResult<Fire> {
    let id = routine["id"].as_i64().unwrap_or_default();
    let org = org_of(routine).to_string();
    let prior: Option<(String, Option<i64>)> = tx
        .query_row(
            "SELECT status, task_id FROM routine_runs WHERE routine_id = ?1 AND fire_key = ?2 AND org_id = ?3",
            params![id, fire_key, org],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((status, task_id)) = prior {
        let status = match status.as_str() {
            "created" => "created",
            "queued" => "queued",
            "skipped" => "skipped",
            _ => "suppressed",
        };
        return Ok(Fire { status, task_id, reason: None, created_new: false, run_row: None });
    }
    // The fire's task is created in the routine's own organization.
    let active = active_task(tx, &org, id)?;
    let skip = active.is_some() && routine["concurrency"] == "skip";
    let mut subject_key = format!("routine:{id}");
    let (mut win, mut matched, mut echoes) = (None, None, 0);
    if !skip && routine["activity_gate"] == "require_activity" {
        let since = window_start(tx, routine)?;
        let (m, e) = scope_activity(tx, routine, &since)?;
        win = Some(since);
        matched = Some(m);
        echoes = e;
    }
    let now = ua_core::time::now();
    let at_text = ua_core::time::format_ts(at);
    let (status, task_id, reason) = if skip {
        subject_key = format!("task:{}", active.unwrap_or_default());
        ("skipped", None, Some(SKIP_OVERLAP))
    } else if matched == Some(0) {
        subject_key = if routine["activity_gate_scope"] == "project" {
            format!("project:{}", routine["project"].as_str().unwrap_or_default())
        } else {
            format!("org:{org}")
        };
        ("suppressed", None, Some(if echoes > 0 { SKIP_SELF_ECHO } else { SKIP_NO_SIGNAL }))
    } else {
        let status = if active.is_some() { "queued" } else { "created" };
        let notes = routine["notes"].as_str().unwrap_or_default().trim().to_string();
        let marker = format!("[routine: {id}] [scheduled: {at_text}]");
        let notes = if notes.is_empty() { marker } else { format!("{notes}\n{marker}") };
        tx.execute(
            "INSERT INTO tasks (title, notes, status, priority, created_at, updated_at, project, domain, lane, \
             org_id) VALUES (?1, ?2, ?3, 'med', ?4, ?4, ?5, ?6, ?7, ?8)",
            params![
                routine["title"].as_str().unwrap_or_default(),
                notes,
                if status == "queued" { "blocked" } else { "open" },
                now,
                routine["project"].as_str().unwrap_or("default"),
                routine["domain"].as_str().unwrap_or("general"),
                routine["lane"].as_str().unwrap_or("default"),
                org,
            ],
        )?;
        let task_id = tx.last_insert_rowid();
        crate::families::tasks::emit(
            tx,
            &org,
            "agent.task.created",
            json!({ "task_id": task_id, "routine_id": id, "status": if status == "queued" { "blocked" } else { "open" } }),
            by,
        )?;
        (status, Some(task_id), None)
    };
    tx.execute(
        "INSERT INTO routine_runs (org_id, routine_id, fire_key, scheduled_for, status, task_id, created_at, \
         reason, window_start, gate_matched, subject_key) VALUES (?11, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![id, fire_key, at_text, status, task_id, now, reason, win, matched, subject_key, org],
    )?;
    let run_row = tx.last_insert_rowid();
    // ORG-EVENT-DEFAULT: the event stays in the default organization's
    // ledger. Another organization's fire key (client text for an api fire,
    // a schedule time for a cron one) never reaches it, not even as an
    // unsalted digest, which a guess could confirm: the event names the
    // hub-generated receipt row instead (`run:<id>`, unique per fire like the
    // key), and its originator is the neutral `system`.
    let event_key =
        if org == ua_core::DEFAULT_ORG { fire_key.to_string() } else { format!("run:{run_row}") };
    ledger::append(
        tx,
        EventInput::new(ua_core::DEFAULT_ORG,
            "agent.routine.fired",
            json!({ "routine_id": id, "fire_key": event_key, "status": status, "task_id": task_id, "reason": reason }),
        )
        .by(crate::approvals::ledger_originator(&org, by))
        .dedupe(format!("routine:{id}:{event_key}:create")),
    )?;
    Ok(Fire { status, task_id, reason, created_new: true, run_row: Some(run_row) })
}

/// Open the oldest queued task of each routine once its earlier work is done.
/// Returns the released `routine_runs` row ids. Runs for every organization;
/// each receipt is compared only with its own organization's.
fn release_queued(tx: &mut WriteTx<'_>) -> UaResult<Vec<i64>> {
    let rows: Vec<(i64, String, i64, i64)> = {
        let mut stmt = tx.prepare(
            "SELECT rr.id, rr.org_id, rr.routine_id, rr.task_id FROM routine_runs rr \
             JOIN tasks t ON t.id = rr.task_id AND t.org_id = rr.org_id \
             WHERE rr.status = 'queued' AND t.status = 'blocked' ORDER BY rr.id",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<_, _>>()?
    };
    let mut released = Vec::new();
    for (row_id, org, routine_id, task_id) in rows {
        let earlier: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM routine_runs old JOIN tasks t ON t.id = old.task_id AND t.org_id = old.org_id \
                 WHERE old.routine_id = ?1 \
                 AND old.org_id = ?3 AND old.id < ?2 AND t.status NOT IN ('done','cancelled') LIMIT 1",
                params![routine_id, row_id, org],
                |r| r.get(0),
            )
            .optional()?;
        if earlier.is_some() {
            continue;
        }
        let now = ua_core::time::now();
        tx.execute(
            "UPDATE tasks SET status = 'open', updated_at = ?2 WHERE id = ?1 AND org_id = ?3",
            params![task_id, now, org],
        )?;
        tx.execute(
            "UPDATE routine_runs SET status = 'created' WHERE id = ?1 AND org_id = ?2",
            params![row_id, org],
        )?;
        ledger::append(
            tx,
            EventInput::new(
                ua_core::DEFAULT_ORG,
                "agent.routine.released",
                json!({ "routine_id": routine_id, "task_id": task_id, "status": "open" }),
            )
            .by("routines")
            .dedupe(format!("routine-run:{row_id}:release")),
        )?;
        released.push(row_id);
    }
    Ok(released)
}

/// A routine of `org` by id; another organization's answers as a missing one.
fn routine_by_id(c: &Connection, org: &str, id: i64) -> UaResult<Option<Map<String, Value>>> {
    Ok(c.query_row("SELECT * FROM routines WHERE id = ?1 AND org_id = ?2", params![id, org], row_map)
        .optional()?)
}

/// The organization a stored routine (or receipt) row belongs to.
fn org_of(row: &Map<String, Value>) -> &str {
    row.get("org_id").and_then(Value::as_str).unwrap_or_default()
}

/// Refuse an organization `orgs` does not hold, before anything is written.
/// Organizations are never deleted, so the check cannot go stale.
fn require_org(c: &Connection, org: &str) -> UaResult<()> {
    let known = c.query_row("SELECT 1 FROM orgs WHERE id = ?1", [org], |_| Ok(())).optional()?;
    if known.is_none() {
        return Err(UaError::invalid(format!("unknown organization {org:?}; no routine was changed")));
    }
    Ok(())
}

/// Whether `caller` may fire or pause a routine owned by `owner`: the owner
/// itself, verified, or a verified human.
fn may_operate(caller: &Caller, owner: &str) -> bool {
    caller.is_human() || (caller.kind == ActorKind::Agent && caller.label == owner)
}

fn require_operator(caller: &Caller, routine: &Map<String, Value>) -> UaResult<()> {
    let owner = routine["owner"].as_str().unwrap_or_default();
    if may_operate(caller, owner) {
        Ok(())
    } else {
        Err(UaError::denied(
            "not_owner",
            format!("only the routine's owner ({owner:?}), verified, or a verified human may do this"),
        ))
    }
}

/// The caller a routine's workflow runs as: its owner, never wider than the
/// owner's configured default profile, always profile-enforced. Human
/// authority is carried only when `attended` (the human owner fired it in
/// person); an unattended run is an agent under the owner's label, so policy
/// overlays clamp it like any agent.
fn owner_caller(hub: &Hub, owner: &str, attended: bool) -> Caller {
    let kind = if attended && hub.cfg().is_human(owner) { ActorKind::Human } else { ActorKind::Agent };
    Caller {
        label: owner.to_string(),
        kind,
        profile: crate::sessions::default_profile(hub, ua_core::DEFAULT_ORG, owner),
        enforce_profile: true,
        session_key: None,
        transport: Transport::Internal,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

/// Run the routine's workflow for one created fire and record the outcome.
/// The run takes the receipt's organization (its routine's), never a
/// caller's.
async fn run_fire_workflow(hub: &Hub, run_row: i64, attended: bool) -> Option<Value> {
    let loaded = hub
        .db()
        .read_async(move |c| {
            let receipt: Option<(i64, String)> = c
                .query_row("SELECT routine_id, org_id FROM routine_runs WHERE id = ?1", [run_row], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            Ok(match receipt {
                Some((id, org)) => routine_by_id(c, &org, id)?,
                None => None,
            })
        })
        .await
        .ok()
        .flatten()?;
    let workflow = loaded.get("workflow").and_then(Value::as_str)?.to_string();
    let org = org_of(&loaded).to_string();
    if org != ua_core::DEFAULT_ORG {
        // The owner's caller can only be built in the default organization
        // until the resolver binds others (`org_guard`), and a workflow must
        // never run one organization's routine under another's caller. The
        // fire's task exists in the routine's organization; its workflow is
        // recorded as not run.
        let o = org.clone();
        let _ = hub
            .db()
            .write_async(move |tx| {
                tx.execute(
                    "UPDATE routine_runs SET workflow_status = 'not_run' WHERE id = ?1 AND org_id = ?2",
                    params![run_row, o],
                )?;
                Ok(())
            })
            .await;
        return Some(json!({
            "routine_id": loaded.get("id"),
            "workflow": workflow,
            "run_id": null,
            "status": "not_run",
            "error": format!("routine workflows run only in the {:?} organization", ua_core::DEFAULT_ORG),
        }));
    }
    let owner = loaded["owner"].as_str().unwrap_or_default().to_string();
    let inputs: Map<String, Value> = loaded
        .get("workflow_inputs")
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let caller = owner_caller(hub, &owner, attended);
    let actor_kind = caller.kind;
    // Mark the fire before its workflow starts, so a hub that stops midway
    // leaves `running` (reconciled as interrupted at the next start), never
    // a fire that looks unstarted and would run twice.
    let o = org.clone();
    let _ = hub
        .db()
        .write_async(move |tx| {
            tx.execute(
                "UPDATE routine_runs SET workflow_status = 'running' WHERE id = ?1 AND org_id = ?2",
                params![run_row, o],
            )?;
            Ok(())
        })
        .await;
    let (status, run_id, error) = match workflows::run_as(hub, &caller, &org, &workflow, inputs).await {
        Ok(report) => (report.status.clone(), Some(report.run_id.clone()), report.error.clone()),
        Err(e) => ("error".to_string(), None, Some(e.to_string())),
    };
    let (st, rid) = (status.clone(), run_id.clone());
    let _ = hub
        .db()
        .write_async(move |tx| {
            tx.execute(
                "UPDATE routine_runs SET workflow_run_id = ?2, workflow_status = ?3 WHERE id = ?1 AND org_id = ?4",
                params![run_row, rid, st, org],
            )?;
            Ok(())
        })
        .await;
    Some(json!({
        "routine_id": loaded.get("id"),
        "workflow": workflow,
        "run_id": run_id,
        "status": status,
        "error": error,
        "actor_kind": actor_kind,
    }))
}

/// Fires with a workflow younger than this that never started are run at
/// the next start; older ones are marked `not_run`.
const RERUN_WINDOW_S: i64 = 24 * 3600;

/// Reconcile routine fires a previous hub process left behind (`ua serve`
/// runs it at startup, before the ticker):
/// - a fire whose workflow was running (`workflow_status = 'running'`) is
///   marked `interrupted`: part of it may have run, so it is not repeated;
/// - a `created` fire of a routine with a workflow that never started
///   (`workflow_status` unset) runs its workflow now when it is less than a
///   day old, and is marked `not_run` otherwise.
///
/// Each mark is ledgered as `agent.routine.fire_reconciled`.
pub async fn reconcile_fires(hub: &Hub) -> UaResult<Value> {
    let cutoff = ua_core::time::format_ts(
        jiff::Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_secs(RERUN_WINDOW_S))
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH),
    );
    let (interrupted, stale, rerun) = hub
        .db()
        .write_async(move |tx| {
            let ids = |tx: &WriteTx<'_>, sql: &str, p: &[&dyn rusqlite::ToSql]| -> UaResult<Vec<i64>> {
                let mut stmt = tx.prepare(sql)?;
                Ok(stmt.query_map(p, |r| r.get(0))?.collect::<Result<_, _>>()?)
            };
            let interrupted =
                ids(tx, "SELECT id FROM routine_runs WHERE workflow_status = 'running' ORDER BY id", &[])?;
            let unstarted = "SELECT rr.id FROM routine_runs rr \
                 JOIN routines r ON r.id = rr.routine_id AND r.org_id = rr.org_id \
                 WHERE rr.status = 'created' AND rr.workflow_status IS NULL AND r.workflow IS NOT NULL";
            let stale = ids(tx, &format!("{unstarted} AND rr.created_at < ?1 ORDER BY rr.id"), &[&cutoff])?;
            let rerun = ids(tx, &format!("{unstarted} AND rr.created_at >= ?1 ORDER BY rr.id"), &[&cutoff])?;
            for (list, status) in [(&interrupted, "interrupted"), (&stale, "not_run")] {
                for id in list {
                    tx.execute(
                        "UPDATE routine_runs SET workflow_status = ?2 WHERE id = ?1",
                        params![id, status],
                    )?;
                    ledger::append(
                        tx,
                        EventInput::new(
                            ua_core::DEFAULT_ORG,
                            "agent.routine.fire_reconciled",
                            json!({ "routine_run_id": id, "workflow_status": status }),
                        )
                        .by("routines"),
                    )?;
                }
            }
            Ok((interrupted, stale, rerun))
        })
        .await?;
    let mut runs = Vec::new();
    for id in &rerun {
        if let Some(r) = run_fire_workflow(hub, *id, false).await {
            runs.push(r);
        }
    }
    Ok(json!({ "interrupted": interrupted, "not_run": stale, "rerun": rerun, "workflows": runs }))
}

// ---------------------------------------------------------------------------
// tick

fn count(result: &mut Value, fire: &Fire) {
    if let Some(n) = result.get_mut(fire.status) {
        *n = json!(n.as_i64().unwrap_or(0) + 1);
    }
    if let Some(reason) = fire.reason {
        let reasons = &mut result["skip_reasons"];
        reasons[reason] = json!(reasons.get(reason).and_then(Value::as_i64).unwrap_or(0) + 1);
    }
}

/// Run one scheduler tick at `now`: release queued tasks whose earlier work
/// finished, fire every due cron routine, then run the workflows of created
/// and released fires. Safe to repeat for the same `now`. Without `force`, a
/// hub with `routines_enabled` unset does nothing.
pub async fn tick(hub: &Hub, now: jiff::Timestamp, force: bool) -> UaResult<Value> {
    if !force && !hub.cfg().routines_enabled {
        return Ok(json!({ "status": "disabled", "created": 0, "queued": 0, "skipped": 0 }));
    }
    let cutoff = minute_floor(now);
    let (result, to_run) = hub
        .db()
        .write_async(move |tx| {
            let mut result = json!({
                "status": "ok",
                "created": 0,
                "queued": 0,
                "skipped": 0,
                "suppressed": 0,
                "released": 0,
                "skip_reasons": {},
            });
            let mut to_run = release_queued(tx)?;
            result["released"] = json!(to_run.len());
            // Every organization's due routines; each fire takes its routine's
            // organization.
            let routines: Vec<Map<String, Value>> = {
                let mut stmt =
                    tx.prepare("SELECT * FROM routines WHERE trigger = 'cron' AND paused = 0 ORDER BY id")?;
                stmt.query_map([], row_map)?.collect::<Result<_, _>>()?
            };
            for routine in routines {
                let id = routine["id"].as_i64().unwrap_or_default();
                let schedule = routine["schedule"].as_str().unwrap_or_default().to_string();
                let mut cursor = parse_ts(routine["cursor_at"].as_str().unwrap_or_default())?;
                let catch_up = routine["catch_up"].as_str().unwrap_or("last").to_string();
                let mut fired = Vec::new();
                if catch_up != "all" {
                    let Some(latest) = cron_latest(&schedule, cutoff, cursor)? else { continue };
                    if catch_up == "last" || latest == cutoff {
                        let key = format!("cron:{}", ua_core::time::format_ts(latest));
                        fired.push(create_fire(tx, &routine, &key, latest, "routines")?);
                    } else {
                        let key = format!("cron:{}", ua_core::time::format_ts(latest));
                        let n = tx.execute(
                            "INSERT INTO routine_runs (org_id, routine_id, fire_key, scheduled_for, status, \
                             created_at, reason, subject_key) VALUES (?7, ?1, ?2, ?3, 'skipped', ?4, ?5, ?6) \
                             ON CONFLICT (routine_id, fire_key) DO NOTHING",
                            params![
                                id,
                                key,
                                ua_core::time::format_ts(latest),
                                ua_core::time::now(),
                                SKIP_CATCH_UP_NONE,
                                format!("routine:{id}"),
                                org_of(&routine),
                            ],
                        )?;
                        if n == 1 {
                            count(
                                &mut result,
                                &Fire {
                                    status: "skipped",
                                    task_id: None,
                                    reason: Some(SKIP_CATCH_UP_NONE),
                                    created_new: true,
                                    run_row: None,
                                },
                            );
                        }
                    }
                    cursor = cutoff;
                } else {
                    let mut due = Vec::new();
                    let mut candidate = cron_next(&schedule, cursor)?;
                    while candidate <= cutoff && due.len() < MAX_DUE_PER_TICK {
                        due.push(candidate);
                        cursor = candidate;
                        candidate = cron_next(&schedule, cursor)?;
                    }
                    if due.is_empty() {
                        continue;
                    }
                    if due.len() == MAX_DUE_PER_TICK && candidate <= cutoff {
                        result["backlog"] = json!(true);
                    }
                    for at in due {
                        let key = format!("cron:{}", ua_core::time::format_ts(at));
                        fired.push(create_fire(tx, &routine, &key, at, "routines")?);
                    }
                }
                for fire in &fired {
                    if fire.created_new {
                        count(&mut result, fire);
                        if fire.status == "created"
                            && let Some(row) = fire.run_row
                        {
                            to_run.push(row);
                        }
                    }
                }
                tx.execute(
                    "UPDATE routines SET cursor_at = ?2, updated_at = ?3 WHERE id = ?1 AND org_id = ?4",
                    params![id, ua_core::time::format_ts(cursor), ua_core::time::now(), org_of(&routine)],
                )?;
            }
            Ok((result, to_run))
        })
        .await?;
    let mut result = result;
    let mut runs = Vec::new();
    for row in to_run {
        if let Some(r) = run_fire_workflow(hub, row, false).await {
            runs.push(r);
        }
    }
    if !runs.is_empty() {
        result["workflows"] = Value::Array(runs);
    }
    Ok(result)
}

/// Tick once a minute, on the minute, until `ct` is cancelled. Spawned by
/// `ua serve` when `routines_enabled` is set. Cancellation is honoured
/// between ticks: a tick in progress runs to the end.
pub async fn run_ticker(hub: Hub, ct: tokio_util::sync::CancellationToken) {
    loop {
        let now = jiff::Timestamp::now();
        let wait = 60 - now.as_second().rem_euclid(60);
        tokio::select! {
            biased;
            _ = ct.cancelled() => return,
            _ = tokio::time::sleep(std::time::Duration::from_secs(wait as u64)) => {}
        }
        if let Err(e) = tick(&hub, jiff::Timestamp::now(), false).await {
            tracing::warn!(error = %e, "routine tick failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Tools

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddArgs {
    /// One line, at most 200 characters; the title of every task it creates.
    pub title: String,
    /// `cron` (default), `api` or `webhook`.
    #[serde(default = "cron")]
    pub trigger: String,
    /// Five UTC cron fields; required for `cron`, refused otherwise.
    pub schedule: Option<String>,
    /// Notes copied into every created task.
    pub notes: Option<String>,
    #[serde(default = "default_slug")]
    pub lane: String,
    #[serde(default = "default_slug")]
    pub project: String,
    #[serde(default = "general")]
    pub domain: String,
    /// `skip` (default: no new task while one is unfinished) or `queue`.
    #[serde(default = "skip")]
    pub concurrency: String,
    /// Missed cron slots: `last` (default, fire the latest once), `all` or `none`.
    #[serde(default = "last")]
    pub catch_up: String,
    /// RFC 3339 time the schedule starts from (default now).
    pub start_at: Option<String>,
    /// `always` (default) or `require_activity`: suppress a fire when nothing
    /// happened in the gate scope since the previous fire.
    #[serde(default = "always")]
    pub activity_gate: String,
    /// `org` (default) or `project`.
    #[serde(default = "org")]
    pub activity_gate_scope: String,
    /// A reviewed workflow to run, as the routine's owner, on every created fire.
    pub workflow: Option<String>,
    /// Inputs for `workflow`.
    pub inputs: Option<Map<String, Value>>,
}

fn cron() -> String {
    "cron".into()
}
fn default_slug() -> String {
    "default".into()
}
fn general() -> String {
    "general".into()
}
fn skip() -> String {
    "skip".into()
}
fn last() -> String {
    "last".into()
}
fn always() -> String {
    "always".into()
}
fn org() -> String {
    "org".into()
}

async fn routine_add(ctx: ToolCtx, a: AddArgs) -> UaResult<Value> {
    let owner = write_identity(&ctx.caller, None)?;
    let title = a.title.trim().to_string();
    if title.is_empty() || title.contains('\n') || title.len() > 200 {
        return Err(UaError::invalid("title must be one nonempty line of at most 200 characters"));
    }
    if !["cron", "api", "webhook"].contains(&a.trigger.as_str()) {
        return Err(UaError::invalid("trigger must be cron, api, or webhook"));
    }
    if (a.trigger == "cron") != a.schedule.is_some() {
        return Err(UaError::invalid("cron requires schedule; api/webhook must omit it"));
    }
    if !["always", "require_activity"].contains(&a.activity_gate.as_str()) {
        return Err(UaError::invalid("activity_gate must be always or require_activity"));
    }
    if !["org", "project"].contains(&a.activity_gate_scope.as_str()) {
        return Err(UaError::invalid("activity_gate_scope must be org or project"));
    }
    if !["skip", "queue"].contains(&a.concurrency.as_str())
        || !["none", "last", "all"].contains(&a.catch_up.as_str())
    {
        return Err(UaError::invalid("invalid concurrency or catch_up policy"));
    }
    let project = check_slug("project", &a.project)?;
    let domain = check_slug("domain", &a.domain)?;
    let lane = check_slug("lane", &a.lane)?;
    let start = match &a.start_at {
        Some(s) => parse_ts(s)?,
        None => jiff::Timestamp::now(),
    };
    if let Some(schedule) = &a.schedule {
        cron_next(schedule, start)?;
    }
    if a.inputs.is_some() && a.workflow.is_none() {
        return Err(UaError::invalid("inputs require a workflow"));
    }
    let inputs = a.inputs.unwrap_or_default();
    if let Some(name) = a.workflow.clone() {
        let cfg = ctx.hub.cfg().clone();
        let ins = inputs.clone();
        blocking(move || {
            let def = workflows::load(&cfg, &name)?;
            workflows::check_inputs(&def, &ins)
        })
        .await?;
    }
    let inputs_text = a.workflow.as_ref().map(|_| serde_json::to_string(&inputs)).transpose()?;
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let now = ua_core::time::now();
            tx.execute(
                "INSERT INTO routines (org_id, title, notes, trigger, schedule, lane, project, domain, concurrency, \
                 catch_up, cursor_at, activity_gate, activity_gate_scope, workflow, workflow_inputs, owner, \
                 created_at, updated_at) \
                 VALUES (?17, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16)",
                params![
                    title,
                    a.notes,
                    a.trigger,
                    a.schedule.map(|s| s.trim().to_string()),
                    lane,
                    project,
                    domain,
                    a.concurrency,
                    a.catch_up,
                    ua_core::time::format_ts(start),
                    a.activity_gate,
                    a.activity_gate_scope,
                    a.workflow,
                    inputs_text,
                    owner,
                    now,
                    org
                ],
            )?;
            let id = tx.last_insert_rowid();
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG, "agent.routine.added", json!({ "routine_id": id, "trigger": a.trigger }))
                    .by(owner.clone()),
            )?;
            Ok(json!({ "id": id }))
        })
        .await
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    #[serde(default = "yes")]
    pub include_paused: bool,
    /// Newest receipts per routine, 0-100.
    #[serde(default)]
    pub recent_runs: i64,
}

fn yes() -> bool {
    true
}

async fn routine_list(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    let limit = a.recent_runs.min(MAX_RECENT_RUNS);
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt =
                c.prepare("SELECT * FROM routines WHERE org_id = ?2 AND (?1 OR paused = 0) ORDER BY id")?;
            let mut routines: Vec<Map<String, Value>> =
                stmt.query_map(params![a.include_paused, org], row_map)?.collect::<Result<_, _>>()?;
            for r in &mut routines {
                if let Some(text) = r.get("workflow_inputs").and_then(Value::as_str) {
                    let parsed = serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
                    r.insert("workflow_inputs".into(), parsed);
                }
                if limit > 0 {
                    let mut s = c.prepare(&format!(
                        "SELECT {RECENT_RUN_COLUMNS} FROM routine_runs WHERE routine_id = ?1 AND org_id = ?3 \
                         ORDER BY id DESC LIMIT ?2"
                    ))?;
                    let runs: Vec<Value> = s
                        .query_map(params![r["id"].as_i64(), limit, org], |row| {
                            Ok(Value::Object(row_map(row)?))
                        })?
                        .collect::<Result<_, _>>()?;
                    r.insert("recent_runs".into(), Value::Array(runs));
                }
            }
            Ok(json!({ "routines": routines }))
        })
        .await
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PauseArgs {
    pub routine_id: i64,
    /// `false` resumes; the schedule restarts from now (no catch-up of the pause).
    #[serde(default = "yes")]
    pub paused: bool,
}

async fn routine_pause(ctx: ToolCtx, a: PauseArgs) -> UaResult<Value> {
    let caller = ctx.caller.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let org = caller.org_id.as_str();
            require_org(tx, org)?;
            let routine =
                routine_by_id(tx, org, a.routine_id)?.ok_or_else(|| UaError::not_found("unknown routine"))?;
            require_operator(&caller, &routine)?;
            let previous = routine["paused"].as_i64().unwrap_or(0) != 0;
            let now = ua_core::time::now();
            tx.execute(
                "UPDATE routines SET paused = ?2, updated_at = ?3, \
                 cursor_at = CASE WHEN paused = 1 AND ?2 = 0 THEN ?3 ELSE cursor_at END WHERE id = ?1 AND org_id = ?4",
                params![a.routine_id, a.paused, now, org],
            )?;
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG,
                    "agent.routine.paused",
                    json!({ "routine_id": a.routine_id, "paused": a.paused, "previous_paused": previous }),
                )
                .by(caller.label.clone()),
            )?;
            Ok(json!({ "id": a.routine_id, "paused": i64::from(a.paused), "previous_paused": i64::from(previous) }))
        })
        .await
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FireArgs {
    pub routine_id: i64,
    /// Stable source event id (1-200 characters); a replay returns the same task.
    pub idempotency_key: String,
}

async fn routine_fire(ctx: ToolCtx, a: FireArgs) -> UaResult<Value> {
    if !ctx.hub.cfg().routines_enabled {
        return Err(UaError::denied("routines_disabled", "routines are disabled; set routines_enabled"));
    }
    if a.idempotency_key.is_empty() || a.idempotency_key.len() > 200 {
        return Err(UaError::invalid("idempotency_key must be 1-200 characters"));
    }
    let caller = ctx.caller.clone();
    let by = caller.label.clone();
    let fire = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let org = caller.org_id.clone();
            require_org(tx, &org)?;
            let routine =
                routine_by_id(tx, &org, a.routine_id)?.ok_or_else(|| UaError::not_found("unknown routine"))?;
            require_operator(&caller, &routine)?;
            // Human authority only when the human owner fires in person.
            let attended = caller.is_human() && routine["owner"].as_str() == Some(caller.label.as_str());
            let key = format!("event:{}", a.idempotency_key);
            let previous: Option<(String, Option<i64>)> = tx
                .query_row(
                    "SELECT status, task_id FROM routine_runs WHERE routine_id = ?1 AND fire_key = ?2 AND org_id = ?3",
                    params![a.routine_id, key, org],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((status, task_id)) = previous {
                return Ok((
                    json!({ "status": status, "task_id": task_id, "replayed": true }),
                    None,
                    attended,
                ));
            }
            if routine["paused"].as_i64() == Some(1) {
                return Err(UaError::conflict("routine is paused"));
            }
            if routine["trigger"] == "cron" {
                return Err(UaError::invalid("cron routines are fired by the scheduler"));
            }
            let fire = create_fire(tx, &routine, &key, jiff::Timestamp::now(), &by)?;
            let run = (fire.status == "created").then_some(fire.run_row).flatten();
            let mut out = json!({ "status": fire.status, "task_id": fire.task_id });
            if let Some(reason) = fire.reason {
                out["reason"] = json!(reason);
            }
            Ok((out, run, attended))
        })
        .await?;
    let (mut out, run, attended) = fire;
    if let Some(row) = run
        && let Some(r) = run_fire_workflow(&ctx.hub, row, attended).await
    {
        out["workflow"] = r;
    }
    Ok(out)
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "routine_add",
            "Store a routine: a cron schedule (five UTC fields) or an api/webhook trigger that creates a \
             task per fire, with concurrency (skip|queue), catch_up (none|last|all) and an optional activity \
             gate. `workflow` names a reviewed workflow the routine runs as its owner on each created fire. \
             Cron fires happen only when the hub has routines_enabled. Returns {id}.",
            routine_add,
        )
        .family("routines"),
    );
    r.add(
        tool(
            "routine_list",
            "List routine definitions; recent_runs above 0 (max 100) adds each routine's newest fire \
             receipts with status, reason, task_id and workflow run.",
            routine_list,
        )
        .family("routines")
        .read_only(),
    );
    r.add(
        tool(
            "routine_pause",
            "Pause or resume a routine. Only its owner (verified) or a verified human may. Returns {id, paused, \
             previous_paused}.",
            routine_pause,
        )
        .family("routines"),
    );
    r.add(
        tool(
            "routine_fire",
            "Fire an api/webhook routine with a stable source event id; a replay returns the same task. Only \
             the routine's owner (verified) or a verified human may fire it; its workflow runs as the owner, \
             with human authority only when a human owner fires it in person. Cron routines are fired only by \
             the scheduler. Needs routines_enabled.",
            routine_fire,
        )
        .handler_may_gate(crate::HandlerGate::Always)
        .family("routines"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_is_five_fields_and_deterministic() {
        assert!(parse_cron("* * * * * *").is_err());
        assert!(parse_cron("61 * * * *").is_err());
        let t = parse_ts("2026-01-01T10:00:30+00:00").unwrap();
        let next = cron_next("*/15 * * * *", t).unwrap();
        assert_eq!(ua_core::time::format_ts(next), "2026-01-01T10:15:00+00:00");
        let latest = cron_latest("0 * * * *", parse_ts("2026-01-01T12:30:00+00:00").unwrap(), t).unwrap();
        assert_eq!(latest.map(ua_core::time::format_ts).as_deref(), Some("2026-01-01T12:00:00+00:00"));
    }
}
