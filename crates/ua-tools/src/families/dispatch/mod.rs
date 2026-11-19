//! Dispatch: a task handed to an agent harness (a CLI coding agent run as a
//! child process), tracked as a run with a lease and a fence, and reported
//! back.
//!
//! Tools: `dispatch_task` (always gated), `dispatch_report_self`,
//! `dispatch_cancel`, `dispatch_resume` (always gated),
//! `dispatch_retry_cancellation`, `dispatch_confirm_cancellation`,
//! `dispatch_delivery_receipt` and `dispatch_delivery_receipts_list`.
//!
//! Every run state change goes through [`transition`], which checks the edge
//! against [`states::legal`] and writes it as a compare-and-swap on
//! `(run_id, state, fence, termination_outcome)`. The fence is the run's
//! generation: it starts at 1 and grows on every resume, so a report or a
//! supervisor from an earlier attempt can never move the current one.
//!
//! Cancellation keeps three claims apart, as in the original hub: intent
//! recorded (`termination_outcome = 'requested'`), a stop attempted, and
//! cessation confirmed (`confirmed`) or not (`unknown`). A run whose
//! cessation is not confirmed keeps its task's live slot and cannot be
//! resumed until an operator retries or confirms the cancellation.

pub mod executor;
pub mod reaper;
pub mod states;
mod tools;

use rusqlite::types::Value as Sql;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

pub use reaper::{reap_expired_leases, spawn_reaper};

use crate::registry::Registry;

pub const CHANNEL_TRANSITION: &str = "agent.dispatch.transition";

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "dispatch.v1",
    sql: "
CREATE TABLE IF NOT EXISTS dispatch_runs (
    run_id TEXT PRIMARY KEY,
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    delegation_id INTEGER,
    agent_label TEXT NOT NULL,
    harness TEXT,
    state TEXT NOT NULL CHECK (state IN (
        'claimed','launched','running','finished','failed','retryable',
        'blocked','denied','cancelled','expired')),
    actor TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    attempt INTEGER NOT NULL DEFAULT 1,
    fence INTEGER NOT NULL DEFAULT 1,
    failure_reason TEXT,
    failure_class TEXT,
    evidence_ref TEXT,
    termination_outcome TEXT CHECK (termination_outcome IS NULL
        OR termination_outcome IN ('requested','confirmed','unknown')),
    workdir TEXT,
    prompt TEXT,
    prompt_sha256 TEXT,
    pid INTEGER,
    log_path TEXT,
    exit_code INTEGER,
    exit_signal INTEGER,
    timed_out INTEGER NOT NULL DEFAULT 0,
    output_bytes INTEGER,
    output_truncated INTEGER NOT NULL DEFAULT 0,
    usage TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    ended_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_dispatch_runs_task ON dispatch_runs(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_dispatch_runs_state ON dispatch_runs(state);
-- One live slot per task: a live run, or a cancellation whose cessation is
-- not confirmed, holds it.
CREATE UNIQUE INDEX IF NOT EXISTS idx_dispatch_runs_live_task ON dispatch_runs(task_id)
    WHERE state IN ('claimed','launched','running')
       OR (state = 'cancelled' AND (termination_outcome IS NULL OR termination_outcome != 'confirmed'));

-- One row per recorded outcome of a run attempt: who reported what, with a
-- hash over the row so a receipt can be checked against its ledger event.
CREATE TABLE IF NOT EXISTS dispatch_receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES dispatch_runs(run_id) ON DELETE CASCADE,
    fence INTEGER NOT NULL,
    task_id INTEGER NOT NULL,
    agent_label TEXT NOT NULL,
    state TEXT NOT NULL,
    source TEXT NOT NULL,
    reported_by TEXT NOT NULL,
    evidence_ref TEXT,
    failure_reason TEXT,
    exit_code INTEGER,
    termination_outcome TEXT,
    event_ulid TEXT,
    receipt_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dispatch_receipts_run ON dispatch_receipts(run_id, id);
",
};

pub fn schema_parts() -> Vec<SchemaPart> {
    vec![SCHEMA]
}

pub fn register(r: &mut Registry) {
    tools::register(r);
}

// ---------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------

/// The fields of a run the state machine reads.
#[derive(Debug, Clone)]
pub(crate) struct Run {
    pub run_id: String,
    pub task_id: i64,
    pub agent_label: String,
    pub harness: Option<String>,
    pub state: String,
    pub fence: i64,
    pub attempt: i64,
    pub termination_outcome: Option<String>,
    pub pid: Option<i64>,
    pub evidence_ref: Option<String>,
    pub failure_reason: Option<String>,
    pub lease_expires_at: Option<String>,
    pub workdir: Option<String>,
    pub prompt: Option<String>,
}

const RUN_COLUMNS: &str = "run_id, task_id, agent_label, harness, state, fence, attempt, termination_outcome, \
                           pid, evidence_ref, failure_reason, lease_expires_at, workdir, prompt";

fn run_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Run> {
    Ok(Run {
        run_id: r.get(0)?,
        task_id: r.get(1)?,
        agent_label: r.get(2)?,
        harness: r.get(3)?,
        state: r.get(4)?,
        fence: r.get(5)?,
        attempt: r.get(6)?,
        termination_outcome: r.get(7)?,
        pid: r.get(8)?,
        evidence_ref: r.get(9)?,
        failure_reason: r.get(10)?,
        lease_expires_at: r.get(11)?,
        workdir: r.get(12)?,
        prompt: r.get(13)?,
    })
}

pub(crate) fn load_run(conn: &Connection, run_id: &str) -> UaResult<Option<Run>> {
    Ok(conn
        .query_row(
            &format!("SELECT {RUN_COLUMNS} FROM dispatch_runs WHERE run_id = ?1"),
            [run_id],
            run_from_row,
        )
        .optional()?)
}

pub(crate) fn runs_where(conn: &Connection, filter: &str) -> UaResult<Vec<Run>> {
    let mut stmt = conn.prepare(&format!("SELECT {RUN_COLUMNS} FROM dispatch_runs WHERE {filter}"))?;
    let rows = stmt.query_map([], run_from_row)?.collect::<Result<_, _>>()?;
    Ok(rows)
}

/// The run row as a JSON object, without the prompt text.
pub(crate) fn run_object(conn: &Connection, run_id: &str) -> UaResult<Option<Map<String, Value>>> {
    let row = conn
        .query_row(
            "SELECT * FROM dispatch_runs WHERE run_id = ?1",
            [run_id],
            crate::families::tasks::row_object,
        )
        .optional()?;
    Ok(row.map(|mut m| {
        m.remove("prompt");
        if let Some(Value::String(u)) = m.get("usage").cloned() {
            m.insert("usage".into(), serde_json::from_str(&u).unwrap_or(Value::String(u)));
        }
        m
    }))
}

/// The run that holds `task_id`'s live slot, if any.
pub(crate) fn live_run_for_task(conn: &Connection, task_id: i64) -> UaResult<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT run_id FROM dispatch_runs WHERE task_id = ?1 AND (state IN ('claimed','launched','running') \
             OR (state = 'cancelled' AND (termination_outcome IS NULL OR termination_outcome != 'confirmed'))) \
             ORDER BY created_at DESC LIMIT 1",
            [task_id],
            |r| r.get(0),
        )
        .optional()?)
}

pub(crate) fn now() -> String {
    ua_core::time::now()
}

/// `now + seconds` in the storage form.
pub(crate) fn after_seconds(seconds: u64) -> String {
    let ts = jiff::Timestamp::now();
    let secs = i64::try_from(seconds).unwrap_or(i64::MAX / 2);
    let later = ts.checked_add(jiff::SignedDuration::from_secs(secs)).unwrap_or(ts);
    ua_core::time::format_ts(later)
}

/// A refusal reply: `{ok: false, reason, run_id, ...extra}`.
pub(crate) fn refusal(reason: &str, run_id: &str, extra: Value) -> Value {
    let mut out = json!({ "ok": false, "reason": reason, "run_id": run_id });
    if let (Some(o), Value::Object(e)) = (out.as_object_mut(), extra) {
        o.extend(e);
    }
    out
}

fn cap(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

// ---------------------------------------------------------------------------
// Transitions
// ---------------------------------------------------------------------------

/// One guarded change to a run row.
pub(crate) struct Edge {
    /// Target state; `None` changes only columns (e.g. the cancel intent).
    pub to: Option<&'static str>,
    /// Column assignments (`column = value`). Column names are code constants.
    pub sets: Vec<(&'static str, Sql)>,
    /// Refuse while a cancellation is recorded on the row.
    pub require_unlocked: bool,
}

impl Edge {
    pub fn to(state: &'static str) -> Self {
        Self { to: Some(state), sets: Vec::new(), require_unlocked: true }
    }

    pub fn set(mut self, column: &'static str, value: impl Into<Sql>) -> Self {
        self.sets.push((column, value.into()));
        self
    }

    pub fn set_opt(self, column: &'static str, value: Option<String>) -> Self {
        match value {
            Some(v) => self.set(column, v),
            None => self,
        }
    }

    pub fn null(self, column: &'static str) -> Self {
        self.set(column, Sql::Null)
    }

    pub fn locked_ok(mut self) -> Self {
        self.require_unlocked = false;
        self
    }
}

/// Apply `edge` to `run` as a compare-and-swap. `Err(reason)` leaves the row
/// untouched: `invalid_transition`, `already_terminal`,
/// `cancellation_in_progress` or `state_race`.
pub(crate) fn transition(tx: &WriteTx<'_>, run: &Run, edge: Edge) -> UaResult<Result<(), &'static str>> {
    if let Some(to) = edge.to
        && !states::legal(&run.state, to)
    {
        return Ok(Err(if states::is_terminal(&run.state) {
            "already_terminal"
        } else {
            "invalid_transition"
        }));
    }
    if edge.require_unlocked && run.termination_outcome.is_some() {
        return Ok(Err("cancellation_in_progress"));
    }
    let mut sets = vec!["updated_at = ?".to_string()];
    let mut values: Vec<Sql> = vec![now().into()];
    if let Some(to) = edge.to {
        sets.push("state = ?".into());
        values.push(to.to_string().into());
    }
    for (col, v) in edge.sets {
        sets.push(format!("{col} = ?"));
        values.push(v);
    }
    let mut sql =
        format!("UPDATE dispatch_runs SET {} WHERE run_id = ? AND state = ? AND fence = ?", sets.join(", "));
    values.push(run.run_id.clone().into());
    values.push(run.state.clone().into());
    values.push(run.fence.into());
    match &run.termination_outcome {
        None => sql.push_str(" AND termination_outcome IS NULL"),
        Some(t) => {
            sql.push_str(" AND termination_outcome = ?");
            values.push(t.clone().into());
        }
    }
    let n = tx.execute(&sql, rusqlite::params_from_iter(values))?;
    Ok(if n == 1 { Ok(()) } else { Err("state_race") })
}

/// Append an `agent.dispatch.transition` event for the run as it now is.
/// `label` is the state shown in the event (`resumed`, `cancel_requested`, ...).
pub(crate) fn record_transition(
    tx: &mut WriteTx<'_>,
    run_id: &str,
    label: &str,
    actor: &str,
    extra: Value,
) -> UaResult<Option<String>> {
    let Some(run) = load_run(tx, run_id)? else { return Ok(None) };
    let mut payload = json!({
        "actor": actor,
        "run_id": run.run_id,
        "task_id": run.task_id,
        "agent_label": run.agent_label,
        "harness": run.harness,
        "state": label,
        "run_state": run.state,
        "fence": run.fence,
        "attempt": run.attempt,
        "retry_count": run.attempt - 1,
        "failure_reason": run.failure_reason,
        "evidence_ref": run.evidence_ref,
        "termination_outcome": run.termination_outcome,
        "timestamp": now(),
    });
    if let (Some(o), Value::Object(e)) = (payload.as_object_mut(), extra) {
        o.extend(e);
    }
    let ev = ledger::append(tx, EventInput::new(CHANNEL_TRANSITION, payload).by(actor.to_string()))?;
    Ok(ev.map(|e| e.ulid))
}

/// Store a receipt for the run's current (just written) outcome.
pub(crate) fn insert_receipt(
    tx: &WriteTx<'_>,
    run_id: &str,
    source: &str,
    reported_by: &str,
    event_ulid: Option<&str>,
) -> UaResult<()> {
    // The hash covers the receipt's own fields (sorted keys), so a stored
    // receipt can be re-checked against the row and its ledger event.
    let mut body = tx.query_row(
        "SELECT run_id, fence, task_id, agent_label, state, evidence_ref, failure_reason, exit_code, \
         termination_outcome FROM dispatch_runs WHERE run_id = ?1",
        [run_id],
        crate::families::tasks::row_object,
    )?;
    let created_at = now();
    body.insert("source".into(), json!(source));
    body.insert("reported_by".into(), json!(reported_by));
    body.insert("event_ulid".into(), json!(event_ulid));
    body.insert("created_at".into(), json!(created_at));
    let hash = hex::encode(Sha256::digest(Value::Object(body).to_string().as_bytes()));
    tx.execute(
        "INSERT INTO dispatch_receipts (run_id, fence, task_id, agent_label, state, source, reported_by, \
         evidence_ref, failure_reason, exit_code, termination_outcome, event_ulid, receipt_hash, created_at) \
         SELECT run_id, fence, task_id, agent_label, state, ?2, ?3, evidence_ref, failure_reason, exit_code, \
         termination_outcome, ?4, ?5, ?6 FROM dispatch_runs WHERE run_id = ?1",
        params![run_id, source, reported_by, event_ulid, hash, created_at],
    )?;
    Ok(())
}

/// Task bookkeeping after a run outcome: release the task's run pointer and,
/// on `finished`, close the task with the evidence.
fn settle_task(tx: &WriteTx<'_>, run: &Run, state: &str, evidence: Option<&str>) -> UaResult<()> {
    let revision = crate::families::tasks::next_revision(None);
    tx.execute(
        "UPDATE tasks SET current_run_id = NULL, current_run_agent = NULL WHERE id = ?1 AND current_run_id = ?2",
        params![run.task_id, run.run_id],
    )?;
    if state == "finished" {
        let note = format!(
            "[dispatch] run {} finished (fence {}): {}",
            run.run_id,
            run.fence,
            evidence.unwrap_or("no evidence")
        );
        tx.execute(
            "UPDATE tasks SET status = 'done', completed_at = ?2, updated_at = ?2, \
             evidence_ref = COALESCE(evidence_ref, ?3), \
             notes = CASE WHEN notes IS NULL OR notes = '' THEN ?4 ELSE notes || char(10) || ?4 END \
             WHERE id = ?1 AND status NOT IN ('done','cancelled')",
            params![run.task_id, revision, evidence, note],
        )?;
    }
    Ok(())
}

/// Exit information from a supervised child.
#[derive(Debug, Clone, Default)]
pub(crate) struct ExitInfo {
    pub exit_code: Option<i64>,
    pub exit_signal: Option<i64>,
    pub timed_out: bool,
    pub output_bytes: i64,
    pub output_truncated: bool,
}

/// One outcome report (self-report, supervisor, reaper).
pub(crate) struct Outcome<'a> {
    pub run_id: &'a str,
    /// The reporter's fence; `None` accepts the run's current fence.
    pub fence: Option<i64>,
    pub state: &'static str,
    pub actor: &'a str,
    pub source: &'a str,
    pub evidence: Option<String>,
    pub failure_reason: Option<String>,
    pub failure_class: Option<String>,
    pub usage: Option<Value>,
}

/// Record a terminal (or `retryable`) outcome on a live run. Refusals are
/// returned as `{ok: false, reason}`: `unknown_run`, `stale_fence`,
/// `already_terminal`, `cancellation_in_progress`, `superseded_run`,
/// `invalid_transition` or `state_race`.
pub(crate) fn record_outcome(tx: &mut WriteTx<'_>, o: Outcome<'_>) -> UaResult<Value> {
    let Some(run) = load_run(tx, o.run_id)? else {
        return Ok(refusal("unknown_run", o.run_id, json!({ "state": o.state })));
    };
    if let Some(f) = o.fence
        && f != run.fence
    {
        return Ok(refusal("stale_fence", o.run_id, json!({ "fence": f, "current_fence": run.fence })));
    }
    if states::is_terminal(&run.state) {
        return Ok(refusal("already_terminal", o.run_id, json!({ "state": run.state })));
    }
    if run.termination_outcome.is_some() {
        return Ok(refusal(
            "cancellation_in_progress",
            o.run_id,
            json!({ "state": run.state, "termination_outcome": run.termination_outcome }),
        ));
    }
    if let Some(live) = live_run_for_task(tx, run.task_id)?
        && live != run.run_id
    {
        return Ok(refusal("superseded_run", o.run_id, json!({ "state": run.state, "live_run_id": live })));
    }
    let reason = o.failure_reason.as_deref().map(|r| cap(r, 200));
    let class = match o.state {
        "finished" => None,
        _ => Some(o.failure_class.clone().unwrap_or_else(|| "error".into())),
    };
    let mut edge = Edge::to(o.state)
        .null("lease_expires_at")
        .set("ended_at", now())
        .set_opt("failure_reason", reason.clone())
        .set_opt("failure_class", class)
        .set_opt("evidence_ref", o.evidence.clone());
    if let Some(u) = &o.usage {
        edge = edge.set("usage", u.to_string());
    }
    if let Err(reason) = transition(tx, &run, edge)? {
        return Ok(refusal(reason, o.run_id, json!({ "state": run.state })));
    }
    let ulid = record_transition(tx, o.run_id, o.state, o.actor, json!({ "source": o.source }))?;
    insert_receipt(tx, o.run_id, o.source, o.actor, ulid.as_deref())?;
    settle_task(tx, &run, o.state, o.evidence.as_deref())?;
    Ok(json!({
        "ok": true,
        "run_id": o.run_id,
        "state": o.state,
        "task_id": run.task_id,
        "fence": run.fence,
        "failure_reason": reason,
        "evidence_ref": o.evidence,
    }))
}

/// Write a child's exit information. Not a state change: it lands whatever
/// state the run reached, as long as the fence still matches.
pub(crate) fn record_exit(tx: &WriteTx<'_>, run_id: &str, fence: i64, exit: &ExitInfo) -> UaResult<()> {
    tx.execute(
        "UPDATE dispatch_runs SET exit_code = ?3, exit_signal = ?4, timed_out = ?5, output_bytes = ?6, \
         output_truncated = ?7, ended_at = COALESCE(ended_at, ?8), updated_at = ?8 \
         WHERE run_id = ?1 AND fence = ?2",
        params![
            run_id,
            fence,
            exit.exit_code,
            exit.exit_signal,
            exit.timed_out,
            exit.output_bytes,
            exit.output_truncated,
            now()
        ],
    )?;
    Ok(())
}

/// Commit a cancellation outcome. `cessation` is `confirmed` or `unknown`;
/// `termination` is the raw result of the stop attempt. A run already
/// cancelled with confirmed cessation is reported as `already_finalized`.
pub(crate) fn finalize_cancellation(
    tx: &mut WriteTx<'_>,
    run_id: &str,
    actor: &str,
    source: &str,
    reason: &str,
    termination: &str,
    cessation: &'static str,
) -> UaResult<Value> {
    let Some(run) = load_run(tx, run_id)? else { return Ok(refusal("unknown_run", run_id, json!({}))) };
    if run.state == "cancelled" && run.termination_outcome.as_deref() == Some("confirmed") {
        return Ok(json!({
            "ok": true, "run_id": run_id, "state": "cancelled", "termination": termination,
            "cessation": "confirmed", "already_finalized": true,
        }));
    }
    let mut edge = Edge::to("cancelled")
        .locked_ok()
        .set("failure_reason", cap(reason, 200))
        .set("termination_outcome", cessation.to_string())
        .set("ended_at", now());
    if cessation == "confirmed" {
        edge = edge.null("lease_expires_at");
    }
    if let Err(why) = transition(tx, &run, edge)? {
        return Ok(refusal(why, run_id, json!({ "state": run.state })));
    }
    let ulid = record_transition(
        tx,
        run_id,
        "cancelled",
        actor,
        json!({ "termination": termination, "source": source }),
    )?;
    insert_receipt(tx, run_id, source, actor, ulid.as_deref())?;
    settle_task(tx, &run, "cancelled", None)?;
    Ok(json!({
        "ok": true, "run_id": run_id, "state": "cancelled", "termination": termination, "cessation": cessation,
    }))
}

/// Map a stop attempt to the claim it supports.
pub(crate) fn classify_termination(termination: &str) -> &'static str {
    match termination {
        "killed" | "already_gone" | "operator_confirmed" => "confirmed",
        _ => "unknown",
    }
}

/// Check an identity-bound tool's caller: verified, and the run's agent.
pub(crate) fn check_run_owner(caller: &ua_core::Caller, tool: &str, run: &Run) -> UaResult<()> {
    if caller.kind == ua_core::ActorKind::Anonymous {
        return Err(UaError::denied(
            "unauthenticated",
            format!("{tool} requires an authenticated hub identity; anonymous callers cannot bind a run"),
        ));
    }
    if caller.label != run.agent_label {
        return Err(UaError::denied(
            "identity_mismatch",
            format!(
                "identity mismatch: verified as {:?} but run {} belongs to {:?}",
                caller.label, run.run_id, run.agent_label
            ),
        ));
    }
    Ok(())
}
