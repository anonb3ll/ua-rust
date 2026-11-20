//! Continuity: what lets work survive a compaction, a handoff or a quiet month.
//!
//! - Task workflow ([`workflow`]): `task_workflow_get`, `task_workflow_set`,
//!   `task_check_record`, `task_check_verify`. One stage and resume capsule
//!   per task, and named checks graded `verified`, `attested` or `unknown`
//!   at a head. CI references are looked up through the hub's
//!   [`CiVerifier`](crate::ci::CiVerifier).
//! - Session handoff notes ([`handoff`]): `session_handoff_propose`,
//!   `session_handoff_update`, `session_handoff_seal`,
//!   `session_handoff_discard`, `session_handoff_recover`,
//!   `session_handoff_ack`. An agent's own note for its session, with `seal`
//!   as the commit point.
//! - Conversation handoff ([`conversation`]): `conversation_handoff`,
//!   `conversation_handoffs`. A task that points at a mailbox conversation
//!   without copying it.
//! - Queue closure ([`queue`]): `queue_health`, `queue_stale`, `queue_sweep`,
//!   `queue_park`, `queue_fold`, `queue_unpark`. Parking is recorded in its
//!   own task columns (`parked_at`, `parked_by`, `parked_reason`,
//!   `folded_into`), separate from archiving.
//! - Close-on-merge ([`merged`]): `queue_close_merged`, and the same rules
//!   applied to merges the GitHub webhook and poller report.
//!
//! All of these are `coordination_manage` actions. Every write appends a
//! ledger event in its own write transaction. See `docs/continuity.md`.

mod conversation;
mod handoff;
pub(crate) mod merged;
mod queue;
mod workflow;

use ua_core::{Caller, Config};
use ua_store::SchemaPart;

pub(crate) use conversation::{conversation_handoff, conversation_handoffs};
pub(crate) use handoff::{
    latest_committed_note, session_handoff_ack, session_handoff_discard, session_handoff_propose,
    session_handoff_recover, session_handoff_seal, session_handoff_update,
};
pub(crate) use merged::queue_close_merged;
pub(crate) use queue::{
    parked_block, queue_fold, queue_health, queue_park, queue_stale, queue_sweep, queue_unpark,
};
pub(crate) use workflow::{
    STAGES, packet_section, task_check_record, task_check_verify, task_workflow_get, task_workflow_set,
};

/// The workflow record, task checks and session handoff notes. Column names
/// match the Python hub's tables, so an import copies them by name.
pub const SCHEMA: SchemaPart = SchemaPart {
    name: "continuity.v1",
    sql: "
CREATE TABLE IF NOT EXISTS task_workflow (
    task_id INTEGER PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
    stage TEXT CHECK (stage IS NULL OR stage IN
        ('plan','implement','verify','review','merge','deploy','prove','done')),
    goal TEXT,
    done_json TEXT NOT NULL DEFAULT '[]',
    focus TEXT,
    head_sha TEXT,
    expected_json TEXT NOT NULL DEFAULT '[]',
    revision INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS task_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('pass','fail')),
    grade TEXT NOT NULL CHECK (grade IN ('attested','verified')),
    ref_kind TEXT,
    ref TEXT,
    repo TEXT,
    ref_job TEXT,
    detail TEXT,
    verification_json TEXT,
    recorded_by TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    verified_at TEXT,
    UNIQUE (task_id, name, head_sha)
);
CREATE INDEX IF NOT EXISTS idx_task_checks_task ON task_checks(task_id, recorded_at);

CREATE TABLE IF NOT EXISTS session_handoff_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    agent TEXT NOT NULL,
    -- No foreign key: a sealed note is immutable, so a deleted task must not
    -- rewrite it. The task id stays as the record of what the note was about.
    task_id INTEGER,
    done TEXT NOT NULL,
    next_steps TEXT NOT NULL,
    open_questions TEXT NOT NULL DEFAULT '[]',
    state TEXT NOT NULL DEFAULT 'draft'
        CHECK (state IN ('draft','sealed','assigned','delivered','superseded','discarded')),
    epoch INTEGER NOT NULL DEFAULT 0,
    supersedes INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    sealed_at TEXT,
    assigned_to TEXT,
    assigned_at TEXT,
    delivered_to TEXT,
    delivered_at TEXT,
    acknowledged_at TEXT,
    failover_reason TEXT,
    attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_session_handoff_notes_session
    ON session_handoff_notes(session_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_session_handoff_notes_one_draft
    ON session_handoff_notes(session_id) WHERE state = 'draft';
CREATE UNIQUE INDEX IF NOT EXISTS idx_session_handoff_notes_one_pending
    ON session_handoff_notes(session_id) WHERE state IN ('sealed', 'assigned');
CREATE TRIGGER IF NOT EXISTS session_handoff_notes_forward_only
BEFORE UPDATE OF state ON session_handoff_notes
WHEN NOT (
    OLD.state = NEW.state
    OR (OLD.state = 'draft' AND NEW.state IN ('sealed', 'discarded'))
    OR (OLD.state = 'sealed' AND NEW.state IN ('assigned', 'delivered', 'superseded'))
    OR (OLD.state = 'assigned' AND NEW.state IN ('delivered', 'superseded'))
)
BEGIN
    SELECT RAISE(ABORT, 'session handoff notes are forward-only');
END;
CREATE TRIGGER IF NOT EXISTS session_handoff_notes_sealed_immutable
BEFORE UPDATE OF session_id, agent, task_id, done, next_steps, open_questions, epoch
ON session_handoff_notes
WHEN OLD.state != 'draft'
BEGIN
    SELECT RAISE(ABORT, 'session handoff notes are forward-only: a sealed note is immutable');
END;
",
};

/// Parking columns on `tasks`. A parked task keeps its status and is left
/// out of the working queue; `folded_into` names the parked root a folded
/// descendant went with.
pub const PARKING_SCHEMA: SchemaPart = SchemaPart {
    name: "continuity.parking.v1",
    sql: "
ALTER TABLE tasks ADD COLUMN parked_at TEXT;
ALTER TABLE tasks ADD COLUMN parked_by TEXT;
ALTER TABLE tasks ADD COLUMN parked_reason TEXT;
ALTER TABLE tasks ADD COLUMN folded_into INTEGER REFERENCES tasks(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_parked ON tasks(parked_at) WHERE parked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_folded_into ON tasks(folded_into) WHERE folded_into IS NOT NULL;
",
};

/// The CI job each expected check is bound to, by check name (a JSON
/// object). A separate column so `expected_json` keeps the Python hub's
/// shape (a list of names) for import.
pub const CHECK_JOBS_SCHEMA: SchemaPart = SchemaPart {
    name: "continuity.check_jobs.v1",
    sql: "
ALTER TABLE task_workflow ADD COLUMN expected_jobs_json TEXT NOT NULL DEFAULT '{}';
",
};

/// The head a `review_ready` notification was last sent for, so each head
/// is announced once.
pub const REVIEW_READY_SCHEMA: SchemaPart = SchemaPart {
    name: "continuity.review_ready.v1",
    sql: "
ALTER TABLE task_workflow ADD COLUMN review_notified_head TEXT;
",
};

pub fn schema_parts() -> Vec<SchemaPart> {
    vec![SCHEMA, PARKING_SCHEMA, CHECK_JOBS_SCHEMA, REVIEW_READY_SCHEMA]
}

// --- shared helpers ---------------------------------------------------------------

/// A timestamp at microsecond precision. Workflow writes are fenced on the
/// stored value, so two records inside one second must not share it.
pub(crate) fn now_micros() -> String {
    jiff::Timestamp::now().strftime("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
}

/// Whether `who` holds operator authority: a human caller, a configured
/// human identity or a lifecycle operator.
pub(crate) fn is_operator_identity(cfg: &Config, caller: &Caller, who: &str) -> bool {
    caller.is_human() || cfg.is_human(who) || cfg.is_lifecycle_operator(who)
}

/// Same label, ignoring ASCII case.
pub(crate) fn same_label(a: Option<&str>, b: &str) -> bool {
    a.is_some_and(|a| !a.trim().is_empty() && a.trim().eq_ignore_ascii_case(b.trim()))
}

/// Trimmed text of at most `limit` characters, else a refusal naming `field`.
pub(crate) fn bounded(value: &str, field: &str, limit: usize) -> ua_core::UaResult<String> {
    let text = value.trim();
    if text.chars().count() > limit {
        return Err(ua_core::UaError::invalid(format!("{field} must be at most {limit} characters")));
    }
    Ok(text.to_string())
}
