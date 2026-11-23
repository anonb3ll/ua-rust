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

use ua_store::{Procedure, SchemaPart};

pub(crate) use conversation::{HANDOFF_KEY_PREFIX, conversation_handoff, conversation_handoffs};
pub(crate) use handoff::{
    recover_note, session_handoff_ack, session_handoff_discard, session_handoff_propose,
    session_handoff_recover, session_handoff_seal, session_handoff_update,
};
pub(crate) use merged::queue_close_merged;
pub(crate) use queue::{
    parked_block, queue_fold, queue_health, queue_park, queue_stale, queue_sweep, queue_unpark,
};
pub(crate) use workflow::{
    STAGES, capsule_head, packet_section, require_review_at_head, require_writer, review_ready,
    task_check_record, task_check_verify, task_repo, task_workflow_get, task_workflow_set, write_capsule,
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

/// Every `review_ready` notice sent, one row per task and head, so a head
/// is announced at most once (even when the task returns to it) and a task's
/// notices can be rate limited.
pub const REVIEW_NOTICES_SCHEMA: SchemaPart = SchemaPart {
    name: "continuity.review_notices.v1",
    sql: "
CREATE TABLE IF NOT EXISTS review_ready_notices (
    task_id INTEGER NOT NULL,
    head_sha TEXT NOT NULL,
    notified_at TEXT NOT NULL,
    PRIMARY KEY (task_id, head_sha)
);
CREATE INDEX IF NOT EXISTS idx_review_ready_notices_task ON review_ready_notices(task_id, notified_at);
",
};

/// `organization.v1.tools.continuity`: `org_id` on `task_workflow`,
/// `task_checks` and `review_ready_notices`, and their generated
/// `*_org_exists` / `*_org_immutable` triggers. No key rebuild: every key is
/// led by a hub-global task id (`task_workflow(task_id)`,
/// `task_checks(task_id, name, head_sha)` and its AUTOINCREMENT `id`,
/// `review_ready_notices(task_id, head_sha)`), so two organizations can never
/// collide. The column fills with the default organization here;
/// [`ORG_SCOPE`] then moves each row to its task's organization. Applied
/// after the continuity parts and `tasks.v2.org_scope`.
pub const TENANT_PART: Procedure = ua_store::org::tenant_part(
    "organization.v1.tools.continuity",
    &["task_workflow", "task_checks", "review_ready_notices"],
);

/// The `*_org_immutable` trigger [`ua_store::org::tenant_part`] generates for
/// `table`, spelled exactly as it does, so a part that must move existing
/// rows once can drop it and put the same trigger back.
macro_rules! org_immutable {
    ($table:literal) => {
        concat!(
            "CREATE TRIGGER ",
            $table,
            "_org_immutable BEFORE UPDATE OF org_id ON ",
            $table,
            " WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id \
             BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END;"
        )
    };
}
pub(crate) use org_immutable;

/// `continuity.v2.org_scope`: rows written before [`TENANT_PART`] move to
/// their task's organization (a row whose task is gone stays in the default
/// organization), indexes led by `org_id` for the stage filter of
/// `task_list` and the re-verification scan by repository and head, and
/// triggers that keep every row's `task_id` inside the row's organization
/// (the foreign key alone would accept another organization's task). The
/// backfill drops each `*_org_immutable` trigger for its one `UPDATE` and
/// puts the same trigger back, in this part's transaction.
pub const ORG_SCOPE: SchemaPart = SchemaPart {
    name: "continuity.v2.org_scope",
    sql: concat!(
        "
DROP TRIGGER task_workflow_org_immutable;
UPDATE task_workflow SET org_id = (SELECT t.org_id FROM tasks t WHERE t.id = task_workflow.task_id)
WHERE EXISTS (SELECT 1 FROM tasks t WHERE t.id = task_workflow.task_id AND t.org_id IS NOT task_workflow.org_id);
",
        org_immutable!("task_workflow"),
        "
DROP TRIGGER task_checks_org_immutable;
UPDATE task_checks SET org_id = (SELECT t.org_id FROM tasks t WHERE t.id = task_checks.task_id)
WHERE EXISTS (SELECT 1 FROM tasks t WHERE t.id = task_checks.task_id AND t.org_id IS NOT task_checks.org_id);
",
        org_immutable!("task_checks"),
        "
DROP TRIGGER review_ready_notices_org_immutable;
UPDATE review_ready_notices SET org_id = (SELECT t.org_id FROM tasks t WHERE t.id = review_ready_notices.task_id)
WHERE EXISTS (
    SELECT 1 FROM tasks t WHERE t.id = review_ready_notices.task_id AND t.org_id IS NOT review_ready_notices.org_id
);
",
        org_immutable!("review_ready_notices"),
        "
CREATE INDEX IF NOT EXISTS idx_task_workflow_org_stage ON task_workflow(org_id, stage);
CREATE INDEX IF NOT EXISTS idx_task_checks_org_repo_head ON task_checks(org_id, lower(repo), lower(head_sha));

CREATE TRIGGER IF NOT EXISTS task_workflow_org_parent BEFORE INSERT ON task_workflow
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS task_workflow_org_parent_update BEFORE UPDATE OF task_id ON task_workflow
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS task_checks_org_parent BEFORE INSERT ON task_checks
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS task_checks_org_parent_update BEFORE UPDATE OF task_id ON task_checks
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS review_ready_notices_org_parent BEFORE INSERT ON review_ready_notices
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS review_ready_notices_org_parent_update BEFORE UPDATE OF task_id ON review_ready_notices
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
"
    ),
};

pub fn schema_parts() -> Vec<SchemaPart> {
    vec![SCHEMA, PARKING_SCHEMA, CHECK_JOBS_SCHEMA, REVIEW_READY_SCHEMA, REVIEW_NOTICES_SCHEMA]
}

// --- shared helpers ---------------------------------------------------------------

/// A timestamp at microsecond precision. Workflow writes are fenced on the
/// stored value, so two records inside one second must not share it.
pub(crate) fn now_micros() -> String {
    jiff::Timestamp::now().strftime("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
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
