//! Which Python tables are copied, in which order, and how.
//!
//! Every mapped table keeps its name. Columns are matched by name at run time:
//! a source column the target lacks is reported as unmapped, a target column
//! the source lacks takes its default. Rows are walked in source `rowid` order,
//! which is also the resume key.

/// A foreign key checked before a row is inserted.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ref {
    /// Column in the copied table.
    pub col: &'static str,
    /// Table the value must exist in (in the target).
    pub table: &'static str,
    /// Key column of that table.
    pub key: &'static str,
}

/// Per-table behavior beyond a plain column copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Plain,
    /// History only: a pending request or an approved, unconsumed pass is
    /// never imported.
    Approvals,
    /// Hashes only, and only in the scheme ua-rust verifies (hex SHA-256).
    Tokens,
    /// `event_seq` may be NULL in older Python rows; it is filled from the
    /// imported ledger by `event_ulid`.
    MessageIndex,
    /// The hash-chained event ledger, copied byte-exactly.
    Ledger,
    /// Remote nodes: owner, version, timestamps and retirement move across,
    /// host facts do not. ua-rust stores only facts it bounded on write, so
    /// `facts_json` starts empty and the node's next registration fills it.
    Nodes,
    /// Tasks: stale `current_run_id` and `current_run_agent` pointers (not in
    /// target `dispatch_runs`) are cleared to NULL.
    Tasks,
    /// Work proposals: coerce NULL `status`/`reporting_mode` to defaults.
    WorkProposals,
    /// Work proposal items: keep frozen title/notes/scope_json/digests intact
    /// and coerce NULL defaults from older schemas.
    WorkProposalItems,
    /// Task subtree holds: coerce NULL defaults and refuse duplicate active holds.
    TaskHolds,
    /// Task hold members: coerce NULL `cancel_requested_by_hold` to `0`.
    TaskHoldMembers,
    /// Project repository bindings: validate `project` slug, `repo`, and branch.
    ProjectRepoBindings,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TableMap {
    pub source: &'static str,
    pub target: &'static str,
    /// Target column that receives the source `rowid` (when the Python table
    /// keys rows by its implicit rowid and ua-rust names that key).
    pub rowid_to: Option<&'static str>,
    /// Required references: a row whose value is missing in the target is
    /// skipped and counted.
    pub refs: &'static [Ref],
    /// A reference into the same table. A forward reference is inserted as
    /// NULL and restored after the table is copied; a dangling one stays NULL.
    pub self_ref: Option<Ref>,
    pub kind: Kind,
}

const fn plain(source: &'static str) -> TableMap {
    TableMap { source, target: source, rowid_to: None, refs: &[], self_ref: None, kind: Kind::Plain }
}

const TASK_REF: Ref = Ref { col: "task_id", table: "tasks", key: "id" };

/// Copy order: referenced tables before the tables that point at them.
pub(crate) const MAPS: &[TableMap] = &[
    plain("agents"),
    TableMap {
        self_ref: Some(Ref { col: "rotated_from", table: "agent_tokens", key: "id" }),
        kind: Kind::Tokens,
        ..plain("agent_tokens")
    },
    TableMap {
        self_ref: Some(Ref { col: "parent_id", table: "tasks", key: "id" }),
        kind: Kind::Tasks,
        ..plain("tasks")
    },
    TableMap {
        refs: &[TASK_REF, Ref { col: "depends_on_task_id", table: "tasks", key: "id" }],
        ..plain("task_dependencies")
    },
    TableMap { refs: &[TASK_REF], ..plain("task_comment_threads") },
    TableMap {
        refs: &[TASK_REF],
        self_ref: Some(Ref { col: "parent_comment_id", table: "task_comments", key: "id" }),
        ..plain("task_comments")
    },
    TableMap { self_ref: Some(Ref { col: "parent_goal_id", table: "goals", key: "id" }), ..plain("goals") },
    TableMap {
        refs: &[TASK_REF, Ref { col: "goal_id", table: "goals", key: "id" }],
        ..plain("task_goal_links")
    },
    TableMap { refs: &[TASK_REF], ..plain("task_workflow") },
    TableMap { refs: &[TASK_REF], ..plain("task_checks") },
    // A handoff note keeps its task id as a record even when the task is gone.
    plain("session_handoff_notes"),
    plain("plans"),
    TableMap { refs: &[Ref { col: "plan_id", table: "plans", key: "id" }], ..plain("plan_steps") },
    TableMap { refs: &[Ref { col: "plan_id", table: "plans", key: "id" }], ..plain("plan_checkpoints") },
    TableMap { refs: &[TASK_REF], ..plain("delegations") },
    TableMap { kind: Kind::WorkProposals, ..plain("work_proposals") },
    TableMap {
        refs: &[Ref { col: "proposal_id", table: "work_proposals", key: "id" }],
        kind: Kind::WorkProposalItems,
        ..plain("work_proposal_items")
    },
    TableMap {
        refs: &[Ref { col: "root_task_id", table: "tasks", key: "id" }],
        kind: Kind::TaskHolds,
        ..plain("task_holds")
    },
    TableMap {
        refs: &[Ref { col: "hold_id", table: "task_holds", key: "id" }, TASK_REF],
        kind: Kind::TaskHoldMembers,
        ..plain("task_hold_members")
    },
    TableMap { kind: Kind::ProjectRepoBindings, ..plain("project_repo_bindings") },
    TableMap { rowid_to: Some("seq"), ..plain("memory") },
    TableMap { refs: &[Ref { col: "note_id", table: "memory", key: "id" }], ..plain("memory_versions") },
    TableMap { kind: Kind::Approvals, ..plain("approvals") },
    TableMap { kind: Kind::Nodes, ..plain("nodes") },
    // Skill versions are immutable (insert only) and keep their ids; drift
    // proposals and reports are not copied, since their apply approvals are
    // pending or unconsumed passes, which are never imported.
    plain("skill_versions"),
    plain("skill_assignments"),
    plain("harness_config_bundles"),
    plain("graph_canvas_scenes"),
    TableMap { kind: Kind::Ledger, ..plain("event_log") },
    TableMap { kind: Kind::MessageIndex, ..plain("message_index") },
    TableMap {
        refs: &[Ref { col: "message_id", table: "message_index", key: "message_id" }],
        ..plain("message_reads")
    },
];

/// The ledger columns hashed by `compute_entry_hash`, in source order.
pub(crate) const LEDGER_COLUMNS: [&str; 10] = [
    "ulid",
    "channel",
    "payload",
    "originator",
    "episode_id",
    "causal_parent_id",
    "created_at",
    "dedupe_key",
    "prev_hash",
    "entry_hash",
];
