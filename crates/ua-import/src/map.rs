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
    /// Legacy agents are imported into the default organization (a source
    /// `org_id` is never copied).
    Agents,
    /// Legacy session handoff notes are imported into the default
    /// organization, with their sessions' agents.
    HandoffNotes,
    /// History only: a pending request or an approved, unconsumed pass is
    /// never imported. Imported into the default organization.
    Approvals,
    /// Hashes only, and only in the scheme ua-rust verifies (hex SHA-256).
    /// Imported into the default organization, with their agents.
    Tokens,
    /// `event_seq` may be NULL in older Python rows; it is filled from the
    /// imported ledger by `event_ulid`. Legacy messages are imported into the
    /// default organization (a source `org_id` is never copied).
    MessageIndex,
    /// Legacy mailbox read receipts are imported into the default
    /// organization, with their messages.
    MessageReads,
    /// The hash-chained event ledger, copied byte-exactly.
    Ledger,
    /// Remote nodes: owner, version, timestamps and retirement move across,
    /// host facts do not. ua-rust stores only facts it bounded on write, so
    /// `facts_json` starts empty and the node's next registration fills it.
    /// Legacy nodes are imported into the default organization.
    Nodes,
    /// Tasks: `current_run_id` and `current_run_agent` are cleared to NULL
    /// because `dispatch_runs` are not imported. Legacy tasks are imported
    /// into the default organization.
    Tasks,
    /// Task dependencies, comments, comment threads, workflow records,
    /// checks and hold members: imported into the default organization, with
    /// their tasks.
    TaskChildren,
    /// Task subtree holds: require valid `status` and refuse duplicate active
    /// holds. Imported into the default organization.
    TaskHolds,
    /// Project repository bindings: validate `project` slug and `repo`, and
    /// normalize `default_branch` (clearing invalid values to NULL). Legacy
    /// bindings are imported into the default organization.
    ProjectRepoBindings,
    /// Legacy canvas boards are imported into the default organization.
    GraphCanvas,
    /// Legacy skill versions and assignments are imported into the default
    /// organization.
    SkillRegistry,
    /// Legacy harness config bundles are imported into the default
    /// organization (a source `org_id` is reported and dropped, never copied).
    HarnessConfig,
    /// Legacy plans, their steps and checkpoints are imported into the
    /// default organization.
    Plans,
    /// Legacy delegations are imported into the default organization, with
    /// their tasks (a source `org_id` is never copied).
    Delegations,
    /// Legacy goals and task-goal links are imported into the default
    /// organization, with their tasks (a source `org_id` is never copied).
    Goals,
    /// Legacy work proposals and their items are imported into the default
    /// organization (a source `org_id` is never copied).
    WorkProposals,
    /// Legacy memory notes and their versions are imported into the default
    /// organization (a source `org_id` is never copied).
    Memory,
}

impl Kind {
    /// Rows of this kind are written with `org_id = 'default'` named
    /// explicitly: the target table is keyed by organization, and the
    /// Python source has no organization to copy. A source `org_id` is never
    /// copied by column name.
    pub(crate) fn writes_default_org(self) -> bool {
        matches!(
            self,
            Kind::GraphCanvas
                | Kind::Tasks
                | Kind::TaskChildren
                | Kind::TaskHolds
                | Kind::SkillRegistry
                | Kind::ProjectRepoBindings
                | Kind::HarnessConfig
                | Kind::Plans
                | Kind::Approvals
                | Kind::Delegations
                | Kind::Goals
                | Kind::WorkProposals
                | Kind::Memory
                | Kind::Nodes
                | Kind::MessageIndex
                | Kind::MessageReads
                | Kind::Agents
                | Kind::Tokens
                | Kind::HandoffNotes
        )
    }
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
const PLAN_REF: Ref = Ref { col: "plan_id", table: "plans", key: "id" };

/// Copy order: referenced tables before the tables that point at them.
pub(crate) const MAPS: &[TableMap] = &[
    TableMap { kind: Kind::Agents, ..plain("agents") },
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
        kind: Kind::TaskChildren,
        ..plain("task_dependencies")
    },
    TableMap { refs: &[TASK_REF], kind: Kind::TaskChildren, ..plain("task_comment_threads") },
    TableMap {
        refs: &[TASK_REF],
        self_ref: Some(Ref { col: "parent_comment_id", table: "task_comments", key: "id" }),
        kind: Kind::TaskChildren,
        ..plain("task_comments")
    },
    TableMap {
        self_ref: Some(Ref { col: "parent_goal_id", table: "goals", key: "id" }),
        kind: Kind::Goals,
        ..plain("goals")
    },
    TableMap {
        refs: &[TASK_REF, Ref { col: "goal_id", table: "goals", key: "id" }],
        kind: Kind::Goals,
        ..plain("task_goal_links")
    },
    TableMap { refs: &[TASK_REF], kind: Kind::TaskChildren, ..plain("task_workflow") },
    TableMap { refs: &[TASK_REF], kind: Kind::TaskChildren, ..plain("task_checks") },
    // A handoff note keeps its task id as a record even when the task is gone.
    TableMap { kind: Kind::HandoffNotes, ..plain("session_handoff_notes") },
    TableMap { kind: Kind::Plans, ..plain("plans") },
    TableMap { refs: &[PLAN_REF], kind: Kind::Plans, ..plain("plan_steps") },
    TableMap { refs: &[PLAN_REF], kind: Kind::Plans, ..plain("plan_checkpoints") },
    TableMap { refs: &[TASK_REF], kind: Kind::Delegations, ..plain("delegations") },
    TableMap { kind: Kind::WorkProposals, ..plain("work_proposals") },
    TableMap {
        refs: &[Ref { col: "proposal_id", table: "work_proposals", key: "id" }],
        kind: Kind::WorkProposals,
        ..plain("work_proposal_items")
    },
    // Neither schema has an FK from task_holds.root_task_id to tasks: hold
    // records intentionally outlive deleted tasks, while members keep their task FK.
    TableMap { kind: Kind::TaskHolds, ..plain("task_holds") },
    TableMap {
        refs: &[Ref { col: "hold_id", table: "task_holds", key: "id" }, TASK_REF],
        kind: Kind::TaskChildren,
        ..plain("task_hold_members")
    },
    TableMap { kind: Kind::ProjectRepoBindings, ..plain("project_repo_bindings") },
    TableMap { rowid_to: Some("seq"), kind: Kind::Memory, ..plain("memory") },
    TableMap {
        refs: &[Ref { col: "note_id", table: "memory", key: "id" }],
        kind: Kind::Memory,
        ..plain("memory_versions")
    },
    TableMap { kind: Kind::Approvals, ..plain("approvals") },
    TableMap { kind: Kind::Nodes, ..plain("nodes") },
    // Skill versions are immutable (insert only) and keep their ids; drift
    // proposals and reports are not copied, since their apply approvals are
    // pending or unconsumed passes, which are never imported.
    TableMap { kind: Kind::SkillRegistry, ..plain("skill_versions") },
    TableMap { kind: Kind::SkillRegistry, ..plain("skill_assignments") },
    TableMap { kind: Kind::HarnessConfig, ..plain("harness_config_bundles") },
    TableMap { kind: Kind::GraphCanvas, ..plain("graph_canvas_scenes") },
    TableMap { kind: Kind::Ledger, ..plain("event_log") },
    TableMap { kind: Kind::MessageIndex, ..plain("message_index") },
    TableMap {
        refs: &[Ref { col: "message_id", table: "message_index", key: "message_id" }],
        kind: Kind::MessageReads,
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
