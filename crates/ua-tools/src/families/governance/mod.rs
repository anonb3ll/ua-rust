//! Governance controls: who may take work, and over which tasks.
//!
//! - Agent lifecycle ([`lifecycle`]): `agent_state`, `agent_states`,
//!   `agent_pause`, `agent_resume`, `agent_terminate`, `agent_retire`,
//!   `agent_unretire`.
//! - Task subtree holds ([`holds`]): `task_hold`, `task_holds`,
//!   `task_hold_get`.
//! - Operator claim release ([`claim_release`]): `task_claim_release`.
//! - Project repository bindings ([`bindings`]): `project_repo_bind`,
//!   `project_repo_unbind`, `project_repo_get`, `project_repo_list`.
//! - Batch work proposals ([`proposals`]): `work_proposal_file`,
//!   `work_proposal_decide`, `work_proposal_withdraw`, `work_proposal_get`,
//!   `work_proposal_list`, `work_proposal_recover`.
//!
//! These are `coordination_manage` actions. The one top-level tool here is
//! `cleanup_stale_worktrees` ([`worktrees`]).
//!
//! [`claim_block`] is the single check every path that hands out work runs
//! inside its own write transaction: `task_claim`, `task_update` into
//! `doing`, `dispatch_task`, `dispatch_resume`, `node_dispatch` (and every
//! other enqueue), `node_claim` and, for the agent part, `plan_step_claim`. It refuses with a stable reason code: `agent_paused`,
//! `agent_terminated` or `agent_retired` for the agent that would hold the
//! work, and `task_held` for a task inside an active subtree hold.

mod bindings;
mod block;
mod claim_release;
mod holds;
mod lifecycle;
mod procscan;
mod proposals;
mod worktrees;

use ua_core::{Caller, UaError, UaResult};
use ua_store::SchemaPart;

pub(crate) use bindings::{
    bound_repo, normalize_repo, project_repo_bind, project_repo_get, project_repo_list, project_repo_unbind,
};
pub(crate) use block::{Blocked, check_claim, claim_block};
pub(crate) use claim_release::task_claim_release;
pub(crate) use holds::{task_hold, task_hold_get, task_holds};
pub use lifecycle::is_retired;
pub(crate) use lifecycle::{
    agent_pause, agent_resume, agent_retire, agent_state, agent_states, agent_terminate, agent_unretire,
    stopped,
};
pub(crate) use proposals::{
    check_contract, task_contract, work_proposal_decide, work_proposal_file, work_proposal_get,
    work_proposal_list, work_proposal_recover, work_proposal_withdraw,
};

use super::agents::verified;
use crate::registry::Registry;

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "governance.v1",
    sql: "
CREATE TABLE IF NOT EXISTS agent_lifecycle (
    agent TEXT PRIMARY KEY COLLATE NOCASE,
    state TEXT NOT NULL CHECK (state IN ('active','paused','terminated','retired')),
    previous TEXT,
    action TEXT NOT NULL,
    reason TEXT,
    actor TEXT NOT NULL,
    imposed_by TEXT,
    owner TEXT,
    since TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_holds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root_task_id INTEGER NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('pause','cancel')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','released')),
    reason TEXT NOT NULL DEFAULT '',
    release_policy TEXT NOT NULL DEFAULT 'manual'
        CHECK (release_policy IN ('manual','after_active_runs_finish')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    released_by TEXT,
    released_at TEXT,
    cancelling_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_task_holds_active_root ON task_holds(root_task_id)
    WHERE status = 'active';
CREATE TABLE IF NOT EXISTS task_hold_members (
    hold_id INTEGER NOT NULL REFERENCES task_holds(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    status_at_hold TEXT NOT NULL,
    cancel_requested_by_hold INTEGER NOT NULL DEFAULT 0,
    cancelled_run_id TEXT,
    cancelled_run_agent TEXT,
    restored_at TEXT,
    PRIMARY KEY (hold_id, task_id)
);
CREATE INDEX IF NOT EXISTS idx_task_hold_members_task ON task_hold_members(task_id);

CREATE TABLE IF NOT EXISTS project_repo_bindings (
    project TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    default_branch TEXT,
    bound_by TEXT NOT NULL,
    bound_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS work_proposals (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    proposer TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reporting_mode TEXT NOT NULL DEFAULT 'final_only',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    withdrawn_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_work_proposals_status ON work_proposals(status, created_at);
CREATE TABLE IF NOT EXISTS work_proposal_items (
    proposal_id TEXT NOT NULL REFERENCES work_proposals(id) ON DELETE CASCADE,
    idx INTEGER NOT NULL,
    title TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    scope_json TEXT NOT NULL DEFAULT '{}',
    priority TEXT NOT NULL DEFAULT 'med',
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approving','approved','rejected','withdrawn')),
    filed_digest TEXT NOT NULL,
    contract_digest TEXT NOT NULL,
    edited INTEGER NOT NULL DEFAULT 0,
    approving_by TEXT,
    approving_at TEXT,
    decided_by TEXT,
    decided_at TEXT,
    task_id INTEGER,
    PRIMARY KEY (proposal_id, idx)
);
CREATE INDEX IF NOT EXISTS idx_work_proposal_items_approving ON work_proposal_items(approving_at)
    WHERE status = 'approving';
",
};

pub fn register(r: &mut Registry) {
    worktrees::register(r);
}

// --- shared helpers -------------------------------------------------------------

/// The longest reason any governance action stores.
pub(crate) const MAX_REASON: usize = 500;

/// Whitespace-collapsed reason text, at most [`MAX_REASON`] characters.
pub(crate) fn clean_reason(raw: Option<&str>, required: Option<&str>) -> UaResult<String> {
    let text = raw.unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(what) = required
        && text.is_empty()
    {
        return Err(UaError::invalid(format!("a reason is required to {what}")));
    }
    if text.chars().count() > MAX_REASON {
        return Err(UaError::invalid(format!("reason must be at most {MAX_REASON} characters")));
    }
    Ok(text)
}

/// The verified identity running `verb`, else a refusal.
pub(crate) fn verified_actor(caller: &Caller, verb: &str) -> UaResult<String> {
    verified(caller).map(str::to_string).ok_or_else(|| {
        UaError::denied("identity_required", format!("{verb} requires an authenticated identity"))
    })
}

pub(crate) fn now() -> String {
    ua_core::time::now()
}
