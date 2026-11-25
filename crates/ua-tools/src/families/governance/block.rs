//! The one claim gate.

use ua_core::{UaError, UaResult};
use ua_store::WriteTx;

use super::{holds, lifecycle};
use crate::families::continuity;

/// Why work may not be handed out right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Blocked {
    /// Stable reason code: `agent_paused`, `agent_terminated`,
    /// `agent_retired`, `task_held` or `task_parked`.
    pub code: &'static str,
    pub message: String,
}

impl Blocked {
    /// The refusal as a `denied` error carrying the reason code.
    pub fn error(self) -> UaError {
        UaError::denied(self.code, self.message)
    }
}

/// Why `agent` may not take work, or `task_id` may not be newly claimed or
/// dispatched, right now. `None` when nothing blocks.
///
/// Runs inside the caller's write transaction, so the answer holds for the
/// write that follows it:
///
/// - `agent` (the agent that would hold the work): refused while it is
///   paused, terminated or retired. This applies to lease renewals too, so a
///   stopped agent cannot keep extending a claim.
/// - `task_id`: refused while an active subtree hold covers it, unless
///   `renewal` is set (a live renewal of the caller's own lease, which a hold
///   lets through so an in-flight run can finish and report). A due
///   `after_active_runs_finish` hold is released here first, in this
///   transaction.
/// - `task_id`: refused while the task is parked or folded into a parked
///   root (`queue_park`), renewals included: parking refuses a task with a
///   live claim, so nothing parked has one to renew.
///
/// Every path that hands out work calls this: `task_claim`, `task_update`
/// into `doing`, `dispatch_task`, `dispatch_resume`, every node enqueue
/// (`node_dispatch`, `node_command_start`, node-routed dispatch),
/// `node_claim` (for the node's owner, and per queued item to skip held
/// ones) and `plan_step_claim` (the agent only; a plan step is not a task).
///
/// `task_id` is a task of organization `org`; another organization's task is
/// read as a missing one, which blocks nothing (the caller has already
/// resolved the task in its organization, or refuses it as missing).
pub(crate) fn claim_block(
    tx: &mut WriteTx<'_>,
    org: &str,
    agent: Option<&str>,
    task_id: Option<i64>,
    renewal: bool,
) -> UaResult<Option<Blocked>> {
    if let Some(agent) = agent
        && let Some(stopped) = lifecycle::stopped(tx, agent)?
    {
        return Ok(Some(Blocked { code: stopped.code(), message: stopped.refusal(agent) }));
    }
    if let Some(task_id) = task_id
        && let Some(message) = continuity::parked_block(tx, org, task_id)?
    {
        return Ok(Some(Blocked { code: "task_parked", message }));
    }
    if let Some(task_id) = task_id
        && !renewal
        && let Some(message) = holds::subtree_block(tx, org, task_id)?
    {
        return Ok(Some(Blocked { code: "task_held", message }));
    }
    Ok(None)
}

/// [`claim_block`] as an error.
pub(crate) fn check_claim(
    tx: &mut WriteTx<'_>,
    org: &str,
    agent: Option<&str>,
    task_id: Option<i64>,
    renewal: bool,
) -> UaResult<()> {
    match claim_block(tx, org, agent, task_id, renewal)? {
        Some(b) => Err(b.error()),
        None => Ok(()),
    }
}
