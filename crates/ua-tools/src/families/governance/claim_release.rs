//! Operator release of another agent's live task claim.
//!
//! `task_update(release_claim=true)` lets the claimant release its own claim
//! and anyone release an expired one. `task_claim_release` is the
//! task-scoped operator path for a live claim held by someone else:
//!
//! - **Authority**: a lifecycle operator or a human identity. Nobody else;
//!   the claimant uses `task_update(release_claim=true)`.
//! - **Fencing**: `expected_claimant` is required; `expected_run_id` and
//!   `expected_claimed_at` (the claim generation) are optional. All are
//!   checked inside the write transaction, so a claim that changed hands, a
//!   run a renewal replaced, or a drop and re-claim by the same agent loses
//!   as a conflict instead of being released blind. A done or cancelled task
//!   is refused: its `claimed_by` is the row's attribution.
//! - **Effect**: the claim columns are cleared; a `doing` task goes back to
//!   `open`, any other status is kept. Handing the task over is then an
//!   ordinary `task_claim` by the new agent.
//! - **Audit**: one `agent.task.claim_released` event in the release
//!   transaction (actor, authority, previous claimant and run, reason); the
//!   reason is also appended to the task notes.
//!
//! Release does not stop a running executor: a live dispatch run on the task
//! is refused (cancel it first with `dispatch_cancel`).

use rusqlite::params;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use super::{clean_reason, now, verified_actor};
use crate::families::dispatch::live_run_for_task;
use crate::families::tasks::{is_terminal, next_revision, require_task, str_field, task_reply};
use crate::registry::ToolCtx;
use ua_org::authz::{Authority, Authz};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArgs {
    /// The task whose claim is released.
    pub task_id: i64,
    /// The agent that holds the claim now. Refused if someone else holds it.
    pub expected_claimant: String,
    /// Why (required), at most 500 characters. Appended to the task notes.
    pub reason: Option<String>,
    /// Guard: the task's current dispatch run id.
    pub expected_run_id: Option<String>,
    /// Guard: the claim generation (`claimed_at`). With no `expected_run_id`
    /// it also requires that the claim still has no run.
    pub expected_claimed_at: Option<String>,
}

/// `coordination_manage(action="task_claim_release")`.
pub(crate) async fn task_claim_release(ctx: ToolCtx, a: ReleaseArgs) -> UaResult<Value> {
    let who = verified_actor(&ctx.caller, "releasing another agent's claim")?;
    if a.task_id <= 0 {
        return Err(UaError::invalid("task_id must be a positive integer"));
    }
    let claimant = a.expected_claimant.split_whitespace().collect::<Vec<_>>().join(" ");
    if claimant.is_empty() {
        return Err(UaError::invalid(
            "expected_claimant is required: name the agent whose claim you release",
        ));
    }
    if !Authz::new(ctx.hub.cfg()).holds(
        &ctx.caller,
        &[Authority::Operator, Authority::LifecycleOperator],
        ua_core::DEFAULT_ORG,
    ) {
        return Err(UaError::denied(
            "not_lifecycle_operator",
            format!(
                "{who:?} may not release another agent's claim: that is an operator action (lifecycle_operators \
                 or a human identity). A claimant releases its own claim with task_update(release_claim=true)."
            ),
        ));
    }
    let authority = if ctx.caller.is_human() || ctx.hub.cfg().is_human(&who) {
        "human_operator"
    } else {
        "lifecycle_operator"
    };
    let reason = clean_reason(a.reason.as_deref(), Some("release another agent's claim"))?;
    let expected_claimed_at = match a.expected_claimed_at.as_deref().map(str::trim) {
        Some("") => return Err(UaError::invalid("expected_claimed_at must be a non-empty claim generation")),
        other => other.map(str::to_string),
    };
    let expected_run = a.expected_run_id.map(|r| r.trim().to_string());
    let id = a.task_id;

    ctx.hub
        .db()
        .write_async(move |tx| {
            let row = require_task(tx, id)?;
            let status = str_field(&row, "status").unwrap_or("open").to_string();
            let holder = str_field(&row, "claimed_by").map(String::from);
            let claimed_at = str_field(&row, "claimed_at").map(String::from);
            let run = str_field(&row, "current_run_id").map(String::from);
            let lease = str_field(&row, "lock_expires_at").map(String::from);
            let Some(holder) = holder else {
                return Err(UaError::conflict(format!("task {id} has no claim to release")));
            };
            if is_terminal(&status) {
                return Err(UaError::conflict(format!(
                    "task {id} is {status}: a terminal task has no claim to transfer, and its claimed_by records \
                     who did the work"
                )));
            }
            if holder != claimant {
                return Err(UaError::conflict(format!(
                    "task {id} is claimed by {holder:?}, not the expected {claimant:?}; refresh and retry"
                )));
            }
            if let Some(gen_) = &expected_claimed_at
                && claimed_at.as_deref() != Some(gen_.as_str())
            {
                return Err(UaError::conflict(format!(
                    "task {id} was re-claimed by {holder:?} since claim generation {gen_:?}; refresh and retry"
                )));
            }
            match &expected_run {
                Some(r) if run.as_deref() != Some(r.as_str()) => {
                    return Err(UaError::conflict(format!(
                        "task {id}'s current run is {run:?}, not the expected {r:?}; refresh and retry"
                    )));
                }
                None if expected_claimed_at.is_some() && run.is_some() => {
                    return Err(UaError::conflict(format!("task {id}'s claim now has a run; refresh and retry")));
                }
                _ => {}
            }
            if let Some(live) = live_run_for_task(tx, id)? {
                return Err(UaError::conflict(format!(
                    "task {id} has a live dispatch run {live:?}; releasing the claim would not stop it. Cancel it \
                     first (dispatch_cancel) and retry once its termination is confirmed"
                )));
            }

            let status_after = if status == "doing" { "open" } else { status.as_str() }.to_string();
            let note = format!(
                "[claim-released] {who} ({authority}) released {holder}'s claim (run {}): {reason}",
                run.as_deref().unwrap_or("-")
            );
            let notes = match str_field(&row, "notes").filter(|n| !n.is_empty()) {
                Some(n) => format!("{n}\n{note}"),
                None => note,
            };
            let n = tx.execute(
                "UPDATE tasks SET status = ?2, claimed_by = NULL, claimed_at = NULL, lock_expires_at = NULL, \
                 next_owner = NULL, ownership_generation = ownership_generation + 1, notes = ?3, updated_at = ?4 \
                 WHERE id = ?1 AND claimed_by = ?5 AND status = ?6",
                params![id, status_after, notes, next_revision(str_field(&row, "updated_at")), holder, status],
            )?;
            if n != 1 {
                return Err(UaError::conflict(format!("task {id} changed during the release; refresh and retry")));
            }
            let released = json!({
                "kind": "claim.operator_released",
                "task_id": id,
                "claimant": holder,
                "previous_claimant": holder,
                "previous_run_id": run,
                "previous_lock_expires_at": lease,
                "status_before": status,
                "status_after": status_after,
                "reason": reason,
                "actor": who,
                "authority": authority,
                "at": now(),
            });
            let event =
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "agent.task.claim_released", released.clone()).by(who.clone()))?;
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG,
                    "agent.task.updated",
                    json!({
                        "task_id": id,
                        "fields": ["status", "claimed_by", "claimed_at", "lock_expires_at", "notes"],
                        "from_status": status,
                        "status": status_after,
                    }),
                )
                .by(who.clone()),
            )?;
            let mut released = released;
            released["event_ulid"] = json!(event.map(|e| e.ulid));
            Ok(json!({ "task": task_reply(tx, id)?, "released": released }))
        })
        .await
}
