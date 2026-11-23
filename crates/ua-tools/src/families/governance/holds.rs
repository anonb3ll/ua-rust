//! Task subtree holds: stop a unit of work in one action and resume it safely.
//!
//! A hold covers a root task and its subtree. One active hold exists per
//! root; a released hold stays as history.
//!
//! - **Members are a snapshot**: the subtree at hold time, with each
//!   member's status then. A task added under the root later is not held
//!   (hold again after release); a member moved out stays held.
//! - **Refusal**: while a hold is active, the one claim gate refuses new
//!   work on a member with `task_held`: `task_claim`, `task_update` into
//!   `doing`, `dispatch_task`, node enqueues; `node_claim` skips (and keeps
//!   queued) a held member's items. A live renewal by the current claimant
//!   passes, so an in-flight run can finish and report.
//! - **Modes** (`task_hold`): `pause` creates the hold (an active hold is
//!   returned as is); `cancel` holds and also requests cancellation of each
//!   member's live dispatch run and queued or claimed node item, each under
//!   its own authority rule (escalating an active pause hold); `resume`
//!   releases; `restore` releases once every run the hold's cancel stopped
//!   has closed (until then the member is `pending` and the hold stays).
//! - **Release policy**: `manual` (default) or `after_active_runs_finish`,
//!   which releases the hold by itself once no member has live work (a
//!   claimed `doing` row on a live lease, a live dispatch run, or a queued
//!   or claimed node item). It is evaluated when a hold is read and when a
//!   claim meets it, so no daemon is involved. It cannot be combined with
//!   `cancel`, and a new hold with it needs live work in the subtree.
//!
//! Who may hold: a caller whose profile exposes `task_update`. Who may
//! release: the hold's creator or an operator (a lifecycle operator or a
//! human identity). Every hold, release, cancel and restore is an
//! `agent.task.hold` ledger event in the same transaction.

use rusqlite::{Connection, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, Procedure, SchemaPart, WriteTx, ledger};

use super::lifecycle::stop_runs;
use super::{clean_reason, now};
use crate::families::agents::verified;
use crate::families::dispatch::{load_run, states};
use crate::families::node_queue;
use crate::families::tasks::{acting_identity, subtree_ids};
use crate::registry::ToolCtx;
use ua_org::authz::{Authority, Authz};

/// `organization.v1.tools.holds`: `org_id` on `task_holds` and
/// `task_hold_members`, and their generated `*_org_exists` /
/// `*_org_immutable` triggers. No key rebuild: a hold id is a hub-global
/// AUTOINCREMENT id, a member's key `(hold_id, task_id)` is led by it, and the
/// one-active-hold-per-root index stays keyed by the hub-global root task id.
/// The column fills with the default organization here; [`HOLDS_ORG_SCOPE`]
/// then moves each row to its root task's organization. Applied after the
/// governance parts and `tasks.v2.org_scope`.
pub const HOLDS_TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.tools.holds", &["task_holds", "task_hold_members"]);

/// `governance.v3.holds_org_scope`: holds written before
/// [`HOLDS_TENANT_PART`] move to their root task's organization (a hold whose
/// root is gone stays in the default organization) and members to their
/// hold's; indexes led by `org_id` for the hold list and the member lookup
/// of the claim gate; and triggers that keep a hold's root task, a member's
/// task and a member's hold inside the row's organization (`root_task_id`
/// has no foreign key, and the members' foreign keys alone would accept
/// another organization's row). The backfill drops each `*_org_immutable`
/// trigger for its one `UPDATE` and puts the same trigger back, in this
/// part's transaction.
pub const HOLDS_ORG_SCOPE: SchemaPart = SchemaPart {
    name: "governance.v3.holds_org_scope",
    sql: concat!(
        "
DROP TRIGGER task_holds_org_immutable;
UPDATE task_holds SET org_id = (SELECT t.org_id FROM tasks t WHERE t.id = task_holds.root_task_id)
WHERE EXISTS (SELECT 1 FROM tasks t WHERE t.id = task_holds.root_task_id AND t.org_id IS NOT task_holds.org_id);
",
        crate::families::continuity::org_immutable!("task_holds"),
        "
DROP TRIGGER task_hold_members_org_immutable;
UPDATE task_hold_members SET org_id = (SELECT h.org_id FROM task_holds h WHERE h.id = task_hold_members.hold_id)
WHERE EXISTS (
    SELECT 1 FROM task_holds h WHERE h.id = task_hold_members.hold_id AND h.org_id IS NOT task_hold_members.org_id
);
",
        crate::families::continuity::org_immutable!("task_hold_members"),
        "
CREATE INDEX IF NOT EXISTS idx_task_holds_org_status ON task_holds(org_id, status, root_task_id);
CREATE INDEX IF NOT EXISTS idx_task_hold_members_org_task ON task_hold_members(org_id, task_id);

CREATE TRIGGER IF NOT EXISTS task_holds_org_parent BEFORE INSERT ON task_holds
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.root_task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS task_holds_org_parent_update BEFORE UPDATE OF root_task_id ON task_holds
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.root_task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS task_hold_members_org_parent BEFORE INSERT ON task_hold_members
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM task_holds WHERE id = NEW.hold_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task or hold belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS task_hold_members_org_parent_update
BEFORE UPDATE OF task_id, hold_id ON task_hold_members
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM task_holds WHERE id = NEW.hold_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task or hold belongs to another organization'); END;
"
    ),
};

pub const CHANNEL: &str = "agent.task.hold";
const MODES: [&str; 4] = ["pause", "cancel", "resume", "restore"];
const POLICIES: [&str; 2] = ["manual", "after_active_runs_finish"];
const AUTO_RELEASE_ACTOR: &str = "task-hold:after_active_runs_finish";
/// A `cancelling` mark older than this is from an interrupted cancel.
const CANCELLING_STALE_S: i64 = 300;
const LIST_MAX: i64 = 500;
const NO_AUTO_RELEASE_CANCEL: &str = "release_policy after_active_runs_finish cannot be combined with cancel: a \
     cancel hold that released itself could no longer be restored; use release_policy manual";

#[derive(Debug, Clone)]
struct Hold {
    id: i64,
    /// The hold's organization (`task_holds.org_id`): its root task's, kept
    /// when the root is deleted.
    org: String,
    root_task_id: i64,
    mode: String,
    status: String,
    reason: String,
    release_policy: String,
    created_by: String,
    created_at: String,
    released_by: Option<String>,
    released_at: Option<String>,
    cancelling_at: Option<String>,
}

const HOLD_COLS: &str = "h.id, h.root_task_id, h.mode, h.status, h.reason, h.release_policy, h.created_by, \
     h.created_at, h.released_by, h.released_at, h.cancelling_at, h.org_id";

fn hold_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<Hold> {
    Ok(Hold {
        id: r.get(0)?,
        root_task_id: r.get(1)?,
        mode: r.get(2)?,
        status: r.get(3)?,
        reason: r.get(4)?,
        release_policy: r.get(5)?,
        created_by: r.get(6)?,
        created_at: r.get(7)?,
        released_by: r.get(8)?,
        released_at: r.get(9)?,
        cancelling_at: r.get(10)?,
        org: r.get(11)?,
    })
}

fn holds_where(c: &Connection, filter: &str, p: impl rusqlite::Params) -> UaResult<Vec<Hold>> {
    let mut stmt = c.prepare(&format!("SELECT {HOLD_COLS} FROM task_holds h WHERE {filter}"))?;
    let rows = stmt.query_map(p, hold_from)?.collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Hold `id` of organization `org`; another organization's hold answers as
/// a missing one.
fn load_hold(c: &Connection, org: &str, id: i64) -> UaResult<Option<Hold>> {
    Ok(holds_where(c, "h.org_id = ?2 AND h.id = ?1", params![id, org])?.into_iter().next())
}

fn active_for_root(c: &Connection, org: &str, root: i64) -> UaResult<Option<Hold>> {
    Ok(holds_where(c, "h.org_id = ?2 AND h.root_task_id = ?1 AND h.status = 'active'", params![root, org])?
        .into_iter()
        .next())
}

/// Whether a cancel on this hold is still recording its requests.
fn cancelling(h: &Hold) -> bool {
    let Some(at) = h.cancelling_at.as_deref().and_then(ua_core::time::parse_ts) else { return false };
    jiff::Timestamp::now().as_second() - at.as_second() < CANCELLING_STALE_S
}

/// Members with live work: a claimed `doing` row on a live lease, a live
/// dispatch run, or a queued or claimed node item. Only the hold's own
/// organization's members count.
fn live_run_task_ids(c: &Connection, h: &Hold) -> UaResult<Vec<i64>> {
    let mut stmt = c.prepare(
        "SELECT t.id FROM task_hold_members m JOIN tasks t ON t.id = m.task_id AND t.org_id = ?3
         WHERE m.org_id = ?3 AND m.hold_id = ?1 AND t.status = 'doing' AND t.claimed_by IS NOT NULL
           AND t.lock_expires_at IS NOT NULL AND t.lock_expires_at > ?2
         UNION
         SELECT d.task_id FROM dispatch_runs d JOIN task_hold_members m ON m.task_id = d.task_id
         WHERE m.org_id = ?3 AND m.hold_id = ?1 AND d.state IN ('claimed','launched','running')
         UNION
         SELECT n.task_id FROM node_dispatch n JOIN task_hold_members m ON m.task_id = n.task_id
         WHERE m.org_id = ?3 AND m.hold_id = ?1 AND n.status IN ('queued','claimed')
         ORDER BY 1",
    )?;
    let ids = stmt.query_map(params![h.id, now(), h.org], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(ids)
}

/// Record a hold event about a hold of organization `org`. ORG-EVENT-DEFAULT:
/// the row stays in the default ledger, so another organization's reason,
/// actor and per-member outcomes (which carry agent labels) are `null` and
/// the originator is the neutral `system`; ids and the action remain.
fn record(tx: &mut WriteTx<'_>, org: &str, who: &str, mut payload: Value) -> UaResult<()> {
    payload["kind"] = json!("task.hold");
    payload["actor"] = json!(who);
    payload["at"] = json!(now());
    let mut by = who.to_string();
    if org != ua_core::DEFAULT_ORG {
        by = "system".into();
        for key in ["actor", "reason", "outcomes", "restored"] {
            if let Some(v) = payload.get_mut(key) {
                *v = Value::Null;
            }
        }
    }
    ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, CHANNEL, payload).by(by))?;
    Ok(())
}

fn release_in_tx(
    tx: &mut WriteTx<'_>,
    h: &Hold,
    who: &str,
    action: &str,
    reason: &str,
    extra: Value,
) -> UaResult<()> {
    let n = tx.execute(
        "UPDATE task_holds SET status = 'released', released_by = ?2, released_at = ?3 \
         WHERE org_id = ?4 AND id = ?1 AND status = 'active'",
        params![h.id, who, now(), h.org],
    )?;
    if n != 1 {
        return Err(UaError::conflict(format!("hold #{} changed while it was being released; retry", h.id)));
    }
    let mut payload = json!({
        "action": action,
        "hold_id": h.id,
        "root_task_id": h.root_task_id,
        "reason": (!reason.is_empty()).then_some(reason),
    });
    if let (Some(p), Value::Object(e)) = (payload.as_object_mut(), extra) {
        p.extend(e);
    }
    record(tx, &h.org, who, payload)
}

fn auto_release(tx: &mut WriteTx<'_>, h: &Hold) -> UaResult<()> {
    release_in_tx(
        tx,
        h,
        AUTO_RELEASE_ACTOR,
        "auto_release",
        "no member has a live run (release_policy after_active_runs_finish)",
        json!({}),
    )
}

/// Release every due `after_active_runs_finish` hold of organization `org`:
/// the read-time check. Another organization's due holds are released when
/// that organization reads its holds or a claim meets them.
fn settle_due(tx: &mut WriteTx<'_>, org: &str) -> UaResult<()> {
    for h in holds_where(
        tx,
        "h.org_id = ?1 AND h.status = 'active' AND h.release_policy = 'after_active_runs_finish'",
        [org],
    )? {
        if live_run_task_ids(tx, &h)?.is_empty() {
            auto_release(tx, &h)?;
        }
    }
    Ok(())
}

/// The active hold over `task_id`, as a refusal message, after releasing
/// any `after_active_runs_finish` hold over it that is due.
pub(crate) fn subtree_block(tx: &mut WriteTx<'_>, org: &str, task_id: i64) -> UaResult<Option<String>> {
    let rows = holds_where(
        tx,
        "h.org_id = ?2 AND h.status = 'active' \
         AND h.id IN (SELECT hold_id FROM task_hold_members WHERE org_id = ?2 AND task_id = ?1) ORDER BY h.id",
        params![task_id, org],
    )?;
    for h in rows {
        if h.release_policy == "after_active_runs_finish" && live_run_task_ids(tx, &h)?.is_empty() {
            auto_release(tx, &h)?;
            continue;
        }
        let why = if h.reason.is_empty() { String::new() } else { format!(": {}", h.reason) };
        return Ok(Some(format!(
            "task {task_id} is held by hold #{} on task #{} ({}, by {}){why}; new claims are refused until the \
             hold is released (coordination_manage task_hold mode=resume)",
            h.id, h.root_task_id, h.mode, h.created_by
        )));
    }
    Ok(None)
}

/// A member row joined with its task.
struct Member {
    task_id: i64,
    status_at_hold: String,
    cancel_requested_by_hold: bool,
    cancelled_run_id: Option<String>,
    cancelled_run_agent: Option<String>,
    restored_at: Option<String>,
    status: String,
    claimed_by: Option<String>,
}

fn members(c: &Connection, org: &str, hold_id: i64) -> UaResult<Vec<Member>> {
    let mut stmt = c.prepare(
        "SELECT m.task_id, m.status_at_hold, m.cancel_requested_by_hold, m.cancelled_run_id, m.cancelled_run_agent, \
         m.restored_at, t.status, t.claimed_by FROM task_hold_members m \
         JOIN tasks t ON t.id = m.task_id AND t.org_id = ?2 \
         WHERE m.org_id = ?2 AND m.hold_id = ?1 ORDER BY m.task_id",
    )?;
    let rows = stmt
        .query_map(params![hold_id, org], |r| {
            Ok(Member {
                task_id: r.get(0)?,
                status_at_hold: r.get(1)?,
                cancel_requested_by_hold: r.get::<_, i64>(2)? != 0,
                cancelled_run_id: r.get(3)?,
                cancelled_run_agent: r.get(4)?,
                restored_at: r.get(5)?,
                status: r.get(6)?,
                claimed_by: r.get(7)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

fn serialize(c: &Connection, h: &Hold) -> UaResult<Value> {
    let ms = members(c, &h.org, h.id)?;
    let active = h.status == "active";
    Ok(json!({
        "id": h.id,
        "root_task_id": h.root_task_id,
        "mode": h.mode,
        "status": h.status,
        "reason": h.reason,
        "release_policy": h.release_policy,
        "created_by": h.created_by,
        "created_at": h.created_at,
        "released_by": h.released_by,
        "released_at": h.released_at,
        "cancelling": active && cancelling(h),
        "member_ids": ms.iter().map(|m| m.task_id).collect::<Vec<_>>(),
        "members": ms.iter().map(|m| json!({
            "task_id": m.task_id,
            "status_at_hold": m.status_at_hold,
            "status": m.status,
            "cancel_requested_by_hold": m.cancel_requested_by_hold,
            "cancelled_run_id": m.cancelled_run_id,
            "restored_at": m.restored_at,
        })).collect::<Vec<_>>(),
        "live_run_task_ids": if active { live_run_task_ids(c, h)? } else { Vec::new() },
    }))
}

fn get(c: &Connection, org: &str, id: i64) -> UaResult<Value> {
    let h = load_hold(c, org, id)?.ok_or_else(|| UaError::not_found(format!("no task hold with id {id}")))?;
    serialize(c, &h)
}

// --- arguments ------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HoldArgs {
    /// The root task: it and its subtree (as of now) are held.
    pub root_task_id: i64,
    /// `pause` (default), `cancel`, `resume` or `restore`.
    pub mode: Option<String>,
    /// Why (required for pause and cancel), at most 500 characters.
    pub reason: Option<String>,
    /// `manual` (default) or `after_active_runs_finish` (pause only: release
    /// by itself once nothing in the subtree is running).
    pub release_policy: Option<String>,
    /// Guard: refuse unless this is the root's active hold.
    pub hold_id: Option<i64>,
    /// Attribution for an unverified caller; ignored when the caller is
    /// verified. It grants no authority: releasing needs a verified creator
    /// or operator.
    pub actor: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HoldsArgs {
    /// Only holds on this root task.
    pub root_task_id: Option<i64>,
    /// `active` (default), `released` or `all`.
    pub status: Option<String>,
    /// Rows, newest first (default 200, max 500).
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HoldGetArgs {
    /// The hold.
    pub hold_id: i64,
}

// --- reads ----------------------------------------------------------------------

/// `coordination_manage(action="task_holds")`.
pub(crate) async fn task_holds(ctx: ToolCtx, a: HoldsArgs) -> UaResult<Value> {
    let view = a.status.as_deref().map(str::trim).unwrap_or("active").to_ascii_lowercase();
    if !["active", "released", "all"].contains(&view.as_str()) {
        return Err(UaError::invalid("status must be one of active, released, all"));
    }
    let cap = a.limit.unwrap_or(200).clamp(1, LIST_MAX);
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            settle_due(tx, &org)?;
            let rows = holds_where(
                tx,
                "h.org_id = ?4 AND (?1 = 'all' OR h.status = ?1) AND (?2 IS NULL OR h.root_task_id = ?2) \
                 ORDER BY h.id DESC LIMIT ?3",
                params![view, a.root_task_id, cap + 1, org],
            )?;
            let truncated = rows.len() as i64 > cap;
            let holds =
                rows.iter().take(cap as usize).map(|h| serialize(tx, h)).collect::<UaResult<Vec<_>>>()?;
            Ok(json!({ "holds": holds, "truncated": truncated }))
        })
        .await
}

/// `coordination_manage(action="task_hold_get")`.
pub(crate) async fn task_hold_get(ctx: ToolCtx, a: HoldGetArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            settle_due(tx, &org)?;
            get(tx, &org, a.hold_id)
        })
        .await
}

// --- the action -----------------------------------------------------------------

/// Who may release `h`: its creator or an operator, both verified. An
/// unverified caller's `actor` is attribution only, so naming the creator
/// grants nothing. Returns whether the releaser is an operator.
fn release_authority(h: &Hold, who: &str, verified: bool, maintainer: bool) -> UaResult<bool> {
    if verified && maintainer {
        return Ok(true);
    }
    if verified && who == h.created_by {
        return Ok(false);
    }
    Err(UaError::denied(
        "not_hold_owner",
        format!(
            "{who:?} may not release hold #{}: only its creator ({}) or an operator (lifecycle_operators or a \
             human identity) may",
            h.id, h.created_by
        ),
    ))
}

fn create(
    tx: &mut WriteTx<'_>,
    org: &str,
    root: i64,
    mode: &str,
    reason: &str,
    policy: &str,
    who: &str,
) -> UaResult<i64> {
    tx.execute(
        "INSERT INTO task_holds (org_id, root_task_id, mode, status, reason, release_policy, created_by, \
         created_at, cancelling_at) VALUES (?8, ?1, ?2, 'active', ?3, ?4, ?5, ?6, ?7)",
        params![root, mode, reason, policy, who, now(), (mode == "cancel").then(now), org],
    )?;
    let id = tx.last_insert_rowid();
    for task_id in subtree_ids(tx, org, root)? {
        tx.execute(
            "INSERT INTO task_hold_members (org_id, hold_id, task_id, status_at_hold) \
             SELECT ?3, ?1, id, status FROM tasks WHERE org_id = ?3 AND id = ?2",
            params![id, task_id, org],
        )?;
    }
    Ok(id)
}

/// Undo the hold's cancel member by member. Returns the outcomes and
/// whether every member is settled.
fn restore_in_tx(
    tx: &mut WriteTx<'_>,
    h: &Hold,
    who: &str,
    verified: bool,
    maintainer: bool,
) -> UaResult<(Vec<Value>, bool)> {
    let mut out = Vec::new();
    let mut settled = true;
    let stamp = now();
    for m in members(tx, &h.org, h.id)? {
        if !m.cancel_requested_by_hold || crate::families::tasks::is_terminal(&m.status_at_hold) {
            continue;
        }
        let base = json!({ "task_id": m.task_id, "run_id": m.cancelled_run_id });
        let with = |control: &str, detail: String| {
            let mut v = base.clone();
            v["control"] = json!(control);
            v["detail"] = json!(detail);
            v
        };
        if let Some(at) = &m.restored_at {
            out.push(with("restored", format!("at {at}")));
            continue;
        }
        let run_agent = m.cancelled_run_agent.clone().unwrap_or_default();
        if !maintainer && !(verified && who == run_agent) {
            settled = false;
            out.push(with(
                "refused",
                format!(
                    "{who:?} may not undo the cancel on {run_agent:?}'s run: its claimant or an operator may"
                ),
            ));
            continue;
        }
        let run = match &m.cancelled_run_id {
            Some(r) => load_run(tx, r)?,
            None => None,
        };
        if run.as_ref().is_some_and(|r| states::is_live(&r.state)) {
            settled = false;
            out.push(with("pending", "run still stopping; restore again once it closes".into()));
            continue;
        }
        tx.execute(
            "UPDATE task_hold_members SET restored_at = ?3 WHERE org_id = ?4 AND hold_id = ?1 AND task_id = ?2",
            params![h.id, m.task_id, stamp, h.org],
        )?;
        let mut v = with("closed", "the cancelled run has closed; the task keeps its status".into());
        v["status"] = json!(m.status);
        out.push(v);
    }
    Ok((out, settled))
}

struct Outcome {
    hold_id: i64,
    changed: bool,
    released: bool,
    restored: Vec<Value>,
    cancel: bool,
}

/// `coordination_manage(action="task_hold")`.
pub(crate) async fn task_hold(ctx: ToolCtx, a: HoldArgs) -> UaResult<Value> {
    let verb = a.mode.as_deref().map(str::trim).unwrap_or("pause").to_ascii_lowercase();
    if !MODES.contains(&verb.as_str()) {
        return Err(UaError::invalid(format!("mode must be one of {}", MODES.join(", "))));
    }
    let policy = a.release_policy.as_deref().map(str::trim).unwrap_or("manual").to_ascii_lowercase();
    if !POLICIES.contains(&policy.as_str()) {
        return Err(UaError::invalid(format!("release_policy must be one of {}", POLICIES.join(", "))));
    }
    if verb == "cancel" && policy == "after_active_runs_finish" {
        return Err(UaError::invalid(NO_AUTO_RELEASE_CANCEL));
    }
    if ctx.caller.enforce_profile && !ctx.caller.profile.allows_tool("task_update") {
        return Err(UaError::denied(
            "profile_denied",
            format!("task holds need task_update in the active profile ({})", ctx.caller.profile),
        ));
    }
    let who = acting_identity(&ctx.caller, a.actor.as_deref())?;
    let is_verified = verified(&ctx.caller).is_some();
    let org = ctx.caller.org_id.clone();
    let maintainer = Authz::new(ctx.hub.cfg()).holds(
        &ctx.caller,
        &[Authority::Operator, Authority::LifecycleOperator],
        &org,
    );
    let reason = clean_reason(
        a.reason.as_deref(),
        matches!(verb.as_str(), "pause" | "cancel").then_some("hold a subtree"),
    )?;
    let root = a.root_task_id;
    let (v2, w2, r2, o2) = (verb.clone(), who.clone(), reason.clone(), org.clone());
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let (verb, who, reason, org) = (v2, w2, r2, o2);
            crate::families::tasks::require_org(tx, &org)?;
            let mut existing = active_for_root(tx, &org, root)?;
            // A due after_active_runs_finish hold would release itself on the
            // next read. Settle it first, so a pause or cancel takes effect
            // instead of finding a hold that is about to go.
            if matches!(verb.as_str(), "pause" | "cancel")
                && let Some(h) = &existing
                && h.release_policy == "after_active_runs_finish"
                && live_run_task_ids(tx, h)?.is_empty()
            {
                auto_release(tx, h)?;
                existing = None;
            }
            // Existing holds can outlive their roots. Releasing one still
            // uses its stored creator and the same release authority check.
            if existing.is_none() || matches!(verb.as_str(), "pause" | "cancel") {
                crate::families::tasks::require_task(tx, &org, root)?;
            }
            if let Some(want) = a.hold_id
                && existing.as_ref().map(|h| h.id) != Some(want)
            {
                return Err(UaError::invalid(format!("hold #{want} is not the active hold on task #{root}")));
            }
            let mut out =
                Outcome { hold_id: 0, changed: true, released: false, restored: Vec::new(), cancel: false };
            if verb == "pause" || verb == "cancel" {
                let escalated = existing.is_some();
                match &existing {
                    Some(h) if verb == "pause" || h.mode == "cancel" => {
                        out.changed = false;
                        out.hold_id = h.id;
                    }
                    Some(h) => {
                        if h.release_policy == "after_active_runs_finish" {
                            return Err(UaError::invalid(NO_AUTO_RELEASE_CANCEL));
                        }
                        out.hold_id = h.id;
                        tx.execute(
                            "UPDATE task_holds SET mode = 'cancel', cancelling_at = ?2 WHERE org_id = ?3 AND id = ?1",
                            params![h.id, now(), org],
                        )?;
                    }
                    None => {
                        out.hold_id = create(tx, &org, root, &verb, &reason, &policy, &who)?;
                        let created = load_hold(tx, &org, out.hold_id)?
                            .ok_or_else(|| UaError::internal(format!("hold #{} vanished", out.hold_id)))?;
                        if policy == "after_active_runs_finish" && live_run_task_ids(tx, &created)?.is_empty()
                        {
                            return Err(UaError::invalid(format!(
                                "nothing is running in task #{root}'s subtree, so release_policy \
                                 after_active_runs_finish would release the hold at once; hold it with \
                                 release_policy manual and release it by hand"
                            )));
                        }
                    }
                }
                if out.changed {
                    let ids: Vec<i64> = members(tx, &org, out.hold_id)?.iter().map(|m| m.task_id).collect();
                    record(
                        tx,
                        &org,
                        &who,
                        json!({
                            "action": verb,
                            "hold_id": out.hold_id,
                            "root_task_id": root,
                            "reason": reason,
                            "release_policy": (!escalated).then_some(&policy),
                            "members": ids,
                            "escalated": escalated,
                        }),
                    )?;
                    out.cancel = verb == "cancel";
                }
            } else {
                let Some(h) = existing else {
                    return Err(UaError::invalid(format!("task {root} has no active hold")));
                };
                out.hold_id = h.id;
                let op = release_authority(&h, &who, is_verified, maintainer)?;
                if cancelling(&h) {
                    return Err(UaError::conflict(format!(
                        "hold #{} is still recording its cancel requests; {verb} once that finishes",
                        h.id
                    )));
                }
                out.released = true;
                if verb == "restore" {
                    let (restored, settled) = restore_in_tx(tx, &h, &who, is_verified, op)?;
                    out.restored = restored;
                    out.released = settled;
                }
                if out.released {
                    let extra = json!({ "restored": (!out.restored.is_empty()).then_some(&out.restored) });
                    release_in_tx(tx, &h, &who, &verb, &reason, extra)?;
                } else {
                    record(
                        tx,
                        &org,
                        &who,
                        json!({
                            "action": "restore_pending",
                            "hold_id": h.id,
                            "root_task_id": root,
                            "reason": (!reason.is_empty()).then_some(&reason),
                            "restored": out.restored,
                        }),
                    )?;
                }
            }
            Ok(out)
        })
        .await?;

    let mut result = json!({ "action": verb, "changed": out.changed });
    if out.cancel {
        result["cancel_requests"] =
            json!(request_cancels(&ctx, &org, out.hold_id, root, &who, maintainer, &reason).await?);
    }
    if verb == "resume" || verb == "restore" {
        result["released"] = json!(out.released);
    }
    if !out.restored.is_empty() {
        result["pending"] = json!(
            out.restored
                .iter()
                .filter(|r| matches!(r["control"].as_str(), Some("pending" | "refused")))
                .map(|r| r["task_id"].clone())
                .collect::<Vec<_>>()
        );
        result["restored"] = json!(out.restored);
    }
    let id = out.hold_id;
    result["hold"] = ctx.hub.db().read_async(move |c| get(c, &org, id)).await?;
    Ok(result)
}

/// Request cancellation of the live work of the hold's non-terminal members,
/// each through its own path and authority rule. The hold is `cancelling`
/// until the outcomes are recorded; the mark is always cleared.
async fn request_cancels(
    ctx: &ToolCtx,
    org: &str,
    hold_id: i64,
    root: i64,
    who: &str,
    maintainer: bool,
    reason: &str,
) -> UaResult<Vec<Value>> {
    let is_verified = verified(&ctx.caller).is_some();
    type Run = (String, i64, String);
    let org1 = org.to_string();
    let (runs, items): (Vec<Run>, Vec<(node_queue::Item, Option<String>)>) = ctx
        .hub
        .db()
        .read_async(move |c| {
            let live: Vec<Member> = members(c, &org1, hold_id)?
                .into_iter()
                .filter(|m| !crate::families::tasks::is_terminal(&m.status_at_hold))
                .collect();
            let mut runs = Vec::new();
            let mut items = Vec::new();
            for m in &live {
                let mut stmt = c.prepare(
                    "SELECT run_id, agent_label FROM dispatch_runs WHERE task_id = ?1 \
                     AND state IN ('claimed','launched','running') AND termination_outcome IS NULL",
                )?;
                for r in
                    stmt.query_map([m.task_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                {
                    let (run_id, agent) = r?;
                    runs.push((run_id, m.task_id, agent));
                }
                for item in node_queue::items_where(
                    c,
                    "task_id = ?1 AND status IN ('queued','claimed') AND run_id IS NULL ORDER BY created_at",
                    [m.task_id],
                )? {
                    items.push((item, m.claimed_by.clone()));
                }
            }
            Ok((runs, items))
        })
        .await?;

    let mut outcomes = Vec::new();
    let mut flagged: Vec<(String, String, i64)> = Vec::new();
    let why = format!("task hold #{hold_id}: {reason}");
    for (run_id, task_id, agent) in runs {
        if !(maintainer || (is_verified && who == agent)) {
            outcomes.push(json!({
                "task_id": task_id, "path": "dispatch", "ref": run_id, "control": "refused",
                "detail": "cancelling another agent's run is an operator action",
            }));
            continue;
        }
        let mut row = stop_runs(&ctx.hub, who, vec![(run_id.clone(), task_id)], &why).await.remove(0);
        if matches!(row["control"].as_str(), Some("confirmed" | "requested")) {
            flagged.push((run_id, agent, task_id));
        }
        row["task_id"] = json!(task_id);
        outcomes.push(row);
    }
    let (who2, why2) = (who.to_string(), why.clone());
    let mut node_out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let mut out = Vec::new();
            for (item, claimant) in items {
                let base = json!({ "task_id": item.task_id, "path": "node", "ref": item.id });
                let allowed = maintainer
                    || (is_verified
                        && (who2 == item.created_by
                            || who2 == item.agent
                            || claimant.as_deref() == Some(&who2)));
                let mut v = base.clone();
                if !allowed {
                    v["control"] = json!("refused");
                    v["detail"] = json!("stopping another identity's node item is an operator action");
                } else {
                    let res = node_queue::cancel_item(tx, &item.id, &who2, &why2)?;
                    v["control"] =
                        json!(if res["changed"] == json!(true) { "requested" } else { "unchanged" });
                    v["detail"] = json!(if item.status == "queued" {
                        "will not start"
                    } else {
                        "relayed on the node's next heartbeat"
                    });
                }
                out.push(v);
            }
            Ok(out)
        })
        .await
        .unwrap_or_else(|e| vec![json!({ "path": "node", "control": "failed", "detail": e.to_string() })]);
    outcomes.append(&mut node_out);

    let (who3, recorded, org3) = (who.to_string(), outcomes.clone(), org.to_string());
    ctx.hub
        .db()
        .write_async(move |tx| {
            for (run_id, agent, task_id) in &flagged {
                tx.execute(
                    "UPDATE task_hold_members SET cancel_requested_by_hold = 1, cancelled_run_id = ?3, \
                     cancelled_run_agent = ?4 WHERE org_id = ?5 AND hold_id = ?1 AND task_id = ?2",
                    params![hold_id, task_id, run_id, agent, org3],
                )?;
            }
            tx.execute(
                "UPDATE task_holds SET cancelling_at = NULL WHERE org_id = ?2 AND id = ?1",
                params![hold_id, org3],
            )?;
            record(
                tx,
                &org3,
                &who3,
                json!({ "action": "cancel_requested", "hold_id": hold_id, "root_task_id": root, "outcomes": recorded }),
            )
        })
        .await?;
    Ok(outcomes)
}
