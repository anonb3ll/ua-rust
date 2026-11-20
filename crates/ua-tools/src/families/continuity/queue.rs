//! Queue closure: staleness, park, fold, unpark and a queue-health read.
//!
//! The rules:
//!
//! 1. A task untouched for `stale_days` (default 30) may be PARKED, with a
//!    stated reason. Parked, not closed: it keeps its status.
//! 2. When a task is parked, its open descendants FOLD into it: no open
//!    child is left under a parked root.
//! 3. Nothing closes on a date alone. `queue_sweep` only proposes.
//!
//! Parking lives in its own columns on `tasks`: `parked_at`, `parked_by`,
//! `parked_reason` and `folded_into` (the parked root a folded descendant
//! went with; NULL on the root itself). Archiving (`archived_at`) is a
//! different thing (filed work) and is not touched. A parked task is left out
//! of `task_list` unless `parked=true` is passed, and the claim gate refuses
//! it (`task_parked`) until `queue_unpark` restores it. Closing a parked task
//! (`task_update` to done or cancelled) clears its parking.
//!
//! **Staleness** is the latest of `updated_at`, `claimed_at` and the task's
//! comment thread, else `created_at`. A task with live work (a live claim,
//! an open or live dispatch run, a pending or in-flight delegation, queued or
//! claimed node work) is never stale and is never parked or folded.
//!
//! **Protected** rows are never proposed for parking: the human-only lanes
//! (`operator-only`, `interactive-only`), `waiting_review`, a
//! `[waiting-for: ...]` marker, a red-tier row and the `tracking` lane.
//! `queue_park` parks a gated row only for a verified human or lifecycle
//! operator caller; the approval recorded is that caller's identity.
//! `approved_by` is free text and never authority: only such a caller may
//! pass it, and it is recorded as a note beside the approval.
//!
//! **Authority.** Park, fold and unpark need a verified caller. A task
//! someone holds (a non-empty `claimed_by` or `next_owner`) is written by
//! its claimant, its next owner, a lifecycle operator or a human, the same
//! rule as the task workflow record. A task nobody holds may be parked,
//! folded or unparked by any verified caller on the coordinator, lead or
//! developer profile. Parking also folds every open descendant, so each
//! descendant held by someone other than the caller needs an operator too.
//! Unpark is judged on the root alone: restoring a fold hides nothing.
//!
//! Close-on-merge (`queue_close_merged` in the Python hub) needs merged-PR
//! evidence from the forge and waits for the native GitHub client.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{Profile, UaError, UaResult};
use ua_store::WriteTx;

use super::same_label;
use crate::families::dispatch::live_run_for_task;
use crate::families::governance;
use crate::families::tasks::{
    acting_identity, ancestors, emit, has_marker, int_field, next_revision, require_task, row_object,
    str_field, subtree_ids,
};
use crate::registry::ToolCtx;

const DEFAULT_STALE_DAYS: i64 = 30;
const ACTIVE_STATUSES: [&str; 4] = ["open", "doing", "waiting_review", "blocked"];
const HUMAN_ONLY_LANES: [&str; 2] = ["operator-only", "interactive-only"];
/// Lanes that name no agent: a task in one of them has nobody to move it.
const POOL_LANES: [&str; 5] = ["default", "dispatch-ready", "tracking", "operator-only", "interactive-only"];
const REASON_MAX: usize = 500;
const MILESTONE_MARKER: &str = "[milestone-review]";
const CHANNEL_PARKED: &str = "agent.queue.parked";
const CHANNEL_FOLDED: &str = "agent.queue.folded";
const CHANNEL_UNPARKED: &str = "agent.queue.unparked";
const PARK_FIELDS: [&str; 4] = ["parked_at", "parked_by", "parked_reason", "folded_into"];
/// Profiles that may park, fold or unpark a task nobody holds.
const QUEUE_WRITER_PROFILES: [Profile; 3] = [Profile::Coordinator, Profile::Lead, Profile::Developer];

// --- arguments ----------------------------------------------------------------------

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthArgs {
    /// Days without a touch before a task counts as stale (default 30).
    pub stale_days: Option<i64>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaleArgs {
    /// Days without a touch before a task counts as stale (default 30).
    pub stale_days: Option<i64>,
    /// At most this many rows (1-1000, default 200).
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParkArgs {
    /// The task to park.
    pub task_id: i64,
    /// Why (required, at most 500 characters).
    pub reason: String,
    /// A note on the approval, recorded with the park. Not authority: a
    /// protected row (operator-only lane, human gate, red-tier) is parked
    /// only by a verified human or lifecycle operator, and only such a
    /// caller may pass this.
    pub approved_by: Option<String>,
    /// Fold open descendants into this task (default true). False refuses
    /// when any are open instead of leaving them under a parked root.
    pub fold_children: Option<bool>,
    /// Must name the caller when given: these writes need a verified caller.
    pub actor: Option<String>,
    /// Check and report without writing.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldArgs {
    /// An open descendant of `into`.
    pub task_id: i64,
    /// A parked root that is an ancestor of `task_id`.
    pub into: i64,
    /// Why (required, at most 500 characters).
    pub reason: String,
    /// Must name the caller when given: these writes need a verified caller.
    pub actor: Option<String>,
    /// Check and report without writing.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnparkArgs {
    /// A parked root (a folded task is restored through its root).
    pub task_id: i64,
    /// Why (required, at most 500 characters).
    pub reason: String,
    /// Must name the caller when given: these writes need a verified caller.
    pub actor: Option<String>,
    /// Check and report without writing.
    #[serde(default)]
    pub dry_run: bool,
}

// --- authority ----------------------------------------------------------------------

/// A verified caller allowed to write the queue, and whether it holds
/// operator authority (a human or a lifecycle operator).
struct Writer {
    who: String,
    operator: bool,
}

fn queue_writer(ctx: &ToolCtx, actor: Option<&str>, verb: &str) -> UaResult<Writer> {
    acting_identity(&ctx.caller, actor)?;
    let who = governance::verified_actor(&ctx.caller, verb)?;
    let operator = governance::is_operator(ctx.hub.cfg(), &ctx.caller, &who);
    if !operator && !QUEUE_WRITER_PROFILES.contains(&ctx.caller.profile) {
        return Err(UaError::denied(
            "profile_denied",
            format!(
                "{verb} needs the coordinator, lead or developer profile, a lifecycle operator or a human"
            ),
        ));
    }
    Ok(Writer { who, operator })
}

/// The agents holding a task: its claimant and next owner, when set.
fn holders(row: &Row) -> Vec<&str> {
    ["claimed_by", "next_owner"]
        .into_iter()
        .filter_map(|k| s(row, k).map(str::trim))
        .filter(|h| !h.is_empty())
        .collect()
}

/// Refuse a write to a task someone other than the caller holds, unless the
/// caller is an operator. A task nobody holds is open to any queue writer.
fn require_holder(w: &Writer, row: &Row, verb: &str) -> UaResult<()> {
    let held = holders(row);
    if w.operator || held.is_empty() || held.iter().any(|h| same_label(Some(h), &w.who)) {
        return Ok(());
    }
    let id = int_field(row, "id").unwrap_or_default();
    Err(UaError::denied(
        "not_task_owner",
        format!(
            "{:?} may not {verb} task {id}: it is held by {}; only its claimant, its next owner, a lifecycle \
             operator or a human may",
            w.who,
            held.join(" and ")
        ),
    ))
}

// --- helpers ------------------------------------------------------------------------

fn stale_days(raw: Option<i64>) -> UaResult<i64> {
    match raw {
        None => Ok(DEFAULT_STALE_DAYS),
        Some(d) if d >= 1 => Ok(d),
        Some(_) => Err(UaError::invalid("stale_days must be at least 1")),
    }
}

fn clean_reason(raw: &str) -> UaResult<String> {
    let text = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        return Err(UaError::invalid("a reason is required: parking and folding are never silent"));
    }
    if text.chars().count() > REASON_MAX {
        return Err(UaError::invalid(format!("reason must be at most {REASON_MAX} characters")));
    }
    Ok(text)
}

type Row = Map<String, Value>;

fn s<'a>(row: &'a Row, key: &str) -> Option<&'a str> {
    str_field(row, key)
}

fn status(row: &Row) -> &str {
    s(row, "status").unwrap_or("open")
}

fn is_parked(row: &Row) -> bool {
    s(row, "parked_at").is_some()
}

/// Unfinished, unparked and not archived: work the queue still shows.
fn is_active(row: &Row) -> bool {
    ACTIVE_STATUSES.contains(&status(row)) && !is_parked(row) && s(row, "archived_at").is_none()
}

fn ts(raw: Option<&str>) -> Option<jiff::Timestamp> {
    raw.and_then(ua_core::time::parse_ts)
}

fn iso(t: jiff::Timestamp) -> String {
    ua_core::time::format_ts(t)
}

fn short(row: &Row) -> Value {
    json!({ "task_id": int_field(row, "id"), "title": s(row, "title"), "status": status(row) })
}

/// Why a task is being worked right now. Empty when nothing is live.
fn live_reasons(conn: &Connection, row: &Row, now: jiff::Timestamp) -> UaResult<Vec<String>> {
    let id = int_field(row, "id").unwrap_or_default();
    let mut out = Vec::new();
    if status(row) == "doing"
        && let Some(holder) = s(row, "claimed_by")
        && ts(s(row, "lock_expires_at")).is_none_or(|exp| exp > now)
    {
        out.push(format!("live claim by {holder}"));
    }
    if s(row, "current_run_id").is_some() {
        out.push("open run".into());
    } else if live_run_for_task(conn, id)?.is_some() {
        out.push("live dispatch run".into());
    }
    let delegation: Option<String> = conn
        .query_row(
            "SELECT status FROM delegations WHERE task_id = ?1 AND status IN ('pending','in_flight') LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(d) = delegation {
        out.push(format!("{d} delegation"));
    }
    let node: Option<String> = conn
        .query_row(
            "SELECT status FROM node_dispatch WHERE task_id = ?1 AND status IN ('queued','claimed') LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(n) = node {
        out.push(format!("{n} node work"));
    }
    Ok(out)
}

/// `[waiting-for: X]` markers in `notes`, X trimmed.
fn waiting_for(notes: &str) -> Vec<String> {
    let lower = notes.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = lower[from..].find("[waiting-for:") {
        let start = from + pos + "[waiting-for:".len();
        let Some(end) = lower[start..].find(']') else { break };
        out.push(notes[start..start + end].trim().to_string());
        from = start + end;
    }
    out
}

/// Human-gated rows the sweep never acts on.
fn gate_reasons(row: &Row) -> Vec<String> {
    let mut out = Vec::new();
    let lane = s(row, "lane").unwrap_or("default");
    if HUMAN_ONLY_LANES.contains(&lane) {
        out.push(format!("lane {lane}"));
    }
    if status(row) == "waiting_review" {
        out.push("human gate: waiting_review".into());
    }
    let notes = s(row, "notes").unwrap_or_default();
    for gate in waiting_for(notes) {
        out.push(format!("human gate: waiting-for {gate}"));
    }
    let text = format!("{}\n{notes}", s(row, "title").unwrap_or_default()).to_ascii_lowercase();
    if text.contains("red-tier") || text.contains("red tier") {
        out.push("red-tier row".into());
    }
    let mut seen = BTreeSet::new();
    out.retain(|r| seen.insert(r.clone()));
    out
}

/// Everything that keeps the sweep from proposing a park.
fn protection(conn: &Connection, row: &Row, now: jiff::Timestamp) -> UaResult<Vec<String>> {
    let mut out = gate_reasons(row);
    if s(row, "lane") == Some("tracking") {
        out.push("tracking lane".into());
    }
    out.extend(live_reasons(conn, row, now)?);
    Ok(out)
}

fn task_rows(conn: &Connection, sql: &str, p: impl rusqlite::Params) -> UaResult<Vec<Row>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(p, row_object)?.collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Every descendant row of `id` (not `id` itself), parents before children.
fn descendants(conn: &Connection, id: i64) -> UaResult<Vec<Row>> {
    let mut out = Vec::new();
    for d in subtree_ids(conn, id)?.into_iter().filter(|d| *d != id) {
        out.push(require_task(conn, d)?);
    }
    Ok(out)
}

/// Unparked, unarchived active rows with the comment thread's last write.
fn active_rows(conn: &Connection) -> UaResult<Vec<Row>> {
    task_rows(
        conn,
        "SELECT t.*, c.updated_at AS comment_at FROM tasks t \
         LEFT JOIN task_comment_threads c ON c.task_id = t.id \
         WHERE t.archived_at IS NULL AND t.parked_at IS NULL \
         AND t.status IN ('open','doing','waiting_review','blocked') ORDER BY t.id",
        [],
    )
}

fn last_touch(row: &Row) -> Option<jiff::Timestamp> {
    ["updated_at", "claimed_at", "comment_at"]
        .into_iter()
        .filter_map(|k| ts(s(row, k)))
        .max()
        .or_else(|| ts(s(row, "created_at")))
}

struct Stale {
    row: Row,
    touched: jiff::Timestamp,
    age_days: f64,
}

/// Active tasks with no touch for `days` days and no live work. Inclusive:
/// exactly `days` days is stale.
fn stale_tasks(conn: &Connection, now: jiff::Timestamp, days: i64) -> UaResult<Vec<Stale>> {
    let cutoff = now.as_second() - days * 86_400;
    let mut out = Vec::new();
    for row in active_rows(conn)? {
        let Some(touched) = last_touch(&row) else { continue };
        if touched.as_second() > cutoff || !live_reasons(conn, &row, now)?.is_empty() {
            continue;
        }
        let age = (now.as_second() - touched.as_second()) as f64 / 86_400.0;
        out.push(Stale { row, touched, age_days: (age * 10.0).round() / 10.0 });
    }
    Ok(out)
}

/// Set (or, with `None`, clear) one row's parking columns, fenced on its
/// revision, and record the change on the task's own channel.
fn write_parking(
    tx: &mut WriteTx<'_>,
    row: &Row,
    park: Option<(&str, &str, &str, Option<i64>)>,
) -> UaResult<()> {
    let id = int_field(row, "id").unwrap_or_default();
    let prior = s(row, "updated_at").map(str::to_string);
    let revision = next_revision(prior.as_deref());
    let n = match park {
        Some((at, by, reason, into)) => tx.execute(
            "UPDATE tasks SET parked_at = ?1, parked_by = ?2, parked_reason = ?3, folded_into = ?4, updated_at = ?5 \
             WHERE id = ?6 AND updated_at IS ?7",
            params![at, by, reason, into, revision, id, prior],
        )?,
        None => tx.execute(
            "UPDATE tasks SET parked_at = NULL, parked_by = NULL, parked_reason = NULL, folded_into = NULL, \
             updated_at = ?1 WHERE id = ?2 AND updated_at IS ?3",
            params![revision, id, prior],
        )?,
    };
    if n != 1 {
        return Err(UaError::conflict(format!("task {id} changed while it was being updated; retry")));
    }
    let by = park.map(|p| p.1.to_string()).unwrap_or_default();
    emit(
        tx,
        "agent.task.updated",
        json!({ "task_id": id, "fields": PARK_FIELDS, "from_status": status(row), "status": status(row) }),
        if by.is_empty() { "queue" } else { &by },
    )?;
    Ok(())
}

/// The claim-gate check: why a parked task may not be claimed or dispatched.
pub(crate) fn parked_block(conn: &Connection, task_id: i64) -> UaResult<Option<String>> {
    let row: Option<(Option<String>, Option<i64>)> = conn
        .query_row("SELECT parked_at, folded_into FROM tasks WHERE id = ?1", [task_id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    Ok(match row {
        Some((Some(_), Some(root))) => Some(format!(
            "task {task_id} is folded into parked task #{root}: unpark #{root} first (coordination_manage queue_unpark)"
        )),
        Some((Some(_), None)) => Some(format!(
            "task {task_id} is parked: unpark it first (coordination_manage queue_unpark) before work starts"
        )),
        _ => None,
    })
}

// --- park / fold / unpark -------------------------------------------------------------

/// `coordination_manage(action="queue_park")`.
pub(crate) async fn queue_park(ctx: ToolCtx, a: ParkArgs) -> UaResult<Value> {
    let reason = clean_reason(&a.reason)?;
    let writer = queue_writer(&ctx, a.actor.as_deref(), "parking a task")?;
    let note = a.approved_by.as_deref().map(|x| x.split_whitespace().collect::<Vec<_>>().join(" "));
    let note = note.filter(|x| !x.is_empty());
    if let Some(n) = &note
        && n.chars().count() > REASON_MAX
    {
        return Err(UaError::invalid(format!("approved_by must be at most {REASON_MAX} characters")));
    }
    if note.is_some() && !writer.operator {
        return Err(UaError::denied(
            "operator_required",
            "approved_by is recorded only for a verified human or lifecycle operator; it is a note, not authority",
        ));
    }
    let who = writer.who.clone();
    let fold = a.fold_children.unwrap_or(true);
    let (id, dry_run) = (a.task_id, a.dry_run);
    ctx.hub
        .db()
        .write_async(move |tx| {
            let row = require_task(tx, id)?;
            let st = status(&row).to_string();
            if !ACTIVE_STATUSES.contains(&st.as_str()) {
                return Err(UaError::conflict(format!("task {id} is already {st}; there is nothing to park")));
            }
            if is_parked(&row) {
                return Err(UaError::conflict(format!("task {id} is already parked")));
            }
            if s(&row, "archived_at").is_some() {
                return Err(UaError::conflict(format!(
                    "task {id} is archived (filed away); unarchive it before parking"
                )));
            }
            let now = jiff::Timestamp::now();
            let live = live_reasons(tx, &row, now)?;
            if !live.is_empty() {
                return Err(UaError::conflict_code(
                    "task_live",
                    format!("task {id} cannot be parked: {}", live.join("; ")),
                ));
            }
            let gated = gate_reasons(&row);
            if !gated.is_empty() && !writer.operator {
                return Err(UaError::denied(
                    "protected_task",
                    format!(
                        "task {id} is protected ({}); only a verified human or lifecycle operator may park it",
                        gated.join("; ")
                    ),
                ));
            }
            require_holder(&writer, &row, "park")?;
            let open: Vec<Row> = descendants(tx, id)?.into_iter().filter(is_active).collect();
            for child in &open {
                let child_live = live_reasons(tx, child, now)?;
                if !child_live.is_empty() {
                    return Err(UaError::conflict_code(
                        "task_live",
                        format!(
                            "task {id} cannot be parked: child #{} has {}",
                            int_field(child, "id").unwrap_or_default(),
                            child_live.join("; ")
                        ),
                    ));
                }
            }
            for child in &open {
                require_holder(&writer, child, "fold")?;
            }
            if !open.is_empty() && !fold {
                return Err(UaError::conflict(format!(
                    "task {id} has {} open child task(s); parking it would leave them open under a parked root. \
                     Fold them (the default) or park them first",
                    open.len()
                )));
            }
            let folded: Vec<i64> = open.iter().filter_map(|c| int_field(c, "id")).collect();
            let stamp = iso(now);
            // The approval is the operator's own identity; the note rides along.
            let approver = (!gated.is_empty()).then(|| who.clone());
            let recorded = match (&approver, &note) {
                (Some(by), Some(n)) => format!("{reason} (approved by {by}: {n})"),
                (Some(by), None) => format!("{reason} (approved by {by})"),
                (None, Some(n)) => format!("{reason} (note: {n})"),
                (None, None) => reason.clone(),
            };
            if !dry_run {
                write_parking(tx, &row, Some((&stamp, &who, &recorded, None)))?;
                let child_reason = format!("parent #{id} parked: {recorded}");
                for child in &open {
                    write_parking(tx, child, Some((&stamp, &who, &child_reason, Some(id))))?;
                }
                emit(
                    tx,
                    CHANNEL_PARKED,
                    json!({
                        "task_id": id, "reason": reason, "approved_by": approver, "approval_note": note,
                        "protected": gated, "folded": folded, "actor": who,
                    }),
                    &who,
                )?;
            }
            Ok(json!({
                "dry_run": dry_run,
                "parked": id,
                "folded": folded,
                "reason": reason,
                "approved_by": approver,
                "approval_note": note,
                "protected": gated,
                "actor": who,
                "reversible_with": "queue_unpark",
            }))
        })
        .await
}

/// `coordination_manage(action="queue_fold")`: fold an open descendant into
/// its already-parked root, for a child that appeared after the park.
pub(crate) async fn queue_fold(ctx: ToolCtx, a: FoldArgs) -> UaResult<Value> {
    let reason = clean_reason(&a.reason)?;
    let writer = queue_writer(&ctx, a.actor.as_deref(), "folding a task")?;
    let who = writer.who.clone();
    let (id, into, dry_run) = (a.task_id, a.into, a.dry_run);
    ctx.hub
        .db()
        .write_async(move |tx| {
            let row = require_task(tx, id)?;
            let root = require_task(tx, into)?;
            if !is_parked(&root) || int_field(&root, "folded_into").is_some() {
                return Err(UaError::conflict(format!(
                    "task {into} is not a parked root; fold only into a parked task that is not itself folded"
                )));
            }
            if !ancestors(tx, id)?.contains(&into) {
                return Err(UaError::invalid(format!("task {into} is not an ancestor of task {id}")));
            }
            if !is_active(&row) {
                return Err(UaError::conflict(format!(
                    "task {id} is {} and {}; nothing to fold",
                    status(&row),
                    if is_parked(&row) { "parked" } else { "not open" }
                )));
            }
            let live = live_reasons(tx, &row, jiff::Timestamp::now())?;
            if !live.is_empty() {
                return Err(UaError::conflict_code(
                    "task_live",
                    format!("task {id} cannot be folded: {}", live.join("; ")),
                ));
            }
            require_holder(&writer, &row, "fold")?;
            if !dry_run {
                let stamp = ua_core::time::now();
                write_parking(tx, &row, Some((&stamp, &who, &reason, Some(into))))?;
                emit(
                    tx,
                    CHANNEL_FOLDED,
                    json!({ "task_id": id, "into": into, "reason": reason, "actor": who }),
                    &who,
                )?;
            }
            Ok(json!({ "dry_run": dry_run, "folded": id, "into": into, "reason": reason, "actor": who }))
        })
        .await
}

/// `coordination_manage(action="queue_unpark")`: restore a parked root and
/// every descendant folded into it. Statuses are kept; the staleness clock
/// restarts.
pub(crate) async fn queue_unpark(ctx: ToolCtx, a: UnparkArgs) -> UaResult<Value> {
    let reason = clean_reason(&a.reason)?;
    let writer = queue_writer(&ctx, a.actor.as_deref(), "unparking a task")?;
    let who = writer.who.clone();
    let (id, dry_run) = (a.task_id, a.dry_run);
    ctx.hub
        .db()
        .write_async(move |tx| {
            let row = require_task(tx, id)?;
            if !is_parked(&row) {
                return Err(UaError::conflict(format!("task {id} is not parked")));
            }
            require_holder(&writer, &row, "unpark")?;
            let mut parked_above = Vec::new();
            if let Some(root) = int_field(&row, "folded_into") {
                parked_above.push(root);
            }
            for anc in ancestors(tx, id)? {
                if is_parked(&require_task(tx, anc)?) {
                    parked_above.push(anc);
                }
            }
            if let Some(root) = parked_above.first() {
                return Err(UaError::conflict(format!(
                    "task {id} sits under parked task #{root}; unpark that root instead (it restores the children \
                     folded into it)"
                )));
            }
            let mut targets = vec![row];
            targets.extend(
                descendants(tx, id)?
                    .into_iter()
                    .filter(|d| is_parked(d) && int_field(d, "folded_into") == Some(id)),
            );
            let restored: Vec<i64> = targets.iter().filter_map(|t| int_field(t, "id")).collect();
            if !dry_run {
                for t in &targets {
                    write_parking(tx, t, None)?;
                }
                emit(
                    tx,
                    CHANNEL_UNPARKED,
                    json!({ "task_id": id, "reason": reason, "restored": restored, "actor": who }),
                    &who,
                )?;
            }
            Ok(json!({ "dry_run": dry_run, "unparked": id, "restored": restored, "reason": reason, "actor": who }))
        })
        .await
}

// --- reads ---------------------------------------------------------------------------

/// `coordination_manage(action="queue_stale")`: stale tasks, oldest first,
/// with any protection. Read only.
pub(crate) async fn queue_stale(ctx: ToolCtx, a: StaleArgs) -> UaResult<Value> {
    let days = stale_days(a.stale_days)?;
    let cap = a.limit.unwrap_or(200).clamp(1, 1000) as usize;
    ctx.hub
        .db()
        .read_async(move |c| {
            let now = jiff::Timestamp::now();
            let mut items = stale_tasks(c, now, days)?;
            items.sort_by_key(|i| i.touched);
            let total = items.len();
            let mut rows = Vec::new();
            for i in items.iter().take(cap) {
                rows.push(json!({
                    "task_id": int_field(&i.row, "id"),
                    "title": s(&i.row, "title"),
                    "status": status(&i.row),
                    "lane": s(&i.row, "lane"),
                    "last_touched": iso(i.touched),
                    "age_days": i.age_days,
                    "protected": protection(c, &i.row, now)?,
                }));
            }
            Ok(json!({
                "as_of": iso(now),
                "stale_days": days,
                "total": total,
                "tasks": rows,
                "truncated": total > cap,
            }))
        })
        .await
}

/// `coordination_manage(action="queue_sweep")`: PROPOSE parks and folds for
/// someone to approve. Writes nothing.
pub(crate) async fn queue_sweep(ctx: ToolCtx, a: HealthArgs) -> UaResult<Value> {
    let days = stale_days(a.stale_days)?;
    ctx.hub.db().read_async(move |c| sweep(c, days)).await
}

fn sweep(c: &Connection, days: i64) -> UaResult<Value> {
    let now = jiff::Timestamp::now();
    let mut proposals: Vec<Value> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();
    let mut proposed: BTreeSet<i64> = BTreeSet::new();

    // Open children under a parked root.
    let roots = task_rows(
        c,
        "SELECT * FROM tasks WHERE parked_at IS NOT NULL AND folded_into IS NULL ORDER BY id",
        [],
    )?;
    for root in &roots {
        let rid = int_field(root, "id").unwrap_or_default();
        for child in descendants(c, rid)? {
            let cid = int_field(&child, "id").unwrap_or_default();
            if !is_active(&child) || proposed.contains(&cid) {
                continue;
            }
            let live = live_reasons(c, &child, now)?;
            if !live.is_empty() {
                let mut entry = short(&child);
                entry["would_be"] = json!("fold");
                entry["reason"] = json!(live.join("; "));
                entry["evidence"] = json!({ "parked_root": rid });
                skipped.push(entry);
                continue;
            }
            proposed.insert(cid);
            let mut entry = short(&child);
            entry["proposed_action"] = json!("fold");
            entry["reason"] = json!(format!("open child under parked root #{rid}"));
            entry["evidence"] = json!({ "parked_root": rid, "root_reason": s(root, "parked_reason") });
            entry["auto"] = json!(false);
            proposals.push(entry);
        }
    }

    // Stale tasks, ancestors first, so a stale child is covered by its stale
    // parent's fold list instead of being proposed on its own.
    let mut stale = stale_tasks(c, now, days)?;
    let mut depth = BTreeMap::new();
    for item in &stale {
        let id = int_field(&item.row, "id").unwrap_or_default();
        depth.insert(id, ancestors(c, id)?.len());
    }
    stale.sort_by_key(|i| {
        let id = int_field(&i.row, "id").unwrap_or_default();
        (depth.get(&id).copied().unwrap_or(0), id)
    });
    let mut covered: BTreeSet<i64> = BTreeSet::new();
    for item in &stale {
        let row = &item.row;
        let id = int_field(row, "id").unwrap_or_default();
        if proposed.contains(&id) || covered.contains(&id) {
            continue;
        }
        let protected = protection(c, row, now)?;
        let mut entry = short(row);
        if !protected.is_empty() {
            entry["would_be"] = json!("park");
            entry["reason"] = json!(protected.join("; "));
            entry["evidence"] = json!({ "last_touched": iso(item.touched) });
            skipped.push(entry);
            continue;
        }
        let open: Vec<Row> = descendants(c, id)?.into_iter().filter(is_active).collect();
        let mut blocking = None;
        for child in &open {
            let live = live_reasons(c, child, now)?;
            if !live.is_empty() {
                blocking = Some((int_field(child, "id").unwrap_or_default(), live));
                break;
            }
        }
        if let Some((cid, why)) = blocking {
            entry["would_be"] = json!("park");
            entry["reason"] = json!(format!("child #{cid} has {}", why.join("; ")));
            entry["evidence"] = json!({ "last_touched": iso(item.touched) });
            skipped.push(entry);
            continue;
        }
        proposed.insert(id);
        let children: Vec<i64> = open.iter().filter_map(|c| int_field(c, "id")).collect();
        entry["proposed_action"] = json!("park");
        entry["reason"] =
            json!(format!("no claim, status change or note for {} days (threshold {days})", item.age_days));
        entry["evidence"] = json!({
            "last_touched": iso(item.touched),
            "age_days": item.age_days,
            "fold_children": children,
        });
        entry["auto"] = json!(false);
        proposals.push(entry);
        for child in &open {
            let cid = int_field(child, "id").unwrap_or_default();
            covered.insert(cid);
            if !proposed.insert(cid) {
                continue;
            }
            let mut e = short(child);
            e["proposed_action"] = json!("fold");
            e["reason"] = json!(format!("open child of #{id}, proposed for park"));
            e["evidence"] = json!({ "parked_root": id, "root_proposed": true });
            e["auto"] = json!(false);
            proposals.push(e);
        }
    }
    let mut counts: BTreeMap<String, i64> = BTreeMap::new();
    for p in &proposals {
        *counts.entry(p["proposed_action"].as_str().unwrap_or("").to_string()).or_default() += 1;
    }
    Ok(json!({
        "as_of": iso(now),
        "dry_run": true,
        "writes": 0,
        "stale_days": days,
        "proposals": proposals,
        "skipped": skipped,
        "counts": counts,
        "close_on_merge": "not available: merged-PR evidence needs the native GitHub client",
        "note": "Proposals only. Park and fold run only through queue_park / queue_fold once someone approves. \
                 Nothing closes on a date.",
    }))
}

/// `coordination_manage(action="queue_health")`: open, parked, stale and
/// unjudged review-ready milestone counts. Read only.
pub(crate) async fn queue_health(ctx: ToolCtx, a: HealthArgs) -> UaResult<Value> {
    let days = stale_days(a.stale_days)?;
    ctx.hub.db().read_async(move |c| health(c, days)).await
}

fn health(c: &Connection, days: i64) -> UaResult<Value> {
    let now = jiff::Timestamp::now();
    let mut by_status: BTreeMap<String, i64> = ACTIVE_STATUSES.iter().map(|s| (s.to_string(), 0)).collect();
    let mut stmt = c.prepare(
        "SELECT status, COUNT(*) FROM tasks WHERE archived_at IS NULL AND parked_at IS NULL \
         AND status IN ('open','doing','waiting_review','blocked') GROUP BY status",
    )?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
        let (st, n) = row?;
        by_status.insert(st, n);
    }
    let (parked, folded): (i64, i64) = c.query_row(
        "SELECT COUNT(*), COALESCE(SUM(folded_into IS NOT NULL), 0) FROM tasks \
         WHERE parked_at IS NOT NULL AND status NOT IN ('done','cancelled')",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let stale = stale_tasks(c, now, days)?;
    let mut actionable = 0;
    for item in &stale {
        if protection(c, &item.row, now)?.is_empty() {
            actionable += 1;
        }
    }
    let milestones = milestone_readiness(c)?;
    let ready_unowned = ready_unowned(c)?;
    Ok(json!({
        "as_of": iso(now),
        "stale_days": days,
        "open": by_status.get("open").copied().unwrap_or(0),
        "active": by_status.values().sum::<i64>(),
        "by_status": by_status,
        "parked": parked,
        "parked_folded": folded,
        "stale": stale.len(),
        "stale_actionable": actionable,
        "milestones_review_ready_unjudged": milestones["review_ready_unjudged"],
        "milestones": milestones,
        "ready_unowned": ready_unowned,
    }))
}

/// Unparked active tasks with prerequisites, all closed, and nobody to move
/// them: no next owner, no claimant, and a lane that names no agent.
fn ready_unowned(c: &Connection) -> UaResult<i64> {
    let rows = task_rows(
        c,
        "SELECT * FROM tasks WHERE archived_at IS NULL AND parked_at IS NULL \
         AND status NOT IN ('done','cancelled') \
         AND EXISTS (SELECT 1 FROM task_dependencies d WHERE d.task_id = tasks.id) \
         AND NOT EXISTS (SELECT 1 FROM task_dependencies d JOIN tasks p ON p.id = d.depends_on_task_id \
             WHERE d.task_id = tasks.id AND p.status NOT IN ('done','cancelled')) \
         AND COALESCE(TRIM(next_owner), '') = '' AND COALESCE(TRIM(claimed_by), '') = ''",
        [],
    )?;
    Ok(rows.iter().filter(|r| POOL_LANES.contains(&s(r, "lane").unwrap_or("default"))).count() as i64)
}

/// Task ids on a milestone's `Gate:` line. The list ends at a newline or a
/// sentence end, unless the next sentence itself starts with a task id.
fn gate_task_ids(notes: &str) -> BTreeSet<i64> {
    let lower = notes.to_ascii_lowercase();
    let mut start = None;
    let mut from = 0;
    while let Some(pos) = lower[from..].find("gate:") {
        let at = from + pos;
        let boundary = at == 0 || !lower.as_bytes()[at - 1].is_ascii_alphanumeric();
        if boundary {
            start = Some(at + "gate:".len());
            break;
        }
        from = at + 1;
    }
    let Some(start) = start else { return BTreeSet::new() };
    let line = notes[start..].split('\n').next().unwrap_or("");
    let bytes = line.as_bytes();
    let mut end = line.len();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'.' && (i + 1 == bytes.len() || bytes[i + 1].is_ascii_whitespace()) {
            let rest = line[i + 1..].trim_start();
            let continues =
                rest.starts_with('#') && rest[1..].chars().next().is_some_and(|c| c.is_ascii_digit());
            if !continues {
                end = i;
                break;
            }
        }
        i += 1;
    }
    let mut ids = BTreeSet::new();
    let scope = &line[..end];
    let mut rest = scope;
    while let Some(pos) = rest.find('#') {
        let digits: String = rest[pos + 1..].chars().take_while(char::is_ascii_digit).collect();
        if let Ok(n) = digits.parse::<i64>() {
            ids.insert(n);
        }
        rest = &rest[pos + 1..];
    }
    ids
}

fn has_verdict(notes: &str) -> bool {
    let lower = notes.to_ascii_lowercase();
    if lower.contains("[milestone-verdict") {
        return true;
    }
    let mut from = 0;
    while let Some(pos) = lower[from..].find("verdict") {
        let at = from + pos;
        let before_ok = at == 0 || !lower.as_bytes()[at - 1].is_ascii_alphanumeric();
        let after = lower[at + "verdict".len()..].trim_start();
        if before_ok && (after.starts_with(':') || after.starts_with('-')) {
            return true;
        }
        from = at + 1;
    }
    false
}

/// Milestones (`[milestone-review]` in the notes) whose gate is satisfied
/// while the milestone is still open and unjudged. Read only.
fn milestone_readiness(c: &Connection) -> UaResult<Value> {
    let rows = task_rows(
        c,
        "SELECT * FROM tasks WHERE archived_at IS NULL AND parked_at IS NULL \
         AND status NOT IN ('done','cancelled') AND instr(lower(COALESCE(notes, '')), ?1) > 0 ORDER BY id",
        [MILESTONE_MARKER],
    )?;
    let mut ready = Vec::new();
    let mut unjudged = Vec::new();
    for row in rows {
        let id = int_field(&row, "id").unwrap_or_default();
        let notes = s(&row, "notes").unwrap_or_default();
        if !has_marker(notes, MILESTONE_MARKER) {
            continue;
        }
        let mut gate = gate_task_ids(notes);
        let mut stmt = c.prepare("SELECT depends_on_task_id FROM task_dependencies WHERE task_id = ?1")?;
        for dep in stmt.query_map([id], |r| r.get::<_, i64>(0))? {
            gate.insert(dep?);
        }
        gate.remove(&id);
        if gate.is_empty() {
            continue;
        }
        let mut done = 0usize;
        for g in &gate {
            let st: Option<String> =
                c.query_row("SELECT status FROM tasks WHERE id = ?1", [g], |r| r.get(0)).optional()?;
            if st.as_deref() == Some("done") {
                done += 1;
            }
        }
        if done != gate.len() {
            continue;
        }
        let judged = has_verdict(notes);
        ready.push(json!({ "task_id": id, "title": s(&row, "title"), "judged": judged }));
        if !judged {
            unjudged.push(id);
        }
    }
    Ok(json!({
        "review_ready": ready.len(),
        "review_ready_unjudged": unjudged.len(),
        "unjudged_ids": unjudged,
        "milestones": ready,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_line_parsing_matches_the_python_rules() {
        assert_eq!(gate_task_ids("x\nGate: #1, #2 done. More text #9"), BTreeSet::from([1, 2]));
        assert_eq!(gate_task_ids("Gate: #1 done. #2 also. Then #7"), BTreeSet::from([1, 2]));
        assert_eq!(gate_task_ids("Gate: #3\n#4 is not on the line"), BTreeSet::from([3]));
        assert!(gate_task_ids("no gate here #5").is_empty());
        assert!(gate_task_ids("Tollgate: #5").is_empty());
    }

    #[test]
    fn verdicts_and_waiting_markers() {
        assert!(has_verdict("VERDICT: pass"));
        assert!(has_verdict("[milestone-verdict fail]"));
        assert!(!has_verdict("the verdict is pending"));
        assert_eq!(
            waiting_for("a [waiting-for: review] b [Waiting-For:  operator ]"),
            ["review", "operator"]
        );
    }
}
