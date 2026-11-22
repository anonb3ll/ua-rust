//! Agent-authored session handoff notes with a commit point.
//!
//! A session can be resumed from a derived packet (`session_packet`), but
//! what the agent itself knew at the end of its context does not survive
//! unless it writes it down: what it finished, what comes next, what is still
//! open. This module stores that note, written by the agent that owns the
//! session.
//!
//! State machine (enforced here and again by SQLite triggers):
//!
//! ```text
//! draft --seal--> sealed --(failover)--> assigned --> delivered
//!   |               |          \_______________________^
//!   +--discard--> discarded
//!                   +--(a newer note seals)--> superseded
//! ```
//!
//! `seal` is the commit point. Before it a draft may be edited in place
//! (`session_handoff_update`) or discarded, and `session_handoff_recover`
//! never returns it. After it the note is immutable and only moves forward.
//!
//! Limits, per session: one pending note at a time (a draft, or a sealed or
//! assigned note not yet delivered; a new note while a sealed one is pending
//! must pass `supersede: true`), a 5-minute cooldown between proposals and at
//! most 5 proposals in any rolling hour. Edits to a draft are not proposals.
//!
//! `done` and `next_steps` need at least one non-empty item each. Items are
//! redacted for credential shapes and bounded (20 items of 500 characters).
//!
//! Failover (handing a pending note to another agent) is hub-side machinery
//! in the Python hub with no tool surface; it is not ported. An imported
//! `assigned` note can still be acknowledged by its receiver.
//!
//! `session_handoff_recover` is for the session's owner (or the note's
//! author), the agent the note was assigned or delivered to, a lifecycle
//! operator or a human, all verified. Anyone else, unverified callers
//! included, reads `not_found`, as for a session that does not exist.
//!
//! Every state change appends one `agent.lifecycle.handoff` event in the
//! same transaction, with the session as its episode, so the session packet's
//! `lifecycle` section shows it.

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, WriteTx, ledger};

use crate::families::agents::verified;
use crate::families::audit::rules::redact_secrets;
use crate::families::injection::mark_untrusted;
use crate::families::tasks::{acting_identity, row_object};
use crate::registry::ToolCtx;
use ua_org::authz::{Authority, Authz};

const CHANNEL: &str = "agent.lifecycle.handoff";
const COOLDOWN_SECS: i64 = 5 * 60;
const HOURLY_LIMIT: usize = 5;
const ITEMS_MAX: usize = 20;
const ITEM_MAX_CHARS: usize = 500;

// --- arguments ----------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposeArgs {
    /// A session you own.
    pub session_id: String,
    /// What you finished: at least one non-empty item (up to 20).
    pub done: Vec<String>,
    /// What comes next: at least one non-empty item (up to 20).
    pub next_steps: Vec<String>,
    /// What is still open (up to 20).
    pub open_questions: Option<Vec<String>>,
    /// The task the note is about. Default: the session's task.
    pub task_id: Option<i64>,
    /// Write a note that replaces the session's pending sealed note once it seals.
    #[serde(default)]
    pub supersede: bool,
    /// Acting identity for an unverified caller; a verified caller acts as itself.
    pub agent: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateArgs {
    /// Your draft note.
    pub note_id: i64,
    /// Replace the done list (at least one non-empty item).
    pub done: Option<Vec<String>>,
    /// Replace the next steps (at least one non-empty item).
    pub next_steps: Option<Vec<String>>,
    /// Replace the open questions.
    pub open_questions: Option<Vec<String>>,
    /// Acting identity for an unverified caller; a verified caller acts as itself.
    pub agent: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteArgs {
    /// The note.
    pub note_id: i64,
    /// Acting identity for an unverified caller; a verified caller acts as itself.
    pub agent: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoverArgs {
    /// The session to resume.
    pub session_id: String,
}

// --- helpers ------------------------------------------------------------------------

fn items(value: Option<&[String]>, field: &str, required: bool) -> UaResult<Vec<String>> {
    let mut out = Vec::new();
    for item in value.unwrap_or_default() {
        let text = item.trim();
        if text.is_empty() {
            continue;
        }
        let redacted = redact_secrets(text).0;
        out.push(redacted.chars().take(ITEM_MAX_CHARS).collect::<String>());
        if out.len() >= ITEMS_MAX {
            break;
        }
    }
    if required && out.is_empty() {
        return Err(UaError::invalid(format!("{field} needs at least one non-empty item")));
    }
    Ok(out)
}

fn note_from(mut row: Map<String, Value>) -> Value {
    for key in ["done", "next_steps", "open_questions"] {
        let parsed = row
            .get(key)
            .and_then(Value::as_str)
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .unwrap_or_else(|| json!([]));
        row.insert(key.into(), parsed);
    }
    Value::Object(row)
}

fn load_note(conn: &Connection, id: i64) -> UaResult<Value> {
    conn.query_row("SELECT * FROM session_handoff_notes WHERE id = ?1", [id], row_object)
        .optional()?
        .map(note_from)
        .ok_or_else(|| UaError::not_found(format!("handoff note {id} not found")))
}

fn owned_note(conn: &Connection, id: i64, agent: &str) -> UaResult<Value> {
    let note = load_note(conn, id)?;
    if note["agent"].as_str() != Some(agent) {
        return Err(UaError::denied(
            "not_note_owner",
            format!("handoff note {id} is owned by {}", note["agent"].as_str().unwrap_or("?")),
        ));
    }
    Ok(note)
}

fn require_draft(note: &Value, action: &str) -> UaResult<()> {
    let state = note["state"].as_str().unwrap_or("");
    if state == "draft" {
        return Ok(());
    }
    Err(UaError::conflict(format!(
        "handoff note {} is {state}: only a draft can be {action}; a sealed note only moves forward (assigned, \
         delivered or superseded)",
        note["id"]
    )))
}

fn emit(tx: &mut WriteTx<'_>, note: &Value, state: &str, by: &str, extra: Value) -> UaResult<()> {
    let mut payload = json!({
        "kind": "handoff",
        "state": state,
        "note_id": note["id"],
        "session_id": note["session_id"],
        "task_id": note["task_id"],
        "agent": note["agent"],
        "epoch": note["epoch"],
    });
    if let (Value::Object(p), Value::Object(e)) = (&mut payload, extra) {
        p.extend(e);
    }
    let session = note["session_id"].as_str().map(str::to_string);
    ledger::append(
        tx,
        EventInput {
            episode_id: session,
            ..EventInput::new(ua_core::DEFAULT_ORG, CHANNEL, payload).by(by.to_string())
        },
    )?;
    Ok(())
}

/// Refuse a proposal inside the cooldown or past the hourly limit.
fn check_limits(conn: &Connection, session_id: &str, now: jiff::Timestamp) -> UaResult<()> {
    let mut stmt = conn.prepare(
        "SELECT created_at FROM session_handoff_notes WHERE session_id = ?1 \
         ORDER BY created_at DESC, id DESC LIMIT ?2",
    )?;
    let stamps: Vec<jiff::Timestamp> = stmt
        .query_map(params![session_id, HOURLY_LIMIT as i64], |r| r.get::<_, String>(0))?
        .filter_map(Result::ok)
        .filter_map(|s| ua_core::time::parse_ts(&s))
        .collect();
    let age = |t: &jiff::Timestamp| now.as_second() - t.as_second();
    if let Some(latest) = stamps.first()
        && age(latest) < COOLDOWN_SECS
    {
        let wait = COOLDOWN_SECS - age(latest);
        return Err(UaError::conflict_code(
            "handoff_cooldown",
            format!(
                "handoff cooldown: session {session_id} proposed a note less than 5 minutes ago; retry in {wait}s, \
                 or edit the existing draft with session_handoff_update"
            ),
        ));
    }
    if stamps.iter().filter(|t| age(t) < 3600).count() >= HOURLY_LIMIT {
        return Err(UaError::conflict_code(
            "handoff_rate_limited",
            format!(
                "handoff limit: session {session_id} reached {HOURLY_LIMIT} proposals per hour; edit the existing \
                 draft instead of proposing a new note"
            ),
        ));
    }
    Ok(())
}

/// The session's latest committed note (sealed, assigned or delivered), never
/// a draft, marked untrusted.
fn latest_committed_note(conn: &Connection, session_id: &str) -> UaResult<Option<Value>> {
    let note = conn
        .query_row(
            "SELECT * FROM session_handoff_notes WHERE session_id = ?1 \
             AND state IN ('sealed','assigned','delivered') ORDER BY sealed_at DESC, id DESC LIMIT 1",
            [session_id],
            row_object,
        )
        .optional()?
        .map(note_from);
    Ok(note.map(|mut n| {
        let author = n["agent"].as_str().map(str::to_string);
        mark_untrusted(&mut n, "handoff_note", author.as_deref());
        n
    }))
}

/// Apply the same note visibility to the recovery tool and the resume packet.
pub(crate) fn recover_note(conn: &Connection, session_id: &str, ctx: &ToolCtx) -> UaResult<Option<Value>> {
    let who = verified(&ctx.caller);
    let maintainer = who.is_some()
        && Authz::new(ctx.hub.cfg()).holds(
            &ctx.caller,
            &[Authority::Operator, Authority::LifecycleOperator],
            ua_core::DEFAULT_ORG,
        );
    let owner: Option<String> = conn
        .query_row("SELECT agent FROM agent_sessions WHERE id = ?1", [session_id], |r| r.get(0))
        .optional()?;
    let note = latest_committed_note(conn, session_id)?;
    let allowed = maintainer
        || who.is_some_and(|who| {
            owner.as_deref() == Some(who)
                || note.as_ref().is_some_and(|n| {
                    ["agent", "assigned_to", "delivered_to"].iter().any(|k| n[*k].as_str() == Some(who))
                })
        });
    if !allowed {
        return Err(UaError::not_found(format!("session {session_id} not found")));
    }
    Ok(note)
}

// --- actions ------------------------------------------------------------------------

/// `coordination_manage(action="session_handoff_propose")`.
pub(crate) async fn session_handoff_propose(ctx: ToolCtx, a: ProposeArgs) -> UaResult<Value> {
    let agent = acting_identity(&ctx.caller, a.agent.as_deref())?;
    let done = items(Some(&a.done), "done", true)?;
    let next = items(Some(&a.next_steps), "next_steps", true)?;
    let questions = items(a.open_questions.as_deref(), "open_questions", false)?;
    let sid = a.session_id.trim().to_string();
    if sid.is_empty() {
        return Err(UaError::invalid("session_id is required"));
    }
    let (task_arg, supersede) = (a.task_id, a.supersede);
    ctx.hub
        .db()
        .write_async(move |tx| {
            let session: Option<(String, Option<i64>)> = tx
                .query_row("SELECT agent, task_id FROM agent_sessions WHERE id = ?1", [&sid], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let Some((owner, session_task)) = session else {
                return Err(UaError::not_found(format!("session {sid} not found")));
            };
            if owner != agent {
                return Err(UaError::denied(
                    "not_session_owner",
                    format!("session {sid} is owned by {owner}; only its owner writes its handoff"),
                ));
            }
            let pending: Option<(i64, String)> = tx
                .query_row(
                    "SELECT id, state FROM session_handoff_notes WHERE session_id = ?1 \
                     AND state IN ('draft','sealed','assigned') ORDER BY state = 'draft' DESC LIMIT 1",
                    [&sid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let supersedes = match pending {
                Some((id, state)) if state == "draft" => {
                    return Err(UaError::conflict(format!(
                        "session {sid} already has a pending draft (note {id}): edit it with session_handoff_update, \
                         seal it, or discard it"
                    )));
                }
                Some((id, state)) if !supersede => {
                    return Err(UaError::conflict(format!(
                        "session {sid} has {state} note {id} pending delivery; pass supersede=true to write a note \
                         that replaces it once sealed"
                    )));
                }
                Some((id, _)) => Some(id),
                None => None,
            };
            let now = jiff::Timestamp::now();
            check_limits(tx, &sid, now)?;
            let task_id = task_arg.or(session_task);
            if let Some(t) = task_id {
                let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM tasks WHERE id = ?1)", [t], |r| r.get(0))?;
                if !exists {
                    return Err(UaError::not_found(format!(
                        "task {t} not found: a handoff note can only reference a task here"
                    )));
                }
            }
            let stamp = ua_core::time::format_ts(now);
            tx.execute(
                "INSERT INTO session_handoff_notes (session_id, agent, task_id, done, next_steps, open_questions, \
                 state, epoch, supersedes, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'draft', 0, ?7, ?8, ?8)",
                params![
                    sid,
                    agent,
                    task_id,
                    json!(done).to_string(),
                    json!(next).to_string(),
                    json!(questions).to_string(),
                    supersedes,
                    stamp
                ],
            )?;
            let note = load_note(tx, tx.last_insert_rowid())?;
            emit(tx, &note, "drafted", &agent, json!({ "supersedes": supersedes }))?;
            Ok(note)
        })
        .await
}

/// `coordination_manage(action="session_handoff_update")`.
pub(crate) async fn session_handoff_update(ctx: ToolCtx, a: UpdateArgs) -> UaResult<Value> {
    let agent = acting_identity(&ctx.caller, a.agent.as_deref())?;
    let mut fields: Vec<(&'static str, String)> = Vec::new();
    if let Some(d) = &a.done {
        fields.push(("done", json!(items(Some(d), "done", true)?).to_string()));
    }
    if let Some(n) = &a.next_steps {
        fields.push(("next_steps", json!(items(Some(n), "next_steps", true)?).to_string()));
    }
    if let Some(q) = &a.open_questions {
        fields.push(("open_questions", json!(items(Some(q), "open_questions", false)?).to_string()));
    }
    if fields.is_empty() {
        return Err(UaError::invalid("nothing to update: pass done, next_steps or open_questions"));
    }
    let id = a.note_id;
    ctx.hub
        .db()
        .write_async(move |tx| {
            let note = owned_note(tx, id, &agent)?;
            require_draft(&note, "edited")?;
            let changed: Vec<&str> = fields.iter().map(|(c, _)| *c).collect();
            for (column, value) in &fields {
                tx.execute(
                    &format!("UPDATE session_handoff_notes SET {column} = ?1 WHERE id = ?2"),
                    params![value, id],
                )?;
            }
            tx.execute(
                "UPDATE session_handoff_notes SET updated_at = ?1 WHERE id = ?2",
                params![ua_core::time::now(), id],
            )?;
            let note = load_note(tx, id)?;
            emit(tx, &note, "draft_updated", &agent, json!({ "fields": changed }))?;
            Ok(note)
        })
        .await
}

/// `coordination_manage(action="session_handoff_discard")`.
pub(crate) async fn session_handoff_discard(ctx: ToolCtx, a: NoteArgs) -> UaResult<Value> {
    let agent = acting_identity(&ctx.caller, a.agent.as_deref())?;
    let id = a.note_id;
    ctx.hub
        .db()
        .write_async(move |tx| {
            let note = owned_note(tx, id, &agent)?;
            require_draft(&note, "discarded")?;
            tx.execute(
                "UPDATE session_handoff_notes SET state = 'discarded', updated_at = ?1 WHERE id = ?2",
                params![ua_core::time::now(), id],
            )?;
            let note = load_note(tx, id)?;
            emit(tx, &note, "discarded", &agent, json!({}))?;
            Ok(note)
        })
        .await
}

/// `coordination_manage(action="session_handoff_seal")`: the commit point.
/// A sealed or assigned note already pending for the session becomes
/// `superseded` in the same transaction.
pub(crate) async fn session_handoff_seal(ctx: ToolCtx, a: NoteArgs) -> UaResult<Value> {
    let agent = acting_identity(&ctx.caller, a.agent.as_deref())?;
    let id = a.note_id;
    ctx.hub
        .db()
        .write_async(move |tx| {
            let note = owned_note(tx, id, &agent)?;
            require_draft(&note, "sealed")?;
            let stamp = ua_core::time::now();
            let sid = note["session_id"].as_str().unwrap_or_default().to_string();
            let superseded: Vec<i64> = {
                let mut stmt = tx.prepare(
                    "SELECT id FROM session_handoff_notes WHERE session_id = ?1 AND state IN ('sealed','assigned') \
                     ORDER BY id",
                )?;
                stmt.query_map([&sid], |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            for old in &superseded {
                tx.execute(
                    "UPDATE session_handoff_notes SET state = 'superseded', updated_at = ?1 WHERE id = ?2",
                    params![stamp, old],
                )?;
                let old_note = load_note(tx, *old)?;
                emit(tx, &old_note, "superseded", &agent, json!({ "superseded_by": id }))?;
            }
            tx.execute(
                "UPDATE session_handoff_notes SET state = 'sealed', sealed_at = ?1, updated_at = ?1 WHERE id = ?2",
                params![stamp, id],
            )?;
            let note = load_note(tx, id)?;
            emit(tx, &note, "sealed", &agent, json!({ "superseded": superseded }))?;
            Ok(note)
        })
        .await
}

/// `coordination_manage(action="session_handoff_recover")`: the latest
/// sealed, assigned or delivered note, never a draft. Only the session's
/// owner, the note's author or receiver, a lifecycle operator or a human
/// sees it; anyone else reads `not_found`.
pub(crate) async fn session_handoff_recover(ctx: ToolCtx, a: RecoverArgs) -> UaResult<Value> {
    let sid = a.session_id.trim().to_string();
    if sid.is_empty() {
        return Err(UaError::invalid("session_id is required"));
    }
    let hub = ctx.hub.clone();
    hub.db()
        .read_async(move |c| {
            let note = recover_note(c, &sid, &ctx)?;
            Ok(json!({ "session_id": sid, "note": note }))
        })
        .await
}

/// `coordination_manage(action="session_handoff_ack")`: the receiver says it
/// has a note handed to it. An `assigned` note becomes `delivered`; repeating
/// the call returns the note unchanged.
pub(crate) async fn session_handoff_ack(ctx: ToolCtx, a: NoteArgs) -> UaResult<Value> {
    let agent = acting_identity(&ctx.caller, a.agent.as_deref())?;
    let id = a.note_id;
    ctx.hub
        .db()
        .write_async(move |tx| {
            let note = load_note(tx, id)?;
            let receiver = note["delivered_to"].as_str().or(note["assigned_to"].as_str()).unwrap_or("");
            let state = note["state"].as_str().unwrap_or("");
            if !matches!(state, "assigned" | "delivered") || receiver != agent {
                return Err(UaError::denied(
                    "not_note_receiver",
                    format!(
                        "handoff note {id} is not handed to {agent}: only the agent a note was assigned or delivered \
                         to acknowledges it"
                    ),
                ));
            }
            if !note["acknowledged_at"].is_null() {
                return Ok(note);
            }
            let stamp = ua_core::time::now();
            tx.execute(
                "UPDATE session_handoff_notes SET state = 'delivered', delivered_to = ?1, \
                 delivered_at = COALESCE(delivered_at, ?2), acknowledged_at = ?2, updated_at = ?2 WHERE id = ?3",
                params![agent, stamp, id],
            )?;
            let note = load_note(tx, id)?;
            emit(tx, &note, "acknowledged", &agent, json!({ "to_agent": agent }))?;
            Ok(note)
        })
        .await
}
