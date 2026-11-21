//! Hand a mailbox conversation off to a task.
//!
//! A conversation is a `message_send` thread (`conversation_id`). Handing it
//! off creates a task, or links an existing one, that *references* the
//! conversation by id. The transcript keeps one owner: no message body is
//! copied into task notes or any other table.
//!
//! The link is recorded twice: a
//! `[conversation: <id>] handed off from the agent conversation` line in the
//! task notes, and one `agent.conversation.handoff` ledger event (who handed
//! off, and when). The event is the audited record: `conversation_handoffs`
//! lists a task under `handoffs` only when a handoff event links it, and a
//! task whose notes merely carry the line (anyone who can write notes can
//! type it) under `unaudited`, so a note line never passes for a handoff.
//!
//! Rules:
//!
//! - Both actions need a verified caller that can see the conversation: it
//!   sent or received a message in it, or it may read every mailbox (a human,
//!   or the coordinator profile). "Missing" and "not yours" read alike
//!   (`not_found`).
//! - Only an id-safe conversation id (1-200 letters, digits, `.`, `_`, `:`
//!   or `-`) is written into notes, so an id cannot forge a note marker.
//! - The task write is the registered `task_add` (create) or `task_update`
//!   (link, `append_note`) called through the governed registry as the
//!   caller, so the caller's profile, the policy file and the approval gate
//!   apply exactly as to a direct call.
//! - Creating is idempotent per conversation, title, project and priority
//!   (a `task_add` idempotency key derived from them): a repeat returns the
//!   same task. Relinking appends nothing new (`task_update` suppresses a
//!   verbatim repeat of a note line).

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{Profile, UaError, UaResult};
use ua_store::{EventInput, ledger};

use crate::families::agents::verified;
use crate::families::governance;
use crate::registry::ToolCtx;

const CHANNEL: &str = "agent.conversation.handoff";
const MAX_TITLE: usize = 300;
const MAX_ID_LEN: usize = 200;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffArgs {
    /// A conversation you can see (1-200 letters, digits, `.`, `_`, `:` or `-`).
    pub conversation_id: String,
    /// Link this existing task. Pass this or `title`, not both.
    pub task_id: Option<i64>,
    /// Create a task with this title. Pass this or `task_id`, not both.
    pub title: Option<String>,
    /// Project for a created task.
    pub project: Option<String>,
    /// Priority for a created task: `high`, `med` (default) or `low`.
    pub priority: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffsArgs {
    /// A conversation you can see.
    pub conversation_id: String,
}

/// The task-note line that points at a conversation.
fn reference(cid: &str) -> String {
    format!("[conversation: {cid}] handed off from the agent conversation")
}

fn is_id_safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

/// Whether the verified caller may read every mailbox (and so every
/// conversation). An unverified caller never is.
fn unrestricted(ctx: &ToolCtx) -> bool {
    let cfg = ctx.hub.cfg();
    verified(&ctx.caller).is_some_and(|label| {
        ctx.caller.is_human() || cfg.is_human(label) || ctx.caller.profile == Profile::Coordinator
    })
}

fn visible(conn: &Connection, cid: &str, viewer: Option<&str>) -> UaResult<bool> {
    let found: bool = match viewer {
        None => conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM message_index WHERE conversation_id = ?1)",
            [cid],
            |r| r.get(0),
        )?,
        Some(me) => conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM message_index WHERE conversation_id = ?1 AND (sender = ?2 OR recipient = ?2))",
            params![cid, me],
            |r| r.get(0),
        )?,
    };
    Ok(found)
}

/// The idempotency key one create handoff uses.
fn create_key(cid: &str, title: &str, project: Option<&str>, priority: &str) -> String {
    let material = json!([cid, title, project.unwrap_or(""), priority]).to_string();
    let digest = hex::encode(Sha256::digest(material.as_bytes()));
    format!("conversation-handoff:{}", &digest[..40])
}

fn registry() -> &'static crate::Registry {
    crate::builtin_registry_shared()
}

/// `coordination_manage(action="conversation_handoff")`.
pub(crate) async fn conversation_handoff(ctx: ToolCtx, a: HandoffArgs) -> UaResult<Value> {
    let actor = governance::verified_actor(&ctx.caller, "handing off a conversation")?;
    let cid = a.conversation_id.trim().to_string();
    if !is_id_safe(&cid) {
        return Err(UaError::invalid("conversation_id must be 1-200 letters, digits, '.', '_', ':' or '-'"));
    }
    let title = a.title.as_deref().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
    if a.task_id.is_some() == title.is_some() {
        return Err(UaError::invalid("pass exactly one of task_id (link) or title (create)"));
    }
    let viewer = (!unrestricted(&ctx)).then(|| actor.clone());
    let c2 = cid.clone();
    if !ctx.hub.db().read_async(move |c| visible(c, &c2, viewer.as_deref())).await? {
        return Err(UaError::not_found("conversation not found"));
    }

    let line = reference(&cid);
    let (task_id, created) = match (a.task_id, title) {
        (Some(id), _) => {
            let reply = registry()
                .call(&ctx.hub, &ctx.caller, "task_update", json!({ "id": id, "append_note": line }))
                .await?;
            (reply["id"].as_i64().unwrap_or(id), false)
        }
        (None, Some(title)) => {
            let title: String = title.chars().take(MAX_TITLE).collect();
            let priority = a.priority.unwrap_or_else(|| "med".into());
            let key = create_key(&cid, &title, a.project.as_deref(), &priority);
            let k2 = key.clone();
            let seen: bool = ctx
                .hub
                .db()
                .read_async(move |c| {
                    Ok(c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM idempotency_keys WHERE tool = 'task_add' AND key = ?1)",
                        [format!("task_add:{k2}")],
                        |r| r.get(0),
                    )?)
                })
                .await?;
            let mut args =
                json!({ "title": title, "notes": line, "priority": priority, "idempotency_key": key });
            if let Some(p) = a.project {
                args["project"] = json!(p);
            }
            let reply = registry().call(&ctx.hub, &ctx.caller, "task_add", args).await?;
            let id = reply["id"]
                .as_i64()
                .ok_or_else(|| UaError::internal("task_add returned no task id for the handoff"))?;
            (id, !seen)
        }
        (None, None) => unreachable!("checked above"),
    };

    let (c2, a2) = (cid.clone(), actor.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            let base = format!("conversation-handoff:{c2}:{task_id}:{a2}");
            let creator_recorded: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM event_log WHERE dedupe_key = ?1)",
                [format!("{base}:created")],
                |r| r.get(0),
            )?;
            if !created && creator_recorded {
                // The creating call's event already says who handed off and when.
                return Ok(());
            }
            let key = if created { format!("{base}:created") } else { base };
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    CHANNEL,
                    json!({ "conversation_id": c2, "task_id": task_id, "created": created, "by": a2 }),
                )
                .by(a2.clone())
                .dedupe(key),
            )?;
            Ok(())
        })
        .await?;
    Ok(json!({ "conversation_id": cid, "task_id": task_id, "created": created, "reference": line }))
}

/// `coordination_manage(action="conversation_handoffs")`: the tasks a visible
/// conversation was handed off to, by task id. `handoffs` holds the links a
/// handoff ledger event records (with `by`, `at` and whether the notes line
/// is still there); `unaudited` holds tasks whose notes carry the line with
/// no handoff event behind it. Same caller rule as `conversation_handoff`.
pub(crate) async fn conversation_handoffs(ctx: ToolCtx, a: HandoffsArgs) -> UaResult<Value> {
    let actor = governance::verified_actor(&ctx.caller, "reading a conversation's handoffs")?;
    let cid = a.conversation_id.trim().to_string();
    if !is_id_safe(&cid) {
        return Err(UaError::invalid("conversation_id must be 1-200 letters, digits, '.', '_', ':' or '-'"));
    }
    let viewer = (!unrestricted(&ctx)).then_some(actor);
    ctx.hub
        .db()
        .read_async(move |c| {
            if !visible(c, &cid, viewer.as_deref())? {
                return Err(UaError::not_found("conversation not found"));
            }
            let mut stmt =
                c.prepare("SELECT id FROM tasks WHERE instr(COALESCE(notes, ''), ?1) > 0 ORDER BY id")?;
            let noted: BTreeSet<i64> =
                stmt.query_map([reference(&cid)], |r| r.get(0))?.collect::<Result<_, _>>()?;
            // The first event per task says who handed off and when.
            let mut audit: BTreeMap<i64, (Option<String>, String)> = BTreeMap::new();
            let mut stmt = c.prepare(
                "SELECT json_extract(payload, '$.task_id'), json_extract(payload, '$.by'), created_at \
                 FROM event_log WHERE channel = ?1 AND json_extract(payload, '$.conversation_id') = ?2 ORDER BY seq",
            )?;
            let rows = stmt.query_map(params![CHANNEL, cid], |r| {
                Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, String>(2)?))
            })?;
            for row in rows {
                let (task, by, at) = row?;
                if let Some(t) = task {
                    audit.entry(t).or_insert((by, at));
                }
            }
            let task = |id: i64| -> UaResult<Option<(String, String)>> {
                Ok(c.query_row("SELECT title, status FROM tasks WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
                    .optional()?)
            };
            let mut handoffs = Vec::new();
            for (id, (by, at)) in &audit {
                let Some((title, status)) = task(*id)? else { continue };
                handoffs.push(json!({
                    "task_id": id, "title": title, "status": status, "by": by, "at": at,
                    "note_reference": noted.contains(id),
                }));
            }
            let mut unaudited = Vec::new();
            for id in noted.iter().filter(|id| !audit.contains_key(id)) {
                if let Some((title, status)) = task(*id)? {
                    unaudited.push(json!({ "task_id": id, "title": title, "status": status }));
                }
            }
            Ok(json!({ "conversation_id": cid, "handoffs": handoffs, "unaudited": unaudited }))
        })
        .await
}
