//! `memory_delete`, `memory_restore` and `memory_feedback`.

use rusqlite::params;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use super::note::{
    self, DELETED_BY_HUMAN_TAG, DELETED_TAG, assert_privileged, is_human, json_list, json_text, verified,
};
use crate::registry::{Registry, ToolCtx, tool};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdArgs {
    /// Note id.
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackArgs {
    /// Note id.
    pub id: String,
    /// One of `helpful`, `not_helpful`, `stale`, `wrong`.
    pub signal: String,
}

async fn delete(ctx: ToolCtx, a: IdArgs) -> UaResult<Value> {
    let Some(actor) = verified(&ctx.caller).map(str::to_string) else {
        return Err(UaError::denied(
            "unverified",
            "memory_delete requires a verified identity; an unverified or spoofed author is refused",
        ));
    };
    let human = is_human(&ctx.caller);
    let label = ctx.caller.label.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let Some(n) = note::fetch(tx, &a.id)? else { return Ok(json!({ "deleted": false })) };
            if n.is_deleted() {
                return Ok(json!({ "deleted": false }));
            }
            if n.author.as_deref() != Some(actor.as_str()) && !human {
                return Err(UaError::denied(
                    "not_owner",
                    format!(
                        "memory note {:?} is owned by {:?}; you are {actor:?}. Only the note owner or a verified \
                         human identity can delete it.",
                        a.id,
                        n.author.as_deref().unwrap_or_default()
                    ),
                ));
            }
            let ts = ua_core::time::now();
            let tombstone = note::tombstone_block(n.author.as_deref(), n.title.as_deref(), &n.content, Some(&actor), &ts);
            let mut tags = n.tags.clone();
            tags.push(DELETED_TAG.into());
            if human {
                tags.push(DELETED_BY_HUMAN_TAG.into());
            }
            tags.sort();
            tags.dedup();
            // The row stays: the tombstone keeps the text, the version
            // history keeps the prior state, and memory_restore undoes it.
            tx.execute(
                "UPDATE memory SET content = ?1, tags = ?2, updated_at = ?3, updated_by = ?4 WHERE id = ?5",
                params![tombstone.trim_start_matches('\n'), json_text(&tags), ts, actor, a.id],
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "agent.memory.deleted",
                    json!({ "id": a.id, "owner": n.author, "actor": actor, "by_human": human }),
                )
                .by(label),
            )?;
            Ok(json!({ "deleted": true }))
        })
        .await
}

async fn restore(ctx: ToolCtx, a: IdArgs) -> UaResult<Value> {
    let caller = ctx.caller.clone();
    let hub = ctx.hub.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let n = note::require(tx, &a.id)?;
            let actor = verified(&caller).map(str::to_string);
            let human = is_human(&caller);
            if n.is_deleted() {
                let Some(actor) = actor else {
                    return Err(UaError::denied(
                        "unverified",
                        "restoring a deleted memory note requires a verified identity; an unverified or spoofed \
                         author is refused",
                    ));
                };
                // A delete a human made is undone only by a human; an older
                // tombstone is judged by the identity that wrote it.
                let human_deleted = n.tags.iter().any(|t| t == DELETED_BY_HUMAN_TAG)
                    || n.updated_by.as_deref().is_some_and(|u| hub.cfg().is_human(u));
                if human_deleted && !human {
                    return Err(UaError::denied(
                        "human_only",
                        format!(
                            "memory note {:?} was deleted by a verified human ({:?}); only a verified human \
                             identity can restore it.",
                            a.id,
                            n.updated_by.as_deref().unwrap_or_default()
                        ),
                    ));
                }
                if n.author.as_deref() != Some(actor.as_str()) && !human {
                    return Err(UaError::denied(
                        "not_owner",
                        format!(
                            "memory note {:?} is owned by {:?}; you are {actor:?}. Only the note owner or a \
                             verified human identity can restore it.",
                            a.id,
                            n.author.as_deref().unwrap_or_default()
                        ),
                    ));
                }
                let prior = {
                    let mut stmt = tx.prepare(
                        "SELECT version, content, tags FROM memory_versions WHERE note_id = ?1 ORDER BY version DESC",
                    )?;
                    let rows = stmt.query_map([&a.id], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?))
                    })?;
                    let mut found = None;
                    for row in rows {
                        let (version, content, tags) = row?;
                        let tags = json_list(tags);
                        if !tags.iter().any(|t| t == DELETED_TAG) {
                            found = Some((version, content, tags));
                            break;
                        }
                    }
                    found
                };
                let Some((version, content, mut tags)) = prior else {
                    return Err(UaError::invalid(format!(
                        "memory note {:?} has no recorded version from before its deletion, so it cannot be \
                         restored in place. memory_get still reads the tombstone, which keeps the deleted text; \
                         save that as a new note instead.",
                        a.id
                    )));
                };
                tags.sort();
                tags.dedup();
                // A restored broadcast note is a broadcast again.
                assert_privileged(&caller, &tags, None)?;
                let ts = ua_core::time::now();
                tx.execute(
                    "UPDATE memory SET content = ?1, tags = ?2, updated_at = ?3, updated_by = ?4 WHERE id = ?5",
                    params![content, json_text(&tags), ts, actor, a.id],
                )?;
                ledger::append(
                    tx,
                    EventInput::new(
                        "agent.memory.restored",
                        json!({ "id": a.id, "was_deleted": true, "restored_version": version, "actor": actor }),
                    )
                    .by(caller.label.clone()),
                )?;
                let revision = note::require(tx, &a.id)?.revision();
                let mut res = json!({
                    "id": a.id,
                    "restored": true,
                    "was_superseded_by": null,
                    "was_deleted": true,
                    "restored_version": version,
                    "revision": revision,
                });
                if let Some(by) = &n.superseded_by {
                    // Undelete only; a second memory_restore re-promotes it.
                    res["superseded_by"] = json!(by);
                }
                return Ok(res);
            }

            let Some(was) = n.superseded_by.clone() else {
                return Ok(json!({ "id": a.id, "restored": false, "was_superseded_by": null }));
            };
            // Restore reverses a supersede, so it takes the same owner rule.
            if let Some(actor) = &actor
                && !human
                && n.author.as_deref() != Some(actor.as_str())
            {
                return Err(UaError::denied("not_owner", "only the note owner or a verified human can restore it"));
            }
            tx.execute("UPDATE memory SET superseded_by = NULL, valid_to = NULL WHERE id = ?1", [&a.id])?;
            ledger::append(
                tx,
                EventInput::new(
                    "agent.memory.restored",
                    json!({ "id": a.id, "was_superseded_by": was, "actor": actor }),
                )
                .by(caller.label.clone()),
            )?;
            Ok(json!({ "id": a.id, "restored": true, "was_superseded_by": was }))
        })
        .await
}

const SIGNALS: [(&str, &str); 4] = [
    ("helpful", "feedback_helpful"),
    ("not_helpful", "feedback_not_helpful"),
    ("stale", "feedback_stale"),
    ("wrong", "feedback_wrong"),
];

async fn feedback(ctx: ToolCtx, a: FeedbackArgs) -> UaResult<Value> {
    let signal = a.signal.trim().to_lowercase();
    let Some((_, column)) = SIGNALS.iter().find(|(s, _)| *s == signal) else {
        return Err(UaError::invalid("signal must be one of helpful, not_helpful, stale, wrong"));
    };
    let column = *column;
    let label = ctx.caller.label.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            note::require(tx, &a.id)?;
            // Feedback is not an edit: content, tags and updated_at stay. A
            // helpful vote is also an explicit upvote for ranking.
            let upvote = if signal == "helpful" { ", upvoted_count = upvoted_count + 1" } else { "" };
            tx.execute(&format!("UPDATE memory SET {column} = {column} + 1{upvote} WHERE id = ?1"), [&a.id])?;
            ledger::append(
                tx,
                EventInput::new("agent.memory.feedback", json!({ "id": a.id, "signal": signal })).by(label),
            )?;
            let n = note::require(tx, &a.id)?;
            let open = note::open_contradictions(tx, None)?.get(&a.id).copied().unwrap_or(0);
            let mut res = json!({ "id": a.id, "signal": signal });
            if let (Some(obj), Value::Object(summary)) = (res.as_object_mut(), n.summary()) {
                obj.extend(summary);
            }
            res["confidence_posterior"] = n.confidence_block(open);
            Ok(res)
        })
        .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "memory_delete",
            "Soft-delete a memory note: its content becomes an attributed tombstone and it is tagged \
             meta:deleted, so search and listing hide it while memory_get still reads it. Needs a verified \
             identity that owns the note, or a human. Returns {deleted}; false when the id is missing or already \
             deleted.",
            delete,
        )
        .family("memory"),
    );
    r.add(
        tool(
            "memory_restore",
            "Re-promote a superseded note (clears superseded_by), or undo a soft delete in place from the newest \
             version recorded before the delete. Undeleting needs the owner or a human; a note a human deleted \
             needs a human. Returns {id, restored, was_superseded_by}.",
            restore,
        )
        .family("memory"),
    );
    r.add(
        tool(
            "memory_feedback",
            "Record helpful / not_helpful / stale / wrong on a memory note. The counts form a Beta posterior that \
             feeds search ranking; content and updated_at are not touched. Returns the counters and \
             confidence_posterior.",
            feedback,
        )
        .family("memory"),
    );
}
