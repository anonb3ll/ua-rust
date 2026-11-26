//! A note's lifecycle after it is saved: soft delete (`memory_delete`),
//! undelete and un-supersede (`memory_restore`), and feedback
//! (`memory_feedback`).

use rusqlite::params;
use serde_json::{Value, json};
use ua_core::{Caller, Config, UaError, UaResult};
use ua_store::Db;

use super::note::{
    self, DELETED_BY_HUMAN_TAG, DELETED_TAG, assert_privileged, emit, json_list, json_text, ledger_label,
    verified,
};

/// Soft-delete note `id` of the caller's organization as `caller`: its
/// content becomes an attributed tombstone and it is tagged [`DELETED_TAG`].
/// Returns `{deleted}`; `false` for a missing note, and for another
/// organization's, alike.
pub async fn delete(db: &Db, cfg: &Config, caller: &Caller, id: String) -> UaResult<Value> {
    let Some(actor) = verified(caller).map(str::to_string) else {
        return Err(UaError::denied(
            "unverified",
            "memory_delete requires a verified identity; an unverified or spoofed author is refused",
        ));
    };
    let human = ua_org::authz::human(caller);
    let (label, org, ts) = (caller.label.clone(), caller.org_id.clone(), cfg.clock.now());
    db.write_async(move |tx| {
        note::require_org(tx, &org)?;
        let Some(n) = note::fetch(tx, &org, &id)? else { return Ok(json!({ "deleted": false })) };
        if n.is_deleted() {
            return Ok(json!({ "deleted": false }));
        }
        if n.author.as_deref() != Some(actor.as_str()) && !human {
            return Err(UaError::denied(
                "not_owner",
                format!(
                    "memory note {:?} is owned by {:?}; you are {actor:?}. Only the note owner or a verified \
                     human identity can delete it.",
                    id,
                    n.author.as_deref().unwrap_or_default()
                ),
            ));
        }
        let tombstone =
            note::tombstone_block(n.author.as_deref(), n.title.as_deref(), &n.content, Some(&actor), &ts);
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
            "UPDATE memory SET content = ?1, tags = ?2, updated_at = ?3, updated_by = ?4 \
             WHERE id = ?5 AND org_id = ?6",
            params![tombstone.trim_start_matches('\n'), json_text(&tags), ts, actor, id, org],
        )?;
        emit(
            tx,
            &org,
            "agent.memory.deleted",
            json!({
                "id": id,
                "owner": ledger_label(&org, n.author.as_deref()),
                "actor": ledger_label(&org, Some(&actor)),
                "by_human": human,
            }),
            &label,
        )?;
        Ok(json!({ "deleted": true }))
    })
    .await
}

/// Re-promote superseded note `id` of the caller's organization, or undo its
/// soft delete from the newest version recorded before the delete, as
/// `caller`. `cfg.human_identities`
/// names the identities whose deletes only a human may undo.
pub async fn restore(db: &Db, cfg: &Config, caller: &Caller, id: String) -> UaResult<Value> {
    let caller = caller.clone();
    // Only what `Config::is_human` reads, not the whole config.
    let humans = cfg.human_identities.clone();
    let ts = cfg.clock.now();
    db.write_async(move |tx| {
        let org = caller.org_id.clone();
        note::require_org(tx, &org)?;
        let n = note::require(tx, &org, &id)?;
        let actor = verified(&caller).map(str::to_string);
        let human = ua_org::authz::human(&caller);
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
                || n.updated_by.as_deref().is_some_and(|u| humans.iter().any(|h| h == u));
            if human_deleted && !human {
                return Err(UaError::denied(
                    "human_only",
                    format!(
                        "memory note {:?} was deleted by a verified human ({:?}); only a verified human \
                         identity can restore it.",
                        id,
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
                        id,
                        n.author.as_deref().unwrap_or_default()
                    ),
                ));
            }
            let prior = {
                let mut stmt = tx.prepare(
                    "SELECT version, content, tags FROM memory_versions WHERE note_id = ?1 AND org_id = ?2 \
                     ORDER BY version DESC",
                )?;
                let rows = stmt.query_map(params![id, org], |r| {
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
                    id
                )));
            };
            tags.sort();
            tags.dedup();
            // A restored broadcast note is a broadcast again.
            assert_privileged(&caller, &tags, None)?;
            tx.execute(
                "UPDATE memory SET content = ?1, tags = ?2, updated_at = ?3, updated_by = ?4 \
                 WHERE id = ?5 AND org_id = ?6",
                params![content, json_text(&tags), ts, actor, id, org],
            )?;
            emit(
                tx,
                &org,
                "agent.memory.restored",
                json!({
                    "id": id,
                    "was_deleted": true,
                    "restored_version": version,
                    "actor": ledger_label(&org, Some(&actor)),
                }),
                &caller.label,
            )?;
            let revision = note::require(tx, &org, &id)?.revision();
            let mut res = json!({
                "id": id,
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
            return Ok(json!({ "id": id, "restored": false, "was_superseded_by": null }));
        };
        // Restore reverses a supersede, so it takes the same owner rule.
        if let Some(actor) = &actor
            && !human
            && n.author.as_deref() != Some(actor.as_str())
        {
            return Err(UaError::denied(
                "not_owner",
                "only the note owner or a verified human can restore it",
            ));
        }
        tx.execute(
            "UPDATE memory SET superseded_by = NULL, valid_to = NULL WHERE id = ?1 AND org_id = ?2",
            params![id, org],
        )?;
        emit(
            tx,
            &org,
            "agent.memory.restored",
            json!({ "id": id, "was_superseded_by": was, "actor": ledger_label(&org, actor.as_deref()) }),
            &caller.label,
        )?;
        Ok(json!({ "id": id, "restored": true, "was_superseded_by": was }))
    })
    .await
}

const SIGNALS: [(&str, &str); 4] = [
    ("helpful", "feedback_helpful"),
    ("not_helpful", "feedback_not_helpful"),
    ("stale", "feedback_stale"),
    ("wrong", "feedback_wrong"),
];

/// Record `signal` (`helpful`, `not_helpful`, `stale` or `wrong`) on note
/// `id` of the caller's organization. Returns the note's counters and its
/// `confidence_posterior`.
pub async fn feedback(db: &Db, cfg: &Config, caller: &Caller, id: String, signal: String) -> UaResult<Value> {
    let signal = signal.trim().to_lowercase();
    let Some((_, column)) = SIGNALS.iter().find(|(s, _)| *s == signal) else {
        return Err(UaError::invalid("signal must be one of helpful, not_helpful, stale, wrong"));
    };
    let column = *column;
    let (label, org, now) = (caller.label.clone(), caller.org_id.clone(), cfg.clock.now());
    db.write_async(move |tx| {
        note::require_org(tx, &org)?;
        note::require(tx, &org, &id)?;
        // Feedback is not an edit: content, tags and updated_at stay. A
        // helpful vote is also an explicit upvote for ranking.
        let upvote = if signal == "helpful" { ", upvoted_count = upvoted_count + 1" } else { "" };
        tx.execute(
            &format!("UPDATE memory SET {column} = {column} + 1{upvote} WHERE id = ?1 AND org_id = ?2"),
            params![id, org],
        )?;
        emit(tx, &org, "agent.memory.feedback", json!({ "id": id, "signal": signal }), &label)?;
        let n = note::require(tx, &org, &id)?;
        let open = note::open_contradictions(tx, &org, None, &now)?.get(&id).copied().unwrap_or(0);
        let mut res = json!({ "id": id, "signal": signal });
        if let (Some(obj), Value::Object(summary)) = (res.as_object_mut(), n.summary()) {
            obj.extend(summary);
        }
        res["confidence_posterior"] = n.confidence_block(open);
        Ok(res)
    })
    .await
}
