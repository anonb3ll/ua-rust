//! `task_comment(action, params)`: an append-only conversation on a task.
//!
//! Notes stay the specification (`task_update(append_note=...)`). A comment
//! is an authored utterance, optionally threaded, with mentions and
//! references. There is no update or delete.

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};

use super::*;
use crate::registry::{Registry, ToolCtx, tool};

const MAX_BODY: usize = 8000;
const MAX_MENTIONS: usize = 20;
const REF_KEYS: [&str; 3] = ["plan_id", "decision_id", "handoff_id"];
const CREDENTIAL_PREFIX: &str = "uas_";
const CREDENTIAL_MIN_TAIL: usize = 16;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommentArgs {
    /// `append`, `list` or `get`.
    pub action: String,
    /// Action arguments. append: `task_id`, `body`, `parent_comment_id?`,
    /// `mentions?` (agent labels), `refs?` (`plan_id`, `decision_id`,
    /// `handoff_id`), `idempotency_key?`, `author?`. list: `task_id`.
    /// get: `comment_id`.
    pub params: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendParams {
    task_id: i64,
    body: String,
    parent_comment_id: Option<i64>,
    mentions: Option<Vec<String>>,
    refs: Option<Map<String, Value>>,
    idempotency_key: Option<String>,
    author: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    task_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetParams {
    comment_id: i64,
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "task_comment",
            "Append-only task comments. action: append (task_id, body, parent_comment_id?, mentions?, refs?, \
             idempotency_key?), list (task_id) or get (comment_id). There is no update or delete.",
            |ctx: ToolCtx, a: CommentArgs| async move { comment(ctx, a).await },
        )
        .family("tasks"),
    );
}

async fn comment(ctx: ToolCtx, a: CommentArgs) -> UaResult<Value> {
    match crate::routes::action_of("task_comment", Some(&a.action))? {
        "update" | "delete" | "edit" | "remove" => Err(UaError::invalid("comments are append-only")),
        "append" => {
            let p: AppendParams = parse_params("append", a.params)?;
            append(ctx, p).await
        }
        "list" => {
            let p: ListParams = parse_params("list", a.params)?;
            ctx.hub.db().read_async(move |c| list(c, p.task_id)).await
        }
        "get" => {
            let p: GetParams = parse_params("get", a.params)?;
            ctx.hub
                .db()
                .read_async(move |c| {
                    let row = get(c, p.comment_id)?
                        .ok_or_else(|| UaError::not_found(format!("unknown comment: {}", p.comment_id)))?;
                    Ok(json!({ "comment": row }))
                })
                .await
        }
        other => Err(crate::routes::unhandled("task_comment", other)),
    }
}

fn is_credential_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Replace hub session credentials (`uas_...`) with a placeholder.
fn redact_credentials(text: &str) -> (String, bool) {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut found = false;
    while let Some(pos) = rest.find(CREDENTIAL_PREFIX) {
        let boundary = rest[..pos].chars().next_back().is_none_or(|c| !is_credential_char(c));
        let tail_start = pos + CREDENTIAL_PREFIX.len();
        let tail_len = rest[tail_start..].chars().take_while(|c| is_credential_char(*c)).count();
        out.push_str(&rest[..pos]);
        if boundary && tail_len >= CREDENTIAL_MIN_TAIL {
            out.push_str("[redacted-credential]");
            found = true;
        } else {
            out.push_str(&rest[pos..tail_start + tail_len]);
        }
        rest = &rest[tail_start + tail_len..];
    }
    out.push_str(rest);
    (out, found)
}

fn public(row: &rusqlite::Row<'_>) -> rusqlite::Result<Map<String, Value>> {
    let mut obj = row_object(row)?;
    for (key, empty) in [("mentions", json!([])), ("refs", json!({}))] {
        let parsed =
            obj.get(key).and_then(Value::as_str).and_then(|s| serde_json::from_str(s).ok()).unwrap_or(empty);
        obj.insert(key.into(), parsed);
    }
    let mut participants = vec![obj.get("author").cloned().unwrap_or(Value::Null)];
    participants.extend(obj.get("mentions").and_then(Value::as_array).cloned().unwrap_or_default());
    obj.insert("participants".into(), Value::Array(participants));
    Ok(obj)
}

fn get(conn: &Connection, id: i64) -> UaResult<Option<Map<String, Value>>> {
    Ok(conn.query_row("SELECT * FROM task_comments WHERE id = ?1", [id], public).optional()?)
}

fn list(conn: &Connection, task_id: i64) -> UaResult<Value> {
    if task_object(conn, task_id)?.is_none() {
        return Err(UaError::not_found(format!("unknown task: {task_id}")));
    }
    let mut stmt = conn.prepare("SELECT * FROM task_comments WHERE task_id = ?1 ORDER BY id")?;
    let comments: Vec<Map<String, Value>> = stmt.query_map([task_id], public)?.collect::<Result<_, _>>()?;
    let snap: Option<(i64, String)> = conn
        .query_row(
            "SELECT revision, updated_at FROM task_comment_threads WHERE task_id = ?1",
            [task_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(json!({
        "task_id": task_id,
        "revision": snap.as_ref().map(|s| s.0).unwrap_or(0),
        "updated_at": snap.map(|s| s.1),
        "comments": comments,
        "notes_are_spec": true,
    }))
}

fn check_mentions(raw: Option<Vec<String>>) -> UaResult<Vec<String>> {
    let mut labels: Vec<String> = Vec::new();
    for item in raw.unwrap_or_default() {
        let label = item.trim().to_string();
        if label.is_empty() || label.chars().any(char::is_whitespace) || label.len() > 64 {
            return Err(UaError::invalid(format!("invalid mention: {item:?}")));
        }
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if labels.len() > MAX_MENTIONS {
        return Err(UaError::invalid(format!(
            "a comment may mention at most {MAX_MENTIONS} agents (got {})",
            labels.len()
        )));
    }
    Ok(labels)
}

fn check_refs(raw: Option<Map<String, Value>>) -> UaResult<Map<String, Value>> {
    let mut out = Map::new();
    for (k, v) in raw.unwrap_or_default() {
        if !REF_KEYS.contains(&k.as_str()) {
            return Err(UaError::invalid(format!("unknown ref key {k:?}; expected one of {REF_KEYS:?}")));
        }
        if v.is_null() {
            continue;
        }
        let cleaned = if k == "handoff_id" {
            json!(v.as_i64().ok_or_else(|| UaError::invalid("handoff_id must be an integer delegation id"))?)
        } else {
            let s = match &v {
                Value::String(s) => s.trim().to_string(),
                Value::Number(n) => n.to_string(),
                _ => return Err(UaError::invalid(format!("{k} must be a string or number"))),
            };
            if s.is_empty() || s.len() > 200 {
                return Err(UaError::invalid(format!("{k} must be 1-200 characters")));
            }
            json!(s)
        };
        out.insert(k, cleaned);
    }
    Ok(out)
}

async fn append(ctx: ToolCtx, p: AppendParams) -> UaResult<Value> {
    let body = p.body.trim();
    if body.is_empty() {
        return Err(UaError::invalid("body must not be empty"));
    }
    for (field, value) in [
        ("author", p.author.clone().unwrap_or_default()),
        ("mentions", p.mentions.clone().unwrap_or_default().join(" ")),
        ("idempotency_key", p.idempotency_key.clone().unwrap_or_default()),
    ] {
        if redact_credentials(&value).1 {
            return Err(UaError::invalid(format!("{field} must not carry a hub session credential")));
        }
    }
    let (body, redacted) = redact_credentials(body);
    if body.chars().count() > MAX_BODY {
        return Err(UaError::invalid(format!("body must be at most {MAX_BODY} characters")));
    }
    let author = if is_verified(&ctx.caller) {
        ctx.caller.label.clone()
    } else {
        acting_identity(&ctx.caller, p.author.as_deref())?
    };
    let key = check_idempotency_key(p.idempotency_key.as_deref())?;
    let mentions = check_mentions(p.mentions)?;
    let refs = check_refs(p.refs)?;
    let task_id = p.task_id;
    let parent = p.parent_comment_id;

    ctx.hub
        .db()
        .write_async(move |tx| {
            if task_object(tx, task_id)?.is_none() {
                return Err(UaError::not_found(format!("unknown task: {task_id}")));
            }
            if let Some(k) = &key {
                let prior = tx
                    .query_row(
                        "SELECT * FROM task_comments WHERE task_id = ?1 AND author = ?2 AND idempotency_key = ?3",
                        params![task_id, author, k],
                        public,
                    )
                    .optional()?;
                if let Some(prior) = prior {
                    return Ok(json!({ "comment": prior, "idempotent_replay": true }));
                }
            }
            if let Some(pid) = parent {
                let on: Option<i64> = tx
                    .query_row("SELECT task_id FROM task_comments WHERE id = ?1", [pid], |r| r.get(0))
                    .optional()?;
                if on != Some(task_id) {
                    return Err(UaError::invalid("parent comment is not on this task"));
                }
            }
            let ts = now();
            tx.execute(
                "INSERT INTO task_comment_threads (task_id, revision, updated_at) VALUES (?1, 1, ?2) \
                 ON CONFLICT(task_id) DO UPDATE SET revision = revision + 1, updated_at = excluded.updated_at",
                params![task_id, ts],
            )?;
            let revision: i64 =
                tx.query_row("SELECT revision FROM task_comment_threads WHERE task_id = ?1", [task_id], |r| r.get(0))?;
            tx.execute(
                "INSERT INTO task_comments (task_id, parent_comment_id, author, body, mentions, refs, \
                 idempotency_key, thread_revision, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    task_id,
                    parent,
                    author,
                    body,
                    Value::from(mentions.clone()).to_string(),
                    Value::Object(refs).to_string(),
                    key,
                    revision,
                    ts
                ],
            )?;
            let comment_id = tx.last_insert_rowid();
            emit(
                tx,
                "agent.task.commented",
                json!({ "comment_id": comment_id, "task_id": task_id, "thread_revision": revision,
                        "mentions": mentions }),
                &author,
            )?;
            let mut out = json!({ "comment": get(tx, comment_id)?, "idempotent_replay": false });
            if redacted {
                out["warning"] = json!(
                    "a hub session credential (uas_...) was redacted from this comment; credentials never belong \
                     in a task thread"
                );
            }
            Ok(out)
        })
        .await
}
