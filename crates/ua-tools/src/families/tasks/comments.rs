//! `task_comment(action, params)`: an append-only conversation on a task.
//!
//! Notes stay the specification (`task_update(append_note=...)`). A comment
//! is an authored utterance, optionally threaded, with mentions and
//! references. There is no update or delete.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};
use ua_store::task_comments::{
    NewTaskComment, SqliteTaskComments, TaskCommentRow, TaskCommentsRead, TaskCommentsWrite,
};

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
            let org = ctx.caller.org_id.clone();
            ctx.hub.db().read_async(move |c| list(c, &org, p.task_id)).await
        }
        "get" => {
            let p: GetParams = parse_params("get", a.params)?;
            let org = ctx.caller.org_id.clone();
            ctx.hub
                .db()
                .read_async(move |c| {
                    let mut repo = SqliteTaskComments::new(c);
                    let row = get(&mut repo, &org, p.comment_id)?
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

/// Base 10-field JSON map matching the pre-migration `SELECT *` row shape of
/// `task_comments` (without `org_id`), leaving `mentions` and `refs` as raw
/// text so each caller can apply its own JSON decoding rules.
pub(crate) fn base_json_map(row: &TaskCommentRow) -> Map<String, Value> {
    let mut obj = Map::new();
    obj.insert("id".into(), json!(row.id));
    obj.insert("task_id".into(), json!(row.task_id));
    obj.insert("parent_comment_id".into(), json!(row.parent_comment_id));
    obj.insert("author".into(), json!(row.author));
    obj.insert("body".into(), json!(row.body));
    obj.insert("mentions".into(), Value::String(row.mentions_json.clone()));
    obj.insert("refs".into(), Value::String(row.refs_json.clone()));
    obj.insert("idempotency_key".into(), json!(row.idempotency_key));
    obj.insert("thread_revision".into(), json!(row.thread_revision));
    obj.insert("created_at".into(), json!(row.created_at));
    obj
}

/// A comment reply, without its `org_id` (the caller's own).
fn public(row: &TaskCommentRow) -> Map<String, Value> {
    let mut obj = base_json_map(row);
    for (key, empty) in [("mentions", json!([])), ("refs", json!({}))] {
        let parsed =
            obj.get(key).and_then(Value::as_str).and_then(|s| serde_json::from_str(s).ok()).unwrap_or(empty);
        obj.insert(key.into(), parsed);
    }
    let mut participants = vec![obj.get("author").cloned().unwrap_or(Value::Null)];
    participants.extend(obj.get("mentions").and_then(Value::as_array).cloned().unwrap_or_default());
    obj.insert("participants".into(), Value::Array(participants));
    obj
}

/// Comment `id` of organization `org`; another organization's comment
/// answers as a missing one.
fn get(repo: &mut impl TaskCommentsRead, org: &str, id: i64) -> UaResult<Option<Map<String, Value>>> {
    Ok(repo.get_task_comment(org, id)?.as_ref().map(public))
}

fn list(conn: &Connection, org: &str, task_id: i64) -> UaResult<Value> {
    if task_object(conn, org, task_id)?.is_none() {
        return Err(UaError::not_found(format!("unknown task: {task_id}")));
    }
    let mut repo = SqliteTaskComments::new(conn);
    let comments: Vec<Map<String, Value>> =
        repo.list_task_comments(org, task_id)?.iter().map(public).collect();
    let snap = repo.get_task_comment_thread(org, task_id)?;
    Ok(json!({
        "task_id": task_id,
        "revision": snap.as_ref().map(|s| s.revision).unwrap_or(0),
        "updated_at": snap.map(|s| s.updated_at),
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
    let org = ctx.caller.org_id.clone();
    let clock = ctx.hub.cfg().clock;

    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            if task_object(tx, &org, task_id)?.is_none() {
                return Err(UaError::not_found(format!("unknown task: {task_id}")));
            }
            if let Some(k) = &key {
                let prior = tx.find_task_comment_by_idempotency_key(&org, task_id, &author, k)?;
                if let Some(prior) = prior {
                    return Ok(json!({ "comment": public(&prior), "idempotent_replay": true }));
                }
            }
            if let Some(pid) = parent {
                let on = tx.get_task_comment(&org, pid)?.map(|c| c.task_id);
                if on != Some(task_id) {
                    return Err(UaError::invalid("parent comment is not on this task"));
                }
            }
            let ts = clock.now();
            let revision = tx.bump_task_comment_thread(&org, task_id, &ts)?;
            let comment_id = tx.insert_task_comment(&NewTaskComment {
                org_id: org.clone(),
                task_id,
                parent_comment_id: parent,
                author: author.clone(),
                body,
                mentions_json: Value::from(mentions.clone()).to_string(),
                refs_json: Value::Object(refs).to_string(),
                idempotency_key: key,
                thread_revision: revision,
                created_at: ts,
            })?;
            let mentions = if org == ua_core::DEFAULT_ORG { json!(mentions) } else { Value::Null };
            emit(
                tx,
                &org,
                "agent.task.commented",
                json!({ "comment_id": comment_id, "task_id": task_id, "thread_revision": revision,
                        "mentions": mentions }),
                &author,
            )?;
            let mut out = json!({ "comment": get(tx, &org, comment_id)?, "idempotent_replay": false });
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
