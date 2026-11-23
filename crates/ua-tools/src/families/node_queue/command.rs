//! Supervised commands: an argv (never a shell string) run on a node that
//! allowlists its program, behind the `node_dispatch` approval with the argv
//! in the approved payload. Each claim mints a fence token the receipt must
//! echo, so a command from an earlier claim cannot report. When it ends, its
//! owner gets one message from `hub-node` with the outcome and log location.

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use ua_core::{UaError, UaResult};
use ua_store::WriteTx;

use super::{
    Item, check_item_id, clip, load_item, now, record, request_dispatch, validate_new, verified_caller,
};
use crate::families::{agents, messaging};
use crate::hub::Hub;
use crate::registry::ToolCtx;
use ua_org::authz::{Authority, Authz};

/// The sender of command notices.
pub const NOTICE_SENDER: &str = "hub-node";
const MAX_ARG: usize = 4096;
const LOG_NAME: &str = "command.log";

#[derive(Debug, Clone)]
pub(crate) struct NewCommand {
    pub argv: Vec<String>,
    pub owner_agent: String,
    pub owner_session: Option<String>,
}

pub(crate) struct CommandRow {
    pub item_id: String,
    pub argv: Vec<String>,
    pub owner_agent: String,
    pub owner_session: Option<String>,
    pub fence_attempt: Option<i64>,
    pub fence_token: Option<String>,
    pub exit_code: Option<i64>,
    pub log_path: Option<String>,
}

impl CommandRow {
    /// Never the fence token.
    pub fn public(&self) -> Value {
        json!({
            "argv": self.argv,
            "owner_agent": self.owner_agent,
            "owner_session": self.owner_session,
            "exit_code": self.exit_code,
            "log_path": self.log_path,
        })
    }
}

pub(crate) fn validate_argv(argv: &[String]) -> UaResult<Vec<String>> {
    if argv.is_empty() || argv.len() > super::MAX_ARGV {
        return Err(UaError::invalid(format!("argv must hold 1-{} strings", super::MAX_ARGV)));
    }
    if argv.iter().any(|a| a.len() >= MAX_ARG || a.contains('\0')) {
        return Err(UaError::invalid(format!("each argv entry must be under {MAX_ARG} bytes, with no NUL")));
    }
    if argv[0].trim().is_empty() {
        return Err(UaError::invalid("argv[0] must name a program"));
    }
    Ok(argv.to_vec())
}

/// `argv` as one shell-quoted line, for display only.
pub(crate) fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if !a.is_empty() && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"_./:=@%+-,".contains(&b)) {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn insert(tx: &WriteTx<'_>, item_id: &str, c: &NewCommand, ts: &str) -> UaResult<()> {
    tx.execute(
        "INSERT INTO node_command (item_id, argv_json, owner_agent, owner_session, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![item_id, serde_json::to_string(&c.argv)?, c.owner_agent, c.owner_session, ts],
    )?;
    Ok(())
}

pub(crate) fn load(c: &Connection, item_id: &str) -> UaResult<Option<CommandRow>> {
    Ok(c.query_row(
        "SELECT item_id, argv_json, owner_agent, owner_session, fence_attempt, fence_token, exit_code, log_path \
         FROM node_command WHERE item_id = ?1",
        [item_id],
        |r| {
            let argv: String = r.get(1)?;
            Ok(CommandRow {
                item_id: r.get(0)?,
                argv: serde_json::from_str(&argv).unwrap_or_default(),
                owner_agent: r.get(2)?,
                owner_session: r.get(3)?,
                fence_attempt: r.get(4)?,
                fence_token: r.get(5)?,
                exit_code: r.get(6)?,
                log_path: r.get(7)?,
            })
        },
    )
    .optional()?)
}

/// A fresh fence for this claim: the payload's `command` object.
pub(crate) fn mint_fence(tx: &WriteTx<'_>, item_id: &str, attempt: i64) -> UaResult<Value> {
    let Some(row) = load(tx, item_id)? else {
        return Err(UaError::internal(format!("command item {item_id} has no command row")));
    };
    let token = uuid::Uuid::new_v4().simple().to_string();
    tx.execute(
        "UPDATE node_command SET fence_attempt = ?2, fence_token = ?3, updated_at = ?4 WHERE item_id = ?1",
        params![item_id, attempt, token, now()],
    )?;
    Ok(json!({ "argv": row.argv, "fence_token": token, "log_name": LOG_NAME }))
}

/// The receipt's token must be this attempt's fence token.
pub(crate) fn check_fence(tx: &WriteTx<'_>, item: &Item, token: &str) -> UaResult<()> {
    let Some(row) = load(tx, &item.id)? else {
        return Err(UaError::conflict(format!("command item {} has no command row", item.id)));
    };
    let ok = row.fence_attempt == Some(item.attempts)
        && row.fence_token.as_deref().is_some_and(|t| bool::from(t.as_bytes().ct_eq(token.as_bytes())));
    if ok {
        Ok(())
    } else {
        Err(UaError::conflict_code(
            "stale_fence",
            format!("receipt for {} does not hold the fence of attempt {}", item.id, item.attempts),
        ))
    }
}

/// Store the exit code and log path, and queue the owner's notice.
pub(crate) fn record_completion(tx: &WriteTx<'_>, item: &Item, status: &str, stored: &Value) -> UaResult<()> {
    let Some(row) = load(tx, &item.id)? else { return Ok(()) };
    let ts = now();
    let exit = stored["exit_code"].as_i64();
    let log = stored["log_path"].as_str();
    tx.execute(
        "UPDATE node_command SET exit_code = ?2, log_path = ?3, updated_at = ?4 WHERE item_id = ?1",
        params![item.id, exit, log, ts],
    )?;
    let duration =
        match (item.claimed_at.as_deref().and_then(ua_core::time::parse_ts), ua_core::time::parse_ts(&ts)) {
            (Some(a), Some(b)) => format!("{}s", (b.as_second() - a.as_second()).max(0)),
            _ => "unknown".into(),
        };
    let mut body = format!(
        "Supervised command {} on node {} {status} (exit code {}, after {duration}): {}",
        item.id,
        item.node,
        exit.map_or("none".to_string(), |e| e.to_string()),
        clip(&shell_join(&row.argv), 600),
    );
    if let Some(r) = stored["reason"].as_str() {
        body.push_str(&format!("\nReason: {}", clip(r, 300)));
    }
    if let Some(l) = log {
        body.push_str(&format!("\nLog on the node: {}", clip(l, 500)));
    }
    body.push_str(&format!("\nDetails: coordination_manage node_command_status item_id={}", item.id));
    tx.execute(
        "INSERT OR IGNORE INTO node_command_notice (item_id, attempt, terminal, owner_agent, body, task_id, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![item.id, item.attempts, status, row.owner_agent, clip(&body, 3500), item.task_id, ts],
    )?;
    Ok(())
}

/// Which owed notices [`deliver_pending`] retries.
#[derive(Debug, Clone, Copy)]
pub(crate) enum NoticeScope<'a> {
    /// One item's notices (after its receipt).
    Item(&'a str),
    /// Notices for one node's items (an idle claim, a node's sweep).
    Node(&'a str),
    /// Any node's (the `ua serve` sweep).
    All,
}

/// Send owed notices in `scope` (up to 50), each in its own transaction
/// under a stable message id, so a retry never sends twice. Returns how
/// many were delivered now.
pub(crate) fn deliver_pending(hub: &Hub, scope: NoticeScope<'_>) -> UaResult<usize> {
    let (item, node) = match scope {
        NoticeScope::Item(i) => (Some(i.to_string()), None),
        NoticeScope::Node(n) => (None, Some(n.to_string())),
        NoticeScope::All => (None, None),
    };
    let owed: Vec<(String, i64, String, String, String, Option<i64>)> = hub.db().read(|c| {
        let mut stmt = c.prepare(
            "SELECT item_id, attempt, terminal, owner_agent, body, task_id FROM node_command_notice \
             WHERE sent_at IS NULL AND (?1 IS NULL OR item_id = ?1) \
             AND (?2 IS NULL OR item_id IN (SELECT id FROM node_dispatch WHERE node = ?2)) \
             ORDER BY created_at LIMIT 50",
        )?;
        let rows = stmt
            .query_map(params![item, node], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })?;
    let mut sent = 0;
    for (item_id, attempt, terminal, owner, body, task_id) in owed {
        let mid = format!("node-command-{item_id}-{attempt}-{terminal}");
        // The owner's chosen session (node_command_adopt) first; label mail
        // when that session can no longer take it.
        let session: Option<String> = hub.db().read(|c| {
            Ok(c.query_row("SELECT owner_session FROM node_command WHERE item_id = ?1", [&item_id], |r| {
                r.get(0)
            })
            .optional()?
            .flatten())
        })?;
        let send = |to_session: Option<&str>| {
            hub.db().write(|tx| {
                let sent =
                    messaging::send_system(tx, NOTICE_SENDER, &owner, to_session, &mid, &body, task_id)?;
                // `mid` is hub-node's client id; the message's own id is the hub's.
                let message_id = sent["message_id"].as_str().unwrap_or(&mid).to_string();
                tx.execute(
                    "UPDATE node_command_notice SET sent_at = ?4, message_id = ?5, last_error = NULL \
                     WHERE item_id = ?1 AND attempt = ?2 AND terminal = ?3",
                    params![item_id, attempt, terminal, now(), message_id],
                )?;
                Ok(())
            })
        };
        let res = match session.as_deref() {
            Some(s) => send(Some(s)).or_else(|_| send(None)),
            None => send(None),
        };
        match res {
            Ok(()) => sent += 1,
            Err(e) => {
                let msg = clip(&e.to_string(), 300);
                hub.db().write(|tx| {
                    tx.execute(
                        "UPDATE node_command_notice SET last_error = ?4 \
                         WHERE item_id = ?1 AND attempt = ?2 AND terminal = ?3",
                        params![item_id, attempt, terminal, msg],
                    )?;
                    Ok(())
                })?;
            }
        }
    }
    Ok(sent)
}

// --- coordination_manage actions ------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StartArgs {
    /// Node to run on; it must allowlist `argv[0]`.
    pub node: String,
    /// The program and its arguments, 1-64 strings. Never a shell string.
    pub argv: Vec<String>,
    /// Working directory on the node.
    pub cwd: String,
    /// Wall-clock limit, 1-21600 seconds (default 3600).
    pub timeout_s: Option<i64>,
    /// Task the command is for.
    pub task_id: Option<i64>,
    /// Your own session to notify (default: your label's mailbox).
    pub session_id: Option<String>,
}

/// `coordination_manage(action="node_command_start")`.
pub(crate) async fn node_command_start(ctx: ToolCtx, a: StartArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "starting a supervised command")?;
    let argv = validate_argv(&a.argv)?;
    let session = a.session_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    if let Some(s) = session.clone() {
        let who2 = who.clone();
        ctx.hub.db().read_async(move |c| agents::own_session(c, &s, &who2, false).map(|_| ())).await?;
    }
    let prompt = clip(&format!("command: {}", shell_join(&argv)), 2000);
    let mut n =
        validate_new(&a.node, "command", &prompt, &a.cwd, None, None, None, a.timeout_s, a.task_id, None)?;
    n.command =
        Some(NewCommand { argv: argv.clone(), owner_agent: who.clone(), owner_session: session.clone() });
    let mut out = request_dispatch(&ctx.hub, &ctx.caller, n).await?;
    out["owner_agent"] = json!(who);
    out["owner_session"] = json!(session);
    out["argv"] = json!(argv);
    Ok(out)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusArgs {
    /// The command's item id.
    pub item_id: String,
}

/// `coordination_manage(action="node_command_status")`.
pub(crate) async fn node_command_status(ctx: ToolCtx, a: StatusArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "reading a supervised command")?;
    let id = check_item_id(&a.item_id)?;
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    ctx.hub
        .db()
        .read_async(move |c| {
            let hidden = || UaError::not_found(format!("no command item {id} visible to you"));
            let item = load_item(c, &id)?.ok_or_else(hidden)?;
            let cmd = load(c, &id)?.ok_or_else(hidden)?;
            if !(cmd.owner_agent == who
                || item.created_by == who
                || Authz::new(hub.cfg()).holds(
                    &caller,
                    &[Authority::Operator, Authority::LifecycleOperator],
                    ua_core::DEFAULT_ORG,
                ))
            {
                return Err(hidden());
            }
            let receipt = item.receipt().unwrap_or(Value::Null);
            Ok(json!({
                "item_id": item.id,
                "node": item.node,
                "status": item.status,
                "attempt": item.attempts,
                "argv": cmd.argv,
                "cwd": item.cwd,
                "owner_agent": cmd.owner_agent,
                "owner_session": cmd.owner_session,
                "exit_code": cmd.exit_code,
                "log_path": cmd.log_path,
                "log_capture": receipt.get("log_capture").cloned().unwrap_or(Value::Null),
                "reason": receipt.get("reason").cloned().unwrap_or(Value::Null),
                "task_id": item.task_id,
                "cancel_requested": item.cancel_requested,
                "queued_at": item.created_at,
                "claimed_at": item.claimed_at,
                "completed_at": item.completed_at,
            }))
        })
        .await
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdoptArgs {
    /// The command's item id.
    pub item_id: String,
    /// A session of the owner's label to notify instead (omit for label mail).
    pub session_id: Option<String>,
}

/// `coordination_manage(action="node_command_adopt")`: rebind the session an
/// unfinished command reports to. Never changes its attempt or fence.
pub(crate) async fn node_command_adopt(ctx: ToolCtx, a: AdoptArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "adopting a supervised command")?;
    let id = check_item_id(&a.item_id)?;
    let session = a.session_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            let hidden = || UaError::not_found(format!("no command item {id} visible to you"));
            let item = load_item(tx, &id)?.ok_or_else(hidden)?;
            let cmd = load(tx, &id)?.ok_or_else(hidden)?;
            let operator = Authz::new(hub.cfg()).holds(&caller, &[Authority::Operator], ua_core::DEFAULT_ORG);
            if cmd.owner_agent != who && !operator {
                return Err(UaError::denied(
                    "not_command_owner",
                    format!("only {:?} or an operator (a verified human) may adopt {id}", cmd.owner_agent),
                ));
            }
            if !matches!(item.status.as_str(), "queued" | "claimed") {
                return Err(UaError::conflict(format!(
                    "command {id} is {}; only an unfinished one is adopted",
                    item.status
                )));
            }
            if let Some(s) = &session {
                agents::own_session(tx, s, &cmd.owner_agent, false).map_err(|_| {
                    UaError::invalid(format!("session {s:?} does not belong to {:?}", cmd.owner_agent))
                })?;
            }
            tx.execute(
                "UPDATE node_command SET owner_session = ?2, updated_at = ?3 WHERE item_id = ?1",
                params![id, session, now()],
            )?;
            record(
                tx,
                "command_adopted",
                json!({
                    "item_id": id, "owner_agent": cmd.owner_agent, "from_session": cmd.owner_session,
                    "to_session": session, "actor": who,
                }),
                &who,
            )?;
            let mut v = load(tx, &id)?.map(|c| c.public()).unwrap_or(Value::Null);
            v["item_id"] = json!(id);
            v["status"] = json!(item.status);
            v["adopted"] = json!(true);
            let _ = cmd.item_id;
            Ok(v)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_is_quoted_for_display_only() {
        let argv = vec!["cargo".to_string(), "test".into(), "a b".into(), "it's".into()];
        assert_eq!(shell_join(&argv), "cargo test 'a b' 'it'\\''s'");
    }

    #[test]
    fn argv_bounds() {
        assert!(validate_argv(&[]).is_err());
        assert!(validate_argv(&[" ".into()]).is_err());
        assert!(validate_argv(&["ls".into(), "a\0b".into()]).is_err());
        assert!(validate_argv(&["ls".into()]).is_ok());
    }
}
