//! What flows between a running item and the hub while it runs: the node's
//! ACP session events, operator follow-ups into the session, and permission
//! prompts the session raises for a human to answer.

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, WriteTx, ledger};

use super::{
    CHANNEL, Item, check_item_id, clip, device_agent, evidence_ref, is_operator, load_item, now, owned_node,
    record, run_gate, verified_caller,
};
use crate::approvals::{self, GateOutcome};
use crate::families::audit::rules::redact_secrets;
use crate::registry::{Registry, ToolCtx, tool};

const MAX_EVENTS: usize = 200;
const MAX_EVENT_BYTES: usize = 32_768;
const MAX_EVENT_TEXT: usize = 4000;
/// Open follow-ups one item may hold.
pub const FOLLOWUP_OPEN_MAX: i64 = 20;
const FOLLOWUP_BATCH: i64 = 20;
const MAX_ACKS: usize = 50;
const MAX_FOLLOWUP_CHARS: usize = 20_000;
/// The approval an agent's follow-up waits on: its own tool name, so a
/// reviewer never mistakes it for queuing new work (`node_dispatch`).
const FOLLOWUP_GATE: &str = "node_followup";
const MAX_OPTIONS: usize = 32;
const MAX_PERMISSION_BYTES: usize = 32_768;

/// `id, created_by, mode, body, seq, status, created_at, operator_authored, approval`.
type FollowupRow = (String, String, String, String, i64, String, String, i64, String);

/// Redact credential-shaped text in every string of `v`.
fn redact(v: &Value) -> Value {
    match v {
        Value::String(s) => json!(redact_secrets(s).0),
        Value::Array(a) => Value::Array(a.iter().map(redact).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), redact(v))).collect()),
        other => other.clone(),
    }
}

/// The item `id` of `node`, which must be claimed for live traffic.
fn live_item(c: &Connection, node: &str, id: &str, what: &str) -> UaResult<Item> {
    let Some(item) = load_item(c, id)?.filter(|i| i.node == node) else {
        return Err(UaError::not_found(format!("item {id} is not queued for node {node:?}")));
    };
    if item.status != "claimed" {
        return Err(UaError::conflict(format!(
            "item {id} is {}; {what} only for an in-flight claim",
            item.status
        )));
    }
    Ok(item)
}

// --- events ---------------------------------------------------------------------

fn turn_summary(
    tx: &mut WriteTx<'_>,
    item: &Item,
    agent: &str,
    kind: &str,
    turn: &str,
    ev: &Value,
) -> UaResult<()> {
    let Some(task_id) = item.task_id else { return Ok(()) };
    // Counts over this turn's recorded events.
    let rows: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT payload FROM event_log WHERE channel = ?1 AND json_extract(payload, '$.kind') = 'acp_event' \
             AND json_extract(payload, '$.item_id') = ?2 AND json_extract(payload, '$.turn_id') = ?3",
        )?;
        stmt.query_map(params![CHANNEL, item.id, turn], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    let (mut calls, mut updates, mut failed) = (0, 0, 0);
    for p in rows.iter().filter_map(|s| serde_json::from_str::<Value>(s).ok()) {
        match p["acp_kind"].as_str() {
            Some("tool_call") => calls += 1,
            Some("tool_call_update") => {
                updates += 1;
                if p["tool_call"]["status"] == "failed" || p["data"]["status"] == "failed" {
                    failed += 1;
                }
            }
            _ => {}
        }
    }
    let aborted = kind == "turn_aborted";
    let mut payload = json!({
        "kind": "turn_summary",
        "outcome": if aborted { "aborted" } else { "completed" },
        "node": item.node,
        "item_id": item.id,
        "task_id": task_id,
        "evidence_ref": evidence_ref(&item.node, &item.id),
        "turn_id": turn,
        "session_id": item.session_id,
        "stop_reason": ev.get("stop_reason").or_else(|| ev["data"].get("stop_reason")).cloned().unwrap_or(Value::Null),
        "events": rows.len(),
        "tool_calls": calls,
        "tool_call_updates": updates,
        "tool_calls_failed": failed,
    });
    if aborted {
        payload["abort_reason"] =
            ev.get("reason").or_else(|| ev["data"].get("reason")).cloned().unwrap_or(Value::Null);
    }
    ledger::append(
        tx,
        EventInput::new(CHANNEL, payload)
            .by(agent.to_string())
            .dedupe(format!("turn_summary:{}:{}:{turn}", item.node, item.id)),
    )?;
    Ok(())
}

fn record_events(
    tx: &mut WriteTx<'_>,
    agent: &str,
    node: &str,
    id: &str,
    events: &[Value],
) -> UaResult<Value> {
    let row = owned_node(tx, node, agent)?;
    let node = row.node;
    let mut item = live_item(tx, &node, id, "ACP events are accepted")?;
    let (mut recorded, mut dropped) = (0, 0);
    let mut kinds = Vec::new();
    for ev in events {
        let Some(m) = ev.as_object() else {
            dropped += 1;
            continue;
        };
        if serde_json::to_vec(ev).map_or(true, |b| b.len() > MAX_EVENT_BYTES) {
            dropped += 1;
            continue;
        }
        let kind = clip(m.get("kind").and_then(Value::as_str).unwrap_or("unknown"), 80);
        let data = m.get("data").cloned().unwrap_or(Value::Null);
        let turn = m
            .get("turn_id")
            .and_then(Value::as_str)
            .or_else(|| data.get("turn_id").and_then(Value::as_str))
            .map(|t| clip(t, 40));
        let session = m
            .get("session_id")
            .and_then(Value::as_str)
            .or_else(|| data.get("acp_session_id").and_then(Value::as_str))
            .map(|s| clip(s, 200));
        let payload = json!({
            "node": node,
            "item_id": id,
            "acp_kind": kind,
            "turn_id": turn,
            "session_id": session,
            "at": m.get("at").and_then(Value::as_str).map(|s| clip(s, 40)),
            "data": redact(&data),
            "text": m.get("text").and_then(Value::as_str).map(|t| redact_secrets(&clip(t, MAX_EVENT_TEXT)).0),
            "tool_call": redact(m.get("tool_call").unwrap_or(&Value::Null)),
            "plan": redact(m.get("plan").unwrap_or(&Value::Null)),
            "device_agent": agent,
        });
        record(tx, "acp_event", payload, agent)?;
        recorded += 1;
        kinds.push(kind.clone());
        match kind.as_str() {
            "session_open" | "session_ready" => {
                if let Some(s) = &session
                    && item.session_id.is_none()
                {
                    tx.execute(
                        "UPDATE node_dispatch SET session_id = ?2, updated_at = ?3 \
                         WHERE id = ?1 AND session_id IS NULL AND status = 'claimed'",
                        params![id, s, now()],
                    )?;
                    item.session_id = Some(s.clone());
                }
            }
            "followup_delivered" | "followup_dropped" => {
                apply_followup_event(tx, id, &kind, &data, agent)?;
            }
            "turn_end" | "turn_aborted" => {
                if let Some(t) = &turn {
                    turn_summary(tx, &item, agent, &kind, t, ev)?;
                }
            }
            _ => {}
        }
    }
    super::acceptance::on_events(tx, &item, &kinds)?;
    Ok(json!({ "recorded": recorded, "dropped": dropped }))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsArgs {
    /// Your node's name.
    pub node: String,
    /// The claimed item.
    pub item_id: String,
    /// Up to 200 event objects `{kind, turn_id?, session_id?, at?, data?, text?, tool_call?, plan?}`,
    /// each at most 32 KB as JSON. Strings are redacted before they are stored.
    pub events: Vec<Value>,
}

async fn node_events(ctx: ToolCtx, a: EventsArgs) -> UaResult<Value> {
    let agent = device_agent(&ctx.caller)?;
    let id = check_item_id(&a.item_id)?;
    if a.events.len() > MAX_EVENTS {
        return Err(UaError::invalid(format!("events exceeds {MAX_EVENTS} per call")));
    }
    ctx.hub.db().write_async(move |tx| record_events(tx, &agent, &a.node, &id, &a.events)).await
}

// --- follow-ups -----------------------------------------------------------------

fn valid_followup_id(id: &str) -> bool {
    id.len() == 19 && id.starts_with("nf-") && id[3..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn apply_followup_event(
    tx: &mut WriteTx<'_>,
    item_id: &str,
    kind: &str,
    data: &Value,
    agent: &str,
) -> UaResult<()> {
    let Some(fid) = data.get("followup_id").and_then(Value::as_str).filter(|f| valid_followup_id(f)) else {
        return Ok(());
    };
    let ts = now();
    let n = if kind == "followup_delivered" {
        tx.execute(
            "UPDATE node_followups SET status = 'delivered', delivered_at = ?3, turn_id = ?4, path = ?5, updated_at = ?3 \
             WHERE id = ?1 AND item_id = ?2 AND status IN ('queued','claimed')",
            params![
                fid,
                item_id,
                ts,
                data.get("turn_id").and_then(Value::as_str).map(|s| clip(s, 40)),
                data.get("path").and_then(Value::as_str).map(|s| clip(s, 40)),
            ],
        )?
    } else {
        tx.execute(
            "UPDATE node_followups SET status = 'dropped', reason = ?3, updated_at = ?4 \
             WHERE id = ?1 AND item_id = ?2 AND status IN ('queued','claimed')",
            params![fid, item_id, data.get("reason").and_then(Value::as_str).map(|s| clip(s, 200)), ts],
        )?
    };
    if n == 1 && kind == "followup_dropped" {
        record(
            tx,
            "followup_dropped",
            json!({ "item_id": item_id, "followup_id": fid, "by": "node" }),
            agent,
        )?;
    }
    Ok(())
}

/// Drop every open follow-up of an item that ended. A claimed one was
/// handed to the node but never confirmed.
pub(crate) fn drop_open_followups(tx: &mut WriteTx<'_>, item_id: &str, reason: &str) -> UaResult<()> {
    let open: Vec<(String, String)> = {
        let mut stmt = tx.prepare(
            "SELECT id, status FROM node_followups WHERE item_id = ?1 AND status IN ('queued','claimed') ORDER BY seq",
        )?;
        stmt.query_map([item_id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
    };
    let ts = now();
    for (fid, status) in open {
        let why = if status == "claimed" { "delivery_unconfirmed" } else { reason };
        tx.execute(
            "UPDATE node_followups SET status = 'dropped', reason = ?2, updated_at = ?3 WHERE id = ?1",
            params![fid, why, ts],
        )?;
        record(
            tx,
            "followup_dropped",
            json!({ "item_id": item_id, "followup_id": fid, "reason": why }),
            "node-queue",
        )?;
    }
    Ok(())
}

pub(crate) fn followups_of(c: &Connection, item_id: &str) -> UaResult<Value> {
    let mut stmt = c.prepare(
        "SELECT id, seq, mode, status, created_by, created_at, delivered_at, reason, operator_authored, approval \
         FROM node_followups WHERE item_id = ?1 ORDER BY seq",
    )?;
    let rows = stmt
        .query_map([item_id], |r| {
            Ok(json!({
                "followup_id": r.get::<_, String>(0)?,
                "seq": r.get::<_, i64>(1)?,
                "mode": r.get::<_, String>(2)?,
                "status": r.get::<_, String>(3)?,
                "created_by": r.get::<_, String>(4)?,
                "created_at": r.get::<_, String>(5)?,
                "delivered_at": r.get::<_, Option<String>>(6)?,
                "reason": r.get::<_, Option<String>>(7)?,
                "operator_authored": r.get::<_, i64>(8)? != 0,
                "approval": r.get::<_, String>(9)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!(rows))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PollArgs {
    /// Your node's name.
    pub node: String,
    /// The claimed item.
    pub item_id: String,
    /// Follow-up ids you received and will deliver (at most 50); they are not sent again.
    #[serde(default)]
    pub ack: Vec<String>,
}

async fn node_followups(ctx: ToolCtx, a: PollArgs) -> UaResult<Value> {
    let agent = device_agent(&ctx.caller)?;
    let id = check_item_id(&a.item_id)?;
    if a.ack.len() > MAX_ACKS || a.ack.iter().any(|f| !valid_followup_id(f)) {
        return Err(UaError::invalid(format!("ack must be at most {MAX_ACKS} follow-up ids (nf- + 16 hex)")));
    }
    ctx.hub
        .db()
        .write_async(move |tx| {
            let row = owned_node(tx, &a.node, &agent)?;
            live_item(tx, &row.node, &id, "follow-ups are served")?;
            let ts = now();
            for f in &a.ack {
                tx.execute(
                    "UPDATE node_followups SET status = 'claimed', claimed_at = ?3, updated_at = ?3 \
                     WHERE id = ?1 AND item_id = ?2 AND status = 'queued'",
                    params![f, id, ts],
                )?;
            }
            let mut stmt = tx.prepare(
                "SELECT id, seq, mode, body FROM node_followups WHERE item_id = ?1 AND status = 'queued' \
                 ORDER BY seq LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(params![id, FOLLOWUP_BATCH], |r| {
                    Ok(json!({
                        "id": r.get::<_, String>(0)?,
                        "seq": r.get::<_, i64>(1)?,
                        "mode": r.get::<_, String>(2)?,
                        "body": r.get::<_, String>(3)?,
                    }))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({ "item_id": id, "followups": rows }))
        })
        .await
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FollowupArgs {
    /// The running ACP item.
    pub item_id: String,
    /// `queue` (delivered after the current turn) or `steer` (into the current turn; claimed items only).
    pub mode: String,
    /// The text, 1-20000 characters.
    pub body: String,
    /// Client key, 8-128 of `[A-Za-z0-9_.:-]`: a retry with the same key returns the first follow-up.
    pub idempotency_key: String,
}

fn followup_admission(c: &Connection, item: &Item, mode: &str) -> UaResult<()> {
    if !item.is_acp() {
        return Err(UaError::conflict(format!(
            "item {} runs {}; follow-ups need an acp:* session",
            item.id, item.backend
        )));
    }
    if !matches!(item.status.as_str(), "queued" | "claimed") {
        return Err(UaError::conflict(format!("item {} is {}", item.id, item.status)));
    }
    if item.cancel_requested {
        return Err(UaError::conflict(format!("item {} is being cancelled", item.id)));
    }
    if mode == "steer" && item.status != "claimed" {
        return Err(UaError::conflict("steer needs a running session; use mode=queue"));
    }
    let node = super::load_node(c, &item.node)?;
    if !node.as_ref().is_some_and(|n| n.has_feature("acp_followups")) {
        return Err(UaError::conflict_code(
            "node_feature_missing",
            format!("node {:?} does not take follow-ups (acp_followups)", item.node),
        ));
    }
    let open: i64 = c.query_row(
        "SELECT COUNT(*) FROM node_followups WHERE item_id = ?1 AND status IN ('queued','claimed')",
        [&item.id],
        |r| r.get(0),
    )?;
    if open >= FOLLOWUP_OPEN_MAX {
        return Err(UaError::conflict_code(
            "followup_limit",
            format!("item {} already holds {open} open follow-ups; wait for delivery", item.id),
        ));
    }
    Ok(())
}

async fn node_followup(ctx: ToolCtx, a: FollowupArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "sending a follow-up")?;
    let id = check_item_id(&a.item_id)?;
    let mode = a.mode.trim().to_string();
    if !matches!(mode.as_str(), "queue" | "steer") {
        return Err(UaError::invalid("mode must be queue or steer"));
    }
    let body = a.body.clone();
    if body.trim().is_empty() || body.chars().count() > MAX_FOLLOWUP_CHARS {
        return Err(UaError::invalid(format!("body must be 1-{MAX_FOLLOWUP_CHARS} characters")));
    }
    let key = a.idempotency_key.trim().to_string();
    if !(8..=128).contains(&key.len())
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
    {
        return Err(UaError::invalid("idempotency_key must be 8-128 of [A-Za-z0-9_.:-]"));
    }
    // Only a human writes without a gate; an agent's follow-up is new
    // instructions to a running session and needs its own approval.
    let operator = ctx.caller.is_human() || ctx.hub.cfg().is_human(&who);
    if !operator
        && let Err(refusal) = crate::policy::check_prod_action(ctx.hub.cfg(), &ctx.caller, FOLLOWUP_GATE)
    {
        return Err(refusal.error);
    }
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let Some(item) = load_item(tx, &id)? else {
                return Err(UaError::not_found(format!("node item {id} does not exist")));
            };
            if !operator {
                if !(item.created_by == who || item.agent == who || is_operator(&hub, &caller, &who)) {
                    return Err(UaError::denied(
                        "not_item_owner",
                        format!("{who:?} did not request {id}; only its requester or an operator sends follow-ups"),
                    ));
                }
                if let Some(t) = item.task_id {
                    let holder: Option<Option<String>> = tx
                        .query_row("SELECT claimed_by FROM tasks WHERE id = ?1", [t], |r| r.get(0))
                        .optional()?;
                    if let Some(Some(h)) = holder
                        && h != who
                    {
                        return Err(UaError::denied(
                            "task_claimed_elsewhere",
                            format!("task {t} is claimed by {h:?}"),
                        ));
                    }
                }
            }
            let existing: Option<FollowupRow> = tx
                .query_row(
                    "SELECT id, created_by, mode, body, seq, status, created_at, operator_authored, approval \
                     FROM node_followups WHERE item_id = ?1 AND idempotency_key = ?2",
                    params![id, key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)),
                )
                .optional()?;
            if let Some((fid, by, m, b, seq, status, at, op, approval)) = existing {
                if by != who {
                    return Err(UaError::conflict("idempotency_key was used by another identity"));
                }
                if m != mode || b != body {
                    return Err(UaError::conflict("idempotency_key was used for a different follow-up"));
                }
                return Ok(Ok(json!({
                    "followup_id": fid, "item_id": id, "seq": seq, "mode": m, "status": status, "created_by": by,
                    "created_at": at, "operator_authored": op != 0, "approval": approval, "duplicate": true,
                })));
            }
            followup_admission(tx, &item, &mode)?;
            let approval = if operator {
                "not_required_operator"
            } else {
                let payload = json!({
                    "summary": format!("follow-up ({mode}) into {id} on {}", item.node),
                    "node": item.node,
                    "backend": item.backend,
                    "cwd": item.cwd,
                    "task_id": item.task_id,
                    "run_id": item.run_id,
                    "followup": { "item_id": id, "mode": mode, "idempotency_key": key },
                    "prompt": body,
                    "action": "dispatch",
                    "agent": who,
                });
                match approvals::gate(tx, hub.cfg(), &caller, FOLLOWUP_GATE, &payload)? {
                    GateOutcome::Pass { .. } => "gate_passed",
                    GateOutcome::Pending { approval_id } => return Ok(Err(approval_id)),
                    GateOutcome::Denied { approval_id, reason } => {
                        return Err(UaError::denied(
                            "approval_denied",
                            format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                        ));
                    }
                }
            };
            let seq: i64 = tx.query_row(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM node_followups WHERE item_id = ?1",
                [&id],
                |r| r.get(0),
            )?;
            let fid = format!("nf-{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);
            let ts = now();
            tx.execute(
                "INSERT INTO node_followups (id, item_id, seq, mode, body, idempotency_key, status, created_by, \
                 created_at, operator_authored, approval, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', ?7, ?8, ?9, ?10, ?8)",
                params![fid, id, seq, mode, body, key, who, ts, operator, approval],
            )?;
            record(
                tx,
                "followup_queued",
                json!({
                    "node": item.node, "item_id": id, "followup_id": fid, "seq": seq, "mode": mode,
                    "status": "queued", "operator_authored": operator, "approval": approval,
                    "text": redact_secrets(&clip(&body, MAX_EVENT_TEXT)).0,
                }),
                &who,
            )?;
            Ok(Ok(json!({
                "followup_id": fid, "item_id": id, "seq": seq, "mode": mode, "status": "queued", "created_by": who,
                "created_at": ts, "operator_authored": operator, "approval": approval, "duplicate": false,
            })))
        })
        .await?;
    out.map_err(|approval_id| UaError::ApprovalRequired { tool: FOLLOWUP_GATE.into(), approval_id })
}

// --- permission prompts ---------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PermissionArgs {
    /// Your node's name.
    pub node: String,
    /// The claimed item whose session asks.
    pub item_id: String,
    /// The ACP session id, at most 200 characters.
    pub session_id: String,
    /// The tool call the session wants to make (a non-empty object).
    pub tool_call: Value,
    /// Up to 32 options `{optionId, name, kind}` the session offers.
    #[serde(default)]
    pub options: Vec<Value>,
}

fn permission_block(c: &Connection, item: &Item) -> UaResult<Option<String>> {
    if item.status != "claimed" {
        return Ok(Some(format!("item_{}", item.status)));
    }
    if item.cancel_requested {
        return Ok(Some("cancel_requested".into()));
    }
    Ok(run_gate(c, item)?.map(str::to_string))
}

async fn node_permission(ctx: ToolCtx, a: PermissionArgs) -> UaResult<Value> {
    let agent = device_agent(&ctx.caller)?;
    // A pass approved earlier carries no call the caller may no longer make.
    if let Err(refusal) = crate::policy::check_prod_action(ctx.hub.cfg(), &ctx.caller, "acp_permission") {
        return Err(refusal.error);
    }
    let id = check_item_id(&a.item_id)?;
    let session = redact_secrets(a.session_id.trim()).0;
    if session.is_empty() || session.chars().count() > 200 {
        return Err(UaError::invalid("session_id must be 1-200 characters"));
    }
    let Some(tool_call) = a.tool_call.as_object().filter(|m| !m.is_empty()) else {
        return Err(UaError::invalid("tool_call must be a non-empty object"));
    };
    if a.options.len() > MAX_OPTIONS {
        return Err(UaError::invalid(format!("options must hold at most {MAX_OPTIONS} entries")));
    }
    let mut options = Vec::new();
    for o in &a.options {
        let Some(m) = o.as_object() else { return Err(UaError::invalid("each option must be an object")) };
        let field = |k: &str, max: usize| -> Value {
            m.get(k).and_then(Value::as_str).map_or(Value::Null, |s| json!(clip(&redact_secrets(s).0, max)))
        };
        options.push(json!({ "optionId": field("optionId", 120), "name": field("name", 200), "kind": field("kind", 60) }));
    }
    let tool_call = redact(&Value::Object(tool_call.clone()));
    let node = a.node.clone();
    let canonical_base = (tool_call, options);
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            let row = owned_node(tx, &node, &agent)?;
            let Some(item) = load_item(tx, &id)?.filter(|i| i.node == row.node) else {
                return Err(UaError::not_found(format!("item {id} is not queued for node {:?}", row.node)));
            };
            if let Some(why) = permission_block(tx, &item)? {
                return Ok(json!({ "status": "denied", "reason": why }));
            }
            let (tool_call, options) = &canonical_base;
            // Nothing an approval could select: do not ask a human for it.
            if !options.iter().any(|o| o["kind"].as_str().is_some_and(|k| k.starts_with("allow"))) {
                return Ok(json!({ "status": "denied", "reason": "no_allow_option" }));
            }
            let canonical = json!({
                "node": row.node, "item_id": id, "session_id": session, "tool_call": tool_call, "options": options,
            });
            if serde_json::to_vec(&canonical)?.len() > MAX_PERMISSION_BYTES {
                return Err(UaError::invalid(format!("the permission request exceeds {MAX_PERMISSION_BYTES} bytes")));
            }
            let base = json!({ "node": row.node, "item_id": id, "session_id": session, "approval_id": Value::Null });
            match approvals::gate(tx, hub.cfg(), &caller, "acp_permission", &canonical)? {
                GateOutcome::Pass { approval_id } => {
                    let mut ev = base.clone();
                    ev["approval_id"] = json!(approval_id);
                    ev["decision"] = json!("approved");
                    record(tx, "acp_permission", ev, &agent)?;
                    Ok(json!({
                        "status": "approved",
                        "approval_id": approval_id,
                        "option_id": allow_option(options),
                    }))
                }
                GateOutcome::Pending { approval_id } => Ok(json!({ "status": "pending", "approval_id": approval_id })),
                GateOutcome::Denied { approval_id, reason } => {
                    let mut ev = base.clone();
                    ev["approval_id"] = json!(approval_id);
                    ev["decision"] = json!("denied");
                    record(tx, "acp_permission", ev, &agent)?;
                    Ok(json!({ "status": "denied", "approval_id": approval_id, "reason": reason }))
                }
            }
        })
        .await
}

/// The option an approval selects: the first `allow_once`, else the first
/// `allow*` kind.
fn allow_option(options: &[Value]) -> Value {
    let pick = |pred: &dyn Fn(&str) -> bool| {
        options.iter().find(|o| o["kind"].as_str().is_some_and(pred)).map(|o| o["optionId"].clone())
    };
    pick(&|k| k == "allow_once").or_else(|| pick(&|k| k.starts_with("allow"))).unwrap_or(Value::Null)
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "node_events",
            "Device plane: record up to 200 ACP session events for your claimed item (redacted, at most 32 KB \
             each). session_open binds the item's session id, followup_delivered/followup_dropped settle \
             follow-ups, and turn_end/turn_aborted on a task-linked item write one turn summary. Returns \
             {recorded, dropped}.",
            node_events,
        )
        .family("nodes"),
    );
    r.add(
        tool(
            "node_followups",
            "Device plane: fetch queued follow-ups for your claimed ACP item (up to 20, by seq). Acknowledge the \
             ids you will deliver in `ack`; unacknowledged ones are sent again. Returns {item_id, followups: \
             [{id, seq, mode, body}]}.",
            node_followups,
        )
        .family("nodes"),
    );
    r.add(
        tool(
            "node_followup",
            "Send a follow-up into a running ACP item's session: mode queue (after the current turn) or steer \
             (into it). A human's follow-up needs no approval; an agent (the item's requester) needs a one-time \
             human approval (tool node_followup) of the exact text. Idempotent by idempotency_key. Returns \
             {followup_id, seq, status, approval, duplicate}.",
            node_followup,
        )
        .gates_in_handler()
        .family("nodes"),
    );
    r.add(
        tool(
            "node_permission",
            "Device plane: relay an ACP session's permission prompt for a human decision. Ask again with the \
             identical request until it is decided. A prompt with no allow* option is denied \
             (no_allow_option) without asking anyone. Returns {status: pending|approved|denied, approval_id, \
             option_id?, reason?}; an approval is used once.",
            node_permission,
        )
        .gates_in_handler()
        .family("nodes"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allow_option_prefers_allow_once() {
        let opts = vec![
            json!({ "optionId": "a", "kind": "allow_always" }),
            json!({ "optionId": "b", "kind": "allow_once" }),
            json!({ "optionId": "c", "kind": "reject_once" }),
        ];
        assert_eq!(allow_option(&opts), json!("b"));
        assert_eq!(allow_option(&opts[..1]), json!("a"));
        assert_eq!(allow_option(&opts[2..]), Value::Null);
    }

    #[test]
    fn strings_are_redacted_deeply() {
        // Same GitHub token shape `redact_secrets` matches: `gh[pousr]_` and
        // 36 alphanumerics, replaced by `[REDACTED_SECRET]`.
        let token = "ghp_FakeToken0Example1Mixed2Case3Abc4567";
        let v = redact(&json!({ "a": [format!("token {token}")] }));
        assert!(!v.to_string().contains(token), "{v}");
        assert_eq!(v["a"][0], "token [REDACTED_SECRET]");
    }
}
