//! Claims: a node takes its oldest runnable item, under an attempt fence and
//! a lease, optionally through a durable claim operation.
//!
//! A claim operation (`claim_op = {id, mode, issued_at}`) lets a node that
//! lost the answer to a claim ask again under the same id: `mode = "claim"`
//! returns the same item (or the same no) while the binding still holds;
//! `mode = "reconcile"` never selects work and settles a pending operation.

use std::time::{Duration, Instant};

use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::WriteTx;

use super::{
    CHANNEL, Dedupe, Item, LEASE_GRACE_S, acceptance, after, before, cancel_item, check_item_id, clip,
    command, credentials, device_agent, emit, evidence_ref, items_where, load_item, now, owned_node, record,
    renew_run, require_org, run_gate, run_running, sweep_tx,
};
use crate::families::{governance, nodes};
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, tool};

/// How long a node may hold a claim request open.
pub const CLAIM_MAX_WAIT_S: f64 = 30.0;
const CLAIM_POLL: Duration = Duration::from_secs(1);

/// A claim operation older than this (by its `issued_at`) is not admitted.
const OP_MAX_AGE_S: i64 = 600;
/// How long a settled operation is kept, so a retry gets the same answer.
const OP_TOMBSTONE_S: i64 = 3600;
/// How long a bound operation is kept after its claim.
const OP_BOUND_S: i64 = 86_400;
const OP_MAX_PER_NODE: i64 = 5000;
const OP_CLEANUP_LIMIT: i64 = 50;

fn unix_now() -> i64 {
    jiff::Timestamp::now().as_second()
}

// --- claim operations -----------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct ClaimOp {
    pub id: String,
    pub reconcile: bool,
    pub issued_at: i64,
}

fn parse_op(v: &Value) -> UaResult<ClaimOp> {
    let Some(m) = v.as_object() else { return Err(UaError::invalid("claim_op must be an object")) };
    let unknown: Vec<&str> =
        m.keys().map(String::as_str).filter(|k| !["id", "mode", "issued_at"].contains(k)).collect();
    if !unknown.is_empty() {
        return Err(UaError::invalid(format!("claim_op has unknown field(s): {}", unknown.join(", "))));
    }
    let id = m.get("id").and_then(Value::as_str).unwrap_or("");
    if id.len() != 32 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(UaError::invalid("claim_op.id must be 32 lowercase hex characters"));
    }
    let reconcile = match m.get("mode").and_then(Value::as_str) {
        Some("claim") => false,
        Some("reconcile") => true,
        _ => return Err(UaError::invalid("claim_op.mode must be claim or reconcile")),
    };
    let issued_at = match m.get("issued_at") {
        Some(Value::Number(n)) if n.is_i64() => n.as_i64().unwrap_or(0),
        _ => return Err(UaError::invalid("claim_op.issued_at must be an integer (unix seconds)")),
    };
    if !(1_000_000_000..=9_999_999_999).contains(&issued_at) {
        return Err(UaError::invalid("claim_op.issued_at is out of range"));
    }
    Ok(ClaimOp { id: id.to_string(), reconcile, issued_at })
}

struct OpRow {
    identity: String,
    issued_at: i64,
    state: String,
    reason: Option<String>,
    item_id: Option<String>,
    attempt: Option<i64>,
    snapshot: Option<String>,
    fence_expires_at: i64,
}

fn load_op(tx: &WriteTx<'_>, org: &str, node: &str, id: &str) -> UaResult<Option<OpRow>> {
    Ok(tx
        .query_row(
            "SELECT identity, issued_at, state, reason, item_id, attempt, snapshot_json, fence_expires_at \
             FROM node_claim_ops WHERE node = ?1 AND op_id = ?2 AND org_id = ?3",
            params![node, id, org],
            |r| {
                Ok(OpRow {
                    identity: r.get(0)?,
                    issued_at: r.get(1)?,
                    state: r.get(2)?,
                    reason: r.get(3)?,
                    item_id: r.get(4)?,
                    attempt: r.get(5)?,
                    snapshot: r.get(6)?,
                    fence_expires_at: r.get(7)?,
                })
            },
        )
        .optional()?)
}

fn close_op(tx: &WriteTx<'_>, org: &str, node: &str, op: &OpRow, id: &str, reason: &str) -> UaResult<()> {
    let fence = op.fence_expires_at.max(unix_now() + OP_TOMBSTONE_S);
    tx.execute(
        "UPDATE node_claim_ops SET state = 'no_claim', reason = ?3, fence_expires_at = ?4, updated_at = ?5 \
         WHERE node = ?1 AND op_id = ?2 AND org_id = ?6 AND state = 'pending'",
        params![node, id, reason, fence, now(), org],
    )?;
    Ok(())
}

/// Why a bound operation's claim may no longer run, if it may not.
fn bound_refusal(tx: &WriteTx<'_>, org: &str, item_id: &str, attempt: i64) -> UaResult<Option<String>> {
    let Some(item) = load_item(tx, org, item_id)? else { return Ok(Some("item_missing".into())) };
    if item.receipt_json.is_some() {
        return Ok(Some("receipt_stored".into()));
    }
    if item.status != "claimed" {
        return Ok(Some(format!("item_{}", item.status)));
    }
    if item.attempts != attempt {
        return Ok(Some("attempt_superseded".into()));
    }
    if item.lease_expires_at.as_deref().is_none_or(|l| before(l, &now())) {
        return Ok(Some("lease_expired".into()));
    }
    if item.cancel_requested {
        return Ok(Some("cancel_requested".into()));
    }
    if run_gate(tx, &item)?.is_some() {
        return Ok(Some("run_not_live".into()));
    }
    Ok(None)
}

/// The answer for a settled (not pending) operation: its disposition, and
/// the stored snapshot while the binding still holds.
fn settled(tx: &WriteTx<'_>, org: &str, op_id: &str, row: &OpRow) -> UaResult<(Value, Option<Value>)> {
    let mut refusal = None;
    let mut item = None;
    if row.state == "bound"
        && let (Some(id), Some(attempt)) = (&row.item_id, row.attempt)
    {
        refusal = bound_refusal(tx, org, id, attempt)?;
        if refusal.is_none() {
            match row.snapshot.as_deref().and_then(|s| serde_json::from_str::<Value>(s).ok()) {
                Some(snap) => item = Some(snap),
                None => refusal = Some("snapshot_unreadable".into()),
            }
        }
    }
    let disposition = json!({
        "id": op_id,
        "state": row.state,
        "reason": refusal.clone().or(row.reason.clone()),
        "item_id": row.item_id,
        "attempt": row.attempt,
        "executable": row.state == "bound" && refusal.is_none(),
    });
    Ok((disposition, item))
}

/// Remove expired operations, keeping a bound one whose claim is still live.
/// A hub job (the sweep): it spans every organization, and an operation's
/// item is matched in the operation's own organization.
pub(crate) fn cleanup_ops(tx: &WriteTx<'_>, node: Option<&str>) -> UaResult<()> {
    tx.execute(
        "DELETE FROM node_claim_ops WHERE rowid IN (SELECT o.rowid FROM node_claim_ops o \
         WHERE o.fence_expires_at < ?1 AND (?2 IS NULL OR o.node = ?2) AND NOT (o.state = 'bound' AND EXISTS ( \
           SELECT 1 FROM node_dispatch d WHERE d.id = o.item_id AND d.org_id = o.org_id \
           AND d.status = 'claimed' AND d.attempts = o.attempt)) \
         LIMIT ?3)",
        params![unix_now(), node, OP_CLEANUP_LIMIT],
    )?;
    Ok(())
}

// --- one claim attempt ----------------------------------------------------------

pub(crate) struct ClaimOutcome {
    pub item: Option<Value>,
    pub disposition: Option<Value>,
    /// The operation is still pending: the node may ask again.
    pub pending: bool,
    /// The node's owner may not take work now. Returned as a value, not an
    /// error, so the sweep this claim ran still commits.
    pub refused: Option<governance::Blocked>,
}

/// What the node is told to run.
fn payload(hub: &Hub, item: &Item, lease: &str, attempt: i64, command: Option<Value>) -> Value {
    let mut p = json!({
        "item_id": item.id,
        "node": item.node,
        "agent": item.agent,
        "backend": item.backend,
        "prompt": item.prompt,
        "cwd": item.cwd,
        "cwd_realpath": item.cwd_realpath,
        "model": item.model,
        "permission_mode": item.permission_mode.clone().or_else(|| item.is_acp().then(|| "supervised".to_string())),
        "settings_source": item.settings_source.clone().unwrap_or_else(|| "legacy_supervised_default".into()),
        "timeout_s": item.timeout_s,
        "task_id": item.task_id,
        "run_id": item.run_id,
        "attempt": attempt,
        "lease_expires_at": lease,
        "session_id": item.session_id,
        "resume_session_id": Value::Null,
        "resume_source": Value::Null,
        "evidence_ref": evidence_ref(&item.node, &item.id),
        "hold_for_followups": item.run_id.is_none() && hub.cfg().is_human(&item.created_by),
    });
    if let Some(c) = command {
        p["command"] = c;
    }
    p
}

/// One claim by the node's own token: `org` is that token's organization,
/// so the node must be `org`'s and only `org`'s work is chosen. A node token
/// of another organization finds no such node.
fn claim_once(
    tx: &mut WriteTx<'_>,
    hub: &Hub,
    org: &str,
    agent: &str,
    node: &str,
    op: Option<&ClaimOp>,
    last: bool,
) -> UaResult<ClaimOutcome> {
    require_org(tx, org)?;
    let row = owned_node(tx, org, node, agent)?;
    let node = row.node.clone();
    sweep_tx(tx, Some(&node), "node-queue-claim")?;
    // Queued work whose run went away is cancelled before it can be chosen.
    for item in items_where(
        tx,
        "org_id = ?1 AND node = ?2 AND status = 'queued' AND run_id IS NOT NULL",
        params![org, node],
    )? {
        if run_gate(tx, &item)?.is_some() {
            cancel_item(tx, org, &item.id, "node-queue-claim", "dispatch run is no longer live")?;
        }
    }
    // A paused, terminated or retired owner claims nothing, whatever is
    // queued. Checked after the sweep above, which commits despite the
    // refusal; the queued items stay queued for a resume.
    // No task: only the agent half of the gate runs.
    if let Some(refused) = governance::claim_block(tx, org, Some(agent), None, false)? {
        return Ok(ClaimOutcome { item: None, disposition: None, pending: false, refused: Some(refused) });
    }

    if let Some(op) = op {
        let existing = load_op(tx, org, &node, &op.id)?;
        if let Some(e) = &existing
            && (e.identity != agent || e.issued_at != op.issued_at)
        {
            return Err(UaError::conflict("claim_op.id conflicts with an earlier claim operation"));
        }
        let ts = now();
        match existing {
            None if op.reconcile => {
                tx.execute(
                    "INSERT INTO node_claim_ops (node, op_id, identity, issued_at, state, reason, created_at, \
                     updated_at, fence_expires_at, org_id) \
                     VALUES (?1, ?2, ?3, ?4, 'no_claim', 'reconciled_unknown', ?5, ?5, ?6, ?7)",
                    params![
                        node,
                        op.id,
                        agent,
                        op.issued_at,
                        ts,
                        unix_now().max(op.issued_at) + OP_TOMBSTONE_S,
                        org
                    ],
                )?;
                return reconciled(tx, org, &node, op);
            }
            Some(e) if op.reconcile => {
                if e.state == "pending" {
                    close_op(tx, org, &node, &e, &op.id, "reconciled_pending")?;
                }
                return reconciled(tx, org, &node, op);
            }
            None => {
                if (unix_now() - op.issued_at).abs() > OP_MAX_AGE_S {
                    return Err(UaError::conflict(
                        "claim_op is outside its admission window; issue a new operation id",
                    ));
                }
                let held: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM node_claim_ops WHERE node = ?1 AND org_id = ?2",
                    params![node, org],
                    |r| r.get(0),
                )?;
                if held >= OP_MAX_PER_NODE {
                    return Err(UaError::conflict(
                        "claim operation store is at capacity for this node; retry later",
                    ));
                }
                tx.execute(
                    "INSERT INTO node_claim_ops (node, op_id, identity, issued_at, state, created_at, updated_at, \
                     fence_expires_at, org_id) VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?5, ?6, ?7)",
                    params![
                        node,
                        op.id,
                        agent,
                        op.issued_at,
                        ts,
                        unix_now().max(op.issued_at) + OP_TOMBSTONE_S,
                        org
                    ],
                )?;
            }
            Some(e) if e.state != "pending" => {
                let (disposition, item) = settled(tx, org, &op.id, &e)?;
                return Ok(ClaimOutcome {
                    item,
                    disposition: Some(disposition),
                    pending: false,
                    refused: None,
                });
            }
            Some(e) => {
                if unix_now() - e.issued_at > OP_MAX_AGE_S {
                    close_op(tx, org, &node, &e, &op.id, "operation_expired")?;
                    let e = load_op(tx, org, &node, &op.id)?
                        .ok_or_else(|| UaError::internal("claim op vanished"))?;
                    let (disposition, item) = settled(tx, org, &op.id, &e)?;
                    return Ok(ClaimOutcome {
                        item,
                        disposition: Some(disposition),
                        pending: false,
                        refused: None,
                    });
                }
            }
        }
    }

    // The oldest runnable item.
    let candidates = items_where(
        tx,
        "org_id = ?1 AND node = ?2 AND status = 'queued' AND cancel_requested = 0 \
         ORDER BY created_at, rowid LIMIT 50",
        params![org, node],
    )?;
    // Acceptance items run only for the node's live acceptance run; real
    // work waits while acceptance is required and not yet passed.
    let gate = acceptance::claim_gate(tx, hub.cfg(), &row)?;
    let mut chosen = None;
    for item in candidates {
        if !gate.admits(&item) || run_gate(tx, &item)?.is_some() {
            continue;
        }
        // A held task keeps its item queued: skipped now, claimable once the
        // hold is released.
        // The item's task is the item's organization's (the
        // `node_dispatch_org_parent` trigger).
        if let Some(task_id) = item.task_id
            && governance::claim_block(tx, org, None, Some(task_id), false)?.is_some()
        {
            continue;
        }
        chosen = Some(item);
        break;
    }
    let Some(item) = chosen else {
        let mut disposition = None;
        let mut pending = op.is_some();
        if let Some(op) = op {
            if last {
                if let Some(e) = load_op(tx, org, &node, &op.id)? {
                    close_op(tx, org, &node, &e, &op.id, "no_item")?;
                }
                pending = false;
            }
            let e = load_op(tx, org, &node, &op.id)?.ok_or_else(|| UaError::internal("claim op vanished"))?;
            disposition = Some(settled(tx, org, &op.id, &e)?.0);
        }
        return Ok(ClaimOutcome { item: None, disposition, pending, refused: None });
    };

    let attempt = item.attempts + 1;
    let ts = now();
    let lease = after(item.timeout_s + LEASE_GRACE_S);
    let n = tx.execute(
        "UPDATE node_dispatch SET status = 'claimed', attempts = ?2, claimed_at = ?3, lease_expires_at = ?4, \
         updated_at = ?3 WHERE id = ?1 AND org_id = ?6 AND status = 'queued' AND attempts = ?5",
        params![item.id, attempt, ts, lease, item.attempts, org],
    )?;
    if n != 1 {
        return Err(UaError::conflict(format!("node item {} changed during the claim; retry", item.id)));
    }
    run_running(tx, &item, &lease)?;
    let command =
        if item.backend == "command" { Some(command::mint_fence(tx, org, &item.id, attempt)?) } else { None };
    let snapshot = payload(hub, &item, &lease, attempt, command);
    let mut ev = json!({ "node": node, "item_id": item.id, "attempt": attempt });
    let mut disposition = None;
    if let Some(op) = op {
        tx.execute(
            "UPDATE node_claim_ops SET state = 'bound', item_id = ?3, attempt = ?4, snapshot_json = ?5, \
             fence_expires_at = ?6, updated_at = ?7 WHERE node = ?1 AND op_id = ?2 AND org_id = ?8",
            params![node, op.id, item.id, attempt, snapshot.to_string(), unix_now() + OP_BOUND_S, ts, org],
        )?;
        ev["claim_op"] = json!(op.id);
        disposition = Some(json!({
            "id": op.id, "state": "bound", "reason": Value::Null, "item_id": item.id,
            "attempt": attempt, "executable": true,
        }));
    }
    record(tx, org, "claim", ev, agent)?;
    Ok(ClaimOutcome { item: Some(snapshot), disposition, pending: false, refused: None })
}

fn reconciled(tx: &mut WriteTx<'_>, org: &str, node: &str, op: &ClaimOp) -> UaResult<ClaimOutcome> {
    let e = load_op(tx, org, node, &op.id)?.ok_or_else(|| UaError::internal("claim op vanished"))?;
    let (disposition, item) = settled(tx, org, &op.id, &e)?;
    record(
        tx,
        org,
        "claim_reconciled",
        json!({
            "node": node, "claim_op": op.id, "state": disposition["state"], "item_id": disposition["item_id"],
            "executable": disposition["executable"], "reason": disposition["reason"],
        }),
        &e.identity,
    )?;
    Ok(ClaimOutcome { item, disposition: Some(disposition), pending: false, refused: None })
}

// --- heartbeat hook -------------------------------------------------------------

/// Called inside a node heartbeat's transaction: renew the running item's
/// lease (and its run's), and return the claimed items the node must stop.
///
/// `org` is the node's organization (its token's): only that organization's
/// items are renewed or relayed.
pub(crate) fn on_heartbeat(
    tx: &mut WriteTx<'_>,
    org: &str,
    node: &str,
    agent: &str,
    running: Option<&str>,
    progress: Option<&str>,
) -> UaResult<Vec<String>> {
    // A malformed id names no item; the heartbeat itself still counts.
    if let Some(id) = running.and_then(|r| check_item_id(r).ok())
        && let Some(item) = load_item(tx, org, &id)?.filter(|i| i.node == node && i.status == "claimed")
    {
        let lease = after(item.timeout_s + LEASE_GRACE_S);
        tx.execute(
            "UPDATE node_dispatch SET lease_expires_at = ?2, updated_at = ?3 \
             WHERE id = ?1 AND org_id = ?4 AND status = 'claimed'",
            params![item.id, lease, now(), org],
        )?;
        renew_run(tx, &item, &lease)?;
        credentials::slide_idle(tx, org, &item.id, node)?;
        if !item.cancel_requested
            && let Some(why) = run_gate(tx, &item)?
        {
            tx.execute(
                "UPDATE node_dispatch SET cancel_requested = 1 WHERE id = ?1 AND org_id = ?2",
                params![item.id, org],
            )?;
            credentials::revoke_for_item(tx, org, &item.id, "cancelled", "node-queue")?;
            record(
                tx,
                org,
                "cancel_requested",
                json!({ "node": node, "item_id": item.id, "actor": "node-queue", "reason": why }),
                "node-queue",
            )?;
        }
        if let Some(p) = progress.map(str::trim).filter(|p| !p.is_empty()) {
            record(
                tx,
                org,
                "progress",
                json!({ "node": node, "item_id": item.id, "note": clip(p, 2000) }),
                agent,
            )?;
        }
    }
    let cancel: Vec<Item> = items_where(
        tx,
        "org_id = ?1 AND node = ?2 AND status = 'claimed' AND cancel_requested = 1",
        params![org, node],
    )?;
    for item in &cancel {
        // Once per claim, however many heartbeats it takes the node to stop.
        emit(
            tx,
            org,
            CHANNEL,
            json!({ "kind": "cancel_relayed", "node": node, "item_id": item.id }),
            agent,
            Some(Dedupe {
                named: format!("cancel_relayed:{}:{}", item.id, item.attempts),
                hub: format!("cancel_relayed:{}:{}", item.id, item.attempts),
            }),
        )?;
    }
    Ok(cancel.into_iter().map(|i| i.id).collect())
}

// --- the tool -------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimArgs {
    /// Your node's name.
    pub node: String,
    /// Seconds to wait for work, 0-30 (default 0).
    pub wait_s: Option<f64>,
    /// Durable claim operation `{id: 32 hex, mode: "claim"|"reconcile", issued_at: unix seconds}`.
    pub claim_op: Option<Value>,
}

async fn node_claim(ctx: ToolCtx, a: ClaimArgs) -> UaResult<Value> {
    let agent = device_agent(&ctx.caller)?;
    let wait = match a.wait_s {
        None => 0.0,
        Some(w) if w.is_finite() => w.clamp(0.0, CLAIM_MAX_WAIT_S),
        Some(_) => return Err(UaError::invalid("wait_s must be a number")),
    };
    let op = a.claim_op.as_ref().filter(|v| !v.is_null()).map(parse_op).transpose()?;
    let deadline = Instant::now() + Duration::from_secs_f64(wait);
    let mut first = true;
    loop {
        let last = op.as_ref().is_some_and(|o| o.reconcile) || Instant::now() >= deadline;
        // Between the first and last attempt, take the write lock only when
        // there is something queued for this node.
        if !first && !last {
            let (node, org) = (a.node.trim().to_string(), ctx.caller.org_id.clone());
            let queued: bool = ctx
                .hub
                .db()
                .read_async(move |c| {
                    Ok(c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM node_dispatch WHERE org_id = ?1 AND node = ?2 \
                         AND status = 'queued')",
                        params![org, node],
                        |r| r.get(0),
                    )?)
                })
                .await?;
            if !queued {
                tokio::time::sleep(CLAIM_POLL.min(deadline.saturating_duration_since(Instant::now()))).await;
                continue;
            }
        }
        first = false;
        let (hub, agent2, node, op2) = (ctx.hub.clone(), agent.clone(), a.node.clone(), op.clone());
        let org = ctx.caller.org_id.clone();
        let out = ctx
            .hub
            .db()
            .write_async(move |tx| claim_once(tx, &hub, &org, &agent2, &node, op2.as_ref(), last))
            .await?;
        if let Some(refused) = out.refused {
            return Err(refused.error());
        }
        let done = out.item.is_some() || !out.pending && op.is_some() || last;
        if done {
            if out.item.is_none() {
                // Nothing to run: retry any command notice still owed for
                // this node's items (the serve sweep covers every node).
                let (hub, node) = (ctx.hub.clone(), nodes::validate_node_name(&a.node)?);
                let _ = tokio::task::spawn_blocking(move || {
                    command::deliver_pending(&hub, command::NoticeScope::Node(&node))
                })
                .await;
            }
            let mut v = json!({ "item": out.item });
            if let Some(d) = out.disposition {
                v["claim_op"] = d;
            }
            return Ok(v);
        }
        tokio::time::sleep(CLAIM_POLL.min(deadline.saturating_duration_since(Instant::now()))).await;
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "node_claim",
            "Device plane: your node claims its oldest runnable work item, waiting up to wait_s (max 30) for one. \
             The claim adds one to the item's attempt and sets a lease of timeout_s + 300 seconds, renewed by \
             node_heartbeat(running=item_id). With claim_op the claim is durable: asking again under the same id \
             returns the same item while it is still runnable. Returns {item: payload|null, claim_op?}.",
            node_claim,
        )
        .family("nodes"),
    );
}
