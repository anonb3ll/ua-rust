//! Device acceptance: a harmless job a node passes before it takes real work.
//!
//! A run queues two items with the built-in `acceptance` backend (no model,
//! no harness) through the ordinary queue, so the node reaches them through
//! the same claim, heartbeat, events and receipt paths as real work:
//!
//! - `launch`: the node claimed the `complete` job and reported an
//!   `acceptance_launch` event;
//! - `progress`: it reported progress steps 1..3, in order, after the launch;
//! - `receipt`: it posted a `finished` receipt whose text carries the output
//!   digest the hub recomputes from the job spec;
//! - `cancel_confirmed`: the `cancel` job, which the hub cancels as soon as it
//!   reports progress, stopped mid-run (`killed`, reason `cancelled_by_hub`)
//!   with a confirmed `acceptance_stopped` event after the cancel relay;
//! - `revocation`: the ownership gate every claim, heartbeat and receipt
//!   passes refuses this node to a foreign agent and once it is retired
//!   (probed against the stored row; nothing is written).
//!
//! A run is `pending`, then `accepted` or `failed`. Passing every check is the
//! node's own report, so it leaves the run `pending` until a lifecycle
//! operator who is not the node's agent attests it
//! (`node_acceptance_attest`) with a reference to independent evidence. A
//! run still pending [`DEADLINE_S`] after it started fails `timed_out`.
//!
//! With `node_require_acceptance` on, a node takes no work but its live
//! acceptance run's two items until its latest run is accepted: the enqueue
//! paths refuse it (`node_not_accepted`) and `node_claim` skips it.
//!
//! The outcome is kept in `node_acceptance` (one row per node, the latest
//! run). Events go on `agent.node`: `acceptance_started`,
//! `acceptance_failed`, `acceptance_attested`.

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::time::parse_ts;
use ua_core::{Config, UaError, UaResult};
use ua_store::{SchemaPart, WriteTx};

use super::{
    Item, NodeRow, TERMINAL, cancel_item, insert_item, is_operator, load_item, load_node, now, record,
    validate_new, verified_caller,
};
use crate::families::nodes;
use crate::hub::Hub;
use crate::registry::ToolCtx;

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "node_acceptance.v1",
    sql: "
CREATE TABLE IF NOT EXISTS node_acceptance (
    node TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    agent TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','accepted','failed')),
    complete_item_id TEXT,
    cancel_item_id TEXT,
    checks_json TEXT NOT NULL DEFAULT '{}',
    reason TEXT,
    code_sha TEXT,
    started_by TEXT NOT NULL,
    started_at TEXT NOT NULL,
    evaluated_at TEXT,
    accepted_at TEXT,
    attested_by TEXT,
    attestation_ref TEXT,
    updated_at TEXT NOT NULL
);
",
};

pub const BACKEND: &str = "acceptance";
pub const CHECKS: [&str; 5] = ["launch", "progress", "receipt", "cancel_confirmed", "revocation"];
/// A run not accepted this long after it started fails `timed_out`.
pub const DEADLINE_S: i64 = 900;
const COMPLETE_STEPS: i64 = 3;
const COMPLETE_TIMEOUT_S: i64 = 120;
const CANCEL_TIMEOUT_S: i64 = 300;
/// Hub-internal attribution for the cancel the run issues itself.
pub const ACTOR: &str = "node-acceptance";
/// The identity the revocation probe presents; never a real owner.
const PROBE_IDENTITY: &str = "ua-acceptance-probe";
const MAX_EVIDENCE: usize = 1000;

const PASS: &str = "pass";
const FAIL: &str = "fail";
const PENDING: &str = "pending";

fn check(status: &str, detail: impl Into<String>) -> Value {
    let detail: String = detail.into();
    json!({ "status": status, "detail": detail.chars().take(300).collect::<String>() })
}

fn status_of(checks: &Map<String, Value>, name: &str) -> String {
    checks.get(name).and_then(|c| c["status"].as_str()).unwrap_or("").to_string()
}

fn all_pass(checks: &Map<String, Value>) -> bool {
    CHECKS.iter().all(|c| status_of(checks, c) == PASS)
}

/// The exact bytes a `complete` job writes, so the hub can check the digest.
fn expected_output(run: &str, steps: i64) -> Vec<u8> {
    (1..=steps)
        .map(|i| format!("ua-node acceptance {run} step {i}/{steps}\n"))
        .collect::<String>()
        .into_bytes()
}

/// The receipt text a `complete` job reports for `data`.
pub fn receipt_text(run: &str) -> String {
    let data = expected_output(run, COMPLETE_STEPS);
    format!(
        "acceptance:complete run={run} bytes={} sha256={}",
        data.len(),
        hex::encode(Sha256::digest(&data))
    )
}

// --- the stored row -------------------------------------------------------------

#[derive(Debug, Clone)]
struct Row {
    node: String,
    run_id: String,
    agent: String,
    state: String,
    complete_item_id: Option<String>,
    cancel_item_id: Option<String>,
    checks: Map<String, Value>,
    reason: Option<String>,
    code_sha: Option<String>,
    started_by: String,
    started_at: String,
    evaluated_at: Option<String>,
    accepted_at: Option<String>,
    attested_by: Option<String>,
    attestation_ref: Option<String>,
}

const ROW_COLS: &str = "node, run_id, agent, state, complete_item_id, cancel_item_id, checks_json, reason, code_sha, \
    started_by, started_at, evaluated_at, accepted_at, attested_by, attestation_ref";

fn row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let checks: String = r.get(6)?;
    Ok(Row {
        node: r.get(0)?,
        run_id: r.get(1)?,
        agent: r.get(2)?,
        state: r.get(3)?,
        complete_item_id: r.get(4)?,
        cancel_item_id: r.get(5)?,
        checks: serde_json::from_str::<Value>(&checks)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default(),
        reason: r.get(7)?,
        code_sha: r.get(8)?,
        started_by: r.get(9)?,
        started_at: r.get(10)?,
        evaluated_at: r.get(11)?,
        accepted_at: r.get(12)?,
        attested_by: r.get(13)?,
        attestation_ref: r.get(14)?,
    })
}

fn load_row(c: &Connection, node: &str) -> UaResult<Option<Row>> {
    Ok(c.query_row(&format!("SELECT {ROW_COLS} FROM node_acceptance WHERE node = ?1"), [node], row_from)
        .optional()?)
}

fn age_s(ts: &str) -> Option<i64> {
    parse_ts(ts).map(|t| (jiff::Timestamp::now() - t).as_secs())
}

fn past_deadline(row: &Row) -> bool {
    age_s(&row.started_at).is_some_and(|a| a > DEADLINE_S)
}

fn accepted(row: Option<&Row>, agent: &str) -> bool {
    row.is_some_and(|r| {
        r.state == "accepted" && r.agent == agent && r.attested_by.is_some() && r.attestation_ref.is_some()
    })
}

fn public(row: &Row, cfg: &Config) -> Value {
    json!({
        "node": row.node,
        "run_id": row.run_id,
        "agent": row.agent,
        "state": row.state,
        "reason": row.reason,
        "checks": row.checks,
        "complete_item_id": row.complete_item_id,
        "cancel_item_id": row.cancel_item_id,
        "code_sha": row.code_sha,
        "started_by": row.started_by,
        "started_at": row.started_at,
        "evaluated_at": row.evaluated_at,
        "accepted_at": row.accepted_at,
        "required": cfg.node_require_acceptance,
        "diagnostics_passed": all_pass(&row.checks),
        "evidence_trust": "node_self_report",
        "attested_by": row.attested_by,
        "attestation_ref": row.attestation_ref,
    })
}

fn not_run(node: &str, cfg: &Config) -> Value {
    json!({
        "node": node,
        "state": "not_run",
        "reason": "no acceptance run yet",
        "checks": {},
        "required": cfg.node_require_acceptance,
    })
}

// --- evaluation -----------------------------------------------------------------

/// One reported event of an acceptance item, in ledger order.
struct Ev {
    kind: String,
    data: Value,
}

fn item_events(c: &Connection, item_id: Option<&str>) -> UaResult<Vec<Ev>> {
    let Some(id) = item_id else { return Ok(Vec::new()) };
    let mut stmt = c.prepare(
        "SELECT payload FROM event_log WHERE channel = 'agent.node' AND json_extract(payload, '$.item_id') = ?1 \
         AND json_extract(payload, '$.kind') IN ('acp_event', 'cancel_relayed') ORDER BY seq",
    )?;
    let rows: Vec<String> = stmt.query_map([id], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(rows
        .iter()
        .filter_map(|p| serde_json::from_str::<Value>(p).ok())
        .map(|p| {
            let kind = if p["kind"] == "acp_event" {
                p["acp_kind"].as_str().unwrap_or("").to_string()
            } else {
                "hub_cancel_relayed".to_string()
            };
            let data = if p["data"].is_object() { p["data"].clone() } else { json!({}) };
            Ev { kind, data }
        })
        .collect())
}

fn of_run<'a>(evs: &'a [Ev], kind: &str, run: &str) -> Vec<&'a Ev> {
    evs.iter().filter(|e| e.kind == kind && e.data["run"] == run).collect()
}

fn terminal(item: Option<&Item>) -> bool {
    item.is_some_and(|i| TERMINAL.contains(&i.status.as_str()))
}

fn ordered_progress(evs: &[Ev], run: &str, steps: i64) -> bool {
    let mut launched = false;
    let mut actual = Vec::new();
    for e in evs.iter().filter(|e| e.data["run"] == run) {
        match e.kind.as_str() {
            "acceptance_launch" => {
                if launched {
                    return false;
                }
                launched = true;
            }
            "acceptance_progress" => {
                if !launched || e.data["of"].as_i64() != Some(steps) {
                    return false;
                }
                match e.data["step"].as_i64() {
                    Some(s) if e.data["step"].is_i64() => actual.push(s),
                    _ => return false,
                }
            }
            _ => {}
        }
    }
    actual == (1..=steps).collect::<Vec<_>>()
}

fn launch_and_progress(item: Option<&Item>, evs: &[Ev], run: &str) -> (Value, Value) {
    let Some(it) = item else {
        let missing = check(FAIL, "the acceptance item is gone from the queue");
        return (missing.clone(), missing);
    };
    let launch = if !of_run(evs, "acceptance_launch", run).is_empty() {
        check(PASS, format!("launched on claim attempt {}", it.attempts))
    } else if terminal(item) {
        check(FAIL, format!("item ended {} without a launch event", it.status))
    } else {
        check(PENDING, format!("item is {}", it.status))
    };
    let seen = of_run(evs, "acceptance_progress", run).len();
    let progress = if ordered_progress(evs, run, COMPLETE_STEPS) {
        check(PASS, format!("{COMPLETE_STEPS} unique ordered progress steps after launch"))
    } else if terminal(item) {
        check(FAIL, format!("{seen} of {COMPLETE_STEPS} progress event(s) before it ended"))
    } else {
        check(PENDING, format!("{seen} of {COMPLETE_STEPS} progress event(s) so far"))
    };
    (launch, progress)
}

fn receipt_check(item: Option<&Item>, run: &str) -> Value {
    let Some(it) = item else { return check(FAIL, "the acceptance item is gone from the queue") };
    if !terminal(item) {
        return check(PENDING, format!("item is {}", it.status));
    }
    let receipt = it.receipt().unwrap_or(json!({}));
    if it.status != "finished" {
        let reason = receipt["reason"].as_str().map(|r| format!(": {r}")).unwrap_or_default();
        return check(FAIL, format!("item ended {}{reason}", it.status));
    }
    if receipt["backend_status"] != "success" || receipt["text"].as_str() != Some(receipt_text(run).as_str())
    {
        return check(FAIL, "receipt output does not match the job spec digest");
    }
    check(PASS, "finished; output digest verified")
}

fn cancel_check(item: Option<&Item>, evs: &[Ev], run: &str) -> Value {
    let Some(it) = item else { return check(FAIL, "the cancel item is gone from the queue") };
    if !terminal(item) {
        let state = if it.cancel_requested { "cancel requested" } else { "running, no cancel yet" };
        return check(PENDING, format!("item is {} ({state})", it.status));
    }
    let receipt = it.receipt().unwrap_or(json!({}));
    let at = |pred: &dyn Fn(&Ev) -> bool| -> Vec<usize> {
        evs.iter().enumerate().filter(|(_, e)| pred(e)).map(|(i, _)| i).collect()
    };
    let relays = at(&|e| e.kind == "hub_cancel_relayed");
    let launches = at(&|e| e.kind == "acceptance_launch" && e.data["run"] == run);
    let steps = at(&|e| e.kind == "acceptance_progress" && e.data["run"] == run && e.data["step"] == 1);
    let stopped: Vec<&Ev> = evs
        .iter()
        .enumerate()
        .filter(|(i, e)| {
            e.kind == "acceptance_stopped"
                && e.data["run"] == run
                && e.data["confirmed"] == true
                && launches
                    .iter()
                    .any(|l| steps.iter().any(|s| l < s && relays.iter().any(|r| s < r && r < i)))
        })
        .map(|(_, e)| e)
        .collect();
    if it.status == "killed"
        && it.cancel_requested
        && receipt["reason"] == "cancelled_by_hub"
        && !stopped.is_empty()
    {
        let at_step = stopped.last().map(|e| e.data["at_step"].clone()).unwrap_or(Value::Null);
        return check(PASS, format!("stopped mid-run at step {at_step}"));
    }
    if it.status == "cancelled" {
        return check(FAIL, "cancelled before the device ever ran it");
    }
    let reason = receipt["reason"].as_str().map(|r| format!(" ({r})")).unwrap_or_default();
    let missing = if stopped.is_empty() { "; no confirmed stop event" } else { "" };
    check(FAIL, format!("item ended {}{reason}{missing}", it.status))
}

/// The ownership gate every claim, heartbeat and receipt passes must refuse
/// this node to a foreign agent, and to its own agent once it is retired.
/// Runs against the stored row and writes nothing.
fn revocation_probe(node: Option<&NodeRow>) -> Value {
    let Some(n) = node else { return check(FAIL, "node is not registered") };
    let mut refused = Vec::new();
    let mut admitted = Vec::new();
    for (label, probe) in [
        ("foreign_agent", nodes::check_owner(&n.agent, n.retired, &n.node, PROBE_IDENTITY)),
        ("retired_node", nodes::check_owner(&n.agent, true, &n.node, &n.agent)),
    ] {
        match probe {
            Err(UaError::Denied { .. }) => refused.push(label),
            _ => admitted.push(label),
        }
    }
    if admitted.is_empty() {
        check(PASS, format!("claim refused (403) for: {}", refused.join(", ")))
    } else {
        check(FAIL, format!("claim gate admitted: {}", admitted.join(", ")))
    }
}

fn timed_out_reason(diagnostics_passed: bool) -> String {
    if diagnostics_passed {
        format!(
            "timed_out awaiting_operator_attestation: every diagnostic passed but no operator attested within \
             {DEADLINE_S}s; start a fresh run when an operator is ready to attest"
        )
    } else {
        format!("timed_out after {DEADLINE_S}s; start a fresh run")
    }
}

fn outcome(row: &Row, checks: &Map<String, Value>) -> (String, Option<String>) {
    match row.state.as_str() {
        "failed" => return ("failed".into(), row.reason.clone()),
        "accepted" if row.attested_by.is_none() || row.attestation_ref.is_none() => {
            return (
                "failed".into(),
                Some(
                    "legacy_unattested: start diagnostics and obtain independent operator attestation".into(),
                ),
            );
        }
        "accepted" => return ("accepted".into(), row.reason.clone()),
        _ => {}
    }
    if past_deadline(row) {
        // Judged by the last stored evaluation: a check that first passes
        // after the deadline is a late device, not a missing operator.
        return ("failed".into(), Some(timed_out_reason(all_pass(&row.checks))));
    }
    if let Some(first) = CHECKS.iter().find(|c| status_of(checks, c) == FAIL) {
        let detail = checks[*first]["detail"].as_str().unwrap_or("").to_string();
        return ("failed".into(), Some(format!("{first}: {detail}")));
    }
    if all_pass(checks) {
        return (
            "pending".into(),
            Some(
                "awaiting_operator_attestation: diagnostics passed (node self-report); an independent lifecycle \
                 operator must attest this run before real work"
                    .into(),
            ),
        );
    }
    ("pending".into(), None)
}

/// Compute the run's current view without writing anything.
fn compute(c: &Connection, row: &Row) -> UaResult<Row> {
    let run = row.run_id.as_str();
    let complete = row.complete_item_id.as_deref().map(|id| load_item(c, id)).transpose()?.flatten();
    let cancel = row.cancel_item_id.as_deref().map(|id| load_item(c, id)).transpose()?.flatten();
    let complete_evs = item_events(c, row.complete_item_id.as_deref())?;
    let cancel_evs = item_events(c, row.cancel_item_id.as_deref())?;
    let node = load_node(c, &row.node)?;
    let (launch, progress) = launch_and_progress(complete.as_ref(), &complete_evs, run);
    let mut checks = Map::new();
    checks.insert("launch".into(), launch);
    checks.insert("progress".into(), progress);
    checks.insert("receipt".into(), receipt_check(complete.as_ref(), run));
    checks.insert("cancel_confirmed".into(), cancel_check(cancel.as_ref(), &cancel_evs, run));
    checks.insert("revocation".into(), revocation_probe(node.as_ref()));
    let (mut state, mut reason) = if node.as_ref().is_some_and(|n| n.agent != row.agent) {
        (
            "failed".to_string(),
            Some(
                "node registration binding no longer matches this run; re-register and start a fresh run"
                    .into(),
            ),
        )
    } else {
        outcome(row, &checks)
    };
    if state == "pending" && row.state != "pending" {
        // An ended run never reads pending again.
        state = row.state.clone();
        reason = row.reason.clone();
    }
    let code_sha = node
        .as_ref()
        .and_then(|n| n.facts.get("code_sha").and_then(Value::as_str).map(str::to_string))
        .or(row.code_sha.clone());
    let ts = now();
    let accepted_at = if state == "accepted" { row.accepted_at.clone().or(Some(ts.clone())) } else { None };
    Ok(Row { state, reason, checks, code_sha, evaluated_at: Some(ts), accepted_at, ..row.clone() })
}

/// Re-evaluate `node`'s latest run and record the outcome, in the caller's
/// transaction. Cancels the run's cancel item first if it is running and the
/// event-time cancel was missed, and the run's open items once it fails.
pub(crate) fn evaluate_tx(tx: &mut WriteTx<'_>, cfg: &Config, node: &str) -> UaResult<Value> {
    let Some(row) = load_row(tx, node)? else { return Ok(not_run(node, cfg)) };
    if row.state == "pending"
        && let Some(id) = row.cancel_item_id.as_deref()
        && let Some(item) = load_item(tx, id)?
        && item.status == "claimed"
        && !item.cancel_requested
        && !of_run(&item_events(tx, Some(id))?, "acceptance_progress", &row.run_id).is_empty()
    {
        cancel_item(tx, id, ACTOR, "device acceptance: cancel the running job")?;
    }
    let out = compute(tx, &row)?;
    tx.execute(
        "UPDATE node_acceptance SET state = ?3, checks_json = ?4, reason = ?5, code_sha = ?6, evaluated_at = ?7, \
         accepted_at = ?8, updated_at = ?7 WHERE node = ?1 AND run_id = ?2 AND state = ?9",
        params![
            node,
            row.run_id,
            out.state,
            Value::Object(out.checks.clone()).to_string(),
            out.reason,
            out.code_sha,
            out.evaluated_at,
            out.accepted_at,
            row.state,
        ],
    )?;
    if out.state == "failed" {
        for id in [&row.complete_item_id, &row.cancel_item_id].into_iter().flatten() {
            if load_item(tx, id)?.is_some_and(|i| matches!(i.status.as_str(), "queued" | "claimed")) {
                cancel_item(tx, id, ACTOR, "device acceptance run ended")?;
            }
        }
    }
    if out.state != row.state {
        record(
            tx,
            &format!("acceptance_{}", out.state),
            json!({ "node": node, "run_id": row.run_id, "reason": out.reason, "code_sha": out.code_sha }),
            ACTOR,
        )?;
    }
    Ok(public(&out, cfg))
}

// --- hooks from the queue -------------------------------------------------------

/// After a node reports events for `item`: cancel the run's cancel item as
/// soon as it reports progress, so the cancel reaches it mid-run.
pub(crate) fn on_events(tx: &mut WriteTx<'_>, item: &Item, kinds: &[String]) -> UaResult<()> {
    if item.backend != BACKEND || !kinds.iter().any(|k| k == "acceptance_progress") {
        return Ok(());
    }
    let Some(row) = load_row(tx, &item.node)? else { return Ok(()) };
    if row.state != "pending" || row.cancel_item_id.as_deref() != Some(item.id.as_str()) {
        return Ok(());
    }
    if load_item(tx, &item.id)?.is_some_and(|i| i.status == "claimed" && !i.cancel_requested) {
        cancel_item(tx, &item.id, ACTOR, "device acceptance: cancel the running job")?;
    }
    Ok(())
}

/// After a receipt for an acceptance item: re-evaluate its run.
pub(crate) fn on_receipt(tx: &mut WriteTx<'_>, cfg: &Config, item: &Item) -> UaResult<()> {
    if item.backend != BACKEND {
        return Ok(());
    }
    if let Some(row) = load_row(tx, &item.node)?
        && [&row.complete_item_id, &row.cancel_item_id]
            .iter()
            .any(|id| id.as_deref() == Some(item.id.as_str()))
    {
        evaluate_tx(tx, cfg, &item.node)?;
    }
    Ok(())
}

/// What `node`'s claim may take now: real work (when accepted, or when
/// acceptance is not required) and the live run's own two items.
pub(crate) struct ClaimGate {
    pub real: bool,
    pub acceptance_ids: Vec<String>,
}

pub(crate) fn claim_gate(c: &Connection, cfg: &Config, node: &NodeRow) -> UaResult<ClaimGate> {
    let row = load_row(c, &node.node)?;
    let real = !cfg.node_require_acceptance || accepted(row.as_ref(), &node.agent);
    let acceptance_ids = row
        .filter(|r| r.state == "pending" && r.agent == node.agent && !past_deadline(r))
        .map(|r| [r.complete_item_id, r.cancel_item_id].into_iter().flatten().collect())
        .unwrap_or_default();
    Ok(ClaimGate { real, acceptance_ids })
}

impl ClaimGate {
    pub fn admits(&self, item: &Item) -> bool {
        if item.backend == BACKEND { self.acceptance_ids.contains(&item.id) } else { self.real }
    }
}

/// Refuse non-acceptance work for a node that has not passed acceptance,
/// while `node_require_acceptance` is on.
pub(crate) fn require_accepted(c: &Connection, cfg: &Config, node: &NodeRow, backend: &str) -> UaResult<()> {
    if backend == BACKEND || !cfg.node_require_acceptance {
        return Ok(());
    }
    let row = load_row(c, &node.node)?;
    if accepted(row.as_ref(), &node.agent) {
        return Ok(());
    }
    let state = row.map_or_else(|| "never run".to_string(), |r| r.state);
    Err(UaError::conflict_code(
        "node_not_accepted",
        format!(
            "node {:?} has not passed device acceptance ({state}); node_require_acceptance holds real work until \
             it does. Start it with coordination_manage action node_acceptance_start (params node), then retry",
            node.node
        ),
    ))
}

// --- the actions ----------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeArgs {
    /// Node name.
    pub node: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusArgs {
    /// One node's live evaluation; without it, every node's stored summary.
    pub node: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttestArgs {
    /// Node name.
    pub node: String,
    /// The exact pending run being attested (`acc-` + 16 hex).
    pub run_id: String,
    /// Where the independent verification is recorded, 1-1000 characters.
    pub evidence_ref: String,
}

/// The node's own agent or an operator may start or evaluate a run.
fn authorize(c: &Connection, hub: &Hub, ctx: &ToolCtx, who: &str, node: &str) -> UaResult<NodeRow> {
    let Some(row) = load_node(c, node)? else {
        return Err(UaError::not_found(format!("node {node:?} is not registered")));
    };
    if row.agent != who && !is_operator(hub, &ctx.caller, who) {
        return Err(UaError::denied(
            "not_node_agent",
            format!(
                "only {:?} (the node's agent) or an operator may run device acceptance on this node",
                row.agent
            ),
        ));
    }
    Ok(row)
}

fn first_root(node: &NodeRow) -> Option<String> {
    node.facts
        .get("worktree_roots")
        .and_then(Value::as_array)?
        .iter()
        .filter(|r| r.get("exists") != Some(&json!(false)))
        .find_map(|r| r.get("path").and_then(Value::as_str).map(str::to_string))
}

/// `coordination_manage(action="node_acceptance_start")`: queue a run's two
/// jobs and its tracking row in one transaction. Takes no approval: the
/// jobs run no model and no harness.
pub(crate) async fn node_acceptance_start(ctx: ToolCtx, a: NodeArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "device acceptance")?;
    let name = nodes::validate_node_name(&a.node)?;
    let hub = ctx.hub.clone();
    let c2 = ctx.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let node = authorize(tx, &hub, &c2, &who, &name)?;
            // Expire an abandoned run before reserving a new one.
            evaluate_tx(tx, hub.cfg(), &name)?;
            if let Some(existing) = load_row(tx, &name)?
                && existing.state == "pending"
            {
                return Err(UaError::conflict_code(
                    "acceptance_pending",
                    format!(
                        "acceptance run {} for node {name:?} is still pending; read diagnostics, attest when they \
                         pass, or wait for its deadline",
                        existing.run_id
                    ),
                ));
            }
            if !node.backends().unwrap_or_default().iter().any(|b| b == BACKEND) {
                return Err(UaError::conflict_code(
                    "backend_unavailable",
                    format!("node {name:?} does not advertise the {BACKEND:?} backend; update the node"),
                ));
            }
            let Some(cwd) = first_root(&node) else {
                return Err(UaError::conflict_code(
                    "node_no_worktree_root",
                    format!("node {name:?} reported no usable worktree root"),
                ));
            };
            let run_id = format!("acc-{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);
            let mut items = Vec::new();
            for (mode, spec, timeout) in [
                ("complete", json!({ "steps": COMPLETE_STEPS, "step_s": 1.0 }), COMPLETE_TIMEOUT_S),
                ("cancel", json!({ "steps": 2, "step_s": 1.0, "hold_s": 240.0 }), CANCEL_TIMEOUT_S),
            ] {
                let mut prompt = json!({ "acceptance": mode, "run": run_id });
                for (k, v) in spec.as_object().into_iter().flatten() {
                    prompt[k] = v.clone();
                }
                let n = validate_new(
                    &name,
                    BACKEND,
                    &prompt.to_string(),
                    &cwd,
                    None,
                    None,
                    None,
                    Some(timeout),
                    None,
                    None,
                )?;
                let queued = insert_item(tx, &hub, &n, &node, &who)?;
                items.push(queued["item_id"].as_str().unwrap_or_default().to_string());
            }
            let ts = now();
            let checks: Map<String, Value> =
                CHECKS.iter().map(|c| (c.to_string(), check(PENDING, "not evaluated yet"))).collect();
            let code_sha = node.facts.get("code_sha").and_then(Value::as_str).map(str::to_string);
            tx.execute(
                "INSERT OR REPLACE INTO node_acceptance (node, run_id, agent, state, complete_item_id, cancel_item_id, \
                 checks_json, reason, code_sha, started_by, started_at, updated_at) \
                 VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, NULL, ?7, ?8, ?9, ?9)",
                params![name, run_id, node.agent, items[0], items[1], Value::Object(checks).to_string(), code_sha, who, ts],
            )?;
            record(tx, "acceptance_started", json!({ "node": name, "run_id": run_id, "items": items }), &who)?;
            let row = load_row(tx, &name)?.ok_or_else(|| UaError::internal("acceptance row vanished"))?;
            Ok(public(&row, hub.cfg()))
        })
        .await
}

/// `coordination_manage(action="node_acceptance_evaluate")`: re-evaluate and
/// record the outcome (the node's agent or an operator).
pub(crate) async fn node_acceptance_evaluate(ctx: ToolCtx, a: NodeArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "device acceptance")?;
    let name = nodes::validate_node_name(&a.node)?;
    let hub = ctx.hub.clone();
    let c2 = ctx.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            authorize(tx, &hub, &c2, &who, &name)?;
            evaluate_tx(tx, hub.cfg(), &name)
        })
        .await
}

/// A stored row as a listing summary; a run pending past its deadline reads
/// `failed`.
fn summary(row: &Row) -> Value {
    let (mut state, mut reason) = (row.state.clone(), row.reason.clone());
    if state == "pending" && past_deadline(row) {
        state = "failed".into();
        reason = Some(timed_out_reason(all_pass(&row.checks)));
    }
    if state == "accepted" && row.attested_by.is_none() {
        state = "failed".into();
        reason = Some("legacy_unattested: start a fresh independently attested run".into());
    }
    let checks: Map<String, Value> = CHECKS
        .iter()
        .map(|c| (c.to_string(), json!(row.checks.get(*c).and_then(|v| v["status"].as_str()))))
        .collect();
    json!({
        "state": state,
        "agent": row.agent,
        "run_id": row.run_id,
        "reason": reason,
        "checks": checks,
        "code_sha": row.code_sha,
        "started_at": row.started_at,
        "evaluated_at": row.evaluated_at,
        "accepted_at": row.accepted_at,
    })
}

/// Every node in service's stored summary (no event reads).
pub(crate) fn read_states(c: &Connection) -> UaResult<Map<String, Value>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {} FROM node_acceptance a JOIN nodes n ON n.node = a.node WHERE n.retired_at IS NULL ORDER BY a.node",
        ROW_COLS.split(", ").map(|col| format!("a.{col}")).collect::<Vec<_>>().join(", ")
    ))?;
    let rows: Vec<Row> = stmt.query_map([], row_from)?.collect::<Result<_, _>>()?;
    Ok(rows.iter().map(|r| (r.node.clone(), summary(r))).collect())
}

/// `coordination_manage(action="node_acceptance_status")` and
/// `GET /api/nodes/acceptance`: one node's live evaluation (computed, not
/// recorded), or every node's stored summary. Read-only.
pub(crate) async fn node_acceptance_status(ctx: ToolCtx, a: StatusArgs) -> UaResult<Value> {
    let hub = ctx.hub.clone();
    let node = a.node.map(|n| nodes::validate_node_name(&n)).transpose()?;
    ctx.hub
        .db()
        .read_async(move |c| match node {
            Some(name) => match load_row(c, &name)? {
                None => Ok(not_run(&name, hub.cfg())),
                Some(row) => Ok(public(&compute(c, &row)?, hub.cfg())),
            },
            None => Ok(json!({ "nodes": read_states(c)?, "required": hub.cfg().node_require_acceptance })),
        })
        .await
}

/// `coordination_manage(action="node_acceptance_attest")`: an operator who is
/// not the node's agent attests one exact pending run whose diagnostics all
/// passed, naming the independent evidence. This records a human trust
/// decision; the node's self-report alone never accepts a node.
pub(crate) async fn node_acceptance_attest(ctx: ToolCtx, a: AttestArgs) -> UaResult<Value> {
    let who = verified_caller(&ctx.caller, "attesting device acceptance")?;
    if !is_operator(&ctx.hub, &ctx.caller, &who) {
        return Err(UaError::denied(
            "not_operator",
            "only an independent operator may attest device acceptance",
        ));
    }
    let evidence = a.evidence_ref.trim().to_string();
    if evidence.is_empty() || evidence.chars().count() > MAX_EVIDENCE {
        return Err(UaError::invalid(
            "evidence_ref must identify independent verification (1-1000 characters)",
        ));
    }
    let name = nodes::validate_node_name(&a.node)?;
    let run_id = a.run_id.trim().to_string();
    let hub = ctx.hub.clone();
    // Record the latest evaluation first, whatever the attestation decides.
    let n2 = name.clone();
    ctx.hub.db().write_async(move |tx| evaluate_tx(tx, hub.cfg(), &n2)).await?;
    let hub = ctx.hub.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let Some(node) = load_node(tx, &name)? else {
                return Err(UaError::not_found(format!("node {name:?} is not registered")));
            };
            if node.agent == who {
                return Err(UaError::denied("self_attestation", "a node's own agent cannot attest its acceptance"));
            }
            let row = load_row(tx, &name)?;
            let Some(row) = row.filter(|r| r.run_id == run_id && r.state == "pending") else {
                return Err(UaError::conflict_code(
                    "acceptance_not_pending",
                    "attestation requires the exact pending acceptance run",
                ));
            };
            if node.agent != row.agent || !all_pass(&row.checks) {
                return Err(UaError::conflict_code(
                    "diagnostics_incomplete",
                    "all transport diagnostics must pass before attestation",
                ));
            }
            if past_deadline(&row) {
                return Err(UaError::conflict_code("timed_out", "acceptance run timed out; start a fresh run"));
            }
            let ts = now();
            tx.execute(
                "UPDATE node_acceptance SET state = 'accepted', reason = NULL, accepted_at = ?3, attested_by = ?4, \
                 attestation_ref = ?5, updated_at = ?3 WHERE node = ?1 AND run_id = ?2",
                params![name, run_id, ts, who, evidence],
            )?;
            record(
                tx,
                "acceptance_attested",
                json!({ "node": name, "run_id": run_id, "attested_by": who, "evidence_ref": evidence }),
                &who,
            )?;
            let row = load_row(tx, &name)?.ok_or_else(|| UaError::internal("acceptance row vanished"))?;
            Ok(public(&row, hub.cfg()))
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_receipt_digest_survives_redaction() {
        let text = receipt_text("acc-0123456789abcdef");
        assert!(text.starts_with("acceptance:complete run=acc-0123456789abcdef bytes="), "{text}");
        let (redacted, n) = crate::families::audit::rules::redact_secrets(&text);
        assert_eq!((redacted.as_str(), n), (text.as_str(), 0));
    }
}
