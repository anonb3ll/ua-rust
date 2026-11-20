//! Plans: dumb storage for goal decomposition, checkpoints and bounded retries.
//!
//! There is no model in the loop and nothing runs automatically. The calling
//! agent writes its own decomposition, decides each step and drives progress;
//! these tools persist that state so work survives across turns, agents and
//! restarts.
//!
//! - Decomposition: `create`, `update`, and the structure edits `step_add`,
//!   `step_edit`, `step_remove`, `step_reorder`, `edit`.
//! - Checkpointing: `checkpoint`, `resume`.
//! - Bounded self-correction: `step_retry` escalates to a human after
//!   [`MAX_RETRIES`] failed attempts.
//! - Chained work: `step_claim` (atomic, dependency-aware) and `handoff`.
//!
//! Every action is reachable through `plan_manage(action, params)`; the
//! legacy `plan_*` tools are thin aliases onto the same functions.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, Row, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::{ActorKind, Caller, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use crate::registry::{Registry, ToolCtx, blocking, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "plans.v1",
    sql: "
CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    goal TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'default',
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','done','blocked','abandoned')),
    author TEXT,
    escalated INTEGER NOT NULL DEFAULT 0,
    escalation_note TEXT,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_plans_status ON plans(status, created_at);

CREATE TABLE IF NOT EXISTS plan_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    step_idx INTEGER NOT NULL,
    description TEXT NOT NULL,
    owner TEXT,
    depends_on TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','doing','done','failed','blocked')),
    note TEXT,
    outputs TEXT NOT NULL DEFAULT '{}',
    retries INTEGER NOT NULL DEFAULT 0,
    done_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (plan_id, step_idx)
);
CREATE INDEX IF NOT EXISTS idx_plan_steps_plan ON plan_steps(plan_id);

CREATE TABLE IF NOT EXISTS plan_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    context TEXT NOT NULL DEFAULT '{}',
    note TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (plan_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_plan_checkpoints_plan ON plan_checkpoints(plan_id);
",
};

pub const STEP_STATUSES: [&str; 5] = ["open", "doing", "done", "failed", "blocked"];
pub const PLAN_STATUSES: [&str; 4] = ["active", "done", "blocked", "abandoned"];
const TERMINAL_PLAN_STATUSES: [&str; 2] = ["done", "abandoned"];
const UNTOUCHABLE_STEP_STATUSES: [&str; 2] = ["doing", "done"];
/// Failed attempts at one step before the step and its plan become `blocked`.
pub const MAX_RETRIES: i64 = 3;
/// Escalation is recorded on the plan only; nothing is sent anywhere.
pub const ESCALATION_CHANNEL: &str = "flag";
const TITLE_MAX: usize = 200;
const DESCRIPTION_MAX: usize = 4_000;

// ---------------------------------------------------------------------------
// Helpers shared with the delegation family.

/// One row as a JSON object keyed by column name.
pub(crate) fn row_map(r: &Row<'_>) -> rusqlite::Result<Map<String, Value>> {
    let stmt: &rusqlite::Statement<'_> = r.as_ref();
    let mut m = Map::new();
    for i in 0..stmt.column_count() {
        let name = stmt.column_name(i)?.to_string();
        let v = match r.get_ref(i)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(n) => json!(n),
            ValueRef::Real(f) => json!(f),
            ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(b) => Value::String(hex::encode(b)),
        };
        m.insert(name, v);
    }
    Ok(m)
}

/// The identity a write is attributed to.
///
/// Anonymous (local stdio) and system callers keep the label they claim. A
/// verified caller is always attributed to itself, and naming another label
/// is refused rather than silently rewritten.
pub(crate) fn write_identity(caller: &Caller, claimed: Option<&str>) -> UaResult<String> {
    let claimed = claimed.map(str::trim).filter(|s| !s.is_empty());
    match caller.kind {
        ActorKind::Anonymous | ActorKind::System => Ok(claimed.unwrap_or(&caller.label).to_string()),
        ActorKind::Agent | ActorKind::Human => match claimed {
            Some(c) if c != caller.label => Err(UaError::denied(
                "identity_mismatch",
                format!("claimed {c:?} but the caller is verified as {:?}", caller.label),
            )),
            _ => Ok(caller.label.clone()),
        },
    }
}

/// Deserialize a `*_manage` action's `params` into its argument struct.
pub(crate) fn parse_params<T: DeserializeOwned>(
    family: &str,
    action: &str,
    params: Option<Value>,
) -> UaResult<T> {
    let raw = match params {
        None | Some(Value::Null) => json!({}),
        Some(v @ Value::Object(_)) => v,
        Some(_) => return Err(UaError::invalid("params must be an object")),
    };
    serde_json::from_value(raw)
        .map_err(|e| UaError::invalid(format!("invalid params for {family} action {action:?}: {e}")))
}

pub(crate) fn emit(tx: &mut WriteTx<'_>, caller: &Caller, channel: &str, payload: Value) -> UaResult<()> {
    ledger::append(tx, EventInput::new(channel, payload).by(caller.label.clone()))?;
    Ok(())
}

fn new_plan_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let salt = std::collections::hash_map::RandomState::new().hash_one(n);
    let mut h = Sha256::new();
    h.update(ua_core::time::now_ms().to_le_bytes());
    h.update(n.to_le_bytes());
    h.update(salt.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    hex::encode(h.finalize())[..12].to_string()
}

// ---------------------------------------------------------------------------
// Reading plans and steps.

#[derive(Debug, Clone)]
struct Step {
    id: i64,
    idx: i64,
    status: String,
    owner: Option<String>,
    depends_on: Vec<i64>,
    updated_at: String,
    json: Value,
}

fn split_goal(goal: &str) -> (String, String) {
    match goal.trim().split_once('\n') {
        Some((title, rest)) => (title.trim().to_string(), rest.trim().to_string()),
        None => (goal.trim().to_string(), String::new()),
    }
}

fn plan_from_row(r: &Row<'_>) -> rusqlite::Result<Value> {
    let mut m = row_map(r)?;
    let escalated = m.get("escalated").and_then(Value::as_i64).unwrap_or(0) != 0;
    m.insert("needs_human".into(), json!(escalated));
    let (title, description) = split_goal(m.get("goal").and_then(Value::as_str).unwrap_or(""));
    m.insert("title".into(), json!(title));
    m.insert("description".into(), json!(description));
    Ok(Value::Object(m))
}

fn step_from_row(r: &Row<'_>) -> rusqlite::Result<Step> {
    let mut m = row_map(r)?;
    let deps: Vec<i64> =
        serde_json::from_str(m.get("depends_on").and_then(Value::as_str).unwrap_or("[]")).unwrap_or_default();
    m.insert("depends_on".into(), json!(deps));
    let outputs = m
        .get("outputs")
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| json!({}));
    m.insert("outputs".into(), outputs);
    Ok(Step {
        id: r.get("id")?,
        idx: r.get("step_idx")?,
        status: r.get("status")?,
        owner: r.get("owner")?,
        depends_on: deps,
        updated_at: r.get("updated_at")?,
        json: Value::Object(m),
    })
}

fn get_plan(c: &Connection, plan_id: &str) -> UaResult<Value> {
    c.query_row("SELECT * FROM plans WHERE id = ?1", [plan_id], plan_from_row)
        .optional()?
        .ok_or_else(|| UaError::not_found(format!("no plan with id {plan_id:?}")))
}

fn load_steps(c: &Connection, plan_id: &str) -> UaResult<Vec<Step>> {
    let mut stmt = c.prepare("SELECT * FROM plan_steps WHERE plan_id = ?1 ORDER BY step_idx")?;
    let rows = stmt.query_map([plan_id], step_from_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn steps_json(steps: &[Step]) -> Value {
    Value::Array(steps.iter().map(|s| s.json.clone()).collect())
}

/// First not-done step whose dependencies are all done.
fn next_actionable(steps: &[Step]) -> Option<i64> {
    let done: BTreeSet<i64> = steps.iter().filter(|s| s.status == "done").map(|s| s.idx).collect();
    steps.iter().find(|s| s.status != "done" && s.depends_on.iter().all(|d| done.contains(d))).map(|s| s.idx)
}

fn checkpoint_from_row(r: &Row<'_>) -> rusqlite::Result<Value> {
    let mut m = row_map(r)?;
    let ctx = m
        .get("context")
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| json!({}));
    m.insert("context".into(), ctx);
    Ok(Value::Object(m))
}

fn checkpoint_at(c: &Connection, plan_id: &str, seq: i64) -> UaResult<Option<Value>> {
    Ok(c.query_row(
        "SELECT * FROM plan_checkpoints WHERE plan_id = ?1 AND seq = ?2",
        params![plan_id, seq],
        checkpoint_from_row,
    )
    .optional()?)
}

fn step_at<'a>(steps: &'a [Step], plan_id: &str, idx: i64) -> UaResult<&'a Step> {
    steps
        .iter()
        .find(|s| s.idx == idx)
        .ok_or_else(|| UaError::not_found(format!("plan {plan_id:?} has no step at index {idx}")))
}

/// Refuse an index-addressed write when the step at `idx` is no longer the
/// row the caller read (a reorder, insert or removal moved it).
fn check_step_id(plan_id: &str, idx: i64, steps: &[Step], expected: Option<i64>) -> UaResult<()> {
    let Some(expected) = expected else { return Ok(()) };
    let current = steps.iter().find(|s| s.idx == idx).map(|s| s.id);
    if current != Some(expected) {
        return Err(UaError::conflict(format!(
            "step {idx} of plan {plan_id:?} is not step id {expected} (current: {}): the steps moved since \
             they were read; reload the plan and try again",
            current.map_or("none".to_string(), |i| i.to_string())
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Writing.

/// Every plan write advances `revision` and `updated_at`.
fn touch(tx: &WriteTx<'_>, plan_id: &str, ts: &str) -> UaResult<()> {
    tx.execute(
        "UPDATE plans SET updated_at = ?2, revision = revision + 1 WHERE id = ?1",
        params![plan_id, ts],
    )?;
    Ok(())
}

/// Flip a non-escalated active plan to done once every step is done.
fn maybe_autocomplete(tx: &mut WriteTx<'_>, caller: &Caller, plan_id: &str, ts: &str) -> UaResult<()> {
    let steps = load_steps(tx, plan_id)?;
    if !steps.is_empty() && steps.iter().all(|s| s.status == "done") {
        let n = tx.execute(
            "UPDATE plans SET status = 'done', updated_at = ?2 WHERE id = ?1 AND status = 'active' AND escalated = 0",
            params![plan_id, ts],
        )?;
        if n > 0 {
            emit(tx, caller, "agent.plan.completed", json!({ "plan_id": plan_id }))?;
        }
    }
    Ok(())
}

fn insert_checkpoint(
    tx: &WriteTx<'_>,
    plan_id: &str,
    mut context: Map<String, Value>,
    note: Option<&str>,
    ts: &str,
) -> UaResult<i64> {
    let seq: i64 = tx.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM plan_checkpoints WHERE plan_id = ?1",
        [plan_id],
        |r| r.get(0),
    )?;
    let state: Vec<Value> = load_steps(tx, plan_id)?
        .iter()
        .map(|s| json!({ "step_idx": s.idx, "status": s.status, "description": s.json["description"] }))
        .collect();
    context.insert("step_state".into(), Value::Array(state));
    tx.execute(
        "INSERT INTO plan_checkpoints (plan_id, seq, context, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![plan_id, seq, Value::Object(context).to_string(), note, ts],
    )?;
    Ok(seq)
}

struct StepSpec {
    description: String,
    owner: Option<String>,
    depends_on: Vec<i64>,
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn normalize_steps(steps: &[Value]) -> UaResult<Vec<StepSpec>> {
    if steps.is_empty() {
        return Err(UaError::invalid("steps must be a non-empty list"));
    }
    let n = steps.len() as i64;
    let mut out = Vec::with_capacity(steps.len());
    for (i, raw) in steps.iter().enumerate() {
        let (desc, owner, deps) = match raw {
            Value::String(s) => (s.clone(), None, Vec::new()),
            Value::Object(o) => {
                let desc = match o.get("description") {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                };
                let owner = match o.get("owner") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(other) => Some(other.to_string()),
                };
                let deps = match o.get("depends_on") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(a)) => a
                        .iter()
                        .map(|d| {
                            d.as_i64().ok_or_else(|| {
                                UaError::invalid(format!(
                                    "step {i} depends_on entries must be integer step indices"
                                ))
                            })
                        })
                        .collect::<UaResult<Vec<_>>>()?,
                    Some(_) => {
                        return Err(UaError::invalid(format!(
                            "step {i} depends_on must be a list of step indices"
                        )));
                    }
                };
                (desc, owner, deps)
            }
            other => {
                return Err(UaError::invalid(format!(
                    "step {i} must be a string or an object, got {}",
                    json_type(other)
                )));
            }
        };
        let desc = desc.trim().to_string();
        if desc.is_empty() {
            return Err(UaError::invalid(format!("step {i} must have a non-empty description")));
        }
        for &d in &deps {
            if d < 0 || d >= n {
                return Err(UaError::invalid(format!(
                    "step {i} depends_on index {d} is out of range (0..{})",
                    n - 1
                )));
            }
            if d == i as i64 {
                return Err(UaError::invalid(format!("step {i} cannot depend on itself")));
            }
        }
        let depends_on: Vec<i64> = deps.into_iter().collect::<BTreeSet<_>>().into_iter().collect();
        out.push(StepSpec { description: desc, owner, depends_on });
    }
    // A cycle would leave every step on it unclaimable forever.
    let mut state = vec![0u8; out.len()];
    fn visit(i: usize, specs: &[StepSpec], state: &mut [u8]) -> Option<usize> {
        match state[i] {
            1 => return Some(i),
            2 => return None,
            _ => {}
        }
        state[i] = 1;
        for &d in &specs[i].depends_on {
            if let Some(c) = visit(d as usize, specs, state) {
                return Some(c);
            }
        }
        state[i] = 2;
        None
    }
    for i in 0..out.len() {
        if let Some(c) = visit(i, &out, &mut state) {
            return Err(UaError::invalid(format!("step dependencies form a cycle through step {c}")));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Argument structs.

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateArgs {
    /// What the plan achieves. The first line is reported as `title`, the rest as `description`.
    pub goal: String,
    /// Ordered steps. Each is a description string or `{description, owner?, depends_on?}`
    /// where `depends_on` lists 0-based indexes of steps that must be done first.
    pub steps: Vec<Value>,
    /// Groups plans; default `default`.
    pub scope: Option<String>,
    /// Your agent label; a verified caller is always recorded as itself.
    pub author: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateArgs {
    pub plan_id: String,
    /// 0-based step index.
    pub step_idx: i64,
    /// `open`, `doing`, `done`, `failed` or `blocked`. `done` stamps `done_at`.
    pub status: Option<String>,
    /// Replaces the step note.
    pub note: Option<String>,
    /// Replaces the step owner.
    pub owner: Option<String>,
    /// The step's row id as last read; a moved step turns the write into a conflict.
    pub expected_step_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanIdArgs {
    pub plan_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// `active` (default), `done`, `blocked`, `abandoned` or `all`.
    pub status: Option<String>,
    /// Only plans in this scope.
    pub scope: Option<String>,
    /// 1-200, default 50.
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckpointArgs {
    pub plan_id: String,
    /// Memory note ids relevant to resuming.
    pub memory_ids: Option<Vec<String>>,
    /// File paths relevant to resuming.
    pub file_paths: Option<Vec<String>>,
    /// Free-form map of key results.
    pub outputs: Option<Map<String, Value>>,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResumeArgs {
    pub plan_id: String,
    /// Checkpoint sequence number; default the latest.
    pub from_checkpoint: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetryArgs {
    pub plan_id: String,
    pub step_idx: i64,
    /// Why the attempt failed; appended to the step note.
    pub reason: String,
    pub expected_step_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimArgs {
    pub plan_id: String,
    pub step_idx: i64,
    /// Claiming agent; defaults to the caller. A verified caller can only claim as itself.
    pub agent: Option<String>,
    pub expected_step_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffArgs {
    pub plan_id: String,
    pub step_idx: i64,
    /// Payload for the next step's owner, read back through `get`/`resume`.
    pub outputs: Option<Map<String, Value>>,
    pub note: Option<String>,
    /// Finishing agent; a verified caller is always recorded as itself.
    pub agent: Option<String>,
    /// Accepted for compatibility. This hub sends no notifications; `notified` is always false.
    #[serde(default)]
    pub notify_owner: bool,
    pub expected_step_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloseArgs {
    pub plan_id: String,
    /// Why the plan is abandoned. Required.
    pub reason: String,
    /// Optional evidence map stored in the final checkpoint.
    pub outputs: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepAddArgs {
    pub plan_id: String,
    pub description: String,
    /// Insert position, 0..=step count; default the end.
    pub position: Option<i64>,
    pub owner: Option<String>,
    /// Current indexes of steps the new one waits for.
    pub depends_on: Option<Vec<i64>>,
    /// The plan's `revision` as last read; a stale value is a conflict.
    pub expected_revision: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepEditArgs {
    pub plan_id: String,
    pub step_idx: i64,
    pub description: String,
    pub expected_revision: Option<i64>,
    pub expected_step_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepRemoveArgs {
    pub plan_id: String,
    pub step_idx: i64,
    pub expected_revision: Option<i64>,
    pub expected_step_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepReorderArgs {
    pub plan_id: String,
    /// A permutation of the current indexes: `order[i]` is the step that moves to position `i`.
    pub order: Vec<i64>,
    pub expected_revision: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EditArgs {
    pub plan_id: String,
    /// One line, at most 200 characters.
    pub title: Option<String>,
    /// At most 4000 characters; empty clears it.
    pub description: Option<String>,
    pub expected_revision: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManageArgs {
    /// One of create, update, get, list, checkpoint, resume, step_retry (retry), step_claim
    /// (claim), handoff, close, delete, step_add, step_edit, step_remove, step_reorder, edit.
    pub action: String,
    /// The action's arguments, exactly as the matching standalone tool takes them.
    pub params: Option<Value>,
}

// ---------------------------------------------------------------------------
// Operations.

fn create(ctx: &ToolCtx, a: CreateArgs) -> UaResult<Value> {
    let goal = a.goal.trim().to_string();
    if goal.is_empty() {
        return Err(UaError::invalid("goal must not be empty"));
    }
    let specs = normalize_steps(&a.steps)?;
    let author = match a.author.as_deref() {
        Some(x) => Some(write_identity(&ctx.caller, Some(x))?),
        None if matches!(ctx.caller.kind, ActorKind::Agent | ActorKind::Human) => {
            Some(ctx.caller.label.clone())
        }
        None => None,
    };
    let scope =
        a.scope.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "default".into());
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let ts = ua_core::time::now();
        let mut plan_id = new_plan_id();
        while tx.query_row("SELECT 1 FROM plans WHERE id = ?1", [&plan_id], |_| Ok(())).optional()?.is_some()
        {
            plan_id = new_plan_id();
        }
        tx.execute(
            "INSERT INTO plans (id, goal, scope, status, author, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?5)",
            params![plan_id, goal, scope, author, ts],
        )?;
        for (idx, s) in specs.iter().enumerate() {
            tx.execute(
                "INSERT INTO plan_steps (plan_id, step_idx, description, owner, depends_on, status, retries, \
                 created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 'open', 0, ?6, ?6)",
                params![plan_id, idx as i64, s.description, s.owner, json!(s.depends_on).to_string(), ts],
            )?;
        }
        emit(
            tx,
            &caller,
            "agent.plan.created",
            json!({ "plan_id": plan_id, "goal": goal, "scope": scope, "step_count": specs.len() }),
        )?;
        let steps = load_steps(tx, &plan_id)?;
        Ok(json!({ "plan_id": plan_id, "steps": steps_json(&steps) }))
    })
}

fn update(ctx: &ToolCtx, a: UpdateArgs) -> UaResult<Value> {
    if let Some(s) = a.status.as_deref()
        && !STEP_STATUSES.contains(&s)
    {
        return Err(UaError::invalid(format!("status must be one of {STEP_STATUSES:?}")));
    }
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let ts = ua_core::time::now();
        get_plan(tx, &a.plan_id)?;
        let steps = load_steps(tx, &a.plan_id)?;
        check_step_id(&a.plan_id, a.step_idx, &steps, a.expected_step_id)?;
        let step = step_at(&steps, &a.plan_id, a.step_idx)?.clone();
        if let Some(st) = a.status.as_deref() {
            let done_at = (st == "done").then(|| ts.clone());
            tx.execute(
                "UPDATE plan_steps SET status = ?2, done_at = ?3 WHERE id = ?1",
                params![step.id, st, done_at],
            )?;
        }
        if let Some(note) = a.note.as_deref() {
            tx.execute("UPDATE plan_steps SET note = ?2 WHERE id = ?1", params![step.id, note])?;
        }
        if let Some(owner) = a.owner.as_deref() {
            tx.execute("UPDATE plan_steps SET owner = ?2 WHERE id = ?1", params![step.id, owner])?;
        }
        tx.execute("UPDATE plan_steps SET updated_at = ?2 WHERE id = ?1", params![step.id, ts])?;
        touch(tx, &a.plan_id, &ts)?;
        emit(
            tx,
            &caller,
            "agent.plan.step_updated",
            json!({ "plan_id": a.plan_id, "step_idx": a.step_idx, "status": a.status, "owner": a.owner }),
        )?;
        maybe_autocomplete(tx, &caller, &a.plan_id, &ts)?;
        let steps = load_steps(tx, &a.plan_id)?;
        Ok(json!({
            "step": step_at(&steps, &a.plan_id, a.step_idx)?.json,
            "plan": get_plan(tx, &a.plan_id)?,
            "next_step_idx": next_actionable(&steps),
        }))
    })
}

fn get(ctx: &ToolCtx, a: PlanIdArgs) -> UaResult<Value> {
    ctx.hub.db().read(|c| {
        let plan = get_plan(c, &a.plan_id)?;
        let steps = load_steps(c, &a.plan_id)?;
        let mut stmt = c.prepare("SELECT * FROM plan_checkpoints WHERE plan_id = ?1 ORDER BY seq")?;
        let checkpoints: Vec<Value> =
            stmt.query_map([&a.plan_id], checkpoint_from_row)?.collect::<Result<_, _>>()?;
        Ok(json!({
            "plan": plan,
            "steps": steps_json(&steps),
            "checkpoints": checkpoints,
            "next_step_idx": next_actionable(&steps),
        }))
    })
}

fn list(ctx: &ToolCtx, a: ListArgs) -> UaResult<Value> {
    let status = a.status.unwrap_or_else(|| "active".into());
    if status != "all" && !PLAN_STATUSES.contains(&status.as_str()) {
        return Err(UaError::invalid(format!("status must be one of {PLAN_STATUSES:?} or \"all\"")));
    }
    let limit = a.limit.unwrap_or(50).clamp(1, 200);
    ctx.hub.db().read(|c| {
        let mut stmt = c.prepare(
            "SELECT * FROM plans WHERE (?1 = 'all' OR status = ?1) AND (?2 IS NULL OR scope = ?2) \
             ORDER BY created_at DESC, rowid DESC LIMIT ?3",
        )?;
        let plans: Vec<Value> =
            stmt.query_map(params![status, a.scope, limit], plan_from_row)?.collect::<Result<_, _>>()?;
        Ok(json!({ "plans": plans }))
    })
}

fn checkpoint(ctx: &ToolCtx, a: CheckpointArgs) -> UaResult<Value> {
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let ts = ua_core::time::now();
        get_plan(tx, &a.plan_id)?;
        let mut context = Map::new();
        context.insert("memory_ids".into(), json!(a.memory_ids.unwrap_or_default()));
        context.insert("file_paths".into(), json!(a.file_paths.unwrap_or_default()));
        context.insert("outputs".into(), Value::Object(a.outputs.unwrap_or_default()));
        let seq = insert_checkpoint(tx, &a.plan_id, context, a.note.as_deref(), &ts)?;
        touch(tx, &a.plan_id, &ts)?;
        emit(tx, &caller, "agent.plan.checkpointed", json!({ "plan_id": a.plan_id, "seq": seq }))?;
        Ok(json!({ "plan_id": a.plan_id, "seq": seq, "checkpoint": checkpoint_at(tx, &a.plan_id, seq)? }))
    })
}

fn resume(ctx: &ToolCtx, a: ResumeArgs) -> UaResult<Value> {
    ctx.hub.db().read(|c| {
        let plan = get_plan(c, &a.plan_id)?;
        let steps = load_steps(c, &a.plan_id)?;
        let checkpoint = match a.from_checkpoint {
            Some(seq) => Some(checkpoint_at(c, &a.plan_id, seq)?.ok_or_else(|| {
                UaError::not_found(format!("plan {:?} has no checkpoint seq {seq}", a.plan_id))
            })?),
            None => c
                .query_row(
                    "SELECT * FROM plan_checkpoints WHERE plan_id = ?1 ORDER BY seq DESC LIMIT 1",
                    [&a.plan_id],
                    checkpoint_from_row,
                )
                .optional()?,
        };
        Ok(json!({
            "plan": plan,
            "steps": steps_json(&steps),
            "next_step_idx": next_actionable(&steps),
            "checkpoint": checkpoint,
        }))
    })
}

fn step_retry(ctx: &ToolCtx, a: RetryArgs) -> UaResult<Value> {
    let reason = a.reason.trim().to_string();
    if reason.is_empty() {
        return Err(UaError::invalid("reason must not be empty"));
    }
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let ts = ua_core::time::now();
        get_plan(tx, &a.plan_id)?;
        let steps = load_steps(tx, &a.plan_id)?;
        check_step_id(&a.plan_id, a.step_idx, &steps, a.expected_step_id)?;
        let step = step_at(&steps, &a.plan_id, a.step_idx)?;
        let retries = step.json["retries"].as_i64().unwrap_or(0) + 1;
        let escalated = retries >= MAX_RETRIES;
        let prior = step.json["note"].as_str().filter(|s| !s.is_empty());
        let note = format!(
            "{}[retry {retries}/{MAX_RETRIES} @ {ts}] {reason}",
            prior.map(|p| format!("{p}\n")).unwrap_or_default()
        );
        let status = if escalated { "blocked" } else { "failed" };
        tx.execute(
            "UPDATE plan_steps SET retries = ?2, status = ?3, note = ?4, updated_at = ?5 WHERE id = ?1",
            params![step.id, retries, status, note, ts],
        )?;
        touch(tx, &a.plan_id, &ts)?;
        if escalated {
            let esc = format!("step {} exhausted {retries}/{MAX_RETRIES} retries; last reason: {reason}", a.step_idx);
            tx.execute(
                "UPDATE plans SET status = 'blocked', escalated = 1, escalation_note = ?2 WHERE id = ?1",
                params![a.plan_id, esc],
            )?;
        }
        emit(
            tx,
            &caller,
            "agent.plan.step_retried",
            json!({ "plan_id": a.plan_id, "step_idx": a.step_idx, "retries": retries, "escalated": escalated }),
        )?;
        let steps = load_steps(tx, &a.plan_id)?;
        Ok(json!({
            "step": step_at(&steps, &a.plan_id, a.step_idx)?.json,
            "retries": retries,
            "escalated": escalated,
            "max_retries": MAX_RETRIES,
            "escalation_channel": ESCALATION_CHANNEL,
            "plan": get_plan(tx, &a.plan_id)?,
        }))
    })
}

fn step_claim(ctx: &ToolCtx, a: ClaimArgs) -> UaResult<Value> {
    let agent = write_identity(&ctx.caller, a.agent.as_deref())?;
    if agent.is_empty() {
        return Err(UaError::invalid("agent label must not be empty"));
    }
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let ts = ua_core::time::now();
        let plan = get_plan(tx, &a.plan_id)?;
        let plan_status = plan["status"].as_str().unwrap_or("");
        if TERMINAL_PLAN_STATUSES.contains(&plan_status) {
            return Err(UaError::conflict(format!("plan {:?} is {plan_status}; its steps cannot be claimed", a.plan_id)));
        }
        let steps = load_steps(tx, &a.plan_id)?;
        check_step_id(&a.plan_id, a.step_idx, &steps, a.expected_step_id)?;
        let step = step_at(&steps, &a.plan_id, a.step_idx)?;
        let waiting: Vec<i64> = step
            .depends_on
            .iter()
            .copied()
            .filter(|d| steps.iter().find(|s| s.idx == *d).is_none_or(|s| s.status != "done"))
            .collect();
        if !waiting.is_empty() {
            return Err(UaError::conflict(format!(
                "step {} of plan {:?} is not claimable: it depends on step(s) {waiting:?}, which are not done",
                a.step_idx, a.plan_id
            )));
        }
        // The one claim gate, agent part: a paused, terminated or retired
        // agent claims no plan step either.
        crate::families::governance::check_claim(tx, Some(&agent), None, false)?;
        let n = tx.execute(
            "UPDATE plan_steps SET owner = ?2, status = 'doing', updated_at = ?3 \
             WHERE id = ?1 AND status IN ('open','failed') AND (owner IS NULL OR owner = ?2)",
            params![step.id, agent, ts],
        )?;
        if n == 0 {
            return Err(UaError::conflict(format!(
                "step {} of plan {:?} is not claimable: status={:?}, owner={:?}. Claims only succeed on an \
                 open/failed step that is unowned or already yours.",
                a.step_idx,
                a.plan_id,
                step.status,
                step.owner.as_deref().unwrap_or("(unowned)")
            )));
        }
        touch(tx, &a.plan_id, &ts)?;
        emit(
            tx,
            &caller,
            "agent.plan.step_claimed",
            json!({ "plan_id": a.plan_id, "step_idx": a.step_idx, "agent": agent }),
        )?;
        let steps = load_steps(tx, &a.plan_id)?;
        Ok(json!({
            "step": step_at(&steps, &a.plan_id, a.step_idx)?.json,
            "plan": get_plan(tx, &a.plan_id)?,
            "claimed": true,
        }))
    })
}

fn handoff(ctx: &ToolCtx, a: HandoffArgs) -> UaResult<Value> {
    let agent = match a.agent.as_deref() {
        Some(x) => Some(write_identity(&ctx.caller, Some(x))?),
        None if matches!(ctx.caller.kind, ActorKind::Agent | ActorKind::Human) => {
            Some(ctx.caller.label.clone())
        }
        None => None,
    };
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let ts = ua_core::time::now();
        get_plan(tx, &a.plan_id)?;
        let steps = load_steps(tx, &a.plan_id)?;
        check_step_id(&a.plan_id, a.step_idx, &steps, a.expected_step_id)?;
        let step = step_at(&steps, &a.plan_id, a.step_idx)?.clone();
        let outputs = a.outputs.clone().unwrap_or_default();
        let mut context = Map::new();
        context.insert("memory_ids".into(), json!([]));
        context.insert("file_paths".into(), json!([]));
        context.insert("outputs".into(), Value::Object(outputs.clone()));
        let default_note = format!("Automatic checkpoint on step {} handoff", a.step_idx);
        insert_checkpoint(tx, &a.plan_id, context, Some(a.note.as_deref().unwrap_or(&default_note)), &ts)?;
        tx.execute(
            "UPDATE plan_steps SET status = 'done', done_at = ?2, outputs = ?3, updated_at = ?2, \
             note = COALESCE(?4, note) WHERE id = ?1",
            params![step.id, ts, Value::Object(outputs).to_string(), a.note],
        )?;
        touch(tx, &a.plan_id, &ts)?;
        let steps = load_steps(tx, &a.plan_id)?;
        let next_idx = next_actionable(&steps);
        let next_step = next_idx.and_then(|i| steps.iter().find(|s| s.idx == i));
        let finisher = agent.clone().or(step.owner.clone());
        emit(
            tx,
            &caller,
            "agent.plan.handoff",
            json!({
                "plan_id": a.plan_id,
                "step_idx": a.step_idx,
                "agent": finisher,
                "next_step_idx": next_idx,
                "next_owner": next_step.and_then(|s| s.owner.clone()),
            }),
        )?;
        let next_json = next_step.map(|s| s.json.clone());
        let step_json = step_at(&steps, &a.plan_id, a.step_idx)?.json.clone();
        maybe_autocomplete(tx, &caller, &a.plan_id, &ts)?;
        Ok(json!({
            "step": step_json,
            "next_step": next_json,
            "plan": get_plan(tx, &a.plan_id)?,
            "notified": false,
        }))
    })
}

fn close(ctx: &ToolCtx, a: CloseArgs) -> UaResult<Value> {
    let reason = a.reason.trim().to_string();
    if reason.is_empty() {
        return Err(UaError::invalid("reason must be a non-empty string"));
    }
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let ts = ua_core::time::now();
        let plan = get_plan(tx, &a.plan_id)?;
        let status = plan["status"].as_str().unwrap_or("");
        if TERMINAL_PLAN_STATUSES.contains(&status) {
            return Err(UaError::conflict(format!("plan {:?} is already {status}", a.plan_id)));
        }
        let mut outputs = a.outputs.clone().unwrap_or_default();
        outputs.insert("closed_as".into(), json!("abandoned"));
        outputs.insert("reason".into(), json!(reason));
        let mut context = Map::new();
        context.insert("memory_ids".into(), json!([]));
        context.insert("file_paths".into(), json!([]));
        context.insert("outputs".into(), Value::Object(outputs));
        let seq = insert_checkpoint(tx, &a.plan_id, context, Some(&format!("closed as abandoned: {reason}")), &ts)?;
        tx.execute("UPDATE plans SET status = 'abandoned' WHERE id = ?1", [&a.plan_id])?;
        touch(tx, &a.plan_id, &ts)?;
        emit(tx, &caller, "agent.plan.closed", json!({ "plan_id": a.plan_id, "reason": reason, "seq": seq }))?;
        Ok(json!({ "plan": get_plan(tx, &a.plan_id)?, "seq": seq, "checkpoint": checkpoint_at(tx, &a.plan_id, seq)? }))
    })
}

fn delete(ctx: &ToolCtx, a: PlanIdArgs) -> UaResult<Value> {
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let n = tx.execute("DELETE FROM plans WHERE id = ?1", [&a.plan_id])?;
        if n > 0 {
            emit(tx, &caller, "agent.plan.deleted", json!({ "plan_id": a.plan_id }))?;
        }
        Ok(json!({ "deleted": n > 0 }))
    })
}

// --- structure edits --------------------------------------------------------
//
// Steps keep their row id; `step_idx` is their position. A structure change
// renumbers positions and rewrites `depends_on` through one old -> new map in
// one transaction. A claimed (`doing`) or `done` step is never edited, removed
// or renumbered.

fn open_structure_edit(
    tx: &WriteTx<'_>,
    plan_id: &str,
    expected_revision: Option<i64>,
    steps_change: bool,
) -> UaResult<(Value, Vec<Step>)> {
    let plan = get_plan(tx, plan_id)?;
    let revision = plan["revision"].as_i64().unwrap_or(0);
    if let Some(expected) = expected_revision
        && expected != revision
    {
        return Err(UaError::conflict(format!(
            "plan {plan_id:?} changed since it was read (revision {revision}, expected {expected}); reload it and \
             try again"
        )));
    }
    let status = plan["status"].as_str().unwrap_or("");
    if steps_change && TERMINAL_PLAN_STATUSES.contains(&status) {
        return Err(UaError::invalid(format!("plan {plan_id:?} is {status}; its steps cannot change")));
    }
    let steps = load_steps(tx, plan_id)?;
    Ok((plan, steps))
}

fn refuse_untouchable(step: &Step, verb: &str) -> UaResult<()> {
    if UNTOUCHABLE_STEP_STATUSES.contains(&step.status.as_str()) {
        return Err(UaError::conflict(format!(
            "step {} is {}; a claimed or done step cannot be {verb}",
            step.idx, step.status
        )));
    }
    Ok(())
}

/// Move each kept step to `new_index[old]` and remap every `depends_on`.
/// Rows are parked at negative indexes first so `UNIQUE(plan_id, step_idx)`
/// holds throughout.
fn apply_layout(tx: &WriteTx<'_>, steps: &[Step], new_index: &BTreeMap<i64, i64>, ts: &str) -> UaResult<()> {
    let kept: Vec<&Step> = steps.iter().filter(|s| new_index.contains_key(&s.idx)).collect();
    for s in &kept {
        if new_index[&s.idx] != s.idx {
            refuse_untouchable(s, "renumbered")?;
        }
    }
    for s in &kept {
        tx.execute("UPDATE plan_steps SET step_idx = ?2 WHERE id = ?1", params![s.id, -1 - s.id])?;
    }
    for s in &kept {
        let deps: Vec<i64> = s
            .depends_on
            .iter()
            .filter_map(|d| new_index.get(d).copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let moved = new_index[&s.idx] != s.idx || deps != s.depends_on;
        tx.execute(
            "UPDATE plan_steps SET step_idx = ?2, depends_on = ?3, updated_at = ?4 WHERE id = ?1",
            params![s.id, new_index[&s.idx], json!(deps).to_string(), if moved { ts } else { &s.updated_at }],
        )?;
    }
    Ok(())
}

fn structure_result(
    tx: &mut WriteTx<'_>,
    caller: &Caller,
    plan_id: &str,
    ts: &str,
    channel: &str,
    detail: Value,
    step_idx: Option<i64>,
) -> UaResult<Map<String, Value>> {
    touch(tx, plan_id, ts)?;
    let mut payload = json!({ "plan_id": plan_id });
    if let (Some(p), Value::Object(d)) = (payload.as_object_mut(), detail) {
        p.extend(d);
    }
    emit(tx, caller, channel, payload)?;
    let steps = load_steps(tx, plan_id)?;
    let mut out = Map::new();
    out.insert("plan".into(), get_plan(tx, plan_id)?);
    out.insert("steps".into(), steps_json(&steps));
    out.insert("next_step_idx".into(), json!(next_actionable(&steps)));
    if let Some(i) = step_idx {
        out.insert("step".into(), step_at(&steps, plan_id, i)?.json.clone());
    }
    Ok(out)
}

fn clean_description(d: &str) -> UaResult<String> {
    let t = d.trim();
    if t.is_empty() {
        return Err(UaError::invalid("description must be a non-empty string"));
    }
    Ok(t.to_string())
}

fn step_add(ctx: &ToolCtx, a: StepAddArgs) -> UaResult<Value> {
    let text = clean_description(&a.description)?;
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let (_plan, steps) = open_structure_edit(tx, &a.plan_id, a.expected_revision, true)?;
        let ts = ua_core::time::now();
        let n = steps.len() as i64;
        let pos = a.position.unwrap_or(n);
        if !(0..=n).contains(&pos) {
            return Err(UaError::invalid(format!("position must be an integer between 0 and {n}")));
        }
        let deps = a.depends_on.clone().unwrap_or_default();
        for &d in &deps {
            if !(0..n).contains(&d) {
                return Err(UaError::invalid(format!("depends_on index {d} is out of range (0..{})", n - 1)));
            }
        }
        let new_index: BTreeMap<i64, i64> =
            steps.iter().map(|s| (s.idx, s.idx + i64::from(s.idx >= pos))).collect();
        apply_layout(tx, &steps, &new_index, &ts)?;
        let new_deps: BTreeSet<i64> = deps.iter().map(|d| new_index[d]).collect();
        tx.execute(
            "INSERT INTO plan_steps (plan_id, step_idx, description, owner, depends_on, status, retries, \
             created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 'open', 0, ?6, ?6)",
            params![a.plan_id, pos, text, a.owner, json!(new_deps).to_string(), ts],
        )?;
        let out = structure_result(
            tx,
            &caller,
            &a.plan_id,
            &ts,
            "agent.plan.step_added",
            json!({ "step_idx": pos }),
            Some(pos),
        )?;
        Ok(Value::Object(out))
    })
}

fn step_edit(ctx: &ToolCtx, a: StepEditArgs) -> UaResult<Value> {
    let text = clean_description(&a.description)?;
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let (_plan, steps) = open_structure_edit(tx, &a.plan_id, a.expected_revision, true)?;
        let ts = ua_core::time::now();
        check_step_id(&a.plan_id, a.step_idx, &steps, a.expected_step_id)?;
        let step = step_at(&steps, &a.plan_id, a.step_idx)?;
        refuse_untouchable(step, "edited")?;
        tx.execute(
            "UPDATE plan_steps SET description = ?2, updated_at = ?3 WHERE id = ?1",
            params![step.id, text, ts],
        )?;
        let out = structure_result(
            tx,
            &caller,
            &a.plan_id,
            &ts,
            "agent.plan.step_edited",
            json!({ "step_idx": a.step_idx }),
            Some(a.step_idx),
        )?;
        Ok(Value::Object(out))
    })
}

fn step_remove(ctx: &ToolCtx, a: StepRemoveArgs) -> UaResult<Value> {
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let (_plan, steps) = open_structure_edit(tx, &a.plan_id, a.expected_revision, true)?;
        let ts = ua_core::time::now();
        check_step_id(&a.plan_id, a.step_idx, &steps, a.expected_step_id)?;
        let step = step_at(&steps, &a.plan_id, a.step_idx)?.clone();
        refuse_untouchable(&step, "removed")?;
        if steps.len() == 1 {
            return Err(UaError::invalid(format!(
                "step {} is the plan's only step; a plan keeps at least one",
                a.step_idx
            )));
        }
        let dependents: Vec<String> = steps
            .iter()
            .filter(|s| s.depends_on.contains(&a.step_idx))
            .map(|s| format!("step {}", s.idx))
            .collect();
        if !dependents.is_empty() {
            return Err(UaError::invalid(format!(
                "cannot remove step {}: {} depends on it; remove or edit that dependency first",
                a.step_idx,
                dependents.join(", ")
            )));
        }
        let rest: Vec<Step> = steps.iter().filter(|s| s.idx != a.step_idx).cloned().collect();
        let new_index: BTreeMap<i64, i64> =
            rest.iter().map(|s| (s.idx, s.idx - i64::from(s.idx > a.step_idx))).collect();
        for s in &rest {
            if new_index[&s.idx] != s.idx {
                refuse_untouchable(s, "renumbered")?;
            }
        }
        tx.execute("DELETE FROM plan_steps WHERE id = ?1", [step.id])?;
        apply_layout(tx, &rest, &new_index, &ts)?;
        let mut out = structure_result(
            tx,
            &caller,
            &a.plan_id,
            &ts,
            "agent.plan.step_removed",
            json!({ "step_idx": a.step_idx }),
            None,
        )?;
        out.insert("removed".into(), step.json);
        Ok(Value::Object(out))
    })
}

fn step_reorder(ctx: &ToolCtx, a: StepReorderArgs) -> UaResult<Value> {
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let (_plan, steps) = open_structure_edit(tx, &a.plan_id, a.expected_revision, true)?;
        let ts = ua_core::time::now();
        let n = steps.len() as i64;
        let mut sorted = a.order.clone();
        sorted.sort_unstable();
        if sorted != (0..n).collect::<Vec<_>>() {
            return Err(UaError::invalid(format!(
                "order must be a permutation of the step indices 0..{}",
                n - 1
            )));
        }
        let new_index: BTreeMap<i64, i64> =
            a.order.iter().enumerate().map(|(new, &old)| (old, new as i64)).collect();
        for s in &steps {
            for d in &s.depends_on {
                if *d < s.idx && new_index[d] > new_index[&s.idx] {
                    return Err(UaError::invalid(format!(
                        "order moves step {} ahead of step {d}, which it depends on",
                        s.idx
                    )));
                }
            }
        }
        apply_layout(tx, &steps, &new_index, &ts)?;
        let out = structure_result(
            tx,
            &caller,
            &a.plan_id,
            &ts,
            "agent.plan.steps_reordered",
            json!({ "order": a.order }),
            None,
        )?;
        Ok(Value::Object(out))
    })
}

fn edit(ctx: &ToolCtx, a: EditArgs) -> UaResult<Value> {
    if a.title.is_none() && a.description.is_none() {
        return Err(UaError::invalid("pass title, description or both"));
    }
    let title = match a.title.as_deref() {
        Some(t) => {
            let t = t.trim();
            if t.is_empty() || t.contains('\n') || t.chars().count() > TITLE_MAX {
                return Err(UaError::invalid(format!(
                    "title must be one nonempty line of at most {TITLE_MAX} characters"
                )));
            }
            Some(t.to_string())
        }
        None => None,
    };
    let description = match a.description.as_deref() {
        Some(d) => {
            let d = d.trim();
            if d.chars().count() > DESCRIPTION_MAX {
                return Err(UaError::invalid(format!(
                    "description must be at most {DESCRIPTION_MAX} characters"
                )));
            }
            Some(d.to_string())
        }
        None => None,
    };
    let caller = ctx.caller.clone();
    ctx.hub.db().write(|tx| {
        let (plan, _steps) = open_structure_edit(tx, &a.plan_id, a.expected_revision, false)?;
        let ts = ua_core::time::now();
        let (cur_title, cur_desc) = split_goal(plan["goal"].as_str().unwrap_or(""));
        let new_title = title.clone().unwrap_or(cur_title);
        let new_desc = description.clone().unwrap_or(cur_desc);
        let goal = if new_desc.is_empty() { new_title } else { format!("{new_title}\n\n{new_desc}") };
        tx.execute("UPDATE plans SET goal = ?2 WHERE id = ?1", params![a.plan_id, goal])?;
        let out = structure_result(tx, &caller, &a.plan_id, &ts, "agent.plan.edited", json!({}), None)?;
        Ok(Value::Object(out))
    })
}

// ---------------------------------------------------------------------------
// The consolidated entry point and registration.

const ACTIONS: [&str; 16] = [
    "create",
    "update",
    "get",
    "list",
    "checkpoint",
    "resume",
    "step_retry",
    "step_claim",
    "handoff",
    "close",
    "delete",
    "step_add",
    "step_edit",
    "step_remove",
    "step_reorder",
    "edit",
];

/// Canonical action name. Accepts the short forms `retry`/`claim` and the
/// legacy tool names (`plan_create`, `plan_step_claim`, ...).
pub(crate) fn canonical_action(action: &str) -> UaResult<&'static str> {
    let a = action.trim().to_ascii_lowercase();
    let a = a.strip_prefix("plan_").unwrap_or(&a);
    let a = match a {
        "retry" => "step_retry",
        "claim" => "step_claim",
        other => other,
    };
    ACTIONS
        .iter()
        .find(|x| **x == a)
        .copied()
        .ok_or_else(|| UaError::invalid(format!("action must be one of {ACTIONS:?}")))
}

fn dispatch(ctx: &ToolCtx, action: &str, params: Option<Value>) -> UaResult<Value> {
    let act = canonical_action(action)?;
    let p = params;
    match act {
        "create" => create(ctx, parse_params("plan", act, p)?),
        "update" => update(ctx, parse_params("plan", act, p)?),
        "get" => get(ctx, parse_params("plan", act, p)?),
        "list" => list(ctx, parse_params("plan", act, p)?),
        "checkpoint" => checkpoint(ctx, parse_params("plan", act, p)?),
        "resume" => resume(ctx, parse_params("plan", act, p)?),
        "step_retry" => step_retry(ctx, parse_params("plan", act, p)?),
        "step_claim" => step_claim(ctx, parse_params("plan", act, p)?),
        "handoff" => handoff(ctx, parse_params("plan", act, p)?),
        "close" => close(ctx, parse_params("plan", act, p)?),
        "delete" => delete(ctx, parse_params("plan", act, p)?),
        "step_add" => step_add(ctx, parse_params("plan", act, p)?),
        "step_edit" => step_edit(ctx, parse_params("plan", act, p)?),
        "step_remove" => step_remove(ctx, parse_params("plan", act, p)?),
        "step_reorder" => step_reorder(ctx, parse_params("plan", act, p)?),
        "edit" => edit(ctx, parse_params("plan", act, p)?),
        other => Err(UaError::invalid(format!("unknown plan action {other:?}"))),
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "plan_manage",
            "Plan lifecycle in one tool: create, update, get, list, checkpoint, resume, step_retry, step_claim, \
             handoff, close, delete, step_add, step_edit, step_remove, step_reorder, edit. `params` holds the \
             action's arguments. Plans are storage only: nothing is executed.",
            |ctx: ToolCtx, a: ManageArgs| blocking(move || dispatch(&ctx, &a.action, a.params)),
        )
        .family("plans"),
    );
    r.add(
        tool(
            "plan_create",
            "Persist an ordered plan. Each step is a string or {description, owner?, depends_on?} with 0-based \
             depends_on indexes. Nothing is executed. Returns {plan_id, steps}.",
            |ctx: ToolCtx, a: CreateArgs| blocking(move || create(&ctx, a)),
        )
        .family("plans"),
    );
    r.add(
        tool(
            "plan_update",
            "Set one step's status, note or owner. `done` stamps done_at; when every step is done the plan \
             completes unless escalated. Dependency order is not enforced here.",
            |ctx: ToolCtx, a: UpdateArgs| blocking(move || update(&ctx, a)),
        )
        .family("plans"),
    );
    r.add(
        tool(
            "plan_get",
            "Read a plan: metadata, steps, checkpoints and next_step_idx. needs_human is true once a step \
             exhausted its retries.",
            |ctx: ToolCtx, a: PlanIdArgs| blocking(move || get(&ctx, a)),
        )
        .family("plans")
        .read_only(),
    );
    r.add(
        tool(
            "plan_list",
            "List plans by status (active, done, blocked, abandoned or all), newest first, optionally by scope.",
            |ctx: ToolCtx, a: ListArgs| blocking(move || list(&ctx, a)),
        )
        .family("plans")
        .read_only(),
    );
    r.add(
        tool(
            "plan_checkpoint",
            "Store a sequenced context slice (memory ids, file paths, outputs map) plus the live step state, \
             for plan_resume.",
            |ctx: ToolCtx, a: CheckpointArgs| blocking(move || checkpoint(&ctx, a)),
        )
        .family("plans"),
    );
    r.add(
        tool(
            "plan_resume",
            "Return the plan, live steps, the next actionable step and a checkpoint (the latest, or \
             from_checkpoint by sequence; null when none exists).",
            |ctx: ToolCtx, a: ResumeArgs| blocking(move || resume(&ctx, a)),
        )
        .family("plans")
        .read_only(),
    );
    r.add(
        tool(
            "plan_step_retry",
            "Record a failed attempt: increments retries, marks the step failed and appends the reason. At 3 \
             retries the step and plan become blocked with needs_human. Sends nothing.",
            |ctx: ToolCtx, a: RetryArgs| blocking(move || step_retry(&ctx, a)),
        )
        .family("plans"),
    );
    r.add(
        tool(
            "plan_step_claim",
            "Atomically claim one open or failed step whose dependencies are all done. Re-claiming your own \
             failed step is allowed; a lost race names the current owner.",
            |ctx: ToolCtx, a: ClaimArgs| blocking(move || step_claim(&ctx, a)),
        )
        .family("plans"),
    );
    r.add(
        tool(
            "plan_handoff",
            "Mark a step done, store its outputs map, checkpoint, and return the next actionable step.",
            |ctx: ToolCtx, a: HandoffArgs| blocking(move || handoff(&ctx, a)),
        )
        .family("plans"),
    );
    r.add(
        tool(
            "plan_delete",
            "Delete a plan with its steps and checkpoints. Returns {deleted}.",
            |ctx: ToolCtx, a: PlanIdArgs| blocking(move || delete(&ctx, a)),
        )
        .family("plans"),
    );
}
