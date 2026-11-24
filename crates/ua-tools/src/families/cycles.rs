//! Autonomous cycles: a bounded, idempotent state machine for one unit of
//! autonomous development work.
//!
//! A cycle starts in `plan` and moves only along [`TRANSITIONS`]. Every
//! transition is a compare-and-swap on `version` (`expected_version`) keyed
//! by an `idempotency_key`, so a retry is safe and a stale writer is refused.
//! Entering `pr`, `completed`, `blocked` or `failed` needs a one-time human
//! approval (`autonomous_cycle:<action>` in the approval queue), except that a
//! green-path-eligible cycle may enter `completed` (and `pr`) without one.
//! Budgets (time, tokens, retries, cost) and `max_rework` block the cycle when
//! exceeded; the kill switch stops it from any non-terminal state.
//!
//! Tools: `autonomous_cycle_manage(action, params)` and the legacy
//! `autonomous_cycle_*` aliases, plus `autonomous_cycle_green_path_eligibility`.
//!
//! The three tables are tenant data (`org_id`, `organization.v1.tools.cycles`,
//! `cycles.v2.org_scope`). Every read and write is scoped to the caller's
//! organization: another organization's cycle answers exactly as a missing
//! one, and a write for an organization `orgs` does not hold is refused
//! before anything changes. No key needed a rebuild: a cycle id is a
//! hub-generated random id, and a transition's `(cycle_id, idempotency_key)`
//! and a usage row's `(cycle_id, usage_run_id, usage_id)` are led by it. A
//! transition or usage row always belongs to its cycle's organization (the
//! `*_org_parent` triggers). Nothing runs a cycle without a caller.
//!
//! A cycle may name a task and a delegation. Both are read in the cycle's
//! organization: another organization's task, or a delegation of another
//! organization's task, answers as a missing one (`cycles.v3.task_org` also
//! keeps a cycle's task in its own organization). Attempt-keyed usage and
//! the green path read the cycle's task in the cycle's organization.

use std::collections::BTreeSet;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{ActorKind, Caller, UaError, UaResult};
use ua_store::{Procedure, SchemaPart, WriteTx};

use crate::approvals::{self, GateOutcome};
use crate::families::plans::{emit, ledger_text, parse_params, row_map, write_identity};
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "cycles.v1",
    sql: "
CREATE TABLE IF NOT EXISTS autonomous_cycles (
    id TEXT PRIMARY KEY,
    task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
    plan_id TEXT,
    delegation_id INTEGER,
    state TEXT NOT NULL DEFAULT 'plan'
        CHECK (state IN ('plan','delegated','executing','validating','reviewing',
                         'rework','pr','blocked','completed','failed','killed')),
    max_rework INTEGER NOT NULL DEFAULT 2 CHECK (max_rework >= 0),
    rework_count INTEGER NOT NULL DEFAULT 0 CHECK (rework_count >= 0),
    max_time_s REAL NOT NULL CHECK (max_time_s > 0),
    max_tokens INTEGER NOT NULL CHECK (max_tokens > 0),
    max_retries INTEGER NOT NULL CHECK (max_retries > 0),
    max_cost_cents REAL NOT NULL CHECK (max_cost_cents > 0),
    used_time_s REAL NOT NULL DEFAULT 0 CHECK (used_time_s >= 0),
    used_tokens INTEGER NOT NULL DEFAULT 0 CHECK (used_tokens >= 0),
    used_retries INTEGER NOT NULL DEFAULT 0 CHECK (used_retries >= 0),
    used_cost_cents REAL NOT NULL DEFAULT 0 CHECK (used_cost_cents >= 0),
    allowed_capabilities TEXT,
    stop_reason TEXT,
    pr_url TEXT,
    version INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_autonomous_cycles_state ON autonomous_cycles(state);
CREATE INDEX IF NOT EXISTS idx_autonomous_cycles_task ON autonomous_cycles(task_id);

CREATE TABLE IF NOT EXISTS autonomous_cycle_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id TEXT NOT NULL REFERENCES autonomous_cycles(id) ON DELETE CASCADE,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (cycle_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS autonomous_cycle_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id TEXT NOT NULL REFERENCES autonomous_cycles(id) ON DELETE CASCADE,
    usage_run_id TEXT NOT NULL,
    usage_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (cycle_id, usage_run_id, usage_id)
);
",
};

/// `organization.v1.tools.cycles`: `org_id` on `autonomous_cycles`,
/// `autonomous_cycle_transitions` and `autonomous_cycle_usage` (existing rows
/// backfilled to the default organization) and their generated
/// `*_org_exists` / `*_org_immutable` triggers. No key needs a rebuild (see
/// the module docs). Applied after `cycles.v1` and `organization.v1.store`.
pub const TENANT_PART: Procedure = ua_store::org::tenant_part(
    "organization.v1.tools.cycles",
    &["autonomous_cycles", "autonomous_cycle_transitions", "autonomous_cycle_usage"],
);

/// `cycles.v2.org_scope`: the index the per-organization cycle list uses, and
/// triggers that keep a transition or usage row in its cycle's organization
/// (the `cycle_id` foreign key alone would accept a cycle in another
/// organization). A missing cycle is still the foreign key's error. Applied
/// after `organization.v1.tools.cycles`.
pub const ORG_SCOPE: SchemaPart = SchemaPart {
    name: "cycles.v2.org_scope",
    sql: "
CREATE INDEX IF NOT EXISTS idx_autonomous_cycles_org_state ON autonomous_cycles(org_id, state, updated_at);

CREATE TRIGGER IF NOT EXISTS autonomous_cycle_transitions_org_parent BEFORE INSERT ON autonomous_cycle_transitions
WHEN EXISTS (SELECT 1 FROM autonomous_cycles WHERE id = NEW.cycle_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'cycle belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS autonomous_cycle_transitions_org_parent_update
BEFORE UPDATE OF cycle_id ON autonomous_cycle_transitions
WHEN EXISTS (SELECT 1 FROM autonomous_cycles WHERE id = NEW.cycle_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'cycle belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS autonomous_cycle_usage_org_parent BEFORE INSERT ON autonomous_cycle_usage
WHEN EXISTS (SELECT 1 FROM autonomous_cycles WHERE id = NEW.cycle_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'cycle belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS autonomous_cycle_usage_org_parent_update
BEFORE UPDATE OF cycle_id ON autonomous_cycle_usage
WHEN EXISTS (SELECT 1 FROM autonomous_cycles WHERE id = NEW.cycle_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'cycle belongs to another organization'); END;
",
};

/// `cycles.v3.task_org`: a cycle's `task_id` points at a task in the cycle's
/// own organization (the foreign key alone would accept another
/// organization's task). A missing task is still the foreign key's error.
/// Applied after `organization.v1.tools.tasks`.
pub const TASK_ORG_SCHEMA: SchemaPart = SchemaPart {
    name: "cycles.v3.task_org",
    sql: "
CREATE TRIGGER IF NOT EXISTS autonomous_cycles_task_org BEFORE INSERT ON autonomous_cycles
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'an autonomous cycle must point at a task in its own organization'); END;
CREATE TRIGGER IF NOT EXISTS autonomous_cycles_task_org_update BEFORE UPDATE OF task_id ON autonomous_cycles
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'an autonomous cycle must point at a task in its own organization'); END;
",
};

pub const STATES: [&str; 11] = [
    "plan",
    "delegated",
    "executing",
    "validating",
    "reviewing",
    "rework",
    "pr",
    "blocked",
    "completed",
    "failed",
    "killed",
];
const TERMINAL: [&str; 3] = ["completed", "failed", "killed"];

/// Legal next states.
pub fn transitions(from: &str) -> &'static [&'static str] {
    match from {
        "plan" => &["delegated", "blocked", "failed", "killed"],
        "delegated" => &["executing", "blocked", "failed", "killed"],
        "executing" => &["validating", "rework", "blocked", "failed", "killed"],
        "validating" => &["reviewing", "rework", "blocked", "failed", "killed"],
        "reviewing" => &["pr", "rework", "blocked", "failed", "killed"],
        "rework" => &["delegated", "executing", "blocked", "failed", "killed"],
        "pr" => &["completed", "blocked", "failed", "killed"],
        "blocked" => &["plan", "failed", "killed"],
        _ => &[],
    }
}

/// The approval action a target state needs, if any.
fn approval_action(to: &str) -> Option<&'static str> {
    match to {
        "pr" => Some("external_mutation"),
        "completed" => Some("merge"),
        "blocked" | "failed" => Some("escalation"),
        _ => None,
    }
}

static EVIDENCE_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^https?://\S+$").expect("static regex"));
static EVIDENCE_SHA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{7,40}$").expect("static regex"));

/// Changed paths that always need a human merge decision.
const RED_TIER_PATTERNS: &[&str] = &[
    r"config\.ya?ml$",
    r"\.env",
    r"SOUL\.md",
    r"SKILL\.md",
    r"AGENTS\.md",
    r"CLAUDE\.md",
    r"GEMINI\.md",
    r"\.cursorrules$",
    r"(^|/)SECURITY\.md$",
    r"(^|/)security/",
    r"security[^/]*\.(py|rs)$",
    r"safety\.(py|rs)$",
    r"server\.py$",
    r"deploy/",
    r"hooks?/",
    r"\.mcp\.json$",
    r"mcp_config\.json$",
    r"(^|/)\.github/workflows/",
    r"(^|/)\.depot/",
    r"(^|/)policy\.(py|rs|ya?ml)$",
    r"(^|/)approvals\.rs$",
    r"(^|/)registry\.rs$",
    r"(^|/)cycles\.rs$",
];

static RED_TIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&RED_TIER_PATTERNS.join("|")).expect("static regex"));

const VALIDATION_TIMEOUT: Duration = Duration::from_secs(900);
/// Validation output is drained and discarded past this many bytes per stream.
const VALIDATION_OUTPUT_CAP: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Helpers

fn actor(caller: &Caller, agent: &str) -> UaResult<String> {
    let label = write_identity(caller, Some(agent))?;
    if label.trim().is_empty() {
        return Err(UaError::invalid("an agent identity is required"));
    }
    Ok(label)
}

fn new_cycle_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// Refuse an organization `orgs` does not hold, before anything is written.
/// The `org_exists` triggers fire only on insert, so a write with nothing to
/// insert (a transition's update, a kill) would otherwise pass.
fn require_org(c: &Connection, org: &str) -> UaResult<()> {
    let known = c.query_row("SELECT 1 FROM orgs WHERE id = ?1", [org], |_| Ok(())).optional()?.is_some();
    if !known {
        return Err(UaError::denied(
            "unknown_organization",
            format!("unknown organization {org:?}; no autonomous cycle was changed"),
        ));
    }
    Ok(())
}

/// The cycle `id` of `org`. Another organization's cycle answers exactly as
/// a missing one.
fn cycle_json(c: &Connection, org: &str, id: &str) -> UaResult<Option<Map<String, Value>>> {
    Ok(c.query_row("SELECT * FROM autonomous_cycles WHERE org_id = ?1 AND id = ?2", params![org, id], |r| {
        let mut m = row_map(r)?;
        let caps = m
            .get("allowed_capabilities")
            .and_then(Value::as_str)
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .unwrap_or(Value::Null);
        m.insert("allowed_capabilities".into(), caps);
        Ok(m)
    })
    .optional()?)
}

fn require_cycle(c: &Connection, org: &str, id: &str) -> UaResult<Map<String, Value>> {
    cycle_json(c, org, id)?.ok_or_else(|| UaError::not_found(format!("no autonomous cycle with id {id:?}")))
}

fn s<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(Value::as_str)
}

fn i(m: &Map<String, Value>, k: &str) -> i64 {
    m.get(k).and_then(Value::as_i64).unwrap_or(0)
}

fn f(m: &Map<String, Value>, k: &str) -> f64 {
    m.get(k).and_then(Value::as_f64).unwrap_or(0.0)
}

fn allowed_caps(m: &Map<String, Value>) -> Option<Vec<String>> {
    m.get("allowed_capabilities")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
}

/// One transition of `org` matching `where_sql` (whose own parameters are
/// `?1`..`?n`; the organization is bound after them).
fn transition_json(
    c: &Connection,
    org: &str,
    where_sql: &str,
    p: &[&dyn rusqlite::ToSql],
) -> UaResult<Option<Value>> {
    let sql = format!(
        "SELECT id, cycle_id, from_state, to_state, idempotency_key, actor, reason, created_at \
         FROM autonomous_cycle_transitions WHERE ({where_sql}) AND org_id = ?{}",
        p.len() + 1
    );
    let mut all: Vec<&dyn rusqlite::ToSql> = p.to_vec();
    all.push(&org);
    Ok(c.query_row(&sql, all.as_slice(), |r| Ok(Value::Object(row_map(r)?))).optional()?)
}

/// Append `agent.cycle.updated` to the default organization's ledger
/// (`ORG-EVENT-DEFAULT`, through `emit`). For a cycle outside it, the stop
/// reason (caller-supplied text) is `null`, and the event is attributed to
/// the caller's own label rather than the agent a system or anonymous caller
/// claims to act as.
fn updated_event(
    tx: &mut WriteTx<'_>,
    caller: &Caller,
    actor: &str,
    cycle: &Map<String, Value>,
    action: &str,
    extra: Value,
) -> UaResult<()> {
    let org = s(cycle, "org_id").unwrap_or(ua_core::DEFAULT_ORG);
    let mut payload = json!({
        "action": action,
        "cycle_id": cycle.get("id"),
        "task_id": cycle.get("task_id"),
        "state": cycle.get("state"),
        "version": cycle.get("version"),
        "stop_reason": s(cycle, "stop_reason").map_or(Value::Null, |r| ledger_text(org, r)),
    });
    if let (Some(p), Value::Object(e)) = (payload.as_object_mut(), extra) {
        p.extend(e);
    }
    let by = if org == ua_core::DEFAULT_ORG { actor } else { caller.label.as_str() };
    let caller = Caller { label: by.to_string(), ..Caller::system() };
    emit(tx, &caller, "agent.cycle.updated", payload)
}

// ---------------------------------------------------------------------------
// start

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StartArgs {
    /// The acting agent; must be the authenticated caller.
    pub agent: String,
    pub task_id: Option<i64>,
    pub plan_id: Option<String>,
    pub delegation_id: Option<i64>,
    /// Rework transitions allowed before the cycle blocks (0-20, default 2).
    #[serde(default = "two")]
    pub max_rework: i64,
    /// Positive `time_s`, `tokens`, `retries`, `cost_cents`; omitted ones use
    /// the hub's `autonomy_max_*` defaults.
    pub budgets: Option<Map<String, Value>>,
    /// Tool names this cycle may use; each must be visible to the agent's
    /// default profile, else the cycle starts `blocked`.
    pub capabilities: Option<Vec<String>>,
}

fn two() -> i64 {
    2
}

async fn start(ctx: ToolCtx, a: StartArgs) -> UaResult<Value> {
    let actor = actor(&ctx.caller, &a.agent)?;
    if !(0..=20).contains(&a.max_rework) {
        return Err(UaError::invalid("max_rework must be between 0 and 20"));
    }
    let cfg = ctx.hub.cfg();
    let mut time_s = cfg.autonomy_max_time_s;
    let mut tokens = cfg.autonomy_max_tokens as f64;
    let mut retries = cfg.autonomy_max_retries as f64;
    let mut cost = cfg.autonomy_max_cost_cents;
    for (k, v) in a.budgets.unwrap_or_default() {
        let n = v.as_f64().ok_or_else(|| UaError::invalid(format!("budget {k} must be a number")))?;
        match k.as_str() {
            "time_s" => time_s = n,
            "tokens" => tokens = n,
            "retries" => retries = n,
            "cost_cents" => cost = n,
            other => return Err(UaError::invalid(format!("unknown budget {other:?}"))),
        }
    }
    if [time_s, tokens, retries, cost].iter().any(|v| !v.is_finite() || *v <= 0.0) {
        return Err(UaError::invalid("autonomy budgets must be positive and finite"));
    }
    if tokens.fract() != 0.0 || retries.fract() != 0.0 {
        return Err(UaError::invalid("tokens and retries budgets must be whole numbers"));
    }
    let requested: Option<BTreeSet<String>> = match a.capabilities {
        None => None,
        Some(list) => {
            if list.iter().any(|c| c.trim().is_empty()) {
                return Err(UaError::invalid("capabilities must be a list of non-empty tool names"));
            }
            Some(list.into_iter().collect())
        }
    };
    let profile = crate::sessions::default_profile(&ctx.hub, &ctx.caller.org_id, &actor);
    let registry = crate::families::workflows::step_registry();
    let denied: Vec<String> = requested
        .iter()
        .flatten()
        .filter(|c| registry.get(c).is_none() || !profile.allows_tool(c))
        .cloned()
        .collect();
    let (state, stop_reason) = if denied.is_empty() {
        ("plan", None)
    } else {
        ("blocked", Some(format!("capability policy denied: {}", denied.join(", "))))
    };
    let caps_json =
        requested.map(|r| serde_json::to_string(&r.into_iter().collect::<Vec<_>>())).transpose()?;
    let id = new_cycle_id();
    let (task_id, plan_id, delegation_id, max_rework) = (a.task_id, a.plan_id, a.delegation_id, a.max_rework);
    let (caller, org) = (ctx.caller.clone(), ctx.caller.org_id.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            // A task, and the delegation tied to one, is read in the cycle's
            // organization: another organization's answers as a missing one.
            if let Some(t) = task_id
                && tx
                    .query_row("SELECT 1 FROM tasks WHERE org_id = ?1 AND id = ?2", params![org, t], |_| Ok(()))
                    .optional()?
                    .is_none()
            {
                return Err(UaError::not_found(format!("no task with id {t}")));
            }
            if let Some(d) = delegation_id
                && tx
                    .query_row(
                        "SELECT 1 FROM delegations WHERE org_id = ?1 AND id = ?2",
                        params![org, d],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_none()
            {
                return Err(UaError::not_found(format!("no delegation with id {d}")));
            }
            let now = ua_core::time::now();
            tx.execute(
                "INSERT INTO autonomous_cycles (org_id, id, task_id, plan_id, delegation_id, state, max_rework, \
                 max_time_s, max_tokens, max_retries, max_cost_cents, allowed_capabilities, stop_reason, created_by, \
                 created_at, updated_at) VALUES (?15, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14)",
                params![
                    id,
                    task_id,
                    plan_id,
                    delegation_id,
                    state,
                    max_rework,
                    time_s,
                    tokens as i64,
                    retries as i64,
                    cost,
                    caps_json,
                    stop_reason,
                    actor,
                    now,
                    org
                ],
            )?;
            let cycle = require_cycle(tx, &org, &id)?;
            updated_event(tx, &caller, &actor, &cycle, "start", json!({}))?;
            Ok(json!({ "cycle": cycle, "created": true }))
        })
        .await
}

// ---------------------------------------------------------------------------
// get / list / get_for_task

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetArgs {
    pub cycle_id: String,
}

async fn get(ctx: ToolCtx, a: GetArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let cycle = require_cycle(c, &org, &a.cycle_id)?;
            let mut stmt = c.prepare(
                "SELECT id, cycle_id, from_state, to_state, idempotency_key, actor, reason, created_at \
                 FROM autonomous_cycle_transitions WHERE org_id = ?1 AND cycle_id = ?2 ORDER BY id",
            )?;
            let rows = stmt.query_map(params![org, a.cycle_id], |r| Ok(Value::Object(row_map(r)?)))?;
            let transitions: Vec<Value> = rows.collect::<Result<_, _>>()?;
            Ok(json!({ "cycle": cycle, "transitions": transitions }))
        })
        .await
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Only cycles in this state.
    pub state: Option<String>,
    /// 1-500, default 100.
    #[serde(default = "hundred")]
    pub limit: i64,
}

fn hundred() -> i64 {
    100
}

async fn list(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    if let Some(st) = &a.state
        && !STATES.contains(&st.as_str())
    {
        return Err(UaError::invalid(format!("state must be one of {STATES:?}")));
    }
    let limit = a.limit.clamp(1, 500);
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT id FROM autonomous_cycles WHERE org_id = ?1 AND (?2 IS NULL OR state = ?2) \
                 ORDER BY updated_at DESC, rowid DESC LIMIT ?3",
            )?;
            let ids: Vec<String> =
                stmt.query_map(params![org, a.state, limit], |r| r.get(0))?.collect::<Result<_, _>>()?;
            let cycles: Vec<Value> = ids
                .iter()
                .map(|id| require_cycle(c, &org, id).map(Value::Object))
                .collect::<UaResult<_>>()?;
            Ok(json!({ "cycles": cycles }))
        })
        .await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForTaskParams {
    task_id: i64,
}

/// The newest cycle governing a task. Excludes only `completed` and
/// `failed`: a `killed` cycle must stay visible so the kill switch holds.
/// Only the caller's organization's cycles count.
async fn get_for_task(ctx: ToolCtx, a: ForTaskParams) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let id: Option<String> = c
                .query_row(
                    "SELECT id FROM autonomous_cycles WHERE org_id = ?1 AND task_id = ?2 \
                     AND state NOT IN ('completed','failed') ORDER BY updated_at DESC, rowid DESC LIMIT 1",
                    params![org, a.task_id],
                    |r| r.get(0),
                )
                .optional()?;
            let cycle = match id {
                Some(id) => Value::Object(require_cycle(c, &org, &id)?),
                None => Value::Null,
            };
            Ok(json!({ "cycle": cycle }))
        })
        .await
}

// ---------------------------------------------------------------------------
// transition

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransitionArgs {
    pub cycle_id: String,
    /// Target state.
    pub to_state: String,
    /// Retry token (1-128 characters): repeating it returns the first result.
    pub idempotency_key: String,
    /// The acting agent; must be the authenticated caller.
    pub agent: String,
    /// Refuse unless the cycle's `version` still equals this.
    pub expected_version: Option<i64>,
    /// Required for `blocked`, `failed` and `killed`.
    pub reason: Option<String>,
    /// Required for `pr`: an http(s) URL or a commit SHA.
    pub pr_url: Option<String>,
    /// Capability this step uses; one outside the cycle's list blocks it.
    pub capability: Option<String>,
}

enum Phase {
    Done(Value),
    Go(Map<String, Value>),
}

fn check_live(
    cycle: &Map<String, Value>,
    org: &str,
    a: &TransitionArgs,
    key: &str,
    c: &Connection,
) -> UaResult<Phase> {
    if let Some(existing) =
        transition_json(c, org, "cycle_id = ?1 AND idempotency_key = ?2", &[&a.cycle_id, &key])?
    {
        if existing["to_state"] != a.to_state && !(existing["to_state"] == "blocked") {
            return Err(UaError::conflict("idempotency key was already used for another transition"));
        }
        return Ok(Phase::Done(json!({ "cycle": cycle, "transition": existing, "idempotent": true })));
    }
    let version = i(cycle, "version");
    if let Some(expected) = a.expected_version
        && expected != version
    {
        return Err(UaError::conflict(format!(
            "stale cycle version: expected {expected}, current {version}"
        )));
    }
    let current = s(cycle, "state").unwrap_or_default();
    if !transitions(current).contains(&a.to_state.as_str()) {
        return Err(UaError::conflict(format!("invalid transition {current:?} -> {:?}", a.to_state)));
    }
    Ok(Phase::Go(cycle.clone()))
}

async fn transition(ctx: ToolCtx, a: TransitionArgs) -> UaResult<Value> {
    let actor = actor(&ctx.caller, &a.agent)?;
    if !STATES.contains(&a.to_state.as_str()) {
        return Err(UaError::invalid(format!("to_state must be one of {STATES:?}")));
    }
    let key = a.idempotency_key.trim().to_string();
    if key.is_empty() || key.len() > 128 {
        return Err(UaError::invalid("idempotency_key is required and must be at most 128 characters"));
    }
    if ["blocked", "failed", "killed"].contains(&a.to_state.as_str())
        && a.reason.as_deref().is_none_or(|r| r.trim().is_empty())
    {
        return Err(UaError::invalid(format!("reason is required when stopping in {}", a.to_state)));
    }
    let pr_url = a.pr_url.as_deref().map(str::trim).filter(|p| !p.is_empty()).map(String::from);
    if a.to_state == "pr" {
        let Some(p) = &pr_url else {
            return Err(UaError::invalid("pr_url is required before entering pr state"));
        };
        if !(EVIDENCE_URL.is_match(p) || EVIDENCE_SHA.is_match(p)) {
            return Err(UaError::invalid(
                "pr_url must be a verifiable pointer (an http(s) URL or a 7-40 character commit SHA), not free text",
            ));
        }
    }

    // Phase 1: read and validate without holding the write lock. An unknown
    // organization is refused here, before the approval gate writes anything.
    let a = std::sync::Arc::new(a);
    let org = ctx.caller.org_id.clone();
    let (a1, k1, o1) = (a.clone(), key.clone(), org.clone());
    let phase = ctx
        .hub
        .db()
        .read_async(move |c| {
            require_org(c, &o1)?;
            let cycle = require_cycle(c, &o1, &a1.cycle_id)?;
            check_live(&cycle, &o1, &a1, &k1, c)
        })
        .await?;
    let cycle = match phase {
        Phase::Done(v) => return Ok(v),
        Phase::Go(c) => c,
    };
    let caps = allowed_caps(&cycle);
    let capability_denied = match (&caps, &a.capability) {
        (Some(list), Some(cap)) => !list.contains(cap),
        _ => false,
    };
    let mut gate_action = if capability_denied { None } else { approval_action(&a.to_state) };

    // The green-path and auto-PR checks run validation gates that can take
    // minutes, so they run outside any transaction.
    let mut bypass_reasons: Option<(String, Vec<String>)> = None;
    if let Some(action @ ("merge" | "external_mutation")) = gate_action {
        let task_id = cycle.get("task_id").and_then(Value::as_i64);
        let mode = if action == "merge" { Mode::Merge } else { Mode::Pr(pr_url.clone()) };
        let verdict = eligibility(&ctx.hub, &org, task_id, &cycle, mode).await;
        if verdict.eligible {
            let tag = if action == "merge" { "[green-path auto-merge]" } else { "[auto-pr]" };
            bypass_reasons = Some((tag.to_string(), verdict.reasons));
            gate_action = None;
        }
    }
    if let Some(action) = gate_action {
        // The payload binds the cycle's organization, so a pass is never
        // consumed across organizations.
        let payload = json!({
            "org_id": org,
            "cycle_id": a.cycle_id,
            "to_state": a.to_state,
            "idempotency_key": key,
            "expected_version": a.expected_version,
            "pr_url": pr_url,
        });
        let gate_tool = format!("autonomous_cycle:{action}");
        let (h, c, g) = (ctx.hub.clone(), ctx.caller.clone(), gate_tool.clone());
        let outcome =
            ctx.hub.db().write_async(move |tx| approvals::gate(tx, h.cfg(), &c, &g, &payload)).await?;
        match outcome {
            GateOutcome::Pass { .. } => {}
            GateOutcome::Pending { approval_id } => {
                return Err(UaError::ApprovalRequired { tool: gate_tool, approval_id });
            }
            GateOutcome::Denied { approval_id, reason } => {
                return Err(UaError::denied(
                    "approval_denied",
                    format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                ));
            }
        }
    }

    // Phase 2: revalidate against a fresh row and apply.
    let a2 = a.clone();
    let caller = ctx.caller.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let cycle = require_cycle(tx, &org, &a2.cycle_id)?;
            let cycle = match check_live(&cycle, &org, &a2, &key, tx)? {
                Phase::Done(v) => return Ok(v),
                Phase::Go(c) => c,
            };
            let current = s(&cycle, "state").unwrap_or_default().to_string();
            let mut rework = i(&cycle, "rework_count");
            let mut final_state = if capability_denied { "blocked".to_string() } else { a2.to_state.clone() };
            let mut final_reason = if capability_denied {
                Some(format!("capability policy denied: {}", a2.capability.clone().unwrap_or_default()))
            } else if let Some((tag, reasons)) = &bypass_reasons {
                Some(format!("{tag} {}", reasons.join("; ")))
            } else {
                a2.reason.as_deref().map(str::trim).map(String::from)
            };
            if a2.to_state == "rework" && !capability_denied {
                rework += 1;
                if rework > i(&cycle, "max_rework") {
                    final_state = "blocked".into();
                    final_reason = Some("rework budget exhausted".into());
                }
            }
            // An auto-PR rationale belongs on the transition row only: `pr` is
            // a mid-cycle success state and a stop_reason would make the
            // cycle ineligible for the green path one step later.
            let auto_pr = bypass_reasons.as_ref().is_some_and(|(t, _)| t == "[auto-pr]");
            let stop_reason = if auto_pr { s(&cycle, "stop_reason").map(String::from) } else { final_reason.clone() };
            let pr = pr_url.clone().or_else(|| s(&cycle, "pr_url").map(String::from));
            let now = ua_core::time::now();
            let n = tx.execute(
                "UPDATE autonomous_cycles SET state = ?1, rework_count = ?2, stop_reason = ?3, pr_url = ?4, \
                 version = version + 1, updated_at = ?5 WHERE org_id = ?8 AND id = ?6 AND version = ?7",
                params![final_state, rework, stop_reason, pr, now, a2.cycle_id, i(&cycle, "version"), org],
            )?;
            if n != 1 {
                return Err(UaError::conflict("cycle changed concurrently; retry with the current version"));
            }
            tx.execute(
                "INSERT INTO autonomous_cycle_transitions (org_id, cycle_id, from_state, to_state, idempotency_key, \
                 actor, reason, created_at) VALUES (?8, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![a2.cycle_id, current, final_state, key, actor, final_reason, now, org],
            )?;
            let tid = tx.last_insert_rowid();
            let updated = require_cycle(tx, &org, &a2.cycle_id)?;
            let transition = transition_json(tx, &org, "id = ?1", &[&tid])?.unwrap_or(Value::Null);
            updated_event(tx, &caller, &actor, &updated, "transition", json!({ "from_state": current }))?;
            Ok(json!({ "cycle": updated, "transition": transition, "idempotent": false }))
        })
        .await
}

// ---------------------------------------------------------------------------
// kill

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KillArgs {
    pub cycle_id: String,
    /// The acting agent; must be the authenticated caller.
    pub agent: String,
    /// Why the cycle is stopped (required).
    pub reason: String,
}

/// The kill switch: terminal `killed` from any non-terminal state, never
/// approval-gated. It does not signal running processes; executors check the
/// cycle state before each dispatch.
async fn kill(ctx: ToolCtx, a: KillArgs) -> UaResult<Value> {
    if a.reason.trim().is_empty() {
        return Err(UaError::invalid("reason is required to kill a cycle"));
    }
    let actor = actor(&ctx.caller, &a.agent)?;
    let (caller, org) = (ctx.caller.clone(), ctx.caller.org_id.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let cycle = require_cycle(tx, &org, &a.cycle_id)?;
            let current = s(&cycle, "state").unwrap_or_default().to_string();
            if TERMINAL.contains(&current.as_str()) {
                return Err(UaError::conflict(format!(
                    "cycle {:?} is already terminal ({current}); nothing to kill",
                    a.cycle_id
                )));
            }
            let reason = format!("killed by {actor}: {}", a.reason.trim());
            let now = ua_core::time::now();
            let n = tx.execute(
                "UPDATE autonomous_cycles SET state = 'killed', stop_reason = ?1, version = version + 1, \
                 updated_at = ?2 WHERE org_id = ?5 AND id = ?3 AND version = ?4",
                params![reason, now, a.cycle_id, i(&cycle, "version"), org],
            )?;
            if n != 1 {
                return Err(UaError::conflict("cycle changed concurrently; retry"));
            }
            let key = format!("kill-{}", ulid::Ulid::generate());
            tx.execute(
                "INSERT INTO autonomous_cycle_transitions (org_id, cycle_id, from_state, to_state, idempotency_key, \
                 actor, reason, created_at) VALUES (?7, ?1, ?2, 'killed', ?3, ?4, ?5, ?6)",
                params![a.cycle_id, current, key, actor, reason, now, org],
            )?;
            let updated = require_cycle(tx, &org, &a.cycle_id)?;
            updated_event(tx, &caller, &actor, &updated, "kill", json!({ "killed_from": current }))?;
            Ok(json!({ "cycle": updated, "killed_from": current }))
        })
        .await
}

// ---------------------------------------------------------------------------
// record_usage

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageArgs {
    pub cycle_id: String,
    /// The acting agent; must be the authenticated caller.
    pub agent: String,
    #[serde(default)]
    pub elapsed_s: f64,
    #[serde(default)]
    pub tokens: i64,
    #[serde(default)]
    pub retries: i64,
    #[serde(default)]
    pub cost_cents: f64,
    /// Capability used; one outside the cycle's list blocks it.
    pub capability: Option<String>,
    /// With `usage_id`: record this attempt once, even after the cycle
    /// stops. The caller must hold the claim on the cycle's task.
    pub usage_run_id: Option<String>,
    pub usage_id: Option<String>,
}

async fn record_usage(ctx: ToolCtx, a: UsageArgs) -> UaResult<Value> {
    let actor = actor(&ctx.caller, &a.agent)?;
    if [a.elapsed_s, a.cost_cents].iter().any(|v| !v.is_finite() || *v < 0.0) || a.tokens < 0 || a.retries < 0
    {
        return Err(UaError::invalid("usage values must be finite and nonnegative"));
    }
    if a.usage_run_id.is_some() != a.usage_id.is_some() {
        return Err(UaError::invalid("usage_run_id and usage_id must be supplied together"));
    }
    if let Some(id) = &a.usage_id
        && (id.trim().is_empty() || id.len() > 128)
    {
        return Err(UaError::invalid("usage_id must be nonempty and at most 128 characters"));
    }
    let verified = matches!(ctx.caller.kind, ActorKind::Agent | ActorKind::Human);
    let (caller, org) = (ctx.caller.clone(), ctx.caller.org_id.clone());
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let cycle = require_cycle(tx, &org, &a.cycle_id)?;
            let state = s(&cycle, "state").unwrap_or_default().to_string();
            let terminal = TERMINAL.contains(&state.as_str());
            if let (Some(run_id), Some(usage_id)) = (&a.usage_run_id, &a.usage_id) {
                if !verified {
                    return Err(UaError::denied(
                        "unverified_identity",
                        "attempt-keyed usage requires an authenticated caller",
                    ));
                }
                // The cycle's task, in the cycle's organization.
                let task_id = cycle.get("task_id").and_then(Value::as_i64);
                let task: Option<(Option<String>, Option<String>)> = match task_id {
                    Some(t) => tx
                        .query_row(
                            "SELECT claimed_by, current_run_id FROM tasks WHERE org_id = ?1 AND id = ?2",
                            params![org, t],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?,
                    None => None,
                };
                let owns = match &task {
                    Some((Some(claimant), run)) => {
                        claimant == &actor && run.as_deref().is_none_or(|r| r == run_id.as_str())
                    }
                    _ => false,
                };
                if !owns {
                    return Err(UaError::denied(
                        "not_owner",
                        "cycle usage requires the claimant of the cycle's bound task",
                    ));
                }
                let payload = json!({
                    "elapsed_s": a.elapsed_s,
                    "tokens": a.tokens,
                    "retries": a.retries,
                    "cost_cents": a.cost_cents,
                    "capability": a.capability,
                })
                .to_string();
                let previous: Option<String> = tx
                    .query_row(
                        "SELECT payload FROM autonomous_cycle_usage WHERE org_id = ?4 AND cycle_id = ?1 \
                         AND usage_run_id = ?2 AND usage_id = ?3",
                        params![a.cycle_id, run_id, usage_id, org],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(prev) = previous {
                    if prev != payload {
                        return Err(UaError::conflict("usage_id already recorded with different usage"));
                    }
                    return Ok(json!({
                        "cycle": cycle,
                        "blocked": state == "blocked",
                        "reason": cycle.get("stop_reason"),
                        "replayed": true,
                    }));
                }
                tx.execute(
                    "INSERT INTO autonomous_cycle_usage (org_id, cycle_id, usage_run_id, usage_id, actor, payload, \
                     created_at) VALUES (?7, ?1, ?2, ?3, ?4, ?5, ?6)",
                    params![a.cycle_id, run_id, usage_id, actor, payload, ua_core::time::now(), org],
                )?;
            } else if terminal {
                return Err(UaError::conflict(format!("cannot record usage for terminal cycle state {state:?}")));
            }

            let cap_denied = matches!((allowed_caps(&cycle), &a.capability), (Some(list), Some(cap)) if !list.contains(cap));
            let (mut used_t, mut used_k, mut used_r, mut used_c) = (
                f(&cycle, "used_time_s"),
                i(&cycle, "used_tokens"),
                i(&cycle, "used_retries"),
                f(&cycle, "used_cost_cents"),
            );
            let reason = if cap_denied {
                Some(format!("capability policy denied: {}", a.capability.clone().unwrap_or_default()))
            } else {
                used_t += a.elapsed_s;
                used_k = used_k.saturating_add(a.tokens);
                used_r = used_r.saturating_add(a.retries);
                used_c += a.cost_cents;
                let mut exceeded = Vec::new();
                if used_t > f(&cycle, "max_time_s") {
                    exceeded.push("time_s");
                }
                if used_k > i(&cycle, "max_tokens") {
                    exceeded.push("tokens");
                }
                if used_r > i(&cycle, "max_retries") {
                    exceeded.push("retries");
                }
                if used_c > f(&cycle, "max_cost_cents") {
                    exceeded.push("cost_cents");
                }
                (!exceeded.is_empty()).then(|| format!("autonomy budget exhausted: {}", exceeded.join(", ")))
            };
            let blocks_now = reason.is_some() && !terminal && state != "blocked";
            let new_state = if blocks_now { "blocked".to_string() } else { state.clone() };
            // A newly blocked cycle, or a blocked one exceeding again, takes the
            // new reason; otherwise (terminal, replay-keyed, or within budget)
            // the recorded stop reason is kept.
            let refresh = state == "blocked" && !terminal && a.usage_run_id.is_none() && reason.is_some();
            let stop_reason = if blocks_now || refresh {
                reason.clone()
            } else {
                s(&cycle, "stop_reason").map(String::from)
            };
            tx.execute(
                "UPDATE autonomous_cycles SET used_time_s = ?1, used_tokens = ?2, used_retries = ?3, \
                 used_cost_cents = ?4, state = ?5, stop_reason = ?6, version = version + 1, updated_at = ?7 \
                 WHERE org_id = ?9 AND id = ?8",
                params![
                    used_t,
                    used_k,
                    used_r,
                    used_c,
                    new_state,
                    stop_reason,
                    ua_core::time::now(),
                    a.cycle_id,
                    org
                ],
            )?;
            let updated = require_cycle(tx, &org, &a.cycle_id)?;
            updated_event(tx, &caller, &actor, &updated, "usage", json!({ "blocked": new_state == "blocked" }))?;
            Ok(json!({ "cycle": updated, "blocked": new_state == "blocked", "reason": stop_reason }))
        })
        .await
}

// ---------------------------------------------------------------------------
// Green-path eligibility

enum Mode {
    Merge,
    Pr(Option<String>),
}

pub(crate) struct Verdict {
    pub eligible: bool,
    pub reasons: Vec<String>,
}

fn no(mut reasons: Vec<String>, why: impl Into<String>) -> Verdict {
    reasons.push(why.into());
    Verdict { eligible: false, reasons }
}

/// Run git in an agent-controlled worktree with a cleared environment that
/// keeps repository config from starting a filesystem monitor or prompting.
async fn git(dir: &str, args: &[&str]) -> Option<String> {
    let env = crate::families::workspace::git_env();
    let out = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env_clear()
            .envs(env)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn sha_prefix_matches(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    a.len() >= 7 && b.len() >= 7 && (a.starts_with(&b) || b.starts_with(&a))
}

fn short(h: &str) -> String {
    h.chars().take(12).collect()
}

/// The commit `rev` names in the worktree, as a full SHA.
async fn resolve(dir: &str, rev: &str) -> Option<String> {
    if rev.starts_with('-') {
        return None;
    }
    let spec = format!("{rev}^{{commit}}");
    git(dir, &["rev-parse", "--verify", "--quiet", &spec])
        .await
        .filter(|h| h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// When the task names a branch, its tip must be the commit being validated.
async fn branch_matches(dir: &str, branch: Option<&str>, head: &str) -> Result<Option<String>, String> {
    let Some(b) = branch else { return Ok(None) };
    match resolve(dir, b).await {
        Some(tip) if tip == head => Ok(Some(format!("task branch {b:?} is at the validated commit"))),
        Some(tip) => {
            Err(format!("task branch {b:?} is at {}, not the worktree HEAD {}", short(&tip), short(head)))
        }
        None => {
            Err(format!("task branch {b:?} could not be resolved locally to bind it to the worktree HEAD"))
        }
    }
}

/// The validation command's environment: the dispatch executor's safe names
/// (never `UA_*` or credential-looking ones, and none of the `XDG_*`
/// directories that lead back into the operator's home), the operator's
/// `cycle_validation_env` additions under the same rules, and a fresh HOME.
pub(crate) fn validation_env(
    parent: impl IntoIterator<Item = (String, String)>,
    extra: &[String],
    home: &std::path::Path,
) -> Vec<(String, String)> {
    use crate::families::dispatch::executor::{SAFE_ENV, harness_may_pass, looks_secret};
    let mut env: Vec<(String, String)> = parent
        .into_iter()
        .filter(|(k, _)| {
            let safe = SAFE_ENV.contains(&k.as_str()) && !k.starts_with("XDG_");
            let listed = extra.iter().any(|n| n == k) && harness_may_pass(k);
            k != "HOME" && (safe || listed) && !looks_secret(k)
        })
        .collect();
    env.push(("HOME".into(), home.to_string_lossy().into_owned()));
    env
}

/// The green-path verdict: a decision, never an action. Checks in order
/// (first failure wins): state, recorded pr_url (merge only), no
/// stop_reason, the worktree HEAD (and the task branch tip, when named)
/// pinned, the PR head bound to that commit, a readable `main...<HEAD>` diff
/// touching no red-tier path, and the configured validation command passing
/// with the HEAD unchanged afterwards. A PR head that cannot be checked
/// offline (a URL rather than the head commit SHA) is never eligible.
/// `org` is the organization judging: another organization's task answers
/// as one without a worktree.
async fn eligibility(
    hub: &Hub,
    org: &str,
    task_id: Option<i64>,
    cycle: &Map<String, Value>,
    mode: Mode,
) -> Verdict {
    let mut reasons = Vec::new();
    let state = s(cycle, "state").unwrap_or_default();
    match &mode {
        Mode::Merge if !["pr", "completed"].contains(&state) => {
            return no(reasons, format!("cycle state is {state:?}, expected 'pr' or 'completed'"));
        }
        Mode::Pr(_) if state != "reviewing" => {
            return no(reasons, format!("cycle state is {state:?}, expected 'reviewing'"));
        }
        _ => reasons.push(format!("cycle state is {state:?}")),
    }
    let pr_head = match &mode {
        Mode::Merge => match s(cycle, "pr_url").map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => {
                reasons.push(format!("evidence recorded: {p}"));
                p.to_string()
            }
            None => return no(reasons, "no pr_url recorded"),
        },
        Mode::Pr(Some(p)) => p.clone(),
        Mode::Pr(None) => return no(reasons, "no pr_url given"),
    };
    if let Some(r) = s(cycle, "stop_reason").filter(|r| !r.is_empty()) {
        return no(reasons, format!("cycle carries a stop_reason: {r:?}"));
    }
    reasons.push("no stop_reason recorded".into());

    let Some(task_id) = task_id else { return no(reasons, "cycle has no task") };
    let task_org = org.to_string();
    let wt: Option<(Option<String>, Option<String>)> = hub
        .db()
        .read_async(move |c| {
            Ok(c.query_row(
                "SELECT worktree_path, branch FROM tasks WHERE org_id = ?1 AND id = ?2",
                params![task_org, task_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
        })
        .await
        .ok()
        .flatten();
    let Some((Some(dir), branch)) = wt else { return no(reasons, "no git worktree found for this task") };
    if !std::path::Path::new(&dir).is_dir() {
        return no(reasons, "no git worktree found for this task");
    }
    let branch = branch.map(|b| b.trim().to_string()).filter(|b| !b.is_empty());

    // Pin the commit everything below judges.
    let Some(head_before) = resolve(&dir, "HEAD").await else {
        return no(reasons, "worktree HEAD could not be resolved before validation");
    };
    match branch_matches(&dir, branch.as_deref(), &head_before).await {
        Ok(Some(why)) => reasons.push(why),
        Ok(None) => {}
        Err(why) => return no(reasons, why),
    }
    if !EVIDENCE_SHA.is_match(&pr_head) {
        return no(
            reasons,
            "PR head cannot be verified offline (pr_url is not the head commit SHA); holding for a human",
        );
    }
    if !sha_prefix_matches(&pr_head, &head_before) {
        return no(
            reasons,
            format!(
                "PR head {} is not the worktree HEAD {}; holding for a human",
                short(&pr_head),
                short(&head_before)
            ),
        );
    }
    reasons.push(format!("PR head bound to worktree HEAD {}", short(&head_before)));

    let mut changed = None;
    for base in ["main", "origin/main"] {
        let range = format!("{base}...{head_before}");
        if let Some(out) = git(&dir, &["diff", "--no-ext-diff", "--no-textconv", "--name-only", &range]).await
        {
            changed = Some(out);
            break;
        }
    }
    let files: Vec<String> = changed
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    if files.is_empty() {
        return no(reasons, "the change set is empty or could not be read; holding for a human");
    }
    let red: Vec<&str> = files.iter().map(String::as_str).filter(|f| RED_TIER.is_match(f)).collect();
    if !red.is_empty() {
        return no(reasons, format!("touches red-tier file(s): {}", red.join(", ")));
    }
    reasons.push("no red-tier files touched".into());

    let cfg = hub.cfg();
    let Some((program, args)) = cfg.cycle_validation_command.split_first() else {
        return no(reasons, "no validation gates configured (cycle_validation_command)");
    };
    let home = match crate::families::workspace::ScratchHome::new() {
        Ok(h) => h,
        Err(e) => return no(reasons, format!("validation gates could not start: {e}")),
    };
    let env = validation_env(std::env::vars(), &cfg.cycle_validation_env, &home.path);
    let run = crate::families::workspace::run_program(
        program,
        args,
        std::path::Path::new(&dir),
        &env,
        VALIDATION_TIMEOUT,
        VALIDATION_OUTPUT_CAP,
    )
    .await;
    drop(home);
    match run {
        Err(e) => return no(reasons, format!("validation gates could not start: {e}")),
        Ok(out) if out.timed_out => return no(reasons, "validation gates timed out"),
        Ok(out) if out.exit_code != 0 => {
            return no(reasons, format!("validation gates failed: exit code {}", out.exit_code));
        }
        Ok(_) => {}
    }
    let head_after = resolve(&dir, "HEAD").await;
    if head_after.as_deref() != Some(head_before.as_str()) {
        return no(
            reasons,
            format!(
                "worktree HEAD moved during validation (validated {}, now {})",
                short(&head_before),
                short(head_after.as_deref().unwrap_or("unresolved"))
            ),
        );
    }
    if let Err(why) = branch_matches(&dir, branch.as_deref(), &head_before).await {
        return no(reasons, format!("after validation: {why}"));
    }
    reasons.push(format!("validation gates passed at pinned commit {}", short(&head_before)));
    Verdict { eligible: true, reasons }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EligibilityArgs {
    /// A stored cycle to judge (its task is used).
    pub cycle_id: Option<String>,
    /// The task whose worktree is judged, with `cycle`.
    pub task_id: Option<i64>,
    /// A cycle summary (`state`, `pr_url`, `stop_reason`), with `task_id`.
    pub cycle: Option<Map<String, Value>>,
}

async fn green_path(ctx: ToolCtx, a: EligibilityArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    let (task_id, cycle) = match (a.cycle_id, a.task_id, a.cycle) {
        (Some(id), _, None) => {
            let o = org.clone();
            let cycle = ctx.hub.db().read_async(move |c| require_cycle(c, &o, &id)).await?;
            (a.task_id.or_else(|| cycle.get("task_id").and_then(Value::as_i64)), cycle)
        }
        (None, Some(t), Some(cycle)) => (Some(t), cycle),
        _ => return Err(UaError::invalid("pass cycle_id, or task_id with cycle")),
    };
    let v = eligibility(&ctx.hub, &org, task_id, &cycle, Mode::Merge).await;
    Ok(json!({ "eligible": v.eligible, "reasons": v.reasons }))
}

// ---------------------------------------------------------------------------
// autonomous_cycle_manage

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManageArgs {
    /// `start`, `get`, `get_for_task`, `transition`, `kill`, `record_usage` or `list`.
    pub action: String,
    /// The action's arguments, as for the matching `autonomous_cycle_*` tool;
    /// `get_for_task` takes `task_id`.
    pub params: Option<Value>,
}

async fn manage(ctx: ToolCtx, a: ManageArgs) -> UaResult<Value> {
    let fam = "autonomous_cycle_manage";
    let action = crate::routes::action_of(fam, Some(&a.action))?;
    match action {
        "start" => start(ctx, parse_params(fam, action, a.params)?).await,
        "get" => get(ctx, parse_params(fam, action, a.params)?).await,
        "get_for_task" => get_for_task(ctx, parse_params(fam, action, a.params)?).await,
        "transition" => transition(ctx, parse_params(fam, action, a.params)?).await,
        "kill" => kill(ctx, parse_params(fam, action, a.params)?).await,
        "record_usage" => record_usage(ctx, parse_params(fam, action, a.params)?).await,
        "list" => list(ctx, parse_params(fam, action, a.params)?).await,
        other => Err(crate::routes::unhandled(fam, other)),
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "autonomous_cycle_manage",
            "Autonomous-cycle lifecycle in one tool: action start, get, get_for_task, transition, kill, \
             record_usage or list, with that action's arguments in params. The state machine, idempotency \
             keys, expected_version checks, approval gates, budgets and kill switch all apply.",
            manage,
        )
        .handler_may_gate(crate::HandlerGate::Actions(&["transition"]))
        .family("cycles"),
    );
    r.add(
        tool(
            "autonomous_cycle_start",
            "Create a cycle in `plan` state (nothing executes). budgets may set positive time_s, tokens, \
             retries and cost_cents (defaults from the hub's autonomy_max_* settings); capabilities outside \
             the agent's profile start the cycle blocked.",
            start,
        )
        .family("cycles"),
    );
    r.add(
        tool(
            "autonomous_cycle_transition",
            "Apply one compare-and-swap transition through the bounded cycle state machine. Repeating an \
             idempotency_key returns the first result; a stale expected_version is refused. pr, completed, \
             blocked and failed need a human approval (autonomous_cycle:<action>) unless the green path \
             clears a merge or PR.",
            transition,
        )
        .handler_may_gate(crate::HandlerGate::Always)
        .family("cycles"),
    );
    r.add(
        tool(
            "autonomous_cycle_record_usage",
            "Atomically add usage (elapsed_s, tokens, retries, cost_cents). Crossing a budget or using a \
             capability outside the cycle's list blocks the cycle with a durable reason. usage_run_id plus \
             usage_id records one attempt idempotently.",
            record_usage,
        )
        .family("cycles"),
    );
    r.add(
        tool("autonomous_cycle_get", "Read one cycle and its transition history.", get)
            .family("cycles")
            .read_only(),
    );
    r.add(
        tool("autonomous_cycle_list", "List cycle summaries, newest first, optionally by state.", list)
            .family("cycles")
            .read_only(),
    );
    r.add(
        tool(
            "autonomous_cycle_kill",
            "Kill switch: force a cycle to terminal `killed` from any non-terminal state. Never approval-gated; \
             it does not signal running processes, executors refuse further dispatch for the cycle.",
            kill,
        )
        .family("cycles"),
    );
    r.add(
        tool(
            "autonomous_cycle_green_path_eligibility",
            "Green-path verdict for a cycle as {eligible, reasons}: state pr or completed, a pr_url that is \
             the PR head commit SHA and equals the worktree HEAD (and the task branch tip), no stop_reason, a \
             readable main...HEAD diff with no red-tier file, and the configured validation command passing \
             (cleared environment, fresh HOME) with HEAD unchanged. A PR head that cannot be checked offline \
             is never eligible. A decision only; it merges nothing.",
            green_path,
        )
        .family("cycles"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent() -> Vec<(String, String)> {
        [
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/srv/hub"),
            ("LANG", "C.UTF-8"),
            ("XDG_CONFIG_HOME", "/srv/hub/.config"),
            ("UA_AGENT_TOKENS", "hub-secret"),
            ("UA_HTTP_BEARER", "hub-secret"),
            ("UA_HOME", "/hub/state"),
            ("EXAMPLE_API_KEY", "hub-secret"),
            ("SOME_TOKEN", "hub-secret"),
            ("TOOLCHAIN_DIR", "/opt/toolchain"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .to_vec()
    }

    #[test]
    fn validation_env_keeps_hub_secrets_out() {
        // Even when an operator lists them, hub and credential names stay out.
        let extra: Vec<String> =
            ["TOOLCHAIN_DIR", "UA_AGENT_TOKENS", "UA_HOME", "EXAMPLE_API_KEY", "SOME_TOKEN"]
                .map(String::from)
                .to_vec();
        let env = validation_env(parent(), &extra, std::path::Path::new("/scratch/home"));
        let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["PATH", "LANG", "TOOLCHAIN_DIR", "HOME"]);
        assert!(env.contains(&("HOME".into(), "/scratch/home".into())));
        assert!(env.iter().all(|(_, v)| v != "hub-secret"));
        // Unlisted, a plain variable is not passed either.
        let env = validation_env(parent(), &[], std::path::Path::new("/scratch/home"));
        assert!(!env.iter().any(|(k, _)| k == "TOOLCHAIN_DIR"));
    }

    #[tokio::test]
    async fn a_hub_secret_does_not_reach_the_validation_child() {
        let dir = tempfile::tempdir().unwrap();
        let env = validation_env(parent(), &["UA_AGENT_TOKENS".into()], dir.path());
        let args: Vec<String> = [
            "-c",
            r#"test -z "$UA_AGENT_TOKENS$UA_HTTP_BEARER$EXAMPLE_API_KEY$SOME_TOKEN" && test "$HOME" = "$1""#,
            "sh",
        ]
        .map(String::from)
        .into_iter()
        .chain([dir.path().to_string_lossy().into_owned()])
        .collect();
        let out = crate::families::workspace::run_program(
            "sh",
            &args,
            dir.path(),
            &env,
            Duration::from_secs(10),
            4096,
        )
        .await
        .unwrap();
        assert_eq!(out.exit_code, 0, "{}", String::from_utf8_lossy(&out.stderr));
        // The same check fails when the secret is present, so it is a real check.
        let mut leaky = env.clone();
        leaky.push(("UA_AGENT_TOKENS".into(), "hub-secret".into()));
        let out = crate::families::workspace::run_program(
            "sh",
            &args,
            dir.path(),
            &leaky,
            Duration::from_secs(10),
            4096,
        )
        .await
        .unwrap();
        assert_ne!(out.exit_code, 0);
    }
}
