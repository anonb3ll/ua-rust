//! Delegation: agent-to-agent handoff of work with an audit trail.
//!
//! `delegate` links two records instead of inventing a new queue: a child task
//! addressed to the receiving agent (`[delegated-to: X]`, lane = X) and a
//! `delegations` row tying them together with the from/to labels, an optional
//! advisory deadline and a callback preference. Delegation executes nothing
//! and grants the receiver no extra tools.
//!
//! The lifecycle is fenced: `claim` moves `pending -> in_flight` with one
//! conditional update and bumps `claim_generation`; every later transition by
//! the assignee names the generation it holds, so a delayed write from an old
//! attempt can never move a newer one.

mod spec;

pub use spec::{SpecCheck, TextOrList};

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};
use ua_store::{Procedure, SchemaPart, WriteTx};

use super::plans::{emit, ledger_label, ledger_text, parse_params, row_map, write_identity};
use crate::approvals;
use crate::registry::{Registry, ToolCtx, blocking, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "delegation.v1",
    sql: "
CREATE TABLE IF NOT EXISTS delegations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_agent TEXT NOT NULL,
    to_agent TEXT NOT NULL,
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    task_spec TEXT NOT NULL,
    deadline TEXT,
    callback TEXT NOT NULL DEFAULT 'notify' CHECK (callback IN ('notify','memory','none')),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','in_flight','completed','cancelled','failed')),
    memory_id TEXT,
    callback_result TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    claim_generation INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_delegations_task ON delegations(task_id);
CREATE INDEX IF NOT EXISTS idx_delegations_to_agent ON delegations(to_agent, status);
CREATE INDEX IF NOT EXISTS idx_delegations_status ON delegations(status, created_at);
",
};

/// `organization.v1.tools.delegation`: `org_id` on `delegations` (existing
/// rows take the default organization; [`ORG_SCOPE`] then moves each to its
/// task's) and the generated `delegations_org_exists` /
/// `delegations_org_immutable` triggers. No key rebuild: a delegation id is a
/// hub-global AUTOINCREMENT id and no other key exists. Applied after the
/// tasks parts (`tasks.v2.org_scope`).
pub const TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.tools.delegation", &["delegations"]);

/// `delegation.v2.org_scope`: each existing delegation moves to its task's
/// organization (the generated immutability trigger is dropped for that one
/// update and recreated exactly as [`TENANT_PART`] made it; a delegation whose
/// task is gone stays the default organization's), then indexes led by
/// `org_id` for the assignee queue, the status list and the stats window, and
/// triggers that keep a delegation's `task_id` inside its own organization
/// (the foreign key alone would accept another organization's task). A
/// missing task is still the foreign key's error.
pub const ORG_SCOPE: SchemaPart = SchemaPart {
    name: "delegation.v2.org_scope",
    sql: "
DROP TRIGGER IF EXISTS delegations_org_immutable;
UPDATE delegations SET org_id = (SELECT t.org_id FROM tasks t WHERE t.id = delegations.task_id)
WHERE EXISTS (SELECT 1 FROM tasks t WHERE t.id = delegations.task_id AND t.org_id IS NOT delegations.org_id);
CREATE TRIGGER delegations_org_immutable BEFORE UPDATE OF org_id ON delegations \
WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id \
BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END;

CREATE INDEX IF NOT EXISTS idx_delegations_org_to_agent ON delegations(org_id, to_agent, status);
CREATE INDEX IF NOT EXISTS idx_delegations_org_status ON delegations(org_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_delegations_org_created ON delegations(org_id, created_at);

CREATE TRIGGER IF NOT EXISTS delegations_org_parent BEFORE INSERT ON delegations
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS delegations_org_parent_update BEFORE UPDATE OF task_id ON delegations
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
",
};

pub const CALLBACKS: [&str; 3] = ["notify", "memory", "none"];
pub const DELEGATION_STATUSES: [&str; 5] = ["pending", "in_flight", "completed", "cancelled", "failed"];
const PRIORITIES: [&str; 3] = ["high", "med", "low"];
const LABEL_MAX: usize = 64;
const REASON_MAX: usize = 500;

// ---------------------------------------------------------------------------
// Validation helpers.

fn validate_label(label: &str, field: &str) -> UaResult<String> {
    let l = label.trim();
    let ok = !l.is_empty()
        && l.len() <= LABEL_MAX
        && l.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '@'));
    if !ok {
        return Err(UaError::invalid(format!(
            "{field} must be an agent label of 1-{LABEL_MAX} letters, digits or _-.:@, got {label:?}"
        )));
    }
    Ok(l.to_string())
}

/// `agent`, refused unless it is the verified caller.
fn caller_label(ctx: &ToolCtx, agent: Option<&str>) -> UaResult<String> {
    let actor = write_identity(&ctx.caller, agent)?;
    validate_label(&actor, "agent")
}

fn validate_generation(g: Option<i64>) -> UaResult<Option<i64>> {
    if let Some(g) = g
        && g < 0
    {
        return Err(UaError::invalid("expected_claim_generation must be a nonnegative integer"));
    }
    Ok(g)
}

fn deadline_ts(s: &str) -> Option<jiff::Timestamp> {
    if let Ok(ts) = s.parse::<jiff::Timestamp>() {
        return Some(ts);
    }
    if let Ok(dt) = s.parse::<jiff::civil::DateTime>() {
        return jiff::tz::TimeZone::UTC.to_timestamp(dt).ok();
    }
    if let Ok(d) = s.parse::<jiff::civil::Date>() {
        return jiff::tz::TimeZone::UTC.to_timestamp(d.at(0, 0, 0, 0)).ok();
    }
    None
}

fn validate_deadline(d: Option<&str>) -> UaResult<Option<String>> {
    let Some(d) = d.map(str::trim).filter(|s| !s.is_empty()) else { return Ok(None) };
    if deadline_ts(d).is_none() {
        return Err(UaError::invalid(format!(
            "deadline {d:?} is not ISO-8601 (e.g. '2026-07-20' or '2026-07-20T18:00:00+00:00')"
        )));
    }
    Ok(Some(d.to_string()))
}

fn validate_idempotency_key(k: &str) -> UaResult<String> {
    let ok = !k.is_empty()
        && k.len() <= 128
        && k.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if !ok {
        return Err(UaError::invalid("idempotency_key must be 1-128 letters, digits, '.', '_', ':' or '-'"));
    }
    Ok(k.to_string())
}

fn truncate(s: &str, n: usize) -> String {
    s.trim().chars().take(n).collect()
}

/// A Markdown heading marker or a bare section label (`### Objective`,
/// `OBJECTIVE:`): structure from the spec template, never a real title.
fn is_heading_or_label(line: &str) -> bool {
    let mut rest = line;
    if rest.starts_with('#') {
        let run = rest.chars().take_while(|c| *c == '#').count();
        if run > 6 {
            return false;
        }
        rest = rest[run..].trim_start();
    }
    let rest = rest.strip_suffix([':', '*']).unwrap_or(rest);
    let mut chars = rest.chars();
    let Some(first) = chars.next() else { return false };
    let tail: Vec<char> = chars.collect();
    first.is_ascii_alphabetic()
        && (2..=40).contains(&tail.len())
        && tail.iter().all(|c| c.is_ascii_alphabetic() || *c == ' ' || *c == '/')
}

/// First real content line of a spec, for the child task's title.
fn derive_title(task_spec: &str) -> String {
    for raw in task_spec.lines() {
        let line = raw.trim();
        if line.is_empty() || is_heading_or_label(line) {
            continue;
        }
        return line.chars().take(120).collect();
    }
    let first = task_spec.trim().lines().next().unwrap_or("");
    let stripped = first.trim_start_matches('#').trim();
    let t: String = stripped.chars().take(120).collect();
    if t.is_empty() { "untitled delegation".into() } else { t }
}

/// A delegation row as a reply: the row without its `org_id` (replies keep
/// their shape, owner decision (d)).
fn delegation_reply(r: &rusqlite::Row<'_>) -> rusqlite::Result<serde_json::Map<String, Value>> {
    let mut m = row_map(r)?;
    m.remove("org_id");
    Ok(m)
}

/// Delegation `id` of organization `org`; another organization's answers
/// exactly as a missing one.
fn delegation_row(c: &Connection, org: &str, id: i64) -> UaResult<Value> {
    c.query_row("SELECT * FROM delegations WHERE org_id = ?1 AND id = ?2", params![org, id], |r| {
        delegation_reply(r).map(Value::Object)
    })
    .optional()?
    .ok_or_else(|| UaError::not_found(format!("no delegation with id {id}")))
}

/// The stored idempotency key of a delegation: per delegating agent, with
/// `%`, `:` and `/` in its label percent-escaped (as `task_update`'s keys are),
/// so the label ends at the first `:` after the tool name and two agents
/// never share a stored key. `idempotency_keys` is still hub-wide, so another
/// organization's key is prefixed with its organization
/// (`crate::families::tasks::idem_key`) and never replays the default
/// organization's receipt, or a third's; the default keeps the
/// `delegate:<label>:<key>` form. Only a label holding `:` is stored
/// differently from before, and a receipt stored under its old unescaped form
/// is not read.
fn receipt_key(org: &str, from_agent: &str, key: &str) -> String {
    let label = from_agent.replace('%', "%25").replace(':', "%3A").replace('/', "%2F");
    crate::families::tasks::idem_key(org, "delegate", &format!("{label}:{key}"))
}

/// A delegation event about a delegation of organization `org`, through the
/// shared [`emit`]. ORG-EVENT-DEFAULT: callers pass another organization's
/// free text and labels (title, project, lane, agents, reasons, results,
/// deadline, callback) through [`ledger_text`] / [`ledger_label`], so only
/// ids, statuses and generations reach the default ledger, and the
/// originator is the neutral `system`, never the acting agent.
fn org_emit(
    tx: &mut WriteTx<'_>,
    org: &str,
    caller: &ua_core::Caller,
    channel: &str,
    payload: Value,
) -> UaResult<()> {
    if org == ua_core::DEFAULT_ORG {
        return emit(tx, caller, channel, payload);
    }
    let neutral = ua_core::Caller { label: "system".into(), ..ua_core::Caller::system() };
    emit(tx, &neutral, channel, payload)
}

/// A stored receipt: (request digest, committed result).
fn read_receipt(c: &Connection, key: &str) -> UaResult<Option<(String, Value)>> {
    let raw: Option<String> = c
        .query_row(
            "SELECT result_json FROM idempotency_keys WHERE key = ?1 AND tool = 'delegate'",
            [key],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.and_then(|s| serde_json::from_str::<Value>(&s).ok()).map(|v| {
        (
            v["digest"].as_str().unwrap_or_default().to_string(),
            v.get("result").cloned().unwrap_or(Value::Null),
        )
    }))
}

fn replay(existing: Option<(String, Value)>, digest: &str) -> UaResult<Option<Value>> {
    match existing {
        Some((d, result)) if d == digest => Ok(Some(result)),
        Some(_) => {
            Err(UaError::conflict("idempotency_key was already used for a different delegation request"))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Argument structs.

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegateArgs {
    /// The work, written to the Delegation Spec Standard (see delegation_spec_template).
    pub task_spec: String,
    /// Delegating agent; defaults to the caller. A verified caller can only delegate as itself.
    pub from_agent: Option<String>,
    /// Receiving agent label. Must differ from from_agent.
    pub to_agent: String,
    /// Advisory ISO-8601 deadline; delegate_list flags overdue rows, nothing expires.
    pub deadline: Option<String>,
    /// `notify` (default), `memory` or `none`. Recorded for the completion hook.
    pub callback: Option<String>,
    /// Child task priority: `high`, `med` (default) or `low`.
    pub priority: Option<String>,
    /// Parent task for the child task. An untrusted parent makes the child untrusted.
    pub parent_task_id: Option<i64>,
    /// Child task project; default the parent's project, else `default`.
    pub project: Option<String>,
    /// Caller-scoped retry token (1-128 of letters, digits, `.`, `_`, `:`, `-`). A retry with the
    /// same key and request returns the committed result; a different request is a conflict.
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// `pending` (default), `in_flight`, `completed`, `cancelled`, `failed` or `all`.
    pub status: Option<String>,
    pub to_agent: Option<String>,
    /// 1-200, default 50.
    pub limit: Option<i64>,
    pub task_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimArgs {
    /// Delegation id.
    pub id: i64,
    /// The assignee; defaults to the caller. A verified caller can only act as itself.
    pub agent: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FencedArgs {
    pub id: i64,
    pub agent: Option<String>,
    /// The claim_generation returned by delegate_claim.
    pub expected_claim_generation: Option<i64>,
    /// Also require the delegation's task to be running this run for this agent.
    pub expected_run_id: Option<String>,
    /// Also require the delegation to belong to this task.
    pub task_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelArgs {
    pub id: i64,
    pub agent: Option<String>,
    pub reason: Option<String>,
    pub expected_claim_generation: Option<i64>,
    /// Retire only when the task's current run is no longer this one (or was cancelled).
    pub expected_run_id: Option<String>,
    /// Retire only when the task has no current run.
    #[serde(default)]
    pub require_no_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailArgs {
    pub id: i64,
    pub agent: Option<String>,
    pub reason: Option<String>,
    pub expected_claim_generation: Option<i64>,
    pub expected_run_id: Option<String>,
    pub task_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompleteArgs {
    pub id: i64,
    pub agent: Option<String>,
    /// Short result summary, stored as callback_result.
    pub result: Option<String>,
    pub expected_claim_generation: Option<i64>,
    pub expected_run_id: Option<String>,
    pub task_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetryArgs {
    pub id: i64,
    pub agent: Option<String>,
    pub reason: Option<String>,
    pub expected_claim_generation: Option<i64>,
    pub expected_run_id: Option<String>,
    pub task_id: Option<i64>,
    /// Clear last_attempt_at so a backoff scheduler retries immediately.
    #[serde(default)]
    pub clear_backoff: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetArgs {
    pub id: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LookupArgs {
    pub idempotency_key: String,
    pub from_agent: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffArgs {
    /// The work, written to the Delegation Spec Standard.
    pub task_spec: String,
    pub to_agent: String,
    /// Sender; a verified caller is always the sender.
    pub agent: Option<String>,
    pub deadline: Option<String>,
    pub priority: Option<String>,
    pub parent_task_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffListArgs {
    /// 1-200, default 200.
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpecCheckArgs {
    pub task_spec: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpecTemplateArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpecBuildArgs {
    pub objective: String,
    pub scope_files: Option<TextOrList>,
    /// Definition of Done criteria; at least one must be an observable behaviour.
    pub dod_criteria: Option<TextOrList>,
    pub tdd_stub: Option<TextOrList>,
    pub tdd_must_be_real: Option<TextOrList>,
    pub boundaries: Option<TextOrList>,
    /// Append the standard gates line (default true).
    pub include_gates: Option<bool>,
    /// Refuse a spec that fails the standard (default true).
    pub auto_validate: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManageArgs {
    /// One of create, list, claim, release, cancel, fail, complete, retry, get, lookup,
    /// spec_check, spec_template, spec_build.
    pub action: String,
    /// The action's arguments, exactly as the matching standalone tool takes them.
    pub params: Option<Value>,
}

// ---------------------------------------------------------------------------
// Create.

/// Every door to this (`delegate`, `delegation_manage` create, `handoff`)
/// passes `delegate`'s profile entry, policy rules and approval gate in the
/// registry first, on the arguments of a `delegate` call (see
/// `crate::routes`), so nothing here gates again.
fn create(ctx: &ToolCtx, a: DelegateArgs) -> UaResult<Value> {
    let task_spec = a.task_spec.trim().to_string();
    if task_spec.is_empty() {
        return Err(UaError::invalid("task_spec must not be empty"));
    }
    let from_agent = validate_label(&write_identity(&ctx.caller, a.from_agent.as_deref())?, "from_agent")?;
    let to_agent = validate_label(&a.to_agent, "to_agent")?;
    if from_agent == to_agent {
        return Err(UaError::invalid("from_agent and to_agent must differ: you cannot delegate to yourself"));
    }
    let callback = a.callback.unwrap_or_else(|| "notify".into());
    if !CALLBACKS.contains(&callback.as_str()) {
        return Err(UaError::invalid(format!("callback must be one of {CALLBACKS:?}")));
    }
    let priority = a.priority.unwrap_or_else(|| "med".into());
    if !PRIORITIES.contains(&priority.as_str()) {
        return Err(UaError::invalid(format!("priority must be one of {PRIORITIES:?}")));
    }
    let deadline = validate_deadline(a.deadline.as_deref())?;
    let idem = a.idempotency_key.as_deref().map(validate_idempotency_key).transpose()?;
    let project = a.project.map(|p| p.trim().to_string()).filter(|p| !p.is_empty());

    // The spec standard runs before any approval: there is no point queueing a
    // human decision on a malformed delegation.
    let check = spec::check(&task_spec);
    if !check.ok {
        return Err(UaError::invalid(format!(
            "delegation to {to_agent:?} does not meet the Delegation Spec Standard:\n  - {}\n\nCall \
             delegation_spec_template() for the canonical shape.",
            check.errors.join("\n  - ")
        )));
    }

    let request = json!({
        "task_spec": task_spec,
        "from_agent": from_agent,
        "to_agent": to_agent,
        "deadline": deadline,
        "callback": callback,
        "priority": priority,
        "parent_task_id": a.parent_task_id,
        "project": project,
    });
    let digest = hex::encode(Sha256::digest(approvals::canonical_payload(&request).as_bytes()));
    let org = ctx.caller.org_id.clone();
    let rkey = idem.as_deref().map(|k| receipt_key(&org, &from_agent, k));

    // A committed retry replays before any gate: no second approval, no effect.
    if let Some(k) = rkey.clone() {
        let existing = ctx.hub.db().read(|c| read_receipt(c, &k))?;
        if let Some(done) = replay(existing, &digest)? {
            return Ok(done);
        }
    }

    let caller = ctx.caller.clone();
    let warnings: Vec<String> = check.warnings.clone();
    ctx.hub.db().write(|tx| {
        if let Some(k) = rkey.as_deref()
            && let Some(done) = replay(read_receipt(tx, k)?, &digest)?
        {
            return Ok(done);
        }
        crate::families::tasks::require_org(tx, &org)?;
        let ts = ua_core::time::now();
        let (parent_untrusted, parent_project) = match a.parent_task_id {
            Some(pid) => tx
                .query_row(
                    "SELECT untrusted, project FROM tasks WHERE org_id = ?1 AND id = ?2",
                    params![org, pid],
                    |r| Ok((r.get::<_, i64>(0)? != 0, Some(r.get::<_, String>(1)?))),
                )
                .optional()?
                .ok_or_else(|| UaError::not_found(format!("no task with id {pid}")))?,
            None => (false, None),
        };
        let project = project.clone().or(parent_project).unwrap_or_else(|| "default".into());
        let title = derive_title(&task_spec);
        let mut notes = format!("[delegated-by: {from_agent}] [delegated-to: {to_agent}]");
        if let Some(d) = &deadline {
            notes.push_str(&format!("\n[deadline: {d}]"));
        }
        notes.push_str(&format!("\n\ntask-spec:\n{task_spec}"));
        tx.execute(
            "INSERT INTO tasks (title, notes, status, priority, parent_id, created_at, updated_at, untrusted, \
             project, lane, org_id) VALUES (?1, ?2, 'open', ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9)",
            params![
                title,
                notes,
                priority,
                a.parent_task_id,
                ts,
                i64::from(parent_untrusted),
                project,
                to_agent,
                org
            ],
        )?;
        let task_id = tx.last_insert_rowid();
        // The delegation and its task are both the caller's organization's.
        tx.execute(
            "INSERT INTO delegations (org_id, from_agent, to_agent, task_id, task_spec, deadline, callback, \
             status, created_at, updated_at) VALUES (?8, ?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?7)",
            params![from_agent, to_agent, task_id, task_spec, deadline, callback, ts, org],
        )?;
        let delegation_id = tx.last_insert_rowid();
        org_emit(
            tx,
            &org,
            &caller,
            "agent.task.created",
            json!({
                "task_id": task_id,
                "title": ledger_text(&org, &title),
                "project": ledger_text(&org, &project),
                "lane": ledger_text(&org, &to_agent),
                "via": "delegate",
            }),
        )?;
        org_emit(
            tx,
            &org,
            &caller,
            "agent.delegation.created",
            json!({
                "delegation_id": delegation_id,
                "task_id": task_id,
                "from_agent": ledger_text(&org, &from_agent),
                "to_agent": ledger_text(&org, &to_agent),
                "deadline": ledger_label(&org, deadline.as_deref()),
                "callback": ledger_text(&org, &callback),
            }),
        )?;
        let mut result = json!({ "delegation_id": delegation_id, "task_id": task_id, "memory_id": null });
        if !warnings.is_empty() {
            result["spec_warnings"] = json!(warnings);
        }
        if let Some(k) = rkey.as_deref() {
            tx.execute(
                "INSERT INTO idempotency_keys (key, tool, result_json, created_at) VALUES (?1, 'delegate', ?2, ?3)",
                params![k, json!({ "digest": digest, "result": result }).to_string(), ts],
            )?;
        }
        Ok(result)
    })
}

fn lookup(ctx: &ToolCtx, a: LookupArgs) -> UaResult<Value> {
    let actor = validate_label(&write_identity(&ctx.caller, a.from_agent.as_deref())?, "from_agent")?;
    let key = validate_idempotency_key(&a.idempotency_key)?;
    let rkey = receipt_key(&ctx.caller.org_id, &actor, &key);
    let found = ctx.hub.db().read(|c| read_receipt(c, &rkey))?;
    Ok(match found {
        Some((_, result)) => json!({ "idempotency_key": key, "state": "committed", "result": result }),
        None => json!({ "idempotency_key": key, "state": "not_found" }),
    })
}

// ---------------------------------------------------------------------------
// Reads.

fn list(ctx: &ToolCtx, a: ListArgs) -> UaResult<Value> {
    let status = a.status.unwrap_or_else(|| "pending".into());
    if status != "all" && !DELEGATION_STATUSES.contains(&status.as_str()) {
        return Err(UaError::invalid(format!("status must be one of {DELEGATION_STATUSES:?} or \"all\"")));
    }
    if let Some(t) = a.task_id
        && t <= 0
    {
        return Err(UaError::invalid("task_id must be a positive integer"));
    }
    let limit = a.limit.unwrap_or(50).clamp(1, 200);
    let now = jiff::Timestamp::now();
    let org = ctx.caller.org_id.clone();
    ctx.hub.db().read(|c| {
        // Only the caller's organization's delegations.
        let mut stmt = c.prepare(
            "SELECT * FROM delegations WHERE org_id = ?5 \
             AND (?1 = 'all' OR status = ?1) AND (?2 IS NULL OR to_agent = ?2) \
             AND (?3 IS NULL OR task_id = ?3) ORDER BY created_at DESC, id DESC LIMIT ?4",
        )?;
        let rows: Vec<_> = stmt
            .query_map(params![status, a.to_agent, a.task_id, limit + 1, org], delegation_reply)?
            .collect::<Result<_, _>>()?;
        let truncated = rows.len() as i64 > limit;
        let out: Vec<Value> = rows
            .into_iter()
            .take(limit as usize)
            .map(|mut m| {
                let overdue = m.get("status").and_then(Value::as_str) == Some("pending")
                    && m.get("deadline")
                        .and_then(Value::as_str)
                        .and_then(deadline_ts)
                        .is_some_and(|d| d < now);
                m.insert("overdue".into(), json!(overdue));
                Value::Object(m)
            })
            .collect();
        Ok(json!({ "delegations": out, "truncated": truncated }))
    })
}

fn get(ctx: &ToolCtx, a: GetArgs) -> UaResult<Value> {
    ctx.hub.db().read(|c| Ok(json!({ "delegation": delegation_row(c, &ctx.caller.org_id, a.id)? })))
}

// ---------------------------------------------------------------------------
// Lifecycle transitions.

/// Extra atomic conditions for run- or task-fenced transitions. Neither a run
/// token nor a task id grants authority; they only narrow.
fn run_guard(
    agent: &str,
    task_id: Option<i64>,
    expected_run_id: Option<&str>,
) -> UaResult<(String, Vec<SqlValue>)> {
    if let Some(t) = task_id
        && t <= 0
    {
        return Err(UaError::invalid("task_id must be a positive integer"));
    }
    let Some(run) = expected_run_id else {
        return Ok(match task_id {
            Some(t) => (" AND task_id = ?".into(), vec![SqlValue::Integer(t)]),
            None => (String::new(), vec![]),
        });
    };
    if run.trim().is_empty() || run.len() > 256 {
        return Err(UaError::invalid("expected_run_id must be a nonempty bounded string"));
    }
    let mut sql = String::from(
        " AND to_agent = ? AND EXISTS (SELECT 1 FROM tasks t WHERE t.id = delegations.task_id \
             AND t.org_id = delegations.org_id",
    );
    let mut p = vec![SqlValue::Text(agent.into())];
    if let Some(t) = task_id {
        sql.push_str(" AND t.id = ?");
        p.push(SqlValue::Integer(t));
    }
    sql.push_str(
        " AND t.claimed_by = ? AND t.cancel_requested = 0 AND t.current_run_id = ? AND t.current_run_agent = ? \
         AND t.status = 'doing')",
    );
    p.extend([SqlValue::Text(agent.into()), SqlValue::Text(run.into()), SqlValue::Text(agent.into())]);
    Ok((sql, p))
}

fn transition_result(key: &str, changed: bool, expected_run_id: Option<&str>) -> Value {
    let mut out = json!({ key: changed });
    if !changed && expected_run_id.is_some() {
        out["reason"] = json!("run_not_current");
    }
    out
}

/// Run one guarded UPDATE and, when it changed the row, append `channel`.
fn transition(
    ctx: &ToolCtx,
    id: i64,
    sql: String,
    params: Vec<SqlValue>,
    channel: &'static str,
    detail: Value,
) -> UaResult<bool> {
    let caller = ctx.caller.clone();
    let org = caller.org_id.clone();
    // Only a delegation of the caller's organization moves; another
    // organization's changes nothing and answers as a missing one would.
    let sql = format!("{sql} AND org_id = ?");
    let mut params = params;
    params.push(SqlValue::Text(org.clone()));
    ctx.hub.db().write(move |tx: &mut WriteTx<'_>| {
        crate::families::tasks::require_org(tx, &org)?;
        let n = tx.execute(&sql, params_from_iter(params))?;
        if n > 0 {
            let row = delegation_row(tx, &org, id)?;
            let mut payload = json!({
                "delegation_id": id,
                "task_id": row["task_id"],
                "status": row["status"],
                "claim_generation": row["claim_generation"],
            });
            if let (Some(p), Value::Object(d)) = (payload.as_object_mut(), detail) {
                p.extend(d);
            }
            org_emit(tx, &org, &caller, channel, payload)?;
        }
        Ok(n > 0)
    })
}

fn claim(ctx: &ToolCtx, a: ClaimArgs) -> UaResult<Value> {
    let agent = caller_label(ctx, a.agent.as_deref())?;
    let caller = ctx.caller.clone();
    let org = caller.org_id.clone();
    ctx.hub.db().write(|tx| {
        crate::families::tasks::require_org(tx, &org)?;
        let ts = ua_core::time::now();
        let n = tx.execute(
            "UPDATE delegations SET status = 'in_flight', attempts = attempts + 1, \
             claim_generation = claim_generation + 1, last_attempt_at = ?3, updated_at = ?3 \
             WHERE id = ?1 AND status = 'pending' AND to_agent = ?2 AND org_id = ?4",
            params![a.id, agent, ts, org],
        )?;
        // Read inside the same transaction so a later release and reclaim
        // cannot swap a successor's generation into this response.
        let row = delegation_row(tx, &org, a.id)?;
        if n > 0 {
            org_emit(
                tx,
                &org,
                &caller,
                "agent.delegation.claimed",
                json!({
                    "delegation_id": a.id,
                    "task_id": row["task_id"],
                    "agent": ledger_text(&org, &agent),
                    "claim_generation": row["claim_generation"],
                }),
            )?;
        }
        Ok(json!({ "claimed": n > 0, "delegation": row }))
    })
}

fn require_generation(g: Option<i64>, action: &str) -> UaResult<i64> {
    g.ok_or_else(|| {
        UaError::invalid(format!(
            "{action} needs expected_claim_generation (the value delegate_claim returned)"
        ))
    })
}

fn release(ctx: &ToolCtx, a: FencedArgs) -> UaResult<Value> {
    let agent = caller_label(ctx, a.agent.as_deref())?;
    let generation = require_generation(validate_generation(a.expected_claim_generation)?, "release")?;
    let (guard, gp) = run_guard(&agent, a.task_id, a.expected_run_id.as_deref())?;
    let sql = format!(
        "UPDATE delegations SET status = 'pending', attempts = MAX(0, attempts - 1), last_attempt_at = NULL, \
         updated_at = ? WHERE id = ? AND status = 'in_flight' AND to_agent = ? AND claim_generation = ?{guard}"
    );
    let mut p = vec![
        SqlValue::Text(ua_core::time::now()),
        SqlValue::Integer(a.id),
        SqlValue::Text(agent.clone()),
        SqlValue::Integer(generation),
    ];
    p.extend(gp);
    let changed = transition(
        ctx,
        a.id,
        sql,
        p,
        "agent.delegation.released",
        json!({ "agent": ledger_text(&ctx.caller.org_id, &agent) }),
    )?;
    Ok(transition_result("released", changed, a.expected_run_id.as_deref()))
}

fn cancel(ctx: &ToolCtx, a: CancelArgs) -> UaResult<Value> {
    let agent = caller_label(ctx, a.agent.as_deref())?;
    let generation = validate_generation(a.expected_claim_generation)?;
    if a.expected_run_id.is_some() && generation.is_none() {
        return Err(UaError::invalid("expected_claim_generation is required with expected_run_id"));
    }
    if a.expected_run_id.is_some() && a.require_no_run {
        return Err(UaError::invalid("expected_run_id and require_no_run are mutually exclusive"));
    }
    let reason = truncate(
        a.reason.as_deref().filter(|r| !r.trim().is_empty()).unwrap_or("delegation abandoned"),
        REASON_MAX,
    );
    let ts = ua_core::time::now();
    let mut sql = String::from(
        "UPDATE delegations SET status = 'cancelled', completed_at = ?, updated_at = ?, callback_result = ? \
         WHERE id = ? AND status IN ('pending','in_flight') AND (from_agent = ? OR to_agent = ?)",
    );
    let mut p = vec![
        SqlValue::Text(ts.clone()),
        SqlValue::Text(ts),
        SqlValue::Text(reason.clone()),
        SqlValue::Integer(a.id),
        SqlValue::Text(agent.clone()),
        SqlValue::Text(agent.clone()),
    ];
    if let Some(g) = generation {
        sql.push_str(" AND claim_generation = ?");
        p.push(SqlValue::Integer(g));
    }
    if let Some(run) = a.expected_run_id.as_deref() {
        // The old attempt may retire its delegation once its own run was
        // cancelled or superseded, never after a newer attempt took over.
        sql.push_str(
            " AND EXISTS (SELECT 1 FROM tasks t WHERE t.id = delegations.task_id \
             AND t.org_id = delegations.org_id AND (t.current_run_id IS NOT ? OR t.cancel_requested = 1))",
        );
        p.push(SqlValue::Text(run.into()));
    }
    if a.require_no_run {
        sql.push_str(
            " AND EXISTS (SELECT 1 FROM tasks t WHERE t.id = delegations.task_id \
             AND t.org_id = delegations.org_id AND t.current_run_id IS NULL)",
        );
    }
    let changed = transition(
        ctx,
        a.id,
        sql,
        p,
        "agent.delegation.cancelled",
        json!({
            "agent": ledger_text(&ctx.caller.org_id, &agent),
            "reason": ledger_text(&ctx.caller.org_id, &reason),
        }),
    )?;
    Ok(json!({ "cancelled": changed }))
}

/// Shared shape of `fail` and `complete`: a pending row needs no generation;
/// an in-flight row needs the current one.
fn finish(
    ctx: &ToolCtx,
    a: FencedArgs,
    status: &str,
    text: String,
    key: &'static str,
    channel: &'static str,
) -> UaResult<Value> {
    let agent = caller_label(ctx, a.agent.as_deref())?;
    let generation = validate_generation(a.expected_claim_generation)?;
    let (guard, gp) = run_guard(&agent, a.task_id, a.expected_run_id.as_deref())?;
    let ts = ua_core::time::now();
    let completed_at = if status == "completed" { SqlValue::Text(ts.clone()) } else { SqlValue::Null };
    let sql = format!(
        "UPDATE delegations SET status = ?, completed_at = COALESCE(?, completed_at), updated_at = ?, \
         callback_result = ? WHERE id = ? AND (from_agent = ? OR to_agent = ?) \
         AND ((? IS NULL AND status = 'pending') OR (claim_generation = ? AND status = 'in_flight')){guard}"
    );
    let g = generation.map_or(SqlValue::Null, SqlValue::Integer);
    let mut p = vec![
        SqlValue::Text(status.into()),
        completed_at,
        SqlValue::Text(ts),
        SqlValue::Text(text.clone()),
        SqlValue::Integer(a.id),
        SqlValue::Text(agent.clone()),
        SqlValue::Text(agent.clone()),
        g.clone(),
        g,
    ];
    p.extend(gp);
    let changed = transition(
        ctx,
        a.id,
        sql,
        p,
        channel,
        json!({
            "agent": ledger_text(&ctx.caller.org_id, &agent),
            "result": ledger_text(&ctx.caller.org_id, &text),
        }),
    )?;
    Ok(transition_result(key, changed, a.expected_run_id.as_deref()))
}

fn fail(ctx: &ToolCtx, a: FailArgs) -> UaResult<Value> {
    let reason = truncate(
        a.reason.as_deref().filter(|r| !r.trim().is_empty()).unwrap_or("delegation failed"),
        REASON_MAX,
    );
    let f = FencedArgs {
        id: a.id,
        agent: a.agent,
        expected_claim_generation: a.expected_claim_generation,
        expected_run_id: a.expected_run_id,
        task_id: a.task_id,
    };
    finish(ctx, f, "failed", reason, "failed", "agent.delegation.failed")
}

fn complete(ctx: &ToolCtx, a: CompleteArgs) -> UaResult<Value> {
    let result = truncate(a.result.as_deref().unwrap_or(""), REASON_MAX);
    let f = FencedArgs {
        id: a.id,
        agent: a.agent,
        expected_claim_generation: a.expected_claim_generation,
        expected_run_id: a.expected_run_id,
        task_id: a.task_id,
    };
    finish(ctx, f, "completed", result, "completed", "agent.delegation.completed")
}

/// Back to pending after a failed execution. Unlike `release`, `attempts` and
/// `last_attempt_at` are kept so backoff and attempt ceilings keep working.
fn retry(ctx: &ToolCtx, a: RetryArgs) -> UaResult<Value> {
    let agent = caller_label(ctx, a.agent.as_deref())?;
    let generation = require_generation(validate_generation(a.expected_claim_generation)?, "retry")?;
    let (guard, gp) = run_guard(&agent, a.task_id, a.expected_run_id.as_deref())?;
    let reason = truncate(a.reason.as_deref().unwrap_or(""), REASON_MAX);
    let sql = format!(
        "UPDATE delegations SET status = 'pending', updated_at = ?, callback_result = ?, \
         last_attempt_at = CASE WHEN ? THEN NULL ELSE last_attempt_at END \
         WHERE id = ? AND to_agent = ? AND claim_generation = ? AND status = 'in_flight'{guard}"
    );
    let mut p = vec![
        SqlValue::Text(ua_core::time::now()),
        SqlValue::Text(reason.clone()),
        SqlValue::Integer(i64::from(a.clear_backoff)),
        SqlValue::Integer(a.id),
        SqlValue::Text(agent.clone()),
        SqlValue::Integer(generation),
    ];
    p.extend(gp);
    let changed = transition(
        ctx,
        a.id,
        sql,
        p,
        "agent.delegation.retried",
        json!({
            "agent": ledger_text(&ctx.caller.org_id, &agent),
            "reason": ledger_text(&ctx.caller.org_id, &reason),
        }),
    )?;
    Ok(transition_result("retried", changed, a.expected_run_id.as_deref()))
}

// ---------------------------------------------------------------------------
// Handoff (lifecycle metadata only) and spec tools.

/// A `handoff` call's arguments as the `delegate` call it makes: the same
/// fields, `agent` as `from_agent`, `callback: "none"`; absent fields are
/// left out, so a direct `delegate` call with these arguments binds the same
/// approval. The registry gates `handoff` under `delegate` on this mapping
/// (`crate::routes::DOORS`), and [`handoff`] builds its delegation from it.
pub(crate) fn handoff_as_delegate(args: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for (from, to) in [
        ("task_spec", "task_spec"),
        ("agent", "from_agent"),
        ("to_agent", "to_agent"),
        ("deadline", "deadline"),
        ("priority", "priority"),
        ("parent_task_id", "parent_task_id"),
    ] {
        if let Some(v) = args.get(from).filter(|v| !v.is_null()) {
            out.insert(to.to_string(), v.clone());
        }
    }
    out.insert("callback".into(), json!("none"));
    Value::Object(out)
}

fn handoff(ctx: &ToolCtx, a: HandoffArgs) -> UaResult<Value> {
    let raw = serde_json::to_value(&a).map_err(|e| UaError::internal(e.to_string()))?;
    let d: DelegateArgs =
        serde_json::from_value(handoff_as_delegate(&raw)).map_err(|e| UaError::invalid(e.to_string()))?;
    let r = create(ctx, d)?;
    Ok(json!({ "handoff_id": r["delegation_id"], "task_id": r["task_id"], "status": "pending" }))
}

const HANDOFF_FIELDS: [&str; 11] = [
    "id",
    "task_id",
    "from_agent",
    "to_agent",
    "deadline",
    "status",
    "attempts",
    "last_attempt_at",
    "created_at",
    "updated_at",
    "completed_at",
];

fn handoff_list(ctx: &ToolCtx, a: HandoffListArgs) -> UaResult<Value> {
    let r = list(
        ctx,
        ListArgs {
            status: Some("all".into()),
            to_agent: None,
            limit: Some(a.limit.unwrap_or(200)),
            task_id: None,
        },
    )?;
    let rows: Vec<Value> = r["delegations"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|d| Value::Object(HANDOFF_FIELDS.iter().map(|k| (k.to_string(), d[*k].clone())).collect()))
        .collect();
    Ok(json!({ "handoffs": rows }))
}

fn spec_check(a: SpecCheckArgs) -> UaResult<Value> {
    Ok(serde_json::to_value(spec::check(&a.task_spec))?)
}

fn spec_template() -> Value {
    json!({ "template": spec::TEMPLATE, "required_sections": spec::REQUIRED_SECTIONS })
}

fn spec_build(a: SpecBuildArgs) -> UaResult<Value> {
    spec::build(spec::BuildInput {
        objective: &a.objective,
        scope_files: a.scope_files.as_ref(),
        dod_criteria: a.dod_criteria.as_ref(),
        tdd_stub: a.tdd_stub.as_ref(),
        tdd_must_be_real: a.tdd_must_be_real.as_ref(),
        boundaries: a.boundaries.as_ref(),
        include_gates: a.include_gates.unwrap_or(true),
        auto_validate: a.auto_validate.unwrap_or(true),
    })
}

// ---------------------------------------------------------------------------
// The consolidated entry point and registration.

pub(crate) const ACTIONS: [&str; 13] = [
    "create",
    "list",
    "claim",
    "release",
    "cancel",
    "fail",
    "complete",
    "retry",
    "get",
    "lookup",
    "spec_check",
    "spec_template",
    "spec_build",
];

/// Canonical action name; legacy tool names (`delegate`, `delegate_claim`,
/// `delegation_spec_check`, ...) are accepted too.
pub(crate) fn canonical_action(action: &str) -> UaResult<&'static str> {
    let a = action.trim().to_ascii_lowercase();
    let a = match a.as_str() {
        "delegate" => "create",
        other => {
            other.strip_prefix("delegation_").or_else(|| other.strip_prefix("delegate_")).unwrap_or(other)
        }
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
    let f = "delegation";
    match act {
        // The registry gated this action as `delegate` (see `crate::routes`).
        "create" => create(ctx, parse_params(f, act, p)?),
        "list" => list(ctx, parse_params(f, act, p)?),
        "claim" => claim(ctx, parse_params(f, act, p)?),
        "release" => release(ctx, parse_params(f, act, p)?),
        "cancel" => cancel(ctx, parse_params(f, act, p)?),
        "fail" => fail(ctx, parse_params(f, act, p)?),
        "complete" => complete(ctx, parse_params(f, act, p)?),
        "retry" => retry(ctx, parse_params(f, act, p)?),
        "get" => get(ctx, parse_params(f, act, p)?),
        "lookup" => lookup(ctx, parse_params(f, act, p)?),
        "spec_check" => spec_check(parse_params(f, act, p)?),
        "spec_template" => {
            let _: SpecTemplateArgs = parse_params(f, act, p)?;
            Ok(spec_template())
        }
        "spec_build" => spec_build(parse_params(f, act, p)?),
        other => Err(crate::routes::unhandled("delegation_manage", other)),
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "delegation_manage",
            "Delegation lifecycle in one tool: create, list, claim, release, cancel, fail, complete, retry, get, \
             lookup, spec_check, spec_template, spec_build. `params` holds the action's arguments.",
            |ctx: ToolCtx, a: ManageArgs| blocking(move || dispatch(&ctx, &a.action, a.params)),
        )
        .family("delegation"),
    );
    r.add(
        tool(
            "delegate",
            "Delegate work to another agent: creates a child task addressed to to_agent and a pending \
             delegations row. The spec must meet the Delegation Spec Standard. Grants the receiver no extra \
             tools. Returns {delegation_id, task_id, memory_id}.",
            |ctx: ToolCtx, a: DelegateArgs| blocking(move || create(&ctx, a)),
        )
        .family("delegation"),
    );
    r.add(
        tool(
            "delegate_list",
            "List delegations by status (pending by default, or all), optionally by to_agent or task_id. Pending \
             rows past their deadline carry overdue: true; nothing expires.",
            |ctx: ToolCtx, a: ListArgs| blocking(move || list(&ctx, a)),
        )
        .family("delegation")
        .read_only(),
    );
    r.add(
        tool(
            "delegate_claim",
            "Atomically move one pending delegation addressed to you to in_flight and bump its claim_generation. \
             Returns {claimed, delegation}; claimed is false when someone else got there first.",
            |ctx: ToolCtx, a: ClaimArgs| blocking(move || claim(&ctx, a)),
        )
        .family("delegation"),
    );
    r.add(
        tool(
            "delegate_release",
            "Return an in_flight delegation to pending for crash recovery, fenced by expected_claim_generation. \
             Not a retry-on-failure path.",
            |ctx: ToolCtx, a: FencedArgs| blocking(move || release(&ctx, a)),
        )
        .family("delegation"),
    );
    r.add(
        tool(
            "delegate_cancel",
            "Retire a pending or in_flight delegation without claiming success. Only the delegator or assignee \
             may cancel.",
            |ctx: ToolCtx, a: CancelArgs| blocking(move || cancel(&ctx, a)),
        )
        .family("delegation"),
    );
    r.add(
        tool(
            "handoff",
            "Hand work to another agent as the verified sender: a delegation with callback none. Returns only \
             lifecycle ids: {handoff_id, task_id, status}.",
            |ctx: ToolCtx, a: HandoffArgs| blocking(move || handoff(&ctx, a)),
        )
        .family("delegation"),
    );
    r.add(
        tool(
            "handoff_list",
            "List handoff lifecycle metadata, newest first, without specs or callback payloads.",
            |ctx: ToolCtx, a: HandoffListArgs| blocking(move || handoff_list(&ctx, a)),
        )
        .family("delegation")
        .read_only(),
    );
    r.add(
        tool(
            "delegation_spec_check",
            "Lint a delegation spec against the Delegation Spec Standard: required sections, and a Definition of \
             Done that names at least one observable behaviour, not only build status. Advisory.",
            |_ctx: ToolCtx, a: SpecCheckArgs| async move { spec_check(a) },
        )
        .family("delegation")
        .read_only(),
    );
    r.add(
        tool(
            "delegation_spec_template",
            "Return the canonical delegation spec template and its required section names.",
            |_ctx: ToolCtx, _a: SpecTemplateArgs| async move { Ok(spec_template()) },
        )
        .family("delegation")
        .read_only(),
    );
    r.add(
        tool(
            "delegation_spec_build",
            "Build a Delegation Spec in Markdown from structured fields and, with auto_validate (default), \
             validate it against the standard.",
            |_ctx: ToolCtx, a: SpecBuildArgs| async move { spec_build(a) },
        )
        .family("delegation")
        .read_only(),
    );
}
