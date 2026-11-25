//! The dispatch tools.

use std::path::{Path, PathBuf};

use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use ua_core::{ActorKind, Caller, UaError, UaResult};

use super::executor::{self, LaunchSpec};
use super::{
    Edge, Outcome, after_seconds, check_agent_or_operator, check_run_owner, classify_termination,
    finalize_cancellation, live_run_for_task, load_run, now, record_outcome, record_transition, refusal,
    run_object, states, transition,
};
use crate::approvals::{self, GateOutcome, Refusal, RefusalReason};
use crate::families::node_queue::require_org;
use crate::families::tasks::{check_slug, next_revision, require_task, row_object, str_field, ts_le};
use crate::families::{governance, node_queue, provider_accounts};
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, blocking, tool};

const PROMPT_CAP: usize = 32 * 1024;
const MAX_LEASE_SECONDS: i64 = 86_400;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskArgs {
    /// Task to dispatch.
    pub task_id: i64,
    /// Agent label the run belongs to. Only this identity may report or
    /// resume the run; it or an operator may cancel it. The caller must be
    /// this agent or an operator.
    pub agent: String,
    /// Harness name from the hub's `[harnesses.<name>]` config. Omitted, the
    /// run is recorded and marked launched but no process is started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// Prompt substituted for `{prompt}` (at most 32 KB). Defaults to the
    /// task title and notes plus the run id to report against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Lease length in seconds (1-86400). Defaults to `dispatch_lease_seconds`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_seconds: Option<i64>,
    /// Route the run to this registered remote node instead of starting a
    /// local harness: the node must belong to `agent`. The run is linked to
    /// one node work item (`evidence_ref = node:<node>:<item>`), moves to
    /// running when the node claims it, and ends with the node's receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Node backend to run (`codex`, `claude`, `acp:claude`, ...). Defaults to
    /// the first backend the node advertises. Only with `node`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Wall-clock limit on the node, 1-21600 seconds (default 3600). Only with `node`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_timeout_s: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportArgs {
    /// `finished`, `failed` or `blocked`.
    pub state: String,
    /// The run to report on (`UA_DISPATCH_RUN_ID` in the child's environment).
    pub run_id: String,
    /// Commit SHA, PR URL or log path. Required for `finished`.
    pub evidence: Option<String>,
    /// Why the run failed or is blocked.
    pub failure_reason: Option<String>,
    /// The fence the child was started with (`UA_DISPATCH_FENCE`). A report
    /// from an earlier attempt of a resumed run is refused (`stale_fence`).
    pub fence: Option<i64>,
    /// Usage figures to store on the run (tokens, cost, elapsed), as an object.
    pub usage: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelArgs {
    /// The run to cancel.
    pub run_id: String,
    /// Reason recorded on the run (default `client cancelled`).
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunArgs {
    /// The dispatch run.
    pub run_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmArgs {
    /// The dispatch run.
    pub run_id: String,
    /// Confirmation note recorded with the operator's identity.
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Only this task's runs.
    pub task_id: Option<i64>,
    /// Only runs in this state.
    pub state: Option<String>,
    /// Rows to return, newest first (default 20, max 200).
    pub limit: Option<i64>,
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "dispatch_task",
            "Dispatch a task to an agent harness: mint a run (claimed, fence 1, with a lease), claim the task \
             for the agent, and start the configured harness as a child process in the task's worktree with an \
             allowlisted environment. The caller must be the agent or an operator. Always needs a one-time \
             human approval, bound to what will run: the approval shows the run id, resolved workdir, harness \
             argv template, env allowlist, timeout_s, output_cap_bytes, prompt_sha256 and whether the agent's \
             token is passed, and a pass \
             is refused (approval_binding_changed) if any of them changed since. With `node` (instead of a \
             harness) the run is routed to that registered remote node of the agent: the approval also binds \
             the node, backend, working directory on the node and node_timeout_s, the run is launched as one \
             node work item and ends with the node's receipt. Returns {ok, run_id, state, fence, pid, \
             log_path, spawned, stub} (routed: {routed, node, backend, cwd, item_id, evidence_ref}).",
            |ctx: ToolCtx, a: TaskArgs| async move { dispatch_task(ctx, a).await },
        )
        // Gated in the handler, not by the registry: the approval must cover
        // values resolved from the task and config, not just the arguments.
        .handler_may_gate(crate::HandlerGate::Always)
        .family("dispatch"),
    );
    r.add(
        tool(
            "dispatch_report_self",
            "Record a terminal outcome (finished, failed or blocked) for the caller's own dispatch run. The \
             verified identity must match the run's agent_label; finished needs evidence. Returns {ok, run_id, \
             state, agent_label, evidence_ref, outcome}; a refused report has ok false and outcome.reason \
             (already_terminal, stale_fence, cancellation_in_progress, superseded_run).",
            |ctx: ToolCtx, a: ReportArgs| async move { report_self(ctx, a).await },
        )
        .family("dispatch"),
    );
    r.add(
        tool(
            "dispatch_cancel",
            "Cancel a live dispatch run (the caller's own, or any run for an operator or human): record the \
             intent and who cancelled, stop the run's process group when this hub started it or can prove it \
             is this hub's orphan, and record whether cessation is confirmed. Returns {ok, run_id, state, \
             termination, cessation, cancelled_by}.",
            |ctx: ToolCtx, a: CancelArgs| async move { cancel(ctx, a).await },
        )
        .family("dispatch"),
    );
    r.add(
        tool(
            "dispatch_resume",
            "Resume the caller's cancelled (with confirmed cessation), failed or retryable dispatch run under a \
             new fence and relaunch its harness. Fails closed when the run or task is terminal, another run holds \
             the task, or cessation is unconfirmed, and is refused (approval_binding_changed) before any \
             approval is requested when the harness, argv, env allowlist, timeout_s, output_cap_bytes, token \
             passing, workdir or prompt differ from what the run's dispatch_task approval bound. Always needs a \
             one-time human approval, which shows those fields and the attempt (from_fence) it resumes.",
            |ctx: ToolCtx, a: RunArgs| async move { resume(ctx, a).await },
        )
        // Gated in the handler, like dispatch_task: the approval shows the
        // resolved binding, and a resume bound to fail is refused unparked.
        .family("dispatch")
        .always_gated()
        .gates_in_handler(),
    );
    r.add(
        tool(
            "dispatch_retry_cancellation",
            "Operator only: retry the stop of a cancellation whose cessation is not confirmed. Returns {ok, \
             run_id, state, termination, cessation}.",
            |ctx: ToolCtx, a: RunArgs| async move { retry_cancellation(ctx, a).await },
        )
        .family("dispatch"),
    );
    r.add(
        tool(
            "dispatch_confirm_cancellation",
            "Operator only: confirm a cancellation after verifying the target is gone, releasing the task's live \
             slot. Records the operator and the note. Returns {ok, run_id, state, cessation}.",
            |ctx: ToolCtx, a: ConfirmArgs| async move { confirm_cancellation(ctx, a).await },
        )
        .family("dispatch"),
    );
    r.add(
        tool(
            "dispatch_delivery_receipt",
            "Read-only accountability receipt for one dispatch run: task, lease, fence, transitions, approval, \
             evidence, exit, stored outcome receipts and the final task state.",
            |ctx: ToolCtx, a: RunArgs| async move { delivery_receipt(ctx, a).await },
        )
        .family("dispatch")
        .read_only(),
    );
    r.add(
        tool(
            "dispatch_delivery_receipts_list",
            "List recent dispatch runs as delivery-receipt summaries, newest first. Returns {receipts, count, \
             terminal_count}.",
            |ctx: ToolCtx, a: ListArgs| async move { receipts_list(ctx, a).await },
        )
        .family("dispatch")
        .read_only(),
    );
}

fn verified(caller: &Caller, tool: &str) -> UaResult<()> {
    if caller.kind == ActorKind::Anonymous {
        return Err(UaError::denied(
            "unauthenticated",
            format!("{tool} requires an authenticated hub identity"),
        ));
    }
    Ok(())
}

fn operator(cfg: &ua_core::Config, caller: &Caller, tool: &str) -> UaResult<()> {
    verified(caller, tool)?;
    if !super::is_operator(cfg, caller) {
        return Err(UaError::denied(
            "operator_authorization_required",
            format!("{tool} requires an operator (a verified human)"),
        ));
    }
    Ok(())
}

fn trimmed(field: &str, v: &str) -> UaResult<String> {
    let t = v.trim();
    if t.is_empty() {
        return Err(UaError::invalid(format!("{field} is required")));
    }
    Ok(t.to_string())
}

/// The caller's organization's run `run_id`; another organization's answers
/// exactly like an unknown one.
async fn require_run(ctx: &ToolCtx, run_id: &str) -> UaResult<super::Run> {
    let (rid, org) = (run_id.to_string(), ctx.caller.org_id.clone());
    ctx.hub
        .db()
        .read_async(move |c| load_run(c, &org, &rid))
        .await?
        .ok_or_else(|| UaError::not_found(format!("unknown dispatch run: {run_id}")))
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// A local harness is a process the hub spawns on its own host, in a
/// directory of the hub's filesystem: the default organization's. Another
/// organization's caller is refused (`org_unsupported`) before the harness
/// is looked up, before a task's recorded `worktree_path` is resolved and
/// before any approval, so a path it recorded through `task_claim` is never
/// touched. Routing to a node is checked by the node tools; a run with no
/// harness spawns nothing.
fn require_hub_org_for_harness(caller: &Caller) -> UaResult<()> {
    if caller.org_id != ua_core::DEFAULT_ORG {
        return Err(UaError::denied(
            "org_unsupported",
            "a local harness runs as a process on the hub, which serves the default organization only; \
             nothing was resolved, started or written",
        ));
    }
    Ok(())
}

/// Resolve and check the directory a harness runs in: absolute, existing,
/// not the filesystem root and not inside the hub's home (`$UA_HOME`, which
/// holds the database and run logs).
fn resolve_workdir(raw: &str, ua_home: &Path) -> UaResult<PathBuf> {
    let p = PathBuf::from(raw);
    if !p.is_absolute() {
        return Err(UaError::invalid(format!("worktree {raw:?} must be an absolute path")));
    }
    let canon = p.canonicalize().map_err(|_| UaError::invalid(format!("worktree {raw:?} does not exist")))?;
    if !canon.is_dir() {
        return Err(UaError::invalid(format!("worktree {raw:?} is not a directory")));
    }
    if canon.parent().is_none() {
        return Err(UaError::invalid("a harness may not run in the filesystem root"));
    }
    let home = ua_home.canonicalize().unwrap_or_else(|_| ua_home.to_path_buf());
    if canon.starts_with(&home) {
        return Err(UaError::invalid(format!(
            "worktree {raw:?} is inside the hub home; a harness may not run there"
        )));
    }
    Ok(canon)
}

/// Refuse a task another agent holds, a terminal task, or one with a live run.
/// `task_id` is a task of organization `org`; another organization's task
/// answers as a missing one.
fn check_task_free(
    conn: &rusqlite::Connection,
    org: &str,
    task_id: i64,
    agent: &str,
    run_id: Option<&str>,
) -> UaResult<()> {
    let task = require_task(conn, org, task_id)?;
    let status = str_field(&task, "status").unwrap_or_default();
    if crate::families::tasks::is_terminal(status) {
        return Err(UaError::conflict(format!("task_terminal: task {task_id} is {status}")));
    }
    if let Some(holder) = str_field(&task, "claimed_by")
        && holder != agent
        && str_field(&task, "lock_expires_at").is_some_and(|exp| !ts_le(exp, &now()))
    {
        return Err(UaError::conflict(format!("task_claimed: task {task_id} is claimed by {holder:?}")));
    }
    if let Some(live) = live_run_for_task(conn, org, task_id)?
        && Some(live.as_str()) != run_id
    {
        return Err(UaError::conflict(format!("already_claimed: run {live} holds task {task_id}")));
    }
    Ok(())
}

/// Point the task at the run and claim it for the agent.
fn bind_task(
    tx: &rusqlite::Connection,
    org: &str,
    task_id: i64,
    run_id: &str,
    agent: &str,
    lease: &str,
) -> UaResult<()> {
    tx.execute(
        "UPDATE tasks SET claimed_by = ?2, claimed_at = ?3, lock_expires_at = ?4, current_run_id = ?5, \
         current_run_agent = ?2, status = CASE WHEN status = 'open' THEN 'doing' ELSE status END, updated_at = ?6 \
         WHERE id = ?1 AND org_id = ?7",
        params![task_id, agent, now(), lease, run_id, next_revision(None), org],
    )?;
    Ok(())
}

/// Attach approval `approval_id` of organization `org` (just consumed) to
/// the run.
fn link_approval_id(tx: &rusqlite::Connection, org: &str, approval_id: i64, run_id: &str) -> UaResult<()> {
    let n = tx.execute(
        "UPDATE approvals SET run_id = ?1 WHERE org_id = ?3 AND id = ?2 AND status = 'consumed' AND run_id IS NULL",
        params![run_id, approval_id, org],
    )?;
    expect_one_link(n, run_id)
}

fn expect_one_link(n: usize, run_id: &str) -> UaResult<()> {
    if n != 1 {
        return Err(UaError::conflict(format!(
            "approval_link_failed: expected one consumed approval to link to run {run_id}, found {n}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// dispatch_task
// ---------------------------------------------------------------------------

/// Argument keys of a `dispatch_task` approval payload; the rest of the
/// payload is the binding resolved from them.
const ARG_KEYS: [&str; 8] =
    ["task_id", "agent", "harness", "prompt", "lease_seconds", "node", "backend", "node_timeout_s"];
const BOUND_KEYS: [&str; 19] = [
    "node_cwd",
    "env_sha256",
    "env_denylist",
    "program",
    "path_prepend",
    "stdin",
    "provider_account",
    "rerouted_from",
    "run_id",
    "workdir",
    "argv",
    "env_allowlist",
    "timeout_s",
    "output_cap_bytes",
    "prompt_source",
    "prompt_sha256",
    "prompt_bytes",
    "prompt_text",
    "passes_token_of",
];

/// What a harness launch is bound to, as approval payload fields: the
/// harness, resolved workdir, argv template, the absolute program `argv[0]`
/// resolves to, env allowlist, wall-clock limit, output cap and, when it is
/// passed, whose token the child gets. Fixed `env` values are bound by their
/// SHA-256, never shown raw.
fn harness_binding(
    harness: Option<&(String, ua_core::config::HarnessConfig)>,
    workdir: Option<&Path>,
    agent: &str,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("harness".into(), json!(harness.map(|(n, _)| n.clone())));
    m.insert("workdir".into(), json!(workdir.map(|p| p.display().to_string())));
    m.insert("argv".into(), json!(harness.map(|(_, h)| h.argv.clone())));
    m.insert(
        "program".into(),
        json!(
            harness.and_then(|(_, h)| executor::resolve_program(h, workdir)).map(|p| p.display().to_string())
        ),
    );
    m.insert("env_allowlist".into(), json!(harness.map(|(_, h)| h.env_allowlist.clone())));
    m.insert("timeout_s".into(), json!(harness.map(|(_, h)| h.timeout_s)));
    m.insert("output_cap_bytes".into(), json!(harness.map(|(_, h)| h.output_cap_bytes)));
    if harness.is_some_and(|(_, h)| h.pass_agent_token) {
        m.insert("passes_token_of".into(), json!(agent));
    }
    // Launch settings an approver must see, bound only when a harness sets them.
    if let Some((_, h)) = harness {
        if !h.env.is_empty() {
            let hashed: Map<String, Value> =
                h.env.iter().map(|(k, v)| (k.clone(), json!(sha256_hex(v)))).collect();
            m.insert("env_sha256".into(), Value::Object(hashed));
        }
        if !h.env_denylist.is_empty() {
            m.insert("env_denylist".into(), json!(h.env_denylist));
        }
        if !h.path_prepend.is_empty() {
            m.insert("path_prepend".into(), json!(h.path_prepend));
        }
        if let Some(t) = &h.stdin {
            m.insert("stdin".into(), json!(t));
        }
        if let Some(a) = &h.provider_account {
            m.insert("provider_account".into(), json!(a));
        }
    }
    m
}

/// The longest prompt built from a task that may be approved. The approver
/// is shown the whole text, never a preview: task notes are agent-writable,
/// so anything cut from view could carry instructions nobody read. Longer
/// prompts must be passed explicitly in `prompt`.
const PROMPT_SHOW_MAX_CHARS: usize = 16_000;

/// How many recent passes [`stale_pass`] looks at.
const STALE_PASS_SCAN: i64 = 50;

/// A run id that is stable between the call that requests the approval and
/// the call that consumes it: derived from a random per-database salt, the
/// task, how many runs it has had, and the agent. Another run of the task in
/// between changes it, which the approval binding then reports.
fn derive_run_id(tx: &rusqlite::Connection, org: &str, task_id: i64, agent: &str) -> UaResult<String> {
    let salt: Option<String> = tx
        .query_row("SELECT value FROM dispatch_meta WHERE key = 'run_id_salt'", [], |r| r.get(0))
        .optional()?;
    let salt = match salt {
        Some(s) => s,
        None => {
            let s = uuid::Uuid::new_v4().simple().to_string();
            tx.execute("INSERT INTO dispatch_meta (key, value) VALUES ('run_id_salt', ?1)", [&s])?;
            s
        }
    };
    // A task's runs are all its own organization's (`dispatch_runs_org_parent`).
    let prior: i64 = tx.query_row(
        "SELECT COUNT(*) FROM dispatch_runs WHERE org_id = ?2 AND task_id = ?1",
        params![task_id, org],
        |r| r.get(0),
    )?;
    let h = sha256_hex(&format!("{salt}:{task_id}:{prior}:{agent}"));
    Ok(format!("run-{task_id}-{}", &h[..8]))
}

/// The default prompt for a run routed to a node: the node's receipt
/// reports the outcome, so the session is not asked to report it.
fn node_prompt(task_id: i64, task: &Map<String, Value>, notes: &str, run_id: &str, node: &str) -> String {
    let notes: String = notes.chars().take(8000).collect();
    format!(
        "Task #{task_id}: {}\n\n{notes}\n\nYou are dispatch run {run_id} on node {node}. The hub records the \
         outcome from this session's end; do the work and leave a clear final summary.",
        str_field(task, "title").unwrap_or_default()
    )
}

/// The default prompt: the task title and notes, and the run to report on.
/// `notes` is the task's work order: its notes, or for a task an approved
/// work proposal spawned, the contract block alone.
fn default_prompt(task_id: i64, task: &Map<String, Value>, notes: &str, run_id: &str) -> String {
    let notes: String = notes.chars().take(8000).collect();
    format!(
        "Task #{task_id}: {}\n\n{notes}\n\nYou are dispatch run {run_id}. When done, call \
         dispatch_report_self(state, run_id=\"{run_id}\", evidence=...).",
        str_field(task, "title").unwrap_or_default()
    )
}

/// An approved, unconsumed, unexpired pass for the same arguments whose
/// binding no longer matches: its id and the bound fields that changed. Only
/// the latest [`STALE_PASS_SCAN`] passes within the pass TTL are read.
fn stale_pass(
    tx: &rusqlite::Connection,
    cfg: &ua_core::Config,
    org: &str,
    requester: &str,
    payload: &Value,
) -> UaResult<Option<(i64, Vec<String>, String)>> {
    let ttl = jiff::SignedDuration::from_secs((cfg.approval_pass_ttl_hours.max(0.0) * 3600.0) as i64);
    let cutoff =
        ua_core::time::format_ts(jiff::Timestamp::now().checked_sub(ttl).unwrap_or(jiff::Timestamp::MIN));
    let mut stmt = tx.prepare(
        "SELECT id, payload FROM approvals WHERE org_id = ?4 AND tool = 'dispatch_task' AND requested_by = ?1 \
         AND status = 'approved' AND resolved_at >= ?2 ORDER BY id DESC LIMIT ?3",
    )?;
    let rows: Vec<(i64, String)> = stmt
        .query_map(params![requester, cutoff, STALE_PASS_SCAN, org], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for (id, text) in rows {
        let Ok(old) = serde_json::from_str::<Value>(&text) else { continue };
        if ARG_KEYS.iter().any(|k| old.get(k) != payload.get(k)) {
            continue;
        }
        let changed: Vec<String> =
            BOUND_KEYS.iter().filter(|k| old.get(**k) != payload.get(**k)).map(|k| k.to_string()).collect();
        if !changed.is_empty() {
            return Ok(Some((id, changed, approvals::payload_sha256("dispatch_task", &old))));
        }
    }
    Ok(None)
}

enum Gated {
    Run {
        run_id: String,
        prompt: String,
        workdir: Option<PathBuf>,
        harness: Box<Option<(String, ua_core::config::HarnessConfig)>>,
        rerouted_from: Option<Value>,
        program: Option<PathBuf>,
    },
    Routed(Value),
    Pending {
        approval_id: i64,
        stale: Option<(i64, Vec<String>)>,
    },
    Denied {
        approval_id: i64,
        reason: Option<String>,
    },
}

/// The node a run is routed to: registered in the dispatcher's organization
/// `org` (another organization's node answers as unregistered), in service,
/// owned by the run's agent and advertising the backend; the backend, and
/// the working directory on the node (the task's worktree when it lies
/// under one of the node's roots, else the node's first existing root).
fn node_route(
    tx: &rusqlite::Connection,
    cfg: &ua_core::Config,
    org: &str,
    node: &str,
    agent: &str,
    backend: Option<&str>,
    task: &Map<String, Value>,
) -> UaResult<(node_queue::NodeRow, String, String)> {
    let name = super::super::nodes::validate_node_name(node)?;
    let Some(row) = node_queue::load_node(tx, org, &name)? else {
        return Err(UaError::not_found(format!("node {name:?} is not registered")));
    };
    if row.agent != agent {
        return Err(UaError::denied(
            "node_owned_elsewhere",
            format!("node {name:?} belongs to {:?}, not the run's agent {agent:?}", row.agent),
        ));
    }
    let advertised: Vec<String> = row.backends().unwrap_or_default();
    let backend = match backend.map(|b| b.trim().to_ascii_lowercase()).filter(|b| !b.is_empty()) {
        Some(b) => b,
        None => {
            advertised.iter().find(|b| !matches!(b.as_str(), "acceptance" | "command")).cloned().ok_or_else(
                || UaError::invalid(format!("node {name:?} advertises no backend; pass backend")),
            )?
        }
    };
    if matches!(backend.as_str(), "acceptance" | "command") {
        return Err(UaError::invalid("a dispatch run cannot use the acceptance or command backend"));
    }
    let roots: Vec<(String, bool)> = row
        .facts
        .get("worktree_roots")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|r| {
                    let path = r.get("realpath").or_else(|| r.get("path")).and_then(Value::as_str)?;
                    Some((path.to_string(), r.get("exists") != Some(&json!(false))))
                })
                .collect()
        })
        .unwrap_or_default();
    let inside = |p: &str, root: &str| {
        let parts = |s: &str| {
            s.split('/').filter(|c| !c.is_empty() && *c != ".").map(str::to_string).collect::<Vec<_>>()
        };
        p.starts_with('/') && !p.split('/').any(|c| c == "..") && parts(p).starts_with(&parts(root))
    };
    let worktree = str_field(task, "worktree_path");
    let cwd = worktree
        .filter(|w| roots.iter().any(|(r, exists)| *exists && inside(w, r)))
        .map(str::to_string)
        .or_else(|| roots.iter().find(|(_, exists)| *exists).map(|(r, _)| r.clone()))
        .ok_or_else(|| {
            UaError::conflict_code(
                "node_no_worktree_root",
                format!("node {name:?} reports no usable worktree root"),
            )
        })?;
    let probe = node_queue::validate_new(&name, &backend, "probe", &cwd, None, None, None, None, None, None)?;
    node_queue::accepting_node(tx, cfg, org, &probe)?;
    Ok((row, backend, cwd))
}

/// Queue the run's node work item and mark the run launched, linked to it.
#[allow(clippy::too_many_arguments)]
fn route_to_node(
    tx: &mut ua_store::WriteTx<'_>,
    hub: &crate::hub::Hub,
    org: &str,
    actor: &str,
    run_id: &str,
    task_id: i64,
    row: &node_queue::NodeRow,
    backend: &str,
    cwd: &str,
    prompt: &str,
    timeout_s: i64,
) -> UaResult<Value> {
    let mut n = node_queue::validate_new(
        &row.node,
        backend,
        prompt,
        cwd,
        None,
        None,
        None,
        Some(timeout_s),
        Some(task_id),
        None,
    )?;
    n.run_id = Some(run_id.to_string());
    let queued = node_queue::insert_item(tx, hub, org, &n, row, actor)?;
    let item_id = queued["item_id"].as_str().unwrap_or_default().to_string();
    let evidence = node_queue::evidence_ref(&row.node, &item_id);
    let run = load_run(tx, org, run_id)?.ok_or_else(|| UaError::internal("routed run vanished"))?;
    let edge = Edge::to("launched").set("evidence_ref", evidence.clone());
    if let Err(why) = transition(tx, &run, edge)? {
        return Err(UaError::conflict(format!("run {run_id} could not be routed: {why}")));
    }
    record_transition(
        tx,
        org,
        run_id,
        "launched",
        actor,
        json!({ "routed": "node", "node": row.node, "item_id": item_id, "backend": backend }),
    )?;
    Ok(json!({
        "ok": true,
        "run_id": run_id,
        "state": "launched",
        "fence": 1,
        "routed": "node",
        "node": row.node,
        "backend": backend,
        "cwd": cwd,
        "item_id": item_id,
        "evidence_ref": evidence,
        "waiting": queued.get("waiting").cloned().unwrap_or(Value::Null),
        "spawned": false,
    }))
}

async fn dispatch_task(ctx: ToolCtx, a: TaskArgs) -> UaResult<Value> {
    let agent = check_slug("agent", &a.agent)?;
    check_agent_or_operator(ctx.hub.cfg(), &ctx.caller, "dispatch_task", &agent)?;
    if let Err(refusal) = crate::policy::check_prod_action(ctx.hub.cfg(), &ctx.caller, "dispatch_task") {
        return Err(refusal.error);
    }
    let cfg = ctx.hub.cfg().clone();
    let named = a.harness.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if named.is_some() {
        require_hub_org_for_harness(&ctx.caller)?;
    }
    let harness = match named {
        Some(name) => Some((
            name.to_string(),
            cfg.harnesses
                .get(name)
                .cloned()
                .ok_or_else(|| UaError::invalid(format!("unknown harness {name:?}")))?,
        )),
        None => None,
    };
    if let Some((name, h)) = &harness
        && h.argv.first().is_none_or(|p| p.trim().is_empty())
    {
        return Err(UaError::invalid(format!("harness {name:?} has an empty argv")));
    }
    let lease = match a.lease_seconds {
        Some(s) if !(1..=MAX_LEASE_SECONDS).contains(&s) => {
            return Err(UaError::invalid(format!("lease_seconds must be 1-{MAX_LEASE_SECONDS}")));
        }
        Some(s) => s as u64,
        None => cfg.dispatch_lease_seconds.max(1),
    };
    if a.prompt.as_ref().is_some_and(|p| p.len() > PROMPT_CAP) {
        return Err(UaError::invalid(format!("prompt is longer than {PROMPT_CAP} bytes")));
    }
    let node = a.node.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    if node.is_none() && (a.backend.is_some() || a.node_timeout_s.is_some()) {
        return Err(UaError::invalid("backend and node_timeout_s apply only with node"));
    }
    if node.is_some() && harness.is_some() {
        return Err(UaError::invalid("a run goes to a local harness or to a node, not both"));
    }
    let node_timeout = a.node_timeout_s.unwrap_or(node_queue::DEFAULT_TIMEOUT_S);
    if !(1..=node_queue::MAX_TIMEOUT_S).contains(&node_timeout) {
        return Err(UaError::invalid(format!("node_timeout_s must be 1-{}", node_queue::MAX_TIMEOUT_S)));
    }

    // Resolve what will run, gate on it, and mint the run, in one write
    // transaction: nothing the approval covers can change in between.
    let tid = a.task_id;
    let (hub, caller, ag) = (ctx.hub.clone(), ctx.caller.clone(), agent.clone());
    let h2 = harness.clone();
    let lease_at = after_seconds(lease);
    let gated = ctx
        .hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &caller.org_id)?;
            let task = require_task(tx, &caller.org_id, tid)?;
            check_task_free(tx, &caller.org_id, tid, &ag, None)?;
            // The one claim gate: a stopped agent or a held task takes no run.
            governance::check_claim(tx, &caller.org_id, Some(&ag), Some(tid), false)?;
            // A proposal-spawned task must still match its frozen contract,
            // and its work order is the contract block: notes appended after
            // it never reach a prompt the hub builds.
            let work_order = governance::check_contract(
                tx,
                &caller.org_id,
                tid,
                str_field(&task, "title").unwrap_or_default(),
                str_field(&task, "notes").unwrap_or_default(),
            )?;
            let notes = work_order.unwrap_or_else(|| str_field(&task, "notes").unwrap_or_default().to_string());
            // The harness's provider account must be able to take the run;
            // with provider_fallback another harness of the provider may.
            let (h2, rerouted_from) = match h2 {
                None => (None, None),
                Some((name, h)) => {
                    let (name, h, from) = provider_accounts::select_harness(tx, hub.cfg(), name, h)?;
                    provider_accounts::check_billing_env(tx, &name, &h)?;
                    (Some((name, h)), from)
                }
            };
            let workdir = match &h2 {
                None => None,
                Some((name, h)) => {
                    let raw = str_field(&task, "worktree_path")
                        .map(str::to_string)
                        .or_else(|| h.workdir.as_ref().map(|p| p.display().to_string()))
                        .ok_or_else(|| {
                            UaError::invalid(format!(
                                "task {tid} records no worktree and harness {name:?} sets no workdir"
                            ))
                        })?;
                    Some(resolve_workdir(&raw, &hub.cfg().home)?)
                }
            };
            let route = match &node {
                None => None,
                Some(n) => Some(node_route(tx, hub.cfg(), &caller.org_id, n, &ag, a.backend.as_deref(), &task)?),
            };
            let run_id = derive_run_id(tx, &caller.org_id, tid, &ag)?;
            let (prompt, source) = match &a.prompt {
                Some(p) => (p.clone(), "args"),
                None => match &route {
                    Some((row, _, _)) => (node_prompt(tid, &task, &notes, &run_id, &row.node), "task"),
                    None => (default_prompt(tid, &task, &notes, &run_id), "task"),
                },
            };
            if prompt.len() > PROMPT_CAP {
                return Err(UaError::invalid(format!("prompt is longer than {PROMPT_CAP} bytes")));
            }
            let prompt_sha = sha256_hex(&prompt);
            let mut payload = json!({
                "task_id": tid,
                "agent": ag,
                "lease_seconds": lease,
                "run_id": run_id,
                "prompt_source": source,
                "prompt_sha256": prompt_sha,
            });
            if let Some(o) = payload.as_object_mut() {
                o.extend(harness_binding(h2.as_ref(), workdir.as_deref(), &ag));
            }
            if let Some(from) = &rerouted_from {
                payload["rerouted_from"] = from.clone();
            }
            if let Some((row, backend, cwd)) = &route {
                payload["node"] = json!(row.node);
                payload["backend"] = json!(backend);
                payload["node_cwd"] = json!(cwd);
                payload["node_timeout_s"] = json!(node_timeout);
            }
            match &a.prompt {
                Some(p) => payload["prompt"] = json!(p),
                // The approver sees the whole prompt the hub built from the
                // task, as they see a prompt passed in the arguments.
                None => {
                    if prompt.chars().count() > PROMPT_SHOW_MAX_CHARS {
                        return Err(UaError::invalid(format!(
                            "the prompt built from task {} is longer than {PROMPT_SHOW_MAX_CHARS} characters, \
                             too long to show the approver in full; pass `prompt` explicitly",
                            a.task_id
                        )));
                    }
                    payload["prompt_bytes"] = json!(prompt.len());
                    payload["prompt_text"] = json!(prompt);
                }
            }
            let approval_id = match approvals::gate(tx, hub.cfg(), &caller, "dispatch_task", &payload)? {
                GateOutcome::Pass { approval_id } => approval_id,
                GateOutcome::Pending { approval_id } => {
                    let stale = stale_pass(tx, hub.cfg(), &caller.org_id, &caller.label, &payload)?;
                    let stale = match stale {
                        Some((old, changed, approved_sha)) => {
                            let r = Refusal::new("dispatch_task", RefusalReason::BindingChanged)
                                .approval(old)
                                .task(Some(tid))
                                .hashes(Some(approved_sha), Some(approvals::payload_sha256("dispatch_task", &payload)))
                                .changed(changed.clone());
                            approvals::refused(tx, &caller.org_id, &caller.label, &r, None)?;
                            Some((old, changed))
                        }
                        None => None,
                    };
                    return Ok(Gated::Pending { approval_id, stale });
                }
                GateOutcome::Denied { approval_id, reason } => return Ok(Gated::Denied { approval_id, reason }),
            };
            let ts = now();
            tx.execute(
                "INSERT INTO dispatch_runs (run_id, task_id, agent_label, harness, state, actor, lease_owner, \
                 lease_expires_at, attempt, fence, workdir, prompt, prompt_sha256, created_at, updated_at, \
                 provider_account, org_id) \
                 VALUES (?1, ?2, ?3, ?4, 'claimed', ?5, ?5, ?6, 1, 1, ?7, ?8, ?9, ?10, ?10, ?11, ?12)",
                params![
                    run_id,
                    tid,
                    ag,
                    payload["harness"].as_str(),
                    caller.label,
                    lease_at,
                    payload["workdir"].as_str(),
                    prompt,
                    prompt_sha,
                    ts,
                    payload["provider_account"].as_str(),
                    caller.org_id,
                ],
            )?;
            bind_task(tx, &caller.org_id, tid, &run_id, &ag, &lease_at)?;
            link_approval_id(tx, &caller.org_id, approval_id, &run_id)?;
            record_transition(
                tx,
                &caller.org_id,
                &run_id,
                "claimed",
                &caller.label,
                json!({ "approval_id": approval_id }),
            )?;
            if let Some((row, backend, cwd)) = route {
                let out = route_to_node(tx, &hub, &caller.org_id, &caller.label, &run_id, tid, &row, &backend, &cwd, &prompt, node_timeout)?;
                return Ok(Gated::Routed(out));
            }
            let program = payload["program"].as_str().map(PathBuf::from);
            Ok(Gated::Run { run_id, prompt, workdir, harness: Box::new(h2), rerouted_from, program })
        })
        .await?;
    let (run_id, prompt, workdir, harness, rerouted_from, program) = match gated {
        Gated::Run { run_id, prompt, workdir, harness, rerouted_from, program } => {
            (run_id, prompt, workdir, *harness, rerouted_from, program)
        }
        Gated::Routed(mut out) => {
            out["task_id"] = json!(tid);
            out["agent_label"] = json!(agent);
            return Ok(out);
        }
        Gated::Pending { approval_id, stale: None } => {
            return Err(UaError::ApprovalRequired { tool: "dispatch_task".into(), approval_id });
        }
        Gated::Pending { approval_id, stale: Some((old, changed)) } => {
            return Err(UaError::denied(
                "approval_binding_changed",
                format!(
                    "approval {old} no longer matches what would run (changed: {}); approval {approval_id} \
                     was requested for the current values",
                    changed.join(", ")
                ),
            ));
        }
        Gated::Denied { approval_id, reason } => {
            return Err(UaError::denied(
                "approval_denied",
                format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
            ));
        }
    };

    let mut out = match harness {
        None => {
            executor::launch_stub(
                &ctx.hub,
                ctx.caller.org_id.clone(),
                run_id.clone(),
                ctx.caller.label.clone(),
            )
            .await?
        }
        Some((harness_name, h)) => {
            let spec = LaunchSpec {
                org: ctx.caller.org_id.clone(),
                run_id: run_id.clone(),
                task_id: tid,
                agent: agent.clone(),
                fence: 1,
                harness_name,
                harness: h,
                workdir: workdir.unwrap_or_default(),
                prompt,
                actor: ctx.caller.label.clone(),
                program,
            };
            executor::launch(&ctx.hub, spec).await?
        }
    };
    if let Some(o) = out.as_object_mut() {
        o.insert("task_id".into(), json!(tid));
        o.insert("agent_label".into(), json!(agent));
        o.entry("fence").or_insert(json!(1));
        if let Some(from) = rerouted_from {
            o.insert("rerouted_from".into(), from);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// dispatch_report_self
// ---------------------------------------------------------------------------

async fn report_self(ctx: ToolCtx, a: ReportArgs) -> UaResult<Value> {
    verified(&ctx.caller, "dispatch_report_self")?;
    let rid = trimmed("run_id", &a.run_id)?;
    let state: &'static str = match a.state.trim() {
        "finished" => "finished",
        "failed" => "failed",
        "blocked" => "blocked",
        other => {
            return Err(UaError::invalid(format!(
                "state must be one of {:?}; got {other:?}",
                states::SELF_REPORT
            )));
        }
    };
    let run = require_run(&ctx, &rid).await?;
    check_run_owner(&ctx.caller, "dispatch_report_self", &run)?;
    if run.evidence_ref.as_deref().is_some_and(|e| e.starts_with("node:")) {
        return Err(UaError::conflict(
            "run was routed to a node: its outcome comes from the node's receipt, not dispatch_report_self",
        ));
    }
    let evidence = a.evidence.map(|e| e.trim().to_string()).filter(|e| !e.is_empty());
    if state == "finished" && evidence.is_none() {
        return Err(UaError::invalid(
            "finished requires non-empty evidence (commit SHA, PR URL, or child-authored log path)",
        ));
    }
    if let Some(u) = &a.usage
        && !u.is_object()
    {
        return Err(UaError::invalid("usage must be an object"));
    }
    let reason = a
        .failure_reason
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .or_else(|| (state != "finished").then(|| format!("self_report:{state}")));
    let identity = ctx.caller.label.clone();
    let (rid2, id2, ev2, org) = (rid.clone(), identity.clone(), evidence.clone(), ctx.caller.org_id.clone());
    let outcome = ctx
        .hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            record_outcome(
                tx,
                Outcome {
                    org: &org,
                    run_id: &rid2,
                    fence: a.fence,
                    state,
                    actor: &id2,
                    source: "self_report",
                    evidence: ev2,
                    failure_reason: reason,
                    failure_class: None,
                    usage: a.usage,
                    quota_signal: None,
                },
            )
        })
        .await?;
    Ok(json!({
        "ok": outcome["ok"] == json!(true),
        "run_id": rid,
        "state": state,
        "agent_label": identity,
        "evidence_ref": evidence,
        "outcome": outcome,
    }))
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

async fn cancel(ctx: ToolCtx, a: CancelArgs) -> UaResult<Value> {
    verified(&ctx.caller, "dispatch_cancel")?;
    let rid = trimmed("run_id", &a.run_id)?;
    let run = require_run(&ctx, &rid).await?;
    check_agent_or_operator(ctx.hub.cfg(), &ctx.caller, "dispatch_cancel", &run.agent_label)?;
    let reason =
        a.reason.map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).unwrap_or("client cancelled".into());
    cancel_run(&ctx.hub, ctx.caller.org_id.clone(), ctx.caller.label.clone(), rid, reason).await
}

/// Cancel one run of organization `org` as `actor`: record the intent, stop
/// the process (or ask the node to), and commit the outcome. The caller has
/// checked authority. A refusal is an `{ok: false, reason}` reply, not an
/// error; another organization's run answers as unknown.
pub(crate) async fn cancel_run(
    hub: &Hub,
    org: String,
    actor: String,
    rid: String,
    reason: String,
) -> UaResult<Value> {
    // 1. Record the intent (state unchanged) as a compare-and-swap.
    let (rid2, actor2, reason2, org2) = (rid.clone(), actor.clone(), reason.clone(), org.clone());
    let intent = hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org2)?;
            let Some(run) = load_run(tx, &org2, &rid2)? else {
                return Ok(Err(refusal("unknown_run", &rid2, json!({}))));
            };
            if !states::is_live(&run.state) {
                return Ok(Err(refusal("already_terminal", &rid2, json!({ "state": run.state }))));
            }
            if run.termination_outcome.is_some() {
                return Ok(Err(refusal(
                    "cancellation_in_progress",
                    &rid2,
                    json!({ "state": run.state, "termination_outcome": run.termination_outcome }),
                )));
            }
            let edge = Edge {
                to: None,
                sets: vec![
                    ("termination_outcome", "requested".to_string().into()),
                    ("cancelled_by", actor2.clone().into()),
                ],
                require_unlocked: true,
            };
            if let Err(why) = transition(tx, &run, edge)? {
                return Ok(Err(refusal(why, &rid2, json!({ "state": run.state }))));
            }
            record_transition(
                tx,
                &org2,
                &rid2,
                "cancel_requested",
                &actor2,
                json!({ "reason": reason2, "cancelled_by": actor2, "on_behalf": actor2 != run.agent_label }),
            )?;
            Ok(Ok(()))
        })
        .await?;
    if let Err(r) = intent {
        return Ok(r);
    }

    // 2. Stop the process (re-read: a launch may have recorded a pid since).
    // A node-routed run is stopped by its node: cessation is confirmed only
    // by the node's receipt, unless the item was never claimed.
    let (rid3, org3) = (rid.clone(), org.clone());
    let fresh = hub
        .db()
        .read_async(move |c| load_run(c, &org3, &rid3))
        .await?
        .ok_or_else(|| UaError::not_found(format!("unknown dispatch run: {rid}")))?;
    let termination = match fresh.evidence_ref.clone().filter(|e| e.starts_with("node:")) {
        Some(ev) => {
            let (by, org4) = (actor.clone(), org.clone());
            hub.db()
                .write_async(move |tx| {
                    Ok(node_queue::cancel_for_run(tx, &org4, &ev, &by)?.unwrap_or("unknown"))
                })
                .await?
        }
        None => blocking(move || Ok(executor::terminate(&fresh))).await?,
    };
    let cessation = classify_termination(termination);

    // 3. Commit the outcome.
    let by = actor.clone();
    let mut out = hub
        .db()
        .write_async(move |tx| {
            finalize_cancellation(tx, &org, &rid, &actor, "cancel", &reason, termination, cessation)
        })
        .await?;
    if let Some(o) = out.as_object_mut() {
        o.insert("cancelled_by".into(), json!(by));
    }
    Ok(out)
}

fn reconcilable_for_retry(run: &super::Run) -> bool {
    matches!(run.state.as_str(), "cancelled" | "blocked")
        && matches!(run.termination_outcome.as_deref(), None | Some("requested") | Some("unknown"))
}

async fn retry_cancellation(ctx: ToolCtx, a: RunArgs) -> UaResult<Value> {
    operator(ctx.hub.cfg(), &ctx.caller, "dispatch_retry_cancellation")?;
    let rid = trimmed("run_id", &a.run_id)?;
    let run = require_run(&ctx, &rid).await?;
    if !reconcilable_for_retry(&run) {
        return Err(UaError::conflict(format!(
            "dispatch cancellation retry failed: not_reconcilable (state {}, termination_outcome {:?})",
            run.state, run.termination_outcome
        )));
    }
    let termination = blocking(move || Ok(executor::terminate(&run))).await?;
    let cessation = classify_termination(termination);
    let (actor, org) = (ctx.caller.label.clone(), ctx.caller.org_id.clone());
    let res = ctx
        .hub
        .db()
        .write_async(move |tx| {
            finalize_cancellation(
                tx,
                &org,
                &rid,
                &actor,
                "operator",
                "retry_cancellation",
                termination,
                cessation,
            )
        })
        .await?;
    if res["ok"] != json!(true) {
        return Err(UaError::conflict(format!("dispatch cancellation retry failed: {}", res["reason"])));
    }
    Ok(res)
}

async fn confirm_cancellation(ctx: ToolCtx, a: ConfirmArgs) -> UaResult<Value> {
    operator(ctx.hub.cfg(), &ctx.caller, "dispatch_confirm_cancellation")?;
    let rid = trimmed("run_id", &a.run_id)?;
    let run = require_run(&ctx, &rid).await?;
    if !matches!(run.state.as_str(), "cancelled" | "blocked")
        || run.termination_outcome.as_deref() == Some("confirmed")
    {
        return Err(UaError::conflict(format!(
            "dispatch cancellation confirmation failed: not_reconcilable (state {}, termination_outcome {:?})",
            run.state, run.termination_outcome
        )));
    }
    let note =
        a.note.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).unwrap_or("operator_confirmed".into());
    let (actor, org) = (ctx.caller.label.clone(), ctx.caller.org_id.clone());
    let res = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let reason = format!("operator_override:{note}");
            finalize_cancellation(
                tx,
                &org,
                &rid,
                &actor,
                "operator",
                &reason,
                "operator_confirmed",
                "confirmed",
            )
        })
        .await?;
    if res["ok"] != json!(true) {
        return Err(UaError::conflict(format!(
            "dispatch cancellation confirmation failed: {}",
            res["reason"]
        )));
    }
    Ok(res)
}

// ---------------------------------------------------------------------------
// dispatch_resume
// ---------------------------------------------------------------------------

/// Why a run cannot be resumed, or `None`.
fn resume_refusal(run: &super::Run) -> Option<String> {
    let s = run.state.as_str();
    if matches!(s, "finished" | "denied" | "expired") {
        return Some(format!("terminal_{s}"));
    }
    if states::is_live(s) {
        return Some("already_active".into());
    }
    if !states::RESUMABLE.contains(&s) {
        return Some(format!("unresumable_state_{s}"));
    }
    if s == "cancelled" && run.termination_outcome.as_deref() != Some("confirmed") {
        return Some("cessation_unconfirmed".into());
    }
    if s == "failed" && run.failure_reason.as_deref() == Some("lease_expired_outcome_unknown") {
        return Some("outcome_unknown".into());
    }
    None
}

/// Keys of the run's `dispatch_task` approval a resume must still match.
/// An approval recorded before `timeout_s` and `output_cap_bytes` were bound
/// lacks them, so it counts as changed and such a run must be dispatched
/// again: the approver never saw those limits.
const RESUME_BOUND_KEYS: [&str; 14] = [
    "harness",
    "env_sha256",
    "program",
    "env_denylist",
    "path_prepend",
    "stdin",
    "provider_account",
    "workdir",
    "argv",
    "env_allowlist",
    "timeout_s",
    "output_cap_bytes",
    "passes_token_of",
    "prompt_sha256",
];

/// A resume relaunches under the hub's current config. Refuse it
/// (`approval_binding_changed`) unless what it would run is what the run's
/// `dispatch_task` approval bound: the same harness, argv, env allowlist,
/// limits, token passing, resolved workdir and prompt. Returns those fields
/// for the resume's own approval payload.
///
/// A refusal is ledgered (`agent.approval.refused`, kept although the
/// caller's transaction rolls back) with the `dispatch_task` approval it
/// checked against.
fn check_resume_binding(
    tx: &mut ua_store::WriteTx<'_>,
    org: &str,
    caller: &str,
    run: &super::Run,
    harness: Option<&(String, ua_core::config::HarnessConfig)>,
    workdir: Option<&Path>,
) -> UaResult<Map<String, Value>> {
    let bound: Option<(i64, String)> = tx
        .query_row(
            "SELECT id, payload FROM approvals WHERE org_id = ?2 AND tool = 'dispatch_task' AND run_id = ?1 \
             AND status = 'consumed' ORDER BY id LIMIT 1",
            params![run.run_id, org],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((approval_id, bound)) =
        bound.and_then(|(id, t)| serde_json::from_str::<Value>(&t).ok().map(|v| (id, v)))
    else {
        let r = Refusal::new("dispatch_resume", RefusalReason::NoMatchingApproval).task(Some(run.task_id));
        approvals::refused(tx, org, caller, &r, None)?;
        return Err(UaError::denied(
            "approval_binding_changed",
            format!("run {} has no dispatch_task approval to resume under", run.run_id),
        ));
    };
    let mut current = harness_binding(harness, workdir, &run.agent_label);
    current.insert("prompt_sha256".into(), json!(sha256_hex(run.prompt.as_deref().unwrap_or_default())));
    let changed: Vec<&str> =
        RESUME_BOUND_KEYS.iter().copied().filter(|k| bound.get(*k) != current.get(*k)).collect();
    if !changed.is_empty() {
        // The approved payload against the same payload with what would
        // run now in place of the changed fields.
        let mut presented = bound.clone();
        if let Some(o) = presented.as_object_mut() {
            for k in &changed {
                match current.get(*k) {
                    Some(v) => o.insert(k.to_string(), v.clone()),
                    None => o.remove(*k),
                };
            }
        }
        let r = Refusal::new("dispatch_resume", RefusalReason::BindingChanged)
            .approval(approval_id)
            .task(Some(run.task_id))
            .hashes(
                Some(approvals::payload_sha256("dispatch_task", &bound)),
                Some(approvals::payload_sha256("dispatch_task", &presented)),
            )
            .changed(changed.iter().map(|k| k.to_string()).collect());
        approvals::refused(tx, org, caller, &r, None)?;
        return Err(UaError::denied(
            "approval_binding_changed",
            format!(
                "run {} no longer matches its dispatch_task approval (changed: {}); dispatch the task again",
                run.run_id,
                changed.join(", ")
            ),
        ));
    }
    Ok(current)
}

enum ResumeGate {
    Run { fence: i64, program: Option<PathBuf> },
    Pending { approval_id: i64 },
    Denied { approval_id: i64, reason: Option<String> },
}

async fn resume(ctx: ToolCtx, a: RunArgs) -> UaResult<Value> {
    verified(&ctx.caller, "dispatch_resume")?;
    let rid = trimmed("run_id", &a.run_id)?;
    let run = require_run(&ctx, &rid).await?;
    check_run_owner(&ctx.caller, "dispatch_resume", &run)?;
    if let Some(why) = resume_refusal(&run) {
        return Err(UaError::conflict(format!("dispatch resume failed: {why}")));
    }
    if run.evidence_ref.as_deref().is_some_and(|e| e.starts_with("node:")) {
        return Err(UaError::conflict(
            "dispatch resume failed: the run was routed to a node; dispatch the task to the node again",
        ));
    }
    if run.harness.is_some() {
        require_hub_org_for_harness(&ctx.caller)?;
    }
    let cfg = ctx.hub.cfg().clone();
    let harness = match &run.harness {
        None => None,
        Some(name) => Some((
            name.clone(),
            cfg.harnesses.get(name).cloned().ok_or_else(|| {
                UaError::conflict(format!("dispatch resume failed: harness {name:?} is no longer configured"))
            })?,
        )),
    };
    let workdir = match (&harness, run.workdir.as_deref()) {
        (Some(_), Some(w)) => Some(resolve_workdir(w, &cfg.home)?),
        (Some(_), None) => {
            return Err(UaError::conflict("dispatch resume failed: the run recorded no workdir"));
        }
        (None, _) => None,
    };
    let lease_at = after_seconds(cfg.dispatch_lease_seconds.max(1));
    let actor = ctx.caller.label.clone();
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let (rid2, actor2) = (rid.clone(), actor.clone());
    let (h2, w2) = (harness.clone(), workdir.clone());
    // Check, gate and transition in one write transaction: a resume bound to
    // fail is refused before a human is asked, and nothing the approval
    // shows can change between the check and the relaunch.
    let gated = ctx
        .hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &caller.org_id)?;
            let Some(run) = load_run(tx, &caller.org_id, &rid2)? else {
                return Err(UaError::not_found(format!("unknown dispatch run: {rid2}")));
            };
            if let Some(why) = resume_refusal(&run) {
                return Err(UaError::conflict(format!("dispatch resume failed: {why}")));
            }
            let binding =
                check_resume_binding(tx, &caller.org_id, &caller.label, &run, h2.as_ref(), w2.as_deref())?;
            // A resume runs what was approved: it is refused, never rerouted,
            // while the harness's provider account cannot take a run.
            if let Some((name, h)) = &h2 {
                provider_accounts::check_available(tx, name, h)?;
                provider_accounts::check_billing_env(tx, name, h)?;
            }
            check_task_free(tx, &caller.org_id, run.task_id, &run.agent_label, Some(&rid2))
                .map_err(|e| UaError::conflict(format!("dispatch resume failed: {e}")))?;
            // A resumed attempt is new work: the one claim gate applies, and
            // a proposal-spawned task must still match its frozen contract.
            governance::check_claim(tx, &caller.org_id, Some(&run.agent_label), Some(run.task_id), false)?;
            governance::task_contract(tx, &caller.org_id, run.task_id)?;
            // The approver sees what will run, and the attempt it replaces:
            // a pass resumes this attempt only.
            let mut payload = json!({
                "run_id": rid2,
                "task_id": run.task_id,
                "agent": run.agent_label,
                "from_fence": run.fence,
            });
            if let Some(o) = payload.as_object_mut() {
                o.extend(binding);
            }
            let approval_id = match approvals::gate(tx, hub.cfg(), &caller, "dispatch_resume", &payload)? {
                GateOutcome::Pass { approval_id } => approval_id,
                GateOutcome::Pending { approval_id } => return Ok(ResumeGate::Pending { approval_id }),
                GateOutcome::Denied { approval_id, reason } => {
                    return Ok(ResumeGate::Denied { approval_id, reason });
                }
            };
            let fence = run.fence + 1;
            let edge = Edge::to("claimed")
                .locked_ok()
                .set("fence", fence)
                .set("attempt", run.attempt + 1)
                .set("lease_owner", actor2.clone())
                .set("lease_expires_at", lease_at.clone())
                .set("timed_out", 0)
                .set("output_truncated", 0)
                .null("failure_reason")
                .null("failure_class")
                .null("evidence_ref")
                .null("termination_outcome")
                .null("pid")
                .null("pgid")
                .null("pid_start_time")
                .null("supervisor_pid")
                .null("supervisor_start_time")
                .null("cancelled_by")
                .null("exit_code")
                .null("exit_signal")
                .null("output_bytes")
                .null("started_at")
                .null("ended_at")
                .null("usage");
            if let Err(why) = transition(tx, &run, edge)? {
                return Err(UaError::conflict(format!("dispatch resume failed: {why}")));
            }
            bind_task(tx, &caller.org_id, run.task_id, &rid2, &run.agent_label, &lease_at)?;
            link_approval_id(tx, &caller.org_id, approval_id, &rid2)?;
            record_transition(
                tx,
                &caller.org_id,
                &rid2,
                "resumed",
                &actor2,
                json!({ "previous_fence": run.fence, "approval_id": approval_id }),
            )?;
            let program = payload["program"].as_str().map(PathBuf::from);
            Ok(ResumeGate::Run { fence, program })
        })
        .await?;
    let (fence, program) = match gated {
        ResumeGate::Run { fence, program } => (fence, program),
        ResumeGate::Pending { approval_id } => {
            return Err(UaError::ApprovalRequired { tool: "dispatch_resume".into(), approval_id });
        }
        ResumeGate::Denied { approval_id, reason } => {
            return Err(UaError::denied(
                "approval_denied",
                format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
            ));
        }
    };

    let mut out = match harness {
        None => {
            executor::launch_stub(&ctx.hub, ctx.caller.org_id.clone(), rid.clone(), actor.clone()).await?
        }
        Some((harness_name, h)) => {
            let spec = LaunchSpec {
                org: ctx.caller.org_id.clone(),
                run_id: rid.clone(),
                task_id: run.task_id,
                agent: run.agent_label.clone(),
                fence,
                harness_name,
                harness: h,
                workdir: workdir.unwrap_or_default(),
                prompt: run.prompt.clone().unwrap_or_default(),
                actor,
                program,
            };
            executor::launch(&ctx.hub, spec).await?
        }
    };
    if let Some(o) = out.as_object_mut() {
        o.insert("resumed".into(), json!(true));
        o.insert("fence".into(), json!(fence));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

fn transitions(conn: &rusqlite::Connection, run_id: &str) -> UaResult<Vec<Value>> {
    let mut stmt = conn.prepare(
        "SELECT ulid, payload FROM event_log WHERE channel = ?1 AND json_extract(payload, '$.run_id') = ?2 \
         ORDER BY seq",
    )?;
    let rows: Vec<(String, String)> = stmt
        .query_map(params![super::CHANNEL_TRANSITION, run_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|(ulid, payload)| {
            let p: Value = serde_json::from_str(&payload).ok()?;
            Some(json!({
                "ulid": ulid,
                "state": p.get("state"),
                "timestamp": p.get("timestamp"),
                "actor": p.get("actor"),
                "fence": p.get("fence"),
                "failure_reason": p.get("failure_reason"),
                "evidence_ref": p.get("evidence_ref"),
                "retry_count": p.get("retry_count"),
                "termination_outcome": p.get("termination_outcome"),
            }))
        })
        .collect())
}

fn build_receipt(conn: &rusqlite::Connection, org: &str, run_id: &str) -> UaResult<Value> {
    let Some(run) = run_object(conn, org, run_id)? else {
        return Err(UaError::not_found(format!("unknown dispatch run: {run_id}")));
    };
    let get = |k: &str| run.get(k).cloned().unwrap_or(Value::Null);
    let task_id = run.get("task_id").and_then(Value::as_i64).unwrap_or_default();
    let task_state: Option<String> = conn
        .query_row("SELECT status FROM tasks WHERE org_id = ?1 AND id = ?2", params![org, task_id], |r| {
            r.get(0)
        })
        .optional()?;
    let transitions = transitions(conn, run_id)?;
    let approval: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, status FROM approvals WHERE org_id = ?2 AND run_id = ?1 ORDER BY id DESC LIMIT 1",
            params![run_id, org],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let claimed = transitions.iter().any(|t| matches!(t["state"].as_str(), Some("claimed" | "resumed")));
    let state = run.get("state").and_then(Value::as_str).unwrap_or("unknown").to_string();
    let policy_outcome = if claimed {
        "approved"
    } else if state == "denied" {
        "denied"
    } else {
        "unknown"
    };
    let approval_outcome = match &approval {
        Some((_, status)) if status == "consumed" => "approved".to_string(),
        Some((_, status)) => status.clone(),
        // A minted run with no approval row behind it is never reported as
        // approved.
        None if claimed => "unlinked".into(),
        None => "not_requested".into(),
    };
    let mut receipts_stmt =
        conn.prepare("SELECT * FROM dispatch_receipts WHERE run_id = ?1 AND org_id = ?2 ORDER BY id")?;
    let receipts: Vec<Value> = receipts_stmt
        .query_map(params![run_id, org], row_object)?
        .map(|r| {
            r.map(|mut m| {
                m.remove("org_id");
                Value::Object(m)
            })
        })
        .collect::<Result<_, _>>()?;
    let attempt = run.get("attempt").and_then(Value::as_i64).unwrap_or(1);
    Ok(json!({
        "schema_version": "1.0",
        "task_id": task_id,
        "run_id": run_id,
        "delegation_id": get("delegation_id"),
        "executor_identity": get("agent_label"),
        "harness": get("harness"),
        "lease": {
            "owner": get("lease_owner"),
            "expires_at": get("lease_expires_at"),
            "active": states::is_live(&state),
        },
        "fence": get("fence"),
        "attempt": attempt,
        "retry_count": attempt - 1,
        "event_cursor": transitions.last().map(|t| t["ulid"].clone()),
        "policy_outcome": policy_outcome,
        "approval_outcome": approval_outcome,
        "approval_id": approval.map(|(id, _)| id),
        "evidence_ref": get("evidence_ref"),
        "failure_reason": get("failure_reason"),
        "failure_class": get("failure_class"),
        "provider_account": get("provider_account"),
        "termination_outcome": get("termination_outcome"),
        "cancelled_by": get("cancelled_by"),
        "final_task_state": task_state,
        "run_state": state,
        "terminal": states::is_terminal(&state),
        "exit": {
            "code": get("exit_code"),
            "signal": get("exit_signal"),
            "timed_out": get("timed_out") == json!(1),
            "output_bytes": get("output_bytes"),
            "output_truncated": get("output_truncated") == json!(1),
        },
        "pid": get("pid"),
        "log_path": get("log_path"),
        "usage": get("usage"),
        "transitions": transitions,
        "receipts": receipts,
        "executor_auth": { "status": "UNKNOWN", "authenticated": null, "probe_process": "hub_skipped" },
    }))
}

async fn delivery_receipt(ctx: ToolCtx, a: RunArgs) -> UaResult<Value> {
    let rid = trimmed("run_id", &a.run_id)?;
    let org = ctx.caller.org_id.clone();
    ctx.hub.db().read_async(move |c| build_receipt(c, &org, &rid)).await
}

const SUMMARY_FIELDS: [&str; 15] = [
    "run_id",
    "task_id",
    "delegation_id",
    "agent_label",
    "harness",
    "state",
    "actor",
    "fence",
    "lease_expires_at",
    "failure_reason",
    "failure_class",
    "evidence_ref",
    "termination_outcome",
    "created_at",
    "updated_at",
];

async fn receipts_list(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    if let Some(s) = &a.state
        && !states::ALL.contains(&s.as_str())
    {
        return Err(UaError::invalid(format!("state must be one of {:?}", states::ALL)));
    }
    let limit = a.limit.unwrap_or(20).clamp(1, 200);
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT * FROM dispatch_runs WHERE org_id = ?4 AND (?1 IS NULL OR task_id = ?1) \
                 AND (?2 IS NULL OR state = ?2) ORDER BY created_at DESC, rowid DESC LIMIT ?3",
            )?;
            let rows: Vec<Map<String, Value>> = stmt
                .query_map(params![a.task_id, a.state, limit, org], row_object)?
                .collect::<Result<_, _>>()?;
            let receipts: Vec<Value> = rows
                .into_iter()
                .map(|row| {
                    let mut out = Map::new();
                    for f in SUMMARY_FIELDS {
                        out.insert(f.into(), row.get(f).cloned().unwrap_or(Value::Null));
                    }
                    let state = row.get("state").and_then(Value::as_str).unwrap_or_default();
                    out.insert("terminal".into(), json!(states::is_terminal(state)));
                    out.insert(
                        "has_evidence".into(),
                        json!(row.get("evidence_ref").and_then(Value::as_str).is_some_and(|e| !e.is_empty())),
                    );
                    Value::Object(out)
                })
                .collect();
            let terminal = receipts.iter().filter(|r| r["terminal"] == json!(true)).count();
            Ok(json!({ "receipts": receipts, "count": receipts.len(), "terminal_count": terminal }))
        })
        .await
}
