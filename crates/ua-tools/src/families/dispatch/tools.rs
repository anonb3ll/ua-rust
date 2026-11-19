//! The dispatch tools.

use std::path::{Path, PathBuf};

use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use ua_core::{ActorKind, Caller, Profile, UaError, UaResult};

use super::executor::{self, LaunchSpec};
use super::{
    Edge, Outcome, after_seconds, check_agent_or_operator, check_run_owner, classify_termination,
    finalize_cancellation, live_run_for_task, load_run, now, record_outcome, record_transition, refusal,
    run_object, states, transition,
};
use crate::approvals::{self, GateOutcome};
use crate::families::tasks::{check_slug, next_revision, require_task, row_object, str_field, ts_le};
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
             argv template, env allowlist, prompt_sha256 and whether the agent's token is passed, and a pass \
             is refused (approval_binding_changed) if any of them changed since. Returns {ok, run_id, state, \
             fence, pid, log_path, spawned, stub}.",
            |ctx: ToolCtx, a: TaskArgs| async move { dispatch_task(ctx, a).await },
        )
        // Gated in the handler, not by the registry: the approval must cover
        // values resolved from the task and config, not just the arguments.
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
             the task, or cessation is unconfirmed, and is refused (approval_binding_changed) when the harness, \
             argv, env allowlist, token passing, workdir or prompt differ from what the run's dispatch_task \
             approval bound. Always needs a one-time human approval.",
            |ctx: ToolCtx, a: RunArgs| async move { resume(ctx, a).await },
        )
        .family("dispatch")
        .always_gated(),
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

fn operator(caller: &Caller, tool: &str) -> UaResult<()> {
    verified(caller, tool)?;
    if caller.profile != Profile::Operator {
        return Err(UaError::denied(
            "operator_authorization_required",
            format!("{tool} requires the authenticated operator profile"),
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

async fn require_run(ctx: &ToolCtx, run_id: &str) -> UaResult<super::Run> {
    let rid = run_id.to_string();
    ctx.hub
        .db()
        .read_async(move |c| load_run(c, &rid))
        .await?
        .ok_or_else(|| UaError::not_found(format!("unknown dispatch run: {run_id}")))
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(s.as_bytes()))
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
fn check_task_free(
    conn: &rusqlite::Connection,
    task_id: i64,
    agent: &str,
    run_id: Option<&str>,
) -> UaResult<()> {
    let task = require_task(conn, task_id)?;
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
    if let Some(live) = live_run_for_task(conn, task_id)?
        && Some(live.as_str()) != run_id
    {
        return Err(UaError::conflict(format!("already_claimed: run {live} holds task {task_id}")));
    }
    Ok(())
}

/// Point the task at the run and claim it for the agent.
fn bind_task(
    tx: &rusqlite::Connection,
    task_id: i64,
    run_id: &str,
    agent: &str,
    lease: &str,
) -> UaResult<()> {
    tx.execute(
        "UPDATE tasks SET claimed_by = ?2, claimed_at = ?3, lock_expires_at = ?4, current_run_id = ?5, \
         current_run_agent = ?2, status = CASE WHEN status = 'open' THEN 'doing' ELSE status END, updated_at = ?6 \
         WHERE id = ?1",
        params![task_id, agent, now(), lease, run_id, next_revision(None)],
    )?;
    Ok(())
}

/// Attach the approval pass the registry just consumed for this call. Exactly
/// one row must be linked; anything else fails the caller's transaction.
fn link_approval(
    tx: &rusqlite::Connection,
    tool: &str,
    requester: &str,
    payload: &str,
    run_id: &str,
) -> UaResult<()> {
    let n = tx.execute(
        "UPDATE approvals SET run_id = ?1 WHERE id = (SELECT id FROM approvals WHERE tool = ?2 \
         AND status = 'consumed' AND requested_by = ?3 AND payload = ?4 AND run_id IS NULL \
         ORDER BY consumed_at DESC, id DESC LIMIT 1)",
        params![run_id, tool, requester, payload],
    )?;
    expect_one_link(n, run_id)
}

/// Attach approval `approval_id` (just consumed) to the run.
fn link_approval_id(tx: &rusqlite::Connection, approval_id: i64, run_id: &str) -> UaResult<()> {
    let n = tx.execute(
        "UPDATE approvals SET run_id = ?1 WHERE id = ?2 AND status = 'consumed' AND run_id IS NULL",
        params![run_id, approval_id],
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
const ARG_KEYS: [&str; 5] = ["task_id", "agent", "harness", "prompt", "lease_seconds"];
const BOUND_KEYS: [&str; 9] = [
    "run_id",
    "workdir",
    "argv",
    "env_allowlist",
    "prompt_source",
    "prompt_sha256",
    "prompt_bytes",
    "prompt_text",
    "passes_token_of",
];

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
fn derive_run_id(tx: &rusqlite::Connection, task_id: i64, agent: &str) -> UaResult<String> {
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
    let prior: i64 =
        tx.query_row("SELECT COUNT(*) FROM dispatch_runs WHERE task_id = ?1", [task_id], |r| r.get(0))?;
    let h = sha256_hex(&format!("{salt}:{task_id}:{prior}:{agent}"));
    Ok(format!("run-{task_id}-{}", &h[..8]))
}

/// The default prompt: the task title and notes, and the run to report on.
fn default_prompt(task_id: i64, task: &Map<String, Value>, run_id: &str) -> String {
    let notes: String = str_field(task, "notes").unwrap_or_default().chars().take(8000).collect();
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
    requester: &str,
    payload: &Value,
) -> UaResult<Option<(i64, Vec<String>)>> {
    let ttl = jiff::SignedDuration::from_secs((cfg.approval_pass_ttl_hours.max(0.0) * 3600.0) as i64);
    let cutoff =
        ua_core::time::format_ts(jiff::Timestamp::now().checked_sub(ttl).unwrap_or(jiff::Timestamp::MIN));
    let mut stmt = tx.prepare(
        "SELECT id, payload FROM approvals WHERE tool = 'dispatch_task' AND requested_by = ?1 \
         AND status = 'approved' AND resolved_at >= ?2 ORDER BY id DESC LIMIT ?3",
    )?;
    let rows: Vec<(i64, String)> = stmt
        .query_map(params![requester, cutoff, STALE_PASS_SCAN], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for (id, text) in rows {
        let Ok(old) = serde_json::from_str::<Value>(&text) else { continue };
        if ARG_KEYS.iter().any(|k| old.get(k) != payload.get(k)) {
            continue;
        }
        let changed: Vec<String> =
            BOUND_KEYS.iter().filter(|k| old.get(**k) != payload.get(**k)).map(|k| k.to_string()).collect();
        if !changed.is_empty() {
            return Ok(Some((id, changed)));
        }
    }
    Ok(None)
}

enum Gated {
    Run { run_id: String, prompt: String, workdir: Option<PathBuf> },
    Pending { approval_id: i64, stale: Option<(i64, Vec<String>)> },
    Denied { approval_id: i64, reason: Option<String> },
}

async fn dispatch_task(ctx: ToolCtx, a: TaskArgs) -> UaResult<Value> {
    let agent = check_slug("agent", &a.agent)?;
    check_agent_or_operator(&ctx.caller, "dispatch_task", &agent)?;
    if let Err(refusal) = crate::policy::check_prod_action(ctx.hub.cfg(), &ctx.caller, "dispatch_task") {
        return Err(refusal.error);
    }
    let cfg = ctx.hub.cfg().clone();
    let harness = match a.harness.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
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
            let task = require_task(tx, tid)?;
            check_task_free(tx, tid, &ag, None)?;
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
            let run_id = derive_run_id(tx, tid, &ag)?;
            let (prompt, source) = match &a.prompt {
                Some(p) => (p.clone(), "args"),
                None => (default_prompt(tid, &task, &run_id), "task"),
            };
            if prompt.len() > PROMPT_CAP {
                return Err(UaError::invalid(format!("prompt is longer than {PROMPT_CAP} bytes")));
            }
            let prompt_sha = sha256_hex(&prompt);
            let mut payload = json!({
                "task_id": tid,
                "agent": ag,
                "harness": h2.as_ref().map(|(n, _)| n.clone()),
                "lease_seconds": lease,
                "run_id": run_id,
                "workdir": workdir.as_ref().map(|p| p.display().to_string()),
                "argv": h2.as_ref().map(|(_, h)| h.argv.clone()),
                "env_allowlist": h2.as_ref().map(|(_, h)| h.env_allowlist.clone()),
                "prompt_source": source,
                "prompt_sha256": prompt_sha,
            });
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
            if h2.as_ref().is_some_and(|(_, h)| h.pass_agent_token) {
                payload["passes_token_of"] = json!(ag);
            }
            let approval_id = match approvals::gate(tx, hub.cfg(), &caller, "dispatch_task", &payload)? {
                GateOutcome::Pass { approval_id } => approval_id,
                GateOutcome::Pending { approval_id } => {
                    let stale = stale_pass(tx, hub.cfg(), &caller.label, &payload)?;
                    return Ok(Gated::Pending { approval_id, stale });
                }
                GateOutcome::Denied { approval_id, reason } => return Ok(Gated::Denied { approval_id, reason }),
            };
            let ts = now();
            tx.execute(
                "INSERT INTO dispatch_runs (run_id, task_id, agent_label, harness, state, actor, lease_owner, \
                 lease_expires_at, attempt, fence, workdir, prompt, prompt_sha256, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, 'claimed', ?5, ?5, ?6, 1, 1, ?7, ?8, ?9, ?10, ?10)",
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
                    ts
                ],
            )?;
            bind_task(tx, tid, &run_id, &ag, &lease_at)?;
            link_approval_id(tx, approval_id, &run_id)?;
            record_transition(tx, &run_id, "claimed", &caller.label, json!({ "approval_id": approval_id }))?;
            Ok(Gated::Run { run_id, prompt, workdir })
        })
        .await?;
    let (run_id, prompt, workdir) = match gated {
        Gated::Run { run_id, prompt, workdir } => (run_id, prompt, workdir),
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
        None => executor::launch_stub(&ctx.hub, run_id.clone(), ctx.caller.label.clone()).await?,
        Some((harness_name, h)) => {
            let spec = LaunchSpec {
                run_id: run_id.clone(),
                task_id: tid,
                agent: agent.clone(),
                fence: 1,
                harness_name,
                harness: h,
                workdir: workdir.unwrap_or_default(),
                prompt,
                actor: ctx.caller.label.clone(),
            };
            executor::launch(&ctx.hub, spec).await?
        }
    };
    if let Some(o) = out.as_object_mut() {
        o.insert("task_id".into(), json!(tid));
        o.insert("agent_label".into(), json!(agent));
        o.entry("fence").or_insert(json!(1));
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
    let (rid2, id2, ev2) = (rid.clone(), identity.clone(), evidence.clone());
    let outcome = ctx
        .hub
        .db()
        .write_async(move |tx| {
            record_outcome(
                tx,
                Outcome {
                    run_id: &rid2,
                    fence: a.fence,
                    state,
                    actor: &id2,
                    source: "self_report",
                    evidence: ev2,
                    failure_reason: reason,
                    failure_class: None,
                    usage: a.usage,
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
    check_agent_or_operator(&ctx.caller, "dispatch_cancel", &run.agent_label)?;
    let reason =
        a.reason.map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).unwrap_or("client cancelled".into());
    let actor = ctx.caller.label.clone();

    // 1. Record the intent (state unchanged) as a compare-and-swap.
    let (rid2, actor2, reason2) = (rid.clone(), actor.clone(), reason.clone());
    let intent = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let Some(run) = load_run(tx, &rid2)? else {
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
    let fresh = require_run(&ctx, &rid).await?;
    let termination = blocking(move || Ok(executor::terminate(&fresh))).await?;
    let cessation = classify_termination(termination);

    // 3. Commit the outcome.
    let by = actor.clone();
    let mut out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            finalize_cancellation(tx, &rid, &actor, "cancel", &reason, termination, cessation)
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
    operator(&ctx.caller, "dispatch_retry_cancellation")?;
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
    let actor = ctx.caller.label.clone();
    let res = ctx
        .hub
        .db()
        .write_async(move |tx| {
            finalize_cancellation(tx, &rid, &actor, "operator", "retry_cancellation", termination, cessation)
        })
        .await?;
    if res["ok"] != json!(true) {
        return Err(UaError::conflict(format!("dispatch cancellation retry failed: {}", res["reason"])));
    }
    Ok(res)
}

async fn confirm_cancellation(ctx: ToolCtx, a: ConfirmArgs) -> UaResult<Value> {
    operator(&ctx.caller, "dispatch_confirm_cancellation")?;
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
    let actor = ctx.caller.label.clone();
    let res = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let reason = format!("operator_override:{note}");
            finalize_cancellation(tx, &rid, &actor, "operator", &reason, "operator_confirmed", "confirmed")
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
const RESUME_BOUND_KEYS: [&str; 6] =
    ["harness", "workdir", "argv", "env_allowlist", "passes_token_of", "prompt_sha256"];

/// A resume relaunches under the hub's current config, and its own approval
/// names only the run. Refuse it (`approval_binding_changed`) unless what it
/// would run is what the run's `dispatch_task` approval bound: the same
/// harness, argv, env allowlist, token passing, resolved workdir and prompt.
fn check_resume_binding(
    tx: &rusqlite::Connection,
    run: &super::Run,
    harness: Option<&(String, ua_core::config::HarnessConfig)>,
    workdir: Option<&Path>,
) -> UaResult<()> {
    let bound: Option<String> = tx
        .query_row(
            "SELECT payload FROM approvals WHERE tool = 'dispatch_task' AND run_id = ?1 \
             AND status = 'consumed' ORDER BY id LIMIT 1",
            [&run.run_id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(bound) = bound.and_then(|t| serde_json::from_str::<Value>(&t).ok()) else {
        return Err(UaError::denied(
            "approval_binding_changed",
            format!("run {} has no dispatch_task approval to resume under", run.run_id),
        ));
    };
    let mut current = json!({
        "harness": harness.map(|(n, _)| n.clone()),
        "workdir": workdir.map(|p| p.display().to_string()),
        "argv": harness.map(|(_, h)| h.argv.clone()),
        "env_allowlist": harness.map(|(_, h)| h.env_allowlist.clone()),
        "prompt_sha256": sha256_hex(run.prompt.as_deref().unwrap_or_default()),
    });
    if harness.is_some_and(|(_, h)| h.pass_agent_token) {
        current["passes_token_of"] = json!(run.agent_label);
    }
    let changed: Vec<&str> =
        RESUME_BOUND_KEYS.iter().copied().filter(|k| bound.get(*k) != current.get(*k)).collect();
    if !changed.is_empty() {
        return Err(UaError::denied(
            "approval_binding_changed",
            format!(
                "run {} no longer matches its dispatch_task approval (changed: {}); dispatch the task again",
                run.run_id,
                changed.join(", ")
            ),
        ));
    }
    Ok(())
}

async fn resume(ctx: ToolCtx, a: RunArgs) -> UaResult<Value> {
    verified(&ctx.caller, "dispatch_resume")?;
    let rid = trimmed("run_id", &a.run_id)?;
    let run = require_run(&ctx, &rid).await?;
    check_run_owner(&ctx.caller, "dispatch_resume", &run)?;
    if let Some(why) = resume_refusal(&run) {
        return Err(UaError::conflict(format!("dispatch resume failed: {why}")));
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
    let payload = crate::approvals::canonical_payload(&serde_json::to_value(&a)?);
    let lease_at = after_seconds(cfg.dispatch_lease_seconds.max(1));
    let actor = ctx.caller.label.clone();
    let (rid2, actor2) = (rid.clone(), actor.clone());
    let (h2, w2) = (harness.clone(), workdir.clone());
    let fence = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let Some(run) = load_run(tx, &rid2)? else {
                return Err(UaError::not_found(format!("unknown dispatch run: {rid2}")));
            };
            if let Some(why) = resume_refusal(&run) {
                return Err(UaError::conflict(format!("dispatch resume failed: {why}")));
            }
            check_resume_binding(tx, &run, h2.as_ref(), w2.as_deref())?;
            check_task_free(tx, run.task_id, &run.agent_label, Some(&rid2))
                .map_err(|e| UaError::conflict(format!("dispatch resume failed: {e}")))?;
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
            bind_task(tx, run.task_id, &rid2, &run.agent_label, &lease_at)?;
            link_approval(tx, "dispatch_resume", &actor2, &payload, &rid2)?;
            record_transition(tx, &rid2, "resumed", &actor2, json!({ "previous_fence": run.fence }))?;
            Ok(fence)
        })
        .await?;

    let mut out = match harness {
        None => executor::launch_stub(&ctx.hub, rid.clone(), actor.clone()).await?,
        Some((harness_name, h)) => {
            let spec = LaunchSpec {
                run_id: rid.clone(),
                task_id: run.task_id,
                agent: run.agent_label.clone(),
                fence,
                harness_name,
                harness: h,
                workdir: workdir.unwrap_or_default(),
                prompt: run.prompt.clone().unwrap_or_default(),
                actor,
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

fn build_receipt(conn: &rusqlite::Connection, run_id: &str) -> UaResult<Value> {
    let Some(run) = run_object(conn, run_id)? else {
        return Err(UaError::not_found(format!("unknown dispatch run: {run_id}")));
    };
    let get = |k: &str| run.get(k).cloned().unwrap_or(Value::Null);
    let task_id = run.get("task_id").and_then(Value::as_i64).unwrap_or_default();
    let task_state: Option<String> =
        conn.query_row("SELECT status FROM tasks WHERE id = ?1", [task_id], |r| r.get(0)).optional()?;
    let transitions = transitions(conn, run_id)?;
    let approval: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, status FROM approvals WHERE run_id = ?1 ORDER BY id DESC LIMIT 1",
            [run_id],
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
    let mut receipts_stmt = conn.prepare("SELECT * FROM dispatch_receipts WHERE run_id = ?1 ORDER BY id")?;
    let receipts: Vec<Value> = receipts_stmt
        .query_map([run_id], row_object)?
        .map(|r| r.map(Value::Object))
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
    ctx.hub.db().read_async(move |c| build_receipt(c, &rid)).await
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
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT * FROM dispatch_runs WHERE (?1 IS NULL OR task_id = ?1) AND (?2 IS NULL OR state = ?2) \
                 ORDER BY created_at DESC, rowid DESC LIMIT ?3",
            )?;
            let rows: Vec<Map<String, Value>> =
                stmt.query_map(params![a.task_id, a.state, limit], row_object)?.collect::<Result<_, _>>()?;
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
