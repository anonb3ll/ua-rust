//! The `langgraph_*` tools.
//!
//! The original hub ran these graphs on LangGraph with a separate checkpoint
//! database. Here they are built-in definitions on the workflow engine: the
//! same argument names and result fields, checkpoints in the hub database,
//! and every mutating hop behind a `langgraph_governed_call` approval.
//!
//! - `langgraph_run`: research run (gated `web_search`, a synthesis, and an
//!   optional receipt on the task).
//! - `langgraph_workflow_run`: plan → build → verify → merge; build and merge
//!   each append one receipt to the task through `task_update` and each wait
//!   on an approval.
//! - `langgraph_progress_note`: one gated receipt with a caller-supplied
//!   output digest.
//! - `langgraph_checkpoints`: checkpoint metadata (no outputs).

use std::sync::LazyLock;

use regex::Regex;
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{ActorKind, Caller, UaError, UaResult};

use super::engine::{self, Definition, Report, RunRow, StepDef};
use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, tool};

pub(crate) const GATE: &str = "langgraph_governed_call";
const RESEARCH: &str = "langgraph-research";
const GOVERNED: &str = "langgraph-governed-workflow";
const PROGRESS: &str = "langgraph-progress-note";

static DIGEST_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-f]{64}$").expect("static regex"));

fn research_definition(auto_record: bool) -> Definition {
    let mut steps = vec![
        StepDef::call("search", "web_search", json!({ "query": "{{ inputs.query }}", "max_results": 3 })).gated(GATE),
        StepDef::local("synthesize", json!({ "query": "{{ inputs.query }}", "results": "{{ steps.search }}" })),
    ];
    if auto_record {
        steps.push(StepDef::call(
            "record",
            "task_update",
            json!({
                "id": "{{ inputs.task_id }}",
                "append_note": "[langgraph run {{ inputs.run_id }}] research completed; output sha256 {{ steps.synthesize | sha256 }}",
                "idempotency_key": "langgraph-{{ inputs.run_id }}-record",
            }),
        ));
    }
    Definition {
        name: RESEARCH.into(),
        description: Some("Governed research run: gated web_search, synthesis, task receipt.".into()),
        inputs: ["task_id", "query", "run_id", "claimed_by", "budget_revision", "auto_record"]
            .map(String::from)
            .to_vec(),
        steps,
    }
}

fn governed_definition() -> Definition {
    let receipt = |hop: &str, from: &str| {
        json!({
            "id": "{{ inputs.task_id }}",
            "append_note": format!(
                "[langgraph {hop}] run {{{{ inputs.run_id }}}} by {{{{ inputs.claimed_by }}}} digest {{{{ steps.{from} | sha256 }}}}"
            ),
            "idempotency_key": format!("langgraph-{{{{ inputs.run_id }}}}-{hop}"),
        })
    };
    Definition {
        name: GOVERNED.into(),
        description: Some("Governed plan, build, verify, merge chain with gated receipts.".into()),
        inputs: ["task_id", "query", "run_id", "claimed_by"].map(String::from).to_vec(),
        steps: vec![
            StepDef::local("plan", json!({ "hop": "plan", "task_id": "{{ inputs.task_id }}", "query": "{{ inputs.query }}" })),
            StepDef::call("build", "task_update", receipt("build", "plan")).gated(GATE),
            StepDef::local("verify", json!({ "hop": "verify", "build_sha256": "{{ steps.build | sha256 }}" })),
            StepDef::call("merge", "task_update", receipt("merge", "verify")).gated(GATE),
        ],
    }
}

fn progress_definition() -> Definition {
    Definition {
        name: PROGRESS.into(),
        description: Some("One gated progress receipt on the run's task.".into()),
        inputs: ["task_id", "output_digest", "run_id", "claimed_by"].map(String::from).to_vec(),
        steps: vec![
            StepDef::call(
                "note",
                "task_update",
                json!({
                    "id": "{{ inputs.task_id }}",
                    "append_note": "[langgraph progress] run {{ inputs.run_id }} output_digest {{ inputs.output_digest }}",
                    "idempotency_key": "langgraph-{{ inputs.run_id }}-progress",
                }),
            )
            .gated(GATE),
        ],
    }
}

fn budget_revision(hub: &Hub, task_id: i64) -> String {
    let c = hub.cfg();
    engine::sha256_hex(
        &json!({
            "task_id": task_id,
            "graph": RESEARCH,
            "limits": {
                "time_s": c.autonomy_max_time_s,
                "tokens": c.autonomy_max_tokens,
                "retries": c.autonomy_max_retries,
                "cost_cents": c.autonomy_max_cost_cents,
            },
        })
        .to_string(),
    )
}

fn verified(caller: &Caller) -> bool {
    matches!(caller.kind, ActorKind::Agent | ActorKind::Human)
}

struct TaskState {
    status: String,
    claimed_by: Option<String>,
    lock_expires_at: Option<String>,
}

async fn task_state(hub: &Hub, task_id: i64) -> UaResult<Option<TaskState>> {
    hub.db()
        .read_async(move |c| {
            Ok(c.query_row(
                "SELECT status, claimed_by, lock_expires_at FROM tasks WHERE id = ?1",
                [task_id],
                |r| Ok(TaskState { status: r.get(0)?, claimed_by: r.get(1)?, lock_expires_at: r.get(2)? }),
            )
            .optional()?)
        })
        .await
}

/// A new run needs a claimed task in `doing`; a verified caller must hold the claim.
async fn start_authority(hub: &Hub, caller: &Caller, task_id: i64) -> UaResult<String> {
    if task_id <= 0 {
        return Err(UaError::invalid("task_id must be a positive integer"));
    }
    let task = task_state(hub, task_id).await?.ok_or_else(|| UaError::invalid(format!("task #{task_id} not found")))?;
    if task.status != "doing" {
        return Err(UaError::invalid(format!(
            "task #{task_id} is in status '{}'; it must be 'doing' to run",
            task.status
        )));
    }
    let Some(claimed_by) = task.claimed_by else {
        return Err(UaError::invalid(format!("task #{task_id} is unclaimed; claim the task before running")));
    };
    if verified(caller) && caller.label != claimed_by {
        return Err(UaError::denied(
            "not_claimant",
            format!("task #{task_id} is claimed by {claimed_by:?}, not the caller"),
        ));
    }
    Ok(claimed_by)
}

/// Why a stored run's origin authority no longer holds, if it does not.
async fn origin_lapse(hub: &Hub, run: &RunRow) -> UaResult<Option<String>> {
    let Some(task_id) = run.task_id else { return Ok(Some("run has no task".into())) };
    let Some(task) = task_state(hub, task_id).await? else {
        return Ok(Some("origin task no longer exists".into()));
    };
    if task.status != "doing" {
        return Ok(Some(format!("origin task is {}", task.status)));
    }
    if task.claimed_by.as_deref() != run.inputs.get("claimed_by").and_then(Value::as_str) {
        return Ok(Some("origin task owner changed".into()));
    }
    let now = ua_core::time::now();
    match task.lock_expires_at {
        Some(exp) if exp.as_str() > now.as_str() => Ok(None),
        _ => Ok(Some("origin claim lease expired".into())),
    }
}

/// `(status, outcome, code)` for an engine report.
fn classify(report: &Report) -> (&'static str, &'static str, Option<String>) {
    match report.status.as_str() {
        "done" => ("completed", "run_completed", None),
        "pending-approval" => ("interrupted", "approval_interrupted", None),
        "denied" => ("denied", "run_denied", Some(report.code.clone().unwrap_or_else(|| "policy_denied".into()))),
        "conflict" => ("conflict", "run_conflict", report.code.clone()),
        "indeterminate" => ("failed", "run_failed", Some("run_error".into())),
        _ => ("failed", "run_failed", Some("gateway_failed".into())),
    }
}

fn events(report: &Report) -> Value {
    Value::Array(
        report
            .steps
            .iter()
            .map(|s| {
                json!({
                    "node": s["name"],
                    "status": s["status"],
                    "attempts": s["attempts"],
                    "output_digest": s.get("output_digest").cloned().unwrap_or(Value::Null),
                    "approval_id": s.get("approval_id").cloned().unwrap_or(Value::Null),
                })
            })
            .collect(),
    )
}

fn base_result(run_id: &str, task_id: Option<i64>, resumed: bool) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("run_id".into(), json!(run_id));
    m.insert("thread_id".into(), json!(run_id));
    m.insert("task_id".into(), json!(task_id));
    m.insert("trace_id".into(), json!(format!("trace-lg-{run_id}")));
    m.insert("resumed".into(), json!(resumed));
    m.insert("duplicate".into(), json!(false));
    m
}

fn refusal(run_id: &str, task_id: Option<i64>, outcome: &str, code: &str, reason: &str) -> Value {
    let mut m = base_result(run_id, task_id, true);
    let status = match outcome {
        "run_denied" => "denied",
        "run_conflict" => "conflict",
        _ => "failed",
    };
    m.insert("status".into(), json!(status));
    m.insert("outcome".into(), json!(outcome));
    m.insert("code".into(), json!(code));
    m.insert("reason".into(), json!(reason));
    m.insert("events".into(), json!([]));
    m.insert("output".into(), Value::Null);
    Value::Object(m)
}

fn report_result(report: &Report, task_id: Option<i64>, resumed: bool, output: Value) -> Map<String, Value> {
    let (status, outcome, code) = classify(report);
    let mut m = base_result(&report.run_id, task_id, resumed);
    m.insert("status".into(), json!(status));
    m.insert("outcome".into(), json!(outcome));
    m.insert("code".into(), json!(code));
    m.insert("reason".into(), json!(report.error));
    m.insert("duplicate".into(), json!(report.duplicate));
    m.insert("events".into(), events(report));
    m.insert("output".into(), if status == "completed" { output } else { Value::Null });
    if let Some(id) = report.approval_id {
        m.insert("interrupted_by".into(), json!({ "approval_id": id, "tool": GATE, "step": report.pending_step }));
    }
    m
}

/// Load a stored run for resume, or say why it cannot be resumed.
async fn resume_checks(
    hub: &Hub,
    caller: &Caller,
    run_id: &str,
    kind: &str,
    task_id: Option<i64>,
) -> UaResult<Result<RunRow, Value>> {
    if !engine::is_ulid(run_id) {
        return Err(UaError::invalid("run_id must be a 26-character Crockford ULID"));
    }
    let rid = run_id.to_string();
    let run = hub.db().read_async(move |c| engine::load_run(c, &rid)).await?;
    let Some(run) = run else {
        return Ok(Err(refusal(run_id, task_id, "run_failed", "checkpoint_missing", "no checkpoint exists for this run")));
    };
    if run.kind != kind {
        return Ok(Err(refusal(
            run_id,
            task_id,
            "run_failed",
            "checkpoint_incompatible",
            "the run belongs to another graph",
        )));
    }
    if let Some(t) = task_id
        && run.task_id != Some(t)
    {
        return Err(UaError::invalid("task_id does not match the run"));
    }
    if let Err(e) = super::check_resume_authority(caller, &run) {
        let code = match &e {
            UaError::Denied { reason_code, .. } => reason_code.clone(),
            _ => "not_run_owner".into(),
        };
        return Ok(Err(refusal(run_id, run.task_id, "run_denied", &code, &e.to_string())));
    }
    if run.status != "done"
        && let Some(lapse) = origin_lapse(hub, &run).await?
    {
        return Ok(Err(refusal(run_id, run.task_id, "run_denied", "stale_authority", &lapse)));
    }
    Ok(Ok(run))
}

async fn start(
    hub: &Hub,
    caller: &Caller,
    run_id: &str,
    kind: &str,
    def: &Definition,
    inputs: Map<String, Value>,
    task_id: i64,
) -> UaResult<(RunRow, Report)> {
    engine::check_inputs(def, &inputs)?;
    engine::create_run(hub, caller, run_id, kind, def, &inputs, Some(task_id)).await?;
    let rid = run_id.to_string();
    let run = hub
        .db()
        .read_async(move |c| engine::load_run(c, &rid))
        .await?
        .ok_or_else(|| UaError::internal("run vanished after insert"))?;
    let report = engine::execute(hub, caller, &run, def).await?;
    Ok((run, report))
}

// ---------------------------------------------------------------------------
// langgraph_run

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunArgs {
    /// Task in `doing` status, claimed by the caller (required to start).
    pub task_id: Option<i64>,
    /// Research query (required to start).
    pub query: Option<String>,
    /// Append a receipt (run id, output digest) to the task when the run completes.
    #[serde(default = "yes")]
    pub auto_record: bool,
    /// The paused run to continue (with `resume=true`).
    pub run_id: Option<String>,
    /// Continue `run_id` from its checkpoint instead of starting a run.
    #[serde(default)]
    pub resume: bool,
}

fn yes() -> bool {
    true
}

async fn langgraph_run(ctx: ToolCtx, a: RunArgs) -> UaResult<Value> {
    let hub = &ctx.hub;
    if a.run_id.is_some() && !a.resume {
        return Err(UaError::invalid("run_id continues a paused run: pass resume=true with it"));
    }
    let query = a.query.as_deref().map(str::trim).filter(|q| !q.is_empty()).map(String::from);
    if a.resume {
        let Some(run_id) = a.run_id.as_deref() else {
            return Err(UaError::invalid("resume=true needs the run_id of the paused run"));
        };
        let run = match resume_checks(hub, &ctx.caller, run_id, RESEARCH, a.task_id).await? {
            Ok(run) => run,
            Err(refused) => return Ok(refused),
        };
        if let Some(q) = &query
            && run.inputs.get("query").and_then(Value::as_str) != Some(q.as_str())
        {
            return Err(UaError::invalid("query does not match the run"));
        }
        let task_id = run.task_id.unwrap_or_default();
        let stored = run.inputs.get("budget_revision").and_then(Value::as_str).unwrap_or_default().to_string();
        if run.status != "done" && stored != budget_revision(hub, task_id) {
            return Ok(refusal(
                run_id,
                run.task_id,
                "run_denied",
                "stale_authority",
                "the hub's autonomy limits changed since the run started",
            ));
        }
        let auto_record = run.inputs.get("auto_record").and_then(Value::as_bool).unwrap_or(true);
        let def = research_definition(auto_record);
        if def.digest() != run.definition_digest {
            return Ok(refusal(run_id, run.task_id, "run_failed", "checkpoint_incompatible", "graph definition changed"));
        }
        let report = engine::execute(hub, &ctx.caller, &run, &def).await?;
        return Ok(research_result(&report, &run, stored, true));
    }
    let Some(task_id) = a.task_id else { return Err(UaError::invalid("task_id must be a positive integer")) };
    let Some(query) = query else { return Err(UaError::invalid("query must not be empty")) };
    let claimed_by = start_authority(hub, &ctx.caller, task_id).await?;
    let run_id = engine::new_run_id();
    let revision = budget_revision(hub, task_id);
    let def = research_definition(a.auto_record);
    let inputs = json!({
        "task_id": task_id,
        "query": query,
        "run_id": run_id,
        "claimed_by": claimed_by,
        "budget_revision": revision,
        "auto_record": a.auto_record,
    });
    let inputs = inputs.as_object().cloned().unwrap_or_default();
    let (run, report) = start(hub, &ctx.caller, &run_id, RESEARCH, &def, inputs, task_id).await?;
    Ok(research_result(&report, &run, revision, false))
}

fn research_result(report: &Report, run: &RunRow, revision: String, resumed: bool) -> Value {
    let output = report.outputs.get("synthesize").cloned().unwrap_or(Value::Null);
    let mut m = report_result(report, run.task_id, resumed, output);
    m.insert("budget_revision".into(), json!(revision));
    Value::Object(m)
}

// ---------------------------------------------------------------------------
// langgraph_workflow_run

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunArgs {
    /// Task in `doing` status, claimed by the caller.
    pub task_id: i64,
    /// What the chain is for; repeated unchanged on each continuation.
    pub query: String,
    /// The run to continue after an approval.
    pub run_id: Option<String>,
}

async fn langgraph_workflow_run(ctx: ToolCtx, a: WorkflowRunArgs) -> UaResult<Value> {
    let hub = &ctx.hub;
    let query = a.query.trim().to_string();
    if query.is_empty() {
        return Err(UaError::invalid("query must not be empty"));
    }
    let def = governed_definition();
    let (run, report, resumed) = match a.run_id.as_deref() {
        Some(run_id) => {
            let run = match resume_checks(hub, &ctx.caller, run_id, GOVERNED, Some(a.task_id)).await? {
                Ok(run) => run,
                Err(refused) => return Ok(refused),
            };
            if run.inputs.get("query").and_then(Value::as_str) != Some(query.as_str()) {
                return Err(UaError::invalid("query does not match the run"));
            }
            if def.digest() != run.definition_digest {
                return Ok(refusal(run_id, run.task_id, "run_failed", "checkpoint_incompatible", "graph definition changed"));
            }
            let report = engine::execute(hub, &ctx.caller, &run, &def).await?;
            (run, report, true)
        }
        None => {
            let claimed_by = start_authority(hub, &ctx.caller, a.task_id).await?;
            let run_id = engine::new_run_id();
            let inputs = json!({ "task_id": a.task_id, "query": query, "run_id": run_id, "claimed_by": claimed_by });
            let inputs = inputs.as_object().cloned().unwrap_or_default();
            let (run, report) = start(hub, &ctx.caller, &run_id, GOVERNED, &def, inputs, a.task_id).await?;
            (run, report, false)
        }
    };
    let receipts: Map<String, Value> = report
        .steps
        .iter()
        .filter(|s| s["status"] == "done")
        .map(|s| (s["name"].as_str().unwrap_or_default().to_string(), s["output_digest"].clone()))
        .collect();
    let mut m = report_result(&report, run.task_id, resumed, json!({ "receipts": receipts }));
    m.insert("graph".into(), json!(GOVERNED));
    m.insert("pending_hop".into(), json!(report.pending_step));
    Ok(Value::Object(m))
}

// ---------------------------------------------------------------------------
// langgraph_progress_note

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProgressArgs {
    /// Task in `doing` status, claimed by the caller.
    pub task_id: i64,
    /// Lowercase SHA-256 hex digest of the output being reported.
    pub output_digest: String,
    /// The run returned by the first call, after its approval is decided.
    pub run_id: Option<String>,
}

async fn langgraph_progress_note(ctx: ToolCtx, a: ProgressArgs) -> UaResult<Value> {
    let hub = &ctx.hub;
    if !DIGEST_RE.is_match(&a.output_digest) {
        return Err(UaError::invalid("output_digest must be a lowercase 64-character SHA-256 hex digest"));
    }
    let def = progress_definition();
    let (run, report, resumed) = match a.run_id.as_deref() {
        Some(run_id) => {
            let run = match resume_checks(hub, &ctx.caller, run_id, PROGRESS, Some(a.task_id)).await? {
                Ok(run) => run,
                Err(refused) => return Ok(refused),
            };
            if run.inputs.get("output_digest").and_then(Value::as_str) != Some(a.output_digest.as_str()) {
                return Err(UaError::invalid("output_digest does not match the run"));
            }
            let report = engine::execute(hub, &ctx.caller, &run, &def).await?;
            (run, report, true)
        }
        None => {
            let claimed_by = start_authority(hub, &ctx.caller, a.task_id).await?;
            let run_id = engine::new_run_id();
            let inputs = json!({
                "task_id": a.task_id,
                "output_digest": a.output_digest,
                "run_id": run_id,
                "claimed_by": claimed_by,
            });
            let inputs = inputs.as_object().cloned().unwrap_or_default();
            let (run, report) = start(hub, &ctx.caller, &run_id, PROGRESS, &def, inputs, a.task_id).await?;
            (run, report, false)
        }
    };
    let receipt = json!({
        "task_id": run.task_id,
        "run_id": run.run_id,
        "output_digest": a.output_digest,
        "note": format!("[langgraph progress] run {} output_digest {}", run.run_id, a.output_digest),
    });
    let mut m = report_result(&report, run.task_id, resumed, receipt);
    m.insert("graph".into(), json!(PROGRESS));
    Ok(Value::Object(m))
}

// ---------------------------------------------------------------------------
// langgraph_checkpoints

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckpointsArgs {
    /// Only this run's checkpoints.
    pub run_id: Option<String>,
    /// Maximum records, 1-200 (default 20), newest first.
    #[serde(default = "twenty")]
    pub limit: i64,
}

fn twenty() -> i64 {
    20
}

async fn langgraph_checkpoints(ctx: ToolCtx, a: CheckpointsArgs) -> UaResult<Value> {
    let limit = a.limit.clamp(1, 200);
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT cp.id, cp.run_id, r.kind, r.name, r.task_id, cp.seq, cp.step_name, cp.tool, cp.status, \
                 cp.attempts, cp.output_digest, cp.error, cp.approval_id, cp.created_at \
                 FROM workflow_checkpoints cp JOIN workflow_runs r ON r.run_id = cp.run_id \
                 WHERE (?1 IS NULL OR cp.run_id = ?1) ORDER BY cp.id DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![a.run_id, limit], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "run_id": r.get::<_, String>(1)?,
                    "graph": r.get::<_, String>(3)?,
                    "kind": r.get::<_, String>(2)?,
                    "task_id": r.get::<_, Option<i64>>(4)?,
                    "seq": r.get::<_, i64>(5)?,
                    "node": r.get::<_, String>(6)?,
                    "tool": r.get::<_, Option<String>>(7)?,
                    "status": r.get::<_, String>(8)?,
                    "attempts": r.get::<_, i64>(9)?,
                    "output_digest": r.get::<_, Option<String>>(10)?,
                    "error": r.get::<_, Option<String>>(11)?,
                    "approval_id": r.get::<_, Option<i64>>(12)?,
                    "created_at": r.get::<_, String>(13)?,
                }))
            })?;
            let records: Vec<Value> = rows.collect::<Result<_, _>>()?;
            Ok(json!({
                "checkpoint_db": "hub database (workflow_checkpoints)",
                "exists": true,
                "count": records.len(),
                "records": records,
            }))
        })
        .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "langgraph_run",
            "Run, or resume, a governed research run for a claimed task in 'doing' status. Backed by the \
             hub's durable workflow engine (no LangGraph runtime): the web_search hop waits on a \
             langgraph_governed_call approval, every node is checkpointed in the hub database, and \
             auto_record appends a receipt to the task. Continue a paused run with run_id and resume=true. \
             Returns {run_id, thread_id, task_id, trace_id, budget_revision, status, outcome, code, reason, \
             resumed, duplicate, events, output}.",
            langgraph_run,
        )
        .family("workflows"),
    );
    r.add(
        tool(
            "langgraph_workflow_run",
            "Run the governed plan→build→verify→merge chain for a claimed task in 'doing' status, on the \
             hub's durable workflow engine (no LangGraph runtime). Build and merge each append one receipt \
             through task_update and each wait on a langgraph_governed_call approval; repeat task_id and \
             query with the returned run_id after each approval. Merges nothing and dispatches nothing. \
             Returns run metadata, status, pending_hop, interrupted_by and, when completed, output.",
            langgraph_workflow_run,
        )
        .family("workflows"),
    );
    r.add(
        tool(
            "langgraph_progress_note",
            "Append one receipt (run id and a caller-supplied lowercase SHA-256 output digest) to your \
             claimed 'doing' task, behind a langgraph_governed_call approval. The first call returns \
             'interrupted' with the approval id; call again with the returned run_id after the decision. \
             Runs on the hub's durable workflow engine (no LangGraph runtime).",
            langgraph_progress_note,
        )
        .family("workflows"),
    );
    r.add(
        tool(
            "langgraph_checkpoints",
            "Checkpoint metadata of langgraph and workflow runs from the hub database (no outputs), newest \
             first, optionally for one run. Returns {checkpoint_db, exists, count, records}.",
            langgraph_checkpoints,
        )
        .family("workflows")
        .read_only(),
    );
}
