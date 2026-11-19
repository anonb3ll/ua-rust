//! The durable step engine behind `workflow_run`, the `langgraph_*` tools and
//! routines.
//!
//! A run is a row in `workflow_runs`; every step outcome is a row in
//! `workflow_checkpoints`. Steps run in order. A step either calls a tool
//! through the governed [`Registry::call`] path with the run's caller, or is a
//! local step whose output is its substituted arguments. A step may also carry
//! an approval gate that must pass before it runs.
//!
//! Resuming a run replays nothing: outputs of steps already checkpointed as
//! `done` are read back into the scope and execution continues at the first
//! step without a `done` checkpoint. One executor holds a run at a time (a
//! lease in the run row); every checkpoint write checks the lease, so an
//! executor whose lease was taken over records nothing further.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, OnceLock};

use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::{Caller, Config, UaError, UaResult};
use ua_store::{EventInput, WriteTx, ledger};

use crate::approvals::{self, GateOutcome};
use crate::hub::Hub;
use crate::registry::Registry;

/// Tools a reviewed workflow step may name. Excluded on purpose: the
/// workflow, routine, cycle and langgraph tools (no recursion), the approval
/// tools (a workflow must not resolve its own gate), destructive deletes and
/// repo-mutating git tools. A curated tool that this build does not register
/// fails the definition at load time; nothing falls back to an ungoverned call.
pub(crate) const STEP_TOOLS: &[&str] = &[
    "agent_activity",
    "audit_triage_tasks",
    "check_anomalies",
    "dash_list",
    "dash_search",
    "dash_view",
    "delegate",
    "delegate_list",
    "export_memory",
    "export_tasks",
    "fs_list",
    "fs_read",
    "fs_search",
    "fs_write",
    "memory_get",
    "memory_list",
    "memory_save",
    "memory_search",
    "metrics_snapshot",
    "notify",
    "plan_checkpoint",
    "plan_create",
    "plan_get",
    "plan_handoff",
    "plan_list",
    "plan_resume",
    "plan_step_claim",
    "plan_step_retry",
    "plan_update",
    "python_lint_and_format",
    "review_and_notify",
    "run_cmd",
    "run_cmd_check",
    "security_audit",
    "system_doctor",
    "task_add",
    "task_list",
    "task_update",
    "vault_journal",
    "vault_list",
    "vault_read",
    "vault_search",
    "vault_write",
    "web_fetch",
    "web_search",
];

pub(crate) const MAX_STEP_RETRIES: u32 = 3;
/// A step output larger than this cannot be checkpointed.
const MAX_OUTPUT_BYTES: usize = 1 << 20;
/// Seconds an executor holds a run before another may take it over.
const LEASE_SECONDS: i64 = 600;
const MAX_DEFINITION_BYTES: u64 = 256 * 1024;

static NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$").expect("static regex"));
static WHOLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*\{\{\s*([A-Za-z0-9_.-]+)\s*(?:\|\s*([a-z0-9_]+)\s*)?\}\}\s*$").expect("static regex")
});
static EMBEDDED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{\s*([A-Za-z0-9_.-]+)\s*(?:\|\s*([a-z0-9_]+)\s*)?\}\}").expect("static regex")
});

/// The registry steps call through. Built once; it is the same set of tools
/// and the same governed path every adapter uses.
pub(crate) fn registry() -> &'static Registry {
    static REG: OnceLock<Registry> = OnceLock::new();
    REG.get_or_init(crate::builtin_registry)
}

pub(crate) fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

pub(crate) fn new_run_id() -> String {
    ulid::Ulid::generate().to_string()
}

pub(crate) fn is_ulid(s: &str) -> bool {
    s.len() == 26 && s.parse::<ulid::Ulid>().is_ok()
}

// ---------------------------------------------------------------------------
// Definitions

/// One step of a definition.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct StepDef {
    pub name: String,
    /// The tool to call; `None` makes a local step whose output is its args.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub args: Value,
    pub retries: u32,
    /// Approval-queue tool name that must pass before the step runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate: Option<String>,
}

impl StepDef {
    pub(crate) fn call(name: &str, tool: &str, args: Value) -> Self {
        Self { name: name.into(), tool: Some(tool.into()), args, retries: 0, gate: None }
    }

    pub(crate) fn local(name: &str, args: Value) -> Self {
        Self { name: name.into(), tool: None, args, retries: 0, gate: None }
    }

    pub(crate) fn gated(mut self, gate: &str) -> Self {
        self.gate = Some(gate.into());
        self
    }
}

/// A workflow definition: loaded from reviewed YAML or built in.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Definition {
    pub name: String,
    pub description: Option<String>,
    pub inputs: Vec<String>,
    pub steps: Vec<StepDef>,
}

impl Definition {
    /// Content digest; a resumed run must find the same definition.
    pub(crate) fn digest(&self) -> String {
        sha256_hex(&serde_json::to_string(self).unwrap_or_default())
    }

    /// Check names, references and tools. `curated` restricts tools to
    /// [`STEP_TOOLS`]; built-in definitions skip that list but still need
    /// registered tools.
    pub(crate) fn validate(&self, curated: bool) -> UaResult<()> {
        let name = &self.name;
        if self.steps.is_empty() {
            return Err(UaError::invalid(format!("workflow {name:?} must define a non-empty `steps` list")));
        }
        let declared: BTreeSet<&str> = self.inputs.iter().map(String::as_str).collect();
        if declared.len() != self.inputs.len() {
            return Err(UaError::invalid(format!("workflow {name:?} declares an input twice")));
        }
        let mut seen = BTreeSet::new();
        for (i, step) in self.steps.iter().enumerate() {
            if !NAME_RE.is_match(&step.name) {
                return Err(UaError::invalid(format!("workflow {name:?} step {i} needs a valid `name`")));
            }
            if step.retries > MAX_STEP_RETRIES {
                return Err(UaError::invalid(format!(
                    "workflow {name:?} step {:?}: retries is at most {MAX_STEP_RETRIES}",
                    step.name
                )));
            }
            if !step.args.is_object() {
                return Err(UaError::invalid(format!(
                    "workflow {name:?} step {:?} `args` must be a mapping",
                    step.name
                )));
            }
            if let Some(tool) = &step.tool {
                if curated && !STEP_TOOLS.contains(&tool.as_str()) {
                    return Err(UaError::invalid(format!(
                        "workflow {name:?} step {:?} calls unknown or uncallable tool {tool:?}; workflow steps \
                         may only call the curated tool list",
                        step.name
                    )));
                }
                if registry().get(tool).is_none() {
                    return Err(UaError::invalid(format!(
                        "workflow {name:?} step {:?}: tool {tool:?} is not registered on this build; refusing \
                         an ungoverned fallback",
                        step.name
                    )));
                }
            }
            for path in placeholders(&step.args) {
                let mut parts = path.split('.');
                match (parts.next(), parts.next()) {
                    (Some("inputs"), Some(input)) if declared.contains(input) => {}
                    (Some("steps"), Some(prior)) if seen.contains(prior) => {}
                    _ => {
                        return Err(UaError::invalid(format!(
                            "workflow {name:?} step {:?} references {{{{ {path} }}}}: only declared inputs and \
                             earlier steps can be referenced",
                            step.name
                        )));
                    }
                }
            }
            if !seen.insert(step.name.as_str()) {
                return Err(UaError::invalid(format!(
                    "workflow {name:?} has duplicate step name {:?}",
                    step.name
                )));
            }
        }
        Ok(())
    }
}

fn placeholders(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(s) => out.extend(EMBEDDED_RE.captures_iter(s).map(|c| c[1].to_string())),
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(o) => stack.extend(o.values()),
            _ => {}
        }
    }
    out
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefinition {
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    inputs: Option<Vec<String>>,
    steps: Option<Vec<RawStep>>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStep {
    name: String,
    tool: String,
    #[serde(default)]
    args: Option<Value>,
    #[serde(default)]
    retries: Option<u32>,
}

pub(crate) fn check_name(name: &str) -> UaResult<()> {
    if NAME_RE.is_match(name) {
        Ok(())
    } else {
        Err(UaError::invalid(format!(
            "workflow name {name:?} is invalid (letters, digits, hyphen and underscore only)"
        )))
    }
}

fn definition_files(cfg: &Config) -> Vec<std::path::PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(cfg.workflow_dir())
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "yaml") && p.is_file())
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

fn parse_definition(name: &str, text: &str) -> UaResult<Definition> {
    let doc: Value = serde_saphyr::from_str(text)
        .map_err(|e| UaError::invalid(format!("workflow {name:?} is not valid YAML: {e}")))?;
    let Some(obj) = doc.as_object() else {
        return Err(UaError::invalid(format!("workflow {name:?} must be a YAML mapping")));
    };
    if obj.contains_key("roles") {
        return Err(UaError::invalid(format!(
            "workflow {name:?} is a role workflow; role workflows are not supported by this hub"
        )));
    }
    let raw: RawDefinition = serde_json::from_value(doc)
        .map_err(|e| UaError::invalid(format!("workflow {name:?} has an invalid shape: {e}")))?;
    if let Some(declared) = &raw.name
        && declared != name
    {
        return Err(UaError::invalid(format!(
            "workflow {name:?} declares name {declared:?}; the name must match the file stem"
        )));
    }
    let steps = raw.steps.unwrap_or_default();
    let def = Definition {
        name: name.to_string(),
        description: raw.description,
        inputs: raw.inputs.unwrap_or_default(),
        steps: steps
            .into_iter()
            .map(|s| StepDef {
                name: s.name,
                tool: Some(s.tool),
                args: s.args.unwrap_or_else(|| json!({})),
                retries: s.retries.unwrap_or(0),
                gate: None,
            })
            .collect(),
    };
    def.validate(true)?;
    Ok(def)
}

/// Load and validate the reviewed definition `name`.
pub(crate) fn load_definition(cfg: &Config, name: &str) -> UaResult<Definition> {
    check_name(name)?;
    let dir = cfg.workflow_dir();
    let path = dir.join(format!("{name}.yaml"));
    let meta = std::fs::metadata(&path).ok().filter(|m| m.is_file());
    let Some(meta) = meta else {
        let available: Vec<String> = definition_files(cfg)
            .iter()
            .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
            .collect();
        return Err(UaError::not_found(format!(
            "no workflow definition {name:?}; available: {}",
            if available.is_empty() { "(none)".to_string() } else { available.join(", ") }
        )));
    };
    if meta.len() > MAX_DEFINITION_BYTES {
        return Err(UaError::invalid(format!(
            "workflow {name:?} is larger than {MAX_DEFINITION_BYTES} bytes"
        )));
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| UaError::invalid(format!("cannot read workflow {name:?}: {e}")))?;
    parse_definition(name, &text)
}

/// Every definition in the directory, unparseable ones included.
pub(crate) fn list_definitions(cfg: &Config) -> Vec<Value> {
    definition_files(cfg)
        .into_iter()
        .filter_map(|path| {
            let name = path.file_stem()?.to_string_lossy().into_owned();
            if !NAME_RE.is_match(&name) {
                return None;
            }
            let entry = match load_definition(cfg, &name) {
                Ok(def) => json!({
                    "name": name,
                    "description": def.description,
                    "steps": def.steps.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
                    "inputs": def.inputs,
                }),
                Err(e) => json!({
                    "name": name,
                    "description": "(unparseable definition)",
                    "steps": Value::Null,
                    "inputs": [],
                    "error": e.to_string(),
                }),
            };
            Some(entry)
        })
        .collect()
}

/// Check supplied inputs against the declared list: all present, none extra.
pub(crate) fn check_inputs(def: &Definition, inputs: &Map<String, Value>) -> UaResult<()> {
    let missing: Vec<&str> =
        def.inputs.iter().filter(|k| !inputs.contains_key(k.as_str())).map(String::as_str).collect();
    if !missing.is_empty() {
        return Err(UaError::invalid(format!(
            "workflow {:?} missing required inputs: {}",
            def.name,
            missing.join(", ")
        )));
    }
    let unknown: Vec<&str> =
        inputs.keys().filter(|k| !def.inputs.iter().any(|d| d == *k)).map(String::as_str).collect();
    if !unknown.is_empty() {
        return Err(UaError::invalid(format!(
            "workflow {:?} got undeclared inputs: {} (declare them in the definition's `inputs` list)",
            def.name,
            unknown.join(", ")
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Substitution

fn resolve_path(scope: &Value, dotted: &str) -> UaResult<Value> {
    let mut cur = scope;
    for part in dotted.split('.') {
        cur = cur.get(part).ok_or_else(|| {
            UaError::invalid(format!(
                "cannot resolve {{{{ {dotted} }}}}: {part:?} not found; data passing is explicit, only declared \
                 inputs and earlier step results are available"
            ))
        })?;
    }
    Ok(cur.clone())
}

fn apply_filter(v: Value, filter: Option<&str>) -> UaResult<Value> {
    match filter {
        None => Ok(v),
        Some("sha256") => {
            let text = match &v {
                Value::String(s) => s.clone(),
                other => serde_json::to_string(other).unwrap_or_default(),
            };
            Ok(Value::String(sha256_hex(&text)))
        }
        Some(other) => Err(UaError::invalid(format!("unknown placeholder filter {other:?}"))),
    }
}

/// Substitute `{{ path }}` placeholders. A string that is exactly one
/// placeholder takes the referenced value with its type; placeholders inside
/// a longer string interpolate as text. `{{ path | sha256 }}` gives the
/// SHA-256 of the value's text.
pub(crate) fn substitute(v: &Value, scope: &Value) -> UaResult<Value> {
    match v {
        Value::String(s) => {
            if let Some(c) = WHOLE_RE.captures(s) {
                return apply_filter(resolve_path(scope, &c[1])?, c.get(2).map(|m| m.as_str()));
            }
            let mut out = String::with_capacity(s.len());
            let mut last = 0;
            for c in EMBEDDED_RE.captures_iter(s) {
                let m = c.get(0).expect("whole match");
                out.push_str(&s[last..m.start()]);
                let val = apply_filter(resolve_path(scope, &c[1])?, c.get(2).map(|m| m.as_str()))?;
                match val {
                    Value::String(t) => out.push_str(&t),
                    other => out.push_str(&other.to_string()),
                }
                last = m.end();
            }
            out.push_str(&s[last..]);
            Ok(Value::String(out))
        }
        Value::Array(a) => Ok(Value::Array(a.iter().map(|x| substitute(x, scope)).collect::<UaResult<_>>()?)),
        Value::Object(o) => {
            let mut m = Map::new();
            for (k, x) in o {
                m.insert(k.clone(), substitute(x, scope)?);
            }
            Ok(Value::Object(m))
        }
        other => Ok(other.clone()),
    }
}

// ---------------------------------------------------------------------------
// Runs

/// A stored run.
#[derive(Debug, Clone)]
pub(crate) struct RunRow {
    pub run_id: String,
    pub kind: String,
    pub name: String,
    pub definition_digest: String,
    pub inputs: Map<String, Value>,
    pub task_id: Option<i64>,
    pub owner: String,
    pub owner_profile: String,
    pub status: String,
}

pub(crate) fn load_run(conn: &Connection, run_id: &str) -> UaResult<Option<RunRow>> {
    Ok(conn
        .query_row(
            "SELECT run_id, kind, name, definition_digest, inputs, task_id, owner, owner_profile, status \
             FROM workflow_runs WHERE run_id = ?1",
            [run_id],
            |r| {
                let inputs: String = r.get(4)?;
                Ok(RunRow {
                    run_id: r.get(0)?,
                    kind: r.get(1)?,
                    name: r.get(2)?,
                    definition_digest: r.get(3)?,
                    inputs: serde_json::from_str(&inputs).unwrap_or_default(),
                    task_id: r.get(5)?,
                    owner: r.get(6)?,
                    owner_profile: r.get(7)?,
                    status: r.get(8)?,
                })
            },
        )
        .optional()?)
}

/// Store a new run. Nothing executes until [`execute`].
pub(crate) async fn create_run(
    hub: &Hub,
    caller: &Caller,
    run_id: &str,
    kind: &str,
    def: &Definition,
    inputs: &Map<String, Value>,
    task_id: Option<i64>,
) -> UaResult<()> {
    let (caller, run_id, kind) = (caller.clone(), run_id.to_string(), kind.to_string());
    let (name, digest) = (def.name.clone(), def.digest());
    let definition = serde_json::to_string(def)?;
    let inputs_text = serde_json::to_string(inputs)?;
    hub.db()
        .write_async(move |tx| {
            let now = ua_core::time::now();
            tx.execute(
                "INSERT INTO workflow_runs (run_id, kind, name, definition_digest, definition, inputs, task_id, \
                 owner, owner_profile, status, next_step, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'running', 0, ?10, ?10)",
                params![
                    run_id,
                    kind,
                    name,
                    digest,
                    definition,
                    inputs_text,
                    task_id,
                    caller.label,
                    caller.profile.as_str(),
                    now
                ],
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "agent.workflow.started",
                    json!({
                        "run_id": run_id,
                        "kind": kind,
                        "workflow": name,
                        "task_id": task_id,
                        "definition_digest": digest,
                        "inputs_sha256": sha256_hex(&inputs_text),
                    }),
                )
                .by(caller.label.clone()),
            )?;
            Ok(())
        })
        .await
}

/// What happened to one run of [`execute`].
#[derive(Debug, Clone, Default)]
pub(crate) struct Report {
    pub run_id: String,
    /// `done`, `failed`, `pending-approval`, `denied`, `indeterminate` or `conflict`.
    pub status: String,
    /// Refusal code: `resume_in_flight`, `lease_lost`, `approval_denied`, ...
    pub code: Option<String>,
    pub error: Option<String>,
    /// One entry per step that has a checkpoint, in definition order.
    pub steps: Vec<Value>,
    /// Outputs of `done` steps by step name.
    pub outputs: Map<String, Value>,
    pub approval_id: Option<i64>,
    pub pending_step: Option<String>,
    /// The run had already finished; nothing was executed.
    pub duplicate: bool,
}

enum Outcome {
    Done(Value),
    Pending { approval_id: i64, error: String },
    Denied { code: String, error: String },
    Failed(String),
    Indeterminate(String),
}

impl Outcome {
    fn status(&self) -> &'static str {
        match self {
            Outcome::Done(_) => "done",
            Outcome::Pending { .. } => "pending-approval",
            Outcome::Denied { .. } => "denied",
            Outcome::Failed(_) => "failed",
            Outcome::Indeterminate(_) => "indeterminate",
        }
    }
}

struct Checkpoint {
    step_name: String,
    tool: Option<String>,
    status: String,
    attempts: i64,
    output: Option<Value>,
    output_digest: Option<String>,
    error: Option<String>,
    approval_id: Option<i64>,
}

/// The newest checkpoint of each step.
fn latest_checkpoints(conn: &Connection, run_id: &str) -> UaResult<BTreeMap<String, Checkpoint>> {
    let mut stmt = conn.prepare(
        "SELECT step_name, tool, status, attempts, output, output_digest, error, approval_id \
         FROM workflow_checkpoints WHERE run_id = ?1 ORDER BY seq",
    )?;
    let rows = stmt.query_map([run_id], |r| {
        let output: Option<String> = r.get(4)?;
        Ok(Checkpoint {
            step_name: r.get(0)?,
            tool: r.get(1)?,
            status: r.get(2)?,
            attempts: r.get(3)?,
            output: output.and_then(|o| serde_json::from_str(&o).ok()),
            output_digest: r.get(5)?,
            error: r.get(6)?,
            approval_id: r.get(7)?,
        })
    })?;
    let mut out = BTreeMap::new();
    for cp in rows {
        let cp = cp?;
        out.insert(cp.step_name.clone(), cp);
    }
    Ok(out)
}

fn step_reports(
    conn: &Connection,
    run_id: &str,
    def: &Definition,
) -> UaResult<(Vec<Value>, Map<String, Value>)> {
    let latest = latest_checkpoints(conn, run_id)?;
    let mut steps = Vec::new();
    let mut outputs = Map::new();
    for step in &def.steps {
        let Some(cp) = latest.get(&step.name) else { continue };
        let mut entry = json!({
            "name": cp.step_name,
            "tool": cp.tool,
            "status": cp.status,
            "attempts": cp.attempts,
            "error": cp.error,
        });
        if let Some(id) = cp.approval_id {
            entry["approval_id"] = json!(id);
        }
        if cp.status == "done" {
            let result = cp.output.clone().unwrap_or(Value::Null);
            entry["result"] = result.clone();
            entry["output_digest"] = json!(cp.output_digest);
            outputs.insert(cp.step_name.clone(), result);
        }
        steps.push(entry);
    }
    Ok((steps, outputs))
}

fn lease_deadline() -> String {
    let ts = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(LEASE_SECONDS))
        .unwrap_or_else(|_| jiff::Timestamp::now());
    ua_core::time::format_ts(ts)
}

enum Acquire {
    Held,
    Finished,
    Busy,
}

/// Execute (or continue) a run as `caller` until it finishes, fails, is
/// denied or waits on an approval.
pub(crate) async fn execute(hub: &Hub, caller: &Caller, run: &RunRow, def: &Definition) -> UaResult<Report> {
    let token = new_run_id();
    let (rid, tok) = (run.run_id.clone(), token.clone());
    let acquired = hub
        .db()
        .write_async(move |tx| {
            let (status, lease, expires): (String, Option<String>, Option<String>) = tx.query_row(
                "SELECT status, lease_token, lease_expires_at FROM workflow_runs WHERE run_id = ?1",
                [&rid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            if status == "done" {
                return Ok(Acquire::Finished);
            }
            let now = ua_core::time::now();
            let live = lease.is_some() && expires.as_deref().is_some_and(|e| e > now.as_str());
            if live {
                return Ok(Acquire::Busy);
            }
            tx.execute(
                "UPDATE workflow_runs SET lease_token = ?2, lease_expires_at = ?3, status = 'running', \
                 error = NULL, updated_at = ?4 WHERE run_id = ?1",
                params![rid, tok, lease_deadline(), now],
            )?;
            Ok(Acquire::Held)
        })
        .await?;
    match acquired {
        Acquire::Held => {}
        Acquire::Finished => return finished_report(hub, run, def, "done", None, true).await,
        Acquire::Busy => {
            let mut report = finished_report(hub, run, def, "conflict", None, false).await?;
            report.code = Some("resume_in_flight".into());
            report.error = Some("another executor holds this run; try again shortly".into());
            return Ok(report);
        }
    }
    match run_steps(hub, caller, run, def, &token).await {
        Ok(report) => Ok(report),
        Err(e) => {
            // Best effort: release the lease so a retry is not blocked for the
            // lease period by an internal error.
            let (rid, tok, msg) = (run.run_id.clone(), token.clone(), e.to_string());
            let _ = hub
                .db()
                .write_async(move |tx| {
                    tx.execute(
                        "UPDATE workflow_runs SET status = 'failed', error = ?3, lease_token = NULL, \
                         lease_expires_at = NULL, updated_at = ?4 WHERE run_id = ?1 AND lease_token = ?2",
                        params![rid, tok, msg, ua_core::time::now()],
                    )?;
                    Ok(())
                })
                .await;
            Err(e)
        }
    }
}

async fn finished_report(
    hub: &Hub,
    run: &RunRow,
    def: &Definition,
    status: &str,
    error: Option<String>,
    duplicate: bool,
) -> UaResult<Report> {
    let (rid, d) = (run.run_id.clone(), def.clone());
    let (steps, outputs) = hub.db().read_async(move |c| step_reports(c, &rid, &d)).await?;
    Ok(Report {
        run_id: run.run_id.clone(),
        status: status.into(),
        error,
        steps,
        outputs,
        duplicate,
        ..Report::default()
    })
}

fn classify(err: &UaError) -> Option<Outcome> {
    match err {
        UaError::ApprovalRequired { approval_id, .. } => {
            Some(Outcome::Pending { approval_id: *approval_id, error: err.to_string() })
        }
        UaError::Denied { reason_code, .. } => {
            Some(Outcome::Denied { code: reason_code.clone(), error: err.to_string() })
        }
        UaError::Unauthenticated(_) => {
            Some(Outcome::Denied { code: "unauthenticated".into(), error: err.to_string() })
        }
        _ => None,
    }
}

async fn run_one(hub: &Hub, caller: &Caller, run_id: &str, step: &StepDef, scope: &Value) -> (Outcome, i64) {
    let args = match substitute(&step.args, scope) {
        Ok(a) => a,
        Err(e) => return (Outcome::Failed(e.to_string()), 0),
    };
    if let Some(gate) = &step.gate {
        let payload = json!({
            "run_id": run_id,
            "step": step.name,
            "tool": step.tool,
            "args_sha256": sha256_hex(&approvals::canonical_payload(&args)),
        });
        let (h, c, g) = (hub.clone(), caller.clone(), gate.clone());
        let gated = hub.db().write_async(move |tx| approvals::gate(tx, h.cfg(), &c, &g, &payload)).await;
        match gated {
            Ok(GateOutcome::Pass { .. }) => {}
            Ok(GateOutcome::Pending { approval_id }) => {
                return (
                    Outcome::Pending {
                        approval_id,
                        error: format!("waiting on approval {approval_id} for {gate}"),
                    },
                    0,
                );
            }
            Ok(GateOutcome::Denied { approval_id, reason }) => {
                return (
                    Outcome::Denied {
                        code: "approval_denied".into(),
                        error: format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                    },
                    0,
                );
            }
            Err(e) => return (Outcome::Failed(e.to_string()), 0),
        }
    }
    let Some(tool) = &step.tool else { return (Outcome::Done(args), 1) };
    let mut attempts = 0;
    let mut last_error = String::new();
    while attempts <= i64::from(step.retries) {
        attempts += 1;
        match registry().call(hub, caller, tool, args.clone()).await {
            Ok(v) => {
                let size = serde_json::to_string(&v).map(|s| s.len()).unwrap_or(usize::MAX);
                if size > MAX_OUTPUT_BYTES {
                    return (
                        Outcome::Indeterminate(format!(
                            "{tool} ran but its output ({size} bytes) exceeds the {MAX_OUTPUT_BYTES}-byte \
                             checkpoint limit; verify its effects before resuming"
                        )),
                        attempts,
                    );
                }
                return (Outcome::Done(v), attempts);
            }
            Err(e) => {
                if let Some(outcome) = classify(&e) {
                    return (outcome, attempts);
                }
                last_error = e.to_string();
            }
        }
    }
    (Outcome::Failed(last_error), attempts)
}

/// Record one step outcome. Returns false when the lease was lost.
async fn checkpoint(
    hub: &Hub,
    caller: &Caller,
    run: &RunRow,
    token: &str,
    idx: usize,
    step: &StepDef,
    result: &(Outcome, i64),
) -> UaResult<bool> {
    let (outcome, attempts) = (&result.0, result.1);
    let (output, digest) = match outcome {
        Outcome::Done(v) => {
            let text = serde_json::to_string(v)?;
            let digest = sha256_hex(&text);
            (Some(text), Some(digest))
        }
        _ => (None, None),
    };
    let (error, approval_id) = match outcome {
        Outcome::Done(_) => (None, None),
        Outcome::Pending { approval_id, error } => (Some(error.clone()), Some(*approval_id)),
        Outcome::Denied { error, .. } | Outcome::Failed(error) | Outcome::Indeterminate(error) => {
            (Some(error.clone()), None)
        }
    };
    let status = outcome.status();
    let next_step = if status == "done" { idx + 1 } else { idx } as i64;
    let (rid, tok, label) = (run.run_id.clone(), token.to_string(), caller.label.clone());
    let (name, tool) = (step.name.clone(), step.tool.clone());
    hub.db()
        .write_async(move |tx: &mut WriteTx<'_>| {
            let now = ua_core::time::now();
            let n = tx.execute(
                "UPDATE workflow_runs SET updated_at = ?3, lease_expires_at = ?4, next_step = ?5 \
                 WHERE run_id = ?1 AND lease_token = ?2",
                params![rid, tok, now, lease_deadline(), next_step],
            )?;
            if n == 0 {
                return Ok(false);
            }
            let seq: i64 = tx.query_row(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM workflow_checkpoints WHERE run_id = ?1",
                [&rid],
                |r| r.get(0),
            )?;
            tx.execute(
                "INSERT INTO workflow_checkpoints (run_id, seq, step_index, step_name, tool, status, attempts, \
                 output, output_digest, error, approval_id, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    rid,
                    seq,
                    idx as i64,
                    name,
                    tool,
                    status,
                    attempts,
                    output,
                    digest,
                    error,
                    approval_id,
                    now
                ],
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    "agent.workflow.step",
                    json!({
                        "run_id": rid,
                        "step": name,
                        "tool": tool,
                        "status": status,
                        "attempts": attempts,
                        "output_digest": digest,
                        "approval_id": approval_id,
                    }),
                )
                .by(label),
            )?;
            Ok(true)
        })
        .await
}

async fn run_steps(
    hub: &Hub,
    caller: &Caller,
    run: &RunRow,
    def: &Definition,
    token: &str,
) -> UaResult<Report> {
    let (rid, d) = (run.run_id.clone(), def.clone());
    let (_, done_outputs) = hub.db().read_async(move |c| step_reports(c, &rid, &d)).await?;
    let mut steps_scope = Map::new();
    for (name, out) in &done_outputs {
        steps_scope.insert(name.clone(), as_scope_value(out));
    }
    let mut scope =
        json!({ "inputs": Value::Object(run.inputs.clone()), "steps": Value::Object(steps_scope) });

    let mut final_status = "done";
    let mut code = None;
    let mut error = None;
    let mut approval_id = None;
    let mut pending_step = None;
    for (idx, step) in def.steps.iter().enumerate() {
        if done_outputs.contains_key(&step.name) {
            continue;
        }
        let result = run_one(hub, caller, &run.run_id, step, &scope).await;
        if !checkpoint(hub, caller, run, token, idx, step, &result).await? {
            let mut report = finished_report(hub, run, def, "conflict", None, false).await?;
            report.code = Some("lease_lost".into());
            report.error = Some("this executor's lease expired and another took the run over".into());
            return Ok(report);
        }
        match result.0 {
            Outcome::Done(v) => {
                scope["steps"][&step.name] = as_scope_value(&v);
            }
            Outcome::Pending { approval_id: id, error: e } => {
                final_status = "pending-approval";
                approval_id = Some(id);
                pending_step = Some(step.name.clone());
                error = Some(e);
                break;
            }
            Outcome::Denied { code: c, error: e } => {
                final_status = "denied";
                code = Some(c);
                error = Some(e);
                break;
            }
            Outcome::Failed(e) => {
                final_status = "failed";
                error = Some(e);
                break;
            }
            Outcome::Indeterminate(e) => {
                final_status = "indeterminate";
                error = Some(e);
                break;
            }
        }
    }

    let (rid, tok, label, st, err) =
        (run.run_id.clone(), token.to_string(), caller.label.clone(), final_status, error.clone());
    let released = hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now();
            let n = tx.execute(
                "UPDATE workflow_runs SET status = ?3, error = ?4, lease_token = NULL, lease_expires_at = NULL, \
                 updated_at = ?5, completed_at = CASE WHEN ?3 = 'done' THEN ?5 ELSE completed_at END \
                 WHERE run_id = ?1 AND lease_token = ?2",
                params![rid, tok, st, err, now],
            )?;
            if n == 0 {
                return Ok(false);
            }
            ledger::append(
                tx,
                EventInput::new("agent.workflow.finished", json!({ "run_id": rid, "status": st })).by(label),
            )?;
            Ok(true)
        })
        .await?;
    if !released {
        let mut report = finished_report(hub, run, def, "conflict", None, false).await?;
        report.code = Some("lease_lost".into());
        return Ok(report);
    }
    let mut report = finished_report(hub, run, def, final_status, error, false).await?;
    report.code = code;
    report.approval_id = approval_id;
    report.pending_step = pending_step;
    Ok(report)
}

fn as_scope_value(v: &Value) -> Value {
    if v.is_object() { v.clone() } else { json!({ "value": v }) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_keeps_types_and_interpolates() {
        let scope = json!({ "inputs": { "n": 3, "s": "hi" }, "steps": { "a": { "out": [1, 2] } } });
        let v =
            substitute(&json!({ "x": "{{ inputs.n }}", "y": "say {{ inputs.s }} {{steps.a.out}}" }), &scope)
                .unwrap();
        assert_eq!(v, json!({ "x": 3, "y": "say hi [1,2]" }));
        let d = substitute(&json!("{{ inputs.s | sha256 }}"), &scope).unwrap();
        assert_eq!(d, json!(sha256_hex("hi")));
        assert!(substitute(&json!("{{ inputs.missing }}"), &scope).is_err());
    }

    #[test]
    fn yaml_definitions_validate() {
        let ok = "name: demo\ninputs: [msg]\nsteps:\n  - name: a\n    tool: run_cmd_check\n    args:\n      command: \"echo {{ inputs.msg }}\"\n";
        let def = parse_definition("demo", ok).unwrap();
        assert_eq!(def.steps.len(), 1);
        let bad_ref =
            "steps:\n  - name: a\n    tool: run_cmd_check\n    args: { command: \"{{ steps.b.x }}\" }\n";
        assert!(parse_definition("x", bad_ref).is_err());
        let recursion = "steps:\n  - name: a\n    tool: workflow_run\n    args: {}\n";
        assert!(parse_definition("x", recursion).is_err());
        let roles = "roles: {}\nsteps: []\n";
        assert!(parse_definition("x", roles).unwrap_err().to_string().contains("role workflow"));
        let mismatch = "name: other\nsteps:\n  - name: a\n    tool: task_list\n";
        assert!(parse_definition("x", mismatch).is_err());
    }
}
