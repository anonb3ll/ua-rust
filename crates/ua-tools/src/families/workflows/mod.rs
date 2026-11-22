//! Workflows: reviewed YAML definitions run by a durable step engine.
//!
//! Tools: `workflow_list`, `workflow_run`, and the `langgraph_*` tools, which
//! keep the original hub's LangGraph contract but run on the same engine.
//!
//! Definitions are YAML files in `workflow_dir` (default `$home/workflows`),
//! one per workflow, named `<name>.yaml`. They are executable, so treat that
//! directory as code and review every change.
//!
//! ```yaml
//! name: smoke-echo            # optional; must match the file stem
//! description: Echo an input and vet the result.
//! inputs: [message]           # every input must be supplied, no others
//! steps:                      # run in order
//!   - name: echo
//!     tool: run_cmd           # from the curated step tool list
//!     args: { command: "echo {{ inputs.message }}" }
//!   - name: vet
//!     tool: run_cmd_check
//!     args: { command: "echo {{ steps.echo.stdout }}" }
//!     retries: 1              # 0-3, read-only tools only; refusals and
//!                             # approvals are never retried
//! ```
//!
//! A failed step whose tool changes state is never retried: the run stops as
//! `indeterminate`, for an operator to check its effects and resume.
//!
//! Each step calls its tool through the governed registry path with the
//! caller's own identity and profile, so a step can never do what the caller
//! could not do directly. Every step outcome is checkpointed; a run stopped by
//! a failure or an approval continues with `workflow_run(name, run_id=...,
//! resume=true)` from the first step that has not completed.
//!
//! Both tables are tenant data (`org_id`, `organization.v1.tools.workflows`,
//! `workflows.v2.org_indexes`). A run belongs to the organization of the
//! caller that started it, or for a routine's fire to the routine's; every
//! checkpoint takes its run's organization. A run of another organization
//! answers as a missing one, a caller whose organization `orgs` does not hold
//! is refused before a run is recorded, and a gated step's approval payload
//! binds the run's organization.

pub(crate) mod engine;
mod langgraph;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{Procedure, SchemaPart};

pub(crate) use engine::{Report, check_inputs, load_definition as load, registry as step_registry};

use crate::families::plans::write_identity;
use crate::registry::{Registry, ToolCtx, blocking, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "workflows.v1",
    sql: "
CREATE TABLE IF NOT EXISTS workflow_runs (
    run_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    definition TEXT NOT NULL,
    inputs TEXT NOT NULL DEFAULT '{}',
    task_id INTEGER,
    owner TEXT NOT NULL,
    owner_profile TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('running','pending-approval','done','failed','denied','indeterminate')),
    next_step INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    lease_token TEXT,
    lease_expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_task ON workflow_runs(task_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_owner ON workflow_runs(owner, created_at);

CREATE TABLE IF NOT EXISTS workflow_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES workflow_runs(run_id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    step_index INTEGER NOT NULL,
    step_name TEXT NOT NULL,
    tool TEXT,
    status TEXT NOT NULL CHECK (status IN ('done','failed','pending-approval','denied','indeterminate')),
    attempts INTEGER NOT NULL DEFAULT 0,
    output TEXT,
    output_digest TEXT,
    error TEXT,
    approval_id INTEGER,
    created_at TEXT NOT NULL,
    UNIQUE (run_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_workflow_checkpoints_run ON workflow_checkpoints(run_id, seq);
",
};

/// `organization.v1.tools.workflows`: `org_id` on `workflow_runs` and
/// `workflow_checkpoints` (existing rows backfilled to the default
/// organization) and their generated `*_org_exists` / `*_org_immutable`
/// triggers. No key rebuild: a run's key is a ULID the hub generates (never
/// client text), and a checkpoint's `UNIQUE (run_id, seq)` is led by it, so
/// two organizations can never collide. Applied after `workflows.v1` and
/// `organization.v1.store`.
pub const TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.tools.workflows", &["workflow_runs", "workflow_checkpoints"]);

/// `workflows.v2.org_indexes`: the indexes the per-organization reads use,
/// and the same-organization rule between a checkpoint and its run. Applied
/// after [`TENANT_PART`], which adds the column.
pub const ORG_SCHEMA: SchemaPart = SchemaPart {
    name: "workflows.v2.org_indexes",
    sql: "
CREATE INDEX IF NOT EXISTS idx_workflow_runs_org_created ON workflow_runs(org_id, created_at, run_id);
CREATE INDEX IF NOT EXISTS idx_workflow_checkpoints_org ON workflow_checkpoints(org_id, id);

CREATE TRIGGER IF NOT EXISTS workflow_checkpoints_same_org
BEFORE INSERT ON workflow_checkpoints
WHEN NEW.org_id IS NOT (SELECT org_id FROM workflow_runs WHERE run_id = NEW.run_id)
BEGIN SELECT RAISE(ABORT, 'a workflow checkpoint must be in its run''s organization'); END;

CREATE TRIGGER IF NOT EXISTS workflow_checkpoints_same_org_update
BEFORE UPDATE OF run_id ON workflow_checkpoints
WHEN NEW.org_id IS NOT (SELECT org_id FROM workflow_runs WHERE run_id = NEW.run_id)
BEGIN SELECT RAISE(ABORT, 'a workflow checkpoint must be in its run''s organization'); END;
",
};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunArgs {
    /// Workflow name: the definition file stem.
    pub name: String,
    /// Input values by name. Every declared input is required and undeclared
    /// ones are refused. On resume, when given, they must equal the run's.
    pub inputs: Option<Map<String, Value>>,
    /// Your agent label. It must match the authenticated caller; omitted, it
    /// is the caller.
    pub author: Option<String>,
    /// A run to continue (with `resume=true`).
    pub run_id: Option<String>,
    /// Continue `run_id` from its last completed step instead of starting.
    #[serde(default)]
    pub resume: bool,
    /// Role workflows are not supported by this hub; refused when set.
    pub instance_id: Option<String>,
    /// Role workflows are not supported by this hub; refused when set.
    pub role_bindings: Option<Value>,
    /// Role workflows are not supported by this hub; refused when set.
    pub closure: Option<Value>,
}

/// Public shape of a workflow run.
pub(crate) fn report_json(workflow: &str, report: &engine::Report, resumed: bool) -> Value {
    let mut out = json!({
        "workflow": workflow,
        "run_id": report.run_id,
        "status": report.status,
        "steps": report.steps,
        "outputs": report.outputs,
        "resumed": resumed,
        "duplicate": report.duplicate,
    });
    if let Some(e) = &report.error {
        out["error"] = json!(e);
    }
    if let Some(c) = &report.code {
        out["code"] = json!(c);
    }
    if let Some(id) = report.approval_id {
        out["approval_id"] = json!(id);
    }
    if let Some(s) = &report.pending_step {
        out["pending_step"] = json!(s);
    }
    out
}

/// Refuse a resume by anyone but the run's owner, or under another profile.
pub(crate) fn check_resume_authority(caller: &ua_core::Caller, run: &engine::RunRow) -> UaResult<()> {
    if caller.label != run.owner {
        return Err(UaError::denied(
            "not_run_owner",
            format!("run {} belongs to {:?}; only its owner may resume it", run.run_id, run.owner),
        ));
    }
    if caller.enforce_profile && caller.profile.as_str() != run.owner_profile {
        return Err(UaError::denied(
            "stale_authority",
            format!(
                "run {} was started under profile {} but the caller now has {}",
                run.run_id, run.owner_profile, caller.profile
            ),
        ));
    }
    Ok(())
}

async fn workflow_list(ctx: ToolCtx, _a: ListArgs) -> UaResult<Value> {
    let cfg = ctx.hub.cfg().clone();
    let workflows = blocking(move || Ok(engine::list_definitions(&cfg))).await?;
    Ok(json!({ "workflows": workflows, "directory": "workflow_dir" }))
}

async fn workflow_run(ctx: ToolCtx, a: RunArgs) -> UaResult<Value> {
    write_identity(&ctx.caller, a.author.as_deref())?;
    if a.instance_id.is_some() || a.role_bindings.is_some() || a.closure.is_some() {
        return Err(UaError::invalid(
            "role workflows (instance_id, role_bindings, closure) are not supported by this hub",
        ));
    }
    engine::check_name(&a.name)?;
    let cfg = ctx.hub.cfg().clone();
    let name = a.name.clone();
    let def = blocking(move || engine::load_definition(&cfg, &name)).await?;

    match (a.run_id, a.resume) {
        (Some(_), false) => Err(UaError::invalid("run_id continues a stopped run: pass resume=true with it")),
        (None, true) => Err(UaError::invalid("resume=true needs the run_id of the run to continue")),
        (None, false) => {
            let inputs = a.inputs.unwrap_or_default();
            engine::check_inputs(&def, &inputs)?;
            let run_id = engine::new_run_id();
            let org = ctx.caller.org_id.clone();
            engine::create_run(&ctx.hub, &ctx.caller, &org, &run_id, "workflow", &def, &inputs, None).await?;
            let rid = run_id.clone();
            let run = ctx
                .hub
                .db()
                .read_async(move |c| engine::load_run(c, &org, &rid))
                .await?
                .ok_or_else(|| UaError::internal("run vanished after insert"))?;
            let report = engine::execute(&ctx.hub, &ctx.caller, &run, &def).await?;
            Ok(report_json(&def.name, &report, false))
        }
        (Some(run_id), true) => {
            let (rid, org) = (run_id.clone(), ctx.caller.org_id.clone());
            let run = ctx
                .hub
                .db()
                .read_async(move |c| engine::load_run(c, &org, &rid))
                .await?
                .ok_or_else(|| UaError::not_found(format!("no workflow run {run_id:?}")))?;
            if run.kind != "workflow" || run.name != def.name {
                return Err(UaError::invalid(format!(
                    "run {run_id} is not a run of workflow {:?}",
                    def.name
                )));
            }
            check_resume_authority(&ctx.caller, &run)?;
            if let Some(inputs) = &a.inputs
                && *inputs != run.inputs
            {
                return Err(UaError::invalid("inputs do not match the run being resumed"));
            }
            if def.digest() != run.definition_digest {
                return Err(UaError::conflict(format!(
                    "workflow {:?} changed since run {run_id} started (checkpoint_incompatible); start a new run",
                    def.name
                )));
            }
            let report = engine::execute(&ctx.hub, &ctx.caller, &run, &def).await?;
            Ok(report_json(&def.name, &report, true))
        }
    }
}

/// Start and execute a new run of the reviewed workflow `name` as `caller`,
/// recorded in organization `org` (routines use this to run as their owner,
/// in the routine's organization).
pub(crate) async fn run_as(
    hub: &crate::hub::Hub,
    caller: &ua_core::Caller,
    org: &str,
    name: &str,
    inputs: Map<String, Value>,
) -> UaResult<Report> {
    let cfg = hub.cfg().clone();
    let n = name.to_string();
    let def = blocking(move || engine::load_definition(&cfg, &n)).await?;
    engine::check_inputs(&def, &inputs)?;
    let run_id = engine::new_run_id();
    engine::create_run(hub, caller, org, &run_id, "workflow", &def, &inputs, None).await?;
    let (rid, org) = (run_id.clone(), org.to_string());
    let run = hub
        .db()
        .read_async(move |c| engine::load_run(c, &org, &rid))
        .await?
        .ok_or_else(|| UaError::internal("run vanished after insert"))?;
    engine::execute(hub, caller, &run, &def).await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "workflow_list",
            "List the reviewed YAML workflow definitions in the hub's workflow directory: \
             {workflows: [{name, description, steps, inputs}]}. Definitions are code; change them by review.",
            workflow_list,
        )
        .family("workflows")
        .read_only(),
    );
    r.add(
        tool(
            "workflow_run",
            "Run a reviewed YAML workflow. Each step calls one curated tool through the same governed path \
             as a direct call, with your identity and profile, so the profile, policy, approval queue and \
             sandbox apply to every step. Args take {{ inputs.<name> }} and {{ steps.<step>.<field> }}. \
             A failed read-only step retries up to `retries` (max 3) then the run stops as `failed`; a failed \
             step whose tool changes state is never retried and stops the run as `indeterminate` for an \
             operator to verify and resume; a step held by the \
             approval queue stops it as `pending-approval`; a refused step stops it as `denied`. Every step \
             is checkpointed: continue a stopped run with run_id and resume=true from its first unfinished \
             step. Returns {workflow, run_id, status, steps, outputs, resumed, duplicate}.",
            workflow_run,
        )
        .handler_may_gate(crate::HandlerGate::Always)
        .family("workflows"),
    );
    langgraph::register(r);
}
