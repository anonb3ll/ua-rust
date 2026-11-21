//! Per-task workflow record: stage, resume capsule and graded checks.
//!
//! A task's notes say what happened, in prose. Two questions they answer
//! badly come right after a compaction or a handoff: *which stage is this
//! task in, and what was I in the middle of?* and *which of the checks I am
//! about to rely on did anyone other than an agent confirm?*
//!
//! **Stage and capsule.** One `task_workflow` row per task: `stage` (one of
//! [`STAGES`]), `goal`, `done` (a short list), `focus`, the `head_sha` the
//! capsule describes and the `expected_checks`. Every write bumps `revision`;
//! `expected_revision` refuses a write over one the caller did not see.
//! `session_packet` carries the record as `workflow`.
//!
//! **Checks and grades.** A check is one named result (`tests`, `lint`,
//! `ci`...) at one head, graded:
//!
//! - `attested`: an agent said so. Every recorded check starts here, and a
//!   re-record at the same head goes back here.
//! - `verified`: the hub looked the check's CI run up itself
//!   ([`CiVerifier`](crate::ci::CiVerifier)) and it agrees: same head,
//!   finished, the stated outcome. A reference naming a `job` is graded on
//!   that job; without one only the whole run is (`verified_scope: "run"`,
//!   `summary.verified_run_only`).
//! - `unknown`: nothing recorded at the head that matters (no row, or only a
//!   row at an older head, shown as `stale_head`).
//!
//! A reference that contradicts the claim leaves the grade `attested` and is
//! listed in `summary.contradicted`. Report mode: nothing here gates a claim
//! or a merge.
//!
//! **What may be verified.** A caller cannot pick what the hub looks up:
//!
//! - The repository is the task's project's bound repository
//!   (`project_repo_bind`). A `ref.repo` naming another is refused
//!   (`repo_mismatch`); an omitted one is filled in from the binding. A
//!   project with no binding keeps the reference, but the check cannot be
//!   graded `verified` (the verdict says why).
//! - A check with a reference needs the full 40-character `head_sha`: an
//!   abbreviated SHA is ambiguous, so it is never graded `verified`.
//! - `expected_checks` may bind a check name to one CI job
//!   (`{name: "tests", job: "unit"}`, stored in `expected_jobs_json`). A
//!   reference for that check naming another job is refused
//!   (`job_mismatch`); one naming no job is graded on the expected job, so a
//!   run-scope `tests` can never be verified by some other job. A binding set
//!   after a check was recorded is applied again when it is verified.
//!
//! Writers are the task's claimant, its `next_owner`, a lifecycle operator or
//! a human. Anyone who can call the action may read and re-verify.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::types::Value as Sql;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};

use super::{bounded, now_micros, same_label};
use crate::ci::{CiRun, Verdict};
use crate::families::governance;
use crate::families::tasks::{acting_identity, emit, require_task, str_field};
use crate::registry::ToolCtx;

pub(crate) const STAGES: [&str; 8] =
    ["plan", "implement", "verify", "review", "merge", "deploy", "prove", "done"];
const ATTESTED: &str = "attested";
const VERIFIED: &str = "verified";
const UNKNOWN: &str = "unknown";
const GRADES: [&str; 3] = [ATTESTED, VERIFIED, UNKNOWN];
const OUTCOMES: [&str; 2] = ["pass", "fail"];
const REF_KINDS: [&str; 1] = ["ci_run"];
const CHANNEL: &str = "agent.task.workflow";

const GOAL_MAX: usize = 500;
const FOCUS_MAX: usize = 500;
const DONE_MAX_ITEMS: usize = 20;
const DONE_ITEM_MAX: usize = 300;
const DETAIL_MAX: usize = 500;
const EXPECTED_MAX: usize = 12;
const CHECKS_PER_TASK: i64 = 200;
const JOB_MAX: usize = 120;
const SCOPE_JOB: &str = "job";
const SCOPE_RUN: &str = "run";

// --- arguments ----------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGetArgs {
    /// The task.
    pub task_id: i64,
    /// Grade checks at this head (7-40 hex). Default: the head the capsule names.
    pub head_sha: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSetArgs {
    /// The task.
    pub task_id: i64,
    /// plan, implement, verify, review, merge, deploy, prove or done.
    pub stage: Option<String>,
    /// What the task is for, at most 500 characters. Empty clears it.
    pub goal: Option<String>,
    /// What is finished: up to 20 items of at most 300 characters. Replaces the list.
    pub done: Option<Vec<String>>,
    /// What you are in the middle of, at most 500 characters. Empty clears it.
    pub focus: Option<String>,
    /// The commit (7-40 hex) the capsule describes; checks are graded here by default.
    pub head_sha: Option<String>,
    /// Checks expected before the task is done (up to 12); a missing one reads
    /// `unknown`. Each is a name, or `{name, job}` binding the check to that CI
    /// job: its reference must name that job (or none, and is graded on it).
    pub expected_checks: Option<Vec<ExpectedCheck>>,
    /// Guard: refuse unless the record is still at this revision (0 when none exists).
    pub expected_revision: Option<i64>,
    /// Acting identity for an unverified caller; a verified caller acts as itself.
    pub actor: Option<String>,
}

/// An expected check: a bare name, or a name bound to one CI job.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ExpectedCheck {
    Name(String),
    Job(ExpectedCheckJob),
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedCheckJob {
    /// The check name.
    pub name: String,
    /// The CI job that alone may verify it.
    pub job: Option<String>,
}

/// A CI run id: digits, as text or a number.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RunId {
    Text(String),
    Number(u64),
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckRef {
    /// `ci_run`.
    pub kind: String,
    /// The CI run id (digits; a leading `#` is dropped).
    #[serde(rename = "ref")]
    pub reference: RunId,
    /// `owner/name`. Must be the task's project's bound repository; omitted,
    /// the binding is used. Without a binding the check cannot be verified.
    pub repo: Option<String>,
    /// The CI job the check stands for. With it the grade is that job's;
    /// without it a verified grade covers the whole run only.
    pub job: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckRecordArgs {
    /// The task.
    pub task_id: i64,
    /// Check name: 1-64 of a-z, 0-9, `_`, `.`, `:` or `-` (lowercased).
    pub name: String,
    /// `pass` or `fail`.
    pub outcome: String,
    /// The commit the result is for: 7-40 hex, and the full 40 with a `ref`.
    pub head_sha: String,
    /// What the hub can look up to verify the claim: `{kind: "ci_run", ref, repo, job?}`.
    #[serde(rename = "ref")]
    pub reference: Option<CheckRef>,
    /// A short note, at most 500 characters.
    pub detail: Option<String>,
    /// Try to verify a resolvable reference at once (default true).
    pub verify: Option<bool>,
    /// Acting identity for an unverified caller; a verified caller acts as itself.
    pub actor: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckVerifyArgs {
    /// The task.
    pub task_id: i64,
    /// The check's name.
    pub name: String,
    /// The head the check was recorded at.
    pub head_sha: String,
    /// Acting identity for an unverified caller; a verified caller acts as itself.
    pub actor: Option<String>,
}

// --- validation ---------------------------------------------------------------------

fn check_name(raw: &str) -> UaResult<String> {
    let name = raw.trim().to_ascii_lowercase();
    let ok = (1..=64).contains(&name.len())
        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | '-'));
    if ok {
        Ok(name)
    } else {
        Err(UaError::invalid("a check name is 1-64 chars of a-z, 0-9, '_', '.', ':' or '-'"))
    }
}

pub(crate) fn sha(raw: &str, field: &str) -> UaResult<String> {
    let s = raw.trim().to_ascii_lowercase();
    if (7..=40).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(s)
    } else {
        Err(UaError::invalid(format!("{field} must be a 7-40 character hex commit SHA")))
    }
}

fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn job_name(raw: &str, field: &str) -> UaResult<String> {
    let j = raw.trim();
    if j.is_empty() || j.chars().count() > JOB_MAX {
        return Err(UaError::invalid(format!("{field} must be the job's name, 1-{JOB_MAX} characters")));
    }
    Ok(j.to_string())
}

fn same_sha(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) if !a.is_empty() && !b.is_empty() => {
            let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
            a.starts_with(&b) || b.starts_with(&a)
        }
        _ => false,
    }
}

fn is_repo(s: &str) -> bool {
    let part = |p: &str| {
        (1..=100).contains(&p.len())
            && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    };
    matches!(s.split_once('/'), Some((o, n)) if part(o) && part(n))
}

struct ParsedRef {
    kind: String,
    run: String,
    repo: Option<String>,
    job: Option<String>,
}

fn parse_ref(r: Option<CheckRef>) -> UaResult<Option<ParsedRef>> {
    let Some(r) = r else { return Ok(None) };
    if !REF_KINDS.contains(&r.kind.as_str()) {
        return Err(UaError::invalid(format!("ref.kind must be one of {REF_KINDS:?}")));
    }
    let run = match r.reference {
        RunId::Text(s) => s.trim().trim_start_matches('#').to_string(),
        RunId::Number(n) => n.to_string(),
    };
    if !(1..=15).contains(&run.len()) || !run.chars().all(|c| c.is_ascii_digit()) {
        return Err(UaError::invalid("a ci_run ref is a numeric run id"));
    }
    let repo = r.repo.map(|s| s.trim().to_string());
    if let Some(repo) = &repo
        && !is_repo(repo)
    {
        return Err(UaError::invalid("ref.repo must be owner/name"));
    }
    let job = r.job.as_deref().map(|j| job_name(j, "ref.job")).transpose()?;
    Ok(Some(ParsedRef { kind: r.kind, run, repo, job }))
}

// --- authority ----------------------------------------------------------------------

/// The claimant, the next owner, or an operator may write a task's workflow
/// record. Operator authority is governance's rule, which needs a verified
/// caller: an unverified caller that names a human's label as its `actor` is
/// not an operator (it still writes a task whose claimant or next owner it
/// names, as every unverified write does).
fn require_writer(ctx: &ToolCtx, task: &Map<String, Value>, who: &str, id: i64) -> UaResult<()> {
    let allowed = governance::is_operator(ctx.hub.cfg(), &ctx.caller, who)
        || same_label(str_field(task, "claimed_by"), who)
        || same_label(str_field(task, "next_owner"), who);
    if allowed {
        Ok(())
    } else {
        Err(UaError::denied(
            "not_task_owner",
            format!(
                "{who:?} may not write task {id}'s workflow record: only its claimant, its next owner, a lifecycle \
                 operator or a human may"
            ),
        ))
    }
}

/// The repository the task's project is bound to.
fn task_repo(conn: &Connection, task: &Map<String, Value>) -> UaResult<Option<String>> {
    match str_field(task, "project") {
        Some(project) => governance::bound_repo(conn, project),
        None => Ok(None),
    }
}

/// The CI job `expected_checks` binds check `name` to, if any.
fn expected_job(conn: &Connection, task_id: i64, name: &str) -> UaResult<Option<String>> {
    let raw: Option<String> = conn
        .query_row("SELECT expected_jobs_json FROM task_workflow WHERE task_id = ?1", [task_id], |r| r.get(0))
        .optional()?;
    Ok(job_map(raw).remove(name))
}

fn job_map(raw: Option<String>) -> BTreeMap<String, String> {
    raw.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

// --- reads --------------------------------------------------------------------------

struct CheckRow {
    id: i64,
    name: String,
    head_sha: String,
    outcome: String,
    grade: String,
    ref_kind: Option<String>,
    reference: Option<String>,
    repo: Option<String>,
    ref_job: Option<String>,
    detail: Option<String>,
    verification: Option<Value>,
    recorded_by: String,
    recorded_at: String,
    verified_at: Option<String>,
}

const CHECK_COLUMNS: &str = "id, name, head_sha, outcome, grade, ref_kind, ref, repo, ref_job, detail, \
                             verification_json, recorded_by, recorded_at, verified_at";

fn check_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<CheckRow> {
    let verification: Option<String> = r.get(10)?;
    Ok(CheckRow {
        id: r.get(0)?,
        name: r.get(1)?,
        head_sha: r.get(2)?,
        outcome: r.get(3)?,
        grade: r.get(4)?,
        ref_kind: r.get(5)?,
        reference: r.get(6)?,
        repo: r.get(7)?,
        ref_job: r.get(8)?,
        detail: r.get(9)?,
        verification: verification.and_then(|v| serde_json::from_str(&v).ok()),
        recorded_by: r.get(11)?,
        recorded_at: r.get(12)?,
        verified_at: r.get(13)?,
    })
}

fn check_public(row: &CheckRow) -> Value {
    let scope = (row.grade == VERIFIED)
        .then(|| row.verification.as_ref().and_then(|v| v["observed"]["scope"].as_str().map(str::to_string)))
        .flatten();
    json!({
        "name": row.name,
        "head_sha": row.head_sha,
        "outcome": row.outcome,
        "grade": row.grade,
        "ref": row.ref_kind.as_ref().map(|k| json!({
            "kind": k, "ref": row.reference, "repo": row.repo, "job": row.ref_job,
        })),
        "detail": row.detail,
        "verification": row.verification,
        "verified_scope": scope,
        "recorded_by": row.recorded_by,
        "recorded_at": row.recorded_at,
        "verified_at": row.verified_at,
    })
}

/// One graded entry per check name, judged at `head`, plus the summary.
fn graded(mut rows: Vec<CheckRow>, head: Option<&str>, expected: &[String]) -> (Vec<Value>, Value) {
    rows.sort_by(|a, b| (a.recorded_at.as_str(), a.id).cmp(&(b.recorded_at.as_str(), b.id)));
    let mut newest: BTreeMap<String, usize> = BTreeMap::new();
    let mut at_head: BTreeMap<String, usize> = BTreeMap::new();
    for (i, row) in rows.iter().enumerate() {
        newest.insert(row.name.clone(), i);
        if head.is_some() && same_sha(Some(&row.head_sha), head) {
            at_head.insert(row.name.clone(), i);
        }
    }
    let names: BTreeSet<String> = newest.keys().cloned().chain(expected.iter().cloned()).collect();
    let mut checks = Vec::with_capacity(names.len());
    for name in &names {
        let pick = if head.is_some() { at_head.get(name) } else { newest.get(name) };
        if let Some(&i) = pick {
            checks.push(check_public(&rows[i]));
            continue;
        }
        checks.push(json!({
            "name": name,
            "head_sha": head,
            "outcome": null,
            "grade": UNKNOWN,
            "stale_head": newest.get(name).map(|&i| rows[i].head_sha.clone()),
            "expected": expected.contains(name),
        }));
    }
    let names_where = |f: &dyn Fn(&Value) -> bool| -> Vec<String> {
        checks.iter().filter(|c| f(c)).filter_map(|c| c["name"].as_str().map(str::to_string)).collect()
    };
    let mut summary = Map::new();
    for grade in GRADES {
        summary.insert(grade.into(), json!(names_where(&|c| c["grade"] == grade)));
    }
    summary.insert(
        "verified_run_only".into(),
        json!(names_where(&|c| c["grade"] == VERIFIED && c["verified_scope"] != SCOPE_JOB)),
    );
    summary.insert("failing".into(), json!(names_where(&|c| c["outcome"] == "fail")));
    summary.insert(
        "contradicted".into(),
        json!(names_where(&|c| c["grade"] == ATTESTED && c["verification"]["verdict"] == "mismatch")),
    );
    (checks, Value::Object(summary))
}

fn json_list(raw: Option<String>) -> Vec<String> {
    raw.and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok()).unwrap_or_default()
}

/// The full workflow view of a task, checks graded at `head` (default: the
/// capsule's head).
pub(crate) fn view(conn: &Connection, task_id: i64, head: Option<&str>) -> UaResult<Value> {
    type RecordRow = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let record: Option<RecordRow> = conn
        .query_row(
            "SELECT stage, goal, done_json, focus, head_sha, expected_json, revision, updated_by, updated_at, \
             expected_jobs_json FROM task_workflow WHERE task_id = ?1",
            [task_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            },
        )
        .optional()?;
    let mut out = json!({
        "task_id": task_id, "stage": null, "capsule": null, "head_sha": null, "revision": 0,
        "updated_by": null, "updated_at": null,
    });
    let mut expected = Vec::new();
    let mut jobs = BTreeMap::new();
    let mut capsule_head = None;
    if let Some((stage, goal, done, focus, head_sha, exp, revision, by, at, exp_jobs)) = record {
        expected = json_list(exp);
        jobs = job_map(exp_jobs);
        capsule_head = head_sha.clone();
        out["stage"] = json!(stage);
        out["capsule"] = json!({ "goal": goal, "done": json_list(done), "focus": focus });
        out["head_sha"] = json!(head_sha);
        out["revision"] = json!(revision);
        out["updated_by"] = json!(by);
        out["updated_at"] = json!(at);
    }
    let judged = head.map(str::to_string).or(capsule_head);
    let mut stmt = conn.prepare(&format!(
        "SELECT {CHECK_COLUMNS} FROM task_checks WHERE task_id = ?1 ORDER BY recorded_at DESC, id DESC LIMIT ?2"
    ))?;
    let rows: Vec<CheckRow> =
        stmt.query_map(params![task_id, CHECKS_PER_TASK], check_row)?.collect::<Result<_, _>>()?;
    let (checks, summary) = graded(rows, judged.as_deref(), &expected);
    out["expected_checks"] = json!(expected);
    out["expected_jobs"] = json!(jobs);
    out["judged_at_head"] = json!(judged);
    out["checks"] = json!(checks);
    out["summary"] = summary;
    out["trust"] = json!({
        "level": "untrusted",
        "source": "agent_written",
        "note": "Stage, capsule and attested checks are agent-written (T2); only a verified grade was confirmed by the hub.",
    });
    Ok(out)
}

/// The compact block `session_packet` carries as `workflow`; `None` when the
/// task has no record and no checks.
pub(crate) fn packet_section(conn: &Connection, task_id: Option<i64>) -> Option<Value> {
    let v = view(conn, task_id?, None).ok()?;
    if v["revision"] == 0 && v["checks"].as_array().is_none_or(Vec::is_empty) {
        return None;
    }
    let grades: Map<String, Value> = v["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| Some((c["name"].as_str()?.to_string(), c["grade"].clone())))
        .collect();
    Some(json!({
        "stage": v["stage"],
        "capsule": v["capsule"],
        "head_sha": v["head_sha"],
        "revision": v["revision"],
        "updated_at": v["updated_at"],
        "checks": grades,
        "failing": v["summary"]["failing"],
        "contradicted": v["summary"]["contradicted"],
    }))
}

// --- actions ------------------------------------------------------------------------

fn positive(id: i64) -> UaResult<i64> {
    if id > 0 { Ok(id) } else { Err(UaError::invalid("task_id must be a positive integer")) }
}

/// `coordination_manage(action="task_workflow_get")`.
pub(crate) async fn task_workflow_get(ctx: ToolCtx, a: WorkflowGetArgs) -> UaResult<Value> {
    let id = positive(a.task_id)?;
    let head = a.head_sha.as_deref().map(|h| sha(h, "head_sha")).transpose()?;
    ctx.hub
        .db()
        .read_async(move |c| {
            require_task(c, id)?;
            view(c, id, head.as_deref())
        })
        .await
}

/// `coordination_manage(action="task_workflow_set")`.
pub(crate) async fn task_workflow_set(ctx: ToolCtx, a: WorkflowSetArgs) -> UaResult<Value> {
    let id = positive(a.task_id)?;
    let who = acting_identity(&ctx.caller, a.actor.as_deref())?;
    let mut fields: Vec<(&'static str, Sql)> = Vec::new();
    let opt_text = |s: String| if s.is_empty() { Sql::Null } else { Sql::Text(s) };
    if let Some(stage) = a.stage {
        let stage = stage.trim().to_string();
        if !STAGES.contains(&stage.as_str()) {
            return Err(UaError::invalid(format!("stage must be one of {STAGES:?}")));
        }
        fields.push(("stage", Sql::Text(stage)));
    }
    if let Some(goal) = a.goal {
        fields.push(("goal", opt_text(bounded(&goal, "goal", GOAL_MAX)?)));
    }
    if let Some(done) = a.done {
        if done.len() > DONE_MAX_ITEMS {
            return Err(UaError::invalid(format!("done must be a list of at most {DONE_MAX_ITEMS} strings")));
        }
        let items: Vec<String> = done
            .iter()
            .map(|d| bounded(d, "done item", DONE_ITEM_MAX))
            .collect::<UaResult<Vec<_>>>()?
            .into_iter()
            .filter(|d| !d.is_empty())
            .collect();
        fields.push(("done_json", Sql::Text(json!(items).to_string())));
    }
    if let Some(focus) = a.focus {
        fields.push(("focus", opt_text(bounded(&focus, "focus", FOCUS_MAX)?)));
    }
    if let Some(head) = a.head_sha {
        fields.push(("head_sha", Sql::Text(sha(&head, "head_sha")?)));
    }
    if let Some(exp) = a.expected_checks {
        if exp.len() > EXPECTED_MAX {
            return Err(UaError::invalid(format!(
                "expected_checks must be a list of at most {EXPECTED_MAX} names"
            )));
        }
        let mut names: BTreeSet<String> = BTreeSet::new();
        let mut jobs: BTreeMap<String, String> = BTreeMap::new();
        for entry in &exp {
            let (name, job) = match entry {
                ExpectedCheck::Name(n) => (check_name(n)?, None),
                ExpectedCheck::Job(j) => (
                    check_name(&j.name)?,
                    j.job.as_deref().map(|x| job_name(x, "expected_checks job")).transpose()?,
                ),
            };
            if let Some(job) = job
                && let Some(prior) = jobs.insert(name.clone(), job.clone())
                && prior != job
            {
                return Err(UaError::invalid(format!(
                    "expected check {name:?} names two jobs: {prior:?} and {job:?}"
                )));
            }
            names.insert(name);
        }
        fields.push(("expected_json", Sql::Text(json!(names).to_string())));
        fields.push(("expected_jobs_json", Sql::Text(json!(jobs).to_string())));
    }
    if fields.is_empty() {
        return Err(UaError::invalid(
            "nothing to set: pass stage, goal, done, focus, head_sha or expected_checks",
        ));
    }
    let expected_revision = a.expected_revision;
    let ctx2 = ctx.clone();
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let task = require_task(tx, id)?;
            require_writer(&ctx2, &task, &who, id)?;
            let revision: Option<i64> = tx
                .query_row("SELECT revision FROM task_workflow WHERE task_id = ?1", [id], |r| r.get(0))
                .optional()?;
            let current = revision.unwrap_or(0);
            if let Some(exp) = expected_revision
                && exp != current
            {
                return Err(UaError::conflict(format!(
                    "task {id}'s workflow record is at revision {current}, not {exp}; read it again"
                )));
            }
            let now = now_micros();
            if revision.is_none() {
                tx.execute(
                    "INSERT INTO task_workflow (task_id, revision, updated_by, updated_at) VALUES (?1, 0, ?2, ?3)",
                    params![id, who, now],
                )?;
            }
            let names: Vec<&str> = fields.iter().map(|(c, _)| *c).collect();
            let mut values: Vec<Sql> = fields.into_iter().map(|(_, v)| v).collect();
            let assignments: Vec<String> = names.iter().enumerate().map(|(i, c)| format!("{c} = ?{}", i + 1)).collect();
            values.push(Sql::Text(who.clone()));
            values.push(Sql::Text(now));
            values.push(Sql::Integer(id));
            let n = values.len();
            tx.execute(
                &format!(
                    "UPDATE task_workflow SET {}, revision = revision + 1, updated_by = ?{}, updated_at = ?{} \
                     WHERE task_id = ?{n}",
                    assignments.join(", "),
                    n - 2,
                    n - 1
                ),
                params_from_iter(values.iter()),
            )?;
            let stage = names.contains(&"stage").then(|| {
                tx.query_row("SELECT stage FROM task_workflow WHERE task_id = ?1", [id], |r| r.get::<_, String>(0))
                    .ok()
            });
            let mut sorted = names.clone();
            sorted.sort_unstable();
            emit(
                tx,
                CHANNEL,
                json!({ "kind": "capsule", "task_id": id, "stage": stage.flatten(), "fields": sorted, "revision": current + 1 }),
                &who,
            )?;
            view(tx, id, None)
        })
        .await?;
    review_ready(&ctx.hub, id).await;
    Ok(out)
}

/// `coordination_manage(action="task_check_record")`.
pub(crate) async fn task_check_record(ctx: ToolCtx, a: CheckRecordArgs) -> UaResult<Value> {
    let id = positive(a.task_id)?;
    let who = acting_identity(&ctx.caller, a.actor.as_deref())?;
    let name = check_name(&a.name)?;
    let outcome = a.outcome.trim().to_string();
    if !OUTCOMES.contains(&outcome.as_str()) {
        return Err(UaError::invalid(format!("outcome must be one of {OUTCOMES:?}")));
    }
    let head = sha(&a.head_sha, "head_sha")?;
    let parsed = parse_ref(a.reference)?;
    if parsed.is_some() && !is_full_sha(&head) {
        return Err(UaError::invalid(
            "a check with a ref needs the full 40-character head_sha: an abbreviated SHA is never graded verified",
        ));
    }
    let detail = a.detail.as_deref().map(|d| bounded(d, "detail", DETAIL_MAX)).transpose()?;
    let verify = a.verify.unwrap_or(true);

    let (ctx2, who2, name2, head2) = (ctx.clone(), who.clone(), name.clone(), head.clone());
    let has_repo = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let task = require_task(tx, id)?;
            require_writer(&ctx2, &task, &who2, id)?;
            let (kind, run, repo, job) = match parsed {
                Some(p) => {
                    let bound = task_repo(tx, &task)?;
                    let repo = match (p.repo, bound) {
                        (Some(given), Some(bound)) if !given.eq_ignore_ascii_case(&bound) => {
                            return Err(UaError::denied(
                                "repo_mismatch",
                                format!(
                                    "ref.repo {given:?} is not task {id}'s bound repository {bound:?}; a check is \
                                     verified only against its project's repository"
                                ),
                            ));
                        }
                        (_, Some(bound)) => Some(bound),
                        (given, None) => given,
                    };
                    let job = match (p.job, expected_job(tx, id, &name2)?) {
                        (Some(given), Some(want)) if given != want => {
                            return Err(UaError::denied(
                                "job_mismatch",
                                format!(
                                    "check {name2:?} on task {id} is bound to job {want:?}; a ref naming job \
                                     {given:?} cannot stand for it"
                                ),
                            ));
                        }
                        (given, want) => given.or(want),
                    };
                    (Some(p.kind), Some(p.run), repo, job)
                }
                None => (None, None, None, None),
            };
            let has_repo = repo.is_some();
            tx.execute(
                "INSERT INTO task_checks (task_id, name, head_sha, outcome, grade, ref_kind, ref, repo, ref_job, \
                 detail, verification_json, recorded_by, recorded_at, verified_at) \
                 VALUES (?1, ?2, ?3, ?4, 'attested', ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, NULL) \
                 ON CONFLICT (task_id, name, head_sha) DO UPDATE SET outcome = excluded.outcome, \
                 grade = excluded.grade, ref_kind = excluded.ref_kind, ref = excluded.ref, repo = excluded.repo, \
                 ref_job = excluded.ref_job, detail = excluded.detail, verification_json = NULL, \
                 recorded_by = excluded.recorded_by, recorded_at = excluded.recorded_at, verified_at = NULL",
                params![id, name2, head2, outcome, kind, run, repo, job, detail, who2, now_micros()],
            )?;
            emit(
                tx,
                CHANNEL,
                json!({ "kind": "check", "task_id": id, "name": name2, "head_sha": head2, "outcome": outcome, "grade": ATTESTED }),
                &who2,
            )?;
            Ok(has_repo)
        })
        .await?;
    if verify && has_repo {
        return verify_stored(&ctx, id, &name, &head, &who).await;
    }
    ctx.hub.db().read_async(move |c| view(c, id, Some(&head))).await
}

/// `coordination_manage(action="task_check_verify")`.
pub(crate) async fn task_check_verify(ctx: ToolCtx, a: CheckVerifyArgs) -> UaResult<Value> {
    let id = positive(a.task_id)?;
    let who = acting_identity(&ctx.caller, a.actor.as_deref())?;
    let name = check_name(&a.name)?;
    let head = sha(&a.head_sha, "head_sha")?;
    verify_stored(&ctx, id, &name, &head, &who).await
}

/// Look a stored check's reference up now and store the grade it earns.
///
/// The verifier runs outside any transaction; the write is fenced on the
/// row's `recorded_at`, so a re-record meanwhile is not overwritten.
async fn verify_stored(ctx: &ToolCtx, id: i64, name: &str, head: &str, who: &str) -> UaResult<Value> {
    let (n, h) = (name.to_string(), head.to_string());
    let (row, bound, want_job) = ctx
        .hub
        .db()
        .read_async(move |c| {
            let task = require_task(c, id)?;
            let row = c
                .query_row(
                    &format!(
                        "SELECT {CHECK_COLUMNS} FROM task_checks WHERE task_id = ?1 AND name = ?2 AND head_sha = ?3"
                    ),
                    params![id, n, h],
                    check_row,
                )
                .optional()?;
            Ok((row, task_repo(c, &task)?, expected_job(c, id, &n)?))
        })
        .await?;
    let row = row.ok_or_else(|| {
        UaError::not_found(format!(
            "no check {name:?} recorded for task {id} at {}",
            &head[..head.len().min(12)]
        ))
    })?;

    let refused = |detail: String| {
        (
            ATTESTED,
            Some(json!({ "verdict": Verdict::Unverifiable.as_str(), "detail": detail, "observed": {} })),
        )
    };
    let (grade, verification) = match (&row.ref_kind, &row.reference) {
        (Some(_), _) if !is_full_sha(&row.head_sha) => refused(
            "a verified grade needs the full 40-character head SHA; this check names an abbreviated one"
                .into(),
        ),
        (Some(_), _) if bound.is_none() => refused(format!(
            "task {id}'s project has no bound repository (project_repo_bind): there is nothing to verify against"
        )),
        (Some(_), _)
            if !row
                .repo
                .as_deref()
                .is_none_or(|r| bound.as_deref().is_some_and(|b| r.eq_ignore_ascii_case(b))) =>
        {
            refused(format!(
                "the reference names repository {:?}, not the project's bound repository {:?}",
                row.repo.as_deref().unwrap_or_default(),
                bound.as_deref().unwrap_or_default()
            ))
        }
        (Some(_), _) if want_job.as_ref().is_some_and(|w| row.ref_job.as_ref().is_some_and(|j| j != w)) => {
            refused(format!(
                "check {name:?} is bound to job {:?}; the reference names job {:?}",
                want_job.as_deref().unwrap_or_default(),
                row.ref_job.as_deref().unwrap_or_default()
            ))
        }
        (Some(_), Some(run_id)) => {
            let repo = bound.clone().unwrap_or_default();
            let job = row.ref_job.clone().or_else(|| want_job.clone());
            let run = CiRun {
                repo,
                run_id: run_id.clone(),
                head_sha: row.head_sha.clone(),
                expect: if row.outcome == "pass" { "success" } else { "failure" }.into(),
                check: name.to_string(),
                job: job.clone(),
            };
            let ci = ctx.hub.ci();
            let mut outcome = ci.verify_run(&run).await;
            let mut observed = match outcome.observed.take() {
                Value::Object(m) => m,
                _ => Map::new(),
            };
            if outcome.verdict == Verdict::Verified {
                if let Some(job) = &job {
                    let job_outcome = ci.verify_job(&run, job).await;
                    if let Value::Object(seen) = job_outcome.observed {
                        observed.extend(seen);
                    }
                    observed.insert("scope".into(), json!(SCOPE_JOB));
                    outcome.verdict = job_outcome.verdict;
                    outcome.detail = job_outcome.detail;
                } else {
                    observed.insert("scope".into(), json!(SCOPE_RUN));
                    outcome.detail = format!("{}; the whole run only, no job was named", outcome.detail);
                }
            }
            let detail: String = outcome.detail.chars().take(DETAIL_MAX).collect();
            let grade = if outcome.verdict == Verdict::Verified { VERIFIED } else { ATTESTED };
            (
                grade,
                Some(json!({ "verdict": outcome.verdict.as_str(), "detail": detail, "observed": observed })),
            )
        }
        _ => (ATTESTED, None),
    };

    let (who, n, h) = (who.to_string(), name.to_string(), head.to_string());
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let verified_at = (grade == VERIFIED).then(now_micros);
            let updated = tx.execute(
                "UPDATE task_checks SET grade = ?1, verification_json = ?2, verified_at = ?3 \
                 WHERE id = ?4 AND recorded_at = ?5",
                params![
                    grade,
                    verification.as_ref().map(Value::to_string),
                    verified_at,
                    row.id,
                    row.recorded_at
                ],
            )?;
            if updated == 1 {
                emit(
                    tx,
                    CHANNEL,
                    json!({
                        "kind": "verify", "task_id": id, "name": n, "head_sha": h, "grade": grade,
                        "verdict": verification.as_ref().map(|v| v["verdict"].clone()),
                    }),
                    &who,
                )?;
            }
            view(tx, id, Some(&h))
        })
        .await?;
    if grade == VERIFIED {
        review_ready(&ctx.hub, id).await;
    }
    Ok(out)
}

// --- review-ready notification ------------------------------------------------------

/// The shortest gap between two `review_ready` notices for one task.
const REVIEW_READY_GAP_S: i64 = 600;

/// Notify when a task sits at stage `review`, expects at least one check, and
/// every expected check is `verified` at the capsule's head.
///
/// The message is a fixed template (task id, head, check names): nothing an
/// agent wrote (title, notes, detail) reaches the notification channel, so a
/// profile that denies `notify` cannot push text through it. Each head is
/// announced at most once per task (`review_ready_notices`), and a task gets
/// at most one notice per [`REVIEW_READY_GAP_S`] seconds; a head that becomes
/// ready inside the gap is ledgered as `review_ready_suppressed` and not sent.
/// Best effort: a failure is logged, never returned to the writer.
pub(crate) async fn review_ready(hub: &crate::Hub, task_id: i64) {
    let claimed = hub
        .db()
        .write_async(move |tx| {
            let row: Option<(Option<String>, Option<String>)> = tx
                .query_row("SELECT stage, head_sha FROM task_workflow WHERE task_id = ?1", [task_id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let Some((Some(stage), Some(head))) = row else { return Ok(None) };
            if stage != "review" || !is_full_sha(&head) {
                return Ok(None);
            }
            let sent: bool = tx
                .query_row(
                    "SELECT 1 FROM review_ready_notices WHERE task_id = ?1 AND head_sha = ?2",
                    params![task_id, head],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if sent {
                return Ok(None);
            }
            let v = view(tx, task_id, None)?;
            let expected: Vec<String> = json_list(Some(v["expected_checks"].to_string()));
            let checks = v["checks"].as_array().cloned().unwrap_or_default();
            let verified = |name: &str| checks.iter().any(|c| c["name"] == name && c["grade"] == VERIFIED);
            if expected.is_empty() || !expected.iter().all(|n| verified(n)) {
                return Ok(None);
            }
            let now = jiff::Timestamp::now();
            let since = ua_core::time::format_ts(
                now.checked_sub(jiff::SignedDuration::from_secs(REVIEW_READY_GAP_S)).unwrap_or(now),
            );
            let recent: bool = tx
                .query_row(
                    "SELECT 1 FROM review_ready_notices WHERE task_id = ?1 AND notified_at > ?2 LIMIT 1",
                    params![task_id, since],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if recent {
                emit(
                    tx,
                    CHANNEL,
                    json!({ "kind": "review_ready_suppressed", "task_id": task_id, "head_sha": head,
                            "reason": "rate limited: one notice per task per 10 minutes" }),
                    REVIEW_READY_AGENT,
                )?;
                return Ok(None);
            }
            tx.execute(
                "INSERT INTO review_ready_notices (task_id, head_sha, notified_at) VALUES (?1, ?2, ?3)",
                params![task_id, head, ua_core::time::format_ts(now)],
            )?;
            tx.execute(
                "UPDATE task_workflow SET review_notified_head = ?1 WHERE task_id = ?2",
                params![head, task_id],
            )?;
            emit(
                tx,
                CHANNEL,
                json!({ "kind": "review_ready", "task_id": task_id, "head_sha": head, "checks": expected }),
                REVIEW_READY_AGENT,
            )?;
            Ok(Some(review_ready_message(task_id, &head, &expected)))
        })
        .await;
    match claimed {
        Ok(Some(message)) => {
            if let Err(e) =
                crate::families::notify::send_event(hub, "review_ready", REVIEW_READY_AGENT, &message).await
            {
                tracing::warn!(task_id, error = %e, "review_ready notification failed");
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(task_id, error = %e, "review_ready check failed"),
    }
}

/// The fixed review-ready text. Check names are validated identifiers
/// (`a-z0-9_.:-`) and the head is hex, so nothing here is free text.
fn review_ready_message(task_id: i64, head: &str, checks: &[String]) -> String {
    let short: String = head.chars().take(12).collect();
    let names: Vec<&str> = checks.iter().map(String::as_str).filter(|n| check_name(n).is_ok()).collect();
    format!("Task #{task_id} is ready for review (head {short}; verified checks: {})", names.join(", "))
}

/// The identity review-ready notifications are attributed to.
const REVIEW_READY_AGENT: &str = "hub";
