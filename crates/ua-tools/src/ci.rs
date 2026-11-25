//! CI verification for task checks.
//!
//! A task check (`coordination_manage(action="task_check_record")`) is an
//! agent's claim: "tests pass at head `abc1234`". When the check names a CI
//! run (`ref: {kind: "ci_run", ref, repo, job?}`), the hub can try to confirm
//! the claim itself. That lookup goes through [`CiVerifier`], held by the
//! [`Hub`](crate::Hub), so the hub never shells out to a forge CLI and tests
//! can plug in a fake.
//!
//! The default verifier, [`GitHubCiVerifier`], looks the run up through the
//! native GitHub client in the repository the task's project is bound to, in
//! the task's organization and with that organization's own token
//! ([`crate::families::github::credentials::github_credential_for`]). When
//! that organization has no token (credential off) it answers
//! [`Verdict::Unverifiable`] and makes no request; it never uses another
//! organization's token or the hub's for a non-default organization. An unverifiable check keeps its `attested` grade; nothing is
//! lowered and nothing is refused.
//!
//! Verdicts mean:
//!
//! - [`Verdict::Verified`]: the run (or job) exists, finished, is for the
//!   claimed head, concluded as claimed and is the run the check stands for
//!   (see below).
//! - [`Verdict::Mismatch`]: the forge contradicts the claim (another head,
//!   another conclusion, a missing or skipped job). The grade stays
//!   `attested` and the contradiction is listed.
//! - [`Verdict::Insufficient`]: the forge could not settle it yet (still
//!   running, rate limited, unreadable).
//! - [`Verdict::Unverifiable`]: this hub cannot look the reference up at all.
//!
//! **Which run may verify which check.** A green run proves only what it
//! ran, so the GitHub verifier also ties the run to the check:
//!
//! - A check run counts only when the GitHub App that created it is listed
//!   in `github_ci_apps` (by slug or numeric id; default `github-actions`).
//!   Any other app's check run is `insufficient`. Workflow runs are Actions
//!   runs and always count.
//! - The run must be the check's workflow: `github_check_workflows` maps a
//!   check name to a workflow name, or to a workflow file path that pins the
//!   run to that file. Unmapped, a check bound to a job is pinned by the job
//!   name; a check with no job is verified only by a run whose name is the
//!   check's name (ASCII case-blind). Anything else is `insufficient`.
//! - For a workflow run, the workflow file at the run's head is compared with
//!   the default branch's (blob SHAs from the contents API) and recorded as
//!   `observed.workflow_unchanged`. With
//!   `github_require_default_branch_workflow` a changed or unknown file is
//!   `insufficient`, so a branch cannot rewrite the workflow that grades it.
//! - A job that ran more than once must agree on every attempt, unless
//!   `github_ci_latest_attempt_only` judges the latest attempt alone (earlier
//!   attempts stay in `observed.attempts`).

use std::future::Future;
use std::pin::Pin;

use serde_json::{Value, json};
use ua_core::Config;
use ua_store::Db;

use crate::families::github::client::{BoundRepo, GhError, GitHub, full_sha};

/// One CI run a check points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiRun {
    /// The organization of the task whose check this is. The run is looked
    /// up with this organization's token, in its bound repository.
    pub org: String,
    /// `owner/name`.
    pub repo: String,
    /// The forge's numeric run id, as text.
    pub run_id: String,
    /// The head the check claims the run is for (7-40 lowercase hex).
    pub head_sha: String,
    /// The conclusion the claim implies: `success` for a pass, `failure`
    /// for a fail.
    pub expect: String,
    /// The task check this run is claimed for (lowercase check name).
    pub check: String,
    /// The CI job the check stands for, when one is named or bound.
    pub job: Option<String>,
}

/// What the forge said about a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Verified,
    Mismatch,
    Insufficient,
    Unverifiable,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::Mismatch => "mismatch",
            Verdict::Insufficient => "insufficient",
            Verdict::Unverifiable => "unverifiable",
        }
    }
}

/// A verdict with a short reason and what was observed.
#[derive(Debug, Clone, PartialEq)]
pub struct CiOutcome {
    pub verdict: Verdict,
    /// One line for the record (at most 500 characters are stored).
    pub detail: String,
    /// What the verifier saw (run status, conclusion, head, job states).
    pub observed: Value,
}

impl CiOutcome {
    pub fn new(verdict: Verdict, detail: impl Into<String>) -> Self {
        Self { verdict, detail: detail.into(), observed: json!({}) }
    }

    pub fn observed(mut self, observed: Value) -> Self {
        self.observed = observed;
        self
    }
}

/// A boxed verification future.
pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = CiOutcome> + Send + 'a>>;

/// Looks a CI run up at its forge. Implementations must never panic or
/// return an error: a lookup that fails is [`Verdict::Insufficient`].
pub trait CiVerifier: Send + Sync {
    /// The run as a whole: it must be for `run.head_sha`, finished, and have
    /// concluded `run.expect`.
    fn verify_run<'a>(&'a self, run: &'a CiRun) -> VerifyFuture<'a>;

    /// One named job of the run (called only after [`Self::verify_run`] said
    /// verified): it must exist, have run (not skipped) and concluded
    /// `run.expect`. A job that ran more than once must agree every time.
    fn verify_job<'a>(&'a self, run: &'a CiRun, job: &'a str) -> VerifyFuture<'a>;
}

/// The GitHub verifier: looks a run up in the bound repository through the
/// native client ([`crate::families::github`]).
///
/// The run id is tried as an Actions workflow run first, then as a check
/// run. Without a token for the task's organization (`github_token_env` for
/// the default organization, `github_credential_set` for another) every
/// lookup is [`Verdict::Unverifiable`] and nothing touches the network. The
/// repository must still be bound to a project of that organization when
/// the lookup runs.
#[derive(Clone)]
pub struct GitHubCiVerifier {
    cfg: Config,
    db: Db,
}

impl GitHubCiVerifier {
    pub fn new(cfg: Config, db: Db) -> Self {
        Self { cfg, db }
    }

    async fn client(&self, run: &CiRun) -> Result<(GitHub, BoundRepo), CiOutcome> {
        let seen = json!({ "forge": "github", "repo": run.repo, "run_id": run.run_id });
        let (cfg, org, repo) = (self.cfg.clone(), run.org.clone(), run.repo.clone());
        // The task's organization's token and binding, together: never the
        // hub's token for another organization, nor another's binding.
        let found = self
            .db
            .read_async(move |c| {
                let client = GitHub::for_org(c, &cfg, &org);
                let bound = BoundRepo::check(c, &org, &repo);
                Ok((client, bound))
            })
            .await;
        let (client, bound) = match found {
            Ok(f) => f,
            Err(e) => return Err(CiOutcome::new(Verdict::Unverifiable, e.to_string()).observed(seen)),
        };
        let client = match client {
            Ok(Some(c)) => c,
            Ok(None) => {
                let why = GhError::CredentialOff(run.org == ua_core::DEFAULT_ORG).detail();
                return Err(
                    CiOutcome::new(Verdict::Unverifiable, format!("{why}; {NO_TOKEN}")).observed(seen)
                );
            }
            Err(e) => return Err(CiOutcome::new(Verdict::Unverifiable, e.detail()).observed(seen)),
        };
        match bound {
            Ok(b) => Ok((client, b)),
            Err(e) => Err(CiOutcome::new(Verdict::Unverifiable, e.to_string()).observed(seen)),
        }
    }
}

const NO_TOKEN: &str = "CI runs cannot be looked up (credential off); the check stays attested";

/// What one run lookup found.
struct RunSeen {
    kind: &'static str,
    head_sha: String,
    status: String,
    conclusion: Option<String>,
    name: String,
    /// A workflow run's workflow file (`.github/workflows/ci.yml`).
    path: Option<String>,
    /// A check run's GitHub App: slug and id.
    app_slug: Option<String>,
    app_id: Option<u64>,
}

impl RunSeen {
    fn from_workflow_run(v: &Value) -> Self {
        let path = v["path"].as_str().map(|p| p.split('@').next().unwrap_or_default().to_string());
        RunSeen {
            kind: "workflow_run",
            head_sha: text(v, "head_sha").to_ascii_lowercase(),
            status: text(v, "status"),
            conclusion: v["conclusion"].as_str().map(str::to_string),
            name: text(v, "name"),
            path: path.filter(|p| !p.is_empty()),
            app_slug: None,
            app_id: None,
        }
    }

    fn from_check_run(v: &Value) -> Self {
        RunSeen {
            kind: "check_run",
            head_sha: text(v, "head_sha").to_ascii_lowercase(),
            status: text(v, "status"),
            conclusion: v["conclusion"].as_str().map(str::to_string),
            name: text(v, "name"),
            path: None,
            app_slug: v["app"]["slug"].as_str().map(str::to_ascii_lowercase),
            app_id: v["app"]["id"].as_u64(),
        }
    }

    fn describe(&self, seen: &mut Value) {
        seen["kind"] = json!(self.kind);
        seen["head_sha"] = json!(self.head_sha);
        seen["status"] = json!(self.status);
        seen["conclusion"] = json!(self.conclusion);
        seen["name"] = json!(self.name);
        if let Some(p) = &self.path {
            seen["workflow_path"] = json!(p);
        }
        if self.kind == "check_run" {
            seen["app"] = json!({ "slug": self.app_slug, "id": self.app_id });
        }
    }
}

/// A check run counts as CI only when its app is listed in `github_ci_apps`.
fn app_allowed(cfg: &Config, r: &RunSeen) -> Result<(), String> {
    if r.kind != "check_run" {
        return Ok(());
    }
    let listed = cfg.github_ci_apps.iter().map(|a| a.trim()).filter(|a| !a.is_empty()).any(|a| {
        match a.parse::<u64>() {
            Ok(id) => r.app_id == Some(id),
            Err(_) => r.app_slug.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(a)),
        }
    });
    if listed {
        Ok(())
    } else {
        Err(format!(
            "check run from GitHub App {:?} (id {}), which github_ci_apps does not list; only listed apps' check \
             runs and workflow runs count as CI",
            r.app_slug.as_deref().unwrap_or("unknown"),
            r.app_id.map(|i| i.to_string()).unwrap_or_else(|| "unknown".into())
        ))
    }
}

/// A workflow file path, as `github_check_workflows` or the API names it.
fn is_workflow_path(s: &str) -> bool {
    let s = s.trim().trim_start_matches("./");
    let Some(file) = s.strip_prefix(".github/workflows/") else { return false };
    (file.ends_with(".yml") || file.ends_with(".yaml"))
        && !file.is_empty()
        && file.len() <= 200
        && file.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// The workflow `github_check_workflows` maps `check` to, if any.
fn mapped_workflow<'a>(cfg: &'a Config, check: &str) -> Option<&'a str> {
    cfg.github_check_workflows
        .iter()
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(check))
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

/// Whether the run is the one the check stands for (see the module docs).
fn run_matches_check(cfg: &Config, run: &CiRun, r: &RunSeen) -> Result<&'static str, String> {
    match mapped_workflow(cfg, &run.check) {
        Some(m) if m.contains('/') => {
            let want = m.trim_start_matches("./");
            if r.kind != "workflow_run" {
                return Err(format!(
                    "check {:?} is mapped to workflow file {want:?}; a check run cannot show which file ran",
                    run.check
                ));
            }
            if r.path.as_deref() == Some(want) {
                Ok("workflow_path")
            } else {
                Err(format!(
                    "the run's workflow file is {:?}, not {want:?} as github_check_workflows maps check {:?}",
                    r.path.as_deref().unwrap_or("unknown"),
                    run.check
                ))
            }
        }
        Some(m) => {
            if r.name.trim().eq_ignore_ascii_case(m) {
                Ok("workflow_name")
            } else {
                Err(format!(
                    "the run is {:?}, not {m:?} as github_check_workflows maps check {:?}",
                    r.name, run.check
                ))
            }
        }
        None if run.job.is_some() => Ok("job"),
        None if r.name.trim().eq_ignore_ascii_case(&run.check) => Ok("run_name"),
        None => Err(format!(
            "the run is {:?}, not the check {:?}: name the workflow after the check, bind the check to a job \
             or map it in github_check_workflows",
            r.name, run.check
        )),
    }
}

/// A branch name safe to put in a query string (encoded anyway).
fn branch_ok(b: &str) -> bool {
    (1..=255).contains(&b.len())
        && b.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/'))
        && !b.contains("..")
}

/// Whether the workflow file at the run's head is the same blob as on the
/// default branch. `Ok(None)` when it cannot be told.
async fn workflow_unchanged(
    gh: &GitHub,
    repo: &BoundRepo,
    path: &str,
    head: &str,
    seen: &mut Value,
) -> Option<bool> {
    if !is_workflow_path(path) || full_sha(head).is_none() {
        seen["workflow_check"] = json!("the workflow path is not a plain .github/workflows file");
        return None;
    }
    let default = match gh.get_json(repo, "").await {
        Ok(v) => v["default_branch"].as_str().map(str::to_string).filter(|b| branch_ok(b)),
        Err(e) => {
            seen["workflow_check"] = json!(e.detail());
            return None;
        }
    };
    let Some(default) = default else {
        seen["workflow_check"] = json!("the repository has no usable default branch");
        return None;
    };
    seen["default_branch"] = json!(default);
    let enc: String = url::form_urlencoded::byte_serialize(default.as_bytes()).collect();
    let mut blob = |v: Result<Value, GhError>| match v {
        Ok(v) => v["sha"].as_str().and_then(full_sha),
        Err(GhError::NotFound) => None,
        Err(e) => {
            seen["workflow_check"] = json!(e.detail());
            None
        }
    };
    let at_head = blob(gh.get_json(repo, &format!("contents/{path}?ref={head}")).await);
    let on_default = blob(gh.get_json(repo, &format!("contents/{path}?ref={enc}")).await);
    seen["workflow_blob"] = json!({ "head": at_head, "default_branch": on_default });
    match (at_head, on_default) {
        (Some(a), Some(b)) => Some(a == b),
        // A workflow that exists only on the branch is a changed workflow.
        (Some(_), None) => Some(false),
        _ => None,
    }
}

fn text(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_default().to_string()
}

fn lookup_failed(e: &GhError) -> Verdict {
    match e {
        GhError::NotConfigured(_)
        | GhError::CredentialOff(_)
        | GhError::Unusable(_)
        | GhError::Unauthorized
        | GhError::Forbidden => Verdict::Unverifiable,
        _ => Verdict::Insufficient,
    }
}

async fn find_run(gh: &GitHub, repo: &BoundRepo, id: &str) -> Result<RunSeen, GhError> {
    let id: u64 = id.parse().map_err(|_| GhError::NotFound)?;
    match gh.get_json(repo, &format!("actions/runs/{id}")).await {
        Ok(v) => return Ok(RunSeen::from_workflow_run(&v)),
        Err(GhError::NotFound) => {}
        Err(e) => return Err(e),
    }
    let v = gh.get_json(repo, &format!("check-runs/{id}")).await?;
    Ok(RunSeen::from_check_run(&v))
}

/// Judge a finished-or-not run (or job) against the claim.
fn judge(run: &CiRun, head: &str, status: &str, conclusion: Option<&str>, what: &str) -> (Verdict, String) {
    if full_sha(head).as_deref() != Some(run.head_sha.as_str()) {
        return (Verdict::Mismatch, format!("{what} is for head {head:?}, not {}", run.head_sha));
    }
    if status != "completed" {
        return (Verdict::Insufficient, format!("{what} has not finished (status {status:?})"));
    }
    match conclusion {
        Some(c) if c == run.expect => {
            (Verdict::Verified, format!("{what} completed with {c:?} at the claimed head"))
        }
        Some(c) => (Verdict::Mismatch, format!("{what} concluded {c:?}, the claim implies {:?}", run.expect)),
        None => (Verdict::Insufficient, format!("{what} has no conclusion yet")),
    }
}

impl CiVerifier for GitHubCiVerifier {
    fn verify_run<'a>(&'a self, run: &'a CiRun) -> VerifyFuture<'a> {
        Box::pin(async move {
            let (gh, repo) = match self.client(run).await {
                Ok(c) => c,
                Err(outcome) => return outcome,
            };
            let mut seen = json!({ "forge": "github", "repo": repo.as_str(), "run_id": run.run_id });
            if full_sha(&run.head_sha).is_none() {
                return CiOutcome::new(Verdict::Unverifiable, "the claim names an abbreviated head")
                    .observed(seen);
            }
            let r = match find_run(&gh, &repo, &run.run_id).await {
                Ok(r) => r,
                Err(e) => return CiOutcome::new(lookup_failed(&e), e.detail()).observed(seen),
            };
            r.describe(&mut seen);
            if let Err(why) = app_allowed(&self.cfg, &r) {
                return CiOutcome::new(Verdict::Insufficient, why).observed(seen);
            }
            match run_matches_check(&self.cfg, run, &r) {
                Ok(by) => seen["matched_by"] = json!(by),
                Err(why) => return CiOutcome::new(Verdict::Insufficient, why).observed(seen),
            }
            let (verdict, detail) = judge(
                run,
                &r.head_sha,
                &r.status,
                r.conclusion.as_deref(),
                &format!("{} {}", r.kind, run.run_id),
            );
            if verdict != Verdict::Verified {
                return CiOutcome::new(verdict, detail).observed(seen);
            }
            let require = self.cfg.github_require_default_branch_workflow;
            let unchanged = match &r.path {
                Some(path) => workflow_unchanged(&gh, &repo, path, &run.head_sha, &mut seen).await,
                None => None,
            };
            seen["workflow_unchanged"] = json!(unchanged);
            if require && unchanged != Some(true) {
                let why = match unchanged {
                    Some(false) => "the workflow file at this head differs from the default branch's",
                    _ => "the workflow file could not be compared with the default branch's",
                };
                return CiOutcome::new(
                    Verdict::Insufficient,
                    format!("{why} (github_require_default_branch_workflow)"),
                )
                .observed(seen);
            }
            CiOutcome::new(verdict, detail).observed(seen)
        })
    }

    fn verify_job<'a>(&'a self, run: &'a CiRun, job: &'a str) -> VerifyFuture<'a> {
        Box::pin(async move {
            let (gh, repo) = match self.client(run).await {
                Ok(c) => c,
                Err(outcome) => return outcome,
            };
            let mut seen =
                json!({ "forge": "github", "repo": repo.as_str(), "run_id": run.run_id, "job": job });
            let Ok(id) = run.run_id.parse::<u64>() else {
                return CiOutcome::new(Verdict::Unverifiable, "the run id is not numeric").observed(seen);
            };
            // Every attempt's jobs: a job that ran more than once must agree each time.
            let mut jobs: Vec<Value> = Vec::new();
            let mut workflow = true;
            for page in 1..=JOB_PAGES {
                match gh
                    .get_json(&repo, &format!("actions/runs/{id}/jobs?filter=all&per_page=100&page={page}"))
                    .await
                {
                    Ok(v) => {
                        let batch = v["jobs"].as_array().cloned().unwrap_or_default();
                        let total = v["total_count"].as_u64().unwrap_or(0) as usize;
                        let done = batch.len() < 100;
                        jobs.extend(batch);
                        if done || jobs.len() >= total {
                            break;
                        }
                    }
                    Err(GhError::NotFound) if page == 1 => {
                        workflow = false;
                        break;
                    }
                    Err(e) => return CiOutcome::new(lookup_failed(&e), e.detail()).observed(seen),
                }
            }
            if !workflow {
                // A check run stands for exactly one job: its own name.
                return match find_run(&gh, &repo, &run.run_id).await {
                    Ok(r) if app_allowed(&self.cfg, &r).is_err() => {
                        let why = app_allowed(&self.cfg, &r).err().unwrap_or_default();
                        CiOutcome::new(Verdict::Insufficient, why).observed(seen)
                    }
                    Ok(r) if r.name != job => {
                        seen["name"] = json!(r.name);
                        CiOutcome::new(
                            Verdict::Mismatch,
                            format!("check run {id} is {:?}, not job {job:?}", r.name),
                        )
                        .observed(seen)
                    }
                    Ok(r) => {
                        let (verdict, detail) = judge(
                            run,
                            &r.head_sha,
                            &r.status,
                            r.conclusion.as_deref(),
                            &format!("job {job:?}"),
                        );
                        seen["attempts"] = json!([{ "status": r.status, "conclusion": r.conclusion }]);
                        CiOutcome::new(verdict, detail).observed(seen)
                    }
                    Err(e) => CiOutcome::new(lookup_failed(&e), e.detail()).observed(seen),
                };
            }
            let mut named: Vec<&Value> = jobs.iter().filter(|j| j["name"].as_str() == Some(job)).collect();
            seen["attempts"] = json!(
                named
                    .iter()
                    .map(|j| json!({ "attempt": j["run_attempt"], "status": j["status"], "conclusion": j["conclusion"] }))
                    .collect::<Vec<_>>()
            );
            if named.is_empty() {
                return CiOutcome::new(Verdict::Mismatch, format!("run {id} has no job named {job:?}"))
                    .observed(seen);
            }
            if self.cfg.github_ci_latest_attempt_only {
                // Judge the latest attempt alone; every attempt stays in `attempts`.
                let latest = named.iter().filter_map(|j| j["run_attempt"].as_u64()).max();
                if let Some(latest) = latest {
                    named.retain(|j| j["run_attempt"].as_u64() == Some(latest));
                }
                seen["judged"] = json!({ "latest_attempt_only": true, "attempt": latest });
            }
            let mut worst: Option<(Verdict, String)> = None;
            for j in &named {
                let conclusion = j["conclusion"].as_str();
                let (v, d) = if conclusion == Some("skipped") {
                    (Verdict::Mismatch, format!("job {job:?} was skipped"))
                } else {
                    judge(
                        run,
                        j["head_sha"].as_str().unwrap_or_default(),
                        j["status"].as_str().unwrap_or_default(),
                        conclusion,
                        &format!("job {job:?}"),
                    )
                };
                let rank = |v: Verdict| match v {
                    Verdict::Mismatch => 3,
                    Verdict::Insufficient => 2,
                    Verdict::Unverifiable => 1,
                    Verdict::Verified => 0,
                };
                if worst.as_ref().is_none_or(|(w, _)| rank(v) > rank(*w)) {
                    worst = Some((v, d));
                }
            }
            let (verdict, detail) = worst.unwrap_or((Verdict::Insufficient, "no job state".into()));
            let detail = if verdict == Verdict::Verified && named.len() > 1 {
                format!("{detail} (all {} attempts agree)", named.len())
            } else {
                detail
            };
            CiOutcome::new(verdict, detail).observed(seen)
        })
    }
}

const JOB_PAGES: usize = 5;
