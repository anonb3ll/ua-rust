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
//! native GitHub client in the repository the task's project is bound to.
//! Without a configured token it answers [`Verdict::Unverifiable`] and makes
//! no request. An unverifiable check keeps its `attested` grade; nothing is
//! lowered and nothing is refused.
//!
//! Verdicts mean:
//!
//! - [`Verdict::Verified`]: the run (or job) exists, finished, is for the
//!   claimed head and concluded as claimed.
//! - [`Verdict::Mismatch`]: the forge contradicts the claim (another head,
//!   another conclusion, a missing or skipped job). The grade stays
//!   `attested` and the contradiction is listed.
//! - [`Verdict::Insufficient`]: the forge could not settle it yet (still
//!   running, rate limited, unreadable).
//! - [`Verdict::Unverifiable`]: this hub cannot look the reference up at all.

use std::future::Future;
use std::pin::Pin;

use serde_json::{Value, json};
use ua_core::Config;
use ua_store::Db;

use crate::families::github::client::{BoundRepo, GhError, GitHub, full_sha};

/// One CI run a check points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiRun {
    /// `owner/name`.
    pub repo: String,
    /// The forge's numeric run id, as text.
    pub run_id: String,
    /// The head the check claims the run is for (7-40 lowercase hex).
    pub head_sha: String,
    /// The conclusion the claim implies: `success` for a pass, `failure`
    /// for a fail.
    pub expect: String,
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
/// run. Without a token (`github_token_env`) every lookup is
/// [`Verdict::Unverifiable`] and nothing touches the network. The
/// repository must still be bound to a project when the lookup runs.
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
        let client = match GitHub::from_config(&self.cfg) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Err(CiOutcome::new(Verdict::Unverifiable, NO_TOKEN).observed(seen));
            }
            Err(e) => return Err(CiOutcome::new(Verdict::Unverifiable, e.detail()).observed(seen)),
        };
        let repo = run.repo.clone();
        let bound = self.db.read_async(move |c| BoundRepo::check(c, &repo)).await;
        match bound {
            Ok(b) => Ok((client, b)),
            Err(e) => Err(CiOutcome::new(Verdict::Unverifiable, e.to_string()).observed(seen)),
        }
    }
}

const NO_TOKEN: &str = "no GitHub token is configured (github_token_env), so CI runs cannot be looked up; the check stays attested";

/// What one run lookup found.
struct RunSeen {
    kind: &'static str,
    head_sha: String,
    status: String,
    conclusion: Option<String>,
    name: String,
}

fn text(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_default().to_string()
}

fn lookup_failed(e: &GhError) -> Verdict {
    match e {
        GhError::NotConfigured(_) | GhError::Unauthorized | GhError::Forbidden => Verdict::Unverifiable,
        _ => Verdict::Insufficient,
    }
}

async fn find_run(gh: &GitHub, repo: &BoundRepo, id: &str) -> Result<RunSeen, GhError> {
    let id: u64 = id.parse().map_err(|_| GhError::NotFound)?;
    match gh.get_json(repo, &format!("actions/runs/{id}")).await {
        Ok(v) => {
            return Ok(RunSeen {
                kind: "workflow_run",
                head_sha: text(&v, "head_sha").to_ascii_lowercase(),
                status: text(&v, "status"),
                conclusion: v["conclusion"].as_str().map(str::to_string),
                name: text(&v, "name"),
            });
        }
        Err(GhError::NotFound) => {}
        Err(e) => return Err(e),
    }
    let v = gh.get_json(repo, &format!("check-runs/{id}")).await?;
    Ok(RunSeen {
        kind: "check_run",
        head_sha: text(&v, "head_sha").to_ascii_lowercase(),
        status: text(&v, "status"),
        conclusion: v["conclusion"].as_str().map(str::to_string),
        name: text(&v, "name"),
    })
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
            match find_run(&gh, &repo, &run.run_id).await {
                Ok(r) => {
                    let (verdict, detail) = judge(
                        run,
                        &r.head_sha,
                        &r.status,
                        r.conclusion.as_deref(),
                        &format!("{} {}", r.kind, run.run_id),
                    );
                    seen["kind"] = json!(r.kind);
                    seen["head_sha"] = json!(r.head_sha);
                    seen["status"] = json!(r.status);
                    seen["conclusion"] = json!(r.conclusion);
                    seen["name"] = json!(r.name);
                    CiOutcome::new(verdict, detail).observed(seen)
                }
                Err(e) => CiOutcome::new(lookup_failed(&e), e.detail()).observed(seen),
            }
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
            let named: Vec<&Value> = jobs.iter().filter(|j| j["name"].as_str() == Some(job)).collect();
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
