//! CI verification for task checks.
//!
//! A task check (`coordination_manage(action="task_check_record")`) is an
//! agent's claim: "tests pass at head `abc1234`". When the check names a CI
//! run (`ref: {kind: "ci_run", ref, repo, job?}`), the hub can try to confirm
//! the claim itself. That lookup goes through [`CiVerifier`], held by the
//! [`Hub`](crate::Hub), so the hub never shells out to a forge CLI and tests
//! can plug in a fake.
//!
//! The default verifier, [`GitHubCiVerifier`], is a stub: it answers
//! [`Verdict::Unverifiable`] for every run until the native GitHub client
//! lands. An unverifiable check keeps its `attested` grade; nothing is
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

/// The GitHub verifier. A stub until the native GitHub client exists: every
/// lookup is [`Verdict::Unverifiable`], so recorded checks stay `attested`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GitHubCiVerifier;

const STUB_DETAIL: &str =
    "this hub has no GitHub client yet, so CI runs cannot be looked up; the check stays attested";

impl CiVerifier for GitHubCiVerifier {
    fn verify_run<'a>(&'a self, run: &'a CiRun) -> VerifyFuture<'a> {
        Box::pin(async move {
            CiOutcome::new(Verdict::Unverifiable, STUB_DETAIL)
                .observed(json!({ "forge": "github", "repo": run.repo, "run_id": run.run_id }))
        })
    }

    fn verify_job<'a>(&'a self, run: &'a CiRun, job: &'a str) -> VerifyFuture<'a> {
        Box::pin(async move {
            CiOutcome::new(Verdict::Unverifiable, STUB_DETAIL)
                .observed(json!({ "forge": "github", "repo": run.repo, "run_id": run.run_id, "job": job }))
        })
    }
}
