//! Close-on-merge: a task whose work merged closes with the merge commit as
//! its evidence.
//!
//! A task is matched to a merged pull request only by an explicit link:
//!
//! - its `evidence_ref` names the PR (`https://<host>/<owner>/<name>/pull/<n>`
//!   or `<owner>/<name>#<n>`), or
//! - its notes carry a `closes: <owner>/<name>#<n>` marker (or `closes:`
//!   followed by the PR URL). Free text such as "blocked by owner/name#3"
//!   is never a match.
//!
//! A URL must name the configured GitHub web host (`github_web_host`, by
//! default `github.com` or the GHES host). Only links into the task
//! project's bound repository count, and the task's project must be bound to
//! the PR's repository. It closes only when nothing argues against it:
//!
//! - it links exactly one pull request in that repository (two are `ambiguous`),
//! - the PR merged into the project's merge branch: `github_merge_branches`
//!   for the project, else the repository's default branch. A PR merged
//!   anywhere else (a stacked PR into a feature branch) is ledgered as
//!   `agent.github.merged_to_non_default` and the task stays open,
//! - the PR did not merge before the task was created,
//! - it is unfinished and nobody is working it (no live claim, open or live
//!   dispatch run, pending delegation or node work),
//! - it is not human-gated (`operator-only`/`interactive-only` lane,
//!   `waiting_review`, a `[waiting-for: ...]` marker, red tier) and not in the
//!   `tracking` lane,
//! - it has no open descendants,
//! - when both are known, the PR's head branch is the task's recorded branch,
//! - the merge commit is a full 40-character SHA.
//!
//! Closing goes through the governed `task_update` (status `done`,
//! `evidence_ref` = the merge commit, one `[github: closed-on-merge ...]`
//! notes line), fenced on the task's `updated_at` as it was matched, so a
//! task edited in between is skipped. Each close appends an
//! `agent.github.closed_on_merge` event.
//!
//! Merged PRs come from three places: the webhook (`pull_request` closed and
//! merged), the poller (an open PR that left the open list and is merged),
//! and `coordination_manage(action="queue_close_merged")`, which looks every
//! PR that an unfinished task links up on GitHub. `dry_run` defaults to true
//! there and only reports; `dry_run=false` is for a lifecycle operator or a
//! human.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{Caller, UaError, UaResult};

use super::queue::{Row, descendants, is_active, protection, task_rows};
use crate::Hub;
use crate::families::github::client::{BoundRepo, GitHub, full_sha};
use crate::families::tasks::{emit, int_field, str_field};
use crate::registry::ToolCtx;
use ua_org::authz::{Authority, Authz};

const CHANNEL: &str = "agent.github.closed_on_merge";
const OFF_BRANCH_CHANNEL: &str = "agent.github.merged_to_non_default";
/// Pull requests one on-demand pass looks up.
const LOOKUP_CAP: usize = 50;

/// A merged pull request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MergedPr {
    /// Lowercase `owner/name`.
    pub repo: String,
    pub number: u64,
    /// The merge commit, 40 hex.
    pub merge_sha: String,
    /// The PR's head branch, when known.
    pub head_ref: Option<String>,
    /// The branch the PR merged into (`pull_request.base.ref`).
    pub base_ref: Option<String>,
    /// The repository's default branch, as the payload or API reported it.
    pub default_branch: Option<String>,
    /// When it merged (RFC 3339), when known.
    pub merged_at: Option<String>,
    pub url: String,
}

/// The configuration close-on-merge matches with.
#[derive(Debug, Clone)]
struct Rules {
    /// Lowercase web host PR URLs must name.
    host: String,
    /// Merge branch by project.
    branches: std::collections::BTreeMap<String, String>,
}

impl Rules {
    fn of(cfg: &ua_core::Config) -> Self {
        Rules { host: cfg.github_web_host(), branches: cfg.github_merge_branches.clone() }
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloseMergedArgs {
    /// Report what would close and write nothing (default true).
    pub dry_run: Option<bool>,
    /// Only this bound repository (`owner/name`).
    pub repo: Option<String>,
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:https?://)?([a-z0-9.-]+\.[a-z]{2,}|localhost)(?::\d+)?/([a-z0-9_.-]+/[a-z0-9_.-]+)/pull/(\d{1,9})\b")
            .expect("valid regex")
    })
}

/// A `closes: <link>` marker in task notes.
fn marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:^|[^a-z0-9_-])closes:[ \t]*(\S+)").expect("valid regex"))
}

fn short_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:^|[^a-z0-9_./-])([a-z0-9_.-]+/[a-z0-9_.-]+)#(\d{1,9})\b").expect("valid regex")
    })
}

/// Pull requests as `(owner/name, number)`.
type PrLinks = BTreeSet<(String, u64)>;

/// Every pull request `text` links, as `(owner/name, number)`. A URL counts
/// only when it names `host`.
pub(crate) fn pr_links(text: &str, host: &str) -> BTreeSet<(String, u64)> {
    let mut out = BTreeSet::new();
    for c in url_re().captures_iter(text) {
        if let (Some(h), Some(repo), Some(n)) =
            (c.get(1), c.get(2), c.get(3).and_then(|n| n.as_str().parse::<u64>().ok()))
            && h.as_str().eq_ignore_ascii_case(host)
        {
            out.insert((repo.as_str().to_ascii_lowercase(), n));
        }
    }
    for c in short_re().captures_iter(text) {
        if let (Some(repo), Some(n)) = (c.get(1), c.get(2).and_then(|n| n.as_str().parse::<u64>().ok())) {
            out.insert((repo.as_str().to_ascii_lowercase(), n));
        }
    }
    out
}

/// The pull requests `closes:` markers in `notes` name.
pub(crate) fn closes_markers(notes: &str, host: &str) -> BTreeSet<(String, u64)> {
    let mut out = BTreeSet::new();
    for c in marker_re().captures_iter(notes) {
        if let Some(target) = c.get(1) {
            // The marker names one link: the token right after `closes:`.
            let token = target.as_str().trim_end_matches(['.', ',', ';', ')', ']']);
            out.extend(pr_links(&format!(" {token}"), host));
        }
    }
    out
}

/// The links that tie a task to a PR: its `evidence_ref` and its notes'
/// `closes:` markers, each marked with where it was found.
fn task_links(row: &Row, host: &str) -> (PrLinks, PrLinks) {
    let evidence = pr_links(str_field(row, "evidence_ref").unwrap_or_default(), host);
    let markers = closes_markers(str_field(row, "notes").unwrap_or_default(), host);
    (evidence, markers)
}

/// Unfinished tasks in projects bound to `repo`.
fn candidates(conn: &rusqlite::Connection, repo: &str) -> UaResult<Vec<Row>> {
    task_rows(
        conn,
        "SELECT t.* FROM tasks t JOIN project_repo_bindings b ON b.project = t.project \
         WHERE lower(b.repo) = ?1 AND t.status IN ('open','doing','waiting_review','blocked') ORDER BY t.id",
        [repo],
    )
}

/// One task's verdict for one merged PR.
fn assess(
    conn: &rusqlite::Connection,
    row: &Row,
    pr: &MergedPr,
    now: jiff::Timestamp,
    rules: &Rules,
) -> UaResult<Option<Value>> {
    let (evidence, markers) = task_links(row, &rules.host);
    // Only links into the PR's (the project's bound) repository count, so a
    // mention of another repository's PR never makes a task ambiguous.
    let links: BTreeSet<(String, u64)> =
        evidence.union(&markers).filter(|(r, _)| *r == pr.repo).cloned().collect();
    let key = (pr.repo.clone(), pr.number);
    if !links.contains(&key) {
        return Ok(None);
    }
    let id = int_field(row, "id").unwrap_or_default();
    let in_evidence = evidence.contains(&key);
    let mut entry = json!({
        "task_id": id,
        "title": str_field(row, "title"),
        "status": str_field(row, "status"),
        "repo": pr.repo,
        "pr": pr.number,
        "pr_url": pr.url,
        "merge_sha": pr.merge_sha,
        "matched_by": if in_evidence { "evidence_ref" } else { "closes_marker" },
        "prior_evidence_ref": str_field(row, "evidence_ref"),
        "task_revision": str_field(row, "updated_at"),
        "base_ref": pr.base_ref,
    });
    if links.len() > 1 {
        entry["outcome"] = json!("ambiguous");
        entry["reason"] = json!(format!("the task links {} pull requests", links.len()));
        entry["candidates"] = json!(links.iter().map(|(r, n)| format!("{r}#{n}")).collect::<Vec<_>>());
        return Ok(Some(entry));
    }
    // The PR must have merged into the project's merge branch.
    let project = str_field(row, "project").unwrap_or("default");
    let want = rules.branches.get(project).cloned().or_else(|| pr.default_branch.clone());
    entry["merge_branch"] = json!(want);
    if want.is_none() || pr.base_ref.is_none() || want != pr.base_ref {
        entry["outcome"] = json!("merged_to_non_default");
        entry["reason"] = json!(format!(
            "the PR merged into {:?}, not the merge branch {:?}; the merge commit is not on it, so the task stays open",
            pr.base_ref.as_deref().unwrap_or("unknown"),
            want.as_deref().unwrap_or("unknown")
        ));
        return Ok(Some(entry));
    }
    let mut reasons = protection(conn, row, now)?;
    if let (Some(merged), Some(created)) = (
        pr.merged_at.as_deref().and_then(ua_core::time::parse_ts),
        str_field(row, "created_at").and_then(ua_core::time::parse_ts),
    ) && merged < created
    {
        reasons.push("the pull request merged before the task was created".into());
    }
    let open_children: Vec<String> = descendants(conn, id)?
        .iter()
        .filter(|c| is_active(c))
        .filter_map(|c| int_field(c, "id").map(|i| format!("#{i}")))
        .take(10)
        .collect();
    if !open_children.is_empty() {
        reasons.push(format!("open child task(s): {}", open_children.join(", ")));
    }
    if let (Some(branch), Some(head)) =
        (str_field(row, "branch").filter(|b| !b.trim().is_empty()), &pr.head_ref)
        && branch.trim() != head
    {
        reasons.push(format!("the PR's head branch {head:?} is not the task's branch {branch:?}"));
    }
    if full_sha(&pr.merge_sha).is_none() {
        reasons.push("the merge commit is not a full SHA".into());
    }
    if reasons.is_empty() {
        entry["outcome"] = json!("close");
    } else {
        entry["outcome"] = json!("blocked");
        entry["reason"] = json!(reasons.join("; "));
    }
    Ok(Some(entry))
}

/// Match `prs` to tasks and, unless `dry_run`, close the clear matches as
/// `actor` through `task_update`.
pub(crate) async fn close_merged(
    hub: &Hub,
    actor: &Caller,
    prs: Vec<MergedPr>,
    dry_run: bool,
) -> UaResult<Value> {
    let considered = prs.len();
    let rules = Rules::of(hub.cfg());
    let matches: Vec<Value> = hub
        .db()
        .read_async(move |c| {
            let now = jiff::Timestamp::now();
            let mut out = Vec::new();
            for pr in &prs {
                for row in candidates(c, &pr.repo)? {
                    if let Some(m) = assess(c, &row, pr, now, &rules)? {
                        out.push(m);
                    }
                }
            }
            Ok(out)
        })
        .await?;
    let (mut ambiguous, mut blocked, mut would_close, mut closed, mut skipped) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut off_branch = Vec::new();
    let mut seen = BTreeSet::new();
    for m in matches {
        match m["outcome"].as_str() {
            Some("ambiguous") => ambiguous.push(m),
            Some("blocked") => blocked.push(m),
            Some("merged_to_non_default") => off_branch.push(m),
            _ if !seen.insert(m["task_id"].as_i64()) => {}
            _ if dry_run => would_close.push(m),
            _ => match close_one(hub, actor, &m).await {
                Ok(()) => closed.push(m),
                Err(e) => {
                    let mut m = m;
                    m["outcome"] = json!("skipped");
                    m["reason"] = json!(e.to_string());
                    skipped.push(m);
                }
            },
        }
    }
    if !dry_run && !off_branch.is_empty() {
        let (events, by) = (off_branch.clone(), actor.label.clone());
        hub.db()
            .write_async(move |tx| {
                for m in &events {
                    let payload = json!({
                        "task_id": m["task_id"], "repo": m["repo"], "pr": m["pr"], "merge_sha": m["merge_sha"],
                        "base_ref": m["base_ref"], "merge_branch": m["merge_branch"],
                    });
                    emit(tx, OFF_BRANCH_CHANNEL, payload, &by)?;
                }
                Ok(())
            })
            .await?;
    }
    Ok(json!({
        "dry_run": dry_run,
        "prs_considered": considered,
        "would_close": would_close,
        "closed": closed,
        "skipped": skipped,
        "ambiguous": ambiguous,
        "blocked": blocked,
        "merged_to_non_default": off_branch,
    }))
}

async fn close_one(hub: &Hub, actor: &Caller, m: &Value) -> UaResult<()> {
    let id = m["task_id"].as_i64().unwrap_or_default();
    let sha = m["merge_sha"].as_str().unwrap_or_default().to_string();
    let prior = m["prior_evidence_ref"]
        .as_str()
        .filter(|p| !p.trim().is_empty())
        .map(|p| format!("; prior evidence_ref: {}", p.chars().take(200).collect::<String>()))
        .unwrap_or_default();
    let note = format!(
        "[github: closed-on-merge @ {}] PR {} merge_sha={sha} (matched by {}{prior})",
        ua_core::time::now(),
        m["pr_url"].as_str().unwrap_or_default(),
        m["matched_by"].as_str().unwrap_or_default(),
    );
    let mut args = json!({
        "id": id,
        "status": "done",
        "evidence_ref": sha,
        "append_note": note,
    });
    if let Some(rev) = m["task_revision"].as_str() {
        args["expected_updated_at"] = json!(rev);
    }
    crate::builtin_registry_shared().call(hub, actor, "task_update", args).await?;
    let payload = json!({
        "task_id": id, "repo": m["repo"], "pr": m["pr"], "merge_sha": sha, "matched_by": m["matched_by"],
    });
    let by = actor.label.clone();
    hub.db().write_async(move |tx| emit(tx, CHANNEL, payload, &by)).await
}

/// `coordination_manage(action="queue_close_merged")`.
pub(crate) async fn queue_close_merged(ctx: ToolCtx, a: CloseMergedArgs) -> UaResult<Value> {
    let dry_run = a.dry_run.unwrap_or(true);
    if !dry_run {
        // Closing other agents' tasks in bulk is an operator act: a lifecycle
        // operator or a human. Each close is a task_update as them.
        crate::families::governance::verified_actor(&ctx.caller, "close merged tasks")?;
        if !Authz::new(ctx.hub.cfg()).holds(
            &ctx.caller,
            &[Authority::Operator, Authority::LifecycleOperator],
            ua_core::DEFAULT_ORG,
        ) {
            return Err(UaError::denied(
                "operator_required",
                "queue_close_merged with dry_run=false is for a lifecycle operator or a human; a dry run is open to all",
            ));
        }
    }
    let host = ctx.hub.cfg().github_web_host();
    let only = a.repo.as_deref().map(crate::families::governance::normalize_repo).transpose()?;
    let gh = GitHub::require(ctx.hub.cfg()).map_err(|e| UaError::invalid(e.detail()))?;
    // Every PR an unfinished task in a bound project links, in that repository.
    let wanted: Vec<(BoundRepo, u64)> = ctx
        .hub
        .db()
        .read_async(move |c| {
            let mut out: BTreeSet<(BoundRepo, u64)> = BTreeSet::new();
            for repo in BoundRepo::all(c)? {
                if only.as_deref().is_some_and(|o| o != repo.as_str()) {
                    continue;
                }
                for row in candidates(c, repo.as_str())? {
                    let (evidence, markers) = task_links(&row, &host);
                    for (r, n) in evidence.into_iter().chain(markers) {
                        if r == repo.as_str() {
                            out.insert((repo.clone(), n));
                        }
                    }
                }
            }
            Ok(out.into_iter().collect())
        })
        .await?;
    let truncated = wanted.len() > LOOKUP_CAP;
    let mut prs = Vec::new();
    let mut lookups = Vec::new();
    for (repo, n) in wanted.into_iter().take(LOOKUP_CAP) {
        match gh.get_json(&repo, &format!("pulls/{n}")).await {
            Ok(v) => match merged_from_api(repo.as_str(), &v) {
                Some(pr) => prs.push(pr),
                None => lookups.push(json!({ "repo": repo.as_str(), "pr": n, "merged": false })),
            },
            Err(e) => lookups.push(json!({ "repo": repo.as_str(), "pr": n, "error": e.detail() })),
        }
    }
    let mut out = close_merged(&ctx.hub, &ctx.caller, prs, dry_run).await?;
    out["not_merged_or_failed"] = json!(lookups);
    out["truncated"] = json!(truncated);
    Ok(out)
}

/// A merged PR from a GitHub pull request object, else `None`.
pub(crate) fn merged_from_api(repo: &str, pr: &Value) -> Option<MergedPr> {
    let merged = pr["merged"].as_bool() == Some(true) || pr["merged_at"].as_str().is_some();
    if !merged {
        return None;
    }
    let number = pr["number"].as_u64()?;
    Some(MergedPr {
        repo: repo.to_ascii_lowercase(),
        number,
        merge_sha: full_sha(pr["merge_commit_sha"].as_str()?)?,
        head_ref: pr["head"]["ref"].as_str().map(str::to_string),
        base_ref: pr["base"]["ref"].as_str().map(str::to_string),
        default_branch: pr["base"]["repo"]["default_branch"].as_str().map(str::to_string),
        merged_at: pr["merged_at"].as_str().map(str::to_string),
        url: pr["html_url"].as_str().map(str::to_string).unwrap_or_else(|| format!("{repo}#{number}")),
    })
}

#[cfg(test)]
mod tests {
    use super::{closes_markers, pr_links};

    #[test]
    fn links_are_urls_or_short_references() {
        let found = pr_links(
            "see https://github.com/Owner/Repo/pull/12 and owner/other#7, not #9 or a/b/c#4 or path/x#\n\
             github.com/owner/repo/pull/12/files",
            "github.com",
        );
        let want: Vec<(String, u64)> = vec![("owner/other".into(), 7), ("owner/repo".into(), 12)];
        assert_eq!(found.into_iter().collect::<Vec<_>>(), want);
        assert!(pr_links("owner/repo#12345678901", "github.com").is_empty(), "absurd numbers are not links");
    }

    #[test]
    fn a_url_must_name_the_configured_host() {
        assert!(pr_links("https://evil.example.com/owner/repo/pull/3", "github.com").is_empty());
        assert_eq!(pr_links("https://GHE.example.com/owner/repo/pull/3", "ghe.example.com").len(), 1);
    }

    #[test]
    fn only_closes_markers_count_in_notes() {
        let notes = "blocked by owner/repo#3; see owner/repo#4\ncloses: owner/repo#5.\nCloses: https://github.com/owner/repo/pull/6\nencloses: owner/repo#8";
        let got: Vec<u64> = closes_markers(notes, "github.com").into_iter().map(|(_, n)| n).collect();
        assert_eq!(got, vec![5, 6]);
    }
}
