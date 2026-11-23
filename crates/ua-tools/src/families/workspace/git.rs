//! `git_diff_staged`, `git_commit_staged`, `git_worktree_*` and `git_merge_task`.
//!
//! git runs through the CLI with a cleaned environment (no inherited `GIT_*`
//! variables) and fixed argument lists, so a caller cannot pass `-c`,
//! `--exec-path` or another repository. Every tool first checks that the
//! repository's toplevel lies inside the workspace root: git walks upward to
//! find `.git`, and an outer repository is out of bounds.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use rusqlite::OptionalExtension;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::safety::resolve_in_root;
use ua_core::{UaError, UaResult};

use crate::approvals::{self, GateOutcome, Refusal, RefusalReason};
use crate::families::continuity;
use crate::families::github::authz;

use super::{RunOutput, Sandbox, git_env, record, run_program, sandbox};
use crate::registry::{Registry, ToolCtx, tool};

const GIT_TIMEOUT: Duration = Duration::from_secs(30);
/// Output kept per stream from one git call.
const GIT_OUTPUT_CAP: usize = 8 * 1024 * 1024;

static CONVENTIONAL_COMMIT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(?:\([a-zA-Z0-9_\-\s]+\))?!?:\s[^\n]{1,100}$",
    )
    .ok()
});
/// Must not start with `-` (git would parse an option); git's ref characters only.
static BRANCH_NAME: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._/\-]*$").ok());

fn dot() -> String {
    ".".into()
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoArgs {
    /// A directory inside the repository (relative to the workspace root).
    #[serde(default = "dot")]
    pub repo_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitArgs {
    /// Conventional Commits message: `<type>(<scope>)?!?: <description>`
    /// (header max 100 chars), optionally a blank line and a body.
    pub message: String,
    #[serde(default = "dot")]
    pub repo_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorktreeAddArgs {
    /// Where to create the worktree, inside the workspace root.
    pub path: String,
    /// Branch to check out; created from HEAD when it does not exist.
    pub branch: String,
    #[serde(default = "dot")]
    pub repo_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorktreeRemoveArgs {
    /// The worktree to remove, inside the workspace root.
    pub path: String,
    /// Remove even with modified or untracked files.
    #[serde(default)]
    pub force: bool,
    #[serde(default = "dot")]
    pub repo_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeArgs {
    /// Task whose recorded branch is merged.
    pub task_id: i64,
    /// Skip the task-status and clean-worktree checks.
    #[serde(default)]
    pub force: bool,
    /// Run every check and report; merge and clean up nothing.
    #[serde(default)]
    pub dry_run: bool,
    /// Accept a task that is still `doing` or `blocked` (status check only).
    #[serde(default)]
    pub allow_in_flight: bool,
    /// Merge under this policy authorization (`policy_authorization_record`)
    /// instead of a one-time human approval. It must be valid, for this task,
    /// for the task project's bound repository and for exactly the head being
    /// merged, and recorded by someone other than the caller who is still a
    /// human identity. `force` is refused on this path, and `allow_in_flight`
    /// unless the authorization allows it. A successful merge spends it (a
    /// failed one leaves it active); a dry run only reports that it covers
    /// the merge.
    pub policy_authorization_id: Option<i64>,
}

async fn git(args: &[&str], cwd: &Path) -> UaResult<RunOutput> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let out = run_program("git", &args, cwd, &git_env(), GIT_TIMEOUT, GIT_OUTPUT_CAP).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            UaError::not_found("git executable not found on PATH")
        } else {
            UaError::internal(format!("could not start git: {e}"))
        }
    })?;
    if out.timed_out {
        return Err(UaError::conflict(format!(
            "git {} timed out after 30 seconds",
            args.first().map_or("", |s| s)
        )));
    }
    Ok(out)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn git_failure(what: &str, out: &RunOutput) -> UaError {
    UaError::conflict(format!("{what} failed: {}", text(&out.stderr).trim()))
}

/// Resolve `repo_path` in the workspace and require the repository toplevel
/// to lie inside the workspace root. Returns (directory, toplevel).
async fn ensure_repo(sb: &Sandbox, repo_path: &str) -> UaResult<(PathBuf, PathBuf)> {
    let dir = resolve_in_root(repo_path, std::slice::from_ref(&sb.root), true)?;
    if !dir.is_dir() {
        return Err(UaError::invalid(format!("{repo_path:?} is not a directory")));
    }
    let out = git(&["rev-parse", "--show-toplevel"], &dir).await?;
    if out.exit_code != 0 {
        return Err(UaError::invalid(format!("{repo_path:?} is not inside a git repository")));
    }
    let top = PathBuf::from(text(&out.stdout).trim());
    let top = top.canonicalize().unwrap_or(top);
    if !top.starts_with(&sb.root) {
        return Err(UaError::denied(
            "repo_outside_workspace",
            "the repository root is outside the workspace root; git tools only operate on repositories \
             inside the workspace",
        ));
    }
    Ok((dir, top))
}

async fn git_diff_staged(ctx: ToolCtx, a: RepoArgs) -> UaResult<Value> {
    let sb = sandbox(&ctx)?;
    let (dir, _) = ensure_repo(&sb, &a.repo_path).await?;
    let status = git(&["status", "--porcelain"], &dir).await?;
    if status.exit_code != 0 {
        return Err(git_failure("git status", &status));
    }
    let staged: Vec<Value> = text(&status.stdout)
        .lines()
        .filter(|l| l.len() >= 3)
        .filter_map(|l| {
            let st = l.chars().next()?;
            matches!(st, 'M' | 'A' | 'D' | 'R' | 'C')
                .then(|| json!({ "file": &l[3..], "status": st.to_string() }))
        })
        .collect();
    let diff = git(&["diff", "--cached", "--no-ext-diff", "--no-textconv", "--no-color"], &dir).await?;
    if diff.exit_code != 0 {
        return Err(git_failure("git diff", &diff));
    }
    let diff_text = text(&diff.stdout);
    let is_clean = staged.is_empty() && diff_text.trim().is_empty();
    let mut out = json!({ "staged_files": staged, "diff_text": diff_text, "is_clean": is_clean });
    if diff.stdout_total > diff.stdout.len() {
        out["diff_truncated"] = json!(true);
    }
    Ok(out)
}

/// Check a commit message against Conventional Commits; returns it trimmed.
pub fn check_commit_message(message: &str) -> UaResult<String> {
    let message = message.trim().to_string();
    let mut lines = message.lines();
    let header = lines.next().unwrap_or("");
    let ok = CONVENTIONAL_COMMIT.as_ref().is_some_and(|rx| rx.is_match(header));
    if !ok {
        return Err(UaError::invalid(format!(
            "commit header {header:?} does not match the Conventional Commits specification. Expected \
             '<type>(<scope>)?: <description>' (max 100 characters); types: feat, fix, docs, style, \
             refactor, perf, test, build, ci, chore, revert."
        )));
    }
    if lines.next().is_some_and(|l| !l.trim().is_empty()) {
        return Err(UaError::invalid(
            "Conventional Commits requires a blank line between the header and the body.",
        ));
    }
    Ok(message)
}

async fn git_commit_staged(ctx: ToolCtx, a: CommitArgs) -> UaResult<Value> {
    let message = check_commit_message(&a.message)?;
    let sb = sandbox(&ctx)?;
    let (dir, top) = ensure_repo(&sb, &a.repo_path).await?;
    let commit = git(&["commit", "-m", &message], &dir).await?;
    if commit.exit_code != 0 {
        let detail = if commit.stderr.is_empty() { &commit.stdout } else { &commit.stderr };
        return Err(UaError::conflict(format!("git commit failed: {}", text(detail).trim())));
    }
    let log = git(&["log", "-n", "1", "--pretty=format:%h %s"], &dir).await?;
    let line = if log.exit_code == 0 { text(&log.stdout).trim().to_string() } else { String::new() };
    let (hash, summary) =
        line.split_once(' ').map_or((line.clone(), String::new()), |(h, s)| (h.into(), s.into()));
    record(&ctx, "agent.git.committed", json!({ "repo": sb.rel(&top), "commit_hash": hash })).await?;
    Ok(json!({ "commit_hash": hash, "summary": summary, "stdout": text(&commit.stdout).trim() }))
}

/// Parse `git worktree list --porcelain`.
pub fn parse_worktree_porcelain(stdout: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut cur = Map::new();
    for line in stdout.lines().map(str::trim) {
        if line.is_empty() {
            if !cur.is_empty() {
                out.push(Value::Object(std::mem::take(&mut cur)));
            }
            continue;
        }
        let (key, val) = line.split_once(' ').unwrap_or((line, ""));
        match key {
            "worktree" => {
                cur.insert("path".into(), json!(val));
            }
            "HEAD" => {
                cur.insert("head".into(), json!(val));
            }
            "branch" => {
                cur.insert("branch".into(), json!(val.strip_prefix("refs/heads/").unwrap_or(val)));
            }
            "bare" => {
                cur.insert("bare".into(), json!(true));
            }
            _ => {}
        }
    }
    if !cur.is_empty() {
        out.push(Value::Object(cur));
    }
    out
}

async fn git_worktree_list(ctx: ToolCtx, a: RepoArgs) -> UaResult<Value> {
    let sb = sandbox(&ctx)?;
    let (dir, _) = ensure_repo(&sb, &a.repo_path).await?;
    let out = git(&["worktree", "list", "--porcelain"], &dir).await?;
    if out.exit_code != 0 {
        return Err(git_failure("git worktree list", &out));
    }
    Ok(json!({ "worktrees": parse_worktree_porcelain(&text(&out.stdout)) }))
}

fn check_branch(branch: &str) -> UaResult<()> {
    let ok = BRANCH_NAME.as_ref().is_some_and(|rx| rx.is_match(branch)) && !branch.contains("..");
    if !ok {
        return Err(UaError::invalid(format!(
            "invalid branch name {branch:?}: must start with a letter or digit and contain only letters, \
             digits, '.', '_', '/', '-'"
        )));
    }
    Ok(())
}

async fn branch_exists(dir: &Path, branch: &str) -> UaResult<bool> {
    let refname = format!("refs/heads/{branch}");
    Ok(git(&["show-ref", "--verify", "--quiet", &refname], dir).await?.exit_code == 0)
}

async fn git_worktree_add(ctx: ToolCtx, a: WorktreeAddArgs) -> UaResult<Value> {
    check_branch(&a.branch)?;
    let sb = sandbox(&ctx)?;
    let (dir, top) = ensure_repo(&sb, &a.repo_path).await?;
    let target = resolve_in_root(&a.path, std::slice::from_ref(&sb.root), true)?;
    let target_s = target.to_string_lossy().into_owned();
    let exists = branch_exists(&dir, &a.branch).await?;
    let args: Vec<&str> = if exists {
        vec!["worktree", "add", &target_s, &a.branch]
    } else {
        vec!["worktree", "add", "-b", &a.branch, &target_s]
    };
    let out = git(&args, &dir).await?;
    if out.exit_code != 0 {
        return Err(git_failure("git worktree add", &out));
    }
    record(
        &ctx,
        "agent.git.worktree_added",
        json!({ "repo": sb.rel(&top), "path": sb.rel(&target), "branch": a.branch, "created_branch": !exists }),
    )
    .await?;
    Ok(json!({ "path": target_s, "branch": a.branch, "stdout": text(&out.stdout).trim() }))
}

async fn git_worktree_remove(ctx: ToolCtx, a: WorktreeRemoveArgs) -> UaResult<Value> {
    let sb = sandbox(&ctx)?;
    let (dir, top) = ensure_repo(&sb, &a.repo_path).await?;
    let target = resolve_in_root(&a.path, std::slice::from_ref(&sb.root), true)?;
    let target_s = target.to_string_lossy().into_owned();
    let mut args = vec!["worktree", "remove"];
    if a.force {
        args.push("--force");
    }
    args.push(&target_s);
    let out = git(&args, &dir).await?;
    if out.exit_code != 0 {
        return Err(git_failure("git worktree remove", &out));
    }
    record(
        &ctx,
        "agent.git.worktree_removed",
        json!({ "repo": sb.rel(&top), "path": sb.rel(&target), "force": a.force }),
    )
    .await?;
    Ok(json!({ "path": target_s, "deleted": true, "stdout": text(&out.stdout).trim() }))
}

struct TaskRow {
    title: String,
    status: String,
    branch: Option<String>,
    worktree_path: Option<String>,
    /// The repository the task's project is bound to.
    repo: Option<String>,
}

async fn rev_parse(dir: &Path, rev: &str) -> UaResult<Option<String>> {
    let out = git(&["rev-parse", "--verify", "--quiet", rev], dir).await?;
    Ok((out.exit_code == 0).then(|| text(&out.stdout).trim().to_string()))
}

async fn is_clean(dir: &Path, untracked: bool) -> UaResult<bool> {
    let flag = if untracked { "--untracked-files=normal" } else { "--untracked-files=no" };
    let out = git(&["status", "--porcelain", flag], dir).await?;
    if out.exit_code != 0 {
        return Err(git_failure("git status", &out));
    }
    Ok(text(&out.stdout).trim().is_empty())
}

/// Check out `target` and merge `head` into it. Returns the new HEAD.
async fn run_merge(top: &Path, target: &str, id: i64, title: &str, head: &str) -> UaResult<String> {
    let current = git(&["rev-parse", "--abbrev-ref", "HEAD"], top).await?;
    if text(&current.stdout).trim() != target {
        let co = git(&["checkout", target], top).await?;
        if co.exit_code != 0 {
            return Err(git_failure(&format!("git checkout {target}"), &co));
        }
    }
    let title: String = title.lines().next().unwrap_or("").chars().take(120).collect();
    let message = format!("feat(merge): merge task {id}: {title}");
    // Merge the commit checked above, not a name that may have moved since.
    let merged = git(&["merge", "--no-edit", "-m", &message, head], top).await?;
    if merged.exit_code != 0 {
        let _ = git(&["merge", "--abort"], top).await;
        return Err(git_failure("git merge", &merged));
    }
    Ok(rev_parse(top, "HEAD").await?.unwrap_or_default())
}

const MERGE_TOOL: &str = "git_merge_task";

/// What a one-time approval of a merge binds: the call's arguments and the
/// head, branch, target branch and bound repository (`owner/name`, `null`
/// when the task's project has none) resolved when the call is made, with a
/// one-line `summary` naming the commit and the target for the approver.
fn merge_approval_payload(
    a: &MergeArgs,
    branch: &str,
    head: &str,
    target: &str,
    repo: Option<&str>,
) -> Value {
    let short: String = head.chars().take(12).collect();
    let into = match repo {
        Some(r) => format!("{target} of {r}"),
        None => format!("{target} of the workspace repository (no repository bound)"),
    };
    let what = if a.dry_run { "Dry run of merging" } else { "Merge" };
    json!({
        "task_id": a.task_id,
        "force": a.force,
        "dry_run": a.dry_run,
        "allow_in_flight": a.allow_in_flight,
        "branch": branch,
        "head": head,
        "target": target,
        "repo": repo,
        "summary": format!("{what} task {} branch {branch} at commit {short} into {into}", a.task_id),
    })
}

/// Take a one-time approval for exactly `payload`. First enforces any required
/// review at `head` so an unreviewed commit does not park or spend a pass. A
/// live pass for the same task bound to other values (the branch moved, the
/// project was rebound) does not cover it: the call is refused
/// (`approval_binding_changed`), the refusal is ledgered, and a new request
/// for the current values is parked.
async fn one_time_approval(ctx: &ToolCtx, task_id: i64, head: &str, payload: Value) -> UaResult<()> {
    let (hub, caller, head) = (ctx.hub.clone(), ctx.caller.clone(), head.to_string());
    ctx.hub
        .db()
        .write_async(move |tx| {
            continuity::require_review_at_head(tx, &caller.org_id, task_id, &head)?;
            let cfg = hub.cfg();
            match approvals::gate(tx, cfg, &caller, MERGE_TOOL, &payload)? {
                GateOutcome::Pass { .. } => Ok(Ok(())),
                GateOutcome::Denied { approval_id, reason } => Ok(Err(UaError::denied(
                    "approval_denied",
                    format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                ))),
                GateOutcome::Pending { approval_id } => {
                    let stale = approvals::stale_pass(tx, cfg, &caller.org_id, &caller.label, MERGE_TOOL, &payload, &["task_id"])?;
                    let Some(stale) = stale else {
                        return Ok(Err(UaError::ApprovalRequired { tool: MERGE_TOOL.into(), approval_id }));
                    };
                    // The summary restates the bound fields; name those.
                    let changed: Vec<String> = stale.changed.into_iter().filter(|f| f != "summary").collect();
                    let r = Refusal::new(MERGE_TOOL, RefusalReason::BindingChanged)
                        .approval(stale.approval_id)
                        .task(Some(task_id))
                        .hashes(Some(stale.approved_sha256), Some(approvals::payload_sha256(MERGE_TOOL, &payload)))
                        .changed(changed.clone());
                    approvals::refused(tx, &caller.org_id, &caller.label, &r, None)?;
                    Ok(Err(UaError::denied(
                        "approval_binding_changed",
                        format!(
                            "approval {} no longer matches this merge (changed: {}); approval {approval_id} was \
                             requested for the current values",
                            stale.approval_id,
                            changed.join(", ")
                        ),
                    )))
                }
            }
        })
        .await?
}

async fn git_merge_task(ctx: ToolCtx, a: MergeArgs) -> UaResult<Value> {
    let sb = sandbox(&ctx)?;
    let id = a.task_id;
    let org = ctx.caller.org_id.clone();
    let org1 = org.clone();
    let row = ctx
        .hub
        .db()
        .read_async(move |c| {
            Ok(c.query_row(
                // The task is the caller's organization's; only the binding
                // of the task row's own organization joins.
                "SELECT t.title, t.status, t.branch, t.worktree_path, b.repo FROM tasks t \
                 LEFT JOIN project_repo_bindings b ON b.org_id = t.org_id AND b.project = t.project \
                 WHERE t.id = ?1 AND t.org_id = ?2",
                rusqlite::params![id, org1],
                |r| {
                    Ok(TaskRow {
                        title: r.get(0)?,
                        status: r.get(1)?,
                        branch: r.get(2)?,
                        worktree_path: r.get(3)?,
                        repo: r.get(4)?,
                    })
                },
            )
            .optional()?)
        })
        .await?
        .ok_or_else(|| UaError::not_found(format!("task {id}")))?;

    if let Some(auth_id) = a.policy_authorization_id
        && a.force
    {
        let who = ctx.caller.label.clone();
        let org2 = org.clone();
        return Err(ctx
            .hub
            .db()
            .write_async(move |tx| {
                let row = authz::row(tx, &org2, auth_id)?;
                let err = UaError::denied(
                    "policy_authorization_force",
                    "force=true is refused under a policy authorization: it covers a clean merge only; ask for a \
                     one-time approval instead",
                );
                Err::<(), _>(authz::refuse_mode(tx, &org2, &who, auth_id, id, row.as_ref(), "force", err))
            })
            .await
            .unwrap_err());
    }
    let status_ok =
        row.status == "done" || (a.allow_in_flight && ["doing", "blocked"].contains(&row.status.as_str()));
    if !status_ok && !a.force {
        return Err(UaError::conflict(format!(
            "task {id} is {}, not done; pass force=true (or allow_in_flight=true for doing/blocked)",
            row.status
        )));
    }

    let (_, top) = ensure_repo(&sb, ".").await?;

    // The worktree, when recorded, must be inside the workspace.
    let worktree = match row.worktree_path.as_deref().filter(|p| !p.trim().is_empty()) {
        Some(p) => Some(resolve_in_root(p, std::slice::from_ref(&sb.root), true)?),
        None => None,
    };
    let worktree = worktree.filter(|p| p.is_dir());

    let branch = match row.branch.clone().filter(|b| !b.trim().is_empty()) {
        Some(b) => b,
        None => {
            // Fall back to the branch checked out in the recorded worktree.
            let Some(wt) = &worktree else {
                return Err(UaError::not_found(format!("task {id} has no recorded branch or worktree")));
            };
            let out = git(&["rev-parse", "--abbrev-ref", "HEAD"], wt).await?;
            let b = text(&out.stdout).trim().to_string();
            if out.exit_code != 0 || b.is_empty() || b == "HEAD" {
                return Err(UaError::not_found(format!("task {id}'s worktree has no branch checked out")));
            }
            b
        }
    };
    check_branch(&branch)?;
    let head = rev_parse(&top, &format!("refs/heads/{branch}^{{commit}}")).await?.ok_or_else(|| {
        UaError::not_found(format!("branch {branch:?} does not exist in the workspace repository"))
    })?;

    let worktree_clean = match &worktree {
        Some(wt) => Some(is_clean(wt, true).await?),
        None => None,
    };
    if worktree_clean == Some(false) && !a.force {
        return Err(UaError::conflict(format!(
            "task {id}'s worktree has uncommitted changes; pass force=true"
        )));
    }

    let target = if branch_exists(&top, "main").await? {
        "main"
    } else if branch_exists(&top, "master").await? {
        "master"
    } else {
        return Err(UaError::not_found("the workspace repository has no main (or master) branch"));
    };
    if branch == target {
        return Err(UaError::invalid(format!("task {id}'s branch is {target} itself")));
    }
    if !is_clean(&top, false).await? {
        return Err(UaError::conflict("the workspace repository checkout has uncommitted changes"));
    }
    let already_merged =
        git(&["merge-base", "--is-ancestor", &head, &format!("refs/heads/{target}")], &top).await?.exit_code
            == 0;

    let mut report = json!({
        "success": true,
        "task_id": id,
        "branch": branch,
        "head": head,
        "target": target,
        "worktree_path": worktree.as_ref().map(|p| sb.rel(p)),
        "worktree_clean": worktree_clean,
        "already_merged": already_merged,
    });
    // Without a policy authorization the merge needs a one-time approval
    // bound to what it will do, resolved now: the head, the branch, the
    // target branch and the bound repository. A commit added after the human
    // approved, or a project rebound to another repository, no longer matches.
    if a.policy_authorization_id.is_none() {
        let payload = merge_approval_payload(&a, &branch, &head, target, row.repo.as_deref());
        one_time_approval(&ctx, id, &head, payload).await?;
    }
    // A policy authorization stands in for the one-time approval. It is
    // reserved (consumed, fenced on the head) right before the merge and put
    // back to active if the merge does not happen, so a failure does not burn it.
    let mut spent: Option<(i64, String)> = None;
    if let Some(auth_id) = a.policy_authorization_id {
        let (repo, h, who, cfg) =
            (row.repo.clone(), head.clone(), ctx.caller.label.clone(), ctx.hub.cfg().clone());
        let (dry, in_flight, status) = (a.dry_run, a.allow_in_flight, row.status.clone());
        let org3 = org.clone();
        let stamp = ctx
            .hub
            .db()
            .write_async(move |tx| {
                let auth = authz::covering(tx, &cfg, &org3, auth_id, id, repo.as_deref(), &h, &who)?;
                if in_flight && status != "done" && !authz::allows_in_flight(&auth) {
                    let err = UaError::denied(
                        "policy_authorization_mismatch",
                        format!(
                            "policy authorization {auth_id} does not cover merging task {id} while it is {status}; \
                             record one with allow_in_flight=true"
                        ),
                    );
                    return Err(authz::refuse_mode(tx, &org3, &who, auth_id, id, Some(&auth), "in_flight", err));
                }
                continuity::require_review_at_head(tx, &org3, id, &h)?;
                if dry { Ok(None) } else { authz::consume(tx, &org3, &auth, auth_id, id, &h, &who).map(Some) }
            })
            .await?;
        spent = stamp.map(|s| (auth_id, s));
        report["policy_authorization_id"] = json!(auth_id);
    }
    if a.dry_run {
        report["dry_run"] = json!(true);
        return Ok(report);
    }

    let merge_result = run_merge(&top, target, id, &row.title, &head).await;
    let commit_hash = match merge_result {
        Ok(c) => c,
        Err(e) => {
            if let Some((auth_id, stamp)) = spent {
                let (h, who, why, org4) =
                    (head.clone(), ctx.caller.label.clone(), e.to_string(), org.clone());
                let restored = ctx
                    .hub
                    .db()
                    .write_async(move |tx| authz::restore(tx, &org4, auth_id, &h, &who, &stamp, &why))
                    .await;
                if let Err(re) = restored {
                    tracing::warn!(auth_id, error = %re, "could not restore a policy authorization after a failed merge");
                }
            }
            return Err(e);
        }
    };
    let short: String = commit_hash.chars().take(12).collect();

    // Cleanup: only when the source did not move after the checks.
    let mut cleanup_skipped: Option<String> = None;
    let mut branch_retained: Option<String> = None;
    let tip_now = rev_parse(&top, &format!("refs/heads/{branch}^{{commit}}")).await?;
    if tip_now.as_deref() != Some(head.as_str()) {
        cleanup_skipped = Some("source changed after admission".into());
    } else {
        if let Some(wt) = &worktree {
            let wt_s = wt.to_string_lossy().into_owned();
            let mut args = vec!["worktree", "remove"];
            if a.force {
                args.push("--force");
            }
            args.push(&wt_s);
            let rm = git(&args, &top).await?;
            if rm.exit_code != 0 {
                cleanup_skipped = Some(format!("source worktree retained: {}", text(&rm.stderr).trim()));
            }
        }
        if cleanup_skipped.is_none() {
            let refname = format!("refs/heads/{branch}");
            let del = git(&["update-ref", "-d", &refname, &head], &top).await?;
            if del.exit_code != 0 {
                branch_retained = Some("expected-SHA deletion refused".into());
            }
        }
    }

    record(
        &ctx,
        "agent.git.merged",
        json!({
            "task_id": id,
            "branch": branch,
            "head": head,
            "target": target,
            "commit_hash": commit_hash,
            "cleanup_skipped": cleanup_skipped,
            "branch_retained": branch_retained,
        }),
    )
    .await?;

    let mut out = json!({ "success": true, "commit_hash": short, "task_id": id, "branch": branch });
    if let Some(s) = cleanup_skipped {
        out["cleanup_skipped"] = json!(s);
    }
    if let Some(s) = branch_retained {
        out["branch_retained"] = json!(s);
    }
    Ok(out)
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "git_diff_staged",
            "Staged changes of a workspace repository. Returns {staged_files: [{file, status}], diff_text, is_clean}.",
            git_diff_staged,
        )
        .family("workspace")
        .read_only(),
    );
    r.add(
        tool(
            "git_commit_staged",
            "Commit staged changes with a Conventional Commits message ('<type>(<scope>)?!?: <description>', \
             header max 100 chars, blank line before any body). Returns {commit_hash, summary, stdout}.",
            git_commit_staged,
        )
        .family("workspace"),
    );
    r.add(
        tool(
            "git_worktree_list",
            "List the worktrees of a workspace repository. Returns {worktrees: [{path, head, branch, bare}]}.",
            git_worktree_list,
        )
        .family("workspace")
        .read_only(),
    );
    r.add(
        tool(
            "git_worktree_add",
            "Create a worktree at a path inside the workspace on a branch (created from HEAD when missing). \
             Returns {path, branch, stdout}.",
            git_worktree_add,
        )
        .family("workspace"),
    );
    r.add(
        tool(
            "git_worktree_remove",
            "Remove a worktree inside the workspace; force=true discards its changes. Returns {path, deleted, stdout}.",
            git_worktree_remove,
        )
        .family("workspace"),
    );
    r.add(
        tool(
            "git_merge_task",
            "Merge a task's recorded branch into main of the workspace repository after checking the task \
             status, a clean worktree, and (when `review` is in the task's `expected_checks`) a passing, \
             uncontradicted `review` check at the exact head being merged (refusing a self-review by the commit \
             deliverable revision's producer; not bypassed by `force`), then remove the worktree and delete the \
             branch (expected-SHA). dry_run=true checks every gate and reports without merging. Always needs a \
             one-time human approval, bound to the head, branch, target branch and bound repository resolved at \
             the call (a later commit or a rebound project needs a new one: approval_binding_changed), or \
             policy_authorization_id: a human's policy authorization for exactly this task, its project's bound \
             repository and the head being merged (spent only by a successful merge; force is refused on that \
             path). Returns {success, commit_hash, task_id, branch} plus cleanup_skipped / branch_retained when \
             the source was kept.",
            git_merge_task,
        )
        .family("workspace")
        .always_gated()
        .gates_in_handler(),
    );
}
