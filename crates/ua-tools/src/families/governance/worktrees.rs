//! `cleanup_stale_worktrees`: find stale task worktrees under the workspace's
//! `.worktrees/` and remove the ones whose removal destroys nothing.
//!
//! - **Stale** (policy): the worktree's task (`task-<id>...` folder name) is
//!   `done`, or no longer exists (`orphaned_task`), or nothing touched the
//!   worktree for `max_idle_days` (at least 1; the newest of the directory's
//!   and its gitdir's `index`, `HEAD` and reflog mtimes). A `blocked` task is
//!   paused work, not finished work: only the idle threshold makes its
//!   worktree stale. A live claim on the task, a deploy checkout
//!   (`release-*`, `rollback-*`) and a worktree a running process works in
//!   are never stale.
//! - **Disposable** (safety): no uncommitted changes, no untracked files and
//!   no ignored files (`git status --porcelain --ignored`; `git worktree
//!   remove` deletes ignored files such as a local `.env` without asking, so
//!   any ignored path, build output included, keeps the worktree), and the
//!   base branch (`main`, else `master`) already contains everything on the
//!   branch (merging `HEAD` into the base would not change the base's tree;
//!   this also recognizes squash merges). Anything that cannot be
//!   established keeps the worktree.
//!
//! `dry_run` defaults to true: the call reports candidates and changes
//! nothing, and any caller may run it. A removal (`dry_run=false`) needs a
//! verified human identity or a lifecycle operator. Each stale candidate is
//! re-checked (in use, then disposable) and removed with `git worktree
//! remove` without `--force`, so git itself refuses a worktree that is dirty
//! or locked. A stale but non-disposable worktree is reported under
//! `retained` with the reason. Nothing is ever deleted any other way.
//!
//! "In use" comes from the process table ([`super::procscan`]): the working
//! directory, executable and absolute command-line arguments of every
//! process, read from `/proc` on Linux and through `proc_pidinfo`,
//! `proc_pidpath` and `KERN_PROCARGS2` on macOS. Where the table cannot be
//! read liveness is unknown and every candidate is kept. A process with this
//! hub's own credentials that hides its working directory (a non-dumpable
//! daemon such as an SSH agent) is listed under `unreadable_processes`
//! rather than making liveness unknown: removal still needs a clean, merged
//! worktree and never forces.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use super::procscan::{Live, live_process_paths};
use crate::families::workspace::{RunOutput, git_env, run_program, sandbox};
use crate::registry::{Registry, ToolCtx, blocking, tool};

const MAX_NEST_DEPTH: usize = 5;
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_CAP: usize = 1024 * 1024;
const DEPLOY_PREFIXES: [&str; 2] = ["release-", "rollback-"];
/// The smallest idle threshold a sweep accepts, in days.
const MIN_IDLE_DAYS: f64 = 1.0;
const ACTIVITY_FILES: [&str; 6] = ["index", "HEAD", "logs/HEAD", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD"];

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CleanupArgs {
    /// Idle threshold in days (default 7, at least 1).
    pub max_idle_days: Option<f64>,
    /// Report candidates without removing anything (default true).
    pub dry_run: Option<bool>,
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "cleanup_stale_worktrees",
            "Find stale task worktrees under the workspace's .worktrees/ (task done or deleted, or idle for \
             max_idle_days, default 7, at least 1) and, with dry_run=false, remove the ones whose removal \
             destroys nothing: no uncommitted changes, no untracked or ignored files (a local .env, build \
             output) and the base branch already contains the branch. Removal is `git worktree remove` without \
             --force and needs a human identity or a lifecycle operator; a worktree with uncommitted changes, \
             untracked or ignored files, unmerged commits, a live claim, or a process using it is retained and \
             reported. dry_run defaults to true. Returns {cleaned_count, stale_worktrees, skipped, retained, failed, dry_run, liveness_unknown}.",
            cleanup_stale_worktrees,
        )
        .family("workspace"),
    );
}

/// A `task-<id>` folder's task id.
fn task_id_from_folder(name: &str) -> Option<i64> {
    name.strip_prefix("task-")?.split('-').next()?.parse().ok()
}

/// Candidate directories under `base`, descending into nested `.worktrees`.
fn worktree_dirs(base: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_NEST_DEPTH {
        return;
    }
    let Ok(rd) = std::fs::read_dir(base) else { return };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for item in entries {
        let Ok(meta) = std::fs::symlink_metadata(&item) else { continue };
        if !meta.is_dir() {
            continue;
        }
        out.push(item.clone());
        let nested = item.join(".worktrees");
        if std::fs::symlink_metadata(&nested).is_ok_and(|m| m.is_dir()) {
            worktree_dirs(&nested, depth + 1, out);
        }
    }
}

/// The gitdir of a worktree root: `.git` itself, or where a `.git` file points.
fn git_dir(item: &Path) -> Option<PathBuf> {
    let dotgit = item.join(".git");
    if dotgit.is_dir() {
        return Some(dotgit);
    }
    let text = std::fs::read_to_string(&dotgit).ok()?;
    let target = text.lines().find_map(|l| l.strip_prefix("gitdir:"))?.trim();
    let p = PathBuf::from(target);
    Some(if p.is_absolute() { p } else { item.join(p) })
}

/// Newest mtime of the worktree root and its gitdir's activity files.
fn last_activity(item: &Path) -> SystemTime {
    let Ok(mut newest) = std::fs::metadata(item).and_then(|m| m.modified()) else {
        return SystemTime::now();
    };
    if let Some(gd) = git_dir(item) {
        for f in ACTIVITY_FILES {
            if let Ok(t) = std::fs::metadata(gd.join(f)).and_then(|m| m.modified()) {
                newest = newest.max(t);
            }
        }
    }
    newest
}

/// Whether a running process uses `item`; `None` when unknown.
fn in_use(item: &Path, live: Option<&Live>) -> Option<bool> {
    let live = &live?.paths;
    let mut roots = vec![item.to_path_buf()];
    if let Ok(c) = item.canonicalize() {
        roots.push(c);
    }
    Some(live.iter().any(|p| roots.iter().any(|r| p.starts_with(r))))
}

/// A task's row as the staleness policy needs it.
struct TaskRow {
    status: String,
    claimed_by: Option<String>,
    lock_expires_at: Option<String>,
}

/// `(task_id, stale, reason)`.
fn staleness(
    item: &Path,
    tasks: &std::collections::HashMap<i64, TaskRow>,
    cutoff: SystemTime,
    live: Option<&Live>,
) -> (Option<i64>, bool, Option<&'static str>) {
    let name = item.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let task_id = task_id_from_folder(&name);
    if DEPLOY_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return (task_id, false, Some("deploy_checkout"));
    }
    let used = in_use(item, live);
    let mut idle = last_activity(item) < cutoff;
    let mut live_reason = None;
    if idle && used != Some(false) {
        idle = false;
        live_reason = Some(if used == Some(true) { "in_use" } else { "liveness_unknown" });
    }
    match task_id {
        Some(id) => match tasks.get(&id) {
            Some(t) => {
                let now = ua_core::time::now();
                if t.claimed_by.is_some()
                    && t.lock_expires_at.as_deref().is_some_and(|l| !crate::families::tasks::ts_le(l, &now))
                {
                    return (task_id, false, Some("active_claim"));
                }
                match t.status.as_str() {
                    "done" => (task_id, true, Some("task_done")),
                    _ if idle => (task_id, true, Some("idle_timeout")),
                    _ => (task_id, false, live_reason),
                }
            }
            None => (task_id, true, Some("orphaned_task")),
        },
        None if idle => (None, true, Some("idle_timeout")),
        None => (None, false, live_reason),
    }
}

async fn git(dir: &Path, args: &[&str]) -> Option<RunOutput> {
    let mut env = git_env();
    env.push(("GIT_OPTIONAL_LOCKS".into(), "0".into()));
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run_program("git", &args, dir, &env, GIT_TIMEOUT, GIT_CAP).await.ok().filter(|o| !o.timed_out)
}

fn out_text(o: &RunOutput) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// Why `git status --porcelain --ignored` output keeps a worktree: tracked
/// changes first, then untracked files, then ignored files. `None` when the
/// output is empty.
fn status_blocker(porcelain: &str) -> Option<&'static str> {
    let lines: Vec<&str> = porcelain.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        None
    } else if lines.iter().any(|l| !l.starts_with("??") && !l.starts_with("!!")) {
        Some("uncommitted_changes")
    } else if lines.iter().any(|l| l.starts_with("??")) {
        Some("untracked_files")
    } else {
        Some("ignored_files")
    }
}

/// `(true, "")` when removing `path` destroys nothing, else `(false, reason)`.
async fn disposable(path: &Path) -> (bool, &'static str) {
    // `--ignored`: `git worktree remove` deletes ignored files without
    // asking, so an ignored `.env` or local config is work to keep too.
    let Some(status) = git(path, &["--no-optional-locks", "status", "--porcelain", "--ignored"]).await else {
        return (false, "git_status_unavailable");
    };
    if status.exit_code != 0 {
        return (false, "git_status_unavailable");
    }
    if let Some(why) = status_blocker(&out_text(&status)) {
        return (false, why);
    }
    let mut base = None;
    for candidate in ["main", "master"] {
        let r = format!("refs/heads/{candidate}");
        if git(path, &["rev-parse", "--verify", "--quiet", &r]).await.is_some_and(|o| o.exit_code == 0) {
            base = Some(candidate);
            break;
        }
    }
    let Some(base) = base else { return (false, "no_base_branch") };
    // Would merging HEAD into the base change the base's tree?
    if let Some(merged) = git(path, &["merge-tree", "--write-tree", base, "HEAD"]).await {
        if merged.exit_code == 1 {
            return (false, "conflicts_with_base");
        }
        if merged.exit_code == 0 {
            let tree = out_text(&merged).lines().next().unwrap_or("").trim().to_string();
            let base_tree = format!("{base}^{{tree}}");
            if let Some(bt) = git(path, &["rev-parse", &base_tree]).await.filter(|o| o.exit_code == 0)
                && !tree.is_empty()
            {
                return if tree == out_text(&bt) { (true, "") } else { (false, "unmerged_content") };
            }
        }
    }
    // Fallback for a git without `merge-tree --write-tree`.
    let range = format!("{base}..HEAD");
    match git(path, &["diff", "--quiet", &range]).await.map(|o| o.exit_code) {
        Some(0) => (true, ""),
        Some(1) => (false, "unmerged_content"),
        _ => (false, "git_diff_unavailable"),
    }
}

/// The repository directory a worktree under `<repo>/.worktrees/` belongs to.
fn owning_repo(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    (parent.file_name()? == ".worktrees").then(|| parent.parent().map(Path::to_path_buf))?
}

async fn cleanup_stale_worktrees(ctx: ToolCtx, a: CleanupArgs) -> UaResult<Value> {
    let days = a.max_idle_days.unwrap_or(7.0);
    if !days.is_finite() || days < MIN_IDLE_DAYS {
        return Err(UaError::invalid(format!("max_idle_days must be a number of at least {MIN_IDLE_DAYS}")));
    }
    let dry_run = a.dry_run.unwrap_or(true);
    if !dry_run {
        let who = super::verified_actor(&ctx.caller, "removing worktrees (dry_run=false)")?;
        if !super::is_operator(ctx.hub.cfg(), &ctx.caller, &who) {
            return Err(UaError::denied(
                "not_lifecycle_operator",
                format!(
                    "{who:?} may not remove worktrees: dry_run=false needs a human identity or a lifecycle \
                     operator (lifecycle_operators). A dry run is open to any caller."
                ),
            ));
        }
    }
    let sb = sandbox(&ctx)?;
    let root = sb.root.clone();
    let tasks = ctx
        .hub
        .db()
        .read_async(|c| {
            let mut stmt = c.prepare("SELECT id, status, claimed_by, lock_expires_at FROM tasks")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        TaskRow { status: r.get(1)?, claimed_by: r.get(2)?, lock_expires_at: r.get(3)? },
                    ))
                })?
                .collect::<Result<std::collections::HashMap<_, _>, _>>()?;
            Ok(rows)
        })
        .await?;
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs_f64(days * 86_400.0))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let root2 = root.clone();
    let (mut candidates, skipped, live) = blocking(move || {
        let live = live_process_paths();
        let mut dirs = Vec::new();
        worktree_dirs(&root2.join(".worktrees"), 0, &mut dirs);
        let mut candidates = Vec::new();
        let mut skipped = Vec::new();
        for item in dirs {
            let rel = item.strip_prefix(&root2).unwrap_or(&item).to_string_lossy().into_owned();
            if !item.join(".git").exists() {
                skipped.push(json!({ "path": rel, "reason": "not_a_git_worktree" }));
                continue;
            }
            let (task_id, stale, reason) = staleness(&item, &tasks, cutoff, live.as_ref());
            if stale {
                let modified: jiff::Timestamp = jiff::Timestamp::try_from(last_activity(&item))
                    .unwrap_or_else(|_| jiff::Timestamp::now());
                candidates.push((
                    item.clone(),
                    json!({
                        "path": rel,
                        "task_id": task_id,
                        "reason": reason,
                        "last_modified": ua_core::time::format_ts(modified),
                        "in_use": in_use(&item, live.as_ref()),
                    }),
                ));
            }
        }
        Ok((candidates, skipped, live))
    })
    .await?;
    // Children before parents: removing a parent would take a nested one with it.
    candidates.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
    let mut liveness_unknown = live.is_none();
    let unreadable = live.as_ref().map(|l| l.unreadable.clone()).unwrap_or_default();

    let mut cleaned = Vec::new();
    let mut retained = Vec::new();
    let mut failed = Vec::new();
    if !dry_run {
        for (path, cand) in &candidates {
            let p2 = path.clone();
            let now_used = blocking(move || Ok(in_use(&p2, live_process_paths().as_ref()))).await?;
            if now_used.is_none() {
                liveness_unknown = true;
            }
            let keep = |why: &str| {
                let mut c = cand.clone();
                c["retained_because"] = json!(why);
                c
            };
            if cand["in_use"].is_null() || now_used.is_none() {
                retained.push(keep("liveness_unknown"));
                continue;
            }
            if cand["in_use"] == json!(true) || now_used == Some(true) {
                retained.push(keep("in_use"));
                continue;
            }
            let (ok, why) = disposable(path).await;
            if !ok {
                retained.push(keep(why));
                continue;
            }
            let Some(repo) = owning_repo(path) else {
                failed.push(json!({ "path": cand["path"], "error": "no owning repository" }));
                continue;
            };
            let target = path.to_string_lossy().into_owned();
            match git(&repo, &["worktree", "remove", &target]).await {
                Some(o) if o.exit_code == 0 => cleaned.push(cand["path"].clone()),
                Some(o) => failed.push(json!({
                    "path": cand["path"],
                    "error": String::from_utf8_lossy(&o.stderr).trim().chars().take(300).collect::<String>(),
                })),
                None => failed.push(json!({ "path": cand["path"], "error": "git could not be run" })),
            }
        }
        if !cleaned.is_empty() || !retained.is_empty() || !failed.is_empty() {
            let by = ctx.caller.label.clone();
            let payload = json!({
                "removed": cleaned,
                "retained": retained.iter().map(|r| json!({ "path": r["path"], "why": r["retained_because"] })).collect::<Vec<_>>(),
                "failed": failed.len(),
                "max_idle_days": days,
            });
            ctx.hub
                .db()
                .write_async(move |tx| {
                    ledger::append(tx, EventInput::new("agent.git.worktrees_cleaned", payload).by(by))?;
                    Ok(())
                })
                .await?;
        }
    }

    let mut out = json!({
        "cleaned_count": cleaned.len(),
        "cleaned": cleaned,
        "stale_worktrees": candidates.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
        "skipped": skipped,
        "retained": retained,
        "failed": failed,
        "dry_run": dry_run,
        "liveness_unknown": liveness_unknown,
        "unreadable_processes": unreadable,
    });
    if liveness_unknown {
        out["note"] = json!(
            "running processes could not be listed on this host, so every candidate is kept (liveness_unknown)"
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_folders_name_their_task() {
        assert_eq!(task_id_from_folder("task-42"), Some(42));
        assert_eq!(task_id_from_folder("task-42-fix-the-build"), Some(42));
        assert_eq!(task_id_from_folder("release-42"), None);
        assert_eq!(task_id_from_folder("task-x"), None);
    }

    #[test]
    fn untracked_and_ignored_files_keep_a_worktree() {
        assert_eq!(status_blocker(""), None);
        assert_eq!(status_blocker(" M a.rs\n?? b\n!! .env"), Some("uncommitted_changes"));
        assert_eq!(status_blocker("?? b\n!! .env"), Some("untracked_files"));
        assert_eq!(status_blocker("!! .env"), Some("ignored_files"));
    }

    #[test]
    fn a_worktree_belongs_to_the_repo_above_its_worktrees_dir() {
        assert_eq!(owning_repo(Path::new("/w/repo/.worktrees/task-1")), Some(PathBuf::from("/w/repo")));
        assert_eq!(owning_repo(Path::new("/w/repo/other/task-1")), None);
    }
}
