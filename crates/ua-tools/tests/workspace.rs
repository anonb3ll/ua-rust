//! Workspace family: sandboxed files, allowlisted commands and git, all
//! called through the governed registry path.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

struct Env {
    _home: tempfile::TempDir,
    _ws: tempfile::TempDir,
    _extra: tempfile::TempDir,
    ws: PathBuf,
    extra: PathBuf,
    hub: Hub,
    reg: Registry,
}

fn setup_with(tweak: impl FnOnce(&mut Config)) -> Env {
    let home = tempfile::tempdir().unwrap();
    let ws_dir = tempfile::tempdir().unwrap();
    let extra_dir = tempfile::tempdir().unwrap();
    let ws = ws_dir.path().canonicalize().unwrap();
    let extra = extra_dir.path().canonicalize().unwrap();
    let mut cfg = Config::for_home(home.path());
    cfg.workspace = Some(ws.clone());
    cfg.read_roots = vec![extra.clone()];
    cfg.human_identities = vec!["operator".into()];
    tweak(&mut cfg);
    let hub = Hub::in_memory(cfg).unwrap();
    Env { _home: home, _ws: ws_dir, _extra: extra_dir, ws, extra, hub, reg: builtin_registry() }
}

fn setup() -> Env {
    setup_with(|_| {})
}

fn agent(label: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

fn human() -> Caller {
    Caller { kind: ActorKind::Human, profile: Profile::Operator, ..agent("operator", Profile::Operator) }
}

impl Env {
    async fn call(&self, tool: &str, args: Value) -> Result<Value, UaError> {
        // Coordinator sees every tool, including git_commit_staged and git_merge_task.
        self.reg.call(&self.hub, &agent("builder-1", Profile::Coordinator), tool, args).await
    }

    async fn ok(&self, tool: &str, args: Value) -> Value {
        self.call(tool, args.clone()).await.unwrap_or_else(|e| panic!("{tool} {args}: {e}"))
    }

    async fn approve_pending(&self, tool: &str) {
        let pending =
            self.reg.call(&self.hub, &human(), "approval_pending", json!({ "tool": tool })).await.unwrap();
        let id = pending["pending"][0]["id"].as_i64().expect("a pending approval");
        self.reg
            .call(&self.hub, &human(), "approval_resolve", json!({ "id": id, "decision": "approve" }))
            .await
            .unwrap();
    }

    async fn events(&self, channel: &str) -> Vec<Value> {
        let out = self
            .reg
            .call(&self.hub, &human(), "event_log_query", json!({ "channels": [channel] }))
            .await
            .unwrap();
        out["events"].as_array().cloned().unwrap_or_default()
    }
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    }
}

#[tokio::test]
async fn read_write_list_search() {
    let env = setup();
    let w = env.ok("fs_write", json!({ "path": "src/notes.txt", "content": "alpha\nbeta\ngamma\n" })).await;
    assert_eq!(w["bytes_written"], 17);
    env.ok("fs_write", json!({ "path": "src/notes.txt", "content": "delta\n", "append": true })).await;

    let r = env.ok("fs_read", json!({ "path": "src/notes.txt", "offset": 1, "limit": 2 })).await;
    assert_eq!(r["content"], "beta\ngamma");
    assert_eq!(r["total_lines"], 4);
    assert_eq!(r["truncated"], true);

    // Conditional replace: wrong hash conflicts, the right one succeeds.
    let bad = env
        .call("fs_write", json!({ "path": "src/notes.txt", "content": "x", "expected_content_hash": "" }))
        .await
        .unwrap_err();
    assert_eq!(bad.code(), "conflict");

    // Credential-looking files are refused for writes as well as reads.
    for name in [".env", "deploy.pem", "credentials.json", "secrets/id_ed25519"] {
        let err = env.call("fs_write", json!({ "path": name, "content": "x" })).await.unwrap_err();
        assert_eq!(err.code(), "denied", "{name}: {err}");
    }

    std::fs::write(env.ws.join("src/lib.rs"), "fn main() {}\n").unwrap();
    std::fs::write(env.ws.join(".env"), "SECRET=placeholder\n").unwrap();
    let list = env.ok("fs_list", json!({})).await;
    let names: Vec<&str> =
        list["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["src"], "the .env file is hidden from listings");
    let list = env.ok("fs_list", json!({ "path": "src", "glob": "*.txt" })).await;
    assert_eq!(list["entries"][0]["name"], "notes.txt");
    assert_eq!(list["entries"][0]["size"], 23);
    let list = env.ok("fs_list", json!({ "glob": "**/*.rs" })).await;
    assert_eq!(list["entries"][0]["name"], "lib.rs");
    assert!(env.call("fs_list", json!({ "glob": "../*" })).await.is_err());

    let s = env.ok("fs_search", json!({ "pattern": "^(beta|fn)" })).await;
    let hits: Vec<(String, i64)> = s["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| (m["path"].as_str().unwrap().to_string(), m["line_no"].as_i64().unwrap()))
        .collect();
    assert_eq!(hits, [("src/lib.rs".to_string(), 1), ("src/notes.txt".to_string(), 2)]);
    let s = env.ok("fs_search", json!({ "pattern": "a", "glob": "*.rs", "max_results": 1 })).await;
    assert_eq!(s["matches"].as_array().unwrap().len(), 1);
    assert!(env.call("fs_search", json!({ "pattern": "(" })).await.is_err());
    let s = env.ok("fs_search", json!({ "pattern": "SECRET" })).await;
    assert_eq!(s["matches"].as_array().unwrap().len(), 0, "secret files are not searched");

    // gitignore-aware walking.
    std::fs::write(env.ws.join(".gitignore"), "ignored/\n").unwrap();
    std::fs::create_dir_all(env.ws.join("ignored")).unwrap();
    std::fs::write(env.ws.join("ignored/x.txt"), "beta\n").unwrap();
    let s = env.ok("fs_search", json!({ "pattern": "^beta" })).await;
    assert_eq!(s["matches"].as_array().unwrap().len(), 1);

    // Ledger: relative path and a hash, never the content.
    let ev = env.events("agent.fs.written").await;
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0]["payload"]["path"], "src/notes.txt");
    assert!(ev[0]["payload"]["content_sha256"].is_string());
    assert!(!ev[0]["payload"].to_string().contains("alpha"));
}

#[tokio::test]
async fn sandbox_escapes_are_refused() {
    let env = setup();
    std::fs::write(env.extra.join("shared.md"), "shared\n").unwrap();
    std::fs::write(env.ws.join(".env"), "X=1\n").unwrap();

    for path in ["../outside.txt", "/etc/hostname"] {
        let e = env.call("fs_read", json!({ "path": path })).await.unwrap_err();
        assert_eq!(e.code(), "denied", "{path}");
        assert!(env.call("fs_write", json!({ "path": path, "content": "x" })).await.is_err(), "{path}");
    }
    let e = env.call("fs_read", json!({ "path": ".env" })).await.unwrap_err();
    assert_eq!(reason(&e), "secret_file");
    let e = env
        .call("fs_write", json!({ "path": ".git/hooks/pre-commit", "content": "#!/bin/sh" }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "hook_dir");
    let e = env.call("fs_write", json!({ "path": ".Husky/pre-commit", "content": "x" })).await.unwrap_err();
    assert_eq!(reason(&e), "hook_dir");

    // An absolute path into a read root reads; a relative one never reaches it; writes never do.
    let abs = env.extra.join("shared.md");
    let r = env.ok("fs_read", json!({ "path": abs.to_str().unwrap() })).await;
    assert_eq!(r["content"], "shared");
    let name = env.extra.file_name().unwrap().to_str().unwrap();
    assert!(env.call("fs_read", json!({ "path": format!("../{name}/shared.md") })).await.is_err());
    assert!(env.call("fs_write", json!({ "path": abs.to_str().unwrap(), "content": "x" })).await.is_err());

    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("f.txt"), "outside\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), env.ws.join("link")).unwrap();
        assert_eq!(env.call("fs_read", json!({ "path": "link/f.txt" })).await.unwrap_err().code(), "denied");
        assert!(env.call("fs_write", json!({ "path": "link/new.txt", "content": "x" })).await.is_err());
        let list = env.ok("fs_list", json!({})).await;
        assert!(list["entries"].as_array().unwrap().iter().all(|e| e["name"] != "link"));
        let s = env.ok("fs_search", json!({ "pattern": "outside" })).await;
        assert_eq!(s["matches"].as_array().unwrap().len(), 0);
    }
}

#[tokio::test]
async fn denied_agent_workspace() {
    let env = setup_with(|c| {
        c.agent_workspaces.insert("builder-1".into(), "DENY".into());
    });
    for (tool, args) in [
        ("fs_read", json!({ "path": "x" })),
        ("fs_list", json!({})),
        ("run_cmd", json!({ "command": "echo hi" })),
        ("git_worktree_list", json!({})),
    ] {
        let e = env.call(tool, args).await.unwrap_err();
        assert_eq!(reason(&e), "workspace_denied", "{tool}");
    }
}

#[tokio::test]
async fn commands_are_vetted_and_bounded() {
    let env = setup_with(|c| {
        c.shell_allowlist = ["echo", "ls", "cat", "sleep", "python3", "no-such-program-xyz"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    });
    let r = env.ok("run_cmd", json!({ "command": "echo hello world" })).await;
    assert_eq!(r["exit_code"], 0);
    assert_eq!(r["stdout"], "hello world\n");
    assert_eq!(r["timed_out"], false);

    // Not allowlisted, by path, shell syntax, destructive, cwd escape.
    for (cmd, code) in [
        ("rm notes.txt", "program_not_allowed"),
        ("/bin/echo hi", "program_path"),
        ("echo hi | cat", "shell_syntax"),
        ("echo $(id)", "shell_syntax"),
    ] {
        let e = env.call("run_cmd", json!({ "command": cmd })).await.unwrap_err();
        assert_eq!(reason(&e), code, "{cmd}");
    }
    let e = env.call("run_cmd", json!({ "command": "echo hi", "cwd": ".." })).await.unwrap_err();
    assert_eq!(reason(&e), "outside_sandbox");

    // Quoted metacharacters stay literal and are flagged.
    let r = env.ok("run_cmd", json!({ "command": "echo a '|' b" })).await;
    assert_eq!(r["stdout"], "a | b\n");
    assert!(r["warnings"][0].as_str().unwrap().contains("no shell"));

    // Timeout kills the process group promptly.
    let t0 = Instant::now();
    let r = env.ok("run_cmd", json!({ "command": "sleep 30", "timeout_s": 1 })).await;
    assert_eq!(r["timed_out"], true);
    assert_eq!(r["exit_code"], -1);
    assert!(t0.elapsed().as_secs() < 10, "took {:?}", t0.elapsed());

    // Output cap: 50 KB combined, halves kept.
    std::fs::write(env.ws.join("big.txt"), "x".repeat(200 * 1024)).unwrap();
    let r = env.ok("run_cmd", json!({ "command": "cat big.txt" })).await;
    assert_eq!(r["truncated"], true);
    assert_eq!(r["stdout"].as_str().unwrap().len(), 25 * 1024);

    // Missing program reports 127 rather than failing.
    let r = env.ok("run_cmd", json!({ "command": "no-such-program-xyz" })).await;
    assert_eq!(r["exit_code"], 127);

    // A content reader aimed at a secret file is blocked.
    std::fs::write(env.ws.join("service.env"), "X=1\n").unwrap();
    let e = env.call("run_cmd", json!({ "command": "cat service.env" })).await.unwrap_err();
    assert_eq!(reason(&e), "secret-path");

    let ev = env.events("agent.cmd.ran").await;
    assert!(ev.iter().any(|e| e["payload"]["program"] == "sleep" && e["payload"]["timed_out"] == true));
}

#[tokio::test]
async fn dangerous_commands_need_approval() {
    let env = setup();
    // An argument outside the workspace forces the approval gate.
    let e = env.call("run_cmd", json!({ "command": "ls /" })).await.unwrap_err();
    assert_eq!(e.code(), "approval_required");
    env.approve_pending("run_cmd").await;
    let r = env.ok("run_cmd", json!({ "command": "ls /" })).await;
    assert_eq!(r["exit_code"], 0);
    assert!(r["warnings"][0].as_str().unwrap().contains("outside the workspace"));
    // The pass is single-use.
    assert_eq!(
        env.call("run_cmd", json!({ "command": "ls /" })).await.unwrap_err().code(),
        "approval_required"
    );
}

#[tokio::test]
async fn run_cmd_check_reports_without_running() {
    let env = setup();
    let r = env.ok("run_cmd_check", json!({ "command": "python3 build.py" })).await;
    assert_eq!(r["verdict"], "warn");
    assert_eq!(r["mutates"], "maybe");
    assert!(r["findings"].as_array().unwrap().iter().any(|f| f["code"] == "arbitrary-code"));

    let r = env.ok("run_cmd_check", json!({ "command": "rm -rf build" })).await;
    assert_eq!(r["ok"], false);
    assert_eq!(r["findings"][0]["code"], "rejected");

    let r = env.ok("run_cmd_check", json!({ "command": "git reset --hard" })).await;
    assert_eq!(r["findings"][0]["code"], "destructive");

    let r = env.ok("run_cmd_check", json!({ "command": "git frobnicate" })).await;
    assert!(r["findings"].as_array().unwrap().iter().any(|f| f["code"] == "allowlist-bypass"));

    let r = env.ok("run_cmd_check", json!({ "command": "sed -n 's/a/b/w out' f.txt" })).await;
    assert!(r["findings"].as_array().unwrap().iter().any(|f| f["code"] == "allowlist-bypass"));

    // Advisory classification, one case per heuristic.
    let codes = |r: &Value| -> Vec<String> {
        r["findings"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap().to_string()).collect()
    };
    for (cmd, code, mutates) in [
        ("sed -n 's/we/were/g' f.txt", None, "no"),
        ("sed '1e id' f.txt", Some("allowlist-bypass"), "no"),
        ("sed -i s/a/b/ f.txt", None, "yes"),
        ("awk '{print $1}' f.txt", Some("allowlist-bypass"), "maybe"),
        ("sort -o out.txt in.txt", None, "yes"),
        ("sort --compress-program=gzip in.txt", Some("allowlist-bypass"), "no"),
        ("find . -name x -fprint out", Some("allowlist-bypass"), "yes"),
        ("git config alias.x '!id'", Some("allowlist-bypass"), "maybe"),
        ("git config --get user.name", None, "maybe"),
        ("git log --oneline", None, "no"),
        ("git push origin main", Some("network"), "yes"),
        ("git --git-dir=other.git log", Some("allowlist-bypass"), "no"),
        ("cat /etc/hostname", Some("path-escape"), "no"),
        ("echo 'x' '$HOME'", Some("no-expansion"), "no"),
        ("python3 --version", None, "maybe"),
    ] {
        let r = env.ok("run_cmd_check", json!({ "command": cmd })).await;
        let got = codes(&r);
        match code {
            Some(c) => assert!(got.iter().any(|g| g == c), "{cmd}: {got:?}"),
            None => assert!(got.iter().all(|g| g == "not-found"), "{cmd}: {got:?}"),
        }
        assert_eq!(r["mutates"], mutates, "{cmd}");
    }

    let r = env.ok("run_cmd_check", json!({ "command": "ls -la", "cwd": "../" })).await;
    assert_eq!(r["verdict"], "block");
    assert!(r["findings"].as_array().unwrap().iter().any(|f| f["code"] == "cwd"));

    let r = env.ok("run_cmd_check", json!({ "command": "echo ok" })).await;
    assert_eq!(r["verdict"], "ok");
    assert_eq!(r["argv"], json!(["echo", "ok"]));
    assert!(env.events("agent.cmd.ran").await.is_empty(), "run_cmd_check runs nothing");
}

// ---- git ----

fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_repo(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main"]);
    for (k, v) in [
        ("user.name", "builder-1"),
        ("user.email", "builder-1@example.com"),
        ("commit.gpgsign", "false"),
        ("core.hooksPath", "/dev/null"),
    ] {
        git(dir, &["config", k, v]);
    }
    std::fs::write(dir.join("README.md"), "readme\n").unwrap();
    git(dir, &["add", "README.md"]);
    git(dir, &["commit", "-q", "-m", "chore: initial commit"]);
}

#[tokio::test]
async fn git_diff_commit_and_worktrees() {
    if !have_git() {
        eprintln!("git not installed; skipping");
        return;
    }
    let env = setup();
    init_repo(&env.ws);

    env.ok("fs_write", json!({ "path": "new.txt", "content": "new\n" })).await;
    env.ok("run_cmd", json!({ "command": "git add new.txt" })).await;
    let d = env.ok("git_diff_staged", json!({})).await;
    assert_eq!(d["staged_files"], json!([{ "file": "new.txt", "status": "A" }]));
    assert!(d["diff_text"].as_str().unwrap().contains("+new"));
    assert_eq!(d["is_clean"], false);

    for bad in ["add file", "feat: x\nbody without blank line", "feat:missing space"] {
        let e = env.call("git_commit_staged", json!({ "message": bad })).await.unwrap_err();
        assert_eq!(e.code(), "invalid_argument", "{bad:?}");
    }
    let c = env
        .ok("git_commit_staged", json!({ "message": "feat(files): add new file\n\nWhy it exists." }))
        .await;
    assert_eq!(c["summary"], "feat(files): add new file");
    assert!(!c["commit_hash"].as_str().unwrap().is_empty());
    assert_eq!(env.ok("git_diff_staged", json!({})).await["is_clean"], true);

    let bad = env.call("git_worktree_add", json!({ "path": ".worktrees/x", "branch": "-evil" })).await;
    assert_eq!(bad.unwrap_err().code(), "invalid_argument");
    let bad = env.call("git_worktree_add", json!({ "path": "../elsewhere", "branch": "task-1" })).await;
    assert_eq!(bad.unwrap_err().code(), "denied");

    let a = env.ok("git_worktree_add", json!({ "path": ".worktrees/task-1", "branch": "task-1" })).await;
    assert_eq!(a["branch"], "task-1");
    assert!(env.ws.join(".worktrees/task-1/README.md").exists());
    let l = env.ok("git_worktree_list", json!({})).await;
    let branches: Vec<&str> =
        l["worktrees"].as_array().unwrap().iter().filter_map(|w| w["branch"].as_str()).collect();
    assert_eq!(branches, ["main", "task-1"]);

    let r = env.ok("git_worktree_remove", json!({ "path": ".worktrees/task-1" })).await;
    assert_eq!(r["deleted"], true);
    assert!(!env.ws.join(".worktrees/task-1").exists());

    let channels: Vec<String> =
        ["agent.git.committed", "agent.git.worktree_added", "agent.git.worktree_removed"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    for ch in channels {
        assert_eq!(env.events(&ch).await.len(), 1, "{ch}");
    }
}

#[tokio::test]
async fn git_refuses_repositories_outside_the_workspace() {
    if !have_git() {
        eprintln!("git not installed; skipping");
        return;
    }
    let outer = tempfile::tempdir().unwrap();
    let outer_root = outer.path().canonicalize().unwrap();
    init_repo(&outer_root);
    std::fs::create_dir_all(outer_root.join("sub")).unwrap();
    let ws = outer_root.join("sub");
    let env = setup_with(|c| c.workspace = Some(ws.clone()));
    let e = env.call("git_diff_staged", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), "repo_outside_workspace");
    // Not a repository at all.
    let env = setup();
    assert_eq!(env.call("git_worktree_list", json!({})).await.unwrap_err().code(), "invalid_argument");
    // run_cmd cannot pass git config overrides either.
    let e = env.call("run_cmd", json!({ "command": "git -c core.pager=sh log" })).await.unwrap_err();
    assert_eq!(reason(&e), "git_config_override");
}

#[tokio::test]
async fn git_merge_task_parks_for_approval_then_merges() {
    if !have_git() {
        eprintln!("git not installed; skipping");
        return;
    }
    let env = setup();
    init_repo(&env.ws);
    std::fs::write(env.ws.join(".gitignore"), ".worktrees/\n").unwrap();
    git(&env.ws, &["add", ".gitignore"]);
    git(&env.ws, &["commit", "-q", "-m", "chore: ignore worktrees"]);
    env.ok("git_worktree_add", json!({ "path": ".worktrees/task-7", "branch": "task-7" })).await;
    let wt = env.ws.join(".worktrees/task-7");
    std::fs::write(wt.join("feature.txt"), "feature\n").unwrap();
    git(&wt, &["add", "feature.txt"]);
    git(&wt, &["commit", "-q", "-m", "feat: add feature"]);

    let task_id = env
        .hub
        .db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO tasks (title, status, branch, worktree_path, created_at, updated_at) \
                 VALUES ('Add feature', 'done', 'task-7', '.worktrees/task-7', ?1, ?1)",
                [ua_core::time::now()],
            )?;
            Ok(tx.last_insert_rowid())
        })
        .unwrap();

    // Developer sessions do not see git_merge_task at all.
    let dev = agent("builder-1", Profile::Developer);
    let e = env.reg.call(&env.hub, &dev, "git_merge_task", json!({ "task_id": task_id })).await.unwrap_err();
    assert_eq!(reason(&e), "profile_denied");

    // Always gated, even for a dry run and with no approval_tools configured.
    let dry = json!({ "task_id": task_id, "dry_run": true });
    assert_eq!(env.call("git_merge_task", dry.clone()).await.unwrap_err().code(), "approval_required");
    env.approve_pending("git_merge_task").await;
    let r = env.ok("git_merge_task", dry).await;
    assert_eq!(r["dry_run"], true);
    assert_eq!(r["worktree_clean"], true);
    assert!(!env.ws.join("feature.txt").exists(), "a dry run merges nothing");

    let real = json!({ "task_id": task_id });
    assert_eq!(env.call("git_merge_task", real.clone()).await.unwrap_err().code(), "approval_required");
    env.approve_pending("git_merge_task").await;
    let r = env.ok("git_merge_task", real).await;
    assert_eq!(r["success"], true);
    assert_eq!(r["branch"], "task-7");
    assert!(r.get("cleanup_skipped").is_none(), "{r}");
    assert!(env.ws.join("feature.txt").exists());
    assert!(!wt.exists(), "the task worktree is removed");
    let branches = git(&env.ws, &["branch", "--list", "task-7"]);
    assert!(branches.is_empty(), "the merged branch is deleted");
    assert_eq!(env.events("agent.git.merged").await.len(), 1);

    // Unknown task: parks first, then reports not found once approved.
    let missing = json!({ "task_id": 9999 });
    assert_eq!(env.call("git_merge_task", missing.clone()).await.unwrap_err().code(), "approval_required");
    env.approve_pending("git_merge_task").await;
    assert_eq!(env.call("git_merge_task", missing).await.unwrap_err().code(), "not_found");
}

/// `run_cmd` runs with an empty per-call HOME. git still needs an identity
/// to commit; the hub supplies one from the caller's label.
#[tokio::test]
async fn run_cmd_git_commit_works_in_a_fresh_workspace() {
    if !have_git() {
        eprintln!("git not installed; skipping");
        return;
    }
    let env = setup();
    let run = async |command: &str| -> Value {
        let args = json!({ "command": command });
        match env.call("run_cmd", args.clone()).await {
            Ok(v) => v,
            Err(e) if e.code() == "approval_required" => {
                env.approve_pending("run_cmd").await;
                env.ok("run_cmd", args).await
            }
            Err(e) => panic!("{command}: {e}"),
        }
    };
    let r = run("git init -q -b main").await;
    assert_eq!(r["exit_code"], 0, "{r}");
    let r = run("git commit --allow-empty -q -m x").await;
    assert_eq!(r["exit_code"], 0, "{r}");
    let author = git(&env.ws, &["log", "-1", "--format=%an <%ae> / %cn <%ce>"]);
    assert_eq!(author, "builder-1 <builder-1@agents.invalid> / builder-1 <builder-1@agents.invalid>");
}

/// Each caller gets its own persistent caches, and no command sees the hub
/// user's cargo or rustup home.
#[tokio::test]
async fn run_cmd_caches_are_per_caller_and_cargo_home_is_the_hubs() {
    let env = setup_with(|c| c.shell_allowlist = vec!["env".into()]);
    let vars = async |label: &str| -> std::collections::HashMap<String, String> {
        let r = env
            .reg
            .call(&env.hub, &agent(label, Profile::Coordinator), "run_cmd", json!({ "command": "env" }))
            .await
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(r["exit_code"], 0, "{r}");
        r["stdout"]
            .as_str()
            .unwrap()
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let a = vars("builder-1").await;
    let b = vars("builder-2").await;
    let cache_root = env.hub.cfg().home.join("run-cache");
    for key in ["CARGO_HOME", "XDG_CACHE_HOME", "UV_CACHE_DIR"] {
        assert_ne!(a[key], b[key], "{key} is shared between callers");
        assert!(Path::new(&a[key]).starts_with(&cache_root), "{key}={}", a[key]);
    }
    assert!(!a.contains_key("RUSTUP_HOME"));
    if let Some(real) = std::env::var_os("CARGO_HOME") {
        assert_ne!(Path::new(&a["CARGO_HOME"]), Path::new(&real));
    }
}

/// Cargo reads `.cargo/config*` in every ancestor of its cwd, so a config
/// above the workspace root would reach run_cmd's cargo: refused, with
/// the path named.
#[tokio::test]
async fn run_cmd_refuses_cargo_under_an_ancestor_cargo_config() {
    let outer = tempfile::tempdir().unwrap();
    let top = outer.path().canonicalize().unwrap();
    let ws = top.join("nested/ws");
    std::fs::create_dir_all(&ws).unwrap();
    let env = setup_with(|c| {
        c.workspace = Some(ws.clone());
        c.shell_allowlist = vec!["cargo".into(), "echo".into()];
    });
    // Nothing above the workspace yet (outside the temp dir, the host may
    // have its own; only ones under `top` are this test's).
    let ours = |p: &PathBuf| p.starts_with(&top);
    assert!(!ua_tools::families::workspace::ancestor_cargo_configs(&ws).iter().any(ours));

    let planted = top.join(".cargo/config.toml");
    std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
    std::fs::write(&planted, "[alias]\nleak = \"version\"\n").unwrap();

    let err = env.call("run_cmd", json!({ "command": "cargo leak" })).await.unwrap_err();
    match &err {
        UaError::Denied { reason_code, reason } => {
            assert_eq!(reason_code, "cargo-config");
            assert!(reason.contains(&planted.display().to_string()), "{reason}");
            assert!(reason.contains("outside that directory tree"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    let check = env.call("run_cmd_check", json!({ "command": "cargo build" })).await.unwrap();
    assert_eq!(check["verdict"], "block", "{check}");
    assert!(check["findings"].as_array().unwrap().iter().any(|f| f["code"] == "cargo-config"), "{check}");
    // Other programs are unaffected.
    let r = env.call("run_cmd", json!({ "command": "echo ok" })).await.unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    // The startup warning names the file too.
    let warning = ua_tools::families::workspace::cargo_config_warning(env.hub.cfg()).unwrap();
    assert!(warning.contains(&planted.display().to_string()), "{warning}");
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// The refusal reason of a `run_cmd` call refused for a cargo config.
async fn cargo_config_refusal(env: &Env, command: &str) -> String {
    match env.call("run_cmd", json!({ "command": command })).await {
        Err(UaError::Denied { reason_code, reason }) if reason_code == "cargo-config" => reason,
        other => panic!("expected a cargo-config refusal, got {other:?}"),
    }
}

/// An operator can let cargo read a reviewed ancestor cargo config by
/// pinning its path and SHA-256 in `trusted_cargo_configs`. An unlisted
/// config, or a listed one whose content changed, is still refused, and
/// the refusal names the setting and the file's current hash.
#[tokio::test]
async fn run_cmd_runs_cargo_under_a_trusted_ancestor_cargo_config_while_it_is_unchanged() {
    use ua_core::config::TrustedCargoConfig;
    let outer = tempfile::tempdir().unwrap();
    let top = outer.path().canonicalize().unwrap();
    let ws = top.join("nested/ws");
    std::fs::create_dir_all(&ws).unwrap();
    let planted = top.join(".cargo/config.toml");
    std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
    let content = b"[build]\nrustc-wrapper = \"sccache\"\n";
    std::fs::write(&planted, content).unwrap();
    let sha = sha256_hex(content);
    // Configs the host itself has above the temp dir are trusted as they
    // are, so only this test's file decides the outcome.
    let host: Vec<TrustedCargoConfig> = ua_tools::families::workspace::ancestor_cargo_configs(&ws)
        .into_iter()
        .filter(|p| !p.starts_with(&top))
        .map(|p| TrustedCargoConfig { sha256: sha256_hex(&std::fs::read(&p).unwrap_or_default()), path: p })
        .collect();
    let with = |trusted: Vec<TrustedCargoConfig>| {
        let (ws, host) = (ws.clone(), host.clone());
        setup_with(move |c| {
            c.workspace = Some(ws);
            c.shell_allowlist = vec!["cargo".into()];
            c.trusted_cargo_configs = host.into_iter().chain(trusted).collect();
        })
    };

    // Unlisted: refused, and the refusal says how to trust this content.
    let env = with(Vec::new());
    let reason = cargo_config_refusal(&env, "cargo --version").await;
    assert!(reason.contains(&planted.display().to_string()), "{reason}");
    assert!(reason.contains("trusted_cargo_configs"), "{reason}");
    assert!(reason.contains(&format!("sha256 = \"{sha}\"")), "{reason}");
    assert!(reason.contains("outside that directory tree"), "{reason}");
    let warning = ua_tools::families::workspace::cargo_config_warning(env.hub.cfg()).unwrap();
    assert!(warning.contains(&sha), "{warning}");

    // Listed with the matching hash (in any case): cargo runs.
    let pin = |sha256: &str| TrustedCargoConfig { path: planted.clone(), sha256: sha256.into() };
    let env = with(vec![pin(&sha.to_ascii_uppercase())]);
    let r = env.call("run_cmd", json!({ "command": "cargo --version" })).await;
    assert!(r.is_ok(), "a trusted config refused cargo: {r:?}");
    let check = env.call("run_cmd_check", json!({ "command": "cargo build" })).await.unwrap();
    assert!(!check["findings"].as_array().unwrap().iter().any(|f| f["code"] == "cargo-config"), "{check}");
    assert!(ua_tools::families::workspace::cargo_config_warning(env.hub.cfg()).is_none());

    // The file changes after it was pinned: refused again, naming both hashes.
    let changed = b"[build]\nrustc-wrapper = \"/tmp/other\"\n";
    std::fs::write(&planted, changed).unwrap();
    let now = sha256_hex(changed);
    let reason = cargo_config_refusal(&env, "cargo --version").await;
    assert!(reason.contains(&format!("sha256 = \"{now}\"")), "{reason}");
    assert!(reason.contains(&format!("changed since trusted_cargo_configs pinned sha256 {sha}")), "{reason}");
    let check = env.call("run_cmd_check", json!({ "command": "cargo build" })).await.unwrap();
    assert_eq!(check["verdict"], "block", "{check}");

    // A second, unlisted config next to the trusted one is refused too.
    std::fs::write(&planted, content).unwrap();
    let other = top.join("nested/.cargo/config");
    std::fs::create_dir_all(other.parent().unwrap()).unwrap();
    std::fs::write(&other, "").unwrap();
    let reason = cargo_config_refusal(&env, "cargo --version").await;
    assert!(reason.contains(&other.display().to_string()), "{reason}");
    assert!(!reason.contains(&planted.display().to_string()), "the trusted file is not named: {reason}");
}

#[tokio::test]
async fn allowlist_refusals_do_not_reveal_membership_to_non_operators() {
    let env = setup_with(|c| c.shell_allowlist = vec!["echo".into(), "git".into()]);
    let dev = agent("builder-2", Profile::Developer);
    // Not allowlisted, and allowlisted but refused for its arguments: the
    // same answer, which names no program.
    let mut texts = Vec::new();
    for cmd in ["rm notes.txt", "git reset --hard", "git -c core.pager=x log"] {
        let e = env.reg.call(&env.hub, &dev, "run_cmd", json!({ "command": cmd })).await.unwrap_err();
        assert_eq!(reason(&e), "command_refused", "{cmd}");
        texts.push(e.to_string());
        let r = env.reg.call(&env.hub, &dev, "run_cmd_check", json!({ "command": cmd })).await.unwrap();
        let text = r.to_string();
        assert!(
            !text.contains("not in the command allowlist") && !text.contains("destructive command"),
            "{text}"
        );
    }
    assert!(texts.windows(2).all(|w| w[0] == w[1]), "{texts:?}");
    // An operator still sees why.
    let e = env.call("run_cmd", json!({ "command": "rm notes.txt" })).await.unwrap_err();
    assert_eq!(reason(&e), "program_not_allowed");
    let e = env.call("run_cmd", json!({ "command": "git reset --hard" })).await.unwrap_err();
    assert_eq!(reason(&e), "destructive");
}
