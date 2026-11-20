//! `python_lint_and_format`: fixed ruff argv, workspace sandbox, no shell.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::families::code::lint::argv_on_allowlist;
use ua_tools::{Hub, Registry, builtin_registry};

struct Env {
    dir: tempfile::TempDir,
    workspace: PathBuf,
    /// Each fake-ruff run appends one line: its arguments, NUL-separated.
    log: PathBuf,
    /// The fake ruff's `RUFF_NO_CACHE`, one line per run.
    env_log: PathBuf,
    hub: Hub,
    reg: Registry,
}

/// A hub whose `ruff` is a fake that logs its argv (and, with `sleep`, hangs).
fn env_with(sleep: Option<u32>, tweak: impl FnOnce(&mut Config)) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let bin = dir.path().join("bin");
    let log = dir.path().join("ruff.log");
    let env_log = dir.path().join("ruff-env.log");
    install_fake_ruff(&bin, &log, &env_log, sleep);
    let mut cfg = Config::for_home(dir.path());
    cfg.workspace = Some(workspace.clone());
    cfg.python_lint_path_prepend = Some(bin);
    tweak(&mut cfg);
    Env { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), dir, workspace, log, env_log }
}

fn env() -> Env {
    env_with(None, |_| {})
}

fn caller(label: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some(format!("{label}-s1")),
        transport: Transport::Mcp,
    }
}

impl Env {
    async fn call(&self, args: Value) -> Result<Value, ua_core::UaError> {
        self.reg.call(&self.hub, &caller("builder-1", Profile::Developer), "python_lint_and_format", args).await
    }

    fn write(&self, rel: &str, body: &str) -> PathBuf {
        let p = self.workspace.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p
    }

    /// The argv of every fake-ruff run, in order.
    fn runs(&self) -> Vec<Vec<String>> {
        let bytes = std::fs::read(&self.log).unwrap_or_default();
        bytes
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                line.split(|b| *b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect()
            })
            .collect()
    }

    async fn lint_events(&self) -> Vec<Value> {
        let out = self
            .reg
            .call(
                &self.hub,
                &caller("builder-1", Profile::Developer),
                "event_log_query",
                json!({"channels": ["agent.python_lint.ran"], "limit": 50}),
            )
            .await
            .unwrap();
        out["events"].as_array().unwrap().clone()
    }

    /// The call is refused and no ruff process started.
    async fn refused(&self, args: Value) -> ua_core::UaError {
        let err = self.call(args.clone()).await.expect_err(&format!("{args} should be refused"));
        assert!(self.runs().is_empty(), "ruff ran for {args}: {:?}", self.runs());
        err
    }
}

fn install_fake_ruff(bin: &Path, log: &Path, env_log: &Path, sleep: Option<u32>) {
    std::fs::create_dir_all(bin).unwrap();
    let pause = sleep.map(|s| format!("sleep {s}\n")).unwrap_or_default();
    let script = format!(
        "#!/bin/sh\n{pause}printf '%s\\0' \"$@\" >> {log}\nprintf '\\n' >> {log}\nprintf '%s\\n' \"$RUFF_NO_CACHE\" >> {env_log}\n",
        log = shell_quote(log),
        env_log = shell_quote(env_log),
    );
    let path = bin.join("ruff");
    std::fs::write(&path, script).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn allowlist_is_only_the_two_fixed_invocations() {
    let ok = |parts: &[&str]| assert!(argv_on_allowlist(&argv(parts)), "{parts:?} should be allowed");
    let no = |parts: &[&str]| assert!(!argv_on_allowlist(&argv(parts)), "{parts:?} should be rejected");
    ok(&["ruff", "check", "--isolated", "--fix", "src/app.py"]);
    ok(&["ruff", "format", "--isolated", "src/app.py"]);
    // Without --isolated a config file could add flags back.
    no(&["ruff", "check", "--fix", "src/app.py"]);
    no(&["ruff", "format", "src/app.py"]);
    no(&["ruff", "check", "--isolated", "--fix", "--unsafe-fixes", "src/app.py"]);
    no(&["ruff", "check", "--isolated", "src/app.py"]);
    no(&["ruff", "format", "--isolated", "--check", "src/app.py"]);
    no(&["ruff", "format", "--isolated", "--", "src/app.py"]);
    no(&["ruff", "check", "--fix", "--isolated", "src/app.py"]);
    no(&["/usr/bin/ruff", "format", "--isolated", "src/app.py"]);
    no(&["python", "-m", "ruff", "check", "--isolated", "--fix", "src/app.py"]);
    no(&["ruff", "check", "--isolated", "--fix", "-src/app.py"]);
    no(&["ruff", "format", "--isolated", "--config=x.toml"]);
    no(&["bash", "-c", "ruff format --isolated src/app.py"]);
}

#[tokio::test]
async fn rejected_arguments_do_not_start_a_process() {
    let e = env();
    e.write("app.py", "x = 1\n");
    let err = e.refused(json!({"path": "app.py", "args": ["--unsafe-fixes"]})).await;
    assert!(err.to_string().contains("arguments are not accepted"), "{err}");
    let unknown = e.refused(json!({"path": "app.py", "command": "bash"})).await;
    assert!(unknown.to_string().contains("unknown field"), "{unknown}");
    // The same target with no extra arguments does reach the fake ruff.
    e.call(json!({"path": "app.py"})).await.unwrap();
    assert_eq!(e.runs().len(), 2);
}

#[tokio::test]
async fn paths_outside_the_workspace_are_refused() {
    let e = env();
    let outside = e.dir.path().join("outside.py");
    std::fs::write(&outside, "print('no')\n").unwrap();
    let err = e.refused(json!({"path": "../outside.py"})).await;
    assert_eq!(err.reason_code(), Some("outside_sandbox"), "{err}");
    let err = e.refused(json!({"path": outside.to_string_lossy()})).await;
    assert_eq!(err.reason_code(), Some("outside_sandbox"), "{err}");

    // A symlinked target resolves to where it points.
    std::os::unix::fs::symlink(&outside, e.workspace.join("link.py")).unwrap();
    let err = e.refused(json!({"path": "link.py"})).await;
    assert_eq!(err.reason_code(), Some("outside_sandbox"), "{err}");
}

#[tokio::test]
async fn a_symlink_inside_a_target_directory_is_refused() {
    let e = env();
    let outside = e.dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("victim.py"), "x=1\n").unwrap();
    e.write("pkg/ok.py", "x = 1\n");
    std::fs::create_dir_all(e.workspace.join("pkg/deep")).unwrap();
    std::os::unix::fs::symlink(&outside, e.workspace.join("pkg/deep/escape")).unwrap();
    let err = e.refused(json!({"path": "pkg"})).await;
    assert_eq!(err.reason_code(), Some("symlink_in_target"), "{err}");
    assert!(err.to_string().contains("pkg/deep/escape"), "{err}");
    assert_eq!(std::fs::read_to_string(outside.join("victim.py")).unwrap(), "x=1\n");
    // The workspace root holds that directory too.
    let err = e.refused(json!({"path": "."})).await;
    assert_eq!(err.reason_code(), Some("symlink_in_target"), "{err}");
}

#[tokio::test]
async fn credential_files_and_non_python_files_are_refused() {
    let e = env();
    e.write(".env", "SECRET=1\n");
    let err = e.refused(json!({"path": ".env"})).await;
    assert_eq!(err.reason_code(), Some("secret_file"), "{err}");
    e.write("deploy.pem", "x\n");
    let err = e.refused(json!({"path": "deploy.pem"})).await;
    assert_eq!(err.reason_code(), Some("secret_file"), "{err}");
    e.write("notes.txt", "x\n");
    let err = e.refused(json!({"path": "notes.txt"})).await;
    assert!(err.to_string().contains("not a Python file"), "{err}");
    let err = e.refused(json!({"path": "missing.py"})).await;
    assert!(err.to_string().contains("does not exist"), "{err}");
    for ok in ["a.py", "b.pyi", "c.ipynb"] {
        e.write(ok, "\n");
    }
    for ok in ["a.py", "b.pyi", "c.ipynb"] {
        e.call(json!({"path": ok})).await.unwrap_or_else(|err| panic!("{ok}: {err}"));
    }
}

#[tokio::test]
async fn git_internals_and_the_configured_hooks_directory_are_refused() {
    let e = env();
    e.write(".git/hooks/pre_commit.py", "x = 1\n");
    e.refused(json!({"path": ".git/hooks/pre_commit.py"})).await;
    e.refused(json!({"path": ".git"})).await;

    // A repository whose core.hooksPath is a plain-looking directory.
    let repo = e.workspace.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let git = |args: &[&str]| {
        let ok = std::process::Command::new("git").args(args).current_dir(&repo).output().unwrap().status;
        assert!(ok.success(), "git {args:?}");
    };
    git(&["init", "-q"]);
    git(&["config", "core.hooksPath", "tools/hooks"]);
    e.write("repo/tools/hooks/pre_push.py", "x = 1\n");
    e.write("repo/src/app.py", "x = 1\n");
    let err = e.refused(json!({"path": "repo/tools/hooks/pre_push.py"})).await;
    assert_eq!(err.reason_code(), Some("hook_dir"), "{err}");
    let err = e.refused(json!({"path": "repo/tools"})).await;
    assert_eq!(err.reason_code(), Some("hook_dir"), "{err}");
    let err = e.refused(json!({"path": "repo"})).await;
    assert_eq!(err.reason_code(), Some("hook_dir"), "{err}");
    e.call(json!({"path": "repo/src"})).await.unwrap();
}

#[tokio::test]
async fn a_leading_dash_never_becomes_a_flag() {
    let e = env();
    e.write("-x.py", "x = 1\n");
    let err = e.refused(json!({"path": "-x.py"})).await;
    assert_eq!(err.reason_code(), Some("argv_rejected"), "{err}");
    let err = e.refused(json!({"path": "./-x.py"})).await;
    assert_eq!(err.reason_code(), Some("argv_rejected"), "{err}");
}

#[tokio::test]
async fn ruff_must_be_on_the_run_cmd_allowlist() {
    let e = env_with(None, |cfg| cfg.shell_allowlist = vec!["ls".into(), "git".into()]);
    e.write("app.py", "x = 1\n");
    let err = e.refused(json!({"path": "app.py"})).await;
    assert_eq!(err.code(), "denied", "{err}");
    // A non-operator is not told which program is missing, as with run_cmd.
    assert_eq!(err.reason_code(), Some("command_refused"), "{err}");
}

#[tokio::test]
async fn fixed_argv_runs_in_the_workspace_without_a_shell_or_config() {
    let e = env();
    let tricky = "pkg/sample.py; echo pwned.py";
    e.write(tricky, "x = 1\n");
    // A project config that would pull in a file outside the workspace and
    // move the cache there: --isolated means ruff never reads it.
    e.write("pyproject.toml", "[tool.ruff]\nextend = \"/etc/hostname\"\ncache-dir = \"/var/tmp/ruff-cache\"\n");

    let ran = e.call(json!({"path": tricky, "args": []})).await.unwrap();
    assert_eq!(ran["success"], true, "{ran}");
    assert!(!e.workspace.join("pwned").exists(), "the path must not be evaluated by a shell");
    assert!(!e.dir.path().join("pwned").exists());
    assert_eq!(
        e.runs(),
        vec![argv(&["check", "--isolated", "--fix", tricky]), argv(&["format", "--isolated", tricky])]
    );
    let env_lines = std::fs::read_to_string(&e.env_log).unwrap();
    assert_eq!(env_lines, "true\ntrue\n", "RUFF_NO_CACHE must be set for both steps");

    let events = e.lint_events().await;
    assert_eq!(events.len(), 1, "{events:?}");
    let p = &events[0]["payload"];
    assert_eq!(p["path"], tricky);
    assert_eq!(p["success"], true);
    assert_eq!(p["timed_out"], false);
    assert_eq!(p["error"], Value::Null);
    assert_eq!(p["lint_exit_code"], 0);
    assert_eq!(events[0]["originator"], "builder-1");
}

#[tokio::test]
async fn a_timeout_is_an_error_and_is_still_recorded() {
    let e = env_with(Some(5), |cfg| cfg.python_lint_timeout = Some(Duration::from_millis(300)));
    e.write("app.py", "x = 1\n");
    let started = std::time::Instant::now();
    let err = e.call(json!({"path": "app.py"})).await.unwrap_err();
    assert!(err.to_string().contains("timed out"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(5), "the hung ruff was not cut off");
    let events = e.lint_events().await;
    assert_eq!(events.len(), 1, "{events:?}");
    let p = &events[0]["payload"];
    assert_eq!(p["timed_out"], true);
    assert_eq!(p["success"], false);
    assert!(p["error"].as_str().unwrap().contains("timed out"), "{p}");
    assert_eq!(p["lint_exit_code"], Value::Null);
    assert_eq!(p["format_exit_code"], Value::Null, "format does not run after a failed check");
}

#[tokio::test]
async fn a_missing_ruff_is_an_error_and_is_still_recorded() {
    if which_ruff_on_path() {
        eprintln!("skipped: the host has a ruff on PATH");
        return;
    }
    let e = env_with(None, |cfg| cfg.python_lint_path_prepend = None);
    e.write("app.py", "x = 1\n");
    let err = e.call(json!({"path": "app.py"})).await.unwrap_err();
    assert!(err.to_string().contains("command not found"), "{err}");
    let events = e.lint_events().await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(events[0]["payload"]["error"].as_str().unwrap().contains("command not found"));
    assert_eq!(events[0]["payload"]["timed_out"], false);
    assert_eq!(events[0]["payload"]["success"], false);
}

fn which_ruff_on_path() -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("ruff").is_file()))
}

#[tokio::test]
async fn only_profiles_that_write_see_the_tool() {
    let e = env();
    e.write("app.py", "x = 1\n");
    assert!(Profile::Developer.allows_tool("python_lint_and_format"));
    for profile in [Profile::Reviewer, Profile::Research, Profile::Public] {
        assert!(!profile.allows_tool("python_lint_and_format"), "{profile}");
        let err = e
            .reg
            .call(&e.hub, &caller("someone-1", profile), "python_lint_and_format", json!({"path": "app.py"}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "denied", "{profile}: {err}");
    }
    assert!(e.runs().is_empty());
}

/// With a real ruff on PATH, a hostile project config is not honoured: an
/// `extend` naming a file outside the workspace would fail the run (it is
/// not a ruff config), and `cache-dir` would create a directory outside it.
#[tokio::test]
async fn a_real_ruff_ignores_the_project_config() {
    if !which_ruff_on_path() {
        eprintln!("skipped: no ruff on PATH");
        return;
    }
    let e = env_with(None, |cfg| cfg.python_lint_path_prepend = None);
    let cache = e.dir.path().join("outside-cache");
    e.write(
        "pyproject.toml",
        &format!("[tool.ruff]\nextend = \"/etc/hostname\"\ncache-dir = {:?}\n", cache.to_string_lossy()),
    );
    e.write("app.py", "x=1\n");
    let ran = e.call(json!({"path": "app.py"})).await.unwrap();
    assert_eq!(ran["success"], true, "{ran}");
    assert!(!cache.exists(), "cache-dir from the project config was honoured");
    assert!(!e.workspace.join(".ruff_cache").exists(), "RUFF_NO_CACHE was not honoured");
    assert_eq!(std::fs::read_to_string(e.workspace.join("app.py")).unwrap(), "x = 1\n");
}
