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
    /// The fake ruff's working directory, one line per run.
    cwd_log: PathBuf,
    hub: Hub,
    reg: Registry,
}

/// A hub whose `ruff` is a fake that logs its argv (and, with `sleep`, hangs).
fn env_with(sleep: Option<u32>, tweak: impl FnOnce(&mut Config)) -> Env {
    env_script(sleep, "", tweak)
}

/// As [`env_with`], with `extra` shell appended to the fake ruff (run in the workspace).
fn env_script(sleep: Option<u32>, extra: &str, tweak: impl FnOnce(&mut Config)) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let bin = dir.path().join("bin");
    let log = dir.path().join("ruff.log");
    let env_log = dir.path().join("ruff-env.log");
    let cwd_log = dir.path().join("ruff-cwd.log");
    install_fake_ruff(&bin, &log, &env_log, &cwd_log, sleep, extra);
    let mut cfg = Config::for_home(dir.path());
    cfg.workspace = Some(workspace.clone());
    cfg.python_lint_path_prepend = Some(bin);
    tweak(&mut cfg);
    Env { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), dir, workspace, log, env_log, cwd_log }
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
        org_id: ua_core::DEFAULT_ORG.into(),
    }
}

impl Env {
    async fn call(&self, args: Value) -> Result<Value, ua_core::UaError> {
        self.reg
            .call(&self.hub, &caller("builder-1", Profile::Developer), "python_lint_and_format", args)
            .await
    }

    /// The absolute path ruff is given for a workspace-relative target.
    fn abs(&self, rel: &str) -> String {
        self.workspace.canonicalize().unwrap().join(rel).to_string_lossy().into_owned()
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

fn install_fake_ruff(
    bin: &Path,
    log: &Path,
    env_log: &Path,
    cwd_log: &Path,
    sleep: Option<u32>,
    extra: &str,
) {
    std::fs::create_dir_all(bin).unwrap();
    let pause = sleep.map(|s| format!("sleep {s}\n")).unwrap_or_default();
    let script = format!(
        "#!/bin/sh\n{pause}printf '%s\\0' \"$@\" >> {log}\nprintf '\\n' >> {log}\nprintf '%s\\n' \"$RUFF_NO_CACHE\" >> {env_log}\npwd >> {cwd_log}\n{extra}\n",
        log = shell_quote(log),
        env_log = shell_quote(env_log),
        cwd_log = shell_quote(cwd_log),
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

    // Project style arrives as --config pairs, only for the allowlisted keys.
    ok(&["ruff", "check", "--isolated", "--config", "line-length=120", "--fix", "src/app.py"]);
    ok(&[
        "ruff",
        "check",
        "--isolated",
        "--config",
        "target-version=\"py311\"",
        "--config",
        "lint.select=[\"E\",\"F\",\"UP\"]",
        "--config",
        "lint.ignore=[\"E501\"]",
        "--fix",
        "src/app.py",
    ]);
    ok(&["ruff", "format", "--isolated", "--config", "format.quote-style=\"single\"", "src/app.py"]);
    ok(&["ruff", "format", "--isolated", "--config", "indent-width=2", "src/app.py"]);
    ok(&[
        "ruff",
        "format",
        "--isolated",
        "--config",
        "exclude=[]",
        "--config",
        "force-exclude=true",
        "/w/app.py",
    ]);
    ok(&[
        "ruff",
        "check",
        "--isolated",
        "--config",
        "extend-exclude=[\"migrations\",\"/w/gen/*.py\",\"{a,b}.py\"]",
        "--config",
        "lint.extend-select=[\"B\"]",
        "--config",
        "lint.extend-ignore=[\"E501\"]",
        "--config",
        "lint.per-file-ignores={\"/w/tests/*\"=[\"S101\"],\"__init__.py\"=[\"F401\",\"E\"]}",
        "--fix",
        "/w/app.py",
    ]);
    for pair in [
        "extend=\"/etc/hostname\"",
        "cache-dir=\"/var/tmp/x\"",
        "unsafe-fixes=true",
        "lint.unsafe-fixes=true",
        "src=[\"/\"]",
        "include=[\"*.py\"]",
        "exclude=[\"../up\"]",
        "exclude=[\"a/../../b\"]",
        "exclude=[\"$HOME/x\"]",
        "exclude=[\"~/x\"]",
        "exclude=[\"a\\\\b\"]",
        "exclude=[\"a\",]",
        "exclude=[a]",
        "force-exclude=yes",
        "lint.extend-select=[\"e1\"]",
        "lint.per-file-ignores={\"a\"=[\"e1\"]}",
        "lint.per-file-ignores={\"../a\"=[\"E\"]}",
        "lint.per-file-ignores={\"a\"=[\"E\"],}",
        "lint.per-file-ignores={\"a\"=\"E\"}",
        "fix=true",
        "line-length=0",
        "line-length=999",
        "line-length=120 ",
        "line-length=\"120\"",
        "line-length=1_20",
        "indent-width=0",
        "target-version=\"py27\"",
        "target-version=py311",
        "format.quote-style=\"preserve\"",
        "format.quote-style='single'",
        "lint.select=[\"E\";\"F\"]",
        "lint.select=[\"e501\"]",
        "lint.select=[\"E\",]",
        "lint.select=\"E\"",
        "line-length",
        "=120",
    ] {
        no(&["ruff", "format", "--isolated", "--config", pair, "src/app.py"]);
        no(&["ruff", "check", "--isolated", "--config", pair, "--fix", "src/app.py"]);
    }
    // The pairs go between --isolated and the step's own flag, as separate elements.
    no(&["ruff", "check", "--isolated", "--fix", "--config", "line-length=120", "src/app.py"]);
    no(&["ruff", "format", "--config", "line-length=120", "--isolated", "src/app.py"]);
    no(&["ruff", "format", "--isolated", "--config=line-length=120", "src/app.py"]);
    no(&["ruff", "format", "--isolated", "--config", "src/app.py"]);
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
    // The target reaches ruff as an absolute path, which never starts with a dash.
    e.call(json!({"path": "-x.py"})).await.unwrap();
    e.call(json!({"path": "./-x.py"})).await.unwrap();
    let runs = e.runs();
    assert_eq!(runs.len(), 4);
    for run in runs {
        assert_eq!(run.last().unwrap(), &e.abs("-x.py"));
    }
    // The argv check itself still refuses a relative path that starts with a dash.
    assert!(!argv_on_allowlist(&argv(&["ruff", "format", "--isolated", "-x.py"])));
}

#[tokio::test]
async fn ruff_runs_in_an_empty_directory_so_no_file_can_be_a_config() {
    let e = env();
    e.write("pyproject.toml", "[tool.ruff]\nline-length = 120\n");
    // A workspace file named like the forwarded pair: ruff would read it as a config file.
    e.write("line-length=120", "extend = \"/etc/hostname\"\n");
    e.write("app.py", "x = 1\n");
    e.call(json!({"path": "app.py"})).await.unwrap();
    let cwds = std::fs::read_to_string(&e.cwd_log).unwrap();
    let workspace = e.workspace.canonicalize().unwrap();
    for cwd in cwds.lines() {
        let cwd = Path::new(cwd);
        assert!(!cwd.starts_with(&workspace), "ruff ran inside the workspace: {}", cwd.display());
        assert!(!cwd.join("line-length=120").exists());
    }
    assert_eq!(cwds.lines().count(), 2, "{cwds}");
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
    e.write(
        "pyproject.toml",
        "[tool.ruff]\nextend = \"/etc/hostname\"\ncache-dir = \"/var/tmp/ruff-cache\"\n",
    );

    let ran = e.call(json!({"path": tricky, "args": []})).await.unwrap();
    let tricky_abs = e.abs(tricky);
    assert_eq!(ran["success"], true, "{ran}");
    assert!(!e.workspace.join("pwned").exists(), "the path must not be evaluated by a shell");
    assert!(!e.dir.path().join("pwned").exists());
    assert_eq!(
        e.runs(),
        vec![
            argv(&["check", "--isolated", "--fix", &tricky_abs]),
            argv(&["format", "--isolated", &tricky_abs])
        ]
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

/// The forwarded `--config` pairs of each run, in order.
fn config_pairs(run: &[String]) -> Vec<String> {
    run.windows(2).filter(|w| w[0] == "--config").map(|w| w[1].clone()).collect()
}

#[tokio::test]
async fn the_project_style_is_forwarded_as_config_pairs() {
    let e = env();
    e.write(
        "proj/pyproject.toml",
        "[project]\nname = \"demo\"\n\n[tool.ruff]\nline-length = 120\nindent-width = 4\ntarget-version = \"py311\"\n\n\
         [tool.ruff.format]\nquote-style = \"single\"\n\n[tool.ruff.lint]\nselect = [\"E\", \"F\", \"UP\"]\nignore = [\"E501\"]\n",
    );
    e.write("proj/src/app.py", "x = 'a'\n");
    let ran = e.call(json!({"path": "proj/src/app.py"})).await.unwrap();
    assert_eq!(ran["success"], true, "{ran}");
    let runs = e.runs();
    assert_eq!(
        runs[0],
        argv(&[
            "check",
            "--isolated",
            "--config",
            "line-length=120",
            "--config",
            "indent-width=4",
            "--config",
            "target-version=\"py311\"",
            "--config",
            "lint.select=[\"E\",\"F\",\"UP\"]",
            "--config",
            "lint.ignore=[\"E501\"]",
            "--fix",
            &e.abs("proj/src/app.py"),
        ])
    );
    assert_eq!(
        runs[1],
        argv(&[
            "format",
            "--isolated",
            "--config",
            "line-length=120",
            "--config",
            "indent-width=4",
            "--config",
            "target-version=\"py311\"",
            "--config",
            "format.quote-style=\"single\"",
            &e.abs("proj/src/app.py"),
        ])
    );
    assert_eq!(ran["config"]["source"], "proj/pyproject.toml", "{ran}");
    let events = e.lint_events().await;
    assert_eq!(events[0]["payload"]["config"]["source"], "proj/pyproject.toml");
}

#[tokio::test]
async fn ruff_toml_is_found_from_the_target_and_wins_over_pyproject() {
    let e = env();
    e.write("pyproject.toml", "[tool.ruff]\nline-length = 88\n");
    e.write("svc/ruff.toml", "line-length = 100\n[format]\nquote-style = \"double\"\n");
    e.write("svc/pyproject.toml", "[tool.ruff]\nline-length = 70\n");
    e.write("svc/.ruff.toml", "line-length = 110\n");
    e.write("svc/pkg/mod.py", "x = 1\n");
    e.write("other/mod.py", "x = 1\n");
    // .ruff.toml beats ruff.toml beats pyproject.toml in one directory, as in ruff.
    e.call(json!({"path": "svc/pkg"})).await.unwrap();
    assert_eq!(config_pairs(&e.runs()[0]), vec!["line-length=110"]);
    std::fs::remove_file(e.workspace.join("svc/.ruff.toml")).unwrap();
    e.call(json!({"path": "svc/pkg/mod.py"})).await.unwrap();
    assert_eq!(config_pairs(&e.runs()[3]), vec!["line-length=100", "format.quote-style=\"double\""]);
    // A target with no config of its own uses the nearest one above it.
    e.call(json!({"path": "other/mod.py"})).await.unwrap();
    assert_eq!(config_pairs(&e.runs()[4]), vec!["line-length=88"]);
    // A pyproject.toml without [tool.ruff] is skipped, as ruff skips it.
    e.write("other/pyproject.toml", "[project]\nname = \"x\"\n");
    e.call(json!({"path": "other/mod.py"})).await.unwrap();
    assert_eq!(config_pairs(&e.runs()[6]), vec!["line-length=88"]);
}

#[tokio::test]
async fn hostile_config_keys_are_never_forwarded() {
    let e = env();
    e.write(
        "pyproject.toml",
        "[tool.ruff]\nextend = \"/etc/hostname\"\ncache-dir = \"/var/tmp/ruff-cache\"\nunsafe-fixes = true\n\
         src = [\"/\"]\ninclude = [\"*.py\"]\nexclude = [\"../outside\", \"/etc\"]\nline-length = 100\n\n\
         [tool.ruff.lint]\nextend-safe-fixes = [\"ALL\"]\nunsafe-fixes = true\nselect = [\"F\"]\n\
         per-file-ignores = {\"../x/*\" = [\"E\"]}\n",
    );
    e.write("app.py", "x = 1\n");
    let ran = e.call(json!({"path": "app.py"})).await.unwrap();
    let runs = e.runs();
    assert_eq!(config_pairs(&runs[0]), vec!["line-length=100", "lint.select=[\"F\"]"]);
    assert_eq!(config_pairs(&runs[1]), vec!["line-length=100"]);
    let notes = ran["config"]["notes"].to_string();
    for key in [
        "extend",
        "cache-dir",
        "unsafe-fixes",
        "src",
        "include",
        "exclude",
        "lint.extend-safe-fixes",
        "lint.per-file-ignores",
    ] {
        assert!(notes.contains(key), "no note for {key}: {notes}");
    }
}

#[tokio::test]
async fn bad_config_values_are_ignored_with_a_note() {
    let e = env();
    e.write(
        "pyproject.toml",
        "[tool.ruff]\nline-length = 0\nindent-width = \"4\"\ntarget-version = \"py27\"\n\n[tool.ruff.format]\n\
         quote-style = \"preserve\"\n\n[tool.ruff.lint]\nselect = [\"E\", \"F; rm -rf /\"]\nignore = \"E501\"\n",
    );
    e.write("app.py", "x = 1\n");
    let ran = e.call(json!({"path": "app.py"})).await.unwrap();
    for run in e.runs() {
        assert!(config_pairs(&run).is_empty(), "{run:?}");
    }
    let notes = ran["config"]["notes"].to_string();
    for key in
        ["line-length", "indent-width", "target-version", "format.quote-style", "lint.select", "lint.ignore"]
    {
        assert!(notes.contains(key), "no note for {key}: {notes}");
    }
    // A file that is not valid TOML is skipped with a note; the run goes ahead on ruff's defaults.
    e.write("pyproject.toml", "[tool.ruff\nline-length = 100\n");
    let ran = e.call(json!({"path": "app.py"})).await.unwrap();
    assert!(ran["config"]["notes"].to_string().contains("pyproject.toml"), "{ran}");
    assert!(config_pairs(&e.runs()[2]).is_empty());
}

#[tokio::test]
async fn a_config_file_symlinked_out_of_the_workspace_is_not_read() {
    let e = env();
    let outside = e.dir.path().join("ruff.toml");
    std::fs::write(&outside, "line-length = 100\n").unwrap();
    std::os::unix::fs::symlink(&outside, e.workspace.join("ruff.toml")).unwrap();
    e.write("app.py", "x = 1\n");
    let ran = e.call(json!({"path": "app.py"})).await.unwrap();
    assert!(config_pairs(&e.runs()[0]).is_empty(), "{:?}", e.runs());
    assert!(ran["config"]["notes"].to_string().contains("ruff.toml"), "{ran}");
}

#[tokio::test]
async fn the_ledger_records_changed_files_and_counts() {
    let script = "case \"$1\" in\n\
        check) echo 'Found 3 errors (2 fixed, 1 remaining).' ;;\n\
        format) for last in \"$@\"; do :; done; printf 'y = 2\\n' > \"$last/b.py\"; \
                echo '1 file reformatted, 1 file left unchanged' ;;\n\
        esac";
    let e = env_script(None, script, |_| {});
    e.write("pkg/a.py", "x = 1\n");
    e.write("pkg/b.py", "y=2\n");
    e.write("pkg/notes.txt", "not python\n");
    let ran = e.call(json!({"path": "pkg"})).await.unwrap();
    assert_eq!(ran["changed_files"], json!(["pkg/b.py"]), "{ran}");
    let events = e.lint_events().await;
    let p = &events[0]["payload"];
    assert_eq!(p["changed_files"], json!(["pkg/b.py"]), "{p}");
    assert_eq!(p["files_scanned"], 2, "{p}");
    assert_eq!(p["files_truncated"], false, "{p}");
    assert_eq!(p["fixed"], 2, "{p}");
    assert_eq!(p["remaining"], 1, "{p}");
    assert_eq!(p["reformatted"], 1, "{p}");
    // No absolute path reaches the ledger.
    let text = p.to_string();
    assert!(!text.contains(&*e.workspace.to_string_lossy()), "{text}");
    assert!(!text.contains(&*e.dir.path().to_string_lossy()), "{text}");

    // Output ruff did not print leaves the counts null; nothing changed is an empty list.
    let quiet = env();
    quiet.write("app.py", "x = 1\n");
    quiet.call(json!({"path": "app.py"})).await.unwrap();
    let p = &quiet.lint_events().await[0]["payload"];
    assert_eq!(p["changed_files"], json!([]), "{p}");
    assert_eq!(p["fixed"], Value::Null, "{p}");
    assert_eq!(p["reformatted"], Value::Null, "{p}");
}

/// With a real ruff on PATH, the project's own style survives a run: a
/// 100-column line with single quotes is left as it is under line-length 120
/// and quote-style single, where ruff's defaults would rewrite both.
#[tokio::test]
async fn a_real_ruff_keeps_the_project_style() {
    if !which_ruff_on_path() {
        eprintln!("skipped: no ruff on PATH");
        return;
    }
    let e = env_with(None, |cfg| cfg.python_lint_path_prepend = None);
    e.write(
        "pyproject.toml",
        "[tool.ruff]\nline-length = 120\n\n[tool.ruff.format]\nquote-style = \"single\"\n",
    );
    let body = "data = {'alpha': 'first value here', 'beta': 'second value here', 'gamma': 'third value'}\n";
    assert!(body.len() > 89 && body.len() < 120);
    e.write("app.py", body);
    let ran = e.call(json!({"path": "app.py"})).await.unwrap();
    assert_eq!(ran["success"], true, "{ran}");
    assert_eq!(std::fs::read_to_string(e.workspace.join("app.py")).unwrap(), body);
    assert_eq!(ran["changed_files"], json!([]), "{ran}");
}

#[tokio::test]
async fn excludes_and_rule_extensions_are_forwarded_anchored_at_the_project() {
    let e = env();
    e.write(
        "proj/pyproject.toml",
        "[tool.ruff]\nexclude = [\"migrations\"]\nextend-exclude = [\"./gen/*.py\"]\nforce-exclude = true\n\n\
         [tool.ruff.lint]\nextend-select = [\"B\"]\nextend-ignore = [\"E501\"]\n\
         per-file-ignores = {\"tests/*\" = [\"S101\"], \"__init__.py\" = [\"F401\"]}\n",
    );
    e.write("proj/app.py", "x = 1\n");
    e.write("proj/migrations/0001.py", "x=1\n");
    e.write("proj/gen/out.py", "x=1\n");
    let ran = e.call(json!({"path": "proj"})).await.unwrap();
    let proj = e.abs("proj");
    assert_eq!(
        config_pairs(&e.runs()[0]),
        vec![
            "exclude=[\"migrations\"]".to_string(),
            format!("extend-exclude=[\"{proj}/gen/*.py\"]"),
            "force-exclude=true".to_string(),
            "lint.extend-select=[\"B\"]".to_string(),
            "lint.extend-ignore=[\"E501\"]".to_string(),
            format!("lint.per-file-ignores={{\"__init__.py\"=[\"F401\"],\"{proj}/tests/*\"=[\"S101\"]}}"),
        ]
    );
    assert_eq!(
        config_pairs(&e.runs()[1]),
        vec![
            "exclude=[\"migrations\"]".to_string(),
            format!("extend-exclude=[\"{proj}/gen/*.py\"]"),
            "force-exclude=true".to_string(),
        ]
    );
    // The change snapshot skips what ruff skips: only app.py is hashed.
    let events = e.lint_events().await;
    assert_eq!(events[0]["payload"]["files_scanned"], 1, "{ran}");
}

/// With a real ruff, an excluded directory survives a directory run.
#[tokio::test]
async fn a_real_ruff_leaves_excluded_directories_alone() {
    if !which_ruff_on_path() {
        eprintln!("skipped: no ruff on PATH");
        return;
    }
    let e = env_with(None, |cfg| cfg.python_lint_path_prepend = None);
    e.write("svc/pyproject.toml", "[tool.ruff]\nextend-exclude = [\"migrations\", \"gen/*.py\"]\n");
    let ugly = "x=1\ny  =  [1,2]\n";
    e.write("svc/migrations/0001_initial.py", ugly);
    e.write("svc/gen/out.py", ugly);
    e.write("svc/app/views.py", ugly);
    let ran = e.call(json!({"path": "svc"})).await.unwrap();
    assert_eq!(ran["success"], true, "{ran}");
    assert_eq!(std::fs::read_to_string(e.workspace.join("svc/migrations/0001_initial.py")).unwrap(), ugly);
    assert_eq!(std::fs::read_to_string(e.workspace.join("svc/gen/out.py")).unwrap(), ugly);
    assert_ne!(std::fs::read_to_string(e.workspace.join("svc/app/views.py")).unwrap(), ugly);
    assert_eq!(ran["changed_files"], json!(["svc/app/views.py"]), "{ran}");
    // Output names files relative to the workspace, never by absolute path.
    let out = ran.to_string();
    assert!(!out.contains(&*e.workspace.canonicalize().unwrap().to_string_lossy()), "{out}");
}

#[tokio::test]
async fn spoofed_summary_text_does_not_set_the_counts() {
    let script = "case \"$1\" in\n\
        check) printf '%s\\n' '  |' '1 | Found 9 errors (9 fixed, 0 remaining).' 'Found 1 error (1 fixed, 0 remaining).' ;;\n\
        format) printf '%s\\n' '3 | 7 files reformatted' ;;\n\
        esac";
    let e = env_script(None, script, |_| {});
    e.write("app.py", "x = 1\n");
    let ran = e.call(json!({"path": "app.py"})).await.unwrap();
    assert_eq!(ran["fixed"], 1, "{ran}");
    assert_eq!(ran["remaining"], 0, "{ran}");
    assert_eq!(ran["reformatted"], Value::Null, "{ran}");
}
