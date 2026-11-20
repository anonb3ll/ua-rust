//! `python_lint_and_format`: fixed ruff argv, workspace sandbox, no shell.

use std::os::unix::fs::PermissionsExt;

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};
use ua_tools::families::code::lint::argv_on_allowlist;
use ua_tools::{Hub, Registry, builtin_registry};

struct Env {
    _dir: tempfile::TempDir,
    workspace: std::path::PathBuf,
    hub: Hub,
    reg: Registry,
}

fn env_with(prepend: Option<std::path::PathBuf>) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let mut cfg = Config::for_home(dir.path());
    cfg.workspace = Some(workspace.clone());
    cfg.python_lint_path_prepend = prepend;
    Env { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _dir: dir, workspace }
}

fn env() -> Env {
    env_with(None)
}

fn agent() -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

impl Env {
    async fn call(&self, args: Value) -> Result<Value, ua_core::UaError> {
        self.reg.call(&self.hub, &agent(), "python_lint_and_format", args).await
    }
}

fn install_fake_ruff(bin: &std::path::Path, log: &std::path::Path) {
    std::fs::create_dir_all(bin).unwrap();
    let script = format!("#!/bin/sh\nprintf '%s\\0' \"$@\" >> {}\n", shell_quote(log));
    let path = bin.join("ruff");
    std::fs::write(&path, script).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
}

fn shell_quote(path: &std::path::Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

/// The fake `ruff` writes each argument, NUL-separated, with no shell joining.
fn nul_args(log: &std::path::Path) -> Vec<Vec<String>> {
    let bytes = std::fs::read(log).unwrap_or_default();
    let words: Vec<String> = bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    let mut commands = Vec::new();
    let mut i = 0;
    while i < words.len() {
        if words[i] == "check" && words.get(i + 1).is_some_and(|s| s == "--fix") && i + 2 < words.len() {
            commands.push(vec![words[i].clone(), words[i + 1].clone(), words[i + 2].clone()]);
            i += 3;
        } else if words[i] == "format" && i + 1 < words.len() {
            commands.push(vec![words[i].clone(), words[i + 1].clone()]);
            i += 2;
        } else {
            commands.push(vec![words[i].clone()]);
            i += 1;
        }
    }
    commands
}

#[test]
fn allowlist_is_only_the_two_fixed_invocations() {
    let ok = |argv: &[&str]| {
        let owned: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
        assert!(argv_on_allowlist(&owned), "{argv:?} should be allowed");
    };
    let no = |argv: &[&str]| {
        let owned: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
        assert!(!argv_on_allowlist(&owned), "{argv:?} should be rejected");
    };
    ok(&["ruff", "check", "--fix", "src/app.py"]);
    ok(&["ruff", "format", "src/app.py"]);
    no(&["ruff", "check", "--fix", "--unsafe-fixes", "src/app.py"]);
    no(&["ruff", "check", "src/app.py"]);
    no(&["ruff", "format", "--check", "src/app.py"]);
    no(&["ruff", "format", "--", "src/app.py"]);
    no(&["/usr/bin/ruff", "format", "src/app.py"]);
    no(&["python", "-m", "ruff", "check", "--fix", "src/app.py"]);
    no(&["ruff", "check", "--fix", "-src/app.py"]);
    no(&["bash", "-c", "ruff format src/app.py"]);
}

#[tokio::test]
async fn rejected_arguments_do_not_start_a_process() {
    let e = env();
    let log = e._dir.path().join("should-not-exist.log");
    let err = e.call(json!({"path": "missing.py", "args": ["--unsafe-fixes"]})).await.unwrap_err();
    assert!(err.to_string().contains("arguments are not accepted"), "{err}");
    assert!(!log.exists());
    let unknown = e.call(json!({"path": "missing.py", "command": "bash"})).await.unwrap_err();
    assert!(unknown.to_string().contains("unknown field"), "{unknown}");
}

#[tokio::test]
async fn path_outside_the_workspace_is_refused() {
    let e = env();
    let outside = e._dir.path().join("outside.py");
    std::fs::write(&outside, "print('no')\n").unwrap();
    let err = e.call(json!({"path": "../outside.py"})).await.unwrap_err();
    assert_eq!(err.reason_code(), Some("outside_sandbox"), "{err}");
}

#[tokio::test]
async fn fixed_argv_runs_in_the_workspace_without_a_shell() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let log = dir.path().join("ruff.log");
    install_fake_ruff(&bin, &log);
    let e = env_with(Some(bin));
    let tricky = "pkg/sample.py; echo pwned";
    std::fs::create_dir_all(e.workspace.join("pkg")).unwrap();
    std::fs::write(e.workspace.join("pkg").join("sample.py; echo pwned"), "x = 1\n").unwrap();

    let ran = e.call(json!({"path": tricky, "args": []})).await.unwrap();
    assert_eq!(ran["success"], true, "{ran}");
    assert!(!e.workspace.join("pwned").exists(), "the path must not be evaluated by a shell");
    assert!(!e._dir.path().join("pwned").exists());
    let commands = nul_args(&log);
    assert_eq!(
        commands,
        vec![
            vec!["check".to_string(), "--fix".to_string(), tricky.to_string()],
            vec!["format".to_string(), tricky.to_string()],
        ],
        "log was {}",
        String::from_utf8_lossy(&std::fs::read(&log).unwrap())
    );
}
