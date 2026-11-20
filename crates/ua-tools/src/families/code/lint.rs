//! `python_lint_and_format`: ruff check and ruff format, and nothing else.
//!
//! The only programs started are exactly:
//!
//! - `ruff check --isolated --fix <path>`
//! - `ruff format --isolated <path>`
//!
//! `<path>` is one argv element resolved inside the workspace sandbox used by
//! `run_cmd`. There is no shell, so metacharacters in the path stay one
//! argument. Any other argv, including extra flags, is refused. A non-empty
//! `args` field is refused before a process is started.
//!
//! `--isolated` makes ruff ignore every configuration file, so a
//! `pyproject.toml` or `ruff.toml` in the workspace cannot turn on what the
//! fixed argv leaves out (unsafe fixes, `extend` from a file outside the
//! workspace, a `cache-dir` elsewhere). The cache is off (`RUFF_NO_CACHE`).
//!
//! The target gets the guards `fs_write` applies: no credential file names, no
//! repository hooks directory. A file must be Python (`.py`, `.pyi`,
//! `.ipynb`); a directory must not contain a symlink, since ruff would follow
//! it out of the workspace. `ruff` must be on the `run_cmd` allowlist.

use std::path::Path;
use std::time::Duration;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::safety::{guard_secret_filename, resolve_in_root};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use crate::families::capability::is_operator;
use crate::families::workspace::{
    ScratchHome, base_env, guard_configured_hooks, guard_configured_hooks_dir, run_program, sandbox,
};
use crate::registry::{Registry, ToolCtx, blocking, tool};

const TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_CAP: usize = 50_000;
/// Extensions a single-file target may have.
const PYTHON_EXTENSIONS: [&str; 3] = ["py", "pyi", "ipynb"];
/// Entries a directory target may hold before the symlink walk gives up.
const WALK_MAX_ENTRIES: usize = 200_000;

/// Whether `argv` is one of the two fixed ruff invocations.
///
/// `path` is a single element. It must be non-empty, must not start with `-`
/// (that would be another flag) and must not contain a NUL.
pub fn argv_on_allowlist(argv: &[String]) -> bool {
    let parts: Vec<&str> = argv.iter().map(String::as_str).collect();
    match parts.as_slice() {
        ["ruff", "check", "--isolated", "--fix", path] | ["ruff", "format", "--isolated", path] => {
            path_ok(path)
        }
        _ => false,
    }
}

fn path_ok(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('-') && !path.contains('\0')
}

fn argv_refusal() -> UaError {
    UaError::denied(
        "argv_rejected",
        "ruff invocation is not on the allowlist (ruff check --isolated --fix <path> or ruff format --isolated <path>)",
    )
}

fn fixed_invocations(rel: &str) -> UaResult<[Vec<String>; 2]> {
    let invocations = [
        vec!["ruff".into(), "check".into(), "--isolated".into(), "--fix".into(), rel.into()],
        vec!["ruff".into(), "format".into(), "--isolated".into(), rel.into()],
    ];
    if invocations.iter().any(|argv| !argv_on_allowlist(argv)) {
        return Err(argv_refusal());
    }
    Ok(invocations)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LintArgs {
    /// Python file (.py, .pyi, .ipynb) or directory inside the workspace to check and format.
    pub path: String,
    /// Extra arguments. Refused: only the fixed ruff check and ruff format invocations run.
    pub args: Option<Vec<String>>,
}

fn output_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

/// One ruff step's result.
#[derive(Default)]
struct Step {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    timed_out: bool,
    error: Option<String>,
}

impl Step {
    fn completed(&self) -> bool {
        self.exit_code.is_some() && !self.timed_out && self.error.is_none()
    }
}

async fn run_fixed(argv: &[String], cwd: &Path, env: &[(String, String)], timeout: Duration, which: &str) -> Step {
    if !argv_on_allowlist(argv) {
        return Step { error: Some(argv_refusal().to_string()), ..Step::default() };
    }
    match run_program(&argv[0], &argv[1..], cwd, env, timeout, OUTPUT_CAP).await {
        Ok(out) if out.timed_out => Step {
            timed_out: true,
            error: Some(format!("ruff {which} timed out after {} ms", timeout.as_millis())),
            ..Step::default()
        },
        Ok(out) => Step {
            exit_code: Some(out.exit_code),
            stdout: output_text(&out.stdout),
            stderr: output_text(&out.stderr),
            ..Step::default()
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Step { error: Some(format!("failed to execute ruff {which}: command not found")), ..Step::default() }
        }
        Err(e) => Step { error: Some(format!("failed to execute ruff {which}: {e}")), ..Step::default() },
    }
}

/// Refuse unless `ruff` is on the effective `run_cmd` allowlist. As in
/// `run_cmd`, only an operator is told why: the allowlist is not shown to
/// anyone else.
fn guard_allowlisted(ctx: &ToolCtx) -> UaResult<()> {
    let cfg = ctx.hub.cfg();
    if cfg.shell_allowlist().iter().any(|p| p == "ruff") {
        return Ok(());
    }
    if is_operator(&ctx.caller, cfg) {
        Err(UaError::denied("program_not_allowed", "ruff is not on the run_cmd shell_allowlist"))
    } else {
        Err(UaError::denied(
            "command_refused",
            "command refused: run_cmd runs only allowlisted programs, without config overrides or \
             destructive arguments",
        ))
    }
}

/// The first symlink at or under `dir`, without following any.
fn first_symlink(dir: &Path) -> UaResult<Option<std::path::PathBuf>> {
    let mut stack = vec![dir.to_path_buf()];
    let mut seen = 0usize;
    while let Some(d) = stack.pop() {
        let entries =
            std::fs::read_dir(&d).map_err(|e| UaError::invalid(format!("cannot read {}: {e}", d.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| UaError::invalid(format!("cannot read {}: {e}", d.display())))?;
            seen += 1;
            if seen > WALK_MAX_ENTRIES {
                return Err(UaError::invalid(format!(
                    "the target directory holds more than {WALK_MAX_ENTRIES} entries; pass a narrower path"
                )));
            }
            let kind = entry
                .file_type()
                .map_err(|e| UaError::invalid(format!("cannot stat {}: {e}", entry.path().display())))?;
            if kind.is_symlink() {
                return Ok(Some(entry.path()));
            }
            if kind.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    Ok(None)
}

async fn python_lint_and_format(ctx: ToolCtx, a: LintArgs) -> UaResult<Value> {
    if a.args.as_ref().is_some_and(|args| !args.is_empty()) {
        return Err(UaError::invalid(
            "arguments are not accepted; python_lint_and_format runs only `ruff check --isolated --fix <path>` \
             and `ruff format --isolated <path>`",
        ));
    }
    guard_allowlisted(&ctx)?;
    let sb = sandbox(&ctx)?;
    let resolved = resolve_in_root(&a.path, std::slice::from_ref(&sb.root), true)?;
    let meta = std::fs::symlink_metadata(&resolved)
        .map_err(|_| UaError::invalid(format!("target path {:?} does not exist", a.path)))?;
    // The same guards fs_write applies to a path it is about to rewrite.
    guard_secret_filename(&resolved)?;
    if meta.is_dir() {
        guard_configured_hooks_dir(&resolved, &sb.root, &a.path).await?;
        let dir = resolved.clone();
        if let Some(link) = blocking(move || first_symlink(&dir)).await? {
            return Err(UaError::denied(
                "symlink_in_target",
                format!(
                    "{:?} contains a symlink ({}); ruff would follow it. Pass a narrower path",
                    a.path,
                    sb.rel(&link)
                ),
            ));
        }
    } else {
        guard_configured_hooks(&resolved, &sb.root, &a.path).await?;
        let ext = resolved.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase);
        if !meta.is_file() || !ext.as_deref().is_some_and(|e| PYTHON_EXTENSIONS.contains(&e)) {
            return Err(UaError::invalid(format!(
                "{:?} is not a Python file (.py, .pyi or .ipynb) or a directory",
                a.path
            )));
        }
    }
    let rel = sb.rel(&resolved);
    let [check, format] = fixed_invocations(&rel)?;
    let scratch = ScratchHome::new()?;
    let mut env = base_env();
    env.retain(|(key, _)| key != "HOME");
    env.push(("HOME".into(), scratch.path.to_string_lossy().into_owned()));
    env.push(("RUFF_NO_CACHE".into(), "true".into()));
    let cfg = ctx.hub.cfg();
    if let Some(prepend) = &cfg.python_lint_path_prepend {
        let path =
            env.iter().find(|(key, _)| key == "PATH").map(|(_, value)| value.clone()).unwrap_or_default();
        let merged =
            std::env::join_paths(std::iter::once(prepend.clone()).chain(std::env::split_paths(&path)))
                .map_err(|_| UaError::internal("could not build PATH for ruff"))?;
        if let Some((_, value)) = env.iter_mut().find(|(key, _)| key == "PATH") {
            *value = merged.to_string_lossy().into_owned();
        }
    }
    let timeout = cfg.python_lint_timeout.unwrap_or(TIMEOUT);

    let lint = run_fixed(&check, &sb.root, &env, timeout, "check").await;
    let fmt = if lint.completed() {
        run_fixed(&format, &sb.root, &env, timeout, "format").await
    } else {
        Step::default()
    };
    let error = lint.error.clone().or_else(|| fmt.error.clone());
    let timed_out = lint.timed_out || fmt.timed_out;
    let success = error.is_none() && lint.exit_code == Some(0) && fmt.exit_code == Some(0);
    let by = ctx.caller.label.clone();
    let event = json!({
        "path": rel,
        "lint_exit_code": lint.exit_code,
        "format_exit_code": fmt.exit_code,
        "success": success,
        "timed_out": timed_out,
        "error": error,
    });
    ctx.hub
        .db()
        .write_async(move |tx| {
            ledger::append(tx, EventInput::new("agent.python_lint.ran", event).by(by))?;
            Ok(())
        })
        .await?;
    if let Some(e) = error {
        return Err(UaError::invalid(e));
    }
    Ok(json!({
        "lint_stdout": lint.stdout,
        "lint_stderr": lint.stderr,
        "format_stdout": fmt.stdout,
        "format_stderr": fmt.stderr,
        "success": success,
    }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "python_lint_and_format",
            "Run `ruff check --isolated --fix <path>` and then `ruff format --isolated <path>` on one \
             workspace Python file (.py, .pyi, .ipynb) or directory. The path is a single argv element \
             inside the run_cmd sandbox; credential files, the repository hooks directory and directories \
             holding a symlink are refused, and ruff must be on the run_cmd allowlist. No shell is used. \
             Extra arguments are refused; the flags are fixed and ruff configuration files are ignored. \
             Returns {lint_stdout, lint_stderr, format_stdout, format_stderr, success}. Each step times out \
             after 30 seconds. Every run, including a failed or timed-out one, is recorded on \
             agent.python_lint.ran.",
            python_lint_and_format,
        )
        .family("code"),
    );
}
