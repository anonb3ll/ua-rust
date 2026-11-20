//! `python_lint_and_format`: ruff check and ruff format, and nothing else.
//!
//! The only programs started are exactly:
//!
//! - `ruff check --fix <path>`
//! - `ruff format <path>`
//!
//! `<path>` is one argv element resolved inside the workspace sandbox used by
//! `run_cmd`. There is no shell, so metacharacters in the path stay one
//! argument. Any other argv, including extra flags, is refused. A non-empty
//! `args` field is refused before a process is started.

use std::path::Path;
use std::time::Duration;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::safety::resolve_in_root;
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use crate::families::workspace::{ScratchHome, base_env, run_program, sandbox};
use crate::registry::{Registry, ToolCtx, tool};

const TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_CAP: usize = 50_000;

/// Whether `argv` is one of the two fixed ruff invocations.
///
/// `path` is a single element. It must be non-empty, must not start with `-`
/// (that would be another flag) and must not contain a NUL.
pub fn argv_on_allowlist(argv: &[String]) -> bool {
    let parts: Vec<&str> = argv.iter().map(String::as_str).collect();
    match parts.as_slice() {
        ["ruff", "check", "--fix", path] | ["ruff", "format", path] => path_ok(path),
        _ => false,
    }
}

fn path_ok(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('-') && !path.contains('\0')
}

fn fixed_invocations(rel: &str) -> UaResult<[Vec<String>; 2]> {
    let invocations = [
        vec!["ruff".into(), "check".into(), "--fix".into(), rel.into()],
        vec!["ruff".into(), "format".into(), rel.into()],
    ];
    if invocations.iter().any(|argv| !argv_on_allowlist(argv)) {
        return Err(UaError::denied(
            "argv_rejected",
            "ruff invocation is not on the allowlist (ruff check --fix <path> or ruff format <path>)",
        ));
    }
    Ok(invocations)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LintArgs {
    /// File or directory inside the workspace to check and format.
    pub path: String,
    /// Extra arguments. Refused: only the fixed ruff check and ruff format invocations run.
    pub args: Option<Vec<String>>,
}

fn output_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

async fn run_fixed(
    argv: &[String],
    cwd: &Path,
    env: &[(String, String)],
    which: &str,
) -> UaResult<(i32, String, String)> {
    if !argv_on_allowlist(argv) {
        return Err(UaError::denied(
            "argv_rejected",
            "ruff invocation is not on the allowlist (ruff check --fix <path> or ruff format <path>)",
        ));
    }
    let program = &argv[0];
    let args = &argv[1..];
    match run_program(program, args, cwd, env, TIMEOUT, OUTPUT_CAP).await {
        Ok(out) if out.timed_out => Err(UaError::invalid(format!("Ruff {which} timed out after 30 seconds"))),
        Ok(out) => Ok((out.exit_code, output_text(&out.stdout), output_text(&out.stderr))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(UaError::invalid(format!("Failed to execute ruff {which}: command not found")))
        }
        Err(e) => Err(UaError::invalid(format!("Failed to execute ruff {which}: {e}"))),
    }
}

async fn python_lint_and_format(ctx: ToolCtx, a: LintArgs) -> UaResult<Value> {
    if a.args.as_ref().is_some_and(|args| !args.is_empty()) {
        return Err(UaError::invalid(
            "arguments are not accepted; python_lint_and_format runs only `ruff check --fix <path>` and `ruff format <path>`",
        ));
    }
    let sb = sandbox(&ctx)?;
    let resolved = resolve_in_root(&a.path, std::slice::from_ref(&sb.root), true)?;
    if !resolved.exists() {
        return Err(UaError::invalid(format!("target path {:?} does not exist", a.path)));
    }
    let rel = sb.rel(&resolved);
    let [check, format] = fixed_invocations(&rel)?;
    let scratch = ScratchHome::new()?;
    let mut env = base_env();
    env.retain(|(key, _)| key != "HOME");
    env.push(("HOME".into(), scratch.path.to_string_lossy().into_owned()));
    if let Some(prepend) = &ctx.hub.cfg().python_lint_path_prepend {
        let path =
            env.iter().find(|(key, _)| key == "PATH").map(|(_, value)| value.clone()).unwrap_or_default();
        let merged =
            std::env::join_paths(std::iter::once(prepend.clone()).chain(std::env::split_paths(&path)))
                .map_err(|_| UaError::internal("could not build PATH for ruff"))?;
        if let Some((_, value)) = env.iter_mut().find(|(key, _)| key == "PATH") {
            *value = merged.to_string_lossy().into_owned();
        }
    }

    let (lint_code, lint_stdout, lint_stderr) = run_fixed(&check, &sb.root, &env, "check").await?;
    let (format_code, format_stdout, format_stderr) = run_fixed(&format, &sb.root, &env, "format").await?;
    let success = lint_code == 0 && format_code == 0;
    let by = ctx.caller.label.clone();
    let rel_event = rel.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            ledger::append(
                tx,
                EventInput::new(
                    "agent.python_lint.ran",
                    json!({
                        "path": rel_event,
                        "lint_exit_code": lint_code,
                        "format_exit_code": format_code,
                        "success": success,
                    }),
                )
                .by(by),
            )?;
            Ok(())
        })
        .await?;
    Ok(json!({
        "lint_stdout": lint_stdout,
        "lint_stderr": lint_stderr,
        "format_stdout": format_stdout,
        "format_stderr": format_stderr,
        "success": success,
    }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "python_lint_and_format",
            "Run `ruff check --fix <path>` and then `ruff format <path>` on one workspace file or directory. \
             The path is a single argv element inside the run_cmd sandbox. No shell is used. Extra arguments \
             are refused; the flags are fixed. Returns {lint_stdout, lint_stderr, format_stdout, format_stderr, \
             success}. Each step times out after 30 seconds.",
            python_lint_and_format,
        )
        .family("code"),
    );
}
