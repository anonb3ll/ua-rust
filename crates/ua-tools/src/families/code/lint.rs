//! `python_lint_and_format`: ruff check and ruff format, and nothing else.
//!
//! The only programs started are exactly:
//!
//! - `ruff check --isolated [--config <pair>]... --fix <path>`
//! - `ruff format --isolated [--config <pair>]... <path>`
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
//! The project's style is kept another way: the hub reads the nearest ruff
//! configuration at or above the target, inside the workspace (`.ruff.toml`,
//! then `ruff.toml`, then a `pyproject.toml` with `[tool.ruff]`, per directory,
//! as ruff orders them), and forwards only [`CONFIG_KEYS`] as `--config
//! key=value` pairs, each value checked and re-rendered by the hub. Every other
//! key, and every value out of range, is left out with a note in the result.
//!
//! The target gets the guards `fs_write` applies: no credential file names, no
//! repository hooks directory. A file must be Python (`.py`, `.pyi`,
//! `.ipynb`); a directory must not contain a symlink, since ruff would follow
//! it out of the workspace. `ruff` must be on the `run_cmd` allowlist.
//!
//! `agent.python_lint.ran` records the workspace-relative Python files whose
//! content the run changed (hashed before and after, at most
//! [`HASH_MAX_FILES`] files and [`HASH_MAX_BYTES`] bytes) and the fixed,
//! remaining and reformatted counts ruff printed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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

/// The ruff settings forwarded from a project's configuration, in argv order.
pub const CONFIG_KEYS: [&str; 6] =
    ["line-length", "indent-width", "target-version", "format.quote-style", "lint.select", "lint.ignore"];
/// The subset `ruff check` gets; `ruff format` gets the first three and the quote style.
const CHECK_KEYS: [&str; 5] = ["line-length", "indent-width", "target-version", "lint.select", "lint.ignore"];
const FORMAT_KEYS: [&str; 4] = ["line-length", "indent-width", "target-version", "format.quote-style"];
const TARGET_VERSIONS: [&str; 8] = ["py37", "py38", "py39", "py310", "py311", "py312", "py313", "py314"];
const LINE_LENGTH_MAX: i64 = 320;
const INDENT_WIDTH_MAX: i64 = 16;
/// Rule codes one `select` or `ignore` list may hold, and the longest code.
const RULES_MAX: usize = 500;
const RULE_CODE_MAX_LEN: usize = 16;
/// Configuration files, per directory, in the order ruff prefers them.
const CONFIG_FILES: [&str; 3] = [".ruff.toml", "ruff.toml", "pyproject.toml"];
/// A configuration file larger than this is not read.
const CONFIG_MAX_BYTES: u64 = 256 * 1024;
/// Notes kept about one configuration.
const NOTES_MAX: usize = 40;
/// Python files hashed before and after a run, and the bytes read for it.
pub const HASH_MAX_FILES: usize = 2_000;
pub const HASH_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Directories ruff skips by default; their files are not hashed.
const SKIPPED_DIRS: [&str; 26] = [
    ".bzr",
    ".direnv",
    ".eggs",
    ".git",
    ".git-rewrite",
    ".hg",
    ".ipynb_checkpoints",
    ".mypy_cache",
    ".nox",
    ".pants.d",
    ".pyenv",
    ".pytest_cache",
    ".pytype",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    ".vscode",
    "__pycache__",
    "__pypackages__",
    "_build",
    "buck-out",
    "dist",
    "node_modules",
    "site-packages",
    "venv",
];

static RULE_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z]+[0-9]*$").expect("valid regex"));

fn rule_code_ok(code: &str) -> bool {
    code.len() <= RULE_CODE_MAX_LEN && RULE_CODE.is_match(code)
}

/// `1..=max` written as plain decimal digits, no sign, no separators.
fn small_int_ok(value: &str, max: i64) -> bool {
    !value.is_empty()
        && value.len() <= 3
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<i64>().is_ok_and(|n| (1..=max).contains(&n))
}

/// `["E","F401"]` exactly as [`render_rules`] writes it.
fn rule_list_ok(value: &str) -> bool {
    let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) else { return false };
    if inner.is_empty() {
        return true;
    }
    let codes: Vec<&str> = inner.split(',').collect();
    codes.len() <= RULES_MAX
        && codes
            .iter()
            .all(|c| c.strip_prefix('"').and_then(|c| c.strip_suffix('"')).is_some_and(rule_code_ok))
}

fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

/// Whether `pair` is one allowlisted `key=value` with a value the hub would render.
pub fn config_pair_ok(pair: &str) -> bool {
    let Some((key, value)) = pair.split_once('=') else { return false };
    match key {
        "line-length" => small_int_ok(value, LINE_LENGTH_MAX),
        "indent-width" => small_int_ok(value, INDENT_WIDTH_MAX),
        "target-version" => TARGET_VERSIONS.iter().any(|v| quoted(v) == value),
        "format.quote-style" => value == "\"single\"" || value == "\"double\"",
        "lint.select" | "lint.ignore" => rule_list_ok(value),
        _ => false,
    }
}

/// Whether `argv` is one of the two fixed ruff invocations.
///
/// Between `--isolated` and the step's own tail come zero or more `--config
/// <pair>` couples, each a distinct key accepted by [`config_pair_ok`].
/// `path` is a single element. It must be non-empty, must not start with `-`
/// (that would be another flag) and must not contain a NUL.
pub fn argv_on_allowlist(argv: &[String]) -> bool {
    let parts: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (rest, check) = match parts.as_slice() {
        ["ruff", "check", "--isolated", rest @ ..] => (rest, true),
        ["ruff", "format", "--isolated", rest @ ..] => (rest, false),
        _ => return false,
    };
    let Some((path, mut flags)) = rest.split_last() else { return false };
    if check {
        match flags.split_last() {
            Some((&"--fix", before)) => flags = before,
            _ => return false,
        }
    }
    if flags.len() % 2 != 0 {
        return false;
    }
    let mut seen: Vec<&str> = Vec::new();
    for couple in flags.chunks(2) {
        let (flag, pair) = (couple[0], couple[1]);
        if flag != "--config" || !config_pair_ok(pair) {
            return false;
        }
        let key = pair.split_once('=').map(|(k, _)| k).unwrap_or_default();
        if seen.contains(&key) {
            return false;
        }
        seen.push(key);
    }
    path_ok(path)
}

fn path_ok(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('-') && !path.contains('\0')
}

fn argv_refusal() -> UaError {
    UaError::denied(
        "argv_rejected",
        "ruff invocation is not on the allowlist (ruff check --isolated [--config <pair>]... --fix <path> or \
         ruff format --isolated [--config <pair>]... <path>)",
    )
}

fn fixed_invocations(rel: &str, pairs: &[(&'static str, String)]) -> UaResult<[Vec<String>; 2]> {
    let configs = |keys: &[&str]| -> Vec<String> {
        pairs
            .iter()
            .filter(|(k, _)| keys.contains(k))
            .flat_map(|(k, v)| ["--config".to_string(), format!("{k}={v}")])
            .collect()
    };
    let mut check: Vec<String> = vec!["ruff".into(), "check".into(), "--isolated".into()];
    check.extend(configs(&CHECK_KEYS));
    check.extend(["--fix".into(), rel.into()]);
    let mut format: Vec<String> = vec!["ruff".into(), "format".into(), "--isolated".into()];
    format.extend(configs(&FORMAT_KEYS));
    format.push(rel.into());
    let invocations = [check, format];
    if invocations.iter().any(|argv| !argv_on_allowlist(argv)) {
        return Err(argv_refusal());
    }
    Ok(invocations)
}

// ---------------------------------------------------------------------------
// The project's ruff configuration.

/// What was read from the project's configuration.
#[derive(Debug, Default)]
struct ProjectConfig {
    /// Workspace-relative path of the file read.
    source: Option<String>,
    /// Allowlisted keys and their rendered values, in [`CONFIG_KEYS`] order.
    pairs: Vec<(&'static str, String)>,
    notes: Vec<String>,
}

impl ProjectConfig {
    fn note(&mut self, note: String) {
        if self.notes.len() < NOTES_MAX {
            self.notes.push(note);
        } else if self.notes.len() == NOTES_MAX {
            self.notes.push("further notes omitted".into());
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "source": self.source,
            "forwarded": self.pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>(),
            "notes": self.notes,
        })
    }
}

fn rel_to(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).map(|r| r.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Find and read the nearest ruff configuration for `start` (a directory),
/// walking up to `root` and never above it.
fn project_config(start: &Path, root: &Path) -> ProjectConfig {
    let mut out = ProjectConfig::default();
    let mut dir = start.to_path_buf();
    loop {
        for name in CONFIG_FILES {
            let path = dir.join(name);
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            let rel = rel_to(root, &path);
            if meta.file_type().is_symlink() {
                out.note(format!("{rel} is a symlink; not read"));
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if meta.len() > CONFIG_MAX_BYTES {
                out.note(format!("{rel} is over {CONFIG_MAX_BYTES} bytes; not read"));
                continue;
            }
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    out.note(format!("{rel} could not be read ({}); not used", e.kind()));
                    continue;
                }
            };
            let doc: toml::Table = match toml::from_str(&text) {
                Ok(d) => d,
                Err(_) => {
                    out.note(format!("{rel} is not valid TOML; ruff's defaults apply"));
                    out.source = Some(rel);
                    return out;
                }
            };
            let table = if name == "pyproject.toml" {
                match doc.get("tool").and_then(|t| t.get("ruff")).and_then(toml::Value::as_table) {
                    Some(t) => t.clone(),
                    // ruff skips a pyproject.toml without [tool.ruff].
                    None => continue,
                }
            } else {
                doc
            };
            out.source = Some(rel);
            read_ruff_table(&table, &mut out);
            return out;
        }
        if dir == root {
            return out;
        }
        match dir.parent() {
            Some(parent) if parent.starts_with(root) => dir = parent.to_path_buf(),
            _ => return out,
        }
    }
}

fn int_setting(v: &toml::Value, key: &str, max: i64, out: &mut ProjectConfig) -> Option<String> {
    match v.as_integer() {
        Some(n) if (1..=max).contains(&n) => Some(n.to_string()),
        _ => {
            out.note(format!("{key} must be an integer from 1 to {max}; ignored"));
            None
        }
    }
}

fn rules_setting(v: &toml::Value, key: &str, out: &mut ProjectConfig) -> Option<String> {
    let codes: Option<Vec<&str>> = v.as_array().and_then(|a| a.iter().map(toml::Value::as_str).collect());
    match codes {
        Some(codes) if codes.len() <= RULES_MAX && codes.iter().all(|c| rule_code_ok(c)) => {
            Some(format!("[{}]", codes.iter().map(|c| quoted(c)).collect::<Vec<_>>().join(",")))
        }
        _ => {
            out.note(format!(
                "{key} must be a list of at most {RULES_MAX} rule codes such as \"E\" or \"F401\"; ignored"
            ));
            None
        }
    }
}

/// Collect the allowlisted settings of a ruff table (`[tool.ruff]` or a
/// `ruff.toml` document) into `out`, noting every key left out.
fn read_ruff_table(table: &toml::Table, out: &mut ProjectConfig) {
    let mut found: BTreeMap<&'static str, String> = BTreeMap::new();
    // Top-level `select` / `ignore` are ruff's older spelling of the lint keys.
    let mut legacy: Vec<(&'static str, &toml::Value)> = Vec::new();
    for (key, value) in table {
        match key.as_str() {
            "line-length" => {
                if let Some(v) = int_setting(value, "line-length", LINE_LENGTH_MAX, out) {
                    found.insert("line-length", v);
                }
            }
            "indent-width" => {
                if let Some(v) = int_setting(value, "indent-width", INDENT_WIDTH_MAX, out) {
                    found.insert("indent-width", v);
                }
            }
            "target-version" => match value.as_str() {
                Some(v) if TARGET_VERSIONS.contains(&v) => {
                    found.insert("target-version", quoted(v));
                }
                _ => {
                    out.note(format!("target-version must be one of {}; ignored", TARGET_VERSIONS.join(", ")))
                }
            },
            "select" => legacy.push(("lint.select", value)),
            "ignore" => legacy.push(("lint.ignore", value)),
            "format" | "lint" => {
                let Some(sub) = value.as_table() else {
                    out.note(format!("{key} is not a table; ignored"));
                    continue;
                };
                for (k, v) in sub {
                    match (key.as_str(), k.as_str()) {
                        ("format", "quote-style") => match v.as_str() {
                            Some(q @ ("single" | "double")) => {
                                found.insert("format.quote-style", quoted(q));
                            }
                            _ => out.note("format.quote-style must be single or double; ignored".into()),
                        },
                        ("lint", "select") => {
                            if let Some(r) = rules_setting(v, "lint.select", out) {
                                found.insert("lint.select", r);
                            }
                        }
                        ("lint", "ignore") => {
                            if let Some(r) = rules_setting(v, "lint.ignore", out) {
                                found.insert("lint.ignore", r);
                            }
                        }
                        _ => out.note(format!("{key}.{k} is not forwarded")),
                    }
                }
            }
            other => out.note(format!("{other} is not forwarded")),
        }
    }
    for (key, value) in legacy {
        let shown = key.trim_start_matches("lint.");
        if found.contains_key(key) {
            out.note(format!("top-level {shown} is overridden by {key}"));
            continue;
        }
        if let Some(r) = rules_setting(value, shown, out) {
            found.insert(key, r);
        }
    }
    out.pairs = CONFIG_KEYS
        .iter()
        .filter_map(|k| found.remove(k).map(|v| (*k, v)))
        .collect::<Vec<(&'static str, String)>>();
}

// ---------------------------------------------------------------------------
// Content hashes before and after a run.

#[derive(Debug, Default)]
struct Snapshot {
    files: BTreeMap<PathBuf, Option<[u8; 32]>>,
    truncated: bool,
}

fn hash_file(path: &Path) -> Option<[u8; 32]> {
    std::fs::read(path).ok().map(|bytes| Sha256::digest(&bytes).into())
}

fn is_python(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| PYTHON_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

/// Hash the target's Python files, sorted, within the file and byte budgets.
fn snapshot(target: &Path, is_dir: bool) -> Snapshot {
    let mut snap = Snapshot::default();
    if !is_dir {
        snap.files.insert(target.to_path_buf(), hash_file(target));
        return snap;
    }
    let mut bytes = 0u64;
    let mut stack = vec![target.to_path_buf()];
    let mut found: Vec<PathBuf> = Vec::new();
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        // Pushed in reverse, so directories are visited in name order.
        for entry in entries.into_iter().rev() {
            let Ok(kind) = entry.file_type() else { continue };
            let path = entry.path();
            if kind.is_dir() {
                let name = entry.file_name();
                if !SKIPPED_DIRS.iter().any(|s| name == *s) {
                    stack.push(path);
                }
            } else if kind.is_file() && is_python(&path) {
                found.push(path);
            }
        }
    }
    found.sort();
    for path in found {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if snap.files.len() >= HASH_MAX_FILES || bytes.saturating_add(size) > HASH_MAX_BYTES {
            snap.truncated = true;
            break;
        }
        bytes += size;
        let hash = hash_file(&path);
        snap.files.insert(path, hash);
    }
    snap
}

/// The files of `before` whose content differs now.
fn changed_since(before: &Snapshot) -> Vec<PathBuf> {
    before.files.iter().filter(|(path, hash)| hash_file(path) != **hash).map(|(p, _)| p.clone()).collect()
}

// ---------------------------------------------------------------------------
// Counts from ruff's output.

static FIXED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\((\d+) fixed, (\d+) remaining\)").expect("valid regex"));
static FOUND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Found (\d+) errors?\.").expect("valid regex"));
static REFORMATTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d+) files? reformatted").expect("valid regex"));
static UNCHANGED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d+) files? left unchanged").expect("valid regex"));

fn capture_u64(re: &Regex, text: &str, group: usize) -> Option<u64> {
    re.captures(text).and_then(|c| c.get(group)).and_then(|m| m.as_str().parse().ok())
}

/// `(fixed, remaining)` from `ruff check --fix` output, when it printed them.
fn check_counts(text: &str) -> (Option<u64>, Option<u64>) {
    if let Some(c) = FIXED.captures(text) {
        return (c[1].parse().ok(), c[2].parse().ok());
    }
    if let Some(found) = capture_u64(&FOUND, text, 1) {
        return (Some(0), Some(found));
    }
    if text.contains("All checks passed!") {
        return (Some(0), Some(0));
    }
    (None, None)
}

/// Files `ruff format` reformatted, when it said.
fn format_count(text: &str) -> Option<u64> {
    capture_u64(&REFORMATTED, text, 1).or_else(|| capture_u64(&UNCHANGED, text, 1).map(|_| 0))
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

async fn run_fixed(
    argv: &[String],
    cwd: &Path,
    env: &[(String, String)],
    timeout: Duration,
    which: &str,
) -> Step {
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Step {
            error: Some(format!("failed to execute ruff {which}: command not found")),
            ..Step::default()
        },
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
        let entries = std::fs::read_dir(&d)
            .map_err(|e| UaError::invalid(format!("cannot read {}: {e}", d.display())))?;
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
             and `ruff format --isolated <path>`, with the project's allowlisted style settings",
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
    let is_dir = meta.is_dir();
    let (target, root) = (resolved.clone(), sb.root.clone());
    let (config, before) = blocking(move || {
        let start = if is_dir { target.clone() } else { target.parent().unwrap_or(&root).to_path_buf() };
        Ok((project_config(&start, &root), snapshot(&target, is_dir)))
    })
    .await?;
    let [check, format] = fixed_invocations(&rel, &config.pairs)?;
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
    // Ruff may have rewritten files even when a step failed: compare in every case.
    let truncated = before.truncated;
    let scanned = before.files.len();
    let changed = blocking(move || Ok(changed_since(&before))).await?;
    let changed_files: Vec<String> = changed.iter().map(|p| sb.rel(p)).collect();
    let (fixed, remaining) = check_counts(&format!("{}\n{}", lint.stdout, lint.stderr));
    let reformatted = format_count(&format!("{}\n{}", fmt.stdout, fmt.stderr));
    let config_json = config.to_json();
    let by = ctx.caller.label.clone();
    let event = json!({
        "path": rel,
        "lint_exit_code": lint.exit_code,
        "format_exit_code": fmt.exit_code,
        "success": success,
        "timed_out": timed_out,
        "error": error,
        "changed_files": changed_files,
        "files_scanned": scanned,
        "files_truncated": truncated,
        "fixed": fixed,
        "remaining": remaining,
        "reformatted": reformatted,
        "config": config_json,
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
        "changed_files": changed_files,
        "files_truncated": truncated,
        "fixed": fixed,
        "remaining": remaining,
        "reformatted": reformatted,
        "config": config_json,
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
             Extra arguments are refused. Ruff reads no configuration file itself: the hub reads the nearest \
             .ruff.toml, ruff.toml or pyproject.toml [tool.ruff] at or above the target inside the workspace \
             and forwards only line-length, indent-width, target-version, format.quote-style, lint.select \
             and lint.ignore, validated, as --config pairs; every other key is left out with a note. \
             Returns {lint_stdout, lint_stderr, format_stdout, format_stderr, success, changed_files, \
             files_truncated, fixed, remaining, reformatted, config}. Each step times out after 30 seconds. \
             Every run, including a failed or timed-out one, is recorded on agent.python_lint.ran with the \
             workspace-relative files it changed (at most 2000 hashed) and ruff's counts.",
            python_lint_and_format,
        )
        .family("code"),
    );
}
