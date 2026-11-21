//! `python_lint_and_format`: ruff check and ruff format, and nothing else.
//!
//! The only programs started are exactly:
//!
//! - `ruff check --isolated [--config <pair>]... --fix <path>`
//! - `ruff format --isolated [--config <pair>]... <path>`
//!
//! `<path>` is one argv element: the target, resolved inside the workspace
//! sandbox used by `run_cmd`, as an absolute path. Ruff runs in an empty
//! scratch directory, so neither the path nor a `--config` value can name a
//! workspace file (ruff reads a `--config` value that names an existing file
//! as a configuration file). There is no shell, so metacharacters in the path
//! stay one argument. Any other argv, including extra flags, is refused. A
//! non-empty `args` field is refused before a process is started.
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
//! key=value` pairs, each value checked and re-rendered by the hub. Exclude
//! and per-file-ignore globs must be relative and stay inside the project
//! (no `..`); a glob with a `/` is anchored at the configuration file's
//! directory, as ruff anchors it. Every other key, and every value out of
//! range, is left out with a note in the result.
//!
//! The target gets the guards `fs_write` applies: no credential file names, no
//! repository hooks directory. A file must be Python (`.py`, `.pyi`,
//! `.ipynb`); a directory must not contain a symlink, since ruff would follow
//! it out of the workspace. `ruff` must be on the `run_cmd` allowlist.
//!
//! `agent.python_lint.ran` records the workspace-relative Python files whose
//! content the run changed (hashed before and after, skipping excluded paths,
//! at most [`HASH_MAX_FILES`] files and [`HASH_MAX_BYTES`] bytes) and the
//! fixed, remaining and reformatted counts from ruff's summary lines.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use globset::{Glob, GlobSet, GlobSetBuilder};
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
pub const CONFIG_KEYS: [&str; 12] = [
    "line-length",
    "indent-width",
    "target-version",
    "exclude",
    "extend-exclude",
    "force-exclude",
    "format.quote-style",
    "lint.select",
    "lint.extend-select",
    "lint.ignore",
    "lint.extend-ignore",
    "lint.per-file-ignores",
];
/// The settings `ruff format` gets; `ruff check` gets every other one too, but not the quote style.
const FORMAT_KEYS: [&str; 7] = [
    "line-length",
    "indent-width",
    "target-version",
    "exclude",
    "extend-exclude",
    "force-exclude",
    "format.quote-style",
];
const TARGET_VERSIONS: [&str; 8] = ["py37", "py38", "py39", "py310", "py311", "py312", "py313", "py314"];
const LINE_LENGTH_MAX: i64 = 320;
const INDENT_WIDTH_MAX: i64 = 16;
/// Rule codes one `select` or `ignore` list may hold, and the longest code.
const RULES_MAX: usize = 500;
const RULE_CODE_MAX_LEN: usize = 16;
/// Globs one exclude list or per-file-ignores table may hold, and the longest
/// glob as written in the project and as passed to ruff (anchored).
const GLOBS_MAX: usize = 200;
const GLOB_MAX_LEN: usize = 256;
const ANCHORED_GLOB_MAX_LEN: usize = 4096;
/// Configuration files, per directory, in the order ruff prefers them.
const CONFIG_FILES: [&str; 3] = [".ruff.toml", "ruff.toml", "pyproject.toml"];
/// A configuration file larger than this is not read.
const CONFIG_MAX_BYTES: u64 = 256 * 1024;
/// Notes kept about one configuration, and the longest key name a note repeats.
const NOTES_MAX: usize = 40;
const NOTE_KEY_MAX: usize = 64;
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

/// A glob as passed to ruff: printable ASCII without quotes, backslashes or
/// shell expansion characters, no `..` component. It may be absolute (the hub
/// anchors project-relative globs at the project directory).
fn glob_ok(glob: &str) -> bool {
    !glob.is_empty()
        && glob.len() <= ANCHORED_GLOB_MAX_LEN
        && glob.bytes().all(|b| (0x20..0x7f).contains(&b) && !matches!(b, b'"' | b'\\' | b'$' | b'~'))
        && !glob.split('/').any(|part| part == "..")
}

/// `1..=max` written as plain decimal digits, no sign, no separators.
fn small_int_ok(value: &str, max: i64) -> bool {
    !value.is_empty()
        && value.len() <= 3
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<i64>().is_ok_and(|n| (1..=max).contains(&n))
}

/// Parse a run of `"..."` strings separated by `,` up to `close`, as
/// [`render_list`] writes them. The strings hold no `"` or `\`. Returns the
/// strings and the rest after `close`.
fn parse_strings(mut s: &str, close: char) -> Option<(Vec<&str>, &str)> {
    let mut out = Vec::new();
    if let Some(rest) = s.strip_prefix(close) {
        return Some((out, rest));
    }
    loop {
        let body = s.strip_prefix('"')?;
        let end = body.find('"')?;
        out.push(&body[..end]);
        s = &body[end + 1..];
        if let Some(rest) = s.strip_prefix(close) {
            return Some((out, rest));
        }
        s = s.strip_prefix(',')?;
    }
}

/// `[<string>,...]` exactly, every item accepted by `item_ok`, at most `max`.
fn list_ok(value: &str, max: usize, item_ok: fn(&str) -> bool) -> bool {
    let Some(rest) = value.strip_prefix('[') else { return false };
    match parse_strings(rest, ']') {
        Some((items, "")) => items.len() <= max && items.iter().all(|i| item_ok(i)),
        _ => false,
    }
}

/// `{"<glob>"=[<codes>],...}` exactly.
fn per_file_ignores_ok(value: &str) -> bool {
    let Some(mut s) = value.strip_prefix('{') else { return false };
    if s == "}" {
        return true;
    }
    let mut entries = 0usize;
    loop {
        let Some(body) = s.strip_prefix('"') else { return false };
        let Some(end) = body.find('"') else { return false };
        if !glob_ok(&body[..end]) {
            return false;
        }
        let Some(rest) = body[end + 1..].strip_prefix("=[") else { return false };
        let Some((codes, rest)) = parse_strings(rest, ']') else { return false };
        if codes.len() > RULES_MAX || !codes.iter().all(|c| rule_code_ok(c)) {
            return false;
        }
        entries += 1;
        if entries > GLOBS_MAX {
            return false;
        }
        if rest == "}" {
            return true;
        }
        let Some(rest) = rest.strip_prefix(',') else { return false };
        s = rest;
    }
}

fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

fn render_list<S: AsRef<str>>(items: &[S]) -> String {
    format!("[{}]", items.iter().map(|i| quoted(i.as_ref())).collect::<Vec<_>>().join(","))
}

/// Whether `pair` is one allowlisted `key=value` with a value the hub would render.
pub fn config_pair_ok(pair: &str) -> bool {
    let Some((key, value)) = pair.split_once('=') else { return false };
    match key {
        "line-length" => small_int_ok(value, LINE_LENGTH_MAX),
        "indent-width" => small_int_ok(value, INDENT_WIDTH_MAX),
        "target-version" => TARGET_VERSIONS.iter().any(|v| quoted(v) == value),
        "format.quote-style" => value == "\"single\"" || value == "\"double\"",
        "force-exclude" => value == "true" || value == "false",
        "lint.select" | "lint.ignore" | "lint.extend-select" | "lint.extend-ignore" => {
            list_ok(value, RULES_MAX, rule_code_ok)
        }
        "exclude" | "extend-exclude" => list_ok(value, GLOBS_MAX, glob_ok),
        "lint.per-file-ignores" => per_file_ignores_ok(value),
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

fn fixed_invocations(target: &str, pairs: &[(&'static str, String)]) -> UaResult<[Vec<String>; 2]> {
    let configs = |format: bool| -> Vec<String> {
        pairs
            .iter()
            .filter(|(k, _)| if format { FORMAT_KEYS.contains(k) } else { *k != "format.quote-style" })
            .flat_map(|(k, v)| ["--config".to_string(), format!("{k}={v}")])
            .collect()
    };
    let mut check: Vec<String> = vec!["ruff".into(), "check".into(), "--isolated".into()];
    check.extend(configs(false));
    check.extend(["--fix".into(), target.into()]);
    let mut format: Vec<String> = vec!["ruff".into(), "format".into(), "--isolated".into()];
    format.extend(configs(true));
    format.push(target.into());
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
    /// The forwarded `exclude` and `extend-exclude` globs, as passed to ruff.
    excludes: Vec<String>,
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

    /// The configuration for results and the ledger: anchored globs are
    /// shown relative to the workspace `root`.
    fn to_json(&self, root: &Path) -> Value {
        json!({
            "source": self.source,
            "forwarded": self.pairs.iter().map(|(k, v)| scrub(format!("{k}={v}"), root)).collect::<Vec<_>>(),
            "notes": self.notes,
        })
    }
}

/// A project-controlled key name, safe to repeat in a note: control
/// characters replaced and at most [`NOTE_KEY_MAX`] characters.
fn shown(key: &str) -> String {
    let mut out: String =
        key.chars().take(NOTE_KEY_MAX).map(|c| if c.is_control() { '?' } else { c }).collect();
    if key.chars().count() > NOTE_KEY_MAX {
        out.push_str("...");
    }
    out
}

fn rel_to(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).map(|r| r.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Read one candidate configuration file without following a symlink, from
/// the handle that was opened. `Ok(None)`: nothing to read there.
fn read_config_file(path: &Path) -> Result<Option<String>, String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // No symlink as the last component, and no blocking on a FIFO.
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err("is a symlink; not read".into()),
        Err(e) => return Err(format!("could not be opened ({}); not read", e.kind())),
    };
    let meta = file.metadata().map_err(|e| format!("could not be read ({}); not read", e.kind()))?;
    if !meta.is_file() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    file.take(CONFIG_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not be read ({}); not read", e.kind()))?;
    if bytes.len() as u64 > CONFIG_MAX_BYTES {
        return Err(format!("is over {CONFIG_MAX_BYTES} bytes; not read"));
    }
    String::from_utf8(bytes).map(Some).map_err(|_| "is not UTF-8; not read".into())
}

/// Find and read the nearest ruff configuration for `start` (a directory),
/// walking up to `root` and never above it.
fn project_config(start: &Path, root: &Path) -> ProjectConfig {
    let mut out = ProjectConfig::default();
    let mut dir = start.to_path_buf();
    loop {
        for name in CONFIG_FILES {
            let path = dir.join(name);
            let rel = rel_to(root, &path);
            let text = match read_config_file(&path) {
                Ok(Some(t)) => t,
                Ok(None) => continue,
                Err(why) => {
                    out.note(format!("{rel} {why}"));
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
            read_ruff_table(&table, &dir, &mut out);
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
            Some(render_list(&codes))
        }
        _ => {
            out.note(format!(
                "{key} must be a list of at most {RULES_MAX} rule codes such as \"E\" or \"F401\"; ignored"
            ));
            None
        }
    }
}

/// A project glob, relative and inside the project, as ruff will get it: a
/// glob with a `/` is anchored at `dir` (ruff anchors it at the project root).
fn project_glob(raw: &str, dir: &Path) -> Option<String> {
    let glob = raw.strip_prefix("./").unwrap_or(raw);
    if glob.len() > GLOB_MAX_LEN || glob.starts_with('/') || !glob_ok(glob) {
        return None;
    }
    if !glob.contains('/') {
        return Some(glob.to_string());
    }
    let anchored = format!("{}/{glob}", dir.to_str()?);
    glob_ok(&anchored).then_some(anchored)
}

const GLOB_RULE: &str = "relative globs inside the project (no .., no absolute path, no quotes, \
                         backslashes, $ or ~), at most 200";

fn globs_setting(v: &toml::Value, key: &str, dir: &Path, out: &mut ProjectConfig) -> Option<Vec<String>> {
    let globs: Option<Vec<String>> = v
        .as_array()
        .filter(|a| a.len() <= GLOBS_MAX)
        .and_then(|a| a.iter().map(|g| g.as_str().and_then(|g| project_glob(g, dir))).collect());
    if globs.is_none() {
        out.note(format!("{key} must hold {GLOB_RULE}; ignored"));
    }
    globs
}

fn per_file_ignores_setting(
    v: &toml::Value,
    key: &str,
    dir: &Path,
    out: &mut ProjectConfig,
) -> Option<String> {
    let rendered: Option<Vec<String>> = v.as_table().filter(|t| t.len() <= GLOBS_MAX).and_then(|t| {
        t.iter()
            .map(|(glob, codes)| {
                let glob = project_glob(glob, dir)?;
                let codes: Vec<&str> =
                    codes.as_array()?.iter().map(toml::Value::as_str).collect::<Option<_>>()?;
                (codes.len() <= RULES_MAX && codes.iter().all(|c| rule_code_ok(c)))
                    .then(|| format!("{}={}", quoted(&glob), render_list(&codes)))
            })
            .collect()
    });
    match rendered {
        Some(entries) => Some(format!("{{{}}}", entries.join(","))),
        None => {
            out.note(format!("{key} must map {GLOB_RULE} to rule codes; ignored"));
            None
        }
    }
}

/// Collect the allowlisted settings of a ruff table (`[tool.ruff]` or a
/// `ruff.toml` document in `dir`) into `out`, noting every key left out.
fn read_ruff_table(table: &toml::Table, dir: &Path, out: &mut ProjectConfig) {
    let mut found: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut excludes: Vec<String> = Vec::new();
    // Top-level lint keys are ruff's older spelling; `lint.*` wins.
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
            k @ ("exclude" | "extend-exclude") => {
                let k: &'static str = if k == "exclude" { "exclude" } else { "extend-exclude" };
                if let Some(globs) = globs_setting(value, k, dir, out) {
                    found.insert(k, render_list(&globs));
                    excludes.extend(globs);
                }
            }
            "force-exclude" => match value.as_bool() {
                Some(b) => {
                    found.insert("force-exclude", b.to_string());
                }
                None => out.note("force-exclude must be true or false; ignored".into()),
            },
            "select" => legacy.push(("lint.select", value)),
            "ignore" => legacy.push(("lint.ignore", value)),
            "extend-select" => legacy.push(("lint.extend-select", value)),
            "extend-ignore" => legacy.push(("lint.extend-ignore", value)),
            "per-file-ignores" => legacy.push(("lint.per-file-ignores", value)),
            "format" | "lint" => {
                let Some(sub) = value.as_table() else {
                    out.note(format!("{key} is not a table; ignored"));
                    continue;
                };
                for (k, v) in sub {
                    let lint_key: Option<&'static str> = match (key.as_str(), k.as_str()) {
                        ("lint", "select") => Some("lint.select"),
                        ("lint", "ignore") => Some("lint.ignore"),
                        ("lint", "extend-select") => Some("lint.extend-select"),
                        ("lint", "extend-ignore") => Some("lint.extend-ignore"),
                        ("lint", "per-file-ignores") => Some("lint.per-file-ignores"),
                        _ => None,
                    };
                    if let Some(lk) = lint_key {
                        if let Some(r) = lint_setting(lk, v, dir, out) {
                            found.insert(lk, r);
                        }
                        continue;
                    }
                    match (key.as_str(), k.as_str()) {
                        ("format", "quote-style") => match v.as_str() {
                            Some(q @ ("single" | "double")) => {
                                found.insert("format.quote-style", quoted(q));
                            }
                            _ => out.note("format.quote-style must be single or double; ignored".into()),
                        },
                        _ => out.note(format!("{key}.{} is not forwarded", shown(k))),
                    }
                }
            }
            other => out.note(format!("{} is not forwarded", shown(other))),
        }
    }
    for (key, value) in legacy {
        let top = key.trim_start_matches("lint.");
        if found.contains_key(key) {
            out.note(format!("top-level {top} is overridden by {key}"));
            continue;
        }
        if let Some(r) = lint_setting(key, value, dir, out) {
            found.insert(key, r);
        }
    }
    out.pairs = CONFIG_KEYS.iter().filter_map(|k| found.remove(k).map(|v| (*k, v))).collect();
    out.excludes = excludes;
}

fn lint_setting(key: &'static str, v: &toml::Value, dir: &Path, out: &mut ProjectConfig) -> Option<String> {
    if key == "lint.per-file-ignores" {
        per_file_ignores_setting(v, key, dir, out)
    } else {
        rules_setting(v, key, out)
    }
}

// ---------------------------------------------------------------------------
// Content hashes before and after a run.

/// How much a snapshot may read.
#[derive(Debug, Clone, Copy)]
struct Limits {
    files: usize,
    bytes: u64,
}

const LIMITS: Limits = Limits { files: HASH_MAX_FILES, bytes: HASH_MAX_BYTES };

#[derive(Debug, Default)]
struct Snapshot {
    files: BTreeMap<PathBuf, Option<[u8; 32]>>,
    truncated: bool,
}

/// SHA-256 of at most `limit` bytes of `path`, read in a stream.
fn hash_file(path: &Path, limit: u64) -> Option<[u8; 32]> {
    let file = std::fs::File::open(path).ok()?;
    let mut reader = file.take(limit);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(hasher.finalize().into())
}

fn is_python(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| PYTHON_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

/// The forwarded exclude globs, matched as ruff matches them: against the
/// file name and against the absolute path.
fn exclude_set(globs: &[String]) -> GlobSet {
    let mut b = GlobSetBuilder::new();
    for g in globs {
        if let Ok(glob) = Glob::new(g) {
            b.add(glob);
        }
    }
    b.build().unwrap_or_else(|_| GlobSet::empty())
}

fn excluded(set: &GlobSet, path: &Path) -> bool {
    !set.is_empty() && (set.is_match(path) || path.file_name().is_some_and(|n| set.is_match(Path::new(n))))
}

/// Hash the target's Python files in path order, skipping excluded paths,
/// and stop as soon as either limit would be passed.
fn snapshot(target: &Path, is_dir: bool, excludes: &GlobSet, limits: Limits) -> Snapshot {
    let mut snap = Snapshot::default();
    let mut bytes = 0u64;
    // Returns false once the walk must stop.
    let mut take = |path: &Path, snap: &mut Snapshot| -> bool {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if snap.files.len() >= limits.files || bytes.saturating_add(size) > limits.bytes {
            snap.truncated = true;
            return false;
        }
        bytes += size;
        snap.files.insert(path.to_path_buf(), hash_file(path, limits.bytes));
        true
    };
    if !is_dir {
        take(target, &mut snap);
        return snap;
    }
    let mut stack = vec![target.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        let mut dirs = Vec::new();
        for entry in entries {
            let Ok(kind) = entry.file_type() else { continue };
            let path = entry.path();
            if excluded(excludes, &path) {
                continue;
            }
            if kind.is_dir() {
                if !SKIPPED_DIRS.iter().any(|s| entry.file_name() == *s) {
                    dirs.push(path);
                }
            } else if kind.is_file() && is_python(&path) && !take(&path, &mut snap) {
                return snap;
            }
        }
        // Visit subdirectories in name order.
        stack.extend(dirs.into_iter().rev());
    }
    snap
}

/// The files of `before` whose content differs now.
fn changed_since(before: &Snapshot, limits: Limits) -> Vec<PathBuf> {
    before
        .files
        .iter()
        .filter(|(path, hash)| hash_file(path, limits.bytes) != **hash)
        .map(|(p, _)| p.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Counts from ruff's summary lines.

static FIXED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Found (\d+) errors? \((\d+) fixed, (\d+) remaining\)\.$").expect("valid regex")
});
static FOUND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Found (\d+) errors?\.$").expect("valid regex"));
static REFORMATTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d+) files? reformatted(?:, \d+ files? left unchanged)?$").expect("valid regex")
});
static UNCHANGED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d+ files? left unchanged$").expect("valid regex"));

/// The last line, trailing whitespace trimmed, that `f` reads a value from.
fn last_summary<T>(text: &str, f: impl Fn(&str) -> Option<T>) -> Option<T> {
    text.lines().rev().map(str::trim_end).find_map(f)
}

/// `(fixed, remaining)` from the last summary line of `ruff check --fix`.
/// Only a whole line counts, so text quoted from source code cannot spoof it.
fn check_counts(text: &str) -> (Option<u64>, Option<u64>) {
    last_summary(text, |line| {
        if let Some(c) = FIXED.captures(line) {
            return Some((c[2].parse().ok(), c[3].parse().ok()));
        }
        if let Some(c) = FOUND.captures(line) {
            return Some((Some(0), c[1].parse().ok()));
        }
        (line == "All checks passed!").then_some((Some(0), Some(0)))
    })
    .unwrap_or((None, None))
}

/// Files `ruff format` reformatted, from its last summary line.
fn format_count(text: &str) -> Option<u64> {
    last_summary(text, |line| {
        if let Some(c) = REFORMATTED.captures(line) {
            return c[1].parse().ok();
        }
        UNCHANGED.is_match(line).then_some(0)
    })
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

/// Remove the workspace root from ruff's output, which names files by their
/// absolute path: results carry workspace-relative paths only.
fn scrub(text: String, root: &Path) -> String {
    let prefix = format!("{}/", root.display());
    if text.contains(&prefix) { text.replace(&prefix, "") } else { text }
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
    let Some(target) = resolved.to_str().map(str::to_string) else {
        return Err(UaError::invalid(format!("{:?} is not a UTF-8 path", a.path)));
    };
    let is_dir = meta.is_dir();
    let (walk_target, root) = (resolved.clone(), sb.root.clone());
    let (config, before) = blocking(move || {
        let start =
            if is_dir { walk_target.clone() } else { walk_target.parent().unwrap_or(&root).to_path_buf() };
        let config = project_config(&start, &root);
        let excludes = exclude_set(&config.excludes);
        let before = snapshot(&walk_target, is_dir, &excludes, LIMITS);
        Ok((config, before))
    })
    .await?;
    let [check, format] = fixed_invocations(&target, &config.pairs)?;
    let scratch = ScratchHome::new()?;
    // An empty working directory: no workspace file can stand in for a
    // `--config` value or a relative path.
    let cwd = ScratchHome::new()?;
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

    let lint = run_fixed(&check, &cwd.path, &env, timeout, "check").await;
    let fmt = if lint.completed() {
        run_fixed(&format, &cwd.path, &env, timeout, "format").await
    } else {
        Step::default()
    };
    let error = lint.error.clone().or_else(|| fmt.error.clone());
    let timed_out = lint.timed_out || fmt.timed_out;
    let success = error.is_none() && lint.exit_code == Some(0) && fmt.exit_code == Some(0);
    // Ruff may have rewritten files even when a step failed: compare in every case.
    let truncated = before.truncated;
    let scanned = before.files.len();
    let changed = blocking(move || Ok(changed_since(&before, LIMITS))).await?;
    let changed_files: Vec<String> = changed.iter().map(|p| sb.rel(p)).collect();
    let (fixed, remaining) = check_counts(&format!("{}\n{}", lint.stderr, lint.stdout));
    let reformatted = format_count(&format!("{}\n{}", fmt.stderr, fmt.stdout));
    let config_json = config.to_json(&sb.root);
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
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "agent.python_lint.ran", event).by(by))?;
            Ok(())
        })
        .await?;
    if let Some(e) = error {
        return Err(UaError::invalid(scrub(e, &sb.root)));
    }
    Ok(json!({
        "lint_stdout": scrub(lint.stdout, &sb.root),
        "lint_stderr": scrub(lint.stderr, &sb.root),
        "format_stdout": scrub(fmt.stdout, &sb.root),
        "format_stderr": scrub(fmt.stderr, &sb.root),
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
             workspace Python file (.py, .pyi, .ipynb) or directory. The path is resolved inside the run_cmd \
             sandbox and passed as one absolute argv element; ruff runs in an empty scratch directory. \
             Credential files, the repository hooks directory and directories holding a symlink are refused, \
             and ruff must be on the run_cmd allowlist. No shell is used. Extra arguments are refused. Ruff \
             reads no configuration file itself: the hub reads the nearest .ruff.toml, ruff.toml or \
             pyproject.toml [tool.ruff] at or above the target inside the workspace and forwards only \
             line-length, indent-width, target-version, exclude, extend-exclude, force-exclude, \
             format.quote-style and the lint select, extend-select, ignore, extend-ignore and per-file-ignores \
             settings, validated (globs relative and inside the project), as --config pairs; every other key \
             is left out with a note. Returns {lint_stdout, lint_stderr, format_stdout, format_stderr, success, \
             changed_files, files_truncated, fixed, remaining, reformatted, config}. Each step times out after \
             30 seconds. Every run, including a failed or timed-out one, is recorded on agent.python_lint.ran \
             with the workspace-relative files it changed (excluded paths skipped, at most 2000 files and 64 MB \
             hashed) and the counts from ruff's summary lines.",
            python_lint_and_format,
        )
        .family("code"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_large_single_file_is_flagged_not_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.py");
        std::fs::write(&big, vec![b'x'; 4096]).unwrap();
        let limits = Limits { files: 10, bytes: 1024 };
        let snap = snapshot(&big, false, &GlobSet::empty(), limits);
        assert!(snap.truncated, "a file over the byte budget is flagged");
        assert!(snap.files.is_empty(), "and not hashed");
        // The stream hash reads only up to its limit.
        let full = hash_file(&big, u64::MAX).unwrap();
        let capped = hash_file(&big, 1024).unwrap();
        assert_ne!(full, capped);
        assert_eq!(capped, <[u8; 32]>::from(Sha256::digest(vec![b'x'; 1024])));
    }

    #[test]
    fn the_walk_stops_at_the_file_limit() {
        let dir = tempfile::tempdir().unwrap();
        for d in ["a", "b", "c"] {
            std::fs::create_dir_all(dir.path().join(d)).unwrap();
            for f in ["1.py", "2.py"] {
                std::fs::write(dir.path().join(d).join(f), "x = 1\n").unwrap();
            }
        }
        let snap = snapshot(dir.path(), true, &GlobSet::empty(), Limits { files: 3, bytes: 1 << 20 });
        assert!(snap.truncated);
        let names: Vec<String> =
            snap.files.keys().map(|p| p.strip_prefix(dir.path()).unwrap().display().to_string()).collect();
        assert_eq!(names, ["a/1.py", "a/2.py", "b/1.py"]);
    }

    #[test]
    fn counts_come_only_from_whole_summary_lines() {
        // Diagnostics quote source lines behind a gutter; only the last bare summary counts.
        let check = "app.py:1:1: F401 unused\n  |\n1 | x = 'Found 9 errors (9 fixed, 0 remaining).'\n  |\n\
                     Found 9 errors (9 fixed, 0 remaining).zzz\nFound 3 errors (2 fixed, 1 remaining).\n\
                     [*] 1 fixable with the --fix option.\n";
        assert_eq!(check_counts(check), (Some(2), Some(1)));
        assert_eq!(check_counts("  Found 4 errors (4 fixed, 0 remaining).\n"), (None, None));
        assert_eq!(check_counts("Found 2 errors.\n"), (Some(0), Some(2)));
        assert_eq!(check_counts("All checks passed!\n"), (Some(0), Some(0)));
        assert_eq!(
            format_count("x 7 files reformatted\n2 files reformatted, 1 file left unchanged\n"),
            Some(2)
        );
        assert_eq!(format_count("1 file left unchanged\n"), Some(0));
        assert_eq!(format_count("   5 files reformatted\n"), None);
    }

    #[test]
    fn notes_do_not_repeat_long_or_control_key_names() {
        let long = "k".repeat(500);
        assert_eq!(shown(&long).len(), NOTE_KEY_MAX + 3);
        assert_eq!(shown("a\nb\u{1b}"), "a?b?");
    }

    #[test]
    fn project_globs_stay_relative_and_inside() {
        let dir = Path::new("/proj");
        assert_eq!(project_glob("migrations", dir).as_deref(), Some("migrations"));
        assert_eq!(project_glob("./gen/*.py", dir).as_deref(), Some("/proj/gen/*.py"));
        for bad in ["/etc", "../x", "a/../../b", "a\"b", "a\\b", "$HOME/x", "~/x", "a\nb", ""] {
            assert_eq!(project_glob(bad, dir), None, "{bad:?}");
        }
    }
}
