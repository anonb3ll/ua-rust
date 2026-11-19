//! `run_cmd` and `run_cmd_check`.
//!
//! The command line is split without a shell and the program must be on the
//! allowlist (`ua_core::safety::vet_command`, which also refuses destructive
//! argv such as `rm -rf`). Only `cwd` is confined; arguments are not, so the
//! advisories below flag arguments that escape the workspace, programs that
//! can run other programs, and similar surprises. The `path-escape`,
//! `allowlist-bypass` and `arbitrary-code` advisories, and `git push`, force
//! a one-time human approval even when `run_cmd` is not in `approval_tools`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ua_core::safety::{
    canonicalize_lenient, git_global_options, git_subcommand, guard_secret_filename, resolve_in_root,
    split_command, vet_command,
};
use ua_core::{UaError, UaResult};

use super::{Sandbox, base_env, record, run_program, sandbox, sha256_hex};
use crate::approvals::{self, GateOutcome};
use crate::registry::{Registry, ToolCtx, tool};

/// Longest `run_cmd` timeout, seconds.
pub const CMD_TIMEOUT_CAP_S: u64 = 120;
/// Combined stdout + stderr kept, bytes.
pub const CMD_OUTPUT_CAP: usize = 50 * 1024;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunArgs {
    /// Command line. Split like a POSIX shell would split words, but no shell
    /// runs: no pipes, redirection, globbing or `$VAR` expansion.
    pub command: String,
    /// Working directory inside the workspace (default: the root).
    #[serde(default = "dot")]
    pub cwd: String,
    /// Seconds before the whole process group is killed, 1-120 (default 30).
    #[serde(default = "default_timeout")]
    pub timeout_s: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckArgs {
    /// Command line to vet; nothing is executed.
    pub command: String,
    /// Working directory inside the workspace (default: the root).
    #[serde(default = "dot")]
    pub cwd: String,
}

fn dot() -> String {
    ".".into()
}

fn default_timeout() -> i64 {
    30
}

/// One vetting note.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// `block` (run_cmd refuses), `warn` (probably not intended) or `info`.
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
}

fn finding(severity: &'static str, code: &'static str, message: impl Into<String>) -> Finding {
    Finding { severity, code, message: message.into() }
}

/// Codes that force the approval gate.
const APPROVAL_REQUIRED_CODES: &[&str] = &["path-escape", "allowlist-bypass", "arbitrary-code"];

const SHELL_SYNTAX_TOKENS: &[&str] =
    &["|", "||", "&&", ";", "&", ">", ">>", "<", "<<", "2>", "2>>", "2>&1", "1>&2"];
const READ_ONLY_PROGRAMS: &[&str] =
    &["ls", "cat", "head", "tail", "grep", "wc", "diff", "which", "echo", "date"];
const CONTENT_READERS: &[&str] = &["cat", "head", "tail", "grep", "diff", "uniq", "sort", "sed", "awk", "wc"];
const FIND_SIDE_EFFECTS: &[&str] =
    &["-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"];
const HARMLESS_INFO_ARGS: &[&str] = &["-h", "--help", "-V", "--version"];
const GIT_READ_ONLY: &[&str] = &[
    "status",
    "log",
    "diff",
    "show",
    "blame",
    "grep",
    "ls-files",
    "ls-tree",
    "rev-parse",
    "describe",
    "shortlog",
    "reflog",
    "cat-file",
];
const GIT_MUTATING: &[&str] = &[
    "add",
    "commit",
    "push",
    "fetch",
    "pull",
    "merge",
    "rebase",
    "reset",
    "restore",
    "checkout",
    "switch",
    "clean",
    "rm",
    "mv",
    "cherry-pick",
    "revert",
    "am",
    "apply",
    "clone",
    "init",
    "gc",
    "prune",
    "submodule",
];
const GIT_NETWORK: &[&str] = &["push", "fetch", "pull", "clone", "ls-remote"];
const GIT_OUTPUT_SUBCOMMANDS: &[&str] =
    &["log", "show", "diff", "diff-tree", "diff-index", "diff-files", "format-patch", "whatchanged"];
/// Built-in git commands. git never lets an alias shadow one of these, so
/// any other subcommand may be `alias.<name>=!cmd` from a repository config.
const GIT_KNOWN_SUBCOMMANDS: &[&str] = &[
    "add",
    "am",
    "annotate",
    "apply",
    "archive",
    "bisect",
    "blame",
    "branch",
    "bugreport",
    "bundle",
    "cat-file",
    "check-attr",
    "check-ignore",
    "check-mailmap",
    "check-ref-format",
    "checkout",
    "checkout-index",
    "cherry",
    "cherry-pick",
    "clean",
    "clone",
    "column",
    "commit",
    "commit-graph",
    "commit-tree",
    "config",
    "count-objects",
    "credential",
    "describe",
    "diagnose",
    "diff",
    "diff-files",
    "diff-index",
    "diff-tree",
    "difftool",
    "fast-export",
    "fast-import",
    "fetch",
    "fetch-pack",
    "filter-branch",
    "fmt-merge-msg",
    "for-each-ref",
    "for-each-repo",
    "format-patch",
    "fsck",
    "gc",
    "get-tar-commit-id",
    "grep",
    "hash-object",
    "help",
    "hook",
    "index-pack",
    "init",
    "interpret-trailers",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "mailinfo",
    "mailsplit",
    "maintenance",
    "merge",
    "merge-base",
    "merge-file",
    "merge-tree",
    "mergetool",
    "mktag",
    "mktree",
    "multi-pack-index",
    "mv",
    "name-rev",
    "notes",
    "pack-objects",
    "pack-refs",
    "patch-id",
    "prune",
    "pull",
    "push",
    "range-diff",
    "read-tree",
    "rebase",
    "reflog",
    "remote",
    "repack",
    "replace",
    "request-pull",
    "rerere",
    "reset",
    "restore",
    "rev-list",
    "rev-parse",
    "revert",
    "rm",
    "shortlog",
    "show",
    "show-branch",
    "show-index",
    "show-ref",
    "sparse-checkout",
    "stash",
    "status",
    "stripspace",
    "submodule",
    "switch",
    "symbolic-ref",
    "tag",
    "unpack-file",
    "unpack-objects",
    "update-index",
    "update-ref",
    "var",
    "verify-commit",
    "verify-pack",
    "verify-tag",
    "version",
    "whatchanged",
    "worktree",
    "write-tree",
];

static EXPANSION_RE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"\$[\w{(]|`").ok());

fn program_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Cargo config files in the directories above `root` (not in `root` or
/// below it, which the workspace owns). Cargo reads `.cargo/config` and
/// `.cargo/config.toml` in every ancestor of its cwd and has no supported
/// switch to stop that walk, so a config there applies to every cargo
/// command run in the workspace, whatever `CARGO_HOME` says.
pub fn ancestor_cargo_configs(root: &Path) -> Vec<PathBuf> {
    root.ancestors()
        .skip(1)
        .flat_map(|dir| ["config", "config.toml"].map(|f| dir.join(".cargo").join(f)))
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .collect()
}

/// A startup warning when cargo config files sit above any configured
/// workspace root (the default root and each per-agent root); `None` when
/// there are none. `run_cmd` refuses cargo in such a workspace.
pub fn cargo_config_warning(cfg: &ua_core::Config) -> Option<String> {
    let mut roots = vec![cfg.workspace_root()];
    roots.extend(
        cfg.agent_workspaces
            .values()
            .filter(|v| !v.trim().eq_ignore_ascii_case("deny"))
            .map(|v| super::expand_tilde(v.trim())),
    );
    let mut found: Vec<PathBuf> =
        roots.iter().filter_map(|r| r.canonicalize().ok()).flat_map(|r| ancestor_cargo_configs(&r)).collect();
    found.sort();
    found.dedup();
    if found.is_empty() {
        return None;
    }
    let list: Vec<String> = found.iter().map(|p| p.display().to_string()).collect();
    Some(format!(
        "cargo config above a workspace root: {}. Cargo reads every ancestor .cargo/config of its cwd, so \
         run_cmd refuses cargo in that workspace; move the workspace outside that directory tree.",
        list.join(", ")
    ))
}

/// First token naming one of `names` (bare, `=value`, or an unambiguous
/// long-option prefix) or starting with `short`.
fn has_flag<'a>(args: &'a [String], names: &[&str], short: Option<&str>) -> Option<&'a str> {
    for tok in args {
        if names.contains(&tok.as_str()) {
            return Some(tok);
        }
        if tok.starts_with("--") {
            let name = tok.split('=').next().unwrap_or(tok);
            if name.len() >= 3 && names.iter().any(|n| n.starts_with("--") && n.starts_with(name)) {
                return Some(tok);
            }
            continue;
        }
        if let Some(s) = short
            && tok.starts_with(s)
        {
            return Some(tok);
        }
    }
    None
}

/// Short options whose attached value is a path (`git -C/x`, `sort -o/x`).
fn attached_path_value<'a>(prog: &str, tok: &'a str) -> Option<&'a str> {
    let opts: &[&str] = match program_name(prog) {
        "git" => &["-C"],
        "sort" => &["-o", "-T"],
        _ => &[],
    };
    opts.iter().find_map(|o| tok.strip_prefix(o).filter(|v| !v.is_empty()))
}

/// Candidate path strings: bare operands, `--opt=value` and known `-Xvalue`.
fn arg_path_values(prog: &str, rest: &[String]) -> Vec<String> {
    let is_git = program_name(prog) == "git";
    let text_opts = ["-m", "--message"];
    let mut out = Vec::new();
    let mut skip = false;
    for tok in rest {
        if skip {
            skip = false;
            continue;
        }
        if is_git && text_opts.contains(&tok.as_str()) {
            skip = true;
            continue;
        }
        if tok.starts_with("--") {
            if let Some((name, value)) = tok.split_once('=')
                && !(is_git && text_opts.contains(&name))
            {
                out.push(value.to_string());
            }
            continue;
        }
        if tok.starts_with('-') && tok.len() > 2 {
            if let Some(v) = attached_path_value(prog, tok) {
                out.push(v.to_string());
            }
            continue;
        }
        if !tok.starts_with('-') {
            out.push(tok.clone());
        }
    }
    out.retain(|v| !v.is_empty());
    out
}

/// Write destinations of `sort`: `-o F`, `-oF`, `--output[=]F` (by prefix).
fn sort_output_paths(rest: &[String]) -> Vec<String> {
    const VALUE_OPTS: &[&str] = &[
        "--buffer-size",
        "--compress-program",
        "--field-separator",
        "--files0-from",
        "--key",
        "--output",
        "--parallel",
        "--random-source",
        "--sort",
        "--temporary-directory",
    ];
    let mut out = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let tok = &rest[i];
        let next = rest.get(i + 1);
        if tok == "--" {
            break;
        }
        if tok.starts_with("--") {
            let (name, value) = match tok.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (tok.as_str(), None),
            };
            let hits: Vec<&&str> = VALUE_OPTS.iter().filter(|o| o.starts_with(name)).collect();
            if name.len() >= 3 && hits.len() == 1 {
                if *hits[0] == "--output"
                    && let Some(v) = value.map(str::to_string).or_else(|| next.cloned())
                {
                    out.push(v);
                }
                if value.is_none() && next.is_some() {
                    i += 1;
                }
            }
        } else if tok.starts_with('-') && tok.len() > 1 {
            let cluster = &tok[1..];
            for (j, c) in cluster.char_indices() {
                if !"ktoST".contains(c) {
                    continue;
                }
                let value = &cluster[j + c.len_utf8()..];
                if c == 'o' {
                    if !value.is_empty() {
                        out.push(value.to_string());
                    } else if let Some(n) = next {
                        out.push(n.clone());
                    }
                }
                if value.is_empty() && next.is_some() {
                    i += 1;
                }
                break;
            }
        }
        i += 1;
    }
    out.retain(|v| !v.is_empty());
    out
}

/// `uniq [OPTION]... [IN [OUT]]`: OUT is a write.
fn uniq_output_paths(rest: &[String]) -> Vec<String> {
    let mut operands: Vec<String> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let tok = &rest[i];
        if tok == "--" {
            operands.extend(rest[i + 1..].iter().cloned());
            break;
        }
        if ["-f", "-s", "-w"].contains(&tok.as_str()) {
            i += 2;
            continue;
        }
        if !tok.starts_with('-') || tok == "-" {
            operands.push(tok.clone());
        }
        i += 1;
    }
    operands.into_iter().skip(1).take(1).collect()
}

fn expand_user(tok: &str) -> PathBuf {
    if (tok == "~" || tok.starts_with("~/"))
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(tok.trim_start_matches('~').trim_start_matches('/'));
    }
    PathBuf::from(tok)
}

fn resolve_arg(tok: &str, workdir: &Path) -> PathBuf {
    let p = expand_user(tok);
    let joined = if p.is_absolute() { p } else { workdir.join(p) };
    canonicalize_lenient(&joined).unwrap_or(joined)
}

/// True when a path argument lands inside `.git`/`.hg` (config, hooks) or a `.husky` tree.
fn targets_hook_dir(value: &str, workdir: &Path) -> bool {
    let resolved = resolve_arg(value, workdir);
    let parts: Vec<String> = resolved
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => Some(n.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect();
    if parts.iter().any(|p| p == ".husky") {
        return true;
    }
    parts.iter().take(parts.len().saturating_sub(1)).any(|p| p == ".git" || p == ".hg")
}

fn sed_in_place(rest: &[String]) -> bool {
    rest.iter().any(|a| {
        a.starts_with("--in-place") || (a.starts_with('-') && !a.starts_with("--") && a[1..].contains('i'))
    })
}

/// Inline sed scripts and `-f` script files.
fn sed_sources(rest: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut scripts, mut files) = (Vec::new(), Vec::new());
    let mut explicit = false;
    let mut first_operand: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        let tok = &rest[i];
        let next = rest.get(i + 1).cloned();
        if tok == "--" {
            if first_operand.is_none() {
                first_operand = next;
            }
            break;
        }
        if tok == "-e" || tok == "--expression" {
            explicit = true;
            scripts.extend(next);
            i += 2;
            continue;
        }
        if tok == "-f" || tok == "--file" {
            explicit = true;
            files.extend(next);
            i += 2;
            continue;
        }
        if let Some(v) = tok.strip_prefix("--expression=") {
            explicit = true;
            scripts.push(v.to_string());
        } else if let Some(v) = tok.strip_prefix("--file=") {
            explicit = true;
            files.push(v.to_string());
        } else if tok.starts_with('-') && !tok.starts_with("--") && tok.len() > 1 {
            // A short cluster: the first e/f takes the rest (or the next token).
            let cluster = &tok[1..];
            if let Some(pos) = cluster.find(['e', 'f', 'l']) {
                let opt = &cluster[pos..pos + 1];
                let value = &cluster[pos + 1..];
                let v = if value.is_empty() {
                    i += 1;
                    next.clone().unwrap_or_default()
                } else {
                    value.to_string()
                };
                match opt {
                    "e" => {
                        explicit = true;
                        scripts.push(v);
                    }
                    "f" => {
                        explicit = true;
                        files.push(v);
                    }
                    _ => {}
                }
            }
        } else if !tok.starts_with('-') && first_operand.is_none() {
            first_operand = Some(tok.clone());
        }
        i += 1;
    }
    if !explicit && let Some(s) = first_operand {
        scripts.push(s);
    }
    (scripts, files)
}

/// Skip a delimited sed field starting after the opening delimiter.
fn skip_delimited(s: &[char], mut i: usize, delim: char) -> usize {
    while i < s.len() {
        if s[i] == '\\' {
            i += 2;
            continue;
        }
        if s[i] == delim {
            return i + 1;
        }
        i += 1;
    }
    i
}

/// True when a sed script uses `e`, `w` or `W` (as a command or an `s` flag).
fn sed_script_has_exec_or_write(script: &str) -> bool {
    let s: Vec<char> = script.chars().collect();
    let n = s.len();
    let mut i = 0;
    while i < n {
        let begin = i;
        // Skip separators and addresses.
        while i < n && (s[i].is_whitespace() || s[i] == ';' || s[i] == '{' || s[i] == '}') {
            i += 1;
        }
        loop {
            if i >= n {
                break;
            }
            let c = s[i];
            if c.is_ascii_digit() || matches!(c, '$' | ',' | '!' | '~' | '+' | ' ') {
                i += 1;
            } else if c == '/' {
                i = skip_delimited(&s, i + 1, '/');
            } else if c == '\\' && i + 1 < n {
                let d = s[i + 1];
                i = skip_delimited(&s, i + 2, d);
            } else if (c == 'I' || c == 'M') && i > begin && matches!(s[i - 1], '/' | 'I' | 'M') {
                i += 1;
            } else {
                break;
            }
        }
        if i >= n {
            break;
        }
        let cmd = s[i];
        i += 1;
        match cmd {
            'e' | 'w' | 'W' => return true,
            's' => {
                if i >= n {
                    break;
                }
                let d = s[i];
                i = skip_delimited(&s, i + 1, d);
                i = skip_delimited(&s, i, d);
                while i < n && !matches!(s[i], ';' | '\n' | '}') {
                    if matches!(s[i], 'e' | 'w') {
                        return true;
                    }
                    i += 1;
                }
            }
            'y' => {
                if i < n {
                    let d = s[i];
                    i = skip_delimited(&s, i + 1, d);
                    i = skip_delimited(&s, i, d);
                }
            }
            'a' | 'i' | 'c' | 'r' | 'R' | 'b' | 't' | 'T' | ':' => {
                // Text, file name or label to the end of the line (labels also end at ';').
                let stop_semicolon = matches!(cmd, 'b' | 't' | 'T' | ':');
                while i < n && s[i] != '\n' && !(stop_semicolon && s[i] == ';') {
                    i += 1;
                }
            }
            _ => {}
        }
        if i <= begin {
            i = begin + 1;
        }
    }
    false
}

/// True when awk is given program text, `-f`/`-e`, or an explicit `system(`.
fn awk_can_run_code(rest: &[String]) -> bool {
    if rest.iter().any(|t| t.contains("system(")) {
        return true;
    }
    let program_opts = ["-f", "--file", "-e", "--source", "-E", "--exec"];
    let mut i = 0;
    while i < rest.len() {
        let tok = rest[i].as_str();
        if tok == "--" {
            return i + 1 < rest.len();
        }
        if program_opts.contains(&tok) || tok.starts_with("--file=") || tok.starts_with("--source=") {
            return true;
        }
        if (tok.starts_with("-f") || tok.starts_with("-e")) && tok.len() > 2 && !tok.starts_with("--") {
            return true;
        }
        let takes_value = ["-F", "-v", "--field-separator", "--assign"].contains(&tok);
        let attached = (tok.starts_with("-F") || tok.starts_with("-v")) && tok.len() > 2
            || tok.starts_with("--field-separator=")
            || tok.starts_with("--assign=");
        if takes_value || attached {
            i += if attached { 1 } else { 2 };
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        return true;
    }
    false
}

fn git_config_writes(args: &[String]) -> bool {
    const READ_FLAGS: &[&str] = &[
        "--get",
        "--get-all",
        "--get-regexp",
        "--get-urlmatch",
        "--get-color",
        "--get-colorbool",
        "-l",
        "--list",
    ];
    const WRITE_FLAGS: &[&str] = &[
        "--add",
        "--replace-all",
        "--unset",
        "--unset-all",
        "--rename-section",
        "--remove-section",
        "-e",
        "--edit",
    ];
    const VALUE_FLAGS: &[&str] = &["-f", "--file", "--blob", "-t", "--type", "--default", "--comment"];
    let mut positionals: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_str();
        if READ_FLAGS.contains(&tok) {
            return false;
        }
        if WRITE_FLAGS.contains(&tok) {
            return true;
        }
        if VALUE_FLAGS.contains(&tok) {
            i += 2;
            continue;
        }
        if !tok.starts_with('-') {
            positionals.push(tok);
        }
        i += 1;
    }
    if positionals.first().is_some_and(|p| *p == "get" || *p == "list") {
        return false;
    }
    positionals.len() != 1 || ["set", "unset", "edit"].contains(&positionals[0])
}

/// Why a git argv runs a caller-supplied program, if it does.
fn git_exec_reason(rest: &[String]) -> Option<String> {
    let (sub, args) = git_subcommand(rest)?;
    if !GIT_KNOWN_SUBCOMMANDS.contains(&sub.as_str()) {
        return Some(format!(
            "git {sub} is not a built-in git command; it may run alias.{sub}=!cmd from a repository \
             config or an external git-{sub} program"
        ));
    }
    if sub == "config" && git_config_writes(args) {
        return Some(
            "git config writes configuration; a key such as alias.<name>=!cmd, core.pager, \
             core.hooksPath or include.path makes a later git call run an arbitrary program"
                .into(),
        );
    }
    if ["filter-branch", "difftool", "mergetool"].contains(&sub.as_str()) {
        return Some(format!("git {sub} runs external commands or configured tools"));
    }
    if sub == "grep"
        && let Some(hit) = has_flag(args, &["--open-files-in-pager"], Some("-O"))
    {
        return Some(format!("git grep {hit} runs the named pager program"));
    }
    if sub == "rebase"
        && let Some(hit) = has_flag(args, &["--exec"], Some("-x"))
    {
        return Some(format!("git rebase {hit} runs a command after each commit"));
    }
    if sub == "bisect" && args.first().is_some_and(|a| a == "run") {
        return Some("git bisect run executes a command".into());
    }
    if sub == "submodule" && args.iter().any(|a| a == "foreach") {
        return Some("git submodule foreach executes a command in every submodule".into());
    }
    if ["ls-remote", "fetch", "pull", "clone", "push", "archive"].contains(&sub.as_str()) {
        let mut hit = has_flag(args, &["--upload-pack", "--receive-pack", "--exec", "--template"], None);
        if hit.is_none() && (sub == "ls-remote" || sub == "clone") {
            hit = has_flag(args, &[], Some("-u"));
        }
        if let Some(hit) = hit {
            return Some(format!("git {sub} {hit} runs a supplied program or installs template hooks"));
        }
    }
    None
}

/// `no` / `maybe` / `yes`: a heuristic estimate of filesystem mutation.
fn mutation_risk(argv: &[String]) -> &'static str {
    let Some((prog, rest)) = argv.split_first() else { return "no" };
    let name = program_name(prog);
    if READ_ONLY_PROGRAMS.contains(&name) {
        return "no";
    }
    match name {
        "sort" => {
            if sort_output_paths(rest).is_empty() {
                "no"
            } else {
                "yes"
            }
        }
        "uniq" => {
            if uniq_output_paths(rest).is_empty() {
                "no"
            } else {
                "yes"
            }
        }
        "find" => {
            if rest.iter().any(|t| FIND_SIDE_EFFECTS.contains(&t.as_str())) {
                "yes"
            } else {
                "no"
            }
        }
        "sed" => {
            if sed_in_place(rest) {
                "yes"
            } else {
                "no"
            }
        }
        "ruff" => {
            let format_writes = rest.first().is_some_and(|a| a == "format")
                && !rest.iter().any(|a| a == "--check" || a == "--diff");
            if rest.iter().any(|a| a == "--fix") || format_writes { "yes" } else { "no" }
        }
        "git" => match git_subcommand(rest) {
            Some((sub, args))
                if GIT_OUTPUT_SUBCOMMANDS.contains(&sub.as_str())
                    && has_flag(args, &["--output"], None).is_some() =>
            {
                "yes"
            }
            Some((sub, _)) if GIT_READ_ONLY.contains(&sub.as_str()) => "no",
            Some((sub, _)) if GIT_MUTATING.contains(&sub.as_str()) => "yes",
            _ => "maybe",
        },
        _ => "maybe",
    }
}

/// Advisory findings for a vetted argv.
fn advisories(argv: &[String], workdir: &Path, root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((prog, rest)) = argv.split_first() else { return out };
    let name = program_name(prog);

    let mut syntax: Vec<&str> = rest
        .iter()
        .map(String::as_str)
        .filter(|t| SHELL_SYNTAX_TOKENS.contains(t) || (t.len() > 1 && t.ends_with(';')))
        .filter(|t| !(name == "find" && *t == ";"))
        .collect();
    syntax.sort_unstable();
    syntax.dedup();
    if !syntax.is_empty() {
        out.push(finding(
            "warn",
            "shell-syntax",
            format!(
                "run_cmd uses no shell: {} reach {name} as literal arguments, so pipes, redirection and \
                 chaining will not happen. Make separate run_cmd calls instead (or fs_write to save output).",
                syntax.join(", ")
            ),
        ));
    }
    if let Some(rx) = EXPANSION_RE.as_ref()
        && let Some(tok) = argv.iter().find(|t| rx.is_match(t))
    {
        out.push(finding(
            "warn",
            "no-expansion",
            format!(
                "no shell expansion: {tok:?} is passed literally ($VAR, $(...) and backticks never expand)."
            ),
        ));
    }

    // Arguments that resolve outside the workspace.
    let output_paths = match name {
        "sort" => sort_output_paths(rest),
        "uniq" => uniq_output_paths(rest),
        _ => Vec::new(),
    };
    let candidates =
        rest.iter().map(|r| (r.as_str(), false)).chain(output_paths.iter().map(|r| (r.as_str(), true)));
    for (raw, explicit) in candidates {
        let mut tok = raw;
        if !explicit && tok.starts_with('-') {
            if let Some((_, v)) = tok.split_once('=') {
                tok = v;
            } else if let Some(v) = attached_path_value(prog, tok).filter(|_| !tok.starts_with("--")) {
                tok = v;
            } else {
                continue;
            }
        }
        if tok.is_empty() {
            continue;
        }
        let looks_like_path = tok.starts_with('/')
            || tok.starts_with('~')
            || tok.starts_with("./")
            || tok.starts_with("../")
            || tok == "."
            || tok == ".."
            || tok.contains("/../");
        if !explicit && !looks_like_path {
            continue;
        }
        if !resolve_arg(tok, workdir).starts_with(root) {
            out.push(finding(
                "warn",
                "path-escape",
                format!(
                    "argument {raw:?} resolves outside the workspace root. run_cmd only confines cwd, not \
                     arguments; {name} could read or write there. Keep paths inside the workspace."
                ),
            ));
        }
    }

    // Content readers must not print what fs_read refuses.
    if CONTENT_READERS.contains(&name) {
        for value in arg_path_values(prog, rest) {
            let candidate = {
                let p = expand_user(&value);
                if p.is_absolute() { p } else { workdir.join(p) }
            };
            if candidate.symlink_metadata().is_err() {
                continue;
            }
            let resolved = canonicalize_lenient(&candidate).unwrap_or(candidate);
            let inside = resolved
                .strip_prefix(root)
                .map(Path::to_path_buf)
                .unwrap_or_else(|_| resolved.file_name().map(PathBuf::from).unwrap_or_default());
            let refused =
                inside.components().find_map(|c| guard_secret_filename(Path::new(c.as_os_str())).err());
            if let Some(e) = refused {
                out.push(finding("block", "secret-path", format!("{name}: {e}")));
                break;
            }
        }
    }

    if name == "find"
        && let Some(hit) = rest.iter().find(|t| FIND_SIDE_EFFECTS.contains(&t.as_str()))
    {
        out.push(finding(
            "warn",
            "allowlist-bypass",
            format!(
                "find {hit} writes files or runs an arbitrary program, sidestepping the run_cmd allowlist."
            ),
        ));
    }
    if name == "sort"
        && let Some(hit) = has_flag(rest, &["--compress-program"], None)
    {
        out.push(finding(
            "warn",
            "allowlist-bypass",
            format!("sort {hit} pipes data through the named program, sidestepping the run_cmd allowlist."),
        ));
    }
    let hook_candidates = if READ_ONLY_PROGRAMS.contains(&name) {
        Vec::new()
    } else if name == "sort" || name == "uniq" {
        output_paths.clone()
    } else {
        arg_path_values(prog, rest)
    };
    if let Some(hit) = hook_candidates.iter().find(|v| targets_hook_dir(v, workdir)) {
        out.push(finding(
            "warn",
            "allowlist-bypass",
            format!(
                "argument {hit:?} points into .git, .hg or .husky; a hook or config written there runs a \
                 program on the next git operation, sidestepping the run_cmd allowlist."
            ),
        ));
    }
    if name == "awk" && awk_can_run_code(rest) {
        out.push(finding(
            "warn",
            "allowlist-bypass",
            "awk program text or a -f/-e script can call system(), sidestepping the run_cmd allowlist.",
        ));
    }
    if name == "sed" {
        let (scripts, files) = sed_sources(rest);
        if scripts.iter().any(|s| sed_script_has_exec_or_write(s)) {
            out.push(finding(
                "warn",
                "allowlist-bypass",
                "sed script contains the e, w or W command, which runs a program or writes a file and \
                 sidesteps the run_cmd allowlist.",
            ));
        }
        if let Some(f) = files.first() {
            out.push(finding(
                "warn",
                "allowlist-bypass",
                format!("sed -f {f:?}: a script file is not inspected and may use e, w or W."),
            ));
        }
    }
    if name == "git" {
        for tok in git_global_options(rest) {
            if tok == "--git-dir"
                || tok == "--work-tree"
                || tok.starts_with("--git-dir=")
                || tok.starts_with("--work-tree=")
            {
                out.push(finding(
                    "warn",
                    "allowlist-bypass",
                    format!(
                        "git {tok} selects a repository whose config (aliases, pager, hooks) may have been \
                         written by the agent, sidestepping the run_cmd allowlist."
                    ),
                ));
            }
        }
        if let Some(reason) = git_exec_reason(rest) {
            out.push(finding(
                "warn",
                "allowlist-bypass",
                format!("{reason}, sidestepping the run_cmd allowlist."),
            ));
        }
        if let Some((sub, _)) = git_subcommand(rest)
            && GIT_NETWORK.contains(&sub.as_str())
        {
            out.push(finding("warn", "network", format!("git {sub} contacts remote repositories.")));
        }
    }
    let info_only = !rest.is_empty() && rest.iter().all(|a| HARMLESS_INFO_ARGS.contains(&a.as_str()));
    if (name == "python3" || name == "python") && !info_only {
        out.push(finding(
            "warn",
            "arbitrary-code",
            format!(
                "{name} executes arbitrary code (a script, -m, -c, or the REPL); only its cwd is confined to \
                 the workspace."
            ),
        ));
    }
    if name == "cargo" || name.starts_with("cargo-") {
        let found = ancestor_cargo_configs(root);
        if !found.is_empty() {
            let list: Vec<String> = found.iter().map(|p| p.display().to_string()).collect();
            out.push(finding(
                "block",
                "cargo-config",
                format!(
                    "cargo reads every .cargo/config in the directories above its cwd, so it would apply {} \
                     (aliases, [env], build.rustc-wrapper, source replacement, credential providers) from \
                     outside the workspace. Move the workspace outside that directory tree.",
                    list.join(", ")
                ),
            ));
        }
    }
    if ["uv", "pytest", "cargo"].contains(&name) && !info_only {
        out.push(finding(
            "warn",
            "arbitrary-code",
            format!("{name} executes arbitrary project code; only its cwd is confined to the workspace."),
        ));
    }
    out
}

fn program_on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| find_on_path(program, &path).is_some())
}

fn find_on_path(program: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path).map(|dir| dir.join(program)).find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            m.is_file() && m.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            m.is_file()
        }
    })
}

/// Resolve `cwd` inside the workspace root; it must be a directory.
fn resolve_cwd(sb: &Sandbox, cwd: &str) -> UaResult<PathBuf> {
    let dir = resolve_in_root(cwd, std::slice::from_ref(&sb.root), true)?;
    if !dir.is_dir() {
        return Err(UaError::invalid(format!("cwd {cwd:?} is not a directory")));
    }
    Ok(dir)
}

fn run_cmd_check(ctx: &ToolCtx, a: CheckArgs) -> UaResult<Value> {
    let sb = sandbox(ctx)?;
    let mut findings = Vec::new();
    let argv: Vec<String> = match vet_command(&a.command, &ctx.hub.cfg().shell_allowlist()) {
        Ok(v) => std::iter::once(v.program).chain(v.args).collect(),
        Err(e) => {
            let code = match &e {
                UaError::Denied { reason_code, .. } if reason_code == "destructive" => "destructive",
                _ => "rejected",
            };
            findings.push(finding("block", code, e.to_string()));
            split_command(&a.command).unwrap_or_default()
        }
    };
    let workdir = match resolve_cwd(&sb, &a.cwd) {
        Ok(d) => d,
        Err(e) => {
            findings.push(finding("block", "cwd", e.to_string()));
            sb.root.clone()
        }
    };
    let program = argv.first().cloned().unwrap_or_default();
    let program_found = !program.is_empty() && !program.contains('/') && program_on_path(&program);
    if !program.is_empty() && !program_found {
        findings.push(finding(
            "warn",
            "not-found",
            format!("{program:?} not found on PATH; run_cmd would return exit code 127."),
        ));
    }
    findings.extend(advisories(&argv, &workdir, &sb.root));
    let blocked = findings.iter().any(|f| f.severity == "block");
    let warned = findings.iter().any(|f| f.severity == "warn");
    Ok(json!({
        "ok": !blocked,
        "verdict": if blocked { "block" } else if warned { "warn" } else { "ok" },
        "argv": argv,
        "program": program,
        "program_found": program_found,
        "mutates": mutation_risk(&argv),
        "findings": findings,
    }))
}

/// Force the approval gate for a dangerous command unless the registry
/// already gated this call because `run_cmd` is in `approval_tools`.
async fn force_gate(ctx: &ToolCtx, payload: Value) -> UaResult<()> {
    if ctx.hub.cfg().approval_tools.iter().any(|t| t == "run_cmd") {
        return Ok(());
    }
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let outcome = ctx
        .hub
        .db()
        .write_async(move |tx| approvals::gate(tx, hub.cfg(), &caller, "run_cmd", &payload))
        .await?;
    match outcome {
        GateOutcome::Pass { .. } => Ok(()),
        GateOutcome::Pending { approval_id } => {
            Err(UaError::ApprovalRequired { tool: "run_cmd".into(), approval_id })
        }
        GateOutcome::Denied { approval_id, reason } => Err(UaError::denied(
            "approval_denied",
            format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
        )),
    }
}

async fn run_cmd(ctx: ToolCtx, a: RunArgs) -> UaResult<Value> {
    let sb = sandbox(&ctx)?;
    let vetted = vet_command(&a.command, &ctx.hub.cfg().shell_allowlist())?;
    let workdir = resolve_cwd(&sb, &a.cwd)?;
    let argv: Vec<String> =
        std::iter::once(vetted.program.clone()).chain(vetted.args.iter().cloned()).collect();
    let findings = advisories(&argv, &workdir, &sb.root);
    if let Some(block) = findings.iter().find(|f| f.severity == "block") {
        return Err(UaError::denied(block.code, block.message.clone()));
    }
    let warnings: Vec<String> =
        findings.iter().filter(|f| f.severity == "warn").map(|f| f.message.clone()).collect();

    let mut codes: Vec<&str> =
        findings.iter().map(|f| f.code).filter(|c| APPROVAL_REQUIRED_CODES.contains(c)).collect();
    if vetted.program == "git" && git_subcommand(&vetted.args).is_some_and(|(s, _)| s == "push") {
        codes.push("network");
    }
    codes.sort_unstable();
    codes.dedup();
    if !codes.is_empty() {
        force_gate(&ctx, json!({ "command": a.command, "cwd": a.cwd, "advisory_codes": codes })).await?;
    }

    // A fresh, empty HOME per call, removed afterwards: commands never see
    // the operator's dotfiles, cargo home or credential helpers, and nothing
    // one call writes under `~` (tool config, rc files) reaches a later call.
    // What common work needs from HOME is set explicitly instead: a git
    // identity for the caller, the Rust toolchain on PATH, and the caller's
    // own persistent caches.
    let scratch_home = ScratchHome::new()?;
    let ua_home = &ctx.hub.cfg().home;
    let host = HostRust::get(ua_home).await;
    let mut env = command_env(ua_home, &ctx.caller.label, &scratch_home.path, &host);
    if vetted.program == "git" {
        // Never discover a bare repository an agent laid out with fs_write.
        for (k, v) in [
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "safe.bareRepository"),
            ("GIT_CONFIG_VALUE_0", "explicit"),
        ] {
            env.push((k.into(), v.into()));
        }
    }
    let timeout = Duration::from_secs(a.timeout_s.clamp(1, CMD_TIMEOUT_CAP_S as i64) as u64);
    let res = run_program(&vetted.program, &vetted.args, &workdir, &env, timeout, CMD_OUTPUT_CAP).await;
    let (exit_code, mut stdout, mut stderr, truncated, timed_out) = match res {
        Ok(o) => {
            let truncated = o.stdout_total + o.stderr_total > CMD_OUTPUT_CAP;
            (o.exit_code, o.stdout, o.stderr, truncated, o.timed_out)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            (127, Vec::new(), format!("command not found: {}", vetted.program).into_bytes(), false, false)
        }
        Err(e) => {
            (126, Vec::new(), format!("could not start {}: {e}", vetted.program).into_bytes(), false, false)
        }
    };
    if truncated {
        stdout.truncate(CMD_OUTPUT_CAP / 2);
        stderr.truncate(CMD_OUTPUT_CAP / 2);
    }
    record(
        &ctx,
        "agent.cmd.ran",
        json!({
            "program": vetted.program,
            "command_sha256": sha256_hex(a.command.as_bytes()),
            "cwd": sb.rel(&workdir),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "truncated": truncated,
            "advisory_codes": codes,
        }),
    )
    .await?;
    Ok(json!({
        "exit_code": exit_code,
        "stdout": String::from_utf8_lossy(&stdout),
        "stderr": String::from_utf8_lossy(&stderr),
        "truncated": truncated,
        "timed_out": timed_out,
        "warnings": warnings,
    }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "run_cmd",
            "Run an allowlisted program inside the workspace without a shell (metacharacters are refused \
             or literal). Timeout 1-120 s kills the whole process group; output capped at 50 KB. Commands \
             with path-escape, allowlist-bypass or arbitrary-code advisories, and git push, need a one-time \
             human approval. Returns {exit_code, stdout, stderr, truncated, timed_out, warnings}.",
            run_cmd,
        )
        .family("workspace"),
    );
    r.add(
        tool(
            "run_cmd_check",
            "Vet a run_cmd invocation without executing it: allowlist, cwd, destructive argv, literal shell \
             syntax, unexpanded $VAR, workspace-escaping arguments, allowlist bypasses and arbitrary code. \
             Returns {ok, verdict, argv, program, program_found, mutates, findings}.",
            |ctx: ToolCtx, a: CheckArgs| async move { run_cmd_check(&ctx, a) },
        )
        .family("workspace")
        .read_only(),
    );
}

/// Run homes older than this are left over from a crashed process; no call
/// lives longer than [`CMD_TIMEOUT_CAP_S`] plus a few seconds.
const STALE_RUN_HOME: Duration = Duration::from_secs(600);

/// Parent of the per-call homes: `$XDG_RUNTIME_DIR/ua-run/` when set, else
/// `<temp>/ua-run-<uid>/`. Outside `$UA_HOME`, so a command never lands in
/// the hub's data directory, and on a runtime dir when there is one.
fn run_home_parent() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        Some(rt) => PathBuf::from(rt).join("ua-run"),
        None => {
            #[cfg(unix)]
            // SAFETY: geteuid has no preconditions and cannot fail.
            let uid = unsafe { libc::geteuid() };
            #[cfg(not(unix))]
            let uid = 0;
            std::env::temp_dir().join(format!("ua-run-{uid}"))
        }
    }
}

/// Create `dir` (mode 0700) or accept an existing one only when it is a real
/// directory owned by this user, never a symlink: in a shared temp dir
/// another user could have created the name first.
fn private_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir_all(dir)?,
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(std::io::Error::other(format!("{} is not a directory", dir.display())));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::other(format!("{} belongs to another user", dir.display())));
        }
        if meta.mode() & 0o777 != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Remove run homes left over by a crashed process. `ua serve` calls this
/// at startup. Only entries older than a few minutes go, so a concurrent
/// process's live homes are kept.
pub fn sweep_run_homes() {
    let parent = run_home_parent();
    if private_dir(&parent).is_err() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(&parent) else { return };
    for entry in entries.flatten() {
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > STALE_RUN_HOME);
        if stale {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// `GIT_AUTHOR_*` and `GIT_COMMITTER_*` for the caller, so `git commit`
/// works in an empty HOME and agent commits name the agent. The address
/// uses the reserved `.invalid` domain.
fn git_identity_env(label: &str) -> Vec<(String, String)> {
    let name: String = label.chars().filter(|c| !c.is_control() && !matches!(c, '<' | '>')).collect();
    let name = if name.trim().is_empty() { "agent".to_string() } else { name.trim().to_string() };
    let local: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
        .collect();
    let local = local.trim_matches(['.', '-']);
    let email = format!("{}@agents.invalid", if local.is_empty() { "agent" } else { local });
    ["AUTHOR", "COMMITTER"]
        .iter()
        .flat_map(|who| {
            [(format!("GIT_{who}_NAME"), name.clone()), (format!("GIT_{who}_EMAIL"), email.clone())]
        })
        .collect()
}

/// What `run_cmd` takes from the hub's own environment, resolved once: the
/// hub's PATH with the default Rust toolchain's `bin` directory in front.
///
/// The toolchain is reached through its real `bin` directory (the one that
/// holds `cargo` and `rustc` themselves, not the rustup proxies), so a
/// command never gets `RUSTUP_HOME` or the operator's `CARGO_HOME`. Rustup
/// proxies need a `RUSTUP_HOME`, and through it a command could install
/// toolchains or change the operator's rustup settings; with the resolved
/// `bin` first on PATH they are never reached for `cargo` or `rustc`. The
/// cost: a `rust-toolchain.toml` in the workspace and `cargo +toolchain`
/// are not honored, and `rustup` itself does not work inside `run_cmd`.
#[derive(Debug, Clone)]
struct HostRust {
    /// PATH for commands.
    path: String,
    /// The toolchain `bin` first on `path`, when one was found.
    toolchain: Option<PathBuf>,
}

/// The last successful resolution. A failed one is not kept, so the next
/// call tries again; a kept one is dropped once its toolchain is gone.
static HOST_RUST: tokio::sync::Mutex<Option<Arc<HostRust>>> = tokio::sync::Mutex::const_new(None);

impl HostRust {
    async fn get(ua_home: &Path) -> Arc<HostRust> {
        let vars: Vec<(String, String)> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        Self::cached(&HOST_RUST, &vars, ua_home).await
    }

    /// `slot`'s resolution while its toolchain still holds a `rustc`, else
    /// a fresh one, kept only when it found a toolchain.
    async fn cached(
        slot: &tokio::sync::Mutex<Option<Arc<HostRust>>>,
        vars: &[(String, String)],
        ua_home: &Path,
    ) -> Arc<HostRust> {
        let mut slot = slot.lock().await;
        if let Some(host) = slot.as_ref()
            && host.toolchain.as_ref().is_some_and(|bin| is_executable(&bin.join("rustc")))
        {
            return host.clone();
        }
        let host = Arc::new(HostRust::resolve(vars, ua_home).await);
        *slot = host.toolchain.is_some().then(|| host.clone());
        host
    }

    /// Resolve from `vars` (the hub's environment). The default toolchain
    /// is asked for with `ua_home` as the working directory, a hub-owned
    /// directory, so no override file an agent wrote can pick it. The hub
    /// user's cargo `bin` directories (`$CARGO_HOME/bin`, `~/.cargo/bin`:
    /// `cargo install` binaries, `cargo-*` subcommands, rustup proxies) are
    /// dropped from PATH; the toolchain's own `bin` goes first instead.
    async fn resolve(vars: &[(String, String)], ua_home: &Path) -> HostRust {
        let path = var(vars, "PATH").unwrap_or_else(|| "/usr/bin:/bin:/usr/local/bin".into());
        let toolchain = toolchain_bin(vars, &path, ua_home).await;
        let dropped = operator_cargo_bins(vars);
        let same = |a: &Path, b: &Path| {
            a == b || a.canonicalize().ok().is_some_and(|c| b.canonicalize().ok() == Some(c))
        };
        let rest = std::env::split_paths(&path).filter(|p| {
            !dropped.iter().any(|d| same(p, d)) && toolchain.as_deref().is_none_or(|t| !same(p, t))
        });
        let path = std::env::join_paths(toolchain.clone().into_iter().chain(rest))
            .ok()
            .and_then(|p| p.into_string().ok())
            .unwrap_or_else(|| "/usr/bin:/bin".into());
        HostRust { path, toolchain }
    }
}

/// The hub user's cargo `bin` directories: `$CARGO_HOME/bin` and
/// `$HOME/.cargo/bin`.
fn operator_cargo_bins(vars: &[(String, String)]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(h) = var(vars, "CARGO_HOME") {
        out.push(PathBuf::from(h).join("bin"));
    }
    if let Some(h) = var(vars, "HOME") {
        out.push(PathBuf::from(h).join(".cargo").join("bin"));
    }
    out
}

fn var(vars: &[(String, String)], key: &str) -> Option<String> {
    vars.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).filter(|v| !v.is_empty())
}

/// The `bin` directory of the toolchain `rustc --print sysroot` names, when
/// it holds a `rustc`. `rustc` is looked up in `$CARGO_HOME/bin`, then PATH.
async fn toolchain_bin(vars: &[(String, String)], path: &str, cwd: &Path) -> Option<PathBuf> {
    let rustc = var(vars, "CARGO_HOME")
        .map(|h| PathBuf::from(h).join("bin").join("rustc"))
        .filter(|p| is_executable(p))
        .or_else(|| find_on_path("rustc", std::ffi::OsStr::new(path)))?;
    let args = ["--print".to_string(), "sysroot".to_string()];
    let cwd = if cwd.is_dir() { cwd.to_path_buf() } else { std::env::temp_dir() };
    let out = run_program(&rustc.to_string_lossy(), &args, &cwd, vars, Duration::from_secs(30), 4096).await;
    let out = out.ok().filter(|o| o.exit_code == 0 && !o.timed_out)?;
    let sysroot = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    let bin = sysroot.join("bin");
    (sysroot.is_absolute() && is_executable(&bin.join("rustc"))).then_some(bin)
}

/// The per-caller cache directory name: the label reduced to safe
/// characters, plus a digest of the exact label so two labels that reduce
/// to the same text still get different directories.
fn cache_key(label: &str) -> String {
    let safe: String = label
        .chars()
        .take(48)
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
        .collect();
    let safe = safe.trim_matches(['.', '-']);
    let safe = if safe.is_empty() { "agent" } else { safe };
    format!("{safe}-{}", &sha256_hex(label.as_bytes())[..12])
}

/// Touched in a cache directory each time a call uses it; its mtime is the
/// last use [`prune_run_caches`] goes by.
const CACHE_MARKER: &str = ".last-used";
/// Cache directories unused for this long are removed at `ua serve` startup.
pub const RUN_CACHE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);

/// Create `p` or set its modification time to now.
fn touch(p: &Path) {
    if let Ok(f) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(p) {
        let _ = f.set_modified(std::time::SystemTime::now());
    }
}

/// Remove the per-caller cache directories under `$UA_HOME/run-cache/`
/// whose marker is older than `max_age`; returns how many went. A directory
/// without a marker (made before markers existed) gets one now and is kept,
/// so its age counts from today. Only real directories directly under a
/// private `run-cache/` are touched; symlinks are left alone.
pub fn prune_run_caches(ua_home: &Path, max_age: Duration) -> usize {
    let root = ua_home.join("run-cache");
    if std::fs::symlink_metadata(&root).is_err() || private_dir(&root).is_err() {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(&root) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        let dir = entry.path();
        if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        let marker = dir.join(CACHE_MARKER);
        let age = match std::fs::symlink_metadata(&marker) {
            Ok(m) => m.modified().ok().and_then(|t| t.elapsed().ok()),
            Err(_) => {
                touch(&marker);
                continue;
            }
        };
        if age.is_some_and(|a| a > max_age) && std::fs::remove_dir_all(&dir).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Files that would make a cargo home more than a download cache.
const CARGO_HOME_SCRUB: &[&str] = &["config", "config.toml", "credentials", "credentials.toml"];

/// PATH, `CARGO_HOME`, `XDG_CACHE_HOME` and `UV_CACHE_DIR` for one caller.
///
/// The caches persist between calls, so tools do not download the same
/// packages every time, but each caller label has its own directory
/// (`$UA_HOME/run-cache/<label>-<digest>/`), so one agent cannot poison
/// another agent's caches. `CARGO_HOME` is that directory's `cargo/`, never
/// the operator's: cargo config and credential files are removed from it
/// before every call, so it only ever serves as the registry and git cache.
/// Without a usable cache directory, the cache variables are left out and
/// tools fall back to the empty per-call HOME.
fn toolchain_and_cache_env(ua_home: &Path, label: &str, host: &HostRust) -> Vec<(String, String)> {
    let mut out = vec![("PATH".to_string(), host.path.clone())];
    let root = ua_home.join("run-cache");
    let dir = root.join(cache_key(label));
    if private_dir(&root).is_err() || private_dir(&dir).is_err() {
        return out;
    }
    touch(&dir.join(CACHE_MARKER));
    let cargo = dir.join("cargo");
    if std::fs::create_dir_all(&cargo).is_ok() {
        for name in CARGO_HOME_SCRUB {
            let p = cargo.join(name);
            if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
                let _ = std::fs::remove_dir_all(&p);
            } else {
                let _ = std::fs::remove_file(&p);
            }
        }
        out.push(("CARGO_HOME".into(), cargo.to_string_lossy().into_owned()));
    }
    out.push(("XDG_CACHE_HOME".into(), dir.join("xdg").to_string_lossy().into_owned()));
    out.push(("UV_CACHE_DIR".into(), dir.join("uv").to_string_lossy().into_owned()));
    out
}

/// The whole environment of one `run_cmd` call: the minimal base, the
/// per-call HOME, the caller's git identity, PATH with the toolchain, and
/// the caller's caches.
fn command_env(ua_home: &Path, label: &str, home: &Path, host: &HostRust) -> Vec<(String, String)> {
    let mut out = base_env();
    out.retain(|(k, _)| k != "HOME" && k != "PATH");
    out.push(("HOME".into(), home.to_string_lossy().into_owned()));
    out.extend(git_identity_env(label));
    out.extend(toolchain_and_cache_env(ua_home, label, host));
    out
}

/// A per-call HOME directory under [`run_home_parent`], deleted on drop.
pub(crate) struct ScratchHome {
    pub(crate) path: PathBuf,
}

impl ScratchHome {
    pub(crate) fn new() -> UaResult<Self> {
        let fail = |e: std::io::Error| UaError::internal(format!("cannot prepare the command HOME: {e}"));
        let parent = run_home_parent();
        private_dir(&parent).map_err(fail)?;
        let path = parent.join(ulid::Ulid::generate().to_string());
        private_dir(&path).map_err(fail)?;
        Ok(Self { path })
    }
}

impl Drop for ScratchHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod run_env_tests {
    use super::*;

    #[test]
    fn ancestor_cargo_configs_are_found_above_the_root_only() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path().canonicalize().unwrap();
        let ws = top.join("a/ws");
        std::fs::create_dir_all(ws.join(".cargo")).unwrap();
        std::fs::write(ws.join(".cargo/config.toml"), "").unwrap();
        assert!(ancestor_cargo_configs(&ws).iter().all(|p| !p.starts_with(&top)));
        std::fs::create_dir_all(top.join(".cargo")).unwrap();
        std::fs::write(top.join(".cargo/config"), "").unwrap();
        std::fs::create_dir_all(top.join("a/.cargo")).unwrap();
        std::fs::write(top.join("a/.cargo/config.toml"), "").unwrap();
        let found: Vec<_> = ancestor_cargo_configs(&ws).into_iter().filter(|p| p.starts_with(&top)).collect();
        assert_eq!(found, vec![top.join("a/.cargo/config.toml"), top.join(".cargo/config")]);
    }

    #[test]
    fn unused_run_caches_are_pruned() {
        let ua_home = tempfile::tempdir().unwrap();
        let host = HostRust { path: "/usr/bin".into(), toolchain: None };
        toolchain_and_cache_env(ua_home.path(), "fresh", &host);
        toolchain_and_cache_env(ua_home.path(), "stale", &host);
        let root = ua_home.path().join("run-cache");
        let (fresh, stale) = (root.join(cache_key("fresh")), root.join(cache_key("stale")));
        assert!(fresh.join(CACHE_MARKER).exists());
        let old = std::time::SystemTime::now() - Duration::from_secs(40 * 24 * 3600);
        std::fs::File::options()
            .write(true)
            .open(stale.join(CACHE_MARKER))
            .unwrap()
            .set_modified(old)
            .unwrap();
        // A cache from before markers existed starts its clock now.
        let legacy = root.join("legacy-000000000000");
        std::fs::create_dir_all(legacy.join("cargo")).unwrap();
        // A symlink in the cache root is never followed or removed.
        let outside = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();

        assert_eq!(prune_run_caches(ua_home.path(), RUN_CACHE_MAX_AGE), 1);
        assert!(fresh.exists());
        assert!(!stale.exists());
        assert!(legacy.join(CACHE_MARKER).exists());
        assert!(outside.path().exists());
        // A use refreshes the marker, so a later prune keeps it.
        toolchain_and_cache_env(ua_home.path(), "stale", &host);
        assert_eq!(prune_run_caches(ua_home.path(), RUN_CACHE_MAX_AGE), 0);
        assert!(stale.exists());
        // A missing run-cache directory is not an error.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(prune_run_caches(empty.path(), RUN_CACHE_MAX_AGE), 0);
        assert!(!empty.path().join("run-cache").exists());
    }

    #[test]
    fn git_identity_comes_from_the_label() {
        let env: std::collections::HashMap<_, _> = git_identity_env("builder-1").into_iter().collect();
        assert_eq!(env["GIT_AUTHOR_NAME"], "builder-1");
        assert_eq!(env["GIT_COMMITTER_EMAIL"], "builder-1@agents.invalid");
        let env: std::collections::HashMap<_, _> = git_identity_env("Odd <label> x").into_iter().collect();
        assert_eq!(env["GIT_AUTHOR_NAME"], "Odd label x");
        assert_eq!(env["GIT_AUTHOR_EMAIL"], "Odd-label-x@agents.invalid");
        let env: std::collections::HashMap<_, _> = git_identity_env("  ").into_iter().collect();
        assert_eq!(env["GIT_AUTHOR_EMAIL"], "agent@agents.invalid");
    }

    #[test]
    fn run_homes_live_outside_ua_home_and_are_private() {
        let home = ScratchHome::new().unwrap();
        assert!(home.path.starts_with(run_home_parent()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [run_home_parent(), home.path.clone()] {
                assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o700, "{p:?}");
            }
        }
        let path = home.path.clone();
        drop(home);
        assert!(!path.exists());
    }

    fn as_map(v: Vec<(String, String)>) -> std::collections::HashMap<String, String> {
        v.into_iter().collect()
    }

    #[test]
    fn each_label_gets_its_own_cache() {
        let ua_home = tempfile::tempdir().unwrap();
        let host = HostRust { path: "/usr/bin:/bin".into(), toolchain: None };
        let a = as_map(toolchain_and_cache_env(ua_home.path(), "builder-1", &host));
        let b = as_map(toolchain_and_cache_env(ua_home.path(), "builder-2", &host));
        // Labels that reduce to the same safe text still differ.
        let c = as_map(toolchain_and_cache_env(ua_home.path(), "builder 1", &host));
        for key in ["CARGO_HOME", "XDG_CACHE_HOME", "UV_CACHE_DIR"] {
            assert_ne!(a[key], b[key], "{key}");
            assert_ne!(a[key], c[key], "{key}");
            for m in [&a, &b, &c] {
                assert!(
                    Path::new(&m[key]).starts_with(ua_home.path().join("run-cache")),
                    "{key}: {}",
                    m[key]
                );
            }
        }
        assert!(Path::new(&a["CARGO_HOME"]).ends_with("cargo"));
        // Path separators and dots never escape the cache root.
        let odd = as_map(toolchain_and_cache_env(ua_home.path(), "../../x/..", &host));
        let dir = Path::new(&odd["CARGO_HOME"]).parent().unwrap();
        assert_eq!(dir.parent().unwrap(), ua_home.path().join("run-cache"));
        assert!(!dir.file_name().unwrap().to_string_lossy().contains('/'));
    }

    /// A fake operator setup: a real-looking cargo home holding credentials
    /// and config, a `rustc` proxy in its `bin/` that names a toolchain.
    #[cfg(unix)]
    struct FakeOperator {
        _dir: tempfile::TempDir,
        cargo_home: PathBuf,
        rustup_home: PathBuf,
        toolchain_bin: PathBuf,
    }

    #[cfg(unix)]
    fn fake_operator() -> FakeOperator {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let cargo_home = root.join("cargo-home");
        let rustup_home = root.join("rustup-home");
        let toolchain_bin = rustup_home.join("toolchains/stable/bin");
        std::fs::create_dir_all(cargo_home.join("bin")).unwrap();
        std::fs::create_dir_all(&toolchain_bin).unwrap();
        std::fs::write(cargo_home.join("credentials.toml"), "[registry]\ntoken = \"planted\"\n").unwrap();
        std::fs::write(cargo_home.join("config.toml"), "[alias]\nleak = \"version\"\n").unwrap();
        let exe = |p: &Path, body: &str| {
            std::fs::write(p, body).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        let sysroot = toolchain_bin.parent().unwrap().display().to_string();
        exe(&cargo_home.join("bin/rustc"), &format!("#!/bin/sh\necho '{sysroot}'\n"));
        exe(&toolchain_bin.join("rustc"), "#!/bin/sh\nexit 0\n");
        FakeOperator { _dir: dir, cargo_home, rustup_home, toolchain_bin }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn commands_get_the_toolchain_on_path_and_never_the_real_cargo_home() {
        let op = fake_operator();
        let vars = vec![
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("CARGO_HOME".to_string(), op.cargo_home.display().to_string()),
            ("RUSTUP_HOME".to_string(), op.rustup_home.display().to_string()),
        ];
        let ua_home = tempfile::tempdir().unwrap();
        let host = HostRust::resolve(&vars, ua_home.path()).await;
        let first = std::env::split_paths(&host.path).next().unwrap();
        assert_eq!(first, op.toolchain_bin, "the resolved toolchain bin comes first: {}", host.path);

        let scratch = ScratchHome::new().unwrap();
        let env = command_env(ua_home.path(), "builder-1", &scratch.path, &host);
        let real = op.cargo_home.display().to_string();
        let rustup = op.rustup_home.display().to_string();
        for (k, v) in &env {
            assert_ne!(k, "RUSTUP_HOME", "rustup proxies are not reachable, so no RUSTUP_HOME");
            assert!(!v.contains(&real), "{k}={v} exposes the operator's cargo home");
            if k != "PATH" {
                assert!(!v.contains(&rustup), "{k}={v} exposes the operator's rustup home");
            }
        }
        let map = as_map(env.clone());
        let cargo_home = PathBuf::from(&map["CARGO_HOME"]);
        assert!(cargo_home.starts_with(ua_home.path()));
        assert!(!cargo_home.join("credentials.toml").exists());

        // Credentials or config a command leaves in its own cargo home are
        // removed before the next call.
        std::fs::write(cargo_home.join("credentials.toml"), "x").unwrap();
        std::fs::write(cargo_home.join("config.toml"), "x").unwrap();
        command_env(ua_home.path(), "builder-1", &scratch.path, &host);
        assert!(!cargo_home.join("credentials.toml").exists());
        assert!(!cargo_home.join("config.toml").exists());
    }

    /// The hub user's cargo `bin` directories never reach a command's
    /// PATH, by either spelling, and the toolchain still comes first.
    #[cfg(unix)]
    #[tokio::test]
    async fn operator_cargo_bins_are_dropped_from_path() {
        let op = fake_operator();
        let home = op.cargo_home.parent().unwrap().join("home");
        std::fs::create_dir_all(home.join(".cargo/bin")).unwrap();
        let path = format!(
            "{}:/usr/bin:{}/:{}:/bin",
            op.cargo_home.join("bin").display(),
            home.join(".cargo/bin").display(),
            home.join(".cargo/../.cargo/bin").display(),
        );
        let vars = vec![
            ("PATH".to_string(), path),
            ("HOME".to_string(), home.display().to_string()),
            ("CARGO_HOME".to_string(), op.cargo_home.display().to_string()),
        ];
        let ua_home = tempfile::tempdir().unwrap();
        let host = HostRust::resolve(&vars, ua_home.path()).await;
        let dirs: Vec<PathBuf> = std::env::split_paths(&host.path).collect();
        assert_eq!(
            dirs,
            vec![op.toolchain_bin.clone(), PathBuf::from("/usr/bin"), PathBuf::from("/bin")],
            "{}",
            host.path
        );
    }

    /// Only a resolution that found a toolchain is kept, and a kept one is
    /// redone once its toolchain is gone.
    #[cfg(unix)]
    #[tokio::test]
    async fn only_a_working_toolchain_is_cached() {
        let op = fake_operator();
        let ua_home = tempfile::tempdir().unwrap();
        let slot = tokio::sync::Mutex::new(None);
        // No rustc anywhere: nothing is cached.
        let none = vec![("PATH".to_string(), "/nonexistent".to_string())];
        let host = HostRust::cached(&slot, &none, ua_home.path()).await;
        assert!(host.toolchain.is_none());
        assert!(slot.lock().await.is_none(), "a failed resolution was kept");
        // The next call resolves again and keeps the result.
        let vars = vec![
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("CARGO_HOME".to_string(), op.cargo_home.display().to_string()),
        ];
        let host = HostRust::cached(&slot, &vars, ua_home.path()).await;
        assert_eq!(host.toolchain.as_deref(), Some(op.toolchain_bin.as_path()));
        let again = HostRust::cached(&slot, &none, ua_home.path()).await;
        assert!(Arc::ptr_eq(&host, &again), "a working toolchain is reused");
        // The toolchain disappears: resolved again (and, with nothing
        // found, not kept).
        std::fs::remove_file(op.toolchain_bin.join("rustc")).unwrap();
        let after = HostRust::cached(&slot, &none, ua_home.path()).await;
        assert!(after.toolchain.is_none());
        assert!(slot.lock().await.is_none());
    }

    /// With the real toolchain, when there is one: cargo run with the
    /// command environment does not read the operator's cargo config and
    /// does not touch the operator's credentials.
    #[cfg(unix)]
    #[tokio::test]
    async fn real_cargo_cannot_see_or_change_the_operator_cargo_home() {
        let op = fake_operator();
        std::fs::remove_file(op.cargo_home.join("bin/rustc")).unwrap();
        let mut vars: Vec<(String, String)> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .filter(|(k, _)| k != "CARGO_HOME")
            .collect();
        vars.push(("CARGO_HOME".into(), op.cargo_home.display().to_string()));
        let ua_home = tempfile::tempdir().unwrap();
        let host = HostRust::resolve(&vars, ua_home.path()).await;
        let path = std::ffi::OsString::from(&host.path);
        let Some(cargo) = find_on_path("cargo", &path) else {
            eprintln!("no cargo on PATH; skipping");
            return;
        };
        let work = tempfile::tempdir().unwrap();
        let scratch = ScratchHome::new().unwrap();
        let env = command_env(ua_home.path(), "builder-1", &scratch.path, &host);
        let run = |args: &[&str], env: Vec<(String, String)>| {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let cargo = cargo.to_string_lossy().into_owned();
            let cwd = work.path().to_path_buf();
            async move { run_program(&cargo, &args, &cwd, &env, Duration::from_secs(60), 65536).await.unwrap() }
        };

        // The planted alias works against the operator's home (so the
        // check below means something), and not with the command env.
        let mut exposed = env.clone();
        exposed.retain(|(k, _)| k != "CARGO_HOME");
        exposed.push(("CARGO_HOME".into(), op.cargo_home.display().to_string()));
        let direct = run(&["leak"], exposed).await;
        if direct.exit_code != 0 {
            eprintln!(
                "toolchain cargo is not usable here; skipping: {}",
                String::from_utf8_lossy(&direct.stderr)
            );
            return;
        }
        let out = run(&["leak"], env.clone()).await;
        assert_ne!(out.exit_code, 0, "the operator's cargo config was read");

        let before = std::fs::read(op.cargo_home.join("credentials.toml")).unwrap();
        let _ = run(&["logout"], env).await;
        assert_eq!(std::fs::read(op.cargo_home.join("credentials.toml")).unwrap(), before);
        assert!(op.cargo_home.join("config.toml").exists());
    }
}
