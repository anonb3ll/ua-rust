//! `security_audit`: read-only best-practice checks for AI-assisted projects.
//!
//! Walks a directory (or one file) and reports, per file and line: committed
//! secrets by shape, private keys, hidden Unicode and bypass directives in
//! agent instruction files, permissive agent settings and risky hooks,
//! MCP configs with literal secrets or unpinned packages, `eval`/`exec`/shell
//! use next to LLM SDK imports, `.env` exposure and lockfile hygiene, and (for
//! documents) injection phrases, hidden Unicode and base64 payload blobs.
//!
//! A finding never carries a matched secret: it names the rule, the file, the
//! line and a redacted preview. A line containing `ua:allow` is exempt. The
//! scan reads at most 5000 regular files of at most 1 MB each, skips binaries
//! and non-regular files, and caps the report at 500 findings; `truncated_by`
//! says which cap fired so a truncated report is never mistaken for a whole one.
//!
//! `remediate=true` applies the few safe fixes in [`remediate`]; it is
//! confined to the workspace and refused for single files and the vault.

mod remediate;
pub mod rules;
mod safe_io;
mod triage;

use std::path::{Path, PathBuf};

use globset::{Glob, GlobBuilder, GlobMatcher};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::safety::{canonicalize_lenient, containing_root};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use self::rules::{Finding, SEVERITIES, SUPPRESS_MARKER, severity_rank};
use crate::approvals::{self, GateOutcome};
use crate::registry::{Registry, ToolCtx, blocking, tool};

pub const MAX_FILES: usize = 5000;
pub const MAX_FINDINGS: usize = 500;
pub const MAX_FILE_BYTES: usize = 1 << 20;

const SKIP_DIRS: [&str; 13] = [
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    "target",
];
/// Task worktrees are full checkouts of other branches: scanning them from the
/// repo root would report every finding once per worktree.
const SKIP_NAMES_EXTRA: [&str; 1] = [".worktrees"];
/// `(parent, child)` pairs of vendored or generated trees at a nested path.
const SKIP_NESTED: [(&str, &str); 2] = [(".obsidian", "plugins"), (".claude", "worktrees")];

/// What an audit run is told besides the root.
#[derive(Debug, Clone, Default)]
pub struct AuditOptions {
    pub excludes: Vec<String>,
    /// Run the repo-hygiene rules (`.gitignore`, lockfiles, agent settings,
    /// MCP configs). Off for vault content, which is not a code project.
    pub include_repo_rules: bool,
    pub remediate: bool,
    /// Vault inbox directory name: documents below it are untrusted captures.
    pub inbox_dir: Option<String>,
}

// --- exclude patterns ------------------------------------------------------------------

struct ExcludeItem {
    clean: String,
    basename: Option<GlobMatcher>,
    /// Path glob, the number of segments it spans, and whether it has `**`.
    path: Option<(GlobMatcher, usize, bool)>,
}

pub struct Excludes(Vec<ExcludeItem>);

impl Excludes {
    pub fn new(patterns: &[String]) -> Self {
        let mut items = Vec::new();
        for raw in patterns {
            let pattern = raw.trim();
            if pattern.is_empty() || pattern.starts_with('#') {
                continue;
            }
            let clean = pattern.strip_suffix('/').unwrap_or(pattern).to_string();
            let basename = (!pattern.contains('/'))
                .then(|| Glob::new(pattern).ok().map(|g| g.compile_matcher()))
                .flatten();
            let path = GlobBuilder::new(pattern)
                .literal_separator(true)
                .build()
                .ok()
                .map(|g| (g.compile_matcher(), pattern.split('/').count(), pattern.contains("**")));
            items.push(ExcludeItem { clean, basename, path });
        }
        Self(items)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Exact or directory-prefix match, a basename glob when the pattern has
    /// no slash, and a segment-aware path glob matched from the right (so `*`
    /// never crosses `/`, and `test*` never leaks into `tests/secret.py`).
    pub fn matches(&self, relpath: &str) -> bool {
        let segments: Vec<&str> = relpath.split('/').collect();
        let basename = segments.last().copied().unwrap_or("");
        self.0.iter().any(|it| {
            if relpath == it.clean
                || relpath.starts_with(&format!("{}/", it.clean))
                || format!("/{relpath}").contains(&format!("/{}/", it.clean))
            {
                return true;
            }
            if it.basename.as_ref().is_some_and(|g| g.is_match(basename)) {
                return true;
            }
            match &it.path {
                Some((g, n, true)) => {
                    let _ = n;
                    g.is_match(relpath) || g.is_match(format!("x/{relpath}"))
                }
                Some((g, n, false)) => {
                    segments.len() >= *n && g.is_match(segments[segments.len() - n..].join("/"))
                }
                None => false,
            }
        })
    }
}

// --- walking ---------------------------------------------------------------------------

fn skip_dir(parent: &str, name: &str) -> bool {
    SKIP_DIRS.contains(&name) || SKIP_NAMES_EXTRA.contains(&name) || SKIP_NESTED.contains(&(parent, name))
}

fn is_regular(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(true)
}

/// Every file name below `root` (sorted, top-down), the walk cut at
/// [`MAX_FILES`] regular files. Non-regular names stay in the list for the
/// name-based repo rules but do not use up a slot, and are never opened.
/// Symlinked directories are not followed; a file symlink that leaves `root`
/// is not listed.
fn iter_files(root: &Path, excludes: &Excludes) -> (Vec<PathBuf>, bool) {
    let mut files = Vec::new();
    let mut eligible = 0usize;
    let mut stack = vec![root.to_path_buf()];
    // Depth-first, directory files before subdirectories, names sorted.
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        let parent = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let rel_dir = dir.strip_prefix(root).unwrap_or(&dir).to_string_lossy().replace('\\', "/");
        let mut subdirs = Vec::new();
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            let path = e.path();
            let Ok(ft) = e.file_type() else { continue };
            let is_dir = if ft.is_symlink() { false } else { ft.is_dir() };
            if ft.is_symlink() && std::fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(false) {
                continue;
            }
            if is_dir {
                if skip_dir(&parent, &name) {
                    continue;
                }
                let child_rel = if rel_dir.is_empty() { name.clone() } else { format!("{rel_dir}/{name}") };
                // Prune subtrees an exclude already covers, before the cap is hit.
                if !excludes.is_empty() && excludes.matches(&format!("{child_rel}/__ua_probe__")) {
                    continue;
                }
                subdirs.push(path);
                continue;
            }
            if ft.is_symlink()
                && let Ok(real) = path.canonicalize()
                && let Ok(real_root) = root.canonicalize()
                && !real.starts_with(&real_root)
            {
                continue;
            }
            if is_regular(&path) {
                if eligible >= MAX_FILES {
                    return (files, true);
                }
                eligible += 1;
            }
            files.push(path);
        }
        // Reverse so the stack pops subdirectories in sorted order.
        stack.extend(subdirs.into_iter().rev());
    }
    (files, false)
}

/// Decoded text of a regular file within the size cap; `None` for binaries,
/// oversized or non-regular files.
fn read_text(path: &Path) -> Option<String> {
    let data = safe_io::read_regular_file(path, Some(MAX_FILE_BYTES))?;
    if data.iter().take(8192).any(|b| *b == 0) {
        return None;
    }
    Some(String::from_utf8_lossy(&data).into_owned())
}

/// Lossy text of a regular file, for the triage tool.
pub fn read_text_lossy(path: &Path) -> Option<String> {
    safe_io::read_regular_file(path, Some(MAX_FILE_BYTES)).map(|b| String::from_utf8_lossy(&b).into_owned())
}

pub fn status_of(findings: &[Value]) -> &'static str {
    let has = |sev: &str| findings.iter().any(|f| f["severity"] == sev);
    if has("high") {
        "fail"
    } else if has("medium") {
        "warn"
    } else {
        "pass"
    }
}

fn grade(summary: &Value, truncated: bool) -> &'static str {
    let n = |k: &str| summary[k].as_u64().unwrap_or(0);
    if n("high") > 0 {
        "F"
    } else if truncated {
        "E"
    } else if n("medium") > 0 {
        "D"
    } else if n("low") > 0 {
        "C"
    } else if n("info") > 0 {
        "B"
    } else {
        "A"
    }
}

/// Audit `root` (a directory or one file) and return the report.
pub fn run_audit(root: &Path, opts: &AuditOptions) -> UaResult<Value> {
    if opts.remediate {
        return Err(UaError::invalid("remediation must go through run_audit_with and the approval gate"));
    }
    run_audit_with(root, opts, None).map(|(report, _)| report)
}

/// Like [`run_audit`], optionally remediating: `Plan` writes nothing and
/// reports the files it would change; `Apply` writes only what was approved.
pub fn run_audit_with(
    root: &Path,
    opts: &AuditOptions,
    mode: Option<remediate::Mode<'_>>,
) -> UaResult<(Value, Vec<remediate::Change>)> {
    let root =
        root.canonicalize().map_err(|e| UaError::invalid(format!("cannot resolve the audit root: {e}")))?;
    let single_file = root.is_file();
    let base: PathBuf = if single_file {
        root.parent().map(Path::to_path_buf).unwrap_or_else(|| root.clone())
    } else {
        root.clone()
    };

    let mut patterns = opts.excludes.clone();
    if let Some(ignore) = safe_io::read_regular_text(&base.join(".ua-audit-ignore")) {
        patterns.extend(
            ignore
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        );
    }
    let excludes = Excludes::new(&patterns);

    let (files, files_truncated) =
        if single_file { (vec![root.clone()], false) } else { iter_files(&root, &excludes) };

    let mut findings: Vec<Finding> = Vec::new();
    let mut scanned = 0usize;
    let mut excluded_files: std::collections::BTreeSet<String> = Default::default();

    for f in &files {
        let relpath = f.strip_prefix(&base).unwrap_or(f).to_string_lossy().replace('\\', "/");
        if excludes.matches(&relpath) {
            excluded_files.insert(relpath);
            continue;
        }
        let Some(text) = read_text(f) else { continue };
        scanned += 1;
        let lines: Vec<&str> = text.lines().collect();
        for fd in rules::content_findings(&relpath, &text, opts.inbox_dir.as_deref()) {
            let suppressed =
                fd.line.is_some_and(|n| n >= 1 && n <= lines.len() && lines[n - 1].contains(SUPPRESS_MARKER));
            if !suppressed {
                findings.push(fd);
            }
        }
    }

    if opts.include_repo_rules && !single_file {
        findings.extend(rules::repo_findings(&root, &files));
    }

    // Findings tied to an excluded path (from the repo rules) go too.
    findings.retain(|fd| match &fd.path {
        Some(p) if excluded_files.contains(p) || excludes.matches(p) => {
            excluded_files.insert(p.clone());
            false
        }
        _ => true,
    });

    let changes = match mode {
        Some(mode) => remediate::remediate_findings(&root, &mut findings, mode),
        None => Vec::new(),
    };

    // Drop byte-identical findings so overlapping rules cannot inflate counts.
    let mut seen = std::collections::BTreeSet::new();
    findings.retain(|fd| seen.insert((fd.rule.clone(), fd.path.clone(), fd.line, fd.message.clone())));

    // Sort before capping: a cap must never drop the highs and keep the infos.
    findings.sort_by(|a, b| {
        severity_rank(a.severity)
            .cmp(&severity_rank(b.severity))
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.unwrap_or(0).cmp(&b.line.unwrap_or(0)))
    });
    let findings_total = findings.len();
    let findings_truncated = findings_total > MAX_FINDINGS;
    findings.truncate(MAX_FINDINGS);
    let mut truncated_by = Vec::new();
    if files_truncated {
        truncated_by.push("files");
    }
    if findings_truncated {
        truncated_by.push("findings");
    }

    let mut summary = serde_json::Map::new();
    for sev in SEVERITIES {
        let n = findings.iter().filter(|f| !f.fixed && f.severity == sev).count();
        summary.insert(sev.to_string(), json!(n));
    }
    summary.insert("excluded".into(), json!(excluded_files.len()));
    let summary = Value::Object(summary);
    let as_json: Vec<Value> = findings.iter().map(Finding::to_json).collect();
    let truncated = !truncated_by.is_empty();
    let report = json!({
        "root": root.to_string_lossy(),
        "files_scanned": scanned,
        "status": status_of(&as_json.iter().filter(|f| f["fixed"] != true).cloned().collect::<Vec<_>>()),
        "grade": grade(&summary, truncated),
        "summary": summary,
        "findings": as_json,
        "findings_total": findings_total,
        "truncated": truncated,
        "truncated_by": truncated_by,
    });
    Ok((report, changes))
}

// --- path resolution -----------------------------------------------------------------------

/// A resolved audit target.
#[derive(Debug, Clone)]
pub struct Target {
    pub path: PathBuf,
    /// The path lies inside the configured vault.
    pub under_vault: bool,
    /// The vault inbox directory name, when auditing vault content.
    pub inbox_dir: Option<String>,
}

fn canonical_vault(ctx: &ToolCtx) -> Option<PathBuf> {
    ctx.hub.cfg().vault_path.as_ref().and_then(|p| p.canonicalize().ok())
}

/// Resolve `path` for an audit. Without `vault`, a relative path resolves
/// inside the workspace and an absolute one may also lie in a read root or the
/// vault; with `vault`, it resolves inside the vault under the vault's own
/// rules. `for_write` (remediation) confines the target to the workspace.
pub fn resolve_target(ctx: &ToolCtx, path: &str, vault: bool, for_write: bool) -> UaResult<Target> {
    if path.contains('\0') {
        return Err(UaError::invalid("path contains a NUL byte"));
    }
    let cfg = ctx.hub.cfg();
    let inbox = cfg.vault_inbox_dir.trim().trim_matches('/').to_string();
    if vault {
        let resolved = crate::families::vault::vault(ctx)?.resolve(path)?;
        if !resolved.exists() {
            return Err(UaError::not_found(format!("path {path:?} does not exist")));
        }
        return Ok(Target {
            path: resolved,
            under_vault: true,
            inbox_dir: (!inbox.is_empty()).then_some(inbox),
        });
    }
    let workspace = cfg.workspace_root();
    let mut roots = vec![workspace.clone()];
    if Path::new(path).is_absolute() {
        roots.extend(cfg.read_roots.iter().cloned());
        if let Some(v) = cfg.vault_path.as_ref() {
            roots.push(v.clone());
        }
    }
    let raw = Path::new(if path.trim().is_empty() { "." } else { path });
    let joined = if raw.is_absolute() { raw.to_path_buf() } else { workspace.join(raw) };
    let resolved = canonicalize_lenient(&joined)
        .map_err(|e| UaError::invalid(format!("cannot resolve {path:?}: {e}")))?;
    if containing_root(&resolved, &roots).is_none() {
        return Err(UaError::denied("outside_sandbox", format!("{path:?} is outside the auditable roots")));
    }
    if !resolved.exists() {
        return Err(UaError::not_found(format!("path {path:?} does not exist")));
    }
    let under_vault = canonical_vault(ctx).is_some_and(|v| resolved.starts_with(&v));
    if for_write {
        if under_vault {
            return Err(UaError::denied(
                "vault_read_only",
                "remediate is not supported for vault paths; vault audits are always read-only",
            ));
        }
        let ws = workspace.canonicalize().unwrap_or(workspace);
        if !resolved.starts_with(&ws) {
            return Err(UaError::denied(
                "outside_workspace",
                "remediate only writes inside the workspace; read roots stay read-only",
            ));
        }
    }
    Ok(Target {
        path: resolved,
        under_vault,
        inbox_dir: under_vault.then_some(inbox).filter(|i| !i.is_empty()),
    })
}

/// The caller's excludes, plus (for vault audits) the generated security audit
/// reports, which quote prior findings and would bury new ones.
pub fn effective_excludes(ctx: &ToolCtx, vault: bool, excludes: Option<Vec<String>>) -> Vec<String> {
    let mut out = Vec::new();
    if vault {
        let inbox = ctx.hub.cfg().vault_inbox_dir.trim().trim_matches('/').to_string();
        if !inbox.is_empty() {
            out.push(format!("{inbox}/Security Audit *.md"));
        }
        out.push("Archive/**/Security Audit *.md".into());
        // Auditing inside the inbox or archive directly: the base is that directory.
        out.push("Security Audit *.md".into());
    }
    out.extend(excludes.unwrap_or_default());
    out
}

// --- the tool --------------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditArgs {
    /// File or directory to audit. Workspace-relative, or absolute under the
    /// workspace, a read root or the vault. Default `.`.
    pub path: Option<String>,
    /// Lowest severity returned: `high`, `medium`, `low` or `info` (default).
    /// `status` is computed before this filter.
    pub min_severity: Option<String>,
    /// Apply the safe auto-fixes (create or extend `.gitignore`, strip hidden
    /// Unicode from an instruction file, scaffold `CLAUDE.md`). Directory
    /// paths inside the workspace only; refused with `vault`.
    #[serde(default)]
    pub remediate: bool,
    /// Glob patterns of paths to leave out (also read from `.ua-audit-ignore`).
    pub excludes: Option<Vec<String>>,
    /// Audit inside the vault instead (pre-ingest scan of captures). The
    /// repo-hygiene rules are skipped; always read-only.
    #[serde(default)]
    pub vault: bool,
}

async fn security_audit(ctx: ToolCtx, a: AuditArgs) -> UaResult<Value> {
    let min = a.min_severity.unwrap_or_else(|| "info".into());
    if !SEVERITIES.contains(&min.as_str()) {
        return Err(UaError::invalid(format!("min_severity must be one of {}", SEVERITIES.join(", "))));
    }
    if a.vault && a.remediate {
        return Err(UaError::invalid("remediate is not supported for vault-scoped audits (vault=true)"));
    }
    let path = a.path.unwrap_or_else(|| ".".into());
    let remediate = a.remediate;
    let (excludes_arg, vault) = (a.excludes, a.vault);
    let prep = {
        let ctx = ctx.clone();
        blocking(move || {
            let target = resolve_target(&ctx, &path, vault, remediate)?;
            if remediate && target.path.is_file() {
                return Err(UaError::invalid("remediate requires a directory path, not a single file"));
            }
            let opts = AuditOptions {
                excludes: effective_excludes(&ctx, vault, excludes_arg),
                include_repo_rules: !vault && !target.under_vault,
                remediate: false,
                inbox_dir: target.inbox_dir.clone(),
            };
            let plan = if remediate {
                run_audit_with(&target.path, &opts, Some(remediate::Mode::Plan))?.1
            } else {
                Vec::new()
            };
            Ok((target, opts, plan))
        })
        .await?
    };
    let (target, opts, plan) = prep;

    // Writing files is a state change: park the exact planned list for a human.
    let root = target.path.canonicalize().unwrap_or_else(|_| target.path.clone());
    let mut approval_id = None;
    if !plan.is_empty() {
        let payload = json!({
            "remediate": true,
            "root": root.to_string_lossy(),
            "changes": plan.iter().map(remediate::Change::to_json).collect::<Vec<_>>(),
        });
        approval_id = Some(gate_remediation(&ctx, payload).await?);
    }

    let events_ctx = ctx.clone();
    let (report, changes) = blocking(move || {
        let mode = if remediate { Some(remediate::Mode::Apply(&plan)) } else { None };
        let (mut report, changes) = run_audit_with(&target.path, &opts, mode)?;
        let cutoff = severity_rank(&min);
        if let Some(list) = report["findings"].as_array_mut() {
            list.retain(|f| severity_rank(f["severity"].as_str().unwrap_or("info")) <= cutoff);
        }
        Ok((report, changes))
    })
    .await?;

    let mut report = report;
    report["remediated_files"] = json!(changes.iter().map(remediate::Change::to_json).collect::<Vec<_>>());
    if !changes.is_empty() {
        let files: Vec<Value> = changes.iter().map(remediate::Change::to_json).collect();
        let by = events_ctx.caller.label.clone();
        let root = root.to_string_lossy().into_owned();
        let appended = events_ctx
            .hub
            .db()
            .write_async(move |tx| {
                ledger::append(
                    tx,
                    EventInput::new(
                        "agent.audit.remediated",
                        json!({ "approval_id": approval_id, "root": root, "files": files }),
                    )
                    .by(by),
                )?;
                Ok(())
            })
            .await;
        // The files are already written: report a failed record, never hide it.
        if let Err(e) = appended {
            tracing::warn!(error = %e, "security_audit remediation applied but its ledger event failed");
            report["ledger_error"] = json!(format!("remediation applied but the ledger event failed: {e}"));
        }
    }
    Ok(report)
}

/// Park or consume an approval bound to the exact planned file changes.
/// `security_audit` is not `always_gated` (a read-only audit needs none), so
/// the gate is forced here for `remediate=true`; the payload carries the plan,
/// so an approval never covers a different set of files.
async fn gate_remediation(ctx: &ToolCtx, payload: Value) -> UaResult<i64> {
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let outcome = ctx
        .hub
        .db()
        .write_async(move |tx| approvals::gate(tx, hub.cfg(), &caller, "security_audit", &payload))
        .await?;
    match outcome {
        GateOutcome::Pass { approval_id } => Ok(approval_id),
        GateOutcome::Pending { approval_id } => {
            Err(UaError::ApprovalRequired { tool: "security_audit".into(), approval_id })
        }
        GateOutcome::Denied { approval_id, reason } => Err(UaError::denied(
            "approval_denied",
            format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
        )),
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "security_audit",
            "Audit a project (or, with vault=true, a vault note or directory) for AI-development security problems: committed secrets and private keys, .env exposure, permissive agent settings and risky hooks, MCP configs with literal secrets or unpinned packages, hidden Unicode and bypass directives in instruction files, eval/shell use near LLM SDKs, lockfile and .gitignore hygiene, and injection phrases, hidden Unicode and base64 blobs in documents. A finding never contains a secret value, only file, line, rule and a redacted preview. Lines with `ua:allow` are exempt. Scans at most 5000 files of 1 MB; remediate=true applies safe fixes inside the workspace, but only after a human approves the exact list of files it would change (the call parks as approval_required first), and records each changed file's SHA-256 before and after in the ledger. Returns {root, files_scanned, status, grade, summary, findings, findings_total, truncated, truncated_by}; status is fail (any high), warn (any medium) or pass.",
            security_audit,
        )
        .family("audit"),
    );
    triage::register(r);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_are_segment_aware() {
        let ex = Excludes::new(&["test*".into(), "config/*.yaml".into(), "vendor/".into()]);
        assert!(ex.matches("test_x.py"));
        assert!(ex.matches("config/prod.yaml"));
        assert!(!ex.matches("config/sub/prod.yaml"));
        assert!(ex.matches("vendor/a/b.rs"));
        assert!(!ex.matches("src/main.rs"));
    }
}
