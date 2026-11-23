//! `audit_triage_tasks`: run a security audit and file one deduplicated
//! triage task per group of findings.
//!
//! Findings at or above `min_severity` (default `high`) are grouped by rule
//! (else file) and by class: the first path segment under the audited root,
//! or `(repo)` for a finding with no path. Each group becomes one task whose
//! notes start with the marker `[audit-triage: <root>:<rule>:<class>]`
//! (`<root>` is the root's basename and the first 8 hex of the SHA-256 of
//! its full path) and list every finding as `- [severity] path:line:
//! message` with its suggested fix.
//!
//! A group is not filed again while a task carrying its marker is still
//! open, or was closed (`done` or `cancelled`) with `[accepted-risk]` in its
//! notes. A clean audit files nothing. `dry_run` reports what would be filed.

use std::collections::BTreeMap;

use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};

use super::rules::{SEVERITIES, severity_rank};
use super::{AuditOptions, effective_excludes, resolve_target, run_audit};
use crate::families::tasks::{NewTask, insert_task};
use crate::registry::{Registry, ToolCtx, blocking, tool};

pub const ACCEPTED_RISK_TAG: &str = "[accepted-risk]";
const REPO_CLASS: &str = "(repo)";
const CLASS_MAX: usize = 48;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriageArgs {
    /// Directory to audit (workspace-relative, or absolute under a read root). Default `.`.
    pub path: Option<String>,
    /// Lowest severity filed: `high` (default), `medium`, `low` or `info`.
    pub min_severity: Option<String>,
    /// Glob patterns of paths to leave out (also read from `.ua-audit-ignore`).
    pub excludes: Option<Vec<String>>,
    /// Report what would be filed without filing anything.
    #[serde(default)]
    pub dry_run: bool,
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "audit_triage_tasks",
            "Run security_audit and file one triage task per group of findings at or above min_severity (default \
             high), grouped by rule and by top-level path. Each task's notes carry a stable [audit-triage: ...] \
             marker and every finding with its fix. A group is skipped while a task with its marker is open, or \
             closed with [accepted-risk]. A clean audit files nothing; dry_run files nothing and reports what it \
             would file. Returns {status, files_scanned, groups, created, skipped, tasks, dry_run}.",
            audit_triage_tasks,
        )
        .family("audit"),
    );
}

/// The audited root's display name: its basename.
fn root_label(root: &str) -> String {
    std::path::Path::new(root)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or(root.to_string())
}

/// The root's dedup identity: `<basename>@<first 8 hex of sha256(path)>`.
fn root_key(root: &str) -> String {
    format!("{}@{}", root_label(root), &hex::encode(Sha256::digest(root.as_bytes()))[..8])
}

static UNSAFE: std::sync::LazyLock<Option<Regex>> =
    std::sync::LazyLock::new(|| Regex::new(r"[^A-Za-z0-9._@+-]").ok());

/// A path segment as a marker token, bounded; a changed one gets a digest.
fn safe_class(segment: &str) -> String {
    let safe = UNSAFE.as_ref().map(|r| r.replace_all(segment, "_").into_owned()).unwrap_or_default();
    if safe == segment && safe.chars().count() <= CLASS_MAX {
        return safe;
    }
    let digest = &hex::encode(Sha256::digest(segment.as_bytes()))[..8];
    let head: String = safe.chars().take(CLASS_MAX - 9).collect();
    format!("{head}~{digest}")
}

/// The class of a finding at `path`: its first segment, or `(repo)`.
fn path_class(path: Option<&str>) -> String {
    let Some(p) = path.filter(|p| !p.is_empty()) else { return REPO_CLASS.into() };
    let first = p.trim_matches('/').split('/').next().unwrap_or("");
    if first.is_empty() || first == "." { REPO_CLASS.into() } else { safe_class(first) }
}

fn marker(scope: &str, key: &str, class: &str) -> String {
    format!("[audit-triage: {scope}:{key}:{class}]")
}

async fn audit_triage_tasks(ctx: ToolCtx, a: TriageArgs) -> UaResult<Value> {
    let min = a.min_severity.unwrap_or_else(|| "high".into());
    if !SEVERITIES.contains(&min.as_str()) {
        return Err(UaError::invalid(format!("min_severity must be one of {}", SEVERITIES.join(", "))));
    }
    let path = a.path.unwrap_or_else(|| ".".into());
    let excludes = a.excludes;
    let c2 = ctx.clone();
    let report = blocking(move || {
        let target = resolve_target(&c2, &path, false, false)?;
        let opts = AuditOptions {
            excludes: effective_excludes(&c2, false, excludes),
            include_repo_rules: !target.under_vault,
            remediate: false,
            inbox_dir: target.inbox_dir.clone(),
        };
        run_audit(&target.path, &opts)
    })
    .await?;

    let cutoff = severity_rank(&min);
    let mut groups: BTreeMap<(String, String), Vec<Value>> = BTreeMap::new();
    for f in report["findings"].as_array().into_iter().flatten() {
        if f["fixed"] == json!(true) || severity_rank(f["severity"].as_str().unwrap_or("info")) > cutoff {
            continue;
        }
        let key = f["rule"]
            .as_str()
            .filter(|s| !s.is_empty())
            .or(f["path"].as_str().filter(|s| !s.is_empty()))
            .unwrap_or("general")
            .to_string();
        groups.entry((key, path_class(f["path"].as_str()))).or_default().push(f.clone());
    }
    let root = report["root"].as_str().unwrap_or(".").to_string();
    let (label, scope) = (root_label(&root), root_key(&root));
    let by = ctx.caller.label.clone();
    let org = ctx.caller.org_id.clone();
    let dry_run = a.dry_run;
    let n_groups = groups.len();
    let (created, skipped) = ctx
        .hub
        .db()
        .write_async(move |tx| {
            crate::families::tasks::require_org(tx, &org)?;
            let mut created = Vec::new();
            let mut skipped = Vec::new();
            for ((key, class), findings) in groups {
                let mark = marker(&scope, &key, &class);
                let tracked: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM tasks WHERE org_id = ?3 AND instr(notes, ?1) > 0 \
                     AND archived_at IS NULL AND (status NOT IN ('done','cancelled') OR instr(notes, ?2) > 0))",
                    [mark.as_str(), ACCEPTED_RISK_TAG, org.as_str()],
                    |r| r.get(0),
                )?;
                if tracked {
                    skipped.push(format!("{key}:{class}"));
                    continue;
                }
                let title = format!("[Security Audit] {label}: {key} ({class}) — {} finding(s)", findings.len());
                let lines: Vec<String> = findings
                    .iter()
                    .map(|f| {
                        let line = f["line"].as_i64().map(|l| format!(":{l}")).unwrap_or_default();
                        let mut s = format!(
                            "- [{}] {}{line}: {}",
                            f["severity"].as_str().unwrap_or("info"),
                            f["path"].as_str().unwrap_or(REPO_CLASS),
                            f["message"].as_str().unwrap_or("")
                        );
                        if let Some(fix) = f["fix"].as_str().filter(|x| !x.is_empty()) {
                            s.push_str(&format!("\n  fix: {fix}"));
                        }
                        s
                    })
                    .collect();
                let notes = format!(
                    "{mark}\n\nAuto-filed from security_audit over {root} (min_severity={min}).\n\n{}",
                    lines.join("\n")
                );
                let entry = json!({ "title": title, "group": key, "class": class, "findings": findings.len() });
                let id = if dry_run {
                    Value::Null
                } else {
                    json!(insert_task(tx, &org, NewTask::simple(title, notes, "med"), &by)?)
                };
                let mut entry = entry;
                entry["id"] = id;
                created.push(entry);
            }
            Ok((created, skipped))
        })
        .await?;
    Ok(json!({
        "status": report["status"],
        "files_scanned": report["files_scanned"],
        "groups": n_groups,
        "created": created.len(),
        "skipped": skipped,
        "tasks": created,
        "dry_run": dry_run,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_are_first_segments_and_bounded() {
        assert_eq!(path_class(None), "(repo)");
        assert_eq!(path_class(Some("sessions/2026/x.jsonl")), "sessions");
        assert_eq!(path_class(Some("auth.json")), "auth.json");
        let odd = path_class(Some("a b]/x"));
        assert!(odd.starts_with("a_b_~") && !odd.contains(']'), "{odd}");
        assert!(root_key("/srv/repo").starts_with("repo@"));
    }
}
