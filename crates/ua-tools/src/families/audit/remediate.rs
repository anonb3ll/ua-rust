//! Safe, non-destructive auto-fixes for a few audit findings.
//!
//! Only these are applied: create or extend `.gitignore` (default entries,
//! `.env*`), strip hidden Unicode from an instruction file, and scaffold a
//! minimal `CLAUDE.md` when no instruction file exists. Every read and write
//! goes through `safe_io`, so a FIFO, device or symlink at a target leaves the
//! finding unfixed with an `[AUTO-FIX-FAILED]` message. Nothing else is ever
//! touched; secrets are never rewritten.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::rules::Finding;
use super::safe_io::{read_regular_file, read_regular_text, write_regular_text};
use crate::families::injection::hidden_char_regex;

const DEFAULT_GITIGNORE: &str = "# Default .gitignore created by audit auto-remediation
.env*
__pycache__/
*.py[cod]
.venv/
venv/
node_modules/
target/
.DS_Store
";

const DEFAULT_INSTRUCTIONS: &str = "# CLAUDE.md

Guidelines for AI assistants working in this repository.

## Build and Test Commands
- Build: (fill in the build command)
- Test: (fill in the test command)

## Development Constraints
- Follow the repository's style guidelines.
- Do not disable confirmation settings or bypass safety-rail permissions.
";

const INSTRUCTION_NAMES: [&str; 5] =
    ["CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules"];

fn fail(fd: &mut Finding, what: &str, e: impl std::fmt::Display) {
    fd.message = format!("[AUTO-FIX-FAILED] {what}: {e}. {}", fd.message);
}

/// A finding path that stays inside the root: relative, no `..`.
fn inside(rel: &str) -> bool {
    let p = Path::new(rel);
    !p.is_absolute() && p.components().all(|c| matches!(c, Component::Normal(_)))
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// One file a remediation creates or rewrites. Hashes only, never content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    /// `None` when the file is created.
    pub sha256_before: Option<String>,
    pub sha256_after: String,
}

impl Change {
    pub fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "action": if self.sha256_before.is_some() { "modify" } else { "create" },
            "sha256_before": self.sha256_before,
            "sha256_after": self.sha256_after,
        })
    }
}

/// Plan only (nothing is written), or write exactly what was approved.
pub enum Mode<'a> {
    Plan,
    Apply(&'a [Change]),
}

struct Fixer<'a> {
    root: &'a Path,
    mode: Mode<'a>,
    /// Content of files this run has already planned or written.
    overlay: BTreeMap<String, String>,
    changes: BTreeMap<String, Change>,
}

impl Fixer<'_> {
    fn exists(&self, rel: &str) -> bool {
        self.overlay.contains_key(rel) || std::fs::symlink_metadata(self.root.join(rel)).is_ok()
    }

    fn read(&self, rel: &str) -> Option<String> {
        match self.overlay.get(rel) {
            Some(t) => Some(t.clone()),
            None => read_regular_text(&self.root.join(rel)),
        }
    }

    /// Create (`create_only`) or replace `rel` with `text`.
    fn put(&mut self, rel: &str, text: &str, create_only: bool) -> std::io::Result<()> {
        let path = self.root.join(rel);
        let ours = self.overlay.contains_key(rel);
        let before = if create_only || ours {
            None
        } else {
            match read_regular_file(&path, Some(8 << 20)) {
                Some(b) => Some(sha(&b)),
                None => return Err(std::io::Error::other("not a readable regular file")),
            }
        };
        let first = self.changes.get(rel).map(|c| c.sha256_before.clone());
        let before_for_change = first.unwrap_or_else(|| before.clone());
        if let Mode::Apply(expected) = &self.mode
            && !ours
            && !expected.iter().any(|c| c.path == rel && c.sha256_before == before)
        {
            return Err(std::io::Error::other("file changed since the plan was approved"));
        }
        if matches!(self.mode, Mode::Apply(_)) {
            write_regular_text(&path, text, create_only && !ours)?;
        }
        self.overlay.insert(rel.to_string(), text.to_string());
        self.changes.insert(
            rel.to_string(),
            Change {
                path: rel.to_string(),
                sha256_before: before_for_change,
                sha256_after: sha(text.as_bytes()),
            },
        );
        Ok(())
    }
}

/// Apply (or, in `Mode::Plan`, only plan) the safe fixes. Returns the files
/// changed, sorted by path.
pub fn remediate_findings(root: &Path, findings: &mut [Finding], mode: Mode<'_>) -> Vec<Change> {
    let mut fx = Fixer { root, mode, overlay: BTreeMap::new(), changes: BTreeMap::new() };
    for fd in findings.iter_mut() {
        if fd.fixed {
            continue;
        }
        match fd.rule.as_str() {
            "HYGIENE-NO-GITIGNORE" => match fx.put(".gitignore", DEFAULT_GITIGNORE, true) {
                Ok(()) => {
                    fd.fixed = true;
                    fd.message = format!("[AUTO-FIXED] Created default .gitignore: {}", fd.message);
                }
                Err(e) => fail(fd, "Failed to create .gitignore", e),
            },
            "SECRETS-ENV-EXPOSED" => {
                let result = if fx.exists(".gitignore") {
                    match fx.read(".gitignore") {
                        None => Err(std::io::Error::other("not a readable regular file")),
                        Some(cur) if [".env*", "*.env", ".env"].iter().any(|p| cur.contains(p)) => Ok(()),
                        Some(cur) => fx.put(
                            ".gitignore",
                            &format!("{cur}\n# Added by audit auto-remediation\n.env*\n"),
                            false,
                        ),
                    }
                } else {
                    fx.put(".gitignore", DEFAULT_GITIGNORE, true)
                };
                match result {
                    Ok(()) => {
                        fd.fixed = true;
                        fd.message = format!("[AUTO-FIXED] Added `.env*` to .gitignore: {}", fd.message);
                    }
                    Err(e) => fail(fd, "Failed to update .gitignore", e),
                }
            }
            "AGENT-HIDDEN-UNICODE" => {
                let Some(rel) = fd.path.clone().filter(|p| inside(p)) else { continue };
                let Some(original) = fx.read(&rel) else {
                    fail(fd, "Failed to clean hidden Unicode", "not a readable regular file");
                    continue;
                };
                let cleaned = hidden_char_regex().replace_all(&original, "").into_owned();
                if cleaned != original {
                    match fx.put(&rel, &cleaned, false) {
                        Ok(()) => {
                            fd.fixed = true;
                            fd.message = format!(
                                "[AUTO-FIXED] Stripped hidden/bidi Unicode characters: {}",
                                fd.message
                            );
                        }
                        Err(e) => fail(fd, "Failed to clean hidden Unicode", e),
                    }
                }
            }
            "AGENT-NO-INSTRUCTIONS" => {
                if INSTRUCTION_NAMES.iter().any(|f| fx.overlay.contains_key(*f) || root.join(f).is_file()) {
                    continue;
                }
                match fx.put("CLAUDE.md", DEFAULT_INSTRUCTIONS, true) {
                    Ok(()) => {
                        fd.fixed = true;
                        fd.message = format!(
                            "[AUTO-FIXED] Created default instruction file CLAUDE.md: {}",
                            fd.message
                        );
                    }
                    Err(e) => fail(fd, "Failed to create CLAUDE.md", e),
                }
            }
            _ => {}
        }
    }
    fx.changes.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str) -> Finding {
        Finding::new(rule, "low", None, None, "m".into(), "r")
    }

    #[test]
    fn a_file_created_after_the_scan_is_not_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan_findings = [finding("HYGIENE-NO-GITIGNORE")];
        let plan = remediate_findings(dir.path(), &mut plan_findings, Mode::Plan);
        assert_eq!(plan.len(), 1);
        assert!(!dir.path().join(".gitignore").exists(), "planning writes nothing");

        // Someone creates it between the plan and the apply.
        std::fs::write(dir.path().join(".gitignore"), "mine\n").unwrap();
        let mut findings = [finding("HYGIENE-NO-GITIGNORE")];
        let done = remediate_findings(dir.path(), &mut findings, Mode::Apply(&plan));
        assert!(done.is_empty());
        assert!(!findings[0].fixed);
        assert!(findings[0].message.contains("AUTO-FIX-FAILED"));
        assert_eq!(std::fs::read_to_string(dir.path().join(".gitignore")).unwrap(), "mine\n");
    }
}
