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
use super::safe_io::{create_regular_text, read_regular_text_strict, replace_regular_text};
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

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::other(msg.to_string())
}

/// One file a remediation creates or rewrites. Hashes and a fixed-phrase
/// description only, never file content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    /// `None` when the file is created.
    pub sha256_before: Option<String>,
    pub sha256_after: String,
    /// Short human-readable summary: fixed phrases and line numbers only.
    pub description: String,
}

impl Change {
    pub fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "action": if self.sha256_before.is_some() { "modify" } else { "create" },
            "description": self.description,
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

    fn record(&mut self, rel: &str, before: Option<String>, new: &str, description: String) {
        let before = match self.changes.get(rel) {
            Some(first) => first.sha256_before.clone(),
            None => before,
        };
        self.overlay.insert(rel.to_string(), new.to_string());
        self.changes.insert(
            rel.to_string(),
            Change {
                path: rel.to_string(),
                sha256_before: before,
                sha256_after: sha(new.as_bytes()),
                description,
            },
        );
    }

    /// Create `rel` with `text`; it must not exist.
    fn create(&mut self, rel: &str, text: &str, description: &str) -> std::io::Result<()> {
        if self.overlay.contains_key(rel) {
            return Ok(()); // an earlier fix in this run already created it
        }
        if self.exists(rel) {
            return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "file already exists"));
        }
        if let Mode::Apply(expected) = &self.mode {
            let after = sha(text.as_bytes());
            if !expected.iter().any(|c| c.path == rel && c.sha256_before.is_none() && c.sha256_after == after)
            {
                return Err(io_err("the change differs from the approved plan"));
            }
            create_regular_text(&self.root.join(rel), text)?;
        }
        self.record(rel, None, text, description.to_string());
        Ok(())
    }

    /// Replace `rel` with what `f` makes of its current text (`None` = leave
    /// it alone). The file is read once, strictly as UTF-8; in apply mode the
    /// same bytes are checked against the approved plan before the temp file
    /// is renamed over it.
    fn modify(&mut self, rel: &str, f: impl FnOnce(&str) -> Option<(String, String)>) -> std::io::Result<()> {
        let path = self.root.join(rel);
        let ours = self.overlay.get(rel).cloned();
        if let (Mode::Apply(expected), Some(ours)) = (&self.mode, ours.as_ref()) {
            // A file this run already wrote: the disk must still hold our
            // output, and the final bytes must match the approved plan.
            let first_before = self.changes.get(rel).and_then(|c| c.sha256_before.clone());
            let our_hash = sha(ours.as_bytes());
            let mut done: Option<(String, String)> = None;
            replace_regular_text(&path, |bytes| {
                if sha(bytes) != our_hash {
                    return Err(io_err("file changed since the plan was approved"));
                }
                let Some((new, desc)) = f(ours) else { return Ok(None) };
                let after = sha(new.as_bytes());
                if !expected
                    .iter()
                    .any(|c| c.path == rel && c.sha256_before == first_before && c.sha256_after == after)
                {
                    return Err(io_err("the change differs from the approved plan"));
                }
                done = Some((new.clone(), desc));
                Ok(Some(new))
            })
            .map_err(|e| {
                if e.raw_os_error().is_some() || e.kind() == std::io::ErrorKind::NotFound {
                    io_err("not a readable regular file")
                } else {
                    e
                }
            })?;
            if let Some((new, desc)) = done {
                self.record(rel, None, &new, desc);
            }
            return Ok(());
        }
        if matches!(self.mode, Mode::Plan) {
            // Plan mode: nothing is written.
            let (cur, before) = match ours {
                Some(t) => (t, None),
                None => {
                    let (t, bytes) = read_regular_text_strict(&path).map_err(|e| {
                        if e.kind() == std::io::ErrorKind::InvalidData {
                            e
                        } else {
                            io_err("not a readable regular file")
                        }
                    })?;
                    (t, Some(sha(&bytes)))
                }
            };
            if let Some((new, desc)) = f(&cur) {
                self.record(rel, before, &new, desc);
            }
            return Ok(());
        }
        let Mode::Apply(expected) = self.mode else { return Ok(()) };
        let mut done: Option<(Option<String>, String, String)> = None;
        replace_regular_text(&path, |bytes| {
            let before = sha(bytes);
            let cur = std::str::from_utf8(bytes)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not valid UTF-8"))?;
            let Some((new, desc)) = f(cur) else { return Ok(None) };
            let Some(approved) =
                expected.iter().find(|c| c.path == rel && c.sha256_before.as_deref() == Some(&before))
            else {
                return Err(io_err("file changed since the plan was approved"));
            };
            if approved.sha256_after != sha(new.as_bytes()) {
                return Err(io_err("the change differs from the approved plan"));
            }
            done = Some((Some(before), new.clone(), desc));
            Ok(Some(new))
        })
        .map_err(|e| {
            if matches!(e.kind(), std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotFound)
                || e.raw_os_error().is_some()
            {
                io_err("not a readable regular file")
            } else {
                e
            }
        })?;
        if let Some((before, new, desc)) = done {
            self.record(rel, before, &new, desc);
        }
        Ok(())
    }
}

/// "strip 3 hidden chars on lines 2, 9": counts and line numbers only.
fn strip_description(original: &str) -> String {
    let re = hidden_char_regex();
    let count = re.find_iter(original).count();
    let lines: Vec<usize> =
        original.lines().enumerate().filter(|(_, l)| re.is_match(l)).map(|(i, _)| i + 1).collect();
    let mut shown: Vec<String> = lines.iter().take(10).map(usize::to_string).collect();
    if lines.len() > 10 {
        shown.push("...".into());
    }
    format!("strip {count} hidden chars on lines {}", shown.join(", "))
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
            "HYGIENE-NO-GITIGNORE" => {
                match fx.create(".gitignore", DEFAULT_GITIGNORE, "create default .gitignore") {
                    Ok(()) => {
                        fd.fixed = true;
                        fd.message = format!("[AUTO-FIXED] Created default .gitignore: {}", fd.message);
                    }
                    Err(e) => fail(fd, "Failed to create .gitignore", e),
                }
            }
            "SECRETS-ENV-EXPOSED" => {
                let result = if fx.exists(".gitignore") {
                    fx.modify(".gitignore", |cur| {
                        if [".env*", "*.env", ".env"].iter().any(|p| cur.contains(p)) {
                            return None;
                        }
                        Some((
                            format!("{cur}\n# Added by audit auto-remediation\n.env*\n"),
                            "append `.env*` to .gitignore".to_string(),
                        ))
                    })
                } else {
                    fx.create(".gitignore", DEFAULT_GITIGNORE, "create default .gitignore")
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
                let mut changed = false;
                let result = fx.modify(&rel, |original| {
                    let cleaned = hidden_char_regex().replace_all(original, "").into_owned();
                    (cleaned != original).then(|| {
                        changed = true;
                        (cleaned, strip_description(original))
                    })
                });
                match result {
                    Ok(()) if changed => {
                        fd.fixed = true;
                        fd.message =
                            format!("[AUTO-FIXED] Stripped hidden/bidi Unicode characters: {}", fd.message);
                    }
                    Ok(()) => {}
                    Err(e) => fail(fd, "Failed to clean hidden Unicode", e),
                }
            }
            "AGENT-NO-INSTRUCTIONS" => {
                if INSTRUCTION_NAMES.iter().any(|f| fx.overlay.contains_key(*f) || root.join(f).is_file()) {
                    continue;
                }
                match fx.create("CLAUDE.md", DEFAULT_INSTRUCTIONS, "create default CLAUDE.md") {
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

    #[test]
    fn apply_refuses_a_plan_whose_after_hash_differs() {
        let dir = tempfile::tempdir().unwrap();
        let mut fs = [finding("HYGIENE-NO-GITIGNORE")];
        let mut plan = remediate_findings(dir.path(), &mut fs, Mode::Plan);
        plan[0].sha256_after = "0".repeat(64);
        let mut fs = [finding("HYGIENE-NO-GITIGNORE")];
        let done = remediate_findings(dir.path(), &mut fs, Mode::Apply(&plan));
        assert!(done.is_empty());
        assert!(fs[0].message.contains("differs from the approved plan"), "{}", fs[0].message);
        assert!(!dir.path().join(".gitignore").exists());

        // A modification with a tampered after-hash leaves the file as it was.
        std::fs::write(dir.path().join(".gitignore"), "target/\n").unwrap();
        let mut fs = [finding("SECRETS-ENV-EXPOSED")];
        let mut plan = remediate_findings(dir.path(), &mut fs, Mode::Plan);
        assert_eq!(plan[0].description, "append `.env*` to .gitignore");
        plan[0].sha256_after = "0".repeat(64);
        let mut fs = [finding("SECRETS-ENV-EXPOSED")];
        let done = remediate_findings(dir.path(), &mut fs, Mode::Apply(&plan));
        assert!(done.is_empty());
        assert_eq!(std::fs::read_to_string(dir.path().join(".gitignore")).unwrap(), "target/\n");
    }

    #[test]
    fn overlay_branch_checks_disk_and_plan() {
        let dir = tempfile::tempdir().unwrap();
        let gi = dir.path().join(".gitignore");
        std::fs::write(&gi, "target/\n").unwrap();
        let hidden = "a\u{200b}b\n";
        std::fs::write(dir.path().join("AGENTS.md"), hidden).unwrap();
        let mk = |p: &str| {
            let mut f = finding("AGENT-HIDDEN-UNICODE");
            f.path = Some(p.into());
            f
        };
        let mut fs = [mk("AGENTS.md"), mk("AGENTS.md")];
        let plan = remediate_findings(dir.path(), &mut fs, Mode::Plan);
        assert_eq!(plan.len(), 1);
        // Happy path: the second finding hits the overlay and is a no-op.
        let mut fs = [mk("AGENTS.md"), mk("AGENTS.md")];
        assert_eq!(remediate_findings(dir.path(), &mut fs, Mode::Apply(&plan)).len(), 1);
        assert_eq!(std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap(), "ab\n");

        // Overlay with a tampered plan: the second write must not slip through.
        let mut fx = Fixer {
            root: dir.path(),
            mode: Mode::Apply(&plan),
            overlay: BTreeMap::new(),
            changes: BTreeMap::new(),
        };
        std::fs::write(&gi, "x\n").unwrap();
        fx.record(".gitignore", None, "x\n", "d".into());
        // Disk drifted from our output.
        std::fs::write(&gi, "drift\n").unwrap();
        let err = fx.modify(".gitignore", |c| Some((format!("{c}y"), "d".into()))).unwrap_err();
        assert!(err.to_string().contains("changed"), "{err}");
        // Disk matches, but the result is not in the plan.
        std::fs::write(&gi, "x\n").unwrap();
        let err = fx.modify(".gitignore", |c| Some((format!("{c}y"), "d".into()))).unwrap_err();
        assert!(err.to_string().contains("approved plan"), "{err}");
        assert_eq!(std::fs::read_to_string(&gi).unwrap(), "x\n");
    }

    #[test]
    fn apply_refuses_a_file_edited_after_the_plan() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "target/\n").unwrap();
        let mut fs = [finding("SECRETS-ENV-EXPOSED")];
        let plan = remediate_findings(dir.path(), &mut fs, Mode::Plan);
        std::fs::write(dir.path().join(".gitignore"), "edited\n").unwrap();
        let mut fs = [finding("SECRETS-ENV-EXPOSED")];
        assert!(remediate_findings(dir.path(), &mut fs, Mode::Apply(&plan)).is_empty());
        assert_eq!(std::fs::read_to_string(dir.path().join(".gitignore")).unwrap(), "edited\n");

        // And the happy path applies exactly the plan, atomically.
        std::fs::write(dir.path().join(".gitignore"), "target/\n").unwrap();
        let mut fs = [finding("SECRETS-ENV-EXPOSED")];
        let done = remediate_findings(dir.path(), &mut fs, Mode::Apply(&plan));
        assert_eq!(done, plan);
        assert!(std::fs::read_to_string(dir.path().join(".gitignore")).unwrap().ends_with(".env*\n"));
    }
}
