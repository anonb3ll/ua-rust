//! Safe, non-destructive auto-fixes for a few audit findings.
//!
//! Only these are applied: create or extend `.gitignore` (default entries,
//! `.env*`), strip hidden Unicode from an instruction file, and scaffold a
//! minimal `CLAUDE.md` when no instruction file exists. Every read and write
//! goes through `safe_io`, so a FIFO, device or symlink at a target leaves the
//! finding unfixed with an `[AUTO-FIX-FAILED]` message. Nothing else is ever
//! touched; secrets are never rewritten.

use std::path::{Component, Path};

use super::rules::Finding;
use super::safe_io::{read_regular_text, write_regular_text};
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

pub fn remediate_findings(root: &Path, findings: &mut [Finding]) {
    for fd in findings.iter_mut() {
        if fd.fixed {
            continue;
        }
        match fd.rule.as_str() {
            "HYGIENE-NO-GITIGNORE" => match write_regular_text(&root.join(".gitignore"), DEFAULT_GITIGNORE) {
                Ok(()) => {
                    fd.fixed = true;
                    fd.message = format!("[AUTO-FIXED] Created default .gitignore: {}", fd.message);
                }
                Err(e) => fail(fd, "Failed to create .gitignore", e),
            },
            "SECRETS-ENV-EXPOSED" => {
                let path = root.join(".gitignore");
                let result = if path.exists() {
                    match read_regular_text(&path) {
                        None => Err(std::io::Error::other("not a readable regular file")),
                        Some(cur) if [".env*", "*.env", ".env"].iter().any(|p| cur.contains(p)) => Ok(()),
                        Some(cur) => write_regular_text(
                            &path,
                            &format!("{cur}\n# Added by audit auto-remediation\n.env*\n"),
                        ),
                    }
                } else {
                    write_regular_text(&path, DEFAULT_GITIGNORE)
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
                let file = root.join(&rel);
                let Some(original) = read_regular_text(&file) else {
                    fail(fd, "Failed to clean hidden Unicode", "not a readable regular file");
                    continue;
                };
                let cleaned = hidden_char_regex().replace_all(&original, "").into_owned();
                if cleaned != original {
                    match write_regular_text(&file, &cleaned) {
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
                if INSTRUCTION_NAMES.iter().any(|f| root.join(f).is_file()) {
                    continue;
                }
                match write_regular_text(&root.join("CLAUDE.md"), DEFAULT_INSTRUCTIONS) {
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
}
