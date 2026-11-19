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
use super::safe_io::{create_regular_text, is_hardlink, read_regular_text_strict, replace_regular_text};
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

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Read,
    Write,
}

/// Turn an I/O error into one with a fixed phrase that names the cause and
/// carries no path or content.
fn cause(e: std::io::Error, phase: Phase) -> std::io::Error {
    use std::io::ErrorKind as K;
    if is_hardlink(&e) {
        return io_err("file has more than one hard link");
    }
    let os = e.raw_os_error();
    match e.kind() {
        K::InvalidData => e,
        K::AlreadyExists => io_err("file already exists"),
        K::StorageFull | K::QuotaExceeded => io_err("no space left on the device"),
        K::PermissionDenied | K::ReadOnlyFilesystem => io_err("permission denied"),
        K::InvalidInput | K::NotFound => io_err("not a readable regular file"),
        _ if os.is_some() => match phase {
            Phase::Read => io_err("not a readable regular file"),
            Phase::Write => io_err("could not write the file"),
        },
        _ => e,
    }
}

/// A file this run creates or rewrites, held in memory until the commit.
struct Entry {
    text: String,
    /// Hash of the file as first read; `None` when it is created.
    before: Option<String>,
    descriptions: Vec<String>,
}

struct Fixer<'a> {
    root: &'a Path,
    /// Final content of every file the fixers changed or created.
    overlay: BTreeMap<String, Entry>,
}

impl Fixer<'_> {
    fn new(root: &Path) -> Fixer<'_> {
        Fixer { root, overlay: BTreeMap::new() }
    }

    fn exists(&self, rel: &str) -> bool {
        self.overlay.contains_key(rel) || std::fs::symlink_metadata(self.root.join(rel)).is_ok()
    }

    /// Create `rel` with `text`; it must not exist.
    fn create(&mut self, rel: &str, text: &str, description: &str) -> std::io::Result<()> {
        if self.overlay.contains_key(rel) {
            return Ok(()); // an earlier fix in this run already created it
        }
        if self.exists(rel) {
            return Err(io_err("file already exists"));
        }
        self.overlay.insert(
            rel.to_string(),
            Entry { text: text.to_string(), before: None, descriptions: vec![description.to_string()] },
        );
        Ok(())
    }

    /// Replace `rel` with what `f` makes of its current text (`None` = leave
    /// it alone). The file is read once, strictly as UTF-8, on first touch;
    /// later fixes work on the in-memory text.
    fn modify(&mut self, rel: &str, f: impl FnOnce(&str) -> Option<(String, String)>) -> std::io::Result<()> {
        let (cur, before) = match self.overlay.get(rel) {
            Some(e) => (e.text.clone(), e.before.clone()),
            None => {
                let (t, bytes) =
                    read_regular_text_strict(&self.root.join(rel)).map_err(|e| cause(e, Phase::Read))?;
                (t, Some(sha(&bytes)))
            }
        };
        let Some((new, desc)) = f(&cur) else { return Ok(()) };
        let entry = self.overlay.entry(rel.to_string()).or_insert_with(|| Entry {
            text: String::new(),
            before,
            descriptions: Vec::new(),
        });
        entry.text = new;
        entry.descriptions.push(desc);
        Ok(())
    }

    fn change(rel: &str, e: &Entry) -> Change {
        Change {
            path: rel.to_string(),
            sha256_before: e.before.clone(),
            sha256_after: sha(e.text.as_bytes()),
            description: e.descriptions.join("; "),
        }
    }

    /// The path's (first before, final after) must be exactly an approved change.
    fn check_plan(rel: &str, e: &Entry, expected: &[Change]) -> std::io::Result<()> {
        let after = sha(e.text.as_bytes());
        let same_before = |c: &&Change| c.path == rel && c.sha256_before == e.before;
        if e.before.is_some() && !expected.iter().any(|c| same_before(&c)) {
            return Err(io_err("file changed since the plan was approved"));
        }
        if !expected.iter().any(|c| same_before(&c) && c.sha256_after == after) {
            return Err(io_err("the change differs from the approved plan"));
        }
        Ok(())
    }

    /// One create or one replace for `rel`, checked against the plan.
    fn commit(&self, rel: &str, e: &Entry, expected: &[Change]) -> std::io::Result<()> {
        Self::check_plan(rel, e, expected)?;
        let path = self.root.join(rel);
        match &e.before {
            None => create_regular_text(&path, &e.text).map_err(|e| cause(e, Phase::Write)),
            Some(before) => replace_regular_text(&path, |bytes| {
                if &sha(bytes) != before {
                    return Err(io_err("file changed since the plan was approved"));
                }
                Ok(Some(e.text.clone()))
            })
            .map(|_| ())
            .map_err(|e| cause(e, Phase::Write)),
        }
    }
}

/// Whether the `.gitignore` text already ignores `.env`: a whole non-comment
/// line naming it, not undone by a later `!` line.
fn ignores_env(text: &str) -> bool {
    let covers = |p: &str| matches!(p, ".env" | ".env*" | "*.env" | "/.env" | "**/.env" | "**/.env*");
    let mut covered = false;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.strip_prefix('!') {
            Some(p) if covers(p) => covered = false,
            Some(_) => {}
            None if covers(line) => covered = true,
            None => {}
        }
    }
    covered
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
    let mut fx = Fixer::new(root);
    // (finding index, file it depends on, message before the fix note)
    let mut fixed_by: Vec<(usize, String, String)> = Vec::new();
    for (idx, fd) in findings.iter_mut().enumerate() {
        if fd.fixed {
            continue;
        }
        let orig = fd.message.clone();
        let target: &str = match fd.rule.as_str() {
            "HYGIENE-NO-GITIGNORE" | "SECRETS-ENV-EXPOSED" => ".gitignore",
            "AGENT-NO-INSTRUCTIONS" => "CLAUDE.md",
            _ => "",
        };
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
                let mut wrote = false;
                let result = if fx.exists(".gitignore") {
                    fx.modify(".gitignore", |cur| {
                        if ignores_env(cur) {
                            return None;
                        }
                        wrote = true;
                        Some((
                            format!("{cur}\n# Added by audit auto-remediation\n.env*\n"),
                            "append `.env*` to .gitignore".to_string(),
                        ))
                    })
                } else {
                    wrote = true;
                    fx.create(".gitignore", DEFAULT_GITIGNORE, "create default .gitignore")
                };
                match result {
                    Ok(()) if wrote => {
                        fd.fixed = true;
                        fd.message = format!("[AUTO-FIXED] Added `.env*` to .gitignore: {}", fd.message);
                    }
                    Ok(()) => {}
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
        if fd.fixed {
            let rel =
                if target.is_empty() { fd.path.clone().unwrap_or_default() } else { target.to_string() };
            fixed_by.push((idx, rel, orig));
        }
    }
    let Mode::Apply(expected) = mode else {
        return fx.overlay.iter().map(|(rel, e)| Fixer::change(rel, e)).collect();
    };
    // Every approved change is checked before the first write, then each file
    // is created or replaced exactly once.
    let mut failed: BTreeMap<String, std::io::Error> = BTreeMap::new();
    for (rel, e) in &fx.overlay {
        if let Err(err) = Fixer::check_plan(rel, e, expected) {
            failed.insert(rel.clone(), err);
        }
    }
    let mut done = Vec::new();
    for (rel, e) in &fx.overlay {
        if failed.contains_key(rel) {
            continue;
        }
        match fx.commit(rel, e, expected) {
            Ok(()) => done.push(Fixer::change(rel, e)),
            Err(err) => {
                failed.insert(rel.clone(), err);
            }
        }
    }
    for (idx, rel, orig) in fixed_by {
        if let Some(err) = failed.get(&rel) {
            let fd = &mut findings[idx];
            fd.fixed = false;
            fd.message = orig;
            fail(fd, "Failed to apply the fix", err);
        }
    }
    done
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
    }

    /// Two distinct edits to one file in one run: one write, checked against
    /// (first before, final after).
    #[test]
    fn two_edits_to_one_file_plan_and_apply() {
        let dir = tempfile::tempdir().unwrap();
        let gi = dir.path().join(".gitignore");
        std::fs::write(&gi, "target/\n").unwrap();
        let edits = |fx: &mut Fixer<'_>| {
            fx.modify(".gitignore", |c| Some((format!("{c}one\n"), "add one".into()))).unwrap();
            fx.modify(".gitignore", |c| Some((format!("{c}two\n"), "add two".into()))).unwrap();
        };
        let mut fx = Fixer::new(dir.path());
        edits(&mut fx);
        let plan: Vec<Change> = fx.overlay.iter().map(|(r, e)| Fixer::change(r, e)).collect();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].description, "add one; add two");
        assert_eq!(std::fs::read_to_string(&gi).unwrap(), "target/\n", "planning writes nothing");

        let mut fx = Fixer::new(dir.path());
        edits(&mut fx);
        for (rel, e) in &fx.overlay {
            fx.commit(rel, e, &plan).unwrap();
        }
        assert_eq!(std::fs::read_to_string(&gi).unwrap(), "target/\none\ntwo\n");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        // A plan for only the first edit does not cover the combined result.
        std::fs::write(&gi, "target/\n").unwrap();
        let mut fx = Fixer::new(dir.path());
        edits(&mut fx);
        let mut partial = plan.clone();
        partial[0].sha256_after = sha(b"target/\none\n");
        let (rel, e) = fx.overlay.iter().next().unwrap();
        let err = fx.commit(rel, e, &partial).unwrap_err();
        assert!(err.to_string().contains("approved plan"), "{err}");
        assert_eq!(std::fs::read_to_string(&gi).unwrap(), "target/\n");
    }

    #[test]
    fn create_then_append_in_one_run_is_one_create() {
        let dir = tempfile::tempdir().unwrap();
        let run = |mode: Mode<'_>| {
            let mut fx = Fixer::new(dir.path());
            fx.create(".gitignore", "a\n", "create").unwrap();
            fx.modify(".gitignore", |c| Some((format!("{c}b\n"), "append".into()))).unwrap();
            let plan: Vec<Change> = fx.overlay.iter().map(|(r, e)| Fixer::change(r, e)).collect();
            if let Mode::Apply(exp) = mode {
                for (rel, e) in &fx.overlay {
                    fx.commit(rel, e, exp).unwrap();
                }
            }
            plan
        };
        let plan = run(Mode::Plan);
        assert_eq!(plan[0].sha256_before, None);
        run(Mode::Apply(&plan));
        assert_eq!(std::fs::read_to_string(dir.path().join(".gitignore")).unwrap(), "a\nb\n");
    }

    #[test]
    fn env_lookalikes_do_not_count_as_ignored() {
        for text in ["!.env\n", ".envrc\n", ".env.example\n", "# .env\n", ".env\n!.env\n"] {
            assert!(!ignores_env(text), "{text:?}");
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(".gitignore"), text).unwrap();
            let mut fs = [finding("SECRETS-ENV-EXPOSED")];
            let plan = remediate_findings(dir.path(), &mut fs, Mode::Plan);
            assert_eq!(plan.len(), 1, "{text:?}");
            assert!(fs[0].fixed);
            let mut fs = [finding("SECRETS-ENV-EXPOSED")];
            assert_eq!(remediate_findings(dir.path(), &mut fs, Mode::Apply(&plan)).len(), 1);
            assert!(std::fs::read_to_string(dir.path().join(".gitignore")).unwrap().ends_with(".env*\n"));
        }
        for text in [".env\n", "x\n.env*\n", "*.env\n", "/.env\n", "!.env\n.env\n"] {
            assert!(ignores_env(text), "{text:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
        let mut fs = [finding("SECRETS-ENV-EXPOSED")];
        assert!(remediate_findings(dir.path(), &mut fs, Mode::Plan).is_empty());
        assert!(!fs[0].fixed, "nothing written, nothing reported fixed");
    }

    #[cfg(unix)]
    #[test]
    fn a_hardlinked_target_names_its_cause() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("AGENTS.md");
        std::fs::write(&f, "a\u{200b}b\n").unwrap();
        std::fs::hard_link(&f, dir.path().join("other.md")).unwrap();
        let mk = || {
            let mut fd = finding("AGENT-HIDDEN-UNICODE");
            fd.path = Some("AGENTS.md".into());
            fd
        };
        let mut fs = [mk()];
        let plan = remediate_findings(dir.path(), &mut fs, Mode::Plan);
        assert!(plan.is_empty(), "a hardlinked file cannot be planned");
        assert!(fs[0].message.contains("more than one hard link"), "{}", fs[0].message);
    }

    #[test]
    fn io_causes_have_fixed_phrases() {
        use std::io::{Error, ErrorKind as K};
        let msg = |e: Error, p| cause(e, p).to_string();
        assert_eq!(msg(Error::from_raw_os_error(28), Phase::Write), "no space left on the device");
        assert_eq!(msg(Error::from_raw_os_error(13), Phase::Write), "permission denied");
        assert_eq!(msg(Error::from_raw_os_error(5), Phase::Write), "could not write the file");
        assert_eq!(msg(Error::from_raw_os_error(5), Phase::Read), "not a readable regular file");
        assert_eq!(msg(Error::from(K::NotFound), Phase::Read), "not a readable regular file");
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
