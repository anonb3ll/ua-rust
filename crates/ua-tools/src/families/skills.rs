//! `skill_review`: rule-based quality checks for agent skills (`SKILL.md`).
//!
//! A deterministic complement to a judgment review. Hosts load only the
//! front-matter `name` and `description` before a skill is invoked, so the
//! description is the whole trigger surface and competes with sibling skills;
//! the body is read only after the skill fires. The rules verify that
//! contract: front-matter validity, description trigger quality and sibling
//! overlap, body size and payload, filler phrases and support-file links.
//! Read-only.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};

use super::audit::rules::{Finding, SEVERITIES, severity_rank};
use super::audit::{read_text_lossy, resolve_target};
use crate::registry::{Registry, ToolCtx, blocking, tool};

const NAME_MAX: usize = 64;
const DESC_MAX: usize = 1024;
const DESC_MIN: usize = 20;
const BODY_MAX_LINES: usize = 500;
const BODY_MIN_CONTENT_LINES: usize = 3;
pub const MAX_SKILLS: usize = 100;
const OVERLAP_THRESHOLD: f64 = 0.4;

const HYPE_WORDS: [&str; 8] = [
    "powerful",
    "comprehensive",
    "advanced",
    "robust",
    "seamless",
    "state-of-the-art",
    "best-in-class",
    "cutting-edge",
];

const FILLER_PHRASES: [&str; 6] = [
    "think carefully",
    "use your best judgment",
    "be smart",
    "be thorough",
    "do your best",
    "high-quality output",
];

/// Words too common in descriptions to signal genuine overlap.
const STOPWORDS: &str = "a an the to for of in on and or with when where while use uses using used this that \
these those it its is are be been was were as by from at into your you skill skills file files user users \
asked want wants";

struct Rx {
    kebab: Regex,
    trigger: Regex,
    first_person: Regex,
    md_link: Regex,
    scheme: Regex,
    token: Regex,
}

fn rx() -> &'static Rx {
    static RX: OnceLock<Rx> = OnceLock::new();
    RX.get_or_init(|| {
        let c = |p: &str| Regex::new(p).expect("skill pattern compiles");
        Rx {
            kebab: c(r"^[a-z0-9]+(-[a-z0-9]+)*$"),
            trigger: c(r"(?i)\buse\s+(when|this|it|for)\b|\bwhen\s+(the\s+user|asked|you)\b|\btrigger\b"),
            first_person: c(r"\bI\b|\bmy\b"),
            md_link: c(r"\[[^\]]*\]\(([^)#\s][^)]*)\)"),
            scheme: c(r"^[a-z][a-z0-9+.-]*:"),
            token: c(r"[a-z0-9']+"),
        }
    })
}

struct Skill {
    dir: PathBuf,
    /// `SKILL.md` path shown in findings.
    relpath: String,
    meta: Map<String, Value>,
    meta_error: Option<String>,
    body: String,
    /// 1-based line where the body begins.
    body_start: usize,
    fm_lines: Vec<String>,
}

impl Skill {
    fn text_field(&self, key: &str) -> Option<&str> {
        self.meta.get(key).and_then(Value::as_str)
    }

    fn dir_name(&self) -> String {
        self.dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }

    /// 1-based line of a top-level front-matter key, for clickable findings.
    fn meta_line(&self, key: &str) -> Option<usize> {
        self.fm_lines.iter().position(|l| l.starts_with(&format!("{key}:"))).map(|i| i + 2)
    }
}

fn parse_skill(dir: &Path, relpath: String) -> Skill {
    let text = read_text_lossy(&dir.join("SKILL.md")).unwrap_or_default();
    let mut skill = Skill {
        dir: dir.to_path_buf(),
        relpath,
        meta: Map::new(),
        meta_error: None,
        body: String::new(),
        body_start: 1,
        fm_lines: Vec::new(),
    };
    let Some(rest) = text.strip_prefix("---\n") else {
        skill.meta_error = Some("file does not start with a `---` YAML frontmatter block".into());
        skill.body = text;
        return skill;
    };
    let Some(end) = rest.find("\n---\n") else {
        skill.meta_error = Some("frontmatter block is never closed with `---`".into());
        skill.body = text;
        return skill;
    };
    let fm_text = &rest[..end];
    skill.fm_lines = fm_text.lines().map(str::to_string).collect();
    skill.body = rest[end + 5..].to_string();
    skill.body_start = skill.fm_lines.len() + 3;
    match serde_saphyr::from_str::<Value>(fm_text) {
        Err(e) => skill.meta_error = Some(format!("frontmatter is not valid YAML: {e}")),
        Ok(Value::Object(m)) => skill.meta = m,
        Ok(_) => skill.meta_error = Some("frontmatter is not a YAML mapping".into()),
    }
    skill
}

fn finding(
    skill: &Skill,
    rule: &str,
    severity: &'static str,
    line: Option<usize>,
    message: String,
    fix: &str,
) -> Finding {
    Finding {
        rule: rule.into(),
        severity,
        message,
        fix: fix.into(),
        path: Some(skill.relpath.clone()),
        line,
        fixed: false,
    }
}

fn check_frontmatter(skill: &Skill, out: &mut Vec<Finding>) {
    if let Some(err) = &skill.meta_error {
        out.push(finding(
            skill,
            "SKILL-FRONTMATTER",
            "high",
            Some(1),
            err.clone(),
            "add a YAML frontmatter block with `name` and `description`; hosts load only those two fields to decide when to invoke the skill",
        ));
        return;
    }
    for key in ["name", "description"] {
        if skill.text_field(key).is_none_or(str::is_empty) {
            out.push(finding(
                skill,
                "SKILL-FRONTMATTER",
                "high",
                Some(1),
                format!("frontmatter is missing `{key}` (or it is not a string)"),
                &format!("add a `{key}:` field; without it the skill cannot be matched to requests"),
            ));
        }
    }
}

fn check_name(skill: &Skill, out: &mut Vec<Finding>) {
    let Some(name) = skill.text_field("name").filter(|n| !n.is_empty()) else { return };
    let line = skill.meta_line("name");
    let dir = skill.dir_name();
    if name != dir {
        out.push(finding(
            skill,
            "SKILL-NAME",
            "medium",
            line,
            format!("name {name:?} does not match its directory {dir:?}"),
            "rename the directory or the `name` field so they match exactly",
        ));
    }
    if !rx().kebab.is_match(name) {
        out.push(finding(
            skill,
            "SKILL-NAME",
            "medium",
            line,
            format!("name {name:?} is not kebab-case (lowercase letters, digits, hyphens)"),
            "use a kebab-case name, e.g. `skill-review`",
        ));
    }
    if name.chars().count() > NAME_MAX {
        out.push(finding(
            skill,
            "SKILL-NAME",
            "medium",
            line,
            format!("name is {} chars (limit {NAME_MAX})", name.chars().count()),
            "shorten the name",
        ));
    }
}

fn check_description(skill: &Skill, out: &mut Vec<Finding>) {
    let Some(desc) = skill.text_field("description").filter(|d| !d.is_empty()) else { return };
    let line = skill.meta_line("description");
    let len = desc.chars().count();
    if len > DESC_MAX {
        out.push(finding(
            skill,
            "SKILL-DESC-LENGTH",
            "medium",
            line,
            format!("description is {len} chars (limit {DESC_MAX})"),
            "tighten the description; keep what it does plus concrete trigger scenarios",
        ));
    } else if len < DESC_MIN {
        out.push(finding(
            skill,
            "SKILL-DESC-LENGTH",
            "low",
            line,
            format!("description is only {len} chars — too thin to carry trigger vocabulary"),
            "state what the skill does and when to use it, with words a user would type",
        ));
    }
    if !rx().trigger.is_match(desc) {
        let buried = rx().trigger.is_match(&skill.body);
        let (sev, msg) = if buried {
            (
                "medium",
                "trigger guidance ('use when …') lives in the body but not the description; the body is only loaded after invocation, so it cannot help triggering",
            )
        } else {
            ("low", "description has no 'Use when …' trigger guidance")
        };
        out.push(finding(
            skill,
            "SKILL-DESC-TRIGGER",
            sev,
            line,
            msg.into(),
            "move/add concrete trigger scenarios into the `description` field",
        ));
    }
    if rx().first_person.is_match(desc) {
        out.push(finding(
            skill,
            "SKILL-DESC-VOICE",
            "low",
            line,
            "description uses first person; hosts match descriptions written in third person".into(),
            "rewrite as 'Reviews …. Use when …', not 'I review …'",
        ));
    }
    let lower = desc.to_lowercase();
    let hits: Vec<&str> = HYPE_WORDS.iter().copied().filter(|w| lower.contains(w)).collect();
    if !hits.is_empty() {
        out.push(finding(
            skill,
            "SKILL-DESC-HYPE",
            "info",
            line,
            format!("quality adjectives do not help request matching: {}", hits.join(", ")),
            "replace adjectives with concrete tasks and trigger phrases",
        ));
    }
}

/// Front-matter keys that grant a skill tools, hooks or permissions on the
/// host. A distributed skill must not carry them.
pub(crate) const PERMISSION_KEYS: [&str; 5] =
    ["allowed-tools", "allowed_tools", "hooks", "permissions", "disallowed-tools"];

/// Code points that hide or reorder text from a human reader: Unicode tag
/// characters (U+E0000-E007F), zero-width characters and bidi controls.
pub(crate) fn hidden_char(c: char) -> bool {
    matches!(c,
        '\u{E0000}'..='\u{E007F}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{061C}'
        | '\u{180E}'
        | '\u{FEFF}')
}

/// Hidden code points in `text`: (1-based line, code point), at most 10.
pub(crate) fn hidden_chars(text: &str) -> Vec<(usize, char)> {
    text.lines()
        .enumerate()
        .flat_map(|(i, l)| l.chars().filter(|c| hidden_char(*c)).map(move |c| (i + 1, c)))
        .take(10)
        .collect()
}

/// Permission-bearing keys of a front-matter mapping.
pub(crate) fn permission_keys(meta: &Map<String, Value>) -> Vec<String> {
    meta.keys().filter(|k| PERMISSION_KEYS.contains(&k.to_ascii_lowercase().as_str())).cloned().collect()
}

/// Security checks: a skill reaches every host it is distributed to, so it
/// may not grant itself tools or hooks, or carry text a reviewer cannot see.
fn check_security(skill: &Skill, out: &mut Vec<Finding>) {
    for key in permission_keys(&skill.meta) {
        out.push(finding(
            skill,
            "SKILL-PERMISSIONS",
            "high",
            skill.meta_line(&key),
            format!("frontmatter key `{key}` grants the skill tools, hooks or permissions on the host"),
            "remove it; a distributed skill gets no permissions of its own",
        ));
    }
    let text = format!("{}\n{}", skill.fm_lines.join("\n"), skill.body);
    for (line, c) in hidden_chars(&text) {
        out.push(finding(
            skill,
            "SKILL-HIDDEN-TEXT",
            "high",
            Some(line + 1),
            format!("invisible or bidi control code point U+{:04X}", c as u32),
            "remove it; text a reviewer cannot see must not reach an agent",
        ));
    }
}

fn check_body(skill: &Skill, out: &mut Vec<Finding>) {
    let lines: Vec<&str> = skill.body.lines().collect();
    let content = lines.iter().filter(|l| !l.trim().is_empty()).count();
    if lines.len() > BODY_MAX_LINES {
        out.push(finding(
            skill,
            "SKILL-BODY-LENGTH",
            "medium",
            Some(skill.body_start),
            format!("body is {} lines (guideline ≤{BODY_MAX_LINES})", lines.len()),
            "move reference material into support files the body points to, loaded on demand",
        ));
    }
    if content < BODY_MIN_CONTENT_LINES && skill.meta_error.is_none() {
        out.push(finding(
            skill,
            "SKILL-BODY-EMPTY",
            "medium",
            Some(skill.body_start),
            format!("body has {content} non-blank lines — no payload beyond the description"),
            "add the concrete instructions the skill exists to deliver, or delete it",
        ));
    }
    let lower: Vec<String> = lines.iter().map(|l| l.to_lowercase()).collect();
    for phrase in FILLER_PHRASES {
        if let Some(i) = lower.iter().position(|l| l.contains(phrase)) {
            out.push(finding(
                skill,
                "SKILL-BODY-FILLER",
                "info",
                Some(skill.body_start + i),
                format!("generic filler {phrase:?} restates default model behavior"),
                "delete it or replace with an operational instruction",
            ));
        }
    }
    for (i, line) in lines.iter().enumerate() {
        for m in rx().md_link.captures_iter(line) {
            let target = m[1].trim();
            if rx().scheme.is_match(target) || target.starts_with('/') {
                continue; // URL, mailto: or absolute path: not a support file
            }
            if !skill.dir.join(target).exists() {
                out.push(finding(
                    skill,
                    "SKILL-BROKEN-REF",
                    "medium",
                    Some(skill.body_start + i),
                    format!("linked support file {target:?} does not exist"),
                    "fix the link or add the file; broken references break progressive disclosure",
                ));
            }
        }
    }
}

fn desc_tokens(desc: &str) -> BTreeSet<String> {
    let stop: BTreeSet<&str> = STOPWORDS.split_whitespace().collect();
    rx().token
        .find_iter(&desc.to_lowercase())
        .map(|m| m.as_str().to_string())
        .filter(|w| w.chars().count() > 2 && !stop.contains(w.as_str()))
        .collect()
}

fn check_overlap(pairs: &[(&Skill, &Skill)], out: &mut Vec<Finding>) {
    for (a, b) in pairs {
        let ta = desc_tokens(a.text_field("description").unwrap_or(""));
        let tb = desc_tokens(b.text_field("description").unwrap_or(""));
        if ta.len() < 8 || tb.len() < 8 {
            continue;
        }
        let shared = ta.intersection(&tb).count() as f64;
        let similarity = shared / ta.union(&tb).count() as f64;
        if similarity >= OVERLAP_THRESHOLD {
            out.push(finding(
                a,
                "SKILL-DESC-OVERLAP",
                "medium",
                a.meta_line("description"),
                format!(
                    "description overlaps sibling skill {:?} ({:.0}% shared vocabulary); invocation between them is unreliable",
                    b.dir_name(),
                    similarity * 100.0
                ),
                "differentiate the two descriptions and state the boundary ('not for X — use Y for that')",
            ));
        }
    }
}

/// The skill directories to review and the base their paths are shown against.
fn collect_skill_dirs(root: &Path, shown: &str) -> UaResult<(Vec<PathBuf>, PathBuf)> {
    if root.is_file() {
        if root.file_name().is_none_or(|n| n != "SKILL.md") {
            return Err(UaError::invalid(format!("{shown:?} is a file but not a SKILL.md")));
        }
        let parent = root.parent().map(Path::to_path_buf).unwrap_or_default();
        return Ok((vec![parent.clone()], parent));
    }
    if !root.is_dir() {
        return Err(UaError::not_found(format!("not found: {shown:?}")));
    }
    if root.join("SKILL.md").is_file() {
        return Ok((vec![root.to_path_buf()], root.to_path_buf()));
    }
    let mut children: Vec<PathBuf> = std::fs::read_dir(root)
        .map_err(|e| UaError::invalid(format!("cannot read {shown:?}: {e}")))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("SKILL.md").is_file())
        .collect();
    children.sort();
    if children.is_empty() {
        return Err(UaError::not_found(format!(
            "no SKILL.md found at {shown:?} or in its immediate subdirectories"
        )));
    }
    Ok((children, root.to_path_buf()))
}

pub(crate) fn review_dirs(skill_dirs: Vec<PathBuf>, base: &Path, min_severity: &str) -> Value {
    let truncated = skill_dirs.len() > MAX_SKILLS;
    let skill_dirs: Vec<PathBuf> = skill_dirs.into_iter().take(MAX_SKILLS).collect();
    let rel = |d: &Path| -> String {
        let md = d.join("SKILL.md");
        md.strip_prefix(base)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| md.to_string_lossy().into_owned())
    };
    let skills: Vec<Skill> = skill_dirs.iter().map(|d| parse_skill(d, rel(d))).collect();

    let mut findings = Vec::new();
    for skill in &skills {
        check_frontmatter(skill, &mut findings);
        check_name(skill, &mut findings);
        check_description(skill, &mut findings);
        check_body(skill, &mut findings);
        check_security(skill, &mut findings);
    }

    if skills.len() > 1 {
        let mut pairs = Vec::new();
        for i in 0..skills.len() {
            for j in i + 1..skills.len() {
                pairs.push((&skills[i], &skills[j]));
            }
        }
        check_overlap(&pairs, &mut findings);
    } else if let Some(target) = skills.first() {
        // A single skill is compared against its unreviewed siblings: their
        // descriptions compete with it at invocation time.
        let mut sibling_dirs: Vec<PathBuf> = target
            .dir
            .parent()
            .and_then(|p| std::fs::read_dir(p).ok())
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| p.is_dir() && *p != target.dir && p.join("SKILL.md").is_file())
                    .collect()
            })
            .unwrap_or_default();
        sibling_dirs.sort();
        let siblings: Vec<Skill> = sibling_dirs.iter().map(|d| parse_skill(d, rel(d))).collect();
        let pairs: Vec<(&Skill, &Skill)> = siblings.iter().map(|s| (target, s)).collect();
        check_overlap(&pairs, &mut findings);
    }

    findings.sort_by(|a, b| {
        severity_rank(a.severity)
            .cmp(&severity_rank(b.severity))
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.unwrap_or(0).cmp(&b.line.unwrap_or(0)))
    });
    let count = |sev: &str| findings.iter().filter(|f| f.severity == sev).count();
    let summary: Map<String, Value> = SEVERITIES.iter().map(|s| (s.to_string(), json!(count(s)))).collect();
    let status = if count("high") > 0 {
        "fail"
    } else if count("medium") > 0 {
        "warn"
    } else {
        "pass"
    };
    let cutoff = severity_rank(min_severity);
    json!({
        "root": base.to_string_lossy(),
        "skills_reviewed": skills.iter().map(Skill::dir_name).collect::<Vec<_>>(),
        "status": status,
        "summary": summary,
        "findings": findings.iter().filter(|f| severity_rank(f.severity) <= cutoff).map(Finding::to_json).collect::<Vec<_>>(),
        "truncated": truncated,
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillReviewArgs {
    /// A `SKILL.md` file, one skill directory, or a directory of skill
    /// directories. Workspace-relative, or absolute under an audit root.
    /// Default `.`.
    pub path: Option<String>,
    /// Lowest severity returned: `high`, `medium`, `low` or `info` (default).
    pub min_severity: Option<String>,
}

async fn skill_review(ctx: ToolCtx, a: SkillReviewArgs) -> UaResult<Value> {
    let min = a.min_severity.unwrap_or_else(|| "info".into());
    if !SEVERITIES.contains(&min.as_str()) {
        return Err(UaError::invalid(format!("min_severity must be one of {}", SEVERITIES.join(", "))));
    }
    let path = a.path.unwrap_or_else(|| ".".into());
    blocking(move || {
        let target = resolve_target(&ctx, &path, false, false)?;
        let (dirs, base) = collect_skill_dirs(&target.path, &path)?;
        Ok(review_dirs(dirs, &base, &min))
    })
    .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "skill_review",
            "Lint agent skills (SKILL.md) against the auto-invocation contract: front-matter validity, kebab-case name matching its directory, description length and 'use when' trigger vocabulary, first-person voice and hype words, description overlap with sibling skills, body size and payload, filler phrases, and broken support-file links. `path` may be one SKILL.md, one skill directory or a directory of them (at most 100 are reviewed per call). Read-only. Returns {root, skills_reviewed, status, summary, findings, truncated}.",
            skill_review,
        )
        .family("skills")
        .read_only(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_drop_stopwords_and_short_words() {
        let t = desc_tokens("Use this skill to review the pull request diff");
        assert!(t.contains("review") && t.contains("pull") && t.contains("diff"));
        assert!(!t.contains("the") && !t.contains("use") && !t.contains("to"));
    }

    #[test]
    fn unclosed_frontmatter_is_reported() {
        let dir = std::env::temp_dir().join(format!("skill-unit-{}", std::process::id()));
        let skill_dir = dir.join("a-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), "---\nname: a-skill\n").unwrap();
        let report = review_dirs(vec![skill_dir], &dir, "info");
        assert_eq!(report["status"], "fail");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
