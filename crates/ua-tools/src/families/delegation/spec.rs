//! The Delegation Spec Standard: a structural lint on delegated work.
//!
//! One rule matters most: a Definition of Done must name an observable
//! behaviour of the artifact, not only build, lint or test status. A green
//! build proves the code compiles and that the assertions someone wrote agree
//! with the code someone wrote; it does not prove the artifact does its job.
//!
//! This is not a security boundary or a quality oracle. It checks that a
//! delegation states how it will be proven, so a reviewer has something to
//! hold the work against. The matching rules are the original hub's regular
//! expressions, hand-ported (case-insensitive, Unicode word boundaries).

use serde::Serialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};

pub const REQUIRED_SECTIONS: [&str; 5] = ["objective", "scope", "definition of done", "tdd", "boundaries"];

fn aliases(section: &str) -> &'static [&'static str] {
    match section {
        "objective" => &["objective", "goal"],
        "scope" => &["scope", "files you may touch"],
        "definition of done" => &["definition of done", "dod", "acceptance criteria", "verification"],
        "tdd" => &["tdd", "tdd constraints", "tdd boundary", "test constraints"],
        "boundaries" => &["boundaries", "out of scope", "non-goals", "do not"],
        _ => &[],
    }
}

const MIN_DOD_CRITERIA: usize = 2;

/// The gates line used by the template and the builder. It is build status
/// on purpose: it never counts as an observable behaviour.
pub const GATES_LINE: &str = "- Gates: the test suite, lint, format check and CI pass";

pub const TEMPLATE: &str = "\
### Objective
<What must be true afterwards that is not true now. One paragraph.>

### Scope
Files this delegation may touch:
- <path>
- <path>

### Definition of Done
At least one criterion must name an OBSERVABLE BEHAVIOUR of the artifact.
\"the build passes\" is necessary and never sufficient.
- <the capability, exercised: what is called, with what input, and what is
  asserted about the result>
- <the failure mode, exercised: what goes wrong, and what the code does about
  it - assert the refusal, not just the happy path>
- Gates: the test suite, lint, format check and CI pass

### TDD Constraints
The test suite is GROUND TRUTH. Tests may not be muted, skipped, deleted, or
weakened to make a change pass. A test that appears wrong is an escalation, not
an edit. State here what may be stubbed and what must be real:
- Stub: <e.g. the HTTP layer, the clock>
- Must be real: <e.g. the git repository, the database schema>

### Boundaries
- <what this delegation must NOT change>
- <the restrictive-direction rule: which invariant may not be relaxed to make
  the work easier>
";

#[derive(Debug, Clone, Serialize)]
pub struct SpecCheck {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub sections_present: Vec<String>,
    pub sections_missing: Vec<String>,
    pub dod_criteria: usize,
    pub behavioural_criteria: usize,
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn line_starts(chars: &[char]) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(0).chain(chars.iter().enumerate().filter(|(_, c)| **c == '\n').map(|(i, _)| i + 1))
}

fn skip(chars: &[char], mut i: usize, pred: impl Fn(char) -> bool) -> usize {
    while i < chars.len() && pred(chars[i]) {
        i += 1;
    }
    i
}

/// `word` at `pos`, followed by a word boundary.
fn word_at(chars: &[char], pos: usize, word: &str) -> Option<usize> {
    let mut i = pos;
    for w in word.chars() {
        if i >= chars.len() || chars[i] != w {
            return None;
        }
        i += 1;
    }
    if i < chars.len() && is_word(chars[i]) {
        return None;
    }
    Some(i)
}

/// Positions where an alias may start on the line beginning at `i`: right
/// there, after 1-6 `#` and spaces, or after `**`.
fn heading_candidates(chars: &[char], i: usize, ws: impl Fn(char) -> bool) -> Vec<usize> {
    let mut out = vec![i];
    if i < chars.len() && chars[i] == '#' {
        let run = skip(chars, i, |c| c == '#') - i;
        if (1..=6).contains(&run) {
            out.push(skip(chars, i + run, ws));
        }
    } else if chars.get(i) == Some(&'*') && chars.get(i + 1) == Some(&'*') {
        out.push(i + 2);
    }
    out
}

/// `(?:^|\n)\s*(?:#{1,6}\s*|\*\*)?ALIAS\b`
fn has_section(chars: &[char], section: &str) -> bool {
    aliases(section).iter().any(|alias| {
        line_starts(chars).any(|start| {
            let i = skip(chars, start, char::is_whitespace);
            heading_candidates(chars, i, char::is_whitespace)
                .into_iter()
                .any(|c| word_at(chars, c, alias).is_some())
        })
    })
}

/// The lookahead that ends a section body: `\n\s*(?:#{1,6}\s*[a-z]|\*\*[a-z]|[a-z][a-z /]{3,}(?:\n|\s*\())`.
fn heading_at(chars: &[char], q: usize) -> bool {
    let k = skip(chars, q, char::is_whitespace);
    let Some(&c) = chars.get(k) else { return false };
    if c == '#' {
        let run = skip(chars, k, |c| c == '#') - k;
        if !(1..=6).contains(&run) {
            return false;
        }
        let m = skip(chars, k + run, char::is_whitespace);
        return chars.get(m).is_some_and(char::is_ascii_alphabetic);
    }
    if c == '*' {
        return chars.get(k + 1) == Some(&'*') && chars.get(k + 2).is_some_and(char::is_ascii_alphabetic);
    }
    if c.is_ascii_alphabetic() {
        let e = skip(chars, k + 1, |c| c.is_ascii_alphabetic() || c == ' ' || c == '/');
        if e - (k + 1) < 3 {
            return false;
        }
        if chars.get(e) == Some(&'\n') {
            return true;
        }
        let f = skip(chars, e, char::is_whitespace);
        return chars.get(f) == Some(&'(');
    }
    false
}

/// Text between the Definition of Done heading and the next heading. An
/// empty section yields "" rather than running on into the next one.
fn dod_body(chars: &[char]) -> String {
    let blank = |c: char| c == ' ' || c == '\t';
    for alias in aliases("definition of done") {
        for start in line_starts(chars) {
            let i = skip(chars, start, blank);
            for c in heading_candidates(chars, i, blank) {
                let Some(end) = word_at(chars, c, alias) else { continue };
                let mut j = skip(chars, end, |c| matches!(c, ':' | '*' | '\t' | ' '));
                if chars.get(j) == Some(&'\r') {
                    j += 1;
                }
                if chars.get(j) != Some(&'\n') {
                    continue;
                }
                let body_start = j + 1;
                let mut p = body_start;
                while p < chars.len() {
                    if chars[p] == '\n' && heading_at(chars, p + 1) {
                        break;
                    }
                    p += 1;
                }
                return chars[body_start.min(p)..p].iter().collect();
            }
        }
    }
    String::new()
}

/// `\s*(?:[-*]|\d+[.)])\s+\S` at the start of a line.
fn is_bullet(line: &str) -> bool {
    let chars: Vec<char> = line.chars().collect();
    let i = skip(&chars, 0, char::is_whitespace);
    let j = match chars.get(i) {
        Some('-' | '*') => i + 1,
        Some(c) if c.is_ascii_digit() => {
            let d = skip(&chars, i, |c| c.is_ascii_digit());
            if !matches!(chars.get(d), Some('.' | ')')) {
                return false;
            }
            d + 1
        }
        _ => return false,
    };
    let k = skip(&chars, j, char::is_whitespace);
    k > j && k < chars.len()
}

fn criteria(body: &str) -> Vec<String> {
    let bullets: Vec<String> = body
        .lines()
        .filter(|ln| is_bullet(ln))
        .map(|ln| ln.trim().trim_start_matches(|c| "-*0123456789.) ".contains(c)).trim().to_string())
        .collect();
    if !bullets.is_empty() {
        return bullets.into_iter().filter(|b| !b.is_empty()).collect();
    }
    body.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect()
}

/// A word token and the separator text that follows it.
struct Tok {
    word: String,
    sep_after: String,
}

fn tokens(text: &str) -> Vec<Tok> {
    let lower = text.to_lowercase();
    let mut out: Vec<Tok> = Vec::new();
    let mut cur = String::new();
    let mut sep = String::new();
    for c in lower.chars() {
        if is_word(c) {
            if cur.is_empty()
                && let Some(last) = out.last_mut()
            {
                last.sep_after = std::mem::take(&mut sep);
            }
            sep.clear();
            cur.push(c);
        } else {
            if !cur.is_empty() {
                out.push(Tok { word: std::mem::take(&mut cur), sep_after: String::new() });
            }
            sep.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(Tok { word: cur, sep_after: String::new() });
    }
    out
}

type Pred<'a> = &'a dyn Fn(&str) -> bool;

/// Consecutive tokens matching `preds`, separated by exactly one character
/// drawn from the matching entry of `seps`.
fn seq(toks: &[Tok], preds: &[Pred<'_>], seps: &[&str]) -> bool {
    (0..toks.len()).any(|i| {
        i + preds.len() <= toks.len()
            && preds.iter().enumerate().all(|(k, p)| {
                p(&toks[i + k].word)
                    && (k + 1 == preds.len() || {
                        let s = &toks[i + k].sep_after;
                        s.chars().count() == 1 && seps[k].contains(s.as_str())
                    })
            })
    })
}

fn one_of<'a>(words: &'a [&'a str]) -> impl Fn(&str) -> bool + 'a {
    move |w| words.contains(&w)
}

fn prefix(p: &'static str, min_extra: usize) -> impl Fn(&str) -> bool {
    move |w| w.starts_with(p) && w.len() >= p.len() + min_extra
}

fn any_tok(toks: &[Tok], p: impl Fn(&str) -> bool) -> bool {
    toks.iter().any(|t| p(&t.word))
}

/// Build, lint or test status: the toolchain agreeing with itself.
fn is_build_status(text: &str) -> bool {
    let t = tokens(text);
    let tests = one_of(&["test", "tests"]);
    any_tok(
        &t,
        one_of(&["build", "builds", "ci", "gate", "gates", "pytest", "ruff", "lint", "linter", "linting"]),
    ) || any_tok(&t, one_of(&["compile", "compiles"]))
        || any_tok(&t, prefix("typecheck", 0))
        || seq(&t, &[&one_of(&["type"]), &prefix("check", 0)], &["- "])
        || seq(&t, &[&one_of(&["no"]), &one_of(&["error", "errors", "warning", "warnings"])], &[" "])
        || seq(
            &t,
            &[&one_of(&["no"]), &one_of(&["new"]), &one_of(&["error", "errors", "warning", "warnings"])],
            &[" ", " "],
        )
        || seq(&t, &[&one_of(&["audit"]), &one_of(&["pass", "passes"])], &[" "])
        || seq(&t, &[&one_of(&["all"]), &tests, &one_of(&["pass", "passes", "passing"])], &[" ", " "])
        || seq(&t, &[&tests, &one_of(&["green"])], &[" "])
        || seq(&t, &[&tests, &one_of(&["are"]), &one_of(&["green"])], &[" ", " "])
}

/// Something the artifact does, exercised and asserted.
fn is_behavioural(text: &str) -> bool {
    let t = tokens(text);
    any_tok(&t, prefix("assert", 0))
        || any_tok(&t, prefix("verif", 1))
        || any_tok(&t, prefix("reproduc", 1))
        || any_tok(&t, prefix("exercis", 1))
        || any_tok(&t, prefix("load", 0))
        || any_tok(&t, prefix("run", 0))
        || any_tok(&t, prefix("return", 0))
        || any_tok(&t, prefix("refus", 1))
        || any_tok(&t, prefix("reject", 0))
        || any_tok(&t, prefix("observ", 1))
        || any_tok(&t, one_of(&["never", "unchanged", "roundtrip"]))
        || seq(&t, &[&one_of(&["must"]), &one_of(&["not"])], &[" "])
        || seq(&t, &[&one_of(&["fail", "fails"]), &one_of(&["closed", "with"])], &[" "])
        || seq(&t, &[&one_of(&["round"]), &one_of(&["trip"])], &["- "])
        || seq(&t, &[&one_of(&["end"]), &one_of(&["to"]), &one_of(&["end"])], &["- ", "- "])
        || seq(&t, &[&one_of(&["byte"]), &one_of(&["identical"])], &["- "])
}

/// Lint a spec against the standard. Read-only and advisory by itself.
pub fn check(task_spec: &str) -> SpecCheck {
    let spec = task_spec.trim();
    if spec.is_empty() {
        return SpecCheck {
            ok: false,
            errors: vec!["task_spec is empty".into()],
            warnings: vec![],
            sections_present: vec![],
            sections_missing: REQUIRED_SECTIONS.iter().map(|s| s.to_string()).collect(),
            dod_criteria: 0,
            behavioural_criteria: 0,
        };
    }
    let chars: Vec<char> = spec.to_lowercase().chars().collect();
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let present: Vec<String> =
        REQUIRED_SECTIONS.iter().filter(|s| has_section(&chars, s)).map(|s| s.to_string()).collect();
    let missing: Vec<String> = REQUIRED_SECTIONS
        .iter()
        .filter(|s| !present.iter().any(|p| p == *s))
        .map(|s| s.to_string())
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "missing required section(s): {} - see delegation_spec_template()",
            missing.join(", ")
        ));
    }
    let crit = criteria(&dod_body(&chars));
    let build_only: Vec<&String> = crit.iter().filter(|c| is_build_status(c)).collect();
    let behavioural: Vec<&String> =
        crit.iter().filter(|c| !build_only.contains(c) && is_behavioural(c)).collect();
    if present.iter().any(|p| p == "definition of done") {
        if crit.is_empty() {
            errors.push("Definition of Done section is empty".into());
        } else if behavioural.is_empty() {
            errors.push(
                "Definition of Done names no observable behaviour - every criterion is build/lint/test status. A \
                 green build proves the code compiles and that the assertions someone wrote agree with the code \
                 someone wrote; it does not prove the artifact does its job. State what is exercised and what is \
                 asserted about the result."
                    .into(),
            );
        } else if crit.len() < MIN_DOD_CRITERIA {
            warnings.push(format!(
                "Definition of Done has only {} criterion - consider also stating the failure mode that must be \
                 exercised, not just the happy path",
                crit.len()
            ));
        }
        if !build_only.is_empty() && build_only.len() == crit.len() {
            errors.push("Definition of Done is build status only".into());
        }
    }
    SpecCheck {
        ok: errors.is_empty(),
        errors,
        warnings,
        sections_present: present,
        sections_missing: missing,
        dod_criteria: crit.len(),
        behavioural_criteria: behavioural.len(),
    }
}

/// Strip one leading list marker (`-`, `*`, `1.`, `12)`) followed by spaces.
fn strip_list_marker(s: &str) -> String {
    let s = s.trim();
    let chars: Vec<char> = s.chars().collect();
    let after = match chars.first() {
        Some('-' | '*') => Some(1),
        Some(c) if c.is_ascii_digit() => {
            let d = skip(&chars, 0, |c| c.is_ascii_digit());
            matches!(chars.get(d), Some('.' | ')')).then_some(d + 1)
        }
        _ => None,
    };
    if let Some(j) = after {
        let k = skip(&chars, j, char::is_whitespace);
        if k > j {
            return chars[k..].iter().collect::<String>().trim().to_string();
        }
    }
    s.to_string()
}

/// A list argument given either as lines of text or as an array of strings.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum TextOrList {
    Text(String),
    List(Vec<String>),
}

fn normalize_list(v: Option<&TextOrList>) -> Vec<String> {
    match v {
        None => vec![],
        Some(TextOrList::Text(s)) => s.lines().map(strip_list_marker).filter(|l| !l.is_empty()).collect(),
        Some(TextOrList::List(items)) => {
            items.iter().filter(|i| !i.trim().is_empty()).map(|i| strip_list_marker(i)).collect()
        }
    }
}

pub struct BuildInput<'a> {
    pub objective: &'a str,
    pub scope_files: Option<&'a TextOrList>,
    pub dod_criteria: Option<&'a TextOrList>,
    pub tdd_stub: Option<&'a TextOrList>,
    pub tdd_must_be_real: Option<&'a TextOrList>,
    pub boundaries: Option<&'a TextOrList>,
    pub include_gates: bool,
    pub auto_validate: bool,
}

/// Assemble a spec from structured fields and validate it.
pub fn build(input: BuildInput<'_>) -> UaResult<Value> {
    let objective = input.objective.trim();
    if objective.is_empty() {
        return Err(UaError::invalid("objective is required"));
    }
    let files = normalize_list(input.scope_files);
    let dods = normalize_list(input.dod_criteria);
    let stubs = normalize_list(input.tdd_stub);
    let reals = normalize_list(input.tdd_must_be_real);
    let bounds = normalize_list(input.boundaries);

    let mut lines: Vec<String> =
        vec!["### Objective".into(), objective.into(), String::new(), "### Scope".into()];
    lines.push("Files this delegation may touch:".into());
    if files.is_empty() {
        lines.push("- (Unrestricted or specified in task prompt)".into());
    } else {
        lines.extend(files.iter().map(|f| format!("- {f}")));
    }
    lines.push(String::new());
    lines.push("### Definition of Done".into());
    lines.extend(dods.iter().map(|d| format!("- {d}")));
    if input.include_gates {
        lines.push(GATES_LINE.into());
    }
    lines.push(String::new());
    lines.push("### TDD Constraints".into());
    lines.push(
        "The test suite is GROUND TRUTH. Tests may not be muted, skipped, deleted, or weakened to make a change \
         pass."
            .into(),
    );
    lines.push(if stubs.is_empty() {
        "- Stub: none".into()
    } else {
        format!("- Stub: {}", stubs.join(", "))
    });
    lines.push(if reals.is_empty() {
        "- Must be real: whole test harness and persistent storage".into()
    } else {
        format!("- Must be real: {}", reals.join(", "))
    });
    lines.push(String::new());
    lines.push("### Boundaries".into());
    if bounds.is_empty() {
        lines.push("- Do not relax existing test assertions, security gates, or allowlists.".into());
    } else {
        lines.extend(bounds.iter().map(|b| format!("- {b}")));
    }
    let spec = format!("{}\n", lines.join("\n").trim());
    let result = check(&spec);
    if input.auto_validate && !result.ok {
        return Err(UaError::invalid(format!(
            "Generated delegation spec failed validation:\n  - {}",
            result.errors.join("\n  - ")
        )));
    }
    Ok(json!({ "spec": spec, "ok": result.ok, "check_result": result }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_has_every_section() {
        let r = check(TEMPLATE);
        assert!(r.sections_missing.is_empty(), "{r:?}");
        assert_eq!(r.dod_criteria, 3, "{r:?}");
    }

    #[test]
    fn word_rules() {
        assert!(is_build_status("uv run pytest green"));
        assert!(is_build_status("No new warnings"));
        assert!(is_build_status("type-check clean"));
        assert!(!is_build_status("the linters agree"));
        assert!(is_behavioural("the call returns 404"));
        assert!(is_behavioural("end-to-end round trip"));
        assert!(!is_behavioural("verif"));
        assert!(!is_behavioural("ends to end"));
    }

    #[test]
    fn empty_dod_does_not_run_into_next_section() {
        let spec =
            "### Objective\nx\n### Scope\ny\n### Definition of Done\n\n### TDD\nz\n### Boundaries\n- b\n";
        let r = check(spec);
        assert!(r.errors.iter().any(|e| e.contains("is empty")), "{r:?}");
    }

    #[test]
    fn list_markers() {
        assert_eq!(strip_list_marker("- a"), "a");
        assert_eq!(strip_list_marker("12) b"), "b");
        assert_eq!(strip_list_marker(".github/workflows/ci.yml"), ".github/workflows/ci.yml");
        assert_eq!(strip_list_marker("401 Unauthorized"), "401 Unauthorized");
    }
}
