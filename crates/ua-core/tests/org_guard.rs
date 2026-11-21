//! Until memberships exist, every caller and every ledger event is in the
//! default organization (`docs/organization.md`). The type system makes every
//! `Caller` literal and every `EventInput` name an organization; this test
//! keeps the value honest in the non-test code of **every workspace crate**
//! (it walks `crates/*/src`, so it sees all of them from here, and it reads
//! only source, so it runs the same under `--no-default-features`):
//!
//! - `EventInput::new`'s first argument, and `org_id` in an `EventInput { .. }`
//!   literal, must be `DEFAULT_ORG`. An event carries the organization of
//!   the row it is about, never the caller's, so `caller.org_id` or any other
//!   expression fails;
//! - `org_id` in a `Caller { .. }` literal must be `DEFAULT_ORG`; the
//!   shorthand `Caller { org_id, .. }` fails too;
//! - nothing assigns `.org_id = ...` except from `DEFAULT_ORG`;
//! - `Caller::system_for` is called nowhere yet.
//!
//! Test code is excluded by removing each `#[cfg(test)]` item (a `mod`
//! block found by brace matching, or the single item that follows), wherever
//! it sits in the file. Comments, strings, raw strings and character literals
//! are blanked before matching, so braces and code-like text inside them do
//! not count.
//!
//! When memberships land, the resolver becomes the one other source of an
//! organization, and this test changes with it.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Blank out comments, string and char literal contents (keeping offsets and
/// newlines), so brace matching and pattern search see code only.
fn mask(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = src[i..].find('\n').map_or(b.len(), |n| i + n);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = src[i + 2..].find("*/").map_or(b.len(), |n| i + 2 + n + 2);
                blank(&mut out, i, end);
                i = end;
            }
            b'r' if (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) =>
            {
                let hashes = b[i + 1..].iter().take_while(|c| **c == b'#').count();
                if b.get(i + 1 + hashes) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                let start = i + 2 + hashes;
                let end = src[start..].find(&close).map_or(b.len(), |n| start + n + close.len());
                blank(&mut out, start, end - close.len());
                i = end;
            }
            b'"' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                blank(&mut out, i + 1, j.min(b.len()));
                i = j + 1;
            }
            // A char literal ('x', '\n', '\''), not a lifetime ('a).
            b'\'' => {
                let end = if b.get(i + 1) == Some(&b'\\') {
                    // Skip the escaped character itself (`'\''`).
                    src.get(i + 3..).and_then(|r| r.find('\'')).map(|n| i + 3 + n)
                } else if b.get(i + 2) == Some(&b'\'') {
                    Some(i + 2)
                } else {
                    src[i + 1..].chars().next().and_then(|c| {
                        let after = i + 1 + c.len_utf8();
                        (b.get(after) == Some(&b'\'')).then_some(after)
                    })
                };
                match end {
                    Some(e) => {
                        blank(&mut out, i + 1, e);
                        i = e + 1;
                    }
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).expect("masking keeps UTF-8 boundaries for ASCII delimiters")
}

/// Index just past the brace that opens at `open` in masked text.
fn close_brace(m: &str, open: usize) -> usize {
    let mut depth = 0usize;
    for (i, c) in m[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open + i + 1;
                }
            }
            _ => {}
        }
    }
    m.len()
}

/// Masked source with every `#[cfg(test)]` item blanked.
fn without_tests(src: &str) -> String {
    let mut m = mask(src);
    while let Some(at) = m.find("#[cfg(test)]") {
        let after = at + "#[cfg(test)]".len();
        // The item ends at its matching brace, or at `;` when it has none.
        let brace = m[after..].find('{').map(|n| after + n);
        let semi = m[after..].find(';').map(|n| after + n);
        let end = match (brace, semi) {
            (Some(b), Some(s)) if s < b => s + 1,
            (Some(b), _) => close_brace(&m, b),
            (None, Some(s)) => s + 1,
            (None, None) => m.len(),
        };
        let blank: String = m[at..end].chars().map(|c| if c == '\n' { '\n' } else { ' ' }).collect();
        m.replace_range(at..end, &blank);
    }
    m
}

/// Non-test source of every workspace crate.
fn sources() -> Vec<(PathBuf, String)> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(crates).unwrap() {
        let src = entry.unwrap().path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    files.sort();
    files.into_iter().map(|p| (p.clone(), std::fs::read_to_string(&p).unwrap())).collect()
}

/// The expression starting at `from` up to the next top-level `,` or the end.
fn expr_at(m: &str, from: usize, end: usize) -> &str {
    let mut depth = 0i32;
    for (i, c) in m[from..end].char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return m[from..from + i].trim(),
            _ => {}
        }
    }
    m[from..end].trim()
}

/// `DEFAULT_ORG`, optionally path-qualified and converted to a `String`.
fn is_default_org(expr: &str) -> bool {
    let joined: String = expr.split_whitespace().collect();
    let mut e = joined.as_str();
    for suffix in [".into()", ".to_string()", ".to_owned()"] {
        if let Some(rest) = e.strip_suffix(suffix) {
            e = rest;
            break;
        }
    }
    let Some(path) = e.strip_suffix("DEFAULT_ORG") else { return false };
    path.is_empty()
        || path.strip_suffix("::").is_some_and(|p| {
            p.split("::").all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_alphanumeric() || c == '_'))
        })
}

fn line_of(m: &str, at: usize) -> usize {
    m[..at].matches('\n').count() + 1
}

/// Start offsets of `pat` in `m` that begin a path segment.
fn find_all<'a>(m: &'a str, pat: &'a str) -> impl Iterator<Item = usize> + 'a {
    m.match_indices(pat).map(|(i, _)| i).filter(move |&i| {
        i == 0 || !m[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// The value of field `org_id` in a struct literal body, `Some("org_id")`
/// for the shorthand, `None` when absent.
fn org_field(body: &str) -> Option<&str> {
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in body.char_indices().chain([(body.len(), ',')]) {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                let field = body[start..i].trim();
                if let Some(v) = field.strip_prefix("org_id") {
                    let v = v.trim_start();
                    if v.is_empty() {
                        return Some("org_id");
                    }
                    if let Some(v) = v.strip_prefix(':') {
                        return Some(v.trim());
                    }
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    None
}

fn findings(files: &[(PathBuf, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, src) in files {
        let name = path.display();
        let m = without_tests(src);
        for ty in ["Caller", "EventInput"] {
            for at in find_all(&m, &format!("{ty} {{")) {
                let before = m[..at].trim_end_matches(|c: char| c.is_alphanumeric() || c == '_' || c == ':');
                let before = before.trim_end();
                if ["struct", "impl", "enum", "->", "for"].iter().any(|k| before.ends_with(k)) {
                    continue;
                }
                let open = at + ty.len() + 1;
                let body = &m[open + 1..close_brace(&m, open) - 1];
                if let Some(v) = org_field(body)
                    && !is_default_org(v)
                {
                    out.push(format!(
                        "{name}:{}: {ty} literal sets org_id to `{v}`, not DEFAULT_ORG",
                        line_of(&m, at)
                    ));
                }
            }
        }
        for at in find_all(&m, "EventInput::new(") {
            let from = at + "EventInput::new(".len();
            let arg = expr_at(&m, from, m.len());
            if !is_default_org(arg) {
                out.push(format!(
                    "{name}:{}: EventInput::new names organization `{arg}`, not DEFAULT_ORG (an event carries the \
                     organization of the affected row)",
                    line_of(&m, at)
                ));
            }
        }
        for (at, _) in m.match_indices(".org_id =") {
            if m[at..].starts_with(".org_id ==") {
                continue;
            }
            let from = at + ".org_id =".len();
            let end = m[from..].find(';').map_or(m.len(), |n| from + n);
            let v = m[from..end].trim();
            if !is_default_org(v) {
                out.push(format!("{name}:{}: assigns org_id from `{v}`, not DEFAULT_ORG", line_of(&m, at)));
            }
        }
        for at in find_all(&m, "system_for(") {
            let line_start = m[..at].rfind('\n').map_or(0, |n| n + 1);
            let line = m[line_start..].lines().next().unwrap_or("");
            if line.contains("fn system_for(") || line.contains("Self::system_for(DEFAULT_ORG)") {
                continue;
            }
            out.push(format!(
                "{name}:{}: calls Caller::system_for before memberships exist",
                line_of(&m, at)
            ));
        }
    }
    out
}

fn one(src: &str) -> Vec<String> {
    findings(&[(PathBuf::from("demo.rs"), src.to_string())])
}

#[test]
fn non_test_callers_and_events_are_in_the_default_organization() {
    let files = sources();
    assert!(files.len() > 100, "found only {} source files", files.len());
    let events: usize =
        files.iter().map(|(_, s)| find_all(&without_tests(s), "EventInput::new(").count()).sum();
    assert!(events > 100, "found only {events} EventInput::new calls outside tests");
    let found = findings(&files);
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn the_guard_catches_a_caller_in_another_organization() {
    assert_eq!(one("fn f() { let c = Caller { label: x, org_id: \"org-b\".into(), kind: k }; }").len(), 1);
    // The shorthand form.
    let found = one("fn f(org_id: String) { let c = Caller { label: x, org_id, kind: k }; }");
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("org_id to `org_id`"), "{found:?}");
    assert_eq!(one("fn f() { c.org_id = other; }").len(), 1);
    assert_eq!(one("fn f() { Caller::system_for(\"org-b\"); }").len(), 1);
    assert!(
        one("fn f() -> Caller { Caller { label: x, org_id: ua_core::DEFAULT_ORG.into(), kind: k } }")
            .is_empty()
    );
}

#[test]
fn the_guard_catches_an_event_in_the_callers_organization() {
    for arg in ["caller.org_id", "ctx.caller.org_id.clone()", "&self.org_id", "\"org-b\"", "org"] {
        let found =
            one(&format!("fn f() {{ ledger::append(tx, EventInput::new({arg}, \"x.y\", json!({{}}))); }}"));
        assert_eq!(found.len(), 1, "{arg}: {found:?}");
        assert!(found[0].contains("affected row"), "{found:?}");
    }
    let found =
        one("fn f() { let e = EventInput { org_id: ctx.caller.org_id.clone(), channel: c, payload: p }; }");
    assert_eq!(found.len(), 1, "{found:?}");
    let found = one("fn f() { let e = EventInput { org_id, ..EventInput::new(DEFAULT_ORG, c, p) }; }");
    assert_eq!(found.len(), 1, "shorthand: {found:?}");
    for ok in ["ua_core::DEFAULT_ORG", "DEFAULT_ORG", "crate::DEFAULT_ORG", "ua_core::org::DEFAULT_ORG"] {
        assert!(one(&format!("fn f() {{ EventInput::new({ok}, \"x\", p); }}")).is_empty(), "{ok}");
    }
    assert!(
        one("fn f() { EventInput {\n org_id: ua_core::DEFAULT_ORG.into(),\n channel: c,\n }; }").is_empty()
    );
}

#[test]
fn only_test_items_are_excluded_wherever_they_sit() {
    // A test module in the middle of a file: code after it is still checked.
    let src = "#[cfg(test)]\nmod tests { fn t() { EventInput::new(\"org-b\", c, p); } }\n\
               fn later() { EventInput::new(caller.org_id, c, p); }\n";
    let found = one(src);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].starts_with("demo.rs:3:"), "{found:?}");
    // A single `#[cfg(test)]` function is excluded, and nothing beyond it.
    let src =
        "#[cfg(test)]\nfn helper() { EventInput::new(\"org-b\", c, p); }\nfn real() { c.org_id = x; }\n";
    assert_eq!(one(src).len(), 1);
}

#[test]
fn strings_comments_and_raw_strings_do_not_confuse_the_scan() {
    let src = r####"
// EventInput::new(caller.org_id, c, p) in a comment
/* Caller { org_id, } in a block comment */
fn f() {
    let s = "EventInput::new(caller.org_id, c, p) {";
    let r = r#"{ "a": "}" } EventInput::new(x"#;
    let ch = '{';
    EventInput::new(ua_core::DEFAULT_ORG, "x", p);
}
fn g<'a>(x: &'a str) { EventInput::new(x, "y", p); }
"####;
    let found = one(src);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].starts_with("demo.rs:10:"), "{found:?}");
}
