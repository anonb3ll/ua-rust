//! Until memberships exist, every caller is in the default organization
//! (`docs/organization.md`). The type system makes every `Caller` literal
//! and every `EventInput` name an organization; this test keeps the value
//! honest in the workspace's non-test code:
//!
//! - a `Caller { .. }` literal that sets `org_id` must set it from
//!   `DEFAULT_ORG`;
//! - nothing assigns `.org_id = ...` except from `DEFAULT_ORG`;
//! - `Caller::system_for` is called nowhere yet (it exists for the system
//!   jobs that will act for another organization).
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

/// Non-test source: every crate's `src/`, with `#[cfg(test)]` modules cut
/// off (they sit at the end of a file by convention here).
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
    files
        .into_iter()
        .map(|p| {
            let s = std::fs::read_to_string(&p).unwrap();
            let s = match s.find("#[cfg(test)]") {
                Some(i) => s[..i].to_string(),
                None => s,
            };
            (p, s)
        })
        .collect()
}

/// The body of the brace that opens at `open` (exclusive), skipping strings.
fn brace_body(s: &str, open: usize) -> &str {
    let b = s.as_bytes();
    let (mut depth, mut i) = (0usize, open);
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &s[open + 1..i];
                }
            }
            b'"' => {
                i += 1;
                while b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            _ => {}
        }
        i += 1;
    }
    &s[open + 1..]
}

/// The expression after `field:` up to the next top-level comma.
fn field_value<'s>(body: &'s str, field: &str) -> Option<&'s str> {
    let start = body.find(&format!("{field}:"))? + field.len() + 1;
    let rest = &body[start..];
    let mut depth = 0i32;
    for (i, c) in rest.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return Some(rest[..i].trim()),
            _ => {}
        }
    }
    Some(rest.trim())
}

fn findings(files: &[(PathBuf, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, s) in files {
        let name = path.display();
        let mut from = 0;
        while let Some(i) = s[from..].find("Caller {") {
            let at = from + i;
            from = at + 1;
            let before = s[..at].trim_end_matches(|c: char| c.is_alphanumeric() || c == '_' || c == ':');
            let before = before.trim_end();
            if ["struct", "impl", "enum", "->"].iter().any(|k| before.ends_with(k)) {
                continue;
            }
            let body = brace_body(s, at + "Caller ".len());
            if let Some(v) = field_value(body, "org_id")
                && !v.contains("DEFAULT_ORG")
            {
                out.push(format!("{name}: Caller literal sets org_id to `{v}`, not DEFAULT_ORG"));
            }
        }
        for (n, line) in s.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") {
                continue;
            }
            if let Some(i) = t.find(".org_id =")
                && !t[i..].starts_with(".org_id ==")
                && !t.contains("DEFAULT_ORG")
            {
                out.push(format!("{name}:{}: assigns org_id from something other than DEFAULT_ORG", n + 1));
            }
            if t.contains("system_for(")
                && !t.contains("fn system_for(")
                && !t.contains("Self::system_for(DEFAULT_ORG)")
            {
                out.push(format!("{name}:{}: calls Caller::system_for before memberships exist", n + 1));
            }
        }
    }
    out
}

#[test]
fn non_test_callers_are_in_the_default_organization() {
    let files = sources();
    assert!(files.len() > 100, "found only {} source files", files.len());
    let found = findings(&files);
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn the_guard_catches_another_organization() {
    let bad = vec![(
        PathBuf::from("demo.rs"),
        "fn f() { let c = Caller { label: x, org_id: \"org-b\".into(), kind: k }; c.org_id = other; \
         Caller::system_for(\"org-b\"); }"
            .to_string(),
    )];
    let found = findings(&bad);
    assert_eq!(found.len(), 3, "{found:?}");
    let good = vec![(
        PathBuf::from("demo.rs"),
        "fn f() -> Caller { Caller { label: x, org_id: ua_core::DEFAULT_ORG.into(), kind: k } }".to_string(),
    )];
    assert!(findings(&good).is_empty());
}
