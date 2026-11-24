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
//!   shorthand `Caller { org_id, .. }` fails too. The one exception is the
//!   HTTP resolver ([`RESOLVER_ALLOWED`]): `caller_for` builds a caller in
//!   the organization its credential resolved to (`AuthIdentity::org_id`,
//!   a managed token's or a session credential's, which must be its
//!   agent's), and nowhere else does;
//! - nothing assigns `.org_id = ...` except from `DEFAULT_ORG`;
//! - `Caller::system_for` is called nowhere except the GitHub family's
//!   [`SYSTEM_FOR_ALLOWED`] site: callerless per-organization work (a
//!   webhook delivery verified by an organization's own secret, a poll with
//!   its own token) acts as the hub identity in that organization, and
//!   nowhere else does;
//! - `github_caller_for(` (that site's wrapper, a caller for any
//!   organization) is called only inside `families/github/`.
//!
//! Test code is excluded by removing each `#[cfg(test)]` item (a `mod`
//! block found by brace matching, or the single item that follows), wherever
//! it sits in the file. Comments, strings, raw strings and character literals
//! are blanked before matching, so braces and code-like text inside them do
//! not count.
//!
//! The resolver is the one other source of an organization: since the
//! agents family converted, a managed token or a session credential carries
//! its agent's organization, and `caller_for` builds its caller there. When
//! memberships land, the resolver's other credentials join it.

mod support;

use std::path::PathBuf;

use support::{close_brace, find_all, line_of, sources, without_tests};

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

/// The only places `Caller::system_for` may be called outside tests, as
/// (path suffix, calls allowed there): the GitHub family's
/// `github_caller_for`, the hub identity acting for the organization a
/// delivery or a poll belongs to.
const SYSTEM_FOR_ALLOWED: &[(&str, usize)] = &[("ua-tools/src/families/github/mod.rs", 1)];

/// The only places a `Caller { .. }` literal may set `org_id` from anything
/// but `DEFAULT_ORG`, as (path suffix, literals allowed there): the HTTP
/// resolver's `caller_for`, whose two literals take the organization the
/// credential resolved to, `id.org_id`.
const RESOLVER_ALLOWED: &[(&str, usize)] = &[("ua-server/src/auth.rs", 2)];

/// The value the resolver's literals may set `org_id` to.
const RESOLVER_ORG: &str = "id.org_id.clone()";

/// The one directory whose code may call `github_caller_for`.
const GITHUB_CALLER_FOR_HOME: &str = "ua-tools/src/families/github/";

fn findings(files: &[(PathBuf, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, src) in files {
        let name = path.display();
        let m = without_tests(src);
        let unix_path = path.to_string_lossy().replace('\\', "/");
        let mut resolver_left =
            RESOLVER_ALLOWED.iter().find(|(suffix, _)| unix_path.ends_with(suffix)).map_or(0, |(_, n)| *n);
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
                    if ty == "Caller" && resolver_left > 0 && v == RESOLVER_ORG {
                        resolver_left -= 1;
                        continue;
                    }
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
        let unix = path.to_string_lossy().replace('\\', "/");
        let mut allowed =
            SYSTEM_FOR_ALLOWED.iter().find(|(suffix, _)| unix.ends_with(suffix)).map_or(0, |(_, n)| *n);
        for at in find_all(&m, "system_for(") {
            let line_start = m[..at].rfind('\n').map_or(0, |n| n + 1);
            let line = m[line_start..].lines().next().unwrap_or("");
            if line.contains("fn system_for(") || line.contains("Self::system_for(DEFAULT_ORG)") {
                continue;
            }
            if allowed > 0 {
                allowed -= 1;
                continue;
            }
            out.push(format!(
                "{name}:{}: calls Caller::system_for before memberships exist",
                line_of(&m, at)
            ));
        }
        if !unix.contains(GITHUB_CALLER_FOR_HOME) {
            for at in find_all(&m, "github_caller_for(") {
                // Its definition is not a call.
                if m[..at].trim_end().strip_suffix("fn").is_some_and(|b| b.ends_with(char::is_whitespace)) {
                    continue;
                }
                out.push(format!(
                    "{name}:{}: calls github_caller_for outside the GitHub family (a caller for any \
                     organization)",
                    line_of(&m, at)
                ));
            }
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
    // A sanity floor for the scanner, not a quota: families that route
    // their events through one `emit` helper lower the count.
    assert!(events > 80, "found only {events} EventInput::new calls outside tests");
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
    // The GitHub family's one site is allowed, a second call there is not.
    let github = |src: &str| {
        findings(&[(PathBuf::from("crates/ua-tools/src/families/github/mod.rs"), src.to_string())])
    };
    assert!(github("fn f(o: &str) { Caller::system_for(o); }").is_empty());
    assert_eq!(github("fn f(o: &str) { Caller::system_for(o); Caller::system_for(o); }").len(), 1);
    // `github_caller_for` is callable inside the GitHub family only.
    let at = |path: &str, src: &str| findings(&[(PathBuf::from(path), src.to_string())]);
    let call = "fn f(o: &str) { let c = github_caller_for(o); }";
    assert!(at("crates/ua-tools/src/families/github/webhook.rs", call).is_empty());
    let found = at("crates/ua-tools/src/families/tasks/mod.rs", call);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("outside the GitHub family"), "{found:?}");
    assert_eq!(
        at("crates/ua-tools/src/ci.rs", "fn f() { super::github::github_caller_for(\"org-b\"); }").len(),
        1
    );
    // Its definition is not a call.
    assert!(
        at("crates/ua-tools/src/families/other.rs", "pub(crate) fn github_caller_for(o: &str) {}").is_empty()
    );
    assert!(
        one("fn f() -> Caller { Caller { label: x, org_id: ua_core::DEFAULT_ORG.into(), kind: k } }")
            .is_empty()
    );
    // The HTTP resolver's two literals take the credential's organization;
    // a third there, another value there, or the same literal elsewhere fails.
    let lit = "let c = Caller { label: x, org_id: id.org_id.clone(), kind: k };";
    let resolver = |n: usize| at("crates/ua-server/src/auth.rs", &format!("fn f() {{ {} }}", lit.repeat(n)));
    assert!(resolver(2).is_empty());
    assert_eq!(resolver(3).len(), 1);
    assert_eq!(at("crates/ua-server/src/auth.rs", "fn f() { Caller { org_id: other, kind: k }; }").len(), 1);
    assert_eq!(at("crates/ua-server/src/api.rs", &format!("fn f() {{ {lit} }}")).len(), 1);
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
