//! The authz ratchet (`docs/organization.md`, Authority checks): authority
//! is decided in `ua_org::authz`, and the ad-hoc checks that predate it may
//! only go away.
//!
//! The test scans the non-test source of every workspace crate except
//! `ua-org` (which owns authz) and `ua-core` (which defines the primitives
//! `Caller::is_human`, `Config::is_human` and `Config::is_lifecycle_operator`)
//! and counts, per crate:
//!
//! - `is_human_def`: definitions of `fn is_human`;
//! - `is_human_call`: calls of `is_human(` (method or free function);
//! - `lifecycle_call`: calls of `is_lifecycle_operator(`;
//! - `operator_fn_def`: definitions of `fn is_operator…`, the ad-hoc operator
//!   predicates (today each is a one-line delegation to authz);
//! - `profile_check`: comparisons of a profile with `Profile::…` (`==`,
//!   `!=`, `matches!`), the shape of a profile used as an authority decision;
//! - `profile_authority_use`: uses of the transitional authorities that are a
//!   profile used as authority (`TransitionalProfileOperator`,
//!   `TransitionalHubView`, `TransitionalMailboxReader`,
//!   `TransitionalLocalMailboxReader`).
//!
//! Each count must equal [`BASELINE`]: above it, a new ad-hoc check was added
//! (route it through authz instead); below it, one was removed (lower the
//! baseline in the same change). The baseline only ever goes down.
//!
//! It reads source only, so it runs the same under `--no-default-features`.

mod support;

use std::collections::BTreeMap;
use std::path::PathBuf;

use support::{find_all, sources, without_tests};

/// The checked-in counts: `(crate, category, count)`. A missing entry is 0.
const BASELINE: &[(&str, &str, usize)] = &[
    ("ua-cli", "is_human_call", 2),
    ("ua-server", "is_human_call", 13),
    ("ua-server", "is_human_def", 1),
    ("ua-tools", "is_human_call", 35),
    ("ua-tools", "lifecycle_call", 4),
    ("ua-tools", "operator_fn_def", 4),
    ("ua-tools", "profile_authority_use", 4),
    ("ua-tools", "profile_check", 9),
];

const CATEGORIES: &[&str] = &[
    "is_human_def",
    "is_human_call",
    "lifecycle_call",
    "operator_fn_def",
    "profile_check",
    "profile_authority_use",
];

const PROFILE_AUTHORITIES: &[&str] = &[
    "Authority::TransitionalProfileOperator",
    "Authority::TransitionalHubView",
    "Authority::TransitionalMailboxReader",
    "Authority::TransitionalLocalMailboxReader",
];

fn crate_of(path: &std::path::Path) -> String {
    let parts: Vec<_> = path.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    let i = parts.iter().rposition(|p| p == "src").expect("a src path");
    parts[i - 1].clone()
}

/// Every occurrence of each category in one (masked, test-free) source.
fn count(m: &str) -> BTreeMap<&'static str, Vec<usize>> {
    let mut out: BTreeMap<&'static str, Vec<usize>> = BTreeMap::new();
    let preceded_by_fn = |at: usize| m[..at].trim_end().ends_with("fn");
    for at in find_all(m, "is_human(") {
        out.entry(if preceded_by_fn(at) { "is_human_def" } else { "is_human_call" }).or_default().push(at);
    }
    for (at, _) in m.match_indices("is_lifecycle_operator(") {
        if !preceded_by_fn(at) {
            out.entry("lifecycle_call").or_default().push(at);
        }
    }
    for (at, _) in m.match_indices("fn is_operator") {
        out.entry("operator_fn_def").or_default().push(at);
    }
    for (at, _) in m.match_indices("Profile::") {
        let before = m[..at].trim_end_matches(|c: char| c.is_alphanumeric() || c == '_' || c == ':');
        let before = before.trim_end();
        let in_matches = {
            let line_start = m[..at].rfind('\n').map_or(0, |n| n + 1);
            let line = &m[line_start..at];
            line.contains("matches!(") && line.contains("profile")
        };
        if before.ends_with("==") || before.ends_with("!=") || in_matches {
            out.entry("profile_check").or_default().push(at);
        }
    }
    for pat in PROFILE_AUTHORITIES {
        for (at, _) in m.match_indices(pat) {
            out.entry("profile_authority_use").or_default().push(at);
        }
    }
    out
}

/// Per-crate counts over `files`, skipping `ua-org` and `ua-core`.
fn tally(files: &[(PathBuf, String)]) -> BTreeMap<(String, &'static str), usize> {
    let mut out = BTreeMap::new();
    for (path, src) in files {
        let krate = crate_of(path);
        if krate == "ua-org" || krate == "ua-core" {
            continue;
        }
        for (cat, hits) in count(&without_tests(src)) {
            *out.entry((krate.clone(), cat)).or_insert(0) += hits.len();
        }
    }
    out
}

fn baseline() -> BTreeMap<(String, &'static str), usize> {
    BASELINE.iter().map(|(k, c, n)| ((k.to_string(), *c), *n)).collect()
}

/// Differences from the baseline, one line each.
fn drift(actual: &BTreeMap<(String, &'static str), usize>) -> Vec<String> {
    let base = baseline();
    let mut keys: Vec<_> = actual.keys().chain(base.keys()).cloned().collect();
    keys.sort();
    keys.dedup();
    let mut out = Vec::new();
    for key in keys {
        let (a, b) = (actual.get(&key).copied().unwrap_or(0), base.get(&key).copied().unwrap_or(0));
        let (krate, cat) = &key;
        if a > b {
            out.push(format!(
                "{krate} {cat}: {a}, above the baseline {b}; route the new check through ua_org::authz"
            ));
        } else if a < b {
            out.push(format!("{krate} {cat}: {a}, below the baseline {b}; lower BASELINE to {a}"));
        }
    }
    out
}

#[test]
fn ad_hoc_authority_checks_only_go_down() {
    let files = sources();
    assert!(files.len() > 100, "found only {} source files", files.len());
    for (_, cat, _) in BASELINE {
        assert!(CATEGORIES.contains(cat), "unknown category {cat}");
    }
    let actual = tally(&files);
    let found = drift(&actual);
    let table: Vec<String> =
        actual.iter().map(|((k, c), n)| format!("    (\"{k}\", \"{c}\", {n}),")).collect();
    assert!(found.is_empty(), "{}\n\ncurrent counts:\n{}", found.join("\n"), table.join("\n"));
}

fn one(src: &str) -> BTreeMap<&'static str, usize> {
    count(&without_tests(src)).into_iter().map(|(k, v)| (k, v.len())).collect()
}

#[test]
fn each_category_is_caught() {
    let cases: &[(&str, &str)] = &[
        ("fn is_human(c: &Caller) -> bool { c.kind == ActorKind::Human }", "is_human_def"),
        ("fn f() { if caller.is_human() {} }", "is_human_call"),
        ("fn f() { if is_human(&caller) {} }", "is_human_call"),
        ("fn f() { cfg.is_lifecycle_operator(who); }", "lifecycle_call"),
        ("fn is_operator_ish(c: &Caller) -> bool { true }", "operator_fn_def"),
        ("fn f() { if caller.profile == Profile::Coordinator {} }", "profile_check"),
        ("fn f() { if caller.profile != ua_core::Profile::Operator {} }", "profile_check"),
        ("fn f() { matches!(caller.profile, Profile::Coordinator | Profile::Operator); }", "profile_check"),
        ("fn f() { authz.holds(c, &[Authority::TransitionalHubView], o); }", "profile_authority_use"),
    ];
    for (src, cat) in cases {
        let got = one(src);
        assert!(got.get(cat).copied().unwrap_or(0) >= 1, "{cat} not caught in {src}: {got:?}");
    }
    // A Profile value that is not compared is not a check.
    assert!(one("fn f() -> Profile { Profile::Developer }").is_empty());
    // Comments, strings and test code are not counted.
    assert!(one("// caller.is_human()\nfn f() { let s = \"is_human(\"; }").is_empty());
    assert!(one("#[cfg(test)]\nmod tests { fn t() { assert!(c.is_human()); } }").is_empty());
}

#[test]
fn drift_is_reported_both_ways() {
    let mut actual = BTreeMap::new();
    actual.insert(("ua-demo".to_string(), "is_human_call"), 1);
    let found = drift(&actual);
    assert!(
        found.iter().any(|l| l.starts_with("ua-demo is_human_call: 1, above the baseline 0")),
        "{found:?}"
    );
    if let Some((k, c, n)) = BASELINE.first() {
        let found = drift(&BTreeMap::new());
        assert!(
            found.iter().any(|l| l == &format!("{k} {c}: 0, below the baseline {n}; lower BASELINE to 0"))
        );
    }
}
