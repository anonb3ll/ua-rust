//! The authz ratchet (`docs/organization.md`, Authority checks): authority
//! is decided in `ua_org::authz`, and the ad-hoc checks that predate it may
//! only go away.
//!
//! The test scans the non-test source of every workspace crate except
//! `ua-org` (which owns authz). In `ua-core` it skips only the files that
//! define the primitives (`Caller::is_human`, `Config::is_human`,
//! `Config::is_lifecycle_operator`, the identity lists, `Profile`), for the
//! categories those definitions are; everything else there is counted like
//! any crate. Per crate it counts:
//!
//! - `is_human_def`: definitions of `fn is_human`;
//! - `is_human_call`: calls of `is_human(` (method or free function);
//! - `lifecycle_call`: calls of `is_lifecycle_operator(`;
//! - `operator_fn_def`: definitions of `fn is_operator…`, the ad-hoc operator
//!   predicates (today each is a one-line delegation to authz);
//! - `profile_check`: comparisons of a profile with `Profile::…` (`==`,
//!   `!=`, `matches!`), the shape of a profile used as an authority decision;
//! - `profile_authority_use`: uses of the authorities that once made a
//!   profile an authority (`TransitionalProfileOperator`,
//!   `TransitionalHubView`, `TransitionalMailboxReader`,
//!   `TransitionalLocalMailboxReader`). They are deleted; the count is 0 in
//!   every crate and must stay 0;
//! - `actor_kind_check`: `ActorKind::Human`, `::Agent` or `::Anonymous`
//!   compared (`==`/`!=`), used as a `match` arm, or inside `matches!(..)`
//!   (over any number of lines). Building a value with a kind is not counted;
//! - `config_identity_read`: direct reads of `human_identities` or
//!   `lifecycle_operators`.
//!
//! `profile_check` counts a `Profile::…` that is compared, any `Profile::…`
//! inside a `matches!(..)` whose first argument names a profile, and each
//! `match` whose scrutinee names a profile (once per `match`). It does not
//! try to tell an authority decision from a surface restriction; every such
//! use is counted.
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
    // Slack identity validation inside `Config`, beside the primitive.
    ("ua-core", "is_human_call", 2),
    ("ua-memory", "actor_kind_check", 1),
    ("ua-memory", "config_identity_read", 1),
    ("ua-server", "actor_kind_check", 5),
    ("ua-server", "config_identity_read", 2),
    ("ua-server", "is_human_call", 13),
    ("ua-server", "is_human_def", 1),
    ("ua-tools", "actor_kind_check", 43),
    ("ua-tools", "config_identity_read", 4),
    ("ua-tools", "is_human_call", 24),
    ("ua-tools", "operator_fn_def", 2),
    ("ua-tools", "profile_check", 13),
];

const CATEGORIES: &[&str] = &[
    "is_human_def",
    "is_human_call",
    "lifecycle_call",
    "operator_fn_def",
    "profile_check",
    "profile_authority_use",
    "actor_kind_check",
    "config_identity_read",
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

/// The `(start, end)` spans of every `matches!( .. )` invocation, with the
/// text of its first argument.
fn matches_spans(m: &str) -> Vec<(usize, usize, &str)> {
    let mut out = Vec::new();
    for (at, _) in m.match_indices("matches!(") {
        let open = at + "matches!".len();
        let mut depth = 0i32;
        let mut first_end = None;
        let mut end = m.len();
        for (i, c) in m[open..].char_indices() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                ',' if depth == 1 && first_end.is_none() => first_end = Some(open + i),
                _ => {}
            }
        }
        out.push((at, end, &m[open + 1..first_end.unwrap_or(end)]));
    }
    out
}

/// Whether the token at `at..end` is compared (`==`/`!=` on either side) or
/// is a `match` arm pattern (followed by `=>` or `|`).
fn compared_or_arm(m: &str, at: usize, end: usize) -> bool {
    let before = m[..at].trim_end_matches(|c: char| c.is_alphanumeric() || c == '_' || c == ':').trim_end();
    let after = m[end..].trim_start();
    before.ends_with("==")
        || before.ends_with("!=")
        || after.starts_with("==")
        || after.starts_with("!=")
        || after.starts_with("=>")
        || (after.starts_with('|') && !after.starts_with("||"))
}

/// The end of the path token starting at `at` (`ActorKind::Human`).
fn token_end(m: &str, at: usize) -> usize {
    at + m[at..].find(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':')).unwrap_or(m.len() - at)
}

/// Every occurrence of each category in one (masked, test-free) source.
fn count(m: &str) -> BTreeMap<&'static str, Vec<usize>> {
    let mut out: BTreeMap<&'static str, Vec<usize>> = BTreeMap::new();
    let preceded_by_fn = |at: usize| m[..at].trim_end().ends_with("fn");
    let spans = matches_spans(m);
    let in_matches = |at: usize, first_arg_has: &str| {
        spans.iter().any(|(s, e, first)| {
            *s < at && at < *e && (first_arg_has.is_empty() || first.contains(first_arg_has))
        })
    };
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
    // A profile compared, matched in `matches!(.. profile ..)` (on any number
    // of lines), or the scrutinee of a `match` on a profile (counted once per
    // `match`, not per arm).
    for (at, _) in m.match_indices("Profile::") {
        if (compared_or_arm(m, at, token_end(m, at)) && !inside_profile_match(m, at))
            || in_matches(at, "profile")
        {
            out.entry("profile_check").or_default().push(at);
        }
    }
    for at in find_all(m, "match ") {
        let head_end = m[at..].find('{').map_or(m.len(), |n| at + n);
        let head = &m[at + "match ".len()..head_end];
        if head.contains("profile") && !head.contains(';') {
            out.entry("profile_check").or_default().push(at);
        }
    }
    // An actor kind compared, matched as an arm, or inside `matches!`.
    for kind in ["ActorKind::Human", "ActorKind::Agent", "ActorKind::Anonymous"] {
        for at in find_all(m, kind) {
            let end = at + kind.len();
            if m[end..].starts_with(|c: char| c.is_alphanumeric() || c == '_') {
                continue;
            }
            if compared_or_arm(m, at, end) || in_matches(at, "") {
                out.entry("actor_kind_check").or_default().push(at);
            }
        }
    }
    // The configured identity lists, read directly.
    for field in ["human_identities", "lifecycle_operators"] {
        for at in find_all(m, field) {
            if !m[at + field.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_') {
                out.entry("config_identity_read").or_default().push(at);
            }
        }
    }
    for pat in PROFILE_AUTHORITIES {
        for (at, _) in m.match_indices(pat) {
            out.entry("profile_authority_use").or_default().push(at);
        }
    }
    out
}

/// Whether `at` is an arm pattern of a `match` whose scrutinee names a
/// profile (that `match` is counted once by its header instead).
fn inside_profile_match(m: &str, at: usize) -> bool {
    for start in find_all(m, "match ") {
        if start > at {
            break;
        }
        let Some(open) = m[start..].find('{').map(|n| start + n) else { continue };
        let head = &m[start + "match ".len()..open];
        if head.contains("profile") && !head.contains(';') && at > open && at < support::close_brace(m, open)
        {
            return true;
        }
    }
    false
}

/// Files whose definitions are the primitives themselves: a category found
/// there is not an ad-hoc check. Only `ua-core` files are listed.
const PRIMITIVES: &[(&str, &[&str])] = &[
    // `Caller::is_human` and the `Caller` constructors.
    ("ua-core/src/identity.rs", &["is_human_def", "actor_kind_check"]),
    // `Config::is_human`, `is_lifecycle_operator` and the identity lists.
    ("ua-core/src/config.rs", &["is_human_def", "lifecycle_call", "config_identity_read"]),
    // `Profile` itself.
    ("ua-core/src/profiles.rs", &["profile_check"]),
];

fn allowlisted(path: &std::path::Path, cat: &str) -> bool {
    let p = path.to_string_lossy().replace('\\', "/");
    PRIMITIVES.iter().any(|(file, cats)| p.ends_with(file) && cats.contains(&cat))
}

/// Per-crate counts over `files`, skipping `ua-org` (which owns authz) and
/// the primitives' own definitions in `ua-core`.
fn tally(files: &[(PathBuf, String)]) -> BTreeMap<(String, &'static str), usize> {
    let mut out = BTreeMap::new();
    for (path, src) in files {
        let krate = crate_of(path);
        if krate == "ua-org" {
            continue;
        }
        for (cat, hits) in count(&without_tests(src)) {
            if allowlisted(path, cat) {
                continue;
            }
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
        (
            "fn f() { matches!(\n    caller.profile,\n    Profile::Coordinator\n        | Profile::Lead\n); }",
            "profile_check",
        ),
        ("fn f() { match caller.profile { Profile::Operator => true, _ => false }; }", "profile_check"),
        ("fn f() { if caller.kind == ActorKind::Human {} }", "actor_kind_check"),
        ("fn f() { if ActorKind::Anonymous != c.kind {} }", "actor_kind_check"),
        (
            "fn f() { matches!(\n    caller.kind,\n    ActorKind::Agent | ActorKind::Human\n); }",
            "actor_kind_check",
        ),
        ("fn f() { match c.kind { ActorKind::Human => 1, _ => 0 }; }", "actor_kind_check"),
        ("fn f() { cfg.human_identities.iter().any(|h| h == l); }", "config_identity_read"),
        ("fn f() { cfg.lifecycle_operators().contains(&l); }", "config_identity_read"),
    ];
    for (src, cat) in cases {
        let got = one(src);
        assert!(got.get(cat).copied().unwrap_or(0) >= 1, "{cat} not caught in {src}: {got:?}");
    }
    // A Profile value that is not compared is not a check.
    assert!(one("fn f() -> Profile { Profile::Developer }").is_empty());
    // Building a caller with a kind is not a check; `||` is not an arm.
    assert!(one("fn f() { Caller { kind: ActorKind::Human, ..c } }").is_empty());
    assert!(one("fn f() { let k = ActorKind::Agent; g(k) || h(); }").is_empty());
    // A match on a profile counts once, not once per arm.
    assert_eq!(
        one("fn f() { match p.profile { Profile::A => 1, Profile::B | Profile::C => 2, _ => 0 }; }")
            .get("profile_check"),
        Some(&1)
    );
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
