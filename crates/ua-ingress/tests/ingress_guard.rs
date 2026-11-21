//! The ingress ratchet (`docs/ingress.md`): talking to the outside world
//! belongs in `ua-ingress`, and the duplicates that predate it may only go
//! away.
//!
//! The test scans the non-test source of every workspace crate except
//! `ua-ingress` and counts, per crate:
//!
//! - `client_builder`: `reqwest` client builder sites (`Client::builder(`,
//!   `ClientBuilder::new(`/`::default(`, and `Client::new(`/`::default(` in
//!   a file that names `reqwest`). Build an `ua_ingress::Outbound` with a
//!   policy instead;
//! - `address_classifier`: definitions of a function that takes an IP
//!   address (`IpAddr`, `Ipv4Addr`, `Ipv6Addr`, by value or reference),
//!   returns `bool`, `Option<..>` or `Result<..>`, and whose body tests an
//!   address range or takes the address apart ([`RANGE_PROBES`]): the shape
//!   of an address classifier. Use `ua_ingress::addr` instead;
//! - `delivery_table`: `CREATE TABLE` (with or without `IF NOT EXISTS`) of
//!   an inbound duplicate-delivery table: `github_deliveries`,
//!   `github_delivery_bodies`, `slack_seen_signatures`,
//!   `slack_seen_deliveries`. Searched in the text as written, since SQL
//!   lives in strings.
//!
//! Test code (`#[cfg(test)]` items) is not counted; comments and strings are
//! not counted for the first two categories.
//!
//! Each count must equal [`BASELINE`]: above it, a new duplicate was added
//! (use the crate instead); below it, one was removed (lower the baseline
//! in the same change). The baseline only ever goes down.
//!
//! It reads source only, so it runs the same under `--no-default-features`.

#[path = "../../ua-core/tests/support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use support::{close_brace, find_all, sources, without_tests, without_tests_raw};

/// The checked-in counts: `(crate, category, count)`. A missing entry is 0.
const BASELINE: &[(&str, &str, usize)] = &[
    // `oauth/cimd.rs` (the client ID metadata document fetch).
    ("ua-server", "client_builder", 1),
    // `web::vet_ip`, `mcp::scope::{classify, classify_v4}` and
    // `relay::gates::{v4_kind, v6_kind}` (which judge publication, not
    // reachability, but have the same shape).
    ("ua-tools", "address_classifier", 5),
    // `web::http_client`, `github::client`, `mcp::gateway`, `notify`,
    // `vault::obsidian`.
    ("ua-tools", "client_builder", 5),
    // `github_deliveries`, `github_delivery_bodies` (github/mod.rs) and
    // `slack_seen_signatures`, `slack_seen_deliveries` (slack.rs).
    ("ua-tools", "delivery_table", 4),
];

const CATEGORIES: &[&str] = &["client_builder", "address_classifier", "delivery_table"];

const DELIVERY_TABLES: &[&str] =
    &["github_deliveries", "github_delivery_bodies", "slack_seen_signatures", "slack_seen_deliveries"];

const IP_TYPES: &[&str] = &["IpAddr", "Ipv4Addr", "Ipv6Addr"];

/// What a classifier's body does to an address: test a range or take it
/// apart. A function that only uses an address as a key is not counted.
const RANGE_PROBES: &[&str] = &[
    ".is_loopback(",
    ".is_private(",
    ".is_link_local(",
    ".is_multicast(",
    ".is_unspecified(",
    ".is_documentation(",
    ".is_broadcast(",
    ".is_global(",
    ".octets(",
    ".segments(",
    ".to_ipv4_mapped(",
    ".to_ipv4(",
    "non_public_reason(",
    "embedded_v4(",
    "is_loopback(",
];

fn crate_of(path: &Path) -> String {
    let parts: Vec<_> = path.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    let i = parts.iter().rposition(|p| p == "src").expect("a src path");
    parts[i - 1].clone()
}

/// Whether the text right after `at + len` continues an identifier.
fn continues_ident(m: &str, end: usize) -> bool {
    m[end..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
}

/// Whether a parameter list names an IP address type as a parameter's type
/// (`ip: IpAddr`, `a: &std::net::Ipv6Addr`, `mut ip: Ipv4Addr`).
fn takes_ip(params: &str) -> bool {
    IP_TYPES.iter().any(|t| {
        find_all(params, t).any(|at| {
            if continues_ident(params, at + t.len()) {
                return false;
            }
            // Walk back over a path prefix, `&` and `mut` to the parameter's colon.
            let mut before = params[..at].trim_end();
            loop {
                if let Some(s) = before.strip_suffix("::") {
                    before = s.trim_end_matches(|c: char| c.is_alphanumeric() || c == '_').trim_end();
                } else if let Some(s) = before.strip_suffix('&') {
                    before = s.trim_end();
                } else if let Some(s) = before
                    .strip_suffix("mut")
                    .filter(|s| !s.ends_with(|c: char| c.is_alphanumeric() || c == '_'))
                {
                    before = s.trim_end();
                } else {
                    return before.ends_with(':') && !before.ends_with("::");
                }
            }
        })
    })
}

/// Whether `name` (the text between `fn ` and `(`) is a function name,
/// generics allowed.
fn is_fn_name(name: &str) -> bool {
    let ident = name.split('<').next().unwrap_or("");
    ident.starts_with(|c: char| c.is_alphabetic() || c == '_')
        && ident.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Every occurrence of each code category in one masked, test-free source.
fn count_code(m: &str) -> BTreeMap<&'static str, Vec<usize>> {
    let mut out: BTreeMap<&'static str, Vec<usize>> = BTreeMap::new();
    for pat in ["Client::builder(", "ClientBuilder::new(", "ClientBuilder::default("] {
        for at in find_all(m, pat) {
            out.entry("client_builder").or_default().push(at);
        }
    }
    if m.contains("reqwest") {
        for pat in ["Client::new(", "Client::default("] {
            for at in find_all(m, pat) {
                out.entry("client_builder").or_default().push(at);
            }
        }
    }
    for at in find_all(m, "fn ") {
        let Some(open) = m[at..].find('(').map(|n| at + n) else { continue };
        if !is_fn_name(m[at + 3..open].trim()) {
            continue;
        }
        // The parameter list ends at the matching parenthesis.
        let mut depth = 0i32;
        let mut close = None;
        for (i, c) in m[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else { continue };
        let tail_end = m[close..].find(['{', ';']).map_or(m.len(), |n| close + n);
        let ret = m[close + 1..tail_end].split(" where ").next().unwrap_or("").trim();
        let returns_verdict =
            ret.starts_with("-> bool") || ret.starts_with("-> Option<") || ret.starts_with("-> Result<");
        if !(returns_verdict && takes_ip(&m[open + 1..close])) || !m[tail_end..].starts_with('{') {
            continue;
        }
        let body = &m[tail_end..close_brace(m, tail_end)];
        if RANGE_PROBES.iter().any(|p| body.contains(p)) {
            out.entry("address_classifier").or_default().push(at);
        }
    }
    out
}

/// `CREATE TABLE` of a delivery table in raw, test-free source.
fn count_tables(raw: &str) -> Vec<usize> {
    let lower = raw.to_ascii_lowercase();
    let mut out = Vec::new();
    for (at, _) in lower.match_indices("create table") {
        let mut rest = lower[at + "create table".len()..].trim_start();
        if let Some(r) = rest.strip_prefix("if not exists") {
            rest = r.trim_start();
        }
        let rest = rest.trim_start_matches(['"', '`', '[']);
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if DELIVERY_TABLES.contains(&name.as_str()) {
            out.push(at);
        }
    }
    out
}

fn count(src: &str) -> BTreeMap<&'static str, usize> {
    let mut out: BTreeMap<&'static str, usize> =
        count_code(&without_tests(src)).into_iter().map(|(k, v)| (k, v.len())).collect();
    let tables = count_tables(&without_tests_raw(src)).len();
    if tables > 0 {
        out.insert("delivery_table", tables);
    }
    out
}

/// Per-crate counts over `files`, skipping `ua-ingress` itself.
fn tally(files: &[(PathBuf, String)]) -> BTreeMap<(String, &'static str), usize> {
    let mut out = BTreeMap::new();
    for (path, src) in files {
        let krate = crate_of(path);
        if krate == "ua-ingress" {
            continue;
        }
        for (cat, n) in count(src) {
            *out.entry((krate.clone(), cat)).or_insert(0) += n;
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
            out.push(format!("{krate} {cat}: {a}, above the baseline {b}; use ua_ingress instead"));
        } else if a < b {
            out.push(format!("{krate} {cat}: {a}, below the baseline {b}; lower BASELINE to {a}"));
        }
    }
    out
}

#[test]
fn duplicated_ingress_plumbing_only_goes_down() {
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

#[test]
fn each_category_is_caught() {
    let cases: &[(&str, &str)] = &[
        ("fn f() { let c = reqwest::Client::builder().build(); }", "client_builder"),
        ("use reqwest::ClientBuilder;\nfn f() { ClientBuilder::new().build(); }", "client_builder"),
        ("use reqwest::Client;\nfn f() { let c = Client::new(); }", "client_builder"),
        ("fn f() { let c = reqwest::Client::default(); }", "client_builder"),
        ("fn is_ok(ip: IpAddr) -> bool { ip.is_loopback() }", "address_classifier"),
        (
            "pub fn why(ip: std::net::Ipv4Addr) -> Option<&'static str> { (ip.octets()[0] == 0).then_some(\"zero\") }",
            "address_classifier",
        ),
        (
            "pub(crate) fn vet(a: &Ipv6Addr, loopback: bool) -> Result<(), String> { non_public_reason(a)?; Ok(()) }",
            "address_classifier",
        ),
        (
            "fn multi(\n    host: &str,\n    ip: &mut IpAddr,\n) -> bool {\n    ip.is_multicast()\n}",
            "address_classifier",
        ),
        (
            "fn g<T: Into<u8>>(t: T, ip: &net::IpAddr) -> Option<T> { embedded_v4(ip).map(|_| t) }",
            "address_classifier",
        ),
        ("const S: &str = \"CREATE TABLE IF NOT EXISTS github_deliveries (id TEXT)\";", "delivery_table"),
        ("const S: &str = \"create table slack_seen_signatures (sig TEXT)\";", "delivery_table"),
        ("const S: &str = r#\"CREATE TABLE \"github_delivery_bodies\" (x)\"#;", "delivery_table"),
        ("const S: &str = \"CREATE TABLE IF NOT EXISTS\n    slack_seen_deliveries (x)\";", "delivery_table"),
    ];
    for (src, cat) in cases {
        let got = count(src);
        assert!(got.get(cat).copied().unwrap_or(0) >= 1, "{cat} not caught in {src}: {got:?}");
    }
    // Not a classifier: no address parameter, no verdict returned, or the
    // address only used as a key.
    assert!(count("fn f(port: u16) -> bool { ip.is_loopback() }").is_empty());
    assert!(count("fn rate_ok(addr: IpAddr, n: u32) -> bool { seen(addr) < n }").is_empty());
    assert!(count("fn show(ip: IpAddr) -> String { ip.octets().len().to_string() }").is_empty());
    assert!(count("fn f(ip: MyIpAddrish) -> bool { ip.is_private() }").is_empty());
    // Other tables, other clients, and a `Client::new` with no reqwest in sight.
    assert!(count("const S: &str = \"CREATE TABLE github_deliveries_v2 (x)\";").is_empty());
    assert!(count("const S: &str = \"CREATE TABLE tasks (x)\";").is_empty());
    assert!(count("fn f() { let c = rmcp::Client::new(); }").is_empty());
    assert!(count("fn f() { let c = HttpClient::builder(); }").is_empty());
    // Comments and test code are not counted; code text in strings is not.
    assert!(count("// reqwest::Client::builder()\nfn f() { let s = \"Client::builder(\"; }").is_empty());
    assert!(count("// fn f(ip: IpAddr) -> bool { ip.is_private() }\nfn g() {}").is_empty());
    assert!(
        count("#[cfg(test)]\nmod tests { fn t(ip: IpAddr) -> bool { reqwest::Client::builder(); ip.is_private() } }")
            .is_empty()
    );
    assert!(
        count("#[cfg(test)]\nmod tests { const S: &str = \"CREATE TABLE github_deliveries (x)\"; }")
            .is_empty()
    );
    // The table scan keeps offsets after a test item with multi-byte text.
    assert_eq!(
        count("#[cfg(test)]\nmod t { const A: &str = \"—é\"; }\nconst S: &str = \"CREATE TABLE slack_seen_deliveries (x)\";")
            .get("delivery_table"),
        Some(&1)
    );
}

#[test]
fn drift_is_reported_both_ways() {
    let mut actual = BTreeMap::new();
    actual.insert(("ua-demo".to_string(), "client_builder"), 1);
    let found = drift(&actual);
    assert!(
        found.iter().any(|l| l.starts_with("ua-demo client_builder: 1, above the baseline 0")),
        "{found:?}"
    );
    if let Some((k, c, n)) = BASELINE.first() {
        let found = drift(&BTreeMap::new());
        assert!(
            found.iter().any(|l| l == &format!("{k} {c}: 0, below the baseline {n}; lower BASELINE to 0"))
        );
    }
}
