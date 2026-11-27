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
//!   returns `bool`, `Option<..>` or `Result<..>`, and whose body holds
//!   hand-written range logic ([`RANGE_PROBES`]: a standard-library range
//!   test or taking the address apart): the shape of an address classifier.
//!   A function that only calls `ua_ingress::addr` is not counted. Use
//!   `ua_ingress::addr` instead;
//! - `inline_address_check`: each [`RANGE_PROBES`] call outside such a
//!   function: range logic written inline, on an address or a socket
//!   address (`addr.ip().is_loopback()`). Calls of the `ua_ingress::addr`
//!   functions are not counted;
//! - `direct_dial`: a connection dialled by hand instead of through
//!   `Outbound` ([`DIAL_PATTERNS`]: `TcpStream::connect…`, `TcpSocket`,
//!   rustls or native TLS connectors, `tokio-tungstenite` client
//!   handshakes, hyper's `HttpConnector`). Unix-domain sockets are local and
//!   not counted;
//! - `delivery_table`: `CREATE TABLE` (with or without `IF NOT EXISTS`) of
//!   an inbound delivery, replay or dedupe record: a table whose name holds
//!   one of [`DELIVERY_NAME_MARKS`] or which has a column named in
//!   [`DELIVERY_COLUMNS`]. Searched in the text as written, since SQL lives
//!   in strings.
//!
//! Test code (`#[cfg(test)]` items) is not counted; comments and strings are
//! not counted for the code categories.
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
    // `oauth/register.rs`: a loopback redirect host (2) and the
    // registration rate limit's loopback peer (1); `login.rs`: a loopback
    // link host (2).
    ("ua-server", "inline_address_check", 5),
    // `slack_socket.rs::connect`: `TcpStream::connect`, the rustls
    // `TlsConnector`, the `tokio-tungstenite` client handshake.
    ("ua-server", "direct_dial", 3),
    // `ops/doctor.rs`: is the bind address loopback.
    ("ua-cli", "inline_address_check", 1),
    // `mcp::scope::{classify, classify_v4}` and `relay::gates::{v4_kind,
    // v6_kind}` (which judge publication, not reachability, but have the
    // same shape).
    ("ua-tools", "address_classifier", 4),
    // Loopback URL hosts in `slack.rs` (2), `zulip.rs` (2),
    // `github/client.rs` (2) and `harness_config/policy.rs` (2); loopback
    // bind or host checks in `observability.rs` (2) and `vault/obsidian.rs`
    // (1).
    ("ua-tools", "inline_address_check", 11),
    // `mcp::gateway` (`web::http_client`, `github::client`,
    // `vault::obsidian` and `notify` are gone: their consumers use
    // `Outbound`).
    ("ua-tools", "client_builder", 1),
    // `github_deliveries`, `github_delivery_bodies` (github/mod.rs) and
    // `slack_seen_signatures`, `slack_seen_deliveries` (slack.rs).
    ("ua-tools", "delivery_table", 4),
];

const CATEGORIES: &[&str] =
    &["client_builder", "address_classifier", "inline_address_check", "direct_dial", "delivery_table"];

/// Words in a table name that mark an inbound delivery, replay or dedupe
/// record. Checked against every table in the tree: they match the four
/// delivery tables and nothing else (`idempotency_keys` and
/// `dispatch_receipts` are not inbound deliveries and match no mark).
const DELIVERY_NAME_MARKS: &[&str] = &["deliver", "seen", "replay", "dedup", "webhook", "envelope"];

/// Words that contain a mark but name something else, removed from a table
/// name before the marks are looked for: a deliverable is what a task
/// produces (`ua-deliverables`), not an inbound delivery. A name that also
/// holds a real mark (`deliverable_deliveries`) is still caught.
const NOT_DELIVERY_WORDS: &[&str] = &["deliverable"];

/// Column names that mark an inbound delivery record, whatever the table is
/// called.
const DELIVERY_COLUMNS: &[&str] = &["delivery_id", "envelope_id", "event_id", "trigger_id", "request_sha"];

/// Connections dialled by hand.
const DIAL_PATTERNS: &[&str] = &[
    "TcpStream::connect",
    "TcpSocket::new_v4(",
    "TcpSocket::new_v6(",
    "TlsConnector::from(",
    "TlsConnector::new(",
    "TlsConnector::builder(",
    "connect_async",
    "client_async",
    "HttpConnector::new(",
];

const IP_TYPES: &[&str] = &["IpAddr", "Ipv4Addr", "Ipv6Addr"];

/// Hand-written range logic: a standard-library range test, or taking the
/// address apart. A function that only uses an address as a key, or only
/// calls `ua_ingress::addr`, holds none.
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
    ".is_unique_local(",
    ".is_unicast_link_local(",
    ".to_ipv4_mapped(",
    ".to_ipv4(",
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
    let mut classifier_bodies: Vec<(usize, usize)> = Vec::new();
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
        let end = close_brace(m, tail_end);
        if RANGE_PROBES.iter().any(|p| m[tail_end..end].contains(p)) {
            out.entry("address_classifier").or_default().push(at);
            classifier_bodies.push((tail_end, end));
        }
    }
    for p in RANGE_PROBES {
        for (at, _) in m.match_indices(p) {
            if !classifier_bodies.iter().any(|(s, e)| *s <= at && at < *e) {
                out.entry("inline_address_check").or_default().push(at);
            }
        }
    }
    for pat in DIAL_PATTERNS {
        for at in find_all(m, pat) {
            out.entry("direct_dial").or_default().push(at);
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
        let mut name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        for word in NOT_DELIVERY_WORDS {
            name = name.replace(word, "_");
        }
        if DELIVERY_NAME_MARKS.iter().any(|w| name.contains(w))
            || columns(rest).iter().any(|c| DELIVERY_COLUMNS.contains(&c.as_str()))
        {
            out.push(at);
        }
    }
    out
}

/// The column names of a `CREATE TABLE` body (`rest` starts at the table
/// name): the first word of each top-level item, constraints skipped.
fn columns(rest: &str) -> Vec<String> {
    let Some(open) = rest.find('(') else { return Vec::new() };
    let mut depth = 0i32;
    let mut items = Vec::new();
    let mut start = open + 1;
    for (i, c) in rest[open..].char_indices() {
        let i = open + i;
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    items.push(&rest[start..i]);
                    break;
                }
            }
            ',' if depth == 1 => {
                items.push(&rest[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    items
        .iter()
        .filter_map(|item| item.split_whitespace().next())
        .map(|w| w.trim_matches(['"', '`', '[', ']']).to_string())
        .filter(|w| !["primary", "unique", "foreign", "check", "constraint"].contains(&w.as_str()))
        .collect()
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
            "pub(crate) fn vet(a: &Ipv6Addr, loopback: bool) -> Result<(), String> { (a.segments()[0] == 0).then_some(()).ok_or_default() }",
            "address_classifier",
        ),
        (
            "fn multi(\n    host: &str,\n    ip: &mut IpAddr,\n) -> bool {\n    ip.is_multicast()\n}",
            "address_classifier",
        ),
        (
            "fn g<T: Into<u8>>(t: T, ip: &net::IpAddr) -> Option<T> { ip.to_ipv4_mapped().map(|_| t) }",
            "address_classifier",
        ),
        ("fn f() { let local = cfg.bind.ip().is_loopback(); }", "inline_address_check"),
        (
            "fn f(h: url::Host) -> bool { matches!(h, Host::Ipv4(ip) if ip.is_private()) }",
            "inline_address_check",
        ),
        ("fn f(o: [u8; 4]) { let x = ip.octets()[0] == 10; }", "inline_address_check"),
        ("async fn f() { tokio::net::TcpStream::connect(&addrs[..]).await; }", "direct_dial"),
        ("fn f() { std::net::TcpStream::connect_timeout(&a, t); }", "direct_dial"),
        ("fn f() { let c = tokio_rustls::TlsConnector::from(Arc::new(config)); }", "direct_dial"),
        ("async fn f() { tokio_tungstenite::client_async_with_config(u, io, None).await; }", "direct_dial"),
        ("async fn f() { tokio_tungstenite::connect_async(u).await; }", "direct_dial"),
        ("fn f() { let s = tokio::net::TcpSocket::new_v4(); }", "direct_dial"),
        ("const S: &str = \"CREATE TABLE IF NOT EXISTS github_deliveries (id TEXT)\";", "delivery_table"),
        ("const S: &str = \"create table slack_seen_signatures (sig TEXT)\";", "delivery_table"),
        ("const S: &str = r#\"CREATE TABLE \"github_delivery_bodies\" (x)\"#;", "delivery_table"),
        ("const S: &str = \"CREATE TABLE IF NOT EXISTS\n    slack_seen_deliveries (x)\";", "delivery_table"),
        // Under another name: by a name mark, or by a column.
        ("const S: &str = \"CREATE TABLE zulip_webhook_log (id TEXT)\";", "delivery_table"),
        ("const S: &str = \"CREATE TABLE inbound_replays (id TEXT)\";", "delivery_table"),
        (
            "const S: &str = \"CREATE TABLE IF NOT EXISTS chat_inbox (\n    team TEXT,\n    event_id TEXT NOT NULL,\n    PRIMARY KEY (team, event_id)\n)\";",
            "delivery_table",
        ),
        ("const S: &str = \"CREATE TABLE things (kind TEXT, delivery_id TEXT)\";", "delivery_table"),
        // A deliverable's word does not hide a real mark next to it.
        ("const S: &str = \"CREATE TABLE deliverable_deliveries (id TEXT)\";", "delivery_table"),
        ("const S: &str = \"CREATE TABLE deliverables_seen (id TEXT)\";", "delivery_table"),
    ];
    for (src, cat) in cases {
        let got = count(src);
        assert!(got.get(cat).copied().unwrap_or(0) >= 1, "{cat} not caught in {src}: {got:?}");
    }
    // Not a classifier: no address parameter, no verdict returned, or the
    // address only used as a key.
    assert_eq!(
        count("fn f(port: u16) -> bool { ip.is_loopback() }"),
        BTreeMap::from([("inline_address_check", 1)]),
        "not a classifier, but inline range logic"
    );
    assert!(count("fn rate_ok(addr: IpAddr, n: u32) -> bool { seen(addr) < n }").is_empty());
    assert!(
        !count("fn show(ip: IpAddr) -> String { ip.octets().len().to_string() }")
            .contains_key("address_classifier")
    );
    assert!(!count("fn f(ip: MyIpAddrish) -> bool { ip.is_private() }").contains_key("address_classifier"));
    // A function that only calls the crate's classifier holds no range logic.
    assert!(
        count("fn vet(ip: IpAddr, lo: bool) -> Result<(), String> { match non_public_reason(ip) { None => Ok(()), Some(_) if lo && is_loopback(ip) => Ok(()), Some(r) => Err(r.into()) } }")
            .is_empty()
    );
    assert!(count("fn f(a: SocketAddr) -> bool { ua_ingress::addr::is_public(a.ip()) }").is_empty());
    // Probes inside a counted classifier are not counted again inline.
    assert_eq!(
        count("fn c(ip: Ipv4Addr) -> bool { ip.is_loopback() || ip.is_private() }"),
        BTreeMap::from([("address_classifier", 1)])
    );
    // Local sockets are not dialled connections.
    assert!(count("async fn f() { tokio::net::UnixStream::connect(p).await; }").is_empty());
    assert!(count("fn reconnect_async_later() {}").is_empty());
    // Other tables (the tree's lookalikes among them), other clients, and a
    // `Client::new` with no reqwest in sight.
    assert!(count("const S: &str = \"CREATE TABLE tasks (x)\";").is_empty());
    assert!(
        count("const S: &str = \"CREATE TABLE idempotency_keys (key TEXT PRIMARY KEY, response TEXT)\";")
            .is_empty()
    );
    assert!(
        count("const S: &str = \"CREATE TABLE dispatch_receipts (run_id TEXT, received_at TEXT)\";")
            .is_empty()
    );
    assert!(count("const S: &str = \"CREATE TABLE managed_secrets (name TEXT, nonce BLOB)\";").is_empty());
    // A deliverable is a task's work product, not an inbound delivery.
    assert!(count("const S: &str = \"CREATE TABLE IF NOT EXISTS deliverables (id INTEGER)\";").is_empty());
    assert!(
        count("const S: &str = \"CREATE TABLE deliverable_revisions (id INTEGER, identity TEXT)\";")
            .is_empty()
    );
    assert!(
        count(
            "const S: &str = \"CREATE TABLE event_log (id INTEGER, kind TEXT, CHECK (kind <> 'event_id'))\";"
        )
        .is_empty()
    );
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

/// The relaxed policies (`ua_ingress::policy::RELAXED`) and the only file
/// outside `ua-ingress` that may name each. By construction they cannot be
/// looked up by name and build only clients pinned to one origin
/// (`Outbound::pinned`); this scan is the second line of defence, keeping
/// each relaxed client in its one consumer file. Pinning guarantees one
/// origin per client. That the origin is the operator's configured value,
/// never one a caller supplies, is not proved here: it remains a review duty
/// in these three files.
/// `github.enterprise` and `notify.webhook` admit private networks for the
/// operator's `github_api_url` and `notify_webhook_url`; never for a URL a
/// caller supplies. `obsidian.local_rest` accepts any TLS certificate, on
/// loopback only.
const EXCEPTION_POLICIES: &[(&str, &str)] = &[
    ("GITHUB_ENTERPRISE", "ua-tools/src/families/github/client.rs"),
    ("OBSIDIAN_LOCAL", "ua-tools/src/families/vault/obsidian.rs"),
    ("NOTIFY_WEBHOOK", "ua-tools/src/families/notify.rs"),
    ("EMBEDDER_REMOTE", "ua-tools/src/families/memory/remote.rs"),
];

/// Relaxations that only `ua-ingress` itself may write.
const RELAXATIONS: &[&str] = &["OperatorConfigured", "accept_invalid_certs"];

#[test]
fn relaxed_policies_stay_with_their_one_consumer() {
    let files = sources();
    let homes: Vec<&str> = EXCEPTION_POLICIES.iter().map(|(_, home)| *home).collect();
    for (path, src) in &files {
        if crate_of(path) == "ua-ingress" {
            continue;
        }
        let code = without_tests(src);
        let shown = path.to_string_lossy();
        for r in RELAXATIONS {
            assert!(!code.contains(r), "{shown} names {r}: only ua_ingress::policy may use it");
        }
        for (constant, home) in EXCEPTION_POLICIES {
            let names_it = find_all(&code, constant).any(|at| !continues_ident(&code, at + constant.len()));
            assert!(!names_it || shown.ends_with(home), "{shown} names {constant}; only {home} may");
        }
        // A convenience, not the guard: an alias or other spacing gets past
        // this text match. The real guard is the constant check above, since
        // `Outbound::pinned` accepts only one of those relaxed policies.
        if code.contains("Outbound::pinned(") || code.contains("Outbound::pinned_to_addrs(") {
            assert!(homes.iter().any(|h| shown.ends_with(h)), "{shown} builds a pinned client");
        }
    }
}
