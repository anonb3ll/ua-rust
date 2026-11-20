//! Public-safety gates for the relay.
//!
//! Every gate refuses: a draft with any finding is blocked, and nothing is
//! rewritten. The agent fixes the text and drafts again, so the text a human
//! approves is exactly the text the agent wrote and exactly the text sent.
//!
//! Findings carry a category, a detail and, where it is safe, a masked
//! excerpt and the character offset. A match of the private denylist carries
//! neither, and any other finding that overlaps one loses both, so no part
//! of a denylisted term is echoed back.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};
use secrecy::ExposeSecret;
use serde::Serialize;
use serde_json::{Value, json};
use ua_core::{Config, UaError, UaResult};

use crate::families::audit::rules::{mask, secret_spans};
use crate::families::web::embedded_v4;

/// Findings listed in a result; the category counts cover all of them.
pub const MAX_FINDINGS_SHOWN: usize = 50;
/// Hard ceiling on `relay_max_chars`, under GitHub's 65536-character limit.
pub const MAX_CHARS_CEILING: usize = 65_000;

/// One gate hit.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: &'static str,
    pub detail: String,
    /// A bounded, masked excerpt; never the whole match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    /// Character offset of the match in the text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(skip)]
    start: usize,
    #[serde(skip)]
    end: usize,
}

impl Finding {
    fn new(category: &'static str, detail: impl Into<String>, start: usize, end: usize) -> Self {
        Self { category, detail: detail.into(), excerpt: None, offset: None, start, end }
    }

    fn excerpt(mut self, excerpt: String) -> Self {
        self.excerpt = Some(excerpt);
        self
    }
}

/// The gates' verdict on one text.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub findings: Vec<Finding>,
}

impl Verdict {
    pub fn passed(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn label(&self) -> &'static str {
        if self.passed() { "pass" } else { "block" }
    }

    /// Findings per category.
    pub fn categories(&self) -> BTreeMap<&'static str, usize> {
        let mut out = BTreeMap::new();
        for f in &self.findings {
            *out.entry(f.category).or_insert(0) += 1;
        }
        out
    }

    /// `{verdict, findings (at most MAX_FINDINGS_SHOWN), findings_total, categories}`.
    pub fn to_json(&self) -> Value {
        let shown: Vec<&Finding> = self.findings.iter().take(MAX_FINDINGS_SHOWN).collect();
        json!({
            "verdict": self.label(),
            "findings": shown,
            "findings_total": self.findings.len(),
            "categories": self.categories(),
        })
    }
}

/// The gates, built from the configuration once per call.
pub struct Gates {
    max_chars: usize,
    internal_hosts: Vec<Regex>,
    denylist: Vec<Regex>,
}

impl Gates {
    /// Fails closed when a denylist entry does not compile. The error names
    /// the entry's position, never its text.
    pub fn from_config(cfg: &Config) -> UaResult<Self> {
        let mut denylist = Vec::new();
        for (i, p) in cfg.relay_denylist.iter().enumerate() {
            let rx = RegexBuilder::new(p.expose_secret())
                .case_insensitive(true)
                .size_limit(1 << 20)
                .build()
                .map_err(|_| {
                    UaError::denied(
                        "relay_denylist_invalid",
                        format!(
                            "relay_denylist entry {} does not compile; the relay refuses every draft until it is fixed",
                            i + 1
                        ),
                    )
                })?;
            denylist.push(rx);
        }
        let internal_hosts = cfg
            .relay_internal_hosts
            .iter()
            .map(|h| h.trim())
            .filter(|h| !h.is_empty())
            .filter_map(|h| RegexBuilder::new(&regex::escape(h)).case_insensitive(true).build().ok())
            .collect();
        Ok(Self { max_chars: cfg.relay_max_chars.clamp(1, MAX_CHARS_CEILING), internal_hosts, denylist })
    }

    pub fn max_chars(&self) -> usize {
        self.max_chars
    }

    /// Run every gate over `text`.
    pub fn check(&self, text: &str) -> Verdict {
        let mut found = Vec::new();
        secrets(text, &mut found);
        hidden(text, &mut found);
        addresses(text, &mut found);
        hosts(text, &self.internal_hosts, &mut found);
        home_paths(text, &mut found);
        pii(text, &mut found);
        let chars = text.chars().count();
        if chars > self.max_chars {
            found.push(Finding::new(
                "length",
                format!("{chars} characters; the limit is {}", self.max_chars),
                0,
                0,
            ));
        }
        let mut denied_spans = Vec::new();
        let mut denied = Vec::new();
        for rx in &self.denylist {
            let spans: Vec<(usize, usize)> = rx.find_iter(text).map(|m| (m.start(), m.end())).collect();
            if !spans.is_empty() {
                denied.push(Finding::new("denylist", "matches an entry of the private denylist", 0, 0));
                denied_spans.extend(spans);
            }
        }
        let mut findings = dedupe(found);
        for f in &mut findings {
            if denied_spans.iter().any(|&(s, e)| f.start < e.max(s + 1) && s < f.end.max(f.start + 1)) {
                f.excerpt = None;
            } else if f.category != "length" {
                f.offset = Some(text[..f.start].chars().count());
            }
        }
        findings.extend(denied);
        Verdict { findings }
    }
}

/// Drop a finding wholly inside an earlier finding of the same category.
fn dedupe(mut found: Vec<Finding>) -> Vec<Finding> {
    found.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut kept: Vec<Finding> = Vec::new();
    for f in found {
        let covered = kept
            .iter()
            .any(|k| k.category == f.category && k.start <= f.start && f.end <= k.end && k.end > k.start);
        if !covered {
            kept.push(f);
        }
    }
    kept
}

fn rx(p: &str) -> Regex {
    Regex::new(p).expect("relay gate pattern compiles")
}

fn prev_char(text: &str, i: usize) -> Option<char> {
    text[..i].chars().next_back()
}

/// The character at `i` and the one after it.
fn next_two(text: &str, i: usize) -> (Option<char>, Option<char>) {
    let mut it = text[i..].chars();
    (it.next(), it.next())
}

fn word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// True when the match ends a token: the next character is not a word
/// character, and not a dot that continues the token (`10.0.0.1.5`).
fn ends_token(text: &str, end: usize, also: &[char]) -> bool {
    match next_two(text, end) {
        (Some(c), _) if word(c) || also.contains(&c) => false,
        (Some('.'), Some(d)) if word(d) => false,
        _ => true,
    }
}

fn starts_token(text: &str, start: usize, also: &[char]) -> bool {
    !prev_char(text, start).is_some_and(|c| word(c) || also.contains(&c))
}

/// A short excerpt: the first `keep` characters and the length.
fn short(s: &str, keep: usize) -> String {
    let n = s.chars().count();
    let head: String = s.chars().take(keep.min(n / 3).max(1)).collect();
    format!("{head}…({n} chars)")
}

// --- secrets ---------------------------------------------------------------------------

fn hidden_rx() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    // Format characters (zero-width, bidirectional controls, tags, soft
    // hyphen), variation selectors, Hangul fillers that render blank, line
    // and paragraph separators, and C0/C1 controls.
    RX.get_or_init(|| {
        rx(r"[\p{Cf}\p{Cc}\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}\x{115F}\x{1160}\x{3164}\x{FFA0}\x{2028}\x{2029}]")
    })
}

fn allowed_control(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\t')
}

/// `text` without hidden characters, and for each kept byte its index in `text`.
fn strip_hidden(text: &str) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len());
    let mut keep = |from: usize, to: usize, out: &mut String| {
        out.push_str(&text[from..to]);
        map.extend(from..to);
    };
    let mut last = 0;
    for m in hidden_rx().find_iter(text) {
        if m.as_str().chars().all(allowed_control) {
            continue;
        }
        keep(last, m.start(), &mut out);
        last = m.end();
    }
    keep(last, text.len(), &mut out);
    (out, map)
}

fn extra_secret_shapes() -> &'static [(&'static str, &'static str, Regex)] {
    static SHAPES: OnceLock<Vec<(&'static str, &'static str, Regex)>> = OnceLock::new();
    SHAPES.get_or_init(|| {
        vec![
            ("private_key", "private key block", rx(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")),
            (
                "secret",
                "credential assignment",
                rx(
                    r#"\b[A-Z][A-Z0-9_]*_(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)\s*[=:]\s*["']?(?P<val>[^\s"']{8,})"#,
                ),
            ),
            ("secret", "bearer credential", rx(r"(?i)\bbearer\s+(?P<val>[A-Za-z0-9._~+/=-]{20,})")),
        ]
    })
}

fn placeholder(value: &str) -> bool {
    static RX: OnceLock<Regex> = OnceLock::new();
    let rx = RX.get_or_init(|| {
        rx(r"(?i)^(?:<[^<>\s]+>|\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|[*x.\x{2022}]+|\[REDACTED[A-Z_]*\])$")
    });
    rx.is_match(value.trim_matches(|c| c == '"' || c == '\''))
}

/// Credential shapes, matched on the text with hidden characters removed so
/// a zero-width character inside a token does not hide it.
fn secrets(text: &str, out: &mut Vec<Finding>) {
    let (stripped, map) = strip_hidden(text);
    let back = |s: usize, e: usize| -> (usize, usize) {
        let start = map.get(s).copied().unwrap_or(text.len());
        let end = if e == 0 { start } else { map.get(e - 1).map(|i| i + 1).unwrap_or(text.len()) };
        // Map onto character boundaries of the original text.
        let start = (0..=start).rev().find(|i| text.is_char_boundary(*i)).unwrap_or(0);
        let end = (end..=text.len()).find(|i| text.is_char_boundary(*i)).unwrap_or(text.len());
        (start, end)
    };
    for s in secret_spans(&stripped) {
        let (start, end) = back(s.start, s.end);
        let (category, excerpt) = if s.name.contains("private key") {
            ("private_key", "PuTTY-User-Key-File…".to_string())
        } else {
            ("secret", mask(&s.value))
        };
        out.push(Finding::new(category, s.name, start, end).excerpt(excerpt));
    }
    for (category, name, shape) in extra_secret_shapes() {
        for caps in shape.captures_iter(&stripped) {
            let Some(whole) = caps.get(0) else { continue };
            let value = caps.name("val").map(|m| m.as_str()).unwrap_or(whole.as_str());
            if *category == "secret" && placeholder(value) {
                continue;
            }
            let (start, end) = back(whole.start(), whole.end());
            let excerpt = if *category == "private_key" {
                "-----BEGIN …PRIVATE KEY".to_string()
            } else {
                mask(value)
            };
            out.push(Finding::new(category, *name, start, end).excerpt(excerpt));
        }
    }
}

// --- hidden characters -------------------------------------------------------------------

fn hidden(text: &str, out: &mut Vec<Finding>) {
    for m in hidden_rx().find_iter(text) {
        let Some(c) = m.as_str().chars().next() else { continue };
        if allowed_control(c) {
            continue;
        }
        let detail = if c.is_control() {
            "control character"
        } else {
            "invisible, bidirectional or variation-selector character"
        };
        out.push(
            Finding::new("hidden_unicode", detail, m.start(), m.end()).excerpt(format!("U+{:04X}", c as u32)),
        );
    }
}

// --- addresses ------------------------------------------------------------------------------

/// Why an IPv4 address must not be published, or `None`.
fn v4_kind(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    if ip.is_loopback() {
        Some("loopback address")
    } else if ip.is_private() {
        Some("private network address")
    } else if ip.is_link_local() {
        Some("link-local address")
    } else if o[0] == 100 && (o[1] & 0xC0) == 64 {
        Some("shared (CGNAT) address, as tailnets use")
    } else {
        None
    }
}

fn v6_kind(ip: Ipv6Addr) -> Option<&'static str> {
    if let Some(v4) = embedded_v4(ip) {
        return v4_kind(v4);
    }
    let s = ip.segments();
    if ip.is_loopback() {
        Some("loopback address")
    } else if (s[0] & 0xfe00) == 0xfc00 {
        Some("unique local address")
    } else if (s[0] & 0xffc0) == 0xfe80 {
        Some("link-local address")
    } else {
        None
    }
}

fn addresses(text: &str, out: &mut Vec<Finding>) {
    static V4: OnceLock<Regex> = OnceLock::new();
    static V6: OnceLock<Regex> = OnceLock::new();
    let v4 = V4.get_or_init(|| rx(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}"));
    let v6 = V6.get_or_init(|| rx(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f.]{0,15}){2,8}"));
    for m in v4.find_iter(text) {
        if !starts_token(text, m.start(), &['.']) || !ends_token(text, m.end(), &[]) {
            continue;
        }
        if let Some(kind) = m.as_str().parse::<Ipv4Addr>().ok().and_then(v4_kind) {
            out.push(Finding::new("private_address", kind, m.start(), m.end()).excerpt(short(m.as_str(), 4)));
        }
    }
    for m in v6.find_iter(text) {
        let cand = m.as_str().trim_end_matches('.');
        if !cand.chars().any(|c| c.is_ascii_hexdigit())
            || !starts_token(text, m.start(), &[':', '.'])
            || !ends_token(text, m.start() + cand.len(), &[':'])
        {
            continue;
        }
        if let Some(kind) = cand.parse::<Ipv6Addr>().ok().and_then(v6_kind) {
            let end = m.start() + cand.len();
            out.push(Finding::new("private_address", kind, m.start(), end).excerpt(short(cand, 4)));
        }
    }
}

// --- host names --------------------------------------------------------------------------------

fn hosts(text: &str, configured: &[Regex], out: &mut Vec<Finding>) {
    static SUFFIX: OnceLock<Regex> = OnceLock::new();
    static URL_HOST: OnceLock<Regex> = OnceLock::new();
    let suffix = SUFFIX.get_or_init(|| {
        rx(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:ts\.net|local|localdomain|internal|intranet|lan|corp|home\.arpa)")
    });
    let url_host = URL_HOST.get_or_init(|| {
        rx(r#"(?i)\b[a-z][a-z0-9+.-]*://(?:[^\s/@]*@)?(?P<host>[a-z0-9-]{1,63})(?::[0-9]{1,5})?(?:[/?#\s)\]>"'<,;]|$)"#)
    });
    for m in suffix.find_iter(text) {
        if starts_token(text, m.start(), &['.', '@', '-']) && ends_token(text, m.end(), &['-']) {
            out.push(
                Finding::new("internal_host", "private DNS suffix", m.start(), m.end())
                    .excerpt(short(m.as_str(), 4)),
            );
        }
    }
    for caps in url_host.captures_iter(text) {
        let Some(h) = caps.name("host") else { continue };
        if h.as_str().eq_ignore_ascii_case("localhost") {
            continue;
        }
        out.push(
            Finding::new("internal_host", "single-label host name in a URL", h.start(), h.end())
                .excerpt(short(h.as_str(), 3)),
        );
    }
    for rx in configured {
        for m in rx.find_iter(text) {
            if starts_token(text, m.start(), &['.', '-']) && ends_token(text, m.end(), &['-']) {
                out.push(
                    Finding::new(
                        "internal_host",
                        "host name listed in relay_internal_hosts",
                        m.start(),
                        m.end(),
                    )
                    .excerpt(short(m.as_str(), 3)),
                );
            }
        }
    }
}

// --- home paths ----------------------------------------------------------------------------------

/// Account names that stand for "some user" in documentation and CI logs.
const GENERIC_ACCOUNTS: [&str; 8] =
    ["user", "username", "you", "me", "example", "runner", "shared", "public"];

fn home_paths(text: &str, out: &mut Vec<Finding>) {
    static UNIX: OnceLock<Regex> = OnceLock::new();
    static WINDOWS: OnceLock<Regex> = OnceLock::new();
    let unix = UNIX.get_or_init(|| rx(r"(?:/var/home|/home|/Users)/(?P<user>[A-Za-z0-9._-]+)"));
    let windows = WINDOWS.get_or_init(|| rx(r"(?i)\b[a-z]:\\users\\(?P<user>[a-z0-9._-]+)"));
    for re in [unix, windows] {
        for caps in re.captures_iter(text) {
            let (Some(m), Some(user)) = (caps.get(0), caps.name("user")) else { continue };
            if !starts_token(text, m.start(), &['.']) {
                continue;
            }
            let name = user.as_str().to_ascii_lowercase();
            if GENERIC_ACCOUNTS.contains(&name.as_str()) || name.chars().all(|c| c == '.') {
                continue;
            }
            out.push(
                Finding::new(
                    "home_path",
                    "absolute home directory path (names an account)",
                    m.start(),
                    m.end(),
                )
                .excerpt(short(m.as_str(), 6)),
            );
        }
    }
}

// --- personal data --------------------------------------------------------------------------------

const SAFE_EMAIL_DOMAINS: [&str; 3] = ["example.com", "example.org", "example.net"];
const SAFE_EMAIL_TLDS: [&str; 4] = ["example", "test", "invalid", "localhost"];

fn safe_email(addr: &str) -> bool {
    let lower = addr.to_ascii_lowercase();
    let (local, domain) = lower.rsplit_once('@').unwrap_or(("", &lower));
    let tld = domain.rsplit('.').next().unwrap_or("");
    lower.contains("noreply")
        || local == "git"
        || SAFE_EMAIL_TLDS.contains(&tld)
        || SAFE_EMAIL_DOMAINS.iter().any(|d| domain == *d || domain.ends_with(&format!(".{d}")))
}

fn luhn(digits: &[u32]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| if i % 2 == 1 { if d * 2 > 9 { d * 2 - 9 } else { d * 2 } } else { d })
        .sum();
    sum.is_multiple_of(10)
}

/// A payment card number: a known issuer prefix, a valid length and checksum.
fn card_number(raw: &str) -> bool {
    let d: Vec<u32> = raw.chars().filter_map(|c| c.to_digit(10)).collect();
    let s: String = raw.chars().filter(char::is_ascii_digit).collect();
    let n = d.len();
    let p = |k: usize| s.get(..k).and_then(|x| x.parse::<u32>().ok()).unwrap_or(0);
    let issuer = (s.starts_with('4') && matches!(n, 13 | 16 | 19))
        || (((51..=55).contains(&p(2)) || (2221..=2720).contains(&p(4))) && n == 16)
        || (matches!(p(2), 34 | 37) && n == 15)
        || ((p(4) == 6011 || p(2) == 65 || (644..=649).contains(&p(3))) && (16..=19).contains(&n));
    issuer && luhn(&d)
}

fn pii(text: &str, out: &mut Vec<Finding>) {
    static EMAIL: OnceLock<Regex> = OnceLock::new();
    static PHONE: OnceLock<Regex> = OnceLock::new();
    static INTL: OnceLock<Regex> = OnceLock::new();
    static SSN: OnceLock<Regex> = OnceLock::new();
    static CARD: OnceLock<Regex> = OnceLock::new();
    let email =
        EMAIL.get_or_init(|| rx(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"));
    let phone = PHONE
        .get_or_init(|| rx(r"(?:\+[0-9]{1,3}[ .-]?)?(?:\([0-9]{3}\) ?|[0-9]{3}[ .-])[0-9]{3}[ .-][0-9]{4}"));
    let intl = INTL.get_or_init(|| rx(r"\+[0-9]{10,15}"));
    let ssn = SSN.get_or_init(|| rx(r"[0-9]{3}-[0-9]{2}-[0-9]{4}"));
    let card = CARD.get_or_init(|| {
        rx(r"[0-9]{4}[ -][0-9]{6}[ -][0-9]{5}|[0-9]{4}(?:[ -][0-9]{4}){2}[ -][0-9]{4,7}|[0-9]{13,19}")
    });
    for m in email.find_iter(text) {
        if starts_token(text, m.start(), &['.', '+', '-', '%'])
            && ends_token(text, m.end(), &['-'])
            && !safe_email(m.as_str())
        {
            out.push(
                Finding::new("email", "e-mail address", m.start(), m.end()).excerpt(short(m.as_str(), 2)),
            );
        }
    }
    for re in [phone, intl] {
        for m in re.find_iter(text) {
            let lead = if m.as_str().starts_with(['+', '(']) { &[][..] } else { &['.', '+', '-'][..] };
            if starts_token(text, m.start(), lead) && ends_token(text, m.end(), &['-']) {
                out.push(
                    Finding::new("phone", "phone number", m.start(), m.end()).excerpt(short(m.as_str(), 2)),
                );
            }
        }
    }
    for m in ssn.find_iter(text) {
        if starts_token(text, m.start(), &['-', '.']) && ends_token(text, m.end(), &['-']) {
            out.push(
                Finding::new("national_id", "national identity number shape (US SSN)", m.start(), m.end())
                    .excerpt(short(m.as_str(), 1)),
            );
        }
    }
    for m in card.find_iter(text) {
        if starts_token(text, m.start(), &['-', '.'])
            && ends_token(text, m.end(), &['-'])
            && card_number(m.as_str())
        {
            out.push(
                Finding::new("payment_card", "payment card number", m.start(), m.end())
                    .excerpt(short(m.as_str(), 2)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_and_issuers() {
        assert!(card_number("4111 1111 1111 1111"));
        assert!(card_number("5555-5555-5555-4444"));
        assert!(card_number("378282246310005"));
        assert!(!card_number("4111 1111 1111 1112"), "bad checksum");
        assert!(!card_number("1700000000000"), "a millisecond timestamp is not a card");
    }

    #[test]
    fn hidden_characters_are_stripped_with_a_byte_map() {
        let t = "ab\u{200B}c";
        let (s, map) = strip_hidden(t);
        assert_eq!(s, "abc");
        assert_eq!(map, vec![0, 1, 5]);
        let (s, _) = strip_hidden("a\nb\tc");
        assert_eq!(s, "a\nb\tc", "newlines and tabs are kept");
    }

    #[test]
    fn emails_on_documentation_domains_pass() {
        assert!(safe_email("dev@example.com"));
        assert!(safe_email("a@mail.example.org"));
        assert!(safe_email("12345+bot@users.noreply.github.com"));
        assert!(safe_email("git@github.com"));
        assert!(!safe_email("someone@gmail.com"));
    }
}
