//! Public-safety gates for the relay.
//!
//! Every gate refuses: a draft with any finding is blocked, and nothing is
//! rewritten. The agent fixes the text and drafts again, so the text a human
//! approves is exactly the text the agent wrote and exactly the text sent.
//!
//! The content gates (secrets, addresses, host names, home paths, personal
//! data, the denylist) run twice: over the text as written, and over a copy
//! that is HTML-decoded, stripped of tags and comments, cleared of invisible
//! characters, NFKC-normalized, folded for common look-alike letters and
//! whitespace-collapsed. A credential split by `<b></b>`, an address written
//! with `&#46;` or a denylisted term spelled with Cyrillic letters is caught
//! by the second run. Structural gates (raw markup, links, mentions,
//! cross-references) read the Markdown the way GitHub renders it.
//!
//! Findings carry a category, a detail and, where it is safe, a masked
//! excerpt and the character offset. When the private denylist matches,
//! no finding carries an excerpt or an offset, so a caller cannot learn
//! where (or which part of) the text matched.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use base64::Engine;
use comrak::nodes::NodeValue;
use comrak::{Arena, Options, parse_document};
use icu_normalizer::ComposingNormalizerBorrowed;
use icu_properties::props::{DefaultIgnorableCodePoint, GeneralCategory, NoncharacterCodePoint, WhiteSpace};
use icu_properties::{CodePointMapData, CodePointSetData};
use regex::{Regex, RegexBuilder};
use secrecy::ExposeSecret;
use serde::Serialize;
use serde_json::{Value, json};
use ua_core::{Config, UaError, UaResult};
use url::{Host, Url};

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
    /// Byte range in the scanned text; `None` when the finding has no place
    /// in the text as written (a length finding, or one from the
    /// normalized copy).
    #[serde(skip)]
    span: Option<(usize, usize)>,
}

impl Finding {
    fn new(category: &'static str, detail: impl Into<String>, start: usize, end: usize) -> Self {
        Self { category, detail: detail.into(), excerpt: None, offset: None, span: Some((start, end)) }
    }

    fn unplaced(category: &'static str, detail: impl Into<String>) -> Self {
        Self { category, detail: detail.into(), excerpt: None, offset: None, span: None }
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
    redirectors: Vec<Regex>,
    denylist: Vec<Regex>,
    /// Lower-case `user` and `org/team` names that may be mentioned.
    mentions: BTreeSet<String>,
    /// Lower-case `owner/repo` slugs that may be cross-referenced.
    repos: BTreeSet<String>,
}

fn host_patterns(list: &[String]) -> Vec<Regex> {
    list.iter()
        .map(|h| h.trim())
        .filter(|h| !h.is_empty())
        .filter_map(|h| RegexBuilder::new(&regex::escape(h)).case_insensitive(true).build().ok())
        .collect()
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
        let lower = |list: &[String]| -> BTreeSet<String> {
            list.iter()
                .map(|s| s.trim().trim_start_matches('@').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };
        Ok(Self {
            max_chars: cfg.relay_max_chars.clamp(1, MAX_CHARS_CEILING),
            internal_hosts: host_patterns(&cfg.relay_internal_hosts),
            redirectors: host_patterns(&cfg.relay_redirector_hosts),
            denylist,
            mentions: lower(&cfg.relay_mention_allowlist),
            repos: lower(&cfg.relay_github_repos),
        })
    }

    pub fn max_chars(&self) -> usize {
        self.max_chars
    }

    /// The gates that read what the text says, over `text`.
    fn content(&self, text: &str, out: &mut Vec<Finding>) {
        secrets(text, out);
        addresses(text, out);
        hosts(text, &self.internal_hosts, &self.redirectors, out);
        home_paths(text, out);
        pii(text, out);
    }

    /// Run every gate over `text`.
    pub fn check(&self, text: &str) -> Verdict {
        let mut found = Vec::new();
        self.content(text, &mut found);
        hidden(text, &mut found);
        let md = Markdown::scan(text);
        markup(text, &md, &mut found);
        links(text, &md, &mut found);
        mentions(text, &md, &self.mentions, &mut found);
        cross_references(text, &md, &self.repos, &mut found);
        let chars = text.chars().count();
        if chars > self.max_chars {
            found.push(Finding::unplaced(
                "length",
                format!("{chars} characters; the limit is {}", self.max_chars),
            ));
        }
        let mut findings = dedupe(found);

        // The same content gates over the decoded, normalized copy. A finding
        // the text as written already has is not counted twice.
        let norm = normalize(text);
        let mut extra = Vec::new();
        if norm != text {
            let seen: BTreeSet<(&'static str, String)> = findings
                .iter()
                .filter_map(|f| f.span.map(|(s, e)| (f.category, normalize(&text[s..e]))))
                .collect();
            let mut on_norm = Vec::new();
            self.content(&norm, &mut on_norm);
            for f in dedupe(on_norm) {
                let Some((s, e)) = f.span else { continue };
                if seen.contains(&(f.category, norm[s..e].trim().to_string())) {
                    continue;
                }
                let mut f = f;
                f.span = None;
                f.detail = format!("{} (once HTML is decoded and Unicode normalized)", f.detail);
                extra.push(f);
            }
        }
        findings.extend(extra);

        let denied = self
            .denylist
            .iter()
            .filter(|rx| rx.is_match(text) || (norm != text && rx.is_match(&norm)))
            .count();
        for f in &mut findings {
            if denied > 0 {
                // Nothing that could locate or spell a denylisted term.
                f.excerpt = None;
                f.offset = None;
            } else if let Some((s, _)) = f.span {
                f.offset = Some(text[..s].chars().count());
            }
        }
        findings.extend(
            (0..denied).map(|_| Finding::unplaced("denylist", "matches an entry of the private denylist")),
        );
        Verdict { findings }
    }
}

/// Drop a finding wholly inside an earlier finding of the same category.
fn dedupe(mut found: Vec<Finding>) -> Vec<Finding> {
    found.sort_by_key(|f| f.span.map(|(s, e)| (s, usize::MAX - e)).unwrap_or((usize::MAX, 0)));
    let mut kept: Vec<Finding> = Vec::new();
    for f in found {
        let covered = f.span.is_some_and(|(s, e)| {
            kept.iter().any(|k| {
                k.category == f.category && k.span.is_some_and(|(ks, ke)| ks <= s && e <= ke && ke > ks)
            })
        });
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

/// The first occurrence of `needle` in `text` at or after `*from`, moving
/// `*from` past it; else the first occurrence anywhere.
fn locate(text: &str, needle: &str, from: &mut usize) -> Option<(usize, usize)> {
    if needle.is_empty() {
        return None;
    }
    let at =
        text.get(*from..).and_then(|t| t.find(needle)).map(|i| i + *from).or_else(|| text.find(needle))?;
    *from = at + needle.len();
    Some((at, at + needle.len()))
}

// --- characters -----------------------------------------------------------------------------

/// Characters that render blank but are neither whitespace nor
/// default-ignorable.
const BLANK: [char; 3] = ['\u{2800}', '\u{3164}', '\u{FFFC}'];

/// Why a character must not appear in a public message, or `None`. An
/// allowlist: printable ASCII, the ASCII space, tab, line feed and carriage
/// return, and any assigned, visible, non-private character.
fn hidden_kind(c: char) -> Option<&'static str> {
    if matches!(c, ' ' | '\t' | '\n' | '\r') {
        return None;
    }
    if c.is_ascii() {
        return c.is_ascii_control().then_some("control character");
    }
    let gc = CodePointMapData::<GeneralCategory>::new().get(c);
    if gc == GeneralCategory::Control {
        Some("control character")
    } else if CodePointSetData::new::<WhiteSpace>().contains(c)
        || matches!(
            gc,
            GeneralCategory::SpaceSeparator
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
        )
    {
        Some("whitespace other than an ASCII space, tab or line break")
    } else if gc == GeneralCategory::Format
        || CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c)
    {
        Some("invisible character (format, default-ignorable or variation selector)")
    } else if CodePointSetData::new::<NoncharacterCodePoint>().contains(c) {
        Some("Unicode noncharacter")
    } else if gc == GeneralCategory::Unassigned {
        Some("unassigned code point")
    } else if gc == GeneralCategory::PrivateUse || gc == GeneralCategory::Surrogate {
        Some("private-use character")
    } else if BLANK.contains(&c) {
        Some("character that renders blank")
    } else {
        None
    }
}

fn hidden(text: &str, out: &mut Vec<Finding>) {
    for (i, c) in text.char_indices() {
        if let Some(detail) = hidden_kind(c) {
            out.push(
                Finding::new("hidden_unicode", detail, i, i + c.len_utf8())
                    .excerpt(format!("U+{:04X}", c as u32)),
            );
        }
    }
}

/// The text as an approver should read it: printable ASCII, space, tab and
/// line feed as they are, a backslash doubled, everything else `\u{XXXX}`.
pub fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' | '\t' | '\n' => out.push(c),
            c if c.is_ascii_graphic() => out.push(c),
            c => out.push_str(&format!("\\u{{{:X}}}", c as u32)),
        }
    }
    out
}

/// `text` without the bytes `drop` selects, and for each kept byte its
/// index in `text`.
fn remove(text: &str, drop: &[(usize, usize)]) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len());
    let mut last = 0;
    for &(s, e) in drop {
        out.push_str(&text[last..s]);
        map.extend(last..s);
        last = e;
    }
    out.push_str(&text[last..]);
    map.extend(last..text.len());
    (out, map)
}

/// `text` without hidden characters, and for each kept byte its index in `text`.
fn strip_hidden(text: &str) -> (String, Vec<usize>) {
    let drop: Vec<(usize, usize)> = text
        .char_indices()
        .filter(|(_, c)| hidden_kind(*c).is_some())
        .map(|(i, c)| (i, i + c.len_utf8()))
        .collect();
    remove(text, &drop)
}

/// Look-alike letters from other scripts, folded to the ASCII letter they
/// imitate. NFKC already folds full-width and mathematical forms.
fn confusable(c: char) -> Option<char> {
    Some(match c {
        'а' | 'α' => 'a',
        'Ь' | 'Ꮟ' => 'b',
        'с' | 'ϲ' => 'c',
        'ԁ' => 'd',
        'е' | 'ε' => 'e',
        'ɡ' => 'g',
        'һ' => 'h',
        'і' | 'ι' | 'ı' => 'i',
        'ј' => 'j',
        'κ' => 'k',
        'ο' | 'о' | 'σ' => 'o',
        'р' | 'ρ' => 'p',
        'ԛ' => 'q',
        'ѕ' => 's',
        'υ' => 'u',
        'ν' => 'v',
        'ԝ' => 'w',
        'х' | 'χ' => 'x',
        'у' | 'γ' => 'y',
        'А' | 'Α' => 'A',
        'В' | 'Β' => 'B',
        'С' | 'Ϲ' => 'C',
        'Е' | 'Ε' => 'E',
        'Н' | 'Η' => 'H',
        'І' | 'Ι' | 'Ӏ' => 'I',
        'Ј' => 'J',
        'К' | 'Κ' => 'K',
        'М' | 'Μ' => 'M',
        'Ν' => 'N',
        'О' | 'Ο' => 'O',
        'Р' | 'Ρ' => 'P',
        'Ѕ' => 'S',
        'Т' | 'Τ' => 'T',
        'Х' | 'Χ' => 'X',
        'У' | 'Υ' => 'Y',
        'Ζ' => 'Z',
        '。' | '｡' | '․' => '.',
        _ => return None,
    })
}

fn strip_tags(text: &str) -> String {
    static RX: OnceLock<Regex> = OnceLock::new();
    let rx = RX.get_or_init(|| {
        rx(r"(?s)<!--.*?(?:-->|\z)|</?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?/?>|<![A-Za-z\[][^<>]*>|<\?[^<>]*\?>")
    });
    rx.replace_all(text, "").into_owned()
}

/// The copy the content gates run over a second time: entities decoded
/// (twice nested at most), tags and comments removed, hidden characters
/// removed and other whitespace made a space, NFKC, look-alikes folded,
/// whitespace runs collapsed to one space.
pub(crate) fn normalize(text: &str) -> String {
    let mut s = text.to_string();
    for _ in 0..3 {
        let next = strip_tags(&html_escape::decode_html_entities(&strip_tags(&s)));
        if next == s {
            break;
        }
        s = next;
    }
    let visible: String = s
        .chars()
        .filter_map(|c| match hidden_kind(c) {
            None => Some(c),
            Some(_) if c.is_whitespace() || CodePointSetData::new::<WhiteSpace>().contains(c) => Some(' '),
            Some(_) => None,
        })
        .collect();
    let nfkc = ComposingNormalizerBorrowed::new_nfkc().normalize(&visible);
    let mut out = String::with_capacity(nfkc.len());
    let mut space = false;
    for c in nfkc.chars().filter(|c| hidden_kind(*c).is_none() || c.is_whitespace()) {
        if c.is_whitespace() {
            space = true;
            continue;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        out.push(confusable(c).unwrap_or(c));
    }
    out
}

// --- secrets ---------------------------------------------------------------------------

fn extra_secret_shapes() -> &'static [(&'static str, &'static str, Regex)] {
    static SHAPES: OnceLock<Vec<(&'static str, &'static str, Regex)>> = OnceLock::new();
    SHAPES.get_or_init(|| {
        vec![
            ("private_key", "private key block", rx(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")),
            (
                "secret",
                "credential assignment",
                rx(
                    r#"\b[A-Z][A-Z0-9_]*_(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)\s*[=:]\s*["']?(?P<val>[^\s"'`]{8,})"#,
                ),
            ),
            ("secret", "bearer credential", rx(r"(?i)\bbearer\s+(?P<val>[A-Za-z0-9._~+/=-]{20,})")),
        ]
    })
}

/// `api_token = '…'`, `"token": "…"`, `password: …` in any case, quoted or
/// not. The value must look like a credential (letters and digits, or long
/// and mixed), so prose such as `token: required` passes.
fn assignment_shape() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        rx(
            r#"(?i)(?:^|[^A-Za-z0-9_])["']?(?P<name>[A-Za-z0-9_.-]*?(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|credentials?)s?)["']?\s*[:=]\s*["']?(?P<val>[^\s"'`,;]{8,})"#,
        )
    })
}

fn looks_like_credential(v: &str) -> bool {
    let n = v.chars().count();
    let digit = v.chars().any(|c| c.is_ascii_digit());
    let alpha = v.chars().any(|c| c.is_ascii_alphabetic());
    let upper = v.chars().any(|c| c.is_ascii_uppercase());
    let lower = v.chars().any(|c| c.is_ascii_lowercase());
    (digit && alpha) || (n >= 20 && upper && lower) || (n >= 20 && v.contains(['+', '/', '=']))
}

fn placeholder(value: &str) -> bool {
    static RX: OnceLock<Regex> = OnceLock::new();
    let rx = RX.get_or_init(|| {
        rx(r"(?i)^(?:<[^<>\s]+>|\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|[*x.\x{2022}]+|\[REDACTED[A-Z_]*\])$")
    });
    rx.is_match(value.trim_matches(|c| matches!(c, '"' | '\'' | '`')))
}

/// Every credential shape in `text`: `(category, name, start, end, value)`.
fn credential_matches(text: &str) -> Vec<(&'static str, &'static str, usize, usize, String)> {
    let mut out = Vec::new();
    for s in secret_spans(text) {
        let category = if s.name.contains("private key") { "private_key" } else { "secret" };
        out.push((category, s.name, s.start, s.end, s.value));
    }
    for (category, name, shape) in extra_secret_shapes() {
        for caps in shape.captures_iter(text) {
            let Some(whole) = caps.get(0) else { continue };
            let value = caps.name("val").map(|m| m.as_str()).unwrap_or(whole.as_str());
            if *category == "secret" && placeholder(value) {
                continue;
            }
            out.push((category, name, whole.start(), whole.end(), value.to_string()));
        }
    }
    for caps in assignment_shape().captures_iter(text) {
        let (Some(name), Some(val)) = (caps.name("name"), caps.name("val")) else { continue };
        if placeholder(val.as_str()) || !looks_like_credential(val.as_str()) {
            continue;
        }
        out.push(("secret", "credential assignment", name.start(), val.end(), val.as_str().to_string()));
    }
    out
}

fn excerpt_for(category: &str, value: &str) -> String {
    if category == "private_key" { "-----BEGIN …PRIVATE KEY".to_string() } else { mask(value) }
}

/// A base64 or percent-encoded run, decoded, when it decodes to text.
fn decoded_run(run: &str) -> Option<String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let printable = |s: &str| !s.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'));
    if run.contains('%') {
        let bytes = run.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && let Some(b) = run.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 3;
            } else {
                out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
                i += 1;
            }
        }
        return String::from_utf8(out).ok().filter(|s| printable(s));
    }
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(run).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| printable(s))
}

/// Credential shapes, matched on the text with hidden characters removed so
/// a zero-width character inside a token does not hide it; then on that
/// text with line breaks joined, and inside base64 and percent-encoded runs.
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
    for (category, name, s, e, value) in credential_matches(&stripped) {
        let (start, end) = back(s, e);
        out.push(Finding::new(category, name, start, end).excerpt(excerpt_for(category, &value)));
    }

    // A token broken over lines: join them and keep only the matches that
    // span a join (vendor shapes only; they are specific enough).
    static BREAK: OnceLock<Regex> = OnceLock::new();
    let breaks: Vec<(usize, usize)> = BREAK
        .get_or_init(|| rx(r"[ \t]*\r?\n[ \t]*"))
        .find_iter(&stripped)
        .map(|m| (m.start(), m.end()))
        .collect();
    if !breaks.is_empty() {
        let (joined, jmap) = remove(&stripped, &breaks);
        for s in secret_spans(&joined) {
            let (js, je) = (jmap[s.start], jmap[s.end - 1] + 1);
            if je - js == s.end - s.start {
                continue; // no join inside
            }
            let (start, end) = back(js, je);
            out.push(
                Finding::new("secret", format!("{} split across lines", s.name), start, end)
                    .excerpt(mask(&s.value)),
            );
        }
    }

    // Encoded runs.
    static B64: OnceLock<Regex> = OnceLock::new();
    static PCT: OnceLock<Regex> = OnceLock::new();
    let b64 = B64.get_or_init(|| rx(r"[A-Za-z0-9+/_-]{20,}={0,2}"));
    let pct = PCT.get_or_init(|| rx(r"(?:[A-Za-z0-9._~+-]|%[0-9A-Fa-f]{2}){12,}"));
    let runs = b64.find_iter(&stripped).map(|m| ("base64-encoded", m)).chain(
        pct.find_iter(&stripped)
            .filter(|m| m.as_str().matches('%').count() >= 2)
            .map(|m| ("percent-encoded", m)),
    );
    for (how, m) in runs {
        let Some(decoded) = decoded_run(m.as_str()) else { continue };
        if let Some((category, name, _, _, _)) = credential_matches(&decoded).into_iter().next() {
            let (start, end) = back(m.start(), m.end());
            out.push(Finding::new(category, format!("{how} {name}"), start, end).excerpt(mask(m.as_str())));
        }
    }
}

// --- markup -----------------------------------------------------------------------------

/// Stands in for `&` while the Markdown is parsed, so character references
/// survive into the tree undecoded and can be found.
const AMP: char = '\u{E000}';

fn restore(s: &str) -> String {
    s.replace(AMP, "&")
}

/// One link or image.
struct LinkInfo {
    url: String,
    /// The visible text, code spans included.
    text: String,
    image: bool,
}

/// What GitHub's Markdown renderer would make of a text.
struct Markdown {
    /// Raw HTML: tags, comments, declarations, as written.
    html: Vec<String>,
    /// Character references outside code, as written (`&#64;`).
    entities: Vec<String>,
    /// The prose outside code and HTML, entities decoded, one line per block.
    prose: String,
    links: Vec<LinkInfo>,
}

fn md_options() -> Options<'static> {
    let mut o = Options::default();
    o.extension.strikethrough = true;
    o.extension.table = true;
    o.extension.autolink = true;
    o.extension.tasklist = true;
    o.extension.footnotes = true;
    o
}

fn entity_refs(s: &str, out: &mut Vec<String>) {
    static RX: OnceLock<Regex> = OnceLock::new();
    let rx =
        RX.get_or_init(|| rx(r"\x{E000}(?:#[0-9]{1,8}|#[xX][0-9A-Fa-f]{1,7}|[A-Za-z][A-Za-z0-9]{1,31});"));
    for m in rx.find_iter(s) {
        let lit = restore(m.as_str());
        if html_escape::decode_html_entities(&lit) != lit {
            out.push(lit);
        }
    }
}

impl Markdown {
    fn scan(text: &str) -> Self {
        let src = text.replace(AMP, "\u{FFFD}").replace('&', &AMP.to_string());
        let arena = Arena::new();
        let root = parse_document(&arena, &src, &md_options());
        let mut md =
            Markdown { html: Vec::new(), entities: Vec::new(), prose: String::new(), links: Vec::new() };
        for node in root.descendants() {
            let data = node.data.borrow();
            match &data.value {
                NodeValue::Text(t) => {
                    entity_refs(t, &mut md.entities);
                    md.prose.push_str(&html_escape::decode_html_entities(&restore(t)));
                }
                NodeValue::Code(_) => md.prose.push(' '),
                NodeValue::HtmlInline(h) => {
                    md.html.push(restore(h));
                    md.prose.push(' ');
                }
                NodeValue::HtmlBlock(b) => {
                    md.html.push(restore(b.literal.trim_end()));
                    md.prose.push('\n');
                }
                NodeValue::SoftBreak | NodeValue::LineBreak => md.prose.push('\n'),
                NodeValue::Link(l) | NodeValue::Image(l) => {
                    entity_refs(&l.url, &mut md.entities);
                    entity_refs(&l.title, &mut md.entities);
                    let mut visible = String::new();
                    for d in node.descendants().skip(1) {
                        match &d.data.borrow().value {
                            NodeValue::Text(t) => visible.push_str(&restore(t)),
                            NodeValue::Code(c) => visible.push_str(&restore(&c.literal)),
                            _ => {}
                        }
                    }
                    md.links.push(LinkInfo {
                        url: restore(&l.url),
                        text: html_escape::decode_html_entities(&visible).trim().to_string(),
                        image: matches!(data.value, NodeValue::Image(_)),
                    });
                }
                v if v.block() => md.prose.push('\n'),
                _ => {}
            }
        }
        md
    }
}

fn markup(text: &str, md: &Markdown, out: &mut Vec<Finding>) {
    let mut from = 0;
    for h in &md.html {
        let detail = if h.starts_with("<!--") {
            "HTML comment (GitHub hides it from readers)"
        } else {
            "raw HTML (GitHub renders or removes it; write Markdown, or put code in backticks)"
        };
        let f = match locate(text, h, &mut from) {
            Some((s, e)) => Finding::new("markup", detail, s, e),
            None => Finding::unplaced("markup", detail),
        };
        out.push(f.excerpt(short(h, 4)));
    }
    let mut from = 0;
    for e in &md.entities {
        let detail = "HTML character reference (GitHub decodes it; write the character itself)";
        let f = match locate(text, e, &mut from) {
            Some((s, end)) => Finding::new("markup", detail, s, end),
            None => Finding::unplaced("markup", detail),
        };
        out.push(f.excerpt(short(e, 2)));
    }
}

/// The host a link opens, as the approval shows it.
fn link_host(url: &str) -> String {
    match Url::parse(url) {
        Ok(u) => match u.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => format!("{}:", u.scheme()),
        },
        Err(_) => "(relative link)".into(),
    }
}

/// Every host the text's links and images open, sorted and unique.
pub fn link_hosts(text: &str) -> Vec<String> {
    let set: BTreeSet<String> = Markdown::scan(text).links.iter().map(|l| link_host(&l.url)).collect();
    set.into_iter().collect()
}

/// The URL a link's visible text names, when it reads as one.
fn text_url(s: &str) -> Option<Url> {
    static DOMAIN: OnceLock<Regex> = OnceLock::new();
    let domain = DOMAIN.get_or_init(|| rx(r"(?i)^(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#]\S*)?$"));
    let s = s.trim();
    if s.contains(char::is_whitespace) || s.contains('@') && !s.contains("://") {
        return None;
    }
    if s.contains("://") {
        Url::parse(s).ok()
    } else if domain.is_match(s) {
        Url::parse(&format!("https://{s}")).ok()
    } else {
        None
    }
}

fn links(text: &str, md: &Markdown, out: &mut Vec<Finding>) {
    let mut from = 0;
    for l in md.links.iter().filter(|l| !l.image) {
        let Some(shown) = text_url(&l.text) else { continue };
        let opens = Url::parse(&l.url).ok();
        let same = opens.as_ref().is_some_and(|o| {
            let host = |u: &Url| u.host_str().map(|h| h.trim_start_matches("www.").to_ascii_lowercase());
            let path = |u: &Url| u.path().trim_end_matches('/').to_string();
            host(o) == host(&shown)
                && (shown.path().trim_matches('/').is_empty() && shown.query().is_none()
                    || (path(o) == path(&shown) && o.query() == shown.query()))
        });
        if !same {
            let detail = "link text shows one URL but the link opens another";
            let f = match locate(text, &l.url, &mut from) {
                Some((s, e)) => Finding::new("link", detail, s, e),
                None => Finding::unplaced("link", detail),
            };
            out.push(f.excerpt(short(&l.url, 8)));
        }
    }
}

// --- mentions and cross-references ------------------------------------------------------

fn mentions(text: &str, md: &Markdown, allowed: &BTreeSet<String>, out: &mut Vec<Finding>) {
    static RX: OnceLock<Regex> = OnceLock::new();
    let rx = RX.get_or_init(|| {
        rx(r"@(?P<name>[A-Za-z0-9][A-Za-z0-9-]{0,38})(?:/(?P<team>[A-Za-z0-9][A-Za-z0-9_.-]*))?")
    });
    let mut from = 0;
    for caps in rx.captures_iter(&md.prose) {
        let (Some(m), Some(name)) = (caps.get(0), caps.name("name")) else { continue };
        // `a@b` is an address and `x/@y` a path, not a mention.
        if prev_char(&md.prose, m.start())
            .is_some_and(|c| word(c) || matches!(c, '.' | '@' | '/' | '-' | '`'))
        {
            continue;
        }
        let handle = match caps.name("team") {
            Some(t) => format!("{}/{}", name.as_str(), t.as_str().trim_end_matches('.')),
            None => name.as_str().to_string(),
        };
        if allowed.contains(&handle.to_ascii_lowercase()) {
            continue;
        }
        let needle = format!("@{handle}");
        let detail = "@-mention notifies a GitHub account or team; only those in relay_mention_allowlist may be mentioned";
        let f = match locate(text, &needle, &mut from) {
            Some((s, e)) => Finding::new("mention", detail, s, e),
            None => Finding::unplaced("mention", detail),
        };
        out.push(f.excerpt(short(&needle, 3)));
    }
}

fn cross_references(text: &str, md: &Markdown, repos: &BTreeSet<String>, out: &mut Vec<Finding>) {
    static SHORT: OnceLock<Regex> = OnceLock::new();
    static URL_REF: OnceLock<Regex> = OnceLock::new();
    let short_ref = SHORT.get_or_init(|| {
        rx(r"(?P<slug>(?P<owner>[A-Za-z0-9][A-Za-z0-9-]{0,38})/(?P<repo>[A-Za-z0-9_.-]{1,100}))#[0-9]+\b")
    });
    let url_ref = URL_REF.get_or_init(|| {
        rx(r"(?i)\bhttps?://(?:www\.)?github\.com/(?P<slug>[A-Za-z0-9-]+/[A-Za-z0-9_.-]+?)/(?:issues|pull|discussions)/[0-9]+")
    });
    let mut haystacks = vec![md.prose.clone()];
    haystacks.extend(md.links.iter().map(|l| l.url.clone()));
    let mut from = 0;
    for hay in &haystacks {
        let refs = short_ref
            .captures_iter(hay)
            .filter(|c| {
                c.get(0).is_some_and(|m| {
                    !prev_char(hay, m.start()).is_some_and(|p| word(p) || matches!(p, '.' | '/' | '-' | '@'))
                })
            })
            .chain(url_ref.captures_iter(hay));
        for caps in refs {
            let (Some(m), Some(slug)) = (caps.get(0), caps.name("slug")) else { continue };
            if repos.contains(&slug.as_str().to_ascii_lowercase()) {
                continue;
            }
            let detail = "cross-reference to an issue or pull request in a repository not in relay_github_repos \
                          (GitHub links it back from there)";
            let f = match locate(text, m.as_str(), &mut from) {
                Some((s, e)) => Finding::new("cross_reference", detail, s, e),
                None => Finding::unplaced("cross_reference", detail),
            };
            out.push(f.excerpt(short(m.as_str(), 4)));
        }
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

/// Why a URL host must not be published, judged on the address a browser
/// would resolve it to (`10.1`, `0177.0.0.1` and `0x7f.1` included).
fn host_kind(host: &str) -> Option<&'static str> {
    match Url::parse(&format!("http://{host}/")).ok()?.host()? {
        Host::Ipv4(ip) => v4_kind(ip),
        Host::Ipv6(ip) => v6_kind(ip),
        Host::Domain(_) => None,
    }
}

fn addresses(text: &str, out: &mut Vec<Finding>) {
    static V4: OnceLock<Regex> = OnceLock::new();
    static V6: OnceLock<Regex> = OnceLock::new();
    static URL_RX: OnceLock<Regex> = OnceLock::new();
    static LOOSE: OnceLock<Regex> = OnceLock::new();
    let v4 = V4.get_or_init(|| rx(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}"));
    let v6 = V6.get_or_init(|| rx(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f.]{0,15}){2,8}"));
    let url_rx = URL_RX.get_or_init(|| rx(r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>"'`)\]]+"#));
    let loose = LOOSE.get_or_init(|| {
        rx(r"(?i)(?P<host>(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3})(?P<port>:[0-9]{1,5})?")
    });
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
    // URL hosts, parsed as a browser parses them.
    for m in url_rx.find_iter(text) {
        let Ok(u) = Url::parse(m.as_str()) else { continue };
        let kind = match u.host() {
            Some(Host::Ipv4(ip)) => v4_kind(ip),
            Some(Host::Ipv6(ip)) => v6_kind(ip),
            _ => None,
        };
        if let Some(kind) = kind {
            out.push(
                Finding::new("private_address", format!("{kind} (URL host)"), m.start(), m.end())
                    .excerpt(short(m.as_str(), 8)),
            );
        }
    }
    // Short and non-decimal forms outside URLs: `127.1`, `0177.0.0.1`,
    // `0x7f.1`, or any numeric host with a port (`10.1:8080`). Plain dotted
    // quads are judged above; other short dotted numbers are versions.
    for caps in loose.captures_iter(text) {
        let (Some(m), Some(host)) = (caps.get(0), caps.name("host")) else { continue };
        if !starts_token(text, m.start(), &['.', ':', '/', '-']) || !ends_token(text, m.end(), &[':', '-']) {
            continue;
        }
        let parts: Vec<&str> = host.as_str().split('.').collect();
        let odd = parts.iter().any(|p| p.len() > 1 && (p.starts_with('0')));
        let port = caps.name("port").is_some();
        let eligible = odd || port || (matches!(parts.len(), 2 | 3) && parts[0] == "127");
        if !eligible || (parts.len() == 4 && !odd) {
            continue;
        }
        if let Some(kind) = host_kind(host.as_str()) {
            out.push(
                Finding::new(
                    "private_address",
                    format!("{kind} (short or non-decimal form)"),
                    m.start(),
                    m.end(),
                )
                .excerpt(short(m.as_str(), 3)),
            );
        }
    }
}

// --- host names --------------------------------------------------------------------------------

fn hosts(text: &str, configured: &[Regex], redirectors: &[Regex], out: &mut Vec<Finding>) {
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
        // A numeric single label (`http://2130706433/`) is an address, judged
        // by the address gate.
        if h.as_str().eq_ignore_ascii_case("localhost") || h.as_str().chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if h.as_str().to_ascii_lowercase().starts_with("0x") && host_kind(h.as_str()).is_some() {
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
    // A subdomain of a shortener is still the shortener, so a leading dot
    // does not end the match.
    for rx in redirectors {
        for m in rx.find_iter(text) {
            if starts_token(text, m.start(), &['-']) && ends_token(text, m.end(), &['-']) {
                out.push(
                    Finding::new(
                        "redirector",
                        "link shortener or redirector (relay_redirector_hosts): the approver cannot see where it leads",
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
    fn the_character_allowlist() {
        for c in ['a', ' ', '\n', '\t', '\r', 'é', '日', '🚀', '\u{0301}', 'Ω'] {
            assert_eq!(hidden_kind(c), None, "U+{:04X}", c as u32);
        }
        for c in [
            '\u{034F}', '\u{180B}', '\u{180E}', '\u{180F}', '\u{2800}', '\u{2000}', '\u{200A}', '\u{00A0}',
            '\u{E000}', '\u{FFF0}', '\u{FDD0}', '\u{3164}', '\u{115F}', '\u{FFA0}', '\u{0378}', '\u{7F}',
        ] {
            assert!(hidden_kind(c).is_some(), "U+{:04X} must be refused", c as u32);
        }
    }

    #[test]
    fn the_escaped_view_shows_every_non_ascii_character() {
        assert_eq!(escaped("a\u{200B}b é\\n\r"), "a\\u{200B}b \\u{E9}\\\\n\\u{D}");
        assert_eq!(escaped("plain text\nline two"), "plain text\nline two");
    }

    #[test]
    fn normalization_decodes_strips_and_folds() {
        assert_eq!(normalize("10&#46;0&#46;0&#46;1"), "10.0.0.1");
        assert_eq!(normalize("ab<b></b>cd<!-- x -->ef"), "abcdef");
        assert_eq!(normalize("&amp;#64;"), "@");
        assert_eq!(normalize("ｆａｌｃｏｎ"), "falcon");
        assert_eq!(normalize("fаlcоn"), "falcon", "Cyrillic a and o");
        assert_eq!(normalize("a\u{00A0}\u{200B}b \n\t c"), "a b c");
    }

    #[test]
    fn short_and_non_decimal_addresses_resolve() {
        assert_eq!(host_kind("10.1"), Some("private network address"));
        assert_eq!(host_kind("127.1"), Some("loopback address"));
        assert_eq!(host_kind("0177.0.0.1"), Some("loopback address"));
        assert_eq!(host_kind("0x7f.1"), Some("loopback address"));
        assert_eq!(host_kind("2130706433"), Some("loopback address"));
        assert_eq!(host_kind("8.8.8.8"), None);
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
