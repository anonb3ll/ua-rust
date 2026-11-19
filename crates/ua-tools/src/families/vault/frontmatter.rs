//! YAML front matter: the `locked: true` verdict and note metadata.
//!
//! The lock verdict reads only a note's head and fails closed: a note is
//! locked when a column-0 `locked:` line or the parsed YAML mapping gives the
//! `locked` key any value but `false`/`no`/`off`/`0`, and also when the
//! front matter cannot be parsed or bounded but mentions a `locked` key. A
//! UTF-8 BOM, CRLF line endings, quoted keys and inline comments are read.

use regex::Regex;
use serde_json::{Map, Value};
use std::sync::LazyLock;

/// YAML 1.1 falsy scalars; any other `locked` value counts as locked.
const LOCK_FALSE: &[&str] = &["false", "no", "off", "0"];

static LOCKED_VALUE_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?im)^['"]?locked['"]?[ \t]*:[ \t]*(.*)$"#).expect("static regex"));
static LOCKED_KEY_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?im)^[ \t]*['"]?locked['"]?[ \t]*:"#).expect("static regex"));

/// Normalized lines of a note head: BOM dropped, CRLF and CR read as LF.
fn head_lines(head: &[u8]) -> Vec<String> {
    let body = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    let text = String::from_utf8_lossy(body).replace("\r\n", "\n").replace('\r', "\n");
    text.split('\n').map(str::to_string).collect()
}

/// Lock verdict from the first bytes of a note. `truncated` says the note
/// continues past `head`.
pub fn head_is_locked(head: &[u8], truncated: bool) -> bool {
    let lines = head_lines(head);
    if lines.first().map(|l| l.trim_end()) != Some("---") {
        return false;
    }
    let end = (1..lines.len()).find(|&i| {
        let l = lines[i].trim_end();
        // The last line of a truncated head may be cut mid-line.
        (l == "---" || l == "...") && (i + 1 < lines.len() || !truncated)
    });
    let Some(end) = end else {
        // No closing delimiter in the head: the block may continue past it.
        let region = if truncated {
            lines[1..].join("\n")
        } else {
            lines[1..].iter().take_while(|l| !l.trim().is_empty()).cloned().collect::<Vec<_>>().join("\n")
        };
        return truncated || LOCKED_KEY_LINE.is_match(&region);
    };
    let block = lines[1..end].join("\n");
    if line_scan_locked(&block) {
        return true;
    }
    match parse_yaml(&block) {
        Some(Value::Object(map)) => {
            map.iter().any(|(k, v)| k.trim().eq_ignore_ascii_case("locked") && value_locks(v))
        }
        Some(Value::Null) => false,
        // Not a mapping, or unparseable: fail closed only if it names `locked`.
        _ => LOCKED_KEY_LINE.is_match(&block),
    }
}

fn line_scan_locked(block: &str) -> bool {
    LOCKED_VALUE_LINE.captures_iter(block).any(|c| {
        let raw = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let value = match raw.find(" #").or_else(|| raw.find("\t#")) {
            Some(i) => &raw[..i],
            None => raw,
        };
        let value = value.trim().trim_matches(|ch| ch == '\'' || ch == '"').trim().to_lowercase();
        !LOCK_FALSE.contains(&value.as_str())
    })
}

fn value_locks(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !LOCK_FALSE.contains(&s.trim().to_lowercase().as_str()),
        // Null, a list or a mapping: unclear, so locked.
        _ => true,
    }
}

/// Parse a YAML block with serde-saphyr. `None` when it is not valid YAML.
pub fn parse_yaml(block: &str) -> Option<Value> {
    if block.trim().is_empty() {
        return Some(Value::Null);
    }
    serde_saphyr::from_str::<Value>(block).ok()
}

/// Split a note into its front-matter block (without delimiters) and body.
/// Only a leading `---` … `---` block counts, as in Obsidian.
pub fn split(text: &str) -> (Option<&str>, &str) {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Some(rest) = t.strip_prefix("---\n").or_else(|| t.strip_prefix("---\r\n")) else {
        return (None, text);
    };
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        if line.trim_end() == "---" {
            let body = &rest[offset + line.len()..];
            return (Some(&rest[..offset]), body);
        }
        offset += line.len();
    }
    (None, text)
}

/// The front matter of a note as a JSON object (empty when absent or invalid).
pub fn metadata(text: &str) -> Map<String, Value> {
    match split(text).0.and_then(parse_yaml) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

/// A string or list-of-strings front-matter field as a list.
pub fn string_list(meta: &Map<String, Value>, key: &str) -> Vec<String> {
    let mut out: Vec<String> = match meta.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => vec![s.trim().to_string()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s.trim().to_string()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    };
    out.sort();
    out.dedup();
    out
}

/// A scalar front-matter field as lowercase text.
pub fn scalar_lower(meta: &Map<String, Value>, key: &str) -> Option<String> {
    match meta.get(key)? {
        Value::String(s) => Some(s.trim().to_lowercase()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}
