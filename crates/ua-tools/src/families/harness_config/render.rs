//! Bundle validation and per-harness rendering, byte-compatible with the
//! Python hub.
//!
//! A Python node renders the served bundle itself and compares each surface
//! with the hub's by SHA-256, and the hub refuses a drift report whose
//! `desired_hash` is not its own render. So for every surface this module
//! must produce exactly the bytes the Python renderer produces for the same
//! bundle: the same rules fallbacks and placeholder text, the same TOML lines
//! for the codex surface, and `json.dumps(indent=2, sort_keys=True)` (ASCII
//! escapes included) for the JSON surfaces. Golden fixtures rendered by the
//! Python module (`scripts/harness_config_fixtures.py`) pin this in
//! `crates/ua-tools/tests/harness_config.rs`.
//!
//! Validation follows the Python hub too (`normalize_bundle`): the same
//! limits, the same accepted spellings (`serverUrl`, `auth_type`, `content`)
//! and the same refusal of bearer or token auth and embedded secrets in MCP
//! entries.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};

pub const MAX_BUNDLE_BYTES: usize = 512_000;
pub const MAX_FILE_BYTES: usize = 256_000;
pub const MAX_DIFF_CHARS: usize = 80_000;
pub const MAX_PROPOSALS_PER_REPORT: usize = 32;
pub const MAX_SKILLS: usize = 64;
pub const MAX_MCP_SERVERS: usize = 32;

/// The surfaces a bundle renders when it declares none: name, relative path
/// under the node's harness-config root, kind.
pub const DEFAULT_SURFACES: [(&str, &str, &str); 5] = [
    ("claude", "CLAUDE.md", "rules"),
    ("agents", "AGENTS.md", "rules"),
    ("cursor", ".cursorrules", "rules"),
    ("codex", "codex/config.toml", "mcp"),
    ("opencode", "opencode/opencode.json", "mcp"),
];

/// Surfaces that always render rules text, whatever kind they declare.
const RULES_SURFACES: [&str; 3] = ["claude", "agents", "cursor"];

const OK_MCP_AUTH: [&str; 3] = ["none", "oauth", "oauth2"];
const FORBIDDEN_MCP_AUTH: [&str; 5] = ["bearer", "token", "apikey", "api_key", "header"];
const SECRET_KEYS: [&str; 6] = ["token", "bearer", "authorization", "api_key", "apiKey", "headers"];

struct Rx {
    surface: Regex,
    version: Regex,
    path: Regex,
    skill: Regex,
}

fn rx() -> &'static Rx {
    static RX: OnceLock<Rx> = OnceLock::new();
    RX.get_or_init(|| {
        let c = |p: &str| Regex::new(p).expect("harness config pattern compiles");
        Rx {
            surface: c(r"^[a-z][a-z0-9_-]{0,31}$"),
            version: c(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
            path: c(r"^[A-Za-z0-9._/@+-][A-Za-z0-9._/@+-]{0,255}$"),
            skill: c(r"^[a-z0-9][a-z0-9-]{0,63}$"),
        }
    })
}

/// A surface name: a lowercase letter, then up to 31 of `a-z 0-9 _ -`.
pub fn valid_surface(s: &str) -> bool {
    rx().surface.is_match(s)
}

// --- the bundle -------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Skill {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServer {
    pub name: String,
    pub url: String,
    pub auth: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Surface {
    pub path: String,
    #[serde(default = "rules_kind")]
    pub kind: String,
}

fn rules_kind() -> String {
    "rules".into()
}

/// A validated bundle, in the Python hub's stored shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    pub version: String,
    #[serde(default)]
    pub rules: BTreeMap<String, String>,
    #[serde(default)]
    pub skills: Vec<Skill>,
    #[serde(default)]
    pub mcp_servers: Vec<McpServer>,
    #[serde(default)]
    pub surfaces: BTreeMap<String, Surface>,
}

fn default_surfaces() -> BTreeMap<String, Surface> {
    DEFAULT_SURFACES
        .iter()
        .map(|(n, p, k)| (n.to_string(), Surface { path: p.to_string(), kind: k.to_string() }))
        .collect()
}

impl Bundle {
    /// The bundle as JSON (what a node is served).
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }

    /// What the Python hub stores in `bundle_json`:
    /// `json.dumps(bundle, sort_keys=True, separators=(",", ":"))`.
    pub fn to_json(&self) -> String {
        py_dumps(&self.to_value(), None)
    }

    /// SHA-256 of [`Bundle::to_json`]: binds a publish approval to the content.
    pub fn sha256(&self) -> String {
        content_hash(&self.to_json())
    }

    /// The declared surfaces, or the defaults when there are none.
    pub fn surfaces(&self) -> BTreeMap<String, Surface> {
        if self.surfaces.is_empty() { default_surfaces() } else { self.surfaces.clone() }
    }
}

/// Hex SHA-256 of the UTF-8 text.
pub fn content_hash(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

// --- Python value semantics ---------------------------------------------------------

/// Python truthiness of a JSON value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Python `a or b or c`: the first truthy value, else the last.
fn py_or<'a>(values: &[Option<&'a Value>]) -> Option<&'a Value> {
    values.iter().copied().find(|v| truthy(*v)).unwrap_or_else(|| values.last().copied().flatten())
}

/// `str.isspace`: Rust's whitespace plus the four ASCII separators.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// `str.strip()`.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}

/// The Python hub's `_bounded_str`: `None` for a missing, null or blank
/// value; a refusal for a non-string or one over `limit` characters.
fn bounded_str(v: Option<&Value>, limit: usize) -> UaResult<Option<String>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let t = py_strip(s);
            if t.is_empty() {
                Ok(None)
            } else if t.chars().count() > limit {
                Err(UaError::invalid(format!("string exceeds {limit} characters")))
            } else {
                Ok(Some(t.to_string()))
            }
        }
        Some(_) => Err(UaError::invalid("expected a string")),
    }
}

/// Python `repr` of a short string, for refusal messages.
fn repr(s: &str) -> String {
    if s.contains('\'') && !s.contains('"') {
        format!("\"{s}\"")
    } else {
        format!("'{}'", s.replace('\'', "\\'"))
    }
}

// --- validation -------------------------------------------------------------------

fn validate_mcp_servers(v: Option<&Value>) -> UaResult<Vec<McpServer>> {
    let list = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(_) => return Err(UaError::invalid("mcp_servers must be a list")),
    };
    if list.len() > MAX_MCP_SERVERS {
        return Err(UaError::invalid(format!("at most {MAX_MCP_SERVERS} mcp_servers")));
    }
    let mut out = Vec::new();
    for raw in list {
        let Some(raw) = raw.as_object() else {
            return Err(UaError::invalid("each mcp_server must be an object"));
        };
        let Some(name) = bounded_str(raw.get("name"), 64)? else {
            return Err(UaError::invalid("mcp_server.name is required"));
        };
        let url = bounded_str(py_or(&[raw.get("url"), raw.get("serverUrl"), raw.get("server_url")]), 500)?;
        let Some(url) = url else {
            return Err(UaError::invalid(format!("mcp_server {} needs a url", repr(&name))));
        };
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(UaError::invalid(format!("mcp_server {} url must be http(s)", repr(&name))));
        }
        let auth_raw = py_or(&[raw.get("auth"), raw.get("auth_type")]);
        let auth = match auth_raw {
            Some(v) if truthy(Some(v)) => match v {
                Value::String(s) => py_strip(s).to_lowercase(),
                other => other.to_string().to_lowercase(),
            },
            _ => "oauth".to_string(),
        };
        if FORBIDDEN_MCP_AUTH.contains(&auth.as_str()) || auth.contains("bearer") {
            return Err(UaError::invalid(format!(
                "mcp_server {} must use OAuth (or none), not bearer/token auth",
                repr(&name)
            )));
        }
        if !OK_MCP_AUTH.contains(&auth.as_str()) {
            return Err(UaError::invalid(format!(
                "mcp_server {} auth must be one of ['none', 'oauth', 'oauth2']",
                repr(&name)
            )));
        }
        for key in SECRET_KEYS {
            if truthy(raw.get(key)) {
                return Err(UaError::invalid(format!(
                    "mcp_server {} must not embed {}; use OAuth on the hub",
                    repr(&name),
                    repr(key)
                )));
            }
        }
        let transport = if truthy(raw.get("transport")) {
            Some(bounded_str(raw.get("transport"), 32)?.unwrap_or_else(|| "http".into()))
        } else {
            None
        };
        out.push(McpServer { name, url, auth, transport });
    }
    Ok(out)
}

fn validate_skills(v: Option<&Value>) -> UaResult<Vec<Skill>> {
    let list = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(_) => return Err(UaError::invalid("skills must be a list")),
    };
    if list.len() > MAX_SKILLS {
        return Err(UaError::invalid(format!("at most {MAX_SKILLS} skills")));
    }
    let mut out = Vec::new();
    for raw in list {
        let Some(raw) = raw.as_object() else {
            return Err(UaError::invalid("each skill must be an object"));
        };
        let name = bounded_str(raw.get("name"), 64)?;
        let Some(name) = name.filter(|n| rx().skill.is_match(n)) else {
            return Err(UaError::invalid("skill.name must be kebab-case \u{2264}64 chars"));
        };
        let description = bounded_str(raw.get("description"), 1024)?.unwrap_or_default();
        let body = match py_or(&[raw.get("body"), raw.get("content")]) {
            Some(v) if truthy(Some(v)) => match v {
                Value::String(s) => s.clone(),
                _ => return Err(UaError::invalid(format!("skill {} body must be a string", repr(&name)))),
            },
            _ => String::new(),
        };
        if body.len() > MAX_FILE_BYTES {
            return Err(UaError::invalid(format!("skill {} body exceeds size limit", repr(&name))));
        }
        out.push(Skill { name, description, body });
    }
    Ok(out)
}

fn validate_rules(v: Option<&Value>) -> UaResult<BTreeMap<String, String>> {
    let map = match v {
        None | Some(Value::Null) => return Ok(BTreeMap::new()),
        Some(Value::Object(o)) => o,
        Some(_) => return Err(UaError::invalid("rules must be an object")),
    };
    let mut out = BTreeMap::new();
    for (key, value) in map {
        let surface = py_strip(key).to_lowercase();
        if !valid_surface(&surface) {
            return Err(UaError::invalid(format!("invalid rules surface {}", repr(key))));
        }
        let Some(text) = value.as_str() else {
            return Err(UaError::invalid(format!("rules.{surface} must be a string")));
        };
        if text.len() > MAX_FILE_BYTES {
            return Err(UaError::invalid(format!("rules.{surface} exceeds size limit")));
        }
        out.insert(surface, text.to_string());
    }
    Ok(out)
}

fn validate_surfaces(v: Option<&Value>) -> UaResult<BTreeMap<String, Surface>> {
    let map = match v {
        None | Some(Value::Null) => return Ok(default_surfaces()),
        Some(Value::Object(o)) => o,
        Some(_) => return Err(UaError::invalid("surfaces must be an object")),
    };
    let mut out = BTreeMap::new();
    for (key, raw) in map {
        let surface = py_strip(key).to_lowercase();
        if !valid_surface(&surface) {
            return Err(UaError::invalid(format!("invalid surface {}", repr(key))));
        }
        let Some(raw) = raw.as_object() else {
            return Err(UaError::invalid(format!("surfaces.{surface} must be an object")));
        };
        let path = bounded_str(raw.get("path"), 256)?;
        let Some(path) = path.filter(|p| rx().path.is_match(p) && !p.split('/').any(|s| s == "..")) else {
            return Err(UaError::invalid(format!("surfaces.{surface}.path is invalid")));
        };
        let kind = bounded_str(raw.get("kind"), 32)?.unwrap_or_else(rules_kind);
        out.insert(surface, Surface { path, kind });
    }
    Ok(if out.is_empty() { default_surfaces() } else { out })
}

/// Validate and canonicalize a publish payload (the Python hub's
/// `normalize_bundle`). Every refusal is an invalid argument.
pub fn normalize(raw: &Value) -> UaResult<Bundle> {
    let Some(raw) = raw.as_object() else {
        return Err(UaError::invalid("bundle must be a JSON object"));
    };
    let version = bounded_str(raw.get("version"), 64)?;
    let Some(version) = version.filter(|v| rx().version.is_match(v)) else {
        return Err(UaError::invalid("version is required (alphanumeric, ._- , \u{2264}64)"));
    };
    let bundle = Bundle {
        version,
        rules: validate_rules(raw.get("rules"))?,
        skills: validate_skills(raw.get("skills"))?,
        mcp_servers: validate_mcp_servers(raw.get("mcp_servers"))?,
        surfaces: validate_surfaces(raw.get("surfaces"))?,
    };
    if bundle.to_json().len() > MAX_BUNDLE_BYTES {
        return Err(UaError::invalid("bundle exceeds size limit"));
    }
    Ok(bundle)
}

// --- rendering --------------------------------------------------------------------

/// One rendered surface.
#[derive(Debug, Clone, PartialEq)]
pub struct Rendered {
    pub path: String,
    pub kind: String,
    pub content: String,
    pub hash: String,
}

fn non_empty(s: Option<&String>) -> Option<&String> {
    s.filter(|s| !s.is_empty())
}

/// The desired on-disk text of one surface (the Python hub's
/// `render_surface`). A surface the bundle does not declare renders with its
/// default kind when it is a default surface; any other is refused.
pub fn render_surface(bundle: &Bundle, surface: &str) -> UaResult<String> {
    let surface = py_strip(surface).to_lowercase();
    let declared = bundle.surfaces();
    let kind = match declared.get(&surface) {
        Some(meta) => meta.kind.clone(),
        None => match DEFAULT_SURFACES.iter().find(|(n, _, _)| *n == surface) {
            Some((_, _, k)) => k.to_string(),
            None => return Err(UaError::invalid(format!("unknown surface {}", repr(&surface)))),
        },
    };
    let kind = if kind.is_empty() { rules_kind() } else { kind };
    let rules = &bundle.rules;

    if kind == "rules" || RULES_SURFACES.contains(&surface.as_str()) {
        let mut text = rules.get(&surface);
        if text.is_none() && surface == "agents" {
            text = rules.get("claude");
        }
        let mut text = match text {
            Some(t) => t.clone(),
            None => format!(
                "# Hub-managed {surface} rules\n# bundle {}\n# (empty \u{2014} publish rules.<surface> to fill)\n",
                bundle.version
            ),
        };
        if !text.ends_with('\n') {
            text.push('\n');
        }
        return Ok(text);
    }

    if surface == "codex" {
        let mut lines: Vec<String> = vec![
            format!("# Generated by unified-agent harness_config bundle {}", bundle.version),
            "# Do not hand-edit; approve a new proposal from Control Center.".into(),
            String::new(),
            "[mcp]".into(),
        ];
        for s in &bundle.mcp_servers {
            lines.push(format!("[mcp.servers.{}]", s.name));
            lines.push(format!("url = \"{}\"", s.url));
            lines.push(format!("auth = \"{}\"", s.auth));
            lines.push(String::new());
        }
        if !bundle.skills.is_empty() {
            lines.push("[skills]".into());
            for s in &bundle.skills {
                lines.push(format!("[skills.{}]", s.name));
                lines.push(format!("description = \"{}\"", s.description.replace('"', "\\\"")));
                lines.push(String::new());
            }
        }
        if let Some(text) = non_empty(rules.get("codex")).or_else(|| non_empty(rules.get("agents"))) {
            lines.push("[ua.rules]".into());
            lines.push("text = \"\"\"".into());
            lines.push(text.trim_end_matches('\n').to_string());
            lines.push("\"\"\"".into());
            lines.push(String::new());
        }
        return Ok(lines.join("\n"));
    }

    // opencode and any other JSON surface.
    let mut mcp = Map::new();
    for s in &bundle.mcp_servers {
        let kind = s.transport.clone().filter(|t| !t.is_empty()).unwrap_or_else(|| "remote".into());
        mcp.insert(s.name.clone(), json!({ "url": s.url, "auth": s.auth, "type": kind }));
    }
    let skills: Vec<Value> = bundle
        .skills
        .iter()
        .map(|s| json!({ "name": s.name, "description": s.description, "body": s.body }))
        .collect();
    let mut payload = json!({ "ua_bundle_version": bundle.version, "mcp": mcp, "skills": skills });
    if let Some(text) = non_empty(rules.get(&surface)).or_else(|| non_empty(rules.get("agents"))) {
        payload["rules"] = json!(text);
    }
    let mut out = py_dumps(&payload, Some(2));
    out.push('\n');
    Ok(out)
}

/// Every declared surface, rendered (the Python hub's `render_all`).
pub fn render_all(bundle: &Bundle) -> UaResult<BTreeMap<String, Rendered>> {
    let mut out = BTreeMap::new();
    for (name, meta) in bundle.surfaces() {
        let content = render_surface(bundle, &name)?;
        let kind = if meta.kind.is_empty() { rules_kind() } else { meta.kind };
        out.insert(name, Rendered { path: meta.path, kind, hash: content_hash(&content), content });
    }
    Ok(out)
}

// --- diffs ------------------------------------------------------------------------

/// `str.splitlines(keepends=True)`.
fn py_splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let end = match c {
            '\r' => match it.peek() {
                Some((j, '\n')) => {
                    let j = *j;
                    it.next();
                    j + 1
                }
                _ => i + 1,
            },
            '\n' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}' => {
                i + c.len_utf8()
            }
            _ => continue,
        };
        out.push(&s[start..end]);
        start = end;
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Clip a diff to [`MAX_DIFF_CHARS`] characters the way the Python hub does.
pub fn clip_diff(diff: String) -> String {
    if diff.chars().count() > MAX_DIFF_CHARS {
        let mut out: String = diff.chars().take(MAX_DIFF_CHARS - 40).collect();
        out.push_str("\n# \u{2026} diff truncated \u{2026}\n");
        out
    } else {
        diff
    }
}

/// The unified diff from an absent file to `desired` (the Python hub's
/// `make_diff(path, None, desired)`).
pub fn diff_from_empty(path: &str, desired: &str) -> String {
    let lines = py_splitlines(desired);
    if lines.is_empty() {
        return String::new();
    }
    let range = if lines.len() == 1 { "1".to_string() } else { format!("1,{}", lines.len()) };
    let mut out = format!("--- a/{path}\n+++ b/{path}\n@@ -0,0 +{range} @@\n");
    for l in lines {
        out.push('+');
        out.push_str(l);
    }
    clip_diff(out)
}

// --- json.dumps ---------------------------------------------------------------------

/// Python's `json.dumps(v, sort_keys=True, ensure_ascii=True)`, with
/// `indent=n` (separators `,` and `: `) or compact (`,` and `:`).
pub fn py_dumps(v: &Value, indent: Option<usize>) -> String {
    let mut out = String::new();
    dump(v, indent, 0, &mut out);
    out
}

fn dump(v: &Value, indent: Option<usize>, level: usize, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => dump_str(s, out),
        Value::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(indent, level + 1, out);
                dump(item, indent, level + 1, out);
            }
            newline(indent, level, out);
            out.push(']');
        }
        Value::Object(o) => {
            if o.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(indent, level + 1, out);
                dump_str(k, out);
                out.push_str(if indent.is_some() { ": " } else { ":" });
                dump(&o[k], indent, level + 1, out);
            }
            newline(indent, level, out);
            out.push('}');
        }
    }
}

fn newline(indent: Option<usize>, level: usize, out: &mut String) {
    if let Some(n) = indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', n * level));
    }
}

/// `json.encoder.py_encode_basestring_ascii`.
fn dump_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumps_matches_python_for_nesting_and_escapes() {
        let v = json!({ "b": [], "a": { "y": [1, "\u{e9}\u{1f680}\x7f"], "x": {} } });
        assert_eq!(
            py_dumps(&v, None),
            "{\"a\":{\"x\":{},\"y\":[1,\"\\u00e9\\ud83d\\ude80\\u007f\"]},\"b\":[]}"
        );
        assert_eq!(
            py_dumps(&v, Some(2)),
            "{\n  \"a\": {\n    \"x\": {},\n    \"y\": [\n      1,\n      \"\\u00e9\\ud83d\\ude80\\u007f\"\n    ]\n  },\n  \"b\": []\n}"
        );
    }

    #[test]
    fn splitlines_follows_python() {
        assert_eq!(py_splitlines("a\r\nb\rc\x0cd\u{2028}e"), ["a\r\n", "b\r", "c\x0c", "d\u{2028}", "e"]);
        assert_eq!(py_splitlines("x\n"), ["x\n"]);
        assert!(py_splitlines("").is_empty());
    }

    #[test]
    fn strip_includes_the_ascii_separators() {
        assert_eq!(py_strip("\x1c a \u{3000}\x1f"), "a");
    }

    #[test]
    fn bearer_auth_and_embedded_secrets_are_refused() {
        let bad = [
            json!({ "version": "1", "mcp_servers": [{ "name": "a", "url": "https://x.example.com", "auth": "Bearer" }] }),
            json!({ "version": "1", "mcp_servers": [{ "name": "a", "url": "https://x.example.com", "token": "t" }] }),
            json!({ "version": "1", "mcp_servers": [{ "name": "a", "url": "ftp://x.example.com" }] }),
            json!({ "version": "1", "skills": [{ "name": "Bad Name" }] }),
            json!({ "version": "1", "surfaces": { "x": { "path": "../escape" } } }),
            json!({ "version": "bad version" }),
            json!({ "version": "1", "rules": { "claude": 5 } }),
        ];
        for raw in bad {
            assert!(normalize(&raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn an_undeclared_non_default_surface_is_unknown() {
        let b = normalize(&json!({ "version": "1" })).unwrap();
        assert!(render_surface(&b, "nope").is_err());
        assert!(render_surface(&b, " Codex ").unwrap().starts_with("# Generated"));
    }
}
