//! The hub's own policy for a harness config bundle, on top of the Python
//! hub's validation ([`super::render::normalize`]).
//!
//! The renderer stays byte-compatible with the Python hub; anything that
//! would let bundle content escape its place in a rendered file, or reach a
//! node unseen, is refused here instead:
//!
//! - TOML injection in the codex surface: MCP server names are
//!   `[A-Za-z0-9_-]{1,64}`, MCP URLs carry no control, whitespace, quote,
//!   backslash or bracket character, skill descriptions no backslash, control
//!   character or newline, and the codex and agents rules (both rendered into
//!   a TOML multi-line string) no `"""`;
//! - MCP URLs: no user info, no fragment, no credential-looking query
//!   parameter or path segment, and `https` unless the host is loopback;
//! - hidden text and front matter: no invisible, bidi or tag code points in
//!   rules or skills, and front matter in a skill body or any rules text (a
//!   rules surface may be a host's command or subagent file,
//!   `.claude/commands/*.md`, `.claude/agents/*.md`) only with the keys in
//!   [`SAFE_FRONT_MATTER_KEYS`] and plain values; a block that does not
//!   parse is refused ([`front_matter_findings`]);
//! - surfaces: at most [`MAX_SURFACES`]; `kind` is `rules` or `mcp`, and a
//!   default surface keeps its default kind; paths are relative with no empty,
//!   `.` or `..` segment, never a git directory, hooks, `.mcp.json` or host
//!   settings, carry an extension that fits their kind, and are distinct
//!   ignoring case;
//! - size: every rendered surface and the whole render are capped.

use std::collections::BTreeSet;

use serde_json::Value;
use ua_core::{UaError, UaResult};

use super::render::{self, Bundle, DEFAULT_SURFACES};
use crate::families::skills::{SAFE_FRONT_MATTER_KEYS, disallowed_keys, hidden_chars};

/// Surfaces one bundle may declare.
pub const MAX_SURFACES: usize = 16;
/// Bytes one rendered surface may hold.
pub const MAX_SURFACE_BYTES: usize = 600_000;
/// Bytes all rendered surfaces of a bundle may hold together.
pub const MAX_RENDERED_BYTES: usize = 3_000_000;

const KINDS: [&str; 2] = ["rules", "mcp"];
const RULES_EXTENSIONS: [&str; 3] = ["md", "mdc", "txt"];
const RULES_DOTFILES: [&str; 4] = [".cursorrules", ".windsurfrules", ".clinerules", ".rules"];
const MCP_EXTENSIONS: [&str; 3] = ["json", "jsonc", "toml"];

fn refuse<T>(msg: impl Into<String>) -> UaResult<T> {
    Err(UaError::invalid(msg.into()))
}

/// A path the node may write under its harness-config root: relative, no
/// empty, `.` or `..` segment, within the Python hub's character set.
pub fn safe_path(p: &str) -> bool {
    let charset = p.len() <= 256
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'@' | b'+' | b'-'));
    charset && !p.starts_with('/') && p.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

/// Why `path` may not be a `kind` surface, if it may not.
fn path_refusal(path: &str, kind: &str) -> Option<String> {
    if !safe_path(path) {
        return Some("must be relative, with no empty, `.` or `..` segment".into());
    }
    let lower = path.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('/').collect();
    let base = segments.last().copied().unwrap_or_default();
    if segments.iter().any(|s| matches!(*s, ".git" | "hooks" | ".githooks" | ".husky")) {
        return Some("may not be inside a git directory or a hooks directory".into());
    }
    if base == ".mcp.json" {
        return Some("may not be a project MCP server list (.mcp.json)".into());
    }
    if segments.iter().any(|s| s.starts_with(".claude") || *s == ".vscode") && base.starts_with("settings") {
        return Some("may not be a host settings file".into());
    }
    let ext = base.rsplit_once('.').map(|(stem, e)| if stem.is_empty() { "" } else { e }).unwrap_or("");
    let fits = match kind {
        "rules" => RULES_EXTENSIONS.contains(&ext) || RULES_DOTFILES.contains(&base),
        _ => MCP_EXTENSIONS.contains(&ext),
    };
    if !fits {
        let allowed = if kind == "rules" { "md, mdc, txt or a rules dotfile" } else { "json, jsonc or toml" };
        return Some(format!("needs an extension that fits kind {kind} ({allowed})"));
    }
    None
}

fn check_surfaces(b: &Bundle) -> UaResult<()> {
    let surfaces = b.surfaces();
    if surfaces.len() > MAX_SURFACES {
        return refuse(format!("at most {MAX_SURFACES} surfaces"));
    }
    let mut seen = BTreeSet::new();
    for (name, s) in &surfaces {
        if !KINDS.contains(&s.kind.as_str()) {
            return refuse(format!("surfaces.{name}.kind must be rules or mcp"));
        }
        if let Some((_, _, k)) = DEFAULT_SURFACES.iter().find(|(n, _, _)| n == name)
            && s.kind != *k
        {
            return refuse(format!("surfaces.{name} is a default surface; its kind is {k}"));
        }
        if let Some(why) = path_refusal(&s.path, &s.kind) {
            return refuse(format!("surfaces.{name}.path {:?} {why}", s.path));
        }
        if !seen.insert(s.path.to_lowercase()) {
            return refuse(format!("surfaces.{name}.path {:?} duplicates another surface's path", s.path));
        }
    }
    Ok(())
}

/// Shannon entropy in bits per character.
fn entropy(s: &str) -> f64 {
    let n = s.chars().count() as f64;
    let mut counts = std::collections::BTreeMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    counts.values().map(|&k| k as f64 / n).map(|p| -p * p.log2()).sum()
}

/// A path segment that looks like an embedded credential: long, mixed
/// letters and digits, and random-looking.
fn secret_segment(seg: &str) -> bool {
    let alnum = seg.chars().filter(char::is_ascii_alphanumeric).count();
    seg.len() >= 24
        && alnum * 10 >= seg.len() * 8
        && seg.chars().any(|c| c.is_ascii_digit())
        && seg.chars().any(|c| c.is_ascii_alphabetic())
        && entropy(seg) >= 3.5
}

/// Query parameter names that look like credentials.
fn secret_param(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const PARTS: [&str; 10] = [
        "token",
        "secret",
        "passw",
        "apikey",
        "api_key",
        "api-key",
        "auth",
        "signature",
        "credential",
        "session",
    ];
    PARTS.iter().any(|p| n.contains(p))
        || matches!(n.as_str(), "key" | "sig" | "pwd" | "jwt")
        || n.ends_with("_key")
        || n.ends_with("-key")
}

fn check_mcp(b: &Bundle) -> UaResult<()> {
    for s in &b.mcp_servers {
        let name = &s.name;
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return refuse(format!("mcp_server name {name:?} must be 1-64 of A-Z a-z 0-9 _ -"));
        }
        let raw = &s.url;
        let why = |w: &str| refuse::<()>(format!("mcp_server {name:?} url {w}"));
        if raw
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | '[' | ']'))
        {
            return why("may not contain control, whitespace, quote, backslash or bracket characters");
        }
        let Ok(url) = url::Url::parse(raw) else { return why("is not a valid URL") };
        if !url.username().is_empty() || url.password().is_some() {
            return why("must not carry credentials (user:password@)");
        }
        if url.fragment().is_some() {
            return why("must not carry a fragment");
        }
        if let Some((k, _)) = url.query_pairs().find(|(k, _)| secret_param(k)) {
            return why(&format!(
                "must not carry a secret-looking query parameter ({k:?}); use OAuth on the hub"
            ));
        }
        if url.path_segments().into_iter().flatten().any(secret_segment) {
            return why("must not carry a secret-looking path segment; use OAuth on the hub");
        }
        let loopback = match url.host() {
            Some(url::Host::Domain(d)) => {
                d.eq_ignore_ascii_case("localhost") || d.to_ascii_lowercase().ends_with(".localhost")
            }
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if url.scheme() != "https" && !loopback {
            return why("must use https (plain http only for a loopback host)");
        }
    }
    Ok(())
}

/// Why a skill description cannot go into the codex TOML, if it cannot.
pub fn description_refusal(d: &str) -> Option<&'static str> {
    if d.contains('\\') {
        Some("may not contain a backslash")
    } else if d.chars().any(|c| c.is_control()) {
        Some("may not contain control characters or newlines")
    } else {
        None
    }
}

/// Problems with the front matter at the top of `text`, read at least as
/// leniently as hosts read it. Empty when there is none or it is safe.
///
/// - **Opening:** the first non-blank line (after an optional BOM, LF or
///   CRLF) starting with `---` (`---yaml` names the language) or `+++`
///   (TOML).
/// - **Closing:** the next line starting with the same delimiter. Hosts
///   such as Claude Code also close on a `---` at the end of a line; the
///   block up to such a line is checked as well.
/// - **Unclosed:** a host may read the whole rest as front matter. It is
///   front matter here when it parses as a mapping; otherwise (a markdown
///   horizontal rule above prose) the text has none.
/// - **Fail closed:** a closed block that does not parse (too deeply
///   nested, malformed) is refused, as is a language other than YAML or
///   TOML. A mapping may hold only [`SAFE_FRONT_MATTER_KEYS`], each with a
///   scalar or a list of scalars. Keys are read after parsing, so flow
///   mappings, indentation and escaped quoted keys change nothing.
pub fn front_matter_findings(text: &str) -> Vec<String> {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let lines: Vec<&str> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    let Some(open) = lines.iter().position(|l| !l.trim().is_empty()) else { return Vec::new() };
    let first = lines[open].trim();
    let (delim, lang) = if let Some(rest) = first.strip_prefix("---") {
        ("---", rest.trim_start_matches('-').trim().to_ascii_lowercase())
    } else if let Some(rest) = first.strip_prefix("+++") {
        ("+++", rest.trim_start_matches('+').trim().to_ascii_lowercase())
    } else {
        return Vec::new();
    };
    let toml = delim == "+++" || lang == "toml";
    if !(lang.is_empty() || lang == "yaml" || lang == "yml" || lang == "toml") {
        return vec![format!("front matter in {lang:?} is not allowed (YAML only)")];
    }
    let body = &lines[open + 1..];
    let close = body.iter().position(|l| l.trim_start().starts_with(delim));
    let mut out = Vec::new();
    match close {
        Some(end) => check_front_matter_block(&body[..end].join("\n"), toml, true, &mut out),
        // Unclosed: front matter only if a host could read the rest as one.
        None => check_front_matter_block(&body.join("\n"), toml, false, &mut out),
    }
    // A host that closes on `---` at the end of a line reads less.
    if !toml {
        let limit = close.unwrap_or(body.len());
        if let Some(end) = body[..limit].iter().position(|l| l.trim_end().ends_with("---")) {
            let mut block: Vec<&str> = body[..end].to_vec();
            let last = body[end].trim_end();
            block.push(&last[..last.len() - 3]);
            check_front_matter_block(&block.join("\n"), false, true, &mut out);
        }
    }
    out.dedup();
    out
}

/// Check one candidate front-matter block. `closed`: a host certainly reads
/// it as front matter, so a parse failure is refused; an unclosed block that
/// does not parse to a mapping is no front matter at all.
fn check_front_matter_block(block: &str, toml: bool, closed: bool, out: &mut Vec<String>) {
    let parsed: Result<Value, String> = if toml {
        toml::from_str::<toml::Table>(block)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::to_value(t).map_err(|e| e.to_string()))
    } else {
        serde_saphyr::from_str::<Value>(block).map_err(|e| e.to_string())
    };
    let meta = match parsed {
        Ok(Value::Object(meta)) => meta,
        // No keys: nothing a host could act on.
        Ok(_) => return,
        Err(e) if closed => {
            let e = e.lines().next().unwrap_or_default().to_string();
            out.push(format!("front matter does not parse, so it cannot be checked ({e})"));
            return;
        }
        Err(_) => return,
    };
    for key in disallowed_keys(&meta) {
        out.push(format!(
            "front matter key `{key}` is not allowed (allowed: {})",
            SAFE_FRONT_MATTER_KEYS.join(", ")
        ));
    }
    for (key, v) in &meta {
        let scalar = |v: &Value| !matches!(v, Value::Object(_) | Value::Array(_));
        let plain = match v {
            Value::Array(items) => items.iter().all(scalar),
            other => scalar(other),
        };
        if SAFE_FRONT_MATTER_KEYS.contains(&key.as_str()) && !plain {
            out.push(format!("front matter key `{key}` must be a plain value or a list of them"));
        }
    }
}

/// Security findings for one skill: front matter in its body that is not
/// allowlisted or does not parse ([`front_matter_findings`]), and hidden
/// code points in its description or body.
pub fn skill_findings(description: &str, body: &str) -> Vec<String> {
    let mut out = front_matter_findings(body);
    for (where_, text) in [("description", description), ("body", body)] {
        for (line, c) in hidden_chars(text) {
            out.push(format!("{where_} line {line}: hidden code point U+{:04X}", c as u32));
        }
    }
    out
}

fn check_text(b: &Bundle) -> UaResult<()> {
    for key in ["codex", "agents"] {
        if b.rules.get(key).is_some_and(|t| t.contains("\"\"\"")) {
            return refuse(format!("rules.{key} may not contain \"\"\" (it is rendered into a TOML string)"));
        }
    }
    for (surface, text) in &b.rules {
        if let Some((line, c)) = hidden_chars(text).first() {
            return refuse(format!(
                "rules.{surface} line {line} has a hidden code point U+{:04X}",
                *c as u32
            ));
        }
        // Any rules text may land in a host's command or subagent file,
        // whose front matter grants tools.
        let findings = front_matter_findings(text);
        if !findings.is_empty() {
            return refuse(format!("rules.{surface} refused: {}", findings.join("; ")));
        }
    }
    for s in &b.skills {
        if let Some(why) = description_refusal(&s.description) {
            return refuse(format!("skill {:?} description {why}", s.name));
        }
        let findings = skill_findings(&s.description, &s.body);
        if !findings.is_empty() {
            return refuse(format!("skill {:?} refused: {}", s.name, findings.join("; ")));
        }
    }
    Ok(())
}

/// Every rendered surface within [`MAX_SURFACE_BYTES`], all of them within
/// [`MAX_RENDERED_BYTES`].
pub fn check_rendered(b: &Bundle) -> UaResult<()> {
    let mut total = 0;
    for (name, r) in render::render_all(b)? {
        if r.content.len() > MAX_SURFACE_BYTES {
            return refuse(format!("surface {name:?} renders to more than {MAX_SURFACE_BYTES} bytes"));
        }
        total += r.content.len();
    }
    if total > MAX_RENDERED_BYTES {
        return refuse(format!("the bundle renders to more than {MAX_RENDERED_BYTES} bytes"));
    }
    Ok(())
}

/// The hub's policy for a bundle the Python validation accepted.
pub fn check(b: &Bundle) -> UaResult<()> {
    check_surfaces(b)?;
    check_mcp(b)?;
    check_text(b)?;
    check_rendered(b)
}

/// Python validation, then the hub's policy: what a publish accepts.
pub fn validate(raw: &Value) -> UaResult<Bundle> {
    let b = render::normalize(raw)?;
    check(&b)?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, json};

    use super::*;

    fn refused(raw: Value) -> String {
        match validate(&raw) {
            Ok(_) => panic!("{raw} should be refused"),
            Err(e) => e.to_string(),
        }
    }

    fn mcp(url: &str) -> Value {
        json!({ "version": "1", "mcp_servers": [{ "name": "a", "url": url }] })
    }

    #[test]
    fn toml_injection_is_refused_at_validation() {
        // A URL closing its string and opening a table of its own.
        let e = refused(mcp("https://x.example.com/\"\n[mcp_servers.evil]\ncommand = \"sh"));
        assert!(e.contains("url"), "{e}");
        let e = refused(mcp("https://x.example.com/[mcp_servers.x]"));
        assert!(e.contains("bracket"), "{e}");
        // The renderer escapes `"` as `\"`; a description ending in `\` turns
        // that into `\\"` and closes the string.
        let e =
            refused(json!({ "version": "1", "skills": [{ "name": "s", "description": "x\\\" \n[evil]" }] }));
        assert!(e.contains("backslash"), "{e}");
        let e = refused(json!({ "version": "1", "skills": [{ "name": "s", "description": "a\nb" }] }));
        assert!(e.contains("control"), "{e}");
        for key in ["codex", "agents"] {
            let e = refused(json!({ "version": "1", "rules": { key: "x\n\"\"\"\n[mcp_servers.evil]\n" } }));
            assert!(e.contains("\"\"\""), "{e}");
        }
        let e = refused(
            json!({ "version": "1", "mcp_servers": [{ "name": "a.b", "url": "https://x.example.com/" }] }),
        );
        assert!(e.contains("name"), "{e}");
    }

    #[test]
    fn url_hygiene() {
        for url in [
            "https://user:pw@x.example.com/mcp",
            "https://x.example.com/mcp?access_token=t",
            "https://x.example.com/mcp?Key=t",
            "http://x.example.com/mcp",
            "https://x.example.com/mcp#frag",
            "https://x.example.com/mcp/sk9Fq2LmZ81xPq7TvWb3NcY0hJ4dRk",
            "https://x.example.com/ mcp",
        ] {
            refused(mcp(url));
        }
        for url in [
            "http://127.0.0.1:8765/mcp",
            "http://localhost/mcp",
            "https://x.example.com/mcp?region=eu&x=1",
            "https://x.example.com/v1/organizations/default/mcp",
        ] {
            validate(&mcp(url)).unwrap_or_else(|e| panic!("{url}: {e}"));
        }
    }

    #[test]
    fn hidden_text_and_permission_front_matter_are_refused() {
        let e = refused(json!({ "version": "1", "rules": { "claude": "ok\u{E0041}\u{E0042}\n" } }));
        assert!(e.contains("U+E0041"), "{e}");
        refused(json!({ "version": "1", "rules": { "cursor": "a\u{202E}b" } }));
        refused(json!({ "version": "1", "skills": [{ "name": "s", "description": "zero\u{200B}width" }] }));
        let e = refused(
            json!({ "version": "1", "skills": [{ "name": "s", "body": "---\nname: s\nallowed-tools: Bash\n---\nx\n" }] }),
        );
        assert!(e.contains("allowed-tools"), "{e}");
        refused(json!({ "version": "1", "skills": [{ "name": "s", "body": "---\nhooks: {}\n---\n" }] }));
    }

    #[test]
    fn surfaces_are_allowlisted() {
        let surf = |s: Value| json!({ "version": "1", "surfaces": s });
        for s in [
            json!({ "x": { "path": "/etc/profile" } }),
            json!({ "x": { "path": "a/./b.md" } }),
            json!({ "x": { "path": "a//b.md" } }),
            json!({ "x": { "path": "x.md", "kind": "skills" } }),
            json!({ "codex": { "path": "codex/rules.md", "kind": "rules" } }),
            json!({ "x": { "path": ".claude/settings.local.json", "kind": "mcp" } }),
            json!({ "x": { "path": ".git/hooks/pre-commit.md" } }),
            json!({ "x": { "path": "hooks/run.md" } }),
            json!({ "x": { "path": ".mcp.json", "kind": "mcp" } }),
            json!({ "x": { "path": ".bashrc" } }),
            json!({ "x": { "path": "run.sh", "kind": "mcp" } }),
            json!({ "x": { "path": "A.md" }, "y": { "path": "a.md" } }),
        ] {
            refused(surf(s));
        }
        let many: Map<String, Value> =
            (0..17).map(|i| (format!("s{i}"), json!({ "path": format!("s{i}.md") }))).collect();
        assert!(refused(surf(Value::Object(many))).contains("at most"));
        validate(&surf(json!({ "notes": { "path": "docs/NOTES.md" }, "zed": { "path": "zed/settings.json", "kind": "mcp" } })))
            .unwrap();
    }

    #[test]
    fn rendered_size_is_capped() {
        let body = "x".repeat(250_000);
        let skills: Vec<Value> = (0..3).map(|i| json!({ "name": format!("s{i}"), "body": body })).collect();
        let e = refused(json!({ "version": "1", "skills": skills[..2], "surfaces": {
            "a": { "path": "a.json", "kind": "mcp" }, "b": { "path": "b.json", "kind": "mcp" },
            "c": { "path": "c.json", "kind": "mcp" }, "d": { "path": "d.json", "kind": "mcp" },
            "e": { "path": "e.json", "kind": "mcp" }, "f": { "path": "f.json", "kind": "mcp" },
            "g": { "path": "g.json", "kind": "mcp" } } }));
        assert!(e.contains("renders to more than"), "{e}");
    }
}
