//! Audit rules. Each rule returns findings; the engine decides which files it
//! sees. Content rules run per text file, repo rules once against the tree.
//! A line containing `ua:allow` suppresses content-rule findings on it.
//!
//! No rule ever puts a matched secret value in a finding: messages carry the
//! rule's name, the file, the line and a short redacted preview.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use base64::Engine as _;
use regex::Regex;
use serde_json::{Value, json};

use super::safe_io::read_regular_text;
use crate::families::injection::{hidden_char_regex, injection_regex};

pub const SEVERITIES: [&str; 4] = ["high", "medium", "low", "info"];
pub const SUPPRESS_MARKER: &str = "ua:allow";

pub fn severity_rank(sev: &str) -> usize {
    SEVERITIES.iter().position(|s| *s == sev).unwrap_or(SEVERITIES.len())
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: String,
    pub severity: &'static str,
    pub message: String,
    pub fix: String,
    pub path: Option<String>,
    pub line: Option<usize>,
    pub fixed: bool,
}

impl Finding {
    pub(super) fn new(
        rule: &str,
        severity: &'static str,
        path: Option<&str>,
        line: Option<usize>,
        message: String,
        fix: &str,
    ) -> Self {
        Self {
            rule: rule.to_string(),
            severity,
            message,
            fix: fix.to_string(),
            path: path.map(str::to_string),
            line,
            fixed: false,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "rule": self.rule, "severity": self.severity, "message": self.message, "fix": self.fix,
            "path": self.path, "line": self.line, "fixed": self.fixed,
        })
    }
}

fn rx(p: &str) -> Regex {
    Regex::new(p).expect("audit pattern compiles")
}

/// A redacted preview of a matched value: at most four leading characters (a
/// vendor prefix) and the length, never more than a quarter of the value.
pub fn mask(secret: &str) -> String {
    let n = secret.chars().count();
    let show = (n / 4).min(4);
    let head: String = secret.chars().take(show).collect();
    format!("{head}…({n} chars)")
}

// --- secrets ----------------------------------------------------------------------------

struct SecretShape {
    name: &'static str,
    rx: Regex,
}

fn secret_shapes() -> &'static Vec<SecretShape> {
    static SHAPES: OnceLock<Vec<SecretShape>> = OnceLock::new();
    SHAPES.get_or_init(|| {
        let s = |name, p: &str| SecretShape { name, rx: rx(p) };
        vec![
            s("Anthropic API key", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
            s("OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"),
            s("AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            s("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
            s("Slack token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
            s("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
            s(
                "assigned secret literal",
                r#"(?i)\b(?:api_?key|secret|token|passwd|password|credential)\s*[:=]\s*["'](?P<val>[A-Za-z0-9+/=_\-]{16,})["']"#,
            ),
            s("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
            s("AWS secret access key", r#"(?i)aws_secret_access_key\s*[:=]\s*['"]?(?P<val>[^\s'"]{8,})['"]?"#),
            s("credential in URL", r"(?i)[a-z][a-z0-9+.-]{0,31}://[^\s/:@]+:(?P<val>[^\s/@]+)@"),
            s("JSON web token", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
            s("Stripe key", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}"),
            s("Slack app token", r"\bxapp-[0-9A-Za-z-]{10,}"),
            s("Slack webhook", r"hooks\.slack\.com/services/[A-Za-z0-9_/-]{8,}"),
            s("HTTP Basic credentials", r"\bBasic (?P<val>[A-Za-z0-9+/]{12,}={0,2})"),
            s("session credential", r"\buas_[A-Za-z0-9_-]{40,}"),
            s("PuTTY private key", r"PuTTY-User-Key-File-\d+:"),
        ]
    })
}

const PLACEHOLDER_HINTS: [&str; 7] =
    ["example", "your", "placeholder", "changeme", "dummy", "xxxx", "redacted"];
const PLACEHOLDER_WORDS: [&str; 8] =
    ["pass", "password", "passwd", "passphrase", "pwd", "pw", "secret", "token"];

fn placeholder_shape() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        rx(r"(?i)^<[^<>\s]+>$|^\$\{[^}]*\}$|^\$[A-Za-z_][A-Za-z0-9_]*$|^%[A-Za-z_][A-Za-z0-9_]*%$|^[*x.\x{2022}]+$")
    })
}

fn url_user() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| rx(r"://([^\s/:@]+):"))
}

/// Documentation shapes that stand in for a credential: a placeholder word,
/// an angle-bracket slot, a variable reference, a mask, or a URL password
/// that repeats its user name.
pub fn is_placeholder(value: &str, matched: &str) -> bool {
    let low = value.to_lowercase();
    let stripped = value.trim_matches(|c| c == '"' || c == '\'');
    let user_same = url_user().captures(matched).is_some_and(|c| c[1].to_lowercase() == low);
    PLACEHOLDER_HINTS.iter().any(|h| low.contains(h))
        || PLACEHOLDER_WORDS.contains(&stripped.to_lowercase().as_str())
        || placeholder_shape().is_match(stripped)
        || user_same
}

fn secret_scan_skip() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| rx(r"(^|/)(\.env[^/]*|.*\.lock|package-lock\.json|.*\.min\.js)$"))
}

pub fn skip_secret_scan(relpath: &str) -> bool {
    secret_scan_skip().is_match(relpath)
}

pub fn check_secrets(relpath: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if skip_secret_scan(relpath) {
        return out;
    }
    for (i, line) in text.lines().enumerate() {
        for shape in secret_shapes() {
            let Some(caps) = shape.rx.captures(line) else { continue };
            let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let value = caps.name("val").map(|m| m.as_str()).unwrap_or(whole);
            if shape.name == "HTTP Basic credentials"
                && !value.chars().any(|c| c.is_ascii_digit() || matches!(c, '+' | '/' | '='))
            {
                continue;
            }
            if is_placeholder(value, whole) {
                continue;
            }
            out.push(Finding::new(
                "SECRETS-KEY",
                "high",
                Some(relpath),
                Some(i + 1),
                format!("possible {} committed in source: {}", shape.name, mask(value)),
                "move the credential to an environment variable or secret store, rotate it, and purge it from git history",
            ));
            break;
        }
    }
    out
}

/// Replace every credential-shaped match in `text` with `[REDACTED_SECRET]`;
/// returns the new text and how many matches were replaced. Placeholder values
/// are left alone, as in the audit itself.
pub fn redact_secrets(text: &str) -> (String, usize) {
    let mut out = text.to_string();
    let mut count = 0;
    for shape in secret_shapes() {
        let current = out.clone();
        out = shape
            .rx
            .replace_all(&current, |caps: &regex::Captures<'_>| {
                let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                let value = caps.name("val").map(|m| m.as_str()).unwrap_or(whole);
                if is_placeholder(value, whole) {
                    whole.to_string()
                } else {
                    count += 1;
                    "[REDACTED_SECRET]".to_string()
                }
            })
            .into_owned();
    }
    (out, count)
}

pub fn check_private_key(relpath: &str, text: &str) -> Vec<Finding> {
    static RX: OnceLock<Regex> = OnceLock::new();
    let rx = RX.get_or_init(|| rx(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY"));
    for (i, line) in text.lines().enumerate() {
        if rx.is_match(line) {
            return vec![Finding::new(
                "SECRETS-PRIVATE-KEY",
                "high",
                Some(relpath),
                Some(i + 1),
                "private key material found in the repository".into(),
                "remove the key, rotate it, and store keys outside the repo (e.g. a keychain or secrets manager)",
            )];
        }
    }
    Vec::new()
}

// --- agent configuration ----------------------------------------------------------------

pub const INSTRUCTION_FILES: [&str; 7] = [
    "CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".github/copilot-instructions.md",
    "README.md",
];

fn is_instruction_file(relpath: &str) -> bool {
    INSTRUCTION_FILES.contains(&relpath) || relpath.starts_with(".cursor/rules/")
}

pub fn check_hidden_unicode(relpath: &str, text: &str) -> Vec<Finding> {
    if !is_instruction_file(relpath) {
        return Vec::new();
    }
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    for (i, line) in body.lines().enumerate() {
        if let Some(m) = hidden_char_regex().find(line) {
            let cp = m.as_str().chars().next().map(|c| c as u32).unwrap_or(0);
            return vec![Finding::new(
                "AGENT-HIDDEN-UNICODE",
                "high",
                Some(relpath),
                Some(i + 1),
                format!(
                    "invisible/bidi Unicode (U+{cp:04X}) in an agent instruction file — possible hidden prompt injection"
                ),
                "inspect the file with a hex viewer and delete the hidden characters; treat unexplained ones as hostile",
            )];
        }
    }
    Vec::new()
}

pub fn check_risky_instructions(relpath: &str, text: &str) -> Vec<Finding> {
    static RX: OnceLock<Regex> = OnceLock::new();
    let rx = RX.get_or_init(|| {
        rx(r"(?i)dangerously-skip-permissions|bypassPermissions|--yolo|--trust-all-tools|--no-verify")
    });
    if !is_instruction_file(relpath) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if let Some(m) = rx.find(line) {
            out.push(Finding::new(
                "AGENT-RISKY-INSTRUCTIONS",
                "medium",
                Some(relpath),
                Some(i + 1),
                format!("instruction file tells agents to bypass a safety rail ({:?})", m.as_str()),
                "remove the directive; grant narrow permissions in settings instead of disabling confirmation entirely",
            ));
        }
    }
    out
}

fn load_json(path: &Path) -> Option<Value> {
    let text = read_regular_text(path)?;
    match serde_json::from_str::<Value>(&text) {
        Ok(v @ Value::Object(_)) => Some(v),
        _ => None,
    }
}

fn hook_commands(node: &Value, out: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            for (k, v) in map {
                match (k.as_str(), v) {
                    ("command", Value::String(s)) => out.push(s.clone()),
                    _ => hook_commands(v, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|i| hook_commands(i, out)),
        _ => {}
    }
}

pub const AGENT_SETTINGS_PATHS: [&str; 5] = [
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".agents/hooks.json",
    "hooks.json",
    "config/hooks.json",
];

const BROAD_PERMISSIONS: [&str; 5] = ["*", "Bash", "Bash(*)", "Bash(*:*)", "Bash(**)"];

pub fn check_agent_settings(root: &Path) -> Vec<Finding> {
    static HOOK_RX: OnceLock<Regex> = OnceLock::new();
    let hook_rx = HOOK_RX.get_or_init(|| rx(r"(?i)curl[^|;&]*\|\s*(?:ba)?sh|\beval\b"));
    let mut out = Vec::new();
    for rel in AGENT_SETTINGS_PATHS {
        let p = root.join(rel);
        if !p.is_file() {
            continue;
        }
        let Some(data) = load_json(&p) else {
            out.push(Finding::new(
                "AGENT-PERMISSIVE-CONFIG",
                "info",
                Some(rel),
                None,
                "agent settings file is not valid JSON; could not audit it".into(),
                "fix the JSON so permissions can be reviewed",
            ));
            continue;
        };
        let perms = data.get("permissions").filter(|p| p.is_object());
        let bypass = data.get("defaultMode").and_then(Value::as_str) == Some("bypassPermissions")
            || perms.and_then(|p| p.get("defaultMode")).and_then(Value::as_str) == Some("bypassPermissions");
        if bypass {
            out.push(Finding::new(
                "AGENT-PERMISSIVE-CONFIG",
                "high",
                Some(rel),
                None,
                "agent runs with bypassPermissions: every tool call is auto-approved".into(),
                "use acceptEdits or an explicit allowlist instead of bypassing prompts",
            ));
        }
        if let Some(allow) = perms.and_then(|p| p.get("allow")).and_then(Value::as_array) {
            for entry in allow.iter().filter_map(Value::as_str) {
                if BROAD_PERMISSIONS.contains(&entry) {
                    out.push(Finding::new(
                        "AGENT-PERMISSIVE-CONFIG",
                        "high",
                        Some(rel),
                        None,
                        format!("permission allowlist entry {entry:?} auto-approves arbitrary commands"),
                        "allow specific commands (e.g. 'Bash(npm test:*)') rather than wildcards over Bash",
                    ));
                }
            }
        }
        let hook_root = if rel.ends_with("hooks.json") {
            match data.get("hooks") {
                Some(n) if n.is_object() || n.is_array() => n.clone(),
                _ => data.clone(),
            }
        } else {
            data.get("hooks").cloned().unwrap_or(Value::Null)
        };
        let mut cmds = Vec::new();
        hook_commands(&hook_root, &mut cmds);
        for cmd in cmds {
            if hook_rx.is_match(&cmd) {
                let short: String = cmd.chars().take(80).collect();
                out.push(Finding::new(
                    "AGENT-HOOK-SHELL",
                    "medium",
                    Some(rel),
                    None,
                    format!("hook pipes downloaded content to a shell or uses eval: {short:?}"),
                    "vendor the script into the repo and execute it directly",
                ));
            }
        }
    }
    out
}

pub const MCP_CONFIG_PATHS: [&str; 5] =
    [".mcp.json", ".cursor/mcp.json", "mcp.json", "config/mcp_config.json", ".gemini/config/mcp_config.json"];

fn mcp_regexes() -> &'static (Regex, Regex, Regex, Regex, Regex) {
    static RX: OnceLock<(Regex, Regex, Regex, Regex, Regex)> = OnceLock::new();
    RX.get_or_init(|| {
        (
            rx(r"\$\{?[A-Z_][A-Z0-9_]*\}?"),
            rx(r"\$\{[A-Za-z_][^}]*\}|\{(?:env|file):[^}]+\}"),
            rx(r"^[A-Za-z0-9+/=_\-]{16,}$"),
            rx(r"(?i)\bbearer\s+(\S{8,})"),
            rx(r"^/?(?:[A-Za-z0-9_.\-]+/)+[A-Za-z0-9_.\-]+/?$"),
        )
    })
}

fn interpolated(value: &str) -> bool {
    let (env_ref, interp, ..) = mcp_regexes();
    env_ref.is_match(value) || interp.is_match(value)
}

/// The token to mask when `value` is a committed secret, else `None`.
fn literal_mcp_secret(value: &str) -> Option<String> {
    let (_, _, secretish, bearer, path_like) = mcp_regexes();
    let low = value.to_lowercase();
    if interpolated(value) || PLACEHOLDER_HINTS.iter().any(|h| low.contains(h)) {
        return None;
    }
    if let Some(c) = bearer.captures(value) {
        let token = c[1].to_string();
        return if interpolated(&token) { None } else { Some(token) };
    }
    if secretish.is_match(value) && !path_like.is_match(value) {
        return Some(value.to_string());
    }
    None
}

fn check_one_mcp_config(
    rel: &str,
    data: &Value,
    secret_severity: &'static str,
    with_secrets: bool,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(servers) = data.get("mcpServers").and_then(Value::as_object) else { return out };
    for (name, server) in servers {
        let Some(server) = server.as_object() else { continue };
        for (field, fix) in [
            (
                "env",
                "reference an environment variable (e.g. \"${API_KEY}\") instead of committing the value",
            ),
            (
                "headers",
                "use a host env/file interpolator (e.g. ${env:HUB_TOKEN}) instead of committing the value",
            ),
        ] {
            let Some(map) = server.get(field).and_then(Value::as_object) else { continue };
            if !with_secrets {
                continue;
            }
            for (key, value) in map {
                let Some(value) = value.as_str() else { continue };
                if let Some(token) = literal_mcp_secret(value) {
                    out.push(Finding::new(
                        "AGENT-MCP-SECRETS",
                        secret_severity,
                        Some(rel),
                        None,
                        format!(
                            "MCP server {name:?} has a literal secret in {field}[{key:?}]: {}",
                            mask(&token)
                        ),
                        fix,
                    ));
                }
            }
        }
        let mut argv: Vec<String> =
            vec![server.get("command").and_then(Value::as_str).unwrap_or("").to_string()];
        if let Some(args) = server.get("args").and_then(Value::as_array) {
            argv.extend(args.iter().filter_map(|a| a.as_str().map(str::to_string)));
        }
        if let Some(pos) = argv.iter().position(|a| a == "npx" || a == "uvx") {
            let runner = argv[pos].clone();
            let pkg = argv[pos + 1..].iter().find(|a| !a.is_empty() && !a.starts_with('-'));
            if let Some(pkg) = pkg
                && !pkg.trim_start_matches('@').contains('@')
            {
                out.push(Finding::new(
                    "AGENT-MCP-UNPINNED",
                    "medium",
                    Some(rel),
                    None,
                    format!(
                        "MCP server {name:?} runs {runner} {pkg:?} without a version pin (supply-chain risk: you execute whatever is published next)"
                    ),
                    &format!("pin an exact version, e.g. {pkg}@1.2.3, and review before bumping"),
                ));
            }
        }
    }
    out
}

/// Whether a root `.gitignore` names `rel` exactly: such a config is local
/// host state, not a committed secret.
fn gitignored_exactly(root: &Path, rel: &str) -> bool {
    let Some(text) = read_regular_text(&root.join(".gitignore")) else { return false };
    text.lines().map(str::trim).any(|l| l == rel || l.strip_prefix('/') == Some(rel))
}

pub fn check_mcp_config(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for rel in MCP_CONFIG_PATHS {
        let p = root.join(rel);
        let Ok(canon) = p.canonicalize() else { continue };
        if !canon.is_file() || !seen.insert(canon) {
            continue;
        }
        let Some(data) = load_json(&p) else { continue };
        // An untracked, ignored config is local host state: still flag
        // unpinned packages, not its secrets.
        let with_secrets = !gitignored_exactly(root, rel);
        out.extend(check_one_mcp_config(rel, &data, "high", with_secrets));
    }
    out
}

pub fn check_instructions_exist(root: &Path) -> Vec<Finding> {
    if INSTRUCTION_FILES[..INSTRUCTION_FILES.len() - 1].iter().any(|f| root.join(f).is_file()) {
        return Vec::new();
    }
    vec![Finding::new(
        "AGENT-NO-INSTRUCTIONS",
        "info",
        None,
        None,
        "no agent instruction file (CLAUDE.md / AGENTS.md / .cursorrules) found".into(),
        "add one stating build/test commands and guardrails (what agents must not touch), so every assistant starts with the same constraints",
    )]
}

// --- LLM application code -----------------------------------------------------------------

fn llm_regexes() -> &'static (Regex, Regex, Regex, Regex, Regex) {
    static RX: OnceLock<(Regex, Regex, Regex, Regex, Regex)> = OnceLock::new();
    RX.get_or_init(|| {
        (
            rx(r"(?m)^\s*(?:from|import)\s+(?:anthropic|openai|google\.generativeai|google\.genai|litellm|langchain\w*|mistralai|cohere|groq|ollama)\b"),
            rx(r#"["'](?:@anthropic-ai/sdk|openai|@google/generative-ai|ai|langchain)["']"#),
            rx(r"(?:^|[^.\w])(?:eval|exec)\("),
            rx(r"shell\s*=\s*True"),
            rx(r"\beval\(|new\s+Function\("),
        )
    })
}

pub fn check_llm_code(relpath: &str, text: &str) -> Vec<Finding> {
    let (py_import, js_import, py_eval, shell_true, js_eval) = llm_regexes();
    let mut out = Vec::new();
    let is_js = [".js", ".ts", ".mjs", ".tsx", ".jsx"].iter().any(|e| relpath.ends_with(e));
    if is_js && js_import.is_match(text) {
        for (i, line) in text.lines().enumerate() {
            if js_eval.is_match(line) {
                out.push(Finding::new(
                    "LLM-EVAL",
                    "high",
                    Some(relpath),
                    Some(i + 1),
                    "eval/new Function in a file that talks to an LLM — model output may reach code execution".into(),
                    "parse structured output instead of evaluating it",
                ));
            }
        }
    }
    if relpath.ends_with(".py") && py_import.is_match(text) {
        for (i, line) in text.lines().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            if py_eval.is_match(line) {
                out.push(Finding::new(
                    "LLM-EVAL",
                    "high",
                    Some(relpath),
                    Some(i + 1),
                    "eval/exec in a file that talks to an LLM — model output may reach code execution".into(),
                    "parse structured output (JSON/tool calls) instead of evaluating it; if execution is the feature, sandbox it",
                ));
            }
            if shell_true.is_match(line) {
                out.push(Finding::new(
                    "LLM-SHELL-TRUE",
                    "medium",
                    Some(relpath),
                    Some(i + 1),
                    "subprocess(shell=True) in a file that talks to an LLM — model-influenced strings may reach a shell".into(),
                    "pass an argv list with shell=False and validate against an allowlist",
                ));
            }
        }
    }
    out
}

// --- repo hygiene -----------------------------------------------------------------------------

const GITIGNORE_ENV_PATTERNS: [&str; 5] = [".env", ".env*", "*.env", ".env.*", "**/.env"];

fn gitignore_covers_env(gitignore: &Path) -> bool {
    read_regular_text(gitignore)
        .is_some_and(|t| t.lines().map(str::trim).any(|l| GITIGNORE_ENV_PATTERNS.contains(&l)))
}

fn env_covered_in_chain(env_file: &Path, root: &Path) -> bool {
    let mut d = env_file.parent();
    while let Some(dir) = d {
        if gitignore_covers_env(&dir.join(".gitignore")) {
            return true;
        }
        if dir == root {
            return false;
        }
        d = dir.parent();
    }
    false
}

fn repo_in_chain(env_file: &Path, root: &Path) -> bool {
    let mut d = env_file.parent();
    while let Some(dir) = d {
        if dir.join(".git").exists() {
            return true;
        }
        if dir == root {
            return false;
        }
        d = dir.parent();
    }
    false
}

pub fn check_env_exposure(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in files {
        let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let is_env = name == ".env" || name.starts_with(".env.");
        let template = [".env.example", ".env.sample", ".env.template", ".env.dist"].contains(&name.as_str());
        if !is_env || template || env_covered_in_chain(f, root) {
            continue;
        }
        let at_root = f.parent() == Some(root);
        let severity = if repo_in_chain(f, root) || at_root { "high" } else { "info" };
        let rel = f.strip_prefix(root).unwrap_or(f).to_string_lossy().replace('\\', "/");
        out.push(Finding::new(
            "SECRETS-ENV-EXPOSED",
            severity,
            Some(&rel),
            None,
            ".env file present but no .gitignore rule covers it — secrets are one `git add .` away from being committed (and readable by any agent/tool)".into(),
            "add `.env*` to .gitignore; if already committed, rotate the secrets",
        ));
    }
    out
}

pub fn check_lockfiles(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let any = |names: &[&str]| names.iter().any(|n| root.join(n).is_file());
    if root.join("package.json").is_file()
        && !any(&["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"])
    {
        out.push(Finding::new(
            "HYGIENE-NO-LOCKFILE",
            "low",
            Some("package.json"),
            None,
            "no JS lockfile — installs are unpinned (agents may add hallucinated or typosquatted packages unnoticed)".into(),
            "commit a lockfile and review dependency diffs in PRs",
        ));
    }
    if root.join("pyproject.toml").is_file() && !any(&["uv.lock", "poetry.lock", "pdm.lock"]) {
        out.push(Finding::new(
            "HYGIENE-NO-LOCKFILE",
            "low",
            Some("pyproject.toml"),
            None,
            "no Python lockfile — installs are unpinned".into(),
            "commit uv.lock / poetry.lock so environments are reproducible",
        ));
    }
    if root.join("Cargo.toml").is_file() && !root.join("Cargo.lock").is_file() {
        out.push(Finding::new(
            "HYGIENE-NO-LOCKFILE",
            "low",
            Some("Cargo.toml"),
            None,
            "no Cargo.lock — installs are unpinned".into(),
            "commit Cargo.lock for binaries so builds are reproducible",
        ));
    }
    out
}

pub fn check_gitignore_exists(root: &Path) -> Vec<Finding> {
    if root.join(".git").exists() && !root.join(".gitignore").is_file() {
        return vec![Finding::new(
            "HYGIENE-NO-GITIGNORE",
            "low",
            None,
            None,
            "git repository without a .gitignore".into(),
            "add one covering .env*, credentials, and build artifacts before agents start committing",
        )];
    }
    Vec::new()
}

// --- untrusted documents (injection, hidden unicode, base64) ----------------------------

const BASE64_MIN_RUN: usize = 64;
const HEX_DIGEST_LENGTHS: [usize; 5] = [32, 40, 64, 96, 128];
const TEXT_RATIO: f64 = 0.75;
const TEXT_RUN_MIN: usize = 18;
const WORD_RUN_LOWER_RATIO: f64 = 0.8;
const WORD_RUN_MIN_DISTINCT: usize = 8;
const CONTAINER_MAGIC: [&[u8]; 8] = [
    b"\x78\x01",
    b"\x78\x5e",
    b"\x78\x9c",
    b"\x78\xda",
    b"\x1f\x8b",
    b"\x28\xb5\x2f\xfd",
    b"BZh",
    b"\x04\x22\x4d\x18",
];

fn base64_blob_rx() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| rx(&format!(r"\b[A-Za-z0-9+/]{{{BASE64_MIN_RUN},}}=*\b")))
}

fn url_rx() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| rx(r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>"'`]+"#))
}

fn decodes_to_text(raw: &[u8]) -> bool {
    let body: Vec<u8> = raw.iter().copied().filter(|b| *b != 0).collect();
    if body.is_empty() {
        return false;
    }
    let texty = body.iter().filter(|b| matches!(**b, 0x20..=0x7e | 0x09 | 0x0a | 0x0d)).count();
    if texty as f64 / body.len() as f64 >= TEXT_RATIO {
        return true;
    }
    let valid = match std::str::from_utf8(&body) {
        Ok(s) => s,
        // A sequence cut off at the end still counts; anything else is binary.
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&body[..e.valid_up_to()]).unwrap_or(""),
        Err(_) => return false,
    };
    let n = valid.chars().count();
    n > 0
        && valid.chars().filter(|c| !c.is_control() || c.is_whitespace()).count() as f64 / n as f64
            >= TEXT_RATIO
}

fn has_text_run(raw: &[u8]) -> bool {
    let mut run = 0;
    for b in raw {
        if matches!(*b, 0x20..=0x7e | 0x09 | 0x0a | 0x0d) {
            run += 1;
            if run >= TEXT_RUN_MIN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn is_hex_digest(blob: &str) -> bool {
    if !HEX_DIGEST_LENGTHS.contains(&blob.len()) || !blob.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let Some(raw) = hex_to_bytes(blob) else { return false };
    !CONTAINER_MAGIC.iter().any(|m| raw.starts_with(m)) && !decodes_to_text(&raw)
}

/// Whether the run, read from any of its four offsets, base64-decodes to text
/// or a container. A decoding error counts as a payload: nothing can vouch
/// for it.
fn payload_at_any_alignment(blob: &str) -> bool {
    for offset in 0..4 {
        let Some(chunk) = blob.get(offset..) else { continue };
        let chunk = &chunk[..chunk.len() - chunk.len() % 4];
        if chunk.len() < 8 {
            continue;
        }
        match base64::engine::general_purpose::STANDARD.decode(chunk) {
            Err(_) => return true,
            Ok(raw) => {
                if CONTAINER_MAGIC.iter().any(|m| raw.starts_with(m))
                    || decodes_to_text(&raw)
                    || has_text_run(&raw)
                {
                    return true;
                }
            }
        }
    }
    false
}

fn is_source_path(blob: &str) -> bool {
    static SEG: OnceLock<Regex> = OnceLock::new();
    let seg = SEG.get_or_init(|| rx(r"^(?:[a-z]+[0-9]*(?:[A-Z][a-z]+[0-9]*)*|(?:[A-Z][a-z]+[0-9]*)+)$"));
    if blob.contains('+') || blob.contains('=') {
        return false;
    }
    let segments: Vec<&str> = blob.split('/').collect();
    if segments.len() < 3 || !segments.iter().all(|s| seg.is_match(s)) {
        return false;
    }
    let whole = &blob[..blob.len() - blob.len() % 4];
    match base64::engine::general_purpose::STANDARD.decode(whole) {
        Ok(raw) => !decodes_to_text(&raw),
        Err(_) => false,
    }
}

fn is_lowercase_word_run(blob: &str) -> bool {
    if blob.contains('+') || blob.contains('=') {
        return false;
    }
    let body: String = blob.chars().filter(|c| *c != '/').collect();
    if body.is_empty() {
        return false;
    }
    let distinct: BTreeSet<char> = body.chars().collect();
    if distinct.len() < WORD_RUN_MIN_DISTINCT {
        return false;
    }
    let lower = body.chars().filter(char::is_ascii_lowercase).count();
    if (lower as f64 / body.chars().count() as f64) < WORD_RUN_LOWER_RATIO {
        return false;
    }
    !payload_at_any_alignment(blob)
}

fn is_benign_base64_shape(blob: &str) -> bool {
    blob.bytes().all(|b| b.is_ascii_digit() || b == b'/')
        || is_hex_digest(blob)
        || is_source_path(blob)
        || is_lowercase_word_run(blob)
}

fn is_inert_url_part(blob: &str) -> bool {
    let mut starts = vec![0];
    starts.extend(blob.char_indices().filter(|(_, c)| *c == '/').map(|(i, _)| i + 1));
    !starts.iter().any(|s| blob.get(*s..).is_some_and(payload_at_any_alignment))
}

fn flags_base64(line: &str) -> bool {
    let mut urls: Option<Vec<(usize, usize)>> = None;
    for m in base64_blob_rx().find_iter(line) {
        let blob = m.as_str();
        if is_benign_base64_shape(blob) {
            continue;
        }
        let spans =
            urls.get_or_insert_with(|| url_rx().find_iter(line).map(|u| (u.start(), u.end())).collect());
        let in_url = spans.iter().any(|(s, e)| *s <= m.start() && m.end() <= *e);
        if in_url && is_inert_url_part(blob) {
            continue;
        }
        return true;
    }
    false
}

pub fn check_untrusted_injection(relpath: &str, text: &str, inbox_dir: Option<&str>) -> Vec<Finding> {
    let p = Path::new(relpath);
    let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy().to_lowercase())).unwrap_or_default();
    let in_inbox = inbox_dir.is_some_and(|d| {
        let d = d.trim_matches('/').to_lowercase();
        !d.is_empty() && relpath.split('/').any(|c| c.to_lowercase() == d)
    });
    let is_doc = matches!(ext.as_str(), ".md" | ".txt" | "") || in_inbox;
    if skip_secret_scan(relpath) || matches!(ext.as_str(), ".py" | ".pyc" | ".lock") || !is_doc {
        return Vec::new();
    }
    let lower = relpath.to_lowercase();
    let skip_base64 = lower.ends_with(".excalidraw.md") || lower.ends_with(".excalidraw");

    let mut out = Vec::new();
    let (mut run_start, mut run_len) = (0usize, 0usize);
    let flush = |out: &mut Vec<Finding>, run_start: &mut usize, run_len: &mut usize| {
        if *run_len == 0 {
            return;
        }
        let span = if *run_len > 1 { format!(" spanning {} lines", *run_len) } else { String::new() };
        out.push(Finding::new(
            "INJECTION-BASE64",
            "medium",
            Some(relpath),
            Some(*run_start),
            format!("large base64 blob{span} found in document: potential obfuscated instruction payload"),
            "inspect and decode the base64 content to verify it does not contain hidden directives",
        ));
        *run_start = 0;
        *run_len = 0;
    };
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    for (i, line) in body.lines().enumerate() {
        let n = i + 1;
        if line.contains(SUPPRESS_MARKER) {
            flush(&mut out, &mut run_start, &mut run_len);
            continue;
        }
        if let Some(m) = hidden_char_regex().find(line) {
            flush(&mut out, &mut run_start, &mut run_len);
            let cp = m.as_str().chars().next().map(|c| c as u32).unwrap_or(0);
            out.push(Finding::new(
                "INJECTION-HIDDEN-UNICODE",
                "medium",
                Some(relpath),
                Some(n),
                format!("invisible/bidi Unicode (U+{cp:04X}) found in document: potential prompt injection"),
                "inspect the file with a hex viewer and remove the hidden character",
            ));
            continue;
        }
        if let Some(m) = injection_regex().find(line) {
            flush(&mut out, &mut run_start, &mut run_len);
            out.push(Finding::new(
                "INJECTION-KEYWORD",
                "medium",
                Some(relpath),
                Some(n),
                format!("possible prompt injection instruction pattern detected ({:?})", m.as_str()),
                "quarantine the document or remove the instruction-like text",
            ));
            continue;
        }
        if skip_base64 {
            continue;
        }
        if flags_base64(line) {
            if run_len == 0 {
                run_start = n;
            }
            run_len += 1;
        } else {
            flush(&mut out, &mut run_start, &mut run_len);
        }
    }
    flush(&mut out, &mut run_start, &mut run_len);
    out
}

/// Every content rule, in order, for one text file.
pub fn content_findings(relpath: &str, text: &str, inbox_dir: Option<&str>) -> Vec<Finding> {
    let mut out = check_secrets(relpath, text);
    out.extend(check_private_key(relpath, text));
    out.extend(check_hidden_unicode(relpath, text));
    out.extend(check_risky_instructions(relpath, text));
    out.extend(check_llm_code(relpath, text));
    out.extend(check_untrusted_injection(relpath, text, inbox_dir));
    out
}

/// Every repo rule, once against the tree.
pub fn repo_findings(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let mut out = check_agent_settings(root);
    out.extend(check_mcp_config(root));
    out.extend(check_instructions_exist(root));
    out.extend(check_env_exposure(root, files));
    out.extend(check_lockfiles(root));
    out.extend(check_gitignore_exists(root));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_never_reveals_more_than_a_quarter() {
        assert_eq!(mask("abcdefghijklmnop"), "abcd…(16 chars)");
        assert_eq!(mask("abcd"), "a…(4 chars)");
    }

    #[test]
    fn placeholders_are_skipped_and_real_shapes_are_not() {
        assert!(is_placeholder("your-api-key-here", ""));
        assert!(is_placeholder("${TOKEN}", ""));
        assert!(!is_placeholder("sk-test-00000000000000000000000000000000", ""));
    }

    #[test]
    fn secret_finding_has_no_full_value() {
        let secret = "sk-test-00000000000000000000000000000000";
        let f = check_secrets("a.rs", &format!("let k = \"{secret}\";"));
        assert_eq!(f.len(), 1);
        assert!(!f[0].message.contains(secret));
    }
}
