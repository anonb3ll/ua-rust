//! The policy gate: call-time rules loaded from `policy_file` (YAML).
//!
//! Profiles decide which tools a session can see. The policy file decides
//! whether one visible call may run. Rule kinds:
//!
//! - `tool`: `allow`, `deny` or `require_approval` for tools matching a glob.
//! - `role`: only the named profiles or identities may call the tool.
//! - `threshold`: act when a numeric argument field crosses `max` / `min`.
//! - `rate_limit`: at most `max_calls` per caller per tool inside
//!   `window_seconds`, counted from the `tool_calls` table.
//! - `cooldown`: a minimum gap between two calls of the tool.
//! - `max_calls_per_episode`, `fatigue_band_cap`: per-episode caps. Callers
//!   carry no episode here, so these fail closed (`episode_limited`), as the
//!   original does when a call has no episode.
//!
//! Every rule may carry `bind` (agent / project / task / company scope) and,
//! except `role`, an optional `roles` filter. Deny beats allow; an allow never
//! cancels a later deny or an exhausted rate limit. `require_approval` sends
//! the call through the approval queue even when the tool is not listed in
//! `approval_tools`.
//!
//! The file is fail-closed: a file that exists but cannot be read or parsed
//! refuses every governed call with `policy_unavailable` until it is fixed. A
//! missing file is an empty, allow-everything policy. The parsed policy is
//! cached per path and reloaded when the file's modification time or size
//! changes.
//!
//! The file may also carry `profile_defaults`, an identity → profile overlay
//! that can only lower an identity's configured default (see
//! [`overlay_profile`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::SystemTime;

use globset::{Glob, GlobMatcher};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use ua_core::{ActorKind, Caller, Profile, UaError};

/// Longest rate-limit window.
pub const MAX_WINDOW_SECONDS: f64 = 3600.0;
/// Largest rate-limit `max_calls`.
pub const MAX_CALLS: i64 = 1000;
/// Keys a `bind` block may use.
pub const BIND_KEYS: [&str; 4] = ["company", "agent", "project", "task"];

/// What a rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Tool,
    Role,
    Threshold,
    RateLimit,
    Cooldown,
    MaxCallsPerEpisode,
    FatigueBandCap,
}

impl RuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleKind::Tool => "tool",
            RuleKind::Role => "role",
            RuleKind::Threshold => "threshold",
            RuleKind::RateLimit => "rate_limit",
            RuleKind::Cooldown => "cooldown",
            RuleKind::MaxCallsPerEpisode => "max_calls_per_episode",
            RuleKind::FatigueBandCap => "fatigue_band_cap",
        }
    }

    const ALL: [RuleKind; 7] = [
        RuleKind::Tool,
        RuleKind::Role,
        RuleKind::Threshold,
        RuleKind::RateLimit,
        RuleKind::Cooldown,
        RuleKind::MaxCallsPerEpisode,
        RuleKind::FatigueBandCap,
    ];

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// What a matched rule asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
    RequireApproval,
}

impl RuleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleAction::Allow => "allow",
            RuleAction::Deny => "deny",
            RuleAction::RequireApproval => "require_approval",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(RuleAction::Allow),
            "deny" => Some(RuleAction::Deny),
            "require_approval" => Some(RuleAction::RequireApproval),
            _ => None,
        }
    }
}

/// One parsed rule.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub name: String,
    pub description: String,
    /// Tool glob (`*`, `?`, `[...]`), as fnmatch.
    pub tool: String,
    pub kind: RuleKind,
    pub action: RuleAction,
    pub roles: Vec<String>,
    /// Dotted path into the arguments (threshold rules).
    pub field: Option<String>,
    pub max: Option<f64>,
    pub min: Option<f64>,
    pub window_seconds: Option<f64>,
    pub max_calls: Option<i64>,
    pub cooldown_seconds: Option<f64>,
    pub bands: BTreeMap<String, i64>,
    pub require_episode: bool,
    pub bind: BTreeMap<String, String>,
    matcher: GlobMatcher,
    /// The name a plain `tool:action` spelling reads as, when it differs.
    alias: Option<String>,
}

impl PolicyRule {
    pub fn matches_tool(&self, tool: &str) -> bool {
        self.matcher.is_match(tool)
    }

    /// Whether this rule restricts `tool` only through its alias spelling
    /// (`tool: plan_manage:delete` for `plan_delete`). Such a match takes
    /// the rule's restrictive effect alone: an `allow` (a `tool` or
    /// `threshold` allow) is skipped, and no alias match counts as a
    /// permission rule against `default_action: deny`, so an upgrade that
    /// reads the alias can tighten a policy but never loosen it.
    fn restricts_alias(&self, tool: &str) -> bool {
        self.alias.as_deref() == Some(tool)
            && !(matches!(self.kind, RuleKind::Tool | RuleKind::Threshold)
                && self.action == RuleAction::Allow)
    }

    /// False only for rules whose match can let a call through: a `tool`,
    /// `threshold` or `role` allow. Those must not match on missing claims.
    fn is_restrictive(&self) -> bool {
        !(matches!(self.kind, RuleKind::Tool | RuleKind::Threshold | RuleKind::Role)
            && self.action == RuleAction::Allow)
    }
}

/// A parsed policy file.
#[derive(Debug, Clone)]
pub struct Policy {
    pub version: i64,
    pub enabled: bool,
    /// `default_action: deny` refuses tools no permission rule matches.
    pub default_deny: bool,
    pub rules: Vec<PolicyRule>,
    /// Identity → profile overlay. Applied only when it lowers the default.
    pub profile_defaults: BTreeMap<String, String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: 1,
            enabled: true,
            default_deny: false,
            rules: Vec::new(),
            profile_defaults: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing.

/// Parse YAML text into a JSON value (mappings, lists, scalars). Non-finite
/// numbers (`.inf`, `.nan`) are refused rather than silently becoming null,
/// and scalar mapping keys become strings.
pub fn yaml_to_value(text: &str) -> Result<Value, String> {
    serde_saphyr::from_str::<Strict>(text).map(|s| s.0).map_err(|e| format!("invalid YAML: {e}"))
}

/// A JSON value deserialized strictly from YAML.
struct Strict(Value);

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a YAML value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite numbers (.inf, .nan) are not allowed"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = serde_json::Map::new();
        while let Some((Strict(k), Strict(v))) = map.next_entry()? {
            let key = match k {
                Value::String(s) => s,
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => return Err(serde::de::Error::custom("mapping keys must be scalars")),
            };
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

/// Parse and validate policy text. Errors name the offending rule.
pub fn parse_policy(text: &str) -> Result<Policy, String> {
    let data = yaml_to_value(text)?;
    parse_policy_value(&data)
}

fn finite(raw: Option<&Value>, rule: &str, key: &str) -> Result<Option<f64>, String> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.is_null() {
        return Ok(None);
    }
    let v = match raw {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
    .ok_or_else(|| format!("policy rule {rule:?}: {key:?} must be a number, got {raw}"))?;
    if !v.is_finite() {
        return Err(format!(
            "policy rule {rule:?}: {key:?} must be a finite number (a non-finite bound is a misconfiguration)"
        ));
    }
    Ok(Some(v))
}

fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Validate a parsed policy mapping.
pub fn parse_policy_value(data: &Value) -> Result<Policy, String> {
    let Some(map) = data.as_object() else {
        return Err("the policy file must be a YAML mapping".into());
    };
    let enabled = match map.get("enabled") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(other) => return Err(format!("policy 'enabled' must be true or false, got {other}")),
    };
    let default_deny = match map.get("default_action").and_then(Value::as_str) {
        None if map.get("default_action").is_none_or(Value::is_null) => false,
        Some("allow") => false,
        Some("deny") => true,
        _ => {
            return Err(format!(
                "policy default_action must be 'allow' or 'deny', got {}",
                map.get("default_action").cloned().unwrap_or(Value::Null)
            ));
        }
    };
    let version = match map.get("version") {
        None | Some(Value::Null) => 1,
        Some(v) => v.as_i64().ok_or_else(|| format!("policy 'version' must be an integer, got {v}"))?,
    };
    let profile_defaults = match map.get("profile_defaults") {
        None | Some(Value::Null) => BTreeMap::new(),
        Some(Value::Object(o)) => {
            let mut out = BTreeMap::new();
            for (k, v) in o {
                let p = v.as_str().ok_or_else(|| format!("profile_defaults.{k} must be a profile name"))?;
                Profile::parse_assignable(p).map_err(|e| format!("profile_defaults.{k}: {e}"))?;
                out.insert(k.clone(), p.to_string());
            }
            out
        }
        Some(_) => return Err("policy 'profile_defaults' must be a mapping".into()),
    };
    let raw_rules = match map.get("rules") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err("policy 'rules' must be a list".into()),
    };
    let mut rules = Vec::with_capacity(raw_rules.len());
    let mut rate_names = BTreeSet::new();
    for item in &raw_rules {
        let rule = parse_rule(item)?;
        if rule.kind == RuleKind::RateLimit && !rate_names.insert(rule.name.clone()) {
            return Err(format!(
                "policy rule name {:?} is used by more than one rate_limit rule; rate-limit budgets are keyed by name",
                rule.name
            ));
        }
        rules.push(rule);
    }
    Ok(Policy { version, enabled, default_deny, rules, profile_defaults })
}

fn parse_rule(item: &Value) -> Result<PolicyRule, String> {
    let Some(r) = item.as_object() else {
        return Err("each policy rule must be a YAML mapping".into());
    };
    let str_of = |k: &str, default: &str| -> String {
        match r.get(k) {
            None | Some(Value::Null) => default.to_string(),
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
        }
    };
    let name = str_of("name", "unnamed_rule");
    let type_text = str_of("type", "max_calls_per_episode");
    let kind = RuleKind::parse(&type_text).ok_or_else(|| {
        let names: Vec<&str> = RuleKind::ALL.iter().map(|k| k.as_str()).collect();
        format!("unknown policy rule type {type_text:?}; supported: {}", names.join(", "))
    })?;
    let action = match r.get("action") {
        None | Some(Value::Null) if kind == RuleKind::Role => RuleAction::Allow,
        None | Some(Value::Null) => RuleAction::Deny,
        Some(v) => {
            let text = v.as_str().unwrap_or_default();
            RuleAction::parse(text).ok_or_else(|| {
                format!("policy rule {name:?}: action must be allow, deny or require_approval, got {v}")
            })?
        }
    };
    let tool = str_of("tool", "*");
    let matcher = Glob::new(&tool)
        .map_err(|e| format!("policy rule {name:?}: invalid tool pattern {tool:?}: {e}"))?
        .compile_matcher();
    // A plain `tool:action` spelling of an action that has a standalone tool
    // (`plan_manage:delete` for `plan_delete`) also restricts that tool, so a
    // deny, approval, role, threshold or limit holds as meant. It never
    // permits it: see [`PolicyRule::restricts_alias`].
    let alias = crate::routes::is_plain_name(&tool)
        .then(|| crate::routes::canonical_gate_name(&tool).into_owned())
        .filter(|c| *c != tool);
    let roles = match r.get("roles") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) => {
            let s = s.trim();
            if s.is_empty() { Vec::new() } else { vec![s.to_string()] }
        }
        Some(Value::Array(a)) => a.iter().filter_map(scalar_text).filter(|s| !s.is_empty()).collect(),
        Some(_) => return Err(format!("policy rule {name:?}: 'roles' must be a string or a list")),
    };
    let field = r.get("field").and_then(scalar_text).filter(|s| !s.is_empty());
    let max_calls = match r.get("max_calls") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_i64() {
            Some(n) => Some(n),
            None => return Err(format!("policy rule {name:?}: 'max_calls' must be an integer, got {v}")),
        },
    };
    let bands = match r.get("bands") {
        None | Some(Value::Null) => BTreeMap::new(),
        Some(Value::Object(o)) => {
            let mut out = BTreeMap::new();
            for (k, v) in o {
                let n = v
                    .as_i64()
                    .ok_or_else(|| format!("policy rule {name:?}: band {k:?} must be an integer"))?;
                out.insert(k.to_ascii_lowercase(), n);
            }
            out
        }
        Some(_) => return Err(format!("policy rule {name:?}: 'bands' must be a mapping")),
    };
    let require_episode = match r.get("require_episode") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(v) => {
            return Err(format!("policy rule {name:?}: 'require_episode' must be true or false, got {v}"));
        }
    };
    let bind = parse_bind(&name, r.get("bind"))?;
    let rule = PolicyRule {
        description: str_of("description", ""),
        tool,
        kind,
        action,
        roles,
        field,
        max: finite(r.get("max"), &name, "max")?,
        min: finite(r.get("min"), &name, "min")?,
        window_seconds: finite(r.get("window_seconds"), &name, "window_seconds")?,
        max_calls,
        cooldown_seconds: finite(r.get("cooldown_seconds"), &name, "cooldown_seconds")?,
        bands,
        require_episode,
        bind,
        matcher,
        alias,
        name,
    };
    validate_rule(&rule)?;
    Ok(rule)
}

fn parse_bind(name: &str, raw: Option<&Value>) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let Some(raw) = raw else { return Ok(out) };
    let obj = match raw {
        Value::Null => return Ok(out),
        Value::Object(o) => o,
        _ => return Err(format!("policy rule {name:?}: 'bind' must be a mapping")),
    };
    for (k, v) in obj {
        if !BIND_KEYS.contains(&k.as_str()) {
            return Err(format!(
                "policy rule {name:?}: bind key {k:?} is not one of {}",
                BIND_KEYS.join(", ")
            ));
        }
        let text = scalar_text(v)
            .ok_or_else(|| format!("policy rule {name:?}: bind '{k}' must be a string or integer"))?;
        if text.is_empty() {
            return Err(format!("policy rule {name:?}: bind '{k}' must be non-empty"));
        }
        out.insert(k.clone(), text);
    }
    Ok(out)
}

fn validate_rule(rule: &PolicyRule) -> Result<(), String> {
    let name = &rule.name;
    match rule.kind {
        RuleKind::Threshold => {
            if rule.field.is_none() {
                return Err(format!("policy rule {name:?} of type 'threshold' requires a 'field' path"));
            }
            if rule.max.is_none() && rule.min.is_none() {
                return Err(format!("policy rule {name:?} of type 'threshold' requires 'max' and/or 'min'"));
            }
        }
        RuleKind::Role => {
            if rule.roles.is_empty() {
                return Err(format!("policy rule {name:?} of type 'role' requires a non-empty 'roles' list"));
            }
        }
        RuleKind::RateLimit => {
            match rule.max_calls {
                Some(n) if (1..=MAX_CALLS).contains(&n) => {}
                other => {
                    return Err(format!(
                        "policy rule {name:?}: 'max_calls' for rate_limit must be an integer from 1 to {MAX_CALLS}, got {}",
                        other.map(|n| n.to_string()).unwrap_or_else(|| "nothing".into())
                    ));
                }
            }
            match rule.window_seconds {
                None => {
                    return Err(format!(
                        "policy rule {name:?} of type 'rate_limit' requires 'window_seconds'"
                    ));
                }
                Some(w) if !(1.0..=MAX_WINDOW_SECONDS).contains(&w) => {
                    return Err(format!(
                        "policy rule {name:?}: window_seconds must be from 1 to {MAX_WINDOW_SECONDS}s, got {w}"
                    ));
                }
                Some(_) => {}
            }
            if rule.action != RuleAction::Deny {
                return Err(format!(
                    "policy rule {name:?} of type 'rate_limit' denies when the window is exhausted; action must be deny"
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Loading with mtime-based reload.

struct CacheEntry {
    stamp: (Option<SystemTime>, u64),
    loaded: Result<Arc<Policy>, String>,
}

static CACHE: LazyLock<Mutex<HashMap<PathBuf, CacheEntry>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Load the policy at `path`. A missing file is the empty allow policy; a file
/// that cannot be read or parsed is an error (callers fail closed). The parse
/// is cached until the file's modification time or size changes.
pub fn load(path: &Path) -> Result<Arc<Policy>, String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Ok(mut c) = CACHE.lock() {
                c.remove(path);
            }
            return Ok(Arc::new(Policy::default()));
        }
        Err(e) => return Err(format!("cannot read the policy file: {e}")),
    };
    let stamp = (meta.modified().ok(), meta.len());
    if let Ok(c) = CACHE.lock()
        && let Some(entry) = c.get(path)
        && entry.stamp == stamp
    {
        return entry.loaded.clone();
    }
    let loaded = match std::fs::read_to_string(path) {
        Ok(text) => parse_policy(&text).map(Arc::new).map_err(|e| format!("invalid policy file: {e}")),
        Err(e) => Err(format!("cannot read the policy file: {e}")),
    };
    if let Ok(p) = &loaded {
        let unknown = unknown_action_keys(p);
        if !unknown.is_empty() {
            tracing::warn!(
                path = %path.display(),
                "policy rules name no known tool action, so they match nothing: {}",
                unknown.join("; ")
            );
        }
    }
    if let Ok(mut c) = CACHE.lock() {
        c.insert(path.to_path_buf(), CacheEntry { stamp, loaded: loaded.clone() });
    }
    loaded
}

/// Rules whose `tool` is a plain `tool:action` name that is not a gate key
/// as written (see [`crate::routes::check_gate_name`]), each with the
/// reason: a key that matches nothing, or a spelling read as another name
/// (`plan_manage:delete` matches `plan_delete`). Glob patterns and plain
/// tool names are not checked, as before.
pub fn unknown_action_keys(policy: &Policy) -> Vec<String> {
    policy
        .rules
        .iter()
        .filter(|r| r.tool.contains(':') && crate::routes::is_plain_name(&r.tool))
        .filter_map(|r| {
            crate::routes::check_gate_name(&r.tool).err().map(|e| format!("rule {:?}: {e}", r.name))
        })
        .collect()
}

/// Drop the cached parse of `path` (after a write through config revisions).
pub fn invalidate(path: &Path) {
    if let Ok(mut c) = CACHE.lock() {
        c.remove(path);
    }
}

// ---------------------------------------------------------------------------
// Profile overlay.

/// Whether an overlay may move an identity from `code_default` to `chosen`:
/// the same profile, or a strictly lower rank that grants no tool (among
/// `tools`) the default refuses. Rank alone is not enough: `operator` sits
/// below `developer` and still grants `approval_resolve`.
pub fn overlay_allowed<'a>(
    chosen: Profile,
    code_default: Profile,
    tools: impl IntoIterator<Item = &'a str>,
) -> bool {
    if !chosen.assignable() {
        return false;
    }
    if chosen == code_default {
        return true;
    }
    if chosen.rank() >= code_default.rank() {
        return false;
    }
    !tools.into_iter().any(|t| chosen.allows_tool(t) && !code_default.allows_tool(t))
}

/// The overlay profile for `label`, when the policy names one that is allowed
/// over `code_default`.
pub fn overlay_profile<'a>(
    policy: &Policy,
    label: &str,
    code_default: Profile,
    tools: impl IntoIterator<Item = &'a str>,
) -> Option<Profile> {
    let chosen: Profile = policy.profile_defaults.get(label)?.parse().ok()?;
    overlay_allowed(chosen, code_default, tools).then_some(chosen)
}

// ---------------------------------------------------------------------------
// Evaluation.

/// A refusal: the error returned to the caller plus the rule that fired.
#[derive(Debug)]
pub struct Refusal {
    pub error: UaError,
    pub rule: String,
}

impl Refusal {
    fn new(reason_code: &str, rule: &str, msg: impl Into<String>) -> Self {
        Self { error: UaError::denied(reason_code, msg), rule: rule.to_string() }
    }
}

/// A call the policy lets through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Send the call through the approval queue. Holds the rule names.
    RequireApproval(Vec<String>),
}

/// One live claim (a `doing` task held by the caller).
#[derive(Debug, Clone, Default)]
struct Claim {
    company: String,
    project: String,
    task: String,
}

/// Server-side context a binding is matched against.
#[derive(Debug, Clone, Default)]
struct Scope {
    agent: String,
    claims: Vec<Claim>,
}

/// The identity a binding or role sees. Anonymous callers are namespaced so
/// they can neither match an `agent` bind nor borrow a real agent's claims.
fn scope_agent(caller: &Caller) -> String {
    if caller.kind == ActorKind::Anonymous {
        format!("unverified:{}", caller.label)
    } else {
        caller.label.clone()
    }
}

fn bind_needs_claims(bind: &BTreeMap<String, String>) -> bool {
    ["company", "project", "task"].iter().any(|k| bind.get(*k).is_some_and(|v| v != "*"))
}

/// Every specified bind key must match; `*` and an omitted key are open.
/// Claim keys must all match one claim, not a union across claims. A caller
/// with no claims is not known to be outside the scope, so a restrictive rule
/// (`unclaimed_matches`) treats it as inside.
fn binding_matches(bind: &BTreeMap<String, String>, scope: &Scope, unclaimed_matches: bool) -> bool {
    if bind.is_empty() {
        return true;
    }
    if let Some(agent) = bind.get("agent")
        && agent != "*"
        && &scope.agent != agent
    {
        return false;
    }
    let keys: Vec<&str> = ["company", "project", "task"]
        .into_iter()
        .filter(|k| bind.get(*k).is_some_and(|v| v != "*"))
        .collect();
    if keys.is_empty() {
        return true;
    }
    let field = |c: &Claim, k: &str| -> String {
        match k {
            "company" => c.company.clone(),
            "project" => c.project.clone(),
            _ => c.task.clone(),
        }
    };
    if scope.claims.is_empty() {
        return unclaimed_matches;
    }
    if scope.claims.iter().any(|c| keys.iter().all(|k| field(c, k) == bind[*k])) {
        return true;
    }
    if !unclaimed_matches {
        return false;
    }
    // A blank field on a claim is not a known conflict.
    scope.claims.iter().any(|c| {
        keys.iter().all(|k| {
            let v = field(c, k);
            v.is_empty() || v == bind[*k]
        })
    })
}

/// The live claims of `label` in its organization `org`.
fn resolve_claims(conn: &Connection, org: &str, label: &str) -> rusqlite::Result<Vec<Claim>> {
    let now = ua_core::time::now();
    let mut stmt = conn.prepare(
        "SELECT id, project FROM tasks WHERE org_id = ?3 AND claimed_by = ?1 AND status = 'doing' \
         AND (lock_expires_at IS NULL OR lock_expires_at > ?2)",
    )?;
    let rows = stmt.query_map(params![label, now, org], |r| {
        let id: i64 = r.get(0)?;
        let project: Option<String> = r.get(1)?;
        Ok(Claim {
            // Tasks carry no company/org column in this hub.
            company: String::new(),
            project: project.map(|p| p.trim().to_string()).unwrap_or_default(),
            task: id.to_string(),
        })
    })?;
    rows.collect()
}

/// Who a `roles` list is matched against: the caller's identity label and
/// its profile, kept apart so a label that happens to equal a profile name
/// never stands in for the profile (or the other way round).
struct Principals {
    agent: Option<String>,
    profile: Profile,
}

fn principals(caller: &Caller, scope: &Scope) -> Principals {
    Principals { agent: (!scope.agent.is_empty()).then(|| scope.agent.clone()), profile: caller.profile }
}

/// One `roles` entry: `agent:<label>` names an identity, `profile:<name>` a
/// profile (a legacy profile name is accepted). A bare entry is a profile
/// when it parses as one, else an identity label.
fn role_matches(entry: &str, who: &Principals) -> bool {
    if let Some(label) = entry.strip_prefix("agent:") {
        return who.agent.as_deref() == Some(label);
    }
    if let Some(name) = entry.strip_prefix("profile:") {
        return name.parse::<Profile>().is_ok_and(|p| p == who.profile);
    }
    match entry.parse::<Profile>() {
        Ok(p) => p == who.profile,
        Err(_) => who.agent.as_deref() == Some(entry),
    }
}

fn roles_apply(rule: &PolicyRule, who: &Principals) -> bool {
    rule.roles.is_empty() || rule.roles.iter().any(|r| role_matches(r, who))
}

fn payload_field<'a>(args: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = args;
    for part in path.split('.') {
        cur = cur.as_object()?.get(part)?;
    }
    (!cur.is_null()).then_some(cur)
}

fn numeric(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

fn unavailable(rule: &str, e: impl std::fmt::Display) -> Refusal {
    Refusal::new("policy_unavailable", rule, format!("policy evaluation failed closed: {e}"))
}

/// Seconds between `ts` (storage form) and now.
fn age_seconds(ts: &str) -> Option<f64> {
    let t = ua_core::time::parse_ts(ts)?;
    Some((ua_core::time::now_ms() - t.as_millisecond()) as f64 / 1000.0)
}

/// Completed calls of `tool` by `label` in organization `org` inside the
/// last `window` seconds, including calls of a consolidated tool whose action
/// ran `tool` (`action_tool`). Timestamps have second precision: a call
/// counts while `now - start < window`.
pub fn recent_calls(
    conn: &Connection,
    org: &str,
    tool: &str,
    label: &str,
    window: f64,
) -> rusqlite::Result<i64> {
    let cutoff_ms = ua_core::time::now_ms() - (window * 1000.0) as i64;
    let cutoff = jiff::Timestamp::from_millisecond(cutoff_ms)
        .map(ua_core::time::format_ts)
        .unwrap_or_else(|_| ua_core::time::now());
    conn.query_row(
        "SELECT COUNT(*) FROM tool_calls WHERE org_id = ?4 AND caller = ?2 AND (tool = ?1 OR action_tool = ?1) \
         AND started_at > ?3",
        params![tool, label, cutoff, org],
        |r| r.get(0),
    )
}

/// Evaluate `policy` for one call. Reads claims, rate-limit counts and
/// cooldowns from `conn`; any read failure refuses the call.
pub fn evaluate(
    conn: &Connection,
    policy: &Policy,
    caller: &Caller,
    tool: &str,
    args: &Value,
) -> Result<Verdict, Refusal> {
    evaluate_with(conn, policy, caller, tool, args, policy.default_deny)
}

/// Evaluate `policy` for the action a consolidated tool's call runs, under
/// the action's own name (a standalone tool, or `tool:action`; see
/// [`crate::routes`]) and on the action's arguments. Every rule applies as
/// for a direct call, except `default_action: deny`: the consolidated tool
/// itself was already held to it, and a rule allowing that tool must not be
/// undone because no rule names each of its actions.
pub fn evaluate_routed(
    conn: &Connection,
    policy: &Policy,
    caller: &Caller,
    tool: &str,
    args: &Value,
) -> Result<Verdict, Refusal> {
    evaluate_with(conn, policy, caller, tool, args, false)
}

fn evaluate_with(
    conn: &Connection,
    policy: &Policy,
    caller: &Caller,
    tool: &str,
    args: &Value,
    default_deny: bool,
) -> Result<Verdict, Refusal> {
    if !policy.enabled {
        return Ok(Verdict::Allow);
    }
    let tool_matched: Vec<&PolicyRule> =
        policy.rules.iter().filter(|r| r.matches_tool(tool) || r.restricts_alias(tool)).collect();
    if tool_matched.is_empty() && !default_deny {
        return Ok(Verdict::Allow);
    }
    let mut scope = Scope { agent: scope_agent(caller), claims: Vec::new() };
    if caller.kind != ActorKind::Anonymous && tool_matched.iter().any(|r| bind_needs_claims(&r.bind)) {
        scope.claims = resolve_claims(conn, &caller.org_id, &caller.label).map_err(|e| unavailable("", e))?;
    }
    let who = principals(caller, &scope);
    // `role` rules are allow-lists and still fire for callers outside `roles`;
    // other kinds treat `roles` as a scope filter. Bindings filter every kind.
    let matching: Vec<&PolicyRule> = tool_matched
        .into_iter()
        .filter(|r| {
            binding_matches(&r.bind, &scope, r.is_restrictive())
                && (r.kind == RuleKind::Role || roles_apply(r, &who))
        })
        .collect();
    let has_permission_rule = matching.iter().any(|r| r.kind != RuleKind::RateLimit && r.matches_tool(tool));
    if !has_permission_rule && default_deny {
        return Err(Refusal::new(
            "default_deny",
            "",
            format!("tool {tool} is denied by the default policy action"),
        ));
    }
    if matching.is_empty() {
        return Ok(Verdict::Allow);
    }

    let mut deferred: Vec<String> = Vec::new();
    let mut act = |rule: &PolicyRule, reason_code: &str| -> Result<(), Refusal> {
        match rule.action {
            RuleAction::Allow => Ok(()),
            RuleAction::RequireApproval => {
                deferred.push(rule.name.clone());
                Ok(())
            }
            RuleAction::Deny => {
                let detail = if rule.description.is_empty() {
                    String::new()
                } else {
                    format!(": {}", rule.description)
                };
                Err(Refusal::new(
                    reason_code,
                    &rule.name,
                    format!("tool {tool} denied by policy rule {:?}{detail}", rule.name),
                ))
            }
        }
    };

    for rule in &matching {
        match rule.kind {
            RuleKind::RateLimit => {}
            RuleKind::Tool => act(rule, "policy_deny")?,
            RuleKind::Role => {
                if !roles_apply(rule, &who) {
                    return Err(Refusal::new(
                        "role_denied",
                        &rule.name,
                        format!(
                            "tool {tool} denied by role policy {:?}: requires one of {:?}",
                            rule.name, rule.roles
                        ),
                    ));
                }
                act(rule, "policy_deny")?;
            }
            RuleKind::Threshold => {
                let path = rule.field.as_deref().unwrap_or_default();
                let Some(raw) = payload_field(args, path) else {
                    return Err(Refusal::new(
                        "threshold_invalid",
                        &rule.name,
                        format!(
                            "policy rule {:?} requires argument field {path:?} (fail-closed: missing value)",
                            rule.name
                        ),
                    ));
                };
                let Some(value) = numeric(raw).filter(|v| v.is_finite()) else {
                    return Err(Refusal::new(
                        "threshold_invalid",
                        &rule.name,
                        format!(
                            "policy rule {:?}: argument field {path:?} must be a finite number, got {raw}",
                            rule.name
                        ),
                    ));
                };
                let breached = rule.max.is_some_and(|m| value > m) || rule.min.is_some_and(|m| value < m);
                if breached {
                    act(rule, "threshold_breached")?;
                }
            }
            RuleKind::Cooldown | RuleKind::MaxCallsPerEpisode | RuleKind::FatigueBandCap => {
                let episode_rule = rule.require_episode || rule.kind != RuleKind::Cooldown;
                if episode_rule {
                    // Callers carry no episode id, so an episode rule cannot be
                    // satisfied: fail closed, as the original does without one.
                    return Err(Refusal::new(
                        "episode_limited",
                        &rule.name,
                        format!(
                            "policy rule {:?} requires a valid episode_id, but none was provided",
                            rule.name
                        ),
                    ));
                }
                let cooldown = rule.cooldown_seconds.unwrap_or(0.0);
                if cooldown > 0.0 {
                    let last: Option<String> = conn
                        // Per caller: one identity's call must not put every
                        // other identity into cooldown.
                        .query_row(
                            "SELECT MAX(started_at) FROM tool_calls WHERE org_id = ?3 AND caller = ?2 \
                             AND (tool = ?1 OR action_tool = ?1)",
                            params![tool, caller.label, caller.org_id],
                            |r| r.get(0),
                        )
                        .optional()
                        .map_err(|e| unavailable(&rule.name, e))?
                        .flatten();
                    if let Some(age) = last.as_deref().and_then(age_seconds)
                        && age < cooldown
                    {
                        return Err(Refusal::new(
                            "episode_limited",
                            &rule.name,
                            format!(
                                "cooldown active for tool {tool}: {:.1}s remaining (rule {:?})",
                                cooldown - age,
                                rule.name
                            ),
                        ));
                    }
                }
            }
        }
    }

    // Rate limits are checked after every deny and before any approval pass.
    for rule in matching.iter().filter(|r| r.kind == RuleKind::RateLimit) {
        let (Some(max_calls), Some(window)) = (rule.max_calls, rule.window_seconds) else { continue };
        let used = recent_calls(conn, &caller.org_id, tool, &caller.label, window)
            .map_err(|e| unavailable(&rule.name, e))?;
        if used >= max_calls {
            return Err(Refusal::new(
                "rate_limited",
                &rule.name,
                format!(
                    "tool {tool} rate limited by policy rule {:?}: {max_calls} calls per {window}s for this caller",
                    rule.name
                ),
            ));
        }
    }

    if deferred.is_empty() { Ok(Verdict::Allow) } else { Ok(Verdict::RequireApproval(deferred)) }
}

// ---------------------------------------------------------------------------
// Prod-action gate.

/// The action vocabulary of always-gated tools, as in the original hub.
pub fn prod_action(tool: &str) -> &str {
    match tool {
        "git_merge_task" => "merge",
        "task_delete" => "delete",
        "deploy" => "deploy",
        "fleet_host_action" => "restart",
        "oauth_device_manage" | "mcp_server_revoke" => "revoke",
        "managed_secret_delete" | "github_credential_clear" => "delete",
        "node_dispatch" | "node_followup" | "acp_permission" | "dispatch_task" | "dispatch_resume" => {
            "dispatch"
        }
        other => other,
    }
}

/// The identity half of the prod-action gate for an always-gated tool:
/// anonymous network callers, revoked agents and unscoped agents are refused
/// before any approval pass is looked at, so a pass approved earlier cannot
/// carry a call the caller is no longer entitled to make.
pub fn check_prod_action(cfg: &ua_core::Config, caller: &Caller, tool: &str) -> Result<(), Refusal> {
    use ua_core::identity::Transport;
    let action = prod_action(tool);
    if caller.kind == ActorKind::Anonymous
        && matches!(caller.transport, Transport::Http | Transport::Mcp | Transport::Slack)
    {
        return Err(Refusal::new(
            "anonymous_prod_action",
            "",
            format!("anonymous callers cannot run prod action {action:?}; authenticate first"),
        ));
    }
    if cfg.revoked_agents.iter().any(|a| a == &caller.label) {
        return Err(Refusal::new(
            "agent_revoked",
            "",
            format!("agent {:?} is revoked from prod action {action:?}", caller.label),
        ));
    }
    if let Some(scopes) = cfg.prod_scopes(&caller.label)
        && !scopes.iter().any(|s| s == action || s == tool)
    {
        return Err(Refusal::new(
            "scope_denied",
            "",
            format!("agent {:?} is not scoped for prod action {action:?}", caller.label),
        ));
    }
    Ok(())
}
