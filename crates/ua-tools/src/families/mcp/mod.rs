//! Downstream MCP servers: the reviewed server registry and the gateway.
//!
//! An operator registers a server behind a one-time human approval
//! (`mcp_server_register`), or declares it in config (`[mcp_servers.<name>]`).
//! The registration is the whole boundary for that server: its transport
//! (`stdio` command and arguments, or a `streamable_http` URL with an address
//! scope), the managed secrets injected into it by name, the read/write
//! classification of every downstream tool it may call, which profiles may
//! call its reads, and how long the review lasts. Nothing the downstream
//! server says about itself (tool annotations, its tool list) widens it.
//!
//! Tools: `mcp_server_register`, `mcp_server_review` (renew the review
//! window), `mcp_server_revoke` (all three need a one-time human approval),
//! `mcp_server_list`, and `mcp_gateway` (see [`gateway`]).
//!
//! A server is usable only while it is registered, unrevoked and inside its
//! review window. A config entry's window is its `review_expires_at`, or a
//! later `mcp_server_review` of the same spec. Revoking a config entry holds
//! until its spec changes: an edited entry is a new declaration.
//!
//! Reads: `read_profiles` lists the profiles whose sessions may call the read
//! tools. Left empty it means humans and configured operator identities
//! (`human_identities`, `lifecycle_operators`) only; a registration that
//! should serve agents names their profiles explicitly. An anonymous caller
//! (a local stdio process, or HTTP without enforced auth) never reads from a
//! server that injects secrets, whatever `read_profiles` says.
//!
//! Secrets and revocation: a server's secrets are bound to its name
//! (`mcp:<name>`), and a revoked name may be registered again, perhaps at
//! another endpoint. So revoking orphans them: the revocation's approval
//! payload lists every secret bound to `mcp:<name>` (name and fingerprint),
//! and the approved revocation deletes them. A re-registration starts with no
//! credential; the operator sets it again for the new spec.

pub mod gateway;
pub mod redact;
pub mod scope;

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{Caller, Config, Profile, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, ledger};

use self::scope::AddressScope;
use super::dispatch::executor::looks_secret;
use super::managed_secrets::{self, mcp_consumer};
use crate::approvals::{self, GateOutcome};
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "mcp_servers.v1",
    sql: "
CREATE TABLE IF NOT EXISTS mcp_servers (
    name TEXT PRIMARY KEY,
    source TEXT NOT NULL CHECK (source IN ('registry', 'config')),
    spec_json TEXT NOT NULL,
    spec_sha256 TEXT NOT NULL,
    registered_by TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    reviewed_by TEXT,
    reviewed_at TEXT,
    review_expires_at TEXT,
    revoked_by TEXT,
    revoked_at TEXT,
    approval_id INTEGER
);
",
};

/// Ledger channel of registry changes.
pub const REGISTRY_CHANNEL: &str = "agent.mcp_server";
const MAX_TOOLS: usize = 256;
const MAX_ARGS: usize = 64;
const MAX_ARG_CHARS: usize = 1024;
const MAX_ENV: usize = 32;
const MAX_ENV_VALUE: usize = 4096;
const MAX_SECRETS: usize = 8;
pub const DEFAULT_TIMEOUT_S: u64 = 30;
const MAX_TIMEOUT_S: u64 = 120;
const MAX_REVIEW_DAYS: u32 = 365;

// --- the spec -------------------------------------------------------------------

/// How the hub reaches a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// A child process speaking MCP on stdin/stdout.
    Stdio,
    /// MCP Streamable HTTP at a URL.
    StreamableHttp,
}

/// What a downstream tool does, as the reviewer classified it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Changes nothing. Allowed to the server's `read_profiles`.
    Read,
    /// Anything else. Every call needs a one-time human approval.
    Write,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// One managed secret injected into a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// Managed secret name. It must be bound to consumer `mcp:<server>`.
    pub secret: String,
    /// `bearer` (HTTP `Authorization: Bearer`), `header:<Name>` (another HTTP
    /// header) or `env:<NAME>` (an environment variable of a stdio child).
    pub inject: String,
}

/// Where a secret goes, parsed from [`SecretRef::inject`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inject {
    Bearer,
    Header(String),
    Env(String),
}

/// A downstream MCP server as registered and reviewed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerSpec {
    /// `stdio` or `streamable_http`.
    pub transport: TransportKind,
    /// stdio: absolute path of the program. Run without a shell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// stdio: arguments (at most 64, 1024 characters each).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// stdio: absolute working directory (default: the system temp directory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// stdio: extra non-secret environment for the child. The child never
    /// inherits the hub's environment; credentials go in `secrets`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// streamable_http: the endpoint URL. https, or http to a loopback or
    /// private address; no credentials, query or fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// streamable_http: the only addresses the host may resolve to
    /// (`public`, `private` or `loopback`; default `public`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_scope: Option<AddressScope>,
    /// Managed secrets injected by name (at most 8).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretRef>,
    /// Every downstream tool the gateway may call, classified `read` or
    /// `write` (1-256). Any other tool is refused.
    pub tools: BTreeMap<String, Access>,
    /// Profiles whose sessions may call the read tools. Empty: humans and
    /// configured operator identities only. Anonymous callers never read from
    /// a server with secrets. Writes always need a human approval.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_profiles: Vec<String>,
    /// Seconds one gateway call may take, connection included (1-120, default 30).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_s: Option<u64>,
}

/// `[a-z0-9][a-z0-9_-]{0,63}`.
pub fn check_server_name(name: &str) -> UaResult<()> {
    let mut chars = name.chars();
    let ok = name.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'));
    if ok { Ok(()) } else { Err(UaError::invalid("server name must match [a-z0-9][a-z0-9_-]{0,63}")) }
}

/// MCP tool names: 1-128 of `[A-Za-z0-9_.-]`.
fn check_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

fn env_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Names a child's environment may never carry from the spec: loader and
/// interpreter hooks and the hub's own namespace.
fn env_reserved(name: &str) -> bool {
    matches!(
        name,
        "PATH"
            | "PYTHONPATH"
            | "PYTHONSTARTUP"
            | "NODE_OPTIONS"
            | "PERL5LIB"
            | "RUBYOPT"
            | "BASH_ENV"
            | "ENV"
    ) || name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || name.starts_with("UA_")
}

/// HTTP headers a secret may not be injected as.
fn header_reserved(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "host"
            | "authorization"
            | "content-length"
            | "content-type"
            | "content-encoding"
            | "accept"
            | "accept-encoding"
            | "connection"
            | "transfer-encoding"
            | "te"
            | "upgrade"
            | "cookie"
            | "last-event-id"
            | "proxy-authorization"
    ) || n.starts_with("mcp-")
}

impl SecretRef {
    pub fn parse(&self) -> UaResult<Inject> {
        let bad = || {
            UaError::invalid(format!(
                "secret {:?}: inject must be `bearer`, `header:<Name>` or `env:<NAME>`",
                self.secret
            ))
        };
        if self.inject == "bearer" {
            return Ok(Inject::Bearer);
        }
        if let Some(h) = self.inject.strip_prefix("header:") {
            if h.is_empty() || h.len() > 64 || !h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(bad());
            }
            if header_reserved(h) {
                return Err(UaError::invalid(format!("secret {:?}: header {h:?} is reserved", self.secret)));
            }
            return Ok(Inject::Header(h.to_string()));
        }
        if let Some(e) = self.inject.strip_prefix("env:") {
            if !env_name_ok(e) {
                return Err(bad());
            }
            if env_reserved(e) {
                return Err(UaError::invalid(format!("secret {:?}: {e:?} is a reserved name", self.secret)));
            }
            return Ok(Inject::Env(e.to_string()));
        }
        Err(bad())
    }
}

/// The URL parts the gateway pins to.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub url: url::Url,
    /// Lowercased host as it appears in the URL (an IP literal without brackets).
    pub host: String,
    pub literal: Option<std::net::IpAddr>,
    pub scope: AddressScope,
}

fn check_url(raw: &str, scope: AddressScope) -> UaResult<Endpoint> {
    let url = url::Url::parse(raw).map_err(|_| UaError::invalid("url is not a valid URL"))?;
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(UaError::invalid("url must be https or http"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UaError::invalid("url must not carry credentials; use secrets"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(UaError::invalid("url must not carry a query or fragment"));
    }
    let (host, literal) = match url.host() {
        Some(url::Host::Domain(d)) => (d.trim_end_matches('.').to_ascii_lowercase(), None),
        Some(url::Host::Ipv4(ip)) => (ip.to_string(), Some(std::net::IpAddr::V4(ip))),
        Some(url::Host::Ipv6(ip)) => (ip.to_string(), Some(std::net::IpAddr::V6(ip))),
        None => return Err(UaError::invalid("url has no host")),
    };
    if host.is_empty() {
        return Err(UaError::invalid("url has no host"));
    }
    match literal {
        Some(ip) => {
            if !scope::allowed(ip, scope) {
                return Err(UaError::invalid(format!(
                    "url host {ip} is not a {} address; register the scope it belongs to",
                    scope.as_str()
                )));
            }
        }
        None => {
            if scope::names_loopback(&host) && scope != AddressScope::Loopback {
                return Err(UaError::invalid(format!(
                    "url host {host:?} is loopback; register address_scope loopback"
                )));
            }
            if host.rsplit('.').next().is_some_and(|l| l.chars().all(|c| c.is_ascii_digit())) {
                return Err(UaError::invalid(format!(
                    "url host {host:?} is a non-canonical numeric address"
                )));
            }
        }
    }
    if scheme == "http" && scope == AddressScope::Public {
        return Err(UaError::invalid("url must be https, or http to a loopback or private address"));
    }
    Ok(Endpoint { url, host, literal, scope })
}

impl ServerSpec {
    /// Validate and normalize in place (defaults made explicit, so the spec
    /// hash is stable). `server` is the name it is registered under.
    pub fn normalize(&mut self, server: &str) -> UaResult<()> {
        check_server_name(server)?;
        if self.tools.is_empty() || self.tools.len() > MAX_TOOLS {
            return Err(UaError::invalid(format!("tools must classify 1-{MAX_TOOLS} downstream tools")));
        }
        if let Some(bad) = self.tools.keys().find(|t| !check_tool_name(t)) {
            return Err(UaError::invalid(format!("tool name {bad:?} is not a valid MCP tool name")));
        }
        for p in &self.read_profiles {
            p.parse::<Profile>().map_err(UaError::invalid)?;
        }
        self.read_profiles.sort();
        self.read_profiles.dedup();
        let timeout = self.timeout_s.unwrap_or(DEFAULT_TIMEOUT_S);
        if !(1..=MAX_TIMEOUT_S).contains(&timeout) {
            return Err(UaError::invalid(format!("timeout_s must be 1-{MAX_TIMEOUT_S}")));
        }
        self.timeout_s = Some(timeout);
        if self.secrets.len() > MAX_SECRETS {
            return Err(UaError::invalid(format!("at most {MAX_SECRETS} secrets")));
        }
        let mut targets = Vec::new();
        for s in &self.secrets {
            managed_secrets::check_name(&s.secret)?;
            let inject = s.parse()?;
            let ok = matches!(
                (&inject, self.transport),
                (Inject::Env(_), TransportKind::Stdio)
                    | (Inject::Bearer | Inject::Header(_), TransportKind::StreamableHttp)
            );
            if !ok {
                return Err(UaError::invalid(format!(
                    "secret {:?}: {} cannot be injected into a {} server",
                    s.secret,
                    s.inject,
                    if self.transport == TransportKind::Stdio { "stdio" } else { "streamable_http" }
                )));
            }
            let target = match &inject {
                Inject::Bearer => "bearer".to_string(),
                Inject::Header(h) => format!("header:{}", h.to_ascii_lowercase()),
                Inject::Env(e) => format!("env:{e}"),
            };
            if targets.contains(&target) {
                return Err(UaError::invalid(format!("two secrets are injected as {target}")));
            }
            targets.push(target);
        }
        match self.transport {
            TransportKind::Stdio => {
                if self.url.is_some() || self.address_scope.is_some() {
                    return Err(UaError::invalid("a stdio server takes no url or address_scope"));
                }
                let command = self.command.as_deref().unwrap_or("");
                let path = std::path::Path::new(command);
                if command.is_empty()
                    || command.contains('\0')
                    || !path.is_absolute()
                    || path.components().any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    return Err(UaError::invalid(
                        "a stdio server needs command: an absolute path to the program",
                    ));
                }
                if self.args.len() > MAX_ARGS
                    || self.args.iter().any(|a| a.chars().count() > MAX_ARG_CHARS || a.contains('\0'))
                {
                    return Err(UaError::invalid(format!(
                        "args must be at most {MAX_ARGS} strings of at most {MAX_ARG_CHARS} characters"
                    )));
                }
                if let Some(cwd) = &self.cwd
                    && !std::path::Path::new(cwd).is_absolute()
                {
                    return Err(UaError::invalid("cwd must be an absolute path"));
                }
                if self.env.len() > MAX_ENV {
                    return Err(UaError::invalid(format!("at most {MAX_ENV} env entries")));
                }
                for (k, v) in &self.env {
                    if !env_name_ok(k) || v.contains('\0') || v.len() > MAX_ENV_VALUE {
                        return Err(UaError::invalid(format!("env entry {k:?} is not usable")));
                    }
                    if env_reserved(k) {
                        return Err(UaError::invalid(format!("env may not set {k:?}")));
                    }
                    if looks_secret(k) {
                        return Err(UaError::invalid(format!(
                            "env {k:?} looks like a credential; store it with managed_secret_set and inject it \
                             with secrets: [{{secret, inject: \"env:{k}\"}}]"
                        )));
                    }
                    if targets.contains(&format!("env:{k}")) {
                        return Err(UaError::invalid(format!("env {k:?} is also a secret target")));
                    }
                }
            }
            TransportKind::StreamableHttp => {
                if self.command.is_some()
                    || !self.args.is_empty()
                    || self.cwd.is_some()
                    || !self.env.is_empty()
                {
                    return Err(UaError::invalid(
                        "a streamable_http server takes no command, args, cwd or env",
                    ));
                }
                let scope = *self.address_scope.get_or_insert(AddressScope::Public);
                let raw = self
                    .url
                    .as_deref()
                    .ok_or_else(|| UaError::invalid("a streamable_http server needs url"))?;
                let ep = check_url(raw, scope)?;
                self.url = Some(ep.url.to_string());
            }
        }
        Ok(())
    }

    /// The URL parts, for a validated streamable_http spec.
    pub fn endpoint(&self) -> UaResult<Endpoint> {
        let scope = self.address_scope.unwrap_or(AddressScope::Public);
        check_url(self.url.as_deref().unwrap_or(""), scope)
    }

    /// Hex SHA-256 of the canonical JSON form.
    pub fn sha256(&self) -> String {
        let canon = serde_json::to_string(self).unwrap_or_default();
        hex::encode(Sha256::digest(canon.as_bytes()))
    }

    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_s.unwrap_or(DEFAULT_TIMEOUT_S))
    }

    /// Whether `caller` may call this server's read tools. An anonymous
    /// caller never reads from a server that injects secrets; an empty
    /// `read_profiles` admits humans and configured operator identities only.
    pub fn reads_allowed(&self, cfg: &Config, caller: &Caller) -> bool {
        if caller.kind == ua_core::ActorKind::Anonymous && !self.secrets.is_empty() {
            return false;
        }
        if caller.is_human() {
            return true;
        }
        if self.read_profiles.is_empty() {
            return managed_secrets::is_secret_admin(cfg, caller);
        }
        self.read_profiles.iter().any(|p| p == caller.profile.as_str())
    }
}

// --- effective servers -----------------------------------------------------------

/// Where a server was declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Registry,
    Config,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Config => "config",
        }
    }
}

/// One server with its review state, ready for the gateway.
#[derive(Debug, Clone)]
pub struct Server {
    pub name: String,
    pub source: Source,
    pub spec: ServerSpec,
    pub spec_sha256: String,
    pub review_expires_at: Option<String>,
    pub reviewed_by: Option<String>,
    pub revoked_at: Option<String>,
    pub registered_by: Option<String>,
    pub registered_at: Option<String>,
}

impl Server {
    /// `active`, `revoked`, `review_expired` or `review_required`.
    pub fn status(&self) -> &'static str {
        if self.revoked_at.is_some() {
            return "revoked";
        }
        match self.review_expires_at.as_deref().and_then(ua_core::time::parse_ts) {
            None => "review_required",
            Some(t) if t <= jiff::Timestamp::now() => "review_expired",
            Some(_) => "active",
        }
    }

    /// The refusal for a server that may not be called, or `Ok`.
    pub fn usable(&self) -> UaResult<()> {
        match self.status() {
            "active" => Ok(()),
            "revoked" => {
                Err(UaError::denied("server_revoked", format!("MCP server {:?} is revoked", self.name)))
            }
            "review_expired" => Err(UaError::denied(
                "review_expired",
                format!(
                    "the review of MCP server {:?} expired at {}; renew it with mcp_server_review",
                    self.name,
                    self.review_expires_at.as_deref().unwrap_or("?")
                ),
            )),
            _ => Err(UaError::denied(
                "review_required",
                format!(
                    "MCP server {:?} has no review window; set review_expires_at in config or run mcp_server_review",
                    self.name
                ),
            )),
        }
    }

    fn public(&self, conn: &Connection) -> Value {
        let secrets: Vec<Value> = self
            .spec
            .secrets
            .iter()
            .map(|s| {
                let stored =
                    managed_secrets::bound_to(conn, &s.secret, &mcp_consumer(&self.name)).unwrap_or(false);
                json!({ "secret": s.secret, "inject": s.inject, "stored": stored })
            })
            .collect();
        let (reads, writes): (Vec<_>, Vec<_>) =
            self.spec.tools.iter().partition(|(_, a)| **a == Access::Read);
        json!({
            "name": self.name,
            "source": self.source.as_str(),
            "status": self.status(),
            "transport": self.spec.transport,
            "command": self.spec.command,
            "args": self.spec.args,
            "url": self.spec.url,
            "address_scope": self.spec.address_scope,
            "secrets": secrets,
            "consumer": mcp_consumer(&self.name),
            "read_tools": reads.into_iter().map(|(t, _)| t).collect::<Vec<_>>(),
            "write_tools": writes.into_iter().map(|(t, _)| t).collect::<Vec<_>>(),
            "read_profiles": self.spec.read_profiles,
            "timeout_s": self.spec.timeout_s,
            "spec_sha256": self.spec_sha256,
            "review_expires_at": self.review_expires_at,
            "reviewed_by": self.reviewed_by,
            "revoked_at": self.revoked_at,
            "registered_by": self.registered_by,
            "registered_at": self.registered_at,
        })
    }
}

/// A stored registry row.
struct Row {
    source: String,
    spec_json: String,
    spec_sha256: String,
    registered_by: String,
    registered_at: String,
    reviewed_by: Option<String>,
    review_expires_at: Option<String>,
    revoked_at: Option<String>,
}

fn load_row(conn: &Connection, name: &str) -> UaResult<Option<Row>> {
    Ok(conn
        .query_row(
            "SELECT source, spec_json, spec_sha256, registered_by, registered_at, reviewed_by, review_expires_at, \
             revoked_at FROM mcp_servers WHERE name = ?1",
            [name],
            |r| {
                Ok(Row {
                    source: r.get(0)?,
                    spec_json: r.get(1)?,
                    spec_sha256: r.get(2)?,
                    registered_by: r.get(3)?,
                    registered_at: r.get(4)?,
                    reviewed_by: r.get(5)?,
                    review_expires_at: r.get(6)?,
                    revoked_at: r.get(7)?,
                })
            },
        )
        .optional()?)
}

/// A timestamp or a `YYYY-MM-DD` date (midnight UTC), in storage form.
fn parse_expiry(raw: &str) -> Option<String> {
    let t = ua_core::time::parse_ts(raw).or_else(|| ua_core::time::parse_ts(&format!("{raw}T00:00:00Z")))?;
    Some(ua_core::time::format_ts(t))
}

/// Parse one config entry into a spec and its configured review expiry.
fn config_spec(name: &str, raw: &Value) -> UaResult<(ServerSpec, Option<String>)> {
    let Value::Object(map) = raw else {
        return Err(UaError::invalid(format!("[mcp_servers.{name}] must be a table")));
    };
    let mut map = map.clone();
    let expiry = match map.remove("review_expires_at") {
        None => None,
        Some(Value::String(s)) => Some(parse_expiry(&s).ok_or_else(|| {
            UaError::invalid(format!(
                "[mcp_servers.{name}] review_expires_at must be a date or RFC 3339 timestamp"
            ))
        })?),
        Some(_) => {
            return Err(UaError::invalid(format!("[mcp_servers.{name}] review_expires_at must be a string")));
        }
    };
    let mut spec: ServerSpec = serde_json::from_value(Value::Object(map))
        .map_err(|e| UaError::invalid(format!("[mcp_servers.{name}]: {e}")))?;
    spec.normalize(name).map_err(|e| UaError::invalid(format!("[mcp_servers.{name}]: {e}")))?;
    Ok((spec, expiry))
}

fn later(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => {
            let ta = ua_core::time::parse_ts(&a);
            let tb = ua_core::time::parse_ts(&b);
            if tb > ta { Some(b) } else { Some(a) }
        }
        (a, b) => a.or(b),
    }
}

/// Resolve one server by name: a registry row, or a config entry overlaid
/// with any review or revocation recorded for its exact spec.
pub fn resolve(conn: &Connection, cfg: &Config, name: &str) -> UaResult<Server> {
    let row = load_row(conn, name)?;
    if let Some(raw) = cfg.mcp_servers.get(name) {
        let (spec, cfg_expiry) = config_spec(name, raw).map_err(|e| {
            UaError::denied("server_misconfigured", format!("MCP server {name:?} is misconfigured: {e}"))
        })?;
        let sha = spec.sha256();
        let mut server = Server {
            name: name.to_string(),
            source: Source::Config,
            spec,
            spec_sha256: sha.clone(),
            review_expires_at: cfg_expiry,
            reviewed_by: None,
            revoked_at: None,
            registered_by: None,
            registered_at: None,
        };
        if let Some(row) = row {
            if row.source != "config" {
                return Err(UaError::denied(
                    "server_misconfigured",
                    format!("MCP server {name:?} is declared in config and also registered; remove one"),
                ));
            }
            if row.spec_sha256 == sha {
                server.review_expires_at = later(server.review_expires_at, row.review_expires_at);
                server.reviewed_by = row.reviewed_by;
                server.revoked_at = row.revoked_at;
            }
        }
        return Ok(server);
    }
    let Some(row) = row.filter(|r| r.source == "registry") else {
        return Err(UaError::not_found(format!("no MCP server named {name:?} is registered")));
    };
    let spec: ServerSpec = serde_json::from_str(&row.spec_json).map_err(|_| {
        UaError::denied("server_misconfigured", format!("MCP server {name:?} has a corrupt record"))
    })?;
    if spec.sha256() != row.spec_sha256 {
        return Err(UaError::denied(
            "server_misconfigured",
            format!("MCP server {name:?} has a corrupt record"),
        ));
    }
    Ok(Server {
        name: name.to_string(),
        source: Source::Registry,
        spec,
        spec_sha256: row.spec_sha256,
        review_expires_at: row.review_expires_at,
        reviewed_by: row.reviewed_by,
        revoked_at: row.revoked_at,
        registered_by: Some(row.registered_by),
        registered_at: Some(row.registered_at),
    })
}

/// Every known server name: registry rows and config entries.
fn all_names(conn: &Connection, cfg: &Config) -> UaResult<Vec<String>> {
    let mut stmt = conn.prepare("SELECT name FROM mcp_servers WHERE source = 'registry'")?;
    let mut names: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    names.extend(cfg.mcp_servers.keys().cloned());
    names.sort();
    names.dedup();
    Ok(names)
}

// --- shared gating ---------------------------------------------------------------

/// Who may register, review or revoke: a human or an operator.
fn require_operator(ctx: &ToolCtx, tool: &str) -> UaResult<()> {
    if ctx.caller.kind == ua_core::ActorKind::Anonymous {
        return Err(UaError::denied(
            "identity_required",
            format!("{tool} requires an authenticated identity"),
        ));
    }
    if !managed_secrets::is_secret_admin(ctx.hub.cfg(), &ctx.caller) {
        return Err(UaError::denied("operator_only", format!("{tool} is for a human or an operator")));
    }
    crate::policy::check_prod_action(ctx.hub.cfg(), &ctx.caller, tool).map_err(|r| r.error)
}

/// Gate inside a write transaction; `Ok(Err(id))` when pending.
fn gate(
    tx: &mut ua_store::WriteTx<'_>,
    cfg: &Config,
    caller: &Caller,
    tool: &str,
    payload: &Value,
) -> UaResult<Result<i64, i64>> {
    match approvals::gate(tx, cfg, caller, tool, payload)? {
        GateOutcome::Pass { approval_id } => Ok(Ok(approval_id)),
        GateOutcome::Pending { approval_id } => Ok(Err(approval_id)),
        GateOutcome::Denied { approval_id, reason } => Err(UaError::denied(
            "approval_denied",
            format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
        )),
    }
}

fn pending(tool: &str, r: Result<Value, i64>) -> UaResult<Value> {
    r.map_err(|approval_id| UaError::ApprovalRequired { tool: tool.into(), approval_id })
}

fn review_days(cfg: &Config, asked: Option<u32>) -> UaResult<u32> {
    let days = asked.unwrap_or(cfg.mcp_review_ttl_days.clamp(1, MAX_REVIEW_DAYS));
    if !(1..=MAX_REVIEW_DAYS).contains(&days) {
        return Err(UaError::invalid(format!("review_days must be 1-{MAX_REVIEW_DAYS}")));
    }
    Ok(days)
}

fn expiry_after(days: u32) -> String {
    let t = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_hours(i64::from(days) * 24))
        .unwrap_or(jiff::Timestamp::MAX);
    ua_core::time::format_ts(t)
}

// --- tools -----------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterArgs {
    /// Server name, `[a-z0-9][a-z0-9_-]{0,63}`. Its secrets use consumer `mcp:<name>`.
    pub name: String,
    /// The server: transport, command or URL, secrets, tool classification.
    pub server: ServerSpec,
    /// Days the review lasts (1-365, default `mcp_review_ttl_days`).
    pub review_days: Option<u32>,
}

async fn mcp_server_register(ctx: ToolCtx, a: RegisterArgs) -> UaResult<Value> {
    require_operator(&ctx, "mcp_server_register")?;
    let mut spec = a.server;
    spec.normalize(&a.name)?;
    let days = review_days(ctx.hub.cfg(), a.review_days)?;
    if ctx.hub.cfg().mcp_servers.contains_key(&a.name) {
        return Err(UaError::conflict_code(
            "server_in_config",
            format!("MCP server {:?} is declared in config; edit the config entry instead", a.name),
        ));
    }
    let sha = spec.sha256();
    let spec_json = serde_json::to_string(&spec)?;
    let (hub, caller, name) = (ctx.hub.clone(), ctx.caller.clone(), a.name);
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            if let Some(row) = load_row(tx, &name)?
                && row.revoked_at.is_none()
            {
                return Err(UaError::conflict_code(
                    "server_registered",
                    format!("MCP server {name:?} is already registered; revoke it before registering it again"),
                ));
            }
            let payload = json!({
                "op": "register", "name": name, "server": serde_json::from_str::<Value>(&spec_json)?,
                "spec_sha256": sha, "review_days": days,
            });
            let approval_id = match gate(tx, hub.cfg(), &caller, "mcp_server_register", &payload)? {
                Ok(id) => id,
                Err(id) => return Ok(Err(id)),
            };
            let (now, expires) = (ua_core::time::now(), expiry_after(days));
            tx.execute(
                "INSERT INTO mcp_servers (name, source, spec_json, spec_sha256, registered_by, registered_at, \
                 reviewed_by, reviewed_at, review_expires_at, approval_id) \
                 VALUES (?1, 'registry', ?2, ?3, ?4, ?5, ?4, ?5, ?6, ?7) \
                 ON CONFLICT(name) DO UPDATE SET source = 'registry', spec_json = ?2, spec_sha256 = ?3, \
                 registered_by = ?4, registered_at = ?5, reviewed_by = ?4, reviewed_at = ?5, \
                 review_expires_at = ?6, revoked_by = NULL, revoked_at = NULL, approval_id = ?7",
                params![name, spec_json, sha, caller.label, now, expires, approval_id],
            )?;
            ledger::append(
                tx,
                EventInput::new(
                    REGISTRY_CHANNEL,
                    json!({ "op": "registered", "name": name, "spec_sha256": sha, "review_expires_at": expires,
                            "approval_id": approval_id }),
                )
                .by(caller.label.clone()),
            )?;
            let server = resolve(tx, hub.cfg(), &name)?;
            Ok(Ok(json!({ "server": server.public(tx), "approval_id": approval_id })))
        })
        .await?;
    pending("mcp_server_register", out)
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NameArgs {
    /// Server name.
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewArgs {
    /// Server name.
    pub name: String,
    /// Days from now the renewed review lasts (1-365, default `mcp_review_ttl_days`).
    pub review_days: Option<u32>,
}

async fn mcp_server_review(ctx: ToolCtx, a: ReviewArgs) -> UaResult<Value> {
    require_operator(&ctx, "mcp_server_review")?;
    check_server_name(&a.name)?;
    let days = review_days(ctx.hub.cfg(), a.review_days)?;
    let (hub, caller, name) = (ctx.hub.clone(), ctx.caller.clone(), a.name);
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let server = resolve(tx, hub.cfg(), &name)?;
            if server.revoked_at.is_some() {
                return Err(UaError::denied("server_revoked", format!("MCP server {name:?} is revoked")));
            }
            let payload = json!({ "op": "review", "name": name, "spec_sha256": server.spec_sha256, "review_days": days });
            let approval_id = match gate(tx, hub.cfg(), &caller, "mcp_server_review", &payload)? {
                Ok(id) => id,
                Err(id) => return Ok(Err(id)),
            };
            let (now, expires) = (ua_core::time::now(), expiry_after(days));
            match server.source {
                Source::Registry => {
                    tx.execute(
                        "UPDATE mcp_servers SET reviewed_by = ?2, reviewed_at = ?3, review_expires_at = ?4, \
                         approval_id = ?5 WHERE name = ?1",
                        params![name, caller.label, now, expires, approval_id],
                    )?;
                }
                Source::Config => {
                    let spec_json = serde_json::to_string(&server.spec)?;
                    tx.execute(
                        "INSERT INTO mcp_servers (name, source, spec_json, spec_sha256, registered_by, registered_at, \
                         reviewed_by, reviewed_at, review_expires_at, approval_id) \
                         VALUES (?1, 'config', ?2, ?3, ?4, ?5, ?4, ?5, ?6, ?7) \
                         ON CONFLICT(name) DO UPDATE SET spec_json = ?2, spec_sha256 = ?3, reviewed_by = ?4, \
                         reviewed_at = ?5, review_expires_at = ?6, revoked_by = NULL, revoked_at = NULL, approval_id = ?7",
                        params![name, spec_json, server.spec_sha256, caller.label, now, expires, approval_id],
                    )?;
                }
            }
            ledger::append(
                tx,
                EventInput::new(
                    REGISTRY_CHANNEL,
                    json!({ "op": "reviewed", "name": name, "spec_sha256": server.spec_sha256,
                            "review_expires_at": expires, "approval_id": approval_id }),
                )
                .by(caller.label.clone()),
            )?;
            let server = resolve(tx, hub.cfg(), &name)?;
            Ok(Ok(json!({ "server": server.public(tx), "approval_id": approval_id })))
        })
        .await?;
    pending("mcp_server_review", out)
}

async fn mcp_server_revoke(ctx: ToolCtx, a: NameArgs) -> UaResult<Value> {
    require_operator(&ctx, "mcp_server_revoke")?;
    check_server_name(&a.name)?;
    let (hub, caller, name) = (ctx.hub.clone(), ctx.caller.clone(), a.name);
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            // A config entry that does not parse is already refused by the
            // gateway; it is fixed or removed in the config, not revoked.
            let server = resolve(tx, hub.cfg(), &name)?;
            if server.revoked_at.is_some() {
                return Ok(Ok(json!({ "server": server.public(tx), "already_revoked": true })));
            }
            // The secrets this revocation orphans, bound into the approval: a
            // secret set or rotated after the request needs a new approval.
            let consumer = mcp_consumer(&name);
            let orphans: Vec<Value> = managed_secrets::bound_secrets(tx, &consumer)?
                .into_iter()
                .map(|(secret, fingerprint)| json!({ "secret": secret, "fingerprint": fingerprint }))
                .collect();
            let payload = json!({
                "op": "revoke", "name": name, "spec_sha256": server.spec_sha256, "orphaned_secrets": orphans,
            });
            let approval_id = match gate(tx, hub.cfg(), &caller, "mcp_server_revoke", &payload)? {
                Ok(id) => id,
                Err(id) => return Ok(Err(id)),
            };
            let orphaned =
                managed_secrets::orphan_consumer(tx, &consumer, &caller.label, approval_id, "mcp_server_revoked")?;
            let now = ua_core::time::now();
            match server.source {
                Source::Registry => {
                    tx.execute(
                        "UPDATE mcp_servers SET revoked_by = ?2, revoked_at = ?3, approval_id = ?4 WHERE name = ?1",
                        params![name, caller.label, now, approval_id],
                    )?;
                }
                Source::Config => {
                    let spec_json = serde_json::to_string(&server.spec)?;
                    tx.execute(
                        "INSERT INTO mcp_servers (name, source, spec_json, spec_sha256, registered_by, registered_at, \
                         revoked_by, revoked_at, approval_id) VALUES (?1, 'config', ?2, ?3, ?4, ?5, ?4, ?5, ?6) \
                         ON CONFLICT(name) DO UPDATE SET spec_json = ?2, spec_sha256 = ?3, revoked_by = ?4, \
                         revoked_at = ?5, approval_id = ?6",
                        params![name, spec_json, server.spec_sha256, caller.label, now, approval_id],
                    )?;
                }
            }
            ledger::append(
                tx,
                EventInput::new(
                    REGISTRY_CHANNEL,
                    json!({ "op": "revoked", "name": name, "spec_sha256": server.spec_sha256, "approval_id": approval_id,
                            "orphaned_secrets": orphaned }),
                )
                .by(caller.label.clone()),
            )?;
            let server = resolve(tx, hub.cfg(), &name)?;
            Ok(Ok(json!({ "server": server.public(tx), "approval_id": approval_id, "orphaned_secrets": orphaned })))
        })
        .await?;
    pending("mcp_server_revoke", out)
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Also list revoked servers.
    #[serde(default)]
    pub include_revoked: bool,
}

async fn mcp_server_list(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    let cfg = ctx.hub.cfg().clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut servers = Vec::new();
            for name in all_names(c, &cfg)? {
                match resolve(c, &cfg, &name) {
                    Ok(s) if s.revoked_at.is_some() && !a.include_revoked => {}
                    Ok(s) => servers.push(s.public(c)),
                    Err(e) => servers.push(json!({ "name": name, "status": "misconfigured", "error": e.to_string() })),
                }
            }
            Ok(json!({ "servers": servers, "count": servers.len(), "review_ttl_days": cfg.mcp_review_ttl_days }))
        })
        .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "mcp_server_register",
            "Register a downstream MCP server for mcp_gateway. For a human or an operator, and needs a one-time \
             human approval bound to the whole spec: transport (stdio command/args, or a streamable_http URL with \
             its address_scope), managed secrets injected by name (consumer mcp:<name>), the read/write \
             classification of every downstream tool it may call, read_profiles (empty: humans and configured \
             operator identities only) and timeout. The review lasts review_days (default mcp_review_ttl_days). \
             A revoked name may be registered again; its old secrets were deleted at revocation and must be set \
             again.",
            mcp_server_register,
        )
        .gates_in_handler()
        .family("mcp"),
    );
    r.add(
        tool(
            "mcp_server_review",
            "Renew a downstream MCP server's review window (registry or config entry) for review_days from now. \
             For a human or an operator; needs a one-time human approval bound to the server's current spec.",
            mcp_server_review,
        )
        .gates_in_handler()
        .family("mcp"),
    );
    r.add(
        tool(
            "mcp_server_revoke",
            "Revoke a downstream MCP server so mcp_gateway refuses it. For a human or an operator; needs a \
             one-time human approval, whose payload lists the managed secrets bound to mcp:<name>: the approved \
             revocation deletes them, so a later registration of the name never inherits a credential. A \
             revoked config entry stays revoked until its spec changes.",
            mcp_server_revoke,
        )
        .always_gated()
        .gates_in_handler()
        .family("mcp"),
    );
    r.add(
        tool(
            "mcp_server_list",
            "List downstream MCP servers (registry and config): status (active, review_expired, review_required, \
             revoked, misconfigured), transport, URL or command, address scope, secret names and whether each \
             is stored, read and write tools, read_profiles and the review window. Never secret values.",
            mcp_server_list,
        )
        .read_only()
        .family("mcp"),
    );
    gateway::register(r);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(url: &str, scope: Option<AddressScope>) -> ServerSpec {
        ServerSpec {
            transport: TransportKind::StreamableHttp,
            command: None,
            args: vec![],
            cwd: None,
            env: BTreeMap::new(),
            url: Some(url.into()),
            address_scope: scope,
            secrets: vec![],
            tools: BTreeMap::from([("search".into(), Access::Read)]),
            read_profiles: vec![],
            timeout_s: None,
        }
    }

    fn norm(mut s: ServerSpec) -> UaResult<ServerSpec> {
        s.normalize("docs").map(|_| s)
    }

    #[test]
    fn urls_are_pinned_to_their_scope() {
        let s = norm(http("https://docs.example.com/mcp", None)).unwrap();
        assert_eq!(
            s.address_scope,
            Some(AddressScope::Public),
            "the default scope is explicit after normalizing"
        );
        assert_eq!(s.timeout_s, Some(DEFAULT_TIMEOUT_S));
        assert!(norm(http("http://docs.example.com/mcp", None)).is_err(), "plain http to a public host");
        assert!(norm(http("https://127.0.0.1/mcp", None)).is_err(), "loopback literal in a public scope");
        assert!(norm(http("http://localhost:8080/mcp", None)).is_err(), "localhost in a public scope");
        assert!(norm(http("http://localhost:8080/mcp", Some(AddressScope::Loopback))).is_ok());
        assert!(norm(http("http://127.0.0.1:8080/mcp", Some(AddressScope::Loopback))).is_ok());
        assert!(norm(http("http://10.0.0.2/mcp", Some(AddressScope::Loopback))).is_err());
        assert!(norm(http("http://10.0.0.2/mcp", Some(AddressScope::Private))).is_ok());
        assert!(norm(http("http://169.254.169.254/mcp", Some(AddressScope::Private))).is_err(), "metadata");
        assert!(norm(http("https://u:p@docs.example.com/mcp", None)).is_err(), "userinfo");
        assert!(norm(http("https://docs.example.com/mcp?k=v", None)).is_err(), "query");
        assert!(norm(http("https://docs.example.com/mcp#f", None)).is_err(), "fragment");
        assert!(norm(http("ftp://docs.example.com/mcp", None)).is_err(), "scheme");
        assert!(norm(http("https://2130706433/mcp", None)).is_err(), "numeric host");
    }

    #[test]
    fn secrets_go_only_where_the_transport_takes_them() {
        let mut s = http("https://docs.example.com/mcp", None);
        s.secrets = vec![SecretRef { secret: "docs-token".into(), inject: "bearer".into() }];
        assert!(norm(s.clone()).is_ok());
        s.secrets[0].inject = "env:DOCS_TOKEN".into();
        assert!(norm(s.clone()).is_err(), "env injection into an HTTP server");
        s.secrets[0].inject = "header:Authorization".into();
        assert!(norm(s.clone()).is_err(), "reserved header");
        s.secrets[0].inject = "header:X-Api-Key".into();
        assert!(norm(s).is_ok());
    }

    #[test]
    fn stdio_specs() {
        let mut s = ServerSpec {
            transport: TransportKind::Stdio,
            command: Some("/usr/local/bin/srv".into()),
            url: None,
            address_scope: None,
            ..http("https://x.example.com", None)
        };
        assert!(norm(s.clone()).is_ok());
        s.command = Some("srv".into());
        assert!(norm(s.clone()).is_err(), "relative command");
        s.command = Some("/usr/local/bin/srv".into());
        s.env.insert("API_TOKEN".into(), "x".into());
        assert!(norm(s.clone()).is_err(), "credential-looking env");
        s.env.clear();
        s.env.insert("LD_PRELOAD".into(), "/x.so".into());
        assert!(norm(s.clone()).is_err(), "loader hook");
        s.env.clear();
        s.env.insert("LOG_LEVEL".into(), "debug".into());
        s.secrets = vec![SecretRef { secret: "srv-key".into(), inject: "env:SRV_TOKEN".into() }];
        assert!(norm(s.clone()).is_ok());
        s.secrets[0].inject = "env:UA_AGENT_TOKENS".into();
        assert!(norm(s.clone()).is_err(), "hub namespace");
        s.secrets[0].inject = "bearer".into();
        assert!(norm(s).is_err(), "bearer into a stdio child");
    }

    #[test]
    fn tool_classification_is_required() {
        let mut s = http("https://docs.example.com/mcp", None);
        s.tools.clear();
        assert!(norm(s.clone()).is_err());
        s.tools.insert("bad name!".into(), Access::Read);
        assert!(norm(s).is_err());
    }

    #[test]
    fn spec_hash_is_stable_across_spelling() {
        let a = norm(http("https://docs.example.com/mcp", None)).unwrap();
        let b = norm(http("https://DOCS.example.com/mcp", Some(AddressScope::Public))).unwrap();
        assert_eq!(a.sha256(), b.sha256());
    }

    #[test]
    fn expiry_dates() {
        assert_eq!(parse_expiry("2027-01-02").as_deref(), Some("2027-01-02T00:00:00+00:00"));
        assert_eq!(parse_expiry("2027-01-02T03:04:05Z").as_deref(), Some("2027-01-02T03:04:05+00:00"));
        assert!(parse_expiry("soon").is_none());
    }
}
