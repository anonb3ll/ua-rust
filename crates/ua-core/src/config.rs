//! Configuration.
//!
//! Layers, lowest to highest precedence:
//! 1. built-in defaults,
//! 2. a TOML file (`$UA_CONFIG`, else `$UA_HOME/config.toml` when present),
//! 3. `UA_*` environment variables (`UA_VAULT_PATH` sets `vault_path`).
//!
//! List settings accept either a TOML array or a comma/space separated string,
//! so `UA_VAULT_WRITE_DIRS="Inbox,Logs"` works from the environment.
//! Secret values are held in [`SecretString`] and never appear in `Debug`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};

/// Programs `run_cmd` may start when `UA_SHELL_ALLOWLIST` is unset.
pub const DEFAULT_SHELL_ALLOWLIST: &[&str] = &[
    "ls", "cat", "head", "tail", "grep", "find", "wc", "sed", "awk", "git", "python3", "uv", "pytest",
    "ruff", "diff", "sort", "uniq", "which", "echo", "date", "cargo",
];

/// Vault directories agents may write to by default.
pub const DEFAULT_VAULT_WRITE_DIRS: &[&str] = &["Inbox", "Logs", "Wiki"];

/// The full runtime configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    /// Data directory: database, keys, caches.
    pub home: PathBuf,
    /// SQLite database path. Defaults to `$home/ua.db`.
    pub db_path: Option<PathBuf>,
    /// Root that `fs_write`, `run_cmd` and `git_*` are confined to.
    pub workspace: Option<PathBuf>,
    /// Extra read-only roots for `fs_read`/`fs_list`/`fs_search`.
    #[serde(deserialize_with = "string_or_list")]
    pub read_roots: Vec<PathBuf>,
    /// Markdown knowledge vault (Obsidian-compatible). Vault tools are off when unset.
    pub vault_path: Option<PathBuf>,
    /// Vault directories (relative to the vault) agents may write to.
    #[serde(deserialize_with = "string_or_list")]
    pub vault_write_dirs: Vec<String>,
    /// Vault directory holding raw captures (the steward inbox).
    pub vault_inbox_dir: String,
    /// Refuse a `vault_write` overwrite of an existing note without `expected_revision`.
    pub vault_require_revision: bool,
    /// Lowest memory-note confidence `memory_promote` accepts.
    pub promote_min_confidence: f64,
    /// Obsidian Local REST API base URL (loopback only), e.g. `https://127.0.0.1:27124`.
    pub obsidian_api_url: Option<String>,
    /// Obsidian Local REST API key (`UA_OBSIDIAN_API_KEY`).
    #[serde(skip_serializing)]
    pub obsidian_api_key: Option<SecretString>,
    /// HTTP listen address. Keep it on loopback and put a proxy in front.
    pub bind: SocketAddr,
    /// Require a verified credential on every HTTP request.
    pub enforce_auth: bool,
    /// Host headers the HTTP hub answers (DNS-rebinding guard).
    #[serde(deserialize_with = "string_or_list")]
    pub allowed_hosts: Vec<String>,
    /// Static agent tokens: `label:token,label:token` or a path to a file of such lines.
    #[serde(skip_serializing)]
    pub agent_tokens: Option<SecretString>,
    /// Identities that are humans (operators). Only humans resolve approvals.
    #[serde(deserialize_with = "string_or_list")]
    pub human_identities: Vec<String>,
    /// Identities that may run lifecycle operator actions (`node_retire`,
    /// `node_unretire`). Unset means `human_identities`; an empty list means
    /// nobody. Setting it replaces that default rather than adding to it.
    #[serde(default, deserialize_with = "opt_string_or_list", skip_serializing_if = "Option::is_none")]
    pub lifecycle_operators: Option<Vec<String>>,
    /// Remote nodes one agent may hold in service (registered, not retired).
    /// A registration of a new node name past it is refused (`node_limit`).
    pub node_max_per_agent: u32,
    /// How long a node work item queued for a node that is not live waits
    /// for it before it fails (`waiting_expired_node_offline`), in seconds.
    /// Clamped to 60-604800.
    pub node_queue_wait_s: u64,
    /// Seconds between node queue sweeps under `ua serve` (expired waits,
    /// lapsed leases, undelivered command notices). 0 turns the sweep off;
    /// claims still sweep their own node.
    pub node_wait_sweep_s: u64,
    /// Planning canvas boards one agent may create (`graph_canvas_write`).
    /// Creating a new board past it is refused (`canvas_limit`); updating a
    /// board is never capped.
    pub graph_canvas_max_boards_per_agent: u32,
    /// Planning canvas boards the hub holds in all. Creating a new board past
    /// it is refused (`canvas_limit`).
    pub graph_canvas_max_boards: u32,
    /// Prior scenes kept per board for `graph_canvas_history` and
    /// `graph_canvas_restore`; older revisions are dropped. 0 keeps none.
    pub graph_canvas_history_max: u32,
    /// Programs `run_cmd` may run. Setting it replaces the default list.
    #[serde(deserialize_with = "string_or_list")]
    pub shell_allowlist: Vec<String>,
    /// Cargo config files above a workspace root that `run_cmd` lets cargo
    /// read, each pinned to the SHA-256 of its content. Cargo is refused
    /// under any other ancestor cargo config, and under a listed one whose
    /// content no longer matches. TOML only:
    /// `trusted_cargo_configs = [{ path = "~/.cargo/config.toml", sha256 = "..." }]`.
    pub trusted_cargo_configs: Vec<TrustedCargoConfig>,
    /// Tools that always need a one-time human approval.
    #[serde(deserialize_with = "string_or_list")]
    pub approval_tools: Vec<String>,
    /// Hours an approved, unconsumed one-shot pass stays valid.
    pub approval_pass_ttl_hours: f64,
    /// Policy rules file (YAML).
    pub policy_file: Option<PathBuf>,
    /// Agents revoked from every always-gated (prod) action, whatever approvals they hold.
    #[serde(deserialize_with = "string_or_list")]
    pub revoked_agents: Vec<String>,
    /// Prod-action scopes: label → `merge|delete|...` (actions or tool names).
    /// Empty means nobody is restricted; once set, an unlisted agent has no scope.
    pub agent_scopes: BTreeMap<String, String>,
    /// Identity label → default profile name. Unlisted identities get `developer`.
    pub profiles: BTreeMap<String, String>,
    /// Per-agent workspace overrides: label → root (or `"deny"`).
    pub agent_workspaces: BTreeMap<String, String>,
    /// Embedding model for semantic memory search (needs the `embeddings` feature).
    pub embed_model: String,
    /// Edition: `full` (default) or `core`, which hides ledger features.
    pub edition: String,
    /// Public base URL of the hub, e.g. `https://hub.example.com`. It is the
    /// OAuth issuer, the passkey origin and the base of login links. Defaults
    /// to `http://<bind>`.
    pub public_url: Option<String>,
    /// Run the OAuth 2.1 authorization server for remote MCP clients.
    pub oauth_enabled: bool,
    /// Accept RFC 7591 dynamic client registration at `/oauth/register`.
    pub oauth_dcr_enabled: bool,
    /// Hours a dynamically registered client that never received a grant
    /// is kept before it is pruned.
    pub oauth_dcr_unused_ttl_hours: f64,
    /// Dynamic client registrations allowed per remote address per hour.
    pub oauth_dcr_rate_per_hour: u32,
    /// Accept URL client ids (Client ID Metadata Documents). The hub then
    /// fetches public HTTPS URLs on behalf of unauthenticated `/oauth/authorize` calls.
    pub oauth_cimd_enabled: bool,
    /// Hosts whose client metadata documents may be fetched (a leading `.`
    /// admits subdomains). Empty admits any public host.
    #[serde(deserialize_with = "string_or_list")]
    pub oauth_cimd_allow: Vec<String>,
    /// Identities a human may bind an OAuth grant to on the consent page.
    /// The first one is preselected. Human identities are never allowed.
    #[serde(deserialize_with = "string_or_list")]
    pub oauth_identities: Vec<String>,
    /// Default profile for OAuth identities without an entry in `profiles`.
    pub oauth_profile: String,
    /// Access token lifetime in seconds.
    pub oauth_access_ttl_secs: u64,
    /// Refresh token lifetime in days.
    pub oauth_refresh_ttl_days: u64,
    /// Confidential clients for the `client_credentials` grant:
    /// `client_id|secret|identity` entries separated by commas or newlines.
    #[serde(skip_serializing)]
    pub oauth_client_credentials: Option<SecretString>,
    /// Send the browser session cookie with `Secure`. Turn off only for plain
    /// `http://localhost` development.
    pub ui_cookie_secure: bool,
    /// Browser session lifetime in hours.
    pub ui_session_ttl_hours: u64,
    /// Lifetime of a `ua login-link` URL in seconds.
    pub login_link_ttl_secs: u64,
    /// WebAuthn relying-party id. Defaults to the host of `public_url`.
    pub webauthn_rp_id: Option<String>,
    /// `web_search` provider: `auto` (an API provider whose key is set, else
    /// `ddg`), `ddg` (keyless DuckDuckGo), `brave` or `tavily`.
    pub search_provider: String,
    /// Brave Search API key. `BRAVE_API_KEY` is also read when this is unset.
    #[serde(skip_serializing)]
    pub brave_api_key: Option<SecretString>,
    /// Tavily API key. `TAVILY_API_KEY` is also read when this is unset.
    #[serde(skip_serializing)]
    pub tavily_api_key: Option<SecretString>,
    /// Minutes a cached `web_search` answer stays fresh; 0 turns the cache off.
    pub search_cache_ttl_min: f64,
    /// Directories holding Dash/Zeal `.docset` bundles, as a list or a
    /// colon-separated string. The `dash_*` tools are off when empty.
    #[serde(deserialize_with = "colon_or_list")]
    pub dash_docsets: Vec<PathBuf>,
    /// Test hook: lets `web_fetch` and `web_search` reach loopback addresses
    /// (and only those). It cannot be set from TOML or the environment.
    #[serde(skip)]
    pub fetch_allow_loopback: bool,
    /// Test hook: replaces the DuckDuckGo endpoint `web_search` queries. It
    /// cannot be set from TOML or the environment.
    #[serde(skip)]
    pub search_endpoint: Option<String>,
    /// Outbound notification webhook (`notify`, `flush_digest`). Unset keeps
    /// notifications in the outbox with status `not_configured`.
    pub notify_webhook_url: Option<String>,
    /// Header name that carries `notify_webhook_secret`.
    pub notify_webhook_header: String,
    /// Header value sent with every webhook delivery (e.g. `Bearer ...`).
    #[serde(skip_serializing)]
    pub notify_webhook_secret: Option<SecretString>,
    /// Delivery attempts per notification (1-10) before it is marked failed.
    pub notify_max_attempts: u32,
    /// Agent harnesses `dispatch_task` may start, by name (`[harnesses.<name>]`).
    /// Empty means dispatch only records runs and spawns nothing.
    pub harnesses: BTreeMap<String, HarnessConfig>,
    /// Seconds a dispatch run's lease lasts; a live supervisor renews it.
    pub dispatch_lease_seconds: u64,
    /// Seconds between lease-reaper sweeps under `ua serve`. Unset, a third of
    /// `dispatch_lease_seconds`; 0 turns the background loop off (the one
    /// sweep at startup still runs).
    pub dispatch_reaper_interval_s: Option<u64>,
    /// Directory of reviewed YAML workflow definitions read by `workflow_list`
    /// and `workflow_run`. Defaults to `$home/workflows`. Definitions are
    /// executable: review a change to this directory like code.
    pub workflow_dir: Option<PathBuf>,
    /// Allow `routine_fire`, and run due cron routines once a minute from
    /// `ua serve` (`UA_ROUTINES_ENABLED`). Off by default.
    pub routines_enabled: bool,
    /// Default wall-clock budget of an autonomous cycle, in seconds.
    pub autonomy_max_time_s: f64,
    /// Default token budget of an autonomous cycle.
    pub autonomy_max_tokens: i64,
    /// Default retry budget of an autonomous cycle.
    pub autonomy_max_retries: i64,
    /// Default cost budget of an autonomous cycle, in cents.
    pub autonomy_max_cost_cents: f64,
    /// Validation gates for the autonomous-cycle green path: a program and its
    /// arguments, run in the task worktree, that must exit 0. Empty (the
    /// default) means no cycle is ever green-path eligible, so every merge and
    /// PR transition waits for a human approval.
    #[serde(deserialize_with = "string_or_list")]
    pub cycle_validation_command: Vec<String>,
    /// Extra hub environment variable names passed through to the validation
    /// command (for example a toolchain location). The command otherwise
    /// gets a cleared environment with a fresh, empty HOME. `UA_*` names and
    /// credential-looking names are never passed, even when listed.
    #[serde(deserialize_with = "string_or_list")]
    pub cycle_validation_env: Vec<String>,
    /// Key(s) that encrypt managed secrets at rest (`UA_MANAGED_SECRET_KEY`):
    /// 32 random bytes as base64 or 64 hex characters. A comma-separated list
    /// rotates keys: the first encrypts new writes, every key decrypts.
    /// Unset, `managed_secret_set` refuses and stored secrets cannot be used.
    #[serde(skip_serializing)]
    pub managed_secret_key: Option<SecretString>,
    /// Downstream MCP servers declared by the operator, by name
    /// (`[mcp_servers.<name>]`, TOML only). Each entry has the shape
    /// `mcp_server_register` takes plus `review_expires_at`; see docs/mcp.md.
    /// A bad entry refuses only itself.
    pub mcp_servers: BTreeMap<String, serde_json::Value>,
    /// Days an `mcp_server_register` or `mcp_server_review` approval keeps a
    /// downstream MCP server usable before it must be reviewed again (1-365).
    pub mcp_review_ttl_days: u32,
    /// GitHub repositories (`owner/repo`) the public relay (`relay_manage`)
    /// may comment on. Empty means the relay sends nowhere.
    #[serde(deserialize_with = "string_or_list")]
    pub relay_github_repos: Vec<String>,
    /// Name of the managed secret, bound to consumer `relay:github`, holding
    /// the token the relay posts GitHub comments with.
    pub relay_github_secret: Option<String>,
    /// GitHub REST API base URL (https). Change it only for GitHub Enterprise.
    pub relay_github_api_url: String,
    /// Host names the relay treats as internal, besides the built-in private
    /// suffixes (`.internal`, `.local`, `.lan`, ...): machine names, intranet
    /// domains.
    #[serde(deserialize_with = "string_or_list")]
    pub relay_internal_hosts: Vec<String>,
    /// Private denylist for the relay: regular expressions (matched
    /// case-insensitively) a public message must not match. A TOML list, or
    /// one pattern per line in `UA_RELAY_DENYLIST`. Never serialized, logged
    /// or returned; a draft that matches is told only that it matched.
    #[serde(skip_serializing, deserialize_with = "lines_or_list")]
    pub relay_denylist: Vec<SecretString>,
    /// Longest relay message, in characters (1-65000).
    pub relay_max_chars: usize,
    /// GitHub accounts and teams (`user` or `org/team`, case-insensitive) a
    /// relay message may @-mention. Every other mention is refused.
    #[serde(deserialize_with = "string_or_list")]
    pub relay_mention_allowlist: Vec<String>,
    /// Link shorteners and redirectors the relay refuses to link to: a
    /// shortened link hides where it leads from the human who approves it.
    #[serde(deserialize_with = "string_or_list")]
    pub relay_redirector_hosts: Vec<String>,
    /// Gate runs (`check` and `draft`) one caller may make per hour, so the
    /// private denylist cannot be probed term by term. 0 refuses every run.
    pub relay_checks_per_hour: u32,
}

/// A cargo config file above a workspace root that the operator reviewed
/// and lets `run_cmd`'s cargo read, as long as its content is unchanged.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedCargoConfig {
    /// The file, e.g. `~/.cargo/config.toml`.
    pub path: PathBuf,
    /// Hex SHA-256 of the file's bytes.
    pub sha256: String,
}

/// One agent harness: a CLI coding agent dispatch runs as a child process.
///
/// The program runs without a shell. Each `argv` element may carry the
/// placeholders `{run_id}`, `{task_id}`, `{agent}`, `{fence}`, `{worktree}`
/// and `{prompt}`, substituted literally. The child environment starts empty:
/// only the process plumbing (`PATH`, `HOME`, locale, ...), the names in
/// `env_allowlist` and the dispatch binding (`UA_DISPATCH_*`) are passed, and
/// hub secrets such as `UA_AGENT_TOKENS` never are.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct HarnessConfig {
    /// Program and arguments, e.g. `["agent-cli", "--print", "{prompt}"]`.
    pub argv: Vec<String>,
    /// Extra parent environment names the child may inherit.
    pub env_allowlist: Vec<String>,
    /// Wall-clock limit in seconds; the whole process group is killed after it.
    pub timeout_s: u64,
    /// Bytes of combined output kept in the run log; the rest is discarded.
    pub output_cap_bytes: u64,
    /// Working directory when the task records no worktree.
    pub workdir: Option<PathBuf>,
    /// Pass the dispatched agent's own hub bearer (from `agent_tokens`) as
    /// `UA_AGENT_BEARER_TOKEN`, so the child can call `dispatch_report_self`.
    /// Off by default; no other agent's token is ever passed.
    pub pass_agent_token: bool,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            argv: Vec::new(),
            env_allowlist: Vec::new(),
            timeout_s: 3600,
            output_cap_bytes: 1024 * 1024,
            workdir: None,
            pass_agent_token: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            home: default_home(),
            db_path: None,
            workspace: None,
            read_roots: Vec::new(),
            vault_path: None,
            vault_write_dirs: DEFAULT_VAULT_WRITE_DIRS.iter().map(|s| s.to_string()).collect(),
            vault_inbox_dir: "Inbox".into(),
            vault_require_revision: false,
            promote_min_confidence: 0.7,
            obsidian_api_url: None,
            obsidian_api_key: None,
            bind: SocketAddr::from(([127, 0, 0, 1], 8765)),
            enforce_auth: true,
            allowed_hosts: vec!["localhost".into(), "127.0.0.1".into(), "::1".into()],
            agent_tokens: None,
            human_identities: Vec::new(),
            lifecycle_operators: None,
            node_max_per_agent: 8,
            node_queue_wait_s: 3600,
            node_wait_sweep_s: 60,
            graph_canvas_max_boards_per_agent: 50,
            graph_canvas_max_boards: 1000,
            graph_canvas_history_max: 20,
            shell_allowlist: Vec::new(),
            trusted_cargo_configs: Vec::new(),
            approval_tools: Vec::new(),
            approval_pass_ttl_hours: 24.0,
            policy_file: None,
            revoked_agents: Vec::new(),
            agent_scopes: BTreeMap::new(),
            profiles: BTreeMap::new(),
            agent_workspaces: BTreeMap::new(),
            embed_model: "BAAI/bge-small-en-v1.5".into(),
            edition: "full".into(),
            public_url: None,
            oauth_enabled: false,
            oauth_dcr_enabled: true,
            oauth_dcr_unused_ttl_hours: 24.0,
            oauth_dcr_rate_per_hour: 20,
            oauth_cimd_enabled: false,
            oauth_cimd_allow: Vec::new(),
            oauth_identities: vec!["remote-agent".into()],
            oauth_profile: "public".into(),
            oauth_access_ttl_secs: 3600,
            oauth_refresh_ttl_days: 30,
            oauth_client_credentials: None,
            ui_cookie_secure: true,
            ui_session_ttl_hours: 12,
            login_link_ttl_secs: 600,
            webauthn_rp_id: None,
            search_provider: "auto".into(),
            brave_api_key: None,
            tavily_api_key: None,
            search_cache_ttl_min: 60.0,
            dash_docsets: Vec::new(),
            fetch_allow_loopback: false,
            search_endpoint: None,
            notify_webhook_url: None,
            notify_webhook_header: "Authorization".into(),
            notify_webhook_secret: None,
            notify_max_attempts: 3,
            harnesses: BTreeMap::new(),
            dispatch_lease_seconds: 300,
            dispatch_reaper_interval_s: None,
            workflow_dir: None,
            routines_enabled: false,
            autonomy_max_time_s: 3600.0,
            autonomy_max_tokens: 100_000,
            autonomy_max_retries: 3,
            autonomy_max_cost_cents: 1000.0,
            cycle_validation_command: Vec::new(),
            cycle_validation_env: Vec::new(),
            managed_secret_key: None,
            mcp_servers: BTreeMap::new(),
            mcp_review_ttl_days: 90,
            relay_github_repos: Vec::new(),
            relay_github_secret: None,
            relay_github_api_url: "https://api.github.com".into(),
            relay_internal_hosts: Vec::new(),
            relay_denylist: Vec::new(),
            relay_max_chars: 10_000,
            relay_mention_allowlist: Vec::new(),
            relay_redirector_hosts: DEFAULT_REDIRECTOR_HOSTS.iter().map(|h| h.to_string()).collect(),
            relay_checks_per_hour: 60,
        }
    }
}

/// Link shorteners and redirectors the relay refuses by default.
pub const DEFAULT_REDIRECTOR_HOSTS: [&str; 16] = [
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "t.ly",
    "tiny.cc",
    "tinyurl.com",
    "v.gd",
    "href.li",
];

fn default_home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")).join(".ua-rust")
}

fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    p.to_path_buf()
}

impl Config {
    /// Load from defaults, the TOML file and the `UA_*` environment.
    pub fn load() -> anyhow::Result<Self> {
        Self::load_inner(None, true)
    }

    /// Load with an explicit config file (tests, `--config`).
    pub fn load_from(path: &Path) -> anyhow::Result<Self> {
        Self::load_inner(Some(path), true)
    }

    fn load_inner(explicit: Option<&Path>, with_env: bool) -> anyhow::Result<Self> {
        Self::figment(explicit, with_env).extract::<Config>().map(Self::normalized).map_err(Into::into)
    }

    fn figment(explicit: Option<&Path>, with_env: bool) -> Figment {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));
        let file = explicit
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os("UA_CONFIG").map(PathBuf::from))
            .or_else(|| {
                let home = std::env::var_os("UA_HOME").map(PathBuf::from).unwrap_or_else(default_home);
                let p = expand_tilde(&home).join("config.toml");
                p.exists().then_some(p)
            });
        if let Some(f) = file {
            fig = fig.merge(Toml::file(f));
        }
        if with_env {
            // MCP servers come from TOML only: no JSON-in-an-environment-variable form.
            fig = fig.merge(Env::prefixed("UA_").ignore(&["config", "mcp_servers"]));
        }
        fig
    }

    fn normalized(mut self) -> Self {
        self.home = expand_tilde(&self.home);
        self.db_path = self.db_path.map(|p| expand_tilde(&p));
        self.workspace = self.workspace.map(|p| expand_tilde(&p));
        self.vault_path = self.vault_path.map(|p| expand_tilde(&p));
        self.read_roots = self.read_roots.iter().map(|p| expand_tilde(p)).collect();
        self.public_url = self.public_url.map(|u| u.trim().trim_end_matches('/').to_string());
        self.apply_oauth_profiles();
        self.policy_file = self.policy_file.map(|p| expand_tilde(&p));
        self.dash_docsets = self.dash_docsets.iter().map(|p| expand_tilde(p)).collect();
        for h in self.harnesses.values_mut() {
            h.workdir = h.workdir.as_deref().map(expand_tilde);
        }
        self.workflow_dir = self.workflow_dir.map(|p| expand_tilde(&p));
        for t in &mut self.trusted_cargo_configs {
            t.path = expand_tilde(&t.path);
            t.sha256 = t.sha256.trim().to_ascii_lowercase();
        }
        self
    }

    /// Seconds between lease-reaper sweeps; 0 means off. See
    /// `dispatch_reaper_interval_s`.
    pub fn dispatch_reaper_interval(&self) -> u64 {
        self.dispatch_reaper_interval_s.unwrap_or_else(|| (self.dispatch_lease_seconds / 3).max(1))
    }

    /// Give every OAuth identity without an explicit `profiles` entry the
    /// `oauth_profile`, so a remote grant never falls back to the broad default.
    pub fn apply_oauth_profiles(&mut self) {
        for label in &self.oauth_identities {
            self.profiles.entry(label.clone()).or_insert_with(|| self.oauth_profile.clone());
        }
    }

    /// The hub's public base URL, without a trailing slash.
    pub fn public_base_url(&self) -> String {
        match &self.public_url {
            Some(u) if !u.trim().is_empty() => u.trim().trim_end_matches('/').to_string(),
            _ => format!("http://{}", self.bind),
        }
    }

    /// Parse `oauth_client_credentials` into `(client_id, secret, identity)`.
    /// A client id listed twice is dropped entirely (fail closed).
    pub fn oauth_client_credentials(&self) -> Vec<(String, SecretString, String)> {
        let Some(raw) = &self.oauth_client_credentials else { return Vec::new() };
        let rows: Vec<(String, String, String)> = raw
            .expose_secret()
            .split([',', '\n'])
            .filter_map(|e| {
                let mut it = e.trim().splitn(3, '|');
                let (id, secret, label) = (it.next()?.trim(), it.next()?.trim(), it.next()?.trim());
                (!id.is_empty() && !secret.is_empty() && !label.is_empty())
                    .then(|| (id.to_string(), secret.to_string(), label.to_string()))
            })
            .collect();
        rows.iter()
            .filter(|(id, _, _)| rows.iter().filter(|(other, _, _)| other == id).count() == 1)
            .map(|(id, secret, label)| (id.clone(), SecretString::from(secret.clone()), label.clone()))
            .collect()
    }

    /// A config rooted in `home`, for tests and embedded use.
    pub fn for_home(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into(), ..Self::default() }
    }

    pub fn db_path(&self) -> PathBuf {
        self.db_path.clone().unwrap_or_else(|| self.home.join("ua.db"))
    }

    pub fn workspace_root(&self) -> PathBuf {
        self.workspace.clone().unwrap_or_else(|| self.home.join("workspace"))
    }

    /// Where reviewed workflow definitions live.
    pub fn workflow_dir(&self) -> PathBuf {
        self.workflow_dir.clone().unwrap_or_else(|| self.home.join("workflows"))
    }

    pub fn shell_allowlist(&self) -> Vec<String> {
        if self.shell_allowlist.is_empty() {
            DEFAULT_SHELL_ALLOWLIST.iter().map(|s| s.to_string()).collect()
        } else {
            self.shell_allowlist.clone()
        }
    }

    /// Prod-action scopes of `label`, lower-cased. `None` when scopes are not configured.
    pub fn prod_scopes(&self, label: &str) -> Option<Vec<String>> {
        if self.agent_scopes.is_empty() {
            return None;
        }
        let raw = self.agent_scopes.get(label).map(String::as_str).unwrap_or("");
        Some(
            raw.split(['|', ',', ' '])
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        )
    }

    pub fn is_human(&self, label: &str) -> bool {
        self.human_identities.iter().any(|h| h == label)
    }

    /// The identities allowed to run lifecycle operator actions:
    /// `lifecycle_operators` when it is set, else `human_identities`.
    pub fn lifecycle_operators(&self) -> &[String] {
        self.lifecycle_operators.as_deref().unwrap_or(&self.human_identities)
    }

    pub fn is_lifecycle_operator(&self, label: &str) -> bool {
        self.lifecycle_operators().iter().any(|o| o == label)
    }

    /// Parse the static token list into `(label, token)` pairs.
    ///
    /// Accepts `label:token` entries separated by commas or newlines, or a
    /// path to a file containing them. A token listed for two different
    /// labels authenticates nobody (fail closed).
    pub fn static_tokens(&self) -> Vec<(String, SecretString)> {
        let Some(raw) = &self.agent_tokens else { return Vec::new() };
        let raw = raw.expose_secret();
        let text = if !raw.contains(':') && Path::new(raw.trim()).is_file() {
            std::fs::read_to_string(raw.trim()).unwrap_or_default()
        } else {
            raw.to_string()
        };
        let mut pairs: Vec<(String, String)> = text
            .split([',', '\n'])
            .filter_map(|e| {
                let e = e.trim();
                if e.is_empty() || e.starts_with('#') {
                    return None;
                }
                let (label, tok) = e.split_once(':')?;
                let (label, tok) = (label.trim(), tok.trim());
                (!label.is_empty() && !tok.is_empty()).then(|| (label.to_string(), tok.to_string()))
            })
            .collect();
        let collided: Vec<String> = pairs
            .iter()
            .filter(|(l, t)| pairs.iter().any(|(l2, t2)| t2 == t && l2 != l))
            .map(|(_, t)| t.clone())
            .collect();
        pairs.retain(|(_, t)| !collided.contains(t));
        pairs.into_iter().map(|(l, t)| (l, SecretString::from(t))).collect()
    }
}

/// Deserialize either a list or a comma/whitespace separated string.
fn string_or_list<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: From<String>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    let items = match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => {
            s.split([',', ' ', '\n']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
        }
        OneOrMany::Many(v) => v,
    };
    Ok(items.into_iter().map(T::from).collect())
}

/// Deserialize either a list or a newline separated string. For values that
/// may hold commas and spaces themselves (regular expressions).
fn lines_or_list<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: From<String>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    let items = match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => s.lines().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect(),
        OneOrMany::Many(v) => v,
    };
    Ok(items.into_iter().map(T::from).collect())
}

/// [`string_or_list`] for a setting whose absence means something other
/// than an empty list.
fn opt_string_or_list<'de, D>(d: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    string_or_list(d).map(Some)
}

/// Deserialize either a list or a colon/newline separated string. Paths can
/// hold spaces, so unlike [`string_or_list`] a space does not split.
fn colon_or_list<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: From<String>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    let items = match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => {
            s.split([':', '\n']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
        }
        OneOrMany::Many(v) => v,
    };
    Ok(items.into_iter().map(T::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_layer_and_lists() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("c.toml");
        std::fs::write(
            &file,
            "home = \"/data/ua\"\nvault_write_dirs = \"Inbox, Wiki\"\nagent_tokens = \"alpha:t1,beta:t2,gamma:t1\"\n[profiles]\nops = \"operator\"\n",
        )
        .unwrap();
        let cfg = Config::load_inner(Some(&file), false).unwrap();
        assert_eq!(cfg.home, PathBuf::from("/data/ua"));
        assert_eq!(cfg.vault_write_dirs, vec!["Inbox", "Wiki"]);
        assert_eq!(cfg.profiles.get("ops").map(String::as_str), Some("operator"));
        // t1 is shared by alpha and gamma: neither authenticates.
        let toks = cfg.static_tokens();
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].0, "beta");
        assert!(!format!("{cfg:?}").contains("t2"), "secrets must not leak through Debug");
    }

    #[test]
    fn harness_tables() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("c.toml");
        std::fs::write(
            &file,
            "dispatch_lease_seconds = 60\n[harnesses.echo]\nargv = [\"echo\", \"{prompt}\"]\ntimeout_s = 5\n",
        )
        .unwrap();
        let cfg = Config::load_inner(Some(&file), false).unwrap();
        let h = &cfg.harnesses["echo"];
        assert_eq!(h.argv, vec!["echo", "{prompt}"]);
        assert_eq!(h.timeout_s, 5);
        assert_eq!(h.output_cap_bytes, 1024 * 1024, "unset fields keep their defaults");
        assert_eq!(cfg.dispatch_lease_seconds, 60);
        assert_eq!(cfg.dispatch_reaper_interval(), 20, "the reaper runs every third of a lease by default");
        let off = dir.path().join("off.toml");
        std::fs::write(&off, "dispatch_reaper_interval_s = 0\n").unwrap();
        assert_eq!(Config::load_inner(Some(&off), false).unwrap().dispatch_reaper_interval(), 0);
    }

    #[test]
    fn lifecycle_operators_default_to_humans_and_replace_when_set() {
        let dir = tempfile::tempdir().unwrap();
        let load = |name: &str, body: &str| {
            let file = dir.path().join(name);
            std::fs::write(&file, body).unwrap();
            Config::load_inner(Some(&file), false).unwrap()
        };
        let cfg = load("unset.toml", "human_identities = [\"operator\"]\n");
        assert!(cfg.is_lifecycle_operator("operator"));
        assert!(!cfg.is_lifecycle_operator("ops-bot"));

        let cfg =
            load("set.toml", "human_identities = [\"operator\"]\nlifecycle_operators = \"ops-bot, ops-2\"\n");
        assert_eq!(cfg.lifecycle_operators(), ["ops-bot", "ops-2"]);
        assert!(!cfg.is_lifecycle_operator("operator"), "setting the list replaces the default");

        let cfg = load("empty.toml", "human_identities = [\"operator\"]\nlifecycle_operators = []\n");
        assert!(!cfg.is_lifecycle_operator("operator"), "an empty list means nobody");
    }

    #[test]
    fn trusted_cargo_configs_are_path_and_hash_pairs() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("c.toml");
        std::fs::write(
            &file,
            "trusted_cargo_configs = [{ path = \"/opt/ws/.cargo/config.toml\", sha256 = \" ABCDEF \" }]\n",
        )
        .unwrap();
        let cfg = Config::load_inner(Some(&file), false).unwrap();
        assert_eq!(
            cfg.trusted_cargo_configs,
            vec![TrustedCargoConfig { path: "/opt/ws/.cargo/config.toml".into(), sha256: "abcdef".into() }]
        );
        assert!(Config::default().trusted_cargo_configs.is_empty(), "nothing is trusted by default");
        // A misspelled key is an error, not a silently ignored entry.
        std::fs::write(&file, "trusted_cargo_configs = [{ path = \"/x\", sha = \"ab\" }]\n").unwrap();
        assert!(Config::load_inner(Some(&file), false).is_err());
    }

    #[test]
    fn mcp_server_tables_and_the_secret_key() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("c.toml");
        std::fs::write(
            &file,
            "managed_secret_key = \"k-one\"\n[mcp_servers.docs]\ntransport = \"streamable_http\"\n\
             url = \"https://docs.example.com/mcp\"\n[mcp_servers.docs.tools]\nsearch = \"read\"\n",
        )
        .unwrap();
        let cfg = Config::load_inner(Some(&file), false).unwrap();
        let docs = &cfg.mcp_servers["docs"];
        assert_eq!(docs["url"], "https://docs.example.com/mcp");
        assert_eq!(docs["tools"]["search"], "read");
        assert_eq!(cfg.mcp_review_ttl_days, 90);
        assert_eq!(
            cfg.managed_secret_key.as_ref().map(|k| k.expose_secret().to_string()).as_deref(),
            Some("k-one")
        );
        assert!(!format!("{cfg:?}").contains("k-one"), "the key must not leak through Debug");
    }

    #[test]
    fn relay_settings_and_a_private_denylist() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("c.toml");
        std::fs::write(
            &file,
            "relay_github_repos = \"acme/widgets, acme/docs\"\nrelay_github_secret = \"relay-gh\"\n\
             relay_denylist = [\"project[- ]falcon\", \"a, b\"]\nrelay_max_chars = 500\n",
        )
        .unwrap();
        let cfg = Config::load_inner(Some(&file), false).unwrap();
        assert_eq!(cfg.relay_github_repos, vec!["acme/widgets", "acme/docs"]);
        assert_eq!(cfg.relay_github_secret.as_deref(), Some("relay-gh"));
        assert_eq!(cfg.relay_github_api_url, "https://api.github.com");
        assert_eq!(cfg.relay_max_chars, 500);
        assert_eq!(cfg.relay_checks_per_hour, 60);
        assert!(cfg.relay_redirector_hosts.iter().any(|h| h == "bit.ly"));
        assert!(cfg.relay_mention_allowlist.is_empty());
        let deny: Vec<&str> = cfg.relay_denylist.iter().map(|p| p.expose_secret()).collect();
        assert_eq!(deny, vec!["project[- ]falcon", "a, b"], "list items are not split on commas");
        assert!(!format!("{cfg:?}").contains("falcon"), "the denylist must not leak through Debug");
        let one: Vec<SecretString> =
            lines_or_list(serde_json::Value::String("x y\n\n z,w \n".into())).unwrap();
        assert_eq!(one.iter().map(|p| p.expose_secret()).collect::<Vec<_>>(), vec!["x y", "z,w"]);
    }
}
