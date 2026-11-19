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
    /// Programs `run_cmd` may run. Setting it replaces the default list.
    #[serde(deserialize_with = "string_or_list")]
    pub shell_allowlist: Vec<String>,
    /// Tools that always need a one-time human approval.
    #[serde(deserialize_with = "string_or_list")]
    pub approval_tools: Vec<String>,
    /// Hours an approved, unconsumed one-shot pass stays valid.
    pub approval_pass_ttl_hours: f64,
    /// Policy rules file (YAML).
    pub policy_file: Option<PathBuf>,
    /// Identity label → default profile name. Unlisted identities get `developer`.
    pub profiles: BTreeMap<String, String>,
    /// Per-agent workspace overrides: label → root (or `"deny"`).
    pub agent_workspaces: BTreeMap<String, String>,
    /// Embedding model for semantic memory search (needs the `embeddings` feature).
    pub embed_model: String,
    /// Edition: `full` (default) or `core`, which hides ledger features.
    pub edition: String,
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
            bind: SocketAddr::from(([127, 0, 0, 1], 8765)),
            enforce_auth: false,
            allowed_hosts: vec!["localhost".into(), "127.0.0.1".into()],
            agent_tokens: None,
            human_identities: Vec::new(),
            shell_allowlist: Vec::new(),
            approval_tools: Vec::new(),
            approval_pass_ttl_hours: 24.0,
            policy_file: None,
            profiles: BTreeMap::new(),
            agent_workspaces: BTreeMap::new(),
            embed_model: "BAAI/bge-small-en-v1.5".into(),
            edition: "full".into(),
            search_provider: "auto".into(),
            brave_api_key: None,
            tavily_api_key: None,
            search_cache_ttl_min: 60.0,
            dash_docsets: Vec::new(),
            fetch_allow_loopback: false,
            search_endpoint: None,
        }
    }
}

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
            fig = fig.merge(Env::prefixed("UA_").ignore(&["config"]));
        }
        fig
    }

    fn normalized(mut self) -> Self {
        self.home = expand_tilde(&self.home);
        self.db_path = self.db_path.map(|p| expand_tilde(&p));
        self.workspace = self.workspace.map(|p| expand_tilde(&p));
        self.vault_path = self.vault_path.map(|p| expand_tilde(&p));
        self.read_roots = self.read_roots.iter().map(|p| expand_tilde(p)).collect();
        self.dash_docsets = self.dash_docsets.iter().map(|p| expand_tilde(p)).collect();
        self
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

    pub fn shell_allowlist(&self) -> Vec<String> {
        if self.shell_allowlist.is_empty() {
            DEFAULT_SHELL_ALLOWLIST.iter().map(|s| s.to_string()).collect()
        } else {
            self.shell_allowlist.clone()
        }
    }

    pub fn is_human(&self, label: &str) -> bool {
        self.human_identities.iter().any(|h| h == label)
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
}
