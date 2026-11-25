//! Hardened Git fetch plumbing for skill sources (`docs/skill-sources.md` §1, §3).
//!
//! Safety properties enforced on every fetch:
//! - Public `https://` sources on port 443 with multi-label DNS hostnames only
//!   (`ssh://` off by default; `file://` compiled only under `cfg(test)` or
//!   `feature = "test-util"`).
//! - Zero credentials, queries, fragments, IP literals, single-label hosts,
//!   non-443 ports, empty authorities (`https:///...`), leading `-`, or control
//!   characters in URLs; path case and any trailing `.git` suffix are preserved
//!   in `canonical_url` so the exact approved URL is fetched, while uniqueness
//!   normalizes both.
//! - Git version verified once per process (`git >= 2.37` required so
//!   `http.curloptResolve` and `GIT_CONFIG_GLOBAL` are honoured).
//! - DNS resolved once per fetch, **every** returned IP classified against
//!   `ua_ingress::addr` (failing the whole fetch on any non-public or cloud
//!   metadata address), and the fetch pinned to the classified IP via
//!   `-c http.curloptResolve=<host>:443:<ip>`.
//! - Bare cache initialized with `--bare --template=` (mode `0700`), serialized
//!   by an exclusive file lock + in-process mutex; no working tree is ever
//!   checked out.
//! - Scrubbed environment (`.env_clear()`, stripping `GIT_*`, `SSH_AUTH_SOCK`,
//!   `*_ASKPASS`, proxy vars, `HOME`, and ambient tokens) plus CLI `-c`
//!   overrides disabling hooks, fsmonitor, submodules, LFS/filters, credential
//!   helpers, proxies, redirects (`http.followRedirects=false`), and setting
//!   `http.lowSpeedLimit` / `http.lowSpeedTime`.
//! - Process-group isolation (`process_group(0)` on Unix): timeout, stdout
//!   overflow, or live transfer cache-size breach kills the entire process
//!   group (`SIGKILL`) and bounds reader joins so stalled child helpers
//!   (`git-remote-https`, `index-pack`) cannot wedge the cache lock.
//! - Shallow `--depth=1` fetch of the exact 40-char commit SHA with no fallback
//!   to a full fetch.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};
use url::{Host, Url};

pub const MAX_URL_BYTES: usize = 512;
pub const MAX_REF_BYTES: usize = 200;
pub const MAX_SUBPATH_BYTES: usize = 512;
pub const MAX_ALLOWED_SUBPATHS: usize = 32;
pub const DEFAULT_GIT_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024;
/// Minimum Git version required: 2.37 added `http.curloptResolve` (2.32 added
/// `GIT_CONFIG_GLOBAL`). Older Git silently ignores unknown `-c` keys, which
/// would reopen DNS rebinding.
pub const MIN_GIT_VERSION: (u32, u32) = (2, 37);

const READER_JOIN_GRACE: Duration = Duration::from_millis(500);
const LIVE_SIZE_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceScheme {
    Https,
    #[cfg(any(test, feature = "test-util"))]
    File,
}

impl SourceScheme {
    pub fn git_allow_protocol(self) -> &'static str {
        match self {
            SourceScheme::Https => "https",
            #[cfg(any(test, feature = "test-util"))]
            SourceScheme::File => "file",
        }
    }
}

/// A validated, canonical skill source URL.
///
/// Hostname is lowercased, explicit `:443` and trailing slashes are stripped.
/// Repository path case and any trailing `.git` suffix are preserved verbatim
/// so case-sensitive and `.git`-only remotes (e.g. cgit, `git-http-backend`)
/// are fetched at the exact approved URL; allowlist uniqueness normalizes both
/// separately via [`url_uniqueness_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSourceUrl {
    pub canonical_url: String,
    pub scheme: SourceScheme,
    pub host: String,
    pub port: u16,
    pub repo_path: String,
}

fn strip_trailing_dot_git(path: &str) -> &str {
    if path.len() > 4 && path[path.len() - 4..].eq_ignore_ascii_case(".git") {
        &path[..path.len() - 4]
    } else {
        path
    }
}

/// Normalized uniqueness key for a canonical skill source URL: lowercased with
/// any trailing `.git` stripped. Used only for org-level uniqueness and
/// revoked-SHA checks, never as the fetched URL or bare cache key.
pub fn url_uniqueness_key(canonical_url: &str) -> String {
    let lower = canonical_url.to_ascii_lowercase();
    if lower.len() > 4 && lower.ends_with(".git") { lower[..lower.len() - 4].to_string() } else { lower }
}

fn valid_domain_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Multi-label public-style DNS hostname: refuses single-label internal names
/// (e.g. `metadata`, `localhost`), trailing dots, and IP literals.
fn valid_domain(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    let lower = host.to_ascii_lowercase();
    if !lower.contains('.') {
        return false;
    }
    if lower == "localhost" || lower.ends_with(".localhost") {
        return false;
    }
    if lower.parse::<IpAddr>().is_ok() {
        return false;
    }
    lower.split('.').all(valid_domain_label)
}

/// Validate a production `https://` skill source URL per `docs/skill-sources.md` §1.
///
/// Refuses non-`https://` schemes, credentials, queries, fragments, backslashes,
/// empty authorities (`https:///...`), IP literals, single-label hosts, non-443
/// ports, leading `-`, spaces, control characters, and raw path traversal.
/// Strips trailing `/` while preserving path case and any `.git` suffix so the
/// fetched URL matches the approved URL verbatim.
pub fn validate_source_url(raw: &str) -> UaResult<ParsedSourceUrl> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(UaError::invalid("skill source url must not contain control characters"));
    }
    let text = raw.trim();
    if text.is_empty()
        || text.len() > MAX_URL_BYTES
        || text.starts_with('-')
        || text.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return Err(UaError::invalid(
            "skill source url must be a non-empty https:// URL without spaces, control characters, or a leading '-'",
        ));
    }
    if text.contains('?') || text.contains('#') || text.contains('\\') {
        return Err(UaError::invalid("skill source url must not carry a query, fragment, or backslash"));
    }
    if !text.starts_with("https://") {
        return Err(UaError::invalid(
            "skill source url must use https:// (ssh://, http://, git://, ext::, and file:// are refused)",
        ));
    }
    let after_scheme = &text["https://".len()..];
    let Some((authority, raw_after_slash)) = after_scheme.split_once('/') else {
        return Err(UaError::invalid("skill source url needs a hostname and repository path"));
    };
    // Refuse empty authority (e.g. `https:///evil.com/x`, which WHATWG Url::parse reparses).
    if authority.is_empty() {
        return Err(UaError::invalid("skill source url has an empty host authority"));
    }
    if authority.contains('@') {
        return Err(UaError::invalid("skill source url must not embed credentials"));
    }
    let raw_rel = raw_after_slash.trim_end_matches('/');
    if raw_rel.is_empty() {
        return Err(UaError::invalid("skill source url needs a repository path"));
    }
    for seg in raw_rel.split('/') {
        let lower_seg = seg.to_ascii_lowercase();
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || lower_seg.contains("%2e")
            || lower_seg.contains("%2f")
            || lower_seg.contains("%5c")
        {
            return Err(UaError::invalid("skill source repository path contains an unsafe segment"));
        }
    }

    let parsed =
        Url::parse(text).map_err(|_| UaError::invalid("skill source url is not a valid https:// URL"))?;
    if parsed.scheme() != "https" {
        return Err(UaError::invalid("skill source url must use https://"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(UaError::invalid("skill source url must not embed credentials"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(UaError::invalid("skill source url must not carry a query or fragment"));
    }
    let host = match parsed.host() {
        Some(Host::Domain(d)) => {
            let lower = d.to_ascii_lowercase();
            if !valid_domain(&lower) {
                return Err(UaError::invalid(format!(
                    "skill source host {d:?} must be a multi-label public DNS hostname, not an IP literal or single-label host"
                )));
            }
            lower
        }
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => {
            return Err(UaError::invalid("skill source url must not use an IP literal"));
        }
        None => return Err(UaError::invalid("skill source url needs a hostname")),
    };
    if parsed.port().is_some_and(|p| p != 443) {
        return Err(UaError::invalid("skill source url must use default HTTPS port 443"));
    }

    let raw_path = parsed.path().trim_matches('/');
    let without_git = strip_trailing_dot_git(raw_path).trim_end_matches('/');
    if raw_path.is_empty()
        || raw_path.eq_ignore_ascii_case(".git")
        || without_git.is_empty()
        || without_git.eq_ignore_ascii_case(".git")
    {
        return Err(UaError::invalid("skill source url needs a non-empty repository path"));
    }
    for seg in raw_path.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.eq_ignore_ascii_case(".git") {
            return Err(UaError::invalid("skill source repository path contains an unsafe segment"));
        }
    }
    let canonical_url = format!("https://{host}/{raw_path}");
    Ok(ParsedSourceUrl {
        canonical_url,
        scheme: SourceScheme::Https,
        host,
        port: 443,
        repo_path: raw_path.to_string(),
    })
}

/// Test-only validator for local `file:///absolute/path` fixtures.
/// Compiled only under `#[cfg(test)]` or `--features test-util`.
#[cfg(any(test, feature = "test-util"))]
pub fn validate_file_source_url_for_test(raw: &str) -> UaResult<ParsedSourceUrl> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(UaError::invalid("skill source url must not contain control characters"));
    }
    let text = raw.trim();
    if text.is_empty() || text.len() > MAX_URL_BYTES || text.contains('?') || text.contains('#') {
        return Err(UaError::invalid("invalid file:// skill source url"));
    }
    let Some(rest) = text.strip_prefix("file://") else {
        return Err(UaError::invalid("expected a file:///absolute/path url"));
    };
    if !rest.starts_with('/') || rest.len() < 2 {
        return Err(UaError::invalid("file:// skill source must be file:///absolute/path"));
    }
    let path_part = rest.trim_end_matches('/');
    if path_part.is_empty() || path_part.split('/').any(|s| s == "..") {
        return Err(UaError::invalid("file:// skill source path must not contain '..'"));
    }
    Ok(ParsedSourceUrl {
        canonical_url: format!("file://{path_part}"),
        scheme: SourceScheme::File,
        host: String::new(),
        port: 0,
        repo_path: path_part.to_string(),
    })
}

/// Validate a 40-character lowercase hex Git commit SHA.
pub fn validate_sha(raw: &str) -> UaResult<String> {
    let text = raw.trim();
    if text.len() == 40 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(text.to_string())
    } else {
        Err(UaError::invalid("pinned_sha must be an exact 40-character lowercase hex commit SHA"))
    }
}

/// Validate a Git tracking ref (branch, tag, `HEAD`, or exact 40-char SHA).
pub fn validate_tracking_ref(raw: &str) -> UaResult<String> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(UaError::invalid("tracking_ref must not contain control characters"));
    }
    let text = raw.trim();
    if text.is_empty()
        || text.len() > MAX_REF_BYTES
        || text.starts_with('-')
        || text.contains("..")
        || text.contains("//")
        || text.ends_with('.')
        || text.ends_with('/')
        || text.ends_with(".lock")
        || !text.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        || !text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
        || text.split('/').any(|part| part.is_empty() || part.starts_with('.'))
    {
        return Err(UaError::invalid(
            "tracking_ref must be a valid branch/tag name, HEAD, or 40-char commit SHA",
        ));
    }
    Ok(text.to_string())
}

/// Validate and canonically sort optional allowed repository-relative subpath prefixes.
/// Leading-dot repo directories (such as `.claude/skills`) are permitted as
/// repo-relative prefixes; `.`, `..`, `.git`, backslashes, colons, control
/// characters, and hidden/bidi Unicode code points are refused.
pub fn validate_allowed_subpaths(raw: Option<Vec<String>>) -> UaResult<Vec<String>> {
    let Some(list) = raw else {
        return Ok(Vec::new());
    };
    if list.len() > MAX_ALLOWED_SUBPATHS {
        return Err(UaError::invalid(format!(
            "allowed_subpaths exceeds the {MAX_ALLOWED_SUBPATHS}-entry limit"
        )));
    }
    let mut out = Vec::new();
    for entry in list {
        let trimmed = entry.trim().trim_matches('/');
        if trimmed.is_empty()
            || trimmed.len() > MAX_SUBPATH_BYTES
            || trimmed.contains('\\')
            || trimmed.contains(':')
            || trimmed.chars().any(|c| c.is_control() || crate::families::skills::hidden_char(c))
        {
            return Err(UaError::invalid(format!("unsafe allowed_subpaths entry {entry:?}")));
        }
        for part in trimmed.split('/') {
            if part.is_empty() || part == "." || part == ".." || part.eq_ignore_ascii_case(".git") {
                return Err(UaError::invalid(format!("unsafe allowed_subpaths entry {entry:?}")));
            }
        }
        out.push(trimmed.to_string());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

// --- Git version check (>= 2.37 required for http.curloptResolve) ------------------

/// Parse `(major, minor)` from `git --version` output (for example
/// `"git version 2.56.1"` or `"git version 2.39.5 (Apple Git-154)"`).
pub fn parse_git_version(raw: &str) -> Option<(u32, u32)> {
    let token = raw.split_whitespace().find(|tok| {
        let mut parts = tok.split('.');
        let major_ok = parts.next().is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        let minor_ok = parts.next().is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        major_ok && minor_ok
    })?;
    let mut parts = token.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Validate a parsed `git --version` output against [`MIN_GIT_VERSION`].
pub fn check_git_version_output(raw: &str) -> UaResult<(u32, u32)> {
    let Some((major, minor)) = parse_git_version(raw) else {
        return Err(UaError::internal(format!(
            "could not parse git version from {:?}; git >= {}.{} is required",
            raw.trim(),
            MIN_GIT_VERSION.0,
            MIN_GIT_VERSION.1
        )));
    };
    if (major, minor) < MIN_GIT_VERSION {
        return Err(UaError::internal(format!(
            "git {major}.{minor} is too old; git >= {}.{} is required for http.curloptResolve DNS pinning",
            MIN_GIT_VERSION.0, MIN_GIT_VERSION.1
        )));
    }
    Ok((major, minor))
}

/// Check the host's `git --version` once per process and refuse below 2.37.
pub fn ensure_supported_git_version(opts: &FetchOptions) -> UaResult<(u32, u32)> {
    static VERSION: OnceLock<Result<(u32, u32), String>> = OnceLock::new();
    let res = VERSION.get_or_init(|| {
        let spec = build_git_command(None, None, None, &["--version"], opts).map_err(|e| e.to_string())?;
        let out = run_git(&spec, Duration::from_secs(10), 4096).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&out);
        check_git_version_output(&text).map_err(|e| e.to_string())
    });
    match res {
        Ok(v) => Ok(*v),
        Err(msg) => Err(UaError::internal(msg.clone())),
    }
}

// --- DNS classification and pinning ------------------------------------------------

/// DNS resolver abstraction so tests verify pinning and SSRF refusals offline.
pub trait DnsResolver {
    fn resolve(&self, host: &str, port: u16) -> UaResult<Vec<IpAddr>>;
}

pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> UaResult<Vec<IpAddr>> {
        let addrs: Vec<IpAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|_| UaError::invalid(format!("could not resolve skill source host {host:?}")))?
            .map(|sa| sa.ip())
            .collect();
        if addrs.is_empty() {
            return Err(UaError::invalid(format!("skill source host {host:?} resolved to no addresses")));
        }
        Ok(addrs)
    }
}

/// Resolve `host:port`, classify **every** returned IP against
/// `ua_ingress::addr`, refuse the whole fetch if any returned IP is non-public
/// or cloud metadata, and return the pinned IP for `http.curloptResolve`.
pub fn classify_and_pin_ip(host: &str, port: u16, resolver: &dyn DnsResolver) -> UaResult<IpAddr> {
    let addrs = resolver.resolve(host, port)?;
    if addrs.is_empty() {
        return Err(UaError::invalid(format!("skill source host {host:?} resolved to no addresses")));
    }
    for &ip in &addrs {
        if ua_ingress::addr::is_cloud_metadata(ip) {
            return Err(UaError::denied(
                "ssrf_blocked",
                format!("skill source host {host:?} resolved to a blocked address (cloud metadata)"),
            ));
        }
        if let Some(reason) = ua_ingress::addr::non_public_reason(ip) {
            return Err(UaError::denied(
                "ssrf_blocked",
                format!("skill source host {host:?} resolved to a non-public address ({reason})"),
            ));
        }
    }
    Ok(addrs.iter().copied().find(IpAddr::is_ipv4).unwrap_or(addrs[0]))
}

fn format_curlopt_resolve(host: &str, port: u16, ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{host}:{port}:{v4}"),
        IpAddr::V6(v6) => format!("{host}:{port}:[{v6}]"),
    }
}

// --- hardened git command builder --------------------------------------------------

/// Runtime bounds for [`fetch_exact_sha`].
#[derive(Debug, Clone)]
pub struct FetchOptions {
    #[cfg(any(test, feature = "test-util"))]
    allow_file_urls: bool,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub max_cache_bytes: u64,
}

impl FetchOptions {
    /// Production defaults: `https://` only, 120s timeout, 16 MiB stdout cap,
    /// 64 MiB bare cache cap.
    pub fn production() -> Self {
        Self {
            #[cfg(any(test, feature = "test-util"))]
            allow_file_urls: false,
            timeout: DEFAULT_GIT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_cache_bytes: DEFAULT_MAX_CACHE_BYTES,
        }
    }

    /// Test-only options enabling local `file://` fixtures without network I/O.
    /// Compiled only under `#[cfg(test)]` or `--features test-util`.
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_local_file_test() -> Self {
        Self { allow_file_urls: true, ..Self::production() }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn is_file_allowed(&self) -> bool {
        self.allow_file_urls
    }
}

/// Exact program, argv, and scrubbed environment built for one `git` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

/// Mandatory `-c` overrides placed before every git subcommand (`docs/skill-sources.md` §3).
pub const GIT_HARDENING_OVERRIDES: &[&str] = &[
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "core.quotePath=false",
    "core.bigFileThreshold=524288",
    "gc.auto=0",
    "protocol.ext.allow=never",
    "submodule.recurse=false",
    "fetch.recurseSubmodules=false",
    "credential.interactive=never",
    "credential.helper=",
    "http.proxy=",
    "http.followRedirects=false",
    "http.lowSpeedLimit=1000",
    "http.lowSpeedTime=30",
    "filter.lfs.smudge=",
    "filter.lfs.clean=",
    "filter.lfs.process=",
    "filter.lfs.required=false",
    "transfer.fsckObjects=true",
    "fetch.fsckObjects=true",
];

/// Environment variables inherited from the host when building the scrubbed
/// git environment (everything else — `GIT_*`, `SSH_AUTH_SOCK`, `*_ASKPASS`,
/// `HOME`, proxy vars, ambient tokens — is dropped).
const SAFE_HOST_ENV_KEYS: &[&str] = &["PATH", "TMPDIR", "TEMP", "TMP", "TZ", "SYSTEMROOT", "COMSPEC"];

/// Build a hardened [`GitCommandSpec`] using the current process environment
/// as the source for minimal OS paths (`PATH`, `TMPDIR`, etc.).
pub fn build_git_command(
    repo_dir: Option<&Path>,
    url: Option<&ParsedSourceUrl>,
    pinned_ip: Option<IpAddr>,
    subcmd_args: &[&str],
    opts: &FetchOptions,
) -> UaResult<GitCommandSpec> {
    build_git_command_with_host_env(repo_dir, url, pinned_ip, subcmd_args, opts, std::env::vars())
}

/// Deterministic variant taking explicit `host_env` pairs.
pub fn build_git_command_with_host_env<I, K, V>(
    repo_dir: Option<&Path>,
    url: Option<&ParsedSourceUrl>,
    pinned_ip: Option<IpAddr>,
    subcmd_args: &[&str],
    opts: &FetchOptions,
    host_env: I,
) -> UaResult<GitCommandSpec>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    #[cfg(not(any(test, feature = "test-util")))]
    let _ = opts;

    let mut args: Vec<String> = Vec::new();
    for kv in GIT_HARDENING_OVERRIDES {
        args.push("-c".into());
        args.push((*kv).into());
    }

    let allow_protocol = match url {
        None => "none",
        Some(u) => match u.scheme {
            SourceScheme::Https => {
                let ip = pinned_ip.ok_or_else(|| {
                    UaError::internal("https skill source fetch requires a classified pinned IP")
                })?;
                args.push("-c".into());
                args.push("http.sslVerify=true".into());
                args.push("-c".into());
                args.push(format!("http.curloptResolve={}", format_curlopt_resolve(&u.host, u.port, ip)));
                u.scheme.git_allow_protocol()
            }
            #[cfg(any(test, feature = "test-util"))]
            SourceScheme::File => {
                if !opts.allow_file_urls {
                    return Err(UaError::invalid("file:// skill sources are disabled"));
                }
                u.scheme.git_allow_protocol()
            }
        },
    };

    if let Some(dir) = repo_dir {
        args.push(format!("--git-dir={}", dir.display()));
    }
    for a in subcmd_args {
        args.push((*a).into());
    }

    let mut env: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in host_env {
        let k = k.into();
        if SAFE_HOST_ENV_KEYS.contains(&k.as_str()) {
            env.insert(k, v.into());
        }
    }
    env.insert("LC_ALL".into(), "C".into());
    env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    env.insert("GIT_PROTOCOL_FROM_USER".into(), "0".into());
    env.insert("GIT_LFS_SKIP_SMUDGE".into(), "1".into());
    env.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
    env.insert("GIT_CONFIG_GLOBAL".into(), "/dev/null".into());
    env.insert("XDG_CONFIG_HOME".into(), "/dev/null".into());
    env.insert("GIT_ALLOW_PROTOCOL".into(), allow_protocol.into());

    Ok(GitCommandSpec { program: "git".into(), args, env })
}

// --- bare cache & locked execution -------------------------------------------------

pub(crate) fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    let full = hex::encode(Sha256::digest(bytes));
    full[..chars.min(full.len())].to_string()
}

/// Org-isolated bare cache directory (`$home/skill_sources/<org_digest>/<url_digest>.git`).
/// Keyed on the exact `canonical_url` so repos differing in path case never
/// share a bare cache.
pub fn cache_dir(data_home: &Path, org_id: &str, canonical_url: &str) -> PathBuf {
    let org_hash = hex_prefix(org_id.as_bytes(), 16);
    let url_hash = hex_prefix(canonical_url.as_bytes(), 24);
    data_home.join("skill_sources").join(org_hash).join(format!("{url_hash}.git"))
}

fn cache_mutex(path: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
    guard.entry(path.to_path_buf()).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
}

pub(crate) fn with_locked_cache<T>(cache: &Path, f: impl FnOnce() -> UaResult<T>) -> UaResult<T> {
    let parent = cache.parent().ok_or_else(|| UaError::internal("invalid cache path"))?;
    fs::create_dir_all(parent)
        .map_err(|e| UaError::internal(format!("could not create skill_sources cache dir: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    let mutex = cache_mutex(cache);
    let _mem_guard = mutex.lock().unwrap_or_else(|e| e.into_inner());

    let lock_path = cache.with_extension("lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&lock_path)
        .map_err(|e| UaError::internal(format!("could not open skill source lock: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(UaError::internal("could not lock skill source cache"));
        }
    }
    let res = f();
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN);
        }
    }
    drop(lock_file);
    res
}

pub(crate) fn dir_size_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(meta) = fs::symlink_metadata(entry.path()) else { continue };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.file_type().is_dir() {
                stack.push(entry.path());
            } else if meta.file_type().is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

fn terminate_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as libc::pid_t;
        if pid > 0 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Run one hardened [`GitCommandSpec`] with process-group timeout enforcement
/// and stdout cap.
pub fn run_git(spec: &GitCommandSpec, timeout: Duration, max_output_bytes: usize) -> UaResult<Vec<u8>> {
    run_git_watched(spec, timeout, max_output_bytes, None)
}

/// Same as [`run_git`], plus an optional live disk-usage watchdog
/// `(watch_dir, max_bytes)` polled while the child runs so a hostile pack is
/// killed mid-transfer rather than only after filling disk.
pub fn run_git_watched(
    spec: &GitCommandSpec,
    timeout: Duration,
    max_output_bytes: usize,
    watch_dir: Option<(&Path, u64)>,
) -> UaResult<Vec<u8>> {
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .env_clear()
        .envs(&spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = cmd.spawn().map_err(|_| UaError::internal("git is not available on this host"))?;
    let mut stdout = child.stdout.take().ok_or_else(|| UaError::internal("git stdout pipe missing"))?;
    let mut stderr = child.stderr.take().ok_or_else(|| UaError::internal("git stderr pipe missing"))?;

    let (out_tx, out_rx) = mpsc::channel::<std::io::Result<(Vec<u8>, bool)>>();
    let cap = max_output_bytes;
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let res = (&mut stdout).take(cap as u64 + 1).read_to_end(&mut buf).map(|_| {
            let overflow = buf.len() > cap;
            if overflow {
                buf.truncate(cap);
            }
            (buf, overflow)
        });
        let _ = out_tx.send(res);
    });
    let (err_tx, err_rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stderr).take(4096).read_to_end(&mut buf);
        let _ = err_tx.send(buf);
    });

    let deadline = Instant::now() + timeout;
    let mut last_size_check = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| UaError::internal(format!("git wait: {e}")))? {
            break status;
        }
        if let Some((dir, max_bytes)) = watch_dir
            && last_size_check.elapsed() >= LIVE_SIZE_POLL_INTERVAL
        {
            last_size_check = Instant::now();
            let used = dir_size_bytes(dir);
            if used > max_bytes {
                terminate_process_group(&mut child);
                let _ = out_rx.recv_timeout(READER_JOIN_GRACE);
                let _ = err_rx.recv_timeout(READER_JOIN_GRACE);
                return Err(UaError::invalid(format!(
                    "skill source transfer exceeded the {max_bytes}-byte cache limit ({used} bytes)"
                )));
            }
        }
        if Instant::now() >= deadline {
            terminate_process_group(&mut child);
            let _ = out_rx.recv_timeout(READER_JOIN_GRACE);
            let _ = err_rx.recv_timeout(READER_JOIN_GRACE);
            return Err(UaError::invalid(format!("git fetch timed out after {}s", timeout.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    let (out, overflow) = out_rx
        .recv_timeout(READER_JOIN_GRACE)
        .map_err(|_| {
            terminate_process_group(&mut child);
            UaError::invalid("git stdout reader did not close after process exit")
        })?
        .map_err(|e| UaError::internal(format!("git stdout read failed: {e}")))?;
    let err_bytes = err_rx.recv_timeout(READER_JOIN_GRACE).unwrap_or_default();

    if overflow {
        return Err(UaError::invalid(format!(
            "git output exceeded the {max_output_bytes}-byte skill source work limit"
        )));
    }
    if !status.success() {
        let detail = String::from_utf8_lossy(&err_bytes);
        let hint = detail.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("git command failed");
        return Err(UaError::invalid(format!("git command failed: {}", hint.trim())));
    }
    Ok(out)
}

/// Result of a verified shallow fetch of an exact commit SHA into the org's bare cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedCommit {
    pub cache_dir: PathBuf,
    pub commit_sha: String,
    pub pinned_ip: Option<IpAddr>,
}

/// Build the exact shallow `--depth=1` fetch command for `refspec` -> `dst_ref`.
pub fn build_fetch_command(
    cache: &Path,
    url: &ParsedSourceUrl,
    pinned_ip: Option<IpAddr>,
    refspec: &str,
    dst_ref: &str,
    opts: &FetchOptions,
) -> UaResult<GitCommandSpec> {
    let mapping = format!("+{refspec}:{dst_ref}");
    build_git_command(
        Some(cache),
        Some(url),
        pinned_ip,
        &[
            "fetch",
            "--quiet",
            "--depth=1",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--",
            &url.canonical_url,
            &mapping,
        ],
        opts,
    )
}

pub(crate) fn ensure_bare_repo(cache: &Path, opts: &FetchOptions) -> UaResult<()> {
    if cache.join("HEAD").is_file() {
        return Ok(());
    }
    let cache_str =
        cache.to_str().ok_or_else(|| UaError::internal("skill source cache path is not valid UTF-8"))?;
    let init_spec =
        build_git_command(None, None, None, &["init", "--quiet", "--bare", "--template=", cache_str], opts)?;
    run_git(&init_spec, opts.timeout, opts.max_output_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(cache, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

pub(crate) fn commit_present(cache: &Path, sha: &str, opts: &FetchOptions) -> bool {
    let target = format!("{sha}^{{commit}}");
    let Ok(spec) = build_git_command(Some(cache), None, None, &["cat-file", "-e", &target], opts) else {
        return false;
    };
    run_git(&spec, opts.timeout, opts.max_output_bytes).is_ok()
}

/// Shallow-fetch the exact 40-char `pinned_sha` from `url` into the org's bare
/// cache, pinned to a classified public IP (for `https://`) and enforcing all
/// §3 bounds (including live cache-size watching during transfer).
///
/// If `verify_tracking_ref` is `Some(ref_name)`, also verifies that shallow
/// resolution of `ref_name` matches `pinned_sha`, refusing on mismatch. Never
/// falls back to a full or unshallow fetch if the remote rejects a SHA want.
pub fn fetch_exact_sha(
    data_home: &Path,
    org_id: &str,
    url: &ParsedSourceUrl,
    pinned_sha: &str,
    verify_tracking_ref: Option<&str>,
    resolver: &dyn DnsResolver,
    opts: &FetchOptions,
) -> UaResult<FetchedCommit> {
    let sha = validate_sha(pinned_sha)?;
    let tracking = verify_tracking_ref.map(validate_tracking_ref).transpose()?;
    let pinned_ip = match url.scheme {
        SourceScheme::Https => Some(classify_and_pin_ip(&url.host, url.port, resolver)?),
        #[cfg(any(test, feature = "test-util"))]
        SourceScheme::File => {
            if !opts.allow_file_urls {
                return Err(UaError::invalid("file:// skill sources are disabled"));
            }
            None
        }
    };

    ensure_supported_git_version(opts)?;

    let cache = cache_dir(data_home, org_id, &url.canonical_url);
    with_locked_cache(&cache, || {
        ensure_bare_repo(&cache, opts)?;

        if let Some(ref_name) = &tracking {
            let dst = format!("refs/ua/track/{}", hex_prefix(ref_name.as_bytes(), 16));
            let spec = build_fetch_command(&cache, url, pinned_ip, ref_name, &dst, opts)?;
            if let Err(e) = run_git_watched(
                &spec,
                opts.timeout,
                opts.max_output_bytes,
                Some((&cache, opts.max_cache_bytes)),
            ) {
                if dir_size_bytes(&cache) > opts.max_cache_bytes {
                    let _ = fs::remove_dir_all(&cache);
                }
                return Err(e);
            }
            let rev_spec = build_git_command(
                Some(&cache),
                None,
                None,
                &["rev-parse", "--verify", "--quiet", &format!("{dst}^{{commit}}")],
                opts,
            )?;
            let out = run_git(&rev_spec, opts.timeout, opts.max_output_bytes)?;
            let got = String::from_utf8_lossy(&out).trim().to_string();
            if got != sha {
                return Err(UaError::conflict(format!(
                    "tracking_ref {ref_name:?} resolved to {got:?}, which does not match pinned_sha {sha:?}; refusing without full-history fallback"
                )));
            }
        } else if !commit_present(&cache, &sha, opts) {
            let dst = format!("refs/ua/fetch/{}", &sha[..16]);
            let spec = build_fetch_command(&cache, url, pinned_ip, &sha, &dst, opts)?;
            if let Err(e) = run_git_watched(
                &spec,
                opts.timeout,
                opts.max_output_bytes,
                Some((&cache, opts.max_cache_bytes)),
            ) {
                if dir_size_bytes(&cache) > opts.max_cache_bytes {
                    let _ = fs::remove_dir_all(&cache);
                    return Err(e);
                }
                return Err(UaError::invalid(format!(
                    "shallow fetch of pinned_sha {sha} failed (no full-history fallback): {e}"
                )));
            }
            let rev_spec = build_git_command(
                Some(&cache),
                None,
                None,
                &["rev-parse", "--verify", "--quiet", &format!("{dst}^{{commit}}")],
                opts,
            )?;
            let out = run_git(&rev_spec, opts.timeout, opts.max_output_bytes)?;
            let got = String::from_utf8_lossy(&out).trim().to_string();
            if got != sha {
                return Err(UaError::conflict(format!(
                    "fetched commit {got:?} does not match pinned_sha {sha:?}"
                )));
            }
        }

        let cache_bytes = dir_size_bytes(&cache);
        if cache_bytes > opts.max_cache_bytes {
            let _ = fs::remove_dir_all(&cache);
            return Err(UaError::invalid(format!(
                "skill source bare cache ({cache_bytes} bytes) exceeded the {}-byte limit",
                opts.max_cache_bytes
            )));
        }

        let pin_ref = format!("refs/ua/sha/{sha}");
        let update_spec = build_git_command(Some(&cache), None, None, &["update-ref", &pin_ref, &sha], opts)?;
        run_git(&update_spec, opts.timeout, opts.max_output_bytes)?;

        Ok(FetchedCommit { cache_dir: cache.clone(), commit_sha: sha, pinned_ip })
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    struct StaticResolver(Vec<IpAddr>);
    impl DnsResolver for StaticResolver {
        fn resolve(&self, _host: &str, _port: u16) -> UaResult<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn url_validation_enforces_section_1_ports_single_label_and_git_suffix() {
        let ok = validate_source_url("https://GitHub.COM/Example-Org/skills-repo/").unwrap();
        assert_eq!(ok.canonical_url, "https://github.com/Example-Org/skills-repo");
        assert_eq!(ok.host, "github.com");
        assert_eq!(ok.port, 443);
        assert_eq!(ok.repo_path, "Example-Org/skills-repo");

        // Trailing .git is preserved in canonical_url so .git-only hosts fetch
        // the exact approved URL, while url_uniqueness_key normalizes it away.
        let dot_git = validate_source_url("https://github.com/Example-Org/skills-repo.git").unwrap();
        assert_eq!(dot_git.canonical_url, "https://github.com/Example-Org/skills-repo.git");
        assert_eq!(dot_git.repo_path, "Example-Org/skills-repo.git");
        let dot_git_upper = validate_source_url("https://github.com/Example-Org/skills-repo.GIT/").unwrap();
        assert_eq!(dot_git_upper.canonical_url, "https://github.com/Example-Org/skills-repo.GIT");
        assert_eq!(url_uniqueness_key(&ok.canonical_url), "https://github.com/example-org/skills-repo");
        assert_eq!(url_uniqueness_key(&dot_git.canonical_url), url_uniqueness_key(&ok.canonical_url));
        assert_eq!(url_uniqueness_key(&dot_git_upper.canonical_url), url_uniqueness_key(&ok.canonical_url));

        // Cache directory keys on the exact canonical URL, not the lowercased form.
        let lower_url = validate_source_url("https://github.com/example-org/skills-repo").unwrap();
        assert_ne!(
            cache_dir(Path::new("/data"), "default", &ok.canonical_url),
            cache_dir(Path::new("/data"), "default", &lower_url.canonical_url),
        );
        assert_ne!(
            cache_dir(Path::new("/data"), "default", &ok.canonical_url),
            cache_dir(Path::new("/data"), "default", &dot_git.canonical_url),
        );

        // Explicit port 443 normalizes cleanly.
        let explicit_443 = validate_source_url("https://github.com:443/Example-Org/skills-repo").unwrap();
        assert_eq!(explicit_443.canonical_url, "https://github.com/Example-Org/skills-repo");

        for bad in [
            "",
            "http://example.com/org/repo",
            "git://example.com/org/repo",
            "ssh://git@example.com/org/repo",
            "git@example.com:org/repo",
            "ext::sh -c evil",
            "file:///tmp/repo",
            "https://user:pass@example.com/org/repo",
            "https://user@example.com/org/repo",
            "https://@example.com/org/repo",
            "https://example.com/org/repo?ref=main",
            "https://example.com/org/repo#frag",
            "https://127.0.0.1/org/repo",
            "https://93.184.215.14/org/repo",
            "https://[::1]/org/repo",
            "https://[2606:4700:4700::1111]/org/repo",
            "https://localhost/org/repo",
            "https://sub.localhost/org/repo",
            "https://metadata/latest/meta-data",
            "https://git/org/repo",
            "https://example.com:22/org/repo",
            "https://example.com:8443/org/repo",
            "https:///evil.com/org/repo",
            "https://example.com/.git",
            "-https://example.com/org/repo",
            "--upload-pack=evil",
            "https://example.com/org/repo\n",
            "https://example.com/org/re\x00po",
            "https://example.com/org/repo with space",
            "https://example.com/",
            "https://example.com/org/../secret",
            "https://example.com/org//repo",
            &format!("https://example.com/{}", "a".repeat(MAX_URL_BYTES)),
        ] {
            assert!(validate_source_url(bad).is_err(), "should refuse {bad:?}");
        }

        // Test-only file:// validator works for local fixtures only.
        let f = validate_file_source_url_for_test("file:///var/fixtures/skills.git/").unwrap();
        assert_eq!(f.scheme, SourceScheme::File);
        assert_eq!(f.canonical_url, "file:///var/fixtures/skills.git");
        assert!(validate_file_source_url_for_test("file://host/path").is_err());
        assert!(validate_file_source_url_for_test("file:///var/../etc").is_err());
    }

    #[test]
    fn git_version_check_refuses_below_2_37() {
        for old in [
            "git version 1.9.5",
            "git version 2.31.1",
            "git version 2.36.9",
            "git version 2.36.0 (Apple Git-130)",
            "not a version",
        ] {
            assert!(check_git_version_output(old).is_err(), "should refuse {old:?}");
        }
        for ok in [
            "git version 2.37.0",
            "git version 2.39.5 (Apple Git-154)",
            "git version 2.56.1",
            "git version 3.0.0",
        ] {
            assert!(check_git_version_output(ok).is_ok(), "should accept {ok:?}");
        }
    }

    #[test]
    fn dns_pinning_refuses_non_public_and_mixed_addresses() {
        let r_priv = StaticResolver(vec!["127.0.0.1".parse().unwrap()]);
        let e = classify_and_pin_ip("example.com", 443, &r_priv).unwrap_err();
        assert_eq!(e.reason_code(), Some("ssrf_blocked"), "{e:?}");

        let r_meta = StaticResolver(vec!["169.254.169.254".parse().unwrap()]);
        assert_eq!(
            classify_and_pin_ip("example.com", 443, &r_meta).unwrap_err().reason_code(),
            Some("ssrf_blocked")
        );

        let cloud_meta = IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200));
        let r_cloud = StaticResolver(vec![cloud_meta]);
        assert_eq!(
            classify_and_pin_ip("example.com", 443, &r_cloud).unwrap_err().reason_code(),
            Some("ssrf_blocked")
        );

        let r_mixed = StaticResolver(vec!["93.184.215.14".parse().unwrap(), "10.0.0.1".parse().unwrap()]);
        assert_eq!(
            classify_and_pin_ip("example.com", 443, &r_mixed).unwrap_err().reason_code(),
            Some("ssrf_blocked")
        );

        let r_pub =
            StaticResolver(vec!["2606:4700:4700::1111".parse().unwrap(), "93.184.215.14".parse().unwrap()]);
        assert_eq!(
            classify_and_pin_ip("example.com", 443, &r_pub).unwrap(),
            "93.184.215.14".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn hardened_git_command_asserts_exact_flags_and_scrubbed_env() {
        let parsed = validate_source_url("https://github.com/example/skills").unwrap();
        let ip: IpAddr = "93.184.215.14".parse().unwrap();
        let opts = FetchOptions::production();
        let dirty_env = vec![
            ("PATH", "/usr/bin"),
            ("HOME", "/nonexistent/home"),
            ("HTTPS_PROXY", "http://evil.proxy:8080"),
            ("https_proxy", "http://evil.proxy:8080"),
            ("HTTP_PROXY", "http://evil.proxy:8080"),
            ("http_proxy", "http://evil.proxy:8080"),
            ("ALL_PROXY", "socks5://evil.proxy:1080"),
            ("all_proxy", "socks5://evil.proxy:1080"),
            ("NO_PROXY", "*"),
            ("no_proxy", "*"),
            ("SSH_AUTH_SOCK", "/run/ssh.sock"),
            ("SSH_ASKPASS", "/bin/askpass"),
            ("GIT_ASKPASS", "/bin/askpass"),
            ("GIT_SSH_COMMAND", "ssh -o ProxyCommand=evil"),
            ("GIT_CONFIG_PARAMETERS", "'core.hooksPath=/tmp/evil'"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GITHUB_TOKEN", "ghp_should_not_leak"),
            ("GH_TOKEN", "ghp_should_not_leak"),
        ];
        let spec = build_git_command_with_host_env(
            Some(Path::new("/cache/repo.git")),
            Some(&parsed),
            Some(ip),
            &[
                "fetch",
                "--quiet",
                "--depth=1",
                "--no-tags",
                "--no-recurse-submodules",
                "--no-write-fetch-head",
                "--",
                &parsed.canonical_url,
                "+0123456789abcdef0123456789abcdef01234567:refs/ua/fetch/0123456789abcdef",
            ],
            &opts,
            dirty_env,
        )
        .unwrap();

        assert_eq!(spec.program, "git");
        let pairs: Vec<(&str, &str)> =
            spec.args.windows(2).filter(|w| w[0] == "-c").map(|w| (w[0].as_str(), w[1].as_str())).collect();
        for required in [
            "core.hooksPath=/dev/null",
            "core.fsmonitor=false",
            "core.quotePath=false",
            "core.bigFileThreshold=524288",
            "gc.auto=0",
            "protocol.ext.allow=never",
            "submodule.recurse=false",
            "fetch.recurseSubmodules=false",
            "credential.interactive=never",
            "credential.helper=",
            "http.proxy=",
            "http.followRedirects=false",
            "http.lowSpeedLimit=1000",
            "http.lowSpeedTime=30",
            "filter.lfs.smudge=",
            "filter.lfs.clean=",
            "filter.lfs.process=",
            "filter.lfs.required=false",
            "http.sslVerify=true",
            "http.curloptResolve=github.com:443:93.184.215.14",
        ] {
            assert!(pairs.iter().any(|(_, v)| *v == required), "missing -c {required} in {:?}", spec.args);
        }

        for stripped in [
            "HOME",
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "SSH_AUTH_SOCK",
            "SSH_ASKPASS",
            "GIT_ASKPASS",
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
            "GITHUB_TOKEN",
            "GH_TOKEN",
        ] {
            assert!(!spec.env.contains_key(stripped), "env leaked {stripped}: {:?}", spec.env);
        }
        assert_eq!(spec.env.get("GIT_CONFIG_GLOBAL").map(String::as_str), Some("/dev/null"));
        assert_eq!(spec.env.get("XDG_CONFIG_HOME").map(String::as_str), Some("/dev/null"));
        assert_eq!(spec.env.get("GIT_ALLOW_PROTOCOL").map(String::as_str), Some("https"));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_entire_process_group_without_waiting_for_grandchild() {
        let mut env = BTreeMap::new();
        if let Ok(path) = std::env::var("PATH") {
            env.insert("PATH".into(), path);
        }
        let spec = GitCommandSpec {
            program: "sh".into(),
            args: vec!["-c".into(), "sleep 12 & exec sleep 60".into()],
            env,
        };
        let start = Instant::now();
        let err = run_git(&spec, Duration::from_secs(1), 4096).unwrap_err();
        let elapsed = start.elapsed();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(elapsed < Duration::from_secs(4), "timeout waited for grandchild: {elapsed:?}");
    }

    #[cfg(unix)]
    #[test]
    fn live_cache_size_watchdog_kills_streaming_transfer_mid_flight() {
        let tmp = tempfile::tempdir().unwrap();
        let watch = tmp.path().join("cache");
        fs::create_dir_all(&watch).unwrap();
        let target = watch.join("tmp_pack_stream");
        let mut env = BTreeMap::new();
        if let Ok(path) = std::env::var("PATH") {
            env.insert("PATH".into(), path);
        }
        let spec = GitCommandSpec {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                format!("dd if=/dev/zero of='{}' bs=4096 count=16 2>/dev/null; sleep 10", target.display()),
            ],
            env,
        };
        let start = Instant::now();
        let err = run_git_watched(&spec, Duration::from_secs(10), 4096, Some((&watch, 8192))).unwrap_err();
        let elapsed = start.elapsed();
        assert!(err.to_string().contains("cache limit"), "{err}");
        assert!(elapsed < Duration::from_secs(3), "watchdog did not abort mid-transfer: {elapsed:?}");
    }

    #[test]
    fn local_file_fixture_fetches_exact_sha_into_bare_cache_and_refuses_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let remote = tmp.path().join("remote-skills");
        let data_home = tmp.path().join("data");
        fs::create_dir_all(&remote).unwrap();

        let git_ok = |dir: &Path, args: &[&str]| -> String {
            let out = Command::new("git")
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        git_ok(&remote, &["init", "-b", "main"]);
        fs::create_dir_all(remote.join("skills/demo")).unwrap();
        fs::write(remote.join("skills/demo/SKILL.md"), "---\nname: demo\n---\nhello\n").unwrap();
        git_ok(&remote, &["add", "."]);
        git_ok(&remote, &["commit", "-m", "v1"]);
        let sha1 = git_ok(&remote, &["rev-parse", "HEAD"]);

        fs::write(remote.join("skills/demo/SKILL.md"), "---\nname: demo\n---\nv2\n").unwrap();
        git_ok(&remote, &["add", "."]);
        git_ok(&remote, &["commit", "-m", "v2"]);
        let sha2 = git_ok(&remote, &["rev-parse", "HEAD"]);

        let file_url = format!("file://{}", remote.display());
        let parsed = validate_file_source_url_for_test(&file_url).unwrap();
        let opts = FetchOptions::for_local_file_test();
        let no_dns = StaticResolver(vec![]);

        // Production options refuse file:// even with a parsed URL.
        assert!(
            fetch_exact_sha(
                &data_home,
                "default",
                &parsed,
                &sha2,
                Some("main"),
                &no_dns,
                &FetchOptions::production()
            )
            .is_err()
        );

        let fetched =
            fetch_exact_sha(&data_home, "default", &parsed, &sha2, Some("main"), &no_dns, &opts).unwrap();
        assert_eq!(fetched.commit_sha, sha2);
        assert!(fetched.cache_dir.join("HEAD").is_file());
        assert!(!fetched.cache_dir.join("skills").exists(), "bare cache must never check out files");

        let mismatch =
            fetch_exact_sha(&data_home, "default", &parsed, &sha1, Some("main"), &no_dns, &opts).unwrap_err();
        assert!(matches!(mismatch, UaError::Conflict { .. }), "{mismatch:?}");

        let fake_sha = "f".repeat(40);
        let missing =
            fetch_exact_sha(&data_home, "default", &parsed, &fake_sha, None, &no_dns, &opts).unwrap_err();
        assert!(missing.to_string().contains("no full-history fallback"), "{missing}");

        let tiny_opts = FetchOptions { max_cache_bytes: 1, ..opts };
        let capped =
            fetch_exact_sha(&data_home, "org-small", &parsed, &sha2, Some("main"), &no_dns, &tiny_opts)
                .unwrap_err();
        assert!(capped.to_string().contains("limit"), "{capped}");
    }

    #[test]
    fn https_fetch_blocks_when_dns_resolves_to_private_ip() {
        let tmp = tempfile::tempdir().unwrap();
        let parsed = validate_source_url("https://github.com/example/skills").unwrap();
        let sha = "a".repeat(40);
        let bad_dns = StaticResolver(vec!["127.0.0.1".parse().unwrap()]);
        let err = fetch_exact_sha(
            tmp.path(),
            "default",
            &parsed,
            &sha,
            Some("main"),
            &bad_dns,
            &FetchOptions::production(),
        )
        .unwrap_err();
        assert_eq!(err.reason_code(), Some("ssrf_blocked"), "{err:?}");
    }
}
