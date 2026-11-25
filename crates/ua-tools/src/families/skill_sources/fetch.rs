//! Hardened Git fetch plumbing for skill sources (`docs/skill-sources.md` §1, §3).
//!
//! Safety properties enforced on every fetch:
//! - Public `https://` sources only by default (`ssh://` off by default;
//!   `file://` permitted only via [`FetchOptions::for_local_file_test`]).
//! - Zero credentials, queries, fragments, IP literals, leading `-`, or control
//!   characters in URLs.
//! - DNS resolved once per fetch, **every** returned IP classified against
//!   `ua_ingress::addr` (failing the whole fetch on any non-public or cloud
//!   metadata address), and the fetch pinned to the classified IP via
//!   `-c http.curloptResolve=<host>:<port>:<ip>`.
//! - Bare cache initialized with `--bare --template=` (mode `0700`), serialized
//!   by an exclusive file lock + in-process mutex; no working tree is ever
//!   checked out.
//! - Scrubbed environment (all `GIT_*`, `SSH_AUTH_SOCK`, `*_ASKPASS`, and
//!   proxy variables cleared) plus CLI `-c` overrides disabling hooks,
//!   fsmonitor, submodules, LFS/filters, credential helpers, proxies, and
//!   redirects (`http.followRedirects=false`).
//! - Shallow `--depth=1` fetch of the exact 40-char commit SHA with no fallback
//!   to a full fetch, bounded by wall-clock timeout, stdout cap, and cache size cap.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};
use url::{Host, Url};

pub const MAX_URL_BYTES: usize = 512;
pub const MAX_REF_BYTES: usize = 200;
pub const MAX_SUBPATH_BYTES: usize = 240;
pub const MAX_ALLOWED_SUBPATHS: usize = 32;
pub const DEFAULT_GIT_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceScheme {
    Https,
    File,
}

impl SourceScheme {
    pub fn git_allow_protocol(self) -> &'static str {
        match self {
            SourceScheme::Https => "https",
            SourceScheme::File => "file",
        }
    }
}

/// A validated, canonical skill source URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSourceUrl {
    pub canonical_url: String,
    pub scheme: SourceScheme,
    pub host: String,
    pub port: u16,
    pub repo_path: String,
}

fn valid_domain_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_domain(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return false;
    }
    // Reject any dotted-quad or IP-like string even if parsed as a domain.
    if lower.parse::<IpAddr>().is_ok() {
        return false;
    }
    lower.split('.').all(valid_domain_label)
}

/// Validate a skill source URL per `docs/skill-sources.md` §1.
///
/// Production callers always pass `allow_file = false`: only `https://` URLs
/// with a public-style DNS hostname and repository path are accepted (`ssh://`,
/// `http://`, `git://`, `ext::`, `file://`, credentials, queries, fragments,
/// IP literals, leading `-`, and control characters are refused).
pub fn validate_source_url(raw: &str, allow_file: bool) -> UaResult<ParsedSourceUrl> {
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

    if let Some(rest) = text.strip_prefix("file://") {
        if !allow_file {
            return Err(UaError::invalid(
                "file:// skill sources are disabled; only https:// skill sources are accepted",
            ));
        }
        if !rest.starts_with('/') || rest.len() < 2 {
            return Err(UaError::invalid("file:// skill source must be file:///absolute/path"));
        }
        let path_part = rest.trim_end_matches('/');
        if path_part.is_empty() || path_part.split('/').any(|s| s == "..") {
            return Err(UaError::invalid("file:// skill source path must not contain '..'"));
        }
        return Ok(ParsedSourceUrl {
            canonical_url: format!("file://{path_part}"),
            scheme: SourceScheme::File,
            host: String::new(),
            port: 0,
            repo_path: path_part.to_string(),
        });
    }

    if !text.starts_with("https://") {
        return Err(UaError::invalid(
            "skill source url must use https:// (ssh://, http://, git://, ext::, and file:// are refused)",
        ));
    }
    let after_scheme = &text["https://".len()..];
    let Some((authority, raw_after_slash)) = after_scheme.split_once('/') else {
        return Err(UaError::invalid("skill source url needs a repository path"));
    };
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
                    "skill source host {d:?} must be a public DNS hostname, not an IP literal or localhost"
                )));
            }
            lower
        }
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => {
            return Err(UaError::invalid("skill source url must not use an IP literal"));
        }
        None => return Err(UaError::invalid("skill source url needs a hostname")),
    };
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err(UaError::invalid("skill source url port must be non-zero"));
    }

    let raw_path = parsed.path().trim_matches('/');
    if raw_path.is_empty() {
        return Err(UaError::invalid("skill source url needs a repository path"));
    }
    for seg in raw_path.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(UaError::invalid("skill source repository path contains an unsafe segment"));
        }
    }
    let canonical_url = if port == 443 {
        format!("https://{host}/{raw_path}")
    } else {
        format!("https://{host}:{port}/{raw_path}")
    };
    Ok(ParsedSourceUrl {
        canonical_url,
        scheme: SourceScheme::Https,
        host,
        port,
        repo_path: raw_path.to_string(),
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
            || trimmed.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            return Err(UaError::invalid(format!("unsafe allowed_subpaths entry {entry:?}")));
        }
        for part in trimmed.split('/') {
            if part.is_empty() || part == "." || part == ".." || part.starts_with('.') {
                return Err(UaError::invalid(format!("unsafe allowed_subpaths entry {entry:?}")));
            }
        }
        out.push(trimmed.to_string());
    }
    out.sort();
    out.dedup();
    Ok(out)
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
    // Prefer an IPv4 public address when both v4 and v6 are returned.
    Ok(addrs.iter().copied().find(IpAddr::is_ipv4).unwrap_or(addrs[0]))
}

fn format_curlopt_resolve(host: &str, port: u16, ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{host}:{port}:{v4}"),
        IpAddr::V6(v6) => format!("{host}:{port}:[{v6}]"),
    }
}

// --- hardened git command builder --------------------------------------------------

/// Runtime bounds and test-only toggles for [`fetch_exact_sha`].
#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub allow_file_urls: bool,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub max_cache_bytes: u64,
}

impl FetchOptions {
    /// Production defaults: `https://` only (`file://` refused), 120s timeout,
    /// 16 MiB stdout cap, 64 MiB bare cache cap.
    pub fn production() -> Self {
        Self {
            allow_file_urls: false,
            timeout: DEFAULT_GIT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_cache_bytes: DEFAULT_MAX_CACHE_BYTES,
        }
    }

    /// Test-only options enabling local `file://` fixtures without network I/O.
    pub fn for_local_file_test() -> Self {
        Self { allow_file_urls: true, ..Self::production() }
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
    "protocol.ext.allow=never",
    "submodule.recurse=false",
    "fetch.recurseSubmodules=false",
    "credential.interactive=never",
    "credential.helper=",
    "http.proxy=",
    "http.followRedirects=false",
    "filter.lfs.smudge=",
    "filter.lfs.clean=",
    "filter.lfs.process=",
    "filter.lfs.required=false",
    "transfer.fsckObjects=true",
    "fetch.fsckObjects=true",
];

/// Environment variables inherited from the host when building the scrubbed
/// git environment (everything else — `GIT_*`, `SSH_AUTH_SOCK`, `*_ASKPASS`,
/// proxy vars, ambient tokens — is dropped).
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

/// Deterministic variant taking explicit `host_env` pairs so tests can prove
/// that proxy variables, `SSH_AUTH_SOCK`, `GIT_ASKPASS`, `GIT_*`, and ambient
/// tokens are stripped regardless of the test runner's environment.
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
    env.insert("GIT_ALLOW_PROTOCOL".into(), allow_protocol.into());

    Ok(GitCommandSpec { program: "git".into(), args, env })
}

// --- bare cache & locked execution -------------------------------------------------

fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    let full = hex::encode(Sha256::digest(bytes));
    full[..chars.min(full.len())].to_string()
}

/// Org-isolated bare cache directory (`$home/skill_sources/<org_digest>/<url_digest>.git`).
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

fn with_locked_cache<T>(cache: &Path, f: impl FnOnce() -> UaResult<T>) -> UaResult<T> {
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

fn dir_size_bytes(root: &Path) -> u64 {
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

/// Run one hardened [`GitCommandSpec`] with wall-clock timeout and stdout cap.
pub fn run_git(spec: &GitCommandSpec, timeout: Duration, max_output_bytes: usize) -> UaResult<Vec<u8>> {
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .env_clear()
        .envs(&spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|_| UaError::internal("git is not available on this host"))?;
    let mut stdout = child.stdout.take().ok_or_else(|| UaError::internal("git stdout pipe missing"))?;
    let mut stderr = child.stderr.take().ok_or_else(|| UaError::internal("git stderr pipe missing"))?;

    let cap = max_output_bytes;
    let out_thread = std::thread::spawn(move || -> std::io::Result<(Vec<u8>, bool)> {
        let mut buf = Vec::new();
        (&mut stdout).take(cap as u64 + 1).read_to_end(&mut buf)?;
        let overflow = buf.len() > cap;
        if overflow {
            buf.truncate(cap);
        }
        Ok((buf, overflow))
    });
    let err_thread = std::thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = (&mut stderr).take(4096).read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| UaError::internal(format!("git wait: {e}")))? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_thread.join();
            let _ = err_thread.join();
            return Err(UaError::invalid(format!("git fetch timed out after {}s", timeout.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    let (out, overflow) = out_thread
        .join()
        .map_err(|_| UaError::internal("git stdout reader panicked"))?
        .map_err(|e| UaError::internal(format!("git stdout read failed: {e}")))?;
    let err_bytes = err_thread.join().unwrap_or_default();

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

fn ensure_bare_repo(cache: &Path, opts: &FetchOptions) -> UaResult<()> {
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

fn commit_present(cache: &Path, sha: &str, opts: &FetchOptions) -> bool {
    let target = format!("{sha}^{{commit}}");
    let Ok(spec) = build_git_command(Some(cache), None, None, &["cat-file", "-e", &target], opts) else {
        return false;
    };
    run_git(&spec, opts.timeout, opts.max_output_bytes).is_ok()
}

/// Shallow-fetch the exact 40-char `pinned_sha` from `url` into the org's bare
/// cache, pinned to a classified public IP (for `https://`) and enforcing all
/// §3 bounds.
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
        SourceScheme::File => {
            if !opts.allow_file_urls {
                return Err(UaError::invalid("file:// skill sources are disabled"));
            }
            None
        }
    };

    let cache = cache_dir(data_home, org_id, &url.canonical_url);
    with_locked_cache(&cache, || {
        ensure_bare_repo(&cache, opts)?;

        if let Some(ref_name) = &tracking {
            let dst = format!("refs/ua/track/{}", hex_prefix(ref_name.as_bytes(), 16));
            let spec = build_fetch_command(&cache, url, pinned_ip, ref_name, &dst, opts)?;
            run_git(&spec, opts.timeout, opts.max_output_bytes)?;
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
            run_git(&spec, opts.timeout, opts.max_output_bytes).map_err(|e| {
                UaError::invalid(format!(
                    "shallow fetch of pinned_sha {sha} failed (no full-history fallback): {e}"
                ))
            })?;
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

        // Pin the commit locally so git gc never drops it.
        let pin_ref = format!("refs/ua/sha/{sha}");
        let update_spec = build_git_command(Some(&cache), None, None, &["update-ref", &pin_ref, &sha], opts)?;
        run_git(&update_spec, opts.timeout, opts.max_output_bytes)?;

        Ok(FetchedCommit { cache_dir: cache.clone(), commit_sha: sha, pinned_ip })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticResolver(Vec<IpAddr>);
    impl DnsResolver for StaticResolver {
        fn resolve(&self, _host: &str, _port: u16) -> UaResult<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn url_validation_enforces_section_1() {
        let ok = validate_source_url("https://GitHub.COM/Example-Org/skills-repo/", false).unwrap();
        assert_eq!(ok.canonical_url, "https://github.com/Example-Org/skills-repo");
        assert_eq!(ok.host, "github.com");
        assert_eq!(ok.port, 443);
        assert_eq!(ok.repo_path, "Example-Org/skills-repo");

        let with_port = validate_source_url("https://git.example.com:8443/team/skills", false).unwrap();
        assert_eq!(with_port.canonical_url, "https://git.example.com:8443/team/skills");
        assert_eq!(with_port.port, 8443);

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
            assert!(validate_source_url(bad, false).is_err(), "should refuse {bad:?}");
        }

        // file:// is allowed ONLY when the explicit test-only flag is true.
        let f = validate_source_url("file:///var/fixtures/skills.git/", true).unwrap();
        assert_eq!(f.scheme, SourceScheme::File);
        assert_eq!(f.canonical_url, "file:///var/fixtures/skills.git");
        assert!(validate_source_url("file://host/path", true).is_err());
        assert!(validate_source_url("file:///var/../etc", true).is_err());
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

        let r_cloud = StaticResolver(vec!["100.100.100.200".parse().unwrap()]);
        assert_eq!(
            classify_and_pin_ip("example.com", 443, &r_cloud).unwrap_err().reason_code(),
            Some("ssrf_blocked")
        );

        // Mixed public + private answer must refuse the whole fetch.
        let r_mixed = StaticResolver(vec!["93.184.215.14".parse().unwrap(), "10.0.0.1".parse().unwrap()]);
        assert_eq!(
            classify_and_pin_ip("example.com", 443, &r_mixed).unwrap_err().reason_code(),
            Some("ssrf_blocked")
        );

        // Pure public answer pins the IP.
        let r_pub =
            StaticResolver(vec!["2606:4700:4700::1111".parse().unwrap(), "93.184.215.14".parse().unwrap()]);
        assert_eq!(
            classify_and_pin_ip("example.com", 443, &r_pub).unwrap(),
            "93.184.215.14".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn hardened_git_command_asserts_exact_flags_and_scrubbed_env() {
        let parsed = validate_source_url("https://github.com/example/skills", false).unwrap();
        let ip: IpAddr = "93.184.215.14".parse().unwrap();
        let opts = FetchOptions::production();
        let dirty_env = vec![
            ("PATH", "/usr/bin"),
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
            "protocol.ext.allow=never",
            "submodule.recurse=false",
            "fetch.recurseSubmodules=false",
            "credential.interactive=never",
            "credential.helper=",
            "http.proxy=",
            "http.followRedirects=false",
            "filter.lfs.smudge=",
            "filter.lfs.clean=",
            "filter.lfs.process=",
            "filter.lfs.required=false",
            "http.sslVerify=true",
            "http.curloptResolve=github.com:443:93.184.215.14",
        ] {
            assert!(pairs.iter().any(|(_, v)| *v == required), "missing -c {required} in {:?}", spec.args);
        }
        assert!(spec.args.contains(&"--depth=1".to_string()));
        assert!(spec.args.contains(&"--no-tags".to_string()));
        assert!(spec.args.contains(&"--no-recurse-submodules".to_string()));
        assert!(spec.args.contains(&"--no-write-fetch-head".to_string()));

        // Scrubbed environment: zero proxies, zero SSH/askpass, zero tokens.
        for stripped in [
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
            "GITHUB_TOKEN",
            "GH_TOKEN",
        ] {
            assert!(!spec.env.contains_key(stripped), "env leaked {stripped}: {:?}", spec.env);
        }
        assert_eq!(spec.env.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(spec.env.get("LC_ALL").map(String::as_str), Some("C"));
        assert_eq!(spec.env.get("GIT_TERMINAL_PROMPT").map(String::as_str), Some("0"));
        assert_eq!(spec.env.get("GIT_PROTOCOL_FROM_USER").map(String::as_str), Some("0"));
        assert_eq!(spec.env.get("GIT_LFS_SKIP_SMUDGE").map(String::as_str), Some("1"));
        assert_eq!(spec.env.get("GIT_CONFIG_NOSYSTEM").map(String::as_str), Some("1"));
        assert_eq!(spec.env.get("GIT_CONFIG_GLOBAL").map(String::as_str), Some("/dev/null"));
        assert_eq!(spec.env.get("GIT_ALLOW_PROTOCOL").map(String::as_str), Some("https"));

        // IPv6 pinning wraps the address in brackets for libcurl.
        let v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        let spec_v6 = build_git_command_with_host_env(
            None,
            Some(&parsed),
            Some(v6),
            &["ls-remote"],
            &opts,
            Vec::<(&str, &str)>::new(),
        )
        .unwrap();
        assert!(
            spec_v6.args.contains(&"http.curloptResolve=github.com:443:[2606:4700:4700::1111]".to_string()),
            "{:?}",
            spec_v6.args
        );
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
        let parsed = validate_source_url(&file_url, true).unwrap();
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

        // Tracking ref matching pinned_sha succeeds into a bare cache with no worktree.
        let fetched =
            fetch_exact_sha(&data_home, "default", &parsed, &sha2, Some("main"), &no_dns, &opts).unwrap();
        assert_eq!(fetched.commit_sha, sha2);
        assert!(fetched.cache_dir.join("HEAD").is_file());
        assert!(!fetched.cache_dir.join("skills").exists(), "bare cache must never check out files");

        // Tracking ref disagreeing with pinned_sha is refused (no full-history fallback).
        let mismatch =
            fetch_exact_sha(&data_home, "default", &parsed, &sha1, Some("main"), &no_dns, &opts).unwrap_err();
        assert!(matches!(mismatch, UaError::Conflict { .. }), "{mismatch:?}");

        // Non-existent SHA want is refused without full-history fallback.
        let fake_sha = "f".repeat(40);
        let missing =
            fetch_exact_sha(&data_home, "default", &parsed, &fake_sha, None, &no_dns, &opts).unwrap_err();
        assert!(missing.to_string().contains("no full-history fallback"), "{missing}");

        // Cache size cap refuses an oversized cache.
        let tiny_opts = FetchOptions { max_cache_bytes: 1, ..opts };
        let capped =
            fetch_exact_sha(&data_home, "org-small", &parsed, &sha2, Some("main"), &no_dns, &tiny_opts)
                .unwrap_err();
        assert!(capped.to_string().contains("limit"), "{capped}");
    }

    #[test]
    fn https_fetch_blocks_when_dns_resolves_to_private_ip() {
        let tmp = tempfile::tempdir().unwrap();
        let parsed = validate_source_url("https://github.com/example/skills", false).unwrap();
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
