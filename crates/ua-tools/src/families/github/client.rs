//! The GitHub REST client.
//!
//! - **One host.** Every request goes to `github_api_url` (default
//!   `https://api.github.com`; a GitHub Enterprise Server API root works the
//!   same). The URL must be `https` without credentials, query or fragment
//!   (plain `http` only to loopback under the `fetch_allow_loopback` test
//!   hook). Requests go through `ua_ingress::Outbound`: the public API under
//!   the `github.rest` policy (that one host, public addresses only, checked
//!   at connect time and again on the connection's peer), any other base
//!   under `github.enterprise` (the operator's GHES host may be on a private
//!   network or this host; link-local, multicast and reserved addresses are
//!   still refused). No proxy is used.
//! - **No redirects.** A 3xx other than 304 is an error, never followed, so
//!   the token is never sent anywhere else. The token is a secret header,
//!   bound to the API base's origin.
//! - **Bound repositories only.** Every call takes a [`BoundRepo`], which
//!   exists only for a repository some project is bound to
//!   (`project_repo_bind`). Paths are built from the normalized `owner/name`
//!   and numeric ids, never from caller text.
//! - **Bounded.** 20 seconds per request, 8 MiB per body, JSON only.
//! - **One connection pool per API base.** The `Outbound` client for a base URL
//!   is built once and reused by every later request (connections and TLS
//!   sessions are kept), never rebuilt per call.
//! - **Rate-limit aware.** `x-ratelimit-remaining: 0` (or a 403/429 that says
//!   so) blocks further requests to that host until `x-ratelimit-reset`
//!   (or `retry-after`), without touching the network.
//! - **The token** comes from [`Config::github_token`] (the variable
//!   `github_token_env` names). It is sent as a sensitive header and never
//!   stored, returned or logged. A GitHub App installation token can stand
//!   in for it later; once the managed-secret store lands, it becomes the
//!   token's source.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use reqwest::header::ETAG;
use reqwest::{StatusCode, Url};
use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use ua_core::{Config, UaError, UaResult};
use ua_ingress::{Outbound, OutboundError, Request, policy};

/// The policies' body cap (both GitHub policies have the same).
const MAX_BODY: usize = policy::GITHUB_REST.max_body_bytes;
const API_VERSION: &str = "2022-11-28";
/// Longest a rate-limit block is honoured, whatever the server says.
const MAX_BLOCK_S: i64 = 3600;

/// Why a GitHub request did not produce a usable answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GhError {
    /// No token configured, or the base URL is unusable.
    NotConfigured(String),
    NotFound,
    /// 401: the token is missing, expired or wrong.
    Unauthorized,
    /// 403 that is not a rate limit: the token may not read this.
    Forbidden,
    /// Rate limited until this Unix second (when known).
    RateLimited(Option<i64>),
    /// Any other HTTP status.
    Status(u16),
    /// A redirect, which is never followed.
    Redirect(u16),
    Network(String),
    TooLarge,
    Decode(String),
}

impl GhError {
    /// One line for a record or a log. Never contains the token.
    pub(crate) fn detail(&self) -> String {
        match self {
            GhError::NotConfigured(why) => why.clone(),
            GhError::NotFound => "GitHub answered 404 (missing, or the token cannot see it)".into(),
            GhError::Unauthorized => "GitHub refused the token (401)".into(),
            GhError::Forbidden => "the token may not read this (403)".into(),
            GhError::RateLimited(Some(reset)) => format!("GitHub rate limit reached; resets at unix {reset}"),
            GhError::RateLimited(None) => "GitHub rate limit reached".into(),
            GhError::Status(s) => format!("GitHub answered HTTP {s}"),
            GhError::Redirect(s) => {
                format!("GitHub answered a redirect (HTTP {s}); redirects are never followed")
            }
            GhError::Network(e) => format!("GitHub request failed: {e}"),
            GhError::TooLarge => format!("GitHub response larger than {MAX_BODY} bytes"),
            GhError::Decode(e) => format!("GitHub response is not the expected JSON: {e}"),
        }
    }
}

/// A repository some project is bound to, normalized `owner/name`. The only
/// way to name a repository to [`GitHub`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BoundRepo(String);

impl BoundRepo {
    /// `repo` if a project is bound to it.
    pub(crate) fn check(conn: &Connection, repo: &str) -> UaResult<BoundRepo> {
        let want = repo.trim().to_ascii_lowercase();
        let found: Option<String> = conn
            .query_row(
                "SELECT repo FROM project_repo_bindings WHERE lower(repo) = ?1 LIMIT 1",
                [&want],
                |r| r.get(0),
            )
            .ok();
        match found {
            Some(r) => Ok(BoundRepo(r.to_ascii_lowercase())),
            None => Err(UaError::denied(
                "repo_not_bound",
                format!("{want:?} is not bound to any project; bind it with project_repo_bind first"),
            )),
        }
    }

    /// Every bound repository, once each.
    pub(crate) fn all(conn: &Connection) -> UaResult<Vec<BoundRepo>> {
        let mut stmt = conn.prepare("SELECT DISTINCT lower(repo) FROM project_repo_bindings ORDER BY 1")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows.into_iter().map(BoundRepo).collect())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A response: a fresh JSON body with its ETag, or 304 Not Modified.
#[derive(Debug)]
pub(crate) enum Got {
    Fresh { etag: Option<String>, body: Value },
    NotModified,
}

/// A GitHub REST client pinned to one API host.
pub(crate) struct GitHub {
    base: Url,
    http: Arc<Outbound>,
    token: SecretString,
}

/// The clients built so far, one per (API base, loopback test hook).
type Clients = Mutex<HashMap<(String, bool), Arc<Outbound>>>;

fn clients() -> &'static Clients {
    static CLIENTS: OnceLock<Clients> = OnceLock::new();
    CLIENTS.get_or_init(Mutex::default)
}

/// The policy for `base`: `github.rest` for the public API, else
/// `github.enterprise`; under the loopback test hook when it is on.
fn policy_for(base: &Url, allow_loopback: bool) -> ua_ingress::Policy {
    let public_api = base
        .host_str()
        .is_some_and(|h| h.strip_suffix('.').unwrap_or(h).eq_ignore_ascii_case("api.github.com"));
    let p = if public_api { policy::GITHUB_REST } else { policy::GITHUB_ENTERPRISE };
    if allow_loopback { p.loopback_test_hook() } else { p }
}

/// The shared client for `base`, built on first use. The second value says
/// whether this call built it.
fn shared_client(base: &Url, allow_loopback: bool) -> Result<(Arc<Outbound>, bool), GhError> {
    let key = (base.as_str().to_string(), allow_loopback);
    let mut map =
        clients().lock().map_err(|_| GhError::NotConfigured("HTTP client cache poisoned".into()))?;
    if let Some(c) = map.get(&key) {
        return Ok((c.clone(), false));
    }
    // Pinned to the base's origin: `github.enterprise` builds no other client.
    let http = Outbound::pinned(policy_for(base, allow_loopback), base)
        .map(Arc::new)
        .map_err(|e| GhError::NotConfigured(format!("cannot build the HTTP client: {e}")))?;
    if map.len() >= 16 {
        // Only a reconfigured base adds entries; keep the cache bounded anyway.
        map.clear();
    }
    map.insert(key, http.clone());
    Ok((http, true))
}

/// Hosts blocked by a rate limit, until a Unix second.
fn blocks() -> &'static Mutex<HashMap<String, i64>> {
    static BLOCKS: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    BLOCKS.get_or_init(Mutex::default)
}

fn now_s() -> i64 {
    ua_core::time::now_ms() / 1000
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// The configured API base, vetted.
pub(crate) fn api_base(cfg: &Config) -> Result<Url, GhError> {
    let bad = |why: &str| GhError::NotConfigured(format!("github_api_url is unusable: {why}"));
    let mut url = Url::parse(cfg.github_api_url.trim()).map_err(|_| bad("not a URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("it must not carry credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(bad("it must not carry a query or fragment"));
    }
    match url.scheme() {
        "https" => {}
        "http" if cfg.fetch_allow_loopback && is_loopback_host(&url) => {}
        _ => return Err(bad("it must be https")),
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(bad("it has no host"));
    }
    // One spelling for the public API (the parser lowercases):
    // `api.github.com.` is the public API too, and must get its policy. Any
    // other host keeps the spelling the operator wrote: a trailing dot there
    // can be deliberate (it stops the resolver from trying search domains).
    if url.host_str() == Some("api.github.com.") {
        url.set_host(Some("api.github.com")).map_err(|_| bad("it has no host"))?;
    }
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Ok(url)
}

impl GitHub {
    /// The client for `cfg`, `Ok(None)` when no token is configured.
    pub(crate) fn from_config(cfg: &Config) -> Result<Option<GitHub>, GhError> {
        let Some(token) = cfg.github_token() else { return Ok(None) };
        let base = api_base(cfg)?;
        let (http, _) = shared_client(&base, cfg.fetch_allow_loopback)?;
        Ok(Some(GitHub { base, http, token }))
    }

    /// The client, or an error saying why there is none.
    pub(crate) fn require(cfg: &Config) -> Result<GitHub, GhError> {
        GitHub::from_config(cfg)?.ok_or_else(|| {
            GhError::NotConfigured(
                "no GitHub token is configured (github_token_env names an unset variable)".into(),
            )
        })
    }

    fn host_key(&self) -> String {
        self.base.origin().ascii_serialization()
    }

    fn url(&self, repo: &BoundRepo, path: &str) -> Result<Url, GhError> {
        let base = self.base.as_str().trim_end_matches('/');
        let raw = if path.is_empty() {
            format!("{base}/repos/{}", repo.as_str())
        } else {
            format!("{base}/repos/{}/{path}", repo.as_str())
        };
        let url = Url::parse(&raw).map_err(|e| GhError::NotConfigured(format!("bad request URL: {e}")))?;
        if url.host_str() != self.base.host_str()
            || url.port_or_known_default() != self.base.port_or_known_default()
        {
            return Err(GhError::NotConfigured("request URL left the configured host".into()));
        }
        Ok(url)
    }

    /// `GET /repos/{repo}/{path}`, with `If-None-Match` when `etag` is given.
    /// `path` is built by this module from constants and numbers.
    pub(crate) async fn get(&self, repo: &BoundRepo, path: &str, etag: Option<&str>) -> Result<Got, GhError> {
        let key = self.host_key();
        if let Ok(map) = blocks().lock()
            && let Some(&until) = map.get(&key)
            && until > now_s()
        {
            return Err(GhError::RateLimited(Some(until)));
        }
        let url = self.url(repo, path)?;
        let mut req = Request::get(url)
            .secret_header("authorization", &format!("Bearer {}", self.token.expose_secret()))
            .map_err(|_| GhError::NotConfigured("the GitHub token is not a valid header value".into()))?
            .header("accept", "application/vnd.github+json")
            .and_then(|r| r.header("x-github-api-version", API_VERSION))
            .map_err(|e| GhError::Network(e.to_string()))?;
        if let Some(tag) = etag {
            // An unusable stored tag is skipped, as before.
            req = req.clone().header("if-none-match", tag).unwrap_or(req);
        }
        let resp = self.http.send(req).await.map_err(network)?;
        let status = resp.status();
        let header = |name: &str| resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
        let remaining = header("x-ratelimit-remaining").and_then(|v| v.trim().parse::<i64>().ok());
        let reset = header("x-ratelimit-reset").and_then(|v| v.trim().parse::<i64>().ok());
        let retry_after = header("retry-after").and_then(|v| v.trim().parse::<i64>().ok());
        let limited_until = retry_after.map(|s| now_s() + s.clamp(1, MAX_BLOCK_S)).or_else(|| {
            (remaining == Some(0)).then(|| reset.unwrap_or(now_s() + 60).min(now_s() + MAX_BLOCK_S))
        });
        if let Some(until) = limited_until
            && let Ok(mut map) = blocks().lock()
        {
            if map.len() > 64 {
                map.retain(|_, u| *u > now_s());
            }
            map.insert(key, until);
        }
        if status == StatusCode::NOT_MODIFIED {
            return Ok(Got::NotModified);
        }
        if status.is_redirection() {
            return Err(GhError::Redirect(status.as_u16()));
        }
        match status.as_u16() {
            401 => return Err(GhError::Unauthorized),
            403 | 429 if limited_until.is_some() || status.as_u16() == 429 => {
                return Err(GhError::RateLimited(limited_until));
            }
            403 => return Err(GhError::Forbidden),
            404 => return Err(GhError::NotFound),
            s if !(200..300).contains(&s) => return Err(GhError::Status(s)),
            _ => {}
        }
        let etag = header(ETAG.as_str());
        let body = resp.bytes().await.map_err(network)?;
        let body: Value = serde_json::from_slice(&body).map_err(|e| GhError::Decode(e.to_string()))?;
        Ok(Got::Fresh { etag, body })
    }

    /// `GET` without a cache validator: the JSON body.
    pub(crate) async fn get_json(&self, repo: &BoundRepo, path: &str) -> Result<Value, GhError> {
        match self.get(repo, path, None).await? {
            Got::Fresh { body, .. } => Ok(body),
            Got::NotModified => Err(GhError::Status(304)),
        }
    }
}

/// A failed send or body read. A body past the cap is [`GhError::TooLarge`];
/// everything else is a network failure, as before.
fn network(e: OutboundError) -> GhError {
    match e {
        OutboundError::TooLarge { .. } => GhError::TooLarge,
        other => GhError::Network(other.to_string()),
    }
}

/// A full 40-character hex SHA, lowercased.
pub(crate) fn full_sha(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    (s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_api_base_is_https_without_credentials() {
        let mut cfg = Config::default();
        assert_eq!(api_base(&cfg).unwrap().as_str(), "https://api.github.com/");
        cfg.github_api_url = "https://ghe.example.com/api/v3/".into();
        assert_eq!(api_base(&cfg).unwrap().path(), "/api/v3");
        for bad in [
            "http://api.github.com",
            "https://user:pw@api.github.com",
            "https://api.github.com/?x=1",
            "ftp://api.github.com",
            "http://127.0.0.1:9",
        ] {
            cfg.github_api_url = bad.into();
            assert!(api_base(&cfg).is_err(), "{bad} should be refused");
        }
        cfg.fetch_allow_loopback = true;
        cfg.github_api_url = "http://127.0.0.1:9".into();
        assert!(api_base(&cfg).is_ok(), "loopback http only under the test hook");
    }

    #[test]
    fn the_http_client_is_built_once_per_base() {
        let base = Url::parse("https://ghe-client-cache.example.com/api/v3").unwrap();
        let (_, built) = shared_client(&base, false).unwrap();
        assert!(built, "the first request to a base builds its client");
        for _ in 0..3 {
            let (_, built) = shared_client(&base, false).unwrap();
            assert!(!built, "later requests reuse it");
        }
        let mut cfg = Config { github_api_url: base.to_string(), ..Config::default() };
        cfg.github_token_value = Some("t".to_string().into());
        GitHub::from_config(&cfg).unwrap().unwrap();
        let (_, built) = shared_client(&api_base(&cfg).unwrap(), false).unwrap();
        assert!(!built, "from_config shares the cached client");
    }

    #[test]
    fn the_public_api_and_an_enterprise_host_get_their_own_policies() {
        let public = Url::parse("https://api.github.com").unwrap();
        let ghe = Url::parse("https://ghe.example.com/api/v3").unwrap();
        assert_eq!(policy_for(&public, false).name, "github.rest");
        assert_eq!(policy_for(&ghe, false).name, "github.enterprise");
        // Case and a trailing dot do not turn the public API into an
        // enterprise host.
        for spelling in ["https://API.GitHub.com", "https://api.github.com.", "https://Api.Github.Com./"] {
            let cfg = Config { github_api_url: spelling.into(), ..Config::default() };
            let base = api_base(&cfg).unwrap();
            assert_eq!(base.host_str(), Some("api.github.com"), "{spelling}");
            assert_eq!(policy_for(&base, false).name, "github.rest", "{spelling}");
            assert!(policy_for(&base, false).check_url(&base).is_ok(), "{spelling}");
            assert_eq!(policy_for(&Url::parse(spelling).unwrap(), false).name, "github.rest", "{spelling}");
        }
        // An enterprise host keeps the spelling the operator wrote.
        let cfg = Config { github_api_url: "https://ghe.example.com./api/v3".into(), ..Config::default() };
        let base = api_base(&cfg).unwrap();
        assert_eq!(base.host_str(), Some("ghe.example.com."));
        assert_eq!(policy_for(&base, false).name, "github.enterprise");
        let hooked = policy_for(&Url::parse("http://127.0.0.1:9").unwrap(), true);
        assert!(hooked.check_url(&Url::parse("http://127.0.0.1:9/repos/a/b").unwrap()).is_ok());
    }

    #[test]
    fn no_token_means_no_client() {
        assert!(GitHub::from_config(&Config::default()).unwrap().is_none());
    }
}
