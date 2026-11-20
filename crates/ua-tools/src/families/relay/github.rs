//! The relay's one adapter: a comment on a GitHub issue or pull request.
//!
//! The target is `owner/repo#123`, and the repository must be listed in
//! `relay_github_repos`. The token is a managed secret named by
//! `relay_github_secret` and bound to consumer `relay:github`; it is loaded
//! in-process at send time and sent only as the `Authorization` header to
//! `relay_github_api_url`. Requests go through the web family's client: no
//! redirects, no proxy, a 20-second timeout, and non-public addresses refused.

use reqwest::Url;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use ua_core::{Config, UaError, UaResult};

use crate::families::audit::rules::redact_secrets;
use crate::families::web::{error_chain, http_client, vet_url};

/// The managed-secret consumer the relay's GitHub token must be bound to.
pub const CONSUMER: &str = "relay:github";
/// Largest response body read.
const MAX_REPLY_BYTES: usize = 256 * 1024;
const ERROR_CHARS: usize = 300;

/// An issue or pull request in one repository.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub owner: String,
    pub repo: String,
    pub number: u64,
}

impl Target {
    /// `owner/repo`.
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }

    /// `owner/repo#123`.
    pub fn canonical(&self) -> String {
        format!("{}/{}#{}", self.owner, self.repo, self.number)
    }
}

fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !s.chars().all(|c| c == '.')
}

/// Parse `owner/repo#123`.
pub fn parse_target(raw: &str) -> UaResult<Target> {
    let bad =
        || UaError::invalid("github target must look like owner/repo#123 (an issue or pull request number)");
    let (slug, number) = raw.trim().rsplit_once('#').ok_or_else(bad)?;
    let (owner, repo) = slug.split_once('/').ok_or_else(bad)?;
    if !name_ok(owner) || !name_ok(repo) || number.is_empty() || number.len() > 9 {
        return Err(bad());
    }
    let number: u64 = number.parse().map_err(|_| bad())?;
    if number == 0 || !number_digits_only(raw) {
        return Err(bad());
    }
    Ok(Target { owner: owner.into(), repo: repo.into(), number })
}

fn number_digits_only(raw: &str) -> bool {
    raw.trim().rsplit_once('#').is_some_and(|(_, n)| n.chars().all(|c| c.is_ascii_digit()))
}

/// Whether the repository is in `relay_github_repos` (case-insensitive).
pub fn repo_allowed(cfg: &Config, t: &Target) -> bool {
    let slug = t.slug();
    cfg.relay_github_repos.iter().any(|r| r.trim().eq_ignore_ascii_case(&slug))
}

pub fn require_allowed(cfg: &Config, t: &Target) -> UaResult<()> {
    if repo_allowed(cfg, t) {
        Ok(())
    } else {
        Err(UaError::denied(
            "relay_target_not_allowed",
            format!("repository {} is not in relay_github_repos; the relay will not post there", t.slug()),
        ))
    }
}

/// The managed secret's name, or why the adapter cannot send.
pub fn secret_name(cfg: &Config) -> UaResult<&str> {
    cfg.relay_github_secret.as_deref().map(str::trim).filter(|s| !s.is_empty()).ok_or_else(|| {
        UaError::denied(
            "relay_unavailable",
            format!(
                "relay_github_secret is not set: store a GitHub token with managed_secret_set (consumer {CONSUMER:?}) and name it there"
            ),
        )
    })
}

/// The API base URL: https, or plain http only under the loopback test hook.
pub fn api_base(cfg: &Config) -> UaResult<Url> {
    let raw = cfg.relay_github_api_url.trim().trim_end_matches('/');
    let url =
        Url::parse(raw).map_err(|_| UaError::invalid("relay_github_api_url does not parse as a URL"))?;
    let ok = url.scheme() == "https" || (url.scheme() == "http" && cfg.fetch_allow_loopback);
    if !ok || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(UaError::invalid("relay_github_api_url must be an https URL without credentials"));
    }
    Ok(url)
}

/// How one delivery attempt ended.
#[derive(Debug)]
pub enum Outcome {
    /// GitHub created the comment.
    Sent(Value),
    /// Nothing can have reached GitHub (refused locally, connection refused,
    /// or a definite 4xx rejection).
    Failed { http_status: Option<u16>, error: String },
    /// The request may have been accepted (timeout, dropped connection,
    /// 5xx, 408, 429). Not retried.
    Uncertain { http_status: Option<u16>, error: String },
}

fn clean(s: &str) -> String {
    redact_secrets(s).0.chars().take(ERROR_CHARS).collect()
}

async fn read_capped(mut resp: reqwest::Response) -> Vec<u8> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_REPLY_BYTES {
            break;
        }
    }
    body
}

/// Post `body` as a comment on `t`.
pub async fn post_comment(cfg: &Config, token: &SecretString, t: &Target, body: &str) -> Outcome {
    let failed = |error: String| Outcome::Failed { http_status: None, error };
    let base = match api_base(cfg) {
        Ok(u) => u,
        Err(e) => return failed(e.to_string()),
    };
    let url = match Url::parse(&format!(
        "{}/repos/{}/{}/issues/{}/comments",
        base.as_str().trim_end_matches('/'),
        t.owner,
        t.repo,
        t.number
    )) {
        Ok(u) => u,
        Err(_) => return failed("could not build the GitHub API URL".into()),
    };
    if let Err(e) = vet_url(&url, cfg.fetch_allow_loopback).await {
        return failed(e.to_string());
    }
    let client = match http_client(cfg) {
        Ok(c) => c,
        Err(e) => return failed(e.to_string()),
    };
    let mut auth = match HeaderValue::from_str(&format!("Bearer {}", token.expose_secret().trim())) {
        Ok(v) => v,
        Err(_) => return failed("the relay's GitHub token is not a valid header value".into()),
    };
    auth.set_sensitive(true);
    let sent = client
        .post(url)
        .header(AUTHORIZATION, auth)
        .header(ACCEPT, HeaderValue::from_static("application/vnd.github+json"))
        .header("X-GitHub-Api-Version", HeaderValue::from_static("2022-11-28"))
        .json(&json!({ "body": body }))
        .send()
        .await;
    let resp = match sent {
        Ok(r) => r,
        Err(e) => {
            let error = clean(&error_chain(&e));
            return if e.is_connect() || e.is_builder() {
                Outcome::Failed { http_status: None, error }
            } else {
                Outcome::Uncertain { http_status: None, error }
            };
        }
    };
    let status = resp.status().as_u16();
    let reply: Value = serde_json::from_slice(&read_capped(resp).await).unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        return Outcome::Sent(json!({
            "http_status": status,
            "comment_id": reply.get("id").cloned().unwrap_or(Value::Null),
            "html_url": reply.get("html_url").cloned().unwrap_or(Value::Null),
        }));
    }
    let message = reply.get("message").and_then(Value::as_str).unwrap_or("no message");
    let error = clean(&format!("GitHub answered HTTP {status}: {message}"));
    if (400..500).contains(&status) && status != 408 && status != 429 {
        Outcome::Failed { http_status: Some(status), error }
    } else {
        Outcome::Uncertain { http_status: Some(status), error }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        let t = parse_target("acme/widgets#42").unwrap();
        assert_eq!((t.owner.as_str(), t.repo.as_str(), t.number), ("acme", "widgets", 42));
        assert_eq!(t.canonical(), "acme/widgets#42");
        for bad in [
            "acme/widgets",
            "acme#1",
            "acme/../x#1",
            "a/..#1",
            "a/b#0",
            "a/b#-1",
            "a/b#1x",
            "a b/c#1",
            "a/b#+1",
        ] {
            assert!(parse_target(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn api_base_wants_https() {
        let mut cfg = Config::for_home(std::env::temp_dir());
        assert!(api_base(&cfg).is_ok());
        cfg.relay_github_api_url = "http://api.example.com".into();
        assert!(api_base(&cfg).is_err());
        cfg.relay_github_api_url = "https://user:pw@api.example.com".into();
        assert!(api_base(&cfg).is_err());
    }
}
