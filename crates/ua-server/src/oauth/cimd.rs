//! Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).
//!
//! A URL-shaped `client_id` is the client's registration: the hub fetches the
//! JSON document at that URL on first use. Because an unauthenticated
//! `/oauth/authorize` call can trigger the fetch, it is fenced:
//!
//! - the URL must be canonical `https` with a DNS host, a path, and no port,
//!   credentials, query, fragment or dot segments; an optional host allowlist
//!   (`oauth_cimd_allow`) narrows it further;
//! - every address the host resolves to must be globally routable (no
//!   loopback, private, link-local, CGNAT, documentation, multicast, IPv4
//!   mapped or translated ranges), and the connection is pinned to the vetted
//!   address, so DNS rebinding cannot swap it afterwards;
//! - no redirects, no proxy, a 5 s timeout and a 5 KiB body cap;
//! - at most four fetches run at once;
//! - results are cached for an hour, failures for a minute.
//!
//! The document must name the same `client_id`, list `redirect_uris`, and
//! describe a public client (`token_endpoint_auth_method` `none`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

pub const MAX_DOCUMENT_BYTES: usize = 5 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_TTL: Duration = Duration::from_secs(3600);
const NEGATIVE_TTL: Duration = Duration::from_secs(60);
const MAX_CACHE: usize = 512;
const MAX_INFLIGHT: usize = 4;

/// A rejected client id URL or document. The message is safe to show and log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimdError(pub String);

impl std::fmt::Display for CimdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, CimdError> {
    Err(CimdError(msg.into()))
}

/// A client described by a metadata document. Always a public client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimdClient {
    pub client_id: String,
    /// Display name, always carrying the document's host.
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
}

/// True for a URL-shaped client id (valid or not).
pub fn looks_like_cimd(client_id: &str) -> bool {
    client_id.starts_with("https://")
}

fn host_allowed(host: &str, allow: &[String]) -> bool {
    allow.is_empty()
        || allow.iter().any(|e| {
            let e = e.trim().to_ascii_lowercase();
            match e.strip_prefix('.') {
                Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
                None => host == e,
            }
        })
}

/// Validate a client id URL. Returns its host.
pub fn validate_client_id_url(client_id: &str, allow: &[String]) -> Result<String, CimdError> {
    if client_id.len() > 2048 {
        return err("client_id URL is too long");
    }
    if !client_id.is_ascii() || client_id.chars().any(|c| c.is_ascii_whitespace() || c.is_ascii_control()) {
        return err("client_id URL must be printable ASCII without whitespace");
    }
    if client_id.contains('\\') || client_id.contains('%') {
        return err("client_id URL may not contain backslashes or percent-encoding");
    }
    let url =
        url::Url::parse(client_id).map_err(|e| CimdError(format!("client_id URL is malformed: {e}")))?;
    if url.scheme() != "https" {
        return err("client_id URL must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return err("client_id URL may not carry credentials");
    }
    if url.port().is_some() {
        return err("client_id URL may not carry a port");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return err("client_id URL may not carry a query or fragment");
    }
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        Some(_) => return err("client_id URL host must be a DNS name, not an IP address"),
        None => return err("client_id URL has no host"),
    };
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    };
    if labels.len() < 2 || !labels.iter().all(|l| label_ok(l)) {
        return err("client_id URL host is not a valid DNS name");
    }
    let path = url.path();
    if path.is_empty() || path == "/" {
        return err("client_id URL must have a path");
    }
    // The parser silently resolves dot segments; compare against the input
    // so what is validated is exactly what was presented.
    if url.as_str() != client_id {
        return err("client_id URL is not in canonical form");
    }
    if path.split('/').any(|s| s == "." || s == "..") {
        return err("client_id URL may not contain dot segments");
    }
    if !host_allowed(&host, allow) {
        return err(format!("client_id host {host} is not in oauth_cimd_allow"));
    }
    Ok(host)
}

/// True only for globally routable unicast addresses.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || o[0] == 0                                   // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64)        // 100.64.0.0/10 shared (CGNAT)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0.0/24 protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18)        // 198.18.0.0/15 benchmarking
        || o[0] >= 240) // 240.0.0.0/4 reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00                   // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80                   // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0                   // fec0::/10 site-local
        || (s[0] == 0x2001 && s[1] == 0x0db8)          // documentation
        || (s[0] == 0x2001 && s[1] == 0)               // Teredo
        || s[0] == 0x2002                              // 6to4
        || (s[0] == 0x64 && s[1] == 0xff9b)            // NAT64
        || (s[0] == 0x100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // discard
        || s[..6] == [0, 0, 0, 0, 0, 0]) // IPv4-compatible and other ::/96
}

/// Vet resolved addresses: every one must be public. Returns the address to
/// pin the connection to.
pub fn vet_addresses(addrs: &[SocketAddr]) -> Result<SocketAddr, CimdError> {
    let Some(first) = addrs.first() else { return err("client_id host does not resolve") };
    if let Some(bad) = addrs.iter().find(|a| !is_public_ip(a.ip())) {
        return err(format!("client_id host resolves to a non-public address ({})", bad.ip()));
    }
    Ok(*first)
}

/// Validate a fetched document against its URL.
pub fn parse_document(client_id: &str, host: &str, body: &[u8]) -> Result<CimdClient, CimdError> {
    if body.len() > MAX_DOCUMENT_BYTES {
        return err("client metadata document is too large");
    }
    let doc: Value =
        serde_json::from_slice(body).map_err(|_| CimdError("client metadata document is not JSON".into()))?;
    let Some(obj) = doc.as_object() else { return err("client metadata document must be a JSON object") };
    if obj.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return err("client metadata document client_id does not match its URL");
    }
    if obj.contains_key("client_secret") || obj.contains_key("client_secret_expires_at") {
        return err("client metadata document may not carry a client secret");
    }
    let method = obj.get("token_endpoint_auth_method").and_then(Value::as_str).unwrap_or("none");
    if method != "none" {
        return err("client metadata document must describe a public client (auth method none)");
    }
    let redirect_uris: Vec<String> = match obj.get("redirect_uris").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => {
            a.iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect::<Option<_>>()
                .ok_or_else(|| CimdError("client metadata document redirect_uris must be strings".into()))?
        }
        _ => return err("client metadata document must list redirect_uris"),
    };
    for uri in &redirect_uris {
        super::register::check_redirect_uri(uri).map_err(CimdError)?;
    }
    let grant_types: Vec<String> = match obj.get("grant_types") {
        None => vec!["authorization_code".into(), "refresh_token".into()],
        Some(v) => v
            .as_array()
            .and_then(|a| a.iter().map(|g| g.as_str().map(str::to_string)).collect::<Option<Vec<_>>>())
            .ok_or_else(|| CimdError("client metadata document grant_types must be strings".into()))?,
    };
    if grant_types.iter().any(|g| g != "authorization_code" && g != "refresh_token") {
        return err("client metadata document requests an unsupported grant type");
    }
    let name: String = obj
        .get("client_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    let name = name.trim();
    Ok(CimdClient {
        client_id: client_id.to_string(),
        client_name: if name.is_empty() { host.to_string() } else { format!("{name} ({host})") },
        redirect_uris,
        grant_types,
    })
}

struct Entry {
    result: Result<CimdClient, CimdError>,
    expires: Instant,
}

static CACHE: LazyLock<Mutex<HashMap<String, Entry>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static INFLIGHT: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(MAX_INFLIGHT));

fn cached(client_id: &str) -> Option<Result<CimdClient, CimdError>> {
    let cache = CACHE.lock().ok()?;
    let e = cache.get(client_id)?;
    (e.expires > Instant::now()).then(|| e.result.clone())
}

fn store(client_id: &str, result: Result<CimdClient, CimdError>) {
    let ttl = if result.is_ok() { CACHE_TTL } else { NEGATIVE_TTL };
    if let Ok(mut cache) = CACHE.lock() {
        let now = Instant::now();
        cache.retain(|_, e| e.expires > now);
        if cache.len() >= MAX_CACHE
            && let Some(oldest) = cache.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| k.clone())
        {
            cache.remove(&oldest);
        }
        cache.insert(client_id.to_string(), Entry { result, expires: now + ttl });
    }
}

/// Resolve a URL client id, from cache or by fetching its document. The URL
/// (and the allowlist) is re-validated on every call.
pub async fn resolve(client_id: &str, allow: &[String]) -> Result<CimdClient, CimdError> {
    let host = validate_client_id_url(client_id, allow)?;
    if let Some(hit) = cached(client_id) {
        return hit;
    }
    let Ok(_permit) = INFLIGHT.try_acquire() else {
        // Not negatively cached: the client did nothing wrong.
        return err("too many client metadata fetches in flight; retry shortly");
    };
    let result = match fetch(client_id, &host).await {
        Ok(body) => parse_document(client_id, &host, &body),
        Err(e) => Err(e),
    };
    store(client_id, result.clone());
    result
}

async fn fetch(client_id: &str, host: &str) -> Result<Vec<u8>, CimdError> {
    let lookup = tokio::time::timeout(FETCH_TIMEOUT, tokio::net::lookup_host((host, 443)))
        .await
        .map_err(|_| CimdError("client_id host lookup timed out".into()))?
        .map_err(|_| CimdError("client_id host does not resolve".into()))?;
    let addrs: Vec<SocketAddr> = lookup.collect();
    let pinned = vet_addresses(&addrs)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(FETCH_TIMEOUT)
        .resolve(host, pinned)
        .build()
        .map_err(|_| CimdError("client metadata fetch could not start".into()))?;
    let mut resp = client
        .get(client_id)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| CimdError("client metadata document fetch failed".into()))?;
    if resp.status().is_redirection() {
        return err("client metadata document redirected; redirects are refused");
    }
    if resp.status() != reqwest::StatusCode::OK {
        return err(format!("client metadata document returned HTTP {}", resp.status().as_u16()));
    }
    if resp.content_length().is_some_and(|n| n as usize > MAX_DOCUMENT_BYTES) {
        return err("client metadata document is too large");
    }
    let mut body = Vec::new();
    while let Some(chunk) =
        resp.chunk().await.map_err(|_| CimdError("client metadata document fetch failed".into()))?
    {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_DOCUMENT_BYTES {
            return err("client metadata document is too large");
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "https://app.example.com/oauth/client.json";

    #[test]
    fn url_rules() {
        assert_eq!(validate_client_id_url(ID, &[]).unwrap(), "app.example.com");
        for bad in [
            "http://app.example.com/c.json",
            "https://app.example.com",
            "https://app.example.com/",
            "https://user:pw@app.example.com/c.json",
            "https://app.example.com:8443/c.json",
            "https://app.example.com/c.json?x=1",
            "https://app.example.com/c.json#f",
            "https://127.0.0.1/c.json",
            "https://[::1]/c.json",
            "https://localhost/c.json",
            "https://APP.example.com/c.json",
            "https://app.example.com/a/../c.json",
            "https://app.example.com/a/%2e%2e/c.json",
            "https://app.example.com/c json",
        ] {
            assert!(validate_client_id_url(bad, &[]).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn allowlist() {
        let allow = vec![".example.com".to_string()];
        assert!(validate_client_id_url(ID, &allow).is_ok());
        assert!(validate_client_id_url("https://evil.test/c.json", &allow).is_err());
        assert!(validate_client_id_url("https://notexample.com/c.json", &allow).is_err());
    }

    #[test]
    fn private_addresses_are_refused() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.100",
            "0.0.0.0",
            "198.18.0.1",
            "192.0.2.1",
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "2002:7f00:1::",
            "2001:db8::1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!is_public_ip(ip), "{ip} must not be public");
        }
        for ip in ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_public_ip(ip), "{ip} is public");
        }
    }

    #[test]
    fn one_private_address_poisons_the_set() {
        let public: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let private: SocketAddr = "10.0.0.5:443".parse().unwrap();
        assert_eq!(vet_addresses(&[public]).unwrap(), public);
        assert!(vet_addresses(&[public, private]).is_err());
        assert!(vet_addresses(&[]).is_err());
    }

    #[test]
    fn document_rules() {
        let ok = format!(
            r#"{{"client_id":"{ID}","client_name":"Editor","redirect_uris":["http://127.0.0.1:3000/cb"]}}"#
        );
        let c = parse_document(ID, "app.example.com", ok.as_bytes()).unwrap();
        assert_eq!(c.client_name, "Editor (app.example.com)");
        let wrong_id = r#"{"client_id":"https://other.example.com/c.json","redirect_uris":["https://a.example.com/cb"]}"#;
        assert!(parse_document(ID, "app.example.com", wrong_id.as_bytes()).is_err());
        let secret = format!(
            r#"{{"client_id":"{ID}","client_secret":"x","redirect_uris":["https://a.example.com/cb"]}}"#
        );
        assert!(parse_document(ID, "app.example.com", secret.as_bytes()).is_err());
        let confidential = format!(
            r#"{{"client_id":"{ID}","token_endpoint_auth_method":"client_secret_basic","redirect_uris":["https://a.example.com/cb"]}}"#
        );
        assert!(parse_document(ID, "app.example.com", confidential.as_bytes()).is_err());
        let no_redirects = format!(r#"{{"client_id":"{ID}"}}"#);
        assert!(parse_document(ID, "app.example.com", no_redirects.as_bytes()).is_err());
        let big = vec![b' '; MAX_DOCUMENT_BYTES + 1];
        assert!(parse_document(ID, "app.example.com", &big).is_err());
    }
}
