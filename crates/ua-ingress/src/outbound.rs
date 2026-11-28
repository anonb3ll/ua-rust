//! [`Outbound`]: the one guarded HTTP client.
//!
//! Every client is built from a [`Policy`] and enforces, whatever the caller
//! does:
//!
//! - **No proxy** from the environment (`HTTP_PROXY`, `HTTPS_PROXY`,
//!   `ALL_PROXY` and the system settings are ignored).
//! - **No redirects** unless the policy allows them. Allowed redirects are
//!   followed by hand, and each hop is checked against the policy again.
//!   Headers and the body belong to the origin of the request URL: once a
//!   chain leaves it, every later hop (a return included) carries only
//!   `accept` and `accept-language`, a 307 or
//!   308 that would resend the body to another origin is refused, and so is
//!   a hop from https to http unless the policy allows it (only `web.page`).
//! - **A body cap** on every read path of a [`Response`].
//! - **A connect-time address check.** The client's DNS resolver classifies
//!   every address a name resolves to and fails the lookup when any one is
//!   outside [`Policy::addresses`]; the connector dials only addresses that
//!   resolver returned. An IP-literal host never reaches a resolver, so
//!   [`Policy::check_url`] checks it before each hop. After the response
//!   head arrives, the peer address of the connection that carried it is
//!   checked once more. See `docs/ingress.md` for what this does and does
//!   not guarantee.
//! - **Secret headers stay with their origin, and never leave loopback over
//!   plain `http`.** A header added with [`Request::secret_header`] is bound
//!   to the origin (scheme, host, port) of the request URL and is attached
//!   only to a hop with that origin. So is every plain header outside the
//!   short cross-origin list above. On any plain `http` hop that would carry
//!   a secret header (or URL credentials), every resolved address at connect
//!   time — and the connection's peer address after the response head — must
//!   be loopback ([`crate::addr::is_loopback`]); any non-loopback address is
//!   refused with [`OutboundError::CleartextSecret`], on every hop including
//!   redirects. [`Request::header`] also refuses names that look like
//!   credentials, an extra check that cross-origin safety does not rely on.
//! - **Timeouts**: connect, per request (body included) and for the whole
//!   call (redirects and body included).

use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use reqwest::header::{
    ACCEPT, ACCEPT_LANGUAGE, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, LOCATION,
};
use reqwest::{Method, StatusCode};
use tokio::time::Instant;
use url::Url;

use crate::policy::{self, Addresses, Policy, Schemes};

const USER_AGENT: &str = concat!("ua-rust/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an outbound call did not produce a response. Messages never carry the
/// request URL's path or query, nor any header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundError {
    /// No policy has this name.
    UnknownPolicy(String),
    /// The policy is empty or unbounded.
    InvalidPolicy {
        policy: &'static str,
        why: &'static str,
    },
    /// The URL (or a redirect target) is outside the policy.
    UrlRefused {
        policy: &'static str,
        why: &'static str,
    },
    /// An address the request would reach is outside the policy's address
    /// class (an IP-literal host, or a name that resolves there). Nothing
    /// was sent.
    AddressRefused {
        host: String,
        ip: IpAddr,
        reason: &'static str,
    },
    /// The name could not be resolved (`why`: the resolver's error, or
    /// `timed out`, or `no address`). Nothing was sent.
    Lookup {
        host: String,
        why: String,
    },
    /// No connection was made, or the request could not be built, so
    /// nothing was sent. `timed_out` when the connect timed out.
    NotSent {
        why: String,
        timed_out: bool,
    },
    /// The connection that carried the response reached a peer outside the
    /// policy's address class. The request was sent.
    PeerRefused {
        host: String,
        ip: IpAddr,
        reason: &'static str,
    },
    /// The connection's peer address could not be read, so it could not be
    /// checked. The request was sent.
    Unverified,
    /// A header was refused (a credential-like name passed as a plain header,
    /// or a value that is not a valid header).
    HeaderRefused(String),
    /// A credential header or URL credential would travel over plain `http` to
    /// a non-loopback address.
    CleartextSecret {
        host: String,
        ip: IpAddr,
    },
    /// A redirect without a usable target, or too many of them.
    Redirect(String),
    Timeout,
    /// The response body is larger than the policy's cap.
    TooLarge {
        limit: usize,
    },
    /// The request body could not be encoded or the response not decoded.
    Body(String),
    /// Connection, TLS or protocol failure.
    Transport(String),
}

impl std::fmt::Display for OutboundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPolicy(name) => write!(f, "no outbound policy is named {name:?}"),
            Self::InvalidPolicy { policy, why } => write!(f, "outbound policy {policy} is invalid: {why}"),
            Self::UrlRefused { policy, why } => write!(f, "outbound policy {policy} refuses the URL: {why}"),
            Self::AddressRefused { host, ip, reason } => {
                write!(f, "{host:?} resolves to {ip}, a non-public address ({reason})")
            }
            Self::Lookup { host, why } => write!(f, "could not resolve host {host:?}: {why}"),
            Self::NotSent { why, .. } => write!(f, "outbound request not sent: {why}"),
            Self::PeerRefused { host, ip, reason } => {
                write!(f, "the connection to {host:?} reached {ip}, a non-public address ({reason})")
            }
            Self::Unverified => f.write_str("the connection's peer address could not be checked"),
            Self::HeaderRefused(why) => write!(f, "header refused: {why}"),
            Self::CleartextSecret { host, ip } => write!(
                f,
                "refusing to send credentials over plain http to {host:?} ({ip}, not loopback); use https"
            ),
            Self::Redirect(why) => write!(f, "redirect refused: {why}"),
            Self::Timeout => f.write_str("the outbound request timed out"),
            Self::TooLarge { limit } => write!(f, "the response body is larger than {limit} bytes"),
            Self::Body(why) => write!(f, "body error: {why}"),
            Self::Transport(why) => write!(f, "outbound request failed: {why}"),
        }
    }
}

impl StdError for OutboundError {}

impl From<OutboundError> for ua_core::UaError {
    fn from(e: OutboundError) -> Self {
        let msg = e.to_string();
        match e {
            OutboundError::AddressRefused { .. } | OutboundError::PeerRefused { .. } => {
                ua_core::UaError::denied("ssrf_blocked", msg)
            }
            OutboundError::UrlRefused { .. } | OutboundError::CleartextSecret { .. } => {
                ua_core::UaError::denied("outbound_refused", msg)
            }
            OutboundError::UnknownPolicy(_) | OutboundError::InvalidPolicy { .. } => {
                ua_core::UaError::internal(msg)
            }
            _ => ua_core::UaError::invalid(msg),
        }
    }
}

/// The error the resolver fails a lookup with; found again in the error
/// chain of the failed request.
#[derive(Debug)]
struct RefusedAtConnect {
    host: String,
    ip: IpAddr,
    reason: &'static str,
}

impl std::fmt::Display for RefusedAtConnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "address_refused: {:?} resolves to {} ({})", self.host, self.ip, self.reason)
    }
}

impl StdError for RefusedAtConnect {}

/// The resolver refused a non-loopback address for a plain `http` hop carrying
/// credentials; found again in the error chain of the failed request.
#[derive(Debug)]
struct CleartextSecretAtConnect {
    host: String,
    ip: IpAddr,
}

impl std::fmt::Display for CleartextSecretAtConnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cleartext_secret: {:?} resolves to {} (not loopback)", self.host, self.ip)
    }
}

impl StdError for CleartextSecretAtConnect {}

/// A lookup that failed for another reason than the address check.
#[derive(Debug)]
struct LookupFailed {
    host: String,
    why: String,
}

impl std::fmt::Display for LookupFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "could not resolve {:?}: {}", self.host, self.why)
    }
}

impl StdError for LookupFailed {}

fn error_chain(e: &dyn StdError) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(inner) = cur {
        let t = inner.to_string();
        if !s.contains(&t) {
            s.push_str(": ");
            s.push_str(&t);
        }
        cur = inner.source();
    }
    s
}

fn send_error(e: reqwest::Error) -> OutboundError {
    let e = e.without_url();
    let mut cur: Option<&(dyn StdError + 'static)> = Some(&e);
    while let Some(inner) = cur {
        if let Some(r) = inner.downcast_ref::<RefusedAtConnect>() {
            return OutboundError::AddressRefused { host: r.host.clone(), ip: r.ip, reason: r.reason };
        }
        if let Some(c) = inner.downcast_ref::<CleartextSecretAtConnect>() {
            return OutboundError::CleartextSecret { host: c.host.clone(), ip: c.ip };
        }
        if let Some(l) = inner.downcast_ref::<LookupFailed>() {
            return OutboundError::Lookup { host: l.host.clone(), why: l.why.clone() };
        }
        cur = inner.source();
    }
    if e.is_connect() || e.is_builder() {
        return OutboundError::NotSent { why: error_chain(&e), timed_out: e.is_timeout() };
    }
    if e.is_timeout() {
        return OutboundError::Timeout;
    }
    OutboundError::Transport(error_chain(&e))
}

// ---------------------------------------------------------------------------
// The resolver: the connect-time address check
// ---------------------------------------------------------------------------

/// Result of resolving an outbound URL's host once and classifying whether
/// any resolved address is non-loopback (`is_remote`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    pub host: String,
    pub addrs: Vec<SocketAddr>,
    /// True if any resolved address is outside loopback (`!ua_ingress::addr::is_loopback`).
    pub is_remote: bool,
}

/// Resolve `url`'s host once using system DNS (or parse an IP literal without
/// DNS) and classify whether any resolved address is non-loopback.
pub async fn resolve_endpoint(
    url: &Url,
    timeout: std::time::Duration,
) -> Result<ResolvedEndpoint, OutboundError> {
    resolve_endpoint_with_lookup(url, timeout, system_lookup()).await
}

/// Resolve `url`'s host once through `lookup` (for deterministic DNS-rebinding tests).
pub async fn resolve_endpoint_with_lookup(
    url: &Url,
    timeout: std::time::Duration,
    lookup: Lookup,
) -> Result<ResolvedEndpoint, OutboundError> {
    let port = url
        .port_or_known_default()
        .ok_or(OutboundError::UrlRefused { policy: "resolve", why: "URL has no known port" })?;
    let host_str =
        url.host_str().ok_or(OutboundError::UrlRefused { policy: "resolve", why: "URL has no host" })?;
    let addrs: Vec<SocketAddr> = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
        Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
        Some(url::Host::Domain(domain)) => {
            let pending = (lookup)(domain);
            let raw = match tokio::time::timeout(timeout, pending).await {
                Ok(Ok(addrs)) => addrs,
                Ok(Err(e)) => {
                    return Err(OutboundError::Lookup { host: domain.to_string(), why: e.to_string() });
                }
                Err(_) => {
                    return Err(OutboundError::Lookup { host: domain.to_string(), why: "timed out".into() });
                }
            };
            if raw.is_empty() {
                return Err(OutboundError::Lookup { host: domain.to_string(), why: "no address".into() });
            }
            raw.into_iter().map(|a| SocketAddr::new(a.ip(), port)).collect()
        }
        None => {
            return Err(OutboundError::UrlRefused { policy: "resolve", why: "URL has no host" });
        }
    };
    let is_remote = addrs.iter().any(|a| !crate::addr::is_loopback(a.ip()));
    Ok(ResolvedEndpoint { host: host_str.to_string(), addrs, is_remote })
}

/// A custom async lookup closure type for [`resolve_endpoint_with_lookup`].
pub type Lookup = Arc<dyn Fn(&str) -> LookupFuture + Send + Sync>;

type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>;

fn system_lookup() -> Lookup {
    Arc::new(|host: &str| {
        let host = host.to_string();
        Box::pin(async move { Ok(tokio::net::lookup_host((host.as_str(), 0)).await?.collect()) })
    })
}

/// Resolves a name and hands the connector only addresses inside the
/// policy's class. One address outside it fails the whole lookup, so a
/// mixed answer cannot be raced into a connection to the bad one.
struct GuardedResolver {
    addresses: Addresses,
    /// When true, every resolved address must also be loopback
    /// (`addr::is_loopback`); used for plain `http` hops carrying credentials.
    require_loopback: bool,
    timeout: std::time::Duration,
    lookup: Lookup,
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let (rule, require_loopback, timeout) = (self.addresses, self.require_loopback, self.timeout);
        let pending = (self.lookup)(&host);
        Box::pin(async move {
            let failed = |host: &str, why: String| {
                Err(Box::new(LookupFailed { host: host.to_string(), why }) as Box<dyn StdError + Send + Sync>)
            };
            let addrs = match tokio::time::timeout(timeout, pending).await {
                Ok(Ok(addrs)) => addrs,
                Ok(Err(e)) => return failed(&host, e.to_string()),
                Err(_) => return failed(&host, "timed out".into()),
            };
            if addrs.is_empty() {
                return failed(&host, "no address".into());
            }
            for a in &addrs {
                if let Err(reason) = rule.check(a.ip()) {
                    return Err(Box::new(RefusedAtConnect { host, ip: a.ip(), reason }) as _);
                }
                if require_loopback && !crate::addr::is_loopback(a.ip()) {
                    return Err(Box::new(CleartextSecretAtConnect { host, ip: a.ip() }) as _);
                }
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Install ring as the process-wide rustls provider once (reqwest is built
/// without one so no C toolchain is needed).
fn install_crypto_provider() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// A header bound to one origin.
#[derive(Clone)]
struct SecretHeader {
    origin: url::Origin,
    name: HeaderName,
    value: HeaderValue,
}

/// One outbound request.
#[derive(Clone)]
pub struct Request {
    method: Method,
    url: Url,
    headers: HeaderMap,
    secrets: Vec<SecretHeader>,
    body: Option<Vec<u8>>,
}

/// Header names that carry credentials; they go through
/// [`Request::secret_header`] only.
fn looks_secret(name: &HeaderName) -> bool {
    let n = name.as_str();
    matches!(n, "authorization" | "proxy-authorization" | "cookie")
        || ["token", "secret", "api-key", "apikey", "password"].iter().any(|w| n.contains(w))
}

fn header_parts(name: &str, value: &str) -> Result<(HeaderName, HeaderValue), OutboundError> {
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| OutboundError::HeaderRefused("invalid header name".into()))?;
    let value = HeaderValue::from_str(value)
        .map_err(|_| OutboundError::HeaderRefused(format!("invalid value for {name}")))?;
    Ok((name, value))
}

impl Request {
    pub fn new(method: Method, url: Url) -> Self {
        Self { method, url, headers: HeaderMap::new(), secrets: Vec::new(), body: None }
    }

    /// The URL the request was built for.
    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn get(url: Url) -> Self {
        Self::new(Method::GET, url)
    }

    pub fn post(url: Url) -> Self {
        Self::new(Method::POST, url)
    }

    /// A plain header. A credential-like name is refused: use
    /// [`Request::secret_header`].
    pub fn header(mut self, name: &str, value: &str) -> Result<Self, OutboundError> {
        let (name, value) = header_parts(name, value)?;
        if looks_secret(&name) {
            return Err(OutboundError::HeaderRefused(format!(
                "{name} carries a credential; use secret_header"
            )));
        }
        self.headers.append(name, value);
        Ok(self)
    }

    /// A credential header, bound to the origin of this request's URL. It is
    /// sent only to that origin: never to a redirect target elsewhere.
    pub fn secret_header(mut self, name: &str, value: &str) -> Result<Self, OutboundError> {
        let (name, mut value) = header_parts(name, value)?;
        value.set_sensitive(true);
        self.secrets.push(SecretHeader { origin: self.url.origin(), name, value });
        Ok(self)
    }

    /// A JSON body (and `Content-Type: application/json`).
    pub fn json<T: serde::Serialize + ?Sized>(mut self, body: &T) -> Result<Self, OutboundError> {
        let bytes = serde_json::to_vec(body).map_err(|e| OutboundError::Body(e.to_string()))?;
        self.headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        self.body = Some(bytes);
        Ok(self)
    }

    /// A raw body with its content type.
    pub fn body(mut self, content_type: &str, bytes: Vec<u8>) -> Result<Self, OutboundError> {
        let ct = HeaderValue::from_str(content_type)
            .map_err(|_| OutboundError::HeaderRefused("invalid content type".into()))?;
        self.headers.insert(CONTENT_TYPE, ct);
        self.body = Some(bytes);
        Ok(self)
    }
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// Headers that may follow a redirect to another origin. Every other header,
/// however it was named or set, is sent only to the origin of the request
/// URL it was built for. `content-type` would be listed only together with a
/// body, and a body never crosses origins.
const CROSS_ORIGIN_HEADERS: &[HeaderName] = &[ACCEPT, ACCEPT_LANGUAGE];

/// How the client reads the peer address of a response's connection.
type PeerOf = fn(&reqwest::Response) -> Option<SocketAddr>;

/// A guarded HTTP client for one [`Policy`].
pub struct Outbound {
    policy: Policy,
    client: reqwest::Client,
    /// Separate client used only for plain `http` hops that carry credentials:
    /// its resolver requires every resolved address to be loopback and its
    /// connection pool is never shared with unauthenticated `http` hops.
    loopback_secret_client: Option<reqwest::Client>,
    /// `reqwest::Response::remote_addr`, except in tests.
    peer_of: PeerOf,
    /// The one origin a pinned client may send to ([`Outbound::pinned`]).
    pin: Option<url::Origin>,
}

fn build_reqwest_client(
    policy: &Policy,
    resolver: GuardedResolver,
) -> Result<reqwest::Client, OutboundError> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(policy.schemes == Schemes::HttpsOnly)
        // `validate` allows this only for a loopback-only policy.
        .danger_accept_invalid_certs(policy.accept_invalid_certs)
        .connect_timeout(policy.connect_timeout)
        .timeout(policy.request_timeout)
        .dns_resolver(resolver)
        .build()
        .map_err(|e| OutboundError::Transport(format!("cannot build the HTTP client: {}", error_chain(&e))))
}

fn url_ip(url: &Url) -> Option<IpAddr> {
    match url.host()? {
        url::Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
        url::Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
        url::Host::Domain(_) => None,
    }
}

impl Outbound {
    /// A client for `policy`. An invalid policy, or a relaxed one
    /// ([`Policy::is_relaxed`]: use [`Outbound::pinned`]), is refused.
    pub fn new(policy: Policy) -> Result<Self, OutboundError> {
        policy.validate_unpinned()?;
        Self::build(policy, system_lookup(), policy.addresses, reqwest::Response::remote_addr)
    }

    /// A client for `policy` that sends only to the origin (scheme, host,
    /// port) of `origin`, the destination the operator configured. Every
    /// request to another origin is refused before anything is sent. A
    /// relaxed policy builds a client only this way, and only when it is one
    /// of the relaxed policies this crate defines (or one of them under the
    /// loopback test hook). Requests to the origin are checked against the
    /// policy like any other, so an origin outside it fails on first use.
    pub fn pinned(policy: Policy, origin: &Url) -> Result<Self, OutboundError> {
        policy.validate_pinned()?;
        let mut out = Self::build(policy, system_lookup(), policy.addresses, reqwest::Response::remote_addr)?;
        out.pin = Some(origin.origin());
        Ok(out)
    }

    /// A client for `policy` pinned to BOTH the origin of `origin` AND a
    /// pre-resolved list of socket addresses `addrs` from a single earlier
    /// lookup ([`resolve_endpoint`]). No second DNS lookup is ever performed,
    /// so a hostname that re-resolves after the check cannot move the request
    /// off the checked addresses. Every address in `addrs` is checked against
    /// `policy.addresses` up front and re-checked against the peer address
    /// after the response head arrives.
    pub fn pinned_to_addrs(
        policy: Policy,
        origin: &Url,
        addrs: Vec<SocketAddr>,
    ) -> Result<Self, OutboundError> {
        policy.validate_pinned()?;
        if addrs.is_empty() {
            return Err(OutboundError::Lookup {
                host: origin.host_str().unwrap_or_default().to_string(),
                why: "no address".into(),
            });
        }
        let host = origin.host_str().unwrap_or_default().to_ascii_lowercase();
        for a in &addrs {
            if let Err(reason) = policy.addresses.check(a.ip()) {
                return Err(OutboundError::AddressRefused { host, ip: a.ip(), reason });
            }
        }
        let pinned_host = host.clone();
        let pinned_addrs = Arc::new(addrs);
        let lookup: Lookup = Arc::new(move |req_host: &str| {
            let matches = req_host.eq_ignore_ascii_case(&pinned_host);
            let out = if matches {
                Ok((*pinned_addrs).clone())
            } else {
                Err(io::Error::other(format!("host {req_host:?} does not match pinned host")))
            };
            Box::pin(async move { out })
        });
        let mut out = Self::build(policy, lookup, policy.addresses, reqwest::Response::remote_addr)?;
        out.pin = Some(origin.origin());
        Ok(out)
    }

    /// A client for the named policy ([`policy::POLICIES`]). An unknown
    /// name is refused.
    pub fn named(name: &str) -> Result<Self, OutboundError> {
        Self::new(*policy::lookup(name)?)
    }

    #[cfg(test)]
    pub(crate) fn with_lookup(policy: Policy, lookup: Lookup) -> Result<Self, OutboundError> {
        policy.validate_unpinned()?;
        Self::build(policy, lookup, policy.addresses, reqwest::Response::remote_addr)
    }

    /// [`Outbound::pinned`] with a test lookup.
    #[cfg(test)]
    pub(crate) fn pinned_with_lookup(
        policy: Policy,
        origin: &Url,
        lookup: Lookup,
    ) -> Result<Self, OutboundError> {
        policy.validate_pinned()?;
        let mut out = Self::build(policy, lookup, policy.addresses, reqwest::Response::remote_addr)?;
        out.pin = Some(origin.origin());
        Ok(out)
    }

    /// Test seam for the peer-address re-check: the resolver applies
    /// `resolver_rule` instead of the policy's rule, and `peer_of` reads the
    /// peer address.
    #[cfg(test)]
    pub(crate) fn with_seams(
        policy: Policy,
        lookup: Lookup,
        resolver_rule: Addresses,
        peer_of: PeerOf,
    ) -> Result<Self, OutboundError> {
        Self::build(policy, lookup, resolver_rule, peer_of)
    }

    fn build(
        policy: Policy,
        lookup: Lookup,
        resolver_rule: Addresses,
        peer_of: PeerOf,
    ) -> Result<Self, OutboundError> {
        policy.validate()?;
        install_crypto_provider();
        let client = build_reqwest_client(
            &policy,
            GuardedResolver {
                addresses: resolver_rule,
                require_loopback: false,
                timeout: policy.connect_timeout,
                lookup: lookup.clone(),
            },
        )?;
        let loopback_secret_client = if policy.schemes == Schemes::HttpOrHttps {
            Some(build_reqwest_client(
                &policy,
                GuardedResolver {
                    addresses: resolver_rule,
                    require_loopback: true,
                    timeout: policy.connect_timeout,
                    lookup,
                },
            )?)
        } else {
            None
        };
        Ok(Self { policy, client, loopback_secret_client, peer_of, pin: None })
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Send `req` under this client's policy. A non-success status is a
    /// response, not an error. With redirects off, a redirect response is
    /// returned as it is.
    pub async fn send(&self, req: Request) -> Result<Response, OutboundError> {
        let deadline = Instant::now() + self.policy.total_timeout;
        match tokio::time::timeout_at(deadline, self.send_hops(req, deadline)).await {
            Ok(result) => result,
            Err(_) => Err(OutboundError::Timeout),
        }
    }

    /// The hops of one call. Headers and the body belong to the origin of
    /// the request URL (`home`): a hop there gets them all, but only until
    /// the chain first leaves it. From the first hop to any other origin on,
    /// every hop (a return to `home` included) gets only
    /// [`CROSS_ORIGIN_HEADERS`], so an intermediate origin cannot choose
    /// which path on `home` receives them. A redirect that would resend the
    /// body to another origin, or move from https to http, is refused.
    async fn send_hops(&self, mut req: Request, deadline: Instant) -> Result<Response, OutboundError> {
        let max = self.policy.max_redirects;
        let home = req.url.origin();
        let mut left_home = false;
        for hop in 0..=max {
            self.policy.check_url(&req.url)?;
            if let Some(pin) = &self.pin
                && req.url.origin() != *pin
            {
                return Err(OutboundError::UrlRefused {
                    policy: self.policy.name,
                    why: "not the origin this client is pinned to",
                });
            }
            let origin = req.url.origin();
            left_home |= origin != home;
            let active_secrets: Vec<&SecretHeader> =
                req.secrets.iter().filter(|s| !left_home && s.origin == origin).collect();
            let has_userinfo = !req.url.username().is_empty() || req.url.password().is_some();
            let cleartext_secret = req.url.scheme() == "http" && (!active_secrets.is_empty() || has_userinfo);
            if cleartext_secret
                && let Some(ip) = url_ip(&req.url)
                && !crate::addr::is_loopback(ip)
            {
                return Err(OutboundError::CleartextSecret { host: ip.to_string(), ip });
            }
            let client = if cleartext_secret {
                self.loopback_secret_client.as_ref().ok_or(OutboundError::UrlRefused {
                    policy: self.policy.name,
                    why: "scheme not allowed",
                })?
            } else {
                &self.client
            };
            let headers = if !left_home {
                req.headers.clone()
            } else {
                let mut kept = HeaderMap::new();
                for name in CROSS_ORIGIN_HEADERS {
                    for v in req.headers.get_all(name) {
                        kept.append(name.clone(), v.clone());
                    }
                }
                kept
            };
            let mut rb = client.request(req.method.clone(), req.url.clone()).headers(headers);
            for s in active_secrets {
                rb = rb.header(s.name.clone(), s.value.clone());
            }
            if let Some(b) = &req.body {
                if origin != home {
                    // Unreachable: the redirect step below refuses this hop.
                    return Err(OutboundError::Redirect("the body may not go to another origin".into()));
                }
                rb = rb.body(b.clone());
            }
            let resp = rb.send().await.map_err(send_error)?;
            let remote = (self.peer_of)(&resp).ok_or(OutboundError::Unverified)?;
            self.policy.addresses.check(remote.ip()).map_err(|reason| OutboundError::PeerRefused {
                host: req.url.host_str().unwrap_or_default().to_string(),
                ip: remote.ip(),
                reason,
            })?;
            if cleartext_secret && !crate::addr::is_loopback(remote.ip()) {
                return Err(OutboundError::CleartextSecret {
                    host: req.url.host_str().unwrap_or_default().to_string(),
                    ip: remote.ip(),
                });
            }
            let status = resp.status();
            if max == 0 || !status.is_redirection() || status == StatusCode::NOT_MODIFIED {
                return Ok(Response {
                    inner: resp,
                    url: req.url,
                    remote,
                    cap: self.policy.max_body_bytes,
                    deadline,
                });
            }
            if hop == max {
                return Err(OutboundError::Redirect(format!("stopped after {max} redirects")));
            }
            let loc = resp.headers().get(LOCATION).and_then(|v| v.to_str().ok());
            self.follow(&mut req, &home, status, loc)?;
        }
        Err(OutboundError::Redirect(format!("stopped after {max} redirects")))
    }

    /// Turn `req` into the next hop of a redirect, or refuse it. `home` is
    /// the origin the request was built for.
    fn follow(
        &self,
        req: &mut Request,
        home: &url::Origin,
        status: StatusCode,
        location: Option<&str>,
    ) -> Result<(), OutboundError> {
        let loc = location.ok_or_else(|| {
            OutboundError::Redirect(format!("HTTP {} without a Location header", status.as_u16()))
        })?;
        let next = req.url.join(loc).map_err(|_| OutboundError::Redirect("bad redirect target".into()))?;
        if req.url.scheme() == "https" && next.scheme() == "http" && !self.policy.allow_scheme_downgrade {
            return Err(OutboundError::Redirect("refusing a redirect from https to http".into()));
        }
        if !matches!(status.as_u16(), 307 | 308) {
            // 301, 302 and 303 become a GET without a body.
            req.method = Method::GET;
            req.body = None;
            req.headers.remove(CONTENT_TYPE);
        }
        if req.body.is_some() && &next.origin() != home {
            return Err(OutboundError::Redirect(format!(
                "refusing HTTP {} to another origin: it would resend the request body",
                status.as_u16()
            )));
        }
        req.url = next;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// A response whose body can only be read under the policy's cap and the
/// call's deadline.
pub struct Response {
    inner: reqwest::Response,
    url: Url,
    remote: SocketAddr,
    cap: usize,
    deadline: Instant,
}

/// A body read under the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    pub bytes: Vec<u8>,
    /// The body was longer than the cap and was cut.
    pub truncated: bool,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    /// The URL of the hop that answered.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The checked peer address of the connection that carried the response.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// At most the cap, cut there (`truncated` says so).
    pub async fn body(self) -> Result<Body, OutboundError> {
        self.read(false).await
    }

    /// The whole body, or [`OutboundError::TooLarge`] past the cap.
    pub async fn bytes(self) -> Result<Vec<u8>, OutboundError> {
        Ok(self.read(true).await?.bytes)
    }

    /// The whole body, or [`OutboundError::TooLarge`] past `limit` (or the
    /// policy's cap, whichever is smaller).
    pub async fn bytes_within(mut self, limit: usize) -> Result<Vec<u8>, OutboundError> {
        self.cap = self.cap.min(limit);
        Ok(self.read(true).await?.bytes)
    }

    /// Stream the response body directly into `writer`, enforcing the policy's
    /// body cap and call deadline without buffering the full body in memory.
    pub async fn stream_to_writer<W: io::Write>(mut self, writer: &mut W) -> Result<usize, OutboundError> {
        let cap = self.cap;
        let declared = self
            .inner
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|n| n > cap as u64) {
            return Err(OutboundError::TooLarge { limit: cap });
        }
        let mut written = 0usize;
        loop {
            let chunk = match tokio::time::timeout_at(self.deadline, self.inner.chunk()).await {
                Err(_) => return Err(OutboundError::Timeout),
                Ok(Err(e)) => return Err(send_error(e)),
                Ok(Ok(None)) => return Ok(written),
                Ok(Ok(Some(chunk))) => chunk,
            };
            if chunk.len() > cap - written {
                return Err(OutboundError::TooLarge { limit: cap });
            }
            writer.write_all(&chunk).map_err(|e| OutboundError::Body(e.to_string()))?;
            written += chunk.len();
        }
    }

    /// The whole body as JSON, or [`OutboundError::TooLarge`] past the cap.
    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, OutboundError> {
        let bytes = self.bytes().await?;
        serde_json::from_slice(&bytes).map_err(|e| OutboundError::Body(format!("invalid JSON: {e}")))
    }

    async fn read(mut self, strict: bool) -> Result<Body, OutboundError> {
        let cap = self.cap;
        let declared = self
            .inner
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if strict && declared.is_some_and(|n| n > cap as u64) {
            return Err(OutboundError::TooLarge { limit: cap });
        }
        let mut bytes = Vec::new();
        loop {
            let chunk = match tokio::time::timeout_at(self.deadline, self.inner.chunk()).await {
                Err(_) => return Err(OutboundError::Timeout),
                Ok(Err(e)) => return Err(send_error(e)),
                Ok(Ok(None)) => return Ok(Body { bytes, truncated: false }),
                Ok(Ok(Some(chunk))) => chunk,
            };
            let room = cap - bytes.len();
            if chunk.len() > room {
                if strict {
                    return Err(OutboundError::TooLarge { limit: cap });
                }
                bytes.extend_from_slice(&chunk[..room]);
                return Ok(Body { bytes, truncated: true });
            }
            bytes.extend_from_slice(&chunk);
        }
    }
}

#[cfg(test)]
mod tests;
