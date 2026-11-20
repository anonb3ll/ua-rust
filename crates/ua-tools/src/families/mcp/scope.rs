//! Address scopes for Streamable HTTP downstream servers.
//!
//! A server is registered with one scope and may only be reached at an
//! address inside it: `public` (global unicast), `private` (RFC 1918, the
//! shared/CGNAT range that tailnets use, and IPv6 unique-local) or
//! `loopback`. Everything else (link-local and cloud metadata, multicast,
//! unspecified, documentation, benchmarking, reserved, and IPv6 forms that
//! embed an IPv4 address: compatible, translated, NAT64 and 6to4) is in no
//! scope and is never dialled. IPv4-mapped IPv6 is judged as its IPv4.
//!
//! The URL host is checked at registration, and again at call time on every
//! address the resolver returns: [`PinnedResolver`] resolves only the
//! registered host name and hands the connection only addresses it checked,
//! so a rebinding answer between the check and the connect cannot slip in.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::families::web::{embedded_v4, non_public_reason};

/// Where a Streamable HTTP server may be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddressScope {
    /// Global unicast addresses only (the default).
    Public,
    /// RFC 1918, 100.64.0.0/10 (tailnets) and fc00::/7 only.
    Private,
    /// 127.0.0.0/8 and ::1 only.
    Loopback,
}

impl AddressScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Loopback => "loopback",
        }
    }
}

fn classify_v4(ip: Ipv4Addr) -> Option<AddressScope> {
    let o = ip.octets();
    if ip.is_loopback() {
        return Some(AddressScope::Loopback);
    }
    if ip.is_private() || (o[0] == 100 && (o[1] & 0xC0) == 64) {
        return Some(AddressScope::Private);
    }
    non_public_reason(IpAddr::V4(ip)).is_none().then_some(AddressScope::Public)
}

/// The scope `ip` belongs to, or `None` when no scope admits it.
pub fn classify(ip: IpAddr) -> Option<AddressScope> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_v4(v4);
            }
            if embedded_v4(v6).is_some() {
                return None;
            }
            if v6.is_loopback() {
                return Some(AddressScope::Loopback);
            }
            if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                return Some(AddressScope::Private);
            }
            non_public_reason(IpAddr::V6(v6)).is_none().then_some(AddressScope::Public)
        }
    }
}

/// Whether a server registered with `scope` may dial `ip`.
pub fn allowed(ip: IpAddr, scope: AddressScope) -> bool {
    classify(ip) == Some(scope)
}

/// Whether a host name, by its spelling alone, belongs to loopback.
pub fn names_loopback(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost" || h.ends_with(".localhost")
}

/// Resolve `host` once and check every address against `scope`.
pub async fn resolve_in_scope(host: &str, scope: AddressScope) -> Result<Vec<SocketAddr>, String> {
    let lookup = tokio::net::lookup_host((host, 0));
    let addrs: Vec<SocketAddr> = match tokio::time::timeout(Duration::from_secs(10), lookup).await {
        Ok(Ok(it)) => it.collect(),
        Ok(Err(_)) => return Err(format!("address_refused: could not resolve {host:?}")),
        Err(_) => return Err(format!("address_refused: resolving {host:?} timed out")),
    };
    if addrs.is_empty() {
        return Err(format!("address_refused: {host:?} resolved to no address"));
    }
    if let Some(bad) = addrs.iter().find(|a| !allowed(a.ip(), scope)) {
        return Err(format!(
            "address_refused: {host:?} resolves to {}, outside its registered {} scope",
            bad.ip(),
            scope.as_str()
        ));
    }
    Ok(addrs)
}

/// The HTTP client's resolver: only the registered host, only in scope.
pub struct PinnedResolver {
    pub host: String,
    pub scope: AddressScope,
}

impl reqwest::dns::Resolve for PinnedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let asked = name.as_str().trim_end_matches('.').to_ascii_lowercase();
        let (host, scope) = (self.host.clone(), self.scope);
        Box::pin(async move {
            if asked != host {
                let e: Box<dyn std::error::Error + Send + Sync> =
                    format!("address_refused: the connection is pinned to {host:?}").into();
                return Err(e);
            }
            let addrs = resolve_in_scope(&host, scope).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Option<AddressScope> {
        classify(s.parse().unwrap())
    }

    #[test]
    fn loopback_private_and_public() {
        use AddressScope::*;
        assert_eq!(c("127.0.0.1"), Some(Loopback));
        assert_eq!(c("127.8.9.10"), Some(Loopback));
        assert_eq!(c("::1"), Some(Loopback));
        assert_eq!(c("::ffff:127.0.0.1"), Some(Loopback), "mapped addresses are judged as IPv4");
        assert_eq!(c("10.1.2.3"), Some(Private));
        assert_eq!(c("172.16.0.1"), Some(Private));
        assert_eq!(c("192.168.1.1"), Some(Private));
        assert_eq!(c("100.64.0.1"), Some(Private), "tailnet / CGNAT");
        assert_eq!(c("fd7a:115c:a1e0::1"), Some(Private), "tailnet ULA");
        assert_eq!(c("::ffff:10.0.0.1"), Some(Private));
        assert_eq!(c("8.8.8.8"), Some(Public));
        assert_eq!(c("2606:4700:4700::1111"), Some(Public));
    }

    #[test]
    fn addresses_in_no_scope() {
        for ip in [
            "169.254.169.254", // cloud metadata
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "192.0.0.1",
            "::",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::7f00:1",  // NAT64 of 127.0.0.1
            "64:ff9b::808:808", // NAT64 of a public address: still refused
            "2002:7f00:1::",    // 6to4
            "::127.0.0.1",      // IPv4-compatible
            "::ffff:169.254.169.254",
        ] {
            assert_eq!(c(ip), None, "{ip} must be in no scope");
        }
    }

    #[test]
    fn scope_membership_is_exact() {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let private: IpAddr = "10.0.0.5".parse().unwrap();
        let public: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(allowed(lo, AddressScope::Loopback));
        assert!(!allowed(lo, AddressScope::Public));
        assert!(!allowed(lo, AddressScope::Private));
        assert!(!allowed(private, AddressScope::Public), "private needs a private registration");
        assert!(!allowed(public, AddressScope::Private));
        assert!(allowed(public, AddressScope::Public));
    }

    #[test]
    fn loopback_names() {
        assert!(names_loopback("localhost"));
        assert!(names_loopback("LOCALHOST."));
        assert!(names_loopback("api.localhost"));
        assert!(!names_loopback("localhost.example.com"));
    }

    #[tokio::test]
    async fn the_resolver_pins_one_host_and_checks_its_scope() {
        use reqwest::dns::Resolve;
        let r = PinnedResolver { host: "localhost".into(), scope: AddressScope::Loopback };
        let addrs: Vec<_> = r.resolve("localhost".parse().unwrap()).await.unwrap().collect();
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
        assert!(r.resolve("example.com".parse().unwrap()).await.is_err(), "other names are refused");
        let public = PinnedResolver { host: "localhost".into(), scope: AddressScope::Public };
        let e = public.resolve("localhost".parse().unwrap()).await.err().unwrap().to_string();
        assert!(e.contains("outside its registered public scope"), "{e}");
    }
}
