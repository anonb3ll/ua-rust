//! Named outbound policies, one per destination class.
//!
//! A [`Policy`] fixes everything about where an [`crate::Outbound`] client
//! may go and how much it may take: schemes, hosts, ports, the address
//! classes a connection may reach, redirects, the body cap and the timeouts.
//! The policies the hub uses are constants here and listed in [`POLICIES`];
//! [`lookup`] refuses any other name.

use std::net::IpAddr;
use std::time::Duration;

use crate::addr;
use crate::outbound::OutboundError;

/// Which URL schemes a policy accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schemes {
    HttpsOnly,
    HttpOrHttps,
}

/// Which hosts a policy accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hosts {
    /// Exactly these DNS names, compared byte for byte after the URL parser
    /// lowercased them (a trailing dot is a different name). IP-literal
    /// hosts are refused.
    Exactly(&'static [&'static str]),
    /// Any DNS name or IP literal; the address check still applies.
    Any,
}

/// Which addresses a connection may reach, by [`addr::Class`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addresses {
    /// [`addr::Class::Public`] only (NAT64 and 6to4 of a public IPv4
    /// address included).
    Public,
    /// [`addr::Class::GlobalUnicastOnly`] only: no NAT64 or 6to4 form.
    GlobalUnicastOnly,
    /// [`addr::Class::Public`] and loopback, nothing else. For a destination
    /// that is deliberately local, and for tests.
    PublicOrLoopback,
}

impl Addresses {
    /// The address class this rule is built on.
    pub fn class(self) -> addr::Class {
        match self {
            Addresses::Public | Addresses::PublicOrLoopback => addr::Class::Public,
            Addresses::GlobalUnicastOnly => addr::Class::GlobalUnicastOnly,
        }
    }

    /// `Err` with the reason when a connection to `ip` is not allowed.
    pub fn check(self, ip: IpAddr) -> Result<(), &'static str> {
        match addr::reason_in(ip, self.class()) {
            None => Ok(()),
            Some(_) if self == Addresses::PublicOrLoopback && addr::is_loopback(ip) => Ok(()),
            Some(reason) => Err(reason),
        }
    }
}

/// One destination class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Stable name, used in errors and logs.
    pub name: &'static str,
    pub schemes: Schemes,
    pub hosts: Hosts,
    /// Refuse a URL that names a port (the scheme's default port is fine:
    /// the URL parser drops it).
    pub default_port_only: bool,
    pub addresses: Addresses,
    /// Redirects followed by hand, each hop checked against this policy
    /// again. With 0 a redirect response is returned as it is.
    pub max_redirects: u8,
    /// Follow a redirect from https to http. No shipped policy does.
    pub allow_scheme_downgrade: bool,
    /// Largest response body any read path returns.
    pub max_body_bytes: usize,
    pub connect_timeout: Duration,
    /// One request, response body included.
    pub request_timeout: Duration,
    /// The whole call, redirects and body included.
    pub total_timeout: Duration,
}

/// The destination of a Slack slash command's ephemeral reply: Slack's
/// `response_url` host, https on the default port, public addresses only,
/// no redirects, 10 seconds for the whole call.
pub const SLACK_RESPONSE_URL: Policy = Policy {
    name: "slack.response_url",
    schemes: Schemes::HttpsOnly,
    hosts: Hosts::Exactly(&["hooks.slack.com"]),
    default_port_only: true,
    addresses: Addresses::Public,
    max_redirects: 0,
    allow_scheme_downgrade: false,
    max_body_bytes: 64 * 1024,
    connect_timeout: Duration::from_secs(10),
    request_timeout: Duration::from_secs(10),
    total_timeout: Duration::from_secs(10),
};

/// Every named policy.
pub const POLICIES: &[&Policy] = &[&SLACK_RESPONSE_URL];

/// The policy called `name`. An unknown name is refused.
pub fn lookup(name: &str) -> Result<&'static Policy, OutboundError> {
    POLICIES.iter().copied().find(|p| p.name == name).ok_or_else(|| OutboundError::UnknownPolicy(name.into()))
}

/// Largest values a policy may carry: a policy is a bound, not a way out.
const MAX_BODY_CEILING: usize = 64 * 1024 * 1024;
const MAX_TIMEOUT_CEILING: Duration = Duration::from_secs(300);
const MAX_REDIRECTS_CEILING: u8 = 10;

impl Policy {
    /// Refuse a policy that is empty or unbounded.
    pub(crate) fn validate(&self) -> Result<(), OutboundError> {
        let bad = |why: &'static str| Err(OutboundError::InvalidPolicy { policy: self.name, why });
        if self.name.is_empty() {
            return bad("the policy has no name");
        }
        if self.max_body_bytes == 0 || self.max_body_bytes > MAX_BODY_CEILING {
            return bad("the body cap must be between 1 byte and 64 MiB");
        }
        for t in [self.connect_timeout, self.request_timeout, self.total_timeout] {
            if t.is_zero() || t > MAX_TIMEOUT_CEILING {
                return bad("every timeout must be between 0 and 300 seconds");
            }
        }
        if self.max_redirects > MAX_REDIRECTS_CEILING {
            return bad("at most 10 redirects");
        }
        if let Hosts::Exactly(names) = self.hosts
            && (names.is_empty() || names.iter().any(|n| n.is_empty()))
        {
            return bad("the host list is empty");
        }
        Ok(())
    }

    /// Check one URL (the first request or a redirect hop) against the
    /// policy. An IP-literal host is checked against [`Policy::addresses`]
    /// here, because no resolver runs for it.
    pub fn check_url(&self, url: &url::Url) -> Result<(), OutboundError> {
        let refused = |why: &'static str| Err(OutboundError::UrlRefused { policy: self.name, why });
        let scheme_ok = match self.schemes {
            Schemes::HttpsOnly => url.scheme() == "https",
            Schemes::HttpOrHttps => matches!(url.scheme(), "http" | "https"),
        };
        if !scheme_ok {
            return refused("scheme not allowed");
        }
        if !url.username().is_empty() || url.password().is_some() {
            return refused("credentials in the URL");
        }
        if self.default_port_only && url.port().is_some() {
            return refused("explicit port not allowed");
        }
        let ip = match url.host() {
            None => return refused("no host"),
            Some(url::Host::Domain(name)) => {
                return match self.hosts {
                    Hosts::Any => Ok(()),
                    Hosts::Exactly(names) if names.contains(&name) => Ok(()),
                    Hosts::Exactly(_) => refused("host not allowed"),
                };
            }
            Some(url::Host::Ipv4(v4)) => IpAddr::V4(v4),
            Some(url::Host::Ipv6(v6)) => IpAddr::V6(v6),
        };
        if matches!(self.hosts, Hosts::Exactly(_)) {
            return refused("IP-literal host not allowed");
        }
        self.addresses.check(ip).map_err(|reason| OutboundError::AddressRefused {
            host: ip.to_string(),
            ip,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn an_unknown_policy_is_refused() {
        assert!(matches!(lookup("no.such.policy"), Err(OutboundError::UnknownPolicy(_))));
        assert!(matches!(lookup(""), Err(OutboundError::UnknownPolicy(_))));
        assert_eq!(lookup("slack.response_url").unwrap(), &SLACK_RESPONSE_URL);
    }

    #[test]
    fn every_named_policy_is_valid_and_unique() {
        for p in POLICIES {
            p.validate().unwrap();
            assert_eq!(POLICIES.iter().filter(|q| q.name == p.name).count(), 1, "{}", p.name);
        }
    }

    #[test]
    fn unbounded_or_empty_policies_are_refused() {
        let base = SLACK_RESPONSE_URL;
        for bad in [
            Policy { name: "", ..base },
            Policy { max_body_bytes: 0, ..base },
            Policy { max_body_bytes: MAX_BODY_CEILING + 1, ..base },
            Policy { connect_timeout: Duration::ZERO, ..base },
            Policy { request_timeout: Duration::from_secs(301), ..base },
            Policy { total_timeout: Duration::ZERO, ..base },
            Policy { max_redirects: 11, ..base },
            Policy { hosts: Hosts::Exactly(&[]), ..base },
            Policy { hosts: Hosts::Exactly(&[""]), ..base },
        ] {
            assert!(matches!(bad.validate(), Err(OutboundError::InvalidPolicy { .. })), "{bad:?}");
        }
    }

    #[test]
    fn the_slack_policy_admits_only_its_host() {
        let p = SLACK_RESPONSE_URL;
        assert!(p.check_url(&url("https://hooks.slack.com/commands/T0/1/abc")).is_ok());
        assert!(p.check_url(&url("https://HOOKS.slack.com/commands/x")).is_ok(), "the parser lowercases");
        assert!(p.check_url(&url("https://hooks.slack.com:443/x")).is_ok(), "the default port is dropped");
        for bad in [
            "http://hooks.slack.com/x",
            "https://hooks.slack.com:8443/x",
            "https://hooks.slack.com./x",
            "https://user:pw@hooks.slack.com/x",
            "https://hooks.slack.com.example.com/x",
            "https://evil.example.com/x",
            "https://93.184.215.14/x",
            "https://[2606:4700:4700::1111]/x",
            "ftp://hooks.slack.com/x",
        ] {
            assert!(matches!(p.check_url(&url(bad)), Err(OutboundError::UrlRefused { .. })), "{bad}");
        }
    }

    #[test]
    fn ip_literals_are_checked_without_a_resolver() {
        let any = Policy { hosts: Hosts::Any, schemes: Schemes::HttpOrHttps, ..SLACK_RESPONSE_URL };
        assert!(any.check_url(&url("https://93.184.215.14/")).is_ok());
        for bad in ["https://127.0.0.1/", "https://10.0.0.1/", "https://[::1]/", "https://[::ffff:10.0.0.1]/"]
        {
            assert!(matches!(any.check_url(&url(bad)), Err(OutboundError::AddressRefused { .. })), "{bad}");
        }
        // The class decides NAT64 and 6to4 of a public address.
        let nat64 = url("https://[64:ff9b::808:808]/");
        assert!(any.check_url(&nat64).is_ok());
        let strict = Policy { addresses: Addresses::GlobalUnicastOnly, ..any };
        assert!(matches!(
            strict.check_url(&nat64),
            Err(OutboundError::AddressRefused { reason: "NAT64", .. })
        ));
        assert!(strict.check_url(&url("https://93.184.215.14/")).is_ok());
        let lo = Policy { addresses: Addresses::PublicOrLoopback, ..any };
        assert!(lo.check_url(&url("http://127.0.0.1/")).is_ok());
        assert!(lo.check_url(&url("http://[::1]/")).is_ok());
        assert!(lo.check_url(&url("http://10.0.0.1/")).is_err(), "loopback admits loopback only");
    }
}
