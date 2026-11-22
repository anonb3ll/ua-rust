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
    /// A destination the operator configured (a config value, never a URL a
    /// caller supplies): [`addr::Class::Public`], loopback and private
    /// networks ([`addr::is_private_network`]: RFC 1918, the RFC 6598 shared
    /// address space, `fc00::/7`). An operator may run the GitHub Enterprise
    /// API or a webhook receiver on a private network or on this host. Still
    /// refused: unspecified, link-local (cloud metadata), multicast,
    /// broadcast and reserved, documentation, benchmarking and IETF protocol
    /// assignments.
    /// A policy with this class follows no redirect ([`Policy::validate`]):
    /// a redirect target is chosen by the server, not by the operator.
    OperatorConfigured,
    /// Loopback only (IPv4, IPv6 or IPv4-mapped): a service on this host.
    LoopbackOnly,
}

impl Addresses {
    /// The range tables `check` starts from. Private, so that no decision
    /// can be made from the class alone: `LoopbackOnly` and the relaxed
    /// classes differ from it, and only [`Addresses::check`] knows how.
    fn base_class(self) -> addr::Class {
        match self {
            Addresses::Public
            | Addresses::PublicOrLoopback
            | Addresses::OperatorConfigured
            | Addresses::LoopbackOnly => addr::Class::Public,
            Addresses::GlobalUnicastOnly => addr::Class::GlobalUnicastOnly,
        }
    }

    /// `Err` with the reason when a connection to `ip` is not allowed.
    pub fn check(self, ip: IpAddr) -> Result<(), &'static str> {
        // Refused whatever the class, before any relaxation applies.
        if addr::is_cloud_metadata(ip) {
            return Err("cloud metadata");
        }
        if self == Addresses::LoopbackOnly {
            return if addr::is_loopback(ip) {
                Ok(())
            } else {
                Err(addr::non_public_reason(ip).unwrap_or("not loopback"))
            };
        }
        match addr::reason_in(ip, self.base_class()) {
            None => Ok(()),
            Some(_) if self == Addresses::PublicOrLoopback && addr::is_loopback(ip) => Ok(()),
            Some(_)
                if self == Addresses::OperatorConfigured
                    && (addr::is_loopback(ip) || addr::is_private_network(ip)) =>
            {
                Ok(())
            }
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
    /// Follow a redirect from https to http. Only `WEB_PAGE` does.
    pub allow_scheme_downgrade: bool,
    /// Accept any TLS certificate (self-signed, expired, another name). Only
    /// with [`Addresses::LoopbackOnly`] ([`Policy::validate`]); only
    /// `OBSIDIAN_LOCAL` sets it.
    pub accept_invalid_certs: bool,
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
    accept_invalid_certs: false,
    max_body_bytes: 64 * 1024,
    connect_timeout: Duration::from_secs(10),
    request_timeout: Duration::from_secs(10),
    total_timeout: Duration::from_secs(10),
};

/// Slack Web API calls (`apps.connections.open` for Socket Mode): https to
/// `slack.com` on the default port, public addresses, no redirects, a
/// 16 KiB body, 15 seconds for the whole call.
pub const SLACK_WEB_API: Policy = Policy {
    name: "slack.web_api",
    schemes: Schemes::HttpsOnly,
    hosts: Hosts::Exactly(&["slack.com"]),
    default_port_only: true,
    addresses: Addresses::Public,
    max_redirects: 0,
    allow_scheme_downgrade: false,
    accept_invalid_certs: false,
    max_body_bytes: 16 * 1024,
    connect_timeout: Duration::from_secs(10),
    request_timeout: Duration::from_secs(15),
    total_timeout: Duration::from_secs(15),
};

/// `web_fetch`: any public http or https page. Up to five redirects, each
/// hop checked again; a redirect from https to http is followed, because
/// the tool sends no credentials and may fetch plain http pages directly.
/// A 2 MB body (cut, not refused), 20 seconds a request, 45 for the call.
pub const WEB_PAGE: Policy = Policy {
    name: "web.page",
    schemes: Schemes::HttpOrHttps,
    hosts: Hosts::Any,
    default_port_only: false,
    addresses: Addresses::Public,
    max_redirects: 5,
    allow_scheme_downgrade: true,
    accept_invalid_certs: false,
    max_body_bytes: 2 * 1024 * 1024,
    connect_timeout: Duration::from_secs(10),
    request_timeout: Duration::from_secs(20),
    total_timeout: Duration::from_secs(45),
};

/// `web_search` providers (DuckDuckGo, Brave, Tavily): as [`WEB_PAGE`], but
/// a redirect from https to http is refused, since requests may carry an
/// API key.
pub const WEB_SEARCH: Policy = Policy { name: "web.search", allow_scheme_downgrade: false, ..WEB_PAGE };

/// The Zulip REST API at the configured site: https, any host (the site
/// comes from config and is pinned by the caller), public addresses, no
/// redirects, a 4 MiB body, 20 seconds for the call.
pub const ZULIP_API: Policy = Policy {
    name: "zulip.api",
    schemes: Schemes::HttpsOnly,
    hosts: Hosts::Any,
    default_port_only: false,
    addresses: Addresses::Public,
    max_redirects: 0,
    allow_scheme_downgrade: false,
    accept_invalid_certs: false,
    max_body_bytes: 4 * 1024 * 1024,
    connect_timeout: Duration::from_secs(10),
    request_timeout: Duration::from_secs(20),
    total_timeout: Duration::from_secs(20),
};

/// The relay's GitHub REST calls at the configured API base: as
/// [`ZULIP_API`] with a 256 KiB body.
pub const RELAY_GITHUB: Policy = Policy { name: "relay.github", max_body_bytes: 256 * 1024, ..ZULIP_API };

/// The GitHub REST API at `api.github.com` (`github_api_url` left at its
/// default): https, that one host, public addresses, no redirects, an 8 MiB
/// body (refused past it), 10 seconds to connect and 20 for the call, body
/// included.
pub const GITHUB_REST: Policy = Policy {
    name: "github.rest",
    schemes: Schemes::HttpsOnly,
    hosts: Hosts::Exactly(&["api.github.com"]),
    default_port_only: false,
    addresses: Addresses::Public,
    max_redirects: 0,
    allow_scheme_downgrade: false,
    accept_invalid_certs: false,
    max_body_bytes: 8 * 1024 * 1024,
    connect_timeout: Duration::from_secs(10),
    request_timeout: Duration::from_secs(20),
    total_timeout: Duration::from_secs(20),
};

/// A GitHub Enterprise Server API root set in `github_api_url`: as
/// [`GITHUB_REST`] for any host, with [`Addresses::OperatorConfigured`],
/// since the operator's server may be on a private network.
pub const GITHUB_ENTERPRISE: Policy = Policy {
    name: "github.enterprise",
    hosts: Hosts::Any,
    addresses: Addresses::OperatorConfigured,
    ..GITHUB_REST
};

/// The Obsidian Local REST API plugin on this host (`obsidian_api_url`):
/// http or https, loopback only, no redirects, a 16 MiB body, 20 seconds
/// for everything. The plugin serves https with a self-signed certificate,
/// so certificates are not verified; that is allowed only because every
/// address this policy reaches is loopback.
pub const OBSIDIAN_LOCAL: Policy = Policy {
    name: "obsidian.local_rest",
    schemes: Schemes::HttpOrHttps,
    hosts: Hosts::Any,
    default_port_only: false,
    addresses: Addresses::LoopbackOnly,
    max_redirects: 0,
    allow_scheme_downgrade: false,
    accept_invalid_certs: true,
    max_body_bytes: 16 * 1024 * 1024,
    connect_timeout: Duration::from_secs(20),
    request_timeout: Duration::from_secs(20),
    total_timeout: Duration::from_secs(20),
};

/// The operator's notification webhook (`notify_webhook_url`): http or
/// https, any host and port, [`Addresses::OperatorConfigured`] (the
/// receiver may be on a private network or this host), no redirects. The
/// body is never read; 64 KiB is the cap if it were. 120 seconds for
/// everything, the longest attempt the caller allows; the caller bounds
/// each attempt more tightly.
pub const NOTIFY_WEBHOOK: Policy = Policy {
    name: "notify.webhook",
    schemes: Schemes::HttpOrHttps,
    hosts: Hosts::Any,
    default_port_only: false,
    addresses: Addresses::OperatorConfigured,
    max_redirects: 0,
    allow_scheme_downgrade: false,
    accept_invalid_certs: false,
    max_body_bytes: 64 * 1024,
    connect_timeout: Duration::from_secs(120),
    request_timeout: Duration::from_secs(120),
    total_timeout: Duration::from_secs(120),
};

/// Every named policy.
///
/// These are the policies obtainable by name ([`lookup`],
/// [`crate::Outbound::named`]). None of them is relaxed
/// ([`Policy::is_relaxed`]); the relaxed ones are in [`RELAXED`], which is
/// not public, and only [`crate::Outbound::pinned`] builds a client from one.
pub const POLICIES: &[&Policy] =
    &[&SLACK_RESPONSE_URL, &SLACK_WEB_API, &WEB_PAGE, &WEB_SEARCH, &ZULIP_API, &RELAY_GITHUB, &GITHUB_REST];

/// The relaxed policies: an operator-configured address class or
/// unverified certificates. Not obtainable by name; a client built from one
/// is pinned to the one origin it was built for.
pub(crate) const RELAXED: &[&Policy] = &[&GITHUB_ENTERPRISE, &OBSIDIAN_LOCAL, &NOTIFY_WEBHOOK];

/// The policy called `name`. An unknown name, or the name of a relaxed
/// policy, is refused.
pub fn lookup(name: &str) -> Result<&'static Policy, OutboundError> {
    POLICIES
        .iter()
        .copied()
        .find(|p| p.name == name && !p.is_relaxed())
        .ok_or_else(|| OutboundError::UnknownPolicy(name.into()))
}

/// Largest values a policy may carry: a policy is a bound, not a way out.
const MAX_BODY_CEILING: usize = 64 * 1024 * 1024;
const MAX_TIMEOUT_CEILING: Duration = Duration::from_secs(300);
const MAX_REDIRECTS_CEILING: u8 = 10;

impl Policy {
    /// The policy under a loopback test hook (`fetch_allow_loopback`, the
    /// Slack test API base): loopback admitted besides public addresses,
    /// plain http allowed, any host and port. A class that already admits
    /// loopback ([`Addresses::OperatorConfigured`], [`Addresses::LoopbackOnly`])
    /// is kept as it is.
    /// Everything else is unchanged. Only test configuration reaches this;
    /// TOML and the environment cannot set those hooks.
    pub const fn loopback_test_hook(self) -> Policy {
        let addresses = match self.addresses {
            Addresses::OperatorConfigured => Addresses::OperatorConfigured,
            Addresses::LoopbackOnly => Addresses::LoopbackOnly,
            _ => Addresses::PublicOrLoopback,
        };
        Policy {
            schemes: Schemes::HttpOrHttps,
            hosts: Hosts::Any,
            default_port_only: false,
            addresses,
            ..self
        }
    }

    /// Whether the policy relaxes a default: an operator-configured address
    /// class or unverified certificates. A relaxed policy builds a client
    /// only through [`crate::Outbound::pinned`], and only when it is one of
    /// [`RELAXED`] (or that policy under the loopback test hook).
    pub fn is_relaxed(&self) -> bool {
        self.addresses == Addresses::OperatorConfigured || self.accept_invalid_certs
    }

    /// Refuse a relaxed policy for an unpinned client (one that may be sent
    /// to any URL the policy admits), on top of [`Policy::validate`].
    pub(crate) fn validate_unpinned(&self) -> Result<(), OutboundError> {
        self.validate()?;
        if self.is_relaxed() {
            return Err(OutboundError::InvalidPolicy {
                policy: self.name,
                why: "a relaxed policy builds only a client pinned to its configured origin",
            });
        }
        Ok(())
    }

    /// Refuse a relaxed policy that is not one of [`RELAXED`] (or one of
    /// them under the loopback test hook), on top of [`Policy::validate`].
    pub(crate) fn validate_pinned(&self) -> Result<(), OutboundError> {
        self.validate()?;
        if self.is_relaxed() && !RELAXED.iter().any(|r| **r == *self || r.loopback_test_hook() == *self) {
            return Err(OutboundError::InvalidPolicy {
                policy: self.name,
                why: "not one of the relaxed policies ua_ingress defines",
            });
        }
        Ok(())
    }

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
        if self.addresses == Addresses::OperatorConfigured && self.max_redirects > 0 {
            return bad("an operator-configured destination follows no redirect");
        }
        if self.accept_invalid_certs && (self.addresses != Addresses::LoopbackOnly || self.max_redirects > 0)
        {
            return bad("certificates may go unverified only for loopback, without redirects");
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
        for p in POLICIES.iter().chain(RELAXED) {
            p.validate().unwrap();
            assert_eq!(POLICIES.iter().chain(RELAXED).filter(|q| q.name == p.name).count(), 1, "{}", p.name);
        }
        for p in POLICIES {
            p.validate_unpinned().unwrap();
        }
    }

    #[test]
    fn relaxed_policies_are_not_obtainable_by_name() {
        for r in RELAXED {
            assert!(r.is_relaxed(), "{}", r.name);
            r.validate_pinned().unwrap();
            r.loopback_test_hook().validate_pinned().unwrap();
            assert!(matches!(r.validate_unpinned(), Err(OutboundError::InvalidPolicy { .. })), "{}", r.name);
            assert!(
                !POLICIES.iter().any(|p| p.name == r.name || *p == *r),
                "{} is in the public list",
                r.name
            );
            // Also a name built at run time.
            let built = format!("{}{}", &r.name[..3], &r.name[3..]);
            assert!(matches!(lookup(&built), Err(OutboundError::UnknownPolicy(_))), "{}", r.name);
        }
        assert!(POLICIES.iter().all(|p| !p.is_relaxed()));
        // A hand-made relaxed policy is not one of ua_ingress's.
        for odd in [
            Policy { name: "odd.op", addresses: Addresses::OperatorConfigured, ..ZULIP_API },
            Policy { max_body_bytes: 1, ..NOTIFY_WEBHOOK },
            Policy { total_timeout: Duration::from_secs(300), ..GITHUB_ENTERPRISE },
        ] {
            assert!(matches!(odd.validate_pinned(), Err(OutboundError::InvalidPolicy { .. })), "{odd:?}");
        }
        // A strict policy may be pinned too.
        ZULIP_API.validate_pinned().unwrap();
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
            Policy { max_redirects: 1, ..GITHUB_ENTERPRISE },
            Policy { accept_invalid_certs: true, ..base },
            Policy { accept_invalid_certs: true, addresses: Addresses::PublicOrLoopback, ..OBSIDIAN_LOCAL },
            Policy { max_redirects: 1, ..OBSIDIAN_LOCAL },
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

    #[test]
    fn the_operator_class_admits_private_networks_and_nothing_else_extra() {
        let op = Addresses::OperatorConfigured;
        for yes in [
            "8.8.8.8",
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "10.1.2.3",
            "::ffff:10.1.2.3",
            "172.16.5.4",
            "192.168.1.10",
            "::ffff:192.168.1.10",
            "100.100.100.201",
            "fd00::7",
            "fd00:ec2::253",
            "fd20:ce::1",
            "64:ff9b::808:808",
        ] {
            assert!(op.check(yes.parse().unwrap()).is_ok(), "{yes}");
        }
        for (no, why) in [
            ("100.100.100.200", "cloud metadata"),
            ("::ffff:100.100.100.200", "cloud metadata"),
            ("::ffff:0:100.100.100.200", "cloud metadata"),
            ("64:ff9b::100.100.100.200", "cloud metadata"),
            ("fd00:ec2::254", "cloud metadata"),
            ("fd20:ce::254", "cloud metadata"),
            ("169.254.169.254", "link-local (includes cloud metadata)"),
            ("::ffff:169.254.169.254", "link-local (includes cloud metadata)"),
            ("64:ff9b::169.254.169.254", "link-local (includes cloud metadata)"),
            // Only the mapped form of a private address is a private network.
            ("::ffff:0:10.1.2.3", "private"),
            ("64:ff9b::10.1.2.3", "private"),
            ("2002:a01:203::", "private"),
            ("::10.1.2.3", "private"),
            ("fe80::1", "link-local"),
            ("0.0.0.0", "unspecified"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "reserved"),
            ("192.0.2.1", "documentation"),
        ] {
            assert_eq!(op.check(no.parse().unwrap()), Err(why), "{no}");
        }
        // The class is only used by policies for operator-set destinations.
        let users: Vec<&str> =
            RELAXED.iter().filter(|p| p.addresses == Addresses::OperatorConfigured).map(|p| p.name).collect();
        assert_eq!(users, ["github.enterprise", "notify.webhook"]);
    }

    #[test]
    fn every_class_refuses_cloud_metadata_and_loopback_only_refuses_public() {
        let all = [
            Addresses::Public,
            Addresses::GlobalUnicastOnly,
            Addresses::PublicOrLoopback,
            Addresses::OperatorConfigured,
            Addresses::LoopbackOnly,
        ];
        for a in all {
            for m in ["100.100.100.200", "::ffff:100.100.100.200", "fd00:ec2::254", "fd20:ce::254"] {
                assert_eq!(a.check(m.parse().unwrap()), Err("cloud metadata"), "{a:?} {m}");
            }
        }
        // LoopbackOnly is decided by `check` alone (there is no public class
        // accessor to misuse): public addresses are refused.
        for public in ["8.8.8.8", "2606:4700:4700::1111", "64:ff9b::808:808"] {
            assert_eq!(
                Addresses::LoopbackOnly.check(public.parse().unwrap()),
                Err("not loopback"),
                "{public}"
            );
        }
        assert!(Addresses::LoopbackOnly.check("::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn the_obsidian_policy_is_loopback_only() {
        let p = OBSIDIAN_LOCAL;
        for ok in [
            "https://127.0.0.1:27124/",
            "http://127.0.0.1:27123/",
            "https://[::1]:27124/",
            "https://localhost:27124/",
        ] {
            assert!(p.check_url(&url(ok)).is_ok(), "{ok}");
        }
        for bad in ["https://10.0.0.1:27124/", "https://93.184.215.14/", "https://[fd00::1]/"] {
            assert!(matches!(p.check_url(&url(bad)), Err(OutboundError::AddressRefused { .. })), "{bad}");
        }
        assert_eq!(Addresses::LoopbackOnly.check("8.8.8.8".parse().unwrap()), Err("not loopback"));
        assert_eq!(Addresses::LoopbackOnly.check("10.0.0.1".parse().unwrap()), Err("private"));
        // The test hook does not widen it, and unverified TLS appears nowhere else.
        assert_eq!(p.loopback_test_hook().addresses, Addresses::LoopbackOnly);
        let lax: Vec<&str> = RELAXED.iter().filter(|p| p.accept_invalid_certs).map(|p| p.name).collect();
        assert_eq!(lax, ["obsidian.local_rest"]);
    }

    #[test]
    fn the_github_policies() {
        assert!(GITHUB_REST.check_url(&url("https://api.github.com/repos/a/b")).is_ok());
        assert!(GITHUB_REST.check_url(&url("https://ghe.example.com/api/v3")).is_err());
        assert!(GITHUB_REST.check_url(&url("http://api.github.com/")).is_err());
        assert!(GITHUB_ENTERPRISE.check_url(&url("https://ghe.example.com/api/v3")).is_ok());
        assert!(GITHUB_ENTERPRISE.check_url(&url("https://10.20.30.40/api/v3")).is_ok());
        assert!(GITHUB_ENTERPRISE.check_url(&url("https://169.254.169.254/")).is_err());
        assert!(GITHUB_ENTERPRISE.check_url(&url("http://ghe.example.com/")).is_err());
        // The test hook keeps the operator class (it already admits loopback).
        let hooked = GITHUB_ENTERPRISE.loopback_test_hook();
        assert_eq!(hooked.addresses, Addresses::OperatorConfigured);
        assert!(hooked.check_url(&url("http://127.0.0.1:9/")).is_ok());
    }
}
