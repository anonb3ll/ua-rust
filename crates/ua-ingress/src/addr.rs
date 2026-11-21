//! The address classifier: is an IP address public, and if not, why.
//!
//! This is the one implementation. `ua_tools::families::web::non_public_reason`
//! and `ua_server::oauth::cimd::is_public_ip` are re-exports of it.
//!
//! An address is public only when it is global unicast. Refused, with the
//! reason returned:
//!
//! - IPv4: `0.0.0.0/8` (unspecified), loopback, RFC 1918 private, link-local
//!   (cloud metadata lives there), the shared address space `100.64.0.0/10`,
//!   IETF protocol assignments `192.0.0.0/24`, the documentation ranges,
//!   benchmarking `198.18.0.0/15`, multicast, and `240.0.0.0/4` (reserved,
//!   broadcast included);
//! - IPv6: unspecified, loopback, unique local `fc00::/7`, link-local
//!   `fe80::/10` and the old site-local `fec0::/10`, multicast, everything
//!   outside `2000::/3`, documentation (`2001:db8::/32`, `3fff::/20`) and
//!   IETF protocol assignments `2001::/23` (Teredo included);
//! - IPv6 forms that carry an IPv4 address (mapped, compatible, translated,
//!   NAT64 well-known and local-use, 6to4) are judged by that IPv4 address
//!   first. Mapped and translated forms of a public IPv4 address are public;
//!   the compatible form `::/96`, NAT64 `64:ff9b::/32` and 6to4 `2002::/16`
//!   are refused whatever they carry.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why `ip` is not a public address, or `None` for a public one.
pub fn non_public_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => v4_reason(v4),
        IpAddr::V6(v6) => v6_reason(v6),
    }
}

/// True only for globally routable unicast addresses.
pub fn is_public(ip: IpAddr) -> bool {
    non_public_reason(ip).is_none()
}

/// Loopback, in IPv4, IPv6 or IPv4-mapped IPv6 form.
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
    }
}

/// The IPv4 destination an IPv6 address stands for (mapped, compatible,
/// translated, NAT64 and 6to4 forms).
pub fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let from = |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    if s[..6] == [0; 6] && !(s[6] == 0 && s[7] <= 1) {
        return Some(from(s[6], s[7])); // ::a.b.c.d (deprecated compatible form)
    }
    if s[..4] == [0; 4] && s[4] == 0xffff && s[5] == 0 {
        return Some(from(s[6], s[7])); // ::ffff:0:a.b.c.d (translated)
    }
    if s[0] == 0x64 && s[1] == 0xff9b && (s[2..6] == [0; 4] || s[2] == 1) {
        return Some(from(s[6], s[7])); // NAT64, well-known and local-use
    }
    if s[0] == 0x2002 {
        return Some(from(s[1], s[2])); // 6to4
    }
    None
}

fn v4_reason(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    if o[0] == 0 {
        return Some("unspecified");
    }
    if ip.is_loopback() {
        return Some("loopback");
    }
    if ip.is_private() {
        return Some("private");
    }
    if ip.is_link_local() {
        return Some("link-local (includes cloud metadata)");
    }
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return Some("shared address space");
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return Some("IETF protocol assignment");
    }
    if ip.is_documentation() {
        return Some("documentation");
    }
    if o[0] == 198 && (o[1] & 0xFE) == 18 {
        return Some("benchmarking");
    }
    if ip.is_multicast() {
        return Some("multicast");
    }
    if o[0] >= 240 {
        return Some("reserved");
    }
    None
}

/// Why an IPv6 wrapper of a public IPv4 address is still refused, or `None`
/// for the forms judged as their IPv4 address (mapped and translated).
fn wrapper_reason(ip: Ipv6Addr) -> Option<&'static str> {
    let s = ip.segments();
    if ip.to_ipv4_mapped().is_some() || (s[..4] == [0; 4] && s[4] == 0xffff && s[5] == 0) {
        return None;
    }
    if s[..6] == [0; 6] {
        return Some("IPv4-compatible");
    }
    if s[0] == 0x64 && s[1] == 0xff9b {
        return Some("NAT64");
    }
    if s[0] == 0x2002 {
        return Some("6to4");
    }
    // `embedded_v4` knows no other form; refuse rather than guess.
    Some("embeds an IPv4 address")
}

fn v6_reason(ip: Ipv6Addr) -> Option<&'static str> {
    if let Some(v4) = embedded_v4(ip) {
        return v4_reason(v4).or_else(|| wrapper_reason(ip));
    }
    let s = ip.segments();
    if ip.is_unspecified() {
        return Some("unspecified");
    }
    if ip.is_loopback() {
        return Some("loopback");
    }
    if (s[0] & 0xfe00) == 0xfc00 {
        return Some("unique local");
    }
    if (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0 {
        return Some("link-local");
    }
    if (s[0] & 0xff00) == 0xff00 {
        return Some("multicast");
    }
    if (s[0] & 0xe000) != 0x2000 {
        return Some("reserved");
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 || s[0] == 0x3fff && s[1] < 0x1000 {
        return Some("documentation");
    }
    if s[0] == 0x2001 && s[1] < 0x0200 {
        return Some("IETF protocol assignment");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(s: &str) -> Option<&'static str> {
        non_public_reason(s.parse().unwrap_or_else(|_| panic!("{s} is not an address")))
    }

    #[test]
    fn ipv4_table() {
        let table: &[(&str, Option<&str>)] = &[
            ("0.0.0.0", Some("unspecified")),
            ("0.1.2.3", Some("unspecified")),
            ("127.0.0.1", Some("loopback")),
            ("127.255.255.254", Some("loopback")),
            ("10.0.0.1", Some("private")),
            ("172.16.0.1", Some("private")),
            ("172.31.255.255", Some("private")),
            ("192.168.1.1", Some("private")),
            ("169.254.169.254", Some("link-local (includes cloud metadata)")),
            ("169.254.0.1", Some("link-local (includes cloud metadata)")),
            ("100.64.0.1", Some("shared address space")),
            ("100.127.255.255", Some("shared address space")),
            ("192.0.0.8", Some("IETF protocol assignment")),
            ("192.0.2.1", Some("documentation")),
            ("198.51.100.7", Some("documentation")),
            ("203.0.113.9", Some("documentation")),
            ("198.18.0.1", Some("benchmarking")),
            ("198.19.255.255", Some("benchmarking")),
            ("224.0.0.1", Some("multicast")),
            ("239.255.255.250", Some("multicast")),
            ("240.0.0.1", Some("reserved")),
            ("255.255.255.255", Some("reserved")),
            // Public neighbours of the ranges above.
            ("1.1.1.1", None),
            ("8.8.8.8", None),
            ("93.184.215.14", None),
            ("100.63.255.255", None),
            ("100.128.0.0", None),
            ("172.15.255.255", None),
            ("172.32.0.0", None),
            ("198.17.255.255", None),
            ("198.20.0.0", None),
            ("223.255.255.255", None),
        ];
        for (ip, want) in table {
            assert_eq!(reason(ip), *want, "{ip}");
        }
    }

    #[test]
    fn ipv6_table() {
        let table: &[(&str, Option<&str>)] = &[
            ("::", Some("unspecified")),
            ("::1", Some("loopback")),
            ("fc00::1", Some("unique local")),
            ("fd12:3456::1", Some("unique local")),
            ("fe80::1", Some("link-local")),
            ("febf::1", Some("link-local")),
            ("fec0::1", Some("link-local")),
            ("ff02::1", Some("multicast")),
            ("ff0e::1", Some("multicast")),
            ("2001:db8::1", Some("documentation")),
            ("3fff::1", Some("documentation")),
            ("2001::1", Some("IETF protocol assignment")), // Teredo
            ("2001:1ff::1", Some("IETF protocol assignment")),
            ("100::1", Some("reserved")), // discard
            ("4000::1", Some("reserved")),
            ("::2:0:0:1", Some("reserved")),
            // IPv4-mapped: judged as the IPv4 address.
            ("::ffff:127.0.0.1", Some("loopback")),
            ("::ffff:10.0.0.1", Some("private")),
            ("::ffff:169.254.169.254", Some("link-local (includes cloud metadata)")),
            ("::ffff:0.0.0.0", Some("unspecified")),
            ("::ffff:8.8.8.8", None),
            // IPv4-compatible: refused whatever it carries.
            ("::127.0.0.1", Some("loopback")),
            ("::10.0.0.1", Some("private")),
            ("::8.8.8.8", Some("IPv4-compatible")),
            // Translated (SIIT): judged as the IPv4 address.
            ("::ffff:0:127.0.0.1", Some("loopback")),
            ("::ffff:0:192.168.0.1", Some("private")),
            ("::ffff:0:8.8.8.8", None),
            // NAT64, well-known and local-use, and the rest of 64:ff9b::/32.
            ("64:ff9b::7f00:1", Some("loopback")),
            ("64:ff9b::a9fe:a9fe", Some("link-local (includes cloud metadata)")),
            ("64:ff9b::808:808", Some("NAT64")),
            ("64:ff9b:1::808:808", Some("NAT64")),
            ("64:ff9b:1::a00:1", Some("private")),
            ("64:ff9b:2::808:808", Some("reserved")),
            // 6to4: the embedded IPv4 first, then refused anyway.
            ("2002:7f00:1::", Some("loopback")),
            ("2002:a00:1::", Some("private")),
            ("2002:808:808::", Some("6to4")),
            // Public.
            ("2606:4700:4700::1111", None),
            ("2a00:1450:4001::1", None),
            ("2001:200::1", None),
            ("3fff:1000::1", None),
        ];
        for (ip, want) in table {
            assert_eq!(reason(ip), *want, "{ip}");
        }
    }

    #[test]
    fn loopback_forms() {
        for ip in ["127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1"] {
            assert!(is_loopback(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["10.0.0.1", "::", "::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::"] {
            assert!(!is_loopback(ip.parse().unwrap()), "{ip}");
        }
    }

    // --- the union of the two classifiers this one replaced -------------------

    /// `ua_tools::families::web::non_public_reason` before it became a
    /// re-export, kept here verbatim (as a predicate) to prove the union.
    fn legacy_web_refuses(ip: IpAddr) -> bool {
        fn v4(ip: Ipv4Addr) -> bool {
            let o = ip.octets();
            o[0] == 0
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || ip.is_documentation()
                || (o[0] == 198 && (o[1] & 0xFE) == 18)
                || ip.is_multicast()
                || o[0] >= 240
        }
        match ip {
            IpAddr::V4(a) => v4(a),
            IpAddr::V6(a) => {
                if let Some(e) = embedded_v4(a) {
                    return v4(e);
                }
                let s = a.segments();
                a.is_unspecified()
                    || a.is_loopback()
                    || (s[0] & 0xfe00) == 0xfc00
                    || (s[0] & 0xffc0) == 0xfe80
                    || (s[0] & 0xffc0) == 0xfec0
                    || (s[0] & 0xff00) == 0xff00
                    || (s[0] & 0xe000) != 0x2000
                    || (s[0] == 0x2001 && s[1] == 0x0db8)
                    || (s[0] == 0x3fff && s[1] < 0x1000)
                    || (s[0] == 0x2001 && s[1] < 0x0200)
            }
        }
    }

    /// `ua_server::oauth::cimd::is_public_ip` before it became a re-export,
    /// negated, kept here verbatim to prove the union.
    fn legacy_cimd_refuses(ip: IpAddr) -> bool {
        fn public_v4(ip: Ipv4Addr) -> bool {
            let o = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        fn public_v6(ip: Ipv6Addr) -> bool {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return public_v4(v4);
            }
            let s = ip.segments();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x2001 && s[1] == 0)
                || s[0] == 0x2002
                || (s[0] == 0x64 && s[1] == 0xff9b)
                || (s[0] == 0x100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
                || s[..6] == [0, 0, 0, 0, 0, 0])
        }
        !match ip {
            IpAddr::V4(a) => public_v4(a),
            IpAddr::V6(a) => public_v6(a),
        }
    }

    /// A spread of IPv4 addresses: every first octet, each with second
    /// octets at and around the range boundaries used above.
    fn v4_sample() -> Vec<Ipv4Addr> {
        let mut out = Vec::new();
        for a in 0..=255u8 {
            for b in
                [0u8, 1, 2, 15, 16, 17, 18, 19, 20, 31, 32, 51, 63, 64, 100, 127, 128, 168, 169, 254, 255]
            {
                for (c, d) in [(0u8, 0u8), (0, 1), (0, 8), (2, 1), (100, 7), (113, 9), (255, 255)] {
                    out.push(Ipv4Addr::new(a, b, c, d));
                }
            }
        }
        out
    }

    fn v6_sample() -> Vec<Ipv6Addr> {
        let mut out = Vec::new();
        let firsts: [u16; 24] = [
            0, 0x64, 0x100, 0x1fff, 0x2000, 0x2001, 0x2002, 0x2400, 0x2606, 0x3fff, 0x4000, 0x8000, 0xfc00,
            0xfd00, 0xfe80, 0xfebf, 0xfec0, 0xff00, 0xff02, 0xffff, 0x2a00, 0x3ffe, 0x2003, 0x1,
        ];
        let seconds: [u16; 9] = [0, 1, 0xff9b, 0x0db8, 0x1ff, 0x200, 0xfff, 0x1000, 0x4860];
        for v4 in v4_sample().into_iter().step_by(7) {
            let o = v4.octets();
            let (hi, lo) = (u16::from_be_bytes([o[0], o[1]]), u16::from_be_bytes([o[2], o[3]]));
            out.push(v4.to_ipv6_mapped());
            out.push(Ipv6Addr::new(0, 0, 0, 0, 0, 0, hi, lo));
            out.push(Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, hi, lo));
            out.push(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, hi, lo));
            out.push(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, hi, lo));
            out.push(Ipv6Addr::new(0x2002, hi, lo, 0, 0, 0, 0, 1));
        }
        for f in firsts {
            for s in seconds {
                for rest in [[0u16; 6], [0, 0, 0, 0, 0, 1], [1, 2, 3, 4, 5, 6], [0xffff; 6]] {
                    out.push(Ipv6Addr::new(f, s, rest[0], rest[1], rest[2], rest[3], rest[4], rest[5]));
                }
            }
        }
        out
    }

    /// Whether `ip` is in a class where the union is knowingly stricter than
    /// `ua_tools::families::web::non_public_reason` was.
    fn web_stricter_class(ip: IpAddr) -> bool {
        let IpAddr::V6(a) = ip else { return false };
        let s = a.segments();
        s[..6] == [0; 6] || s[0] == 0x2002 || (s[0] == 0x64 && s[1] == 0xff9b)
    }

    #[test]
    fn at_least_as_strict_as_both_replaced_classifiers() {
        let all: Vec<IpAddr> =
            v4_sample().into_iter().map(IpAddr::V4).chain(v6_sample().into_iter().map(IpAddr::V6)).collect();
        assert!(all.len() > 30_000, "sample too small: {}", all.len());
        let mut stricter_than_web = 0;
        for ip in all {
            let refused = non_public_reason(ip).is_some();
            let (web, cimd) = (legacy_web_refuses(ip), legacy_cimd_refuses(ip));
            assert!(refused || !web, "{ip} was refused by the web classifier");
            assert!(refused || !cimd, "{ip} was refused by the CIMD classifier");
            // Nothing outside the union is refused.
            assert_eq!(refused, web || cimd, "{ip} is outside the union");
            if refused && !web {
                assert!(web_stricter_class(ip), "{ip}: stricter than web outside the listed classes");
                stricter_than_web += 1;
            }
        }
        assert!(stricter_than_web > 0);
    }
}
