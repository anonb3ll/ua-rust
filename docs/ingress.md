# Ingress and outbound calls

`crates/ua-ingress` is the hub's boundary to the outside world. Code that
classifies an address, calls another system over HTTP, or (in later slices)
accepts a delivery from one belongs here, so each guard is written once
and reviewed once.

The crate depends on `ua-core` and third-party crates only. `ua-tools` and
`ua-server` may depend on it; nothing below them may
(`crates/ua-ingress/tests/dependencies.rs`).

## The address classifier

`ua_ingress::addr` says whether an IP address is in an address class and,
if not, why. It is the only implementation, with two named classes over the
same range tables:

| Class | Functions | Used by |
|---|---|---|
| `Class::Public` | `non_public_reason`, `is_public` | `ua_tools::families::web::non_public_reason` (a re-export): the web tools, Zulip, the relay's GitHub client, GitHub REST, Slack replies and Socket Mode; outbound policies with `Addresses::Public` or `PublicOrLoopback` |
| `Class::GlobalUnicastOnly` | `non_global_unicast_reason`, `is_global_unicast` | `ua_server::oauth::cimd::is_public_ip` (a re-export); outbound policies with `Addresses::GlobalUnicastOnly` |

Refused in both classes:

- IPv4: `0.0.0.0/8`, loopback, RFC 1918, link-local (cloud metadata),
  `100.64.0.0/10`, `192.0.0.0/24`, the documentation ranges,
  `198.18.0.0/15`, multicast and `240.0.0.0/4` (broadcast included).
- IPv6: unspecified, loopback, `fc00::/7`, `fe80::/10`, `fec0::/10`,
  multicast, everything outside `2000::/3` (the rest of `64:ff9b::/32`
  included), `2001:db8::/32`, `3fff::/20` and `2001::/23`.
- IPv6 forms that carry an IPv4 address (mapped `::ffff:a.b.c.d`,
  translated `::ffff:0:a.b.c.d`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`,
  6to4 `2002::/16`) when that IPv4 address is refused.
- The IPv4-compatible form `::a.b.c.d`, whatever it carries. RFC 4291
  deprecated it, it lies in `::/8`, which is not routed on the internet,
  and no current transition mechanism produces it, so no reachable
  destination has such an address.

The classes differ only on NAT64 and 6to4 forms of a public IPv4 address:
`Public` judges them by that address and admits them (on an IPv6-only
network behind DNS64, every IPv4-only site resolves to a NAT64 address);
`GlobalUnicastOnly` refuses them.

Unit tests compare both classes with verbatim copies of the two classifiers
they replaced, over about 70,000 addresses: `Public` refuses what the old
web classifier refused plus only the IPv4-compatible form of a public
address; `GlobalUnicastOnly` refuses exactly what either old classifier
refused.

## Outbound: the guarded client

`ua_ingress::Outbound` is built from a `Policy`, one per destination class.
A policy fixes the schemes, the hosts (an exact list, or any), whether a
URL may name a port, the address class a connection may reach (`Public`,
`GlobalUnicastOnly`, or `PublicOrLoopback`), how many redirects are followed, the response body
cap, and three timeouts (connect, one request with its body, the whole
call). Named policies are constants in `ua_ingress::policy`;
`Outbound::named` and `policy::lookup` refuse any other name, and a policy
with an empty host list, a zero or unbounded cap or timeout, or more than
ten redirects builds no client.

Each property is enforced in the crate and has a test there:

- **No proxy.** `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and the system
  proxy settings are ignored (`tests/no_proxy.rs` shows a default client
  using them and `Outbound` not).
- **No redirects unless the policy allows them.** With `max_redirects = 0`
  a redirect response is returned as it is. Otherwise each hop is followed
  by hand and checked against the policy again (scheme, host, port,
  address); past the limit the call fails.
- **A body cap on every read path.** A `Response` exposes its body only as
  `body()` (cut at the cap, with a `truncated` flag), `bytes()` and
  `json()` (both fail past the cap, before reading when `Content-Length`
  already says so).
- **A connect-time address check** (below).
- **Secret headers stay with their origin.** `Request::secret_header` binds
  a header to the origin (scheme, host, port) of the request URL; it is
  attached only to a hop with that origin, so a redirect elsewhere never
  carries it. `Request::header` refuses names that look like credentials
  (`authorization`, `proxy-authorization`, `cookie`, and any name
  containing `token`, `secret`, `api-key`, `apikey` or `password`).
- **Timeouts.** Connect (which also bounds the DNS lookup), per request
  including the body, and a deadline for the whole call that also bounds
  body reads.

Errors never include the request URL's path or query or any header value.
`OutboundError` converts into `UaError` (`ssrf_blocked` for an address
refusal, `outbound_refused` for a URL outside the policy).

### What the connect-time check guarantees

The mechanism, with `reqwest` 0.13 (`hyper-util` 0.1 underneath): the client
is built with `ClientBuilder::dns_resolver` set to a resolver that looks the
name up, classifies every returned address against the policy, and fails
the lookup if any one is outside the class. `reqwest`'s connector dials only
the addresses the resolver returned. Proxies are off, so no proxy dials on
the client's behalf.

Guaranteed:

- For a DNS host, the TCP connection goes to an address that was classified
  by the lookup made for that connection, not by an earlier one. A DNS
  answer that changes between a caller's own check and the connection
  cannot slip through, and an answer that mixes good and bad addresses is
  refused whole.
- For an IP-literal host, `hyper-util` skips the resolver, so
  `Policy::check_url` classifies the literal before every hop. A host list
  (`Hosts::Exactly`) refuses IP literals outright.
- After the response head arrives, the peer address of the connection that
  carried it (`Response::remote_addr`, read from the socket) is checked
  again. If it is missing or outside the class, the call fails and no
  response is returned.

Not guaranteed:

- The peer check runs after the request was sent. It stops the caller from
  using the answer; it does not unsend the request.
- The check judges the IP address, not the network path. Something on the
  network that forwards a public address to an internal host is not seen.
- A pooled keep-alive connection was checked when it was opened and is not
  looked up again on reuse.
- Code that builds its own `reqwest` client gets none of this. That is what
  the ratchet below tracks.

## The ratchet

`crates/ua-ingress/tests/ingress_guard.rs` scans the non-test source of
every workspace crate except `ua-ingress` and counts, per crate:

- `client_builder`: `reqwest` client builder sites;
- `address_classifier`: functions that take an IP address, return a
  verdict (`bool`, `Option`, `Result`) and test address ranges;
- `delivery_table`: `CREATE TABLE` of an inbound duplicate-delivery table
  (`github_deliveries`, `github_delivery_bodies`, `slack_seen_signatures`,
  `slack_seen_deliveries`).

Each count must equal the checked-in baseline. Above it, use the crate;
below it, lower the baseline in the same change. It also checks that each
category is caught. The baseline when the crate landed: `client_builder` 5
in `ua-tools` and 1 in `ua-server`, `address_classifier` 5 in `ua-tools`,
`delivery_table` 4 in `ua-tools`.

## Consumers

| Consumer | Policy |
|---|---|
| Slack slash-command replies (`slack::post_reply`) | `slack.response_url`: https to `hooks.slack.com` on the default port, public addresses, no redirects, 64 KiB cap, 10 s for everything |

## Planned slices

1. Move the remaining HTTP client consumers onto policies.
2. One inbound-delivery table, with a cut-over for GitHub deliveries.
3. Slack's signed HTTP routes and Socket Mode onto it.
4. GitHub REST and the MCP gateway.
5. Retire the old delivery tables one release later.
