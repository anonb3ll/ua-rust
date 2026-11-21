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
  address); past the limit the call fails. A hop to another origin follows
  the cross-origin rule below.
- **A body cap on every read path.** A `Response` exposes its body only as
  `body()` (cut at the cap, with a `truncated` flag), `bytes()` and
  `json()` (both fail past the cap, before reading when `Content-Length`
  already says so).
- **A connect-time address check** (below).
- **Headers stay with their origin.** `Request::secret_header` binds a
  header to the origin (scheme, host, port) of the request URL; it is
  attached only to a hop with that origin. Plain headers do the same,
  except the short cross-origin list below. `Request::header` also refuses
  names that look like credentials (`authorization`, `proxy-authorization`,
  `cookie`, and any name containing `token`, `secret`, `api-key`, `apikey`
  or `password`); that word list is an extra refusal, and cross-origin
  safety does not depend on it.
- **Timeouts.** Connect (which also bounds the DNS lookup), per request
  including the body, and a deadline for the whole call that also bounds
  body reads.

### The cross-origin rule

No shipped policy allows redirects; these rules are in place for the first
one that does. A request's headers and body belong to the origin of the
URL it was built for. On each redirect hop:

- **A hop from https to http is refused**, unless the policy sets
  `allow_scheme_downgrade`. No shipped policy does.
- **301, 302 and 303** turn the request into a `GET` without a body or a
  `Content-Type`, as browsers do. The hop may then go to another origin.
- **307 and 308** must repeat the method and the body. A 307 or 308 that
  would send a body to another origin is refused, not followed. Dropping
  the body would turn the request into a different request than the
  status allows, and resending it would hand the payload to a host it was
  not written for; refusing is the only safe answer, and the caller sees a
  `Redirect` error. A 307 or 308 within the origin, or one without a body,
  is followed.
- **Headers on a hop to another origin** are `Accept` and
  `Accept-Language` only (and the client's own `User-Agent`). Every other
  header, plain or secret, whatever its name, is not sent there. A later
  hop back to the request's own origin carries them again.

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
  response is returned. A test gives the resolver a looser rule than the
  policy, so a loopback answer passes it and the connection is made, and
  shows the peer check refusing it; another removes the peer address.

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
  verdict (`bool`, `Option`, `Result`) and hold hand-written range logic (a
  standard-library range test such as `is_private`, or `octets`,
  `segments`, `to_ipv4_mapped`). A function that only calls
  `ua_ingress::addr` is not counted;
- `inline_address_check`: the same range logic written outside such a
  function, on an address or a socket address (`addr.ip().is_loopback()`).
  Calls of `ua_ingress::addr` are not counted;
- `direct_dial`: connections dialled by hand: `TcpStream::connect…`,
  `TcpSocket`, rustls or native TLS connectors, `tokio-tungstenite` client
  handshakes, hyper's `HttpConnector`. Unix-domain sockets are local and
  not counted;
- `delivery_table`: `CREATE TABLE` of an inbound delivery, replay or dedupe
  record: a table whose name contains `deliver`, `seen`, `replay`,
  `dedup`, `webhook` or `envelope`, or which has a column named
  `delivery_id`, `envelope_id`, `event_id`, `trigger_id` or `request_sha`.
  Checked against every table in the tree, the rule matches the four
  delivery tables and nothing else (`idempotency_keys` and
  `dispatch_receipts` match no mark). A table that records deliveries
  under a name and columns that carry none of these marks is not caught.

Each count must equal the checked-in baseline. Above it, use the crate;
below it, lower the baseline in the same change. It also checks that each
category is caught, and that the lookalikes above are not. Baselines:

| Crate | Category | Count | Sites |
|---|---|---|---|
| `ua-server` | `client_builder` | 1 | `oauth/cimd.rs` |
| `ua-server` | `direct_dial` | 3 | `slack_socket.rs::connect`: `TcpStream::connect`, the rustls `TlsConnector`, the WebSocket client handshake |
| `ua-server` | `inline_address_check` | 5 | loopback checks in `oauth/register.rs` (3) and `login.rs` (2) |
| `ua-cli` | `inline_address_check` | 1 | `ops/doctor.rs`, the bind address |
| `ua-tools` | `client_builder` | 5 | `web`, `github/client`, `mcp/gateway`, `notify`, `vault/obsidian` |
| `ua-tools` | `address_classifier` | 4 | `mcp/scope.rs` `classify`, `classify_v4`; `relay/gates.rs` `v4_kind`, `v6_kind` |
| `ua-tools` | `inline_address_check` | 11 | loopback URL hosts in `slack.rs`, `zulip.rs`, `github/client.rs`, `harness_config/policy.rs` (2 each); `observability.rs` (2); `vault/obsidian.rs` (1) |
| `ua-tools` | `delivery_table` | 4 | `github_deliveries`, `github_delivery_bodies`, `slack_seen_signatures`, `slack_seen_deliveries` |

`web::vet_ip` was counted as a classifier when the crate landed; it only
calls `ua_ingress::addr`, so it no longer counts.

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
