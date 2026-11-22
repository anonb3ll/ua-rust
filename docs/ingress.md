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
| `Class::Public` | `non_public_reason`, `is_public` | `ua_tools::families::web::non_public_reason` (a re-export): the web tools, Zulip, the relay's GitHub client, GitHub REST, Slack replies and Socket Mode; outbound policies with `Addresses::Public`, `PublicOrLoopback` or `OperatorConfigured` |
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

`addr::is_cloud_metadata` names the well-known cloud instance-metadata
addresses that are not link-local: `100.100.100.200` (in the shared address
space), `fd00:ec2::254` and `fd20:ce::254` (in unique local space), and any
IPv6 form that carries the IPv4 one. Both classes refuse them anyway; every
outbound address rule (`Addresses::check`) refuses them first, with the
reason `cloud metadata`, before any relaxation applies. The common
`169.254.169.254` is link-local and refused as such.

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
`GlobalUnicastOnly`, `PublicOrLoopback`, `OperatorConfigured`, or
`LoopbackOnly`), how many redirects are followed, whether TLS certificates
are verified, the response body
cap, and three timeouts (connect, one request with its body, the whole
call). Named policies are constants in `ua_ingress::policy`;
`Outbound::named` and `policy::lookup` refuse any other name, and a policy
with an empty host list, a zero or unbounded cap or timeout, more than
ten redirects, an operator-configured class that follows redirects, or
unverified certificates on anything but a loopback-only policy without
redirects builds no client.

`Addresses::OperatorConfigured` is for a destination the operator set in
configuration, never for a URL a caller supplies: the public class plus
loopback and private networks (`addr::is_private_network`: RFC 1918, the
shared address space `100.64.0.0/10` that carrier-grade NAT and mesh VPNs
use, unique local `fc00::/7`, and the IPv4-mapped form of the IPv4 ranges).
It still refuses the cloud-metadata addresses above (including the ones
inside the shared and unique local ranges it otherwise admits), unspecified,
link-local, multicast, broadcast and reserved, documentation, benchmarking
and IETF protocol addresses, and every IPv6 form of a private IPv4 address
other than the mapped one. Only `Addresses::check` decides: the class's
base range table is private to it, so no caller can judge an address by a
looser class than the rule. A policy with this class follows no redirect, since a redirect
target is the server's choice, not the operator's. Only `ua_ingress::policy`
names the class, and each policy that uses it is named by one consumer
file only (`tests/ingress_guard.rs`, `relaxed_policies_stay_with_their_one_consumer`).

`Policy::accept_invalid_certs` turns certificate verification off (any
certificate, any name). Only `obsidian.local_rest` sets it: the Obsidian
Local REST API plugin serves https on this host with a self-signed
certificate. `validate` refuses it unless the class is `LoopbackOnly` and no
redirect is followed, the loopback test hook never widens a `LoopbackOnly`
class, and the same ratchet test keeps the field's name out of every other
crate.

A limit that predates this policy: the client cannot tell the plugin from
any other local process. Whatever answers on the configured loopback port,
over plain http or with any certificate, receives the API key. Run the hub
only where no untrusted local process can bind that port.

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
- **TLS certificates are verified**, except under the one loopback-only
  policy above.

### The cross-origin rule

`web.page` and `web.search` follow up to five redirects; every other
shipped policy follows none. A request's headers and body belong to the
origin of the URL it was built for. On each redirect hop:

- **A hop from https to http is refused**, unless the policy sets
  `allow_scheme_downgrade`. Only `web.page` does: `web_fetch` sends no
  credentials and may fetch plain http pages directly, and the scheme is
  part of the origin, so the downgraded hop carries none of the caller's
  headers anyway.
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
  header, plain or secret, whatever its name, is not sent there.
- **Once a chain has left the request's origin, it stays stripped.** A
  later hop back to that origin carries only the same short list: the
  caller's headers and secret headers are dropped for the rest of the
  chain. Otherwise the intermediate origin could choose which path on the
  original origin receives them. The return hop is followed rather than
  refused, so a round trip through another host still reaches its page;
  it simply arrives without credentials.

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

## Inbound deliveries

`ua_ingress::inbound` is the one table that remembers what other systems
sent: `inbound_deliveries`, keyed by `(org_id, source, kind,
delivery_key)`. `source` names the sender (`github`), `kind` what the key is
(`delivery_id`, `body_sha256`). Each row has a state, `received_at`,
`updated_at` and `expires_at` (Unix seconds), the claim it was taken on
under, an optional identity, and a free-text `detail`.

A claim is the process's prefix (its id and start time) and a number of its
own: every `record` that takes a delivery on hands out a new one. A claim
whose prefix is not this process's belongs to a process that stopped; a
claim with this prefix but another number is another handler in this
process (a redelivery that took the delivery over).

| State | Meaning | A repeat is |
|---|---|---|
| `seen` | Recorded, not taken on | a duplicate |
| `accepted` | Taken on under a claim | a duplicate while the claim is live (this process's prefix, inside the in-flight bound); stale once the claim belongs to a stopped process or the bound passes |
| `finished` | Handled | a duplicate until the row expires |
| `abandoned` | Was `accepted`, claim gone or past the bound; outcome unknown | stale |

What a stale repeat means is the caller's rule (`Stale`): `Redeliver` takes
it on again (for idempotent effects), `Duplicate` refuses it.

A caller, inside one write transaction that also holds its own records (its
ledger event, for one):

1. `sweep(org, source, now, rules)`: within one organization, abandon `accepted` rows whose claim is gone
   or past `abandon_after_s`, delete expired rows (those whose `expires_at`
   is before `now`; never an `accepted` one),
   and keep at most `max_per_kind` rows per organization and kind (never
   dropping an `accepted` one). Stuck rows are marked `abandoned` rather
   than released: the sweep cannot know whether their effects happened, and
   releasing one would let a non-idempotent delivery run again unnoticed.
   They are returned, so a caller can record them.
2. `record(delivery, now, rules, detail)`: `First { claim }`,
   `Duplicate { state }` or `Redelivered { was, claim }`.
3. `accept(delivery, claim, now, identity)` when it takes the delivery on.

Then, after handling, in a second transaction: `finish(delivery, claim,
now)` when it is done, or `release(delivery, claim)` when a retry should
be processed as a first sight. Both act only on a row that still carries
the caller's claim and return `Settled` or `NotMine { state }`; on
`NotMine` nothing changed, and the caller logs it:

| The row is | `finish` with the caller's claim | `release` with the caller's claim | either with another claim |
|---|---|---|---|
| `accepted` under the caller's claim | `Settled`: `finished` | `Settled`: deleted | `NotMine` |
| `abandoned`, still the caller's claim | `Settled`: `finished` | `NotMine`: stays `abandoned` | `NotMine` |
| taken over by a redelivery (new claim) | `NotMine` | `NotMine` | (the new owner settles it) |
| `finished` | `NotMine` | `NotMine` | `NotMine` |
| `seen`, or gone | `NotMine` | `NotMine` | `NotMine` |

A slow handler therefore never undoes a newer owner's record: once a
redelivery has taken the delivery over, the original's `finish` or
`release` changes nothing, and the newer owner's settlement stands. An
`abandoned` row whose original handler does finish is still that handler's
(nobody took it over, since a takeover changes the claim) and its effects
are done, so `finish` marks it `finished` and a later copy is a duplicate
instead of running again. `release` leaves an `abandoned` row alone: the
sweep has already reported its outcome as unknown, and a source that
redelivers stale rows processes the next copy anyway.

### Limits

- **One `ua serve` per database.** Only `ua serve` hosts the routes that
  record inbound deliveries (the GitHub webhook, the Slack routes and Slack
  Socket Mode). Two of them on one database would each see the other's
  claims as a stopped process's: each treats the other's in-flight
  deliveries as stale, so with `Stale::Redeliver` a delivery can be handled
  by both, and the sweep of either abandons the other's work in progress.
  This is enforced: `ua serve` holds `<db>.serve.lock` exclusively for its
  whole life and a second `ua serve` on the same database (same file, links
  resolved) is refused before it opens the database or binds a port
  (`docs/operations.md`, section 5). What remains: the lock is advisory and
  taken by the `ua` command, so a program that embeds `ua-server` and calls
  `serve_http` without taking `ua_import::ServeLock` is not covered, and on
  a platform without `flock` (not Unix) nothing is locked. Two hosts that
  share one database file over a network file system are covered only if
  that file system honours `flock` across hosts; do not do that.
- **The clock.** Staleness is judged against the wall clock. A forward
  step past the in-flight bound (15 minutes for GitHub) makes this
  process's own in-flight deliveries stale, with the same effect as a
  second process for the deliveries in flight at that moment. A backward
  step only makes rows look younger, so they stay duplicates longer.
- **Downgrading.** Nothing refuses an older binary on a database that has
  these parts. Recorded parts a build does not know are ignored when the
  store opens, and the rollback fence (`docs/organization.md`) refuses only
  a ledger whose newest row has a `hash_v` above the build's, which these
  parts do not write. `ua doctor` and `system_doctor` report the parts as
  from another build, and `ua restore` refuses them without
  `--allow-newer`, but `ua serve` starts. An older binary reads only the old
  GitHub tables, which stopped being written at the cut-over, so a downgrade
  reopens a replay window: a copy of any GitHub delivery handled since the
  upgrade (within its 30-day retention, and inside the payload-timestamp
  window) is accepted again. The same holds for Slack, where it matters
  more: an older binary reads only the old Slack tables, so for about a day
  (the delivery-id retention) a Slack retry of a command the newer build
  already ran is run again, and Slack commands are not idempotent. Do not
  downgrade past this change while either endpoint takes traffic.

The table is a tenant table: `org_id NOT NULL` from its first part
(`ingress.inbound.v1`) and the generated triggers from
`organization.v1.ingress`. Both are registered by `ua_tools::schema_parts`
after the family parts.

### GitHub webhook

The webhook records the delivery id and the body hash as two kinds, with
30 days of retention, at most 20 000 of each, a 15-minute in-flight bound
and `Stale::Redeliver`:

| Case | Before | Now |
|---|---|---|
| First delivery | recorded, handled, 200 | the same |
| The same delivery id again | 409 `replayed` | the same |
| The same body under a new id | 409 `replayed`; the new id is not kept | the same |
| A redelivery after the hub stopped between recording and handling | 409 `replayed`: the event was lost | handled, 200; ledgered with `"redelivered": true` |
| A redelivery after handling failed with an internal error | handled (the records were deleted) | handled (the records are released) |
| A redelivery after handling refused the payload (400) | 409 `replayed` | the same (the records are finished) |
| A second copy while the first is still being handled here | 409 `replayed` | the same, until the 15-minute bound |
| A copy after a slow original was abandoned and then finished | 409 `replayed` | the same (the original's `finish` still counts) |
| A slow original that fails after a redelivery took over | the original deleted the newer record | the original's `release` is `NotMine`; the newer record stands |

When the sweep abandons GitHub deliveries it appends one
`agent.github.webhook.abandoned` event per sweep (actor `hub-github`), under
the organization it swept (each sweep covers one, so every abandoned row is
in the event's organization; the webhook serves the default organization
today), with
`count`, `kinds` (`delivery_id` and `body_sha256` counts), `delivery_ids` (at
most 50) and `delivery_ids_truncated`; never a body or a body hash. Each is
a delivery that may never have been handled.

`github.inbound.v1.copy` (a procedure part) copies the rows of the old
`github_deliveries` and `github_delivery_bodies` into the table as
`finished`, keeping their receipt times, so a hub upgraded between two
copies of one delivery still refuses the second. A row that was in the
crash window at the upgrade is copied as `finished` too: its redelivery is
refused, as it was before. The old tables stay in the schema, unread and
unwritten, and are dropped one release later. The importer does not map
them from the Python hub (they are reported as unmapped), and it does not
map `inbound_deliveries` either.

### Slack

Slack is the second consumer, under source `slack` in the default
organization:

| Kind | Key | Kept | Written |
|---|---|---|---|
| `request_sha` | SHA-256 of the signed base `v0:{timestamp}:{body}` (HTTP) or of `socket-envelope:{envelope_id}` (Socket Mode) | 600 s | `seen`, at admission, before the identity is looked up |
| `trigger`, `event` | the slash command's `trigger_id` or the event's `event_id` | a day | `seen` then `accepted` with the mapped identity, in the admission transaction; `finished` when the outcome is ledgered |

Slack commands are not idempotent (a slash command or an approval must
never run twice), so Slack uses `Stale::Duplicate`: a delivery taken on and
never finished is refused like any other repeat ("Already received."),
never taken on again. That is the opposite of GitHub, whose effects are
idempotent and whose redelivery is how a lost event is recovered. What
happened to such a Slack delivery is reported instead: at startup, before
the routes take traffic, `abandon_all_accepted` marks every `accepted` row
`abandoned` (all of them belong to a process that has stopped), and the
Slack family ledgers each as `agent.slack.request.abandoned` with
`outcome: "unknown"`, as it did before. If the outcome does arrive later
(a slow handler), it is still ledgered, and the row is finished when it
still carries the claim it was accepted under. Two cases differ, and in
neither does anything run twice: a row the upgrade copy carried over has no
claim, so a late outcome is ledgered and the row stays `abandoned`; and if
a settled row has expired and the same id was recorded again (a day or more
later), a very late outcome for the first settles the newer row.

`record_executed` takes no claim: Slack never takes a delivery over, so an
`accepted` row keeps the claim it was accepted under, and the handler
settles it with that claim (`claim_of`).

Every response is as before: a byte replay is 401 `replayed` on the HTTP
routes (a redelivered envelope is acknowledged again and runs nothing), a
duplicate delivery is answered "Already received.", and every refusal and
reply text is unchanged.

`slack.inbound.v1.copy` carries the rows of `slack_seen_signatures` (as
`seen`) and `slack_seen_deliveries` (each in its own state: `seen`,
`accepted`, `finished` or `abandoned`, with its identity) into the table,
keeping `seen_at` as the receipt time and each kind's retention. A row the
old hub had `accepted` stays `accepted` with no claim, so the next startup
sweep reports it as abandoned, exactly as before; nothing becomes
`finished`. The old tables stay, unread and unwritten, until a later
release drops them; the ratchet's `delivery_table` count stays 4 meanwhile.

The Socket Mode connector (`slack_socket.rs::connect`) has not moved into
this crate: it checks resolved addresses only for `wss`, and plain `ws` is
the tests' loopback hook, so moving it without changing behaviour needs its
own slice. It stays counted as `direct_dial` 3.

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
| `ua-tools` | `client_builder` | 1 | `mcp/gateway` (`web::http_client`, the GitHub REST client, the Obsidian client and the notify client were removed when their consumers moved onto `Outbound`) |
| `ua-tools` | `address_classifier` | 4 | `mcp/scope.rs` `classify`, `classify_v4`; `relay/gates.rs` `v4_kind`, `v6_kind` |
| `ua-tools` | `inline_address_check` | 11 | loopback URL hosts in `slack.rs`, `zulip.rs`, `github/client.rs`, `harness_config/policy.rs` (2 each); `observability.rs` (2); `vault/obsidian.rs` (1) |
| `ua-tools` | `delivery_table` | 4 | `github_deliveries`, `github_delivery_bodies` (still created, no longer read or written; dropped one release later), `slack_seen_signatures`, `slack_seen_deliveries`. `inbound_deliveries` is in `ua-ingress` and not counted |

`web::vet_ip` was counted as a classifier when the crate landed; it only
calls `ua_ingress::addr`, so it no longer counts.

## Consumers

| Consumer | Policy |
|---|---|
| Slack slash-command replies (`slack::post_reply`) | `slack.response_url`: https to `hooks.slack.com` on the default port, public addresses, no redirects, 64 KiB cap, 10 s for everything |
| Slack Socket Mode `apps.connections.open` (`slack::open_socket_url`) | `slack.web_api`: https to `slack.com` on the default port, public addresses, no redirects, 16 KiB cap (refused past it), 15 s |
| `web_fetch` | `web.page`: http or https, any host and port, public addresses, 5 redirects with https to http followed, 2 MB cap (cut), 20 s a request, 45 s in all |
| `web_search` (DuckDuckGo, Brave, Tavily) | `web.search`: as `web.page`, but a redirect from https to http is refused |
| Zulip (`zulip_send_message`, `zulip_fetch_messages`) | `zulip.api`: https to the configured site, public addresses, no redirects, 4 MiB cap (each call reads less), 20 s |
| The relay's GitHub comments (`relay/github.rs`) | `relay.github`: https to `relay_github_api_url`, public addresses, no redirects, 256 KiB cap (cut), 20 s |
| GitHub REST (`github/client.rs`: CI checks, polling, merged pull requests), public API | `github.rest`: https to `api.github.com`, public addresses, no redirects, 8 MiB cap (refused past it), 10 s to connect, 20 s for the call; one client per API base, reused |
| GitHub REST against a GHES root in `github_api_url` | `github.enterprise`: as `github.rest` for any host, with `OperatorConfigured` addresses |
| The Obsidian Local REST API (`vault/obsidian.rs`: `obsidian_status`, `_open`, `_active_note`, `_search`, `_append`) | `obsidian.local_rest`: http or https to `obsidian_api_url` (which must name `localhost` or a loopback address), `LoopbackOnly` addresses, certificates not verified, no redirects, 16 MiB cap (refused past it), 20 s for everything |
| Notification webhook (`notify.rs`: `notify`, `batch_notify`, `flush_digest`, hub events such as `review_ready`) | `notify.webhook`: http or https to `notify_webhook_url`, any host and port, `OperatorConfigured` addresses, no redirects, the body never read (64 KiB cap), 120 s, with each attempt bounded by the caller's timeout (1 to 120 s, default 60; 20 for hub events) |

The loopback test hooks (`fetch_allow_loopback`, `slack_socket_test_api`,
neither settable from TOML or the environment) apply
`Policy::loopback_test_hook`: loopback admitted besides public addresses,
plain http, any host and port; everything else unchanged. A policy whose
class already admits loopback keeps its class: `OperatorConfigured` stays
operator-configured, and `LoopbackOnly` (the Obsidian policy) stays
loopback-only, so the hook never lets an unverified-certificate policy
reach a public address.

## Planned slices

1. Move the remaining HTTP client consumers onto policies (the MCP
   gateway and the client ID metadata fetch; the web, Zulip, relay, Slack
   Web API, GitHub REST, Obsidian and notify consumers have moved).
2. One inbound-delivery table, with a cut-over for GitHub deliveries
   (done: [Inbound deliveries](#inbound-deliveries)).
3. Slack's signed HTTP routes and Socket Mode onto it (the replay keys and
   delivery ids are done: [Slack](#slack); the Socket Mode connector is
   still to move).
4. GitHub REST and the MCP gateway.
5. Retire the old delivery tables one release later.
