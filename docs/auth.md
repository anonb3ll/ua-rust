# Authentication

The hub accepts five kinds of credential. Every credential the hub mints is
stored only as a SHA-256 digest, and every comparison is constant time.

| Credential | Who uses it | Accepted on | Stored in |
|---|---|---|---|
| Static bearer token (`agent_tokens` setting) | local agents | `/mcp`, `/api` | configuration |
| Managed bearer token | agents | `/mcp`, `/api` | `agent_tokens` (digest) |
| OAuth access token (`uao_…`) | remote MCP clients | `/mcp`; also `/api` when issued for the whole hub | `oauth_tokens` (digest) |
| Browser session cookie (`ua_session`) | humans in the Control Center | `/ui`, `/api` only, **never `/mcp`** | `ui_sessions` (digest) |
| Session credential (`uas_…`) | the ACP session a node runs for one claimed item | `/mcp`, `/api/tools`, `/api/whoami` only | `session_credentials` (digest) |

The auth middleware (`crates/ua-server/src/auth.rs`) checks a `uas_` bearer
only as a session credential (below). It tries any other bearer token
first, then (for `/ui` and `/api` only) the session cookie. With
`enforce_auth` on, a request with neither gets a 401 (a `GET /ui/...` is
redirected to `/login?next=...` instead). With `enforce_auth` off, a request
with no credential runs as the local anonymous identity, as stdio does.

A 401 carries an RFC 9728 challenge when OAuth is on:

```
WWW-Authenticate: Bearer realm="ua", resource_metadata="https://hub.example.com/.well-known/oauth-protected-resource/mcp", scope="mcp", error="invalid_token"
```

## Settings

All settings are in `config.toml` or `UA_*` environment variables. The
defaults are safe: OAuth is off, cookies are `Secure`.

| Setting | Default | Meaning |
|---|---|---|
| `public_url` | `http://<bind>` | The hub's public base URL. OAuth issuer, passkey origin, base of login links. Set it, e.g. `https://hub.example.com`. |
| `oauth_enabled` | `false` | Serve the authorization server and accept OAuth access tokens. |
| `oauth_dcr_enabled` | `true` | Accept RFC 7591 dynamic client registration (only while OAuth is on). |
| `oauth_dcr_unused_ttl_hours` | `24` | A registered client that never received a grant is pruned after this many hours (checked on each registration and when `ua serve` starts). |
| `oauth_dcr_rate_per_hour` | `20` | Registrations allowed per remote address per hour. Behind a loopback reverse proxy the last `X-Forwarded-For` address counts. |
| `oauth_cimd_enabled` | `false` | Accept URL client ids (Client ID Metadata Documents). The hub then fetches public HTTPS URLs on behalf of unauthenticated callers. |
| `oauth_cimd_allow` | empty | Hosts whose metadata documents may be fetched; `.example.com` admits subdomains. Empty admits any public host. |
| `oauth_identities` | `remote-agent` | Identities a human may bind a grant to on the consent page. Human identities are always refused. |
| `oauth_profile` | `public` | Profile given to each `oauth_identities` label that has no `profiles` entry. |
| `oauth_access_ttl_secs` | `3600` | Access token lifetime (clamped to 60 s .. 30 days). |
| `oauth_refresh_ttl_days` | `30` | Refresh token lifetime (clamped to 1 .. 365 days). |
| `oauth_client_credentials` | none | Confidential clients for `client_credentials`: `client_id\|secret\|identity` entries separated by commas or newlines. Secret; never printed. A client id listed twice is dropped. |
| `ui_cookie_secure` | `true` | Send the session cookie with `Secure`. Leave it on: browsers treat `http://localhost` and loopback addresses as secure contexts and keep `Secure` cookies there. Turning it off does not make plain `http://` to another host safe; use HTTPS instead (see "Remote access"). |
| `ui_session_ttl_hours` | `12` | Browser session lifetime. |
| `login_link_ttl_secs` | `600` | Lifetime of a `ua login-link` URL. |
| `webauthn_rp_id` | host of `public_url` | WebAuthn relying-party id. |

`allowed_hosts` (default `localhost`, `127.0.0.1`, `::1`) lists the `Host`
headers `/mcp`, `/api` and `/ui` answer, as protection against DNS
rebinding. The host of `public_url` is always allowed as well, so a hub
reached only through its public name needs no entry. Add every other name
the hub is reached by, for example:

```toml
public_url = "https://hub.example.com"
allowed_hosts = ["localhost", "127.0.0.1", "::1", "hub.lan.example.com"]
```

A refused host is logged once at warn level (`refused a request for a host
outside allowed_hosts and public_url`), so a misconfigured name shows up in
the log instead of only as a 403 in the browser.

## Remote access

Browser sign-in needs a secure context. Browsers drop `Secure` cookies on
plain `http://` to any host other than localhost or a loopback address, and
WebAuthn (passkeys) refuses to run there. On such an origin a login link or
passkey appears to work and then bounces back to `/login`. `ua serve` warns
at startup when the effective public origin (`public_url`, else
`http://<bind>`) is plain `http://` on a non-loopback host while the session
cookie is `Secure` or human identities are configured. It warns rather than
refuses, because bearer-token clients on `/mcp` and `/api` keep working over
plain HTTP on a trusted network.

For remote use, keep `bind` on loopback and put TLS in front:

- **A private-network TLS terminator** such as `tailscale serve`: HTTPS
  with a certificate for the machine's private-network name, reachable only
  from that network. Do not use Tailscale Funnel, which publishes the hub to
  the whole internet.

  ```
  tailscale serve --bg 8765
  ```

  then set `public_url` to the https:// address it serves (the machine's
  private-network name). Its host is allowed automatically.
- Any other TLS-terminating reverse proxy (Caddy, nginx, ...) with the same
  `public_url` setting.

## OAuth 2.1 authorization server

Code: `crates/ua-server/src/oauth/`. It follows the MCP authorization spec
(revision 2026-07-28).

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-protected-resource/mcp` | RFC 9728 metadata for the MCP endpoint (`resource` = `<public_url>/mcp`). |
| `GET /.well-known/oauth-protected-resource` | Metadata for the whole hub (`resource` = `<public_url>`). |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata. |
| `GET /oauth/authorize` | Authorization request; renders the consent page for a signed-in human. |
| `POST /oauth/authorize` | The consent decision (form, CSRF-protected). |
| `POST /oauth/token` | `authorization_code`, `refresh_token`, `client_credentials`. |
| `POST /oauth/revoke` | RFC 7009 revocation. |
| `POST /oauth/register` | RFC 7591 dynamic registration (if `oauth_dcr_enabled`). |

Every endpoint answers 404 while `oauth_enabled` is off.

Rules the server enforces:

- **PKCE S256 only.** `plain` and missing challenges are refused.
- **Exact redirect URIs.** A loopback `http` redirect may use any port
  (native apps). An unregistered redirect URI gets an error page, never a
  redirect.
- **`iss` on every authorization response** (RFC 9207), success or error.
- **Bounded registration.** `/oauth/register` is unauthenticated, so a
  client that never receives a grant is pruned after
  `oauth_dcr_unused_ttl_hours`, at most 1000 such clients are kept (a new
  registration evicts the oldest instead of failing), only clients holding a
  grant count against the 10 000-client cap, and each remote address may
  register `oauth_dcr_rate_per_hour` clients per hour (HTTP 429 beyond).
- **Resource indicators** (RFC 8707). `resource` may be omitted (the token is
  for `/mcp`), `<public_url>/mcp`, or `<public_url>` (valid on `/mcp` and
  `/api`). Anything else is `invalid_target`. The bearer check enforces the
  audience.
- **Consent needs a signed-in human.** Without a session the browser goes to
  `/login?next=...` and comes back. The human picks one of
  `oauth_identities`; the grant acts as that identity under its profile
  (`public` by default). Grants never act as a human.
- **Codes** live 120 s and work once. A replayed code revokes everything the
  first exchange issued.
- **Refresh tokens rotate** on every use. Presenting a rotated refresh token
  revokes the whole grant (every access and refresh token of that sign-in).
- **Client authentication:** `none` (public clients, PKCE is the proof),
  `client_secret_basic`, `client_secret_post`. `client_credentials` is limited
  to clients in `oauth_client_credentials`, gets no refresh token, and may not
  act as a human identity.
- **Client ID Metadata Documents** (`oauth_cimd_enabled`): the client id must
  be a canonical `https` URL with a DNS host and a path, no port, query,
  fragment, credentials or dot segments. Every resolved address must be
  globally routable (no loopback, private, link-local, CGNAT, documentation,
  NAT64, 6to4 ...), and the connection is pinned to the vetted address so DNS
  rebinding cannot swap it. No redirects, no proxy, 5 s timeout, 5 KiB cap, at
  most four fetches in flight; results cached for an hour, failures for a
  minute. The document must repeat the same `client_id`, list
  `redirect_uris`, and describe a public client.

Tokens are opaque: `uao_` (access), `uar_` (refresh), `uac_` (code), each
followed by 32 random bytes in base64url.

## Browser sign-in (Control Center)

Code: `crates/ua-server/src/login.rs`.

| Route | Purpose |
|---|---|
| `GET /login?next=/ui/...` | Sign-in page (passkey). |
| `POST /login/passkey/start`, `/login/passkey/finish` | Passkey assertion (JSON). |
| `GET /login/link?token=...` | Confirmation page for a login link. Does not consume it, so link previews cannot burn it. |
| `POST /login/link` | Consumes the link and opens a session. |
| `GET /login/passkeys` | Lists the human's passkeys and registers new ones. |
| `POST /login/passkeys/register/start`, `/finish` | Passkey registration (session + CSRF header). |
| `POST /logout` | Ends the session (CSRF token in the header or a `csrf` form field). |
| `GET /api/session` | The CSRF helper (below). |

**First sign-in on a fresh install.** There is no passkey yet. On the hub
host run:

```
ua login-link <label>
```

`<label>` must be in `human_identities`. It prints a single-use URL that
expires after `login_link_ttl_secs`. Open it, press Continue, then register a
passkey on the page you land on.

**The session cookie** `ua_session` is encrypted (axum-extra
`PrivateCookieJar`; the key is generated on first use and kept in the
`ui_keys` table) and set with `HttpOnly; SameSite=Lax; Path=/` plus `Secure`
unless `ui_cookie_secure` is off. It has no `Max-Age`; the server-side row
bounds its life. Removing a label from `human_identities` ends its sessions at
once.

The cookie is `SameSite=Lax`, not `Strict`, on purpose. An MCP client starts
OAuth by sending the browser from another site (the client's page or a
native app) to `/oauth/authorize`. That is a cross-site top-level
navigation: a `Strict` cookie would not be sent, the human would look signed
out on the consent page and have to sign in again on every authorization.
`Lax` sends the cookie on top-level `GET` navigations only; cross-site
`POST`s, fetches and iframes still go without it, and every state-changing
cookie request needs the CSRF token as well.

## CSRF: integrating the UI

Every state-changing request (anything but `GET`, `HEAD`, `OPTIONS`) that
authenticates with the session cookie must carry the session's CSRF token in
the `X-CSRF-Token` header. Without it the middleware answers 403
`{"error": "csrf"}`. Bearer-authenticated requests need no CSRF token.

Two ways to get the token:

1. **From the browser:** `GET /api/session` returns

   ```json
   {
     "identity": "operator",
     "kind": "human",
     "verified": true,
     "auth": "cookie",
     "csrf_header": "X-CSRF-Token",
     "csrf_token": "…",
     "expires_at": "…"
   }
   ```

   Send `csrf_token` in the header named by `csrf_header`, e.g. for htmx:
   `<body hx-headers='{"X-CSRF-Token": "…"}'>`.

2. **Server-side, in a `/ui` handler:** the middleware inserts the session as
   a request extension. Use

   ```rust
   ua_server::login::csrf_token(request.extensions()) // -> Option<&str>
   ```

   or extract `Option<Extension<ua_server::login::UiSession>>` and read
   `csrf_token`, then render it into templates. The constant
   `ua_server::login::CSRF_HEADER` holds the header name.

The handler also receives `Extension<AuthIdentity>` (kind `human`) as for any
other authenticated request.

## Session credentials

A node that launches an ACP session for a claimed item can give that one
session its own short-lived hub credential, so the harness reaches the hub
without the node agent's token. Off unless `session_credentials_enabled =
true`; the setting is read on every request, so turning it off refuses every
outstanding credential at once.

**Minting.** The node's agent calls `POST /api/node/session_credential`
(tool `node_session_credential`) with `{node, item_id, attempt}`. The answer
(`201`, `Cache-Control: no-store`) is `{credential, credential_id,
expires_at, idle_expires_at, tools, mcp_server_name}`. The value is `uas_`
plus 43 base64url characters (32 random bytes). It is returned once and is
never stored, logged or put in an event; the table holds its SHA-256, and
events name the public `credential_id` (16 hex). A refusal answers `{error,
code, reason}`; `reason` is one of:

| Reason | Status | When |
|---|---|---|
| `disabled` | 403 | `session_credentials_enabled` is off |
| `node_binding` | 403 / 409 | the node is not registered, retired, or another agent's, or the item's agent is not the node's |
| `node_feature_missing` | 409 | the node did not advertise `acp_session_mcp` |
| `item_not_found` | 409 | no such item on this node |
| `not_acp` | 409 | the item's backend is not `acp:*` |
| `item_not_claimed` | 409 | the item is not claimed |
| `stale_attempt` | 409 | `attempt` is not the item's current claim |
| `lease_expired` | 409 | the claim's lease has lapsed |
| `cancel_requested` | 409 | the item, or its dispatch run, is being cancelled |
| `agent_retired` | 403 | the item's agent is retired |
| `label_refused` | 403 | the item's agent is in `revoked_agents` |
| `human_subject` | 403 | the item's agent is a human identity |
| `task_closed` | 409 | the item's task is done, cancelled or missing |

**Binding.** Everything comes from rows the hub owns: the subject is the
item's agent, and the credential is bound to the node, the item and the
claim's attempt (and so to the item's task and run). It expires at the
claim's lease deadline, `claimed_at + timeout_s + 300`. An idle window of
`min(now + 600 s, expiry)` is slid forward by each node heartbeat that names
the item as `running`; it never moves past the expiry or revives a lapsed
window. A second mint for the same item and attempt revokes the first
(`superseded`).

**Each request** re-reads the row (nothing is cached) and refuses with 401
unless: the setting is on; the credential is not revoked and inside both
windows; the item is still claimed by that node under the same attempt and
not being cancelled; its task (if any) is open; the node is registered to
the same agent, not retired and live (heartbeat within 90 s); and the agent
is not retired, revoked or a human. A lapsed window, a closed or deleted
task and a retired agent are written as a revocation on that request. Any
path other than `/mcp`, `/api/tools`, `/api/tools/{name}` and `/api/whoami`
answers 403 (`session_credential_path`).

**Authority.** The request runs as the subject with kind `agent` under the
`acp-session` profile, whatever session key the client sends, and inside the
credential's grant. The grant is the `acp-session` tool list
(`ACP_SESSION_ALLOWED_TOOLS`: `evidence_report`, `profile_status`,
`session_packet`, `task_comment`, `task_list`), narrowed to what the
subject's own default profile exposes. Memory tools are not in it: a
credential would otherwise read every agent's notes and write notes in its
owner's name. Each tool in the list has its own rule in the grant; a tool
without one is refused (`session_tool_unscoped`) even if a stored grant names
it. The task tools reach the item's own task only, and a
refusal names `session_task_scope`:

- `task_comment` may only `append` to or `list` that task's comments.
- `session_packet` and `evidence_report` read that task: an omitted
  `task_id` is filled in with it and any other `task_id` is refused, as are
  `session_id` (`session_packet`) and `project_id` (`evidence_report`),
  which would reach other rows.
- `task_list` lists that task at most, whatever its filters say.

An item without a task reads and comments on no task. A tool outside the
grant is refused (`profile_denied`) before any policy or approval is looked
at, and is not listed. A session credential cannot mint another one.

`acp-session` exists only for this: `profile_activate` refuses it
(`profile_reserved`), config loading refuses it in `profiles` and
`oauth_profile`, and a policy `profile_defaults` entry or profile overlay
naming it is invalid. A caller under that profile with no verified grant
(reachable only through a stale stored binding or a bug) is refused every
tool (`session_grant_required`) and sees none.

**Revocation.** The receipt for the item (`session_end`), cancelling the item
or its run (`cancelled`), a lapsed lease (`lease_expired`, by the sweep),
retiring the agent (`agent_retired`), an operator
(`coordination_manage` action `session_credential_revoke`, params exactly one
of `credential_id`, `item_id` or `node`; it answers the revoked ids and their
metadata, never a value), and on use a lapsed window (`expired`,
`idle_expired`) or a closed or deleted task (`task_closed`, `task_deleted`).

Events: `hub.session_credential.minted`, `hub.session_credential.revoked`
(one per credential, with its reason) and `hub.session_credential.refused`
(the failed check, at most once a minute per check and credential: the
credential id when the value matched one, else a prefix of the presented
value's SHA-256; at most 32 a minute per check in all).

A managed token may not start with `uas_` (nor `uao_`, `uar_`), and a static
token that does is never matched.

## Tools

In `crates/ua-tools/src/families/tokens.rs`:

| Tool | Notes |
|---|---|
| `agent_token_issue` | Human only. The caller supplies the value (32+ characters); the hub stores its digest and returns metadata, never the value. |
| `agent_token_rotate` | Human only. Replaces the identity's newest active token; the old one stops working at once. |
| `agent_token_list` | Metadata only (digests, status, dates). |
| `oauth_device_manage` | `list` the live OAuth sessions (one per approved sign-in), or `revoke` one `session_id` or every session of an `identity`. Revoke needs a one-time human approval. |

`ua token issue <label>` remains the one path that mints and prints a token
value.

## Ledger events

`agent.oauth.client_registered`, `agent.oauth.clients_pruned`, `agent.oauth.consent`,
`agent.oauth.token_issued`, `agent.oauth.token_revoked`,
`agent.oauth.code_reuse`, `agent.oauth.refresh_reuse`,
`agent.oauth.sessions_revoked`, `agent.ui.login`, `agent.ui.logout`,
`agent.ui.login_link_created`, `agent.ui.passkey_registered`,
`agent.token.issued`, `agent.token.rotated`. None carries a token, code,
secret or session id; grants are named by their session id (the grant family
id).
