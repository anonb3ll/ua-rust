# Authentication

The hub accepts four kinds of credential. Every credential the hub mints is
stored only as a SHA-256 digest, and every comparison is constant time.

| Credential | Who uses it | Accepted on | Stored in |
|---|---|---|---|
| Static bearer token (`agent_tokens` setting) | local agents | `/mcp`, `/api` | configuration |
| Managed bearer token | agents | `/mcp`, `/api` | `agent_tokens` (digest) |
| OAuth access token (`uao_…`) | remote MCP clients | `/mcp`; also `/api` when issued for the whole hub | `oauth_tokens` (digest) |
| Browser session cookie (`ua_session`) | humans in the Control Center | `/ui`, `/api` only, **never `/mcp`** | `ui_sessions` (digest) |

The auth middleware (`crates/ua-server/src/auth.rs`) tries a bearer token
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
| `oauth_cimd_enabled` | `false` | Accept URL client ids (Client ID Metadata Documents). The hub then fetches public HTTPS URLs on behalf of unauthenticated callers. |
| `oauth_cimd_allow` | empty | Hosts whose metadata documents may be fetched; `.example.com` admits subdomains. Empty admits any public host. |
| `oauth_identities` | `remote-agent` | Identities a human may bind a grant to on the consent page. Human identities are always refused. |
| `oauth_profile` | `public` | Profile given to each `oauth_identities` label that has no `profiles` entry. |
| `oauth_access_ttl_secs` | `3600` | Access token lifetime (clamped to 60 s .. 30 days). |
| `oauth_refresh_ttl_days` | `30` | Refresh token lifetime (clamped to 1 .. 365 days). |
| `oauth_client_credentials` | none | Confidential clients for `client_credentials`: `client_id\|secret\|identity` entries separated by commas or newlines. Secret; never printed. A client id listed twice is dropped. |
| `ui_cookie_secure` | `true` | Send the session cookie with `Secure`. Turn off only for plain `http://localhost`. |
| `ui_session_ttl_hours` | `12` | Browser session lifetime. |
| `login_link_ttl_secs` | `600` | Lifetime of a `ua login-link` URL. |
| `webauthn_rp_id` | host of `public_url` | WebAuthn relying-party id. |

The MCP endpoint also checks the `Host` header against `allowed_hosts`. Add
the host of `public_url` there when the hub is reached by name.

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

`agent.oauth.client_registered`, `agent.oauth.consent`,
`agent.oauth.token_issued`, `agent.oauth.token_revoked`,
`agent.oauth.code_reuse`, `agent.oauth.refresh_reuse`,
`agent.oauth.sessions_revoked`, `agent.ui.login`, `agent.ui.logout`,
`agent.ui.login_link_created`, `agent.ui.passkey_registered`,
`agent.token.issued`, `agent.token.rotated`. None carries a token, code,
secret or session id; grants are named by their session id (the grant family
id).
