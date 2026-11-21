# Downstream MCP servers

The hub can call tools on other MCP servers for an agent, so the agent needs
only the hub's MCP entry and never holds the downstream credential. Three
pieces make this work:

- **Managed secrets**: an encrypted, write-only store of credentials, each
  bound to one consumer.
- **The server registry**: downstream servers an operator registered and a
  human approved, or that are declared in `config.toml`.
- **`mcp_gateway`**: the tool that calls one catalogued tool on one
  registered server.

## Managed secrets

| Tool | Who | What |
|---|---|---|
| `managed_secret_set` | A human, or an agent whose identity is in `human_identities` or `lifecycle_operators` | Store a value for one consumer. Returns metadata and a fingerprint, never the value. Replacing an existing value needs a one-time human approval. |
| `managed_secret_list` | Profiles that see it (not `developer` or `reviewer`) | Name, consumer, fingerprint, size, key id, who set it. |
| `managed_secret_delete` | As for `set`, plus a one-time human approval | The approval binds the name, consumer and current fingerprint. |

- **Admin is an identity, not a profile.** Who may set, delete, register,
  review or revoke is decided by the verified identity: a human, or an agent
  listed in `human_identities` or `lifecycle_operators`. The `operator`
  profile grants none of it, because an agent may activate any profile that
  ranks no higher than its default.
- **Replacing a value.** A first `managed_secret_set` of a name needs no
  approval (unless `approval_tools` lists it). Setting a name that already
  holds a value parks for a one-time human approval bound to the name,
  consumer, size and the new value's fingerprint; the identical retry after
  approval stores it. Swapping a credential is as consequential as deleting
  it, and a gateway write approved earlier no longer applies (see
  [Calling a tool](#calling-a-tool)).

- **Encryption.** AES-256-GCM, a fresh random 96-bit nonce per write, and the
  secret's name and consumer as associated data, so a row copied under another
  name or consumer does not decrypt. The key comes from `managed_secret_key`
  (or `UA_MANAGED_SECRET_KEY`): 32 random bytes as base64 or 64 hex
  characters, for example `openssl rand -base64 32`. It is never stored in
  the database. With no key, `managed_secret_set` is refused; there is no
  plaintext mode.
- **Rotation.** Give a comma-separated list: the first key encrypts new
  writes and every key decrypts. `managed_secret_list` shows
  `key_current: false` for rows sealed with an older key; set them again,
  then drop the old key.
- **Consumer.** Required, with no default. A downstream MCP server `docs`
  only loads secrets bound to consumer `mcp:docs`. Rebinding a name to
  another consumer needs a delete first.
- **Fingerprint.** HMAC-SHA256 of the value under a key derived from the
  encryption key (first 128 bits, hex). Someone who can read metadata or the
  approval queue cannot test a guessed value against it.
- **What is recorded.** `managed_secret.set` and `managed_secret.deleted`
  ledger events carry the name and consumer only. `tool_calls` rows never hold
  arguments. If an operator lists `managed_secret_set` in `approval_tools`, the
  approval binds the name, consumer, fingerprint and size, not the value.
- **No read path.** No tool returns a value. Only the consumer's own code
  decrypts one, in-process, at the moment it is used.

## Registering a server

`mcp_server_register` takes a name (`[a-z0-9][a-z0-9_-]{0,63}`), a server
spec and an optional `review_days`. It is for a human or an operator, and it
always needs a one-time human approval bound to the whole spec. The spec is
checked before anyone is asked, so a request that would fail never reaches
the approval queue.

```json
{
  "name": "docs",
  "server": {
    "transport": "streamable_http",
    "url": "https://docs.example.com/mcp",
    "address_scope": "public",
    "secrets": [{ "secret": "docs-token", "inject": "bearer" }],
    "tools": { "search": "read", "get_page": "read", "put_page": "write" },
    "read_profiles": ["developer", "reviewer"],
    "timeout_s": 30
  },
  "review_days": 90
}
```

| Field | Meaning |
|---|---|
| `transport` | `stdio` (a child process) or `streamable_http`. |
| `command`, `args`, `cwd`, `env` | stdio only. `command` is an absolute path, run without a shell. `env` holds non-secret settings; loader and interpreter hooks (`LD_*`, `DYLD_*`, `PATH`, `NODE_OPTIONS`, ...), the hub's `UA_*` names and anything that looks like a credential are refused. |
| `url`, `address_scope` | streamable_http only. See [Address scope](#address-scope). |
| `secrets` | Managed secrets injected by name: `bearer` (HTTP `Authorization`), `header:<Name>` (another HTTP header) or `env:<NAME>` (a stdio child's environment). Each must be bound to consumer `mcp:<name>`. At most 8. |
| `tools` | Every downstream tool the gateway may call, classified `read` or `write` by the reviewer. 1-256 entries. Nothing the server says about its own tools (annotations, its tool list) changes this. |
| `read_profiles` | Profiles whose sessions may call the read tools. Empty: operators (verified humans, `human_identities`) only, so a server meant for agents names their profiles. An anonymous caller never reads from a server with `secrets`. |
| `timeout_s` | One call's budget, connection included: 1-120, default 30. |

`mcp_server_review` renews the review window for `review_days` from now
(default `mcp_review_ttl_days`, 90) and needs a one-time human approval bound
to the server's current spec. `mcp_server_revoke` (always gated) makes the
gateway refuse the server and orphans its credentials: the approval payload
lists every managed secret bound to `mcp:<name>` (`orphaned_secrets`, names
and fingerprints), and the approved revocation deletes them, each with a
`managed_secret.deleted` event. A revoked name can be registered again with a
new approval, perhaps at another endpoint, so it starts with no credential:
the operator sets the secrets again for the new registration. A secret set
after the revocation was requested changes the payload and needs a new
approval. `mcp_server_list` shows every server with its status (`active`,
`review_expired`, `review_required`, `revoked` or `misconfigured`), its
secret names and whether each is stored. It never shows a secret value.

Each change appends an `agent.mcp_server` ledger event (`registered`,
`reviewed`, `revoked`) with the spec hash and approval id, in the same
transaction as the change.

### Servers in config

An operator can also declare servers in `config.toml`. Each table has the
same fields as the spec, plus `review_expires_at` (a date or an RFC 3339
timestamp). There is no environment-variable form.

```toml
[mcp_servers.codegraph]
transport = "stdio"
command = "/usr/local/bin/codegraph-mcp"
args = ["--read-only"]
secrets = [{ secret = "codegraph-key", inject = "env:CODEGRAPH_KEY" }]
review_expires_at = "2027-03-01"

[mcp_servers.codegraph.tools]
search_graph = "read"
get_code_snippet = "read"
index_repository = "write"
```

A config entry is usable until its `review_expires_at`, or later if
`mcp_server_review` renews it. An entry without `review_expires_at` needs a
review first. A bad entry refuses only itself. `mcp_server_revoke` works on a
config entry too. The revocation is tied to the entry's exact spec, so it
holds until the entry is edited, and the edit counts as a new declaration. A
name cannot be both declared in config and registered.

## Calling a tool

```json
{ "server": "docs", "tool": "search", "arguments": { "query": "lease reaper" } }
```

`mcp_gateway` with `action: "call"` (the default) checks, in order:

1. The server exists, is not revoked, and is inside its review window.
2. The tool is in the server's `tools`. Any other tool is refused
   (`tool_not_catalogued`), even if the server offers it.
3. A read from a server with `secrets` needs an authenticated caller
   (`identity_required`): a local stdio process or HTTP without enforced auth
   is anonymous. Then a human may read; anyone else needs a profile in
   `read_profiles`, or, when it is empty, an identity in `human_identities` or
   `lifecycle_operators`. A write needs an authenticated caller who is not in `revoked_agents` and, when
   `agent_scopes` is set, is scoped for `mcp_gateway_write`.
4. The policy file runs under the name `mcp_gateway.<server>.<tool>`, so a
   rule such as `tool: "mcp_gateway.docs.*"` holds however the call is made.
5. The server has a free call slot (4 at a time). A busy server refuses the
   call (`server_busy`) instead of queuing it.
6. The server's secrets decrypt for consumer `mcp:<server>`.
7. A write, or a call a policy rule sends to approval, needs a one-time human
   approval. A write's approval binds the server, the tool, the exact
   arguments, the spec hash and each injected secret's keyed fingerprint
   (`secrets: {name: fingerprint}`) under the queue name `mcp_gateway_write`,
   so a credential replaced after the approval needs a new one. The
   first call parks with an `approval_id`, and the identical call runs once a
   human approves it. Steps 5 and 6 come first, so a call that would fail
   anyway does not spend the approval.
8. The call runs within the server's timeout.

`action: "list"` returns the catalogued tools and their class. With
`live: true` it also asks the server for each catalogued tool's description
and input schema, and counts the uncatalogued tools without naming them.
`live` counts as a read.

The result is `{server, tool, access, is_error, content, structured_content?,
truncated?, untrusted: true, trust}`. `content` keeps text blocks; other block
types appear as `{type, omitted: true}`. A downstream tool error comes back
with `is_error: true`.

## Security boundaries

- **Callers name servers, not endpoints.** An agent supplies a server name and
  a tool name, never a URL, a command or a credential.
- **Address scope.** A URL server is registered with one scope: `public`
  (global unicast, the default), `private` (RFC 1918, `100.64.0.0/10` as used
  by tailnets, and `fc00::/7`) or `loopback`. The URL host must be inside it
  at registration: a loopback or private address, or `localhost`, needs that
  scope registered explicitly. Plain `http` is allowed only for `loopback` and
  `private`. URLs may not carry credentials, a query or a fragment. Link-local
  and metadata addresses, multicast, unspecified, documentation and reserved
  ranges, and IPv6 forms that embed an IPv4 address (compatible, translated,
  NAT64, 6to4) are in no scope. An IPv4-mapped address is judged as its IPv4.
- **Origin pinning.** The HTTP client ignores proxy variables and follows no
  redirect. Its resolver answers only for the registered host name, checks
  every address it returns against the scope, and hands the connection only
  those addresses, so a rebinding DNS answer cannot redirect a call.
- **Stdio children.** The child starts from an empty environment: a few
  plumbing names (`PATH`, `HOME`, `LANG`, ...), the spec's `env`, and its
  injected secrets. It never inherits the hub's environment, so
  `UA_MANAGED_SECRET_KEY` and agent tokens stay out of it. Its stderr is
  discarded. It runs in its own process group, and the whole group is killed
  after every call, on success, error or timeout.
- **Redaction.** Every injected secret is removed from the result and from
  any error text: the raw value; its percent-encoding and hex in either case;
  its base64 (standard or URL-safe, padded or not) at all three byte offsets,
  so it is found inside a larger blob such as `Basic base64("user:" + v)`;
  each of these with whitespace ignored, so a value split by spaces or line
  breaks is found; and any substring of one of these forms at least
  `max(12, len/2)` long (a partial echo). A shorter fragment (at least
  `max(8, len/3)`) that remains, or a value split across text blocks or
  string values, cannot be redacted cleanly: the result is withheld and comes
  back as `is_error: true, withheld: true` with a fixed message (ledger
  outcome `withheld`); an error message is replaced the same way. Redaction
  happens before the size cap, so a cut can never leave part of a credential.
- **Bounds.** Arguments are at most 64 KB. A stdio message (one line) is at
  most 1 MiB and a stdio call reads at most 4 MiB. An HTTP JSON body or SSE
  event is at most 1 MiB. The returned content is capped at 256 KB
  (`truncated: true`). Every call has the server's timeout.
- **Untrusted output.** Downstream text is data written by someone else. The
  result carries the hub's `trust` marker.
- **Logs.** rmcp logs whole requests and responses at debug and trace. The
  `ua` binary drops rmcp events below info after `UA_LOG` is parsed, so no
  directive (not even `rmcp::service=debug`) brings them back.
- **Evidence.** Every gateway call, refused or not, appends exactly one
  `agent.mcp_gateway.call` event: action, server, tool, access, caller,
  argument and result sizes, outcome, latency and any approval id. The event
  never holds the arguments, the result or a secret.

## Limits

- The client uses the `initialize` handshake (protocol 2025-11-25). Servers
  that only speak the stateless 2026-07-28 revision are not reached yet.
- Each call opens a fresh session: a stdio server starts once per call.
- Policy `rate_limit` and `cooldown` rules count `tool_calls` rows. Those rows
  carry the tool name `mcp_gateway`, so rate-limit `mcp_gateway` itself; a
  rate limit on `mcp_gateway.<server>.<tool>` never trips.
- The public relay (`relay_manage`) loads its GitHub token from the same
  store, bound to consumer `relay:github`; see [relay.md](relay.md).
