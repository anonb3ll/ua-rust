# Slack ingress

The hub can take coordination commands from Slack: slash commands and, for
messages addressed to the app, the Events API. It is **off by default**.
Commands run through the same governed tool path as every other caller, as
the hub identity the Slack user is mapped to.

| Route | Slack feature | Body |
|---|---|---|
| `POST /api/slack/commands` | Slash commands | `application/x-www-form-urlencoded` |
| `POST /api/slack/events` | Events API (including the `url_verification` handshake) | JSON |

Both routes exist only when `slack_enabled = true` **and**
`UA_SLACK_SIGNING_SECRET` is set (and `slack_identities` is valid). Like
every other setting, `slack_enabled` can also be set from the environment
(`UA_SLACK_ENABLED=true` turns the gate on); `slack_identities` cannot (TOML
only), so the environment alone never lets anyone in.
Otherwise they answer 404, and `ua serve` logs one line at startup saying
which condition is missing. Code: `crates/ua-server/src/slack_api.rs` (the
route) and `crates/ua-tools/src/families/slack.rs` (verifier, admission,
dedupe, command mapping).

**These routes need a public HTTPS Request URL.** Slack calls the hub; it
cannot reach a hub that is only on a private network. For such a hub, use
[Socket Mode](#socket-mode) instead: the hub opens an outbound WebSocket to
Slack and needs no public URL. Everything below about identities, commands,
approvals, dedupe and the ledger applies to both transports.

## Enabling it

1. Create a Slack app for your workspace. Under **Basic Information**, copy
   the **Signing Secret**.
2. Set it in the hub's environment, never in `config.toml`:

   ```sh
   export UA_SLACK_SIGNING_SECRET=...   # never logged or stored
   ```

3. In `config.toml`, turn the routes on and map each Slack user who may use
   them to a human identity:

   ```toml
   slack_enabled = true
   human_identities = ["operator", "reviewer-1"]

   [profiles]
   operator = "coordinator"
   reviewer-1 = "developer"

   [[slack_identities]]
   team_id = "T0000000000"     # the workspace id
   user_id = "U0000000000"     # the member id (profile → ⋮ → Copy member ID)
   identity = "operator"
   can_approve = true          # may use /approve; off unless set

   [[slack_identities]]
   team_id = "T0000000000"
   user_id = "U0000000001"
   identity = "reviewer-1"     # no /approve from Slack
   ```

4. Make the hub reachable over HTTPS at `public_url` (Slack only calls
   public HTTPS URLs) and add the routes to the app:
   - **Slash Commands**: create `/task`, `/status`, `/approve` and so on (one
     per command), or a single command such as `/hub` whose text carries the
     command (`/hub task write the report`). Request URL:
     `https://hub.example.com/api/slack/commands`.
   - **Event Subscriptions** (optional): Request URL
     `https://hub.example.com/api/slack/events`, under **Subscribe to bot
     events**: `app_mention` and, for direct messages with the app,
     `message.im`. Subscribe `message.im` as a **bot** event, not under
     "Subscribe to events on behalf of users": the hub runs a direct
     message only when the envelope's `authorizations` include the app's
     bot (`is_bot: true`), so a user-scoped subscription (a person's DMs
     with colleagues) never becomes commands. Slack sends a signed
     `url_verification` challenge when you save the URL; the hub answers it.

### `slack_identities`

The only way a Slack request gets an identity. Each entry is a
(`team_id`, `user_id`) pair, the hub `identity` it acts as, and
`can_approve` (default `false`). It is read from TOML only (not from the
environment), and the hub refuses to start when:

- a `team_id` is not `T` plus uppercase letters and digits, or a `user_id`
  not `U`/`W` plus uppercase letters and digits;
- the same pair is listed twice;
- an `identity` is not in `human_identities`. A person typing in Slack never
  acts under an agent label; agents have their own credentials.

A request from a pair that is not listed is refused, and so is a pair whose
identity has since left `human_identities`.

Removing an identity from `human_identities` while a `[[slack_identities]]`
row still names it makes the hub **refuse to start** (it fails closed, with
`slack_identities[N].identity "..." is not in human_identities`). Remove or
change that `[[slack_identities]]` row in the same edit, then start the hub. Slack's `user_name`, display
names and any other display field are never read.

Map a Slack account to a human identity only if that account is protected
like the human's other credentials (Slack SSO and 2FA).

**`can_approve`** is a per-mapping opt-in for `/approve`. Without it,
`/approve` is refused (`approve_not_enabled`, ledgered under the mapped
identity, and the Slack user is told approvals are not enabled for them),
so turning Slack on does not widen who can approve. With it, the approval
still goes through `approval_resolve`'s own rules unchanged.

## Commands

The text is parsed by `parse_slack_command` (also the read-only tool
`slack_parse_command`): at most 4000 characters, no control or format
characters, no special mentions (`<!here>`, `<!channel>`, `<!subteam^…>`),
task ids as `task-<digits>`, approval ids as digits.

| Command | Runs | As |
|---|---|---|
| `contact` | nothing; replies with the mapped identity | |
| `task <text>` | `task_add` | the mapped identity |
| `assign <agent> <text>` | `delegate` (a generated Delegation Spec, `callback = none`) | the mapped identity |
| `progress\|blocker\|review task-N <note>` | `task_update` to `doing`, `blocked` or `waiting_review`, appending the note | the mapped identity |
| `plan <text>` | `plan_create` | the mapped identity |
| `approve <id>` | `approval_resolve` with `decision = approve` (slash commands only) | the mapped identity |
| `status task-N` | `platform_object_get` (kind `task`) | the mapped identity |

Every call goes through `Registry::call`: the identity's profile, the policy
file, the approval gate and the `tool_calls` record apply exactly as for an
MCP or HTTP caller. The caller's transport is `slack`, so a Slack-run call is
visible as such in `tool_calls.transport` (and in `tool_calls`-based reports)
without joining on the delivery id. `slack` is never treated as more trusted
than `http`: it is not a browser or passkey session, and nothing that
requires one accepts it. A command a profile does not allow is refused; a
gated call parks an approval like any other.

**`/approve`** needs `can_approve` on the mapping, then resolves as the
mapped identity with `approval_resolve`'s own rule: the approver must be a
verified human other than the requester, and the profile must allow
`approval_resolve`. Approvals from Slack are therefore opt-in per
identity, and each one is recorded as coming from Slack: the approval row's
`resolved_transport` is `slack` (every decision records the adapter it came
through: `ui`, `http`, `mcp`, `cli`, `slack`), the `agent.approval.resolved`
ledger event carries `transport: "slack"`, the Control Center inbox shows
it in the "Via" column, and the `approval_resolve` call's `tool_calls` row
has transport `slack`. The row's `reason` is `approved from Slack`.
`approve` is accepted **only as a slash command**: sent as a
message through the Events API, in any spelling (`!approve`, `/approve`,
any case), it is refused (`approve_needs_slash_command`
in the ledger), because an app holding a user's token can post messages as
that user, while only the person can invoke a slash command.

In the Events API, only an `app_mention` or a direct message with the app
(`message` with `channel_type = im`, delivered to the app's bot: the
envelope's `authorizations` include `is_bot: true`), written by a person (no
`bot_id`, `subtype`, `app_id` or `bot_profile` on the event) and not edited
(no `edited`), runs anything, and only when it is **marked** as a command:
after any leading mentions, `!` or `/` immediately followed by one of the
nine command words (ignoring case):

- `!task write the report` in a direct message;
- `@hub !status task-12` or `@hub /task write the report` in a channel.

Use `!` in messages: Slack's composer takes a message that *starts* with
`/` as a slash command and does not post it, so `/task` only works after a
mention. A bare word is never a command, in a direct message or a channel:
ordinary conversation ("Plan looks good to me", "Task done, thanks!") must
not write to the hub. Every other event is acknowledged and ignored without
touching the database.

## What happens to a request

1. **Body limit.** At most 64 KiB (`DefaultBodyLimit`); larger is 413.
2. **Signature over the raw bytes**, before any parsing: HMAC-SHA256 of
   `v0:{timestamp}:{body}` under the signing secret, compared in constant
   time. The timestamp must be 1 to 12 digits within 300 seconds of the hub
   clock; the signature `v0=` and 64 lowercase hex digits.
3. **401 before state.** A missing, malformed, stale or wrong signature is a
   401 and no database transaction is opened. These refusals are logged by
   reason class (`missing_signature`, `bad_signature`, `stale`) at debug
   level only, never ledgered: they are unauthenticated and anyone can send
   them.
4. **Parse.** Form fields (a repeated field is malformed) or a JSON object.
   `url_verification` is answered here. Ignored events stop here.
5. **Admission**, one write transaction (`slack::admit`):
   - the signed base's hash goes into `slack_seen_signatures`; the same
     signed bytes a second time are a 401 (`replayed`);
   - (`team_id`, `user_id`) is looked up in `slack_identities`; unmapped is
     refused **with no ledger row** (the signature
     is still remembered, so a replay is still refused), logged at debug
     level only: any workspace member, or anyone in a shared channel, can
     send signed requests in a loop, and the ledger is permanent;
   - the `trigger_id` (commands) or envelope `event_id` (events) goes into
     `slack_seen_deliveries`; a repeat is answered "Already received." and
     runs nothing. Slack retries an event it thinks timed out with a new
     timestamp, so a retry passes the signature check and stops here;
   - `/approve` from a mapping without `can_approve` is refused.
6. **Ack first.** Slack gets its answer at once (a slash command an ephemeral
   sentence, an event an empty 200), well inside Slack's 3 seconds. The
   command then runs on a tracked background task, so a graceful shutdown
   waits for it.
7. **Result.** The outcome is ledgered and the delivery's row in
   `slack_seen_deliveries` moves from `accepted` to `finished`. A slash
   command's result is posted to its `response_url` as an ephemeral message
   (see below).

### Commands with no recorded outcome

If the hub stops after a delivery was admitted but before its outcome was
recorded, Slack's retry is answered "Already received." So at startup,
before `ua serve` binds, every delivery still `accepted` is ledgered once
as `agent.slack.request.abandoned` with `outcome: "unknown"` (identity,
kind, delivery id, age in seconds; no body) and marked `abandoned`.

"Unknown" is exact: the delivery was admitted and no outcome was recorded.
Usually the command never ran, but its tool call may have committed while
the outcome record did not (a shutdown deadline, a failed write), or it may
still be running under a second `ua serve` on the same database. Check
`tool_calls` (transport `slack`, that identity, around that time) before
asking for it to be sent again. The event carries no `tool_calls` id: a
call record does not hold the Slack delivery id, and matching by caller and
time would not be exact. An `accepted` row is never pruned before the
sweep has seen it.

## Result delivery

A slash command's `response_url` is posted to only when it is
`https://hooks.slack.com/...` on the default port with no user info: that
exact host, nothing else. The client is the web tools' guarded client: no
redirects, no proxy, every resolved address must be public (loopback is
refused here even under `fetch_allow_loopback`), a 10-second timeout, and the
response body is never read. Any other `response_url` is ignored and the
acknowledgement says the result is in the hub ledger.

The reply is one fixed sentence per command (ids, and for `status` the
task's status and title), or the error code and its client-safe message.
`&`, `<` and `>` are escaped, so nothing in a hub value turns into a Slack
mention or link.

Events carry no `response_url`, so Events API commands reply nothing; their
outcome is in the ledger. Posting with a bot token (`chat.postMessage`) is
not implemented.

## Ledger

| Event | When | Attributed to |
|---|---|---|
| `agent.slack.signature_accepted` | A verified, fresh signature from a mapped identity (request hash and timestamp) | `system` |
| `agent.slack.request.refused` | A mapped identity's request refused: `malformed_payload`, `invalid_command`, `approve_needs_slash_command`, `approve_not_enabled` | the mapped identity |
| `agent.slack.request.deduped` | A repeated trigger id or event id | the mapped identity |
| `agent.slack.request.accepted` | Admitted: kind, delivery id, command | the mapped identity |
| `agent.slack.request.executed` | After the command ran: tool, `ok`, and on failure the error code, reason code and any approval id | the mapped identity |
| `agent.slack.request.abandoned` | At startup: admitted before the last stop with no recorded outcome (identity, kind, delivery id, `age_s`, `outcome: "unknown"`; check `tool_calls`) | the mapped identity |
| `agent.slack.reply.failed` | The `response_url` post failed: `timeout`, `transport`, `status` | the mapped identity |

Requests with no mapped identity (`unmapped_identity`) write no ledger row
at all; they are logged at debug level, with the
reason class only.

Plus the tool's own events (`agent.task.created`, `agent.approval.resolved`
and so on) and its `tool_calls` row, attributed to the mapped identity. No
event carries the body, the command text, the signing secret, a signature or
the `response_url`.

`slack_seen_signatures` rows older than 600 seconds and
`slack_seen_deliveries` rows older than a day (except `accepted` ones, see
[Commands with no recorded outcome](#commands-with-no-recorded-outcome)) are pruned on each admission.

## Threat model

- **Who can reach the routes:** anyone, since they are public. Without the
  signing secret a request gets a 401 and costs one HMAC; nothing is
  written and it is logged at debug level only.
- **Signed but unmapped:** every member of the workspace (and of a shared
  channel) can make Slack sign requests. Those add a row to the short-lived
  replay table (pruned after 10 minutes) and nothing to the ledger, so they
  cannot grow permanent state.
- **Who can act:** whoever can make Slack sign a request from a mapped
  Slack account: that account's owner, a Slack workspace admin able to take
  it over, Slack itself, or anyone holding the signing secret (who can forge
  any user id). The signing secret is therefore equivalent to a bearer token
  for every mapped human's commands, and to approval power only for the
  mappings with `can_approve`. Map humans only from accounts protected like
  the human's other credentials.
- **What they can do:** only the nine commands, each one governed call as
  the mapped human within its profile, policy and approval gate. There is
  no new privileged path: `/approve` is `approval_resolve` with its own
  rules, and only for opted-in mappings. Turning Slack on does not widen who
  can approve unless the operator sets `can_approve`.
- **Only humans:** a mapping to an agent label is refused at load, so a
  person typing in Slack never acts under an agent's identity, and Slack
  calls are recorded with transport `slack`.
- **Replays and retries:** the same signed bytes are accepted once; a
  re-signed retry of the same event or trigger runs once; signatures older
  than 5 minutes are refused.
- **Messages posted on someone's behalf:** an app installed with a user
  token can post messages that look like the user's own, and Slack does not
  always mark them. Events with `bot_id`, `subtype`, `app_id` or
  `bot_profile` are ignored, an edited message is not run a second time,
  and `/approve` is never accepted from the Events API at all, only as a
  slash command, which only the person can invoke. Other commands sent as
  messages must be marked (`!task`) and run as the mapped identity, so an
  app with a mapped user's token can still create or update tasks as that
  user by posting `!task …` to the app; turn off Event Subscriptions if
  that matters to you. A `message.im` subscription on behalf of users is
  ignored (no bot authorization).
- **Spoofed identity fields:** `user_name` and display names are never used;
  the `team_id` is part of the key, so the same user id in another workspace
  is not the mapped user.

## Socket Mode

Socket Mode serves the same commands and events over a WebSocket the hub
opens to Slack, so the hub needs **no public URL** (and no signing secret).
Use it for a hub that is reachable only on a private network. It runs inside
`ua serve` and needs a binary with the `slack-socket` cargo feature (on by
default). Code: `crates/ua-server/src/slack_socket.rs`.

### Setting it up

1. In the Slack app's settings, turn on **Socket Mode** and create an
   **app-level token** (`xapp-…`) with the `connections:write` scope.
2. Keep Slash Commands and Event Subscriptions as above (`app_mention`,
   `message.im` as bot events). With Socket Mode on, Slack delivers them
   over the socket and asks for no Request URL.
3. Set the token in the hub's environment only. It is never read from
   `config.toml`, never logged and never ledgered:

   ```sh
   export UA_SLACK_APP_TOKEN=xapp-...
   ```

4. In `config.toml`:

   ```toml
   slack_socket_mode = true     # UA_SLACK_SOCKET_MODE also sets it
   # slack_identities as above; slack_enabled may stay false
   ```

`ua serve` logs one line at startup saying whether Socket Mode started and,
if not, why (off, no token, a token that is not `xapp-…`, an invalid
`slack_identities`, or a binary without the feature). `system_doctor`'s
`slack` row reports the transport's state: off, not compiled, connecting,
connected, restarting (a connection failed and is being reopened) or auth
failed. It never shows the token.

Both transports may be on at once. A delivery is deduplicated by its event
id or trigger id across both, so one that arrives on each runs once.

### How it works

1. The hub POSTs `https://slack.com/api/apps.connections.open` with the token
   in the `Authorization` header, through the guarded web client (no
   redirects, no proxy, public addresses only; the response is read up to
   16 KiB). It answers a one-time `wss://` URL.
2. The URL must be `wss`, on `slack.com` or a subdomain, on the default port,
   with no user info; otherwise it is refused and the hub retries later. The
   first refusal of each reason is ledgered as `agent.slack.socket.url_refused`
   (reason class only; the URL carries a connection ticket and is not
   recorded); repeats are only logged, until a connection works again. Every
   address the host resolves to must be public, and TLS is rustls with the
   platform's certificate verifier.
3. Slack sends `hello`, then envelopes (`envelope_id`, `type`, `payload`,
   `accepts_response_payload`). Each is acknowledged by sending
   `{"envelope_id": …}` back, well inside Slack's few seconds:
   - `slash_commands`: the payload carries the same fields as the HTTP form
     and goes through the same admission. When the envelope accepts a
     response payload, the ephemeral sentence rides in the acknowledgement;
     `response_url` delivery stays as on the HTTP route.
   - `events_api`: the payload is the Events API `event_callback` body and
     goes through the same filters (marker, bot authorization for DMs, no
     app-written or edited messages, approve refused).
   - `interactive` and anything else: acknowledged, not acted on.
4. `disconnect` (Slack's `warning`, `refresh_requested`, `link_disabled`):
   the hub closes the socket and opens a new one after about a second
   (jittered; never zero, so a `hello`/`disconnect` loop cannot make it
   hammer Slack). Other failures reconnect with exponential backoff and
   jitter (1 s doubling to a 60 s cap; the count starts over after a
   `hello`).
5. Liveness: the hub pings every 30 seconds (a late tick is not made up
   with a burst). One deadline, reset only by an incoming frame (a message,
   ping or pong), drops a connection that has been silent for two minutes;
   two pings in a row with no pong drop it sooner; and Slack must say
   `hello` within 30 seconds of the handshake, which pings and pongs do not
   satisfy. So a peer that vanishes
   without a TCP reset (a NAT timeout, a suspended machine) is noticed.
   A panic inside a connection is caught: the state reads `restarting` and
   the hub reconnects with backoff.
6. If `apps.connections.open` refuses the token or the app (`invalid_auth`,
   `not_authed`, `token_revoked`, `token_expired`, `account_inactive`,
   `not_allowed_token_type` and the like), the transport stops, logs one
   line and does not retry until `ua serve` restarts.

Bounds: WebSocket messages over 1 MiB end the connection; an envelope whose
payload is over 64 KiB is acknowledged and not acted on. Each envelope is
admitted on its own task while the connection keeps being read (so a slow
admission never stalls pings, pongs or other envelopes), and its single
acknowledgement goes back to the connection when ready; acknowledgements
may leave in a different order than the envelopes came (each is
independent, and the event and trigger id dedupe does not depend on
order). At most 32 envelopes per connection are being admitted at once,
counted until each admission finishes, not just until it is acknowledged
(so a stalled database cannot let a new batch start every ack period). One
past that is turned away without admission, ledger or replay row, logged
at warn (envelope hash, type, in-flight count) and counted in the
`system_doctor` `slack` row: a slash command is acknowledged with "The hub
is busy. Try again in a moment." (Slack may not redeliver it, so the person
is told and can retry); an event is left unacknowledged, so Slack
redelivers it. A failure or
panic in one envelope never ends the connection, and a shutdown waits for
envelopes in flight. If its admission transaction fails, it is not acknowledged, so
Slack redelivers it. If admission is slower than the 2.5-second ack
deadline, the envelope is acknowledged first and admission finishes on its
own task; should it then fail, Slack will not redeliver it, so the hub logs
a warning with the envelope hash and ledgers
`agent.slack.envelope.outcome_unknown` (envelope hash, reason class) when the
database accepts the write.

The Socket Mode URL carries a one-time ticket. tungstenite logs the
handshake request at trace level, so `ua` caps `tungstenite` and
`tokio_tungstenite` logs at info whatever `UA_LOG` says, as it does for
`rmcp`.

### Replay protection without a signature

There is no request signature in Socket Mode: the connection itself is
authenticated by the app token over TLS. In place of the signed bytes, the
envelope id goes into the same replay table (`slack_seen_signatures`, keyed
by the SHA-256 of `socket-envelope:{envelope_id}`, so it never collides with
an HTTP key, and pruned after the same 10 minutes). A redelivered envelope
(Slack retries ones it saw no acknowledgement for) is acknowledged again and
runs nothing. Past that, the event id and trigger id dedupe
(`slack_seen_deliveries`, a day) still applies, across both transports. For
a mapped identity the admission ledgers `agent.slack.envelope_accepted`
(the envelope hash) where the HTTP route ledgers
`agent.slack.signature_accepted`; unmapped users add no ledger row, as on
HTTP.

### Threat model

- The app-level token is equivalent to the signing secret: whoever holds it
  can receive every delivery and answer for every mapped human (and approve
  as the opted-in ones). Keep it in the same secret store as the signing
  secret, and rotate it in the Slack app settings if it leaks.
- The hub connects only to `slack.com` hosts it resolved to public
  addresses, with certificate verification; it accepts no inbound
  connection for Slack at all.
- Everything after the socket (identity, `can_approve`, approve only from
  slash commands, marker, filters, dedupe, governed calls, ledger) is the
  same code as the HTTP routes.

### Not verified against a live workspace

Built from Slack's Socket Mode documentation and tested against an
in-process stand-in, not yet against a live workspace:

- that an `events_api` payload is the full `event_callback` body with
  `event_id` and `authorizations` (Slack's page shows only an inner event
  and says the payloads are "identical to the typical Events API payloads,
  with some additional metadata"); if it is not, events are acknowledged and
  ignored (fail closed) and slash commands still work;
- the acknowledgement deadline and redelivery behaviour (the docs say Slack
  retries unacknowledged envelopes but give neither a deadline nor a
  `retry_attempt` field); the hub acknowledges within 2.5 seconds;
- whether a socket URL may be reused (the hub never reuses one);
- the exact set of permanent `apps.connections.open` errors (the hub treats
  the auth-, token- and permission-class codes on the method page as
  permanent and everything else, `ratelimited` included, as retryable).

## Not included

- Interactions (buttons, modals; `/api/slack/interactions`): the command
  parser and the approval flow work from text, so nothing needs them yet.
- Bot-token posting (`chat.postMessage`), threaded replies and live chat.
- Channel allowlists: identity is per user, in any channel the app is in.
- Enterprise Grid org-wide installs have not been exercised.
- The direct-message bot check follows Slack's documented envelope
  (`authorizations`: one installation the event is visible to, with
  `enterprise_id`, `team_id`, `user_id`, `is_bot`, `is_enterprise_install`).
  It has not yet been confirmed against a live workspace that a bot-event
  `message.im` carries `is_bot: true`; if it does not, direct-message
  commands are ignored (fail closed) and mentions still work.

## Primitives

- `verify_slack_signature(secret, timestamp, body, signature, now)`: the v0
  check above. Not an agent tool: an agent that could submit signed bodies
  could spend another request's replay slot or probe the verifier.
- `remember_signed_request(tx, timestamp, body, now)`: the replay table.
- `admit(tx, cfg, timestamp, body, now, delivery)`: signature record,
  identity, the `can_approve` check, dedupe and the admission ledger event,
  in the caller's transaction.
- `sweep_abandoned(tx, now)`: the startup sweep for admitted commands with no recorded outcome.
- `command_call(parsed, delivery_id)`: the registry call a parsed command
  becomes.
- `parse_slack_command(text)`: the parser (`slack_parse_command`). It never
  runs the command.
