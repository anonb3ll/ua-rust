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
`UA_SLACK_SIGNING_SECRET` is set (and `slack_identities` is valid).
Otherwise they answer 404, and `ua serve` logs one line at startup saying
which condition is missing. Code: `crates/ua-server/src/slack_api.rs` (the
route) and `crates/ua-tools/src/families/slack.rs` (verifier, admission,
dedupe, command mapping).

## Enabling it

1. Create a Slack app for your workspace. Under **Basic Information**, copy
   the **Signing Secret**.
2. Set it in the hub's environment, never in `config.toml`:

   ```sh
   export UA_SLACK_SIGNING_SECRET=...   # never logged or stored
   ```

3. In `config.toml`, turn the routes on and map each Slack user who may use
   them to a hub identity:

   ```toml
   slack_enabled = true
   human_identities = ["operator"]

   [profiles]
   operator = "coordinator"
   builder-1 = "developer"

   [[slack_identities]]
   team_id = "T0000000000"     # the workspace id
   user_id = "U0000000000"     # the member id (profile → ⋮ → Copy member ID)
   identity = "operator"

   [[slack_identities]]
   team_id = "T0000000000"
   user_id = "U0000000001"
   identity = "builder-1"
   ```

4. Make the hub reachable over HTTPS at `public_url` (Slack only calls
   public HTTPS URLs) and add the routes to the app:
   - **Slash Commands**: create `/task`, `/status`, `/approve` and so on (one
     per command), or a single command such as `/hub` whose text carries the
     command (`/hub task write the report`). Request URL:
     `https://hub.example.com/api/slack/commands`.
   - **Event Subscriptions** (optional): Request URL
     `https://hub.example.com/api/slack/events`, bot events `app_mention`
     and, for direct messages, `message.im`. Slack sends a signed
     `url_verification` challenge when you save the URL; the hub answers it.

### `slack_identities`

The only way a Slack request gets an identity. Each entry is a
(`team_id`, `user_id`) pair and the hub `identity` it acts as. It is read
from TOML only (not from the environment), and the hub refuses to start when:

- a `team_id` is not `T` plus uppercase letters and digits, or a `user_id`
  not `U`/`W` plus uppercase letters and digits;
- the same pair is listed twice;
- an `identity` is neither in `human_identities` nor has an explicit
  `profiles` entry (a Slack user never falls back to the broad default
  profile).

A request from a pair that is not listed is refused. Slack's `user_name`,
display names and any other display field are never read.

An identity in `human_identities` acts as a **human**: it can resolve
approvals, subject to its profile and the separation-of-duties rule below.
Map a Slack account to a human identity only if that account is protected
like the human's other credentials (Slack SSO and 2FA).

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
| `approve <id>` | `approval_resolve` with `decision = approve` | the mapped identity |
| `status task-N` | `platform_object_get` (kind `task`) | the mapped identity |

Every call goes through `Registry::call`: the identity's profile, the policy
file, the approval gate and the `tool_calls` record apply exactly as for an
MCP or HTTP caller (transport `http`). A command a profile does not allow is
refused; a gated call parks an approval like any other.

**`/approve`** resolves as the mapped identity with `approval_resolve`'s own
rule: the approver must be a verified human (an identity in
`human_identities`) other than the requester, and the profile must allow
`approval_resolve`. A Slack user mapped to an agent cannot approve, whatever
its profile.

In the Events API, only an `app_mention` or a direct message (`message`
with `channel_type = im`), written by a person (no `bot_id`, no `subtype`),
whose first word after mentions starts with `/` runs anything
(`@hub /task write the report`). Every other event is acknowledged and
ignored without touching the database.

## What happens to a request

1. **Body limit.** At most 64 KiB (`DefaultBodyLimit`); larger is 413.
2. **Signature over the raw bytes**, before any parsing: HMAC-SHA256 of
   `v0:{timestamp}:{body}` under the signing secret, compared in constant
   time. The timestamp must be 1 to 12 digits within 300 seconds of the hub
   clock; the signature `v0=` and 64 lowercase hex digits.
3. **401 before state.** A missing, malformed, stale or wrong signature is a
   401 and no database transaction is opened. These refusals are logged by
   reason class (`missing_signature`, `bad_signature`, `stale`) at info
   level, never ledgered: they are unauthenticated and anyone can send them.
4. **Parse.** Form fields (a repeated field is malformed) or a JSON object.
   `url_verification` is answered here. Ignored events stop here.
5. **Admission**, one write transaction (`slack::admit`):
   - the signed base's hash goes into `slack_seen_signatures`; the same
     signed bytes a second time are a 401 (`replayed`);
   - (`team_id`, `user_id`) is looked up in `slack_identities`; unmapped
     (or a retired agent) is refused;
   - the `trigger_id` (commands) or envelope `event_id` (events) goes into
     `slack_seen_deliveries`; a repeat is answered "Already received." and
     runs nothing. Slack retries an event it thinks timed out with a new
     timestamp, so a retry passes the signature check and stops here.
6. **Ack first.** Slack gets its answer at once (a slash command an ephemeral
   sentence, an event an empty 200), well inside Slack's 3 seconds. The
   command then runs on a tracked background task, so a graceful shutdown
   waits for it.
7. **Result.** The outcome is ledgered. A slash command's result is posted
   to its `response_url` as an ephemeral message (see below).

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
| `agent.slack.signature_accepted` | A verified, fresh signature (request hash and timestamp) | `system` |
| `agent.slack.request.refused` | A verified request refused: `unmapped_identity`, `identity_retired` (with the Slack `team_id` and `user_id`), `malformed_payload`, `invalid_command` | `system`, or the mapped identity once known |
| `agent.slack.request.deduped` | A repeated trigger id or event id | the mapped identity |
| `agent.slack.request.accepted` | Admitted: kind, delivery id, command | the mapped identity |
| `agent.slack.request.executed` | After the command ran: tool, `ok`, and on failure the error code, reason code and any approval id | the mapped identity |
| `agent.slack.reply.failed` | The `response_url` post failed: `timeout`, `transport`, `status` | the mapped identity |

Plus the tool's own events (`agent.task.created`, `agent.approval.resolved`
and so on) and its `tool_calls` row, attributed to the mapped identity. No
event carries the body, the command text, the signing secret, a signature or
the `response_url`.

`slack_seen_signatures` rows older than 600 seconds and
`slack_seen_deliveries` rows older than a day are pruned on each admission.

## Threat model

- **Who can reach the routes:** anyone, since they are public. Without the
  signing secret a request gets a 401 and costs one HMAC; nothing is
  written.
- **Who can act:** whoever can make Slack sign a request from a mapped
  Slack account: that account's owner, a Slack workspace admin able to take
  it over, Slack itself, or anyone holding the signing secret (who can forge
  any user id). Treat the signing secret like a bearer token for every
  mapped identity, and map humans only from accounts protected like the
  human's other credentials.
- **What they can do:** only the nine commands, each one governed call as
  the mapped identity within its profile, policy and approval gate. There is
  no new privileged path: `/approve` is `approval_resolve` with its own
  rules.
- **Replays and retries:** the same signed bytes are accepted once; a
  re-signed retry of the same event or trigger runs once; signatures older
  than 5 minutes are refused.
- **Spoofed identity fields:** `user_name` and display names are never used;
  the `team_id` is part of the key, so the same user id in another workspace
  is not the mapped user.

## Not included

- Interactions (buttons, modals; `/api/slack/interactions`): the command
  parser and the approval flow work from text, so nothing needs them yet.
- Bot-token posting (`chat.postMessage`), threaded replies and live chat.
- Channel allowlists: identity is per user, in any channel the app is in.
- Enterprise Grid org-wide installs have not been exercised.

## Primitives

- `verify_slack_signature(secret, timestamp, body, signature, now)`: the v0
  check above. Not an agent tool: an agent that could submit signed bodies
  could spend another request's replay slot or probe the verifier.
- `remember_signed_request(tx, timestamp, body, now)`: the replay table.
- `admit(tx, cfg, timestamp, body, now, delivery)`: signature record,
  identity, dedupe and the admission ledger event, in the caller's
  transaction.
- `command_call(parsed, delivery_id)`: the registry call a parsed command
  becomes.
- `parse_slack_command(text)`: the parser (`slack_parse_command`). It never
  runs the command.
