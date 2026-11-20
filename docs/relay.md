# Public relay

`relay_manage` lets an agent post a message to a public surface without
holding the credential and without the hub posting anything a human has not
read. Today the one surface is a comment on a GitHub issue or pull request in
a repository the operator allowlisted.

```
check (gates only, nothing stored)

draft --gates fail--> blocked (stored without its text)
  |
  +--gates pass--> draft --request_send--> pending_approval --send--> sending --> sent
                     |                          |                        |
                     +--cancel--> cancelled <---+                        +--> failed
                                                                         +--> uncertain --resolve--> sent | failed
```

1. **`draft`** `{target, text, channel?}`: the hub checks the target, runs
   every gate and stores the draft. The result lists the findings. A draft
   with any finding is `blocked`; it is kept without its text and can never
   be sent. Fix the text and draft again.
2. **`request_send`** `{draft_id}`: the requester asks for a human decision.
   The hub first runs the gates again under the current configuration and
   checks that the repository is still allowed and the credential is stored,
   so a request that would fail never reaches a human. It then parks a
   one-time approval bound to the draft id, channel, target, exact text and
   the credential it will post with (its managed-secret name and keyed
   fingerprint, never the value). The human sees all of it in
   `approval_pending`. A token replaced after the approval no longer matches,
   so nothing is posted under another account.
3. A human runs `approval_resolve(id, "approve")`. The approver must be a
   verified human other than the requester.
4. **`send`** `{draft_id, text}`: the requester repeats the exact text. The
   hub sends only when all of these hold, and refuses otherwise without
   spending the approval:
   - the text equals the stored text byte for byte (`text_mismatch` names the
     first differing character);
   - the stored draft still equals what the approval bound: text, its
     SHA-256, target and channel (`approval_mismatch`);
   - the gates still pass and the repository is still allowed
     (`relay_blocked`, `relay_target_not_allowed`);
   - no earlier draft sent the same text to the same target with an unknown
     outcome (`relay_duplicate`).

   It then consumes the pass, marks the draft `sending`, posts, and records
   `sent` (with the comment id and URL), `failed` or `uncertain`.
5. **`status`** `{draft_id}` or `{approval_id}`, **`list`** `{status?,
   limit?}` and **`cancel`** `{draft_id, reason?}`. Cancelling withdraws the
   approval too (a pending one is denied, an unspent pass is revoked) and
   drops the stored text.
6. **`resolve`** `{draft_id, outcome, reason?}`, for a human only: after
   checking the thread, record `delivered` or `not_delivered` for an
   `uncertain` send, or for one still `sending` two minutes after it started
   (the hub stopped mid-send). It never posts anything.

Only the requester can request, send or cancel its own drafts; a human can
cancel any. An agent sees only its own drafts in `status` and `list`; a human
sees all. `list` never returns text.

`check` takes the same arguments as `draft`, runs the gates and returns the
findings without storing or recording anything.

## Gates

Every gate refuses; none rewrites the text. The text a human approves is the
text the agent wrote, and it is the text sent.

| Category | What it catches | Lets through |
|---|---|---|
| `secret` | The audit's credential shapes (vendor API keys, GitHub and Slack tokens, AWS keys, JWTs, credentials in URLs, assigned secret literals), `NAME_TOKEN=value`-style assignments and `Bearer` credentials. Matched with hidden characters removed, so a zero-width character inside a token does not hide it. | A value that is wholly a placeholder: `<token>`, `${VAR}`, `$VAR`, `%VAR%`, a mask such as `xxxx`, `[REDACTED_SECRET]` |
| `private_key` | `-----BEGIN ... PRIVATE KEY-----` blocks and PuTTY key files | Public keys |
| `hidden_unicode` | Unicode format characters (zero-width, bidirectional controls and isolates, tags, soft hyphen), variation selectors, blank Hangul fillers, line and paragraph separators, control characters | Newline, carriage return, tab; ordinary non-ASCII text and emoji without variation selectors |
| `private_address` | Loopback, RFC 1918, link-local, the shared `100.64/10` range (RFC 6598) tailnets use, IPv6 loopback, unique-local and link-local, and IPv6 forms embedding one of those | Public and documentation addresses; dotted version numbers that do not parse as one of these |
| `internal_host` | Names under `.internal`, `.local`, `.localdomain`, `.lan`, `.intranet`, `.corp`, `.home.arpa` and tailnet MagicDNS names; a single-label host in a URL (`http://buildbox:8080/`); names listed in `relay_internal_hosts` | `localhost`, public domains |
| `home_path` | `/home/<user>`, `/var/home/<user>`, `/Users/<user>`, `C:\Users\<user>` | Generic accounts (`user`, `runner`, `example`, `shared`, ...), `~/...` |
| `email` | E-mail addresses | `example.com`/`.org`/`.net`, the `.example`, `.test` and `.invalid` TLDs, `noreply` addresses, `git@` |
| `phone` | North American and `+`-prefixed international numbers | Dates, versions |
| `national_id` | The US SSN shape `123-45-6789` | |
| `payment_card` | Card numbers with a known issuer prefix, a valid length and a passing Luhn check | Other long digit runs |
| `length` | More than `relay_max_chars` characters (default 10000, at most 65000) | Empty or whitespace-only text is refused as an invalid argument |
| `denylist` | A match of any `relay_denylist` regular expression | |

Each finding has a category, a detail, a masked excerpt (a few leading
characters and the length, never the whole match) and the character offset.
A `denylist` finding has neither excerpt nor offset, and any other finding
that overlaps a denylisted match loses both, so no part of a private term is
echoed. A `relay_denylist` entry that does not compile refuses every draft
(`relay_denylist_invalid`, naming the entry's position only) until it is
fixed.

## GitHub adapter

| Setting | Meaning |
|---|---|
| `relay_github_repos` | `owner/repo` entries the relay may comment on (case-insensitive). Empty: the relay posts nowhere. |
| `relay_github_secret` | The name of a managed secret bound to consumer `relay:github`, holding a token that can comment on those repositories (a fine-grained token with issues and pull requests write access is enough). |
| `relay_github_api_url` | `https://api.github.com` by default; change it for GitHub Enterprise. https only. |

Store the token as a human or operator:

```json
{ "name": "relay-github", "consumer": "relay:github", "value": "<token>" }
```

with `managed_secret_set`, and set `relay_github_secret = "relay-github"`.
The token is decrypted in-process at send time and sent only as the
`Authorization` header. The target is `owner/repo#123`; the comment is
`POST /repos/{owner}/{repo}/issues/{number}/comments`, which covers issues and
pull requests. Requests use the web family's client: no redirects, no proxy,
a 20-second timeout, and non-public addresses refused.

Outcomes:

- **sent**: GitHub answered 2xx. The receipt holds the comment id and URL.
- **failed**: nothing can have been posted (the connection was refused, or
  GitHub answered a 4xx other than 408 and 429). The approval is spent; draft
  again for a new decision.
- **uncertain**: the comment may be live (timeout, dropped connection, 5xx,
  408, 429). It is never retried, and the same text cannot be sent to the
  same target again while this attempt has no confirmed outcome. A human
  checks the thread and records the outcome with `resolve`.

## What is recorded

Ledger events, each with the draft id: `relay.drafted` (target, characters,
bytes, the text's SHA-256, verdict, findings per category),
`relay.send_requested` (plus the approval id), `relay.sending`, then
`relay.sent` (plus the HTTP status and comment id), `relay.send_failed` or
`relay.send_uncertain` (plus a redacted, clipped error), `relay.cancelled`
and `relay.resolved`. No event holds the text, the token, a finding's excerpt or
a denylist pattern. The `relay_messages` table keeps the text of a draft that
passed the gates, for the human and for the binding check; blocked and
cancelled drafts keep none.

## Profiles

`relay_manage` is outbound speech, like `notify`: the `developer` and `cto`
profiles do not see it. Profiles with a deny list that does not name it, and
humans, do. Every send still needs a human approval.

## Configuration

```toml
relay_github_repos = ["acme/widgets"]
relay_github_secret = "relay-github"
# relay_github_api_url = "https://api.github.com"
# relay_internal_hosts = ["buildbox", "intranet.example.com"]
# relay_max_chars = 10000
# Private: keep these in the environment (UA_RELAY_DENYLIST, one per line)
# or in a config file only the hub can read.
# relay_denylist = ["project[- ]codename"]
```

## Differences from the original hub

- **Refuse, never redact.** The original redacted addresses, host names,
  home paths and personal data in place and asked a human to approve the
  rewritten text. Here every finding blocks and the agent rewrites, so what
  the agent wrote, what the human read and what is sent are the same bytes.
- **Stored drafts and an explicit request.** The original re-submitted the
  full draft on every call. Here a draft gets an id, `request_send` parks the
  approval, and `send` names the draft and repeats the text.
- **No hub-id gate.** Task references, run ids and memory ids are not gated:
  on GitHub `#123` is an issue reference, and twelve hex digits are a commit.
- **No attempt marker or reconciliation.** The original appended a hidden
  HTML marker to the posted body to find it again after an uncertain send.
  That would post text the human did not approve, so an uncertain send stays
  `uncertain` and blocks a duplicate until a human checks the thread and
  records the outcome with `resolve` (the original's `resolve_attempt`).
- **No dry-run adapter, and GitHub only** (no Zulip, Slack or others). The
  token comes from the managed-secret store, not a GitHub App installation.
  There is no auto-send: every send needs a human approval.
