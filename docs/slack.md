# Slack ingress

The hub does not serve Slack yet. `crates/ua-tools/src/families/slack.rs`
holds the pieces a future route will use:

- `verify_slack_signature(secret, timestamp, body, signature, now)`: Slack's
  v0 scheme, HMAC-SHA256 over `v0:{timestamp}:{body}`, compared in constant
  time. The timestamp must be 1 to 12 ASCII digits within 300 seconds of the
  hub clock; the signature must be `v0=` and 64 lowercase hex digits; the
  body at most 64 KiB.
- `remember_signed_request(tx, timestamp, body, now)`: records the SHA-256 of
  the signed base in `slack_seen_signatures` and refuses a second acceptance
  (`replayed`). Rows older than twice the replay window are pruned; such a
  request would already fail the timestamp check. The ledger event
  `agent.slack.signature_accepted` carries the hash and timestamp, never the
  body, and is attributed to `system`.
- `parse_slack_command(text)` (also the read-only tool `slack_parse_command`):
  one of `contact`, `task`, `assign`, `progress`, `blocker`, `review`, `plan`,
  `approve`, `status`. It refuses text over 4000 characters, control and
  format characters (bidirectional controls included; tab and line feed
  pass) and special mentions (`<!channel>`, `<!here>`, `<!subteam^…>`), drops
  leading user mentions, unescapes `&amp;`, `&lt;` and `&gt;` in arguments,
  and requires `task-<digits>` task ids and numeric approval ids. It never
  runs the command.

Signature checking is not an agent tool. An agent that could submit signed
bodies could spend another request's replay slot or probe the verifier.

The signing secret comes from the `UA_SLACK_SIGNING_SECRET` environment
variable. Do not put it in `config.toml`.

## Route checklist

A route that accepts Slack requests must do all of the following before it
is merged:

1. **Body limit.** `DefaultBodyLimit` of at most 64 KiB on the route.
2. **Raw bytes first.** Verify the signature over the raw body bytes, before
   any form or JSON parsing.
3. **Fail before state.** Answer 401 for a missing, malformed, stale or wrong
   signature before opening a database transaction. Only a verified request
   reaches `remember_signed_request`.
4. **Identity allowlist.** An explicit configuration mapping of
   (`team_id`, `user_id`) to a hub identity. A request from an unmapped pair is
   refused; Slack's `user_name` is never used for identity.
5. **Approvals as the human.** `/approve` resolves the approval as the mapped
   human identity, with the same separation of duties as `approval_resolve`
   (the approver is a verified human other than the requester).
6. **Dedupe.** Besides the signature replay table, drop a repeated
   `event_id` (Events API) or `trigger_id` (slash commands and interactions),
   since Slack retries deliveries.
7. **Ack within 3 seconds.** Acknowledge first and do the work after; Slack
   retries a slow answer, and the retry must hit the dedupe.
8. **Off by default.** A config gate (for example `slack_enabled = false`)
   that leaves the route unmounted until an operator turns it on, in addition
   to the signing secret being set.
