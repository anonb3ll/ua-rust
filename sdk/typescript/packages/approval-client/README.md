# @unified-agent/approval-client

A governed approval client on top of `@unified-agent/client` — a phone-first
Telegram adapter over the hub's typed `approval_pending` / `approval_resolve`
surface.

## What this is, and isn't

- **Is:** a thin, typed forwarder. Every decision it makes is an unmodified
  call to the hub's `approval_resolve` tool. It never mints or extends
  approval authority — the hub is still the sole source of policy.
- **Is:** idempotent-safe. A double-tapped button or a retried message
  resolves to the same outcome without erroring — see `ApprovalClient`'s
  doc comment for exactly how.
- **Isn't:** an elicitation implementation. It does not receive or answer
  server-initiated MCP `elicitation/create` requests — that needs a
  bidirectional channel this transport doesn't have (see
  `docs/compatibility-matrix.md`). This client polls
  `approval_pending` and acts through `approval_resolve` — a request/response
  pattern the existing transport already supports fully.

## Single-user pilot setup

This is scoped for a single-user pilot: one
accountable owner, one workflow, boring deployment.

1. Create a Telegram bot via [@BotFather](https://t.me/BotFather) — `/newbot`,
   copy the token it gives you. Never commit it; never paste it into chat
   with an agent (per this repo's secrets hygiene convention).
2. Find your own Telegram numeric user id (e.g. message
   [@userinfobot](https://t.me/userinfobot)).
3. Deploy with Docker (from the repo root — "their IT can run it" is the bar):

   ```bash
   cp packages/approval-client/.env.example packages/approval-client/.env
   # edit .env: UA_HUB_URL, UA_HUB_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_OWNER_IDS
   docker compose -f packages/approval-client/docker-compose.yml up -d
   ```

   The image is stateless — no volumes, no database. The hub is the only
   durable store and is expected to run elsewhere; point `UA_HUB_URL` at it
   (`http://host.docker.internal:8765/mcp` if the hub runs on the Docker
   host itself). See `Dockerfile` for the build and
   `bin/run-telegram-bot.mjs` for the entrypoint and its full environment
   variable reference.

   Or run it directly with Node (no Docker):

   ```bash
   npm run build
   UA_HUB_URL=... UA_HUB_TOKEN=... TELEGRAM_BOT_TOKEN=... TELEGRAM_OWNER_IDS=123456789 \
     node bin/run-telegram-bot.mjs
   ```

4. Message the bot `/pending`. Tap Approve/Deny on any item.

`TELEGRAM_OWNER_IDS` (env) / `allowedUserIds` (API) is required and must be
non-empty — an unrestricted bot fails open, which this package refuses to
construct.

To wire it up programmatically instead of via the CLI entrypoint, see
`bin/run-telegram-bot.mjs` — it's a complete, short example of constructing
`UnifiedAgentClient`, `ApprovalClient`, and `TelegramApprovalBot` together
with graceful shutdown.

## Testing without a live bot or hub

Every test in `tests/` runs against an in-memory `TelegramApi` double and a
mocked `HubTransport` fetch — no network, no token, matching the pattern in
`@unified-agent/client`'s own test suite. Run:

```bash
npm test
```

## API surface

| Export | What it does |
|---|---|
| `ApprovalClient` | `listPending()`, `approve(id, reason?)`, `deny(id, reason?)` — idempotent-safe wrappers over the hub's approval tools. |
| `TelegramApprovalBot` | `/pending` command, Approve/Deny inline buttons, an allowlist gate, and a `run()` polling loop. |
| `createHttpTelegramApi` | Real Telegram Bot API client (long polling). Inject your own `TelegramApi` for tests or an alternative transport (webhook, another messaging platform). |
| `ApprovalConflictError` | Thrown when a decision genuinely conflicts with the row's current state (not a double-tap) — e.g. approving something someone else already denied. |
