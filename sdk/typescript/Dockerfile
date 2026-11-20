# Single-user pilot deployment: the Telegram approval bot on
# @unified-agent/approval-client. "Boring deployment" is the explicit goal —
# one image, env-var configuration, no state to persist (the hub owns all
# durable state; this bot is a stateless forwarder).
#
# Build:
#   docker build -t unified-agent-approval-bot .
# Run:
#   docker run --rm \
#     -e UA_HUB_URL=http://host.docker.internal:8765/mcp \
#     -e UA_HUB_TOKEN=... \
#     -e TELEGRAM_BOT_TOKEN=... \
#     -e TELEGRAM_OWNER_IDS=123456789 \
#     unified-agent-approval-bot
# Or see packages/approval-client/docker-compose.yml.

FROM node:20-alpine AS builder
WORKDIR /app

# Package manifests first for better layer caching on rebuilds.
COPY package.json package-lock.json ./
COPY packages/protocol/package.json packages/protocol/package.json
COPY packages/client/package.json packages/client/package.json
COPY packages/approval-client/package.json packages/approval-client/package.json
RUN npm ci

COPY packages/protocol packages/protocol
COPY packages/client packages/client
COPY packages/approval-client packages/approval-client
RUN npm run build -w @unified-agent/protocol \
 && npm run build -w @unified-agent/client \
 && npm run build -w @unified-agent/approval-client

FROM node:20-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=builder /app /app
# node:20-alpine ships an unprivileged "node" user — no bespoke role setup needed.
USER node

ENTRYPOINT ["node", "packages/approval-client/bin/run-telegram-bot.mjs"]
