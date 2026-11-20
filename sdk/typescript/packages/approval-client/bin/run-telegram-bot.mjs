#!/usr/bin/env node
/**
 * Entrypoint for the single-user pilot deployment: a Telegram
 * approval bot wired to a hub over the network, run as a long-lived process
 * (systemd unit, Docker container, or a bare `node` invocation).
 *
 * Configuration is entirely environment variables — no config file, no
 * secrets on the command line (visible in `ps`). Required:
 *
 *   UA_HUB_URL            Full MCP endpoint, e.g. http://127.0.0.1:8765/mcp
 *   UA_HUB_TOKEN           Per-agent bearer token for the hub
 *   TELEGRAM_BOT_TOKEN     From @BotFather
 *   TELEGRAM_OWNER_IDS     Comma-separated Telegram numeric user ids allowed
 *                          to use the bot. At least one required — see
 *                          TelegramApprovalBot's own refusal to construct
 *                          with an empty allowlist.
 *
 * Optional:
 *
 *   UA_OPERATOR_LABEL      Recorded as resolved_by on every decision.
 *                          Default: "Pilot Operator (via telegram)".
 *   UA_APPROVAL_TOOL_FILTER  Restrict /pending to one tool name.
 *   UA_POLL_IDLE_MS        Delay between empty getUpdates batches. Default 2000.
 */

import {
  ApprovalClient,
  TelegramApprovalBot,
  createHttpTelegramApi,
} from "@unified-agent/approval-client";
import { UnifiedAgentClient } from "@unified-agent/client";

function requireEnv(name) {
  const value = process.env[name];
  if (!value || !value.trim()) {
    console.error(`Missing required environment variable: ${name}`);
    process.exit(1);
  }
  return value;
}

const hubUrl = requireEnv("UA_HUB_URL");
const hubToken = requireEnv("UA_HUB_TOKEN");
const telegramToken = requireEnv("TELEGRAM_BOT_TOKEN");
const ownerIdsRaw = requireEnv("TELEGRAM_OWNER_IDS");

const ownerIds = new Set(
  ownerIdsRaw
    .split(",")
    .map((id) => id.trim())
    .filter(Boolean)
    .map((id) => {
      const n = Number(id);
      if (!Number.isInteger(n)) {
        console.error(`TELEGRAM_OWNER_IDS: '${id}' is not a valid Telegram numeric user id`);
        process.exit(1);
      }
      return n;
    }),
);

const operatorLabel = process.env.UA_OPERATOR_LABEL?.trim() || "Pilot Operator (via telegram)";
const idleDelayMs = Number(process.env.UA_POLL_IDLE_MS ?? 2000);

const client = new UnifiedAgentClient({
  url: hubUrl,
  bearerToken: hubToken,
  clientName: "unified-agent-approval-bot",
});

const bot = new TelegramApprovalBot({
  api: createHttpTelegramApi(telegramToken),
  approvalClient: new ApprovalClient(client, operatorLabel),
  allowedUserIds: ownerIds,
  idleDelayMs,
});

const controller = new AbortController();
let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${signal} received, stopping poll loop and closing hub session...`);
  controller.abort();
  await client.close();
  console.log("closed cleanly.");
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

console.log(
  `Approval bot starting: hub=${hubUrl} operator="${operatorLabel}" owners=${[...ownerIds].join(",")}`,
);
await bot.run(controller.signal);
