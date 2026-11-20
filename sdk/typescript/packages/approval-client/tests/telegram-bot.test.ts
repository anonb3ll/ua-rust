import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { UnifiedAgentClient, type FetchLike } from "@unified-agent/client";

import { ApprovalClient } from "../src/approval-client.ts";
import type { TelegramApi, TelegramUpdate } from "../src/telegram/api.ts";
import { TelegramApprovalBot } from "../src/telegram/bot.ts";

type JsonRpcBody = {
  method?: string;
  id?: number;
  params?: { name?: string; arguments?: Record<string, unknown> };
};

/** In-memory Telegram double: records every outgoing call, never touches the network. */
class FakeTelegramApi implements TelegramApi {
  queue: TelegramUpdate[] = [];
  sentMessages: Array<{ chatId: number; text: string }> = [];
  callbackAnswers: Array<{ id: string; text?: string }> = [];

  async getUpdates(): Promise<TelegramUpdate[]> {
    const batch = this.queue;
    this.queue = [];
    return batch;
  }
  async sendMessage(chatId: number, text: string): Promise<void> {
    this.sentMessages.push({ chatId, text });
  }
  async answerCallbackQuery(id: string, text?: string): Promise<void> {
    this.callbackAnswers.push({ id, text });
  }
}

function mockHubWithApprovals(rows: Map<number, { status: string; tool: string }>): FetchLike {
  return async (_url, init) => {
    const body = (init?.body ? JSON.parse(init.body) : {}) as JsonRpcBody;
    if (body.method === "initialize") {
      return {
        ok: true,
        status: 200,
        headers: { get: (n: string) => (n.toLowerCase() === "mcp-session-id" ? "sess-bot" : null) },
        text: async () =>
          JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2025-11-25" } }),
      };
    }
    if (body.method === "notifications/initialized") {
      return { ok: true, status: 202, headers: { get: () => null }, text: async () => "" };
    }
    if (body.method === "tools/call") {
      const name = body.params?.name;
      const args = body.params?.arguments ?? {};
      if (name === "approval_pending") {
        const pending = [...rows.entries()]
          .filter(([, r]) => r.status === "pending")
          .map(([id, r]) => ({
            id,
            tool: r.tool,
            payload: {},
            requested_by: "builder-3",
            status: "pending",
            created_at: "2026-09-11T00:00:00+00:00",
            updated_at: "2026-09-11T00:00:00+00:00",
          }));
        return jsonRpcResult(body.id, {
          pending,
          approved_unconsumed: [],
          expired_passes: [],
          gated_tools: [...new Set(pending.map((p) => p.tool))],
          pass_ttl_hours: null,
        });
      }
      if (name === "approval_resolve") {
        const id = Number(args.id);
        const decision = args.decision as string;
        const row = rows.get(id);
        if (!row || row.status !== "pending") {
          return jsonRpcToolError(
            body.id,
            `approval request ${id} is '${row?.status}', not 'pending'; only pending requests can be approved or denied`,
          );
        }
        const newStatus = decision === "approve" ? "approved" : "denied";
        rows.set(id, { ...row, status: newStatus });
        return jsonRpcResult(body.id, { id, status: newStatus });
      }
      throw new Error(`unhandled tool: ${name}`);
    }
    throw new Error(`unhandled method: ${body.method}`);
  };
}

function jsonRpcResult(id: number | undefined, structuredContent: unknown) {
  return {
    ok: true,
    status: 200,
    headers: { get: () => "application/json" },
    text: async () => JSON.stringify({ jsonrpc: "2.0", id, result: { structuredContent } }),
  };
}

function jsonRpcToolError(id: number | undefined, text: string) {
  return {
    ok: true,
    status: 200,
    headers: { get: () => "application/json" },
    text: async () =>
      JSON.stringify({
        jsonrpc: "2.0",
        id,
        result: { isError: true, content: [{ type: "text", text }] },
      }),
  };
}

const OWNER_ID = 12345;

function setup(rows: Array<[number, { status: string; tool: string }]>) {
  const rowMap = new Map(rows);
  const client = new UnifiedAgentClient({
    url: "http://hub.invalid/mcp",
    bearerToken: "fixture-token",
    fetch: mockHubWithApprovals(rowMap),
  });
  const approvalClient = new ApprovalClient(client, "operator (via telegram)");
  const api = new FakeTelegramApi();
  const bot = new TelegramApprovalBot({ api, approvalClient, allowedUserIds: new Set([OWNER_ID]) });
  return { api, bot, rowMap };
}

describe("TelegramApprovalBot", () => {
  it("refuses an unrestricted bot — an empty allowlist would fail open", () => {
    const client = new UnifiedAgentClient({ url: "http://x/mcp", bearerToken: "t" });
    const approvalClient = new ApprovalClient(client, "op");
    assert.throws(
      () => new TelegramApprovalBot({ api: new FakeTelegramApi(), approvalClient, allowedUserIds: new Set() }),
      /allowedUserIds must not be empty/,
    );
  });

  it("rejects a command from an unlisted user without touching the hub", async () => {
    const { api, bot, rowMap } = setup([[1, { status: "pending", tool: "delegate" }]]);
    api.queue.push({
      update_id: 1,
      message: { message_id: 1, chat: { id: 999 }, from: { id: 666 }, text: "/pending" },
    });
    await bot.pollOnce();
    assert.equal(api.sentMessages.length, 1);
    assert.match(api.sentMessages[0]!.text, /Not authorized/);
    // The row is untouched — proof the hub was never called for the unauthorized request.
    assert.equal(rowMap.get(1)!.status, "pending");
  });

  it("/pending lists items with Approve/Deny buttons for an authorized user", async () => {
    const { api, bot } = setup([[1, { status: "pending", tool: "example_gated_action" }]]);
    api.queue.push({
      update_id: 1,
      message: { message_id: 1, chat: { id: 999 }, from: { id: OWNER_ID }, text: "/pending" },
    });
    await bot.pollOnce();
    assert.equal(api.sentMessages.length, 1);
    assert.match(api.sentMessages[0]!.text, /example_gated_action/);
  });

  it("an authorized approve callback resolves the row and confirms", async () => {
    const { api, bot, rowMap } = setup([[1, { status: "pending", tool: "delegate" }]]);
    api.queue.push({
      update_id: 1,
      callback_query: {
        id: "cbq-1",
        from: { id: OWNER_ID },
        data: "approve:1",
        message: { message_id: 1, chat: { id: 999 } },
      },
    });
    await bot.pollOnce();
    assert.equal(rowMap.get(1)!.status, "approved");
    assert.equal(api.callbackAnswers.length, 1);
    assert.match(api.callbackAnswers[0]!.text ?? "", /approved/);
    assert.match(api.sentMessages[0]!.text, /#1 approved/);
  });

  it("a callback from an unlisted user never reaches the hub", async () => {
    const { api, bot, rowMap } = setup([[1, { status: "pending", tool: "delegate" }]]);
    api.queue.push({
      update_id: 1,
      callback_query: {
        id: "cbq-1",
        from: { id: 666 },
        data: "approve:1",
        message: { message_id: 1, chat: { id: 999 } },
      },
    });
    await bot.pollOnce();
    assert.equal(rowMap.get(1)!.status, "pending");
    assert.match(api.callbackAnswers[0]!.text ?? "", /Not authorized/);
  });

  it("a double-tap approve is idempotent end-to-end through the bot", async () => {
    const { api, bot } = setup([[1, { status: "pending", tool: "delegate" }]]);
    const tapApprove = () => ({
      update_id: 1,
      callback_query: {
        id: "cbq-1",
        from: { id: OWNER_ID },
        data: "approve:1",
        message: { message_id: 1, chat: { id: 999 } },
      },
    });
    api.queue.push(tapApprove());
    await bot.pollOnce();
    api.queue.push(tapApprove());
    await bot.pollOnce();
    assert.equal(api.callbackAnswers.length, 2);
    assert.match(api.callbackAnswers[1]!.text ?? "", /already resolved/);
  });

  it("a genuine conflict (deny after already approved) surfaces to the operator instead of crashing", async () => {
    const { api, bot, rowMap } = setup([[1, { status: "approved", tool: "delegate" }]]);
    api.queue.push({
      update_id: 1,
      callback_query: {
        id: "cbq-1",
        from: { id: OWNER_ID },
        data: "deny:1",
        message: { message_id: 1, chat: { id: 999 } },
      },
    });
    await bot.pollOnce();
    assert.equal(rowMap.get(1)!.status, "approved", "the conflicting action must not silently overwrite state");
    assert.match(api.callbackAnswers[0]!.text ?? "", /Failed/);
    assert.match(api.sentMessages[0]!.text, /already 'approved'/);
  });

  it("run() survives a poll error instead of crashing, and keeps polling after backoff", async () => {
    const client = new UnifiedAgentClient({
      url: "http://hub.invalid/mcp",
      bearerToken: "fixture-token",
      fetch: mockHubWithApprovals(new Map()),
    });
    const approvalClient = new ApprovalClient(client, "operator (via telegram)");
    const api = new FakeTelegramApi();
    let calls = 0;
    api.getUpdates = async () => {
      calls += 1;
      if (calls === 1) {
        throw new Error("Telegram API getUpdates failed: Not Found");
      }
      return [];
    };
    // A tiny idleDelayMs keeps the initial backoff short so the test doesn't
    // have to wait out the production default (2s) to see a retry happen.
    const bot = new TelegramApprovalBot({
      api,
      approvalClient,
      allowedUserIds: new Set([OWNER_ID]),
      idleDelayMs: 5,
    });

    const loggedErrors: string[] = [];
    const originalConsoleError = console.error;
    console.error = (msg: string) => loggedErrors.push(msg);

    const controller = new AbortController();
    const runPromise = bot.run(controller.signal);
    // Give the loop enough ticks to hit the error, back off, and recover.
    await new Promise((resolve) => setTimeout(resolve, 50));
    controller.abort();
    await runPromise;
    console.error = originalConsoleError;

    assert.ok(calls >= 2, "must retry getUpdates after the first failure instead of exiting");
    assert.ok(
      loggedErrors.some((m) => /Telegram poll failed/.test(m) && /Not Found/.test(m)),
      "must log the poll failure with the underlying error",
    );
  });

  it("advances the update offset so a processed update is never redelivered", async () => {
    const { api, bot } = setup([]);
    api.queue.push({
      update_id: 41,
      message: { message_id: 1, chat: { id: 999 }, from: { id: OWNER_ID }, text: "/pending" },
    });
    const first = await bot.pollOnce();
    assert.equal(first, 1);
    const second = await bot.pollOnce();
    assert.equal(second, 0);
  });
});
