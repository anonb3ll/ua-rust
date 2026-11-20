/**
 * Telegram command/API adapter over {@link ApprovalClient}.
 *
 * Scope, deliberately narrow for a single-user pilot:
 * - `/pending` lists pending approvals with gated-tool context and pass TTL,
 *   each with inline Approve/Deny buttons.
 * - The buttons drive approve/deny through the same idempotent-safe path as
 *   calling `ApprovalClient` directly — a double-tap is safe.
 * - Every command and callback is checked against `allowedUserIds` *before*
 *   touching the hub. An unlisted user gets a fixed "not authorized" reply
 *   and nothing else happens — fail closed, not "best effort."
 * - This adapter cannot approve or deny anything on its own initiative. It
 *   only ever forwards an explicit human tap/command to the hub.
 */

import type { ApprovalClient, PendingApprovalView } from "../approval-client.js";
import { ApprovalConflictError } from "../errors.js";
import type { InlineKeyboardButton, TelegramApi, TelegramUpdate } from "./api.js";

export type TelegramApprovalBotOptions = {
  api: TelegramApi;
  approvalClient: ApprovalClient;
  /** Only these Telegram user ids may issue commands. Required — no open-door default. */
  allowedUserIds: ReadonlySet<number>;
  /** Poll delay when getUpdates returns nothing (real long-polling makes this rare). Default 2000ms. */
  idleDelayMs?: number;
};

const CALLBACK_RE = /^(approve|deny):(\d+)$/;

/** Cap on the exponential poll-error backoff — a wedged Telegram
 * API or a revoked token must not go longer than this between retries. */
const MAX_POLL_BACKOFF_MS = 60_000;

export class TelegramApprovalBot {
  private readonly api: TelegramApi;
  private readonly approvalClient: ApprovalClient;
  private readonly allowedUserIds: ReadonlySet<number>;
  private readonly idleDelayMs: number;
  private offset = 0;

  constructor(options: TelegramApprovalBotOptions) {
    if (options.allowedUserIds.size === 0) {
      throw new Error("allowedUserIds must not be empty — an unrestricted bot fails open");
    }
    this.api = options.api;
    this.approvalClient = options.approvalClient;
    this.allowedUserIds = options.allowedUserIds;
    this.idleDelayMs = options.idleDelayMs ?? 2000;
  }

  /** Process exactly one batch of updates. Exposed directly so tests don't need real polling. */
  async pollOnce(): Promise<number> {
    const updates = await this.api.getUpdates(this.offset);
    for (const update of updates) {
      this.offset = Math.max(this.offset, update.update_id + 1);
      await this.handleUpdate(update);
    }
    return updates.length;
  }

  /**
   * Run until `signal` aborts.
   *
   * A poll failure (Telegram API error, network blip, expired token) does
   * not crash the process: it's logged and the loop backs off
   * exponentially — capped at {@link MAX_POLL_BACKOFF_MS} — instead of
   * exiting, since a `docker compose`/systemd `restart: unless-stopped`
   * policy would otherwise busy-loop container restarts on the first
   * transient hiccup. Backoff resets to `idleDelayMs` after a successful
   * poll.
   */
  async run(signal?: AbortSignal): Promise<void> {
    let backoffMs = this.idleDelayMs;
    while (!signal?.aborted) {
      try {
        const processed = await this.pollOnce();
        backoffMs = this.idleDelayMs;
        if (processed === 0 && !signal?.aborted) {
          await sleep(this.idleDelayMs, signal);
        }
      } catch (err) {
        if (signal?.aborted) break;
        console.error(`Telegram poll failed, retrying in ${backoffMs}ms: ${describeError(err)}`);
        await sleep(backoffMs, signal);
        backoffMs = Math.min(backoffMs * 2, MAX_POLL_BACKOFF_MS);
      }
    }
  }

  private async handleUpdate(update: TelegramUpdate): Promise<void> {
    if (update.callback_query) {
      await this.handleCallback(update.callback_query.id, update.callback_query);
      return;
    }
    if (update.message?.text) {
      await this.handleMessage(update.message.chat.id, update.message.from, update.message.text);
    }
  }

  private isAuthorized(userId: number | undefined): boolean {
    return userId !== undefined && this.allowedUserIds.has(userId);
  }

  private async handleMessage(
    chatId: number,
    from: { id: number } | undefined,
    text: string,
  ): Promise<void> {
    if (!this.isAuthorized(from?.id)) {
      await this.api.sendMessage(chatId, "Not authorized.");
      return;
    }
    const command = text.trim().split(/\s+/)[0]?.toLowerCase();
    if (command === "/pending" || command === "/start") {
      await this.sendPendingList(chatId);
      return;
    }
    await this.api.sendMessage(chatId, "Commands: /pending");
  }

  private async handleCallback(
    callbackQueryId: string,
    query: { from: { id: number }; data?: string; message?: { chat: { id: number } } },
  ): Promise<void> {
    if (!this.isAuthorized(query.from.id)) {
      await this.api.answerCallbackQuery(callbackQueryId, "Not authorized.");
      return;
    }
    const match = query.data ? CALLBACK_RE.exec(query.data) : null;
    if (!match) {
      await this.api.answerCallbackQuery(callbackQueryId, "Unrecognized action.");
      return;
    }
    const decision = match[1] as "approve" | "deny";
    const id = Number(match[2]);
    const chatId = query.message?.chat.id;

    try {
      const result =
        decision === "approve"
          ? await this.approvalClient.approve(id)
          : await this.approvalClient.deny(id);
      const suffix = result.idempotent ? " (already resolved — no change)" : "";
      await this.api.answerCallbackQuery(callbackQueryId, `${result.status}${suffix}`);
      if (chatId !== undefined) {
        await this.api.sendMessage(chatId, `#${id} ${result.status}${suffix}.`);
      }
    } catch (err) {
      await this.api.answerCallbackQuery(callbackQueryId, "Failed — see chat.");
      if (chatId !== undefined) {
        await this.api.sendMessage(chatId, `#${id} action failed: ${describeError(err)}`);
      }
    }
  }

  private async sendPendingList(chatId: number): Promise<void> {
    const view = await this.approvalClient.listPending();
    if (view.pending.length === 0) {
      await this.api.sendMessage(chatId, "No pending approvals.");
      return;
    }
    for (const item of view.pending) {
      await this.api.sendMessage(chatId, formatPendingItem(item), {
        inlineKeyboard: approveDenyKeyboard(item.id),
      });
    }
  }
}

function approveDenyKeyboard(id: number): InlineKeyboardButton[][] {
  return [
    [
      { text: "✅ Approve", callback_data: `approve:${id}` },
      { text: "❌ Deny", callback_data: `deny:${id}` },
    ],
  ];
}

function formatPendingItem(item: PendingApprovalView): string {
  const lines = [
    `<b>#${item.id}</b> — <code>${escapeHtml(item.tool)}</code>`,
    `requested by: ${item.requestedBy ?? "unknown"}`,
  ];
  if (item.expiresInHours !== null) {
    lines.push(`expires in: ${item.expiresInHours}h`);
  }
  const payloadPreview = JSON.stringify(item.payload);
  if (payloadPreview.length > 0 && payloadPreview !== "{}") {
    lines.push(`<code>${escapeHtml(truncate(payloadPreview, 200))}</code>`);
  }
  return lines.join("\n");
}

function describeError(err: unknown): string {
  if (err instanceof ApprovalConflictError) {
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
  });
}
