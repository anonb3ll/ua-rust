/**
 * Minimal Telegram Bot API surface, typed narrowly to what the approval
 * adapter needs. Injectable (see {@link TelegramApi}) so tests never touch
 * a real bot token or the network — same pattern as `FetchLike` in
 * `@unified-agent/client`'s `HubTransport`.
 */

export type TelegramUser = {
  id: number;
  username?: string;
};

export type TelegramMessage = {
  message_id: number;
  chat: { id: number };
  from?: TelegramUser;
  text?: string;
};

export type TelegramCallbackQuery = {
  id: string;
  from: TelegramUser;
  data?: string;
  message?: TelegramMessage;
};

export type TelegramUpdate = {
  update_id: number;
  message?: TelegramMessage;
  callback_query?: TelegramCallbackQuery;
};

export type InlineKeyboardButton = { text: string; callback_data: string };

export interface TelegramApi {
  /** Long-poll for updates after `offset`. Returns an empty array on timeout. */
  getUpdates(offset: number): Promise<TelegramUpdate[]>;
  sendMessage(
    chatId: number,
    text: string,
    options?: { inlineKeyboard?: InlineKeyboardButton[][] },
  ): Promise<void>;
  answerCallbackQuery(callbackQueryId: string, text?: string): Promise<void>;
}

/** Real Telegram Bot API over HTTPS. Never logs the token. */
export function createHttpTelegramApi(
  token: string,
  fetchImpl: typeof fetch = fetch,
): TelegramApi {
  const base = `https://api.telegram.org/bot${token}`;

  async function call(method: string, body: Record<string, unknown>): Promise<unknown> {
    const res = await fetchImpl(`${base}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = (await res.json()) as { ok: boolean; result?: unknown; description?: string };
    if (!json.ok) {
      // Telegram's own error text never contains the token — safe to surface.
      throw new Error(`Telegram API ${method} failed: ${json.description ?? "unknown error"}`);
    }
    return json.result;
  }

  return {
    async getUpdates(offset: number): Promise<TelegramUpdate[]> {
      const result = await call("getUpdates", { offset, timeout: 30 });
      return Array.isArray(result) ? (result as TelegramUpdate[]) : [];
    },
    async sendMessage(chatId, text, options): Promise<void> {
      await call("sendMessage", {
        chat_id: chatId,
        text,
        parse_mode: "HTML",
        ...(options?.inlineKeyboard
          ? { reply_markup: { inline_keyboard: options.inlineKeyboard } }
          : {}),
      });
    },
    async answerCallbackQuery(callbackQueryId, text): Promise<void> {
      await call("answerCallbackQuery", {
        callback_query_id: callbackQueryId,
        ...(text !== undefined ? { text } : {}),
      });
    },
  };
}
