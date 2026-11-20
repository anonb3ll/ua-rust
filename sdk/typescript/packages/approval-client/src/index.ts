export { ApprovalClient } from "./approval-client.js";
export type {
  ApprovalDecisionResult,
  PendingApprovalView,
  PendingApprovalsView,
} from "./approval-client.js";

export {
  ApprovalClientError,
  ApprovalConflictError,
  UnauthorizedOperatorError,
} from "./errors.js";

export { TelegramApprovalBot } from "./telegram/bot.js";
export type { TelegramApprovalBotOptions } from "./telegram/bot.js";

export { createHttpTelegramApi } from "./telegram/api.js";
export type {
  InlineKeyboardButton,
  TelegramApi,
  TelegramCallbackQuery,
  TelegramMessage,
  TelegramUpdate,
  TelegramUser,
} from "./telegram/api.js";
