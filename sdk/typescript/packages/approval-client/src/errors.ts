/** Errors raised by the approval client. Never include bearer tokens or full request payloads. */

export class ApprovalClientError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ApprovalClientError";
    this.code = code;
  }
}

/**
 * A resolve call found the approval already in a *different* terminal state
 * than the one requested — e.g. you tried to approve a request someone else
 * already denied. This is a real conflict, not a double-tap: never silently
 * swallow it. Distinct from the idempotent case (already resolved to the
 * *same* outcome you requested), which {@link ApprovalClient.approve} /
 * {@link ApprovalClient.deny} resolve without throwing.
 */
export class ApprovalConflictError extends ApprovalClientError {
  readonly approvalId: number;
  readonly requestedDecision: "approve" | "deny";
  readonly actualStatus: string;

  constructor(approvalId: number, requestedDecision: "approve" | "deny", actualStatus: string) {
    super(
      "approval_conflict",
      `approval ${approvalId}: requested '${requestedDecision}' but it is already '${actualStatus}'`,
    );
    this.name = "ApprovalConflictError";
    this.approvalId = approvalId;
    this.requestedDecision = requestedDecision;
    this.actualStatus = actualStatus;
  }
}

/** The caller (e.g. a Telegram user id) is not on the configured allowlist. Fail closed. */
export class UnauthorizedOperatorError extends ApprovalClientError {
  constructor(detail: string) {
    super("unauthorized_operator", `operator not authorized: ${detail}`);
    this.name = "UnauthorizedOperatorError";
  }
}
