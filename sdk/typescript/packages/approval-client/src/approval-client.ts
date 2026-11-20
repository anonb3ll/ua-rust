/**
 * Governed approval client.
 *
 * A thin, typed wrapper over `UnifiedAgentClient.approvalPending()` /
 * `.approvalResolve()`. Every decision it makes is a direct, unmodified call
 * to the hub's `approval_resolve` tool — this client mints no authority of
 * its own. What it adds on top:
 *
 * - **Idempotent decisions.** A phone-first UI (a double-tapped button, a
 *   retried webhook) can call `approve`/`deny` twice for the same id. The
 *   hub's `approval_resolve` rejects a second call on a non-'pending' row
 *   with a `ToolError` naming the row's current status. This client parses
 *   that specific shape and treats "already resolved to the outcome I just
 *   asked for" as success, not an error — while a genuine conflict (approved
 *   after someone else already denied it) still raises
 *   {@link ApprovalConflictError} rather than being silently absorbed.
 * - **Typed, phone-friendly views** of the pending queue (gated tool,
 *   requester, pass TTL) instead of the raw hub row shape.
 *
 * Policy stays on the hub. This client cannot approve, deny, or extend
 * anything the hub itself would refuse.
 */

import { HubRpcError, type ApprovalType, type UnifiedAgentClient } from "@unified-agent/client";

import { ApprovalConflictError } from "./errors.js";

export type PendingApprovalView = {
  id: number;
  tool: string;
  payload: Record<string, unknown>;
  requestedBy: string | null;
  createdAt: string;
  expiresAt: string | null;
  expiresInHours: number | null;
};

export type PendingApprovalsView = {
  pending: PendingApprovalView[];
  /** Tools currently gated behind approval on this hub — context for an operator deciding blind. */
  gatedTools: string[];
  /** Default one-shot pass lifetime once approved, if the hub reports one. */
  passTtlHours: number | null;
};

export type ApprovalDecisionResult = {
  id: number;
  decision: "approve" | "deny";
  /** The row's resulting status ("approved" / "denied"). */
  status: string;
  resolvedBy: string;
  /**
   * True when this call didn't actually change anything — the row was
   * already resolved to the requested outcome (a double-tap or retry). The
   * decision still "succeeded" from the caller's point of view.
   */
  idempotent: boolean;
};

/** Matches the tool error text the hub's `approval_resolve` returns. */
const ALREADY_RESOLVED_RE = /approval request \d+ is '([a-z_]+)', not 'pending'/;

function toView(row: ApprovalType): PendingApprovalView {
  return {
    id: row.id,
    tool: row.tool,
    payload: row.payload,
    requestedBy: row.requested_by ?? null,
    createdAt: row.created_at,
    expiresAt: row.expires_at ?? null,
    expiresInHours: row.expires_in_hours ?? null,
  };
}

export class ApprovalClient {
  private readonly client: UnifiedAgentClient;
  private readonly operatorLabel: string;

  /**
   * @param client Hub-backed SDK client — already authenticated.
   * @param operatorLabel Who this client resolves approvals as, e.g.
   *   `"operator (via telegram)"`. Recorded on every decision for the audit
   *   trail; never the raw messaging-platform user id, so the audit log
   *   reads the same whether the operator used Telegram, a CLI, or the /ui.
   */
  constructor(client: UnifiedAgentClient, operatorLabel: string) {
    if (!operatorLabel.trim()) {
      throw new Error("operatorLabel is required — every decision must be attributable");
    }
    this.client = client;
    this.operatorLabel = operatorLabel;
  }

  async listPending(params: { tool?: string; limit?: number } = {}): Promise<PendingApprovalsView> {
    const result = await this.client.approvalPending(params);
    return {
      pending: result.pending.map(toView),
      gatedTools: result.gated_tools,
      passTtlHours: result.pass_ttl_hours ?? null,
    };
  }

  async approve(id: number, reason?: string): Promise<ApprovalDecisionResult> {
    return this.resolve(id, "approve", reason);
  }

  async deny(id: number, reason?: string): Promise<ApprovalDecisionResult> {
    return this.resolve(id, "deny", reason);
  }

  private async resolve(
    id: number,
    decision: "approve" | "deny",
    reason: string | undefined,
  ): Promise<ApprovalDecisionResult> {
    try {
      const row = await this.client.approvalResolve({
        id,
        decision,
        resolved_by: this.operatorLabel,
        ...(reason !== undefined ? { reason } : {}),
      });
      return {
        id,
        decision,
        status: typeof row.status === "string" ? row.status : decision === "approve" ? "approved" : "denied",
        resolvedBy: this.operatorLabel,
        idempotent: false,
      };
    } catch (err) {
      const reconciled = reconcileAlreadyResolved(err, id, decision);
      if (reconciled) {
        return { ...reconciled, resolvedBy: this.operatorLabel };
      }
      throw err;
    }
  }
}

/**
 * Interpret a `HubRpcError` from a rejected `approval_resolve` call. Returns
 * a reconciled idempotent result when the row was already resolved to
 * *exactly* the outcome the caller asked for; throws {@link
 * ApprovalConflictError} when it was resolved to something else; returns
 * `null` for any other error shape (transport failures, auth, unrelated
 * ToolErrors) so the caller re-throws it unchanged — this function only ever
 * narrows one specific, known-safe case.
 */
function reconcileAlreadyResolved(
  err: unknown,
  id: number,
  decision: "approve" | "deny",
): Omit<ApprovalDecisionResult, "resolvedBy"> | null {
  if (!(err instanceof HubRpcError)) {
    return null;
  }
  const match = ALREADY_RESOLVED_RE.exec(err.message);
  if (!match) {
    return null;
  }
  const actualStatus = match[1]!;
  const wantedStatus = decision === "approve" ? "approved" : "denied";
  if (actualStatus === wantedStatus) {
    return { id, decision, status: actualStatus, idempotent: true };
  }
  throw new ApprovalConflictError(id, decision, actualStatus);
}
