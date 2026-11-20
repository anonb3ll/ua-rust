import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { UnifiedAgentClient, HubAuthError, type FetchLike } from "@unified-agent/client";

import { ApprovalClient } from "../src/approval-client.ts";
import { ApprovalConflictError } from "../src/errors.ts";

type JsonRpcBody = {
  method?: string;
  id?: number;
  params?: { name?: string; arguments?: Record<string, unknown> };
};

/**
 * A hub double whose approval_pending/approval_resolve behavior is driven by
 * a small in-memory row set, so tests can exercise real state transitions
 * (pending -> approved, a second call hitting a non-pending row) instead of
 * canned one-shot responses.
 */
function mockHubWithApprovals(rows: Map<number, { status: string; tool: string }>): FetchLike {
  return async (_url, init) => {
    const body = (init?.body ? JSON.parse(init.body) : {}) as JsonRpcBody;
    if (body.method === "initialize") {
      return {
        ok: true,
        status: 200,
        headers: { get: (n: string) => (n.toLowerCase() === "mcp-session-id" ? "sess-approval" : null) },
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
            payload: { action: "restart" },
            requested_by: "builder-3",
            status: "pending",
            created_at: "2026-09-11T00:00:00+00:00",
            updated_at: "2026-09-11T00:00:00+00:00",
            expires_in_hours: 24,
          }));
        return jsonRpcResult(body.id, {
          pending,
          approved_unconsumed: [],
          expired_passes: [],
          gated_tools: [...new Set(pending.map((p) => p.tool))],
          pass_ttl_hours: 24,
        });
      }
      if (name === "approval_resolve") {
        const id = Number(args.id);
        const decision = args.decision as string;
        const row = rows.get(id);
        if (!row) {
          return jsonRpcToolError(body.id, `no approval request with id ${id}`);
        }
        if (row.status !== "pending") {
          return jsonRpcToolError(
            body.id,
            `approval request ${id} is '${row.status}', not 'pending'; only pending requests can be approved or denied`,
          );
        }
        const newStatus = decision === "approve" ? "approved" : "denied";
        rows.set(id, { ...row, status: newStatus });
        return jsonRpcResult(body.id, {
          id,
          tool: row.tool,
          status: newStatus,
          resolved_by: String(args.resolved_by),
          created_at: "2026-09-11T00:00:00+00:00",
          updated_at: "2026-09-11T00:01:00+00:00",
        });
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

function setup(rows: Array<[number, { status: string; tool: string }]>) {
  const rowMap = new Map(rows);
  const client = new UnifiedAgentClient({
    url: "http://hub.invalid/mcp",
    bearerToken: "fixture-token",
    fetch: mockHubWithApprovals(rowMap),
  });
  return { client, approvals: new ApprovalClient(client, "operator (via telegram)"), rowMap };
}

describe("ApprovalClient", () => {
  it("requires an operator label — a decision must be attributable", () => {
    const client = new UnifiedAgentClient({ url: "http://x/mcp", bearerToken: "t" });
    assert.throws(() => new ApprovalClient(client, ""), /operatorLabel is required/);
  });

  it("lists pending approvals with gated-tool context and pass TTL", async () => {
    const { approvals } = setup([[1, { status: "pending", tool: "example_gated_action" }]]);
    const view = await approvals.listPending();
    assert.equal(view.pending.length, 1);
    assert.equal(view.pending[0]!.tool, "example_gated_action");
    assert.equal(view.pending[0]!.expiresInHours, 24);
    assert.deepEqual(view.gatedTools, ["example_gated_action"]);
    assert.equal(view.passTtlHours, 24);
  });

  it("approve() resolves a pending row and attributes it to the operator label", async () => {
    const { approvals, rowMap } = setup([[1, { status: "pending", tool: "delegate" }]]);
    const result = await approvals.approve(1);
    assert.equal(result.status, "approved");
    assert.equal(result.resolvedBy, "operator (via telegram)");
    assert.equal(result.idempotent, false);
    assert.equal(rowMap.get(1)!.status, "approved");
  });

  it("deny() resolves a pending row", async () => {
    const { approvals } = setup([[1, { status: "pending", tool: "delegate" }]]);
    const result = await approvals.deny(1, "not now");
    assert.equal(result.status, "denied");
    assert.equal(result.idempotent, false);
  });

  it("a double-approve is idempotent, not an error", async () => {
    const { approvals } = setup([[1, { status: "pending", tool: "delegate" }]]);
    const first = await approvals.approve(1);
    assert.equal(first.idempotent, false);
    const second = await approvals.approve(1);
    assert.equal(second.idempotent, true);
    assert.equal(second.status, "approved");
  });

  it("approving something already denied by someone else is a real conflict, not swallowed", async () => {
    const { approvals } = setup([[1, { status: "denied", tool: "delegate" }]]);
    await assert.rejects(
      () => approvals.approve(1),
      (err: unknown) => {
        assert.ok(err instanceof ApprovalConflictError);
        assert.equal(err.approvalId, 1);
        assert.equal(err.requestedDecision, "approve");
        assert.equal(err.actualStatus, "denied");
        return true;
      },
    );
  });

  it("an unrelated hub error (e.g. unknown id) is not mistaken for idempotency", async () => {
    const { approvals } = setup([]);
    await assert.rejects(() => approvals.approve(999), /no approval request with id 999/);
  });

  it("a transport/auth failure propagates unchanged — never reinterpreted as a decision outcome", async () => {
    const client = new UnifiedAgentClient({
      url: "http://hub.invalid/mcp",
      bearerToken: "bad",
      fetch: async () => ({
        ok: false,
        status: 401,
        headers: { get: () => "application/json" },
        text: async () => "invalid token",
      }),
    });
    const approvals = new ApprovalClient(client, "operator (via telegram)");
    await assert.rejects(() => approvals.approve(1), HubAuthError);
  });
});
