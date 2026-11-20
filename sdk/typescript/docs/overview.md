# Overview

## Packages

| Package | Role |
|---|---|
| `@unified-agent/protocol` | Zod source of truth, exported to JSON Schema and generated Pydantic models |
| `@unified-agent/client` | Typed MCP Streamable HTTP client and Control Center HTTP/JSON client |
| `@unified-agent/approval-client` | Approval forwarder over `approval_pending` / `approval_resolve`, with a Telegram adapter |

## Invariant

The SDK is a typed remote. Every tool call, including every mutation, runs on
the hub. Policy, approvals, sandboxing, identity, memory, tasks and vault
writes are not reimplemented here.

## Reliability

- An expired MCP session (`HTTP 404`) re-handshakes once, then retries the
  same call.
- A transient transport failure is retried only when the arguments carry an
  `idempotency_key` or `CallToolOptions.retryable` is set. A mutation without
  an idempotency key is never retried blindly.
- `HubAuthError` and `HubRpcError` are never retried.
- A malformed typed response raises `HubValidationError`.
- An `AbortSignal` sends `notifications/cancelled` once.

## Publication

The packages keep `"private": true`. Publishing to npm is a separate decision
and is not done from this repository yet.
