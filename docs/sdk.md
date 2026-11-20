# TypeScript SDK

The TypeScript SDK in the Python repository (`packages/client`, package
`@unified-agent/client` 0.2.1, with `@unified-agent/protocol` 0.2.1) runs
against ua-rust. It has two halves:

- `UnifiedAgentClient` calls tools over MCP Streamable HTTP at `/mcp`.
- `ControlCenterClient` calls the Control Center's HTTP/JSON routes under
  `/api`.

Both send `Authorization: Bearer <token>`; the hub takes the identity, the
profile and every attribution from that token, never from the body.

## Pointing the SDK at ua-rust

```sh
ua token issue sdk-agent        # prints the token once
ua serve                        # http://127.0.0.1:8765
```

```ts
const hub = "http://127.0.0.1:8765";
const token = process.env.UA_AGENT_BEARER_TOKEN!;
const mcp = new UnifiedAgentClient({ url: `${hub}/mcp`, bearerToken: token });
const cc = new ControlCenterClient({ baseUrl: hub, bearerToken: token });
```

A remote hub must be reached through TLS and its host listed in
`allowed_hosts` (or be the host of `public_url`); see [auth.md](auth.md).
A human credential for `resolveApproval` is a token whose label is in
`human_identities`.

## Supported surface

| SDK method | Route | Tool |
|---|---|---|
| MCP methods (`taskList`, `memorySearch`, `approvalPending`, `dispatchDeliveryReceipt`, `callTool`, ...) | `POST /mcp` | the named tool |
| `createTask`, `updateTask` | `POST /api/tasks`, `POST /api/action/task` | `task_add`, `task_update` |
| `requestApproval`, `resolveApproval` | `POST /api/approvals/request`, `POST /api/action/approval` | the approval gate, `approval_resolve` |
| `capabilityCatalog` | `GET /api/capability-catalog` | the registry |
| `listSessions`, `listNodes` | `GET /api/sessions`, `GET /api/nodes` | `session_list`, `node_list` |
| `listRuns` | `GET /api/runs` | `run_list` |
| `getRun` | `GET /api/runs/{run_id}` | `run_get` |
| `platformManifest` | `GET /api/platform/manifest` | `platform_manifest` |
| `platformObject` | `GET /api/platform/objects/{kind}/{id}` | `platform_object_get` |
| `createEvidence` | `POST /api/evidence` | `evidence_append` |

Every route sits behind the same middleware as the rest of `/api` (bearer or
session cookie, host check, cross-site refusal, `X-CSRF-Token` on cookie
writes) and calls its tool through the governed registry, so profile, policy
rules, the approval gate and `tool_calls` telemetry apply as they do over MCP.
A write the gate parks answers `202` with `{approval_id, status: "pending",
tool, payload}`, which the SDK returns as `PendingApprovalResult`.

### Runs

`run_list` projects four stores into one row shape: `run_id`, `kind`,
`task_id`, `agent`, `status` (the store's own state, verbatim), `outcome`,
`started_at`, `ended_at`, `lease_expires_at`, `abandoned`, `abandon_reason`
and `links {self, task, delegation, dispatch_run, evidence}`, plus
kind-specific fields.

| `kind` | Store | `agent` | `abandoned` when |
|---|---|---|---|
| `dispatch` | `dispatch_runs` | `agent_label` | `expired`, or a live run whose lease lapsed |
| `session` | `agent_sessions` | `agent` | `abandoned`, or open with no heartbeat for 30 minutes |
| `workflow` | `workflow_runs` | `owner` | `running` with a lapsed lease |
| `node` | `node_dispatch` | the node's agent | `claimed` with a lapsed lease |

`abandoned` is judged on read; nothing is written. `links.evidence` lists the
ledger events that name the run (dispatch transitions, workflow completion,
node queue events; at most 50). Pages are newest first by `(started_at,
run_id)`; pass `next_cursor` back as `cursor`.

The SDK's `Run` schema accepts only the kinds `dispatch`, `selfpickup` and
`session`, so `GET /api/runs` without `kind` lists `dispatch` and `session`
rows. `kind=workflow`, `kind=node` and `kind=all` are opt-in for other HTTP
clients (the `run_list` tool lists every kind by default). This hub records
no self-pickup runs: `kind=selfpickup` is an empty page. `GET
/api/runs/{run_id}` answers for any kind, so `getRun` on a workflow run or
node item id fails the SDK's schema check rather than returning 404.

Node items are visible only to their requester, the node's agent, a
command's owner and operators, as with `node_items`; another caller gets 404.

### Platform objects

`platform_manifest` declares the object model with the original hub's
fields (`kind`, `uri`, `id_param`, `id_pattern`, `profile_tool`,
`lifecycle`, `terminal_states`, `event_kinds`, `schema`, ...). Served kinds:
`board` (collection), `task`, `run`, `approval`, `evidence_event`, `plan`,
`delegation`, `agent`, `session`, `memory_note`, `goal` and `comment`.
`work_product` is listed with `served: false`.

A read answers `{uri, <kind>: {...}}` (`{uri, tasks, count, truncated}` for
the board). Each kind is gated by its own `profile_tool` before storage is
read, so the call needs `platform_object_get` and that tool. Approval
payloads have secret-shaped fields redacted; an evidence event carries its
stored `payload` text verbatim plus `payload_parsed`. An unknown kind, an
unserved kind, an id that does not fit the kind's pattern and a missing row
are all 404; an id on a collection or none on an id kind is 400.

### Evidence

`evidence_append` writes one ledger event on a channel in the `sdk.`
namespace, attributed to the verified caller. `dedupe_key` is scoped to the
caller: a repeat appends nothing and returns the first event's ulid with
`inserted: false`, and another identity using the same key gets its own
event. The route answers `201` for a new event and `200` for a repeat (the
SDK accepts both). Payloads are capped at 64 KiB.

`GET /api/evidence` returns `evidence_report` as JSON (`task_id`,
`project_id`, `since`, `until`, `agent`, `project`, `pr`, `item`, `limit`).

## Not supported

| SDK method or route | Status |
|---|---|
| `queueHealth` (`GET /api/queue-health`) | not served (404) |
| `startNodeSession`, `cancelNodeSession`, `restartNodeSession` (`POST /api/action/node-session`) | not served; queue node work with the `node_dispatch` tool |
| `submitWorkProduct`, `releaseWorkProduct` (`/api/work-products*`) | `501`: work products are not being ported |
| `GET /api/evidence?format=csv\|markdown\|text\|pdf`, `cursor` | `400`: JSON only, no keyset paging |
| `GET /api/evidence/export`, `GET /api/platform/provenance-graph` | `501` |
| `org_unit`, `org_proposal`, `agent_token` platform objects | not declared |

`requestApproval` queues a request only for a tool that is gated (always
gated, `approval_tools`, or a policy rule); for any other tool it answers
`409`, so the SDK's live write suite needs `approval_tools` to include
`task_update`, which in turn parks its `updateTask` step.

## Verifying

`crates/ua-server/tests/platform.rs` calls each route the way
`ControlCenterClient` does and checks the keys its schemas require. Against
a running hub, the SDK's own live suite runs with:

```sh
cd packages/client
UA_SDK_CONFORMANCE_URL=http://127.0.0.1:8765/mcp UA_SDK_CONFORMANCE_TOKEN=... \
UA_SDK_WRITE_CONFORMANCE_URL=http://127.0.0.1:8765 UA_SDK_WRITE_CONFORMANCE_TOKEN=... \
UA_SDK_WRITE_CONFORMANCE_HUMAN_TOKEN=... npm run test:conformance:live
```

Use a disposable hub: the write suite creates a task, queues an approval and
appends evidence.
