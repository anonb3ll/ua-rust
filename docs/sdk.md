# TypeScript SDK

The TypeScript SDK lives in this repository under
[`sdk/typescript`](../sdk/typescript/README.md): `@unified-agent/client`
0.2.1, `@unified-agent/protocol` 0.2.1 and `@unified-agent/approval-client`
0.1.0, an npm workspace that is not published. The client has two halves:

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
| `getRun` | `GET /api/runs/{run_id}` | `run_get` (SDK kinds unless `kind` is given) |
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
/api/runs/{run_id}` looks in the same kinds, so `getRun` on a workflow run
or node item id is 404 rather than a row the SDK's schema rejects; pass
`?kind=workflow`, `?kind=node` or `?kind=all` to read one. The `run_get`
tool takes the same `kind` (or `kinds`) and, like `run_list`, looks in
every store when it is omitted. The platform `run` object resolves every
kind.

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
read, as if the caller had called that tool: the profile must allow it, and
the policy file's tool, role, bind and `default_action` rules for it apply,
with the refusal codes a direct call would get (`role_denied`,
`policy_deny`, `default_deny`, ...). A tool that a `require_approval` rule
or `approval_tools` sends through the gate is refused here
(`approval_required`); call it directly. So the call needs
`platform_object_get` and that tool. Approval payloads have secret-shaped
fields redacted; an evidence event carries its stored `payload` text
verbatim plus `payload_parsed`, and an `sdk.` event adds a `trust` label
(`level: untrusted`, `source: sdk_evidence`, `author`): its payload is data
a client wrote, not instructions. An unknown kind, an
unserved kind, an id that does not fit the kind's pattern and a missing row
are all 404; an id on a collection or none on an id kind is 400.

### Evidence

`evidence_append` writes one ledger event on a channel in the `sdk.`
namespace, attributed to the verified caller. `dedupe_key` is scoped to the
caller: a repeat appends nothing and returns the first event's ulid with
`inserted: false`, and another identity using the same key gets its own
event. The route answers `201` for a new event and `200` for a repeat (the
SDK accepts both). Payloads are capped at 64 KiB.

Appends are budgeted per identity over a rolling hour:
`evidence_append_max_per_hour` events (default 120) and
`evidence_append_max_bytes_per_hour` serialized payload bytes (default 2
MiB). Past either, the append is refused with `403` and `reason_code:
"rate_limited"`. The budget is counted from the ledger (the caller's `sdk.`
events in the last hour), so a restart does not reset it. A deduplicated
repeat appends nothing and is never refused.

`GET /api/evidence` returns `evidence_report` as JSON (`task_id`,
`project_id`, `since`, `until`, `agent`, `project`, `pr`, `item`, `limit`).

Client evidence never attributes a task. An `sdk.` event's `task_id` is
whatever the client wrote, so the report leaves those events out of a
record's `events`, `participants`, `proof` and tool-call window, and the
`agent` filter does not match on them. Each record lists them apart under
`client_asserted`:

```json
{
  "asserted_by": "client", "verified": false, "counts_as_attribution": false,
  "total": 1, "truncated": false,
  "events": [{ "ulid": "...", "channel": "sdk.claim", "originator": "builder-2",
               "created_at": "...", "entry_hash": "...", "payload_bytes": 52,
               "payload_inline": true, "payload": { "task_id": 41 },
               "platform": { "kind": "evidence_event", "uri": "unified-agent://evidence/..." },
               "trust": { "level": "untrusted", "source": "sdk_evidence", "author": "builder-2" } }]
}
```

At most 20 events are listed per record; a payload over 4 KiB is not
inlined (`payload_inline: false`) and is read through its `platform`
reference. `event_log_query` and `GET /api/events/stream` label `sdk.`
events the same way.

## Not supported

| SDK method or route | Status |
|---|---|
| `queueHealth` (`GET /api/queue-health`) | not served (404) |
| `startNodeSession`, `cancelNodeSession`, `restartNodeSession` (`POST /api/action/node-session`) | not served; queue node work with the `node_dispatch` tool |
| `submitWorkProduct`, `releaseWorkProduct` (`/api/work-products*`) | `501`: not ported (see below) |
| `GET /api/evidence?format=csv\|markdown\|text\|pdf`, `cursor` | `400`: JSON only, no keyset paging |
| `GET /api/evidence/export`, `GET /api/platform/provenance-graph` | `501` |
| `org_unit`, `org_proposal`, `agent_token` platform objects | not declared |

Work products (submit, named-reviewer approval, release) are not ported
pending an explicit product decision; hub task #2658 lists the options.
Until that decision, `/api/work-products*` answers `501` and the manifest
lists `work_product` with `served: false`.

`requestApproval` (`POST /api/approvals/request`, body `{tool, payload}`)
queues a human approval ahead of a call and never runs anything. This is the
settled contract:

| Status | When |
|---|---|
| `202 {approval_id, status: "pending", tool, payload}` | A new or identical open request for a gated tool. |
| `200` with `status` `approved` or `denied` | An identical request already decided (a live pass is reported, never consumed). |
| `400` | A malformed body, or a `payload` the tool's typed arguments refuse (unknown or missing fields). A caller without a profile limit also gets `400` for an unknown tool. |
| `401` | No verified identity. |
| `403` | The same refusal a call would get: the caller's profile cannot call the tool (or `approval_pending`), the session grant, a policy rule or the prod-action check refuses it. An unknown tool reads the same for a profile-bound caller, so the route cannot enumerate tools. |
| `409` | The tool is not approval-gated (always gated, `approval_tools`, or a policy `require_approval` rule): there is nothing to approve. Also for a tool whose handler binds its approval to values it resolves when called (dispatch and node work, `run_cmd`, workflows and routines, cycle transitions, audit remediation, OAuth revoke, config revisions, managed secrets, MCP registrations and gateway writes, relay sends, the skill registry, harness config publishing and node config reports): call the tool instead. |
| `413` | `payload` over 16 KiB. |
| `429` | The requester holds 20 open requests, or filed 60 in the last hour that are still open or that it withdrew itself; the message names which. |

The stored payload is the one the tool's own gate binds: a tool with a
secret argument binds a projection instead (`agent_token_issue` and
`agent_token_rotate` bind the label and a keyed fingerprint of the token,
never the value). An approved request is a one-time pass that the
requester's next identical call consumes within `approval_pass_ttl_hours`;
the requester cannot approve its own request.

The SDK's live write suite still requests approval for `task_update`, which
nothing gates, so that case gets `409` (see
[known gaps](../sdk/typescript/docs/known-gaps.md)); it is to be changed to
request approval for a gated tool. `crew_intervene` is one: always approval-gated
with no configuration, gated by the registry rather than its handler (so it
is requestable here), and callable with a developer-profile token. Its
payload is `{session_id, message}`.

## Verifying

`crates/ua-server/tests/platform.rs` calls each route the way
`ControlCenterClient` does and checks the keys its schemas require. Against
a running hub, the SDK's own live suite runs with:

```sh
cd sdk/typescript
UA_SDK_CONFORMANCE_URL=http://127.0.0.1:8765/mcp UA_SDK_CONFORMANCE_TOKEN=... \
UA_SDK_WRITE_CONFORMANCE_URL=http://127.0.0.1:8765 UA_SDK_WRITE_CONFORMANCE_TOKEN=... \
UA_SDK_WRITE_CONFORMANCE_HUMAN_TOKEN=... npm run test:conformance:live
```

Use a disposable hub: the write suite creates a task, queues an approval and
appends evidence. The `sdk` workflow (`.github/workflows/sdk.yml`) runs the
same suite against a `ua serve` it builds from the commit under test; the
current results are in
[sdk/typescript/docs/known-gaps.md](../sdk/typescript/docs/known-gaps.md).
