# Control Center (web UI)

`ua serve` serves a server-rendered Control Center at `/ui` on the hub's bind
address (default `http://127.0.0.1:8765/ui`). It needs no Node toolchain and
loads nothing from a CDN: pages are askama templates, interactivity is htmx
2.0 with its SSE extension, and the static files are embedded in release
builds with memory-serve (debug builds read `crates/ua-server/static/` from
disk).

## Screens

| Page | Path | What it shows and does |
|---|---|---|
| Inbox | `/ui/inbox` | Pending approvals with approve, deny and revoke; live one-shot passes; expired passes. |
| Work | `/ui/work` | Task board grouped by status, filtered by project, priority and search; a form to create a task. |
| Task | `/ui/tasks/{id}` | Detail with notes, comments and dependencies; update fields, append a note, comment, add or remove a dependency. |
| Plans | `/ui/plans`, `/ui/plans/{id}` | Plans and delegations filtered by status; a plan's steps, next actionable step and checkpoint count. |
| Delegation | `/ui/delegations/{id}` | One delegation's fields and spec. |
| Agents | `/ui/agents` | The roster with liveness and live sessions. |
| Messages | `/ui/messages` | Messages, filtered by recipient and unread. |
| Memory | `/ui/memory`, `/ui/memory/{id}` | Search memory notes and read one. |
| Activity | `/ui/activity` | The event ledger as a live feed (server-sent events), filtered by channel prefix, plus the hash-chain check from `event_log_verify`. |

Every read and write runs a registered tool through the same call wrapper as
MCP and the JSON API, as the request's caller with transport `ui`. Profiles,
policy, the approval gate and the ledger therefore apply to the UI unchanged.
A write that the gate parks redirects back with a notice naming the pending
approval. A tool the caller's profile does not allow shows as an error in
that section rather than failing the page. Approve, deny and revoke run
`approval_resolve`, which agent profiles do not expose and which refuses
self-approval, so an agent token cannot clear its own gate through the UI.

Values under secret-shaped keys (`token`, `secret`, `password`, `api_key`,
`authorization`, `cookie` and similar) are shown as `[redacted]` wherever the
UI prints JSON.

## Signing in

The header links to `/login` and `/logout`. The UI uses the same
authentication as the rest of the hub: with `enforce_auth` on (the default)
every `/ui` request needs a signed-in identity; with it off, a request without
credentials runs as the local anonymous caller, which suits a hub bound to
`127.0.0.1`. Do not turn `enforce_auth` off on a hub reachable from other
machines.

## Security

- **CSRF.** A random token lives in the `ua_csrf` cookie (`SameSite=Strict`,
  `HttpOnly`, path `/ui`, `Secure` over HTTPS). Pages render the same token
  into `hx-headers`, so htmx sends it as `X-CSRF-Token`; plain forms carry it
  in a hidden `_csrf` field. A POST without a matching token, with a
  cross-site `Sec-Fetch-Site`, or with an `Origin` that does not match the
  host is refused with `403`.
- **Headers.** UI responses carry a Content-Security-Policy with no inline
  script or style and no framing, plus `X-Content-Type-Options: nosniff`
  and `X-Frame-Options: DENY`.
- htmx is configured with `allowEval` and `allowScriptTags` off and
  `selfRequestsOnly` on.

## Compatibility API

For the TypeScript SDK, the hub also serves the Python Control Center's JSON
routes with the same request and response shapes:

| Route | Backed by |
|---|---|
| `GET /api/tasks`, `POST /api/tasks` | `task_list`, `task_add` |
| `POST /api/action/task` | `task_update` |
| `POST /api/action/approval` | `approval_resolve` (verified human only) |
| `GET /api/approvals`, `GET /api/approvals/{id}` | `approval_pending`, one approval row |
| `POST /api/approvals/request` | the approval gate, request only |
| `GET /api/sessions` | `session_list` |
| `GET /api/capability-catalog` | the tool registry, grouped by family |
| `GET /api/board` | `task_list`, `dependency_list`, `delegate_list` |

`/api/runs`, `/api/nodes`, `/api/work-products`, `/api/evidence` and
`/api/platform/*` answer `501` with
`{"error": "not_implemented", "capability": "..."}` until their tool
families exist.

## Third-party files

The vendored htmx files and their licenses are listed in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
