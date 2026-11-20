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
| Activity | `/ui/activity` | The event ledger as a live feed (server-sent events), filtered by channel prefix. The hash-chain check (`event_log_verify`, which recomputes every entry) runs only when asked: the Verify the hash chain button (`?verify=1`). |

Every read and write runs a registered tool through the same call wrapper as
MCP and the JSON API, as the request's caller with transport `ui`. Profiles,
policy, the approval gate and the ledger therefore apply to the UI unchanged.
A write that the gate parks redirects back with a notice naming the pending
approval. A tool the caller's profile does not allow shows as an error in
that section rather than failing the page. Approve, deny and revoke run
`approval_resolve`, which agent profiles do not expose and which refuses
self-approval, so an agent token cannot clear its own gate through the UI.

A page is composed from several reads (the Work board makes six
`task_list` calls). For a **verified human's browser session** (the session
cookie) those reads run inside `page_reads` (`ua_tools::registry`): every
check applies as above, but a *skip-eligible* call that succeeds leaves no
`tool_calls` row, so viewing a page writes nothing to the database. A call
is skip-eligible when the tool is read-only, no approval gate applies, it
has no side effect for these arguments, and no policy file is loaded.

Everything else records as usual:
- refusals reach the ledger;
- writes and gated calls record;
- reads with a side effect record: `session_list` reaps stale sessions,
  `memory_search` and `memory_get` (unless `count_access=false`) bump access
  counters, and `message_list` with a `session_id` is that session's
  heartbeat;
- with a policy file loaded, every call reserves its `tool_calls` row up
  front (rate limits and cooldowns must count it), so every page read is
  recorded.

A skip-eligible read that fails is recorded with `page = 1`. Error rates and
call statistics (`metrics_snapshot`, `perf_summary`, `check_anomalies`, the
call counts, `evidence_report`) leave those rows out, because their
successful siblings left none.

Any other caller is recorded. An agent token on a `/ui` page records every
call. `GET /api/board` for a caller other than a human's browser session
writes **one** summary row per view (tool `api_board`, outcome `ok` or the
first inner failure's code) instead of its six to eight inner reads, so
agent activity, performance and evidence reports still see the view. MCP
and `/api/tools/{name}` calls are never inside a page scope: each records
one row.

The live feeds (`/ui/activity/stream`, and `/api/events/stream` for JSON
clients) open with one `event_log_query` call as the caller, so a profile or
policy that refuses that tool refuses the stream with the same status. Every
row, live or replayed, passes the same channel filter the tool applies. A
reconnect sends `Last-Event-ID` (the ledger seq) and gets the rows it missed
from the ledger; `/api/events/stream` also takes `?after_seq=`. A client too
slow for the live broadcast is caught up from the ledger the same way. When
a catch-up cannot be complete (more than 1000 matching rows, or a failed
read), the stream sends a `gap` event (`{"gap": true, "after_seq",
"until_seq", "reason"}`; the Activity page shows it as a row) instead of
skipping rows silently.

Values under secret-shaped keys (`token`, `secret`, `password`, `api_key`,
`authorization`, `cookie` and similar) are shown as `[redacted]` wherever the
UI prints JSON.

## Signing in

The header links to `/login`; signing out is a small form that posts to
`/logout` with the browser session's CSRF token (the route takes no GET, and
the page runs no inline script). The UI uses the same
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
  and `X-Frame-Options: DENY`. The sign-in, passkey and OAuth consent pages
  outside `/ui` have their own policy (`default-src 'none'`, script and
  style from the hub only, no `'unsafe-inline'`); their script and style are
  the files `/login/assets/login.js` and `/login/assets/page.css`.
- **Host check.** `/ui` and `/api` refuse a request naming a host outside
  `allowed_hosts` and the `public_url` host. The names checked are the
  `Host` header and, for HTTP/2 (which may send no `Host`), the
  `:authority`; every name present must be allowed.
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
| `POST /api/approvals/request` | the approval gate, request only: the same grant, profile, policy and prod-action checks as a call, typed arguments, and the payload the tool's own gate binds (a secret is never stored); `409` for a tool nothing gates and for one that binds its approval when called (see [sdk.md](sdk.md)) |
| `GET /api/sessions` | `session_list` |
| `GET /api/capability-catalog` | the tool registry, grouped by family |
| `GET /api/board` | `task_list`, `dependency_list`, `delegate_list` (page reads: no rows for a browser session, one `api_board` row otherwise) |
| `GET /api/nodes` | `node_list` |
| `POST /api/node/register`, `POST /api/node/heartbeat` | `node_register`, `node_heartbeat` (agent token only) |
| `GET /api/runs`, `GET /api/runs/{run_id}` | `run_list`, `run_get` |
| `GET /api/platform/manifest`, `GET /api/platform/objects/{kind}[/{id}]` | `platform_manifest`, `platform_object_get` |
| `GET /api/evidence`, `POST /api/evidence` | `evidence_report`, `evidence_append` |

The runs, platform and evidence routes and what the SDK can rely on are in
[sdk.md](sdk.md). `/api/nodes/*` (acceptance), the node wake, config and
session-credential routes under `/api/node/`, the provenance graph and the
evidence export answer `501` with `{"error": "not_implemented", "capability":
"..."}` until they are built. `/api/work-products*` answers `501` too: work
products are not ported pending an explicit product decision (hub task
#2658).

## Third-party files

The vendored htmx files and their licenses are listed in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
