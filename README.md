# ua-rust

An agent-operations hub in Rust. One process gives every coding agent you run
(Claude Code, Codex, Cursor, OpenCode, Copilot and others) the same governed
tool surface: shared tasks, plans, delegation, messaging, memory and a
knowledge vault, behind one identity, policy and approval gate, with a
tamper-evident event ledger.

ua-rust is the next version of the Python unified-agent hub, not a copy of it.
Parity is measured at three levels, set out in [docs/parity.md](docs/parity.md):

- **Contract**: the tool names, argument shapes and HTTP routes a client
  depends on are kept, so an existing MCP client can point at this process
  unchanged for the families that are in. A change is deliberate and listed
  under that family's "Differences from the Python hub".
- **Capability**: what a person or an agent can get done is the measure. It is
  reached or exceeded.
- **Implementation**: how the Python hub does it is not preserved. Duplicated
  paths are merged, not ported.

That program is a separate codebase. Building and running this repository does
not require it. The storage schema and some of the user interface are new.

> **Status: alpha.** 214 tools are registered and the core families are ported.
> It is not yet run in production. See [What is in](#what-is-in) and [Not yet ported](#not-yet-ported).

## How it fits together

```
 MCP (stdio, Streamable HTTP /mcp)   HTTP/JSON /api   Web UI /ui   CLI
                 \                        |              |          /
                  +---- one call wrapper: authenticate -> profile ->
                        policy -> approval gate -> tool -> ledger ----+
                                          |
                    SQLite (WAL): tasks, plans, delegations, messages,
                    approvals, sessions, memory (FTS5 + vectors),
                    hash-chained event log
```

Every interface reaches the same registered tools through the same wrapper, so
a rule is written once and holds for every client.

| Crate | Holds |
|---|---|
| `ua-core` | Config, identity, session profiles, errors, sandbox resolvers |
| `ua-store` | SQLite storage: the writer and reader connections, named schema parts, the event ledger, and backup, restore and database checks |
| `ua-memory` | Memory notes: schema, note model, save, hybrid search, ranking, embeddings, lifecycle |
| `ua-tools` | Tool registry, the call wrapper and the tool families |
| `ua-server` | axum HTTP API, MCP adapter, auth, server-rendered UI |
| `ua-import` | `ua import python-hub`: copies a Python hub database, ledger chain intact |
| `ua-cli` | The `ua` binary |

The TypeScript SDK (protocol and client packages) is in `sdk/typescript`, and
the Slack routes and Socket Mode are described in [docs/slack.md](docs/slack.md).

Library choices and the reasons for them are in [docs/stack.md](docs/stack.md).

## Quick start

Build the `ua` binary, start the hub, and check liveness. The process listens
on `127.0.0.1:8765`. Auth is on by default. `GET /healthz` does not need a
token.

```sh
cargo build --release
./target/release/ua serve
```

In a second shell, while `ua serve` is running:

```sh
curl -fsS http://127.0.0.1:8765/healthz
```

Every other route needs a bearer token. Issue one for each agent with
`./target/release/ua token issue <label>`; it prints the raw value once.

The database file is `$UA_HOME/ua.db` (`$HOME/.ua-rust/ua.db` when `UA_HOME`
is unset). Configuration is read from defaults, then `$UA_HOME/config.toml`
(or `$UA_CONFIG`), then `UA_*` environment variables. See
[config.example.toml](config.example.toml) and [.env.example](.env.example).
Every value in those files is a placeholder.

### Build options

`cargo build --release` builds everything in the table below except
`embeddings`. To leave the heavy dependencies out, build without default
features and add back what you want:

```sh
cargo build --release --no-default-features                          # smallest build
cargo build --release --no-default-features --features mcp-server    # MCP clients can still connect
cargo build --release --features embeddings                          # add semantic memory search
```

| Feature | Default | Enables | Without it |
|---|---|---|---|
| `code-intel` | on | tree-sitter symbol tools: `fs_index_symbols`, `fs_list_symbols`, `fs_search_symbols`, `fs_repo_map` | Those tools are not registered. |
| `readability` | on | dom_smoothie article extraction in `web_fetch` and `dash_view` | The whole page is converted (`extraction: "full-page"`). |
| `mcp-gateway` | on | `mcp_gateway`, the client for downstream MCP servers | `mcp_server_register` refuses. |
| `mcp-server` | on | The hub's own MCP server: `/mcp` and `ua mcp` | `ua serve` serves the JSON API and UI only, and warns at startup. |
| `slack-socket` | on | Slack Socket Mode: Slack over an outbound WebSocket, no public URL | `slack_socket_mode = true` is reported as not compiled in. |
| `embeddings` | off | Semantic memory search with fastembed | Memory search is lexical (FTS5). |

`system_doctor` and `capability_catalog` report which features a build has
and which tools a missing feature leaves out. See
[docs/stack.md](docs/stack.md#cargo-features).

## First run

```sh
ua token issue agent-1          # prints a token once; give it to that agent
ua serve                        # http://127.0.0.1:8765 (/mcp, /api, /ui)
ua login-link operator          # on the hub host, at a terminal: a browser sign-in link
```

`ua serve` stops cleanly on Ctrl-C (SIGINT) or SIGTERM. Open requests, MCP
tool calls, dispatch runs and the background loops share a 10-second grace
period, and event streams end. Dispatch runs still going 3 seconds before
the deadline are stopped (SIGTERM, then SIGKILL) and recorded `retryable`
with a `hub_shutdown` receipt. The WAL is then checkpointed into the
database file. A second signal exits at once, killing the run process
groups. See [docs/dispatch.md](docs/dispatch.md#hub-shutdown).

Auth is on by default. Agents connect over MCP with their bearer token, or
over stdio with `ua mcp --label agent-1`. Remote MCP clients can use OAuth
2.1 when `oauth_enabled` is set; see [docs/auth.md](docs/auth.md).

## Security model

- The HTTP hub binds to `127.0.0.1` and enforces auth by default. For remote
  access use a TLS terminator on a private network (for example `tailscale
  serve`), and list the host in `allowed_hosts`.
- Tokens are opaque, compared in constant time and stored as SHA-256 digests.
- Every call passes the same wrapper: profile, policy rules, approval gate,
  typed arguments, then a `tool_calls` row and ledger events. Ledger
  verification (`event_log_verify`, `evidence_report`) fails on any row
  without a hash after the chain starts; only an imported legacy prefix may
  lack one, it must be exactly as long as the import recorded, and it is
  reported as `unhashed_legacy_prefix`.
- Approvals need a verified human. The approval payload binds the exact
  arguments, and for dispatch the resolved workdir, argv and prompt.
- `fs_*`, `run_cmd` and `git_*` are confined to a workspace root. Hook
  directories and credential files are refused. `run_cmd` runs allowlisted
  programs without a shell, with a fresh `HOME` per call; interpreters and
  build tools need approval.
- `/api` and `/ui` refuse unknown hosts (DNS rebinding) and cross-site
  writes; the UI uses CSRF tokens and a strict CSP.
- The GitHub webhook authenticates each delivery by HMAC-SHA256 and refuses
  replayed delivery ids; the GitHub token is read from an environment
  variable the config names and is never stored or logged; only
  repositories bound to a project are ever requested
  ([docs/github.md](docs/github.md#security-model)).
- The Slack routes are off by default. When enabled they check Slack's
  signature over the raw body before parsing or touching the database, act
  only for Slack users mapped to a human identity, and run commands through the
  same governed path ([docs/slack.md](docs/slack.md#threat-model)).
- Managed secrets are encrypted at rest with a key the database never holds,
  and no tool returns a value. Downstream MCP servers get them by reference
  and see only what their registration names.
- Run agents under a different OS user than the hub: anything running as the
  hub's user can edit its database directly.

Details are in [SECURITY.md](SECURITY.md), which also says how to report a
vulnerability.

## What is in

| Area | Tools and features | Docs |
|---|---|---|
| Kernel | Identity, bearer tokens, 10 session profiles, policy rules, approvals, hash-chained ledger | [policy](docs/policy.md) |
| Coordination | Tasks and dependencies, goals, plans, delegation, messaging, agents and sessions | |
| Memory and vault | Memory notes (FTS5, optional embeddings), Obsidian vault read/write, graph query, journal | |
| Workspace | `fs_*`, `run_cmd`, `git_*`, worktrees, code intelligence (tree-sitter), web search and fetch | |
| Execution | Dispatch with leases and fences, harness executor, workflows with checkpoints, cron routines, autonomous cycles | [dispatch](docs/dispatch.md) |
| Remote nodes | Node registry with derived liveness and operator retire, reassign and forget; a work queue: approval-bound `node_dispatch`, long-poll claims with attempt fences, leases and durable claim operations, idempotent receipts, cancel and restart, waits for offline nodes, supervised commands with fence tokens and owner notices, ACP events, follow-ups and permission prompts; `dispatch_task` runs routed to a node; per-item session credentials (`uas_…`) for ACP sessions; device acceptance runs with operator attestation and `node_require_acceptance`; idle-session wakes over the session's own agent's node long-poll (`/api/node/wake`, check and receipt) behind a session request and a human grant, with the original budget (debounce, floor, hourly caps, breaker) | [nodes](docs/nodes.md#idle-session-wakes) |
| Harness config | Versioned bundles of rules, skills and OAuth MCP servers published behind a human approval (`harness_config_publish`), served at `/api/node/config` rendered byte-for-byte as the Python hub renders them; drift reports park one `harness_config_apply` approval per surface, and a node writes only after consuming it; bundles are checked against TOML injection, hidden text, unsafe paths and unclean MCP URLs; the skills registry (`skill_registry`: immutable content-hash versions, staged and approved in full, pinned assignments to agents and profiles) feeds each node's bundle | [nodes](docs/nodes.md#harness-config-bundle) |
| Provider accounts | Operator registry of provider accounts (`provider_account_*`), quota observed from harness-declared signals (`quota_patterns` on stderr, Pi's JSON error events; `provider_quota_status`), `dispatch_task` refusals or same-provider, same-billing fallback on a disabled or rate-limited account; Pi as an ordinary harness (`env`, `env_denylist`, `path_prepend`, `stdin`) | [dispatch](docs/dispatch.md#provider-accounts) |
| Governance | One claim gate for every path that hands out work; agent lifecycle (pause, resume, terminate, retire with token revocation); task subtree holds; fenced operator claim release; work proposals whose approved items become tasks with a frozen contract; project repo bindings; `cleanup_stale_worktrees` and `audit_triage_tasks` | [policy](docs/policy.md#governance-controls) |
| Continuity | Task workflow record (stage, resume capsule, checks graded `verified` / `attested` / `unknown` at a head through a pluggable CI verifier); session handoff notes with `seal` as the commit point; conversation handoff to a task without copying messages; queue closure in its own task columns (`queue_park`, `queue_fold`, `queue_unpark`, a dry-run `queue_sweep`, `queue_health`, `task_list(parked=true)`), close-on-merge (`queue_close_merged`); the review queue (`task_list(stage="review")`) and a `review_ready` notification; delegation stats in `observability_manage` | [continuity](docs/continuity.md) |
| GitHub | Native REST client scoped to bound repositories (no redirects, bounded, rate-limit aware); CI runs and jobs verify task checks; signed webhook `POST /api/github/webhook` with replay protection (merges close tasks, completed runs re-verify checks); ETag polling fallback; `policy_authorization_record` / `policy_authorization_list`, accepted by `git_merge_task` in place of a one-time approval for one exact head | [github](docs/github.md) |
| Planning and capability | Planning canvas (`graph_canvas_read` / `graph_canvas_write`: Excalidraw boards parsed into task and dependency suggestions, optimistic writes, per-agent and hub board caps; `graph_canvas_history` / `graph_canvas_restore`: every overwrite keeps the replaced scene, newest `graph_canvas_history_max` per board within `graph_canvas_history_max_bytes`; deleted elements are not parsed), `check_agent_capability` (a task's `[requires: ...]` against the agent's profile) and `capability_catalog` (agents, tools by family, programs, harnesses, workflows, skills, MCP surface; health, boundaries, agent hosts and the program allowlist for operators only; with a task and agent, readiness from tools, identity and an executor) | |
| Downstream MCP | `mcp_gateway` calls a catalogued tool on a registered MCP server (stdio or Streamable HTTP) with hub-held credentials: reads per profile, every write behind a one-time human approval bound to its arguments, address-scope and origin pinning, secrets injected by name and redacted from results, bounded size and time, one ledger event per call. `mcp_server_register` / `_review` / `_revoke` (approval-gated, with a review window) and `mcp_server_list`; servers may also be declared in `config.toml` | [mcp](docs/mcp.md) |
| Managed secrets | `managed_secret_set` (human or configured operator identity; replacing a value is approval-gated), `managed_secret_list` (metadata and a keyed fingerprint only), `managed_secret_delete` (approval-gated): AES-256-GCM at rest under `managed_secret_key`, each secret bound to one consumer, no read path | [mcp](docs/mcp.md#managed-secrets) |
| Public relay | `relay_manage`: an agent drafts a comment for an issue or pull request in an allowlisted GitHub repository; gates refuse secrets, hidden or bidirectional Unicode, private addresses and internal host names, home paths, personal data, over-long text and a private denylist, never rewriting the text; a human approves the exact text and target, the send repeats it byte for byte, and the token is a managed secret | [relay](docs/relay.md) |
| Slack | Off by default. Signed slash commands (`POST /api/slack/commands`) and Events API callbacks (`POST /api/slack/events`) behind `slack_enabled` and `UA_SLACK_SIGNING_SECRET`: the nine coordination commands run as the human identity a (`team_id`, `user_id`) pair is mapped to, through the governed call path (transport `slack`); `/approve` only for mappings with `can_approve`, as a verified human other than the requester; commands with no recorded outcome ledgered at startup; messages run only when marked (`!task`); replay and retry dedupe; slash-command results posted to `hooks.slack.com` only. Or, for a hub with no public URL, Socket Mode (`slack_socket_mode`, `UA_SLACK_APP_TOKEN`): the same admission and execution over an outbound WebSocket to Slack | [slack](docs/slack.md) |
| Zulip | `zulip_send_message`: the relay's gates plus Zulip wildcard, group and unlisted mentions and unlisted link hosts, then a human approval of the exact stream, topic and text; an uncertain send blocks a duplicate until a human runs `zulip_resolve_send`. `zulip_fetch_messages`: forward-only cursor, messages labelled untrusted. Off until configured; sending retired by default | [zulip](docs/zulip.md) |
| Quality | Security audit (with approved remediation), skill review, injection triage, observability, evidence and export | |
| Adapters | MCP (stdio, Streamable HTTP 2026-07-28 plus legacy sessions), HTTP/JSON and compatibility API, CLI | |
| TypeScript SDK | The SDK itself is in [`sdk/typescript`](sdk/typescript/README.md) (protocol and client packages; not published). The hub serves its `ControlCenterClient` platform routes: runs (`run_list` / `run_get`: dispatch runs, sessions, workflow runs and node items as one row shape), the platform object model (`platform_manifest` / `platform_object_get`, each kind gated by its own profile tool) and evidence (`evidence_append`: `sdk.` channels, caller-attributed, deduplicated per caller; `evidence_report`) | [sdk](docs/sdk.md) |
| Control Center | Server-rendered UI at `/ui`: inbox, work board, plans, agents, messages, memory, live activity | [ui](docs/ui.md) |
| Auth | OAuth 2.1 authorization server, passkeys, browser sessions, node session credentials | [auth](docs/auth.md) |
| Migration | `ua import python-hub` with a dry run, resumable and chain-verified | |

## Not yet ported

Native-session resume and adopt, cloud executors, Slack interactions,
bot-token posting and live chat (slash commands and events are in),
role workflows, GitHub writes other than the relay's approved comments
(labels, held PRs, the GitHub App installation flow), session-handoff
failover, the SDK's queue-health and node-session routes
(`/api/queue-health`, `/api/action/node-session`, which no route serves), the
provenance graph and evidence export (`/api/platform/*` paths other than the
manifest and objects, and `/api/evidence/export`, answer 501), discovered
native sessions (`/api/nodes/*` other than `/api/nodes/acceptance`, 501),
billing and usage ledgers, and tenancy (`org_id`). Work products
(`/api/work-products*`) are not ported as they were: they are being redesigned
as generic deliverables reviewed through task stages
([docs/parity.md](docs/parity.md)), and the routes answer 501 until then.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
