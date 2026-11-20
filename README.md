# ua-rust

An agent-operations hub in Rust. One process gives every coding agent you run
(Claude Code, Codex, Cursor, OpenCode, Copilot and others) the same governed
tool surface: shared tasks, plans, delegation, messaging, memory and a
knowledge vault, behind one identity, policy and approval gate, with a
tamper-evident event ledger.

ua-rust is a Rust rebuild of the Python `unified-agent` hub. It keeps the tool
contract (tool names, argument shapes and HTTP routes) so existing MCP clients
can point at it unchanged; the storage schema and some of the UX are new.

> **Status: alpha.** 169 tools are registered and the core families are ported.
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
| `ua-store` | SQLite storage, migrations, repositories, the event ledger |
| `ua-tools` | Tool registry, the call wrapper and the tool families |
| `ua-server` | axum HTTP API, MCP adapter, auth, server-rendered UI |
| `ua-import` | `ua import python-hub`: copies a Python hub database, ledger chain intact |
| `ua-cli` | The `ua` binary |

Library choices and the reasons for them are in [docs/stack.md](docs/stack.md).

## Quick start

```sh
cargo build --release
cp config.example.toml ~/.ua-rust/config.toml   # optional
./target/release/ua --help
```

Configuration comes from defaults, then `$UA_HOME/config.toml` (or
`$UA_CONFIG`), then `UA_*` environment variables. See
[config.example.toml](config.example.toml) and [.env.example](.env.example).
Every value in those files is a placeholder.

## First run

```sh
ua token issue agent-1          # prints a token once; give it to that agent
ua serve                        # http://127.0.0.1:8765 (/mcp, /api, /ui)
ua login-link operator          # on the hub host, at a terminal: a browser sign-in link
```

Auth is on by default. Agents connect over MCP with their bearer token, or
over stdio with `ua mcp --label agent-1`. Remote MCP clients can use OAuth
2.1 when `oauth_enabled` is set; see [docs/auth.md](docs/auth.md).

## Security model

- The HTTP hub binds to `127.0.0.1` and enforces auth by default. For remote
  access use a TLS terminator on a private network (for example `tailscale
  serve`), and list the host in `allowed_hosts`.
- Tokens are opaque, compared in constant time and stored as SHA-256 digests.
- Every call passes the same wrapper: profile, policy rules, approval gate,
  typed arguments, then a `tool_calls` row and ledger events.
- Approvals need a verified human. The approval payload binds the exact
  arguments, and for dispatch the resolved workdir, argv and prompt.
- `fs_*`, `run_cmd` and `git_*` are confined to a workspace root. Hook
  directories and credential files are refused. `run_cmd` runs allowlisted
  programs without a shell, with a fresh `HOME` per call; interpreters and
  build tools need approval.
- `/api` and `/ui` refuse unknown hosts (DNS rebinding) and cross-site
  writes; the UI uses CSRF tokens and a strict CSP.
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
| Remote nodes | Node registry with derived liveness and operator retire, reassign and forget; a work queue: approval-bound `node_dispatch`, long-poll claims with attempt fences, leases and durable claim operations, idempotent receipts, cancel and restart, waits for offline nodes, supervised commands with fence tokens and owner notices, ACP events, follow-ups and permission prompts; `dispatch_task` runs routed to a node | [nodes](docs/nodes.md) |
| Quality | Security audit (with approved remediation), skill review, injection triage, observability, evidence and export | |
| Adapters | MCP (stdio, Streamable HTTP 2026-07-28 plus legacy sessions), HTTP/JSON and compatibility API, CLI | |
| Control Center | Server-rendered UI at `/ui`: inbox, work board, plans, agents, messages, memory, live activity | [ui](docs/ui.md) |
| Auth | OAuth 2.1 authorization server, passkeys, browser sessions | [auth](docs/auth.md) |
| Migration | `ua import python-hub` with a dry run, resumable and chain-verified | |

## Not yet ported

The node wake transport, harness config bundle and session credentials
(`/api/node/wake*`, `/config`, `/session_credential` answer 501), device
acceptance, cloud executors, ACP, Slack and Zulip
connectors, role workflows, the TypeScript SDK's platform routes
(`/api/runs`, `/api/platform/*` answer 501), billing and usage ledgers, and
tenancy (`org_id`).

## License

Apache-2.0. See [LICENSE](LICENSE).
