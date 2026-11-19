# ua-rust

An agent-operations hub in Rust. One process gives every coding agent you run
(Claude Code, Codex, Cursor, OpenCode, Copilot and others) the same governed
tool surface: shared tasks, plans, delegation, messaging, memory and a
knowledge vault, behind one identity, policy and approval gate, with a
tamper-evident event ledger.

ua-rust is a Rust rebuild of the Python `unified-agent` hub. It keeps the tool
contract (tool names, argument shapes and HTTP routes) so existing MCP clients
can point at it unchanged; the storage schema and some of the UX are new.

> **Status: early.** The kernel is being built first. See [Roadmap](#roadmap).

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

## Security model

- The HTTP hub binds to `127.0.0.1` by default. Put a reverse proxy or a
  private network in front of it; do not bind it to every interface.
- Agent tokens are compared in constant time and stored hashed.
- `fs_*`, `run_cmd` and `git_*` are confined to a workspace root. Paths are
  resolved through symlinks, hook directories (`.git`, `.husky`, ...) and
  credential files are refused, and `run_cmd` runs allowlisted programs
  without a shell.
- Approval-gated tools park as pending until a human resolves them.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Roadmap

1. Kernel: storage, identity and tokens, profiles and policy, approvals, event ledger.
2. Coordination: tasks, dependencies, plans, delegation, messages, memory, sessions.
3. Adapters: MCP (stdio and Streamable HTTP), HTTP/JSON API, CLI.
4. Workspace tools: fs, run_cmd, git and worktrees, web search and fetch, vault.
5. Execution: dispatch, executor, workflows, schedules.
6. Control center: server-rendered UI with live updates.
7. Importer from the Python hub's database.

## License

Apache-2.0. See [LICENSE](LICENSE).
