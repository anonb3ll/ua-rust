# Contributing

## Layout

| Crate | Rule |
|---|---|
| `ua-core` | No I/O beyond reading config. Types, profiles, sandbox resolvers. |
| `ua-store` | SQLite access and the ledger. No tool logic. |
| `ua-tools` | Tools. Every tool is registered in the `Registry` and runs only through `Registry::call`. |
| `ua-server` | Adapters (MCP, HTTP, UI). Adapters build a `Caller` and call the registry; they never run tool code directly. |
| `ua-cli` | The `ua` binary. |

## Adding a tool family

1. Create `crates/ua-tools/src/families/<name>.rs`.
2. Tables: declare `pub const SCHEMA: SchemaPart` (or several) with a unique,
   versioned name such as `"memory.v1"`. Use `CREATE TABLE IF NOT EXISTS`.
   Never edit a released part; add `"memory.v2"` instead. Tables shared by
   several families (tasks, agents, agent_sessions) live in `core_schema.rs`.
3. Tools: one argument struct per tool deriving `Deserialize` and
   `JsonSchema` with `#[serde(deny_unknown_fields)]`. Document each field with
   a `///` comment: it becomes the schema description agents read.
4. Register with `tool(name, description, handler)`, plus `.family("<name>")`
   and `.read_only()` when the tool never writes. Tools that must always have
   a human approval use `.always_gated()`.
5. Database work runs off the async runtime: `ctx.hub.db().read_async(..)` /
   `write_async(..)`, or wrap a synchronous body in `registry::blocking`.
6. State changes append a ledger event in the same write transaction
   (`ua_store::ledger::append(tx, EventInput::new("agent.<noun>.<verb>", payload).by(caller))`).
7. Add the module to the lists in `families/mod.rs` (alphabetical).
8. Tests go in `crates/ua-tools/tests/<name>.rs` and call tools through
   `builtin_registry().call(..)`, so profile and approval rules are exercised.

## Tool contract

Tool names, argument names and their meaning match the original Python hub
(`docs/tools-reference.md` there). Return shapes are JSON objects. Errors are
`UaError` values; never panic in a tool.

## Checks

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test -p ua-tools --test <name>
scripts/vocab-check.sh
```

CI runs the full suite. Commit messages: imperative subject, a short body
saying what and why.

## Privacy

This repository is public. No personal names, e-mail addresses, home
directory paths, host names or real tokens in code, tests, docs or commits.
Use placeholders such as `builder-1`, `operator`, `~/projects`,
`example.com`. `scripts/vocab-check.sh` (run in CI) enforces this; list an
intended exception in `scripts/vocab-allowlist.txt`.
