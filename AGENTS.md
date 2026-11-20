# Notes for coding agents

Guidance for any coding agent (or person) changing this repository. The
human-facing version is [CONTRIBUTING.md](CONTRIBUTING.md); where they differ,
CONTRIBUTING.md wins.

## Build, lint, test

```sh
cargo build
cargo fmt --all
cargo clippy --workspace --all-targets      # CI denies warnings
cargo test -p <crate>                        # e.g. -p ua-core
cargo test -p ua-tools --lib
cargo test -p ua-tools --test <name>         # one file in crates/ua-tools/tests/
scripts/vocab-check.sh                       # no team vocabulary or personal identifiers
```

The full suite is large. Run the tests for the crates and test files you
touched; CI runs the whole workspace (`cargo nextest run --workspace`).

## Crate map

| Crate | Holds | Rule |
|---|---|---|
| `ua-core` | Config, identity, session profiles (`profiles.rs`, `profiles.json`), errors, sandbox resolvers | No I/O beyond reading config. |
| `ua-store` | SQLite access, migrations, the hash-chained ledger | No tool logic. |
| `ua-memory` | The memory domain: schema parts, note model, save, hybrid search, ranking, embeddings (`embeddings` feature), lifecycle | Depends only on `ua-core` and `ua-store`, never on the registry. The memory tools stay in `ua-tools` (`families/memory`); adapters reach memory only through them (`tests/boundary.rs` enforces that only `ua-tools` depends on it). |
| `ua-org` | The organization registry: offices, roles and seats | Depends only on `ua-core` and `ua-store`, never on the registry. It reaches SQLite through `ua-store`'s `OrgRead` / `OrgWrite`. The tools stay in `ua-tools` (`families/org`); adapters reach the registry only through them (`tests/boundary.rs` enforces that only `ua-tools` depends on it). |
| `ua-tools` | The tool registry, the governed call wrapper (`Registry::call`), policy, approvals, tool families (`src/families/`) | Every tool is registered and runs only through `Registry::call`. |
| `ua-server` | MCP, HTTP API, OAuth, server-rendered UI | Adapters build a `Caller` and call the registry; they never run tool code directly. |
| `ua-import` | `ua import python-hub`: copies a Python hub database, ledger chain intact | |
| `ua-cli` | The `ua` binary | |

## Rules that matter most

- **Every tool goes through the registry wrapper.** Register it with
  `tool(name, description, handler)` in its family's `register`, and call it
  only through `Registry::call`, which checks the profile, the policy file and
  the approval gate, validates arguments and records the call. Do not add a
  route, CLI command or UI handler that runs tool code directly.
- Argument structs derive `Deserialize` and `JsonSchema` with
  `#[serde(deny_unknown_fields)]`; each field's `///` comment is the schema
  description agents read.
- State changes append a ledger event in the same write transaction.
- Tests in `crates/ua-tools/tests/` call tools through
  `builtin_registry().call(..)`, so profile and approval rules are exercised.
- A tool named in `crates/ua-core/src/profiles.json` must be registered; a
  unit test in `ua-tools` enforces this.
- Tool names and argument shapes match the original Python hub. Profile names
  are neutral capability tiers; old names are accepted only as aliases
  (see [docs/policy.md](docs/policy.md#profiles)).

## Privacy

This repository is public. No personal names, e-mail addresses, home
directory paths, host names, private-network addresses or real tokens in
code, tests, docs or commits, and no team- or organization-specific roles or
vocabulary. Use placeholders such as `builder-1`, `operator`, `~/projects`,
`example.com`. `scripts/vocab-check.sh` runs in CI; an intended exception
goes in `scripts/vocab-allowlist.txt` with a reason.
