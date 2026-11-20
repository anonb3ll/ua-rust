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

## Cloud Build CI

`scripts/cloud-ci.sh` runs the `check` and `vocab` jobs of
`.github/workflows/ci.yml` for one exact commit on Google Cloud Build and posts
the results as GitHub commit statuses. GitHub Actions stays the primary CI
(its minutes are free for this public repository and it runs the macOS
dispatch job); Cloud Build is an additional runner for a pinned head.

```sh
UA_CI_GCP_PROJECT=<project-id> scripts/cloud-ci.sh <pr-number | branch | sha>
```

- It uploads a one-commit checkout of the resolved head, submits
  `deploy/cloudbuild/ci.yaml` from your checkout, waits for the build, and
  posts `CI / vocab`, `CI / check` and `CI / full-verification`. Each status
  names the build and links to its log. A PR number or branch resolves to the
  head GitHub has, so push first.
- `UA_CI_GCP_PROJECT` is required; no default project is assumed.
  `UA_CI_GCP_REGION` defaults to `us-central1`, `UA_CI_REPO` to the current
  repository. `UA_CI_NO_STATUS=1` posts nothing (the build still runs and is
  billed).
- Needs `git`, `gcloud` (allowed to submit builds in the project), `gh`
  (allowed to write commit statuses) and GNU `timeout`. Statuses are posted
  from your machine; no GitHub credential enters the build.
- If the watcher is interrupted, do not resubmit. Re-attach to the same build,
  which posts its final statuses without starting another:

  ```sh
  UA_CI_GCP_PROJECT=<project-id> scripts/cloud-ci.sh --reconcile <build-id> <pr-number | branch | sha>
  ```

- An older build never overwrites a newer run's statuses: the script compares
  build creation times and refuses, posting nothing, when a context holds a
  status from a run it cannot prove older.
- The `vocab` step reads private patterns from the Secret Manager secret
  `ua-rust-vocab-denylist` (newline-separated extended regexes, the same
  format as the `VOCAB_DENYLIST` Actions secret) when it exists in the build's
  project, and needs the build's service account to be able to read it.
  Without the secret it checks the generic patterns only and says so in the
  log.

## Privacy

This repository is public. No personal names, e-mail addresses, home
directory paths, host names or real tokens in code, tests, docs or commits.
Use placeholders such as `builder-1`, `operator`, `~/projects`,
`example.com`. `scripts/vocab-check.sh` (run in CI) enforces this; list an
intended exception in `scripts/vocab-allowlist.txt`.
