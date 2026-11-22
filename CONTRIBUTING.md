# Contributing

The [software factory direction](docs/software-factory.md) describes what
ua-rust is building toward and the evidence that will show it works across
harnesses. Use it to judge a proposal's value alongside its compatibility
requirements.

## Layout

| Crate | Rule |
|---|---|
| `ua-core` | No I/O beyond reading config. Types, profiles, sandbox resolvers. |
| `ua-ingress` | The address classifier and the guarded outbound HTTP client (`Outbound` with a named `Policy`). Depends only on `ua-core`; only `ua-tools` and `ua-server` depend on it. Call other systems through it: `tests/ingress_guard.rs` fails on a new `reqwest` client builder, address classifier or inbound delivery table outside it (see [docs/ingress.md](docs/ingress.md)). |
| `ua-store` | SQLite access and the ledger. No tool logic. |
| `ua-memory` | The memory domain: schema parts, note model, save, search, ranking, embeddings, lifecycle. Depends only on `ua-core` and `ua-store`, never on the `Registry`. Its tools are registered in `ua-tools` (`families/memory`), and adapters reach memory only through them; `ua-memory/tests/boundary.rs` fails if any other crate depends on it. |
| `ua-tools` | Tools. Every tool is registered in the `Registry` and runs only through `Registry::call`. |
| `ua-server` | Adapters (MCP, HTTP, UI). Adapters build a `Caller` and call the registry; they never run tool code directly. |
| `ua-cli` | The `ua` binary. |

## Adding a tool family

1. Create `crates/ua-tools/src/families/<name>.rs`.
2. Tables: declare `pub const SCHEMA: SchemaPart` (or several) with a unique,
   versioned name such as `"memory.v1"`. Use `CREATE TABLE IF NOT EXISTS`.
   Never edit a released part; add `"memory.v2"` instead. Tables shared by
   several families (tasks, agents, agent_sessions) live in `core_schema.rs`.
   Classify every new table in `crates/ua-tools/tests/org_classification.rs`
   (see `docs/organization.md`, Scoping per subsystem); an unclassified table
   fails that test.
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
UA_CI_GCP_PROJECT=<project-id> UA_CI_SERVICE_ACCOUNT=ua-rust-ci@<project-id>.iam.gserviceaccount.com \
  scripts/cloud-ci.sh <pr-number | branch | sha>
```

- It uploads a one-commit checkout of the resolved head, submits
  `deploy/cloudbuild/ci.yaml` from your checkout, waits for the build, and
  posts `CI / vocab`, `CI / check` and `CI / full-verification`. When the
  commit has `sdk/typescript`, an `sdk` step (Node image, the `verify` job of
  `.github/workflows/sdk.yml`) runs beside them; it has no status of its own,
  and `CI / full-verification` fails if it fails. Each status
  names the build and links to its log. A PR number or branch resolves to the
  head GitHub has, so push first.
- The commit's own code (build scripts, tests) runs inside the build with the
  build's credentials. A PR from a fork is therefore refused unless you have
  reviewed it and pass `--allow-fork`; a SHA is run as given. The build runs as
  `UA_CI_SERVICE_ACCOUNT` (see below). Without it the script refuses, unless
  `--default-sa` explicitly accepts the project's default build account and
  all of its permissions.
- The `vocab` step runs your checkout's `scripts/vocab-check.sh` (uploaded
  beside the step script), never the head's copy, so the private denylist is
  only handed to code you run.
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

### The build's service account

Use a dedicated, least-privilege account. It needs:

- `roles/logging.logWriter` on the project, for the build log (the config
  logs to Cloud Logging only, as a user-specified account requires);
- `roles/secretmanager.secretAccessor` on the `ua-rust-vocab-denylist` secret
  only, and only if that secret exists;
- nothing else. If the first build cannot fetch its source,
  `roles/storage.objectViewer` on the `<project-id>_cloudbuild` bucket, where
  `gcloud builds submit` uploads it, is the one addition to make.

Whoever runs the script also needs `roles/iam.serviceAccountUser` on that
account, to start builds as it. The commit under test runs with this
account's token, so anything the account can read, the commit can read too:
the denylist is the only secret within its reach.

## Privacy

This repository is public. No personal names, e-mail addresses, home
directory paths, host names or real tokens in code, tests, docs or commits.
Use placeholders such as `builder-1`, `operator`, `~/projects`,
`example.com`. `scripts/vocab-check.sh` (run in CI) enforces this; list an
intended exception in `scripts/vocab-allowlist.txt`.
