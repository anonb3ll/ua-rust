# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No version has been released. The items below are what `main` contains, taken
from its commit history.

### Added

- Workspace crates `ua-core`, `ua-store`, `ua-tools`, `ua-server`, `ua-cli` and
  `ua-import`.
- Hash-chained event ledger in SQLite, with verification that fails on an
  unhashed row inside the chain. An imported unhashed prefix must be exactly
  as long as the import recorded.
- Tool registry and a call wrapper that checks the profile, the policy file
  and the approval gate, then records the call.
- MCP over stdio and Streamable HTTP, an HTTP/JSON API, bearer tokens, and the
  `ua` binary.
- Tool families for tasks, messaging, agents and sessions, files and commands,
  git, plans, delegation, memory, policy, a vault, web and code intelligence,
  and observability.
- Control Center UI and a compatibility API.
- OAuth 2.1 authorization server, passkeys and browser sessions.
- `ua import python-hub`, which copies a database from the original hub. A dry
  run reports counts without writing. A re-run resumes. The source ledger is
  checked, and a refusal happens before any target write.
- Dispatch runs and an executor. An approval binds the resolved workdir, argv
  and prompt. An operator can cancel a run. A previous process's orphans are
  reaped, including on macOS.
- Workflow engine, cron routines and autonomous cycles.
- Security audit, skill review, injection triage and session tools. Applying
  an audit remediation requires approval and is recorded.
- Node registry: register, heartbeat, list, retire, reassign and forget.
- Node work queue: approval-bound dispatch, long-poll claims, receipts,
  commands, follow-ups and permission prompts.
- Planning canvas and capability tools.
- Managed secrets (encrypted at rest; no tool returns a value), an MCP server
  registry and `mcp_gateway`.
- Governance controls: agent lifecycle, task holds, claim release and work
  proposals.
- Platform routes used by the TypeScript SDK: runs, platform objects and
  client evidence.
- Continuity records: task workflow, session handoff notes, and queue closure
  (park, fold, unpark) in its own task columns.
- Node session credentials and device acceptance.
- Public relay (`relay_manage`). The gates refuse a draft; they do not rewrite
  it. A send repeats the approved text.
- Idle-session wakes, a provider-account registry and a Pi harness.
- GitHub connector limited to bound repositories: CI checks, a signed webhook
  with replay protection, and polling when no webhook can reach the hub.
- Harness config bundles served at `/api/node/config`, and a skills registry.
- A security contact in `SECURITY.md`, and `NOTICE`.
- A Cloud Build runner that builds the pushed head.

### Changed

- Session profile names are neutral capability tiers. Older names are accepted
  only as aliases.
- Acting as a human from the CLI requires an interactive confirmation. Each
  `run_cmd` call gets a fresh `HOME`.
- `run_cmd` uses a per-caller cargo home, refuses cargo when an ancestor cargo
  config is not listed and hashed, and does not put the operator's cargo
  binaries on `PATH`.
- Sign-out is a POST form that carries the session CSRF token.
- A `run_cmd` refusal does not say whether the program is on the allowlist.
- Migration manifests are version 2: the event log is a summary (count, ulid
  range, a rolling hash over recomputed entry hashes, `chain_ok`) with an
  optional `events_since_ulid` row listing kept out of the fingerprint, the
  manifest is streamed against its cap, and memory is capped at 50000 notes.
  `compare_migration_manifests` reads the caller's own recorded exports under
  `exports/` and compares event logs, row content included. Both tools are
  denied to developer and lead sessions, and `export_data` runs them as
  governed calls under their own names.
- The manifest summary's `chain_ok` covers `seq`-order `prev_hash` linkage
  from genesis and zero `entry_hash` mismatches, plus a legacy unhashed prefix
  whose length must match the length the import recorded in `ledger_meta`;
  stores imported before that record existed (0a2466b) report false, as
  `event_log_verify` already does. Ulid order feeds the rolling hash but is
  not checked for linkage, so imported rows whose ULIDs were minted out of
  write order no longer fail it. The summary has no anchor: it records the
  count, the ulid range and the rolling hash, not the head `entry_hash`, so a
  truncated or rewritten tail still reports true — compare against an earlier
  manifest to catch it.
- `python_lint_and_format` keeps the project's ruff style: it forwards
  line-length, indent-width, target-version, quote style, excludes
  (relative globs, anchored at the project) and the lint select, ignore,
  extend and per-file-ignores settings, validated, as `--config` pairs, and
  still runs with `--isolated`, from an empty directory, on an absolute path. Its ledger event lists the files a run changed and ruff's
  fixed and reformatted counts.
- The memory domain (schema, note model, save, search, ranking, embeddings,
  lifecycle) moved from `ua-tools` into a new `ua-memory` crate, which does
  not depend on the tool registry. Tool names, arguments, schema parts and
  ledger events are unchanged; `ua-tools/embeddings` still turns on semantic
  search.
- tree-sitter, dom_smoothie and rmcp are optional, behind cargo features that
  are on by default: `code-intel` (the four symbol tools), `readability`
  (article extraction in `web_fetch` and `dash_view`), `mcp-gateway` (the
  `mcp_gateway` client) and `mcp-server` (`/mcp` and `ua mcp`). Every crate
  forwards them, and `embeddings`, under the same names. A
  `--no-default-features` build reports what it lacks: `system_doctor` and
  `capability_catalog` list `build_features` and the tools left out,
  `web_fetch` and `dash_view` results carry `extraction`, `mcp_server_register`
  refuses without a gateway, and without an MCP server `ua serve` warns, OAuth
  issues hub-wide tokens and does not advertise `/mcp`, and `ua mcp` exits with
  an error naming the feature.

### Security

- `/api` and `/ui` refuse an unknown host and a cross-site write.
- Auth fails closed: with `enforce_auth` and no token, every route except
  `GET /healthz` is rejected.
- Agent tokens are stored as SHA-256 digests.
- The GitHub webhook checks HMAC-SHA256 and refuses a delivery id it has
  already seen.
- OAuth `client_credentials` refuses a scope other than `mcp`, a retired
  identity, and an identity with no configured profile (it no longer falls
  back to `developer`). An authorization code exchanged after its identity
  was retired is refused.
- OAuth identities never fall back to the `developer` profile: an access
  token, a refresh and a code exchange are refused once the identity has no
  explicit `profiles` entry, and refreshing a consented grant needs the
  identity to still be in `oauth_identities`. An unknown client id and a
  wrong client secret get the same error.
- A `harness_config_apply` approval binds deterministic values only; the diff
  the approver reads is shown beside it (and only when it was computed from
  the base the approval binds), so an approved pass no longer stops matching
  when the diff timed out. Upgrading expires apply approvals in the old
  payload shape, pending or approved but unused; nodes report again.
- Front matter in harness config rules text and skills may carry only
  allowlisted keys (`name`, `description`, `globs`, `alwaysApply`,
  `argument-hint`, `model`; skills also `license`, `version` and a
  `metadata` map of plain values) with plain values; front matter that does
  not parse is refused.
- A gate on a tool holds when a consolidated tool runs it as an action.
  `plan_manage`, `delegation_manage`, `coordination_manage`,
  `observability_manage`, `autonomous_cycle_manage` and `export_data` ran
  their actions' handlers directly, so `approval_tools = ["plan_delete"]` or
  a policy rule on `plan_delete` did not stop `plan_manage` action `delete`.
  Such a call now passes the profile check, policy rules, approval gate and
  prod-action check of the standalone tool too, and its approval binds what
  a direct call binds, so one approval runs one action once through either
  tool. An action with no standalone tool is
  gated as `tool:action` (`plan_manage:close`) in `approval_tools` and policy
  rules; `system_doctor` flags a key that matches nothing. Rate limits and
  cooldowns on the standalone name count calls through the consolidated
  tool. An unknown action is refused before the tool runs. `tool_calls`
  gains `action_tool` (schema part `core.v4`), gateway decisions name it,
  and approval events carry `via`. `delegation_manage` `create` is gated
  once, as `delegate`, and can be requested ahead.

[Unreleased]: https://github.com/anonb3ll/ua-rust/commits/main
