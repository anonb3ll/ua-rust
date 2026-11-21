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
- Slack ingress, off by default: `POST /api/slack/commands` and
  `POST /api/slack/events`, mounted only with `slack_enabled = true` and
  `UA_SLACK_SIGNING_SECRET`. Each Slack (`team_id`, `user_id`) pair in
  `[[slack_identities]]` runs the nine coordination commands as the human
  identity it is mapped to, through the governed call path, recorded with
  the new `slack` transport; `/approve` needs the mapping's `can_approve`
  opt-in and then follows `approval_resolve`'s rules. Slash-command results
  go to `response_url` on `hooks.slack.com` only. Repeated event ids and
  trigger ids are dropped (`slack_seen_deliveries`), and a command accepted
  before a stop with no recorded outcome is ledgered at startup as
  `agent.slack.request.abandoned` (outcome unknown). Messages run only when
  marked (`!task …`, or `/task` after a mention), and direct messages only
  when delivered to the app's bot. Interactions and bot-token posting are
  not included.
- Slack Socket Mode, off by default (`slack_socket_mode = true` plus the
  app-level token in `UA_SLACK_APP_TOKEN`, never the config file): `ua serve`
  opens an outbound WebSocket to Slack, so a hub with no public URL can serve
  Slack. Envelopes go through the same admission and execution as the HTTP
  routes; a redelivered envelope is acknowledged and runs nothing (its
  envelope id goes into the replay table). Slash-command answers ride in the
  acknowledgement. The socket URL must be `wss` on `slack.com`; reconnects
  back off with jitter, and a refused token stops the transport with one log
  line. `system_doctor` reports the transport's state. Behind the new
  default-on cargo feature `slack-socket` (tokio-tungstenite, on the existing
  rustls stack).
- The TypeScript SDK under `sdk/typescript` (`@unified-agent/protocol` and
  `@unified-agent/client`; not published), with workflows that typecheck,
  test and check codegen, and run the live conformance suite against a
  `ua serve` built from the commit.
- Operations commands: `ua init` (private `$UA_HOME`, a validated
  `config.toml`, an optional starter policy and token), `ua doctor` (read-only
  checks of config, permissions, policy, SQLite and the ledger, with `--json`
  and `--strict`), `ua backup` (an online snapshot, safe while `ua serve` runs)
  and `ua restore` (verifies the backup, keeps a pre-restore copy, and needs
  the hub stopped). `ua-store` gained `check_database`, `backup_database` and
  `restore_database`. Docker, systemd, launchd and Litestream templates are in
  `deploy/`, with `docs/operations.md`.
- Zulip, off until `zulip_site`, `zulip_email` and `zulip_api_key` are set:
  `zulip_send_message` (retired unless `zulip_retired` is turned off) and
  `zulip_fetch_messages` (a cursor per agent, channel and topic; messages are
  labelled untrusted). The API key is never logged, ledgered or stored.
- Slack request signature check (v0 HMAC, five-minute window, replayed bodies
  refused) and `slack_parse_command` for the nine coordination commands. The
  Slack routes above build on both.
- Organization groundwork (`docs/organization.md`, `organization.v1`): the
  `orgs` table with one seeded `default` organization, and `org_id` and
  `hash_v` columns on `event_log`, in the schema part `organization.v1.store`.
  Every event belongs to `default` and keeps the existing hash form
  (`hash_v = 1`); `org_id` is not covered by that hash yet, so it is not
  tamper-evident. Ledger verification refuses any other `hash_v`. No tool and
  no permission changes.
- Procedure schema parts: a part that runs a Rust function once, records its
  version and the SQL it generated (`schema_procedures`), and refuses a
  version change under the same name. A `standalone` procedure runs outside
  the shared migration transaction. `ua_store::org::tenant_part` builds the
  part that gives a crate's tables `org_id` and its guard triggers.
- A test that classifies every table for organization scoping and fails on
  an unclassified one.

### Changed

- `ua import python-hub` never copies a source `org_id` by column name, even
  where the target has the column (`event_log`, the harness config tables).
  Such rows are refused unless `--drop-org-scope` is given. Before this,
  `harness_config_bundles.org_id` was copied verbatim.
- Upgrade note: a backup taken after `organization.v1.store` applied cannot be
  restored by an earlier build, even with `--allow-newer`, because that build
  sees `event_log` as an altered table and refuses. Older backups restore into
  this build as before (see `docs/operations.md`).
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
- Bearer and session lookups and every sign-in handler no longer block
  runtime threads, and the cookie key is cached for up to a minute. A database
  read that finds every pooled reader busy opens a short-lived extra reader
  (at most four) instead of queueing behind the writer, and a panic in a read
  no longer leaks a reader.
- A successful read-only call made for a UI page, or for `GET /api/board` from
  a signed-in browser session, leaves no `tool_calls` row; other callers of
  `GET /api/board` get one summary row. `memory_search` and `memory_get` are
  marked read-only but still record a row, because they update access
  counters, and a failed counter update no longer fails the read.
- `ua serve` stops on SIGTERM as well as Ctrl-C: one cancellation token stops
  the server and the background loops, and the WAL is checkpointed on exit.
- Canonical JSON for approval payloads, digests and fingerprints sorts keys
  itself (`ua_core::canonical`) instead of relying on serde_json's map order.
  The output is byte-identical to before.
- The `/login` pages and the OAuth consent page carry no inline script or
  style, and are covered by a content security policy.
- The stale-worktree scan works on macOS, where it reads processes with
  `proc_pidinfo`.

### Security

- `/api` and `/ui` refuse an unknown host and a cross-site write.
- Auth fails closed: with `enforce_auth` and no token, every route except
  `GET /healthz` is rejected.
- Agent tokens are stored as SHA-256 digests.
- The GitHub webhook checks HMAC-SHA256 and refuses a delivery id it has
  already seen.
- The Slack routes verify the signature over the raw body before any parsing
  or database transaction (401 otherwise), refuse a replayed signature and an
  unmapped Slack user, never use `user_name` for identity, and refuse a
  `slack_identities` table with a duplicate pair or a non-human identity at
  load.
  A signed request from an unmapped Slack user adds no ledger row (only its
  replay-table entry), and `/approve` is accepted only as a slash command,
  never from an Events API message an app could post on a user's behalf.
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
  once, as `delegate`, and can be requested ahead. `handoff` is held to
  `delegate`'s profile entry, policy rules and approval gate (a reviewer
  session could hand off what it may not delegate). A call with no `action`
  is gated as the tool's default action. A `tool:action` spelling of an
  action that has a standalone tool (`plan_manage:delete`) restricts that
  tool in `approval_tools` and restrictive policy rules; an `allow` so
  spelled stays literal, so no existing policy is loosened.
  A plan object read through `platform_object_get` is also checked as
  `plan_get`. Upgrading: an approval for `delegation_manage` `create` or for
  `handoff` requested before the upgrade and not yet used bound the old
  payload (the normalized request); it no longer matches and must be
  requested and approved again, as `delegate`.
- `POST /api/approvals/request` runs the same profile, policy and prod-action
  checks as a tool call before it parks a request, and refuses a tool that
  binds its own approval or marks its arguments secret (409). A payload that
  does not match the tool's typed arguments gets 400, and one over 16 KiB gets
  413. `agent_token_issue` and `agent_token_rotate` bind the label and a keyed
  fingerprint of the token, never the token.
- Releasing a task hold as its creator, and binding or unbinding a project
  repository, need a verified identity; an unverified `actor` is no longer
  trusted.
- A node session credential can no longer reach memory tools, and a granted
  tool with no narrowing rule is refused (`session_tool_unscoped`).
- The host check covers the HTTP/2 `:authority` and absolute-form request
  targets, so a request without a `Host` header is no longer let through.
- Deleted elements in a planning canvas are not parsed as live shapes, and
  canvas history is bounded by `graph_canvas_history_max_bytes` per board.

[Unreleased]: https://github.com/anonb3ll/ua-rust/commits/main
