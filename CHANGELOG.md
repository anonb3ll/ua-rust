# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No version has been released. The items below are what `main` contains, taken
from its commit history.

### Added

- File deliverables can be submitted from a task worktree, verified by SHA-256
  and released to a configured directory after an independent human approves
  the exact revision and destination. The release records approval and
  completion evidence and moves the task and workflow to done.

- A verified human operator can cancel an unpublished file release by its
  approval ID. Cancellation discards the saved bytes, frees the reserved
  destination and records an audit event. A later attempt needs fresh approval.

- Evidence checkpoint signing and the public-key store (S2 of
  `docs/evidence-export.md`): `evidence_key` holds Ed25519 public keys only,
  `evidence_checkpoint` holds one row per checkpoint with its canonical digest
  and the operator's signature. `ua evidence key-generate|key-add|key-retire|
  key-revoke|checkpoint|sign|attach|verify` runs the offline signing step. The
  hub never holds a private key: it writes the digest, the operator signs it
  offline, and `verify` recomputes the digest, checks the ledger anchor and
  checks the signature against a pinned key, exiting non-zero unless the
  signature is valid. The signed digest carries the domain tag
  `ua.evidence.checkpoint.v1`; key and checkpoint changes are ledgered; the
  offline commands do not open a hub database. Red tier — ledger semantics.
- GitHub webhooks per organization: `POST /api/github/webhook/{org}` (the
  organization's id) checks a delivery against that organization's own
  webhook secret only, and handles it for that organization only. The bare
  `POST /api/github/webhook` stays the default organization's route (also
  reachable as `/api/github/webhook/default`) and checks only
  `github_webhook_secret_env`. Configure each organization's GitHub webhook
  with its own URL (`docs/github.md#security-model`).
- `github_webhook_max_in_flight` (default 16, clamped to 1-256): one cap on
  deliveries being read or handled across both webhook routes. Over it a
  delivery waits up to `github_webhook_busy_wait_ms` (default 2000) for a
  slot, then is answered 429 `busy` with `Retry-After: 1` before its body
  is read, and nothing is recorded. A delivery holding a slot must send its
  whole body within `github_webhook_read_timeout_ms` (default 10000) or is
  answered 408 `timeout` and its slot freed, so senders that declare a body
  and never send it cannot hold the cap. GitHub does not redeliver a
  refused delivery on its own: enable the poller as a backstop and
  redeliver by hand (`docs/github.md#security-model`).
- Webhook routes whose secret another route shares are refused (fail
  closed). At startup and after every webhook-secret change the hub
  compares the hub configuration's secret with every organization's stored
  one (by keyed fingerprint under each row's key) and the stored ones with
  each other; every matching route, the bare route included, answers
  401 `bad_signature` until each has its own secret. The hub logs an error
  naming the organizations, and `system_doctor` counts the refused routes.
  Only the serving hub runs the check. If it fails (a database error),
  every route is refused while the hub retries it in the background with
  a backoff capped at one minute, until one succeeds.
- Every webhook refusal takes the same steps: one database read with the
  same query for any organization id, one AES-GCM decryption (a dummy one
  when there is nothing to decrypt) and one MAC. Equal work, not constant
  time: SQLite's time to find or miss a row is not equalised.
- `github_credential_set` kind `webhook_secret` refuses a value that another
  organization already stores, or (outside the default organization) the
  hub's `github_webhook_secret_env` value: 409 `webhook_secret_in_use`,
  naming no organization. Compared by keyed fingerprint under each stored
  row's own key, never by plaintext, after the approval gate (a
  replacement answers nothing before its approval), and each refusal is
  ledgered as `github.credential.refused` with the attempted value's keyed
  fingerprint only. Set and clear still refuse every caller until
  memberships exist, so this waits for that path.
- Workspace crates `ua-core`, `ua-store`, `ua-tools`, `ua-server`, `ua-cli` and
  `ua-import`.
- Crate `ua-ingress` (`docs/ingress.md`): one address classifier
  (`ua_ingress::addr`, with a public class and a stricter global-unicast-only
  class) and one guarded outbound HTTP client (`Outbound`)
  built from a named policy per destination class. The client ignores proxy
  settings, follows redirects only when the policy allows (checking every
  hop), caps every body read, checks addresses at connect time through its
  resolver and again on the connection's peer address, sends a secret header
  only to the origin it was built for, and bounds connect, request and total
  time. An unknown policy is refused. Slack slash-command replies are its
  first consumer (policy `slack.response_url`); their refusals and failure
  reasons (`response_url_refused`, `timeout`, `transport`, `status`) are
  unchanged. A ratchet test counts `reqwest` client builders, address
  classifiers and inbound delivery tables outside the crate; the counts may
  only go down.
- `ua-ingress` hardening before any policy follows redirects: a hop to
  another origin carries only `Accept` and `Accept-Language` (every other
  header stays with its origin, whatever its name), a 307 or 308 that would
  resend the body to another origin is refused, and a redirect from https to
  http is refused unless a policy allows it (none does). The ratchet also
  counts connections dialled by hand, inline address range checks, and
  delivery tables recognised by name marks or columns instead of a fixed
  list. No change for Slack replies, which follow no redirect.
- Slack's replay keys (signed bytes, Socket Mode envelopes) and delivery
  ids (`trigger_id`, `event_id`) moved onto `inbound_deliveries` (source
  `slack`; kinds `request_sha`, `trigger`, `event`). Slack never takes a
  stale delivery on again (`Stale::Duplicate`): a command admitted and
  never finished is refused as a repeat and reported by the startup sweep
  as before. Every HTTP response and Socket Mode acknowledgement, every
  reply text and every ledger event is unchanged. `slack.inbound.v1.copy`
  carries the old rows across with their states; `slack_seen_signatures`
  and `slack_seen_deliveries` stay, unread and unwritten, until a later
  release drops them. `ua_ingress::inbound` gains `abandon_all_accepted`
  (the startup sweep) and `claim_of`, and an expired row is now kept
  through its expiry second (as both families did before). Downgrading past
  this change while Slack takes traffic lets a Slack retry of a command the
  newer build already ran run again for about a day (`docs/ingress.md`,
  Limits).
- `ua-ingress::inbound`: one inbound-delivery table, `inbound_deliveries`
  (parts `ingress.inbound.v1`, `organization.v1.ingress`; a tenant table
  from birth), with `record`, `accept`, `finish`, `release` and `sweep` and
  the states `seen`, `accepted`, `finished`, `abandoned`. The GitHub
  webhook's delivery-id and body-hash checks moved onto it;
  `github.inbound.v1.copy` carries the rows of `github_deliveries` and
  `github_delivery_bodies` across, and those two tables stay, unread and
  unwritten, until a later release drops them. `ua-ingress` now depends on
  `ua-store`.
- `ua-ingress`: once a redirect chain leaves the request's origin, the
  caller's headers and secret headers are dropped for the rest of the
  chain, including a hop back to the original origin (only `Accept` and
  `Accept-Language` travel from then on), so an intermediate origin cannot
  choose which path on the original origin receives them.
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
  checked, and a refusal happens before any target write. Now also imports
  `work_proposals`, `work_proposal_items`, `task_holds`, `task_hold_members`
  and `project_repo_bindings`, clears `tasks.current_run_id` and
  `current_run_agent` (since `dispatch_runs` are not imported) with separate
  count and capped task-id reporting, never copies `org_id` on any mapped
  table including `harness_config_bundles`, refuses duplicate active holds and
  duplicate trimmed project slugs in `--dry-run` as well as real imports, and
  clears invalid `project_repo_bindings.default_branch` values to `NULL`
  instead of dropping the binding.
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
- `ua-org`, a new crate holding `authz`: the operator, dispatch, hub-view
  and mailbox authority checks go through it, with today's rules kept as
  named transitional authorities, and a guard test holds the remaining
  ad-hoc checks to counts that only go down.
- Callers and ledger events name their organization: `Caller.org_id` and
  `Caller::system_for`, and `EventInput::new` takes the `org_id` first (no
  `Default`). Every caller and every event is in the default organization;
  nothing reads the value for authority, and no serialized output a tool
  returns changes.
- Organization groundwork (`docs/organization.md`, `organization.v1`): the
  `orgs` table with one seeded `default` organization, and `org_id` and
  `hash_v` columns on `event_log`, in the schema part `organization.v1.store`.
  Every event belongs to `default` and keeps the existing hash form
  (`hash_v = 1`); `org_id` is not covered by that hash yet, so it is not
  tamper-evident. Ledger verification refuses any other `hash_v`, and the
  store refuses to open, or append to, a ledger whose newest row has a newer
  `hash_v` than this build writes (a rollback fence). No tool and no
  permission changes.
- Procedure schema parts: a part that runs a Rust function once, records its
  version, arguments and the SQL it generated (`schema_procedures`), and
  refuses a version or argument change under the same name. A `standalone` procedure runs outside
  the shared migration transaction. `ua_store::org::tenant_part` builds the
  part that gives a crate's tables `org_id` and its guard triggers.
- A test that classifies every table for organization scoping and fails on
  an unclassified one.
- The software factory acceptance scenario as a scored test
  (`crates/ua-server/tests/factory_scenario.rs`): each step of the scenario in
  `docs/software-factory.md` is a set of named checks, each `pass`, `fail` or
  `not-built`, compared against a checked-in scorecard
  (`tests/fixtures/factory_scenario.txt`) that only moves forward. Status
  page: `docs/software-factory-status.md`. Tests and docs only.
- The first existing table family with an organization key: the code
  family's `code_symbols` gets `org_id` (existing rows backfilled to
  `default`) and its `org_exists` / `org_immutable` triggers in the schema
  part `organization.v1.tools.code`. `fs_index_symbols`, `fs_list_symbols`,
  `fs_search_symbols` and `fs_repo_map` read and write only the caller's
  organization's symbols, and indexing for an organization `orgs` does not
  hold is refused (`invalid_argument`) before anything changes. A hub with
  only the default organization sees no change in any tool result or event.
  As with every new part, a database that has applied it is refused by an
  earlier build (the unknown-part fence).
- Graph canvas boards and revisions have organization-scoped keys and
  triggers. Existing boards and history migrate to `default`. Organizations
  can use the same board names independently, with separate board quotas and
  revision retention. Canvas tool results and event payloads retain their
  existing shapes.
- Web search cache rows (`web_search_cache`) have organization-scoped keys
  and triggers (`web.v2.tenant_keys`, `organization.v1.tools.web`). Existing
  cached entries migrate to `default`. Organizations cache identical queries
  independently, and one organization's TTL eviction does not remove another
  organization's cached entries.
- Skill registry versions, assignments and staged publishes
  (`skill_versions`, `skill_assignments`, `skill_publish_staging`) are
  organization-scoped. The standalone rebuild `skill_registry.v2.tenant_keys`
  makes the keys `UNIQUE(org_id, name, version)` and
  `UNIQUE(org_id, skill_name, target_type, target)`, keeping ids, the
  AUTOINCREMENT sequence, indexes, the version immutability triggers and
  views, and adds indexes led by `org_id`; `organization.v1.tools.skills`
  adds `org_id` to the staging table and installs the organization triggers
  on all three. Existing rows migrate to `default`. Every `skill_registry`
  action and the skills a node's harness bundle carries use the caller's
  organization: another organization's skill, version or staged publish
  answers as a missing one, and a write for an organization `orgs` does not
  hold is refused (`invalid_argument`) before anything is read or written.
  The importer writes legacy skill versions and assignments to `default`.
  Results and events in the default organization are unchanged.
- Project repository bindings (`project_repo_bindings`) have
  organization-scoped keys and triggers
  (`governance.v2.project_bindings_tenant_keys`, a standalone rebuild, then
  `organization.v1.tools.project_bindings`). Existing bindings migrate to
  `default`. `project_repo_bind`, `project_repo_unbind`, `project_repo_get`
  and `project_repo_list` read and write only the caller's organization's
  bindings, so two organizations may bind the same project slug to different
  repositories; a bind or unbind for an organization `orgs` does not hold is
  refused (`unknown_organization`) before anything changes, and both that
  refusal and `operator_required` come before the writer lock is taken.
  Task-driven lookups (CI check verification, merges, policy authorizations,
  merged-PR reconciliation, deliverables, GitHub polling and webhooks) use
  the default organization's bindings, since tasks are not yet
  organization-scoped; each names the shared `TASK_ORG` constant, and a test
  proves another organization's binding of the same project is never read. The
  importer writes imported bindings to `default`. Tool results and event
  payloads keep their shapes.
- The notification tables carry an organization key: `notify_outbox` and
  `pending_notifications` (`organization.v1.tools.notify`, with indexes led
  by `org_id` in `notify.v2.org_indexes`) and `zulip_sends`
  (`organization.v1.tools.zulip`). No key rebuild: none has a key beyond its
  AUTOINCREMENT id. Existing rows move to `default`. `notify`,
  `batch_notify`, `flush_digest` and `notify_delivery_status` read and write
  only the caller's organization's rows (the digest threshold counts that
  organization's queue, and a digest never mixes organizations);
  `review_ready` notices are recorded in their task's organization
  (`TASK_ORG`). The hub's webhook and Zulip configuration are the default
  organization's destinations: another organization's notifications stay in
  its outbox as `not_configured`, and its `zulip_send_message` is refused
  (`zulip_not_configured`) before anything is recorded. The Zulip duplicate
  check and `zulip_resolve_send` see only the caller's organization's sends;
  another organization's send answers as a missing one. An organization
  `orgs` does not hold is refused before any write. The `observability`
  webhook health check reads the default organization's last delivery.
  `review_ready_notices` stays in the tasks family. Results and events in
  the default organization are unchanged.
- Harness config bundles, drift proposals, drift reports and report windows
  (`harness_config_bundles`, `harness_config_proposals`,
  `harness_config_drift`, `harness_config_report_window`) are
  organization-scoped. The standalone rebuild `harness_config.v3.tenant_keys`
  makes the bundle key `UNIQUE(org_id, version)`, makes the proposals'
  nullable `org_id` `NOT NULL`, and keys report windows by `(org_id, node)`,
  keeping the bundles' ids and AUTOINCREMENT sequence, indexes, triggers and
  views, and adding indexes led by `org_id`; `organization.v1.tools.harness_config`
  adds `org_id` to the drift table and installs the organization triggers on
  all four. Existing rows, including legacy `NULL` `org_id`s, migrate to
  `default`. Each organization has its own bundle versions and active bundle:
  `harness_config_publish`, `harness_config_status` and `node_config`
  (`get`, `report`, `applied`) use the caller's organization, another
  organization's bundle or proposal answers as a missing one, and a publish,
  report or applied call for an organization `orgs` does not hold is refused
  (`unknown_organization`) before anything changes. The importer writes
  legacy bundles to `default`. Event payloads and tool results keep their
  shapes.
- Routines and workflow runs carry an organization key: `routines` and
  `routine_runs` (`organization.v1.tools.routines`, with indexes led by
  `org_id` and a same-organization rule between a receipt and its routine in
  `routines.v2.org_indexes`), and `workflow_runs` and `workflow_checkpoints`
  (`organization.v1.tools.workflows`, with indexes and a same-organization
  rule between a checkpoint and its run in `workflows.v2.org_indexes`). No key
  rebuild: their keys are AUTOINCREMENT ids, hub-generated run ids, and
  unique pairs led by one of those. Existing rows move to `default`.
  `routine_add`, `routine_list`, `routine_pause`, `routine_fire`,
  `workflow_run`, the `langgraph_*` tools and the workflow rows of `run_list`
  and `run_get` read and write only the caller's organization's rows; another
  organization's routine or run answers as a missing one, and an organization
  `orgs` does not hold is refused before any write. The scheduler and the
  startup reconciliation fire each routine in its own organization, and a
  routine's workflow run takes the routine's organization. Tasks carry no
  organization yet (`TASK_ORG`), so a fire of a routine in another
  organization creates no task and runs no workflow: it is recorded as
  `skipped` with reason `org_tasks_unavailable`, and `routine_fire` now
  returns a skipped fire's `reason`. LangGraph runs see only the task
  organization's tasks. A gated workflow step's approval payload binds
  `org_id`, so an approval parked before this change is not reused: resuming
  such a run parks a new one. Results and events in the default organization
  are otherwise unchanged.
- Plans, plan steps and plan checkpoints (`plans`, `plan_steps`,
  `plan_checkpoints`) are organization-scoped: `organization.v1.tools.plans`
  adds `org_id` and the organization triggers, and `plans.v2.org_scope`
  adds an index led by `org_id` and triggers that keep a step or checkpoint
  in its plan's organization. No key rebuild: plan ids are hub-generated,
  and the step and checkpoint keys hang off them. Existing rows move to
  `default`. Every `plan_manage` action, the legacy `plan_*` tools and the
  `plan` kind of `platform_object_get` read and write only the caller's
  organization's rows; another organization's plan answers as a missing
  one, and a write for an organization `orgs` does not hold is refused
  (`unknown_organization`) before anything changes. Plan events stay in the
  default organization's ledger, with another organization's text and
  labels left out (`null`): `goal` and `scope` on `agent.plan.created`,
  `owner` on `agent.plan.step_updated`, `agent` on
  `agent.plan.step_claimed`, `agent` and `next_owner` on
  `agent.plan.handoff`, and `reason` on `agent.plan.closed`. The importer writes legacy plans to
  `default`. Results and events in the default organization are unchanged,
  except that plan rows now carry `org_id`.
- Autonomous cycles, their transitions and usage (`autonomous_cycles`,
  `autonomous_cycle_transitions`, `autonomous_cycle_usage`) are
  organization-scoped: `organization.v1.tools.cycles` adds `org_id` and the
  organization triggers, and `cycles.v2.org_scope` adds an index led by
  `org_id` and triggers that keep a transition or usage row in its cycle's
  organization. No key rebuild: cycle ids are hub-generated, and the
  transition and usage keys are led by them. Existing rows move to
  `default`. Every `autonomous_cycle_manage` action, the legacy
  `autonomous_cycle_*` tools and `autonomous_cycle_green_path_eligibility`
  read and write only the caller's organization's rows; another
  organization's cycle answers as a missing one, and an organization `orgs`
  does not hold is refused (`unknown_organization`) before anything changes.
  Tasks carry no organization yet (`TASK_ORG`): only the task organization
  can bind a cycle to a task or a delegation, and to any other organization
  a task or delegation id answers as a missing one. A gated transition's
  approval payload binds `org_id`, so an approval parked before this change
  is not reused: retrying the transition parks a new one. In
  `agent.cycle.updated`, a cycle outside the default organization has a
  `null` `stop_reason` and is attributed to the caller's own label. Results
  and events in the default organization are unchanged, except that cycle
  rows now carry `org_id`. `delegations` is not converted: it belongs to the
  tasks family and converts with `tasks`.
- The approval queue (`approvals`) is organization-scoped:
  `organization.v1.tools.approvals` adds `org_id` and the organization
  triggers, and `approvals.v3.org_indexes` adds indexes led by `org_id`. No
  key rebuild: the only key is an AUTOINCREMENT id. Existing rows move to
  `default`. An approval belongs to its requester's organization: the gate
  (`gate`, `gate_via`, `request`, `peek`, the stale-pass checks) matches a
  denial, pass or pending request only within the caller's organization, so
  a pass granted in one organization never satisfies an identical call in
  another, and an expired pass is expired by its own organization's call.
  `approval_pending`, `GET /api/approvals` and `/api/approvals/{id}`, the
  inbox, `platform_object_get`, the session packet, the evidence report and
  the `approval_queue_age` anomaly show only the reader's organization;
  `approval_resolve` (and so the UI, HTTP and Slack routes over it) answers
  another organization's approval exactly as a missing id. Approving, and a
  human's deny or revoke, also needs `ua_org::authz::require_same_org`, which
  admits only the default organization until memberships exist; the
  requester may still deny or revoke its own request. A gate for an
  organization `orgs` does not hold is refused (`unknown_organization`)
  before anything changes. Approval events stay in the default
  organization's ledger with another organization's `requested_by` and
  `resolved_by` left out (`null`). The importer writes legacy approvals to
  `default`. Results and events in the default organization are unchanged.
- The core task tables are organization-scoped:
  `organization.v1.tools.tasks` adds `org_id` and the organization triggers
  to `tasks`, `task_dependencies`, `task_comments` and
  `task_comment_threads` (existing rows move to `default`), and
  `tasks.v2.org_scope` adds indexes led by `org_id` and same-organization
  triggers for a task's `parent_id` and `folded_into`, both ends of a
  dependency, and a comment's task and parent comment. No key rebuild: task
  ids stay hub-global AUTOINCREMENT ids. `routines.v3.task_org`,
  `workflows.v3.task_org`, `cycles.v3.task_org` and `deliverables.v2.task_org`
  keep a routine run's, workflow run's, cycle's and deliverable's `task_id`
  inside its own organization. Every task, dependency, lineage and comment
  tool, `project_build`, the queue and workflow-record actions, holds,
  claims, dispatch, node work, the session packet, agents, capability,
  policy claims, the evidence report, observability, export,
  `platform_object_get` and the UI's task page read and write only the
  caller's organization's tasks; another organization's task answers exactly
  as a missing one, and a write for an organization `orgs` does not hold is
  refused (`unknown_organization`) before anything changes. Ranked search
  (`task_list query=`) filters the organization before the candidate cap.
  Replies keep their shape: `org_id` is not added to a task or comment.
  A task-driven lookup (its project's binding, deliverables, review-at-head,
  `review_ready`) takes the task row's organization. Task events stay in the
  default organization's ledger; another organization's titles, notes,
  comment bodies, reasons and caller-supplied labels are `null` in them and
  the originator is `system`. `task_add`, `task_update` and `delegate`
  idempotency keys of another organization are stored with its organization
  prefixed, so a key reused in another organization never replays. The
  migration manifest (`export_migration_manifest`,
  `compare_migration_manifests`, and both through `export_data`) is
  hub-wide and refused to another organization's caller (`org_unsupported`).
  Deleting another organization's task also deletes the holds rooted in its
  subtree and the policy authorizations naming it, so none falls into the
  default organization. `state_sync_verify` counts only the caller's
  organization's tasks in `task_fts`'s check, a proposal or contract marker
  on another organization's task fails the contract check without reading
  the default organization's proposals, and a node follow-up checks the
  task holder in the task's organization. The importer writes legacy tasks,
  dependencies, comments and threads to `default`. Results and events in the
  default organization are unchanged, except for two fixes that apply to
  every organization: a `task_update` idempotency key is now the caller's
  (`task_update:<escaped label>:<key>`), is checked only after the task is
  found, and replays only for the same task (another task is refused
  `idempotency_key_reused`); and `conversation_handoff` now creates its task
  itself under `task_add`'s gate, with a key scoped to the organization and
  actor stored under its own tool name, while `task_add` refuses client keys
  starting with `conversation-handoff:`.
- The task workflow and hold tables are organization-scoped:
  `organization.v1.tools.continuity` adds `org_id` and the organization
  triggers to `task_workflow`, `task_checks` and `review_ready_notices`,
  and `organization.v1.tools.holds` to `task_holds` and
  `task_hold_members`. `continuity.v2.org_scope` and
  `governance.v3.holds_org_scope` move existing rows to their task's (a
  hold's root task's, a member's hold's) organization, a row whose task is
  gone staying in `default`, and add indexes led by `org_id` and
  same-organization triggers for every row's task, a hold's root and a
  member's hold. No key rebuild: every key is led by a hub-global task or
  hold id. The workflow record, checks and their verification, the
  review-at-head merge gate, `review_ready` and its notices, the session
  packet's workflow block, deliverables' workflow head, `task_list`'s stage
  filter and every hold read, write and claim check filter on the
  organization; a hold's organization is its own column instead of its root
  task's. The read-time release of `after_active_runs_finish` holds settles
  only the reader's organization's holds. Head re-verification from the
  GitHub webhook and poller stays default-only (`ORG-GITHUB-DEFAULT`).
  Replies keep their shape. The importer writes legacy workflow records,
  checks, holds and members to `default`. Results and events in the default
  organization are unchanged.
- Delegations are organization-scoped: `organization.v1.tools.delegation`
  adds `org_id` and the organization triggers to `delegations`, and
  `delegation.v2.org_scope` moves each existing delegation to its task's
  organization, adds indexes led by `org_id` and the
  `delegations_org_parent` triggers that keep a delegation's task in its own
  organization. No key rebuild: a delegation id is a hub-global
  AUTOINCREMENT id. A delegation and its task are created together in the
  delegator's organization. Every delegation action and legacy tool, the
  plans UI, the evidence report, `delegation_stats`, the session packet,
  `platform_object_get` (which read any organization's delegation before),
  a cycle's `delegation_id` and the task queue's live-work check read and
  write only the caller's organization's delegations; another
  organization's delegation answers exactly as a missing one, including a
  claim or a fenced transition, and a write for an organization `orgs` does
  not hold is refused (`unknown_organization`) before anything changes.
  Replies carry no `org_id`. Delegation events stay in the default
  organization's ledger; another organization's title, project, lane,
  agents, deadline, callback, reasons and results are `null` in them and
  the originator is `system`. The importer writes legacy delegations to
  `default`.
- Goals and work proposals are organization-scoped:
  `organization.v1.tools.goals` adds `org_id` and the organization triggers
  to `goals` and `task_goal_links`, and `organization.v1.tools.proposals` to
  `work_proposals` and `work_proposal_items`. Existing goals and proposals
  move to `default`; `goals.v2.org_scope` moves each link to its task's
  organization (and deletes a link whose goal is then in another
  organization) and `governance.v4.proposals_org_scope` each item to its
  proposal's. Both add indexes led by `org_id` and same-organization
  triggers for a goal's parent, a link's task and goal, and an item's
  proposal and spawned task. No key rebuild: a goal id is a hub-global
  AUTOINCREMENT id and a proposal id is hub-generated. Every `goal_manage`
  action, the goal-project check of a `task_update` project move,
  `platform_object_get` (which read any organization's goal before) and
  every work-proposal action read and write only the caller's
  organization's rows; another organization's goal or proposal answers
  exactly as a missing one, and a write for an organization `orgs` does not
  hold is refused (`unknown_organization`) before anything changes.
  `goal_manage` still refuses `params.org_id`. Replies carry no `org_id`.
  Goal and work-proposal events stay in the default organization's ledger;
  another organization's reasons and proposer are `null` in them and the
  originator is `system`. The importer writes legacy goals, links,
  proposals and items to `default` and never copies a source `org_id`.
- Memory notes are organization-scoped: `organization.v1.memory` adds
  `org_id` and the organization triggers to `memory`, `memory_versions` and
  `memory_embeddings`; every existing row lands in `default` and none is
  dropped. `memory.v2.org_scope` recreates `memory_versions_capture` so a
  version names its note's organization, adds same-organization triggers
  for versions, vectors and supersede pointers, and indexes led by
  `org_id`. No key rebuild: a note id is hub-generated. Every memory tool,
  both search legs (FTS and vectors, scoped inside the ranked query),
  `export_memory`, `platform_object_get`, the session packet,
  `vault_ingest`, `state_sync_verify` and `system_doctor` read and write
  only the caller's organization's notes; another organization's note
  answers as a missing one, and a write for an unknown organization is
  refused (`unknown_organization`), as is one for a suspended organization
  (`organization_suspended`). `memory_promote`, and a file export
  (`write_to_vault`) of tasks, notes or the journal, are refused outside the
  default organization (`org_unsupported`); an inline export still works.
  Another organization's save keys are stored as
  `org:<org>/memory_save/<label>/<key>` with the organization and label
  escaped, and a receipt naming a note the caller cannot see is refused
  (`idempotency_key_conflict`), never replayed. Memory events and
  `state_sync_verify`'s resync event stay in the default ledger with
  another organization's titles, tags, revisions and labels `null` and the
  originator `system`. The importer
  writes legacy notes and versions to `default`. Accepted leak candidate:
  bm25 corpus statistics over the one `memory_fts` index span every
  organization.
- Nodes, node work and dispatch runs are organization-scoped
  (`docs/organization.md`, the nodes family). A node belongs to the
  organization that registered it; work, commands, claims and follow-ups
  belong to their creator's organization and may target only that
  organization's nodes, and another organization's node, item or run
  answers exactly like a missing one. A node token claims, heartbeats and
  reports only its own organization's work. `organization.v1.tools.dispatch`
  and `dispatch.v4.org_scope` give `dispatch_runs` and `dispatch_receipts`
  `org_id`, triggers and same-organization rules; the standalone
  `node_queue.v2.tenant_keys` rebuilds `node_dispatch` with a `NOT NULL`
  `org_id` and launch keys unique per organization (ids and rowids kept);
  `organization.v1.tools.nodes` and `node_queue.v2.org_scope` give the
  seven node tables `org_id`, triggers, org-led indexes and
  same-organization reference triggers. Every existing row lands in
  `default`; none is dropped. Hub-wide views (`system_doctor`'s fleet row,
  a provider account's recent runs) list the default organization's nodes
  and runs and count the rest. Session credentials, device acceptance,
  idle-session wakes and command notices stay default-organization only
  (`org_unsupported`, or the notice kept unsent) until their own tables
  carry an organization. Node and dispatch events from another organization
  keep only ids, states and counts, under the `system` originator, with
  dedupe keys built from hub-generated ids only (no node name or digest of
  one). A reassigned or forgotten node closes only its own organization's
  harness-config proposals, and `node_reassign` refuses a `to_agent` known
  to work in another organization (`agent_org_mismatch`). A default
  lifecycle operator recovers a name another organization holds with
  `node_retire` and `node_forget` `any_org=true`, acting in that node's
  organization. The doctor's fleet row splits other organizations' nodes
  into active and retired, and counts those that take no work under
  `node_require_acceptance` and their unsent command notices. The importer
  writes legacy nodes to `default`.
- Idempotency receipts are organization-scoped (`docs/organization.md`,
  the idempotency keys family). The standalone
  `idempotency.v2.tenant_keys` rebuilds `idempotency_keys` around
  `(org_id, key)` and `organization.v1.tools.idempotency` adds its
  triggers. Every row keeps its rowid, key text, tool, stored result and
  timestamp; a row whose key carries the interim prefix of exactly one
  organization (`org:<org>/<tool>:…`, or the escaped
  `org:<org>/<tool>/…`) moves to it, and every other row lands in
  `default`. Nothing is dropped or rewritten. A prefix naming an
  organization `orgs` does not hold, or two at once, stays in `default`,
  where no writer builds such a key, so it never replays to anyone;
  `system_doctor` reports the count (`database.idempotency_keys_unplaced`,
  default organization only) and the rebuild's audit record names the row
  ids. Every reader (`task_add`, `task_update`, the conversation handoff,
  `delegate` and its `lookup`, `memory_save`, `message_send`,
  `lifecycle_record`) filters on the caller's organization and every writer
  names it. The writers keep the organization prefix in the key text, byte
  for byte as before, as defence in depth and so a retry in flight across
  the upgrade still replays. `lifecycle_record`'s keys, which carried no
  organization, are now the caller's organization's. The one exception to
  the replay: a pre-upgrade `lifecycle_record` key of another organization
  carried no prefix, so it lands in `default`; that organization's retry
  across the upgrade records a second capture, and a default caller who
  sends the same session, kind and key gets the old receipt (its event id
  and the caller-supplied values), as anyone on the hub could before.
  Stored keys are kept indefinitely; there is no retention sweep yet.
- Agents and sessions are organization-scoped (`docs/organization.md`, the
  agents and sessions family). **Design assumption (the owner may revisit
  it):** an agent belongs to exactly one organization, the one of the token
  or grant it authenticates with; its sessions, profile bindings, session
  credentials, handoff notes and wake rows belong to it too. Agent labels
  stay one hub-wide, case-insensitive namespace: a label another
  organization holds is refused (`agent_label_taken`), and a default
  lifecycle operator recovers one with `agent_retire` and the new
  `agent_forget` `any_org=true`, acting in that agent's organization.
  `organization.v1.tools.agents` gives `agents`, `agent_sessions`,
  `agent_tokens`, `agent_lifecycle`, `session_profiles`,
  `session_credentials`, `session_handoff_notes`, `session_wake` and
  `session_wake_offers` `org_id` and their triggers; `agents.v2.org_scope`
  adds org-led indexes and same-organization reference triggers. No key is
  rebuilt; every existing row lands in `default` and none is dropped. The
  HTTP resolver binds a caller to its credential's organization: a managed
  token resolves to its own organization and is refused when that is not
  its agent's; a session credential to its item's; a static token or an
  OAuth grant to the default organization, refused while another
  organization's agent holds its label (`org_guard` admits `caller_for` as
  the one resolver site). Every read and write filters `org_id`, and
  another organization's agent or session answers like a missing one. The
  interim carve-outs are lifted: a session can be addressed inside its own
  organization (`cross_org_recipient` and `require_default_sessions` are
  gone), `crew_view` and `crew_intervene` work in the caller's organization,
  session credentials and idle-session wakes run per organization, and
  `node_reassign` reads `agents.org_id`. A delegation must target a
  registered agent of the delegator's organization (see Behaviour
  changes); the target matches without regard to case and the registered
  spelling is stored. Labels hub configuration names (human identities,
  lifecycle operators, static tokens, `[profiles]`, `agent_scopes`,
  `agent_workspaces`, `revoked_agents`, OAuth and Slack identities, policy
  role identities) are reserved for the default organization: no other
  organization can register, bind or hold a token for one, so none
  inherits a label-keyed setting, and the default credential for it always
  authenticates. While the policy file is unreadable, another organization
  cannot register or get a token for a label it does not already hold
  (`policy_unavailable`). A stale row of another organization for a
  reserved label (one older than the reservation) still blocks the default
  credential's writes: `session_start` is refused `agent_label_blocked`
  and `agent_heartbeat` answers `recorded: false`, until hub recovery
  (`agent_retire` and `agent_forget` with `any_org=true`), which reaches
  that row, removes it. `agent_forget` revokes every credential issued
  since the retire and is refused for a configured label in the default
  organization (`agent_label_configured`), whose retired row is what keeps
  its static token refused, and while the agent owns a node in service
  (`agent_owns_nodes`); it never deletes a second spelling of the label
  (`agent_label_ambiguous`). Lifecycle stops act in the agent's
  organization only. Workspace tools (`fs_*`, `run_cmd*`, `git_*` and the
  rest), `skill_registry` publish and drift, and the `security_audit` and
  `skill_review` targets are refused
  (`org_unsupported`) outside the default organization before any
  filesystem access, and another organization's autonomous cycle is held
  before its worktree is read. Device acceptance,
  command notices and learning-proposal and drop-file writes into the hub's
  shared vault and workspace stay default-organization only. Events about
  another organization's agents and sessions keep only ids, states and
  counts, under the `system` originator; its `lifecycle_record` keys are
  its own through the `(org_id, key)` idempotency table. The importer writes legacy agents, tokens
  and handoff notes to `default`.
- Managed secrets are organization-scoped and each organization can hold
  its own GitHub credentials: `managed_secrets.v2.tenant_keys` rebuilds the
  table around `(org_id, name)` and adds `aad_v` (new writes bind the
  organization into the associated data; a row stored before decrypts only
  in the default organization), and `organization.v1.tools.managed_secrets`
  adds the organization triggers. `github_credential_for(org, kind)`
  resolves the default organization to the hub's configured token and
  webhook secret and every other organization to its own reserved managed
  secrets (`github:token`, `github:webhook-secret`), never another's.
  `github_credential_set`, `github_credential_clear` and
  `github_credential_status` act in the caller's organization; a
  `system_doctor` line names each organization's credential state for a hub
  operator and gives counts only to anyone else. An upgrade finding a
  legacy row with a NULL name stops with its row ids and the fix instead of
  dropping it.
- GitHub and CI automation run per organization, each under its own
  credentials (`docs/github.md#automation-per-organization`). A webhook
  delivery belongs to every organization whose own webhook secret verifies
  its signature (constant-time, never logged) and is recorded, ledgered and
  handled against that organization's bindings and tasks only; when two
  organizations share a secret it is processed once for each, the default
  organization first, then by id. A missing or malformed
  `X-Hub-Signature-256` is refused (401) before the database is touched;
  secrets are decrypted in one read and the MACs computed after it; a
  suspended organization's secret is never consulted. A delivery any
  organization other than the default matched is answered
  organization-neutrally (`{"ok", "matched", "statuses"}`); with several,
  any internal failure answers 500, any success 200, else any bad request
  400, else 409. The poller polls each organization that
  has a token with that token and skips one without; one organization's
  failure is recorded per repository (`github_poll_repos.last_error`, a
  fixed code such as `unauthorized` or `rate_limited`, never library text
  or a value), counted on the `system_doctor` `github_credentials` line
  (only repositories still bound in an organization with a usable token)
  and never stops the others; setting or clearing an organization's token
  lifts its rate-limit block. CI run lookups and `queue_close_merged` use the
  task's or caller's organization's token and bindings; an organization
  without a token is credential-off and the hub's token is never used for
  it. The GitHub client is built per organization and keeps rate-limit
  blocks per host and organization. `github.v2.poll_repos` adds
  `github_poll_repos` keyed `(org_id, repo)` and copies every
  `github_poll_state` row to the default organization (nothing dropped; the
  old table stays unread), and `organization.v1.tools.github_poll` adds its
  triggers. The `ORG-GITHUB-DEFAULT` marker and the `TASK_ORG` constant are
  gone; `org_guard` admits one `Caller::system_for` site
  (`github_caller_for`, now crate-private) and refuses a call to
  `github_caller_for` outside the GitHub family.
- Policy authorizations and tool-call telemetry are organization-scoped:
  `organization.v1.tools.policy_authorizations` and
  `organization.v1.tools.tool_calls` add `org_id` and the organization
  triggers. `github.v3.policy_authorizations_org_scope` moves each existing
  authorization to its task's organization (one whose task is gone stays in
  `default`), adds org-led indexes and the same-organization task triggers;
  `core.v5.tool_calls_org_scope` adds two org-led indexes. Every existing
  call row is the default organization's. No row is dropped; no key rebuild.
  The policy-authorization tools, the merge path's check, spend and restore,
  and the task delete act only on the caller's organization's rows, and its
  refusals are ledgered under it (another organization's requester is
  `null`, originator `system`). The registry records the caller's
  organization on every call row with no extra query; every telemetry
  reader (`perf_summary`, `metrics_snapshot`, `check_anomalies`,
  `mcp_health_telemetry`, `evidence_report`) and the policy rate limits and
  cooldowns count only the reader's organization's calls, keeping the
  own-calls rule inside it. Another organization's authorization events
  carry no repository or policy reference.
- Messages and relay drafts are organization-scoped:
  `organization.v1.tools.messaging` and `organization.v1.tools.relay` add
  `org_id` and the organization triggers to `message_index`,
  `message_reads` and `relay_messages`; every existing row is the default
  organization's and nothing is dropped. `messaging.v2.org_scope` and
  `relay.v2.org_scope` add org-led indexes and same-organization triggers
  for a read receipt, a reply and a draft's approval. Every mailbox read and
  write (send, list, inbox, ack, replies, conversations, `crew_view`,
  `session_packet`, wakes, the ledger visibility rule) is scoped, and
  another organization's message, conversation and client id answer as
  missing ones. Mail to a label is stored in the sender's organization and
  read only there; registering the label anywhere (a heartbeat,
  `session_start`) never stops it or changes the send's reply. Sessions
  stay the default organization's: outside it a send to a session is
  refused (`cross_org_recipient`), and `crew_view` and `crew_intervene`
  refuse the caller (`org_unsupported`), `crew_intervene` in a new registry
  pre-gate that runs before the approval gate, so no approval is parked.
  Another organization's message events carry no body, label, client text,
  `task_id` or `delegation_id` (the message is kept on its own row) and use
  the `system` originator; its conversation handoff events record a
  per-organization digest instead of the conversation id and actor, in the
  payload and the dedupe key, and `conversation_handoffs` matches only the
  reader's organization's digest (the default organization's events and keys
  are unchanged). Its client ids are stored as
  `org:<org>/message_send/<sender>/<id>` with `%` and `/` escaped (the
  default key is unchanged for labels and ids without either). Unknown or
  suspended organizations are refused before any read or write. The relay stays
  default-only for check, draft and send; its status and cancel answer
  another organization's draft as a missing one.
- An insert guard beside the classification test: it fails when an
  `INSERT` (any conflict form, upserts and `REPLACE` included) into a tenant
  table that carries its organization key does not name `org_id`, in any
  crate's non-test source or any trigger body. It cannot see a table name
  built at run time, nor check what an `INSERT … SELECT` supplies.
- Crate `ua-deliverables` and the tools `deliverable_create`,
  `deliverable_revise`, `deliverable_get` and `deliverable_list`
  (`docs/deliverables.md`): a task's deliverable and its immutable, ordered
  revisions. For the `commit` kind a revision is the full 40-hex commit SHA
  in the task's project's bound repository; recording one also sets the
  task's workflow head through the workflow record's own write, so checks
  are graded there. The writers are the workflow record's writers (the
  `reviewer` profile does not see the write tools). Tables `deliverables`
  and `deliverable_revisions` carry `org_id` and the organization triggers
  from their first parts (`deliverables.v1`, `organization.v1.deliverables`);
  triggers keep revisions immutable and in order. Events
  `agent.deliverable.created` and `agent.deliverable.revised` carry ids and
  the revision identity, no content. The scenario check
  `delegate.deliverable-revision-object` passes. `/api/work-products*` still
  answers 501. `ua_org::authz::require_same_org` exposes the organization
  check every authority check applies.
- Refusals in the audit record (`docs/policy.md#approvals-in-the-audit-record`):
  a gated call refused because of its approval state appends one
  `agent.approval.refused` ledger event with a reason (`expired`,
  `binding_changed`, `no_matching_approval`, `denied`, `not_covered`,
  `not_eligible`). It names the tool, the approval or policy authorization,
  the task, the SHA-256 of the canonical payload that was approved and of the
  one presented, and the top-level fields that differ by name, never their
  values. It covers the approval gate, `git_merge_task` under a policy
  authorization, `dispatch_task`, `dispatch_resume` and the relay's send.
  The event survives the refused call: `ua_store::ledger::append_surviving`
  appends it in the call's transaction and, when that transaction rolls
  back, `Db::write` appends it again in a separate small transaction before
  returning the call's error. The `agent.approval.requested`, `resolved` and
  `consumed` events and the policy authorization `recorded` and `consumed`
  events gain `payload_sha256`; `resolved` gains `expires_at` on an approval.
  Additive: no response or schema changes.

### Fixed

- Organization-tenancy review follow-ups (latent while `authz` admits only
  the default organization):
  - Another organization's node command notices are now mailed within that
    organization, to the command's owner, in its own mailbox (the mailbox
    carries `org_id`); before, they were recorded and never sent. A notice
    left unsent by an earlier build goes out with the next sweep.
  - `zulip_fetch_messages` refuses an unknown organization and any
    organization but the default (`zulip_not_configured`) before any
    request, cursor or event, as a send does.
  - Events no longer carry another organization's names or unsalted
    digests into the default ledger: skill registry events (name, target,
    source, content hash), notification events (category; originator
    `system`), routine fires (the fire key, formerly a `sha256:` digest, is
    now `run:<receipt id>`; originator `system`) and work-proposal events
    (contract digests). Events written earlier keep what they recorded.
  - `system_doctor` reports the harness config approvals the organization
    upgrade expired (`database.harness_config_approvals_expired_at_upgrade`),
    since that schema part could leave no ledger event.
  - The `task_add`, `task_update`, `delegate` and conversation-handoff
    idempotency keys of an organization whose id holds `%` or `/` escape it,
    as the other writers do; a receipt stored in the earlier unescaped form
    still replays in its own organization. Default-organization keys are
    unchanged.
  - A guard test fails on any read, update or delete of `idempotency_keys`
    in non-test source that does not filter `org_id`.

- Organization hardening of the approval queue (latent: every caller is in
  the default organization today). Approval events for another
  organization's approval record the neutral originator `system` instead of
  the requester's or resolver's label (the payload already left it out),
  including the relay's `consumed` event. The workflow engine refuses to run
  a run whose organization differs from its caller's, before taking the
  lease, so a gated step can no longer check one organization and park in
  another. `relay_manage status` answers a draft whose approval is in
  another organization with `approval_status: null` instead of failing the
  call; `cancel` still fails closed. Isolation tests now cover the session
  packet's and the evidence report's approval reads. Excluded: a
  policy-authorization refusal (`github/authz.rs:181`) is still ledgered as
  a default-organization event and writes the caller's label to the default
  ledger until `policy_authorizations` carries `org_id`.

- `scripts/vocab-check.sh`: an allowlist entry now silences only the pattern
  class it was written for. A `vocab` entry (the legacy profile names) no
  longer hides a private address, home path or tailnet name on the same line,
  and a `private` entry no longer hides role vocabulary. Entries without the
  class field keep their previous line-wide meaning.
  `scripts/vocab-check-selftest.sh` pins both directions and runs in CI.

### Changed

- `docs/organization.md` publishes the organization contract: the organization
  as the security boundary, immutable identifiers, names local to one
  organization and resource type, one verified active organization per request,
  membership plus explicit grants as the only authority, default-organization
  compatibility and recovery, fail-closed rules (including `enforce_auth` off
  being a single-organization mode), client and API constraints, a staged
  migration with a rollback fence, and a two-organization acceptance matrix.
  The existing hub-wide agent and node names are recorded as compatibility
  until the identity migration lands.
- The default organization's task→goal links are `serves_goal` edges in the
  shared graph store (`docs/graph.md`, C2 slice b). `goal_manage` `link`,
  `unlink` and `ancestry`, and `task_update`'s project check, keep their
  replies and errors; a second goal for a linked task is still refused
  (`single-valued`). Linking ensures the task and goal nodes and asserts the
  edge (`agent.graph.node_created` / `agent.graph.edge_asserted` beside
  `agent.goal.linked`); unlinking, and deleting the task, close it with
  `valid_to` (`agent.graph.edge_retracted`) and never delete it. An
  unverified caller's claimed label is recorded as an agent; a claimed
  `system` is refused. Explicit contract change: linking is subject to the
  graph limits (`graph_max_nodes_per_org`, `graph_max_edges_per_org`, which
  counts closed edges too, and `graph_max_live_edges_per_node`, which caps a
  goal at 5,000 live tasks by default; the upgrade copy ignores the caps, so a
  goal already over them refuses new links). The schema part
  `goals.v3.serves_goal_graph` copies existing default-organization
  `task_goal_links` rows onto import edges through `MigrationGraph`
  (`source_kind = 'import'`, `valid_from` the row's `linked_at`), deletes no
  row, records its summary in its audit SQL, reports it in `system_doctor`
  (`database.serves_goal_migration`), and freezes the table for the default
  organization (`task_goal_links_default_frozen` triggers). `ua import
  python-hub` writes legacy links as graph edges and refuses a target where
  a linked task already serves a goal. Other organizations keep
  `task_goal_links`, unchanged, until immutable principal IDs land (#2790).
- `ua import python-hub` never copies a source `org_id` by column name, even
  where the target has the column (`event_log`, the harness config tables).
  Such rows are refused unless `--drop-org-scope` is given. Before this,
  `harness_config_bundles.org_id` was copied verbatim.
- Upgrade note: notification webhooks (`notify_webhook_url`) no longer use
  `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` or the system proxy settings; they
  connect directly. An operator whose hub reaches its webhook receiver only
  through a proxy must make the receiver reachable directly (the Obsidian
  client, which also honoured them, talks to loopback only).
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
- The organization registry (offices, role grants, agent seats and service
  identities) lives in a new `ua-org` crate. It stores them in SQLite and
  reaches the database through `ua-store`'s `OrgRead` and `OrgWrite`. The
  tools are `org_registry_read`, `org_office_register`, `org_role_register`,
  `org_seat_register` and `org_service_register`.
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

### Behaviour changes

- Another organization's `not_configured` notification row no longer
  keeps its message text: it has no destination, and nothing resends from
  the outbox automatically (a resend is manual). The default
  organization's row still does.
- Known gap, documented: `goals.v2.org_scope` deleted every
  `task_goal_links` row whose goal was in another organization than its
  task, with no ledger event, count or archive. The part is merged and
  cannot change, and on an upgraded database those links are gone; only a
  backup taken before the upgrade holds them. A hub upgraded with a single
  organization lost none (see `docs/organization.md`, the goal and
  work-proposal tables).

- `delegate` (and `delegation_manage` create and `handoff`) accepts only a
  `to_agent` that is a registered agent of the delegator's own
  organization: an `agents` row there with exactly that label. A label no
  agent has registered is now refused in every organization, the default
  included, with the same `not_found` answer as a label another
  organization's agent holds, so neither reveals whether the label exists.
  **Upgrade note:** a workflow that delegated to an agent before it first
  connected must have the agent connect (heartbeat or `session_start`)
  first. Delegations already created are unchanged.
- GitHub webhook multi-match is removed. A delivery belongs to the one
  organization its route names, not to every organization whose secret
  verifies it, and the aggregate answer (`{"ok", "matched", "statuses"}`)
  is gone: another organization's route answers `{"ok": true}` on success.
  The bare route no longer tries other organizations' secrets, and
  `503 not_configured` is gone: a route with no secret answers the same
  401 `bad_signature` as a wrong signature (the hub logs, at most every
  five minutes, when the default organization's secret is unset).
  **Migration note:** a deployment where another organization's GitHub
  webhook pointed at the bare `/api/github/webhook` must repoint it to
  `/api/github/webhook/<org id>`; until then its deliveries are refused
  (401), and GitHub does not redeliver them on its own. After repointing,
  redeliver each refused delivery by hand from the hook's "Recent
  Deliveries" page within `github_webhook_max_age_hours` (older ones are
  refused as `stale`), or let the poller catch up merged pull requests. A
  deployment where two organizations shared one webhook secret
  (multi-match) must give each its own secret and its own URL: the shared
  delivery now reaches only the routed organization, storing the shared
  value again for a second organization is refused, and the hub refuses
  every route of a shared secret it finds at startup until each has its
  own.
- An internal failure on the default organization's webhook route answers
  500 with a fixed message, as every other route does, never the error's
  text (the hub's log has it). An organization id that is not UTF-8 gets
  the uniform 401 `bad_signature`, not a 400.
- `managed_secret_set` refuses the names `github:token` and
  `github:webhook-secret` and consumers of kind `github`
  (`reserved_secret`). **Upgrade note:** a secret already stored under one
  of those names (for example the relay's token named by
  `relay_github_secret`) can no longer be rotated with `managed_secret_set`;
  it still loads in the default organization, so delete it with
  `managed_secret_delete`, store the value under a new name and point the
  setting at it. `managed_secret_list` shows such a row without its
  fingerprint, size or key id.
- `coordination_manage(action="queue_close_merged")` runs in the caller's
  organization instead of refusing another organization's caller
  (`org_unsupported`); an organization without a GitHub token gets
  `github_credential_off`. `github_credential_status` reports
  `automation_scope: "per_organization"`. GitHub webhook responses and
  `agent.github.*` events carry `org_id`; for another organization the
  events' repository, branch and check names are `null`. `poll_once`
  reports per organization under `orgs` (the flat `repos` list stays).
- The relay's `request_send` and `send`, and `mcp_gateway` `call` and live
  `list` on a server that injects secrets, refuse another organization's
  caller (`org_unsupported`): they use the default organization's secrets.
- `skill_registry` approval payloads (publish, assign, unassign) now carry
  `org_id`, so a pass is never consumed across organizations. An approval
  parked in the old payload shape no longer matches its call: it can never
  be consumed, so no migration expires it. **Upgrade note:** deny or revoke
  pending or approved `skill_registry` approvals at upgrade and retry the
  call, which parks a new approval in the new shape.
- A routine outside the default organization now creates its task in its
  own organization when it fires, instead of being recorded as `skipped`
  (`org_tasks_unavailable`); its workflow is still recorded as `not_run`
  until a routine owner can act outside the default organization. Old
  receipts keep their recorded reason.
- Merged-PR reconciliation (`queue_close_merged`) and the GitHub webhook,
  poller and CI lookups stay with the default organization: another
  organization's caller is refused (`org_unsupported`) by
  `queue_close_merged`, and the hub's GitHub paths only read and close
  default-organization tasks (`ORG-GITHUB-DEFAULT`).
- Work proposals are no longer refused to another organization's caller
  (`org_unsupported`): it files, reads, lists, withdraws and recovers its own
  organization's proposals. Deciding also needs the organization half of
  authority (`ua_org::authz`), which admits only the default organization
  until memberships exist, so another organization's human is refused
  (`org_mismatch`) and nothing is written. An approved item's task is
  created in the proposal's organization, and the contract check on a task
  (claim, `doing`, dispatch, node work) reads only the task organization's
  proposals and items: a marker naming another organization's proposal is
  refused as an unknown item, instead of every marker on another
  organization's task being refused outright.
- Policy authorizations carry no organization yet; each is reached only
  through its task's organization, so another organization's authorization
  answers as a missing one. Delegation to another organization's agent is
  still allowed; that agent can never claim it.
- `observability_manage`'s `delegation_stats` counts only the caller's
  organization's delegations (it counted every organization's).
- A `delegate` idempotency key stores its delegating agent's label with
  `%`, `:` and `/` percent-escaped, as `task_update` keys do, so two agents
  never share a stored key. Only a label holding `:` changes its stored
  form; a retry or `lookup` from such a label still finds a receipt stored
  under the old unescaped form, but only when it is the caller's (its
  request digest, or its delegation's `from_agent`, names the caller), so a
  retry across the upgrade creates no second delegation and never replays
  another agent's receipt.
- `cleanup_stale_worktrees` judges a worktree only against the caller's
  organization's tasks and skips (`other_organization`) a worktree of
  another organization's task.
- `conversation_handoff` no longer writes the
  `[conversation: <id>] handed off from the agent conversation` line into the
  task's notes and no longer returns `reference`: the link is recorded only
  by the audited `agent.conversation.handoff` ledger event, visible per the
  event-visibility rule, and the task's notes and `updated_at` stay
  untouched. `conversation_handoffs` still reports legacy notes-only links
  under `unaudited` and whether the line survives (`note_reference`).
- `harness_config_publish` and `harness_config_apply` approval payloads now
  carry `org_id`, the organization the bundle or surface write belongs to, so
  an approval is never consumed across organizations. Upgrading expires every
  open (pending, or approved and unused) approval of either tool in the old
  payload shape: retry a publish, and a node's next drift report parks a new
  apply approval.
- `git_merge_task` now enforces the review-at-head gate whenever `"review"` is
  in the task's `expected_checks` (for both policy-authorization and one-time
  approval merges, including `dry_run=true`, and not bypassed by `force=true`).
  The merge requires a passing (`outcome: "pass"`), uncontradicted `review`
  check (`attested` or `verified`) recorded at the exact 40-hex commit being
  merged (`review_required`), and when a commit deliverable revision matches
  that commit, refuses a self-review by its `producer` (`self_review_refused`).
  Under a policy authorization, authorization coverage is validated first so
  expired or mismatched authorizations still emit `agent.approval.refused`, and
  the review gate runs before the authorization is consumed so an unreviewed
  head does not burn it. The software-factory scenario check
  `release.requires-review-at-head` now passes (Step 3 is 10/10).

- A one-time approval of `git_merge_task` no longer covers a later commit.
  The approval now binds the head (full SHA), branch, target branch and the
  task project's bound repository resolved when the merge is called, plus a
  summary naming the commit and the target for the approver. A merge whose
  branch moved after the approval, or whose project was rebound to another
  repository, is refused with `approval_binding_changed` (ledgered as an
  `agent.approval.refused` event, reason `binding_changed`) and a new
  request for the current values is parked; before, it ran under the old
  approval. Passes approved before this change bound only the arguments and
  no longer match: they need a new approval. Because the handler now
  resolves the payload, `git_merge_task` can no longer be requested ahead
  through `POST /api/approvals/request` (`409`), and a merge bound to fail
  (an unknown task, an unfinished task, a dirty worktree) is refused with
  that error before an approval is parked, instead of parking first. The
  policy authorization path is unchanged.

- An unknown schema part refuses to open the database. Opening the store
  compares the parts recorded in `schema_parts` with every part name the
  build knows (optional and feature-gated parts included, so a lean build
  of the same version is not refused) and, inside the first migration
  transaction before anything is applied, refuses a database a newer build
  wrote, naming the unknown parts and saying to run the newer build or
  restore a backup taken before the upgrade. `ua serve`, `ua mcp`,
  `ua call`, `ua init` (when it mints a token), `ua import` and the other
  commands that open the hub refuse; `ua doctor`, `ua backup` and
  `ua restore` run. `--allow-newer-schema` or `UA_ALLOW_NEWER_SCHEMA=1` (the
  real environment only; a `.env` file cannot set it) opens it anyway for
  recovery, logged at every open, but `ua serve` refuses such a database
  even then. `system_doctor` reports a hub under the override as degraded.
  A checked-in list of every shipped part name is pinned by a test: part
  names are never retired or renamed. The fence protects only from this
  change on, against parts added later: every earlier build (every build
  from before the inbound-delivery table included) still opens an upgraded
  database and is refused by nothing, so never run a build older than this
  change against a database a newer build has opened; restore a
  pre-upgrade backup instead (`docs/operations.md`, "Older builds and a
  newer database").
- A command that would migrate the database (apply a schema part it does
  not record yet) refuses while another process holds the serve lock: a
  newer build no longer migrates underneath an older running `ua serve`.
  `ua serve` migrates at startup under its own lock; an open with nothing
  to apply is unaffected; the recovery override does not lift it
  (`docs/operations.md`, "Processes already running"). The guard is part
  of the store's open (`Db::open`, `Hub::open`, `Hub::open_with`), so a
  program that embeds the hub gets it by default; the only way to skip it
  is the held serve lock of that database (`Fence::serving`,
  `Hub::open_serving`). The lock code moved from `ua-import` to
  `ua_store::lock`; `ua_import` re-exports the same names.
- `ua doctor`: the `schema` check fails, where it warned, when the database
  records parts this build does not know, and leads with that explanation
  before any object findings. A plain `ua doctor` (without `--strict`) now
  exits non-zero on such a database.
- A second `ua serve` on the same database is refused. `ua serve` holds a
  serve-only lock (`<db>.serve.lock`, owner-only, next to the database)
  exclusively for the life of the process, beside the shared hub lock; a
  second one exits before it opens the database or binds a port, with an
  error naming the database and saying another `ua serve` holds it. The OS
  releases the lock when the process exits or crashes. "The same database"
  is the file SQLite opens, with every symbolic link followed (dangling
  ones included) and `.`/`..` resolved; hard links are not covered. On a
  platform without `flock` nothing is locked and a warning says so.
  `ua mcp`, `ua call`, backups and the other commands are unaffected;
  `ua restore` and `ua import` still refuse while a serve runs
  (`docs/operations.md`, section 5).
- The shared hub lock (`<db>.hub.lock`) now uses the same path resolution
  and is created owner-only, so an import or restore that reaches the
  database by another spelling refuses beside a running hub. For a
  database reached through a link or an unusual spelling, a process from
  before this change and one from after it use different hub-lock files
  during the transition: stop every old process before an import or
  restore.

- GitHub webhook: a delivery that the hub recorded but never finished
  handling (it stopped in between, or the delivery has been in flight for
  15 minutes) is processed when GitHub redelivers it, instead of being
  refused as a replay and lost. Its `agent.github.webhook.received` event
  carries `"redelivered": true`. Every other response is unchanged.
  Settling a delivery record is by claim (one per taking-on): a slow
  handler cannot finish or release a record a redelivery took over, and one
  whose record the sweep abandoned still finishes it, so a later copy stays
  a replay. When the sweep abandons deliveries it appends one
  `agent.github.webhook.abandoned` event (counts and up to 50 delivery ids,
  no body) under the organization it swept; a sweep covers one
  organization. Downgrading past this change reopens a replay window for
  deliveries handled since, because an older binary reads only the old
  GitHub tables, and nothing refuses it: every such build predates the
  unknown-part fence (`docs/ingress.md`, Limits).

- Operator authority is a verified caller of kind human, nothing else.
  Dispatch and governance agree on it: acting for another agent in dispatch,
  and confirming or retrying a cancellation, need an operator, not the
  `operator` profile. Agents listed in `lifecycle_operators` keep their
  fleet-maintenance operations under a separate grant (closing, parking and
  folding tasks, releasing claims and holds, worktree cleanup, handoff
  recovery, workflow records, wake handling, skill registry changes, harness
  config status, node-queue administration including node acceptance, agent
  and node lifecycle), but are not operators: secret administration (and
  the default MCP read rule), provider-account administration, project repo
  bindings, harness config publish, session credential revocation, node
  command adoption, the hub view, reading every mailbox or conversation, and
  `vault_move` need a verified human.
- An unattended routine no longer holds operator authority anywhere: it runs
  as an agent under its owner's label, and an agent is never an operator.
  To give a routine fleet-maintenance rights, list its label in
  `lifecycle_operators`. When `lifecycle_operators` is unset it defaults to
  `human_identities` for humans only; that fallback grants nothing to an
  agent.
- The same rule now holds at the last places that still read the caller's
  label instead: a follow-up into a running node session from a routine
  waits for the one-time approval like any agent's, and clearing a task's
  untrusted quarantine or filing a work proposal in another identity's name
  needs the human as themselves.
- The `coordinator` and `operator` profiles grant no authority. The hub
  view, reading every mailbox or conversation, and `vault_move` need an
  operator. A coordinator agent that read every mailbox to route work cannot
  any more; organization roles will replace that.
- With auth enforcement off there is no verified identity to scope a read
  by, so mailboxes and conversations are a message board
  ([auth.md](docs/auth.md#with-auth-enforcement-off)). An unverified caller
  reads every mailbox, as before, and now `conversation_handoffs` too
  (handing a conversation off still needs a verified caller). Reading
  another label's mailbox no longer changes its read state: for a caller
  configured with its own label, `message_inbox` on another mailbox lists
  without marking and says so (`read_state`), and `message_ack` and
  `session_id` on it are refused. A caller with only the shared `local`
  label has no mailbox of its own and still acts as the mailbox it names.
  This read grant never counts as operator, lifecycle or human authority.
- Messages carry `sender_verified`: `false` when the sender was not
  authenticated, so `from_agent` is only what the caller said (`null` on
  messages sent before this).

- The web tools' and the OAuth client-metadata fetch's address checks are
  now one classifier (`ua_ingress::addr`) with two named classes. Nothing is
  allowed that was refused before. Newly refused:
  - by the web-class callers (`web_fetch`, `web_search`, Zulip, the relay's
    GitHub client, GitHub REST, Slack replies and the Socket Mode `wss`
    host): the IPv4-compatible form `::a.b.c.d` of a public IPv4 address.
    It is deprecated (RFC 4291), lies in `::/8`, which is not routed, and no
    current transition mechanism produces it, so no reachable destination
    uses it. NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`) and 6to4 addresses are
    still judged by the IPv4 address they carry, as before, so IPv6-only
    networks behind DNS64 keep working;
  - by the client-metadata fetch: translated IPv6 (`::ffff:0:a.b.c.d`) of a
    non-public IPv4 address, `3fff::/20` (documentation), `2001::/23` beyond
    Teredo (IETF protocol assignments), and every IPv6 address outside
    `2000::/3` not refused before. It still refuses every NAT64, 6to4 and
    IPv4-compatible address, as before.
- `web_fetch`, `web_search`, the Zulip tools, the relay's GitHub comments
  and Slack Socket Mode's `apps.connections.open` call now go through
  `ua_ingress::Outbound` under named policies (`web.page`, `web.search`,
  `zulip.api`, `relay.github`, `slack.web_api`; `docs/ingress.md`), and the
  web family's shared client is gone. Schemes, hosts, redirect limits, body
  caps, timeouts, proxy handling, outcomes and error messages are as
  before, except where each is now stricter:
  - every one: the address of the connection that carried a response is
    checked again after it arrives (a peer outside the class fails the
    call), and failure messages no longer quote the request URL;
  - `web_fetch`: a URL with credentials (`user:password@host`) is refused
    (they were sent as basic auth); a fetch that runs out of its 45-second
    budget reads `fetch of <host> timed out` instead of `fetch timed out`;
  - `web_search`: a redirect from https to http is refused (it was
    followed); a 307 or 308 that would resend the DuckDuckGo form or the
    Tavily request body to another origin is refused (it was resent);
    the Brave and Tavily keys, and every header other than `Accept` and
    `Accept-Language`, are not sent once a redirect chain changes origin,
    where before they were dropped only when the host changed (a change of
    scheme or port kept them); a credentialled endpoint URL is refused;
  - Slack Socket Mode's `apps.connections.open` call is now pinned to its
    one host: the `slack.web_api` policy accepts only `https://slack.com` on
    the default port (before, only the hard-coded base URL kept it there);
  - Zulip and the relay: nothing beyond the first item. None of these
    follows redirects, before or now.
- The GitHub REST client (CI check verification, polling, merged pull
  requests) now goes through `ua_ingress::Outbound`: `github.rest` for
  `api.github.com`, `github.enterprise` for a GHES root in `github_api_url`
  (`docs/ingress.md`). Its client is still built once per API base. The
  host, https, the loopback test hook, no proxy, no redirects (a 3xx is an
  error), the 8 MiB cap, 20 seconds and its errors are as before. The new
  address class `OperatorConfigured` (public, loopback and private networks:
  RFC 1918, the RFC 6598 shared address space, `fc00::/7`) serves the GHES case and follows no
  redirect. Stricter:
  - a GHES host was not address-checked at all; now a name or address in
    link-local (cloud metadata), unspecified, multicast, broadcast and
    reserved, documentation, benchmarking or IETF protocol ranges is
    refused, at connect time and on the connection's peer. Private and
    loopback addresses are still reached;
  - the public API's connection peer is checked again after the response
    arrives;
  - a network failure's detail is `ua_ingress`'s message rather than the
    HTTP library's error chain (it never quotes the URL).
- The Obsidian tools (`obsidian_status`, `obsidian_open`,
  `obsidian_active_note`, `obsidian_search`, `obsidian_append`) now go
  through `ua_ingress::Outbound` under `obsidian.local_rest`. The URL check
  (`obsidian_url`), http or https, the bearer key, 20 seconds, the 412
  conflict and the error prefix `Obsidian request failed:` are as before,
  and TLS certificates are still not verified (the plugin's certificate is
  self-signed): `Policy::accept_invalid_certs` exists for this one policy
  and is refused on any policy that is not loopback-only (new class
  `LoopbackOnly`) or that follows redirects. Stricter:
  - every address a connection reaches must be loopback, checked when it is
    made and again on its peer (before, only the configured URL's host was
    checked, so `localhost` resolving elsewhere was followed);
  - redirects are not followed (up to ten were, with the key dropped only
    on a host change); a 3xx now reads `HTTP 3xx` as any other non-success;
  - proxy environment variables are ignored (they were honoured, so the key
    could travel through a proxy);
  - a reply larger than 16 MiB is refused (there was no cap); from
    `obsidian_append`, whose patch has already been applied, such a reply
    reads as `response: null` instead;
  - replies are decoded as UTF-8 (lossy) whatever charset they declare;
  - requests carry the hub's `User-Agent` (there was none).
- Notification webhooks (`notify`, `batch_notify`, `flush_digest`, hub
  events such as `review_ready`) now go through `ua_ingress::Outbound`
  under `notify.webhook`: http or https to `notify_webhook_url`, any host
  and port, `OperatorConfigured` addresses (private networks and this host
  are still reached), no redirects, each attempt bounded by its timeout as
  before. Retries on network errors, 429 and 5xx, the outbox and its error
  texts are unchanged. Credentials in the URL are still sent as basic auth,
  now as a header bound to the URL's origin. Stricter:
  - notify over plain `http` to a non-loopback host carrying
    `notify_webhook_secret` or URL credentials (Basic auth) is refused with
    `invalid_argument` before the outbox write; operators should switch to
    `https` (loopback `http` remains allowed);
  - a URL whose host is or resolves to a link-local (cloud metadata),
    unspecified, multicast, broadcast and reserved, documentation,
    benchmarking or IETF protocol address is refused (nothing was checked),
    with `webhook address refused (<reason>)` and no retry; the peer
    address is checked again after the response;
  - proxy environment variables are ignored (they were honoured, so the
    secret header could travel through a proxy);
  - requests carry the hub's `User-Agent` (`ua-rust/<version>`; there was
    none).
- Every outbound address rule now refuses the well-known cloud
  instance-metadata addresses that are not link-local, with the reason
  `cloud metadata`: `100.100.100.200` and `fd00:ec2::254`, `fd20:ce::254`,
  and any IPv6 form that carries the IPv4 one (mapped, translated, NAT64,
  6to4). `OperatorConfigured` (GHES, notify webhooks) admitted them inside
  the shared address space and unique local space; the rest of both ranges
  is still reachable. The public classes refused them already, under their
  range's reason.
- `Addresses::class()` is gone: it returned the public range table for
  `LoopbackOnly` too, so a caller deciding by it would have admitted public
  addresses. Every decision goes through `Addresses::check`.
- GitHub REST: `github_api_url` spelled with a trailing dot or in another
  case (`https://API.GitHub.com.`) is the public API, gets `github.rest`, and
  is normalised to `api.github.com`; before, a trailing dot selected
  `github.enterprise`. Any other host keeps the spelling the operator wrote,
  trailing dot included.
- Five tool-call telemetry reads now count only the reader's own calls
  unless the reader may read every mailbox (scope `all`; anything else is
  `own_calls`, and an unverified or other-organization reader counts
  nothing): `perf_summary` (`observability_manage` `performance` and the
  `perf_summary` tool), the `metrics_snapshot` tool-call totals,
  `check_anomalies`' `tool_error_rate` rule, `mcp_health_telemetry`, and
  `evidence_report`'s `tool_call_window` (which gains `scope` and
  `counted_callers` fields alongside the participant `callers`). Note that a
  fleet-wide tool-error spike is now detected only for a mail-unrestricted
  (operator) reader: a restricted reader's `tool_error_rate` sees only its
  own calls.

### Security

- The unauthenticated GitHub webhook costs one secret check per delivery:
  it loads and decrypts only the routed organization's secret and computes
  one MAC (over a fixed dummy key when there is no secret), instead of one
  decrypt and one MAC over up to 5 MiB per organization. An unknown,
  malformed or suspended organization, one with no secret, an unusable
  stored secret and a bad signature all get one byte-identical answer, so
  the route no longer reveals whether any organization has a secret. Both
  webhook routes share an in-flight cap (`github_webhook_max_in_flight`).
- Ledger event visibility: `agent.message.*`, `agent.mailbox.*` (inbox
  read/ack receipts), `agent.lifecycle.handoff` and
  `agent.conversation.handoff` rows are now visible only to the readers the
  record concerns — a message's sender and recipient, a receipt's mailbox
  owner (its writer), a handoff note's
  parties and the session's owner (or a note-reading operator), a
  conversation's participants and the linked task's holders, or a
  mail-unrestricted reader. The rule (`VISIBLE_EVENT`) applies to
  `event_log_query`, the live event stream, `session_packet` event lists,
  `observability_manage` activity and metrics, evidence reports and the
  migration manifest (which keeps a `{ulid, entry_hash, redacted}`
  placeholder per hidden row — chain metadata stays visible as the accepted
  integrity exception, never the rows' contents, channels or parties).
  `message_send` accepts an explicit `conversation_id` from a restricted
  caller only when the sender is already a party; a missing and a foreign id
  answer the same `not_found`, as do a missing and a foreign `reply_to`
  parent, so neither tests whether a conversation or message exists. New
  conversations take a hub-minted id or inherit one through `reply_to`; a
  mail-unrestricted reader may still start one under a chosen id, and only
  the gated `crew_intervene` opens or joins a session's `crew:<session>`
  thread. `crew_view` no longer returns other agents' private mail: a
  restricted caller sees only the crew's messages and worktree intervention
  lines it sent or received (session mail only when it targets the session
  viewed), and only the session agent gets the drop file's path.
  `crew_intervene` no longer copies the body or the parties anywhere outside
  the mailbox: the task-note marker records only the time and session, and
  the worktree `.ua/interventions.jsonl` line holds only `{ts, session_id,
  message_id}`. `crew_view` resolves each line's `message_id` against the
  mailbox under the reader's rule and drops a line that is not a crew
  `request` into that session, so a planted line shows nothing; only the
  newest 1000 lines are resolved. On unix the file is opened relative to an
  `O_NOFOLLOW` descriptor of `.ua` with `O_NOFOLLOW` itself, and must be a
  regular file with one link, so neither a symlink (of the file or of `.ua`,
  even swapped in between check and open) nor a hard link is written or
  read; other platforms only check before opening and do not detect hard
  links. `message_send`
  refuses a client-chosen `message_id` with an external-thread prefix
  (`ts:`).
- `message_send`: a client-chosen `message_id` is the sender's own
  idempotency key, keyed by `(sender, id)`, and no longer an existence
  oracle. Every message now gets a hub-minted `message_id`; the client id is
  echoed as `client_message_id` (in the send result and in listed rows).
  The sender's retry with the same id still returns the first result,
  while another sender's use of the same id answers exactly like a fresh id
  instead of `conflict`. The sender's own client id also resolves as its
  `reply_to` and in `message_list(message_id=...)`; a recipient replies and
  acks with the hub-minted id. A send keyed before this change keeps its
  old id and its sender's retry still finds it. Hub-node command notices
  record the hub-minted id. A restricted caller's `conversation not found`
  now says to omit `conversation_id` or answer with `reply_to`.
  `ua-import` does not carry `idempotency_keys` over, so a client id from
  imported (or otherwise pre-upgrade, unkeyed) data now produces a new
  message on reuse instead of `conflict`.
- `message_list` takes `client_message_id`: only messages whose sender keyed
  them with that id. A restricted caller still sees only its own mail, so
  the filter finds nothing it could not already list.
- `message_send`: an unverified caller (auth enforcement off) may no longer
  send as a label the hub sends as itself (`system`, `pr-watch`, or any
  label starting with `hub-`, such as `hub-node`, ignoring case), so it
  cannot take a hub client id such as `node-command-…` first.
- `memory_save`: an `idempotency_key` is stored as
  `memory_save/<caller>/<key>` and looked up only among `memory_save` rows.
  Another tool's use of the same text (a `message_send` client id, a
  hub-node `node-command-…` id) is no longer reported as `conflict … already
  used by message_send`, and a memory key can no longer occupy another
  tool's key and make its later write fail. A key `memory_save` stored before
  this change still replays for a retry by the caller that wrote or last
  updated the note it names; another caller reusing it gets its own save
  instead of that receipt.
- `crew_intervene` / `crew_view` drop file: on unix the worktree path is
  walked from `/` with `O_NOFOLLOW` at every directory, so a symlink swapped
  in for an ancestor of the worktree after the containment check is refused
  instead of followed out of the workspace.
- `lifecycle_record` with `kind: "handoff"` now writes to
  `agent.lifecycle.handoff_hook` instead of `agent.lifecycle.handoff`, and
  only its writer and note-reading operators can read it. Before, any agent
  could name another agent's session and have a handoff row appear in that
  owner's ledger view and `session_packet` as if it were a handoff-note event
  (#111).
- `ua_ingress`: the relaxed outbound policies (`github.enterprise`,
  `notify.webhook`, `obsidian.local_rest`) can no longer be obtained by
  name or from the public policy list, and build only clients pinned to one
  origin (`Outbound::pinned`): a request to another scheme, host or port is
  refused before anything is sent. `Outbound::new` refuses a relaxed policy,
  and a hand-made one is refused even pinned. The GitHub REST, Obsidian and
  notify clients pin to their configured URL; their behaviour is unchanged.
- Slack: a command's outcome settles its delivery under the claim its own
  admission took, so a very late outcome can no longer mark a newer
  delivery with the same id (recorded after the old row expired) as
  finished; it is still ledgered. Admission also logs, at info level, an
  accept that changed no row.
- An unverified caller (auth off) that names a configured human or lifecycle
  operator as its `actor` no longer gets operator authority over other
  agents' task workflow records and checks; it is refused, as every other
  operator check already refused it.
- An approval decision records the adapter it came through: the approval
  row's new `resolved_transport` (schema part `approvals.v2`; `stdio`,
  `http`, `mcp`, `cli`, `ui`, `internal` or `slack`; NULL, shown as unknown,
  for older rows; the row holds the latest decision), the
  `agent.approval.resolved` and `relay.cancelled` ledger events'
  `transport`, the approval list
  and detail outputs, and a "Via" column in the Control Center inbox. A
  `/approve` from Slack is no longer indistinguishable from a click in the
  Control Center. Who may approve is unchanged.
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
