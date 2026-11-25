# Organization model

Status: **design, first infrastructure in the tree.** This document is the
review gate for the `organization.*` schema parts and the `ua-org` crate. Its
companion is `docs/memory.md` (PR #40), which relies on the decisions recorded
here for memory columns, owners and defaults.

`organization.v1` lands in several PRs rather than one. What is in the tree:

- The `Procedure` part kind with `version` refusal and the `standalone` flag
  ([Schema](#schema)). It departs from the wording below in one way:
  `SchemaPart` stays the static kind, unchanged, and both kinds convert into
  a `Part` that `schema::apply` takes, so existing static parts did not
  change. A procedure's generated SQL is stored in a `schema_procedures`
  table, created with the first procedure that runs, rather than in a column
  of `schema_parts`, so an older database and an older backup keep exactly
  the objects they had.
- `organization.v1.store`: `orgs` (created without `IF NOT EXISTS`, so a
  database holding another `orgs` table refuses the part), the seed, and
  `event_log.org_id` and `event_log.hash_v`. Every row is written with
  `hash_v = 1`, the nine-field form, which does **not** cover `org_id`: until
  rows are written with `hash_v = 2`, a row's `org_id` can be changed without
  `verify()` noticing. `verify()` refuses any `hash_v` other than 1.
- `ua_store::org::tenant_part`. It takes the full part name
  (`organization.v1.<crate>.<family>`, or `organization.v1.<crate>` for a
  crate that is one family) rather than the owner alone, so the part stays a
  constant. There is one part per table family, because a generated part's checksum covers its table list, so a released part can never take another family's tables. Its first user is `organization.v1.ingress`, for
  `inbound_deliveries`, a table that carries `org_id` from its first part;
  `organization.v1.deliverables` does the same for `deliverables` and
  `deliverable_revisions`.
- `ua_core::DEFAULT_ORG`.
- The importer exclusion: `org_id` is never mapped by column name.
- The classification test (`crates/ua-tools/tests/org_classification.rs`,
  until `ua-org` exists). It uses the classes in
  [Scoping per subsystem](#scoping-per-subsystem), plus `schema_procedures`
  as a hub table. **The test is the authority on classification**; the table
  in that section is a copy kept in step with it. Two temporary relaxations
  may only shrink: the tenant tables still missing `org_id` (1 of the frozen
  baseline of 68 today, `idempotency_keys`; `code_symbols`, `graph_canvas_scenes`,
  `graph_canvas_revisions`, `web_search_cache`, `skill_versions`,
  `skill_assignments`, `skill_publish_staging`, `project_repo_bindings`,
  `notify_outbox`, `pending_notifications`, `zulip_sends`,
  `harness_config_bundles`, `harness_config_proposals`,
  `harness_config_drift`, `harness_config_report_window`, `routines`,
  `routine_runs`, `workflow_runs`, `workflow_checkpoints`, `plans`,
  `plan_steps`, `plan_checkpoints`, `autonomous_cycles`,
  `autonomous_cycle_transitions`, `autonomous_cycle_usage`, `approvals`,
  `tasks`, `task_dependencies`, `task_comments`, `task_comment_threads`,
  `task_workflow`, `task_checks`, `review_ready_notices`, `task_holds`,
  `task_hold_members`, `delegations`, `goals`, `task_goal_links`,
  `work_proposals`, `work_proposal_items`, `policy_authorizations`,
  `tool_calls`, `memory`, `memory_versions`, `memory_embeddings`, `nodes`,
  `node_acceptance`, `node_claim_ops`, `node_command`,
  `node_command_notice`, `node_dispatch`, `node_followups`,
  `dispatch_runs`, `dispatch_receipts`, `agents`, `agent_sessions`,
  `agent_tokens`, `agent_lifecycle`, `session_profiles`,
  `session_credentials`, `session_handoff_notes`, `session_wake` and
  `session_wake_offers` having left it;
  a new table cannot join it), and the grant tables
  `oauth_grants` and `ui_sessions`, which must carry `org_id` and do not yet.
- The procedure checksum covers the part's name, `version` and arguments,
  so a table added to a released tenant part is refused, not skipped.
- A rollback fence: opening the store, and every append, refuses a ledger
  whose newest row has a `hash_v` above the build's. It sits beside the
  unknown-part fence (`docs/operations.md`, "Older builds and a newer
  database"), which refuses, before any part is applied, a database that
  records a schema part the build does not know. The two are independent:
  the unknown-part fence catches a newer schema, this one a newer ledger
  form, and `--allow-newer-schema` lifts only the first (and never for
  `ua serve`). A build is never allowed to append a row in an older hash
  form after a newer one. Both stop only builds that contain them.

- `Caller.org_id` (a serialized caller without it reads as the default)
  and `Caller::system_for(org_id)`, with `Caller::system()` in the default
  organization. A source test (`crates/ua-core/tests/org_guard.rs`, over
  every crate's non-test source) fails if a `Caller` literal, an
  `EventInput`, or an `.org_id =` assignment names any organization but
  `DEFAULT_ORG` (a caller's organization included), or if anything calls
  `system_for`, before memberships exist. Two exceptions are admitted by
  site: the GitHub family's `github_caller_for` (below), and, since the
  agents family converted, the HTTP resolver's `caller_for`
  (`ua-server/src/auth.rs`), whose two literals take the organization the
  credential resolved to (`AuthIdentity::org_id`: a managed token's or a
  session credential's, else the default).
- `EventInput::new(org_id, …)` with `Default` removed, so every event names
  its organization; every site passes `ua_core::DEFAULT_ORG`, the
  organization of the affected row, never the caller's. `append` writes
  `org_id` and `hash_v` explicitly, and refuses an organization `orgs` does
  not hold. On a ledger from before
  `organization.v1.store` (an older backup just restored) it writes the old
  row shape, and refuses any organization other than the default rather than
  drop it. `org_id` is still not covered by the hash.

- The `ua-org` crate, holding only `authz` for now. Departure from the
  [Authority checks](#authority-checks) API: until users and memberships
  exist (`organization.v2`), authority comes from the hub configuration, so
  the checks run through an `Authz { cfg }` value with
  `require(caller, need, target_org)` and `holds(...)`. `target_org` must be
  `'default'` and the caller's organization; anything else is refused. The
  authorities are **transitional**: each reproduces one rule the tree used,
  and names the design authority that replaces it. Four of them use a
  profile as authority, which this design forbids; they are marked, and kept
  only to preserve behaviour. The operator, dispatch, hub-view and mailbox
  predicates delegate to `authz`, and ua-memory's human check goes through
  it. A guard test (`crates/ua-core/tests/authz_guard.rs`) holds per-crate
  counts of the remaining ad-hoc checks (`is_human` definitions and calls,
  `is_lifecycle_operator` calls, `fn is_operator…`, profile comparisons and
  matches, profile-as-authority uses, `ActorKind` comparisons and matches,
  and direct reads of `human_identities` / `lifecycle_operators`), which may
  only go down. It scans `ua-core` too, skipping only the files that define
  the primitives. One behaviour change:
  an unverified caller naming a configured human as its actor is no longer a
  workflow-record operator.

- Authority comes from identity, never from a profile (two owner
  decisions). `Operator` is a verified caller of kind human, so an
  unattended routine (an agent under a human's label) is never one;
  `LifecycleOperator` is a
  separate fleet-maintenance grant for agents in `lifecycle_operators`,
  never operator authority, named at each call site that admits it next to
  `Operator`. The coordinator and operator profiles grant nothing; the
  profile-as-authority count in the guard is 0. With auth enforcement off,
  mailboxes and conversations are a message board: `LocalTrustReader` is a
  read grant for a caller with no verified identity, and never satisfies
  another authority ([auth.md](auth.md#with-auth-enforcement-off)).

- The first tenant part for an existing table family,
  `organization.v1.tools.code`, for the code family's `code_symbols`: `org_id`
  added `NOT NULL DEFAULT 'default'` (existing rows backfilled), and the
  generated triggers. The part is named for the owning crate **and family**
  (`organization.v1.<crate>.<family>`) rather than one
  `organization.v1.tools` for all of `ua-tools`, because the procedure
  checksum covers its table list: a part for one family cannot later take
  another family's tables, so each family gets its own part. Every query of
  the symbol tools filters on the caller's `org_id`; indexing for an
  organization `orgs` does not hold is refused before any row changes. The
  `agent.code.indexed` event still names `DEFAULT_ORG`, which is the indexed
  rows' organization for every caller until memberships exist; the
  `org_guard` test admits no other value yet. **Resolver work item:** every
  event at a site marked `ORG-EVENT-DEFAULT` in the source must switch to the
  organization of the row it is about in the same change that lets a second
  organization have callers, or the default organization's ledger would
  record another organization's activity. A second resolver work item,
  `ORG-TASK-DEFAULT`, covered every lookup that starts from a task; it was
  resolved when tasks gained `org_id` (the tasks family below). The hub's
  GitHub and CI paths, held default-only for a while, now run per
  organization (see managed secrets below).
  `code_symbols` has no index led by
  `org_id`; its queries use the existing `(workspace, …)` indexes, which is
  enough while one organization holds the rows. A large tenant table gets an
  index led by `org_id`, in a new static part, when its family is converted.
- The graph canvas family applies `graph_canvas.v2.tenant_keys` to rebuild
  both keys around `org_id` and keep existing boards and history in `default`.
  `organization.v1.tools.graph` installs the organization triggers. Canvas
  reads, writes, restores, quotas and history retention use the caller's
  organization. Each revision references a board in the same organization.
  The Python importer explicitly writes legacy canvas boards to `default`.
- The web family applies the standalone procedure `web.v2.tenant_keys` to
  rebuild `web_search_cache` around `(org_id, provider, query, max_results)`
  and migrate existing rows to `default`, followed by
  `organization.v1.tools.web` to install the organization triggers. Search
  cache reads, writes and TTL evictions scope to the caller's organization.
- The skill registry applies the standalone procedure
  `skill_registry.v2.tenant_keys` to rebuild `skill_versions` around
  `UNIQUE(org_id, name, version)` and `skill_assignments` around
  `UNIQUE(org_id, skill_name, target_type, target)` in one transaction,
  keeping ids and the AUTOINCREMENT sequence, indexes, the version
  immutability triggers and views, and adding indexes led by `org_id`.
  `skill_publish_staging` is keyed by a hub-global random id and needs no
  rebuild. `organization.v1.tools.skills` then adds its `org_id` and installs
  the organization triggers on all three. Every `skill_registry` action
  (publish, staging, list, get, assign, unassign, resolve, drift) and the
  registry skills in a node's harness bundle use the caller's organization;
  a write for an organization `orgs` does not hold is refused before anything
  is read or written. Operator actions still need `ua_org::authz`, which
  admits only the default organization until memberships exist. The publish,
  assign and unassign approval payloads bind `org_id`, so a pass is never
  consumed across organizations; approvals parked in the earlier payload
  shape no longer match and should be denied at upgrade (no migration
  expires them: they can never be consumed). The importer writes legacy
  skill versions and assignments to `default`.
- The governance family applies the standalone procedure
  `governance.v2.project_bindings_tenant_keys` to rebuild
  `project_repo_bindings` around `(org_id, project)` and migrate existing
  bindings to `default`, followed by `organization.v1.tools.project_bindings`
  to install the organization triggers. `project_repo_bind`,
  `project_repo_unbind`, `project_repo_get` and `project_repo_list` scope to
  the caller's organization, and a bind or unbind for an unknown organization
  is refused before anything changes. Every task-driven lookup of a binding
  (CI checks, merges, policy authorizations, deliverables) reads the
  binding of the task row's own organization (the tasks family below). The
  hub's GitHub and CI paths without a caller (the webhook, the poller, the
  CI run lookup, the head re-verification and merged-PR reconciliation) read
  the bindings of the organization they act for: the delivery's (by its
  verified secret), the poll's, or the task's. The
  Python importer explicitly writes legacy bindings to `default`.
  `crates/ua-tools/tests/project_bindings_tenant.rs` holds
  another organization's binding of the same project and checks that none
  of these lookups reads it. The `project.repo.bound` and
  `project.repo.unbound` events are `ORG-EVENT-DEFAULT` sites whose payloads
  carry the project and repository names (and the previous binding) into
  the default organization's ledger. They must move to the binding's
  organization with the `ORG-EVENT-DEFAULT` switch, in the same change that
  lets a second organization bind; the payload shape stays as it is.
- The notification tables: `organization.v1.tools.notify` gives
  `notify_outbox` and `pending_notifications` their `org_id` and triggers,
  `notify.v2.org_indexes` adds indexes led by `org_id`, and
  `organization.v1.tools.zulip` does the same for `zulip_sends`. No rebuild:
  their only keys are AUTOINCREMENT ids, and the keys that matter between
  organizations are query keys (the digest category count, the Zulip
  duplicate check on stream, topic and content hash), which now filter on
  `org_id`. Every notify tool and Zulip send or resolve reads and writes only
  the caller's organization's rows; an unknown organization is refused before
  any write. The notification webhook and the Zulip site, account and
  channels live in the hub configuration and are the **default
  organization's destinations**: another organization's notifications are
  kept in its outbox as `not_configured`, never sent to them, and its
  `zulip_send_message` is refused before anything is recorded, until
  organizations configure their own destinations. A hub-originated
  notification takes the organization of the row it is about, never a
  caller's: `review_ready` uses its task row's.
  `review_ready_notices` stays with the tasks family: it belongs to the task
  workflow (continuity), is keyed by the hub-global task id, and is read in
  the same transaction as `task_workflow`, so it converts with
  `task_workflow` (the continuity tables below). The
  queued, settled and Zulip events are `ORG-EVENT-DEFAULT` sites; their
  payloads carry ids, counts, hashes and categories, never message text.
  `crates/ua-tools/tests/notify_tenant.rs` holds the upgrade and the
  isolation tests.
- The harness config family applies the standalone procedure
  `harness_config.v3.tenant_keys` to rebuild `harness_config_bundles` around
  `UNIQUE(org_id, version)`, `harness_config_proposals` with a `NOT NULL`
  `org_id` (its key is a hub-global random id), and
  `harness_config_report_window` around `PRIMARY KEY (org_id, node)`, in one
  transaction, keeping the bundles' ids and AUTOINCREMENT sequence, every
  index, trigger and view, and adding indexes led by `org_id`. Existing rows,
  including the legacy `NULL` `org_id`s, move to `default`. The same
  transaction expires open `harness_config_publish` and
  `harness_config_apply` approvals whose payload does not bind `org_id`.
  `organization.v1.tools.harness_config` then adds `org_id` to
  `harness_config_drift` and installs the organization triggers on all four.
  Each organization has its own versions and its own active bundle;
  `harness_config_publish`, `harness_config_status` and every `node_config`
  action (`get`, `report`, `applied`) use the caller's organization (for a
  node, its agent's), another organization's bundle or proposal answers as a
  missing one, and a publish, report or applied call for an organization
  `orgs` does not hold is refused (`unknown_organization`) before anything
  changes. Publish and apply approvals bind `org_id`, so a pass is never
  consumed across organizations. Publishing still needs `ua_org::authz`,
  which admits only the default organization until memberships exist. Closing
  a reassigned or forgotten node's open proposals takes the node's
  organization (`nodes.org_id`, the nodes family below; it no longer spans
  every organization), and a node's
  `node_config` calls reach only a node of the caller's organization.
  The `agent.harness_config` events are `ORG-EVENT-DEFAULT` sites. The
  importer writes legacy bundles to `default`.
- The routine and workflow-run tables: `organization.v1.tools.routines`
  gives `routines` and `routine_runs` their `org_id` and triggers, and
  `routines.v2.org_indexes` adds indexes led by `org_id` and the
  `routine_runs_same_org` triggers (a receipt is in its routine's
  organization); `organization.v1.tools.workflows` and
  `workflows.v2.org_indexes` do the same for `workflow_runs` and
  `workflow_checkpoints` (a checkpoint is in its run's organization). No
  rebuild: `routines` is keyed by an AUTOINCREMENT id, a run by a ULID the
  hub generates, and the unique pairs `(routine_id, fire_key)` and
  `(run_id, seq)` are led by those hub-global ids. Every routine, workflow and
  LangGraph tool, and the workflow rows of `run_list` and `run_get`, read and
  write only the caller's organization's rows; another organization's
  routine or run answers as a missing one, and an organization `orgs` does
  not hold is refused before any write. The scheduler (`tick`) and the
  startup reconciliation have no caller: each fire takes its routine's
  organization, and a routine's workflow run is recorded in it. A routine's
  workflow runs as its owner, and that caller can only be built in the
  default organization until the resolver binds others (`org_guard`), so a
  fire outside it never runs its workflow (reconciliation marks one `not_run`).
  Each fire creates its task in its routine's organization (before tasks
  carried an organization, a fire outside the default organization was
  recorded as `skipped`, `org_tasks_unavailable`; old receipts keep that
  reason), and the LangGraph tools see only the caller's organization's
  tasks. A gated step's approval payload binds `org_id`.
  `routine_runs` and `workflow_runs` point at tasks (`task_id`), but neither
  is keyed by a task id nor part of the task workflow, so they convert here,
  not with `tasks`. The routine and workflow events are `ORG-EVENT-DEFAULT`
  sites; another organization's client-chosen fire key reaches the ledger
  only as a SHA-256 digest. The importer copies none of these tables.
  `crates/ua-tools/tests/routines_tenant.rs` holds the upgrade and the
  isolation tests.
- The plans tables: `organization.v1.tools.plans` gives `plans`,
  `plan_steps` and `plan_checkpoints` their `org_id` and triggers, and
  `plans.v2.org_scope` adds an index led by `org_id` for the plan list and
  the `*_org_parent` triggers that keep a step or checkpoint in its plan's
  organization (the `plan_id` foreign key alone would accept a parent in
  another organization). No rebuild: a plan id is a hub-generated random
  id (the hub-global primary key, never chosen by a caller), and the step
  key `(plan_id, step_idx)` and checkpoint key `(plan_id, seq)` hang off it,
  so two organizations cannot collide on any of them. The one unscoped
  statement is the fresh-id check in `create`, which must span every
  organization because the key does. Every `plan_manage` action and legacy
  `plan_*` tool, and the `plan` kind of `platform_object_get`, reads and
  writes only the caller's organization's rows; another organization's plan
  answers exactly as a missing one, and a write for an organization `orgs`
  does not hold is refused (`unknown_organization`) before anything
  changes. Plans do not link to tasks, so no task-organization rule applies, and
  no plan action has an approval gate of its own. The `agent.plan.*`
  events are `ORG-EVENT-DEFAULT` sites: for a plan outside the default
  organization their free text and caller-supplied labels are `null`
  (`goal` and `scope` on `created`, `owner` on `step_updated`, `agent` on
  `step_claimed`, `agent` and `next_owner` on `handoff`, `reason` on
  `closed`), so none of it reaches the default organization's ledger; the
  payload keeps its shape. The other fields are ids, counts, step indexes
  and enumerated statuses. The importer writes legacy plans,
  steps and checkpoints to `default`. `crates/ua-tools/tests/plans_tenant.rs`
  holds the upgrade and the isolation tests.
- The autonomous-cycle tables: `organization.v1.tools.cycles` gives
  `autonomous_cycles`, `autonomous_cycle_transitions` and
  `autonomous_cycle_usage` their `org_id` and triggers, and
  `cycles.v2.org_scope` adds an index led by `org_id` for the cycle list and
  the `*_org_parent` triggers (on insert and on a changed `cycle_id`) that
  keep a transition or usage row in its cycle's organization. No rebuild: a
  cycle id is a hub-generated random id, and the transition key
  `(cycle_id, idempotency_key)` and usage key
  `(cycle_id, usage_run_id, usage_id)` are led by it. Every
  `autonomous_cycle_manage` action, legacy `autonomous_cycle_*` tool and the
  green-path check reads and writes only the caller's organization's rows;
  another organization's cycle answers exactly as a missing one, and an
  organization `orgs` does not hold is refused (`unknown_organization`)
  before anything changes, including before a gated transition reaches the
  approval queue. A gated transition's approval payload binds `org_id`.
  Nothing runs a cycle without a caller. A cycle may name a task and a
  delegation, both read in the cycle's organization: to another
  organization a task, or a delegation of another organization's task,
  answers as a missing one (`cycles.v3.task_org` also keeps a cycle's task in
  its own organization). `autonomous_cycles.task_id` is
  optional and the table is keyed by its own id, so it converts here, not
  with `tasks`. `agent.cycle.updated` is an `ORG-EVENT-DEFAULT` site: for a
  cycle outside the default organization its `stop_reason` (which carries
  kill reasons, capability names and the acting agent) is `null`, and the
  event is attributed to the caller's own label, never to the agent a system
  or anonymous caller claims. The importer copies none of these tables.
  `crates/ua-tools/tests/cycles_tenant.rs` holds the upgrade and the
  isolation tests.
- The approval queue: `organization.v1.tools.approvals` gives `approvals`
  its `org_id` and triggers, and `approvals.v3.org_indexes` adds indexes led
  by `org_id` for the gate's match and the per-organization queue. No
  rebuild: the table's only key is an AUTOINCREMENT id, and no unique key or
  payload-hash constraint exists; the gate's match on `(tool, payload,
  requested_by)` is a query key, which now filters on `org_id`, as in the
  [binding rule](#approvals-routed-by-team). Existing rows move to
  `default`; their payloads did not change, so no open approval is expired.
  An approval belongs to the organization of its **requester** (the gate
  caller's `org_id`). `gate`, `gate_via`, `request`, `peek` and the
  stale-pass checks match only the caller's organization, so a pass parked
  in organization A never satisfies the identical call in B, even with the
  same tool, payload and requester label; expiry happens at gate time, per
  organization. Runners without a human caller (workflow steps, harness
  config, skills, routines, dispatch, the relay) gate with the caller they
  already build, whose organization is the row's. `approval_pending`, the
  `/api/approvals` routes, the inbox, `platform_object_get`, the session
  packet, the evidence report and the `approval_queue_age` anomaly show only
  the reader's organization. `approval_resolve` answers another
  organization's approval exactly as a missing id on every transport (MCP,
  HTTP, UI, CLI, Slack all resolve through it). Every existing resolver rule
  holds (`not_human`, `self_approval`, `resolver_mismatch`, Slack's
  `can_approve`); approving, and a human's deny or revoke, also needs
  `ua_org::authz::require_same_org`, which admits only the default
  organization until memberships exist (a human identity is hub
  configuration, so it always resolves there), so another organization's
  approvals can be withdrawn by their requester but approved by no one yet:
  fail closed. A gate or request for an organization `orgs` does not hold
  is refused (`unknown_organization`) before anything changes. The
  `agent.approval.*` events are `ORG-EVENT-DEFAULT` sites; for an approval
  outside the default organization `requested_by` and `resolved_by` are
  `null` in their payloads (the other fields are ids, tool names, hashes and
  enumerated codes), and the event's `originator` column is the neutral
  `system`, never the requester's or resolver's label. A workflow run is
  executed only by a caller of the run's own organization: a gated step's
  payload binds the run's `org_id` while the gate parks in the caller's, so
  a mismatch is refused (an internal error) before the run's lease is taken
  or anything is parked, rather than rebuilding the caller (`org_guard`
  forbids that). A relay draft and its approval are in one organization
  since `relay_messages` converted (the mailbox and relay below), so a
  draft's `status` and `cancel` always see its own approval; a `cancel`
  whose approval is nonetheless missing fails closed (`not found`), so a
  draft is never marked cancelled while its approval stays live. Skill
  registry approvals (publish, assign, unassign) bind `org_id`. A
  policy-authorization refusal is ledgered under the authorization's
  organization (the caller's) since `policy_authorizations` converted (the
  policy authorizations below), so another organization's requester label
  is `null` and the `originator` is `system`. The importer
  writes legacy approvals to `default`. `crates/ua-tools/tests/approvals_tenant.rs`
  holds the upgrade and the isolation tests.
- The core task tables: `organization.v1.tools.tasks` gives `tasks`,
  `task_dependencies`, `task_comments` and `task_comment_threads` their
  `org_id` and triggers (existing rows move to `default`), and
  `tasks.v2.org_scope` adds indexes led by `org_id` for the status, project
  and claimant queues and the `*_org_parent` triggers that keep a task's
  `parent_id` and `folded_into`, both ends of a dependency, and a comment's
  task and parent comment inside one organization. No rebuild: a task id is
  a hub-global AUTOINCREMENT id (Decision 3: task identity never moves
  between organizations) and every child key is led by a task or comment id.
  The converted families gain the same rule for their `task_id`:
  `routines.v3.task_org`, `workflows.v3.task_org`, `cycles.v3.task_org` and
  `deliverables.v2.task_org` (the last lives in `ua-tools`, because the
  `ua-deliverables` store has no `tasks` table). The shared lookups
  (`task_object`, `require_task`, `ancestors`, `subtree_ids`, `rollup`,
  `decorate`, `check_nesting`) take the organization and filter on it, so
  every task tool, the queue and workflow-record actions, claims and their
  release, holds, dispatch, node work, the relay, the session packet,
  agents, capability, policy claims, the evidence report, observability,
  the task, memory and journal exports, `platform_object_get`,
  `state_sync_verify`'s `task_fts` counts and the UI read and write only the
  caller's organization's tasks (the follow-up relay checks a node item's
  task holder in the task row's organization); a job with no caller (dispatch outcomes, node
  runners, `review_ready`) uses the task row's organization. Another
  organization's task, dependency, comment, hold, delegation or policy
  authorization answers exactly as a missing one, and a write for an
  organization `orgs` does not hold is refused (`unknown_organization`, "no
  task was changed") before anything changes. Task and comment replies keep
  their shape: `org_id` is not added (owner decision). `task_fts` stays an
  external-content index with no column: ranked search scopes its
  `eligible` subquery by `org_id` before the candidate cap.
  - **Owner decisions (2026-11-23).** (a) `idempotency_keys` stayed
    hub-wide until its rebuild; meanwhile another organization's
    `task_add`, `task_update` and `delegate` keys were stored with its
    organization prefixed (`org:<org>/<tool>:<key>`), so a key reused in
    another organization never replayed, and the default organization keeps
    its `<tool>:<key>` form. The rebuild has landed
    (`idempotency.v2.tenant_keys`, the idempotency keys family below); the
    prefix stays in the key text as defence in depth. (b) The GitHub and CI paths
    without a caller stayed default-only until they ran per organization
    (superseded; see
    managed secrets below): every task scan now filters on the
    organization the path acts for, so a delivery for a repository two
    organizations bind touches only the tasks of the organizations whose
    secret verified it, and `queue_close_merged` runs in the caller's
    organization. (c) A delegation to another organization's agent
    was allowed pending the agents conversion (it could never be claimed:
    the delegate looks the task up in its own organization and finds
    none). Since agents carry an organization it is refused instead, fail
    closed, and (owner decision) the target must be a **registered agent of
    the delegator's own organization**: `delegate` answers a `to_agent` that
    no agent has registered and one another organization's agent holds
    byte-for-byte alike, as `not_found` ("no agent in this organization"),
    and creates nothing. This applies to the default organization too. The
    match ignores letter case, as the label namespace does (an exact
    spelling wins), and the delegation stores the **registered** spelling
    as `to_agent`, the one the agent's claims and lists match: `Builder-1`
    delegates to the registered `builder-1`.
    Policy authorizations, which carry no `org_id` yet, are reached only
    through their task's organization; delegations carry their own (below).
    (d) Task replies carry no `org_id`.
  - The migration manifest (`export_migration_manifest`,
    `compare_migration_manifests`, and both through `export_data`) is a
    hub-wide snapshot: every organization's tasks and notes and the whole
    event-log summary. Only the default organization, which operates the
    hub, may build or compare one; another organization's caller is
    refused (`org_unsupported`) before anything is read.
  - `task_update` idempotency keys are the caller's: stored as
    `task_update:<label>:<key>` (organization-prefixed outside the
    default), with `%`, `:` and `/` in the label percent-escaped so two
    labels never share a stored key. The task is looked up first, and a
    stored reply is replayed only for the same task; the same key on
    another task is refused (`idempotency_key_reused`). Old
    `task_update:<key>` rows are not read.
  - A conversation handoff's task is created by the handoff itself, under
    `task_add`'s gate, with a key derived from the organization, actor,
    conversation, title, project and priority and stored under its own tool
    name (`conversation_handoff`). `task_add` refuses client keys starting
    with `conversation-handoff:`.
  - Deleting another organization's task deletes, in the same transaction,
    the policy authorizations naming a task in its subtree and the holds
    rooted in it (and their members), in their own organization only. Both
    now carry `org_id` and could not fall into the default organization,
    but the outcome of deleting another organization's task is kept. The
    default organization's holds and authorizations outlive their task, as
    before.
  - Work proposals and goals carry their own organization (the goal and
    work-proposal tables, below): a proposal's task is created in the
    proposal's organization, and the contract check reads only the task
    organization's proposals and items.
  - Events stay in the default organization's ledger (`ORG-EVENT-DEFAULT`):
    for another organization's task its titles, notes, comment bodies,
    reasons, check names and caller-supplied labels are `null`, and the
    originator is `system`.
  - **Accepted residuals.** Task ids are hub-global, so the gaps in the ids
    one organization sees reveal how many tasks the hub holds overall.
    bm25's term statistics (document frequencies, average length) come
    from the whole `task_fts` index, so another organization's tasks can
    shift a score's value, never which rows match or are returned. A
    default-organization hold or policy authorization outlives its task in
    the default organization. A delegation carries its own organization
    (`delegations` below), so it never falls back to the default one.
  - The importer writes legacy tasks, dependencies, comments and threads to
    `default`. A routine fire in another organization now creates its task
    there. `crates/ua-tools/tests/tasks_tenant.rs` holds the upgrade and the
    isolation tests.
- The task workflow and hold tables: `organization.v1.tools.continuity`
  gives `task_workflow`, `task_checks` and `review_ready_notices` their
  `org_id` and triggers, and `continuity.v2.org_scope` moves each existing
  row to its task's organization (a row whose task is gone stays in
  `default`), adds indexes led by `org_id` for `task_list`'s stage filter
  and the re-verification scan by repository and head, and the
  `*_org_parent` triggers that keep every row's `task_id` inside the row's
  organization. `organization.v1.tools.holds` and
  `governance.v3.holds_org_scope` do the same for `task_holds` (moved to its
  root task's organization) and `task_hold_members` (moved to its hold's),
  with triggers that keep a hold's root task, a member's task and a
  member's hold inside one organization. The backfill drops each generated
  `*_org_immutable` trigger for its one `UPDATE` and recreates it, in the
  part's transaction. No rebuild: every key is led by a hub-global task or
  hold id, and the one-active-hold-per-root index stays keyed by the root
  task id. Every statement on the five tables filters `org_id`: the
  workflow record, checks and their verification, the review-at-head merge
  gate, `review_ready` and its notices (in the task row's organization, read
  in the same transaction as the record), the session packet's workflow
  block, deliverables' workflow head, `task_list`'s stage filter, and every
  hold read, write and claim-gate check. A hold's organization is its
  `org_id`, no longer derived from its root task, so a hold outlives its
  root inside its own organization. The read-time release of
  `after_active_runs_finish` holds settles only the reader's organization's
  holds; another organization's are released by its own reads and claims.
  A write for an organization `orgs` does not hold is refused
  (`unknown_organization`) before anything changes, and replies carry no
  `org_id` (owner decision (d)). The hub's head re-verification
  (`reverify_head`, from the webhook and the poller) scans only the checks
  of the organization the delivery or poll belongs to, and looks runs up
  with that organization's token. Events
  stay `ORG-EVENT-DEFAULT`: for another organization, check names and hold
  reasons, actors and outcomes are `null` and the originator is `system`;
  workflow goals and focus never reach an event. The importer writes legacy
  workflow records, checks, holds and members to `default`; its
  active-hold clash probe stays hub-wide, because the one-active-hold index
  is. `crates/ua-tools/tests/continuity_tenant.rs` holds the upgrade and the
  isolation tests.
- The delegations table: `organization.v1.tools.delegation` gives
  `delegations` its `org_id` and triggers, and `delegation.v2.org_scope`
  moves each existing delegation to its task's organization (in practice
  all of them are the default organization's; a delegation whose task is
  gone stays there), adds indexes led by `org_id` for the assignee queue,
  the status list and the stats window, and the `delegations_org_parent`
  triggers that keep a delegation's `task_id` inside its own organization.
  To move the rows, it drops the generated `delegations_org_immutable`
  trigger for that one update and recreates it exactly as the tenant part
  made it. No rebuild: a delegation id is a hub-global AUTOINCREMENT id and
  the table has no other key. A delegation is created in its delegator's
  organization, with its task, in one transaction. Every delegation action
  and legacy tool (`delegate`, `delegate_list`, claim, release, cancel,
  fail, complete, retry, get, lookup, `handoff`, `handoff_list`), the plans
  UI, the evidence report, `observability_manage`'s `delegation_stats`,
  the session packet, `platform_object_get`, a cycle's `delegation_id` and
  the task queue's live-work check read and write only the caller's
  organization's delegations. Another organization's delegation answers
  exactly as a missing one: `get` is not found, and a claim, or a fenced
  release, retry, complete, fail or cancel with the right generation,
  changes nothing and answers as it would for a missing id. A write for an
  organization `orgs` does not hold is refused (`unknown_organization`)
  before anything changes. Replies carry no `org_id` (owner decision (d)).
  Owner decision (c), resolved fail-closed by the agents family, then
  narrowed by the owner: a delegation targets only an agent registered in
  the delegator's organization (an `agents` row there with exactly that
  label, the spelling its claims match). A label no agent has registered
  and a label another organization's agent holds are refused alike
  (`not_found`, the same message built from the requested label alone,
  nothing created), through every door (`delegate`, `delegation_manage`
  create, `handoff`). `delegate`
  idempotency keys are stored per delegating agent as
  `delegate:<label>:<key>`, organization-prefixed outside the default
  (owner decision (a)), with `%`, `:` and `/` in the label percent-escaped
  as `task_update`'s are; only a label holding `:` changes its stored form.
  A retry or `lookup` from such a label also reads its old unescaped key,
  which another label can share (`a:b` with key `k`, `a` with key `b:k`), so
  a receipt there counts only when it is shown to be the caller's: a retry
  replays it only when its request digest, which covers `from_agent`,
  matches (any other receipt there reads as not found, and the request runs
  fresh), and `lookup` reports it only when its delegation's `from_agent`
  is the caller. The
  `agent.delegation.*` events, and the `agent.task.created` event of a
  delegation's task, are `ORG-EVENT-DEFAULT` sites through the shared
  `emit`: for a delegation outside the default organization its title,
  project, lane, agents, deadline, callback, reasons and results are `null`
  and the originator is `system`; ids, statuses and generations remain.
  `dispatch_runs.delegation_id` and the messaging tables' `delegation_id`
  are passive references that no code follows into `delegations`. The
  importer writes legacy delegations to `default` and never copies a
  source `org_id`. `crates/ua-tools/tests/delegation_tenant.rs` holds the
  upgrade and the isolation tests.
- The goal and work-proposal tables: `organization.v1.tools.goals` gives
  `goals` and `task_goal_links` their `org_id` and triggers, and
  `organization.v1.tools.proposals` gives `work_proposals` and
  `work_proposal_items` theirs. Every existing goal and proposal stays in
  `default` (they were the default organization's: proposals were refused
  to other organizations, and goals had no organization to take).
  `goals.v2.org_scope` moves each link to its task's organization and then
  deletes a link whose goal is in another organization, since a task may
  serve only its own organization's goal; `governance.v4.proposals_org_scope`
  moves each item to its proposal's organization. Each drops the generated
  `*_org_immutable` trigger for its one `UPDATE` and recreates it exactly,
  in the part's transaction. They add indexes led by `org_id` for the goal
  list, a goal's links, the proposal list and the contract check's lookup of
  the item that spawned a task, and the `*_org_parent` triggers that keep a
  goal's `parent_goal_id`, a link's task and goal, and an item's proposal
  and `task_id` (which has no foreign key) inside the row's organization.
  No rebuild: a goal id is a hub-global AUTOINCREMENT id, a proposal id the
  hub-generated `wp_<uuid12>` (never chosen by a caller), and the link and
  item keys are led by a task or proposal id. Every `goal_manage` action,
  `task_update`'s check that a moved task's goal is in its new project,
  `platform_object_get`, every work-proposal action and the contract check
  that `task_claim`, `task_update` into `doing`, dispatch and node work run
  read and write only one organization's rows: the caller's, or for the
  contract check the task's. Another organization's goal or proposal
  answers exactly as a missing one, a link to another organization's goal
  is refused as a link to a missing goal, and a contract marker naming
  another organization's proposal is refused as naming an unknown item. A
  write for an organization `orgs` does not hold is refused
  (`unknown_organization`) before anything changes. Replies carry no
  `org_id` (owner decision (d)), and `goal_manage` still refuses
  `params.org_id`. Deciding a proposal is authority-gated in the caller's
  organization (`authz` with `TransitionalHuman`), which admits only the
  default organization until memberships exist: another organization's
  proposals can be filed, read, listed, withdrawn and recovered, but its
  human is refused (`org_mismatch`) before anything is read, so no
  approval outside the default organization happens yet; when one does, its
  task is created in the proposal's organization. Filing for another
  identity is operator authority in the caller's organization, so it too is
  default-only for now. The `agent.goal.*` and `agent.work_proposal.*`
  events are `ORG-EVENT-DEFAULT` sites: for another organization the close
  and reopen reason, the proposer and the withdrawal reason are `null` and
  the originator is `system`; ids, indexes, statuses, the reporting mode
  and contract digests remain (goal and item titles and notes never reach
  an event). The importer writes legacy goals, links, proposals and items
  to `default` and never copies a source `org_id`.
  `crates/ua-tools/tests/goals_tenant.rs` holds the upgrade and the
  isolation tests.
- The managed-secret store and per-organization GitHub credentials: the
  standalone procedure `managed_secrets.v2.tenant_keys` rebuilds
  `managed_secrets` around `(org_id, name)` (existing secrets move to
  `default`) and adds `aad_v`, the associated-data form a row was sealed
  under; `organization.v1.tools.managed_secrets` installs the organization
  triggers. Every write now seals with `aad_v = 2`, which binds the
  organization, name and consumer, so a row copied into another
  organization does not decrypt; a legacy row (`aad_v = 1`, name and
  consumer) decrypts only in the default organization, and setting it again
  re-seals it. Every statement filters `org_id`; `managed_secret_set`,
  `managed_secret_list` and `managed_secret_delete` act in the caller's
  organization only, and another organization's secret of the same name
  answers as a missing one. Writing needs `Operator` in the caller's
  organization, which admits only the default organization's humans until
  memberships exist, so another organization's secrets cannot be written by
  any caller yet (fail closed); a write for an organization `orgs` does not
  hold is refused (`unknown_organization`). The hub-scoped consumers (MCP
  servers, the relay) keep their secrets in the default organization.
  **Owner decision (2026-11-23):** GitHub automation (the webhook, the
  poller, CI verification and merged-PR reconciliation) runs per task
  organization, each under its own GitHub credentials, and an organization
  without one stays off; this supersedes "GitHub stays default-only until
  per-organization tokens exist". The credential layer is in the tree
  (`crates/ua-tools/src/families/github/credentials.rs`):
  `github_credential_for(org, kind)` answers the default organization with
  the hub's configured token and webhook secret (`github_token_env`,
  `github_webhook_secret_env`), unchanged, and every other organization with
  its own managed secrets `github:token` (consumer `github:api`) and
  `github:webhook-secret` (consumer `github:webhook`), never with the hub's
  or another organization's (`None`, reported `off`). Those names and the
  consumer kind `github` are reserved: only `github_credential_set` and
  `github_credential_clear` write them, under the same authority, with the
  default organization refused (its credentials are configuration) and
  replacing or clearing one gated by a one-time human approval bound to the
  keyed fingerprint. `github_credential_status` and a `system_doctor` line
  (each organization by name for a hub operator, a verified human of the
  default organization; counts only for any other caller, over its own
  organization outside the default) report `configured`, `off` or
  `unusable`, never a value or fingerprint; `managed_secret_list` shows a
  reserved row's name, consumer and who set it, without fingerprint, size
  or key id. The fingerprint is visible only in the one-time approval a
  replacement or clear binds, as for every managed secret. The relay
  (`relay_manage` `request_send`, `send`) and an MCP server that injects
  secrets (`mcp_gateway` `call`, live `list`) use the default
  organization's secrets, so another organization's caller is refused
  (`org_unsupported`) before anything is read. Every downstream MCP
  server is the hub's, secrets or not: a stdio server is a process the hub
  spawns on its own host, and a Streamable HTTP server is reached from the
  hub's network position (loopback, tailnet and private ranges). So
  `mcp_gateway` `call` and live `list` are refused to another
  organization's caller on every server, before the policy check, the
  slot, any approval, any secret read and any spawn or connection, until
  servers are per organization. A static `list` reads only the
  registration, which `mcp_server_list` already shows, and is not
  refused. The `github.credential.*` and `managed_secret.*` events are
  `ORG-EVENT-DEFAULT` sites: for another organization the secret name and
  consumer are `null` and the originator is `system`. The automation paths
  run per organization through `github_credential_for` (the
  `ORG-GITHUB-DEFAULT` marker and the `TASK_ORG` constant are gone): a
  webhook delivery belongs to the organization its route names
  (`POST /api/github/webhook/<org id>`; the bare `POST /api/github/webhook`
  is the default organization's) and is checked against that
  organization's secret only, one secret and one MAC per delivery, with one
  byte-identical refusal for an unknown, suspended or secretless
  organization and a bad signature; every organization's webhook secret
  must be distinct (`webhook_secret_in_use`, checked by keyed fingerprint
  at `github_credential_set` after the approval gate, each refusal ledgered
  by fingerprint; a shared secret found at startup refuses every route that
  shares it, fail closed), and the former multi-match rule is gone
  (see [github.md](github.md#automation-per-organization)),
  the poller polls each organization with its own token and skips one
  without, CI lookups and `queue_close_merged` use the task's or caller's
  organization's token and bindings, and the hub's token never serves
  another organization. They act as the hub identity in that organization
  (`github_caller_for`, the one `Caller::system_for` site `org_guard`
  admits). The poller's state is per organization in `github_poll_repos`
  (`github.v2.poll_repos` copies every row of `github_poll_state` to the
  default organization; no row is dropped, and the old table stays unread);
  repositories whose last poll failed are counted on the `system_doctor`
  line. **What another organization's GitHub events still show.** The
  `agent.github.*` events stay in the default ledger (`ORG-EVENT-DEFAULT`).
  For another organization the repository, branch names (`base_ref`,
  `merge_branch`), check names and closure text are redacted (`null`, or a
  count), but head and merge commit SHAs and pull request numbers stay
  visible, as task ids already do: they identify commits and numbers, not
  names, and the default organization's operators can correlate them only
  with a repository they can already see. The webhook's HTTP answer on
  another organization's route carries no organization id, repository or
  task (`{"ok": true}`), and an internal failure there answers a fixed
  message, never the error's text.
  `crates/ua-tools/src/families/github/org_automation_tests.rs` holds
  the per-organization automation tests. The importer has
  no managed-secret mapping (the Python hub kept none), so it writes nothing
  here. `crates/ua-tools/tests/managed_secrets_tenant.rs` holds the upgrade,
  isolation, authority and leak tests.
- Policy authorizations: `organization.v1.tools.policy_authorizations`
  gives `policy_authorizations` its `org_id` and triggers, and
  `github.v3.policy_authorizations_org_scope` moves each existing
  authorization to its task's organization (the organization every reader
  already resolved it to; one whose task is gone stays in `default`, as the
  readers treated it), adds indexes led by `org_id` and the
  `policy_authorizations_org_parent` triggers that keep an authorization's
  task in its own organization. Nothing is dropped. No rebuild: the only
  key is an AUTOINCREMENT id. `policy_authorization_record`, `_list` and
  `_revoke`, the merge path's check, spend and restore
  (`git_merge_task(policy_authorization_id)`) and the task delete read and
  write only the caller's organization's rows, so the check never sees
  another organization's authorization: it answers as a missing one. A
  record or revoke for an unknown organization is refused before anything
  changes. The `agent.github.policy_authorization.*` events and the
  refusals are `ORG-EVENT-DEFAULT` sites: for another organization the
  repository, policy reference and revoke or restore reason are `null` and
  the originator is `system`; ids, the head SHA, the pull request number
  and the binding hash stay, as in the other GitHub events. Replies keep
  their shape (no `org_id`). The importer has no mapping for the table.
- Tool-call telemetry: `organization.v1.tools.tool_calls` gives
  `tool_calls` its `org_id` and triggers (every existing row is the default
  organization's; the only earlier caller outside it could be #121's
  `github` system caller on a hub with a hand-added organization, whose
  rows hold only a tool name, the `github` label, timing and outcome), and `core.v5.tool_calls_org_scope` adds two
  indexes led by `org_id`. Nothing is dropped; no rebuild (AUTOINCREMENT
  key). The registry records the caller's organization on every row, in
  the statement it already ran (no extra query per call; an unknown
  organization fails the existence trigger, and the policy reservation then
  fails closed). Its reservation update and release filter on it. Every
  reader counts only the reader's organization's rows, and inside it keeps
  PR #122's rule (an unrestricted reader counts every caller, anyone else
  only its own calls): `perf_summary`, `metrics_snapshot`,
  `check_anomalies`' `tool_error_rate`, `mcp_health`'s telemetry,
  `evidence_report`'s `tool_call_window` and the policy rate limits and
  cooldowns. A verified caller of another organization counts its own calls
  in its own organization (`EventReader::call_bindings`); it is never
  unrestricted there until memberships exist. The compatibility API and
  the UI write through the registry (`page_view`, `page_reads`) and read
  none. There is no retention sweep of `tool_calls`; one added later must
  either run per organization or be hub-wide by design and say so.
  `crates/ua-tools/tests/policy_toolcalls_tenant.rs` holds the upgrade and
  the isolation tests for both tables.
- The memory tables: `organization.v1.memory` gives `memory`,
  `memory_versions` and `memory_embeddings` `org_id` and the organization
  triggers; every existing row lands in `default`, and nothing is moved or
  dropped (so no dropped-row record is needed). `memory.v2.org_scope`
  recreates `memory_versions_capture` so a history row names `OLD.org_id`
  (the released `memory_versions.v1` trigger left it to the default),
  adds `memory_versions_org_parent`, `memory_embeddings_org_parent` (and
  their `_update` twins) and `memory_org_superseded_by`, which keep a
  version, a vector and a supersede pointer in their note's organization,
  and the indexes `idx_memory_org_updated` and
  `idx_memory_embeddings_org_model`. No key rebuild: a note id is
  hub-generated (random, never caller-chosen), and `memory_versions
  (note_id, version)` and `memory_embeddings(note_id)` are led by it. Every
  statement filters `org_id`: `memory_save` (create, update, append,
  overwrite, supersede, contradicts, the similar-note check), `memory_search`
  (the FTS leg, the vector scan and the exact-similarity lookup, each with
  the organization inside the ranked query, so another organization's notes
  never take a candidate slot or a rank), `memory_list`, `memory_get` (with
  its versions, links and contradiction counts), `memory_delete`,
  `memory_restore`, `memory_feedback`, `memory_prune_candidates`,
  `recall_maintenance`, the access counters, `export_memory`,
  `platform_object_get`, the session packet's related notes and the
  learning proposals' duplicate check, `vault_ingest`'s lookup,
  `state_sync_verify`'s count and dangling-pointer check and
  `system_doctor`'s note and vector counts. The UI and the compatibility
  API reach memory only through these tools. Another organization's note
  answers exactly as a missing one; a write for an organization `orgs` does
  not hold is refused (`unknown_organization`), and one for a suspended
  organization (`organization_suspended`), before anything changes.
  `memory_promote` copies a note into the hub-wide vault, so another
  organization's caller is refused (`org_unsupported`); so is
  `vault_to_memory_ingest`, which reads the vault. A file export
  (`export_memory`, `export_tasks` with `write_to_vault`, the default)
  lands in the hub's shared workspace, so it is refused outside the
  default organization (`org_unsupported`, nothing written or ledgered);
  `write_to_vault=false` returns the export inline. `export_journal` reads
  the hub's vault, so it is refused outside the default organization
  inline or not.
  A save's idempotency key is stored as `org:<org>/memory_save/<label>/<key>`
  in another organization, with `%` and `/` escaped in both the
  organization and the label (the default keeps `memory_save/<label>/<key>`
  byte for byte), a receipt whose note the caller's organization cannot see
  is refused (`idempotency_key_conflict`) rather than replayed, and a
  pre-upgrade raw key replays only in the default organization. Memory
  events and `state_sync_verify`'s `agent.state.resynced` are
  `ORG-EVENT-DEFAULT` sites: for another organization the title,
  tags, revision hash, author, owner and actor are `null` and the
  originator is `system`; ids, modes, signals and timestamps remain. The
  importer writes legacy notes and versions to `default` and never copies a
  source `org_id`. The migration manifest and `ua backup` stay hub-wide
  (default organization and the operator only). **Accepted leak
  candidates.** `memory_fts` is one hub-wide FTS5 index, so bm25's corpus
  statistics (document frequencies, average length) count every
  organization's notes: another organization's notes can shift the value of
  a lexical `score` and its `explanation.lexical`, never which notes match,
  rank against each other in a candidate cap, or are returned. Avoiding it
  needs one FTS index per organization. The vector scan has no shared index
  state (vectors are read per organization), so it leaks nothing.
  `crates/ua-tools/tests/memory_tenant.rs` holds the upgrade, isolation,
  semantic-search, idempotency, unknown-organization and ledger tests.
- The mailbox and the relay: `organization.v1.tools.messaging` gives
  `message_index` and `message_reads` their `org_id` and triggers, and
  `organization.v1.tools.relay` gives `relay_messages` its own. Every
  existing row is the default organization's (every sender, reader and
  requester the hub served was a default-organization caller); nothing is
  moved, rewritten or dropped. No rebuild: message ids and event ulids are
  hub-minted, a receipt is keyed by its message id, and a draft by an
  AUTOINCREMENT id. `messaging.v2.org_scope` adds indexes led by `org_id`,
  the `message_reads_org_parent` triggers (a receipt is in its message's
  organization), the `message_index_org_reply` triggers (a reply is in its
  parent's organization; an external `ts:` reply names no row), and
  `org_payload`, below. `relay.v2.org_scope` adds indexes and the
  `relay_messages_org_approval` triggers (a draft's approval is in the
  draft's organization). A message's `task_id` and `delegation_id` get no
  trigger: they were never checked, every reader filters on the message's
  organization, and a trigger would answer another organization's id
  differently from a missing one.
  - **A message is its sender's organization's.** `message_send`,
    `message_list`, `message_inbox`, `message_ack`, the reply, hop and
    short-reply chain checks, `waiting_on_reply`, the conversation-id party
    check, `conversation_handoff(s)`, `crew_view` (its messages and the
    drop file's pointers), `session_packet`'s prior handoff, the wake
    gates and the ledger's mailbox visibility rule (`VISIBLE_EVENT`) read
    and write only that organization's rows. Another organization's
    message, `reply_to`, conversation id and client id answer exactly as
    missing ones. Every reader and writer (`message_list`,
    `conversation_handoff(s)` and `crew_view` included) refuses an unknown
    or suspended organization first.
  - **Mail to a label stays in its sender's organization.** A message
    to `to_agent` is stored in the sender's organization and read only
    there, whatever the label is elsewhere: the same label in two
    organizations is two mailboxes. A send's `availability` reads only the
    sender's organization's agent and sessions, so a label registered in
    another organization answers exactly as an unregistered one
    (`unknown`, `no_liveness_record`), and registering a label elsewhere
    neither stops nor changes the send. (Before the agents family
    converted, outside the default organization the send never consulted
    `agents` at all.)
  - **A session is its agent's organization's** (the agents family,
    below). A send to a session, a sender's `from_session` and a reader's
    `session_id` resolve only the caller's organization's sessions;
    another organization's session answers exactly as a missing one, so a
    message is never delivered across an organization. `crew_view` and
    `crew_intervene` read only the caller's organization's session (the
    interim refusals `cross_org_recipient`, `org_unsupported` and the
    pre-gate are gone). `crew_intervene` stays always approval-gated, so
    another organization's request parks in its own organization, where
    no one can approve it until memberships exist; and its drop file is
    written and read only for the default organization's callers, since
    the workspace it lives in is the hub's.
  - **Events.** Message and mailbox events are `ORG-EVENT-DEFAULT` sites.
    Another organization's `agent.message.*` event keeps the payload's
    shape with only hub-minted ids, the act, the hop and flags: body,
    typed handoff, every label, the conversation id, `reply_to`,
    `event_id`, the client id, `task_id` and `delegation_id` (unchecked
    integers the sender chooses) are `null`; the originator is `system`,
    and it has no episode or causal parent.
    The message itself is kept on its index row (`org_payload`), which only
    its organization reads; a default-organization row leaves it `NULL`
    and reads its event as before. Another organization's
    `agent.mailbox.read` / `.acked` names no mailbox or client id and uses
    `system`. Another organization's `agent.conversation.handoff` names no
    actor (`by` is `null`, the originator `system`) and records its
    conversation as `org/<digest of (organization, conversation id)>`,
    with the dedupe key `conversation-handoff:org/<digest of
    (organization, conversation id, task, actor)>`; `conversation_handoffs`
    matches that organization's digest only, so a default reader who
    reuses a leaked conversation id finds none of its rows. The digest is
    not keyed: whoever knows both the organization id and the
    conversation id can recompute it. The default organization's events
    and keys are unchanged (`conversation_id` itself,
    `conversation-handoff:<cid>:<task>:<actor>[:created]`), so they still
    deduplicate. Accepted edge of `VISIBLE_EVENT`: a writer sees its own
    rows by originator, so a default-organization reader whose verified
    label is `system` matches every redacted event another organization
    wrote with the `system` originator. Those rows carry no content; no
    agent should be issued the label `system`.
  - **Client ids.** The send's idempotency key is
    `message_send/<sender>/<id>` in the default organization and
    `org:<org>/message_send/<sender>/<id>` elsewhere, each part with `%`
    and `/` escaped, so an organization id containing `/` cannot spell
    another's prefix. The default key is byte for byte the earlier one
    only for a sender and client id without `%` or `/` (every validated
    label and client id); a verified identity whose label has one gets a
    new key, and its earlier receipts no longer replay. A pre-scoping `message_send:<id>` key replays only in
    the default organization. A receipt naming another organization's
    message is never replayed: the send is refused (`conflict`) and names
    neither.
  - **Unknown or suspended** organizations are refused
    (`unknown_organization`, `organization_suspended`) before any send,
    read mark or ack, and before a relay `cancel` or `resolve`.
  - **The relay** stays the default organization's: it posts with the
    hub's credential to the hub's repository allowlist under the hub's
    gates, so `check`, `draft`, `request_send` and `send` refuse another
    organization (`org_unsupported`). `status` (by draft or approval id),
    `list`, `cancel` and `resolve` read only the caller's organization's
    drafts, so another organization's draft answers exactly as a missing
    one. Another organization's relay event would carry no target, reason
    or error text and use `system`.
  - The importer writes legacy messages and receipts to `default`.
    `crates/ua-tools/tests/messaging_tenant.rs` holds the upgrade, the
    isolation through every reading tool, the session refusals, mail to a
    label registered elsewhere, the ledger redaction (message and
    conversation-handoff events, dedupe keys included), a legacy draft
    linked to another organization's approval (its status reports no
    approval; its cancel fails closed), the relay parity and the
    idempotency tests.
- The node registry, the node work queue and dispatch runs. **Design
  assumption (the owner may revisit it):** a node belongs to exactly one
  organization, the one that registered it (`nodes.org_id`, immutable);
  existing nodes go to `default`. A queued item, a supervised command, a
  claim operation, a follow-up and a dispatch run belong to the
  organization of the caller who created them, and may only target a node
  of that same organization: another organization's node answers exactly
  like an unregistered one (`not_found`, the same message), whether the
  caller queues work (`node_dispatch`, `node_command_start`), routes a run
  (`dispatch_task` with `node`) or acts on an item, follow-up or run. A node
  claims, heartbeats, reports and serves follow-ups only for its own
  organization's work: the device plane binds every call to the node
  token's organization (`Caller.org_id`), so a token of organization B never
  reaches a default node even under the same label. Hub-wide operator views
  stay default-organization only, plus counts: `system_doctor`'s fleet row
  names only the default organization's nodes and adds `other_org_nodes`
  (`{active, retired}`), `other_org_nodes_not_accepted` (nodes in service
  that take no real work while `node_require_acceptance` is on, named in
  the row's detail) and `other_org_unsent_command_notices`, and a provider
  account's recent runs list only the default organization's and add
  `other_org_runs`.
  **Hub recovery.** Node names are one hub namespace, so a name another
  organization registered (by mistake, or to squat it) would otherwise be
  stuck: its lifecycle operators are not admitted yet, and every operator
  action is scoped to the caller's organization. A default-organization
  lifecycle operator (`Authz` over `default`, which no other
  organization's caller holds) passes `any_org=true` to `node_retire` and
  `node_forget`: the node of whichever organization holds the name is
  retired, then forgotten, in that organization, through the ordinary
  retire and forget code (open work still refuses it, and a suspended
  organization's node is refused until it is active again). The ledger
  entry is that code's `node_queue::emit` in the node's organization, so
  another organization's node gets the `system` originator and only its
  ids, and the answer carries only `{node, org_id, changed, retired or
  forgotten, event_ulid, hub_recovery}`, none of the node's agent or
  history. `node_unretire` and `node_reassign` take no `any_org`, and
  without it every operator action stays in the caller's organization.
  `node_reassign` keeps a node in its organization: it refuses a
  `to_agent` of another one (`agent_org_mismatch`): an agent row there
  (`agents.org_id`, since the agents family converted), or for a label
  with no agent row, a node, node work or a dispatch run there.
  **Parts.** `organization.v1.tools.dispatch` gives `dispatch_runs` and
  `dispatch_receipts` `org_id` and the organization triggers;
  `dispatch.v4.org_scope` adds `idx_dispatch_runs_org_created`,
  `idx_dispatch_runs_org_task` and the `dispatch_runs_org_parent` and
  `dispatch_receipts_org_parent` triggers (and their `_update` twins): a run
  is in its task's organization and a receipt in its run's. The standalone
  procedure `node_queue.v2.tenant_keys` rebuilds `node_dispatch` with
  `org_id TEXT NOT NULL DEFAULT 'default'` and its client launch keys unique
  per organization (`idx_node_dispatch_launch_key` becomes
  `UNIQUE (org_id, launch_key) WHERE launch_key IS NOT NULL`), on the
  harness-config contract: it refuses to run inside a transaction, turns
  foreign keys off, rebuilds in one `BEGIN IMMEDIATE` (rolled back on any
  error), keeps every item's id and rowid (the queue orders by rowid), every
  other index, trigger and view, checks the row count,
  `PRAGMA foreign_key_check(node_dispatch)` and the trigger and view sets,
  and is crash-safe (`COALESCE(org_id, 'default')` for a column left by an
  interrupted run). `organization.v1.tools.nodes` then gives the other six
  node tables `org_id` and installs the organization triggers on all seven,
  and `node_queue.v2.org_scope` adds `idx_nodes_org_agent`,
  `idx_node_dispatch_org_node_status`, `idx_node_dispatch_org_created` and
  the `*_org_parent` triggers (and `_update` twins) that keep an item's
  node, task and run, an acceptance run's node and items, a claim
  operation's node and item, and a command's, a notice's (and its task's)
  and a follow-up's item in the row's own organization. **Nothing is
  dropped or rewritten:** every existing row lands in `default`, because no
  caller outside it could be authenticated before (`org_guard`), so no
  dropped-row record or doctor count is needed.
  **Keys.** Only the launch key needed the organization. `nodes.node` stays
  one hub namespace, like agent labels (a second organization registering a
  taken name is refused `node_owned_elsewhere`, which reveals only that the
  name is taken); `node_claim_ops (node, op_id)` is led by it; item,
  follow-up and run ids are hub-generated, and `node_followups (item_id,
  idempotency_key)`, `(item_id, seq)` and `node_command_notice (item_id,
  attempt, terminal)` are led by an item id. A launch-key retry replays
  only the caller's organization's item; the same key in another
  organization (including one whose id contains `/`) is a fresh item, never
  a replay or a conflict. The family stores no key in `idempotency_keys`.
  **Scoping.** Every statement filters `org_id`: `node_register` (the
  agent's node cap counts per organization; the upsert never updates
  another organization's row), `node_heartbeat`, `node_list`,
  `node_dispatch`, `node_items`, `node_claim` (the claim, the durable claim
  operations, the queued-work probe), `node_receipt`, `node_events`,
  `node_followups`, `node_followup`, `node_permission`,
  `node_session_credential`, every `coordination_manage` node action
  (retire, un-retire, reassign, forget, item cancel, restart and reconcile,
  command start, status and adopt, acceptance start, evaluate, status and
  attest), `dispatch_task`, `dispatch_report_self`, `dispatch_resume`,
  `dispatch_cancel` and the operator cancellation actions,
  `dispatch_delivery_receipt`, `dispatch_delivery_receipts_list`,
  `run_list` and `run_get` (dispatch and node kinds, and a session's node
  links), `capability_catalog`'s executor check, the hold and lifecycle
  stops, `task_claim_release`'s live-run check, the queue's open-work
  reasons and the harness config node lookups. The hub jobs with no caller
  (the node queue sweep, the dispatch lease reaper and startup sweep, an
  agent-wide lifecycle stop) span every organization and act on each row in
  its own organization. An organization `orgs` does not hold, or holds as
  suspended, is refused (`unknown_organization`,
  `organization_suspended`) before anything is read for a write, including
  writes with nothing to insert (a heartbeat, a cancel, a receipt).
  **Sites that stay default-only, and why.** (Session credentials and
  idle-session wakes were default-only here until the agents family gave
  their tables `org_id`; they now run per organization, below.) Device
  acceptance reads its evidence (the
  acceptance items' ACP events) back from the ledger, and another
  organization's node events keep no event data there, so it runs only for
  default nodes (`org_unsupported`); with `node_require_acceptance` on,
  another organization's nodes therefore take no real work until acceptance
  carries its own evidence store. Command notices go
  through the mailbox (`message_index`, no `org_id`), so another
  organization's notice stays recorded on its `node_command_notice` row,
  unsent; its owner reads the outcome with `node_command_status`.
  **Events.** `agent.node.*` and `agent.dispatch.transition` are
  `ORG-EVENT-DEFAULT` sites through `node_queue::emit`: for another
  organization the payload keeps only ids, states, attempts, fences,
  backends and counts (no node name, host fact, agent, actor, path, prompt,
  command, reason, note or output), the originator is `system`, and a
  dedupe key is built from hub-generated ids only and stored as
  `org:<kind>:<item id>:<attempt or ledger event id>` (the default
  organization's key, which can name a node or a turn, is unchanged). An
  unkeyed digest of the named key would let a ledger reader test a guessed
  node name, so neither the name nor a digest of it is stored; there is no
  hub secret to key one with. Another organization's turn summary is
  therefore deduplicated per recorded turn end rather than per node turn
  id. Both channels are ordinary visible ones (`VISIBLE_EVENT`
  restricts neither), which is why the payload is reduced. The provider
  account health keeps another organization's run id and quota line out of
  its row and its events. The importer writes legacy nodes to `default`.
  `crates/ua-tools/tests/nodes_tenant.rs` holds the upgrade (nothing
  dropped, rowids, view and launch-key uniqueness kept, the interrupted
  rebuild), isolation through every read path, cross-organization refusal
  with missing-node parity, the node-token claim test, the launch and
  follow-up key isolation (with an organization id containing `/`), the
  unknown and suspended refusals, the ledger leak test, the trigger checks
  and a family insert guard.
- The idempotency keys: the standalone `idempotency.v2.tenant_keys`
  rebuilds `idempotency_keys` with `org_id TEXT NOT NULL DEFAULT 'default'`
  and the primary key `(org_id, key)` (owner decision (a)), on the
  `managed_secrets` and `node_queue` contract: it runs outside the shared
  transaction with `foreign_keys` off, in one `BEGIN IMMEDIATE`, rolls back
  on any error, keeps rowids, every index, trigger and view (the table has
  no `AUTOINCREMENT`, so there is no `sqlite_sequence` row), checks the row
  count and `foreign_key_check`, and is safe to re-run after a crash
  (`COALESCE(org_id, <placement>)` keeps a stored organization). A `NULL`
  key, which `core.v1` allowed and no writer stored, stops the upgrade with
  its row ids. `organization.v1.tools.idempotency` then adds
  `idempotency_keys_org_exists` and `idempotency_keys_org_immutable`.
  **Row mapping.** Key text, tool, result and timestamp are kept byte for
  byte; only `org_id` is assigned. A row moves to organization O when its
  key starts `org:<O>/<tool>:` (the unescaped form `task_add`,
  `task_update`, `delegate` and the conversation handoff wrote) or
  `org:<O escaped>/<tool>/` (`memory_save` and `message_send`, `%` and `/`
  escaped), `<tool>` being the row's own `tool`, for exactly one
  organization O other than the default in `orgs`. Matching the whole
  organization part against `orgs`, rather than cutting at the first `/`,
  places an organization id holding `/`. Every other row lands in
  `default`: rows without a prefix (all the default organization's), a
  prefix naming an organization `orgs` does not hold, and a key two
  organizations spell (possible only in the unescaped form: `acme`'s key
  `z/task_add:k` and `acme/task_add:z`'s key `k` are both
  `org:acme/task_add:z/task_add:k`). **Nothing is dropped or rewritten**,
  so no dropped-row record is needed; the rows kept in `default` under an
  `org:` prefix are counted. No default-organization writer builds a key
  starting `org:` (the pre-scoping raw `memory_save` keys, read only for
  the note's own author in the default organization, are the one form that
  could, and stay where they were), so such a row never replays to anyone
  and ages out with the table. `system_doctor` reports the count as
  `database.idempotency_keys_unplaced` (and in the `database` row's detail
  when non-zero) to a default-organization reader only, since it is
  hub-wide; the rebuild's audit record (`schema_procedures.generated_sql`)
  names the row ids, never key text. A raw `memory_save` key that happened
  to spell another organization's prefix moves there and fails closed: its
  receipt names a default-organization note, so that organization's save is
  refused (`idempotency_key_conflict`), never replayed. **Prefix decision.**
  The writers keep the organization prefix in the stored key text (defence
  in depth), so the stored key is byte for byte what it was and a retry in
  flight across the upgrade replays its own receipt. Every reader filters
  `org_id` on the caller's organization (`task_add`, `task_update`, the
  conversation handoff, `delegate` and `delegation_manage lookup`,
  `memory_save`, `message_send` and its client-id lookups,
  `lifecycle_record`) and every writer names it, so a receipt is found only
  when both the column and the key text name the caller's organization; the
  column alone separates two organizations whose prefixes spell the same
  text. `lifecycle_record`'s key carried no organization and is now the
  caller's organization's; its pre-upgrade rows, prefixless in every
  organization, land in `default` (see CHANGELOG for the retry exception).
  No sweep deletes stored keys: the table, and the doctor's unplaced count,
  only grow. **Principals.** The `principal` column the
  earlier plan named is not added: the principal is already in the key text
  of every per-caller writer (`task_update` and `delegate` the escaped
  label, `memory_save` and `message_send` the escaped label or sender,
  `lifecycle_record` the session id, which the caller supplies and which is
  not checked against the caller, so two agents of one organization that
  send the same session, kind and key share one receipt, as before).
  `task_add` keys stay organization-wide,
  as before, so two callers in one organization sharing a `task_add` key
  share its receipt, and the conversation handoff's key is derived from
  its actor. `crates/ua-tools/tests/idempotency_tenant.rs` holds the
  upgrade (placement by prefix, an organization id with `/`, an unknown and
  an ambiguous prefix, every byte and rowid kept, index, trigger and view
  kept, the doctor count, no ledger row), pre-upgrade replays through the
  tools, the crash re-run, a nullable `org_id` kept or placed, the `NULL`
  key refusal, the same key in three organizations through `task_add`,
  `task_update`, `memory_save`, `message_send` and `delegate`, two
  organizations spelling one key, the lifecycle key, the triggers and a
  family insert guard.
- The agents and sessions family: `agents`, `agent_sessions`,
  `agent_tokens`, `agent_lifecycle`, `session_profiles`,
  `session_credentials`, `session_handoff_notes`, `session_wake` and
  `session_wake_offers`. **Design assumption (the owner may revisit it):**
  an agent belongs to exactly one organization, the organization of the
  token or grant it authenticates with ("the grant carries the
  organization"); existing agents go to `default`. Its sessions, profile
  bindings, session credentials, handoff notes and wake rows belong to that
  organization too. **Agent labels stay one hub-wide namespace**, as node
  names do, compared without regard to case: a label is held by the
  organization of its agent row, else of a lifecycle row for it, else of an
  active managed token for it, and any other organization registering it
  (a heartbeat, `session_start`, a profile binding, a token issue) is
  refused `agent_label_taken`, which reveals only that the label is taken.
  - **Hub recovery.** A default-organization lifecycle operator (`Authz`
    over `default`, which no other organization's caller holds) passes
    `any_org=true` to `agent_retire` and the new `agent_forget`: the agent
    of whichever organization's **row** holds the label (the rows, not the
    configuration reservation, so a stale row another organization keeps
    for a reserved label is reachable too) is retired (doing claims
    still refuse it; its managed tokens and session credentials, in its
    organization, are revoked, and so are its OAuth sign-ins when it is
    the default organization's: `oauth_grants` carries no organization
    yet, so every grant is the default's, and recovering another
    organization's row never revokes the default grant for the same label
    text), then forgotten (its agent row, lifecycle row and profile
    bindings deleted, so the label is free; its sessions, notes and revoked
    tokens stay in its organization as history), in that organization,
    through the ordinary code. The answer is only `{agent, org_id, changed,
    retired or forgotten, hub_recovery}`, and the ledger entries are that
    code's redacted events. Without `any_org`, a lifecycle action on a label
    another organization holds is refused as taken.
  - **Forget never revives a credential.** A retired agent's lifecycle row
    is what refuses its static configuration token, which cannot be
    revoked. So in the default organization `agent_forget` is refused
    (`agent_label_configured`) for a label hub configuration names (the
    reserved labels below); the operator removes it from configuration
    first. Another organization's stale row for a reserved label, reached
    only through hub recovery, is forgotten normally: that is what frees
    the label for the default credential again. A forget is also refused
    while the agent still owns a node in service (`agent_owns_nodes`): a
    node is keyed by its owner's label, so it would pass to whoever
    registers the label next; retire the nodes (`node_retire`) first. Refusing was chosen over a
    tombstone that `is_retired` would keep honouring: a tombstone leaves
    the label unusable for good, which is what forget exists to undo, and
    every credential path would have to read a second store. A forget also
    revokes, again, every managed token, OAuth sign-in and session
    credential issued for the label since the retire (`agent_forgotten`),
    so none comes back with the freed label. It deletes exactly one agent
    row: when two rows spell the label in different letter cases
    (`agents.label` is case-sensitive) it is refused
    (`agent_label_ambiguous`). The stops a lifecycle action requests (doing
    claims released or reported, node items cancelled, dispatch runs
    stopped) and a retire's doing-claim refusal read the agent's own
    organization only: another organization's task, item or run whose
    agent text matches the label is never this agent's work.
  - **Reserved labels** (the design below, "Reserved labels" and scenario
    17a). Every label hub configuration names is the default
    organization's: `human_identities`, `lifecycle_operators`, static
    token labels, the `[profiles]` map, the `agent_scopes` (prod-action
    scope) and `agent_workspaces` (sandbox root) maps, `revoked_agents`,
    `oauth_identities`, `oauth_client_credentials` identities, Slack
    identities, and the policy file's role identities (`agent:<label>` or a
    bare name; a `profile:<name>` entry names a profile) and
    `profile_defaults` keys, compared without regard to case
    (`agents::Reserved`). Every other `Config` map or list is keyed by
    something other than an agent label (harness, channel, check, project,
    MCP server, Zulip or GitHub user names). Reserving the label-keyed maps
    is what stops another organization's label from inheriting the default
    organization's settings for it: its own `agent_workspaces` root, or a
    prod scope that passes the merge or delete gate. While the policy file
    cannot be read or parsed its role labels are unknown, so the set fails
    closed: outside the default organization a label the organization does
    not already hold is refused (`policy_unavailable`) for registration,
    token issue, `session_start` and heartbeat, until the file is fixed;
    a label it already holds keeps working. The label
    namespace (`label_org`, `require_label_free`, `held_outside_default`)
    treats such a label as held by `default`: another organization's
    heartbeat, `session_start`, profile binding and token issue for it are
    refused as taken; a managed token or session credential of another
    organization for it never authenticates; and the default
    organization's static token, OAuth grant, Control Center session and
    Slack identity for it always authenticate. **Not yet built** from the
    design: who inside the default organization may create a reserved
    label's row (any default writer still may), and the `system_doctor`
    `MISCONFIGURED` report for a label added to configuration while
    another organization already holds a row for it. Such a row (only
    possible if it predates the reservation) is **not** harmless: its own
    tokens and credentials are refused and its writers are refused as
    taken, but `agents.label` is the table's key, so while it exists the
    default credential for the label records nothing either
    (`session_start` is refused `agent_label_blocked` and `agent_heartbeat`
    answers `recorded: false`). A default-organization lifecycle operator
    removes it with hub recovery, `agent_retire` then `agent_forget`, both
    with `any_org=true`, without touching configuration. Between the two
    the label reads as retired hub-wide (`is_retired` is not organization
    aware), so the default credential is refused until the forget.
  - **No workspace outside the default organization yet.** The hub's
    workspace root and read roots are the default organization's. Every
    workspace tool resolves its sandbox through `workspace::sandbox`
    (`fs_*`, `run_cmd`, `run_cmd_check`, `git_*`, the worktree tools, the
    code index, lint, media and dev-server tools, export's workspace
    target), and outside the default organization it is refused
    (`org_unsupported`) before any filesystem access. An `agent_workspaces`
    entry never applies there: its key is a reserved label, the default
    organization's, even when another organization's caller carries the
    same label text. The tools that read the
    hub workspace directly fail the same way (`skill_registry` publish and
    drift, and the `security_audit` and `skill_review` targets), `capability_catalog` lists no
    workspace skills to another organization, and an autonomous cycle of
    another organization is held for a human before its worktree is read
    or the validation command runs. The vault is the hub's too: every
    `vault_*` tool (through `vault::vault`), every `obsidian_*` tool
    (before any request reaches the plugin, configured or not),
    `memory_promote`, `vault_to_memory_ingest` and `export_journal` refuse
    another organization's caller (`org_unsupported`) before a path is
    resolved, and its learning-proposal preview (`dry_run`) reads no vault,
    so it never learns whether a proposal or an earlier one exists there.
    The Dash docsets (`dash_list`, `dash_search`, `dash_view`) are refused
    (`org_unsupported`) before `dash_docsets` is read. `system_doctor`
    gives another organization one neutral `vault` line and one neutral
    `workspace_root` line ("not available to this organization", the same
    whatever the hub holds) and never runs either check for it. A local
    harness (`dispatch_task` or `dispatch_resume` with a harness) is a
    process on the hub and is refused (`org_unsupported`) before the
    harness is looked up or a task's `worktree_path` is resolved, and
    every downstream MCP server, stdio or Streamable HTTP, is refused for
    `mcp_gateway` `call` and live `list` (above). A `worktree_path` another
    organization records through `task_claim` or `session_start` is stored
    as given: it is data in that organization's rows, and every tool that
    would treat it as a path on the hub (the local harness, the `git_*`
    task tools through `workspace::sandbox`, the crew drop file, an
    autonomous cycle's worktree read) refuses another organization first;
    a node route resolves it on the node, which serves the default
    organization only. So until per-organization workspaces and vaults
    exist, another organization has no hub filesystem at all: no
    workspace, vault, Obsidian, docset, local harness or MCP server
    process, and no report of their state. (The hub's configuration files
    are read on every organization's behalf, as configuration: the policy
    file, and the workflow definitions in `workflow_dir`, whose steps each
    run through the registry under these same refusals.)
  - **No human or operator path outside the default organization yet.**
    Human identities and lifecycle operators are hub configuration, the
    default organization's, and no resolver produces a verified human of
    another organization until memberships exist. So in another
    organization no one can grant an idle-session wake, revoke a credential
    as an operator, issue or rotate a managed token, or resolve a
    `crew_intervene` park; those paths are organization-scoped and tested
    with a hand-built caller (`unreachable_b_human` in
    `agents_tenant.rs`) so they stay correct when memberships land.
  - **Parts.** `organization.v1.tools.agents` gives the nine tables `org_id`
    and the generated triggers; `agents.v2.org_scope` adds
    `idx_agents_org_seen`, `idx_agent_sessions_org_agent`,
    `idx_agent_sessions_org_started`, `idx_agent_tokens_org_label`,
    `idx_session_credentials_org_agent` and
    `idx_session_handoff_notes_org_session`, and the `*_org_parent`
    triggers (and `_update` twins) that keep a session's agent and task, a
    token's, a lifecycle row's and a profile binding's agent, a session
    credential's agent, node and item, a handoff note's session, and a wake
    row's and a wake offer's session and node in the row's organization (a
    reference to no row passes, as in the earlier families). Both are
    registered after the node parts, whose tables the triggers read. **No
    key is rebuilt**: `agents.label` and `agent_lifecycle.agent` are the
    label namespace, a session id is a hub-generated ULID, a token or
    credential digest is a digest of a random secret, a credential id and
    an offer id are random, a note's key is an AUTOINCREMENT id,
    `session_wake` is keyed by its session id, and `session_profiles
    (identity, session_key)` is led by a label. The upserts keyed by
    a label or a session id (`agents`, `agent_lifecycle`, `session_wake`,
    `session_profiles`) carry `WHERE <table>.org_id = excluded.org_id`, so
    a collision with another organization's row changes nothing, and is
    refused as a taken label where it can arise. **Nothing is dropped or
    rewritten:** every existing row lands in `default`, so no dropped-row
    record or doctor count is needed.
  - **Resolution.** The HTTP resolver binds every caller to its
    credential's organization (`AuthIdentity::org_id`, then `caller_for`):
    a managed token to `agent_tokens.org_id`, refused when its agent
    (`agents.org_id`) is in another organization; a node session
    credential to `session_credentials.org_id` (its item's); a static
    configuration token, an OAuth grant (which carries no organization yet)
    and a Control Center session to `default`, each refused (as is a Slack
    identity's command) while another organization holds its label, which
    a reserved label never is. A token is issued in
    the issuer's organization and refused for a label another holds. The
    CLI issues default tokens. Profiles: the hub configuration's
    `[profiles]` map is the default organization's; another organization's
    agent gets `developer` until agents carry a default profile, and its
    `profile_activate` binds in its own organization only.
  - **Scoping.** Every statement filters `org_id`: `agent_heartbeat`,
    `agent_list`, `agent_context`, `session_start`, `session_end`,
    `session_list`, `lifecycle_record`, `profile_status`,
    `profile_activate`, `profile_reset`, `agent_token_issue`, `_rotate`,
    `_list`, every agent lifecycle action and read, `session_packet`,
    `crew_view`, `crew_intervene`, `propose_session_learnings`, the
    handoff-note actions, the wake actions and device-plane calls, the node
    session credential mint, verification, slide and revocation, the
    session links of `run_list` and `run_get`, `platform_object_get`'s
    `agent` and `session` kinds, `capability_catalog`'s known-label and
    token checks, the observability token count, the mailbox's session
    checks, memory's `source_host` and the handoff rows of `VISIBLE_EVENT`.
    Another organization's agent or session answers exactly as a missing
    one (a lifecycle observation naming another organization's session is
    recorded with no session). `agent_context` returns the hub's
    `workspace` path to the default organization only (`null` elsewhere). A
    node session credential is refused on use (`org_mismatch`) unless its
    organization is the one holding its subject's label, as a managed
    token is. An unknown or suspended organization is
    refused (`unknown_organization`, `organization_suspended`) before any
    write. The session reaper is a hub job: it reaps every organization's
    sessions, each in its own, ledgered per organization with ids only.
    The claim gate's and the HTTP adapter's lifecycle reads stay keyed by
    label alone, since a label is one organization's.
  - **Carve-outs lifted.** `messaging`'s `cross_org_recipient` and
    `require_default_sessions` (a session is addressed inside its own
    organization; another's answers as missing); `crew_view` and
    `crew_intervene` refusing other organizations (they work in the
    caller's); session credentials (minted for any organization's ACP item,
    the credential is that organization's, and its requests run there);
    idle-session wakes (`WAKE_ORG` is gone: a node token polls, checks and
    reports its own organization's sessions through its own nodes, and the
    consent actions act on the caller's organization's sessions; a grant
    still needs a verified human, so none happens outside the default
    organization until memberships exist); owner decision (c) for
    delegations (now fail-closed and registered agents only, above); and
    `node_reassign`'s
    `agent_org_mismatch` (now `agents.org_id` first). **Kept, and why:**
    device acceptance (its evidence is read back from the ledger, where
    another organization's node events carry no data) and command notices
    (sent through the hub's `hub-node` mail as the default organization's)
    stay default-only; a learning proposal is written to the hub's vault
    and a crew drop file to the hub's workspace, both the default
    organization's, so another organization may only preview a proposal
    (`dry_run`) and its crew interventions write and read no drop file.
  - **Events.** The agents family's events go through `agents::emit`
    (`ORG-EVENT-DEFAULT`): for another organization, labels, hosts,
    branches, worktree and transcript paths, external session ids, kinds,
    exit statuses, reasons and actors are `null`, the originator is
    `system`, and no dedupe key built from a label is stored; a lifecycle
    observation keeps only its kind, its own session id and the task id;
    a handoff-note event and a wake event keep only ids, states and
    counts. `lifecycle_record` idempotency keys are the caller's
    organization's through the `(org_id, key)` table (the idempotency keys
    family above), in the same `lifecycle:<session>:<kind>:<key>` form in
    every organization.
  - The importer writes legacy agents, tokens and handoff notes to
    `default` and never copies a source `org_id`.
    `crates/ua-tools/tests/agents_tenant.rs` holds the upgrade (nothing
    dropped, every row in `default`, triggers present, idempotent re-open),
    isolation through every read path with missing-row parity, the token
    resolution and mismatch refusal, the label namespace and hub recovery,
    the handoff, lifecycle, session-credential, wake and delegation
    behaviour per organization, the `node_reassign` refusal, the unknown
    and suspended refusals, the trigger checks, the ledger leak test and a
    family insert guard; `crates/ua-server/tests/org_tokens.rs` checks the
    HTTP path.
- The insert guard ([guard 2](#organizationv1)): a test fails when an
  `INSERT` into a tenant table that carries its key does not name `org_id`,
  in any crate's non-test source or any trigger body. See
  [Converting a table family](#converting-a-table-family). A released,
  checksum-locked part whose trigger a later part recreates naming `org_id`
  is excused by its exact text (today only `memory_versions.v1`); the live
  trigger is still checked.

Not yet: the tenant parts for the other families, the label index,
`hash_v = 2`, and everything after `organization.v1`.

## Decision

The organization is the structural partition key, and it exists from the first
release: `org_id` is `NOT NULL` on every tenant-scoped table, with one seeded
default organization, so a single-organization hub behaves exactly as it does
today and a second organization needs no further migration.

The alternative — ship single-tenant and add tenancy when a second tenant
appears — was considered and rejected. A partition key added after the tables
exist is a retrofit across every query path, every approval binding and every
audit read. That retrofit is the reason the predecessor implementation filed
organization-as-partition-key and never finished it.

An organization holds **people and agents together**. A hub that serves a
company has to know which humans belong to which team, because approvals,
reviews and escalation belong to a team's lead, not to one global operator
list. People are first-class rows, not configuration.

There are three levels of authority, and every rule below names one:

| Level | Who | Examples |
|---|---|---|
| **Hub** | Hub owners (below) | Create and suspend organizations, hub-wide policy, MCP servers, provider accounts, the vault, credentials that cross organizations |
| **Organization** | Members by role (`org_owner` … `auditor`) | Memberships, teams, specs, secrets, tokens, settings, the organization's approvals |
| **Team** | A team's human leads | The team's own routed approvals and narrowing changes |

## What exists today

| Concept | Where | What it actually is |
|---|---|---|
| Profiles | `ua-core/src/profiles.rs`, `profiles.json` | A **capability overlay**. Decides which tools a session can see. Ten profiles: `public`, `remote-assistant`, `remote-vault-curator`, `research`, `acp-session`, `operator`, `reviewer`, `developer`, `lead`, `coordinator`. `Profile::rank` orders them for display only; it does **not** order capability (`operator`, rank 4, sees `approval_resolve`, which `lead`, rank 7, does not). |
| Agents | `agents` table | A **flat roster** of identity labels (`label` is the primary key). No owner, no reporting line, no grouping. |
| Organization | — | **Does not exist as a concept.** Verified at `28fdf58`: `Caller` has no organization, and no tool scopes by one. Two tables already carry a nullable, unused `org_id`: `harness_config_bundles` and `harness_config_proposals` (`harness_config/mod.rs`). |

Humans exist only as configuration. `human_identities` in `ua-core/src/config.rs`
is a flat list of labels; `Config::is_human` checks membership. The paths that
decide `ActorKind::Human` or refuse a human are:

- `ua-server/src/auth.rs` (bearer tokens; OAuth access tokens are refused for
  human subjects);
- `ua-server/src/login.rs` (login links, passkey start, registration, session
  lookup);
- `ua-server/src/oauth/authorize.rs` and `oauth/token.rs` (a human may not be
  an OAuth subject);
- `ua-server/src/compat_api.rs` (a local `fn is_human` over the identity);
- `ua-server/src/events.rs` (UI sessions on the event stream are human);
- `ua-cli/src/main.rs` (a local `--label` naming a human, after confirmation).

Any listed human can approve any gated action: `approvals.rs::resolve` checks
only `caller.is_human()` and that the approver is not the requester. Beyond
approvals, `is_human()` / `cfg.is_human()` is the authority test at 45 call
sites in 26 `ua-tools` files — token minting, secret administration,
governance, node operations, MCP servers, GitHub authorization and more —
and a few checks grant authority by profile or by `is_lifecycle_operator`
instead.

`Caller` (`ua-core/src/identity.rs`) carries `label`, `kind`, `profile`,
`enforce_profile`, `session_key` and `transport`.

`goal_manage` **refuses** a `params.org_id` today (`invalid_argument`, asserted
in `ua-tools/tests/tasks.rs`), because its parameter structs deny unknown
fields. That stays: the organization never comes from tool arguments.

`ua-import` never copies `org_id` as a column on any table (including
`harness_config_bundles`, `work_proposals`, `work_proposal_items`, `task_holds`,
and `project_repo_bindings`): any non-NULL `org_id` rows are reported in
`org_scoped_rows` and refused unless `--drop-org-scope` is passed (which drops
the tenant boundary and leaves target `org_id` NULL on tables that carry the
column). See [The importer](#the-importer) for the multi-tenant import design when org
columns are introduced.

## The model

All of it is data rather than configuration, because the product promise is
that an operator can define their own organization at runtime and have that
definition audited.

```
users (global identity) ──┐
                          │ org_memberships (role)
orgs ─────────────────────┼── offices          (named capability scopes inside an org)
                          ├── teams            (groupings of people and agents; archived, never deleted)
                          │     ├── team_members  (principal_type human | agent, lead | member)
                          │     └── team_specs    (versioned, executable: seats, edges, budgets)
                          ├── reporting        (supervisor edges, temporal, informational)
                          ├── org_proposals    (self-organization, human-gated)
                          └── agents, tasks, memory, approvals, ...   (the tenant-scoped set)
```

- **user** — a human identity. Global, like a passkey: one person can belong to
  several organizations.
- **org membership** — a user's role in one organization (see [People](#people)).
- **org** — the tenant boundary, with its settings. Created and suspended only
  by hub owners; never deleted.
- **office** — a named role scope within an org, carrying the set of capability
  profiles its agents may hold. Offices are runtime data, never a fixed enum.
  It is not an HR job title.
- **team** — a many-to-many grouping of people and agents, used for approval
  routing, memory visibility and task ownership.
- **team spec** — the executable definition of how a team's agent seats start,
  who they may interact with, and what they may spend.
- **reporting** — a temporal supervisor edge. Informational in v1: it answers
  "who reported to whom in March" and draws the org chart; no authority is
  derived from it.
- **agent owner** — an agent may name the human it acts for
  (`agents.owner_user_id`). Memory uses it to decide which agent may summarize
  that human's private notes; nothing else derives authority from it.

**One label namespace.** Agent labels and user labels share one hub-wide
namespace, compared **case-insensitively** (as `agent_lifecycle.agent` already
is). Today `agents.label` is a case-sensitive primary key, so `Builder-1` in B
could coexist with `builder-1` in A and then overwrite A's NOCASE
`agent_lifecycle` row. `organization.v1` therefore adds a unique index on
`agents(label COLLATE NOCASE)`, after a pre-check that refuses to apply the
part and lists any existing case-collisions for the operator to resolve; the
writers for `agents` and `users` — including `touch_agent`'s auto-create on
first contact — each refuse a label the other table holds in any case. Labels
are identifiers, not secrets; creating either is admin-gated, so the existence
of a label is not treated as confidential.

**Reserved labels.** Every label named in hub configuration —
`human_identities`, `lifecycle_operators`, static `UA_AGENT_TOKENS` labels and
the `[profiles]` map — is **reserved**. A reserved label's row may be created
only in `'default'`, and only by a hub owner, by that label's own verified
credential resolving to `'default'`, or by a local stdio or CLI caller on the
hub host (which already carries hub-host trust, see Resolution). The check
keys on the transport (`Transport::Stdio` / CLI), never on
`ActorKind::Anonymous`, because anonymous HTTP with `enforce_auth` off has the
same actor kind and must stay refused. So a
static-token, `[profiles]` or local agent's first `session_start` or heartbeat
still creates its own row, exactly as today. Every other writer — a tenant
admin, an unverified remote caller, `touch_agent` acting for anyone else —
refuses it in any letter case. A tenant
admin therefore cannot pre-create a row for a label the hub's own config will
later trust, and the config's trust never lands in a tenant. Reservation is
checked at write time, so a label added to the config after an organization
other than `'default'` already holds it is reported `MISCONFIGURED` by
`system_doctor`, and the hub keeps starting but does not grant that label any
configured authority (static token, lifecycle operator, hub owner) until the
operator resolves it — the same treatment as Bootstrap's unadopted row. Rows in
`'default'` are not a conflict; that is where reserved labels belong.

## People

```sql
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    label        TEXT NOT NULL UNIQUE COLLATE NOCASE,  -- the label credentials carry
    display_name TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active','suspended')),
    bootstrap    INTEGER NOT NULL DEFAULT 0 CHECK (bootstrap IN (0,1)),
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS org_memberships (
    org_id   TEXT NOT NULL REFERENCES orgs(id),
    user_id  TEXT NOT NULL REFERENCES users(id),
    role     TEXT NOT NULL
             CHECK (role IN ('org_owner','org_admin','team_lead','member','auditor')),
    profile  TEXT,                 -- session profile in this org; NULL = 'reviewer'
    consolidate_private INTEGER NOT NULL DEFAULT 0
             CHECK (consolidate_private IN (0,1)),  -- set only by the member themselves
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS org_bootstrap (
    label      TEXT PRIMARY KEY COLLATE NOCASE,  -- a human_identities label synced once
    synced_at  TEXT NOT NULL
);
```

`users` is global, like `passkeys`; `org_memberships` is the tenant-scoped
grant. A role decides **which rows and which approvals** a person has authority
over.

| Role | Authority inside the organization |
|---|---|
| `org_owner` | Everything `org_admin` can do, plus granting and removing `org_owner` and changing owner-only settings. The last owner cannot be removed or demoted. |
| `org_admin` | Manage memberships below owner, teams, offices, team specs, budgets, settings, the organization's secrets, agent tokens and nodes. Approve approvals whose required authority is `org_admin` or `team_lead`. |
| `team_lead` | Approve approvals whose required authority is `team_lead` and that are routed to a team they lead ([Approvals](#approvals-routed-by-team)). |
| `member` | Belong to teams and request approvals. No approval authority. |
| `auditor` | Read the organization's ledger, approvals and audit exports. Cannot approve, deny, revoke, write or resolve anything. |

### Hub owners

A **hub owner** is a label listed in `human_identities` **whose `users` row was
created by the bootstrap** (`users.bootstrap = 1`). Only the bootstrap sets that
flag. Binding hub authority to a bootstrap-created row, not to the label alone,
means a row a tenant admin created — and every credential issued for it — can
never become a hub owner by having its label added to the config later.

### Who is a human

A verified credential is human when its label is:

1. a hub owner; or
2. an `active` user with a membership in an `active` organization; or
3. an `active` user whose only memberships are `org_owner` or `auditor` in a
   **suspended** organization — signed in **read-only**, so owners and
   auditors can still inspect a suspended tenant.

This replaces the config-only test at every path listed above. OAuth grants
remain never-human. A local CLI or stdio caller with `--label` runs on the hub
host itself, so a human label there carries **hub-host trust**, equivalent to a
hub owner; this is stated, not hidden, and unchanged from today's confirmation
prompt.

**User status.** Only hub owners suspend or reactivate a `users` row, because
the row is global. An organization's admins remove that person's membership
instead; that affects their organization only.

### Credentials for people

- A credential for **another** human — a login link, a passkey-registration
  invite, or a token on a human label — always needs an approval from a
  different eligible human (two-person). The required authority is
  `org_admin` in the issuer's organization, and **`hub_owner`** when the target
  user holds any membership outside that organization or is a hub owner. So a
  tenant admin who adds someone else's user to their organization cannot then
  sign in as them.
- **Adding** an existing user who holds a membership in another organization,
  or who is a hub owner, is itself two-person with required authority
  **`hub_owner`**. This closes the reverse path: B's admins cannot create a
  user (perhaps under an expected label), give it credentials, and wait for A's
  admin to add "the same person" to A, because that addition needs a hub owner
  who sees the user's other memberships and credential issuers.
- `agent_token_issue` and the managed-token tools refuse any label that is a
  `users` label or listed in `human_identities`; agent tokens are for agents.
- Granting `team_lead`, `org_admin` or `org_owner` is also two-person, with
  required authority `org_admin` (`org_owner` for granting `org_owner`).
- Exemptions: the bootstrap, and grants or credentials **requested by a hub
  owner**, because a hub owner already controls the hub's configuration and a
  second approver adds nothing. Each is still recorded on the ledger.
- Every credential issued for a user records the issuer and the user id.

### Bootstrap and single-operator parity

`human_identities` is the hub-owner list and the bootstrap source. On start,
for each listed label with no `org_bootstrap` row:

- if no `users` row has that label (case-insensitive), create one with
  `bootstrap = 1`, an `org_owner` membership in `'default'`, and the
  `org_bootstrap` row — **once**;
- if a `users` row already exists that the bootstrap did not create, **do not
  adopt it**: that label is not a hub owner, and `system_doctor` reports the
  hub-owner row `MISCONFIGURED` naming the label. The operator resolves it on
  the hub host with `ua org adopt-owner <label>` (hub-host trust), which
  revokes every credential issued for that row, sets `bootstrap = 1` and
  records the adoption on the ledger.

In the same transaction the bootstrap calls the memory re-own hook for the new
user. The hook, and the `memory.owner_type` column it writes, belong to the
memory scope PR (`docs/memory.md`, `MemoryRepo::reown_for_user`); before that
part has applied no hook is registered and the call does nothing. The step is
idempotent.

A later explicit removal of the membership is respected: the `org_bootstrap`
row is the tombstone, so a restart does not re-promote. Removing a label from
the config removes hub-owner authority, not the membership.

A hub with one configured human therefore behaves exactly as today: that human
is a hub owner and owns the default organization.

## Organization settings

Settings are columns on `orgs`, changed only through `org_settings_update`,
which records an `agent.org.settings` ledger event with the old and new values:

| Setting | Default | Who changes it |
|---|---|---|
| `allowed_profiles` | `'default'`: all ten; new orgs: `public`, `remote-assistant`, `research`, `acp-session`, `reviewer`, `developer`, `lead` | hub owners only |
| `memory_default_visibility` | `'private'`; `'org'` for `'default'` | `org_admin` |
| `self_organization` | on | `org_admin` |
| `proposal_daily_limit` | 10 | `org_admin` |
| `memory_consolidator_label` | none | `org_admin`; must be an agent of the org |
| `allow_remote_embedder` | off | `org_owner` |

## Authority checks

Raw `is_human()` checks are replaced by one module, `ua-org::authz`, used by
every tool and every adapter:

```rust
enum Authority<'a> {
    HubOwner,
    LifecycleOperator,                        // hub configuration; crosses organizations
    OrgRole { min: Role },                    // in the target row's organization
    TeamLead { team_id: &'a str },            // a human lead of that team
    Requester { approval_id: i64 },
}
fn require(caller: &Caller, need: &[Authority], target_org: &str) -> UaResult<()>;
```

Every check names the organization of the **target row** and fails when it
differs from the caller's, except `HubOwner` on hub-scoped tools and
`LifecycleOperator`, which are hub authority by definition.
`LifecycleOperator` holds only when the caller's label is in
`lifecycle_operators` **and** is either an agent whose row is in `'default'` or
a hub-owner user — never a same-named row a tenant created (reserved labels make
that row impossible to create, and this check makes it useless if it existed).

**The guard test** scans **every workspace crate except `ua-org`** and fails on
any of these outside `authz`: a call to `is_human(` or `is_lifecycle_operator(`,
a definition of `fn is_human`, and a `match`/`matches!` on `caller.profile` used
as an authority decision. Known sites the implementation must move include
`compat_api.rs`'s local `is_human`, `capability.rs` (hub boundaries shown to
the `operator` profile), `dispatch/tools.rs`, `vault_move`, `messaging.rs`,
`config_revisions.rs`, `nodes.rs`, `node_queue/command.rs`,
`continuity/mod.rs`, and in `crates/ua-memory` (extracted by #49) the
`fn is_human` in `note.rs` and its uses in `lifecycle.rs` (delete, restore,
privileged fields). `ua-core` is the one other exemption: it defines the
primitives (`Caller::is_human` in `identity.rs`, `Config::is_human` and
`Config::is_lifecycle_operator` in `config.rs`) and tests them; the guard
allows those definitions and `ua-core`'s own unit tests, and nothing else.

**Tool scope.** Each registered tool declares `scope: Hub | Tenant`, an
approval authority class, and whether its approvals are `team_routable`. A
hub-scoped tool is callable only by callers in `'default'` — agents and humans
alike — and its approvals need a hub owner.

Initial mapping of today's call sites (the implementation PR classifies every
site; this table is the rule it follows):

| Module | Scope | Required authority | Team-routable |
|---|---|---|---|
| `approvals.rs` | Tenant | [Approvals routed by team](#approvals-routed-by-team) | — |
| `families/tokens.rs` | Tenant | `org_admin`; target agent in the caller's org; human credentials per [Credentials for people](#credentials-for-people) | no |
| `families/managed_secrets.rs` | Tenant | `org_admin` | no |
| `families/governance/*` (claim release, proposals, operator actions) | Tenant | `org_admin` | claim release only |
| `families/node_queue/*`, `families/dispatch` | Tenant | `org_admin` of the node's organization; retire/unretire also hub owners and `lifecycle_operators` | dispatch only |
| `families/tasks/write.rs` | Tenant | `member`; setting `tasks.team_id` per [Routing](#approvals-routed-by-team) | — |
| `families/messaging.rs`, `families/continuity/*` | Tenant | `member` | — |
| `families/memory/*` | Tenant | `member`; `broadcast` and salience above 0.8 need a verified human with `org_admin` or above | — |
| `families/routines.rs`, `families/wake.rs` | Tenant | the owner, or `org_admin` | — |
| `families/capability.rs` | Tenant | any role, for its own organization; hub boundaries only to hub owners | — |
| `families/mcp/*`, `families/github/authz.rs`, `families/vault/*`, `families/zulip.rs`, `families/relay/*` | Hub | hub owner | no |
| `config_revisions.rs`, `families/harness_config` publish of hub-wide surfaces | Hub | hub owner | no |
| team spec commit, `team_up`, proposal apply | Tenant | `team_lead` for narrowing changes and `team_up`, else `org_admin` | yes |

**`lifecycle_operators`** stays hub configuration. Its members are hub-level
operators who may act across organizations; `require()` admits them through
`Authority::LifecycleOperator` (bound to a `'default'` agent row or a hub-owner
user, above), and the list is edited only by whoever controls the hub's config
file. An organization's own `org_admin` has lifecycle
authority over that organization's agents and nodes only.

**Profiles.** A profile decides which tools a session sees; a role never does,
with one stated exception: `approval_pending` and `approval_resolve` are
visible to a verified human holding an approving role (`team_lead` or above)
whatever their profile, so a tenant's leads can act on their approvals.
Session profiles come from:

- `'default'`: the hub config's `[profiles]` by label, as today (parity);
- other organizations, agents: `agents.default_profile` (set by `org_admin`),
  else `developer`;
- other organizations, humans: `org_memberships.profile`, else `reviewer`.

Every profile assigned in an organization — session, office, seat, agent
default, membership — must be in its `allowed_profiles` set. A set, not a rank
ceiling, because rank does not order capability.

**Organizations.** `org_create` (which names the first `org_owner`, an existing
user) and `org_suspend` / `org_reactivate` are hub-scoped and need a hub owner.
A suspended organization's callers are refused every tool with
`org_suspended`, except read tools for its `org_owner` and `auditor` members;
scheduled jobs skip it and its nodes take no work.

## Schema

Released schema parts are immutable; `ua-store/src/schema.rs` refuses to apply a
changed part and requires a new one. The organization model lands as **several
steps**, one per implementation PR, in this order:

| Step | Contents |
|---|---|
| `organization.v1` | `orgs`, `org_id` columns with immutability and existence triggers, `hash_v`, the case-insensitive agent label index, the recreated `memory_versions_capture` trigger, the `node_dispatch` launch-key index, the classification test, the importer exclusion, `Caller.org_id` |
| `organization.v1-rebuild` | the tables whose keys must change ([Global keys](#global-keys-and-table-rebuilds)) |
| `organization.v2` | `users`, `org_memberships`, `org_bootstrap`, agent owner and profile columns, `authz` |
| `organization.v3` | `offices`, `teams`, `team_members`, `reporting`, `team_specs` |
| `organization.v4` | approval routing columns and their same-organization team triggers |
| `organization.v5` | `org_proposals` |

Teams come before approval routing because routing (`task_team`, rule 3b) and
its `tasks_team_same_org` / `approvals_team_same_org` triggers read `teams` and
`team_members`. The memory parts (`docs/memory.md`) follow `organization.v1`;
team visibility needs `organization.v3`.

**Parts per table family.** Tenant tables are created by several crates
(`ua-tools`, `ua-memory`, `ua-import`, …), and a crate's own test database
applies only that crate's parts, so one part that `ALTER`s every crate's tables
would fail there with "no such table". Each step is therefore a set of parts,
one per owner: `ua-store` owns `organization.v1.store` (`orgs`, the seed, the
`event_log` columns), and each table family declares
`organization.v1.<crate>.<family>` for its own tables (`organization.v1.<crate>`
when the crate is one family, as `ua-ingress` is). The unit is the family,
not the crate, because a generated part's checksum covers its table list, so a released part can never take another family's tables: families are converted one at a time, and
a per-crate part released with the first family could not grow. All of them are produced by one
helper, `ua_store::org::tenant_part(owner, tables)`, which emits the `ADD
COLUMN`, the generated `org_exists` / `org_immutable` triggers and the
backfills for exactly the listed tables, so the rules are written once.

**Two part kinds.** `SchemaPart` today is a static `name` and `sql`. It becomes:

| Kind | Body | Checksum covers |
|---|---|---|
| `Static` | a `&'static str` of SQL | that SQL, as today |
| `Procedure` | a named Rust function and an explicit `version` number, run with a connection (and, if flagged `standalone`, outside the shared transaction) | the part name, the `version` and the procedure's static arguments (for a tenant part, its table list) |

An applied procedure is checked by name, `version` and arguments only, because the SQL it
generates may depend on the database it ran on; that generated SQL is stored
beside the checksum for audit and is never regenerated or compared on later
starts. A procedure that changes must bump its `version`, which makes it a new
part, so immutability holds for both kinds. The seed (whose timestamp is bound from
`ua_core::time::now()`), the helper-generated tenant parts and the rebuild are
procedures; the rebuild is the only `standalone` one.

`schema::apply` today runs every pending part in one `BEGIN IMMEDIATE`
transaction. It changes so that a `standalone` part runs **alone**: the pending
parts before it are committed first, the standalone part runs its own procedure
([below](#global-keys-and-table-rebuilds)), and the parts after it resume in a
new transaction.

### `organization.v1`

```sql
CREATE TABLE IF NOT EXISTS orgs (
    id                        TEXT PRIMARY KEY,
    slug                      TEXT NOT NULL UNIQUE,
    display_name              TEXT NOT NULL,
    status                    TEXT NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active','suspended')),
    allowed_profiles          TEXT NOT NULL
        DEFAULT '["public","remote-assistant","research","acp-session","reviewer","developer","lead"]'
        CHECK (json_valid(allowed_profiles) AND json_type(allowed_profiles) = 'array'),
    memory_default_visibility TEXT NOT NULL DEFAULT 'private'
                              CHECK (memory_default_visibility IN ('private','team','org')),
    self_organization         INTEGER NOT NULL DEFAULT 1 CHECK (self_organization IN (0,1)),
    proposal_daily_limit      INTEGER NOT NULL DEFAULT 10 CHECK (proposal_daily_limit > 0),
    memory_consolidator_label TEXT,
    allow_remote_embedder     INTEGER NOT NULL DEFAULT 0 CHECK (allow_remote_embedder IN (0,1)),
    created_at                TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS orgs_no_delete BEFORE DELETE ON orgs
BEGIN SELECT RAISE(ABORT, 'organizations are suspended, never deleted'); END;
```

SQLite permits `ADD COLUMN ... NOT NULL` only with a constant default, which is
exactly the behaviour wanted: every existing row is backfilled atomically with
the default organization. (`ADD COLUMN` cannot also carry `REFERENCES` with a
non-NULL default while foreign keys are on, so existence is guarded by
triggers.) The seed timestamp is bound by the migration code from
`ua_core::time::now()`, so it has the storage form; the literal below is only
for the SQL check.

```sql
INSERT OR IGNORE INTO orgs (id, slug, display_name, status, allowed_profiles,
                            memory_default_visibility, created_at)
    VALUES ('default', 'default', 'Default organization', 'active',
            '["public","remote-assistant","remote-vault-curator","research","acp-session","operator","reviewer","developer","lead","coordinator"]',
            'org', '2026-01-01T00:00:00+00:00');

ALTER TABLE tasks ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE tasks ADD COLUMN team_id TEXT;            -- owning team, nullable
ALTER TABLE approvals ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE agents ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE agent_tokens ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE oauth_grants ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE ui_sessions ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE memory ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE memory_versions ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE memory_embeddings ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
UPDATE harness_config_bundles SET org_id = 'default' WHERE org_id IS NULL;
-- ... one ADD COLUMN org_id per remaining tenant table (see Scoping per subsystem)

-- generated for every tenant table:
CREATE TRIGGER IF NOT EXISTS tasks_org_exists
BEFORE INSERT ON tasks
WHEN NOT EXISTS (SELECT 1 FROM orgs WHERE id = NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'unknown organization'); END;

CREATE TRIGGER IF NOT EXISTS tasks_org_immutable
BEFORE UPDATE OF org_id ON tasks
WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id
BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END;

-- one label namespace, case-insensitive (after the duplicate pre-check)
CREATE UNIQUE INDEX IF NOT EXISTS agents_label_nocase ON agents(label COLLATE NOCASE);

-- launch keys are client-chosen: scope them to the organization
DROP INDEX IF EXISTS idx_node_dispatch_launch_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_node_dispatch_launch_key
    ON node_dispatch(org_id, launch_key);

-- the existing version-capture trigger (part memory_versions.v1) inserts
-- without naming org_id, so every tenant's history would land in 'default'
DROP TRIGGER IF EXISTS memory_versions_capture;
CREATE TRIGGER memory_versions_capture
BEFORE UPDATE OF content, tags ON memory
FOR EACH ROW
WHEN (OLD.content IS NOT NEW.content OR OLD.tags IS NOT NEW.tags)
BEGIN
    INSERT INTO memory_versions (org_id, note_id, version, content, tags, updated_at, actor, recorded_at)
    VALUES (
        OLD.org_id,
        OLD.id,
        COALESCE((SELECT MAX(version) FROM memory_versions WHERE note_id = OLD.id), 0) + 1,
        OLD.content,
        OLD.tags,
        OLD.updated_at,
        COALESCE(OLD.updated_by, OLD.author),
        strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now')
    );
    DELETE FROM memory_versions
    WHERE note_id = OLD.id
      AND version <= (SELECT MAX(version) FROM memory_versions WHERE note_id = OLD.id) - 50;
END;
```

The duplicate pre-check runs before the label index:
`SELECT lower(label) FROM agents GROUP BY lower(label) HAVING count(*) > 1`
(and the same across `agents` and `users` once `users` exists). Any row refuses
the part and names the labels.

An existence trigger (`<table>_org_exists`) and an immutability trigger
(`<table>_org_immutable`) are generated for every tenant table. A row never
moves between organizations; "moving" is a copy plus a reference. Because
organizations are never deleted, insert-time existence is sufficient. The
`OLD.org_id IS NOT NULL` clause lets the harness-config tables' legacy `NULL`
be filled once, before the rebuild makes the column `NOT NULL`.

`org_id` on `memory`, `memory_versions` and `memory_embeddings` belongs to this
part; the memory parts add only visibility, team, owner and credential columns,
so no two parts add the same column.

**The default is a migration convenience, not a safety net.** A tool path that
forgets `org_id` will silently write into the default organization instead of
failing. Three guards:

1. The resolver always binds `org_id` explicitly; it is never omitted.
2. A unit test walks the statement strings in the tenant-scoped families and
   fails for an `INSERT INTO <tenant table>` that does not name `org_id`. It
   also walks the SQL of **every trigger** in `sqlite_master` after all parts
   have applied, because trigger bodies insert too (the
   `memory_versions_capture` case above) and no Rust string shows them.
   It is in the tree (the insert guard in
   `crates/ua-tools/tests/org_classification.rs`) for every tenant table that
   already carries its key; its table list is the classification's own. It
   reads source text, so it cannot see SQL whose table name is built at run
   time (`format!("INSERT INTO {table} …")`), and for `INSERT … SELECT` it
   checks that the column list names `org_id` but not that the `SELECT`
   supplies the right organization.
3. Every lookup by id takes the caller's organization (`WHERE id = ? AND
   org_id = ?`) and returns the same `not_found` for another organization's row
   as for a missing one. This includes `approvals::get` in `resolve`.

### Global keys and table rebuilds

`ALTER TABLE` cannot change a primary key or a `UNIQUE` constraint. Every
global key in the tree is classified:

| Table and key | Class | Reason / action |
|---|---|---|
| `agents.label`, `users.label` | Hub namespace | One case-insensitive label namespace (above). An agent belongs to one organization (`organization.v1.tools.agents`); a label another organization holds is refused `agent_label_taken`, and hub recovery frees one (`agent_retire`, `agent_forget` with `any_org`). `agent_lifecycle.agent` and `session_profiles (identity, session_key)` follow the label. |
| `agent_sessions.id`, `agent_tokens.token_hash`, `session_credentials.credential_id` and `.token_sha256`, `session_handoff_notes.id`, `session_wake.session_id`, `session_wake_offers.offer_id` | Global, safe | Hub-generated ULIDs, digests of random secrets, random ids, AUTOINCREMENT ids or a session id; no rebuild (`organization.v1.tools.agents`, `agents.v2.org_scope`). The `*_org_parent` triggers keep every reference in one organization. |
| `nodes.node` | Hub namespace | Node names are registered hub-wide; a node belongs to the one organization that registered it (`organization.v1.tools.nodes`). `node_claim_ops (node, op_id)` is led by it. |
| `provider_accounts.label`, `mcp_servers.name`, `dispatch_meta.key` | Hub table | Hub-scoped configuration and hub salts, managed by hub owners. |
| `managed_secrets.name` | **Rebuild** | Key becomes `(org_id, name)`, rebuilt in the standalone procedure `managed_secrets.v2.tenant_keys`, which also adds `aad_v` so new rows bind the organization into their associated data. |
| `skill_versions UNIQUE(name, version)` | **Rebuild** | Becomes `UNIQUE(org_id, name, version)`, rebuilt in the standalone procedure `skill_registry.v2.tenant_keys`. |
| `skill_assignments UNIQUE(skill_name, target_type, target)` | **Rebuild** | Becomes `UNIQUE(org_id, skill_name, target_type, target)`, rebuilt in `skill_registry.v2.tenant_keys` together with `skill_versions`. |
| `harness_config_bundles.version UNIQUE`, nullable `org_id` | **Rebuild** | `org_id NOT NULL`, `UNIQUE(org_id, version)`, rebuilt in the standalone procedure `harness_config.v3.tenant_keys`. |
| `harness_config_proposals` nullable `org_id` | **Rebuild** | `org_id NOT NULL`, rebuilt in `harness_config.v3.tenant_keys`; the key stays a hub-global random id. |
| `harness_config_report_window.node` | **Rebuild** | Key becomes `(org_id, node)`, rebuilt in `harness_config.v3.tenant_keys`, so the rate-limit upsert never updates another organization's window (node names are hub-wide: a name one organization forgets, including by hub recovery, can be registered again by another, which must not inherit the old window; `node_reassign` keeps a node in its organization). |
| `idempotency_keys.key` | **Rebuild** | Key becomes `(org_id, key)`, rebuilt in the standalone procedure `idempotency.v2.tenant_keys`; every reader filters `org_id`, so a replay never returns another organization's stored result. Each pre-rebuild row is placed by its interim `org:<org>/…` prefix (else `default`) with its key text unchanged, and the writers keep the prefix, so a retry in flight across the upgrade still replays. The principal stays in the key text of every per-caller writer instead of a `principal` column (`task_add` keys stay organization-wide); see the idempotency keys family above. |
| `node_dispatch` unique index on `launch_key` | **Rebuild** | Becomes `UNIQUE (org_id, launch_key)`, in the standalone procedure `node_queue.v2.tenant_keys`, which also makes `node_dispatch.org_id` `NOT NULL` and keeps ids and rowids. |
| `node_dispatch.id`, `node_command.item_id`, `node_command_notice (item_id, attempt, terminal)`, `node_followups.id`, `node_followups (item_id, idempotency_key)`, `(item_id, seq)`, `node_acceptance.node` | Global, safe | Item and follow-up ids are hub-generated, the other keys are led by one or by a hub-namespace node name; no rebuild. The `*_org_parent` triggers keep every reference in one organization. |
| `dispatch_runs.run_id`, `dispatch_receipts.id` | Global, safe | A run id is hub-derived from a salted hash, a receipt id an AUTOINCREMENT id; no rebuild (`organization.v1.tools.dispatch`, `dispatch.v4.org_scope`). |
| `event_log.dedupe_key UNIQUE` | Global, safe | Every producer builds it from hub-global identifiers (ULIDs, approval, run and delivery ids), never from client-chosen text alone, so two organizations cannot collide on it. A test asserts each producer's key format; a future producer that takes client text must prefix `org_id`. |
| `web_search_cache (provider, query, max_results)` | **Rebuild** | Key becomes `(org_id, provider, query, max_results)`, rebuilt in the standalone procedure `web.v2.tenant_keys`. |
| `project_repo_bindings.project` | **Rebuild** | Key becomes `(org_id, project)`, rebuilt in the standalone procedure `governance.v2.project_bindings_tenant_keys`. |
| `notify_outbox`, `pending_notifications`, `zulip_sends` | No key | AUTOINCREMENT ids only, so no rebuild (`organization.v1.tools.notify`, `organization.v1.tools.zulip`). The digest category count and the Zulip duplicate check (`stream, topic, content_sha256`) are query keys and filter on `org_id`. |
| `routine_runs UNIQUE(routine_id, fire_key)`, `workflow_runs.run_id`, `workflow_checkpoints UNIQUE(run_id, seq)` | Global, safe | Led by a hub-global id (a routine's AUTOINCREMENT id, a hub-generated ULID run id), never client text alone, so two organizations cannot collide; no rebuild (`organization.v1.tools.routines`, `organization.v1.tools.workflows`). The child tables carry a same-organization trigger against their parent. |
| `plans.id`, `plan_steps (plan_id, step_idx)`, `plan_checkpoints (plan_id, seq)` | Global, safe | A plan id is hub-generated (random, never caller-chosen), and the step and checkpoint keys hang off it, so no rebuild (`organization.v1.tools.plans`, `plans.v2.org_scope`). The `*_org_parent` triggers keep steps and checkpoints in their plan's organization. |
| `approvals.id`; the gate's `(tool, payload, requested_by)` match | No key | AUTOINCREMENT id only, so no rebuild (`organization.v1.tools.approvals`, `approvals.v3.org_indexes`). The gate's match is a query key and filters on `org_id`. |
| `tasks.id`, `task_dependencies.id`, `task_comments.id`, `task_comment_threads.task_id` | Global, safe | AUTOINCREMENT ids (and a thread keyed by its task's), never client text, so no rebuild (`organization.v1.tools.tasks`, `tasks.v2.org_scope`); the `*_org_parent` triggers keep every reference in one organization. The client-chosen comment idempotency key is unique per `(task_id, author, key)`, led by the hub-global task id. Accepted residual: the id gaps one organization sees reveal the hub's total task volume. |
| `message_index.message_id`, `message_index.event_ulid`, `message_reads (message_id, session_id)`, `relay_messages.id` | Global, safe | Hub-minted message ids and event ulids, receipts keyed by them, and AUTOINCREMENT draft ids, never client text, so no rebuild (`organization.v1.tools.messaging`, `messaging.v2.org_scope`; `organization.v1.tools.relay`, `relay.v2.org_scope`). A sender's client message id is an `idempotency_keys` row, prefixed with its organization outside the default one. |
| `policy_authorizations.id`, `tool_calls.id` | No key | AUTOINCREMENT ids only, so no rebuild (`organization.v1.tools.policy_authorizations`, `github.v3.policy_authorizations_org_scope`; `organization.v1.tools.tool_calls`, `core.v5.tool_calls_org_scope`). The authorization lookups (by head, task, repository) and the telemetry counts (by caller, tool, window) are query keys and filter on `org_id`. |
| `review_ready_notices (task_id, head_sha)` | Global, safe | Task ids are hub-global, so two organizations cannot collide; the table converts with the tasks family. |
| `autonomous_cycles.id`, `autonomous_cycle_transitions (cycle_id, idempotency_key)`, `autonomous_cycle_usage (cycle_id, usage_run_id, usage_id)` | Global, safe | A cycle id is hub-generated (random, never caller-chosen), and the transition and usage keys are led by it, so the caller-chosen idempotency and usage keys cannot collide across organizations; no rebuild (`organization.v1.tools.cycles`, `cycles.v2.org_scope`). The `*_org_parent` triggers keep transitions and usage in their cycle's organization. |
| `memory.id`, `memory_versions (note_id, version)`, `memory_embeddings.note_id` | Global, safe | A note id is hub-generated (random, never caller-chosen), and the version and vector keys are led by it, so no rebuild (`organization.v1.memory`, `memory.v2.org_scope`). The `*_org_parent` triggers keep versions and vectors in their note's organization. |
| `graph_canvas_scenes.board_id`, `graph_canvas_revisions (board_id, revision)` | **Rebuild** | Keys become `(org_id, board_id)` and `(org_id, board_id, revision)`, rebuilt together in `graph_canvas.v2.tenant_keys`. |

Without the rebuilds, organization B could not create a secret, skill, binding
or board whose name A uses, the conflict error would tell B that A has it, and
an idempotency replay could return A's stored result to B.

The graph canvas rebuild uses a transactional static part. No existing
foreign keys, triggers or views depend on the two original tables. The
rebuild adds the composite revision reference with foreign keys enabled,
so legacy revisions without a board fail the upgrade atomically.

The skill registry rebuild is a standalone procedure, like the web cache's:
`skill_versions` carries immutability triggers that the rebuild must
re-create, and a view may name either table. It checks that the trigger and
view sets are unchanged, and keeps each table's AUTOINCREMENT high-water mark
so an id freed by a delete is never handed out again.

The planned `organization.v1-rebuild` for the remaining tables runs alone, outside the usual transaction, at
start-up before the hub serves, using SQLite's documented table-rebuild
procedure:

1. `PRAGMA foreign_keys = OFF` (it has no effect inside a transaction, which is
   why the part runs alone);
2. `BEGIN IMMEDIATE`; for each table: record its dependent triggers, indexes
   and views from `sqlite_master`; create `<table>_new` with the new keys;
   `INSERT INTO <table>_new SELECT …, COALESCE(org_id, 'default') …`; drop the
   old table; rename; recreate the recorded indexes, triggers (including the
   generated `org_exists` and `org_immutable` triggers) and views;
3. `PRAGMA foreign_key_check(<table>)` for **each rebuilt table** — any row
   aborts with `ROLLBACK`. Not a whole-database check: legacy dangling
   references elsewhere (which `state_sync_verify` exists to report, and which
   imports can carry) must not stop the hub from starting. None of the rebuilt
   tables declares a foreign key or is referenced by one today, so the
   per-table check is what proves the rebuild itself is sound;
4. compare the set of trigger and view names against the recorded set — any
   difference aborts with `ROLLBACK`;
5. record the part, `COMMIT`, `PRAGMA foreign_keys = ON`.

A failed rebuild leaves the database exactly as before and the hub refuses to
start, naming the part.

## Resolution

`Caller` gains `org_id: String` and `user_id: Option<String>`. Both are set by
the adapter from the verified credential and from nothing else:

| Credential | Organization | User |
|---|---|---|
| Static config token (`UA_AGENT_TOKENS`) | always `'default'` — it is hub configuration and its label is reserved. If an organization other than `'default'` held the label before it was added to the config, the token is **refused** (it does not authenticate) until the operator resolves the `MISCONFIGURED` row | the users row, when the label is human |
| Agent token row (`agent_tokens`) | `agent_tokens.org_id`, set at issue to the agent's organization | none — refused for human labels |
| Node session credential (`uas_…`) | `session_credentials.org_id`, the organization of the work item it was minted for | none |
| OAuth grant | `oauth_grants.org_id`, which must equal the subject agent's organization — checked at grant creation and on every use | none — OAuth never acts as a human |
| Passkey / UI session | `ui_sessions.org_id`: chosen at login among the user's memberships, **re-validated against `org_memberships` on every request**; switching organization issues a new session id and CSRF token | the passkey's label |
| CLI and stdio, local | `'default'`, or `--org <slug>`, refused unless the label has a membership there | the users row, when the label is human (hub-host trust) |
| Anonymous HTTP (`enforce_auth` off) | `'default'` | none; never human |
| `Caller::system()` | `'default'` | none |
| `Caller::system_for(org_id)` | the named organization | none |

Background jobs (escalation timers, dispatch, wake, routines, consolidation)
iterate the active organizations and act through `system_for(org_id)`, so each
action is attributed to the organization it touches. There is no
organization-free caller.

**Never from tool arguments.** `goal_manage` keeps refusing `params.org_id`.

## Approvals routed by team

Today any configured human can approve anything. In an organization with
several teams that is wrong in both directions: Team A's lead should not need
the hub owner for routine approvals, and must not be able to approve Team B's
deploys — or anything that needs an admin.

```sql
-- organization.v4
ALTER TABLE approvals ADD COLUMN team_id TEXT;
ALTER TABLE approvals ADD COLUMN routing_basis TEXT NOT NULL DEFAULT 'hub'
    CHECK (routing_basis IN ('hub','task_team','named_team','org'));
ALTER TABLE approvals ADD COLUMN required_authority TEXT NOT NULL DEFAULT 'hub_owner'
    CHECK (required_authority IN ('hub_owner','org_admin','team_lead','agent_owner'));
ALTER TABLE approvals ADD COLUMN two_person INTEGER NOT NULL DEFAULT 0
    CHECK (two_person IN (0,1));
ALTER TABLE approvals ADD COLUMN escalated_at TEXT;
ALTER TABLE approvals ADD COLUMN escalation_targets TEXT;   -- JSON user ids

CREATE TRIGGER IF NOT EXISTS approvals_team_same_org
BEFORE INSERT ON approvals
WHEN NEW.team_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM teams WHERE id = NEW.team_id AND org_id = NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'approvals.team_id must be a team of the approval''s organization'); END;

CREATE TRIGGER IF NOT EXISTS tasks_team_same_org
BEFORE UPDATE OF team_id ON tasks
WHEN NEW.team_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM teams WHERE id = NEW.team_id AND org_id = NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'tasks.team_id must be a team of the task''s organization'); END;
```

The matching insert/update triggers are generated for both columns. The column
defaults are the **narrowest** values, so a pending approval from before the
migration fails closed: on first start after `organization.v4`, a one-time step
reclassifies each pending row from the tool registry (`routing_basis = 'org'`,
`required_authority = 'org_admin'` for tenant-scoped tools; hub-scoped rows
stay as they are).

**Binding.** The gate matches a pass on `(org_id, tool, payload,
requested_by)`. A pass parked in organization A never satisfies the identical
call in B, even for a human who belongs to both.

**Required authority.** Computed when the approval is parked, from the tool's
classification and the payload, and never lowered afterwards:

| Call | `required_authority` |
|---|---|
| A hub-scoped tool | `hub_owner` |
| A team-routable tool routed to a team (below) — and, for a spec commit or proposal apply, only when the change is narrowing | `team_lead` |
| A grant of an approving role, or a credential for another human | `org_admin` with `two_person = 1` (`hub_owner` when [Credentials for people](#credentials-for-people) says so) |
| A root credential for an agent with an `owner_user_id`, requested by anyone but that owner | `agent_owner` |
| Every other tenant-scoped gated call | `org_admin` |

**Routing team.** Only for team-routable tools; every other tool routes to
`org` (or `hub`):

| Basis | When | `team_id` |
|---|---|---|
| `hub` | the tool is hub-scoped | `NULL` |
| `task_team` | the call names a task whose `team_id` is set, **and** the requester is a member of that team | the task's team |
| `named_team` | a team operation (`team_up`, spec commit, proposal apply) **and** the requester is a member of that team | the named team |
| `org` | anything else, including a requester naming another team's task | `NULL` |

`tasks.team_id` can be set by `org_admin` and above. A team lead may set it
only on a task whose current team is `NULL` or one they lead, and only to a
team they lead — so moving a task between teams needs `org_admin` or a lead of
both. Agents cannot set it.

**Eligibility.** `resolve` with `approve` succeeds only when every check holds,
evaluated at resolution time against current rows:

1. **Organization.** The caller is human and `caller.org_id ==
   approvals.org_id` — or the caller is a hub owner and either
   `required_authority = 'hub_owner'` or this is a `two_person` approval in an
   organization with no other eligible human.
2. **Not the requester.** For `two_person` approvals, also not the subject of
   the grant or credential.
3. **Authority**, by `required_authority`:
   - `hub_owner`: the caller is a hub owner;
   - `org_admin`: the caller's role is `org_admin` or `org_owner` (`org_owner`
     when granting `org_owner`);
   - `team_lead`: one of
     - a. the caller's role is `org_admin` or `org_owner`;
     - b. the routing is re-checked — for `task_team`, the task's `team_id` is
       still the recorded team and the requester is still a member; for
       `named_team`, the requester is still a member — **and** the caller is a
       `lead` member of that team with role `team_lead` or above;
     - c. the approval is escalated, the caller is in `escalation_targets`, and
       still holds `team_lead` or above in the same organization.

     If the re-check in (b) fails, only (a) applies.
   - `agent_owner`: the caller is the user in the target agent's current
     `owner_user_id`, whatever their role. Nobody else qualifies, hub owners
     included; if the owner link is cleared while the approval is pending, the
     approval falls back to `org_admin`.
4. Apart from `agent_owner`, `auditor` and `member` never approve.

`deny` follows the same eligibility, plus the requester. `revoke` requires the
same organization and either approve eligibility or being the requester.
Membership is evaluated at resolution, so a lead removed while an approval is
pending can no longer approve it.

**Escalation.** A team spec may set `approval_escalation: {after, to}`.
`after` has a floor of 15 minutes. Each target is `user:<id>` — a user with
`team_lead` or above in the same organization — or `team:<slug>` — a team of
the same organization, meaning its current leads. Targets are validated when
the spec is committed. Escalation applies only to pending approvals whose
`team_id` is that spec's team and whose `required_authority` is `team_lead`; it
never changes `required_authority`. A `system_for(org)` job marks such an
approval older than `after` by setting `escalated_at` and `escalation_targets`
(resolved user ids), records an `agent.approval.escalated` event, and leaves
`status` unchanged (its `CHECK` is not altered). Escalation adds approvers
under rule 3c; it never removes any.

The seat-level `escalates_to` edge is separate: it routes a seat's blocked-task
notifications and confers no approval authority.

## Teams

```sql
-- organization.v3
CREATE TABLE IF NOT EXISTS offices (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id),
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    profiles   TEXT NOT NULL CHECK (json_valid(profiles) AND json_type(profiles) = 'array'),
    created_at TEXT NOT NULL,
    UNIQUE (org_id, slug),
    UNIQUE (org_id, id)
);

CREATE TABLE IF NOT EXISTS teams (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id),
    office_id  TEXT,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
    created_at TEXT NOT NULL,
    UNIQUE (org_id, slug),
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, office_id) REFERENCES offices(org_id, id)
);
CREATE TRIGGER IF NOT EXISTS teams_no_delete BEFORE DELETE ON teams
BEGIN SELECT RAISE(ABORT, 'teams are archived, never deleted'); END;

CREATE TABLE IF NOT EXISTS team_members (
    org_id         TEXT NOT NULL,
    team_id        TEXT NOT NULL,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('human','agent')),
    principal      TEXT NOT NULL,   -- users.id for 'human', agent label for 'agent'
    member_role    TEXT NOT NULL DEFAULT 'member'
                   CHECK (member_role IN ('lead','member')),
    added_at       TEXT NOT NULL,
    PRIMARY KEY (team_id, principal_type, principal),
    CHECK (member_role = 'member' OR principal_type = 'human'),
    FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, id)
);

CREATE TABLE IF NOT EXISTS reporting (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id           TEXT NOT NULL REFERENCES orgs(id),
    subordinate_type TEXT NOT NULL CHECK (subordinate_type IN ('human','agent','office')),
    subordinate      TEXT NOT NULL,
    supervisor_type  TEXT NOT NULL CHECK (supervisor_type IN ('human','agent','office')),
    supervisor       TEXT NOT NULL,
    effective_from   TEXT NOT NULL,
    effective_to     TEXT
);
```

`organization.v2` adds the agent columns:

```sql
ALTER TABLE agents ADD COLUMN owner_user_id TEXT;    -- the human this agent acts for
ALTER TABLE agents ADD COLUMN default_profile TEXT;  -- within allowed_profiles
```

Writer rules the schema cannot express, each with an acceptance test:

- A `lead` member must hold `team_lead`, `org_admin` or `org_owner` in the
  team's organization; eligibility is re-checked at approval time, so a demoted
  user stops leading without a second step.
- A human `principal` must have a membership in the team's organization; an
  agent `principal` must be an agent of that organization.
- `agents.owner_user_id` must be a member of the agent's organization, and is
  set only with **both** parties: the named user's own act **and** an
  `org_admin`'s. Either the user requests a claim and an `org_admin` approves
  it, or an `org_admin` offers the link and the user accepts. Neither can set
  it alone: the approving or offering admin must be a different person from
  the user being linked, so an admin linking an agent to themselves needs
  another admin. Only an agent with no current owner can be claimed. An
  `org_admin` may clear it (that narrows), never set it to someone else.
  Clearing the link immediately ends the agent's eligibility for that
  person's private notes, so an admin who clears it and then issues the agent
  a token, or whose pending `agent_owner` approval falls back to `org_admin`,
  gains nothing over those notes. Memory uses this link to decide
  which agent may summarize that person's private notes, so an admin who holds
  an agent's tokens must not be able to aim it at another person.
- **An owned agent's credentials belong to its owner.** Claiming an agent
  revokes every live credential for it that someone other than the claiming
  user issued (agent tokens, managed tokens, OAuth grants, node session
  credentials). While `owner_user_id` is set, a new **root** credential for
  that agent — `agent_token_issue`, `agent_token_rotate`, a managed token, an
  OAuth grant — is issued in one of two ways: the owner issues it themselves
  (the owner may issue and rotate credentials for their own agent whatever
  their role, with no second approval, since the owner is the person being
  protected), or anyone else requests it and it parks with
  `required_authority = 'agent_owner'`, which only that owner can approve. An
  `org_admin` cannot mint one alone. Node session credentials are not root
  credentials: the agent's own node mints them per dispatch from a credential
  the agent already holds, so they need no extra approval. Otherwise an admin
  could take over an agent its owner had enabled for private consolidation and
  read that person's private notes.
- `org_memberships.consolidate_private` is changed only by the member
  themselves (default off); see `docs/memory.md`.
- `offices.profiles` and `agents.default_profile` must be within the
  organization's `allowed_profiles`.
- `reporting` endpoints must belong to the same organization; only
  `org_admin` and above write it.
- An archived team takes no new members, spec commits or `team_up`; its rows
  stay for history.

## Team specs

A team spec is the executable definition of a team: which agent seats exist,
how each one starts, how seats may interact, and what they may spend. It is
what lets one human approval bring up a working multi-harness team.

Specs are tenant data, not hub configuration, so they live in their own
append-only table rather than in `config_revisions` (which versions the
hub-wide policy file and whose `kind` set is fixed by its schema part).

```sql
CREATE TABLE IF NOT EXISTS team_specs (
    org_id         TEXT NOT NULL,
    team_id        TEXT NOT NULL,
    version        INTEGER NOT NULL,
    parent_version INTEGER NOT NULL,   -- 0 for the first commit
    spec           TEXT NOT NULL,      -- canonical JSON
    spec_sha256    TEXT NOT NULL,
    committed_by   TEXT NOT NULL,
    committed_at   TEXT NOT NULL,
    PRIMARY KEY (team_id, version),
    CHECK (parent_version = version - 1),
    FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, id)
);
CREATE TRIGGER IF NOT EXISTS team_specs_no_update BEFORE UPDATE ON team_specs
BEGIN SELECT RAISE(ABORT, 'team specs are append-only'); END;
CREATE TRIGGER IF NOT EXISTS team_specs_no_delete BEFORE DELETE ON team_specs
BEGIN SELECT RAISE(ABORT, 'team specs are append-only'); END;
```

A commit needs an approval bound to `(org_id, team_id, parent_version,
spec_sha256)` and is refused if the live version is no longer
`parent_version`, so two approved commits cannot silently overwrite each other.
Its `required_authority` is `team_lead` only when the diff from the parent is
narrowing ([Self-organization](#self-organization) rule 5); anything else,
**including the first commit**, is `org_admin`. Every commit appends an
`agent.team.spec` ledger event with the hash.

### Spec shape

```json
{
  "team": "platform",
  "office": "engineering",
  "budget": {"tokens_per_day": 4000000, "cost_usd_per_month": 900},
  "approval_escalation": {"after": "4h", "to": ["team:platform-leads"]},
  "seats": [
    {
      "label": "builder-1",
      "harness": "claude",
      "model": "<model id>",
      "fallback": [{"harness": "codex", "model": "<model id>"}],
      "node": "desk-01",
      "workspace": {"repo": "org/service", "worktree": "per_task", "trust_root": "/srv/work"},
      "profile": "developer",
      "skill_pack": "<published harness_config bundle version>",
      "budget": {"tokens_per_day": 1500000, "cost_usd_per_day": 40},
      "guidance": "short startup guidance"
    }
  ],
  "edges": [
    {"from": "builder-1", "to": "reviewer-1", "type": "reviews"},
    {"from": "planner-1", "to": "builder-1", "type": "delegates_to"},
    {"from": "builder-1", "to": "user:<id>", "type": "escalates_to"},
    {"from": "reviewer-1", "to": "builder-1", "type": "can_observe"}
  ]
}
```

Only one seat is shown; `reviewer-1` and `planner-1` are seats of the same
shape.

Validation at commit (each refusal names the field):

- The team is `active`.
- Every seat `label` is an agent member of this team, in this organization. A
  spec never creates an identity.
- `node` is a node of this organization; `skill_pack` is a published bundle of
  this organization; escalation targets are in this organization with an
  approving role.
- `harness` is one the harness-config surface supports; `fallback` entries are
  tried in order when the primary harness or its provider is unavailable or
  rate-limited.
- `profile` is in both the office's `profiles` and the organization's
  `allowed_profiles`.
- `workspace.trust_root` must be a root the named node itself reported. A spec
  can narrow trust, never grant it; workspaces are never auto-trusted.
- Seat budgets may not sum above the team budget.
- `delegates_to` and `escalates_to` are acyclic; edge endpoints are seats of
  this team, or `user:<id>` for `escalates_to`.
- `approval_escalation.after` is at least 15 minutes.
- The canonical JSON is at most 64 KiB; unknown keys are refused.

### Edges are enforced, not decorative

When a team has a committed spec, its seats are governed by its edges — as
actors **and** as targets. Agents that are not seats of any spec are
unaffected as actors, but they cannot reach into a governed seat.

**Leaving a seat does not free an agent.** An agent removed from a spec's
seats but still a `team_members` row of that team stays **governed with no
edges**: it may not delegate, observe or count as a reviewer until an
`org_admin` removes it from the team. So a team lead's narrowing approval of a
seat removal cannot be used to lift that agent's edge restrictions.

| Edge | Enforced at | As actor | As target |
|---|---|---|---|
| `delegates_to` | delegation and dispatch | A seat may delegate only along its edges. | A seat accepts delegation only from a seat with an edge to it, or from a human `org_admin` or lead of its team. |
| `reviews` | task stage review | A seat's review counts only for authors it has the edge to. | — |
| `escalates_to` | blocked-task notification | Where a seat's blocked tasks are announced. | — |
| `can_observe` | session, run and flight-recorder reads | A seat may read another seat's sessions and runs only along its edges. | A seat's sessions and runs are readable only by seats with an edge to it, and by humans of its organization with `org_admin`, `auditor` or lead of its team. |

All checks live in one function in `ua-org`, called by the tool wrapper's
policy layer. A refusal names the missing edge.

### Budgets

A seat has one budget pool, shared by its primary and its fallbacks; fallback
exists for availability, not to escape a cap. Usage is recorded per run on the
ledger with `usage_source`:

- `node` — reported by the node that ran the harness, from the harness's own
  usage output. Preferred.
- `agent` — reported by the agent. Accepted only where the node cannot report;
  admins see the split.

Budgets are sums over the ledger for the seat, the team and the window. A seat
at its cap is refused new dispatch with `budget_exhausted`, and its
`escalates_to` targets are notified. Enforcement granularity is one run: a run
in flight finishes.

### `ua team plan` and `ua team up`

`ua team plan <team>` (tool `team_plan`) is read-only. It reports two parts:

- `static`: what the spec and slow-moving rows determine — per seat the
  identity, node, harness, model, workspace, trust-root registration, skill
  pack hash, profile, budget limits, and edge validity, each with a refusal and
  its reason. This part is canonical JSON with no timestamps, so two plans of
  the same spec against the same rows are **byte-identical**; `plan_sha256` is
  its hash.
- `volatile`: node liveness, harness presence on the node, and budget headroom.
  Reported, never hashed.

`ua team up <team>` (tool `team_up`) boots a **committed** spec of an active
team only. It recomputes the plan and refuses if any `static` check fails, then
requests one approval bound to `(org_id, team_id, spec_sha256, plan_sha256)`,
routed to the named team (`named_team`, required authority `team_lead`). After
approval it re-checks the `volatile` part; if any seat fails, nothing
launches, the refusals are returned, and the pass stays unconsumed until it
expires so a retry reuses it. Otherwise seats launch in `delegates_to` order
through the node work queue, one run record per seat linked by a
`team_run_id` on `agent.team.run`, and the pass is consumed. A change to
`static` facts changes `plan_sha256` and needs a new approval.

## Self-organization

Agents can see where their own team's structure is wrong — a missing reviewer, a
routing rule that bounces work, a routine nobody runs. They may **propose**
changes; they may never **apply** them.

```sql
-- organization.v5
CREATE TABLE IF NOT EXISTS org_proposals (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id),
    team_id     TEXT,
    proposer    TEXT NOT NULL,
    kind        TEXT NOT NULL
                CHECK (kind IN ('role','team','routing','skill','routine','edge','budget','other')),
    diff        TEXT NOT NULL,   -- structured patch against the live spec or rows
    base_sha256 TEXT NOT NULL,   -- hash of the state the diff applies to
    rationale   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'proposed'
                CHECK (status IN ('proposed','applied','rejected','stale','withdrawn')),
    created_at  TEXT NOT NULL,
    resolved_by TEXT,
    resolved_at TEXT,
    FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, id)
);
```

Rules:

1. **Proposing is on by default** and switched off per organization by the
   `self_organization` setting.
2. **Scope is membership.** A proposer may target only teams it is a
   `team_members` row of; its office scope is the offices of those teams. A
   proposal outside that scope is refused, not queued.
3. **Rate limited.** At most `proposal_daily_limit` proposals per proposer per
   day.
4. **Applying is never automatic.** Apply needs an approval bound to the
   proposal id, the diff hash and `base_sha256`. `base_sha256` is the live
   spec's `spec_sha256` for spec changes, and otherwise the SHA-256 of the
   canonical JSON of the targeted rows ordered by primary key. If the live
   state no longer hashes to it, the proposal becomes `stale` and is not
   applied.
5. **Team leads approve narrowing only.** A change is narrowing only if every
   part of it is on this list:
   - lowering a seat or team budget;
   - moving a seat's profile to another profile already in the office's set
     that the organization classes as narrower (the office lists them in
     order);
   - removing a `delegates_to` or `can_observe` edge;
   - narrowing a `trust_root` to a subdirectory of itself;
   - removing a seat that is **not** an endpoint of a `reviews` edge and
     **not** an `escalates_to` or `approval_escalation` target — the agent
     stays a governed team member with no edges ([above](#edges-are-enforced-not-decorative));
     removing the agent from the team itself needs `org_admin`.

   Everything else needs `org_admin` or `org_owner`. That includes adding
   members, any `reviews` change, `approval_escalation` and `escalates_to`
   changes, `skill_pack` (harness config, so code on a node), `node`,
   `workspace.repo`, `harness`, `fallback`, `model`, `guidance`, and every
   proposal of kind `skill` or `routine`.
6. Applying a spec change commits a new `team_specs` version through the same
   path as a human commit, so history has one shape.

The diff is structured so the review inbox can render it side by side, as
escaped text.

## Scoping per subsystem

Every table is classified, and a test over `sqlite_master` fails on any table
missing from `ua-org`'s classification list. That list (today in
`crates/ua-tools/tests/org_classification.rs`) is the authority; the table
below is kept in step with it. For every **tenant** table it also
checks, through `PRAGMA table_info`, that `org_id` exists and is `NOT NULL`,
and that its `org_exists` and `org_immutable` triggers exist.

| Class | Tables | Rule |
|---|---|---|
| Tenant: tasks and planning | `tasks`, `task_dependencies`, `task_comments`, `task_comment_threads` (`organization.v1.tools.tasks` and `tasks.v2.org_scope`: every task read and write, same-organization reference triggers, ranked search scoped before the candidate cap; the hub's GitHub paths in the delivery's, poll's or task's organization), `task_workflow`, `task_checks`, `review_ready_notices` (`organization.v1.tools.continuity` and `continuity.v2.org_scope`: existing rows moved to their task's organization, every workflow, check and notice read and write, same-organization task triggers; re-verification in the delivery's or poll's organization), `task_holds`, `task_hold_members` (`organization.v1.tools.holds` and `governance.v3.holds_org_scope`: a hold in its root task's organization, every hold read, write and claim check, same-organization root, task and hold triggers), `goals`, `task_goal_links` (`organization.v1.tools.goals` and `goals.v2.org_scope`: a link in its task's organization, every goal and link read and write, same-organization parent, task and goal triggers), `work_proposals`, `work_proposal_items` (`organization.v1.tools.proposals` and `governance.v4.proposals_org_scope`: an item in its proposal's organization, every proposal read and write and the contract check in the task's organization, an approved item's task in the proposal's organization, deciding authority-gated and so default-only today), `project_repo_bindings` (`governance.v2.project_bindings_tenant_keys` and `organization.v1.tools.project_bindings`, scoped key, reads and writes), `plans`, `plan_steps`, `plan_checkpoints` (`organization.v1.tools.plans` and `plans.v2.org_scope`: every plan read and write, same-organization parent triggers), `routines` and `routine_runs` (`organization.v1.tools.routines` and `routines.v2.org_indexes`: scoped reads and writes, each fire in its routine's organization), `workflow_runs` and `workflow_checkpoints` (`organization.v1.tools.workflows` and `workflows.v2.org_indexes`: scoped reads and writes, a run in its starter's or routine's organization, gated approvals bind `org_id`), `delegations` (`organization.v1.tools.delegation` and `delegation.v2.org_scope`: every delegation read and write, a delegation's task in its own organization, created with its task in the delegator's organization), `autonomous_cycles`, `autonomous_cycle_transitions`, `autonomous_cycle_usage` (`organization.v1.tools.cycles` and `cycles.v2.org_scope`: every cycle read and write, same-organization parent triggers, gated approvals bind `org_id`; a cycle binds only its own organization's task or delegation, `cycles.v3.task_org`), `deliverables` and `deliverable_revisions` (carry `org_id` and their triggers from their first part, `organization.v1.deliverables`) | `org_id`; `tasks` also has optional `team_id` |
| Tenant: agents and sessions | `agents`, `agent_sessions`, `agent_tokens`, `agent_lifecycle`, `session_profiles`, `session_credentials`, `session_handoff_notes`, `session_wake`, `session_wake_offers` (`organization.v1.tools.agents` and `agents.v2.org_scope`: an agent in its credential's organization, everything else in its agent's, session's or item's; every read and write scoped; labels one namespace), `dispatch_receipts`, `dispatch_runs` (`organization.v1.tools.dispatch` and `dispatch.v4.org_scope`: a run in its task's organization, a receipt in its run's; every dispatch read and write scoped) | An agent belongs to exactly one organization |
| Tenant: nodes | `nodes`, `node_acceptance`, `node_claim_ops`, `node_command`, `node_command_notice`, `node_dispatch`, `node_followups` (`node_queue.v2.tenant_keys`, `organization.v1.tools.nodes` and `node_queue.v2.org_scope`: a node in the organization that registered it, work in its creator's and its node's, every read and write and the device plane scoped) | A node serves one organization |
| Tenant: people and teams | `org_memberships`, `offices`, `teams`, `team_members`, `team_specs`, `reporting`, `org_proposals` | Per organization |
| Tenant: memory | `memory`, `memory_versions`, `memory_embeddings` (`organization.v1.memory` and `memory.v2.org_scope`: every note read and write, search legs scoped inside the ranked query, versions and vectors in their note's organization), and from `docs/memory.md`: `memory_chunks`, `memory_entities`, `memory_links`, `memory_consolidations`, `memory_consolidation_sources`, `memory_invalidations`, `memory_feedback_events` | `org_id` plus a visibility tier, enforced in the search SQL — see `docs/memory.md`; each new table gets the generated `org_exists` / `org_immutable` triggers |
| Tenant: approvals and policy | `approvals` (`organization.v1.tools.approvals` and `approvals.v3.org_indexes`: the requester's organization; every match, read and decision is scoped), `policy_authorizations` (`organization.v1.tools.policy_authorizations` and `github.v3.policy_authorizations_org_scope`: the task's organization; every read, check, spend and revoke is scoped) | `org_id`, routing `team_id`, required authority |
| Tenant: messages | `message_index`, `message_reads` (`organization.v1.tools.messaging` and `messaging.v2.org_scope`: the sender's organization; every send, read, mark, ack, reply and conversation check is scoped, and a send into another organization is refused), `notify_outbox` and `pending_notifications` (`organization.v1.tools.notify` and `notify.v2.org_indexes`: every notify tool reads and writes only the caller's organization's rows; the hub's webhook carries only the default organization's), `relay_messages` (`organization.v1.tools.relay` and `relay.v2.org_scope`: drafting and sending stay default-only; status, list, cancel and resolve are scoped), `zulip_sends` (`organization.v1.tools.zulip`: the duplicate check and `zulip_resolve_send` are scoped; only the default organization sends through the hub's Zulip) | `org_id` |
| Tenant: skills and config | `skill_versions`, `skill_assignments`, `skill_publish_staging` (`skill_registry.v2.tenant_keys` and `organization.v1.tools.skills`, scoped keys and every registry read and write), `harness_config_bundles`, `harness_config_proposals`, `harness_config_drift`, `harness_config_report_window` (`harness_config.v3.tenant_keys` and `organization.v1.tools.harness_config`, scoped keys, every read and write, approvals bind `org_id`) | Catalog is per organization (keys rebuilt) |
| Tenant: other | `managed_secrets` (`managed_secrets.v2.tenant_keys` and `organization.v1.tools.managed_secrets`: scoped key, every read and write, the organization bound into the associated data; another organization's GitHub credentials live here), `graph_canvas_scenes` and `graph_canvas_revisions` (`organization.v1.tools.graph`, scoped keys and queries), `tool_calls` (`organization.v1.tools.tool_calls` and `core.v5.tool_calls_org_scope`: the caller's organization; every telemetry reader and policy count is scoped), `web_search_cache` (`web.v2.tenant_keys` and `organization.v1.tools.web`, scoped key, reads, writes and eviction), `idempotency_keys` (`idempotency.v2.tenant_keys` and `organization.v1.tools.idempotency`: `(org_id, key)`, every read and write, the interim organization prefix kept in the key text), `code_symbols` (`organization.v1.tools.code`: the symbol tools read and write only the caller's organization's rows, so two organizations indexing one workspace keep separate symbols), `inbound_deliveries` (carries `org_id` and its triggers from its first part, `organization.v1.ingress`; a GitHub delivery's replay keys are recorded in each organization whose secret verified it), `github_poll_repos` (`github.v2.poll_repos` creates it keyed `(org_id, repo)` and copies `github_poll_state`'s rows to the default organization, `organization.v1.tools.github_poll` adds the triggers) | `org_id`; keys rebuilt where listed above |
| Derived index | FTS5 virtual tables `task_fts` and `memory_fts`, and their shadow tables (`*_data`, `*_idx`, `*_content`, `*_docsize`, `*_config`) | No `org_id`; every read joins through the owner table (`tasks`, `memory`) and filters there. Accepted leak: bm25's corpus statistics span every organization |
| SQLite internal | `sqlite_sequence`, `sqlite_stat*` | Not application data |
| Tenant column on a global table | `event_log` | One chain, `org_id` per row — see [The ledger](#the-ledger) |
| Global identity | `users`, `passkeys`, `webauthn_states`, `login_links`, `oauth_clients`, `oauth_codes`, `oauth_grants`, `oauth_requests`, `oauth_tokens`, `ui_keys`, `ui_sessions`, `org_bootstrap` | Identity is global; the **grant** carries the organization (`oauth_grants.org_id`, `ui_sessions.org_id`, `agent_tokens.org_id`) |
| Hub | `orgs`, `config_revisions`, `mcp_servers`, `provider_accounts`, `dispatch_meta`, `github_deliveries`, `github_delivery_bodies`, `github_poll_state` (unread since `github.v2.poll_repos`), `slack_seen_signatures`, `slack_seen_deliveries`, `zulip_fetch_cursors`, `vault_ingest_ledger`, `import_runs`, `import_org_map`, `import_finalized`, `schema_parts`, `ledger_meta` | Hub-scoped tools only; hub owners |

The vault is hub-scoped, so anything that copies tenant data into it —
`memory_promote` above all — is allowed only in `'default'` (see
`docs/memory.md`). Reading it is too: every `vault_*` and `obsidian_*`
tool and `export_journal` refuse another organization's caller
(`org_unsupported`) before touching the vault or the plugin. The other hub
resources refused the same way are listed under "No workspace outside the
default organization yet" above.

The governed call path (`Registry::call`, and an approval requested ahead
of a call) refuses a caller whose organization `orgs` does not hold
(`unknown_organization`) or holds as suspended (`organization_suspended`)
before anything runs: no handler, no policy evaluation, no `tool_calls`
row and no decision event. It is one primary-key read per call of an
organization other than the default, which is seeded with the schema and
cannot be deleted, so its callers skip it. It sits in the registry rather
than only where a credential resolves because every caller passes the
registry (HTTP and MCP credentials, stdio, the hub's per-organization
jobs), and it is not cached so a suspension applies to the next call. Each
family's own `require_org` stays behind it for paths that write without
the registry.

## The ledger

`event_log` is a single global hash chain. The organization must not fork it,
or every existing chain verification breaks and cross-organization tamper
evidence disappears.

**Whose event.** An event's `org_id` is the organization of the **affected
row**, not of the caller. Events about global rows — users, passkeys, login
links, user suspension, bootstrap — go to `'default'`. Today `ledger::EventInput`
derives `Default` and `EventInput::new()` fills the rest with
`..Self::default()`, so a new field would compile silently; the change removes
`Default` and makes `new()` take `org_id`, so every call site must supply one.
A system job acting for organization B writes B's `org_id`, so B's auditors
see it.

**Hash versioning.** Today `ledger::compute_entry_hash` hashes nine fields
(`causal_parent_id`, `channel`, `created_at`, `dedupe_key`, `episode_id`,
`originator`, `payload`, `prev_hash`, `ulid`) in the byte form the Python hub
produced, which is what lets imported chains verify. Adding a field changes that
form, so the hash is versioned:

```sql
ALTER TABLE event_log ADD COLUMN org_id  TEXT NOT NULL DEFAULT 'default';
ALTER TABLE event_log ADD COLUMN hash_v  INTEGER NOT NULL DEFAULT 1;
```

- `hash_v = 1`: the existing nine-field form. Every row written before the
  migration, and every imported row, keeps it. Their `org_id` is not covered by
  their hash, which is honest: those rows predate tenancy.
- `hash_v = 2`: the nine fields plus `org_id`, in sorted key position. Every
  row appended after the migration uses it.
- `verify()` chooses the form per row by `hash_v`, **refuses any other value**,
  and refuses a `hash_v = 1` row whose `seq` is after the first `hash_v = 2`
  row, so a downgrade cannot be slipped into the chain.

**Who verifies.** `verify()` walks every organization's rows and its counts
reveal each tenant's event volume. It is available to callers in `'default'`
(the hub operator's own organization; this keeps today's behaviour, where any
agent may call `event_log_verify`) and to hub owners, and refused to callers in
any other organization. An organization's audit export carries each of its
rows with `prev_hash` and `entry_hash` but **without `seq`**, whose gaps would
reveal hub-wide volume; every row's own hash is checkable, but the export is not
chain-continuous on its own, because the chain links through other
organizations' rows.

**Chain metadata is the accepted integrity exception to event visibility.**
Rows a caller may not see — private mailbox messages and their inbox
read/ack receipts (`agent.mailbox.*`, visible to the mailbox owner),
session-handoff notes and conversation-handoff links outside its reach — are
hidden whole: their
channel, parties, task and payload never leak. The chain itself still does:
sequence numbers, `prev_hash`/`entry_hash` links, the chain head
(`head_ulid`/`head_hash`), verified totals such as `total_verified`, and the
migration manifest's `{ulid, entry_hash, redacted: true}` placeholder for each
hidden row. That metadata proves the ledger is intact and reveals that a row
exists and roughly when it was written — placeholder and chain-head ULIDs
encode millisecond creation time, and a hidden row's `seq` position bounds how
many rows surround it — so its timing can be correlated with a known author's
other visible activity. It never reveals the row's content, channel or
parties.

One grant widens a restricted row beyond its parties: an
`agent.conversation.handoff` row is also visible to the linked task's
holders (`tasks.claimed_by` or `next_owner`), because a task that was handed
a conversation needs the link — `conversation_id`, `task_id`, `created`,
`by` — to reach it.

Who is a conversation's party is never self-granted. `message_send` accepts
an explicit `conversation_id` from a restricted caller only when it is
already the sender, or the label recipient, of a message in it; a missing
and a foreign id answer the same `not_found`, and a `reply_to` naming a
missing or a foreign message answers alike too. New conversations take a
hub-minted id or inherit one through `reply_to`. The one exception is
`crew_intervene`, which after its own profile check and approval gate may
open or join the session's `crew:<session>` thread; a direct `message_send`
naming that id is refused like any other. `crew_view` applies the mailbox
rule to its messages and its `worktree_interventions`: a restricted caller
sees only mail it sent, label mail it received, and session mail addressed
to the session it is viewing; only the session agent and unrestricted
readers get the drop file's `interventions_path`. The worktree's
`.ua/interventions.jsonl` sits in the shared workspace, readable through the
fs tools, so each line holds only `{ts, session_id, message_id}`: no
parties, task or body. `crew_view` treats a line as a pointer, joins its
`message_id` to the mailbox index under the reader's rule, and drops any
line that does not name a crew `request` into that session, so a line
planted by anyone with workspace write access shows nothing. Only the newest
1000 lines are resolved. The drop file
and the task-note marker (`[intervention @ <time>] session=<sid>`, readable
by every caller) show only that the session was steered and when; that
existence and timing are the residual, like the chain metadata above. The
file is opened without following links on unix: the worktree's canonical
path is walked from `/` one directory at a time with `O_NOFOLLOW` (so a
symlink swapped in for any ancestor after the containment check is refused,
not followed out of the workspace), `.ua` is opened the same way, the file is
opened relative to
the `.ua` descriptor with `O_NOFOLLOW`, and it must be a regular file with a
single link, so a symlinked file or `.ua` (even one swapped in after a check)
and a hard link to a file elsewhere are refused. Other platforms check only
before opening: a swap in between, and a hard link, are not caught.

The recipient of session-targeted mail (including the session owner in its
`crew:<session>` thread) is not a party for naming the conversation or
reading its handoff links; it answers through `reply_to`, which does count
it as a party.

A client-chosen `message_id` is the sender's own idempotency key, keyed by
`(organization, sender, id)`; the message itself always gets a hub-minted `message_id`,
and the client id is echoed as `client_message_id`. The sender's retry with
the same id returns the first result; another sender's use of the same id
is independent and answers exactly like a fresh id, so the id reveals
nothing about other senders' messages. The sender's own client id also
resolves as its `reply_to` and in `message_list(message_id=...)`.
`message_list(client_message_id=...)` filters by a sender's key for any
reader, under the same reader rule, so a restricted caller finds only its
own mail. No other tool sees a send's key: `memory_save` stores its keys as
`memory_save/<caller>/<key>` and reads only its own rows, so a memory key
spelling a send's key is a fresh key, never `conflict`, and never occupies
the send's row. An unverified caller may not send as a label the hub sends
as itself (`system`, `pr-watch`, and every `hub-*` label, such as
`hub-node`), so it cannot take a hub client id first.

`agent.lifecycle.handoff` carries only the authoritative handoff-note events.
A hook-reported handoff (`lifecycle_record` with `kind: "handoff"`) goes to
`agent.lifecycle.handoff_hook`, which its writer and note-reading operators
can read and nobody else — the session it names does not grant its owner
access, so one agent cannot place a handoff-shaped row in another agent's
session view or `session_packet`. Rows that `lifecycle_record` wrote to
`agent.lifecycle.handoff` before this change stay there (the ledger is
append-only) and keep that channel's rule. The other lifecycle kinds
(`tool_start`, `stop` and the rest) are ordinary visible observations: any
agent may name any session in one, and its `originator` shows who wrote it.

The Python verifier cannot check `hash_v = 2` rows. That is acceptable because
the Python hub is frozen and never reads a `ua-rust` ledger.

## Converting a table family

Each tenant family gets its organization key in its own change. What every
such change does:

1. **Name the part for the family** (`organization.v1.<crate>.<family>`),
   build it with `tenant_part`, register it after the family's own parts and
   `organization.v1.store`, and add the name to
   `crates/ua-tools/tests/fixtures/schema_part_names.txt`. Never edit or
   extend a released part.
2. **Rebuild first if a key lacks the organization.** A table whose
   `UNIQUE` constraint or non-rowid primary key does not include `org_id`
   needs its key rebuilt ([Global keys](#global-keys-and-table-rebuilds))
   before it can leave the missing list. Otherwise an insert in one
   organization collides with another organization's key, and the conflict
   tells the caller that the key exists; `INSERT OR REPLACE` deletes the other
   organization's row; and an upsert's `DO UPDATE` edits it without touching
   `org_id`, so the immutability trigger never fires.
3. **Foreign keys.** The existence trigger does not stop a row in one
   organization from pointing at a parent in another. A child table needs a
   composite `(org_id, parent_id)` reference or a same-organization trigger,
   and every join filters `org_id` on both sides.
4. **Every statement.** Every `INSERT` names `org_id` (the insert guard
   enforces it); every `SELECT`, `UPDATE` and `DELETE` filters on it. The
   value is the caller's organization or, for a system job, the organization
   of the row it acts on; never a tool argument. A lookup by id answers
   another organization's row exactly as it answers a missing one.
5. **Find every other reader and writer.** Search the whole workspace for the
   table name: the importer's mapping, export and backup, the HTTP and
   compatibility routes, the UI, observability, other parts' triggers and
   views. A `SELECT *` read by position, or an `INSERT … SELECT *`, breaks when
   the column is added; a trigger or view that copies rows elsewhere must
   carry `org_id`.
6. **Refuse an unknown organization in code** before the first delete or
   update. The existence trigger fires only on insert, so a write with
   nothing to insert would otherwise pass.
7. **Indexes.** A large table, or one queried per organization, gets an index
   led by `org_id` in a new static part.
8. **Events.** Name `DEFAULT_ORG` only while `org_guard` requires it, mark the
   site `ORG-EVENT-DEFAULT`, and keep payloads free of content another
   organization should not see.
9. **Tests**, after `crates/ua-tools/tests/code_tenant.rs`: an upgrade from a
   database without the part (rows backfilled, triggers present) and an
   idempotent re-open; two organizations through every tool of the family,
   with the same key in both where the table has one; an unknown organization
   refused with nothing changed, including a write with nothing to insert;
   default-organization results and events unchanged. Give the second
   organization the profiles its test callers use.
10. **Classification.** Remove the tables from `TENANT_MISSING_ORG_ID` only,
    never from its frozen baseline, and update the status list above and the
    [Scoping per subsystem](#scoping-per-subsystem) table.

## Where the code lives

- **`ua-org`**, a new workspace crate: users, memberships, settings, offices,
  teams, members, reporting, specs, proposals, the `authz` module, the edge
  check and approval eligibility. Its tools register through `ua-tools`, which
  stays a thin registry and envelope; no organization logic is added to
  `ua-tools` beyond the calls into `ua-org`.
- **`ua-store`** gains the `org::tenant_part` helper and the `Procedure` part
  kind ([Schema](#schema)), and a `repo` module with an `OrgRepo` trait and its
  SQLite implementation. `ua-org` reaches the database only through that trait, and
  the trait exposes no `rusqlite` types. Methods are synchronous and run inside
  the hub's existing write transaction, because each write must commit
  atomically with its ledger append. A PostgreSQL backend is a later decision;
  this trait is where it would plug in, and the bundled SQLite WAL store stays
  the zero-configuration default.

## The importer

`organization.v1` adds `org_id` to the target tables, which would turn today's
refusal into a silent copy: once the column is mapped, source values are copied
verbatim, a source `NULL` fails `NOT NULL` (an explicit `NULL` bypasses the
default), and a non-null value points at an organization that does not exist.
So **the same change** makes the importer exclude `org_id` from column mapping
explicitly for every table, and keep refusing rows that carry one, until an
explicit mapping is given:

- **A.** `--drop-org-scope`: every source row goes to `'default'`, and the
  report says so.
- **B.** `--org-map <source_org_id>=<target_slug>`, repeated. Every distinct
  non-NULL source `org_id` must be mapped, or the import refuses and lists the
  unmapped ones. Source rows with `NULL` go to `'default'`, and a mapping to
  `default` is allowed. This is the cutover path.

The importer still requires a target ledger holding no events it did not write
(today's rule), so it runs against a fresh store before the hub first serves.
For option B it **creates the mapped organizations itself**, as `orgs` rows
with no ledger events, then imports the source chain unchanged (`hash_v = 1`).

`ua-import` is resumable and supports catch-up runs (`import_runs.last_key`),
so the completion event cannot be written on every run: a catch-up after it
would append `hash_v = 1` rows after a `hash_v = 2` row, which `verify()`
refuses. So:

```sql
CREATE TABLE IF NOT EXISTS import_org_map (
    source_hash   TEXT NOT NULL,
    source_org_id TEXT NOT NULL,
    target_org_id TEXT NOT NULL REFERENCES orgs(id),
    PRIMARY KEY (source_hash, source_org_id)
);
CREATE TABLE IF NOT EXISTS import_finalized (
    source_hash  TEXT PRIMARY KEY,
    finalized_at TEXT NOT NULL,
    event_ulid   TEXT            -- NULL only for the legacy backfill marker
);
```

- Each run records its mapping in `import_org_map`; a later run with a
  different mapping for the same source is refused.
- Ordinary and catch-up runs write **no** `hash_v = 2` row. They are refused if
  the target holds any `hash_v = 2` row.
- `ua import python-hub --finalize` is the explicit last run: it imports any
  remaining rows, appends the completion event — which records the full mapping
  — as the first `hash_v = 2` row, and writes `import_finalized`.
- Finalization is **target-wide**: `--finalize` finalizes every source
  imported into that target at once, so a hub built from two sources imports
  both, then finalizes once. After finalization every further import into that
  target is refused.
- `ua serve` refuses to start on a store with an import recorded but not
  finalized, so the hub cannot append `hash_v = 2` rows ahead of a catch-up.
- **Stores imported before this design** already hold `import_runs` rows and
  hub-written events. `import_finalized` and `import_org_map` are created by a
  `ua-store` procedure part, `organization.v1.import-marker`, ordered after
  `organization.v1.store` (`import_org_map` references `orgs`), which both
  `ua serve` (`Hub::open`) and `ua import` apply, so the check `ua serve` makes
  never depends on a part only the importer applies. When `import_runs` exists,
  that part backfills a legacy marker (`event_ulid` NULL) for every
  `source_hash` already recorded, so those hubs keep starting and are treated
  as finalized; their chain is already `hash_v = 1` throughout and verifies as
  today. On a store never imported, `import_runs` does not exist and nothing is
  checked.

`verify()` therefore always sees the order it requires. The migration manifest
compare records the mapping in its fingerprint.

Imported ledger rows keep `hash_v = 1`, so the `org_id` the mapping assigns to
them is **not** covered by their hash. Imported boundaries are as trustworthy as
the import run that set them, which is recorded on `import_runs` and in the
completion event.

## What this is not

- **Not a tool-permission matrix.** Capability stays with profiles and the
  policy file, bounded by each organization's `allowed_profiles`. Roles decide
  which rows a person administers and which approvals they may resolve; the one
  exception is that approvers see the approval tools.
- **Not hard isolation.** Organizations share one hub and one database. Hard
  data-plane separation per organization was considered and not chosen.
- **Not a job-title system.** Offices carry profiles and a name. No HR
  semantics; reporting edges are informational.
- **Not an external directory.** Users are created by admins or bootstrapped
  from `human_identities`. An external identity provider (OIDC, SAML, SCIM) is a
  later layer that verifies the person and their membership; this model stays
  the authority on what they may do.

## Decisions

The three questions left open in the first draft are settled:

1. **`Caller::system()` belongs to `'default'`.** Hub maintenance runs as the
   default organization. A job that acts for another organization uses
   `Caller::system_for(org_id)`; there is no organization-free caller, so no
   code path can read across tenants by accident. The one sanctioned global
   read is `verify()`, for `'default'` and hub owners.
2. **Offices are runtime data**, not a fixed enum, since the product promise is
   that an operator defines their own.
3. **Tasks are organization-local in v1.** Task identity does not move between
   organizations; a cross-organization handoff is a copy plus a reference.

## Acceptance

Parity and isolation

1. **Single-organization parity.** The existing suite passes unchanged —
   including `goal_manage` refusing `params.org_id` and an agent in `'default'`
   calling `event_log_verify` — the default organization is invisible to
   callers, and a hub with `human_identities = ["operator"]` lets that human do
   exactly what they can do today.
2. **Read isolation, registry-driven.** Seed organization A through the write
   tools of every family, then call every `read_only` tool as a caller in B
   (with A's ids where a tool takes one), plus the SSE event stream, the compat
   API and exports: zero A rows, and A's ids return the same `not_found` as a
   missing id.
3. **Classification.** The `sqlite_master` test fails on an unclassified table,
   on a tenant table whose `org_id` is missing or nullable, and on a tenant
   table missing either generated trigger; FTS virtual and shadow tables and
   SQLite internals pass as classified.
4. **Resolver guard.** The statement-walking test fails if a tenant-scoped
   insert omits `org_id`, in Rust statement strings **or** in any trigger body
   in `sqlite_master`; after `organization.v1`, editing a note in B writes its
   `memory_versions` row with B's `org_id`.
5. **Cross-org references.** Inserting a team member, team office, spec, task
   `team_id` or approval `team_id` that points at another organization fails.
6. **`org_id` is immutable.** An `UPDATE` changing `org_id` on any tenant table
   fails.
7. **Global keys.** After the rebuild, A and B can each create a secret, a skill
   version, a skill assignment, a harness bundle, a project binding and a canvas
   board with the same name, and neither error reveals the other; the same
   idempotency key used in A and B, or by two principals in one organization
   through a per-caller tool (every one but `task_add`, whose keys are
   organization-wide), returns each its own result and the second first-use is
   a fresh call, not a collision; the same node launch key used in A and B succeeds in both; the
   same web search in A and B is cached separately; a rebuild whose rebuilt
   tables fail `foreign_key_check` or that loses a trigger leaves the database
   unchanged and the hub refuses to start, while an unrelated dangling
   reference elsewhere does not stop it; the parts before a standalone part are
   committed and the parts after it apply.
7a. **Schema parts.** Each crate's test database applies its own
   `organization.v1.<crate>.<family>` parts without the other crates' tables; a
   procedure part whose `version` changes is refused as a changed part, while
   one that generated different SQL on a different database is not; a crate
   whose parts read organization tables (e.g. `memory.scope.v1` reads `users`)
   applies the organization parts in its test database first; the `agents` label index part refuses to apply while two
   agent labels differ only in case, and names them.

People and authority

8. **Human derivation.** An admin-created active user with a membership logs in
   as a human; a suspended user, or one with no active membership, does not; an
   owner or auditor of a suspended organization logs in read-only; an OAuth
   grant never does.
9. **Hub-owner binding.** A label added to `human_identities` whose `users` row
   a tenant admin created is not a hub owner, and `system_doctor` reports it;
   `ua org adopt-owner` revokes that row's credentials before adopting it.
10. **Authz guard.** The test fails on `is_human(`, `is_lifecycle_operator(`, a
    `fn is_human` or a profile match used as authority outside `authz`, in any
    workspace crate other than `ua-org` (including `ua-memory`), except the
    `ua-core` primitive definitions and `ua-core`'s own unit tests; for each row
    of the authority table, a `member` and an `auditor` are refused, and a
    caller in B is refused on A's target (for example minting a token for A's
    agent); a lifecycle operator whose label is a `'default'` agent or a hub
    owner may retire a node in any organization, and a same-named label
    resolving to anything else may not.
11. **Hub scope.** A hub-scoped tool is refused to an agent and to a human
    outside `'default'`; its approval is refused to an `org_admin` and accepted
    from a hub owner; `org_create` (with its first owner) and `org_suspend` are
    hub-owner only.
12. **Profiles.** Assigning a profile outside `allowed_profiles` to a session,
    office, seat, agent default or membership is refused; a tenant `team_lead`
    with the `reviewer` profile sees `approval_resolve`; a tenant agent with no
    default gets `developer`.
13. **Suspension.** A suspended organization's callers get `org_suspended`
    except owner and auditor reads; its nodes receive no work. Only a hub owner
    can suspend a user.
14. **Bootstrap.** A label in `human_identities` gets one `org_owner`
    membership once; removing that membership explicitly survives a restart;
    removing the label from the config removes hub-owner authority but not the
    membership; once `memory.scope.v1` has applied, the person's agent-owned
    memory notes are re-owned to the user once through the memory hook, and
    before it the bootstrap succeeds without touching memory.
15. **Two-person rule.** Granting `team_lead` or above, and issuing a credential
    for another human, are refused without an approval from a different
    eligible human who is not the subject; a hub owner's own request proceeds
    and is recorded; the last owner cannot be removed or demoted.
16. **Cross-org people.** An `org_admin` of B cannot add a user who belongs to
    A, or a hub owner, without a hub owner's approval; issuing such a user a
    credential also needs a hub owner; a user B created and credentialed, once
    added to A with that approval, is not reachable by B's credentials in A
    without A's own membership; `agent_token_issue` refuses a human label.
17. **Label namespace.** Creating a user with an agent's label, or the reverse,
    in any letter case, is refused; creating agent `Builder-1` in B while
    `builder-1` exists in A is refused, including through `touch_agent`'s
    auto-create, so B cannot overwrite A's `agent_lifecycle` row.
17a. **Reserved labels.** A tenant admin, an unverified named caller, and
    `touch_agent` acting for another label cannot create an agent or user whose
    label is in `human_identities`, `lifecycle_operators`, a static token or
    the `[profiles]` map, in any case; a hub owner can, only in `'default'`; a
    static-token agent's own first `session_start` creates its row in
    `'default'` as today, and so do a local stdio caller's and a local CLI
    caller's, while an anonymous HTTP caller (`enforce_auth` off) with the same
    label is refused; a label added to the config while a non-default
    organization holds it makes `system_doctor` report `MISCONFIGURED`, the hub
    still starts, the label gets none of its configured authority, and a static
    token for it does not authenticate, until resolved; a reserved label already
    in `'default'` raises nothing.
17b. **Agent owners.** An `org_admin` cannot set `agents.owner_user_id` alone
    and can clear it; a `member` cannot claim an agent alone; a claim needs the
    user's request plus an `org_admin`'s approval (or the reverse offer and
    acceptance), where the admin is not the user being linked; an agent that
    already has an owner cannot be claimed; only the
    member can turn
    `consolidate_private` on or off; claiming an agent revokes credentials for
    it that another person issued, including one minted before the claim; with
    an owner set, an `org_admin` cannot issue or rotate an agent token, or
    issue a managed token or OAuth grant for it, without the owner's approval;
    such a request parks as `agent_owner`, the owner (a plain `member`) can
    approve it, an `org_admin` and a hub owner cannot; the owner can issue and
    rotate their own agent's credentials directly; the agent's node still mints
    per-dispatch session credentials with no approval.
18. **Resolution.** For each credential row of the resolution table, the caller
    gets the stated organization — including a static token, which resolves to
    `'default'`, and is refused outright while its label is held by another
    organization (17a), and an
    `agent_tokens` row of B; an OAuth grant whose `org_id` differs from
    its subject agent's organization is refused at creation and on use; a UI
    session whose membership is removed is refused on its next request;
    switching organization rotates the session id and CSRF token; `--org`
    without a membership is refused.
19. **Settings.** Each setting changes only through `org_settings_update` by the
    role in the settings table, and records old and new values on the ledger.

Approvals

20. **Routing.** `task_team` when the requester is a member of the task's team
    and the tool is team-routable; `org` for a non-routable tool, when the
    requester names another team's task, or no task; `named_team` for `team_up`;
    `hub` for a hub-scoped tool. An agent cannot set `tasks.team_id`; a lead
    cannot move a task out of, or into, a team they do not lead.
21. **Required authority.** A secret or token action that names a team task is
    `org_admin` and refused to that team's lead; a non-narrowing spec commit
    under `named_team` is refused to the lead and to an escalation target;
    pending approvals from before the migration are reclassified and none ends
    up below its tool's authority.
22. **Eligibility.** Team A's lead approves a `team_lead` approval routed to A;
    is refused on B's, on an `org` one and on a `hub` one; is refused once the
    task moved to another team or the requester left the team; `auditor` and
    `member` are refused; `org_admin` approves `team_lead` and `org_admin`
    ones; a lead removed while an approval is pending is refused; the requester
    is always refused.
23. **Cross-org approval.** An approval created in A cannot be seen, approved,
    denied or revoked from B, and its pass does not satisfy the identical call
    in B for a human who belongs to both.
24. **Escalation.** After `after` elapses, a listed target with `team_lead` or
    above can approve a `team_lead` approval of that team, never an `org_admin`
    one; a target who lost the role cannot; `after` below 15 minutes and a
    target outside the organization are refused at commit; status stays
    `pending` throughout.

Ledger

25. **Integrity.** `verify()` reports a valid chain across `hash_v` 1 and 2; an
    unknown `hash_v` fails; a `hash_v = 1` row after the switch fails; a caller
    in a tenant organization is refused, a caller in `'default'` is not.
26. **Attribution.** An event written by a `system_for(B)` job about B's row
    carries B's `org_id` and appears in B's audit read, not A's; an event about
    a user row carries `'default'`; an organization's export contains no `seq`.

Teams

27. **Spec commit.** A commit against a stale `parent_version` is refused; a
    first commit approved by a team lead is refused; a node, bundle or
    escalation target from another organization is refused; a trust root the
    node did not report, seat budgets above the team budget, an unknown key,
    and a spec over 64 KiB are each refused; an archived team refuses a commit.
28. **Plan determinism.** Two `team_plan` calls on the same spec and rows are
    byte-identical in `static`; a heartbeat or a new run changes only
    `volatile`; changing a seat's node changes `plan_sha256`.
29. **Team up.** An uncommitted spec, an archived team, or a `static` refusal is
    refused; a failed `volatile` check launches nothing and leaves the pass
    reusable; a changed `plan_sha256` needs a new approval.
30. **Edges.** For each edge type, the action is allowed with the edge and
    refused without it (naming the edge); a non-seat agent cannot delegate to or
    observe a governed seat; an `auditor` human can observe; an agent removed
    from its seat but still on the team cannot delegate, observe or review
    until an `org_admin` removes it from the team.
31. **Budgets.** A seat at its cap is refused with `budget_exhausted` regardless
    of fallbacks; a primary marked unavailable falls back within the same pool;
    usage records carry `usage_source`.
32. **Self-organization.** A proposal outside the proposer's teams is refused;
    the daily limit is enforced; the setting off suppresses proposing; a stale
    base is not applied; for each non-narrowing category — including removing a
    `reviews` endpoint or an escalation target — a team lead's approval is
    refused and an admin's is accepted; a lead-approved seat removal leaves the
    agent governed with no edges; apply writes a new spec version.
33. **Teams and reporting.** Deleting a team fails and archiving blocks new
    members, commits and `team_up`; a reporting query for a past date returns
    the supervisor in effect then; only `org_admin` and above write
    `reporting`, and a cross-organization endpoint is refused.

Importer

34. **Exclusion.** Against an `organization.v1` target, a source row carrying
    `org_id` is refused without `--drop-org-scope` or `--org-map`, including for
    `harness_config_bundles`.
35. **Mapping and cutover.** `--drop-org-scope` imports everything into
    `'default'`; an unmapped source id refuses the import; a full two-organization
    cutover with both ids mapped creates both organizations, keeps both
    boundaries, and writes no `hash_v = 2` row; a catch-up run with the same
    mapping imports only new rows and a different mapping is refused;
    `--finalize` appends one completion event after the imported chain, after
    which `verify()` reports a valid chain and any further import is refused;
    `ua serve` refuses to start on an imported but unfinalized store; a store
    imported before this design starts after the upgrade (legacy marker) and
    still verifies; two sources imported into one target finalize together.
