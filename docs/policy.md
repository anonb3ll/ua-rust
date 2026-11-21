# Policy file

Profiles decide which tools a session can see. The policy file decides
whether one visible call may run. Point `policy_file` in the hub config at a
YAML file:

```toml
policy_file = "~/.config/ua/policy.yaml"
```

The gateway reads the file on each governed call and caches the parsed result
by path. It reloads the file when its modification time or size changes, so
an edit takes effect on the next call without a restart.

## Fail-closed behaviour

| File state | Effect |
|---|---|
| `policy_file` unset, or the file does not exist | No policy: every call the profile allows goes on to the approval gate. |
| The file exists but cannot be read, is not valid YAML, or fails validation | Every governed call is refused with `policy_unavailable` until the file is fixed. |
| `enabled: false` | The rules are ignored; calls are allowed. |

## Where it sits in the call path

1. Profile check (a `profile_defaults` overlay can lower an agent's profile first).
2. Policy rules: deny, rate limit, or `require_approval`.
3. Prod-action identity check for always-gated tools (below).
4. Approval gate. A `require_approval` match sends the call through the
   approval queue even when the tool is not in `approval_tools`.
5. Argument validation, then the tool runs.

Every refusal appends an `agent.gateway.decision` ledger event with
`decision: deny`, a `reason_code`, and `rule` naming the rule that fired.

A call of a tool that takes an `action` (`plan_manage`, `delegation_manage`,
...) runs steps 1-4 twice: under the tool's own name, and under the name of
the action it runs (see [Consolidated tools](#consolidated-tools)).

## Consolidated tools

Several tools dispatch on an `action` argument. Many of their actions run
the same handler as a standalone tool: `plan_manage` with
`{"action": "delete", "params": {"plan_id": ...}}` deletes exactly what
`plan_delete {"plan_id": ...}` deletes. A gate names a tool, so a gate on
`plan_delete` holds whichever of the two the caller uses:

- **Profile.** Besides the consolidated tool (and its action, for the
  profiles with action lists), the profile must allow the standalone tool.
  An allow-list profile may instead name it in its action list
  (`RESEARCH_ALLOWED_ACTIONS` lists `plan_create`, so `research` creates
  plans through `plan_manage` without seeing `plan_create`).
- **Policy rules.** Rules are evaluated for the consolidated tool's name on
  the call's arguments, and again for the standalone name on the action's
  `params` (so a `threshold` field path is the standalone tool's). Either
  refusal refuses the call. A rate limit or cooldown on the standalone name
  counts calls through the consolidated tool too. `default_action: deny` is
  applied to the consolidated tool's name only: a rule allowing
  `plan_manage` does not need one for each of its actions.
- **Approvals.** `approval_tools`, a `require_approval` rule and an
  always-gated flag on the standalone name gate the call. The approval binds
  the standalone tool's name and the action's `params` (through the
  standalone tool's `gate_payload` projection, when it has one): exactly
  what a direct call binds. A pass approved for `plan_delete {"plan_id":
  "p-1"}` therefore runs that delete once, through either tool, and nothing
  else. When the consolidated tool's own name is gated as well, the one
  approval covers the call; every other action still parks under the
  consolidated tool's name, as before.
- **Prod-action check.** An always-gated standalone tool's identity check
  applies to the consolidated call as well.

`handoff` is a door to `delegate` in the same way: it creates a delegation
with `callback: "none"`, so it is held to `delegate`'s profile entry, policy
rules and approval gate, on the arguments of the equivalent `delegate` call
(`agent` as `from_agent`, plus `callback: "none"`). A pass for that
`delegate` call serves the handoff, once.

An action with no standalone tool is gated under the key `tool:action`, for
example `plan_manage:close` or `coordination_manage:queue_park`. List it in
`approval_tools` or name it in a rule's `tool` (a glob such as
`plan_manage:step_*` works too); its approval binds the whole call
(`{action, params}`). An action of `export_data` that makes a governed call
itself (`manifest`, `compare`) is gated once, by that inner call, under its
own name. For a tool whose handler binds its own approval (`relay_manage`), its keys
take policy rules; an `approval_tools` entry adds nothing, since the handler
already asks a human for every send. The same holds for the own actions
whose handler always asks a human itself (`oauth_device_manage:revoke`,
`coordination_manage:node_command_start`,
`coordination_manage:node_item_restart`, `config_revision_manage:commit`
and `:rollback`): the call takes that one approval, and a request ahead
answers `409` as for the tool itself. Any other own key the registry binds
can be requested ahead under its key.

A call with no `action` is the tool's default action (`list` for
`oauth_device_manage` and `config_revision_manage`, `call` for
`mcp_gateway`, `get` for `node_config`) and is gated as that action. Each
consolidated tool's handler dispatches on the action the table resolves, so
the registry and the handler always agree on which action runs.

An `action` that the routing table does not know is refused
(`invalid_argument`) before the tool runs. The `agent.gateway.decision`
event of a refused call names the tool called in `tool` and the action in
`action_tool`; an approval's `agent.approval.requested` and
`agent.approval.consumed` events carry `via` (the tool called) when it binds
a different name; the call's `tool_calls` row carries `action_tool`.

An `approval_tools` entry or a plain-named policy rule written
`tool:action` for an action that has a standalone tool also restricts that
tool (`plan_manage:delete` gates `plan_delete`, through either door), and an
alias spelling of an own action restricts its key. The reading only ever
restricts: a `deny`, `require_approval`, `role`, `threshold`, rate limit or
cooldown applies to the standalone tool too, while an `allow` stays literal
(it allows the `plan_manage` door's `delete` key, nothing else), and an
alias match never counts as a permission under `default_action: deny`. `system_doctor` still reports
such a spelling, and a `tool:action` name that matches nothing, as
`DEGRADED` (the policy file also logs a warning when it loads), naming the
name to write.

A platform object read through a consolidated tool (`platform_object_get`
for a `plan`, whose `profile_tool` is `plan_manage`) is also checked as that
tool's `get` action: `plan_get`'s profile entry, policy rules and
`approval_tools` entry apply to the read.

Other tools that share a handler or a creation path with a differently
named tool were checked: `handoff` (above) is the only second door to
another tool's operation. The rest are distinct operations with their own
names and gates: `graph_canvas_restore` writes a stored revision back and is
gated as itself, separately from `graph_canvas_write`. The scene it writes
once passed `graph_canvas_write`, but a deny on `graph_canvas_write` does
not stop a restore, so to freeze canvases deny both (`tool:
"graph_canvas_*"` covers them); `workflow_run`,
`langgraph_run`, `langgraph_workflow_run` and `routine_fire` start
different run kinds, and every step of a run is itself a governed call;
`dispatch_resume` and `dispatch_task` gate in their handlers under their own
names; agent lifecycle actions (`agent_terminate`, `agent_retire`) cancel
node items and runs and revoke credentials as consequences of the lifecycle
change, not as calls of `dispatch_cancel` or the revoke tools;
`profile_reset` and `profile_activate` share a binding helper only.

The table (`crates/ua-tools/src/routes.rs`) decides every action of every
such tool; a test fails when a tool or an action has no entry.

| Tool | Action → standalone tool | Gated as `tool:action` |
|---|---|---|
| `plan_manage` | `create` → `plan_create`, `update` → `plan_update`, `get` → `plan_get`, `list` → `plan_list`, `checkpoint` → `plan_checkpoint`, `resume` → `plan_resume`, `step_retry` → `plan_step_retry`, `step_claim` → `plan_step_claim`, `handoff` → `plan_handoff`, `delete` → `plan_delete` | `close`, `step_add`, `step_edit`, `step_remove`, `step_reorder`, `edit` |
| `delegation_manage` | `create` → `delegate`, `list` → `delegate_list`, `claim` → `delegate_claim`, `release` → `delegate_release`, `cancel` → `delegate_cancel`, `spec_check` → `delegation_spec_check`, `spec_template` → `delegation_spec_template`, `spec_build` → `delegation_spec_build` | `fail`, `complete`, `retry`, `get`, `lookup` |
| `observability_manage` | `activity` → `agent_activity`, `metrics` → `metrics_snapshot`, `anomalies` → `check_anomalies`, `performance` → `perf_summary`, `agents` → `agent_list`, `context` → `agent_context` | `delegation_stats` |
| `coordination_manage` | `agent_list` → `agent_list`, `agent_context` → `agent_context` | every other action (61) |
| `autonomous_cycle_manage` | `start`, `get`, `transition`, `kill`, `record_usage`, `list` → `autonomous_cycle_<action>` | `get_for_task` |
| `export_data` | `tasks` → `export_tasks`, `memory` → `export_memory`, `journal` → `export_journal`; `manifest` and `compare` call `export_migration_manifest` and `compare_migration_manifests` as governed calls | (`import` and `rollback` are refused) |
| `config_revision_manage`, `relay_manage`, `oauth_device_manage`, `mcp_gateway`, `skill_registry`, `node_config`, `task_comment`, `goal_manage` | none | every action |

Legacy spellings the tools accept (`plan_delete` as a `plan_manage` action,
`delegate_claim` for `delegation_manage`, `perf_summary` for
`observability_manage`) resolve to the same entry.

### Requesting an approval ahead of a call

`POST /api/approvals/request` runs steps 1-3 for the named tool and its
arguments (a refusal is the same `403` a call would get), checks the
arguments against the tool's typed argument struct, and parks the payload
the tool's gate would bind, without running anything or consuming a pass.
For a consolidated tool's action that is gated under its own name, the
request parks that name and payload, and the response's `tool` says so
(`plan_delete` for `plan_manage` action `delete`).
It answers `409` for a tool step 4 would not gate: only approval-gated tools
can be requested. It also answers `409` for a tool whose handler asks the
gate itself on values it resolves (marked `gates_in_handler`,
`handler_gates_with` or `handler_may_gate`; a test walks every
`approvals::gate` call site and fails for an unmarked tool). A tool with a
secret argument is marked `secret_args` and must bind a `gate_payload`
projection; without one, gating it is refused (`secret_args_unprojected`)
rather than store the secret. The full status table is in
[sdk.md](sdk.md#not-supported).

## Profiles

A profile is a capability tier bound to the verified identity and the client
session. `profiles` in the hub config sets each identity's default
(unlisted identities get `developer`, OAuth identities get `oauth_profile`);
**A profile is a permission set, never authority.** It decides which tools a
session sees. Who may act on another agent's work, read every mailbox or
conversation, see the hub's boundaries, or move vault notes comes from
identity (`ua_org::authz`): an operator is a verified human (`human_identities`),
and an agent in `lifecycle_operators` holds a separate fleet-maintenance grant
(closing, parking and folding tasks, releasing claims and holds, worktree
cleanup, handoff recovery, workflow records, wake handling, node-queue
administration, and agent and node lifecycle), never operator authority. The
Python hub let the coordinator and operator profiles carry authority; ua-rust
does not. A coordinator agent that read every mailbox to route work cannot do
so any more; organization roles (`docs/organization.md`) are what replace it.

`profile_activate` moves a session to a profile no more privileged than that
default, and a `profile_defaults` overlay (below) can only lower it.

| Profile | Rank | Surface |
|---|---|---|
| `coordinator` | 8 | Every tool. A profile overlay may not demote the last identity configured with it (a lockout guard for config revisions). It grants no authority: moving vault notes and reading every mailbox need an operator (a verified human). |
| `lead` | 7 | The developer surface plus `LEAD_EXTRA_TOOLS` (today all of those are already visible to developer), ranked above it. |
| `developer` | 6 | Every tool except approval resolution, config revisions, dispatch cancellation confirm/retry, commits and merges, `notify`, routines, vault moves and archive plans, migration manifests (`export_migration_manifest`, `compare_migration_manifests`, also through `export_data`), and profile switching (deny list: new tools are visible). |
| `reviewer` | 5 | Reads and reviews (deny list): no file writes, commits, merges, worktrees, task claims or deletes, delegation, plan management, coordination, cycles, workflows, memory deletes or approvals. May update another agent's claimed task only to release an expired claim. |
| `operator` | 4 | Allow list: approvals, dispatch cancellation, event log, memory and task reads, node listing. |
| `research` | 3 | Allow list: reads, memory, messages, vault, web, task and plan reads, plus listed `plan_manage` actions. |
| `acp-session` | 3 | Allow list (`ACP_SESSION_ALLOWED_TOOLS`): task listing and comments, profile status, session packet, evidence report (no memory tools). The profile of a node session credential, which narrows it further (see [auth](auth.md#session-credentials)). Never assignable: `profile_activate`, config `profiles` / `oauth_profile` and policy `profile_defaults` refuse it, and without a credential's grant it reaches no tool. |
| `remote-vault-curator` | 2 | The remote assistant surface plus vault access confined to `Wiki/` (and the daily journal). |
| `remote-assistant` | 1 | Allow list: memory reads, messages, task listing and the agent actions of `observability_manage`. |
| `public` | 0 | Allow list: task add and list, docs, profile status. |

The lists live in `crates/ua-core/src/profiles.json`; a test fails if a list
names a tool the hub does not register.

Five profiles had other names in the Python hub. Those names are accepted
for compatibility wherever a profile name is read (config `profiles` and
`oauth_profile`, `profile_activate`, `profile_defaults`, `roles`, profile
config revisions, stored session bindings). The hub always reports the
current name, and config revisions store it.

| Current name | Accepted alias |
|---|---|
| `coordinator` | `chief-of-staff` |
| `lead` | `cto` |
| `reviewer` | `steward` |
| `remote-assistant` | `cloud-assistant` |
| `remote-vault-curator` | `cloud-vault-steward` |

## Format

```yaml
version: 1
enabled: true
default_action: allow        # or deny: refuse tools no permission rule matches

# Identity -> profile. Applied only when it lowers the identity's configured
# default profile; it can never widen access.
profile_defaults:
  example_agent: research

rules:
  - name: no-shell-for-bench
    type: tool
    tool: "run_cmd*"           # glob: *, ?, [...]
    action: deny               # allow | deny | require_approval
    roles: [example_bench_agent]
    description: Bench agents do not run shell commands.

  - name: deletes-need-a-human
    type: tool
    tool: "task_delete"
    action: require_approval

  - name: admins-only
    type: role
    tool: "config_revision_manage"
    roles: [coordinator, example_lead_agent]   # profile names or identity labels

  - name: big-budgets
    type: threshold
    tool: "budget_*"
    field: limits.amount      # dotted path into the call arguments
    max: 500
    action: require_approval

  - name: search-rate
    type: rate_limit
    tool: "web_search"
    max_calls: 30             # 1..1000
    window_seconds: 60        # up to 3600

  - name: deploy-spacing
    type: cooldown
    tool: "deploy"
    cooldown_seconds: 300

  - name: project-scope
    type: tool
    tool: "fs_write"
    action: deny
    bind:
      agent: example_agent
      project: example-project
```

### Rule kinds

| `type` | Fields | Behaviour |
|---|---|---|
| `tool` | `tool`, `action` | Applies `action` to matching tools. `action` defaults to `deny`. |
| `role` | `tool`, `roles` | Allow-list: callers whose identity label or profile is not in `roles` are refused (`role_denied`). An entry `agent:<label>` names an identity, `profile:<name>` a profile; a bare entry is a profile when it is a profile name (current or legacy), else an identity label, so a label that equals a profile name never stands in for that profile. |
| `threshold` | `tool`, `field`, `max` and/or `min`, `action` | Applies `action` when the argument at `field` is above `max` or below `min` (`threshold_breached`). A missing or non-numeric value refuses the call (`threshold_invalid`). |
| `rate_limit` | `tool`, `max_calls`, `window_seconds` | At most `max_calls` completed calls of the tool by the same caller within the window, counted from the `tool_calls` table (`rate_limited`), including calls of a consolidated tool whose action runs it. Checked after every deny and before any approval is parked. Rule names must be unique among rate-limit rules. |
| `cooldown` | `tool`, `cooldown_seconds` | Minimum gap between two calls of the tool by the same caller (`episode_limited`). |
| `max_calls_per_episode`, `fatigue_band_cap` | `bands`, ... | Accepted and validated, but callers carry no episode here, so a matching rule refuses the call (`episode_limited`). A `cooldown` with `require_episode: true` does the same. |

A rule with no `type` is read as `max_calls_per_episode`, as in the original
hub; always set `type` explicitly.

### Common fields

- `name`: shown in refusals and ledger events.
- `tool`: glob, default `*`. It matches tool names and the `tool:action`
  keys of [consolidated tools](#consolidated-tools).
- `roles`: on kinds other than `role`, a filter; the rule applies only to
  callers whose label or profile is listed.
- `bind`: restricts the rule to a scope. Keys: `agent`, `project`, `task`,
  `company`. Project and task are read from the caller's claimed tasks. A
  restrictive rule (deny, require_approval, rate limit) still matches when the
  caller has no claim to compare; an allow rule does not.
- `description`: appended to the refusal message.

Deny beats allow: an `allow` match never cancels another rule's deny, an
exhausted rate limit, or a `require_approval`.

## Prod-action gate

Tools registered as always gated also check the caller's identity before an
approval pass is looked at, so a pass approved earlier cannot carry a call the
caller is no longer entitled to make:

- anonymous HTTP or MCP callers are refused (`anonymous_prod_action`);
- labels in `revoked_agents` are refused (`agent_revoked`);
- when `agent_scopes` is set, a label must list the action (`merge`,
  `delete`, `deploy`, `restart`, `revoke`, `dispatch`) or the tool name
  (`scope_denied`). An unlisted label has no scope.

```toml
revoked_agents = ["example_retired_agent"]

[agent_scopes]
example_lead_agent = "merge|deploy"
```

`git_merge_task` also accepts a **policy authorization** in place of the
one-time approval: a verified human records with
`policy_authorization_record` that a standing policy covers merging one
exact head of one task in its project's bound repository, with an expiry;
the merge names it as `policy_authorization_id` and spends it. The identity
checks above still run first. See [github](github.md#policy-authorizations).

## Governance controls

The policy file and profiles decide whether a call may run. The governance
controls decide who may take work and over which tasks. They are
`coordination_manage` actions (module docs:
`crates/ua-tools/src/families/governance/`), and every change appends a
ledger event in the same write transaction.

### The claim gate

One check, `claim_block`, runs inside the write transaction of every path
that hands out work: `task_claim` (renewals too), `task_update` into
`doing`, `dispatch_task`, `dispatch_resume`, every node enqueue
(`node_dispatch`, `node_command_start`, a node-routed dispatch, checked
before any approval is asked for), `node_claim` and, for the agent part,
`plan_step_claim`. It refuses with a stable reason code:

| Code | When |
|---|---|
| `agent_paused`, `agent_terminated`, `agent_retired` | The agent that would hold the work (the claimant, the dispatch target, or the node's owner) is in that state. |
| `task_held` | The task is a member of an active subtree hold. A live renewal by the current claimant passes. |
| `task_parked` | The task is parked or folded into a parked root (`queue_park`, see [continuity](continuity.md#queue-closure)). Unpark it first. |

`node_claim` refuses a stopped owner after its sweep has committed, and skips
a held task's items, which stay queued until the hold is released.

### Agent lifecycle

| Action | Who | Effect |
|---|---|---|
| `agent_state`, `agent_states` | Anyone | Read the state (`active` when never changed) and owner of record. |
| `agent_pause` (`agent`, `reason`) | An operator, or the agent itself | New work is refused. Live dispatch runs are cancelled (the `dispatch_cancel` path) and claimed node items flagged for the node; queued node items stay queued. |
| `agent_resume` (`agent`) | An operator, or the agent if it stopped itself | Back to `active`. Cannot undo a retirement. A stop an operator imposed is recorded (`imposed_by`) and survives the agent's own later transitions: an operator pause followed by a self-terminate still needs an operator to resume. |
| `agent_terminate` (`agent`, `reason`) | An operator, or the agent itself | As pause, and the agent's `doing` claims return to `open` and its queued node items are cancelled. |
| `agent_retire` (`agent`, `reason`, `owner`) | Lifecycle operators only | Refused while the agent holds `doing` claims. Revokes its `agent_tokens` rows and OAuth sign-ins; the HTTP adapter refuses its static token too. |
| `agent_unretire` (`agent`) | Lifecycle operators only | Back to `active`; re-issues nothing. |

An operator is a `lifecycle_operators` identity (default: the human
identities) or a human. Each result lists `stops` with an honest `control`
(`confirmed`, `requested`, `released`, `unsupported` for a self-picked-up
claim the hub has no process for).

### Task holds and claim release

`task_hold` (`root_task_id`, `mode`, `reason`, `release_policy`) holds a task
and its subtree as snapshotted at hold time. `pause` holds; `cancel` also
cancels the members' live dispatch runs and queued or claimed node items,
each under its own authority (the run's agent or an operator; the item's
requester, node agent, task claimant or an operator); `resume` releases;
`restore` releases once every run the cancel stopped has closed.
`release_policy: after_active_runs_finish` releases the hold by itself once
nothing in the subtree is running. Holding needs `task_update` in the
caller's profile; releasing needs the hold's creator or an operator, verified
either way (an unverified caller's `actor` names nobody).
`task_holds` and `task_hold_get` read.

`task_claim_release` (`task_id`, `expected_claimant`, `reason`,
`expected_run_id`, `expected_claimed_at`) lets an operator release another
agent's live claim. It is fenced on the claimant, the run and the claim
generation, refuses a done or cancelled task and a task with a live dispatch
run, and returns a `doing` task to `open`.

### Work proposals and project bindings

An agent files `work_proposal_file` (1-50 items `{title, notes, scope:
{repo, files}, priority}`); a human decides each item with
`work_proposal_decide` (approve, with optional edits, or reject). Each
approved item becomes one task whose notes start with the contract block:
the item notes, the markers carrying its frozen contract digest (SHA-256 over
its canonical title, notes and scope), and a closing `[end contract]` line.
`task_claim`, `task_update` into `doing`, `dispatch_task` (local and
node-routed), `dispatch_resume` and every node enqueue bound to the task
re-check the whole block and refuse a drifted task with `contract_mismatch`.
The block is the work order: text appended after `[end contract]` (a claim
line, a progress note) passes the check but is commentary, and a prompt the
hub builds from the task carries the block only. Only a verified human caller
decides (the `approval_resolve` rule); an `approver` argument grants nothing
and must name the caller. `work_proposal_withdraw` (the proposer, before any
decision), `work_proposal_get`, `work_proposal_list` and
`work_proposal_recover` complete the set.

`project_repo_bind`, `project_repo_unbind`, `project_repo_get` and
`project_repo_list` bind a project stream to a normalized `owner/name`
repository on an allowed forge host. The binding is the repository a task's
CI checks are verified against, so bind and unbind are for a verified
lifecycle operator or human (`not_lifecycle_operator` otherwise) and are
attributed to that caller; `bound_by` / `unbound_by`, when given, must name
it. Get and list are open.

### Maintenance tools

`cleanup_stale_worktrees` (`max_idle_days`, default 7 and at least 1;
`dry_run`, default true) reports stale task worktrees under the workspace's
`.worktrees/` (task `done` or deleted, or idle; a `blocked` task's worktree is
stale only once idle) and, when a human or lifecycle operator asks with
`dry_run=false`, removes only those with no uncommitted changes, no untracked
files and no ignored files (`git worktree remove` would delete an ignored
`.env` without asking) whose branch the base branch already contains, with
`git worktree remove` and never `--force`. A worktree a running process
uses is never stale; the process table is read from `/proc` on Linux and
through `proc_pidinfo` on macOS, and where it cannot be read every worktree
is kept.
`audit_triage_tasks` runs `security_audit` and files one deduplicated task
per group of findings; a clean audit files nothing.

## Config revisions

`config_revision_manage` keeps append-only revisions of the policy file, the
profile mapping, and the approval rules, each with a SHA-256 content hash.
Actions: `list`, `show`, `diff`, `capture`, `commit`, `rollback`. A `commit`
that changes the file and every `rollback` need a one-time approval from a
human other than the requester; the file is then written atomically
(temporary file and rename). See the module docs in
`crates/ua-tools/src/config_revisions.rs`.
