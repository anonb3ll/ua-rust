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

## Profiles

A profile is a capability tier bound to the verified identity and the client
session. `profiles` in the hub config sets each identity's default
(unlisted identities get `developer`, OAuth identities get `oauth_profile`);
`profile_activate` moves a session to a profile no more privileged than that
default, and a `profile_defaults` overlay (below) can only lower it.

| Profile | Rank | Surface |
|---|---|---|
| `coordinator` | 8 | Every tool. Holds config authority: a profile overlay may not demote the last identity configured with it. Moves vault notes, reads every mailbox. |
| `lead` | 7 | The developer surface plus `LEAD_EXTRA_TOOLS` (today all of those are already visible to developer), ranked above it. |
| `developer` | 6 | Every tool except approval resolution, config revisions, dispatch cancellation confirm/retry, commits and merges, `notify`, routines, vault moves and archive plans, and profile switching (deny list: new tools are visible). |
| `reviewer` | 5 | Reads and reviews (deny list): no file writes, commits, merges, worktrees, task claims or deletes, delegation, plan management, coordination, cycles, workflows, memory deletes or approvals. May update another agent's claimed task only to release an expired claim. |
| `operator` | 4 | Allow list: approvals, dispatch cancellation, event log, memory and task reads, node listing. |
| `research` | 3 | Allow list: reads, memory, messages, vault, web, task and plan reads, plus listed `plan_manage` actions. |
| `acp-session` | 3 | Allow list (`ACP_SESSION_ALLOWED_TOOLS`): memory reads and saves, task listing and comments, profile status, session packet, evidence report. The profile of a node session credential, which narrows it further (see [auth](auth.md#session-credentials)). Never assignable: `profile_activate`, config `profiles` / `oauth_profile` and policy `profile_defaults` refuse it, and without a credential's grant it reaches no tool. |
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
| `rate_limit` | `tool`, `max_calls`, `window_seconds` | At most `max_calls` completed calls of the tool by the same caller within the window, counted from the `tool_calls` table (`rate_limited`). Checked after every deny and before any approval is parked. Rule names must be unique among rate-limit rules. |
| `cooldown` | `tool`, `cooldown_seconds` | Minimum gap between two calls of the tool by the same caller (`episode_limited`). |
| `max_calls_per_episode`, `fatigue_band_cap` | `bands`, ... | Accepted and validated, but callers carry no episode here, so a matching rule refuses the call (`episode_limited`). A `cooldown` with `require_episode: true` does the same. |

A rule with no `type` is read as `max_calls_per_episode`, as in the original
hub; always set `type` explicitly.

### Common fields

- `name`: shown in refusals and ledger events.
- `tool`: glob, default `*`.
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
caller's profile; releasing needs the hold's creator or an operator.
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
repository on an allowed forge host.

### Maintenance tools

`cleanup_stale_worktrees` (`max_idle_days`, default 7 and at least 1;
`dry_run`, default true) reports stale task worktrees under the workspace's
`.worktrees/` (task `done` or deleted, or idle; a `blocked` task's worktree is
stale only once idle) and, when a human or lifecycle operator asks with
`dry_run=false`, removes only those with no uncommitted changes, no untracked
files and no ignored files (`git worktree remove` would delete an ignored
`.env` without asking) whose branch the base branch already contains, with
`git worktree remove` and never `--force`.
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
