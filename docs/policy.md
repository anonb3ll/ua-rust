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

## Format

```yaml
version: 1
enabled: true
default_action: allow        # or deny: refuse tools no permission rule matches

# Identity -> profile. Applied only when it lowers the identity's configured
# default profile; it can never widen access.
profile_defaults:
  example_agent: observer

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
    roles: [admin, example_lead_agent]   # profile names or identity labels

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
| `role` | `tool`, `roles` | Allow-list: callers whose identity label or profile is not in `roles` are refused (`role_denied`). |
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

## Config revisions

`config_revision_manage` keeps append-only revisions of the policy file, the
profile mapping, and the approval rules, each with a SHA-256 content hash.
Actions: `list`, `show`, `diff`, `capture`, `commit`, `rollback`. A `commit`
that changes the file and every `rollback` need a one-time approval from a
human other than the requester; the file is then written atomically
(temporary file and rename). See the module docs in
`crates/ua-tools/src/config_revisions.rs`.
