# Dispatch

`dispatch_task` hands a task to an agent harness: a CLI coding agent that the
hub starts as a child process. The hub tracks each attempt as a run, with a
lease and a fence, and records how it ended.

## Harnesses

A harness is a `[harnesses.<name>]` table in the hub config:

```toml
dispatch_lease_seconds = 300
# dispatch_reaper_interval_s = 100   # default: a third of the lease; 0 = off

[harnesses.coder]
argv = ["agent-cli", "--print", "{prompt}"]
env_allowlist = ["PROVIDER_API_KEY"]
timeout_s = 3600
output_cap_bytes = 1048576
workdir = "~/projects/scratch"   # used when the task records no worktree
pass_agent_token = false
```

`argv` runs without a shell. The placeholders `{run_id}`, `{task_id}`,
`{agent}`, `{fence}`, `{worktree}` and `{prompt}` are substituted literally
into single arguments.

## Who may dispatch and cancel

| Tool | Caller |
|---|---|
| `dispatch_task` | A verified caller that is the target `agent`, or an operator (a human, or the operator profile). |
| `dispatch_report_self`, `dispatch_resume` | The run's agent only. |
| `dispatch_cancel` | The run's agent, or an operator. The run records `cancelled_by`, and the cancel event says whether it acted for another agent. |
| `dispatch_retry_cancellation`, `dispatch_confirm_cancellation` | The operator profile only. |

The shipped operator profile allowlist does not include `dispatch_task` or
`dispatch_cancel`. A session that enforces profiles must therefore be a
human, or run with a wider profile, to reach these tools.

## The approval covers what runs

`dispatch_task` always needs a one-time human approval. The tool gates the
call itself rather than through the registry, because the approval must
cover values the hub resolves from the task and the config, not only the
call's arguments. The approval payload holds:

| Field | Meaning |
|---|---|
| `task_id`, `agent`, `harness`, `lease_seconds`, `prompt` | The call (`prompt` only when the caller supplied one). |
| `run_id` | The run that will be minted. It is derived from the task, its number of earlier runs and the agent, so it is the same when the approved call is retried. |
| `workdir` | The resolved, canonical directory the harness will run in. |
| `argv`, `env_allowlist` | The harness's argv template and environment allowlist. |
| `prompt_source`, `prompt_sha256` | Where the prompt came from (`args` or `task`) and the SHA-256 of the exact prompt text. |
| `prompt_preview`, `prompt_bytes` | For a prompt the hub built from the task: its first 2,000 characters and its full length in bytes, so the approver sees what will run. |
| `passes_token_of` | Present when the harness passes the agent's own hub bearer token to the child. |

The approved call is consumed only when every field still matches. If the
task's notes, its worktree, the harness config or the task's run count
changed after the approval, the call is refused with
`approval_binding_changed`. The refusal names the fields that changed and
requests a new approval for the current values. The consumed approval is
linked to the run in the same transaction. A receipt reports `approved` only
when such a linked row exists, and `unlinked` when it does not.

A pass that no longer matches what would run is reported as
`approval_binding_changed` only when it is within the pass TTL and among the
requester's 50 latest approved `dispatch_task` passes.

Because the tool gates itself, adding `dispatch_task` to `approval_tools` or
to a policy `require_approval` rule adds a second approval of the raw
arguments.

## Routing a run to a node

`dispatch_task` with `node` sends the run to a registered remote node instead
of starting a local harness. The node must belong to the run's `agent`.
`backend` defaults to the first backend the node advertises. The working
directory on the node is the task's worktree when it lies under one of the
node's roots, else the node's first existing root. The approval also binds
`node`, `backend`, `node_cwd` and `node_timeout_s`.

The run is launched as one node work item and records
`evidence_ref = node:<node>:<item>`. Only that item moves or closes the run:

| Event | Run |
|---|---|
| The node claims the item | `running` |
| The node's receipt reports `finished` | `finished` |
| The node's receipt reports `failed` or `killed` | `failed` |
| The item's wait or lease runs out | `failed` |

`dispatch_cancel` cancels a queued item at once (cessation `confirmed`). For
a claimed item it sets the cancel flag and records cessation `unknown`. The
node's receipt then confirms it.

The lease reaper leaves node-routed runs to the queue. `dispatch_resume`
refuses them: dispatch the task again instead. See [nodes](nodes.md).

## Leases, restarts and orphans

A live supervisor renews its run's lease every third of
`dispatch_lease_seconds`. The lease reaper handles runs whose lease has
passed. `ua serve` runs one reaper sweep at startup, then one every
`dispatch_reaper_interval_s` seconds. Only `ua serve` runs the reaper. A
`ua call` or a stdio MCP session does not, so it never judges another
process's children.

At launch the hub records the child's pid, process group and start time,
and its own pid and start time. On Linux the start times come from field 22
of `/proc/<pid>/stat`; on macOS from `proc_pidinfo(PROC_PIDTBSDINFO)`. The
child leads its own group, so the group id is its pid. A later hub process
judges a recorded run like this:

- If the pid now names a process with another start time, the pid was
  reused, which the OS allows only after the old group emptied: the run is
  `already_gone`.
- If the recorded child exited, or is still running in its group, the hub
  probes the group (`killpg(pgid, 0)`). An empty group is `already_gone`.
- If anything in the group still runs, the hub kills the whole group only
  when the hub process that started the child is gone. The run is then
  handed back as `retryable` (`lease_expired_orphan_killed`) or its
  cancellation is confirmed, once the group is empty.

Without that proof, for example when the starting hub is still alive or on
other platforms, the run is reported as `not_ours`. Nothing is signalled,
the expired run fails with `lease_expired_outcome_unknown`, and an operator
must confirm cessation.

## The child's boundary

- The environment starts empty. The child gets the process basics (`PATH`,
  `HOME`, locale, temp and XDG directories), the harness's `env_allowlist`
  and the `UA_DISPATCH_*` binding. Hub secrets and anything in the `UA_`
  namespace are never passed.
- The child leads its own process group. A timeout or a cancel kills the
  whole group.
- The working directory must be an existing absolute directory. It may not
  be the filesystem root or lie inside `$UA_HOME`, which holds the database
  and run logs.
- Run logs go to `$UA_HOME/runs/<run_id>.log`. The directory is created with
  mode 0700 and each log with 0600.
- A program that cannot be started because it is missing, not executable, or
  given too long an argument list fails the run with `failure_class =
  config`. Retrying would not help.
- `HOME` is the operator's real home, not a per-run scratch directory. This
  differs from `run_cmd`. Harness CLIs keep their login state and settings
  under `HOME`, and an empty `HOME` would sign them out.

None of this is isolation. The child runs as the hub's OS user. It can read
anything that user can read, including `$UA_HOME` through a path outside its
working directory. Real isolation needs a separate OS user for harnesses, or
a sandbox or container around them.
