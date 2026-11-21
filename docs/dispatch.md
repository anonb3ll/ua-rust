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
`{agent}`, `{fence}`, `{worktree}`, `{prompt}` and `{prompt_json}` (the
prompt as one JSON string, quotes included) are substituted literally into
single arguments, in one pass: a value that itself contains `{run_id}` stays
as written.

Optional launch settings:

| Key | Meaning |
|---|---|
| `env` | Fixed, non-secret values for the child, e.g. `{ PI_SKIP_VERSION_CHECK = "1" }`. Values take the placeholders. A name in the `UA_` namespace, a hub secret or a binding name is never set. A credential-looking name (`*TOKEN*`, `*SECRET*`, `*_KEY`, ...) or value (a provider key, a bearer or basic credential, a password assignment, a URL with a password, a private key) is refused when the config loads. |
| `env_denylist` | Names never passed, whether inherited, allowlisted or fixed in `env`. |
| `path_prepend` | Absolute directories put in front of the child's `PATH` (`~` is expanded). A relative or empty entry, or one containing `:`, is refused when the config loads. The program in `argv[0]` is looked up on the child's `PATH` when the run is approved, and that absolute path is what runs. |
| `stdin` | Text written to the child's standard input, which is then closed. Takes the placeholders. Unset, standard input is empty. |
| `provider_account` | The [provider account](#provider-accounts) the harness bills. |
| `provider_fallback` | When that account cannot take a run, use another harness of the same provider and billing type (default `false`). |
| `provider_fallback_cross_billing` | Let `provider_fallback` pick an account of another billing type too (default `false`). |
| `quota_patterns` | Case-insensitive phrases that, on a line of the child's standard error, mark a failed run as hitting its provider's usage limit. Empty (the default), no run of the harness is a quota failure. |
| `quota_json_errors` | Also match `quota_patterns` against structured JSON error events on standard output, as Pi's `--mode json` writes them (default `false`). |

**Secrets.** A secret never goes in `env`: list its name in `env_allowlist`
and the child inherits it from the hub's own environment. A mapping from a
managed secret to a child environment name arrives once the managed secret
store is merged; until then the hub's environment is the only source.

## Who may dispatch and cancel

| Tool | Caller |
|---|---|
| `dispatch_task` | A verified caller that is the target `agent`, or an operator (a verified human). A profile grants nothing. |
| `dispatch_report_self`, `dispatch_resume` | The run's agent only. |
| `dispatch_cancel` | The run's agent, or an operator. The run records `cancelled_by`, and the cancel event says whether it acted for another agent. |
| `dispatch_retry_cancellation`, `dispatch_confirm_cancellation` | An operator (a verified human), under a profile that lists the tools. |

The shipped operator profile allowlist does not include `dispatch_task` or
`dispatch_cancel`. A session that enforces profiles must therefore be a
human, or run with a wider profile, to reach these tools.

`dispatch_task` and `dispatch_resume` also run the governance claim gate
before any approval is asked for: a paused, terminated or retired target
agent (`agent_paused`, `agent_terminated`, `agent_retired`) or a task under
an active subtree hold (`task_held`) is refused. A task an approved work
proposal spawned must still match its frozen contract (`contract_mismatch`),
and a prompt built from such a task carries the contract block only, not
notes appended after it. See [policy.md](policy.md#governance-controls).

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
| `program` | The absolute path `argv[0]` resolves to (on the child's `PATH`, or joined to `workdir`); the launch runs exactly that file. `null` when nothing was found, which fails the launch with `failure_class = config`. |
| `prompt_source`, `prompt_sha256` | Where the prompt came from (`args` or `task`) and the SHA-256 of the exact prompt text. |
| `prompt_preview`, `prompt_bytes` | For a prompt the hub built from the task: its first 2,000 characters and its full length in bytes, so the approver sees what will run. |
| `passes_token_of` | Present when the harness passes the agent's own hub bearer token to the child. |
| `env_sha256` | Present when the harness sets `env`: each name with the SHA-256 of its value. Values are never shown raw. |
| `env_denylist`, `path_prepend`, `stdin`, `provider_account` | Present when the harness sets them. |
| `rerouted_from` | Present when `provider_fallback` replaced the requested harness: `{harness, provider_account, billing, reason, to_provider_account, to_billing}`, both accounts' billing included. `harness` is then the harness that runs. |

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

## Provider accounts

A provider account is a registry row an operator keeps for each model
account harnesses bill. It is metadata only: provider, label, billing,
enabled, notes and cooldown. It holds no secret and no secret name (a
harness's credentials come from its `env_allowlist`), and notes that read
like a credential are refused.

| Tool | Caller | What |
|---|---|---|
| `provider_account_register` (`provider, label, billing, enabled?, notes?, cooldown_s?`) | An operator (a verified human) | Add an account. `billing` is `api`, `subscription` or `local`. `label` is what a harness names. |
| `provider_account_update` (`label`, any field, `rate_limited_until?`, `clear_error?`) | Operators | Change it, mark it rate-limited until a time (an empty string clears the limit), or forget its last error. |
| `provider_account_disable` (`label, reason?`) | Operators | Disable it; `provider_account_update(enabled=true)` re-enables. |
| `provider_account_list` (`include_disabled?`) | Any caller | The registry with its observed state. |
| `provider_quota_status` (`label?, recent?`) | Any caller | Per account: `availability` (`available`, `rate_limited`, `disabled`, or `unknown` when nothing was observed), `rate_limited_until`, the last error class, the harnesses that bill it, and a summary of its recent runs by state and failure class. Harnesses that name an unregistered account are listed under `unregistered_accounts`. |

Changes are ledgered on `provider.account`. The operator profile allowlist
includes all five tools; the reviewer profile cannot change accounts.

**What the hub observes.** Each dispatch run records its harness's account.
When a run fails, the hub reads only the signal its harness declares: one of
its `quota_patterns` on a line of the child's standard error (the last 8 KiB,
kept apart from the combined log), or, with `quota_json_errors`, in the
error text of a structured JSON error event on standard output (a JSON
object with `type = "error"`, or whose `message.stopReason` is `"error"`).
The model's own output is never matched. A match gives the run
`failure_class = provider_quota_exhausted` and marks the account
rate-limited for its `cooldown_s` (default 3600 seconds). The
`rate_limited_observed` event carries `signal: {source, line}`: `stderr` or
`json_error`, and the matched line, credentials redacted, at most 200
characters. A self-reported `failure_reason` that reads like a usage limit
is advisory: the run gets `failure_class = provider_quota_reported` and a
`quota_reported` event, and the account is not rate-limited. Any other
failure records the account's last error class, and a finished run its last
success. The hub never probes a provider to measure usage. An operator
lifts a limit with `provider_account_update(rate_limited_until="")`.

**What dispatch does with it.** Before any approval is asked for,
`dispatch_task` checks the harness's account:

| Reason code | When |
|---|---|
| `provider_account_unknown` | The harness names an account that is not registered. |
| `provider_account_disabled` | The account is disabled. |
| `provider_rate_limited` | The account is rate-limited until a future time. The message says until when. |
| `subscription_api_key_passthrough` | The account's billing is `subscription` and the harness's `env_allowlist` passes an `*_API_KEY` name its `env_denylist` does not deny, so the CLI could fall back to metered billing. |

With `provider_fallback = true` on the harness, dispatch instead runs the
first other harness (by name) whose account has the same `provider` and
`billing` (any billing with `provider_fallback_cross_billing = true`), is
available and passes the subscription key check, and reports
`rerouted_from` with both accounts' billing. The approval binds the harness that
runs. With no such harness the original refusal stands. `dispatch_resume`
never reroutes: a resume must run what was approved, so it is refused with
the same codes.

## Pi

[Pi](https://pi.dev) runs as an ordinary harness, not a separate tool. Print
mode runs one prompt and exits; `--mode json` writes its events as JSON
lines, which land in the run log:

```toml
[harnesses.pi]
argv = ["pi", "--print", "--mode", "json", "--provider", "openai-codex",
        "--model", "gpt-5.5", "--no-session", "{prompt}"]
env_denylist = ["OPENAI_API_KEY", "PI_API_KEY", "OPENROUTER_API_KEY",
                "ANTHROPIC_API_KEY", "GEMINI_API_KEY"]
path_prepend = ["~/.local/bin"]
timeout_s = 3600
provider_account = "pi-subscription"
quota_patterns = ["usage limit", "insufficient_quota", "rate_limit"]
quota_json_errors = true
```

The conventions carried over from the original hub's Pi runner:

- `--provider` and `--model` are always given, so Pi never takes a provider
  from its own settings file and bills an account nobody chose.
- Metered keys the subscription must not fall back to are denied with
  `env_denylist`, even when the hub's own environment holds them. Dispatch
  refuses a subscription harness whose `env_allowlist` passes an
  `*_API_KEY` name it does not deny (`subscription_api_key_passthrough`).
- A usage limit is read from Pi's JSON error events (`quota_json_errors`),
  never from the model's text.
- Pi usually lives in `~/.local/bin`, which `path_prepend` puts on the
  child's `PATH`.
- `UA_AGENT_LABEL` is the run's agent, from the dispatch binding.

To keep the prompt out of the process list, drop `{prompt}` from `argv` and
hand it over on standard input to a CLI that reads it there: `stdin =
"{prompt}"`, or a JSON request such as `stdin =
'{"type":"prompt","message":{prompt_json}}'`.

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

Without a `prompt`, a routed run's prompt is built from the task and does
not ask the session to report: the node's receipt does. `dispatch_report_self`
refuses a node-routed run. The lease reaper leaves node-routed leases to the
queue, and finishes an interrupted `dispatch_cancel` through the run's item.
`dispatch_resume` refuses node-routed runs: dispatch the task again instead.
See [nodes](nodes.md).

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

## Hub shutdown

On SIGINT or SIGTERM, `ua serve` drains against one 10-second deadline (see
`serve_until_shutdown` in `crates/ua-cli/src/main.rs`):

1. Every supervisor runs in one task tracker. Runs may finish on their own
   until 3 seconds before the deadline.
2. Each run still going then has its child's process group sent SIGTERM,
   SIGKILL after 2 seconds if it has not exited, and a final SIGKILL sweep
   so no grandchild outlives the run.
3. The run is recorded `retryable`, with failure reason and failure class
   `hub_shutdown` and a receipt whose source is `hub_shutdown`.
   `dispatch_resume` starts it again under a new fence.

A second signal exits at once. It SIGKILLs every live run's group and
records nothing; the next start's reaper sweep reconciles those runs as
described below. Runs left by a hub that was killed outright (SIGKILL, a
crash) are reconciled the same way.

MCP tool calls in flight run as their own tracked tasks, so the drain waits
for them (up to the deadline) even when the MCP session that asked is torn
down. A call still running at the deadline is dropped with the process; a
call that changes state does so inside its own transactions, so nothing is
half-written, but its client gets no answer.

Routine fires are marked `running` before their workflow starts. At the
next start, a fire left `running` is marked `interrupted` and not repeated
(part of it may have run). A fire whose workflow never started runs it then
if the fire is less than a day old; an older one is marked `not_run`. Each
mark is ledgered as `agent.routine.fire_reconciled`.

## The child's boundary

- The environment starts empty. The child gets the process basics (`PATH`,
  `HOME`, locale, temp and XDG directories), the harness's `env_allowlist`,
  its fixed `env` values and `path_prepend`, minus its `env_denylist`, and
  the `UA_DISPATCH_*` binding. The program is the absolute path the
  approval bound. Hub secrets and anything in the `UA_`
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
