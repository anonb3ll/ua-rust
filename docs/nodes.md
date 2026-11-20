# Remote nodes

A node is a machine that runs agent work for the hub: a laptop, a build
box, a cloud VM. It runs a node client under one agent's token. The client
calls out to the hub and never listens, so a node needs no inbound port.

## Registry

| Route | Tool | Who |
|---|---|---|
| `POST /api/node/register` | `node_register` | The node's agent |
| `POST /api/node/heartbeat` | `node_heartbeat` | The node's agent |
| `GET /api/nodes` | `node_list` + `node_items` | Any verified caller |
| `GET /api/nodes/acceptance` | `coordination_manage` `node_acceptance_status` | Any verified caller |
| `POST /api/node/session_credential` | `node_session_credential` | The node's agent |

A node name belongs to the agent label that first registered it. One agent
holds at most `node_max_per_agent` nodes in service. Host facts are bounded on
write. A node is live while its heartbeat is at most 90 seconds old.
Lifecycle operators retire, un-retire, reassign and forget nodes through
`coordination_manage`. None of these is allowed while the node has queued or
claimed work.

## The work queue

An item is one piece of work for one node: a backend (`codex`, `claude`,
`acp:claude`, ...), a prompt, and a working directory on the node.

```
queued --claim--> claimed --receipt--> finished | failed | killed
   |                 |
   +--cancel--> cancelled      lease lapses --> failed (outcome unknown)
   +--wait runs out--> failed (waiting_expired_node_offline)
```

### Queuing work

`node_dispatch` (or `POST /api/node/dispatch`) always needs a one-time human
approval. The approval binds the node, backend, `cwd`, prompt, model,
permission mode, timeout and task. The identical retry after approval queues
the item and returns `201`. While the approval is pending the call returns
`202` with `approval_id`.

The request is checked before anyone is asked to approve it:

- the node is registered and not retired (`node_retired`);
- the backend is one the node advertises (`backend_unavailable`);
- the node supports any feature the item needs, such as `cwd_realpath` or
  ACP session settings (`node_feature_missing`).

A `launch_key` makes a retry return the item it queued. The key belongs to
the caller and the request: reusing it for other arguments, or from another
identity, is refused (`launch_key_reused`) without revealing the item.

When the node is not live, the item waits for it. The wait lasts up to
`node_queue_wait_s` (default one hour). After that the item fails with
`waiting_expired_node_offline`.

### Claiming

The node's agent calls `node_claim` (or `POST /api/node/claim`). It may wait
up to 30 seconds for work. Each claim:

- adds one to the item's `attempt`;
- sets a lease of `timeout_s` + 300 seconds.

A heartbeat that names the running item (`running`) renews the lease and
returns `cancel`, the ids the node must stop. A lease that lapses fails the
item with `lease_expired_outcome_unknown`. The hub cannot tell whether the
work ran, so the item cannot be restarted until the node's agent or an
operator records the real outcome with `node_item_reconcile` (params
`item_id, status, note`). The hub's failure is kept as `prior`.

A **claim operation** (`claim_op = {id, mode, issued_at}`) makes a claim
durable. If the node loses the answer, it asks again under the same id and
gets the same item while that item is still runnable, without a second
attempt. `mode = "reconcile"` never selects work. It settles a pending
operation and reports what the operation became.

### Receipts

`node_receipt` (or `POST /api/node/receipt`) reports `finished`, `failed` or
`killed`, and returns `201`.

- Every receipt names the claim's `attempt`, an integer. A receipt without
  one is refused (`400`, `receipt.attempt is required`).
- The first receipt wins. A retry returns it with `duplicate: true` and
  `200`.
- A receipt that names an earlier `attempt` is refused (`stale_attempt`).
- A receipt for an item the hub already failed is refused
  (`outcome_unknown`).

Only known fields are stored, and each is bounded. Free text (`text`,
`reason`, `log_capture.error`) is redacted before it is stored, as session
events are.

### Cancel and restart

`coordination_manage` takes these actions. They are open to the item's
requester, the node's agent and operators.

- `node_item_cancel` ends a queued item at once. For a claimed item it sets
  a flag. The node sees the flag in its next heartbeat's `cancel` list and
  reports `killed`.
- `node_item_restart` queues a finished item again, behind a new approval.

### Supervised commands

`node_command_start` (params `node, argv, cwd, timeout_s?, task_id?,
session_id?`) runs an argv on a node that allowlists `argv[0]`. The argv is
never a shell string. The approval shows the argv.

Each claim mints a fence token. The receipt must echo it, and one that does
not is refused (`stale_fence`). When the command ends, its owner gets one
message from `hub-node` with the status, exit code and log location. A
message that could not be sent is retried by the sweep.

`node_command_status` reads a command. `node_command_adopt` changes which of
the owner's sessions is notified. A notice for a session that has ended goes
to the owner's label instead.

### ACP sessions: events, follow-ups, permissions

| Tool (route) | What |
|---|---|
| `node_events` (`/api/node/events`) | Up to 200 session events per call. Strings are redacted. `session_open` binds the session id. `turn_end` on a task item writes one turn summary. |
| `node_followup` | Sends a follow-up into a running ACP session, as `queue` (after the current turn) or `steer` (into it). A human needs no approval. The item's requester needs a one-time approval under the tool name `node_followup` (prod action `dispatch`). It binds the node, backend, `cwd`, task, run, the follow-up's item, mode and key, and the exact text, with a `summary` such as `follow-up (queue) into <item> on <node>`. |
| `node_followups` (`/api/node/followups`) | The node fetches queued follow-ups and acknowledges the ids it will deliver. Delivery is confirmed by a `followup_delivered` event. When the item ends, open follow-ups are dropped. |
| `node_permission` (`/api/node/permission`) | The session asks a human to decide a tool call. The answer is `pending`, `approved` (with the chosen `option_id`) or `denied`. An approval answers one prompt. A cancelled item's prompts are denied without asking anyone, and so is a prompt with no option whose `kind` starts with `allow` (`no_allow_option`): there would be nothing to apply. |

### Session credentials

A node can hand the ACP session it launches for a claimed item its own
short-lived hub credential instead of the node agent's token. The node's
agent asks `POST /api/node/session_credential` with `{node, item_id,
attempt}` and gets a `uas_…` value once (`201`, `Cache-Control: no-store`).
The credential runs as the item's agent under the `acp-session` profile,
reaches only `/mcp`, `/api/tools` and `/api/whoami`, and is bound to the
node, item and attempt. It expires at the claim's lease deadline, idles out
600 seconds after the last heartbeat that names the item, and is revoked by
the item's receipt, a cancel, a lapsed lease, a closed task, retiring the
agent, or an operator. Off unless `session_credentials_enabled = true`; the
node learns the hub supports it from `acp_session_mcp` in the registration's
`hub_features`, and advertises it in its own `node_features`. The full
model, refusal reasons and tool set are in
[auth](auth.md#session-credentials).

### Dispatch runs routed to a node

`dispatch_task` with `node` (plus optional `backend` and `node_timeout_s`)
routes a run to a node of the run's agent instead of starting a local
harness. See [dispatch](dispatch.md#routing-a-run-to-a-node).

## The sweep

`ua serve` runs one sweep every `node_wait_sweep_s` seconds (default 60; 0
turns it off). Each sweep does three things:

- expires waits;
- fails lapsed leases;
- retries owed command notices.

Every claim also runs the sweep for its own node. A claim that finds no
work retries only the notices owed for its own node's items; a receipt
retries only its item's.

## Device acceptance

Before a device takes real work it can pass a harmless acceptance run. The
run queues two items with the built-in `acceptance` backend (no model, no
harness) through the ordinary queue, so the node reaches them through the
same claim, heartbeat, events and receipt paths as real work. The node must
advertise the `acceptance` backend and a worktree root.

| Action (`coordination_manage`) | Who | What |
|---|---|---|
| `node_acceptance_start` (params `node`) | The node's agent or an operator | Queue a run: a `complete` job (3 steps, 120 s) and a `cancel` job (300 s). No approval: neither runs a model. Refused while a run is pending (`acceptance_pending`). |
| `node_acceptance_evaluate` (params `node`) | The node's agent or an operator | Re-evaluate the latest run and record the outcome. |
| `node_acceptance_status` (params `node?`) | Any caller | One node's live evaluation (computed, not recorded), or every node in service's stored summary. Also `GET /api/nodes/acceptance[?node=]`. |
| `node_acceptance_attest` (params `node, run_id, evidence_ref`) | An operator who is not the node's agent | Accept the exact pending run whose checks all passed, naming where the independent verification is recorded (1-1000 characters). |

Each item's prompt is a JSON job spec (`{acceptance: "complete" | "cancel",
run: "acc-<16 hex>", steps, step_s, hold_s?}`). The checks:

| Check | Passes when |
|---|---|
| `launch` | the complete job reported an `acceptance_launch` event |
| `progress` | it then reported `acceptance_progress` steps 1, 2, 3 (`of: 3`), in order |
| `receipt` | it ended `finished` with `backend_status: "success"` and the text `acceptance:complete run=<run> bytes=<n> sha256=<digest>` of the job's expected output |
| `cancel_confirmed` | the cancel job, which the hub cancels as soon as it reports progress, ended `killed` with reason `cancelled_by_hub` and a confirmed `acceptance_stopped` event after launch, step 1 and the heartbeat cancel relay |
| `revocation` | the ownership gate every claim, heartbeat and receipt passes refuses the node to a foreign agent and once it is retired (probed against the stored row; nothing is written) |

A run is `pending`, then `accepted` or `failed`. Passing every check is the
node's own report, so the run stays `pending` (`awaiting_operator_attestation`)
until an operator attests it. A failing check fails the run at once and
cancels its open item. A run still pending 900 seconds after it started
fails `timed_out`, naming whether only the attestation was missing. Every
acceptance receipt re-evaluates its run. Events go on `agent.node`:
`acceptance_started`, `acceptance_failed`, `acceptance_attested`.

With `node_require_acceptance = true`, a node whose latest run is not
accepted (and attested) takes no other work: `node_dispatch`,
`node_command_start` and node-routed `dispatch_task` refuse it with
`node_not_accepted` before any approval is asked for, and `node_claim` skips
real items already queued for it. Acceptance items are claimable only while
their run is the node's live pending run.

An acceptance vouches for the node as it was. Retiring, forgetting or
reassigning the node voids it, as does a registration that changes its
`backends` or `harnesses` or a registration or heartbeat that changes a
reported `code_sha`: a pending or accepted run is marked `failed` with
reason `voided: <why>` (an `acceptance_failed` event; a forgotten node's row
is deleted), and the node runs acceptance again before real work. An
identical re-registration (a restart) keeps it.

## Idle-session wakes

An agent session that sits idle at its prompt runs no hooks, so it does not
see new mail until someone types. A wake has the session's own node
type one fixed line into it: `You have <n> new hub messages; run
message_inbox`. No message text ever reaches a wake; the hub hands the node
ids and counts only.

### Consent

Three locks, all required. Each change is ledgered on `agent.wake.request`
or `agent.wake.grant`.

| Action (`coordination_manage`) | Who | What |
|---|---|---|
| `session_wake_opt_in` (params `session_id, wake?, node?`) | The session's own agent | Ask for wakes (`wake` defaults to `true`), or withdraw the request (`false`), which clears any outstanding offer. `node` names the session's wake node, one of the agent's own nodes (else `node_owned_elsewhere`). A request alone enables nothing. |
| `session_wake_grant` (params `session_id, grant?`) | A verified human only | Grant wakes to that one hub session, or revoke them (`grant = false`, clearing offers). A new session needs a new grant. |
| `session_wake_decline` (params `session_id, reason?`) | Any verified human, a lifecycle operator, or the session's own agent | Decline: revokes any grant and clears offers. A decline only restricts, so no grant-level authority is needed. The decline stays when the session asks again; only a later grant clears it. |
| `session_wake_status` (params `session_id?`) | The session's agent or an operator | One session's state, or every session you may see with fleet counts (requested, granted, awaiting a grant, paused, woken). |

A session is offered wakes only while it is opted in, granted, not declined,
open, has an `external_session_id` (the harness's native id, which the node
matches to a pane), and its agent is not paused, terminated or retired.

### Delivery

The node already holds an outbound channel to the hub, so wakes use it; the
hub never connects to a node. A session wakes only through its *wake node*,
which is always a live node owned by the session's own agent:

1. the node the session named in `session_wake_opt_in` (`node`), and only
   that node;
2. else the agent's one node whose name matches the session's registered
   `host` by short lowercase name (`Box.local` and `box` are one host);
3. else, when several of the agent's nodes share that short name, the one
   whose full name is the host (case-insensitively); still ambiguous, the
   session is not woken until it names its node.

Another agent's node never sees the session, however it is named, and two
machines that share a short name never receive each other's wakes.

| Route | Tool | What |
|---|---|---|
| `POST /api/node/wake` | `node_wake` (`node, wait_s, offer_version, live_sessions?`) | Long-poll up to 30 seconds. `offer_version` must be `3`. Answers `{wakes: [{session_id, external_session_id, unread, newest_seq, expires_at, offer_id}]}`. |
| `POST /api/node/wake/check` | `node_wake_check` (`node, session_id, seq, expires_at, offer_id`) | Right before typing: reserve the one attempt an offer allows. Answers `{session_id, valid, remaining_s}`; type only when `valid`, within `remaining_s`. |
| `POST /api/node/wake/receipt` | `node_wake_receipt` (`node, session_id, seq, outcome, reason?, expires_at, offer_id, delivered_at?`) | Report `delivered` (with `delivered_at`, the node's unix time), `failed` or `skipped` (with a `reason` of 1-64 `[a-z0-9_:.-]`). Idempotent: a resend, or a receipt for an offer that lapsed or was superseded, answers `{recorded: false, duplicate: true}`. |

Only the node's agent may call them; another agent's node is refused
(`node_owned_elsewhere`). A check or receipt for a session whose wake node is
not the calling node is refused (`not_found`), and the offer must have been
made to that node. A node holds at most 2 wake polls open at once (a third
is refused with `wake_poll_busy`). An idle poll only reads: it takes the
write lock only when an offer is due or a breaker reset or pause must be
recorded. The registration's `hub_features` carry `node_wake_v3` and
`node_wake_live_sessions`.

`live_sessions` lists the native session ids that have a pane on the node's
host (at most 64). It keeps idle granted sessions whose wake node is this
node open, since nothing else heartbeats them, and reopens one the reaper
closed for lack of heartbeats; a session that ended any other way stays
ended (`agent.wake.session_revived`). Sessions of other agents, or of other
nodes, are never touched.

### The budget

Gates, in the order the hub applies them on every poll:

| Hold | Rule |
|---|---|
| `offer_outstanding` | An offer has no receipt yet and is younger than 120 seconds. |
| `retry_wait` | A failed or skipped offer is retried 30 seconds later. |
| `breaker` | 3 delivered wakes, or 3 reserved attempts, with no inbox read in between pause the session (`paused_reason = no_inbox_read`) until it reads its mail. |
| `floor` | At least 600 seconds between wakes (delivered or attempted). |
| `hourly_cap` | At most 6 wakes and 6 attempts per hour. |
| `nothing_to_wake` | No unread trigger mail newer than the last woken set: a `request`, `query` or `handoff`, or any message with `expects_reply`. `inform` and `done` wait for the session's own hooks. |
| `debounce` | The newest trigger message is under 20 seconds old and the oldest under 60. |

`unread` is every unread message of the session, counted when the offer is
made. An offer carries a random `offer_id`; a check or receipt must echo it,
`newest_seq` and `expires_at` exactly, so a delayed answer to an old offer
never counts for a new one. A check also re-verifies consent, the trigger
mail and the budget, and is valid once per offer. A `delivered` receipt
counts only when an attempt was reserved and `delivered_at` falls inside the
offer (5 seconds of clock slack) and before any revocation. It advances the
mail cursor and the floor. A `skipped` receipt with reason
`delivery_uncertain` keeps the spent attempt and gives the mail set up. The
final skips (`no_match`, `herdr_missing`, `input_state_unavailable`,
`already_delivered`, `delivery_uncertain`) and the 20th retry of one mail set
leave it to the session's hooks. Offers, attempts (`agent.wake.attempt`) and
outcomes are ledgered on `agent.wake`.

A client that hangs up mid-poll may leave an offer it never received; it
lapses after 120 seconds and the session is offered again.

## Not yet ported

The harness config bundle route (`/api/node/config`) answers `501`.
Resuming or adopting native sessions is not ported either.

## Agent lifecycle and holds

The queue consults the governance controls (see
[policy.md](policy.md#governance-controls)). Queuing work for a node whose
owner is paused, terminated or retired, or for a task under an active
subtree hold, is refused before any approval is asked for. `node_claim`
refuses a stopped owner (`agent_paused`, `agent_terminated`,
`agent_retired`) after the claim's sweep has committed, and skips a held
task's items, which stay queued. Pausing an agent flags its claimed items
for the node to stop and leaves its queued items queued for the resume;
terminating or retiring it cancels both.
