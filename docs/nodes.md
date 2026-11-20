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

- The first receipt wins. A retry returns it with `duplicate: true` and
  `200`.
- A receipt that names an earlier `attempt` is refused (`stale_attempt`).
- A receipt for an item the hub already failed is refused
  (`outcome_unknown`).

Only known fields are stored, and each is bounded.

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
| `node_followup` | Sends a follow-up into a running ACP session, as `queue` (after the current turn) or `steer` (into it). A human needs no approval. The item's requester needs a one-time approval of the exact text. |
| `node_followups` (`/api/node/followups`) | The node fetches queued follow-ups and acknowledges the ids it will deliver. Delivery is confirmed by a `followup_delivered` event. When the item ends, open follow-ups are dropped. |
| `node_permission` (`/api/node/permission`) | The session asks a human to decide a tool call. The answer is `pending`, `approved` (with the chosen `option_id`) or `denied`. An approval answers one prompt. A cancelled item's prompts are denied without asking anyone. |

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

Every claim also runs the sweep for its own node.

## Not yet ported

These routes answer `501`:

- the idle-session wake transport (`/api/node/wake`, `/wake/check`,
  `/wake/receipt`);
- the harness config bundle (`/api/node/config`);
- per-item session credentials (`/api/node/session_credential`).

These are not ported either:

- device acceptance runs;
- resuming or adopting native sessions;
- Hermes profile binding (`acp:hermes`);
- the agent lifecycle (pause and terminate) that the original queue consults.
