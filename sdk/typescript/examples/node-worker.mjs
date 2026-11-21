#!/usr/bin/env node
/**
 * A small long-lived Node worker showing the session lifecycle this SDK
 * expects a real consumer to follow.
 *
 * What this demonstrates, and why it matters for a worker that runs for
 * hours or days rather than one script invocation:
 *
 * 1. **One client, reused across many calls.** Don't construct a new
 *    `UnifiedAgentClient` per task — the whole point of the single-flight
 *    `ensureSession()` and session-recovery machinery in `HubTransport` is
 *    that one client safely serves many concurrent/sequential calls over
 *    one MCP session, re-handshaking only when the hub actually expires it.
 * 2. **Concurrent calls are safe by construction.** The batch below fires
 *    several `task_claim` calls at once; if the client hasn't handshaked yet
 *    (cold start) they share exactly one `initialize`, not one each.
 * 3. **Timeouts are automatic.** Every request is bounded by
 *    `requestTimeoutMs` (default 30s) — a hung connection can't stall this
 *    worker's loop forever even though nothing here passes an AbortSignal.
 * 4. **Graceful shutdown calls `close()`.** On SIGINT/SIGTERM this worker
 *    stops claiming new work, lets in-flight calls finish, and closes the
 *    session so the hub can release it immediately rather than waiting out
 *    a lock timeout.
 *
 * Run it against a real hub:
 *
 *   UA_HUB_URL=http://127.0.0.1:8765/mcp \
 *   UA_HUB_TOKEN=... \
 *   UA_AGENT_LABEL=my-worker \
 *   node examples/node-worker.mjs
 *
 * (Build the package first — `npm run build -w @unified-agent/client` — this
 * example imports the built output, same as any other consumer would.)
 */

import { UnifiedAgentClient } from "@unified-agent/client";

const HUB_URL = process.env.UA_HUB_URL;
const HUB_TOKEN = process.env.UA_HUB_TOKEN;
const AGENT_LABEL = process.env.UA_AGENT_LABEL ?? "example-node-worker";
const POLL_INTERVAL_MS = Number(process.env.UA_POLL_INTERVAL_MS ?? 5000);
const BATCH_SIZE = Number(process.env.UA_BATCH_SIZE ?? 3);

if (!HUB_URL || !HUB_TOKEN) {
  console.error("Set UA_HUB_URL and UA_HUB_TOKEN to run this example.");
  process.exit(1);
}

const client = new UnifiedAgentClient({
  url: HUB_URL,
  bearerToken: HUB_TOKEN,
  clientName: AGENT_LABEL,
});

let shuttingDown = false;

async function claimAndProcessOneBatch() {
  // Read-only discovery, then a batch of claims. If the client hasn't
  // handshaked yet this tick, ensureSession()'s single-flight promise means
  // this whole batch shares one initialize, not one per call.
  const open = await client.taskList({ status: "open", lane: "default", limit: BATCH_SIZE });
  if (open.length === 0) {
    return 0;
  }

  const claims = await Promise.allSettled(
    open.map((task) =>
      client.taskClaim({ id: task.id, agent: AGENT_LABEL, expected_lane: "default" }),
    ),
  );

  let claimed = 0;
  for (const [index, result] of claims.entries()) {
    const task = open[index];
    if (result.status === "fulfilled") {
      claimed += 1;
      await processTask(result.value);
    } else {
      // Losing a race for a task another worker claimed first is normal —
      // HubRpcError here, not a transport failure. Anything else (timeout,
      // auth) is worth logging loudly.
      console.warn(`claim failed for task ${task.id}: ${result.reason?.message ?? result.reason}`);
    }
  }
  return claimed;
}

async function processTask(task) {
  try {
    // ... do the actual work here ...
    await client.taskUpdate({
      id: task.id,
      status: "done",
      append_note: `completed by ${AGENT_LABEL}`,
    });
  } catch (err) {
    console.error(`task ${task.id} failed: ${err.message}`);
    await client
      .taskUpdate({ id: task.id, status: "blocked", append_note: `${AGENT_LABEL}: ${err.message}` })
      .catch(() => {
        // Best-effort — if even this fails, the task's lock will eventually
        // expire and another worker can pick it up.
      });
  }
}

async function mainLoop() {
  while (!shuttingDown) {
    try {
      const claimed = await claimAndProcessOneBatch();
      if (claimed === 0) {
        await sleep(POLL_INTERVAL_MS);
      }
    } catch (err) {
      // A transport-level failure (timeout, network) here is not fatal —
      // back off and try again. The next ensureSession() call re-handshakes
      // automatically if the session was the problem.
      console.error(`poll failed: ${err.message}`);
      await sleep(POLL_INTERVAL_MS);
    }
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${signal} received, finishing in-flight work and closing session...`);
  await client.close();
  console.log("session closed, exiting.");
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

console.log(`${AGENT_LABEL} starting against ${HUB_URL}`);
await mainLoop();
