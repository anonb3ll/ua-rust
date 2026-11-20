# Known gaps against `ua serve`

Results of the live conformance suite (`npm run test:conformance:live`)
against `ua serve` from this repository, with an agent token (default
`developer` profile) and no human token. The mock suite (`npm run
test:conformance`) passes in full and is not repeated here.

Last run: 2026-11-20, `ua` debug build of `main`, a throwaway `UA_HOME`, three
consecutive runs with identical results.

| Suite | Cases | Pass | Fail |
|---|---|---|---|
| Live hub, read-only | 10 | 10 | 0 |
| Live HTTP writes | 3 | 2 | 1 |
| Total | 13 | 12 | 1 |

## Failing cases

### `queues approvals without executing, and preserves human-only resolution`

The case asks for an approval for `task_update`:

```
POST /api/approvals/request  {"tool": "task_update", "payload": {...}}
→ 409 {"error":"tool \"task_update\" is not configured to require approval"}
```

This is the hub's settled contract, not a hub bug: `POST
/api/approvals/request` answers `409` for a tool nothing gates
([docs/sdk.md](../../../docs/sdk.md), the `requestApproval` table), and
nothing gates `task_update` by default. The fix is in the test: it
should ask for a tool that is always approval-gated, such as `crew_intervene`
(payload `{session_id, message}`). Done by hand against the same hub, that
request answers `202 pending`, and resolving it with the agent token answers
`403 approval resolution requires a human identity`, which is what the case
expects.

CI marks this case as a known gap with `UA_SDK_CONFORMANCE_KNOWN_GAPS`, so it
still runs and is reported as `todo`. Remove it from that list in
`.github/workflows/sdk.yml` when the test is changed.

## Not covered by the live suite

The live suite does not call these, so they are not counted above. `ua serve`
does not serve them (see [docs/sdk.md](../../../docs/sdk.md#not-supported)):

| SDK method | `ua serve` answer |
|---|---|
| `ControlCenterClient.queueHealth` (`GET /api/queue-health`) | `404` |
| `submitWorkProduct`, `releaseWorkProduct` (`/api/work-products*`) | `501` |
| `startNodeSession`, `cancelNodeSession`, `restartNodeSession` | not served |

The human-token branch of the approval case (`UA_SDK_WRITE_CONFORMANCE_HUMAN_TOKEN`)
was not run: `ua token issue` for a `human_identities` label requires an
operator at an interactive terminal.
