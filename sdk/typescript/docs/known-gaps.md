# Conformance against `ua serve`

Results of the live conformance suite (`npm run test:conformance:live`)
against `ua serve` from this repository. The mock suite (`npm run
test:conformance`, 23 cases) passes in full and is not repeated here.

Last run: 2026-11-20, `ua` debug build, a throwaway `UA_HOME` configured as in
`.github/workflows/sdk-live.yml` (a static agent token, and a static token for
a `human_identities` label with the `operator` profile). Three consecutive
runs on the same hub, plus one run without the human token, all identical:

| Suite | Cases | Pass | Fail |
|---|---|---|---|
| Live hub, read-only | 10 | 10 | 0 |
| Live HTTP writes | 3 | 3 | 0 |
| Total | 13 | 13 | 0 |

The approval case requests approval for `crew_intervene` (always gated),
checks that the agent token is refused when it tries to resolve the request
(`403`), and, with the human token, denies it as the human.

There are no known failing cases. A case that fails against `ua serve` goes
here with what the server answered; it is not deleted or skipped.

## Not covered by the live suite

The live suite does not call these, and `ua serve` does not serve them (see
[docs/sdk.md](../../../docs/sdk.md#not-supported)):

| SDK method | `ua serve` answer |
|---|---|
| `submitWorkProduct`, `releaseWorkProduct` (`/api/work-products*`) | `501` |
| `startNodeSession`, `cancelNodeSession`, `restartNodeSession` | not served |

`queueHealth` (`GET /api/queue-health`, `404` on `ua serve`) was removed from
this SDK; see the [README](../README.md#not-carried-into-this-repository).
