# Hub and client compatibility

Which SDK version speaks which MCP protocol revision, and which hubs it has
been checked against. Update this whenever either side's contract moves.

## How to read it

- **SDK sends**: `MCP_PROTOCOL_VERSION` in `packages/client/src/hub.ts`.
- **Conformant**: the mock suite (`npm run test:conformance`) proves the typed
  contract (schemas, tool names, response shapes, fail-closed negotiation). It
  does not prove live compatibility; only `npm run test:conformance:live`
  against a real hub does.

| SDK version | Sends protocol | Hub | What is proven | Notes |
|---|---|---|---|---|
| 0.2.0 – 0.2.1 | `2025-06-18` | original Python hub | Not checked from this repository | Recorded from the SDK's earlier history. |
| 0.2.2+ | `2025-11-25` | original Python hub | Not checked from this repository | Recorded from the SDK's earlier history. |
| 0.2.2+ | `2025-11-25` | `ua serve` (this repository) | Live suite 13/13 ([results](known-gaps.md)) | The handshake negotiates `2025-11-25` (the legacy session mode). Proven only for what the live suite calls: the MCP read tools it lists, task create/update, approval request with agent-refused and human resolution, and evidence append. |

The SDK fails closed (`HubNegotiationError`) if the hub answers `initialize`
with a revision outside `KNOWN_HANDSHAKE_PROTOCOL_VERSIONS`.

## Two eras on one endpoint

MCP `2026-07-28` is a different transport, not a newer version of the same
one: no `initialize`, no session id, and every request carries its own
`_meta` envelope. A hub that serves both eras decides per connection from the
shape of the first request. A classic `initialize` can never reach
`2026-07-28`, whatever version string it asks for, so a hub reporting
`2026-07-28` as its target is not a gap this SDK closes by changing
`MCP_PROTOCOL_VERSION`. Supporting it means implementing the per-request
envelope transport.

## What a passing live suite does not mean

It proves the handshake and the calls the suite makes, nothing more. Methods
the suite does not call (for example `listRuns`, `platformObject`,
`memorySave`, dispatch control) are covered by the mock suite and by the
hub's own route tests (`crates/ua-server/tests/platform.rs`), not live. Nor
is every legacy-era capability used: elicitation, resource
subscriptions and `roots/list` are typed for discovery
(`HubTransport.serverCapabilities`) but not implemented end to end.

## Adding a row

1. Add a row rather than editing an old one; older SDK versions still need
   their compatibility documented.
2. Run `npm run test:conformance` to confirm the typed contract, including
   fail-closed negotiation.
3. Run `npm run test:conformance:live` against at least one hub in the new
   range, and record any failing case in [known-gaps.md](known-gaps.md).
