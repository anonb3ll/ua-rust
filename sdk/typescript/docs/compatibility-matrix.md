# Hub and client compatibility

Which SDK version speaks which MCP protocol revision, and which hubs it has
been checked against. Update this whenever either side's contract moves.

## How to read it

- **SDK sends**: `MCP_PROTOCOL_VERSION` in `packages/client/src/hub.ts`.
- **Conformant**: the mock suite (`npm run test:conformance`) proves the typed
  contract (schemas, tool names, response shapes, fail-closed negotiation). It
  does not prove live compatibility; only `npm run test:conformance:live`
  against a real hub does.

| SDK version | Sends protocol | Hub | Status | Notes |
|---|---|---|---|---|
| 0.2.0 – 0.2.1 | `2025-06-18` | original Python hub (handshake ceiling `2025-11-25`) | Compatible | The hub echoes `2025-06-18` back, since it is a handshake revision. |
| 0.2.2+ | `2025-11-25` | original Python hub | Compatible | Newest revision reachable through the classic `initialize` handshake. |
| 0.2.2+ | `2025-11-25` | `ua serve` (this repository) | Compatible, with the gaps in [known-gaps.md](known-gaps.md) | `ua serve` speaks the stateless `2026-07-28` revision and keeps a legacy session mode for `2025-11-25` clients; the SDK uses the legacy mode. |

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

## What "compatible" does not mean

It means the handshake succeeds and the tools this SDK wraps round-trip. It
does not mean every legacy-era capability is used: elicitation, resource
subscriptions and `roots/list` are typed for discovery
(`HubTransport.serverCapabilities`) but not implemented end to end.

## Adding a row

1. Add a row rather than editing an old one; older SDK versions still need
   their compatibility documented.
2. Run `npm run test:conformance` to confirm the typed contract, including
   fail-closed negotiation.
3. Run `npm run test:conformance:live` against at least one hub in the new
   range, and record any failing case in [known-gaps.md](known-gaps.md).
