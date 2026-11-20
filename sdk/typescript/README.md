# TypeScript SDK

TypeScript packages for talking to a Unified Agent hub such as `ua serve`.
They are an npm workspace with one lockfile:

| Package | What it is |
|---|---|
| [`@unified-agent/protocol`](packages/protocol/README.md) | The contract shapes as Zod schemas, exported to JSON Schema and to generated Pydantic v2 models. |
| [`@unified-agent/client`](packages/client/README.md) | `UnifiedAgentClient` (tools over MCP Streamable HTTP at `/mcp`) and `ControlCenterClient` (the HTTP/JSON routes under `/api`). |
| [`@unified-agent/approval-client`](packages/approval-client/README.md) | An approval client over `approval_pending` / `approval_resolve`, with a Telegram adapter. |

The packages are a typed remote. Policy, approvals, sandboxing, identity and
every write stay on the hub; there is no local fallback. All three are
`"private": true` and are not published to npm.

## Build and test

Node 22 or newer. From this directory:

```sh
npm ci
npm run typecheck
npm test                 # protocol, client (with the mock conformance suite) and approval-client
npm run build            # emits packages/*/dist
npm run codegen:check    # regenerates the schemas and fails if a committed file changes
```

`codegen:check` needs `uv` (it runs pinned `datamodel-code-generator` and
`ruff` through `uvx`) and `python3`. It does not need a hub. The generated
Python models have their own tests:

```sh
cd packages/protocol
uv run --no-project --python 3.12 --with 'pydantic>=2,<3' python -m unittest discover -s tests -p 'test_*.py'
```

`scripts/pack-candidates.mjs` packs the three packages into installable
tarballs under `dist/candidates/` (internal `file:` links rewritten to exact
versions, nothing published), and `scripts/check-candidates.mjs` installs them
into a temporary consumer and checks the imports and types.

## Pointing the client at `ua serve`

```sh
ua token issue sdk-agent        # prints the token once
ua serve                        # http://127.0.0.1:8765 by default
```

```ts
import { ControlCenterClient, UnifiedAgentClient } from "@unified-agent/client";

const hub = "http://127.0.0.1:8765";
const token = process.env.UA_AGENT_BEARER_TOKEN!;
const mcp = new UnifiedAgentClient({ url: `${hub}/mcp`, bearerToken: token });
const cc = new ControlCenterClient({ baseUrl: hub, bearerToken: token });

await mcp.ping();
const tasks = await mcp.taskList({ status: "open", limit: 10 });
const runs = await cc.listRuns({ limit: 5 });
await mcp.close();
```

The hub takes identity, profile and attribution from the token, never from
the request body. Which routes `ua serve` serves, and what it answers for the
ones it does not, is in [docs/sdk.md](../../docs/sdk.md).

## Conformance

`npm run test:conformance` runs the hermetic mock suite (also part of
`npm test`). `npm run test:conformance:live` runs against a real hub and skips
unless it is configured:

| Variable | Meaning |
|---|---|
| `UA_SDK_CONFORMANCE_URL`, `UA_SDK_CONFORMANCE_TOKEN` | The hub's `/mcp` URL and an agent token. Enables the read-only suite. |
| `UA_SDK_CONFORMANCE_AGENT` | Optional label printed in one case name. |
| `UA_SDK_WRITE_CONFORMANCE_URL`, `UA_SDK_WRITE_CONFORMANCE_TOKEN` | The hub origin and an agent token. Enables the write suite, which creates a task, queues an approval and appends evidence; use a disposable hub. |
| `UA_SDK_WRITE_CONFORMANCE_HUMAN_TOKEN` | Optional token of a `human_identities` label, to check that a human can resolve the approval. |
| `UA_SDK_CONFORMANCE_KNOWN_GAPS` | Case names, one per line, that run as `todo`: reported, but not failing the run. |

Results against `ua serve` and the current known gaps are in
[docs/known-gaps.md](docs/known-gaps.md). CI (`.github/workflows/sdk.yml`)
runs both suites, the live one against a `ua serve` it builds and starts.

## Docs

- [docs/getting-started.md](docs/getting-started.md): first calls.
- [docs/overview.md](docs/overview.md): invariants and reliability rules.
- [docs/compatibility-matrix.md](docs/compatibility-matrix.md): which SDK
  version speaks which MCP revision.
- [docs/known-gaps.md](docs/known-gaps.md): live conformance against `ua serve`.
- [examples/node-worker.mjs](examples/node-worker.mjs): a long-lived worker
  that reuses one client and closes it on shutdown.

## License

Apache-2.0, as the rest of the repository. See [LICENSE](../../LICENSE).
