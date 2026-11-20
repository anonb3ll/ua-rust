# Getting started

The packages are not on npm. Build them from this directory:

```sh
npm ci
npm test
npm run build
```

## Start a hub

```sh
ua token issue builder-1        # prints the token once; keep it in a secret store
ua serve                        # http://127.0.0.1:8765
```

## Minimal client

```ts
import { UnifiedAgentClient } from "@unified-agent/client";

const client = new UnifiedAgentClient({
  url: "http://127.0.0.1:8765/mcp",
  bearerToken: process.env.UA_AGENT_BEARER_TOKEN!,
});

await client.ping();

const open = await client.taskList({
  status: "open",
  project: "example",
  priority: "high",
});

if (open[0]) {
  await client.taskClaim({
    id: open[0].id,
    agent: "builder-1",
    expected_project: "example",
  });
}

await client.close();
```

A remote hub must be reached over TLS and its host listed in the hub's
`allowed_hosts`; see [auth.md](../../../docs/auth.md).

## Workspace scripts

| Script | What it runs |
|---|---|
| `npm test` | Builds protocol, then the protocol and client tests |
| `npm run typecheck` | `tsc --noEmit` over every package |
| `npm run build` | Emits `packages/*/dist` |
| `npm run codegen` | Exports JSON Schema and regenerates the Pydantic models |
| `npm run codegen:check` | `codegen`, then fails if a committed generated file changed |
| `npm run test:conformance` | The mock conformance suite |
| `npm run test:conformance:live` | The live conformance suite (see the [README](../README.md#conformance)) |

## Tokens

Never commit a bearer token. Pass it through the environment or a
file-backed secret in the host's MCP configuration.
