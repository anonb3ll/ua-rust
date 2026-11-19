# Security policy

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/anonb3ll/ua-rust/security/advisories/new)
rather than in a public issue. Include the version or commit, a description,
and steps to reproduce. You will get an acknowledgement within a week.

## Trust boundaries

- **Agents should run under a different OS user than the hub.** The hub's
  database, configuration and token files are readable by its own OS user.
  Anything running as that user can bypass every in-process check by editing
  the database directly. The CLI's human checks are speed bumps, not a
  boundary:
  - acting as a human needs an explicit `--label`;
  - it is refused when `UA_AGENT_LABEL` is set;
  - the label must be typed back on an interactive terminal.
- **Approvals need a verified human.** Use a human bearer token or browser
  session over HTTP, or the confirmed CLI path on the hub host. A
  client-supplied `resolved_by` is never trusted.
- **Auth is on by default** (`enforce_auth = true`). `/api` and `/ui` refuse
  hosts outside `allowed_hosts`, as protection against DNS rebinding. They
  also refuse state-changing requests that are cross-site or have non-JSON
  bodies.
- **`run_cmd`** runs without a shell, from an allowlist. Interpreters and
  build tools park for human approval. Each call gets a fresh, empty `HOME`
  that is deleted afterwards.
