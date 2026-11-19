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
  hosts outside `allowed_hosts` and the host of `public_url`, as protection
  against DNS rebinding. They also refuse state-changing requests that are
  cross-site or have non-JSON bodies.
- **Event streams are governed.** `/api/events/stream` and
  `/ui/activity/stream` open with an `event_log_query` call as the caller,
  so a profile or policy that refuses the tool refuses the stream.
- **Dynamic client registration is bounded.** Clients that never receive a
  grant are pruned after `oauth_dcr_unused_ttl_hours`, unused clients are
  capped (the oldest is evicted), and each address may register
  `oauth_dcr_rate_per_hour` clients per hour.
- **`run_cmd`** runs without a shell, from an allowlist. Interpreters and
  build tools park for human approval. Each call gets a fresh, empty `HOME`
  (under `$XDG_RUNTIME_DIR/ua-run/`, else `<temp>/ua-run-<uid>/`, mode
  0700) that is deleted afterwards. What common work needs is set
  explicitly: a git identity `<label> <label@agents.invalid>`, the `bin`
  directory of the hub's default Rust toolchain first on `PATH`, and
  `CARGO_HOME`, `XDG_CACHE_HOME` and `UV_CACHE_DIR` in a cache of the
  caller's own under `$UA_HOME/run-cache/<label>-<digest>/`. Commands never
  get the hub user's `CARGO_HOME` (credentials, config, installed binaries)
  or `RUSTUP_HOME`; cargo config and credential files are removed from the
  caller's cargo cache before every call. The trade-off: without
  `RUSTUP_HOME` the rustup proxies do not work, so `rustup`,
  `cargo +toolchain` and a workspace `rust-toolchain.toml` are not honored
  inside `run_cmd`. A caller's cache persists between its calls, so an
  agent can affect its own later builds through it, but not another
  agent's.
