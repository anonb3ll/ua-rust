# Security policy

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/anonb3ll/ua-rust/security/advisories/new)
rather than in a public issue. If you cannot use that, email
anonb3ll@pm.me. Include the version or commit, a description, and steps to
reproduce. You will get an acknowledgement within a week.

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
  so a profile or policy that refuses the tool refuses the stream. An open
  stream re-checks its caller every 60 seconds, and within a quarter
  second when a token revocation or rotation, logout, session end, profile
  change or config revision is recorded (a burst of such events shares one
  re-check per stream, and rows recorded after the event are held back
  until it passes): the credential must still resolve to the same
  identity, and the admission the stream opened with (profile after any
  policy overlay, then the policy rules, with the stream's scope as the
  arguments) must still let it in without a new approval. Per-call
  throttles (`rate_limit`, `cooldown`) apply when a stream opens, not to
  the re-check. When the caller is no longer let in, the stream sends a
  final `auth_revoked` event with a short reason code and ends, so
  clients can stop reconnecting.
- **Remote nodes answer to one agent.** A node name belongs to the agent
  label whose token first registered it; registration and heartbeats need
  that agent's credential, and humans and unauthenticated callers are
  refused. An agent holds at most `node_max_per_agent` nodes in service
  (default 8). A node's facts are self-reported: the hub bounds them on
  write (unknown keys dropped, lists and strings capped, 64000 bytes at
  most) but cannot verify them. Heartbeats refresh only advisory facts;
  roots, repos and harnesses change only by registering again, which is
  ledgered when anything in them changes. `node_list` shows paths,
  checkouts, harness binaries and session titles only to the node's own
  agent and to lifecycle operators; others get a summary. Retiring,
  un-retiring, reassigning a node to another label and forgetting a retired
  node are lifecycle operator actions (`lifecycle_operators`, default
  `human_identities`), each ledgered.
- **Dynamic client registration is bounded.** Clients that never receive a
  grant are pruned after `oauth_dcr_unused_ttl_hours`, unused clients are
  capped (the oldest is evicted), and each address may register
  `oauth_dcr_rate_per_hour` clients per hour.
- **`run_cmd`** runs without a shell, from an allowlist. Interpreters and
  build tools park for human approval. Each call gets a fresh, empty `HOME`
  (under `$XDG_RUNTIME_DIR/ua-run/`, else `<temp>/ua-run-<uid>/`, mode
  0700) that is deleted afterwards. What common work needs is set
  explicitly: a git identity `<label> <label@agents.invalid>`, the `bin`
  directory of the hub's default Rust toolchain first on `PATH` (with the
  hub user's `$CARGO_HOME/bin` and `~/.cargo/bin` removed from `PATH`; the
  toolchain is looked up once in the background when `ua serve` starts,
  then only for Rust toolchain programs such as `cargo` and `rustc`, one
  lookup at a time, and re-resolved after a failed lookup or when it
  disappears; other programs reuse the last lookup and never wait on one,
  so a build tool or script that starts cargo before the startup lookup
  finishes runs without the toolchain on `PATH`), and
  `CARGO_HOME`, `XDG_CACHE_HOME` and `UV_CACHE_DIR` in a cache of the
  caller's own under `$UA_HOME/run-cache/<label>-<digest>/`. Commands never
  get the hub user's `CARGO_HOME` (credentials, config, installed binaries)
  or `RUSTUP_HOME`; cargo config and credential files are removed from the
  caller's cargo cache before every call. The trade-off: without
  `RUSTUP_HOME` the rustup proxies do not work, so `rustup`,
  `cargo +toolchain` and a workspace `rust-toolchain.toml` are not honored
  inside `run_cmd`. A caller's cache persists between its calls, so an
  agent can affect its own later builds through it, but not another
  agent's. `ua serve` removes caches unused for 30 days at startup (by the
  mtime of a marker each call touches); there is no size cap.
- **Cargo config above the workspace.** Cargo reads `.cargo/config` and
  `.cargo/config.toml` in every ancestor of its working directory, and
  `CARGO_HOME` does not stop that walk; cargo has no supported switch to
  turn it off. With the default workspace `~/.ua-rust/workspace`, the hub
  user's `~/.cargo/config.toml` is such an ancestor, and its aliases,
  `[env]`, `build.rustc-wrapper`, source replacement and credential
  providers would apply inside `run_cmd`. So `run_cmd` (and
  `run_cmd_check`) refuse `cargo` and `cargo-*` with the advisory
  `cargo-config`, naming the file and the SHA-256 of its content, whenever
  such a file exists above the workspace root, and `ua serve` warns at
  startup. Fix it by moving the workspace outside that directory tree
  (`workspace = "/srv/ua-workspace"` or similar), by removing the file, or
  by trusting it: after reviewing the file, pin its path and current hash
  in the hub config,
  `trusted_cargo_configs = [{ path = "~/.cargo/config.toml", sha256 = "<hex>" }]`
  (the refusal prints the line to copy). A pinned file is hashed again on
  every call; when its content changes, or when another unpinned config
  appears above the workspace, cargo is refused again until the new
  content is pinned. Residual risks of a pin: the file is read and hashed
  when `run_cmd` is called and cargo reads it again when it starts, so a
  change made in between (by something that can already write outside the
  workspace as the hub user) is not caught; and only the file's own bytes
  are pinned, not what it points to (a `rustc-wrapper` or linker binary,
  a credential provider, an `include`d file). Configs inside the workspace
  are the workspace's own and are not refused. Cargo started indirectly (by
  an interpreter or build tool, which already needs approval) is not
  covered by this check.
