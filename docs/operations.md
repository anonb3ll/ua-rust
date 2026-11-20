# Operations guide

This guide covers bootstrapping, health checking, backing up, restoring, and
running `ua` in production. All deployment files under `deploy/` are
ready-to-adapt templates using placeholder paths and identities.

Run every hub administrative command (`ua init`, `ua doctor`, `ua backup`,
`ua restore`, `ua serve`) **as the dedicated hub OS user** (never directly as
root via bare `sudo`, which creates root-owned files in `$UA_HOME`). Commands
check that the effective UID matches the owner of `$UA_HOME`.

## 1. Initialize a hub (`ua init`)

`ua init` creates an owner-only (`0700` on Unix) home directory, writes a
commented `config.toml` (`0600`) that validates cleanly with `Config::load_from`,
optionally writes and validates a starter `policy.yaml`, detects coding-agent
CLIs available on `PATH`, and prints ready-to-paste MCP snippets:

```sh
ua init --home /var/lib/ua-rust --with-policy --agent builder-1
```

Options:

- `--home <PATH>`: target `$UA_HOME` directory (defaults to `$UA_HOME`, else
  `~/.ua-rust`).
- `--workspace <PATH>`: confined workspace root for `fs_*`, `run_cmd`, and
  `git_*` (defaults to `<home>/workspace`).
- `--operator <LABEL>`: initial human identity recorded in `human_identities`
  and `[profiles]` (`operator` by default).
- `--agent <LABEL>`: issue an initial bearer token in the same setup step
  (minted and committed **before** writing `config.toml`/`policy.yaml` so a
  refused human TTY check or lock leaves existing config untouched; raw token
  is printed once).
- `--with-policy`: write and enable a starter `policy.yaml` alongside
  `config.toml`.
- `--force`: save timestamped `0600` `.bak` backups of any existing
  `config.toml`/`policy.yaml` before replacing them (symbolic links are always
  refused).
- `--json`: emit machine-readable setup output.

## 2. Preflight & diagnostics (`ua doctor`)

`ua doctor` runs read-only checks without creating a missing database, running
migrations, or taking a write lock on the SQLite writer:

```sh
ua doctor
ua doctor --json
ua doctor --strict                     # also fail on warnings
ua doctor --strict --allow-non-loopback # allow 0.0.0.0 bind when enforce_auth=true (e.g. Docker)
```

Checks performed:

1. `owner`: confirms effective UID owns `$UA_HOME` on Unix (prevents mixed root/service-user state).
2. `config`: loads effective config layers (`$UA_CONFIG` / `$UA_HOME/config.toml` + `UA_*` env).
3. `permissions`: verifies `$UA_HOME`, active config file, and `ua.db` are owner-only (`mode & 0o077 == 0` on Unix; `0644` warns).
4. `auth_lockout`: ensures `enforce_auth = true` has at least one static or active database token.
5. `origin_security`: checks loopback bind (unless `--allow-non-loopback` with auth enforced), `insecure_origin_warning`, and refuses non-loopback binds with `enforce_auth = false`.
6. `cargo_config`: runs `cargo_config_warning` across configured workspace roots.
7. `policy_file`: validates the fail-closed YAML policy via `policy::load`.
8. `database`: opens the DB strictly read-only (`query_only = ON`) and checks `PRAGMA quick_check`, `PRAGMA foreign_key_check`, `journal_mode=wal`, and WAL size (`> 64 MiB` warns).
9. `schema`: compares applied `schema_parts` checksums and `sqlite_master` tables/triggers against the running build (`drifted` parts or unexpected tables/triggers fail; `missing`/`extra` parts warn).
10. `ledger`: verifies the tamper-evident `event_log` hash chain cleanly (`ledger::verify`).
11. `pre_restore_backups`: warns when leftover `*.pre-restore-*.bak*` recovery files remain in `$UA_HOME` so they can be pruned once verified.
12. `registry`: confirms built-in tool registration count.

## 3. Online backups (`ua backup`)

`ua backup` acquires a shared hub lock (the same lock `ua serve` holds, so
live online backups run safely alongside a serving hub while exclusive
`restore`/`import` operations block it) and takes a consistent SQLite
`VACUUM INTO` snapshot inside a private `0700` staging directory—capturing
committed WAL frames into a standalone, compacted database file (`0600` on Unix)
without touching raw `-wal` or `-shm` sidecars:

```sh
ua backup --to /var/backups/ua-rust/ua-20261120.db --manifest
```

> **Sensitivity & authenticity:** A backup database contains browser cookie keys,
> SHA-256 token hashes, OAuth grants, passkey credentials, and AES-GCM ciphertext
> for managed secrets (`UA_MANAGED_SECRET_KEY` is stored outside the DB and must
> be backed up separately in your secret store). Treat backup files as secrets.
> Note that `ledger::verify` proves internal hash-chain **integrity** of
> `event_log`, not cryptographic authenticity of non-ledger tables (`agent_tokens`,
> triggers) on an untrusted file—always record and verify `--expected-sha256`
> from a trusted manifest.

## 4. Verified restore (`ua restore`)

Always stop both `ua serve` **and** any external replicator such as Litestream
before restoring: non-dry-run `ua restore` acquires an exclusive `HubLock`
(`ua.db.hub.lock`), which Litestream does not participate in. Expect a new
Litestream WAL generation after restarting replication on a restored database.

```sh
# Dry-run: stage via single O_NOFOLLOW open, verify integrity/schema/ledger/digest
ua restore --from /var/backups/ua-rust/ua-20261120.db --dry-run \
  --expected-sha256 <64-hex-sha256>

# Stop ua serve (and Litestream), then restore with pinned SHA-256
ua restore --from /var/backups/ua-rust/ua-20261120.db --force \
  --expected-sha256 <64-hex-sha256> --revoke-sessions
```

Key restore safeguards:

1. **Pinned digest required:** Non-dry-run restores require `--expected-sha256 <hex>`
   unless `--allow-unpinned` is explicitly passed.
2. **Single-open `O_NOFOLLOW` staging + `immutable=1`:** Sources with sibling
   `-wal` or `-journal` sidecars are refused (`ua backup` creates self-contained
   snapshots). The source is opened once (`O_NOFOLLOW`), streamed into a private
   `0700` staging directory (`0600` file), hashed, checked (`PRAGMA integrity_check`,
   required tables, schema/trigger compatibility unless `--allow-newer` overrides
   additive parts, `ledger::verify`) via SQLite `immutable=1`, and never re-opened.
3. **Safety backup preserving WAL/SHM/journal:** Unless `--no-safety-backup` is
   passed, an existing DB is backed up to `<db>.pre-restore-<UTC>.bak` (falling
   back to raw `0600` copies of main + `-wal`/`-shm`/`-journal` sidecars when
   recovering a corrupt/tampered DB).
4. **Atomic swap with rollback & credential handling:** Existing DB and sidecars
   are moved into staging rollback before swapping in the new DB; any failure
   enabling `WAL` mode, running post-install `quick_check`, appending `ops.restored`
   to `event_log`, or re-verifying the chain restores the previous DB + sidecars
   and reports the safety backup path. Because restoring an older snapshot can
   resurrect previously revoked tokens, browser sessions, or OAuth grants, pass
   `--revoke-sessions` to invalidate active UI sessions, login links, OAuth
   grants/tokens/codes/requests, and node session credentials in the restore
   transaction.

## 5. Graceful shutdown & process managers

`ua serve` handles `SIGINT` and `SIGTERM`:

- Open HTTP/SSE and MCP requests, tool calls in flight, active dispatches, and
  background loops share a 10-second drain grace period.
- Running child dispatches receive `SIGTERM` (then `SIGKILL`) 3 seconds before
  the deadline and record a `retryable` / `hub_shutdown` receipt.
- On exit, `ua serve` checkpoints and truncates the WAL into `ua.db`.
- Set service manager stop timeouts (`TimeoutStopSec`, `stop_grace_period`,
  `ExitTimeOut`) to at least `20s`.

Templates are provided in `deploy/`:

- Docker: [`deploy/docker/Dockerfile`](../deploy/docker/Dockerfile),
  [`deploy/docker/compose.yaml`](../deploy/docker/compose.yaml), and root
  [`.dockerignore`](../.dockerignore) (non-root user, `tini` / `init: true` PID 1
  reaping, `embeddings` build feature with cache under `$UA_HOME/models`,
  `read_only: true`, `cap_drop: [ALL]`, loopback port bind).
- Linux systemd: [`deploy/systemd/ua-hub.service`](../deploy/systemd/ua-hub.service)
  (dedicated OS user `ua-hub`, `KillMode=mixed` so `#38` graceful drains run,
  `ProtectSystem=strict`, `ProtectHome=yes`, kernel/capability hardening,
  `UMask=0077`).
- macOS launchd: [`deploy/launchd/com.example.ua-hub.plist`](../deploy/launchd/com.example.ua-hub.plist)
  (dedicated `_ua-hub` user/group, `Umask` `63` / `0077`, standard `/Library/`
  paths, `KeepAlive`, `ExitTimeOut` `20`). Create `/Library/Application Support/ua-rust`
  (`0700`) and `/Library/Logs/ua-rust` (`0750`) owned by `_ua-hub:_ua-hub` first.
- Continuous WAL replication: [`deploy/litestream/litestream.yml`](../deploy/litestream/litestream.yml)
  (unencrypted replica warning; stop alongside `ua serve` before `ua restore`).

## 6. OS-user isolation reminder

As documented in [SECURITY.md](../SECURITY.md), always run coding agents under
a different OS account than `ua serve`. Any process running as the hub's OS
user can read and modify `ua.db`, `config.toml`, and token files directly.
