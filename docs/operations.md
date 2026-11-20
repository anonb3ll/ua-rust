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
9. `schema`: shares `check_schema_compatibility` with `system_doctor`—compares `schema_parts` checksums and all `sqlite_master` tables, views, indexes, and triggers against the running build (`drifted`, missing/altered objects, unexpected triggers on known tables, objects using the reserved `sqlite_` name prefix, unexpected tables with foreign keys into known tables, or unowned objects without an `extra` part fail; `missing`/`extra` parts warn). Only SQLite's own `sqlite_sequence`, `sqlite_stat1`, `sqlite_stat4`, and automatic indexes are exempt from the comparison.
10. `ledger`: verifies the tamper-evident `event_log` hash chain cleanly (`ledger::verify`).
11. `pre_restore_backups`: warns when leftover `*.pre-restore-*.bak*` recovery files remain in `$UA_HOME` so they can be pruned once verified.
12. `restore_staging`: warns when leftover `.ua.db.restore.*.d` rollback directories remain (indicating a failed rollback requiring inspection).
13. `registry`: confirms built-in tool registration count.

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
> triggers) on an untrusted file—record and store `--expected-sha256` **separately
> from the backup directory**, because the sibling `<backup>.sha256.json` manifest
> is unsigned.

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
2. **Single-open `O_NOFOLLOW | O_NONBLOCK` staging next to target + `immutable=1`:**
   Sources with sibling `-wal` or `-journal` sidecars are refused (`ua backup` creates
   self-contained snapshots) and FIFOs are rejected without blocking. The source is
   opened once, streamed into a private `0700` staging directory beside the
   destination (`0600` file, avoiding small `/tmp` mounts even for `--dry-run`), hashed,
   and checked (`PRAGMA integrity_check`, required tables, `schema_parts` + normalized
   table/view/index/trigger DDL compatibility, `sqlite_sequence` counters,
   `ledger::verify`) via SQLite `immutable=1`. Objects named with the reserved
   `sqlite_` prefix (which only `PRAGMA writable_schema` can create) are refused,
   apart from SQLite's own `sqlite_sequence`, `sqlite_stat1`, `sqlite_stat4`, and
   automatic indexes. The `event_log` AUTOINCREMENT counter must equal `MAX(seq)`;
   every other counter must lie between `MAX(rowid)` and 2^53 - 1.
   `--allow-newer` allows snapshots containing `extra` schema parts and
   their new objects (new tables/indexes/triggers on new tables), while still refusing
   drifted parts, missing/altered known objects, broken schema dependency chains,
   triggers or indexes on known tables, new tables with foreign keys into known
   tables, objects colliding with known schema names, or unowned objects without an
   `extra` part.
3. **Safety backup preserving WAL/SHM/journal:** Unless `--no-safety-backup` is
   passed, an existing DB is backed up to `<db>.pre-restore-<UTC>.bak` (falling
   back to raw `0600` copies of main + `-wal`/`-shm`/`-journal` sidecars when
   recovering a corrupt/tampered DB).
4. **Crash-safe replace with hard-linked rollback & credential scope:** The existing DB
   and sidecars are hard-linked (or copied on cross-filesystem mounts) into private
   rollback staging while leaving `ua.db` intact in place (after checkpointing any hot
   WAL into it; the restore is refused if another process blocks that checkpoint, and
   other checkpoint failures, such as a corrupt destination, appear in the report's
   `warnings`), then `ua.db` is replaced
   via `fs::rename`, stale sidecars are cleared, WAL mode + `ops.restored` +
   post-install checks run, and on failure the original DB + sidecars are restored in
   place (or rollback staging is preserved on disk and reported if rollback itself
   fails). Pass `--revoke-sessions` to invalidate UI sessions, login links, OAuth
   grants/tokens/codes/requests, and node `session_credentials` in the restore
   transaction; **note that `--revoke-sessions` does not revoke `agent_tokens`,
   static `UA_AGENT_TOKENS`, or `managed_secrets` ciphertext**—rotate compromised agent
   tokens (`ua token revoke`/`rotate`) and managed secrets separately.

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
  [`.dockerignore`](../.dockerignore) (non-root user with `0700` home, `tini` PID 1
  reaping, `embeddings` build feature with cache under `$UA_HOME/models`,
  `read_only: true`, `cap_drop: [ALL]`, loopback port bind).
- Linux systemd: [`deploy/systemd/ua-hub.service`](../deploy/systemd/ua-hub.service)
  (dedicated OS user `ua-hub`, `KillMode=mixed` so `#38` graceful drains run,
  `ProtectSystem=strict`, `ProtectHome=yes`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`,
  kernel/capability hardening, `UMask=0077`).
- macOS launchd: [`deploy/launchd/com.example.ua-hub.plist`](../deploy/launchd/com.example.ua-hub.plist)
  (dedicated `_ua-hub` user/group, `Umask` `63` / `0077`, standard `/Library/`
  paths, `KeepAlive`, `ExitTimeOut` `20`). Create the `_ua-hub` user/group (via `dscl`,
  documented in the plist header), `/Library/Application Support/ua-rust` (`0700`),
  and `/Library/Logs/ua-rust` (`0750`) first.
- Continuous WAL replication: [`deploy/litestream/litestream.yml`](../deploy/litestream/litestream.yml)
  (unencrypted replica warning; stop alongside `ua serve` before `ua restore`).

## 6. OS-user isolation reminder

As documented in [SECURITY.md](../SECURITY.md), always run coding agents under
a different OS account than `ua serve`. Any process running as the hub's OS
user can read and modify `ua.db`, `config.toml`, and token files directly.
