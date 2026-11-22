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
9. `schema`: shares `check_schema_compatibility` with `system_doctor`—compares `schema_parts` checksums and all `sqlite_master` tables, views, indexes, and triggers against the running build (`drifted`, missing/altered objects, unexpected triggers on known tables, objects using the reserved `sqlite_` name prefix, unexpected tables with foreign keys into known tables, or unowned objects without an `extra` part fail; `extra` parts, which mean a newer build wrote the database and the serving and writing commands refuse it (see [Older builds and a newer database](#older-builds-and-a-newer-database)), fail and are reported first, before any object findings a newer part may explain; `missing` parts warn). **Exit-code change:** `extra` parts used to warn, so a plain `ua doctor` (without `--strict`) now exits non-zero on a database a newer build wrote. Only SQLite's own `sqlite_sequence`, `sqlite_stat1`, `sqlite_stat4`, and automatic indexes are exempt from the comparison.
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
   automatic indexes. Every AUTOINCREMENT table (including `event_log`) must have
   `MAX(rowid)` at or below 2^52, whether or not it has a `sqlite_sequence` row, which
   keeps later ids well inside the exact-JSON integer range. The `event_log` counter
   must equal `MAX(seq)`; every other counter must lie between `MAX(rowid)` and 2^52.
   `event_log` is not required to be gap-free, because `ua import` keeps the source
   hub's `seq` values as they are.
   `--allow-newer` allows snapshots containing `extra` schema parts and
   their new objects (new tables/indexes/triggers on new tables), while still refusing
   drifted parts, missing/altered known objects, broken schema dependency chains,
   triggers or indexes on known tables, new tables with foreign keys into known
   tables, objects colliding with known schema names, or unowned objects without an
   `extra` part. A new table with a foreign key into a known table is refused even
   under `--allow-newer`, including one added by a genuine newer build: the running
   build does not know that child table, so its writes to the known parent could fail
   or cascade. Restore such a backup with a build that knows that schema part.
   **Upgrade note (`organization.v1.store`):** that part adds columns to the
   existing `event_log` table. A backup taken after it applied cannot be
   restored by a build from before it, even with `--allow-newer`: the older
   build sees `event_log` as an altered known table and refuses. Restore it
   with the same or a newer build. A backup taken before the part applied
   restores into a newer build as before, and the part applies on the next
   start.
   **Rolling back a live database** (running an earlier binary on a database
   a later build already upgraded) is different from a restore, and is
   refused by any build that has the unknown-part fence: see
   [Older builds and a newer database](#older-builds-and-a-newer-database).
   An earlier build from before the fence (for example one from before
   `organization.v1.store`) still starts and serves: it ignores parts it
   does not know, and the new `event_log` columns have defaults, so its
   writes succeed, while `ua doctor` and `system_doctor` report the schema
   as degraded. Do not do that; restore a backup taken before the upgrade
   instead (losing the writes made since). A build that has
   `organization.v1.store` also refuses to open, or to append to, a ledger
   whose newest row has a newer `hash_v` than it writes, with an error
   naming both forms; run the later build instead.
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

### Older builds and a newer database

A build refuses to open a database that records in `schema_parts` a part
this build does not know: one a newer build applied. "Knows" means the full
list of part names for this version (`ua_tools::known_schema_part_names`:
the parts every open applies plus the optional ones), so a lean build
(`--no-default-features`) opening a database a full build of the same
version made is not refused. A checked-in list of every part name ever
shipped (`crates/ua-tools/tests/fixtures/schema_part_names.txt`) and a test
that runs in both configurations keep it that way: a part name is never
retired or renamed, because the build that stopped knowing it would refuse
every database an earlier build made.

The check runs when the store opens, inside the first `BEGIN IMMEDIATE`
transaction of the migration, before the tracking table is created or any
part is applied: no other process can record a part between the check and
the apply, and a refused open applies nothing. (The connection setup before
it sets `journal_mode = WAL`, which converts a database file not yet in WAL
mode; every database `ua` creates already is.) The refusal names the
unknown parts, says a newer build wrote the database and what to do:

```text
Error: the database /path/to/ua.db was written by a newer build: it records schema parts this build does not know ([future.v9]). This build refuses to open it for serving or writing, ...
```

On a refused database:

| Command | Without the override | With the override |
|---|---|---|
| `ua serve` | refuses | **refuses** (see below) |
| `ua mcp`, `ua call`, `ua tools`, `ua token`, `ua login-link`, `ua init` (when it mints a token), `ua import` | refuse | run, with a warning at every open |
| `ua doctor` | runs (read-only; its `schema` check fails with `extra=[...]`) | the same |
| `ua backup` | runs (a read-only snapshot) | the same |
| `ua restore` | runs (see below) | the same |
| `ua config` | runs (does not open the database) | the same |

What to do: run the newer build (or a later one) again. If you must go
back, restore a backup taken before the upgrade with `ua restore` (losing
the writes made since); an older build then opens it.

**Override, for recovery only.** `--allow-newer-schema` (a global flag) or
`UA_ALLOW_NEWER_SCHEMA=1` in the process environment opens the database
anyway, ignoring the unknown parts, as builds before the fence did. A `.env`
file cannot switch it on: the variable is read before `ua` loads `.env`, and
a value that only a `.env` file sets is ignored. `UA_ALLOW_NEWER_SCHEMA`
takes `1`/`true`/`yes` or `0`/`false`/`no`; any other value is refused.
Every open under it logs a warning naming the parts (`OPENING A DATABASE
WRITTEN BY A NEWER BUILD`), and a warning when it is set with nothing to
ignore. The risk is whatever the newer parts changed. For the
inbound-delivery table (`docs/ingress.md`, Limits) it would be a replay
window: a build that reads only the old delivery tables accepts again
copies of GitHub deliveries handled since the upgrade (within 30 days),
and runs again a Slack retry of a command the newer build already ran
(within about a day). That is why **`ua serve` refuses a database written
by a newer build even with the override**, naming the unknown parts and
saying why; only `ua serve` takes GitHub and Slack deliveries. Use the
override to inspect, export or repair through `ua call`, `ua tools` or
`ua mcp`, and `ua backup` (which needs no override).

It is the same rule `ua restore` applies to a backup: a backup with parts
this build does not know is refused without `--allow-newer`. Restoring
with `--allow-newer` brings such a database in, and the fence then still
refuses it until the override is set: each step asks for its own consent.
The ledger's `hash_v` rollback fence (`docs/organization.md`) is separate
and not lifted by the override.

**Processes already running.** The fence checks a database when a
process opens it, and a running process is not re-checked. Two cases are
covered anyway:

- An *older* build's command started beside a newer `ua serve` (or after a
  newer build migrated) opens the database after the migration, so the
  fence refuses it if that build has the fence.
- A *newer* build's command beside an *older* running `ua serve`: before an
  open that would apply at least one part the database does not record yet
  (a real migration; an open with nothing to apply is unaffected, so
  everyday use beside a serve of the same build keeps working), every
  command except `ua serve` itself probes the serve lock and refuses if
  another process holds it, before applying anything:

  ```text
  Error: a running `ua serve` holds the database /path/to/ua.db: this command would migrate it (apply the schema parts [...]) underneath that serve, which may be from a build that does not know them. Stop the running `ua serve`, or upgrade it to this build, first; then retry
  ```

  The recovery override does not lift this. `ua serve` migrates at startup
  under its own lock, as before. The probe is a non-blocking shared lock on
  `<db>.serve.lock`, taken inside the migration transaction and released at
  once. What remains: a `ua serve` that starts in the same instant as the
  probe can be refused as if another serve held the database (start it
  again), and one that starts just after the probe is not seen by it; that
  serve opens the database only after the migration commits, so the fence
  decides whether it runs.

Not covered: a running process of an older build that is not `ua serve`
(an older `ua mcp` session, for example) keeps writing after a newer
build migrates; a running `ua serve` from a build before this guard is
still detected (it holds the serve lock), but one from before the serve
lock is not; and on a platform without `flock` (not Unix) no running serve
can be detected. Stop every hub process before upgrading.

**What the fence cannot stop.** It works only in builds that contain it,
and it refuses only parts added after it. Every build from before this
change opens an upgraded database and ignores the parts it does not know.
That includes every build from before the inbound-delivery table
(`ingress.inbound.v1`), the downgrade `docs/ingress.md` warns about: such a
build reads only the old delivery tables, and nothing refuses it. No
version has been released; on `main`, that is every build before this
change. Never run a build older than this change against a database a
newer build has opened; restore a backup taken before the upgrade instead.
Because any new part name refuses every build that has the fence, a later
change that must stop older builds without changing the schema can ship an
empty marker part; no separate minimum-reader record is needed.

## 5. Graceful shutdown & process managers

### One `ua serve` per database

`ua serve` takes a second lock beside the shared hub lock: `<db>.serve.lock`
(`ua.db.serve.lock` by default), next to the database file, held exclusively
for the life of the process. A second `ua serve` on that database exits at
once, before it opens the database, binds its port or touches any
inbound-delivery state, with:

```text
Error: another `ua serve` holds the database /path/to/ua.db: a second `ua serve` on the same database is refused (two would each take the other's in-flight inbound deliveries for stale ones). Stop the running `ua serve` first, or point this one at a different database
```

"The same database" is the file SQLite opens: the configured path made
absolute, with every symbolic link followed (a chain, a relative target, and
a link whose target does not exist yet, so a database not created yet behind
a link meets the same lock as the created one) and `.` and `..` resolved.
The longest part of that path that exists is then given its on-disk
spelling, so on a file system that ignores letter case (the macOS default)
an existing file or directory yields one spelling however it is typed.
Every spelling of one database file gives one lock file. Parts of the path
that do not exist yet keep the case they were typed in, but that is no gap:
the lock files live in the database's own directory, so on a file system
that ignores case two lock names that differ only in case are one file.
One limit: hard links are not resolved, so two hard links to one file are
two databases to the lock. Do not reach a database through two hard links at
all; SQLite's `-wal` and `-shm` files are per name, so that is unsafe
without any `ua` involved.

The shared hub lock (`<db>.hub.lock`) uses the same resolution, so a
`ua restore` or `ua import` that reaches the database by another spelling
still refuses while a serve (or any other hub process) runs. **Upgrade
note:** builds before this change put the hub lock beside the path as
written. For a database reached through a link or an unusual spelling, a
process from before the change and one from after it use different
hub-lock files during the transition, so stop every old process before
running an import or restore with the new build.

Both lock files are owner-only (`0600`), so another local account cannot
hold them: a new one is created so, and an existing one with a wider mode is
tightened when a lock is taken (best effort: a file another account owns
keeps its mode, and the lock is still taken). The operating system releases a lock when the process
exits, a crash or `SIGKILL` included, so there is nothing to clean up: the
file stays and is harmless. Only `ua serve` takes the serve lock. `ua mcp`,
`ua call`, `ua tools`, `ua token`, `ua backup` and `ua doctor` run beside a
serving hub as before. `ua restore` and `ua import` still refuse while it
runs, on the shared hub lock (they take it exclusively). A process manager
that starts a new `ua serve` before the old one has finished draining sees
the refusal until the old one exits; stop, then start (systemd and the
compose file already do), and do not run two containers or units on one
data volume.

On a platform without `flock` (not Unix) nothing is locked: a second
`ua serve` is NOT refused there, and `ua` prints a warning saying so. The
lock is taken by the `ua` command. A program that embeds `ua-server` and
calls `serve_http` itself must take `ua_import::ServeLock` first.

### Shutdown

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
