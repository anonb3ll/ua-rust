# Storage and repository boundaries

Status: **design, with `OrgRead`/`OrgWrite` and `GraphRead`/`GraphRepo` in the tree.**

`ua-store` owns the SQLite WAL database (`Db`: one serialized `BEGIN IMMEDIATE`
writer and a bounded pool of read-only connections), named schema parts,
backups, locks, and the hash-chained event ledger. Today, most tool families
and domain crates still call `rusqlite` directly with inline SQL. That scatters
tenant-scoping predicates, row decoding, and query invariants across hundreds of
call sites and makes it hard to audit or enforce organization boundaries in one
place (and, secondarily, keeps a future second storage backend behind a large
rewrite).

This note defines the per-aggregate repository boundary in `ua-store`, how it
fits with named schema parts and `tenant_part`, what stays raw SQL, how the
raw-SQL ratchet closes bypasses without a schema change or bulk rewrite, and
the concrete pilot migration (`task_comments`).

## Design goals and non-goals

- **One tenant-scoped choke point per aggregate.** Each aggregate's queries
  live in one module in `ua-store`, behind typed read and write traits, with
  explicit `org_id` binding on every tenant query.
- **Single-transaction atomicity.** Writes still commit inside the caller's
  `WriteTx<'_>` alongside `ledger::append` and any cross-aggregate write in the
  same tool call. Repositories never open their own connections or start
  nested transactions.
- **No schema change and no bulk rewrite.** Introducing repository traits and
  the raw-SQL ratchet does not alter any table, index, trigger, or schema-part
  checksum. Existing call sites migrate one aggregate at a time; the ratchet
  stops new raw SQL from accumulating outside `ua-store`.
- **No `ua-store` upward dependencies.** `ua-store` continues to depend only on
  `ua-core` and third-party crates, never on `ua-tools`, `ua-server`, or domain
  crates (`ua-org`, `ua-memory`, `ua-deliverables`, `ua-graph`, `ua-ingress`).

## Repository trait shape per aggregate

Follow the pattern already established in `ua-store` by
`ua_store::org::{OrgRead, OrgWrite, SqliteOrg}` (`crates/ua-store/src/org.rs`)
and `ua_store::graph::{GraphRead, GraphRepo, SqliteGraph, MigrationGraph}`
(`crates/ua-store/src/graph.rs`).

### Read and write trait pair

Each aggregate exposes a read trait and a write trait in its own `ua-store`
module (for example `ua_store::org`, `ua_store::graph`, or
`ua_store::task_comments`):

- **`<Aggregate>Read`** holds read-only queries. Every method takes `&mut self`
  so implementations that arm a SQLite `progress_handler` deadline or cache
  prepared statements on a connection can do so without changing the trait
  signature.
- **`<Aggregate>Write: <Aggregate>Read`** (or `<Aggregate>Repo: <Aggregate>Read`
  for existing `GraphRepo`) holds mutations and write-side lookups that run
  inside an active write transaction.
- **Aggregate-qualified method names.** Because `WriteTx<'_>` implements
  multiple `<Aggregate>Read` and `<Aggregate>Write` traits at once, method names
  must include the aggregate noun (for example `get_task_comment`,
  `list_task_comments`, `insert_task_comment` rather than bare `get`, `list`, or
  `insert`) so calls on `tx` never collide or force UFCS disambiguation.

### Connection, transaction, and migration binding

- **Read paths** run inside `Db::read` / `Db::read_async` (wrapping `&Connection`
  as in `SqliteOrg::new(conn)`, `org.rs:292`) or `Db::read_mut` /
  `Db::read_mut_async` (wrapping `&mut Connection` as in `SqliteGraph::new(conn)`,
  `graph.rs:563`, when a progress-handler deadline is needed). The zero-cost
  `Sqlite<Aggregate><'a>` adapter implements `<Aggregate>Read`.
- **Write paths** run inside `Db::write` / `Db::write_async` by implementing
  both `<Aggregate>Read` and `<Aggregate>Write` directly for `WriteTx<'_>`.
  Because `WriteTx<'_>` wraps a `BEGIN IMMEDIATE` `rusqlite::Transaction`, a
  handler can read current state, apply one or more repository writes, and call
  `ledger::append(tx, ...)` atomically in one transaction.
- **Migration and import adapters.** Where a schema `Procedure` or `ua-import`
  must insert rows through a repository inside an existing migration/import
  transaction **without** appending to the hash-chained `event_log`
  ([organization.md](organization.md)), follow `MigrationGraph<'a>`
  (`graph.rs:583`): a dedicated insert-only wrapper over `&Connection` whose
  usage is confined to explicitly allowlisted migration/import files by a guard
  test (as `crates/ua-graph/tests/update_guard.rs` does). Runtime handlers and
  `ua-server` always write through `&mut WriteTx<'_>`.
- **No `rusqlite` types in trait signatures.** Inputs are plain Rust values and
  parameter structs (`New<Row>`, `<Row>Patch`, `<Query>`). Outputs are
  `UaResult<T>` carrying typed row structs (`<Row>`, `Option<<Row>>`,
  `Vec<<Row>>`), never `rusqlite::Row`, raw SQL fragments, or untyped
  `serde_json::Value` blobs for structured columns.

```rust
/// Typed row returned by the repository; no `rusqlite` types leak out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCommentRow {
    pub id: i64,
    pub org_id: String,
    pub task_id: i64,
    pub parent_comment_id: Option<i64>,
    pub author: String,
    pub body: String,
    pub mentions_json: String,
    pub refs_json: String,
    pub idempotency_key: Option<String>,
    pub thread_revision: i64,
    pub created_at: String,
}

pub trait TaskCommentsRead {
    fn get_task_comment(&mut self, org_id: &str, id: i64) -> UaResult<Option<TaskCommentRow>>;
    fn list_task_comments(&mut self, org_id: &str, task_id: i64) -> UaResult<Vec<TaskCommentRow>>;
}

pub trait TaskCommentsWrite: TaskCommentsRead {
    fn insert_task_comment(&mut self, row: &NewTaskComment) -> UaResult<i64>;
}

/// Thin read adapter over a pooled read-only connection (`&mut Connection`
/// when a SQLite progress-handler deadline is needed, as in `SqliteGraph`).
pub struct SqliteTaskComments<'a> {
    conn: &'a Connection,
}

impl<'a> SqliteTaskComments<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }
}

impl TaskCommentsRead for SqliteTaskComments<'_> { /* delegates to shared SQL helpers */ }
impl TaskCommentsRead for WriteTx<'_> { /* delegates to the same SQL helpers */ }
impl TaskCommentsWrite for WriteTx<'_> { /* writes on `self` inside BEGIN IMMEDIATE */ }
```

### Clocks and timestamps

Repositories take timestamps as explicit inputs (`created_at`, `updated_at`,
etc.) and do **not** read the system clock internally. Callers read
`Config.clock` (`clock.now()`) **inside the write closure** (`Db::write` /
`Db::write_async`), after `BEGIN IMMEDIATE` has serialized the transaction, so
stored timestamps match commit order under contention (matching
`crates/ua-memory/src/save.rs:478-480`).

Two existing deviations in the tree predate this rule and are called out here so
new repositories do not copy them:

- `crates/ua-tools/src/families/tasks/write.rs:288` (`insert_task`) and
  `crates/ua-tools/src/families/tasks/comments.rs:280` call
  `ua_core::time::now()` directly instead of `Config.clock`.
- `crates/ua-store/src/graph.rs` (`GraphRepo` temporal write checks) reads
  `ua_core::time::now()` inside `ua-store` to enforce `valid_to <= now`.

### Tenant scoping, ledger exception, and enforcement

1. **Verified provenance of `org_id`.** Every `org_id` passed into a repository
   method comes strictly from the verified `Caller.org_id` (or
   `Caller::system_for` on verified callerless paths such as GitHub
   webhook/poll), never from tool arguments ([organization.md](organization.md)).
2. **Explicit `org_id` in every tenant query.** Every read and write method on a
   tenant-scoped aggregate takes `org_id: &str` (or a struct with a mandatory
   `org_id: String` field), binds `org_id` in every `SELECT`, `JOIN`, `UPDATE`,
   `DELETE`, and `INSERT`, and never defaults to `DEFAULT_ORG` silently. Any
   visibility or scope predicate runs inside the SQL query before `COUNT` or
   `LIMIT` (never post-filtered in Rust).
3. **Neutral cross-tenant misses.** Point lookups by `(org_id, id)` return
   `Ok(None)` when a row belongs to another organization, so callers map both
   absent rows and foreign-org rows to the same `not_found` error.
4. **Ledger `DEFAULT_ORG` exception (`ORG-EVENT-DEFAULT`).** Where a domain
   crate has no direct `rusqlite` dependency and records ledger events through a
   narrow write-trait helper (`OrgWrite::record` at `org.rs:505`,
   `GraphRepo::record_event` at `graph.rs:2450`), those helpers deliberately
   append with `EventInput::new(DEFAULT_ORG, ...)` as required by
   `crates/ua-core/tests/org_guard.rs` until `event_log` writes `hash_v = 2`
   (which hashes `org_id`). Callers carry tenant attribution in the payload and
   neutralized originator per `ORG-EVENT-DEFAULT`. This exception applies
   **only** to `event_log` appends until `hash_v = 2`, never to tenant-table
   queries.
5. **Enforcement model (convention + ratchets + isolation tests).**
   - `WriteTx<'_>` implements `Deref` and `DerefMut` to `rusqlite::Transaction<'_>`
     (`crates/ua-store/src/db.rs:556-567`), so the type system alone does not
     block callers outside `ua-store` from running raw SQL on `tx`.
   - Enforcement therefore rests on three layers together:
     1. the **raw-SQL ratchet** below (keeps SQL out of non-`ua-store` files),
     2. the existing **tenant-insert guard** in
        `crates/ua-tools/tests/org_classification.rs` (verifies every `INSERT`
        into a keyed tenant table names `org_id`), and
     3. a mandatory **two-organization isolation test** for every migrated
        repository (in the style of `crates/ua-tools/tests/*_tenant.rs`),
        proving reads, point lookups, idempotent replays, parent checks, and
        writes in organization B neither observe nor mutate organization A /
        `'default'`.
6. **Domain rules stay out of `ua-store`.** Domain crates and tool families own
   authorization (`ua_org::authz`), profile/policy checks, input validation, and
   ledger event semantics. `ua-store` repositories own SQL, row decoding,
   explicit `org_id` binding, safe `LIMIT` clamping, and SQLite error mapping.

## How schema parts and `tenant_part` fit

The named schema-part system (`crates/ua-store/src/schema.rs`) does not change
when aggregates move behind repository traits:

- **Immutable released parts.** Static `SchemaPart`s (`name`, `sql`) and
  `Procedure`s (`name`, `version`, `standalone`, `run`, `args`) are recorded in
  `schema_parts` by checksum (and generated procedure SQL in
  `schema_procedures`). A released part is never edited in place; schema changes
  ship as new parts with new names. `Db::open_with` continues to enforce `Fence`
  (refusing unknown newer parts unless `allow_newer` is set) and `ServeLock`
  (refusing migrations while another `ua serve` holds the database).
- **Procedure checksum caveat.** A `Procedure` checksum covers only `(name,
  version, args)`, **not** the Rust code of `run` (`schema.rs:93-120`). If a
  released `Procedure` is ever relocated into `ua-store`, its `name`, `version`,
  `args`, and `run` behavior must remain byte-identical so existing databases
  keep matching checksums and fresh databases produce the exact same schema and
  backfill semantics.
- **Tenancy procedures (`tenant_part`).** Each tenant-scoped table family
  continues to apply
  `ua_store::org::tenant_part("organization.v1.<crate>.<family>", &[tables])`
  after `organization.v1.store`. That procedure adds
  `org_id TEXT NOT NULL DEFAULT 'default'` (or backfills `NULL`s on columns that
  predate it) and installs the `<table>_org_exists` and `<table>_org_immutable`
  triggers. Born-tenant tables (such as `inbound_deliveries` in
  `ingress.inbound.v1`) declare `org_id TEXT NOT NULL` in their initial
  `SchemaPart` and still pair it with `tenant_part` for the triggers.
- **Zero-migration trait extraction.** Moving an aggregate's queries into
  `ua-store` requires no DDL change. The aggregate's existing `SchemaPart` and
  `tenant_part` `Procedure` either stay registered from their current crate or
  are re-exported from `ua-store` with identical `name`, `sql`, `version`, and
  `args`, preserving checksums and registration order.
- **New aggregates.** Any new aggregate added after this note lands declares its
  `SchemaPart` (born with `org_id TEXT NOT NULL`) and `tenant_part` alongside
  its repository module, and reaches SQLite only through its `Read`/`Write`
  traits from day one.

## What stays raw

Not every SQL statement in the workspace belongs behind a domain repository
trait. The following remain direct `rusqlite` SQL:

1. **Migrations and schema machinery inside `ua-store`.**
   - `ua_store::schema` (`schema_parts`, `schema_procedures`, `apply`,
     `unknown_parts`, `unrecorded_parts`),
   - `ua_store::org` schema procedures (`STORE_PART`, `tenant_part`,
     `pragma_table_info` / `sqlite_master` introspection), and
   - static `SchemaPart` DDL strings across crates (DDL strings in `SchemaPart`
     constants are not `prepare`/`execute`/`query_row` call sites).
2. **Existing `Procedure` backfills outside `ua-store`.**
   - Today `ua-tools` holds 11 released `Procedure`s (`github/mod.rs:110`,
     `slack.rs:233`, `web.rs:76`, `idempotency.rs:73`, `skill_registry.rs:209`,
     `tasks/goal_links.rs:385`, `tasks/graph.rs:74`,
     `governance/tenant_keys.rs:28`, `harness_config/tenant_keys.rs:44`,
     `managed_secrets/tenant_keys.rs:37`, `node_queue/tenant_keys.rs:63`).
   - Rather than adding a blanket exemption for migration files in `ua-tools`,
     their existing SQL calls stay **counted in the per-file ratchet baseline**
     (frozen in place so no new raw SQL can slip into those files), and **all
     new `Procedure`s live in `ua-store`** (or reuse `ua_store::org::tenant_part`).
3. **The hash-chained event ledger and evidence store.**
   - `ua_store::ledger` (`event_log`, `append`, `append_surviving`, `verify`,
     `check_hash_form`) and
   - `ua_store::evidence` (`evidence_key`, `evidence_checkpoint`, checkpoint
     signing/verification and immutability triggers).
   The ledger depends on `BEGIN IMMEDIATE` serialization, monotonic ULID and
   sequence minting, canonical hash chaining, rollback-surviving event commits,
   and SQLite append-only triggers; keeping it directly in `ua-store` preserves
   byte-exact chain compatibility and the `hash_v` rollback fence.
4. **Database lifecycle, locking, and backup/restore.**
   - `ua_store::db` (WAL/pragma setup, `wal_checkpoint(TRUNCATE)`, reader pool,
     progress-handler deadlines),
   - `ua_store::backup` (`VACUUM INTO`, `PRAGMA quick_check`, schema-part
     compatibility checks), and
   - `ua_store::lock`.
5. **One-off Python hub importer (`ua-import`).**
   - `crates/ua-import` performs bulk table/column copying from legacy Python
     hub SQLite databases (`import_runs`, dynamic table map in `map.rs`,
     byte-exact ledger preservation). Its files remain tracked in the per-file
     ratchet baseline so raw SQL there cannot grow unreviewed, without forcing
     bulk import through per-row domain repositories.

## Raw-SQL ratchet

A source-level ratchet test (in the style of
`crates/ua-core/tests/authz_guard.rs` and
`crates/ua-ingress/tests/ingress_guard.rs`) enforces the boundary across every
workspace crate outside `ua-store`.

### What is scanned and what is excluded

- **Scope:** walks `crates/*/src/**/*.rs` for every workspace crate **except
  `ua-store`**.
- **Test exclusion (inline and out-of-line):**
  - Inline `#[cfg(test)]` items are stripped with `without_tests` after masking
    comments, strings, and character literals (reusing the lexer approach in
    `crates/ua-core/tests/support/mod.rs`).
  - Out-of-line test modules declared as `#[cfg(test)] mod <name>;` (for example
    `crates/ua-ingress/src/inbound/tests.rs` from `inbound.rs:469`,
    `crates/ua-ingress/src/outbound/tests.rs` from `outbound.rs:938`, and
    `crates/ua-tools/src/families/github/org_automation_tests.rs`) are resolved
    from their parent module declarations (`<dir>/<name>.rs`,
    `<dir>/<name>/mod.rs`, or `<dir>/<stem>/<name>.rs` for non-`lib.rs`/`mod.rs`
    parents) and excluded before scanning, so test files are never counted as
    production code and filename heuristics are not relied on.

### What is counted (closing dynamic and wrapper bypasses)

Counting only SQL string literals passed directly to `prepare`/`execute`/
`query_row` would miss roughly a quarter of existing sites (`format!` SQL, SQL
bound in `let`/`const`, wrapper helpers such as `platform.rs:613` `org_row`,
`execute_batch`, `prepare_cached`, `query_row_and_then`, and `include_str!`),
and would let a caller *lower* the baseline simply by hoisting a literal into a
`let`.

The ratchet therefore counts:

1. **Every call to a SQL-taking `rusqlite` method regardless of argument
   shape** — `prepare`, `prepare_cached`, `execute`, `execute_batch`,
   `query_row`, and `query_row_and_then` (whether passed a literal, `format!`,
   `let`, `const`, a helper parameter, or `include_str!`) — in every file that
   touches SQLite (`rusqlite`, `Connection`, `WriteTx`, or `Transaction`).
   Scoping to SQLite-using files avoids false positives on unrelated
   `.execute(...)` methods (such as `reqwest` or command runners).
2. **No raw-SQL escape hatch in `ua-store`.** A companion check scans
   `crates/ua-store/src/**/*.rs` and forbids adding any `pub fn` (or public
   trait method) outside `schema.rs` that accepts SQL text as a parameter, so
   callers outside `ua-store` cannot bypass the ratchet through a passthrough
   helper.

### Granularity and drift rule

- **Per-file baseline `(crate, relative_path, count)`.** Granularity is per
  file, not per crate. A per-crate sum over `ua-tools` (~950 sites) would allow
  a PR to remove 5 statements in one family while silently adding 5 raw
  statements in another. Per-file baselines catch any increase in any single
  file, and any file absent from `BASELINE` has an implicit baseline of `0`.
- **Exact match, ratchet down only.** A file above its baseline fails (route
  new queries through `ua-store` instead). A file below its baseline also fails
  with a message instructing the author to lower `BASELINE` in the same PR. The
  baseline only ever moves down.
- **Self-test requirements.** Unit tests in the ratchet test verify:
  - drift reporting in **both directions** (above baseline and below baseline),
  - detection of every call form: literal, `format!`, `let`, `const`, a wrapper
    helper forwarding `sql: &str`, `execute_batch`, `prepare_cached`, and
    `query_row_and_then`,
  - non-counting of comments, inline `#[cfg(test)]` items, out-of-line
    `#[cfg(test)] mod ...;` files, and `.execute(...)` in non-SQLite files, and
  - refusal of a synthetic `pub fn` taking SQL text inside `ua-store`.

### Relationship to the `rusqlite` authorizer hook (`docs/memory.md`)

[memory.md](memory.md) (§3, "Enforcement is in the SQL, on every path")
observes that static scans cannot inspect dynamically constructed SQL and
proposes a runtime `rusqlite` authorizer hook denying reads of `memory`,
`memory_*`, and `memory_fts` outside `MemoryRepo` and an explicit allowlist
(migrations, `ua-import`, operator-only migration manifest).

The two controls are complementary layers, not competing designs:

- The **raw-SQL ratchet** is a **compile/test-time migration guard** covering
  the entire workspace outside `ua-store`. By counting every SQL-taking method
  call regardless of argument shape (including `format!`, variables, and
  helpers), it blocks new dynamic SQL outside `ua-store` as well as static
  literals and drives existing files monotonically to `0`.
- The **`rusqlite` authorizer hook** is a **runtime defense-in-depth gate** for
  high-sensitivity tables with row-level visibility (`memory*`), guaranteeing
  that even an accidental or dynamically composed query cannot read hidden
  notes outside `MemoryRepo` at runtime.

## Pilot aggregate: `task_comments`

The first aggregate migrated behind a `ua-store` trait pair (step (c)) is
**`task_comments` and `task_comment_threads`**.

(`inbound_deliveries` was considered and set aside for the pilot:
`ua_ingress::inbound` is already an isolated, typed, org-scoped module inside
`ua-ingress`, and moving it into `ua-store` would pull ingress-domain types
such as `Claim`, `Sight`, `Settle`, and `Stale` downward into `ua-store`.)

### Call-site inventory and expected baseline drop

| File | Current SQL sites | Plan in pilot PR (c) | Baseline change |
|---|---:|---|---:|
| `crates/ua-tools/src/families/tasks/comments.rs` | 8 (`:143`, `:152`, `:156`, `:257`, `:270`, `:281`, `:287`, `:292`) | Move all 8 queries behind `ua_store::task_comments::{TaskCommentsRead, TaskCommentsWrite, SqliteTaskComments}` and drop `rusqlite` from `comments.rs` | `8 → 0` (`-8`) |
| `crates/ua-tools/src/families/platform.rs` | 1 caller at `:744` (`org_row` wrapper at `:613` serves 6 kinds) | Route `"comment"` at `:744` through `SqliteTaskComments::new(c).get_task_comment(&caller.org_id, comment_id)` | `0` (the `org_row` wrapper at `:613` stays until its other 5 kinds migrate, while `task_comments` SQL leaves `platform.rs`) |
| `crates/ua-tools/src/families/continuity/queue.rs` | 1 cross-table join at `:371-375` (`tasks t LEFT JOIN task_comment_threads c`) | **Keep in place** in pilot PR (c): this is a `tasks` / continuity staleness read (`active_rows`) that joins `tasks` with `task_comment_threads.updated_at`. Keeping it avoids N+1 queries and respects the scope fence (no `tasks` rewrite in the pilot). When `tasks` moves to `ua-store`, `active_rows` either stays a single join inside `ua-store` or uses a batched `task_comment_thread_updated_at` read. | `0` |

Total ratchet baseline drop in step (c): **`-8`** (`comments.rs` drops from `8`
to `0`), with zero schema changes and a two-organization isolation test pinning
`TaskCommentsRead` / `TaskCommentsWrite` directly in `ua-store`.

### Pinned JSON response shape (`SELECT *` compatibility)

Today both `comments.rs:125-137` (`public`) and `platform.rs:744-748` read
`task_comments` with `SELECT *` via `row_object` / `row_map`, remove `org_id`,
and decode `mentions` and `refs`. Moving to explicit typed columns in
`TaskCommentRow` (`id`, `org_id`, `task_id`, `parent_comment_id`, `author`,
`body`, `mentions_json`, `refs_json`, `idempotency_key`, `thread_revision`,
`created_at` — matching `tasks.comments.v1` at `tasks/mod.rs:58-69` plus
`organization.v1.tools.tasks`) must preserve the exact public JSON shape:

- **`task_comment` (`append`, `get`, `list`)** emits the 10 non-`org_id` fields
  (`id`, `task_id`, `parent_comment_id`, `author`, `body`, `mentions` as JSON
  array, `refs` as JSON object, `idempotency_key`, `thread_revision`,
  `created_at`) plus the derived `participants` array (`[author, ...mentions]`).
- **`platform_object_get(kind = "comment")`** emits the same 10 non-`org_id`
  fields with `mentions` and `refs` decoded (and without `participants`).

Step (c) will add a test pinning every key and type of both JSON outputs
against the pre-migration `SELECT *` shape.

## Known multi-path aggregate tracked separately: `tasks`

`tasks` currently has multiple write paths and is explicitly **out of scope**
for steps (a)–(c) of this storage refactor; its kernel seams are tracked as
separate follow-up PRs after the raw-SQL ratchet lands:

- **Direct task inserts bypassing `tasks::insert_task`:** despite
  `crates/ua-tools/src/families/tasks/write.rs:272` stating "Every task
  creation goes through here", `crates/ua-tools/src/families/routines.rs:338-359`
  and `crates/ua-tools/src/families/delegation.rs:703-738` still execute raw
  `INSERT INTO tasks` statements directly (only `continuity/conversation.rs:295`
  routes through `insert_task`).
- **Missing `expected_ownership_generation` fence on `task_update`:**
  `UpdateArgs` (`crates/ua-tools/src/families/tasks/write.rs:46-93`) supports
  `expected_project` and `expected_updated_at` (`:520-527`), and `task_update`
  already increments `ownership_generation` on ownership changes (`:423`,
  `:727`, `:733`), but callers cannot yet guard an update with
  `expected_ownership_generation`.

Closing those two seams first ensures that when `tasks` later moves behind a
`ua-store` repository trait, every task creation and fenced update already
flows through one write path.

## Related documents

- [Technology stack](stack.md) — SQLite WAL pool, named schema parts, and
  storage decisions.
- [Organization](organization.md) — `organization.v1.store`, `tenant_part`,
  `Caller.org_id` provenance, and per-family tenancy rules.
- [Graph](graph.md) — `GraphRead` / `GraphRepo` / `MigrationGraph` storage
  invariants and deadline progress handlers.
- [Memory](memory.md) — `Config.clock` write timestamps and the planned
  `rusqlite` authorizer hook for row-level visibility.
- [Ingress](ingress.md) — `inbound_deliveries` lifecycle and `ingress_guard`.
- [Operations](operations.md) — backup/restore, `Fence`, and `ServeLock`.
