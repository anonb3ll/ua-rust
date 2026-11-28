# Storage and repository boundaries

Status: **design, with `OrgRead`/`OrgWrite` and `GraphRead`/`GraphRepo` in the tree.**

`ua-store` owns the SQLite WAL database (`Db`: one serialized `BEGIN IMMEDIATE`
writer and a bounded pool of read-only connections), named schema parts,
backups, locks, and the hash-chained event ledger. Today, most tool families
and domain crates still call `rusqlite` directly with inline SQL literals.
That scatters SQLite syntax, row decoding, and tenant-scoping predicates across
hundreds of call sites and makes a second storage backend (noted in
[stack.md](stack.md#planned-or-not-adopted)) impossible to introduce
incrementally.

This note defines the repository boundary for `ua-store`, how it fits with
named schema parts and `tenant_part`, what stays raw SQL, and how the raw-SQL
ratchet moves call sites behind traits without a schema change or a bulk
rewrite.

## Design goals and non-goals

- **One choke point per aggregate.** Each aggregate's queries live in one
  module in `ua-store`, behind typed read and write traits, with `org_id`
  enforced at every query boundary.
- **Single-transaction atomicity.** Writes still commit inside the caller's
  `WriteTx<'_>` alongside `ledger::append` and any cross-aggregate write in the
  same tool call. Repositories never open their own connections or start
  nested transactions.
- **No schema change and no bulk rewrite.** Introducing repository traits and
  the raw-SQL ratchet does not alter any table, index, trigger, or schema-part
  checksum. Existing call sites migrate one aggregate at a time; the ratchet
  only stops new raw SQL from accumulating outside `ua-store`.
- **No `ua-store` upward dependencies.** `ua-store` continues to depend only on
  `ua-core` and third-party crates, never on `ua-tools`, `ua-server`, or domain
  crates (`ua-org`, `ua-memory`, `ua-deliverables`, `ua-graph`, `ua-ingress`).

## Repository trait shape per aggregate

Follow the pattern already established in `ua-store` by
`ua_store::org::{OrgRead, OrgWrite, SqliteOrg}` and
`ua_store::graph::{GraphRead, GraphRepo, SqliteGraph}`.

### Read and write trait pair

Each aggregate exposes a read trait and a write trait in its own `ua-store`
module (for example `ua_store::org`, `ua_store::graph`, or future modules such
as `ua_store::inbound` or `ua_store::task_comments`):

- **`<Aggregate>Read`** holds read-only queries. Every method takes `&mut self`
  (so implementations that need to arm a SQLite `progress_handler` deadline or
  cache prepared statements on a connection can do so without changing the
  trait signature).
- **`<Aggregate>Write: <Aggregate>Read`** (or `<Aggregate>Repo: <Aggregate>Read`
  for existing `GraphRepo`) holds mutations and write-side lookups that run
  inside an active write transaction.

### Connection and transaction binding

- **Read paths** run inside `Db::read` / `Db::read_async` (or `Db::read_mut` /
  `Db::read_mut_async` when a deadline progress handler is installed) by
  wrapping the borrowed `&Connection` in a zero-cost SQLite adapter
  `Sqlite<Aggregate>::new(conn)` that implements `<Aggregate>Read`.
- **Write paths** run inside `Db::write` / `Db::write_async` by implementing
  both `<Aggregate>Read` and `<Aggregate>Write` directly for `WriteTx<'_>`.
  Because `WriteTx<'_>` wraps a `BEGIN IMMEDIATE` `rusqlite::Transaction`, a
  handler can read current state, apply one or more repository writes, and call
  `ledger::append(tx, ...)` atomically in one transaction.
- **No `rusqlite` types in trait signatures.** Inputs are plain Rust values and
  parameter structs (`New<Row>`, `<Row>Patch`, `<Query>`). Outputs are
  `UaResult<T>` carrying typed row structs (`<Row>`, `Option<<Row>>`,
  `Vec<<Row>>`), never `rusqlite::Row`, raw SQL fragments, or untyped
  `serde_json::Value` blobs for structured columns.

```rust
/// Typed row returned by the repository; no `rusqlite` types leak out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExampleRow {
    pub id: i64,
    pub org_id: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewExample {
    pub org_id: String,
    pub body: String,
    pub created_at: String,
}

pub trait ExampleRead {
    fn get(&mut self, org_id: &str, id: i64) -> UaResult<Option<ExampleRow>>;
    fn list_by_parent(&mut self, org_id: &str, parent_id: i64) -> UaResult<Vec<ExampleRow>>;
}

pub trait ExampleWrite: ExampleRead {
    fn insert(&mut self, row: &NewExample) -> UaResult<i64>;
}

/// Thin read adapter over a pooled read-only connection.
pub struct SqliteExample<'a> {
    conn: &'a Connection,
}

impl<'a> SqliteExample<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }
}

impl ExampleRead for SqliteExample<'_> { /* delegates to shared SQL helpers */ }
impl ExampleRead for WriteTx<'_> { /* delegates to the same SQL helpers */ }
impl ExampleWrite for WriteTx<'_> { /* writes on `self` inside BEGIN IMMEDIATE */ }
```

### Tenant scoping (`org_id` in every tenant query)

Every method on a tenant-scoped aggregate must enforce organization isolation
at the SQL boundary:

1. **Explicit `org_id` on every call.** Every read and write method takes
   `org_id: &str` (or a parameter struct with a mandatory `org_id: String`
   field). Repository methods never default to `DEFAULT_ORG` silently.
2. **Bound in every clause.** Every `SELECT`, `JOIN`, `UPDATE`, and `DELETE`
   binds `org_id` explicitly in SQL; every `INSERT` writes `org_id` explicitly.
   Any visibility or scope predicate also executes inside the SQL query before
   `COUNT` or `LIMIT` (never post-filtered in Rust, avoiding existence leaks
   and short pages).
3. **Neutral cross-tenant misses.** Point lookups by `(org_id, id)` return
   `Ok(None)` when a row belongs to another organization, so callers map both
   absent rows and foreign-org rows to the same `not_found` error.
4. **Storage checks vs. domain rules.** Domain crates and tool families own
   authorization (`ua_org::authz`), profile/policy checks, input validation,
   and ledger event shapes. `ua-store` repositories own SQL, row decoding,
   explicit `org_id` binding, safe `LIMIT` clamping, and mapping SQLite errors
   to `UaError`. Where a domain crate has no direct `rusqlite` dependency and
   must append ledger events through the same trait, the write trait may expose
   a narrow `record(...)` helper that forwards to `ledger::append` (as
   `OrgWrite::record` does).

## How schema parts and `tenant_part` fit

The named schema-part system (`crates/ua-store/src/schema.rs`) does not change
when aggregates move behind repository traits:

- **Immutable released parts.** Static `SchemaPart`s (`name`, `sql`) and
  `Procedure`s (`name`, `version`, `standalone`, `run`, `args`) are recorded in
  `schema_parts` by checksum (and procedure output in `schema_procedures`). A
  released part is never edited in place; schema changes ship as new parts with
  new names. `Db::open_with` continues to enforce `Fence` (refusing unknown
  newer parts unless `allow_newer` is set) and `ServeLock` (refusing migrations
  while another `ua serve` holds the database).
- **Tenancy procedures (`tenant_part`).** Each tenant-scoped table family
  continues to apply `ua_store::org::tenant_part("organization.v1.<crate>.<family>", &[tables])`
  after `organization.v1.store`. That procedure adds `org_id TEXT NOT NULL DEFAULT 'default'`
  (or backfills `NULL`s on columns that predate it) and installs the
  `<table>_org_exists` and `<table>_org_immutable` triggers. Born-tenant tables
  (such as `inbound_deliveries` in `ingress.inbound.v1`) declare `org_id TEXT NOT NULL`
  in their initial `SchemaPart` and still pair it with `tenant_part` for the
  triggers.
- **Zero-migration trait extraction.** Moving an aggregate's queries into
  `ua-store` requires no DDL change. The aggregate's existing `SchemaPart` and
  `tenant_part` `Procedure` either stay registered from their current crate or
  are re-exported from `ua-store` with the **exact same `name`, `sql`,
  `version`, and `args`**, preserving checksums and registration order across
  existing databases.
- **New aggregates.** Any new aggregate added after this note lands declares
  its `SchemaPart` (born with `org_id TEXT NOT NULL`) and `tenant_part`
  alongside its repository module, and reaches SQLite only through its
  `Read`/`Write` traits from day one.

## What stays raw

Not every SQL statement in the workspace belongs behind a domain repository
trait. The following remain direct `rusqlite` SQL inside `ua-store` (or
explicitly scoped infrastructure):

1. **Migrations and schema machinery.**
   - `ua_store::schema` (`schema_parts`, `schema_procedures`, `apply`,
     `unknown_parts`, `unrecorded_parts`),
   - `ua_store::org` schema procedures (`STORE_PART`, `tenant_part`,
     `pragma_table_info` / `sqlite_master` introspection), and
   - every crate's `SchemaPart` and `Procedure` DDL/backfill SQL (for example
     one-time legacy table backfills run during `Db::open`).
   DDL and catalog introspection are inherently SQLite-specific and run only at
   database open.
2. **The hash-chained event ledger and evidence store.**
   - `ua_store::ledger` (`event_log`, `append`, `append_surviving`, `verify`,
     `check_hash_form`) and
   - `ua_store::evidence` (`evidence_key`, `evidence_checkpoint`, checkpoint
     signing/verification and immutability triggers).
   The ledger depends on `BEGIN IMMEDIATE` serialization, monotonic ULID and
   sequence minting, canonical hash chaining, rollback-surviving event commits,
   and SQLite append-only triggers; keeping it directly in `ua-store` preserves
   byte-exact chain compatibility and the `hash_v` rollback fence.
3. **Database lifecycle, locking, and backup/restore.**
   - `ua_store::db` (WAL/pragma setup, `wal_checkpoint(TRUNCATE)`, reader pool,
     progress-handler deadlines),
   - `ua_store::backup` (`VACUUM INTO`, `PRAGMA quick_check`, schema-part
     compatibility checks), and
   - `ua_store::lock`.
4. **One-off Python hub importer (`ua-import`).**
   - `crates/ua-import` performs bulk table/column copying from legacy Python
     hub SQLite databases (`import_runs`, dynamic table map in `map.rs`,
     byte-exact ledger preservation). Its existing raw-SQL count is tracked in
     the ratchet baseline so it cannot grow unreviewed, but bulk import is not
     forced through per-row domain repositories.

## Raw-SQL ratchet and incremental migration

To stop new raw SQL outside `ua-store` while migrating existing families
incrementally, a source-level ratchet test (in the style of
`crates/ua-core/tests/authz_guard.rs` and
`crates/ua-ingress/tests/ingress_guard.rs`) enforces the boundary:

- **Scope:** walks non-test source (`crates/*/src/**/*.rs` with `#[cfg(test)]`
  items removed and comments/strings masked) for every workspace crate **except
  `ua-store`**.
- **What is counted:** direct SQL calls (`prepare`, `execute`, and `query_row`
  called with a string literal) per crate.
- **Ratchet rule:** every crate's count must equal its checked-in `BASELINE`
  entry (missing entries mean `0`). Adding a new raw SQL literal outside
  `ua-store` fails the test; removing raw SQL by moving queries behind a
  `ua-store` repository trait fails with an instruction to lower `BASELINE` in
  the same change. The baseline only ever goes down.
- **Self-test:** unit tests inside the ratchet prove that a synthetic new
  `prepare` / `execute` / `query_row` literal fails the guard and that test
  code and comments do not trigger false positives.
- **First pilot aggregate:** once this design and the ratchet land, one small
  aggregate with few call sites (such as `inbound_deliveries` or
  `task_comments`) moves behind a `ua-store` `<Aggregate>Read` /
  `<Aggregate>Write` pair in its own PR, lowering the ratchet baseline with no
  schema change and no behavior change.

## Related documents

- [Technology stack](stack.md) — SQLite WAL pool, named schema parts, and
  planned backend traits.
- [Organization](organization.md) — `organization.v1.store`, `tenant_part`, and
  per-family tenancy rules.
- [Graph](graph.md) — `GraphRead` / `GraphRepo` storage invariants and deadline
  progress handlers.
- [Ingress](ingress.md) — `inbound_deliveries` lifecycle and `ingress_guard`.
- [Operations](operations.md) — backup/restore, `Fence`, and `ServeLock`.
