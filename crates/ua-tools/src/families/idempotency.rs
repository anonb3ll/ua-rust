//! Organization keys for `idempotency_keys`
//! (`docs/organization.md`, "Global keys and table rebuilds" and
//! "Converting a table family").
//!
//! `core.v1` keyed a stored receipt by its key text alone, hub-wide. Until
//! this rebuild, another organization's writers prefixed their keys with the
//! organization (`org:<org>/…`, owner decision (a)), so a key reused in two
//! organizations never replayed across them. [`TENANT_KEYS`] rebuilds the
//! table around `(org_id, key)`, and [`TENANT_PART`] installs the
//! organization triggers. Every reader filters `org_id` to the caller's
//! organization and every writer names it.
//!
//! The writers keep their stored key text byte for byte (the organization
//! prefix included) as defence in depth: a receipt is found only when both
//! the row's organization and its key text name the caller's organization,
//! and a retry in flight across the upgrade still replays.

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension};
use ua_store::Procedure;

const TABLE: &str = "idempotency_keys";

/// The organization a pre-rebuild row belongs to. A row whose key carries
/// the interim prefix of exactly one organization `orgs` holds (other than
/// the default) moves there; every other row is the default organization's.
/// Two prefix forms were written:
///
/// - `org:<org>/<tool>:<key>` (`task_add`, `task_update`, `delegate`,
///   `conversation_handoff`), the organization unescaped;
/// - `org:<org>/<tool>/<…>` (`memory_save`, `message_send`), the organization
///   with `%` and `/` percent-escaped.
///
/// `<tool>` is the row's own `tool` column, so the organization part is
/// matched exactly, not up to the first `/`: an organization id holding `/`
/// still resolves. A key that matches two organizations (possible only for
/// the unescaped form, with one organization id a prefix of another followed
/// by `/<tool>:`) is ambiguous and stays in the default organization, as does
/// a prefix naming an organization `orgs` does not hold. No default writer
/// builds a key starting `org:`, so such a row never replays to anyone; it
/// is kept, not dropped, and `system_doctor` counts it
/// ([`unplaced_rows`]).
const PLACE_ORG: &str = "COALESCE((\
    SELECT CASE WHEN COUNT(*) = 1 THEN MIN(o.id) END FROM orgs o \
    WHERE o.id <> 'default' AND substr(k.key, 1, 4) = 'org:' AND ( \
        substr(k.key, 1, length('org:' || o.id || '/' || k.tool || ':')) \
            = 'org:' || o.id || '/' || k.tool || ':' \
        OR substr(k.key, 1, length('org:' || replace(replace(o.id, '%', '%25'), '/', '%2F') || '/' || k.tool || '/')) \
            = 'org:' || replace(replace(o.id, '%', '%25'), '/', '%2F') || '/' || k.tool || '/')\
    ), 'default')";

/// `idempotency.v2.tenant_keys`: rebuild `idempotency_keys` with
/// `org_id TEXT NOT NULL DEFAULT 'default'` and the primary key
/// `(org_id, key)`, so a key is unique per organization, never hub-wide.
/// Every row keeps its rowid, key text, tool, stored result and timestamp
/// unchanged; only `org_id` is assigned (see [`PLACE_ORG`]). Nothing is
/// dropped or rewritten: the row count is checked unchanged. Every index,
/// trigger and view is kept (the trigger and view sets are checked
/// unchanged), and `PRAGMA foreign_key_check(idempotency_keys)` must be
/// clean.
///
/// A row with a NULL `key` (which `core.v1`'s `key TEXT PRIMARY KEY` allowed,
/// though no writer ever stored one) stops the upgrade with its row ids and
/// a fix, rather than being dropped.
///
/// Runs standalone outside the shared migration transaction so
/// `PRAGMA foreign_keys = OFF` takes effect before the rebuild transaction
/// and `PRAGMA foreign_keys = ON` is restored afterwards; a failure rolls
/// back and changes nothing. Safe to re-run after a crash before recording:
/// a table that already carries `org_id` keeps it
/// (`COALESCE(org_id, <placement>)`). Needs `organization.v1.store`.
pub const TENANT_KEYS: Procedure = Procedure {
    name: "idempotency.v2.tenant_keys",
    version: 1,
    standalone: true,
    run: rebuild_tenant_keys,
    args: &[TABLE],
};

/// `organization.v1.tools.idempotency`: installs `idempotency_keys_org_exists`
/// and `idempotency_keys_org_immutable` after `idempotency.v2.tenant_keys`.
pub const TENANT_PART: Procedure = ua_store::org::tenant_part("organization.v1.tools.idempotency", &[TABLE]);

/// Rows of the default organization whose key carries an organization
/// prefix (`org:`): pre-rebuild rows whose prefix named no organization
/// `orgs` holds, or more than one, and pre-scoping raw `memory_save` keys
/// that happened to start with `org:`. No writer builds such a key in the
/// default organization, so none of them replays to anyone; they are kept,
/// not dropped, and age out with the table.
pub(crate) fn unplaced_rows(c: &Connection) -> rusqlite::Result<i64> {
    c.query_row(
        "SELECT COUNT(*) FROM idempotency_keys WHERE org_id = 'default' AND substr(key, 1, 4) = 'org:'",
        [],
        |r| r.get(0),
    )
}

fn rebuild_tenant_keys(conn: &Connection, _args: &'static [&'static str]) -> anyhow::Result<String> {
    anyhow::ensure!(conn.is_autocommit(), "idempotency.v2.tenant_keys must run outside a transaction");
    let mut log = Vec::new();
    conn.execute_batch("PRAGMA foreign_keys = OFF;")?;
    log.push("PRAGMA foreign_keys = OFF;".to_string());

    let res = (|| -> anyhow::Result<()> {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        log.push("BEGIN IMMEDIATE;".to_string());
        rebuild_body(conn, &mut log)?;
        conn.execute_batch("COMMIT;")?;
        log.push("COMMIT;".to_string());
        Ok(())
    })();

    if res.is_err() && !conn.is_autocommit() {
        let _ = conn.execute_batch("ROLLBACK;");
    }
    let fk_res = conn.execute_batch("PRAGMA foreign_keys = ON;");
    res?;
    fk_res?;
    log.push("PRAGMA foreign_keys = ON;".to_string());
    Ok(log.join("\n"))
}

fn names(conn: &Connection, sql: &str) -> anyhow::Result<BTreeSet<String>> {
    Ok(conn.prepare(sql)?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
}

fn name_sql(conn: &Connection, sql: &str) -> anyhow::Result<Vec<(String, String)>> {
    Ok(conn.prepare(sql)?.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?)
}

fn run(conn: &Connection, log: &mut Vec<String>, stmt: String) -> anyhow::Result<()> {
    conn.execute_batch(&stmt)?;
    log.push(stmt);
    Ok(())
}

fn has_column(conn: &Connection, col: &str) -> anyhow::Result<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2", [TABLE, col], |_| Ok(true))
        .optional()?
        .unwrap_or(false))
}

fn rebuild_body(conn: &Connection, log: &mut Vec<String>) -> anyhow::Result<()> {
    let exists: bool = conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [TABLE], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    anyhow::ensure!(exists, "{TABLE} does not exist; apply core.v1 first");
    let orgs: bool = conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'orgs'", [], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    anyhow::ensure!(orgs, "orgs does not exist; apply organization.v1.store first");

    let indexes = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master \
         WHERE type = 'index' AND tbl_name = 'idempotency_keys' AND sql IS NOT NULL ORDER BY name",
    )?;
    let table_triggers = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master \
         WHERE type = 'trigger' AND tbl_name = 'idempotency_keys' AND sql IS NOT NULL ORDER BY name",
    )?;
    let triggers_before = names(conn, "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")?;
    let views = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master WHERE type = 'view' AND sql IS NOT NULL ORDER BY rowid",
    )?;
    let views_before: BTreeSet<String> = views.iter().map(|(name, _)| name.clone()).collect();
    let rows_before: i64 = conn.query_row("SELECT COUNT(*) FROM idempotency_keys", [], |r| r.get(0))?;

    // `core.v1` declared `key TEXT PRIMARY KEY`, which SQLite lets hold NULL.
    // No writer stores one and no reader can find one; rather than drop it
    // silently, stop with its row ids (never a value) so the operator removes
    // it by hand. The rebuild rolls back and nothing changes.
    let null_keys: Vec<i64> = conn
        .prepare("SELECT rowid FROM idempotency_keys WHERE key IS NULL ORDER BY rowid")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(
        null_keys.is_empty(),
        "{TABLE} has {} row(s) with a NULL key (rowid {}); no tool can read them and the (org_id, key) \
         key refuses them. Delete them with `DELETE FROM {TABLE} WHERE key IS NULL` and restart; nothing \
         was changed",
        null_keys.len(),
        null_keys.iter().map(i64::to_string).collect::<Vec<_>>().join(", ")
    );

    let org_expr = if has_column(conn, "org_id")? {
        format!("COALESCE(k.org_id, {PLACE_ORG})")
    } else {
        PLACE_ORG.to_string()
    };

    run(
        conn,
        log,
        "CREATE TABLE idempotency_keys_new (\n    \
            key TEXT NOT NULL,\n    \
            tool TEXT NOT NULL,\n    \
            result_json TEXT NOT NULL,\n    \
            created_at TEXT NOT NULL,\n    \
            org_id TEXT NOT NULL DEFAULT 'default',\n    \
            PRIMARY KEY (org_id, key)\n\
        );"
        .to_string(),
    )?;
    run(
        conn,
        log,
        format!(
            "INSERT INTO idempotency_keys_new (rowid, key, tool, result_json, created_at, org_id) \
             SELECT k.rowid, k.key, k.tool, k.result_json, k.created_at, {org_expr} FROM idempotency_keys k;"
        ),
    )?;

    // Drop views before dropping and renaming the table: SQLite's
    // `ALTER TABLE ... RENAME` validates every view in `sqlite_master` and
    // fails if a view references the just-dropped table.
    for (name, _) in &views {
        let escaped = name.replace('"', "\"\"");
        run(conn, log, format!("DROP VIEW \"{escaped}\";"))?;
    }
    run(conn, log, "DROP TABLE idempotency_keys;".to_string())?;
    run(conn, log, "ALTER TABLE idempotency_keys_new RENAME TO idempotency_keys;".to_string())?;

    for (_, sql) in indexes.iter().chain(&table_triggers).chain(&views) {
        run(conn, log, format!("{};", sql.trim_end_matches(';')))?;
    }

    let rows_after: i64 = conn.query_row("SELECT COUNT(*) FROM idempotency_keys", [], |r| r.get(0))?;
    anyhow::ensure!(
        rows_after == rows_before,
        "{TABLE} rebuild kept {rows_after} of {rows_before} rows; nothing was changed"
    );
    // The audit record names what stayed in the default organization under
    // an organization prefix: a count and row ids, never key text.
    let unplaced: Vec<i64> = conn
        .prepare(
            "SELECT rowid FROM idempotency_keys WHERE org_id = 'default' AND substr(key, 1, 4) = 'org:' \
             ORDER BY rowid",
        )?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let placed: i64 =
        conn.query_row("SELECT COUNT(*) FROM idempotency_keys WHERE org_id <> 'default'", [], |r| r.get(0))?;
    log.push(format!(
        "-- {rows_after} row(s) kept; {placed} placed in another organization by their prefix; {} kept in the \
         default organization under an organization prefix no single organization holds (rowid {})",
        unplaced.len(),
        unplaced.iter().map(i64::to_string).collect::<Vec<_>>().join(", ")
    ));

    let fk_violations: Vec<(String, Option<i64>, String, i64)> = conn
        .prepare("PRAGMA foreign_key_check(idempotency_keys)")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(
        fk_violations.is_empty(),
        "PRAGMA foreign_key_check({TABLE}) reported {} violation(s): {:?}",
        fk_violations.len(),
        fk_violations
    );

    let indexes_after = names(
        conn,
        "SELECT name FROM sqlite_master \
         WHERE type = 'index' AND tbl_name = 'idempotency_keys' AND sql IS NOT NULL ORDER BY name",
    )?;
    for (name, _) in &indexes {
        anyhow::ensure!(indexes_after.contains(name), "index {name} missing after {TABLE} rebuild");
    }
    let triggers_after = names(conn, "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")?;
    anyhow::ensure!(
        triggers_after == triggers_before,
        "trigger set changed across {TABLE} rebuild (before: {triggers_before:?}, after: {triggers_after:?})"
    );
    let views_after = names(conn, "SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY name")?;
    anyhow::ensure!(
        views_after == views_before,
        "view set changed across {TABLE} rebuild (before: {views_before:?}, after: {views_after:?})"
    );
    Ok(())
}
