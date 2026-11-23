//! Organization keys for `managed_secrets`.
//!
//! `managed_secrets.v1` keyed a secret by `name` alone, so two organizations
//! could not store a secret under the same name, and the conflict would tell
//! one that the other had it. [`TENANT_KEYS`] rebuilds the table around
//! `(org_id, name)`; [`TENANT_PART`] then installs the organization triggers
//! (`docs/organization.md`, "Global keys and table rebuilds" and "Converting
//! a table family").

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension};
use ua_store::Procedure;

const TABLE: &str = "managed_secrets";

/// `managed_secrets.v2.tenant_keys`: rebuild `managed_secrets` so its primary
/// key is `(org_id, name)` with `org_id TEXT NOT NULL DEFAULT 'default'`, and
/// add `aad_v INTEGER NOT NULL DEFAULT 1`, the form of the associated data a
/// row was sealed under. Existing secrets move to the default organization
/// and keep `aad_v = 1` (name and consumer): their ciphertext is not touched,
/// because the key is configuration the migration never sees. Every write
/// after this part seals with `aad_v = 2`, which binds the organization too,
/// and a row with `aad_v = 1` decrypts only in the default organization. The
/// other columns keep their `managed_secrets.v1` shape. Every index and
/// trigger is kept, and `idx_managed_secrets_org_consumer`, led by `org_id`,
/// is added for the consumer lookups.
///
/// A row with a NULL `name` (which `managed_secrets.v1`'s key allowed) stops
/// the upgrade with its row ids and a fix, rather than being dropped.
///
/// Runs standalone outside the shared migration transaction so
/// `PRAGMA foreign_keys = OFF` takes effect before the rebuild transaction and
/// `PRAGMA foreign_keys = ON` is restored afterwards. Safe to re-run after a
/// crash before recording: a table that already carries `org_id` and `aad_v`
/// keeps them (`COALESCE(org_id, 'default')`, `COALESCE(aad_v, 1)`).
pub const TENANT_KEYS: Procedure = Procedure {
    name: "managed_secrets.v2.tenant_keys",
    version: 1,
    standalone: true,
    run: rebuild_tenant_keys,
    args: &[TABLE],
};

/// `organization.v1.tools.managed_secrets`: installs
/// `managed_secrets_org_exists` and `managed_secrets_org_immutable` after
/// `managed_secrets.v2.tenant_keys` and `organization.v1.store`.
pub const TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.tools.managed_secrets", &[TABLE]);

fn rebuild_tenant_keys(conn: &Connection, _args: &'static [&'static str]) -> anyhow::Result<String> {
    anyhow::ensure!(conn.is_autocommit(), "managed_secrets.v2.tenant_keys must run outside a transaction");
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
    anyhow::ensure!(exists, "{TABLE} does not exist; apply managed_secrets.v1 first");

    let indexes = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master \
         WHERE type = 'index' AND tbl_name = 'managed_secrets' AND sql IS NOT NULL ORDER BY name",
    )?;
    let table_triggers = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master \
         WHERE type = 'trigger' AND tbl_name = 'managed_secrets' AND sql IS NOT NULL ORDER BY name",
    )?;
    let triggers_before = names(conn, "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")?;
    let views = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master WHERE type = 'view' AND sql IS NOT NULL ORDER BY rowid",
    )?;
    let views_before: BTreeSet<String> = views.iter().map(|(name, _)| name.clone()).collect();

    // `managed_secrets.v1` declared `name TEXT PRIMARY KEY`, which SQLite
    // lets hold NULL. Such a row can never be loaded, listed by name or
    // deleted by a tool, and the new key refuses it. Rather than drop it
    // silently, stop with its row ids (never a value) so the operator removes
    // it by hand; the rebuild rolls back and nothing changes.
    let null_names: Vec<i64> = conn
        .prepare("SELECT rowid FROM managed_secrets WHERE name IS NULL ORDER BY rowid")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(
        null_names.is_empty(),
        "{TABLE} has {} row(s) with a NULL name (rowid {}); no tool can load or delete them and the \
         (org_id, name) key refuses them. Delete them with `DELETE FROM {TABLE} WHERE name IS NULL` and \
         restart; nothing was changed",
        null_names.len(),
        null_names.iter().map(i64::to_string).collect::<Vec<_>>().join(", ")
    );

    let org_expr = if has_column(conn, "org_id")? { "COALESCE(org_id, 'default')" } else { "'default'" };
    let aad_expr = if has_column(conn, "aad_v")? { "COALESCE(aad_v, 1)" } else { "1" };

    run(
        conn,
        log,
        "CREATE TABLE managed_secrets_new (\n    \
            org_id TEXT NOT NULL DEFAULT 'default',\n    \
            name TEXT NOT NULL,\n    \
            consumer TEXT NOT NULL,\n    \
            key_id TEXT NOT NULL,\n    \
            nonce BLOB NOT NULL,\n    \
            ciphertext BLOB NOT NULL,\n    \
            fingerprint TEXT NOT NULL,\n    \
            value_bytes INTEGER NOT NULL,\n    \
            created_by TEXT NOT NULL,\n    \
            created_at TEXT NOT NULL,\n    \
            updated_by TEXT NOT NULL,\n    \
            updated_at TEXT NOT NULL,\n    \
            aad_v INTEGER NOT NULL DEFAULT 1,\n    \
            PRIMARY KEY (org_id, name)\n\
        );"
        .to_string(),
    )?;
    run(
        conn,
        log,
        format!(
            "INSERT INTO managed_secrets_new \
             (org_id, name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes, \
              created_by, created_at, updated_by, updated_at, aad_v) \
             SELECT {org_expr}, name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes, \
              created_by, created_at, updated_by, updated_at, {aad_expr} \
             FROM managed_secrets;"
        ),
    )?;

    // Drop views before dropping and renaming the table: SQLite's
    // `ALTER TABLE ... RENAME` validates every view in `sqlite_master` and
    // fails if a view references the just-dropped table.
    for (name, _) in &views {
        let escaped = name.replace('"', "\"\"");
        run(conn, log, format!("DROP VIEW \"{escaped}\";"))?;
    }
    run(conn, log, "DROP TABLE managed_secrets;".to_string())?;
    run(conn, log, "ALTER TABLE managed_secrets_new RENAME TO managed_secrets;".to_string())?;

    for (_, sql) in indexes.iter().chain(&table_triggers).chain(&views) {
        run(conn, log, format!("{};", sql.trim_end_matches(';')))?;
    }
    run(
        conn,
        log,
        "CREATE INDEX IF NOT EXISTS idx_managed_secrets_org_consumer ON managed_secrets(org_id, consumer, name);"
            .to_string(),
    )?;

    let fk_violations: Vec<(String, Option<i64>, String, i64)> = conn
        .prepare("PRAGMA foreign_key_check(managed_secrets)")?
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
         WHERE type = 'index' AND tbl_name = 'managed_secrets' AND sql IS NOT NULL ORDER BY name",
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
