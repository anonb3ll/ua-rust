//! Organization keys for `project_repo_bindings`.
//!
//! `governance.v1` keyed a binding by `project` alone, so two organizations
//! could not bind the same project slug, and the conflict would tell one that
//! the other had it. [`PROJECT_BINDINGS_TENANT_KEYS`] rebuilds the table
//! around `(org_id, project)`; [`PROJECT_BINDINGS_TENANT_PART`] then installs
//! the organization triggers (`docs/organization.md`, "Global keys and table
//! rebuilds" and "Converting a table family").

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension};
use ua_store::Procedure;

const TABLE: &str = "project_repo_bindings";

/// `governance.v2.project_bindings_tenant_keys`: rebuild
/// `project_repo_bindings` so its primary key is `(org_id, project)` with
/// `org_id TEXT NOT NULL DEFAULT 'default'`. Existing bindings move to the
/// default organization. The other columns keep their `governance.v1`
/// shape, so every legacy row copies across.
///
/// Runs standalone outside the shared migration transaction so
/// `PRAGMA foreign_keys = OFF` takes effect before the rebuild transaction and
/// `PRAGMA foreign_keys = ON` is restored afterwards. Safe to re-run after a
/// crash before recording: a table that already carries `org_id` keeps it
/// (`COALESCE(org_id, 'default')`).
pub const PROJECT_BINDINGS_TENANT_KEYS: Procedure = Procedure {
    name: "governance.v2.project_bindings_tenant_keys",
    version: 1,
    standalone: true,
    run: rebuild_tenant_keys,
    args: &[TABLE],
};

/// `organization.v1.tools.project_bindings`: installs
/// `project_repo_bindings_org_exists` and `project_repo_bindings_org_immutable`
/// after `governance.v2.project_bindings_tenant_keys` and
/// `organization.v1.store`.
pub const PROJECT_BINDINGS_TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.tools.project_bindings", &[TABLE]);

fn rebuild_tenant_keys(conn: &Connection, _args: &'static [&'static str]) -> anyhow::Result<String> {
    anyhow::ensure!(
        conn.is_autocommit(),
        "governance.v2.project_bindings_tenant_keys must run outside a transaction"
    );
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

fn rebuild_body(conn: &Connection, log: &mut Vec<String>) -> anyhow::Result<()> {
    let exists: bool = conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [TABLE], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    anyhow::ensure!(exists, "{TABLE} does not exist; apply governance.v1 first");

    let indexes = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master \
         WHERE type = 'index' AND tbl_name = 'project_repo_bindings' AND sql IS NOT NULL ORDER BY name",
    )?;
    let table_triggers = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master \
         WHERE type = 'trigger' AND tbl_name = 'project_repo_bindings' AND sql IS NOT NULL ORDER BY name",
    )?;
    let triggers_before = names(conn, "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")?;
    let views = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master WHERE type = 'view' AND sql IS NOT NULL ORDER BY rowid",
    )?;
    let views_before: BTreeSet<String> = views.iter().map(|(name, _)| name.clone()).collect();

    let has_org_id: bool = conn
        .query_row("SELECT 1 FROM pragma_table_info(?1) WHERE name = 'org_id'", [TABLE], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    let org_expr = if has_org_id { "COALESCE(org_id, 'default')" } else { "'default'" };

    run(
        conn,
        log,
        "CREATE TABLE project_repo_bindings_new (\n    \
            org_id TEXT NOT NULL DEFAULT 'default',\n    \
            project TEXT,\n    \
            repo TEXT NOT NULL,\n    \
            default_branch TEXT,\n    \
            bound_by TEXT NOT NULL,\n    \
            bound_at TEXT NOT NULL,\n    \
            PRIMARY KEY (org_id, project)\n\
        );"
        .to_string(),
    )?;
    run(
        conn,
        log,
        format!(
            "INSERT INTO project_repo_bindings_new \
             (org_id, project, repo, default_branch, bound_by, bound_at) \
             SELECT {org_expr}, project, repo, default_branch, bound_by, bound_at \
             FROM project_repo_bindings;"
        ),
    )?;

    // Drop views before dropping and renaming the table: SQLite's
    // `ALTER TABLE ... RENAME` validates every view in `sqlite_master` and
    // fails if a view references the just-dropped table.
    for (name, _) in &views {
        let escaped = name.replace('"', "\"\"");
        run(conn, log, format!("DROP VIEW \"{escaped}\";"))?;
    }
    run(conn, log, "DROP TABLE project_repo_bindings;".to_string())?;
    run(conn, log, "ALTER TABLE project_repo_bindings_new RENAME TO project_repo_bindings;".to_string())?;

    for (_, sql) in indexes.iter().chain(&table_triggers).chain(&views) {
        run(conn, log, format!("{};", sql.trim_end_matches(';')))?;
    }

    let fk_violations: Vec<(String, Option<i64>, String, i64)> = conn
        .prepare("PRAGMA foreign_key_check(project_repo_bindings)")?
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
         WHERE type = 'index' AND tbl_name = 'project_repo_bindings' AND sql IS NOT NULL ORDER BY name",
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
