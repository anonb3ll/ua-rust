//! Organization keys for the harness config tables.
//!
//! `harness_config.v1` keyed a bundle by `version` alone and left `org_id`
//! nullable on bundles and proposals, so two organizations could not publish
//! the same version and the conflict would tell one that the other had it.
//! [`TENANT_KEYS`] rebuilds three tables around their organization;
//! [`TENANT_PART`] then installs the organization triggers on all four
//! (`docs/organization.md`, "Global keys and table rebuilds" and "Converting a
//! table family").

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension};
use ua_store::Procedure;

/// `harness_config.v3.tenant_keys`: rebuild, each with
/// `org_id TEXT NOT NULL DEFAULT 'default'`:
///
/// - `harness_config_bundles` around `UNIQUE(org_id, version)` (each
///   organization has its own versions and its own active bundle);
/// - `harness_config_proposals`, keyed by a hub-global random id, only so its
///   nullable `org_id` becomes `NOT NULL`;
/// - `harness_config_report_window` around `PRIMARY KEY (org_id, node)`, so
///   the rate-limit upsert's conflict target names the organization and can
///   never update another organization's window.
///
/// `harness_config_drift` has no key to change: `organization.v1.tools.harness_config`
/// adds its `org_id`. Existing rows, including those with a `NULL` `org_id`,
/// move to the default organization. The rebuild keeps the bundles'
/// AUTOINCREMENT ids and high-water mark, every index, trigger and view, and
/// adds an index led by `org_id` to each table.
///
/// In the same transaction it expires `harness_config_publish` and
/// `harness_config_apply` approvals, pending or approved but unused, whose
/// payload does not name `org_id`: every payload now binds the organization,
/// so those could never match again (a publish is retried and a node's next
/// report parks a new approval).
///
/// Runs standalone outside the shared migration transaction so
/// `PRAGMA foreign_keys = OFF` takes effect before the rebuild transaction and
/// `PRAGMA foreign_keys = ON` is restored afterwards. Safe to re-run after a
/// crash before recording: an existing `org_id` is kept
/// (`COALESCE(org_id, 'default')`).
pub const TENANT_KEYS: Procedure = Procedure {
    name: "harness_config.v3.tenant_keys",
    version: 1,
    standalone: true,
    run: rebuild_tenant_keys,
    args: &["harness_config_bundles", "harness_config_proposals", "harness_config_report_window"],
};

/// `organization.v1.tools.harness_config`: installs the `*_org_exists` and
/// `*_org_immutable` triggers of the four harness config tables (and `org_id`
/// on `harness_config_drift`) after `harness_config.v3.tenant_keys` and
/// `organization.v1.store`.
pub const TENANT_PART: Procedure = ua_store::org::tenant_part(
    "organization.v1.tools.harness_config",
    &[
        "harness_config_bundles",
        "harness_config_proposals",
        "harness_config_drift",
        "harness_config_report_window",
    ],
);

/// One table the rebuild re-creates.
struct Rebuild {
    table: &'static str,
    /// The new table's body (after `CREATE TABLE <table>_new`).
    body: &'static str,
    /// Every column but `org_id`, copied by name.
    cols: &'static str,
    /// Rows copied (`WHERE ...`, or empty for all).
    filter: &'static str,
    /// The index led by `org_id`.
    org_index: &'static str,
}

const REBUILDS: [Rebuild; 3] = [
    Rebuild {
        table: "harness_config_bundles",
        body: "(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL DEFAULT 'default',
    version TEXT NOT NULL,
    published_at TEXT NOT NULL,
    published_by TEXT NOT NULL,
    bundle_json TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    UNIQUE(org_id, version)
)",
        cols: "id, version, published_at, published_by, bundle_json, active",
        filter: "",
        org_index: "CREATE INDEX IF NOT EXISTS idx_harness_config_bundles_org_active \
                    ON harness_config_bundles(org_id, active);",
    },
    Rebuild {
        table: "harness_config_proposals",
        body: "(
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT 'default',
    node TEXT NOT NULL,
    agent TEXT,
    surface TEXT NOT NULL,
    path TEXT NOT NULL,
    bundle_version TEXT NOT NULL,
    desired_hash TEXT NOT NULL,
    observed_hash TEXT,
    diff_text TEXT,
    desired_text TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    approval_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT,
    diff_base TEXT
)",
        cols: "id, node, agent, surface, path, bundle_version, desired_hash, observed_hash, diff_text, \
               desired_text, status, approval_id, created_at, updated_at, resolved_at, resolved_by, diff_base",
        filter: "",
        org_index: "CREATE INDEX IF NOT EXISTS idx_harness_config_proposals_org_node \
                    ON harness_config_proposals(org_id, node, status, created_at);",
    },
    Rebuild {
        table: "harness_config_report_window",
        body: "(
    org_id TEXT NOT NULL DEFAULT 'default',
    node TEXT NOT NULL,
    window_start TEXT NOT NULL,
    reports INTEGER NOT NULL,
    PRIMARY KEY (org_id, node)
)",
        cols: "node, window_start, reports",
        // `node TEXT PRIMARY KEY` admitted NULL (a SQLite quirk); no report
        // ever wrote one, and a window no node can match counts nothing.
        filter: "WHERE node IS NOT NULL",
        org_index: "",
    },
];

/// Apply approvals and publish approvals in a payload shape that does not
/// bind the organization: they could never match again.
const EXPIRE_UNSCOPED_APPROVALS: &str = "
UPDATE approvals
   SET status = 'expired',
       reason = COALESCE(reason, 'superseded: harness config approvals now bind org_id'),
       updated_at = strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now')
 WHERE tool IN ('harness_config_apply', 'harness_config_publish')
   AND status IN ('pending', 'approved')
   AND (NOT json_valid(payload) OR json_type(payload, '$.org_id') IS NULL)";

/// The reason [`EXPIRE_UNSCOPED_APPROVALS`] writes on an approval it
/// expires (when the approval had none). Kept apart from that statement,
/// which belongs to a merged, checksum-locked part and must not change; a
/// unit test pins that the statement still carries this text.
const UPGRADE_EXPIRY_REASON: &str = "superseded: harness config approvals now bind org_id";

/// Harness config approvals the upgrade expired: `harness_config_publish` and
/// `harness_config_apply` approvals in the expired state with the reason
/// [`EXPIRE_UNSCOPED_APPROVALS`] wrote. The upgrade is a schema part that
/// runs before the hub can append to its hash-chained ledger, so it left no
/// ledger event; `system_doctor` reports this count instead (the approvals
/// themselves are kept, never dropped). An approval that already carried a
/// reason kept it (`COALESCE`), so it is not counted here. A hub-wide count:
/// every such approval predates organizations and is the default
/// organization's.
pub(crate) fn upgrade_expired_approvals(c: &Connection) -> rusqlite::Result<i64> {
    c.query_row(
        "SELECT COUNT(*) FROM approvals WHERE org_id = 'default' \
         AND tool IN ('harness_config_apply', 'harness_config_publish') AND status = 'expired' AND reason = ?1",
        [UPGRADE_EXPIRY_REASON],
        |r| r.get(0),
    )
}

fn rebuild_tenant_keys(conn: &Connection, _args: &'static [&'static str]) -> anyhow::Result<String> {
    anyhow::ensure!(conn.is_autocommit(), "harness_config.v3.tenant_keys must run outside a transaction");
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

fn names(conn: &Connection, sql: &str, table: Option<&str>) -> anyhow::Result<BTreeSet<String>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = match table {
        Some(t) => stmt.query_map([t], |r| r.get(0))?.collect::<Result<_, _>>()?,
        None => stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?,
    };
    Ok(rows)
}

fn named_sql(conn: &Connection, kind: &str, table: &str) -> anyhow::Result<Vec<(String, String)>> {
    Ok(conn
        .prepare(
            "SELECT name, sql FROM sqlite_master \
             WHERE type = ?1 AND tbl_name = ?2 AND sql IS NOT NULL ORDER BY name",
        )?
        .query_map([kind, table], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?)
}

fn table_exists(conn: &Connection, table: &str) -> anyhow::Result<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |_| Ok(true))
        .optional()?
        .unwrap_or(false))
}

fn step(conn: &Connection, log: &mut Vec<String>, stmt: &str) -> anyhow::Result<()> {
    let stmt = format!("{};", stmt.trim().trim_end_matches(';'));
    conn.execute_batch(&stmt)?;
    log.push(stmt);
    Ok(())
}

fn rebuild_body(conn: &Connection, log: &mut Vec<String>) -> anyhow::Result<()> {
    const ALL_TRIGGERS: &str = "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name";
    const ALL_VIEWS: &str = "SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY name";
    let triggers_before = names(conn, ALL_TRIGGERS, None)?;
    // Views are dropped before the tables are swapped (SQLite's
    // `ALTER TABLE ... RENAME` validates every view and fails on one that
    // names a dropped table) and re-created, in their original order, after.
    let views: Vec<(String, String)> = conn
        .prepare(
            "SELECT name, sql FROM sqlite_master WHERE type = 'view' AND sql IS NOT NULL ORDER BY rowid",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let views_before = names(conn, ALL_VIEWS, None)?;
    for (name, _) in &views {
        step(conn, log, &format!("DROP VIEW \"{}\"", name.replace('"', "\"\"")))?;
    }

    for rb in &REBUILDS {
        let t = rb.table;
        anyhow::ensure!(table_exists(conn, t)?, "{t} does not exist; apply harness_config.v1 first");
        let indexes = named_sql(conn, "index", t)?;
        let triggers = named_sql(conn, "trigger", t)?;
        let seq: Option<i64> = conn
            .query_row("SELECT seq FROM sqlite_sequence WHERE name = ?1", [t], |r| r.get(0))
            .optional()?;
        let has_org_id: bool = conn
            .query_row("SELECT 1 FROM pragma_table_info(?1) WHERE name = 'org_id'", [t], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        let org_expr = if has_org_id { "COALESCE(org_id, 'default')" } else { "'default'" };

        step(conn, log, &format!("CREATE TABLE {t}_new {}", rb.body))?;
        step(
            conn,
            log,
            &format!(
                "INSERT INTO {t}_new (org_id, {cols}) SELECT {org_expr}, {cols} FROM {t} {filter}",
                cols = rb.cols,
                filter = rb.filter,
            ),
        )?;
        step(conn, log, &format!("DROP TABLE {t}"))?;
        step(conn, log, &format!("ALTER TABLE {t}_new RENAME TO {t}"))?;
        // Keep the AUTOINCREMENT high-water mark, so an id freed by a delete
        // is never handed out again.
        if let Some(seq) = seq {
            step(conn, log, &format!("DELETE FROM sqlite_sequence WHERE name IN ('{t}', '{t}_new')"))?;
            step(
                conn,
                log,
                &format!(
                    "INSERT INTO sqlite_sequence (name, seq) \
                     SELECT '{t}', MAX({seq}, COALESCE((SELECT MAX(id) FROM {t}), 0))"
                ),
            )?;
        }
        for (_, sql) in &indexes {
            step(conn, log, sql)?;
        }
        if !rb.org_index.is_empty() {
            step(conn, log, rb.org_index)?;
        }
        for (_, sql) in &triggers {
            step(conn, log, sql)?;
        }
        let after = names(
            conn,
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = ?1 AND sql IS NOT NULL",
            Some(t),
        )?;
        for (name, _) in &indexes {
            anyhow::ensure!(after.contains(name), "index {name} missing after the {t} rebuild");
        }
    }

    for (_, sql) in &views {
        step(conn, log, sql)?;
    }

    if table_exists(conn, "approvals")? {
        step(conn, log, EXPIRE_UNSCOPED_APPROVALS)?;
    }

    for rb in &REBUILDS {
        let t = rb.table;
        let fk_violations: Vec<(String, Option<i64>, String, i64)> = conn
            .prepare(&format!("PRAGMA foreign_key_check({t})"))?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        anyhow::ensure!(
            fk_violations.is_empty(),
            "PRAGMA foreign_key_check({t}) reported {} violation(s): {fk_violations:?}",
            fk_violations.len(),
        );
    }
    let triggers_after = names(conn, ALL_TRIGGERS, None)?;
    anyhow::ensure!(
        triggers_after == triggers_before,
        "trigger set changed across the harness config table rebuild (before: {triggers_before:?}, after: \
         {triggers_after:?})"
    );
    let views_after = names(conn, ALL_VIEWS, None)?;
    anyhow::ensure!(
        views_after == views_before,
        "view set changed across the harness config table rebuild (before: {views_before:?}, after: \
         {views_after:?})"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The doctor's count reads the reason the merged part writes.
    #[test]
    fn the_upgrade_expiry_reason_matches_the_merged_statement() {
        assert!(EXPIRE_UNSCOPED_APPROVALS.contains(&format!("'{UPGRADE_EXPIRY_REASON}'")));
    }
}
