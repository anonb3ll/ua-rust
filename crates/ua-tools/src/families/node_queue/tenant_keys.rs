//! Organization keys for the node and dispatch tables
//! (`docs/organization.md`, "Global keys and table rebuilds" and
//! "Converting a table family").
//!
//! A node belongs to the organization that registered it; a queued item, a
//! claim operation, a supervised command, its owner notice, a follow-up and a
//! device acceptance run belong to their node's (and so the item's)
//! organization; a dispatch run belongs to its task's, and a receipt to its
//! run's.
//!
//! `node_queue.v1` made `launch_key` unique hub-wide, so two organizations
//! could not use the same client key and the conflict would tell one that
//! the other had. [`TENANT_KEYS`] rebuilds `node_dispatch` with a `NOT NULL`
//! `org_id` and the launch-key index on `(org_id, launch_key)`.
//! [`TENANT_PART`] and [`DISPATCH_TENANT_PART`] then add `org_id` to the
//! other tables and install the organization triggers on all nine, and
//! [`ORG_SCOPE`] and [`DISPATCH_ORG_SCOPE`] add the indexes led by `org_id`
//! and the same-organization reference triggers.
//!
//! No other key needs the organization: a node name is one hub namespace
//! (like an agent label, and a node serves one organization), an item, a
//! follow-up and a run id are hub-generated, and every other key is led by
//! one of those (`node_claim_ops (node, op_id)`, `node_followups (item_id,
//! …)`, `node_command_notice (item_id, attempt, terminal)`). Every existing
//! row lands in the default organization: before this change no caller
//! outside it could be authenticated (`org_guard`), so the default
//! organization registered every node and created every item and run.
//! Nothing is dropped or rewritten.

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension};
use ua_store::{Procedure, SchemaPart};

const TABLE: &str = "node_dispatch";

/// The columns of `node_dispatch` as `node_queue.v1` created them, in order.
const COLUMNS: &str = "id, node, agent, backend, prompt, cwd, cwd_realpath, model, permission_mode, \
    settings_source, timeout_s, run_id, task_id, status, attempts, cancel_requested, created_by, created_at, \
    claimed_at, lease_expires_at, completed_at, receipt_json, session_id, launch_key, wait_reason, \
    wait_last_heartbeat, wait_expires_at, updated_at";

/// The launch-key index this rebuild replaces (same name, new key).
const LAUNCH_KEY_INDEX: &str = "idx_node_dispatch_launch_key";

/// `node_queue.v2.tenant_keys`: rebuild `node_dispatch` with
/// `org_id TEXT NOT NULL DEFAULT 'default'` and its client launch keys unique
/// per organization (`UNIQUE (org_id, launch_key) WHERE launch_key IS NOT
/// NULL`), so one organization's key never collides with, replays or reveals
/// another's. Existing items keep their ids and rowids (the queue orders by
/// rowid) and move to the default organization; every existing launch key
/// stays unique, since all of them are now the default organization's. The
/// other columns keep their `node_queue.v1` shape. Every other index, every
/// trigger and every view is kept; the trigger and view sets are checked
/// unchanged, and `PRAGMA foreign_key_check(node_dispatch)` must be clean.
///
/// Runs standalone outside the shared migration transaction so
/// `PRAGMA foreign_keys = OFF` takes effect before the rebuild transaction
/// and `PRAGMA foreign_keys = ON` is restored afterwards; a failure rolls
/// back and changes nothing. Safe to re-run after a crash before recording:
/// a table that already carries `org_id` keeps it
/// (`COALESCE(org_id, 'default')`).
pub const TENANT_KEYS: Procedure = Procedure {
    name: "node_queue.v2.tenant_keys",
    version: 1,
    standalone: true,
    run: rebuild_tenant_keys,
    args: &[TABLE],
};

/// `organization.v1.tools.nodes`: `org_id` on the node registry and the
/// node work queue (`node_dispatch` already has it from
/// [`TENANT_KEYS`]), and the generated `<table>_org_exists` /
/// `<table>_org_immutable` triggers on all seven.
pub const TENANT_PART: Procedure = ua_store::org::tenant_part(
    "organization.v1.tools.nodes",
    &[
        "nodes",
        "node_acceptance",
        "node_claim_ops",
        "node_command",
        "node_command_notice",
        "node_dispatch",
        "node_followups",
    ],
);

/// `organization.v1.tools.dispatch`: `org_id` on `dispatch_runs` and
/// `dispatch_receipts` and their generated organization triggers. No key
/// rebuild: a run id is hub-generated and a receipt's key is an
/// AUTOINCREMENT id.
pub const DISPATCH_TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.tools.dispatch", &["dispatch_runs", "dispatch_receipts"]);

/// `dispatch.v4.org_scope`: indexes led by `org_id` for the run listings,
/// and triggers that keep a run's task, and a receipt's run, in the row's own
/// organization.
pub const DISPATCH_ORG_SCOPE: SchemaPart = SchemaPart {
    name: "dispatch.v4.org_scope",
    sql: "
CREATE INDEX IF NOT EXISTS idx_dispatch_runs_org_created ON dispatch_runs(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_dispatch_runs_org_task ON dispatch_runs(org_id, task_id, created_at);

CREATE TRIGGER IF NOT EXISTS dispatch_runs_org_parent BEFORE INSERT ON dispatch_runs
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS dispatch_runs_org_parent_update BEFORE UPDATE OF task_id ON dispatch_runs
WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'task belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS dispatch_receipts_org_parent BEFORE INSERT ON dispatch_receipts
WHEN EXISTS (SELECT 1 FROM dispatch_runs WHERE run_id = NEW.run_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'dispatch run belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS dispatch_receipts_org_parent_update BEFORE UPDATE OF run_id ON dispatch_receipts
WHEN EXISTS (SELECT 1 FROM dispatch_runs WHERE run_id = NEW.run_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'dispatch run belongs to another organization'); END;
",
};

/// `node_queue.v2.org_scope`: indexes led by `org_id` for the node listing
/// and the per-organization item queries, and triggers that keep every
/// reference inside the row's organization: an item's node, task and run; an
/// acceptance run's node and items; a claim operation's node and item; a
/// command's, a notice's and a follow-up's item (and a notice's task).
pub const ORG_SCOPE: SchemaPart = SchemaPart {
    name: "node_queue.v2.org_scope",
    sql: "
CREATE INDEX IF NOT EXISTS idx_nodes_org_agent ON nodes(org_id, agent);
CREATE INDEX IF NOT EXISTS idx_node_dispatch_org_node_status ON node_dispatch(org_id, node, status, created_at);
CREATE INDEX IF NOT EXISTS idx_node_dispatch_org_created ON node_dispatch(org_id, created_at);

CREATE TRIGGER IF NOT EXISTS node_dispatch_org_parent BEFORE INSERT ON node_dispatch
WHEN EXISTS (SELECT 1 FROM nodes WHERE node = NEW.node AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM dispatch_runs WHERE run_id = NEW.run_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'node, task or run belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS node_dispatch_org_parent_update BEFORE UPDATE OF node, task_id, run_id ON node_dispatch
WHEN EXISTS (SELECT 1 FROM nodes WHERE node = NEW.node AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM dispatch_runs WHERE run_id = NEW.run_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'node, task or run belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS node_acceptance_org_parent BEFORE INSERT ON node_acceptance
WHEN EXISTS (SELECT 1 FROM nodes WHERE node = NEW.node AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM node_dispatch WHERE id IN (NEW.complete_item_id, NEW.cancel_item_id)
             AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'node or item belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS node_acceptance_org_parent_update
BEFORE UPDATE OF node, complete_item_id, cancel_item_id ON node_acceptance
WHEN EXISTS (SELECT 1 FROM nodes WHERE node = NEW.node AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM node_dispatch WHERE id IN (NEW.complete_item_id, NEW.cancel_item_id)
             AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'node or item belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS node_claim_ops_org_parent BEFORE INSERT ON node_claim_ops
WHEN EXISTS (SELECT 1 FROM nodes WHERE node = NEW.node AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM node_dispatch WHERE id = NEW.item_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'node or item belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS node_claim_ops_org_parent_update BEFORE UPDATE OF node, item_id ON node_claim_ops
WHEN EXISTS (SELECT 1 FROM nodes WHERE node = NEW.node AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM node_dispatch WHERE id = NEW.item_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'node or item belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS node_command_org_parent BEFORE INSERT ON node_command
WHEN EXISTS (SELECT 1 FROM node_dispatch WHERE id = NEW.item_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'item belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS node_command_org_parent_update BEFORE UPDATE OF item_id ON node_command
WHEN EXISTS (SELECT 1 FROM node_dispatch WHERE id = NEW.item_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'item belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS node_command_notice_org_parent BEFORE INSERT ON node_command_notice
WHEN EXISTS (SELECT 1 FROM node_dispatch WHERE id = NEW.item_id AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'item or task belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS node_command_notice_org_parent_update
BEFORE UPDATE OF item_id, task_id ON node_command_notice
WHEN EXISTS (SELECT 1 FROM node_dispatch WHERE id = NEW.item_id AND org_id IS NOT NEW.org_id)
  OR EXISTS (SELECT 1 FROM tasks WHERE id = NEW.task_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'item or task belongs to another organization'); END;

CREATE TRIGGER IF NOT EXISTS node_followups_org_parent BEFORE INSERT ON node_followups
WHEN EXISTS (SELECT 1 FROM node_dispatch WHERE id = NEW.item_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'item belongs to another organization'); END;
CREATE TRIGGER IF NOT EXISTS node_followups_org_parent_update BEFORE UPDATE OF item_id ON node_followups
WHEN EXISTS (SELECT 1 FROM node_dispatch WHERE id = NEW.item_id AND org_id IS NOT NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'item belongs to another organization'); END;
",
};

fn rebuild_tenant_keys(conn: &Connection, _args: &'static [&'static str]) -> anyhow::Result<String> {
    anyhow::ensure!(conn.is_autocommit(), "node_queue.v2.tenant_keys must run outside a transaction");
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
    anyhow::ensure!(exists, "{TABLE} does not exist; apply node_queue.v1 first");

    let indexes = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master \
         WHERE type = 'index' AND tbl_name = 'node_dispatch' AND sql IS NOT NULL ORDER BY name",
    )?;
    let table_triggers = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master \
         WHERE type = 'trigger' AND tbl_name = 'node_dispatch' AND sql IS NOT NULL ORDER BY name",
    )?;
    let triggers_before = names(conn, "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")?;
    let views = name_sql(
        conn,
        "SELECT name, sql FROM sqlite_master WHERE type = 'view' AND sql IS NOT NULL ORDER BY rowid",
    )?;
    let views_before: BTreeSet<String> = views.iter().map(|(name, _)| name.clone()).collect();
    let rows_before: i64 = conn.query_row("SELECT COUNT(*) FROM node_dispatch", [], |r| r.get(0))?;

    let org_expr = if has_column(conn, "org_id")? { "COALESCE(org_id, 'default')" } else { "'default'" };

    run(
        conn,
        log,
        "CREATE TABLE node_dispatch_new (\n    \
            id TEXT PRIMARY KEY,\n    \
            node TEXT NOT NULL,\n    \
            agent TEXT NOT NULL,\n    \
            backend TEXT NOT NULL,\n    \
            prompt TEXT NOT NULL,\n    \
            cwd TEXT NOT NULL,\n    \
            cwd_realpath TEXT,\n    \
            model TEXT,\n    \
            permission_mode TEXT,\n    \
            settings_source TEXT,\n    \
            timeout_s INTEGER NOT NULL,\n    \
            run_id TEXT,\n    \
            task_id INTEGER,\n    \
            status TEXT NOT NULL DEFAULT 'queued'\n        \
                CHECK (status IN ('queued','claimed','finished','failed','killed','cancelled')),\n    \
            attempts INTEGER NOT NULL DEFAULT 0,\n    \
            cancel_requested INTEGER NOT NULL DEFAULT 0,\n    \
            created_by TEXT NOT NULL,\n    \
            created_at TEXT NOT NULL,\n    \
            claimed_at TEXT,\n    \
            lease_expires_at TEXT,\n    \
            completed_at TEXT,\n    \
            receipt_json TEXT,\n    \
            session_id TEXT,\n    \
            launch_key TEXT,\n    \
            wait_reason TEXT,\n    \
            wait_last_heartbeat TEXT,\n    \
            wait_expires_at TEXT,\n    \
            updated_at TEXT NOT NULL,\n    \
            org_id TEXT NOT NULL DEFAULT 'default'\n\
        );"
        .to_string(),
    )?;
    run(
        conn,
        log,
        format!(
            "INSERT INTO node_dispatch_new (rowid, {COLUMNS}, org_id) \
             SELECT rowid, {COLUMNS}, {org_expr} FROM node_dispatch;"
        ),
    )?;

    // Drop views before dropping and renaming the table: SQLite's
    // `ALTER TABLE ... RENAME` validates every view in `sqlite_master` and
    // fails if a view references the just-dropped table.
    for (name, _) in &views {
        let escaped = name.replace('"', "\"\"");
        run(conn, log, format!("DROP VIEW \"{escaped}\";"))?;
    }
    run(conn, log, "DROP TABLE node_dispatch;".to_string())?;
    run(conn, log, "ALTER TABLE node_dispatch_new RENAME TO node_dispatch;".to_string())?;

    for (name, sql) in &indexes {
        if name == LAUNCH_KEY_INDEX {
            continue;
        }
        run(conn, log, format!("{};", sql.trim_end_matches(';')))?;
    }
    run(
        conn,
        log,
        format!(
            "CREATE UNIQUE INDEX {LAUNCH_KEY_INDEX} ON node_dispatch(org_id, launch_key) \
             WHERE launch_key IS NOT NULL;"
        ),
    )?;
    for (_, sql) in table_triggers.iter().chain(&views) {
        run(conn, log, format!("{};", sql.trim_end_matches(';')))?;
    }

    let rows_after: i64 = conn.query_row("SELECT COUNT(*) FROM node_dispatch", [], |r| r.get(0))?;
    anyhow::ensure!(
        rows_after == rows_before,
        "{TABLE} rebuild kept {rows_after} of {rows_before} rows; nothing was changed"
    );
    let fk_violations: Vec<(String, Option<i64>, String, i64)> = conn
        .prepare("PRAGMA foreign_key_check(node_dispatch)")?
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
         WHERE type = 'index' AND tbl_name = 'node_dispatch' AND sql IS NOT NULL ORDER BY name",
    )?;
    for (name, _) in &indexes {
        anyhow::ensure!(indexes_after.contains(name), "index {name} missing after {TABLE} rebuild");
    }
    anyhow::ensure!(
        indexes_after.contains(LAUNCH_KEY_INDEX),
        "index {LAUNCH_KEY_INDEX} missing after {TABLE} rebuild"
    );
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
