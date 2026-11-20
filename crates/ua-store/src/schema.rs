//! Named schema parts.

use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// One idempotent unit of schema. `name` must never change once released;
/// to alter a table, add a new part with a new name.
#[derive(Debug, Clone, Copy)]
pub struct SchemaPart {
    pub name: &'static str,
    pub sql: &'static str,
}

const TRACKING: &str = "CREATE TABLE IF NOT EXISTS schema_parts (
    name TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
)";

/// Import progress, per source and table (optional; applied by `ua import`).
pub const IMPORT_SCHEMA: SchemaPart = SchemaPart {
    name: "import.v1",
    sql: "
CREATE TABLE IF NOT EXISTS import_runs (
    source_hash TEXT NOT NULL,
    table_name TEXT NOT NULL,
    copied INTEGER NOT NULL DEFAULT 0,
    skipped INTEGER NOT NULL DEFAULT 0,
    last_key INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (source_hash, table_name)
);
",
};

/// Apply every part not yet recorded. Runs in one transaction.
pub fn apply(conn: &mut Connection, parts: &[SchemaPart]) -> anyhow::Result<Vec<&'static str>> {
    conn.execute_batch(TRACKING)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut applied = Vec::new();
    for part in parts {
        let checksum = hex::encode(Sha256::digest(part.sql.as_bytes()));
        let existing: Option<String> =
            tx.query_row("SELECT checksum FROM schema_parts WHERE name = ?1", [part.name], |r| r.get(0)).ok();
        match existing {
            Some(prev) if prev == checksum => continue,
            Some(_) => {
                anyhow::bail!(
                    "schema part {} changed after it was applied; released parts are immutable, add a new part instead",
                    part.name
                );
            }
            None => {}
        }
        tx.execute_batch(part.sql).map_err(|e| anyhow::anyhow!("schema part {}: {e}", part.name))?;
        tx.execute(
            "INSERT INTO schema_parts (name, checksum, applied_at) VALUES (?1, ?2, ?3)",
            (part.name, &checksum, ua_core::time::now()),
        )?;
        applied.push(part.name);
    }
    tx.commit()?;
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_released_part_is_a_startup_error() {
        let mut conn = Connection::open_in_memory().unwrap();
        let v1 = SchemaPart { name: "demo.v1", sql: "CREATE TABLE IF NOT EXISTS demo (id INTEGER);" };
        assert_eq!(apply(&mut conn, &[v1]).unwrap(), ["demo.v1"]);
        assert!(apply(&mut conn, &[v1]).unwrap().is_empty(), "re-applying is a no-op");
        let edited =
            SchemaPart { name: "demo.v1", sql: "CREATE TABLE IF NOT EXISTS demo (id INTEGER, x TEXT);" };
        let err = apply(&mut conn, &[edited]).unwrap_err();
        assert!(err.to_string().contains("demo.v1"), "{err}");
    }
}
