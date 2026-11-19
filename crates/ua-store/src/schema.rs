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
                tracing::warn!(part = part.name, "schema part changed after release; not re-applied");
                continue;
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
