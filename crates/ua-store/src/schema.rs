//! Named schema parts.
//!
//! A part is one idempotent unit of schema, applied once and recorded by name
//! in `schema_parts` with a checksum. A part never changes once released: a
//! changed part is a start-up error, and an altered table gets a new part with
//! a new name. There are two kinds:
//!
//! | Kind | Body | Checksum covers |
//! |---|---|---|
//! | [`SchemaPart`] (static) | a `&'static str` of SQL | that SQL |
//! | [`Procedure`] | a Rust function and an explicit `version` | the part name and the `version` |
//!
//! A procedure exists for schema whose SQL depends on the database it runs on
//! (a column that may already be there, a timestamp bound at run time). It is
//! checked by name and `version` only. The SQL it generated is stored in
//! `schema_procedures` for audit and is never regenerated or compared on later
//! starts. Re-running a recorded procedure with a different `version` under
//! the same name is refused like a changed static part, so a procedure that
//! changes ships under a new name.
//!
//! A procedure flagged `standalone` runs alone, outside the shared
//! transaction: the pending parts before it are committed first, it runs with
//! no transaction open (so it can, for example, turn `PRAGMA foreign_keys`
//! off), and the parts after it resume in a new transaction.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

/// A static part: one fixed SQL batch. `name` must never change once
/// released; to alter a table, add a new part with a new name.
#[derive(Debug, Clone, Copy)]
pub struct SchemaPart {
    pub name: &'static str,
    pub sql: &'static str,
}

/// The body of a procedure part. It receives the procedure's `args` and
/// returns the SQL it ran, for the audit record.
pub type ProcedureFn = fn(&Connection, &'static [&'static str]) -> anyhow::Result<String>;

/// A procedure part. See the module documentation.
///
/// **Contract for `standalone` procedures: they must be safe to re-run.** A
/// standalone procedure commits its own work, and [`apply`] records the part
/// afterwards in a separate short transaction. If the process dies between
/// the two, the part is not recorded and the procedure runs again on the
/// next start, against the database it already changed. It must then either
/// finish without changing anything further or fail without corrupting the
/// database.
#[derive(Debug, Clone, Copy)]
pub struct Procedure {
    pub name: &'static str,
    /// Bumped whenever `run` or `args` would behave differently. A recorded
    /// procedure whose version differs is refused; ship a new name instead.
    pub version: u32,
    /// Run alone, outside the shared transaction. Such a procedure must be
    /// safe to re-run (see above).
    pub standalone: bool,
    pub run: ProcedureFn,
    /// Static arguments passed to `run` (for example the tables a
    /// tenant part covers).
    pub args: &'static [&'static str],
}

/// What a part runs.
#[derive(Debug, Clone, Copy)]
pub enum PartKind {
    Static { sql: &'static str },
    Procedure(Procedure),
}

/// Any schema part, as [`apply`] and the backup compatibility check take it.
/// A [`SchemaPart`] or a [`Procedure`] converts into it.
#[derive(Debug, Clone, Copy)]
pub struct Part {
    pub name: &'static str,
    pub kind: PartKind,
}

impl From<SchemaPart> for Part {
    fn from(p: SchemaPart) -> Self {
        Part { name: p.name, kind: PartKind::Static { sql: p.sql } }
    }
}

impl From<Procedure> for Part {
    fn from(p: Procedure) -> Self {
        Part { name: p.name, kind: PartKind::Procedure(p) }
    }
}

impl SchemaPart {
    /// The checksum recorded in `schema_parts`.
    pub fn checksum(&self) -> String {
        Part::from(*self).checksum()
    }
}

impl Part {
    /// The checksum recorded in `schema_parts`: the SHA-256 of the SQL for a
    /// static part, of the name and `version` for a procedure.
    pub fn checksum(&self) -> String {
        match self.kind {
            PartKind::Static { sql } => hex::encode(Sha256::digest(sql.as_bytes())),
            PartKind::Procedure(p) => {
                hex::encode(Sha256::digest(format!("procedure\0{}\0{}", p.name, p.version).as_bytes()))
            }
        }
    }

    fn is_standalone(&self) -> bool {
        matches!(self.kind, PartKind::Procedure(Procedure { standalone: true, .. }))
    }
}

/// Convert a slice of any part type into [`Part`]s.
pub fn parts<P: Into<Part> + Copy>(ps: &[P]) -> Vec<Part> {
    ps.iter().map(|p| (*p).into()).collect()
}

const TRACKING: &str = "CREATE TABLE IF NOT EXISTS schema_parts (
    name TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
)";

/// The audit record of applied procedures. Created with the first procedure
/// that runs, so a database that never ran one keeps exactly the objects it
/// had (and an older backup still matches the reference schema).
const PROCEDURE_TRACKING: &str = "CREATE TABLE IF NOT EXISTS schema_procedures (
    name TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    generated_sql TEXT NOT NULL,
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

/// Whether `part` still has to run: `false` when it is recorded with the same
/// checksum, an error when it is recorded with a different one.
fn pending(conn: &Connection, part: &Part) -> anyhow::Result<bool> {
    let existing: Option<String> = conn
        .query_row("SELECT checksum FROM schema_parts WHERE name = ?1", [part.name], |r| r.get(0))
        .optional()?;
    match existing {
        None => Ok(true),
        Some(prev) if prev == part.checksum() => Ok(false),
        Some(_) => match part.kind {
            PartKind::Static { .. } => anyhow::bail!(
                "schema part {} changed after it was applied; released parts are immutable, add a new part instead",
                part.name
            ),
            PartKind::Procedure(p) => {
                let recorded = recorded_procedure_version(conn, p.name)?;
                anyhow::bail!(
                    "schema part {} changed after it was applied (recorded procedure version {}, this build has \
                     version {}); released parts are immutable, ship the changed procedure under a new name",
                    part.name,
                    recorded.map(|v| v.to_string()).unwrap_or_else(|| "unknown".into()),
                    p.version
                )
            }
        },
    }
}

fn recorded_procedure_version(conn: &Connection, name: &str) -> anyhow::Result<Option<i64>> {
    let has: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_procedures'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if !has {
        return Ok(None);
    }
    Ok(conn
        .query_row("SELECT version FROM schema_procedures WHERE name = ?1", [name], |r| r.get(0))
        .optional()?)
}

/// Run one part's body and record it, on a connection that is either inside
/// the shared transaction or (for a standalone part) inside the short
/// transaction that only records it.
fn record(conn: &Connection, part: &Part, generated_sql: Option<&str>) -> anyhow::Result<()> {
    let now = ua_core::time::now();
    conn.execute(
        "INSERT INTO schema_parts (name, checksum, applied_at) VALUES (?1, ?2, ?3)",
        (part.name, part.checksum(), &now),
    )?;
    if let (PartKind::Procedure(p), Some(sql)) = (part.kind, generated_sql) {
        conn.execute_batch(PROCEDURE_TRACKING)?;
        conn.execute(
            "INSERT INTO schema_procedures (name, version, generated_sql, applied_at) VALUES (?1, ?2, ?3, ?4)",
            (p.name, p.version, sql, &now),
        )?;
    }
    Ok(())
}

fn run_in(tx: &Transaction<'_>, part: &Part) -> anyhow::Result<()> {
    let generated = match part.kind {
        PartKind::Static { sql } => {
            tx.execute_batch(sql).map_err(|e| anyhow::anyhow!("schema part {}: {e}", part.name))?;
            None
        }
        PartKind::Procedure(p) => {
            Some((p.run)(tx, p.args).map_err(|e| anyhow::anyhow!("schema part {}: {e:#}", part.name))?)
        }
    };
    record(tx, part, generated.as_deref())
}

/// Apply every part not yet recorded, in order. Ordinary parts share one
/// `BEGIN IMMEDIATE` transaction; a `standalone` procedure splits it (see the
/// module documentation). Returns the names applied.
pub fn apply<P: Into<Part> + Copy>(conn: &mut Connection, parts: &[P]) -> anyhow::Result<Vec<&'static str>> {
    conn.execute_batch(TRACKING)?;
    let parts = self::parts(parts);
    let mut applied = Vec::new();
    let mut rest = parts.as_slice();
    while !rest.is_empty() {
        let split = rest.iter().position(Part::is_standalone).unwrap_or(rest.len());
        let (shared, tail) = rest.split_at(split);
        if !shared.is_empty() {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for part in shared {
                if pending(&tx, part)? {
                    run_in(&tx, part)?;
                    applied.push(part.name);
                }
            }
            tx.commit()?;
        }
        let Some((alone, after)) = tail.split_first() else { break };
        if pending(conn, alone)? {
            let PartKind::Procedure(p) = alone.kind else { unreachable!("only procedures are standalone") };
            let generated =
                (p.run)(conn, p.args).map_err(|e| anyhow::anyhow!("schema part {}: {e:#}", alone.name))?;
            if !conn.is_autocommit() {
                anyhow::bail!("schema part {}: a standalone procedure left a transaction open", alone.name);
            }
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            record(&tx, alone, Some(&generated))?;
            tx.commit()?;
            applied.push(alone.name);
        }
        rest = after;
    }
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

    /// Creates `counted` and returns SQL that names how many rows `base`
    /// holds, so its output depends on the database it runs on.
    fn counting(conn: &Connection, _: &'static [&'static str]) -> anyhow::Result<String> {
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM base", [], |r| r.get(0))?;
        let sql = format!("CREATE TABLE counted (n INTEGER); INSERT INTO counted VALUES ({n});");
        conn.execute_batch(&sql)?;
        Ok(sql)
    }

    const BASE: SchemaPart = SchemaPart { name: "base.v1", sql: "CREATE TABLE base (id INTEGER);" };

    fn counting_part(version: u32) -> Part {
        Procedure { name: "counted.v1", version, standalone: false, run: counting, args: &[] }.into()
    }

    #[test]
    fn a_procedure_runs_once_and_records_its_version_and_sql() {
        let mut conn = Connection::open_in_memory().unwrap();
        let parts = [Part::from(BASE), counting_part(1)];
        assert_eq!(apply(&mut conn, &parts).unwrap(), ["base.v1", "counted.v1"]);
        let (version, sql): (i64, String) = conn
            .query_row(
                "SELECT version, generated_sql FROM schema_procedures WHERE name = 'counted.v1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(version, 1);
        assert!(sql.contains("VALUES (0)"), "{sql}");

        // The procedure would now generate different SQL; it is not re-run,
        // compared or refused, because it is checked by name and version.
        conn.execute_batch("INSERT INTO base VALUES (1), (2);").unwrap();
        assert!(apply(&mut conn, &parts).unwrap().is_empty());
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM counted", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "ran exactly once");
    }

    #[test]
    fn a_procedure_whose_version_changes_is_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, &[Part::from(BASE), counting_part(1)]).unwrap();
        let err = apply(&mut conn, &[Part::from(BASE), counting_part(2)]).unwrap_err().to_string();
        assert!(err.contains("counted.v1"), "{err}");
        assert!(err.contains("recorded procedure version 1") && err.contains("version 2"), "{err}");
        // Nothing ran: the table still has one row and the record is unchanged.
        let v: i64 = conn
            .query_row("SELECT version FROM schema_procedures WHERE name = 'counted.v1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn a_database_without_procedures_gets_no_audit_table() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn, &[BASE]).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 'schema_procedures'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 0);
    }

    /// A standalone body: proves no transaction is open and the part before
    /// it is already committed (a second connection sees it), then does its
    /// own transaction.
    fn alone(conn: &Connection, args: &'static [&'static str]) -> anyhow::Result<String> {
        anyhow::ensure!(conn.is_autocommit(), "a transaction is open");
        let path = conn.path().unwrap_or_default().to_string();
        let other = Connection::open(&path)?;
        let before: i64 =
            other
                .query_row("SELECT COUNT(*) FROM schema_parts WHERE name = 'before.v1'", [], |r| r.get(0))?;
        anyhow::ensure!(before == 1, "the part before was not committed");
        if args.first() == Some(&"fail") {
            anyhow::bail!("refused on purpose");
        }
        let sql = "PRAGMA foreign_keys = OFF; BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS alone (id INTEGER); COMMIT; \
                   PRAGMA foreign_keys = ON;";
        conn.execute_batch(sql)?;
        Ok(sql.to_string())
    }

    const BEFORE: SchemaPart = SchemaPart { name: "before.v1", sql: "CREATE TABLE before (id INTEGER);" };
    const AFTER: SchemaPart = SchemaPart { name: "after.v1", sql: "CREATE TABLE after (id INTEGER);" };

    fn alone_part(args: &'static [&'static str]) -> Part {
        Procedure { name: "alone.v1", version: 1, standalone: true, run: alone, args }.into()
    }

    fn file_db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(dir.path().join("t.db")).unwrap();
        conn.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
        (dir, conn)
    }

    #[test]
    fn a_standalone_part_runs_alone_between_committed_parts() {
        let (_dir, mut conn) = file_db();
        let applied = apply(&mut conn, &[Part::from(BEFORE), alone_part(&[]), Part::from(AFTER)]).unwrap();
        assert_eq!(applied, ["before.v1", "alone.v1", "after.v1"]);
        for t in ["before", "alone", "after"] {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [t],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "{t}");
        }
        assert!(
            apply(&mut conn, &[Part::from(BEFORE), alone_part(&[]), Part::from(AFTER)]).unwrap().is_empty()
        );
    }

    /// A crash after a standalone procedure committed its work but before the
    /// part was recorded: the next start runs it again, which a procedure
    /// honouring the re-run contract survives, and records it exactly once.
    #[test]
    fn a_standalone_part_rerun_after_a_crash_before_its_record_is_safe() {
        let (_dir, mut conn) = file_db();
        apply(&mut conn, &[BEFORE]).unwrap();
        // The simulated crash: the body ran and committed, the record did not.
        alone(&conn, &[]).unwrap();
        conn.execute_batch("INSERT INTO alone (id) VALUES (7);").unwrap();
        let count = |c: &Connection, sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM schema_parts WHERE name = 'alone.v1'"), 0);

        let applied = apply(&mut conn, &[Part::from(BEFORE), alone_part(&[]), Part::from(AFTER)]).unwrap();
        assert_eq!(applied, ["alone.v1", "after.v1"]);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM schema_parts WHERE name = 'alone.v1'"), 1);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM schema_procedures WHERE name = 'alone.v1'"), 1);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM alone WHERE id = 7"), 1, "the first run's data survives");
        assert_eq!(count(&conn, "PRAGMA foreign_keys"), 1, "the procedure restored foreign keys");
        let check: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
        assert_eq!(check, "ok");
        assert!(apply(&mut conn, &[Part::from(BEFORE), alone_part(&[]), Part::from(AFTER)]).unwrap().is_empty());
    }

    #[test]
    fn a_failed_standalone_part_keeps_the_parts_before_it_and_applies_none_after() {
        let (_dir, mut conn) = file_db();
        let err =
            apply(&mut conn, &[Part::from(BEFORE), alone_part(&["fail"]), Part::from(AFTER)]).unwrap_err();
        assert!(err.to_string().contains("alone.v1"), "{err}");
        let names: Vec<String> = conn
            .prepare("SELECT name FROM schema_parts ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(names, ["before.v1"]);
    }
}
