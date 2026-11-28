//! Online backup, verified restore, and read-only health checks for the
//! hub SQLite database.
//!
//! Backups use SQLite's `VACUUM INTO` inside a private `0700` sibling staging
//! directory so a consistent, compacted snapshot can be taken while `ua serve`
//! is running under WAL mode without exposing intermediate files or copying raw
//! WAL or SHM sidecars.
//!
//! Restores open `--from` once with `O_NOFOLLOW | O_NONBLOCK`, stream it into a
//! private `0700` sibling staging directory while hashing, run all SQLite
//! integrity, schema, trigger/index/table DDL, and `event_log` checks on that
//! staged copy via `immutable=1`, preserve a `.pre-restore-*.bak` safety copy
//! (including WAL/SHM/journal sidecars when falling back to raw copies),
//! hard-link the previous DB and sidecars into rollback staging, replace `ua.db`
//! via `fs::rename`, and restore cleanly on any post-install failure (preserving
//! rollback staging intact if rollback itself fails).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::ledger::{self, EventInput, VerifyReport};
use crate::schema;
use crate::schema::Part;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

const STREAM_BUF_BYTES: usize = 64 * 1024;
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const SUMMARY_TABLES: [&str; 8] =
    ["event_log", "tasks", "memory", "memory_notes", "approvals", "agent_tokens", "nodes", "skills"];

/// Read-only health snapshot of a database file and its ledger chain.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DbHealth {
    pub exists: bool,
    pub bytes: Option<u64>,
    pub wal_bytes: Option<u64>,
    pub journal_mode: Option<String>,
    pub foreign_keys: Option<bool>,
    pub quick_check: Option<String>,
    pub foreign_key_violations: Option<u64>,
    pub schema_parts: Option<u64>,
    pub ledger: Option<VerifyReport>,
}

/// Comparison of a database's `schema_parts` and `sqlite_master` objects
/// (tables, views, indexes, triggers) against the running build.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SchemaCompatibility {
    pub ok: bool,
    pub reference_error: Option<String>,
    pub missing: Vec<String>,
    pub drifted: Vec<String>,
    pub extra: Vec<String>,
    pub missing_objects: Vec<String>,
    pub modified_objects: Vec<String>,
    pub conflicting_objects: Vec<String>,
    pub unexpected_indexes: Vec<String>,
    pub unexpected_indexes_on_known_tables: Vec<String>,
    pub unexpected_triggers: Vec<String>,
    pub unexpected_triggers_on_known_tables: Vec<String>,
    pub unexpected_tables: Vec<String>,
    /// Objects using SQLite's reserved `sqlite_` name prefix other than the
    /// internal tables and automatic indexes SQLite creates itself. Only
    /// `PRAGMA writable_schema` can create these, so they always fail.
    pub reserved_name_objects: Vec<String>,
    /// Unexpected tables declaring a foreign key into a known table. The
    /// running build does not know about such a child table, so its writes to
    /// the known parent could fail or cascade unexpectedly.
    pub unexpected_foreign_keys_to_known_tables: Vec<String>,
}

impl SchemaCompatibility {
    /// Whether any unexpected table, view, index, or trigger is present.
    pub fn has_unexpected_objects(&self) -> bool {
        !self.unexpected_tables.is_empty()
            || !self.unexpected_indexes.is_empty()
            || !self.unexpected_triggers.is_empty()
    }

    /// Whether the schema shows tampering or unowned SQLite objects that cannot
    /// be attributed to `extra` (another build's `schema_parts`).
    pub fn has_tampering_or_unowned_objects(&self) -> bool {
        self.reference_error.is_some()
            || !self.drifted.is_empty()
            || !self.missing_objects.is_empty()
            || !self.modified_objects.is_empty()
            || !self.conflicting_objects.is_empty()
            || !self.unexpected_indexes_on_known_tables.is_empty()
            || !self.unexpected_triggers_on_known_tables.is_empty()
            || !self.reserved_name_objects.is_empty()
            || !self.unexpected_foreign_keys_to_known_tables.is_empty()
            || (self.extra.is_empty() && self.has_unexpected_objects())
    }
}

/// Summary produced after taking and verifying a backup snapshot.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BackupReport {
    pub source: String,
    pub destination: String,
    pub bytes: u64,
    pub sha256: String,
    pub quick_check: String,
    pub ledger: VerifyReport,
    pub ledger_head_seq: Option<i64>,
    pub ledger_head_hash: Option<String>,
    pub table_counts: BTreeMap<String, u64>,
    pub created_at: String,
}

/// Options controlling [`restore_database`].
#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
    pub dry_run: bool,
    pub force: bool,
    pub expected_sha256: Option<String>,
    /// Allow non-dry-run restore without `--expected-sha256`.
    pub allow_unpinned: bool,
    /// Allow restoring a backup that includes `schema_parts` from a newer build.
    pub allow_newer: bool,
    pub keep_safety_backup: bool,
    /// Invalidate active UI sessions, login links, OAuth grants/tokens/codes/requests,
    /// and node session credentials in the restore transaction.
    pub revoke_sessions: bool,
    /// Optional `(required, optional)` schema parts from the running build.
    pub expected_schema: Option<(Vec<Part>, Vec<Part>)>,
}

/// Result of verifying (with `dry_run`) or installing a backup over a hub database.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RestoreReport {
    pub source: String,
    pub destination: String,
    pub dry_run: bool,
    pub sha256: String,
    pub bytes: u64,
    pub quick_check: String,
    pub ledger: VerifyReport,
    pub schema: Option<SchemaCompatibility>,
    pub safety_backup: Option<String>,
    pub safety_backup_sidecars: Vec<String>,
    pub revoked_sessions: BTreeMap<String, u64>,
    pub restored_event_seq: Option<i64>,
    /// Non-fatal problems met while installing the backup.
    pub warnings: Vec<String>,
}

struct DirGuard {
    dir: PathBuf,
    keep: bool,
}

impl DirGuard {
    fn create_private_in_existing(parent: &Path, stem: &str, tag: &str) -> anyhow::Result<Self> {
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let id = ulid::Ulid::generate();
        let dir = parent.join(format!(".{stem}.{tag}.{pid}.{seq}.{id}.d"));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).with_context(|| format!("creating private staging dir {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("setting 0700 permissions on {}", dir.display()))?;
        }
        Ok(Self { dir, keep: false })
    }

    fn create_private_in(parent: &Path, stem: &str, tag: &str) -> anyhow::Result<Self> {
        fs::create_dir_all(parent).with_context(|| format!("creating directory {}", parent.display()))?;
        Self::create_private_in_existing(parent, stem, tag)
    }

    fn create_private_sibling(dest: &Path, tag: &str) -> anyhow::Result<Self> {
        let parent = ensure_parent_dir(dest)?;
        let stem = dest.file_name().and_then(|s| s.to_str()).filter(|s| !s.is_empty()).unwrap_or("ua.db");
        Self::create_private_in(parent, stem, tag)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn disarm(&mut self) {
        self.keep = true;
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

fn wal_sidecar_path(db_path: &Path) -> PathBuf {
    append_suffix(db_path, "-wal")
}

fn shm_sidecar_path(db_path: &Path) -> PathBuf {
    append_suffix(db_path, "-shm")
}

fn journal_sidecar_path(db_path: &Path) -> PathBuf {
    append_suffix(db_path, "-journal")
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}

/// Convert `path` to an absolute path so bundled SQLite never interprets a
/// relative filename (for example one starting with `file:`) as a URI.
pub fn absolutize(path: &Path) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir().context("reading current working directory")?.join(path))
    }
}

/// Encode an absolute path as a SQLite `file:///...?immutable=1` URI so the
/// connection never creates or reads WAL/journal sidecars.
fn sqlite_immutable_uri(abs_path: &Path) -> anyhow::Result<String> {
    let text =
        abs_path.to_str().ok_or_else(|| anyhow::anyhow!("path {} is not valid UTF-8", abs_path.display()))?;
    let mut uri = String::from("file://");
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            uri.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(uri, "%{b:02X}");
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}

/// Verify that `owner_uid` matches `effective_uid`.
pub fn check_uid_match(path: &Path, owner_uid: u32, effective_uid: u32) -> anyhow::Result<()> {
    if owner_uid != effective_uid {
        bail!(
            "{} is owned by uid {owner_uid}, but effective uid is {effective_uid}; \
             run ua as the hub OS user rather than under sudo",
            path.display()
        );
    }
    Ok(())
}

/// Verify that `path`, if it already exists, is owned by the current effective
/// UID on Unix (prevents mixed root/hub-user file ownership from `sudo`).
pub fn check_dir_owner(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                // SAFETY: `geteuid()` has no preconditions and always succeeds.
                let euid = unsafe { libc::geteuid() } as u32;
                check_uid_match(path, meta.uid(), euid)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("inspecting owner of {}", path.display())),
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn open_read_only(path: &Path) -> anyhow::Result<Connection> {
    let abs = absolutize(path)?;
    let conn =
        Connection::open_with_flags(&abs, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .with_context(|| format!("opening {} read-only", abs.display()))?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.execute_batch("PRAGMA query_only = ON;")?;
    Ok(conn)
}

fn open_read_only_immutable(abs_path: &Path) -> anyhow::Result<Connection> {
    let uri = sqlite_immutable_uri(abs_path)?;
    let conn = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI,
    )
    .with_context(|| format!("opening staged backup {} read-only", abs_path.display()))?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.execute_batch("PRAGMA query_only = ON;")?;
    Ok(conn)
}

fn table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |_| Ok(true))
        .optional()
        .map(|o| o.unwrap_or(false))
}

fn table_count(conn: &Connection, table: &str) -> anyhow::Result<Option<u64>> {
    if !table_exists(conn, table)? {
        return Ok(None);
    }
    let count: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |r| r.get(0))
        .with_context(|| format!("counting rows in {table}"))?;
    Ok(Some(u64::try_from(count).unwrap_or(0)))
}

fn run_integrity_pragma(conn: &Connection, pragma: &str) -> anyhow::Result<String> {
    let mut stmt = conn.prepare(pragma)?;
    let mut rows = stmt.query([])?;
    let mut messages = Vec::new();
    while let Some(r) = rows.next()? {
        messages.push(r.get::<_, String>(0)?);
    }
    if messages.len() == 1 && messages[0].eq_ignore_ascii_case("ok") {
        Ok("ok".to_string())
    } else if messages.is_empty() {
        Ok("unknown".to_string())
    } else {
        Ok(messages.join("; "))
    }
}

fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

type MasterObjectMap = BTreeMap<(String, String), (String, String, String)>;

/// Read every table, view, index, and trigger from `sqlite_master`.
///
/// Objects are NOT filtered by a `sqlite_` name prefix: SQLite skips its
/// reserved-name check when loading a schema written through
/// `PRAGMA writable_schema`, so a `sqlite_`-named trigger or view loads and
/// runs like any other. Only objects SQLite itself creates are exempt:
/// automatic indexes (`type = 'index'`, `sql IS NULL`, `sqlite_autoindex_`
/// name), which SQLite ties to the owning table's checked DDL, and the
/// internal tables `sqlite_sequence`, `sqlite_stat1`, and `sqlite_stat4`.
/// Any other `sqlite_`-named object stays in the map and is reported by
/// [`check_schema_compatibility`] as `reserved_name_objects`.
fn read_master_objects(conn: &Connection) -> anyhow::Result<MasterObjectMap> {
    let mut map = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master \
         WHERE type IN ('table', 'view', 'index', 'trigger') \
         AND NOT (type = 'index' AND sql IS NULL \
                  AND lower(substr(name, 1, 17)) = 'sqlite_autoindex_') \
         AND NOT (type = 'table' \
                  AND lower(name) IN ('sqlite_sequence', 'sqlite_stat1', 'sqlite_stat4'))",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let obj_type = r.get::<_, String>(0)?;
        let name = r.get::<_, String>(1)?;
        let tbl_name = r.get::<_, String>(2)?;
        let sql = normalize_sql(&r.get::<_, String>(3)?);
        let key = (obj_type, name.to_ascii_lowercase());
        map.insert(key, (name, tbl_name, sql));
    }
    Ok(map)
}

/// Verify `schema_parts` checksums and `sqlite_master` tables, views, indexes,
/// and triggers in `conn` against the schemas registered in the current build.
pub fn check_schema_compatibility<E: Into<Part> + Copy>(
    conn: &Connection,
    expected: &[E],
    optional: &[Part],
) -> anyhow::Result<SchemaCompatibility> {
    let expected = schema::parts(expected);
    if !table_exists(conn, "schema_parts")? {
        bail!("database is missing the schema_parts table");
    }

    let mut applied = BTreeMap::new();
    {
        let mut stmt = conn.prepare("SELECT name, checksum FROM schema_parts")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            applied.insert(r.get::<_, String>(0)?, r.get::<_, String>(1)?);
        }
    }

    let mut missing = Vec::new();
    let mut drifted = Vec::new();
    let mut known = BTreeSet::new();
    let mut applied_parts = Vec::new();
    let mut full_parts = Vec::with_capacity(expected.len() + optional.len());

    for part in &expected {
        known.insert(part.name);
        full_parts.push(*part);
        let sum = part.checksum();
        match applied.get(part.name) {
            None => missing.push(part.name.to_string()),
            Some(s) => {
                applied_parts.push(*part);
                if *s != sum {
                    drifted.push(part.name.to_string());
                }
            }
        }
    }
    for part in optional {
        known.insert(part.name);
        full_parts.push(*part);
        let sum = part.checksum();
        if let Some(s) = applied.get(part.name) {
            applied_parts.push(*part);
            if *s != sum {
                drifted.push(part.name.to_string());
            }
        }
    }

    let extra: Vec<String> = applied.keys().filter(|k| !known.contains(k.as_str())).cloned().collect();

    // Build in-memory reference databases so SQLite FTS5 shadow tables and
    // normalized DDL match the bundled SQLite engine identically.
    let mut full_ref = Connection::open_in_memory().context("opening reference in-memory DB")?;
    full_ref.execute_batch("PRAGMA foreign_keys = ON;")?;
    schema::apply(&mut full_ref, &full_parts)?;
    let full_objs = read_master_objects(&full_ref)?;
    let known_table_names: BTreeSet<String> = full_objs
        .keys()
        .filter(|(t, _)| t == "table" || t == "view")
        .map(|(_, name_lc)| name_lc.clone())
        .collect();
    let known_object_names: BTreeSet<String> = full_objs.keys().map(|(_, name_lc)| name_lc.clone()).collect();

    // If replaying `applied_parts` together fails (e.g., an altered table's base
    // part row was deleted), fail closed via `reference_error` AND apply each part
    // individually on a fresh DB so independent parts still check `missing_objects`.
    let (reference_error, applied_objs) = {
        let mut applied_ref = Connection::open_in_memory().context("opening applied reference DB")?;
        applied_ref.execute_batch("PRAGMA foreign_keys = ON;")?;
        match schema::apply(&mut applied_ref, &applied_parts) {
            Ok(_) => (None, read_master_objects(&applied_ref)?),
            Err(e) => {
                let mut best_ref = Connection::open_in_memory().context("opening fallback reference DB")?;
                best_ref.execute_batch("PRAGMA foreign_keys = ON;")?;
                for part in &applied_parts {
                    let _ = schema::apply(&mut best_ref, &[*part]);
                }
                (
                    Some(format!("applied schema_parts could not be replayed cleanly: {e}")),
                    read_master_objects(&best_ref)?,
                )
            }
        }
    };

    let actual_objs = read_master_objects(conn)?;

    let mut missing_objects = Vec::new();
    for ((obj_type, name_lc), (orig_name, _, _)) in &applied_objs {
        if !actual_objs.contains_key(&(obj_type.clone(), name_lc.clone())) {
            missing_objects.push(format!("{obj_type}:{orig_name}"));
        }
    }

    let mut modified_objects = Vec::new();
    let mut conflicting_objects = Vec::new();
    let mut unexpected_indexes = Vec::new();
    let mut unexpected_indexes_on_known_tables = Vec::new();
    let mut unexpected_triggers = Vec::new();
    let mut unexpected_triggers_on_known_tables = Vec::new();
    let mut unexpected_tables = Vec::new();
    let mut reserved_name_objects = Vec::new();
    let mut unexpected_foreign_keys_to_known_tables = Vec::new();

    for ((obj_type, name_lc), (orig_name, tbl_name, sql)) in &actual_objs {
        // `read_master_objects` already dropped the internal tables and
        // automatic indexes SQLite creates, so any remaining `sqlite_` name was
        // planted through `writable_schema`.
        if name_lc.starts_with("sqlite_") {
            reserved_name_objects.push(format!("{obj_type}:{orig_name}"));
        }
        if let Some((_, exp_tbl, exp_sql)) = applied_objs.get(&(obj_type.clone(), name_lc.clone())) {
            if !exp_tbl.eq_ignore_ascii_case(tbl_name) || exp_sql != sql {
                modified_objects.push(format!("{obj_type}:{orig_name}"));
            }
        } else {
            let name_collides = known_object_names.contains(name_lc);
            let tbl_is_known = known_table_names.contains(&tbl_name.to_ascii_lowercase());
            match obj_type.as_str() {
                "table" | "view" => {
                    let label = format!("{obj_type}:{orig_name}");
                    if name_collides {
                        conflicting_objects.push(label.clone());
                    }
                    if obj_type == "table" {
                        let mut stmt = conn.prepare("SELECT \"table\" FROM pragma_foreign_key_list(?1)")?;
                        let parents = stmt
                            .query_map([orig_name], |r| r.get::<_, String>(0))?
                            .collect::<rusqlite::Result<BTreeSet<String>>>()?;
                        for parent in parents {
                            if known_table_names.contains(&parent.to_ascii_lowercase()) {
                                unexpected_foreign_keys_to_known_tables
                                    .push(format!("{orig_name} references {parent}"));
                            }
                        }
                    }
                    unexpected_tables.push(label);
                }
                "index" => {
                    let label = format!("{orig_name} on {tbl_name}");
                    if tbl_is_known {
                        unexpected_indexes_on_known_tables.push(label.clone());
                    }
                    if name_collides {
                        conflicting_objects.push(format!("index:{orig_name}"));
                    }
                    unexpected_indexes.push(label);
                }
                "trigger" => {
                    let label = format!("{orig_name} on {tbl_name}");
                    if tbl_is_known {
                        unexpected_triggers_on_known_tables.push(label.clone());
                    }
                    if name_collides {
                        conflicting_objects.push(format!("trigger:{orig_name}"));
                    }
                    unexpected_triggers.push(label);
                }
                _ => {}
            }
        }
    }

    let ok = reference_error.is_none()
        && drifted.is_empty()
        && extra.is_empty()
        && missing_objects.is_empty()
        && modified_objects.is_empty()
        && conflicting_objects.is_empty()
        && unexpected_indexes.is_empty()
        && unexpected_triggers.is_empty()
        && unexpected_tables.is_empty()
        && reserved_name_objects.is_empty()
        && unexpected_foreign_keys_to_known_tables.is_empty();
    Ok(SchemaCompatibility {
        ok,
        reference_error,
        missing,
        drifted,
        extra,
        missing_objects,
        modified_objects,
        conflicting_objects,
        unexpected_indexes,
        unexpected_indexes_on_known_tables,
        unexpected_triggers,
        unexpected_triggers_on_known_tables,
        unexpected_tables,
        reserved_name_objects,
        unexpected_foreign_keys_to_known_tables,
    })
}

/// Largest id accepted in an AUTOINCREMENT table, and the largest counter
/// accepted in `sqlite_sequence`: 2^52.
///
/// Ids are exposed through JSON, and 2^53 - 1 is the largest integer JSON
/// clients (JavaScript numbers, many JSON parsers) represent exactly. Capping
/// at 2^52 leaves 2^52 further ids of headroom below that limit, so a restored
/// hub can keep inserting for longer than it will exist (at a million inserts
/// a second, about 142 years) without leaving exact-JSON range, while no honest
/// hub comes near 2^52. A tampered id or counter near 2^63 would otherwise make
/// every later insert fail with "database or disk is full".
const MAX_AUTOINCREMENT_ID: i64 = 1_i64 << 52;

/// Check the AUTOINCREMENT state of every table that uses it. Table data and
/// `seq` values are not covered by the ledger hash chain, so a backup could
/// carry a tampered id or counter that bricks inserts or makes deleted ids
/// reusable.
///
/// Rules (returns one message per violation, empty when consistent):
/// - every AUTOINCREMENT table, found from its DDL in `sqlite_master` (not from
///   `sqlite_sequence`, whose rows can be deleted), plus `event_log` itself,
///   must have `MAX(rowid) <= MAX_AUTOINCREMENT_ID`, whether or not it has a
///   counter row. SQLite takes the next id from the larger of the counter and
///   `MAX(rowid)`, so bounding only the counter is not enough;
/// - every `sqlite_sequence` row names an existing, non-internal table exactly
///   once, with an integer `seq` (SQLite drops a table's row when the table is
///   dropped, and never writes duplicates or non-integers);
/// - `event_log` is append-only (UPDATE/DELETE triggers) and nothing inserts
///   into it with `OR IGNORE`, so its counter must equal `MAX(seq)`, or `0`
///   for an empty ledger. A missing `event_log` row is accepted: SQLite then
///   continues from `MAX(seq)`, which is the same result;
/// - any other counter may exceed `MAX(rowid)` (rows may have been deleted),
///   but must not be below it (ids of deleted rows would be handed out again)
///   nor above `MAX_AUTOINCREMENT_ID`.
///
/// `event_log` is deliberately not required to be contiguous (`MAX(seq) =
/// COUNT(*)`): `ua import` copies `seq` verbatim from the source hub without
/// requiring it to be gap-free, so honest imported ledgers can have gaps.
pub fn check_autoincrement_sequences(conn: &Connection) -> anyhow::Result<Vec<String>> {
    let mut problems = Vec::new();
    let max_rowid = |name: &str| -> rusqlite::Result<Option<i64>> {
        conn.query_row(&format!("SELECT MAX(rowid) FROM \"{}\"", name.replace('"', "\"\"")), [], |r| r.get(0))
    };

    let mut tables = BTreeSet::new();
    let mut autoinc_tables = BTreeSet::new();
    {
        let mut stmt =
            conn.prepare("SELECT name, upper(COALESCE(sql, '')) FROM sqlite_master WHERE type = 'table'")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let name: String = r.get(0)?;
            let sql: String = r.get(1)?;
            // A WITHOUT ROWID table cannot use AUTOINCREMENT, so the word can
            // only appear there inside a comment or string.
            if (name == "event_log" || sql.contains("AUTOINCREMENT")) && !sql.contains("WITHOUT ROWID") {
                autoinc_tables.insert(name.clone());
            }
            tables.insert(name);
        }
    }
    for name in &autoinc_tables {
        match max_rowid(name) {
            Ok(Some(max)) if max > MAX_AUTOINCREMENT_ID => problems.push(format!(
                "{name} holds id {max}, above the limit {MAX_AUTOINCREMENT_ID}; the next insert would leave exact-JSON range or fail"
            )),
            Ok(_) => {}
            Err(e) => problems.push(format!("cannot read MAX(rowid) of {name}: {e}")),
        }
    }

    if !tables.contains("sqlite_sequence") {
        return Ok(problems);
    }
    let mut seen = BTreeSet::new();
    let mut stmt =
        conn.prepare("SELECT CAST(name AS TEXT), typeof(name), seq, typeof(seq) FROM sqlite_sequence")?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let name: Option<String> = r.get(0)?;
        let name_type: String = r.get(1)?;
        let seq_type: String = r.get(3)?;
        let Some(name) = name.filter(|_| name_type == "text") else {
            problems.push(format!("sqlite_sequence row with a non-text name ({name_type})"));
            continue;
        };
        if !seen.insert(name.clone()) {
            problems.push(format!("sqlite_sequence has more than one row for {name}"));
            continue;
        }
        if !tables.contains(&name) || name.to_ascii_lowercase().starts_with("sqlite_") {
            problems.push(format!("sqlite_sequence row for {name}, which is not an application table"));
            continue;
        }
        if seq_type != "integer" {
            problems.push(format!("sqlite_sequence value for {name} is not an integer ({seq_type})"));
            continue;
        }
        let seq: i64 = r.get(2)?;
        let floor = match max_rowid(&name) {
            Ok(v) => v.unwrap_or(0),
            Err(e) => {
                problems.push(format!("cannot read MAX(rowid) of {name} for its sqlite_sequence row: {e}"));
                continue;
            }
        };
        if name == "event_log" {
            if seq != floor {
                problems.push(format!(
                    "sqlite_sequence for event_log is {seq} but MAX(seq) is {floor}; the ledger is append-only, so they must match"
                ));
            }
        } else if seq < floor {
            problems.push(format!(
                "sqlite_sequence for {name} is {seq}, below MAX(rowid) {floor}; ids of deleted rows could be reused"
            ));
        } else if seq > MAX_AUTOINCREMENT_ID {
            problems
                .push(format!("sqlite_sequence for {name} is {seq}, above the limit {MAX_AUTOINCREMENT_ID}"));
        }
    }
    Ok(problems)
}

fn stream_sha256_and_size(path: &Path) -> anyhow::Result<(String, u64)> {
    let mut file = File::open(path).with_context(|| format!("opening {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; STREAM_BUF_BYTES];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

fn open_file_no_follow_ro(abs_path: &Path, role: &str) -> anyhow::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts.open(abs_path).with_context(|| match fs::symlink_metadata(abs_path) {
        Ok(m) if m.file_type().is_symlink() => {
            format!("{role} path {} is a symbolic link; refusing to follow it", abs_path.display())
        }
        _ => format!("opening {role} {}", abs_path.display()),
    })?;
    let meta = file.metadata().with_context(|| format!("inspecting {role} {}", abs_path.display()))?;
    if !meta.is_file() {
        bail!("{role} path {} must be a regular file", abs_path.display());
    }
    Ok(file)
}

fn stream_fd_to_new_file_hashed(reader: &mut File, staged_dest: &Path) -> anyhow::Result<(String, u64)> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut writer =
        opts.open(staged_dest).with_context(|| format!("creating staged file {}", staged_dest.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; STREAM_BUF_BYTES];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        writer.write_all(&buf[..n])?;
        total += n as u64;
    }
    writer.sync_all()?;
    set_owner_only_file(staged_dest)?;
    Ok((hex::encode(hasher.finalize()), total))
}

fn set_owner_only_file(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting 0600 permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> anyhow::Result<&Path> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("destination {} must have a parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating directory {}", parent.display()))?;
    Ok(parent)
}

fn reject_if_symlink(path: &Path, role: &str) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("{role} path {} is a symbolic link; refusing to follow it", path.display());
        }
        Ok(meta) if meta.is_dir() => {
            bail!("{role} path {} is a directory, expected a file", path.display());
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("inspecting {role} path {}", path.display())),
    }
}

fn same_target_file(a: &Path, b: &Path) -> anyhow::Result<bool> {
    if a == b {
        return Ok(true);
    }
    let Ok(ca) = fs::canonicalize(a) else {
        return Ok(false);
    };
    if let Ok(cb) = fs::canonicalize(b) {
        return Ok(ca == cb);
    }
    if let (Some(parent), Some(name)) = (b.parent(), b.file_name()) {
        let resolved_parent = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
        if let Ok(cb_parent) = fs::canonicalize(resolved_parent) {
            return Ok(ca == cb_parent.join(name));
        }
    }
    Ok(false)
}

fn sync_dir(dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Atomically create `destination` with `O_CREAT | O_EXCL | O_NOFOLLOW` when
/// `hard_link` is unsupported or blocked (`EPERM` on vfat/SMB/FUSE), never
/// falling back to a racy check-then-rename.
fn exclusive_copy_new(staged: &Path, destination: &Path) -> anyhow::Result<()> {
    let mut reader = File::open(staged).with_context(|| format!("opening staged {}", staged.display()))?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut writer = match opts.open(destination) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("destination {} already exists (pass --force to overwrite)", destination.display());
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("installing {} at {}", staged.display(), destination.display()));
        }
    };
    let res = (|| -> anyhow::Result<()> {
        let mut buf = vec![0u8; STREAM_BUF_BYTES];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
        }
        writer.sync_all()?;
        set_owner_only_file(destination)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(destination);
    }
    res
}

/// Install `temp_path` at `destination`, refusing to overwrite an existing
/// destination unless `force` is true (using atomic hard link or `O_EXCL` create).
fn install_file(temp_path: &Path, destination: &Path, force: bool) -> anyhow::Result<()> {
    if force {
        fs::rename(temp_path, destination)
            .with_context(|| format!("installing {} at {}", temp_path.display(), destination.display()))?;
    } else {
        #[cfg(unix)]
        {
            match fs::hard_link(temp_path, destination) {
                Ok(()) => {
                    let _ = fs::remove_file(temp_path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    bail!("destination {} already exists (pass --force to overwrite)", destination.display());
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    exclusive_copy_new(temp_path, destination)?;
                    let _ = fs::remove_file(temp_path);
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("installing {} at {}", temp_path.display(), destination.display())
                    });
                }
            }
        }
        #[cfg(not(unix))]
        {
            exclusive_copy_new(temp_path, destination)?;
            let _ = fs::remove_file(temp_path);
        }
    }
    if let Some(parent) = destination.parent().filter(|p| !p.as_os_str().is_empty()) {
        sync_dir(parent)?;
    }
    Ok(())
}

/// Run a strictly read-only integrity, WAL, foreign-key, schema, and ledger check
/// on `path`. Never creates a missing database file or runs migrations.
pub fn check_database(path: &Path) -> anyhow::Result<DbHealth> {
    let abs = absolutize(path)?;
    let meta = match fs::symlink_metadata(&abs) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DbHealth {
                exists: false,
                bytes: None,
                wal_bytes: None,
                journal_mode: None,
                foreign_keys: None,
                quick_check: None,
                foreign_key_violations: None,
                schema_parts: None,
                ledger: None,
            });
        }
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", abs.display())),
    };
    if !meta.is_file() {
        bail!("database path {} is not a regular file", abs.display());
    }
    let bytes = Some(meta.len());
    let wal_bytes = fs::metadata(wal_sidecar_path(&abs)).ok().map(|m| m.len());

    let conn = open_read_only(&abs)?;
    let journal_mode: Option<String> = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)).optional()?;
    let fk: Option<i64> = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).optional()?;
    let quick_check = Some(run_integrity_pragma(&conn, "PRAGMA quick_check")?);

    let mut fk_stmt = conn.prepare("PRAGMA foreign_key_check")?;
    let mut fk_rows = fk_stmt.query([])?;
    let mut violations: u64 = 0;
    while fk_rows.next()?.is_some() {
        violations += 1;
    }

    let schema_parts = table_count(&conn, "schema_parts")?;
    let ledger = if table_exists(&conn, "event_log")? { Some(ledger::verify(&conn)?) } else { None };

    Ok(DbHealth {
        exists: true,
        bytes,
        wal_bytes,
        journal_mode,
        foreign_keys: fk.map(|v| v != 0),
        quick_check,
        foreign_key_violations: Some(violations),
        schema_parts,
        ledger,
    })
}

fn vacuum_into_temp(source: &Path, temp_dest: &Path) -> anyhow::Result<()> {
    let dest_str = temp_dest
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("destination path {} is not valid UTF-8", temp_dest.display()))?;
    if let Ok(conn) = Connection::open_with_flags(
        source,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        if conn.execute("VACUUM INTO ?1", params![dest_str]).is_ok() {
            return Ok(());
        }
        let _ = fs::remove_file(temp_dest);
    }

    let conn = Connection::open_with_flags(
        source,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening {} for online snapshot", source.display()))?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.execute("VACUUM INTO ?1", params![dest_str])
        .with_context(|| format!("running VACUUM INTO {}", temp_dest.display()))?;
    Ok(())
}

/// Take a consistent, standalone SQLite snapshot (`VACUUM INTO`) of `source`,
/// verify SQLite integrity and the `event_log` hash chain on the snapshot, and
/// install it atomically at `destination` (`0600` on Unix).
pub fn backup_database(source: &Path, destination: &Path, force: bool) -> anyhow::Result<BackupReport> {
    let abs_src = absolutize(source)?;
    let abs_dst = absolutize(destination)?;
    let src_meta = fs::symlink_metadata(&abs_src)
        .with_context(|| format!("source database {} does not exist", abs_src.display()))?;
    if !src_meta.is_file() {
        bail!("source database {} is not a regular file", abs_src.display());
    }
    reject_if_symlink(&abs_dst, "destination")?;
    if !force && fs::symlink_metadata(&abs_dst).is_ok() {
        bail!("destination {} already exists (pass --force to overwrite)", abs_dst.display());
    }
    if same_target_file(&abs_src, &abs_dst)? {
        bail!("backup destination {} must be distinct from source {}", abs_dst.display(), abs_src.display());
    }

    let stage_dir = DirGuard::create_private_sibling(&abs_dst, "backup")?;
    let stage_file = stage_dir.file("snapshot.db");
    vacuum_into_temp(&abs_src, &stage_file)?;
    set_owner_only_file(&stage_file)?;

    let (quick_check, ledger_report, ledger_head_seq, ledger_head_hash, table_counts) = {
        let snap = open_read_only_immutable(&stage_file)?;
        let qc = run_integrity_pragma(&snap, "PRAGMA quick_check")?;
        if qc != "ok" {
            bail!("backup snapshot failed quick_check: {qc}");
        }
        if !table_exists(&snap, "schema_parts")? || !table_exists(&snap, "event_log")? {
            bail!(
                "source database {} is not a ua-rust hub database (missing schema_parts or event_log)",
                abs_src.display()
            );
        }
        let report = ledger::verify(&snap)?;
        if !report.ok {
            bail!(
                "refusing backup: event_log verification failed at seq {:?}: {}",
                report.first_bad_seq,
                report.reason.as_deref().unwrap_or("unknown error")
            );
        }
        let head: Option<(i64, Option<String>)> = snap
            .query_row(
                "SELECT seq, entry_hash FROM event_log WHERE entry_hash IS NOT NULL ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let mut counts = BTreeMap::new();
        for table in SUMMARY_TABLES {
            if let Some(n) = table_count(&snap, table)? {
                counts.insert(table.to_string(), n);
            }
        }
        (qc, report, head.as_ref().map(|h| h.0), head.and_then(|h| h.1), counts)
    };

    let (sha256, bytes) = stream_sha256_and_size(&stage_file)?;
    {
        let f = File::open(&stage_file)?;
        f.sync_all()?;
    }
    install_file(&stage_file, &abs_dst, force)?;
    drop(stage_dir);

    Ok(BackupReport {
        source: abs_src.display().to_string(),
        destination: abs_dst.display().to_string(),
        bytes,
        sha256,
        quick_check,
        ledger: ledger_report,
        ledger_head_seq,
        ledger_head_hash,
        table_counts,
        created_at: ua_core::time::now(),
    })
}

fn normalize_sha256(s: &str) -> anyhow::Result<String> {
    let trimmed = s.trim().to_ascii_lowercase();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("expected_sha256 must be a 64-character hex SHA-256 digest");
    }
    Ok(trimmed)
}

fn compact_timestamp_for_filename() -> String {
    let ts = ua_core::time::now();
    let base = ts.split('+').next().unwrap_or(&ts);
    let mut clean: String = base.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    clean.push('Z');
    clean
}

/// Compute SQLite's cumulative WAL frame checksum over 8-byte chunks.
fn wal_checksum(data: &[u8], mut s0: u32, mut s1: u32, big_endian: bool) -> (u32, u32) {
    let word = |chunk: &[u8]| -> u32 {
        let arr: [u8; 4] = chunk.try_into().expect("4-byte chunk");
        if big_endian { u32::from_be_bytes(arr) } else { u32::from_le_bytes(arr) }
    };
    for pair in data.as_chunks::<8>().0 {
        s0 = s0.wrapping_add(word(&pair[0..4])).wrapping_add(s1);
        s1 = s1.wrapping_add(word(&pair[4..8])).wrapping_add(s0);
    }
    (s0, s1)
}

fn read_up_to(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut pos = 0;
    while pos < buf.len() {
        match reader.read(&mut buf[pos..]) {
            Ok(0) => break,
            Ok(n) => pos += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(pos)
}

/// Inspect a staged raw `-wal` copy strictly from disk without opening SQLite.
/// Returns `Ok(true)` if the WAL is empty or its active checksum chain is valid
/// through the last frame of the current salt generation, or `Ok(false)` if any
/// active header/frame is truncated or corrupt.
fn wal_file_is_clean(path: &Path) -> anyhow::Result<bool> {
    let file = File::open(path).with_context(|| format!("opening staged WAL {}", path.display()))?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(true);
    }
    if len < 32 {
        return Ok(false);
    }

    let mut reader = BufReader::with_capacity(STREAM_BUF_BYTES, file);
    let mut hdr = [0u8; 32];
    if read_up_to(&mut reader, &mut hdr)? != 32 {
        return Ok(false);
    }
    let magic = u32::from_be_bytes(hdr[0..4].try_into().expect("4 bytes"));
    let big_endian = match magic {
        0x377f_0682 => false,
        0x377f_0683 => true,
        _ => return Ok(false),
    };
    let format = u32::from_be_bytes(hdr[4..8].try_into().expect("4 bytes"));
    let page_size = u32::from_be_bytes(hdr[8..12].try_into().expect("4 bytes")) as usize;
    if format != 3_007_000 || !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Ok(false);
    }

    let hdr_cksum1 = u32::from_be_bytes(hdr[24..28].try_into().expect("4 bytes"));
    let hdr_cksum2 = u32::from_be_bytes(hdr[28..32].try_into().expect("4 bytes"));
    let (mut s0, mut s1) = wal_checksum(&hdr[0..24], 0, 0, big_endian);
    if (s0, s1) != (hdr_cksum1, hdr_cksum2) {
        return Ok(false);
    }

    let hdr_salt = &hdr[16..24];
    let mut frame = vec![0u8; 24 + page_size];
    loop {
        let n = read_up_to(&mut reader, &mut frame)?;
        if n == 0 {
            return Ok(true);
        }
        if n < frame.len() {
            return Ok(false);
        }
        if &frame[8..16] != hdr_salt {
            // Prior-generation tail frame; SQLite stops replaying here cleanly.
            return Ok(true);
        }
        (s0, s1) = wal_checksum(&frame[0..8], s0, s1, big_endian);
        (s0, s1) = wal_checksum(&frame[24..], s0, s1, big_endian);
        let frame_cksum1 = u32::from_be_bytes(frame[16..20].try_into().expect("4 bytes"));
        let frame_cksum2 = u32::from_be_bytes(frame[20..24].try_into().expect("4 bytes"));
        if (s0, s1) != (frame_cksum1, frame_cksum2) {
            return Ok(false);
        }
    }
}

/// Inspect a staged raw `-journal` copy strictly from disk without opening SQLite.
fn journal_file_is_clean(path: &Path) -> anyhow::Result<bool> {
    const JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
    let mut file = File::open(path).with_context(|| format!("opening staged journal {}", path.display()))?;
    let mut magic = [0u8; 8];
    let n = read_up_to(&mut file, &mut magic)?;
    Ok(n == 0 || (n == 8 && magic == JOURNAL_MAGIC))
}

fn create_safety_backup(existing_dest: &Path) -> anyhow::Result<(PathBuf, Vec<String>)> {
    let stamp = compact_timestamp_for_filename();
    let candidate_base = append_suffix(existing_dest, &format!(".pre-restore-{stamp}.bak"));
    let mut safety_path = candidate_base.clone();
    let mut idx = 1usize;
    while fs::symlink_metadata(&safety_path).is_ok() {
        safety_path = append_suffix(&candidate_base, &format!(".{idx}"));
        idx += 1;
    }

    // Capture raw main and sidecar bytes FIRST so existing_dest is never opened by
    // SQLite before preservation. Every SQLite open (read-only included) runs ONLY
    // on the isolated `probe/` copy, never on `existing_dest` or `raw/`.
    let stage_dir = DirGuard::create_private_sibling(&safety_path, "safety")?;
    let raw_dir = stage_dir.file("raw");
    fs::create_dir(&raw_dir).with_context(|| format!("creating raw safety dir {}", raw_dir.display()))?;

    let mut main_ro = open_file_no_follow_ro(existing_dest, "pre-restore database")?;
    let raw_main = raw_dir.join("main");
    stream_fd_to_new_file_hashed(&mut main_ro, &raw_main)?;
    drop(main_ro);

    let mut captured_sidecars: Vec<(&'static str, PathBuf)> = Vec::new();
    for suffix in ["-wal", "-shm", "-journal"] {
        let side_src = append_suffix(existing_dest, suffix);
        if let Ok(meta) = fs::symlink_metadata(&side_src)
            && !meta.file_type().is_symlink()
            && meta.is_file()
        {
            let mut side_ro = open_file_no_follow_ro(&side_src, "pre-restore sidecar")?;
            let raw_side = raw_dir.join(format!("main{suffix}"));
            stream_fd_to_new_file_hashed(&mut side_ro, &raw_side)?;
            captured_sidecars.push((suffix, raw_side));
        }
    }

    let sidecars_clean = captured_sidecars.iter().all(|(suffix, raw_side)| match *suffix {
        "-wal" => wal_file_is_clean(raw_side).unwrap_or(false),
        "-journal" => journal_file_is_clean(raw_side).unwrap_or(false),
        _ => true,
    });

    if sidecars_clean {
        let probe_dir = stage_dir.file("probe");
        fs::create_dir(&probe_dir)
            .with_context(|| format!("creating probe safety dir {}", probe_dir.display()))?;
        let probe_main = probe_dir.join("main");
        let mut raw_main_ro = open_file_no_follow_ro(&raw_main, "staged pre-restore database")?;
        stream_fd_to_new_file_hashed(&mut raw_main_ro, &probe_main)?;
        for (suffix, raw_side) in &captured_sidecars {
            // Never probe with a copied `-shm`: a wal-index whose valid header lags
            // the WAL would make SQLite trust a stale mxFrame and silently miss
            // committed frames. Without it SQLite rebuilds the index from the WAL.
            if *suffix == "-shm" {
                continue;
            }
            let mut raw_side_ro = open_file_no_follow_ro(raw_side, "staged pre-restore sidecar")?;
            let probe_side = probe_dir.join(format!("main{suffix}"));
            stream_fd_to_new_file_hashed(&mut raw_side_ro, &probe_side)?;
        }
        if backup_database(&probe_main, &safety_path, false).is_ok() {
            return Ok((safety_path, Vec::new()));
        }
    }

    File::open(&raw_main)?.sync_all()?;
    install_file(&raw_main, &safety_path, false)?;

    let mut sidecars = Vec::new();
    for (suffix, raw_side) in &captured_sidecars {
        let side_dst = append_suffix(&safety_path, suffix);
        File::open(raw_side)?.sync_all()?;
        install_file(raw_side, &side_dst, false)?;
        sidecars.push(side_dst.display().to_string());
    }

    Ok((safety_path, sidecars))
}

fn revoke_active_sessions(
    tx: &mut crate::db::WriteTx<'_>,
    now: &str,
) -> anyhow::Result<BTreeMap<String, u64>> {
    let mut revoked = BTreeMap::new();
    let updates: [(&str, &str, bool); 7] = [
        ("ui_sessions", "UPDATE ui_sessions SET revoked_at = ?1 WHERE revoked_at IS NULL", true),
        ("login_links", "UPDATE login_links SET used_at = ?1 WHERE used_at IS NULL", true),
        (
            "oauth_grants",
            "UPDATE oauth_grants SET revoked_at = ?1, revoked_reason = 'restore' WHERE revoked_at IS NULL",
            true,
        ),
        (
            "oauth_tokens",
            "UPDATE oauth_tokens SET status = 'revoked', revoked_at = ?1 WHERE status != 'revoked'",
            true,
        ),
        ("oauth_codes", "UPDATE oauth_codes SET used_at = ?1 WHERE used_at IS NULL", true),
        ("oauth_requests", "DELETE FROM oauth_requests", false),
        (
            "session_credentials",
            "UPDATE session_credentials SET revoked_at = ?1, revoke_reason = 'restore' WHERE revoked_at IS NULL",
            true,
        ),
    ];
    for (table, sql, with_ts) in updates {
        if table_exists(tx, table)? {
            let n = if with_ts { tx.execute(sql, params![now])? } else { tx.execute(sql, [])? };
            if n > 0 {
                revoked.insert(table.to_string(), n as u64);
            }
        }
    }
    Ok(revoked)
}

fn safety_note(safety_backup: &Option<String>) -> String {
    safety_backup.as_deref().map(|p| format!(" (safety backup at {p})")).unwrap_or_default()
}

type PostCommitHook<'a> = &'a dyn Fn(&Path) -> anyhow::Result<()>;

fn post_install_finalize(
    destination: &Path,
    sha256: &str,
    restored_head_seq: Option<i64>,
    restored_head_hash: Option<&str>,
    revoke_sessions: bool,
    post_commit_hook: Option<PostCommitHook<'_>>,
) -> anyhow::Result<(String, BTreeMap<String, u64>, i64)> {
    let mut rw = Connection::open_with_flags(
        destination,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("enabling WAL mode on restored {}", destination.display()))?;
    rw.busy_timeout(BUSY_TIMEOUT)?;
    rw.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;

    let now = ua_core::time::now();
    let (revoked_map, event_seq) = crate::db::write_on_connection(&mut rw, |tx| {
        let revoked_map = if revoke_sessions {
            revoke_active_sessions(tx, &now).map_err(|e| ua_core::UaError::internal(e.to_string()))?
        } else {
            BTreeMap::new()
        };
        let ev = ledger::append(
            tx,
            EventInput::new(
                ua_core::DEFAULT_ORG,
                "ops.restored",
                json!({
                    "source_sha256": sha256,
                    "restored_ledger_head_seq": restored_head_seq,
                    "restored_ledger_head_hash": restored_head_hash,
                    "revoked_sessions": revoked_map,
                }),
            )
            .by("cli"),
        )?;
        let seq = ev.map(|e| e.seq).unwrap_or(0);
        Ok((revoked_map, seq))
    })?;

    rw.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(rw);
    set_owner_only_file(destination)?;

    if let Some(hook) = post_commit_hook {
        hook(destination)?;
    }

    let dst = open_read_only(destination)?;
    let qc = run_integrity_pragma(&dst, "PRAGMA quick_check")?;
    if qc != "ok" {
        bail!("restored database failed post-install quick_check: {qc}");
    }
    let verify_after = ledger::verify(&dst)?;
    if !verify_after.ok {
        bail!(
            "restored database failed post-install ledger verification at seq {:?}: {}",
            verify_after.first_bad_seq,
            verify_after.reason.as_deref().unwrap_or("unknown error")
        );
    }

    Ok((qc, revoked_map, event_seq))
}

fn rollback_swap(destination: &Path, saved: &[(String, PathBuf, PathBuf)]) -> anyhow::Result<()> {
    for sidecar in
        [wal_sidecar_path(destination), shm_sidecar_path(destination), journal_sidecar_path(destination)]
    {
        match fs::remove_file(&sidecar) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("clearing sidecar {}", sidecar.display())),
        }
    }

    let mut had_main = false;
    for (tag, rb_path, orig_path) in saved {
        if tag == "main" {
            had_main = true;
            // Rename directly over `destination` so `ua.db` never disappears mid-rollback.
            fs::rename(rb_path, orig_path)
                .with_context(|| format!("restoring {} -> {}", rb_path.display(), orig_path.display()))?;
        }
    }
    if !had_main {
        match fs::remove_file(destination) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("removing new database {}", destination.display()));
            }
        }
    }
    for (tag, rb_path, orig_path) in saved {
        if tag != "main" {
            fs::rename(rb_path, orig_path).with_context(|| {
                format!("restoring sidecar {} -> {}", rb_path.display(), orig_path.display())
            })?;
        }
    }
    if let Some(parent) = destination.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = sync_dir(parent);
    }
    Ok(())
}

/// Verify a backup database (`O_NOFOLLOW | O_NONBLOCK` single-open copy into private
/// staging, `immutable=1` checks: SHA-256, `PRAGMA integrity_check`, required hub
/// tables, schema/trigger/index/view compatibility, `event_log` hash chain) and,
/// unless `opts.dry_run`, replace `destination` via hard-linked rollback staging +
/// `fs::rename`, rolling back cleanly on post-install failure.
///
/// Callers must hold an exclusive hub lock before invoking non-dry-run restore
/// so no hub process writes to `destination` or its WAL during replacement.
pub fn restore_database(
    source: &Path,
    destination: &Path,
    opts: RestoreOptions,
) -> anyhow::Result<RestoreReport> {
    restore_database_inner(source, destination, opts, None)
}

fn stage_rollback_copy(orig: &Path, rb: &Path) -> anyhow::Result<()> {
    match fs::hard_link(orig, rb) {
        Ok(()) => Ok(()),
        #[cfg(unix)]
        Err(e)
            if matches!(e.kind(), std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied) =>
        {
            let mut src = open_file_no_follow_ro(orig, "rollback source")?;
            stream_fd_to_new_file_hashed(&mut src, rb)?;
            Ok(())
        }
        #[cfg(not(unix))]
        Err(_) => {
            let mut src = open_file_no_follow_ro(orig, "rollback source")?;
            stream_fd_to_new_file_hashed(&mut src, rb)?;
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("hard-linking {} to {}", orig.display(), rb.display())),
    }
}

/// How long [`quiesce_existing_wal`] waits for other connections to let go.
#[cfg(not(test))]
const QUIESCE_BUSY_TIMEOUT: std::time::Duration = BUSY_TIMEOUT;
#[cfg(test)]
const QUIESCE_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Why the existing database's sidecars could not be folded into it.
enum QuiesceFailure {
    /// Another connection holds the database (busy or locked). Removing the
    /// sidecars now would discard frames that process still depends on.
    Busy(String),
    /// Any other failure, for example a corrupt destination being replaced.
    Other(String),
}

fn is_busy_error(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _)
            if matches!(f.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

/// Checkpoint and truncate a hot WAL (or roll back a hot journal) into the
/// existing database and switch it to `journal_mode = DELETE`, so the later
/// sidecar removal discards nothing. Returns `Ok(())` when there was nothing to
/// do or the database is now self-contained.
fn quiesce_existing_wal(abs_dst: &Path) -> Result<(), QuiesceFailure> {
    if !fs::symlink_metadata(abs_dst).is_ok_and(|m| m.is_file()) {
        return Ok(());
    }
    let has_sidecar = [wal_sidecar_path(abs_dst), shm_sidecar_path(abs_dst), journal_sidecar_path(abs_dst)]
        .into_iter()
        .any(|p| fs::symlink_metadata(&p).is_ok_and(|m| m.is_file()));
    if !has_sidecar {
        return Ok(());
    }
    let classify = |what: &str, e: rusqlite::Error| {
        let msg = format!("{what}: {e}");
        if is_busy_error(&e) { QuiesceFailure::Busy(msg) } else { QuiesceFailure::Other(msg) }
    };
    let conn = Connection::open_with_flags(
        abs_dst,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| classify("opening existing database", e))?;
    conn.busy_timeout(QUIESCE_BUSY_TIMEOUT).map_err(|e| classify("setting busy timeout", e))?;
    // `wal_checkpoint` reports a reader or writer that blocked it as `busy = 1`
    // in its result row rather than as an error.
    let (busy, log, checkpointed): (i64, i64, i64) = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(|e| classify("checkpointing WAL", e))?;
    if busy != 0 {
        return Err(QuiesceFailure::Busy(format!(
            "WAL checkpoint blocked by another connection ({checkpointed} of {log} frames checkpointed)"
        )));
    }
    let mode: String = conn
        .query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))
        .map_err(|e| classify("switching journal_mode to DELETE", e))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(QuiesceFailure::Busy(format!(
            "journal_mode stayed {mode}; another connection still holds the database"
        )));
    }
    Ok(())
}

fn restore_database_inner(
    source: &Path,
    destination: &Path,
    opts: RestoreOptions,
    post_commit_hook: Option<PostCommitHook<'_>>,
) -> anyhow::Result<RestoreReport> {
    restore_database_with_hooks(source, destination, opts, None, post_commit_hook)
}

fn restore_database_with_hooks(
    source: &Path,
    destination: &Path,
    opts: RestoreOptions,
    after_rename_hook: Option<PostCommitHook<'_>>,
    post_commit_hook: Option<PostCommitHook<'_>>,
) -> anyhow::Result<RestoreReport> {
    let abs_src = absolutize(source)?;
    let abs_dst = absolutize(destination)?;

    if !opts.dry_run && opts.expected_sha256.is_none() && !opts.allow_unpinned {
        bail!(
            "non-dry-run restore requires --expected-sha256 <64-hex> \
             (or pass --allow-unpinned to opt out)"
        );
    }
    reject_if_symlink(&abs_dst, "destination")?;
    if !opts.dry_run {
        for sidecar in
            [wal_sidecar_path(&abs_dst), shm_sidecar_path(&abs_dst), journal_sidecar_path(&abs_dst)]
        {
            reject_if_symlink(&sidecar, "destination sidecar")?;
        }
    }
    if same_target_file(&abs_src, &abs_dst)? {
        bail!("restore source {} and destination {} must be distinct", abs_src.display(), abs_dst.display());
    }
    for (label, sidecar) in
        [("-wal", wal_sidecar_path(&abs_src)), ("-journal", journal_sidecar_path(&abs_src))]
    {
        if fs::symlink_metadata(&sidecar).is_ok() {
            bail!(
                "refusing restore: source {} has a {label} sidecar ({}); take a self-contained snapshot with `ua backup` first",
                abs_src.display(),
                sidecar.display()
            );
        }
    }
    if !opts.dry_run && !opts.force && fs::symlink_metadata(&abs_dst).is_ok() {
        bail!("destination {} already exists (pass --force to overwrite)", abs_dst.display());
    }

    // Open `--from` once (`O_NOFOLLOW | O_NONBLOCK`), stream into private `0700`
    // staging next to `destination` (never `/tmp`, and without creating a
    // missing destination parent during `--dry-run`), and check via `immutable=1`.
    let mut src_fd = open_file_no_follow_ro(&abs_src, "backup source")?;
    let mut stage_dir = if opts.dry_run {
        let dry_parent = abs_dst
            .parent()
            .filter(|p| p.is_dir())
            .or_else(|| abs_src.parent().filter(|p| p.is_dir()))
            .ok_or_else(|| anyhow::anyhow!("cannot locate an existing directory for dry-run staging"))?;
        let stem = abs_dst.file_name().and_then(|s| s.to_str()).filter(|s| !s.is_empty()).unwrap_or("ua.db");
        DirGuard::create_private_in_existing(dry_parent, stem, "restore-dry")?
    } else {
        DirGuard::create_private_sibling(&abs_dst, "restore")?
    };
    let staged_db = stage_dir.file("staged.db");
    let (sha256, bytes) = stream_fd_to_new_file_hashed(&mut src_fd, &staged_db)?;
    drop(src_fd);

    if let Some(expected) = opts.expected_sha256.as_deref() {
        let expected = normalize_sha256(expected)?;
        if sha256 != expected {
            bail!("backup SHA-256 mismatch: expected {expected}, got {sha256}");
        }
    }

    let (quick_check, ledger_report, schema_compat, restored_head_seq, restored_head_hash) = {
        let conn = open_read_only_immutable(&staged_db)?;
        let check = run_integrity_pragma(&conn, "PRAGMA integrity_check")?;
        if check != "ok" {
            bail!("backup source {} failed integrity_check: {check}", abs_src.display());
        }
        if !table_exists(&conn, "schema_parts")? || !table_exists(&conn, "event_log")? {
            bail!(
                "backup source {} is not a ua-rust hub database (missing schema_parts or event_log)",
                abs_src.display()
            );
        }
        let schema_compat = if let Some((required, optional)) = &opts.expected_schema {
            let compat = check_schema_compatibility(&conn, required, optional)?;
            if let Some(ref err) = compat.reference_error {
                bail!("refusing restore: {err}");
            }
            if !compat.drifted.is_empty() {
                bail!(
                    "refusing restore: schema part checksum drift detected ({})",
                    compat.drifted.join(", ")
                );
            }
            if !compat.missing_objects.is_empty() || !compat.modified_objects.is_empty() {
                bail!(
                    "refusing restore: expected schema objects missing or modified (missing=[{}], modified=[{}])",
                    compat.missing_objects.join(", "),
                    compat.modified_objects.join(", ")
                );
            }
            if !compat.reserved_name_objects.is_empty() {
                bail!(
                    "refusing restore: objects using the reserved sqlite_ name prefix ([{}])",
                    compat.reserved_name_objects.join(", ")
                );
            }
            if !compat.conflicting_objects.is_empty() {
                bail!(
                    "refusing restore: unexpected objects colliding with known schema names ([{}])",
                    compat.conflicting_objects.join(", ")
                );
            }
            if !compat.unexpected_triggers_on_known_tables.is_empty() {
                bail!(
                    "refusing restore: unexpected triggers on known tables ([{}])",
                    compat.unexpected_triggers_on_known_tables.join(", ")
                );
            }
            if !compat.unexpected_indexes_on_known_tables.is_empty() {
                bail!(
                    "refusing restore: unexpected indexes on known tables ([{}])",
                    compat.unexpected_indexes_on_known_tables.join(", ")
                );
            }
            if !compat.extra.is_empty() && !opts.allow_newer {
                bail!(
                    "refusing restore: backup contains schema parts from a newer build ({}); pass --allow-newer to override",
                    compat.extra.join(", ")
                );
            }
            if !compat.unexpected_foreign_keys_to_known_tables.is_empty() {
                bail!(
                    "refusing restore: unexpected tables declare foreign keys into known tables ([{}])",
                    compat.unexpected_foreign_keys_to_known_tables.join(", ")
                );
            }
            if compat.extra.is_empty() && compat.has_unexpected_objects() {
                bail!(
                    "refusing restore: unexpected schema objects (tables=[{}], indexes=[{}], triggers=[{}])",
                    compat.unexpected_tables.join(", "),
                    compat.unexpected_indexes.join(", "),
                    compat.unexpected_triggers.join(", ")
                );
            }
            Some(compat)
        } else {
            None
        };
        let sequence_problems = check_autoincrement_sequences(&conn)?;
        if !sequence_problems.is_empty() {
            bail!("refusing restore: inconsistent AUTOINCREMENT counters ({})", sequence_problems.join("; "));
        }
        let report = ledger::verify(&conn)?;
        if !report.ok {
            bail!(
                "refusing restore: event_log verification failed at seq {:?}: {}",
                report.first_bad_seq,
                report.reason.as_deref().unwrap_or("unknown error")
            );
        }
        let head: Option<(i64, Option<String>)> = conn
            .query_row(
                "SELECT seq, entry_hash FROM event_log WHERE entry_hash IS NOT NULL ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        (check, report, schema_compat, head.as_ref().map(|h| h.0), head.and_then(|h| h.1))
    };

    if opts.dry_run {
        return Ok(RestoreReport {
            source: abs_src.display().to_string(),
            destination: abs_dst.display().to_string(),
            dry_run: true,
            sha256,
            bytes,
            quick_check,
            ledger: ledger_report,
            schema: schema_compat,
            safety_backup: None,
            safety_backup_sidecars: Vec::new(),
            revoked_sessions: BTreeMap::new(),
            restored_event_seq: None,
            warnings: Vec::new(),
        });
    }

    let _parent = ensure_parent_dir(&abs_dst)?;
    let (safety_backup, safety_backup_sidecars) =
        if fs::symlink_metadata(&abs_dst).is_ok() && opts.keep_safety_backup {
            let (path, sidecars) = create_safety_backup(&abs_dst)?;
            (Some(path.display().to_string()), sidecars)
        } else {
            (None, Vec::new())
        };
    let note = safety_note(&safety_backup);

    // Checkpoint and truncate any hot WAL into the existing database BEFORE staging
    // rollback hard links, so SQLite unlinks `-wal`/`-shm` cleanly while keeping
    // all committed frames inside `rollback/main`.
    let mut warnings = Vec::new();
    match quiesce_existing_wal(&abs_dst) {
        Ok(()) => {}
        Err(QuiesceFailure::Busy(msg)) => {
            bail!(
                "refusing restore: another process is using {} ({msg}); stop it and retry{note}",
                abs_dst.display()
            );
        }
        // The destination is unreadable (for example corrupt), which is a normal
        // reason to restore, so carry on and report it. Opening a corrupt file can
        // already make SQLite discard an unreadable WAL, so refusing here would
        // protect nothing; whatever sidecars remain are staged for rollback and,
        // unless `--no-safety-backup` was passed, copied next to the safety backup.
        Err(QuiesceFailure::Other(msg)) => {
            warnings.push(format!(
                "could not checkpoint the existing database's sidecars before replacing it ({msg}){note}"
            ));
        }
    }

    // Link (or copy on cross-FS/vfat) the existing DB and any remaining sidecars into
    // private rollback staging WITHOUT unlinking `ua.db`, so a crash before swap
    // leaves the previous database untouched in place.
    let rollback_dir = stage_dir.file("rollback");
    fs::create_dir(&rollback_dir).with_context(|| format!("creating rollback staging dir{note}"))?;
    let mut saved: Vec<(String, PathBuf, PathBuf)> = Vec::new();
    for (tag, orig) in [
        ("main", abs_dst.clone()),
        ("wal", wal_sidecar_path(&abs_dst)),
        ("shm", shm_sidecar_path(&abs_dst)),
        ("journal", journal_sidecar_path(&abs_dst)),
    ] {
        if fs::symlink_metadata(&orig).is_ok() {
            let rb = rollback_dir.join(tag);
            if let Err(e) = stage_rollback_copy(&orig, &rb) {
                return Err(e).with_context(|| format!("staging rollback copy for {}{note}", orig.display()));
            }
            saved.push((tag.to_string(), rb, orig));
        }
    }
    if let Err(e) = sync_dir(&rollback_dir) {
        return Err(e).with_context(|| format!("syncing rollback staging dir{note}"));
    }

    // Clear any remaining old sidecars BEFORE `fs::rename(&staged_db, &abs_dst)` so
    // a crash immediately after the rename cannot leave stale `-wal`/`-shm`/`-journal`
    // files that SQLite would replay into the newly installed database.
    let mut removed_sidecar = false;
    for sidecar in [wal_sidecar_path(&abs_dst), shm_sidecar_path(&abs_dst), journal_sidecar_path(&abs_dst)] {
        if fs::symlink_metadata(&sidecar).is_ok() {
            if let Err(e) = fs::remove_file(&sidecar) {
                match rollback_swap(&abs_dst, &saved) {
                    Ok(()) => {
                        return Err(e).with_context(|| {
                            format!(
                                "clearing old sidecar {} (rolled back original database){note}",
                                sidecar.display()
                            )
                        });
                    }
                    Err(rb_err) => {
                        stage_dir.disarm();
                        bail!(
                            "failed clearing old sidecar {} ({e}) AND rollback FAILED ({rb_err:#}) — original recovery files preserved in {}{note}",
                            sidecar.display(),
                            rollback_dir.display()
                        );
                    }
                }
            }
            removed_sidecar = true;
        }
    }
    if removed_sidecar && let Some(parent) = abs_dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = sync_dir(parent);
    }

    if let Err(e) = fs::rename(&staged_db, &abs_dst) {
        if removed_sidecar {
            match rollback_swap(&abs_dst, &saved) {
                Ok(()) => {
                    return Err(e).with_context(|| {
                        format!(
                            "installing restored database into {} (rolled back original database){note}",
                            abs_dst.display()
                        )
                    });
                }
                Err(rb_err) => {
                    stage_dir.disarm();
                    bail!(
                        "installing restored database into {} FAILED ({e}) AND rollback FAILED ({rb_err:#}) — original recovery files preserved in {}{note}",
                        abs_dst.display(),
                        rollback_dir.display()
                    );
                }
            }
        }
        return Err(e)
            .with_context(|| format!("installing restored database into {}{note}", abs_dst.display()));
    }
    if let Some(parent) = abs_dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = sync_dir(parent);
    }

    if let Some(hook) = after_rename_hook
        && let Err(e) = hook(&abs_dst)
    {
        match rollback_swap(&abs_dst, &saved) {
            Ok(()) => {
                bail!("post-rename check failed; rolled back original database{note}: {e:#}");
            }
            Err(rb_err) => {
                stage_dir.disarm();
                bail!(
                    "post-rename check failed ({e:#}); rollback FAILED ({rb_err:#}) — original recovery files preserved in {}{note}",
                    rollback_dir.display()
                );
            }
        }
    }

    let (installed_qc, revoked_sessions, event_seq) = match post_install_finalize(
        &abs_dst,
        &sha256,
        restored_head_seq,
        restored_head_hash.as_deref(),
        opts.revoke_sessions,
        post_commit_hook,
    ) {
        Ok(res) => res,
        Err(e) => match rollback_swap(&abs_dst, &saved) {
            Ok(()) => {
                bail!("post-install failure; rolled back original database{note}: {e:#}");
            }
            Err(rb_err) => {
                stage_dir.disarm();
                bail!(
                    "post-install failure ({e:#}); rollback FAILED ({rb_err:#}) — original recovery files preserved in {}{note}",
                    rollback_dir.display()
                );
            }
        },
    };

    drop(stage_dir);

    Ok(RestoreReport {
        source: abs_src.display().to_string(),
        destination: abs_dst.display().to_string(),
        dry_run: false,
        sha256,
        bytes,
        quick_check: installed_qc,
        ledger: ledger_report,
        schema: schema_compat,
        safety_backup,
        safety_backup_sidecars,
        revoked_sessions,
        restored_event_seq: Some(event_seq),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;
    use crate::SchemaPart;
    use crate::ledger::{EventInput, META_SCHEMA, SCHEMA as LEDGER_SCHEMA};
    use serde_json::json;

    const EXTRA: SchemaPart = SchemaPart {
        name: "backup_test.v1",
        sql: "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, val TEXT NOT NULL);",
    };

    fn test_db() -> (tempfile::TempDir, PathBuf, Db) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ua.db");
        let db = Db::open(&path, &[LEDGER_SCHEMA, META_SCHEMA, EXTRA]).unwrap();
        (dir, path, db)
    }

    fn schema_pair() -> Option<(Vec<Part>, Vec<Part>)> {
        Some((schema::parts(&[LEDGER_SCHEMA, META_SCHEMA, EXTRA]), Vec::new()))
    }

    #[test]
    fn live_wal_backup_captures_uncheckpointed_writes_and_sets_0600() {
        let (src_dir, src_path, db) = test_db();
        db.read(|_| {
            for i in 0..25 {
                db.write(|tx| {
                    tx.execute("INSERT INTO items (val) VALUES (?1)", [format!("row-{i}")])?;
                    ledger::append(
                        tx,
                        EventInput::new(ua_core::DEFAULT_ORG, "backup.test", json!({ "i": i }))
                            .by("builder-1"),
                    )?;
                    Ok(())
                })
                .unwrap();
            }
            Ok(())
        })
        .unwrap();

        let wal_len = fs::metadata(wal_sidecar_path(&src_path)).unwrap().len();
        assert!(wal_len > 0, "expected uncheckpointed frames in WAL");

        let dest_dir = tempfile::tempdir().unwrap();
        let bak_path = dest_dir.path().join("snap.db");
        let report = backup_database(&src_path, &bak_path, false).unwrap();
        assert_eq!(report.quick_check, "ok");
        assert!(report.ledger.ok);
        assert_eq!(report.ledger.checked, 25);
        assert_eq!(report.ledger_head_seq, Some(25));
        assert_eq!(report.table_counts.get("event_log"), Some(&25));
        assert!(!wal_sidecar_path(&bak_path).exists(), "snapshot must be self-contained");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&bak_path).unwrap().permissions().mode() & 0o777, 0o600);
        }

        let iso_dir = tempfile::tempdir().unwrap();
        let iso_path = iso_dir.path().join("isolated.db");
        fs::copy(&bak_path, &iso_path).unwrap();
        let health = check_database(&iso_path).unwrap();
        assert!(health.exists);
        assert_eq!(health.quick_check.as_deref(), Some("ok"));
        assert!(health.ledger.as_ref().unwrap().ok);
        assert_eq!(health.ledger.as_ref().unwrap().checked, 25);

        let err = backup_database(&src_path, &bak_path, false).unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");
        let forced = backup_database(&src_path, &bak_path, true).unwrap();
        assert_eq!(forced.sha256, report.sha256);
        drop(src_dir);
    }

    #[test]
    fn concurrent_writes_during_backup_yield_valid_snapshot() {
        let (_dir, src_path, db) = test_db();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_db = db.clone();
        let stop_flag = stop.clone();
        let handle = std::thread::spawn(move || {
            let mut i = 0;
            while !stop_flag.load(Ordering::Relaxed) && i < 120 {
                writer_db
                    .write(|tx| {
                        tx.execute("INSERT INTO items (val) VALUES (?1)", [format!("w-{i}")])?;
                        ledger::append(
                            tx,
                            EventInput::new(ua_core::DEFAULT_ORG, "concurrent.write", json!({ "i": i })),
                        )?;
                        Ok(())
                    })
                    .unwrap();
                std::thread::yield_now();
                i += 1;
            }
        });
        let bak_dir = tempfile::tempdir().unwrap();
        for n in 0..4 {
            let snap = bak_dir.path().join(format!("c-{n}.db"));
            let rep = backup_database(&src_path, &snap, false).unwrap();
            assert_eq!(rep.quick_check, "ok");
            assert!(rep.ledger.ok);
            // Assert transactional consistency between `items` and `event_log` inside the snapshot.
            let sc = open_read_only(&snap).unwrap();
            let item_count: i64 = sc.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0)).unwrap();
            let ev_count: i64 = sc.query_row("SELECT COUNT(*) FROM event_log", [], |r| r.get(0)).unwrap();
            assert_eq!(
                item_count, ev_count,
                "snapshot {n} saw torn transaction: items={item_count} ev={ev_count}"
            );
            if item_count > 0 {
                let last_payload: String = sc
                    .query_row("SELECT payload FROM event_log ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
                    .unwrap();
                let expected = format!("{{\"i\":{}}}", item_count - 1);
                assert_eq!(last_payload, expected);
            }
        }
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    #[test]
    fn failed_backup_leaves_no_staging_dir_behind() {
        let dir = tempfile::tempdir().unwrap();
        let corrupt = dir.path().join("garbage.db");
        fs::write(&corrupt, b"not a sqlite db at all").unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let bak = dest_dir.path().join("out.db");
        assert!(backup_database(&corrupt, &bak, false).is_err());
        assert!(!bak.exists());
        let entries: Vec<_> =
            fs::read_dir(dest_dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(entries.is_empty(), "stray staging files left behind: {entries:?}");
    }

    #[test]
    fn tampered_ledger_refuses_backup_and_restore_and_preserves_wal_on_safety_fallback() {
        let (_dir, path, db) = test_db();
        for i in 0..3 {
            db.write(|tx| {
                tx.execute("INSERT INTO items (val) VALUES (?1)", [format!("pre-{i}")])?;
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "test.ev", json!({ "i": i })))?;
                Ok(())
            })
            .unwrap();
        }
        // Take a clean backup BEFORE tampering so we can restore over tampered+WAL live DB.
        let good_dir = tempfile::tempdir().unwrap();
        let good_bak = good_dir.path().join("clean.db");
        let good_rep = backup_database(&path, &good_bak, false).unwrap();

        // Corrupt seq=2 and write an uncheckpointed row into WAL without checkpointing.
        db.read(|_| {
            db.write(|tx| {
                tx.execute_batch("DROP TRIGGER event_log_no_update;")?;
                tx.execute("UPDATE event_log SET payload = '{\"tampered\":true}' WHERE seq = 2", [])?;
                tx.execute("INSERT INTO items (val) VALUES ('uncheckpointed-wal-row')", [])?;
                Ok(())
            })
            .unwrap();
            Ok(())
        })
        .unwrap();
        assert!(wal_sidecar_path(&path).exists());
        drop(db);

        let bak_bad = good_dir.path().join("bad-backup.db");
        let err = backup_database(&path, &bak_bad, false).unwrap_err().to_string();
        assert!(err.contains("event_log verification failed"), "{err}");

        let rest_bad = good_dir.path().join("restored-from-bad.db");
        let err =
            restore_database(&path, &rest_bad, RestoreOptions { allow_unpinned: true, ..Default::default() })
                .unwrap_err()
                .to_string();
        assert!(err.contains("-wal sidecar") || err.contains("event_log verification failed"), "{err}");

        // Restoring good_bak over tampered live DB preserves BOTH .bak and .bak-wal!
        let restored = restore_database(
            &good_bak,
            &path,
            RestoreOptions {
                force: true,
                expected_sha256: Some(good_rep.sha256),
                keep_safety_backup: true,
                expected_schema: schema_pair(),
                ..Default::default()
            },
        )
        .unwrap();
        let safety = PathBuf::from(restored.safety_backup.unwrap());
        assert!(safety.is_file());
        assert!(
            restored.safety_backup_sidecars.iter().any(|s| s.ends_with("-wal")),
            "expected -wal safety sidecar in {:?}",
            restored.safety_backup_sidecars
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&safety).unwrap().permissions().mode() & 0o777, 0o600);
            for side in &restored.safety_backup_sidecars {
                assert_eq!(fs::metadata(side).unwrap().permissions().mode() & 0o777, 0o600);
            }
        }
        // Inspect the safety backup (with its -wal sidecar) to confirm the uncheckpointed row survived!
        let sc = open_read_only(&safety).unwrap();
        let has_wal_row: i64 = sc
            .query_row("SELECT COUNT(*) FROM items WHERE val = 'uncheckpointed-wal-row'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(has_wal_row, 1);
    }

    /// A backup taken before `organization.v1.store` existed restores into a
    /// build that has it: the part is reported missing, not refused, and
    /// applies on the next open, after which the ledger still verifies.
    #[test]
    fn an_older_backup_without_the_org_part_restores_and_upgrades() {
        let (dir, live_path, db) = test_db();
        for i in 0..3 {
            db.write(|tx| {
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "before.upgrade", json!({ "i": i })))
            })
            .unwrap();
        }
        drop(db);
        let bak = dir.path().join("old.db");
        let rep = backup_database(&live_path, &bak, false).unwrap();

        let full = vec![
            Part::from(LEDGER_SCHEMA),
            Part::from(META_SCHEMA),
            Part::from(crate::org::STORE_PART),
            Part::from(EXTRA),
        ];
        let dest = dir.path().join("restored.db");
        let restored = restore_database(
            &bak,
            &dest,
            RestoreOptions {
                expected_sha256: Some(rep.sha256),
                expected_schema: Some((full.clone(), Vec::new())),
                ..Default::default()
            },
        )
        .unwrap();
        let compat = restored.schema.unwrap();
        assert_eq!(compat.missing, ["organization.v1.store"], "{compat:?}");
        assert!(!compat.has_tampering_or_unowned_objects(), "{compat:?}");

        let db = Db::open(&dest, &full).unwrap();
        let (orgs, hash_forms): (i64, i64) = db
            .read(|c| {
                Ok((
                    c.query_row("SELECT COUNT(*) FROM orgs WHERE id = 'default'", [], |r| r.get(0))?,
                    c.query_row(
                        "SELECT COUNT(*) FROM event_log WHERE org_id = 'default' AND hash_v = 1",
                        [],
                        |r| r.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(orgs, 1);
        assert!(hash_forms >= 3, "every restored row is backfilled ({hash_forms})");
        db.write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "after.upgrade", json!({}))))
            .unwrap();
        let latest_hash_v: i64 = db
            .read(|c| {
                Ok(c.query_row("SELECT hash_v FROM event_log ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))?)
            })
            .unwrap();
        assert_eq!(latest_hash_v, ledger::HASH_V2);
        let report = db.read(ledger::verify).unwrap();
        assert!(report.ok, "{report:?}");

        // Back up and restore the now-mixed v1/v2 store; verify both forms
        // survive intact and the restored store continues in hash_v = 2.
        let mixed_bak = dir.path().join("mixed.bak.db");
        let mixed_rep = backup_database(&dest, &mixed_bak, false).unwrap();
        let mixed_dest = dir.path().join("mixed_restored.db");
        restore_database(
            &mixed_bak,
            &mixed_dest,
            RestoreOptions {
                expected_sha256: Some(mixed_rep.sha256),
                expected_schema: Some((full.clone(), Vec::new())),
                ..Default::default()
            },
        )
        .unwrap();
        let restored_db = Db::open(&mixed_dest, &full).unwrap();
        let (v1_count, v2_count): (i64, i64) = restored_db
            .read(|c| {
                Ok((
                    c.query_row("SELECT COUNT(*) FROM event_log WHERE hash_v = 1", [], |r| r.get(0))?,
                    c.query_row("SELECT COUNT(*) FROM event_log WHERE hash_v = 2", [], |r| r.get(0))?,
                ))
            })
            .unwrap();
        assert!(v1_count >= 3, "pre-upgrade v1 rows preserved ({v1_count})");
        assert!(v2_count >= 2, "post-upgrade v2 + ops.restored rows preserved ({v2_count})");
        let report = restored_db.read(ledger::verify).unwrap();
        assert!(report.ok, "mixed v1/v2 restored store must verify: {report:?}");
    }

    #[test]
    fn restore_enforces_pinning_schema_triggers_and_records_ops_restored_event() {
        let (_dir, live_path, db) = test_db();
        for i in 0..5 {
            db.write(|tx| {
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "phase.one", json!({ "i": i })))
            })
            .unwrap();
        }
        let bak_dir = tempfile::tempdir().unwrap();
        let bak_path = bak_dir.path().join("good.db");
        let bak_rep = backup_database(&live_path, &bak_path, false).unwrap();

        for i in 5..8 {
            db.write(|tx| {
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "phase.two", json!({ "i": i })))
            })
            .unwrap();
        }
        drop(db);

        // Non-dry-run restore without SHA-256 refuses unless allow_unpinned = true.
        let err =
            restore_database(&bak_path, &live_path, RestoreOptions { force: true, ..Default::default() })
                .unwrap_err()
                .to_string();
        assert!(err.contains("--expected-sha256"), "{err}");

        // Wrong SHA-256 refuses.
        let err = restore_database(
            &bak_path,
            &live_path,
            RestoreOptions { force: true, expected_sha256: Some("0".repeat(64)), ..Default::default() },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("SHA-256 mismatch"), "{err}");

        // Dry run checks schema & ledger without touching live_path.
        let dry = restore_database(
            &bak_path,
            &live_path,
            RestoreOptions {
                dry_run: true,
                expected_sha256: Some(bak_rep.sha256.clone()),
                expected_schema: schema_pair(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(dry.dry_run);
        assert!(dry.schema.as_ref().unwrap().ok);
        assert_eq!(check_database(&live_path).unwrap().ledger.unwrap().checked, 8);

        // Real restore appends `ops.restored` event (so ledger count becomes 5 + 1 = 6) and sets 0600.
        let restored = restore_database(
            &bak_path,
            &live_path,
            RestoreOptions {
                force: true,
                expected_sha256: Some(bak_rep.sha256),
                keep_safety_backup: true,
                expected_schema: schema_pair(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(restored.restored_event_seq, Some(6));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&live_path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let after = check_database(&live_path).unwrap();
        assert_eq!(after.journal_mode.as_deref(), Some("wal"));
        assert!(after.ledger.as_ref().unwrap().ok);
        assert_eq!(after.ledger.as_ref().unwrap().checked, 6);
    }

    #[test]
    fn restore_rejects_corrupt_sidecar_schema_drift_newer_build_and_planted_triggers() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("dest.db");

        // Real valid SQLite backup truncated in the middle (valid 100-byte header, truncated body).
        let (_sdir, src_path, db) = test_db();
        db.write(|tx| {
            tx.execute("INSERT INTO items (val) VALUES ('row-0')", [])?;
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({})))?;
            Ok(())
        })
        .unwrap();
        drop(db);
        let valid_for_trunc = dir.path().join("valid-for-trunc.db");
        backup_database(&src_path, &valid_for_trunc, false).unwrap();
        let full_bytes = fs::read(&valid_for_trunc).unwrap();
        assert!(full_bytes.starts_with(b"SQLite format 3\0"));
        let trunc_path = dir.path().join("truncated-real.db");
        fs::write(&trunc_path, &full_bytes[..512]).unwrap();
        assert!(
            restore_database(
                &trunc_path,
                &dest,
                RestoreOptions { allow_unpinned: true, ..Default::default() }
            )
            .is_err()
        );

        // Source with `-wal` sidecar refused.
        let bak_with_wal = dir.path().join("withwal.db");
        fs::copy(&valid_for_trunc, &bak_with_wal).unwrap();
        fs::write(wal_sidecar_path(&bak_with_wal), b"wal-bytes").unwrap();
        let err = restore_database(
            &bak_with_wal,
            &dest,
            RestoreOptions { allow_unpinned: true, ..Default::default() },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("-wal sidecar"), "{err}");

        // Planted trigger refused (even with allow_newer if attached to a known table).
        let (_tdir, trig_src, trig_db) = test_db();
        trig_db
            .write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({}))))
            .unwrap();
        trig_db
            .write(|tx| {
                tx.execute_batch("CREATE TRIGGER evil_trig AFTER INSERT ON items BEGIN SELECT 1; END;")?;
                Ok(())
            })
            .unwrap();
        drop(trig_db);
        let trig_bak = dir.path().join("trig.db");
        backup_database(&trig_src, &trig_bak, false).unwrap();
        let err = restore_database(
            &trig_bak,
            &dest,
            RestoreOptions {
                allow_unpinned: true,
                allow_newer: true,
                expected_schema: schema_pair(),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unexpected triggers on known tables") || err.contains("unexpected schema"),
            "{err}"
        );

        // Dropped expected trigger (`event_log_no_update`) refused.
        let (_ddir, drop_trig_src, drop_trig_db) = test_db();
        drop_trig_db
            .write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({}))))
            .unwrap();
        drop_trig_db.write(|tx| Ok(tx.execute_batch("DROP TRIGGER event_log_no_update;")?)).unwrap();
        drop(drop_trig_db);
        let drop_trig_bak = dir.path().join("drop-trig.db");
        backup_database(&drop_trig_src, &drop_trig_bak, false).unwrap();
        let err = restore_database(
            &drop_trig_bak,
            &dest,
            RestoreOptions { allow_unpinned: true, expected_schema: schema_pair(), ..Default::default() },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("event_log_no_update"), "{err}");

        // Missing expected table (`DROP TABLE items`) refused.
        let (_mdir, miss_tbl_src, miss_tbl_db) = test_db();
        miss_tbl_db
            .write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({}))))
            .unwrap();
        miss_tbl_db.write(|tx| Ok(tx.execute_batch("DROP TABLE items;")?)).unwrap();
        drop(miss_tbl_db);
        let miss_tbl_bak = dir.path().join("miss-tbl.db");
        backup_database(&miss_tbl_src, &miss_tbl_bak, false).unwrap();
        let err = restore_database(
            &miss_tbl_bak,
            &dest,
            RestoreOptions { allow_unpinned: true, expected_schema: schema_pair(), ..Default::default() },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("table:items"), "{err}");

        // Altered expected table DDL (`ALTER TABLE items ADD COLUMN rogue TEXT`) refused.
        let (_adir, alt_src, alt_db) = test_db();
        alt_db
            .write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({}))))
            .unwrap();
        alt_db.write(|tx| Ok(tx.execute_batch("ALTER TABLE items ADD COLUMN rogue TEXT;")?)).unwrap();
        drop(alt_db);
        let alt_bak = dir.path().join("altered.db");
        backup_database(&alt_src, &alt_bak, false).unwrap();
        let err = restore_database(
            &alt_bak,
            &dest,
            RestoreOptions { allow_unpinned: true, expected_schema: schema_pair(), ..Default::default() },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("modified=[table:items]"), "{err}");

        // Real newer-build SchemaPart creating a new table (`future_things`) + index
        // refuses when allow_newer=false, and succeeds when allow_newer=true.
        const NEWER: SchemaPart = SchemaPart {
            name: "future_feature.v1",
            sql: "CREATE TABLE future_things (id INTEGER PRIMARY KEY, label TEXT NOT NULL);
                  CREATE INDEX idx_future_things ON future_things(label);",
        };
        let new_src = dir.path().join("newer-src.db");
        let new_db = Db::open(&new_src, &[LEDGER_SCHEMA, META_SCHEMA, EXTRA, NEWER]).unwrap();
        new_db
            .write(|tx| {
                tx.execute("INSERT INTO future_things (label) VALUES ('ok')", [])?;
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({})))?;
                Ok(())
            })
            .unwrap();
        drop(new_db);
        let new_bak = dir.path().join("newer.db");
        backup_database(&new_src, &new_bak, false).unwrap();
        let err = restore_database(
            &new_bak,
            &dest,
            RestoreOptions { allow_unpinned: true, expected_schema: schema_pair(), ..Default::default() },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("newer build"), "{err}");

        let ok = restore_database(
            &new_bak,
            &dest,
            RestoreOptions {
                allow_unpinned: true,
                allow_newer: true,
                expected_schema: schema_pair(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(ok.restored_event_seq.is_some());

        // Rogue table with NO unknown `schema_parts` refuses EVEN with allow_newer=true.
        let (_rdir, rogue_src, rogue_db) = test_db();
        rogue_db
            .write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({}))))
            .unwrap();
        rogue_db.write(|tx| Ok(tx.execute_batch("CREATE TABLE rogue_tbl (x INT);")?)).unwrap();
        drop(rogue_db);
        let rogue_bak = dir.path().join("rogue.db");
        backup_database(&rogue_src, &rogue_bak, false).unwrap();
        let err = restore_database(
            &rogue_bak,
            &dir.path().join("rogue-dest.db"),
            RestoreOptions {
                allow_unpinned: true,
                allow_newer: true,
                expected_schema: schema_pair(),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unexpected schema objects"), "{err}");

        // Schema drift refused even with allow_newer = true.
        let drift_conn = Connection::open(&src_path).unwrap();
        drift_conn
            .execute("UPDATE schema_parts SET checksum = 'drifted' WHERE name = ?1", [EXTRA.name])
            .unwrap();
        drop(drift_conn);
        let drift_bak = dir.path().join("drift.db");
        backup_database(&src_path, &drift_bak, false).unwrap();
        let err = restore_database(
            &drift_bak,
            &dir.path().join("drift-dest.db"),
            RestoreOptions {
                allow_unpinned: true,
                allow_newer: true,
                expected_schema: schema_pair(),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("checksum drift"), "{err}");
    }

    #[test]
    fn post_install_failure_rolls_back_previous_db_and_sidecars_and_reports_safety_path() {
        let (live_dir, live_path, db) = test_db();
        db.read(|_| {
            for i in 0..3 {
                db.write(|tx| {
                    tx.execute("INSERT INTO items (val) VALUES (?1)", [format!("orig-{i}")])?;
                    ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "orig", json!({ "i": i })))?;
                    Ok(())
                })
                .unwrap();
            }
            Ok(())
        })
        .unwrap();
        let bak_dir = tempfile::tempdir().unwrap();
        let good_bak = bak_dir.path().join("bak.db");
        backup_database(&live_path, &good_bak, false).unwrap();

        db.write(|tx| {
            tx.execute("INSERT INTO items (val) VALUES ('extra-before-swap')", [])?;
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "orig.more", json!({})))?;
            Ok(())
        })
        .unwrap();
        drop(db);

        // Fail AFTER ops.restored has committed + WAL created, then verify clean rollback.
        let err = restore_database_inner(
            &good_bak,
            &live_path,
            RestoreOptions {
                force: true,
                allow_unpinned: true,
                keep_safety_backup: true,
                ..Default::default()
            },
            Some(&|dest| {
                let conn = open_read_only(dest)?;
                let restored_cnt: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM event_log WHERE channel = 'ops.restored'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(restored_cnt, 1, "expected ops.restored committed before failure hook");
                bail!("simulated failure after ops.restored commit");
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("rolled back original database"), "{err}");
        assert!(err.contains(".pre-restore-"), "{err}");

        // Original DB + WAL must be intact (4 entries, extra-before-swap present, NO ops.restored)
        // and no leftover `.restore.` staging dir remains.
        let restored = check_database(&live_path).unwrap();
        assert_eq!(restored.ledger.unwrap().checked, 4);
        let c = open_read_only(&live_path).unwrap();
        let extra_cnt: i64 = c
            .query_row("SELECT COUNT(*) FROM items WHERE val = 'extra-before-swap'", [], |r| r.get(0))
            .unwrap();
        let ops_cnt: i64 = c
            .query_row("SELECT COUNT(*) FROM event_log WHERE channel = 'ops.restored'", [], |r| r.get(0))
            .unwrap();
        assert_eq!((extra_cnt, ops_cnt), (1, 0));
        // Release the read-only verification connection before invoking restore again;
        // quiesce_existing_wal rightly refuses while any SQLite handle still holds the DB open.
        drop(c);
        let stray_staging: Vec<_> = fs::read_dir(live_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".restore."))
            .collect();
        assert!(stray_staging.is_empty(), "stray restore staging dirs: {stray_staging:?}");

        // Now force rollback itself to fail (`destination` replaced with a directory -> EISDIR):
        // rollback staging must be preserved (NOT deleted) and both rollback & safety paths reported.
        let err = restore_database_inner(
            &good_bak,
            &live_path,
            RestoreOptions {
                force: true,
                allow_unpinned: true,
                keep_safety_backup: true,
                ..Default::default()
            },
            Some(&|dest| {
                fs::remove_file(dest)?;
                fs::create_dir(dest)?;
                bail!("simulated swap corruption forcing rollback failure");
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("rollback FAILED"), "{err}");
        assert!(err.contains(".pre-restore-"), "{err}");
        assert!(err.contains("rollback"), "{err}");

        let preserved: Vec<_> = fs::read_dir(live_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().contains(".restore.")))
            .collect();
        assert_eq!(preserved.len(), 1, "expected preserved rollback staging dir: {preserved:?}");
        let rb_main = preserved[0].join("rollback/main");
        assert!(rb_main.is_file(), "rollback/main missing in {}", preserved[0].display());
        let rb_health = check_database(&rb_main).unwrap();
        assert_eq!(rb_health.ledger.unwrap().checked, 4);
    }

    #[test]
    fn check_uid_match_dir_owner_fifo_and_dry_run_staging_cleanup() {
        let err = check_uid_match(Path::new("/var/lib/ua-rust"), 0, 1000).unwrap_err().to_string();
        assert!(
            err.contains("uid 0") && err.contains("effective uid is 1000") && err.contains("sudo"),
            "{err}"
        );
        assert!(check_uid_match(Path::new("/var/lib/ua-rust"), 1000, 1000).is_ok());

        let dir = tempfile::tempdir().unwrap();
        check_dir_owner(dir.path()).unwrap();
        #[cfg(unix)]
        if unsafe { libc::geteuid() } != 0 {
            let root_err = check_dir_owner(Path::new("/")).unwrap_err().to_string();
            assert!(root_err.contains("owned by uid 0"), "{root_err}");
        }

        let missing = dir.path().join("file:tricky.db");
        assert!(!check_database(&missing).unwrap().exists);

        // Dry-run stages next to destination (without creating missing destination parent)
        // and cleans up its staging dir on completion.
        let (_sdir, src, db) = test_db();
        db.write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({})))).unwrap();
        drop(db);
        let bak = dir.path().join("snap.db");
        let bak_rep = backup_database(&src, &bak, false).unwrap();

        let non_existent_dst = dir.path().join("no-such-parent/ua.db");
        let dry_missing_parent = restore_database(
            &bak,
            &non_existent_dst,
            RestoreOptions {
                dry_run: true,
                expected_sha256: Some(bak_rep.sha256.clone()),
                expected_schema: schema_pair(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(dry_missing_parent.dry_run);
        assert!(
            !dir.path().join("no-such-parent").exists(),
            "dry-run must not create destination parent directory"
        );

        let dry_dst_dir = dir.path().join("hub-home");
        fs::create_dir_all(&dry_dst_dir).unwrap();
        let dry_dst = dry_dst_dir.join("ua.db");
        let dry = restore_database(
            &bak,
            &dry_dst,
            RestoreOptions {
                dry_run: true,
                expected_sha256: Some(bak_rep.sha256),
                expected_schema: schema_pair(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(dry.dry_run);
        let stray: Vec<_> = fs::read_dir(&dry_dst_dir).unwrap().collect();
        assert!(stray.is_empty(), "dry-run left files in destination parent: {stray:?}");

        // FIFO passed as `--from` must fail immediately without blocking.
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let fifo = dir.path().join("pipe.db");
            let c_fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
            let rc = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) };
            assert_eq!(rc, 0, "mkfifo failed");
            let err = restore_database(
                &fifo,
                &dry_dst,
                RestoreOptions { allow_unpinned: true, ..Default::default() },
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("regular file"), "{err}");
        }
    }

    #[test]
    fn restore_with_revoke_sessions_invalidates_session_tables() {
        const AUTH_MOCK: SchemaPart = SchemaPart {
            name: "auth_mock.v1",
            sql: "
            CREATE TABLE ui_sessions (id_hash TEXT PRIMARY KEY, revoked_at TEXT);
            CREATE TABLE login_links (token_hash TEXT PRIMARY KEY, used_at TEXT);
            CREATE TABLE oauth_grants (family_id TEXT PRIMARY KEY, revoked_at TEXT, revoked_reason TEXT);
            CREATE TABLE oauth_tokens (token_hash TEXT PRIMARY KEY, status TEXT NOT NULL, revoked_at TEXT);
            CREATE TABLE oauth_codes (code_hash TEXT PRIMARY KEY, used_at TEXT);
            CREATE TABLE oauth_requests (id_hash TEXT PRIMARY KEY);
            CREATE TABLE session_credentials (credential_id TEXT PRIMARY KEY, revoked_at TEXT, revoke_reason TEXT);
            ",
        };
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.db");
        let db = Db::open(&src, &[LEDGER_SCHEMA, META_SCHEMA, AUTH_MOCK]).unwrap();
        db.write(|tx| {
            tx.execute("INSERT INTO ui_sessions (id_hash) VALUES ('s1')", [])?;
            tx.execute("INSERT INTO login_links (token_hash) VALUES ('l1')", [])?;
            tx.execute("INSERT INTO oauth_grants (family_id) VALUES ('g1')", [])?;
            tx.execute("INSERT INTO oauth_tokens (token_hash, status) VALUES ('t1', 'active')", [])?;
            tx.execute("INSERT INTO oauth_codes (code_hash) VALUES ('c1')", [])?;
            tx.execute("INSERT INTO oauth_requests (id_hash) VALUES ('r1')", [])?;
            tx.execute("INSERT INTO session_credentials (credential_id) VALUES ('sc1')", [])?;
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "seed", json!({})))?;
            Ok(())
        })
        .unwrap();
        drop(db);

        let bak = dir.path().join("bak.db");
        let bak_rep = backup_database(&src, &bak, false).unwrap();
        let dest = dir.path().join("dest.db");
        let rep = restore_database(
            &bak,
            &dest,
            RestoreOptions {
                expected_sha256: Some(bak_rep.sha256),
                revoke_sessions: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rep.revoked_sessions.get("ui_sessions"), Some(&1));
        assert_eq!(rep.revoked_sessions.get("oauth_requests"), Some(&1));
        assert_eq!(rep.revoked_sessions.get("session_credentials"), Some(&1));
        let conn = open_read_only(&dest).unwrap();
        let active_ui: i64 = conn
            .query_row("SELECT COUNT(*) FROM ui_sessions WHERE revoked_at IS NULL", [], |r| r.get(0))
            .unwrap();
        let reqs: i64 = conn.query_row("SELECT COUNT(*) FROM oauth_requests", [], |r| r.get(0)).unwrap();
        assert_eq!((active_ui, reqs), (0, 0));
    }

    #[test]
    fn schema_check_rejects_broken_dependency_sqlite_like_wildcards_upper_case_and_conflicts() {
        const DEP_BASE: SchemaPart = SchemaPart {
            name: "dep_base.v1",
            sql: "CREATE TABLE IF NOT EXISTS dep_tbl (id INTEGER PRIMARY KEY);",
        };
        const DEP_ALTER: SchemaPart =
            SchemaPart { name: "dep_base.v2", sql: "ALTER TABLE dep_tbl ADD COLUMN note TEXT;" };
        let parts = vec![LEDGER_SCHEMA, META_SCHEMA, EXTRA, DEP_BASE, DEP_ALTER];
        let optional = schema::parts(&[schema::IMPORT_SCHEMA]);
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("dest.db");

        // 1. Deleting `dep_base.v1` breaks `dep_base.v2` replay in `applied_ref`:
        //    must still fail closed AND detect dropped `event_log` triggers (no `--allow-newer` & `--allow-newer`).
        let p1_src = dir.path().join("p1.db");
        let p1_db = Db::open(&p1_src, &parts).unwrap();
        p1_db.write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({})))).unwrap();
        p1_db
            .write(|tx| {
                tx.execute_batch(
                    "DELETE FROM schema_parts WHERE name = 'dep_base.v1';
                     DROP TRIGGER event_log_no_update;
                     DROP TRIGGER event_log_no_delete;
                     INSERT INTO schema_parts (name, checksum, applied_at) VALUES ('future.v1', 'abc', '2026-01-01T00:00:00Z');",
                )?;
                Ok(())
            })
            .unwrap();
        drop(p1_db);
        let p1_bak = dir.path().join("p1-bak.db");
        backup_database(&p1_src, &p1_bak, false).unwrap();
        let ro_p1 = open_read_only(&p1_bak).unwrap();
        let compat_p1 = check_schema_compatibility(&ro_p1, &parts, &optional).unwrap();
        assert!(compat_p1.reference_error.is_some(), "{compat_p1:?}");
        assert!(
            compat_p1.missing_objects.contains(&"trigger:event_log_no_update".to_string()),
            "{compat_p1:?}"
        );
        assert!(
            compat_p1.missing_objects.contains(&"trigger:event_log_no_delete".to_string()),
            "{compat_p1:?}"
        );
        assert!(compat_p1.has_tampering_or_unowned_objects(), "{compat_p1:?}");
        drop(ro_p1);
        for allow_newer in [false, true] {
            let err = restore_database(
                &p1_bak,
                &dest,
                RestoreOptions {
                    allow_unpinned: true,
                    allow_newer,
                    expected_schema: Some((schema::parts(&parts), schema::parts(&optional))),
                    ..Default::default()
                },
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("could not be replayed cleanly"), "allow_newer={allow_newer}: {err}");
        }

        // Also deleting `ledger.v1` row while `event_log` exists must trigger `conflicting_objects`.
        let p1b_src = dir.path().join("p1b.db");
        let p1b_db = Db::open(&p1b_src, &[LEDGER_SCHEMA, META_SCHEMA, EXTRA]).unwrap();
        p1b_db
            .write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({}))))
            .unwrap();
        p1b_db
            .write(|tx| {
                tx.execute_batch(
                    "DELETE FROM schema_parts WHERE name = 'ledger.v1';
                     INSERT INTO schema_parts (name, checksum, applied_at) VALUES ('future.v1', 'abc', '2026-01-01T00:00:00Z');",
                )?;
                Ok(())
            })
            .unwrap();
        drop(p1b_db);
        let p1b_bak = dir.path().join("p1b-bak.db");
        backup_database(&p1b_src, &p1b_bak, false).unwrap();
        let err = restore_database(
            &p1b_bak,
            &dest,
            RestoreOptions {
                allow_unpinned: true,
                allow_newer: true,
                expected_schema: Some((
                    schema::parts(&[LEDGER_SCHEMA, META_SCHEMA, EXTRA]),
                    schema::parts(&optional),
                )),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("colliding with known schema names"), "{err}");

        // 2. `sqlite_` LIKE wildcard / case-insensitivity bypass (`sqlitexevil`, `Sqlite1rogue`).
        let (_s2dir, p2_src, p2_db) = test_db();
        p2_db.write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({})))).unwrap();
        p2_db
            .write(|tx| {
                tx.execute_batch(
                    "CREATE TRIGGER sqlitexevil BEFORE INSERT ON event_log BEGIN SELECT RAISE(IGNORE); END;
                     CREATE TABLE Sqlite1rogue (x INTEGER);",
                )?;
                Ok(())
            })
            .unwrap();
        drop(p2_db);
        let p2_bak = dir.path().join("p2-bak.db");
        backup_database(&p2_src, &p2_bak, false).unwrap();
        let ro_p2 = open_read_only(&p2_bak).unwrap();
        let compat_p2 =
            check_schema_compatibility(&ro_p2, &[LEDGER_SCHEMA, META_SCHEMA, EXTRA], &optional).unwrap();
        assert!(
            compat_p2.unexpected_triggers_on_known_tables.iter().any(|s| s.contains("sqlitexevil")),
            "{compat_p2:?}"
        );
        assert!(compat_p2.unexpected_tables.contains(&"table:Sqlite1rogue".to_string()), "{compat_p2:?}");
        drop(ro_p2);
        let err = restore_database(
            &p2_bak,
            &dest,
            RestoreOptions {
                allow_unpinned: true,
                expected_schema: Some((
                    schema::parts(&[LEDGER_SCHEMA, META_SCHEMA, EXTRA]),
                    schema::parts(&optional),
                )),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("sqlitexevil"), "{err}");

        // 3. Mixed/uppercase table target in trigger (`ON EVENT_LOG`) with fake `future.v1` + `--allow-newer`.
        let (_s3dir, p3_src, p3_db) = test_db();
        p3_db.write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({})))).unwrap();
        p3_db
            .write(|tx| {
                tx.execute_batch(
                    "INSERT INTO schema_parts (name, checksum, applied_at) VALUES ('future.v1', 'abc', '2026-01-01T00:00:00Z');
                     CREATE TRIGGER evil_upper BEFORE INSERT ON EVENT_LOG BEGIN SELECT 1; END;",
                )?;
                Ok(())
            })
            .unwrap();
        drop(p3_db);
        let p3_bak = dir.path().join("p3-bak.db");
        backup_database(&p3_src, &p3_bak, false).unwrap();
        let err = restore_database(
            &p3_bak,
            &dest,
            RestoreOptions {
                allow_unpinned: true,
                allow_newer: true,
                expected_schema: Some((
                    schema::parts(&[LEDGER_SCHEMA, META_SCHEMA, EXTRA]),
                    schema::parts(&optional),
                )),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unexpected triggers on known tables") && err.contains("evil_upper"), "{err}");

        // 6a. Unexpected index on a known table (`ON EVENT_LOG`) with fake `future.v1` + `--allow-newer`.
        let (_s6dir, p6_src, p6_db) = test_db();
        p6_db.write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({})))).unwrap();
        p6_db
            .write(|tx| {
                tx.execute_batch(
                    "INSERT INTO schema_parts (name, checksum, applied_at) VALUES ('future.v1', 'abc', '2026-01-01T00:00:00Z');
                     CREATE UNIQUE INDEX idx_evil_chan ON EVENT_LOG(channel);",
                )?;
                Ok(())
            })
            .unwrap();
        drop(p6_db);
        let p6_bak = dir.path().join("p6-bak.db");
        backup_database(&p6_src, &p6_bak, false).unwrap();
        let err = restore_database(
            &p6_bak,
            &dest,
            RestoreOptions {
                allow_unpinned: true,
                allow_newer: true,
                expected_schema: Some((
                    schema::parts(&[LEDGER_SCHEMA, META_SCHEMA, EXTRA]),
                    schema::parts(&optional),
                )),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unexpected indexes on known tables") && err.contains("idx_evil_chan"), "{err}");

        // 6b. View shadowing an optional unapplied table (`import_runs`) with fake `future.v1` + `--allow-newer`.
        let (_s6bdir, p6b_src, p6b_db) = test_db();
        p6b_db
            .write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({}))))
            .unwrap();
        p6b_db
            .write(|tx| {
                tx.execute_batch(
                    "INSERT INTO schema_parts (name, checksum, applied_at) VALUES ('future.v1', 'abc', '2026-01-01T00:00:00Z');
                     CREATE VIEW import_runs AS SELECT 1 AS x;",
                )?;
                Ok(())
            })
            .unwrap();
        drop(p6b_db);
        let p6b_bak = dir.path().join("p6b-bak.db");
        backup_database(&p6b_src, &p6b_bak, false).unwrap();
        let err = restore_database(
            &p6b_bak,
            &dest,
            RestoreOptions {
                allow_unpinned: true,
                allow_newer: true,
                expected_schema: Some((
                    schema::parts(&[LEDGER_SCHEMA, META_SCHEMA, EXTRA]),
                    schema::parts(&optional),
                )),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("colliding with known schema names") && err.contains("view:import_runs"),
            "{err}"
        );

        // Control: legitimate newer part with new table, index, and trigger on that new table passes with `--allow-newer`.
        const LEGIT_NEWER: SchemaPart = SchemaPart {
            name: "future_legit.v1",
            sql: "
            CREATE TABLE future_log (id INTEGER PRIMARY KEY, label TEXT NOT NULL);
            CREATE INDEX idx_future_log_label ON future_log(label);
            CREATE TABLE future_log_audit (label TEXT NOT NULL);
            CREATE TRIGGER future_log_ai AFTER INSERT ON future_log BEGIN
                INSERT INTO future_log_audit(label) VALUES (NEW.label);
            END;
            ",
        };
        let legit_src = dir.path().join("legit-newer.db");
        let legit_db = Db::open(&legit_src, &[LEDGER_SCHEMA, META_SCHEMA, EXTRA, LEGIT_NEWER]).unwrap();
        legit_db
            .write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "ev", json!({}))))
            .unwrap();
        drop(legit_db);
        let legit_bak = dir.path().join("legit-bak.db");
        backup_database(&legit_src, &legit_bak, false).unwrap();
        let ok = restore_database(
            &legit_bak,
            &dir.path().join("legit-dest.db"),
            RestoreOptions {
                allow_unpinned: true,
                allow_newer: true,
                expected_schema: Some((
                    schema::parts(&[LEDGER_SCHEMA, META_SCHEMA, EXTRA]),
                    schema::parts(&optional),
                )),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(ok.restored_event_seq.is_some());
    }

    #[test]
    fn hot_wal_crash_window_does_not_replay_old_wal_and_preserves_rollback() {
        let dir = tempfile::tempdir().unwrap();

        // Source backup contains ONLY `'restored-only'`.
        let (_sdir, src_path, src_db) = test_db();
        src_db
            .write(|tx| {
                tx.execute("INSERT INTO items (val) VALUES ('restored-only')", [])?;
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "seed.restored", json!({})))?;
                Ok(())
            })
            .unwrap();
        drop(src_db);
        let bak_path = dir.path().join("restored-bak.db");
        backup_database(&src_path, &bak_path, false).unwrap();

        // Live DB writes `'committed-main'`, then while a read snapshot holds the WAL open,
        // writes `'hot-wal-row'` so `'hot-wal-row'` resides ONLY in `-wal` (not in `ua.db`).
        let (_odir, orig_path, orig_db) = test_db();
        orig_db
            .write(|tx| {
                tx.execute("INSERT INTO items (val) VALUES ('committed-main')", [])?;
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "orig.main", json!({})))?;
                Ok(())
            })
            .unwrap();

        let crash_a_dir = dir.path().join("crash-a");
        let crash_b_dir = dir.path().join("crash-b");
        fs::create_dir_all(&crash_a_dir).unwrap();
        fs::create_dir_all(&crash_b_dir).unwrap();
        let crash_a_db = crash_a_dir.join("ua.db");
        let crash_b_db = crash_b_dir.join("ua.db");

        orig_db
            .read(|_| {
                orig_db
                    .write(|tx| {
                        tx.execute("INSERT INTO items (val) VALUES ('hot-wal-row')", [])?;
                        ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "orig.hot", json!({})))?;
                        Ok(())
                    })
                    .unwrap();
                let wal_len = fs::metadata(wal_sidecar_path(&orig_path)).unwrap().len();
                assert!(wal_len > 0, "expected uncheckpointed hot WAL frames");
                for dst in [&crash_a_db, &crash_b_db] {
                    fs::copy(&orig_path, dst).unwrap();
                    fs::copy(wal_sidecar_path(&orig_path), wal_sidecar_path(dst)).unwrap();
                    if shm_sidecar_path(&orig_path).exists() {
                        fs::copy(shm_sidecar_path(&orig_path), shm_sidecar_path(dst)).unwrap();
                    }
                }
                Ok(())
            })
            .unwrap();
        drop(orig_db);

        // 1. After `fs::rename`, BEFORE `post_install_finalize` opens RW: no stale `-wal`/`-shm`
        //    may remain on disk, opening sees ONLY `'restored-only'` (no hot-WAL replay!), and
        //    `integrity_check` is `"ok"`.
        let rep = restore_database_with_hooks(
            &bak_path,
            &crash_a_db,
            RestoreOptions {
                force: true,
                allow_unpinned: true,
                keep_safety_backup: true,
                ..Default::default()
            },
            Some(&|dest| {
                assert!(!wal_sidecar_path(dest).exists(), "stale -wal present after rename");
                assert!(!shm_sidecar_path(dest).exists(), "stale -shm present after rename");
                let ro = open_read_only(dest)?;
                assert_eq!(run_integrity_pragma(&ro, "PRAGMA integrity_check")?, "ok");
                let restored_cnt: i64 =
                    ro.query_row("SELECT COUNT(*) FROM items WHERE val = 'restored-only'", [], |r| r.get(0))?;
                let hot_cnt: i64 =
                    ro.query_row("SELECT COUNT(*) FROM items WHERE val = 'hot-wal-row'", [], |r| r.get(0))?;
                assert_eq!((restored_cnt, hot_cnt), (1, 0), "old hot WAL replayed over restored DB");
                Ok(())
            }),
            None,
        )
        .unwrap();
        let safety_conn = open_read_only(Path::new(rep.safety_backup.as_deref().unwrap())).unwrap();
        let safety_hot: i64 = safety_conn
            .query_row("SELECT COUNT(*) FROM items WHERE val = 'hot-wal-row'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(safety_hot, 1, "safety backup lost hot-wal-row");

        // 2. If `post_install_finalize` fails on a hot-WAL destination, rollback must still keep `'hot-wal-row'`.
        let err = restore_database_with_hooks(
            &bak_path,
            &crash_b_db,
            RestoreOptions {
                force: true,
                allow_unpinned: true,
                keep_safety_backup: true,
                ..Default::default()
            },
            None,
            Some(&|_| bail!("forced post-commit failure")),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("rolled back original database"), "{err}");
        let rb_conn = open_read_only(&crash_b_db).unwrap();
        let rb_hot: i64 = rb_conn
            .query_row("SELECT COUNT(*) FROM items WHERE val = 'hot-wal-row'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rb_hot, 1, "rollback lost hot-wal-row from original DB");
    }

    /// A mock token table so a planted trigger has a security-relevant target.
    const TOKENS_MOCK: SchemaPart = SchemaPart {
        name: "tokens_mock.v1",
        sql: "CREATE TABLE IF NOT EXISTS agent_tokens (id TEXT PRIMARY KEY, status TEXT NOT NULL);",
    };

    fn tokens_parts() -> Vec<SchemaPart> {
        vec![LEDGER_SCHEMA, META_SCHEMA, TOKENS_MOCK]
    }

    /// Take a clean backup of a hub holding one active token and one event.
    fn tokens_backup(dir: &Path) -> PathBuf {
        let src = dir.join("tokens-src.db");
        let db = Db::open(&src, &tokens_parts()).unwrap();
        db.write(|tx| {
            tx.execute("INSERT INTO agent_tokens (id, status) VALUES ('tok-1', 'active')", [])?;
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "seed", json!({})))?;
            Ok(())
        })
        .unwrap();
        drop(db);
        let bak = dir.join("tokens-bak.db");
        backup_database(&src, &bak, false).unwrap();
        bak
    }

    /// Copy `bak` to `name` and run `sql` on the copy (rollback journal, so the
    /// copy stays a single self-contained file).
    fn tamper_copy(bak: &Path, name: &str, sql: &str) -> PathBuf {
        let out = bak.with_file_name(name);
        fs::copy(bak, &out).unwrap();
        let conn = Connection::open(&out).unwrap();
        conn.execute_batch(sql).unwrap();
        drop(conn);
        assert!(!wal_sidecar_path(&out).exists() && !journal_sidecar_path(&out).exists());
        out
    }

    /// Plant a schema object through `PRAGMA writable_schema`, which bypasses
    /// SQLite's reserved-name check for `sqlite_`-prefixed names.
    fn plant_sql(obj_type: &str, name: &str, tbl: &str, ddl: &str) -> String {
        format!(
            "PRAGMA writable_schema = ON;
             INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql)
             VALUES ('{obj_type}', '{name}', '{tbl}', 0, '{}');
             PRAGMA writable_schema = OFF;",
            ddl.replace('\'', "''")
        )
    }

    fn restore_opts(parts: Vec<SchemaPart>, allow_newer: bool) -> RestoreOptions {
        RestoreOptions {
            allow_unpinned: true,
            allow_newer,
            expected_schema: Some((schema::parts(&parts), Vec::new())),
            ..Default::default()
        }
    }

    #[test]
    fn writable_schema_sqlite_prefixed_trigger_and_view_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let bak = tokens_backup(dir.path());

        // A trigger that re-activates a revoked token.
        let keepalive = plant_sql(
            "trigger",
            "sqlite_keepalive",
            "agent_tokens",
            "CREATE TRIGGER sqlite_keepalive AFTER UPDATE OF status ON agent_tokens \
             BEGIN UPDATE agent_tokens SET status = 'active' WHERE id = NEW.id; END",
        );
        // Prove the planted trigger is live: revoking the token has no effect.
        let probe = tamper_copy(&bak, "probe.db", &keepalive);
        let conn = Connection::open(&probe).unwrap();
        conn.execute("UPDATE agent_tokens SET status = 'revoked' WHERE id = 'tok-1'", []).unwrap();
        let status: String =
            conn.query_row("SELECT status FROM agent_tokens WHERE id = 'tok-1'", [], |r| r.get(0)).unwrap();
        assert_eq!(status, "active", "planted trigger did not load; the test would prove nothing");
        drop(conn);

        let tampered = tamper_copy(&bak, "keepalive.db", &keepalive);
        let ro = open_read_only(&tampered).unwrap();
        assert_eq!(run_integrity_pragma(&ro, "PRAGMA integrity_check").unwrap(), "ok");
        let compat = check_schema_compatibility(&ro, &tokens_parts(), &[]).unwrap();
        assert!(!compat.ok, "{compat:?}");
        assert_eq!(compat.reserved_name_objects, vec!["trigger:sqlite_keepalive".to_string()]);
        assert!(compat.has_tampering_or_unowned_objects(), "{compat:?}");
        drop(ro);
        for allow_newer in [false, true] {
            let err = restore_database(
                &tampered,
                &dir.path().join(format!("dest-keepalive-{allow_newer}.db")),
                restore_opts(tokens_parts(), allow_newer),
            )
            .unwrap_err()
            .to_string();
            assert!(
                err.contains("reserved sqlite_ name prefix") && err.contains("sqlite_keepalive"),
                "allow_newer={allow_newer}: {err}"
            );
        }

        // A trigger that silently drops every ledger append (including `ops.restored`).
        let drop_appends = tamper_copy(
            &bak,
            "drop-appends.db",
            &plant_sql(
                "trigger",
                "sqlite_evil",
                "event_log",
                "CREATE TRIGGER sqlite_evil BEFORE INSERT ON event_log BEGIN SELECT RAISE(IGNORE); END",
            ),
        );
        let err = restore_database(
            &drop_appends,
            &dir.path().join("dest-evil.db"),
            restore_opts(tokens_parts(), false),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("sqlite_evil"), "{err}");

        // A `sqlite_` view next to a fake newer part is refused even under --allow-newer.
        let view = tamper_copy(
            &bak,
            "view.db",
            &format!(
                "INSERT INTO schema_parts (name, checksum, applied_at) \
                 VALUES ('future.v1', 'abc', '2026-01-01T00:00:00Z');
                 {}",
                plant_sql(
                    "view",
                    "sqlite_shadow",
                    "sqlite_shadow",
                    "CREATE VIEW sqlite_shadow AS SELECT 1 AS x"
                )
            ),
        );
        let err =
            restore_database(&view, &dir.path().join("dest-view.db"), restore_opts(tokens_parts(), true))
                .unwrap_err()
                .to_string();
        assert!(err.contains("reserved sqlite_ name prefix") && err.contains("view:sqlite_shadow"), "{err}");

        // Control: the untampered backup (with `sqlite_sequence` and automatic
        // indexes, which stay exempt) restores, and `ops.restored` is recorded.
        let ok =
            restore_database(&bak, &dir.path().join("dest-clean.db"), restore_opts(tokens_parts(), false))
                .unwrap();
        assert!(ok.schema.as_ref().unwrap().ok, "{:?}", ok.schema);
        assert_eq!(ok.restored_event_seq, Some(2));
    }

    #[test]
    fn tampered_sqlite_sequence_is_refused() {
        const COUNTED: SchemaPart = SchemaPart {
            name: "counted.v1",
            sql: "CREATE TABLE IF NOT EXISTS counted (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);
                  CREATE TABLE IF NOT EXISTS idle (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);",
        };
        let parts = vec![LEDGER_SCHEMA, META_SCHEMA, COUNTED];
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("seq-src.db");

        // A fresh hub with an empty ledger has no `sqlite_sequence` rows to check.
        let db = Db::open(&src, &parts).unwrap();
        db.read(|c| {
            assert!(check_autoincrement_sequences(c).unwrap().is_empty());
            Ok(())
        })
        .unwrap();
        db.write(|tx| {
            for i in 0..5 {
                tx.execute("INSERT INTO counted (v) VALUES (?1)", [format!("v{i}")])?;
            }
            // Deleted rows leave the counter above MAX(rowid); that is legitimate.
            tx.execute("DELETE FROM counted WHERE id >= 4", [])?;
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "a", json!({})))?;
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "b", json!({})))?;
            Ok(())
        })
        .unwrap();
        drop(db);
        let bak = dir.path().join("seq-bak.db");
        backup_database(&src, &bak, false).unwrap();
        let clean = open_read_only(&bak).unwrap();
        assert_eq!(check_autoincrement_sequences(&clean).unwrap(), Vec::<String>::new());
        let idle_rows: i64 = clean
            .query_row("SELECT COUNT(*) FROM sqlite_sequence WHERE name = 'idle'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(idle_rows, 0, "the empty AUTOINCREMENT table must have no counter row");
        drop(clean);
        // Honest control: a backup with deleted AUTOINCREMENT rows (counter above
        // MAX(rowid)) and an empty AUTOINCREMENT table without a counter row restores.
        let honest =
            restore_database(&bak, &dir.path().join("dest-honest.db"), restore_opts(parts.clone(), false))
                .unwrap();
        assert_eq!(honest.restored_event_seq, Some(3));

        // event_log's counter pushed toward 2^63 would make every later append fail.
        let near_max = tamper_copy(
            &bak,
            "seq-near-max.db",
            "UPDATE sqlite_sequence SET seq = 9223372036854775806 WHERE name = 'event_log';",
        );
        let err = restore_database(
            &near_max,
            &dir.path().join("dest-near-max.db"),
            restore_opts(parts.clone(), false),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("AUTOINCREMENT") && err.contains("event_log"), "{err}");
        // The same refusal applies without a schema expectation.
        let err = restore_database(
            &near_max,
            &dir.path().join("dest-near-max-2.db"),
            RestoreOptions { allow_unpinned: true, ..Default::default() },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("AUTOINCREMENT"), "{err}");

        let problems_for = |name: &str, sql: &str| {
            let p = tamper_copy(&bak, name, sql);
            let c = open_read_only(&p).unwrap();
            check_autoincrement_sequences(&c).unwrap()
        };
        // event_log must match MAX(seq) exactly, in both directions.
        let low = problems_for("seq-low.db", "UPDATE sqlite_sequence SET seq = 1 WHERE name = 'event_log';");
        assert!(low.iter().any(|p| p.contains("event_log")), "{low:?}");
        let high =
            problems_for("seq-high.db", "UPDATE sqlite_sequence SET seq = 3 WHERE name = 'event_log';");
        assert!(high.iter().any(|p| p.contains("event_log")), "{high:?}");
        // A missing event_log row is harmless: SQLite continues from MAX(seq).
        let gone = problems_for("seq-gone.db", "DELETE FROM sqlite_sequence WHERE name = 'event_log';");
        assert!(gone.is_empty(), "{gone:?}");
        // Other counters: not below MAX(rowid), not above 2^52.
        let reuse =
            problems_for("seq-reuse.db", "UPDATE sqlite_sequence SET seq = 1 WHERE name = 'counted';");
        assert!(reuse.iter().any(|p| p.contains("counted") && p.contains("reused")), "{reuse:?}");
        let huge = problems_for(
            "seq-huge.db",
            "UPDATE sqlite_sequence SET seq = 4503599627370497 WHERE name = 'counted';",
        );
        assert!(huge.iter().any(|p| p.contains("counted") && p.contains("limit")), "{huge:?}");
        let at_cap = problems_for(
            "seq-cap.db",
            "UPDATE sqlite_sequence SET seq = 4503599627370496 WHERE name = 'counted';",
        );
        assert!(at_cap.is_empty(), "{at_cap:?}");
        // Rows SQLite would never write: orphans, duplicates, non-integers.
        let orphan =
            problems_for("seq-orphan.db", "INSERT INTO sqlite_sequence (name, seq) VALUES ('ghost', 7);");
        assert!(orphan.iter().any(|p| p.contains("ghost")), "{orphan:?}");
        let dup = problems_for(
            "seq-dup.db",
            "INSERT INTO sqlite_sequence (name, seq) VALUES ('event_log', 9223372036854775806);",
        );
        assert!(dup.iter().any(|p| p.contains("more than one row")), "{dup:?}");
        let text =
            problems_for("seq-text.db", "UPDATE sqlite_sequence SET seq = 'x' WHERE name = 'counted';");
        assert!(text.iter().any(|p| p.contains("not an integer")), "{text:?}");
    }

    #[test]
    fn autoincrement_ids_above_cap_are_refused_with_or_without_a_counter_row() {
        const COUNTED: SchemaPart = SchemaPart {
            name: "counted.v1",
            sql: "CREATE TABLE IF NOT EXISTS counted (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);",
        };
        let parts = vec![LEDGER_SCHEMA, META_SCHEMA, COUNTED];
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("cap-src.db");
        let db = Db::open(&src, &parts).unwrap();
        db.write(|tx| {
            tx.execute("INSERT INTO counted (v) VALUES ('a')", [])?;
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "a", json!({})))?;
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "b", json!({})))?;
            Ok(())
        })
        .unwrap();
        drop(db);
        let bak = dir.path().join("cap-bak.db");
        backup_database(&src, &bak, false).unwrap();

        // A. Move the last ledger row's seq near 2^63 behind a recreated, identical
        //    no-update trigger and keep the counter equal to MAX(seq). The hash chain
        //    does not cover seq, and the schema check sees the original trigger.
        let ledger_a = tamper_copy(
            &bak,
            "cap-ledger.db",
            "DROP TRIGGER event_log_no_update;
             UPDATE event_log SET seq = 9223372036854775805 WHERE seq = (SELECT MAX(seq) FROM event_log);
             CREATE TRIGGER IF NOT EXISTS event_log_no_update BEFORE UPDATE ON event_log
             BEGIN SELECT RAISE(ABORT, 'event_log is append-only'); END;
             UPDATE sqlite_sequence SET seq = 9223372036854775805 WHERE name = 'event_log';",
        );
        let ro = open_read_only(&ledger_a).unwrap();
        assert!(ledger::verify(&ro).unwrap().ok, "probe must pass the hash chain to be meaningful");
        assert!(check_schema_compatibility(&ro, &parts, &[]).unwrap().ok, "probe must pass the schema check");
        drop(ro);
        let err = restore_database(
            &ledger_a,
            &dir.path().join("dest-ledger.db"),
            restore_opts(parts.clone(), false),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("event_log holds id 9223372036854775805"), "{err}");

        // B. A huge id in another AUTOINCREMENT table with its counter row deleted.
        let table_b = tamper_copy(
            &bak,
            "cap-table.db",
            "INSERT INTO counted (id, v) VALUES (9223372036854775807, 'x');
             DELETE FROM sqlite_sequence WHERE name = 'counted';",
        );
        let err = restore_database(
            &table_b,
            &dir.path().join("dest-table.db"),
            RestoreOptions { allow_unpinned: true, ..Default::default() },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("counted holds id 9223372036854775807"), "{err}");

        // The cap itself is accepted; one above it is not.
        let at_cap = tamper_copy(
            &bak,
            "cap-at.db",
            "INSERT INTO counted (id, v) VALUES (4503599627370496, 'x');
             DELETE FROM sqlite_sequence WHERE name = 'counted';",
        );
        let c = open_read_only(&at_cap).unwrap();
        assert_eq!(check_autoincrement_sequences(&c).unwrap(), Vec::<String>::new());
        drop(c);
        let over =
            tamper_copy(&bak, "cap-over.db", "INSERT INTO counted (id, v) VALUES (4503599627370497, 'x');");
        let c = open_read_only(&over).unwrap();
        let problems = check_autoincrement_sequences(&c).unwrap();
        assert!(problems.iter().any(|p| p.contains("counted holds id")), "{problems:?}");
    }

    #[test]
    fn allow_newer_refuses_new_table_with_foreign_key_into_known_table() {
        let dir = tempfile::tempdir().unwrap();
        let bak = tokens_backup(dir.path());
        let fk = tamper_copy(
            &bak,
            "fk.db",
            "INSERT INTO schema_parts (name, checksum, applied_at) \
             VALUES ('future.v1', 'abc', '2026-01-01T00:00:00Z');
             CREATE TABLE future_child (id INTEGER PRIMARY KEY, token_status TEXT REFERENCES agent_tokens(status));",
        );
        let ro = open_read_only(&fk).unwrap();
        let compat = check_schema_compatibility(&ro, &tokens_parts(), &[]).unwrap();
        assert_eq!(
            compat.unexpected_foreign_keys_to_known_tables,
            vec!["future_child references agent_tokens".to_string()]
        );
        assert!(compat.has_tampering_or_unowned_objects(), "{compat:?}");
        drop(ro);
        let err = restore_database(&fk, &dir.path().join("dest-fk.db"), restore_opts(tokens_parts(), true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("foreign keys into known tables") && err.contains("future_child"), "{err}");

        // A new table whose foreign key stays among new tables is still accepted.
        let fk_new = tamper_copy(
            &bak,
            "fk-new.db",
            "INSERT INTO schema_parts (name, checksum, applied_at) \
             VALUES ('future.v1', 'abc', '2026-01-01T00:00:00Z');
             CREATE TABLE future_parent (id INTEGER PRIMARY KEY);
             CREATE TABLE future_kid (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES future_parent(id));",
        );
        restore_database(&fk_new, &dir.path().join("dest-fk-new.db"), restore_opts(tokens_parts(), true))
            .unwrap();
    }

    #[test]
    fn restore_refuses_when_existing_wal_cannot_be_checkpointed() {
        let dir = tempfile::tempdir().unwrap();
        let (_sdir, src_path, src_db) = test_db();
        src_db
            .write(|tx| ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "seed", json!({}))))
            .unwrap();
        drop(src_db);
        let bak = dir.path().join("bak.db");
        backup_database(&src_path, &bak, false).unwrap();

        // 1. Another process holds a read snapshot on the live database's WAL.
        let (_ldir, live_path, live_db) = test_db();
        live_db
            .write(|tx| {
                tx.execute("INSERT INTO items (val) VALUES ('live-row')", [])?;
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "live", json!({})))?;
                Ok(())
            })
            .unwrap();
        assert!(fs::metadata(wal_sidecar_path(&live_path)).unwrap().len() > 0);
        let reader = Connection::open(&live_path).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let before: i64 = reader.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0)).unwrap();
        assert_eq!(before, 1);

        let err = restore_database(
            &bak,
            &live_path,
            RestoreOptions {
                force: true,
                allow_unpinned: true,
                keep_safety_backup: true,
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("another process is using"), "{err}");
        assert!(wal_sidecar_path(&live_path).exists(), "WAL removed although the checkpoint failed");
        reader.execute_batch("COMMIT").unwrap();
        drop(reader);
        live_db
            .read(|c| {
                let n: i64 =
                    c.query_row("SELECT COUNT(*) FROM items WHERE val = 'live-row'", [], |r| r.get(0))?;
                assert_eq!(n, 1, "live database lost its row");
                Ok(())
            })
            .unwrap();
        drop(live_db);

        // 2. A corrupt destination with a sidecar is still replaceable (that is
        //    what restore is for); the failed checkpoint is reported as a warning.
        let corrupt = dir.path().join("corrupt.db");
        fs::write(&corrupt, b"this is not a database").unwrap();
        fs::write(wal_sidecar_path(&corrupt), b"not a wal either").unwrap();
        let rep = restore_database(
            &bak,
            &corrupt,
            RestoreOptions {
                force: true,
                allow_unpinned: true,
                keep_safety_backup: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rep.warnings.len(), 1, "{rep:?}");
        assert!(rep.warnings[0].contains("could not checkpoint"), "{rep:?}");
        assert!(check_database(&corrupt).unwrap().ledger.unwrap().ok);
    }

    #[test]
    fn safety_backup_preserves_corrupt_db_and_corrupt_wal_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let (_sdir, src_path, src_db) = test_db();
        src_db
            .write(|tx| {
                tx.execute("INSERT INTO items (val) VALUES ('clean-src')", [])?;
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "seed", json!({})))?;
                Ok(())
            })
            .unwrap();
        drop(src_db);
        let bak = dir.path().join("clean.bak");
        backup_database(&src_path, &bak, false).unwrap();

        let corrupt = dir.path().join("corrupt.db");
        let raw_main = b"this is not a database";
        let raw_wal = b"not a wal either";
        fs::write(&corrupt, raw_main).unwrap();
        fs::write(wal_sidecar_path(&corrupt), raw_wal).unwrap();

        let rep = restore_database(
            &bak,
            &corrupt,
            RestoreOptions {
                force: true,
                allow_unpinned: true,
                keep_safety_backup: true,
                ..Default::default()
            },
        )
        .unwrap();

        let safety_main = PathBuf::from(rep.safety_backup.as_deref().unwrap());
        assert_eq!(fs::read(&safety_main).unwrap(), raw_main);
        assert_eq!(rep.safety_backup_sidecars.len(), 1, "{:?}", rep.safety_backup_sidecars);
        let safety_wal = PathBuf::from(&rep.safety_backup_sidecars[0]);
        assert_eq!(fs::read(&safety_wal).unwrap(), raw_wal);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&safety_main).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&safety_wal).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn safety_backup_preserves_corrupt_wal_on_valid_db_without_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let (_sdir, src_path, src_db) = test_db();
        src_db
            .write(|tx| {
                tx.execute("INSERT INTO items (val) VALUES ('clean-src')", [])?;
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "seed", json!({})))?;
                Ok(())
            })
            .unwrap();
        drop(src_db);
        let bak = dir.path().join("clean.bak");
        backup_database(&src_path, &bak, false).unwrap();

        // Sub-case A: valid WAL-mode hub DB with unparseable garbage `-wal`.
        let (_adir, a_seed, a_db) = test_db();
        a_db.write(|tx| {
            tx.execute("INSERT INTO items (val) VALUES ('a-row')", [])?;
            ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "a.seed", json!({})))?;
            Ok(())
        })
        .unwrap();
        drop(a_db);
        let a_dest = dir.path().join("valid-garbage-wal.db");
        fs::copy(&a_seed, &a_dest).unwrap();
        let garbage_wal = b"not a valid wal header";
        fs::write(wal_sidecar_path(&a_dest), garbage_wal).unwrap();

        let rep_a = restore_database(
            &bak,
            &a_dest,
            RestoreOptions {
                force: true,
                allow_unpinned: true,
                keep_safety_backup: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rep_a.safety_backup_sidecars.len(), 1, "{:?}", rep_a.safety_backup_sidecars);
        let a_bak_wal = PathBuf::from(&rep_a.safety_backup_sidecars[0]);
        assert_eq!(fs::read(&a_bak_wal).unwrap(), garbage_wal);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&a_bak_wal).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // Sub-case B: valid WAL-mode hub DB captured hot with a corrupted frame-0 payload byte.
        let (_bdir, b_seed, b_db) = test_db();
        let b_dest = dir.path().join("valid-corrupt-frame-wal.db");
        b_db.read(|_| {
            b_db.write(|tx| {
                tx.execute("INSERT INTO items (val) VALUES ('hot-frame-row')", [])?;
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "b.hot", json!({})))?;
                Ok(())
            })
            .unwrap();
            fs::copy(&b_seed, &b_dest).unwrap();
            fs::copy(wal_sidecar_path(&b_seed), wal_sidecar_path(&b_dest)).unwrap();
            Ok(())
        })
        .unwrap();
        drop(b_db);

        let mut modified_wal = fs::read(wal_sidecar_path(&b_dest)).unwrap();
        assert!(modified_wal.len() > 32 + 24, "expected at least one WAL frame");
        modified_wal[32 + 24] ^= 0xff;
        fs::write(wal_sidecar_path(&b_dest), &modified_wal).unwrap();

        let rep_b = restore_database(
            &bak,
            &b_dest,
            RestoreOptions {
                force: true,
                allow_unpinned: true,
                keep_safety_backup: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rep_b.safety_backup_sidecars.len(), 1, "{:?}", rep_b.safety_backup_sidecars);
        let b_bak_wal = PathBuf::from(&rep_b.safety_backup_sidecars[0]);
        assert_eq!(fs::read(&b_bak_wal).unwrap(), modified_wal);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&b_bak_wal).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn safety_backup_clean_wal_snapshots_uncheckpointed_rows_without_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let (_sdir, src_path, src_db) = test_db();
        src_db
            .write(|tx| {
                tx.execute("INSERT INTO items (val) VALUES ('clean-src')", [])?;
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "seed", json!({})))?;
                Ok(())
            })
            .unwrap();
        drop(src_db);
        let bak = dir.path().join("clean.bak");
        backup_database(&src_path, &bak, false).unwrap();

        // Valid WAL-mode hub DB captured hot: the committed row lives only in the
        // WAL, and the copied `-shm` is snapshotted BEFORE the write, so its
        // wal-index lags the WAL the probe would otherwise trust.
        let (_bdir, b_seed, b_db) = test_db();
        let b_dest = dir.path().join("hot-clean-wal.db");
        b_db.read(|_| {
            fs::copy(&b_seed, &b_dest).unwrap();
            if shm_sidecar_path(&b_seed).exists() {
                fs::copy(shm_sidecar_path(&b_seed), shm_sidecar_path(&b_dest)).unwrap();
            }
            b_db.write(|tx| {
                tx.execute("INSERT INTO items (val) VALUES ('hot-frame-row')", [])?;
                ledger::append(tx, EventInput::new(ua_core::DEFAULT_ORG, "b.hot", json!({})))?;
                Ok(())
            })
            .unwrap();
            fs::copy(&b_seed, &b_dest).unwrap();
            fs::copy(wal_sidecar_path(&b_seed), wal_sidecar_path(&b_dest)).unwrap();
            Ok(())
        })
        .unwrap();
        drop(b_db);

        let rep = restore_database(
            &bak,
            &b_dest,
            RestoreOptions {
                force: true,
                allow_unpinned: true,
                keep_safety_backup: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(rep.safety_backup_sidecars.is_empty(), "{:?}", rep.safety_backup_sidecars);
        let safety = PathBuf::from(rep.safety_backup.as_deref().unwrap());
        let sc = open_read_only(&safety).unwrap();
        let has_wal_row: i64 =
            sc.query_row("SELECT COUNT(*) FROM items WHERE val = 'hot-frame-row'", [], |r| r.get(0)).unwrap();
        assert_eq!(has_wal_row, 1, "uncheckpointed row missing from safety backup");
    }
}
