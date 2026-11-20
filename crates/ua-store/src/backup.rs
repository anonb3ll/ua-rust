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
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::SchemaPart;
use crate::ledger::{self, EventInput, VerifyReport};
use crate::schema;

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
    pub missing: Vec<String>,
    pub drifted: Vec<String>,
    pub extra: Vec<String>,
    pub missing_objects: Vec<String>,
    pub modified_objects: Vec<String>,
    pub unexpected_indexes: Vec<String>,
    pub unexpected_triggers: Vec<String>,
    pub unexpected_triggers_on_known_tables: Vec<String>,
    pub unexpected_tables: Vec<String>,
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
        !self.drifted.is_empty()
            || !self.missing_objects.is_empty()
            || !self.modified_objects.is_empty()
            || !self.unexpected_triggers_on_known_tables.is_empty()
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
    pub expected_schema: Option<(Vec<SchemaPart>, Vec<SchemaPart>)>,
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
}

struct DirGuard {
    dir: PathBuf,
    keep: bool,
}

impl DirGuard {
    fn create_private_in(parent: &Path, stem: &str, tag: &str) -> anyhow::Result<Self> {
        fs::create_dir_all(parent).with_context(|| format!("creating directory {}", parent.display()))?;
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

fn read_master_objects(conn: &Connection) -> anyhow::Result<BTreeMap<(String, String), (String, String)>> {
    let mut map = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master \
         WHERE type IN ('table', 'view', 'index', 'trigger') AND name NOT LIKE 'sqlite_%'",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let obj_type = r.get::<_, String>(0)?;
        let name = r.get::<_, String>(1)?;
        let tbl_name = r.get::<_, String>(2)?;
        let sql = normalize_sql(&r.get::<_, String>(3)?);
        map.insert((obj_type, name), (tbl_name, sql));
    }
    Ok(map)
}

/// Verify `schema_parts` checksums and `sqlite_master` tables, views, indexes,
/// and triggers in `conn` against the schemas registered in the current build.
pub fn check_schema_compatibility(
    conn: &Connection,
    expected: &[SchemaPart],
    optional: &[SchemaPart],
) -> anyhow::Result<SchemaCompatibility> {
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

    for part in expected {
        known.insert(part.name);
        full_parts.push(*part);
        let sum = hex::encode(Sha256::digest(part.sql.as_bytes()));
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
        let sum = hex::encode(Sha256::digest(part.sql.as_bytes()));
        if let Some(s) = applied.get(part.name) {
            full_parts.push(*part);
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
    let known_tables: BTreeSet<String> =
        full_objs.keys().filter(|(t, _)| t == "table" || t == "view").map(|(_, n)| n.clone()).collect();

    let applied_objs = {
        let mut applied_ref = Connection::open_in_memory().context("opening applied reference DB")?;
        applied_ref.execute_batch("PRAGMA foreign_keys = ON;")?;
        if schema::apply(&mut applied_ref, &applied_parts).is_ok() {
            Some(read_master_objects(&applied_ref)?)
        } else {
            None
        }
    };

    let actual_objs = read_master_objects(conn)?;

    let mut missing_objects = Vec::new();
    if let Some(ref exp) = applied_objs {
        for (obj_type, name) in exp.keys() {
            if !actual_objs.contains_key(&(obj_type.clone(), name.clone())) {
                missing_objects.push(format!("{obj_type}:{name}"));
            }
        }
    }

    let mut modified_objects = Vec::new();
    let mut unexpected_indexes = Vec::new();
    let mut unexpected_triggers = Vec::new();
    let mut unexpected_triggers_on_known_tables = Vec::new();
    let mut unexpected_tables = Vec::new();

    for ((obj_type, name), (tbl_name, sql)) in &actual_objs {
        let expected_def = applied_objs
            .as_ref()
            .and_then(|m| m.get(&(obj_type.clone(), name.clone())))
            .or_else(|| full_objs.get(&(obj_type.clone(), name.clone())));
        if let Some((exp_tbl, exp_sql)) = expected_def {
            if exp_tbl != tbl_name || exp_sql != sql {
                modified_objects.push(format!("{obj_type}:{name}"));
            }
        } else {
            match obj_type.as_str() {
                "table" | "view" => unexpected_tables.push(format!("{obj_type}:{name}")),
                "index" => unexpected_indexes.push(format!("{name} on {tbl_name}")),
                "trigger" => {
                    let label = format!("{name} on {tbl_name}");
                    if known_tables.contains(tbl_name) {
                        unexpected_triggers_on_known_tables.push(label.clone());
                    }
                    unexpected_triggers.push(label);
                }
                _ => {}
            }
        }
    }

    let ok = drifted.is_empty()
        && extra.is_empty()
        && missing_objects.is_empty()
        && modified_objects.is_empty()
        && unexpected_indexes.is_empty()
        && unexpected_triggers.is_empty()
        && unexpected_tables.is_empty();
    Ok(SchemaCompatibility {
        ok,
        missing,
        drifted,
        extra,
        missing_objects,
        modified_objects,
        unexpected_indexes,
        unexpected_triggers,
        unexpected_triggers_on_known_tables,
        unexpected_tables,
    })
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

fn create_safety_backup(existing_dest: &Path) -> anyhow::Result<(PathBuf, Vec<String>)> {
    let stamp = compact_timestamp_for_filename();
    let candidate_base = append_suffix(existing_dest, &format!(".pre-restore-{stamp}.bak"));
    let mut safety_path = candidate_base.clone();
    let mut idx = 1usize;
    while fs::symlink_metadata(&safety_path).is_ok() {
        safety_path = append_suffix(&candidate_base, &format!(".{idx}"));
        idx += 1;
    }

    // Prefer a clean online SQLite snapshot if the existing DB is healthy; when
    // recovering a corrupt or ledger-tampered DB, fall back to copying the raw
    // main file AND its `-wal`/`-shm`/`-journal` sidecars (`0600`) so uncheckpointed
    // WAL frames are never lost.
    if backup_database(existing_dest, &safety_path, false).is_ok() {
        return Ok((safety_path, Vec::new()));
    }

    let stage_dir = DirGuard::create_private_sibling(&safety_path, "safety")?;
    let mut main_ro = open_file_no_follow_ro(existing_dest, "pre-restore database")?;
    let staged_main = stage_dir.file("main.bak");
    stream_fd_to_new_file_hashed(&mut main_ro, &staged_main)?;
    install_file(&staged_main, &safety_path, false)?;

    let mut sidecars = Vec::new();
    for suffix in ["-wal", "-shm", "-journal"] {
        let side_src = append_suffix(existing_dest, suffix);
        if let Ok(meta) = fs::symlink_metadata(&side_src)
            && !meta.file_type().is_symlink()
            && meta.is_file()
        {
            let side_dst = append_suffix(&safety_path, suffix);
            let mut side_ro = open_file_no_follow_ro(&side_src, "pre-restore sidecar")?;
            let staged_side = stage_dir.file(&format!("side{suffix}"));
            stream_fd_to_new_file_hashed(&mut side_ro, &staged_side)?;
            install_file(&staged_side, &side_dst, false)?;
            sidecars.push(side_dst.display().to_string());
        }
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

fn restore_database_inner(
    source: &Path,
    destination: &Path,
    opts: RestoreOptions,
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
    // staging next to `destination` (never `/tmp`), and run every subsequent
    // check solely on that staged copy via `immutable=1`.
    let mut src_fd = open_file_no_follow_ro(&abs_src, "backup source")?;
    let mut stage_dir = if opts.dry_run {
        if abs_dst.parent().is_some_and(|p| p.is_dir()) {
            DirGuard::create_private_sibling(&abs_dst, "restore-dry")?
        } else if abs_src.parent().is_some_and(|p| p.is_dir()) {
            DirGuard::create_private_sibling(&abs_src, "restore-dry")?
        } else {
            DirGuard::create_private_sibling(&abs_dst, "restore-dry")?
        }
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
            if !compat.unexpected_triggers_on_known_tables.is_empty() {
                bail!(
                    "refusing restore: unexpected triggers on known tables ([{}])",
                    compat.unexpected_triggers_on_known_tables.join(", ")
                );
            }
            if !compat.extra.is_empty() && !opts.allow_newer {
                bail!(
                    "refusing restore: backup contains schema parts from a newer build ({}); pass --allow-newer to override",
                    compat.extra.join(", ")
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

    // Link (or copy on cross-FS/vfat) the existing DB and sidecars into private
    // rollback staging WITHOUT unlinking `ua.db`, so a crash before `fs::rename`
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

    if let Err(e) = fs::rename(&staged_db, &abs_dst) {
        return Err(e)
            .with_context(|| format!("installing restored database into {}{note}", abs_dst.display()));
    }
    for sidecar in [wal_sidecar_path(&abs_dst), shm_sidecar_path(&abs_dst), journal_sidecar_path(&abs_dst)] {
        if fs::symlink_metadata(&sidecar).is_ok()
            && let Err(e) = fs::remove_file(&sidecar)
        {
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
    }
    if let Some(parent) = abs_dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = sync_dir(parent);
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;
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

    fn schema_pair() -> Option<(Vec<SchemaPart>, Vec<SchemaPart>)> {
        Some((vec![LEDGER_SCHEMA, META_SCHEMA, EXTRA], Vec::new()))
    }

    #[test]
    fn live_wal_backup_captures_uncheckpointed_writes_and_sets_0600() {
        let (src_dir, src_path, db) = test_db();
        db.read(|_| {
            for i in 0..25 {
                db.write(|tx| {
                    tx.execute("INSERT INTO items (val) VALUES (?1)", [format!("row-{i}")])?;
                    ledger::append(tx, EventInput::new("backup.test", json!({ "i": i })).by("builder-1"))?;
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
                        ledger::append(tx, EventInput::new("concurrent.write", json!({ "i": i })))?;
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
                ledger::append(tx, EventInput::new("test.ev", json!({ "i": i })))?;
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

    #[test]
    fn restore_enforces_pinning_schema_triggers_and_records_ops_restored_event() {
        let (_dir, live_path, db) = test_db();
        for i in 0..5 {
            db.write(|tx| ledger::append(tx, EventInput::new("phase.one", json!({ "i": i })))).unwrap();
        }
        let bak_dir = tempfile::tempdir().unwrap();
        let bak_path = bak_dir.path().join("good.db");
        let bak_rep = backup_database(&live_path, &bak_path, false).unwrap();

        for i in 5..8 {
            db.write(|tx| ledger::append(tx, EventInput::new("phase.two", json!({ "i": i })))).unwrap();
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
            ledger::append(tx, EventInput::new("ev", json!({})))?;
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
        trig_db.write(|tx| ledger::append(tx, EventInput::new("ev", json!({})))).unwrap();
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
        drop_trig_db.write(|tx| ledger::append(tx, EventInput::new("ev", json!({})))).unwrap();
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
        miss_tbl_db.write(|tx| ledger::append(tx, EventInput::new("ev", json!({})))).unwrap();
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
        alt_db.write(|tx| ledger::append(tx, EventInput::new("ev", json!({})))).unwrap();
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
                ledger::append(tx, EventInput::new("ev", json!({})))?;
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
        rogue_db.write(|tx| ledger::append(tx, EventInput::new("ev", json!({})))).unwrap();
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
                    ledger::append(tx, EventInput::new("orig", json!({ "i": i })))?;
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
            ledger::append(tx, EventInput::new("orig.more", json!({})))?;
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
        assert!(err.contains("sudo"), "{err}");
        assert!(check_uid_match(Path::new("/var/lib/ua-rust"), 1000, 1000).is_ok());

        let dir = tempfile::tempdir().unwrap();
        check_dir_owner(dir.path()).unwrap();

        let missing = dir.path().join("file:tricky.db");
        assert!(!check_database(&missing).unwrap().exists);

        // Dry-run stages next to destination and cleans up its staging dir on completion.
        let (_sdir, src, db) = test_db();
        db.write(|tx| ledger::append(tx, EventInput::new("ev", json!({})))).unwrap();
        drop(db);
        let bak = dir.path().join("snap.db");
        let bak_rep = backup_database(&src, &bak, false).unwrap();
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
            ledger::append(tx, EventInput::new("seed", json!({})))?;
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
}
