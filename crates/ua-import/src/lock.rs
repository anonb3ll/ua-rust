//! An advisory lock that says "a hub is using this database".
//!
//! Every `ua` command that opens the hub (`serve`, `mcp`, `call`, `token`,
//! ...) holds a shared lock on a file next to the database for as long as it
//! runs, so they can run side by side. An import takes the lock exclusively:
//! it cannot start while any of them runs, and none can start during an
//! import. The OS releases the lock when the holder exits, so a crash leaves
//! nothing stale.
//!
//! `ua serve` also holds a second lock, [`ServeLock`], exclusively: only one
//! serving process may run per database, because the inbound-delivery table
//! judges a stale in-flight delivery by "a claim that is not this process's"
//! (`docs/ingress.md`, Limits). Other commands never take it, so `ua mcp`,
//! `ua call`, backups and the rest run beside a serve as before.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

/// The lock file for a database path: `<db>.hub.lock`.
pub fn lock_path(db_path: &Path) -> PathBuf {
    let mut name = db_path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".hub.lock");
    db_path.with_file_name(name)
}

/// A hold on a database. Dropping it (or exiting) releases it.
#[derive(Debug)]
pub struct HubLock {
    _file: File,
}

impl HubLock {
    /// Take the lock exclusively (an import), or fail with advice to stop
    /// every hub process.
    pub fn acquire(db_path: &Path, what: &str) -> anyhow::Result<HubLock> {
        Self::take(db_path, what, true)
    }

    /// Take the lock shared (any command that opens the hub). Fails only
    /// while an import holds it.
    pub fn acquire_shared(db_path: &Path, what: &str) -> anyhow::Result<HubLock> {
        Self::take(db_path, what, false)
    }

    fn take(db_path: &Path, what: &str, exclusive: bool) -> anyhow::Result<HubLock> {
        let path = lock_path(db_path);
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("opening lock file {}", path.display()))?;
        if !try_lock(&file, exclusive, &path)? {
            if exclusive {
                bail!(
                    "the database {} is in use by a running hub process (ua serve, ua mcp, ua call, ...) \
                     or another import: {what} refused. Stop them first, then retry",
                    db_path.display()
                );
            }
            bail!(
                "the database {} is being imported into: {what} refused until it finishes",
                db_path.display()
            );
        }
        Ok(HubLock { _file: file })
    }
}

/// The serve lock file for a database: `<canonical db>.serve.lock`, next to
/// the database file itself (symbolic links resolved).
pub fn serve_lock_path(db_path: &Path) -> anyhow::Result<PathBuf> {
    let db = canonical_db_path(db_path)?;
    let mut name = db.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".serve.lock");
    Ok(db.with_file_name(name))
}

/// What identifies "the same database": the database file's canonical path.
/// When the file does not exist yet, its directory (created if missing) is
/// canonicalized and the file name joined, so a first `ua serve` and a second
/// one started before the database is created still meet on one lock.
pub fn canonical_db_path(db_path: &Path) -> anyhow::Result<PathBuf> {
    if let Ok(p) = std::fs::canonicalize(db_path) {
        return Ok(p);
    }
    let name = db_path
        .file_name()
        .with_context(|| format!("database path {} has no file name", db_path.display()))?;
    let dir = match db_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        Some(d) => d.to_path_buf(),
        None => PathBuf::from("."),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let dir = std::fs::canonicalize(&dir).with_context(|| format!("resolving {}", dir.display()))?;
    Ok(dir.join(name))
}

/// The one-serving-process lock. `ua serve` takes it exclusively for the life
/// of the process, before it opens the database; the OS releases it when the
/// process exits or crashes.
#[derive(Debug)]
pub struct ServeLock {
    _file: File,
}

impl ServeLock {
    /// Take the serve lock, or fail naming the database and saying another
    /// `ua serve` holds it.
    pub fn acquire(db_path: &Path) -> anyhow::Result<ServeLock> {
        let db = canonical_db_path(db_path)?;
        let path = serve_lock_path(&db)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("opening lock file {}", path.display()))?;
        if !try_lock(&file, true, &path)? {
            bail!(
                "another `ua serve` holds the database {}: a second `ua serve` on the same database is refused \
                 (two would each take the other's in-flight inbound deliveries for stale ones). Stop the running \
                 `ua serve` first, or point this one at a different database",
                db.display()
            );
        }
        Ok(ServeLock { _file: file })
    }
}

#[cfg(unix)]
fn try_lock(file: &File, exclusive: bool, _path: &Path) -> anyhow::Result<bool> {
    use std::os::fd::AsRawFd;
    let mode = if exclusive { libc::LOCK_EX } else { libc::LOCK_SH };
    // SAFETY: `flock` on a descriptor owned by `file`, which outlives the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), mode | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(err).context("locking the database")
    }
}

#[cfg(not(unix))]
fn try_lock(_file: &File, exclusive: bool, path: &Path) -> anyhow::Result<bool> {
    // No advisory lock on this platform yet. Say so instead of pretending.
    if exclusive {
        eprintln!(
            "warning: database locking is not supported on this platform ({} is not locked); make sure no other \
             process that this lock guards against is running",
            path.display()
        );
    }
    Ok(true)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_held_lock_blocks_a_second_holder_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ua.db");
        let first = HubLock::acquire(&db, "import").unwrap();
        assert!(lock_path(&db).is_file());
        let err = HubLock::acquire(&db, "import").unwrap_err().to_string();
        assert!(err.contains("Stop them first"), "{err}");
        drop(first);
        HubLock::acquire(&db, "import").unwrap();
    }

    #[test]
    fn hub_processes_share_the_lock_and_block_an_import() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ua.db");
        let serve = HubLock::acquire_shared(&db, "serve").unwrap();
        let mcp = HubLock::acquire_shared(&db, "mcp").unwrap();
        let err = HubLock::acquire(&db, "import").unwrap_err().to_string();
        assert!(err.contains("Stop them first"), "{err}");
        drop(serve);
        assert!(HubLock::acquire(&db, "import").is_err(), "one hub process is still running");
        drop(mcp);
        let import = HubLock::acquire(&db, "import").unwrap();
        let err = HubLock::acquire_shared(&db, "serve").unwrap_err().to_string();
        assert!(err.contains("being imported"), "{err}");
        drop(import);
    }

    #[test]
    fn a_second_serve_is_refused_until_the_first_releases() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ua.db");
        let first = ServeLock::acquire(&db).unwrap();
        assert!(serve_lock_path(&db).unwrap().is_file());
        let err = ServeLock::acquire(&db).unwrap_err().to_string();
        assert!(err.contains("another `ua serve` holds the database"), "{err}");
        let canonical = std::fs::canonicalize(dir.path()).unwrap().join("ua.db");
        assert!(err.contains(&canonical.display().to_string()), "{err}");
        drop(first);
        ServeLock::acquire(&db).unwrap();
    }

    #[test]
    fn the_serve_lock_leaves_the_shared_hub_lock_alone() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ua.db");
        let _serve_shared = HubLock::acquire_shared(&db, "serve").unwrap();
        let _serve = ServeLock::acquire(&db).unwrap();
        // `ua mcp`, `ua call`, backups: shared, so they still run.
        HubLock::acquire_shared(&db, "mcp").unwrap();
        // An import or restore still refuses, on the shared lock as before.
        assert!(HubLock::acquire(&db, "restore").is_err());
    }

    #[test]
    fn the_same_database_by_another_path_shares_the_serve_lock() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Not created yet, reached through a directory link and a `..` hop.
        let _first = ServeLock::acquire(&real.join("ua.db")).unwrap();
        assert!(ServeLock::acquire(&link.join("ua.db")).is_err());
        assert!(ServeLock::acquire(&real.join("..").join("real").join("ua.db")).is_err());
        // A database file that is itself a link to the real one.
        std::fs::write(real.join("ua.db"), b"").unwrap();
        std::os::unix::fs::symlink(real.join("ua.db"), dir.path().join("alias.db")).unwrap();
        assert!(ServeLock::acquire(&dir.path().join("alias.db")).is_err());
    }

    #[test]
    fn serve_locks_are_per_database() {
        let dir = tempfile::tempdir().unwrap();
        let _a = ServeLock::acquire(&dir.path().join("a.db")).unwrap();
        ServeLock::acquire(&dir.path().join("b.db")).unwrap();
    }

    #[test]
    fn locks_are_per_database() {
        let dir = tempfile::tempdir().unwrap();
        let _a = HubLock::acquire(&dir.path().join("a.db"), "serve").unwrap();
        HubLock::acquire(&dir.path().join("b.db"), "serve").unwrap();
    }
}
