//! An advisory lock that says "a hub is using this database".
//!
//! Every `ua` command that opens the hub (`serve`, `mcp`, `call`, `token`,
//! ...) holds a shared lock on a file next to the database for as long as it
//! runs, so they can run side by side. An import takes the lock exclusively:
//! it cannot start while any of them runs, and none can start during an
//! import. The OS releases the lock when the holder exits, so a crash leaves
//! nothing stale.

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
        if !try_lock(&file, exclusive)? {
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

#[cfg(unix)]
fn try_lock(file: &File, exclusive: bool) -> anyhow::Result<bool> {
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
fn try_lock(_file: &File, exclusive: bool) -> anyhow::Result<bool> {
    // No advisory lock on this platform yet. Say so instead of pretending.
    if exclusive {
        eprintln!(
            "warning: database locking is not supported on this platform; make sure no hub process is running"
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
    fn locks_are_per_database() {
        let dir = tempfile::tempdir().unwrap();
        let _a = HubLock::acquire(&dir.path().join("a.db"), "serve").unwrap();
        HubLock::acquire(&dir.path().join("b.db"), "serve").unwrap();
    }
}
