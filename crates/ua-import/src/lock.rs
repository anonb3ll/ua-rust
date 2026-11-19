//! An advisory lock that says "a hub owns this database".
//!
//! `ua serve` holds an exclusive lock on a file next to the database for its
//! whole lifetime; an import takes the same lock, so it cannot start against a
//! live hub (and a hub cannot start in the middle of an import). The lock is
//! released by the OS when the holder exits, so a crash leaves nothing stale.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

/// The lock file for a database path: `<db>.hub.lock`.
pub fn lock_path(db_path: &Path) -> PathBuf {
    let mut name = db_path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".hub.lock");
    db_path.with_file_name(name)
}

/// An exclusive hold on a database. Dropping it (or exiting) releases it.
#[derive(Debug)]
pub struct HubLock {
    _file: File,
}

impl HubLock {
    /// Take the lock for `db_path`, or fail with advice to stop the hub.
    pub fn acquire(db_path: &Path, what: &str) -> anyhow::Result<HubLock> {
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
        if !try_lock_exclusive(&file)? {
            bail!(
                "the database {} is in use by a running hub (or another import): {what} refused. \
                 Stop the hub first, then retry",
                db_path.display()
            );
        }
        Ok(HubLock { _file: file })
    }
}

#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> anyhow::Result<bool> {
    use std::os::fd::AsRawFd;
    // SAFETY: `flock` on a descriptor owned by `file`, which outlives the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
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
fn try_lock_exclusive(_file: &File) -> anyhow::Result<bool> {
    // No advisory lock on this platform: the caller must stop the hub itself.
    Ok(true)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_held_lock_blocks_a_second_holder_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ua.db");
        let first = HubLock::acquire(&db, "serve").unwrap();
        assert!(lock_path(&db).is_file());
        let err = HubLock::acquire(&db, "import").unwrap_err().to_string();
        assert!(err.contains("Stop the hub first"), "{err}");
        drop(first);
        HubLock::acquire(&db, "import").unwrap();
    }

    #[test]
    fn locks_are_per_database() {
        let dir = tempfile::tempdir().unwrap();
        let _a = HubLock::acquire(&dir.path().join("a.db"), "serve").unwrap();
        HubLock::acquire(&dir.path().join("b.db"), "serve").unwrap();
    }
}
