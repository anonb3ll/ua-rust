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

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};

/// The hub lock file for a database: `<db>.hub.lock` next to the database
/// file, for a path already resolved by [`canonical_db_path`].
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
        // Every spelling of one database meets on one lock file.
        let db = canonical_db_path(db_path)?;
        let path = lock_path(&db);
        let file = open_lock_file(&path)?;
        let unsupported = "an import or restore is NOT refused while a hub process runs, on this platform";
        if !try_lock(&file, exclusive, &path, unsupported)? {
            if exclusive {
                bail!(
                    "the database {} is in use by a running hub process (ua serve, ua mcp, ua call, ...) \
                     or another import: {what} refused. Stop them first, then retry",
                    db.display()
                );
            }
            bail!("the database {} is being imported into: {what} refused until it finishes", db.display());
        }
        Ok(HubLock { _file: file })
    }
}

/// The serve lock file for a database: `<canonical db>.serve.lock`, next to
/// the database file itself (see [`canonical_db_path`]).
pub fn serve_lock_path(db_path: &Path) -> anyhow::Result<PathBuf> {
    let db = canonical_db_path(db_path)?;
    let mut name = db.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".serve.lock");
    Ok(db.with_file_name(name))
}

/// How many symbolic links one path may pass through before it is refused
/// (the usual system limit).
const MAX_LINKS: usize = 40;

/// What identifies "the same database": the absolute path of the file SQLite
/// will open, with every symbolic link followed and `.` and `..` resolved,
/// including links whose target does not exist yet (a database not created
/// yet behind a link) and directories not created yet. Every spelling of one
/// database file therefore yields one path, before and after the file is
/// created. The longest existing prefix takes its on-disk spelling through
/// [`std::fs::canonicalize`], so on a file system that ignores letter case an
/// existing file or directory always yields one spelling; components that do
/// not exist yet are kept as written. Hard links are not resolved: two hard
/// links to one file are two paths (SQLite's WAL and lock files are per name,
/// so a database must never be used through two hard links anyway). Creates
/// nothing.
pub fn canonical_db_path(db_path: &Path) -> anyhow::Result<PathBuf> {
    let start = if db_path.is_absolute() {
        db_path.to_path_buf()
    } else {
        std::env::current_dir().context("reading the current directory")?.join(db_path)
    };
    let mut todo: VecDeque<OsString> = VecDeque::new();
    let mut resolved = PathBuf::new();
    push_components(&start, &mut resolved, &mut todo);
    let mut links = 0;
    while let Some(name) = todo.pop_front() {
        if name == ".." {
            resolved.pop();
            continue;
        }
        let candidate = resolved.join(&name);
        match std::fs::symlink_metadata(&candidate) {
            Ok(meta) if meta.file_type().is_symlink() => {
                links += 1;
                if links > MAX_LINKS {
                    bail!("database path {} passes through too many symbolic links", db_path.display());
                }
                let target = std::fs::read_link(&candidate)
                    .with_context(|| format!("reading the link {}", candidate.display()))?;
                // The link's target, then what was left after the link.
                let rest: Vec<OsString> = todo.drain(..).collect();
                if target.is_absolute() {
                    resolved = PathBuf::new();
                }
                push_components(&target, &mut resolved, &mut todo);
                todo.extend(rest);
            }
            Ok(_) => resolved = candidate,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => resolved = candidate,
            Err(e) => return Err(e).with_context(|| format!("resolving {}", candidate.display())),
        }
    }
    if resolved.file_name().is_none() {
        bail!("database path {} has no file name", db_path.display());
    }
    on_disk_spelling(&resolved)
}

/// The on-disk spelling of a resolved path: its longest existing prefix
/// through [`std::fs::canonicalize`] (which, on a file system that ignores
/// letter case, returns the case stored on disk), then the components that do
/// not exist yet, unchanged.
fn on_disk_spelling(resolved: &Path) -> anyhow::Result<PathBuf> {
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    let mut prefix = resolved;
    loop {
        if std::fs::symlink_metadata(prefix).is_ok() {
            let mut out =
                std::fs::canonicalize(prefix).with_context(|| format!("resolving {}", prefix.display()))?;
            out.extend(rest.iter().rev());
            return Ok(out);
        }
        match (prefix.parent(), prefix.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                prefix = parent;
            }
            // Nothing exists, not even the root: keep the resolution as is.
            _ => return Ok(resolved.to_path_buf()),
        }
    }
}

/// Queue `path`'s components: a root or prefix goes into `resolved` at once,
/// `.` is dropped, names and `..` are queued.
fn push_components(path: &Path, resolved: &mut PathBuf, todo: &mut VecDeque<OsString>) {
    for c in path.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => resolved.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => todo.push_back(OsString::from("..")),
            Component::Normal(n) => todo.push_back(n.to_os_string()),
        }
    }
}

/// Open (creating, owner-only on Unix) a lock file, creating its directory.
fn open_lock_file(path: &Path) -> anyhow::Result<File> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut opts = OpenOptions::new();
    opts.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Another account that could open the file could hold the lock.
        opts.mode(0o600);
    }
    let file = opts.open(path).with_context(|| format!("opening lock file {}", path.display()))?;
    #[cfg(unix)]
    {
        // `mode` applies only to a file this call creates: tighten an existing
        // wider one too. Best effort: a file another account owns cannot be
        // changed, and that must not fail the lock.
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = file.metadata()
            && meta.permissions().mode() & 0o077 != 0
        {
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
    }
    Ok(file)
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
        let file = open_lock_file(&path)?;
        let unsupported = "a second `ua serve` on the same database is NOT refused on this platform";
        if !try_lock(&file, true, &path, unsupported)? {
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

/// Refuse when another process holds the serve lock of `db_path`: a running
/// `ua serve`. Called by a command that is not the serving process before it
/// applies schema parts the database does not record yet (`pending`), so a
/// newer build never migrates the database underneath an older running serve.
///
/// The probe is a non-blocking shared `flock` on the serve lock file, released
/// at once; a missing lock file means no serve ever ran there. While it is
/// held (microseconds), a `ua serve` starting at that instant is refused as if
/// another serve held the database, and a serve that starts just after it is
/// not seen; that one opens the database after the migration (the migration
/// transaction is still open), so the fence, not this guard, decides whether
/// it may run. Not the serving process itself: `flock` locks belong to the
/// open file, so a process probing a lock it holds would see itself.
pub fn refuse_if_served(db_path: &Path, pending: &[String]) -> anyhow::Result<()> {
    let db = canonical_db_path(db_path)?;
    let path = serve_lock_path(&db)?;
    let file = match OpenOptions::new().read(true).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("opening lock file {}", path.display())),
    };
    let unsupported = "a running `ua serve` cannot be detected before a migration on this platform";
    if try_lock(&file, false, &path, unsupported)? {
        // Released when `file` drops, here.
        return Ok(());
    }
    bail!(
        "a running `ua serve` holds the database {}: this command would migrate it (apply the schema parts [{}]) \
         underneath that serve, which may be from a build that does not know them. Stop the running `ua serve`, \
         or upgrade it to this build, first; then retry",
        db.display(),
        pending.join(", ")
    )
}

#[cfg(unix)]
fn try_lock(file: &File, exclusive: bool, _path: &Path, _unsupported: &str) -> anyhow::Result<bool> {
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
fn try_lock(_file: &File, exclusive: bool, path: &Path, unsupported: &str) -> anyhow::Result<bool> {
    // No advisory lock on this platform yet. Say so instead of pretending.
    if exclusive {
        eprintln!(
            "warning: database locking is not supported on this platform ({} is not locked): {unsupported}",
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

    /// A relative spelling of `abs`, from the current directory.
    fn relative_to_cwd(abs: &Path) -> PathBuf {
        let cwd = std::env::current_dir().unwrap();
        let mut rel = PathBuf::new();
        for _ in cwd.components().skip(1) {
            rel.push("..");
        }
        rel.join(abs.strip_prefix("/").unwrap())
    }

    #[test]
    fn every_spelling_of_one_database_gives_one_lock_path() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let real_dir = root.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        let real = real_dir.join("ua.db");
        symlink(&real_dir, root.join("dirlink")).unwrap();
        // A link to the database file, which does not exist yet (dangling),
        // and one with a relative target.
        symlink(&real, root.join("dangling.db")).unwrap();
        symlink("real/ua.db", root.join("relative.db")).unwrap();
        // A chain of links.
        symlink(root.join("dangling.db"), root.join("chain.db")).unwrap();
        let spellings = |root: &Path| -> Vec<PathBuf> {
            vec![
                real.clone(),
                root.join("dirlink/ua.db"),
                root.join("dangling.db"),
                root.join("relative.db"),
                root.join("chain.db"),
                root.join("real/../real/./ua.db"),
                root.join("dirlink/../real/ua.db"),
                relative_to_cwd(&real),
            ]
        };
        let want_serve = real_dir.join("ua.db.serve.lock");
        let want_hub = real_dir.join("ua.db.hub.lock");
        // Before the database exists, then after.
        for created in [false, true] {
            if created {
                std::fs::write(&real, b"").unwrap();
            }
            for p in spellings(&root) {
                assert_eq!(canonical_db_path(&p).unwrap(), real, "{} (created={created})", p.display());
                assert_eq!(serve_lock_path(&p).unwrap(), want_serve, "{}", p.display());
                assert_eq!(lock_path(&canonical_db_path(&p).unwrap()), want_hub, "{}", p.display());
            }
        }
        // A database whose directory does not exist yet: nothing is created.
        let later = root.join("dirlink/not-yet/../not-yet/ua.db");
        assert_eq!(canonical_db_path(&later).unwrap(), real_dir.join("not-yet/ua.db"));
        assert!(!real_dir.join("not-yet").exists());
        // A link loop is refused, not followed forever.
        symlink(root.join("loop-b"), root.join("loop-a")).unwrap();
        symlink(root.join("loop-a"), root.join("loop-b")).unwrap();
        assert!(canonical_db_path(&root.join("loop-a")).is_err());
    }

    #[test]
    fn the_same_database_by_another_path_shares_both_locks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(real.join("ua.db"), dir.path().join("dangling.db")).unwrap();
        // The first serve reaches it through a dangling link; SQLite would
        // create the file at the target, so every later serve sees the target.
        let _first = ServeLock::acquire(&dir.path().join("dangling.db")).unwrap();
        std::fs::write(real.join("ua.db"), b"").unwrap();
        assert!(ServeLock::acquire(&real.join("ua.db")).is_err());
        assert!(ServeLock::acquire(&dir.path().join("dangling.db")).is_err());
        // A serve holds the hub lock shared; a restore by another spelling refuses.
        let _serving = HubLock::acquire_shared(&dir.path().join("dangling.db"), "serve").unwrap();
        assert!(HubLock::acquire(&real.join("ua.db"), "restore").is_err());
    }

    #[test]
    fn an_existing_prefix_takes_its_on_disk_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let real_dir = root.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, root.join("dirlink")).unwrap();
        // An existing directory reached through a link, plus names that do not exist yet.
        assert_eq!(
            on_disk_spelling(&root.join("dirlink/later/ua.db")).unwrap(),
            real_dir.join("later/ua.db")
        );
        assert_eq!(canonical_db_path(&root.join("dirlink/ua.db")).unwrap(), real_dir.join("ua.db"));
        // An existing file reached by two spellings: one path.
        std::fs::write(real_dir.join("ua.db"), b"").unwrap();
        let a = canonical_db_path(&root.join("dirlink/ua.db")).unwrap();
        let b = canonical_db_path(&root.join("real/./x/../ua.db")).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, real_dir.join("ua.db"));
    }

    #[test]
    fn spellings_that_differ_in_case_meet_on_a_case_insensitive_file_system() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("probe"), b"").unwrap();
        if std::fs::metadata(root.join("PROBE")).is_err() {
            eprintln!("skipped: the temporary directory {} is case-sensitive", root.display());
            return;
        }
        std::fs::create_dir_all(root.join("Hub")).unwrap();
        std::fs::write(root.join("Hub/ua.db"), b"").unwrap();
        let want = root.join("Hub/ua.db");
        for p in [root.join("hub/UA.db"), root.join("HUB/ua.DB"), root.join("Hub/ua.db")] {
            assert_eq!(canonical_db_path(&p).unwrap(), want, "{}", p.display());
            assert_eq!(serve_lock_path(&p).unwrap(), root.join("Hub/ua.db.serve.lock"));
        }
    }

    #[test]
    fn an_existing_wider_lock_file_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ua.db");
        for p in [lock_path(&db), serve_lock_path(&db).unwrap()] {
            std::fs::write(&p, b"").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let _hub = HubLock::acquire_shared(&db, "serve").unwrap();
        let _serve = ServeLock::acquire(&db).unwrap();
        for p in [lock_path(&db), serve_lock_path(&db).unwrap()] {
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "{}", p.display());
        }
    }

    #[test]
    fn a_migration_is_refused_while_a_serve_holds_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ua.db");
        let pending = vec!["new.v1".to_string()];
        // No serve ever ran: no lock file, nothing to refuse.
        refuse_if_served(&db, &pending).unwrap();
        assert!(!serve_lock_path(&db).unwrap().exists(), "the probe creates nothing");
        let serve = ServeLock::acquire(&db).unwrap();
        let err = refuse_if_served(&db, &pending).unwrap_err().to_string();
        assert!(err.contains("a running `ua serve` holds the database"), "{err}");
        assert!(err.contains("[new.v1]") && err.contains("Stop the running `ua serve`"), "{err}");
        drop(serve);
        refuse_if_served(&db, &pending).unwrap();
        // The probe released at once: a serve can start right after it.
        ServeLock::acquire(&db).unwrap();
    }

    #[test]
    fn lock_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ua.db");
        let _hub = HubLock::acquire_shared(&db, "serve").unwrap();
        let _serve = ServeLock::acquire(&db).unwrap();
        for p in [lock_path(&db), serve_lock_path(&db).unwrap()] {
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "{}", p.display());
        }
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
