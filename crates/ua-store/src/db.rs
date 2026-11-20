//! Connection management: one writer, a pool of readers.
//!
//! A file database keeps [`READERS`] read-only connections. A read takes one
//! through an RAII guard ([`ReaderGuard`]), so a panicking closure still
//! returns it. When every pooled reader is busy, a read opens a short-lived
//! extra reader (at most [`OVERFLOW_READERS`] at once) and, past that, waits
//! for one to come back (up to [`READER_WAIT`]). A read never falls back to
//! the writer connection: reads must not queue behind, or hold up, writes.
//! An in-memory database (tests) has no readers and reads on the writer.

use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use tokio::sync::broadcast;
use ua_core::{UaError, UaResult};

use crate::ledger::Event;
use crate::schema::{self, SchemaPart};

/// Pooled read-only connections of a file database.
pub const READERS: usize = 4;
/// Extra read-only connections opened while every pooled reader is busy;
/// each is closed when its read ends.
pub const OVERFLOW_READERS: usize = 4;
/// How long a read waits for a reader once the pool and the overflow are
/// both in use, before it fails.
pub const READER_WAIT: Duration = Duration::from_secs(30);

/// Shared handle to the database. Cheap to clone.
#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

struct Inner {
    path: Option<PathBuf>,
    writer: Mutex<Connection>,
    readers: Mutex<Pool>,
    reader_free: Condvar,
    events: broadcast::Sender<Event>,
}

/// The idle pooled readers and the count of overflow readers open now.
struct Pool {
    idle: Vec<Connection>,
    overflow: usize,
}

/// Where a read connection came from, so it goes back to the right place.
enum Lease {
    Pooled(Connection),
    Overflow(Connection),
}

/// A read connection on loan from the pool. Dropping it (also during a
/// panic unwind) returns a pooled reader to the pool, or closes an overflow
/// reader and frees its slot, and wakes one waiting read.
pub struct ReaderGuard<'a> {
    inner: &'a Inner,
    lease: Option<Lease>,
}

impl Deref for ReaderGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        match self.lease.as_ref() {
            Some(Lease::Pooled(c) | Lease::Overflow(c)) => c,
            None => unreachable!("a reader guard holds its connection until dropped"),
        }
    }
}

impl Drop for ReaderGuard<'_> {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else { return };
        let mut pool = lock_pool(self.inner);
        match lease {
            Lease::Pooled(conn) => {
                // A closure that left a read transaction open (or panicked
                // inside one) must not hand a pinned snapshot to the next read.
                if conn.is_autocommit() || conn.execute_batch("ROLLBACK").is_ok() {
                    pool.idle.push(conn);
                } else if let Some(fresh) = self.inner.path.as_deref().and_then(|p| open_reader(p).ok()) {
                    pool.idle.push(fresh);
                }
            }
            Lease::Overflow(conn) => {
                pool.overflow = pool.overflow.saturating_sub(1);
                drop(conn);
            }
        }
        drop(pool);
        self.inner.reader_free.notify_one();
    }
}

/// The pool lock. A poisoned lock is recovered: the pool holds no invariant
/// a panic elsewhere could break (connections are moved in and out whole).
fn lock_pool(inner: &Inner) -> MutexGuard<'_, Pool> {
    inner.readers.lock().unwrap_or_else(|e| e.into_inner())
}

fn open_reader(path: &Path) -> rusqlite::Result<Connection> {
    let r = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI,
    )?;
    r.busy_timeout(std::time::Duration::from_secs(10))?;
    Ok(r)
}

fn configure(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA temp_store = MEMORY;",
    )
}

impl Db {
    /// Open (creating if needed) the database at `path` and apply `parts`.
    pub fn open(path: &Path, parts: &[SchemaPart]) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut writer = Connection::open(path)?;
        configure(&writer)?;
        schema::apply(&mut writer, parts)?;
        let mut readers = Vec::with_capacity(READERS);
        for _ in 0..READERS {
            readers.push(open_reader(path)?);
        }
        Ok(Self::from_parts(Some(path.to_path_buf()), writer, readers))
    }

    /// An in-memory database (tests). Reads share the writer connection.
    pub fn open_in_memory(parts: &[SchemaPart]) -> anyhow::Result<Self> {
        let mut writer = Connection::open_in_memory()?;
        writer.execute_batch("PRAGMA foreign_keys = ON;")?;
        schema::apply(&mut writer, parts)?;
        Ok(Self::from_parts(None, writer, Vec::new()))
    }

    fn from_parts(path: Option<PathBuf>, writer: Connection, readers: Vec<Connection>) -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            inner: Arc::new(Inner {
                path,
                writer: Mutex::new(writer),
                readers: Mutex::new(Pool { idle: readers, overflow: 0 }),
                reader_free: Condvar::new(),
                events,
            }),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.inner.path.as_deref()
    }

    /// Subscribe to events committed from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    /// Run `f` in a `BEGIN IMMEDIATE` transaction on the writer. Commits when
    /// `f` returns `Ok`, rolls back otherwise. Ledger events appended inside
    /// are broadcast to subscribers only after the commit succeeds.
    pub fn write<T>(&self, f: impl FnOnce(&mut WriteTx<'_>) -> UaResult<T>) -> UaResult<T> {
        let (out, pending) = {
            let mut conn = self.inner.writer.lock().map_err(|_| UaError::internal("writer lock poisoned"))?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut wtx = WriteTx { tx, pending: Vec::new() };
            let out = f(&mut wtx)?;
            let WriteTx { tx, pending } = wtx;
            tx.commit()?;
            (out, pending)
        };
        for ev in pending {
            let _ = self.inner.events.send(ev);
        }
        Ok(out)
    }

    /// Run `f` on a read connection. Blocking: from async code use
    /// [`Db::read_async`].
    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> UaResult<T>) -> UaResult<T> {
        // An in-memory database has one connection: read on the writer.
        if self.inner.path.is_none() {
            let conn = self.inner.writer.lock().map_err(|_| UaError::internal("writer lock poisoned"))?;
            return f(&conn);
        }
        let guard = self.reader()?;
        f(&guard)
    }

    /// Take a read connection of a file database: an idle pooled reader, else
    /// a new overflow reader while fewer than [`OVERFLOW_READERS`] are open,
    /// else wait up to [`READER_WAIT`] for either.
    fn reader(&self) -> UaResult<ReaderGuard<'_>> {
        let inner = &*self.inner;
        let path = inner.path.as_deref().ok_or_else(|| UaError::internal("no reader pool in memory"))?;
        let deadline = std::time::Instant::now() + READER_WAIT;
        let mut pool = lock_pool(inner);
        loop {
            if let Some(conn) = pool.idle.pop() {
                return Ok(ReaderGuard { inner, lease: Some(Lease::Pooled(conn)) });
            }
            if pool.overflow < OVERFLOW_READERS {
                // Reserve the slot before opening, outside the lock.
                pool.overflow += 1;
                drop(pool);
                return match open_reader(path) {
                    Ok(conn) => Ok(ReaderGuard { inner, lease: Some(Lease::Overflow(conn)) }),
                    Err(e) => {
                        lock_pool(inner).overflow -= 1;
                        inner.reader_free.notify_one();
                        Err(e.into())
                    }
                };
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err(UaError::internal(format!(
                    "no database reader came free within {}s",
                    READER_WAIT.as_secs()
                )));
            }
            pool = inner.reader_free.wait_timeout(pool, left).unwrap_or_else(|e| e.into_inner()).0;
        }
    }

    /// Checkpoint the WAL into the main database file and truncate it
    /// (`PRAGMA wal_checkpoint(TRUNCATE)`), as a clean shutdown does. Returns
    /// `(busy, wal_frames, checkpointed_frames)`; `busy` is true when a
    /// reader kept the checkpoint from completing. A no-op in memory.
    pub fn checkpoint_truncate(&self) -> UaResult<(bool, i64, i64)> {
        if self.inner.path.is_none() {
            return Ok((false, 0, 0));
        }
        let conn = self.inner.writer.lock().map_err(|_| UaError::internal("writer lock poisoned"))?;
        let (busy, log, done): (i64, i64, i64) =
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok((busy != 0, log, done))
    }

    /// Async wrapper around [`Db::write`] for use from tokio tasks.
    pub async fn write_async<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut WriteTx<'_>) -> UaResult<T> + Send + 'static,
    ) -> UaResult<T> {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.write(f))
            .await
            .map_err(|e| UaError::internal(format!("blocking task failed: {e}")))?
    }

    /// Async wrapper around [`Db::read`].
    pub async fn read_async<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Connection) -> UaResult<T> + Send + 'static,
    ) -> UaResult<T> {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.read(f))
            .await
            .map_err(|e| UaError::internal(format!("blocking task failed: {e}")))?
    }
}

/// A write transaction plus the ledger events it will publish on commit.
pub struct WriteTx<'c> {
    tx: Transaction<'c>,
    pub(crate) pending: Vec<Event>,
}

impl<'c> Deref for WriteTx<'c> {
    type Target = Transaction<'c>;
    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl DerefMut for WriteTx<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::time::Instant;

    use super::*;

    const PART: SchemaPart =
        SchemaPart { name: "pool_test.v1", sql: "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT);" };

    fn file_db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("hub.db"), &[PART]).unwrap();
        (dir, db)
    }

    fn idle(db: &Db) -> usize {
        lock_pool(&db.inner).idle.len()
    }

    fn overflow(db: &Db) -> usize {
        lock_pool(&db.inner).overflow
    }

    #[test]
    fn a_panicking_read_returns_its_reader() {
        let (_dir, db) = file_db();
        for _ in 0..(READERS * 3) {
            let d = db.clone();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                d.read::<()>(|_| panic!("boom")).unwrap();
            }));
            assert!(r.is_err());
        }
        assert_eq!(idle(&db), READERS, "every pooled reader came back");
        assert_eq!(overflow(&db), 0);
        // The pool still serves reads.
        let n: i64 = db.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?)).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn a_read_left_in_a_transaction_does_not_pin_the_next_reads_snapshot() {
        let (_dir, db) = file_db();
        // Hold every reader inside an open read transaction, then release.
        let barrier = Arc::new(Barrier::new(READERS + 1));
        let threads: Vec<_> = (0..READERS)
            .map(|_| {
                let (db, b) = (db.clone(), barrier.clone());
                std::thread::spawn(move || {
                    db.read(|c| {
                        c.execute_batch("BEGIN; SELECT COUNT(*) FROM t;")?;
                        b.wait();
                        Ok(())
                    })
                    .unwrap()
                })
            })
            .collect();
        barrier.wait();
        threads.into_iter().for_each(|t| t.join().unwrap());
        db.write(|tx| {
            tx.execute("INSERT INTO t (v) VALUES ('x')", [])?;
            Ok(())
        })
        .unwrap();
        for _ in 0..READERS {
            let n: i64 = db.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?)).unwrap();
            assert_eq!(n, 1, "a reader returned in a transaction would still see 0 rows");
        }
    }

    /// More concurrent reads than pooled readers: none of them takes the
    /// writer, so a write commits while every read is still in flight, and
    /// the reads beyond pool plus overflow wait instead of failing.
    #[test]
    fn concurrent_reads_beyond_the_pool_never_block_the_writer() {
        let (_dir, db) = file_db();
        let readers = READERS + OVERFLOW_READERS + 4;
        let hold = Duration::from_millis(400);
        let started = Arc::new(Barrier::new(READERS + OVERFLOW_READERS + 1));
        let threads: Vec<_> = (0..readers)
            .map(|i| {
                let (db, started) = (db.clone(), started.clone());
                std::thread::spawn(move || {
                    db.read(|c| {
                        let n: i64 = c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?;
                        if i < READERS + OVERFLOW_READERS {
                            started.wait();
                        }
                        std::thread::sleep(hold);
                        Ok(n)
                    })
                })
            })
            .collect();
        // Wait until pool and overflow are all lent out.
        started.wait();
        assert_eq!(idle(&db), 0);
        assert_eq!(overflow(&db), OVERFLOW_READERS);
        let t0 = Instant::now();
        db.write(|tx| {
            tx.execute("INSERT INTO t (v) VALUES ('w')", [])?;
            Ok(())
        })
        .unwrap();
        let write_took = t0.elapsed();
        assert!(write_took < hold / 2, "the write waited {write_took:?} behind reads");
        for t in threads {
            t.join().unwrap().unwrap();
        }
        assert_eq!(idle(&db), READERS);
        assert_eq!(overflow(&db), 0, "overflow readers are closed after use");
    }

    #[test]
    fn checkpoint_truncate_empties_the_wal() {
        let (dir, db) = file_db();
        for i in 0..50 {
            db.write(|tx| {
                tx.execute("INSERT INTO t (v) VALUES (?1)", [i.to_string()])?;
                Ok(())
            })
            .unwrap();
        }
        let wal = dir.path().join("hub.db-wal");
        assert!(std::fs::metadata(&wal).unwrap().len() > 0);
        let (busy, _, _) = db.checkpoint_truncate().unwrap();
        assert!(!busy);
        assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
        // In memory there is nothing to checkpoint.
        let mem = Db::open_in_memory(&[PART]).unwrap();
        assert_eq!(mem.checkpoint_truncate().unwrap(), (false, 0, 0));
    }
}
