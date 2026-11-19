//! Connection management: one writer, a pool of readers.

use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use tokio::sync::broadcast;
use ua_core::{UaError, UaResult};

use crate::ledger::Event;
use crate::schema::{self, SchemaPart};

const READERS: usize = 4;

/// Shared handle to the database. Cheap to clone.
#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

struct Inner {
    path: Option<PathBuf>,
    writer: Mutex<Connection>,
    readers: Mutex<Vec<Connection>>,
    events: broadcast::Sender<Event>,
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
            let r = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_URI,
            )?;
            r.busy_timeout(std::time::Duration::from_secs(10))?;
            readers.push(r);
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
            inner: Arc::new(Inner { path, writer: Mutex::new(writer), readers: Mutex::new(readers), events }),
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

    /// Run `f` on a read connection.
    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> UaResult<T>) -> UaResult<T> {
        let pooled = {
            let mut pool =
                self.inner.readers.lock().map_err(|_| UaError::internal("reader pool poisoned"))?;
            pool.pop()
        };
        match pooled {
            Some(conn) => {
                let out = f(&conn);
                if let Ok(mut pool) = self.inner.readers.lock() {
                    pool.push(conn);
                }
                out
            }
            // In-memory, or every reader busy: fall back to the writer.
            None => {
                let conn = self.inner.writer.lock().map_err(|_| UaError::internal("writer lock poisoned"))?;
                f(&conn)
            }
        }
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
