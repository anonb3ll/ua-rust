//! Shared hub state handed to every tool.

use std::sync::Arc;

use ua_core::Config;
use ua_store::Db;

/// Configuration plus the database. Cheap to clone.
#[derive(Clone)]
pub struct Hub {
    inner: Arc<HubInner>,
}

struct HubInner {
    cfg: Config,
    db: Db,
}

impl Hub {
    /// Open the hub database described by `cfg`, applying every schema part.
    pub fn open(cfg: Config) -> anyhow::Result<Self> {
        let db = Db::open(&cfg.db_path(), &crate::schema_parts())?;
        Ok(Self::new(cfg, db))
    }

    /// An in-memory hub for tests.
    pub fn in_memory(cfg: Config) -> anyhow::Result<Self> {
        let db = Db::open_in_memory(&crate::schema_parts())?;
        Ok(Self::new(cfg, db))
    }

    pub fn new(cfg: Config, db: Db) -> Self {
        Self { inner: Arc::new(HubInner { cfg, db }) }
    }

    pub fn cfg(&self) -> &Config {
        &self.inner.cfg
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }
}
