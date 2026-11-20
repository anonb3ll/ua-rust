//! Shared hub state handed to every tool.

use std::sync::Arc;

use ua_core::Config;
use ua_store::Db;

use crate::ci::{CiVerifier, GitHubCiVerifier};

/// Configuration, the database and the pluggable outside lookups. Cheap to clone.
#[derive(Clone)]
pub struct Hub {
    inner: Arc<HubInner>,
}

struct HubInner {
    cfg: Config,
    db: Db,
    ci: Arc<dyn CiVerifier>,
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
        Self { inner: Arc::new(HubInner { cfg, db, ci: Arc::new(GitHubCiVerifier) }) }
    }

    /// The same hub with another CI verifier (tests, or a forge client).
    pub fn with_ci_verifier(self, ci: Arc<dyn CiVerifier>) -> Self {
        let (cfg, db) = (self.inner.cfg.clone(), self.inner.db.clone());
        Self { inner: Arc::new(HubInner { cfg, db, ci }) }
    }

    /// The CI verifier task checks are graded with.
    pub fn ci(&self) -> &dyn CiVerifier {
        self.inner.ci.as_ref()
    }

    pub fn cfg(&self) -> &Config {
        &self.inner.cfg
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }
}
