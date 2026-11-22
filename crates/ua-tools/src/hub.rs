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

/// The environment variable that, set to `1`, opens a database written by a
/// newer build anyway (`--allow-newer-schema` on the command line).
pub const ALLOW_NEWER_SCHEMA_ENV: &str = "UA_ALLOW_NEWER_SCHEMA";

/// Open a hub database with the unknown-part fence: refuse a database that
/// records a part this build does not know ([`crate::known_schema_part_names`]),
/// unless `allow_newer`, which opens it and logs a warning naming the parts.
pub fn open_db(path: &std::path::Path, parts: &[ua_store::Part], allow_newer: bool) -> anyhow::Result<Db> {
    let known = crate::known_schema_part_names();
    let db = Db::open_with(path, parts, ua_store::Fence { also_known: &known, allow_newer })?;
    let ignored = db.ignored_newer_parts();
    if !ignored.is_empty() {
        tracing::warn!(
            db = %path.display(),
            unknown_parts = %ignored.join(", "),
            "OPENING A DATABASE WRITTEN BY A NEWER BUILD (--allow-newer-schema / {ALLOW_NEWER_SCHEMA_ENV}): this \
             build ignores what those parts changed. For the inbound-delivery table that reopens a replay window: \
             copies of GitHub and Slack deliveries the newer build handled are accepted again (up to 30 days for \
             GitHub, about a day for Slack). Use it to recover, not to serve; run the newer build or restore a \
             backup taken before the upgrade"
        );
    } else if allow_newer {
        tracing::warn!(
            db = %path.display(),
            "--allow-newer-schema / {ALLOW_NEWER_SCHEMA_ENV} is set, but this database records no part this build \
             does not know; unset it"
        );
    }
    Ok(db)
}

impl Hub {
    /// Open the hub database described by `cfg`, applying every schema part.
    /// A database written by a newer build is refused ([`open_db`]).
    pub fn open(cfg: Config) -> anyhow::Result<Self> {
        Self::open_with(cfg, false)
    }

    /// [`Hub::open`], opening a database written by a newer build anyway when
    /// `allow_newer` (recovery only; logged).
    pub fn open_with(cfg: Config, allow_newer: bool) -> anyhow::Result<Self> {
        let db = open_db(&cfg.db_path(), &crate::schema_parts(), allow_newer)?;
        Ok(Self::new(cfg, db))
    }

    /// An in-memory hub for tests.
    pub fn in_memory(cfg: Config) -> anyhow::Result<Self> {
        let db = Db::open_in_memory(&crate::schema_parts())?;
        Ok(Self::new(cfg, db))
    }

    pub fn new(cfg: Config, db: Db) -> Self {
        let ci = Arc::new(GitHubCiVerifier::new(cfg.clone(), db.clone()));
        Self { inner: Arc::new(HubInner { cfg, db, ci }) }
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
