//! Shared hub state handed to every tool.

use std::sync::{Arc, RwLock};

use ua_core::Config;
use ua_store::Db;

use crate::ci::{CiVerifier, GitHubCiVerifier};
use crate::families::github::credentials::{self, SharedWebhookRoutes};

/// Configuration, the database and the pluggable outside lookups. Cheap to clone.
#[derive(Clone)]
pub struct Hub {
    inner: Arc<HubInner>,
}

struct HubInner {
    cfg: Config,
    db: Db,
    ci: Arc<dyn CiVerifier>,
    /// GitHub webhook routes refused because their secret is shared
    /// ([`credentials::scan_shared_webhook_secrets`]); `None` when the last
    /// check failed, which refuses every route (fail closed).
    shared_webhook_routes: Arc<RwLock<Option<SharedWebhookRoutes>>>,
}

/// The environment variable that, set to `1`, opens a database written by a
/// newer build anyway (`--allow-newer-schema` on the command line).
pub const ALLOW_NEWER_SCHEMA_ENV: &str = "UA_ALLOW_NEWER_SCHEMA";

/// Open a hub database with the unknown-part fence: refuse a database that
/// records a part this build does not know ([`crate::known_schema_part_names`]),
/// unless `allow_newer`, which opens it and logs a warning naming the parts.
///
/// It also runs the migration guard ([`ua_store::Fence`]): an open that would
/// apply a part the database does not record yet is refused while another
/// process holds the database's serve lock. `serving` is the only way to skip
/// that: the caller's own held [`ua_store::ServeLock`] for this database.
pub fn open_db(
    path: &std::path::Path,
    parts: &[ua_store::Part],
    allow_newer: bool,
    serving: Option<&ua_store::ServeLock>,
) -> anyhow::Result<Db> {
    let known = crate::known_schema_part_names();
    let db = Db::open_with(path, parts, ua_store::Fence { also_known: &known, allow_newer, serving })?;
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
    /// A database written by a newer build is refused ([`open_db`]), and so is
    /// a migration (an open that would apply a part the database does not
    /// record yet) while another process holds the database's serve lock: a
    /// running `ua serve`. Every caller but the serving process uses this (or
    /// [`Hub::open_with`]); an open with nothing to apply is never refused by
    /// the guard.
    pub fn open(cfg: Config) -> anyhow::Result<Self> {
        Self::open_with(cfg, false)
    }

    /// [`Hub::open`], opening a database written by a newer build anyway when
    /// `allow_newer` (recovery only; logged). The migration guard still runs.
    pub fn open_with(cfg: Config, allow_newer: bool) -> anyhow::Result<Self> {
        let db = open_db(&cfg.db_path(), &crate::schema_parts(), allow_newer, None)?;
        Ok(Self::new(cfg, db))
    }

    /// The open for the process that serves the database (`ua serve`, or a
    /// program that embeds the server): `serving` is its held serve lock for
    /// this database, taken before the open, and is the only way to migrate
    /// without the migration guard's probe (which would see that same lock).
    /// A lock held for another database is no proof; the guard then runs as
    /// in [`Hub::open`]. A database written by a newer build is always refused.
    pub fn open_serving(cfg: Config, serving: &ua_store::ServeLock) -> anyhow::Result<Self> {
        let db = open_db(&cfg.db_path(), &crate::schema_parts(), false, Some(serving))?;
        Ok(Self::new(cfg, db))
    }

    /// An in-memory hub for tests.
    pub fn in_memory(cfg: Config) -> anyhow::Result<Self> {
        let db = Db::open_in_memory(&crate::schema_parts())?;
        Ok(Self::new(cfg, db))
    }

    /// A hub over `db`. Checks the GitHub webhook secrets for sharing first
    /// ([`Hub::shared_webhook_routes`]).
    pub fn new(cfg: Config, db: Db) -> Self {
        let ci = Arc::new(GitHubCiVerifier::new(cfg.clone(), db.clone()));
        let scan = db.read(|c| credentials::scan_shared_webhook_secrets(c, &cfg)).ok();
        credentials::log_shared_webhook_secrets(scan.as_ref());
        let shared_webhook_routes = Arc::new(RwLock::new(scan));
        Self { inner: Arc::new(HubInner { cfg, db, ci, shared_webhook_routes }) }
    }

    /// The same hub with another CI verifier (tests, or a forge client).
    pub fn with_ci_verifier(self, ci: Arc<dyn CiVerifier>) -> Self {
        let (cfg, db) = (self.inner.cfg.clone(), self.inner.db.clone());
        let shared_webhook_routes = self.inner.shared_webhook_routes.clone();
        Self { inner: Arc::new(HubInner { cfg, db, ci, shared_webhook_routes }) }
    }

    /// The GitHub webhook routes refused because another route shares
    /// their secret, by organization id (the default organization's stands
    /// for the bare route); `None` when the last check failed, and then
    /// every route is refused.
    pub fn shared_webhook_routes(&self) -> Option<SharedWebhookRoutes> {
        self.inner.shared_webhook_routes.read().map(|g| g.clone()).unwrap_or(None)
    }

    /// Whether organization `org`'s webhook route is refused for a shared
    /// secret (or because the last check failed).
    pub fn webhook_route_shared(&self, org: &str) -> bool {
        match self.inner.shared_webhook_routes.read() {
            Ok(g) => g.as_ref().is_none_or(|shared| shared.contains(org)),
            Err(_) => true,
        }
    }

    /// Check the GitHub webhook secrets for sharing again (after one is set
    /// or cleared, or by a test), log the outcome and keep it.
    pub async fn rescan_shared_webhook_secrets(&self) {
        let cfg = self.inner.cfg.clone();
        let scan =
            self.db().read_async(move |c| credentials::scan_shared_webhook_secrets(c, &cfg)).await.ok();
        credentials::log_shared_webhook_secrets(scan.as_ref());
        if let Ok(mut g) = self.inner.shared_webhook_routes.write() {
            *g = scan;
        }
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
