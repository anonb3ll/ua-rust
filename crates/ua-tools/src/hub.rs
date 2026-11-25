//! Shared hub state handed to every tool.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

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
    webhook_scan: Arc<WebhookScan>,
    ledger_status: Arc<RwLock<Option<LedgerStatus>>>,
}

/// The outcome of the last full ledger verify in this process
/// ([`Hub::record_ledger_verify`]).
#[derive(Clone, Copy)]
struct LedgerStatus {
    at: Instant,
    ok: bool,
}

/// The GitHub webhook secret sharing check
/// ([`credentials::scan_shared_webhook_secrets`]) and its outcome.
struct WebhookScan {
    cfg: Config,
    db: Db,
    /// The routes refused because their secret is shared; `None` when the
    /// check has not run in this process (a hub that does not serve) or the
    /// last one failed, which refuses every route (fail closed).
    state: RwLock<Option<SharedWebhookRoutes>>,
    /// Whether this hub serves deliveries: only a serving hub checks at
    /// open and retries a failed check.
    serving: AtomicBool,
    /// Held across a check and the store of its outcome, so a check that
    /// started earlier never overwrites a later one's result.
    run: tokio::sync::Mutex<()>,
    /// Whether a retry task is running (at most one).
    retrying: AtomicBool,
    /// The retry's first delay and its cap, in milliseconds.
    retry_first_ms: AtomicU64,
    retry_cap_ms: AtomicU64,
}

/// A failed sharing check is retried after this long, doubling up to
/// [`WEBHOOK_SCAN_RETRY_CAP`], while the outcome is still a failure.
const WEBHOOK_SCAN_RETRY_FIRST: Duration = Duration::from_secs(1);
const WEBHOOK_SCAN_RETRY_CAP: Duration = Duration::from_secs(60);

impl WebhookScan {
    fn new(cfg: Config, db: Db) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            db,
            state: RwLock::new(None),
            serving: AtomicBool::new(false),
            run: tokio::sync::Mutex::new(()),
            retrying: AtomicBool::new(false),
            retry_first_ms: AtomicU64::new(WEBHOOK_SCAN_RETRY_FIRST.as_millis() as u64),
            retry_cap_ms: AtomicU64::new(WEBHOOK_SCAN_RETRY_CAP.as_millis() as u64),
        })
    }

    fn get(&self) -> Option<SharedWebhookRoutes> {
        self.state.read().map(|g| g.clone()).unwrap_or(None)
    }

    fn failed(&self) -> bool {
        self.state.read().map(|g| g.is_none()).unwrap_or(true)
    }

    fn store(&self, scan: Option<SharedWebhookRoutes>) {
        credentials::log_shared_webhook_secrets(scan.as_ref());
        if let Ok(mut g) = self.state.write() {
            *g = scan;
        }
    }

    /// The first check of a serving hub, at open (nothing else runs yet).
    fn start_serving(self: &Arc<Self>) {
        self.serving.store(true, Ordering::SeqCst);
        let cfg = self.cfg.clone();
        let scan = self.db.read(move |c| credentials::scan_shared_webhook_secrets(c, &cfg)).ok();
        self.store(scan);
        self.retry_if_failed();
    }

    /// Check, store the outcome and log it; `true` when the check failed.
    /// With `only_if_failed`, skip the check (`false`) when the outcome
    /// held once this check's turn comes is not a failure.
    async fn check(&self, only_if_failed: bool) -> bool {
        let _run = self.run.lock().await;
        if only_if_failed && !self.failed() {
            return false;
        }
        let cfg = self.cfg.clone();
        let scan = self.db.read_async(move |c| credentials::scan_shared_webhook_secrets(c, &cfg)).await.ok();
        let failed = scan.is_none();
        self.store(scan);
        failed
    }

    /// On a serving hub whose last check failed, start the retry task
    /// unless one runs. It checks again after a delay that doubles up to
    /// the cap, and ends as soon as the outcome is not a failure (its own
    /// check or another one), or when the hub is gone. Outside a Tokio
    /// runtime nothing retries (only a test builds a hub there).
    fn retry_if_failed(self: &Arc<Self>) {
        if !self.serving.load(Ordering::SeqCst) || !self.failed() {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        if self.retrying.swap(true, Ordering::SeqCst) {
            return;
        }
        let weak = Arc::downgrade(self);
        let mut delay = Duration::from_millis(self.retry_first_ms.load(Ordering::SeqCst));
        let cap = Duration::from_millis(self.retry_cap_ms.load(Ordering::SeqCst));
        rt.spawn(async move {
            loop {
                tokio::time::sleep(delay).await;
                let Some(scan) = weak.upgrade() else { return };
                if scan.check(true).await {
                    delay = (delay * 2).min(cap);
                    continue;
                }
                scan.retrying.store(false, Ordering::SeqCst);
                // A check that failed after ours succeeded saw this task
                // running and started none: keep going for it.
                if scan.failed() && !scan.retrying.swap(true, Ordering::SeqCst) {
                    continue;
                }
                return;
            }
        });
    }
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
    ///
    /// Only this open checks the GitHub webhook secrets for sharing
    /// ([`Hub::shared_webhook_routes`]), and retries a failed check in the
    /// background (from a Tokio runtime) until one succeeds.
    pub fn open_serving(cfg: Config, serving: &ua_store::ServeLock) -> anyhow::Result<Self> {
        let db = open_db(&cfg.db_path(), &crate::schema_parts(), false, Some(serving))?;
        Ok(Self::new(cfg, db).serving())
    }

    /// An in-memory hub for tests. It stands for a serving hub: it checks
    /// the webhook secrets for sharing, as [`Hub::open_serving`] does.
    pub fn in_memory(cfg: Config) -> anyhow::Result<Self> {
        let db = Db::open_in_memory(&crate::schema_parts())?;
        Ok(Self::new(cfg, db).serving())
    }

    /// A hub over `db`. It does not serve GitHub deliveries: its webhook
    /// sharing check has not run, so every webhook route is refused
    /// ([`Hub::webhook_route_shared`]).
    pub fn new(cfg: Config, db: Db) -> Self {
        let ci = Arc::new(GitHubCiVerifier::new(cfg.clone(), db.clone()));
        let webhook_scan = WebhookScan::new(cfg.clone(), db.clone());
        let ledger_status = Arc::new(RwLock::new(None));
        Self { inner: Arc::new(HubInner { cfg, db, ci, webhook_scan, ledger_status }) }
    }

    /// Mark this hub as the one serving deliveries: check the webhook
    /// secrets for sharing now and retry a failed check.
    fn serving(self) -> Self {
        self.inner.webhook_scan.start_serving();
        self
    }

    /// The same hub with another CI verifier (tests, or a forge client).
    pub fn with_ci_verifier(self, ci: Arc<dyn CiVerifier>) -> Self {
        let (cfg, db) = (self.inner.cfg.clone(), self.inner.db.clone());
        let webhook_scan = self.inner.webhook_scan.clone();
        let ledger_status = self.inner.ledger_status.clone();
        Self { inner: Arc::new(HubInner { cfg, db, ci, webhook_scan, ledger_status }) }
    }

    /// Keep the outcome of a full ledger verify (`ua_store::ledger::verify`)
    /// that just ran, for [`Hub::ledger_verified_within`].
    pub(crate) fn record_ledger_verify(&self, ok: bool) {
        if let Ok(mut g) = self.inner.ledger_status.write() {
            *g = Some(LedgerStatus { at: Instant::now(), ok });
        }
    }

    /// Whether the hub's ledger verified, from a full verify kept by
    /// [`Hub::record_ledger_verify`] no older than `max_age`; `None` when
    /// none was kept in this process or the kept one is older.
    pub(crate) fn ledger_verified_within(&self, max_age: Duration) -> Option<bool> {
        let g = self.inner.ledger_status.read().ok()?;
        g.filter(|s| s.at.elapsed() <= max_age).map(|s| s.ok)
    }

    /// The GitHub webhook routes refused because another route shares
    /// their secret, by organization id (the default organization's stands
    /// for the bare route); `None` when the check has not run in this
    /// process (a hub that does not serve) or the last one failed, and then
    /// every route is refused.
    pub fn shared_webhook_routes(&self) -> Option<SharedWebhookRoutes> {
        self.inner.webhook_scan.get()
    }

    /// [`Hub::shared_webhook_routes`] for a report: a hub that does not
    /// serve (a `ua call` from the command line) checks now instead, without
    /// keeping or logging the outcome. `None` when that check fails.
    pub async fn shared_webhook_routes_for_report(&self) -> Option<SharedWebhookRoutes> {
        let scan = &self.inner.webhook_scan;
        if scan.serving.load(Ordering::SeqCst) {
            return scan.get();
        }
        let cfg = self.inner.cfg.clone();
        self.db().read_async(move |c| credentials::scan_shared_webhook_secrets(c, &cfg)).await.ok()
    }

    /// Whether organization `org`'s webhook route is refused for a shared
    /// secret (or because the check has not succeeded).
    pub fn webhook_route_shared(&self, org: &str) -> bool {
        match self.inner.webhook_scan.state.read() {
            Ok(g) => g.as_ref().is_none_or(|shared| shared.contains(org)),
            Err(_) => true,
        }
    }

    /// Check the GitHub webhook secrets for sharing again (after one is set
    /// or cleared, or by a test), log the outcome and keep it. Checks run
    /// one at a time, so an earlier one never overwrites a later one's
    /// outcome. A failure on a serving hub starts the background retry.
    pub async fn rescan_shared_webhook_secrets(&self) {
        let scan = &self.inner.webhook_scan;
        if scan.check(false).await {
            scan.retry_if_failed();
        }
    }

    /// Shorten the background retry of a failed sharing check (tests).
    #[cfg(test)]
    pub(crate) fn set_webhook_scan_retry(&self, first: Duration, cap: Duration) {
        let scan = &self.inner.webhook_scan;
        scan.retry_first_ms.store(first.as_millis() as u64, Ordering::SeqCst);
        scan.retry_cap_ms.store(cap.as_millis() as u64, Ordering::SeqCst);
    }

    /// Whether the background retry of a failed sharing check runs (tests).
    #[cfg(test)]
    pub(crate) fn webhook_scan_retrying(&self) -> bool {
        self.inner.webhook_scan.retrying.load(Ordering::SeqCst)
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
