//! `ua doctor`: read-only health, ownership, permission, security, schema, and ledger checks.
//!
//! Never creates a missing database, never runs migrations, and never holds a
//! write lock on the hub database.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use ua_core::Config;

use super::expand_tilde;

const WAL_WARN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Args)]
pub struct DoctorArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Treat warnings (`warn`) as failures for CI/ops scripts.
    #[arg(long)]
    pub strict: bool,
    /// Allow a non-loopback `bind` (for example `0.0.0.0:8765` in Docker) as long
    /// as `enforce_auth` is enabled.
    #[arg(long)]
    pub allow_non_loopback: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub strict: bool,
    pub summary: DoctorSummary,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorSummary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
}

fn check(name: &str, status: Status, detail: impl Into<String>) -> CheckResult {
    CheckResult { name: name.to_string(), status, detail: detail.into() }
}

fn resolved_config_path(cfg: &Config, explicit_config: Option<&Path>) -> PathBuf {
    explicit_config
        .map(expand_tilde)
        .or_else(|| std::env::var_os("UA_CONFIG").map(PathBuf::from).map(|p| expand_tilde(&p)))
        .unwrap_or_else(|| cfg.home.join("config.toml"))
}

fn check_owner(cfg: &Config) -> CheckResult {
    match ua_store::backup::check_dir_owner(&cfg.home) {
        Ok(()) => check("owner", Status::Pass, "effective uid owns UA_HOME (or UA_HOME not created yet)"),
        Err(e) => check("owner", Status::Fail, e.to_string()),
    }
}

fn check_permissions(cfg: &Config, explicit_config: Option<&Path>) -> CheckResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !cfg.home.exists() {
            return check(
                "permissions",
                Status::Warn,
                format!("home directory {} does not exist yet (run `ua init`)", cfg.home.display()),
            );
        }
        let mut exposed = Vec::new();
        let db_path = cfg.db_path();
        let config_path = resolved_config_path(cfg, explicit_config);
        let to_check: [(&str, &Path); 3] = [("home", &cfg.home), ("config", &config_path), ("db", &db_path)];
        for (label, path) in to_check {
            if let Ok(meta) = fs::symlink_metadata(path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    exposed.push(format!("{label} {} has mode {:03o}", path.display(), mode));
                }
            }
        }
        if exposed.is_empty() {
            check(
                "permissions",
                Status::Pass,
                "home directory, config, and database permissions are owner-only (0700/0600)",
            )
        } else {
            check(
                "permissions",
                Status::Warn,
                format!(
                    "{}; recommend chmod 700 on home and 600 on database/config files",
                    exposed.join("; ")
                ),
            )
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (cfg, explicit_config);
        check("permissions", Status::Pass, "unix mode check not applicable on this platform")
    }
}

fn open_ro(db_path: &Path) -> anyhow::Result<Connection> {
    let abs = ua_store::backup::absolutize(db_path)?;
    let conn = Connection::open_with_flags(
        &abs,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA query_only = ON;")?;
    Ok(conn)
}

fn count_active_tokens_ro(db_path: &Path) -> anyhow::Result<Option<i64>> {
    if !db_path.is_file() {
        return Ok(None);
    }
    let conn = open_ro(db_path)?;
    let exists: bool = conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name='agent_tokens'", [], |_| Ok(true))
        .unwrap_or(false);
    if !exists {
        return Ok(None);
    }
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM agent_tokens WHERE status = 'active'", [], |r| r.get(0))?;
    Ok(Some(count))
}

fn check_auth_lockout(cfg: &Config) -> CheckResult {
    if !cfg.enforce_auth {
        return check(
            "auth_lockout",
            Status::Warn,
            "enforce_auth is false; HTTP routes accept unauthenticated requests",
        );
    }
    let static_count = cfg.static_tokens().len();
    if static_count > 0 {
        return check(
            "auth_lockout",
            Status::Pass,
            format!("enforce_auth is enabled with {static_count} static token(s)"),
        );
    }
    let db_path = cfg.db_path();
    match count_active_tokens_ro(&db_path) {
        Ok(Some(n)) if n > 0 => check(
            "auth_lockout",
            Status::Pass,
            format!("enforce_auth is enabled with {n} active issued token(s)"),
        ),
        Ok(Some(0)) => check(
            "auth_lockout",
            Status::Warn,
            "enforce_auth is enabled, static tokens = 0, active DB tokens = 0; run `ua token issue <label>`",
        ),
        Ok(Some(_)) | Ok(None) => check(
            "auth_lockout",
            Status::Warn,
            "enforce_auth is enabled, static tokens = 0, and no agent_tokens table exists yet; run `ua token issue <label>`",
        ),
        Err(e) => check("auth_lockout", Status::Fail, format!("could not inspect agent_tokens: {e}")),
    }
}

fn check_origin_security(cfg: &Config, allow_non_loopback: bool) -> CheckResult {
    let non_loopback = !cfg.bind.ip().is_loopback();
    if non_loopback && !cfg.enforce_auth {
        return check(
            "origin_security",
            Status::Fail,
            format!(
                "bind {} is non-loopback while enforce_auth is false: anyone who can reach it can call every \
                 tool and read every mailbox and conversation",
                cfg.bind
            ),
        );
    }
    if let Some(warning) = ua_server::login::insecure_origin_warning(cfg) {
        return check("origin_security", Status::Warn, warning);
    }
    if non_loopback && !allow_non_loopback {
        return check(
            "origin_security",
            Status::Warn,
            format!("bind {} is non-loopback; prefer 127.0.0.1 behind a TLS reverse proxy", cfg.bind),
        );
    }
    check(
        "origin_security",
        Status::Pass,
        format!("bind {} and origin settings ({}) valid", cfg.bind, cfg.public_base_url()),
    )
}

fn check_policy(cfg: &Config) -> CheckResult {
    let Some(path) = &cfg.policy_file else {
        return check("policy_file", Status::Pass, "no policy_file configured (default allow policy)");
    };
    let exists = path.exists();
    match ua_tools::policy::load(path) {
        Ok(_) if !exists => check(
            "policy_file",
            Status::Warn,
            format!("configured policy_file {} does not exist yet (empty allow policy)", path.display()),
        ),
        Ok(policy) => check(
            "policy_file",
            Status::Pass,
            format!(
                "{} loaded ({} rule(s), enabled={}, default_action={})",
                path.display(),
                policy.rules.len(),
                policy.enabled,
                if policy.default_deny { "deny" } else { "allow" }
            ),
        ),
        Err(e) => check("policy_file", Status::Fail, format!("{} failed validation: {e}", path.display())),
    }
}

fn check_schema(db_path: &Path) -> CheckResult {
    if !db_path.is_file() {
        return check("schema", Status::Warn, "database does not exist yet");
    }
    let expected = ua_tools::schema_parts();
    let conn = match open_ro(db_path) {
        Ok(c) => c,
        Err(e) => {
            return check("schema", Status::Fail, format!("could not open database for schema check: {e}"));
        }
    };
    match ua_store::backup::check_schema_compatibility(&conn, &expected, &ua_tools::optional_schema_parts()) {
        // The unknown-part fence first: serving and writing commands refuse this
        // database (docs/operations.md, "Older builds and a newer database"). A
        // newer part may well add objects on known tables, so the object
        // findings follow this explanation instead of replacing it.
        Ok(c) if !c.extra.is_empty() => {
            let mut detail = format!(
                "written by a newer build: extra=[{}] are schema parts this build does not know, so ua serve, \
                 ua mcp, ua call and the other writing commands refuse this database (override for recovery, \
                 never for ua serve: --allow-newer-schema or UA_ALLOW_NEWER_SCHEMA=1); run the newer build, or \
                 restore a backup taken before the upgrade; missing=[{}]",
                c.extra.join(", "),
                c.missing.join(", ")
            );
            if c.has_tampering_or_unowned_objects() {
                detail.push_str("; objects this build does not expect (the newer parts may explain them): ");
                detail.push_str(&object_findings(&c));
            }
            check("schema", Status::Fail, detail)
        }
        Ok(c) if c.has_tampering_or_unowned_objects() => check("schema", Status::Fail, object_findings(&c)),
        Ok(c) if !c.missing.is_empty() => check(
            "schema",
            Status::Warn,
            format!("missing=[{}], extra=[{}]", c.missing.join(", "), c.extra.join(", ")),
        ),
        Ok(_) => check("schema", Status::Pass, format!("all {} expected schema parts match", expected.len())),
        Err(e) => check("schema", Status::Fail, format!("schema check failed: {e}")),
    }
}

/// The object-level findings of a schema check, one `name=[...]` per kind.
fn object_findings(c: &ua_store::backup::SchemaCompatibility) -> String {
    let mut parts = vec![format!(
        "drifted=[{}], missing_objects=[{}], modified_objects=[{}], \
         unexpected_tables=[{}], unexpected_indexes=[{}], unexpected_triggers=[{}]",
        c.drifted.join(", "),
        c.missing_objects.join(", "),
        c.modified_objects.join(", "),
        c.unexpected_tables.join(", "),
        c.unexpected_indexes.join(", "),
        c.unexpected_triggers.join(", "),
    )];
    if let Some(ref err) = c.reference_error {
        parts.push(format!("reference_error=[{err}]"));
    }
    if !c.conflicting_objects.is_empty() {
        parts.push(format!("conflicting_objects=[{}]", c.conflicting_objects.join(", ")));
    }
    if !c.unexpected_indexes_on_known_tables.is_empty() {
        parts.push(format!(
            "unexpected_indexes_on_known_tables=[{}]",
            c.unexpected_indexes_on_known_tables.join(", ")
        ));
    }
    if !c.reserved_name_objects.is_empty() {
        parts.push(format!("reserved_name_objects=[{}]", c.reserved_name_objects.join(", ")));
    }
    if !c.unexpected_foreign_keys_to_known_tables.is_empty() {
        parts.push(format!(
            "unexpected_foreign_keys_to_known_tables=[{}]",
            c.unexpected_foreign_keys_to_known_tables.join(", ")
        ));
    }
    parts.join(", ")
}

fn check_restore_staging(db_path: &Path) -> CheckResult {
    let Some(parent) = db_path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return check("restore_staging", Status::Pass, "no leftover restore staging directories");
    };
    if !parent.is_dir() {
        return check("restore_staging", Status::Pass, "home directory not initialized yet");
    }
    let prefix = format!(".{}.restore", db_path.file_name().and_then(|s| s.to_str()).unwrap_or("ua.db"));
    let mut found = Vec::new();
    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.starts_with(&prefix) && entry.path().is_dir() {
                found.push(entry.path().display().to_string());
            }
        }
    }
    found.sort();
    if found.is_empty() {
        check("restore_staging", Status::Pass, "no leftover restore staging directories")
    } else {
        check(
            "restore_staging",
            Status::Warn,
            format!(
                "{} leftover restore staging dir(s) present ({}); inspect rollback/ before removing",
                found.len(),
                found.join(", ")
            ),
        )
    }
}

fn check_pre_restore_backups(db_path: &Path) -> CheckResult {
    let Some(parent) = db_path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return check("pre_restore_backups", Status::Pass, "no pre-restore recovery files");
    };
    if !parent.is_dir() {
        return check("pre_restore_backups", Status::Pass, "home directory not initialized yet");
    }
    let prefix = format!("{}.pre-restore-", db_path.file_name().and_then(|s| s.to_str()).unwrap_or("ua.db"));
    let mut found = Vec::new();
    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(&prefix) {
                found.push(entry.path().display().to_string());
            }
        }
    }
    found.sort();
    if found.is_empty() {
        check("pre_restore_backups", Status::Pass, "no leftover pre-restore recovery backups")
    } else {
        check(
            "pre_restore_backups",
            Status::Warn,
            format!(
                "{} pre-restore recovery file(s) present ({}); prune once the restored DB is verified",
                found.len(),
                found.join(", ")
            ),
        )
    }
}

pub fn run(args: DoctorArgs, explicit_config: Option<&Path>) -> anyhow::Result<ExitCode> {
    let mut checks = Vec::new();

    match crate::load_config(explicit_config) {
        Ok(cfg) => {
            let db_path = cfg.db_path();
            checks.push(check_owner(&cfg));
            checks.push(check(
                "config",
                Status::Pass,
                format!(
                    "home={}, db={}, bind={}, enforce_auth={}",
                    cfg.home.display(),
                    db_path.display(),
                    cfg.bind,
                    cfg.enforce_auth
                ),
            ));
            checks.push(check_permissions(&cfg, explicit_config));
            checks.push(check_auth_lockout(&cfg));
            checks.push(check_origin_security(&cfg, args.allow_non_loopback));
            checks.push(match ua_tools::families::workspace::cargo_config_warning(&cfg) {
                Some(w) => check("cargo_config", Status::Warn, w),
                None => check("cargo_config", Status::Pass, "no untrusted ancestor cargo config found"),
            });
            checks.push(check_policy(&cfg));

            match ua_store::backup::check_database(&db_path) {
                Ok(h) if !h.exists => {
                    checks.push(check(
                        "database",
                        Status::Warn,
                        format!(
                            "database {} does not exist yet (created on first `ua serve` or `ua init --agent`)",
                            db_path.display()
                        ),
                    ));
                    checks.push(check("schema", Status::Warn, "database does not exist yet"));
                    checks.push(check("ledger", Status::Warn, "database does not exist yet"));
                }
                Ok(h) => {
                    let wal = h.wal_bytes.unwrap_or(0);
                    let qc = h.quick_check.as_deref().unwrap_or("unknown");
                    let fk = h.foreign_key_violations.unwrap_or(0);
                    let jm = h.journal_mode.as_deref().unwrap_or("unknown");
                    let db_status = if qc != "ok" || fk > 0 {
                        Status::Fail
                    } else if !jm.eq_ignore_ascii_case("wal") || wal > WAL_WARN_BYTES {
                        Status::Warn
                    } else {
                        Status::Pass
                    };
                    checks.push(check(
                        "database",
                        db_status,
                        format!(
                            "bytes={}, wal_bytes={}, journal_mode={jm}, quick_check={qc}, fk_violations={fk}, schema_parts={}",
                            h.bytes.unwrap_or(0),
                            wal,
                            h.schema_parts.unwrap_or(0)
                        ),
                    ));
                    checks.push(check_schema(&db_path));
                    checks.push(match h.ledger {
                        None => check("ledger", Status::Fail, "database is missing the event_log table"),
                        Some(l) if l.ok => check(
                            "ledger",
                            Status::Pass,
                            format!(
                                "verified {} hashed entry/entries (unhashed_legacy_prefix={})",
                                l.checked, l.unhashed_legacy_prefix
                            ),
                        ),
                        Some(l) => check(
                            "ledger",
                            Status::Fail,
                            format!(
                                "verification failed at seq {:?}: {}",
                                l.first_bad_seq,
                                l.reason.as_deref().unwrap_or("unknown error")
                            ),
                        ),
                    });
                }
                Err(e) => {
                    checks.push(check("database", Status::Fail, format!("database probe failed: {e}")));
                    checks.push(check("schema", Status::Fail, "skipped because database probe failed"));
                    checks.push(check("ledger", Status::Fail, "skipped because database probe failed"));
                }
            }
            checks.push(check_pre_restore_backups(&db_path));
            checks.push(check_restore_staging(&db_path));
        }
        Err(e) => {
            checks.push(check("config", Status::Fail, format!("configuration failed to load: {e}")));
        }
    }

    let tool_count = ua_tools::builtin_registry_shared().all().count();
    checks.push(check("registry", Status::Pass, format!("{tool_count} built-in tool(s) registered")));

    let pass = checks.iter().filter(|c| c.status == Status::Pass).count();
    let warn = checks.iter().filter(|c| c.status == Status::Warn).count();
    let fail = checks.iter().filter(|c| c.status == Status::Fail).count();
    let ok = fail == 0 && (!args.strict || warn == 0);
    let report =
        DoctorReport { ok, strict: args.strict, summary: DoctorSummary { pass, warn, fail }, checks };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for c in &report.checks {
            println!("[{}] {:<20} {}", c.status.label(), c.name, c.detail);
        }
        println!(
            "\nsummary: {} pass, {} warn, {} fail (ok={})",
            report.summary.pass, report.summary.warn, report.summary.fail, report.ok
        );
    }

    Ok(if report.ok { ExitCode::SUCCESS } else { ExitCode::from(1) })
}
