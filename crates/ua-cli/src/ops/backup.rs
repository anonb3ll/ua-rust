//! `ua backup` and `ua restore`: online WAL snapshots and lock-protected restores.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::Args;
use serde::Serialize;
use ua_core::Config;
use ua_store::backup::{BackupReport, RestoreOptions, backup_database, check_dir_owner, restore_database};

use super::{reject_if_symlink, write_atomic_file};

#[derive(Debug, Clone, Args)]
pub struct BackupArgs {
    /// Destination path for the verified SQLite snapshot.
    #[arg(long)]
    pub to: PathBuf,
    /// Overwrite an existing backup (and manifest, if requested).
    #[arg(long)]
    pub force: bool,
    /// Also write `<to>.sha256.json` alongside the backup with digest and metadata.
    #[arg(long)]
    pub manifest: bool,
}

#[derive(Debug, Clone, Args)]
pub struct RestoreArgs {
    /// Path to the backup snapshot to verify and restore.
    #[arg(long)]
    pub from: PathBuf,
    /// Verify integrity, schema/triggers, ledger chain, and SHA-256 without modifying the hub DB.
    #[arg(long)]
    pub dry_run: bool,
    /// Overwrite an existing hub database at `$UA_HOME/ua.db` (or configured `db_path`).
    #[arg(long)]
    pub force: bool,
    /// Require the backup file's SHA-256 digest to match this 64-character hex value.
    #[arg(long)]
    pub expected_sha256: Option<String>,
    /// Allow non-dry-run restore without `--expected-sha256`.
    #[arg(long)]
    pub allow_unpinned: bool,
    /// Allow restoring a backup containing schema parts from a newer build.
    #[arg(long)]
    pub allow_newer: bool,
    /// Skip writing a `.pre-restore-*.bak` safety copy of the existing database.
    #[arg(long)]
    pub no_safety_backup: bool,
    /// Invalidate active UI sessions, login links, OAuth grants/tokens/codes/requests,
    /// and node session credentials inside the restore transaction (does not revoke
    /// `agent_tokens`, static `UA_AGENT_TOKENS`, or `managed_secrets`).
    #[arg(long)]
    pub revoke_sessions: bool,
}

#[derive(Debug, Serialize)]
struct BackupManifest<'a> {
    sha256: &'a str,
    bytes: u64,
    created_at: &'a str,
    quick_check: &'a str,
    ledger: &'a ua_store::ledger::VerifyReport,
    ledger_head_seq: Option<i64>,
    ledger_head_hash: &'a Option<String>,
    table_counts: &'a std::collections::BTreeMap<String, u64>,
}

fn manifest_path_for(backup_path: &Path) -> PathBuf {
    let mut name = backup_path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".sha256.json");
    backup_path.with_file_name(name)
}

pub fn run_backup(cfg: &Config, args: BackupArgs) -> anyhow::Result<()> {
    check_dir_owner(&cfg.home)?;
    let db_path = cfg.db_path();
    let manifest_path = args.manifest.then(|| manifest_path_for(&args.to));
    if let Some(mp) = &manifest_path {
        reject_if_symlink(mp, "manifest")?;
        if !args.force && std::fs::symlink_metadata(mp).is_ok() {
            bail!("manifest {} already exists (pass --force to overwrite)", mp.display());
        }
    }

    // Shared lock matches `ua serve` and `ua mcp`, so live backups succeed while
    // exclusive `import` or `restore` operations block concurrent backups.
    let _lock = ua_import::HubLock::acquire_shared(&db_path, "backup")?;
    let report: BackupReport = backup_database(&db_path, &args.to, args.force)?;

    if let Some(mp) = &manifest_path {
        let manifest = BackupManifest {
            sha256: &report.sha256,
            bytes: report.bytes,
            created_at: &report.created_at,
            quick_check: &report.quick_check,
            ledger: &report.ledger,
            ledger_head_seq: report.ledger_head_seq,
            ledger_head_hash: &report.ledger_head_hash,
            table_counts: &report.table_counts,
        };
        let mut json_bytes = serde_json::to_vec_pretty(&manifest).context("serializing backup manifest")?;
        json_bytes.push(b'\n');
        write_atomic_file(mp, &json_bytes, args.force)?;
    }

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

pub fn run_restore(cfg: &Config, args: RestoreArgs) -> anyhow::Result<()> {
    if !args.dry_run {
        check_dir_owner(&cfg.home)?;
    }
    let db_path = cfg.db_path();
    let _lock = if args.dry_run {
        None
    } else {
        // Exclusive lock refuses restore while `ua serve`, `ua mcp`, `ua call`,
        // `ua backup`, or `ua import` holds the database.
        Some(ua_import::HubLock::acquire(&db_path, "restore")?)
    };

    let report = restore_database(
        &args.from,
        &db_path,
        RestoreOptions {
            dry_run: args.dry_run,
            force: args.force,
            expected_sha256: args.expected_sha256,
            allow_unpinned: args.allow_unpinned,
            allow_newer: args.allow_newer,
            keep_safety_backup: !args.no_safety_backup,
            revoke_sessions: args.revoke_sessions,
            expected_schema: Some((ua_tools::schema_parts(), ua_tools::optional_schema_parts())),
        },
    )?;

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
