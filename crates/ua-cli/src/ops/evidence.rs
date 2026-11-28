//! `ua evidence`: the evidence key store, checkpoint rows, and the offline
//! signing step (`docs/evidence-export.md`, S2).
//!
//! The hub never holds a signing key. `checkpoint` writes a row and emits the
//! full checkpoint payload (and `--out` file) plus the previous signed
//! checkpoint head; the operator signs that checkpoint file offline with
//! `sign --checkpoint-file`, which recomputes the digest locally and displays
//! every field before signing; `attach` verifies and stores the signature on
//! the row; `verify` recomputes the digest and checks the signature against
//! the verifier's pinned key or trust file. `key-generate` makes a key file
//! for an operator who does not already have one; the private key never leaves
//! the machine that runs it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use secrecy::zeroize::Zeroizing;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ua_store::evidence::{
    CHECKPOINT_FORMAT, Checkpoint, CheckpointClass, CheckpointVerification, PinnedCheckpoint, TrustAnchor,
    TrustFile, VerifyTrust, Window, checkpoint_attach, checkpoint_write, key_add, key_list, key_retire,
    key_revoke, latest_signed_checkpoint, verify_checkpoint_with,
};
use ua_store::evidence_bundle::{
    BUNDLE_FORMAT, BundleCheckpointFile, BundleManifest, BundleVerifyTrust, ExportBundleOptions,
    MAX_BUNDLE_FILE_BYTES, MAX_BUNDLE_TOTAL_BYTES, PinnedHubHead, PinnedOrgHead,
    compute_org_window_checkpoint, export_bundle, load_verified_hub_cross_check, sha256_hex,
    snapshot_checkpoint, verify_bundle_dir,
};
use ua_tools::Hub;

use super::{reject_if_symlink, set_owner_only_file, write_atomic_file};

#[derive(Debug, Clone, Args)]
pub struct EvidenceArgs {
    #[command(subcommand)]
    pub cmd: EvidenceCmd,
}

#[derive(Debug, Clone, Subcommand)]
pub enum EvidenceCmd {
    /// Add a public key (hex, 32 bytes) to the evidence key store.
    KeyAdd {
        #[arg(long)]
        key_id: String,
        /// Hex-encoded 32-byte Ed25519 public key.
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// List the evidence keys.
    KeyList,
    /// Retire a key. It stays in the store so older bundles still verify.
    KeyRetire {
        #[arg(long)]
        key_id: String,
    },
    /// Revoke a key. A revoked key is refused for new checkpoints and no
    /// checkpoint naming it verifies. Use this when the key is compromised.
    KeyRevoke {
        #[arg(long)]
        key_id: String,
    },
    /// Generate an Ed25519 key file (0600) and print its public key. Run this
    /// on the operator's machine; the private key never goes to the hub.
    KeyGenerate {
        /// Where to write the 32-byte seed as hex. Refuses to overwrite.
        #[arg(long)]
        out: PathBuf,
    },
    /// Write a checkpoint row, print its fields and digest, and optionally
    /// write a checkpoint JSON file for offline signing.
    Checkpoint(CheckpointArgs),
    /// Export a canonical, hash-manifested evidence bundle for a checkpoint.
    /// Never holds a signing key and never writes `manifest.sig`; sign the
    /// exported bundle offline with `ua evidence sign --bundle`.
    Export {
        /// Checkpoint id in `evidence_checkpoint` whose range to export.
        #[arg(long)]
        checkpoint: String,
        /// Output directory for the bundle (must not exist or must be empty).
        #[arg(long)]
        out: PathBuf,
        /// Optional exclusive start global `seq` for incremental `hub` exports.
        #[arg(long)]
        from_seq: Option<i64>,
        /// Optional exclusive start `org_seq` for incremental `org` exports.
        #[arg(long)]
        from_org_seq: Option<i64>,
    },
    /// Sign a checkpoint file or exported evidence bundle offline with a key
    /// file. Recomputes the digest locally and displays its fields before
    /// signing. Never opens or creates a hub database.
    Sign {
        /// Key file: 64 hex characters (a 32-byte Ed25519 seed).
        #[arg(long)]
        key_file: PathBuf,
        /// Checkpoint JSON file written by `ua evidence checkpoint --out` (or
        /// a bare checkpoint JSON object). Mutually exclusive with `--bundle`.
        #[arg(long, conflicts_with = "bundle", required_unless_present = "bundle")]
        checkpoint_file: Option<PathBuf>,
        /// Exported evidence bundle directory to sign offline. Recomputes
        /// `manifest.json`'s digest and verifies every file hash before
        /// writing `manifest.sig` (or `--out`). Mutually exclusive with
        /// `--checkpoint-file`.
        #[arg(long, conflicts_with = "checkpoint_file", required_unless_present = "checkpoint_file")]
        bundle: Option<PathBuf>,
        /// Optional local copy of the previous checkpoint file you signed, to
        /// display its head and verify continuity before signing the new one.
        #[arg(long)]
        prev_checkpoint: Option<PathBuf>,
        /// Write the signature hex to this file (for `--checkpoint-file`,
        /// defaults to stdout; for `--bundle`, defaults to `<bundle>/manifest.sig`).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Attach an operator's signature to a checkpoint row. Verifies the
    /// signature against the stored public key before storing it.
    Attach {
        #[arg(long)]
        checkpoint: String,
        /// Hex-encoded 64-byte Ed25519 signature.
        #[arg(long)]
        signature: String,
    },
    /// Verify a checkpoint in the hub database (`--checkpoint`) or an exported
    /// evidence bundle offline (`--bundle`). Offline `--bundle` verification
    /// never opens or creates a hub database. Exits 0 verified, 1 refused,
    /// 2 cannot verify.
    Verify {
        /// Checkpoint id in the hub database. Mutually exclusive with `--bundle`.
        #[arg(long, conflicts_with = "bundle", required_unless_present = "bundle")]
        checkpoint: Option<String>,
        /// Exported evidence bundle directory to verify completely offline.
        /// Mutually exclusive with `--checkpoint`.
        #[arg(long, conflicts_with = "checkpoint", required_unless_present = "checkpoint")]
        bundle: Option<PathBuf>,
        /// Hex-encoded 32-byte Ed25519 public key the verifier pinned out of band.
        #[arg(long)]
        anchor_key: Option<String>,
        /// The key id the pinned anchor belongs to. Required when `--anchor-key`
        /// is set; a mismatch against the checkpoint's key id is refused.
        #[arg(long)]
        anchor_key_id: Option<String>,
        /// Local JSON trust file holding pinned `keys`, authoritative
        /// `revoked_key_ids`, and/or out-of-band `signed_checkpoints`.
        #[arg(long)]
        trust_file: Option<PathBuf>,
        /// Mark a key id as revoked at verification time (repeatable). Checked
        /// independently of the database's `revoked_at` column.
        #[arg(long = "revoked-key-id")]
        revoked_key_ids: Vec<String>,
        /// Local copy of a previously signed checkpoint file (repeatable).
        /// For `--checkpoint`: out-of-band hub checkpoints checked against the
        /// database. For `--bundle`: pins the prior checkpoint head (`hub` or
        /// `org`) for incremental completeness verification.
        #[arg(long = "prev-checkpoint")]
        prev_checkpoints: Vec<PathBuf>,
        /// For `--bundle` (class `org` only): path to a signed `hub` bundle
        /// directory used to cross-check `global_from_hash` and
        /// `global_head_hash` against the global ledger chain.
        #[arg(long)]
        hub_bundle: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Args)]
pub struct CheckpointArgs {
    /// Checkpoint id. Defaults to a fresh ULID.
    #[arg(long)]
    pub id: Option<String>,
    /// `hub` or `org`.
    #[arg(long, default_value = "hub")]
    pub class: String,
    /// The organization the bundle covers (`org` class only; defaults to
    /// `default` for `org` and is refused for `hub`).
    #[arg(long)]
    pub org: Option<String>,
    /// The key that signs it.
    #[arg(long)]
    pub key_id: String,
    /// Hub class: the ledger sequence the checkpoint covers.
    #[arg(long)]
    pub seq: Option<i64>,
    /// Hub class: the ledger hash at that sequence.
    #[arg(long)]
    pub hash: Option<String>,
    /// Org class: the window start (RFC 3339).
    #[arg(long)]
    pub window_from: Option<String>,
    /// Org class: the window end (RFC 3339).
    #[arg(long)]
    pub window_to: Option<String>,
    /// Org class: the global hash immediately before the window.
    #[arg(long)]
    pub global_from: Option<String>,
    /// Org class: the global hash at the window's head.
    #[arg(long)]
    pub head: Option<String>,
    /// Org class: how many rows the window covers.
    #[arg(long)]
    pub row_count: Option<i64>,
    /// Org class: the chained hash over the window's rows.
    #[arg(long)]
    pub chain: Option<String>,
    /// Org class: derive `--global-from`, `--head`, `--row-count`, and
    /// `--chain` directly from `event_log` for `--org` over
    /// `[--window-from, --window-to]` (optionally continuing after
    /// `--global-from`).
    #[arg(long)]
    pub derive: bool,
    /// Write the full checkpoint JSON file here for offline signing with
    /// `ua evidence sign --checkpoint-file`. Refuses to overwrite.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// Summary of the previously signed checkpoint's head, carried in a checkpoint
/// file so the operator sees what the new checkpoint continues from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviousCheckpointHead {
    pub checkpoint_id: String,
    pub class: CheckpointClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<Window>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_from_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_head_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_row_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_chain_hash: Option<String>,
    pub key_id: String,
    pub signed_at: String,
    pub digest: String,
}

impl PreviousCheckpointHead {
    fn from_checkpoint(cp: &Checkpoint) -> Self {
        Self {
            checkpoint_id: cp.checkpoint_id.clone(),
            class: cp.class,
            org_id: cp.org_id.clone(),
            seq: cp.seq,
            hash: cp.hash.clone(),
            window: cp.window.clone(),
            global_from_hash: cp.global_from_hash.clone(),
            global_head_hash: cp.global_head_hash.clone(),
            org_row_count: cp.org_row_count,
            org_chain_hash: cp.org_chain_hash.clone(),
            key_id: cp.key_id.clone(),
            signed_at: cp.signed_at.clone(),
            digest: cp.digest(),
        }
    }
}

/// Envelope written by `ua evidence checkpoint --out` and read by
/// `ua evidence sign --checkpoint-file`. `sign` always recomputes the digest
/// locally from `checkpoint` and refuses if an included `digest` disagrees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointFile {
    pub format: String,
    pub checkpoint: Checkpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_signed: Option<PreviousCheckpointHead>,
}

pub fn run(hub: &Hub, args: EvidenceArgs) -> anyhow::Result<ExitCode> {
    match args.cmd {
        EvidenceCmd::KeyAdd { key_id, public_key, note } => {
            let key_id = key_id.trim();
            let now = ua_core::time::now();
            hub.db().write(|tx| key_add(tx, key_id, &public_key, &now, note.as_deref()))?;
            println!("{}", json!({ "key_id": key_id, "added": true }));
            Ok(ExitCode::SUCCESS)
        }
        EvidenceCmd::KeyList => {
            let keys = hub.db().read(key_list)?;
            println!("{}", serde_json::to_string_pretty(&keys)?);
            Ok(ExitCode::SUCCESS)
        }
        EvidenceCmd::KeyRetire { key_id } => {
            let key_id = key_id.trim();
            let now = ua_core::time::now();
            hub.db().write(|tx| key_retire(tx, key_id, &now))?;
            println!("{}", json!({ "key_id": key_id, "retired": true }));
            Ok(ExitCode::SUCCESS)
        }
        EvidenceCmd::KeyRevoke { key_id } => {
            let key_id = key_id.trim();
            let now = ua_core::time::now();
            hub.db().write(|tx| key_revoke(tx, key_id, &now))?;
            println!("{}", json!({ "key_id": key_id, "revoked": true }));
            Ok(ExitCode::SUCCESS)
        }
        EvidenceCmd::KeyGenerate { out } => {
            run_key_generate(&out)?;
            Ok(ExitCode::SUCCESS)
        }
        EvidenceCmd::Checkpoint(args) => {
            let out = args.out.clone();
            let checkpoint = build_checkpoint(hub, args)?;
            let now = ua_core::time::now();
            let previous_signed = hub
                .db()
                .read(|c| latest_signed_checkpoint(c, checkpoint.class, checkpoint.org_id.as_deref()))?
                .as_ref()
                .map(PreviousCheckpointHead::from_checkpoint);
            // The export snapshot (withheld counts, org ordinals) is frozen in
            // the same transaction, so later deletes never change a re-export.
            let digest = hub.db().write(|tx| {
                let digest = checkpoint_write(tx, &checkpoint, &now)?;
                snapshot_checkpoint(tx, &checkpoint.checkpoint_id, &now)?;
                Ok(digest)
            })?;
            let file_payload = CheckpointFile {
                format: CHECKPOINT_FORMAT.to_string(),
                checkpoint: checkpoint.clone(),
                digest: Some(digest.clone()),
                previous_signed: previous_signed.clone(),
            };
            if let Some(path) = out.as_deref() {
                reject_if_symlink(path, "checkpoint file")?;
                let bytes = serde_json::to_vec_pretty(&file_payload)?;
                write_atomic_file(path, &bytes, false)?;
            }
            let mut summary = json!({
                "format": CHECKPOINT_FORMAT,
                "checkpoint_id": checkpoint.checkpoint_id,
                "class": checkpoint.class.as_str(),
                "key_id": checkpoint.key_id,
                "digest": digest,
                "checkpoint": checkpoint,
            });
            if let Some(prev) = previous_signed {
                summary["previous_signed"] = serde_json::to_value(prev)?;
            }
            if let Some(path) = out {
                summary["out"] = json!(path.display().to_string());
            }
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(ExitCode::SUCCESS)
        }
        EvidenceCmd::Export { checkpoint, out, from_seq, from_org_seq } => {
            let opts = ExportBundleOptions {
                checkpoint_id: checkpoint.trim().to_string(),
                from_seq,
                from_org_seq,
                exported_at: ua_core::time::now(),
                host: std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into()),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            // A checkpoint written before export snapshots existed freezes its
            // snapshot on first export.
            hub.db().write(|tx| snapshot_checkpoint(tx, &opts.checkpoint_id, &opts.exported_at))?;
            let result = hub.db().read(|c| export_bundle(c, &out, &opts))?;
            let summary = json!({
                "format": result.manifest.format,
                "class": result.manifest.class.as_str(),
                "org_id": result.manifest.org_id,
                "out": out.display().to_string(),
                "digest": result.manifest.digest,
                "counts": result.manifest.counts,
                "withheld": result.withheld,
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(ExitCode::SUCCESS)
        }
        EvidenceCmd::Sign { key_file, checkpoint_file, bundle, prev_checkpoint, out } => {
            run_sign_cmd(
                &key_file,
                checkpoint_file.as_deref(),
                bundle.as_deref(),
                prev_checkpoint.as_deref(),
                out.as_deref(),
            )?;
            Ok(ExitCode::SUCCESS)
        }
        EvidenceCmd::Attach { checkpoint, signature } => {
            let checkpoint = checkpoint.trim();
            hub.db().write(|tx| checkpoint_attach(tx, checkpoint, &signature))?;
            println!("{}", json!({ "checkpoint_id": checkpoint, "attached": true }));
            Ok(ExitCode::SUCCESS)
        }
        EvidenceCmd::Verify {
            checkpoint,
            bundle,
            anchor_key,
            anchor_key_id,
            trust_file,
            revoked_key_ids,
            prev_checkpoints,
            hub_bundle,
        } => {
            if let Some(bundle_dir) = bundle {
                return run_verify_bundle(
                    &bundle_dir,
                    anchor_key,
                    anchor_key_id,
                    trust_file.as_deref(),
                    revoked_key_ids,
                    prev_checkpoints,
                    hub_bundle.as_deref(),
                );
            }
            if hub_bundle.is_some() {
                eprintln!("cannot verify: --hub-bundle is only valid with --bundle");
                return Ok(ExitCode::from(2));
            }
            let Some(checkpoint) = checkpoint else {
                eprintln!("cannot verify: either --checkpoint or --bundle is required");
                return Ok(ExitCode::from(2));
            };
            let trust = match build_verify_trust(
                anchor_key,
                anchor_key_id,
                trust_file.as_deref(),
                revoked_key_ids,
                prev_checkpoints,
            ) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("cannot verify: {e:#}");
                    return Ok(ExitCode::from(2));
                }
            };
            let verdict = match hub.db().read(|c| verify_checkpoint_with(c, checkpoint.trim(), &trust)) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("cannot verify: {e}");
                    return Ok(ExitCode::from(2));
                }
            };
            println!("{}", serde_json::to_string_pretty(&verdict)?);
            for warning in verdict.warnings() {
                eprintln!("warning: {warning}");
            }
            if let CheckpointVerification::ValidInStoreOnly { .. } = verdict {
                eprintln!(
                    "not authorship: the key came from the same database; pass --anchor-key and --anchor-key-id (or --trust-file)"
                );
            }
            Ok(ExitCode::from(verdict.exit_code()))
        }
    }
}

/// Verify an exported evidence bundle completely offline without opening or
/// creating any hub database or reading `$UA_HOME`.
pub fn run_verify_bundle(
    bundle_dir: &Path,
    anchor_key: Option<String>,
    anchor_key_id: Option<String>,
    trust_file: Option<&Path>,
    revoked_key_ids: Vec<String>,
    prev_checkpoints: Vec<PathBuf>,
    hub_bundle: Option<&Path>,
) -> anyhow::Result<ExitCode> {
    let base_trust =
        match build_verify_trust(anchor_key, anchor_key_id, trust_file, revoked_key_ids, Vec::new()) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cannot verify: {e:#}");
                return Ok(ExitCode::from(2));
            }
        };

    let mut pinned_hub: Option<PinnedHubHead> = base_trust
        .signed_checkpoints
        .iter()
        .max_by_key(|p| p.seq)
        .map(|p| PinnedHubHead { seq: p.seq, hash: p.hash.clone() });
    let mut pinned_org: Option<PinnedOrgHead> = None;

    for path in prev_checkpoints {
        let parsed = match load_checkpoint_file(&path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot verify: {e:#}");
                return Ok(ExitCode::from(2));
            }
        };
        if let Err(e) = parsed.checkpoint.validate_fields() {
            eprintln!("cannot verify: invalid --prev-checkpoint {}: {e}", path.display());
            return Ok(ExitCode::from(2));
        }
        let recomputed = parsed.checkpoint.digest();
        if let Some(claimed) = parsed.digest.as_deref()
            && !claimed.trim().eq_ignore_ascii_case(&recomputed)
        {
            eprintln!(
                "cannot verify: digest mismatch in --prev-checkpoint {} (claims {claimed}, recomputed {recomputed})",
                path.display()
            );
            return Ok(ExitCode::from(2));
        }
        match parsed.checkpoint.class {
            CheckpointClass::Hub => {
                let seq = parsed.checkpoint.seq.expect("validated hub");
                let hash = parsed.checkpoint.hash.expect("validated hub");
                if pinned_hub.as_ref().is_none_or(|cur| seq > cur.seq) {
                    pinned_hub = Some(PinnedHubHead { seq, hash });
                }
            }
            CheckpointClass::Org => {
                let org_id = parsed.checkpoint.org_id.expect("validated org");
                let global_head_hash = parsed.checkpoint.global_head_hash.expect("validated org");
                let org_row_count = parsed.checkpoint.org_row_count.expect("validated org");
                let org_chain_hash = parsed.checkpoint.org_chain_hash.expect("validated org");
                if pinned_org.as_ref().is_none_or(|cur| org_row_count > cur.org_row_count) {
                    pinned_org =
                        Some(PinnedOrgHead { org_id, global_head_hash, org_row_count, org_chain_hash });
                }
            }
        }
    }

    let mut bundle_trust = BundleVerifyTrust {
        anchor: base_trust.anchor,
        trust_keys: base_trust.trust_keys,
        revoked_key_ids: base_trust.revoked_key_ids,
        pinned_hub,
        pinned_org,
        hub_cross_check: None,
    };

    if let Some(hub_dir) = hub_bundle {
        match load_verified_hub_cross_check(hub_dir, &bundle_trust) {
            Ok(Ok(cc)) => bundle_trust.hub_cross_check = Some(cc),
            Ok(Err(failed_hub_verdict)) => {
                println!("{}", serde_json::to_string_pretty(&failed_hub_verdict)?);
                eprintln!(
                    "cannot verify: --hub-bundle {} failed verification (exit {})",
                    hub_dir.display(),
                    failed_hub_verdict.exit_code
                );
                return Ok(ExitCode::from(failed_hub_verdict.exit_code));
            }
            Err(e) => {
                eprintln!("cannot verify: loading --hub-bundle {}: {e}", hub_dir.display());
                return Ok(ExitCode::from(2));
            }
        }
    }

    let verdict = match verify_bundle_dir(bundle_dir, &bundle_trust) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cannot verify: {e}");
            return Ok(ExitCode::from(2));
        }
    };
    println!("{}", serde_json::to_string_pretty(&verdict)?);
    for w in &verdict.warnings {
        eprintln!("warning: {w}");
    }
    Ok(ExitCode::from(verdict.exit_code))
}

/// Generate a key file without opening the hub. This command is offline: it
/// must not create or migrate a hub database.
pub fn run_key_generate(out: &Path) -> anyhow::Result<()> {
    let key = generate_key_file(out)?;
    println!("{}", json!({ "public_key": key, "key_file": out.display().to_string() }));
    Ok(())
}

/// Dispatch offline `ua evidence sign` for either `--checkpoint-file` or
/// `--bundle`. Never opens or creates a hub database.
pub fn run_sign_cmd(
    key_file: &Path,
    checkpoint_file: Option<&Path>,
    bundle: Option<&Path>,
    prev_checkpoint: Option<&Path>,
    out: Option<&Path>,
) -> anyhow::Result<()> {
    match (checkpoint_file, bundle) {
        (Some(cp), None) => run_sign(key_file, cp, prev_checkpoint, out),
        (None, Some(dir)) => {
            if prev_checkpoint.is_some() {
                anyhow::bail!("--prev-checkpoint is only supported with --checkpoint-file");
            }
            run_sign_bundle(key_file, dir, out)
        }
        (Some(_), Some(_)) => anyhow::bail!("pass either --checkpoint-file or --bundle, not both"),
        (None, None) => anyhow::bail!("either --checkpoint-file or --bundle is required"),
    }
}

/// Sign an exported evidence bundle directory offline without opening any hub
/// database. Recomputes `manifest.json`'s digest, refuses symlinks/path
/// traversal/oversized files, verifies every hashed file listed in
/// `manifest.files`, displays summary fields on stderr, and writes
/// `manifest.sig` (or `--out`).
pub fn run_sign_bundle(key_file: &Path, bundle_dir: &Path, out: Option<&Path>) -> anyhow::Result<()> {
    let root_meta = std::fs::symlink_metadata(bundle_dir)
        .with_context(|| format!("inspecting bundle directory {}", bundle_dir.display()))?;
    if root_meta.file_type().is_symlink() {
        anyhow::bail!("refusing bundle directory symlink {}", bundle_dir.display());
    }
    if !root_meta.file_type().is_dir() {
        anyhow::bail!("bundle path {} is not a directory", bundle_dir.display());
    }
    let mut total_read = 0u64;
    let manifest_bytes = read_bundle_file_for_sign(bundle_dir, "manifest.json", &mut total_read)?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parsing bundle manifest {}", bundle_dir.join("manifest.json").display()))?;
    if manifest.format != BUNDLE_FORMAT {
        anyhow::bail!(
            "unsupported bundle format {:?} in {} (expected {:?})",
            manifest.format,
            bundle_dir.join("manifest.json").display(),
            BUNDLE_FORMAT
        );
    }
    let recomputed =
        manifest.recompute_digest().map_err(|e| anyhow::anyhow!("recomputing manifest digest: {e}"))?;
    if !manifest.digest.trim().eq_ignore_ascii_case(&recomputed) {
        anyhow::bail!(
            "refusing to sign bundle: manifest claims digest {} but locally recomputed digest is {}",
            manifest.digest.trim(),
            recomputed
        );
    }
    for (rel, expected_sha) in &manifest.files {
        if rel.is_empty()
            || rel.starts_with('/')
            || rel.contains('\\')
            || !rel.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
            || matches!(rel.as_str(), "manifest.json" | "manifest.sig" | "producer.json")
        {
            anyhow::bail!("refusing to sign bundle: illegal path {rel:?} in manifest.files");
        }
        let bytes = read_bundle_file_for_sign(bundle_dir, rel, &mut total_read)
            .with_context(|| format!("refusing to sign bundle: reading hashed file {rel:?}"))?;
        let actual_sha = sha256_hex(&bytes);
        if !actual_sha.eq_ignore_ascii_case(expected_sha.trim()) {
            anyhow::bail!(
                "refusing to sign bundle: hashed file {rel:?} digest mismatch (manifest {}, actual {})",
                expected_sha.trim(),
                actual_sha
            );
        }
    }

    let cp_bytes = read_bundle_file_for_sign(bundle_dir, "ledger/checkpoint.json", &mut total_read)?;
    let cp_file: BundleCheckpointFile = serde_json::from_slice(&cp_bytes).with_context(|| {
        format!("parsing bundle checkpoint {}", bundle_dir.join("ledger/checkpoint.json").display())
    })?;

    // Run every verifier check except authorship before signing: the operator
    // never attests a bundle the offline verifier would refuse. Without trust
    // input the verifier stops at authorship (`unanchored`, `unsigned_bundle`
    // or `unsigned_checkpoint`), having run every other check first.
    let verdict = verify_bundle_dir(bundle_dir, &BundleVerifyTrust::default())
        .map_err(|e| anyhow::anyhow!("verifying bundle before signing: {e}"))?;
    let authorship_only = verdict.exit_code == 2
        && matches!(
            verdict.reason.as_deref(),
            Some("unanchored" | "unsigned_bundle" | "unsigned_checkpoint")
        );
    if !verdict.ok && !authorship_only {
        anyhow::bail!(
            "refusing to sign bundle: the offline verifier refuses it ({}: {})",
            verdict.reason.as_deref().unwrap_or("unknown"),
            verdict.detail.as_deref().unwrap_or("")
        );
    }

    let (sig, public_key) = sign_digest(key_file, &recomputed)?;

    eprintln!("signing evidence bundle (manifest digest and file hashes verified locally):");
    eprintln!("  format:            {}", manifest.format);
    eprintln!("  class:             {}", manifest.class.as_str());
    if let Some(org_id) = &manifest.org_id {
        eprintln!("  org_id:            {org_id}");
    }
    eprintln!("  checkpoint_id:     {}", cp_file.checkpoint.checkpoint_id);
    eprintln!("  key_id:            {}", cp_file.checkpoint.key_id);
    eprintln!("  signing_pub_key:   {public_key}");
    eprintln!("  window.start:      {}", manifest.window.start);
    eprintln!("  window.end:        {}", manifest.window.end);
    eprintln!("  events:            {}", manifest.counts.events);
    eprintln!("  approvals:         {}", manifest.counts.approvals);
    eprintln!("  artifacts:         {}", manifest.counts.artifacts);
    eprintln!("  withheld_total:    {}", manifest.counts.withheld_total);
    eprintln!("  digest (sha256):   {recomputed}");

    let target = out.map(Path::to_path_buf).unwrap_or_else(|| bundle_dir.join("manifest.sig"));
    reject_if_symlink(&target, "bundle signature file")?;
    write_atomic_file(&target, sig.as_bytes(), false)?;
    println!(
        "{}",
        json!({
            "bundle": bundle_dir.display().to_string(),
            "checkpoint_id": cp_file.checkpoint.checkpoint_id,
            "digest": recomputed,
            "signature": sig,
            "out": target.display().to_string(),
        })
    );
    Ok(())
}

fn read_bundle_file_for_sign(root: &Path, rel: &str, total_read: &mut u64) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;

    let mut cur = root.to_path_buf();
    for seg in rel.split('/') {
        cur.push(seg);
        let meta =
            std::fs::symlink_metadata(&cur).with_context(|| format!("inspecting {}", cur.display()))?;
        if meta.file_type().is_symlink() {
            anyhow::bail!("refusing symlink at {rel:?} inside bundle directory");
        }
    }
    let meta = std::fs::symlink_metadata(&cur)?;
    if !meta.file_type().is_file() {
        anyhow::bail!("refusing non-regular file {rel:?} inside bundle directory");
    }
    if meta.len() > MAX_BUNDLE_FILE_BYTES {
        anyhow::bail!("file {rel:?} exceeds limit {MAX_BUNDLE_FILE_BYTES} bytes");
    }
    if total_read.saturating_add(meta.len()) > MAX_BUNDLE_TOTAL_BYTES {
        anyhow::bail!("bundle total size exceeds limit {MAX_BUNDLE_TOTAL_BYTES} bytes");
    }
    let file = std::fs::File::open(&cur)?;
    let mut buf = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_BUNDLE_FILE_BYTES.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_BUNDLE_FILE_BYTES {
        anyhow::bail!("file {rel:?} exceeds limit {MAX_BUNDLE_FILE_BYTES} bytes");
    }
    *total_read = total_read.saturating_add(buf.len() as u64);
    if *total_read > MAX_BUNDLE_TOTAL_BYTES {
        anyhow::bail!("bundle total size exceeds limit {MAX_BUNDLE_TOTAL_BYTES} bytes");
    }
    Ok(buf)
}

/// Sign a checkpoint file without opening the hub. This command is offline: it
/// must not create or migrate a hub database.
///
/// Recomputes the digest locally from the checkpoint fields, verifies any
/// supplied `--prev-checkpoint` continuity, displays all fields and previous
/// head on stderr, and signs the recomputed raw digest bytes.
pub fn run_sign(
    key_file: &Path,
    checkpoint_file: &Path,
    prev_checkpoint: Option<&Path>,
    out: Option<&Path>,
) -> anyhow::Result<()> {
    let parsed = load_checkpoint_file(checkpoint_file)?;
    parsed
        .checkpoint
        .validate_fields()
        .map_err(|e| anyhow::anyhow!("invalid checkpoint in {}: {e}", checkpoint_file.display()))?;
    let recomputed = parsed.checkpoint.digest();
    if let Some(claimed) = parsed.digest.as_deref()
        && !claimed.trim().eq_ignore_ascii_case(&recomputed)
    {
        anyhow::bail!(
            "refusing to sign: checkpoint file claims digest {} but locally recomputed digest is {}",
            claimed.trim(),
            recomputed
        );
    }

    let local_prev = match prev_checkpoint {
        Some(path) => {
            let prev = load_checkpoint_file(path)?;
            prev.checkpoint
                .validate_fields()
                .map_err(|e| anyhow::anyhow!("invalid previous checkpoint in {}: {e}", path.display()))?;
            let prev_head = PreviousCheckpointHead::from_checkpoint(&prev.checkpoint);
            if let Some(claimed) = prev.digest.as_deref()
                && !claimed.trim().eq_ignore_ascii_case(&prev_head.digest)
            {
                anyhow::bail!(
                    "previous checkpoint file {} has digest mismatch: claimed {}, recomputed {}",
                    path.display(),
                    claimed.trim(),
                    prev_head.digest
                );
            }
            verify_continuity(&prev.checkpoint, &parsed.checkpoint)?;
            if let Some(hub_prev) = &parsed.previous_signed
                && hub_prev != &prev_head
            {
                anyhow::bail!(
                    "continuity mismatch: hub-reported previous_signed ({}, digest {}) disagrees with local --prev-checkpoint ({}, digest {})",
                    hub_prev.checkpoint_id,
                    hub_prev.digest,
                    prev_head.checkpoint_id,
                    prev_head.digest
                );
            }
            Some(prev_head)
        }
        None => None,
    };

    let (sig, public_key) = sign_digest(key_file, &recomputed)?;
    print_signing_summary(
        &parsed.checkpoint,
        &recomputed,
        &public_key,
        local_prev.as_ref(),
        parsed.previous_signed.as_ref(),
    );

    match out {
        Some(path) => {
            reject_if_symlink(path, "signature file")?;
            write_atomic_file(path, sig.as_bytes(), false)?;
            println!(
                "{}",
                json!({
                    "checkpoint_id": parsed.checkpoint.checkpoint_id,
                    "digest": recomputed,
                    "signature": sig,
                    "out": path.display().to_string(),
                })
            );
        }
        None => println!("{sig}"),
    }
    Ok(())
}

fn load_checkpoint_file(path: &Path) -> anyhow::Result<CheckpointFile> {
    let bytes = std::fs::read(path).with_context(|| format!("reading checkpoint file {}", path.display()))?;
    let val: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing checkpoint JSON {}", path.display()))?;
    if val.get("checkpoint").is_some() {
        let parsed: CheckpointFile = serde_json::from_value(val)
            .with_context(|| format!("decoding checkpoint envelope {}", path.display()))?;
        if parsed.format != CHECKPOINT_FORMAT {
            anyhow::bail!(
                "unsupported checkpoint format {:?} in {} (expected {:?})",
                parsed.format,
                path.display(),
                CHECKPOINT_FORMAT
            );
        }
        Ok(parsed)
    } else {
        let checkpoint: Checkpoint =
            serde_json::from_value(val).with_context(|| format!("decoding checkpoint {}", path.display()))?;
        Ok(CheckpointFile {
            format: CHECKPOINT_FORMAT.to_string(),
            checkpoint,
            digest: None,
            previous_signed: None,
        })
    }
}

/// Confirm that `next` advances cleanly from `prev` (same class/org, strictly
/// advancing `seq` for `hub`, matching `global_head_hash -> global_from_hash`
/// and non-decreasing `org_row_count` for `org`).
fn verify_continuity(prev: &Checkpoint, next: &Checkpoint) -> anyhow::Result<()> {
    if prev.class != next.class {
        anyhow::bail!(
            "continuity mismatch: previous checkpoint class is {:?} but new checkpoint is {:?}",
            prev.class.as_str(),
            next.class.as_str()
        );
    }
    if prev.checkpoint_id == next.checkpoint_id {
        anyhow::bail!(
            "continuity mismatch: new checkpoint has the same checkpoint_id {:?} as --prev-checkpoint",
            next.checkpoint_id
        );
    }
    match next.class {
        CheckpointClass::Hub => {
            let prev_seq = prev.seq.expect("validated");
            let next_seq = next.seq.expect("validated");
            if next_seq <= prev_seq {
                anyhow::bail!(
                    "continuity mismatch: new hub checkpoint seq {next_seq} does not advance past previous seq {prev_seq}"
                );
            }
        }
        CheckpointClass::Org => {
            if prev.org_id != next.org_id {
                anyhow::bail!(
                    "continuity mismatch: previous checkpoint org_id {:?} does not match new org_id {:?}",
                    prev.org_id,
                    next.org_id
                );
            }
            let prev_head = prev.global_head_hash.as_deref().expect("validated");
            let next_from = next.global_from_hash.as_deref().expect("validated");
            if !prev_head.eq_ignore_ascii_case(next_from) {
                anyhow::bail!(
                    "continuity mismatch: new org checkpoint global_from_hash {next_from:?} does not match previous global_head_hash {prev_head:?}"
                );
            }
            let prev_count = prev.org_row_count.expect("validated");
            let next_count = next.org_row_count.expect("validated");
            if next_count < prev_count {
                anyhow::bail!(
                    "continuity mismatch: new org checkpoint org_row_count {next_count} regressed below previous {prev_count}"
                );
            }
        }
    }
    Ok(())
}

fn print_signing_summary(
    cp: &Checkpoint,
    recomputed_digest: &str,
    signing_public_key: &str,
    local_prev: Option<&PreviousCheckpointHead>,
    hub_prev: Option<&PreviousCheckpointHead>,
) {
    eprintln!("signing checkpoint (digest recomputed locally):");
    eprintln!("  format:            {CHECKPOINT_FORMAT}");
    eprintln!("  checkpoint_id:     {}", cp.checkpoint_id);
    eprintln!("  class:             {}", cp.class.as_str());
    eprintln!("  key_id:            {}", cp.key_id);
    eprintln!("  signing_pub_key:   {signing_public_key}");
    eprintln!("  signed_at:         {}", cp.signed_at);
    match cp.class {
        CheckpointClass::Hub => {
            eprintln!("  seq:               {}", cp.seq.expect("validated"));
            eprintln!("  hash:              {}", cp.hash.as_deref().expect("validated"));
        }
        CheckpointClass::Org => {
            eprintln!("  org_id:            {}", cp.org_id.as_deref().expect("validated"));
            let w = cp.window.as_ref().expect("validated");
            eprintln!("  window.start:      {}", w.start);
            eprintln!("  window.end:        {}", w.end);
            eprintln!("  global_from_hash:  {}", cp.global_from_hash.as_deref().expect("validated"));
            eprintln!("  global_head_hash:  {}", cp.global_head_hash.as_deref().expect("validated"));
            eprintln!("  org_row_count:     {}", cp.org_row_count.expect("validated"));
            eprintln!("  org_chain_hash:    {}", cp.org_chain_hash.as_deref().expect("validated"));
        }
    }
    eprintln!("  digest (sha256):   {recomputed_digest}");
    match (local_prev, hub_prev) {
        (Some(prev), _) => {
            eprintln!("previous signed checkpoint (verified against --prev-checkpoint):");
            print_prev_head(prev);
        }
        (None, Some(prev)) => {
            eprintln!(
                "previous signed checkpoint (hub-reported; confirm against your own record or pass --prev-checkpoint):"
            );
            print_prev_head(prev);
        }
        (None, None) => {
            eprintln!("previous signed checkpoint: none (first checkpoint or not provided)");
        }
    }
}

fn print_prev_head(prev: &PreviousCheckpointHead) {
    eprintln!("  checkpoint_id:     {}", prev.checkpoint_id);
    eprintln!("  key_id:            {}", prev.key_id);
    eprintln!("  signed_at:         {}", prev.signed_at);
    match prev.class {
        CheckpointClass::Hub => {
            if let Some(seq) = prev.seq {
                eprintln!("  seq:               {seq}");
            }
            if let Some(hash) = &prev.hash {
                eprintln!("  hash:              {hash}");
            }
        }
        CheckpointClass::Org => {
            if let Some(org_id) = &prev.org_id {
                eprintln!("  org_id:            {org_id}");
            }
            if let Some(head) = &prev.global_head_hash {
                eprintln!("  global_head_hash:  {head}");
            }
            if let Some(count) = prev.org_row_count {
                eprintln!("  org_row_count:     {count}");
            }
            if let Some(chain) = &prev.org_chain_hash {
                eprintln!("  org_chain_hash:    {chain}");
            }
        }
    }
    eprintln!("  digest (sha256):   {}", prev.digest);
}

fn validate_hex32(label: &str, raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let bytes = hex::decode(&trimmed).with_context(|| format!("{label} must be hex-encoded"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{label} must be 32 bytes (64 hex characters), got {} bytes", bytes.len());
    }
    Ok(trimmed)
}

fn build_verify_trust(
    anchor_key: Option<String>,
    anchor_key_id: Option<String>,
    trust_file: Option<&Path>,
    revoked_key_ids: Vec<String>,
    prev_checkpoints: Vec<PathBuf>,
) -> anyhow::Result<VerifyTrust> {
    let anchor = match (anchor_key, anchor_key_id) {
        (Some(public_key), Some(key_id)) => {
            let public_key = validate_hex32("--anchor-key", &public_key)?;
            let key_id = key_id.trim().to_string();
            if key_id.is_empty() {
                anyhow::bail!("--anchor-key-id must not be empty");
            }
            Some(TrustAnchor { key_id, public_key })
        }
        (Some(_), None) => anyhow::bail!("--anchor-key-id is required with --anchor-key"),
        (None, Some(_)) => anyhow::bail!("--anchor-key is required with --anchor-key-id"),
        (None, None) => None,
    };

    let mut trust_keys = Vec::new();
    let mut all_revoked: Vec<String> =
        revoked_key_ids.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let mut signed_checkpoints = Vec::new();

    if let Some(path) = trust_file {
        let bytes = std::fs::read(path).with_context(|| format!("reading trust file {}", path.display()))?;
        let parsed: TrustFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing trust file {}", path.display()))?;
        if anchor.is_some() && !parsed.keys.is_empty() {
            anyhow::bail!("pass either --anchor-key/--anchor-key-id or a --trust-file with keys, not both");
        }
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for k in parsed.keys {
            let id = k.key_id.trim().to_string();
            if id.is_empty() {
                anyhow::bail!("trust file {} contains a key with empty key_id", path.display());
            }
            let pk = validate_hex32(&format!("trust file key {id:?}"), &k.public_key)?;
            if let Some(prev_pk) = seen.insert(id.clone(), pk.clone())
                && prev_pk != pk
            {
                anyhow::bail!(
                    "trust file {} defines conflicting public keys for key_id {:?}",
                    path.display(),
                    id
                );
            }
            trust_keys.push(TrustAnchor { key_id: id, public_key: pk });
        }
        for id in parsed.revoked_key_ids {
            let trimmed = id.trim();
            if !trimmed.is_empty() {
                all_revoked.push(trimmed.to_string());
            }
        }
        for cp in parsed.signed_checkpoints {
            let id = cp.checkpoint_id.trim().to_string();
            if id.is_empty() {
                anyhow::bail!(
                    "trust file {} contains a signed_checkpoints entry with empty checkpoint_id",
                    path.display()
                );
            }
            if cp.seq <= 0 {
                anyhow::bail!(
                    "trust file {} signed_checkpoints entry {id:?} must have seq > 0",
                    path.display()
                );
            }
            let hash = validate_hex32(&format!("trust file signed_checkpoints[{id:?}].hash"), &cp.hash)?;
            let digest =
                validate_hex32(&format!("trust file signed_checkpoints[{id:?}].digest"), &cp.digest)?;
            signed_checkpoints.push(PinnedCheckpoint { checkpoint_id: id, seq: cp.seq, hash, digest });
        }
    }

    for path in prev_checkpoints {
        let parsed = load_checkpoint_file(&path)?;
        parsed
            .checkpoint
            .validate_fields()
            .map_err(|e| anyhow::anyhow!("invalid --prev-checkpoint {}: {e}", path.display()))?;
        let recomputed = parsed.checkpoint.digest();
        if let Some(claimed) = parsed.digest.as_deref()
            && !claimed.trim().eq_ignore_ascii_case(&recomputed)
        {
            anyhow::bail!(
                "digest mismatch in --prev-checkpoint {}: file claims {claimed}, recomputed {recomputed}",
                path.display()
            );
        }
        if parsed.checkpoint.class != CheckpointClass::Hub {
            anyhow::bail!(
                "--prev-checkpoint {} has class {:?}; only hub checkpoints can be pinned for ledger verification",
                path.display(),
                parsed.checkpoint.class.as_str()
            );
        }
        let seq = parsed.checkpoint.seq.expect("validated hub checkpoint");
        let hash = parsed.checkpoint.hash.expect("validated hub checkpoint").trim().to_ascii_lowercase();
        signed_checkpoints.push(PinnedCheckpoint {
            checkpoint_id: parsed.checkpoint.checkpoint_id,
            seq,
            hash,
            digest: recomputed,
        });
    }

    Ok(VerifyTrust { anchor, trust_keys, revoked_key_ids: all_revoked, signed_checkpoints })
}

fn build_checkpoint(hub: &Hub, args: CheckpointArgs) -> anyhow::Result<Checkpoint> {
    let class = CheckpointClass::parse(&args.class).map_err(|e| anyhow::anyhow!("{e}"))?;
    let id = args.id.map(|s| s.trim().to_string()).unwrap_or_else(|| ulid::Ulid::generate().to_string());
    let key_id = args.key_id.trim().to_string();
    let signed_at = ua_core::time::now();
    match class {
        CheckpointClass::Hub => {
            if args.org.is_some() {
                anyhow::bail!("--org is only valid for an org checkpoint, not a hub checkpoint");
            }
            if args.derive {
                anyhow::bail!("--derive is only valid for an org checkpoint, not a hub checkpoint");
            }
            let seq = args.seq.ok_or_else(|| anyhow::anyhow!("--seq is required for a hub checkpoint"))?;
            let hash = args
                .hash
                .map(|h| h.trim().to_string())
                .ok_or_else(|| anyhow::anyhow!("--hash is required for a hub checkpoint"))?;
            Ok(Checkpoint {
                checkpoint_id: id,
                class,
                org_id: None,
                seq: Some(seq),
                hash: Some(hash),
                window: None,
                global_from_hash: None,
                global_head_hash: None,
                org_chain_hash: None,
                org_row_count: None,
                key_id,
                signed_at,
            })
        }
        CheckpointClass::Org => {
            if args.seq.is_some() || args.hash.is_some() {
                anyhow::bail!("--seq and --hash are only valid for a hub checkpoint, not an org checkpoint");
            }
            let from = args
                .window_from
                .map(|s| s.trim().to_string())
                .ok_or_else(|| anyhow::anyhow!("--window-from is required for an org checkpoint"))?;
            let to = args
                .window_to
                .map(|s| s.trim().to_string())
                .ok_or_else(|| anyhow::anyhow!("--window-to is required for an org checkpoint"))?;
            let org_id =
                args.org.map(|s| s.trim().to_string()).unwrap_or_else(|| ua_core::DEFAULT_ORG.to_string());
            let (global_from, head, row_count, chain) = if args.derive {
                let prev_head = args.global_from.as_deref().map(str::trim).filter(|s| !s.is_empty());
                let summary =
                    hub.db().read(|c| compute_org_window_checkpoint(c, &org_id, &from, &to, prev_head))?;
                (
                    summary.global_from_hash,
                    summary.global_head_hash,
                    summary.org_row_count,
                    summary.org_chain_hash,
                )
            } else {
                let global_from = args
                    .global_from
                    .map(|s| s.trim().to_string())
                    .ok_or_else(|| anyhow::anyhow!("--global-from is required for an org checkpoint"))?;
                let head = args
                    .head
                    .map(|s| s.trim().to_string())
                    .ok_or_else(|| anyhow::anyhow!("--head is required for an org checkpoint"))?;
                let row_count = args
                    .row_count
                    .ok_or_else(|| anyhow::anyhow!("--row-count is required for an org checkpoint"))?;
                let chain = args
                    .chain
                    .map(|s| s.trim().to_string())
                    .ok_or_else(|| anyhow::anyhow!("--chain is required for an org checkpoint"))?;
                (global_from, head, row_count, chain)
            };
            Ok(Checkpoint {
                checkpoint_id: id,
                class,
                org_id: Some(org_id),
                seq: None,
                hash: None,
                window: Some(Window { start: from, end: to }),
                global_from_hash: Some(global_from),
                global_head_hash: Some(head),
                org_chain_hash: Some(chain),
                org_row_count: Some(row_count),
                key_id,
                signed_at,
            })
        }
    }
}

/// Write a fresh 32-byte Ed25519 seed to `out` as 64 hex characters and return
/// the public key. Refuses to overwrite an existing file. Seed buffers are
/// zeroized on drop.
fn generate_key_file(out: &Path) -> anyhow::Result<String> {
    reject_if_symlink(out, "key file")?;
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *seed);
    let key = SigningKey::from_bytes(&seed);
    let seed_hex = Zeroizing::new(hex::encode(seed.as_slice()));
    write_atomic_file(out, seed_hex.as_bytes(), false)?;
    set_owner_only_file(out)?;
    Ok(hex::encode(key.verifying_key().to_bytes()))
}

/// Sign a checkpoint digest with the seed in `key_file` and return
/// `(signature_hex, public_key_hex)`. Refuses a digest that is not 32 bytes of
/// hex, warns when the key file is readable by others, and zeroizes all seed
/// buffers on drop.
fn sign_digest(key_file: &Path, digest: &str) -> anyhow::Result<(String, String)> {
    let raw = Zeroizing::new(
        std::fs::read(key_file).with_context(|| format!("reading key file {}", key_file.display()))?,
    );
    let seed_str = std::str::from_utf8(&raw).context("key file is not text")?.trim();
    let decoded = Zeroizing::new(hex::decode(seed_str).context("key file is not hex")?);
    if decoded.len() != 32 {
        anyhow::bail!("key file must hold exactly 32 bytes (64 hex characters)");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&decoded);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(key_file)
            && meta.permissions().mode() & 0o077 != 0
        {
            eprintln!("warning: {} is readable by group or others; chmod 600 it", key_file.display());
        }
    }
    let digest_bytes: [u8; 32] = hex::decode(digest.trim())
        .context("digest is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("digest must be 32 bytes (64 hex characters)"))?;
    let key = SigningKey::from_bytes(&seed);
    let public_key = hex::encode(key.verifying_key().to_bytes());
    let signature = hex::encode(key.sign(&digest_bytes).to_bytes());
    Ok((signature, public_key))
}
