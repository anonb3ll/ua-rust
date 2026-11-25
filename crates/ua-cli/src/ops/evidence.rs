//! `ua evidence`: the evidence key store, checkpoint rows, and the offline
//! signing step (`docs/evidence-export.md`, S2).
//!
//! The hub never holds a signing key. `checkpoint` writes a row and prints its
//! digest; the operator signs that digest offline with `sign`; `attach` stores
//! the signature on the row; `verify` recomputes the digest and checks the
//! signature against the key the row names. `key-generate` makes a key file for
//! an operator who does not already have one; the private key never leaves the
//! machine that runs it.

use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Args, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde_json::json;
use ua_store::evidence::{
    Checkpoint, CheckpointClass, CheckpointVerification, Window, checkpoint_attach, checkpoint_write,
    key_add, key_list, key_retire, verify_checkpoint,
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
    /// Generate an Ed25519 key file (0600) and print its public key. Run this
    /// on the operator's machine; the private key never goes to the hub.
    KeyGenerate {
        /// Where to write the 32-byte seed as hex. Refuses to overwrite.
        #[arg(long)]
        out: PathBuf,
    },
    /// Write a checkpoint row and print its digest.
    Checkpoint(CheckpointArgs),
    /// Sign a checkpoint digest offline with a key file. Prints the signature.
    Sign {
        /// Key file: 64 hex characters (a 32-byte Ed25519 seed).
        #[arg(long)]
        key_file: PathBuf,
        /// The checkpoint digest to sign (64 hex characters).
        #[arg(long)]
        digest: String,
        /// Write the signature hex to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Attach an operator's signature to a checkpoint row.
    Attach {
        #[arg(long)]
        checkpoint: String,
        /// Hex-encoded 64-byte Ed25519 signature.
        #[arg(long)]
        signature: String,
    },
    /// Verify a checkpoint's signature against its named key.
    Verify {
        #[arg(long)]
        checkpoint: String,
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
    /// The organization the bundle covers (`org` class; defaults to `default`).
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
}

pub fn run(hub: &Hub, args: EvidenceArgs) -> anyhow::Result<()> {
    match args.cmd {
        EvidenceCmd::KeyAdd { key_id, public_key, note } => {
            let now = ua_core::time::now();
            hub.db().write(|tx| key_add(tx, &key_id, &public_key, &now, note.as_deref()))?;
            println!("{}", json!({ "key_id": key_id, "added": true }));
        }
        EvidenceCmd::KeyList => {
            let keys = hub.db().read(key_list)?;
            println!("{}", serde_json::to_string_pretty(&keys)?);
        }
        EvidenceCmd::KeyRetire { key_id } => {
            let now = ua_core::time::now();
            hub.db().write(|tx| key_retire(tx, &key_id, &now))?;
            println!("{}", json!({ "key_id": key_id, "retired": true }));
        }
        EvidenceCmd::KeyGenerate { out } => {
            let key = generate_key_file(&out)?;
            println!("{}", json!({ "public_key": key, "key_file": out.display().to_string() }));
        }
        EvidenceCmd::Checkpoint(args) => {
            let checkpoint = build_checkpoint(args)?;
            let now = ua_core::time::now();
            let digest = hub.db().write(|tx| checkpoint_write(tx, &checkpoint, &now))?;
            println!(
                "{}",
                json!({
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "class": checkpoint.class.as_str(),
                    "key_id": checkpoint.key_id,
                    "digest": digest,
                })
            );
        }
        EvidenceCmd::Sign { key_file, digest, out } => {
            let sig = sign_digest(&key_file, &digest)?;
            match out {
                Some(path) => {
                    write_atomic_file(&path, sig.as_bytes(), false)?;
                    println!("{}", json!({ "signature": sig, "out": path.display().to_string() }));
                }
                None => println!("{sig}"),
            }
        }
        EvidenceCmd::Attach { checkpoint, signature } => {
            hub.db().write(|tx| checkpoint_attach(tx, &checkpoint, &signature))?;
            println!("{}", json!({ "checkpoint_id": checkpoint, "attached": true }));
        }
        EvidenceCmd::Verify { checkpoint } => {
            let verdict = hub.db().read(|c| verify_checkpoint(c, &checkpoint))?;
            println!("{}", serde_json::to_string_pretty(&verdict)?);
            // A non-valid verdict is not authorship: exit non-zero so a script
            // cannot treat an unverified checkpoint as signed.
            if verdict != CheckpointVerification::Valid {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}

fn build_checkpoint(args: CheckpointArgs) -> anyhow::Result<Checkpoint> {
    let class = CheckpointClass::parse(&args.class).map_err(|e| anyhow::anyhow!("{e}"))?;
    let id = args.id.unwrap_or_else(|| ulid::Ulid::generate().to_string());
    let signed_at = ua_core::time::now();
    match class {
        CheckpointClass::Hub => {
            let seq = args.seq.ok_or_else(|| anyhow::anyhow!("--seq is required for a hub checkpoint"))?;
            let hash = args.hash.ok_or_else(|| anyhow::anyhow!("--hash is required for a hub checkpoint"))?;
            Ok(Checkpoint {
                checkpoint_id: id,
                class,
                org_id: args.org,
                seq: Some(seq),
                hash: Some(hash),
                window: None,
                global_from_hash: None,
                global_head_hash: None,
                org_chain_hash: None,
                org_row_count: None,
                key_id: args.key_id,
                signed_at,
            })
        }
        CheckpointClass::Org => {
            let from = args
                .window_from
                .ok_or_else(|| anyhow::anyhow!("--window-from is required for an org checkpoint"))?;
            let to = args
                .window_to
                .ok_or_else(|| anyhow::anyhow!("--window-to is required for an org checkpoint"))?;
            let global_from = args
                .global_from
                .ok_or_else(|| anyhow::anyhow!("--global-from is required for an org checkpoint"))?;
            let head =
                args.head.ok_or_else(|| anyhow::anyhow!("--head is required for an org checkpoint"))?;
            let row_count = args
                .row_count
                .ok_or_else(|| anyhow::anyhow!("--row-count is required for an org checkpoint"))?;
            let chain =
                args.chain.ok_or_else(|| anyhow::anyhow!("--chain is required for an org checkpoint"))?;
            Ok(Checkpoint {
                checkpoint_id: id,
                class,
                org_id: Some(args.org.unwrap_or_else(|| ua_core::DEFAULT_ORG.to_string())),
                seq: None,
                hash: None,
                window: Some(Window { start: from, end: to }),
                global_from_hash: Some(global_from),
                global_head_hash: Some(head),
                org_chain_hash: Some(chain),
                org_row_count: Some(row_count),
                key_id: args.key_id,
                signed_at,
            })
        }
    }
}

/// Write a fresh 32-byte Ed25519 seed to `out` as 64 hex characters and return
/// the public key. Refuses to overwrite an existing file.
fn generate_key_file(out: &Path) -> anyhow::Result<String> {
    reject_if_symlink(out, "key file")?;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    write_atomic_file(out, hex::encode(seed).as_bytes(), false)?;
    set_owner_only_file(out)?;
    Ok(hex::encode(key.verifying_key().to_bytes()))
}

/// Sign a checkpoint digest with the seed in `key_file`. Refuses a digest that
/// is not 32 bytes of hex, and warns when the key file is readable by others.
fn sign_digest(key_file: &Path, digest: &str) -> anyhow::Result<String> {
    let bytes =
        std::fs::read(key_file).with_context(|| format!("reading key file {}", key_file.display()))?;
    let text = String::from_utf8(bytes).context("key file is not text")?;
    let seed_hex = text.trim();
    let seed: [u8; 32] = hex::decode(seed_hex)
        .context("key file is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key file must hold exactly 32 bytes (64 hex characters)"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(key_file)
            && meta.permissions().mode() & 0o077 != 0
        {
            eprintln!("warning: {} is readable by group or others; chmod 600 it", key_file.display());
        }
    }
    let digest_bytes: [u8; 32] = hex::decode(digest)
        .context("digest is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("digest must be 32 bytes (64 hex characters)"))?;
    let key = SigningKey::from_bytes(&seed);
    Ok(hex::encode(key.sign(&digest_bytes).to_bytes()))
}
