//! Evidence checkpoint signing and the public-key store.
//!
//! Red tier: ledger semantics (`docs/evidence-export.md`, S2). This module
//! owns the part of the evidence format that decides who authored a bundle:
//! the checkpoint digest and the key that signs it.
//!
//! The hub never holds a private key. It writes a checkpoint row containing
//! the canonical digest; the operator signs that digest offline and stores the
//! signature on the row. A verifier recomputes the digest from the stored
//! fields and checks the signature against the public key the checkpoint names.
//! A compromised hub therefore cannot mint a bundle it did not sign, because
//! it never had the key.
//!
//! # Digest form
//!
//! The signed value is the raw 32-byte SHA-256 of one canonical JSON object.
//! The object carries the `format` tag `ua.evidence.checkpoint.v1`, the fields
//! `docs/evidence-export.md` names for the checkpoint's class, keys in sorted
//! order, `,`/`:` separators, and a literal `null` for a field that does not
//! apply. Strings are escaped the way Python's
//! `json.dumps(ensure_ascii=True)` escapes them, so the encoding is
//! byte-stable across languages.
//!
//! - class `hub`: `{class, format, hash, key_id, org_id, seq, signed_at}`
//! - class `org`: `{class, format, global_from_hash, global_head_hash, key_id,
//!   org_chain_hash, org_id, org_row_count, signed_at, window}`
//!
//! `window` is the object `{"end": …, "start": …}` with the same sorted-key
//! encoding. The signature is Ed25519 over the raw digest bytes, not over the
//! hex text.
//!
//! # Keys
//!
//! Public keys only, hex-encoded 32-byte Ed25519 keys. A retired key stays in
//! the table so bundles signed before the rotation still verify; retirement
//! only stops new checkpoints from naming it. A revoked key is refused
//! outright: `revoked_at` is set once and a checkpoint naming it no longer
//! verifies. A checkpoint naming a key the store does not hold is a
//! verification failure, never a pass.
//!
//! # Trust anchor
//!
//! [`verify_checkpoint`] takes an optional [`TrustAnchor`] the verifier
//! obtained out of band. Without one it can only report that the signature
//! matches the key stored in the same database it protects — not authorship.
//! The caller must pass a pinned key to get [`CheckpointVerification::Valid`].

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};

use crate::db::WriteTx;
use crate::ledger::py_json_str;
use crate::schema::SchemaPart;

/// The evidence key store and checkpoint table.
pub const KEY_STORE_PART: SchemaPart = SchemaPart {
    name: "evidence_key_store.v1",
    sql: "
CREATE TABLE IF NOT EXISTS evidence_key (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retired_at TEXT,
    revoked_at TEXT,
    note TEXT
);
CREATE TABLE IF NOT EXISTS evidence_checkpoint (
    checkpoint_id TEXT PRIMARY KEY,
    class TEXT NOT NULL CHECK (class IN ('hub', 'org')),
    org_id TEXT,
    seq INTEGER,
    hash TEXT,
    window_start TEXT,
    window_end TEXT,
    global_from_hash TEXT,
    global_head_hash TEXT,
    org_row_count INTEGER,
    org_chain_hash TEXT,
    key_id TEXT NOT NULL,
    signed_at TEXT NOT NULL,
    digest TEXT NOT NULL,
    signature TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (key_id) REFERENCES evidence_key(key_id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_checkpoint_org
    ON evidence_checkpoint(org_id, created_at);
CREATE TRIGGER IF NOT EXISTS evidence_key_no_delete
BEFORE DELETE ON evidence_key
BEGIN SELECT RAISE(ABORT, 'evidence_key rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_key_immutable
BEFORE UPDATE ON evidence_key
WHEN NOT (
    OLD.key_id IS NEW.key_id
    AND OLD.algorithm IS NEW.algorithm
    AND OLD.public_key IS NEW.public_key
    AND OLD.created_at IS NEW.created_at
    AND OLD.note IS NEW.note
    AND (OLD.retired_at IS NEW.retired_at
         OR (OLD.retired_at IS NULL AND NEW.retired_at IS NOT NULL))
    AND (OLD.revoked_at IS NEW.revoked_at
         OR (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL))
)
BEGIN SELECT RAISE(ABORT, 'evidence_key fields are immutable; retired_at and revoked_at may be set once'); END;
CREATE TRIGGER IF NOT EXISTS evidence_checkpoint_no_delete
BEFORE DELETE ON evidence_checkpoint
BEGIN SELECT RAISE(ABORT, 'evidence_checkpoint rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_checkpoint_immutable
BEFORE UPDATE ON evidence_checkpoint
WHEN NOT (
    OLD.checkpoint_id IS NEW.checkpoint_id
    AND OLD.class IS NEW.class
    AND OLD.org_id IS NEW.org_id
    AND OLD.seq IS NEW.seq
    AND OLD.hash IS NEW.hash
    AND OLD.window_start IS NEW.window_start
    AND OLD.window_end IS NEW.window_end
    AND OLD.global_from_hash IS NEW.global_from_hash
    AND OLD.global_head_hash IS NEW.global_head_hash
    AND OLD.org_row_count IS NEW.org_row_count
    AND OLD.org_chain_hash IS NEW.org_chain_hash
    AND OLD.key_id IS NEW.key_id
    AND OLD.signed_at IS NEW.signed_at
    AND OLD.digest IS NEW.digest
    AND OLD.created_at IS NEW.created_at
    AND (OLD.signature IS NEW.signature
         OR (OLD.signature IS NULL AND NEW.signature IS NOT NULL))
)
BEGIN SELECT RAISE(ABORT, 'evidence_checkpoint rows are immutable; only a signature may be set once'); END;
",
};

/// The only signing algorithm this build accepts.
pub const ALGORITHM_ED25519: &str = "ed25519";

/// The domain tag carried inside every signed checkpoint digest. It is signed
/// so a signature over a checkpoint cannot be replayed as a signature over a
/// different object type, and so the format can be versioned without guessing.
pub const CHECKPOINT_FORMAT: &str = "ua.evidence.checkpoint.v1";

/// A checkpoint's bundle class. The two classes carry different signed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckpointClass {
    /// A whole-hub bundle.
    Hub,
    /// An organization-scoped bundle.
    Org,
}

impl CheckpointClass {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckpointClass::Hub => "hub",
            CheckpointClass::Org => "org",
        }
    }

    pub fn parse(s: &str) -> UaResult<Self> {
        match s {
            "hub" => Ok(CheckpointClass::Hub),
            "org" => Ok(CheckpointClass::Org),
            other => {
                Err(UaError::invalid(format!("checkpoint class must be \"hub\" or \"org\", got {other:?}")))
            }
        }
    }
}

/// The time bounds of an `org` checkpoint's window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    pub start: String,
    pub end: String,
}

/// One checkpoint row. Fields not used by the class stay `None` and encode as
/// `null` in the digest, so the digest never depends on which optional fields
/// a caller happened to populate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub checkpoint_id: String,
    pub class: CheckpointClass,
    pub org_id: Option<String>,
    /// `hub` only: the ledger sequence the checkpoint covers.
    pub seq: Option<i64>,
    /// `hub` only: the entry hash at `seq`.
    pub hash: Option<String>,
    /// `org` only: the window's time bounds.
    pub window: Option<Window>,
    /// `org` only: the last global entry hash before the window.
    pub global_from_hash: Option<String>,
    /// `org` only: the global entry hash at the window's end.
    pub global_head_hash: Option<String>,
    /// `org` only: the cumulative row count at the window's end.
    pub org_row_count: Option<i64>,
    /// `org` only: the chain hash over the window's entries.
    pub org_chain_hash: Option<String>,
    pub key_id: String,
    pub signed_at: String,
}

/// A public key row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceKey {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub created_at: String,
    pub retired_at: Option<String>,
    pub revoked_at: Option<String>,
    pub note: Option<String>,
}

/// A key the verifier obtained out of band. This is the only thing that turns
/// a stored-key match into authorship: the key in the checkpoint's own
/// database is attacker-controlled, so the verifier must pin one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchor {
    pub key_id: String,
    pub public_key: String,
}

/// What verification concluded. A caller must not treat anything but
/// [`CheckpointVerification::Valid`] as authorship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CheckpointVerification {
    /// The signature is present and checks out against a pinned key.
    Valid,
    /// The signature matches the key in the same store, but no trust anchor
    /// was supplied. This is not authorship: the key row could have been
    /// swapped with the checkpoint.
    ValidInStoreOnly { key_id: String },
    /// The row exists but no signature was attached yet.
    Unsigned,
    /// The named key is not in the store.
    UnknownKey { key_id: String },
    /// The named key is revoked: a checkpoint naming it no longer verifies.
    KeyRevoked { key_id: String },
    /// The checkpoint names a different key than the pinned anchor.
    KeyMismatch { expected: String, found: String },
    /// The signature does not verify over the recomputed digest.
    InvalidSignature,
    /// The stored digest does not match the fields (a row edited after signing).
    DigestMismatch,
    /// A hub checkpoint does not match the ledger chain it claims to cover.
    LedgerMismatch { reason: String },
    /// An `org` checkpoint cannot be checked against the ledger in this build.
    OrgClassNotVerifiable,
}

impl Checkpoint {
    /// The canonical digest input: the class's fields only, sorted keys, nulls
    /// explicit. This is the exact byte string whose SHA-256 is signed.
    pub fn digest_input(&self) -> String {
        let mut out = String::new();
        out.push('{');
        match self.class {
            CheckpointClass::Hub => {
                // Sorted: class, format, hash, key_id, org_id, seq, signed_at.
                field_str(&mut out, "class", self.class.as_str(), true);
                field_str(&mut out, "format", CHECKPOINT_FORMAT, false);
                field_opt(&mut out, "hash", self.hash.as_deref(), false);
                field_str(&mut out, "key_id", &self.key_id, false);
                field_opt(&mut out, "org_id", self.org_id.as_deref(), false);
                field_int(&mut out, "seq", self.seq, false);
                field_str(&mut out, "signed_at", &self.signed_at, false);
            }
            CheckpointClass::Org => {
                // Sorted: class, format, global_from_hash, global_head_hash,
                // key_id, org_chain_hash, org_id, org_row_count, signed_at,
                // window.
                field_str(&mut out, "class", self.class.as_str(), true);
                field_str(&mut out, "format", CHECKPOINT_FORMAT, false);
                field_opt(&mut out, "global_from_hash", self.global_from_hash.as_deref(), false);
                field_opt(&mut out, "global_head_hash", self.global_head_hash.as_deref(), false);
                field_str(&mut out, "key_id", &self.key_id, false);
                field_opt(&mut out, "org_chain_hash", self.org_chain_hash.as_deref(), false);
                field_opt(&mut out, "org_id", self.org_id.as_deref(), false);
                field_int(&mut out, "org_row_count", self.org_row_count, false);
                field_str(&mut out, "signed_at", &self.signed_at, false);
                match &self.window {
                    Some(w) => {
                        out.push_str(",\"window\":{");
                        field_str(&mut out, "end", &w.end, true);
                        field_str(&mut out, "start", &w.start, false);
                        out.push('}');
                    }
                    None => out.push_str(",\"window\":null"),
                }
            }
        }
        out.push('}');
        out
    }

    /// The hex SHA-256 of [`Self::digest_input`]. This is the value the
    /// operator signs and the value stored on the row.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.digest_input().as_bytes()))
    }
}

fn field_str(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push(',');
    }
    py_json_str(out, key);
    out.push(':');
    py_json_str(out, value);
}

fn field_opt(out: &mut String, key: &str, value: Option<&str>, first: bool) {
    if !first {
        out.push(',');
    }
    py_json_str(out, key);
    out.push(':');
    match value {
        Some(v) => py_json_str(out, v),
        None => out.push_str("null"),
    }
}

fn field_int(out: &mut String, key: &str, value: Option<i64>, first: bool) {
    if !first {
        out.push(',');
    }
    py_json_str(out, key);
    out.push(':');
    match value {
        Some(v) => out.push_str(&v.to_string()),
        None => out.push_str("null"),
    }
}

fn row_to_key(r: &Row<'_>) -> rusqlite::Result<EvidenceKey> {
    Ok(EvidenceKey {
        key_id: r.get(0)?,
        algorithm: r.get(1)?,
        public_key: r.get(2)?,
        created_at: r.get(3)?,
        retired_at: r.get(4)?,
        revoked_at: r.get(5)?,
        note: r.get(6)?,
    })
}

fn row_to_checkpoint(r: &Row<'_>) -> rusqlite::Result<Checkpoint> {
    let class: String = r.get(1)?;
    let window_start: Option<String> = r.get(5)?;
    let window_end: Option<String> = r.get(6)?;
    Ok(Checkpoint {
        checkpoint_id: r.get(0)?,
        class: CheckpointClass::parse(&class).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())),
            )
        })?,
        org_id: r.get(2)?,
        seq: r.get(3)?,
        hash: r.get(4)?,
        window: match (window_start, window_end) {
            (Some(start), Some(end)) => Some(Window { start, end }),
            _ => None,
        },
        global_from_hash: r.get(7)?,
        global_head_hash: r.get(8)?,
        org_row_count: r.get(9)?,
        org_chain_hash: r.get(10)?,
        key_id: r.get(11)?,
        signed_at: r.get(12)?,
    })
}

/// Add a public key. Refuses a duplicate id and a key whose hex is not a valid
/// 32-byte Ed25519 point. The hex is stored lowercase so a pinned anchor and
/// the stored row compare byte-for-byte.
pub fn key_add(
    tx: &mut WriteTx<'_>,
    key_id: &str,
    public_key_hex: &str,
    created_at: &str,
    note: Option<&str>,
) -> UaResult<()> {
    let normalized = public_key_hex.trim().to_ascii_lowercase();
    let bytes =
        hex::decode(&normalized).map_err(|_| UaError::invalid("public key must be hex-encoded"))?;
    if bytes.len() != 32 {
        return Err(UaError::invalid(format!("an Ed25519 public key is 32 bytes, got {}", bytes.len())));
    }
    let mut point = [0u8; 32];
    point.copy_from_slice(&bytes);
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&point)
        .map_err(|e| UaError::invalid(format!("public key is not a valid Ed25519 point: {e}")))?;
    if verifying.is_weak() {
        return Err(UaError::invalid("public key is a weak Ed25519 point"));
    }
    let exists: Option<String> = tx
        .query_row("SELECT key_id FROM evidence_key WHERE key_id = ?1", [key_id], |r| r.get(0))
        .optional()?;
    if exists.is_some() {
        return Err(UaError::conflict(format!("evidence key {key_id:?} already exists")));
    }
    tx.execute(
        "INSERT INTO evidence_key (key_id, algorithm, public_key, created_at, retired_at, revoked_at, note) \
         VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5)",
        params![key_id, ALGORITHM_ED25519, normalized, created_at, note],
    )?;
    crate::ledger::append(
        tx,
        crate::EventInput::new(
            ua_core::DEFAULT_ORG,
            "evidence.key.added",
            serde_json::json!({ "key_id": key_id, "algorithm": ALGORITHM_ED25519 }),
        )
        .by("evidence"),
    )?;
    Ok(())
}

/// Retire a key: it stays in the store so old checkpoints verify, but new
/// checkpoints may not name it. Retirement is not revocation.
pub fn key_retire(tx: &mut WriteTx<'_>, key_id: &str, retired_at: &str) -> UaResult<()> {
    let changed = tx.execute(
        "UPDATE evidence_key SET retired_at = ?2 WHERE key_id = ?1 AND retired_at IS NULL",
        params![key_id, retired_at],
    )?;
    if changed == 0 {
        return Err(UaError::not_found(format!(
            "no active evidence key {key_id:?} (already retired or unknown)"
        )));
    }
    crate::ledger::append(
        tx,
        crate::EventInput::new(
            ua_core::DEFAULT_ORG,
            "evidence.key.retired",
            serde_json::json!({ "key_id": key_id, "retired_at": retired_at }),
        )
        .by("evidence"),
    )?;
    Ok(())
}

/// Revoke a key: the key is compromised. Unlike retirement, a revoked key is
/// refused for new checkpoints and every checkpoint naming it no longer
/// verifies. Revocation is set once and cannot be undone.
pub fn key_revoke(tx: &mut WriteTx<'_>, key_id: &str, revoked_at: &str) -> UaResult<()> {
    let changed = tx.execute(
        "UPDATE evidence_key SET revoked_at = ?2 WHERE key_id = ?1 AND revoked_at IS NULL",
        params![key_id, revoked_at],
    )?;
    if changed == 0 {
        return Err(UaError::not_found(format!(
            "no unrevoked evidence key {key_id:?} (already revoked or unknown)"
        )));
    }
    crate::ledger::append(
        tx,
        crate::EventInput::new(
            ua_core::DEFAULT_ORG,
            "evidence.key.revoked",
            serde_json::json!({ "key_id": key_id, "revoked_at": revoked_at }),
        )
        .by("evidence"),
    )?;
    Ok(())
}

/// Read one key.
pub fn key_get(conn: &Connection, key_id: &str) -> UaResult<Option<EvidenceKey>> {
    let key = conn
        .query_row(
            "SELECT key_id, algorithm, public_key, created_at, retired_at, revoked_at, note \
             FROM evidence_key WHERE key_id = ?1",
            [key_id],
            row_to_key,
        )
        .optional()?;
    Ok(key)
}

/// List every key, active first.
pub fn key_list(conn: &Connection) -> UaResult<Vec<EvidenceKey>> {
    let mut stmt = conn.prepare(
        "SELECT key_id, algorithm, public_key, created_at, retired_at, revoked_at, note \
         FROM evidence_key ORDER BY revoked_at IS NOT NULL, retired_at IS NOT NULL, key_id",
    )?;
    let rows = stmt.query_map([], row_to_key)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Write a checkpoint row and return its digest. The key must exist and be
/// neither retired nor revoked; a retired key would undo a rotation, and a
/// revoked key is compromised.
pub fn checkpoint_write(tx: &mut WriteTx<'_>, checkpoint: &Checkpoint, created_at: &str) -> UaResult<String> {
    let key = key_get(tx, &checkpoint.key_id)?.ok_or_else(|| {
        UaError::not_found(format!("evidence key {:?} is not in the store", checkpoint.key_id))
    })?;
    if key.retired_at.is_some() {
        return Err(UaError::conflict(format!(
            "evidence key {:?} is retired; a new checkpoint may not name it",
            checkpoint.key_id
        )));
    }
    if key.revoked_at.is_some() {
        return Err(UaError::conflict(format!(
            "evidence key {:?} is revoked; a new checkpoint may not name it",
            checkpoint.key_id
        )));
    }
    let digest = checkpoint.digest();
    tx.execute(
        "INSERT INTO evidence_checkpoint \
         (checkpoint_id, class, org_id, seq, hash, window_start, window_end, global_from_hash, \
          global_head_hash, org_row_count, org_chain_hash, key_id, signed_at, digest, signature, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, ?15)",
        params![
            checkpoint.checkpoint_id,
            checkpoint.class.as_str(),
            checkpoint.org_id,
            checkpoint.seq,
            checkpoint.hash,
            checkpoint.window.as_ref().map(|w| w.start.as_str()),
            checkpoint.window.as_ref().map(|w| w.end.as_str()),
            checkpoint.global_from_hash,
            checkpoint.global_head_hash,
            checkpoint.org_row_count,
            checkpoint.org_chain_hash,
            checkpoint.key_id,
            checkpoint.signed_at,
            digest,
            created_at,
        ],
    )?;
    crate::ledger::append(
        tx,
        crate::EventInput::new(
            ua_core::DEFAULT_ORG,
            "evidence.checkpoint.written",
            serde_json::json!({
                "checkpoint_id": checkpoint.checkpoint_id,
                "class": checkpoint.class.as_str(),
                "key_id": checkpoint.key_id,
            }),
        )
        .by("evidence"),
    )?;
    Ok(digest)
}

/// Attach an operator's signature to a checkpoint. Refuses a second signature:
/// a row is signed once, and a re-signature would hide which key attested it.
/// A retired or revoked key cannot be used to sign a checkpoint.
pub fn checkpoint_attach(tx: &mut WriteTx<'_>, checkpoint_id: &str, signature_hex: &str) -> UaResult<()> {
    let bytes = hex::decode(signature_hex).map_err(|_| UaError::invalid("signature must be hex-encoded"))?;
    if bytes.len() != 64 {
        return Err(UaError::invalid(format!("an Ed25519 signature is 64 bytes, got {}", bytes.len())));
    }
    let existing: Option<Option<String>> = tx
        .query_row(
            "SELECT signature FROM evidence_checkpoint WHERE checkpoint_id = ?1",
            [checkpoint_id],
            |r| r.get(0),
        )
        .optional()?;
    match existing {
        None => return Err(UaError::not_found(format!("no checkpoint {checkpoint_id:?}"))),
        Some(Some(_)) => {
            return Err(UaError::conflict(format!(
                "checkpoint {checkpoint_id:?} already carries a signature"
            )));
        }
        Some(None) => {}
    }
    let checkpoint = checkpoint_get(tx, checkpoint_id)?
        .ok_or_else(|| UaError::not_found(format!("no checkpoint {checkpoint_id:?}")))?;
    let key = key_get(tx, &checkpoint.key_id)?
        .ok_or_else(|| UaError::not_found(format!("evidence key {:?} is not in the store", checkpoint.key_id)))?;
    if key.retired_at.is_some() {
        return Err(UaError::conflict(format!(
            "evidence key {:?} is retired; its checkpoint cannot be signed",
            checkpoint.key_id
        )));
    }
    if key.revoked_at.is_some() {
        return Err(UaError::conflict(format!(
            "evidence key {:?} is revoked; its checkpoint cannot be signed",
            checkpoint.key_id
        )));
    }
    tx.execute(
        "UPDATE evidence_checkpoint SET signature = ?2 WHERE checkpoint_id = ?1",
        params![checkpoint_id, signature_hex],
    )?;
    crate::ledger::append(
        tx,
        crate::EventInput::new(
            ua_core::DEFAULT_ORG,
            "evidence.checkpoint.signed",
            serde_json::json!({
                "checkpoint_id": checkpoint_id,
                "key_id": checkpoint.key_id,
            }),
        )
        .by("evidence"),
    )?;
    Ok(())
}

/// Read one checkpoint row (without its signature).
pub fn checkpoint_get(conn: &Connection, checkpoint_id: &str) -> UaResult<Option<Checkpoint>> {
    let row = conn
        .query_row(
            "SELECT checkpoint_id, class, org_id, seq, hash, window_start, window_end, \
             global_from_hash, global_head_hash, org_row_count, org_chain_hash, key_id, signed_at \
             FROM evidence_checkpoint WHERE checkpoint_id = ?1",
            [checkpoint_id],
            row_to_checkpoint,
        )
        .optional()?;
    Ok(row)
}

/// The stored signature and digest of a checkpoint, or `None` when the row is
/// absent. `signature` is `None` until the operator attaches one.
pub fn checkpoint_signature(
    conn: &Connection,
    checkpoint_id: &str,
) -> UaResult<Option<(String, Option<String>)>> {
    let row = conn
        .query_row(
            "SELECT digest, signature FROM evidence_checkpoint WHERE checkpoint_id = ?1",
            [checkpoint_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row)
}

/// Verify a checkpoint's stored signature and, for a hub checkpoint, its
/// ledger anchor. Recomputes the digest from the fields, so a row edited after
/// signing fails as [`CheckpointVerification::DigestMismatch`].
///
/// `anchor` is the key the verifier obtained out of band. Without it the
/// result is [`CheckpointVerification::ValidInStoreOnly`]: the signature
/// matches the key in the same database the checkpoint protects, which is not
/// authorship. A pinned key must be supplied for
/// [`CheckpointVerification::Valid`].
pub fn verify_checkpoint(
    conn: &Connection,
    checkpoint_id: &str,
    anchor: Option<&TrustAnchor>,
) -> UaResult<CheckpointVerification> {
    let Some(checkpoint) = checkpoint_get(conn, checkpoint_id)? else {
        return Err(UaError::not_found(format!("no checkpoint {checkpoint_id:?}")));
    };
    let Some((stored_digest, signature)) = checkpoint_signature(conn, checkpoint_id)? else {
        return Err(UaError::not_found(format!("no checkpoint {checkpoint_id:?}")));
    };
    if checkpoint.digest() != stored_digest {
        return Ok(CheckpointVerification::DigestMismatch);
    }
    if checkpoint.class == CheckpointClass::Org {
        return Ok(CheckpointVerification::OrgClassNotVerifiable);
    }
    if let Some(reason) = ledger_mismatch(conn, &checkpoint)? {
        return Ok(CheckpointVerification::LedgerMismatch { reason });
    }
    let Some(signature) = signature else {
        return Ok(CheckpointVerification::Unsigned);
    };
    let Some(key) = key_get(conn, &checkpoint.key_id)? else {
        return Ok(CheckpointVerification::UnknownKey { key_id: checkpoint.key_id.clone() });
    };
    if key.algorithm != ALGORITHM_ED25519 {
        return Ok(CheckpointVerification::InvalidSignature);
    }
    if key.revoked_at.is_some() {
        return Ok(CheckpointVerification::KeyRevoked { key_id: checkpoint.key_id.clone() });
    }
    match anchor {
        Some(anchor) => {
            if anchor.key_id != checkpoint.key_id {
                return Ok(CheckpointVerification::KeyMismatch {
                    expected: checkpoint.key_id.clone(),
                    found: anchor.key_id.clone(),
                });
            }
            if !anchor.public_key.eq_ignore_ascii_case(&key.public_key) {
                return Ok(CheckpointVerification::KeyMismatch {
                    expected: key.public_key.clone(),
                    found: anchor.public_key.clone(),
                });
            }
            match verify_ed25519(&anchor.public_key, &stored_digest, &signature) {
                Ok(()) => Ok(CheckpointVerification::Valid),
                Err(_) => Ok(CheckpointVerification::InvalidSignature),
            }
        }
        None => match verify_ed25519(&key.public_key, &stored_digest, &signature) {
            Ok(()) => Ok(CheckpointVerification::ValidInStoreOnly { key_id: checkpoint.key_id.clone() }),
            Err(_) => Ok(CheckpointVerification::InvalidSignature),
        },
    }
}

/// Check a hub checkpoint against the ledger it claims to cover. Returns the
/// reason it does not match, or `None` when the row and the chain up to it are
/// intact. A rewritten or invented `seq`/`hash` therefore cannot verify.
fn ledger_mismatch(conn: &Connection, checkpoint: &Checkpoint) -> UaResult<Option<String>> {
    let Some(seq) = checkpoint.seq else {
        return Ok(Some("hub checkpoint carries no seq".into()));
    };
    let Some(hash) = checkpoint.hash.as_deref() else {
        return Ok(Some("hub checkpoint carries no hash".into()));
    };
    let Some(entry) = crate::ledger::entry_hash_at(conn, seq)? else {
        return Ok(Some(format!("event_log has no row at seq {seq}")));
    };
    if !entry.eq_ignore_ascii_case(hash) {
        return Ok(Some(format!(
            "event_log[{seq}].entry_hash does not match the checkpoint hash"
        )));
    }
    let report = crate::ledger::verify_through(conn, seq)?;
    if !report.ok {
        return Ok(Some(report.reason.unwrap_or_else(|| "ledger chain does not verify".into())));
    }
    Ok(None)
}

/// Verify an Ed25519 signature over the raw digest bytes. Public so the offline
/// signing CLI can check a signature before storing it.
pub fn verify_ed25519(public_key_hex: &str, digest_hex: &str, signature_hex: &str) -> UaResult<()> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let key_bytes: [u8; 32] = hex::decode(public_key_hex)
        .map_err(|_| UaError::invalid("public key must be hex"))?
        .try_into()
        .map_err(|_| UaError::invalid("public key must be 32 bytes"))?;
    let digest: [u8; 32] = hex::decode(digest_hex)
        .map_err(|_| UaError::invalid("digest must be hex"))?
        .try_into()
        .map_err(|_| UaError::invalid("digest must be 32 bytes"))?;
    let sig_bytes: [u8; 64] = hex::decode(signature_hex)
        .map_err(|_| UaError::invalid("signature must be hex"))?
        .try_into()
        .map_err(|_| UaError::invalid("signature must be 64 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| UaError::invalid(format!("not an Ed25519 public key: {e}")))?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify_strict(&digest, &signature)
        .map_err(|e| UaError::denied("signature_invalid", format!("signature does not verify: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::schema::apply;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;

    fn open() -> (tempfile::TempDir, Db) {
        let dir = tempdir().unwrap();
        let db = Db::open(
            &dir.path().join("hub.db"),
            &[KEY_STORE_PART, crate::ledger::SCHEMA],
        )
        .unwrap();
        (dir, db)
    }

    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    /// Append one event and return its seq and entry hash.
    fn ledger_row(db: &Db) -> (i64, String) {
        db.write(|tx| {
            let event = crate::ledger::append(
                tx,
                crate::EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "test.event",
                    serde_json::json!({"n": 1}),
                ),
            )?
            .expect("event appended");
            Ok((event.seq, event.entry_hash.expect("hashed")))
        })
        .unwrap()
    }

    fn hub_checkpoint(key_id: &str, seq: i64, hash: &str) -> Checkpoint {
        Checkpoint {
            checkpoint_id: "cp-1".into(),
            class: CheckpointClass::Hub,
            org_id: Some("default".into()),
            seq: Some(seq),
            hash: Some(hash.into()),
            window: None,
            global_from_hash: None,
            global_head_hash: None,
            org_row_count: None,
            org_chain_hash: None,
            key_id: key_id.into(),
            signed_at: "2026-11-25T00:00:00Z".into(),
        }
    }

    fn signed_checkpoint(db: &Db, sk: &SigningKey, key_id: &str, seq: i64, hash: &str) -> String {
        let cp = hub_checkpoint(key_id, seq, hash);
        let digest = db.write(|tx| checkpoint_write(tx, &cp, "now")).unwrap();
        let sig = hex::encode(sk.sign(&hex::decode(&digest).unwrap()).to_bytes());
        db.write(|tx| checkpoint_attach(tx, "cp-1", &sig)).unwrap();
        digest
    }

    #[test]
    fn digest_is_stable_and_covers_only_the_class_fields() {
        let cp = hub_checkpoint("k1", 42, "abc123");
        let first = cp.digest();
        assert_eq!(first, cp.digest(), "digest must be deterministic");
        assert_eq!(first.len(), 64);
        let input = cp.digest_input();
        assert!(
            input.starts_with("{\"class\":\"hub\",\"format\":\"ua.evidence.checkpoint.v1\",\"hash\":"),
            "{input}"
        );
        assert!(!input.contains("window"), "hub digest must not carry org fields: {input}");
        let mut other = cp.clone();
        other.window = Some(Window { start: "a".into(), end: "b".into() });
        assert_eq!(first, other.digest(), "hub digest ignores org-only fields");
    }

    #[test]
    fn org_digest_carries_window_and_chain_fields() {
        let cp = Checkpoint {
            checkpoint_id: "cp-2".into(),
            class: CheckpointClass::Org,
            org_id: Some("acme".into()),
            seq: None,
            hash: None,
            window: Some(Window {
                start: "2026-11-01T00:00:00Z".into(),
                end: "2026-11-02T00:00:00Z".into(),
            }),
            global_from_hash: Some("g0".into()),
            global_head_hash: Some("g1".into()),
            org_row_count: Some(9),
            org_chain_hash: Some("c9".into()),
            key_id: "k1".into(),
            signed_at: "2026-11-25T00:00:00Z".into(),
        };
        let input = cp.digest_input();
        assert!(input.contains("\"format\":\"ua.evidence.checkpoint.v1\""), "{input}");
        assert!(
            input.contains("\"window\":{\"end\":\"2026-11-02T00:00:00Z\",\"start\":\"2026-11-01T00:00:00Z\"}"),
            "{input}"
        );
        assert!(input.contains("\"org_row_count\":9"), "{input}");
        assert!(!input.contains("\"seq\""), "org digest must not carry seq: {input}");
    }

    #[test]
    fn key_store_round_trip_and_retirement() {
        let (_dir, db) = open();
        let (_sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "2026-11-25T00:00:00Z", Some("test"))).unwrap();
        let key = db.read(|c| key_get(c, "k1")).unwrap().unwrap();
        assert_eq!(key.algorithm, "ed25519");
        assert_eq!(key.public_key, pk);
        assert!(key.retired_at.is_none());
        assert!(key.revoked_at.is_none());

        db.write(|tx| key_retire(tx, "k1", "2026-11-26T00:00:00Z")).unwrap();
        assert!(db.read(|c| key_get(c, "k1")).unwrap().unwrap().retired_at.is_some());
        let (seq, hash) = ledger_row(&db);
        let err = db
            .write(|tx| checkpoint_write(tx, &hub_checkpoint("k1", seq, &hash), "2026-11-27T00:00:00Z"))
            .unwrap_err();
        assert!(err.to_string().contains("retired"), "{err}");
    }

    #[test]
    fn key_add_refuses_bad_length_and_duplicates() {
        let (_dir, db) = open();
        let (_sk, pk) = keypair();
        let err = db.write(|tx| key_add(tx, "k1", "abcd", "now", None)).unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "{err}");
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let err = db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn signed_checkpoint_verifies_with_a_pinned_anchor_only() {
        let (_dir, db) = open();
        let (sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let (seq, hash) = ledger_row(&db);
        signed_checkpoint(&db, &sk, "k1", seq, &hash);

        // No anchor: the signature checks against the store, but authorship is not proven.
        assert_eq!(
            db.read(|c| verify_checkpoint(c, "cp-1", None)).unwrap(),
            CheckpointVerification::ValidInStoreOnly { key_id: "k1".into() }
        );
        // A pinned anchor proves it.
        let anchor = TrustAnchor { key_id: "k1".into(), public_key: pk.clone() };
        assert_eq!(
            db.read(|c| verify_checkpoint(c, "cp-1", Some(&anchor))).unwrap(),
            CheckpointVerification::Valid
        );
        // A different pinned key is refused.
        let wrong = TrustAnchor { key_id: "k1".into(), public_key: hex::encode([9u8; 32]) };
        assert!(matches!(
            db.read(|c| verify_checkpoint(c, "cp-1", Some(&wrong))).unwrap(),
            CheckpointVerification::KeyMismatch { .. }
        ));
    }

    #[test]
    fn a_checkpoint_must_match_the_ledger() {
        let (_dir, db) = open();
        let (sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        // A seq the ledger does not contain at all.
        signed_checkpoint(&db, &sk, "k1", 999, "not-a-real-hash");
        let anchor = TrustAnchor { key_id: "k1".into(), public_key: pk };
        assert!(matches!(
            db.read(|c| verify_checkpoint(c, "cp-1", Some(&anchor))).unwrap(),
            CheckpointVerification::LedgerMismatch { .. }
        ));
    }

    #[test]
    fn a_revoked_key_is_refused() {
        let (_dir, db) = open();
        let (sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let (seq, hash) = ledger_row(&db);
        signed_checkpoint(&db, &sk, "k1", seq, &hash);
        db.write(|tx| key_revoke(tx, "k1", "now")).unwrap();
        let anchor = TrustAnchor { key_id: "k1".into(), public_key: pk };
        assert_eq!(
            db.read(|c| verify_checkpoint(c, "cp-1", Some(&anchor))).unwrap(),
            CheckpointVerification::KeyRevoked { key_id: "k1".into() }
        );
    }

    #[test]
    fn unsigned_checkpoint_is_not_valid() {
        let (_dir, db) = open();
        let (_sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let (seq, hash) = ledger_row(&db);
        db.write(|tx| checkpoint_write(tx, &hub_checkpoint("k1", seq, &hash), "now")).unwrap();
        assert_eq!(
            db.read(|c| verify_checkpoint(c, "cp-1", None)).unwrap(),
            CheckpointVerification::Unsigned
        );
    }

    #[test]
    fn a_wrong_signature_is_invalid() {
        let (_dir, db) = open();
        let (_sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let (seq, hash) = ledger_row(&db);
        let digest =
            db.write(|tx| checkpoint_write(tx, &hub_checkpoint("k1", seq, &hash), "now")).unwrap();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let sig = hex::encode(other.sign(&hex::decode(&digest).unwrap()).to_bytes());
        db.write(|tx| checkpoint_attach(tx, "cp-1", &sig)).unwrap();
        assert_eq!(
            db.read(|c| verify_checkpoint(c, "cp-1", None)).unwrap(),
            CheckpointVerification::InvalidSignature
        );
    }

    #[test]
    fn a_checkpoint_is_signed_once() {
        let (_dir, db) = open();
        let (sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let (seq, hash) = ledger_row(&db);
        let digest =
            db.write(|tx| checkpoint_write(tx, &hub_checkpoint("k1", seq, &hash), "now")).unwrap();
        let sig = hex::encode(sk.sign(&hex::decode(&digest).unwrap()).to_bytes());
        db.write(|tx| checkpoint_attach(tx, "cp-1", &sig)).unwrap();
        let err = db.write(|tx| checkpoint_attach(tx, "cp-1", &sig)).unwrap_err();
        assert!(err.to_string().contains("already carries a signature"), "{err}");
    }

    #[test]
    fn a_tampered_row_fails_the_digest() {
        let (_dir, db) = open();
        let (sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let (seq, hash) = ledger_row(&db);
        signed_checkpoint(&db, &sk, "k1", seq, &hash);
        // An attacker with SQL access drops the guard, then edits a signed field.
        db.write(|tx| {
            tx.execute("DROP TRIGGER evidence_checkpoint_immutable", [])?;
            tx.execute("UPDATE evidence_checkpoint SET seq = 43 WHERE checkpoint_id = 'cp-1'", [])?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            db.read(|c| verify_checkpoint(c, "cp-1", None)).unwrap(),
            CheckpointVerification::DigestMismatch
        );
    }

    #[test]
    fn an_unknown_key_is_not_a_pass() {
        let (dir, db) = open();
        let (sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let (seq, hash) = ledger_row(&db);
        signed_checkpoint(&db, &sk, "k1", seq, &hash);
        // An attacker with SQL access removes the key row after signing. The
        // pragma only takes effect outside a transaction, so use a raw
        // connection to the same file.
        let raw = Connection::open(dir.path().join("hub.db")).unwrap();
        raw.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        raw.execute("DROP TRIGGER evidence_key_no_delete", []).unwrap();
        raw.execute("DELETE FROM evidence_key WHERE key_id = 'k1'", []).unwrap();
        drop(raw);
        assert_eq!(
            db.read(|c| verify_checkpoint(c, "cp-1", None)).unwrap(),
            CheckpointVerification::UnknownKey { key_id: "k1".into() }
        );
    }

    #[test]
    fn triggers_refuse_key_and_checkpoint_edits() {
        let (_dir, db) = open();
        let (sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let (seq, hash) = ledger_row(&db);
        signed_checkpoint(&db, &sk, "k1", seq, &hash);

        // The key's public material cannot be replaced.
        let err = db
            .write(|tx| {
                tx.execute("UPDATE evidence_key SET public_key = '00' WHERE key_id = 'k1'", [])?;
                Ok(())
            })
            .unwrap_err();
        assert!(err.to_string().contains("immutable"), "{err}");
        // A checkpoint's signed fields cannot be edited.
        let err = db
            .write(|tx| {
                tx.execute("UPDATE evidence_checkpoint SET seq = 99 WHERE checkpoint_id = 'cp-1'", [])?;
                Ok(())
            })
            .unwrap_err();
        assert!(err.to_string().contains("immutable"), "{err}");
        // Neither row can be deleted.
        let err = db
            .write(|tx| {
                tx.execute("DELETE FROM evidence_checkpoint WHERE checkpoint_id = 'cp-1'", [])?;
                Ok(())
            })
            .unwrap_err();
        assert!(err.to_string().contains("immutable"), "{err}");
    }

    #[test]
    fn key_and_checkpoint_changes_are_ledgered() {
        let (_dir, db) = open();
        let (sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let (seq, hash) = ledger_row(&db);
        signed_checkpoint(&db, &sk, "k1", seq, &hash);
        db.write(|tx| key_retire(tx, "k1", "now")).unwrap();
        let channels: Vec<String> = db
            .read(|c| {
                let mut stmt = c.prepare("SELECT channel FROM event_log ORDER BY seq")?;
                let rows = stmt.query_map([], |r| r.get(0))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap();
        for expected in [
            "evidence.key.added",
            "evidence.checkpoint.written",
            "evidence.checkpoint.signed",
            "evidence.key.retired",
        ] {
            assert!(channels.iter().any(|c| c == expected), "missing {expected} in {channels:?}");
        }
    }

    #[test]
    fn part_applies_cleanly() {
        let dir = tempdir().unwrap();
        let mut conn = Connection::open(dir.path().join("x.db")).unwrap();
        apply(&mut conn, &[KEY_STORE_PART]).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name IN ('evidence_key','evidence_checkpoint')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }
}
