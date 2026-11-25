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
//! The object carries exactly the fields `docs/evidence-export.md` names for
//! the checkpoint's class, keys in sorted order, `,`/`:` separators, and a
//! literal `null` for a field that does not apply. Strings are escaped the way
//! Python's `json.dumps(ensure_ascii=True)` escapes them, so the encoding is
//! byte-stable across languages.
//!
//! - class `hub`: `{class, hash, key_id, org_id, seq, signed_at}`
//! - class `org`: `{class, global_from_hash, global_head_hash, key_id,
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
//! only stops new checkpoints from naming it. A checkpoint naming a key the
//! store does not hold is a verification failure, never a pass.

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
",
};

/// The only signing algorithm this build accepts.
pub const ALGORITHM_ED25519: &str = "ed25519";

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
    pub note: Option<String>,
}

/// What verification concluded. A caller must not treat anything but
/// [`CheckpointVerification::Valid`] as authorship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CheckpointVerification {
    /// The signature is present and checks out against the named key.
    Valid,
    /// The row exists but no signature was attached yet.
    Unsigned,
    /// The named key is not in the store.
    UnknownKey { key_id: String },
    /// The signature does not verify over the recomputed digest.
    InvalidSignature,
    /// The stored digest does not match the fields (a row edited after signing).
    DigestMismatch,
}

impl Checkpoint {
    /// The canonical digest input: the class's fields only, sorted keys, nulls
    /// explicit. This is the exact byte string whose SHA-256 is signed.
    pub fn digest_input(&self) -> String {
        let mut out = String::new();
        out.push('{');
        match self.class {
            CheckpointClass::Hub => {
                // Sorted: class, hash, key_id, org_id, seq, signed_at.
                field_str(&mut out, "class", self.class.as_str(), true);
                field_opt(&mut out, "hash", self.hash.as_deref(), false);
                field_str(&mut out, "key_id", &self.key_id, false);
                field_opt(&mut out, "org_id", self.org_id.as_deref(), false);
                field_int(&mut out, "seq", self.seq, false);
                field_str(&mut out, "signed_at", &self.signed_at, false);
            }
            CheckpointClass::Org => {
                // Sorted: class, global_from_hash, global_head_hash, key_id,
                // org_chain_hash, org_id, org_row_count, signed_at, window.
                field_str(&mut out, "class", self.class.as_str(), true);
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
        note: r.get(5)?,
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

/// Add a public key. Refuses a duplicate id and a key whose hex is not 32 bytes.
pub fn key_add(
    tx: &mut WriteTx<'_>,
    key_id: &str,
    public_key_hex: &str,
    created_at: &str,
    note: Option<&str>,
) -> UaResult<()> {
    let bytes =
        hex::decode(public_key_hex).map_err(|_| UaError::invalid("public key must be hex-encoded"))?;
    if bytes.len() != 32 {
        return Err(UaError::invalid(format!("an Ed25519 public key is 32 bytes, got {}", bytes.len())));
    }
    let exists: Option<String> = tx
        .query_row("SELECT key_id FROM evidence_key WHERE key_id = ?1", [key_id], |r| r.get(0))
        .optional()?;
    if exists.is_some() {
        return Err(UaError::conflict(format!("evidence key {key_id:?} already exists")));
    }
    tx.execute(
        "INSERT INTO evidence_key (key_id, algorithm, public_key, created_at, retired_at, note) \
         VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
        params![key_id, ALGORITHM_ED25519, public_key_hex, created_at, note],
    )?;
    Ok(())
}

/// Retire a key: it stays in the store so old checkpoints verify, but new
/// checkpoints may not name it.
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
    Ok(())
}

/// Read one key.
pub fn key_get(conn: &Connection, key_id: &str) -> UaResult<Option<EvidenceKey>> {
    let key = conn
        .query_row(
            "SELECT key_id, algorithm, public_key, created_at, retired_at, note \
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
        "SELECT key_id, algorithm, public_key, created_at, retired_at, note \
         FROM evidence_key ORDER BY retired_at IS NOT NULL, key_id",
    )?;
    let rows = stmt.query_map([], row_to_key)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Write a checkpoint row and return its digest. The key must exist and be
/// active; a retired key is refused so a rotation cannot be silently undone.
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
    Ok(digest)
}

/// Attach an operator's signature to a checkpoint. Refuses a second signature:
/// a row is signed once, and a re-signature would hide which key attested it.
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
    tx.execute(
        "UPDATE evidence_checkpoint SET signature = ?2 WHERE checkpoint_id = ?1",
        params![checkpoint_id, signature_hex],
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

/// Verify a checkpoint's stored signature. Recomputes the digest from the
/// fields, so a row edited after signing fails as [`DigestMismatch`].
pub fn verify_checkpoint(conn: &Connection, checkpoint_id: &str) -> UaResult<CheckpointVerification> {
    let Some(checkpoint) = checkpoint_get(conn, checkpoint_id)? else {
        return Err(UaError::not_found(format!("no checkpoint {checkpoint_id:?}")));
    };
    let Some((stored_digest, signature)) = checkpoint_signature(conn, checkpoint_id)? else {
        return Err(UaError::not_found(format!("no checkpoint {checkpoint_id:?}")));
    };
    if checkpoint.digest() != stored_digest {
        return Ok(CheckpointVerification::DigestMismatch);
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
    match verify_ed25519(&key.public_key, &stored_digest, &signature) {
        Ok(()) => Ok(CheckpointVerification::Valid),
        Err(_) => Ok(CheckpointVerification::InvalidSignature),
    }
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
        let db = Db::open(&dir.path().join("hub.db"), &[KEY_STORE_PART]).unwrap();
        (dir, db)
    }

    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    fn hub_checkpoint(key_id: &str) -> Checkpoint {
        Checkpoint {
            checkpoint_id: "cp-1".into(),
            class: CheckpointClass::Hub,
            org_id: Some("default".into()),
            seq: Some(42),
            hash: Some("abc123".into()),
            window: None,
            global_from_hash: None,
            global_head_hash: None,
            org_row_count: None,
            org_chain_hash: None,
            key_id: key_id.into(),
            signed_at: "2026-11-25T00:00:00Z".into(),
        }
    }

    #[test]
    fn digest_is_stable_and_covers_only_the_class_fields() {
        let cp = hub_checkpoint("k1");
        let first = cp.digest();
        assert_eq!(first, cp.digest(), "digest must be deterministic");
        assert_eq!(first.len(), 64);
        let input = cp.digest_input();
        assert!(input.starts_with("{\"class\":\"hub\",\"hash\":"));
        assert!(!input.contains("window"), "hub digest must not carry org fields: {input}");
        // An unused field set to a value must not change the digest.
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
            window: Some(Window { start: "2026-11-01T00:00:00Z".into(), end: "2026-11-02T00:00:00Z".into() }),
            global_from_hash: Some("g0".into()),
            global_head_hash: Some("g1".into()),
            org_row_count: Some(9),
            org_chain_hash: Some("c9".into()),
            key_id: "k1".into(),
            signed_at: "2026-11-25T00:00:00Z".into(),
        };
        let input = cp.digest_input();
        assert!(
            input
                .contains("\"window\":{\"end\":\"2026-11-02T00:00:00Z\",\"start\":\"2026-11-01T00:00:00Z\"}")
        );
        assert!(input.contains("\"org_row_count\":9"));
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

        db.write(|tx| key_retire(tx, "k1", "2026-11-26T00:00:00Z")).unwrap();
        assert!(db.read(|c| key_get(c, "k1")).unwrap().unwrap().retired_at.is_some());
        // A retired key cannot be named by a new checkpoint.
        let err =
            db.write(|tx| checkpoint_write(tx, &hub_checkpoint("k1"), "2026-11-27T00:00:00Z")).unwrap_err();
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
    fn signed_checkpoint_verifies_and_a_tampered_row_does_not() {
        let (_dir, db) = open();
        let (sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let cp = hub_checkpoint("k1");
        let digest = db.write(|tx| checkpoint_write(tx, &cp, "now")).unwrap();
        let sig = hex::encode(sk.sign(&hex::decode(&digest).unwrap()).to_bytes());
        db.write(|tx| checkpoint_attach(tx, "cp-1", &sig)).unwrap();

        assert_eq!(db.read(|c| verify_checkpoint(c, "cp-1")).unwrap(), CheckpointVerification::Valid);

        // Editing a signed field after the signature is attached breaks the digest.
        db.write(|tx| {
            tx.execute("UPDATE evidence_checkpoint SET seq = 43 WHERE checkpoint_id = 'cp-1'", [])?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            db.read(|c| verify_checkpoint(c, "cp-1")).unwrap(),
            CheckpointVerification::DigestMismatch
        );
    }

    #[test]
    fn unsigned_and_unknown_key_are_not_passes() {
        let (_dir, db) = open();
        let (_sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        db.write(|tx| checkpoint_write(tx, &hub_checkpoint("k1"), "now")).unwrap();
        assert_eq!(db.read(|c| verify_checkpoint(c, "cp-1")).unwrap(), CheckpointVerification::Unsigned);

        // A checkpoint whose key is no longer in the store. The store's foreign
        // key refuses this through `Db`, so build the row on a raw connection
        // with enforcement off: that is the state a verifier holding a foreign
        // hub's bundle is in.
        let dir = tempdir().unwrap();
        let mut conn = Connection::open(dir.path().join("raw.db")).unwrap();
        apply(&mut conn, &[KEY_STORE_PART]).unwrap();
        conn.execute(
            "INSERT INTO evidence_key (key_id, algorithm, public_key, created_at) \
             VALUES ('k1', 'ed25519', ?1, 'now')",
            [&pk],
        )
        .unwrap();
        let cp = hub_checkpoint("k1");
        conn.execute(
            "INSERT INTO evidence_checkpoint \
             (checkpoint_id, class, org_id, seq, hash, key_id, signed_at, digest, created_at, signature) \
             VALUES ('cp-1', 'hub', 'default', 42, 'abc123', 'k1', '2026-11-25T00:00:00Z', ?1, 'now', ?2)",
            rusqlite::params![cp.digest(), hex::encode([0u8; 64])],
        )
        .unwrap();
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        conn.execute("DELETE FROM evidence_key WHERE key_id = 'k1'", []).unwrap();
        assert_eq!(
            verify_checkpoint(&conn, "cp-1").unwrap(),
            CheckpointVerification::UnknownKey { key_id: "k1".into() }
        );
    }

    #[test]
    fn a_wrong_signature_is_invalid() {
        let (_dir, db) = open();
        let (_sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let digest = db.write(|tx| checkpoint_write(tx, &hub_checkpoint("k1"), "now")).unwrap();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let sig = hex::encode(other.sign(&hex::decode(&digest).unwrap()).to_bytes());
        db.write(|tx| checkpoint_attach(tx, "cp-1", &sig)).unwrap();
        assert_eq!(
            db.read(|c| verify_checkpoint(c, "cp-1")).unwrap(),
            CheckpointVerification::InvalidSignature
        );
    }

    #[test]
    fn a_checkpoint_is_signed_once() {
        let (_dir, db) = open();
        let (sk, pk) = keypair();
        db.write(|tx| key_add(tx, "k1", &pk, "now", None)).unwrap();
        let digest = db.write(|tx| checkpoint_write(tx, &hub_checkpoint("k1"), "now")).unwrap();
        let sig = hex::encode(sk.sign(&hex::decode(&digest).unwrap()).to_bytes());
        db.write(|tx| checkpoint_attach(tx, "cp-1", &sig)).unwrap();
        let err = db.write(|tx| checkpoint_attach(tx, "cp-1", &sig)).unwrap_err();
        assert!(err.to_string().contains("already carries a signature"), "{err}");
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
