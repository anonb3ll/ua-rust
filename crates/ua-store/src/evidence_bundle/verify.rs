//! Standalone offline evidence bundle verifier (`docs/evidence-export.md`, S4).
//!
//! This module intentionally has **no database dependency**: it never opens,
//! creates, or queries SQLite. It trusts only:
//! 1. Verifier-supplied Ed25519 public keys (`TrustAnchor` / `TrustFile`) and
//!    authoritative revocation list (`revoked_key_ids`).
//! 2. An optional verifier-pinned checkpoint (or genesis) and optional hub
//!    chain cross-check.
//! 3. Its own recomputation over the files in `bundle_dir`.
//!
//! Hardening: refuses symlinks anywhere in `bundle_dir`, refuses non-regular
//! files, caps directory walk depth/entries, and caps per-file and total bytes
//! read before allocating memory.
//!
//! Exit codes:
//! - `0`: verified
//! - `1`: refused (integrity, signature, chain, receipt, trace, downgrade,
//!   symlink/size, or forbidden private/secret content violation — never
//!   downgraded to a warning)
//! - `2`: cannot verify (missing input, unsupported format, unanchored, unknown
//!   or revoked key, unsigned bundle/checkpoint, or incremental bundle missing
//!   its pinned checkpoint)

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ua_core::UaResult;

use crate::evidence::{CHECKPOINT_FORMAT, CheckpointClass, TrustAnchor, verify_ed25519};
use crate::ledger::{GENESIS_HASH, HASH_V1, HASH_V2, compute_entry_hash_for_version};

use super::canonical::{empty_org_chain_hash, org_chain_fold, sha256_hex};
use super::egress::{
    CLASS_APPROVALS_IN_DEFAULT_LEDGER, CLASS_CROSS_ORG_EVENTS, STUB_CLASSES, WithheldReport,
    find_forbidden_in_text, find_forbidden_in_value, ledger_row_stub_class, parse_strict_json,
    parse_strict_json_bytes,
};
use super::export_schema::{CLASS_FREE_TEXT_PAYLOAD, CLASS_UNLISTED_PAYLOAD};
use super::{
    ARTIFACT_CONTENT_HASH_ONLY, ApprovalHistory, ApprovalReceipt, ArtifactIndexEntry, BUNDLE_FORMAT,
    BundleCheckpointFile, BundleLedgerEvent, BundleManifest, CONFIG_REVISION_CHANNEL, EvidenceRow,
    LABEL_PLACEHOLDER, PolicyRevisionRecord, PolicyTimeline, ProducerInfo, REDACTED_CHANNEL,
    RELEASE_NOT_IN_BUNDLE, RELEASE_NOT_PROVABLE_IN_ORG_BUNDLE, RELEASE_RELEASED, RELEASE_REVOKED,
    RELEASE_UNRELEASED, REQUIRED_BUNDLE_FILES, ReleaseEvent, ReleaseState, cmp_ts, derive_evidence_row,
    extract_sod_tools_from_doc, is_evidence_channel, labels_equal, normalize_decision,
    normalize_signature_hex, normalize_ts_utc, release_events, release_state,
};
use crate::evidence::Window;
use ua_core::DEFAULT_ORG;

/// Default maximum size of any single file read from a bundle (64 MiB).
pub const MAX_BUNDLE_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Default maximum cumulative bytes read across an entire bundle (256 MiB).
pub const MAX_BUNDLE_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum directory depth walked inside a bundle directory.
const MAX_WALK_DEPTH: usize = 16;
/// Maximum directory entries inspected inside a bundle directory.
const MAX_WALK_ENTRIES: usize = 100_000;

/// Pinned prior `hub` checkpoint head held out of band by the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedHubHead {
    pub seq: i64,
    pub hash: String,
}

/// Pinned prior `org` checkpoint head held out of band by the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedOrgHead {
    pub org_id: String,
    pub global_head_hash: String,
    pub org_row_count: i64,
    pub org_chain_hash: String,
}

/// Out-of-band hub chain rows used to cross-check an `org` bundle's
/// `global_from_hash` and `global_head_hash` (check 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubCrossCheck {
    pub events: Vec<BundleLedgerEvent>,
}

/// Out-of-band verifier trust inputs for [`verify_bundle_dir`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleVerifyTrust {
    /// One explicitly pinned key (`--anchor-key` + `--anchor-key-id`).
    pub anchor: Option<TrustAnchor>,
    /// Pinned keys from `--trust-file`, used when `anchor` is `None`.
    pub trust_keys: Vec<TrustAnchor>,
    /// Authoritative verifier-side list of revoked key ids.
    pub revoked_key_ids: Vec<String>,
    /// Optional out-of-band pinned `hub` checkpoint head.
    pub pinned_hub: Option<PinnedHubHead>,
    /// Optional out-of-band pinned `org` checkpoint head.
    pub pinned_org: Option<PinnedOrgHead>,
    /// Optional verified global hub events for cross-checking an `org` bundle.
    pub hub_cross_check: Option<HubCrossCheck>,
}

impl BundleVerifyTrust {
    pub fn from_anchor(anchor: TrustAnchor) -> Self {
        Self { anchor: Some(anchor), ..Self::default() }
    }

    fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked_key_ids.iter().any(|id| id.trim() == key_id)
    }
}

/// Status of an individual verification claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStatus {
    #[serde(rename = "verified")]
    Verified,
    #[serde(rename = "refused")]
    Refused,
    #[serde(rename = "unverified")]
    Unverified,
    #[serde(rename = "not-applicable")]
    NotApplicable,
    /// The bundle carries the claim only on the exporting hub's word: the
    /// verifier found nothing hash-verified to bind it to.
    #[serde(rename = "hub-asserted")]
    HubAsserted,
    /// The claim holds for the rows in clear, but the bundle carries
    /// redacted stubs the claim cannot see into (a stub could hide an
    /// approval, a release or a row of the window).
    #[serde(rename = "partial")]
    Partial,
}

/// One of the separate verification claims (`integrity`, `authorship`,
/// `completeness`, `separation_of_duties`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimReport {
    pub status: ClaimStatus,
    pub basis: String,
}

impl ClaimReport {
    fn new(status: ClaimStatus, basis: impl Into<String>) -> Self {
        Self { status, basis: basis.into() }
    }

    fn unchecked() -> Self {
        Self::new(ClaimStatus::Unverified, "not yet checked")
    }
}

/// Appended to receipt, cross-link and separation-of-duties bases whenever the
/// bundle carries redacted stubs.
const REDACTED_COVERAGE_NOTE: &str = "covers unredacted ledger rows only: each redacted hash-only stub is the \
     exporter's assertion that the row was private, and receipts, cross-links and separation of duties cannot be \
     checked against a row whose payload is withheld";

/// Unhashed legacy prefix reported explicitly (check 11).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyPrefixReport {
    pub count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seq: Option<i64>,
}

/// Redacted hash-only ledger rows reported explicitly (chain-linked only,
/// payload omitted and therefore not row-hash-verified).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedEventsReport {
    pub count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seqs: Vec<i64>,
}

/// Complete machine-readable verdict from [`verify_bundle_dir`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleVerdict {
    pub ok: bool,
    pub exit_code: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offending: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<CheckpointClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_digest: Option<String>,
    pub integrity: ClaimReport,
    pub authorship: ClaimReport,
    pub completeness: ClaimReport,
    pub separation_of_duties: ClaimReport,
    /// Approval receipts: bound to hash-verified ledger events, or not covered.
    #[serde(default = "ClaimReport::unchecked")]
    pub approvals: ClaimReport,
    /// `artifacts/index.json`: bound to hash-verified `agent.deliverable.*`
    /// events, or hub-asserted.
    #[serde(default = "ClaimReport::unchecked")]
    pub artifacts: ClaimReport,
    pub unhashed_legacy_prefix: LegacyPrefixReport,
    #[serde(default)]
    pub redacted_events: RedactedEventsReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld: Option<WithheldReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer: Option<ProducerInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl BundleVerdict {
    fn base() -> Self {
        Self {
            ok: false,
            exit_code: 2,
            reason: None,
            detail: None,
            offending: None,
            class: None,
            org_id: None,
            bundle_digest: None,
            integrity: ClaimReport::new(ClaimStatus::Unverified, "not yet checked"),
            authorship: ClaimReport::new(ClaimStatus::Unverified, "not yet checked"),
            completeness: ClaimReport::new(ClaimStatus::Unverified, "not yet checked"),
            separation_of_duties: ClaimReport::new(
                ClaimStatus::NotApplicable,
                "no separation-of-duties-governed approvals checked",
            ),
            approvals: ClaimReport::unchecked(),
            artifacts: ClaimReport::unchecked(),
            unhashed_legacy_prefix: LegacyPrefixReport::default(),
            redacted_events: RedactedEventsReport::default(),
            withheld: None,
            producer: None,
            warnings: Vec::new(),
        }
    }

    fn set_refuse(&mut self, reason: &str, detail: impl Into<String>, offending: Option<Value>) {
        self.ok = false;
        self.exit_code = 1;
        self.reason = Some(reason.to_string());
        self.detail = Some(detail.into());
        self.offending = offending;
    }

    fn refuse(mut self, reason: &str, detail: impl Into<String>, offending: Option<Value>) -> Self {
        self.set_refuse(reason, detail, offending);
        self
    }

    fn cannot_verify(mut self, reason: &str, detail: impl Into<String>, offending: Option<Value>) -> Self {
        self.ok = false;
        self.exit_code = 2;
        self.reason = Some(reason.to_string());
        self.detail = Some(detail.into());
        self.offending = offending;
        self
    }
}

type DeferredCannotVerify = Option<(&'static str, String, Option<Value>)>;

enum SafeReadError {
    NotFound,
    Symlink(String),
    NonRegular(String),
    TooLarge(String),
    Io(String),
}

/// Safely read a relative file inside `root` without following any symlink at
/// any path component, refusing non-regular files, and enforcing per-file and
/// total byte limits before reading into memory.
fn read_bundle_file_checked(
    root: &Path,
    rel: &str,
    max_file_bytes: u64,
    total_read: &mut u64,
    max_total_bytes: u64,
) -> Result<Vec<u8>, SafeReadError> {
    let mut cur = PathBuf::from(root);
    for seg in rel.split('/') {
        cur.push(seg);
        let meta = match std::fs::symlink_metadata(&cur) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(SafeReadError::NotFound),
            Err(e) => return Err(SafeReadError::Io(format!("stat {rel:?}: {e}"))),
        };
        if meta.file_type().is_symlink() {
            return Err(SafeReadError::Symlink(format!("refusing symlink at {rel:?}")));
        }
    }
    let meta =
        std::fs::symlink_metadata(&cur).map_err(|e| SafeReadError::Io(format!("stat {rel:?}: {e}")))?;
    if meta.file_type().is_symlink() {
        return Err(SafeReadError::Symlink(format!("refusing symlink at {rel:?}")));
    }
    if !meta.file_type().is_file() {
        return Err(SafeReadError::NonRegular(format!("refusing non-regular file {rel:?}")));
    }
    if meta.len() > max_file_bytes {
        return Err(SafeReadError::TooLarge(format!(
            "file {rel:?} size {} exceeds limit {max_file_bytes} bytes",
            meta.len()
        )));
    }
    if total_read.saturating_add(meta.len()) > max_total_bytes {
        return Err(SafeReadError::TooLarge(format!(
            "bundle total size exceeds limit {max_total_bytes} bytes at {rel:?}"
        )));
    }
    let file = std::fs::File::open(&cur).map_err(|e| SafeReadError::Io(format!("opening {rel:?}: {e}")))?;
    let mut buf = Vec::with_capacity(meta.len().min(max_file_bytes) as usize);
    file.take(max_file_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| SafeReadError::Io(format!("reading {rel:?}: {e}")))?;
    if buf.len() as u64 > max_file_bytes {
        return Err(SafeReadError::TooLarge(format!("file {rel:?} exceeds limit {max_file_bytes} bytes")));
    }
    *total_read = total_read.saturating_add(buf.len() as u64);
    if *total_read > max_total_bytes {
        return Err(SafeReadError::TooLarge(format!(
            "bundle total size exceeds limit {max_total_bytes} bytes at {rel:?}"
        )));
    }
    Ok(buf)
}

/// Verify a `hub` bundle against `trust` and load its `ledger/events.jsonl`
/// for use as [`HubCrossCheck`] when verifying an `org` bundle.
pub fn load_verified_hub_cross_check(
    hub_bundle_dir: &Path,
    trust: &BundleVerifyTrust,
) -> UaResult<Result<HubCrossCheck, BundleVerdict>> {
    let hub_trust = BundleVerifyTrust {
        anchor: trust.anchor.clone(),
        trust_keys: trust.trust_keys.clone(),
        revoked_key_ids: trust.revoked_key_ids.clone(),
        pinned_hub: trust.pinned_hub.clone(),
        pinned_org: None,
        hub_cross_check: None,
    };
    let verdict = verify_bundle_dir(hub_bundle_dir, &hub_trust)?;
    if !verdict.ok {
        return Ok(Err(verdict));
    }
    if verdict.class != Some(CheckpointClass::Hub) {
        return Ok(Err(BundleVerdict::base().cannot_verify(
            "invalid_hub_bundle",
            "hub cross-check bundle must be class \"hub\"",
            None,
        )));
    }
    let mut total_read = 0u64;
    let bytes = read_bundle_file_checked(
        hub_bundle_dir,
        "ledger/events.jsonl",
        MAX_BUNDLE_FILE_BYTES,
        &mut total_read,
        MAX_BUNDLE_TOTAL_BYTES,
    )
    .map_err(|e| {
        let msg = match e {
            SafeReadError::NotFound => "missing ledger/events.jsonl".into(),
            SafeReadError::Symlink(s)
            | SafeReadError::NonRegular(s)
            | SafeReadError::TooLarge(s)
            | SafeReadError::Io(s) => s,
        };
        ua_core::UaError::internal(format!("reading hub bundle events.jsonl: {msg}"))
    })?;
    let events = parse_jsonl::<BundleLedgerEvent>(&bytes)
        .map_err(|e| ua_core::UaError::internal(format!("parsing hub bundle events.jsonl: {e}")))?;
    Ok(Ok(HubCrossCheck { events }))
}

/// Verify an exported evidence bundle directory offline against `trust`.
///
/// Implements all 12 checks from `docs/evidence-export.md` and returns a
/// [`BundleVerdict`] with exit code `0` (verified), `1` (refused), or `2`
/// (cannot verify). Never touches any hub database or configuration.
pub fn verify_bundle_dir(bundle_dir: &Path, trust: &BundleVerifyTrust) -> UaResult<BundleVerdict> {
    verify_bundle_dir_with_limits(bundle_dir, trust, MAX_BUNDLE_FILE_BYTES, MAX_BUNDLE_TOTAL_BYTES)
}

/// Like [`verify_bundle_dir`], with caller-specified per-file and total byte
/// limits (useful for testing size caps without writing tens of megabytes).
pub fn verify_bundle_dir_with_limits(
    bundle_dir: &Path,
    trust: &BundleVerifyTrust,
    max_file_bytes: u64,
    max_total_bytes: u64,
) -> UaResult<BundleVerdict> {
    let mut verdict = BundleVerdict::base();

    let root_meta = match std::fs::symlink_metadata(bundle_dir) {
        Ok(m) => m,
        Err(_) => {
            return Ok(verdict.cannot_verify(
                "missing_bundle_dir",
                format!("bundle directory {} does not exist", bundle_dir.display()),
                Some(json!({ "path": bundle_dir.display().to_string() })),
            ));
        }
    };
    if root_meta.file_type().is_symlink() {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "bundle root is a symlink");
        return Ok(verdict.refuse(
            "symlink_not_allowed",
            format!("refusing bundle directory symlink {}", bundle_dir.display()),
            Some(json!({ "path": bundle_dir.display().to_string() })),
        ));
    }
    if !root_meta.file_type().is_dir() {
        return Ok(verdict.cannot_verify(
            "missing_bundle_dir",
            format!("bundle path {} is not a directory", bundle_dir.display()),
            Some(json!({ "path": bundle_dir.display().to_string() })),
        ));
    }

    // Walk bundle_dir without following symlinks: refuse any symlink or
    // runaway directory tree immediately before reading any file.
    let mut disk_files = BTreeSet::new();
    let mut walked_entries = 0usize;
    if let Err((reason, detail, offending)) =
        collect_relative_files_safe(bundle_dir, bundle_dir, 0, &mut walked_entries, &mut disk_files)
    {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, detail.clone());
        return Ok(verdict.refuse(reason, detail, offending));
    }

    let mut total_read = 0u64;

    // Read unhashed producer.json (reported, never hashed, never treated as evidence).
    match read_bundle_file_checked(
        bundle_dir,
        "producer.json",
        max_file_bytes,
        &mut total_read,
        max_total_bytes,
    ) {
        Ok(bytes) => match serde_json::from_slice::<ProducerInfo>(&bytes) {
            Ok(p) => verdict.producer = Some(p),
            Err(_) => verdict.warnings.push("producer.json is present but unreadable (not hashed)".into()),
        },
        Err(SafeReadError::NotFound) => {}
        Err(SafeReadError::Symlink(msg)) => {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, msg.clone());
            return Ok(verdict.refuse("symlink_not_allowed", msg, Some(json!({ "file": "producer.json" }))));
        }
        Err(SafeReadError::TooLarge(msg)) => {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, msg.clone());
            return Ok(verdict.refuse("file_too_large", msg, Some(json!({ "file": "producer.json" }))));
        }
        Err(SafeReadError::NonRegular(msg)) | Err(SafeReadError::Io(msg)) => {
            verdict.warnings.push(format!("producer.json unreadable ({msg})"));
        }
    }

    // Check 1: format & manifest parsing.
    let manifest_bytes = match read_bundle_file_checked(
        bundle_dir,
        "manifest.json",
        max_file_bytes,
        &mut total_read,
        max_total_bytes,
    ) {
        Ok(b) => b,
        Err(SafeReadError::NotFound) => {
            return Ok(verdict.cannot_verify(
                "missing_manifest",
                "cannot read manifest.json: file not found",
                Some(json!({ "file": "manifest.json" })),
            ));
        }
        Err(SafeReadError::Symlink(msg)) => {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, msg.clone());
            return Ok(verdict.refuse("symlink_not_allowed", msg, Some(json!({ "file": "manifest.json" }))));
        }
        Err(SafeReadError::TooLarge(msg)) => {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, msg.clone());
            return Ok(verdict.refuse("file_too_large", msg, Some(json!({ "file": "manifest.json" }))));
        }
        Err(SafeReadError::NonRegular(msg)) => {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, msg.clone());
            return Ok(verdict.refuse("invalid_manifest", msg, Some(json!({ "file": "manifest.json" }))));
        }
        Err(SafeReadError::Io(msg)) => {
            return Ok(verdict.cannot_verify(
                "missing_manifest",
                format!("cannot read manifest.json: {msg}"),
                Some(json!({ "file": "manifest.json" })),
            ));
        }
    };
    let manifest: BundleManifest = match parse_strict::<BundleManifest>(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, format!("invalid manifest.json: {e}"));
            return Ok(verdict.refuse(
                "invalid_manifest",
                format!("invalid manifest.json: {e}"),
                Some(json!({ "file": "manifest.json" })),
            ));
        }
    };
    verdict = BundleVerdict { class: Some(manifest.class), org_id: manifest.org_id.clone(), ..verdict };

    if manifest.format != BUNDLE_FORMAT {
        return Ok(verdict.cannot_verify(
            "unsupported_format",
            format!("unsupported bundle format {:?} (expected {:?})", manifest.format, BUNDLE_FORMAT),
            Some(json!({ "field": "format", "value": manifest.format })),
        ));
    }
    if manifest.artifact_content != ARTIFACT_CONTENT_HASH_ONLY {
        return Ok(verdict.cannot_verify(
            "unsupported_artifact_content",
            format!(
                "unsupported artifact_content {:?} (expected {:?})",
                manifest.artifact_content, ARTIFACT_CONTENT_HASH_ONLY
            ),
            Some(json!({ "field": "artifact_content", "value": manifest.artifact_content })),
        ));
    }

    // Validate every manifest path is clean, relative, and never includes unhashed files.
    for rel in manifest.files.keys() {
        if !is_safe_manifest_rel_path(rel)
            || matches!(rel.as_str(), "manifest.json" | "manifest.sig" | "producer.json")
        {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("illegal path {rel:?} in manifest.files"));
            return Ok(verdict.refuse(
                "invalid_manifest_path",
                format!("illegal path {rel:?} listed in manifest.files"),
                Some(json!({ "file": rel })),
            ));
        }
    }
    for rel in manifest.files.keys() {
        if !is_allowed_bundle_file(rel) {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("unexpected file {rel:?} in manifest.files"));
            return Ok(verdict.refuse(
                "unexpected_bundle_file",
                format!(
                    "manifest.files lists {rel:?}; a bundle holds only the required files and approvals/<id>.json \
                     with a canonical decimal id"
                ),
                Some(json!({ "file": rel })),
            ));
        }
    }
    for &req in REQUIRED_BUNDLE_FILES {
        if !manifest.files.contains_key(req) {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("required file {req:?} missing from manifest"),
            );
            return Ok(verdict.refuse(
                "missing_required_file",
                format!("required bundle file {req:?} is missing from manifest.files"),
                Some(json!({ "file": req })),
            ));
        }
    }

    // Report any extra unmanifested files (never counted as evidence).
    for rel in &disk_files {
        if !matches!(rel.as_str(), "manifest.json" | "manifest.sig" | "producer.json")
            && !manifest.files.contains_key(rel)
        {
            verdict.warnings.push(format!("unmanifested file {rel:?} ignored (not counted as evidence)"));
        }
    }

    // Check 2: manifest digest and per-file SHA-256 digests.
    let recomputed_manifest_digest = match manifest.recompute_digest() {
        Ok(d) => d,
        Err(e) => {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("canonical encoding failed: {e}"));
            return Ok(verdict.refuse(
                "manifest_canonical_error",
                format!("failed to recompute manifest digest: {e}"),
                Some(json!({ "file": "manifest.json" })),
            ));
        }
    };
    verdict.bundle_digest = Some(recomputed_manifest_digest.clone());
    if !manifest.digest.trim().eq_ignore_ascii_case(&recomputed_manifest_digest) {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "manifest.json digest mismatch");
        return Ok(verdict.refuse(
            "manifest_digest_mismatch",
            format!(
                "manifest.json claims digest {} but recomputed digest is {recomputed_manifest_digest}",
                manifest.digest.trim()
            ),
            Some(json!({ "file": "manifest.json", "field": "digest" })),
        ));
    }

    let mut file_bytes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (rel, expected_sha) in &manifest.files {
        let bytes =
            match read_bundle_file_checked(bundle_dir, rel, max_file_bytes, &mut total_read, max_total_bytes)
            {
                Ok(b) => b,
                Err(SafeReadError::Symlink(msg)) => {
                    verdict.integrity = ClaimReport::new(ClaimStatus::Refused, msg.clone());
                    return Ok(verdict.refuse("symlink_not_allowed", msg, Some(json!({ "file": rel }))));
                }
                Err(SafeReadError::TooLarge(msg)) => {
                    verdict.integrity = ClaimReport::new(ClaimStatus::Refused, msg.clone());
                    return Ok(verdict.refuse("file_too_large", msg, Some(json!({ "file": rel }))));
                }
                Err(SafeReadError::NonRegular(msg)) => {
                    verdict.integrity = ClaimReport::new(ClaimStatus::Refused, msg.clone());
                    return Ok(verdict.refuse("invalid_file_type", msg, Some(json!({ "file": rel }))));
                }
                Err(SafeReadError::NotFound) | Err(SafeReadError::Io(_)) => {
                    verdict.integrity =
                        ClaimReport::new(ClaimStatus::Refused, format!("missing hashed file {rel:?}"));
                    return Ok(verdict.refuse(
                        "missing_file",
                        format!("hashed file {rel:?} listed in manifest.json is missing on disk"),
                        Some(json!({ "file": rel })),
                    ));
                }
            };
        let actual_sha = sha256_hex(&bytes);
        if !actual_sha.eq_ignore_ascii_case(expected_sha.trim()) {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("sha256 mismatch on hashed file {rel:?}"));
            return Ok(verdict.refuse(
                "file_digest_mismatch",
                format!(
                    "hashed file {rel:?} sha256 mismatch (manifest {}, actual {actual_sha})",
                    expected_sha.trim()
                ),
                Some(json!({ "file": rel })),
            ));
        }
        file_bytes.insert(rel.clone(), bytes);
    }

    // Parse checkpoint file.
    let cp_file: BundleCheckpointFile =
        match parse_strict::<BundleCheckpointFile>(&file_bytes["ledger/checkpoint.json"]) {
            Ok(c) => c,
            Err(e) => {
                verdict.integrity =
                    ClaimReport::new(ClaimStatus::Refused, format!("invalid checkpoint.json: {e}"));
                return Ok(verdict.refuse(
                    "invalid_checkpoint",
                    format!("invalid ledger/checkpoint.json: {e}"),
                    Some(json!({ "file": "ledger/checkpoint.json" })),
                ));
            }
        };
    if cp_file.format != CHECKPOINT_FORMAT {
        return Ok(verdict.cannot_verify(
            "unsupported_checkpoint_format",
            format!("unsupported checkpoint format {:?} (expected {:?})", cp_file.format, CHECKPOINT_FORMAT),
            Some(json!({ "file": "ledger/checkpoint.json", "field": "format" })),
        ));
    }
    if let Err(e) = cp_file.checkpoint.validate_fields() {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, format!("invalid checkpoint fields: {e}"));
        return Ok(verdict.refuse(
            "invalid_checkpoint_fields",
            format!("invalid checkpoint fields: {e}"),
            Some(json!({ "file": "ledger/checkpoint.json" })),
        ));
    }
    if cp_file.checkpoint.class != manifest.class || cp_file.checkpoint.org_id != manifest.org_id {
        verdict.integrity =
            ClaimReport::new(ClaimStatus::Refused, "manifest class/org_id disagrees with checkpoint");
        return Ok(verdict.refuse(
            "manifest_checkpoint_mismatch",
            "manifest class or org_id does not match ledger/checkpoint.json",
            Some(json!({ "file": "ledger/checkpoint.json" })),
        ));
    }
    let recomputed_cp_digest = cp_file.checkpoint.digest();
    if !cp_file.digest.trim().eq_ignore_ascii_case(&recomputed_cp_digest) {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "checkpoint digest mismatch");
        return Ok(verdict.refuse(
            "checkpoint_digest_mismatch",
            format!(
                "ledger/checkpoint.json claims digest {} but recomputed digest is {recomputed_cp_digest}",
                cp_file.digest.trim()
            ),
            Some(json!({ "file": "ledger/checkpoint.json", "field": "digest" })),
        ));
    }

    // Check 3: Checkpoint & manifest signatures against out-of-band pinned trust.
    let mut deferred_cannot_verify: DeferredCannotVerify = None;
    let cp_key_id = cp_file.checkpoint.key_id.as_str();
    let manifest_sig_raw: Option<String> =
        match read_bundle_file_checked(bundle_dir, "manifest.sig", 4096, &mut total_read, max_total_bytes) {
            Ok(b) => match String::from_utf8(b) {
                Ok(s) => Some(s),
                Err(_) => {
                    verdict.authorship =
                        ClaimReport::new(ClaimStatus::Refused, "manifest.sig is not valid UTF-8");
                    return Ok(verdict.refuse(
                        "invalid_manifest_signature",
                        "manifest.sig is not valid UTF-8",
                        Some(json!({ "file": "manifest.sig" })),
                    ));
                }
            },
            Err(SafeReadError::NotFound) => None,
            Err(SafeReadError::Symlink(msg)) => {
                verdict.integrity = ClaimReport::new(ClaimStatus::Refused, msg.clone());
                return Ok(verdict.refuse(
                    "symlink_not_allowed",
                    msg,
                    Some(json!({ "file": "manifest.sig" })),
                ));
            }
            Err(SafeReadError::TooLarge(msg)) => {
                verdict.integrity = ClaimReport::new(ClaimStatus::Refused, msg.clone());
                return Ok(verdict.refuse("file_too_large", msg, Some(json!({ "file": "manifest.sig" }))));
            }
            Err(SafeReadError::NonRegular(msg)) | Err(SafeReadError::Io(msg)) => {
                verdict.authorship = ClaimReport::new(ClaimStatus::Refused, msg.clone());
                return Ok(verdict.refuse(
                    "invalid_manifest_signature",
                    msg,
                    Some(json!({ "file": "manifest.sig" })),
                ));
            }
        };

    if trust.is_revoked(cp_key_id) {
        verdict.authorship = ClaimReport::new(
            ClaimStatus::Unverified,
            format!("key {cp_key_id:?} is revoked by verifier trust"),
        );
        deferred_cannot_verify = Some((
            "key_revoked",
            format!("signing key {cp_key_id:?} is revoked by verifier trust"),
            Some(json!({ "key_id": cp_key_id })),
        ));
    } else if cp_file.signature.is_none() {
        verdict.authorship = ClaimReport::new(ClaimStatus::Unverified, "checkpoint is unsigned");
        deferred_cannot_verify = Some((
            "unsigned_checkpoint",
            "ledger/checkpoint.json carries no signature".into(),
            Some(json!({ "file": "ledger/checkpoint.json" })),
        ));
    } else if manifest_sig_raw.is_none() {
        verdict.authorship = ClaimReport::new(ClaimStatus::Unverified, "manifest.sig is missing");
        deferred_cannot_verify = Some((
            "unsigned_bundle",
            "manifest.sig is missing; bundle proves integrity only, not authorship".into(),
            Some(json!({ "file": "manifest.sig" })),
        ));
    } else {
        let cp_sig = match normalize_signature_hex(cp_file.signature.as_deref().unwrap_or("")) {
            Ok(s) => s,
            Err(e) => {
                verdict.authorship =
                    ClaimReport::new(ClaimStatus::Refused, format!("invalid checkpoint signature: {e}"));
                return Ok(verdict.refuse(
                    "invalid_checkpoint_signature",
                    format!("invalid checkpoint signature encoding: {e}"),
                    Some(json!({ "file": "ledger/checkpoint.json", "field": "signature" })),
                ));
            }
        };
        let manifest_sig = match normalize_signature_hex(manifest_sig_raw.as_deref().unwrap_or("")) {
            Ok(s) => s,
            Err(e) => {
                verdict.authorship =
                    ClaimReport::new(ClaimStatus::Refused, format!("invalid manifest.sig: {e}"));
                return Ok(verdict.refuse(
                    "invalid_manifest_signature",
                    format!("invalid manifest.sig encoding: {e}"),
                    Some(json!({ "file": "manifest.sig" })),
                ));
            }
        };

        let resolved_pk: Option<String> = if let Some(anchor) = &trust.anchor {
            if anchor.key_id.trim() != cp_key_id {
                verdict.authorship = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("key_id mismatch: expected {:?}, found {:?}", anchor.key_id.trim(), cp_key_id),
                );
                return Ok(verdict.refuse(
                    "key_mismatch",
                    format!(
                        "pinned anchor key_id {:?} does not match bundle key_id {:?}",
                        anchor.key_id.trim(),
                        cp_key_id
                    ),
                    Some(json!({ "expected": anchor.key_id.trim(), "found": cp_key_id })),
                ));
            }
            Some(anchor.public_key.trim().to_ascii_lowercase())
        } else if !trust.trust_keys.is_empty() {
            match trust.trust_keys.iter().find(|k| k.key_id.trim() == cp_key_id) {
                Some(k) => Some(k.public_key.trim().to_ascii_lowercase()),
                None => {
                    verdict.authorship = ClaimReport::new(
                        ClaimStatus::Unverified,
                        format!("key {cp_key_id:?} is not present in verifier trust file"),
                    );
                    deferred_cannot_verify = Some((
                        "unknown_key",
                        format!("signing key {cp_key_id:?} is unknown to verifier trust"),
                        Some(json!({ "key_id": cp_key_id })),
                    ));
                    None
                }
            }
        } else {
            verdict.authorship = ClaimReport::new(
                ClaimStatus::Unverified,
                "no out-of-band trust anchor or trust file supplied (integrity only, not authorship)",
            );
            deferred_cannot_verify = Some((
                "unanchored",
                "no --anchor-key/--anchor-key-id or --trust-file supplied; cannot verify authorship".into(),
                Some(json!({ "key_id": cp_key_id })),
            ));
            None
        };

        if let Some(pk) = resolved_pk {
            if verify_ed25519(&pk, &recomputed_cp_digest, &cp_sig).is_err() {
                verdict.authorship =
                    ClaimReport::new(ClaimStatus::Refused, "checkpoint Ed25519 signature invalid");
                return Ok(verdict.refuse(
                    "invalid_checkpoint_signature",
                    "ledger/checkpoint.json Ed25519 signature does not verify against pinned key",
                    Some(json!({ "file": "ledger/checkpoint.json", "key_id": cp_key_id })),
                ));
            }
            if verify_ed25519(&pk, &recomputed_manifest_digest, &manifest_sig).is_err() {
                verdict.authorship =
                    ClaimReport::new(ClaimStatus::Refused, "manifest.sig Ed25519 signature invalid");
                return Ok(verdict.refuse(
                    "invalid_manifest_signature",
                    "manifest.sig Ed25519 signature does not verify against pinned key",
                    Some(json!({ "file": "manifest.sig", "key_id": cp_key_id })),
                ));
            }
            verdict.authorship = ClaimReport::new(
                ClaimStatus::Verified,
                format!(
                    "Ed25519 checkpoint and manifest signatures verified against pinned key {cp_key_id:?}"
                ),
            );
        }
    }

    // Parse remaining hashed files.
    let events = match parse_jsonl_strict::<BundleLedgerEvent>(&file_bytes["ledger/events.jsonl"]) {
        Ok(e) => e,
        Err(e) => {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, format!("invalid events.jsonl: {e}"));
            return Ok(verdict.refuse(
                "invalid_event_json",
                format!("invalid ledger/events.jsonl: {e}"),
                Some(json!({ "file": "ledger/events.jsonl" })),
            ));
        }
    };
    if events.len() as u64 != manifest.counts.events {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "events count disagrees with manifest");
        return Ok(verdict.refuse(
            "count_mismatch",
            format!(
                "manifest counts.events ({}) does not match ledger/events.jsonl ({})",
                manifest.counts.events,
                events.len()
            ),
            Some(json!({ "field": "counts.events" })),
        ));
    }

    let policy_revisions: Vec<PolicyRevisionRecord> =
        match parse_strict::<Vec<PolicyRevisionRecord>>(&file_bytes["policy/revisions.json"]) {
            Ok(p) => p,
            Err(e) => {
                verdict.integrity =
                    ClaimReport::new(ClaimStatus::Refused, format!("invalid policy/revisions.json: {e}"));
                return Ok(verdict.refuse(
                    "invalid_policy_revisions",
                    format!("invalid policy/revisions.json: {e}"),
                    Some(json!({ "file": "policy/revisions.json" })),
                ));
            }
        };
    if policy_revisions.len() as u64 != manifest.counts.policy_revisions {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "policy_revisions count mismatch");
        return Ok(verdict.refuse(
            "count_mismatch",
            "manifest counts.policy_revisions disagrees with policy/revisions.json",
            Some(json!({ "field": "counts.policy_revisions" })),
        ));
    }

    // Verify policy revision uniqueness on (kind, revision) and derive/check
    // document SHA-256 and `sod_tools` independently from the hashed policy doc.
    if verify_policy_revisions(&mut verdict, &policy_revisions).is_err() {
        return Ok(verdict);
    }

    let artifacts: Vec<ArtifactIndexEntry> =
        match parse_strict::<Vec<ArtifactIndexEntry>>(&file_bytes["artifacts/index.json"]) {
            Ok(a) => a,
            Err(e) => {
                verdict.integrity =
                    ClaimReport::new(ClaimStatus::Refused, format!("invalid artifacts/index.json: {e}"));
                return Ok(verdict.refuse(
                    "invalid_artifacts_index",
                    format!("invalid artifacts/index.json: {e}"),
                    Some(json!({ "file": "artifacts/index.json" })),
                ));
            }
        };
    if artifacts.len() as u64 != manifest.counts.artifacts {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "artifacts count mismatch");
        return Ok(verdict.refuse(
            "count_mismatch",
            "manifest counts.artifacts disagrees with artifacts/index.json",
            Some(json!({ "field": "counts.artifacts" })),
        ));
    }

    let evidence_rows = match parse_jsonl_strict::<EvidenceRow>(&file_bytes["evidence/rows.jsonl"]) {
        Ok(r) => r,
        Err(e) => {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("invalid evidence/rows.jsonl: {e}"));
            return Ok(verdict.refuse(
                "invalid_evidence_rows",
                format!("invalid evidence/rows.jsonl: {e}"),
                Some(json!({ "file": "evidence/rows.jsonl" })),
            ));
        }
    };
    if evidence_rows.len() as u64 != manifest.counts.evidence_rows {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "evidence_rows count mismatch");
        return Ok(verdict.refuse(
            "count_mismatch",
            "manifest counts.evidence_rows disagrees with evidence/rows.jsonl",
            Some(json!({ "field": "counts.evidence_rows" })),
        ));
    }

    // Check 12: withheld.json.
    let withheld: WithheldReport = match parse_strict::<WithheldReport>(&file_bytes["withheld.json"]) {
        Ok(w) => w,
        Err(e) => {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, format!("invalid withheld.json: {e}"));
            return Ok(verdict.refuse(
                "invalid_withheld",
                format!("invalid withheld.json: {e}"),
                Some(json!({ "file": "withheld.json" })),
            ));
        }
    };
    let withheld_sum: u64 = withheld.classes.values().sum();
    if withheld.total != withheld_sum || withheld.total != manifest.counts.withheld_total {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "withheld.json total mismatch");
        return Ok(verdict.refuse(
            "withheld_count_mismatch",
            format!(
                "withheld.json total ({}) disagrees with class sum ({withheld_sum}) or manifest ({})",
                withheld.total, manifest.counts.withheld_total
            ),
            Some(json!({ "file": "withheld.json" })),
        ));
    }
    verdict.withheld = Some(withheld.clone());

    // Load every approvals/<id>.json listed in manifest.files.
    let mut receipts: BTreeMap<i64, ApprovalReceipt> = BTreeMap::new();
    for (rel, bytes) in &file_bytes {
        if let Some(rest) = rel.strip_prefix("approvals/") {
            let Some(id_str) = rest.strip_suffix(".json") else {
                verdict.integrity =
                    ClaimReport::new(ClaimStatus::Refused, format!("unexpected file {rel:?}"));
                return Ok(verdict.refuse(
                    "invalid_receipt_filename",
                    format!("unexpected approval file name {rel:?}"),
                    Some(json!({ "file": rel })),
                ));
            };
            let file_id: i64 = match id_str.parse::<i64>() {
                Ok(n) if n > 0 && n.to_string() == id_str => n,
                _ => {
                    verdict.integrity =
                        ClaimReport::new(ClaimStatus::Refused, format!("invalid approval id in {rel:?}"));
                    return Ok(verdict.refuse(
                        "invalid_receipt_filename",
                        format!("non-integer approval id in {rel:?}"),
                        Some(json!({ "file": rel })),
                    ));
                }
            };
            let receipt: ApprovalReceipt = match parse_strict::<ApprovalReceipt>(bytes) {
                Ok(r) => r,
                Err(e) => {
                    verdict.integrity =
                        ClaimReport::new(ClaimStatus::Refused, format!("invalid receipt {rel:?}: {e}"));
                    return Ok(verdict.refuse(
                        "invalid_receipt_json",
                        format!("invalid receipt {rel:?}: {e}"),
                        Some(json!({ "file": rel })),
                    ));
                }
            };
            if receipt.approval_id != file_id {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("receipt approval_id mismatch in {rel:?}"),
                );
                return Ok(verdict.refuse(
                    "receipt_id_filename_mismatch",
                    format!("file {rel:?} carries approval_id {}", receipt.approval_id),
                    Some(json!({ "file": rel, "approval_id": receipt.approval_id })),
                ));
            }
            receipts.insert(file_id, receipt);
        }
    }
    if receipts.len() as u64 != manifest.counts.approvals {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "approvals count mismatch");
        return Ok(verdict.refuse(
            "count_mismatch",
            format!(
                "manifest counts.approvals ({}) disagrees with approval receipts ({})",
                manifest.counts.approvals,
                receipts.len()
            ),
            Some(json!({ "field": "counts.approvals" })),
        ));
    }

    // Check 10: every row in clear must be one the exporter's allow-list
    // exports in clear (`export_schema`): a listed hub channel, typed
    // fields, no free text, strict JSON, and nothing the backstop scanner
    // flags. A row it would stub is refused here.
    for ev in &events {
        let envelope = [
            ev.originator.as_deref(),
            ev.episode_id.as_deref(),
            ev.causal_parent_id.as_deref(),
            ev.dedupe_key.as_deref(),
        ];
        let found = if ev.redacted {
            find_forbidden_in_text(&ev.ulid).map(|v| (v.class, v.detail))
        } else {
            ledger_row_stub_class(manifest.class, &ev.channel, &ev.payload, &envelope)
                .or_else(|| find_forbidden_in_text(&ev.ulid).map(|v| (v.class, v.detail)))
        };
        if let Some((class, detail)) = found {
            let reason = if class == CLASS_UNLISTED_PAYLOAD || class == CLASS_FREE_TEXT_PAYLOAD {
                "unlisted_payload_in_clear"
            } else {
                "forbidden_private_content"
            };
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("forbidden content: {detail}"));
            return Ok(verdict.refuse(
                reason,
                format!("ledger event in clear must be a hash-only stub ({class}): {detail}"),
                Some(json!({
                    "file": "ledger/events.jsonl",
                    "seq": ev.seq,
                    "org_seq": ev.org_seq,
                    "class": class
                })),
            ));
        }
    }
    for (rel, bytes) in &file_bytes {
        if rel == "ledger/events.jsonl" || rel == "withheld.json" {
            continue;
        }
        let values: Vec<Value> = if rel.ends_with(".jsonl") {
            match std::str::from_utf8(bytes) {
                Ok(text) => {
                    let mut vals = Vec::new();
                    for line in text.lines().filter(|l| !l.trim().is_empty()) {
                        match parse_strict_json(line) {
                            Ok(v) => vals.push(v),
                            Err(e) => {
                                verdict.integrity = ClaimReport::new(
                                    ClaimStatus::Refused,
                                    format!("{rel} is not strict JSON"),
                                );
                                return Ok(verdict.refuse(
                                    "invalid_bundle_json",
                                    format!("{rel} line is not strict JSON: {e}"),
                                    Some(json!({ "file": rel })),
                                ));
                            }
                        }
                    }
                    vals
                }
                Err(_) => Vec::new(),
            }
        } else {
            match parse_strict_json_bytes(bytes) {
                Ok(v) => vec![v],
                Err(e) => {
                    verdict.integrity =
                        ClaimReport::new(ClaimStatus::Refused, format!("{rel} is not strict JSON"));
                    return Ok(verdict.refuse(
                        "invalid_bundle_json",
                        format!("{rel} is not strict JSON: {e}"),
                        Some(json!({ "file": rel })),
                    ));
                }
            }
        };
        for (idx, val) in values.iter().enumerate() {
            if let Some(v) = find_forbidden_in_value(val) {
                verdict.integrity =
                    ClaimReport::new(ClaimStatus::Refused, format!("forbidden content: {}", v.detail));
                return Ok(verdict.refuse(
                    "forbidden_private_content",
                    format!(
                        "{rel} record {} contains forbidden content ({}): {}",
                        idx + 1,
                        v.class,
                        v.detail
                    ),
                    Some(json!({ "file": rel, "line": idx + 1, "class": v.class })),
                ));
            }
        }
    }

    // Checks 4, 6, 11: Row hashes under hash_v, downgrade refusal, legacy
    // unhashed prefix, and redacted hash-only row validation.
    let mut seen_hashed = false;
    let mut seen_v2 = false;
    let mut legacy_prefix = LegacyPrefixReport::default();
    let mut redacted_report = RedactedEventsReport::default();
    let mut stub_classes: BTreeMap<String, u64> = BTreeMap::new();
    let mut payload_verified_rows = 0u64;

    for ev in &events {
        let pos = ev.seq.or(ev.org_seq);

        if ev.redacted {
            // `cross_org_events` stubs exist only in a default-organization
            // `org` bundle, where other organizations' ORG-EVENT-DEFAULT
            // approval rows sit in this organization's ledger.
            let cross_org_allowed =
                manifest.class == CheckpointClass::Org && manifest.org_id.as_deref() == Some(DEFAULT_ORG);
            let valid_class = ev.redacted_class.as_deref().is_some_and(|c| {
                STUB_CLASSES.contains(&c) && (c != CLASS_CROSS_ORG_EVENTS || cross_org_allowed)
            });
            let stripped = ev.channel == REDACTED_CHANNEL
                && ev.payload.is_empty()
                && ev.originator.is_none()
                && ev.episode_id.is_none()
                && ev.causal_parent_id.is_none()
                && ev.dedupe_key.is_none();
            if !valid_class || !stripped {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("malformed redacted ledger stub at {pos:?}"),
                );
                return Ok(verdict.refuse(
                    "invalid_redacted_event",
                    format!(
                        "redacted event at {pos:?} must strip channel/payload/parties and carry a valid redacted_class"
                    ),
                    Some(json!({ "seq": ev.seq, "org_seq": ev.org_seq })),
                ));
            }
            redacted_report.count += 1;
            if let Some(p) = pos {
                redacted_report.seqs.push(p);
            }
            if let Some(c) = ev.redacted_class.as_deref() {
                *stub_classes.entry(c.to_string()).or_insert(0u64) += 1;
            }
        } else if ev.redacted_class.is_some() {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("unredacted ledger row at {pos:?} carries redacted_class"),
            );
            return Ok(verdict.refuse(
                "invalid_redacted_event",
                format!("unredacted event at {pos:?} must not set redacted_class"),
                Some(json!({ "seq": ev.seq, "org_seq": ev.org_seq })),
            ));
        }

        let Some(entry_hash) = ev.entry_hash.as_deref() else {
            if seen_hashed {
                verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "unhashed row after hashed rows");
                return Ok(verdict.refuse(
                    "unhashed_row_after_hashed",
                    format!("unhashed ledger row at {pos:?} appears after hashed rows"),
                    Some(json!({ "seq": ev.seq, "org_seq": ev.org_seq })),
                ));
            }
            legacy_prefix.count += 1;
            if legacy_prefix.first_seq.is_none() {
                legacy_prefix.first_seq = pos;
            }
            legacy_prefix.last_seq = pos;
            continue;
        };
        seen_hashed = true;

        if ev.hash_v != HASH_V1 && ev.hash_v != HASH_V2 {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("unsupported hash_v {}", ev.hash_v));
            return Ok(verdict.refuse(
                "unsupported_hash_v",
                format!("unsupported hash_v {} at {pos:?}", ev.hash_v),
                Some(json!({ "seq": ev.seq, "org_seq": ev.org_seq, "hash_v": ev.hash_v })),
            ));
        }
        if ev.hash_v == HASH_V2 {
            seen_v2 = true;
        } else if seen_v2 && ev.hash_v == HASH_V1 {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, "hash_v downgraded from 2 to 1 inside ledger");
            return Ok(verdict.refuse(
                "hash_v_downgrade",
                format!("ledger row at {pos:?} uses hash_v = 1 after a hash_v = 2 row"),
                Some(json!({ "seq": ev.seq, "org_seq": ev.org_seq, "hash_v": ev.hash_v })),
            ));
        }

        if ev.redacted {
            if entry_hash.len() != 64 || !entry_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("redacted ledger stub at {pos:?} has invalid entry_hash"),
                );
                return Ok(verdict.refuse(
                    "invalid_redacted_event",
                    format!("redacted event at {pos:?} entry_hash is not 64 hex chars"),
                    Some(json!({ "seq": ev.seq, "org_seq": ev.org_seq })),
                ));
            }
            // Payload is omitted; chain linkage to neighbors and checkpoint is verified in Check 5.
            continue;
        }

        let expected_hash = compute_entry_hash_for_version(
            ev.hash_v,
            ev.prev_hash.as_deref(),
            &ev.ulid,
            &ev.channel,
            &ev.payload,
            ev.originator.as_deref(),
            ev.episode_id.as_deref(),
            ev.causal_parent_id.as_deref(),
            &ev.created_at,
            ev.dedupe_key.as_deref(),
            Some(ev.org_id.as_str()),
        )
        .expect("hash_v validated above");
        if !expected_hash.eq_ignore_ascii_case(entry_hash) {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("entry_hash mismatch at {pos:?}"));
            return Ok(verdict.refuse(
                "row_hash_mismatch",
                format!("entry_hash mismatch at {pos:?} under hash_v = {}", ev.hash_v),
                Some(json!({ "seq": ev.seq, "org_seq": ev.org_seq, "hash_v": ev.hash_v })),
            ));
        }
        payload_verified_rows += 1;
    }

    if legacy_prefix.count != manifest.counts.unhashed_legacy_prefix {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "unhashed_legacy_prefix count mismatch");
        return Ok(verdict.refuse(
            "count_mismatch",
            format!(
                "manifest counts.unhashed_legacy_prefix ({}) disagrees with events ({})",
                manifest.counts.unhashed_legacy_prefix, legacy_prefix.count
            ),
            Some(json!({ "field": "counts.unhashed_legacy_prefix" })),
        ));
    }
    if redacted_report.count != manifest.counts.redacted_events {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "redacted_events count mismatch");
        return Ok(verdict.refuse(
            "count_mismatch",
            format!(
                "manifest counts.redacted_events ({}) disagrees with events ({})",
                manifest.counts.redacted_events, redacted_report.count
            ),
            Some(json!({ "field": "counts.redacted_events" })),
        ));
    }
    // Every stub must be counted in withheld.json under its class: a stub is
    // the exporter's assertion, and the withheld report is where it is made.
    for (class, n) in &stub_classes {
        let counted = withheld.classes.get(class).copied().unwrap_or(0);
        if counted < *n {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("{n} {class:?} stub(s) but withheld.json counts {counted}"),
            );
            return Ok(verdict.refuse(
                "withheld_count_mismatch",
                format!("ledger/events.jsonl carries {n} redacted stub(s) of class {class:?}, withheld.json counts {counted}"),
                Some(json!({ "file": "withheld.json", "class": class })),
            ));
        }
    }
    verdict.unhashed_legacy_prefix = legacy_prefix;
    verdict.redacted_events = redacted_report;

    // The manifest window must be the window the ledger rows and checkpoint
    // state.
    let expected_window = match manifest.class {
        CheckpointClass::Hub => match (events.first(), events.last()) {
            (Some(first), Some(last)) => Some(Window {
                start: normalize_ts_utc(&first.created_at),
                end: normalize_ts_utc(&last.created_at),
            }),
            _ => None,
        },
        CheckpointClass::Org => cp_file
            .checkpoint
            .window
            .as_ref()
            .map(|w| Window { start: normalize_ts_utc(&w.start), end: normalize_ts_utc(&w.end) }),
    };
    if let Some(w) = expected_window
        && (normalize_ts_utc(&manifest.window.start) != w.start
            || normalize_ts_utc(&manifest.window.end) != w.end)
    {
        verdict.integrity =
            ClaimReport::new(ClaimStatus::Refused, "manifest window disagrees with the ledger");
        return Ok(verdict.refuse(
            "manifest_window_mismatch",
            format!(
                "manifest.window {}..{} does not match the bundle's ledger window {}..{}",
                manifest.window.start, manifest.window.end, w.start, w.end
            ),
            Some(json!({ "field": "window" })),
        ));
    }

    // evidence/rows.jsonl is rebuilt from the unredacted events; any extra,
    // missing or altered row refuses.
    let timeline = PolicyTimeline::build(&events, &policy_revisions);
    if verify_evidence_rows(&mut verdict, manifest.class, &events, &timeline, &evidence_rows).is_err() {
        return Ok(verdict);
    }

    // Check 5: Sequence basis and class-specific chain continuity.
    let chain_ok = match manifest.class {
        CheckpointClass::Hub => verify_hub_chain(
            &mut verdict,
            &cp_file,
            &events,
            payload_verified_rows,
            trust,
            &mut deferred_cannot_verify,
        ),
        CheckpointClass::Org => verify_org_chain(
            &mut verdict,
            &cp_file,
            &events,
            payload_verified_rows,
            trust,
            &mut deferred_cannot_verify,
        ),
    };
    if chain_ok.is_err() {
        return Ok(verdict);
    }

    // Checks 7 & 8: Approval receipts and cross-links.
    if verify_receipts_and_cross_links(
        &mut verdict,
        manifest.class,
        manifest.org_id.as_deref(),
        &events,
        &receipts,
        &policy_revisions,
        &timeline,
        &artifacts,
        &withheld,
    )
    .is_err()
    {
        return Ok(verdict);
    }

    // Check 9: Artifact trace (artifact -> task -> run/attempt -> policy revision -> approval).
    if verify_artifact_traces(
        &mut verdict,
        manifest.class,
        manifest.org_id.as_deref(),
        &events,
        &artifacts,
        &timeline,
        &receipts,
    )
    .is_err()
    {
        return Ok(verdict);
    }

    if verdict.redacted_events.count > 0 {
        let n = verdict.redacted_events.count;
        verdict.warnings.push(format!(
            "{n} redacted hash-only stub(s): approval receipts, releases, cross-links and separation of duties \
             {REDACTED_COVERAGE_NOTE}"
        ));
        // A stub can hide an approval, a release or any row: no claim that
        // depends on row contents may read as complete. The status itself
        // drops to `partial`, not only the text.
        for claim in [
            &mut verdict.completeness,
            &mut verdict.approvals,
            &mut verdict.separation_of_duties,
            &mut verdict.artifacts,
        ] {
            if matches!(claim.status, ClaimStatus::Verified | ClaimStatus::NotApplicable) {
                claim.status = ClaimStatus::Partial;
            }
            claim.basis = format!("{}; {n} stub(s) in the bundle: {REDACTED_COVERAGE_NOTE}", claim.basis);
        }
    }

    if let Some((reason, detail, offending)) = deferred_cannot_verify {
        return Ok(verdict.cannot_verify(reason, detail, offending));
    }

    verdict.ok = true;
    verdict.exit_code = 0;
    Ok(verdict)
}

fn verify_policy_revisions(
    verdict: &mut BundleVerdict,
    policy_revisions: &[PolicyRevisionRecord],
) -> Result<(), ()> {
    let mut seen: BTreeSet<(&str, i64)> = BTreeSet::new();
    for pol in policy_revisions {
        if !seen.insert((pol.kind.as_str(), pol.revision)) {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("duplicate policy revision ({:?}, rev {})", pol.kind, pol.revision),
            );
            verdict.set_refuse(
                "duplicate_policy_revision",
                format!(
                    "policy/revisions.json contains duplicate entry for kind {:?} revision {}",
                    pol.kind, pol.revision
                ),
                Some(json!({ "kind": pol.kind, "revision": pol.revision })),
            );
            return Err(());
        }
        if let Some(doc_str) = pol.document.as_deref() {
            let parsed: Value = match serde_json::from_str(doc_str) {
                Ok(v) => v,
                Err(e) => {
                    verdict.integrity = ClaimReport::new(
                        ClaimStatus::Refused,
                        format!("invalid JSON in policy document ({:?}, rev {})", pol.kind, pol.revision),
                    );
                    verdict.set_refuse(
                        "invalid_policy_document",
                        format!(
                            "policy/revisions.json ({:?}, rev {}) document is not valid JSON: {e}",
                            pol.kind, pol.revision
                        ),
                        Some(json!({ "kind": pol.kind, "revision": pol.revision })),
                    );
                    return Err(());
                }
            };
            let recomputed_sha = sha256_hex(ua_core::canonical::to_string(&parsed).as_bytes());
            if !recomputed_sha.eq_ignore_ascii_case(&pol.document_sha256) {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("policy document digest mismatch ({:?}, rev {})", pol.kind, pol.revision),
                );
                verdict.set_refuse(
                    "policy_document_digest_mismatch",
                    format!(
                        "policy/revisions.json ({:?}, rev {}) document SHA-256 ({recomputed_sha}) disagrees with document_sha256 ({})",
                        pol.kind, pol.revision, pol.document_sha256
                    ),
                    Some(json!({ "kind": pol.kind, "revision": pol.revision })),
                );
                return Err(());
            }
            let expected_sod = extract_sod_tools_from_doc(&parsed);
            let mut claimed_sod = pol.sod_tools.clone();
            claimed_sod.sort();
            claimed_sod.dedup();
            if claimed_sod != expected_sod {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!(
                        "policy sod_tools disagrees with document ({:?}, rev {})",
                        pol.kind, pol.revision
                    ),
                );
                verdict.set_refuse(
                    "policy_sod_mismatch",
                    format!(
                        "policy/revisions.json ({:?}, rev {}) sod_tools ({claimed_sod:?}) does not match policy document ({expected_sod:?})",
                        pol.kind, pol.revision
                    ),
                    Some(json!({ "kind": pol.kind, "revision": pol.revision })),
                );
                return Err(());
            }
        } else if !pol.sod_tools.is_empty() {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!(
                    "policy sod_tools claimed without backing document ({:?}, rev {})",
                    pol.kind, pol.revision
                ),
            );
            verdict.set_refuse(
                "policy_sod_unverifiable",
                format!(
                    "policy/revisions.json ({:?}, rev {}) claims sod_tools without including its hashed document",
                    pol.kind, pol.revision
                ),
                Some(json!({ "kind": pol.kind, "revision": pol.revision })),
            );
            return Err(());
        }
    }
    Ok(())
}

fn integrity_basis(chain_desc: &str, payload_verified: u64, redacted: u64) -> String {
    if redacted == 0 {
        format!(
            "manifest digest, all per-file SHA-256 digests, all {payload_verified} hashed row(s) payload-hash-verified under hash_v, and {chain_desc}"
        )
    } else {
        let total = payload_verified + redacted;
        format!(
            "manifest digest, all per-file SHA-256 digests, {payload_verified} of {total} hashed row(s) payload-hash-verified under hash_v; \
             {redacted} redacted hash-only row(s) chain-linked only (payload omitted and not row-hash-verified), and {chain_desc}"
        )
    }
}

fn verify_hub_chain(
    verdict: &mut BundleVerdict,
    cp_file: &BundleCheckpointFile,
    events: &[BundleLedgerEvent],
    payload_verified_rows: u64,
    trust: &BundleVerifyTrust,
    deferred: &mut DeferredCannotVerify,
) -> Result<(), ()> {
    let cp_seq = cp_file.checkpoint.seq.expect("validated hub checkpoint");
    let cp_hash = cp_file.checkpoint.hash.as_deref().expect("validated hub checkpoint");

    if events.is_empty() {
        verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "hub bundle has no ledger events");
        verdict.completeness = ClaimReport::new(ClaimStatus::Refused, "hub bundle missing checkpoint row");
        verdict.set_refuse(
            "checkpoint_head_mismatch",
            format!("hub checkpoint expects seq {cp_seq} but ledger/events.jsonl is empty"),
            Some(json!({ "expected_seq": cp_seq })),
        );
        return Err(());
    }

    // First validate field presence, duplicates, and monotonic ordering so a
    // swapped pair like [1, 3, 2, 4] is diagnosed as `sequence_out_of_order`
    // rather than stopping early on the 1 -> 3 jump as `sequence_gap`.
    let mut seen_seqs = BTreeSet::new();
    for (idx, ev) in events.iter().enumerate() {
        let Some(seq) = ev.seq else {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "hub ledger event missing global seq");
            verdict.set_refuse(
                "invalid_sequence_field",
                format!("hub bundle event at index {idx} is missing global seq"),
                Some(json!({ "index": idx })),
            );
            return Err(());
        };
        if ev.org_seq.is_some() {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "hub ledger event carries org_seq");
            verdict.set_refuse(
                "invalid_sequence_field",
                format!("hub bundle event at seq {seq} must not carry org_seq"),
                Some(json!({ "seq": seq })),
            );
            return Err(());
        }
        if !seen_seqs.insert(seq) {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, format!("duplicate seq {seq}"));
            verdict.completeness = ClaimReport::new(ClaimStatus::Refused, format!("duplicate seq {seq}"));
            verdict.set_refuse(
                "sequence_duplicate",
                format!("duplicate global seq {seq} in ledger/events.jsonl"),
                Some(json!({ "seq": seq })),
            );
            return Err(());
        }
        if idx > 0 {
            let prev_seq = events[idx - 1].seq.expect("checked");
            if seq < prev_seq {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("out-of-order seq {seq} after {prev_seq}"),
                );
                verdict.completeness = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("out-of-order seq {seq} after {prev_seq}"),
                );
                verdict.set_refuse(
                    "sequence_out_of_order",
                    format!("global seq {seq} appears after {prev_seq} in ledger/events.jsonl"),
                    Some(json!({ "seq": seq, "prev_seq": prev_seq })),
                );
                return Err(());
            }
        }
    }

    for idx in 1..events.len() {
        let prev = &events[idx - 1];
        let ev = &events[idx];
        let prev_seq = prev.seq.expect("checked");
        let seq = ev.seq.expect("checked");
        if seq != prev_seq + 1 {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("sequence gap between {prev_seq} and {seq}"));
            verdict.completeness =
                ClaimReport::new(ClaimStatus::Refused, format!("missing seq {}", prev_seq + 1));
            verdict.set_refuse(
                "sequence_gap",
                format!("missing global seq {} between {prev_seq} and {seq}", prev_seq + 1),
                Some(json!({ "expected_seq": prev_seq + 1, "found_seq": seq })),
            );
            return Err(());
        }
        if let Some(prev_eh) = prev.entry_hash.as_deref() {
            if !ev.prev_hash.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(prev_eh)) {
                verdict.integrity =
                    ClaimReport::new(ClaimStatus::Refused, format!("broken chain link at seq {seq}"));
                verdict.set_refuse(
                    "chain_broken",
                    format!("event at seq {seq} prev_hash does not equal seq {prev_seq} entry_hash"),
                    Some(json!({ "seq": seq })),
                );
                return Err(());
            }
        } else if ev.entry_hash.is_some()
            && !ev.prev_hash.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(GENESIS_HASH))
        {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("first hashed row at seq {seq} not linked to genesis"),
            );
            verdict.set_refuse(
                "chain_broken",
                format!("first hashed event at seq {seq} prev_hash does not equal genesis"),
                Some(json!({ "seq": seq })),
            );
            return Err(());
        }
    }

    let first = &events[0];
    let first_seq = first.seq.expect("checked");
    let last = events.last().expect("non-empty");
    let last_seq = last.seq.expect("checked");
    if last_seq != cp_seq || !last.entry_hash.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(cp_hash)) {
        verdict.integrity =
            ClaimReport::new(ClaimStatus::Refused, "ledger tail disagrees with hub checkpoint");
        verdict.completeness =
            ClaimReport::new(ClaimStatus::Refused, "ledger tail disagrees with hub checkpoint");
        verdict.set_refuse(
            "checkpoint_head_mismatch",
            format!("ledger tail (seq {last_seq}) does not match hub checkpoint (seq {cp_seq})"),
            Some(json!({ "expected_seq": cp_seq, "found_seq": last_seq })),
        );
        return Err(());
    }

    if first_seq == 1 {
        if let Some(first_hashed) = events.iter().find(|e| e.entry_hash.is_some())
            && !first_hashed.prev_hash.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(GENESIS_HASH))
        {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, "first hashed event not linked to genesis");
            verdict.set_refuse(
                "chain_broken",
                "first hashed event prev_hash does not equal genesis",
                Some(json!({ "seq": first_hashed.seq })),
            );
            return Err(());
        }
        if let Some(pin) = &trust.pinned_hub {
            if pin.seq > cp_seq {
                verdict.completeness = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("bundle ends at seq {cp_seq}, earlier than pinned seq {}", pin.seq),
                );
                verdict.set_refuse(
                    "shortened_range",
                    format!("hub bundle ends at seq {cp_seq}, before pinned checkpoint seq {}", pin.seq),
                    Some(json!({ "pinned_seq": pin.seq, "checkpoint_seq": cp_seq })),
                );
                return Err(());
            }
            let pinned_ev = events.iter().find(|e| e.seq == Some(pin.seq));
            if !pinned_ev
                .and_then(|e| e.entry_hash.as_deref())
                .is_some_and(|h| h.eq_ignore_ascii_case(&pin.hash))
            {
                verdict.completeness = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("pinned checkpoint mismatch at seq {}", pin.seq),
                );
                verdict.set_refuse(
                    "pinned_checkpoint_mismatch",
                    format!("event at pinned seq {} does not match pinned checkpoint hash", pin.seq),
                    Some(json!({ "seq": pin.seq })),
                );
                return Err(());
            }
        }
        verdict.completeness = ClaimReport::new(
            ClaimStatus::Verified,
            format!(
                "hub class: every global seq 1..={cp_seq} appears once in order with continuous hash chain from genesis \
                 (cannot detect truncation after seq {cp_seq} without a later pinned checkpoint)"
            ),
        );
    } else if let Some(pin) = &trust.pinned_hub {
        if pin.seq > cp_seq {
            verdict.completeness = ClaimReport::new(
                ClaimStatus::Refused,
                format!("bundle ends at seq {cp_seq}, earlier than pinned seq {}", pin.seq),
            );
            verdict.set_refuse(
                "shortened_range",
                format!("hub bundle ends at seq {cp_seq}, before pinned checkpoint seq {}", pin.seq),
                Some(json!({ "pinned_seq": pin.seq, "checkpoint_seq": cp_seq })),
            );
            return Err(());
        }
        if pin.seq < first_seq - 1 {
            verdict.completeness = ClaimReport::new(
                ClaimStatus::Refused,
                format!("gap between pinned seq {} and bundle start seq {first_seq}", pin.seq),
            );
            verdict.set_refuse(
                "sequence_gap",
                format!(
                    "missing global seq {} between pinned seq {} and bundle start {first_seq}",
                    pin.seq + 1,
                    pin.seq
                ),
                Some(json!({ "expected_seq": pin.seq + 1, "found_seq": first_seq })),
            );
            return Err(());
        }
        if pin.seq == first_seq - 1 {
            if !first.prev_hash.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(&pin.hash)) {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    "incremental hub bundle prev_hash disagrees with pinned checkpoint",
                );
                verdict.completeness = ClaimReport::new(
                    ClaimStatus::Refused,
                    "incremental hub bundle does not chain from pinned checkpoint",
                );
                verdict.set_refuse(
                    "chain_broken",
                    format!(
                        "first event seq {first_seq} prev_hash does not match pinned checkpoint seq {}",
                        pin.seq
                    ),
                    Some(json!({ "seq": first_seq, "pinned_seq": pin.seq })),
                );
                return Err(());
            }
            verdict.completeness = ClaimReport::new(
                ClaimStatus::Verified,
                format!(
                    "hub class: every global seq {first_seq}..={cp_seq} appears once in order, chained from pinned checkpoint seq {} \
                     (cannot detect truncation after seq {cp_seq} without a later pinned checkpoint)",
                    pin.seq
                ),
            );
        } else {
            let pinned_ev = events.iter().find(|e| e.seq == Some(pin.seq));
            if !pinned_ev
                .and_then(|e| e.entry_hash.as_deref())
                .is_some_and(|h| h.eq_ignore_ascii_case(&pin.hash))
            {
                verdict.completeness = ClaimReport::new(ClaimStatus::Refused, "pinned checkpoint mismatch");
                verdict.set_refuse(
                    "pinned_checkpoint_mismatch",
                    format!("event at pinned seq {} does not match pinned checkpoint hash", pin.seq),
                    Some(json!({ "seq": pin.seq })),
                );
                return Err(());
            }
            verdict.completeness = ClaimReport::new(
                ClaimStatus::Unverified,
                format!(
                    "incremental hub bundle starts at seq {first_seq} without a pinned checkpoint at seq {}",
                    first_seq - 1
                ),
            );
            if deferred.is_none() {
                *deferred = Some((
                    "missing_pinned_checkpoint",
                    format!(
                        "incremental hub bundle starts at seq {first_seq}; pass --prev-checkpoint for seq {}",
                        first_seq - 1
                    ),
                    Some(json!({ "first_seq": first_seq })),
                ));
            }
        }
    } else {
        verdict.completeness = ClaimReport::new(
            ClaimStatus::Unverified,
            format!(
                "incremental hub bundle starts at seq {first_seq} without a pinned checkpoint at seq {}",
                first_seq - 1
            ),
        );
        if deferred.is_none() {
            *deferred = Some((
                "missing_pinned_checkpoint",
                format!(
                    "incremental hub bundle starts at seq {first_seq}; pass --prev-checkpoint for seq {}",
                    first_seq - 1
                ),
                Some(json!({ "first_seq": first_seq })),
            ));
        }
    }

    verdict.integrity = ClaimReport::new(
        ClaimStatus::Verified,
        integrity_basis(
            "global chain continuity verified",
            payload_verified_rows,
            verdict.redacted_events.count,
        ),
    );
    Ok(())
}

fn verify_org_chain(
    verdict: &mut BundleVerdict,
    cp_file: &BundleCheckpointFile,
    events: &[BundleLedgerEvent],
    payload_verified_rows: u64,
    trust: &BundleVerifyTrust,
    deferred: &mut DeferredCannotVerify,
) -> Result<(), ()> {
    let target_org = cp_file.checkpoint.org_id.as_deref().expect("validated org checkpoint");
    let global_from = cp_file.checkpoint.global_from_hash.as_deref().expect("validated org checkpoint");
    let global_head = cp_file.checkpoint.global_head_hash.as_deref().expect("validated org checkpoint");
    let expected_count = cp_file.checkpoint.org_row_count.expect("validated org checkpoint");
    let expected_chain = cp_file.checkpoint.org_chain_hash.as_deref().expect("validated org checkpoint");

    let mut seen_org_seqs = BTreeSet::new();
    for (idx, ev) in events.iter().enumerate() {
        if ev.seq.is_some() {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "org bundle leaks global seq");
            verdict.set_refuse(
                "org_scope_violation",
                format!("org bundle event at index {idx} must not carry global seq"),
                Some(json!({ "index": idx, "seq": ev.seq })),
            );
            return Err(());
        }
        let Some(cur_seq) = ev.org_seq else {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "org bundle event missing org_seq");
            verdict.set_refuse(
                "invalid_sequence_field",
                format!("org bundle event at index {idx} is missing org_seq"),
                Some(json!({ "index": idx })),
            );
            return Err(());
        };
        if ev.org_id != target_org {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "org bundle contains foreign org_id");
            verdict.set_refuse(
                "org_scope_violation",
                format!("org bundle for {target_org:?} contains row for {:?}", ev.org_id),
                Some(json!({ "org_seq": ev.org_seq, "expected_org_id": target_org, "found_org_id": ev.org_id })),
            );
            return Err(());
        }
        if !seen_org_seqs.insert(cur_seq) {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("duplicate org_seq {cur_seq}"));
            verdict.completeness =
                ClaimReport::new(ClaimStatus::Refused, format!("duplicate org_seq {cur_seq}"));
            verdict.set_refuse(
                "sequence_duplicate",
                format!("duplicate org_seq {cur_seq} in ledger/events.jsonl"),
                Some(json!({ "org_seq": cur_seq })),
            );
            return Err(());
        }
        if idx > 0 {
            let prev_seq = events[idx - 1].org_seq.expect("checked");
            if cur_seq < prev_seq {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("out-of-order org_seq {cur_seq} after {prev_seq}"),
                );
                verdict.completeness = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("out-of-order org_seq {cur_seq} after {prev_seq}"),
                );
                verdict.set_refuse(
                    "sequence_out_of_order",
                    format!("org_seq {cur_seq} appears after {prev_seq} in ledger/events.jsonl"),
                    Some(json!({ "org_seq": cur_seq, "prev_org_seq": prev_seq })),
                );
                return Err(());
            }
        }
    }
    for idx in 1..events.len() {
        let prev_seq = events[idx - 1].org_seq.expect("checked");
        let cur_seq = events[idx].org_seq.expect("checked");
        if cur_seq != prev_seq + 1 {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("org_seq gap between {prev_seq} and {cur_seq}"),
            );
            verdict.completeness =
                ClaimReport::new(ClaimStatus::Refused, format!("missing org_seq {}", prev_seq + 1));
            verdict.set_refuse(
                "sequence_gap",
                format!("missing org_seq {} between {prev_seq} and {cur_seq}", prev_seq + 1),
                Some(json!({ "expected_org_seq": prev_seq + 1, "found_org_seq": cur_seq })),
            );
            return Err(());
        }
    }

    if let Some(pin) = &trust.pinned_org {
        if pin.org_id != target_org {
            verdict.completeness =
                ClaimReport::new(ClaimStatus::Refused, "pinned org checkpoint org_id mismatch");
            verdict.set_refuse(
                "pinned_org_mismatch",
                format!("pinned org checkpoint is for {:?}, bundle is for {target_org:?}", pin.org_id),
                Some(json!({ "expected_org_id": pin.org_id, "found_org_id": target_org })),
            );
            return Err(());
        }
        if pin.org_row_count > expected_count {
            verdict.completeness = ClaimReport::new(
                ClaimStatus::Refused,
                format!("org_row_count {expected_count} regressed below pinned {}", pin.org_row_count),
            );
            verdict.set_refuse(
                "shortened_range",
                format!(
                    "org checkpoint org_row_count {expected_count} is less than pinned {}",
                    pin.org_row_count
                ),
                Some(json!({ "pinned_org_row_count": pin.org_row_count, "org_row_count": expected_count })),
            );
            return Err(());
        }
        if !pin.global_head_hash.eq_ignore_ascii_case(global_from) {
            verdict.completeness = ClaimReport::new(
                ClaimStatus::Refused,
                "org checkpoint global_from_hash does not continue from pinned global_head_hash",
            );
            verdict.set_refuse(
                "org_window_gap",
                format!(
                    "org checkpoint global_from_hash {global_from:?} does not match pinned global_head_hash {:?}",
                    pin.global_head_hash
                ),
                Some(json!({ "expected": pin.global_head_hash, "found": global_from })),
            );
            return Err(());
        }
    }

    let seed: Option<(i64, String)> = if let Some(pin) = &trust.pinned_org {
        let initial = if pin.org_row_count == 0 { String::new() } else { pin.org_chain_hash.clone() };
        Some((pin.org_row_count, initial))
    } else if global_from.eq_ignore_ascii_case(GENESIS_HASH) {
        Some((0, String::new()))
    } else {
        None
    };

    if let Some((base_count, mut chain)) = seed {
        for (idx, ev) in events.iter().enumerate() {
            let expected_seq = base_count + 1 + idx as i64;
            let actual_seq = ev.org_seq.expect("checked");
            if actual_seq != expected_seq {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("expected org_seq {expected_seq}, got {actual_seq}"),
                );
                verdict.completeness =
                    ClaimReport::new(ClaimStatus::Refused, format!("missing org_seq {expected_seq}"));
                verdict.set_refuse(
                    "sequence_gap",
                    format!(
                        "expected org_seq {expected_seq} in range {}..={expected_count}, found {actual_seq}",
                        base_count + 1
                    ),
                    Some(json!({ "expected_org_seq": expected_seq, "found_org_seq": actual_seq })),
                );
                return Err(());
            }
            if let Some(eh) = ev.entry_hash.as_deref() {
                chain = org_chain_fold(&chain, eh);
            }
        }
        let actual_total = base_count + events.len() as i64;
        if actual_total != expected_count {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!(
                    "org_row_count mismatch: checkpoint claims {expected_count}, bundle reaches {actual_total}"
                ),
            );
            verdict.completeness = ClaimReport::new(
                ClaimStatus::Refused,
                format!("org_row_count mismatch: expected {expected_count}, got {actual_total}"),
            );
            verdict.set_refuse(
                "org_row_count_mismatch",
                format!(
                    "org checkpoint claims org_row_count {expected_count}, but bundle covers {actual_total}"
                ),
                Some(
                    json!({ "expected_org_row_count": expected_count, "actual_org_row_count": actual_total }),
                ),
            );
            return Err(());
        }
        let final_chain = if expected_count == 0 { empty_org_chain_hash() } else { chain };
        if !final_chain.eq_ignore_ascii_case(expected_chain) {
            verdict.integrity = ClaimReport::new(ClaimStatus::Refused, "refolded org_chain_hash mismatch");
            verdict.completeness = ClaimReport::new(ClaimStatus::Refused, "refolded org_chain_hash mismatch");
            verdict.set_refuse(
                "org_chain_hash_mismatch",
                format!(
                    "refolded org_chain_hash {final_chain} disagrees with signed checkpoint {expected_chain}"
                ),
                Some(json!({ "expected": expected_chain, "computed": final_chain })),
            );
            return Err(());
        }
    } else {
        if let Some(last) = events.last()
            && last.org_seq != Some(expected_count)
        {
            verdict.completeness = ClaimReport::new(
                ClaimStatus::Refused,
                format!(
                    "last org_seq {:?} disagrees with checkpoint org_row_count {expected_count}",
                    last.org_seq
                ),
            );
            verdict.set_refuse(
                "org_row_count_mismatch",
                format!(
                    "last event org_seq {:?} does not match checkpoint org_row_count {expected_count}",
                    last.org_seq
                ),
                Some(json!({ "expected_org_row_count": expected_count, "last_org_seq": last.org_seq })),
            );
            return Err(());
        }
        if deferred.is_none() {
            *deferred = Some((
                "missing_pinned_checkpoint",
                "incremental org bundle requires --prev-checkpoint to refold org_chain_hash from the prior window".into(),
                Some(json!({ "global_from_hash": global_from })),
            ));
        }
    }

    // Optional cross-check against a verified global hub chain.
    if let Some(hub_cc) = &trust.hub_cross_check {
        let start_idx: usize = if global_from.eq_ignore_ascii_case(GENESIS_HASH) {
            0
        } else {
            let Some(pos) = hub_cc
                .events
                .iter()
                .position(|e| e.entry_hash.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(global_from)))
            else {
                verdict.completeness = ClaimReport::new(
                    ClaimStatus::Refused,
                    "global_from_hash not found in hub cross-check chain",
                );
                verdict.set_refuse(
                    "hub_cross_check_mismatch",
                    format!("org checkpoint global_from_hash {global_from:?} does not exist in hub chain"),
                    Some(json!({ "global_from_hash": global_from })),
                );
                return Err(());
            };
            pos + 1
        };
        let end_exclusive: usize = if global_head.eq_ignore_ascii_case(GENESIS_HASH) {
            0
        } else {
            let Some(pos) = hub_cc
                .events
                .iter()
                .position(|e| e.entry_hash.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(global_head)))
            else {
                verdict.completeness = ClaimReport::new(
                    ClaimStatus::Refused,
                    "global_head_hash not found in hub cross-check chain",
                );
                verdict.set_refuse(
                    "hub_cross_check_mismatch",
                    format!("org checkpoint global_head_hash {global_head:?} does not exist in hub chain"),
                    Some(json!({ "global_head_hash": global_head })),
                );
                return Err(());
            };
            pos + 1
        };
        if end_exclusive < start_idx {
            verdict.completeness = ClaimReport::new(
                ClaimStatus::Refused,
                "global_head_hash precedes global_from_hash in hub chain",
            );
            verdict.set_refuse(
                "hub_cross_check_mismatch",
                "org checkpoint global_head_hash precedes global_from_hash in hub chain",
                Some(json!({ "global_from_hash": global_from, "global_head_hash": global_head })),
            );
            return Err(());
        }
        let hub_org_hashes: Vec<&str> = hub_cc.events[start_idx..end_exclusive]
            .iter()
            .filter(|e| e.org_id == target_org)
            .filter_map(|e| e.entry_hash.as_deref())
            .collect();
        let bundle_hashes: Vec<&str> = events.iter().filter_map(|e| e.entry_hash.as_deref()).collect();
        if hub_org_hashes.len() != bundle_hashes.len()
            || !hub_org_hashes.iter().zip(bundle_hashes.iter()).all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            verdict.completeness = ClaimReport::new(
                ClaimStatus::Refused,
                "org bundle rows disagree with global hub chain in [global_from_hash..global_head_hash]",
            );
            verdict.set_refuse(
                "hub_cross_check_mismatch",
                format!(
                    "hub chain holds {} row(s) for org {target_org:?} in window, bundle holds {} (omission or tampering detected)",
                    hub_org_hashes.len(),
                    bundle_hashes.len()
                ),
                Some(json!({ "hub_rows": hub_org_hashes.len(), "bundle_rows": bundle_hashes.len() })),
            );
            return Err(());
        }
        // A stub is the exporter's assertion that its row is private. Where
        // the verified hub bundle carries the same row unredacted, the
        // assertion must hold: only a foreign ORG-EVENT-DEFAULT approval row
        // may be stubbed in a default-organization bundle and in clear in the
        // hub bundle.
        let window: HashMap<String, &BundleLedgerEvent> = hub_cc.events[start_idx..end_exclusive]
            .iter()
            .filter_map(|h| h.entry_hash.as_deref().map(|x| (x.to_ascii_lowercase(), h)))
            .collect();
        for stub in events.iter().filter(|e| e.redacted) {
            let Some(eh) = stub.entry_hash.as_deref() else { continue };
            let Some(hub_row) = window.get(&eh.to_ascii_lowercase()).copied() else {
                continue;
            };
            if hub_row.redacted {
                continue;
            }
            // Only another organization's ORG-EVENT-DEFAULT approval row may be
            // a `cross_org_events` stub: the hub writes those with `null`
            // labels and the neutral originator `system`. The default
            // organization's own approval rows carry their labels.
            let foreign_shape = hub_row.channel.starts_with("agent.approval.")
                && hub_row.originator.as_deref().is_none_or(|o| o == "system")
                && parse_strict_json(&hub_row.payload).is_ok_and(|p| {
                    ["resolved_by", "requested_by"].iter().all(|k| p.get(*k).is_none_or(Value::is_null))
                });
            // Any other stub is justified when the org-class egress rules
            // would stub the hub's row too (hub-only text such as a policy
            // diff is in clear only in the operator's hub bundle).
            let envelope = [
                hub_row.originator.as_deref(),
                hub_row.episode_id.as_deref(),
                hub_row.causal_parent_id.as_deref(),
                hub_row.dedupe_key.as_deref(),
            ];
            let org_rules_stub = stub.redacted_class.as_deref() != Some(CLASS_CROSS_ORG_EVENTS)
                && ledger_row_stub_class(CheckpointClass::Org, &hub_row.channel, &hub_row.payload, &envelope)
                    .is_some();
            let justified = (stub.redacted_class.as_deref() == Some(CLASS_CROSS_ORG_EVENTS) && foreign_shape)
                || org_rules_stub;
            if !justified {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("redacted stub at org_seq {:?} is unredacted in the hub chain", stub.org_seq),
                );
                verdict.completeness =
                    ClaimReport::new(ClaimStatus::Refused, "a redaction stub hides a non-private row");
                verdict.set_refuse(
                    "unjustified_redaction",
                    format!(
                        "org bundle stubs the row at org_seq {:?} as {:?}, but the verified hub bundle carries it \
                         unredacted on non-restricted channel {:?}",
                        stub.org_seq, stub.redacted_class, hub_row.channel
                    ),
                    Some(json!({ "org_seq": stub.org_seq, "class": stub.redacted_class, "channel": hub_row.channel })),
                );
                return Err(());
            }
        }
    }

    verdict.integrity = ClaimReport::new(
        ClaimStatus::Verified,
        integrity_basis(
            "org_seq ordering and org_chain_hash verified",
            payload_verified_rows,
            verdict.redacted_events.count,
        ),
    );
    verdict.completeness = if trust.hub_cross_check.is_some() {
        ClaimReport::new(
            ClaimStatus::Verified,
            format!(
                "org class ({target_org}): org_seq and org_chain_hash verified and cross-checked against global hub chain \
                 between global_from_hash and global_head_hash"
            ),
        )
    } else if trust.pinned_org.is_some() {
        ClaimReport::new(
            ClaimStatus::Verified,
            format!(
                "org class ({target_org}): org_seq and refolded org_chain_hash match the hub's signed window statement \
                 from the pinned org checkpoint; cross-organization linkage and hub omission mid-window are not provable \
                 without a hub cross-check"
            ),
        )
    } else {
        ClaimReport::new(
            ClaimStatus::Unverified,
            format!(
                "org class ({target_org}) without a pinned checkpoint or hub cross-check: org_seq and org_chain_hash \
                 match the hub's signed window statement, but cross-organization linkage and hub omission are not provable \
                 from this bundle alone"
            ),
        )
    };
    Ok(())
}

/// Policy revisions whose `document_sha256` is bound to a hash-verified
/// `agent.config.revision` event in this bundle. Every `kind = "policy"`
/// config event in clear must have its revision listed with the same digest;
/// a missing or disagreeing entry refuses.
fn policy_ledger_bindings(
    verdict: &mut BundleVerdict,
    events: &[BundleLedgerEvent],
    policy_revisions: &[PolicyRevisionRecord],
) -> Result<BTreeSet<(String, i64)>, ()> {
    let mut bound = BTreeSet::new();
    for ev in events.iter().filter(|e| !e.redacted && e.channel == CONFIG_REVISION_CHANNEL) {
        let Ok(p) = parse_strict_json(&ev.payload) else { continue };
        let (Some(kind), Some(rev), Some(sha)) = (
            p.get("kind").and_then(Value::as_str),
            p.get("revision").and_then(Value::as_i64),
            p.get("document_sha256").and_then(Value::as_str),
        ) else {
            continue;
        };
        if ua_core::time::parse_ts(&ev.created_at).is_none() {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, "config revision event time is not RFC 3339");
            verdict.set_refuse(
                "invalid_timestamp",
                format!(
                    "agent.config.revision ({kind:?}, rev {rev}) created_at {:?} is not RFC 3339",
                    ev.created_at
                ),
                Some(json!({ "kind": kind, "revision": rev })),
            );
            return Err(());
        }
        match policy_revisions.iter().find(|r| r.kind == kind && r.revision == rev) {
            Some(pol) if !pol.document_sha256.eq_ignore_ascii_case(sha) => {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("policy revision ({kind:?}, {rev}) digest disagrees with its ledger event"),
                );
                verdict.set_refuse(
                    "policy_ledger_mismatch",
                    format!(
                        "policy/revisions.json ({kind:?}, rev {rev}) document_sha256 {} disagrees with the \
                         agent.config.revision event's {sha}",
                        pol.document_sha256
                    ),
                    Some(json!({ "kind": kind, "revision": rev })),
                );
                return Err(());
            }
            Some(_) => {
                bound.insert((kind.to_string(), rev));
            }
            None if kind == "policy" => {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("policy revision {rev} has a ledger event but no policy/revisions.json entry"),
                );
                verdict.set_refuse(
                    "policy_revision_missing",
                    format!(
                        "the bundle carries the agent.config.revision event for policy revision {rev}, but \
                         policy/revisions.json does not list it"
                    ),
                    Some(json!({ "kind": kind, "revision": rev })),
                );
                return Err(());
            }
            None => {}
        }
    }
    Ok(bound)
}

fn refuse_receipt(
    verdict: &mut BundleVerdict,
    aid: i64,
    reason: &str,
    detail: String,
    field: &str,
) -> Result<(), ()> {
    verdict.integrity = ClaimReport::new(ClaimStatus::Refused, format!("receipt {aid}: {detail}"));
    verdict.set_refuse(
        reason,
        format!("approvals/{aid}.json: {detail}"),
        Some(json!({ "approval_id": aid, "field": field })),
    );
    Err(())
}

fn is_rfc3339(ts: &str) -> bool {
    ua_core::time::parse_ts(ts.trim()).is_some()
}

#[allow(clippy::too_many_arguments)]
fn verify_receipts_and_cross_links(
    verdict: &mut BundleVerdict,
    class: CheckpointClass,
    bundle_org_id: Option<&str>,
    events: &[BundleLedgerEvent],
    receipts: &BTreeMap<i64, ApprovalReceipt>,
    policy_revisions: &[PolicyRevisionRecord],
    timeline: &PolicyTimeline,
    artifacts: &[ArtifactIndexEntry],
    withheld: &WithheldReport,
) -> Result<(), ()> {
    let history = ApprovalHistory::build(events);
    for (idx, p) in &history.payloads {
        if events[*idx].channel == "agent.approval.resolved"
            && p.get("approval_id").and_then(Value::as_i64).is_none()
        {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, "agent.approval.resolved missing approval_id");
            verdict.set_refuse(
                "cross_link_missing_receipt",
                "agent.approval.resolved event carries no approval_id",
                Some(json!({ "seq": events[*idx].seq, "org_seq": events[*idx].org_seq })),
            );
            return Err(());
        }
    }
    // The latest resolution per raw approval id is the one a receipt binds.
    let latest: BTreeMap<i64, usize> =
        history.resolved.iter().filter_map(|(aid, idxs)| idxs.last().map(|i| (*aid, *i))).collect();
    let latest_by_org_seq: HashMap<i64, (i64, usize)> =
        latest.iter().filter_map(|(aid, idx)| events[*idx].org_seq.map(|os| (os, (*aid, *idx)))).collect();

    let bound_policies = policy_ledger_bindings(verdict, events, policy_revisions)?;
    let artifact_index: HashMap<(&str, i64), &ArtifactIndexEntry> =
        artifacts.iter().map(|a| ((a.id.as_str(), a.revision), a)).collect();

    let mut matched_raw: BTreeSet<i64> = BTreeSet::new();
    let mut receipt_for_raw: HashMap<i64, &ApprovalReceipt> = HashMap::new();
    let mut resolver_asserted = 0usize;

    // Check 7 & 8b: every receipt must resolve to an event and satisfy all bindings.
    for (&aid, receipt) in receipts {
        let matched = match class {
            CheckpointClass::Hub => latest.get(&aid).map(|idx| (aid, *idx)),
            CheckpointClass::Org => receipt.ledger.org_seq.and_then(|os| latest_by_org_seq.get(&os).copied()),
        };
        let Some((raw_aid, ev_idx)) = matched else {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("receipt {aid} has no matching ledger event"));
            verdict.set_refuse(
                "cross_link_missing_event",
                format!("approvals/{aid}.json has no matching agent.approval.resolved event in ledger/events.jsonl"),
                Some(json!({ "approval_id": aid })),
            );
            return Err(());
        };
        if !matched_raw.insert(raw_aid) {
            return refuse_receipt(
                verdict,
                aid,
                "cross_link_duplicate_receipt",
                "binds an approval event another receipt already binds".into(),
                "ledger",
            );
        }
        receipt_for_raw.insert(raw_aid, receipt);
        let ev = &events[ev_idx];
        let ev_payload = &history.payloads[&ev_idx];

        if let Some(expected_org) = bundle_org_id
            && receipt.org_id != expected_org
        {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, "receipt org_id disagrees with bundle");
            verdict.set_refuse(
                "org_scope_violation",
                format!("receipt {aid} carries org_id {:?}, expected {expected_org:?}", receipt.org_id),
                Some(json!({ "approval_id": aid, "org_id": receipt.org_id })),
            );
            return Err(());
        }

        let recomputed_id = match receipt.compute_receipt_id() {
            Ok(id) => id,
            Err(e) => {
                return refuse_receipt(
                    verdict,
                    aid,
                    "receipt_id_mismatch",
                    format!("failed to recompute receipt_id: {e}"),
                    "receipt_id",
                );
            }
        };
        if !receipt.receipt_id.eq_ignore_ascii_case(&recomputed_id) {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_id_mismatch",
                format!("claims receipt_id {} but recomputed {recomputed_id}", receipt.receipt_id),
                "receipt_id",
            );
        }

        let pointer_ok = match class {
            CheckpointClass::Hub => receipt.ledger.seq == ev.seq && receipt.ledger.org_seq.is_none(),
            CheckpointClass::Org => receipt.ledger.org_seq == ev.org_seq && receipt.ledger.seq.is_none(),
        };
        let hash_ok = ev.entry_hash.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(&receipt.ledger.hash));
        if !pointer_ok || !hash_ok {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("receipt {aid} ledger pointer mismatch"));
            verdict.set_refuse(
                "cross_link_hash_mismatch",
                format!("approvals/{aid}.json ledger reference does not match the resolved event in ledger/events.jsonl"),
                Some(json!({ "approval_id": aid, "seq": ev.seq, "org_seq": ev.org_seq })),
            );
            return Err(());
        }

        let ev_digest = ev_payload
            .get("payload_sha256")
            .or_else(|| ev_payload.get("action_digest"))
            .and_then(Value::as_str);
        match ev_digest {
            Some(d) if d.eq_ignore_ascii_case(&receipt.action_digest) => {}
            Some(d) => {
                return refuse_receipt(
                    verdict,
                    aid,
                    "receipt_action_digest_mismatch",
                    format!(
                        "action_digest ({}) does not match ledger event payload digest ({d})",
                        receipt.action_digest
                    ),
                    "action_digest",
                );
            }
            None => {
                return refuse_receipt(
                    verdict,
                    aid,
                    "receipt_action_digest_missing",
                    "agent.approval.resolved carries neither payload_sha256 nor action_digest".into(),
                    "action_digest",
                );
            }
        }

        let ev_tool = ev_payload.get("tool").and_then(Value::as_str);
        if ev_tool != Some(receipt.tool.as_str()) {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_event_mismatch",
                format!("tool {:?} disagrees with the ledger event's {ev_tool:?}", receipt.tool),
                "tool",
            );
        }
        let ev_decision = ev_payload.get("decision").and_then(Value::as_str).map(normalize_decision);
        if ev_decision.as_deref() != Some(receipt.decision.as_str()) {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_event_mismatch",
                format!("decision {:?} disagrees with the ledger event's {ev_decision:?}", receipt.decision),
                "decision",
            );
        }
        let ev_transport = ev_payload.get("transport").and_then(Value::as_str);
        if ev_transport != receipt.resolver.transport.as_deref() {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_event_mismatch",
                format!(
                    "resolver transport {:?} disagrees with the ledger event's {ev_transport:?}",
                    receipt.resolver.transport
                ),
                "resolver.transport",
            );
        }
        let ev_expires = ev_payload.get("expires_at").and_then(Value::as_str).map(normalize_ts_utc);
        if ev_expires != receipt.expires_at.as_deref().map(normalize_ts_utc) {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_event_mismatch",
                format!(
                    "expires_at {:?} disagrees with the ledger event's {ev_expires:?}",
                    receipt.expires_at
                ),
                "expires_at",
            );
        }
        // decided_at: well-formed, between the request and the event that
        // recorded the decision.
        let requested_ev = history.requested.get(&raw_aid).map(|i| &events[*i]);
        let after_request = requested_ev
            .is_none_or(|r| cmp_ts(&receipt.decided_at, &r.created_at) != std::cmp::Ordering::Less);
        if !is_rfc3339(&receipt.decided_at)
            || !is_rfc3339(&ev.created_at)
            || cmp_ts(&receipt.decided_at, &ev.created_at) == std::cmp::Ordering::Greater
            || !after_request
        {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_decided_at_out_of_range",
                format!(
                    "decided_at {:?} must be RFC 3339, not before the request ({:?}) and not after the event that \
                     recorded the decision ({})",
                    receipt.decided_at,
                    requested_ev.map(|r| r.created_at.as_str()),
                    ev.created_at
                ),
                "decided_at",
            );
        }

        let placeholders =
            receipt.resolver.label == LABEL_PLACEHOLDER || receipt.requester.label == LABEL_PLACEHOLDER;
        if placeholders && (class != CheckpointClass::Hub || receipt.org_id == DEFAULT_ORG) {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_label_placeholder",
                "carries a label placeholder outside a hub bundle's non-default organization receipt".into(),
                "resolver",
            );
        }
        match ev_payload.get("resolved_by") {
            Some(Value::String(l)) => {
                if !labels_equal(l, &receipt.resolver.label) {
                    return refuse_receipt(
                        verdict,
                        aid,
                        "receipt_event_mismatch",
                        format!(
                            "resolver {:?} disagrees with the ledger event's resolved_by {l:?}",
                            receipt.resolver.label
                        ),
                        "resolver.label",
                    );
                }
            }
            None | Some(Value::Null) => resolver_asserted += 1,
            Some(other) => {
                return refuse_receipt(
                    verdict,
                    aid,
                    "receipt_event_mismatch",
                    format!("ledger event resolved_by is not a label: {other}"),
                    "resolver.label",
                );
            }
        }
        let requested_label = history
            .requested
            .get(&raw_aid)
            .and_then(|i| history.payloads.get(i))
            .and_then(|p| p.get("requested_by"))
            .and_then(Value::as_str);
        if let Some(l) = requested_label
            && !labels_equal(l, &receipt.requester.label)
        {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_event_mismatch",
                format!(
                    "requester {:?} disagrees with the agent.approval.requested event's {l:?}",
                    receipt.requester.label
                ),
                "requester.label",
            );
        }
        if !placeholders {
            let computed = labels_equal(&receipt.resolver.label, &receipt.requester.label);
            if computed != receipt.resolver_is_requester {
                return refuse_receipt(
                    verdict,
                    aid,
                    "receipt_event_mismatch",
                    format!(
                        "resolver_is_requester {} disagrees with the labels (resolver {:?}, requester {:?})",
                        receipt.resolver_is_requester, receipt.resolver.label, receipt.requester.label
                    ),
                    "resolver_is_requester",
                );
            }
        }
        if receipt.decision == "approved"
            && (receipt.resolver.kind != "human" || receipt.resolver.label.trim().is_empty())
        {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_resolver_not_human",
                format!(
                    "approved decision requires resolver kind=\"human\" with non-empty label, got kind={:?} label={:?}",
                    receipt.resolver.kind, receipt.resolver.label
                ),
                "resolver",
            );
        }

        // The policy in force when the decision was recorded, chosen by the
        // verifier from the hash-verified event time and config events.
        let in_force = timeline.in_force(&ev.created_at);
        if receipt.policy_revision != in_force.map(|(rev, _)| rev) {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_policy_mismatch",
                format!(
                    "cites policy revision {:?}, but the revision in force when the decision was recorded is {:?}",
                    receipt.policy_revision,
                    in_force.map(|(rev, _)| rev)
                ),
                "policy_revision",
            );
        }
        let pol = in_force
            .and_then(|(rev, _)| policy_revisions.iter().find(|p| p.kind == "policy" && p.revision == rev));
        let digest_ok = match (pol, receipt.policy_digest.as_deref()) {
            (Some(p), Some(d)) => d.eq_ignore_ascii_case(&p.document_sha256),
            (None, None) => true,
            _ => false,
        };
        if !digest_ok {
            return refuse_receipt(
                verdict,
                aid,
                "receipt_policy_digest_mismatch",
                "policy_digest disagrees with the policy in force".into(),
                "policy_digest",
            );
        }

        for cov in &receipt.covers {
            let ok = artifact_index.get(&(cov.id.as_str(), cov.revision)).is_some_and(|a| {
                a.sha256.eq_ignore_ascii_case(&cov.sha256)
                    && a.release_status == RELEASE_RELEASED
                    && a.approval_id == Some(aid)
            });
            if !ok {
                return refuse_receipt(
                    verdict,
                    aid,
                    "receipt_covers_mismatch",
                    format!(
                        "covers ({}, rev {}, sha256 {}), which does not match a released artifact in artifacts/index.json",
                        cov.id, cov.revision, cov.sha256
                    ),
                    "covers",
                );
            }
        }
    }

    // Check 8a: every unredacted approval resolution must have a receipt.
    for (&raw_aid, &idx) in &latest {
        if !matched_raw.contains(&raw_aid) {
            let ev = &events[idx];
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("missing approval receipt for approval {raw_aid}"),
            );
            verdict.set_refuse(
                "cross_link_missing_receipt",
                format!(
                    "agent.approval.resolved event for approval {raw_aid} has no matching approval receipt"
                ),
                Some(json!({ "approval_id": raw_aid, "seq": ev.seq, "org_seq": ev.org_seq })),
            );
            return Err(());
        }
    }

    // Separation of duties over every approve in the history, not only the
    // latest resolution: the hub refuses self-approval whatever the policy.
    let mut approves = 0usize;
    let mut approves_bound = 0usize;
    let mut sod_policy_governed = 0usize;
    let mut asserted_notes: BTreeSet<&'static str> = BTreeSet::new();
    for (raw_aid, idxs) in &history.resolved {
        let receipt = receipt_for_raw.get(raw_aid).copied();
        let requested_label = history
            .requested
            .get(raw_aid)
            .and_then(|i| history.payloads[i].get("requested_by"))
            .and_then(Value::as_str);
        for idx in idxs {
            let p = &history.payloads[idx];
            if p.get("decision").and_then(Value::as_str).map(normalize_decision).as_deref()
                != Some("approved")
            {
                continue;
            }
            approves += 1;
            let resolver = p.get("resolved_by").and_then(Value::as_str);
            let requester = requested_label
                .or_else(|| receipt.map(|r| r.requester.label.as_str()).filter(|l| *l != LABEL_PLACEHOLDER));
            let same = match (resolver, requester) {
                (Some(a), Some(b)) => labels_equal(a, b),
                _ => receipt.is_some_and(|r| r.resolver_is_requester && idxs.last() == Some(idx)),
            };
            if same {
                let aid = receipt.map_or(*raw_aid, |r| r.approval_id);
                verdict.separation_of_duties = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("approval {aid}: an approve was resolved by its requester"),
                );
                verdict.set_refuse(
                    "receipt_sod_violation",
                    format!(
                        "approval {aid} was approved by its own requester {:?} (separation of duties)",
                        resolver.unwrap_or("[redacted-label]")
                    ),
                    Some(json!({ "approval_id": aid, "field": "resolver" })),
                );
                return Err(());
            }
            let ev_time = &events[*idx].created_at;
            let in_force = timeline.in_force(ev_time);
            let policy_bound = in_force
                .is_none_or(|(rev, bound)| bound && bound_policies.contains(&("policy".to_string(), rev)));
            let tool = p.get("tool").and_then(Value::as_str).unwrap_or("");
            if in_force
                .and_then(|(rev, _)| {
                    policy_revisions.iter().find(|r| r.kind == "policy" && r.revision == rev)
                })
                .is_some_and(|r| r.sod_tools.iter().any(|t| t == tool))
            {
                sod_policy_governed += 1;
            }
            if resolver.is_none() {
                asserted_notes.insert("resolver label not recorded in the ledger (ORG-EVENT-DEFAULT)");
            }
            if requested_label.is_none() {
                asserted_notes
                    .insert("requester label not bound to an agent.approval.requested event in this bundle");
            }
            if !policy_bound {
                asserted_notes
                    .insert("policy in force not bound to an agent.config.revision event in this bundle");
            }
            if resolver.is_some() && requested_label.is_some() && policy_bound {
                approves_bound += 1;
            }
        }
    }

    let org_without_approvals =
        class == CheckpointClass::Org && bundle_org_id.is_some_and(|o| o != DEFAULT_ORG);
    verdict.approvals = if org_without_approvals {
        let omitted = withheld.classes.get(CLASS_APPROVALS_IN_DEFAULT_LEDGER).copied().unwrap_or(0);
        ClaimReport::new(
            ClaimStatus::Unverified,
            format!(
                "not covered: organization {:?} records its approval events in the default organization's ledger \
                 (ORG-EVENT-DEFAULT), so this org bundle carries none of its approvals ({omitted} resolved in the \
                 window, withheld as {CLASS_APPROVALS_IN_DEFAULT_LEDGER}); a release cannot be proved from it",
                bundle_org_id.unwrap_or_default()
            ),
        )
    } else if receipts.is_empty() {
        ClaimReport::new(ClaimStatus::NotApplicable, "no approval resolution in clear in this bundle")
    } else {
        let base = format!(
            "{} receipt(s) bound to hash-verified agent.approval.resolved events (tool, decision, transport, \
             expiry, action digest, decision time{}); hub-asserted: resolver kind, requester kind, request_digest, \
             run_id/attempt",
            receipts.len(),
            if resolver_asserted == 0 { ", resolver label" } else { "" }
        );
        if resolver_asserted > 0 {
            ClaimReport::new(
                ClaimStatus::HubAsserted,
                format!(
                    "{base}, and {resolver_asserted} resolver label(s) the ledger does not record (ORG-EVENT-DEFAULT)"
                ),
            )
        } else {
            ClaimReport::new(ClaimStatus::Verified, base)
        }
    };

    verdict.separation_of_duties = if org_without_approvals {
        ClaimReport::new(ClaimStatus::NotApplicable, "no approvals of this organization are in an org bundle")
    } else if approves == 0 {
        ClaimReport::new(ClaimStatus::NotApplicable, "no approve resolution in clear in this bundle")
    } else if approves_bound == approves {
        ClaimReport::new(
            ClaimStatus::Verified,
            format!(
                "{approves} approve resolution(s): resolver differs from requester (the hub invariant), both labels \
                 bound to hash-verified approval events and the policy in force bound to its agent.config.revision \
                 event; {sod_policy_governed} also named by a policy separation-of-duties rule"
            ),
        )
    } else {
        ClaimReport::new(
            ClaimStatus::HubAsserted,
            format!(
                "{approves} approve resolution(s) show resolver != requester, {} of them hub-asserted: {}",
                approves - approves_bound,
                asserted_notes.into_iter().collect::<Vec<_>>().join("; ")
            ),
        )
    };
    Ok(())
}

fn refuse_trace(
    verdict: &mut BundleVerdict,
    art: &ArtifactIndexEntry,
    reason: &str,
    field: &str,
    detail: String,
) -> Result<(), ()> {
    verdict.integrity = ClaimReport::new(ClaimStatus::Refused, format!("artifact {}: {detail}", art.id));
    verdict.set_refuse(
        reason,
        format!("artifact {} rev {}: {detail}", art.id, art.revision),
        Some(json!({ "artifact_id": art.id, "revision": art.revision, "field": field })),
    );
    Err(())
}

#[allow(clippy::too_many_arguments)]
fn verify_artifact_traces(
    verdict: &mut BundleVerdict,
    class: CheckpointClass,
    bundle_org_id: Option<&str>,
    events: &[BundleLedgerEvent],
    artifacts: &[ArtifactIndexEntry],
    timeline: &PolicyTimeline,
    receipts: &BTreeMap<i64, ApprovalReceipt>,
) -> Result<(), ()> {
    let history = ApprovalHistory::build(events);
    // Deliverable revisions and releases recorded by hash-verified events,
    // indexed so every lookup is constant time.
    let mut revised: HashMap<(String, i64), Vec<Value>> = HashMap::new();
    for ev in events.iter().filter(|e| !e.redacted && e.channel == "agent.deliverable.revised") {
        let Ok(p) = parse_strict_json(&ev.payload) else { continue };
        if let (Some(rev), Some(identity)) =
            (p.get("rev_no").and_then(Value::as_i64), p.get("identity").and_then(Value::as_str))
        {
            revised.entry((identity.to_ascii_lowercase(), rev)).or_default().push(p);
        }
    }
    let all_releases = release_events(events);
    let mut releases_by_sha: HashMap<String, Vec<&ReleaseEvent>> = HashMap::new();
    for e in &all_releases {
        releases_by_sha.entry(e.sha256.clone()).or_default().push(e);
    }
    // The raw approval id each receipt binds, through its resolved event.
    let by_hash: HashMap<String, usize> = events
        .iter()
        .enumerate()
        .filter_map(|(i, e)| e.entry_hash.as_deref().map(|h| (h.to_ascii_lowercase(), i)))
        .collect();
    let receipt_raw: HashMap<i64, i64> = receipts
        .values()
        .filter_map(|r| {
            let idx = by_hash.get(&r.ledger.hash.to_ascii_lowercase())?;
            history
                .payloads
                .get(idx)?
                .get("approval_id")
                .and_then(Value::as_i64)
                .map(|raw| (r.approval_id, raw))
        })
        .collect();

    let mut unbound = 0usize;
    let org_without_approvals =
        class == CheckpointClass::Org && bundle_org_id.is_some_and(|o| o != DEFAULT_ORG);

    for art in artifacts {
        if art.task_id <= 0 {
            return refuse_trace(
                verdict,
                art,
                "broken_artifact_trace",
                "task_id",
                format!("invalid task_id {}", art.task_id),
            );
        }
        if !is_rfc3339(&art.recorded_at) {
            return refuse_trace(
                verdict,
                art,
                "broken_artifact_trace",
                "recorded_at",
                "recorded_at is not RFC 3339".into(),
            );
        }
        let in_force = timeline.in_force(&art.recorded_at).map(|(rev, _)| rev);
        if art.policy_revision != in_force {
            return refuse_trace(
                verdict,
                art,
                "broken_artifact_trace",
                "policy_revision",
                format!(
                    "cites policy revision {:?}, but the revision in force at recorded_at is {in_force:?}",
                    art.policy_revision
                ),
            );
        }
        let has_run = art.run_id.as_deref().is_some_and(|s| !s.trim().is_empty());
        let has_attempt = art.attempt.is_some_and(|a| a > 0);
        if has_run != has_attempt || art.attempt.is_some_and(|a| a <= 0) {
            return refuse_trace(
                verdict,
                art,
                "broken_artifact_trace",
                "run_id",
                "must pair run_id with positive attempt".into(),
            );
        }

        let numeric_id = art.id.strip_prefix("deliverable:").and_then(|n| n.parse::<i64>().ok());
        let sha = art.sha256.to_ascii_lowercase();
        let bound = revised.get(&(sha.clone(), art.revision)).is_some_and(|cands| {
            cands.iter().any(|p| {
                let size_ok = p.get("size_bytes").and_then(Value::as_i64).is_none_or(|s| s == art.size);
                let ids_ok = class == CheckpointClass::Org
                    || (p.get("deliverable_id").and_then(Value::as_i64) == numeric_id
                        && p.get("task_id").and_then(Value::as_i64) == Some(art.task_id));
                size_ok && ids_ok
            })
        });
        if !bound {
            unbound += 1;
        }

        // Release state from the hash-verified release and approval events.
        let matching: Vec<&ReleaseEvent> = releases_by_sha
            .get(&sha)
            .map(|v| {
                v.iter()
                    .copied()
                    .filter(|e| {
                        class == CheckpointClass::Org
                            || e.deliverable_id.is_none()
                            || e.deliverable_id == numeric_id
                    })
                    .collect()
            })
            .unwrap_or_default();
        let state = release_state(&matching, &history);

        match art.release_status.as_str() {
            RELEASE_UNRELEASED
            | RELEASE_NOT_IN_BUNDLE
            | RELEASE_NOT_PROVABLE_IN_ORG_BUNDLE
            | RELEASE_REVOKED => {
                if art.approval_id.is_some() {
                    return refuse_trace(
                        verdict,
                        art,
                        "broken_artifact_trace",
                        "release_status",
                        format!("carries approval_id but release_status is {:?}", art.release_status),
                    );
                }
                if art.release_status == RELEASE_NOT_PROVABLE_IN_ORG_BUNDLE && !org_without_approvals {
                    return refuse_trace(
                        verdict,
                        art,
                        "broken_artifact_trace",
                        "release_status",
                        "not_provable_in_org_bundle is valid only in a non-default organization's org bundle"
                            .into(),
                    );
                }
                if let ReleaseState::Released(_) = state {
                    return refuse_trace(
                        verdict,
                        art,
                        "release_hidden",
                        "release_status",
                        format!(
                            "reports {:?}, but the bundle's hash-verified agent.deliverable.released and approval \
                             events show it released",
                            art.release_status
                        ),
                    );
                }
                if art.release_status == RELEASE_REVOKED && state != ReleaseState::Revoked {
                    return refuse_trace(
                        verdict,
                        art,
                        "broken_artifact_trace",
                        "release_status",
                        "release_revoked without a cancelled release or a denied or revoked approval in the bundle".into(),
                    );
                }
                continue;
            }
            RELEASE_RELEASED => {}
            other => {
                return refuse_trace(
                    verdict,
                    art,
                    "broken_artifact_trace",
                    "release_status",
                    format!("unknown release_status {other:?}"),
                );
            }
        }

        // Released artifacts must carry the complete trace:
        // artifact -> task -> run/attempt -> policy revision -> approval -> receipt.covers,
        // and a hash-verified release under an approval that still approves it.
        if !has_run {
            return refuse_trace(
                verdict,
                art,
                "broken_artifact_trace",
                "run_id",
                "released artifact is missing run_id trace link".into(),
            );
        }
        let Some(aid) = art.approval_id else {
            return refuse_trace(
                verdict,
                art,
                "broken_artifact_trace",
                "approval_id",
                "released artifact is missing approval_id".into(),
            );
        };
        let Some(receipt) = receipts.get(&aid) else {
            return refuse_trace(
                verdict,
                art,
                "broken_artifact_trace",
                "approval_id",
                format!("cites approval {aid}, absent from approvals/"),
            );
        };
        let covered = receipt.covers.iter().any(|c| {
            c.id == art.id && c.revision == art.revision && c.sha256.eq_ignore_ascii_case(&art.sha256)
        });
        if !covered {
            return refuse_trace(
                verdict,
                art,
                "broken_artifact_trace",
                "approval_id",
                format!("approvals/{aid}.json does not cover sha256 {}", art.sha256),
            );
        }
        let release_ok = matches!(state, ReleaseState::Released(raw) if receipt_raw.get(&aid) == Some(&raw));
        if !release_ok || receipt.decision != "approved" {
            return refuse_trace(
                verdict,
                art,
                "release_not_bound",
                "release_status",
                format!(
                    "reports released, but the bundle holds no hash-verified agent.deliverable.released event for it \
                     under approval {aid} whose latest resolution approves it (release state: {state:?})"
                ),
            );
        }
    }

    verdict.artifacts = if artifacts.is_empty() {
        ClaimReport::new(ClaimStatus::NotApplicable, "no artifact in this bundle")
    } else if unbound == 0 {
        ClaimReport::new(
            ClaimStatus::Verified,
            format!(
                "{} artifact revision(s) bound to hash-verified agent.deliverable.revised events (revision, sha256, \
                 size{}) and release state bound to agent.deliverable.released and approval events",
                artifacts.len(),
                if class == CheckpointClass::Hub { ", deliverable and task ids" } else { "" }
            ),
        )
    } else {
        ClaimReport::new(
            ClaimStatus::HubAsserted,
            format!(
                "{unbound} of {} artifact revision(s) are not bound to an agent.deliverable.revised event in this \
                 bundle (revision, sha256, size, ids); their index entries are hub-asserted",
                artifacts.len()
            ),
        )
    };
    Ok(())
}

/// Rebuild `evidence/rows.jsonl` from the unredacted evidence-channel events
/// and refuse any extra, missing or altered row. In `org` bundles the
/// organization-local task ordinal cannot be recomputed offline, so a row
/// may carry any positive ordinal (or none) where its event names a task, and
/// must carry none where it does not; `approval_id` is always absent.
fn verify_evidence_rows(
    verdict: &mut BundleVerdict,
    class: CheckpointClass,
    events: &[BundleLedgerEvent],
    timeline: &PolicyTimeline,
    rows: &[EvidenceRow],
) -> Result<(), ()> {
    let mut seen = BTreeSet::new();
    let mut expected = Vec::new();
    for ev in events {
        if ev.redacted || !is_evidence_channel(&ev.channel) || !seen.insert(ev.ulid.clone()) {
            continue;
        }
        let Ok(parsed) = parse_strict_json(&ev.payload) else { continue };
        expected.push(derive_evidence_row(ev, &parsed, timeline));
    }
    let refuse = |verdict: &mut BundleVerdict, idx: usize, detail: String| {
        verdict.integrity =
            ClaimReport::new(ClaimStatus::Refused, format!("evidence row {}: {detail}", idx + 1));
        verdict.set_refuse(
            "evidence_row_mismatch",
            format!("evidence/rows.jsonl row {}: {detail}", idx + 1),
            Some(json!({ "file": "evidence/rows.jsonl", "line": idx + 1 })),
        );
        Err(())
    };
    if rows.len() != expected.len() {
        return refuse(
            verdict,
            rows.len().min(expected.len()),
            format!(
                "{} row(s) present, {} unredacted evidence event(s) in the ledger",
                rows.len(),
                expected.len()
            ),
        );
    }
    for (idx, (row, want)) in rows.iter().zip(expected.iter()).enumerate() {
        let ids_ok = match class {
            CheckpointClass::Hub => row.task_id == want.task_id && row.approval_id == want.approval_id,
            CheckpointClass::Org => {
                row.approval_id.is_none()
                    && match want.task_id {
                        None => row.task_id.is_none(),
                        Some(_) => row.task_id.is_none_or(|t| t > 0),
                    }
            }
        };
        let rest_ok = row.id == want.id
            && row.kind == want.kind
            && row.org_id == want.org_id
            && row.run_id == want.run_id
            && row.attempt == want.attempt
            && row.policy_revision == want.policy_revision
            && row.labels == want.labels
            && row.created_at == want.created_at;
        if !ids_ok || !rest_ok {
            return refuse(verdict, idx, format!("does not match the ledger event {}", want.id));
        }
    }
    Ok(())
}

/// A strict-JSON parse into `T` (duplicate keys, `NaN`, trailing text and
/// excess nesting refuse).
fn parse_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    let v = parse_strict_json_bytes(bytes)?;
    serde_json::from_value(v).map_err(|e| e.to_string())
}

fn parse_jsonl_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<Vec<T>, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not valid UTF-8: {e}"))?;
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v = parse_strict_json(line).map_err(|e| format!("line {}: {e}", idx + 1))?;
        let item: T = serde_json::from_value(v).map_err(|e| format!("line {}: {e}", idx + 1))?;
        out.push(item);
    }
    Ok(out)
}

/// Whether `rel` is one of the bundle's files: a required file, or
/// `approvals/<id>.json` with a positive canonical decimal id.
fn is_allowed_bundle_file(rel: &str) -> bool {
    if REQUIRED_BUNDLE_FILES.contains(&rel) {
        return true;
    }
    rel.strip_prefix("approvals/")
        .and_then(|r| r.strip_suffix(".json"))
        .and_then(|id| id.parse::<i64>().ok().filter(|n| *n > 0 && n.to_string() == id))
        .is_some()
}

fn parse_jsonl<T: DeserializeOwned>(bytes: &[u8]) -> Result<Vec<T>, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not valid UTF-8: {e}"))?;
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let item: T = serde_json::from_str(line).map_err(|e| format!("line {}: {e}", idx + 1))?;
        out.push(item);
    }
    Ok(out)
}

fn is_safe_manifest_rel_path(rel: &str) -> bool {
    if rel.is_empty() || rel.starts_with('/') || rel.contains('\\') {
        return false;
    }
    rel.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Walk `dir` under `root` without ever following symlinks, refusing any
/// symlink or excessive depth/entry count.
fn collect_relative_files_safe(
    root: &Path,
    dir: &Path,
    depth: usize,
    entries_seen: &mut usize,
    out: &mut BTreeSet<String>,
) -> Result<(), (&'static str, String, Option<Value>)> {
    if depth > MAX_WALK_DEPTH {
        return Err((
            "bundle_too_large",
            format!("bundle directory depth exceeds maximum {MAX_WALK_DEPTH}"),
            None,
        ));
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        *entries_seen += 1;
        if *entries_seen > MAX_WALK_ENTRIES {
            return Err((
                "bundle_too_large",
                format!("bundle directory entry count exceeds maximum {MAX_WALK_ENTRIES}"),
                None,
            ));
        }
        let path = entry.path();
        let norm = path
            .strip_prefix(root)
            .ok()
            .map(|rel| {
                rel.components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .unwrap_or_else(|| path.display().to_string());
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) => {
                return Err((
                    "invalid_file_type",
                    format!("cannot inspect entry {norm:?}: {e}"),
                    Some(json!({ "file": norm })),
                ));
            }
        };
        if ft.is_symlink() {
            return Err((
                "symlink_not_allowed",
                format!("refusing symlink {norm:?} inside bundle directory"),
                Some(json!({ "file": norm })),
            ));
        }
        if ft.is_dir() {
            collect_relative_files_safe(root, &path, depth + 1, entries_seen, out)?;
        } else if ft.is_file() {
            out.insert(norm);
        } else {
            return Err((
                "invalid_file_type",
                format!("refusing non-regular file {norm:?} inside bundle directory"),
                Some(json!({ "file": norm })),
            ));
        }
    }
    Ok(())
}
