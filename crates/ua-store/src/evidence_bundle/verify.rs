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
//! Exit codes:
//! - `0`: verified
//! - `1`: refused (integrity, signature, chain, receipt, trace, downgrade, or
//!   forbidden private/secret content violation — never downgraded to a warning)
//! - `2`: cannot verify (missing input, unsupported format, unanchored, unknown
//!   or revoked key, unsigned bundle/checkpoint, or incremental bundle missing
//!   its pinned checkpoint)

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ua_core::UaResult;

use crate::evidence::{CHECKPOINT_FORMAT, CheckpointClass, TrustAnchor, verify_ed25519};
use crate::ledger::{GENESIS_HASH, HASH_V1, HASH_V2, compute_entry_hash_for_version};

use super::canonical::{empty_org_chain_hash, org_chain_fold, sha256_hex};
use super::egress::{WithheldReport, find_forbidden_in_ledger_event, find_forbidden_in_value};
use super::{
    ARTIFACT_CONTENT_HASH_ONLY, ApprovalReceipt, ArtifactIndexEntry, BUNDLE_FORMAT, BundleCheckpointFile,
    BundleLedgerEvent, BundleManifest, EvidenceRow, PolicyRevisionRecord, ProducerInfo,
    REQUIRED_BUNDLE_FILES, normalize_signature_hex,
};

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
}

/// Unhashed legacy prefix reported explicitly (check 11).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyPrefixReport {
    pub count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seq: Option<i64>,
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
    pub unhashed_legacy_prefix: LegacyPrefixReport,
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
            unhashed_legacy_prefix: LegacyPrefixReport::default(),
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
    let bytes = std::fs::read(hub_bundle_dir.join("ledger/events.jsonl"))
        .map_err(|e| ua_core::UaError::internal(format!("reading hub bundle events.jsonl: {e}")))?;
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
    let mut verdict = BundleVerdict::base();

    if !bundle_dir.exists() || !bundle_dir.is_dir() {
        return Ok(verdict.cannot_verify(
            "missing_bundle_dir",
            format!("bundle directory {} does not exist", bundle_dir.display()),
            Some(json!({ "path": bundle_dir.display().to_string() })),
        ));
    }

    // Read unhashed producer.json (reported, never hashed, never treated as evidence).
    let producer_path = bundle_dir.join("producer.json");
    if producer_path.exists() {
        match std::fs::read(&producer_path).ok().and_then(|b| serde_json::from_slice::<ProducerInfo>(&b).ok())
        {
            Some(p) => verdict.producer = Some(p),
            None => verdict.warnings.push("producer.json is present but unreadable (not hashed)".into()),
        }
    }

    // Check 1: format & manifest parsing.
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest_bytes = match std::fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) => {
            return Ok(verdict.cannot_verify(
                "missing_manifest",
                format!("cannot read manifest.json: {e}"),
                Some(json!({ "file": "manifest.json" })),
            ));
        }
    };
    let manifest: BundleManifest = match serde_json::from_slice(&manifest_bytes) {
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

    // Scan bundle_dir for extra unmanifested files (never counted as evidence, reported in warnings).
    let mut disk_files = BTreeSet::new();
    collect_relative_files(bundle_dir, bundle_dir, &mut disk_files);
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
        let path = bundle_dir.join(rel);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
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
    let cp_file: BundleCheckpointFile = match serde_json::from_slice(&file_bytes["ledger/checkpoint.json"]) {
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
    // Cryptographic failures exit 1 immediately; missing trust / unknown key /
    // revoked key / unsigned are recorded as exit-2 pending checks 4-12 so a
    // tampering refusal (exit 1) is never masked by an exit-2 trust issue.
    let mut deferred_cannot_verify: DeferredCannotVerify = None;
    let cp_key_id = cp_file.checkpoint.key_id.as_str();
    let manifest_sig_raw = std::fs::read_to_string(bundle_dir.join("manifest.sig")).ok();

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
    let events = match parse_jsonl::<BundleLedgerEvent>(&file_bytes["ledger/events.jsonl"]) {
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
        match serde_json::from_slice(&file_bytes["policy/revisions.json"]) {
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

    let artifacts: Vec<ArtifactIndexEntry> = match serde_json::from_slice(&file_bytes["artifacts/index.json"])
    {
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

    let evidence_rows = match parse_jsonl::<EvidenceRow>(&file_bytes["evidence/rows.jsonl"]) {
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
    let withheld: WithheldReport = match serde_json::from_slice(&file_bytes["withheld.json"]) {
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
    verdict.withheld = Some(withheld);

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
            let file_id: i64 = match id_str.parse() {
                Ok(n) => n,
                Err(_) => {
                    verdict.integrity =
                        ClaimReport::new(ClaimStatus::Refused, format!("invalid approval id in {rel:?}"));
                    return Ok(verdict.refuse(
                        "invalid_receipt_filename",
                        format!("non-integer approval id in {rel:?}"),
                        Some(json!({ "file": rel })),
                    ));
                }
            };
            let receipt: ApprovalReceipt = match serde_json::from_slice(bytes) {
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

    // Check 10: Private and secret content refusal across every bundle record.
    for ev in &events {
        if let Some(v) = find_forbidden_in_ledger_event(&ev.channel, &ev.payload) {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("forbidden content: {}", v.detail));
            return Ok(verdict.refuse(
                "forbidden_private_content",
                format!("ledger event contains forbidden content ({}): {}", v.class, v.detail),
                Some(json!({
                    "file": "ledger/events.jsonl",
                    "seq": ev.seq,
                    "org_seq": ev.org_seq,
                    "class": v.class
                })),
            ));
        }
    }
    for (rel, bytes) in &file_bytes {
        if rel == "ledger/events.jsonl" || rel == "withheld.json" {
            continue;
        }
        if rel == "evidence/rows.jsonl" {
            for (idx, line) in std::str::from_utf8(bytes).unwrap_or("").lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(val) = serde_json::from_str::<Value>(line)
                    && let Some(v) = find_forbidden_in_value(&val)
                {
                    verdict.integrity =
                        ClaimReport::new(ClaimStatus::Refused, format!("forbidden content: {}", v.detail));
                    return Ok(verdict.refuse(
                        "forbidden_private_content",
                        format!(
                            "evidence row {} contains forbidden content ({}): {}",
                            idx + 1,
                            v.class,
                            v.detail
                        ),
                        Some(json!({ "file": rel, "line": idx + 1, "class": v.class })),
                    ));
                }
            }
        } else if let Ok(val) = serde_json::from_slice::<Value>(bytes)
            && let Some(v) = find_forbidden_in_value(&val)
        {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("forbidden content: {}", v.detail));
            return Ok(verdict.refuse(
                "forbidden_private_content",
                format!("{rel} contains forbidden content ({}): {}", v.class, v.detail),
                Some(json!({ "file": rel, "class": v.class })),
            ));
        }
    }

    // Checks 4, 6, 11: Row hashes under hash_v, downgrade refusal, legacy unhashed prefix.
    let mut seen_hashed = false;
    let mut seen_v2 = false;
    let mut legacy_prefix = LegacyPrefixReport::default();

    for ev in &events {
        let pos = ev.seq.or(ev.org_seq);
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
    verdict.unhashed_legacy_prefix = legacy_prefix;

    // Check 5: Sequence basis and class-specific chain continuity.
    let chain_ok = match manifest.class {
        CheckpointClass::Hub => {
            verify_hub_chain(&mut verdict, &cp_file, &events, trust, &mut deferred_cannot_verify)
        }
        CheckpointClass::Org => {
            verify_org_chain(&mut verdict, &cp_file, &events, trust, &mut deferred_cannot_verify)
        }
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
        &artifacts,
    )
    .is_err()
    {
        return Ok(verdict);
    }

    // Check 9: Artifact trace (artifact -> task -> run/attempt -> policy revision -> approval).
    if verify_artifact_traces(&mut verdict, &artifacts, &policy_revisions, &receipts).is_err() {
        return Ok(verdict);
    }

    if let Some((reason, detail, offending)) = deferred_cannot_verify {
        return Ok(verdict.cannot_verify(reason, detail, offending));
    }

    verdict.ok = true;
    verdict.exit_code = 0;
    Ok(verdict)
}

fn verify_hub_chain(
    verdict: &mut BundleVerdict,
    cp_file: &BundleCheckpointFile,
    events: &[BundleLedgerEvent],
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
            // pin.seq >= first_seq: check pinned row inside bundle, but start prior to pin is unanchored.
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
        "manifest digest, all per-file SHA-256 digests, per-row entry hashes under hash_v, and global chain continuity verified",
    );
    Ok(())
}

fn verify_org_chain(
    verdict: &mut BundleVerdict,
    cp_file: &BundleCheckpointFile,
    events: &[BundleLedgerEvent],
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
    }

    verdict.integrity = ClaimReport::new(
        ClaimStatus::Verified,
        "manifest digest, all per-file SHA-256 digests, per-row entry hashes under hash_v, org_seq ordering, and org_chain_hash verified",
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

fn verify_receipts_and_cross_links(
    verdict: &mut BundleVerdict,
    class: CheckpointClass,
    bundle_org_id: Option<&str>,
    events: &[BundleLedgerEvent],
    receipts: &BTreeMap<i64, ApprovalReceipt>,
    policy_revisions: &[PolicyRevisionRecord],
    artifacts: &[ArtifactIndexEntry],
) -> Result<(), ()> {
    // Map latest agent.approval.resolved event per approval_id.
    let mut resolved_events: BTreeMap<i64, (&BundleLedgerEvent, Value)> = BTreeMap::new();
    for ev in events {
        if ev.channel != "agent.approval.resolved" {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<Value>(&ev.payload) else {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, "unparseable agent.approval.resolved payload");
            verdict.set_refuse(
                "invalid_event_json",
                "agent.approval.resolved payload is not valid JSON",
                Some(json!({ "seq": ev.seq, "org_seq": ev.org_seq })),
            );
            return Err(());
        };
        let Some(aid) = parsed.get("approval_id").and_then(Value::as_i64) else {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, "agent.approval.resolved missing approval_id");
            verdict.set_refuse(
                "cross_link_missing_receipt",
                "agent.approval.resolved event carries no approval_id",
                Some(json!({ "seq": ev.seq, "org_seq": ev.org_seq })),
            );
            return Err(());
        };
        resolved_events.insert(aid, (ev, parsed));
    }

    // Check 8a: every approval event must have a receipt.
    for (&aid, (ev, _)) in &resolved_events {
        if !receipts.contains_key(&aid) {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("missing approval receipt for approval {aid}"),
            );
            verdict.set_refuse(
                "cross_link_missing_receipt",
                format!(
                    "agent.approval.resolved event for approval {aid} has no approvals/{aid}.json receipt"
                ),
                Some(json!({ "approval_id": aid, "seq": ev.seq, "org_seq": ev.org_seq })),
            );
            return Err(());
        }
    }

    let mut sod_verified_count = 0usize;

    // Check 7 & 8b: every receipt must resolve to an event and satisfy all bindings.
    for (&aid, receipt) in receipts {
        let Some((ev, ev_payload)) = resolved_events.get(&aid) else {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("receipt {aid} has no matching ledger event"));
            verdict.set_refuse(
                "cross_link_missing_event",
                format!("approvals/{aid}.json has no matching agent.approval.resolved event in ledger/events.jsonl"),
                Some(json!({ "approval_id": aid })),
            );
            return Err(());
        };

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

        // Receipt self-digest (receipt_id).
        let recomputed_id = match receipt.compute_receipt_id() {
            Ok(id) => id,
            Err(e) => {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("cannot compute receipt_id for {aid}: {e}"),
                );
                verdict.set_refuse(
                    "receipt_id_mismatch",
                    format!("failed to recompute receipt_id for approval {aid}: {e}"),
                    Some(json!({ "approval_id": aid })),
                );
                return Err(());
            }
        };
        if !receipt.receipt_id.eq_ignore_ascii_case(&recomputed_id) {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("receipt_id mismatch for approval {aid}"));
            verdict.set_refuse(
                "receipt_id_mismatch",
                format!(
                    "approvals/{aid}.json claims receipt_id {} but recomputed {}",
                    receipt.receipt_id, recomputed_id
                ),
                Some(json!({ "approval_id": aid, "field": "receipt_id" })),
            );
            return Err(());
        }

        // Ledger pointer check.
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

        // Action digest binding against event payload.
        let ev_digest = ev_payload
            .get("payload_sha256")
            .or_else(|| ev_payload.get("action_digest"))
            .and_then(Value::as_str);
        match ev_digest {
            Some(d) if d.eq_ignore_ascii_case(&receipt.action_digest) => {}
            Some(d) => {
                verdict.integrity =
                    ClaimReport::new(ClaimStatus::Refused, format!("receipt {aid} action_digest mismatch"));
                verdict.set_refuse(
                    "receipt_action_digest_mismatch",
                    format!(
                        "approvals/{aid}.json action_digest ({}) does not match ledger event payload digest ({d})",
                        receipt.action_digest
                    ),
                    Some(json!({ "approval_id": aid, "field": "action_digest" })),
                );
                return Err(());
            }
            None => {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("approval {aid} event lacks payload digest"),
                );
                verdict.set_refuse(
                    "receipt_action_digest_missing",
                    format!("agent.approval.resolved for approval {aid} carries neither payload_sha256 nor action_digest"),
                    Some(json!({ "approval_id": aid, "field": "action_digest" })),
                );
                return Err(());
            }
        }

        // Verified human resolver check for approved decisions.
        if receipt.decision == "approved"
            && (receipt.resolver.kind != "human" || receipt.resolver.label.trim().is_empty())
        {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("receipt {aid} resolver is not a verified human"),
            );
            verdict.set_refuse(
                "receipt_resolver_not_human",
                format!(
                    "approvals/{aid}.json approved decision requires resolver kind=\"human\" with non-empty label, got kind={:?} label={:?}",
                    receipt.resolver.kind, receipt.resolver.label
                ),
                Some(json!({ "approval_id": aid, "field": "resolver" })),
            );
            return Err(());
        }

        // Policy revision and separation of duties (taken from policy/revisions.json).
        if let Some(pol_rev) = receipt.policy_revision {
            let Some(pol) = policy_revisions.iter().find(|p| p.revision == pol_rev) else {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("receipt {aid} cites unknown policy revision {pol_rev}"),
                );
                verdict.set_refuse(
                    "receipt_policy_missing",
                    format!("approvals/{aid}.json cites policy_revision {pol_rev}, absent from policy/revisions.json"),
                    Some(json!({ "approval_id": aid, "policy_revision": pol_rev })),
                );
                return Err(());
            };
            if let Some(pd) = receipt.policy_digest.as_deref()
                && !pd.eq_ignore_ascii_case(&pol.document_sha256)
            {
                verdict.integrity =
                    ClaimReport::new(ClaimStatus::Refused, format!("receipt {aid} policy_digest mismatch"));
                verdict.set_refuse(
                    "receipt_policy_digest_mismatch",
                    format!("approvals/{aid}.json policy_digest disagrees with policy/revisions.json revision {pol_rev}"),
                    Some(json!({ "approval_id": aid, "policy_revision": pol_rev })),
                );
                return Err(());
            }
            if pol.sod_tools.iter().any(|t| t == &receipt.tool) {
                if receipt.decision == "approved"
                    && receipt.resolver.label.trim().eq_ignore_ascii_case(receipt.requester.label.trim())
                {
                    verdict.separation_of_duties = ClaimReport::new(
                        ClaimStatus::Refused,
                        format!(
                            "approval {aid} for {:?} violates separation of duties: resolver {:?} equals requester {:?}",
                            receipt.tool, receipt.resolver.label, receipt.requester.label
                        ),
                    );
                    verdict.set_refuse(
                        "receipt_sod_violation",
                        format!(
                            "approvals/{aid}.json violates separation of duties for tool {:?} (resolver == requester {:?})",
                            receipt.tool, receipt.resolver.label
                        ),
                        Some(json!({ "approval_id": aid, "tool": receipt.tool, "field": "resolver" })),
                    );
                    return Err(());
                }
                sod_verified_count += 1;
            }
        }

        // Covered artifacts check against artifacts/index.json.
        for cov in &receipt.covers {
            let matched = artifacts.iter().any(|a| {
                a.id == cov.id && a.revision == cov.revision && a.sha256.eq_ignore_ascii_case(&cov.sha256)
            });
            if !matched {
                verdict.integrity = ClaimReport::new(
                    ClaimStatus::Refused,
                    format!("receipt {aid} covers unknown/mismatched artifact"),
                );
                verdict.set_refuse(
                    "receipt_covers_mismatch",
                    format!(
                        "approvals/{aid}.json covers ({}, rev {}, sha256 {}), which does not match artifacts/index.json",
                        cov.id, cov.revision, cov.sha256
                    ),
                    Some(json!({ "approval_id": aid, "artifact_id": cov.id, "revision": cov.revision })),
                );
                return Err(());
            }
        }
    }

    verdict.separation_of_duties = if sod_verified_count > 0 {
        ClaimReport::new(
            ClaimStatus::Verified,
            format!(
                "{sod_verified_count} approval receipt(s) verified under policy/revisions.json separation-of-duties rules"
            ),
        )
    } else {
        ClaimReport::new(
            ClaimStatus::NotApplicable,
            "no approval receipt in this bundle is governed by a separation-of-duties clause in policy/revisions.json",
        )
    };

    Ok(())
}

fn verify_artifact_traces(
    verdict: &mut BundleVerdict,
    artifacts: &[ArtifactIndexEntry],
    policy_revisions: &[PolicyRevisionRecord],
    receipts: &BTreeMap<i64, ApprovalReceipt>,
) -> Result<(), ()> {
    for art in artifacts {
        if art.task_id <= 0 {
            verdict.integrity =
                ClaimReport::new(ClaimStatus::Refused, format!("artifact {} missing task_id link", art.id));
            verdict.set_refuse(
                "broken_artifact_trace",
                format!("artifact {} rev {} has invalid task_id {}", art.id, art.revision, art.task_id),
                Some(json!({ "artifact_id": art.id, "revision": art.revision, "field": "task_id" })),
            );
            return Err(());
        }
        if art.run_id.as_deref().is_none_or(|s| s.trim().is_empty()) {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("artifact {} missing run_id trace link", art.id),
            );
            verdict.set_refuse(
                "broken_artifact_trace",
                format!("artifact {} rev {} is missing run_id trace link", art.id, art.revision),
                Some(json!({ "artifact_id": art.id, "revision": art.revision, "field": "run_id" })),
            );
            return Err(());
        }
        if art.attempt.is_none_or(|a| a <= 0) {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("artifact {} missing attempt trace link", art.id),
            );
            verdict.set_refuse(
                "broken_artifact_trace",
                format!("artifact {} rev {} is missing valid attempt number", art.id, art.revision),
                Some(json!({ "artifact_id": art.id, "revision": art.revision, "field": "attempt" })),
            );
            return Err(());
        }
        let Some(pol_rev) = art.policy_revision else {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("artifact {} missing policy_revision trace link", art.id),
            );
            verdict.set_refuse(
                "broken_artifact_trace",
                format!("artifact {} rev {} is missing policy_revision trace link", art.id, art.revision),
                Some(json!({ "artifact_id": art.id, "revision": art.revision, "field": "policy_revision" })),
            );
            return Err(());
        };
        if !policy_revisions.iter().any(|p| p.revision == pol_rev) {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("artifact {} cites unknown policy_revision {pol_rev}", art.id),
            );
            verdict.set_refuse(
                "broken_artifact_trace",
                format!(
                    "artifact {} rev {} cites policy_revision {pol_rev}, which is missing from policy/revisions.json",
                    art.id, art.revision
                ),
                Some(json!({ "artifact_id": art.id, "revision": art.revision, "field": "policy_revision" })),
            );
            return Err(());
        }
        let Some(aid) = art.approval_id else {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("artifact {} missing approval_id trace link", art.id),
            );
            verdict.set_refuse(
                "broken_artifact_trace",
                format!("artifact {} rev {} is missing approval_id trace link", art.id, art.revision),
                Some(json!({ "artifact_id": art.id, "revision": art.revision, "field": "approval_id" })),
            );
            return Err(());
        };
        let Some(receipt) = receipts.get(&aid) else {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("artifact {} cites missing approval receipt {aid}", art.id),
            );
            verdict.set_refuse(
                "broken_artifact_trace",
                format!(
                    "artifact {} rev {} cites approval {aid}, absent from approvals/",
                    art.id, art.revision
                ),
                Some(json!({ "artifact_id": art.id, "revision": art.revision, "field": "approval_id" })),
            );
            return Err(());
        };
        let covered = receipt.covers.iter().any(|c| {
            c.id == art.id && c.revision == art.revision && c.sha256.eq_ignore_ascii_case(&art.sha256)
        });
        if !covered {
            verdict.integrity = ClaimReport::new(
                ClaimStatus::Refused,
                format!("approval receipt {aid} does not cover artifact {} rev {}", art.id, art.revision),
            );
            verdict.set_refuse(
                "broken_artifact_trace",
                format!(
                    "approvals/{aid}.json does not cover artifact {} rev {} (sha256 {})",
                    art.id, art.revision, art.sha256
                ),
                Some(json!({ "artifact_id": art.id, "revision": art.revision, "approval_id": aid })),
            );
            return Err(());
        }
    }
    Ok(())
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

fn collect_relative_files(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_relative_files(root, &path, out);
        } else if path.is_file()
            && let Ok(rel) = path.strip_prefix(root)
        {
            let norm = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.insert(norm);
        }
    }
}
