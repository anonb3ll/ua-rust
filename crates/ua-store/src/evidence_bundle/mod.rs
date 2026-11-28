//! Signed evidence bundle format, exporter, offline manifest signing, and
//! standalone offline verifier (`docs/evidence-export.md`, slices S3 + S4).
//!
//! Layout:
//! ```text
//! bundle/
//!   manifest.json            # format, class, window, counts, sha256 per hashed file, digest
//!   manifest.sig             # offline Ed25519 signature over manifest.json's digest
//!   producer.json            # export time, host, tool version — reported, never hashed
//!   ledger/events.jsonl      # canonical JSON, ascending seq (hub) or org_seq (org)
//!   ledger/checkpoint.json   # signed Checkpoint + digest + signature
//!   approvals/<id>.json      # deterministic receipt per approval in range
//!   evidence/rows.jsonl      # evidence records and labels
//!   policy/revisions.json    # policy revisions cited by receipts
//!   artifacts/index.json     # hash-only artifact index with trace links
//!   withheld.json            # withheld classes and counts
//! ```

pub mod canonical;
pub mod egress;
pub mod export;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ua_core::{UaError, UaResult};

use crate::evidence::{Checkpoint, CheckpointClass, Window};

pub use canonical::{
    empty_org_chain_hash, org_chain_fold, sha256_hex, to_canonical_bytes, to_canonical_string,
};
pub use egress::{EgressFilter, WithheldReport, find_forbidden_in_ledger_event, find_forbidden_in_value};
pub use export::{
    ExportBundleOptions, ExportBundleResult, OrgWindowSummary, compute_org_window_checkpoint, export_bundle,
};

/// Current bundle manifest format version.
pub const BUNDLE_FORMAT: &str = "ua.evidence.bundle.v1";

/// Default artifact content mode (hash-only per Decision 2).
pub const ARTIFACT_CONTENT_HASH_ONLY: &str = "hash_only";

/// Required hashed relative paths inside every bundle (in addition to any
/// `approvals/<id>.json` files).
pub const REQUIRED_BUNDLE_FILES: &[&str] = &[
    "artifacts/index.json",
    "evidence/rows.jsonl",
    "ledger/checkpoint.json",
    "ledger/events.jsonl",
    "policy/revisions.json",
    "withheld.json",
];

/// Manifest counts for quick auditing and completeness cross-checks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestCounts {
    pub events: u64,
    pub unhashed_legacy_prefix: u64,
    pub approvals: u64,
    pub evidence_rows: u64,
    pub policy_revisions: u64,
    pub artifacts: u64,
    pub withheld_total: u64,
}

/// `manifest.json`: covers every hashed file in the bundle.
///
/// `digest` is the hex SHA-256 of the canonical JSON of this struct with the
/// `digest` field removed. `producer.json` is never listed in `files`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub format: String,
    pub class: CheckpointClass,
    pub org_id: Option<String>,
    pub artifact_content: String,
    pub window: Window,
    pub counts: ManifestCounts,
    pub files: BTreeMap<String, String>,
    pub digest: String,
}

#[derive(Serialize)]
struct ManifestWithoutDigest<'a> {
    artifact_content: &'a str,
    class: CheckpointClass,
    counts: &'a ManifestCounts,
    files: &'a BTreeMap<String, String>,
    format: &'a str,
    org_id: &'a Option<String>,
    window: &'a Window,
}

impl BundleManifest {
    /// Recompute the bundle digest: SHA-256 of canonical JSON with `digest` removed.
    pub fn recompute_digest(&self) -> UaResult<String> {
        let body = ManifestWithoutDigest {
            artifact_content: &self.artifact_content,
            class: self.class,
            counts: &self.counts,
            files: &self.files,
            format: &self.format,
            org_id: &self.org_id,
            window: &self.window,
        };
        let bytes = to_canonical_bytes(&body)?;
        Ok(sha256_hex(&bytes))
    }
}

/// `producer.json`: operational metadata, reported by the verifier, never
/// listed in `manifest.json` and never hashed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerInfo {
    pub exported_at: String,
    pub host: String,
    pub tool_version: String,
}

/// One line in `ledger/events.jsonl`.
///
/// - Class `hub` carries `seq` (global) and omits `org_seq`.
/// - Class `org` carries `org_seq` (absolute from genesis) and omits `seq`.
/// - `payload` stays the exact raw SQLite `event_log.payload` text so the
///   verifier recomputes `entry_hash` byte-identically under `hash_v`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleLedgerEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_seq: Option<i64>,
    pub ulid: String,
    pub channel: String,
    pub payload: String,
    pub originator: Option<String>,
    pub episode_id: Option<String>,
    pub causal_parent_id: Option<String>,
    pub created_at: String,
    pub dedupe_key: Option<String>,
    pub prev_hash: Option<String>,
    pub entry_hash: Option<String>,
    pub org_id: String,
    pub hash_v: i64,
}

/// `ledger/checkpoint.json`: the checkpoint record + digest + signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleCheckpointFile {
    pub format: String,
    pub checkpoint: Checkpoint,
    pub digest: String,
    pub signature: Option<String>,
}

/// Identity reference inside an approval receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptActor {
    pub label: String,
    /// `"human"`, `"agent"`, or `"service"`.
    pub kind: String,
}

/// Resolver reference inside an approval receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptResolver {
    pub label: String,
    pub kind: String,
    /// Transport adapter (`ui`, `http`, `mcp`, `cli`, `slack`, ...).
    pub transport: Option<String>,
}

/// Ledger event pointer inside an approval receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptLedgerRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_seq: Option<i64>,
    pub hash: String,
}

/// Artifact revision bound to a one-time approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoveredArtifact {
    pub id: String,
    pub revision: i64,
    pub sha256: String,
}

/// `approvals/<id>.json`: one deterministic receipt per approval in range
/// (`docs/evidence-export.md`, The approval receipt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReceipt {
    pub receipt_id: String,
    pub approval_id: i64,
    pub org_id: String,
    pub tool: String,
    pub action_digest: String,
    pub request_digest: String,
    pub policy_revision: Option<i64>,
    pub policy_digest: Option<String>,
    pub requester: ReceiptActor,
    pub resolver: ReceiptResolver,
    /// `"approved"` or `"denied"`.
    pub decision: String,
    pub reason: Option<String>,
    pub decided_at: String,
    pub expires_at: Option<String>,
    pub ledger: ReceiptLedgerRef,
    pub run_id: Option<String>,
    pub attempt: Option<i64>,
    pub covers: Vec<CoveredArtifact>,
}

#[derive(Serialize)]
struct ReceiptWithoutId<'a> {
    action_digest: &'a str,
    approval_id: i64,
    attempt: Option<i64>,
    covers: &'a [CoveredArtifact],
    decided_at: &'a str,
    decision: &'a str,
    expires_at: &'a Option<String>,
    ledger: &'a ReceiptLedgerRef,
    org_id: &'a str,
    policy_digest: &'a Option<String>,
    policy_revision: Option<i64>,
    reason: &'a Option<String>,
    request_digest: &'a str,
    requester: &'a ReceiptActor,
    resolver: &'a ReceiptResolver,
    run_id: &'a Option<String>,
    tool: &'a str,
}

impl ApprovalReceipt {
    /// Deterministic `receipt_id`: SHA-256 of the canonical JSON of every field
    /// except `receipt_id`.
    pub fn compute_receipt_id(&self) -> UaResult<String> {
        let body = ReceiptWithoutId {
            action_digest: &self.action_digest,
            approval_id: self.approval_id,
            attempt: self.attempt,
            covers: &self.covers,
            decided_at: &self.decided_at,
            decision: &self.decision,
            expires_at: &self.expires_at,
            ledger: &self.ledger,
            org_id: &self.org_id,
            policy_digest: &self.policy_digest,
            policy_revision: self.policy_revision,
            reason: &self.reason,
            request_digest: &self.request_digest,
            requester: &self.requester,
            resolver: &self.resolver,
            run_id: &self.run_id,
            tool: &self.tool,
        };
        let bytes = to_canonical_bytes(&body)?;
        Ok(sha256_hex(&bytes))
    }
}

/// One line in `evidence/rows.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRow {
    pub id: String,
    pub kind: String,
    pub org_id: String,
    pub task_id: Option<i64>,
    pub run_id: Option<String>,
    pub attempt: Option<i64>,
    pub policy_revision: Option<i64>,
    pub approval_id: Option<i64>,
    pub labels: Vec<String>,
    pub created_at: String,
}

/// One entry in `policy/revisions.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevisionRecord {
    pub id: i64,
    pub kind: String,
    pub revision: i64,
    pub action: String,
    pub actor: String,
    pub document_sha256: String,
    pub raw_sha256: String,
    /// Tools under this policy revision whose approval rules require
    /// separation of duties (`resolver != requester`).
    pub sod_tools: Vec<String>,
    pub approval_id: Option<i64>,
    pub event_ulid: Option<String>,
    pub created_at: String,
}

/// One entry in `artifacts/index.json` (hash-only by default, with trace links).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIndexEntry {
    pub id: String,
    pub revision: i64,
    pub sha256: String,
    pub size: i64,
    pub media_type: String,
    pub task_id: i64,
    pub run_id: Option<String>,
    pub attempt: Option<i64>,
    pub policy_revision: Option<i64>,
    pub approval_id: Option<i64>,
    pub recorded_at: String,
}

/// Validate that a hex signature is 64 bytes (128 hex chars) and return lowercase.
pub fn normalize_signature_hex(raw: &str) -> UaResult<String> {
    let norm = raw.trim().to_ascii_lowercase();
    let bytes = hex::decode(&norm).map_err(|_| UaError::invalid("signature must be hex-encoded"))?;
    if bytes.len() != 64 {
        return Err(UaError::invalid(format!("an Ed25519 signature is 64 bytes, got {}", bytes.len())));
    }
    Ok(norm)
}
