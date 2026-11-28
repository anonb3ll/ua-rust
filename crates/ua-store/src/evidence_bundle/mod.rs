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
pub mod export_schema;
pub mod snapshot;
pub mod verify;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ua_core::{UaError, UaResult};

use crate::evidence::{Checkpoint, CheckpointClass, Window};

pub use canonical::{
    empty_org_chain_hash, org_chain_fold, sha256_hex, to_canonical_bytes, to_canonical_string,
};
pub use egress::{
    CLASS_APPROVALS_IN_DEFAULT_LEDGER, CLASS_AUTH_TOKENS, CLASS_CROSS_ORG_EVENTS, CLASS_MANAGED_SECRETS,
    CLASS_PASSKEYS, CLASS_PRIVATE_MESSAGES, CLASS_PRIVATE_RECORDS, CLASS_PROVIDER_CREDENTIALS,
    CLASS_SCANNER_WITHHELD, CLASS_SESSION_CREDENTIALS, CLASS_UNPARSEABLE_PAYLOAD, EgressFilter,
    EgressViolation, MAX_SCANNED_STRING_BYTES, STUB_CLASSES, WithheldReport, find_forbidden_in_ledger_event,
    find_forbidden_in_text, find_forbidden_in_value, is_restricted_channel, ledger_row_stub_class,
    parse_strict_json, restricted_channel_class,
};
pub use export::{
    ExportBundleOptions, ExportBundleResult, OrgWindowSummary, compute_org_window_checkpoint, export_bundle,
};
pub use export_schema::{CHANNEL_RULES, CLASS_FREE_TEXT_PAYLOAD, CLASS_UNLISTED_PAYLOAD, rule_for};
pub use snapshot::{EXPORT_SNAPSHOT_PART, ExportSnapshot, snapshot_checkpoint, snapshot_load};
pub use verify::{
    BundleVerdict, BundleVerifyTrust, ClaimReport, ClaimStatus, HubCrossCheck, LegacyPrefixReport,
    MAX_BUNDLE_FILE_BYTES, MAX_BUNDLE_TOTAL_BYTES, PinnedHubHead, PinnedOrgHead, RedactedEventsReport,
    load_verified_hub_cross_check, verify_bundle_dir, verify_bundle_dir_with_limits,
};

/// Current bundle manifest format version.
pub const BUNDLE_FORMAT: &str = "ua.evidence.bundle.v1";

/// Default artifact content mode (hash-only per Decision 2).
pub const ARTIFACT_CONTENT_HASH_ONLY: &str = "hash_only";

/// Placeholder channel written on hash-only redacted ledger stubs.
pub const REDACTED_CHANNEL: &str = "[redacted]";

/// Placeholder written for another organization's requester or resolver label
/// in a `hub` bundle (the ledger records `null` for it, `ORG-EVENT-DEFAULT`).
pub const LABEL_PLACEHOLDER: &str = "[redacted-label]";

/// `artifacts/index.json` `release_status`: released by an approval whose
/// receipt is in this bundle.
pub const RELEASE_RELEASED: &str = "released";
/// `release_status`: no live release of this revision.
pub const RELEASE_UNRELEASED: &str = "unreleased";
/// `release_status`: the revision has a release, but its approval event sits
/// in the default organization's ledger (`ORG-EVENT-DEFAULT`), so this `org`
/// bundle cannot carry or prove it.
pub const RELEASE_NOT_PROVABLE_IN_ORG_BUNDLE: &str = "not_provable_in_org_bundle";
/// `release_status`: the revision has a live release whose approval event
/// falls outside this bundle's window.
pub const RELEASE_NOT_IN_BUNDLE: &str = "release_not_in_bundle";
/// `release_status`: the revision was released, but the release was
/// cancelled or its approval was denied or revoked.
pub const RELEASE_REVOKED: &str = "release_revoked";

/// Channel of the hub's policy, profile and approval-rule revision events.
pub const CONFIG_REVISION_CHANNEL: &str = "agent.config.revision";

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

fn is_false(b: &bool) -> bool {
    !*b
}

/// Whether two identity labels name the same identity (trimmed, ASCII
/// case-insensitive, as the hub matches labels).
pub fn labels_equal(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Normalize an approval decision (`approve` / `approved` -> `approved`, ...).
pub fn normalize_decision(raw: &str) -> String {
    match raw.trim() {
        "approve" | "approved" => "approved",
        "deny" | "denied" => "denied",
        "revoke" | "revoked" => "revoked",
        other => other,
    }
    .to_string()
}

/// Whether a ledger channel produces an `evidence/rows.jsonl` row.
pub fn is_evidence_channel(channel: &str) -> bool {
    channel.starts_with("evidence.")
        || channel.starts_with("agent.approval.")
        || channel.starts_with("agent.deliverable.")
        || channel.starts_with("sdk.")
}

/// The policy revisions a bundle knows, ordered by when each came into force.
///
/// A revision whose `agent.config.revision` event is in the bundle in clear
/// comes into force at that hash-verified event's `created_at` and is
/// *bound*. A revision listed only in `policy/revisions.json` comes into
/// force at its listed `created_at` and is the hub's word. The exporter and
/// the verifier build the same timeline, so the revision a receipt, artifact
/// or evidence row cites is the verifier's choice, not the exporter's.
#[derive(Debug, Clone, Default)]
pub struct PolicyTimeline {
    /// `(effective timestamp, revision, bound to a ledger event)`.
    entries: Vec<(String, i64, bool)>,
}

impl PolicyTimeline {
    pub fn build(events: &[BundleLedgerEvent], revisions: &[PolicyRevisionRecord]) -> Self {
        let mut entries: Vec<(String, i64, bool)> = Vec::new();
        let mut bound_revs = BTreeSet::new();
        for (rev, ts) in config_policy_events(events) {
            if bound_revs.insert(rev) {
                entries.push((normalize_ts_utc(&ts), rev, true));
            }
        }
        for r in revisions.iter().filter(|r| r.kind == "policy") {
            if !bound_revs.contains(&r.revision) {
                entries.push((normalize_ts_utc(&r.created_at), r.revision, false));
            }
        }
        entries.sort_by(|a, b| cmp_ts(&a.0, &b.0).then(a.1.cmp(&b.1)));
        Self { entries }
    }

    /// The revision in force at `ts` and whether it is bound to a ledger
    /// event: the latest entry effective at or before `ts`.
    pub fn in_force(&self, ts: &str) -> Option<(i64, bool)> {
        self.entries
            .iter()
            .filter(|(at, _, _)| cmp_ts(at, ts) != Ordering::Greater)
            .max_by(|a, b| cmp_ts(&a.0, &b.0).then(a.1.cmp(&b.1)))
            .map(|(_, rev, bound)| (*rev, *bound))
    }
}

/// `(revision, created_at)` of every unredacted `kind = "policy"`
/// `agent.config.revision` event in `events`.
pub fn config_policy_events(events: &[BundleLedgerEvent]) -> Vec<(i64, String)> {
    let mut out = Vec::new();
    for ev in events.iter().filter(|e| !e.redacted && e.channel == CONFIG_REVISION_CHANNEL) {
        let Ok(p) = parse_strict_json(&ev.payload) else { continue };
        if p.get("kind").and_then(Value::as_str) == Some("policy")
            && let Some(rev) = p.get("revision").and_then(Value::as_i64)
        {
            out.push((rev, ev.created_at.clone()));
        }
    }
    out
}

/// The hash-verified approval history in a bundle's unredacted rows.
#[derive(Debug, Clone, Default)]
pub struct ApprovalHistory {
    /// Raw approval id -> indexes of its `agent.approval.resolved` events, in
    /// ledger order.
    pub resolved: BTreeMap<i64, Vec<usize>>,
    /// Raw approval id -> index of its (latest) `agent.approval.requested`.
    pub requested: BTreeMap<i64, usize>,
    /// Parsed payload per event index.
    pub payloads: BTreeMap<usize, Value>,
}

impl ApprovalHistory {
    pub fn build(events: &[BundleLedgerEvent]) -> Self {
        let mut h = Self::default();
        for (idx, ev) in events.iter().enumerate() {
            if ev.redacted || !ev.channel.starts_with("agent.approval.") {
                continue;
            }
            let Ok(p) = parse_strict_json(&ev.payload) else { continue };
            let Some(aid) = p.get("approval_id").and_then(Value::as_i64) else { continue };
            match ev.channel.as_str() {
                "agent.approval.resolved" => h.resolved.entry(aid).or_default().push(idx),
                "agent.approval.requested" => {
                    h.requested.insert(aid, idx);
                }
                _ => continue,
            }
            h.payloads.insert(idx, p);
        }
        h
    }

    /// The decision of the latest resolution of `aid` in the bundle.
    pub fn latest_decision(&self, aid: i64) -> Option<String> {
        let idx = *self.resolved.get(&aid)?.last()?;
        self.payloads.get(&idx)?.get("decision").and_then(Value::as_str).map(normalize_decision)
    }
}

/// A release lifecycle event (`agent.deliverable.released` or
/// `.release_cancelled`) in a bundle's unredacted rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseEvent {
    pub idx: usize,
    pub cancelled: bool,
    pub revision_id: Option<i64>,
    pub deliverable_id: Option<i64>,
    pub sha256: String,
    pub approval_id: Option<i64>,
}

pub fn release_events(events: &[BundleLedgerEvent]) -> Vec<ReleaseEvent> {
    let mut out = Vec::new();
    for (idx, ev) in events.iter().enumerate() {
        let cancelled = match ev.channel.as_str() {
            "agent.deliverable.released" => false,
            "agent.deliverable.release_cancelled" => true,
            _ => continue,
        };
        if ev.redacted {
            continue;
        }
        let Ok(p) = parse_strict_json(&ev.payload) else { continue };
        out.push(ReleaseEvent {
            idx,
            cancelled,
            revision_id: p.get("revision_id").and_then(Value::as_i64),
            deliverable_id: p.get("deliverable_id").and_then(Value::as_i64),
            sha256: p.get("sha256").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase(),
            approval_id: p.get("approval_id").and_then(Value::as_i64),
        });
    }
    out
}

/// What the hash-verified rows say about one artifact revision's release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseState {
    /// No release event for it in the bundle.
    NoEvent,
    /// Released under this raw approval id, whose latest resolution in the
    /// bundle approves it, with no later cancellation.
    Released(i64),
    /// A release event exists, but it was cancelled, or its approval's latest
    /// resolution is a deny or revoke.
    Revoked,
    /// A release event exists, but its approval's resolution is not in the
    /// bundle.
    ApprovalNotInBundle,
}

/// Derive the release state of the revision whose release events are
/// `matching` (in ledger order).
pub fn release_state(matching: &[&ReleaseEvent], history: &ApprovalHistory) -> ReleaseState {
    let Some(last_release) = matching.iter().rev().find(|e| !e.cancelled) else {
        return if matching.is_empty() { ReleaseState::NoEvent } else { ReleaseState::Revoked };
    };
    let cancelled_after = matching
        .iter()
        .any(|e| e.cancelled && e.idx > last_release.idx && e.approval_id == last_release.approval_id);
    if cancelled_after {
        return ReleaseState::Revoked;
    }
    let Some(aid) = last_release.approval_id else { return ReleaseState::ApprovalNotInBundle };
    match history.latest_decision(aid).as_deref() {
        Some("approved") => ReleaseState::Released(aid),
        Some(_) => ReleaseState::Revoked,
        None => ReleaseState::ApprovalNotInBundle,
    }
}

/// Derive the evidence row for an unredacted evidence-channel event from its
/// hash-verified fields. `task_id` and `approval_id` carry the payload's raw
/// hub ids; an `org` exporter maps them to dense ordinals (or `None`).
pub fn derive_evidence_row(ev: &BundleLedgerEvent, parsed: &Value, policies: &PolicyTimeline) -> EvidenceRow {
    let mut labels = vec![ev.channel.clone()];
    if ev.channel.starts_with("sdk.") {
        labels.push("client_asserted".into());
    }
    EvidenceRow {
        id: ev.ulid.clone(),
        kind: ev.channel.clone(),
        org_id: ev.org_id.clone(),
        task_id: parsed.get("task_id").and_then(Value::as_i64),
        run_id: parsed.get("run_id").and_then(Value::as_str).map(str::to_string),
        attempt: parsed.get("attempt").and_then(Value::as_i64),
        policy_revision: policies.in_force(&ev.created_at).map(|(rev, _)| rev),
        approval_id: parsed.get("approval_id").and_then(Value::as_i64),
        labels,
        created_at: normalize_ts_utc(&ev.created_at),
    }
}

/// Normalize any RFC 3339 timestamp (`Z`, `+00:00`, or an arbitrary offset) to
/// canonical RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`, preserving subseconds if
/// non-zero). Returns `raw` unchanged if unparseable.
pub fn normalize_ts_utc(raw: &str) -> String {
    let Some(ts) = ua_core::time::parse_ts(raw.trim()) else {
        return raw.to_string();
    };
    let nanos = ts.subsec_nanosecond();
    if nanos == 0 {
        ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        let frac = format!("{nanos:09}");
        let trimmed = frac.trim_end_matches('0');
        format!("{}.{trimmed}Z", ts.strftime("%Y-%m-%dT%H:%M:%S"))
    }
}

/// Compare two timestamps by instant when both parse as RFC 3339 (so `…Z` and
/// `…+00:00` at the same instant compare `Equal`), falling back to lexical
/// comparison only if either fails to parse.
pub fn cmp_ts(a: &str, b: &str) -> Ordering {
    match (ua_core::time::parse_ts(a.trim()), ua_core::time::parse_ts(b.trim())) {
        (Some(ta), Some(tb)) => ta.cmp(&tb),
        _ => a.cmp(b),
    }
}

/// Extract the sorted list of tools requiring separation of duties from a
/// parsed `config_revisions.document` JSON value.
///
/// Separation of duties is read strictly from the policy document rather than
/// stamped by the exporter:
/// - Explicit top-level `sod_tools` string array (if present).
/// - Any rule in `rules` with `action == "require_approval"` and an explicit
///   separation-of-duties clause (`separation_of_duties: true`,
///   `require_distinct_approver: true`, or `different_approver: true`).
pub fn extract_sod_tools_from_doc(doc: &Value) -> Vec<String> {
    let mut tools = BTreeSet::new();
    let Some(obj) = doc.as_object() else {
        return Vec::new();
    };
    if let Some(arr) = obj.get("sod_tools").and_then(Value::as_array) {
        for item in arr {
            if let Some(s) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                tools.insert(s.to_string());
            }
        }
    }
    if let Some(rules) = obj.get("rules").and_then(Value::as_array) {
        for rule in rules {
            let Some(r) = rule.as_object() else { continue };
            if r.get("action").and_then(Value::as_str) != Some("require_approval") {
                continue;
            }
            let explicit_sod = r
                .get("separation_of_duties")
                .and_then(Value::as_bool)
                .or_else(|| r.get("require_distinct_approver").and_then(Value::as_bool))
                .or_else(|| r.get("different_approver").and_then(Value::as_bool));
            if explicit_sod == Some(true)
                && let Some(tool) =
                    r.get("tool").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
            {
                tools.insert(tool.to_string());
            }
        }
    }
    tools.into_iter().collect()
}

/// Manifest counts for quick auditing and completeness cross-checks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestCounts {
    pub events: u64,
    #[serde(default)]
    pub redacted_events: u64,
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
/// - For unredacted rows, `payload` stays the exact raw SQLite
///   `event_log.payload` text so the verifier recomputes `entry_hash`
///   byte-identically under `hash_v`.
/// - For withheld/redacted private rows (`redacted: true`), `channel` is
///   `"[redacted]"`, `payload` is `""`, `originator`/`episode_id`/
///   `causal_parent_id`/`dedupe_key` are `None`, and only chain metadata
///   (`prev_hash`, `entry_hash`, `hash_v`, `org_id`, `ulid`, `created_at`,
///   `redacted_class`) is kept so chain continuity holds while the verifier
///   reports per-row verification coverage explicitly.
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
    #[serde(default, skip_serializing_if = "is_false")]
    pub redacted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_class: Option<String>,
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
    /// Whether the resolver is the requester. Recomputed from the labels when
    /// both are in clear; the exporter's word when they are
    /// [`LABEL_PLACEHOLDER`]s (another organization's labels in a `hub`
    /// bundle).
    pub resolver_is_requester: bool,
    /// `"approved"`, `"denied"`, or `"revoked"`. Free-text reasons are not
    /// carried: they are not in the ledger and change on a later resolution.
    pub decision: String,
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
    request_digest: &'a str,
    requester: &'a ReceiptActor,
    resolver: &'a ReceiptResolver,
    resolver_is_requester: bool,
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
            request_digest: &self.request_digest,
            requester: &self.requester,
            resolver: &self.resolver,
            resolver_is_requester: self.resolver_is_requester,
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
    /// Hub-wide `config_revisions.id` (present in `hub` bundles, omitted in `org` bundles).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub kind: String,
    pub revision: i64,
    pub action: String,
    pub actor: String,
    /// Canonical policy document JSON string whose SHA-256 equals
    /// `document_sha256` and from which `sod_tools` is independently derived.
    /// Present in `hub` bundles only: policy documents name identities, so an
    /// `org` bundle carries the digest without the document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<String>,
    pub document_sha256: String,
    pub raw_sha256: String,
    /// Tools under this policy revision whose approval rules require
    /// separation of duties (`resolver != requester`), derived from `document`.
    pub sod_tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// [`RELEASE_RELEASED`], [`RELEASE_UNRELEASED`], or
    /// [`RELEASE_NOT_PROVABLE_IN_ORG_BUNDLE`].
    pub release_status: String,
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
