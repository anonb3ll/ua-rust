//! Evidence bundle exporter (`ua evidence export`) and `org` window checkpoint
//! derivation (`docs/evidence-export.md`, S3).
//!
//! All database reads happen here inside `ua-store`; the hub never holds a
//! signing key and never writes `manifest.sig` (signing is strictly offline
//! via `ua evidence sign --bundle`).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use ua_core::{DEFAULT_ORG, UaError, UaResult};

use crate::evidence::{
    CHECKPOINT_FORMAT, Checkpoint, CheckpointClass, Window, checkpoint_get, checkpoint_signature,
};
use crate::ledger::GENESIS_HASH;

use super::canonical::{
    empty_org_chain_hash, org_chain_fold, sha256_hex, to_canonical_bytes, to_canonical_string,
};
use super::egress::{
    CLASS_CROSS_ORG_EVENTS, CLASS_SCANNER_WITHHELD, EgressFilter, LedgerEgressAction, find_forbidden_in_text,
    find_forbidden_in_value, parse_strict_json,
};
use super::export_schema::is_safe_label;
use super::snapshot::{
    ExportSnapshot, column_exists, in_time_window, snapshot_capture, snapshot_load, table_exists,
};
use super::{
    ARTIFACT_CONTENT_HASH_ONLY, ApprovalHistory, ApprovalReceipt, ArtifactIndexEntry, BUNDLE_FORMAT,
    BundleCheckpointFile, BundleLedgerEvent, BundleManifest, CoveredArtifact, EvidenceRow, LABEL_PLACEHOLDER,
    ManifestCounts, PolicyRevisionRecord, PolicyTimeline, ProducerInfo, REDACTED_CHANNEL,
    RELEASE_NOT_IN_BUNDLE, RELEASE_NOT_PROVABLE_IN_ORG_BUNDLE, RELEASE_RELEASED, RELEASE_REVOKED,
    RELEASE_UNRELEASED, ReceiptActor, ReceiptLedgerRef, ReceiptResolver, ReleaseEvent, ReleaseState,
    WithheldReport, cmp_ts, config_policy_events, derive_evidence_row, extract_sod_tools_from_doc,
    is_evidence_channel, labels_equal, normalize_decision, normalize_ts_utc, release_events, release_state,
};

/// Options for [`export_bundle`].
#[derive(Debug, Clone)]
pub struct ExportBundleOptions {
    /// Existing checkpoint id in `evidence_checkpoint` whose range this bundle
    /// covers.
    pub checkpoint_id: String,
    /// Optional start sequence (exclusive) for incremental `hub` exports
    /// (e.g., the `seq` of a previously pinned checkpoint; `None` = genesis).
    pub from_seq: Option<i64>,
    /// Optional start `org_seq` (exclusive) for incremental `org` exports
    /// (the `org_row_count` of a previously pinned `org` checkpoint; `None` = 0).
    pub from_org_seq: Option<i64>,
    /// Export timestamp written into unhashed `producer.json`.
    pub exported_at: String,
    /// Host label written into unhashed `producer.json`.
    pub host: String,
    /// Tool version written into unhashed `producer.json`.
    pub tool_version: String,
}

/// Summary returned by [`export_bundle`].
#[derive(Debug, Clone)]
pub struct ExportBundleResult {
    pub manifest: BundleManifest,
    pub withheld: WithheldReport,
}

/// Derived `org`-class checkpoint fields computed directly from `event_log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgWindowSummary {
    pub org_id: String,
    pub window: Window,
    pub global_from_hash: String,
    pub global_head_hash: String,
    pub org_row_count: i64,
    pub org_chain_hash: String,
    pub window_org_rows: i64,
}

/// Derive `org`-class checkpoint fields directly from `event_log` for `org_id`
/// over the time window `[window_start, window_end]` (or continuing from
/// `prev_global_head_hash` if supplied).
///
/// Compares timestamps by RFC 3339 instant (`Z` and `+00:00` compare equal) and
/// never exposes global `seq` numbers in the returned summary.
pub fn compute_org_window_checkpoint(
    conn: &Connection,
    org_id: &str,
    window_start: &str,
    window_end: &str,
    prev_global_head_hash: Option<&str>,
) -> UaResult<OrgWindowSummary> {
    if org_id.trim().is_empty() {
        return Err(UaError::invalid("org_id must not be empty"));
    }
    let exists: bool = conn
        .query_row("SELECT 1 FROM orgs WHERE id = ?1", [org_id], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    if !exists {
        return Err(UaError::not_found(format!("organization {org_id:?} does not exist")));
    }

    let mut stmt =
        conn.prepare("SELECT seq, created_at, entry_hash, org_id FROM event_log ORDER BY seq ASC")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;

    let mut start_seq_exclusive: i64 = 0;
    let mut global_from_hash = GENESIS_HASH.to_string();
    let mut global_head_hash: Option<String> = None;
    let mut end_seq: i64 = 0;

    let mut all_rows = Vec::new();
    for row in rows {
        all_rows.push(row?);
    }

    if let Some(prev_hash) = prev_global_head_hash {
        if prev_hash == GENESIS_HASH {
            start_seq_exclusive = 0;
            global_from_hash = GENESIS_HASH.to_string();
        } else {
            let found = all_rows
                .iter()
                .find(|(_, _, eh, _)| eh.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(prev_hash)));
            let Some((seq, _, Some(h), _)) = found else {
                return Err(UaError::not_found(format!(
                    "previous global_head_hash {prev_hash:?} not found in event_log"
                )));
            };
            start_seq_exclusive = *seq;
            global_from_hash = h.clone();
        }
    }

    for (seq, created_at, entry_hash, _) in &all_rows {
        let Some(eh) = entry_hash.as_deref() else { continue };
        if prev_global_head_hash.is_none() && cmp_ts(created_at, window_start) == Ordering::Less {
            start_seq_exclusive = *seq;
            global_from_hash = eh.to_string();
        }
        if cmp_ts(created_at, window_end) != Ordering::Greater && *seq > start_seq_exclusive {
            end_seq = *seq;
            global_head_hash = Some(eh.to_string());
        }
    }

    // If no new global rows arrived inside the window, the window closes at global_from_hash.
    let closing_seq = if end_seq > 0 { end_seq } else { start_seq_exclusive };
    let closing_hash = global_head_hash.unwrap_or_else(|| global_from_hash.clone());

    let mut cumulative_count = 0i64;
    let mut window_org_rows = 0i64;
    let mut chain_hash = String::new();
    for (seq, _, entry_hash, row_org) in &all_rows {
        if *seq > closing_seq {
            break;
        }
        if row_org != org_id {
            continue;
        }
        let Some(eh) = entry_hash.as_deref() else { continue };
        chain_hash = org_chain_fold(&chain_hash, eh);
        cumulative_count += 1;
        if *seq > start_seq_exclusive {
            window_org_rows += 1;
        }
    }
    if cumulative_count == 0 {
        chain_hash = empty_org_chain_hash();
    }

    Ok(OrgWindowSummary {
        org_id: org_id.to_string(),
        window: Window { start: normalize_ts_utc(window_start), end: normalize_ts_utc(window_end) },
        global_from_hash,
        global_head_hash: closing_hash,
        org_row_count: cumulative_count,
        org_chain_hash: chain_hash,
        window_org_rows,
    })
}

/// Assemble and write a deterministic, canonical evidence bundle into `out_dir`.
///
/// Refuses to write into an existing non-empty directory. Never writes
/// `manifest.sig` (offline operator signing only).
pub fn export_bundle(
    conn: &Connection,
    out_dir: &Path,
    opts: &ExportBundleOptions,
) -> UaResult<ExportBundleResult> {
    if out_dir.exists() {
        let mut entries = std::fs::read_dir(out_dir)
            .map_err(|e| UaError::internal(format!("reading {}: {e}", out_dir.display())))?;
        if entries.next().is_some() {
            return Err(UaError::conflict(format!(
                "refusing to export into non-empty directory {}",
                out_dir.display()
            )));
        }
    }

    let checkpoint = checkpoint_get(conn, &opts.checkpoint_id)?
        .ok_or_else(|| UaError::not_found(format!("no checkpoint {:?}", opts.checkpoint_id)))?;
    let (stored_digest, signature) = checkpoint_signature(conn, &opts.checkpoint_id)?
        .ok_or_else(|| UaError::not_found(format!("no checkpoint {:?}", opts.checkpoint_id)))?;
    if checkpoint.digest() != stored_digest {
        return Err(UaError::conflict(format!(
            "checkpoint {:?} stored digest does not match its fields",
            opts.checkpoint_id
        )));
    }

    let mut filter = EgressFilter::new();

    // 1. Collect ledger rows covered by the checkpoint. Restricted channels and
    //    cross-org ORG-EVENT-DEFAULT rows in org exports become hash-only stubs.
    let ledger_data =
        collect_ledger_events(conn, &checkpoint, opts.from_seq, opts.from_org_seq, &mut filter)?;

    // Withheld table counts and `org` ordinals come from the checkpoint's
    // frozen export snapshot (captured live when none was stored), so a
    // re-export after deletes stays byte-identical. Counts are scoped to the
    // bundle window and, for `org` bundles, to the organization.
    let snapshot = match snapshot_load(conn, &opts.checkpoint_id)? {
        Some(s) if s.is_for(&checkpoint) => s,
        Some(_) => {
            return Err(UaError::conflict(format!(
                "export snapshot for {:?} was captured for a different checkpoint (class, organization or \
                 digest); refusing to export from it",
                opts.checkpoint_id
            )));
        }
        None => snapshot_capture(conn, &checkpoint)?,
    };
    for (class, n) in snapshot.withheld_in_window(
        ledger_data.start_excl_ts.as_deref(),
        &ledger_data.cutoff_ts,
        ledger_data.seq_bounds,
        &ledger_data.redacted_ulids,
    ) {
        filter.record_withheld(&class, n);
    }

    // The approval and release history the bundle's own unredacted rows hold.
    // Receipts and release state come from these immutable rows, never from
    // live tables, so a revoke or cancel after the checkpoint changes nothing.
    let history = ApprovalHistory::build(&ledger_data.events);
    let releases = release_events(&ledger_data.events);
    let mut approval_event_refs: BTreeMap<i64, ApprovalEventRef> = BTreeMap::new();
    for (&aid, idxs) in &history.resolved {
        let Some(&idx) = idxs.last() else { continue };
        let ev = &ledger_data.events[idx];
        let Some(eh) = ev.entry_hash.as_deref() else { continue };
        approval_event_refs.insert(
            aid,
            ApprovalEventRef {
                ledger: ReceiptLedgerRef { seq: ev.seq, org_seq: ev.org_seq, hash: eh.to_string() },
                payload: history.payloads[&idx].clone(),
                created_at: ev.created_at.clone(),
                requested: history.requested.get(&aid).map(|i| history.payloads[i].clone()),
            },
        );
    }

    let id_mapper = IdMapper::new(checkpoint.class, checkpoint.org_id.as_deref(), &snapshot);

    // 2. Load policy revisions up to the checkpoint cutoff (reading the actual
    //    policy `document` and deriving `sod_tools` from it — never hard-coded).
    //    The revision in force at any instant comes from the policy timeline:
    //    hash-verified `agent.config.revision` events first.
    let all_policy_revisions =
        load_policy_revisions_up_to(conn, &ledger_data.cutoff_ts, checkpoint.class, &mut filter)?;
    let timeline = PolicyTimeline::build(&ledger_data.events, &all_policy_revisions);

    // 3. Collect window-scoped artifacts, approval receipts, and evidence rows.
    let (artifacts, covers_by_raw_approval) = collect_artifacts(
        conn,
        &ArtifactInputs {
            class: checkpoint.class,
            org_id: checkpoint.org_id.as_deref(),
            start_excl_ts: ledger_data.start_excl_ts.as_deref(),
            cutoff_ts: &ledger_data.cutoff_ts,
            history: &history,
            releases: &releases,
            receipts_for: &approval_event_refs,
            timeline: &timeline,
            id_mapper: &id_mapper,
            snapshot: &snapshot,
        },
        &mut filter,
    )?;
    let approvals = collect_approval_receipts(
        conn,
        checkpoint.class,
        checkpoint.org_id.as_deref(),
        &approval_event_refs,
        &timeline,
        &all_policy_revisions,
        &covers_by_raw_approval,
        &id_mapper,
        &snapshot,
        &mut filter,
    )?;
    let evidence_rows = collect_evidence_rows(&ledger_data.events, &timeline, &id_mapper, &mut filter)?;
    let config_revs: BTreeSet<i64> =
        config_policy_events(&ledger_data.events).into_iter().map(|(r, _)| r).collect();
    // `org` bundles carry the digest of each cited policy revision without its
    // document: policy documents name identities across the hub.

    // 4. Filter `policy/revisions.json` to the bundle's scope & window:
    //    - `org` class: only policy revisions actually cited by receipts,
    //      artifacts, or evidence rows in this bundle (no hub-wide revision history).
    //    - `hub` class: revisions created inside the bundle window plus any
    //      earlier revision (<= cutoff) cited by receipts, artifacts, or evidence.
    let mut cited_policy_revs: BTreeSet<i64> = BTreeSet::new();
    for r in &approvals {
        if let Some(rev) = r.policy_revision {
            cited_policy_revs.insert(rev);
        }
    }
    for a in &artifacts {
        if let Some(rev) = a.policy_revision {
            cited_policy_revs.insert(rev);
        }
    }
    for e in &evidence_rows {
        if let Some(rev) = e.policy_revision {
            cited_policy_revs.insert(rev);
        }
    }
    let policy_revisions: Vec<PolicyRevisionRecord> = all_policy_revisions
        .into_iter()
        .map(|mut p| {
            if checkpoint.class == CheckpointClass::Org {
                p.document = None;
                p.sod_tools = Vec::new();
            }
            p
        })
        .filter(|p| {
            // A revision whose config event the bundle carries in clear is
            // always listed, so the verifier can bind it.
            let cited = p.kind == "policy"
                && (cited_policy_revs.contains(&p.revision) || config_revs.contains(&p.revision));
            match checkpoint.class {
                CheckpointClass::Org => cited,
                CheckpointClass::Hub => {
                    cited
                        || in_time_window(
                            &p.created_at,
                            ledger_data.start_excl_ts.as_deref(),
                            &ledger_data.cutoff_ts,
                        )
                }
            }
        })
        .collect();

    let withheld = filter.into_report();

    // 5. Serialize every hashed file canonically and compute per-file SHA-256.
    let mut staged: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    // ledger/events.jsonl
    let mut events_bytes = Vec::new();
    for ev in &ledger_data.events {
        let line = to_canonical_bytes(ev)?;
        events_bytes.extend_from_slice(&line);
        events_bytes.push(b'\n');
    }
    staged.insert("ledger/events.jsonl".into(), events_bytes);

    // ledger/checkpoint.json
    let cp_file = BundleCheckpointFile {
        format: CHECKPOINT_FORMAT.to_string(),
        checkpoint: checkpoint.clone(),
        digest: stored_digest,
        signature,
    };
    staged.insert("ledger/checkpoint.json".into(), to_canonical_bytes(&cp_file)?);

    // approvals/<id>.json (sorted by approval_id via BTreeMap)
    for receipt in &approvals {
        let rel = format!("approvals/{}.json", receipt.approval_id);
        staged.insert(rel, to_canonical_bytes(receipt)?);
    }

    // evidence/rows.jsonl
    let mut ev_rows_bytes = Vec::new();
    for row in &evidence_rows {
        let line = to_canonical_bytes(row)?;
        ev_rows_bytes.extend_from_slice(&line);
        ev_rows_bytes.push(b'\n');
    }
    staged.insert("evidence/rows.jsonl".into(), ev_rows_bytes);

    // policy/revisions.json
    staged.insert("policy/revisions.json".into(), to_canonical_bytes(&policy_revisions)?);

    // artifacts/index.json
    staged.insert("artifacts/index.json".into(), to_canonical_bytes(&artifacts)?);

    // withheld.json
    staged.insert("withheld.json".into(), to_canonical_bytes(&withheld)?);

    // Build manifest.json
    let mut file_hashes = BTreeMap::new();
    for (rel, bytes) in &staged {
        file_hashes.insert(rel.clone(), sha256_hex(bytes));
    }

    let counts = ManifestCounts {
        events: ledger_data.events.len() as u64,
        redacted_events: ledger_data.redacted_events,
        unhashed_legacy_prefix: ledger_data.unhashed_legacy_prefix,
        approvals: approvals.len() as u64,
        evidence_rows: evidence_rows.len() as u64,
        policy_revisions: policy_revisions.len() as u64,
        artifacts: artifacts.len() as u64,
        withheld_total: withheld.total,
    };

    let mut manifest = BundleManifest {
        format: BUNDLE_FORMAT.to_string(),
        class: checkpoint.class,
        org_id: checkpoint.org_id.clone(),
        artifact_content: ARTIFACT_CONTENT_HASH_ONLY.to_string(),
        window: ledger_data.window,
        counts,
        files: file_hashes,
        digest: String::new(),
    };
    manifest.digest = manifest.recompute_digest()?;
    let manifest_bytes = to_canonical_bytes(&manifest)?;

    let producer = ProducerInfo {
        exported_at: normalize_ts_utc(&opts.exported_at),
        host: opts.host.clone(),
        tool_version: opts.tool_version.clone(),
    };
    let producer_bytes = serde_json::to_vec_pretty(&producer)
        .map_err(|e| UaError::internal(format!("encoding producer.json: {e}")))?;

    // 6. Write all files into out_dir.
    std::fs::create_dir_all(out_dir)
        .map_err(|e| UaError::internal(format!("creating {}: {e}", out_dir.display())))?;
    for (rel, bytes) in &staged {
        let dest = out_dir.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| UaError::internal(format!("creating {}: {e}", parent.display())))?;
        }
        std::fs::write(&dest, bytes)
            .map_err(|e| UaError::internal(format!("writing {}: {e}", dest.display())))?;
    }
    std::fs::write(out_dir.join("manifest.json"), &manifest_bytes)
        .map_err(|e| UaError::internal(format!("writing manifest.json: {e}")))?;
    std::fs::write(out_dir.join("producer.json"), &producer_bytes)
        .map_err(|e| UaError::internal(format!("writing producer.json: {e}")))?;

    Ok(ExportBundleResult { manifest, withheld })
}

type ArtifactCollection = (Vec<ArtifactIndexEntry>, BTreeMap<i64, Vec<CoveredArtifact>>);

struct CollectedLedger {
    events: Vec<BundleLedgerEvent>,
    redacted_events: u64,
    unhashed_legacy_prefix: u64,
    window: Window,
    start_excl_ts: Option<String>,
    cutoff_ts: String,
    seq_bounds: Option<(i64, i64)>,
    redacted_ulids: BTreeSet<String>,
}

/// An approval's immutable columns: org, tool, payload, requester, run.
type ApprovalImmutables = (String, String, String, Option<String>, Option<String>);

struct ApprovalEventRef {
    ledger: ReceiptLedgerRef,
    payload: Value,
    /// The resolved event's `created_at` (hash-verified): the decision time.
    created_at: String,
    /// The approval's `agent.approval.requested` payload, if in the bundle.
    requested: Option<Value>,
}

struct ArtifactInputs<'a> {
    class: CheckpointClass,
    org_id: Option<&'a str>,
    start_excl_ts: Option<&'a str>,
    cutoff_ts: &'a str,
    history: &'a ApprovalHistory,
    releases: &'a [ReleaseEvent],
    receipts_for: &'a BTreeMap<i64, ApprovalEventRef>,
    timeline: &'a PolicyTimeline,
    id_mapper: &'a IdMapper<'a>,
    snapshot: &'a ExportSnapshot,
}

/// Maps hub-wide autoincrement ids to dense per-organization ordinals
/// (`1, 2, ...`) from the checkpoint's export snapshot when exporting an
/// `org`-class bundle, so hub-wide gaps never reveal cross-org volume. `hub`
/// bundles keep raw ids.
struct IdMapper<'a> {
    org: Option<String>,
    snapshot: &'a ExportSnapshot,
}

impl<'a> IdMapper<'a> {
    fn new(class: CheckpointClass, org_id: Option<&str>, snapshot: &'a ExportSnapshot) -> Self {
        let org = match class {
            CheckpointClass::Org => org_id.map(str::to_string),
            CheckpointClass::Hub => None,
        };
        Self { org, snapshot }
    }

    fn is_org(&self) -> bool {
        self.org.is_some()
    }

    /// The ordinal of a task in this organization, or `None` when it is not
    /// one of the organization's tasks (another organization's event in the
    /// default ledger, or a task deleted before the snapshot).
    fn task_id(&self, raw: i64) -> Option<i64> {
        if self.org.is_none() {
            return Some(raw);
        }
        self.snapshot.task_ordinal(raw)
    }

    fn approval_id(&self, raw: i64) -> Option<i64> {
        if self.org.is_none() {
            return Some(raw);
        }
        self.snapshot.approval_ordinal(raw)
    }

    fn deliverable_id(&self, raw: i64) -> Option<i64> {
        if self.org.is_none() {
            return Some(raw);
        }
        self.snapshot.deliverable_ordinal(raw)
    }
}

/// Detect whether an `agent.approval.*` event in the `default` ledger actually
/// belongs to another organization (written to `default` under
/// `ORG-EVENT-DEFAULT`).
fn is_foreign_org_approval_event(
    conn: &Connection,
    has_approvals: bool,
    has_approvals_org: bool,
    target_org: &str,
    channel: &str,
    payload: &str,
    originator: Option<&str>,
) -> UaResult<bool> {
    if !channel.starts_with("agent.approval.") {
        return Ok(false);
    }
    let Ok(parsed) = parse_strict_json(payload) else {
        return Ok(false);
    };
    if has_approvals
        && has_approvals_org
        && let Some(aid) = parsed.get("approval_id").and_then(Value::as_i64)
        && let Some(row_org) = conn
            .query_row("SELECT org_id FROM approvals WHERE id = ?1", [aid], |r| r.get::<_, String>(0))
            .optional()?
    {
        return Ok(row_org != target_org);
    }
    // Fallback when approvals row is unavailable: ORG-EVENT-DEFAULT emits
    // resolved_by: null and originator: "system" for non-default org approvals.
    Ok(channel == "agent.approval.resolved"
        && parsed.get("resolved_by").is_some_and(Value::is_null)
        && originator == Some("system"))
}

#[allow(clippy::too_many_arguments)]
fn make_redacted_stub(
    seq: Option<i64>,
    org_seq: Option<i64>,
    ulid: String,
    created_at: String,
    prev_hash: Option<String>,
    entry_hash: Option<String>,
    org_id: String,
    hash_v: i64,
    redacted_class: &'static str,
) -> BundleLedgerEvent {
    BundleLedgerEvent {
        seq,
        org_seq,
        ulid,
        channel: REDACTED_CHANNEL.to_string(),
        payload: String::new(),
        originator: None,
        episode_id: None,
        causal_parent_id: None,
        created_at,
        dedupe_key: None,
        prev_hash,
        entry_hash,
        org_id,
        hash_v,
        redacted: true,
        redacted_class: Some(redacted_class.to_string()),
    }
}

fn collect_ledger_events(
    conn: &Connection,
    checkpoint: &Checkpoint,
    from_seq: Option<i64>,
    from_org_seq: Option<i64>,
    filter: &mut EgressFilter,
) -> UaResult<CollectedLedger> {
    let has_org: bool = conn
        .query_row("SELECT 1 FROM pragma_table_info('event_log') WHERE name = 'hash_v'", [], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    let (org_col, hv_col) = if has_org { ("org_id", "hash_v") } else { ("'default'", "1") };

    let mut stmt = conn.prepare(&format!(
        "SELECT seq, ulid, channel, payload, originator, episode_id, causal_parent_id, created_at, \
                dedupe_key, prev_hash, entry_hash, {org_col}, {hv_col} \
         FROM event_log ORDER BY seq ASC"
    ))?;
    let all_rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, Option<String>>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, Option<String>>(8)?,
            r.get::<_, Option<String>>(9)?,
            r.get::<_, Option<String>>(10)?,
            r.get::<_, String>(11)?,
            r.get::<_, i64>(12)?,
        ))
    })?;

    let mut rows = Vec::new();
    for r in all_rows {
        rows.push(r?);
    }

    match checkpoint.class {
        CheckpointClass::Hub => {
            let max_seq = checkpoint.seq.ok_or_else(|| UaError::invalid("hub checkpoint has no seq"))?;
            let min_excl = from_seq.unwrap_or(0);
            let start_excl_ts = if min_excl > 0 {
                rows.iter().find(|r| r.0 == min_excl).map(|r| normalize_ts_utc(&r.7))
            } else {
                None
            };
            let mut out = Vec::new();
            let mut redacted_events = 0u64;
            let mut redacted_ulids = BTreeSet::new();
            let mut unhashed_prefix = 0u64;
            let mut seen_hashed = false;
            let mut first_ts: Option<String> = None;
            let mut last_ts: Option<String> = None;
            for (seq, ulid, channel, payload, orig, ep, cp, ts, dedupe, prev, entry, org_id, hash_v) in rows {
                if seq > max_seq {
                    break;
                }
                if seq <= min_excl {
                    continue;
                }
                let action = filter.inspect_ledger_event(
                    checkpoint.class,
                    &channel,
                    &payload,
                    &[orig.as_deref(), ep.as_deref(), cp.as_deref(), dedupe.as_deref()],
                );
                if entry.is_none() && !seen_hashed {
                    unhashed_prefix += 1;
                } else if entry.is_some() {
                    seen_hashed = true;
                }
                let norm_ts = normalize_ts_utc(&ts);
                if first_ts.is_none() {
                    first_ts = Some(norm_ts.clone());
                }
                last_ts = Some(norm_ts);
                match action {
                    LedgerEgressAction::Allow => {
                        out.push(BundleLedgerEvent {
                            seq: Some(seq),
                            org_seq: None,
                            ulid,
                            channel,
                            payload,
                            originator: orig,
                            episode_id: ep,
                            causal_parent_id: cp,
                            created_at: ts,
                            dedupe_key: dedupe,
                            prev_hash: prev,
                            entry_hash: entry,
                            org_id,
                            hash_v,
                            redacted: false,
                            redacted_class: None,
                        });
                    }
                    LedgerEgressAction::RedactToHashOnly(class) => {
                        redacted_events += 1;
                        redacted_ulids.insert(ulid.clone());
                        out.push(make_redacted_stub(
                            Some(seq),
                            None,
                            ulid,
                            ts,
                            prev,
                            entry,
                            org_id,
                            hash_v,
                            class,
                        ));
                    }
                }
            }
            let cutoff_ts = last_ts.clone().unwrap_or_else(|| normalize_ts_utc(&checkpoint.signed_at));
            let window =
                Window { start: first_ts.unwrap_or_else(|| cutoff_ts.clone()), end: cutoff_ts.clone() };
            Ok(CollectedLedger {
                events: out,
                redacted_events,
                unhashed_legacy_prefix: unhashed_prefix,
                window,
                start_excl_ts,
                cutoff_ts,
                seq_bounds: Some((min_excl, max_seq)),
                redacted_ulids,
            })
        }
        CheckpointClass::Org => {
            let target_org = checkpoint
                .org_id
                .as_deref()
                .ok_or_else(|| UaError::invalid("org checkpoint has no org_id"))?;
            let global_from = checkpoint
                .global_from_hash
                .as_deref()
                .ok_or_else(|| UaError::invalid("org checkpoint has no global_from_hash"))?;
            let global_head = checkpoint
                .global_head_hash
                .as_deref()
                .ok_or_else(|| UaError::invalid("org checkpoint has no global_head_hash"))?;
            let raw_window =
                checkpoint.window.clone().ok_or_else(|| UaError::invalid("org checkpoint has no window"))?;
            let window =
                Window { start: normalize_ts_utc(&raw_window.start), end: normalize_ts_utc(&raw_window.end) };

            let (start_seq_excl, start_excl_ts): (i64, Option<String>) = if global_from == GENESIS_HASH {
                (0, None)
            } else {
                let row = rows
                    .iter()
                    .find(|r| r.10.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(global_from)))
                    .ok_or_else(|| {
                        UaError::not_found(format!(
                            "org checkpoint global_from_hash {global_from:?} not found in event_log"
                        ))
                    })?;
                (row.0, Some(normalize_ts_utc(&row.7)))
            };
            let (end_seq, head_row_ts): (i64, Option<String>) = if global_head == GENESIS_HASH {
                (0, None)
            } else {
                let row = rows
                    .iter()
                    .find(|r| r.10.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(global_head)))
                    .ok_or_else(|| {
                        UaError::not_found(format!(
                            "org checkpoint global_head_hash {global_head:?} not found in event_log"
                        ))
                    })?;
                (row.0, Some(normalize_ts_utc(&row.7)))
            };
            if end_seq < start_seq_excl {
                return Err(UaError::invalid(
                    "org checkpoint global_head_hash precedes global_from_hash in event_log",
                ));
            }
            let cutoff_ts = head_row_ts.unwrap_or_else(|| window.end.clone());

            let has_approvals = table_exists(conn, "approvals")?;
            let has_approvals_org = has_approvals && column_exists(conn, "approvals", "org_id")?;

            let mut out = Vec::new();
            let mut redacted_events = 0u64;
            let mut redacted_ulids = BTreeSet::new();
            let mut cumulative_org_seq = 0i64;
            let mut org_count_before_window = 0i64;
            let mut chain_hash = String::new();
            for (seq, ulid, channel, payload, orig, ep, cp, ts, dedupe, prev, entry, org_id, hash_v) in rows {
                if seq > end_seq {
                    break;
                }
                if org_id != target_org {
                    continue;
                }
                // `org_chain_hash` and `org_row_count` fold only hashed rows;
                // unhashed legacy rows are not emitted in an `org` bundle, so
                // `unhashed_legacy_prefix` is always 0 for `org` class.
                let Some(eh) = entry.as_deref() else {
                    continue;
                };
                chain_hash = org_chain_fold(&chain_hash, eh);
                cumulative_org_seq += 1;
                if seq <= start_seq_excl {
                    org_count_before_window = cumulative_org_seq;
                    continue;
                }
                if let Some(min_excl) = from_org_seq
                    && cumulative_org_seq <= min_excl
                {
                    continue;
                }
                // Under ORG-EVENT-DEFAULT, other organizations' approval events
                // sit in the `default` ledger. Redact them to hash-only stubs
                // so default-org bundles neither leak foreign activity nor fail
                // receipt cross-links.
                if is_foreign_org_approval_event(
                    conn,
                    has_approvals,
                    has_approvals_org,
                    target_org,
                    &channel,
                    &payload,
                    orig.as_deref(),
                )? {
                    filter.record_withheld(CLASS_CROSS_ORG_EVENTS, 1);
                    redacted_events += 1;
                    redacted_ulids.insert(ulid.clone());
                    out.push(make_redacted_stub(
                        None,
                        Some(cumulative_org_seq),
                        ulid,
                        ts,
                        prev,
                        entry,
                        org_id,
                        hash_v,
                        CLASS_CROSS_ORG_EVENTS,
                    ));
                    continue;
                }
                let action = filter.inspect_ledger_event(
                    checkpoint.class,
                    &channel,
                    &payload,
                    &[orig.as_deref(), ep.as_deref(), cp.as_deref(), dedupe.as_deref()],
                );
                match action {
                    LedgerEgressAction::Allow => {
                        out.push(BundleLedgerEvent {
                            seq: None,
                            org_seq: Some(cumulative_org_seq),
                            ulid,
                            channel,
                            payload,
                            originator: orig,
                            episode_id: ep,
                            causal_parent_id: cp,
                            created_at: ts,
                            dedupe_key: dedupe,
                            prev_hash: prev,
                            entry_hash: entry,
                            org_id,
                            hash_v,
                            redacted: false,
                            redacted_class: None,
                        });
                    }
                    LedgerEgressAction::RedactToHashOnly(class) => {
                        redacted_events += 1;
                        redacted_ulids.insert(ulid.clone());
                        out.push(make_redacted_stub(
                            None,
                            Some(cumulative_org_seq),
                            ulid,
                            ts,
                            prev,
                            entry,
                            org_id,
                            hash_v,
                            class,
                        ));
                    }
                }
            }
            if let Some(min_excl) = from_org_seq
                && min_excl != org_count_before_window
            {
                return Err(UaError::invalid(format!(
                    "from_org_seq ({min_excl}) does not match org row count before global_from_hash ({org_count_before_window})"
                )));
            }
            let final_chain = if cumulative_org_seq == 0 { empty_org_chain_hash() } else { chain_hash };
            if checkpoint.org_row_count != Some(cumulative_org_seq) {
                return Err(UaError::conflict(format!(
                    "org checkpoint org_row_count ({:?}) does not match event_log count ({cumulative_org_seq})",
                    checkpoint.org_row_count
                )));
            }
            if !checkpoint.org_chain_hash.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(&final_chain)) {
                return Err(UaError::conflict(format!(
                    "org checkpoint org_chain_hash ({:?}) does not match event_log fold ({final_chain})",
                    checkpoint.org_chain_hash
                )));
            }
            Ok(CollectedLedger {
                events: out,
                redacted_events,
                unhashed_legacy_prefix: 0,
                window,
                start_excl_ts,
                cutoff_ts,
                seq_bounds: Some((start_seq_excl, end_seq)),
                redacted_ulids,
            })
        }
    }
}

fn load_policy_revisions_up_to(
    conn: &Connection,
    cutoff_ts: &str,
    class: CheckpointClass,
    filter: &mut EgressFilter,
) -> UaResult<Vec<PolicyRevisionRecord>> {
    if !table_exists(conn, "config_revisions")? {
        return Ok(Vec::new());
    }
    let has_doc = column_exists(conn, "config_revisions", "document")?;
    let doc_col = if has_doc { "document" } else { "NULL" };
    let mut stmt = conn.prepare(&format!(
        "SELECT id, kind, revision, action, actor, {doc_col}, document_sha256, raw_sha256, \
                approval_id, event_ulid, created_at \
         FROM config_revisions ORDER BY kind ASC, revision ASC"
    ))?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, Option<i64>>(8)?,
            r.get::<_, Option<String>>(9)?,
            r.get::<_, String>(10)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            kind,
            revision,
            action,
            actor,
            doc_raw,
            document_sha256,
            raw_sha256,
            approval_id,
            event_ulid,
            created_at,
        ) = row?;
        if cmp_ts(&created_at, cutoff_ts) == Ordering::Greater {
            continue;
        }
        let (document, sod_tools) = match doc_raw.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => {
                let parsed: Value = serde_json::from_str(raw).map_err(|e| {
                    UaError::internal(format!("config_revisions ({kind}, rev {revision}) invalid JSON: {e}"))
                })?;
                let sod = extract_sod_tools_from_doc(&parsed);
                (Some(ua_core::canonical::to_string(&parsed)), sod)
            }
            None => (None, Vec::new()),
        };
        let is_hub = class == CheckpointClass::Hub;
        let mut rec = PolicyRevisionRecord {
            id: is_hub.then_some(id),
            kind,
            revision,
            action,
            actor,
            document,
            document_sha256,
            raw_sha256,
            sod_tools,
            approval_id: if is_hub { approval_id } else { None },
            event_ulid: if is_hub { event_ulid } else { None },
            created_at: normalize_ts_utc(&created_at),
        };
        // The backstop never blocks an export: a document it flags is dropped
        // (the digest stays), and an actor that is not a safe label is a
        // placeholder.
        let val = serde_json::to_value(&rec).map_err(|e| UaError::internal(e.to_string()))?;
        if find_forbidden_in_value(&val).is_some() {
            filter.record_withheld(CLASS_SCANNER_WITHHELD, 1);
            rec.document = None;
            rec.sod_tools = Vec::new();
        }
        if !is_safe_label(&rec.actor) || find_forbidden_in_text(&rec.actor).is_some() {
            rec.actor = LABEL_PLACEHOLDER.to_string();
        }
        out.push(rec);
    }
    Ok(out)
}

struct RawArtifactRevision {
    rev_row_id: i64,
    deliverable_id: i64,
    raw_task_id: i64,
    kind: String,
    rev_no: i64,
    identity: String,
    recorded_at: String,
    row_org: String,
}

fn collect_artifacts(
    conn: &Connection,
    inp: &ArtifactInputs<'_>,
    filter: &mut EgressFilter,
) -> UaResult<ArtifactCollection> {
    if !table_exists(conn, "deliverables")? || !table_exists(conn, "deliverable_revisions")? {
        return Ok((Vec::new(), BTreeMap::new()));
    }
    let has_files = table_exists(conn, "deliverable_files")?;
    let has_dispatch_runs = table_exists(conn, "dispatch_runs")?;
    let has_dispatch_runs_org = has_dispatch_runs && column_exists(conn, "dispatch_runs", "org_id")?;
    // A non-default organization's approval events sit in the default ledger
    // (ORG-EVENT-DEFAULT), so its `org` bundle can never prove a release.
    let org_bundle_without_approvals =
        inp.class == CheckpointClass::Org && inp.org_id.is_some_and(|o| o != DEFAULT_ORG);

    let sql = match inp.org_id {
        Some(_) => {
            "SELECT r.id, d.id, d.task_id, d.kind, r.rev_no, r.identity, r.recorded_at, d.org_id \
             FROM deliverable_revisions r \
             JOIN deliverables d ON d.id = r.deliverable_id AND d.org_id = r.org_id \
             WHERE r.org_id = ?1 \
             ORDER BY d.id ASC, r.rev_no ASC"
        }
        None => {
            "SELECT r.id, d.id, d.task_id, d.kind, r.rev_no, r.identity, r.recorded_at, d.org_id \
             FROM deliverable_revisions r \
             JOIN deliverables d ON d.id = r.deliverable_id \
             ORDER BY d.id ASC, r.rev_no ASC"
        }
    };
    let mut stmt = conn.prepare(sql)?;
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<RawArtifactRevision> {
        Ok(RawArtifactRevision {
            rev_row_id: r.get(0)?,
            deliverable_id: r.get(1)?,
            raw_task_id: r.get(2)?,
            kind: r.get(3)?,
            rev_no: r.get(4)?,
            identity: r.get(5)?,
            recorded_at: r.get(6)?,
            row_org: r.get(7)?,
        })
    };
    let raw_rows: Vec<RawArtifactRevision> = match inp.org_id {
        Some(org) => stmt.query_map([org], map_row)?.collect::<Result<_, _>>()?,
        None => stmt.query_map([], map_row)?.collect::<Result<_, _>>()?,
    };

    // Release events by revision id.
    let mut by_revision: BTreeMap<i64, Vec<&ReleaseEvent>> = BTreeMap::new();
    for e in inp.releases {
        if let Some(rid) = e.revision_id {
            by_revision.entry(rid).or_default().push(e);
        }
    }

    let mut out = Vec::new();
    let mut covers_by_raw_approval: BTreeMap<i64, Vec<CoveredArtifact>> = BTreeMap::new();
    for RawArtifactRevision {
        rev_row_id,
        deliverable_id,
        raw_task_id,
        kind,
        rev_no,
        identity,
        recorded_at,
        row_org,
    } in raw_rows
    {
        // Release state from the bundle's own release and approval events.
        let matching = by_revision.get(&rev_row_id).cloned().unwrap_or_default();
        let state = release_state(&matching, inp.history);
        let raw_approval_id = match state {
            ReleaseState::Released(aid) if inp.receipts_for.contains_key(&aid) => Some(aid),
            _ => None,
        };

        // Include revisions recorded inside the bundle window, plus any earlier
        // revision (<= cutoff) released by an approval resolved in this window.
        let in_win = in_time_window(&recorded_at, inp.start_excl_ts, inp.cutoff_ts);
        let covered_in_window =
            raw_approval_id.is_some() && cmp_ts(&recorded_at, inp.cutoff_ts) != Ordering::Greater;
        if !in_win && !covered_in_window {
            continue;
        }

        let size: i64 = if has_files {
            conn.query_row(
                "SELECT size_bytes FROM deliverable_files WHERE revision_id = ?1",
                [rev_row_id],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0)
        } else {
            0
        };

        // Resolve the latest dispatch run for this task created at or before
        // `recorded_at` (and never after `cutoff_ts` so exports stay deterministic).
        let (run_id, attempt): (Option<String>, Option<i64>) = if has_dispatch_runs {
            let runs: Vec<(String, i64, String)> = if has_dispatch_runs_org {
                let mut rstmt = conn.prepare(
                    "SELECT run_id, attempt, created_at FROM dispatch_runs \
                     WHERE task_id = ?1 AND org_id = ?2 ORDER BY attempt DESC, created_at DESC",
                )?;
                rstmt
                    .query_map(rusqlite::params![raw_task_id, row_org], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })?
                    .collect::<Result<_, _>>()?
            } else {
                let mut rstmt = conn.prepare(
                    "SELECT run_id, attempt, created_at FROM dispatch_runs \
                     WHERE task_id = ?1 ORDER BY attempt DESC, created_at DESC",
                )?;
                rstmt
                    .query_map([raw_task_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<_, _>>()?
            };
            let within_cutoff: Vec<_> = runs
                .into_iter()
                .filter(|(_, _, ts)| cmp_ts(ts, inp.cutoff_ts) != Ordering::Greater)
                .collect();
            within_cutoff
                .iter()
                .find(|(_, _, ts)| cmp_ts(ts, &recorded_at) != Ordering::Greater)
                .or_else(|| within_cutoff.first())
                .map_or((None, None), |(rid, att, _)| (Some(rid.clone()), Some(*att)))
        } else {
            (None, None)
        };
        // Typed fields only: an identity or run id that is not a safe label is
        // withheld rather than exported.
        if !is_safe_label(&identity) || run_id.as_deref().is_some_and(|r| !is_safe_label(r)) {
            filter.record_withheld(super::export_schema::CLASS_UNLISTED_PAYLOAD, 1);
            continue;
        }

        let policy_revision = inp.timeline.in_force(&recorded_at).map(|(rev, _)| rev);
        let media_type = if kind == "commit" {
            "application/vnd.ua.git-commit".to_string()
        } else {
            "application/octet-stream".to_string()
        };

        let mapped_deliv_id = inp.id_mapper.deliverable_id(deliverable_id).ok_or_else(|| {
            UaError::conflict(format!(
                "deliverable {deliverable_id} is missing from the checkpoint's export snapshot; cannot map it to an \
                 organization-local id"
            ))
        })?;
        let mapped_task_id = inp.id_mapper.task_id(raw_task_id).ok_or_else(|| {
            UaError::conflict(format!(
                "task {raw_task_id} of deliverable {deliverable_id} is missing from the checkpoint's export \
                 snapshot; cannot map it to an organization-local id"
            ))
        })?;
        let mapped_approval_id = match raw_approval_id {
            Some(aid) => Some(inp.id_mapper.approval_id(aid).ok_or_else(|| {
                UaError::conflict(format!(
                    "approval {aid} is missing from the checkpoint's export snapshot; cannot map it to an \
                     organization-local id"
                ))
            })?),
            None => None,
        };
        let release_status = match state {
            _ if mapped_approval_id.is_some() => RELEASE_RELEASED,
            ReleaseState::Revoked => RELEASE_REVOKED,
            ReleaseState::Released(_) | ReleaseState::ApprovalNotInBundle => RELEASE_NOT_IN_BUNDLE,
            ReleaseState::NoEvent if inp.snapshot.has_live_release(rev_row_id) => {
                if org_bundle_without_approvals {
                    RELEASE_NOT_PROVABLE_IN_ORG_BUNDLE
                } else {
                    RELEASE_NOT_IN_BUNDLE
                }
            }
            ReleaseState::NoEvent => RELEASE_UNRELEASED,
        };
        let artifact_id = format!("deliverable:{mapped_deliv_id}");

        let entry = ArtifactIndexEntry {
            id: artifact_id.clone(),
            revision: rev_no,
            sha256: identity.clone(),
            size,
            media_type,
            task_id: mapped_task_id,
            run_id,
            attempt,
            policy_revision,
            approval_id: mapped_approval_id,
            release_status: release_status.to_string(),
            recorded_at: normalize_ts_utc(&recorded_at),
        };
        let val = serde_json::to_value(&entry).map_err(|e| UaError::internal(e.to_string()))?;
        if find_forbidden_in_value(&val).is_some() {
            // The backstop withholds; it never blocks the export.
            filter.record_withheld(CLASS_SCANNER_WITHHELD, 1);
            continue;
        }
        if let Some(raw_aid) = raw_approval_id {
            covers_by_raw_approval.entry(raw_aid).or_default().push(CoveredArtifact {
                id: artifact_id,
                revision: rev_no,
                sha256: identity,
            });
        }
        out.push(entry);
    }
    Ok((out, covers_by_raw_approval))
}

/// A label as a receipt may carry it: a known-safe label the backstop scanner
/// passes, or [`LABEL_PLACEHOLDER`].
fn receipt_label(label: &str) -> String {
    if is_safe_label(label) && find_forbidden_in_text(label).is_none() {
        label.to_string()
    } else {
        LABEL_PLACEHOLDER.to_string()
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_approval_receipts(
    conn: &Connection,
    class: CheckpointClass,
    org_id: Option<&str>,
    approval_event_refs: &BTreeMap<i64, ApprovalEventRef>,
    timeline: &PolicyTimeline,
    policy_revisions: &[PolicyRevisionRecord],
    covers_by_raw_approval: &BTreeMap<i64, Vec<CoveredArtifact>>,
    id_mapper: &IdMapper<'_>,
    snapshot: &ExportSnapshot,
    filter: &mut EgressFilter,
) -> UaResult<Vec<ApprovalReceipt>> {
    if approval_event_refs.is_empty() || !table_exists(conn, "approvals")? {
        return Ok(Vec::new());
    }
    let has_org = column_exists(conn, "approvals", "org_id")?;
    let org_col = if has_org { "org_id" } else { "'default'" };

    let mut out = Vec::new();
    for (&raw_aid, ev_ref) in approval_event_refs {
        let ev_payload = &ev_ref.payload;
        // Only the approval's immutable columns are read: who asked, for which
        // tool and payload, under which run. Everything that changes with a
        // later resolution comes from the hash-verified events.
        let row: Option<ApprovalImmutables> = conn
            .query_row(
                &format!(
                    "SELECT {org_col}, tool, payload, requested_by, run_id FROM approvals WHERE id = ?1"
                ),
                [raw_aid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((row_org, row_tool, payload_raw, requested_by, run_id)) = row else { continue };
        if let Some(expected_org) = org_id
            && row_org != expected_org
        {
            continue;
        }
        let tool =
            ev_payload.get("tool").and_then(Value::as_str).map(str::to_string).unwrap_or(row_tool.clone());
        let decision = normalize_decision(ev_payload.get("decision").and_then(Value::as_str).unwrap_or(""));
        let decided_at = normalize_ts_utc(&ev_ref.created_at);
        let expires_at = ev_payload.get("expires_at").and_then(Value::as_str).map(normalize_ts_utc);
        let action_digest = match ev_payload
            .get("payload_sha256")
            .or_else(|| ev_payload.get("action_digest"))
            .and_then(Value::as_str)
        {
            Some(d) if !d.is_empty() => d.to_string(),
            _ => {
                let parsed: Value =
                    serde_json::from_str(&payload_raw).unwrap_or_else(|_| Value::String(payload_raw.clone()));
                sha256_hex(ua_core::canonical::to_string(&parsed).as_bytes())
            }
        };

        // Labels: the ledger's own labels when it records them; another
        // organization's labels (`null` in the ledger) are a placeholder in a
        // `hub` bundle.
        let redact_for_hub = class == CheckpointClass::Hub && row_org != DEFAULT_ORG;
        let ledger_requester = ev_ref
            .requested
            .as_ref()
            .and_then(|p| p.get("requested_by"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let raw_req_label = ledger_requester.or(requested_by).unwrap_or_else(|| "unknown".to_string());
        let ledger_resolver = ev_payload.get("resolved_by").and_then(Value::as_str).map(str::to_string);
        let (req_label, resolver_label, resolver_is_requester) = if redact_for_hub {
            (LABEL_PLACEHOLDER.to_string(), LABEL_PLACEHOLDER.to_string(), snapshot.self_resolved(raw_aid))
        } else {
            let req = receipt_label(&raw_req_label);
            let res = receipt_label(ledger_resolver.as_deref().unwrap_or(LABEL_PLACEHOLDER));
            let same = if req == LABEL_PLACEHOLDER || res == LABEL_PLACEHOLDER {
                snapshot.self_resolved(raw_aid)
            } else {
                labels_equal(&req, &res)
            };
            (req, res, same)
        };

        let request_val = json!({
            "payload": payload_raw,
            "requested_by": req_label,
            "tool": row_tool,
        });
        let request_digest = sha256_hex(to_canonical_string(&request_val)?.as_bytes());

        let resolver_transport = ev_payload.get("transport").and_then(Value::as_str).map(str::to_string);
        // The ledger records no resolver kind. The hub admits only a verified
        // human to approve, so an approval's resolver is reported as `human`
        // (hub-asserted); a requester denying or revoking their own call is
        // an `agent`.
        let resolver_kind = if decision != "approved" && resolver_is_requester { "agent" } else { "human" };

        let attempt = if let Some(rid) = run_id.as_deref()
            && table_exists(conn, "dispatch_runs")?
        {
            conn.query_row("SELECT attempt FROM dispatch_runs WHERE run_id = ?1", [rid], |r| r.get(0))
                .optional()?
        } else {
            None
        };
        let run_id = run_id.filter(|r| is_safe_label(r) && find_forbidden_in_text(r).is_none());

        let policy_match = timeline
            .in_force(&decided_at)
            .and_then(|(rev, _)| policy_revisions.iter().find(|p| p.kind == "policy" && p.revision == rev));
        let covers = covers_by_raw_approval.get(&raw_aid).cloned().unwrap_or_default();
        let mapped_aid = id_mapper.approval_id(raw_aid).ok_or_else(|| {
            UaError::conflict(format!(
                "approval {raw_aid} is missing from the checkpoint's export snapshot; cannot map it to an \
                 organization-local id"
            ))
        })?;

        let mut receipt = ApprovalReceipt {
            receipt_id: String::new(),
            approval_id: mapped_aid,
            org_id: row_org,
            tool,
            action_digest,
            request_digest,
            policy_revision: policy_match.map(|p| p.revision),
            policy_digest: policy_match.map(|p| p.document_sha256.clone()),
            requester: ReceiptActor { label: req_label, kind: "agent".to_string() },
            resolver: ReceiptResolver {
                label: resolver_label,
                kind: resolver_kind.to_string(),
                transport: resolver_transport,
            },
            resolver_is_requester,
            decision,
            decided_at,
            expires_at,
            ledger: ev_ref.ledger.clone(),
            run_id,
            attempt,
            covers,
        };
        receipt.receipt_id = receipt.compute_receipt_id()?;
        let val = serde_json::to_value(&receipt).map_err(|e| UaError::internal(e.to_string()))?;
        filter.check_structured_record(&format!("approval receipt {mapped_aid}"), &val)?;
        out.push(receipt);
    }
    out.sort_by_key(|r| r.approval_id);
    Ok(out)
}

fn collect_evidence_rows(
    events: &[BundleLedgerEvent],
    timeline: &PolicyTimeline,
    id_mapper: &IdMapper<'_>,
    filter: &mut EgressFilter,
) -> UaResult<Vec<EvidenceRow>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for ev in events {
        if ev.redacted || !is_evidence_channel(&ev.channel) || !seen.insert(ev.ulid.clone()) {
            continue;
        }
        let Ok(parsed) = parse_strict_json(&ev.payload) else { continue };
        let mut row = derive_evidence_row(ev, &parsed, timeline);
        if id_mapper.is_org() {
            // Dense organization-local task ordinal (or none for a task that is
            // not this organization's); the raw hub approval id is dropped.
            row.task_id = row.task_id.and_then(|tid| id_mapper.task_id(tid));
            row.approval_id = None;
        }
        let val = serde_json::to_value(&row).map_err(|e| UaError::internal(e.to_string()))?;
        if filter.allow_evidence_row(&val)? {
            out.push(row);
        }
    }
    Ok(out)
}
