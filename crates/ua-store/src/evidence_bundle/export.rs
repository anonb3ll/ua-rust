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
use super::egress::{CLASS_CROSS_ORG_EVENTS, EgressFilter, LedgerEgressAction};
use super::{
    ARTIFACT_CONTENT_HASH_ONLY, ApprovalReceipt, ArtifactIndexEntry, BUNDLE_FORMAT, BundleCheckpointFile,
    BundleLedgerEvent, BundleManifest, CoveredArtifact, EvidenceRow, ManifestCounts, PolicyRevisionRecord,
    ProducerInfo, REDACTED_CHANNEL, ReceiptActor, ReceiptLedgerRef, ReceiptResolver, WithheldReport, cmp_ts,
    extract_sod_tools_from_doc, normalize_ts_utc,
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

    // Count inherently withheld database tables strictly within the checkpoint's
    // window so re-exporting an older checkpoint after later writes stays
    // byte-identical and hub bundles never expose all-time table totals.
    filter.count_withheld_tables(
        conn,
        checkpoint.org_id.as_deref(),
        ledger_data.start_excl_ts.as_deref(),
        &ledger_data.cutoff_ts,
        ledger_data.seq_bounds,
        &ledger_data.redacted_ulids,
    )?;

    // Build lookup map of unredacted exported approval resolution events so
    // receipts cross-link directly.
    let mut approval_event_refs: BTreeMap<i64, (ReceiptLedgerRef, Value)> = BTreeMap::new();
    for ev in &ledger_data.events {
        if ev.redacted {
            continue;
        }
        if ev.channel == "agent.approval.resolved"
            && let Some(eh) = ev.entry_hash.as_deref()
            && let Ok(parsed) = serde_json::from_str::<Value>(&ev.payload)
            && let Some(aid) = parsed.get("approval_id").and_then(Value::as_i64)
        {
            approval_event_refs.insert(
                aid,
                (ReceiptLedgerRef { seq: ev.seq, org_seq: ev.org_seq, hash: eh.to_string() }, parsed),
            );
        }
    }

    // Build org-local dense ID mapper for `org` bundles so hub-wide
    // autoincrement gaps never reveal cross-org volume.
    let id_mapper =
        OrgIdMapper::new(conn, checkpoint.class, checkpoint.org_id.as_deref(), &ledger_data.events)?;

    // 2. Load policy revisions up to the checkpoint cutoff (reading the actual
    //    policy `document` and deriving `sod_tools` from it — never hard-coded).
    let all_policy_revisions =
        load_policy_revisions_up_to(conn, &ledger_data.cutoff_ts, checkpoint.class, &mut filter)?;

    // 3. Collect window-scoped artifacts, approval receipts, and evidence rows.
    let exported_raw_approval_ids: BTreeSet<i64> = approval_event_refs.keys().copied().collect();
    let (artifacts, covers_by_raw_approval) = collect_artifacts(
        conn,
        checkpoint.org_id.as_deref(),
        ledger_data.start_excl_ts.as_deref(),
        &ledger_data.cutoff_ts,
        &exported_raw_approval_ids,
        &all_policy_revisions,
        &id_mapper,
        &mut filter,
    )?;
    let approvals = collect_approval_receipts(
        conn,
        checkpoint.class,
        checkpoint.org_id.as_deref(),
        &approval_event_refs,
        &all_policy_revisions,
        &covers_by_raw_approval,
        &id_mapper,
        &mut filter,
    )?;
    let evidence_rows =
        collect_evidence_rows(&ledger_data.events, &all_policy_revisions, &id_mapper, &mut filter)?;

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
        .filter(|p| {
            let cited = p.kind == "policy" && cited_policy_revs.contains(&p.revision);
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

struct RawApprovalRow {
    org_id: String,
    tool: String,
    payload_raw: String,
    requested_by: Option<String>,
    status: String,
    reason: Option<String>,
    resolved_by: Option<String>,
    resolved_at: Option<String>,
    run_id: Option<String>,
    transport: Option<String>,
}

/// Maps hub-wide autoincrement IDs to dense per-organization ordinals (`1, 2, ...`)
/// when exporting an `org`-class bundle so cross-org volume gaps never leak.
/// For `hub` bundles, returns raw IDs unchanged.
struct OrgIdMapper {
    org_id: Option<String>,
    has_tasks_org: bool,
    has_approvals_org: bool,
    has_deliverables_org: bool,
    fallback_task_ordinals: BTreeMap<i64, i64>,
}

impl OrgIdMapper {
    fn new(
        conn: &Connection,
        class: CheckpointClass,
        org_id: Option<&str>,
        events: &[BundleLedgerEvent],
    ) -> UaResult<Self> {
        let Some(org) = (match class {
            CheckpointClass::Org => org_id,
            CheckpointClass::Hub => None,
        }) else {
            return Ok(Self {
                org_id: None,
                has_tasks_org: false,
                has_approvals_org: false,
                has_deliverables_org: false,
                fallback_task_ordinals: BTreeMap::new(),
            });
        };
        let has_tasks_org = table_exists(conn, "tasks")? && column_exists(conn, "tasks", "org_id")?;
        let has_approvals_org =
            table_exists(conn, "approvals")? && column_exists(conn, "approvals", "org_id")?;
        let has_deliverables_org =
            table_exists(conn, "deliverables")? && column_exists(conn, "deliverables", "org_id")?;

        let mut fallback_task_ordinals = BTreeMap::new();
        if !has_tasks_org {
            let mut task_ids = BTreeSet::new();
            if has_deliverables_org {
                let mut stmt = conn.prepare("SELECT DISTINCT task_id FROM deliverables WHERE org_id = ?1")?;
                for row in stmt.query_map([org], |r| r.get::<_, i64>(0))? {
                    let tid = row?;
                    if tid > 0 {
                        task_ids.insert(tid);
                    }
                }
            }
            for ev in events {
                if !ev.redacted
                    && let Ok(v) = serde_json::from_str::<Value>(&ev.payload)
                    && let Some(tid) = v.get("task_id").and_then(Value::as_i64)
                    && tid > 0
                {
                    task_ids.insert(tid);
                }
            }
            for (idx, tid) in task_ids.into_iter().enumerate() {
                fallback_task_ordinals.insert(tid, (idx + 1) as i64);
            }
        }

        Ok(Self {
            org_id: Some(org.to_string()),
            has_tasks_org,
            has_approvals_org,
            has_deliverables_org,
            fallback_task_ordinals,
        })
    }

    fn task_id(&self, conn: &Connection, raw: i64) -> UaResult<i64> {
        let Some(org) = self.org_id.as_deref() else {
            return Ok(raw);
        };
        if self.has_tasks_org {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM tasks WHERE org_id = ?1 AND id <= ?2",
                rusqlite::params![org, raw],
                |r| r.get(0),
            )?;
            if n > 0 {
                return Ok(n);
            }
        }
        Ok(*self.fallback_task_ordinals.get(&raw).unwrap_or(&1))
    }

    fn approval_id(&self, conn: &Connection, raw: i64) -> UaResult<i64> {
        let Some(org) = self.org_id.as_deref() else {
            return Ok(raw);
        };
        if self.has_approvals_org {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM approvals WHERE org_id = ?1 AND id <= ?2",
                rusqlite::params![org, raw],
                |r| r.get(0),
            )?;
            if n > 0 {
                return Ok(n);
            }
        }
        Ok(raw)
    }

    fn deliverable_id(&self, conn: &Connection, raw: i64) -> UaResult<i64> {
        let Some(org) = self.org_id.as_deref() else {
            return Ok(raw);
        };
        if self.has_deliverables_org {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM deliverables WHERE org_id = ?1 AND id <= ?2",
                rusqlite::params![org, raw],
                |r| r.get(0),
            )?;
            if n > 0 {
                return Ok(n);
            }
        }
        Ok(raw)
    }
}

fn in_time_window(ts: &str, start_excl_ts: Option<&str>, cutoff_ts: &str) -> bool {
    if cmp_ts(ts, cutoff_ts) == Ordering::Greater {
        return false;
    }
    if let Some(start) = start_excl_ts
        && cmp_ts(ts, start) != Ordering::Greater
    {
        return false;
    }
    true
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
    let Ok(parsed) = serde_json::from_str::<Value>(payload) else {
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
                let action = filter.inspect_ledger_event(&channel, &payload)?;
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
                let action = filter.inspect_ledger_event(&channel, &payload)?;
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

fn table_exists(conn: &Connection, table: &str) -> UaResult<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |_| Ok(true))
        .optional()?
        .unwrap_or(false))
}

fn column_exists(conn: &Connection, table: &str, col: &str) -> UaResult<bool> {
    Ok(conn
        .query_row(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"), [col], |_| {
            Ok(true)
        })
        .optional()?
        .unwrap_or(false))
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
        let rec = PolicyRevisionRecord {
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
        let val = serde_json::to_value(&rec).map_err(|e| UaError::internal(e.to_string()))?;
        filter.check_structured_record("policy revision", &val)?;
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

#[allow(clippy::too_many_arguments)]
fn collect_artifacts(
    conn: &Connection,
    org_id: Option<&str>,
    start_excl_ts: Option<&str>,
    cutoff_ts: &str,
    exported_raw_approval_ids: &BTreeSet<i64>,
    policy_revisions: &[PolicyRevisionRecord],
    id_mapper: &OrgIdMapper,
    filter: &mut EgressFilter,
) -> UaResult<ArtifactCollection> {
    if !table_exists(conn, "deliverables")? || !table_exists(conn, "deliverable_revisions")? {
        return Ok((Vec::new(), BTreeMap::new()));
    }
    let has_files = table_exists(conn, "deliverable_files")?;
    let has_releases = table_exists(conn, "deliverable_releases")?;
    let has_cancelled_at = has_releases && column_exists(conn, "deliverable_releases", "cancelled_at")?;
    let has_dispatch_runs = table_exists(conn, "dispatch_runs")?;
    let has_dispatch_runs_org = has_dispatch_runs && column_exists(conn, "dispatch_runs", "org_id")?;

    let sql = match org_id {
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
    let raw_rows: Vec<RawArtifactRevision> = match org_id {
        Some(org) => stmt.query_map([org], map_row)?.collect::<Result<_, _>>()?,
        None => stmt.query_map([], map_row)?.collect::<Result<_, _>>()?,
    };

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
        // Check whether this revision is released by an approval inside this bundle.
        let raw_approval_id: Option<i64> = if has_releases {
            let rel_sql = if has_cancelled_at {
                "SELECT approval_id FROM deliverable_releases \
                 WHERE revision_id = ?1 AND cancelled_at IS NULL ORDER BY approval_id ASC"
            } else {
                "SELECT approval_id FROM deliverable_releases \
                 WHERE revision_id = ?1 ORDER BY approval_id ASC"
            };
            let mut rstmt = conn.prepare(rel_sql)?;
            let ids: Vec<i64> = rstmt.query_map([rev_row_id], |r| r.get(0))?.collect::<Result<_, _>>()?;
            ids.into_iter().find(|aid| exported_raw_approval_ids.contains(aid))
        } else {
            None
        };

        // Include revisions recorded inside the bundle window, plus any earlier
        // revision (<= cutoff) covered by a release approval resolved in this window.
        let in_win = in_time_window(&recorded_at, start_excl_ts, cutoff_ts);
        let covered_in_window =
            raw_approval_id.is_some() && cmp_ts(&recorded_at, cutoff_ts) != Ordering::Greater;
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
            let within_cutoff: Vec<_> =
                runs.into_iter().filter(|(_, _, ts)| cmp_ts(ts, cutoff_ts) != Ordering::Greater).collect();
            within_cutoff
                .iter()
                .find(|(_, _, ts)| cmp_ts(ts, &recorded_at) != Ordering::Greater)
                .or_else(|| within_cutoff.first())
                .map_or((None, None), |(rid, att, _)| (Some(rid.clone()), Some(*att)))
        } else {
            (None, None)
        };

        let policy_revision = policy_revisions
            .iter()
            .rev()
            .find(|p| p.kind == "policy" && cmp_ts(&p.created_at, &recorded_at) != Ordering::Greater)
            .map(|p| p.revision);
        let media_type = if kind == "commit" {
            "application/vnd.ua.git-commit".to_string()
        } else {
            "application/octet-stream".to_string()
        };

        let mapped_deliv_id = id_mapper.deliverable_id(conn, deliverable_id)?;
        let mapped_task_id = id_mapper.task_id(conn, raw_task_id)?;
        let mapped_approval_id = match raw_approval_id {
            Some(aid) => Some(id_mapper.approval_id(conn, aid)?),
            None => None,
        };
        let artifact_id = format!("deliverable:{mapped_deliv_id}");
        let released = mapped_approval_id.is_some();

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
            released,
            recorded_at: normalize_ts_utc(&recorded_at),
        };
        let val = serde_json::to_value(&entry).map_err(|e| UaError::internal(e.to_string()))?;
        filter.check_structured_record(&format!("artifact {artifact_id}"), &val)?;
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

/// Deterministic, non-reversible label pseudonymization for non-default org
/// approval actors inside a `hub` bundle, matching `approvals::ledger_label`
/// policy while preserving `resolver != requester` for separation-of-duties
/// verification.
fn redact_tenant_label(org: &str, label: &str) -> String {
    if label.trim().is_empty() {
        return String::new();
    }
    let digest = sha256_hex(format!("ua.label.v1\0{org}\0{label}").as_bytes());
    format!("redacted:{}", &digest[..16])
}

#[allow(clippy::too_many_arguments)]
fn collect_approval_receipts(
    conn: &Connection,
    class: CheckpointClass,
    org_id: Option<&str>,
    approval_event_refs: &BTreeMap<i64, (ReceiptLedgerRef, Value)>,
    policy_revisions: &[PolicyRevisionRecord],
    covers_by_raw_approval: &BTreeMap<i64, Vec<CoveredArtifact>>,
    id_mapper: &OrgIdMapper,
    filter: &mut EgressFilter,
) -> UaResult<Vec<ApprovalReceipt>> {
    if approval_event_refs.is_empty() || !table_exists(conn, "approvals")? {
        return Ok(Vec::new());
    }
    let has_org = column_exists(conn, "approvals", "org_id")?;
    let has_transport = column_exists(conn, "approvals", "resolved_transport")?;
    let org_col = if has_org { "org_id" } else { "'default'" };
    let transport_col = if has_transport { "resolved_transport" } else { "NULL" };

    let mut out = Vec::new();
    for (&raw_aid, (ledger_ref, ev_payload)) in approval_event_refs {
        let row: Option<RawApprovalRow> = conn
            .query_row(
                &format!(
                    "SELECT {org_col}, tool, payload, requested_by, status, reason, resolved_by, \
                            resolved_at, run_id, {transport_col} \
                     FROM approvals WHERE id = ?1"
                ),
                [raw_aid],
                |r| {
                    Ok(RawApprovalRow {
                        org_id: r.get(0)?,
                        tool: r.get(1)?,
                        payload_raw: r.get(2)?,
                        requested_by: r.get(3)?,
                        status: r.get(4)?,
                        reason: r.get(5)?,
                        resolved_by: r.get(6)?,
                        resolved_at: r.get(7)?,
                        run_id: r.get(8)?,
                        transport: r.get(9)?,
                    })
                },
            )
            .optional()?;
        let Some(RawApprovalRow {
            org_id: row_org,
            tool,
            payload_raw,
            requested_by,
            status,
            reason,
            resolved_by,
            resolved_at,
            run_id,
            transport,
        }) = row
        else {
            continue;
        };
        if let Some(expected_org) = org_id
            && row_org != expected_org
        {
            continue;
        }
        let raw_decision = ev_payload.get("decision").and_then(Value::as_str).unwrap_or(status.as_str());
        let decision = match raw_decision {
            "approve" | "approved" => "approved",
            "deny" | "denied" => "denied",
            "revoke" | "revoked" => "revoked",
            other => other,
        }
        .to_string();
        let decided_at_raw = resolved_at.unwrap_or_else(|| {
            ev_payload.get("decided_at").and_then(Value::as_str).unwrap_or("").to_string()
        });
        let decided_at = normalize_ts_utc(&decided_at_raw);
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

        let raw_req_label = requested_by.unwrap_or_else(|| "unknown".to_string());
        let raw_resolver_label = resolved_by
            .or_else(|| ev_payload.get("resolved_by").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default();

        // Respect `ledger_label` redaction: in a `hub` bundle, non-default org
        // tenant labels are pseudonymized (preserving SoD inequality) and their
        // free-text `reason` is omitted so tenant names/notes never bypass
        // ledger redaction.
        let redact_for_hub = class == CheckpointClass::Hub && row_org != DEFAULT_ORG;
        let req_label = if redact_for_hub {
            redact_tenant_label(&row_org, &raw_req_label)
        } else {
            raw_req_label.clone()
        };
        let resolver_label = if redact_for_hub {
            redact_tenant_label(&row_org, &raw_resolver_label)
        } else {
            raw_resolver_label.clone()
        };
        let receipt_reason = if redact_for_hub { None } else { reason };

        let request_val = json!({
            "payload": payload_raw,
            "requested_by": req_label,
            "tool": tool,
        });
        let request_digest = sha256_hex(to_canonical_string(&request_val)?.as_bytes());

        let resolver_transport =
            transport.or_else(|| ev_payload.get("transport").and_then(Value::as_str).map(str::to_string));
        let resolver_kind = if let Some(k) = ev_payload.get("resolver_kind").and_then(Value::as_str) {
            k.to_string()
        } else if decision != "approved" && raw_resolver_label == raw_req_label {
            "agent".to_string()
        } else {
            "human".to_string()
        };
        let requester_kind =
            ev_payload.get("requester_kind").and_then(Value::as_str).unwrap_or("agent").to_string();

        let attempt = if let Some(rid) = run_id.as_deref()
            && table_exists(conn, "dispatch_runs")?
        {
            conn.query_row("SELECT attempt FROM dispatch_runs WHERE run_id = ?1", [rid], |r| r.get(0))
                .optional()?
        } else {
            None
        };

        let policy_match = policy_revisions.iter().rev().find(|p| {
            p.kind == "policy"
                && (decided_at.is_empty() || cmp_ts(&p.created_at, &decided_at) != Ordering::Greater)
        });
        let covers = covers_by_raw_approval.get(&raw_aid).cloned().unwrap_or_default();
        let mapped_aid = id_mapper.approval_id(conn, raw_aid)?;

        let mut receipt = ApprovalReceipt {
            receipt_id: String::new(),
            approval_id: mapped_aid,
            org_id: row_org,
            tool,
            action_digest,
            request_digest,
            policy_revision: policy_match.map(|p| p.revision),
            policy_digest: policy_match.map(|p| p.document_sha256.clone()),
            requester: ReceiptActor { label: req_label, kind: requester_kind },
            resolver: ReceiptResolver {
                label: resolver_label,
                kind: resolver_kind,
                transport: resolver_transport,
            },
            decision,
            reason: receipt_reason,
            decided_at,
            expires_at,
            ledger: ledger_ref.clone(),
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
    policy_revisions: &[PolicyRevisionRecord],
    id_mapper: &OrgIdMapper,
    filter: &mut EgressFilter,
) -> UaResult<Vec<EvidenceRow>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for ev in events {
        if ev.redacted {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<Value>(&ev.payload) else { continue };
        let is_evidence_event = ev.channel.starts_with("evidence.")
            || ev.channel.starts_with("agent.approval.")
            || ev.channel.starts_with("agent.deliverable.")
            || ev.channel.starts_with("sdk.");
        if !is_evidence_event || !seen.insert(ev.ulid.clone()) {
            continue;
        }
        let raw_task_id = parsed.get("task_id").and_then(Value::as_i64);
        let task_id = match (raw_task_id, id_mapper.org_id.as_deref()) {
            (Some(tid), Some(_)) => Some(*id_mapper.fallback_task_ordinals.get(&tid).unwrap_or(&1)),
            (other, _) => other,
        };
        let run_id = parsed.get("run_id").and_then(Value::as_str).map(str::to_string);
        let attempt = parsed.get("attempt").and_then(Value::as_i64);
        // For org bundles, omit raw hub approval_id on EvidenceRow if not mapped
        // (receipts carry the dense org-local approval_id).
        let approval_id =
            if id_mapper.org_id.is_some() { None } else { parsed.get("approval_id").and_then(Value::as_i64) };
        let policy_revision = policy_revisions
            .iter()
            .rev()
            .find(|p| p.kind == "policy" && cmp_ts(&p.created_at, &ev.created_at) != Ordering::Greater)
            .map(|p| p.revision);
        let mut labels = vec![ev.channel.clone()];
        if ev.channel.starts_with("sdk.") {
            labels.push("client_asserted".into());
        }
        let row = EvidenceRow {
            id: ev.ulid.clone(),
            kind: ev.channel.clone(),
            org_id: ev.org_id.clone(),
            task_id,
            run_id,
            attempt,
            policy_revision,
            approval_id,
            labels,
            created_at: normalize_ts_utc(&ev.created_at),
        };
        let val = serde_json::to_value(&row).map_err(|e| UaError::internal(e.to_string()))?;
        if filter.allow_evidence_row(&val)? {
            out.push(row);
        }
    }
    Ok(out)
}
