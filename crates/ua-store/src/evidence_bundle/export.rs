//! Evidence bundle exporter (`ua evidence export`) and `org` window checkpoint
//! derivation (`docs/evidence-export.md`, S3).
//!
//! All database reads happen here inside `ua-store`; the hub never holds a
//! signing key and never writes `manifest.sig` (signing is strictly offline
//! via `ua evidence sign --bundle`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};

use crate::evidence::{
    CHECKPOINT_FORMAT, Checkpoint, CheckpointClass, Window, checkpoint_get, checkpoint_signature,
};
use crate::ledger::{GENESIS_HASH, HASH_V1};

use super::canonical::{
    empty_org_chain_hash, org_chain_fold, sha256_hex, to_canonical_bytes, to_canonical_string,
};
use super::egress::EgressFilter;
use super::{
    ARTIFACT_CONTENT_HASH_ONLY, ApprovalReceipt, ArtifactIndexEntry, BUNDLE_FORMAT, BundleCheckpointFile,
    BundleLedgerEvent, BundleManifest, CoveredArtifact, EvidenceRow, ManifestCounts, PolicyRevisionRecord,
    ProducerInfo, ReceiptActor, ReceiptLedgerRef, ReceiptResolver, WithheldReport,
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
/// Never exposes global `seq` numbers in the returned summary.
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
        if prev_global_head_hash.is_none() && created_at.as_str() < window_start {
            start_seq_exclusive = *seq;
            global_from_hash = eh.to_string();
        }
        if created_at.as_str() <= window_end && *seq > start_seq_exclusive {
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
        window: Window { start: window_start.to_string(), end: window_end.to_string() },
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
    filter.count_withheld_tables(conn, checkpoint.org_id.as_deref())?;

    // 1. Collect ledger rows covered by the checkpoint.
    let (events, unhashed_legacy_prefix, window) =
        collect_ledger_events(conn, &checkpoint, opts.from_seq, opts.from_org_seq, &mut filter)?;

    // Build lookup map of exported approval resolution events so receipts link directly.
    let mut approval_event_refs: BTreeMap<i64, (ReceiptLedgerRef, Value)> = BTreeMap::new();
    for ev in &events {
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

    // 2. Collect policy revisions, artifacts, approvals, and evidence rows.
    let policy_revisions = collect_policy_revisions(conn, &mut filter)?;
    let (artifacts, covers_by_approval) =
        collect_artifacts(conn, checkpoint.org_id.as_deref(), &policy_revisions, &mut filter)?;
    let approvals = collect_approval_receipts(
        conn,
        checkpoint.org_id.as_deref(),
        &approval_event_refs,
        &policy_revisions,
        &covers_by_approval,
        &mut filter,
    )?;
    let evidence_rows = collect_evidence_rows(&events, &policy_revisions, &mut filter)?;

    let withheld = filter.into_report();

    // 3. Serialize every hashed file canonically and compute per-file SHA-256.
    let mut staged: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    // ledger/events.jsonl
    let mut events_bytes = Vec::new();
    for ev in &events {
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
        events: events.len() as u64,
        unhashed_legacy_prefix,
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
        window,
        counts,
        files: file_hashes,
        digest: String::new(),
    };
    manifest.digest = manifest.recompute_digest()?;
    let manifest_bytes = to_canonical_bytes(&manifest)?;

    let producer = ProducerInfo {
        exported_at: opts.exported_at.clone(),
        host: opts.host.clone(),
        tool_version: opts.tool_version.clone(),
    };
    let producer_bytes = serde_json::to_vec_pretty(&producer)
        .map_err(|e| UaError::internal(format!("encoding producer.json: {e}")))?;

    // 4. Write all files into out_dir.
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

fn collect_ledger_events(
    conn: &Connection,
    checkpoint: &Checkpoint,
    from_seq: Option<i64>,
    from_org_seq: Option<i64>,
    filter: &mut EgressFilter,
) -> UaResult<(Vec<BundleLedgerEvent>, u64, Window)> {
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
            let mut out = Vec::new();
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
                filter.check_ledger_event(&channel, &payload)?;
                if entry.is_none() && !seen_hashed {
                    unhashed_prefix += 1;
                } else if entry.is_some() {
                    seen_hashed = true;
                }
                if first_ts.is_none() {
                    first_ts = Some(ts.clone());
                }
                last_ts = Some(ts.clone());
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
                });
            }
            let window = Window {
                start: first_ts.unwrap_or_else(|| checkpoint.signed_at.clone()),
                end: last_ts.unwrap_or_else(|| checkpoint.signed_at.clone()),
            };
            Ok((out, unhashed_prefix, window))
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
            let window =
                checkpoint.window.clone().ok_or_else(|| UaError::invalid("org checkpoint has no window"))?;

            let start_seq_excl: i64 = if global_from == GENESIS_HASH {
                0
            } else {
                rows.iter()
                    .find(|r| r.10.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(global_from)))
                    .map(|r| r.0)
                    .ok_or_else(|| {
                        UaError::not_found(format!(
                            "org checkpoint global_from_hash {global_from:?} not found in event_log"
                        ))
                    })?
            };
            let end_seq: i64 = if global_head == GENESIS_HASH {
                0
            } else {
                rows.iter()
                    .find(|r| r.10.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(global_head)))
                    .map(|r| r.0)
                    .ok_or_else(|| {
                        UaError::not_found(format!(
                            "org checkpoint global_head_hash {global_head:?} not found in event_log"
                        ))
                    })?
            };
            if end_seq < start_seq_excl {
                return Err(UaError::invalid(
                    "org checkpoint global_head_hash precedes global_from_hash in event_log",
                ));
            }

            let mut out = Vec::new();
            let mut cumulative_org_seq = 0i64;
            let mut org_count_before_window = 0i64;
            let mut chain_hash = String::new();
            let mut unhashed_prefix = 0u64;
            for (seq, ulid, channel, payload, orig, ep, cp, ts, dedupe, prev, entry, org_id, hash_v) in rows {
                if seq > end_seq {
                    break;
                }
                if org_id != target_org {
                    continue;
                }
                let Some(eh) = entry.as_deref() else {
                    if seq > start_seq_excl {
                        unhashed_prefix += 1;
                    }
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
                filter.check_ledger_event(&channel, &payload)?;
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
                });
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
            Ok((out, unhashed_prefix, window))
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

fn collect_policy_revisions(
    conn: &Connection,
    filter: &mut EgressFilter,
) -> UaResult<Vec<PolicyRevisionRecord>> {
    if !table_exists(conn, "config_revisions")? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT id, kind, revision, action, actor, document_sha256, raw_sha256, approval_id, \
                event_ulid, created_at \
         FROM config_revisions ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(PolicyRevisionRecord {
            id: r.get(0)?,
            kind: r.get(1)?,
            revision: r.get(2)?,
            action: r.get(3)?,
            actor: r.get(4)?,
            document_sha256: r.get(5)?,
            raw_sha256: r.get(6)?,
            // Tools requiring separation of duties per docs/policy.md.
            sod_tools: vec![
                "config_revision_commit".into(),
                "config_revision_manage".into(),
                "config_revision_rollback".into(),
                "deliverable_release".into(),
            ],
            approval_id: r.get(7)?,
            event_ulid: r.get(8)?,
            created_at: r.get(9)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        let rec = row?;
        let val = serde_json::to_value(&rec).map_err(|e| UaError::internal(e.to_string()))?;
        filter.check_structured_record("policy revision", &val)?;
        out.push(rec);
    }
    Ok(out)
}

fn collect_artifacts(
    conn: &Connection,
    org_id: Option<&str>,
    policy_revisions: &[PolicyRevisionRecord],
    filter: &mut EgressFilter,
) -> UaResult<ArtifactCollection> {
    if !table_exists(conn, "deliverables")? || !table_exists(conn, "deliverable_revisions")? {
        return Ok((Vec::new(), BTreeMap::new()));
    }
    let has_files = table_exists(conn, "deliverable_files")?;
    let has_releases = table_exists(conn, "deliverable_releases")?;
    let has_cancelled_at = has_releases && column_exists(conn, "deliverable_releases", "cancelled_at")?;
    let has_dispatch_runs = table_exists(conn, "dispatch_runs")?;

    let sql = match org_id {
        Some(_) => {
            "SELECT r.id, d.id, d.task_id, d.kind, r.rev_no, r.identity, r.recorded_at \
             FROM deliverable_revisions r \
             JOIN deliverables d ON d.id = r.deliverable_id AND d.org_id = r.org_id \
             WHERE r.org_id = ?1 \
             ORDER BY d.id ASC, r.rev_no ASC"
        }
        None => {
            "SELECT r.id, d.id, d.task_id, d.kind, r.rev_no, r.identity, r.recorded_at \
             FROM deliverable_revisions r \
             JOIN deliverables d ON d.id = r.deliverable_id \
             ORDER BY d.id ASC, r.rev_no ASC"
        }
    };
    let mut stmt = conn.prepare(sql)?;
    let raw_rows: Vec<(i64, i64, i64, String, i64, String, String)> = match org_id {
        Some(org) => stmt
            .query_map([org], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
            })?
            .collect::<Result<_, _>>()?,
        None => stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
            })?
            .collect::<Result<_, _>>()?,
    };

    let mut out = Vec::new();
    let mut covers_by_approval: BTreeMap<i64, Vec<CoveredArtifact>> = BTreeMap::new();
    for (rev_row_id, deliverable_id, task_id, kind, rev_no, identity, recorded_at) in raw_rows {
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
        let approval_id: Option<i64> = if has_releases {
            let rel_sql = if has_cancelled_at {
                "SELECT approval_id FROM deliverable_releases \
                 WHERE revision_id = ?1 AND cancelled_at IS NULL ORDER BY approval_id ASC LIMIT 1"
            } else {
                "SELECT approval_id FROM deliverable_releases \
                 WHERE revision_id = ?1 ORDER BY approval_id ASC LIMIT 1"
            };
            conn.query_row(rel_sql, [rev_row_id], |r| r.get(0)).optional()?
        } else {
            None
        };
        let (run_id, attempt): (Option<String>, Option<i64>) = if has_dispatch_runs {
            conn.query_row(
                "SELECT run_id, attempt FROM dispatch_runs \
                 WHERE task_id = ?1 AND created_at <= ?2 \
                 ORDER BY attempt DESC, created_at DESC LIMIT 1",
                rusqlite::params![task_id, recorded_at],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()?
            .or_else(|| {
                conn.query_row(
                    "SELECT run_id, attempt FROM dispatch_runs \
                     WHERE task_id = ?1 ORDER BY attempt DESC, created_at DESC LIMIT 1",
                    [task_id],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
                )
                .optional()
                .ok()
                .flatten()
            })
            .map_or((None, None), |(rid, att)| (Some(rid), Some(att)))
        } else {
            (None, None)
        };
        let policy_revision = policy_revisions
            .iter()
            .rev()
            .find(|p| p.kind == "policy" && p.created_at <= recorded_at)
            .map(|p| p.revision);
        let media_type = if kind == "commit" {
            "application/vnd.ua.git-commit".to_string()
        } else {
            "application/octet-stream".to_string()
        };
        let artifact_id = format!("deliverable:{deliverable_id}");
        let entry = ArtifactIndexEntry {
            id: artifact_id.clone(),
            revision: rev_no,
            sha256: identity.clone(),
            size,
            media_type,
            task_id,
            run_id,
            attempt,
            policy_revision,
            approval_id,
            recorded_at,
        };
        let val = serde_json::to_value(&entry).map_err(|e| UaError::internal(e.to_string()))?;
        filter.check_structured_record(&format!("artifact {artifact_id}"), &val)?;
        if let Some(aid) = approval_id {
            covers_by_approval.entry(aid).or_default().push(CoveredArtifact {
                id: artifact_id,
                revision: rev_no,
                sha256: identity,
            });
        }
        out.push(entry);
    }
    Ok((out, covers_by_approval))
}

fn collect_approval_receipts(
    conn: &Connection,
    org_id: Option<&str>,
    approval_event_refs: &BTreeMap<i64, (ReceiptLedgerRef, Value)>,
    policy_revisions: &[PolicyRevisionRecord],
    covers_by_approval: &BTreeMap<i64, Vec<CoveredArtifact>>,
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
    for (&aid, (ledger_ref, ev_payload)) in approval_event_refs {
        let row: Option<RawApprovalRow> = conn
            .query_row(
                &format!(
                    "SELECT {org_col}, tool, payload, requested_by, status, reason, resolved_by, \
                            resolved_at, run_id, {transport_col} \
                     FROM approvals WHERE id = ?1"
                ),
                [aid],
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
        let decided_at = resolved_at.unwrap_or_else(|| {
            ev_payload.get("decided_at").and_then(Value::as_str).unwrap_or("").to_string()
        });
        let expires_at = ev_payload.get("expires_at").and_then(Value::as_str).map(str::to_string);
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
        let req_label = requested_by.unwrap_or_else(|| "unknown".to_string());
        let request_val = json!({
            "payload": payload_raw,
            "requested_by": req_label,
            "tool": tool,
        });
        let request_digest = sha256_hex(to_canonical_string(&request_val)?.as_bytes());
        let resolver_label = resolved_by
            .or_else(|| ev_payload.get("resolved_by").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default();
        let resolver_transport =
            transport.or_else(|| ev_payload.get("transport").and_then(Value::as_str).map(str::to_string));
        let resolver_kind = if let Some(k) = ev_payload.get("resolver_kind").and_then(Value::as_str) {
            k.to_string()
        } else if decision != "approved" && resolver_label == req_label {
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

        let policy_match = policy_revisions
            .iter()
            .rev()
            .find(|p| p.kind == "policy" && (decided_at.is_empty() || p.created_at <= decided_at));
        let covers = covers_by_approval.get(&aid).cloned().unwrap_or_default();

        let mut receipt = ApprovalReceipt {
            receipt_id: String::new(),
            approval_id: aid,
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
            reason,
            decided_at,
            expires_at,
            ledger: ledger_ref.clone(),
            run_id,
            attempt,
            covers,
        };
        receipt.receipt_id = receipt.compute_receipt_id()?;
        let val = serde_json::to_value(&receipt).map_err(|e| UaError::internal(e.to_string()))?;
        filter.check_structured_record(&format!("approval receipt {aid}"), &val)?;
        out.push(receipt);
    }
    Ok(out)
}

fn collect_evidence_rows(
    events: &[BundleLedgerEvent],
    policy_revisions: &[PolicyRevisionRecord],
    filter: &mut EgressFilter,
) -> UaResult<Vec<EvidenceRow>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for ev in events {
        let Ok(parsed) = serde_json::from_str::<Value>(&ev.payload) else { continue };
        let task_id = parsed.get("task_id").and_then(Value::as_i64);
        let run_id = parsed.get("run_id").and_then(Value::as_str).map(str::to_string);
        let attempt = parsed.get("attempt").and_then(Value::as_i64);
        let approval_id = parsed.get("approval_id").and_then(Value::as_i64);
        let is_evidence_event = ev.channel.starts_with("evidence.")
            || ev.channel.starts_with("agent.approval.")
            || ev.channel.starts_with("agent.deliverable.")
            || ev.channel.starts_with("sdk.");
        if !is_evidence_event || !seen.insert(ev.ulid.clone()) {
            continue;
        }
        let policy_revision = policy_revisions
            .iter()
            .rev()
            .find(|p| p.kind == "policy" && p.created_at <= ev.created_at)
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
            created_at: ev.created_at.clone(),
        };
        let val = serde_json::to_value(&row).map_err(|e| UaError::internal(e.to_string()))?;
        if filter.allow_evidence_row(&val)? {
            out.push(row);
        }
    }
    Ok(out)
}

/// Ensure `hash_v = 1` rows do not follow `hash_v = 2` (helper re-exported for
/// verifier consistency checks).
#[allow(dead_code)]
pub(crate) fn is_legacy_hash_v(v: i64) -> bool {
    v == HASH_V1
}
